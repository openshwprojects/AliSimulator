#!/usr/bin/env python3
"""
UART console regression test for
OPTICUM X110TS/Software_Patch_X110TS_X110TSE_1.4.0C_PVR_UNI_ENG_2015-05-04.abs
(Opticum HD X110TS / X110TSE, ALi M3606, the universal English patch build
1.4.0C).

Unlike the other X110TS builds this one has no way into the ODM's interactive
console: its input_task polls only the SDK's serial-upgrade listener
(0x8001E230 in the booted image), which matches the UART input against
"comtest" (echoing each matching byte; bit 0 of the listener mode) and
"APP  init ok" (the slave-box handshake of an STB-to-STB upgrade; bit 1).  The
"startconsole" trigger and its "***  CONSOLE ACTIVATED  ***" banner are gone,
while the console's command table (DELETE .. REBOOT, now with NIGHTSCAN and
ADDCHAN instead of TASK / COMCAS* / HANG), its handlers and the
"*** CONSOLE DEACTIVATED ***" string are still linked in -- the command lookup
that walks the table has no caller left.

The test checks that:
  - the boot banner is printed (this build prints even without attach_sci),
  - "comtest" is echoed byte for byte in listener mode (console_mode 2),
  - "startconsole" is not a trigger: the listener echoes only "co", the common
    prefix with "comtest", and the mode stays 2,
  - console commands (HELP, VERSION) get no answer,
  - the console's command table is in the unpacked main code, and the
    activation strings are not.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from console_regression import ConsoleHarness, run_with_retry

# The dead console's dispatch table, as linked (24-byte entries, name first)
CONSOLE_TABLE = ("DELETE", "TOUCH", "READ", "MAGICKEY", "PALANTIR", "RCU", "FLAG", "MAINCODE",
                 "CHANNELS", "VERSION", "CLS", "HEAP", "SENDMSG", "HMSG", "TIME", "GPIOCONFIG",
                 "NIGHTSCAN", "CI_START", "CI_STOP", "ADDDUMMY", "ADDCHAN", "HELP", "EXIT", "REBOOT")


def run():
    h = ConsoleHarness(
        "OPTICUM X110TS/Software_Patch_X110TS_X110TSE_1.4.0C_PVR_UNI_ENG_2015-05-04.abs",
        "Opticum HD X110TS 1.4.0C PVR UNI ENG (M3606, console disabled)",
        boot_insns=10_000_000,
        direct_call=True,
        mask_timer=True,
        attach_sci=True,
    )

    h.check(
        "boot banner prints 'MC: APP  init ok' and Application version 1.0.0@SDK4.0ba.8.0_Combo",
        "MC: APP  init ok" in h.boot_banner and "Application version 1.0.0@SDK4.0ba.8.0_Combo" in h.boot_banner,
        repr(h.boot_banner[-300:]),
    )

    # 1. The upgrade listener echoes "comtest"
    resp = h.send("comtest", max_slices=8, stop_on=("comtest",))
    h.check("comtest is echoed byte for byte in listener mode (console_mode == 2)",
            resp == "comtest" and h.console_mode == 2, repr(resp))

    # 2. "startconsole" is not a trigger: only the "co" it shares with "comtest" is echoed
    resp = h.send("startconsole", max_slices=12, stop_on=())
    h.check("startconsole does not activate a console: the listener echoes only 'co' and stays in mode 2",
            resp == "co" and h.console_mode == 2 and "CONSOLE ACTIVATED" not in resp, repr(resp))

    # 3. Console commands get no answer
    hlp = h.send("HELP\r", max_slices=8, stop_on=())
    ver = h.send("VERSION\r", max_slices=8, stop_on=())
    h.check("console commands (HELP, VERSION) get no answer without a console",
            hlp == "" and ver == "" and h.console_mode == 2, repr((hlp, ver)))

    # 4. The console is linked in but has no way in via UART trigger
    ram = h.ram
    table = next((m.start() for m in re.finditer(b"DELETE\x00", ram) if ram[m.start() + 24:m.start() + 30] == b"TOUCH\x00"), -1)
    in_table = table != -1 and all(
        ram[table + 24 * i:table + 24 * i + len(n) + 1] == n.encode() + b"\x00" for i, n in enumerate(CONSOLE_TABLE))
    h.check(
        "the console's 24-command table (with NIGHTSCAN and ADDCHAN) and '*** CONSOLE DEACTIVATED ***' are linked in",
        in_table and b"*** CONSOLE DEACTIVATED ***" in ram,
        f"table=0x{0x80000000 + table:08X}",
    )
    h.check(
        "the 'startconsole' trigger and the '***  CONSOLE ACTIVATED  ***' banner are not in the main code",
        b"startconsole" not in ram and b"CONSOLE ACTIVATED" not in ram,
    )

    # 5. Wire a tiny dispatcher loop at 0x80F00000 calling the linked-in
    #    _console_get_str(0x80670B90) (0x80086F08) and _console_lookup_cmd()
    #    (0x8008827C) so we can exercise all 24 linked-in commands in 1.4.0C.
    import struct
    stub_addr = 0x80F00000
    stub_words = [
        0x27BDFFE0,  # addiu $sp, $sp, -32
        0xAFBF001C,  # sw $ra, 28($sp)
        0x3C048067,  # lui $a0, 0x8067
        0x24840B90,  # addiu $a0, $a0, 0x0B90
        0x0C021BC2,  # jal 0x80086F08 (_console_get_str)
        0x00000000,  # nop
        0x0C02209F,  # jal 0x8008827C (_console_lookup_cmd)
        0x00000000,  # nop
        0x0040F809,  # jalr $v0
        0x00000000,  # nop
        0x3C04803E,  # lui $a0, 0x803E
        0x24840FF0,  # addiu $a0, $a0, 0x0FF0 (">")
        0x0C02D06F,  # jal 0x800B41BC (libc_printf)
        0x00000000,  # nop
        0x8FBF001C,  # lw $ra, 28($sp)
        0x03E00008,  # jr $ra
        0x27BD0020,  # addiu $sp, $sp, 32
    ]
    h.sim.mu.mem_write(stub_addr, b"".join(struct.pack("<I", w) for w in stub_words))
    h.con_fn = stub_addr
    h.sim.poke(h.con_addr, b"\x04")

    # HELP: lists the 22 public commands (hiding MAGICKEY and PALANTIR)
    resp = h.send("HELP\r")
    public_cmds = [c for c in CONSOLE_TABLE if c not in ("MAGICKEY", "PALANTIR")]
    listed = resp.split("\r\n")[1].split() if resp.count("\r\n") >= 2 else []
    h.check(
        f"linked-in HELP lists all {len(public_cmds)} public commands (including NIGHTSCAN and ADDCHAN) and hides MAGICKEY/PALANTIR",
        listed == public_cmds and "MAGICKEY" not in resp and "PALANTIR" not in resp,
        repr(resp),
    )

    # VERSION / HEAP / MAINCODE
    resp = h.send("VERSION\r")
    h.check("linked-in VERSION prints 'V.0140 UNI RETA PVR (0002)>'",
            "V.0140 UNI RETA PVR (0002)>" in resp, repr(resp))

    resp = h.send("HEAP\r")
    h.check("linked-in HEAP prints heap usage ('HEAP: used/total')",
            "HEAP: " in resp and "/" in resp and resp.endswith(">"), repr(resp))

    resp = h.send("MAINCODE\r")
    h.check("linked-in MAINCODE prints maincode flash usage ('used/size [NN%]')",
            "%]\r\n>" in resp and "/" in resp, repr(resp))

    # DELETE / TOUCH / READ
    for cmd, err in (("DELETE", "_console_delete: error"), ("TOUCH", "_console_touch: error"),
                     ("READ", "_console_read: File error")):
        p1 = h.send(f"{cmd}\r")
        p2 = h.send("foo.bin\r")
        h.check(f"linked-in {cmd} prompts 'Enter name:' and reports '{err}' without a USB disk",
                p1.endswith("Enter name:") and err in p2 and p2.endswith(">"), repr((p1, p2)))

    # FLAG
    p1 = h.send("FLAG\r")
    p2 = h.send("0\r")
    p3 = h.send("1\r")
    h.check("linked-in FLAG shows F0..F7, prompts flag / value and sets F0=1",
            "F0:0, F1:0" in p1 and "F7:" in p1 and p1.endswith("Enter flag:")
            and p2.endswith("Enter val :") and "F0:1, F1:0" in p3 and p3.endswith(">"),
            repr((p1, p2, p3)))

    # CI_START / CI_STOP
    ci_st = h.send("CI_START\r")
    ci_sp = h.send("CI_STOP\r")
    h.check("linked-in CI_START and CI_STOP run silently and return to the prompt",
            ci_st == "CI_START\r\n>" and ci_sp == "CI_STOP\r\n>", repr((ci_st, ci_sp)))

    # TIME
    t1 = h.send("TIME\r", stop_on=("?\r\n",))
    t_abort = h.send("n", stop_on=(">",))
    h.check("linked-in TIME prints the RTC time ('TIME: HH-MM-SS', 'If set new time?') and aborts on 'n'",
            "TIME: " in t1 and "If set new time?" in t1 and "Wrong value!" in t_abort and t_abort.endswith(">"),
            repr((t1, t_abort)))

    # ADDDUMMY / ADDCHAN / CHANNELS / NIGHTSCAN
    d1 = h.send("ADDDUMMY\r")
    d_abort = h.send("n", stop_on=(">",))
    h.check("linked-in ADDDUMMY asks for dummy TP parameters and aborts on 'n'",
            "Adding TP! Please fill in parrams:" in d1 and d1.endswith("freq... ")
            and "Wrong value!" in d_abort and d_abort.endswith(">"), repr((d1, d_abort)))

    ac1 = h.send("ADDCHAN\r")
    ac_abort = h.send("n", stop_on=(">",))
    h.check("linked-in ADDCHAN prompts for TP parameters ('Adding TP! Please fill in parrams:', 'freq... ') and aborts on 'n'",
            "Adding TP! Please fill in parrams:" in ac1 and ac1.endswith("freq... ")
            and "Wrong value!" in ac_abort and ac_abort.endswith(">"),
            repr((ac1, ac_abort)))

    # A populated database pauses to scan between its TV, radio and transponder
    # sections. Keep waiting through those gaps so the next command starts cleanly.
    ch = h.send("CHANNELS\r", max_slices=64)
    h.check("linked-in CHANNELS prints the TV and Radio channel tables (CSV headers)",
            "TV Channels:\r\nNumber;LCN;Frequency" in ch and "Radio Channels:" in ch and ch.endswith(">"),
            repr(ch[:300]))

    ns = h.send("NIGHTSCAN\r")
    h.check("linked-in NIGHTSCAN runs silently and returns to the prompt",
            ns == "NIGHTSCAN\r\n>", repr(ns))

    # Unknown command + privilege lock (MAGICKEY / PALANTIR) + HMSG / GPIOCONFIG / SENDMSG
    unk = h.send("UNKNOWN\r")
    h.check("an unknown command prints 'UNKNOWN: Unknown command!'",
            "UNKNOWN: Unknown command!\r\n>" in unk, repr(unk))

    g_hmsg = h.send("HMSG\r")
    g_gpio = h.send("GPIOCONFIG\r")
    h.check("linked-in HMSG and GPIOCONFIG are gated (silently ignored) at privilege 0",
            g_hmsg == "HMSG\r\n>" and g_gpio == "GPIOCONFIG\r\n>", repr((g_hmsg, g_gpio)))

    mk = h.send("MAGICKEY\r")
    pal = h.send("PALANTIR\r")
    h.check("linked-in hidden MAGICKEY and PALANTIR are accepted silently",
            mk == "MAGICKEY\r\n>" and pal == "PALANTIR\r\n>", repr((mk, pal)))

    hmsg = h.send("HMSG\r", max_slices=16)
    h.check("linked-in HMSG (now unlocked) dumps the control message table ('Lista MSG:', '000\\tCTRL_MSG_SUBTYPE_KEY = 0')",
            "Lista MSG:" in hmsg and "000\tCTRL_MSG_SUBTYPE_KEY = 0" in hmsg and hmsg.endswith(">"),
            repr(hmsg[:200]))

    gp1 = h.send("GPIOCONFIG\r", stop_on=("... ",))
    gp2 = h.send("10\r", stop_on=("output)",))
    gp3 = h.send("1\r", stop_on=("... ",))
    gp4 = h.send("1\r", stop_on=(">",))
    gpio_dir = int.from_bytes(h.sim.mu.mem_read(0xB8000058, 4), "little")
    gpio_do = int.from_bytes(h.sim.mu.mem_read(0xB8000054, 4), "little")
    h.check("linked-in GPIOCONFIG (now unlocked) drives GPIO 10 as output high (MMIO 0xB8000058 / 0xB8000054)",
            gp1.endswith("Wybierz GPIO... ") and "Wybierz DIR... (1 - output)" in gp2
            and "Wybierz VAL... " in gp3 and gp4.endswith(">")
            and (gpio_dir & (1 << 10)) != 0 and (gpio_do & (1 << 10)) != 0,
            f"dir=0x{gpio_dir:08X}, do=0x{gpio_do:08X}, {(gp1, gp2, gp3, gp4)!r}")

    sm1 = h.send("SENDMSG\r", stop_on=("... ",))
    sm2 = h.send("27\r", stop_on=("... ",))
    sm3 = h.send("0\r", stop_on=(">",))
    h.check("linked-in SENDMSG prompts for the message code and parameter and posts it",
            sm1.endswith("Input MSG code... ") and "Input MSG param... " in sm2 and sm3.endswith(">"),
            repr((sm1, sm2, sm3)))

    # RCU / CLS / EXIT / REBOOT
    rcu_enter = h.send("RCU\r")
    h.check("linked-in RCU prints 'Enter RCU emulation mode (press 'ESC' to return)...'",
            "Enter RCU emulation mode (press 'ESC' to return)..." in rcu_enter and rcu_enter.endswith(">"),
            repr(rcu_enter))

    cls_out = h.send("CLS\r")
    h.check("linked-in CLS clears the terminal (ESC[H ESC[2J)",
            cls_out == "CLS\r\n\x1b[H\x1b[2J>", repr(cls_out))

    ex_out = h.send("EXIT\r")
    h.check("linked-in EXIT prints '*** CONSOLE DEACTIVATED ***' and sets console_mode to 2",
            "*** CONSOLE DEACTIVATED ***" in ex_out and h.console_mode == 2,
            f"{ex_out!r}, mode={h.console_mode}")

    reb = h.send("REBOOT\r", stop_on=("Rebooting...\r\n",))
    h.check("linked-in REBOOT prints 'Rebooting...'", "Rebooting..." in reb, repr(reb))

    h.finish()


if __name__ == "__main__":
    run_with_retry(run)

