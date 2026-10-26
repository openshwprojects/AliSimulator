#!/usr/bin/env python3
"""
Full UART console commands regression test for dump_maciej.bin (Globo HD TS1 /
Opticum N2, ALi M3602, Application version 1.0.0@SDK4.0ba.7.4_20120227).

Exercises all 20 commands in the firmware's command dispatch table at 0x806764A4:
  [0] DELETE     [5] RCU        [10] CLS        [15] GPIOCONFIG
  [1] TOUCH      [6] FLAG       [11] HEAP       [16] ADDDUMMY
  [2] READ       [7] MAINCODE   [12] SENDMSG    [17] HELP
  [3] MAGICKEY   [8] CHANNELS   [13] HMSG       [18] EXIT
  [4] PALANTIR   [9] VERSION    [14] TIME       [19] REBOOT

Also checks the console through the running firmware's own task: its clock
advances, EXIT stops command handling, and REBOOT reaches the application and
reactivates the console. These checks leave the RTOS and timer running.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from console_regression import ConsoleHarness, run_with_retry
from simulator import AliMipsSimulator


def check_runtime_lifecycle(check):
    """Drive UART through the firmware's scheduler, including a complete reboot."""
    print("--- console lifecycle through the firmware's own task")
    sim = AliMipsSimulator(log_handler=lambda m: None)
    sim.lzma_insns_per_byte = 0
    sim.setSPIDump(False)
    sim.setI2CDump(False)
    out = []
    sim.setUartHandler(out.append)
    sim.loadFile("dump_maciej.bin")

    def text(start=0):
        return "".join(out[start:])

    def advance(predicate, seconds, step=0.02):
        end = sim._vtime() + seconds
        while sim._vtime() < end:
            sim.run(max_instructions=sim.instruction_count + 10_000_000,
                    max_vtime=min(end, sim._vtime() + step))
            if predicate():
                return True
        return predicate()

    def idle(seconds):
        advance(lambda: False, seconds, 0.25)

    def send(data):
        sim.setUartReceiveData(data, delay_instructions=0)

    def activate(seconds):
        mark = len(out)
        send(b"startconsole\r")
        return advance(lambda: "CONSOLE ACTIVATED" in text(mark)
                       and text().rstrip().endswith(">"), seconds)

    up = advance(lambda: "Application version" in text(), 60, 0.5)
    check("normal boot reaches the application", up, text()[-300:])
    if not up:
        return
    active = activate(40)
    check("the firmware task answers startconsole with its timer running", active, text()[-300:])
    if not active:
        return
    idle(0.5)

    def read_time():
        mark = len(out)
        send(b"TIME\r")
        advance(lambda: "If set new time?" in text(mark), 3)
        idle(0.2)
        send(b"n")
        advance(lambda: text(mark).rstrip().endswith(">"), 5)
        return re.search(r"TIME: (\d\d)-(\d\d)-(\d\d)", text(mark))

    first = read_time()
    idle(3)
    second = read_time()
    def seconds(match):
        return int(match.group(1)) * 3600 + int(match.group(2)) * 60 + int(match.group(3))
    elapsed = (seconds(second) - seconds(first)) % 86400 if first and second else None
    check("TIME advances with three seconds of running firmware", elapsed is not None and 2 <= elapsed <= 6,
          f"elapsed={elapsed}")

    mark = len(out)
    send(b"EXIT\r")
    left = advance(lambda: "CONSOLE DEACTIVATED" in text(mark), 5)
    check("the firmware task processes EXIT", left, text(mark))
    idle(1)
    mark = len(out)
    send(b"HELP\r")
    idle(2)
    check("HELP after EXIT receives no command listing", "DELETE TOUCH" not in text(mark), text(mark))
    active = activate(5)
    check("startconsole reactivates the firmware task after EXIT", active, text()[-300:])
    if not active:
        return
    idle(0.5)

    mark = len(out)
    send(b"REBOOT\r")
    booted = advance(lambda: "Application version" in text(mark), 60, 0.5)
    check("REBOOT runs the bootloader and reaches the application again",
          "Rebooting..." in text(mark) and "bl_verify_sw" in text(mark) and booted,
          text(mark)[-300:])
    if booted:
        check("the console activates again after a complete reboot", activate(40), text()[-300:])


def run():
    h = ConsoleHarness(
        "dump_maciej.bin",
        "Globo HD TS1 / N2 (dump_maciej.bin, M3602)",
        direct_call=True,
        mask_timer=True,
    )
    priv_addr = (h.gp - 0x6130) & 0xFFFFFFFF
    rcu_addr = (h.gp - 0x60BB) & 0xFFFFFFFF

    h.check(
        "boot banner prints Application version 1.0.0@SDK4.0ba",
        "Application version 1.0.0@SDK4.0ba" in h.boot_banner,
        repr(h.boot_banner),
    )

    # 1. comtest & startconsole
    resp, _ = h.handshake()
    h.check("comtest echoes 'comtest' in listener mode (console_mode == 2)", resp == "comtest" and h.console_mode == 2, repr(resp))

    resp, _ = h.activate()
    h.check(
        "startconsole activates interactive console (console_mode == 4)",
        "***  CONSOLE ACTIVATED  ***" in resp and resp.endswith(">") and h.console_mode == 4,
        repr(resp),
    )

    # 2. [17] HELP
    resp = h.send("HELP\r")
    public_cmds = (
        "DELETE", "TOUCH", "READ", "RCU", "FLAG", "MAINCODE", "CHANNELS",
        "VERSION", "CLS", "HEAP", "SENDMSG", "HMSG", "TIME", "GPIOCONFIG",
        "ADDDUMMY", "HELP", "EXIT", "REBOOT",
    )
    h.check(
        "HELP lists all 18 public commands and hides MAGICKEY/PALANTIR",
        all(c in resp for c in public_cmds) and "MAGICKEY" not in resp and "PALANTIR" not in resp,
        repr(resp),
    )

    # 3. [9] VERSION (with Backspace 0x08 editing)
    resp = h.send("verX\x08sion\r")
    h.check(
        "VERSION (with Backspace editing) prints 'V.0112 DVB-T PVR (0002)>'",
        "verX\x08 \x08sion\r\n" in resp and "V.0112 DVB-T PVR (0002)>" in resp,
        repr(resp),
    )

    # 4. [11] HEAP
    resp = h.send("HEAP\r")
    h.check("HEAP prints heap usage (/27695)", "HEAP:" in resp and "/27695" in resp, repr(resp))

    # 5. [7] MAINCODE
    resp = h.send("MAINCODE\r")
    h.check("MAINCODE prints flash usage '1764656/2359296 [74%]'", "1764656/2359296 [74%]" in resp, repr(resp))

    # 6. [0] DELETE
    p1 = h.send("DELETE\r")
    p2 = h.send("foo.bin\r")
    h.check(
        "DELETE prompts 'Enter name:' and reports '_console_delete: error' without USB",
        p1.endswith("Enter name:") and "_console_delete: error" in p2 and p2.endswith(">"),
        repr((p1, p2)),
    )

    # 7. [1] TOUCH
    p1 = h.send("TOUCH\r")
    p2 = h.send("foo.bin\r")
    h.check(
        "TOUCH prompts 'Enter name:' and reports '_console_touch: error' without USB",
        p1.endswith("Enter name:") and "_console_touch: error" in p2 and p2.endswith(">"),
        repr((p1, p2)),
    )

    # 8. [2] READ
    p1 = h.send("READ\r")
    p2 = h.send("foo.bin\r")
    h.check(
        "READ prompts 'Enter name:' and reports '_console_read: File error' without USB",
        p1.endswith("Enter name:") and "_console_read: File error" in p2 and p2.endswith(">"),
        repr((p1, p2)),
    )

    # 9. [6] FLAG
    p1 = h.send("FLAG\r")
    p2 = h.send("0\r")
    p3 = h.send("1\r")
    h.check(
        "FLAG sets F0=1 and prints updated flag state",
        "F0:0, F1:0" in p1 and p2.endswith("Enter val :") and "F0:1, F1:0" in p3 and p3.endswith(">"),
        repr((p1, p2, p3)),
    )

    # 10. [14] TIME
    t1 = h.send("TIME\r", stop_on=("?\r\n",))
    h.send("12\r", stop_on=("\r\n",))
    h.send("34\r", stop_on=("\r\n",))
    t_set = h.send("56\r", stop_on=(">",))
    t2 = h.send("TIME\r", stop_on=("?\r\n",))
    t_abort = h.send("\x1b", stop_on=(">",))
    h.check(
        "TIME sets system clock to 12-34-56 and reads it back",
        "If set new time?" in t1 and t_set.endswith(">") and "TIME: 12-34-56" in t2 and "Wrong value!" in t_abort,
        repr((t1, t2, t_abort)),
    )

    # 11. [16] ADDDUMMY + [8] CHANNELS
    d1 = h.send("ADDDUMMY\r")
    d2 = h.send("500000\r")
    d3 = h.send("8\r")
    d4 = h.send("8000\r")
    h.check(
        "ADDDUMMY creates a dummy transponder and TV program ('TP added!', 'PROG added!')",
        d1.endswith("freq... ") and d2.endswith("qam...    ") and d3.endswith("symbol... ") and "TP added!" in d4 and "PROG added!" in d4,
        repr((d1, d2, d3, d4)),
    )

    ch = h.send("CHANNELS\r", max_slices=16)
    h.check(
        "CHANNELS lists the newly added 'Dummy' TV channel and all 5 satellite/DVBT tables",
        "001;000;0000;0000;0000;0000;0000;0702;Dummy" in ch
        and "Sat 0: DVBT 0.0E [SAT_ID:1]" in ch
        and "Sat 4: C_ARABSAT 2/3A 0.4E [SAT_ID:5]" in ch,
        repr(ch[:300]),
    )

    # 12. Unknown command
    unk = h.send("UNKNOWN\r")
    h.check("Unknown command prints 'UNKNOWN: Unknown command!'", "UNKNOWN: Unknown command!" in unk, repr(unk))

    # 13. [3] MAGICKEY & [4] PALANTIR privilege escalation
    g_hmsg = h.send("HMSG\r")
    g_smsg = h.send("SENDMSG\r")
    h.check(
        "HMSG and SENDMSG are gated at privilege 0",
        g_hmsg == "HMSG\r\n>" and g_smsg == "SENDMSG\r\n>",
        repr((g_hmsg, g_smsg)),
    )

    mk = h.send("MAGICKEY\r")
    priv1 = int.from_bytes(h.sim.peek(priv_addr, 4), "little")
    h.check("MAGICKEY elevates privilege level to 1", mk == "MAGICKEY\r\n>" and priv1 == 1, f"priv={priv1}")

    pal = h.send("PALANTIR\r")
    priv3 = int.from_bytes(h.sim.peek(priv_addr, 4), "little")
    h.check("PALANTIR elevates privilege level to 3", pal == "PALANTIR\r\n>" and priv3 == 3, f"priv={priv3}")

    # 14. [13] HMSG
    hmsg = h.send("HMSG\r", max_slices=16)
    h.check(
        "HMSG dumps 60-entry control message table (000..159)",
        "Lista MSG:" in hmsg and "000\tCTRL_MSG_SUBTYPE_KEY = 0" in hmsg and "159\tCTRL_MSG_ENTER_FACTORY" in hmsg,
        repr(hmsg[:200]),
    )

    # 15. [15] GPIOCONFIG
    gp1 = h.send("GPIOCONFIG\r", stop_on=("... ",))
    gp2 = h.send("10\r", stop_on=("output)",))
    gp3 = h.send("1\r", stop_on=("... ",))
    gp4 = h.send("1\r", stop_on=(">",))
    gpio_dir = int.from_bytes(h.sim.mu.mem_read(0xB8000058, 4), "little")
    gpio_do = int.from_bytes(h.sim.mu.mem_read(0xB8000054, 4), "little")
    h.check(
        "GPIOCONFIG configures GPIO 10 as output high in MMIO 0xB8000058 / 0xB8000054",
        gp1.endswith("Wybierz GPIO... ")
        and "Wybierz DIR... (1 - output)" in gp2
        and "Wybierz VAL... " in gp3
        and gp4.endswith(">")
        and (gpio_dir & (1 << 10)) != 0
        and (gpio_do & (1 << 10)) != 0,
        f"dir=0x{gpio_dir:08X}, do=0x{gpio_do:08X}",
    )

    # 16. [12] SENDMSG
    sm1 = h.send("SENDMSG\r", stop_on=("... ",))
    sm2 = h.send("27\r", stop_on=("... ",))
    sm3 = h.send("0\r", stop_on=(">",))
    h.check(
        "SENDMSG prompts for MSG code & param and dispatches message",
        sm1.endswith("Input MSG code... ") and "Input MSG param... " in sm2 and sm3.endswith(">"),
        repr((sm1, sm2, sm3)),
    )

    # 17. [5] RCU
    rcu_enter = h.send("RCU\r")
    rcu_x = h.send("x", max_slices=6, stop_on=("\r\n",))
    rcu_dn = h.send("\x1b[B", max_slices=8, stop_on=("66[42]\r\n",))
    rcu_exit = h.send("\x1b", stop_on=(">",))
    h.check(
        "RCU enters emulation mode, maps ASCII/VT100 keys, and exits on ESC",
        "Enter RCU emulation mode" in rcu_enter
        and "Key receive: 120[78]" in rcu_x
        and "27[1B]/91[5B]/66[42]" in rcu_dn
        and "Leave RCU emulation mode..." in rcu_exit
        and h.sim.peek(rcu_addr, 1)[0] == 0,
        repr((rcu_enter, rcu_x, rcu_dn, rcu_exit)),
    )

    # 18. [10] CLS
    cls_out = h.send("CLS\r")
    h.check("CLS clears terminal with ANSI escape sequence", cls_out == "CLS\r\n\x1b[H\x1b[2J>", repr(cls_out))

    # 19. [18] EXIT & re-activation
    ex_out = h.send("EXIT\r")
    h.sim.run(max_instructions=h.sim.instruction_count + 200_000)
    re_act = h.send("startconsole")
    h.check(
        "EXIT deactivates console (console_mode == 2) and startconsole re-activates it",
        "*** CONSOLE DEACTIVATED ***" in ex_out and "***  CONSOLE ACTIVATED  ***" in re_act and h.console_mode == 4,
        repr((ex_out, re_act)),
    )

    # 20. [19] REBOOT
    reb = h.send("REBOOT\r", stop_on=("Rebooting...\r\n",))
    h.check("REBOOT prints 'Rebooting...'", "Rebooting..." in reb, repr(reb))

    check_runtime_lifecycle(h.check)
    h.finish()


if __name__ == "__main__":
    run_with_retry(run)
