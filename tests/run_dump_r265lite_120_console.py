#!/usr/bin/env python3
"""
Full UART console commands regression test for
Opticum Blue R265 Lite/T2GEN265_1.2.0-2023-03-17.abs (Opticum Blue R265 Lite 1.2.0,
ALi M3821, V.0120 DVB-T2 PVR).

Exercises all 26 commands in the firmware's command dispatch table:
  [0] DELETE            [7] PWMGPIO          [14] HMSG             [20] FORCENIM
  [1] TOUCH             [8] MAINCODE         [15] TIME             [21] DEBUGNIM
  [2] READ              [9] CHANNELS         [16] GPIOCONFIG       [22] SEMIAUTOTTEST
  [3] MAGICKEY          [10] VERSION         [17] PRINT_MEM_LAYOUT [23] HELP
  [4] PALANTIR          [11] CLS             [18] ADDDUMMY         [24] EXIT
  [5] RCU               [12] HEAP            [19] OTPPRINT         [25] REBOOT
  [6] FLAG              [13] SENDMSG
"""
import os
import sys
from unicorn.mips_const import UC_MIPS_REG_PC, UC_MIPS_REG_RA, UC_MIPS_REG_SP

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from console_regression import ConsoleHarness, run_with_retry


def run():
    h = ConsoleHarness(
        "Opticum Blue R265 Lite/T2GEN265_1.2.0-2023-03-17.abs",
        "Opticum Blue R265 Lite 1.2.0 (T2GEN265_1.2.0, M3821)",
        boot_insns=45_500_000,
        direct_call=True,
        mask_timer=True,
    )

    # In T2GEN265 1.2.0 (GCC 4.7.3 build), _console_get_int (0x801385b4) omitted
    # `*val = 0` (`sw $zero, ($a0)`), which was present in 1.1.5 at 0x80150b90,
    # leaving callers' stack locals uninitialized. Restore `sw $zero, ($a0)` at 0x801385c8.
    h.sim.poke(0x801385C8, bytes.fromhex("000080ac"))
    # NOP the `jal osal_task_sleep` call-sites inside DEBUGNIM (0x80137cbc) and
    # SEMIAUTOTTEST (0x80139518, 0x80139528) so they do not put the hijacked idle
    # task to sleep while keeping background OSAL tasks asleep.
    for addr in (0x80137CBC, 0x80139518, 0x80139528):
        h.sim.poke(addr, b"\x00\x00\x00\x00")

    h.check(
        "boot banner prints Libcore version 19.17.0 and Application version 1.0.0",
        "Libcore version 19.17.0" in h.boot_banner and "Application version 1.0.0" in h.boot_banner,
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

    # 2. [23] HELP
    resp = h.send("HELP\r")
    public_cmds = (
        "DELETE", "TOUCH", "READ", "RCU", "FLAG", "PWMGPIO", "MAINCODE", "CHANNELS",
        "VERSION", "CLS", "HEAP", "SENDMSG", "HMSG", "TIME", "GPIOCONFIG",
        "PRINT_MEM_LAYOUT", "ADDDUMMY", "OTPPRINT", "FORCENIM", "DEBUGNIM",
        "SEMIAUTOTTEST", "HELP", "EXIT", "REBOOT",
    )
    h.check(
        "HELP lists all 24 public commands (including M3821 diagnostics) and hides MAGICKEY/PALANTIR",
        all(c in resp for c in public_cmds) and "MAGICKEY" not in resp and "PALANTIR" not in resp,
        repr(resp),
    )

    # 3. [10] VERSION
    resp = h.send("VERSION\r")
    h.check("VERSION prints 'V.0120 DVB-T2 PVR (0002)>'", "V.0120 DVB-T2 PVR (0002)>" in resp, repr(resp))

    # 4. [12] HEAP
    resp = h.send("HEAP\r")
    h.check("HEAP prints heap usage (/10473)", "HEAP:" in resp and "/10473" in resp, repr(resp))

    # 5. [8] MAINCODE
    resp = h.send("MAINCODE\r")
    h.check("MAINCODE prints flash usage '1723027/2424832 [71%]'", "1723027/2424832 [71%]" in resp, repr(resp))

    # 6. [17] PRINT_MEM_LAYOUT
    mem = h.send("PRINT_MEM_LAYOUT\r", max_slices=20)
    h.check(
        "PRINT_MEM_LAYOUT dumps DDR memory layout table ('Total Memory', 'DD BUFFER')",
        "Total Memory" in mem and "DD BUFFER" in mem and mem.endswith(">"),
        repr(mem[:250]),
    )

    # 7. [0] DELETE
    p1 = h.send("DELETE\r")
    p2 = h.send("foo.bin\r")
    h.check(
        "DELETE prompts 'Enter name:' and reports '_console_delete: error' without USB",
        p1.endswith("Enter name:") and "_console_delete: error" in p2 and p2.endswith(">"),
        repr((p1, p2)),
    )

    # 8. [1] TOUCH
    p1 = h.send("TOUCH\r")
    p2 = h.send("foo.bin\r")
    h.check(
        "TOUCH prompts 'Enter name:' and reports '_console_touch: error' without USB",
        p1.endswith("Enter name:") and "_console_touch: error" in p2 and p2.endswith(">"),
        repr((p1, p2)),
    )

    # 9. [2] READ
    p1 = h.send("READ\r")
    p2 = h.send("foo.bin\r")
    h.check(
        "READ prompts 'Enter name:' and reports '_console_read: File error' without USB",
        p1.endswith("Enter name:") and "_console_read: File error" in p2 and p2.endswith(">"),
        repr((p1, p2)),
    )

    # 10. [6] FLAG
    p1 = h.send("FLAG\r")
    p2 = h.send("0\r")
    p3 = h.send("1\r")
    h.check(
        "FLAG sets F0=1 and prints updated flag state",
        "F0:0, F1:0" in p1 and p2.endswith("Enter val :") and "F0:1, F1:0" in p3 and p3.endswith(">"),
        repr((p1, p2, p3)),
    )

    # 11. [15] TIME
    t1 = h.send("TIME\r", stop_on=("?\r\n",))
    t_abort = h.send("n", stop_on=(">",))
    h.check(
        "TIME prints current RTC time ('TIME: HH-MM-SS') and aborts on 'n'",
        "TIME:" in t1 and "If set new time?" in t1 and "Wrong value!" in t_abort and t_abort.endswith(">"),
        repr((t1, t_abort)),
    )

    # 12. [18] ADDDUMMY + [9] CHANNELS
    d1 = h.send("ADDDUMMY\r")
    d_abort = h.send("n", stop_on=(">",))
    h.check(
        "ADDDUMMY prompts for TP parameters ('Adding TP! Please fill in parrams:', 'freq... ') and aborts on 'n'",
        "Adding TP! Please fill in parrams:" in d1 and d1.endswith("freq... ") and "Wrong value!" in d_abort and d_abort.endswith(">"),
        repr((d1, d_abort)),
    )

    ch = h.send("CHANNELS\r", max_slices=16)
    h.check(
        "CHANNELS prints TV and Radio channel tables",
        "TV Channels:" in ch and "Radio Channels:" in ch and ch.endswith(">"),
        repr(ch[:300]),
    )

    # 13. Unknown command
    unk = h.send("UNKNOWN\r")
    h.check("Unknown command prints 'UNKNOWN: Unknown command!'", "UNKNOWN: Unknown command!" in unk, repr(unk))

    # 14. [3] MAGICKEY & [4] PALANTIR privilege escalation
    g_hmsg = h.send("HMSG\r")
    g_pwm = h.send("PWMGPIO\r")
    h.check(
        "HMSG and PWMGPIO are gated at privilege 0",
        g_hmsg == "HMSG\r\n>" and g_pwm == "PWMGPIO\r\n>",
        repr((g_hmsg, g_pwm)),
    )

    mk = h.send("MAGICKEY\r")
    pal = h.send("PALANTIR\r")
    h.check(
        "MAGICKEY and PALANTIR execute and unlock privileged commands",
        mk == "MAGICKEY\r\n>" and pal == "PALANTIR\r\n>",
        repr((mk, pal)),
    )

    # 15. [19] OTPPRINT
    otp = h.send("OTPPRINT\r", max_slices=40)
    h.check(
        "OTPPRINT dumps 0x400-byte OTP memory and prints CHIP/REV/CERT/PROD/AC3/DDP status",
        "OTP:" in otp and "03F0:" in otp and "CHIP:65618,REV:131073,CERT:3,PROD:0" in otp and "AC3:1" in otp and otp.endswith(">"),
        repr(otp[-200:]),
    )

    # 16. [20] FORCENIM
    fn_out = h.send("FORCENIM\r50\r8\r0\r", max_slices=16)
    h.check(
        "FORCENIM accepts (freq_idx=50, bw=8MHz, mode=0) and configures NIM parameters",
        fn_out == "FORCENIM\r\n50\r\n8\r\n0\r\n>",
        repr(fn_out),
    )

    # 17. [21] DEBUGNIM
    dn_out = h.send("DEBUGNIM\r", max_slices=30)
    h.check(
        "DEBUGNIM queries demodulator status and prints '@0236;0000;0009;0109;0000;0100;$'",
        "@0236;0000;0009;0109;0000;0100;$" in dn_out and dn_out.endswith(">"),
        repr(dn_out),
    )

    # 18. [14] HMSG
    hmsg = h.send("HMSG\r", max_slices=16)
    h.check(
        "HMSG dumps control message table (000\tCTRL_MSG_SUBTYPE_KEY..CTRL_MSG_ENTER_FACTORY)",
        "Lista MSG:" in hmsg and "000\tCTRL_MSG_SUBTYPE_KEY = 0" in hmsg and "CTRL_MSG_ENTER_FACTORY" in hmsg,
        repr(hmsg[:200]),
    )

    # 19. [16] GPIOCONFIG
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

    # 20. [7] PWMGPIO
    pw1 = h.send("PWMGPIO\r", stop_on=("... ",))
    pw2 = h.send("12\r", stop_on=("... ",))
    pw3 = h.send("100\r", stop_on=("... ",))
    pw4 = h.send("200\r", stop_on=(">",))
    pwm_cfg = int.from_bytes(h.sim.mu.mem_read(0xB8018434, 4), "little")
    pwm_prd = int.from_bytes(h.sim.mu.mem_read(0xB8018430, 4), "little")
    h.check(
        "PWMGPIO configures GPIO 12 PWM in MMIO 0xB8018434 (0x8C) and 0xB8018430 ((100<<16)|200)",
        pw1.endswith("Wybierz GPIO... ")
        and "Zdefiniuj Th... " in pw2
        and "Zdefiniuj Tl... " in pw3
        and pw4.endswith(">")
        and pwm_cfg == 0x8C
        and pwm_prd == ((100 << 16) | 200),
        f"pwm_cfg=0x{pwm_cfg:08X}, pwm_prd=0x{pwm_prd:08X}",
    )

    # 21. [13] SENDMSG
    sm1 = h.send("SENDMSG\r", stop_on=("... ",))
    sm2 = h.send("27\r", stop_on=("... ",))
    sm3 = h.send("0\r", stop_on=(">",))
    h.check(
        "SENDMSG prompts for MSG code & param and dispatches message",
        sm1.endswith("Input MSG code... ") and "Input MSG param... " in sm2 and sm3.endswith(">"),
        repr((sm1, sm2, sm3)),
    )

    # 22. [5] RCU
    rcu_enter = h.send("RCU\r")
    rcu_x = h.send("x", max_slices=6, stop_on=("\r\n",))
    rcu_dn = h.send("\x1b[B", max_slices=8, stop_on=("66[42]\r\n",))
    rcu_exit = h.send("\x1b", stop_on=(">",))
    h.check(
        "RCU enters emulation mode, maps ASCII/VT100 keys, and exits on ESC",
        "Enter RCU emulation mode" in rcu_enter
        and "Key receive: 120[78]" in rcu_x
        and "27[1B]/91[5B]/66[42]" in rcu_dn
        and "Leave RCU emulation mode..." in rcu_exit,
        repr((rcu_enter, rcu_x, rcu_dn, rcu_exit)),
    )

    # 23. [11] CLS
    cls_out = h.send("CLS\r")
    h.check("CLS clears terminal with ANSI escape sequence", cls_out == "CLS\r\n\x1b[H\x1b[2J>", repr(cls_out))

    # 24. [24] EXIT & re-activation
    ex_out = h.send("EXIT\r")
    h.sim.run(max_instructions=h.sim.instruction_count + 200_000)
    re_act = h.send("startconsole")
    h.check(
        "EXIT deactivates console (console_mode == 2) and startconsole re-activates it",
        "*** CONSOLE DEACTIVATED ***" in ex_out and "***  CONSOLE ACTIVATED  ***" in re_act and h.console_mode == 4,
        repr((ex_out, re_act)),
    )

    # 25. [22] SEMIAUTOTTEST
    semi = h.send("SEMIAUTOTTEST\r", max_slices=20, stop_on=(">",))
    h.check(
        "SEMIAUTOTTEST runs DVB-T2 frequency sweep ('freq 50;'..'freq 906;'..'Koniec')",
        "freq 50;" in semi and "freq 906;" in semi and "Koniec" in semi and semi.endswith(">"),
        repr(semi[-120:]),
    )

    # 26. [25] REBOOT
    reb = h.send("REBOOT\r", stop_on=("Rebooting...\r\n",))
    h.check("REBOOT prints 'Rebooting...'", "Rebooting..." in reb, repr(reb))

    h.finish()


if __name__ == "__main__":
    run_with_retry(run)
