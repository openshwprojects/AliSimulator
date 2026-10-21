#!/usr/bin/env python3
"""
Full UART console commands regression test for Ali_3801_Globo_DVBT_dump SPI 4mb.bin
(Globo N3, ALi M3801, V.0127 DVB-T PVR).

Exercises all 21 commands in the firmware's command dispatch table at 0x806CF6DC:
  [0] DELETE     [6] FLAG       [11] CLS        [16] GPIOCONFIG
  [1] TOUCH      [7] PWMGPIO    [12] HEAP       [17] ADDDUMMY
  [2] READ       [8] MAINCODE   [13] SENDMSG    [18] HELP
  [3] MAGICKEY   [9] CHANNELS   [14] HMSG       [19] EXIT
  [4] PALANTIR   [10] VERSION   [15] TIME       [20] REBOOT
  [5] RCU
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from console_regression import ConsoleHarness, run_with_retry


def run():
    h = ConsoleHarness(
        "Ali_3801_Globo_DVBT_dump SPI 4mb.bin",
        "Globo N3 (Ali_3801_Globo_DVBT_dump SPI 4mb.bin, M3801)",
    )

    h.check(
        "boot banner prints Libcore version 8.13.0@SDK4.0bd and Application version 1.0.0@SDK4.0ba",
        "Libcore version 8.13.0@SDK4.0bd" in h.boot_banner and "Application version 1.0.0@SDK4.0ba" in h.boot_banner,
        repr(h.boot_banner),
    )

    # 1. comtest & startconsole
    resp = h.send("comtest", max_slices=6, stop_on=("comtest",))
    h.check("comtest echoes 'comtest' in listener mode (console_mode == 2)", resp == "comtest" and h.console_mode == 2, repr(resp))

    resp = h.send("startconsole")
    h.check(
        "startconsole activates interactive console (console_mode == 4)",
        "***  CONSOLE ACTIVATED  ***" in resp and resp.endswith(">") and h.console_mode == 4,
        repr(resp),
    )

    # 2. [18] HELP
    resp = h.send("HELP\r")
    public_cmds = (
        "DELETE", "TOUCH", "READ", "RCU", "FLAG", "PWMGPIO", "MAINCODE", "CHANNELS",
        "VERSION", "CLS", "HEAP", "SENDMSG", "HMSG", "TIME", "GPIOCONFIG",
        "ADDDUMMY", "HELP", "EXIT", "REBOOT",
    )
    h.check(
        "HELP lists all 19 public commands (including PWMGPIO) and hides MAGICKEY/PALANTIR",
        all(c in resp for c in public_cmds) and "MAGICKEY" not in resp and "PALANTIR" not in resp,
        repr(resp),
    )

    # 3. [10] VERSION
    resp = h.send("VERSION\r")
    h.check("VERSION prints 'V.0127 DVB-T PVR (0002)>'", "V.0127 DVB-T PVR (0002)>" in resp, repr(resp))

    # 4. [12] HEAP
    resp = h.send("HEAP\r")
    h.check("HEAP prints heap usage (/27334)", "HEAP:" in resp and "/27334" in resp, repr(resp))

    # 5. [8] MAINCODE
    resp = h.send("MAINCODE\r")
    h.check("MAINCODE prints flash usage '1840238/2359296 [77%]'", "1840238/2359296 [77%]" in resp, repr(resp))

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

    # 10. [15] TIME
    t1 = h.send("TIME\r", stop_on=("?\r\n",))
    t_abort = h.send("n", stop_on=(">",))
    h.check(
        "TIME prints current RTC time ('TIME: HH-MM-SS') and aborts on 'n'",
        "TIME:" in t1 and "If set new time?" in t1 and "Wrong value!" in t_abort and t_abort.endswith(">"),
        repr((t1, t_abort)),
    )

    # 11. [17] ADDDUMMY + [9] CHANNELS
    d1 = h.send("ADDDUMMY\r")
    d2 = h.send("522000\r")
    d3 = h.send("8\r")
    d4 = h.send("8000\r")
    h.check(
        "ADDDUMMY creates a dummy transponder and TV program ('TP added!', 'PROG added!')",
        d1.endswith("freq... ") and d2.endswith("qam...    ") and d3.endswith("symbol... ") and "TP added!" in d4 and "PROG added!" in d4,
        repr((d1, d2, d3, d4)),
    )

    ch = h.send("CHANNELS\r", max_slices=16)
    h.check(
        "CHANNELS lists the newly added 'Dummy' TV channel and DVBT/satellite tables",
        "Dummy" in ch and "Sat 0: DVBT 0.0E [SAT_ID:1]" in ch,
        repr(ch[:300]),
    )

    # 12. Unknown command
    unk = h.send("UNKNOWN\r")
    h.check("Unknown command prints 'UNKNOWN: Unknown command!'", "UNKNOWN: Unknown command!" in unk, repr(unk))

    # 13. [3] MAGICKEY & [4] PALANTIR privilege escalation
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

    # 14. [14] HMSG
    hmsg = h.send("HMSG\r", max_slices=16)
    h.check(
        "HMSG dumps control message table (000\tCTRL_MSG_SUBTYPE_KEY..CTRL_MSG_ENTER_FACTORY)",
        "Lista MSG:" in hmsg and "000\tCTRL_MSG_SUBTYPE_KEY = 0" in hmsg and "CTRL_MSG_ENTER_FACTORY" in hmsg,
        repr(hmsg[:200]),
    )

    # 15. [16] GPIOCONFIG
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

    # 16. [7] PWMGPIO
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

    # 17. [13] SENDMSG
    sm1 = h.send("SENDMSG\r", stop_on=("... ",))
    sm2 = h.send("27\r", stop_on=("... ",))
    sm3 = h.send("0\r", stop_on=(">",))
    h.check(
        "SENDMSG prompts for MSG code & param and dispatches message",
        sm1.endswith("Input MSG code... ") and "Input MSG param... " in sm2 and sm3.endswith(">"),
        repr((sm1, sm2, sm3)),
    )

    # 18. [5] RCU
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

    # 19. [11] CLS
    cls_out = h.send("CLS\r")
    h.check("CLS clears terminal with ANSI escape sequence", cls_out == "CLS\r\n\x1b[H\x1b[2J>", repr(cls_out))

    # 20. [19] EXIT & re-activation
    ex_out = h.send("EXIT\r")
    h.sim.run(max_instructions=h.sim.instruction_count + 200_000)
    re_act = h.send("startconsole")
    h.check(
        "EXIT deactivates console (console_mode == 2) and startconsole re-activates it",
        "*** CONSOLE DEACTIVATED ***" in ex_out and "***  CONSOLE ACTIVATED  ***" in re_act and h.console_mode == 4,
        repr((ex_out, re_act)),
    )

    # 21. [20] REBOOT
    reb = h.send("REBOOT\r", stop_on=("Rebooting...\r\n",))
    h.check("REBOOT prints 'Rebooting...'", "Rebooting..." in reb, repr(reb))

    h.finish()


if __name__ == "__main__":
    run_with_retry(run)
