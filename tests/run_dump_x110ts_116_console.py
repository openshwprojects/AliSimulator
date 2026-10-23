#!/usr/bin/env python3
"""
Full UART console commands regression test for
OPTICUM X110TS/Software_Conax_X110TS_1.1.6_PL_SMART_HD+_2013-12-17.abs
(Opticum HD X110TS, ALi M3606, SW 0116).

Exercises all 24 commands in the firmware's command dispatch table at 0x804D0778:
  [0] DELETE       [6] FLAG          [12] VERSION    [18] GPIOCONFIG
  [1] TOUCH        [7] TASK          [13] CLS        [19] ADDDUMMY
  [2] READ         [8] COMCASDBG     [14] HEAP       [20] HANG
  [3] MAGICKEY     [9] COMCASFORMAT  [15] SENDMSG    [21] HELP
  [4] PALANTIR     [10] MAINCODE     [16] HMSG       [22] EXIT
  [5] RCU          [11] CHANNELS     [17] TIME       [23] REBOOT
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from console_regression import ConsoleHarness, run_with_retry


def run():
    h = ConsoleHarness(
        "OPTICUM X110TS/Software_Conax_X110TS_1.1.6_PL_SMART_HD+_2013-12-17.abs",
        "Opticum HD X110TS 1.1.6 (M3606)",
        boot_insns=10_000_000,
        attach_sci=True,
        direct_call=True,
        mask_timer=True,
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

    # 2. [21] HELP
    resp = h.send("HELP\r")
    public_cmds = (
        "DELETE", "TOUCH", "READ", "RCU", "FLAG", "TASK", "COMCASDBG", "COMCASFORMAT",
        "MAINCODE", "CHANNELS", "VERSION", "CLS", "HEAP", "SENDMSG", "HMSG", "TIME",
        "GPIOCONFIG", "ADDDUMMY", "HANG", "HELP", "EXIT", "REBOOT",
    )
    h.check(
        "HELP lists all 22 public commands and hides MAGICKEY/PALANTIR",
        all(c in resp for c in public_cmds) and "MAGICKEY" not in resp and "PALANTIR" not in resp,
        repr(resp),
    )

    # 3. [12] VERSION
    resp = h.send("VERSION\r")
    h.check("VERSION prints 'SW: 0116' and '(0002)'", "SW: 0116" in resp and "(0002)\r\n>" in resp, repr(resp))

    # 4. [14] HEAP
    resp = h.send("HEAP\r")
    h.check("HEAP prints heap usage ('HEAP:')", "HEAP:" in resp and resp.endswith(">"), repr(resp))

    # 5. [10] MAINCODE
    resp = h.send("MAINCODE\r")
    h.check("MAINCODE prints flash usage ('%]>')", "%]\r\n>" in resp and "/" in resp, repr(resp))

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
        "F0:0, F1:0" in p1 and p2.endswith("Enter val :") and "F0:1, F1:0" in p3,
        repr((p1, p2, p3)),
    )

    # 10. [7] TASK (interactive OSAL task viewer: 'k' refreshes, ESC+ESC exits)
    tsk1 = h.send("TASK\rk", stop_on=("47 \r\n",))
    tsk2 = h.send("\x1b\x1b\r", stop_on=(">",))
    h.check(
        "TASK displays 'TASK LIST:' table and exits cleanly on ESC",
        "TASK LIST:" in tsk1 and "47 \r\n" in tsk1 and tsk2.endswith(">"),
        repr((tsk1[:200], tsk2)),
    )

    # 11. [8] COMCASDBG
    cd1 = h.send("COMCASDBG\r", stop_on=("val :",))
    cd2 = h.send("1\r", stop_on=(">",))
    h.check(
        "COMCASDBG prints 'Actual debug: 0[0000] Enter new val :' and accepts new value",
        "Actual debug: 0[0000] Enter new val :" in cd1 and cd2.endswith(">"),
        repr((cd1, cd2)),
    )

    # 12. [9] COMCASFORMAT
    cf = h.send("COMCASFORMAT\r", max_slices=16)
    h.check(
        "COMCASFORMAT formats ca.bin ('ca.bin formating - first 1024B filled by 0xFF!')",
        "ca.bin formating - first 1024B filled by 0xFF!" in cf and cf.endswith(">"),
        repr(cf),
    )

    # 13. [17] TIME
    t1 = h.send("TIME\r", stop_on=("?\r\n",))
    t_abort = h.send("n", stop_on=(">",))
    h.check(
        "TIME prints current RTC time ('TIME: HH-MM-SS') and aborts on 'n'",
        "TIME:" in t1 and "If set new time?" in t1 and "Wrong value!" in t_abort and t_abort.endswith(">"),
        repr((t1, t_abort)),
    )

    # 14. [19] ADDDUMMY + [11] CHANNELS
    d1 = h.send("ADDDUMMY\r")
    d_abort = h.send("n", stop_on=(">",))
    h.check(
        "ADDDUMMY prompts for TP parameters ('Adding TP! Please fill in parrams:', 'freq... ') and aborts on 'n'",
        "Adding TP! Please fill in parrams:" in d1 and d1.endswith("freq... ") and "Wrong value!" in d_abort and d_abort.endswith(">"),
        repr((d1, d_abort)),
    )

    ch = h.send("CHANNELS\r", max_slices=16)
    h.check(
        "CHANNELS prints TV, Radio, and satellite tables",
        "TV Channels:" in ch and "Radio Channels:" in ch and ch.endswith(">"),
        repr(ch[:300]),
    )

    # 15. [20] HANG
    hg1 = h.send("HANG\r", stop_on=("Set hang time...\t",))
    hg2 = h.send("n", stop_on=(">",))
    h.check(
        "HANG prompts 'Set hang time...' and cancels on 'n' ('user canceled!')",
        "Set hang time..." in hg1 and "user canceled!" in hg2 and hg2.endswith(">"),
        repr((hg1, hg2)),
    )

    # 16. Unknown command
    unk = h.send("UNKNOWN\r")
    h.check("Unknown command prints 'UNKNOWN: Unknown command!'", "UNKNOWN: Unknown command!" in unk, repr(unk))

    # 17. [3] MAGICKEY & [4] PALANTIR privilege escalation
    g_hmsg = h.send("HMSG\r")
    g_gpio = h.send("GPIOCONFIG\r")
    h.check(
        "HMSG and GPIOCONFIG are gated at privilege 0",
        g_hmsg == "HMSG\r\n>" and g_gpio == "GPIOCONFIG\r\n>",
        repr((g_hmsg, g_gpio)),
    )

    mk = h.send("MAGICKEY\r")
    pal = h.send("PALANTIR\r")
    h.check(
        "MAGICKEY and PALANTIR execute and unlock privileged commands",
        mk == "MAGICKEY\r\n>" and pal == "PALANTIR\r\n>",
        repr((mk, pal)),
    )

    # 18. [16] HMSG
    hmsg = h.send("HMSG\r", max_slices=16)
    h.check(
        "HMSG dumps control message table (000\tCTRL_MSG_SUBTYPE_KEY..)",
        "Lista MSG:" in hmsg and "000\tCTRL_MSG_SUBTYPE_KEY = 0" in hmsg and hmsg.endswith(">"),
        repr(hmsg[:200]),
    )

    # 19. [18] GPIOCONFIG
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

    # 20. [15] SENDMSG
    sm1 = h.send("SENDMSG\r", stop_on=("... ",))
    sm2 = h.send("27\r", stop_on=("... ",))
    sm3 = h.send("0\r", stop_on=(">",))
    h.check(
        "SENDMSG prompts for MSG code & param and dispatches message",
        sm1.endswith("Input MSG code... ") and "Input MSG param... " in sm2 and sm3.endswith(">"),
        repr((sm1, sm2, sm3)),
    )

    # 21. [5] RCU
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

    # 22. [13] CLS
    cls_out = h.send("CLS\r")
    h.check("CLS clears terminal with ANSI escape sequence", cls_out == "CLS\r\n\x1b[H\x1b[2J>", repr(cls_out))

    # 23. [22] EXIT & re-activation
    ex_out = h.send("EXIT\r")
    h.sim.run(max_instructions=h.sim.instruction_count + 200_000)
    re_act = h.send("startconsole")
    h.check(
        "EXIT deactivates console (console_mode == 2) and startconsole re-activates it",
        "*** CONSOLE DEACTIVATED ***" in ex_out and "***  CONSOLE ACTIVATED  ***" in re_act and h.console_mode == 4,
        repr((ex_out, re_act)),
    )

    # 24. [23] REBOOT
    reb = h.send("REBOOT\r", stop_on=("Rebooting...\r\n",))
    h.check("REBOOT prints 'Rebooting...'", "Rebooting..." in reb, repr(reb))

    h.finish()


if __name__ == "__main__":
    run_with_retry(run)
