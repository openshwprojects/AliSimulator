"""
Shared command walk-through for the Opticum M3606 (X110p / X110TS) UART
console, used by the per-dump run_dump_x110ts_*_console.py tests.

These builds share one console implementation (the ODM's input_task console,
"startconsole" to enter, MAGICKEY / PALANTIR to raise the privilege level);
they differ only in a few table entries (CI_START / CI_STOP, CI_IFISAIR) and
in the VERSION string.  exercise_m3606_console() sends every command of the
table and records a [PASS] / [FAIL] check per command on the ConsoleHarness.
"""


def exercise_m3606_console(h, version_text, has_ci=True, has_ci_air=False, banner_text=None):
    """Walk every command of an M3606 Opticum console.

    h            -- a booted ConsoleHarness (console_mode 2, listener)
    version_text -- what VERSION prints before '\\r\\n>' (e.g. 'SW: 0119 UNI RETA PVR (0002)')
    has_ci       -- the table has CI_START / CI_STOP
    has_ci_air   -- the table has CI_IFISAIR
    banner_text  -- a string the boot banner must contain (optional)
    """
    if banner_text:
        h.check(f"boot banner prints {banner_text!r}", banner_text in h.boot_banner, repr(h.boot_banner[-300:]))

    # comtest (the SDK's upgrade handshake, echoed in listener mode) & startconsole
    resp, tries = h.handshake()
    h.check("comtest echoes 'comtest' in listener mode (console_mode == 2)",
            resp == "comtest" and h.console_mode == 2, f"{resp!r} after {tries} tries")

    resp, tries = h.activate()
    h.check("startconsole clears the screen and activates the interactive console (console_mode == 4)",
            "\x1b[H\x1b[2J***  CONSOLE ACTIVATED  ***" in resp and resp.endswith(">") and h.console_mode == 4,
            f"{resp!r} after {tries} tries")

    # HELP: the public table; MAGICKEY / PALANTIR are hidden
    resp = h.send("HELP\r")
    public_cmds = ["DELETE", "TOUCH", "READ", "RCU", "FLAG", "TASK", "COMCASDBG", "COMCASFORMAT",
                   "MAINCODE", "CHANNELS", "VERSION", "CLS", "HEAP", "SENDMSG", "HMSG", "TIME",
                   "GPIOCONFIG"]
    if has_ci:
        public_cmds += ["CI_START", "CI_STOP"]
    if has_ci_air:
        public_cmds += ["CI_IFISAIR"]
    public_cmds += ["ADDDUMMY", "HANG", "HELP", "EXIT", "REBOOT"]
    listed = resp.split("\r\n")[1].split() if resp.count("\r\n") >= 2 else []
    h.check(f"HELP lists exactly the {len(public_cmds)} public commands in table order and hides MAGICKEY/PALANTIR",
            listed == public_cmds and "MAGICKEY" not in resp and "PALANTIR" not in resp, repr(resp))

    # VERSION / HEAP / MAINCODE
    resp = h.send("VERSION\r")
    h.check(f"VERSION prints {version_text!r}", f"{version_text}\r\n>" in resp, repr(resp))

    resp = h.send("HEAP\r")
    h.check("HEAP prints heap usage ('HEAP: used/total')", "HEAP: " in resp and "/" in resp and resp.endswith(">"),
            repr(resp))

    resp = h.send("MAINCODE\r")
    h.check("MAINCODE prints maincode flash usage ('used/size [NN%]')", "%]\r\n>" in resp and "/" in resp, repr(resp))

    # File commands: no USB disk in the simulator, so each reports its error
    for cmd, err in (("DELETE", "_console_delete: error"), ("TOUCH", "_console_touch: error"),
                     ("READ", "_console_read: File error")):
        p1 = h.send(f"{cmd}\r")
        p2 = h.send("foo.bin\r")
        h.check(f"{cmd} prompts 'Enter name:' and reports '{err}' without a USB disk",
                p1.endswith("Enter name:") and err in p2 and p2.endswith(">"), repr((p1, p2)))

    # FLAG: shows F0..F7, sets one
    p1 = h.send("FLAG\r")
    p2 = h.send("0\r")
    p3 = h.send("1\r")
    h.check("FLAG shows F0..F7, prompts flag / value and sets F0=1",
            "F0:0, F1:0" in p1 and "F7:" in p1 and p1.endswith("Enter flag:")
            and p2.endswith("Enter val :") and "F0:1, F1:0" in p3 and p3.endswith(">"),
            repr((p1, p2, p3)))

    # TASK: interactive OSAL task viewer ('k' refreshes, ESC ESC leaves)
    tsk1 = h.send("TASK\rk", stop_on=("47 \r\n",))
    tsk2 = h.send("\x1b\x1b\r", stop_on=(">",))
    h.check("TASK shows the OSAL 'TASK LIST:' (priority, state, stack per task) and leaves on ESC",
            "TASK LIST:" in tsk1 and "PRI:" in tsk1 and "STK:" in tsk1 and "47 \r\n" in tsk1 and tsk2.endswith(">"),
            repr((tsk1[:200], tsk2)))

    # COMCASDBG / COMCASFORMAT: Conax CAS debug level and ca.bin format
    cd1 = h.send("COMCASDBG\r", stop_on=("val :",))
    cd2 = h.send("1\r", stop_on=(">",))
    h.check("COMCASDBG prints 'Actual debug: 0[0000] Enter new val :' and accepts a new level",
            "Actual debug: 0[0000] Enter new val :" in cd1 and cd2.endswith(">"), repr((cd1, cd2)))

    cf = h.send("COMCASFORMAT\r", max_slices=16)
    h.check("COMCASFORMAT formats ca.bin ('ca.bin formating - first 1024B filled by 0xFF!')",
            "ca.bin formating - first 1024B filled by 0xFF!" in cf and cf.endswith(">"), repr(cf))

    # CI_START / CI_STOP (/ CI_IFISAIR): common-interface CAM control
    if has_ci:
        ci_st = h.send("CI_START\r")
        ci_sp = h.send("CI_STOP\r")
        h.check("CI_START and CI_STOP run silently and return to the prompt",
                ci_st == "CI_START\r\n>" and ci_sp == "CI_STOP\r\n>", repr((ci_st, ci_sp)))
    if has_ci_air:
        ci_air = h.send("CI_IFISAIR\r")
        h.check("CI_IFISAIR reports how the CAM was recognised ('CAM rozpoznany jako')",
                "CAM rozpoznany jako" in ci_air and ci_air.endswith(">"), repr(ci_air))

    # TIME: shows the RTC time, 'n' declines setting it
    t1 = h.send("TIME\r", stop_on=("?\r\n",))
    t_abort = h.send("n", stop_on=(">",))
    h.check("TIME prints the RTC time ('TIME: HH-MM-SS', 'If set new time?') and aborts on 'n'",
            "TIME: " in t1 and "If set new time?" in t1 and "Wrong value!" in t_abort and t_abort.endswith(">"),
            repr((t1, t_abort)))

    # ADDDUMMY (aborted) + CHANNELS
    d1 = h.send("ADDDUMMY\r")
    d_abort = h.send("n", stop_on=(">",))
    h.check("ADDDUMMY asks for the dummy TP's parameters ('Adding TP! Please fill in parrams:', 'freq... ') "
            "and aborts on 'n'",
            "Adding TP! Please fill in parrams:" in d1 and d1.endswith("freq... ")
            and "Wrong value!" in d_abort and d_abort.endswith(">"), repr((d1, d_abort)))

    ch = h.send("CHANNELS\r", max_slices=16)
    h.check("CHANNELS prints the TV and Radio channel tables (CSV headers)",
            "TV Channels:\r\nNumber;LCN;Frequency" in ch and "Radio Channels:" in ch and ch.endswith(">"),
            repr(ch[:300]))

    # HANG: watchdog hang test, cancelled
    hg1 = h.send("HANG\r", stop_on=("Set hang time...\t",))
    hg2 = h.send("n", stop_on=(">",))
    h.check("HANG prompts 'Set hang time...' and cancels on 'n' ('user canceled!')",
            "Set hang time..." in hg1 and "user canceled!" in hg2 and hg2.endswith(">"), repr((hg1, hg2)))

    # Unknown command
    unk = h.send("UNKNOWN\r")
    h.check("an unknown command prints 'UNKNOWN: Unknown command!'", "UNKNOWN: Unknown command!\r\n>" in unk,
            repr(unk))

    # Privilege: HMSG / GPIOCONFIG do nothing at level 0; MAGICKEY + PALANTIR raise it
    g_hmsg = h.send("HMSG\r")
    g_gpio = h.send("GPIOCONFIG\r")
    h.check("HMSG and GPIOCONFIG are gated (silently ignored) at privilege 0",
            g_hmsg == "HMSG\r\n>" and g_gpio == "GPIOCONFIG\r\n>", repr((g_hmsg, g_gpio)))

    mk = h.send("MAGICKEY\r")
    pal = h.send("PALANTIR\r")
    h.check("hidden MAGICKEY and PALANTIR are accepted silently",
            mk == "MAGICKEY\r\n>" and pal == "PALANTIR\r\n>", repr((mk, pal)))

    hmsg = h.send("HMSG\r", max_slices=16)
    h.check("HMSG (now unlocked) dumps the control message table ('Lista MSG:', '000\\tCTRL_MSG_SUBTYPE_KEY = 0')",
            "Lista MSG:" in hmsg and "000\tCTRL_MSG_SUBTYPE_KEY = 0" in hmsg and hmsg.endswith(">"),
            repr(hmsg[:200]))

    gp1 = h.send("GPIOCONFIG\r", stop_on=("... ",))
    gp2 = h.send("10\r", stop_on=("output)",))
    gp3 = h.send("1\r", stop_on=("... ",))
    gp4 = h.send("1\r", stop_on=(">",))
    gpio_dir = int.from_bytes(h.sim.mu.mem_read(0xB8000058, 4), "little")
    gpio_do = int.from_bytes(h.sim.mu.mem_read(0xB8000054, 4), "little")
    h.check("GPIOCONFIG (now unlocked) drives GPIO 10 as output high (MMIO 0xB8000058 / 0xB8000054)",
            gp1.endswith("Wybierz GPIO... ") and "Wybierz DIR... (1 - output)" in gp2
            and "Wybierz VAL... " in gp3 and gp4.endswith(">")
            and (gpio_dir & (1 << 10)) != 0 and (gpio_do & (1 << 10)) != 0,
            f"dir=0x{gpio_dir:08X}, do=0x{gpio_do:08X}, {(gp1, gp2, gp3, gp4)!r}")

    # SENDMSG: posts a control message
    sm1 = h.send("SENDMSG\r", stop_on=("... ",))
    sm2 = h.send("27\r", stop_on=("... ",))
    sm3 = h.send("0\r", stop_on=(">",))
    h.check("SENDMSG prompts for the message code and parameter and posts it",
            sm1.endswith("Input MSG code... ") and "Input MSG param... " in sm2 and sm3.endswith(">"),
            repr((sm1, sm2, sm3)))

    # RCU: remote-control emulation (ASCII and VT100 keys), ESC leaves
    rcu_enter = h.send("RCU\r")
    rcu_x = h.send("x", max_slices=6, stop_on=("\r\n",))
    rcu_dn = h.send("\x1b[B", max_slices=8, stop_on=("66[42]\r\n",))
    rcu_exit = h.send("\x1b", stop_on=(">",))
    h.check("RCU enters remote emulation, decodes 'x' and VT100 down (ESC [ B), and leaves on ESC",
            "Enter RCU emulation mode" in rcu_enter and "Key receive: 120[78]" in rcu_x
            and "27[1B]/91[5B]/66[42]" in rcu_dn and "Leave RCU emulation mode..." in rcu_exit,
            repr((rcu_enter, rcu_x, rcu_dn, rcu_exit)))

    # CLS
    cls_out = h.send("CLS\r")
    h.check("CLS clears the terminal (ESC[H ESC[2J)", cls_out == "CLS\r\n\x1b[H\x1b[2J>", repr(cls_out))

    # EXIT & re-activation
    ex_out = h.send("EXIT\r")
    mode_after_exit = h.console_mode
    h.sim.run(max_instructions=h.sim.instruction_count + 200_000)
    re_act = h.send("startconsole")
    h.check("EXIT deactivates the console (console_mode 2) and startconsole re-activates it",
            "*** CONSOLE DEACTIVATED ***" in ex_out and mode_after_exit == 2
            and "***  CONSOLE ACTIVATED  ***" in re_act and h.console_mode == 4,
            repr((ex_out, mode_after_exit, re_act)))

    # REBOOT
    reb = h.send("REBOOT\r", stop_on=("Rebooting...\r\n",))
    h.check("REBOOT prints 'Rebooting...'", "Rebooting..." in reb, repr(reb))
