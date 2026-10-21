"""
Shared command walk-through for the Globo HD-XS2 (ALi M3503) UART console,
used by the per-dump run_dump_hdxs2_*_console.py tests.

The HD-XS2 builds carry the ODM's newer console: an ~88-entry table of
{name[20], category, privilege, handler} (categories Navigation / Control /
CAS / Monitor / Debug, and a hidden one), HELP listing per category only what
the current privilege level allows (0 at boot; 10 and 20 unlock the rest),
LOGIN / PASSWORD to raise it, and MAGICKEY / PALANTIR kept only as decoys that
answer "Unknown command!".  These are silent retail builds: the harness routes
libc_printf to UART 0 and attaches sci_16550 itself (attach_sci).

The harness takes the console over early (5-8 M instructions: past that point,
around the 0x01 bytes these builds print as their start-up goes on, the UART
input stops reaching input_task), before the application has attached its
flash storage and database: MAINCODE, CHANNELS
and PRINTSAT read those (MAINCODE divides by the maincode chunk's size, read
as 0 then, and the trap ends in the watchdog reset), so they are left out;
booted to ~60 M they work (MAINCODE "1651543/1703936 [96%]" on the Reta build)
but the hijacked task then depends on host timing too much for a regression.
"""

NAVIGATION = ["SCREEN", "RCU", "HRCU", "CLS", "STARTCONSOLE", "HANG", "HELP", "EXIT", "REBOOT"]
DEBUG = ["MAINCODE", "CHANNELS", "VERSION", "HEAP", "PRINTSAT"]


def _help_sections(resp):
    """{'Navigation': [...], ...} from HELP's '* * *<name>* * *' sections."""
    sections, cur = {}, None
    for line in resp.split("\r\n"):
        if line.startswith("* * *") and line.endswith("* * *"):
            cur = line.strip("* ")
            sections[cur] = []
        elif cur is not None and line.strip() and line != ">":
            sections[cur] += line.split()
    return sections


def exercise_m3503_console(h, version_text, control_cmds):
    """Walk the HD-XS2 console's commands that work at privilege 0.

    h            -- a booted ConsoleHarness (console_mode 2, listener)
    version_text -- what VERSION prints, e.g. 'SW: 0135 POL_NETR_PVR (0162)'
    control_cmds -- the Control commands HELP lists at privilege 0
    """
    # comtest (the SDK's upgrade handshake, echoed in listener mode) & startconsole
    resp, tries = h.handshake()
    h.check("comtest echoes 'comtest' in listener mode (console_mode == 2)",
            resp == "comtest" and h.console_mode == 2, f"{resp!r} after {tries} tries")

    resp, tries = h.activate()
    h.check("startconsole clears the screen and activates the interactive console (console_mode == 4)",
            "\x1b[H\x1b[2J***  CONSOLE ACTIVATED  ***" in resp and resp.endswith(">") and h.console_mode == 4,
            f"{resp!r} after {tries} tries")

    # HELP: per-category listing at privilege 0
    resp = h.send("HELP\r")
    sec = _help_sections(resp)
    h.check("HELP lists the commands by category (Navigation, Control, CAS, Monitor, Debug)",
            list(sec) == ["Navigation", "Control", "CAS", "Monitor", "Debug"], repr(resp[:300]))
    h.check(f"HELP at privilege 0 shows Navigation {NAVIGATION}, Debug {DEBUG} and no CAS / Monitor commands",
            sec.get("Navigation") == NAVIGATION and sec.get("Debug") == DEBUG
            and sec.get("CAS") == [] and sec.get("Monitor") == [], repr(sec))
    h.check(f"HELP at privilege 0 shows the {len(control_cmds)} unprivileged Control commands only",
            sec.get("Control") == control_cmds, repr(sec.get("Control")))
    hidden = ("MAGICKEY", "PALANTIR", "LOGIN", "FLAG", "TASK", "HMSG", "GPIOCONFIG", "OTPPRINT", "TIME")
    h.check("HELP hides the decoys, LOGIN and the privileged commands (FLAG, TASK, HMSG, GPIOCONFIG, OTPPRINT, TIME)",
            not any(c in resp.split() for c in hidden), repr(resp))

    # VERSION / HEAP / STARTCONSOLE / CLS / unknown
    resp = h.send("VERSION\r")
    h.check(f"VERSION prints {version_text!r} and the build time ('unofficial')",
            f"VERSION\r\n{version_text}, " in resp and "unofficial\r\n>" in resp, repr(resp))

    resp = h.send("HEAP\r")
    h.check("HEAP prints heap usage ('HEAP: used/total')", resp.startswith("HEAP\r\nHEAP: ") and "/" in resp
            and resp.endswith(">"), repr(resp))

    resp = h.send("STARTCONSOLE\r")
    h.check("STARTCONSOLE (as a command) prints the activation banner again",
            resp == "STARTCONSOLE\r\n***  CONSOLE ACTIVATED  ***>", repr(resp))

    resp = h.send("CLS\r")
    h.check("CLS clears the terminal (ESC[H ESC[2J)", resp == "CLS\r\n\x1b[H\x1b[2J>", repr(resp))

    resp = h.send("UNKNOWN\r")
    h.check("an unknown command prints 'UNKNOWN: Unknown command!'", resp == "UNKNOWN\r\nUNKNOWN: Unknown command!\r\n>",
            repr(resp))

    # Privilege: privileged commands pass for unknown ones at level 0
    gated = {c: h.send(f"{c}\r") for c in ("FLAG", "HMSG", "GPIOCONFIG", "TIME")}
    h.check("privileged FLAG / HMSG / GPIOCONFIG / TIME answer '<cmd>: Unknown command!' at privilege 0",
            all(f"{c}: Unknown command!\r\n>" in r for c, r in gated.items()), repr(gated))

    decoys = {c: h.send(f"{c}\r") for c in ("MAGICKEY", "PALANTIR")}
    h.check("MAGICKEY / PALANTIR are decoys here: they answer '<cmd>: Unknown command!'",
            all(f"{c}: Unknown command!\r\n>" in r for c, r in decoys.items()), repr(decoys))

    # LOGIN: user / password prompts; wrong credentials leave the level at 0
    l1 = h.send("LOGIN\r", stop_on=("\t",))
    l2 = h.send("guest\r", stop_on=("\t",))
    l3 = h.send("guest\r")
    after = h.send("FLAG\r")
    h.check("LOGIN asks 'LOGIN:' and 'PASSWORD:'; wrong credentials return silently and FLAG stays locked",
            l1.endswith("LOGIN:\t\t") and l2.endswith("PASSWORD:\t") and l3 == "guest\r\n>"
            and "FLAG: Unknown command!" in after, repr((l1, l2, l3, after)))

    # HRCU: the RCU emulation key map
    resp = h.send("HRCU\r")
    h.check("HRCU prints the RCU emulation key map ('Wykaz dostepnych klawiszy', V_KEY_POWER '~' .. V_KEY_RECORD 'K')",
            "Wykaz dostepnych klawiszy" in resp and "V_KEY_POWER \t\t~" in resp and "V_KEY_RECORD \t\tK" in resp
            and resp.endswith(">"), repr(resp[:200]))

    # RCU: remote emulation (ASCII and VT100 keys), ESC leaves
    rcu_enter = h.send("RCU\r", stop_on=("...\r\n",))
    rcu_x = h.send("x", max_slices=6, stop_on=("\r\n",))
    rcu_dn = h.send("\x1b[B", max_slices=8, stop_on=("66[42]\r\n",))
    rcu_exit = h.send("\x1b", stop_on=(">",))
    h.check("RCU enters remote emulation, decodes 'x' and VT100 down (ESC [ B), and leaves on ESC",
            "Enter RCU emulation mode" in rcu_enter and "Key receive: 120[78]" in rcu_x
            and "27[1B]/91[5B]/66[42]" in rcu_dn and "Leave RCU emulation mode..." in rcu_exit,
            repr((rcu_enter, rcu_x, rcu_dn, rcu_exit)))

    # HANG: watchdog hang test, cancelled
    hg1 = h.send("HANG\r", stop_on=("Set hang time...\t",))
    hg2 = h.send("n", stop_on=(">",))
    h.check("HANG prompts 'Set hang time...' and cancels on 'n' ('user canceled!')",
            hg1.endswith("Set hang time...\t") and "user canceled!" in hg2 and hg2.endswith(">"), repr((hg1, hg2)))

    # DELETE / TOUCH / READ / COPY / EXPLORE: full-screen USB file/dir pickers; no disk in the simulator
    d1 = h.send("DELETE\r", stop_on=("_" * 38,))
    d2 = h.send("\x1b", stop_on=(">",))
    h.check("DELETE opens the '*SELECT FILE*' picker ('Error: could not open directory!' without USB) "
            "and ESC reports '_console_delete: error'",
            "Error: could not open directory!" in d1 and "*SELECT FILE*" in d1 and "_console_delete: error" in d2
            and d2.endswith(">"), repr((d1, d2)))

    tc1 = h.send("TOUCH\r", stop_on=("_" * 38,))
    tc2 = h.send("\x1b", stop_on=("Enter name:",))
    tc3 = h.send("foo.bin\r", stop_on=(">",))
    h.check("TOUCH opens '*SELECT DIRECTORY*', prompts 'Enter name:' on ESC, and reports '_console_touch: error'",
            "*SELECT DIRECTORY*" in tc1 and tc2.endswith("Enter name:") and "_console_touch: error" in tc3
            and tc3.endswith(">"), repr((tc1, tc2, tc3)))

    rd1 = h.send("READ\r", stop_on=("_" * 38,))
    rd2 = h.send("\x1b", stop_on=(">",))
    h.check("READ opens the '*SELECT FILE*' picker and ESC reports '_console_read: File error'",
            "*SELECT FILE*" in rd1 and "_console_read: File error" in rd2 and rd2.endswith(">"), repr((rd1, rd2)))

    cp1 = h.send("COPY\r", stop_on=("_" * 38,))
    cp2 = h.send("\x1b", stop_on=("_" * 38,))
    cp3 = h.send("\x1b", stop_on=(">",))
    h.check("COPY opens '*SELECT FILE*' then '*SELECT DIRECTORY*' and returns to prompt on ESC",
            "*SELECT FILE*" in cp1 and "*SELECT DIRECTORY*" in cp2 and cp3.endswith(">"), repr((cp1, cp2, cp3)))

    ex1 = h.send("EXPLORE\r", stop_on=("_" * 38,))
    ex2 = h.send("\x1b", stop_on=(">",))
    h.check("EXPLORE opens the '*EXPLORE*' browser and returns to prompt on ESC",
            "*EXPLORE*" in ex1 and ex2.endswith(">"), repr((ex1, ex2)))

    # Tuner / LNB helpers (those the build has): each prompts, a non-number cancels
    for cmd, prompt in (("NIMCURROUTE", "NIM_ROUTE"), ("MOTORPOW", "MOTOR SPECIAL POWER ON: 1 OFF :0?... ")):
        if cmd not in control_cmds:
            continue
        p1 = h.send(f"{cmd}\r", stop_on=("... ",))
        p2 = h.send("\x1b", stop_on=(">",))
        h.check(f"{cmd} prompts ({prompt.strip()!r}) and cancels on a non-number ('Wrong value!')",
                prompt in p1 and "Wrong value!" in p2 and p2.endswith(">"), repr((p1, p2)))

    if "NIMCURROUTE2" in control_cmds:
        nr1 = h.send("NIMCURROUTE2\r", stop_on=("...",))
        nr2 = h.send("n", stop_on=(">",))
        h.check("NIMCURROUTE2 prompts ('NIM_ROUTE') and cancels on 'n' ('Wrong value!', 'user canceled!')",
                "NIM_ROUTE" in nr1 and "Wrong value!" in nr2 and "user canceled!" in nr2 and nr2.endswith(">"),
                repr((nr1, nr2)))

    if "2FORCENIM" in control_cmds:
        f1 = h.send("2FORCENIM\r", stop_on=(": ",))
        f2 = h.send("\x1b", stop_on=(">",))
        h.check("2FORCENIM asks for the antenna parameters ('Parametry anteny:', 'lnb_type: ') and cancels",
                "Parametry anteny:" in f1 and f1.endswith("lnb_type: ") and "Wrong value!" in f2 and f2.endswith(">"),
                repr((f1, f2)))

    if "PRINTMEM" in control_cmds:
        pm = h.send("PRINTMEM\r")
        h.check("PRINTMEM executes and returns to prompt", pm == "PRINTMEM\r\n>", repr(pm))

    ps1 = h.send("PRINTSAT\r", stop_on=("\t",))
    ps2 = h.send("n", stop_on=(">",))
    h.check("PRINTSAT prompts ('Ktorego satelite zyczysz sobie wypisac:') and cancels on 'n' ('Wrong value!')",
            "Ktorego satelite zyczysz sobie wypisac:" in ps1 and "Wrong value!" in ps2 and ps2.endswith(">"),
            repr((ps1, ps2)))

    # SCREEN: the OSD as an 80-column text picture
    scr = h.send("SCREEN\r", max_slices=16)
    rows = scr.split("\r\n")[1:-1]
    h.check("SCREEN clears the terminal and prints the OSD as an 80-column text picture",
            scr.startswith("SCREEN\r\n\x1b[H\x1b[2J") and len(rows) >= 10
            and all(len(r) == 80 for r in rows[1:10]) and scr.endswith(">"), repr(scr[:200]))

    # Elevate privilege: LOGIN ('ADMIN' / 'PROROK') sets table privilege to 20,
    # and MAGICKEY / PALANTIR set inner handler privilege (-0x5674($gp)) to 1 / 3
    la1 = h.send("LOGIN\r", stop_on=("\t",))
    la2 = h.send("ADMIN\r", stop_on=("\t",))
    la3 = h.send("PROROK\r")
    h.send("MAGICKEY\r")
    h.send("PALANTIR\r")
    sec20 = _help_sections(h.send("HELP\r"))
    h.check("LOGIN ('ADMIN' / 'PROROK') elevates table privilege to 20 and unlocks CAS, Control, and Debug commands in HELP",
            la1.endswith("LOGIN:\t\t") and la2.endswith("PASSWORD:\t") and la3 == "PROROK\r\n>"
            and "COMCASDBG" in sec20.get("CAS", []) and "FLAG" in sec20.get("Control", [])
            and "OTPPRINT" in sec20.get("Debug", []), repr(sec20))

    # Privileged file-system commands: SAVESYSTEM / LOADSYSTEM
    if "SAVESYSTEM" in sec20.get("Control", []):
        ss1 = h.send("SAVESYSTEM\r", stop_on=("_" * 38,))
        ss2 = h.send("\x1b", stop_on=(">",))
        ls1 = h.send("LOADSYSTEM\r", stop_on=("_" * 38,))
        ls2 = h.send("\x1b", stop_on=(">",))
        h.check("SAVESYSTEM and LOADSYSTEM open '*SELECT DIRECTORY*' / '*SELECT FILE*' and cancel on ESC",
                "*SELECT DIRECTORY*" in ss1 and ss2.endswith(">") and "*SELECT FILE*" in ls1 and ls2.endswith(">"),
                repr((ss1[-60:], ss2, ls1[-60:], ls2)))

    # Privileged 1-shot commands: CALL, RANDMSG, CHANNEL_MOD
    if "CALL" in sec20.get("Control", []):
        c_out = h.send("CALL\r")
        h.check("CALL prints 'Function unsupported!'", "Function unsupported!" in c_out and c_out.endswith(">"), repr(c_out))

    rm_out = h.send("RANDMSG\r")
    cm_out = h.send("CHANNEL_MOD\r")
    h.check("RANDMSG and CHANNEL_MOD report unsupported status and return to prompt",
            "Function not supported for this CAS!" in rm_out and "Disable channel modyfications unsupported!" in cm_out,
            repr((rm_out, cm_out)))

    # FLAG, TASK, COMCASDBG
    fl1 = h.send("FLAG\r")
    fl2 = h.send("0\r")
    fl3 = h.send("1\r")
    h.check("FLAG (unlocked) shows F0..F7, prompts flag / value and sets F0=1",
            "F0:0, F1:0" in fl1 and fl1.endswith("Enter flag:") and fl2.endswith("Enter val :")
            and "F0:1, F1:0" in fl3 and fl3.endswith(">"), repr((fl1, fl2, fl3)))

    tsk1 = h.send("TASK\rk", stop_on=("47 \r\n",))
    tsk2 = h.send("\x1b\x1b\r", stop_on=(">",))
    h.check("TASK (unlocked) displays 'TASK LIST:' (PRI, STK) and exits on ESC",
            "TASK LIST:" in tsk1 and "PRI:" in tsk1 and "STK:" in tsk1 and tsk2.endswith(">"),
            repr((tsk1[:160], tsk2)))

    cd1 = h.send("COMCASDBG\r", stop_on=("val :",))
    cd2 = h.send("1\r", stop_on=(">",))
    h.check("COMCASDBG (unlocked) prints 'Actual debug: 0[0000] Enter new val :' and accepts new value",
            "Actual debug: 0[0000] Enter new val :" in cd1 and cd2.endswith(">"), repr((cd1, cd2)))

    # SENDMSG, HMSG, TIME, SAVETIME, USBDBG, DBGTIMERS
    sm1 = h.send("SENDMSG\r", stop_on=("... ",))
    sm2 = h.send("27\r", stop_on=("... ",))
    sm3 = h.send("0\r", stop_on=(">",))
    h.check("SENDMSG (unlocked) prompts for MSG code & param and dispatches message",
            sm1.endswith("Input MSG code... ") and "Input MSG param... " in sm2 and sm3.endswith(">"),
            repr((sm1, sm2, sm3)))

    hmsg = h.send("HMSG\r", max_slices=20)
    h.check("HMSG (unlocked) dumps the control message table ('Lista MSG:', '000\\tCTRL_MSG_SUBTYPE_KEY = 0')",
            "Lista MSG:" in hmsg and "000\tCTRL_MSG_SUBTYPE_KEY = 0" in hmsg and hmsg.endswith(">"),
            repr(hmsg[:200]))

    tm1 = h.send("TIME\r", stop_on=("?\r\n",))
    tm2 = h.send("n", stop_on=(">",))
    h.check("TIME (unlocked) prints RTC time ('TIME: HH-MM-SS', 'If set new time?') and aborts on 'n'",
            "TIME: " in tm1 and "If set new time?" in tm1 and "Wrong value!" in tm2 and tm2.endswith(">"),
            repr((tm1, tm2)))

    st_out = h.send("SAVETIME\r")
    ud_out = h.send("USBDBG\r")
    dt_out = h.send("DBGTIMERS\r")
    h.check("SAVETIME, USBDBG, and DBGTIMERS ('Timer debug', 'common_timer_num: 0') execute and return to prompt",
            st_out == "SAVETIME\r\n>" and ud_out == "USBDBG\r\n>"
            and "Timer debug" in dt_out and "common_timer_num: 0" in dt_out and dt_out.endswith(">"),
            repr((st_out, ud_out, dt_out)))

    # GPIOCONFIG, GPIOINFO, PWMGPIO
    gp1 = h.send("GPIOCONFIG\r", stop_on=("... ",))
    gp2 = h.send("10\r", stop_on=("output)",))
    gp3 = h.send("1\r", stop_on=("... ",))
    gp4 = h.send("1\r", stop_on=(">",))
    gi1 = h.send("GPIOINFO\r", stop_on=("... ",))
    gi2 = h.send("10\r", stop_on=(">",))
    h.check("GPIOCONFIG drives GPIO 10 output high and GPIOINFO reads back 'DIR = 1 (1 - output)' and 'VAL = 1'",
            gp1.endswith("Wybierz GPIO... ") and "Wybierz DIR... (1 - output)" in gp2
            and "Wybierz VAL... " in gp3 and gp4.endswith(">")
            and gi1.endswith("Wybierz GPIO... ") and "DIR = 1 (1 - output)" in gi2 and "VAL = 1" in gi2,
            repr((gp1, gp2, gp3, gp4, gi1, gi2)))

    pw1 = h.send("PWMGPIO\r", stop_on=("... ",))
    pw2 = h.send("12\r", stop_on=("... ",))
    pw3 = h.send("100\r", stop_on=("... ",))
    pw4 = h.send("200\r", stop_on=(">",))
    h.check("PWMGPIO prompts for GPIO, Th, and Tl and configures PWM",
            pw1.endswith("Wybierz GPIO... ") and "Zdefiniuj Th... " in pw2
            and "Zdefiniuj Tl... " in pw3 and pw4.endswith(">"), repr((pw1, pw2, pw3, pw4)))

    # ADDDUMMY, FILLTP, ADDTP, RECORD, RANDREC
    ad1 = h.send("ADDDUMMY\r")
    ad2 = h.send("n", stop_on=(">",))
    ftp = h.send("FILLTP\r")
    at1 = h.send("ADDTP\r")
    at2 = h.send("n", stop_on=(">",))
    h.check("ADDDUMMY, FILLTP ('Filling empty transponders:'), and ADDTP prompt and return cleanly",
            "Adding TP! Please fill in params:" in ad1 and "Wrong value!" in ad2
            and "Filling empty transponders:" in ftp and "Nothing to fill!" in ftp
            and "Adding TP! Please fill in params:" in at1 and "Wrong value!" in at2,
            repr((ad1, ad2, ftp, at1, at2)))

    rc1 = h.send("RECORD\r")
    rc2 = h.send("n", stop_on=(">",))
    rr1 = h.send("RANDREC\r")
    rr2 = h.send("n", stop_on=(">",))
    h.check("RECORD ('Add timer prv!') and RANDREC ('Add random pvr timers!') prompt and cancel on 'n'",
            "Add timer prv!" in rc1 and "user canceled!" in rc2
            and "Add random pvr timers!" in rr1 and "user canceled!" in rr2,
            repr((rc1, rc2, rr1, rr2)))

    # FLASHPRINT, OTPPRINT, CABINPRINT, CABINWRITE
    fp1 = h.send("FLASHPRINT\r", stop_on=("\t",))
    fp2 = h.send("n", stop_on=(">",))
    cb1 = h.send("CABINPRINT\r", stop_on=("\t",))
    cb2 = h.send("n", stop_on=(">",))
    cw1 = h.send("CABINWRITE\r", stop_on=("\t",))
    cw2 = h.send("n", stop_on=(">",))
    otp = h.send("OTPPRINT\r", max_slices=20)
    h.check("FLASHPRINT, CABINPRINT, CABINWRITE prompt/cancel and OTPPRINT dumps 0x200-byte OTP ('0000:'..'01F0:')",
            "Set read debug size(segment):" in fp1 and "Wrong value!" in fp2
            and "Set read debug size(segment):" in cb1 and "Wrong value!" in cb2
            and "Write directly into CA.bin" in cw1 and "Wrong value!" in cw2
            and "OTP:" in otp and "01F0:" in otp and otp.endswith(">"),
            repr((fp1, fp2, cb1, cb2, cw1, cw2, otp[-120:])))

    # Wi-Fi, media, EFU, memory, video/subtitle commands
    ws = h.send("WIFISTORE\r")
    wl = h.send("WIFILOAD\r")
    wc = h.send("WIFICONNECT\r")
    sp1 = h.send("STREAM_PLAY\r", stop_on=("STREAM_PLAY\r\n",))
    sp2 = h.send("http://test\r", stop_on=(">",))
    mp1 = h.send("MUSICPLAY\r", stop_on=(":\r\n",))
    mp2 = h.send("\x1b", stop_on=(">",))
    ef1 = h.send("EFUSENDLEV\r", stop_on=(":",))
    ef2 = h.send("50\r", stop_on=(":",))
    ef3 = h.send("1\r", stop_on=(">",))
    h.check("WIFISTORE, WIFILOAD, WIFICONNECT, STREAM_PLAY, MUSICPLAY, and EFUSENDLEV execute and reply",
            ws == "WIFISTORE\r\n>" and "AP_load_done" in wl and "AP try to connect" in wc
            and "readed: http://test" in sp2 and "Enter file to play:" in mp1 and "user break!" in mp2
            and "level: 50 lock: 1," in ef3,
            repr((ws, wl, wc, sp1, sp2, mp1, mp2, ef1, ef2, ef3)))

    ma1 = h.send("MALLOC\r", stop_on=("\t",))
    ma2 = h.send("1024\r", stop_on=(">",))
    fr1 = h.send("FREE\r")
    fr2 = h.send("FREE\r")
    vc1 = h.send("VIDEOCONTROL\r", stop_on=("\t",))
    vc2 = h.send("n", stop_on=(">",))
    sc1 = h.send("SUBTITLECONTROL\r", stop_on=("\t",))
    sc2 = h.send("n", stop_on=(">",))
    h.check("MALLOC, FREE, VIDEOCONTROL, and SUBTITLECONTROL execute and reply",
            "Set memory size:" in ma1 and ma2 == "1024\r\n>"
            and "Memory is ready to be used again!" in fr1 and "Memory is already free!" in fr2
            and "Set video on/off..." in vc1 and "Wrong value!" in vc2
            and "Subtitle data:" in sc1 and "Wrong value!" in sc2,
            repr((ma1, ma2, fr1, fr2, vc1, vc2, sc1, sc2)))

    # Hidden category-5 stream/tuner diagnostics (present on 1.3.5 / 1.4.0 builds with 2FORCENIM)
    if "2FORCENIM" in control_cmds:
        sto1 = h.send("STREAMTIMEOUT\r", stop_on=("\t",))
        sto2 = h.send("1500\r", stop_on=(">",))
        ste = h.send("STREAMENABLED\r")
        std = h.send("STREAMDISABLED\r")
        sti = h.send("STREAMINFORM\r")
        fnm = h.send("FORCENIM\rn", stop_on=(">",))
        fst = h.send("FORCESAT\rn", stop_on=(">",))
        ftr = h.send("FORCETER\rn", stop_on=(">",))
        dnm = h.send("DEBUGNIM\r")
        dtn = h.send("DEBUGTERNIM\r")
        dbr = h.send("DEBUGBITRATE\r")
        h.check("hidden stream/tuner commands (STREAMTIMEOUT, STREAMENABLED/DISABLED/INFORM, FORCENIM/SAT/TER, DEBUGNIM/TERNIM/BITRATE) reply",
                "Set new scan timeout:" in sto1 and "Aditional time in scan 1.500s" in sto2
                and ste == "STREAMENABLED\r\n>" and std == "STREAMDISABLED\r\n>" and sti == "STREAMINFORM\r\n>"
                and "Wrong value!" in fnm and "Wrong value!" in fst and "Wrong value!" in ftr
                and dnm.startswith("DEBUGNIM\r\n@") and dtn.startswith("DEBUGTERNIM\r\n@")
                and "Program bitrate:" in dbr and "Video bitrate:" in dbr and "Audio bitrate:" in dbr,
                repr((sto1, sto2, ste, std, sti, fnm, fst, ftr, dnm, dtn, dbr)))

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
