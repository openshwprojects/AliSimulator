#!/usr/bin/env python3
"""
Full UART console commands regression test for
OPTICUM X110TS/Software_Conax_X110TS_1.1.9_PL SMART_HD+_2014-04-07.abs
(Opticum HD X110TS, ALi M3606, SW 0119, the Polish Smart HD+ build).

A silent retail build: libc_printf is routed to UART 0 and sci_16550 attached
by the harness (attach_sci).  Then "startconsole" enters the console, and each
of the 26 commands in its dispatch table is run and its effect checked
(console_m3606.exercise_m3606_console):
  [0] DELETE       [7] TASK          [14] HEAP       [21] ADDDUMMY
  [1] TOUCH        [8] COMCASDBG     [15] SENDMSG    [22] HANG
  [2] READ         [9] COMCASFORMAT  [16] HMSG       [23] HELP
  [3] MAGICKEY     [10] MAINCODE     [17] TIME       [24] EXIT
  [4] PALANTIR     [11] CHANNELS     [18] GPIOCONFIG [25] REBOOT
  [5] RCU          [12] VERSION      [19] CI_START
  [6] FLAG         [13] CLS          [20] CI_STOP
VERSION prints "SW: 0119 UNI RETA PVR (0002)".
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from console_m3606 import exercise_m3606_console
from console_regression import ConsoleHarness, run_with_retry


def run():
    h = ConsoleHarness(
        "OPTICUM X110TS/Software_Conax_X110TS_1.1.9_PL SMART_HD+_2014-04-07.abs",
        "Opticum HD X110TS 1.1.9 PL Smart HD+ (M3606)",
        boot_insns=10_000_000,
        direct_call=True,
        mask_timer=True,
        attach_sci=True,
    )
    exercise_m3606_console(
        h,
        version_text="SW: 0119 UNI RETA PVR (0002)",
        has_ci=True,
        has_ci_air=False,
        banner_text="Application version 1.0.0@SDK4.0ba.8.0_Combo_20120530",
    )
    h.finish()


if __name__ == "__main__":
    run_with_retry(run)
