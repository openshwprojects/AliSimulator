#!/usr/bin/env python3
"""
Full UART console commands regression test for
OPTICUM X110TS/Software_X110TS_X110TSE_temp_Tiles_to_Sabbat.abs
(Opticum HD X110TS / X110TSE, ALi M3606, the Tiles-to-Sabbat GUI transition
build, SW 0123 RETA_PROD v.291; Libcore 8.33.0).

libc_printf is routed to UART 0 and sci_16550 attached by the harness where the
build is silent (attach_sci).  Then "startconsole" enters the console, and each
of the 27 commands in its dispatch table -- the X110p 1.3.4 table, with
CI_IFISAIR -- is run and its effect checked
(console_m3606.exercise_m3606_console):
  [0] DELETE       [7] TASK          [14] HEAP       [21] CI_IFISAIR
  [1] TOUCH        [8] COMCASDBG     [15] SENDMSG    [22] ADDDUMMY
  [2] READ         [9] COMCASFORMAT  [16] HMSG       [23] HANG
  [3] MAGICKEY     [10] MAINCODE     [17] TIME       [24] HELP
  [4] PALANTIR     [11] CHANNELS     [18] GPIOCONFIG [25] EXIT
  [5] RCU          [12] VERSION      [19] CI_START   [26] REBOOT
  [6] FLAG         [13] CLS          [20] CI_STOP
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from console_m3606 import exercise_m3606_console
from console_regression import ConsoleHarness, run_with_retry


def run():
    h = ConsoleHarness(
        "OPTICUM X110TS/Software_X110TS_X110TSE_temp_Tiles_to_Sabbat.abs",
        "Opticum HD X110TS Tiles-to-Sabbat transition build (M3606)",
        # The take-over must come after the application's initialisation (its
        # storage, its UART re-attach): the Unicorn engine's instruction estimate
        # follows host time, so a fixed count (10 M) landed too early on the Linux
        # CI runner, where the first command that needed the storage (MAINCODE)
        # ran into the firmware's fatal reboot.  The banner the application
        # prints is the steady milestone (as in run_dump_x110ts_118_rc4_console);
        # the boot then goes on 2 M estimated instructions before the take-over.
        boot_until=lambda uart: 'Libcore version 8.33.0@SDK4.0ba.8.33_20150107' in uart,
        boot_step=1_000_000,
        boot_settle_insns=2_000_000,
        boot_insns=60_000_000,
        direct_call=True,
        mask_timer=True,
        attach_sci=True,
    )
    exercise_m3606_console(
        h,
        version_text="SW: 0123 RETA_PROD v.291 (0003)",
        has_ci=True,
        has_ci_air=True,
        banner_text="Libcore version 8.33.0@SDK4.0ba.8.33_20150107",
    )
    h.finish()


if __name__ == "__main__":
    run_with_retry(run)
