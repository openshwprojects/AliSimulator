#!/usr/bin/env python3
"""
UART console commands regression test for
GLOBO HD-XS2/Sw_Globo_HD-XS2_SmartHD_1.3.5_2015-05-08.abs
(Globo HD-XS2 / Opticum Blue XS65, ALi M3503, SW 0135 SMART HD+ PVR, the
Polish Conax Smart HD+ build).

The newer ODM console (see console_m3503.py), with the Smart HD+ table
(COMCASPAIR / PAIRFLAG for the card pairing, no STREAM_PLAY / Wi-Fi).  Every
command usable at privilege 0 is run and its effect checked: HELP, VERSION,
HEAP, STARTCONSOLE, CLS, an unknown command, the privilege gate (FLAG, HMSG,
GPIOCONFIG, TIME), the MAGICKEY / PALANTIR decoys, LOGIN, HRCU, RCU, HANG,
DELETE's file picker, NIMCURROUTE, MOTORPOW, 2FORCENIM, SCREEN,
EXIT / re-activation and REBOOT.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from console_m3503 import exercise_m3503_console
from console_regression import ConsoleHarness, run_with_retry


def run():
    h = ConsoleHarness(
        "GLOBO HD-XS2/Sw_Globo_HD-XS2_SmartHD_1.3.5_2015-05-08.abs",
        "Globo HD-XS2 Smart HD+ 1.3.5 (M3503)",
        boot_insns=6_000_000,               # (deaf from its second 0x01 on, ~10.7 M; sooner under load)
        direct_call=True,
        mask_timer=True,
        attach_sci=True,
    )
    exercise_m3503_console(
        h,
        version_text="SW: 0135 SMART HD+ PVR (0002)",
        control_cmds=["DELETE", "TOUCH", "READ", "COPY", "EXPLORE", "2FORCENIM", "NIMCLOSE", "NIMOPEN",
                      "NIM2CLOSE", "NIM2OPEN", "MOTORPOW", "NIMCURROUTE", "NIMCURROUTE2", "PRINTMEM"],
    )
    h.finish()


if __name__ == "__main__":
    run_with_retry(run)
