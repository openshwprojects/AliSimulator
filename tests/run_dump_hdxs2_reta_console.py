#!/usr/bin/env python3
"""
UART console commands regression test for
GLOBO HD-XS2/Sw_Globo_HD-XS2_Reta_pol_1.3.5_2015-06-22.abs
(Globo HD-XS2 / Opticum Blue XS65, ALi M3503, SW 0135 POL_NETR_PVR, the Polish
retail network build).

The newer ODM console (see console_m3503.py): "startconsole" enters it, HELP
lists commands by category for the current privilege level, privileged
commands pass for unknown ones at level 0, LOGIN / PASSWORD would raise it and
MAGICKEY / PALANTIR are decoys.  Every command usable at privilege 0 is run and
its effect checked: HELP, VERSION, HEAP, STARTCONSOLE, CLS, an unknown
command, the privilege gate (FLAG, HMSG, GPIOCONFIG, TIME), the decoys,
LOGIN, HRCU, RCU, HANG, DELETE's file picker, NIMCURROUTE, MOTORPOW,
2FORCENIM, SCREEN, EXIT / re-activation and REBOOT.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from console_m3503 import exercise_m3503_console
from console_regression import ConsoleHarness, run_with_retry


def run():
    h = ConsoleHarness(
        "GLOBO HD-XS2/Sw_Globo_HD-XS2_Reta_pol_1.3.5_2015-06-22.abs",
        "Globo HD-XS2 Reta POL 1.3.5 (M3503)",
        boot_insns=8_000_000,
        direct_call=True,
        mask_timer=True,
        attach_sci=True,
    )
    exercise_m3503_console(
        h,
        version_text="SW: 0135 POL_NETR_PVR (0162)",
        control_cmds=["DELETE", "TOUCH", "READ", "COPY", "EXPLORE", "2FORCENIM", "STREAM_PLAY", "NIMCLOSE",
                      "NIMOPEN", "NIM2CLOSE", "NIM2OPEN", "MOTORPOW", "NIMCURROUTE", "NIMCURROUTE2", "PRINTMEM"],
    )
    h.finish()


if __name__ == "__main__":
    run_with_retry(run)
