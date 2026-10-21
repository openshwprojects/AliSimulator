#!/usr/bin/env python3
"""
UART console commands regression test for
GLOBO HD-XS2/Software_GER_RETA_NETWORK_1.2.8_REV.778_RC1_2014-11-28.abs
(Globo HD-XS2, ALi M3503, SW 0128 GER_NETR_PVR, the German retail network
build 1.2.8 RC1).

The newer ODM console (see console_m3503.py), the GER table (Wi-Fi, music and
EFU commands; at privilege 0 its Control category has no 2FORCENIM,
STREAM_PLAY, NIMCURROUTE2 or PRINTMEM).  This build gets to the point where its
UART input stops reaching input_task (the third 0x01 byte it prints, ~8 M
instructions) much sooner than the 1.3.5 builds, so the harness takes the
console over at its second 0x01 (~5.5 M; boot_until) instead of at a fixed
count.  Every command usable at privilege 0 is run and its effect checked:
HELP, VERSION, HEAP, STARTCONSOLE, CLS, an unknown command, the privilege gate
(FLAG, HMSG, GPIOCONFIG, TIME), the MAGICKEY / PALANTIR decoys, LOGIN, HRCU,
RCU, HANG, DELETE's file picker, NIMCURROUTE, MOTORPOW, SCREEN,
EXIT / re-activation and REBOOT.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from console_m3503 import exercise_m3503_console
from console_regression import ConsoleHarness, run_with_retry


def run():
    h = ConsoleHarness(
        "GLOBO HD-XS2/Software_GER_RETA_NETWORK_1.2.8_REV.778_RC1_2014-11-28.abs",
        "Globo HD-XS2 GER network 1.2.8 RC1 (M3503)",
        boot_insns=7_500_000,
        boot_until=lambda uart: uart.count("\x01") >= 2,
        boot_step=500_000,
        direct_call=True,
        mask_timer=True,
        attach_sci=True,
    )
    exercise_m3503_console(
        h,
        version_text="SW: 0128 GER_NETR_PVR (0202)",
        control_cmds=["DELETE", "TOUCH", "READ", "COPY", "EXPLORE", "NIMCLOSE", "NIMOPEN", "NIM2CLOSE",
                      "NIM2OPEN", "MOTORPOW", "NIMCURROUTE"],
    )
    h.finish()


if __name__ == "__main__":
    run_with_retry(run)
