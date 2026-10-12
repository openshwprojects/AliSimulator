#!/usr/bin/env python3
"""The Globo HD-XS2 / Opticum Blue XS65 satellite update 1.3.5 "SmartHD" (an ALi M3503,
chips/m3503.py) boots from the flash window with its stack in the cache-as-RAM range until the DDR
is up, starts its SEE co-processor through the SEE's boot code (chips/see.py), unpacks the main
code and starts the application, which moves its exception vectors (EBase 0x80002000) and starts
the SEE's program on the second core (see.SeeCore), which moves its own (EBase 0x86002000, CPU
number 1).  The two talk through remote calls with the newer chips' doorbells (see.Doorbells: the
ring in the +0x37 byte).  Both are silent builds -- the UART gets one 0x01 byte and one line --, so
the test follows the boot by the SEE starts, the CP0 EBase and the messages each CPU took.
"""
import see_regression

see_regression.run(
    "Sw_Globo_HD-XS2_SmartHD_1.3.5_2015-05-08.abs",
    "the Globo HD-XS2 (M3503, XIP bootloader) runs its application and the SEE's program",
    family="M3503", starts=[(0xA1016804, "parked"), (0x86000200, "run on the SEE core")],
    calls=70, see_calls=30, limit=110_000_000,          # ~74 / 34 by ~55-80 M instructions
    ebase=0x80002000, see_ebase=0x86002001,
    checks=[lambda run: (sum(m.startswith("[CAR]") for m in run.logs) == 1,
                         "the bootloader keeps its stack in the cache-as-RAM range, then runs from RAM")])
