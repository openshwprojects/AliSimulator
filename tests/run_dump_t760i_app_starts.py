#!/usr/bin/env python3
"""The Ferguson Ariva T760i firmware V1.5B4 (ALi C3505, chips/c3505.py) boots through the M3821
family's boot-ROM path with the C3505's chip ID, waits for the ready bit 8 of 0xB8000300, unpacks
its application and starts it: the application moves its exception vectors (CP0 EBase
0x80002000) -- past its ~900-NOP entry at 0x80000200, which fast mode runs under a code hook --
and starts its SEE co-processor's program at 0xA6000200 on the second core (chips/see.py
SeeCore), which moves its own (EBase 0x86002000, CPU number 1).  The application's drivers then
talk to the SEE's through remote calls with the newer chips' doorbells: it prints its banner and
the main CPU and the SEE answer each other's calls.
"""
import see_regression

see_regression.run(
    "Ferguson_T760i_V1.5B4-14092021.abs", "the Ferguson T760i (C3505) runs its application and the SEE's program",
    family="C3505", starts=[(0xA6000200, "run on the SEE core")],
    calls=50, see_calls=30, limit=110_000_000,          # ~60 / 54 by ~80 M instructions
    uart=["Application version 1.0.0@SDK4.0ia.17.15_20171123bycompileserveradministrator"],
    ebase=0x80002000, see_ebase=0x86002001)
