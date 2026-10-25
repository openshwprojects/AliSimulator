#!/usr/bin/env python3
"""The Ferguson Ariva 204 firmware V1.3B3 (ALi C3505 / M3527, chips/c3505.py) boots through the
boot-ROM path with the C3505's chip ID, unpacks its main and SEE LZMA segments, moves its exception
vectors (CP0 EBase 0x80002000), and starts its SEE co-processor's program at 0xA6000200 on the
second core (chips/see.py SeeCore, EBase 0x86002001).  The main CPU and SEE exchange remote calls
through the C3505 doorbells and print the SDK application banner.
"""
import see_regression

see_regression.run(
    "Ferguson_A204_V1.3B3.abs", "the Ferguson Ariva 204 (C3505) runs its application and the SEE's program",
    family="C3505", starts=[(0xA6000200, "run on the SEE core")],
    calls=50, see_calls=30, limit=40_000_000,           # 76 / 53 by ~12 M instructions
    uart=["SDK4.0ba.4.0_20101217"],
    ebase=0x80002000, see_ebase=0x86002001)
