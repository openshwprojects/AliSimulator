#!/usr/bin/env python3
"""The Kruger&Matz KM0186 firmware V1.1.1 (ALi M3606 with chip ID 0x3603, chips/m3602.py) boots its
dual-CPU DVB-T2 application: its bootloader parks the SEE, runs the SEE boot stub at 0xA1E8E0D0 to
copy the SEE image into place, and the main application later starts the SEE co-processor at
0xA6000200 on the second core (chips/see.py SeeCore).  The main CPU and SEE exchange dozens of
remote calls across the inter-processor doorbells (see.Doorbells).
"""
import see_regression

see_regression.run(
    "KM00186_V1.1.1.abs", "the Kruger&Matz KM0186 (M3606) runs its SEE co-processor's program (chips/see.py)",
    family="M3602", chip_id=0x3603, starts=[(0xA1E8E0D0, "parked"), (0xA6000200, "run on the SEE core")],
    calls=65, see_calls=15, limit=45_000_000,           # 68 / 18 by ~30 M instructions
    uart=["Application version 1.0.0@SDK4.0ba.7.2_Sab_T_20120115"])
