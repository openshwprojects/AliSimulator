#!/usr/bin/env python3
"""The Amiko SHD-8110 (Synaps v1.6.95 by Dekolte, System ID 0B000A00, ALi M3601A /
M3606 / C3603 with 128 MB DDR and 8 MB SPI flash, chips/m3602.py) boots its
"M3601A 1.1.3" bootloader, parks the SEE boot stub at 0xA1E9103C, unpacks its
SEE program ("M3606 SEE") to 0xA7000200 and maincode(AV) to 0x80000200, starts
the SEE core at 0xA7000200, configures the ALi S3501 DVB-S2 demodulator at I2C
0x33, and exchanges remote calls with the SEE co-processor.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import see_regression

see_regression.run(
    "AMIKO SHD-8110/AMIKO_SHD-8110_Synaps_1.6.95_by Dekolte.abs",
    "the Amiko SHD-8110 (Synaps v1.6.95 by Dekolte) (8 MB flash, M3601A / C3603) runs its application and SEE at 0xA7000200",
    family="M3602",
    chip_id=0x3603,
    starts=[(0xA1E9103C, "parked"), (0xA7000200, "run on the SEE core")],
    calls=30,
    see_calls=30,
    limit=80_000_000,
    uart=[
        "APP  init ok",
        "---HC164 attach OK--",
        "hs_config_init",
        "stb_tuner_type = 1, stb_board_type =6.",
        "sys_ic_get_chip_id=0x10047",
    ],
    ebase=0x80000000,
    see_ebase=0x80000001,
    wait_for=lambda r: "sys_ic_get_chip_id=0x10047" in r.text,
    checks=[
        lambda r: (
            0x33 in r.sim.i2c_devices and len(r.sim.i2c_devices[0x33].regs) > 4,
            f"ALi S3501 DVB-S2 demodulator configured at I2C 0x33 "
            f"({len(r.sim.i2c_devices[0x33].regs) if 0x33 in r.sim.i2c_devices else 0} registers)",
        ),
    ],
)
