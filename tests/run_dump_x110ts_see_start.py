#!/usr/bin/env python3
"""The Opticum X110TS / X110TSE update 1.4.0C (an ALi M3606 board whose SoC reads the chip ID 0x3603,
its sidecar's chipId; chips/m3602.py) boots like the Cabletech URZ0086: its bootloader starts the
SEE co-processor through the SEE's boot code (0xA1E8F450, chips/see.py) and starts the
application, which -- given the chip ID it checks for, instead of rebooting -- starts the SEE's
program (0xA6000200) on the second core (see.SeeCore) and attaches its drivers through remote calls
the SEE answers.  Without the SEE's program its first message went unacknowledged and it stopped
at its SDBBP assertion (0x801A9608).
"""
from unicorn import UC_HOOK_CODE

import see_regression

ASSERTION = 0x801A9608
asserted = []


def setup(sim):
    sim.mu.hook_add(UC_HOOK_CODE, lambda uc, address, size, user_data: asserted.append(sim.instruction_count),
                    begin=ASSERTION, end=ASSERTION + 3)


see_regression.run(
    "Software_Patch_X110TS_X110TSE_1.4.0C_PVR_UNI_ENG_2015-05-04.abs",
    "the Opticum X110TS (M3606, chip ID 0x3603) runs its SEE's program",
    family="M3602", chip_id=0x3603, starts=[(0xA1E8F450, "parked"), (0xA6000200, "run on the SEE core")],
    calls=75, see_calls=30, limit=75_000_000,           # ~80 / 36 by ~60 M instructions
    uart=["Application version 1.0.0@SDK4.0ba.8.0_Combo_20120530"],
    setup=setup, abort=lambda run: asserted,
    checks=[lambda run: (not asserted, "no SDBBP assertion: the SEE acknowledges every message")])
