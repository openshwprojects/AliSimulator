#!/usr/bin/env python3
"""The Ferguson Ariva T750i firmware V1.20B2 (an M3821 with an XIP bootloader, chips/m3821.py)
boots from the flash window like an M3801 -- its stack in the cache-as-RAM range until the DDR is
up, its CP0 set-up run through the flash's cached view -- takes the M3821 path for the chip ID
0x3821, starts its SEE co-processor through the SEE's boot code (chips/see.py), unpacks the main
code ("success!") and starts the application, which moves its exception vectors (EBase 0x80002000)
and starts the SEE's program on the second core (see.SeeCore).  The application then attaches its
drivers through remote calls the SEE answers, opens its database and starts drawing.  The chip
reads as revision B: before that the application leaves its OSD layers' GMA device to the SEE and
calls it directly, its main CPU jumping into the SEE's code (watched here).
"""
from unicorn import UC_HOOK_CODE

import see_regression

SEE_CODE = (0x86000000, 0x87FFFFFF)             # the SEE's private memory
in_see_code = []


def setup(sim):
    sim.mu.hook_add(UC_HOOK_CODE, lambda uc, address, size, user_data: in_see_code.append(address) if not in_see_code
                    else None, begin=SEE_CODE[0], end=SEE_CODE[1])


see_regression.run(
    "Ferguson_T750i_V1.20B2_18092019.abs",
    "the Ferguson T750i (M3821, XIP bootloader) runs its application and the SEE's program",
    family="M3821", starts=[(0xA1017804, "parked"), (0xA6000200, "run on the SEE core")],
    calls=140, see_calls=20, limit=100_000_000,         # ~150 / 24 by ~80 M instructions
    uart=["HW BootLoader APP  init!", "success!", "DB_init() success!"], ebase=0x80002000,
    setup=setup, wait_for=lambda run: run.sim.ge_ops > 0, abort=lambda run: in_see_code,
    checks=[lambda run: (getattr(run.sim.chip, "xip", False), "the M3821 family recognises its XIP bootloader"),
            lambda run: (run.sim.ge_ops > 0, f"it draws: {run.sim.ge_ops} graphics engine commands"),
            lambda run: (not in_see_code, "the main CPU stays out of the SEE's code"
                         + (f" (0x{in_see_code[0]:08X})" if in_see_code else ""))])
