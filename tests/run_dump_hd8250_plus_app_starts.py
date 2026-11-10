#!/usr/bin/env python3
"""The Amiko HD8250+ 2.4.58 emu update (an ALi M3516A / M3503 rev B, 16 MB SPI
flash, chips/m3503.py) boots from the flash window with its stack in the
cache-as-RAM range until DDR is up, runs its RAM bootloader payload at
0x8141BB94, verifies the chunk CRCs ("check_program finish."), unpacks the
3.25 MB seecode to 0x81889000, sets 0xB8000220 bit 24 to map the upper 240..256
MB DDR window (0x0F000000..0x0FFFFFFF), parks the SEE boot stub at 0xA14187DC,
unpacks the 12.57 MB maincode to 0x80000200 ("success!") and starts the
application.  The application moves its exception vectors (EBase 0x80002000),
starts the SEE's program at 0xAE000200 on the second core (EBase 0x8E002001),
exchanges over 1,500 remote calls with the SEE core, initialises its hs_config
database, unpacks OSD assets via LzmaDecode at 0x80316254, and draws via the 2D
graphics engine.
"""
import see_regression

see_regression.run(
    "AMIKO_HD8250_2.4.58_emu.abs",
    "the Amiko HD8250+ (M3516A / M3503 rev B, 16 MB) runs its application and SEE program and draws via the GE",
    family="M3503", starts=[(0xA14187DC, "parked"), (0xAE000200, "run on the SEE core")],
    calls=1500, see_calls=35, limit=130_000_000,
    uart=["APP  init ok", "check_program finish.", "success!", "hs_config_init"],
    ebase=0x80002000, see_ebase=0x8E002001,
    wait_for=lambda run: run.sim.ge_ops > 0,
    checks=[
        lambda run: (sum(m.startswith("[CAR]") for m in run.logs) == 1,
                     "the bootloader keeps its stack in the cache-as-RAM range, then runs from RAM"),
        lambda run: (run.sim.ge_ops > 0,
                     f"it draws: {run.sim.ge_ops} graphics engine commands"),
    ],
)
