#!/usr/bin/env python3
"""The Cabletech URZ0086 firmware V1.2.1 (ALi M3606, chips/m3602.py) starts its SEE co-processor
the way the chip is started (chips/see.py): its bootloader parks the SEE, sends it to the boot
code in its RAM copy (0xA1E8E0D0) -- which the simulator runs on the SEE's own instance: it copies
the SEE's program into place, sets the started flag the bootloader waits for and parks again --
and the application later starts the SEE's program (0xA6000200), which runs on the second core
(see.SeeCore).  The application's drivers then talk to the SEE's through remote calls: its first
call (HLD_BASE.3) comes before its banner, and it attaches the audio / video decoders, the video
outputs, the subtitle, teletext and VBI decoders -- dozens of calls, which the SEE answers, and
calls of the SEE's own, which the main CPU answers (see.Doorbells counts the messages each CPU
took).
"""
import see_regression

see_regression.run(
    "URZ0086_V1.2.1.abs", "the URZ0086 runs its SEE co-processor's program (chips/see.py)",
    family="M3602", starts=[(0xA1E8E0D0, "parked"), (0xA6000200, "run on the SEE core")],
    calls=65, see_calls=15, limit=40_000_000,           # 68 / 18 by ~34 M instructions
    uart=["Application version 1.0.0@SDK4.0ba.7.2_Sab_T_20120115"])     # after its first remote call
