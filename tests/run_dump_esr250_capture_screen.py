"""
Screen regression for the Echosonic Mini ESR-250 (slow, about 4 minutes): an
ALi M3510A satellite receiver, run as the M3503 family (chips/m3503.py) --
its bootloader ("3510-r1362") is the Globo HD-XS2's XIP kind, with its stack
in cache-as-RAM lines until the DDR is up, and its set-up code branches on
the chip ID 0x3503.  Its single-CPU application draws its "Quick Setup" menu
through the GE some 100 M instructions in, which is captured and compared
with esr250_screen.png.  A task of the application keeps the OSD layer off
unless the NIM device reports an S3501's chip ID: the chip's internal
demodulator (InternalDemod: its registers at 0xB8028000 + the register
number) answers it.  Then the remote's DOWN -- a standard NEC frame whose
key-table code keeps the first address byte (ir_remote's "necfirst") --
moves the highlight from Menu Language to First Audio, compared with
esr250_nav.png.

Usage: python run_dump_esr250_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

FEATURED = {"device": "Echosonic Mini ESR-250", "chips": ["ALi M3510A (as M3503)"],
            "shows": ["boots to screen", "reacts to remote"]}

screen_regression.run(
    dump="Echosonic_Mini_ESR-250__GD25Q32B--DVBS2-M3510A-A3__OK--OK.BIN",
    expected="esr250_screen.png",
    boot_limit_s=20 * 60,
    settle_s=30,
    min_ge_ops=14,            # the Quick Setup menu is complete at 14 commands
    min_colours=16,
    title="Echosonic Mini ESR-250",
    navigation=[("DOWN", 1000)],
)
