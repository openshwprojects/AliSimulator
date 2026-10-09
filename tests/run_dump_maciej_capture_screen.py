"""
Screen regression for dump_maciej.bin, the Opticum STB HD N2 (slow, about 3
minutes): boots the firmware into its application, whose first-install wizard
draws its first page with some 350 GE commands (rectangle fills, palette and
RLE bitmap blits, anti-aliased 4-bit font glyphs, executed into RAM by
ge_m36f.py) about 45 s in and then leaves it alone; that screen, read through
the display layer's base-address register (gma_capture.py: a 1280x720 ARGB1555
surface), is compared pixel by pixel with dump_maciej_screen.png.  The TM1650
front panel is decoded alongside.

Usage: python run_dump_maciej_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

screen_regression.run(
    dump="dump_maciej.bin",
    expected="dump_maciej_screen.png",
    boot_limit_s=15 * 60,
    settle_s=60,
    min_ge_ops=340,           # the wizard's first page is complete at 350 commands
    min_colours=16,
    title="Opticum STB HD N2 (dump_maciej.bin)",
)
