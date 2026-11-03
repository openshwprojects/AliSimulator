"""
Screen regression for the Ferguson Ariva 54 patched firmware V1.3B1_PATCH
(slow, about 1 minute): a compact Full HD H.265/HEVC DVB-S2 satellite receiver
on the single-CPU ALi C3503D SoC (chips/c3503.py: chip word 0x3503D000, internal
S3501-class DVB-S2 demodulator at 0xB804C000, ALi M3031 tuner at I2C 0x20).
Its OSD is drawn through the GE at 0xB800A000 into GMA layer 0 at 0xB8006300
(720 x 576 scaled to 1280 x 720).  With an empty channel database the
application opens its "System Setup" menu while the external FD650K 4-digit
display on GPIO 24 / 23 shows "nenu" ("menu"), captured and compared with
a54_patch_screen.png.

Usage: python run_dump_a54_patch_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="FERGUSON ARIVA 54/Ferguson_A54_V1.3B1_26092019_PATCH.abs",
    expected="a54_patch_screen.png",
    boot_limit_s=20 * 60,
    settle_s=15,
    min_ge_ops=14,
    min_colours=60,
    panel_text="nenu",
    max_diff_pct=1.0,
    title="Ferguson Ariva 54 (firmware V1.3B1_PATCH)",
    retries=2,
)
