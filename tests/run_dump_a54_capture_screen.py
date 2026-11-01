"""
Screen regression for the Ferguson Ariva 54 official firmware V1.3B1 (slow,
about 1-2 minutes): a compact Full HD H.265/HEVC DVB-S2 satellite receiver on
the single-CPU ALi C3503D SoC (chips/c3503.py: chip word 0x3503D000, internal
S3501-class DVB-S2 demodulator at 0xB804C000, ALi M3031 tuner at I2C 0x20).
Its OSD is drawn through the GE at 0xB800A000 into GMA layer 0 at 0xB8006300
(720 x 576 scaled to 1280 x 720).  With an empty channel database the
application opens its "System Setup" menu while the external FD650K 4-digit
display on GPIO 24 / 23 shows "nenu" ("menu"), captured and compared with
a54_screen.png.  Then the remote's DOWN and RIGHT (extended-NEC coding "ext00")
navigate the menu, compared with a54_nav.png.

Usage: python run_dump_a54_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {"device": "Ferguson Ariva 54 (firmware V1.3B1)", "chips": ["ALi C3503D", "FD650K", "ALi M3031"],
            "shows": ["boots to screen", "front panel", "remote navigation"]}

screen_regression.run(
    dump="FERGUSON ARIVA 54/A54_20190926_V1.3B1.abs",
    expected="a54_screen.png",
    boot_limit_s=20 * 60,
    settle_s=15,
    min_ge_ops=14,
    min_colours=60,
    panel_text="nenu",
    max_diff_pct=1.0,
    title="Ferguson Ariva 54 (firmware V1.3B1)",
    retries=2,
    navigation=[("DOWN", 2000), ("RIGHT", 2000)],
    nav_settle_s=45,      # the periodic "Warning: This STB is not signed!" toast stays static >8 s before closing
)
