"""
Screen regression for the Ferguson Ariva 255 Combo official firmware V1.32B4
(slow, about 1-2 minutes): a Full HD H.265/HEVC 10-bit DVB-S2 + DVB-T2/C CI+
combo receiver on the ALi C3505 SoC with 256 MB DDR3 (chips/c3505.py).  Its
bootloader sets 0xB8000220 bit 24 before entering maincode so physical
0x0F000000..0x0FFFFFFF becomes the top 16 MB of DDR (holding its display-engine
ARGB8888 framebuffers) while flash is read from 0xBF800000..0xBFFFFFFF, and the
application runs its SEE program at 0xAE000200 on the second core (chips/see.py)
and initialises both the internal S3505 DVB-S2 demodulator + ALi M3031 tuner
(I2C 0x20) and the external Availink AVL6862 DVB-T2/C demodulator (I2C 0x14 on
SCB3 at 0xB8018D00) + Rafael Micro R836 tuner (I2C 0x3A).  With an empty
channel database it opens its 1280 x 720 "System Setup" OSD menu while the
FD650K front panel on GPIO 107 / 108 shows "nenu" ("menu"), captured and
compared with a255_screen.png.  Then the remote's DOWN and RIGHT (extended-NEC
coding "ext00") navigate the menu, compared with a255_nav.png.

Usage: python run_dump_a255_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Ferguson Ariva 255 Combo (firmware V1.32B4)",
    "chips": ["ALi C3505 (256 MB)", "AVL6862", "ALi M3031", "R836", "FD650K"],
    "shows": ["boots to screen", "second CPU (SEE)", "front panel", "remote navigation"],
}

screen_regression.run(
    dump="FERGUSON ARIVA 255 COMBO/Ferguson_A255_V1.32B4.abs",
    expected="a255_screen.png",
    boot_limit_s=10 * 60,
    settle_s=15,
    min_ge_ops=14,
    min_colours=60,
    panel_text="nenu",
    max_diff_pct=1.0,
    title="Ferguson Ariva 255 Combo (firmware V1.32B4)",
    retries=2,
    navigation=[("DOWN", 2000), ("RIGHT", 2000)],
    nav_settle_s=45,
)
