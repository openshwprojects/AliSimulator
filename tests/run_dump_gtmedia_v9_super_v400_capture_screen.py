"""
Screen regression for the GTMedia V9 Super mass-production firmware V400
(V210.400, 2020-10-20, slow): a Full HD H.265/HEVC DVB-S2 satellite receiver on
the dual-CPU ALi M3505 / C3505 SoC (chips/c3505.py).  Its "M3505---0.1.0"
bootloader writes "boot" to the FD650 4-digit 7-segment display on GPIO 107 / 110
and unpacks Main Code to 0x80000200 and M3505 SEE to 0xA6000200.  With an
unprogrammed serial placeholder in the platform chunk, the application opens its
1280 x 720 "Factory Test Page" OSD, captured and compared with
gtmedia_v9_super_v400_screen.png.

Usage: python run_dump_gtmedia_v9_super_v400_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="GTMEDIA V9 SUPER/GTMedia_V9Super_MP_20201020_v400.bin",
    expected="gtmedia_v9_super_v400_screen.png",
    boot_limit_s=180,
    settle_s=5,
    min_ge_ops=5000,
    min_colours=15,
    panel_text="Strt",
    max_diff_pct=1.0,
    title="GTMedia V9 Super (MP firmware V400)",
    retries=2,
)
