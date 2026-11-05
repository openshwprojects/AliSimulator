"""
Screen regression for GTMedia / Freesat V9 Super v373 firmware
(dual-CPU ALi M3505 / C3505 SoC, chips/c3505.py).

Usage: python run_dump_gtmedia_v9_super_v373_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "GTMedia / Freesat V9 Super v373",
    "chips": ["ALi M3505 / C3505", "AV2011", "FD650"],
    "shows": ["boots to screen", "second CPU (SEE)", "front panel"],
}

screen_regression.run(
    dump="GTMEDIA V9 SUPER/Freesat_V9Super_v373.bin",
    expected="gtmedia_v9_super_v373_screen.png",
    boot_limit_s=180,
    settle_s=5,
    min_ge_ops=100,
    min_colours=15,
    panel_text="Strt",
    max_diff_pct=1.0,
    title="GTMedia / Freesat V9 Super v373",
    retries=1,
)
