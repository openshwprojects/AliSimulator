"""
Screen regression for the Amiko CHD8270+ Galaxy 2.4.89 firmware
(System ID 14000A00, ALi M3516A / M3503 rev B, 256 MB DDR3, 16 MB SPI flash).

Usage: python run_dump_chd8270_galaxy_2489_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko CHD8270+ Galaxy (v2.4.89)",
    "chips": ["ALi M3516A / M3503", "TM1650"],
    "shows": ["boots to screen", "second CPU (SEE)", "front panel"],
}

screen_regression.run(
    dump="AMIKO CHD8270+/amiko_14000A00_galaxy_2.4.89_gisclub.tv.abs",
    expected="chd8270_galaxy_2489_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko CHD8270+ Galaxy (v2.4.89)",
    retries=1,
)
