"""
Screen regression for the Amiko HD8260+ (System ID 14000A00, PowerVu mod by f2f2) firmware (slow): boots on
M3503 (chips/m3503.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
hd8260_f2f2_powervu_screen.png.

Usage: python run_dump_hd8260_f2f2_powervu_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO HD8260+/Amiko_HD8260+32byf2f2.abs',
    expected="hd8260_f2f2_powervu_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=' on ',
    max_diff_pct=1.0,
    title="Amiko HD8260+ (System ID 14000A00, PowerVu mod by f2f2)",
    retries=2,
)
