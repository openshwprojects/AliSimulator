"""
Screen regression for the Amiko Mini HD Combo (System ID 0E060A00, Galaxy v1.6.12) firmware (slow): boots on
M3801 (chips/m3801.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
minihd_combo_galaxy_1612_screen.png.

Usage: python run_dump_minihd_combo_galaxy_1612_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO MINI HD COMBO/AMIKO_MiniHD_Combo_Galaxy_1.6.12.abs',
    expected="minihd_combo_galaxy_1612_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text='-ON-',
    max_diff_pct=1.0,
    title="Amiko Mini HD Combo (System ID 0E060A00, Galaxy v1.6.12)",
    retries=2,
)
