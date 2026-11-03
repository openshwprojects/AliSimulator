"""
Screen regression for the Amiko Mini HD SE (System ID 10000A00, Synaps v2.3.40 by Dekolte) firmware (slow): boots on
M3503 (chips/m3503.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
minihd_se_synaps_2340_screen.png.

Usage: python run_dump_minihd_se_synaps_2340_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO MINI HD SE/AMIKO_MiniHD_SE_Synaps_2.3.40_by Dekolte.abs',
    expected="minihd_se_synaps_2340_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text='-ON-',
    max_diff_pct=1.0,
    title="Amiko Mini HD SE (System ID 10000A00, Synaps v2.3.40 by Dekolte)",
    retries=2,
)
