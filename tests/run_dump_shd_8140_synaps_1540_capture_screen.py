"""
Screen regression for the Amiko SHD-8140 CX E (System ID 0E020A00, Synaps v1.5.40 by Dekolte) firmware (slow): boots on
M3801 (chips/m3801.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
shd_8140_synaps_1540_screen.png.

Usage: python run_dump_shd_8140_synaps_1540_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO SHD-8140/AMIKO_SHD-8140_Synaps_1.5.40_by Dekolte.abs',
    expected="shd_8140_synaps_1540_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text='-ON-',
    max_diff_pct=1.0,
    title="Amiko SHD-8140 CX E (System ID 0E020A00, Synaps v1.5.40 by Dekolte)",
    retries=2,
)
