"""
Screen regression for the Amiko SHD-7900 / SHD-8000 (System ID 06020A00, Synaps v1.5.70 by Dekolte) firmware (slow): boots on
M3602 (chips/m3602.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
shd_7900_8000_synaps_1570_screen.png.

Usage: python run_dump_shd_7900_8000_synaps_1570_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO SHD-8000/AMIKO_SHD-7900-8000_Synaps_1.5.70_by Dekolte.abs',
    expected="shd_7900_8000_synaps_1570_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text='-ON-',
    max_diff_pct=1.0,
    title="Amiko SHD-7900 / SHD-8000 (System ID 06020A00, Synaps v1.5.70 by Dekolte)",
    retries=2,
)
