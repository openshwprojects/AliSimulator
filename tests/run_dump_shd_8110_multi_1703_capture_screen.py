"""
Screen regression for the Amiko SHD-8110 (System ID 0B000A00, Multi v1.7.03 by Dekolte) firmware (slow): boots on
M3602 (chips/m3602.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
shd_8110_multi_1703_screen.png.

Usage: python run_dump_shd_8110_multi_1703_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO SHD-8110/AMIKO_SHD-8110_Multi_1.7.03_by Dekolte.abs',
    expected="shd_8110_multi_1703_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=None,
    max_diff_pct=1.0,
    title="Amiko SHD-8110 (System ID 0B000A00, Multi v1.7.03 by Dekolte)",
    retries=2,
)
