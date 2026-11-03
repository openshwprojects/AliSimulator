"""
Screen regression for the Amiko Mini Combo HD SE (System ID 14020A88, Synaps v2.4.51 by Dekolte) firmware (slow): boots on
M3503 (chips/m3503.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
minicombohd_se_synaps_2451_screen.png.

Usage: python run_dump_minicombohd_se_synaps_2451_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO MINI COMBO HD SE/AMIKO_MiniComboHD_SE_Synaps_2.4.51_by Dekolte.abs',
    expected="minicombohd_se_synaps_2451_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text='-ON-',
    max_diff_pct=1.0,
    title="Amiko Mini Combo HD SE (System ID 14020A88, Synaps v2.4.51 by Dekolte)",
    retries=2,
)
