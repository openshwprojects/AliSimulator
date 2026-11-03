"""
Screen regression for the Amiko Micro HD SE (System ID 10010A00, Synaps v2.3.40 by Dekolte) firmware (slow): boots on
ALi M3511B / M3503 rev B, updates the CH455 front panel to "-ON-", and
renders its 1280 x 720 OSD on GMA layer 0, compared with microhd_se_synaps_2340_screen.png.

Usage: python run_dump_microhd_se_synaps_2340_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO MICRO HD SE/AMIKO_MicroHD_SE_Synaps_2.3.40_by Dekolte.abs",
    expected="microhd_se_synaps_2340_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text="-ON-",
    max_diff_pct=1.0,
    title="Amiko Micro HD SE (System ID 10010A00, Synaps v2.3.40 by Dekolte)",
    retries=2,
)
