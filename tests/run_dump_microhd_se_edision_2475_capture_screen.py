"""
Screen regression for the Amiko Micro HD SE (System ID 10010A88, Edision v2.4.75 by Davor) firmware (slow): boots on
ALi M3511B / M3503 rev B, updates the CH455 front panel to " on ", and
renders its 1280 x 720 OSD on GMA layer 0, compared with microhd_se_edision_2475_screen.png.

Usage: python run_dump_microhd_se_edision_2475_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO MICRO HD SE/AMIKO_MicroHD_SE_Edision_byDavor2475.abs",
    expected="microhd_se_edision_2475_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko Micro HD SE (System ID 10010A88, Edision v2.4.75 by Davor)",
    retries=2,
)
