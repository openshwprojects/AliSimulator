"""
Screen regression for the Amiko Micro HD (System ID 0E000A00, Synaps v1.5.40 by Dekolte) firmware (slow): boots on
ALi M3612 / S3811, updates the CH455 front panel to "-ON-", and
renders its 1280 x 720 OSD on GMA layer 0, compared with microhd_synaps_1540_screen.png.

Usage: python run_dump_microhd_synaps_1540_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO MICRO HD/AMIKO_MicroHD_Synaps_1.5.40_by Dekolte.abs",
    expected="microhd_synaps_1540_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=10,
    panel_text="-ON-",
    max_diff_pct=1.0,
    title="Amiko Micro HD (System ID 0E000A00, Synaps v1.5.40 by Dekolte)",
    retries=2,
)
