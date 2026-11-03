"""
Screen regression for the Amiko Mini Combo Extra RCA (System ID 6A000A00, Edision v1.3.75 by Scepa & Davor) firmware (slow): boots on
C3505 (chips/c3505.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
mini_combo_extra_rca_edision_1375_screen.png.

Usage: python run_dump_mini_combo_extra_rca_edision_1375_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO MINI COMBO EXTRA/Amiko_mini_combo_EXTRA_RCA-Edision_By_Scepa_and_Davor_1375.abs',
    expected="mini_combo_extra_rca_edision_1375_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=' on ',
    max_diff_pct=1.0,
    title="Amiko Mini Combo Extra RCA (System ID 6A000A00, Edision v1.3.75 by Scepa & Davor)",
    retries=2,
)
