"""
Screen regression for the Amiko Micro HD SE (System ID 10010A88, Edision v2.4.86) firmware (slow): boots on
M3503 (chips/m3503.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
micro_hd_se_edision_2486_screen.png.

Usage: python run_dump_micro_hd_se_edision_2486_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO MICRO HD SE/AMIKO MICRO HD SE Edision_v.2486.abs',
    expected="micro_hd_se_edision_2486_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=' on ',
    max_diff_pct=1.0,
    title="Amiko Micro HD SE (System ID 10010A88, Edision v2.4.86)",
    retries=2,
)
