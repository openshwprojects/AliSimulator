"""
Screen regression for the Amiko HD8265+ (System ID 6C000A00, Edision v1.3.17) firmware (slow): boots on
C3505 (chips/c3505.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
hd8265_edision_1317_screen.png.

Usage: python run_dump_hd8265_edision_1317_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO HD8265+/Amiko_HD8265_Edision_1.3.17.abs',
    expected="hd8265_edision_1317_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=' on ',
    max_diff_pct=1.0,
    title="Amiko HD8265+ (System ID 6C000A00, Edision v1.3.17)",
    retries=2,
)
