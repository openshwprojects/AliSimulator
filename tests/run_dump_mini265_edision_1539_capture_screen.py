"""
Screen regression for the Amiko Mini HD265 (System ID 24010A00, Edision EMU v1.5.39 by D.) firmware (slow): boots on
C3505 (chips/c3505.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
mini265_edision_1539_screen.png.

Usage: python run_dump_mini265_edision_1539_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO MINI HD265/Amiko-mini265-edision-emu-by_D._v.1539.abs',
    expected="mini265_edision_1539_screen.png",
    boot_limit_s=180,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=' on ',
    max_diff_pct=1.0,
    title="Amiko Mini HD265 (System ID 24010A00, Edision EMU v1.5.39 by D.)",
    retries=2,
)
