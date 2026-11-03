"""
Screen regression for the Amiko HD8265+ (System ID 6C000A00, Edision EMU v1.4.23 by Davor) firmware (slow): boots on
C3505 (chips/c3505.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
hd8265_edision_1423_screen.png.

Usage: python run_dump_hd8265_edision_1423_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO HD8265+/Amiko_8265_emu_edision_1423_byDavor.abs',
    expected="hd8265_edision_1423_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=' on ',
    max_diff_pct=1.0,
    title="Amiko HD8265+ (System ID 6C000A00, Edision EMU v1.4.23 by Davor)",
    retries=2,
)
