"""
Screen regression for the Amiko HD8260+ (System ID 14000A00, Edision EMU v2.4.83) firmware (slow): boots on
M3503 (chips/m3503.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
hd8260plus_edision_2483_screen.png.

Usage: python run_dump_hd8260plus_edision_2483_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO HD8260+/amiko_hd8260plus_edision_emu_2483.abs',
    expected="hd8260plus_edision_2483_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=' on ',
    max_diff_pct=1.0,
    title="Amiko HD8260+ (System ID 14000A00, Edision EMU v2.4.83)",
    retries=2,
)
