"""
Screen regression for the Amiko CHD8270+ (System ID 14000A00, v2.3.45 EMU) firmware
(slow): boots on M3503 (chips/m3503.py) and renders its 1280 x 720 OSD on GMA
layer 0, compared with chd8270_2345_emu_screen.png.

Usage: python run_dump_chd8270_2345_emu_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO CHD8270+/AMIKO_CHD8270_2.3.45_emu.abs",
    expected="chd8270_2345_emu_screen.png",
    boot_limit_s=120,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko CHD8270+ (System ID 14000A00, v2.3.45 EMU)",
    retries=4,
)
