"""
Screen regression for the Amiko HD8260+ / RSP Mod Edision (System ID 14000A00, v2.4.55) firmware (slow): boots on
M3503 (chips/m3503.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
rsp_edision_amiko8260_2455_screen.png.

Usage: python run_dump_rsp_edision_amiko8260_2455_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO HD8260+/RSP_MOD_EDISION_amiko8260_14000A00_2455.abs',
    expected="rsp_edision_amiko8260_2455_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=' on ',
    max_diff_pct=1.0,
    title="Amiko HD8260+ / RSP Mod Edision (System ID 14000A00, v2.4.55)",
    retries=2,
)
