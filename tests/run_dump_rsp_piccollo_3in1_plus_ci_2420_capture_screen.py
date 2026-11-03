"""
Screen regression for the Amiko HD8260+ / Edision Piccollo 3in1 Plus CI RSP Mod (System ID 14000A00, v2.4.20) firmware (slow): boots on
M3503 (chips/m3503.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
rsp_piccollo_3in1_plus_ci_2420_screen.png.

Usage: python run_dump_rsp_piccollo_3in1_plus_ci_2420_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO HD8260+/RsP_MOD_ALI3516_14000A00_piccollo_3in1_PLUS_CI_2420.abs',
    expected="rsp_piccollo_3in1_plus_ci_2420_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=' on ',
    max_diff_pct=1.0,
    title="Amiko HD8260+ / Edision Piccollo 3in1 Plus CI RSP Mod (System ID 14000A00, v2.4.20)",
    retries=2,
)
