"""
Screen regression for the Opticum HD X402p / X403p 220 (System ID 06020200, Synaps RC1 v1.5.48) firmware (slow): boots on
M3602 (chips/m3602.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
opticum_x402p_403p_synaps_rc1_1548_screen.png.

Usage: python run_dump_opticum_x402p_403p_synaps_rc1_1548_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='OPTICUM HD X403P/Opticum HD X402p-403p_220_ps_synaps_rc1_1.5.48.abs',
    expected="opticum_x402p_403p_synaps_rc1_1548_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=' on ',
    max_diff_pct=1.0,
    title="Opticum HD X402p / X403p 220 (System ID 06020200, Synaps RC1 v1.5.48)",
    retries=2,
)
