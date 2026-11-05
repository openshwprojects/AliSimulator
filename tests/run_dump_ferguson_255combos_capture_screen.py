"""
Screen regression for the Ferguson Ariva 255 Combo S (Slim) V1.29B6 firmware
(chips/c3505.py, 256 MB DDR3, ALi C3505).

Usage: python run_dump_ferguson_255combos_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Ferguson Ariva 255 Combo S (V1.29B6)",
    "chips": ["ALi C3505 (256 MB)", "AVL6862", "RDA5816", "R840", "FD650K"],
    "shows": ["boots to screen", "second CPU (SEE)", "front panel"],
}

screen_regression.run(
    dump="FERGUSON ARIVA 255 COMBO S/Ferguson_255comboS_V1.29B6_27122021.abs",
    expected="a255s_screen.png",
    boot_limit_s=10 * 60,
    settle_s=30,
    min_ge_ops=22,
    min_colours=60,
    panel_text="nenu",
    max_diff_pct=1.0,
    title="Ferguson Ariva 255 Combo S (V1.29B6)",
    retries=2,
)
