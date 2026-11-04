"""
Screen regression for the Amiko Mini Combo HD SE (v2.3.45 EMU, System ID 14020A00,
slow): boots on ALi M3516C / M3503 rev B, updates the CH455 front panel to
" on ", and renders its 1280 x 720 OSD on GMA layer 0, compared with
minicombohd_se_2345_screen.png.

Usage: python run_dump_minicombohd_se_2345_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO MINI COMBO HD SE/AMIKO_MiniComboHD_SE_2.3.45_emu.abs",
    expected="minicombohd_se_2345_screen.png",
    boot_limit_s=180,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko Mini Combo HD SE (v2.3.45 EMU)",
    retries=2,
)
