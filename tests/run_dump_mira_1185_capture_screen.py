"""
Screen regression for the Amiko Mira Wi-Fi (System ID 67010A00, v1.1.85 EMU)
firmware (slow): boots on C3503 (chips/c3503.py) and renders its 1280 x 720 OSD on
GMA layer 0, compared with mira_1185_screen.png.

Usage: python run_dump_mira_1185_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO MIRA WIFI/AMIKO_Mira_1.1.85_emu.abs",
    expected="mira_1185_screen.png",
    boot_limit_s=180,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=None,
    max_diff_pct=1.0,
    title="Amiko Mira Wi-Fi (System ID 67010A00, v1.1.85 EMU)",
    retries=2,
)
