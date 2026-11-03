"""
Screen regression for the Amiko Mini HD (System ID 0A070A00, GI Black Synaps v1.7.14 gisclub.tv) firmware (slow): boots on
M3602 (chips/m3602.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
amiko_0a070a00_gi_black_synaps_1714_screen.png.

Usage: python run_dump_amiko_0a070a00_gi_black_synaps_1714_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='AMIKO MINI HD/amiko_0A070A00_black synaps_gi_1.7.14_gisclub.tv.abs',
    expected="amiko_0a070a00_gi_black_synaps_1714_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=None,
    max_diff_pct=1.0,
    title="Amiko Mini HD (System ID 0A070A00, GI Black Synaps v1.7.14 gisclub.tv)",
    retries=2,
)
