"""
Screen regression for the Opticum Globo / Opticum HD X4 220 (System ID 06020200, GI Black Synaps v1.5.74 gisclub.tv) firmware (slow): boots on
M3602 (chips/m3602.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
globo_x4_black_synaps_gi_1574_screen.png.

Usage: python run_dump_globo_x4_black_synaps_gi_1574_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='OPTICUM HD X4 220/globo_x4_black synaps_gi_1.5.74_gisclub.tv.abs',
    expected="globo_x4_black_synaps_gi_1574_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text='boot',
    max_diff_pct=1.0,
    title="Opticum Globo / Opticum HD X4 220 (System ID 06020200, GI Black Synaps v1.5.74 gisclub.tv)",
    retries=2,
)
