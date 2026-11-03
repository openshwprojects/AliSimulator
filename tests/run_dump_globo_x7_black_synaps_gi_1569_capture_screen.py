"""
Screen regression for the Opticum Globo / Opticum HD X7 (System ID 06000200, GI Black Synaps v1.5.69 gisclub.tv) firmware (slow): boots on
M3602 (chips/m3602.py) and renders its 1280 x 720 OSD on GMA layer 0, compared with
globo_x7_black_synaps_gi_1569_screen.png.

Usage: python run_dump_globo_x7_black_synaps_gi_1569_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump='OPTICUM HD X7/globo_x7_black synaps_gi_1.5.69_gisclub.tv.abs',
    expected="globo_x7_black_synaps_gi_1569_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text='GISCLUB ',
    max_diff_pct=1.0,
    title="Opticum Globo / Opticum HD X7 (System ID 06000200, GI Black Synaps v1.5.69 gisclub.tv)",
    retries=2,
)
