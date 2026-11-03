"""
Screen regression for the Amiko Impulse SAT (System ID 20020A00, Synaps v2.3.40 by Dekolte) firmware (slow): boots on
ALi M3510B / M3503 rev B, updates the CH455 front panel to "-ON-", and
renders its 1280 x 720 OSD on GMA layer 0, compared with impulse_sat_synaps_2340_screen.png.

Usage: python run_dump_impulse_sat_synaps_2340_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO IMPULSE SAT/AMIKO_Impulse_SAT_Synaps_2.3.40_by Dekolte.abs",
    expected="impulse_sat_synaps_2340_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text="-ON-",
    max_diff_pct=1.0,
    title="Amiko Impulse SAT (System ID 20020A00, Synaps v2.3.40 by Dekolte)",
    retries=2,
)
