"""
Screen regression for the Strong Prima VIII update V1.0.6 (slow, about 7
minutes): the manufacturer's update image of the Prima VIII, whose flash dump
run_dump_prima8_capture_screen.py runs.  Without the dump's channel database
the application opens its first-install wizard ("Welcome": language English,
region United Kingdom, subtitle off, aspect mode auto, scan mode free,
connection HDMI) through the M3801's GE and GMA; that screen is captured
once it has settled and compared with prima8_update_screen.png.  Then the
IR remote -- the flash dump's extended-NEC coding, see ir_remote.IR_CODINGS
-- moves the wizard's highlight down twice; that screen is compared with
prima8_update_nav.png.

Usage: python run_dump_prima8_update_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

screen_regression.run(
    dump="SRT_Prima_VIII_V1.0.6_20160114.abs",
    expected="prima8_update_screen.png",
    boot_limit_s=25 * 60,
    settle_s=30,
    min_ge_ops=18,        # the wizard is drawn by ~20 commands
    max_diff_pct=1.0,
    title="Strong Prima VIII (update V1.0.6)",
    retries=2,
    navigation=[("DOWN", 20000), ("DOWN", 20000)],
)
