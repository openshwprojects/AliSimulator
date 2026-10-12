"""
Screen regression for the Opticum X110TS / X110TSE official update 1.4.0C
PVR (slow, about 5 minutes): an M3606 twin-tuner satellite PVR, whose SEE
co-processor's program runs on the second core (chips/see.py) and draws
the OSD the application asks for -- through the same M36F GMA layers as the
M3801's (gma_capture.py).  The application shows the banner of its first
channel ("TVP 1 (13.0E Hotbird13)") and then, with no signal, a red "No
Signal!" box; that screen is captured and compared with x110ts_screen.png.
Its chip, a C3603, reads a product with the DVB-S2 demodulator and has its
S3501 on the I2C bus (chips/m3602.py): without them the application's own
hardware check hid the OSD layer, and the screen stayed black.

Usage: python run_dump_x110ts_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

# this box's card at the top of the report (run_all_tests.py reads it from the source)
FEATURED = {"device": "Opticum X110TS (official update 1.4.0C)", "chips": ["ALi M3606 (C3603)", "S3501"],
            "shows": ["boots to screen", "second CPU (SEE)"]}

screen_regression.run(
    dump="OPTICUM X110TS/Software_Patch_X110TS_X110TSE_1.4.0C_PVR_UNI_ENG_2015-05-04.abs",
    expected="x110ts_screen.png",
    boot_limit_s=20 * 60,
    settle_s=60,
    min_ge_ops=600,       # the no-signal box is up (the banner took the first ~300 commands)
    max_diff_pct=1.0,
    title="Opticum X110TS (official update 1.4.0C)",
    retries=2,
)
