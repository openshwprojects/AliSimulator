"""
Screen regression for the Ferguson Ariva T760i update V1.5B4 (slow, about 5
minutes): a C3505 whose SEE program runs on the second core (chips/see.py),
with its AltoBeam ATBM7812 demodulator on the I2C bus (demods.py, the
sidecar's demodModel: without it the NIM driver retried its power-on for
~125 M instructions).  Its OSD is the newer display engine's layer at
0xB8006900, set up through register lists (gma_capture.de_layers), here an
ARGB8888 bitmap of 1280 x 720.  With its empty channel database the
application opens its first-install wizard ("Welcome": region Poland,
English, 720p_60, "OK (10 sec)" counting down), then starts its automatic
channel search ("Auto Scan"); this test captures the wizard as soon as it
is up (0.5 M instruction slices) and compares it with t760i_screen.png.
Then the front panel's keys (its FD650K, the T750i's key map:
front_panel._FERGUSON_KEYS) leave the wizard for the main menu's "Edit
Channel" page (KI4/DIG2, exit) and highlight "Favorite" (KI4/DIG1, down),
compared with t760i_nav.png.

Usage: python run_dump_t760i_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression
from tm1650_decoder import TM1650Decoder

# this box's card at the top of the report (run_all_tests.py reads it from the source)
FEATURED = {"device": "Ferguson Ariva T760i (update V1.5B4)", "chips": ["ALi C3505", "ATBM7812"],
            "shows": ["boots to screen", "second CPU (SEE)", "panel keys"]}

screen_regression.run(
    dump="Ferguson_T760i_V1.5B4-14092021.abs",
    expected="t760i_screen.png",
    boot_limit_s=25 * 60,
    settle_s=0,           # the wizard counts its "OK (10 sec)" down: the screen of the slice that shows it
    min_ge_ops=5,
    min_colours=60,       # the drawn wizard: some 80 colours
    max_diff_pct=1.0,
    slice_instructions=500_000,
    probe_s=0,
    title="Ferguson Ariva T760i (update V1.5B4)",
    retries=2,
    # panel exit before the countdown starts the channel search, then panel down
    navigation=[(("panel", TM1650Decoder.key_code(4, 2, pressed=False)), 100000),
                (("panel", TM1650Decoder.key_code(4, 1, pressed=False)), 2000)],
)
