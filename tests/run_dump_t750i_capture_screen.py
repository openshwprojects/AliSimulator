"""
Screen regression for the Ferguson Ariva T750i firmware V1.20B2 (slow, about
5 minutes): an M3821 with the SDK's dual-CPU build, whose SEE program runs on
the second core (chips/see.py).  Its OSD is not the M36F GMA's but a layer
of the newer display engine at 0xB8006900, which the drivers set up through
register lists in RAM the display engine loads every frame (gma_capture.py:
de_registers / de_layers) -- an ARGB1555 bitmap of 1280 x 720.  The
application, with its empty channel database, opens its first-install
wizard ("Witamy": region, language, display mode, aspect ratio, free-to-air
only, standby mode; "Ok (5 sec)" counting down); this test captures the
wizard as soon as it is on the screen (0.5 M instruction slices) and
compares it with t750i_screen.png.  Then the front panel's keys (its FD650K:
the PAN_FD650K driver's switch maps KI4/DIG2 to exit, KI4/DIG1 to down,
front_panel._FERGUSON_KEYS) leave the wizard for the main menu's "Edytuj
kanały" page (no item highlighted) and highlight its first item, "Lista
kanałów TV", compared with t750i_nav.png.

Usage: python run_dump_t750i_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression
from tm1650_decoder import TM1650Decoder

# this box's card at the top of the report (run_all_tests.py reads it from the source)
FEATURED = {"device": "Ferguson Ariva T750i (firmware V1.20B2)", "chips": ["ALi M3821", "MxL603"],
            "shows": ["boots to screen", "second CPU (SEE)", "panel keys"]}

screen_regression.run(
    dump="Ferguson_T750i_V1.20B2_18092019.abs",
    expected="t750i_screen.png",
    boot_limit_s=20 * 60,
    settle_s=0,           # the wizard counts its "Ok (3 sec)" down: the screen of the slice that shows it
    min_ge_ops=10,
    min_colours=60,       # the drawn wizard: some 80 colours
    max_diff_pct=1.0,
    slice_instructions=500_000,
    probe_s=0,
    title="Ferguson Ariva T750i (firmware V1.20B2)",
    retries=2,
    # panel exit before the countdown starts the channel search, then panel down
    navigation=[(("panel", TM1650Decoder.key_code(4, 2, pressed=False)), 100000),
                (("panel", TM1650Decoder.key_code(4, 1, pressed=False)), 2000)],
)
