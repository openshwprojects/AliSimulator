"""
Screen regression for the Cabletech URZ0194S dump (slow, about 6 minutes):
boots CABLETECH_urz0194s_v1_0_8.bin -- the URZ0083Q's hardware family with a
newer application (Libcore 8.1j, September 2013) -- into its application,
which scans its flash channel database for some 11 minutes before it draws its
first screen.  The screen is captured and compared with
urz0194s_screen.png (with a small tolerance), the TM1628-class front
panel must read "noCH" (no channels) by then, after " ON " and "----", and the
front panel's keys drive the wizard -- differently from the URZ0083Q: on this
box KS9/K1 steps the highlighted Region value (Polska -> Hungary -> Italian,
and the whole wizard switches language with it) and KS9/K2 is power
(standby, panel "oFF "); two steps make it the Italian wizard.  Then the IR
remote (the URZ0083Q's "necfirst" coding, see ir_remote.IR_CODINGS) opens the
main menu with MENU and moves on with DOWN; that screen is compared with
urz0194s_nav.png.  (With the "plain" coding used before, only MENU worked:
it is the one key whose frame is the same under both.)

Usage: python run_dump_urz0194s_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression
from tm1628_decoder import TM1628Decoder

RIGHT = TM1628Decoder.key_code(9, 1)         # steps the highlighted value (KS9/K2 is power)

# this box's card at the top of the report (run_all_tests.py reads it from the source)
FEATURED = {"device": "Cabletech URZ0194S", "chips": ["ALi M3801", "TM1628-class", "MxL603"],
            "shows": ["boots to screen", "shows noCH on its panel", "reacts to panel keys", "reacts to remote"]}

screen_regression.run(
    dump="CABLETECH_urz0194s_v1_0_8.bin",
    expected="urz0194s_screen.png",
    boot_limit_s=60 * 60,
    settle_s=90,
    min_ge_ops=60,
    max_diff_pct=1.0,
    panel_text="noCH",
    title="Cabletech URZ0194S",
    retries=2,            # its byte-wise flash scan hits the sporadic async-stop race more often
    navigation=[(("panel", RIGHT), 2000), (("panel", RIGHT), 2000), ("MENU", 100000), ("DOWN", 5000)],
)
