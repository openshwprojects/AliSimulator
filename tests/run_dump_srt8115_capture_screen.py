"""
Screen regression for the Strong SRT 8115 dump (slow, about 15 minutes): boots
srt8115.BIN (main board MC6422-M3801) into its application, which scans its
flash channel database for some 8 minutes before it draws its first screen at
about 12 minutes: its live-TV "Brak sygnału" (no signal) icon and text, some 40
GE commands, then a slow trickle of redraws.  The
screen is captured and compared with srt8115_screen.png with a small
tolerance.  Then the IR remote (this firmware's extended-NEC coding, see
ir_remote.IR_CODINGS) drives it: MENU opens the main menu ("Edytuj kanały":
TV / radio channel lists, delete all, favourite lists), the front panel's
down key moves its highlight and EXIT closes it again; the final screen is
compared with srt8115_nav.png.  The front panel is the Cabletech URZ0083Q's
(the same TM1628-class chip on the same pins, digit wiring and font) and
must show the channel number "0001" with the first screen, after " ON " and
"----"; its panel code's table maps KS9/K1 up, KS9/K2 down, KS10/K1 power.

Usage: python run_dump_srt8115_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression
from tm1628_decoder import TM1628Decoder

DOWN = TM1628Decoder.key_code(9, 2)

# this box's card at the top of the report (run_all_tests.py reads it from the source)
FEATURED = {"device": "Strong SRT 8115", "chips": ["ALi M3801", "TM1628-class", "MxL603"],
            "shows": ["boots to screen", "reacts to remote", "panel keys"]}

screen_regression.run(
    dump="srt8115.BIN",
    expected="srt8115_screen.png",
    boot_limit_s=60 * 60,     # 6-20 min alone, much longer on a loaded machine / CI runner
    settle_s=90,
    min_ge_ops=35,
    max_diff_pct=1.0,
    panel_text="OOO1",    # the channel number "0001"
    title="Strong SRT 8115",
    retries=2,            # its byte-wise flash scan hits the sporadic async-stop race more often
    navigation=[("MENU", 100000), (("panel", DOWN), 2000), ("EXIT", 100000)],
)
