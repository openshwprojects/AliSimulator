"""
Screen regression for the Strong Prima VIII flash dump (slow, about 6
minutes): boots "STRONG PRIMA VIII/GD25Q32B_20190128_141501.BIN" (main board
MC6501-M3801, firmware "Prima_viii" of April 2015, Libcore 8.32) into its
application, which draws its live-TV channel banner -- the channel name,
"28/11 01:00", the Bulgarian "няма информация" (no information) and the
channel number -- some 15 GE commands in, about 3 minutes after the start.
This firmware runs in a PAL SD output mode (the display engine scales its
OSD layer 1280 x 720 -> 720 x 576; gma_capture undoes that).  The screen is
captured once the banner is up and compared with prima8_screen.png
with a 1 % tolerance: with no signal on any channel the firmware steps
through its channel list by itself, a channel every minute or two, so the
banner's name and number (BTV 0001, NOVA TV 0002, ...) depend on timing --
they differ by about 1000 pixels.  No navigation yet: over the IR remote
(this firmware's extended-NEC coding, see ir_remote.IR_CODINGS) keys are
acted on only between those re-tunes -- its EPG grid (virtual key 42), the
EPG info window (37), the favourite-list and USB popups (60, 61) and the
banner toggle (16) were all seen once, but none reliably from a fresh boot.
(The manufacturer's update for the same box, the SRT Prima VIII V1.0.6
image of January 2016 in this repository, has no user database and draws
nothing; this dump came with a user database of Bulgarian channels.  Its
firmware drives no front-panel chip over GPIO.)

Usage: python run_dump_prima8_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

# this box's card at the top of the report (run_all_tests.py reads it from the source)
FEATURED = {"device": "Strong Prima VIII", "chips": ["ALi M3801", "MxL603"],
            "shows": ["boots to screen"]}

screen_regression.run(
    dump="STRONG PRIMA VIII/GD25Q32B_20190128_141501.BIN",
    expected="prima8_screen.png",
    boot_limit_s=30 * 60,
    settle_s=60,
    min_ge_ops=15,        # the channel banner
    max_diff_pct=1.0,
    title="Strong Prima VIII",
)
