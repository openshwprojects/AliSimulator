"""
Screen regression for the Strong Prima VIII flash dump (slow, about 8
minutes): boots "STRONG PRIMA VIII/GD25Q32B_20190128_141501.BIN" (main board
MC6501-M3801, firmware "Prima_viii" of April 2015, Libcore 8.32) into its
application, which draws its live-TV channel banner -- the channel name,
"28/11 01:00", the Bulgarian "няма информация" (no information) and the
channel number -- some 15 GE commands in, about 3 minutes after the start,
and once the banner has timed out the "Няма сигнал!" (no signal) box.  This
firmware runs in a PAL SD output mode (the display engine scales its OSD
layer 1280 x 720 -> 720 x 576; gma_capture undoes that).  The no-signal
screen is compared with prima8_screen.png.  Then the IR remote (this
firmware's extended-NEC coding and its own key numbers, see
ir_remote.IR_CODINGS) opens the EPG grid with its virtual key 42 (the
owner's Bulgarian channels: BTV, NOVA TV, BNT1 ...) and closes it with EXIT
(16); that screen is compared with prima8_nav.png.

The box's two front-panel buttons sit straight on GPIO 31 and 9, which its
application polls (front_panel.py: gpio_keys.py answers them released).
Read as pressed -- the simulator's default for an input nothing drives --
they sent channel up / down by themselves every second or two: the
firmware seemed to step through its channel list with no signal, and the
remote's keys got lost between those steps.
(The manufacturer's update for the same box, the SRT Prima VIII V1.0.6
image of January 2016 in this repository, has no user database and draws
nothing; this dump came with a user database of Bulgarian channels.)

Usage: python run_dump_prima8_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

# this box's card at the top of the report (run_all_tests.py reads it from the source)
FEATURED = {"device": "Strong Prima VIII", "chips": ["ALi M3801", "MxL603"],
            "shows": ["boots to screen", "reacts to remote"]}

screen_regression.run(
    dump="STRONG PRIMA VIII/GD25Q32B_20190128_141501.BIN",
    expected="prima8_screen.png",
    boot_limit_s=30 * 60,
    settle_s=120,         # the banner times out, then the no-signal box is drawn
    min_ge_ops=15,        # the channel banner
    max_diff_pct=1.0,
    title="Strong Prima VIII",
    navigation=[(42, 300000), (16, 300000)],      # its EPG grid (virtual key 42), EXIT
    nav_diff_pct=1.0,
    nav_settle_s=300,     # back on live TV, the no-signal box is redrawn
)
