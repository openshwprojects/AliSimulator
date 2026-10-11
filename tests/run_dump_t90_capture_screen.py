"""
Screen regression for the Opticum HD T90 / STB HD N2 / N3 official update
1.3.2 PVR (slow, about 10 minutes): boots "OPTICUM HD T90/STB_HD_T90_N2-3_
1.3.2PVR_2014-01-05.abs" -- the manufacturer's 2015 firmware for the family
of dump_maciej.bin (an N2) and the Globo N3 dump -- through its LZMA
bootloader ("success!" after about 90 s) into the application (Libcore
8.13.0, the Globo N3's), which keeps the update's channel list, tunes a
channel, shows its banner and then, with no signal, the red "Brak sygnału"
(no signal) box of the Globo N3's skin, redrawn a few times a second from
then on; that screen is captured and compared with t90_screen.png.  The
TM1650 front panel is decoded alongside.  The remote reaches it (MENU drew 28
GE commands and changed 60,000 pixels when the expected screen was made), but
the menu steps and their expected screen (t90_nav.png) are not part of the
test yet.

Usage: python run_dump_t90_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

# this box's card at the top of the report (run_all_tests.py reads it from the source)
FEATURED = {"device": "Opticum HD T90 (official update 1.3.2)", "chips": ["ALi M3801", "TM1650", "R820T"],
            "shows": ["boots to screen"]}

screen_regression.run(
    dump="OPTICUM HD T90/STB_HD_T90_N2-3_1.3.2PVR_2014-01-05.abs",
    expected="t90_screen.png",
    boot_limit_s=30 * 60,
    settle_s=60,
    min_ge_ops=900,       # the no-signal box is up (the banner took the first ~600 commands)
    max_diff_pct=1.0,
    title="Opticum HD T90 (official update 1.3.2)",
    retries=2,
    # to do: navigation=[("MENU", 40000), ("RIGHT", 2000), ("EXIT", 40000)] with nav_settle_s=600 --
    # MENU changed 60,000 pixels (28 GE commands) on 2026-10-11, less than the Globo's 200,000
)
