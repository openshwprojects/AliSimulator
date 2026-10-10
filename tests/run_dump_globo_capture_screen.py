"""
Screen regression for the Globo STB HD N3 dump (slow, about 6 minutes): boots
"Ali_3801_Globo_DVBT_dump SPI 4mb.bin" through its LZMA bootloader into the
application, waits for the OSD: the application first shows its channel banner ("41. WP",
clock and date, about 600 GE commands) and clears it again when the banner
times out, then draws the live-TV "Brak sygnału" (no signal) message at about
900 commands, five minutes after it started; that stable screen is captured and
compared with
globo_screen.png.  Then the IR remote drives it: MENU opens the main
menu (six tiles: channel edit, channel scan, media player, settings, USB), RIGHT
moves the highlight, EXIT returns to live TV, whose channel banner reappears;
that screen is compared with globo_nav.png.  The TM1650 front panel is
decoded alongside (" ON " while booting, then the application's text).

Usage: python run_dump_globo_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

# this box's card at the top of the report (run_all_tests.py reads it from the source)
FEATURED = {"device": "Globo STB HD N3", "chips": ["ALi M3801", "TM1650", "R820T"],
            "shows": ["boots to screen", "reacts to remote"]}

screen_regression.run(
    dump="Ali_3801_Globo_DVBT_dump SPI 4mb.bin",
    expected="globo_screen.png",
    boot_limit_s=30 * 60,
    settle_s=60,
    min_ge_ops=900,       # after the channel banner (~600 commands) has timed out
    title="Globo STB HD N3",
    navigation=[("MENU", 200000), ("RIGHT", 2000), ("EXIT", 100000)],
    nav_diff_pct=1.0,
    nav_settle_s=600,     # the channel banner after EXIT slides in and times out (firmware seconds, which take
                          # minutes of wall time on a loaded machine); the stable screen is compared
)
