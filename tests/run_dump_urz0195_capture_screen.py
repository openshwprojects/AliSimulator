"""
Screen regression for the Cabletech URZ0195 with its 2012 firmware (slow, about
12 minutes): boots "urz0195_full_dump(ESMTF25L3204).bin" through its LZMA
bootloader into the application (Libcore 8.1.0@SDK4.0bd.8.1_20120713), which
draws right away -- the channel banner ("Polsat", channel 4, no signal) some 14
GE commands in, then, when the banner has timed out, the live-TV "Brak
sygnału!" (no signal) screen -- and compares that stable screen with
urz0195_2012_screen.png.  The uPD16312-class front panel on GPIO
31 / 9 / 14 must show the channel number "0004" by then (the decoder renders
a 0 as "O"), after " ON " and "----".  Then the IR remote (this firmware's
extended-NEC coding, see ir_remote.IR_CODINGS) opens the channel list with
OK ("All TV": TVP1 HD ... TV6, Polsat highlighted) and moves the highlight
down to TVN; that screen is compared with urz0195_2012_nav.png.  (The
repository's other URZ0195 image, the 2013 firmware, has not drawn anything
in the simulator yet.  No front-panel key does anything on this firmware.)

Usage: python run_dump_urz0195_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

# this box's card at the top of the report (run_all_tests.py reads it from the source)
FEATURED = {"device": "Cabletech URZ0195 (2012 firmware)", "chips": ["ALi M3801", "uPD16312-class", "MxL5007T"],
            "shows": ["boots to screen", "shows its channel on the panel", "reacts to remote"]}

screen_regression.run(
    dump="urz0195_full_dump(ESMTF25L3204).bin",
    expected="urz0195_2012_screen.png",
    boot_limit_s=30 * 60,
    settle_s=90,
    min_ge_ops=40,        # after the channel banner (~14 commands) has timed out
    max_diff_pct=1.0,
    panel_text="OOO4",    # the channel number "0004"
    title="Cabletech URZ0195 (2012 firmware)",
    retries=2,            # its byte-wise flash scan hits the sporadic async-stop race more often
    navigation=[("OK", 100000), ("DOWN", 5000)],
)
