"""
Screen regression for the Cabletech URZ0195 with its 2013 firmware (slow,
about 5 minutes): boots "cableteh_urz0195__w25q32bv.BIN" into its
application (Libcore 8.1c.0@SDK4.0bd.8.7_20121127), which plays the first
channel of its database ("prog id : 4", TVN) and draws its channel banner
(channel 5, "Brak informacji", 0 %) some 20 GE commands in, then, when the
banner has timed out, the live-TV "Brak sygnału!" (no signal) screen; that
stable screen is compared with urz0195_2013_screen.png.  (Its uPD16312-class
front panel's segment wiring is not mapped yet, so its text is not checked.)

Usage: python run_dump_urz0195_2013_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

screen_regression.run(
    dump="cableteh_urz0195__w25q32bv.BIN",
    expected="urz0195_2013_screen.png",
    boot_limit_s=30 * 60,
    settle_s=60,
    min_ge_ops=36,        # after the channel banner (~20 commands) has timed out
    max_diff_pct=1.0,
    title="Cabletech URZ0195 (2013 firmware)",
    retries=2,
)
