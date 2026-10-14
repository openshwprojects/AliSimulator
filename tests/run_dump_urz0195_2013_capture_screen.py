"""
Screen regression for the Cabletech URZ0195 with its 2013 firmware (slow,
about 5 minutes): boots "cableteh_urz0195__w25q32bv.BIN" into its
application (Libcore 8.1c.0@SDK4.0bd.8.7_20121127), which plays the first
channel of its database ("prog id : 4", TVN) and draws its channel banner
(channel 5, "Brak informacji", 0 %) some 20 GE commands in, then, when the
banner has timed out, the live-TV "Brak sygnału!" (no signal) screen; that
stable screen is compared with urz0195_2013_screen.png.  Its uPD16312-class
front panel, wired and driven like the 2012 firmware's (the same font table),
must show the channel number "0005" by then (the decoder renders it "OOOS").
Then the IR remote -- the 2012 firmware's extended-NEC coding, see
ir_remote.IR_CODINGS -- opens the channel list with OK and moves its
highlight with DOWN; that screen is compared with urz0195_2013_nav.png.

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
    panel_text="OOOS",    # the channel number "0005"
    title="Cabletech URZ0195 (2013 firmware)",
    retries=2,
    navigation=[("OK", 100000), ("DOWN", 5000)],
)
