"""
Signal screen regression for the Opticum Blue R265 Lite (slow, about 10
minutes): boots "Opticum Blue R265 Lite/T2GEN265_1.1.5-2022-08-01.abs" with
sim.set_signal(True) -- its sidecar's tuner model (the MxL603 family's
protocol for the board's MxL608, tuners.py) on the I2C bus and the M3821's
internal demodulator reporting lock (chips/m3821.py: register 0x1D bit 6 for
DVB-T, the T2 state in 0x67 / 0x11D).  The home menu is the same as without
a signal (compared with r265lite_signal_screen.png); then the remote opens
"Skan kanałów" (RIGHT, OK) and its "Skanowanie kanałów" page (OK), whose
signal bars read 100 % strength and 30 % quality on CH05 (177.5 MHz) -- 0 %
and 0 % without a signal.  The bars slide to their values, so the page is
compared with r265lite_signal_nav.png once it has settled.

Usage: python run_dump_r265lite_signal_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

# this box's card at the top of the report (run_all_tests.py reads it from the source)
FEATURED = {"device": "Opticum Blue R265 Lite (firmware 1.1.5)", "chips": ["ALi M3822P", "HD2015", "MxL608"],
            "shows": ["boots to screen", "reacts to remote", "shows channel scan with a signal"]}

screen_regression.run(
    dump="Opticum Blue R265 Lite/T2GEN265_1.1.5-2022-08-01.abs",
    expected="r265lite_signal_screen.png",
    boot_limit_s=25 * 60,
    settle_s=60,
    min_ge_ops=360,           # the home menu is complete at 364 commands
    min_colours=16,
    panel_text=" ON ",
    title="Opticum Blue R265 Lite with a signal",
    signal=True,
    navigation=[("RIGHT", 1000), ("OK", 100000), ("OK", 10000)],
    nav_settle_s=300,         # the quality bar slides to its value over a minute or two of wall time
)
