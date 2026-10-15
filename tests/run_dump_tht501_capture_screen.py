"""
Screen regression for the Thomson THT501 update V1.1.5a (ALi M36xx, the
Cabletech URZ0083's generation, chips/m3602.py; about 2 minutes): boots
"THT501_V1.1.5a_20120925.abs" with the chip ID its board reads, 0x3603 (its
sidecar's device.chipId), into its application (SDK4.0ba.6.4_GLS_T), which
decodes its boot logo (video_m36.py) and draws its first-install wizard in
English ("Welcome": Language English, Region United Kingdom, Subtitle Off,
Aspect Mode Auto, Scan Mode Free, Connection HDMI, OK) in a flat red / yellow
skin of only some 7 colours, about 33 GE commands in; that screen is compared
with tht501_screen.png.  Then the remote's DOWN -- the URZ0083's
extended-NEC coding, ir_remote's "ext00" -- moves the highlight from
Language to Region, compared with tht501_nav.png.

Usage: python run_dump_tht501_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

FEATURED = {"device": "Thomson THT501 (update V1.1.5a)", "chips": ["ALi M36xx (C3603)"],
            "shows": ["boots to screen", "reacts to remote"]}

screen_regression.run(
    dump="THT501_V1.1.5a_20120925.abs",
    expected="tht501_screen.png",
    boot_limit_s=30 * 60,
    settle_s=45,
    min_ge_ops=33,            # the wizard is complete at 33 commands
    min_colours=6,            # its flat skin: 7 colours
    title="Thomson THT501 (update V1.1.5a)",
    navigation=[("DOWN", 1000)],
)
