"""
Screen regression for the Opticum Blue R265 Lite's newest firmware, 1.2.0
(ALi M3822P, chips/m3821.py; about 10 minutes): boots "Opticum Blue R265
Lite/T2GEN265_1.2.0-2023-03-17.abs" through its 2023 bootloader (silent on
the UART, its stage 2 copies the application through the flash window word
by word) into the application (Libcore 19.17, 2021), which draws the same
home menu as firmware 1.1.5 -- six tiles in Polish over the INFO hint bar,
complete at 363 GE commands -- some 4 minutes in.  Before it draws, this
application sets bit 4 of +0x6F of the block at 0xB802A000 and waits for the
hardware to clear it (chips/m3821.py answers that; the 1.1.5 application
does not wait there).  The screen is compared with r265lite_120_screen.png;
then the remote's DOWN highlights "Ustawienia systemu" and INFO opens its
description, compared with r265lite_120_nav.png.  (Both expected screens
came out byte-identical to firmware 1.1.5's r265lite_screen.png and
r265lite_nav.png: the two applications draw the same pixels.)

Usage: python run_dump_r265lite_120_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

# this box's card at the top of the report (run_all_tests.py reads it from the source)
FEATURED = {"device": "Opticum Blue R265 Lite (firmware 1.2.0)", "chips": ["ALi M3822P", "HD2015", "MxL608"],
            "shows": ["boots to screen", "reacts to remote"]}

screen_regression.run(
    dump="Opticum Blue R265 Lite/T2GEN265_1.2.0-2023-03-17.abs",
    expected="r265lite_120_screen.png",
    boot_limit_s=30 * 60,     # the menu is up after ~4 min alone
    settle_s=60,
    min_ge_ops=360,           # the home menu is complete at 363 commands
    min_colours=16,
    panel_text=" ON ",        # this bootloader's stage 2 writes the panel too
    title="Opticum Blue R265 Lite firmware 1.2.0",
    navigation=[("DOWN", 1000), ("INFO", 1000)],
)
