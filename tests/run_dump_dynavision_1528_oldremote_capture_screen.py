"""
Screen regression for the Dynavision Davinci HD Synaps firmware 1.5.28
oldremote build (System ID 06020200, ALi M3602B, chips/m3602.py).  Its "M3602B
1.1.6" bootloader communicates with the external Lemontree EuP standby and 4-digit
7-segment front-panel microcontroller at I2C 0x28 on GPIO 62 / 171 (" ON " -> "    "
-> " on "), unpacks maincode to 0x80008000, initialises the S3501 demodulator and
AV2011 tuner, and draws its Synaps OSD dialog through GeM3602 (8 GE commands, 30
colours), compared with dynavision_synaps_screen.png.

Usage: python run_dump_dynavision_1528_oldremote_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Dynavision Davinci HD (Synaps 1.5.28 Old Remote)",
    "chips": ["ALi M3602B", "S3501", "AV2011", "Lemontree EuP MCU"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="DYNAVISION DAVINCI HD/synaps_dynavision_1.5.28_x4_oldremote.abs",
    expected="dynavision_synaps_screen.png",
    boot_limit_s=60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=10,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Dynavision Davinci HD (Synaps 1.5.28 Old Remote)",
    retries=1,
)
