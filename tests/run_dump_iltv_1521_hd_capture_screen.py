"""
Screen regression for the ILTV HD firmware 1.5.21 dual-remote build (System ID
06020200, ALi M3602B, chips/m3602.py).  Its "M3602B 1.1.6" bootloader communicates
with the external Lemontree EuP standby and 4-digit 7-segment front-panel
microcontroller at I2C 0x28 on GPIO 62 / 171 (" ON " -> "    " -> " on "), unpacks
maincode to 0x80008000, initialises the S3501 demodulator and AV2011 tuner, and
draws its ILTV OSD dialog through GeM3602 (7 GE commands, 4 colours), compared with
iltv_1521_hd_screen.png.

Usage: python run_dump_iltv_1521_hd_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "ILTV HD (firmware 1.5.21)",
    "chips": ["ALi M3602B", "S3501", "AV2011", "Lemontree EuP MCU"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="ILTV HD/iltv_1.5.21_hd_x4_newoldremote.abs",
    expected="iltv_1521_hd_screen.png",
    boot_limit_s=60,
    settle_s=5,
    min_ge_ops=7,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="ILTV HD 1.5.21",
    retries=1,
)
