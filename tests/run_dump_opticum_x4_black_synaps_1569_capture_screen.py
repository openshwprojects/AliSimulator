"""
Screen regression for the Opticum HD X403P Black Synaps 1.5.69 firmware
(System ID 06020200, ALi M3602B, chips/m3602.py).  Its "M3602B 1.1.6" bootloader
communicates with the external Lemontree EuP standby and 4-digit 7-segment
front-panel microcontroller at I2C 0x28 on GPIO 62 / 171 (" ON " -> "    " -> "boot"),
unpacks maincode to 0x80008000, initialises the S3501 demodulator and AV2011 tuner,
and draws its Black Synaps OSD dialog through GeM3602 (8 GE commands, 30 colours),
compared with opticum_x4_black_synaps_1569_screen.png.

Usage: python run_dump_opticum_x4_black_synaps_1569_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Opticum HD X403P (Black Synaps 1.5.69)",
    "chips": ["ALi M3602B", "S3501", "AV2011", "Lemontree EuP MCU"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="OPTICUM HD X403P/globo_x4_black synaps_mkfix_1.5.69_gisclub.tv.abs",
    expected="opticum_x4_black_synaps_1569_screen.png",
    boot_limit_s=60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=10,
    panel_text="boot",
    max_diff_pct=1.0,
    title="Opticum HD X403P Black Synaps 1.5.69",
    retries=1,
)
