"""
Screen regression for the Amiko HD8240 / Galaxy Innovations Black Synaps 1.7.01
firmware (System ID 0A040A00, slow): a Full HD receiver on the dual-CPU ALi
M3606B / C3603 SoC (chips/m3602.py, chip ID 0x3603).  Its "M3606B 1.1.3"
bootloader communicates with the Lemontree EuP standby and 4-digit LED
microcontroller at I2C 0x28 on bit-banged GPIO 44 / 43 (" ON " -> "    " ->
" on "), unpacks maincode(AV) to 0x80000200, starts "M3606 SEE" at 0xA7000200,
configures its ALi S3501 DVB-S2 demodulator at I2C 0x33 and Airoha AV2011 tuner
at I2C 0x60, and draws its 1280x720 OSD dialog (9 GE commands, 30 colours),
captured and compared with hd8240_screen.png.

Usage: python run_dump_hd8240_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko HD8240 (Black Synaps 1.7.01)",
    "chips": ["ALi M3606B", "S3501", "AV2011", "Lemontree EuP MCU"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="AMIKO HD8240/amiko_0A040A00_black synaps_gi_1.7.01_gisclub.tv.abs",
    expected="hd8240_screen.png",
    boot_limit_s=15 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=16,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko HD8240 (Black Synaps 1.7.01)",
    retries=2,
)
