"""
Screen regression for the Edision Argus VIP3 firmware 1.6.60 EMU (System ID
0A050800, slow): a dual-tuner pluggable Full HD receiver on the dual-CPU ALi
M3606C / C3603 SoC (chips/m3602.py, chip ID 0x3603).  Its "M3606c 1.1.3"
bootloader communicates with the Lemontree EuP standby and 4-digit LED
microcontroller at I2C 0x28 on bit-banged GPIO 103 / 102 (" ON " -> "    " ->
" on "), unpacks maincode(AV) to 0x80000200, starts "M3606 SEE" at 0xA7000200,
configures its ALi S3501 DVB-S2 demodulator at I2C 0x33 and Airoha AV2011 tuner
at I2C 0x60, and draws its 1280x720 OSD dialog (8 GE commands, 4 colours),
captured and compared with vip3_screen.png.

Usage: python run_dump_vip3_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Edision Argus VIP3 (1.6.60 EMU)",
    "chips": ["ALi M3606C", "S3501", "AV2011", "Lemontree EuP MCU"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="EDISION ARGUS VIP3/Edision.vip3.0A050800_emu_1.6.60.abs",
    expected="vip3_screen.png",
    boot_limit_s=15 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Edision Argus VIP3 (firmware 1.6.60 EMU)",
    retries=2,
)
