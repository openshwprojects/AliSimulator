"""
Screen regression for the Amiko SHD-8360 CI+CA firmware v1.6.96 EMU (System ID
0A0A0A00, slow): a Full HD DVB-S2 satellite receiver on the ALi M3606G / C3603
dual-core SoC (chips/m3602.py with chip ID 0x3603).  Its "M3606G 1.1.3"
bootloader maps the 8 MB SPI flash in the 16 MB window at 0xAF000000, parks the
SEE boot stub at 0xA1E8F9B8, communicates with the external Lemontree EuP
standby and front-panel microcontroller at I2C 0x28 on bit-banged GPIO 103 / 102
(" ON " -> "    " -> " on "), unpacks maincode(AV) to 0x80000200, and starts
"M3606 SEE" at 0xA7000200.  The application configures its ALi S3501 DVB-S2
demodulator at I2C 0x33 and Airoha AV2012 tuner at I2C 0x65 and renders its
1280x720 OSD dialog on GMA layer 0 (9 GE commands, 30 colours), compared with
shd8360_screen.png.

Usage: python run_dump_shd8360_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko SHD-8360 CI+CA (v1.6.96)",
    "chips": ["ALi M3606G / C3603", "S3501", "AV2012", "Lemontree EuP MCU"],
    "shows": ["boots to screen", "second CPU (SEE)", "front panel"],
}

screen_regression.run(
    dump="AMIKO SHD-8360/AMIKO_SHD-8360_1.6.96_emu.abs",
    expected="shd8360_screen.png",
    boot_limit_s=4 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=10,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko SHD-8360 CI+CA (firmware v1.6.96)",
    retries=2,
)
