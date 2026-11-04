"""
Screen regression for the Amiko HD8840 Combo CI+CA (Series v1.6.96 EMU,
System ID 0A050A00, slow): a Full HD DVB-S2 + DVB-T2/C combo receiver on the
dual-CPU ALi M3606C / C3603 SoC (chips/m3602.py, chip ID 0x3603).  Its
"M3606C 1.1.3" bootloader communicates with the Lemontree EuP standby and
front-panel microcontroller at I2C 0x28 on bit-banged GPIO 103 / 102, unpacks
maincode(AV) to 0x80000200, starts "M3606 SEE" at 0xA7000200, configures its
ALi S3501 DVB-S2 demodulator at I2C 0x33 and Airoha AV2011 tuner at I2C 0x60,
and draws its 1280x720 OSD dialog, captured and compared with
hd8840_1696_screen.png.

Usage: python run_dump_hd8840_1696_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO HD8840/AMIKO_HD8840_Series_1.6.96_emu.abs",
    expected="hd8840_1696_screen.png",
    boot_limit_s=180,
    settle_s=5,
    min_ge_ops=8,
    min_colours=8,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko HD8840 Combo (Series v1.6.96 EMU)",
    retries=2,
)
