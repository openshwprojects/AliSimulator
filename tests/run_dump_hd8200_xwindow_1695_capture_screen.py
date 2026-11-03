"""
Screen regression for the Amiko HD8200 Series (XWindow 1.6.95 by Dekolte, System ID 0A040A00,
slow): a Full HD receiver on the dual-CPU ALi M3606B / C3603 SoC
(chips/m3602.py, chip ID 0x3603).  Its "M3606B 1.1.3" bootloader communicates with
the Lemontree EuP standby and front-panel microcontroller at I2C 0x28 on
bit-banged GPIO 44 / 43 (" ON " -> "    " -> "-ON-"), unpacks maincode(AV)
to 0x80000200, starts "M3606 SEE" at 0xA7000200, configures its ALi S3501 DVB-S2
demodulator at I2C 0x33 and Airoha AV2011 tuner at I2C 0x60, and draws its
1280x720 OSD dialog, captured and compared with hd8200_xwindow_1695_screen.png.

Usage: python run_dump_hd8200_xwindow_1695_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO HD8200 SERIES/AMIKO_HD8200_Xwindow_1.6.95_by Dekolte.abs",
    expected="hd8200_xwindow_1695_screen.png",
    boot_limit_s=15 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=8,
    panel_text="-ON-",
    max_diff_pct=1.0,
    title="Amiko HD8200 Series (XWindow 1.6.95 by Dekolte)",
    retries=2,
)
