"""
Screen regression for the SAB Titan I HD 3602 / Opticum HD X4 Amstar firmware
1.6.17 (System ID 06020200, slow): a Full HD DVB-S2 satellite receiver on the
single-CPU ALi M3602B SoC (chips/m3602.py).  Its "M3602B 1.1.6" bootloader
communicates with the external Lemontree EuP standby and 4-digit 7-segment
front-panel microcontroller at I2C 0x28 on bit-banged GPIO 62 / 171
(lemontree_decoder.py: 8-byte CRC-16/XMODEM frames " ON " -> "    " -> "boot")
and unpacks maincode(AV) to 0x80008000.  The application configures its ALi
S3501 DVB-S2 demodulator at I2C 0x33 and Airoha AV2011 tuner at I2C 0x60 and
draws its blue Amstar OSD dialog through GeM3602 (14 GE commands, 4 colours),
captured and compared with globo_x4_amstar_1617_screen.png.

Usage: python run_dump_globo_x4_amstar_1617_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="SAB TITAN I HD 3602/globo_x4_amstar_sab_1.6.17_gisclub.tv.abs",
    expected="globo_x4_amstar_1617_screen.png",
    boot_limit_s=60,
    settle_s=5,
    min_ge_ops=14,
    min_colours=4,
    panel_text="boot",
    max_diff_pct=1.0,
    title="SAB Titan I HD 3602 (Amstar firmware 1.6.17)",
    retries=2,
)
