"""
Screen regression for the Opticum HD X4 220 Amstar UPC firmware 1.5.22.VI
(System ID 06020200, slow): a Full HD DVB-S2 satellite receiver on the
single-CPU ALi M3602B SoC (chips/m3602.py).  Its "M3602B 1.1.6" bootloader
communicates with the external Lemontree EuP standby and 4-digit 7-segment
front-panel microcontroller at I2C 0x28 on bit-banged GPIO 62 / 171
(lemontree_decoder.py: 8-byte CRC-16/XMODEM frames " ON " -> "    " -> " on ")
and unpacks maincode(AV) to 0x80008000.  The application configures its ALi
S3501 DVB-S2 demodulator at I2C 0x33 and Airoha AV2011 tuner at I2C 0x60 and
draws its blue Amstar OSD dialog through GeM3602 (14 GE commands, 4 colours),
captured and compared with x4_amstar_upc_screen.png.

Usage: python run_dump_x4_amstar_upc_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="OPTICUM HD X4 220/ALI3602_06020200_X4_amstar_UPC_1.5.22.VI.abs",
    expected="x4_amstar_upc_screen.png",
    boot_limit_s=60,
    settle_s=5,
    min_ge_ops=7,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Opticum HD X4 220 (Amstar UPC firmware 1.5.22.VI)",
    retries=2,
)
