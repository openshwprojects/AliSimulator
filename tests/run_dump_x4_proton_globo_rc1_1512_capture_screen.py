"""
Screen regression for the Globo HD X4 220 (Proton Lemontree RC1 PS firmware 1.5.12) (System ID 06020200, slow): a Full HD
DVB-S2 satellite receiver on the single-CPU ALi M3602B SoC (chips/m3602.py).
Its "M3602B 1.1.6" bootloader communicates with the external Lemontree EuP
standby and 4-digit 7-segment front-panel microcontroller at I2C 0x28 on
bit-banged GPIO 62 / 171 and unpacks maincode(AV) to 0x80008000.  The
application configures its ALi S3501 DVB-S2 demodulator at I2C 0x33 and Airoha
AV2011 tuner at I2C 0x60 and draws its OSD dialog through GeM3602, captured and
compared with x4_proton_globo_rc1_1512_screen.png.

Usage: python run_dump_x4_proton_globo_rc1_1512_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="OPTICUM HD X4 220/ALI3602_06020200_proton_globo_rc1_220_ps_lemontree_1.5.12.abs",
    expected="x4_proton_globo_rc1_1512_screen.png",
    boot_limit_s=60,
    settle_s=5,
    min_ge_ops=7,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Globo HD X4 220 (Proton Lemontree RC1 PS firmware 1.5.12)",
    retries=2,
)
