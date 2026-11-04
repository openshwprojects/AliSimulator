"""
Screen regression for the Globo HD X7 Combo (SAB XWindow firmware 1.5.53) (System ID 06000200, slow): a Full HD
DVB-S2 + DVB-T combo receiver on the single-CPU ALi M3602A SoC (chips/m3602.py).
Its "M3602A 1.1.6" bootloader communicates with the external Lemontree EuP
standby and PT6311 8-character 14-segment VFD microcontroller at I2C 0x28 on
bit-banged GPIO 62 / 171 and unpacks maincode(AV) to 0x80008000.  The
application configures its ALi S3501 DVB-S2 demodulator at I2C 0x33 and Airoha
AV2011 tuner at I2C 0x60 on SCB0 / SCB1 and draws its OSD dialog through
GeM3602, captured and compared with globo_x7_xwindow_1553_screen.png.

Usage: python run_dump_globo_x7_xwindow_1553_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="OPTICUM HD X7/globo_x7_xwindow_sab_1.5.53_gisclub.tv.abs",
    expected="globo_x7_xwindow_1553_screen.png",
    boot_limit_s=120,
    settle_s=5,
    min_ge_ops=7,
    min_colours=4,
    panel_text="GISCLUB ",
    max_diff_pct=1.0,
    title="Globo HD X7 Combo (SAB XWindow firmware 1.5.53)",
    retries=2,
)
