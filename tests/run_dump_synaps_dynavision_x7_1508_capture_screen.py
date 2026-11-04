"""
Screen regression for the Globo HD X7 Combo (Dynavision Synaps firmware 1.5.08) (System ID 06000200, slow): a Full HD
DVB-S2 + DVB-T combo receiver on the single-CPU ALi M3602A SoC (chips/m3602.py).
Its "M3602A 1.1.6" bootloader communicates with the external Lemontree EuP
standby and PT6311 8-character 14-segment VFD microcontroller at I2C 0x28 on
bit-banged GPIO 62 / 171 and unpacks maincode(AV) to 0x80008000.  The
application configures its ALi S3501 DVB-S2 demodulator at I2C 0x33 and Airoha
AV2011 tuner at I2C 0x60 on SCB0 / SCB1 and draws its OSD dialog through
GeM3602, captured and compared with synaps_dynavision_x7_1508_screen.png.

Usage: python run_dump_synaps_dynavision_x7_1508_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="OPTICUM HD X7/synaps_dynavision_1.5.08_x7_newrmote.abs",
    expected="synaps_dynavision_x7_1508_screen.png",
    boot_limit_s=60,
    settle_s=5,
    min_ge_ops=7,
    min_colours=4,
    panel_text="   ON   ",
    max_diff_pct=1.0,
    title="Globo HD X7 Combo (Dynavision Synaps firmware 1.5.08)",
    retries=2,
)
