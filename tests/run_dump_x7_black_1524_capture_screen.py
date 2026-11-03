"""
Screen regression for the Opticum HD X7 Combo firmware 1.5.24 ("Black Synaps"
PS GUI build, System ID 06000200, slow): a Full HD DVB-S2 + DVB-T combo
receiver on the single-CPU ALi M3602A SoC (chips/m3602.py).  Its "M3602A 1.1.6"
bootloader communicates with the external Lemontree EuP standby and PT6311
8-character 14-segment VFD microcontroller at I2C 0x28 on bit-banged GPIO 62 /
171 (lemontree_decoder.py: 38-byte op-0x33 VFD frames "  BOOT  " -> "        "
-> "   ON   ") and unpacks maincode(AV) to 0x80008000.  The application
configures its ALi S3501 DVB-S2 demodulator at I2C 0x33 and Airoha AV2011 tuner
at I2C 0x60 on SCB0 / SCB1 and draws its Black Synaps OSD dialog through
GeM3602, captured and compared with x7_black_1524_screen.png.

Usage: python run_dump_x7_black_1524_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="OPTICUM HD X7/Optixum_HD_X7_06000200_ablack_synaps_ps_1.5.24.abs",
    expected="x7_black_1524_screen.png",
    boot_limit_s=60,
    settle_s=5,
    min_ge_ops=29,
    min_colours=10,
    panel_text="GISCLUB ",
    max_diff_pct=1.0,
    title="Opticum HD X7 Combo (Black Synaps firmware 1.5.24)",
    retries=2,
)
