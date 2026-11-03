"""
Screen regression for the Opticum HD X402p / X403p Synaps Galaxy PS 1.5.53 TNT
fix firmware by dreamer1983 (System ID 06020200, slow): a Full HD DVB-S2
satellite receiver on the single-CPU ALi M3602B SoC (chips/m3602.py).  Its
"M3602B 1.1.6" bootloader communicates with the external Lemontree EuP standby
and 4-digit 7-segment front-panel microcontroller at I2C 0x28 on bit-banged GPIO
62 / 171 and unpacks maincode(AV) to 0x80008000.  The application configures its
ALi S3501 DVB-S2 demodulator at I2C 0x33 and Airoha AV2011 tuner at I2C 0x60 on
SCB1 and draws its Synaps Galaxy PS OSD dialog through GeM3602, captured and
compared with x402p_403p_galaxy_1553_screen.png.

Usage: python run_dump_x402p_403p_galaxy_1553_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="OPTICUM HD X403P/Opticum_HD-X402p-403p_galaxy_ps_synaps_1.5.53_by dreamer1983_TNT_fix.abs",
    expected="x402p_403p_galaxy_1553_screen.png",
    boot_limit_s=60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=10,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Opticum HD X402p/X403p (Synaps Galaxy PS firmware 1.5.53 TNT fix)",
    retries=2,
)
