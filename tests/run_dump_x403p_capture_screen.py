"""
Screen regression for the Opticum HD X402p / X403p firmware 1.5.48 ("Synaps"
RC2 PS GUI build, System ID 06020200, slow): a Full HD DVB-S2 satellite receiver
on the single-CPU ALi M3602B SoC (chips/m3602.py).  Its "M3602B 1.1.6"
bootloader communicates with the external Lemontree EuP standby and 4-digit
7-segment front-panel microcontroller at I2C 0x28 on bit-banged GPIO 62 / 171
(lemontree_decoder.py: 8-byte CRC-16/XMODEM frames " ON " -> "    " -> " on ")
and unpacks maincode(AV) to 0x80008000.  The application configures its ALi
S3501 DVB-S2 demodulator at I2C 0x33 and Airoha AV2011 tuner at I2C 0x60 on
SCB1 and draws its Synaps OSD dialog through GeM3602 (29 GE commands, 18
colours), captured and compared with x403p_screen.png.

Usage: python run_dump_x403p_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Opticum HD X402p / X403p (Synaps 1.5.48)",
    "chips": ["ALi M3602B", "S3501", "AV2011", "Lemontree EuP MCU"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="OPTICUM HD X403P/Opticum HD X402p-403p_220_ps_synaps_rc2_1.5.48_by dreamer1983.abs",
    expected="x403p_screen.png",
    boot_limit_s=15 * 60,
    settle_s=5,
    min_ge_ops=20,
    min_colours=12,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Opticum HD X402p / X403p (Synaps firmware 1.5.48)",
    retries=2,
)
