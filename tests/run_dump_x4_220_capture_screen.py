"""
Screen regression for the Opticum HD X4 220 firmware 1.3.37 ("Lemontree" PS GUI
build, System ID 06020200, slow): a Full HD DVB-S2 satellite receiver on the
single-CPU ALi M3602B SoC (chips/m3602.py).  Its "M3602B 1.1.5" bootloader
communicates with the external Lemontree EuP standby and 4-digit 7-segment
front-panel microcontroller at I2C 0x28 on bit-banged GPIO 62 / 171
(lemontree_decoder.py: 8-byte CRC-16/XMODEM frames, updating the display
" ON " -> "    " -> " on ") and unpacks maincode(AV) into RAM.  The
application configures its ALi S3501 DVB-S2 demodulator at I2C 0x33 and Airoha
AV2011 tuner at I2C 0x60 on SCB1, verifies its NVM database over SPI, and draws
its OSD through GeM3602 (48+ GE commands), captured and compared with
x4_220_screen.png.

Usage: python run_dump_x4_220_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Opticum HD X4 220 (Lemontree 1.3.37)",
    "chips": ["ALi M3602B", "S3501", "AV2011", "Lemontree EuP MCU"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="OPTICUM HD X4 220/OPTICUM_HD_X4_220_ps_lemontree_1.3.37.abs",
    expected="x4_220_screen.png",
    boot_limit_s=15 * 60,
    settle_s=5,
    min_ge_ops=48,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Opticum HD X4 220 (Lemontree PS firmware 1.3.37)",
    retries=2,
)
