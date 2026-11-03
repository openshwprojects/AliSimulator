"""
Screen regression for the Amiko SHD-7900 / SHD-8000 Galaxy firmware 1.5.75 by
Dekolte (System ID 06020A00, slow): a Full HD DVB-S2 satellite receiver on the
single-CPU ALi M3602B SoC (chips/m3602.py).  Its "M3602B 1.1.6" bootloader
communicates with the external Lemontree EuP standby and 4-digit LED front-panel
microcontroller at I2C 0x28 on bit-banged GPIO 62 / 171 (lemontree_decoder.py:
CRC-16/XMODEM display frames " ON " -> "    " -> "-ON-") and unpacks
maincode(AV) to 0x80008000.  The application configures its ALi S3501 DVB-S2
demodulator at I2C 0x33 and Airoha AV2011 tuner at I2C 0x60 and draws its Galaxy
OSD dialog through GeM3602 (8 GE commands, 30 colours), captured and compared
with shd8000_screen.png.

Usage: python run_dump_shd8000_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko SHD-7900 / SHD-8000 (Galaxy 1.5.75)",
    "chips": ["ALi M3602B", "S3501", "AV2011", "Lemontree EuP MCU"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="AMIKO SHD-8000/AMIKO_SHD-7900-8000_Galaxy_1.5.75_by Dekolte.abs",
    expected="shd8000_screen.png",
    boot_limit_s=4 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=10,
    panel_text="-ON-",
    max_diff_pct=1.0,
    title="Amiko SHD-7900 / SHD-8000 (Galaxy firmware 1.5.75)",
    retries=2,
)
