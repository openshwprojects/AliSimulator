"""
Screen regression for the Yumatu Full HD Amstar firmware 1.5.25 (System ID
06020200, slow): a Full HD DVB-S2 satellite receiver on the single-CPU ALi
M3602B SoC (chips/m3602.py).  Its "M3602B 1.1.6" bootloader communicates with
the external Lemontree EuP standby and 4-digit 7-segment front-panel
microcontroller at I2C 0x28 on bit-banged GPIO 62 / 171 (lemontree_decoder.py:
8-byte CRC-16/XMODEM frames " ON " -> "    " -> " on ") and unpacks maincode(AV)
to 0x80008000.  The application configures its ALi S3501 DVB-S2 demodulator at
I2C 0x33 and Airoha AV2011 tuner at I2C 0x60 and draws its Turkish Amstar OSD
dialog through GeM3602 (14 GE commands, 4 colours), captured and compared with
yumatu_amstar_screen.png.

Usage: python run_dump_yumatu_amstar_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Yumatu Full HD (Amstar 1.5.25)",
    "chips": ["ALi M3602B", "S3501", "AV2011", "Lemontree EuP MCU"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="YUMATU FULL HD AMSTAR/amstar_yumatu_1.5.25_x4_newoldremote.abs",
    expected="yumatu_amstar_screen.png",
    boot_limit_s=4 * 60,
    settle_s=5,
    min_ge_ops=14,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Yumatu Full HD (Amstar firmware 1.5.25)",
    retries=2,
)
