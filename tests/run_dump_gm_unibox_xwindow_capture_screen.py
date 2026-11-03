"""
Screen regression for the Golden Media Uni-Box 9060 / 9080 HD XWindow firmware
1.5.13 (System ID 06020200, slow): a Full HD DVB-S2 satellite receiver on the
single-CPU ALi M3602B SoC (chips/m3602.py).  Its "M3602B 1.1.6" bootloader
communicates with the external Lemontree EuP standby and 4-digit 7-segment
front-panel microcontroller at I2C 0x28 on bit-banged GPIO 62 / 171
(lemontree_decoder.py: 8-byte CRC-16/XMODEM frames " ON " -> "    " -> " on ")
and unpacks maincode(AV) to 0x80008000.  The application configures its ALi
S3501 DVB-S2 demodulator at I2C 0x33 and Airoha AV2011 tuner at I2C 0x60 and
draws its XWindow OSD dialog through GeM3602 (8 GE commands, 19 colours),
captured and compared with gm_unibox_xwindow_screen.png.

Usage: python run_dump_gm_unibox_xwindow_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Golden Media Uni-Box 9060/9080 HD (XWindow 1.5.13)",
    "chips": ["ALi M3602B", "S3501", "AV2011", "Lemontree EuP MCU"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="GOLDEN MEDIA UNIBOX XWINDOW/xwindow_gm_1.5.13_x4_oldremote.abs",
    expected="gm_unibox_xwindow_screen.png",
    boot_limit_s=4 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=8,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Golden Media Uni-Box 9060/9080 HD (XWindow firmware 1.5.13)",
    retries=2,
)
