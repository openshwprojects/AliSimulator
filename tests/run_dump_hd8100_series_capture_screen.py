"""
Screen regression for the Amiko HD8100 Series firmware v1.4.44 (System ID
0B000A00, slow): a Full HD DVB-S2 satellite receiver on the dual-CPU ALi M3601A
/ M3606 (C3603) SoC with 8 MB SPI flash (chips/m3602.py).  Its "M3601A 1.1.3"
bootloader parks the SEE boot stub at 0xA1E9103C, unpacks seecode ("M3606 SEE")
to 0xA7000200 and maincode(AV) to 0x80000200, and starts both cores.  The
application configures its ALi S3501 DVB-S2 demodulator at I2C 0x33, populates
userdb(64+64) at 0x73FF80, and draws its 1280 x 720 ARGB8888 OSD dialog through
GeM36F / GMA layer 0 (9 GE commands, 30 colours), captured and compared with
hd8100_series_screen.png.

Usage: python run_dump_hd8100_series_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko HD8100 Series (v1.4.44)",
    "chips": ["ALi M3601A / C3603", "S3501"],
    "shows": ["boots to screen", "second CPU (SEE)"],
}

screen_regression.run(
    dump="AMIKO HD8100 SERIES/AMIKO_HD8100_Series_v1.4.44_emu.abs",
    expected="hd8100_series_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=10,
    max_diff_pct=1.0,
    title="Amiko HD8100 Series (firmware v1.4.44)",
    retries=2,
)
