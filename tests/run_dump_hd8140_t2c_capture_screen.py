"""
Screen regression for the Amiko HD8140 T2/C firmware v1.5.85 EMU (System ID
0E090A00, slow): a Full HD DVB-T2 / DVB-C receiver on the single-CPU ALi M3612
/ M3801 SoC with 8 MB SPI flash (chips/m3801.py).  Its "M3612 1.0.4" bootloader
writes " ON " to the CH455 front panel on GPIO 31 / 9 and unpacks maincode(AV)
("0E090A001585") to 0x80000200.  With the external Availink AVL6862 demodulator
at I2C 0x14 (ChipID 0x0F -> "Demod is 6862!!!", demods.AVL6862A), Sharp VZ7903 /
AV2012 tuner (0x61), and Rafael Micro R836 DVB-T2/C tuner (0x3A), the
application updates the CH455 panel to " on ", populates userdb(64+64) at
0x73FF80, and enables GMA layer 0 to render its 30-colour 1280 x 720 ARGB8888
OSD dialog (9 GE commands), captured and compared with hd8140_t2c_screen.png.

Usage: python run_dump_hd8140_t2c_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko HD8140 T2/C (v1.5.85)",
    "chips": ["ALi M3612 / M3801", "AVL6862A", "AV2012", "R836", "CH455"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="AMIKO HD8140 T2C/AMIKO_HD8140_T2C_1.5.85_emu.abs",
    expected="hd8140_t2c_screen.png",
    boot_limit_s=5 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=10,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko HD8140 T2/C (firmware v1.5.85 EMU)",
    retries=2,
)
