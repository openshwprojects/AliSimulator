"""
Screen regression for the Amiko Mini HD Combo (firmware Edision 1.4.78 by Dekolte, System ID
0E060A00, slow): a Full HD DVB-S2 / DVB-T2/C receiver on the single-CPU ALi M3612
/ M3801 SoC with 8 MB SPI flash (chips/m3801.py).  Its bootloader writes " ON "
to the CH455 front panel on GPIO 31 / 9 and unpacks maincode(AV) to 0x80000200.
With the external Availink AVL6862 demodulator at I2C 0x14 (ChipID 0x0F,
demods.AVL6862A), Sharp VZ7903 / AV2012 tuner (0x61), and Rafael Micro R836
DVB-T2/C tuner (0x3A), the application updates the CH455 panel to
"-ON-", populates userdb(64+64) at 0x73FF80, and enables GMA layer 0
to render its 1280 x 720 ARGB8888 OSD dialog, captured and compared with
minihd_combo_edision_1478_screen.png.

Usage: python run_dump_minihd_combo_edision_1478_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO MINI HD COMBO/AMIKO_MiniHD_Combo_Edision_1.4.78_by Dekolte.abs",
    expected="minihd_combo_edision_1478_screen.png",
    boot_limit_s=180,
    settle_s=5,
    min_ge_ops=8,
    min_colours=4,
    panel_text="-ON-",
    max_diff_pct=1.0,
    title="Amiko Mini HD Combo (firmware Edision 1.4.78 by Dekolte)",
    retries=2,
)
