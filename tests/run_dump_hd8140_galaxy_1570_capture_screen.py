"""
Screen regression for the Amiko HD8140 Galaxy firmware v1.5.70 by Dekolte
(System ID 0E020A00, slow): a Full HD DVB-S2 satellite receiver on the
single-CPU ALi M3612 / M3801 SoC with 8 MB SPI flash (chips/m3801.py).  Its
"M3612 1.0.4" bootloader writes " ON " to the CH455 front panel on GPIO 31 / 9
and unpacks maincode(AV) ("0E020A001570") to 0x80000200.  With the ALi S3501
DVB-S2 demodulator at I2C 0x33 and Airoha AV2012 tuner at I2C 0x65 on SCB0, the
application updates the CH455 panel to "-ON-", populates userdb(64+64) at
0x73FF80, and enables GMA layer 0 to render its 30-colour 1280 x 720 ARGB8888
OSD dialog (9 GE commands), captured and compared with
hd8140_galaxy_1570_screen.png.

Usage: python run_dump_hd8140_galaxy_1570_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO HD8140/AMIKO_HD8140_Galaxy_1.5.70_by Dekolte.abs",
    expected="hd8140_galaxy_1570_screen.png",
    boot_limit_s=5 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=10,
    panel_text="-ON-",
    max_diff_pct=1.0,
    title="Amiko HD8140 (Galaxy firmware 1.5.70)",
    retries=2,
)
