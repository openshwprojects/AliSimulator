"""
Screen regression for the Amiko HD8150 Synaps firmware v2.3.40 by Dekolte
(System ID 10030A00, slow): a Full HD DVB-S2 satellite receiver on the ALi
M3511D / M3503 rev B SoC with 128 MB DDR3 (chips/m3503.py).  Its XIP bootloader
("M3511D 1.1.1") runs with CacheAsRam at 0x8FFF8000..0x8FFFFFFF, writes " ON "
to the CH455 front panel on GPIO 135 / 134, and starts seecode ("M3606 SEE") at
0xA6000200 alongside maincode(AV) at 0x80000200.  The Synaps application
updates the CH455 panel to "-ON-", populates userdb(64+64) from defaultdb(PRC)
over SPI, and draws its 1280 x 720 OSD dialog on GMA layer 0 (9 GE commands),
compared with hd8150_screen.png.

Usage: python run_dump_hd8150_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko HD8150 (Synaps v2.3.40)",
    "chips": ["ALi M3511D / M3503", "CH455"],
    "shows": ["boots to screen", "second CPU (SEE)", "front panel"],
}

screen_regression.run(
    dump="AMIKO HD8150/AMIKO_HD8150_2.3.40_Synaps_2.3.40_by Dekolte.abs",
    expected="hd8150_screen.png",
    boot_limit_s=4 * 60,
    settle_s=5,
    min_ge_ops=9,
    min_colours=4,
    panel_text="-ON-",
    max_diff_pct=1.0,
    title="Amiko HD8150 (Synaps firmware v2.3.40)",
    retries=2,
)
