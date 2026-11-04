"""
Screen regression for the Amiko HD8150 (Galaxy v2.4.16 by Dekolte, slow): a Full HD
DVB-S2 satellite receiver on the ALi M3503 rev B SoC with 128 MB DDR3
(chips/m3503.py).  Its XIP bootloader runs with CacheAsRam at 0x8FFF8000..0x8FFFFFFF,
writes " ON " to the CH455 front panel on GPIO 135 / 134, and starts seecode
("M3606 SEE") at 0xA6000200 alongside maincode(AV) at 0x80000200.  The application
updates the CH455 panel to "-ON-", populates userdb(64+64) from
defaultdb(PRC) over SPI, and draws its 1280 x 720 OSD dialog on GMA layer 0,
compared with hd8150_galaxy_2416_screen.png.

Usage: python run_dump_hd8150_galaxy_2416_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO HD8150/AMIKO_HD8150_Galaxy_2.4.16_by Dekolte.abs",
    expected="hd8150_galaxy_2416_screen.png",
    boot_limit_s=180,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text="-ON-",
    max_diff_pct=1.0,
    title="Amiko HD8150 (Galaxy v2.4.16 by Dekolte)",
    retries=2,
)
