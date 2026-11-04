"""
Screen regression for the Amiko Micro HD SE (Starlight v2.3.50 by Dekolte, slow): a compact Full HD
DVB-S2 satellite receiver on the ALi M3503 rev B SoC with 128 MB DDR3
(chips/m3503.py).  Its XIP bootloader runs with CacheAsRam at 0x8FFF8000..0x8FFFFFFF,
writes " ON " to the CH455 front panel on GPIO 135 / 134, and starts seecode
("M3606 SEE") at 0xA6000200 alongside maincode(AV) at 0x80000200.  The application
updates the CH455 panel to " on ", populates userdb(64+64) from
defaultdb(PRC) over SPI, and draws its 1280 x 720 OSD dialog on GMA layer 0,
compared with microhd_se_starlight_2350_screen.png.

Usage: python run_dump_microhd_se_starlight_2350_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO MICRO HD SE/AMIKO_MicroHD_SE_Starlight_2.3.50_by Dekolte.abs",
    expected="microhd_se_starlight_2350_screen.png",
    boot_limit_s=180,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text="OOO1",
    max_diff_pct=1.0,
    title="Amiko Micro HD SE (Starlight v2.3.50 by Dekolte)",
    retries=2,
)
