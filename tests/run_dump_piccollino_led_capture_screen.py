"""
Screen regression for the Edision Piccollino LED firmware v.2475 (System ID
10040800, slow): a compact Full HD DVB-S2 satellite receiver on the ALi M3511E /
M3503 rev B SoC with 128 MB DDR3 (chips/m3503.py).  Its XIP bootloader
("M3511E 1.1.1") runs with CacheAsRam at 0x8FFF8000..0x8FFFFFFF, writes " ON "
to the CH455 front panel on GPIO 135 / 134, and starts seecode ("M3606 SEE") at
0x86000200 alongside maincode(AV) at 0x80000200.  The application updates the
CH455 panel to " on ", populates userdb(64+64) from defaultdb(PRC) over SPI, and
draws its 1280 x 720 OSD dialog on GMA layer 0, compared with
piccollino_led_screen.png.

Usage: python run_dump_piccollino_led_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Edision Piccollino LED (v.2475)",
    "chips": ["ALi M3511E / M3503", "CH455"],
    "shows": ["boots to screen", "second CPU (SEE)", "front panel"],
}

screen_regression.run(
    dump="EDISION PICCOLLINO LED/Piccollino_v.2475.abs",
    expected="piccollino_led_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Edision Piccollino LED (firmware v.2475)",
    retries=2,
)
