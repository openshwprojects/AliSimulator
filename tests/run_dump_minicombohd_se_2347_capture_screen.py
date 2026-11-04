"""
Screen regression for the Amiko Mini Combo HD SE (v2.3.47 EMU, slow):
a Full HD receiver on the ALi M3516C / M3503 rev B SoC
with 256 MB DDR3 and 16 MB SPI flash (chips/m3503.py).  Its XIP bootloader
("M3516C 1.2.1") runs with CacheAsRam at 0x8FFF8000..0x8FFFFFFF, writes " ON " to
the CH455 front panel on GPIO 135 / 134, and starts seecode ("M3606 SEE") at
0xAE000200 alongside maincode(AV) at 0x80000200.  The application updates the
CH455 panel to " on " and draws its 1280 x 720 OSD dialog on GMA
layer 0, compared with minicombohd_se_2347_screen.png.

Usage: python run_dump_minicombohd_se_2347_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO MINI COMBO HD SE/AMIKO_MiniComboHD_SE_2.3.47_emu.abs",
    expected="minicombohd_se_2347_screen.png",
    boot_limit_s=180,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko Mini Combo HD SE (v2.3.47 EMU)",
    retries=2,
)
