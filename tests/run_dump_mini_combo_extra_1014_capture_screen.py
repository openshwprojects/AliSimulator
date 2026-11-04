"""
Screen regression for the Amiko Mini Combo Extra (v1.0.14 emu, slow): a Full HD
H.265/HEVC receiver on the ALi C3505 SoC with 256 MB DDR3 (chips/c3505.py).  Its
boot-ROM bootloader sets 0xB8000220 bit 24 to remap physical 0x0F000000..0x0FFFFFFF
to the top 16 MB of DDR, writes " ON " to the CH455 front panel on GPIO 107 / 110,
and starts seecode ("M3606 SEE") at 0xAE000200 alongside maincode(AV) at
0x80000200.  The application populates userdb(64+64) from defaultdb(PRC) over SPI
and renders its OSD dialog through the display engine, compared with
mini_combo_extra_1014_screen.png.

Usage: python run_dump_mini_combo_extra_1014_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO MINI COMBO EXTRA/AMIKO_Mini_Combo_Extra_1.0.14_emu.abs",
    expected="mini_combo_extra_1014_screen.png",
    boot_limit_s=240,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko Mini Combo Extra (v1.0.14 emu)",
    retries=2,
)
