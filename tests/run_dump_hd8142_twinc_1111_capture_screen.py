"""
Screen regression for the Amiko HD8142 Twin-C firmware v1.1.11 emu (System ID
72010A00, slow): a dual-tuner Full HD H.265/HEVC DVB-C cable receiver on the ALi
M3716A / C3505 SoC with 128 MB DDR3 (chips/c3505.py).  Its boot-ROM bootloader
writes " ON " to the CH455 front panel on GPIO 107 / 108 and starts seecode
("M3606 SEE") at 0xA6000200 alongside maincode(AV) at 0x80000200.  The
application updates the CH455 panel to " on ", configures its Rafael Micro R858
dual-path cable tuner on SCB1 at I2C 0x6A, populates userdb(64+64) from
defaultdb(PRC) over SPI, and renders its OSD dialog through the display
engine's G1 CLUT8 layer at 0xB8006A00, compared with hd8142_twinc_1111_screen.png.

Usage: python run_dump_hd8142_twinc_1111_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO HD8142 TWIN-C/Amiko_HD8142_Twin-C_1.1.11_emu.abs",
    expected="hd8142_twinc_1111_screen.png",
    boot_limit_s=240,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko HD8142 Twin-C (firmware v1.1.11 emu)",
    retries=2,
)
