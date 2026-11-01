"""
Screen regression for the Amiko HD8140C SE firmware v1.1.04 emu (System ID
72020A00, slow): a Full HD H.265/HEVC DVB-C cable receiver on the ALi M3712A /
C3505 SoC with 128 MB DDR3 (chips/c3505.py).  Its boot-ROM bootloader writes
" ON " to the CH455 front panel on GPIO 107 / 108 and starts seecode
("M3606 SEE") at 0xA6000200 alongside maincode(AV) at 0x80000200.  The
application updates the CH455 panel to " on ", registers its MaxLinear MxL603
cable tuner on SCB1 at I2C 0x60, populates userdb(64+64) from defaultdb(PRC)
over SPI, and renders its OSD dialog through the display engine's G1 CLUT8
layer at 0xB8006A00 (5 GE commands), compared with hd8140c_se_screen.png.

Usage: python run_dump_hd8140c_se_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko HD8140C SE (v1.1.04 emu)",
    "chips": ["ALi M3712A / C3505", "MxL603", "CH455"],
    "shows": ["boots to screen", "second CPU (SEE)", "front panel"],
}

screen_regression.run(
    dump="AMIKO HD8140C SE/Amiko_HD8140C_SE_1.1.04_emu.abs",
    expected="hd8140c_se_screen.png",
    boot_limit_s=4 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko HD8140C SE (firmware v1.1.04 emu)",
    retries=2,
)
