"""
Screen regression for the Amiko HD8275+ firmware v1.5.52 emu (System ID
6C000A00, slow): a Full HD H.265/HEVC DVB-S2 + DVB-T2/C combo receiver on the
ALi M3529A / C3505 SoC with 256 MB DDR3 (chips/c3505.py).  Its boot-ROM
bootloader writes " ON " to the CH455 front panel on GPIO 107 / 108, sets
0xB8000220 bit 24 to remap physical 0x0F000000..0x0FFFFFFF to the top 16 MB of
DDR, and starts seecode ("M3606 SEE") at 0xAE000200 alongside maincode(AV) at
0x80000200.  The application updates the CH455 panel to " on ", initialises its
Availink AVL6762 DVB-T2/C demodulator (I2C 0x14 on SCB3), Airoha AV2012 DVB-S2
tuner (I2C 0x61 on SCB1) and MaxLinear MxL608 DVB-T2/C tuner (I2C 0x60 on
SCB3), populates userdb(64+64) from defaultdb(PRC) over SPI, and renders its
OSD dialog through the display engine's G1 CLUT8 layer at 0xB8006A00 (5 GE
commands), compared with hd8275_1552_screen.png.

Usage: python run_dump_hd8275_1552_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO HD8275+/Amiko_HD8275_1.5.52_emu.abs",
    expected="hd8275_1552_screen.png",
    boot_limit_s=4 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko HD8275+ (firmware v1.5.52 emu)",
    retries=2,
)
