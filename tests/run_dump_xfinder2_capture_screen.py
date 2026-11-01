"""
Screen regression for the Amiko X-Finder 2 handheld DVB-S2/T2/C signal meter
firmware 2.0.48 emu (System ID 14050000, ALi M3516A / M3503 with 256 MB DDR3 and
16 MB SPI flash, chips/m3503.py, slow).  The XIP bootloader drives CH455 (" ON ")
on GPIO 135 / 134, unpacks 3.1 MB seecode ("M3606 SEE") to 0xAE000200 and 11.5 MB
maincode(AV) to 0x80000200; PAN_PT6311 initialises the handheld meter's
Lemontree-protocol MCU at I2C 0x28 on GPIO 135 / 134 ("Front Panel init ok"), and
the application draws its 1920x1080 CLUT8 GMA layer 0 dialog through GeM36F
(xfinder2_screen.png).

Usage: python run_dump_xfinder2_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko X-Finder 2 handheld meter (firmware 2.0.48 emu)",
    "chips": ["ALi M3516A (M3503, 256 MB DDR3)", "Lemontree handheld MCU (I2C 0x28)"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="AMIKO X-FINDER 2/AMIKO_XFinder2_2.0.48_emu.abs",
    expected="xfinder2_screen.png",
    boot_limit_s=5 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=3,
    panel_text=" ON ",
    title="Amiko X-Finder 2 handheld meter (firmware 2.0.48 emu)",
    retries=1,
)
