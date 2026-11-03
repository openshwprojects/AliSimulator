"""
Screen regression for the Amiko X-Finder+ handheld DVB-S2/T2/C signal meter
firmware 1.0.33 emu (System ID 17010000, ALi M3516F / M3503 with 256 MB DDR3 and
16 MB SPI flash, chips/m3503.py).  The XIP bootloader drives CH455 (" ON ") on
GPIO 135 / 134, unpacks 2.96 MB seecode ("M3606 SEE") to 0xAE000200 and 10.46 MB
maincode(AV) to 0x80000200; PAN_CH455_0 drives the handheld meter's status LEDs
and scans its keypad on GPIO 135 / 134, and the application draws its 1280x720
CLUT8 GMA layer 0 dialog through GeM36F (xfinder_plus_screen.png).

Usage: python run_dump_xfinder_plus_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko X-Finder+ handheld meter (firmware 1.0.33 emu)",
    "chips": ["ALi M3516F (M3503, 256 MB DDR3)", "CH455 keypad/LED controller"],
    "shows": ["boots to screen", "second CPU (SEE)"],
}

screen_regression.run(
    dump="AMIKO X-FINDER+/AMIKO_XFinder_Plus_1.0.33_emu.abs",
    expected="xfinder_plus_screen.png",
    boot_limit_s=5 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=3,
    panel_text="    ",
    title="Amiko X-Finder+ handheld meter (firmware 1.0.33 emu)",
    retries=1,
)
