"""
Screen regression for the Opticum X80 Premium 2 MB SPI flash dump (firmware
V1.2.62C, ALi M3329C / M3101C, chips/m3329.py, slow).  The ETK01---0.1.0
bootloader reads from SPI flash through SF_INS / SF_FMT (0xB8000098) and
unpacks its 2.7 MB LZMA Libcore 1.3.4 maincode into SDRAM; the application
drives its 4-digit panel on GPIO 30 / 31 (" on " -> "----" -> "OOO1"), shows
channel 0001 ("$Pershiy Nacionaln") and settles on its "Немає сигналу!" box
drawn by the CPU into OSD_M3327C (x80_premium_screen.png).  Pressing MENU and
DOWN through its 0x0101 key table and $gp customer code 0x02370000 opens the
3D-icon main menu and steps the highlight to "Інсталяція" (x80_premium_nav.png).

Usage: python run_dump_x80_premium_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Opticum X80 Premium (firmware V1.2.62C)",
    "chips": ["ALi M3329C (M3101C)", "CH455 / TM1650 panel"],
    "shows": ["boots to screen", "front panel", "remote navigation"],
}

screen_regression.run(
    dump="OPTICUM X80 PREMIUM/dump opticum x80 premium.bin",
    expected="x80_premium_screen.png",
    boot_limit_s=5 * 60,
    settle_s=20,
    min_ge_ops=0,
    min_colours=3,
    ge=False,
    panel_text="OOO1",
    title="Opticum X80 Premium (firmware V1.2.62C)",
    retries=1,
    navigation=[("MENU", 20000), ("DOWN", 4000)],
)
