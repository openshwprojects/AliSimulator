"""
Screen regression for the BigSat DSR 6500 Lux 2 MB parallel-NOR flash dump
(maincode 2007-10-14, ALi M3329C / M3101, chips/m3329.py, slow).  The 1.1.1
bootloader unpacks maincode(AV) from parallel NOR into SDRAM; PAN_COMMON_0
multiplexes the 4-digit 74HC164 shift-register panel on GPIO 16..21 (" ON " ->
"----") and OSD_M3327_0 draws the 58-colour 720x576 8 bpp CLUT "Information -
No program found!" dialog directly in SDRAM (bigsat_6500_screen.png).

Usage: python run_dump_bigsat_6500_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "BigSat DSR 6500 Lux (2007-10-14)",
    "chips": ["ALi M3329C (M3101)", "74HC164 multiplexed LED panel"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="BIGSAT DSR 6500 LUX/dump bigsat 6500 lux.bin",
    expected="bigsat_6500_screen.png",
    boot_limit_s=5 * 60,
    settle_s=5,
    min_ge_ops=0,
    min_colours=16,
    ge=False,
    panel_text="----",
    title="BigSat DSR 6500 Lux (2007-10-14)",
    retries=1,
)
