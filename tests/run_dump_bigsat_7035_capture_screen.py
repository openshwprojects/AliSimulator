"""
Screen regression for the BigSat DSR 7035 Plus 2 MB ST M29W160ET parallel-NOR
flash dump (maincode V1.07B5*, 2007-06-07, ALi M3329C / M3101, chips/m3329.py,
slow).  The S1E52-2SR bootloader unpacks maincode into SDRAM; PAN_COMMON_0
multiplexes the 4-digit 74HC164 shift-register panel on GPIO 0 / 1 and digits
GPIO 2, 3, 5, 6 (" ON " -> "Strt" -> "noCH") and OSD_M3327_0 draws the
156-colour 608x430 8 bpp CLUT "Edit Channel" main menu directly in SDRAM
(bigsat_7035_screen.png).

Usage: python run_dump_bigsat_7035_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "BigSat DSR 7035 Plus (V1.07B5*)",
    "chips": ["ALi M3329C (M3101)", "74HC164 multiplexed LED panel"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="BIGSAT DSR 7035 PLUS/bigsat 7035 plus _m29w160et_ok.bin",
    expected="bigsat_7035_screen.png",
    boot_limit_s=5 * 60,
    settle_s=5,
    min_ge_ops=0,
    min_colours=50,
    ge=False,
    panel_text="noCH",
    title="BigSat DSR 7035 Plus (V1.07B5*)",
    retries=1,
)
