"""
Screen regression for the Amiko Eco TC-200 firmware v2.3.09 (System ID
22000A88, slow): a Full HD DVB-T2/C terrestrial and cable receiver on the ALi
M3821A SoC with 128 MB DDR3 and 8 MB SPI flash (chips/m3821.py).  Its XIP
"M3821A 1.1.1" bootloader runs through cache-as-RAM, unpacks seecode ("M3606
SEE") and maincode(AV) ("22000A882309"), and starts both cores (SEE at
0xA6000200).  The application drives its CH455 4-digit LED panel on GPIO 128 /
129 (" ON " -> " on ") and renders its 1280 x 720 OSD dialog through GE_M36F,
captured and compared with eco_tc200_screen.png.

Usage: python run_dump_eco_tc200_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko Eco TC-200 (firmware v2.3.09)",
    "chips": ["ALi M3821A", "CH455"],
    "shows": ["boots to screen", "second CPU (SEE)", "front panel"],
}

screen_regression.run(
    dump="AMIKO ECO TC-200/AMIKO_ECO_TC-200_2.3.09_emu.abs",
    expected="eco_tc200_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko Eco TC-200 (firmware v2.3.09)",
    retries=2,
)
