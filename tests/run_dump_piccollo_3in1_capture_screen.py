"""
Screen regression for the Edision Piccollo 3in1 Plus CI firmware v.2475 (System
ID 14000800, slow): a Full HD DVB-S2 + DVB-T2/C combo receiver on the ALi
M3516A / M3503 SoC with 256 MB DDR3 and a 16 MB SPI flash (chips/m3503.py).  Its
XIP bootloader runs with a cache-as-RAM stack at 0x8FFF8000..0x8FFFFFFF, copies
itself to 0x81400000, sets 0xB8000220 bit 24 to remap physical
0x0F000000..0x0FFFFFFF to the top 16 MB of DDR, parks the SEE boot stub, unpacks
seecode ("M3606 SEE") to 0xAE000200 and maincode(AV) to 0x80000200, and starts
both cores.  The application initialises its external Availink AVL6762 DVB-T2/C
demodulator at I2C 0x14 over bit-banged GPIO 7 / 8 ("Demod is 6762!!!") and
Airoha AV2012 DVB-S2 tuner at I2C 0x61 on SCB0, drives its CH455 4-digit LED
panel on GPIO 135 / 134 (" ON " -> " on "), populates userdb(64+64) at
0xF3FF80, and renders its 1280x720 CLUT8 OSD dialog through GeM36F / GMA layer
0, captured and compared with piccollo_3in1_screen.png.

Usage: python run_dump_piccollo_3in1_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Edision Piccollo 3in1 Plus CI (v.2475)",
    "chips": ["ALi M3516A / M3503 (256 MB)", "AVL6762", "AV2012", "CH455"],
    "shows": ["boots to screen", "second CPU (SEE)", "front panel"],
}

screen_regression.run(
    dump="EDISION PICCOLLO 3IN1 PLUS CI/piccollo_3in1_PLUS_CI_2475.abs",
    expected="piccollo_3in1_screen.png",
    boot_limit_s=15 * 60,
    settle_s=5,
    min_ge_ops=9,
    min_colours=3,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Edision Piccollo 3in1 Plus CI (firmware v.2475)",
    retries=2,
)
