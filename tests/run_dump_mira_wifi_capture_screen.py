"""
Screen regression for the Amiko Mira WiFi firmware v1.1.74 (System ID 67010A00,
slow): a compact Full HD DVB-S2 satellite receiver with built-in Wi-Fi on the
single-CPU ALi M3510C / C3503C SoC (chips/c3503.py: chip word 0x3503C000, OTP
0x210 product 5).  Its boot-ROM SRAM bootloader ("3510CA 1.1.1") copies itself
to 0x81000000, verifies and unpacks the 13.9 MB maincode(AV) to 0x80000200, and
starts the single-CPU application.  The application initialises hs_config_init
and userdb(64+64) and renders its 4-colour 1280 x 720 CLUT8 OSD dialog through
GeM36F / GMA layer 0 (9 GE commands), captured and compared with
mira_wifi_screen.png.

Usage: python run_dump_mira_wifi_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko Mira WiFi (v1.1.74)",
    "chips": ["ALi M3510C / C3503C"],
    "shows": ["boots to screen"],
}

screen_regression.run(
    dump="AMIKO MIRA WIFI/AMIKO_Mira_1.1.74_emu.abs",
    expected="mira_wifi_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=3,
    max_diff_pct=1.0,
    title="Amiko Mira WiFi (firmware v1.1.74)",
    retries=2,
)
