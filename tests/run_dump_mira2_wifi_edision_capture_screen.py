"""
Screen regression for the Amiko Mira2 WiFi Edision firmware v.1231 (System ID
73010A00, slow): a compact Full HD H.265/HEVC DVB-S2 satellite receiver with
built-in Wi-Fi on the single-CPU ALi M3510D / C3503D SoC (chips/c3503.py: chip
word 0x3503D000, bootloader "3510DB 1.1.1").  Its boot-ROM SRAM bootloader
writes " ON " to the CH455 panel on GPIO 24 / 23 and unpacks the 12.51 MB
maincode(AV) to 0x80000200; the application updates the panel to " on ",
unpacks defaultdb(PRC) into userdb(64+64), and renders its 4-colour 1280 x 720
CLUT8 OSD dialog through GeM36F / GMA layer 0, captured and compared with
mira2_wifi_edision_screen.png.

Usage: python run_dump_mira2_wifi_edision_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko Mira2 WiFi (Edision v.1231)",
    "chips": ["ALi M3510D / C3503D", "CH455"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="AMIKO MIRA2 WIFI/AMIKO MIRA WIFI 2 Edision_v.1231.abs",
    expected="mira2_wifi_edision_screen.png",
    boot_limit_s=15 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=3,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko Mira2 WiFi (Edision v.1231)",
    retries=2,
)
