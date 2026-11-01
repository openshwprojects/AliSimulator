"""
Screen regression for the Edision Picco S2 firmware v.1248 (System ID 73010100,
slow): a compact Full HD H.265/HEVC DVB-S2 satellite receiver on the single-CPU
ALi M3510D / C3503D SoC (chips/c3503.py: chip word 0x3503D000, bootloader
"3510DB 1.1.1").  Its boot-ROM SRAM bootloader unpacks the 12.0 MB maincode(AV)
to 0x80000200; the application drives its CH455 4-digit LED panel on GPIO 24 /
23 (" ON " -> " on "), unpacks defaultdb(PRC) into userdb(64+64), and renders its
1280 x 720 CLUT8 OSD dialog through GeM36F / GMA layer 0, captured and compared
with picco_s2_screen.png.

Usage: python run_dump_picco_s2_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Edision Picco S2 (firmware v.1248)",
    "chips": ["ALi M3510D / C3503D", "CH455"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="EDISION PICCO S2/PICCO_S2_v.1248.abs",
    expected="picco_s2_screen.png",
    boot_limit_s=15 * 60,
    settle_s=5,
    min_ge_ops=10,
    min_colours=10,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Edision Picco S2 (firmware v.1248)",
    retries=2,
)
