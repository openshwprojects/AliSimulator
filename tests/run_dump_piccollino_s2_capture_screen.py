"""
Screen regression for the Edision Piccollino S2 firmware v.1375 (System ID
6B000100, slow): a Full HD H.265/HEVC DVB-S2 satellite receiver on the ALi
M3521A / C3505 SoC with 128 MB DDR3 and an 8 MB SPI flash (chips/c3505.py).  Its
boot-ROM bootloader runs in boot SRAM at 0x9FE00800, copies itself to
0x81000000, shows the boot logo through VideoOutputM36F (video_m36.py), unpacks
seecode ("M3606 SEE") to 0xA6000200 and maincode(AV) to 0x80000200, and starts
both cores.  The application drives its CH455 4-digit LED panel on GPIO 107 /
110 (" ON " -> " on ") and renders its 1280 x 720 ARGB8888 OSD dialog through
the display engine at 0xB8006900 (5 GE commands, 14 colours), captured and
compared with piccollino_s2_screen.png.

Usage: python run_dump_piccollino_s2_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Edision Piccollino S2 (v.1375)",
    "chips": ["ALi M3521A / C3505 (128 MB)", "CH455"],
    "shows": ["boots to screen", "second CPU (SEE)", "front panel"],
}

screen_regression.run(
    dump="EDISION PICCOLLINO S2/Piccollino_S2_v.1375.abs",
    expected="piccollino_s2_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=3,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Edision Piccollino S2 (firmware v.1375)",
    retries=2,
)
