"""
Screen regression for the Amiko Mini HD265 (Edision firmware v.1521, System ID 6B000A00): a
compact Full HD H.265/HEVC DVB-S2 satellite receiver on the ALi M3521A / C3505
SoC with 128 MB DDR3 (chips/c3505.py).  Its boot-ROM bootloader runs in boot
SRAM at 0x9FE00800, unpacks maincode(AV) to 0x80000200 and seecode ("M3606 SEE")
to 0xA6000200, and starts both cores.  The application drives its CH455 4-digit
LED panel on GPIO 107 / 110 (" ON " -> " on ") and renders its 1280 x 720
ARGB8888 OSD dialog through the display engine at 0xB8006900, captured and
compared with mini_hd265_v1521_screen.png.

Usage: python run_dump_mini_hd265_v1521_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO MINI HD265/AMIKO MINI HD265 Edision v.1521.abs",
    expected="mini_hd265_v1521_screen.png",
    boot_limit_s=240,
    settle_s=5,
    min_ge_ops=5,
    min_colours=10,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko Mini HD265 (Edision firmware v.1521)",
    retries=2,
)
