"""
Screen regression for the Amiko HD8255+ firmware v1.3.88 EMU (System ID
6C000A00, slow): a Full HD H.265/HEVC DVB-S2 CI+ satellite receiver on the ALi
M3529A / C3505 SoC with 256 MB DDR3 and an 8 MB SPI flash (chips/c3505.py).  Its
boot-ROM bootloader runs in boot SRAM at 0x9FE00800, copies itself to
0x81000000, sets 0xB8000220 bit 24 to remap physical 0x0F000000..0x0FFFFFFF to
the top 16 MB of DDR, shows the boot logo through VideoOutputM36F (video_m36.py),
unpacks seecode ("M3606 SEE") to 0xAE000200 and maincode(AV) to 0x80000200, and
starts both cores.  The application drives its CH455 4-digit LED panel on GPIO
107 / 108 (" ON " -> " on "), completes 2,136 SEE RPC calls (including DSC
Command Queue operations in crypto_engine.py), and renders its 1280 x 720
ARGB8888 OSD dialog through the display engine at 0xB8006900, captured and
compared with hd8255_plus_screen.png.

Usage: python run_dump_hd8255_plus_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko HD8255+ (v1.3.88)",
    "chips": ["ALi M3529A / C3505 (256 MB)", "CH455"],
    "shows": ["boots to screen", "second CPU (SEE)", "front panel"],
}

screen_regression.run(
    dump="AMIKO HD8255+/Amiko_HD8255_1.3.88_emu.abs",
    expected="hd8255_plus_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=3,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko HD8255+ (firmware v1.3.88)",
    retries=2,
)
