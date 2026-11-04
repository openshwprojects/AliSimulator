"""
Screen regression for the Amiko HD8142 Twin-C (firmware v1.1.25 emu, System ID
72010A00, slow): a dual-tuner Full HD H.265/HEVC DVB-C cable receiver on the ALi
M3716A / C3505 SoC with 128 MB DDR3 and 8 MB SPI flash (chips/c3505.py).  Its
boot-ROM bootloader runs in boot SRAM at 0x9FE00800, unpacks seecode ("M3606
SEE") to 0xA6000200 and maincode(AV) ("72010A001125") to 0x80000200, and starts
both cores.  The application initialises its Rafael Micro R858 dual-path cable
tuner at I2C 0x6A, drives its CH455 4-digit LED panel on GPIO 107 / 108 (" ON "
-> " on "), and renders its OSD dialog through the display engine, captured and
compared with hd8142_twinc_1125_screen.png.

Usage: python run_dump_hd8142_twinc_1125_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO HD8142 TWIN-C/Amiko_HD8142_Twin-C_1.1.25_emu.abs",
    expected="hd8142_twinc_1125_screen.png",
    boot_limit_s=240,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko HD8142 Twin-C (firmware v1.1.25 emu)",
    retries=2,
)
