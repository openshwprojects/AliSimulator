"""
Screen regression for the GTMedia V9 Prime firmware V207 (2025-03-20, slow):
a Full HD H.265/HEVC 10-bit DVB-S2X satellite receiver on the single-CPU ALi
M3507 / C3507 SoC (chips/c3503.py: chip word 0x35070000 -> SDK chip code
0x10056, 128-line interrupt controller at 0xB8081080 / 0xB8081040, OTP 0x210
product 5).  Its XIP bootloader ("M3507---3") relocates to 0x82800000, unpacks
the 15.69 MB maincode ("V1.10B1*") to 0x80100200, and starts the single-CPU
application.  With the internal S3501H demodulator's chip ID 0x350100C0 at
0xB804C140, the application decodes its boot logo and renders its 1280 x 720
32-bpp ARGB8888 "Factory Test Page" OSD on GMA layer 0 (70 colours, 157 GE
commands), captured and compared with gtmedia_v9_prime_v207_screen.png.

Usage: python run_dump_gtmedia_v9_prime_v207_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="GTMEDIA V9 PRIME/GTMedia_V9Prime_Release_V207_20250320.bin",
    expected="gtmedia_v9_prime_v207_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=25,
    min_colours=50,
    max_diff_pct=2.0,
    title="GTMedia V9 Prime (firmware V207, 2025-03-20)",
    retries=2,
)
