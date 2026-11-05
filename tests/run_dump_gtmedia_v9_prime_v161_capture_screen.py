"""
Screen regression for the GTMedia V9 Prime firmware V161 (2021-04-22):
a Full HD H.265/HEVC 10-bit DVB-S2X satellite receiver on the single-CPU ALi
M3507 / C3507 SoC (chips/c3503.py: chip word 0x35070000 -> SDK chip code
0x10056, 128-line interrupt controller at 0xB8081080 / 0xB8081040, OTP 0x210
product 5).

Usage: python run_dump_gtmedia_v9_prime_v161_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "GTMedia V9 Prime (firmware V161, 2021-04-22)",
    "chips": ["ALi M3507 / C3507", "internal S3501H", "RDA5815M", "GeM36F"],
    "shows": ["boots to screen", "single-CPU C3507", "Factory Test Page"],
}

screen_regression.run(
    dump="GTMEDIA V9 PRIME/GTMedia_V9Prime_V161_20210422.bin",
    expected="gtmedia_v9_prime_v161_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=25,
    min_colours=50,
    max_diff_pct=2.0,
    title="GTMedia V9 Prime (firmware V161, 2021-04-22)",
    retries=1,
)
