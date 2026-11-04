"""
Screen regression for the Ferguson Ariva 53 patched firmware V1.33B5_PATCH
(slow, about 1 minute): a compact Full HD DVB-S2 satellite receiver on the
single-CPU ALi C3503C SoC (chips/c3503.py: chip word 0x3503C000, OTP DVB-S2
product ID 5 at 0x210, internal S3501-class DVB-S2 demodulator at 0xB804C000,
ALi M3031 tuner at I2C 0x20).  With an empty channel database the application
draws its 1280 x 720 "System Setup" OSD menu through GMA layer 0 at 0xB8006300,
captured and compared with a53_v133b5_patch_screen.png.

Usage: python run_dump_a53_v133b5_patch_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="FERGUSON ARIVA 53/A53_20180528_V1.33B5_PATCH.abs",
    expected="a53_v133b5_patch_screen.png",
    boot_limit_s=20 * 60,
    settle_s=15,
    min_ge_ops=14,
    min_colours=60,
    max_diff_pct=1.0,
    title="Ferguson Ariva 53 (firmware V1.33B5_PATCH)",
    retries=2,
)
