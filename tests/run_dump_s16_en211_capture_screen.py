"""
Screen regression for the Openbox S16 EN2.11 firmware (ALi S3606H / M3606C
dual-CPU DVB-S2 HD satellite receiver on a 4 MB SPI flash, chips/m3602.py with
device.chipId 0x3603, S3501 demodulator at 0x33 and AV2011 tuner at 0x63).

Usage: python run_dump_s16_en211_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Openbox S16 EN2.11 (ALi S3606H / M3606C)",
    "chips": ["ALi S3606H (C3603)", "S3501", "AV2011", "TM1650"],
    "shows": ["boots to screen", "SEE second core", "front panel"],
}

screen_regression.run(
    dump="OPENBOX S16/S16_EN2.11.abs",
    expected="s16_en211_screen.png",
    boot_limit_s=180,
    settle_s=0,
    probe_s=0,
    slice_instructions=500_000,
    min_ge_ops=12,
    min_colours=100,
    panel_text="OOO1",
    title="Openbox S16 EN2.11",
    retries=1,
)
