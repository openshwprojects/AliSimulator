"""
Screen regression for the Amiko SHD-8140 (v1.5.41 EMU, slow): a Full HD DVB-S2
satellite receiver on the single-CPU ALi M3612 / M3801 SoC with 8 MB SPI flash
(chips/m3801.py).  Its "M3612 1.0.4" bootloader writes " ON " to the CH455 front
panel on GPIO 31 / 9 and unpacks maincode(AV) to 0x80000200.  With the ALi S3501
DVB-S2 demodulator at I2C 0x33 on SCB0, the application updates the CH455 panel
to " on ", populates userdb(64+64) at 0x73FF80, and enables GMA
layer 0 to render its 1280 x 720 ARGB8888 OSD dialog, captured and compared with
shd8140_1541_screen.png.

Usage: python run_dump_shd8140_1541_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO SHD-8140/AMIKO_SHD-8140_1.5.41_emu.abs",
    expected="shd8140_1541_screen.png",
    boot_limit_s=180,
    settle_s=5,
    min_ge_ops=8,
    min_colours=8,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko SHD-8140 (v1.5.41 EMU)",
    retries=2,
)
