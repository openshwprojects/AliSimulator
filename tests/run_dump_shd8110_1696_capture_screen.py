"""
Screen regression for the Amiko SHD-8110 (v1.6.96 EMU, System ID
0B000A00, slow): a Full HD DVB-S2 satellite receiver on the dual-CPU ALi M3601A
/ M3606 (C3603) SoC with 8 MB SPI flash (chips/m3602.py).  Its "M3601A 1.1.3"
bootloader parks the SEE boot stub at 0xA1E9103C, unpacks seecode ("M3606 SEE")
to 0xA7000200 and maincode(AV) to 0x80000200, and starts both cores.  The
application configures its ALi S3501 DVB-S2 demodulator at I2C 0x33, populates
userdb(64+64) at 0x73FF80, and draws its 1280 x 720 ARGB8888 OSD dialog through
GeM36F / GMA layer 0, captured and compared with shd8110_1696_screen.png.

Usage: python run_dump_shd8110_1696_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO SHD-8110/AMIKO_SHD-8110_1.6.96_emu.abs",
    expected="shd8110_1696_screen.png",
    boot_limit_s=180,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=None,
    max_diff_pct=1.0,
    title="Amiko SHD-8110 (v1.6.96 EMU)",
    retries=2,
)
