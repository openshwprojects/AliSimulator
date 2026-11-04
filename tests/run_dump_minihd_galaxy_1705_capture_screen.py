"""
Screen regression for the Amiko Mini HD (Galaxy v1.7.05 by Dekolte, System ID
0A070A00, slow): a compact Full HD DVB-S2 satellite receiver on the dual-CPU ALi
M3606F / C3603 SoC with 8 MB SPI flash (chips/m3602.py).  Its "M3606F 1.1.3"
bootloader parks the SEE boot stub at 0xA1E8F988, unpacks seecode ("M3606 SEE")
to 0xA7000200 and maincode(AV) to 0x80000200, and starts both cores.  The
application configures its ALi S3501 DVB-S2 demodulator at I2C 0x33, populates
userdb(64+64) at 0x73FF80, and draws its 1280 x 720 ARGB8888 OSD dialog through
GeM36F / GMA layer 0, captured and compared with minihd_galaxy_1705_screen.png.

Usage: python run_dump_minihd_galaxy_1705_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO MINI HD/AMIKO_MiniHD_Galaxy_1.7.05_by Dekolte.abs",
    expected="minihd_galaxy_1705_screen.png",
    boot_limit_s=180,
    settle_s=5,
    min_ge_ops=5,
    min_colours=4,
    panel_text=None,
    max_diff_pct=1.0,
    title="Amiko Mini HD (Galaxy v1.7.05 by Dekolte)",
    retries=2,
)
