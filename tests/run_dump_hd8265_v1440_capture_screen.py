"""
Screen regression for the Amiko HD8265+ (firmware v.1440, System ID 6C000A00,
slow): a Full HD H.265/HEVC DVB-S2 + DVB-T2/C combo receiver on the ALi M3529A
/ C3505 SoC with 256 MB DDR3 (chips/c3505.py).  Its boot-ROM bootloader sets
0xB8000220 bit 24 to remap physical 0x0F000000..0x0FFFFFFF to the top 16 MB of
DDR and starts seecode ("M3606 SEE") at 0xAE000200 alongside maincode(AV) at
0x80000200.  The application initialises its Availink AVL6762 DVB-T2/C
demodulator (I2C 0x14 on SCB3), Airoha AV2012 DVB-S2 tuner (I2C 0x61 on SCB1)
and MaxLinear MxL608 DVB-T2/C tuner (I2C 0x60 on SCB3), drives its CH455 front
panel on GPIO 107 / 108 (" ON " -> " on "), populates its blank userdb(64+64)
partition from defaultdb(PRC) over SPI, and renders its 1280 x 720 ARGB8888 OSD
dialog through the display engine at 0xB8006900, captured and compared with
hd8265_v1440_screen.png.

Usage: python run_dump_hd8265_v1440_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

screen_regression.run(
    dump="AMIKO HD8265+/AMIKO HD8265+_v.1440.abs",
    expected="hd8265_v1440_screen.png",
    boot_limit_s=120,
    settle_s=5,
    min_ge_ops=5,
    min_colours=10,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko HD8265+ (firmware v.1440)",
    retries=4,
)
