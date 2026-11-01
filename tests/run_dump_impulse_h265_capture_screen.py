"""
Screen regression for the Amiko Impulse H.265 T2/C firmware v1.3.87 (System ID
74000A00, slow): a Full HD H.265/HEVC DVB-T2/C terrestrial and cable receiver on
the ALi M3626A / C3505 SoC with 128 MB DDR3 (chips/c3505.py).  Its boot-ROM
bootloader runs in boot SRAM at 0x9FE00800, unpacks maincode(AV) (chips/base.py)
to 0x80000200 and seecode ("M3606 SEE") to 0xA6000200, and starts both cores.
The application initialises its external Availink AVL6762 DVB-T2/C demodulator
at I2C 0x14 and MaxLinear MxL608 tuner at I2C 0x60 over bit-banged GPIO 105 /
104 ("Demod is 6762!!!", tuned to 474 MHz / 8 MHz), drives its CH455 4-digit LED
panel on GPIO 107 / 110 (" ON " -> " on ") and renders its 1280 x 720 ARGB8888
OSD dialog through the display engine at 0xB8006900, captured and compared with
impulse_h265_screen.png.

Usage: python run_dump_impulse_h265_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko Impulse H.265 T2/C (v1.3.87)",
    "chips": ["ALi M3626A / C3505 (128 MB)", "AVL6762", "MxL608", "CH455"],
    "shows": ["boots to screen", "second CPU (SEE)", "front panel", "tuner"],
}

screen_regression.run(
    dump="AMIKO IMPULSE H265 T2C/AMIKO_Impluse_H265_T2C_1.3.87_emu.abs",
    expected="impulse_h265_screen.png",
    boot_limit_s=15 * 60,
    settle_s=5,
    min_ge_ops=5,
    min_colours=10,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Amiko Impulse H.265 T2/C (firmware v1.3.87)",
    retries=2,
)
