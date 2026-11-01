"""
Screen regression for the Edision Optimuss Underline 3in1 firmware 1.3.79 emu
(System ID 0E060800, slow): a compact Full HD DVB-S2 + DVB-T2/C 3-in-1 combo
receiver on the single-CPU ALi M3612 SoC (chips/m3801.py: chip ID 0x3811,
ALI_S3811, bootloader "M3612 1.0.4").  Its MIPS16e bootloader unpacks the
11.6 MB maincode(AV) to 0x80000200; the application probes its external
Availink AVL6862 combo demodulator on SCB0 at I2C 0x14 (ChipID 0x0F ->
"Demod is 6862!!!", demods.AVL6862A), configures both the Sharp VZ7903 /
AV2012 DVB-S2 tuner (0x61) and Rafael Micro R836 DVB-T2/C tuner (0x3A), drives
its CH455 4-digit LED panel on GPIO 31 / 9 (" ON " -> " on "), unpacks
defaultdb(PRC) into userdb(64+64), and renders its 32-bpp ARGB8888 OSD dialog
through GeM36F / GMA layer 0, captured and compared with
underline_3in1_screen.png.

Usage: python run_dump_underline_3in1_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Edision Optimuss Underline 3in1 (firmware 1.3.79 emu)",
    "chips": ["ALi M3612 (S3811)", "AVL6862A", "AV2012 (VZ7903)", "R836", "CH455"],
    "shows": ["boots to screen", "front panel"],
}

screen_regression.run(
    dump="EDISION OPTIMUSS UNDERLINE 3IN1/Edision.optimuss.underline.3in1.0E06080emu_1.3.79.abs",
    expected="underline_3in1_screen.png",
    boot_limit_s=15 * 60,
    settle_s=5,
    min_ge_ops=8,
    min_colours=4,
    panel_text=" on ",
    max_diff_pct=1.0,
    title="Edision Optimuss Underline 3in1 (firmware 1.3.79 emu)",
    retries=2,
)
