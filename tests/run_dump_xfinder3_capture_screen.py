"""
Screen regression for the Amiko X-Finder 3 firmware v1.0.49 emu (System ID
70020A00, slow): a handheld H.265/HEVC DVB-S2 + DVB-T2/C combo signal meter on
the ALi M3529F / C3505 SoC with 256 MB DDR3 (chips/c3505.py).  Its boot-ROM
bootloader sets 0xB8000220 bit 24 to remap physical 0x0F000000..0x0FFFFFFF to
the top 16 MB of DDR and starts seecode ("M3505 SEE") at 0xAE000200 alongside
maincode(AV) at 0x80000200.  The application initialises its Availink AVL6762
demodulator (SCB3 0x14) and MaxLinear MxL603 tuner (SCB3 0x60), populates
userdb(64+64) from defaultdb(PRC) over SPI, and renders its OSD dialog through
the display engine's G1 CLUT8 layer at 0xB8006A00 (DMA register-list channel
0x6088, 256-entry ARGB8888 palette at 0x6AEC), compared with
xfinder3_screen.png.

Usage: python run_dump_xfinder3_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko X-Finder 3 (v1.0.49 emu)",
    "chips": ["ALi M3529F / C3505 (256 MB)", "AVL6762", "MxL603", "CH455"],
    "shows": ["boots to screen", "second CPU (SEE)"],
}

screen_regression.run(
    dump="AMIKO X-FINDER 3/AMIKO_XFinder_III_1.0.49_emu.abs",
    expected="xfinder3_screen.png",
    boot_limit_s=4 * 60,
    settle_s=5,
    min_ge_ops=4,
    min_colours=4,
    max_diff_pct=1.0,
    title="Amiko X-Finder 3 (firmware v1.0.49 emu)",
    retries=2,
)
