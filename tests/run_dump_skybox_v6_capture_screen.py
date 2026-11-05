"""
Screen regression for the Skybox / Freesat V6 HD firmware (4 MB SPI, ALi M3503,
chips/m3503.py).  The M3503---0.1.0 bootloader unpacks maincode to 0x80000200
and seecode to 0xA6000200, executes 187 GE commands on GMA layer 0 and renders
a 1280x720 OSD dialog (skybox_v6_screen.png).

Usage: python run_dump_skybox_v6_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Skybox / Freesat V6 HD (product_sabbat_dual)",
    "chips": ["ALi M3503 rev B", "internal S3501 DVB-S2", "GeM36F"],
    "shows": ["boots to screen", "dual-core SEE"],
}

screen_regression.run(
    dump="SKYBOX V6/product_sabbat_dual.abs",
    expected="skybox_v6_screen.png",
    boot_limit_s=60,
    settle_s=-1,
    probe_s=0,
    min_ge_ops=50,
    min_colours=100,
    slice_instructions=500_000,
    title="Skybox / Freesat V6 HD",
    retries=1,
)
