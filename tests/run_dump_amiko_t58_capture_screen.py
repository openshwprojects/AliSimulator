"""
Screen regression for the Amiko T58 FTA firmware 1.0.60 (4 MB SPI, single-CPU
ALi M3821, chips/m3821.py, slow).  The XIP Cache-as-RAM BootLoader 1.0.0
trains DDR, writes " ON " to the CH455 panel on GPIO 128 / 129, and unpacks
the 8.1 MB MainCode to 0x80000200; the application probes its Rafael Micro
R836 tuner on SCB2 at I2C 0x3A, updates the panel to "Strt", and draws its
152-colour "Welcome" installation wizard through GeM36F / GMA layer 0
(amiko_t58_screen.png).  Pressing DOWN and RIGHT under necfirst moves the
highlight from Region to Language and steps the selected language
(amiko_t58_nav.png).

Usage: python run_dump_amiko_t58_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression

FEATURED = {
    "device": "Amiko T58 (firmware 1.0.60 FTA)",
    "chips": ["ALi M3821", "R836", "CH455"],
    "shows": ["boots to screen", "front panel", "tuner I2C", "remote navigation"],
}

screen_regression.run(
    dump="AMIKO T58/AMIKO_T58_1.0.60_fta.abs",
    expected="amiko_t58_screen.png",
    boot_limit_s=10 * 60,
    settle_s=5,
    min_ge_ops=15,
    panel_text="Strt",
    title="Amiko T58 (firmware 1.0.60 FTA)",
    retries=1,
    navigation=[("DOWN", 40000), ("RIGHT", 3000)],
)
