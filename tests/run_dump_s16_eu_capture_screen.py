"""
Screen regression for the Openbox S16 EU firmware Eu1129 (ALi S3606H / M3606C
dual-CPU DVB-S2 HD satellite receiver on a 4 MB SPI flash, chips/m3602.py with
device.chipId 0x3603, S3501 demodulator at 0x33 and AV2011 tuner at 0x63): the
bootloader parks the SEE boot stub at 0xA1E8F7C0, unpacks seecode ("M3606 SEE")
and maincode ("S3606H-1.0.0"), and starts the SEE program on the second core at
0xA6000200.  With an empty channel database the application writes " on " ->
"noCH" to its TM1650-compatible front panel on GPIO 62 / 63 and opens the
16-bpp ARGB1555 "Edit Channel" main menu OSD (14 GE commands, 1,832 colours),
captured and compared with s16_eu_screen.png.  Pressing DOWN on its 0x80xx
European remote table ("necfirst" coding) steps to the "Installation" page,
compared with s16_eu_nav.png.

Usage: python run_dump_s16_eu_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

FEATURED = {"device": "Openbox S16 EU (ALi 3606C, Eu1129)",
            "chips": ["ALi S3606H (C3603)", "S3501", "AV2011", "TM1650-compatible"],
            "shows": ["boots to screen", "SEE second core", "front panel", "remote navigation"]}

screen_regression.run(
    dump="OPENBOX S16/OPENBOX-S16_Eu1129.abs",
    expected="s16_eu_screen.png",
    boot_limit_s=10 * 60,
    settle_s=0,
    probe_s=0,
    slice_instructions=1_000_000,
    min_ge_ops=14,
    min_colours=500,
    panel_text="noCH",
    max_diff_pct=0.0,
    title="Openbox S16 EU (ALi S3606H / M3606C, Eu1129)",
    retries=1,
    navigation=[("DOWN", 15000)],
)
