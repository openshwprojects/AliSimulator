"""
Screen regression for the Openbox S16 HD PVR firmware v2.8 CHN (slow, about 1
minute): an ALi M3601S single-CPU DVB-S2 satellite receiver (the M3602
family, chips/m3602.py), whose board reads the chip ID 0x3603 (its sidecar's
device.chipId) and has its S3501 DVB-S2 demodulator on the I2C bus at 0x33
(device.demodModel).  Its bootloader reads the 4 MB flash with the quad I/O
read 0xEB and starts the application (Application 1.0.0@SDK4.0ba.7.1_SAB_S2),
which decodes its boot logo (video_m36.py), drives its TM1650-compatible front
panel on GPIO 62 / 63 (" on ", "Strt", "OOO1"), and shows the channel banner
of its first channel ("1 $无线新闻台(新天11号)", 12 GE commands, 935 colours),
captured and compared with s16_screen.png.  Then the remote's OK opens the
"All Satellite" channel list (ir_remote's "necfirst" coding, table 0x01xx),
compared with s16_nav.png.

Usage: python run_dump_s16_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

FEATURED = {"device": "Openbox S16 HD PVR (firmware v2.8)", "chips": ["ALi M3601S (C3603)", "S3501", "TM1650-compatible"],
            "shows": ["boots to screen", "front panel", "remote navigation"]}

screen_regression.run(
    dump="OPENBOX S16/S16_CHN_2.8.abs",
    expected="s16_screen.png",
    boot_limit_s=20 * 60,
    settle_s=0,
    probe_s=0,
    slice_instructions=500_000,
    min_ge_ops=12,
    min_colours=100,
    panel_text="OOO1",
    max_diff_pct=1.0,
    title="Openbox S16 HD PVR (firmware v2.8)",
    retries=1,
    navigation=[("OK", 20000)],
)
