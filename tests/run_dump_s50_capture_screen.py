"""
Screen regression for the Opticum HD S50 update 1.1.4.1 PVR1 (slow, about
1 minute): the displayless sister model of the Opticum HD S60 on the
single-CPU ALi M3601S satellite SoC (the M3602 family, chips/m3602.py), whose
board reads the chip ID 0x3603 (its sidecar's device.chipId), has its S3501
DVB-S2 demodulator on the I2C bus at 0x33 (device.demodModel) and pulls GPIO
25 up (device.gpioPullUps, the USB power switch's fault line).  The
bootloader reads the 2 MB flash with the quad I/O read 0xEB and starts the
application (Libcore 4.0.0@SDK4.0ba.4.0_20110115), which decodes its boot
logo (video_m36.py) and, with no signal, shows its "No Signal!" message,
captured and compared with s50_screen.png.  The remote's OK opens the channel
list "All Satellites" and DOWN moves the highlight to the next channel
(s50_nav.png), using the "necfirst" IR coding.

Usage: python run_dump_s50_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

FEATURED = {"device": "Opticum HD S50 (update 1.1.4.1 PVR1)", "chips": ["ALi M3601S (C3603)", "S3501"],
            "shows": ["boots to screen", "remote navigation"]}

screen_regression.run(
    dump="OPTICUM S50/Software_S50_1.1.4.1_PVR1_2012-09-26.abs",
    expected="s50_screen.png",
    boot_limit_s=20 * 60,
    settle_s=60,
    min_ge_ops=30,
    max_diff_pct=1.0,
    title="Opticum HD S50 (update 1.1.4.1 PVR1)",
    retries=1,
    navigation=[("OK", 20000), ("DOWN", 2000)],
)
