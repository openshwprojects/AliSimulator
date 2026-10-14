"""
Screen regression for the Opticum HD S60 universal update 1.0.4.1 PVR (slow,
about 4 minutes): an M3601S satellite receiver (the M3602 family,
chips/m3602.py), single-CPU, whose board reads the chip ID 0x3603 (its
sidecar's device.chipId): under the family's own 0x3602 its application's
USB host attach gave its controller no base and the host's start ran into its
assertion.  As a C3603 it reads a product with the DVB-S2 demodulator, whose
S3501 answers at I2C 0x33; its bootloader reads the flash with the quad I/O
read 0xEB, and its application decodes its boot logo (video_m36.py) and,
with no signal, shows its "No Signal!" message, which is captured and
compared with s60_screen.png.  GPIO 25 is pulled up (the sidecar's
device.gpioPullUps): the USB power switch's fault flag -- while it read
low, a task of the application cut the port's power, showed "USB Short
circuit!!" for 3 s and tried again ~10 s later.  The remote's OK opens the
channel list "All Satellites" and DOWN moves its highlight to ZDF HD, and the
front panel's down button (KI3/DIG4) on to RTL Television (s60_nav.png): its
key task keeps a frame's first address byte as the key table code's high
byte -- the IR coding "necfirst", like the ESR-250's.

Usage: python run_dump_s60_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression
from tm1650_decoder import TM1650Decoder

FEATURED = {"device": "Opticum HD S60 (universal update 1.0.4.1)", "chips": ["ALi M3601S (C3603)", "S3501"],
            "shows": ["boots to screen", "remote navigation", "panel keys"]}

screen_regression.run(
    dump="OPTICUM S60/Software_UNI_S60_1.0.4.1_PVR_2012-08-28.abs",
    expected="s60_screen.png",
    boot_limit_s=20 * 60,
    settle_s=60,
    min_ge_ops=30,
    max_diff_pct=1.0,
    title="Opticum HD S60 (universal update 1.0.4.1)",
    retries=1,
    navigation=[("OK", 20000), ("DOWN", 2000), (("panel", TM1650Decoder.key_code(3, 4, pressed=False)), 2000)],
)
