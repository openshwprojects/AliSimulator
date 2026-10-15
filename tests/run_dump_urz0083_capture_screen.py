"""
Screen regression for the Cabletech URZ0083 (ALi M3601E, the M3602 family,
chips/m3602.py; about 2 minutes): boots "URZ0083_v1.1.2.abs" with the chip ID
its board reads, 0x3603 (its sidecar's device.chipId; the bootloader then
reads the flash with the quad I/O read 0xEB), into its application, which
first decodes its boot logo from the flash: the MPEG decoder programs the
video engine, which finishes each picture at once, and waits until the video
output's field interrupts have had the first picture shown (video_m36.py).
Some 85 M instructions in -- after a byte-by-byte scan of a flash area -- it
draws its first-install wizard in Polish ("Welcome": Region Poland, Język
polski, Typ 1080i_25, Wymiary 4:3LB, Tak), which is compared with
urz0083_screen.png; then the remote's DOWN moves the highlight from Region to
Język, compared with urz0083_nav.png.

Usage: python run_dump_urz0083_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

FEATURED = {"device": "Cabletech URZ0083 (firmware 1.1.2)", "chips": ["ALi M3601E (C3603)"],
            "shows": ["boots to screen", "reacts to remote"]}

screen_regression.run(
    dump="URZ0083_v1.1.2.abs",
    expected="urz0083_screen.png",
    boot_limit_s=30 * 60,
    settle_s=45,
    min_ge_ops=17,            # the wizard is complete at 17 commands
    min_colours=16,
    title="Cabletech URZ0083 (firmware 1.1.2)",
    navigation=[("DOWN", 1000)],
)
