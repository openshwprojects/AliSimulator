"""
Screen regression for the Cabletech URZ0086 (ALi M3606: the M3602 family with
the SEE co-processor, chips/m3602.py and chips/see.py; about 7 minutes):
boots "URZ0086_V1.2.1.abs" with the chip ID its board reads, 0x3603 (its
sidecar's device.chipId; the bootloader then reads the flash with the quad
I/O read 0xEB).  The application starts the SEE's program on the second core
(see.SeeCore), whose video drivers decode the boot logo -- the video engine
and the video output's field interrupts (video_m36.py) are wired onto the SEE
core and interrupt it, not the main CPU --, and the SEE's OSD driver draws
the first-install wizard in Polish ("Witaj": Region Poland, Język polski,
Tryb wyświetlania 576i, Tryb proporcji 4:3LB, Tak) through the GE within 230 M
instructions, which is compared with urz0086_screen.png; then the remote's
DOWN moves the highlight from Region to Język, compared with urz0086_nav.png.

Usage: python run_dump_urz0086_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

FEATURED = {"device": "Cabletech URZ0086 (firmware 1.2.1)", "chips": ["ALi M3606 (C3603)"],
            "shows": ["boots to screen", "second CPU (SEE)", "reacts to remote"]}

screen_regression.run(
    dump="URZ0086_V1.2.1.abs",
    expected="urz0086_screen.png",
    boot_limit_s=40 * 60,
    settle_s=45,
    min_ge_ops=18,            # the wizard is complete at 18 commands
    min_colours=16,
    title="Cabletech URZ0086 (firmware 1.2.1)",
    retries=2,                # (the intermittent Unicorn stop of the dual-core runs)
    navigation=[("DOWN", 1000)],
)
