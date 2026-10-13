"""
Screen regression for the Ferguson Ariva T50 firmware V1.02B214 (slow, about
8 minutes): an M3602 DVB-T receiver (chips/m3602.py) whose OSD is drawn by
the M3602's own graphics engine at 0xB800C000 (ge_m3602.py) -- its OSD
driver keeps a 912 x 640 CLUT8 screen and has the engine scale it through
its palette into the AYCbCr8888 layer of the PAL output, 513 x 512 at
(103, 32), which the capture scales back up (gma_capture.m3602_layers).
Its UI waits until its boot logo is shown: the decoder reports the first
picture shown once the HD and the SD output (video_m36.py: the DEO's field
interrupt, its field at bit 19) have both asked for the frame.  Its first
screen is the "Welcome" installation wizard, compared with t50_screen.png;
DOWN moves the highlight from Region to Language, compared with t50_nav.png
(its remote's key table holds the command half only, and its control task
keeps a key only with its remote's address, extended NEC 0x01 / 0xFC:
ir_remote's "cmd").

Usage: python run_dump_t50_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

FEATURED = {"device": "Ferguson Ariva T50 (firmware V1.02B214)", "chips": ["ALi M3602", "ALi M3101"],
            "shows": ["boots to screen", "remote navigation"]}

screen_regression.run(
    dump="FERGUSON ARIVA T50/ArivaT50_20111118_V102B214.abs",
    expected="t50_screen.png",
    boot_limit_s=25 * 60,
    settle_s=30,
    min_ge_ops=85,            # the wizard is complete at 91 commands (67 set up and clear the OSD)
    title="Ferguson Ariva T50 (firmware V1.02B214)",
    retries=1,
    navigation=[("DOWN", 2000)],
)
