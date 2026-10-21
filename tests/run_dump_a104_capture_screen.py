"""
Screen regression for the Ferguson Ariva 104 official firmware V1.3B1 (slow,
about 2 minutes): an ALi C3505 H.265/HEVC DVB-S2 satellite receiver
(chips/c3505.py) whose SEE program ("M3505 SEE") runs on the second core
(chips/see.py) and whose internal S3505 DVB-S2 demodulator answers at
0xB8028000 (C3505.nim).  Its OSD is the newer display engine's ARGB8888
1280 x 720 layer at 0xB8006900 (gma_capture.de_layers).  With an empty channel
database the application opens its "System Setup" menu while the FD650K front
panel on GPIO 107 / 110 shows "nenu" ("menu"), captured and compared with
a104_screen.png.  Then the remote's DOWN and RIGHT (the extended-NEC coding
"ext00") navigate the menu, compared with a104_nav.png.

Usage: python run_dump_a104_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

FEATURED = {"device": "Ferguson Ariva 104 (firmware V1.3B1)", "chips": ["ALi C3505", "FD650K"],
            "shows": ["boots to screen", "second CPU (SEE)", "front panel", "remote navigation"]}

screen_regression.run(
    dump="FERGUSON ARIVA 104/Ferguson_A104_V1.3B1_30072020.abs",
    expected="a104_screen.png",
    boot_limit_s=25 * 60,
    settle_s=20,
    min_ge_ops=20,
    min_colours=60,
    panel_text="nenu",
    max_diff_pct=1.0,
    title="Ferguson Ariva 104 (firmware V1.3B1)",
    retries=2,
    navigation=[("DOWN", 2000), ("RIGHT", 2000)],
)
