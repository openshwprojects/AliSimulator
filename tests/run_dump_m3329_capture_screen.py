"""
Screen regression for the M3329 dump (dumps/other/sat_main_ali3329-s15125_
dump_eeprom_by_h2h_ok.bin, a 2005 satellite receiver, slow: about 2
minutes).  The M3327 platform's chip (chips/m3329.py) boots its application
from the parallel NOR flash (parallel_flash.py: the driver identifies an
MX29LV400B through the autoselect command, whose reset it stores in a branch
delay slot), opens its channel database -- a byte-by-byte search through
120 KB of flash that takes the application ~250 M instructions -- and shows
the channel banner of its last channel, "37" with its Arabic name, drawn by
the CPU into an OSD region (OSD_M3327C: gma_capture.m3327_regions, the
palette written through a port); compared with m3329_screen.png, its front
panel (a TM1650-compatible chip on GPIO 15 / 16) showing the channel number.
The panel's MENU button (KI4/DIG4, held for a dozen of the driver's polls)
opens the "Channel" menu and the remote's DOWN moves its highlight to Radio
Channel (m3329_nav.png): the remote's codes come from the application's own
key table (chips/m3329.M3329.remote_frame).

Usage: python run_dump_m3329_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression
from tm1650_decoder import TM1650Decoder

FEATURED = {"device": "satellite receiver board s15125 (2005)", "chips": ["ALi M3329", "TM1650-compatible panel"],
            "shows": ["boots to screen", "front panel", "panel keys", "remote navigation"]}

screen_regression.run(
    dump="other/sat_main_ali3329-s15125_dump_eeprom_by_h2h_ok.bin",
    expected="m3329_screen.png",
    boot_limit_s=10 * 60,
    settle_s=10,
    min_ge_ops=0,
    ge=False,                 # (its CPU draws the OSD: no graphics engine)
    panel_text="OO37",        # (channel 37; the decoder reads the 7-segment 0 as O)
    title="ALi M3329 board s15125 (2005)",
    retries=1,
    navigation=[(("panel", TM1650Decoder.key_code(4, 4, pressed=False), 12), 20000), ("DOWN", 2000)],
)
