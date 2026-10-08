"""
Screen regression for the Ferguson Ariva T650i update image (slow, about 25
minutes): boots "FERGUSON ARIVA T650i/T650i_V1.13B4_20160721.abs" -- an 8 MB
manufacturer update (bootloader, OTA loader, maincode, empty channel
database), the first image of an 8 MB flash part here -- through its LZMA
bootloader into the application (Libcore 8.1c, dump.bin's library).  With no
channels the application runs the first-install automatic search
("Przeszukiwanie auto", Ferguson's black / orange skin, Polish UI) and ends,
some 217 GE commands in, on the "nie znaleziono kanału!" (no channel found)
dialog at 100 %; that screen is compared with t650i_screen.png and the
FD650K front panel (TM1650-compatible, the board's own digit order and
segment wiring) must read "Find" by then, after " On " and "Strt".  Then the
IR remote (the extended-NEC coding of the Strong firmwares, see
ir_remote.IR_CODINGS) closes the dialog with OK -- with no channels the
firmware then opens its "edytuj kanały" (edit channels) menu by itself --,
highlights "ulubione" (favourites, the only entry enabled without channels)
with DOWN and opens it with OK; the favourites list (Ulubiony 1-8) is
compared with t650i_nav.png.
The application also resets its Ethernet MAC and probes for a PHY over MDIO
at start (see simulator.py: _hook_mac_reset_read / _hook_mac_mdio_read).

Usage: python run_dump_t650i_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

screen_regression.run(
    dump="FERGUSON ARIVA T650i/T650i_V1.13B4_20160721.abs",
    expected="t650i_screen.png",
    boot_limit_s=75 * 60,     # ~18 min alone (a 4-6 min unpack, then the search)
    settle_s=90,
    min_ge_ops=216,           # the search ends on the dialog at 217 commands
    max_diff_pct=1.0,
    panel_text="Find",
    title="Ferguson Ariva T650i",
    retries=2,                # its start (flash erase / program in the upper 4 MB) hits the
                              # sporadic jump-to-0 race more often than the other dumps
    navigation=[("OK", 100000), ("DOWN", 2000), ("OK", 50000)],
)
