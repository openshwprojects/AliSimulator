"""
Screen regression for the Ferguson Ariva T650i update image with a signal on
one channel (slow, about 13 minutes): boots "FERGUSON ARIVA T650i/
T650i_V1.13B4_20160721.abs" -- an 8 MB manufacturer update (bootloader, OTA
loader, maincode, empty channel database), the first image of an 8 MB flash
part here -- through its LZMA bootloader into the application (Libcore 8.1c,
dump.bin's library), with sim.set_signal(True, frequencies=[578 MHz]) -- its
MxL603 tuner model, and the M3801's demodulator reporting lock only while the
tuner is on UHF channel 34 -- and the transport stream behind it
(sim.attach_mux: one service, "AliSimulator TV").  With no channels the
application runs the first-install automatic search ("Przeszukiwanie auto",
Ferguson's black / orange skin, Polish UI) from 578 to 858 MHz: 578 MHz
"... ok" -- it reads the multiplex's PAT, SDT, NIT and the service's PMT --,
every other channel "... Brak" (none).  Its last screen, 98 % with 858 MHz
being searched, "telewizja 1" and "AliSimulator TV" in the list of found
services (some 2558 GE commands in), is compared with t650i_screen.png; the
FD650K front panel (TM1650-compatible, the board's own digit order and
segment wiring) reads "Find" then, after " On " and "Strt".  Then the box
stores the channel and tunes it (the panel shows "1"), asks whether to
download the programme guide ("Kontynuować?", yes after 8 s) and gives up at
0 % after some 100 s -- the multiplex has no EIT schedule, only present /
following --, ending on its live picture; the IR remote's OK (the
extended-NEC coding of the Strong firmwares, see ir_remote.IR_CODINGS) then
opens its channel list ("wszystkie tv": "1 AliSimulator TV", the
multiplex's present / following events "12:00 AliSimulator TV now" and
"13:00 ... next" beside it, "578000/2K/QPSK" below -- the demodulator model
reports no transmission parameters), compared with t650i_nav.png.
(Without a signal the same search ends on "nie znaleziono kanału!", no
channel found.)  The application also resets its Ethernet MAC and probes for
a PHY over MDIO at start (see simulator.py: _hook_mac_reset_read /
_hook_mac_mdio_read).

Usage: python run_dump_t650i_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

# this box's card at the top of the report (run_all_tests.py reads it from the source)
FEATURED = {"device": "Ferguson Ariva T650i", "chips": ["ALi M3801", "FD650K", "MxL603"],
            "shows": ["boots to screen", "finds a channel in its scan", "reacts to remote"]}

screen_regression.run(
    dump="FERGUSON ARIVA T650i/T650i_V1.13B4_20160721.abs",
    expected="t650i_screen.png",
    boot_limit_s=75 * 60,     # ~13 min with another test beside it (the unpack takes seconds, then the search)
    settle_s=5,               # the last search screen is up some 20 s; its redraw is done within 5
    min_ge_ops=2550,          # ... at 2558 GE commands (73 per searched channel)
    min_colours=150,
    max_diff_pct=1.0,
    panel_text="Find",
    title="Ferguson Ariva T650i with a signal on 578 MHz",
    retries=2,                # its start (flash erase / program in the upper 4 MB) hits the
                              # sporadic jump-to-0 race more often than the other dumps
    slice_instructions=500_000,
    probe_s=0,
    navigation=[(("wait", 240), 100000),     # the guide download comes, gives up, live picture
                ("OK", 100000)],             # the channel list
    signal=True,
    signal_frequencies=[578_000_000],
    mux=True,
)
