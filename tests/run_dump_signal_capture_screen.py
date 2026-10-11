"""
Screen regression for dump.bin, the Comsat TE 1050 HD, with a signal and a
transport stream (slow, about 15 minutes): boots dump.bin with
sim.set_signal(True) -- its MxL603 tuner model and the M3801's demodulator
reporting lock -- and sim.attach_mux(), the demultiplexer model fed with a
made-up multiplex (transport_stream.py).  The application tunes its channel,
filters the TDT, the PAT, then the PMT PID of its channel, the CAT, SDT,
NIT, its video / audio PIDs and the EIT, and the model answers every one:
the PMT with the programme number of the channel read from the dump's own
channel database ("TVP Opole", programme 0x11 on PID 0x6A5; "Polsat Sport
News", 0x1A on 0x321).  The TDT's time, 10/10 12:00 UTC, goes into the
chip's real-time clock (rtc_m36.py), whose time plus its time zone (+1 h)
the UI shows: the channel banner reads "10/10 13:00" and carries the
multiplex's EIT -- "Next: 14:00-15:00 TVP Opole next" under "TVP3 Opole" /
0009, above it "Now: 13:00-14:00 TVP Opole now" or, when the banner comes
before the present event's section, "Нет Информации" (no information; some
3,100 pixels, within the tolerance) -- and this test captures it as soon as
it is on the screen (after its 14th GE command, some 950 colours; the boot
runs in 0.5 M instruction slices for that) and compares it with
dump_signal_screen.png.
The banner times out some 14 M instructions later and the channel stays: a
clear black picture, the video and audio streams having no source yet.
Then the remote's EPG key opens the programme guide on that channel at
"13:00 10/10", its time line holding the two events ("TVP Opole now" from
13:00, "TVP Opole next" from 14:00), compared with dump_signal_nav.png.
(Before the RTC was modelled it read 0, month 0 and day 0, which the
firmware's date arithmetic made 28/11: the guide's time line started at
"01:00 28/11", without an event; before its front-panel buttons were
modelled released, gpio_keys.py, the firmware stepped between its two
channels every 20 s or so, the banner kept coming back and the remote's
keys got lost.)

Usage: python run_dump_signal_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

# this box's card at the top of the report (run_all_tests.py reads it from the source)
FEATURED = {"device": "Comsat TE 1050 HD", "chips": ["ALi M3801", "MxL603"],
            "shows": ["boots to screen", "shows the transport stream's EPG", "reacts to remote"]}

screen_regression.run(
    dump="dump.bin",
    expected="dump_signal_screen.png",
    boot_limit_s=45 * 60,
    settle_s=0,           # the banner is up for a few seconds: the screen of the slice that shows it
    min_ge_ops=14,        # the banner is drawn at 14 commands ...
    min_colours=900,      # ... and its EIT lines ("Now: ...", "Next: ...") and EPG icon follow: some 950 colours, 840 without
    max_diff_pct=1.0,
    slice_instructions=500_000,
    probe_s=0,
    navigation=[("EPG", 200000)],     # the programme guide (some 450,000 pixels)
    nav_diff_pct=1.0,
    nav_settle_s=60,
    title="Comsat TE 1050 HD (dump.bin) with a signal and a transport stream",
    retries=2,
    signal=True,
    mux=True,
)
