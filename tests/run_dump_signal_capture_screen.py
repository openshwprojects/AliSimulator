"""
Screen regression for dump.bin, the Comsat TE 1050 HD, with a signal and a
transport stream (slow, about 15 minutes): boots dump.bin with
sim.set_signal(True) -- its MxL603 tuner model and the M3801's demodulator
reporting lock -- and sim.attach_mux(), the demultiplexer model fed with a
made-up multiplex (transport_stream.py).  The application tunes its channel,
filters the PAT, then the PMT PID of its channel, the CAT, SDT, NIT, EIT, TDT
and its video / audio PIDs, and the model answers every one: the PMT with
the programme number of the channel read from the dump's own channel
database ("TVP Opole", programme 0x11 on PID 0x6A5; "Polsat Sport News",
0x1A on 0x321).  So the channel banner shows the multiplex's EIT -- "Now:
02:00-03:00 TVP Opole now" where it used to say "Нет Информации" (no
information) -- which is what this test captures and compares with
dump_signal_screen.png.  The firmware still steps to its next channel every
20 s or so (it waits for the video or audio stream itself, which the
simulator has no source for yet), so the banner alternates between its two
channels: the comparison allows 3 % for the channel's name, number and
programme text.

Usage: python run_dump_signal_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

# this box's card at the top of the report (run_all_tests.py reads it from the source)
FEATURED = {"device": "Comsat TE 1050 HD", "chips": ["ALi M3801", "MxL603"],
            "shows": ["boots to screen", "shows the transport stream's EPG"]}

screen_regression.run(
    dump="dump.bin",
    expected="dump_signal_screen.png",
    boot_limit_s=45 * 60,
    settle_s=60,
    min_ge_ops=15,
    max_diff_pct=3.0,
    title="Comsat TE 1050 HD (dump.bin) with a signal and a transport stream",
    retries=2,
    signal=True,
    mux=True,
)
