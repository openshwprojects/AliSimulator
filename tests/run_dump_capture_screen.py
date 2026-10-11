"""
Screen regression for dump.bin, the Comsat TE 1050 HD (slow, about 7
minutes): boots dump.bin into its application, which reads its flash channel
database word by word and byte by byte before it tunes its first channel and
draws the channel banner (Russian UI) and, once that has timed out, the
"Нет Сигнала!" (no signal) box; that screen is captured and compared with
dump_screen.png.  Then the IR remote (the extended-NEC coding of its
library, see ir_remote.IR_CODINGS) opens the channel list with OK ("All
TV": Polsat, TVN, TV4 ... TVP3 Opole highlighted), closes it with EXIT,
opens the main menu with MENU ("Редактировать Канал": the TV and radio
channel lists, delete all) and closes it again; the no-signal screen after
that is compared with dump_nav.png.  Its two front-panel buttons, straight
on GPIO 31 and 9 (the SDK's key task sends them on as its virtual keys
12 / 13, up / down), are modelled released (front_panel.py: gpio_keys.py);
read as pressed, the simulator's default for an input nothing drives, they
made it hop between its two channels every 20-50 s, and the remote's keys
got lost.

Usage: python run_dump_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

# (the box's featured run is run_dump_signal_capture_screen.py: the same boot with a signal and a transport stream)

screen_regression.run(
    dump="dump.bin",
    expected="dump_screen.png",
    boot_limit_s=45 * 60,
    settle_s=90,          # the banner times out, then the no-signal box is drawn
    min_ge_ops=15,
    max_diff_pct=1.0,
    title="Comsat TE 1050 HD (dump.bin)",
    # the channel list changes some 238,000 pixels, the main menu 481,000
    navigation=[("OK", 100000), ("EXIT", 100000), ("MENU", 200000), ("EXIT", 200000)],
    nav_diff_pct=1.0,
    nav_settle_s=300,     # back on live TV the no-signal box is redrawn
)
