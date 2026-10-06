"""
Screen regression for the Cabletech URZ0083Q dump (slow, about 20 minutes):
boots "CABLETECH URZ0083Q/Cabletech URZ0083Q/EN25Q32B.bin" into its
application, which first scans its flash channel database backwards a few
bytes at a time (about 90k timer ticks, 12-17 minutes of wall time), then
draws its first-install wizard ("Witaj": region, language, video mode, aspect
ratio).  The screen is captured and compared with
cabletech_urz0083q_screen_golden.png (with a small tolerance: the wizard keeps
redrawing a little), and the TM1628-class front panel must read "noCH" (no
channels) by then, after " ON " and "----".  Then the front panel's keys drive
the wizard (this firmware ignores the IR codes of its key table as the
simulator rebuilds them): KS9/K1 = down moves the highlight from Region to
Język and on to Tryb Wyświetlania, KS9/K2 = up moves it back; the last screen
is compared with cabletech_urz0083q_nav_golden.png.

Usage: python run_dump_cabletech_capture_screen.py [--make-golden]
"""
import screen_regression
from tm1628_decoder import TM1628Decoder

DOWN, UP = TM1628Decoder.key_code(9, 1), TM1628Decoder.key_code(9, 2)

screen_regression.run(
    dump="CABLETECH URZ0083Q/Cabletech URZ0083Q/EN25Q32B.bin",
    golden="cabletech_urz0083q_screen_golden.png",
    boot_limit_s=60 * 60,
    settle_s=90,
    min_ge_ops=60,
    max_diff_pct=1.0,
    panel_text="noCH",
    title="Cabletech URZ0083Q",
    navigation=[(("panel", DOWN), 20000), (("panel", DOWN), 20000), (("panel", UP), 20000)],
)
