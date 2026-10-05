"""
Screen regression for dump.bin, the Comsat TE 1050 HD (slow, about 15
minutes): boots dump.bin into its application, which reads its flash channel
database word by word and byte by byte (about 10 minutes of wall time) before
it tunes its first channel and draws the channel banner ("Polsat Sport News",
channel 0008, Russian UI).  The screen is captured and compared with
dump_screen_golden.png with a tolerance for the banner's changing parts.

Usage: python run_dump_capture_screen.py [--make-golden]
"""
import screen_regression

screen_regression.run(
    dump="dump.bin",
    golden="dump_screen_golden.png",
    boot_limit_s=30 * 60,
    settle_s=90,
    min_ge_ops=15,
    max_diff_pct=2.0,
    title="Comsat TE 1050 HD (dump.bin)",
)
