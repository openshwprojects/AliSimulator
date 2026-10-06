"""
Screen regression for the Strong SRT 8115 dump (slow, about 15 minutes): boots
srt8115.BIN (main board MC6422-M3801) into its application, which scans its
flash channel database for some 8 minutes before it draws its first screen at
about 12 minutes: its live-TV "Brak sygnału" (no signal) icon and text, some 40
GE commands, then a slow trickle of redraws.  The
screen is captured and compared with srt8115_screen_golden.png with a small
tolerance; the TM1628-class front panel on the Cabletech's pins is decoded
alongside (its digit wiring is not mapped yet).

Usage: python run_dump_srt8115_capture_screen.py [--make-golden]
"""
import screen_regression

screen_regression.run(
    dump="srt8115.BIN",
    golden="srt8115_screen_golden.png",
    boot_limit_s=30 * 60,
    settle_s=90,
    min_ge_ops=35,
    max_diff_pct=1.0,
    title="Strong SRT 8115",
)
