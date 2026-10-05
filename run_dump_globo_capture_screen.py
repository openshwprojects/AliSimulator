"""
Screen regression for the Globo STB HD N3 dump (slow, about 6 minutes): boots
"Ali_3801_Globo_DVBT_dump SPI 4mb.bin" through its LZMA bootloader into the
application, waits for the OSD: the application first shows its channel banner ("41. WP",
clock and date, about 600 GE commands) and clears it again when the banner
times out, then draws the live-TV "Brak sygnału" (no signal) message at about
900 commands, five minutes after it started; that stable screen is captured and
compared with
globo_screen_golden.png.  The TM1650 front panel is decoded alongside
(" ON " while booting, then the application's text).

Usage: python run_dump_globo_capture_screen.py [--make-golden]
"""
import screen_regression

screen_regression.run(
    dump="Ali_3801_Globo_DVBT_dump SPI 4mb.bin",
    golden="globo_screen_golden.png",
    boot_limit_s=15 * 60,
    settle_s=60,
    min_ge_ops=900,       # after the channel banner (~600 commands) has timed out
    title="Globo STB HD N3",
)
