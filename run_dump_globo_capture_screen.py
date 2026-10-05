"""
Screen regression for the Globo STB HD N3 dump (slow, about 6 minutes): boots
"Ali_3801_Globo_DVBT_dump SPI 4mb.bin" through its LZMA bootloader into the
application, waits for the OSD (the live-TV "Brak sygnału" / no-signal banner,
some 900 GE commands in), captures the display layer and compares it with
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
    min_ge_ops=300,
    title="Globo STB HD N3",
)
