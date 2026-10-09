"""
Screen regression for the Opticum Blue R265 Lite (ALi M3822P, the DVB-T2
generation, chips/m3821.py; about 10 minutes): boots the official firmware
image "Opticum Blue R265 Lite/T2GEN265_1.1.5-2022-08-01.abs" through its
bootloader's two stages and the LZMA decompression into the application
(ALi SDK 4.0, Libcore 19.9), which draws its home menu through the same GE
(0xB800A000) and display layer (0xB8006300) as the M3801 boxes: six tiles
in Polish -- "Edycja kanałów" (highlighted), "Skan kanałów", "Media player",
"Ustawienia systemu", "Dysk USB" -- and the "Wciśnij klawisz INFO" hint bar,
complete at 364 GE commands, at the OSD's own 1280x720.  The menu appears
once the application's start-up has run its large copies through the
8-channel DMA rings at 0xB800F000 and filled the sound engine's PCM ring
(0xB8002000: its read index must follow the write index), both modelled in
chips/m3821.py.  That screen is compared with r265lite_screen.png; the HD2015
front panel (a TM1650 on GPIO 57 / 58, no display soldered on the box) must
still show stage 2's " ON ".  Then the IR remote (press_key, the application's
own key table) moves the highlight down to "Ustawienia systemu" with DOWN and
opens that tile's description with INFO; the result is compared with
r265lite_nav.png.  (The menu refuses a move onto a greyed-out tile: "Media
player" and "Dysk USB" are disabled without a USB device, so RIGHT then DOWN
is ignored.)

Usage: python run_dump_r265lite_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import screen_regression

screen_regression.run(
    dump="Opticum Blue R265 Lite/T2GEN265_1.1.5-2022-08-01.abs",
    expected="r265lite_screen.png",
    boot_limit_s=25 * 60,     # the menu is up after ~5 min alone
    settle_s=60,
    min_ge_ops=360,           # the home menu is complete at 364 commands
    min_colours=16,
    panel_text=" ON ",
    title="Opticum Blue R265 Lite",
    navigation=[("DOWN", 1000), ("INFO", 1000)],
)
