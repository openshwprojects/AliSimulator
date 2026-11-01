"""
Screen regression for the Opticum XS65 Combo Polish retail update 1.4.0
(140_M3515-COMBO-RETAIL-PL.abs, slow): an 8 MB SPI update for the 256 MB ALi
M3515 DVB-S2 + DVB-T2/C combo receiver (chips/m3503.py, revision B variant
0x0001).  Its XIP bootloader copies itself to RAM, remaps 0x0F000000..0x0FFFFFFF
to 256 MB DDR3 via 0xB8000220 bit 24, copies SEECODE to 0xAE000200 and unpacks
the 7.8 MB maincode ("114003202102162") to 0x80000200.  With both USB power
fault inputs (GPIO 67 and 71) pulled up, the application drives its FD650K
front panel on GPIO 135 / 134 (" ON " -> "LOC1") and draws its Polish
first-install wizard ("1 Wybierz język", compared with xs65_combo_screen.png);
remote DOWN switches the wizard to German ("Auswahl Sprache"), and the front
panel's down button (KI3/DIG4) switches it to English ("Select language",
compared with xs65_combo_nav.png).

Usage: python run_dump_xs65_combo_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression
from tm1650_decoder import TM1650Decoder

FEATURED = {
    "device": "Opticum XS65 Combo (1.4.0 Retail PL)",
    "chips": ["ALi M3515 / M3503 (256 MB)", "FD650K", "AV2011"],
    "shows": ["boots to screen", "remote navigation", "panel keys"],
}

screen_regression.run(
    dump="OPTICUM XS65 COMBO/140_M3515-COMBO-RETAIL-PL.abs",
    expected="xs65_combo_screen.png",
    boot_limit_s=15 * 60,
    settle_s=20,
    min_ge_ops=250,
    panel_text="LOC1",
    title="Opticum XS65 Combo (1.4.0 Retail PL)",
    retries=2,
    navigation=[
        ("DOWN", 20000),
        (("panel", TM1650Decoder.key_code(3, 4, pressed=False), 12), 20000),
    ],
)
