"""
Screen regression for the Opticum XS65 Twin Polish retail update 1.4.0
(140_TWIN_RETAIL_PL.abs, slow): an 8 MB SPI update for the 256 MB ALi M3511 /
M3503 twin-tuner DVB-S2 receiver (chips/m3503.py, revision B variant 0x0001).
Its XIP bootloader copies itself to RAM, remaps 0x0F000000..0x0FFFFFFF to 256 MB
DDR3 via 0xB8000220 bit 24, copies SEECODE to 0xAE000200 and unpacks the 8.0 MB
maincode ("113003202102162") to 0x80000200.  With both USB power fault inputs
(GPIO 67 and 71) pulled up and its second DVB-S2 demodulator (external ALi S3501
at I2C 0x33 on bit-banged GPIO 6 / 7) answering its 0x350100C0 chip ID so GMA
layer 0 stays visible, the application drives its FD650K front panel on GPIO 135
/ 134 (" ON " -> " on " -> "LOC1" -> "LOC2") and draws its Polish first-install
wizard ("1 Wybierz język", compared with xs65_twin_screen.png); remote DOWN
switches the wizard to German ("Auswahl Sprache"), and the front panel's down
button (KI3/DIG4, held for 12 reads) steps twice through English back to Polish
(with "[EXIT] Wstecz" in the footer, compared with xs65_twin_nav.png).

Usage: python run_dump_xs65_twin_capture_screen.py [--make-expected]
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
import screen_regression
from tm1650_decoder import TM1650Decoder

FEATURED = {
    "device": "Opticum XS65 Twin (1.4.0 Retail PL)",
    "chips": ["ALi M3511 / M3503 (256 MB)", "S3501", "AV2011", "FD650K"],
    "shows": ["boots to screen", "second CPU (SEE)", "remote navigation", "panel keys"],
}

screen_regression.run(
    dump="OPTICUM XS65 TWIN/140_TWIN_RETAIL_PL.abs",
    expected="xs65_twin_screen.png",
    boot_limit_s=15 * 60,
    settle_s=20,
    min_ge_ops=250,
    panel_text="LOC2",
    title="Opticum XS65 Twin (1.4.0 Retail PL)",
    retries=2,
    navigation=[
        ("DOWN", 20000),
        (("panel", TM1650Decoder.key_code(3, 4, pressed=False), 12), 20000),
    ],
)
