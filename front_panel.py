"""
Front panels of the firmware dumps: which LED-driver chip sits on which
bit-banged GPIO pins, and what its key-matrix positions do (found by pressing
them in the simulator).  tv_gui.py and the run scripts get a dump's panel
decoder from make_panel(); the decoders (tm1650_decoder.py, tm1628_decoder.py)
follow the firmware's GPIO writes and answer its key reads.

  * TM1650 (I2C: SCL, SDA): Opticum STB HD N2 (dump_maciej.bin) and Globo STB
    HD N3 -- SCL = GPIO 31, SDA = GPIO 9; the panel driver reacts to the key
    matrix positions KI1/DIG4 (up) and KI2/DIG4 (down).
  * TM1628-class (3-wire: CLK, DIO, STB): Cabletech URZ0083Q (PCB
    6390-M3801) and the Strong SRT 8115 (MC6422-M3801) -- CLK = GPIO 31, DIO =
    GPIO 9, STB = GPIO 11; the Cabletech's digits in RAM
    0, 2, 4, 6 with its own segment wiring (" ON " at boot, "noCH" without
    channels); its panel driver reacts to KS9/K1 (down), KS9/K2 (up) and
    KS10/K1 (power -> standby, "oFF ").  The Cabletech URZ0195 has a
    uPD16312-class chip on the same bus with STB = GPIO 14.

A dump that matches no entry gets the TM1650 on GPIO 31 / 9 (a board without
one shows a blank display and ignores the keys).
"""
import os

from tm1628_decoder import TM1628Decoder
from tm1650_decoder import TM1650Decoder

# (substring of the dump's path, case-insensitive) -> panel spec
PANELS = [
    ("dump_maciej", dict(chip="tm1650", scl=31, sda=9, labels={(1, 4): "▲", (2, 4): "▼"})),
    ("Globo", dict(chip="tm1650", scl=31, sda=9, labels={(1, 4): "▲", (2, 4): "▼"})),
    # keys found on its first-install wizard: KS9/K1 = down, KS9/K2 = up, KS10/K1 = power
    # (standby: the panel shows "oFF "); the other 17 positions do nothing there
    ("URZ0083Q", dict(chip="tm1628", clk=31, dio=9, stb=11, digit_addrs=(0, 2, 4, 6),
                      seg_map=(4, 2, 0, 6, 7, 3, 1, 5),
                      labels={(9, 1): "▼", (9, 2): "▲", (10, 1): "PWR"})),
    # its bootloader prints "stb: 14 clock: 31 data: 9 / nec 16312 attach ok / digit: 4 seg: 16":
    # a uPD16312 / PT6312-class driver, the same 3-wire command set (digit layout not mapped yet)
    ("URZ0195", dict(chip="tm1628", clk=31, dio=9, stb=14, digit_addrs=(0, 2, 4, 6), labels={})),
    # Cabletech URZ0194S: the URZ0083Q's bootloader build, remote (same wake code) and panel bus,
    # but its digits use the standard segment layout (" ON ", "----", "noCH" come out as is) and
    # its keys differ (found on its wizard): KS7/K1 = left and KS9/K1 = right step the highlighted
    # value, KS8/K1 = menu (its main menu opens), KS8/K2 = down, KS9/K2 = power (standby "oFF ")
    ("urz0194", dict(chip="tm1628", clk=31, dio=9, stb=11, digit_addrs=(0, 2, 4, 6),
                     labels={(7, 1): "◀", (9, 1): "▶", (8, 1): "MENU", (8, 2): "▼", (9, 2): "PWR"})),
    # Strong SRT 8115 (MC6422-M3801): the same 3-wire bus and pins as the Cabletech URZ0083Q
    # (GPIO 31 clocks, 9 carries the data, 11 strobes); digit layout and keys not mapped yet
    ("srt8115", dict(chip="tm1628", clk=31, dio=9, stb=11, digit_addrs=(0, 2, 4, 6), labels={})),
]
DEFAULT = dict(chip="tm1650", scl=31, sda=9, labels={})


def panel_spec(dump):
    """The panel spec of a dump (file name or path)."""
    name = os.path.normpath(dump).lower()
    for pattern, spec in PANELS:
        if pattern.lower() in name:
            return spec
    return DEFAULT


def make_panel(dump, log_handler=None):
    """(decoder, keys, description) for a dump's front panel: the decoder to
    attach with sim.setGpioHandler(decoder.on_gpio_write), its key matrix as
    [(label, code)] for decoder.press_key(code), and a one-line description."""
    spec = panel_spec(dump)
    labels = spec.get("labels", {})
    if spec["chip"] == "tm1628":
        dec = TM1628Decoder(clk_gpio=spec["clk"], dio_gpio=spec["dio"], stb_gpio=spec["stb"],
                            digit_addrs=spec.get("digit_addrs", (0, 2, 4, 6)),
                            seg_map=spec.get("seg_map", TM1628Decoder.STANDARD_SEG_MAP),
                            log_handler=log_handler)
        keys = [(labels.get((ks, k), f"{ks}-{k}"), TM1628Decoder.key_code(ks, k))
                for ks in range(1, 11) for k in (1, 2)]
        desc = f"TM1628 on CLK {spec['clk']} / DIO {spec['dio']} / STB {spec['stb']}, keys KS1-10 × K1-2"
    else:
        dec = TM1650Decoder(scl_gpio=spec["scl"], sda_gpio=spec["sda"], log_handler=log_handler)
        keys = [(labels.get((ki, dig), f"{ki}-{dig}"), TM1650Decoder.key_code(ki, dig, pressed=False))
                for ki in range(1, 8) for dig in range(1, 5)]
        desc = f"TM1650 on SCL {spec['scl']} / SDA {spec['sda']}, keys KI1-7 × DIG1-4"
    return dec, keys, desc
