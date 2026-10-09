"""
Front panels of the firmware dumps: which LED-driver chip sits on which
bit-banged GPIO pins, and what its key-matrix positions do (found by pressing
them in the simulator).  tv_gui.py and the run scripts get a dump's panel
decoder from make_panel(); the decoders (tm1650_decoder.py, tm1628_decoder.py)
follow the firmware's GPIO writes and answer its key reads.

  * TM1650 (I2C: SCL, SDA): Opticum STB HD N2 (dump_maciej.bin) and Globo STB
    HD N3 -- SCL = GPIO 31, SDA = GPIO 9; the panel driver reacts to the key
    matrix positions KI1/DIG4 (up) and KI2/DIG4 (down).  The Ferguson Ariva
    T650i's FD650K is TM1650-compatible on the same pins, with its own digit
    order and segment wiring.  The Opticum Blue R265 Lite (M3822P, the M3821
    family) has an HD2015 -- TM1650-compatible too -- on SCL = GPIO 57, SDA =
    GPIO 58 (bank 0xB80000D4 bits 25 / 26); its firmware writes " ON " at boot.
  * TM1628-class (3-wire: CLK, DIO, STB): Cabletech URZ0083Q (PCB
    6390-M3801) and the Strong SRT 8115 (MC6422-M3801) -- CLK = GPIO 31, DIO =
    GPIO 9, STB = GPIO 11; the Cabletech's digits in RAM
    0, 2, 4, 6 with its own segment wiring (" ON " at boot, "noCH" without
    channels); its panel driver reacts to KS9/K1 (down), KS9/K2 (up) and
    KS10/K1 (power -> standby, "oFF ").  The Cabletech URZ0195 has a
    uPD16312-class chip on the same bus with STB = GPIO 14, its digits in
    grids 4, 2, 3, 1 with their own segment wiring (" ON ", "----", then the
    channel number "0004"); its keys are not driven by the decoder yet.

A dump that matches no entry gets the TM1650 on GPIO 31 / 9 (a board without
one shows a blank display and ignores the keys).
"""
import os

from tm1628_decoder import TM1628Decoder
from tm1650_decoder import TM1650Decoder

# Opticum Blue R265 Lite (M3822P): an HD2015 -- TM1650-compatible -- on GPIO bank 1 (0xB80000D4),
# SCL = GPIO 57, SDA = GPIO 58; no display is soldered on this box, the chip only scans its three
# buttons, but the firmware still writes " ON " at boot (digits in the standard layout).  Both
# the flash dump (M3822P.bin) and the update images (T2GEN265_*.abs) are this board.
_R265_LITE = dict(chip="tm1650", scl=57, sda=58, labels={})

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
    # a uPD16312 / PT6312-class driver with the same 3-wire command set.  Its 4 digits are the
    # low bytes of grids 4, 2, 3, 1 (RAM 6, 2, 4, 0) with their own segment wiring -- read off the
    # 2012 firmware's font table ('0' = 0xEE, '4' = 0x87, '-' = 0x01) and its texts: " ON " at
    # boot, "----" while it tunes, then the channel number ("0004"), "oFF " in standby.  No panel
    # key does anything on that firmware (all 40 key bits tried on its live-TV screen).
    ("URZ0195", dict(chip="tm1628", clk=31, dio=9, stb=14, digit_addrs=(6, 2, 4, 0),
                     seg_map=(3, 7, 1, 5, 6, 2, 0, 4), labels={})),
    # Cabletech URZ0194S: the URZ0083Q's bootloader build, remote (same wake code) and panel bus,
    # but its digits use the standard segment layout (" ON ", "----", "noCH" come out as is) and
    # its keys differ (found on its wizard): KS7/K1 = left and KS9/K1 = right step the highlighted
    # value, KS8/K1 = menu (its main menu opens), KS8/K2 = down, KS9/K2 = power (standby "oFF ")
    ("urz0194", dict(chip="tm1628", clk=31, dio=9, stb=11, digit_addrs=(0, 2, 4, 6),
                     labels={(7, 1): "◀", (9, 1): "▶", (8, 1): "MENU", (8, 2): "▼", (9, 2): "PWR"})),
    # Strong SRT 8115 (MC6422-M3801): the same 3-wire bus and pins as the Cabletech URZ0083Q
    # (GPIO 31 clocks, 9 carries the data, 11 strobes); digit layout and keys not mapped yet
    ("srt8115", dict(chip="tm1628", clk=31, dio=9, stb=11, digit_addrs=(0, 2, 4, 6), labels={})),
    # Ferguson Ariva T650i: an FD650K ("PAN_FD650K"), TM1650-compatible, on the usual pins; its
    # digits are registers 0x6C, 0x6E, 0x6A, 0x68 from the left and its segments a..g, DP sit on
    # bits 1, 5, 6, 0, 7, 2, 4, 3 (read off the font table its application builds in RAM:
    # '0' = 0xEF, '1' = 0x60, '8' = 0xF7, '-' = 0x10): " On " from the bootloader, "Strt"
    # when the application starts (keys not mapped yet)
    ("T650i", dict(chip="tm1650", scl=31, sda=9, digit_order=(2, 3, 1, 0),
                   seg_map=(1, 5, 6, 0, 7, 2, 4, 3), labels={})),
    ("M3822P", _R265_LITE),
    ("T2GEN265", _R265_LITE),
]
DEFAULT = dict(chip="tm1650", scl=31, sda=9, labels={})

# 7-segment geometry of one digit for drawing a display (tv_gui.py's canvas,
# report.py's SVG): bit 0..6 = a (top), b, c, d (bottom), e, f, g (middle) as
# polygons in a 26 x 48 box; bit 7 = DP, a dot at (27, 43).
SEG_POLYS = {
    0: [(3, 0), (19, 0), (17, 3), (5, 3)],
    1: [(20, 1), (23, 4), (23, 18), (20, 21), (18, 18), (18, 4)],
    2: [(20, 23), (23, 26), (23, 40), (20, 43), (18, 40), (18, 26)],
    3: [(3, 44), (19, 44), (17, 41), (5, 41)],
    4: [(0, 23), (3, 26), (3, 40), (0, 43), (-2, 40), (-2, 26)],
    5: [(0, 1), (3, 4), (3, 18), (0, 21), (-2, 18), (-2, 4)],
    6: [(3, 22), (19, 22), (17, 24), (5, 24), (3, 22), (5, 20), (17, 20), (19, 22)],
}


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
        dec = TM1650Decoder(scl_gpio=spec["scl"], sda_gpio=spec["sda"], log_handler=log_handler,
                            digit_order=spec.get("digit_order", (0, 1, 2, 3)),
                            seg_map=spec.get("seg_map", TM1650Decoder.STANDARD_SEG_MAP))
        keys = [(labels.get((ki, dig), f"{ki}-{dig}"), TM1650Decoder.key_code(ki, dig, pressed=False))
                for ki in range(1, 8) for dig in range(1, 5)]
        desc = f"TM1650 on SCL {spec['scl']} / SDA {spec['sda']}, keys KI1-7 × DIG1-4"
    return dec, keys, desc
