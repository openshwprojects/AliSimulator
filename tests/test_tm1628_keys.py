"""
Fast check of the TM1628 3-wire decoder (tm1628_decoder.py), no firmware:

The Cabletech URZ0083Q's panel driver talks to its TM1628-class LED driver
over STB / CLK / DIO (GPIO 11 / 31 / 9, bank 0: DO 0x054, DI 0x050): STB low,
bytes LSB first (set DIO, CLK high, CLK low), STB high.  A key read sends the
command 0x42 and then clocks 40 bits in, reading the GPIO DI register while
CLK is low before each rising edge.  The decoder follows the DO writes and,
through di_override(), drives DIO with the key bytes it answers: all zero (no
key) by default, press_key(code) -> that key's bit for hold_reads reads.

A Python copy of the firmware's bit-bang runs frames through the decoder and
checks the display RAM it keeps and the bytes it clocks in.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

import front_panel
import report_artifacts
from tm1628_decoder import TM1628Decoder

CLK, DIO, STB = 31, 9, 11
DO, DI = 0x054, 0x050


class BitBang:
    """The CPU side: DO register writes go to the decoder, DI reads through its override."""

    def __init__(self, dec):
        self.dec = dec
        self.do = 1 << STB                          # idle: STB high, CLK low (as the firmware leaves it)
        self.dir = (1 << CLK) | (1 << STB) | (1 << DIO)
        dec.on_gpio_write(0xB8000000 + DO, 4, self.do)

    def set(self, pin, level):
        self.do = (self.do & ~(1 << pin)) | (level << pin)
        self.dec.on_gpio_write(0xB8000000 + DO, 4, self.do)

    def read_dio(self):
        di = self.do & self.dir                     # the simulator's loopback for output bits
        di = self.dec.di_override(DI, di) & ~self.dir | (self.do & self.dir)
        return (di >> DIO) & 1

    def write_byte(self, b):
        for i in range(8):
            self.set(DIO, (b >> i) & 1)
            self.set(CLK, 1)
            self.set(CLK, 0)

    def frame(self, *bytes_):
        self.set(STB, 0)
        for b in bytes_:
            self.write_byte(b)
        self.set(STB, 1)

    def read_keys(self):
        """0x42 then 5 bytes clocked in like the firmware: read DI with CLK low."""
        self.set(STB, 0)
        self.write_byte(0x42)
        self.dir &= ~(1 << DIO)                     # DIO becomes an input
        out = []
        for _ in range(5):
            v = 0
            for i in range(8):
                v |= self.read_dio() << i
                self.set(CLK, 1)
                self.set(CLK, 0)
            out.append(v)
        self.dir |= 1 << DIO
        self.set(STB, 1)
        return out


def main():
    dec = TM1628Decoder(clk_gpio=CLK, dio_gpio=DIO, stb_gpio=STB, digit_addrs=(0, 2, 4, 6),
                        log_handler=lambda m: None)
    cpu = BitBang(dec)
    ok = True

    def check(cond, msg):
        nonlocal ok
        print(("  [PASS] " if cond else "  [FAIL] ") + msg)
        ok &= bool(cond)

    print("=== TM1628 decoder: display frames ===")
    cpu.frame(0x03)                                   # 7 grids x 11 segments
    cpu.frame(0x40)                                   # write, auto-increment
    cpu.frame(0xC0, 0x3F, 0x00, 0x06, 0x00, 0x5B, 0x00, 0x4F)   # "O123" at RAM 0, 2, 4, 6
    cpu.frame(0x8F)                                   # on, brightness 7
    check(dec.mode == 3, "display mode command decoded")
    check(dec.ram[:7] == [0x3F, 0x00, 0x06, 0x00, 0x5B, 0x00, 0x4F], "auto-increment write fills RAM from the address")
    check(dec.display_on and dec.brightness == 7, "display control decoded (on, brightness 7)")
    check(dec.get_display_text() == "O123", f"display text {dec.get_display_text()!r} == 'O123'")
    cpu.frame(0x44)                                   # fixed address writes, one byte per frame
    cpu.frame(0xC2, 0x66)
    cpu.frame(0xC6, 0x6D)
    check(dec.ram[2] == 0x66 and dec.ram[6] == 0x6D and dec.ram[3] == 0x00,
          "fixed-address writes change only the addressed byte")
    check(dec.get_display_text() == "O42S", f"display text {dec.get_display_text()!r} == 'O42S'")
    report_artifacts.panel(dec.digits, "display after the fixed-address writes", dec.get_display_text())
    check(dec.frame_count == 7, f"{dec.frame_count} frames counted (7)")

    print("=== TM1628 decoder: the Cabletech URZ0195's uPD16312 digit layout ===")
    # front_panel.py's layout for the URZ0195 (digits in grids 4, 2, 3, 1 with the board's
    # segment wiring), fed the frames its 2012 firmware really writes
    spec = front_panel.panel_spec("urz0195_full_dump(ESMTF25L3204).bin")
    dec2 = TM1628Decoder(clk_gpio=CLK, dio_gpio=DIO, stb_gpio=STB, digit_addrs=spec["digit_addrs"],
                         seg_map=spec["seg_map"], log_handler=lambda m: None)
    cpu2 = BitBang(dec2)
    cpu2.frame(0x40)
    for data, text, what in (((0x00, 0x00, 0xEE, 0x00, 0xCE, 0x00, 0x00, 0x00), " ON ", "the boot text"),
                             ((0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00), "----", "while it tunes"),
                             ((0x87, 0x00, 0xEE, 0x00, 0xEE, 0x00, 0xEE, 0x00), "OOO4", "channel 4 (\"0004\")"),
                             ((0x2F, 0x00, 0xEE, 0x00, 0xEE, 0x00, 0xEE, 0x00), "OOOS", "channel 5 (\"0005\")")):
        cpu2.frame(0xC0, *data)
        check(dec2.get_display_text() == text, f"{what}: display text {dec2.get_display_text()!r} == {text!r}")
    report_artifacts.panel(dec2.digits, "the URZ0195's display on channel 5", dec2.get_display_text())

    print("=== TM1628 decoder: key reads ===")
    check(cpu.read_keys() == [0, 0, 0, 0, 0], "no key: five zero bytes")
    code = TM1628Decoder.key_code(4, 2)              # KS4 / K2: byte 1, bit 4
    check(code == 1 * 8 + 4, f"key_code(KS4, K2) = {code} (byte 1 bit 4)")
    dec.press_key(code, hold_reads=2)
    r1, r2, r3 = cpu.read_keys(), cpu.read_keys(), cpu.read_keys()
    check(r1 == [0, 0x10, 0, 0, 0] and r2 == [0, 0x10, 0, 0, 0], f"pressed for 2 reads: {r1}, {r2}")
    check(r3 == [0, 0, 0, 0, 0], f"released afterwards: {r3}")
    dec.press_key(TM1628Decoder.key_code(9, 1))      # KS9 / K1: byte 4, bit 0
    check(cpu.read_keys() == [0, 0, 0, 0, 0x01], "KS9/K1 lands in the last byte, bit 0")
    check(cpu.read_keys() == [0, 0, 0, 0, 0], "one read by default")
    check(dec.key_reads_answered == 6 and dec.key_read_count == 6, "every key read answered and counted")
    cpu.frame(0x44)
    cpu.frame(0xC0, 0x7F)                            # display writes still work after key reads
    check(dec.ram[0] == 0x7F, "display write after key reads")
    cpu.frame(0x41, 0xFD)                            # uPD16312 LED port (the Cabletech URZ0195 writes it)
    check(dec.leds == 0xFD and dec.ram[0] == 0x7F, "LED port write decoded, display RAM untouched")

    print("\n[PASS] TM1628 decoder" if ok else "\n[FAIL] TM1628 decoder")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
