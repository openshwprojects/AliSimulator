"""
Fast check of the TM1650 key-scan answer (tm1650_decoder.py), no firmware:

The front-panel driver reads the TM1650 key register with a bit-banged I2C
read (address byte 0x4F, then it clocks 8 bits in from SDA, reading the GPIO
DI register after each SCL rising edge).  The decoder follows the CPU's GPIO
writes and, through di_override(), drives SDA with the key byte it answers:
0x00 (no key) by default, press_key(code) -> the code with the pressed bit
for hold_reads reads, then the code released, as the chip reports its last key.

A Python copy of the firmware's bit-bang (dump_maciej: SCL = GPIO 31, SDA =
GPIO 9, both in bank 0: DO 0x054, DI 0x050) runs transactions through the
decoder and checks the bytes it clocks in.
"""
import sys

from tm1650_decoder import TM1650Decoder

SCL, SDA = 31, 9
DO, DI = 0x054, 0x050


class BitBang:
    """The CPU side: DO register writes go to the decoder, DI reads through its override."""

    def __init__(self, dec):
        self.dec, self.do = dec, (1 << SCL) | (1 << SDA)
        self.dir = (1 << SCL) | (1 << SDA)         # both output while the CPU drives
        dec.on_gpio_write(0xB8000000 + DO, 4, self.do)

    def set(self, scl=None, sda=None):
        if scl is not None:
            self.do = (self.do & ~(1 << SCL)) | (scl << SCL)
        if sda is not None:
            self.do = (self.do & ~(1 << SDA)) | (sda << SDA)
        self.dec.on_gpio_write(0xB8000000 + DO, 4, self.do)

    def read_sda(self):
        di = self.do & self.dir                     # the simulator's loopback for output bits
        di = self.dec.di_override(DI, di) & ~self.dir | (self.do & self.dir)
        return (di >> SDA) & 1

    def start(self):
        self.set(scl=1, sda=1); self.set(sda=0); self.set(scl=0)

    def stop(self):
        self.set(scl=0, sda=0); self.set(scl=1); self.set(sda=1)

    def write_byte(self, b):
        for i in range(7, -1, -1):
            self.set(sda=(b >> i) & 1); self.set(scl=1); self.set(scl=0)
        self.dir &= ~(1 << SDA); self.set(sda=1)    # release SDA for the ACK
        self.set(scl=1); ack = self.read_sda(); self.set(scl=0)
        self.dir |= 1 << SDA
        return ack == 0

    def read_byte(self):
        self.dir &= ~(1 << SDA); self.set(sda=1)    # SDA input: the chip drives it
        v = 0
        for _ in range(8):
            self.set(scl=1); v = (v << 1) | self.read_sda(); self.set(scl=0)
        self.dir |= 1 << SDA
        self.set(sda=1); self.set(scl=1); self.set(scl=0)   # NACK
        return v

    def key_read(self):
        self.start(); ack = self.write_byte(0x4F); v = self.read_byte(); self.stop()
        return v if ack else None

    def display_write(self, addr, data):
        self.start(); a = self.write_byte(addr); d = self.write_byte(data); self.stop()
        return a and d


def main():
    ok = True
    dec = TM1650Decoder(scl_gpio=SCL, sda_gpio=SDA, log_handler=lambda m: None)
    bus = BitBang(dec)

    def check(cond, msg):
        nonlocal ok
        print(("  [PASS] " if cond else "  [FAIL] ") + msg)
        ok &= bool(cond)

    check(bus.key_read() == 0x00, "a key read with no key pressed answers 0x00")
    code = TM1650Decoder.key_code(2, 3)                     # KI2 / DIG3
    dec.press_key(code, hold_reads=2)
    reads = [bus.key_read() for _ in range(4)]
    check(reads[:2] == [code | 0x40] * 2, f"two reads answer the pressed key 0x{code | 0x40:02X}: {[hex(r) for r in reads[:2]]}")
    check(reads[2:] == [code & ~0x40] * 2, f"later reads answer it released 0x{code & ~0x40:02X}: {[hex(r) for r in reads[2:]]}")
    check(dec.key_reads_answered == 5 and dec.key_read_count == 5, f"five key reads seen ({dec.key_reads_answered}, {dec.key_read_count})")
    check(bus.display_write(0x68, 0x3F) and dec.digits[0] == 0x3F and dec.get_display_text()[0] == 'O',
          "a display write in between still decodes (digit 1 = 'O')")
    check(bus.key_read() == code & ~0x40, "and the key read after it answers the released code")
    check(TM1650Decoder.parse_key_byte(code | 0x40) == "0x4E PRESSED KI2/DIG3", "parse_key_byte names the key")
    print("[PASS] TM1650 key scan" if ok else "[FAIL] TM1650 key scan")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
