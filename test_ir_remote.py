"""
Fast checks of the IR remote support (ir_remote.py), no firmware boot:

1. nec_rlc() frames decode to the right key code with a Python copy of the
   firmware's receive path: generate_code() run-length grouping (8 us ticks,
   runs of one level summed) and irc_NEC_pulse_to_code() (ALi S3602 build,
   530 us unit, precision 280 us, as disassembled from dump_maciej), then
   scan_code_to_msg_code()'s 16-bit ir_code.
2. find_key_table() finds a g_itou_key_tab-style table in a synthetic RAM
   image, and press-key codes round-trip through ir16_to_nec().
"""
import sys

import numpy as np

import ir_remote

UNIT, PREC = 530, 280
INVALID = 0xFFFFFFFF


class NecDecoder:
    """irc_NEC_pulse_to_code() of the firmware (state machine, first/second half)."""

    def __init__(self):
        self.state = 0
        self.code = 0
        self.first_half = 1
        self.last_width = 0

    def pulse(self, w):
        self.last_width += w
        if w < PREC:
            return INVALID
        lead = PREC << 2
        if self.state == 0:
            if 16 * UNIT - lead < w < 16 * UNIT + lead:
                self.first_half = 0
                return INVALID
        elif self.first_half == 1 and w < 2 * UNIT - PREC:
            self.first_half = 0
            return INVALID
        w, self.last_width, self.first_half = self.last_width, 0, 1
        if self.state == 0:
            if 24 * UNIT - lead < w < 24 * UNIT + lead:
                self.state = 1
            elif w < 20 * UNIT:
                self.state = 0
            return INVALID
        if UNIT < w < 5 * UNIT:
            self.code = ((self.code << 1) | (w > 3 * UNIT)) & 0xFFFFFFFF
            if self.state == 32:
                self.state = 0
                return self.code
            self.state += 1
            return INVALID
        self.state = 0
        return INVALID


def receive(rlc):
    """generate_code(): sum runs of one level (bit 7) into pulse widths."""
    dec, widths, acc = NecDecoder(), [], 0
    dec.pulse(1_000_000)                          # the idle time before the frame
    for i, b in enumerate(rlc):
        acc += (b & 0x7F) * ir_remote.TICK_US
        if i + 1 == len(rlc) or (rlc[i + 1] ^ b) & 0x80:
            widths.append(acc)
            acc = 0
    codes = [c for c in (dec.pulse(w) for w in widths) if c != INVALID]
    return codes


def ir16_of(code):
    """scan_code_to_msg_code(): the 16-bit ir_code of a key code."""
    return (((code >> 16) & 0xFF) << 8) | (code & 0xFF)


def main():
    ok = True
    # 1. every 16-bit table code survives NEC encoding and the firmware decoder
    for ir16 in (0x378F, 0x372F, 0x374F, 0x37FD, 0x377D, 0x377F, 0x0000, 0xFFFF, 0x1234):
        a, c = ir_remote.ir16_to_nec(ir16)
        rlc = ir_remote.nec_rlc(a, c)
        codes = receive(rlc)
        got = [hex(ir16_of(x)) for x in codes]
        if len(codes) != 1 or ir16_of(codes[0]) != ir16 or len(rlc) > 255:
            print(f"[FAIL] ir16 0x{ir16:04X}: NEC 0x{a:02X}/0x{c:02X}, {len(rlc)} RLC bytes -> {got}")
            ok = False
    # 2. key table search
    ram = np.zeros(1 << 20, np.uint8)
    rng = np.random.default_rng(1)
    ram[:] = rng.integers(0, 256, ram.size, dtype=np.uint8)
    table = {v: 0x3700 | ((0x7F - 3 * v) & 0xFF) for v in range(20)}
    base = 0x4321C
    for i, (vkey, ir16) in enumerate(table.items()):
        ram[base + 8 * i: base + 8 * i + 8] = np.frombuffer(
            np.array([0x11 | (ir16 << 16), vkey], '<u4').tobytes(), np.uint8)
    found = ir_remote.find_key_table(ram)
    if found != table:
        print(f"[FAIL] find_key_table: {found}")
        ok = False
    print("[PASS] IR remote: NEC frames decode, key table found" if ok else "[FAIL] IR remote")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
