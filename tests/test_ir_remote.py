"""
Fast checks of the IR remote support (ir_remote.py), no firmware boot:

1. nec_rlc() frames decode to the right key code with a Python copy of the
   firmware's receive path: generate_code() run-length grouping (8 us ticks,
   runs of one level summed) and irc_NEC_pulse_to_code() (ALi S3602 build,
   530 us unit, precision 280 us, as disassembled from dump_maciej), then
   scan_code_to_msg_code()'s 16-bit ir_code -- and under the "necfirst"
   coding the 2015 SDK's, which keeps the code's top byte instead, and under
   "cmd" the Ferguson T50's, which keeps the command half only.
2. find_key_table() finds a g_itou_key_tab-style table in a synthetic RAM
   image -- and the T50's, whose codes have no address byte in common --,
   and press-key codes round-trip through ir16_to_nec().
3. press_key() uses VKEY_FALLBACKS for a key the firmware numbers
   differently (INFO = 29 in dump_maciej) and rejects unknown keys.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

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
    for ir16 in (0x378F, 0x372F, 0x374F, 0x37FD, 0x377D, 0x377F, 0x028F, 0x0000, 0xFFFF, 0x1234):
        a, c = ir_remote.ir16_to_nec(ir16)
        rlc = ir_remote.nec_rlc(a, c)
        codes = receive(rlc)
        got = [hex(ir16_of(x)) for x in codes]
        if len(codes) != 1 or ir16_of(codes[0]) != ir16 or len(rlc) > 255:
            print(f"[FAIL] ir16 0x{ir16:04X}: NEC 0x{a:02X}/0x{c:02X}, {len(rlc)} RLC bytes -> {got}")
            ok = False
        # the 2015 SDK's conversion (the ESR-250's 0x8009C058) keeps the first address byte
        a, c, a_hi = ir_remote.frame_from_ir16(ir16, "necfirst")
        codes = receive(ir_remote.nec_rlc(a, c, a_hi))
        if len(codes) != 1 or (((codes[0] >> 24) << 8) | (codes[0] & 0xFF)) != ir16:
            print(f"[FAIL] necfirst ir16 0x{ir16:04X}: NEC 0x{a:02X}/0x{c:02X} -> {[hex(x) for x in codes]}")
            ok = False
        if (ir16 >> 8) == 0x02 and (codes[0] >> 16) != 0x0237:
            print(f"[FAIL] necfirst 0x{ir16:04X} must decode with high half 0x0237, got 0x{codes[0] >> 16:04X}")
            ok = False
    # the T50's table code is the received code's low half, rev8(command) << 8 | rev8(~command),
    # and its control task keeps only codes whose high half is its remote's address, 0x803F
    for ir16 in (0xDA25, 0x807F, 0x6897, 0xA857):
        a, c, a_hi = ir_remote.frame_from_ir16(ir16, "cmd")
        codes = receive(ir_remote.nec_rlc(a, c, a_hi))
        if len(codes) != 1 or codes[0] != (0x803F << 16 | ir16):
            print(f"[FAIL] cmd ir16 0x{ir16:04X}: NEC 0x{a:02X}/0x{c:02X} -> {[hex(x) for x in codes]}")
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
    # ... and a T50-style one, whose codes share no address byte, only the command / ~command form
    ram[:] = rng.integers(0, 256, ram.size, dtype=np.uint8)
    rev = ir_remote._rev8
    table = {v: rev(0x10 + 7 * v) << 8 | rev(~(0x10 + 7 * v) & 0xFF) for v in range(20)}
    for i, (vkey, ir16) in enumerate(table.items()):
        ram[base + 8 * i: base + 8 * i + 8] = np.frombuffer(
            np.array([0x11 | (ir16 << 16), vkey], '<u4').tobytes(), np.uint8)
    found = ir_remote.find_key_table(ram)
    if found != table:
        print(f"[FAIL] find_key_table, T50 layout: {found}")
        ok = False
    # ... and a M3602-style table (URZ0083/URZ0086 v1.0.x) where a few secondary-remote
    # entries (address byte 0x60) are interleaved inside a larger 0x00xx table
    ram[:] = rng.integers(0, 256, ram.size, dtype=np.uint8)
    main_table = {v: 0x0000 | ((0xFF - 3 * v) & 0xFF) for v in range(30)}
    mixed_entries = []
    for idx, (vkey, ir16) in enumerate(main_table.items()):
        mixed_entries.append((vkey, ir16))
        if idx in (5, 11, 17, 23):
            mixed_entries.append((100 + idx, 0x6000 | idx))
    for i, (vkey, ir16) in enumerate(mixed_entries):
        ram[base + 8 * i: base + 8 * i + 8] = np.frombuffer(
            np.array([0x11 | (ir16 << 16), vkey], '<u4').tobytes(), np.uint8)
    found = ir_remote.find_key_table(ram)
    if found != main_table:
        print(f"[FAIL] find_key_table, interleaved secondary-remote layout: {found}")
        ok = False
    # ... and a Ferguson-style table where dummy 0x80FF placeholder entries sit at
    # unshifted vkey numbers > 9 (32=CH+, 52=GREEN, 53=YELLOW) while digit '1' (vkey=1)
    # legitimately uses 0x80FF and the real keys sit at the M3821 +3 shifted vkeys (35=CH+, 55=GREEN)
    ram[:] = rng.integers(0, 256, ram.size, dtype=np.uint8)
    ferg_entries = [(v, 0x8000 | ((0xE0 - 5 * v) & 0xFF)) for v in range(17)]
    ferg_entries[1] = (1, 0x80FF)                               # real digit '1'
    ferg_entries += [(32, 0x80FF), (34, 0x80FF), (52, 0x80FF), (53, 0x80FF), (35, 0x809D), (55, 0x80B7)]
    for i, (vkey, ir16) in enumerate(ferg_entries):
        ram[base + 8 * i: base + 8 * i + 8] = np.frombuffer(
            np.array([0x11 | (ir16 << 16), vkey], '<u4').tobytes(), np.uint8)
    found = ir_remote.find_key_table(ram)
    if found.get(1) != 0x80FF or 32 in found or 52 in found or found.get(35) != 0x809D or found.get(55) != 0x80B7:
        print(f"[FAIL] find_key_table, Ferguson dummy-0x..FF filtering: {found}")
        ok = False
    # 3. a key the firmware numbers differently: press_key falls back to VKEY_FALLBACKS (+2 and +3 shifts)
    from simulator import AliMipsSimulator
    sim = AliMipsSimulator(log_handler=lambda m: None)
    # UP=12, POWER=19 (where 17 is missing), MUTE=20 (where 18 is missing), INFO=29 (where 27 is missing),
    # CH+=35 (M3821 +3 where 32/34 are missing), RED=53 (+2 where 51 is missing),
    # GREEN=55 (M3821 +3 where 52/54 are missing), STOP=61 (where 59 is missing), FILELIST=86 (where 84 is missing)
    sim._ir_key_table = {12: 0x372F, 19: 0x37DF, 20: 0x377F, 29: 0x37A7, 35: 0x379D,
                         53: 0x37B7, 55: 0x3737, 61: 0x37E5, 86: 0x371D}
    sent = []
    sim.ir_send_nec = lambda a, c, label=None: sent.append((a, c))
    try:
        if (sim.press_key('POWER') != ir_remote.ir16_to_nec(0x37DF) or
                sim.press_key('INFO') != ir_remote.ir16_to_nec(0x37A7) or
                sim.press_key('MUTE') != ir_remote.ir16_to_nec(0x377F) or
                sim.press_key('CH+') != ir_remote.ir16_to_nec(0x379D) or
                sim.press_key('RED') != ir_remote.ir16_to_nec(0x37B7) or
                sim.press_key('GREEN') != ir_remote.ir16_to_nec(0x3737) or
                sim.press_key('STOP') != ir_remote.ir16_to_nec(0x37E5) or
                sim.press_key('FILELIST') != ir_remote.ir16_to_nec(0x371D) or
                sim.press_key('UP') != ir_remote.ir16_to_nec(0x372F)):
            print("[FAIL] press_key: wrong NEC code for POWER/INFO/MUTE/CH+/RED/GREEN/STOP/FILELIST fallbacks or UP")
            ok = False
        try:
            sim.press_key('MENU')
            print("[FAIL] press_key('MENU') must raise KeyError when neither 15 nor a fallback is in the table")
            ok = False
        except KeyError:
            pass
    except Exception as e:
        print(f"[FAIL] press_key: {e!r}")
        ok = False
    # 4. M3329 remote_frame() maps all REMOTE_KEYS names through its key table
    from chips.m3329 import KEY_CONFIG, REMOTE_KEYS, M3329
    m3329 = M3329(sim)
    table_va = 0x8003E0AC
    customer = 0x205D
    unique_codes = sorted(set(REMOTE_KEYS.values()))
    sim.poke(KEY_CONFIG, int(table_va).to_bytes(4, 'little'))
    sim.poke(KEY_CONFIG + 4, int(customer << 16).to_bytes(4, 'little'))
    sim.poke(KEY_CONFIG + 0xE, int(len(unique_codes)).to_bytes(2, 'little'))
    for idx, code in enumerate(unique_codes):
        cmd_byte = (0x40 + idx) & 0xFF
        sim.poke(table_va + 4 * idx, bytes([cmd_byte ^ 0xFF, cmd_byte, code, 0]))
    for name, code in REMOTE_KEYS.items():
        frame = m3329.remote_frame(name)
        if frame is None or frame[0] != 0x04 or frame[2] != 0xBA:
            print(f"[FAIL] M3329 remote_frame({name!r}) -> {frame}")
            ok = False
    for dump_name, want_coding in (
        ("S16_CHN_2.8.abs", "necfirst"),
        ("ALI3606_0A010A00_gui_edision_1.6.89.abs", "necfirst"),
        ("OPTIMUSS_underline_official_hd_1.5.87.abs", "necfirst"),
        ("miniplus_highspeed_official_hd_1.5.87.abs", "necfirst"),
        ("A204_20190903_V1.3B1.abs", "ext00"),
        ("Ferguson_A204_V1.3B3.abs", "ext00"),
        ("A154Combo_10102018_V1.29B8.abs", "ext00"),
        ("A254Combo_09102018_V1.29B7.abs", "ext00"),
        ("254Combo_20200423_V1.32B3.abs", "ext00"),
    ):
        if ir_remote.coding_for(dump_name) != want_coding:
            print(f"[FAIL] coding_for({dump_name!r}) -> {ir_remote.coding_for(dump_name)!r}, expected {want_coding!r}")
            ok = False
    print("[PASS] IR remote: NEC frames decode, key table found" if ok else "[FAIL] IR remote")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
