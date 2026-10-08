"""
Test: SPI flash controller responses never leak into the flash contents.

This is the mechanism behind the old expand() crash: response bytes injected
for JEDEC-id / status reads and command-trigger stores used to stay in the
memory-mapped flash window, so a later normal read of flash word 0 (the
bootloader chunk id) returned garbage.

A MIPS32 program in RAM drives the controller exactly like the firmware's
flash driver (SF_INS at 0xB8000098, memory-mapped window at 0xAFC00000):

  1. INS=0x9F, read a word  -> JEDEC id bytes
  2. INS=0x05, read a byte  -> status register
  3. INS=0x03, read words   -> the real flash contents again
  4. WREN, INS=0x02, store 0x0F at offset 0x10 -> page program ANDs the byte
  5. INS=0x03, read back offset 0x10
  6. WREN, INS=0xD8, store at offset 0x10020   -> 64KB sector 1 erased
  7. INS=0x03, read back offset 0x10030

The ROM is a synthetic 4MB pattern (byte i == i & 0xFF), so every expected
value is known.  Runs in fast mode and with the exact per-instruction hook.

A second scenario boots an 8 MB image (word at offset o == o ^ 0x5A000000)
and checks the layout of a flash larger than 4 MB: the SDK's flash driver
reaches offset o at 0xAFC00000 - (o & 0xC00000) + (o & 0x3FFFFF), so the
upper 4 MB sit below 0xAFC00000; the reset vector still sees offset 0; the
JEDEC id reports 8 MB (EF 40 17) and RES the electronic id 0x16 in every
byte (the ALi drivers' "0x16, 56" table entry for 8 MB parts).
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import struct
import tempfile

from simulator import AliMipsSimulator, flash_size_for
from unicorn.mips_const import (UC_MIPS_REG_PC, UC_MIPS_REG_V0, UC_MIPS_REG_V1, UC_MIPS_REG_A0,
                                UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3)

CODE_BASE = 0x80100000
ZERO, V0, V1, A0, A1, A2, A3, T0, T1, T2, T3 = 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11


def itype(op, rs, rt, imm):
    return (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def lui(rt, imm):        return itype(0x0F, 0, rt, imm)
def ori(rt, rs, imm):    return itype(0x0D, rs, rt, imm)
def addiu(rt, rs, imm):  return itype(0x09, rs, rt, imm)
def sb(rt, off, base):   return itype(0x28, base, rt, off)
def lbu(rt, off, base):  return itype(0x24, base, rt, off)
def lw(rt, off, base):   return itype(0x23, base, rt, off)


PROGRAM = [
    lui(T0, 0xB800), ori(T0, T0, 0x0098),      # t0 = SF_INS
    lui(T2, 0xAFC0),                            # t2 = flash window
    addiu(T1, ZERO, 0x9F), sb(T1, 0, T0),       # JEDEC read id
    lw(V0, 0, T2),                              # v0 = response word
    addiu(T1, ZERO, 0x05), sb(T1, 0, T0),       # read status
    lbu(V1, 0, T2),                             # v1 = status byte
    addiu(T1, ZERO, 0x03), sb(T1, 0, T0),       # normal read mode
    lw(A0, 0, T2), lw(A1, 4, T2),               # a0/a1 = flash words 0/1
    addiu(T1, ZERO, 0x06), sb(T1, 0, T0), sb(ZERO, 0, T2),          # WREN + trigger
    addiu(T1, ZERO, 0x02), sb(T1, 0, T0),                           # page program
    addiu(T3, ZERO, 0x0F), sb(T3, 0x10, T2),                        # program 0x0F at 0x10
    addiu(T1, ZERO, 0x03), sb(T1, 0, T0),                           # normal read mode
    lbu(A2, 0x10, T2),                                              # a2 = programmed byte
    lui(T3, 0xAFC1),                                                # t3 = window + 0x10000 (sector 1)
    addiu(T1, ZERO, 0x06), sb(T1, 0, T0), sb(ZERO, 0, T2),          # WREN + trigger
    addiu(T1, ZERO, 0xD8), sb(T1, 0, T0), sb(ZERO, 0x20, T3),       # erase the sector of 0x10020
    addiu(T1, ZERO, 0x03), sb(T1, 0, T0),                           # normal read mode
    lbu(A3, 0x30, T3),                                              # a3 = byte 0x10030 (erased)
    0x1000FFFF, 0x00000000,                                         # b . ; nop
]
END = CODE_BASE + 4 * (len(PROGRAM) - 2)


def check(cond, msg, fails):
    print(("  PASS " if cond else "  FAIL ") + msg)
    if not cond:
        fails.append(msg)


def run_scenario(rom_path, exact, fails):
    print(f"\n--- {'exact per-instruction hook' if exact else 'fast mode'} ---")
    sim = AliMipsSimulator(log_handler=lambda m: None)
    sim.setSPIDump(False)
    sim.hook_every_instruction = exact
    sim.loadFile(rom_path)
    sim.mu.mem_write(CODE_BASE, struct.pack(f'<{len(PROGRAM)}I', *PROGRAM))
    sim.mu.reg_write(UC_MIPS_REG_PC, CODE_BASE)
    sim.stop_instr = END
    sim.run(max_instructions=1000)
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    check(pc == END, f"program ran to its end (PC=0x{pc:08X})", fails)

    v0 = sim.mu.reg_read(UC_MIPS_REG_V0)
    check(v0 == 0x001640EF, f"JEDEC id read through the window: 0x{v0:08X}", fails)
    v1 = sim.mu.reg_read(UC_MIPS_REG_V1)
    check(v1 == 0x00, f"status byte read through the window: 0x{v1:02X}", fails)
    a0, a1 = sim.mu.reg_read(UC_MIPS_REG_A0), sim.mu.reg_read(UC_MIPS_REG_A1)
    check(a0 == 0x03020100 and a1 == 0x07060504,
          f"flash words 0/1 intact after the command reads: 0x{a0:08X} 0x{a1:08X}", fails)
    a2 = sim.mu.reg_read(UC_MIPS_REG_A2)
    check(a2 == 0x00, f"page program 0x10 & 0x0F -> 0x{a2:02X}", fails)
    a3 = sim.mu.reg_read(UC_MIPS_REG_A3)
    check(a3 == 0xFF, f"sector erase -> byte 0x10030 reads 0x{a3:02X}", fails)

    head = bytes(sim.mu.mem_read(0xAFC00000, 8))
    check(head == bytes(range(8)), f"window bytes 0-7 unchanged: {head.hex()}", fails)
    check(sim.rom_image[0x10] == 0x00 and sim.rom_image[0x10030] == 0xFF
          and sim.rom_image[0x0FFFF] == 0xFF and sim.rom_image[0x20001] == 0x01,
          "flash image: byte 0x10 programmed, sector 1 erased, sectors 0 and 2 otherwise untouched", fails)


PROGRAM_8M = [
    lui(T0, 0xB800), ori(T0, T0, 0x0098),      # t0 = SF_INS
    lui(T2, 0xAFC0),                            # t2 = flash window (offset 0)
    addiu(T1, ZERO, 0x9F), sb(T1, 0, T0),       # JEDEC read id
    lw(V0, 0, T2),                              # v0 = JEDEC id
    addiu(T1, ZERO, 0xAB), sb(T1, 0, T0),       # RES: electronic id
    lw(V1, 0, T2),                              # v1 = electronic id word
    addiu(T1, ZERO, 0x03), sb(T1, 0, T0),       # normal read mode
    lw(A0, 0, T2),                              # a0 = word at offset 0
    lui(T3, 0xAFB0), lw(A1, 0x10, T3),          # a1 = offset 0x700010 (segment 1 at 0xAF800000)
    lui(T3, 0xAF80), lw(A2, 0, T3),             # a2 = offset 0x400000
    lui(T3, 0xBFC0), lw(A3, 4, T3),             # a3 = offset 4 through the reset-vector window
    0x1000FFFF, 0x00000000,                     # b . ; nop
]
END_8M = CODE_BASE + 4 * (len(PROGRAM_8M) - 2)


def run_scenario_8m(rom_path, fails):
    print("\n--- 8 MB flash layout ---")
    size = flash_size_for(rom_path)
    check(size == 0x800000, f"flash_size_for() of an 8 MB image: 0x{size:X}", fails)
    sim = AliMipsSimulator(rom_size=size, log_handler=lambda m: None)
    sim.setSPIDump(False)
    sim.loadFile(rom_path)
    sim.mu.mem_write(CODE_BASE, struct.pack(f'<{len(PROGRAM_8M)}I', *PROGRAM_8M))
    sim.mu.reg_write(UC_MIPS_REG_PC, CODE_BASE)
    sim.stop_instr = END_8M
    sim.run(max_instructions=1000)
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    check(pc == END_8M, f"program ran to its end (PC=0x{pc:08X})", fails)
    v0, v1 = sim.mu.reg_read(UC_MIPS_REG_V0), sim.mu.reg_read(UC_MIPS_REG_V1)
    check(v0 == 0x001740EF, f"JEDEC id of an 8 MB part: 0x{v0:08X}", fails)
    check(v1 == 0x16161616, f"RES electronic id 0x16 in every byte: 0x{v1:08X}", fails)
    mark = lambda o: o ^ 0x5A000000
    a0, a1, a2, a3 = (sim.mu.reg_read(r) for r in (UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3))
    check(a0 == mark(0), f"0xAFC00000 reads offset 0: 0x{a0:08X}", fails)
    check(a1 == mark(0x700010), f"0xAFB00010 reads offset 0x700010: 0x{a1:08X}", fails)
    check(a2 == mark(0x400000), f"0xAF800000 reads offset 0x400000: 0x{a2:08X}", fails)
    check(a3 == mark(4), f"0xBFC00004 reads offset 4: 0x{a3:08X}", fails)
    views = {0x0F400000: 0, 0x0F000000: 0x400000, 0x9F800000: 0x400000, 0xAFFFFFFC: 0x3FFFFC}
    for addr, off in views.items():
        w = int.from_bytes(sim.mu.mem_read(addr, 4), 'little')
        check(w == mark(off), f"view 0x{addr:08X} shows offset 0x{off:06X}: 0x{w:08X}", fails)
    sim._rom_write(0x3FFFFE, b"\x11\x22\x33\x44")          # across the segment boundary
    lo = bytes(sim.mu.mem_read(0xAFFFFFFE, 2))
    hi = bytes(sim.mu.mem_read(0xAF800000, 2))
    check(lo == b"\x11\x22" and hi == b"\x33\x44",
          f"a write across offset 0x400000 lands in both segments: {lo.hex()} {hi.hex()}", fails)


def main():
    print("=== Test: flash window isolation (SPI responses vs flash contents) ===")
    fails = []
    pattern = bytes(range(256)) * (4 * 1024 * 1024 // 256)
    fd, rom_path = tempfile.mkstemp(suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(pattern)
    try:
        for exact in (False, True):
            run_scenario(rom_path, exact, fails)
    finally:
        os.unlink(rom_path)
    words = struct.pack('<2097152I', *[o ^ 0x5A000000 for o in range(0, 0x800000, 4)])
    fd, rom_path = tempfile.mkstemp(suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(words)
    try:
        run_scenario_8m(rom_path, fails)
    finally:
        os.unlink(rom_path)
    if fails:
        print(f"\n\033[91m{len(fails)} check(s) failed\033[0m")
        sys.exit(1)
    print("\n\033[92mAll flash window checks passed\033[0m")
    sys.exit(0)


if __name__ == "__main__":
    main()
