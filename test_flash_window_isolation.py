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
"""
import os
import struct
import sys
import tempfile

from simulator import AliMipsSimulator
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
    if fails:
        print(f"\n\033[91m{len(fails)} check(s) failed\033[0m")
        sys.exit(1)
    print("\n\033[92mAll flash window checks passed\033[0m")
    sys.exit(0)


if __name__ == "__main__":
    main()
