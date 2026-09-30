"""
Test: the simulated CP0 Count register.

Unicorn's MIPS timer is compiled out (mfc0 Count always reads 0, mtc0 Count is
a no-op), so the simulator emulates Count through hooks on the MFC0/MTC0
instructions.  A MIPS32 program in RAM does:

  mfc0 t0, Count ; 50 x nop ; mfc0 t1, Count
  addiu t2, zero, 0x1234 ; mtc0 t2, Count ; nop ; nop ; mfc0 t3, Count ; b .

Expectations:
  - exact per-instruction mode: Count advances by exactly 2 per instruction
    (t1 - t0 == 102) and mtc0 sets it (t3 == 0x1234 + 6),
  - fast mode: the MFC0/MTC0 sites are found by scanning RAM the first time
    the chunk executes, Count advances between the reads and mtc0 sets it.
"""
import struct
import sys

from simulator import AliMipsSimulator
from unicorn.mips_const import (UC_MIPS_REG_PC, UC_MIPS_REG_T0, UC_MIPS_REG_T1,
                                UC_MIPS_REG_T2, UC_MIPS_REG_T3)

CODE_BASE = 0x80100000
MFC0_T0 = 0x40084800      # mfc0 t0, $9
MFC0_T1 = 0x40094800      # mfc0 t1, $9
MFC0_T3 = 0x400B4800      # mfc0 t3, $9
MTC0_T2 = 0x408A4800      # mtc0 t2, $9

PROGRAM = [MFC0_T0] + [0] * 50 + [MFC0_T1, 0x240A1234, MTC0_T2, 0, 0, MFC0_T3, 0x1000FFFF, 0]
END = CODE_BASE + 4 * (len(PROGRAM) - 2)


def check(cond, msg, fails):
    print(("  PASS " if cond else "  FAIL ") + msg)
    if not cond:
        fails.append(msg)


def run_scenario(exact, fails):
    print(f"\n--- {'exact per-instruction hook' if exact else 'fast mode'} ---")
    sim = AliMipsSimulator(log_handler=lambda m: None)
    sim.hook_every_instruction = exact
    sim.mu.mem_write(CODE_BASE, struct.pack(f'<{len(PROGRAM)}I', *PROGRAM))
    sim.mu.reg_write(UC_MIPS_REG_PC, CODE_BASE)
    sim.stop_instr = END
    sim.run(max_instructions=1000)
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    check(pc == END, f"program ran to its end (PC=0x{pc:08X})", fails)

    t0, t1 = sim.mu.reg_read(UC_MIPS_REG_T0), sim.mu.reg_read(UC_MIPS_REG_T1)
    t3 = sim.mu.reg_read(UC_MIPS_REG_T3)
    delta = (t1 - t0) & 0xFFFFFFFF
    if exact:
        check(delta == 102, f"Count advanced by 2 per instruction (delta={delta})", fails)
        check(t3 == 0x1234 + 6, f"mtc0 Count then 3 instructions later: 0x{t3:X}", fails)
    else:
        check(0 < delta < 100_000_000, f"Count advanced between the reads (delta={delta})", fails)
        check(0x1234 <= t3 < 0x1234 + 100_000_000, f"mtc0 Count took effect: 0x{t3:X}", fails)


def main():
    print("=== Test: CP0 Count emulation ===")
    fails = []
    for exact in (False, True):
        run_scenario(exact, fails)
    if fails:
        print(f"\n\033[91m{len(fails)} check(s) failed\033[0m")
        sys.exit(1)
    print("\n\033[92mAll CP0 Count checks passed\033[0m")
    sys.exit(0)


if __name__ == "__main__":
    main()
