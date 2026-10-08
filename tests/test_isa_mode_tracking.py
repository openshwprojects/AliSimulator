"""
Test: exact ISA mode tracking across MIPS32 <-> MIPS16 transitions.

A tiny program is placed in RAM:

  MIPS32 @ 0x80100000:  jalx 0x80100100 ; nop ; addiu v1,zero,0x32 ; b . ; nop
  MIPS16 @ 0x80100100:  li v0,1 ; addiu v0,v0,-1 (RRI-A, opcode 0x08) ;
                        addiu v0,v0,7 ; jr ra ; nop

Checks, both in fast mode and with the exact per-instruction hook:
  - step() reports the mode switch of JALX and executes MIPS16 afterwards,
  - a breakpoint inside the MIPS16 code resumes in MIPS16 mode (this is the
    failure mode of the old address-based mode heuristics),
  - MIPS16 opcode 0x08 is executed by Unicorn as ADDIU ry,rx,imm4 (it used to
    be intercepted and mis-emulated as ADDIU rx,imm8),
  - the return through JR RA lands back in MIPS32.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import struct

from simulator import AliMipsSimulator
from unicorn.mips_const import UC_MIPS_REG_PC, UC_MIPS_REG_V0, UC_MIPS_REG_V1

M32_BASE = 0x80100000
M16_BASE = 0x80100100


def jalx(target):
    return 0x74000000 | ((target >> 2) & 0x03FFFFFF)


M32_CODE = struct.pack('<5I',
                       jalx(M16_BASE),   # jalx -> MIPS16 routine (delay slot follows)
                       0x00000000,       # nop
                       0x24030032,       # addiu v1, zero, 0x32
                       0x1000FFFF,       # b .
                       0x00000000)       # nop
M16_CODE = struct.pack('<5H',
                       0x6A01,           # li    v0, 1
                       0x424F,           # addiu v0, v0, -1   (RRI-A: rx=v0 ry=v0 imm4=0xF)
                       0x4247,           # addiu v0, v0, 7
                       0xE820,           # jr    ra
                       0x6500)           # nop


def check(cond, msg, fails):
    print(("  PASS " if cond else "  FAIL ") + msg)
    if not cond:
        fails.append(msg)


def run_scenario(exact, fails):
    print(f"\n--- {'exact per-instruction hook' if exact else 'fast mode'} ---")
    sim = AliMipsSimulator(log_handler=lambda m: None)
    sim.hook_every_instruction = exact
    sim.mu.mem_write(M32_BASE, M32_CODE)
    sim.mu.mem_write(M16_BASE, M16_CODE)
    sim.mu.reg_write(UC_MIPS_REG_PC, M32_BASE)
    check(not sim.is_mips16_mode(), "starts in MIPS32", fails)

    r = sim.step()
    check(r.instruction == 'jalx', f"first step is jalx (got {r.instruction})", fails)
    check(r.mode_before == 'mips32' and r.mode_after == 'mips16' and r.mode_switched,
          "jalx switches to MIPS16", fails)
    check(r.next_pc == M16_BASE,
          f"PC after jalx + delay slot is 0x{M16_BASE:08X} (got 0x{r.next_pc:08X})", fails)
    check(sim.is_mips16_mode(), "CPU reports MIPS16", fails)

    r = sim.step()
    check(r.instruction == 'li' and r.instruction_size == 2,
          f"MIPS16 li decoded from a 2-byte hook (got {r.instruction}/{r.instruction_size})", fails)
    check(sim.mu.reg_read(UC_MIPS_REG_V0) == 1, "li v0,1 executed", fails)

    # Breakpoint inside MIPS16 code: run() must stop there and resume as MIPS16.
    bp = M16_BASE + 4                       # addiu v0,v0,7
    sim.addBreakpoint(bp)
    sim.run(max_instructions=sim.instruction_count + 100)
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    check(pc == bp, f"breakpoint at 0x{bp:08X} hit (PC=0x{pc:08X})", fails)
    check(sim.is_mips16_mode(), "still MIPS16 at the breakpoint", fails)
    v0 = sim.mu.reg_read(UC_MIPS_REG_V0)
    check(v0 == 0, f"opcode 0x08 executed as addiu v0,v0,-1 (v0={v0})", fails)
    sim.removeBreakpoint(bp)

    sim.stop_instr = M32_BASE + 0xC         # b . in the MIPS32 code
    sim.run(max_instructions=sim.instruction_count + 100)
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    check(pc == M32_BASE + 0xC, f"reached the MIPS32 stop address (PC=0x{pc:08X})", fails)
    check(not sim.is_mips16_mode(), "back in MIPS32 after jr ra", fails)
    v0 = sim.mu.reg_read(UC_MIPS_REG_V0)
    check(v0 == 7, f"v0 == 7 after the MIPS16 routine (got {v0})", fails)
    check(sim.mu.reg_read(UC_MIPS_REG_V1) == 0x32, "MIPS32 code after the return executed", fails)


def main():
    print("=== Test: ISA mode tracking (MIPS32 <-> MIPS16) ===")
    fails = []
    for exact in (False, True):
        run_scenario(exact, fails)
    if fails:
        print(f"\n\033[91m{len(fails)} check(s) failed\033[0m")
        sys.exit(1)
    print("\n\033[92mAll ISA mode checks passed\033[0m")
    sys.exit(0)


if __name__ == "__main__":
    main()
