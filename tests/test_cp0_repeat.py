"""
Test: fast mode's repeated-MTC0 skip (simulator._repeated), and the RTOS's
interrupt disable under the native Status (simulator.native_status).

The same MTC0 again after nothing but NOPs writes the same value, so the
first one's hook moves the PC past both (an emulated register's: the RTOS's
interrupt disable writes Status twice, `mtc0 t0, Status; nop; nop; mtc0 t0,
Status`, a hazard padding -- with the native Status the CPU executes those
itself and the hooks only follow them).

  same       - the disable function in fast and exact mode: the same registers
               and Status
  skip       - `mtc0 t0, EPC; nop; nop; mtc0 t0, EPC`: in fast mode the second
               MTC0's hook never runs, EPC is written
  breakpoint - a breakpoint on a NOP in between: no skip, the run stops there
  different  - a second MTC0 of another register (t1): both hooks run, both
               writes land
"""
import os
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from unicorn.mips_const import UC_MIPS_REG_PC
from simulator import AliMipsSimulator

MAIN = 0x80100000
fails = []


def check(cond, msg):
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    if not cond:
        fails.append(msg)


def i_type(o, rt, rs, imm): return o << 26 | rs << 21 | rt << 16 | (imm & 0xFFFF)
def mfc0(rt, rd): return 0x40000000 | rt << 16 | rd << 11
def mtc0(rt, rd): return 0x40800000 | rt << 16 | rd << 11


PROLOGUE = [i_type(15, 9, 0, 0x1000), i_type(13, 9, 9, 0xFF01), mtc0(9, 12)]          # Status 0x1000FF01
DISABLE = [mfc0(8, 12), 0, 0, 0, 0x24090006, 0x01284824, 0x15200008, 0x2409FFFE, 0x01094024,
           mtc0(8, 12), 0, 0, mtc0(8, 12), 0, 0]


def run(words, exact=False, breakpoint=None):
    """(registers 1..31, end PC, Status, hook calls per address, EPC)."""
    sim = AliMipsSimulator(log_handler=lambda m: None)
    sim.hook_every_instruction = exact
    calls = {}
    orig = sim._hook_cp0_site

    def counting(uc, address, size, user_data):
        calls[address] = calls.get(address, 0) + 1
        return orig(uc, address, size, user_data)
    sim._hook_cp0_site = counting
    sim.mu.mem_write(MAIN, struct.pack(f"<{len(words) + 2}I", *words, 0, 0))
    sim.stop_instr = MAIN + 4 * len(words)
    if breakpoint is not None:
        sim.breakpoints = {breakpoint}
    sim.mu.reg_write(UC_MIPS_REG_PC, MAIN)
    sim._rescan_all()
    for _ in range(20):
        sim.run(max_instructions=sim.instruction_count + 100_000)
        if sim.mu.reg_read(UC_MIPS_REG_PC) in (sim.stop_instr, breakpoint):
            break
    return ([sim.mu.reg_read(sim.gpr_map[r]) for r in range(1, 32)], sim.mu.reg_read(UC_MIPS_REG_PC),
            sim.cp0_status, calls, sim.cp0_epc)


words = PROLOGUE + DISABLE
fast, exact = run(words), run(words, exact=True)
print("--- same")
check(fast[:3] == exact[:3], f"same registers, end 0x{fast[1]:08X} and Status 0x{fast[2]:08X} in both modes")

print("--- skip")
words = PROLOGUE + [i_type(15, 8, 0, 0x8012), i_type(13, 8, 8, 0x3456), mtc0(8, 14), 0, 0, mtc0(8, 14), 0, 0]
second = MAIN + 4 * (len(PROLOGUE) + 5)
fast, exact = run(words), run(words, exact=True)
check(fast[:3] == exact[:3] and fast[4] == exact[4] == 0x80123456,
      f"same registers and EPC (0x{fast[4]:08X}) in both modes")
check(fast[3].get(second, 0) == 0 and fast[3].get(second - 12, 0) == 1,
      f"fast mode: the first MTC0's hook ran once, the second's not ({fast[3].get(second, 0)} calls)")

print("--- breakpoint")
bp = second - 4
regs, pc, status, calls, epc = run(words, breakpoint=bp)
check(pc == bp, f"a breakpoint on the NOP before the second MTC0 stops there (PC 0x{pc:08X})")

print("--- different")
other = PROLOGUE + [i_type(15, 8, 0, 0x1000), i_type(13, 8, 8, 0xFF00), mtc0(8, 12), 0, 0, mtc0(9, 12), 0]
fast, exact = run(other), run(other, exact=True)
second = MAIN + 4 * (len(PROLOGUE) + 5)
check(fast[:3] == exact[:3] and fast[2] == 0x1000FF01 and fast[3].get(second, 0) == 1,
      f"MTC0 t0 then MTC0 t1: both hooks run, Status ends 0x{fast[2]:08X} (0x1000FF01 wanted)")

print()
if fails:
    print(f"\033[91m{len(fails)} repeated-MTC0 check(s) failed\033[0m")
    sys.exit(1)
print("\033[92mAll repeated-MTC0 checks passed\033[0m")
