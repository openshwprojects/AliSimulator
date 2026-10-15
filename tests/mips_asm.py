"""
MIPS32 instruction encoders for the tests' small programs (not a test itself:
run_all_tests.py runs test_*.py and the run_dump_*.py regressions), and a
helper that loads a program and an exception handler into a fresh simulator.
"""
import struct

from unicorn.mips_const import UC_MIPS_REG_PC

# registers
ZERO, AT, V0, V1, A0, A1, A2, A3 = 0, 1, 2, 3, 4, 5, 6, 7
T0, T1, T2, T3, T4, T5, T6, T7 = 8, 9, 10, 11, 12, 13, 14, 15
S0, S1, S2, S3, S4, S5, S6, S7 = 16, 17, 18, 19, 20, 21, 22, 23
T8, T9, K0, K1, GP, SP, FP, RA = 24, 25, 26, 27, 28, 29, 30, 31
# CP0 registers
COUNT, COMPARE, STATUS, CAUSE, EPC = 9, 11, 12, 13, 14

NOP = 0x00000000
ERET = 0x42000018

VECTOR = 0x80000180          # general exception vector (EBase 0x80000000, BEV clear)
MAIN = 0x80100000            # where load() puts the program


def mfc0(rt, rd, sel=0): return 0x40000000 | rt << 16 | rd << 11 | sel
def mtc0(rt, rd, sel=0): return 0x40800000 | rt << 16 | rd << 11 | sel
def addiu(rt, rs, imm): return 0x24000000 | rs << 21 | rt << 16 | (imm & 0xFFFF)
def addu(rd, rs, rt): return 0x00000021 | rs << 21 | rt << 16 | rd << 11
def subu(rd, rs, rt): return 0x00000023 | rs << 21 | rt << 16 | rd << 11
def orr(rd, rs, rt): return 0x00000025 | rs << 21 | rt << 16 | rd << 11
def andi(rt, rs, imm): return 0x30000000 | rs << 21 | rt << 16 | (imm & 0xFFFF)
def ori(rt, rs, imm): return 0x34000000 | rs << 21 | rt << 16 | (imm & 0xFFFF)
def lui(rt, imm): return 0x3C000000 | rt << 16 | (imm & 0xFFFF)
def lw(rt, off, base): return 0x8C000000 | base << 21 | rt << 16 | (off & 0xFFFF)
def lbu(rt, off, base): return 0x90000000 | base << 21 | rt << 16 | (off & 0xFFFF)
def sw(rt, off, base): return 0xAC000000 | base << 21 | rt << 16 | (off & 0xFFFF)
def beq(rs, rt, off): return 0x10000000 | rs << 21 | rt << 16 | (off & 0xFFFF)
def bne(rs, rt, off): return 0x14000000 | rs << 21 | rt << 16 | (off & 0xFFFF)
def b(off): return beq(ZERO, ZERO, off)
def li(rt, value): return [lui(rt, value >> 16), ori(rt, rt, value & 0xFFFF)]


IDLE = [b(-1), NOP]          # `b .` with a nop in its delay slot: the RTOS's idle loop


def tick_handler(period_reg=T5, counter=S1, epc_log=None):
    """A timer interrupt handler: counts ticks in `counter`, logs EPC at
    [epc_log++] when given (a register holding the log pointer), sets
    Compare = Count + period_reg and returns."""
    log = [mfc0(K1, EPC), sw(K1, 0, epc_log), addiu(epc_log, epc_log, 4)] if epc_log is not None else []
    return log + [addiu(counter, counter, 1), mfc0(K0, COUNT), addu(K0, K0, period_reg),
                  mtc0(K0, COMPARE), ERET, NOP]


def timer_prologue(period, first, status, period_reg=T5):
    """Count = 0, Compare = first, period_reg = period, Status = status."""
    return li(period_reg, period) + [mtc0(ZERO, COUNT)] + li(T1, first) + [mtc0(T1, COMPARE)] + \
        li(T2, status) + [mtc0(T2, STATUS)]


def load(sim, main, vector=None, at=MAIN):
    """Put the program at `at` (and a handler at VECTOR), hook its CP0 sites,
    and start there.  Returns the program's start address."""
    sim.mu.mem_write(at, struct.pack(f"<{len(main)}I", *main))
    if vector:
        sim.mu.mem_write(VECTOR, struct.pack(f"<{len(vector)}I", *vector))
    sim.mu.reg_write(UC_MIPS_REG_PC, at)
    sim._rescan_all()
    return at


def address_of(main, index, at=MAIN):
    """The address of main[index] once loaded at `at`."""
    return at + 4 * index
