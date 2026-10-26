"""
Test: the C++ core's loop skipping is exact -- a run with it gives the very
registers and the very time of a run without it (spin_skip off).

  counting  - loops that only count (Core::Block::Ff, a cache-maintenance loop:
              CACHE is a no-op), done at once: bne on the counter before or
              after its step, an slt / sltu / slti / sltiu flag with bnez /
              beqz, a second counter beside it, steps odd, even, negative,
              starts near the ends of the signed and unsigned ranges, loops
              that never end (only the slice's end stops them); 300 random
              ones, each run 1 M instructions -- the loop's end, or the slice
              boundaries cutting it, at the same instruction both ways (a
              Count read right after the loop shows when it ended)
  delay     - a Count-polling delay() (the RTOS's: get_count() in a loop until
              the ticks passed), called with random waits: replayed passes
              skipped (Core::poll_skip), the caller's next Count read the same
              both ways, and the second call of a size skipping from its first
              return to the loop's head (the cache of known loops)
"""
import os
import random
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from engine_check import CPP, not_applicable

if not CPP:
    not_applicable("the C++ core's loop skipping (Unicorn runs every pass)")

import cpp_core
from simulator import AliMipsSimulator
from mips_asm import (COUNT, NOP, RA, STATUS, T0, T1, T2, T3, V0, V1, A0, S0, S1, address_of, addiu, bne,
                      li, load, mfc0, mtc0)

fails = []
# the end of each program: a spin the core runs as a block and skips (interrupts
# are off, so `b .` would not count as idle and would run an instruction at a time)
SPIN = [NOP, 0x1000FFFE, NOP]          # nop; b .-4; nop


def check(cond, msg):
    print(f"  [{'PASS' if cond else 'FAIL'}] {msg}")
    if not cond:
        fails.append(msg)


def cache(base, op=0x19):
    return 0xBC000000 | base << 21 | op << 16


def slt(rd, rs, rt):
    return 0x0000002A | rs << 21 | rt << 16 | rd << 11


def sltu(rd, rs, rt):
    return 0x0000002B | rs << 21 | rt << 16 | rd << 11


def slti(rt, rs, imm):
    return 0x28000000 | rs << 21 | rt << 16 | (imm & 0xFFFF)


def sltiu(rt, rs, imm):
    return 0x2C000000 | rs << 21 | rt << 16 | (imm & 0xFFFF)


def beq(rs, rt, off):
    return 0x10000000 | rs << 21 | rt << 16 | (off & 0xFFFF)


def jal(target):
    return 0x0C000000 | ((target >> 2) & 0x03FFFFFF)


def jr(rs):
    return 0x00000008 | rs << 21


def sltu_r(rd, rs, rt):
    return sltu(rd, rs, rt)


def subu(rd, rs, rt):
    return 0x00000023 | rs << 21 | rt << 16 | rd << 11


# One simulator for every run (a construction costs more than a run here): a run
# starts from reset -- the clock at 0, every register 0, the program loaded anew.
# The core's block cache and its cache of known polling loops stay, as they would
# in a firmware run; both are validated against the code bytes on use.
SIM = AliMipsSimulator(log_handler=lambda m: None, engine="cpp")
SIM.exact_count_threshold = 0
SIM.calibration_slices = 0
SKIP_COUNTERS = (cpp_core.F_FF_SKIPPED, cpp_core.F_POLL_SKIPPED, cpp_core.F_POLL_SKIPS, cpp_core.F_EXECUTED)


def run(program, regs, instructions, skip, routines=()):
    """The program from MAIN with these registers (and `routines`: (address,
    words) pairs placed too), `instructions` of emulation time in timed slices
    (interrupts off); the registers at the end and how much the run skipped:
    (regs, ff skipped, poll skipped, poll loops, executed)."""
    sim = SIM
    sim.instruction_count = 0
    for field in (cpp_core.F_ICOUNT, cpp_core.F_IDLE_SKIPPED, cpp_core.F_SPIN_SKIPPED):
        sim._core.set(field, 0)
    for r in range(32):
        sim.mu.reg_write(2 + r, 0)
    sim._core.set(cpp_core.F_SPIN_SKIP, 1 if skip else 0)
    prologue = li(T2, 0x10000000) + [mtc0(T2, STATUS), mtc0(0, COUNT)]
    for r, v in regs.items():
        prologue += li(r, v)
    load(sim, prologue + program)
    for address, words in routines:
        sim.mu.mem_write(address, struct.pack(f"<{len(words)}I", *words))
    before = [sim._core.get(f) for f in SKIP_COUNTERS]
    end = instructions / sim.cpp_ips
    while sim._vtime() < end:
        sim.run(max_instructions=0, max_vtime=end)
    out = [sim.mu.reg_read(2 + r) for r in range(32)]
    return (out,) + tuple(sim._core.get(f) - b for f, b in zip(SKIP_COUNTERS, before))


def counting_loop(rng):
    """A random counting loop: (its words, the registers it starts with)."""
    step = rng.choice([16, 4, 32, 1, 3, 7, -16, -4, -1, -5, 64, 12])
    start = rng.choice([0x80000000, 0x80100000, 0x7FFFFF00, 0xFFFFFF00, 0x00000100, 0x7FFFFFF0,
                        rng.getrandbits(32)])
    count = rng.choice([0, 1, 2, 5, 100, 1000, 50_000, 300_000, 10_000_000])
    end = (start + count * step) & 0xFFFFFFFF
    if rng.random() < 0.15:
        end = (end + rng.choice([1, 2, 8])) & 0xFFFFFFFF          # (never equal for some steps: endless)
    kind = rng.choice(["bne_after", "bne_before", "slt", "sltu", "slti", "sltiu", "beqz"])
    regs = {T0: start, T1: end, T2: end, T3: rng.getrandbits(32)}
    second = [addiu(T3, T3, rng.choice([16, -8, 5]))] if rng.random() < 0.5 else [NOP]
    if kind == "bne_after":          # cache; bne t0, t1, loop; addiu t0, t0, step
        body = [cache(T0)] + second + [bne(T0, T1, -(2 + len(second))), addiu(T0, T0, step)]
    elif kind == "bne_before":       # addiu t0, t0, step; cache; bne t0, t1, loop; nop
        body = [addiu(T0, T0, step), cache(T0)] + second + [bne(T0, T1, -(3 + len(second))), NOP]
    elif kind in ("slt", "sltu"):    # cache; addiu t0, step; slt at, t0, t2; bnez at, loop; second
        op = slt if kind == "slt" else sltu
        args = (V1, T0, T2) if rng.random() < 0.7 else (V1, T2, T0)
        body = [cache(T0), addiu(T0, T0, step), op(*args), bne(V1, 0, -4)] + second
    elif kind in ("slti", "sltiu"):
        op = slti if kind == "slti" else sltiu
        imm = rng.choice([0x100, -0x100, 0x7FFF, -0x8000, 0, 64])
        body = [cache(T0), addiu(T0, T0, step), op(V1, T0, imm), bne(V1, 0, -4)] + second
    else:                            # beqz: on while the flag is 0
        args = (V1, T2, T0) if rng.random() < 0.7 else (V1, T0, T2)
        body = [cache(T0), addiu(T0, T0, step), slt(*args), beq(V1, 0, -4)] + second
    return body + [mfc0(V0, COUNT)] + SPIN, regs, kind


print("--- counting")
rng = random.Random(3811)
mismatch, skipped_runs, by_kind = 0, 0, {}
for case in range(300):
    program, regs, kind = counting_loop(rng)
    on, ff, _, _, _ = run(program, regs, 1_000_000, True)
    off, ff_off, _, _, _ = run(program, regs, 1_000_000, False)
    by_kind[kind] = by_kind.get(kind, 0) + 1
    if on != off:
        mismatch += 1
        if mismatch <= 5:
            diff = {f"r{r}": (hex(on[r]), hex(off[r])) for r in range(32) if on[r] != off[r]}
            print(f"    case {case} ({kind}, regs {[hex(v) for v in regs.values()]}): {diff}")
    if ff:
        skipped_runs += 1
    if ff_off:
        mismatch += 1
check(mismatch == 0, f"300 random counting loops ({by_kind}): the same registers and loop-end time with "
                     f"and without skipping ({mismatch} differ)")
check(skipped_runs > 100, f"the loops were done at once in {skipped_runs} of the 300 runs (the rest end within a few passes)")

print("--- delay")
GET_COUNT = 0x80180000
get_count = [mfc0(V0, COUNT), NOP, NOP, NOP, NOP, NOP, jr(RA), NOP]
# delay(a0 ticks): start = get_count(); while (get_count() - start < a0);  then V1 = get_count()
delay = [jal(GET_COUNT), NOP, addiu(S0, V0, 0),          # s0 = start
         jal(GET_COUNT), NOP, subu(V0, V0, S0), sltu_r(V0, V0, A0), bne(V0, 0, -5), NOP]
# the newer SDK's (the R265's): `now` kept in v1, a path of its own when Count
# wrapped, the loop closed by `b`; the caller then takes v1 (the last `now`)
delay2 = [jal(GET_COUNT), NOP, addiu(S0, V0, 0),
          jal(GET_COUNT), NOP,                           # loop:
          addiu(V1, V0, 0), sltu(V0, S0, V0), beq(V0, 0, 6), subu(V0, V1, S0),
          sltu(V0, A0, V0), bne(V0, 0, 6), NOP,
          beq(0, 0, -10), NOP,
          addiu(V0, V0, -1), beq(0, 0, -13), NOP,         # wrap: (on polling)
          addiu(T3, V1, 0)]                               # out: the last `now`
waits = [rng.choice([500, 2_000, 40_000, 123_457]) for _ in range(6)]
program = []
for i, w in enumerate(waits):
    program += li(A0, w) + (delay if i % 2 else delay2) + [addiu(S1, S1, 1)]
program += [mfc0(V1, COUNT)] + SPIN


def run_delay(skip):
    """20 ms of emulation time: the six delays, then the spin."""
    regs_, _, poll, loops, executed = run(program, {}, int(0.02 * SIM.cpp_ips), skip, routines=[(GET_COUNT, get_count)])
    return regs_, poll, loops, executed


on, poll_on, loops_on, ex_on = run_delay(True)
off, poll_off, loops_off, ex_off = run_delay(False)
check(on == off, f"6 delays, both kinds ({waits} Count ticks): the same registers both ways -- the Count after them "
                 f"0x{on[3]:X} / 0x{off[3]:X}, the last `now` 0x{on[11]:X} / 0x{off[11]:X}, {on[17]} delays done")
check(poll_on > 0 and loops_on >= 4 and poll_off == 0,
      f"{poll_on:,} instructions of polling skipped in {loops_on} loops ({ex_on:,} executed, {ex_off:,} without)")

print()
if fails:
    print(f"\033[91m{len(fails)} loop-skip check(s) failed\033[0m")
    sys.exit(1)
print("\033[92mAll loop-skip checks passed\033[0m")
