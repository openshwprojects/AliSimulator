"""
Test: the shortcut for the TDS RTOS's microsecond delay() (simulator.delay_hle,
_hook_delay, _hook_delay_loop).

A copy of the routine (its 24 words as the firmwares have them) and of the
get_count() it polls sit next to small programs that call it; its CPU clock
variable (gp-relative) says 200 MHz, 100 Count ticks per microsecond:

  entry     - delay(5) returns at once, 5 us of emulation time later (500
              Count ticks between the caller's two reads of Count), with the
              registers as the routine leaves them (v0 0, v1 its ticks per
              microsecond, s0 / s1 / sp / ra / a0 / t0 kept): the same as when
              it runs (delay_hle = False)
  clock 0   - a clock variable still 0: no wait, v1 0, as the routine does
  loop      - a 50 ms wait in 10 ms slices: the routine runs, its loop moves
              the time on to each slice's end and then to the end of the wait
  newer build - the newer SDK's (35 words, its get_count() with an EHB):
              past the ticks (one more), v0 1, s0 / s1 / s2 kept, the whole
              argument (65,546 us, not 10), and its loop
  bootloader build - its bootloader's (the ticks per microsecond from a
              variable): the registers as it leaves them (v1 untouched), its
              loop
  SEE build - its SEE program's (the clock divided by 2,000,000, the ticks in
              s0): past the ticks, the registers, its loop
  ticks     - 1 ms timer ticks while delay(1) / delay(2500) are called over
              and over: the ticks come on time (none late by more than
              0.5 ms; fast mode's own lateness reaches ~0.2 ms) -- inside the
              2.5 ms waits, which still last 2.5 ms
  counted   - counted slices (near a budget): waits up to delay_hle_max_s are
              skipped, a longer one runs
  fallbacks - the routine runs in exact mode, over a breakpoint in its
              get_count(), up to a stop address in its loop, and once its code
              changed after the scan
  scan      - _find_delay_routines: both builds, the gp offset read, both views
              hooked; not a copy whose calls go elsewhere, whose two calls
              differ, whose get_count() does more, a misaligned one, nor
              anything with delay_hle off
"""
import os
import struct
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from unicorn.mips_const import (UC_MIPS_REG_A0, UC_MIPS_REG_PC, UC_MIPS_REG_RA, UC_MIPS_REG_S0, UC_MIPS_REG_S1,
                                UC_MIPS_REG_S2, UC_MIPS_REG_S3, UC_MIPS_REG_SP, UC_MIPS_REG_T0, UC_MIPS_REG_T1,
                                UC_MIPS_REG_V0, UC_MIPS_REG_V1)
from simulator import AliMipsSimulator
from mips_asm import (A0, COMPARE, COUNT, ERET, GP, K0, K1, NOP, S0, S1, S2, S3, S4, SP, T0, T1, T5, T6, T7,
                      addiu, address_of, addu, b, li, load, mfc0, mtc0, subu, sw, timer_prologue)

DELAY = 0x80140000                  # the routine
GET_COUNT = 0x80140100
GP_VALUE, GP_OFF = 0x80158000, -0x7FF0
CLOCK = GP_VALUE + GP_OFF           # its CPU clock variable
STACK = 0x80380000
TICK_LOG, CALL_LOG = 0x80200000, 0x80280000
fails = []


def check(cond, msg):
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    if not cond:
        fails.append(msg)


def jal(target): return 0x0C000000 | (target >> 2) & 0x03FFFFFF


def routine(call=GET_COUNT, again=None, gp_off=GP_OFF):
    """delay(us): start = get_count(); wait until get_count() - start >=
    (us & 0xFFFF) * (clock * 0x431BDE83 >> 51)."""
    return [0x27BDFFE0, 0xAFBF0018, 0xAFB10014, 0xAFB00010,    # addiu sp, -32; sw ra / s1 / s0
            jal(call), 0x3090FFFF,                              # jal get_count; andi s0, a0, 0xffff
            0x00408821, 0x8F830000 | (gp_off & 0xFFFF),         # move s1, v0; lw v1, clock(gp)
            0x3C02431B, 0x3442DE83, 0x00620019, 0x00001810,     # li v0, 0x431BDE83; multu v1, v0; mfhi v1
            0x00031CC2, 0x72038002,                             # srl v1, 19; mul s0, s0, v1
            jal(call if again is None else again), NOP,         # loop: jal get_count
            0x00511023, 0x0050102B, 0x1440FFFB, 0x8FBF0018,     # subu v0, s1; sltu v0, s0; bnez loop; lw ra
            0x8FB10014, 0x8FB00010, 0x03E00008, 0x27BD0020]     # lw s1 / s0; jr ra; addiu sp, 32


def routine2(call=GET_COUNT, again=None, gp_off=GP_OFF):
    """The newer SDK's build: wait until get_count() - start > us * (clock *
    0x431BDE83 >> 51), the whole argument; the ticks in s2; v0 = 1 at the end."""
    return [0x27BDFFE0, 0xAFBF001C, 0xAFB20018, 0xAFB10014, 0xAFB00010,      # sw ra / s2 / s1 / s0
            jal(call), 0x00808021, 0x00408821,                              # move s0, a0; move s1, v0
            0x8F830000 | (gp_off & 0xFFFF), 0x3C02431B, 0x3442DE83,         # lw v1, clock(gp); li v0, K
            0x00620019, 0x00001810, 0x000394C2, 0x72509002,                 # multu; mfhi; srl s2, 19; mul s2, s0
            jal(call if again is None else again), NOP,                     # loop: jal get_count
            0x00401821, 0x0222102B, 0x10400006, 0x00711023, 0x0242102B,    # move v1, v0; sltu v0, s1, v0; ...
            0x14400007, 0x8FBF001C, 0x1000FFF6, NOP,                        # ... (now - start > ticks: out)
            0x2442FFFF, 0x0242102B, 0x1040FFF2, 0x8FBF001C,                 # (Count wrapped)
            0x8FB20018, 0x8FB10014, 0x8FB00010, 0x03E00008, 0x27BD0020]     # lw s2 / s1 / s0; jr ra


def routine3(call=GET_COUNT, again=None, gp_off=GP_OFF):
    """The newer SDK's bootloader's: the first build's loop, the ticks per
    microsecond from a variable of their own; v1 left alone."""
    return [0x27BDFFE0, 0xAFBF0018, 0xAFB10014, 0xAFB00010,    # addiu sp, -32; sw ra / s1 / s0
            jal(call), 0x3090FFFF, 0x00408821,                  # andi s0, a0, 0xffff; move s1, v0
            0x8F820000 | (gp_off & 0xFFFF), 0x72028002,         # lw v0, per_us(gp); mul s0, s0, v0
            jal(call if again is None else again), NOP,         # loop: jal get_count
            0x00511023, 0x0050102B, 0x1440FFFB, 0x8FBF0018,     # subu v0, s1; sltu v0, s0; bnez loop; lw ra
            0x8FB10014, 0x8FB00010, 0x03E00008, 0x27BD0020]     # lw s1 / s0; jr ra; addiu sp, 32


def routine4(call=GET_COUNT, again=None, gp_off=GP_OFF):
    """The newer SDK's SEE program's: the clock divided by 2,000,000 (DIVU),
    the ticks in s0, past them, v0 = 1."""
    return [0x27BDFFE0, 0xAFBF0018, 0xAFB10014, 0xAFB00010,    # addiu sp, -32; sw ra / s1 / s0
            jal(call), 0x00808021, 0x00408821,                  # move s0, a0; move s1, v0
            0x8F830000 | (gp_off & 0xFFFF), 0x3C02001E, 0x34428480,      # lw v1, clock(gp); li v0, 2000000
            0x0062001B, 0x004001F4, 0x00001812, NOP, NOP,       # divu v1, v0; teq v0, zero; mflo v1
            0x00700018, 0x00008012,                             # mult v1, s0; mflo s0
            jal(call if again is None else again), NOP,         # loop: jal get_count
            0x00401821, 0x0222102B, 0x10400006, 0x00711023, 0x0202102B, 0x14400007, 0x8FBF0018,
            0x1000FFF6, NOP, 0x2442FFFF, 0x0202102B, 0x1040FFF2, 0x8FBF0018,     # (as the newer build's)
            0x8FB10014, 0x8FB00010, 0x03E00008, 0x27BD0020]     # lw s1 / s0; jr ra; addiu sp, 32


GET_COUNT_CODE = [mfc0(2, COUNT)] + [NOP] * 5 + [0x03E00008, NOP]   # mfc0 v0, Count; ...; jr ra
GET_COUNT_CODE2 = [mfc0(2, COUNT), NOP, 0x000000C0] + [NOP] * 4 + [0x03E00008, NOP]   # (an EHB)
BUILDS = {1: (routine, GET_COUNT_CODE), 2: (routine2, GET_COUNT_CODE2), 3: (routine3, GET_COUNT_CODE),
          4: (routine4, GET_COUNT_CODE2)}
SETUP = li(GP, GP_VALUE) + li(SP, STACK)


def pack(words):
    return struct.pack(f"<{len(words)}I", *words)


def make(main, handler=None, clock=200_000_000, hle=True, build=1, **settings):
    """Timed slices from the start (as in a firmware run after its first ones)."""
    sim = AliMipsSimulator(log_handler=lambda m: None)
    sim.exact_count_threshold = 0
    sim.calibration_slices = 0
    sim.delay_hle = hle
    for name, value in settings.items():
        setattr(sim, name, value)
    code, get_count = BUILDS[build]
    sim.mu.mem_write(DELAY, pack(code()))
    sim.mu.mem_write(GET_COUNT, pack(get_count))
    # (the third build's variable holds the ticks per microsecond themselves)
    sim.mu.mem_write(CLOCK, struct.pack("<I", (clock * 0x431BDE83) >> 51 if build == 3 else clock))
    load(sim, main, handler)
    return sim


def call_once(us):
    """Registers set, Count read, delay(us), Count read again (t1: the ticks
    between), then `done`: a `b .` with interrupts off."""
    main = SETUP + li(S0, 0x11111111) + li(S1, 0x22222222) + li(S2, 0x44444444) + li(T0, 0x33333333) + \
        li(A0, us) + [mfc0(S4, COUNT), jal(DELAY), NOP, mfc0(T1, COUNT), subu(T1, T1, S4), b(-1), NOP]
    return main, address_of(main, len(main) - 2)


REGS = (("v0", UC_MIPS_REG_V0), ("v1", UC_MIPS_REG_V1), ("s0", UC_MIPS_REG_S0), ("s1", UC_MIPS_REG_S1),
        ("s2", UC_MIPS_REG_S2), ("sp", UC_MIPS_REG_SP), ("ra", UC_MIPS_REG_RA), ("a0", UC_MIPS_REG_A0),
        ("t0", UC_MIPS_REG_T0))


def run_to(sim, address, budget=200_000_000):
    sim.stop_instr = address
    sim.run(max_instructions=sim.instruction_count + budget)
    return sim.mu.reg_read(UC_MIPS_REG_PC)


def call(us, **settings):
    """Run call_once(us) to `done`: (sim, PC, registers, ticks between the reads)."""
    main, done = call_once(us)
    sim = make(main, **settings)
    pc = run_to(sim, done)
    return sim, pc, {n: sim.mu.reg_read(r) for n, r in REGS}, sim.mu.reg_read(UC_MIPS_REG_T1), done


def show(regs):
    return " ".join(f"{n} {v:X}" for n, v in regs.items())


print("--- entry")
sim, pc, regs, ticks, done = call(5)
_, npc, nregs, nticks, _ = call(5, hle=False)
native5 = nregs
check(pc == done and sim.delay_calls == 1 and sim.delay_jumps == 0 and abs(sim.delay_skipped - 5e-6) < 1e-12,
      f"delay(5) returned at once: {sim.delay_calls} call, {sim.delay_jumps} loop jumps, "
      f"{sim.delay_skipped * 1e6:.3f} us skipped (5 wanted)")
check(ticks >= 500, f"{ticks} Count ticks between the caller's reads (500 or more wanted; {nticks} when it runs)")
check(regs["v0"] == 0 and regs["v1"] == 100 and regs == nregs and npc == done,
      f"the registers as the routine leaves them: {show(regs)} (it: {show(nregs)})")
sim.delay_hle = False                       # (off after the scan: the hooks stand down)
sim.mu.reg_write(UC_MIPS_REG_PC, 0x80100000)
run_to(sim, done)
check(sim.delay_calls == 1 and sim.mu.reg_read(UC_MIPS_REG_T1) >= 500,
      f"delay_hle = False after the scan: it runs ({sim.delay_calls} call skipped in all)")

print("--- clock 0")
sim, pc, regs, ticks, done = call(5, clock=0)
_, _, nregs, _, _ = call(5, clock=0, hle=False)
check(pc == done and sim.delay_calls == 1 and sim.delay_skipped == 0 and regs == nregs and regs["v1"] == 0,
      f"no wait: {sim.delay_skipped} s skipped, {show(regs)} (it: {show(nregs)})")

print("--- loop")
t0 = time.perf_counter()
sim, pc, regs, ticks, done = call(50_000, batch_timeout_us=10_000)
took = time.perf_counter() - t0
_, _, nregs, nticks, _ = call(50_000, hle=False, batch_timeout_us=10_000)
check(pc == done and sim.delay_calls == 0 and sim.delay_jumps >= 5 and 0.045 <= sim.delay_skipped <= 0.0501,
      f"a 50 ms wait in 10 ms slices: {sim.delay_jumps} loop jumps, {sim.delay_skipped * 1e3:.2f} ms skipped "
      f"(set-up and run took {took * 1e3:.0f} ms of host time)")
check(ticks >= 5_000_000 and regs == nregs, f"{ticks} Count ticks (5,000,000 or more wanted; {nticks} when it "
      f"runs), registers {show(regs)} (it: {show(nregs)})")

print("--- newer build")


def but_v1(regs):
    return {n: v for n, v in regs.items() if n != "v1"}      # (v1: the last Count it read)


sim, pc, regs, ticks, done = call(5, build=2)
_, npc, nregs, nticks, _ = call(5, hle=False, build=2)
check(pc == done and sim.delay_calls == 1 and abs(sim.delay_skipped - 5.01e-6) < 1e-12 and ticks >= 501,
      f"delay(5) returned at once: {sim.delay_calls} call, {sim.delay_skipped * 1e6:.3f} us skipped (5.01 wanted: "
      f"past 500 ticks), {ticks} Count ticks between the reads ({nticks} when it runs)")
check(regs["v0"] == 1 and but_v1(regs) == but_v1(nregs) and npc == done,
      f"the registers as it leaves them: {show(regs)} (it: {show(nregs)})")
sim, pc, regs, ticks, done = call(50_000, build=2, batch_timeout_us=10_000)
_, _, nregs, nticks, _ = call(50_000, hle=False, build=2, batch_timeout_us=10_000)
check(pc == done and sim.delay_calls == 0 and sim.delay_jumps >= 5 and 0.045 <= sim.delay_skipped <= 0.0501
      and ticks > 5_000_000 and but_v1(regs) == but_v1(nregs),
      f"a 50 ms wait in 10 ms slices: {sim.delay_jumps} loop jumps, {sim.delay_skipped * 1e3:.2f} ms skipped, "
      f"{ticks} Count ticks ({nticks} when it runs), {show(regs)}")
sim, pc, regs, ticks, done = call(0x10000 + 10, build=2, batch_timeout_us=50_000)
check(pc == done and ticks > 6_554_600 and 0.06 < sim.delay_skipped < 0.065547,
      f"delay(65,546): the whole argument (65.5 ms, not 10 us), {ticks} Count ticks (over 6,554,600 wanted), "
      f"{sim.delay_skipped * 1e3:.2f} ms skipped")

print("--- bootloader build")
sim, pc, regs, ticks, done = call(5, build=3)
_, npc, nregs, nticks, _ = call(5, hle=False, build=3)
check(pc == done and sim.delay_calls == 1 and abs(sim.delay_skipped - 5e-6) < 1e-12 and ticks >= 500
      and regs == nregs and regs["v0"] == 0,
      f"delay(5) returned at once ({sim.delay_calls} call, {sim.delay_skipped * 1e6:.3f} us skipped), {ticks} "
      f"Count ticks ({nticks} when it runs), the registers as it leaves them -- v1 untouched: {show(regs)}")
sim, pc, regs, ticks, done = call(50_000, build=3, batch_timeout_us=10_000)
check(pc == done and sim.delay_jumps >= 5 and 0.045 <= sim.delay_skipped <= 0.0501 and ticks >= 5_000_000,
      f"a 50 ms wait in 10 ms slices: {sim.delay_jumps} loop jumps, {sim.delay_skipped * 1e3:.2f} ms skipped")

print("--- SEE build")
sim, pc, regs, ticks, done = call(5, build=4)
_, npc, nregs, nticks, _ = call(5, hle=False, build=4)
check(pc == done and sim.delay_calls == 1 and abs(sim.delay_skipped - 5.01e-6) < 1e-12 and ticks >= 501
      and regs["v0"] == 1 and but_v1(regs) == but_v1(nregs),
      f"delay(5) returned at once ({sim.delay_calls} call, {sim.delay_skipped * 1e6:.3f} us skipped: past 500 "
      f"ticks), {ticks} Count ticks ({nticks} when it runs), {show(regs)} (it: {show(nregs)})")
sim, pc, regs, ticks, done = call(50_000, build=4, batch_timeout_us=10_000)
check(pc == done and sim.delay_jumps >= 5 and 0.045 <= sim.delay_skipped <= 0.0501 and ticks > 5_000_000,
      f"a 50 ms wait in 10 ms slices: {sim.delay_jumps} loop jumps, {sim.delay_skipped * 1e3:.2f} ms skipped")


def ticking(us, seconds=0.3):
    """1 ms ticks (the handler logs how late each came, in Count ticks) while
    delay(us) is called over and over (each call's Count ticks logged)."""
    main = SETUP + li(T6, TICK_LOG) + li(T7, CALL_LOG) + timer_prologue(100_000, 100_000, 0x10008001)
    top = len(main)
    main += [mfc0(S4, COUNT)] + li(A0, us) + [jal(DELAY), NOP, mfc0(T1, COUNT), subu(T1, T1, S4), sw(T1, 0, T7),
                                              addiu(T7, T7, 4), addiu(S2, S2, 1)]
    main += [b(top - len(main) - 1), NOP]
    handler = [mfc0(K0, COUNT), mfc0(K1, COMPARE), subu(K0, K0, K1), sw(K0, 0, T6), addiu(T6, T6, 4),
               addiu(S3, S3, 1), mfc0(K0, COUNT), addu(K0, K0, T5), mtc0(K0, COMPARE), ERET, NOP]
    sim = make(main, handler)
    until = sim._vtime() + seconds
    while sim._vtime() < until:
        sim.run(max_instructions=sim.instruction_count + 5_000_000, max_vtime=until)
    n_ticks, n_calls = sim.mu.reg_read(UC_MIPS_REG_S3), sim.mu.reg_read(UC_MIPS_REG_S2)
    late = struct.unpack(f"<{n_ticks}I", sim.mu.mem_read(TICK_LOG, 4 * n_ticks))
    calls = struct.unpack(f"<{n_calls}I", sim.mu.mem_read(CALL_LOG, 4 * n_calls))
    return sim, late, calls


print("--- ticks")
for us in (1, 2500):
    sim, late, calls = ticking(us)
    check(250 <= len(late) <= 310 and max(late) < 50_000,
          f"delay({us}): {len(late)} ticks in 0.3 s (~300 wanted), the latest {max(late) / 100:.1f} us late "
          f"(under 500 wanted: fast mode's own is up to ~200, a jump past a tick would add up to 2,500)")
    check(len(calls) > 0 and min(calls) >= 100 * us,
          f"{len(calls)} calls, each {min(calls)} Count ticks or more ({100 * us} wanted; the longest {max(calls)})")
    if us == 1:
        check(sim.delay_calls >= 0.9 * len(calls), f"{sim.delay_calls} of them returned at their entry")
    else:
        check(sim.delay_jumps >= len(late), f"{sim.delay_jumps} loop jumps (a tick inside each wait or more)")

# 6 back-to-back delay(150) calls (900 us total > 500 us threshold) inside one timed slice
multi_prog = SETUP + li(S0, 0x11111111) + li(S1, 0x22222222) + [mfc0(S4, COUNT)]
for _ in range(6):
    multi_prog += li(A0, 150) + [jal(DELAY), NOP]
multi_prog += [mfc0(T1, COUNT), subu(T1, T1, S4), b(-1), NOP]
multi_done = address_of(multi_prog, len(multi_prog) - 2)
sim = make(multi_prog, batch_timeout_us=10_000)
pc = run_to(sim, multi_done)
multi_ticks = sim.mu.reg_read(UC_MIPS_REG_T1)
check(pc == multi_done and sim.delay_calls == 6 and abs(sim.delay_skipped - 900e-6) < 1e-12
      and multi_ticks >= 90_000 and sim.mu.reg_read(UC_MIPS_REG_V1) == 100,
      f"6x delay(150) in a timed slice: {sim.delay_calls} calls skipped ({sim.delay_skipped * 1e6:.0f} us), "
      f"{multi_ticks} Count ticks, v1={sim.mu.reg_read(UC_MIPS_REG_V1)}")

print("--- counted")
sim, pc, regs, ticks, done = call(5, exact_count_threshold=10 ** 12)
check(pc == done and sim.delay_calls == 1 and ticks >= 500 and regs["v1"] == 100,
      f"counted slices: delay(5) skipped ({sim.delay_calls} call, {ticks} ticks)")
sim, pc, regs, ticks, done = call(1000, exact_count_threshold=10 ** 12)
check(pc == done and sim.delay_calls == 0 and sim.delay_jumps == 0 and ticks >= 100_000,
      f"counted slices: delay(1000), 1 ms, more than delay_hle_max_s, runs ({sim.delay_calls} calls, "
      f"{sim.delay_jumps} loop jumps, {ticks} ticks)")

print("--- fallbacks")
sim, pc, regs, ticks, done = call(5, hook_every_instruction=True)
check(pc == done and sim.delay_calls == sim.delay_jumps == 0 and ticks >= 500 and regs == native5,
      f"exact mode: it runs ({sim.delay_calls} calls, {ticks} ticks, {show(regs)})")
main, done = call_once(5)
sim = make(main)
sim.breakpoints.add(GET_COUNT + 4)
sim.run(max_instructions=sim.instruction_count + 1_000_000)
pc = sim.mu.reg_read(UC_MIPS_REG_PC)
check(pc == GET_COUNT + 4 and sim.delay_calls == 0, f"a breakpoint in its get_count(): stopped at 0x{pc:08X}")
sim = make(main)
pc = run_to(sim, DELAY + 64)
check(pc == DELAY + 64 and sim.delay_calls == sim.delay_jumps == 0,
      f"the stop address in its loop: stopped at 0x{pc:08X}")
sim = make(main)
run_to(sim, done)
sim.mu.mem_write(DELAY + 60, pack([0x00000021]))   # (another nop)
sim.mu.reg_write(UC_MIPS_REG_PC, 0x80100000)
pc = run_to(sim, done)
check(pc == done and sim.delay_calls == 1 and sim.mu.reg_read(UC_MIPS_REG_T1) >= 500,
      f"its code changed after the scan: it runs ({sim.delay_calls} call skipped, the first)")

print("--- scan")


def scan(data, base=0x00140000, hle=True, get_count=GET_COUNT_CODE):
    sim = AliMipsSimulator(log_handler=lambda m: None)
    sim.delay_hle = hle
    sim.mu.mem_write(GET_COUNT, pack(get_count))
    sim._find_delay_routines(data, base, (0x80000000, 0xA0000000))
    return sim


for build, (code, get_count) in BUILDS.items():
    sim = scan(pack(code()) + bytes(64), get_count=get_count)
    found = sim._delay_routines.get(DELAY, (None,) * 4)
    check(sorted(sim._delay_hooks) == [DELAY, DELAY | 0x20000000] and found[1:] == (GP_OFF, GET_COUNT, build - 1),
          f"build {build}: found in both views ({[hex(a) for a in sorted(sim._delay_hooks)]}), gp offset "
          f"{found[1]:#x}, get_count() at 0x{found[2]:08X}, build index {found[3]}")
for what, data, hle, get_count in (
        ("calls going elsewhere", pack(routine(call=GET_COUNT + 0x40)), True, GET_COUNT_CODE),
        ("two calls that differ", pack(routine(again=GET_COUNT + 0x40)), True, GET_COUNT_CODE),
        ("the newer build's two calls differing", pack(routine2(again=GET_COUNT + 0x40)), True, GET_COUNT_CODE2),
        ("a get_count() with another instruction", pack(routine2()), True,
         [mfc0(2, COUNT), NOP, addiu(2, 2, 1)] + [NOP] * 4 + [0x03E00008, NOP]),
        ("a misaligned copy", b"\0\0" + pack(routine()), True, GET_COUNT_CODE),
        ("delay_hle off", pack(routine()), False, GET_COUNT_CODE)):
    sim = scan(data, hle=hle, get_count=get_count)
    check(not sim._delay_hooks, f"{what}: nothing hooked ({len(sim._delay_hooks)})")

print()
if fails:
    print(f"\033[91m{len(fails)} delay check(s) failed\033[0m")
    sys.exit(1)
print("\033[92mAll delay checks passed\033[0m")
