"""
Test: the CP0 timer interrupt (Count/Compare -> Cause.TI / IP7).

Unicorn's MIPS timer is compiled out, so the simulator latches Cause.TI/IP7
itself when Count passes Compare, clears it on MTC0 Compare and delivers the
interrupt (EPC, Cause.ExcCode=0, Status.EXL, vector 0x80000180) when
Status has IE=1, EXL=0, ERL=0 and IM7=1.  Small MIPS32/MIPS16 programs in RAM
check it in three modes: exact (per-instruction hook, as the GUI), fast with
counted slices (small budgets right after start-up) and fast with timed slices
(what firmware runs use):

  periodic    - the handler at 0x80000180 runs periodically, sees IP7+TI and
                ExcCode 0, EPC is never a branch delay slot, ERET returns;
                timed slices: the tick rate follows Count/Compare
  masked      - with IM7=0 IP7 is latched (visible in Cause) but not taken;
                setting IM7 delivers it
  no_edge     - Count=0 then Compare=0 (ali_sdk.bin) does not latch IP7
  mips16      - EPC carries the ISA bit; ERET returns to the MIPS16 loop
  m16_selfloop- a MIPS16 `b .` loop (a hook cannot redirect the PC there)
                still takes the interrupt
  vector_iv   - Cause.IV=1 moves the vector to 0x80000200
  continuity  - alternating step() and run() does not make Count jump into a
                far-away Compare
  disabled    - sim.timer_enabled = False: no timer interrupts; turning it on
                again resumes them
  software    - MTC0 Cause IP0 with IM0 raises a software interrupt
  step_noirq  - step() executes the instruction even when an interrupt is
                pending; the next run() takes it
  breakpoint  - resuming from a breakpoint while ticks are due gets past it
  short_period- a tick period shorter than the handler (fast mode: host
                time of the CP0 hooks) does not starve the interrupted code
  late        - (exact) a handler that writes Compare after Count passed it
                gets the next tick at once instead of after a Count wrap
  uart_delay  - (exact) timer ERETs do not bring a setUartReceiveData()
                delay forward
  replay_tx/rx- (timed, native stopper and Unicorn timeout) an asynchronous
                slice stop re-executes the last load/store on resume; UART TX
                characters are not duplicated and RX bytes are not lost (TX
                also with the store in the middle of a translation block,
                from MIPS16 code, plain and EXTENDed, and two identical stores
                in consecutive blocks with a pause between them)
  shared_putc - the same with the timer ISR printing through the same putc
  false_rewind- (exact) a stop *before* a later pass of a store is not taken
                for a rewind (no character dropped)
  counted_external_stop - emu_stop() from the UART callback during the
                start-up counted slices does not duplicate a character
  ds_warning  - a device register store in a branch delay slot runs once (mmio_map);
                a flash-window store there (Unicorn bug) is reported
"""
import struct
import sys
import time

from simulator import AliMipsSimulator
from unicorn.mips_const import (UC_MIPS_REG_PC, UC_MIPS_REG_S0, UC_MIPS_REG_S1, UC_MIPS_REG_S2,
                                UC_MIPS_REG_S4, UC_MIPS_REG_S6, UC_MIPS_REG_S7, UC_MIPS_REG_V0)

# registers
ZERO, T1, T2, T3, T4, T5 = 0, 9, 10, 11, 12, 13
S0, S1, S2, S4, S5, S6, S7, K0, K1 = 16, 17, 18, 20, 21, 22, 23, 26, 27
COUNT, COMPARE, STATUS, CAUSE, EPC = 9, 11, 12, 13, 14


def mfc0(rt, rd): return 0x40000000 | rt << 16 | rd << 11
def mtc0(rt, rd): return 0x40800000 | rt << 16 | rd << 11
def addiu(rt, rs, imm): return 0x24000000 | rs << 21 | rt << 16 | (imm & 0xFFFF)
def addu(rd, rs, rt): return 0x00000021 | rs << 21 | rt << 16 | rd << 11
def orr(rd, rs, rt): return 0x00000025 | rs << 21 | rt << 16 | rd << 11
def lui(rt, imm): return 0x3C000000 | rt << 16 | (imm & 0xFFFF)
def ori(rt, rs, imm): return 0x34000000 | rs << 21 | rt << 16 | (imm & 0xFFFF)
def andi(rt, rs, imm): return 0x30000000 | rs << 21 | rt << 16 | (imm & 0xFFFF)
def sw(rt, off, base): return 0xAC000000 | base << 21 | rt << 16 | (off & 0xFFFF)
def beq(rs, rt, off): return 0x10000000 | rs << 21 | rt << 16 | (off & 0xFFFF)
def b(off): return beq(ZERO, ZERO, off)
def jalx(target): return 0x74000000 | ((target >> 2) & 0x03FFFFFF)
ERET, NOP = 0x42000018, 0x00000000

VECTOR = 0x80000180
VECTOR_IV = 0x80000200
MAIN = 0x80100000
M16_LOOP = 0x80100100
EPC_LOG = 0x80200000

MODES = ('exact', 'fast', 'timed')


def handler(delay_nops=0, clear_cause=True, counter=S1):
    """Counts interrupts in `counter`, keeps the last Cause in s2, logs EPCs at
    [s4++], clears software interrupts (and IV) and sets Compare = Count + t5."""
    return [mfc0(K0, CAUSE), orr(S2, K0, ZERO),
            mfc0(K1, EPC), sw(K1, 0, S4), addiu(S4, S4, 4),
            addiu(counter, counter, 1)] + \
           ([mtc0(ZERO, CAUSE)] if clear_cause else []) + \
           [mfc0(K0, COUNT), addu(K0, K0, T5)] + [NOP] * delay_nops + \
           [mtc0(K0, COMPARE), ERET, NOP]


def li(rt, value):
    return [lui(rt, value >> 16), ori(rt, rt, value & 0xFFFF)]


def prologue(period, first, status):
    return [lui(S4, EPC_LOG >> 16)] + li(T5, period) + [mtc0(ZERO, COUNT)] + li(T1, first) + \
           [mtc0(T1, COMPARE)] + li(T2, status) + [mtc0(T2, STATUS)]


PROLOGUE_LEN = len(prologue(0, 0, 0))


def period(mode):
    """Exact mode: 2000 Count ticks = 1000 instructions.  Fast modes: Count runs
    at 100 MHz and a hooked CP0 instruction costs ~50 us of host time, so use a
    10 ms period (the firmware's tick is 337500 ticks = 3.4 ms)."""
    return 2000 if mode == 'exact' else 0x100000


def idle_loop():
    # loop: addiu s0,s0,1 ; b loop ; addiu s5,s5,1 (delay slot)
    return [addiu(S0, S0, 1), b(-2), addiu(S5, S5, 1)]


def check(cond, msg, fails):
    print(("  PASS " if cond else "  FAIL ") + msg)
    if not cond:
        fails.append(msg)


def make_sim(mode, main, vector_code, extra=None):
    sim = AliMipsSimulator(log_handler=lambda m: None)
    sim.hook_every_instruction = mode == 'exact'
    if mode == 'timed':
        sim.exact_count_threshold = 0       # timed slices from the start
        sim.calibration_slices = 0
    sim.mu.mem_write(VECTOR, struct.pack(f'<{len(vector_code)}I', *vector_code))
    sim.mu.mem_write(MAIN, struct.pack(f'<{len(main)}I', *main))
    for addr, blob in (extra or {}).items():
        sim.mu.mem_write(addr, blob)
    sim.mu.reg_write(UC_MIPS_REG_PC, MAIN)
    return sim


def run_until(sim, mode, insns, cond=lambda s: False, wall=5.0):
    """Exact mode: run exactly insns instructions.  Fast modes: run slices
    until cond(sim) holds or `wall` seconds passed."""
    if mode == 'exact':
        sim.run(max_instructions=sim.instruction_count + insns)
        return
    t0 = time.time()
    while time.time() - t0 < wall and not cond(sim):
        sim.run(max_instructions=sim.instruction_count + 200_000)


def ticks(sim):
    return sim.mu.reg_read(UC_MIPS_REG_S1)


def epcs(sim):
    n = (sim.mu.reg_read(UC_MIPS_REG_S4) - EPC_LOG) // 4
    return list(struct.unpack(f'<{n}I', bytes(sim.mu.mem_read(EPC_LOG, 4 * n)))) if n > 0 else []


def check_slices(sim, mode, fails):
    if mode == 'timed':
        check(sim._timeout_slices > 0, f"ran timed slices ({sim._timeout_slices})", fails)


def scenario_periodic(mode, fails):
    p = period(mode)
    main = prologue(p, p, 0x10008001) + idle_loop()
    sim = make_sim(mode, main, handler())
    v0 = sim._vtime()
    run_until(sim, mode, 20_000, lambda s: ticks(s) >= 5 and s._vtime() - v0 > 0.5)
    n = ticks(sim)
    cause = sim.mu.reg_read(UC_MIPS_REG_S2)
    loop = MAIN + 4 * PROLOGUE_LEN
    if mode == 'exact':
        # 2 Count ticks per instruction: one tick per ~1000 instructions
        check(15 <= n <= 21, f"exact: ~1 tick per 1000 instructions (ticks={n})", fails)
    else:
        check(n >= 5, f"timer interrupts delivered (ticks={n})", fails)
    if mode == 'timed':
        ideal = (sim._vtime() - v0) * sim.count_hz / p
        kind = type(sim._stopper).__name__ if sim._stopper else "Unicorn timeout"
        floor = 0.3 if sim._stopper else 0.05
        check(n >= floor * ideal, f"tick rate follows Count/Compare: {n} ticks, ideal {ideal:.0f} "
                                  f"(stopper: {kind}, floor {floor:.0%})", fails)
    check(cause & 0x40008000 == 0x40008000, f"Cause at entry has TI and IP7 (0x{cause:08X})", fails)
    check(cause & 0x7C == 0, "Cause.ExcCode = 0 (interrupt)", fails)
    e = epcs(sim)
    check(e and all(x in (loop, loop + 4) for x in e),
          f"every EPC is in the loop and never its delay slot 0x{loop + 8:08X} "
          f"({sorted(set(hex(x) for x in e))})", fails)
    check(sim.mu.reg_read(UC_MIPS_REG_S0) > 0, "the main loop runs between interrupts", fails)
    check(sim.timer_irq_count == n, f"timer_irq_count matches ({sim.timer_irq_count})", fails)
    check_slices(sim, mode, fails)


def scenario_masked(mode, fails):
    main = prologue(period(mode), 200, 0x10000001) + [
        mfc0(T3, CAUSE), andi(T4, T3, 0x8000), beq(T4, ZERO, -3), NOP,   # poll Cause.IP7
        orr(S6, T3, ZERO), orr(S7, S1, ZERO),                               # Cause seen, ticks so far
        ori(T2, T2, 0x8000), mtc0(T2, STATUS)] + idle_loop()                # unmask IM7
    sim = make_sim(mode, main, handler())
    run_until(sim, mode, 5_000, lambda s: ticks(s) >= 1)
    s6, s7 = sim.mu.reg_read(UC_MIPS_REG_S6), sim.mu.reg_read(UC_MIPS_REG_S7)
    check(s6 & 0x40008000 == 0x40008000, f"masked IP7 is latched and visible in Cause (0x{s6:08X})", fails)
    check(s7 == 0, "no interrupt while IM7 = 0", fails)
    check(ticks(sim) >= 1, "setting IM7 delivers the pending interrupt", fails)
    check_slices(sim, mode, fails)


def scenario_no_edge(mode, fails):
    main = [mtc0(ZERO, COUNT), mtc0(ZERO, COMPARE), lui(T2, 0x1000), ori(T2, T2, 0x8001),
            mtc0(T2, STATUS), mfc0(S6, CAUSE), addiu(S0, S0, 1), b(-3), NOP]
    sim = make_sim(mode, main, handler())
    run_until(sim, mode, 50_000, wall=1.0)
    s6 = sim.mu.reg_read(UC_MIPS_REG_S6)
    check(ticks(sim) == 0, "Count=0 then Compare=0: no timer interrupt", fails)
    check(s6 & 0x40008000 == 0, f"Cause stays without TI/IP7 (0x{s6:08X})", fails)


JALX_PC = MAIN + 4 * PROLOGUE_LEN


def loop_epcs(sim, mode):
    """EPCs of interrupts taken in the MIPS16 loop.  Fast modes: Count follows
    host time, so a host stall in the prologue can legitimately deliver the
    first tick at the JALX (MIPS32) before the loop is entered."""
    e = epcs(sim)
    return [x for x in e if not (mode != 'exact' and x == JALX_PC)]


def scenario_mips16(mode, fails):
    p = period(mode)
    main = prologue(p, p, 0x10008001) + [jalx(M16_LOOP), NOP]
    m16 = struct.pack('<2H', 0x4A01, 0x17FE)    # L: addiu v0,1 ; b L
    sim = make_sim(mode, main, handler(), {M16_LOOP: m16})
    run_until(sim, mode, 20_000, lambda s: len(loop_epcs(s, mode)) >= 5)
    e = loop_epcs(sim, mode)
    check(len(e) >= 3, f"interrupts taken in the MIPS16 loop ({len(e)})", fails)
    # an interrupt is never injected before the MIPS16 branch at L+2 in exact mode
    allowed = (M16_LOOP,) if mode == 'exact' else (M16_LOOP, M16_LOOP + 2)
    check(e and all(x & 1 and (x & ~1) in allowed for x in e),
          f"EPC carries the MIPS16 bit ({sorted(set(hex(x) for x in e))})", fails)
    in_loop = lambda: sim.mu.reg_read(UC_MIPS_REG_PC) in (M16_LOOP, M16_LOOP + 2)
    if mode != 'exact':
        # a timed / counted slice can end inside the handler (before its ERET):
        # run on until the CPU is back in the loop (a few short runs at most)
        for _ in range(50):
            if in_loop():
                break
            sim.run(max_instructions=sim.instruction_count + 50)
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    v0 = sim.mu.reg_read(UC_MIPS_REG_V0)
    check(sim.is_mips16_mode() and pc in (M16_LOOP, M16_LOOP + 2) and v0 > 0,
          f"ERET returned to the MIPS16 loop (PC=0x{pc:08X}, v0={v0})", fails)


def scenario_m16_selfloop(mode, fails):
    p = period(mode)
    main = prologue(p, p, 0x10008001) + [jalx(M16_LOOP), NOP]
    m16 = struct.pack('<H', 0x17FF)             # L: b L  (a hook PC write faults here)
    sim = make_sim(mode, main, handler(), {M16_LOOP: m16})
    run_until(sim, mode, 20_000, lambda s: len(loop_epcs(s, mode)) >= 3)
    e = loop_epcs(sim, mode)
    check(len(e) >= 3 and all(x == M16_LOOP | 1 for x in e),
          f"MIPS16 `b .` loop takes interrupts with EPC=0x{M16_LOOP | 1:08X} ({len(e)}, "
          f"{sorted(set(hex(x) for x in e))})", fails)


def scenario_vector_iv(mode, fails):
    p = period(mode)
    main = [lui(T1, 0x0080), mtc0(T1, CAUSE)] + prologue(p, p, 0x10008001) + idle_loop()
    wrong = [addiu(S7, S7, 1), ERET, NOP]      # at 0x80000180: must not be used
    iv_handler = handler(clear_cause=False)
    sim = make_sim(mode, main, wrong, {VECTOR_IV: struct.pack(f'<{len(iv_handler)}I', *iv_handler)})
    run_until(sim, mode, 10_000, lambda s: ticks(s) >= 3)
    check(ticks(sim) >= 3 and sim.mu.reg_read(UC_MIPS_REG_S7) == 0,
          f"Cause.IV=1: vector 0x80000200 ({ticks(sim)} interrupts, "
          f"{sim.mu.reg_read(UC_MIPS_REG_S7)} at 0x80000180)", fails)


def scenario_continuity(mode, fails):
    # Compare far away (2^30 Count ticks); stepping switches the Count formula
    main = prologue(period(mode), 0x40000000, 0x10008001) + idle_loop()
    sim = make_sim(mode, main, handler())
    for _ in range(4):
        run_until(sim, mode, 3_000, wall=0.3)
        for _ in range(3):
            sim.step()
    run_until(sim, mode, 3_000, wall=0.3)
    check(ticks(sim) == 0 and not sim._ti,
          "step()/run() alternation causes no spurious timer interrupt", fails)


def scenario_disabled(mode, fails):
    p = period(mode)
    main = prologue(p, p, 0x10008001) + idle_loop()
    sim = make_sim(mode, main, handler())
    sim.timer_enabled = False
    run_until(sim, mode, 20_000, wall=0.5)
    check(ticks(sim) == 0 and sim.mu.reg_read(UC_MIPS_REG_S0) > 0,
          "timer_enabled = False: no timer interrupts", fails)
    sim.timer_enabled = True
    run_until(sim, mode, 20_000, lambda s: ticks(s) >= 2)
    check(ticks(sim) >= 2, f"timer_enabled = True again: ticks resume ({ticks(sim)})", fails)


def scenario_software(mode, fails):
    main = [lui(S4, EPC_LOG >> 16), lui(T2, 0x1000), ori(T2, T2, 0x0101), mtc0(T2, STATUS),
            addiu(T1, ZERO, 0x100), mtc0(T1, CAUSE)] + idle_loop()
    sim = make_sim(mode, main, handler())
    run_until(sim, mode, 2_000, lambda s: ticks(s) >= 1)
    s1, s2 = ticks(sim), sim.mu.reg_read(UC_MIPS_REG_S2)
    check(s1 == 1 and s2 & 0x100, f"software interrupt IP0 taken once (count={s1}, Cause=0x{s2:08X})", fails)


def scenario_step_noirq(mode, fails):
    # IP7 latched while masked, then step over the MTC0 that unmasks it
    main = prologue(period(mode), 200, 0x10000001) + [
        mfc0(T3, CAUSE), andi(T4, T3, 0x8000), beq(T4, ZERO, -3), NOP,
        ori(T2, T2, 0x8000), mtc0(T2, STATUS)] + idle_loop()
    sim = make_sim(mode, main, handler())
    unmask = MAIN + 4 * (PROLOGUE_LEN + 5)
    sim.stop_instr = unmask
    run_until(sim, mode, 5_000, lambda s: s.mu.reg_read(UC_MIPS_REG_PC) == unmask)
    sim.stop_instr = None
    pc0 = sim.mu.reg_read(UC_MIPS_REG_PC)
    r1 = sim.step()                             # mtc0 Status: IM7 on -> interrupt deliverable
    r2 = sim.step()                             # must execute addiu s0, not enter the vector
    check(pc0 == unmask and r1.next_pc == unmask + 4 and r2.next_pc == unmask + 8 and ticks(sim) == 0,
          f"step() executes instructions with an interrupt pending "
          f"(0x{pc0:08X} -> 0x{r1.next_pc:08X} -> 0x{r2.next_pc:08X})", fails)
    run_until(sim, mode, 100, lambda s: ticks(s) >= 1)
    check(ticks(sim) >= 1, "the next run() takes the pending interrupt", fails)


def scenario_breakpoint(mode, fails):
    # a tick is due at (almost) every resume: 16 Count ticks = 8 instructions
    # (exact), 2000 ticks = 20 us (fast)
    p = 16 if mode == 'exact' else 2000
    main = prologue(p, p, 0x10008001) + idle_loop()
    sim = make_sim(mode, main, handler())
    loop = MAIN + 4 * PROLOGUE_LEN
    sim.addBreakpoint(loop)
    run_until(sim, mode, 1_000, lambda s: s.mu.reg_read(UC_MIPS_REG_PC) == loop)   # first arrival
    progressed = 0
    for _ in range(25):
        before = sim.mu.reg_read(UC_MIPS_REG_S0)
        if mode == 'exact':
            sim.run(max_instructions=sim.instruction_count + 50_000)
        else:
            sim.run(max_instructions=sim.instruction_count + 5_000_000)
        if sim.mu.reg_read(UC_MIPS_REG_S0) > before:
            progressed += 1
    check(progressed == 25 and ticks(sim) >= 5,
          f"every resume from the breakpoint gets past it ({progressed}/25, ticks={ticks(sim)})", fails)


def scenario_short_period(mode, fails):
    # Fast modes: a 20 us period is shorter than the handler's host time
    # (hooked CP0 instructions), so a tick is due at every ERET; the
    # interrupted code must still run (irq_min_gap_us).
    p = 40 if mode == 'exact' else 2000
    main = prologue(p, p, 0x10008001) + idle_loop()
    sim = make_sim(mode, main, handler())
    want = 10 if mode == 'fast' else 50     # counted slices are not paced by the timer
    run_until(sim, mode, 20_000, lambda s: ticks(s) >= want and s.mu.reg_read(UC_MIPS_REG_S0) > 1000, wall=3.0)
    s0 = sim.mu.reg_read(UC_MIPS_REG_S0)
    check(ticks(sim) >= want and s0 > 1000,
          f"ticks faster than the handler: the interrupted loop still runs (ticks={ticks(sim)}, loop={s0})", fails)


T6 = 14
def lbu(rt, off, base): return 0x90000000 | base << 21 | rt << 16 | (off & 0xFFFF)
def sb(rt, off, base): return 0xA0000000 | base << 21 | rt << 16 | (off & 0xFFFF)
RX_BUF = 0x80300000


def replay_sim(kind, body):
    """Timed fast mode with the firmware's tick (337500 Count ticks = 3.4 ms):
    hundreds of asynchronous slice stops per second, many inside device hooks."""
    main = prologue(337500, 337500, 0x10008001) + li(T6, 0xB8018300) + body
    sim = make_sim('timed', main, handler())
    sim.slice_stopper = kind
    return sim


def scenario_replay_tx(kind, fails, mid_block=False, sim_hook=None):
    # L: sb s0,0(t6) (UART THR) ; addiu s0,1 ; b L ; nop
    # mid_block: L: addiu t3,t3,1 ; addu t4,t3,s0 ; sb ... -- the store is not the
    # first instruction of its translation block, where Unicorn's PC (as seen by
    # an mmio_map callback) is the block start, not the store (dump_maciej's
    # putc printed 'viic.wang' before the rewind check used the stop PC)
    body = [sb(S0, 0, T6), addiu(S0, S0, 1), b(-3), NOP]
    if mid_block:
        body = [addiu(T3, T3, 1), addu(T4, T3, S0), sb(S0, 0, T6), addiu(S0, S0, 1), b(-5), NOP]
    sim = replay_sim(kind, body)
    if sim_hook:
        sim_hook(sim)
    out = []
    sim.setUartHandler(lambda c: out.append(ord(c)))
    t0 = time.time()
    while time.time() - t0 < 2.0:
        sim.run(max_instructions=sim.instruction_count + 2_000_000)
    bad = sum(1 for a, b_ in zip(out, out[1:]) if (b_ - a) & 0xFF != 1)
    check(len(out) > 1000 and bad == 0 and ticks(sim) >= 5,
          f"[{kind}{', store mid-block' if mid_block else ''}] UART TX under async stops: {len(out)} chars, "
          f"{bad} duplicated/skipped, {ticks(sim)} ticks, {sim._timeout_slices} slices", fails)


def scenario_replay_tx_pairs(kind, fails, sim_hook=None):
    # L: sb s0,0(t6) ; b M ; nop ; M: sb s0,0(t6) ; addiu s0,1 ; b L ; nop
    # Two identical stores (same address, data and registers) in consecutive
    # translation blocks.  A user code hook pauses the CPU right before M on
    # every 5th pass (like a GUI pause): that stop, after the first store, must
    # not be taken for a rewind of the second one, which would then be skipped
    # as a 'replay'.  Every value must come out exactly twice.
    from unicorn import UC_HOOK_CODE
    sim = replay_sim(kind, [sb(S0, 0, T6), b(1), NOP, sb(S0, 0, T6), addiu(S0, S0, 1), b(-6), NOP])
    m_addr = MAIN + 4 * (PROLOGUE_LEN + 2 + 3)
    visits = [0]

    def pause(uc, address, size, user_data):
        visits[0] += 1
        if visits[0] % 5 == 0:
            sim.mu.emu_stop()
    sim.mu.hook_add(UC_HOOK_CODE, pause, begin=m_addr, end=m_addr)
    if sim_hook:
        sim_hook(sim)
    out = []
    sim.setUartHandler(lambda c: out.append(ord(c)))
    t0 = time.time()
    while time.time() - t0 < 2.0:
        sim.run(max_instructions=sim.instruction_count + 2_000_000)
    n = len(out) // 2 * 2
    bad = sum(1 for i in range(0, n, 2) if out[i] != out[i + 1] or (i and (out[i] - out[i - 1]) & 0xFF != 1))
    # (throughput depends on the stopper and the host load: 'unicorn' restarts
    # are slow; the real assertion is bad == 0 over enough pauses)
    check(len(out) > 100 and visits[0] >= 100 and bad == 0,
          f"[{kind}, identical stores in consecutive blocks] UART TX with {visits[0] // 5} pauses before the "
          f"second store and async stops: {len(out)} chars, {bad} pairs wrong (dropped / duplicated), "
          f"{ticks(sim)} ticks", fails)


def scenario_replay_tx_m16(kind, fails, extended, sim_hook=None):
    # The same from MIPS16 code (the bootloaders' device code is MIPS16):
    # L: addiu a0,1 ; sb v0,0(v1)  (or EXTEND sb v0,0x300(v1)) ; addiu v0,1 ; b L
    base, store = (0xB8018000, [0xF300, 0xC340]) if extended else (0xB8018300, [0xC340])
    m16 = [0x4C01] + store + [0x4A01]
    m16 += [0x1000 | ((-(2 * len(m16) + 4) // 2) & 0x7FF)]      # b L (MIPS16 B: no delay slot)
    main = prologue(337500, 337500, 0x10008001) + li(3, base) + [addiu(2, ZERO, 0), jalx(M16_LOOP), NOP]
    sim = make_sim('timed', main, handler(), {M16_LOOP: struct.pack(f'<{len(m16)}H', *m16)})
    sim.slice_stopper = kind
    if sim_hook:
        sim_hook(sim)
    out = []
    sim.setUartHandler(lambda c: out.append(ord(c)))
    t0 = time.time()
    while time.time() - t0 < 2.0:
        sim.run(max_instructions=sim.instruction_count + 2_000_000)
    bad = sum(1 for a, b_ in zip(out, out[1:]) if (b_ - a) & 0xFF != 1)
    check(len(out) > 1000 and bad == 0 and ticks(sim) >= 5,
          f"[{kind}, MIPS16{' EXTEND' if extended else ''} store mid-block] UART TX under async stops: "
          f"{len(out)} chars, {bad} duplicated/skipped, {ticks(sim)} ticks", fails)


def scenario_replay_rx(kind, fails):
    # poll LSR.DR, copy URBR to RX_BUF[s6++]
    body = li(S6, RX_BUF) + [lbu(T3, 5, T6), andi(T3, T3, 1), beq(T3, ZERO, -3), NOP,
                             lbu(T4, 0, T6), sb(T4, 0, S6), addiu(S6, S6, 1), b(-8), NOP]
    sim = replay_sim(kind, body)
    data = bytes(i & 0xFF for i in range(3000))
    sim.setUartReceiveData(data, delay_instructions=0)
    sim._pending_uart_irq = False                # polled: no RX interrupt
    sim.log_callback = lambda m: None
    t0 = time.time()
    while time.time() - t0 < 10.0 and sim.mu.reg_read(UC_MIPS_REG_S6) - RX_BUF < len(data):
        sim.run(max_instructions=sim.instruction_count + 2_000_000)
    n = sim.mu.reg_read(UC_MIPS_REG_S6) - RX_BUF
    got = bytes(sim.mu.mem_read(RX_BUF, max(0, min(n, len(data)))))
    check(got == data, f"[{kind}] UART RX under async stops: {n}/{len(data)} bytes copied, "
                       f"{'identical' if got == data else 'LOST/REORDERED bytes'}, {ticks(sim)} ticks", fails)


A0, SP_, RA = 4, 29, 31
def lw(rt, off, base): return 0x8C000000 | base << 21 | rt << 16 | (off & 0xFFFF)
def jal(target): return 0x0C000000 | ((target >> 2) & 0x03FFFFFF)
def jr(rs): return 0x00000008 | rs << 21
PUTC = 0x80100200


def scenario_false_rewind(fails):
    # Exact mode, deterministic: a user hook stops the CPU *before* every 7th
    # pass of the THR store (like a GUI pause).  That is not a rewind: no
    # character may be dropped (or printed twice).
    from unicorn import UC_HOOK_CODE
    main = prologue(2000, 0x40000000, 0x10000001) + li(T6, 0xB8018300) + \
        [sb(S0, 0, T6), addiu(S1, S1, 1), b(-3), NOP]          # same char every pass; s1 counts
    sim = make_sim('exact', main, handler())
    store = MAIN + 4 * (PROLOGUE_LEN + 2)
    out = []
    sim.setUartHandler(lambda c: out.append(c))
    visits = [0]

    def pause(uc, address, size, user_data):
        visits[0] += 1
        if visits[0] % 7 == 0:
            sim.mu.emu_stop()
    sim.mu.hook_add(UC_HOOK_CODE, pause, begin=store, end=store)
    for _ in range(200):
        sim.run(max_instructions=sim.instruction_count + 200)
    stores = sim.mu.reg_read(UC_MIPS_REG_S1)
    check(abs(len(out) - stores) <= 1 and len(out) > 100,
          f"stops before a pass are not taken for rewinds: {len(out)} chars for {stores} stores "
          f"({visits[0] // 7} pauses)", fails)


def scenario_shared_putc(kind, fails):
    # Timed, firmware tick: the main loop and the timer ISR print through the
    # same PUTC; a rewound main store must not be taken by the ISR's store.
    putc = [sb(A0, 0, T6), jr(RA), NOP]
    isr = [mfc0(K0, CAUSE), addiu(S1, S1, 1),
           addiu(SP_, SP_, -8), sw(RA, 0, SP_), sw(A0, 4, SP_),
           addiu(A0, ZERO, 0x80), jal(PUTC), NOP,
           lw(RA, 0, SP_), lw(A0, 4, SP_), addiu(SP_, SP_, 8),
           mfc0(K0, COUNT), addu(K0, K0, T5), mtc0(K0, COMPARE), ERET, NOP]
    body = li(SP_, 0x80400000) + [andi(A0, S0, 0x7F), jal(PUTC), NOP, addiu(S0, S0, 1), b(-5), NOP]
    main = prologue(337500, 337500, 0x10008001) + li(T6, 0xB8018300) + body
    sim = make_sim('timed', main, isr, {PUTC: struct.pack('<3I', *putc)})
    sim.slice_stopper = kind
    out = []
    sim.setUartHandler(lambda c: out.append(ord(c)))
    t0 = time.time()
    while time.time() - t0 < 2.0:
        sim.run(max_instructions=sim.instruction_count + 2_000_000)
    main_chars = [c for c in out if c < 0x80]
    bad = sum(1 for a, b_ in zip(main_chars, main_chars[1:]) if (b_ - a) & 0x7F != 1)
    isr_chars = len(out) - len(main_chars)
    # (isr_chars only shows the ISR ran: the Unicorn-timeout fallback ticks
    # slowly, and slower still on a loaded host)
    check(len(main_chars) > 1000 and isr_chars >= 5 and bad == 0,
          f"[{kind}] putc shared with the ISR: {len(main_chars)} main chars, {bad} duplicated/skipped, "
          f"{isr_chars} ISR chars", fails)


def scenario_counted_external_stop(fails):
    # Fast mode right after start-up (counted calibration slices): a UART
    # callback that calls emu_stop() inside the THR hook rewinds the store.
    main = prologue(2000, 0x40000000, 0x10000001) + li(T6, 0xB8018300) + \
        [sb(S0, 0, T6), addiu(S0, S0, 1), b(-3), NOP]
    sim = make_sim('fast', main, handler())
    out = []

    def on_uart(c):
        out.append(ord(c))
        if len(out) % 5 == 0:
            sim.mu.emu_stop()
    sim.setUartHandler(on_uart)
    for _ in range(40):
        sim.run(max_instructions=sim.instruction_count + 200)
    bad = sum(1 for a, b_ in zip(out, out[1:]) if (b_ - a) & 0xFF != 1)
    check(len(out) > 50 and bad == 0 and sim._timeout_slices == 0,
          f"emu_stop() from the UART callback in counted slices: {len(out)} chars, {bad} duplicated", fails)


def scenario_ds_warning(fails):
    # A load / store that reaches a Unicorn memory hook (or protection fault)
    # in a branch delay slot hits a Unicorn 2.1.4 bug: the branch target's
    # first instruction runs twice.  Device registers are an mmio_map region,
    # which is not affected; the flash window (write-protected) is, and the
    # simulator warns about it (once per PC).
    for what, base, warned in (("UART THR (mmio_map)", 0xB8018300, False),
                               ("flash window (write-protected)", 0xAFC00100, True)):
        logs, out = [], []
        putc_ds = [jr(RA), sb(A0, 0, T6)]            # store in the delay slot
        main = prologue(2000, 0x40000000, 0x10000001) + li(T6, base) +             [addiu(A0, ZERO, 0x41), jal(PUTC), NOP, addiu(S0, S0, 1), b(-1), NOP]
        sim = make_sim('exact', main, handler(), {PUTC: struct.pack('<2I', *putc_ds)})
        sim.log_callback = logs.append
        sim.setUartHandler(out.append)
        sim.run(max_instructions=200)
        warns = [m for m in logs if 'delay slot' in m and 'WARN' in m]
        if warned:
            check(len(warns) == 1, f"{what}: a store in a delay slot is reported once ({warns[:1]})", fails)
        else:
            check(not warns and sim.mu.reg_read(UC_MIPS_REG_S0) == 1 and out == ['A'],
                  f"{what}: a store in a delay slot runs once and returns once "
                  f"(return-site instruction ran {sim.mu.reg_read(UC_MIPS_REG_S0)}x, output {out}, "
                  f"warnings {len(warns)})", fails)


def scenario_native_eret(fails):
    # Fast mode: one ERET whose hook is skipped (as Unicorn does under an
    # asynchronous stop) runs natively and jumps to ErrorEPC = 0; the boundary
    # repair must redo it and the program must go on ticking.
    p = period('timed')
    main = prologue(p, p, 0x10008001) + idle_loop()
    sim = make_sim('timed', main, handler())
    orig = sim._emulate_cop0
    skipped = [0]

    def emu(uc, address, w, in_ds):
        if w == ERET and sim.timer_irq_count == 3 and not skipped[0]:
            skipped[0] = 1
            return False                         # not emulated: Unicorn executes it natively
        return orig(uc, address, w, in_ds)
    sim._emulate_cop0 = emu
    run_until(sim, 'timed', 0, lambda s: ticks(s) >= 8 and s.mu.reg_read(UC_MIPS_REG_S0) > 0, wall=5.0)
    check(skipped[0] == 1 and sim.native_cp0_repairs >= 1 and ticks(sim) >= 8,
          f"a native ERET (to ErrorEPC 0) is redone: repairs={sim.native_cp0_repairs}, ticks={ticks(sim)}", fails)


def scenario_late(fails):
    # Exact mode: period 4 Count ticks (2 instructions), but the handler writes
    # Compare 12 instructions after reading Count -> Compare is already passed.
    main = prologue(4, 2000, 0x10008001) + idle_loop()
    sim = make_sim('exact', main, handler(delay_nops=12))
    sim.run(max_instructions=5_000)
    n = ticks(sim)
    check(n > 50, f"late Compare write fires at once instead of after a Count wrap (ticks={n})", fails)


def scenario_uart_delay(fails):
    # Exact mode: ticks every ~1000 instructions must not bring the UART RX
    # interrupt (armed 15000 instructions ahead) forward.
    main = prologue(2000, 2000, 0x10008001) + idle_loop()
    sim = make_sim('exact', main, handler())
    sim.setUartReceiveData(b"x", delay_instructions=15_000)
    sim.run(max_instructions=14_000)
    early = sim._uart_irq_retries
    sim.run(max_instructions=17_000)
    check(early == 0 and sim._uart_irq_retries >= 1 and ticks(sim) > 5,
          f"UART RX interrupt waits for its delay despite {ticks(sim)} timer ERETs "
          f"(deliveries before: {early}, after: {sim._uart_irq_retries})", fails)


SCENARIOS = (scenario_periodic, scenario_masked, scenario_no_edge, scenario_mips16, scenario_m16_selfloop,
             scenario_vector_iv, scenario_continuity, scenario_disabled, scenario_software,
             scenario_step_noirq, scenario_breakpoint, scenario_short_period)


def main():
    print("=== Test: CP0 timer interrupt ===")
    fails = []
    for mode in MODES:
        print(f"\n--- {dict(exact='exact per-instruction hook', fast='fast mode, counted slices', timed='fast mode, timed slices')[mode]} ---")
        for scenario in SCENARIOS:
            print(f" [{scenario.__name__[9:]}]")
            scenario(mode, fails)
    print("\n--- exact: late Compare write ---")
    scenario_late(fails)
    print("\n--- exact: UART RX delay with timer ticks ---")
    scenario_uart_delay(fails)
    print("\n--- timed slices: device accesses replayed after asynchronous stops ---")
    for kind in ('auto', 'unicorn'):
        scenario_replay_tx(kind, fails)
        scenario_replay_tx(kind, fails, mid_block=True)
        scenario_replay_tx_m16(kind, fails, extended=False)
        scenario_replay_tx_m16(kind, fails, extended=True)
        scenario_replay_tx_pairs(kind, fails)
        scenario_replay_rx(kind, fails)
        scenario_shared_putc(kind, fails)
    scenario_false_rewind(fails)
    scenario_counted_external_stop(fails)
    scenario_ds_warning(fails)
    print("\n--- timed slices: recovery from a natively executed ERET ---")
    scenario_native_eret(fails)
    if fails:
        print(f"\n\033[91m{len(fails)} check(s) failed\033[0m")
    else:
        print("\n\033[92mAll CP0 timer checks passed\033[0m")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
