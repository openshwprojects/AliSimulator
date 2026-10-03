"""
Test: the simulated devices the firmware applications wait for.

Small MIPS32 programs in RAM, in the same three modes as
test_cp0_timer_interrupt.py (exact per-instruction hook, fast counted slices,
fast timed slices):

  pmu       - PMU 0xB8018D02: bit 0x20 (ready) reads clear until the
              firmware sets bit 0x80 (start), then set (the applications poll
              it with udelay(2000), up to 36,848 times)
  vcap      - VCAP 0xB800F04B: the busy bit 0 the driver sets reads back
              cleared (the driver spins on it without a timeout)
  ge        - graphics engine 0xB800A000: a command written to +4 completes
              at once; its status bit (+8, write 1 to clear) drives
              interrupt-controller line 4 (0xB8000030 bit 4) and IP3.  The
              handler sees IP3 and the line, acks the status, and the line
              drops (no second interrupt for one command)
  ge_masked - with the line disabled in 0xB8000038 the command still completes
              (status and 0xB8000030 show it for polling) but no interrupt is
              taken; enabling the line delivers it
  ge_writeback    - the firmware's acknowledge of 0xB8000030 (writing back
              what it read) does not clear a line the device still asserts
  ge_partial_ack  - two completions pending: the line stays asserted until
              both status bits are acked (two interrupts: status 0x3, 0x2)
  ge_replay - (timed slices) an asynchronous stop that rewinds to the command
              store does not count the command twice
  observers - add_mmio_hook / remove_mmio_hook (device accesses observed
              without a Unicorn memory hook), its argument checks, and
              side-effect-free peek / poke of the physical device window
"""
import struct
import sys

from test_cp0_timer_interrupt import (MODES, MAIN, EPC_LOG, ZERO, T1, T2, T3, T4, T5, S0, S1, S4, S6, S7,
                                      K0, K1, CAUSE, STATUS, ERET, NOP, mfc0, mtc0, addiu, addu, ori, lui,
                                      andi, sw, beq, li, check, make_sim, run_until)
from unicorn.mips_const import (UC_MIPS_REG_S0, UC_MIPS_REG_S1, UC_MIPS_REG_S3, UC_MIPS_REG_S4,
                                UC_MIPS_REG_S6, UC_MIPS_REG_S7)

S3 = 19


def lw(rt, off, base): return 0x8C000000 | base << 21 | rt << 16 | (off & 0xFFFF)
def lbu(rt, off, base): return 0x90000000 | base << 21 | rt << 16 | (off & 0xFFFF)
def sb(rt, off, base): return 0xA0000000 | base << 21 | rt << 16 | (off & 0xFFFF)
def bne(rs, rt, off): return 0x14000000 | rs << 21 | rt << 16 | (off & 0xFFFF)


def reg(sim, r):
    return sim.mu.reg_read(r)


def done(sim):
    return reg(sim, UC_MIPS_REG_S0) == 1


def scenario_pmu(mode, fails):
    # t1 = 0xB8018D02; s6 = ready bit before the start; set start; poll ready; s0 = 1
    main = li(T1, 0xB8018D02) + [
        lbu(S6, 0, T1),
        ori(T2, S6, 0x80), sb(T2, 0, T1),
        lbu(T3, 0, T1), andi(T3, T3, 0x20), beq(T3, ZERO, -3), NOP,
        addiu(S0, ZERO, 1), beq(ZERO, ZERO, -1), NOP]
    sim = make_sim(mode, main, [ERET, NOP])
    run_until(sim, mode, 200, done)
    check(not reg(sim, UC_MIPS_REG_S6) & 0x20, "ready bit 0x20 reads clear before the start bit is set", fails)
    check(done(sim), "after setting start bit 0x80 the ready bit reads set", fails)


def scenario_vcap(mode, fails):
    main = li(T1, 0xB800F04B) + [
        lbu(T2, 0, T1), ori(T2, T2, 0x01), sb(T2, 0, T1),        # set the busy bit
        lbu(T3, 0, T1), andi(T3, T3, 0x01), bne(T3, ZERO, -3), NOP,
        addiu(S0, ZERO, 1), beq(ZERO, ZERO, -1), NOP]
    sim = make_sim(mode, main, [ERET, NOP])
    run_until(sim, mode, 200, done)
    check(done(sim), "the busy bit 0 the driver set reads back cleared (no endless spin)", fails)


def ge_handler():
    """Logs Cause, 0xB8000030 and the GE status at [s4] (12 bytes each), acks
    the status, counts in s1."""
    return [mfc0(K0, CAUSE), sw(K0, 0, S4),
            lui(K1, 0xB800), lw(K0, 0x30, K1), sw(K0, 4, S4),
            ori(K1, K1, 0xA000), lw(K0, 8, K1), sw(K0, 8, S4), sw(K0, 8, K1),
            addiu(S4, S4, 12), addiu(S1, S1, 1), ERET, NOP]


def ge_log(sim):
    n = (reg(sim, UC_MIPS_REG_S4) - EPC_LOG) // 12
    data = bytes(sim.mu.mem_read(EPC_LOG, 12 * n)) if n > 0 else b''
    return [struct.unpack_from('<3I', data, 12 * i) for i in range(n)]


def ge_prologue(enable_line):
    return [lui(S4, EPC_LOG >> 16)] + li(T2, 0x10000801) + [mtc0(T2, STATUS)] + \
           [lui(T3, 0xB800)] + ([addiu(T4, ZERO, 0x10), sw(T4, 0x38, T3)] if enable_line else []) + \
           li(T1, 0xB800A000)


def scenario_ge(mode, fails):
    main = ge_prologue(True) + [
        addiu(T4, ZERO, 2), sw(T4, 4, T1),                       # command 2 -> status bit 0
        beq(S1, ZERO, -1), NOP,                                   # wait for the interrupt
        addiu(T4, ZERO, 1), sw(T4, 4, T1),                       # command 1 -> status bit 2
        addiu(T5, ZERO, 2), bne(S1, T5, -1), NOP,
        lw(S7, 0x30, T3),                                         # 0xB8000030 after both acks
        addiu(S0, ZERO, 1), beq(ZERO, ZERO, -1), NOP]
    sim = make_sim(mode, main, ge_handler())
    run_until(sim, mode, 400, done)
    run_until(sim, mode, 400, lambda s: False, wall=0.3)          # nothing more may come
    log = ge_log(sim)
    check(done(sim) and reg(sim, UC_MIPS_REG_S1) == 2,
          f"two commands, two interrupts (handler ran {reg(sim, UC_MIPS_REG_S1)} times)", fails)
    check(all(c & 0x800 and not c & 0x7C for c, _, _ in log),
          f"Cause has IP3 and ExcCode 0 in the handler ({[hex(c) for c, _, _ in log]})", fails)
    check([(e & 0x10, st) for _, e, st in log] == [(0x10, 0x1), (0x10, 0x4)],
          f"the handler sees line 4 in 0xB8000030 and status 0x1, then 0x4 "
          f"({[(hex(e), hex(st)) for _, e, st in log]})", fails)
    check(not reg(sim, UC_MIPS_REG_S7) & 0x10 and sim._ic_lines == 0,
          f"the ack drops the line (0xB8000030 = 0x{reg(sim, UC_MIPS_REG_S7):08X})", fails)
    check(sim.ge_ops == 2 and sim.ic_irq_count == 2,
          f"ge_ops = {sim.ge_ops}, ic_irq_count = {sim.ic_irq_count}", fails)


def scenario_ge_masked(mode, fails):
    main = ge_prologue(False) + [
        addiu(T4, ZERO, 3), sw(T4, 4, T1),                       # command 3 -> status bit 1
        lw(S6, 8, T1), andi(T4, S6, 0x2), beq(T4, ZERO, -3), NOP,   # poll the status
        lw(S7, 0x30, T3), addiu(T5, ZERO, 0),
        addiu(T5, T5, 1), addiu(T4, ZERO, 200), bne(T5, T4, -3), NOP,  # ~200 loops: no interrupt
        addu(S3, S1, ZERO),                                       # s3 = interrupts so far
        addiu(T4, ZERO, 0x10), sw(T4, 0x38, T3),                 # enable line 4
        beq(S1, ZERO, -1), NOP,
        addiu(S0, ZERO, 1), beq(ZERO, ZERO, -1), NOP]
    sim = make_sim(mode, main, ge_handler())
    run_until(sim, mode, 3000, done)
    check(reg(sim, UC_MIPS_REG_S6) & 0x2, f"polling: status +8 shows bit 1 (0x{reg(sim, UC_MIPS_REG_S6):X})", fails)
    check(reg(sim, UC_MIPS_REG_S7) & 0x10, "0xB8000030 shows line 4 while it is disabled", fails)
    check(reg(sim, UC_MIPS_REG_S3) == 0, "no interrupt while line 4 is disabled in 0xB8000038", fails)
    check(done(sim) and reg(sim, UC_MIPS_REG_S1) == 1, "enabling the line delivers the interrupt", fails)


def scenario_ge_writeback(mode, fails):
    # line disabled: the firmware acks 0xB8000030 by writing back what it read (and 0)
    main = ge_prologue(False) + [
        addiu(T4, ZERO, 2), sw(T4, 4, T1),
        lw(T5, 0x30, T3), sw(T5, 0x30, T3), sw(ZERO, 0x30, T3),
        lw(S6, 0x30, T3),                                         # the device still drives the line
        lw(T5, 8, T1), sw(T5, 8, T1),                             # ack the GE status
        lw(S7, 0x30, T3),
        addiu(S0, ZERO, 1), beq(ZERO, ZERO, -1), NOP]
    sim = make_sim(mode, main, ge_handler())
    run_until(sim, mode, 400, done)
    check(done(sim) and reg(sim, UC_MIPS_REG_S6) & 0x10,
          "writing 0xB8000030 back (or 0) does not clear a line the device still asserts", fails)
    check(not reg(sim, UC_MIPS_REG_S7) & 0x10 and sim._ic_lines == 0,
          "acknowledging the GE status +8 clears it", fails)


def subu(rd, rs, rt): return 0x00000023 | rs << 21 | rt << 16 | rd << 11
def and_(rd, rs, rt): return 0x00000024 | rs << 21 | rt << 16 | rd << 11
T7 = 15


def scenario_ge_partial_ack(mode, fails):
    # two completions pending (IE=0), the handler acks only the lowest status bit
    handler = [mfc0(K0, CAUSE), sw(K0, 0, S4),
               lui(K1, 0xB800), lw(K0, 0x30, K1), sw(K0, 4, S4),
               ori(K1, K1, 0xA000), lw(K0, 8, K1), sw(K0, 8, S4),
               subu(T7, ZERO, K0), and_(T7, K0, T7), sw(T7, 8, K1),     # ack status & -status
               addiu(S4, S4, 12), addiu(S1, S1, 1), ERET, NOP]
    main = [lui(S4, EPC_LOG >> 16)] + li(T2, 0x10000800) + [mtc0(T2, STATUS)] + \
           [lui(T3, 0xB800), addiu(T4, ZERO, 0x10), sw(T4, 0x38, T3)] + li(T1, 0xB800A000) + [
        addiu(T4, ZERO, 2), sw(T4, 4, T1),                       # status bit 0
        addiu(T4, ZERO, 3), sw(T4, 4, T1),                       # status bit 1
        ori(T2, T2, 1), mtc0(T2, STATUS),                         # IE
        addiu(T5, ZERO, 2), bne(S1, T5, -1), NOP,
        addiu(S0, ZERO, 1), beq(ZERO, ZERO, -1), NOP]
    sim = make_sim(mode, main, handler)
    run_until(sim, mode, 400, done)
    run_until(sim, mode, 400, lambda s: False, wall=0.3)
    sts = [st for _, _, st in ge_log(sim)]
    check(done(sim) and sts == [0x3, 0x2],
          f"the line stays asserted until every status bit is acked: interrupts saw status "
          f"{[hex(x) for x in sts]} (expected 0x3, then 0x2)", fails)
    check(sim._ic_lines == 0 and sim.ge_ops == 2, f"line dropped after the second ack, ge_ops = {sim.ge_ops}", fails)


def scenario_ge_replay(kind, fails):
    """Timed slices: every GE command raises the line, which arms a 1 ms
    asynchronous stop, so stops often land right after the command store and
    rewind to it.  The re-executed store must not count as a second command."""
    import time
    handler = [lui(K1, 0xB800), ori(K1, K1, 0xA000), lw(K0, 8, K1), sw(K0, 8, K1),
               addiu(S1, S1, 1), ERET, NOP]
    main = ge_prologue(True) + [addiu(T4, ZERO, 2),
                                sw(T4, 4, T1), addiu(S0, S0, 1), beq(ZERO, ZERO, -3), NOP]
    sim = make_sim('timed', main, handler)
    sim.slice_stopper = kind
    t0 = time.time()
    while time.time() - t0 < 2.0:
        sim.run(max_instructions=sim.instruction_count + 2_000_000)
    stores = reg(sim, UC_MIPS_REG_S0)
    # (the 'unicorn' timeout stops only every 15-150 ms: few interrupts there)
    check(stores > 1000 and reg(sim, UC_MIPS_REG_S1) > 10 and 0 <= sim.ge_ops - stores <= 1,
          f"[{kind}] {stores} command stores, {sim.ge_ops} commands counted, "
          f"{reg(sim, UC_MIPS_REG_S1)} interrupts, {sim._timeout_slices} slices", fails)


def scenario_observers(fails):
    """add_mmio_hook (observing device accesses without a Unicorn memory hook),
    remove_mmio_hook, argument checks, and side-effect-free peek / poke."""
    from test_cp0_timer_interrupt import MAIN
    # loop: sb s0, 0(t1) (UART THR) ; addiu s0,1 ; b loop ; nop
    main = li(T1, 0xB8018300) + [sb(S0, 0, T1), addiu(S0, S0, 1), beq(ZERO, ZERO, -3), NOP]
    sim = make_sim('fast', main, [ERET, NOP])
    out, seen = [], []
    sim.setUartHandler(out.append)
    h = sim.add_mmio_hook('write', lambda uc, a, address, size, value, ud: seen.append((address, value)),
                          0x18018300, 0x18018300)
    sim.run(max_instructions=sim.instruction_count + 40)
    n1 = len(seen)
    check(n1 > 0 and n1 == len(out) and all(a == 0xB8018300 for a, _ in seen)
          and [v for _, v in seen] == [ord(c) for c in out],
          f"the observer sees every THR store with its value, at the 0xB8 view address ({n1} stores, "
          f"{len(out)} characters)", fails)
    sim.remove_mmio_hook(h)
    sim.run(max_instructions=sim.instruction_count + 40)
    check(len(seen) == n1 and len(out) > n1, "after remove_mmio_hook it is not called any more", fails)
    for args, what in ((('r', print, 0x18018300, 0x18018300), "kind 'r'"),
                       (('read', print, 0xAFC00000, 0xAFC00003), "a flash address"),
                       (('read', print, 0xB8018304, 0xB8018300), "begin > end")):
        try:
            sim.add_mmio_hook(*args)
            ok = False
        except ValueError:
            ok = True
        check(ok, f"add_mmio_hook rejects {what}", fails)
    # peek / poke: no device side effects (a physical-window access runs the handlers)
    sim.setUartReceiveData(b"xyz", delay_instructions=1 << 40)
    sim.peek(0x18018300, 1)
    check(len(sim._uart_rx_queue) == 3, "peek of the physical URBR does not consume an RX byte", fails)
    sim.mu.mem_read(0x18018300, 1)
    check(len(sim._uart_rx_queue) == 2, "(while mu.mem_read of it does: it is the device window)", fails)
    n = len(out)
    sim.poke(0x18018300, b"Q")
    check(len(out) == n and bytes(sim.peek(0xB8018300, 1)) == b"Q",
          "poke of the physical THR stores without printing a character", fails)


SCENARIOS = [scenario_pmu, scenario_vcap, scenario_ge, scenario_ge_masked, scenario_ge_writeback,
             scenario_ge_partial_ack]


def main():
    print("=== Test: simulated devices (PMU, VCAP, graphics engine interrupt) ===")
    fails = []
    for mode in MODES:
        print(f"\n--- {dict(exact='exact per-instruction hook', fast='fast mode, counted slices', timed='fast mode, timed slices')[mode]} ---")
        for scenario in SCENARIOS:
            print(f" [{scenario.__name__[9:]}]")
            scenario(mode, fails)
    print("\n--- add_mmio_hook observers, peek / poke ---")
    scenario_observers(fails)
    print("\n--- timed slices: GE command stores replayed after asynchronous stops ---")
    for kind in ('auto', 'unicorn'):
        scenario_ge_replay(kind, fails)
    if fails:
        print(f"\n\033[91m{len(fails)} check(s) failed\033[0m")
    else:
        print("\n\033[92mAll device model checks passed\033[0m")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
