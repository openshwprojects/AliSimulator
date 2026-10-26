"""
Test: fast mode's idle skipping (simulator.idle_skip, _skip_idle).

A program arms a 10 ms CP0 timer tick and waits in `b .` (the RTOS's idle
loop); its handler counts the ticks.  With idle skipping the emulation time
moves on to each next tick instead of spinning there:

  ticks      - the ticks come at the programmed rate of emulation time (200 in
               2 s), most of that time skipped (sim.idle_skipped), and the
               estimated instruction count moves with it at the measured rate
  hook       - the loop gets the code hook that ends the slices reaching it
  off        - idle_skip = False: nothing is skipped, the ticks still come
  budget     - run(max_instructions=N) ends at N exactly, in the middle of a skip
  max_vtime  - run(max_vtime=T) ends at T (within a slice's margin)
  masked     - a `b .` with interrupts disabled is a hang, not idleness: nothing
               is skipped and no tick is taken
  uart       - a UART byte armed 300,000 instructions ahead arrives there, not
               after a skip past it (run()'s budget includes the arming point)
  busy       - time the CPU owes for work done in Python (busy_pending, the
               LZMA decoder's charge) is paid in run()'s steps, with no
               interrupt meanwhile -- the ticks that came due arrive after it,
               one latched edge --, within budgets and max_vtime
"""
import os
import re
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from unicorn.mips_const import UC_MIPS_REG_S1
from simulator import AliMipsSimulator
from mips_asm import (IDLE, K0, address_of, lbu, li, load, tick_handler, timer_prologue)
from engine_check import CPP

PERIOD = 1_000_000                  # Count ticks: 10 ms at count_hz = 100 MHz
fails = []


def check(cond, msg):
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    if not cond:
        fails.append(msg)


def make(status=0x10008001, idle_skip=True):
    """Timed slices from the start (as in a firmware run after its first ones)."""
    logs = []
    sim = AliMipsSimulator(log_handler=logs.append)
    sim.exact_count_threshold = 0
    sim.calibration_slices = 0
    sim.idle_skip = idle_skip
    main = timer_prologue(PERIOD, PERIOD, status) + IDLE
    # the handler also reads the UART's receive register (the 'uart' case's byte)
    handler = li(K0, 0xB8018300) + [lbu(K0, 0, K0)] + tick_handler()
    load(sim, main, handler)
    return sim, logs, address_of(main, len(main) - 2)


def run_for(sim, seconds):
    until = sim._vtime() + seconds
    while sim._vtime() < until:
        sim.run(max_instructions=sim.instruction_count + 2_000_000, max_vtime=until)


def ticks(sim):
    return sim.mu.reg_read(UC_MIPS_REG_S1)


print("--- ticks / hook")
sim, logs, loop = make()
run_for(sim, 0.2)                                 # past the start
v0, n0, i0, s0 = sim._vtime(), ticks(sim), sim.instruction_count, sim.idle_skipped
run_for(sim, 2.0)
dv, dn, di, ds = sim._vtime() - v0, ticks(sim) - n0, sim.instruction_count - i0, sim.idle_skipped - s0
check(170 <= dn <= 230, f"{dn} ticks in {dv:.2f} s of emulation time (200 wanted at 10 ms)")
check(ds / dv > 0.7, f"{ds:.2f} s of it skipped ({100 * ds / dv:.0f}%, more than 70% wanted)")
check(abs(di - sim._insn_rate * dv) <= 0.15 * sim._insn_rate * dv,
      f"the instruction count moved with it: {di} for {sim._insn_rate * dv:.0f} at the estimated rate")
if CPP:
    print("  (the idle loop's code hook: not applicable on the C++ engine, which finds the loop as it runs it)")
else:
    check(loop in sim._idle_loops, f"the idle loop at 0x{loop:08X} is hooked ({[hex(a) for a in sim._idle_loops]})")

print("--- off")
sim, logs, loop = make(idle_skip=False)
run_for(sim, 0.3)
check(sim.idle_skipped == 0 and not sim._idle_loops and 20 <= ticks(sim) <= 40,
      f"idle_skip = False: {sim.idle_skipped:.2f} s skipped, {ticks(sim)} ticks in 0.3 s (~30 wanted)")

print("--- budget / max_vtime")
sim, logs, loop = make()
run_for(sim, 0.2)
target = sim.instruction_count + 123_457
sim.run(max_instructions=target)
check(sim.instruction_count == target, f"run(max_instructions) ends at {sim.instruction_count} ({target} wanted)")
v = sim._vtime()
sim.run(max_instructions=0, max_vtime=v + 0.25)
check(0.25 - 1e-9 <= sim._vtime() - v < 0.27, f"run(max_vtime=+0.25 s) ends {sim._vtime() - v:.4f} s later")

print("--- masked")
sim, logs, loop = make(status=0x10008000)        # IM7 but not IE
run_for(sim, 0.2)
check(sim.idle_skipped == 0 and ticks(sim) == 0 and not sim._idle_loops,
      f"interrupts disabled: {sim.idle_skipped:.2f} s skipped, {ticks(sim)} ticks, loops hooked "
      f"{len(sim._idle_loops)}")

print("--- uart")
sim, logs, loop = make()
run_for(sim, 0.2)
sim.setUartReceiveData(b"x", delay_instructions=300_000)
arm = sim._uart_irq_arm_after
sim.run(max_instructions=sim.instruction_count + 2_000_000)
got = [int(m.group(1)) for m in (re.search(r"\[UART IRQ\] Delivering interrupt #1 .*icount=(\d+)", s) for s in logs)
       if m]
check(bool(got) and arm <= got[0] <= arm + 20_000,
      f"the UART interrupt comes at instruction {got[0] if got else None} (armed at {arm})")

print("--- busy")
sim, logs, loop = make()
run_for(sim, 0.2)
n0, v0 = ticks(sim), sim._vtime()
sim.busy_pending = 0.055                          # five and a half ticks' time
during, steps = [], 0
while sim.busy_pending > 1e-9 and steps < 200:
    target = sim.instruction_count + round(sim._insn_rate / 1000)   # 1 ms of it per step
    sim.run(max_instructions=target)
    during.append((ticks(sim), sim.instruction_count == target))
    steps += 1
check(all(t == n0 for t, _ in during[:-1]) and all(exact for _, exact in during),
      f"no tick while it is paid ({steps} budget-sized steps, each ending at its budget)")
check(abs(sim._vtime() - v0 - 0.055) < 1e-6, f"the emulation time moved on by {sim._vtime() - v0:.6f} s")
run_for(sim, 0.004)
check(ticks(sim) == n0 + 1, f"the ticks that came due arrive after it as one: {ticks(sim) - n0} (1 wanted)")
sim.busy_pending = 0.03
v = sim._vtime()
sim.run(max_instructions=0, max_vtime=v + 0.01)
check(abs(sim._vtime() - v - 0.01) < 1e-6 and abs(sim.busy_pending - 0.02) < 1e-6,
      f"run(max_vtime=+0.01 s) pays 0.01 s of it ({sim.busy_pending:.4f} s left)")

print()
if fails:
    print(f"\033[91m{len(fails)} idle-skip check(s) failed\033[0m")
    sys.exit(1)
print("\033[92mAll idle-skip checks passed\033[0m")
