"""
Test: fast mode's mailbox poll skipping (simulator.poll_skip, _skip_poll).

A program polls the mailbox register 0xB8000200 in the dual-CPU SDK's tight
loop (lw v0, 0(s1); beq v0, v1, back; nop -- waiting while it reads -1) under
a 10 ms CP0 tick; a slice service plays the other core, storing a reply in the
mailbox at a set emulation time (the SEE core stores between the main CPU's
slices the same way), and _mailbox_peer is made to report that core:

  skip      - the spin is idle time: most of the wait skipped (poll_skipped),
              the loop hooked, the reply read as soon as it was stored, the
              ticks still coming at their rate meanwhile
  masked    - with interrupts disabled the time still moves on (to the end of
              each turn) and the reply ends the loop
  no peer   - with no other core running nothing is skipped (the register is
              then just a device register)
  other     - a poll of a register that is no mailbox is left to spin
  off       - poll_skip = False: nothing skipped, the reply still read
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

from unicorn.mips_const import UC_MIPS_REG_PC, UC_MIPS_REG_S1, UC_MIPS_REG_V0
from simulator import AliMipsSimulator
from mips_asm import (IDLE, NOP, S1, S2, T6, V0, V1, address_of, addiu, beq, li, load, lw, tick_handler,
                      timer_prologue)

PERIOD = 1_000_000                  # Count ticks: 10 ms at count_hz = 100 MHz
MAILBOX = 0xB8000200
REPLY_AT = 0.5                      # emulation seconds after the start of the poll
fails = []


def check(cond, msg):
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    if not cond:
        fails.append(msg)


class Peer:
    """The other core: stores `reply` in the mailbox once the emulation time reaches `at`."""

    def __init__(self, sim, address, reply, at):
        self.sim, self.address, self.reply, self.at, self.stored = sim, address, reply, at, None
        sim.slice_services.append(self.service)

    def service(self):
        if self.stored is None and self.sim._vtime() >= self.at:
            self.stored = self.sim._vtime()
            self.sim.poke(self.address, self.reply.to_bytes(4, 'little'))


def make(status=0x10008001, address=MAILBOX, peer=True, poll_skip=True):
    sim = AliMipsSimulator(log_handler=lambda m: None)
    sim.exact_count_threshold = 0
    sim.calibration_slices = 0
    sim.poll_skip = poll_skip
    if peer:
        sim._mailbox_peer = lambda: True
    sim.poke(address, (0xFFFFFFFF).to_bytes(4, 'little'))
    # the poll: s1 = the mailbox, v1 = -1; loop while it reads -1; then v0 holds the reply
    main = timer_prologue(PERIOD, PERIOD, status) + li(S1, address) + [addiu(V1, 0, -1)]
    poll = len(main)
    main += [lw(V0, 0, S1), beq(V0, V1, -2), NOP, addiu(S2, 0, 1)] + IDLE
    load(sim, main, tick_handler(counter=T6))
    return sim, address_of(main, poll), address_of(main, len(main) - 2)


def run_until_done(sim, done, seconds):
    """Run in 10 ms steps until the loop is left; (left, emulation time then, ticks then)."""
    until = sim._vtime() + seconds
    while sim._vtime() < until and sim.mu.reg_read(sim.gpr_map[S2]) != 1:
        sim.run(max_instructions=sim.instruction_count + 2_000_000, max_vtime=min(until, sim._vtime() + 0.01))
    return sim.mu.reg_read(sim.gpr_map[S2]) == 1, sim._vtime(), sim.mu.reg_read(sim.gpr_map[T6])


print("--- skip")
sim, poll, done = make()
peer = Peer(sim, MAILBOX, 0x40, sim._vtime() + REPLY_AT)
v0 = sim._vtime()
ok, left, ticks = run_until_done(sim, done, 2.0)
check(ok and sim.mu.reg_read(UC_MIPS_REG_V0) == 0x40, f"the reply 0x{sim.mu.reg_read(UC_MIPS_REG_V0):X} was read "
      f"and the loop left")
check(sim.poll_skipped > 0.8 * REPLY_AT and poll in sim._poll_loops,
      f"{sim.poll_skipped:.3f} s of the {REPLY_AT} s wait skipped, the loop at 0x{poll:08X} hooked")
check(peer.stored is not None and left - peer.stored < 0.02,
      f"left {1e3 * (left - peer.stored):.1f} ms after the reply was stored (within a tick wanted)")
check(40 <= ticks <= 60, f"{ticks} ticks during the {left - v0:.2f} s of the poll (~50 at 10 ms wanted)")

print("--- masked")
sim, poll, done = make(status=0x10008000)
peer = Peer(sim, MAILBOX, 0x41, sim._vtime() + REPLY_AT)
ok, left, ticks = run_until_done(sim, done, 2.0)
check(ok and sim.poll_skipped > 0.8 * REPLY_AT and ticks == 0 and left - peer.stored < 0.02,
      f"interrupts disabled: {sim.poll_skipped:.3f} s skipped, the reply read "
      f"{1e3 * (left - peer.stored):.1f} ms after it was stored, no tick taken")

print("--- no peer")
sim, poll, done = make(peer=False)
Peer(sim, MAILBOX, 0x42, sim._vtime() + 0.1)
ok, left, ticks = run_until_done(sim, done, 0.5)
check(ok and sim.poll_skipped == 0 and not sim._poll_loops,
      f"no other core: nothing skipped ({sim.poll_skipped} s), the reply still read")

print("--- other")
sim, poll, done = make(address=0xB8000300)
Peer(sim, 0xB8000300, 0x43, sim._vtime() + 0.1)
ok, left, ticks = run_until_done(sim, done, 0.5)
check(ok and sim.poll_skipped == 0, f"a register that is no mailbox: nothing skipped ({sim.poll_skipped} s)")

print("--- off")
sim, poll, done = make(poll_skip=False)
Peer(sim, MAILBOX, 0x44, sim._vtime() + 0.1)
ok, left, ticks = run_until_done(sim, done, 0.5)
check(ok and sim.poll_skipped == 0 and not sim._poll_loops, f"poll_skip = False: nothing skipped, the reply read")

print()
if fails:
    print(f"\033[91m{len(fails)} poll-skip check(s) failed\033[0m")
    sys.exit(1)
print("\033[92mAll poll-skip checks passed\033[0m")
