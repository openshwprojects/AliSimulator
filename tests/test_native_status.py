"""
Test: the native Status (simulator.native_status): kuseg mapped 1:1 by a
wired TLB entry instead of a forced Status.ERL, MFC0 Status running natively,
MTC0 Status running natively while its hook follows it.

  setup      - native_status is on: no forced ERL, MFC0 Status is no CP0 site
  kuseg      - with ERL clear a kuseg store lands in the RAM (read back through
               KSEG0) and a kuseg load of the UART's line status reaches the
               device register; the native Status carries no ERL
  mfc0       - MFC0 Status reads the guest's Status natively (no hook there),
               MTC0 Status keeps its (following) hook
  interrupt  - a tick that came due while interrupts were disabled is taken
               right after the MTC0 Status that enables them (EPC = the next
               instruction), as in exact mode and under the forced ERL
  same       - the programs give the same registers and EPC logs in all three
               (native Status, forced ERL, exact mode)
  disable    - the TDS RTOS's interrupt disable (two MTC0 Status of the Status
               it read with IE cleared) has no hooks under the native Status
               (skip_irq_disable; the forced ERL and skip_irq_disable = False
               hook them), its enable has -- the lean one (_hook_irq_enable)
               under the native Status --; a tick that comes due between the
               two is still taken right after the enable's MTC0, in all three
  eret       - an ERET whose hook is skipped runs natively (to the native EPC,
               0, or under the forced ERL to ErrorEPC, 0) and is redone, in both
               fast modes; the ticks go on
  adopt      - a Status written natively behind the hooks' back is taken over
               at the next slice boundary
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import struct

from unicorn.mips_const import UC_MIPS_REG_CP0_STATUS, UC_MIPS_REG_PC, UC_MIPS_REG_S1, UC_MIPS_REG_S4
from simulator import AliMipsSimulator
from mips_asm import (ERET, IDLE, MAIN, NOP, S4, STATUS, T0, T1, T2, T3, T4, T5, T6, addiu, address_of, b, bne,
                      lbu, li, load, lw, mfc0, mtc0, sw, tick_handler, timer_prologue)

EPC_LOG = 0x80200000
fails = []


class ForcedErl(AliMipsSimulator):
    native_status = False


from engine_check import CPP, unicorn_only

# The forced ERL is a mode of the Unicorn engine only (the C++ core keeps the
# guest's Status itself).  A subclass is never redirected to the C++ engine, so
# on it ForcedErl would quietly be a Unicorn simulator -- whose time is host CPU
# time: on a slow host its tick came due before the program reached the
# disable.  It is left out there.
FORCED = unicorn_only("the forced ERL (native_status = False) is a Unicorn-engine mode")
MODES = (("native Status", AliMipsSimulator, False),) + ((("forced ERL", ForcedErl, False),) if FORCED else ()) + \
    (("exact mode", AliMipsSimulator, True),)


def check(cond, msg):
    print(("  [PASS] " if cond else "  [FAIL] ") + msg)
    if not cond:
        fails.append(msg)


def run_program(cls, exact, main, handler=None, steps=20):
    """Run main (to the IDLE loop it ends with) and return the simulator."""
    sim = cls(log_handler=lambda m: None)
    sim.hook_every_instruction = exact
    sim.exact_count_threshold = 0
    sim.calibration_slices = 0
    load(sim, main, handler)
    end = address_of(main, len(main) - 2)
    for _ in range(steps):
        sim.run(max_instructions=sim.instruction_count + 200_000)
        if (sim.mu.reg_read(UC_MIPS_REG_PC) & ~1) == end:
            break
    return sim


def epc_log(sim):
    n = (sim.mu.reg_read(UC_MIPS_REG_S4) - EPC_LOG) // 4
    return list(struct.unpack(f"<{n}I", bytes(sim.mu.mem_read(EPC_LOG, 4 * n)))) if n > 0 else []


print("--- setup")
sim = AliMipsSimulator(log_handler=lambda m: None)
check(sim.force_erl is False and (CPP or (0x40006000 not in sim._site_words and 0x40806000 in sim._site_words)),
      "native_status: no forced ERL; MTC0 Status is a CP0 site, MFC0 Status is not" +
      (" (no CP0 sites on the C++ engine)" if CPP else ""))
if FORCED:
    forced = ForcedErl(log_handler=lambda m: None)
    check(forced.force_erl is True and 0x40006000 in forced._site_words, "native_status = False: the forced ERL")

print("--- kuseg")
KUSEG = li(T1, 0x1000FF00) + [mtc0(T1, STATUS)] + \
    li(T0, 0x00140000) + li(T2, 0x12345678) + [sw(T2, 0, T0)] + \
    li(T3, 0x80140000) + [lw(T4, 0, T3)] + \
    li(T5, 0x18018305) + [lbu(T6, 0, T5)] + IDLE
results = {}
for name, cls, exact in MODES:
    sim = run_program(cls, exact, KUSEG)
    regs = tuple(sim.mu.reg_read(sim.gpr_map[r]) for r in (T4, T6))
    results[name] = regs
    native = sim.mu.reg_read(UC_MIPS_REG_CP0_STATUS)
    erl_ok = not native & 0x4 if cls is AliMipsSimulator else bool(native & 0x4)
    check(regs[0] == 0x12345678 and regs[1] & 0x20 and erl_ok,
          f"{name}: kuseg store read back 0x{regs[0]:08X}, UART LSR through kuseg 0x{regs[1]:02X}, "
          f"native Status 0x{native:08X}")

print("--- mfc0")
MFC0 = li(T1, 0x1000FF01) + [mtc0(T1, STATUS), mfc0(T2, STATUS)] + IDLE
sim = run_program(AliMipsSimulator, False, MFC0)
mfc0_at, mtc0_at = address_of(MFC0, 3), address_of(MFC0, 2)
check(sim.mu.reg_read(sim.gpr_map[T2]) == 0x1000FF01 and (CPP or (mfc0_at not in sim._cp0_site_hooks
      and mtc0_at in sim._cp0_site_hooks)),
      f"MFC0 Status read 0x{sim.mu.reg_read(sim.gpr_map[T2]):08X} natively (no hook at 0x{mfc0_at:08X}); "
      f"the MTC0 has its hook")

print("--- interrupt")


def interrupt_program(spin):
    """Compare 20 us ahead with interrupts off, a spin past it, then the MTC0
    Status that enables them (returns the program and that MTC0's address)."""
    main = li(S4, EPC_LOG) + timer_prologue(0x7FFFFFFF, 2000, 0x10008000) + \
        li(T3, spin) + [addiu(T3, T3, -1), bne(T3, 0, -2), NOP] + \
        li(T2, 0x10008001) + [mtc0(T2, STATUS), NOP, NOP] + IDLE
    return main, address_of(main, len(main) - 5)


handler = tick_handler(epc_log=S4)
logs = {}
for name, cls, exact in MODES:
    # (the spin outlasts Compare: 2 Count ticks per instruction in exact mode, emulation time in fast mode)
    program, enable_at = interrupt_program(2_000 if exact else 200_000)
    sim = run_program(cls, exact, program, handler)
    logs[name] = epc_log(sim)[:1]
    check(logs[name] == [enable_at + 4],
          f"{name}: the tick that came due with interrupts off is taken after the enabling MTC0 "
          f"(EPC {[hex(e) for e in logs[name]]}, 0x{enable_at + 4:08X} wanted)")

print("--- same")
check(len(set(results.values())) == 1 and len(set(map(tuple, logs.values()))) == 1,
      f"the kuseg and interrupt programs give the same results in all {len(MODES)} modes")

print("--- disable")


def jal(target): return 0x0C000000 | (target >> 2) & 0x03FFFFFF


# the TDS RTOS's interrupt disable / enable (os_disable_interrupt / os_enable_interrupt)
DISABLE = [mfc0(T0, STATUS), NOP, NOP, NOP, addiu(T1, 0, 6), 0x01284824, bne(T1, 0, 8),   # and t1, t1, t0
           addiu(T1, 0, -2), 0x01094024, mtc0(T0, STATUS), NOP, NOP, mtc0(T0, STATUS), NOP, NOP,  # and t0, t0, t1
           0x03E00008, NOP]                                                               # jr ra
ENABLE = [mfc0(T0, STATUS), NOP, NOP, NOP, addiu(T1, 0, 6), 0x01284824, bne(T1, 0, 5),
          0x35080001, mtc0(T0, STATUS), NOP, NOP, NOP, 0x03E00008, NOP]                    # ori t0, t0, 1
EHB = 0x000000C0
# the newer SDK's (the T760i's): an EHB after each mfc0 / mtc0
DISABLE_EHB = [mfc0(T0, STATUS), EHB, NOP, NOP, NOP, addiu(T1, 0, 6), 0x01284824, bne(T1, 0, 10),
               addiu(T1, 0, -2), 0x01094024, mtc0(T0, STATUS), EHB, NOP, NOP, mtc0(T0, STATUS), EHB, NOP, NOP,
               0x03E00008, NOP]
ENABLE_EHB = [mfc0(T0, STATUS), EHB, NOP, NOP, NOP, addiu(T1, 0, 6), 0x01284824, bne(T1, 0, 6),
              0x35080001, mtc0(T0, STATUS), EHB, NOP, NOP, NOP, 0x03E00008, NOP]
# the R265 Lite 1.2.0's: five NOPs in each gap
DISABLE_5 = [mfc0(T0, STATUS)] + [NOP] * 5 + [addiu(T1, 0, 6), 0x01284824, bne(T1, 0, 14), addiu(T1, 0, -2),
                                              0x01094024, mtc0(T0, STATUS)] + [NOP] * 5 + [mtc0(T0, STATUS)] + \
    [NOP] * 5 + [0x03E00008, NOP]
ENABLE_5 = [mfc0(T0, STATUS)] + [NOP] * 5 + [addiu(T1, 0, 6), 0x01284824, bne(T1, 0, 7), 0x35080001,
                                             mtc0(T0, STATUS)] + [NOP] * 5 + [0x03E00008, NOP]


def disable_program(first, spin, disable=DISABLE, enable=ENABLE):
    """Interrupts on, the RTOS's disable, a spin past Compare, its enable:
    (program, the disable's two MTC0 Status, the enable's)."""
    head = li(S4, EPC_LOG) + timer_prologue(0x7FFFFFFF, first, 0x10008001)
    n = len(head) + 2 + 5 + 2 + len(IDLE)
    dis, ena = address_of(None, n), address_of(None, n + len(disable))
    main = head + [jal(dis), NOP] + li(T3, spin) + [addiu(T3, T3, -1), bne(T3, 0, -2), NOP] + \
        [jal(ena), NOP] + IDLE + disable + enable
    mtc0s = [dis + 4 * i for i, w in enumerate(disable) if w == mtc0(T0, STATUS)]
    return main, tuple(mtc0s), ena + 4 * enable.index(mtc0(T0, STATUS))


for (name, cls, exact), (form, disable, enable) in [(m, f) for m in MODES for f in (
        ("", DISABLE, ENABLE), (" (with EHBs)", DISABLE_EHB, ENABLE_EHB), (" (five NOPs)", DISABLE_5, ENABLE_5))]:
    program, disables, enable_at = disable_program(2_000 if exact else 50_000, 2_000 if exact else 500_000,
                                                   disable, enable)
    sim = cls(log_handler=lambda m: None)
    sim.hook_every_instruction = exact
    sim.exact_count_threshold = 0
    sim.calibration_slices = 0
    load(sim, program, handler)
    end = address_of(program, len(program) - len(disable) - len(enable) - 2)
    for _ in range(20):
        sim.run(max_instructions=sim.instruction_count + 200_000)
        if (sim.mu.reg_read(UC_MIPS_REG_PC) & ~1) == end:
            break
    log = epc_log(sim)[:1]
    check(log == [enable_at + 4], f"{name}{form}: the tick that came due inside the disabled section is taken "
                                  f"after the enable's MTC0 (EPC {[hex(e) for e in log]}, 0x{enable_at + 4:08X} wanted)")
    if not exact and not CPP:       # (which CP0 instructions are hooked: the Unicorn engine's)
        hooked = [a in sim._cp0_site_hooks for a in disables + (enable_at,)]
        want = [False, False, True] if cls is AliMipsSimulator else [True, True, True]
        lean = enable_at in sim._irq_enable_sites
        check(hooked == want and lean == (cls is AliMipsSimulator),
              f"{name}{form}: the disable's MTC0 Status hooked {hooked[:2]}, the enable's {hooked[2]} "
              f"({'the lean' if lean else 'the full'} hook)")
sim = AliMipsSimulator(log_handler=lambda m: None)
sim.skip_irq_disable = False
program, disables, enable_at = disable_program(100_000, 500_000)
load(sim, program, handler)
if not CPP:
    check(all(a in sim._cp0_site_hooks for a in disables + (enable_at,)), "skip_irq_disable = False: all three hooked")

print("--- eret")
if CPP:
    print("  (an ERET Unicorn ran natively under an asynchronous stop: not applicable on the C++ engine)")
for name, cls in (("native Status", AliMipsSimulator), ("forced ERL", ForcedErl)) if not CPP else ():
    sim = cls(log_handler=lambda m: None)
    sim.exact_count_threshold = 0
    sim.calibration_slices = 0
    load(sim, timer_prologue(0x100000, 0x100000, 0x10008001) + IDLE, tick_handler())
    orig, skipped = sim._emulate_cop0, [0]

    def emulate(uc, address, w, in_ds, sim=sim, orig=orig, skipped=skipped):
        if w == ERET and sim.mu.reg_read(UC_MIPS_REG_S1) == 3 and not skipped[0]:
            skipped[0] = 1
            return False                    # not emulated: Unicorn executes it natively
        return orig(uc, address, w, in_ds)
    sim._emulate_cop0 = emulate
    for _ in range(40):
        sim.run(max_instructions=sim.instruction_count + 200_000)
        if sim.mu.reg_read(UC_MIPS_REG_S1) >= 8:
            break
    check(skipped[0] == 1 and sim.native_cp0_repairs >= 1 and sim.mu.reg_read(UC_MIPS_REG_S1) >= 8,
          f"{name}: a native ERET is redone ({sim.native_cp0_repairs} repair(s)), "
          f"{sim.mu.reg_read(UC_MIPS_REG_S1)} ticks")

print("--- adopt")
sim = AliMipsSimulator(log_handler=lambda m: None)
sim.exact_count_threshold = 0
sim.calibration_slices = 0
load(sim, li(T1, 0x10000000) + [mtc0(T1, STATUS)] + IDLE)
sim.run(max_instructions=sim.instruction_count + 100_000)
sim.mu.reg_write(UC_MIPS_REG_CP0_STATUS, 0x1000FF00)
sim.run(max_instructions=sim.instruction_count + 100_000)
check(sim.cp0_status == 0x1000FF00, f"a Status written natively is taken over: 0x{sim.cp0_status:08X}")

print()
if fails:
    print(f"\033[91m{len(fails)} native-Status check(s) failed\033[0m")
    sys.exit(1)
print("\033[92mAll native-Status checks passed\033[0m")
