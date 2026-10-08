"""
Test: SPI command-mode reads of the flash window, in every execution mode.

The flash read hook that serves SPI command responses is the simulator's only
Unicorn memory hook, and it only exists during SPI command mode: Unicorn
decides per translation block (when translating it) whether its loads see
memory hooks, and while one exists every load is slow.  So the hook is only
installed / removed between emu_start() calls: entering command mode without it
stops the emulation right at the SF_INS store, and the next emu_start()
installs it and flushes the translated code; leaving command mode does the same
to remove it (simulator.py, _update_flash_read_hooks).  Added from inside the
device callback instead, the rest of the running block read stale flash bytes
(and that version crashed Unicorn natively in 7-30% of the boots).

The program loops N times over:  SF_INS = 0x9F (JEDEC ID) ; four lbu of the
flash window in the same block ; SF_INS = 0x03 (normal read) ; one lbu.
Every response must be EF 40 16 00, and the normal read must return the flash
byte (0x5A), never a leftover response byte.

  idle0   - SPI dump logging on (without flash_reads), flash_hook_idle_s = 0:
            the hook comes and goes with every command phase (2 changes per
            round), and each SF_INS store is processed once although the
            stops make it execute twice (replay guard: one 'CMD' log line each)
  default - the constructor default (flash_hook_idle_s = 0.05 s): through
            these dense command phases the hook stays installed
  hold    - flash_hook_idle_s large: installed once, stays
  toggle  - short run() calls, flash_hook_idle_s = 0: the hook changes at many
            emu_start() boundaries

plus: a default AliMipsSimulator has no Unicorn memory hook (no slow loads)
before and after running code that never enters command mode.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import struct
import time

from test_cp0_timer_interrupt import (MODES, EPC_LOG, ZERO, T1, T2, T3, T4, T5, S0, S1, S4, NOP,
                                      addiu, lui, li, beq, check, make_sim, run_until)
from test_device_models import lbu, sb, bne
from unicorn.mips_const import UC_MIPS_REG_S0

T6, T7, S6 = 14, 15, 22
N = 2000
JEDEC = bytes([0xEF, 0x40, 0x16, 0x00])
FLASH_BYTE = 0x5A


def program():
    body = [addiu(T4, ZERO, 0x9F), sb(T4, 0, T1),                          # SF_INS = JEDEC read ID
            lbu(T5, 0, T3), lbu(T6, 1, T3), lbu(T7, 2, T3), lbu(T2, 3, T3),  # response, same block
            sb(T5, 0, S4), sb(T6, 1, S4), sb(T7, 2, S4), sb(T2, 3, S4),
            addiu(T4, ZERO, 0x03), sb(T4, 0, T1),                          # SF_INS = normal read
            lbu(T5, 0, T3), sb(T5, 4, S4),                                 # flash byte 0
            addiu(S4, S4, 5), addiu(S0, S0, 1)]
    body += [bne(S0, S1, -(len(body) + 1)), NOP]
    return (li(T1, 0xB802E098) + li(T3, 0xAFC00000) + [lui(S4, EPC_LOG >> 16)] + li(S1, N) + body +
            [addiu(S6, ZERO, 1), beq(ZERO, ZERO, -1), NOP])


def scenario(mode, variant, fails):
    sim = make_sim(mode, program(), [NOP])
    spi_lines = []
    if variant == 'idle0':
        sim.setSpiHandler(spi_lines.append)         # logging on (default), collected
    else:
        sim.setSPIDump(False)
    sim.rom_image[0] = FLASH_BYTE
    sim.mu.mem_write(sim.base_addr, bytes([FLASH_BYTE]))
    done = lambda s: s.mu.reg_read(UC_MIPS_REG_S0) >= N
    if variant == 'hold':
        sim.flash_hook_idle_s = 1e9
    elif variant in ('idle0', 'toggle'):
        sim.flash_hook_idle_s = 0.0
    if variant == 'toggle':
        t0 = time.time()
        while not done(sim) and time.time() - t0 < 90:
            sim.run(max_instructions=sim.instruction_count + 300)
    else:
        run_until(sim, mode, 25 * N, done, wall=90.0)
    n = sim.mu.reg_read(UC_MIPS_REG_S0)
    log = bytes(sim.mu.mem_read(EPC_LOG, 5 * n))
    bad_resp = sum(1 for i in range(n) if log[5 * i:5 * i + 4] != JEDEC)
    bad_read = sum(1 for i in range(n) if log[5 * i + 4] != FLASH_BYTE)
    first = next((i for i in range(n) if log[5 * i:5 * i + 4] != JEDEC or log[5 * i + 4] != FLASH_BYTE), None)
    tag = f"[{mode}, {variant}]"
    check(n >= N, f"{tag} all {N} command / read rounds ran ({n})", fails)
    check(bad_resp == 0, f"{tag} every JEDEC response read in the same block is EF 40 16 00 "
                         f"({bad_resp} wrong{'' if first is None else ', first at round %d: %s' % (first, log[5 * first:5 * first + 5].hex())})", fails)
    check(bad_read == 0, f"{tag} normal-mode reads return the flash byte, no leftover response ({bad_read} wrong)", fails)
    if variant == 'idle0':
        cmds = sum(1 for m in spi_lines if 'CMD 0x' in m)
        check(cmds == 2 * n and sim.flash_hook_changes >= 2 * n - 1,
              f"{tag} the hook comes and goes with each command phase ({sim.flash_hook_changes} changes) and "
              f"each SF_INS store is processed once despite the stops ({cmds} CMD lines for {2 * n} stores)", fails)
        check(not any('FLASH READ' in m for m in spi_lines),
              f"{tag} normal-mode flash reads are not logged without flash_reads=True", fails)
    elif variant == 'default':
        check(sim.flash_hook_idle_s == 0.05 and 1 <= sim.flash_hook_changes <= 3,
              f"{tag} with the default idle time the hook stays through dense command phases "
              f"({sim.flash_hook_changes} changes for {n} rounds)", fails)
    elif variant == 'hold':
        check(sim.flash_hook_changes == 1,
              f"{tag} the flash read hook was installed once and stayed ({sim.flash_hook_changes} changes)", fails)
    else:
        check(sim.flash_hook_changes >= 10,
              f"{tag} the flash read hook was installed / removed many times ({sim.flash_hook_changes})", fails)


def scenario_no_hook_by_default(fails):
    from simulator import AliMipsSimulator
    sim = AliMipsSimulator(log_handler=lambda m: None)          # SPI dump logging on by default
    sim.setSpiHandler(lambda m: None)
    before = list(sim._flash_read_hooks)
    main = li(T3, 0xAFC00000) + [lbu(T5, 0, T3), addiu(S0, S0, 1), beq(ZERO, ZERO, -3), NOP]
    sim.mu.mem_write(0x80100000, struct.pack(f'<{len(main)}I', *main))
    from unicorn.mips_const import UC_MIPS_REG_PC
    sim.mu.reg_write(UC_MIPS_REG_PC, 0x80100000)
    sim.run(max_instructions=sim.instruction_count + 50_000)
    check(before == [] and sim._flash_read_hooks == [] and sim.flash_hook_changes == 0,
          "a default simulator (SPI dump logging on) has no Unicorn memory hook, also after flash reads "
          "in normal mode", fails)
    sim.setSPIDump(True, flash_reads=True)
    check(len(sim._flash_read_hooks) > 0, "setSPIDump(True, flash_reads=True) installs it (to log reads)", fails)


def main():
    print("=== Test: SPI command-mode flash reads (flash read hook installed between slices) ===")
    fails = []
    scenario_no_hook_by_default(fails)
    for mode in MODES:
        for variant in ('idle0', 'default', 'hold', 'toggle'):
            scenario(mode, variant, fails)
    if fails:
        print(f"\n\033[91m{len(fails)} check(s) failed\033[0m")
    else:
        print("\n\033[92mAll SPI command-mode checks passed\033[0m")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
