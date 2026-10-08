"""
Helper for the run_dump_*_to_main_app regression tests: boot a firmware dump
in fast mode until its main application has printed its init banner, keep
running until its init got past the hardware waits that used to stall it, and
report what happened.

The banner comes from the application's main task after its first RTOS sleeps,
i.e. only once CP0 timer interrupts (IP7 ticks) are delivered; without them the
application parks in the RTOS idle task right after the bootloader's 'success!'.
After the banner the init starts the PMU (0xB8018D02: sets bit 0x80, polls bit
0x20 with udelay(2000), up to 36,848 times = 6-7 minutes) and opens the video
capture (0xB800F04B: sets bit 0 and spins until it clears, no timeout).
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

from simulator import AliMipsSimulator
from unicorn.mips_const import UC_MIPS_REG_PC

BANNER_END = b"Application version"
PMU, VCAP = 0x018D02, 0x00F04B        # status bytes, offset in the 0x18000000 / 0xB8000000 window
MAX_POLLS = 16                         # a completed handshake takes a few reads; a stall thousands


def _count_reads(sim, counts):
    """Count the byte reads of the status bytes (the drivers' polling loops).
    (sim.add_mmio_hook, not a Unicorn memory hook: those slow every RAM access.)"""
    def hook(uc, access, address, size, value, user_data):
        counts[address & 0xFFFFFF] += 1
    for reg in (PMU, VCAP):
        sim.add_mmio_hook('read', hook, reg, reg)


def run_to_app_banner(fname, expected_len, limit_s=180.0, settle_s=3.0, init_limit_s=60.0):
    """Run until expected_len UART bytes arrived (the banner is complete) or
    limit_s passed; then until the VCAP register was read (or init_limit_s),
    then settle_s more seconds.  Returns a dict with the UART bytes, timer
    ticks before/after, the PMU / VCAP read counts, the final PC, timings and
    any exception."""
    sim = AliMipsSimulator(log_handler=lambda msg: None)
    sim.setSPIDump(False)
    sim.setI2CDump(False)
    uart = bytearray()
    sim.setUartHandler(lambda c: uart.append(ord(c) & 0xFF))
    sim.loadFile(fname)
    polls = {PMU: 0, VCAP: 0}
    _count_reads(sim, polls)

    res = dict(uart=b"", banner_s=None, ticks_at_banner=0, ticks=0, pc=None, error=None, null=False,
               init_s=None)
    t0 = time.time()

    def run_while(cond, limit):
        t = time.time()
        while time.time() - t < limit and cond():
            sim.run(max_instructions=sim.instruction_count + 5_000_000)
            if (sim.mu.reg_read(UC_MIPS_REG_PC) & ~1) == 0:
                res['null'] = True
                return

    try:
        run_while(lambda: len(uart) < expected_len, limit_s)
        if len(uart) >= expected_len and not res['null']:
            res['banner_s'] = time.time() - t0
            res['ticks_at_banner'] = sim.timer_irq_count
            run_while(lambda: polls[VCAP] == 0, init_limit_s)
            if polls[VCAP]:
                res['init_s'] = time.time() - t0
            if not res['null']:
                run_while(lambda: True, settle_s)       # the application keeps running
    except Exception as e:                               # a crash is a test failure, not an abort
        res['error'] = f"{type(e).__name__}: {e}"
    res['uart'] = bytes(uart)
    res['ticks'] = sim.timer_irq_count
    res['pmu_polls'], res['vcap_polls'] = polls[PMU], polls[VCAP]
    res['pc'] = sim.mu.reg_read(UC_MIPS_REG_PC)
    res['elapsed_s'] = time.time() - t0
    return res


def report(title, res, expected):
    """Print the checks; returns True if all passed."""
    ok = True

    def check(cond, msg):
        nonlocal ok
        print(("  [PASS] " if cond else "  [FAIL] ") + msg)
        ok &= bool(cond)

    print(f"  ran {res['elapsed_s']:.1f}s, banner at "
          f"{'-' if res['banner_s'] is None else '%.1fs' % res['banner_s']}, "
          f"VCAP opened at {'-' if res['init_s'] is None else '%.1fs' % res['init_s']}, "
          f"{res['ticks']} timer interrupts, PC=0x{res['pc']:08X}")
    check(res['error'] is None and not res['null'],
          f"no crash ({res['error'] or ('jump to NULL' if res['null'] else 'ok')})")
    check(res['uart'] == expected,
          f"UART output is exactly the expected {len(expected)} bytes (bootloader lines + application banner; "
          f"no duplicated or lost characters)")
    if res['uart'] != expected:
        n = next((i for i, (a, b) in enumerate(zip(res['uart'], expected)) if a != b),
                 min(len(res['uart']), len(expected)))
        print(f"         first difference at byte {n}: got {res['uart'][max(0, n - 20):n + 40]!r}")
        print(f"         expected                    {expected[max(0, n - 20):n + 40]!r}")
    check(res['ticks_at_banner'] > 0, f"the application ran on CP0 timer ticks ({res['ticks_at_banner']} "
                                      f"before the banner completed)")
    check(res['ticks'] > res['ticks_at_banner'],
          f"and keeps ticking afterwards (+{res['ticks'] - res['ticks_at_banner']})")
    check(1 <= res['pmu_polls'] <= MAX_POLLS,
          f"PMU start/ready handshake (0xB8018D02 bit 0x80 -> 0x20) completed: {res['pmu_polls']} reads "
          f"(unmodelled: polled up to 36,848 times, 6-7 minutes)")
    check(1 <= res['vcap_polls'] <= MAX_POLLS,
          f"VCAP busy bit (0xB800F04B bit 0) cleared: {res['vcap_polls']} reads "
          f"(unmodelled: endless spin)")
    print(f"\n[{'PASS' if ok else 'FAIL'}] {title}")
    return ok
