"""
Helper for the run_dump_*_to_main_app regression tests: boot a firmware dump
in fast mode until its main application has printed its init banner, keep
running a little longer, and report what happened.

The banner comes from the application's main task after its first RTOS sleeps,
i.e. only once CP0 timer interrupts (IP7 ticks) are delivered; without them the
application parks in the RTOS idle task right after the bootloader's 'success!'.
"""
import time

from simulator import AliMipsSimulator
from unicorn.mips_const import UC_MIPS_REG_PC

BANNER_END = b"Application version"


def run_to_app_banner(fname, expected_len, limit_s=180.0, settle_s=3.0):
    """Run until expected_len UART bytes arrived (the banner is complete) or
    limit_s passed, then settle_s more seconds.  Returns a dict with the UART
    bytes, timer ticks before/after the settle time, the final PC, timings and
    any exception."""
    sim = AliMipsSimulator(log_handler=lambda msg: None)
    sim.setSPIDump(False)
    sim.setI2CDump(False)
    uart = bytearray()
    sim.setUartHandler(lambda c: uart.append(ord(c) & 0xFF))
    sim.loadFile(fname)

    res = dict(uart=b"", banner_s=None, ticks_at_banner=0, ticks=0, pc=None, error=None, null=False)
    t0 = time.time()
    try:
        while time.time() - t0 < limit_s and len(uart) < expected_len:
            sim.run(max_instructions=sim.instruction_count + 5_000_000)
            if (sim.mu.reg_read(UC_MIPS_REG_PC) & ~1) == 0:
                res['null'] = True
                break
        if len(uart) >= expected_len and not res['null']:
            res['banner_s'] = time.time() - t0
            res['ticks_at_banner'] = getattr(sim, 'timer_irq_count', 0)
            t1 = time.time()
            while time.time() - t1 < settle_s:          # the application keeps running
                sim.run(max_instructions=sim.instruction_count + 5_000_000)
                if (sim.mu.reg_read(UC_MIPS_REG_PC) & ~1) == 0:
                    res['null'] = True
                    break
    except Exception as e:                               # a crash is a test failure, not an abort
        res['error'] = f"{type(e).__name__}: {e}"
    res['uart'] = bytes(uart)
    res['ticks'] = getattr(sim, 'timer_irq_count', 0)
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
    print(f"\n[{'PASS' if ok else 'FAIL'}] {title}")
    return ok
