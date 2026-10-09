"""
Shared body of the UART regressions (run_dump_*_to_*.py, run_dump_no_main_app.py,
run_dump_with_bad_flash_id.py): boot a firmware dump, stop as soon as `stop_at`
shows up on its UART, and check what it printed.

The UART output is echoed as it comes (the first 1000 characters, then
suppressed).  `expected` are strings that must appear in the output; with
ordered=True they must be the first lines printed, in that order (a line may
go on: the firmware prints extra '!' after bl_flash_init).  Exits the process
with the test's result.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

from simulator import AliMipsSimulator

ECHO_CHARS = 1000           # UART characters echoed to stdout before the echo is suppressed


def run(dump, stop_at=None, expected=(), ordered=False, max_instructions=2_000_000, title=None,
        truncate_to=None, setup=None):
    """Boot `dump` (its first truncate_to bytes when given; setup(sim) runs
    before the load), run until `stop_at` appears on the UART or
    max_instructions passed, then check for the expected strings."""
    title = title or f"{dump} prints {stop_at!r}"
    print(f"=== Regression Test: {title} ===")
    sim = AliMipsSimulator(log_handler=lambda msg: None)
    sim.setSPIDump(False)
    sim.setI2CDump(False)
    if setup:
        setup(sim)
    uart = []

    def on_uart(char):
        uart.append(char)
        if len(uart) < ECHO_CHARS:
            sys.stdout.write(char)
            sys.stdout.flush()
        elif len(uart) == ECHO_CHARS:
            sys.stdout.write("\n[... output suppressed due to flooding ...]\n")
        if stop_at and stop_at in "".join(uart[-len(stop_at) - 8:]):
            sim.mu.emu_stop()

    sim.setUartHandler(on_uart)
    try:
        if truncate_to:
            sim.loadFileTruncated(dump, truncate_to)
        else:
            sim.loadFile(dump)
    except FileNotFoundError:
        print(f"{dump} not found")
        sys.exit(1)

    print("Running simulator...", flush=True)
    start = time.time()
    try:
        sim.run(max_instructions=max_instructions)
    except Exception as e:
        print(f"\nSimulator stopped: {e}")
    text = "".join(uart)
    print(f"\n\nTest finished in {time.time() - start:.2f}s")

    ok = True
    if ordered:
        # the lines as printed: no control characters, no blank lines
        cleaned = text.replace("\r\n", "\n").replace("\r", "\n")
        cleaned = "".join(c for c in cleaned if c == "\n" or c.isprintable())
        lines = [l.strip() for l in cleaned.split("\n") if l.strip()]
        for i, s in enumerate(expected):
            got = lines[i] if i < len(lines) else None
            hit = got is not None and got.startswith(s)
            print(f"  [{'PASS' if hit else 'FAIL'}] line {i} is {s!r}" + ("" if hit else f" (got {got!r})"))
            ok &= hit
    else:
        for s in expected:
            hit = s in text
            print(f"  [{'PASS' if hit else 'FAIL'}] {s!r} {'found' if hit else 'NOT found'} in the UART output")
            ok &= hit
    if not ok:
        print(f"UART output captured: {text!r}")
    print(f"\n[{'PASS' if ok else 'FAIL'}] {title}")
    sys.exit(0 if ok else 1)
