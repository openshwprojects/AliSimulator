"""
Shared body of the front-panel regressions: boot a firmware dump with its panel
decoder attached (front_panel.make_panel) and stop as soon as the decoded
display shows the expected text.  Exits the process with the test's result.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

import report_artifacts
from front_panel import make_panel
from simulator import AliMipsSimulator

SLICE = 1_000_000           # instructions between checks of the display


def run(dump, expected=" ON ", max_instructions=5_000_000, title=None):
    """Boot `dump` until its front panel shows `expected` (a 4-character
    string, see PanelDecoder.get_display_text) or max_instructions passed."""
    title = title or f"{dump} shows [{expected}] on its front panel"
    print(f"=== Regression Test: {title} ===")
    sim = AliMipsSimulator(log_handler=lambda msg: None)
    sim.setSPIDump(False)
    panel, _keys, desc = make_panel(dump, log_handler=lambda msg: print(msg) if msg.startswith(panel.TAG) else None)
    sim.setGpioHandler(panel.on_gpio_write)
    sim.setI2CDump(False)
    print(f"panel: {desc}")
    try:
        sim.loadFile(dump)
    except FileNotFoundError:
        print(f"{dump} not found")
        sys.exit(1)

    print("Running simulator...", flush=True)
    start = time.time()
    while sim.instruction_count < max_instructions and panel.get_display_text() != expected:
        sim.run(max_instructions=min(max_instructions, sim.instruction_count + SLICE))
    duration = time.time() - start
    shown = panel.get_display_text()
    report_artifacts.panel(panel.digits, f"front panel ({panel.TAG.strip('[]')}) when the test stopped", shown)
    ok = shown == expected
    print(f"\n[{'PASS' if ok else 'FAIL'}] display shows [{shown}]{'' if ok else f', expected [{expected}]'} "
          f"after {duration:.2f}s, {panel.i2c_transaction_count} transactions")
    sys.exit(0 if ok else 1)
