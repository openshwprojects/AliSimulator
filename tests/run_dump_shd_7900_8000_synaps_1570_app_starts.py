#!/usr/bin/env python3
"""Verify that Amiko SHD-7900 / SHD-8000 (System ID 06020A00, Synaps v1.5.70 by Dekolte) (AMIKO_SHD-7900-8000_Synaps_1.5.70_by Dekolte.abs) boots into its application and renders OSD."""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = 'AMIKO SHD-8000/AMIKO_SHD-7900-8000_Synaps_1.5.70_by Dekolte.abs'
LIMIT = 95_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Amiko SHD-7900 / SHD-8000 (System ID 06020A00, Synaps v1.5.70 by Dekolte) boots into its application ===")
uart = []
panel_texts = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)

panel, _, _ = make_panel(DUMP, log_handler=lambda m: None)
sim.setGpioHandler(panel.on_gpio_write)
sim.setUartHandler(lambda ch: uart.append(ch if isinstance(ch, str) else chr(ch)))
sim.loadFile(DUMP)
sim.attach_tuner()

t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    cur = panel.get_display_text()
    if cur and (not panel_texts or panel_texts[-1] != cur):
        panel_texts.append(cur)
    if sim.ge_ops >= 8 and panel.get_display_text() == '-ON-':
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), "
      f"ge_ops={sim.ge_ops}, panel_texts={panel_texts}")

check(type(sim.chip).__name__ == 'M3602' and sim.chip.chip_id == 0x3602,
      f"detected as M3602 with chip ID 0x3602 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check(panel.get_display_text() == '-ON-',
      f"front panel updated to '-ON-' (texts={panel_texts})")
for expected in ('APP  init ok', '---nim 3501 a-=[1]--type=[0x350100c0]----', 'Starting mcas v.1.0'):
    check(expected in text, f"{expected!r} printed on UART")
check((sim.cp0_ebase & 0xFFFFF000) == 0x80000000,
      f"CP0 EBase at 0x80000000 (got 0x{sim.cp0_ebase:08X})")
check(sim.ge_ops >= 8, f"GE executed {sim.ge_ops} graphics commands")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Amiko SHD-7900 / SHD-8000 (System ID 06020A00, Synaps v1.5.70 by Dekolte) boots into its application")
