#!/usr/bin/env python3
"""Verify that Amiko Mini HD Combo (System ID 0E060A00, v1.5.41 EMU) boots into its application and renders OSD."""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = "AMIKO MINI HD COMBO/AMIKO_MiniHD_Combo_1.5.41_emu.abs"
LIMIT = 110_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Amiko Mini HD Combo (v1.5.41 EMU) boots into its application ===")
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
    if sim.ge_ops >= 5 and panel.get_display_text() in (" on ", "-ON-"):
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), "
      f"ge_ops={sim.ge_ops}, panel_texts={panel_texts}")

check(type(sim.chip).__name__ == "M3801" and sim.chip.chip_id == 0x3811,
      f"detected as M3801 with chip ID 0x3811 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check(panel.get_display_text() in (" on ", "-ON-"),
      f"front panel updated to {panel.get_display_text()!r} (texts={panel_texts})")
for expected in ("APP  init ok", "bl_panel_init!", "-->>ch455!!"):
    check(expected in text, f"{expected!r} printed on UART")
check((sim.cp0_ebase & 0xFFFFF000) == 0x80002000,
      f"CP0 EBase at 0x80002000 (got 0x{sim.cp0_ebase:08X})")
check(sim.ge_ops >= 5, f"GE executed {sim.ge_ops} graphics commands")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Amiko Mini HD Combo (v1.5.41 EMU) boots into its application")
