#!/usr/bin/env python3
"""
The GTMedia V9 Super mass-production firmware V400 (V210.400, 2020-10-20; dual-CPU
ALi M3505 / C3505, chips/c3505.py) boots its "M3505---0.1.0" boot-ROM bootloader
at 0x9FE00800 on an 8 MB SPI flash, writes "boot" (0xB6, 0x36, 0x36, 0xA6) to its
FD650 4-digit 7-segment display on GPIO 107 (SCL) / 110 (SDA), unpacks its 8.89 MB
Main Code to 0x80000200 and M3505 SEE to 0xA6000200, launches the SEE core, and
renders its 1280x720 "Factory Test Page" OSD through the GE and display-engine
list DMA.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = "GTMEDIA V9 SUPER/GTMedia_V9Super_MP_20201020_v400.bin"
LIMIT = 150_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: GTMedia V9 Super V400 (C3505) boots into its application ===")
panel_texts = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)

panel, _, panel_desc = make_panel(DUMP, log_handler=lambda m: None)
panel.dump_enabled = False
sim.setGpioHandler(panel.on_gpio_write)
sim.loadFile(DUMP)

t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    cur = panel.get_display_text()
    if cur.strip() and (not panel_texts or panel_texts[-1] != cur):
        panel_texts.append(cur)
    if sim.ge_ops >= 5000 and panel.get_display_text() == "Strt" and panel.i2c_transaction_count >= 50:
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), "
      f"ge_ops={sim.ge_ops}, panel_tx={panel.i2c_transaction_count}, panel_texts={panel_texts}")

check(type(sim.chip).__name__ == "C3505" and sim.chip.chip_id == 0x3505,
      f"detected as C3505 with chip ID 0x3505 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check(sim.chip.see.run_program and len(sim.chip.see.starts) >= 1 and sim.chip.see.starts[0][0] == 0xA6000200,
      f"SEE second core started at 0xA6000200 (starts={sim.chip.see.starts})")
check(panel.i2c_transaction_count >= 50 and "boot" in panel_texts and panel.get_display_text() == "Strt",
      f"FD650 front panel ({panel_desc}) transitioned from 'boot' to {panel.get_display_text()!r} ({panel.i2c_transaction_count} transactions, texts={panel_texts})")
check(sim.ge_ops >= 5000,
      f"GE executed {sim.ge_ops} commands drawing the Factory Test Page OSD")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] GTMedia V9 Super V400 (C3505) boots into its application")
