#!/usr/bin/env python3
"""
The Amiko HD8140 T2/C firmware v1.5.43 EMU (single-CPU ALi M3612 / S3811,
chips/m3801.py: chip ID 0x3811) boots through its MIPS16e bootloader at
0x81E80000, writes " ON " to its CH455 4-digit panel on GPIO 31 (SCL) / 9 (SDA),
verifies and unpacks its maincode(AV) to 0x80000200, moves CP0 EBase to
0x80002000, probes its external Availink AVL6862 demodulator on SCB0 at I2C 0x14
(ChipID 0x0F, demods.AVL6862A), configures its Sharp VZ7903 / AV2012 (0x61) and
Rafael Micro R836 DVB-T2/C tuner (0x3A), updates the CH455 display, and renders
its 1280x720 OSD dialog through GeM36F / GMA layer 0.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = "AMIKO HD8140 T2C/AMIKO_HD8140_T2C_1.5.43_emu.abs"
LIMIT = 100_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Amiko HD8140 T2/C (v1.5.43 EMU) (ALi M3612 / M3801) boots into its application ===")
uart = []
panel_texts = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)

panel, _, _ = make_panel(DUMP, log_handler=lambda m: None)
sim.setGpioHandler(panel.on_gpio_write)
sim.setUartHandler(lambda c: uart.append(c if isinstance(c, str) else chr(c)))
sim.loadFile(DUMP)
sim.attach_tuner()

t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    cur = panel.get_display_text()
    if cur and (not panel_texts or panel_texts[-1] != cur):
        panel_texts.append(cur)
    if sim.ge_ops >= 8 and panel.get_display_text() in (" on ", "-ON-", "boot"):
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), "
      f"ge_ops={sim.ge_ops}, panel_texts={panel_texts}")

check(type(sim.chip).__name__ == "M3801" and sim.chip.chip_id == 0x3811,
      f"detected as M3801 with chip ID 0x3811 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check(" ON " in panel_texts and panel.get_display_text() in (" on ", "-ON-", "boot"),
      f"CH455 panel on GPIO 31 / 9 updated from ' ON ' to {panel.get_display_text()!r} (texts={panel_texts})")
for expected in ("APP  init ok", "bl_panel_init!", "-->>ch455!!"):
    check(expected in text, f"{expected!r} printed on UART")
avl = sim.i2c_devices.get(0x14)
av2012 = sim.i2c_devices.get(0x61)
r836 = sim.i2c_devices.get(0x3A)
check(avl is not None and avl.writes > 20 and avl.reads > 10,
      f"Availink AVL6862A answered on SCB0 at I2C 0x14 (writes={getattr(avl, 'writes', 0)}, reads={getattr(avl, 'reads', 0)})")
check(av2012 is not None and av2012.writes > 5 and r836 is not None and r836.writes > 20,
      f"Sharp VZ7903 / AV2012 (0x61 writes={getattr(av2012, 'writes', 0)}) and R836 (0x3A writes={getattr(r836, 'writes', 0)}) configured")
check((sim.cp0_ebase & 0xFFFFF000) == 0x80002000,
      f"CP0 EBase moved to 0x80002000 (got 0x{sim.cp0_ebase:08X})")
check(sim.ge_ops >= 8, f"GeM36F executed {sim.ge_ops} graphics engine commands")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Amiko HD8140 T2/C (v1.5.43 EMU) (ALi M3612 / M3801) boots into its application")
