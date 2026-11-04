#!/usr/bin/env python3
"""
The Amiko Micro HD (Galaxy v1.5.57 by Dekolte, single-CPU ALi M3612 / M3801 with 8 MB SPI
flash, chips/m3801.py) boots its "M3612 1.0.4" bootloader, prints
"bl_panel_init! / -->>ch455!!" and writes " ON " -> "-ON-" to its
CH455 front panel on GPIO 31 / 9, unpacks maincode(AV) to 0x80000200, moves CP0
EBase to 0x80002000, configures its ALi S3501 DVB-S2 demodulator at I2C 0x33 on
SCB0, and draws its 1280x720 OSD dialog through GeM36F / GMA layer 0.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = "AMIKO MICRO HD/AMIKO_MicroHD_Galaxy_1.5.57_by Dekolte.abs"
LIMIT = 95_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Amiko Micro HD (Galaxy v1.5.57 by Dekolte) boots into its application ===")
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
    if sim.ge_ops >= 9 and panel.get_display_text() in (" on ", "-ON-") and 0x33 in sim.i2c_devices and len(sim.i2c_devices[0x33].regs) > 4:
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), "
      f"ge_ops={sim.ge_ops}, panel_texts={panel_texts}")

check(type(sim.chip).__name__ == "M3801" and sim.chip.chip_id == 0x3811,
      f"detected as M3801 with chip ID 0x3811 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check(" ON " in panel_texts and panel.get_display_text() in (" on ", "-ON-"),
      f"CH455 panel on GPIO 31 / 9 updated from ' ON ' to {panel.get_display_text()!r} (texts={panel_texts})")
for expected in ("APP  init ok", "bl_panel_init!", "-->>ch455!!"):
    check(expected in text, f"{expected!r} printed on UART")
check("nim S3501 attach nim_reg_read error" not in text and 0x33 in sim.i2c_devices and len(sim.i2c_devices[0x33].regs) > 4,
      f"ALi S3501 DVB-S2 demodulator attached without error at I2C 0x33 ({len(sim.i2c_devices[0x33].regs)} registers)")
check((sim.cp0_ebase & 0xFFFFF000) == 0x80002000,
      f"CP0 EBase moved to 0x80002000 (got 0x{sim.cp0_ebase:08X})")
check(sim.ge_ops >= 9, f"GeM36F executed {sim.ge_ops} graphics engine commands")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Amiko Micro HD (Galaxy v1.5.57 by Dekolte) boots into its application")
