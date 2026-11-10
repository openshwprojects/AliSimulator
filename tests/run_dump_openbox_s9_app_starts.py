#!/usr/bin/env python3
"""
The Openbox S9 HD PVR firmware (4 MB SPI flash, System ID HDS2_S9 by anonymouSX)
runs on the single-core ALi M3602 platform (chips/m3602.py with chip ID 0x3602,
bootloader "  HACK S9  ").

The bootloader unpacks the maincode chunk (0x10000) via LZMA to 0x80000200 and
jumps to 0x80000200.  The single-CPU application prints 'APP  init ok' on UART,
initializes the single-core M3602 environment (no secondary SEE core spawned),
drives the TM1628-class 3-wire front panel (CLK = GPIO 171, DIO = GPIO 62, STB = GPIO 170)
through 'AHAH' -> '1N1t' -> 'OOO2', and renders the OSD interface by issuing
hundreds of graphics engine (GeM3602) commands.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = "OPENBOX S9/HDS2_S9_by_anonymouSX.abs"
LIMIT = 50_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Openbox S9 HD PVR (ALi M3602 single-core) boots into its application ===")
uart = []
panel_texts = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)

panel, _, _ = make_panel(DUMP, log_handler=lambda m: None)
sim.setGpioHandler(panel.on_gpio_write)
sim.setUartHandler(lambda c: uart.append(c if isinstance(c, str) else chr(c)))
sim.loadFile(DUMP)

t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    cur = panel.get_display_text()
    if cur and (not panel_texts or panel_texts[-1] != cur):
        panel_texts.append(cur)
    if sim.ge_ops >= 20 and "1N1t" in panel_texts:
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), "
      f"ge_ops={sim.ge_ops}, panel_texts={panel_texts}")

check(type(sim.chip).__name__ == "M3602" and sim.chip.chip_id == 0x3602,
      f"detected as M3602 with chip ID 0x3602 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check("APP  init ok" in text, "'APP  init ok' printed on UART")
check("1N1t" in panel_texts,
      f"TM1628 panel on GPIO 171 / 62 / 170 shows boot sequence (texts={panel_texts})")
check(sim.ge_ops >= 20, f"GeM3602 executed {sim.ge_ops} graphics engine commands")
see = getattr(sim.chip, "see", None)
check(see is None or not see.starts, "single-CPU M3602: no secondary SEE core spawned")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Openbox S9 HD PVR (ALi M3602 single-core) boots into its application")
