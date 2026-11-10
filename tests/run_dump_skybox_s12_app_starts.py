#!/usr/bin/env python3
"""
The Skybox S12 HD PVR firmware (bootloader "SMT---1.0.0", Application
1.0.0@M3606_DVBS2_SABBAT_20110323, ALi M3602, chips/m3602.py) boots on a 4 MB
SPI flash, prints "APP  init ok", unpacks its 5.91 MB maincode to 0x80000200,
and runs the single-CPU application.  The application drives the 3-wire
PT6964 / TM1628 front panel (PAN_PT_0) on CLK = GPIO 171, DIO = GPIO 62,
STB = GPIO 170 ("boot" -> "Strt" -> "OOO7"), configures the ALi S3501 DVB-S2
demodulator at I2C 0x33 and Sharp BS2S7HZ6306A tuner at I2C 0x60 on SCB0, and
draws its OSD through GeM3602.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = "SKYBOX S12/skybox s12.abs"
LIMIT = 75_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Skybox S12 HD PVR (M3602) boots into its application and drives its PT6964 panel ===")
uart = []
panel_texts = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)

panel, _, _ = make_panel(DUMP, log_handler=lambda m: None)
panel.on_frame = lambda _f: (
    t := panel.get_display_text(),
    panel_texts.append(t) if (not panel_texts or panel_texts[-1] != t) else None,
)
sim.setGpioHandler(panel.on_gpio_write)
sim.setUartHandler(lambda c: uart.append(c if isinstance(c, str) else chr(c)))
sim.loadFile(DUMP)

t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    if sim.ge_ops >= 40 and "OOO7" in panel_texts:
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), "
      f"ge_ops={sim.ge_ops}, panel_frames={panel.frame_count}, panel_texts={panel_texts}")

check(type(sim.chip).__name__ == "M3602" and sim.chip.chip_id == 0x3602,
      f"detected as M3602 with chip ID 0x3602 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check("APP  init ok" in text and text.count("APP  init ok") == 1,
      "bootloader banner 'APP  init ok' printed once on UART")
check(all(w in panel_texts for w in ("boot", "Strt", "OOO7")),
      f"3-wire PT6964/TM1628 panel on GPIO 171/62/170 shows 'boot' -> 'Strt' -> 'OOO7' (got {panel_texts})")
check(0x33 in sim.i2c_devices and len(sim.i2c_devices[0x33].regs) > 4,
      f"ALi S3501 DVB-S2 demodulator configured at I2C 0x33 ({len(sim.i2c_devices.get(0x33).regs) if 0x33 in sim.i2c_devices else 0} registers)")
check(sim.ge_ops >= 40,
      f"GeM3602 executed {sim.ge_ops} graphics engine commands")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Skybox S12 HD PVR (M3602) boots into its application and drives its PT6964 panel")
