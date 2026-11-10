#!/usr/bin/env python3
"""
The AB CryptoBox 500HD satellite receiver firmware (4 MB SPI flash) runs on
the dual-core ALi M3606 platform (chips/m3602.py with chip ID 0x3603).

The bootloader ("DVBS2---0.2.0") unpacks the encrypted maincode chunk container
at 0x20000 via LZMA to 0x80000200 and the SEE co-processor code.
The application prints 'model = 2:500HD', 'Soft Version = 14293', 'MC: APP  init ok',
and continuously updates the front panel.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for

DUMP = "AB CRYPTOBOX 500HD/500HD_Patch_V1.09.14293_13-07-2015_A.abs"
LIMIT = 60_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: AB CryptoBox 500HD (ALi M3606) boots into its application ===")
uart = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.setUartHandler(lambda c: uart.append(c if isinstance(c, str) else chr(c)))
sim.loadFile(DUMP)

t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    try:
        sim.run(max_instructions=sim.instruction_count + SLICE)
    except Exception:
        break
    text = "".join(uart)
    if "500HD" in text and ("Soft Version" in text or "MC: APP" in text):
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s)")

check(type(sim.chip).__name__ == "M3602" and sim.chip.chip_id == 0x3603,
      f"detected as M3602 with chip ID 0x3603 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check("500HD" in text, "'500HD' identified on UART")
check("Soft Version" in text or "MC: APP" in text, "application banner printed on UART")
see = getattr(sim.chip, "see", None)
check(see is not None and len(see.starts) >= 1, "SEE co-processor started")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] AB CryptoBox 500HD (ALi M3606) boots into its application")
