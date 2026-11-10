#!/usr/bin/env python3
"""
The AB CryptoBox 652HD Combo receiver firmware (8 MB SPI flash) runs on
the ALi M3516 dual-core combo platform (chips/m3503.py revision B with chip ID 0x3503).

The bootloader ("DVBS2---0.2.0") sets up its stack in cache-as-RAM, unpacks the
split SEE co-processor code and maincode.  The application moves exception
vectors to 0x80002000, starts the SEE program at 0x86000200, prints 'model = 4:652HD COMBO',
'Soft Version = 19423', 'MC: APP  init ok', and drives the front panel.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for

DUMP = "AB CRYPTOBOX 652HD COMBO/652HD_V1.11.19423_09-05-2018.abs"
LIMIT = 75_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: AB CryptoBox 652HD Combo (ALi M3516) boots into its application ===")
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
    if "MC: APP  init ok" in text and "652HD" in text:
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s)")

check(type(sim.chip).__name__ == "M3503" and sim.chip.chip_id == 0x3503,
      f"detected as M3503 with chip ID 0x3503 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check("MC: APP  init ok" in text, "'MC: APP  init ok' printed on UART")
check("652HD" in text, "'652HD' identified on UART")
see = getattr(sim.chip, "see", None)
check(see is not None and len(see.starts) >= 1, "SEE co-processor started")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] AB CryptoBox 652HD Combo (ALi M3516) boots into its application")
