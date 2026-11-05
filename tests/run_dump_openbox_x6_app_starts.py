#!/usr/bin/env python3
"""
Regression test for the Openbox X6 HD 4 MB SPI flash dump
(Openbox X6 HD.abs, ALi M3606 / M3602, chips/m3602.py).

The bootloader unpacks seecode to 0xA1A00200, starts the SEE core at 0xA1E8F0BC,
and unpacks 5.46 MB of maincode to SDRAM at 0x80000200.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for

DUMP = "OPENBOX X6 HD/Openbox X6 HD.abs"
LIMIT = 25_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Openbox X6 HD bootloader unpacks seecode and maincode ===")
uart1 = []

sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.setUartHandler(lambda c: uart1.append(c if isinstance(c, str) else chr(c)))

sim.loadFile(DUMP)
sim.run(max_instructions=LIMIT)

check(type(sim.chip).__name__ == "M3602", f"detected as M3602 (got {type(sim.chip).__name__})")
check(sim.instruction_count >= 10_000_000, f"bootloader executed ({sim.instruction_count} instructions)")
check(len(sim.lzma_decodes) >= 2, f"unpacked both seecode and maincode stages ({len(sim.lzma_decodes)} LZMA decodes)")

if hasattr(sim.chip, "see"):
    check(len(sim.chip.see.starts) > 0, f"SEE core started by main CPU ({len(sim.chip.see.starts)} start(s))")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Openbox X6 HD bootloader unpacks seecode and maincode")
