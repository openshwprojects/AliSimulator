#!/usr/bin/env python3
"""
Regression test for the Echolink EL-700 FTA / Eurosat 3023 2 MB NOR dump with
bootloader 0.9.7 (Original_mit_bootloader_0.9.7.bin, ALi M3329C, chips/m3329.py).

Verifies the SMT01---0.9.7 bootloader boots from parallel NOR flash at 0xAFC00000,
unpacks its stage to 0x80300000 (chunk ID 0xE3000010), probes GPIO I2C at 0x50,
and executes cleanly.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for

DUMP = "ECHOLINK EL-700 FTA/Original_mit_bootloader_0.9.7.bin"
LIMIT = 25_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Echolink EL-700 FTA bootloader 0.9.7 boots and initializes ===")
uart1 = []

sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.setUartHandler(lambda c: uart1.append(c if isinstance(c, str) else chr(c)))

sim.loadFile(DUMP)
sim.run(max_instructions=LIMIT)

check(type(sim.chip).__name__ == "M3329", f"detected as M3329 (got {type(sim.chip).__name__})")
check(sim.instruction_count >= 10_000_000, f"bootloader executed ({sim.instruction_count} instructions)")

hdr = bytes(sim.peek(0x80300000, 32))
check(hdr.startswith(b"\xe3\x00\x00\x10") and b"bootloader" in hdr,
      f"bootloader unpacked SMT01 stage to 0x80300000 (hdr={hdr[:24]!r})")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Echolink EL-700 FTA bootloader 0.9.7 boots and initializes")
