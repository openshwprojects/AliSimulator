#!/usr/bin/env python3
"""
Regression test for the StarSat SR-X4000D / SR-X4200D 2 MB parallel NOR dump
(ali_dvbs_v4_rock_3329c_v1.1.7_starsat_20080222.bin, ALi M3329C / M3101, chips/m3329.py).

The Moresat SMT03 bootloader (SMT03---3.0.4) boots from parallel NOR flash at 0xAFC00000,
unpacks its stage to 0x80680000, attempts to unpack maincodeC at 0xAFC10000 into SDRAM
at 0x80000200, and communicates with the SMTM51 security MCU over UART2.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for

DUMP = "STARSAT SR-X4000D/ali_dvbs_v4_rock_3329c_v1.1.7_starsat_20080222.bin"
LIMIT = 20_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: StarSat SR-X4000D SMT03 bootloader boots and initializes ===")
uart = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.setUartHandler(lambda c: uart.append(c if isinstance(c, str) else chr(c)))
sim.loadFile(DUMP)

sim.run(max_instructions=LIMIT)
text = "".join(uart)

check(type(sim.chip).__name__ == "M3329", f"detected as M3329 (got {type(sim.chip).__name__})")
check(sim.instruction_count >= 5_000_000, f"bootloader executed ({sim.instruction_count} instructions)")
check("on Z" in text, f"SMT03 bootloader sent front panel / UART challenge (got {text!r})")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] StarSat SR-X4000D SMT03 bootloader boots and initializes")
