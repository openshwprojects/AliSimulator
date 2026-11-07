#!/usr/bin/env python3
"""
The GTMedia V9 Prime firmware V163 (2021-06-18, single-CPU ALi M3507 / C3507,
chips/c3503.py: chip word 0x35070000 -> SDK chip code 0x10056, bootloader
"M3507---3") boots its XIP bootloader from 0xAFC00000 using CacheAsRam at
0x8FFF8000, relocates to 0x82800000, verifies and unpacks its 14.50 MB maincode
("1.1.0" at 0x1B0000) to 0x80100200, moves CP0 EBase to 0x80102000, initialises
NIM_S3501H_0 at 0xB804C000 (chip ID 0x350100C0 at +0x140), and renders its
1280x720 32-bpp ARGB8888 OSD on GMA layer 0.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for

DUMP = "GTMEDIA V9 PRIME/GTMedia_V9Prime_V163_20210618.bin"
LIMIT = 200_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: GTMedia V9 Prime V163 (ALi M3507 / C3507) boots into its application ===")
uart = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.setUartHandler(lambda c: uart.append(c if isinstance(c, str) else chr(c)))
sim.loadFile(DUMP)
chip_word = int.from_bytes(sim.peek(0xB8000000, 4), "little")
chip_word_hi = int.from_bytes(sim.peek(0xB8080000, 4), "little")

t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    if (sim.cp0_ebase & 0xFFFFF000) == 0x80102000 and sim.ge_ops >= 25:
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s)")

check(type(sim.chip).__name__ == "C3503" and chip_word == 0x35070000 and chip_word_hi == 0x35070000,
      f"detected as C3503/C3507 with chip word 0x35070000 at 0xB8000000 and 0xB8080000 (got {type(sim.chip).__name__}, 0x{chip_word:08X}, 0x{chip_word_hi:08X})")
check(not sim.chip.see.run_program and sim.chip.see.core is None,
      "single-CPU C3507: no SEE second core spawned")
check("\x01" in text, "silent retail bootloader/application start byte 0x01 printed on UART")
check((sim.cp0_ebase & 0xFFFFF000) == 0x80102000,
      f"CP0 EBase moved to 0x80102000 (got 0x{sim.cp0_ebase:08X})")
check(sim.ge_ops >= 25,
      f"application issued >= 25 GE commands (got {sim.ge_ops})")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] GTMedia V9 Prime V163 (ALi M3507 / C3507) boots into its application")
