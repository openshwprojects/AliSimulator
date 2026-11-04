#!/usr/bin/env python3
"""Verify that Amiko Mira Wi-Fi (System ID 67010A00, v1.1.85 EMU) boots into its application and renders OSD."""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for

DUMP = "AMIKO MIRA WIFI/AMIKO_Mira_1.1.85_emu.abs"
LIMIT = 95_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Amiko Mira Wi-Fi (System ID 67010A00, v1.1.85 EMU) boots into its application ===")
uart = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)

sim.setUartHandler(lambda ch: uart.append(ch if isinstance(ch, str) else chr(ch)))
sim.loadFile(DUMP)
sim.attach_tuner()

t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    if sim.ge_ops >= 5:
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), "
      f"ge_ops={sim.ge_ops}")

check(type(sim.chip).__name__ == "C3503" and sim.chip.chip_id == 0x3503,
      f"detected as C3503 with chip ID 0x3503 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
for expected in ("APP  init ok", "CRC Check Result : Pass", "Run Maincode, main_entry = 0x80000200!"):
    check(expected in text, f"{expected!r} printed on UART")
check((sim.cp0_ebase & 0xFFFFF000) == 0x80002000,
      f"CP0 EBase at 0x80002000 (got 0x{sim.cp0_ebase:08X})")
check(sim.ge_ops >= 5, f"GE executed {sim.ge_ops} graphics commands")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Amiko Mira Wi-Fi (System ID 67010A00, v1.1.85 EMU) boots into its application")
