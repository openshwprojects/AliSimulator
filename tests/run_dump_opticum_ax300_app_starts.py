#!/usr/bin/env python3
"""
The Opticum AX 300 satellite receiver firmware (4 MB SPI flash) runs on
the ALi M3510A platform (chips/m3503.py with chip ID 0x3503).

The bootloader ("DVBS2---0.2.0") sets up its stack in cache-as-RAM, unpacks the
maincode chunk to 0x80000200.  The application moves exception vectors to
0x80002000, prints 'model = 27:AX300', 'Soft Version = 13196', 'MC: APP  init ok',
'ALI3510E      AX300', and drives the FD650K front panel.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for

DUMP = "OPTICUM AX 300/AX_300_V1.09.13196_PL.abs"
LIMIT = 75_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Opticum AX 300 (ALi M3510A) boots into its application ===")
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
    if "MC: APP  init ok" in text and "AX300" in text:
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s)")

check(type(sim.chip).__name__ == "M3503" and sim.chip.chip_id == 0x3503,
      f"detected as M3503 with chip ID 0x3503 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check("MC: APP  init ok" in text, "'MC: APP  init ok' printed on UART")
check("AX300" in text, "'AX300' identified on UART")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Opticum AX 300 (ALi M3510A) boots into its application")
