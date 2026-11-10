#!/usr/bin/env python3
"""
The Opticum HD 506 satellite receiver firmware (8 MB SPI flash) runs on
the ALi M3511 dual-core platform (chips/m3503.py revision B with chip ID 0x3503).

The bootloader ("DVBS2---0.2.0") sets up its DDR3 memory controller, unpacks
the maincode and SEE co-processor chunks.  The application moves exception
vectors to 0x80002000, starts the SEE program at 0x86000200, prints 'model = 25:HD506',
'Soft Version = 12942', 'MC: APP  init ok', and drives the FD650K front panel.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for

DUMP = "OPTICUM HD 506/HD506_8M_V1.09.12942_24-09-2014_TEMP.abs"
LIMIT = 75_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Opticum HD 506 (ALi M3511) boots into its application ===")
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
    if "MC: APP  init ok" in text and "HD506" in text:
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s)")

check(type(sim.chip).__name__ == "M3503" and sim.chip.chip_id == 0x3503,
      f"detected as M3503 with chip ID 0x3503 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check("MC: APP  init ok" in text, "'MC: APP  init ok' printed on UART")
check("HD506" in text, "'HD506' identified on UART")
see = getattr(sim.chip, "see", None)
check(see is not None and len(see.starts) >= 1, "SEE co-processor started")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Opticum HD 506 (ALi M3511) boots into its application")
