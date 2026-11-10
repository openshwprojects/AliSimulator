#!/usr/bin/env python3
"""
The Opticum HD XC406p DVB-C cable receiver firmware (8 MB SPI flash) runs on
the dual-core ALi M3606 platform (chips/m3602.py with chip ID 0x3603).

The bootloader ("DVBS2---0.2.0") unpacks the encrypted maincode chunk container
at 0x20000 via LZMA to 0x80000200 and the SEE co-processor code to 0xA1A00200.
The application starts the SEE's program at 0xA6000200 on the second core,
prints 'model = HD X406p', 'MC: APP  init ok', and executes graphics engine commands.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for

DUMP = "OPTICUM HD XC406P/Ali_update_3606_8M_x406p_dvbc_v1.07.5468_20120703.abs"
LIMIT = 50_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Opticum HD XC406p (ALi M3606 DVB-C) boots into its application ===")
uart = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.setUartHandler(lambda c: uart.append(c if isinstance(c, str) else chr(c)))
sim.loadFile(DUMP)

t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    text = "".join(uart)
    if "MC: APP  init ok" in text and "HD X406p" in text:
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s)")

check(type(sim.chip).__name__ == "M3602" and sim.chip.chip_id == 0x3603,
      f"detected as M3602 with chip ID 0x3603 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check("MC: APP  init ok" in text, "'MC: APP  init ok' printed on UART")
check("HD X406p" in text, "'HD X406p' identified on UART")
see = getattr(sim.chip, "see", None)
check(see is not None and len(see.starts) >= 1, "SEE co-processor started")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Opticum HD XC406p (ALi M3606 DVB-C) boots into its application")
