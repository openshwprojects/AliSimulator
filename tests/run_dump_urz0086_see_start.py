#!/usr/bin/env python3
"""The Cabletech URZ0086 firmware V1.2.1 (ALi M3606, chips/m3602.py) starts its SEE co-processor
the way the chip is started (chips/see.py): its bootloader parks the SEE, sends it to the boot
code in its RAM copy (0xA1E8E0D0) -- which the simulator runs on the SEE's own instance: it copies
the SEE's program into place, sets the started flag the bootloader waits for and parks again --
and the application later starts the SEE's program (0xA6000200), which the simulator does not run.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

from simulator import AliMipsSimulator, flash_size_for, resolve_dump

DUMP = "URZ0086_V1.2.1.abs"
BOOT_CODE, PROGRAM = 0xA1E8E0D0, 0xA6000200
LIMIT = 120_000_000

print("=== Regression Test: the URZ0086 starts its SEE co-processor (chips/see.py) ===")
path = resolve_dump(DUMP)
starts = []
sim = None


def log(msg):
    if msg.startswith("[SEE] started"):
        print(f"[{sim.instruction_count:>11,}] {msg}", flush=True)
        starts.append(msg)


sim = AliMipsSimulator(rom_size=flash_size_for(path), log_handler=log)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.loadFile(path)
t0 = time.time()
error = None
try:
    while len(sim.chip.see.starts) < 2 and sim.instruction_count < LIMIT:
        sim.run(max_instructions=sim.instruction_count + 2_000_000)
except Exception as e:
    error = e
print(f"\n{time.time() - t0:.1f}s, {sim.instruction_count:,} instructions" + (f", stopped: {error}" if error else ""))

see = sim.chip.see.starts
checks = [
    (type(sim.chip).__name__ == "M3602", f"the image is run as the M3602 family ({type(sim.chip).__name__})"),
    (len(see) >= 1 and see[0] == (BOOT_CODE, "parked"),
     f"the bootloader sends the SEE to its boot code at 0x{BOOT_CODE:08X}, which parks the SEE ({see[:1]})"),
    (len(see) >= 2 and see[1][0] == PROGRAM and "not run" in see[1][1],
     f"the application then starts the SEE's program at 0x{PROGRAM:08X}, which is not run ({see[1:2]})"),
    (len(see) == 2, f"no other start ({len(see)} in all)"),
]
ok = True
for good, text in checks:
    print(f"  [{'PASS' if good else 'FAIL'}] {text}")
    ok &= good
print(f"\n[{'PASS' if ok else 'FAIL'}] URZ0086 SEE start handshake")
sys.exit(0 if ok else 1)
