#!/usr/bin/env python3
"""The Ferguson Ariva T760i firmware V1.5B4 (ALi C3505, chips/c3505.py) boots through the M3821
family's boot-ROM path with the C3505's chip ID, waits for the ready bit 8 of 0xB8000300, unpacks
its application and starts it: the application moves its exception vectors (CP0 EBase
0x80002000) -- past its ~900-NOP entry at 0x80000200, which fast mode now runs under a code hook --
and starts its SEE co-processor's program at 0xA6000200 (chips/see.py), which is not run.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

from simulator import AliMipsSimulator, flash_size_for, resolve_dump

DUMP = "Ferguson_T760i_V1.5B4-14092021.abs"
PROGRAM = 0xA6000200
LIMIT = 200_000_000

print("=== Regression Test: the Ferguson T760i (C3505) starts its application ===")
path = resolve_dump(DUMP)
sim = None


def log(msg):
    if msg.startswith("[SEE] started"):
        print(f"[{sim.instruction_count:>11,}] {msg}", flush=True)


sim = AliMipsSimulator(rom_size=flash_size_for(path), log_handler=log)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.loadFile(path)
t0 = time.time()
error = None
try:
    while not getattr(sim.chip, "see", None) or not sim.chip.see.starts:
        if sim.instruction_count >= LIMIT:
            break
        sim.run(max_instructions=sim.instruction_count + 2_000_000)
    sim.run(max_instructions=sim.instruction_count + 5_000_000)       # a little further: it keeps running
except Exception as e:
    error = e
print(f"\n{time.time() - t0:.1f}s, {sim.instruction_count:,} instructions" + (f", stopped: {error}" if error else ""))

see = getattr(sim.chip, "see", None)
starts = see.starts if see else []
checks = [
    (type(sim.chip).__name__ == "C3505", f"the image is run as the C3505 family ({type(sim.chip).__name__})"),
    (sim.cp0_ebase == 0x80002000, f"the application moved its exception vectors: EBase 0x{sim.cp0_ebase:08X}"),
    (len(starts) >= 1 and starts[0][0] == PROGRAM and "not run" in starts[0][1],
     f"the application starts the SEE's program at 0x{PROGRAM:08X}, which is not run ({starts[:1]})"),
    (error is None, "the simulator runs on without an error"),
]
ok = True
for good, text in checks:
    print(f"  [{'PASS' if good else 'FAIL'}] {text}")
    ok &= good
print(f"\n[{'PASS' if ok else 'FAIL'}] Ferguson T760i application start")
sys.exit(0 if ok else 1)
