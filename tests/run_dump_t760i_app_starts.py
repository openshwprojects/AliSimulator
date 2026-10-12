#!/usr/bin/env python3
"""The Ferguson Ariva T760i firmware V1.5B4 (ALi C3505, chips/c3505.py) boots through the M3821
family's boot-ROM path with the C3505's chip ID, waits for the ready bit 8 of 0xB8000300, unpacks
its application and starts it: the application moves its exception vectors (CP0 EBase
0x80002000) -- past its ~900-NOP entry at 0x80000200, which fast mode runs under a code hook --
and starts its SEE co-processor's program at 0xA6000200 on the second core (chips/see.py
SeeCore), which moves its own (EBase 0x86002000, CPU number 1).  The application's drivers then
talk to the SEE's through remote calls with the newer chips' doorbells: it prints its banner and
the main CPU and the SEE answer each other's calls.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

from simulator import AliMipsSimulator, flash_size_for, resolve_dump

DUMP = "Ferguson_T760i_V1.5B4-14092021.abs"
PROGRAM = 0xA6000200
BANNER = "Application version 1.0.0@SDK4.0ia.17.15_20171123bycompileserveradministrator"
LIMIT = 110_000_000

print("=== Regression Test: the Ferguson T760i (C3505) runs its application and the SEE's program ===")
path = resolve_dump(DUMP)
sim = None


def log(msg):
    if msg.startswith("[SEE] started"):
        print(f"[{sim.instruction_count:>11,}] {msg}", flush=True)


sim = AliMipsSimulator(rom_size=flash_size_for(path), log_handler=log)
sim.setSPIDump(False)
sim.setI2CDump(False)
uart = []
sim.setUartHandler(lambda c: uart.append(c if isinstance(c, str) else chr(c)))
sim.loadFile(path)
t0 = time.time()
error = None
taken = None
try:
    while sim.instruction_count < LIMIT:
        see = getattr(sim.chip, "see", None)
        taken = see.doorbells.taken if see else None
        if taken and taken["main"][1] >= 50 and taken["main"][0] >= 30:   # ~60 / 54 by ~80 M instructions
            break
        sim.run(max_instructions=sim.instruction_count + 2_000_000)
except Exception as e:
    error = e
text = "".join(uart)
see = getattr(sim.chip, "see", None)
taken = see.doorbells.taken if see else {"main": [0, 0], "SEE": [0, 0]}
see_ebase = see.core.core.cp0_ebase if see and see.core else None
print(f"\n{time.time() - t0:.1f}s, {sim.instruction_count:,} instructions, messages taken {taken}"
      + (f", stopped: {error}" if error else ""))

starts = see.starts if see else []
checks = [
    (type(sim.chip).__name__ == "C3505", f"the image is run as the C3505 family ({type(sim.chip).__name__})"),
    (sim.cp0_ebase == 0x80002000, f"the application moved its exception vectors: EBase 0x{sim.cp0_ebase:08X}"),
    (len(starts) >= 1 and starts[0] == (PROGRAM, "run on the SEE core"),
     f"the application starts the SEE's program at 0x{PROGRAM:08X}, which the second core runs ({starts[:1]})"),
    (see_ebase == 0x86002001, f"the SEE's program moved its own exception vectors, CPU number 1: EBase 0x{see_ebase or 0:08X}"),
    (BANNER in text, "the application's first remote calls are answered: it prints its banner"),
    (taken["SEE"][0] >= 50 and taken["main"][1] >= 50,
     f"the SEE takes the drivers' calls and the main CPU its answers ({taken['SEE'][0]} / {taken['main'][1]})"),
    (taken["main"][0] >= 30 and taken["SEE"][1] >= 30,
     f"the main CPU answers the SEE's own calls ({taken['main'][0]} / {taken['SEE'][1]})"),
    (error is None, "the simulator runs on without an error"),
]
ok = True
for good, desc in checks:
    print(f"  [{'PASS' if good else 'FAIL'}] {desc}")
    ok &= good
print(f"\n[{'PASS' if ok else 'FAIL'}] Ferguson T760i application with the SEE's program")
sys.exit(0 if ok else 1)
