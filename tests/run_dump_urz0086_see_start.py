#!/usr/bin/env python3
"""The Cabletech URZ0086 firmware V1.2.1 (ALi M3606, chips/m3602.py) starts its SEE co-processor
the way the chip is started (chips/see.py): its bootloader parks the SEE, sends it to the boot
code in its RAM copy (0xA1E8E0D0) -- which the simulator runs on the SEE's own instance: it copies
the SEE's program into place, sets the started flag the bootloader waits for and parks again --
and the application later starts the SEE's program (0xA6000200), which runs on the second core
(see.SeeCore).  The application's drivers then talk to the SEE's through remote calls: its first
call (HLD_BASE.3) comes before its banner, and it attaches the audio / video decoders, the video
outputs, the subtitle, teletext and VBI decoders -- dozens of calls, which the SEE answers, and
calls of the SEE's own, which the main CPU answers (see.Doorbells counts the messages each CPU
took).
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

from simulator import AliMipsSimulator, flash_size_for, resolve_dump

DUMP = "URZ0086_V1.2.1.abs"
BOOT_CODE, PROGRAM = 0xA1E8E0D0, 0xA6000200
BANNER = "Application version 1.0.0@SDK4.0ba.7.2_Sab_T_20120115"
LIMIT = 40_000_000

print("=== Regression Test: the URZ0086 runs its SEE co-processor's program (chips/see.py) ===")
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
see = sim.chip.see
taken = see.doorbells.taken
t0 = time.time()
error = None
try:
    # until the drivers are attached: 68 calls answered and 18 of the SEE's (at ~34 M instructions)
    while sim.instruction_count < LIMIT and (taken["main"][1] < 65 or taken["main"][0] < 15):
        sim.run(max_instructions=sim.instruction_count + 2_000_000)
except Exception as e:
    error = e
text = "".join(uart)
print(f"\n{time.time() - t0:.1f}s, {sim.instruction_count:,} instructions, messages taken {taken}"
      + (f", stopped: {error}" if error else ""))

starts = see.starts
checks = [
    (type(sim.chip).__name__ == "M3602", f"the image is run as the M3602 family ({type(sim.chip).__name__})"),
    (len(starts) >= 1 and starts[0] == (BOOT_CODE, "parked"),
     f"the bootloader sends the SEE to its boot code at 0x{BOOT_CODE:08X}, which parks the SEE ({starts[:1]})"),
    (len(starts) >= 2 and starts[1] == (PROGRAM, "run on the SEE core"),
     f"the application then starts the SEE's program at 0x{PROGRAM:08X}, which the second core runs ({starts[1:2]})"),
    (len(starts) == 2, f"no other start ({len(starts)} in all)"),
    (BANNER in text, "the application's first remote call is answered: it prints its banner"),
    (taken["SEE"][0] >= 65 and taken["main"][1] >= 65,
     f"the SEE takes the drivers' calls and the main CPU its answers ({taken['SEE'][0]} / {taken['main'][1]})"),
    (taken["main"][0] >= 15 and taken["SEE"][1] >= 15,
     f"the main CPU answers the SEE's own calls ({taken['main'][0]} / {taken['SEE'][1]})"),
    (error is None, "the simulator runs on without an error"),
]
ok = True
for good, desc in checks:
    print(f"  [{'PASS' if good else 'FAIL'}] {desc}")
    ok &= good
print(f"\n[{'PASS' if ok else 'FAIL'}] URZ0086 SEE program")
sys.exit(0 if ok else 1)
