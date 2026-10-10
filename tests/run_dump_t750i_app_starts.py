#!/usr/bin/env python3
"""The Ferguson Ariva T750i firmware V1.20B2 (an M3821 with an XIP bootloader, chips/m3821.py)
boots from the flash window like an M3801 -- its stack in the cache-as-RAM range until the DDR is
up, its CP0 set-up run through the flash's cached view -- takes the M3821 path for the chip ID
0x3821, starts its SEE co-processor through the SEE's boot code (chips/see.py), unpacks the main
code ("success!") and starts the application, which moves its exception vectors (EBase 0x80002000)
and starts the SEE's program, which is not run.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

from simulator import AliMipsSimulator, flash_size_for, resolve_dump

DUMP = "Ferguson_T750i_V1.20B2_18092019.abs"
BOOT_CODE, PROGRAM = 0xA1017804, 0xA6000200
LIMIT = 150_000_000

print("=== Regression Test: the Ferguson T750i (M3821, XIP bootloader) starts its application ===")
path = resolve_dump(DUMP)
sim = None


def log(msg):
    if msg.startswith(("[SEE] started", "[CAR]")):
        print(f"[{sim.instruction_count:>11,}] {msg}", flush=True)


sim = AliMipsSimulator(rom_size=flash_size_for(path), log_handler=log)
sim.setSPIDump(False)
sim.setI2CDump(False)
uart = []
sim.setUartHandler(lambda c: uart.append(c if isinstance(c, str) else chr(c)))
sim.loadFile(path)
t0 = time.time()
error = None
try:
    while len(getattr(getattr(sim.chip, "see", None), "starts", [])) < 2 and sim.instruction_count < LIMIT:
        sim.run(max_instructions=sim.instruction_count + 2_000_000)
    sim.run(max_instructions=sim.instruction_count + 5_000_000)       # a little further: it keeps running
except Exception as e:
    error = e
text = "".join(uart)
print(f"\n{time.time() - t0:.1f}s, {sim.instruction_count:,} instructions" + (f", stopped: {error}" if error else ""))

starts = getattr(getattr(sim.chip, "see", None), "starts", [])
checks = [
    (type(sim.chip).__name__ == "M3821" and getattr(sim.chip, "xip", False),
     f"the image is run as the M3821 family with its XIP bootloader ({type(sim.chip).__name__})"),
    ("HW BootLoader APP  init!" in text, "the bootloader runs from RAM and prints its banner"),
    ("success!" in text, "it unpacks the main code (\"success!\")"),
    (len(starts) >= 1 and starts[0] == (BOOT_CODE, "parked"),
     f"it starts the SEE through the SEE's boot code at 0x{BOOT_CODE:08X}, which parks the SEE ({starts[:1]})"),
    (len(starts) >= 2 and starts[1][0] == PROGRAM and "not run" in starts[1][1],
     f"the application starts the SEE's program at 0x{PROGRAM:08X}, which is not run ({starts[1:2]})"),
    (sim.cp0_ebase == 0x80002000, f"the application moved its exception vectors: EBase 0x{sim.cp0_ebase:08X}"),
    (error is None, "the simulator runs on without an error"),
]
ok = True
for good, desc in checks:
    print(f"  [{'PASS' if good else 'FAIL'}] {desc}")
    ok &= good
print(f"\n[{'PASS' if ok else 'FAIL'}] Ferguson T750i application start")
sys.exit(0 if ok else 1)
