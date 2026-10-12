#!/usr/bin/env python3
"""The Globo HD-XS2 / Opticum Blue XS65 satellite update 1.3.5 "SmartHD" (an ALi M3503,
chips/m3503.py) boots from the flash window with its stack in the cache-as-RAM range until the DDR
is up, starts its SEE co-processor through the SEE's boot code (chips/see.py), unpacks the main
code and starts the application, which moves its exception vectors (EBase 0x80002000) and starts
the SEE's program on the second core (see.SeeCore), which moves its own (EBase 0x86002000, CPU
number 1).  The two talk through remote calls with the newer chips' doorbells (see.Doorbells: the
ring in the +0x37 byte).  Both are silent builds -- the UART gets one 0x01 byte and one line --, so
the test follows the boot by the SEE starts, the CP0 EBase and the messages each CPU took.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

from simulator import AliMipsSimulator, flash_size_for, resolve_dump

DUMP = "Sw_Globo_HD-XS2_SmartHD_1.3.5_2015-05-08.abs"
BOOT_CODE, PROGRAM = 0xA1016804, 0x86000200
LIMIT = 110_000_000

print("=== Regression Test: the Globo HD-XS2 (M3503, XIP bootloader) runs its application and the SEE's program ===")
path = resolve_dump(DUMP)
sim = None
car = []


def log(msg):
    if msg.startswith(("[SEE] started", "[CAR]")):
        print(f"[{sim.instruction_count:>11,}] {msg}", flush=True)
        if msg.startswith("[CAR]"):
            car.append(msg)


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
    # until its drivers are attached: ~74 calls answered and 34 of the SEE's (at ~55-80 M instructions)
    while sim.instruction_count < LIMIT and (taken["main"][1] < 70 or taken["main"][0] < 30):
        sim.run(max_instructions=sim.instruction_count + 2_000_000)
except Exception as e:
    error = e
see_ebase = see.core.core.cp0_ebase if see.core else None
print(f"\n{time.time() - t0:.1f}s, {sim.instruction_count:,} instructions, EBase 0x{sim.cp0_ebase:08X}, "
      f"messages taken {taken}, UART {''.join(uart).encode('unicode_escape')}" + (f", stopped: {error}" if error else ""))

starts = see.starts
checks = [
    (type(sim.chip).__name__ == "M3503", f"the image is run as the M3503 family ({type(sim.chip).__name__})"),
    (len(car) == 1, "the bootloader keeps its stack in the cache-as-RAM range, then runs from RAM"),
    (len(starts) >= 1 and starts[0] == (BOOT_CODE, "parked"),
     f"it starts the SEE through the SEE's boot code at 0x{BOOT_CODE:08X}, which parks the SEE ({starts[:1]})"),
    (len(starts) >= 2 and starts[1] == (PROGRAM, "run on the SEE core"),
     f"the application starts the SEE's program at 0x{PROGRAM:08X}, which the second core runs ({starts[1:2]})"),
    (sim.cp0_ebase == 0x80002000, f"the application moved its exception vectors: EBase 0x{sim.cp0_ebase:08X}"),
    (see_ebase == 0x86002001, f"the SEE's program moved its own, CPU number 1: EBase 0x{see_ebase or 0:08X}"),
    (taken["SEE"][0] >= 70 and taken["main"][1] >= 70,
     f"the SEE takes the drivers' calls and the main CPU its answers ({taken['SEE'][0]} / {taken['main'][1]})"),
    (taken["main"][0] >= 30 and taken["SEE"][1] >= 30,
     f"the main CPU answers the SEE's own calls ({taken['main'][0]} / {taken['SEE'][1]})"),
    (error is None, "the simulator runs on without an error"),
]
ok = True
for good, desc in checks:
    print(f"  [{'PASS' if good else 'FAIL'}] {desc}")
    ok &= good
print(f"\n[{'PASS' if ok else 'FAIL'}] Globo HD-XS2 application with the SEE's program")
sys.exit(0 if ok else 1)
