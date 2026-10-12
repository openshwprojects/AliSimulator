#!/usr/bin/env python3
"""The Opticum X110TS / X110TSE update 1.4.0C (an ALi M3606 board whose SoC reads the chip ID 0x3603,
its sidecar's chipId; chips/m3602.py) boots like the Cabletech URZ0086: its bootloader starts the
SEE co-processor through the SEE's boot code (0xA1E8F450, chips/see.py) and starts the
application, which -- given the chip ID it checks for, instead of rebooting -- starts the SEE's
program (0xA6000200) on the second core (see.SeeCore) and attaches its drivers through remote calls
the SEE answers.  Without the SEE's program its first message went unacknowledged and it stopped
at its SDBBP assertion (0x801A9608).
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

from unicorn import UC_HOOK_CODE

from simulator import AliMipsSimulator, flash_size_for, resolve_dump

DUMP = "Software_Patch_X110TS_X110TSE_1.4.0C_PVR_UNI_ENG_2015-05-04.abs"
BOOT_CODE, PROGRAM, ASSERTION = 0xA1E8F450, 0xA6000200, 0x801A9608
BANNER = "Application version 1.0.0@SDK4.0ba.8.0_Combo_20120530"
LIMIT = 75_000_000

print("=== Regression Test: the Opticum X110TS (M3606, chip ID 0x3603) runs its SEE's program ===")
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
asserted = []
sim.mu.hook_add(UC_HOOK_CODE, lambda uc, address, size, user_data: asserted.append(sim.instruction_count),
                begin=ASSERTION, end=ASSERTION + 3)
taken = sim.chip.see.doorbells.taken
t0 = time.time()
error = None
try:
    # until its drivers are attached: ~80 calls answered and 36 of the SEE's (at ~60 M instructions)
    while sim.instruction_count < LIMIT and not asserted and (taken["main"][1] < 75 or taken["main"][0] < 30):
        sim.run(max_instructions=sim.instruction_count + 2_000_000)
except Exception as e:
    error = e
text = "".join(uart)
print(f"\n{time.time() - t0:.1f}s, {sim.instruction_count:,} instructions, messages taken {taken}"
      + (f", stopped: {error!r}" if error else ""))

see = sim.chip.see.starts
checks = [
    (type(sim.chip).__name__ == "M3602" and sim.chip.chip_id == 0x3603,
     f"the image is run as the M3602 family with its board's chip ID ({type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})"),
    (len(see) >= 1 and see[0] == (BOOT_CODE, "parked"),
     f"the bootloader sends the SEE to its boot code at 0x{BOOT_CODE:08X}, which parks the SEE ({see[:1]})"),
    (len(see) >= 2 and see[1] == (PROGRAM, "run on the SEE core"),
     f"the application starts the SEE's program at 0x{PROGRAM:08X}, which the second core runs ({see[1:2]})"),
    (len(see) == 2, f"no reboot: the SEE is started once by each ({len(see)} starts in all)"),
    (BANNER in text, "the application's first remote calls are answered: it prints its banner"),
    (not asserted, "no SDBBP assertion: the SEE acknowledges every message"),
    (taken["SEE"][0] >= 75 and taken["main"][1] >= 75,
     f"the SEE takes the drivers' calls and the main CPU its answers ({taken['SEE'][0]} / {taken['main'][1]})"),
    (taken["main"][0] >= 30 and taken["SEE"][1] >= 30,
     f"the main CPU answers the SEE's own calls ({taken['main'][0]} / {taken['SEE'][1]})"),
    (error is None, "the simulator runs on without an error"),
]
ok = True
for good, text in checks:
    print(f"  [{'PASS' if good else 'FAIL'}] {text}")
    ok &= good
print(f"\n[{'PASS' if ok else 'FAIL'}] X110TS application with the SEE's program")
sys.exit(0 if ok else 1)
