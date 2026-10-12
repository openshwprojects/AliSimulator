#!/usr/bin/env python3
"""The Ferguson Ariva T750i firmware V1.20B2 (an M3821 with an XIP bootloader, chips/m3821.py)
boots from the flash window like an M3801 -- its stack in the cache-as-RAM range until the DDR is
up, its CP0 set-up run through the flash's cached view -- takes the M3821 path for the chip ID
0x3821, starts its SEE co-processor through the SEE's boot code (chips/see.py), unpacks the main
code ("success!") and starts the application, which moves its exception vectors (EBase 0x80002000)
and starts the SEE's program on the second core (see.SeeCore).  The application then attaches its
drivers through remote calls the SEE answers, opens its database and starts drawing.  The chip
reads as revision B: before that the application leaves its OSD layers' GMA device to the SEE and
calls it directly, its main CPU jumping into the SEE's code (watched here).
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
import time

from unicorn import UC_HOOK_CODE

from simulator import AliMipsSimulator, flash_size_for, resolve_dump

DUMP = "Ferguson_T750i_V1.20B2_18092019.abs"
BOOT_CODE, PROGRAM = 0xA1017804, 0xA6000200
SEE_CODE = (0x86000000, 0x87FFFFFF)             # the SEE's private memory
LIMIT = 100_000_000

print("=== Regression Test: the Ferguson T750i (M3821, XIP bootloader) runs its application and the SEE's program ===")
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
in_see_code = []
sim.mu.hook_add(UC_HOOK_CODE, lambda uc, address, size, user_data: in_see_code.append(address) if not in_see_code else None,
                begin=SEE_CODE[0], end=SEE_CODE[1])
see = sim.chip.see
taken = see.doorbells.taken
t0 = time.time()
error = None
try:
    # until the application draws: ~150 calls answered and 24 of the SEE's (at ~80 M instructions)
    while sim.instruction_count < LIMIT and (taken["main"][1] < 140 or taken["main"][0] < 20 or not sim.ge_ops) \
            and not in_see_code:
        sim.run(max_instructions=sim.instruction_count + 2_000_000)
except Exception as e:
    error = e
text = "".join(uart)
print(f"\n{time.time() - t0:.1f}s, {sim.instruction_count:,} instructions, messages taken {taken}, "
      f"{sim.ge_ops} GE commands" + (f", stopped: {error}" if error else ""))

starts = see.starts
checks = [
    (type(sim.chip).__name__ == "M3821" and getattr(sim.chip, "xip", False),
     f"the image is run as the M3821 family with its XIP bootloader ({type(sim.chip).__name__})"),
    ("HW BootLoader APP  init!" in text, "the bootloader runs from RAM and prints its banner"),
    ("success!" in text, "it unpacks the main code (\"success!\")"),
    (len(starts) >= 1 and starts[0] == (BOOT_CODE, "parked"),
     f"it starts the SEE through the SEE's boot code at 0x{BOOT_CODE:08X}, which parks the SEE ({starts[:1]})"),
    (len(starts) >= 2 and starts[1] == (PROGRAM, "run on the SEE core"),
     f"the application starts the SEE's program at 0x{PROGRAM:08X}, which the second core runs ({starts[1:2]})"),
    (sim.cp0_ebase == 0x80002000, f"the application moved its exception vectors: EBase 0x{sim.cp0_ebase:08X}"),
    (taken["SEE"][0] >= 140 and taken["main"][1] >= 140,
     f"the SEE takes the drivers' calls and the main CPU its answers ({taken['SEE'][0]} / {taken['main'][1]})"),
    (taken["main"][0] >= 20 and taken["SEE"][1] >= 20,
     f"the main CPU answers the SEE's own calls ({taken['main'][0]} / {taken['SEE'][1]})"),
    ("DB_init() success!" in text, "the application opens its database"),
    (sim.ge_ops > 0, f"it draws: {sim.ge_ops} graphics engine commands"),
    (not in_see_code, "the main CPU stays out of the SEE's code" + (f" (0x{in_see_code[0]:08X})" if in_see_code else "")),
    (error is None, "the simulator runs on without an error"),
]
ok = True
for good, desc in checks:
    print(f"  [{'PASS' if good else 'FAIL'}] {desc}")
    ok &= good
print(f"\n[{'PASS' if ok else 'FAIL'}] Ferguson T750i application with the SEE's program")
sys.exit(0 if ok else 1)
