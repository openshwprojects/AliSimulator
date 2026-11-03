#!/usr/bin/env python3
"""
The Amiko Mira WiFi firmware v1.1.74 emu (single-CPU ALi M3510C / C3503C,
chips/c3503.py: chip word 0x3503C000, bootloader "3510CA 1.1.1") boots through
its boot-ROM SRAM bootloader at 0x9FE00800, verifies and unpacks its 13.9 MB
maincode(AV) to 0x80000200, moves CP0 EBase to 0x80002000, initialises
hs_config_init and userdb(64+64), and draws its 1280x720 OSD dialog without
spawning a second SEE core or rebooting.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for

DUMP = "AMIKO MIRA WIFI/AMIKO_Mira_1.1.74_emu.abs"
LIMIT = 90_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Amiko Mira WiFi v1.1.74 (M3510C / C3503C) boots into its application ===")
uart = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.setUartHandler(lambda c: uart.append(c if isinstance(c, str) else chr(c)))
sim.loadFile(DUMP)
chip_word = int.from_bytes(sim.peek(0xB8000000, 4), "little")

t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    if (sim.cp0_ebase & 0xFFFFF000) == 0x80002000 and "hs_config_init" in "".join(uart):
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s)")

check(type(sim.chip).__name__ == "C3503" and chip_word == 0x3503C000,
      f"detected as C3503 with C3503C chip word 0x3503C000 (got {type(sim.chip).__name__}, 0x{chip_word:08X})")
check(not sim.chip.see.run_program and sim.chip.see.core is None,
      "single-CPU C3503: no SEE second core spawned")
for expected in ("APP  init ok", "CRC Check Result : Pass",
                 "Expand Maincode Success, unzip_length = 0xd42424",
                 "Run Maincode, main_entry = 0x80000200!",
                 "---led 455 attach OK--", "hs_config_init"):
    check(expected in text, f"{expected!r} printed on UART")
check(text.count("CRC Check Result : Pass") == 1, "bootloader ran once (no watchdog reboot)")
check((sim.cp0_ebase & 0xFFFFF000) == 0x80002000,
      f"CP0 EBase moved to 0x80002000 (got 0x{sim.cp0_ebase:08X})")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Amiko Mira WiFi v1.1.74 (M3510C / C3503C) boots into its application")
