#!/usr/bin/env python3
"""
The Amiko Mira2 WiFi Edision firmware v.1231 (single-CPU ALi M3510D / C3503D,
chips/c3503.py: chip word 0x3503D000, bootloader "3510DB 1.1.1") boots through
its boot-ROM SRAM bootloader at 0x9FE00800, writes " ON " to its CH455 4-digit
panel bus on GPIO 24 (SCL) / 23 (SDA), verifies and unpacks its 12.51 MB
maincode(AV) to 0x80000200, moves CP0 EBase to 0x80002000, attaches its CH455
panel ("---led 455 attach OK--" -> " on "), and initialises MCAS ("Starting mcas
v.1.0").
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = "AMIKO MIRA2 WIFI/AMIKO MIRA WIFI 2 Edision_v.1231.abs"
LIMIT = 30_000_000
SLICE = 2_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Amiko Mira2 WiFi Edision v.1231 (M3510D / C3503D) boots into its application ===")
uart = []
seen_panels = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
panel, _keys, panel_desc = make_panel(DUMP, log_handler=lambda m: None)
panel.dump_enabled = False


def on_uart(c):
    ch = c if isinstance(c, str) else chr(c)
    uart.append(ch)
    if len(uart) <= 1200:
        sys.stdout.write(ch)
        sys.stdout.flush()


sim.setGpioHandler(panel.on_gpio_write)
sim.setUartHandler(on_uart)
sim.loadFile(DUMP)
chip_word = int.from_bytes(sim.peek(0xB8000000, 4), "little")

t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    txt = panel.get_display_text()
    if txt.strip() and (not seen_panels or seen_panels[-1] != txt):
        seen_panels.append(txt)
    if (sim.cp0_ebase & 0xFFFFF000) == 0x80002000 and " on " in seen_panels and "Starting mcas v.1.0" in "".join(uart):
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
print(f"\nStopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), panel history {seen_panels}")
text = "".join(uart)

check(type(sim.chip).__name__ == "C3503" and chip_word == 0x3503D000,
      f"detected as C3503 with C3503D chip word 0x3503D000 (got {type(sim.chip).__name__}, 0x{chip_word:08X})")
check(not sim.chip.see.run_program and sim.chip.see.core is None,
      "single-CPU C3503: no SEE second core spawned")
check(" ON " in seen_panels and " on " in seen_panels,
      f"CH455 front panel ({panel_desc}) showed ' ON ' -> ' on ' (got {seen_panels})")
for expected in ("Enter Bootloader APP.", "CRC Check Result : Pass",
                 "Expand Maincode Success, unzip_length = 0xc83f64",
                 "Run Maincode, main_entry = 0x80000200!",
                 "---led 455 attach OK--", "Starting mcas v.1.0"):
    check(expected in text, f"{expected!r} printed on UART")
check(text.count("Enter Bootloader APP.") == 1, "bootloader ran once (no watchdog reboot)")
check((sim.cp0_ebase & 0xFFFFF000) == 0x80002000,
      f"CP0 EBase moved to 0x80002000 (got 0x{sim.cp0_ebase:08X})")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Amiko Mira2 WiFi Edision v.1231 (M3510D / C3503D) boots into its application")
