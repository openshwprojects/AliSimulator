#!/usr/bin/env python3
"""
The Edision Picco S2 firmware v.1248 (single-CPU ALi M3510D / C3503D,
chips/c3503.py: chip word 0x3503D000, bootloader "3510DB 1.1.1") boots through
its boot-ROM SRAM bootloader at 0x9FE00800, writes " ON " to its CH455 4-digit
panel on GPIO 24 (SCL) / 23 (SDA), verifies and unpacks its 12.0 MB maincode(AV)
to 0x80000200, moves CP0 EBase to 0x80002000, attaches its CH455 panel driver
("---led 455 attach OK--") and initialises its MCAS key database without
spawning a second SEE core or rebooting.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = "EDISION PICCO S2/PICCO_S2_v.1248.abs"
LIMIT = 150_000_000
SLICE = 5_000_000
STOP_AT = "[mcas] max_key_db_count = 516"

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Edision Picco S2 v.1248 (M3510D / C3503D) boots into its application ===")
uart = []
seen_panels = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
panel, _keys, panel_desc = make_panel(DUMP, log_handler=lambda m: None)
panel.dump_enabled = False


def on_gpio(addr, size, val):
    panel.on_gpio_write(addr, size, val)
    txt = panel.get_display_text()
    if txt.strip() and (not seen_panels or seen_panels[-1] != txt):
        seen_panels.append(txt)


def on_uart(c):
    ch = c if isinstance(c, str) else chr(c)
    uart.append(ch)
    if len(uart) <= 1200:
        sys.stdout.write(ch)
        sys.stdout.flush()
    if STOP_AT in "".join(uart[-len(STOP_AT) - 16:]):
        sim.mu.emu_stop()


sim.setGpioHandler(on_gpio)
sim.setUartHandler(on_uart)
sim.loadFile(DUMP)
chip_word = int.from_bytes(sim.peek(0xB8000000, 4), "little")

t0 = time.time()
while sim.instruction_count < LIMIT and STOP_AT not in "".join(uart[-128:]):
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
print(f"\nStopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), panel history {seen_panels}")
text = "".join(uart)

check(type(sim.chip).__name__ == "C3503" and chip_word == 0x3503D000,
      f"detected as C3503 with C3503D chip word 0x3503D000 (got {type(sim.chip).__name__}, 0x{chip_word:08X})")
check(not sim.chip.see.run_program and sim.chip.see.core is None,
      "single-CPU C3503: no SEE second core spawned")
check(" ON " in seen_panels,
      f"CH455 front panel ({panel_desc}) showed ' ON ' (got {seen_panels})")
for expected in ("Enter Bootloader APP.", "CRC Check Result : Pass",
                 "Run Maincode, main_entry = 0x80000200!", "---led 455 attach OK--",
                 "Starting mcas v.1.0", STOP_AT):
    check(expected in text, f"{expected!r} printed on UART")
check(text.count("Enter Bootloader APP.") == 1, "bootloader ran once (no watchdog reboot)")
check((sim.cp0_ebase & 0xFFFFF000) == 0x80002000,
      f"CP0 EBase moved to 0x80002000 (got 0x{sim.cp0_ebase:08X})")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Edision Picco S2 v.1248 (M3510D / C3503D) boots into its application")
