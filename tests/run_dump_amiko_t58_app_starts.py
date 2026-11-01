#!/usr/bin/env python3
"""
The Amiko T58 FTA firmware 1.0.60 (single-CPU ALi M3821, chips/m3821.py: chip
ID 0x3821 revision B, variant 0x0001; XIP Cache-as-RAM BootLoader 1.0.0;
HDCPKey "M3821") boots from flash through CacheAsRam into RAM at 0x81000000,
writes " ON " to its CH455 panel on GPIO 128 (SCL) / 129 (SDA), unpacks its
8.1 MB MainCode to 0x80000200, moves CP0 EBase to 0x80002000, probes its
Rafael Micro R836 tuner on SCB2 at I2C 0x3A ("--->> tuner type : 836"),
initialises UserDB ("DB_init() success!", "ali play 1.0 $$$"), and updates the
CH455 panel through " on " to "Strt".
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = "AMIKO T58/AMIKO_T58_1.0.60_fta.abs"
LIMIT = 80_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Amiko T58 1.0.60 FTA (single-CPU M3821) boots into its application ===")
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
    if len(uart) <= 1200 and ch.isascii() and (ch.isprintable() or ch in "\r\n\t"):
        sys.stdout.write(ch)
        sys.stdout.flush()


sim.setGpioHandler(panel.on_gpio_write)
sim.setUartHandler(on_uart)
sim.loadFile(DUMP)
sim.attach_tuner()
chip_word = int.from_bytes(sim.peek(0xB8000000, 4), "little")

t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    txt = panel.get_display_text()
    if txt.strip() and (not seen_panels or seen_panels[-1] != txt):
        seen_panels.append(txt)
    if txt == "Strt" and "ali play 1.0 $$$" in "".join(uart):
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
print(f"\nStopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), panel history {seen_panels}")
text = "".join(uart)

check(type(sim.chip).__name__ == "M3821" and chip_word == 0x38210001,
      f"detected as M3821 with revision-B word 0x38210001 (got {type(sim.chip).__name__}, 0x{chip_word:08X})")
check(" ON " in seen_panels and "Strt" in seen_panels,
      f"CH455 front panel ({panel_desc}) showed ' ON ' -> 'Strt' (got {seen_panels})")
for expected in ("MC: APP  init ok", "Libcore version 13.10.0", "Application version 1.0.0",
                 "test r836 tuner i2c --> 1", "--->> tuner type : 836", "DB_init() success!", "ali play 1.0 $$$"):
    check(expected in text, f"{expected!r} printed on UART")
check(text.count("MC: APP  init ok") == 1, "bootloader ran once (no watchdog reboot)")
check((sim.cp0_ebase & 0xFFFFF000) == 0x80002000,
      f"CP0 EBase moved to 0x80002000 (got 0x{sim.cp0_ebase:08X})")
r836 = sim.i2c_devices.get(0x3A)
check(r836 is not None and r836.writes >= 20,
      f"Rafael Micro R836 answered on SCB2 at I2C 0x3A (writes={getattr(r836, 'writes', 0)})")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Amiko T58 1.0.60 FTA (single-CPU M3821) boots into its application")
