#!/usr/bin/env python3
"""
The Opticum X80 Premium 2 MB SPI flash dump (firmware V1.2.62C, ALi M3329C /
M3101C, chips/m3329.py) auto-selects chip ID 0x3101 and SPI flash mode
(ParallelNorFlash disconnected so native SPI flash serves 0xB8000098), boots
its ETK01---0.1.0 bootloader ("BL: APP  init ok"), unpacks its 2.7 MB LZMA
Libcore 1.3.4 maincode to SDRAM ("MC:APP  init ok", "APP init finished..."),
drives its 4-digit panel on GPIO 30 (SCL) / 31 (SDA) through " on " -> "----"
-> "OOO1", and exposes its 0x0101 remote key table with customer code
0x02370000 off $gp.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = "OPTICUM X80 PREMIUM/dump opticum x80 premium.bin"
LIMIT = 50_000_000
SLICE = 2_500_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Opticum X80 Premium V1.2.62C (M3329C / M3101C) boots into its application ===")
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
chip_id = int.from_bytes(sim.peek(0xB8000002, 2), "little")

t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    txt = panel.get_display_text()
    if txt.strip() and (not seen_panels or seen_panels[-1] != txt):
        seen_panels.append(txt)
    if txt == "OOO1" and "APP init finished" in "".join(uart):
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
print(f"\nStopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), panel history {seen_panels}")
text = "".join(uart)

check(type(sim.chip).__name__ == "M3329" and chip_id == 0x3101,
      f"detected as M3329 with M3329C/M3101C chip ID 0x3101 (got {type(sim.chip).__name__}, 0x{chip_id:04X})")
check(sim.flash_device is None,
      f"SPI flash detected by bootloader SF_INS stores (flash_device={sim.flash_device})")
for expected in ("BL: APP  init ok", "MC:APP  init ok", "APP init finished..."):
    check(expected in text, f"{expected!r} printed on UART")
check(text.count("BL: APP  init ok") == 1, "bootloader ran once (no watchdog reboot)")
check(" on " in seen_panels and "OOO1" in seen_panels,
      f"front panel ({panel_desc}) showed ' on ' -> 'OOO1' (got {seen_panels})")
menu_frame = sim.chip.remote_frame("MENU")
check(menu_frame == (0x40, 0x40, 0xEC),
      f"0x0101 Libcore key table + $gp IR_USR_CODE 0x02370000 resolves MENU to (0x40, 0x40, 0xEC) (got {menu_frame})")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Opticum X80 Premium V1.2.62C (M3329C / M3101C) boots into its application")
