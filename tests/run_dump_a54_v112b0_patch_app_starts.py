#!/usr/bin/env python3
"""
The Ferguson Ariva 54 patched firmware V1.12B0_PATCH (single-CPU ALi C3503D,
chips/c3503.py: chip word 0x3503D000, SDK chip code 0x10051) boots through its
boot-ROM SRAM bootloader at 0x9FE00800, writes " On " to its external FD650K
4-digit panel on GPIO 24 (SCL) / 23 (SDA), unpacks its 9.99 MB maincode to
0x80000200 and starts the application.  With its internal S3501-class DVB-S2
demodulator answering at 0xB804C000 and its M3031 tuner at I2C 0x20, the
application moves CP0 EBase, updates the panel to " on ", prints its SDK banner
and starts its tasks without rebooting.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = "FERGUSON ARIVA 54/A54_20190114_V1.12B0_PATCH.abs"
LIMIT = 150_000_000
SLICE = 5_000_000
STOP_AT = "create cs_Init task"

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Ferguson Ariva 54 V1.12B0_PATCH (C3503D) boots into its application ===")
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
    if len(uart) <= 1000:
        sys.stdout.write(ch)
        sys.stdout.flush()
    if STOP_AT in "".join(uart[-len(STOP_AT) - 16:]):
        sim.mu.emu_stop()


sim.setGpioHandler(on_gpio)
sim.setUartHandler(on_uart)
sim.loadFile(DUMP)
tuner = sim.attach_tuner()
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
check(tuner is not None and tuner.writes > 0,
      f"the M3031 tuner at I2C 0x20 was configured ({tuner and tuner.writes} writes)")
check(" On " in seen_panels and " on " in seen_panels,
      f"FD650K front panel ({panel_desc}) showed bootloader ' On ' and app ' on ' (got {seen_panels})")
for expected in ("MC: APP  init ok", "Libcore version 17.15.0@SDK4.0ia.17.15_20171115",
                 "Application version 1.0.0@SDK4.0ia.17.14b_20171018bytest",
                 "It's cold boot", STOP_AT):
    check(expected in text, f"{expected!r} printed on UART")
check("reset nim failed" not in text, "internal DVB-S2 demodulator at 0xB804C000 initialized without 'reset nim failed'")
check(text.count("MC: APP  init ok") == 1, "application banner printed once (no watchdog reboot)")
check((sim.cp0_ebase & 0xF0000000) == 0x80000000 and (sim.cp0_ebase & 0xFFFFF000) != 0x80000000,
      f"CP0 EBase moved into RAM (got 0x{sim.cp0_ebase:08X})")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Ferguson Ariva 54 V1.12B0_PATCH (C3503D) boots into its application")
