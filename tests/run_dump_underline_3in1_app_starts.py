#!/usr/bin/env python3
"""
The Edision Optimuss Underline 3in1 firmware 1.3.79 emu (single-CPU ALi M3612 /
S3811, chips/m3801.py: chip ID 0x3811, bootloader "M3612 1.0.4") boots through
its MIPS16e bootloader at 0x81E80000, writes " ON " to its CH455 4-digit panel
on GPIO 31 (SCL) / 9 (SDA), verifies and unpacks its 11.6 MB maincode(AV) to
0x80000200, moves CP0 EBase to 0x80002000, probes its external Availink
AVL6862 combo demodulator on SCB0 at I2C 0x14 (ChipID 0x0F -> "Demod is 6862!!!",
demods.AVL6862A), configures both its Sharp VZ7903 / AV2012 DVB-S2 tuner (0x61)
and Rafael Micro R836 DVB-T2/C tuner (0x3A), updates the CH455 display to
" on ", and initialises its hs_config database without rebooting.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = "EDISION OPTIMUSS UNDERLINE 3IN1/Edision.optimuss.underline.3in1.0E06080emu_1.3.79.abs"
LIMIT = 100_000_000
SLICE = 5_000_000
STOP_AT = "================control data write ============="

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Edision Optimuss Underline 3in1 1.3.79 (M3612 / M3801) boots into its application ===")
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
    if STOP_AT in "".join(uart[-len(STOP_AT) - 16:]):
        sim.mu.emu_stop()


sim.setGpioHandler(panel.on_gpio_write)
sim.setUartHandler(on_uart)
sim.loadFile(DUMP)
sim.attach_tuner()
chip_id = int.from_bytes(sim.peek(0xB8000002, 2), "little")

t0 = time.time()
while sim.instruction_count < LIMIT and STOP_AT not in "".join(uart[-128:]):
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    txt = panel.get_display_text()
    if txt.strip() and (not seen_panels or seen_panels[-1] != txt):
        seen_panels.append(txt)
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
print(f"\nStopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), panel history {seen_panels}")
text = "".join(uart)

check(type(sim.chip).__name__ == "M3801" and chip_id == 0x3811,
      f"detected as M3801 with S3811 chip ID 0x3811 (got {type(sim.chip).__name__}, 0x{chip_id:04X})")
check(" ON " in seen_panels,
      f"CH455 front panel ({panel_desc}) showed ' ON ' (got {seen_panels})")
for expected in ("APP  init ok", "-->>ch455!!", "bl_verify_sw", "success!",
                 "Demod is 6862!!!", "--> r = 0", "<-- r = 0", STOP_AT):
    check(expected in text, f"{expected!r} printed on UART")
check(text.count("APP  init ok") == 1, "bootloader ran once (no watchdog reboot)")
check((sim.cp0_ebase & 0xFFFFF000) == 0x80002000,
      f"CP0 EBase moved to 0x80002000 (got 0x{sim.cp0_ebase:08X})")
avl = sim.i2c_devices.get(0x14)
av2012 = sim.i2c_devices.get(0x61)
r836 = sim.i2c_devices.get(0x3A)
check(avl is not None and avl.writes > 20 and avl.reads > 10,
      f"Availink AVL6862A answered on SCB0 at I2C 0x14 (writes={getattr(avl, 'writes', 0)}, reads={getattr(avl, 'reads', 0)})")
check(av2012 is not None and av2012.writes > 10 and r836 is not None and r836.writes > 50,
      f"Sharp VZ7903 / AV2012 (0x61 writes={getattr(av2012, 'writes', 0)}) and R836 (0x3A writes={getattr(r836, 'writes', 0)}) configured")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Edision Optimuss Underline 3in1 1.3.79 (M3612 / M3801) boots into its application")
