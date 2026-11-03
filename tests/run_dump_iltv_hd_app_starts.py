#!/usr/bin/env python3
"""
The ILTV HD firmware 1.5.27 (System ID 06020200, ALi M3602B, chips/m3602.py)
boots its "M3602B 1.1.6" bootloader on a 4 MB SPI flash, exchanges CRC-16/XMODEM
8-byte transactions with the external Lemontree EuP standby and 4-digit
7-segment front-panel microcontroller at I2C 0x28 on bit-banged SCL = GPIO 62 /
SDA = GPIO 171 (lemontree_decoder.py, updating the display " ON " -> "    " ->
" on "), prints "APP  init ok", and unpacks its maincode(AV) to 0x80008000.  The
single-CPU application configures the ALi S3501 DVB-S2 demodulator at I2C 0x33
and Airoha AV2011 tuner at I2C 0x60 and draws its ILTV OSD dialog through
GeM3602.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
from simulator import AliMipsSimulator, flash_size_for

DUMP = "ILTV HD/iltv_1.5.27_hd_x4_newoldremote.abs"
LIMIT = 80_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: ILTV HD 1.5.27 (M3602B) boots into its application ===")
uart = []
panel_texts = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)

panel, _, _ = make_panel(DUMP, log_handler=lambda m: None)
sim.setGpioHandler(panel.on_gpio_write)
sim.setUartHandler(lambda c: uart.append(c if isinstance(c, str) else chr(c)))
sim.loadFile(DUMP)
tuner = sim.attach_tuner()

t0 = time.time()
while sim.instruction_count < LIMIT:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    cur = panel.get_display_text()
    if cur and (not panel_texts or panel_texts[-1] != cur):
        panel_texts.append(cur)
    if sim.ge_ops >= 4 and panel.get_display_text() == " on " and panel.i2c_transaction_count >= 25 and tuner is not None and tuner.writes >= 50:
        break
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), "
      f"ge_ops={sim.ge_ops}, mcu_tx={panel.i2c_transaction_count}, panel_texts={panel_texts}")

check(type(sim.chip).__name__ == "M3602" and sim.chip.chip_id == 0x3602,
      f"detected as M3602 with chip ID 0x3602 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check(panel.i2c_transaction_count >= 25 and panel.frame_count >= 3 and panel.get_display_text() == " on ",
      f"Lemontree EuP MCU answered {panel.i2c_transaction_count} CRC-16/XMODEM transactions and {panel.frame_count} "
      f"display frames on GPIO 62 / 171 (texts={panel_texts}, final={panel.get_display_text()!r})")
check("APP  init ok" in text, "'APP  init ok' printed on UART")
check(text.count("APP  init ok") == 1,
      "bootloader banner printed once (no watchdog or MCU-handshake reboot)")
check(0x33 in sim.i2c_devices and len(sim.i2c_devices[0x33].regs) > 4,
      f"ALi S3501 DVB-S2 demodulator configured at I2C 0x33 ({len(sim.i2c_devices.get(0x33).regs) if 0x33 in sim.i2c_devices else 0} registers)")
check(tuner is not None and tuner.writes >= 50,
      f"Airoha AV2011 DVB-S2 tuner configured at I2C 0x60 ({tuner and tuner.writes} writes)")
check(sim.ge_ops >= 4,
      f"GeM3602 executed {sim.ge_ops} graphics engine commands")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] ILTV HD 1.5.27 (M3602B) boots into its application")
