#!/usr/bin/env python3
"""
The Openbox S10 HD PVR firmware C2HS2-12-06-18:05E3CMT (single-CPU ALi M3602,
chips/m3602.py: bootloader "SMT---1.0.0", maincode "SMT 1.0.0", 4 MB SPI flash)
probes DDR at 0xA800AA68, unpacks its 5.88 MB maincode to 0x80000200, prints
"APP  init ok" on the UART, configures its external ALi S3501 DVB-S2
demodulator at I2C 0x33 and Airoha AV2012 DVB-S2 tuner at I2C 0x60 on SCB0,
and issues graphics engine commands through both 0xB800A000 and 0xB800C000.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for

DUMP = "OPENBOX S10/C2HS2-12-06-18_05E3CMT.ABS"
LIMIT = 35_000_000
SLICE = 5_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Openbox S10 HD PVR (ALi M3602, 'SMT 1.0.0') boots into its application ===")
uart = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.setUartHandler(lambda c: uart.append(c if isinstance(c, str) else chr(c)))
sim.loadFile(DUMP)

t0 = time.time()
while sim.instruction_count < LIMIT and sim.ge_ops < 10:
    before = sim.instruction_count
    sim.run(max_instructions=sim.instruction_count + SLICE)
    if sim.instruction_count <= before:
        break
elapsed = time.time() - t0
text = "".join(uart)
print(f"Stopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s), GE ops={sim.ge_ops}")

check(type(sim.chip).__name__ == "M3602" and sim.chip.chip_id == 0x3602,
      f"detected as M3602 with chip ID 0x3602 (got {type(sim.chip).__name__}, 0x{sim.chip.chip_id:04X})")
check(not sim.chip.see.starts and sim.chip.see.core is None,
      f"single-CPU 'SMT' M3602 build: no SEE second core spawned (starts={sim.chip.see.starts})")
check("APP  init ok" in text, f"'APP  init ok' printed on UART (got {text!r})")
check(0x33 in sim.i2c_devices and sim.i2c_devices[0x33].regs[0x00] == 0x91,
      f"external S3501 DVB-S2 demodulator at I2C 0x33 configured on SCB0 (reg 0x00=0x{sim.i2c_devices[0x33].regs[0x00]:02X})")
check(sim.ge_ops >= 10,
      f"application issued >= 10 GE commands on 0xB800A000 (got {sim.ge_ops})")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Openbox S10 HD PVR (ALi M3602, 'SMT 1.0.0') boots into its application")
