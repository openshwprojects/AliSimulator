#!/usr/bin/env python3
"""
The Ferguson Ariva 53 official firmware V1.33B7 (single-CPU ALi C3503C,
chips/c3503.py: chip word 0x3503C000, SDK chip code 0x10050, OTP product 5)
runs its verbose boot-ROM SRAM bootloader ($sp = 0x9FE07F00), calibrates DDR
delay from the ring-oscillator count in 0xB8000302 ("RingOSDelay=296.29600(ns)"),
checks the maincode CRC and unpacks the 9.7 MB maincode to 0x80000200.  The
application passes its 0x10050 board guard at 0x80150EBC, initializes the
internal DVB-S2 demodulator at 0xB804C000 and the M3031 tuner at I2C 0x20
("M3031" on UART), and starts its tasks without rebooting.
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for

DUMP = "A53_20190813_V1.33B7.abs"
LIMIT = 180_000_000
SLICE = 5_000_000
STOP_AT = "create cs_Init task"

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print(f"=== Regression Test: Ferguson Ariva 53 V1.33B7 (C3503C) boots into its application ===")
uart = []
sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)


def on_uart(c):
    ch = c if isinstance(c, str) else chr(c)
    uart.append(ch)
    if len(uart) <= 1200:
        sys.stdout.write(ch)
        sys.stdout.flush()
    if STOP_AT in "".join(uart[-len(STOP_AT) - 16:]):
        sim.mu.emu_stop()


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
print(f"\nStopped after {sim.instruction_count / 1e6:.1f} M instructions ({elapsed:.1f}s)")
text = "".join(uart)

check(type(sim.chip).__name__ == "C3503" and chip_word == 0x3503C000,
      f"detected as C3503 with C3503C chip word 0x3503C000 (got {type(sim.chip).__name__}, 0x{chip_word:08X})")
check(bytes(sim.chip.otp.data[0x210:0x214]) == (5 << 20).to_bytes(4, "little"),
      "OTP word 0x210 carries C3503C DVB-S2 product ID 5 (0x00500000)")
check(not sim.chip.see.run_program and sim.chip.see.core is None,
      "single-CPU C3503: no SEE second core spawned")
check(tuner is not None and tuner.writes > 0,
      f"the M3031 tuner at I2C 0x20 was configured ({tuner and tuner.writes} writes)")
for expected in ("Enter Bootloader APP.", "RingOSDelay=296.29600(ns)", "CRC Check Result : Pass",
                 "Expand Maincode Success, unzip_length = 0x9ad428", "MC: APP  init ok",
                 "Libcore version 17.14.c@SDK4.0ia.17.14c_20171113", "M3031",
                 "It's cold boot", STOP_AT):
    check(expected in text, f"{expected!r} printed on UART")
check("reset nim failed" not in text, "internal DVB-S2 demodulator at 0xB804C000 initialized without 'reset nim failed'")
check(text.count("Enter Bootloader APP.") == 1 and text.count("MC: APP  init ok") == 1,
      "bootloader and application banners printed once (no watchdog reboot)")
check((sim.cp0_ebase & 0xFFFFF000) == 0x80002000,
      f"CP0 EBase moved to 0x80002000 (got 0x{sim.cp0_ebase:08X})")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Ferguson Ariva 53 V1.33B7 (C3503C) boots into its application")
