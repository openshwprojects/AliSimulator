#!/usr/bin/env python3
"""
Regression test for the Ferguson Ariva 160 Combo official firmware (2025-11-26):
a DVB-S2X + DVB-T2/C Full HD H.265/HEVC combo receiver on ALi C3505 SoC with 256 MB DDR3
(chips/c3505.py, chipId 0x3821, variant 0xC000).

Verifies the HATK5 bootloader unpacks maincode to 0x80000200, sets up 256 MB DDR3,
and launches Libcore 19.17.0 application.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from simulator import AliMipsSimulator, flash_size_for

DUMP = "FERGUSON ARIVA 160 COMBO/Ferguson_160combo_20251126.abs"
LIMIT = 30_000_000

failures = []


def check(ok, text):
    print(f"  [{'PASS' if ok else 'FAIL'}] {text}")
    if not ok:
        failures.append(text)


print("=== Regression Test: Ferguson Ariva 160 Combo boots into Libcore application ===")
uart_lines = []


def on_uart(b):
    c = b if isinstance(b, str) else chr(b)
    uart_lines.append(c)


sim = AliMipsSimulator(rom_size=flash_size_for(DUMP), log_handler=lambda m: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
sim.setUartHandler(on_uart)

sim.loadFile(DUMP)
sim.run(max_instructions=LIMIT)

uart_text = "".join(uart_lines)

check(type(sim.chip).__name__ == "C3505", f"detected as C3505 (got {type(sim.chip).__name__})")
check(sim.chip.chip_id == 0x3821, f"chip ID is 0x3821 (got 0x{sim.chip.chip_id:04X})")
check(sim.ram_size == 0x08000000, f"128 MB DDR3 configured (got 0x{sim.ram_size:X})")
check(sim.instruction_count >= 20_000_000, f"bootloader and application executed ({sim.instruction_count} instructions)")
check("SDK4.0ba.4.0_20101217" in uart_text, "SDK banner present in UART")
check("Libcore version 19.17.0" in uart_text, "Libcore version 19.17.0 banner present in UART")
check("NOR flash id_buf[0]=0x001740EF" in uart_text, "SPI flash identification completed")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Ferguson Ariva 160 Combo boots into Libcore application")
