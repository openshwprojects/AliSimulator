#!/usr/bin/env python3
"""
The Amiko HD9265+ firmware v1.0.12 MCAS (System ID 8E000A00, bootloader "M3759A
1.0.1") packages an ARMv7-A (ALi M3759A / C3702 / CAP210) bootloader and
application inside ALi's standard NCRC flash chunk container (0x23010010 at
0x000000, "HEAD" record at 0x250, and LZMA-compressed maincode(AV) at 0x078000).
Verify the NCRC chunk layout, the ARMv7-A exception vector table and CP15 SCTLR
read at offset 0x800, and the decompressed ARMv7-A maincode image.
"""
import os
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from chips.base import chunk_chain, maincode
from simulator import resolve_dump

DUMP = "AMIKO HD9265+/Amiko_HD9265+_1.0.12_mcas.abs"
failures = []


def check(ok, msg):
    print(f"  [{'PASS' if ok else 'FAIL'}] {msg}")
    if not ok:
        failures.append(msg)


print("=== Regression Test: Amiko HD9265+ v1.0.12 MCAS (ALi M3759A / C3702 ARMv7-A in NCRC container) ===")
data = open(resolve_dump(DUMP), "rb").read()
chunks = list(chunk_chain(data))
mc = maincode(data)

check(len(data) == 8 * 1024 * 1024, f"8 MB SPI flash image ({len(data):,} bytes)")
check(len(chunks) == 14 and chunks[0] == (0x000000, "bootloader", "M3759A 1.0.1")
      and chunks[1] == (0x078000, "maincode(AV)", "8E000A001012"),
      f"14-chunk NCRC layout starts with bootloader 'M3759A 1.0.1' and maincode(AV) '8E000A001012' (got {chunks[:2]})")
check(data[0x258:0x25C] == b"HEAD", "boot-ROM descriptor carries 'HEAD' tag at 0x258")

vec0, vec1, vec2 = struct.unpack_from("<III", data, 0x800)
cp15_mrc, cp15_bic = struct.unpack_from("<II", data, 0x820)
check(vec0 == 0xEA000006 and vec1 == 0xEAFFFFFE and vec2 == 0xEA00004D,
      f"0x800 holds ARMv7-A exception vector branches (0x{vec0:08X}, 0x{vec1:08X}, 0x{vec2:08X})")
check(cp15_mrc == 0xEE110F10 or cp15_mrc == 0xEE400F10 or (cp15_mrc & 0x0F000F10) == 0x0E000F10,
      f"reset handler at 0x820 accesses ARM CP15 (0x{cp15_mrc:08X}, 0x{cp15_bic:08X})")
check(len(mc) > 15_000_000 and b"M3759" in mc and b"C3702" in mc and b"get_clock_cap210" in mc,
      f"LZMA maincode(AV) decompresses to {len(mc):,} bytes naming M3759 / C3702 / get_clock_cap210")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Amiko HD9265+ v1.0.12 MCAS (ALi M3759A / C3702 ARMv7-A container layout verified)")
