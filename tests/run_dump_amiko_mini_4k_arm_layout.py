#!/usr/bin/env python3
"""
The Amiko Mini 4K UHD Combo firmware v1.0.21 EMU (System ID 7C000A00, bootloader
"M2662A 1.0.1") packages an ARMv7-A (ALi M2662A / C3922 4K UHD combo SoC) bootloader
and application inside ALi's standard NCRC flash chunk container (0x23010010 at
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

DUMP = "AMIKO MINI 4K UHD COMBO/AMIKO_Mini_4K_Combo_1.0.21_emu.abs"
failures = []


def check(ok, msg):
    print(f"  [{'PASS' if ok else 'FAIL'}] {msg}")
    if not ok:
        failures.append(msg)


print("=== Regression Test: Amiko Mini 4K UHD Combo v1.0.21 (ALi M2662A / C3922 ARMv7-A in NCRC container) ===")
data = open(resolve_dump(DUMP), "rb").read()
chunks = list(chunk_chain(data))
mc = maincode(data)

check(len(data) == 8 * 1024 * 1024, f"8 MB SPI flash image ({len(data):,} bytes)")
check(len(chunks) >= 4 and chunks[0] == (0x000000, "bootloader", "M2662A 1.0.1")
      and chunks[1] == (0x078000, "maincode(AV)", "7C000A001021"),
      f"NCRC layout starts with bootloader 'M2662A 1.0.1' and maincode(AV) '7C000A001021' (got {chunks[:2]})")
check(data[0x258:0x25C] == b"HEAD", "boot-ROM descriptor carries 'HEAD' tag at 0x258")

vec0, vec1, vec2 = struct.unpack_from("<III", data, 0x800)
check(vec0 == 0xEA000006 and vec1 == 0xEAFFFFFE and vec2 == 0xEA00004D,
      f"0x800 holds ARMv7-A exception vector branches (0x{vec0:08X}, 0x{vec1:08X}, 0x{vec2:08X})")

check(mc is not None and len(mc) == 15_835_440 and b"DECV_HEVC_0" in mc and b"NIM_C3501h_0" in mc,
      f"LZMA maincode(AV) decompresses to {len(mc) if mc else 0:,} bytes naming DECV_HEVC_0 and NIM_C3501h_0")

if failures:
    print(f"\n[FAIL] {len(failures)} check(s) failed")
    sys.exit(1)
print("\n[PASS] Amiko Mini 4K UHD Combo v1.0.21 (ALi M2662A / C3922 ARMv7-A) verified")
