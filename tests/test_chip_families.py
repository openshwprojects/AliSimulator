#!/usr/bin/env python3
"""
chips.detect() picks each firmware image's chip family from its chunk chain:
the R265 Lite images' "M3821b" bootloader version makes them M3821, the T760i's
boot-ROM bootloader with a SEE program and a main code that names the chip
C3505, the M36xx update images (HDCPKey "Demo s3602", or a maincode named after
the M3602 / M3606 demo projects) M3602, and everything else -- the M3801 dumps
among them -- falls back to the M3801.  Also checks chunk_chain() on one
image's known layout.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules

import chips
from chips.base import chunk_chain
from simulator import resolve_dump

EXPECTED = [
    ("dump.bin", "M3801"),
    ("Ali_3801_Globo_DVBT_dump SPI 4mb.bin", "M3801"),
    ("T650i_V1.13B4_20160721.abs", "M3801"),
    ("M3822P.bin", "M3821"),
    ("T2GEN265_1.2.0-2023-03-17.abs", "M3821"),
    ("URZ0083_V1.2.5.abs", "M3602"),             # HDCPKey "Demo s3602", maincode "Demo M3606"
    ("THT501_V1.1.5a_20120925.abs", "M3602"),    # HDCPKey "Demo s3602", maincode "501"
    ("URZ0086_V1.2.1.abs", "M3602"),             # maincode "M3606 2Tuner"
    ("ArivaT50_20111118_V102B214.abs", "M3602"),  # no HDCPKey chunk: maincode "Demo M3602"
    ("Ferguson_T760i_V1.5B4-14092021.abs", "C3505"),  # boot-ROM bootloader, SEE program, main code names ALI_C3505
    ("Ferguson_T760i_V1.4B8_28072020.abs", "C3505"),
]

print("=== Test: chips.detect() picks each image's chip family ===")
failures = 0
for dump, family in EXPECTED:
    with open(resolve_dump(dump), "rb") as f:
        got = chips.detect(f.read()).__name__
    ok = got == family
    failures += not ok
    print(f"  [{'PASS' if ok else 'FAIL'}] {dump}: {got}" + ("" if ok else f" (expected {family})"))

with open(resolve_dump("URZ0083_V1.2.5.abs"), "rb") as f:
    chain = chunk_chain(f.read())
want = [(0x000000, "bootloader", "DVBT---0.1.0"), (0x01FE00, "HDCPKey", "Demo s3602"),
        (0x020000, "maincode", "Demo M3606"), (0x170000, "Radioback", "1.0.0"),
        (0x177200, "countryband", "1.0.0"), (0x17FF80, "userdb", "1.0.0")]
ok = chain == want
failures += not ok
print(f"  [{'PASS' if ok else 'FAIL'}] chunk_chain(URZ0083_V1.2.5.abs): "
      + ", ".join(f"{name}@0x{off:06X} ({version})" for off, name, version in chain))

print(f"\n[{'PASS' if not failures else 'FAIL'}] chip family detection")
sys.exit(1 if failures else 0)
