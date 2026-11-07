#!/usr/bin/env python3
"""The Opticum XS65 Polish retail firmware 1.4.0 (140_M3511-RETAIL_PL.abs, a 4 MB SPI image for the
128 MB single-tuner DVB-S2 ALi M3511 / M3503 board, chips/m3503.py) has a numeric-named 0x01FE0101
maincode chunk ("112003000202162" at 0x030000).  It boots XIP with its stack in the cache-as-RAM
window (0x8FFF8000..0x8FFFFFFF), switches to RAM, parks the SEE boot stub at 0xA1016804, unpacks
seecode ("00000140") to 0x86000200 and maincode to 0x80000200, starts both cores (main EBase
0x80002000, SEE EBase 0x86002001), and draws its OSD through the graphics engine.
"""
import see_regression

DUMP = "OPTICUM XS65/140_M3511-RETAIL_PL.abs"

see_regression.run(
    DUMP,
    "the Opticum XS65 (4 MB flash, 128 MB M3511 / M3503) runs its application and SEE at 0x86000200",
    family="M3503",
    starts=[(0xA1016804, "parked"), (0x86000200, "run on the SEE core")],
    calls=150,
    see_calls=30,
    limit=90_000_000,
    uart=["\x01\x01\x01"],
    ebase=0x80002000,
    see_ebase=0x86002001,
    wait_for=lambda r: r.sim.ge_ops >= 200,
    checks=[
        lambda r: (
            sum(m.startswith("[CAR]") for m in r.logs) == 1,
            "the bootloader keeps its stack in the cache-as-RAM range, then runs from RAM",
        ),
        lambda r: (
            r.sim.ram_size == 0x08000000 and not r.sim._upper_ram_mapped,
            f"128 MB DDR3 active without 256 MB upper-DDR remap "
            f"(ram_size=0x{r.sim.ram_size:X}, upper_ram={r.sim._upper_ram_mapped})",
        ),
        lambda r: (
            r.sim.ge_ops >= 200,
            f"application issued >= 200 GE commands ({r.sim.ge_ops})",
        ),
    ],
)
