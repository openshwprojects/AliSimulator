#!/usr/bin/env python3
"""The Amiko HD8155 firmware v.1453 (Edision GUI build, System ID 6B000A00, ALi M3521A / C3505 with
128 MB DDR3, chips/c3505.py) boots through the boot-ROM path in boot SRAM at 0x9FE00800, unpacks its
maincode(AV) chunk (chips/base.py) to 0x80000200 and its SEE program ("M3606 SEE") to 0xA6000200,
starts the SEE core at 0xA6000200 (chips/see.py SeeCore, EBase 0x86002001), moves the main CPU's CP0
EBase to 0x80002000, attaches its CH455 front panel ("---led 455 attach OK--"), and exchanges remote
calls with the SEE co-processor.
"""
import see_regression

see_regression.run(
    "AMIKO HD8155/AMIKO 8155 Edision_v.1453.abs",
    "the Amiko HD8155 (128 MB C3505) runs its application and the SEE's program at 0xA6000200",
    family="C3505",
    starts=[(0xA6000200, "run on the SEE core")],
    calls=30,
    see_calls=30,
    limit=160_000_000,
    uart=[
        "Enter Bootloader APP.",
        "Run Maincode, main_entry = 0x80000200!",
        "---led 455 attach OK--",
        "Starting mcas v.1.0",
    ],
    ebase=0x80002000,
    see_ebase=0x86002001,
    wait_for=lambda r: "Starting mcas v.1.0" in r.text,
    checks=[
        lambda r: (
            r.sim.ram_size == 0x08000000 and not r.sim._upper_ram_mapped,
            f"128 MB DDR3 active without 256 MB upper-RAM remap "
            f"(ram_size=0x{r.sim.ram_size:X}, upper_ram={r.sim._upper_ram_mapped})",
        ),
    ],
)
