#!/usr/bin/env python3
"""The Amiko Mini HD265 firmware 1.1.67 (System ID 6B000A00, ALi M3521A / C3505 with 128 MB DDR3,
chips/c3505.py) boots through the boot-ROM path in boot SRAM at 0x9FE00800, unpacks its
maincode(AV) chunk at 0x030000 (chips/base.py) to 0x80000200 and its SEE program ("M3606 SEE") to
0xA6000200, starts the SEE core at 0xA6000200 (chips/see.py SeeCore, EBase 0x86002001), moves the
main CPU's CP0 EBase to 0x80002000, attaches its CH455 front panel ("---led 455 attach OK--"), and
exchanges remote calls with the SEE co-processor.
"""
import see_regression

see_regression.run(
    "AMIKO MINI HD265/Amiko_Mini_HD265_1.1.67_emu.abs",
    "the Amiko Mini HD265 (128 MB C3505) runs its application and the SEE's program at 0xA6000200",
    family="C3505",
    starts=[(0xA6000200, "run on the SEE core")],
    calls=30,
    see_calls=30,
    limit=160_000_000,
    uart=[
        "Enter Bootloader APP.",
        "Run Maincode, main_entry = 0x80000200!",
        "---led 455 attach OK--",
        "----need_updata_system=1-----",
        "libnet_init  error!",
    ],
    ebase=0x80002000,
    see_ebase=0x86002001,
    wait_for=lambda r: "libnet_init  error!" in r.text,
    checks=[
        lambda r: (
            r.sim.ram_size == 0x08000000 and not r.sim._upper_ram_mapped,
            f"128 MB DDR3 active without 256 MB upper-RAM remap "
            f"(ram_size=0x{r.sim.ram_size:X}, upper_ram={r.sim._upper_ram_mapped})",
        ),
    ],
)
