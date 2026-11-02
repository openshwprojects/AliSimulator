#!/usr/bin/env python3
"""The Edision Piccollino S2+T2/C firmware v.1539 (System ID 6A000100, ALi
M3526A / C3505 with 256 MB DDR3 and 8 MB SPI flash, chips/c3505.py) boots
through the boot-ROM path in boot SRAM at 0x9FE00800, copies its bootloader to
0x81000000, sets 0xB8000220 bit 24 to remap physical 0x0F000000..0x0FFFFFFF to
the top 16 MB of DDR, shows its boot logo through VideoOutputM36F
(video_m36.py, VSync interrupts on IC line 2), unpacks seecode ("M3606 SEE" at
0x3F0000) to 0xAE000200 and maincode(AV) (at 0x060000) to 0x80000200, and
starts both cores (main EBase 0x80002000, SEE EBase 0x8E002001).  The
application attaches its CH455 front panel ("---led 455 attach OK--") on GPIO
107 / 110 and exchanges remote calls with the SEE co-processor (including DSC
Command Queue operations in crypto_engine.py).
"""
import see_regression

see_regression.run(
    "EDISION PICCOLLINO S2+T2C/piccollino_S2+T2C_v.1539.abs",
    "Edision Piccollino S2+T2/C (8 MB flash, 256 MB C3505) runs its application and the SEE's program at 0xAE000200",
    family="C3505",
    starts=[(0xAE000200, "run on the SEE core")],
    calls=30,
    see_calls=30,
    limit=130_000_000,
    uart=[
        "Enter Bootloader APP.",
        "bl_show_logo 1115: HELLO WORLD LOGO!!",
        "Run Seecode, see_entry = 0xae000200!",
        "Run Maincode, main_entry = 0x80000200!",
        "---led 455 attach OK--",
        "Check_Av2012_0xc4_ext",
    ],
    ebase=0x80002000,
    see_ebase=0x8E002001,
    wait_for=lambda r: (
        "Check_Av2012_0xc4_ext" in r.text
        and r.sim.chip.see.doorbells.taken["main"][0] >= 30
        and r.sim.chip.see.doorbells.taken["SEE"][0] >= 30
    ),
    checks=[
        lambda r: (
            r.sim.ram_size == 0x10000000 and r.sim._upper_ram_mapped,
            f"256 MB DDR3 active and 0xB8000220 bit 24 remapped 0x0F000000..0x0FFFFFFF to RAM "
            f"(ram_size=0x{r.sim.ram_size:X}, upper_ram={r.sim._upper_ram_mapped})",
        ),
    ],
)
