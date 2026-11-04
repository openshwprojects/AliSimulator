#!/usr/bin/env python3
"""The Amiko HD8265+ firmware v.1515 (Edision GUI build, System ID 6C000A00, ALi M3529A / C3505 with
256 MB DDR3, chips/c3505.py) boots through the boot-ROM path in boot SRAM at 0x9FE00800, unpacks its
maincode(AV) chunk (chips/base.py) to 0x80000200 and its SEE program ("M3606 SEE") to 0xAE000200,
sets 0xB8000220 bit 24 to remap physical 0x0F000000..0x0FFFFFFF to the top 16 MB of DDR, starts the
SEE core at 0xAE000200 (chips/see.py SeeCore, EBase 0x8E002001), moves the main CPU's CP0 EBase to
0x80002000, attaches its CH455 front panel ("---led 455 attach OK--"), and initialises its external
Availink AVL6762 DVB-T2/C demodulator ("Demod is 6762!!!", I2C 0x14 on SCB3), Airoha AV2012 DVB-S2
tuner (I2C 0x61 on SCB1) and MaxLinear MxL608 DVB-T2/C tuner (I2C 0x60 on SCB3).
"""
import see_regression

see_regression.run(
    "AMIKO HD8265+/AMIKO 8265+ Edision_v.1515.abs",
    "the Amiko HD8265+ v.1515 (256 MB C3505) runs its application, SEE at 0xAE000200, and AVL6762 + AV2012 + MxL608 RF chain",
    family="C3505",
    starts=[(0xAE000200, "run on the SEE core")],
    calls=8,
    see_calls=0,
    limit=160_000_000,
    setup=lambda sim: sim.attach_tuner(),
    uart=[
        "Enter Bootloader APP.",
        "Run Maincode, main_entry = 0x80000200!",
        "---led 455 attach OK--",
        "Demod is 6762!!!",
    ],
    ebase=0x80002000,
    see_ebase=0x8E002001,
    wait_for=lambda r: (
        "Demod is 6762!!!" in r.text
        and 0x61 in r.sim.i2c_devices and r.sim.i2c_devices[0x61].writes >= 5
        and 0x60 in r.sim.i2c_devices and r.sim.i2c_devices[0x60].writes >= 80
    ),
    checks=[
        lambda r: (
            r.sim.ram_size == 0x10000000 and r.sim._upper_ram_mapped,
            f"256 MB DDR3 active and 0xB8000220 bit 24 remapped 0x0F000000..0x0FFFFFFF to RAM "
            f"(ram_size=0x{r.sim.ram_size:X}, upper_ram={r.sim._upper_ram_mapped})",
        ),
        lambda r: (
            0x14 in r.sim.i2c_devices and r.sim.i2c_devices[0x14].reads >= 50,
            f"Availink AVL6762 demodulator answered on SCB3 at I2C 0x14 "
            f"(writes={r.sim.i2c_devices[0x14].writes}, reads={r.sim.i2c_devices[0x14].reads})",
        ),
        lambda r: (
            0x61 in r.sim.i2c_devices and r.sim.i2c_devices[0x61].writes >= 5
            and 0x60 in r.sim.i2c_devices and r.sim.i2c_devices[0x60].writes >= 80,
            f"Airoha AV2012 (0x61: writes={r.sim.i2c_devices[0x61].writes}) and "
            f"MaxLinear MxL608 (0x60: writes={r.sim.i2c_devices[0x60].writes}) tuners configured",
        ),
    ],
)
