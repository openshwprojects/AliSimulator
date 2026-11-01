#!/usr/bin/env python3
"""The Amiko Impulse H.265 T2/C firmware v1.3.87 (System ID 74000A00, ALi M3626A / C3505 with 128 MB
DDR3, chips/c3505.py) boots through the boot-ROM path in boot SRAM at 0x9FE00800, unpacks its
maincode(AV) chunk (chips/base.py) to 0x80000200 and its SEE program ("M3606 SEE") to 0xA6000200,
starts the SEE core at 0xA6000200 (chips/see.py SeeCore, EBase 0x86002001), moves the main CPU's CP0
EBase to 0x80002000, attaches its CH455 front panel ("---led 455 attach OK--"), initialises its
external Availink AVL6762 DVB-T2/C demodulator at I2C 0x14 ("Demod is 6762!!!") and MaxLinear MxL608
tuner at I2C 0x60 over bit-banged GPIO I2C on SCL = GPIO 105 / SDA = GPIO 104, and exchanges remote
calls with the SEE co-processor.
"""
import see_regression

see_regression.run(
    "AMIKO IMPULSE H265 T2C/AMIKO_Impluse_H265_T2C_1.3.87_emu.abs",
    "the Amiko Impulse H.265 T2/C (128 MB M3626A / C3505) runs its application, SEE at 0xA6000200, and AVL6762 + MxL608 RF chain",
    family="C3505",
    starts=[(0xA6000200, "run on the SEE core")],
    calls=30,
    see_calls=30,
    limit=250_000_000,
    setup=lambda sim: sim.attach_tuner(),
    uart=[
        "Enter Bootloader APP.",
        "Run Maincode, main_entry = 0x80000200!",
        "---led 455 attach OK--",
        "Demod is 6762!!!",
        "================control data write =============",
    ],
    ebase=0x80002000,
    see_ebase=0x86002001,
    wait_for=lambda r: (
        "================control data write =============" in r.text
        and 0x14 in r.sim.i2c_devices and r.sim.i2c_devices[0x14].writes >= 1000
        and 0x60 in r.sim.i2c_devices and r.sim.i2c_devices[0x60].frequency() is not None
    ),
    checks=[
        lambda r: (
            r.sim.ram_size == 0x08000000 and not r.sim._upper_ram_mapped,
            f"128 MB DDR3 active without 256 MB upper-RAM remap "
            f"(ram_size=0x{r.sim.ram_size:X}, upper_ram={r.sim._upper_ram_mapped})",
        ),
        lambda r: (
            0x14 in r.sim.i2c_devices and r.sim.i2c_devices[0x14].writes >= 1000
            and r.sim.i2c_devices[0x14].reads >= 50,
            f"Availink AVL6762 demodulator answered over bit-banged GPIO 105/104 I2C at 0x14 "
            f"(writes={r.sim.i2c_devices[0x14].writes}, reads={r.sim.i2c_devices[0x14].reads})",
        ),
        lambda r: (
            0x60 in r.sim.i2c_devices and r.sim.i2c_devices[0x60].frequency() is not None,
            f"MaxLinear MxL608 DVB-T2/C tuner tuned at I2C 0x60 ({r.sim.tuner_info()})",
        ),
    ],
)
