#!/usr/bin/env python3
"""The Ferguson Ariva 255 Combo official firmware V1.32B4 (ALi C3505 with 256 MB DDR3,
chips/c3505.py) boots through the boot-ROM path in boot SRAM at 0x9FE00800, unpacks its maincode to
0x80000200 and its SEE program ("M3505 SEE") to 0xAE000200, sets 0xB8000220 bit 24 to remap
0x0F000000..0x0FFFFFFF from the flash window to the top 16 MB of DDR (restoring 0xBFE00000 to the
0xBF800000..0xBFFFFFFF flash mirror), moves CP0 EBase to 0x80002000, and starts the SEE program at
0xAE000200 on the second core (chips/see.py SeeCore, EBase 0x8E002001).  The application exchanges
remote calls with the SEE and initialises its external Availink AVL6862 DVB-T2/C demodulator at I2C
0x14 on SCB3 (0xB8018D00).
"""
import see_regression

see_regression.run(
    "FERGUSON ARIVA 255 COMBO/Ferguson_A255_V1.32B4.abs",
    "the Ferguson Ariva 255 Combo (256 MB C3505) runs its application and the SEE's program at 0xAE000200",
    family="C3505",
    starts=[(0xAE000200, "run on the SEE core")],
    calls=50,
    see_calls=30,
    limit=65_000_000,
    uart=[
        "<< SDK4.0ba.4.0_20101217 >>",
        "Application version 1.0.0@SDK4.0ia.17.19_20181226bycompileserveradministrator",
        "FamilyID = Ox68624955,ChipID = 0x2",
    ],
    ebase=0x80002000,
    see_ebase=0x8E002001,
    wait_for=lambda r: "FamilyID = Ox68624955,ChipID = 0x2" in r.text,
    checks=[
        lambda r: (
            r.sim.ram_size == 0x10000000 and r.sim._upper_ram_mapped,
            f"256 MB DDR3 active and 0xB8000220 bit 24 remapped 0x0F000000..0x0FFFFFFF to RAM "
            f"(ram_size=0x{r.sim.ram_size:X}, upper_ram={r.sim._upper_ram_mapped})",
        ),
        lambda r: (
            0x14 in r.sim.i2c_devices and r.sim.i2c_devices[0x14].reads >= 4,
            f"Availink AVL6862 demodulator answered on SCB3 at I2C 0x14 "
            f"(writes={r.sim.i2c_devices[0x14].writes}, reads={r.sim.i2c_devices[0x14].reads})",
        ),
    ],
)
