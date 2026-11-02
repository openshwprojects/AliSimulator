#!/usr/bin/env python3
"""The Edision Piccollo 3in1 Plus CI firmware v.2475 (System ID 14000800, ALi
M3516A / M3503 with 256 MB DDR3 and 16 MB SPI flash, chips/m3503.py) boots XIP
with its stack in the cache-as-RAM window at 0x8FFF8000..0x8FFFFFFF, copies its
bootloader to 0x81400000, sets 0xB8000220 bit 24 to remap physical
0x0F000000..0x0FFFFFFF to the top 16 MB of DDR, parks the SEE boot stub at
0xA14187DC, unpacks seecode ("M3606 SEE") to 0xAE000200 and maincode(AV) to
0x80000200, and starts both cores (main EBase 0x80002000, SEE EBase
0x8E002001).  The application initialises its CH455 front panel ("CH455 panel
init OK!"), its external Availink AVL6762 DVB-T2/C demodulator at I2C 0x14 over
bit-banged GPIO I2C on SCL = GPIO 7 / SDA = GPIO 8 ("Demod is 6762!!!",
demods.py:AVL6762), and its Airoha AV2012 DVB-S2 tuner at I2C 0x61 on SCB0.
"""
import see_regression

see_regression.run(
    "EDISION PICCOLLO 3IN1 PLUS CI/piccollo_3in1_PLUS_CI_2475.abs",
    "Edision Piccollo 3in1 Plus CI (16 MB flash, 256 MB M3503) runs its application, SEE at 0xAE000200, and AVL6762 + AV2012 RF chain",
    family="M3503",
    starts=[(0xA14187DC, "parked"), (0xAE000200, "run on the SEE core")],
    calls=8,
    see_calls=0,
    limit=300_000_000,
    setup=lambda sim: sim.attach_tuner(),
    uart=[
        "APP  init ok",
        "CH455 panel init OK!",
        "check_program finish.",
        "success!",
        "Demod is 6762!!!",
        "Starting mcas v.1.0",
    ],
    ebase=0x80002000,
    see_ebase=0x8E002001,
    wait_for=lambda r: (
        "Starting mcas v.1.0" in r.text
        and 0x14 in r.sim.i2c_devices and r.sim.i2c_devices[0x14].writes >= 1000
        and 0x61 in r.sim.i2c_devices and r.sim.i2c_devices[0x61].writes >= 5
    ),
    checks=[
        lambda r: (
            sum(m.startswith("[CAR]") for m in r.logs) == 1,
            f"XIP bootloader ran with cache-as-RAM stack before switching to RAM "
            f"({sum(m.startswith('[CAR]') for m in r.logs)} CAR transition)",
        ),
        lambda r: (
            r.sim.ram_size == 0x10000000 and r.sim._upper_ram_mapped,
            f"256 MB DDR3 active and 0xB8000220 bit 24 remapped 0x0F000000..0x0FFFFFFF to RAM "
            f"(ram_size=0x{r.sim.ram_size:X}, upper_ram={r.sim._upper_ram_mapped})",
        ),
        lambda r: (
            0x14 in r.sim.i2c_devices and r.sim.i2c_devices[0x14].writes >= 1000
            and r.sim.i2c_devices[0x14].reads >= 50,
            f"Availink AVL6762 demodulator answered over bit-banged GPIO 7/8 I2C at 0x14 "
            f"(writes={r.sim.i2c_devices[0x14].writes}, reads={r.sim.i2c_devices[0x14].reads})",
        ),
        lambda r: (
            0x61 in r.sim.i2c_devices and r.sim.i2c_devices[0x61].writes >= 5,
            f"Airoha AV2012 DVB-S2 tuner configured at I2C 0x61 (writes={r.sim.i2c_devices[0x61].writes})",
        ),
    ],
)
