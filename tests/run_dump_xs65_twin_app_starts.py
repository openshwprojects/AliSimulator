#!/usr/bin/env python3
"""The Opticum XS65 Twin Polish retail firmware 1.4.0 (140_TWIN_RETAIL_PL.abs, an 8 MB SPI image for
the 256 MB dual-DVB-S2 ALi M3511 / M3503 board, chips/m3503.py) has uppercase BOOTLOADER / SEECODE
chunk names and a numeric-named 0x01FE0101 maincode chunk ("113003202102162" at 0x220000).  It boots
XIP with its stack in the cache-as-RAM window (0x8FFF8000..0x8FFFFFFF), switches to RAM, sets
0xB8000220 bit 24 to remap physical 0x0F000000..0x0FFFFFFF to the top 16 MB of 256 MB DDR3, parks
the SEE boot stub at 0xA08987DC to copy SEECODE to 0xAE000200, unpacks the 8.0 MB maincode to
0x80000200, starts both cores (main EBase 0x80002000, SEE EBase 0x8E002001), initialises its second
DVB-S2 demodulator (external ALi S3501 at I2C 0x33 on bit-banged SCL = GPIO 6 / SDA = GPIO 7) so
that GMA layer 0 stays enabled, and powers both USB ports.
"""
import see_regression

see_regression.run(
    "OPTICUM XS65 TWIN/140_TWIN_RETAIL_PL.abs",
    "the Opticum XS65 Twin (8 MB flash, 256 MB M3503 rev B, dual DVB-S2) runs its application, SEE at 0xAE000200, and S3501 second demod",
    family="M3503",
    starts=[(0xA08987DC, "parked"), (0xAE000200, "run on the SEE core")],
    calls=200,
    see_calls=35,
    limit=110_000_000,
    setup=lambda sim: sim.attach_tuner(),
    uart=[
        "Init power usb queue with left usb power = 1",
        "Left usb power(at gpio 72) = 1!",
    ],
    ebase=0x80002000,
    see_ebase=0x8E002001,
    wait_for=lambda r: (
        "Left usb power(at gpio 72) = 1!" in r.text
        and (r.sim._mmio_view[0x6300] & 1) == 1
        and r.sim.ge_ops >= 250
    ),
    checks=[
        lambda r: (
            sum(m.startswith("[CAR]") for m in r.logs) == 1,
            "the bootloader keeps its stack in the cache-as-RAM range, then runs from RAM",
        ),
        lambda r: (
            r.sim.ram_size == 0x10000000 and r.sim._upper_ram_mapped and r.sim.chip.variant() == 0x0001,
            f"256 MB M3503 rev B active with 0xB8000220 bit 24 upper-DDR remap "
            f"(ram_size=0x{r.sim.ram_size:X}, upper_ram={r.sim._upper_ram_mapped}, var=0x{r.sim.chip.variant():04X})",
        ),
        lambda r: (
            0x33 in r.sim.i2c_devices and (r.sim._mmio_view[0x6300] & 1) == 1,
            f"external S3501 second DVB-S2 demodulator answered at 0x33 over GPIO 6/7 I2C and kept GMA layer 0 enabled "
            f"(0x6300=0x{r.sim._mmio_view[0x6300]:02X}, ge_ops={r.sim.ge_ops})",
        ),
    ],
)
