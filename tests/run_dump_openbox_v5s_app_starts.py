#!/usr/bin/env python3
"""The Openbox V5S firmware 15051903A3 (OPENBOX_V5S_3601HD_CMT_15051903A3.abs,
a 4 MB SPI image for the dual-CPU ALi M3601S / M3602 DVB-S2 HD satellite
receiver, chips/m3602.py: bootloader "DVBS2---0.1.0", maincode "M3601 Demo",
seecode "MSEE Demo") parks the SEE boot stub at 0xA1E92ECC, unpacks seecode to
0xA6000200 and maincode to 0x80000200, starts the SEE core at 0xA6000200,
outputs "\x01\x02" on UART, and exchanges remote calls between the main CPU
and the SEE co-processor.
"""
import see_regression

DUMP = "OPENBOX V5S/OPENBOX_V5S_3601HD_CMT_15051903A3.abs"

see_regression.run(
    DUMP,
    "the Openbox V5S (dual-CPU M3601S / M3602) runs its application and SEE at 0xA6000200",
    family="M3602",
    chip_id=0x3602,
    starts=[
        (0xA1E92ECC, "parked"),
        (0xA6000200, "run on the SEE core"),
    ],
    calls=25,
    see_calls=15,
    limit=35_000_000,
    uart=["\x01\x02"],
    ebase=0x80000000,
    see_ebase=0x80000001,
)
