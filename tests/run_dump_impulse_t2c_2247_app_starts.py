#!/usr/bin/env python3
"""The Amiko Impulse T2/C firmware v2.2.47 emu (System ID 22000A00, ALi M3821A
with 128 MB DDR3 and 8 MB SPI flash, chips/m3821.py) boots its XIP "M3821A 1.1.1"
bootloader through cache-as-RAM, initialises its CH455 front panel on GPIO 128 /
129 ("CH455 panel init OK!"), parks the SEE boot stub at 0xA1016804, unpacks its
SEE program ("M3606 SEE") and maincode(AV) ("22000A002247"), moves the main
CPU's CP0 EBase to 0x80002000, starts the SEE core at 0xA6000200 (EBase
0x86002001), attaches PAN_CH455_0 ("---led 455 attach OK--"), and exchanges
remote calls with the SEE co-processor.
"""
import see_regression

see_regression.run(
    "AMIKO IMPULSE T2C/AMIKO_Impulse_T2C_2.2.47_emu.abs",
    "the Amiko Impulse T2/C v2.2.47 (M3821A, XIP bootloader) runs its application and the SEE's program at 0xA6000200",
    family="M3821",
    starts=[(0xA1016804, "parked"), (0xA6000200, "run on the SEE core")],
    calls=80,
    see_calls=30,
    limit=160_000_000,
    uart=[
        "HW BootLoader APP  init!",
        "CH455 panel init OK!",
        "success!",
        "MC: APP  init ok",
        "_RD_DEBUG_ = 0",
    ],
    ebase=0x80002000,
    see_ebase=0x86002001,
    wait_for=lambda r: "_RD_DEBUG_ = 0" in r.text,
    checks=[
        lambda r: (getattr(r.sim.chip, "xip", False), "the M3821 family recognises its XIP bootloader"),
    ],
)
