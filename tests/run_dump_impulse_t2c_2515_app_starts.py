#!/usr/bin/env python3
"""The Amiko Impulse T2/C firmware v2.5.15 emu (System ID 22000A88, ALi M3821A
with 128 MB DDR3 and 8 MB SPI flash, chips/m3821.py) boots its XIP "M3821A 1.1.1"
bootloader through cache-as-RAM, initialises its CH455 front panel on GPIO 128 /
129 ("CH455 panel init OK!"), parks the SEE boot stub at 0xA1016804, unpacks its
SEE program ("M3606 SEE") and maincode(AV) ("22000A882515"), moves the main
CPU's CP0 EBase to 0x80002000, starts the SEE core at 0xA6000200 (EBase
0x86002001), attaches PAN_CH455_0 ("---led 455 attach OK--"), and exchanges
remote calls with the SEE co-processor.
"""
import see_regression
from front_panel import make_panel

DUMP = "AMIKO IMPULSE T2C/AMIKO_Impluse_T2C_2.5.15_emu.abs"
_HOLDER = {}


def _setup(sim):
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    _HOLDER["panel"] = panel


see_regression.run(
    DUMP,
    "the Amiko Impulse T2/C v2.5.15 (M3821A, XIP bootloader) runs its application and the SEE's program at 0xA6000200",
    family="M3821",
    starts=[(0xA1016804, "parked"), (0xA6000200, "run on the SEE core")],
    calls=80,
    see_calls=30,
    limit=160_000_000,
    setup=_setup,
    uart=[
        "HW BootLoader APP  init!",
        "CH455 panel init OK!",
        "success!",
    ],
    ebase=0x80002000,
    see_ebase=0x86002001,
    wait_for=lambda r: (
        r.sim.chip.see.doorbells.taken["SEE"][0] >= 80
        and r.sim.chip.see.doorbells.taken["main"][0] >= 30
        and _HOLDER["panel"].get_display_text() == " on "
    ),
    checks=[
        lambda r: (getattr(r.sim.chip, "xip", False), "the M3821 family recognises its XIP bootloader"),
        lambda r: (
            _HOLDER["panel"].get_display_text() == " on ",
            f"CH455 panel on GPIO 128 / 129 updated from ' ON ' to {_HOLDER['panel'].get_display_text()!r}",
        ),
    ],
)
