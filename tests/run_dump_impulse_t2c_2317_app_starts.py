#!/usr/bin/env python3
"""The Amiko Impulse T2/C firmware v2.3.17 EMU (System ID 22000A88, ALi M3821A
dual-CPU DVB-T2/C SoC with 128 MB DDR3 and 8 MB SPI flash, chips/m3821.py) boots
through its XIP bootloader using cache-as-RAM until DDR3 is up, initialises its
CH455 front panel on GPIO 128 / 129 (" ON "), parks the SEE boot stub at
0xA1016804, unpacks seecode ("M3606 SEE") and maincode(AV) ("22000A882317") via
LZMA, starts the SEE co-processor at 0xA6000200 (EBase 0x86002001), moves the
main CPU's CP0 EBase to 0x80002000, updates the CH455 panel to " on ", and
exchanges remote calls with the SEE core.
"""
import see_regression
from front_panel import make_panel

DUMP = "AMIKO IMPULSE T2C/AMIKO_Impluse_T2C_2.3.17_emu.abs"
_HOLDER = {}


def _setup(sim):
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    _HOLDER["panel"] = panel


see_regression.run(
    DUMP,
    "the Amiko Impulse T2/C v2.3.17 EMU (M3821) runs its application and the SEE's program at 0xA6000200",
    family="M3821",
    starts=[(0xA1016804, "parked"), (0xA6000200, "run on the SEE core")],
    calls=30,
    see_calls=30,
    limit=160_000_000,
    uart=[
        "HW BootLoader APP  init!",
        "CH455 panel init OK!",
        "check_program finish.",
        "run see, see_entry = 0x8141f000!",
        "---led 455 attach OK--",
    ],
    ebase=0x80002000,
    see_ebase=0x86002001,
    setup=_setup,
    wait_for=lambda r: _HOLDER["panel"].get_display_text() == " on ",
    checks=[
        lambda r: (
            _HOLDER["panel"].get_display_text() == " on ",
            f"CH455 front panel on GPIO 128 / 129 shows ' on ' (got {_HOLDER['panel'].get_display_text()!r})",
        ),
    ],
)
