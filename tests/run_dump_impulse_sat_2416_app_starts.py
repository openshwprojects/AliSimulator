#!/usr/bin/env python3
"""The Amiko Impulse SAT firmware 2.4.16 emu (System ID 20020A88, ALi M3510B /
M3503 rev B with 128 MB DDR3 and 8 MB SPI flash, chips/m3503.py) boots its XIP
"M3510B 1.1.1" bootloader using CacheAsRam at 0x8FFF8000..0x8FFFFFFF, prints
"CH455 panel init OK!" and writes " ON " to the CH455 front panel on GPIO 135 /
134, parks the SEE boot stub at 0xA141A7DC, unpacks seecode ("M3606 SEE") and
maincode(AV) ("20020A882416") to 0x80000200, starts the SEE core at 0xA6000200
(EBase 0x86002001), moves the main CPU's CP0 EBase to 0x80002000, updates the
CH455 panel to " on ", and exchanges remote calls with the SEE co-processor.
"""
import see_regression
from front_panel import make_panel

DUMP = "AMIKO IMPULSE SAT/AMIKO_Impulse_SAT_2.4.16_emu.abs"
_HOLDER = {}


def _setup(sim):
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    _HOLDER["panel"] = panel


see_regression.run(
    DUMP,
    "the Amiko Impulse SAT 2.4.16 emu (M3510B / M3503) runs its application and the SEE's program at 0xA6000200",
    family="M3503",
    starts=[(0xA141A7DC, "parked"), (0xA6000200, "run on the SEE core")],
    calls=30,
    see_calls=30,
    limit=160_000_000,
    uart=[
        "APP  init ok",
        "CH455 panel init OK!",
        "check_program finish.",
        "run see, see_entry = 0x81864000!",
        "---led 455 attach OK--",
    ],
    ebase=0x80002000,
    see_ebase=0x86002001,
    setup=_setup,
    wait_for=lambda r: _HOLDER["panel"].get_display_text() == " on ",
    checks=[
        lambda r: (
            _HOLDER["panel"].get_display_text() == " on ",
            f"CH455 front panel on GPIO 135 / 134 shows ' on ' (got {_HOLDER['panel'].get_display_text()!r})",
        ),
    ],
)
