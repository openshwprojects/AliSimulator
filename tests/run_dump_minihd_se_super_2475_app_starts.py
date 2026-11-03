#!/usr/bin/env python3
"""Verify that Amiko Mini HD SE (System ID 10000A00, Super v2.4.75 by Dekolte) (AMIKO_MiniHD_SE_Super_2.4.75_by Dekolte.abs) boots and starts its application and SEE co-processor."""
import see_regression
from front_panel import make_panel

DUMP = 'AMIKO MINI HD SE/AMIKO_MiniHD_SE_Super_2.4.75_by Dekolte.abs'
_HOLDER = {}


def _setup(sim):
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    sim.attach_tuner()
    _HOLDER["panel"] = panel

see_regression.run(
    DUMP,
    "the Amiko Mini HD SE (System ID 10000A00, Super v2.4.75 by Dekolte) runs its application and SEE co-processor",
    family='M3503',
    starts=[(0xA141A7DC, 'parked'), (0xA6000200, 'run on the SEE core')],
    calls=20,
    see_calls=15,
    limit=100_000_000,
    uart=('CH455 panel init OK!', 'check_program finish.'),
    setup=_setup,
    ebase=0x80002000,
    see_ebase=0x86002001,
    wait_for=lambda r: (
        r.sim.chip.see.doorbells.taken["SEE"][0] >= 20
        and r.sim.chip.see.doorbells.taken["main"][0] >= 15
        and _HOLDER["panel"].get_display_text() == '-ON-'
    ),
    checks=[
        lambda r: (
            _HOLDER["panel"].get_display_text() == '-ON-',
            f"front panel updated to {_HOLDER['panel'].get_display_text()!r}",
        ),
    ],
)
