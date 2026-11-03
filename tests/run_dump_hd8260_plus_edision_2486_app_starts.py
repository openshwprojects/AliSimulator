#!/usr/bin/env python3
"""Verify that Amiko HD8260+ (System ID 14000A88, Edision v2.4.86 by Davor) (amiko_8260_plus_edision_2486_by_Davor.abs) boots and starts its application and SEE co-processor."""
import see_regression
from front_panel import make_panel

DUMP = 'AMIKO HD8260+/amiko_8260_plus_edision_2486_by_Davor.abs'
_HOLDER = {}


def _setup(sim):
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    sim.attach_tuner()
    _HOLDER["panel"] = panel

see_regression.run(
    DUMP,
    "the Amiko HD8260+ (System ID 14000A88, Edision v2.4.86 by Davor) runs its application and SEE co-processor",
    family='M3503',
    starts=[(0xA14187DC, 'parked'), (0xAE000200, 'run on the SEE core')],
    calls=20,
    see_calls=15,
    limit=100_000_000,
    uart=('CH455 panel init OK!', 'check_program finish.'),
    setup=_setup,
    ebase=0x80002000,
    see_ebase=0x8E002001,
    wait_for=lambda r: (
        r.sim.chip.see.doorbells.taken["SEE"][0] >= 20
        and r.sim.chip.see.doorbells.taken["main"][0] >= 15
        and _HOLDER["panel"].get_display_text() == ' on '
    ),
    checks=[
        lambda r: (
            _HOLDER["panel"].get_display_text() == ' on ',
            f"front panel updated to {_HOLDER['panel'].get_display_text()!r}",
        ),
    ],
)
