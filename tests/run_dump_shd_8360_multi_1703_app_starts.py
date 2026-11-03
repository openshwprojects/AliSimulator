#!/usr/bin/env python3
"""Verify that Amiko SHD-8360 (System ID 0A0A0A00, Multi v1.7.03 by Dekolte) (AMIKO_SHD-8360_Multi_1.7.03_by Dekolte..abs) boots and starts its application and SEE co-processor."""
import see_regression
from front_panel import make_panel

DUMP = 'AMIKO SHD-8360/AMIKO_SHD-8360_Multi_1.7.03_by Dekolte..abs'
_HOLDER = {}


def _setup(sim):
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    sim.attach_tuner()
    _HOLDER["panel"] = panel

see_regression.run(
    DUMP,
    "the Amiko SHD-8360 (System ID 0A0A0A00, Multi v1.7.03 by Dekolte) runs its application and SEE co-processor",
    family='M3602',
    chip_id=0x3603,
    starts=[(0xA1E8F9B8, 'parked'), (0xA7000200, 'run on the SEE core')],
    calls=20,
    see_calls=15,
    limit=100_000_000,
    uart=('APP  init ok', 'start attatch external crystal net board'),
    setup=_setup,
    ebase=0x80000000,
    see_ebase=0x80000001,
    wait_for=lambda r: (
        r.sim.chip.see.doorbells.taken["SEE"][0] >= 20
        and r.sim.chip.see.doorbells.taken["main"][0] >= 15
        and _HOLDER["panel"].get_display_text() == 'dE O'
    ),
    checks=[
        lambda r: (
            _HOLDER["panel"].get_display_text() == 'dE O',
            f"front panel updated to {_HOLDER['panel'].get_display_text()!r}",
        ),
    ],
)
