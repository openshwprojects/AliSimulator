#!/usr/bin/env python3
"""Verify that Amiko HD8265+ (System ID 6C000A00, Edision EMU v1.4.23 by Davor) (Amiko_8265_emu_edision_1423_byDavor.abs) boots and starts its application and SEE co-processor."""
import see_regression
from front_panel import make_panel

DUMP = 'AMIKO HD8265+/Amiko_8265_emu_edision_1423_byDavor.abs'
_HOLDER = {}


def _setup(sim):
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    sim.attach_tuner()
    _HOLDER["panel"] = panel

see_regression.run(
    DUMP,
    "the Amiko HD8265+ (System ID 6C000A00, Edision EMU v1.4.23 by Davor) runs its application and SEE co-processor",
    family='C3505',
    starts=[(0xAE000200, 'run on the SEE core')],
    calls=20,
    see_calls=15,
    limit=160_000_000,
    uart=('Enter Bootloader APP.', 'Run Maincode, main_entry = 0x80000200!', '---led 455 attach OK--', 'Demod is 6762!!!'),
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
