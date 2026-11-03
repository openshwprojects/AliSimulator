#!/usr/bin/env python3
"""Verify that Amiko Mini HD (System ID 0A070A00, v1.7.10 EMU) (AMIKO_MiniHD_1.7.10_emu.abs) boots and starts its application and SEE co-processor."""
import see_regression
from front_panel import make_panel

DUMP = 'AMIKO MINI HD/AMIKO_MiniHD_1.7.10_emu.abs'
_HOLDER = {}


def _setup(sim):
    sim.attach_tuner()

see_regression.run(
    DUMP,
    "the Amiko Mini HD (System ID 0A070A00, v1.7.10 EMU) runs its application and SEE co-processor",
    family='M3602',
    chip_id=0x3603,
    starts=[(0xA1E8F988, 'parked'), (0xA7000200, 'run on the SEE core')],
    calls=20,
    see_calls=15,
    limit=100_000_000,
    uart=('APP  init ok', 'start attatch external crystal net board'),
    setup=_setup,
    ebase=0x80000000,
    see_ebase=0x80000001,
)
