#!/usr/bin/env python3
"""Verify that Amiko SHD-8110 (System ID 0B000A00, Ultra v1.7.03 by Dekolte) (AMIKO_SHD-8110_Ultra_1.7.03_by Dekolte.abs) boots and starts its application and SEE co-processor."""
import see_regression
from front_panel import make_panel

DUMP = 'AMIKO SHD-8110/AMIKO_SHD-8110_Ultra_1.7.03_by Dekolte.abs'
_HOLDER = {}


def _setup(sim):
    sim.attach_tuner()

see_regression.run(
    DUMP,
    "the Amiko SHD-8110 (System ID 0B000A00, Ultra v1.7.03 by Dekolte) runs its application and SEE co-processor",
    family='M3602',
    chip_id=0x3603,
    starts=[(0xA1E9103C, 'parked'), (0xA7000200, 'run on the SEE core')],
    calls=20,
    see_calls=15,
    limit=100_000_000,
    uart=('APP  init ok', '---HC164 attach OK--'),
    setup=_setup,
    ebase=0x80000000,
    see_ebase=0x80000001,
)
