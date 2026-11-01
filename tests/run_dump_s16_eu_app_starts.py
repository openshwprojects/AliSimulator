#!/usr/bin/env python3
"""The Openbox S16 EU firmware Eu1129 (ALi S3606H / M3606C dual-CPU DVB-S2 HD
satellite receiver on a 4 MB SPI flash, chips/m3602.py with device.chipId
0x3603) parks the SEE boot stub at 0xA1E8F7C0, unpacks its 2.42 MB seecode
("M3606 SEE") and 5.24 MB maincode ("S3606H-1.0.0"), starts the SEE core at
0xA6000200 (EBase 0x80000001), probes its S3501 demodulator (0x33) and AV2011
tuner (0x63) on SCB1, writes " on " -> "noCH" to its TM1650-compatible front
panel on GPIO 62 / 63, and exchanges remote calls with the SEE co-processor.
"""
import see_regression
from front_panel import make_panel

DUMP = "OPENBOX S16/OPENBOX-S16_Eu1129.abs"
_HOLDER = {}


def _setup(sim):
    _HOLDER["tuner"] = sim.attach_tuner()
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    _HOLDER["panel"] = panel


see_regression.run(
    DUMP,
    "the Openbox S16 EU (dual-CPU S3606H / M3606C) runs its application and SEE at 0xA6000200",
    family="M3602",
    chip_id=0x3603,
    starts=[
        (0xA1E8F7C0, "parked"),
        (0xA6000200, "run on the SEE core"),
    ],
    calls=30,
    see_calls=30,
    limit=80_000_000,
    setup=_setup,
    uart=("Libcore version 7.3.0@SDK4.0ba.7.3", "Application version 1.0.0@SDK4.0ba.7.1_SAB_S2"),
    ebase=0x80000000,
    see_ebase=0x80000001,
    wait_for=lambda r: (
        _HOLDER["panel"].get_display_text() == "noCH"
        and r.sim.ge_ops >= 14
    ),
    checks=[
        lambda r: (
            _HOLDER["panel"].get_display_text() == "noCH",
            f"TM1650-compatible panel on GPIO 62 / 63 shows {_HOLDER['panel'].get_display_text()!r}",
        ),
        lambda r: (
            _HOLDER["tuner"] is not None and sum(_HOLDER["tuner"].reads.values()) > 0,
            f"Airoha AV2011 tuner at 0x63 probed on SCB1 (reads={dict(_HOLDER['tuner'].reads) if _HOLDER['tuner'] else {}})",
        ),
    ],
)
