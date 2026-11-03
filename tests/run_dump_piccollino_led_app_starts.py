#!/usr/bin/env python3
"""The Edision Piccollino LED firmware v.2475 (System ID 10040800, ALi M3511E /
M3503 rev B with 128 MB DDR3 and 8 MB SPI flash, chips/m3503.py) runs its XIP
bootloader ("M3511E 1.1.1") with CacheAsRam at 0x8FFF8000..0x8FFFFFFF, prints
"CH455 panel init OK!" and writes " ON " -> " on " to its CH455 front panel on
GPIO 135 / 134, parks the SEE boot stub at 0xA1416804, unpacks its SEE program
("M3606 SEE") to 0x86000200 and maincode(AV) ("100408002475") to 0x80000200,
starts the SEE core at 0x86000200 (EBase 0x86002001), moves the main CPU's CP0
EBase to 0x80002000, prints "---led 455 attach OK--" and "Starting mcas v.1.0"
on the UART, and exchanges remote calls with the SEE co-processor.
"""
import see_regression
from front_panel import make_panel

_HOLDER = {}


def _setup(sim):
    panel, _keys, _desc = make_panel(
        "EDISION PICCOLLINO LED/Piccollino_v.2475.abs",
        log_handler=lambda m: None,
    )
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    _HOLDER["panel"] = panel


see_regression.run(
    "EDISION PICCOLLINO LED/Piccollino_v.2475.abs",
    "the Edision Piccollino LED (128 MB M3511E / M3503 rev B) runs its application and SEE at 0x86000200",
    family="M3503",
    starts=[(0xA1416804, "parked"), (0x86000200, "run on the SEE core")],
    calls=20,
    see_calls=20,
    limit=100_000_000,
    uart=("CH455 panel init OK!", "---led 455 attach OK--", "Starting mcas v.1.0"),
    setup=_setup,
    ebase=0x80002000,
    see_ebase=0x86002001,
    wait_for=lambda r: (
        r.sim.chip.see.doorbells.taken["SEE"][0] >= 20
        and r.sim.chip.see.doorbells.taken["main"][0] >= 20
        and _HOLDER["panel"].get_display_text() == " on "
        and "Starting mcas v.1.0" in r.text
    ),
    checks=[
        lambda r: (
            r.sim.ram_size == 0x08000000 and not r.sim._upper_ram_mapped,
            f"128 MB DDR3 active without 256 MB remap (ram_size=0x{r.sim.ram_size:X}, "
            f"upper_ram={r.sim._upper_ram_mapped})",
        ),
        lambda r: (
            _HOLDER["panel"].get_display_text() == " on ",
            f"CH455 panel on GPIO 135 / 134 updated from ' ON ' to {_HOLDER['panel'].get_display_text()!r}",
        ),
    ],
)
