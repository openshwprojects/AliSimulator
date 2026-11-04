#!/usr/bin/env python3
"""The Amiko HD8150 (v2.3.62 EMU, 128 MB DDR3 M3503 rev B with 8 MB SPI flash,
chips/m3503.py) runs its XIP bootloader with CacheAsRam at 0x8FFF8000..0x8FFFFFFF,
prints "CH455 panel init OK!" and writes " ON " -> " on " to its CH455
front panel on GPIO 135 / 134, parks the SEE boot stub at 0xA141A7DC, unpacks its
SEE program ("M3606 SEE") to 0xA6000200 and maincode(AV) to 0x80000200, starts the
SEE core at 0xA6000200 (EBase 0x86002001), moves the main CPU's CP0 EBase to
0x80002000, and exchanges remote calls with the SEE co-processor.
"""
import see_regression
from front_panel import make_panel

DUMP = "AMIKO HD8150/AMIKO_HD8150_2.3.62_emu.abs"
_HOLDER = {}


def _setup(sim):
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    _HOLDER["panel"] = panel


see_regression.run(
    DUMP,
    "the Amiko HD8150 (v2.3.62 EMU) (128 MB M3503 rev B) runs its application and SEE at 0xA6000200",
    family="M3503",
    starts=[(0xA141A7DC, "parked"), (0xA6000200, "run on the SEE core")],
    calls=20,
    see_calls=15,
    limit=100_000_000,
    uart=("CH455 panel init OK!",),
    setup=_setup,
    ebase=0x80002000,
    see_ebase=0x86002001,
    wait_for=lambda r: (
        r.sim.chip.see.doorbells.taken["SEE"][0] >= 20
        and r.sim.chip.see.doorbells.taken["main"][0] >= 15
        and _HOLDER["panel"].get_display_text() in (" on ", "-ON-", "boot")
    ),
    checks=[
        lambda r: (
            r.sim.ram_size == 0x08000000 and not r.sim._upper_ram_mapped,
            f"128 MB DDR3 active without 256 MB remap (ram_size=0x{r.sim.ram_size:X}, "
            f"upper_ram={r.sim._upper_ram_mapped})",
        ),
        lambda r: (
            _HOLDER["panel"].get_display_text() in (" on ", "-ON-", "boot"),
            f"CH455 panel on GPIO 135 / 134 updated from ' ON ' to {_HOLDER['panel'].get_display_text()!r}",
        ),
    ],
)
