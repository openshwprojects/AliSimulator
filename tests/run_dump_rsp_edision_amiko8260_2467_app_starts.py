#!/usr/bin/env python3
"""The Amiko HD8260+ / RSP Mod Edision 14000A00 firmware v2.4.67 (System ID
14000A00, ALi M3516A / M3503 rev B with 256 MB DDR3 and 16 MB SPI flash,
chips/m3503.py) runs its XIP bootloader ("M3516A 1.2.1") with CacheAsRam at
0x8FFF8000..0x8FFFFFFF, prints "CH455 panel init OK!" and writes " ON " -> " on "
to its CH455 front panel on GPIO 135 / 134, parks the SEE boot stub at
0xA14187DC, unpacks its SEE program ("M3606 SEE") to 0xAE000200 and maincode(AV)
("14000A002467") to 0x80000200, starts the SEE core at 0xAE000200 (EBase
0x8E002001), moves the main CPU's CP0 EBase to 0x80002000, prints
"hs_config_init" on the UART, and exchanges remote calls with the SEE
co-processor.
"""
import see_regression
from front_panel import make_panel

DUMP = "AMIKO HD8260+/RSP_MOD_EDISION_amiko8260_14000A00_2467.abs"
_HOLDER = {}


def _setup(sim):
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    _HOLDER["panel"] = panel


see_regression.run(
    DUMP,
    "Amiko HD8260+ RSP Mod Edision v2.4.67 (256 MB M3516A / M3503 rev B) runs its application and SEE at 0xAE000200",
    family="M3503",
    starts=[(0xA14187DC, "parked"), (0xAE000200, "run on the SEE core")],
    calls=20,
    see_calls=20,
    limit=120_000_000,
    uart=("APP  init ok", "CH455 panel init OK!", "check_program finish.", "success!"),
    setup=_setup,
    ebase=0x80002000,
    see_ebase=0x8E002001,
    wait_for=lambda r: (
        r.sim.chip.see.doorbells.taken["SEE"][0] >= 20
        and r.sim.chip.see.doorbells.taken["main"][0] >= 20
        and _HOLDER["panel"].get_display_text() in (" on ", "-ON-", "boot")
    ),
    checks=[
        lambda r: (
            r.sim.ram_size == 0x10000000 and r.sim._upper_ram_mapped,
            f"256 MB DDR3 active with upper 128 MB mapped (ram_size=0x{r.sim.ram_size:X}, "
            f"upper_ram={r.sim._upper_ram_mapped})",
        ),
        lambda r: (
            _HOLDER["panel"].get_display_text() in (" on ", "-ON-", "boot"),
            f"CH455 panel on GPIO 135 / 134 updated from ' ON ' to {_HOLDER['panel'].get_display_text()!r}",
        ),
    ],
)
