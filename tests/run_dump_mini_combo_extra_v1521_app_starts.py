#!/usr/bin/env python3
"""The Amiko Mini Combo Extra Edision firmware v.1521 (System ID 6A000A00, ALi
M3526C / C3505 with 256 MB DDR3 and 8 MB SPI flash, chips/c3505.py) boots
through the boot-ROM path in boot SRAM at 0x9FE00800, sets 0xB8000220 bit 24 to
remap physical 0x0F000000..0x0FFFFFFF to the top 16 MB of DDR, writes " ON " ->
" on " to its CH455 front panel on GPIO 107 / 110, unpacks its SEE program
("M3606 SEE") to 0xAE000200 and maincode(AV) to 0x80000200, starts the SEE core
at 0xAE000200 (EBase 0x8E002001), moves the main CPU's CP0 EBase to 0x80002000,
and exchanges remote calls with the SEE co-processor.
"""
import see_regression
from front_panel import make_panel

DUMP = "AMIKO MINI COMBO EXTRA/AMIKO MINI COMBO EXTRA Edision_v.1521.abs"
_HOLDER = {}


def _setup(sim):
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    _HOLDER["panel"] = panel


see_regression.run(
    DUMP,
    "the Amiko Mini Combo Extra Edision v.1521 (256 MB M3526C / C3505) runs its application and SEE at 0xAE000200",
    family="C3505",
    starts=[(0xAE000200, "run on the SEE core")],
    calls=30,
    see_calls=30,
    limit=160_000_000,
    uart=[
        "Enter Bootloader APP.",
        "Load Maincode Success: id=0x01fe0100",
        "Load Seecode Success: id=0x086f90101",
        "Run Seecode, see_entry = 0xae000200!",
        "Run Maincode, main_entry = 0x80000200!",
    ],
    setup=_setup,
    ebase=0x80002000,
    see_ebase=0x8E002001,
    wait_for=lambda r: _HOLDER["panel"].get_display_text() == " on ",
    checks=[
        lambda r: (
            r.sim.ram_size == 0x10000000 and r.sim._upper_ram_mapped,
            f"256 MB DDR3 active and 0xB8000220 bit 24 remapped 0x0F000000..0x0FFFFFFF to RAM "
            f"(ram_size=0x{r.sim.ram_size:X}, upper_ram={r.sim._upper_ram_mapped})",
        ),
        lambda r: (
            _HOLDER["panel"].get_display_text() == " on ",
            f"CH455 panel on GPIO 107 / 110 updated from ' ON ' to {_HOLDER['panel'].get_display_text()!r}",
        ),
    ],
)
