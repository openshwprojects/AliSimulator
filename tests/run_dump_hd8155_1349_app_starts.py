#!/usr/bin/env python3
"""The Amiko HD8155 firmware v1.3.49 EMU (System ID 6B000A00, ALi M3521A / C3505 with
128 MB DDR3, chips/c3505.py) boots through the boot-ROM path in boot SRAM at 0x9FE00800, unpacks its
maincode(AV) chunk to 0x80000200 and its SEE program ("M3606 SEE") to 0xA6000200, starts the SEE core
at 0xA6000200 (chips/see.py SeeCore, EBase 0x86002001), moves the main CPU's CP0 EBase to 0x80002000,
updates its CH455 front panel on GPIO 107 / 110 from " ON " to " on ", and exchanges remote calls
with the SEE co-processor.
"""
import see_regression
from front_panel import make_panel

DUMP = "AMIKO HD8155/AMIKO_HD8155_1.3.49_emu.abs"
_HOLDER = {}


def _setup(sim):
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    _HOLDER["panel"] = panel


see_regression.run(
    DUMP,
    "the Amiko HD8155 v1.3.49 EMU (128 MB C3505) runs its application and the SEE's program at 0xA6000200",
    family="C3505",
    starts=[(0xA6000200, "run on the SEE core")],
    calls=30,
    see_calls=30,
    limit=160_000_000,
    uart=[
        "Enter Bootloader APP.",
        "Load Maincode Success: id=0x01fe0100",
        "Load Seecode Success: id=0x086f90101",
        "Run Seecode, see_entry = 0xa6000200!",
        "Run Maincode, main_entry = 0x80000200!",
    ],
    ebase=0x80002000,
    see_ebase=0x86002001,
    setup=_setup,
    wait_for=lambda r: _HOLDER["panel"].get_display_text() == " on ",
    checks=[
        lambda r: (
            r.sim.ram_size == 0x08000000 and not r.sim._upper_ram_mapped,
            f"128 MB DDR3 active without 256 MB upper-RAM remap "
            f"(ram_size=0x{r.sim.ram_size:X}, upper_ram={r.sim._upper_ram_mapped})",
        ),
        lambda r: (
            _HOLDER["panel"].get_display_text() == " on ",
            f"CH455 front panel on GPIO 107 / 110 shows ' on ' (got {_HOLDER['panel'].get_display_text()!r})",
        ),
    ],
)
