#!/usr/bin/env python3
"""The Edision Piccollino S2 firmware v.1375 (System ID 6B000100, ALi M3521A /
C3505 with 128 MB DDR3 and 8 MB SPI flash, chips/c3505.py) boots through the
boot-ROM path in boot SRAM at 0x9FE00800, copies its bootloader to 0x81000000,
shows its boot logo through VideoOutputM36F (video_m36.py, VSync interrupts on
IC line 2), unpacks seecode ("M3606 SEE" at 0x3F0000) to 0xA6000200 and
maincode(AV) (at 0x060000) to 0x80000200, and starts both cores (main EBase
0x80002000, SEE EBase 0x86002001).  The application drives its CH455 front panel
on GPIO 107 / 110 (" ON " -> " on "), initializes MultiCAS ("[mcas]
max_key_db_count = 505"), and exchanges remote calls with the SEE co-processor.
"""
import see_regression
from front_panel import make_panel

_HOLDER = {}


def _setup(sim):
    panel, _keys, _desc = make_panel(
        "EDISION PICCOLLINO S2/Piccollino_S2_v.1375.abs",
        log_handler=lambda m: None,
    )
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    _HOLDER["panel"] = panel


see_regression.run(
    "EDISION PICCOLLINO S2/Piccollino_S2_v.1375.abs",
    "Edision Piccollino S2 (8 MB flash, 128 MB M3521A / C3505) runs its application and the SEE's program at 0xA6000200",
    family="C3505",
    starts=[(0xA6000200, "run on the SEE core")],
    calls=30,
    see_calls=30,
    limit=130_000_000,
    uart=[
        "Enter Bootloader APP.",
        "bl_show_logo 1115: HELLO WORLD LOGO!!",
        "Run Seecode, see_entry = 0xa6000200!",
        "Run Maincode, main_entry = 0x80000200!",
        "[mcas] max_key_db_count = 505",
    ],
    setup=_setup,
    ebase=0x80002000,
    see_ebase=0x86002001,
    wait_for=lambda r: (
        "[mcas] max_key_db_count = 505" in r.text
        and r.sim.chip.see.doorbells.taken["main"][0] >= 30
        and r.sim.chip.see.doorbells.taken["SEE"][0] >= 30
        and _HOLDER["panel"].get_display_text() == " on "
    ),
    checks=[
        lambda r: (
            r.sim.ram_size == 0x08000000 and not r.sim._upper_ram_mapped,
            f"128 MB DDR3 active without 256 MB remap (ram_size=0x{r.sim.ram_size:X}, "
            f"upper_ram={r.sim._upper_ram_mapped})",
        ),
        lambda r: (
            _HOLDER["panel"].get_display_text() == " on ",
            f"CH455 panel on GPIO 107 / 110 updated from ' ON ' to {_HOLDER['panel'].get_display_text()!r}",
        ),
    ],
)
