#!/usr/bin/env python3
"""The Amiko HD8265+ firmware v1.4.17 EMU (System ID 6C000A00, ALi M3529A / C3505 with
256 MB DDR3, chips/c3505.py) boots through the boot-ROM path in boot SRAM at 0x9FE00800, unpacks its
maincode(AV) chunk to 0x80000200 and its SEE program ("M3606 SEE") to 0xAE000200, sets 0xB8000220 bit 24
to remap physical 0x0F000000..0x0FFFFFFF to the top 16 MB of DDR, starts the SEE core at 0xAE000200
(chips/see.py SeeCore, EBase 0x8E002001), moves the main CPU's CP0 EBase to 0x80002000, updates its
CH455 front panel on GPIO 107 / 108 from " ON " to " on ", and initialises its AVL6762 + AV2012 +
MxL608 RF chain.
"""
import see_regression
from front_panel import make_panel

DUMP = "AMIKO HD8265+/Amiko_HD8265_1.4.17_emu.abs"
_HOLDER = {}


def _setup(sim):
    sim.attach_tuner()
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    _HOLDER["panel"] = panel


see_regression.run(
    DUMP,
    "the Amiko HD8265+ v1.4.17 EMU (256 MB C3505) runs its application, SEE at 0xAE000200, and AVL6762 + AV2012 + MxL608 RF chain",
    family="C3505",
    starts=[(0xAE000200, "run on the SEE core")],
    calls=8,
    see_calls=0,
    limit=160_000_000,
    setup=_setup,
    uart=[
        "Enter Bootloader APP.",
        "Load Maincode Success: id=0x01fe0100",
        "Load Seecode Success: id=0x086f90101",
        "Run Seecode, see_entry = 0xae000200!",
        "Run Maincode, main_entry = 0x80000200!",
    ],
    ebase=0x80002000,
    see_ebase=0x8E002001,
    wait_for=lambda r: (
        _HOLDER["panel"].get_display_text() == " on "
        and 0x14 in r.sim.i2c_devices and r.sim.i2c_devices[0x14].reads >= 50
        and 0x61 in r.sim.i2c_devices and r.sim.i2c_devices[0x61].writes >= 5
        and 0x60 in r.sim.i2c_devices and r.sim.i2c_devices[0x60].writes >= 80
    ),
    checks=[
        lambda r: (
            r.sim.ram_size == 0x10000000 and r.sim._upper_ram_mapped,
            f"256 MB DDR3 active and 0xB8000220 bit 24 remapped 0x0F000000..0x0FFFFFFF to RAM "
            f"(ram_size=0x{r.sim.ram_size:X}, upper_ram={r.sim._upper_ram_mapped})",
        ),
        lambda r: (
            _HOLDER["panel"].get_display_text() == " on ",
            f"CH455 front panel on GPIO 107 / 108 shows ' on ' (got {_HOLDER['panel'].get_display_text()!r})",
        ),
        lambda r: (
            0x14 in r.sim.i2c_devices and r.sim.i2c_devices[0x14].reads >= 50,
            f"Availink AVL6762 demodulator answered on SCB3 at I2C 0x14 "
            f"(writes={r.sim.i2c_devices[0x14].writes}, reads={r.sim.i2c_devices[0x14].reads})",
        ),
        lambda r: (
            0x61 in r.sim.i2c_devices and r.sim.i2c_devices[0x61].writes >= 5
            and 0x60 in r.sim.i2c_devices and r.sim.i2c_devices[0x60].writes >= 80,
            f"Airoha AV2012 (0x61: writes={r.sim.i2c_devices[0x61].writes}) and "
            f"MaxLinear MxL608 (0x60: writes={r.sim.i2c_devices[0x60].writes}) tuners configured",
        ),
    ],
)
