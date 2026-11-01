#!/usr/bin/env python3
"""The Amiko HD8275+ firmware v1.2.02 emu (System ID 6C000A00, ALi M3529A /
C3505 Full HD H.265/HEVC DVB-S2 + DVB-T2/C combo receiver with 256 MB DDR3 and
8 MB SPI flash, chips/c3505.py) boots through the boot-ROM path in boot SRAM at
0x9FE00800, sets 0xB8000220 bit 24 to remap physical 0x0F000000..0x0FFFFFFF to
the top 16 MB of DDR, writes " ON " -> " on " to its CH455 front panel on GPIO
107 / 108 ("---led 455 attach OK--"), unpacks its 3.73 MB SEE program
("M3606 SEE") to 0xAE000200 and 12.16 MB maincode(AV) ("6C000A001202") to
0x80000200, starts the SEE core at 0xAE000200 (EBase 0x8E002001), moves the
main CPU's CP0 EBase to 0x80002000, and initialises its external Availink
AVL6762 DVB-T2/C demodulator ("Demod is 6762!!!", I2C 0x14 on SCB3), Airoha
AV2012 DVB-S2 tuner (I2C 0x61 on SCB1), and MaxLinear MxL608 DVB-T2/C tuner
(I2C 0x60 on SCB3).
"""
import see_regression
from front_panel import make_panel

DUMP = "AMIKO HD8275+/Amiko_HD8275_1.2.02_emu.abs"
_HOLDER = {}


def _setup(sim):
    sim.attach_tuner()
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    _HOLDER["panel"] = panel


see_regression.run(
    DUMP,
    "the Amiko HD8275+ (256 MB M3529A / C3505) runs its application, SEE at 0xAE000200, and AVL6762 + AV2012 + MxL608 RF chain",
    family="C3505",
    starts=[(0xAE000200, "run on the SEE core")],
    calls=8,
    see_calls=0,
    limit=160_000_000,
    setup=_setup,
    uart=[
        "Enter Bootloader APP.",
        "Run Maincode, main_entry = 0x80000200!",
        "---led 455 attach OK--",
        "Demod is 6762!!!",
    ],
    ebase=0x80002000,
    see_ebase=0x8E002001,
    wait_for=lambda r: (
        "Demod is 6762!!!" in r.text
        and _HOLDER["panel"].get_display_text() == " on "
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
            f"CH455 panel on GPIO 107 / 108 updated from ' ON ' to {_HOLDER['panel'].get_display_text()!r}",
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
