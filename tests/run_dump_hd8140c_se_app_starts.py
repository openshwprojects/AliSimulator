#!/usr/bin/env python3
"""The Amiko HD8140C SE firmware v1.1.04 emu (System ID 72020A00, ALi M3712A /
C3505 Full HD H.265/HEVC DVB-C cable receiver with 128 MB DDR3 and 8 MB SPI
flash, chips/c3505.py) boots through the boot-ROM path in boot SRAM at
0x9FE00800, reports chip ID 0x3505 ("chip_id: HW_TYPE_CHIP+80"), writes " ON "
-> " on " to its CH455 front panel on GPIO 107 / 108, unpacks its 3.01 MB SEE
program ("M3606 SEE") to 0xA6000200 and 12.71 MB maincode(AV) ("72020A001104")
to 0x80000200, starts the SEE core at 0xA6000200 (EBase 0x86002001), moves the
main CPU's CP0 EBase to 0x80002000, registers its MaxLinear MxL603 DVB-C cable
tuner on SCB1 at I2C 0x60 ("[tun_mxl603_init_DVBC]line=294,success!"), and
exchanges remote calls with the SEE co-processor.
"""
import see_regression
from front_panel import make_panel

DUMP = "AMIKO HD8140C SE/Amiko_HD8140C_SE_1.1.04_emu.abs"
_HOLDER = {}


def _setup(sim):
    _HOLDER["tuner"] = sim.attach_tuner()
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    _HOLDER["panel"] = panel


see_regression.run(
    DUMP,
    "the Amiko HD8140C SE (128 MB M3712A / C3505 DVB-C) runs its application and SEE at 0xA6000200",
    family="C3505",
    starts=[(0xA6000200, "run on the SEE core")],
    calls=50,
    see_calls=50,
    limit=200_000_000,
    setup=_setup,
    uart=("chip_id: HW_TYPE_CHIP+80", "[tun_mxl603_init_DVBC]line=294,success!"),
    ebase=0x80002000,
    see_ebase=0x86002001,
    wait_for=lambda r: (
        r.sim.chip.see.doorbells.taken["SEE"][0] >= 50
        and r.sim.chip.see.doorbells.taken["main"][0] >= 50
        and _HOLDER["panel"].get_display_text() == " on "
        and "[tun_mxl603_init_DVBC]line=294,success!" in r.text
    ),
    checks=[
        lambda r: (
            r.sim.ram_size == 0x08000000 and not r.sim._upper_ram_mapped,
            f"128 MB DDR3 active without 256 MB upper-RAM remap "
            f"(ram_size=0x{r.sim.ram_size:X}, upper_ram={r.sim._upper_ram_mapped})",
        ),
        lambda r: (
            _HOLDER["panel"].get_display_text() == " on ",
            f"CH455 panel on GPIO 107 / 108 updated from ' ON ' to {_HOLDER['panel'].get_display_text()!r}",
        ),
        lambda r: (
            type(_HOLDER["tuner"]).__name__ == "MxL603" and r.sim.i2c_devices.get(0x60) is _HOLDER["tuner"],
            f"MaxLinear MxL603 DVB-C tuner attached at 0x60 ({_HOLDER['tuner']!r})",
        ),
    ],
)
