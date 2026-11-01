#!/usr/bin/env python3
"""The Amiko X-Finder 3 firmware v1.0.49 emu (System ID 70020A00, ALi M3529F /
C3505 handheld HEVC signal meter with 256 MB DDR3 and 8 MB SPI flash,
chips/c3505.py) boots through the boot-ROM path in boot SRAM at 0x9FE00800,
sets 0xB8000220 bit 24 to remap physical 0x0F000000..0x0FFFFFFF to the top
16 MB of DDR, unpacks its 4.11 MB SEE program ("M3505 SEE") to 0xAE000200 and
10.99 MB maincode(AV) ("70020A001049") to 0x80000200, starts the SEE core at
0xAE000200 (EBase 0x8E002001), moves the main CPU's CP0 EBase to 0x80002000,
initialises its Availink AVL6762 DVB-T2/C demodulator (SCB3 0x14) and MaxLinear
MxL603 tuner (SCB3 0x60), scans its CH455 keypad on GPIO 107 / 108, and
exchanges remote calls with the SEE co-processor.
"""
import see_regression
from front_panel import make_panel

DUMP = "AMIKO X-FINDER 3/AMIKO_XFinder_III_1.0.49_emu.abs"
_HOLDER = {}


def _setup(sim):
    sim.attach_tuner()
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim.setGpioHandler(panel.on_gpio_write)
    _HOLDER["panel"] = panel


see_regression.run(
    DUMP,
    "the Amiko X-Finder 3 (256 MB M3529F / C3505 handheld meter) runs its application and SEE at 0xAE000200",
    family="C3505",
    starts=[(0x8E000200, "run on the SEE core")],
    calls=30,
    see_calls=20,
    limit=240_000_000,
    setup=_setup,
    uart=("1  attach tuner=0",),
    ebase=0x80002000,
    see_ebase=0x8E002001,
    wait_for=lambda r: (
        r.sim.chip.see.doorbells.taken["SEE"][0] >= 30
        and r.sim.chip.see.doorbells.taken["main"][0] >= 20
        and _HOLDER["panel"].key_read_count >= 10
    ),
    checks=[
        lambda r: (
            r.sim.ram_size == 0x10000000 and r.sim._upper_ram_mapped,
            f"256 MB DDR3 active and 0xB8000220 bit 24 remapped 0x0F000000..0x0FFFFFFF to RAM "
            f"(ram_size=0x{r.sim.ram_size:X}, upper_ram={r.sim._upper_ram_mapped})",
        ),
        lambda r: (
            _HOLDER["panel"].key_read_count >= 10,
            f"CH455 keypad scanner on GPIO 107 / 108 polled {_HOLDER['panel'].key_read_count} time(s)",
        ),
    ],
)
