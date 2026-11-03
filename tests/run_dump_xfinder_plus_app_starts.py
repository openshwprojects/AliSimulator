#!/usr/bin/env python3
"""The Amiko X-Finder+ handheld DVB-S2/T2/C signal meter firmware 1.0.33 emu
(System ID 17010000, ALi M3516F / M3503 with 256 MB DDR3 and 16 MB SPI flash,
chips/m3503.py) boots XIP with its stack in the cache-as-RAM window at
0x8FFF8000..0x8FFFFFFF, drives CH455 ("CH455 panel init OK!", " ON ") on GPIO
135 / 134, sets 0xB8000220 bit 24 to remap physical 0x0F000000..0x0FFFFFFF to
the top 16 MB of DDR, parks the SEE boot stub at 0xA141A7DC, unpacks 2.96 MB
seecode ("M3606 SEE") to 0xAE000200 and 10.46 MB maincode(AV) to 0x80000200, and
starts both cores (main EBase 0x80002000, SEE EBase 0x8E002001).  In maincode,
PAN_CH455_0 blanks the 7-segment digits ("    "), drives the meter's status LEDs
(0x64 / 0x66), and scans the keypad matrix on GPIO 135 / 134 (tm1650_decoder.py),
prints "ali play 1.0 $$$" and "nim_avl6862_set_lnb_power=1", and exchanges
remote calls with the SEE co-processor.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from front_panel import make_panel
import see_regression

DUMP = "AMIKO X-FINDER+/AMIKO_XFinder_Plus_1.0.33_emu.abs"


def setup(sim):
    panel, _keys, _desc = make_panel(DUMP, log_handler=lambda m: None)
    panel.dump_enabled = False
    sim._panel = panel
    sim.setGpioHandler(panel.on_gpio_write)


see_regression.run(
    DUMP,
    "the Amiko X-Finder+ handheld meter (16 MB flash, 256 MB M3503) runs its application, SEE at 0xAE000200, and CH455 keypad controller",
    family="M3503",
    starts=[(0xA141A7DC, "parked"), (0xAE000200, "run on the SEE core")],
    calls=30,
    see_calls=20,
    limit=160_000_000,
    setup=setup,
    uart=[
        "APP  init ok",
        "CH455 panel init OK!",
        "check_program finish.",
        "success!",
        "MC: APP  init ok",
        "ali play 1.0 $$$",
    ],
    ebase=0x80002000,
    see_ebase=0x8E002001,
    wait_for=lambda r: (
        r.sim.chip.see.doorbells.taken["SEE"][0] >= 30
        and r.sim.chip.see.doorbells.taken["main"][0] >= 20
        and "ali play 1.0 $$$" in r.text
        and r.sim._panel.key_read_count >= 10
    ),
    checks=[
        lambda r: (
            sum(m.startswith("[CAR]") for m in r.logs) == 1,
            f"XIP bootloader ran with cache-as-RAM stack before switching to RAM "
            f"({sum(m.startswith('[CAR]') for m in r.logs)} CAR transition)",
        ),
        lambda r: (
            r.sim.ram_size == 0x10000000 and r.sim._upper_ram_mapped,
            f"256 MB DDR3 active and 0xB8000220 bit 24 remapped 0x0F000000..0x0FFFFFFF to RAM "
            f"(ram_size=0x{r.sim.ram_size:X}, upper_ram={r.sim._upper_ram_mapped})",
        ),
        lambda r: (
            r.sim._panel.key_read_count >= 10 and r.sim._panel.i2c_transaction_count >= 50,
            f"CH455 keypad controller on GPIO 135/134 answered {r.sim._panel.i2c_transaction_count} "
            f"I2C transactions and {r.sim._panel.key_read_count} key scans",
        ),
    ],
)
