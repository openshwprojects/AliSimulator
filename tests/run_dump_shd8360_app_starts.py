#!/usr/bin/env python3
"""
The Amiko SHD-8360 CI+CA firmware v1.6.96 EMU (System ID 0A0A0A00, ALi M3606G /
C3603, chips/m3602.py with chip ID 0x3603) boots its "M3606G 1.1.3" bootloader
from the 16 MB flash window at 0xAF000000 on an 8 MB SPI flash, parks the SEE
boot stub at 0xA1E8F9B8, communicates with the external Lemontree EuP standby
and front-panel microcontroller at I2C 0x28 on bit-banged GPIO 103 (SCL) / 102
(SDA) (" ON " -> "    " -> " on "), unpacks maincode(AV) to 0x80000200 and
starts "M3606 SEE" on the second core at 0xA7000200.  The application configures
its ALi S3501 DVB-S2 demodulator at I2C 0x33 and Airoha AV2012 tuner at I2C 0x65
("stb_tuner_type = 1, stb_board_type =9.") and draws its 1280x720 OSD dialog.
"""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from lemontree_decoder import LemontreeDecoder
import see_regression


def _lemontree(run):
    for dev in run.sim.gpio_devices:
        if isinstance(dev, LemontreeDecoder):
            return dev
    return None


def _check_panel(run):
    lt = _lemontree(run)
    tx = lt.i2c_transaction_count if lt else 0
    txt = lt.get_display_text() if lt else ""
    return (
        lt is not None and tx >= 20 and txt == " on ",
        f"Lemontree EuP MCU answered {tx} transactions on GPIO 103 / 102 and displays {txt!r}",
    )


def _check_rf(run):
    demod = run.sim.i2c_devices.get(0x33)
    tuner = run.sim.i2c_devices.get(0x65)
    d_regs = len(getattr(demod, "regs", ()))
    t_writes = getattr(tuner, "writes", 0)
    return (
        d_regs > 4 and t_writes > 0,
        f"ALi S3501 demodulator at 0x33 ({d_regs} regs) and Airoha AV2012 tuner at 0x65 ({t_writes} writes) configured",
    )


see_regression.run(
    "AMIKO SHD-8360/AMIKO_SHD-8360_1.6.96_emu.abs",
    "Amiko SHD-8360 1.6.96 (M3606G / C3603, Lemontree EuP MCU) runs its application and SEE program",
    family="M3602",
    chip_id=0x3603,
    starts=[(0xA1E8F9B8, "parked"), (0xA7000200, "run on the SEE core")],
    calls=80,
    see_calls=30,
    limit=95_000_000,
    uart=[
        "APP  init ok",
        "success!",
        "================control data write =============",
        "stb_tuner_type = 1, stb_board_type =9.",
    ],
    ebase=0x80000000,
    see_ebase=0x80000001,
    wait_for=lambda r: "3606 IC type=0" in r.text and (_lemontree(r) is not None and _lemontree(r).get_display_text() == " on "),
    checks=[_check_panel, _check_rf],
)
