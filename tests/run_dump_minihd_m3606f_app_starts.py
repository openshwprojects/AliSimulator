#!/usr/bin/env python3
"""The Amiko Mini HD firmware v1.6.96 (System ID 0A070A00, ALi M3606F / C3603
with 128 MB DDR and 8 MB SPI flash, chips/m3602.py) boots its "M3606F 1.1.3"
bootloader, parks the SEE boot stub at 0xA1E8F988, unpacks its SEE program
("M3606 SEE") to 0xA7000200 and maincode(AV) ("0A070A001696") to 0x80000200,
starts the SEE core at 0xA7000200, configures the ALi S3501 DVB-S2 demodulator
at I2C 0x33, and exchanges remote calls with the SEE co-processor.
"""
import see_regression

see_regression.run(
    "AMIKO MINI HD/AMIKO_MiniHD_1.6.96_emu.abs",
    "the Amiko Mini HD (8 MB flash, M3606F / C3603) runs its application and SEE at 0xA7000200",
    family="M3602",
    chip_id=0x3603,
    starts=[(0xA1E8F988, "parked"), (0xA7000200, "run on the SEE core")],
    calls=30,
    see_calls=30,
    limit=85_000_000,
    uart=[
        "APP  init ok",
        "success!",
        "hs_config_init",
        "stb_tuner_type = 1, stb_board_type =8.",
        "sys_ic_get_chip_id=0x10047",
    ],
    ebase=0x80000000,
    see_ebase=0x80000001,
    wait_for=lambda r: "sys_ic_get_chip_id=0x10047" in r.text,
    checks=[
        lambda r: (
            0x33 in r.sim.i2c_devices and len(r.sim.i2c_devices[0x33].regs) > 4,
            f"ALi S3501 DVB-S2 demodulator configured at I2C 0x33 "
            f"({len(r.sim.i2c_devices[0x33].regs) if 0x33 in r.sim.i2c_devices else 0} registers)",
        ),
    ],
)
