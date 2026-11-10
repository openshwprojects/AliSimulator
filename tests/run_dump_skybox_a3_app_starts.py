#!/usr/bin/env python3
"""The Skybox A3 / A4 / M5 14012005F1 CMT update (an ALi M3606 / M3602,
chips/m3602.py) boots from the 4 MB SPI flash, unscrambles the 13-byte
rolling-XOR-obfuscated seecode and maincode chunks in 64 KB blocks and unpacks
them via LzmaDec_DecodeToBuf (0x81E88274), parks the SEE co-processor at
0xA1E92F14 (chips/see.py) and starts the application at 0x80000200, which
starts the SEE's program at 0xA6000200 on the second core, exchanges remote
calls with the SEE core and drives the open-drain 3-wire PT6315 / uPD16315
24-byte VFD front panel (display mode 0x04) on CLK = GPIO 62, DIO = GPIO 63,
STB = GPIO 64 ("LOAD" -> "LOO1".."LO93").
"""
import see_regression
from front_panel import make_panel

texts = []


def setup(sim):
    dec, _keys, _desc = make_panel("SKYBOX_A3_A4_M5_3606HD_CMT_14012005F1.abs", log_handler=lambda _m: None)
    dec.on_frame = lambda _f: (
        t := dec.get_display_text(),
        texts.append(t) if (not texts or texts[-1] != t) else None,
    )
    sim.setGpioHandler(dec.on_gpio_write)


see_regression.run(
    "SKYBOX_A3_A4_M5_3606HD_CMT_14012005F1.abs",
    "the Skybox A3 / A4 / M5 (M3606 / M3602) unpacks XOR-scrambled LZMA chunks and runs its application",
    family="M3602", starts=[(0xA1E92F14, "parked"), (0xA6000200, "run on the SEE core")],
    calls=25, see_calls=15, limit=25_000_000,
    ebase=0x80000000, see_ebase=0x80000001,
    setup=setup,
    wait_for=lambda _run: "LOAD" in texts and "LOO1" in texts and "LO93" in texts,
    checks=[
        lambda _run: ("LOAD" in texts and "LOO1" in texts and "LO93" in texts,
                      f"the PT6315 VFD front panel shows 'LOAD' and 'LOO1'..'LO93' progress ({texts[:6]}..{texts[-3:]})"),
    ],
)
