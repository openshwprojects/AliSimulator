#!/usr/bin/env python3
"""The Openbox V8S 150519039D update (an ALi M3511 / M3503 rev B, chips/m3503.py)
boots from the flash window with its stack in the cache-as-RAM range until DDR is up,
unscrambles the 13-byte rolling-XOR-obfuscated seecode and maincode chunks in 64 KB
blocks and unpacks them via LzmaDec_DecodeToBuf (0x8108EBDC), parks the SEE
co-processor at 0xA10987DC (chips/see.py) and starts the application at 0x80000200,
which moves its exception vectors (EBase 0x80002000), starts the SEE's program at
0xAE000200 on the second core (EBase 0x8E002001), exchanges remote calls with the
SEE core and drives the 3-wire TM1628 front panel on GPIO 135/134/19 ("LoAd" ->
"L000".."L099").
"""
import see_regression
from front_panel import make_panel

texts = []


def setup(sim):
    dec, _keys, _desc = make_panel("OPENBOX_V8S_3511HD_CMT_150519039D.abs")
    dec.on_frame = lambda _f: (
        t := dec.get_display_text(),
        texts.append(t) if (not texts or texts[-1] != t) else None,
    )
    sim.setGpioHandler(dec.on_gpio_write)


see_regression.run(
    "OPENBOX_V8S_3511HD_CMT_150519039D.abs",
    "the Openbox V8S (M3511 / M3503 rev B) unpacks XOR-scrambled LZMA chunks and runs its application",
    family="M3503", starts=[(0xA10987DC, "parked"), (0xAE000200, "run on the SEE core")],
    calls=25, see_calls=15, limit=55_000_000,
    ebase=0x80002000, see_ebase=0x8E002001,
    setup=setup,
    wait_for=lambda _run: "LoAd" in texts and "LOO1" in texts,
    checks=[
        lambda run: (sum(m.startswith("[CAR]") for m in run.logs) == 1,
                     "the bootloader keeps its stack in the cache-as-RAM range, then runs from RAM"),
        lambda _run: ("LoAd" in texts and "LOO1" in texts,
                      f"the TM1628 front panel shows 'LoAd' and 'LOxx' progress ({texts[:8]})"),
    ],
)
