#!/usr/bin/env python3
"""The Opticum Blue R265 Lite firmware writes ' ON ' to its HD2015 front-panel chip
(TM1650-compatible, bit-banged I2C on GPIO 57 / 58 of the M3821) from stage 2 of its
bootloader; the decoder front_panel.py picks for the image reads it back.
"""
import panel_regression

panel_regression.run("T2GEN265_1.1.5-2022-08-01.abs", expected=" ON ", max_instructions=40_000_000,
                     title="Opticum Blue R265 Lite (M3821) shows ' ON ' on its HD2015 panel")
