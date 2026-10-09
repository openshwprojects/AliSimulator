"""
Regression test: runs dump_maciej.bin and checks that its TM1650 front panel
(bit-banged I2C on GPIO 31 / 9) shows ' ON ' (digits 0x00, 0x3F, 0x37, 0x00).
"""
import panel_regression

panel_regression.run("dump_maciej.bin", expected=" ON ", max_instructions=5_000_000,
                     title="dump_maciej -> I2C display ' ON '")
