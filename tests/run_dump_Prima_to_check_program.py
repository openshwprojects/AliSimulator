"""
Regression test: runs SRT_Prima_VIII_V1.0.6_20160114.abs until 'check_program!' is printed to UART,
then verifies the UART output starts with the expected boot sequence lines.
"""
import uart_regression

uart_regression.run("SRT_Prima_VIII_V1.0.6_20160114.abs", stop_at="check_program!", ordered=True,
                    expected=["APP  init!", "bl_flash_init!", "bl_verify_sw", "check_program!"])
