"""
Regression test: runs SRT_Prima_VIII_V1.0.6_20160114.abs until the bootloader's
'success!' is printed to UART (the whole bootloader, up to 150 M instructions).
"""
import uart_regression

uart_regression.run("SRT_Prima_VIII_V1.0.6_20160114.abs", stop_at="success!", expected=["success!"],
                    max_instructions=150_000_000)
