"""
Regression test: runs dump_maciej.bin until 'bl_flash_init!' is printed to UART,
then verifies the UART output starts with the expected boot sequence lines.
"""
import uart_regression

uart_regression.run("dump_maciej.bin", stop_at="bl_flash_init!", ordered=True,
                    expected=["APP  init!", "bl_panel_init!", "bl_flash_init!"])
