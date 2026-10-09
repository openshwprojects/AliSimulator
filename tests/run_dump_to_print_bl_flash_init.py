"""
Regression test: runs dump.bin until 'bl_flash_init!' is printed to UART.
"""
import uart_regression

uart_regression.run("dump.bin", stop_at="bl_flash_init!", expected=["bl_flash_init!"])
