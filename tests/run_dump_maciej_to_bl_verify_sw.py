"""
Regression test: runs dump_maciej.bin until 'bl_verify_sw' is printed to UART.
Verifies the boot sequence: APP init -> bl_panel_init -> bl_flash_init -> bl_verify_sw.
"""
import uart_regression

uart_regression.run("dump_maciej.bin", stop_at="bl_verify_sw",
                    expected=["APP  init!", "bl_panel_init!", "bl_flash_init!", "bl_verify_sw"])
