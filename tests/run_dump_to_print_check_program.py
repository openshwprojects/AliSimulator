"""
Regression test: runs dump.bin until 'check_program!' is printed to UART.
Verifies the full boot sequence: APP init -> bl_flash_init -> bl_verify_sw -> check_program.
"""
import uart_regression

uart_regression.run("dump.bin", stop_at="check_program!",
                    expected=["APP  init!", "bl_flash_init!", "bl_verify_sw", "check_program!"])
