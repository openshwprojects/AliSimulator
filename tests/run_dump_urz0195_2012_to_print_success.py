"""
Regression test: the Cabletech URZ0195's older flash image
(cableteh_urz0195__w25q32bv.BIN, the 2012 firmware from the elektroda.pl forum,
see its note in dumps/) boots through its bootloader: it prints the panel
configuration of its uPD16312-class LED driver (STB 14, CLK 31, DIO 9), checks
the main code and ends with 'success!'.  Its application never draws through
the graphics engine, so this image has no screen regression.
"""
import uart_regression

uart_regression.run("cableteh_urz0195__w25q32bv.BIN", stop_at="success!", max_instructions=150_000_000,
                    expected=["bl_panel_init!", "stb: 14 clock: 31 data: 9", "nec 16312 attach ok",
                              "digit: 4 seg: 16 data_count: 8", "bl_flash_init!", "bl_verify_sw",
                              "check_program!", "success!"])
