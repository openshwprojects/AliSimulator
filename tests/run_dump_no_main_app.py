"""
Regression test: truncated ROM boot (no main app).
Loads dump.bin but erases everything past 88KB so the bootloader can't find
the main application chunks.  Expected behavior: bootloader prints CRC error
messages and does NOT call expand().

Expected UART output:
  APP  init!
  bl_flash_init!
  bl_verify_sw
  check_program!
  @pointer[...] id[FFFFFFFF] ... > flash size
  crc error!
  Boot loader: CRC bad2!
"""
import uart_regression

uart_regression.run("dump.bin", truncate_to=88 * 1024, stop_at="CRC bad2!", max_instructions=10_000_000,
                    title="truncated ROM boot (no main app)",
                    expected=["APP  init!", "bl_flash_init!", "bl_verify_sw", "check_program!",
                              "crc error!", "Boot loader: CRC bad2!"])
