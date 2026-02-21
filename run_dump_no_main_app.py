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
import sys
import time
from simulator import AliMipsSimulator

EXPECTED_STRINGS = [
    "APP  init!",
    "bl_flash_init!",
    "bl_verify_sw",
    "check_program!",
    "crc error!",
    "Boot loader: CRC bad2!",
]


def main():
    print("=== Regression Test: truncated ROM boot (no main app) ===")

    sim = AliMipsSimulator(log_handler=lambda msg: None)
    sim.setSPIDump(False)
    sim.setI2CDump(False)

    uart_output = []
    target_found = False

    def on_uart(char):
        nonlocal target_found
        uart_output.append(char)
        # Stop once we've seen the final expected marker
        text = "".join(uart_output[-30:])
        if "CRC bad2!" in text:
            target_found = True
            sim.mu.emu_stop()

    sim.setUartHandler(on_uart)

    try:
        sim.loadFileTruncated("dump.bin", 88 * 1024)
    except FileNotFoundError:
        print("dump.bin not found, skipping test")
        return

    print("Running simulator...", flush=True)
    start_time = time.time()
    try:
        sim.run(max_instructions=10_000_000)
    except Exception:
        pass

    duration = time.time() - start_time
    full_text = "".join(uart_output)

    print(f"  Duration: {duration:.1f}s, icount={sim.instruction_count}")

    # Assert all expected strings are present
    passed = 0
    failed = 0
    for s in EXPECTED_STRINGS:
        if s in full_text:
            print(f"  [PASS] '{s}' found in UART output.")
            passed += 1
        else:
            print(f"  [FAIL] '{s}' NOT found in UART output!")
            failed += 1

    if failed == 0:
        print(f"\n[PASS] Truncated ROM boot sequence verified ({passed}/{passed}).")
        sys.exit(0)
    else:
        print(f"\n[FAIL] {failed} expected string(s) missing from UART output.")
        print(f"  Full UART output: {full_text!r}")
        sys.exit(1)


if __name__ == "__main__":
    main()
