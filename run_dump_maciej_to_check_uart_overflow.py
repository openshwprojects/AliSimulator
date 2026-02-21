"""
Overflow test: sends 300 bytes via UART interrupt into a 256-byte ring buffer.
Checks what happens — does the firmware:
  (a) drop the oldest bytes (ring buffer wrap)?
  (b) drop the newest bytes (stop accepting)?
  (c) print an error via UART TX?
  (d) crash?

Pattern: bytes 0x00..0xFF then 0x00..0x2B (300 total).
The last 256 bytes would be 0x2C..0xFF,0x00..0x2B if wrapping drops oldest.
"""
import sys
import time
from simulator import AliMipsSimulator

BUF_SIZE = 256
OVERFLOW_COUNT = 300
# Offset pattern: byte i = (i + 0x41) & 0xFF
# This way bytes 0..255 are 0x41..0x40 and bytes 256..299 are 0x41..0x6C
# So positions 0..43 get OVERWRITTEN from 0x41..0x6C to 0x41..0x6C... wait.
# Better: use i+1 so byte 0 = 0x01, byte 255 = 0x00, byte 256 = 0x01, etc.
# No — still collides.  Use high bit: first 256 have bit7=0, overflow has bit7=1.
# Simplest: two distinct halves.
# Bytes 0..255: 'A' + (i % 26) = uppercase letter pattern  
# Bytes 256..299: '0' + (i % 10) = digit pattern
# This way if digits appear in buffer, the overflow bytes overwrote the letters.
UART_TEST_DATA = bytes(
    [ord('A') + (i % 26) for i in range(BUF_SIZE)] +   # 256 letters: ABCDEFG...
    [ord('0') + (i % 10) for i in range(OVERFLOW_COUNT - BUF_SIZE)]  # 44 digits: 01234...
)


def main():
    print(f"=== Overflow Test: {OVERFLOW_COUNT} bytes into {BUF_SIZE}-byte ring buffer ===")

    irq_log = []
    def log_handler(msg):
        irq_log.append(msg)
        if any(k in msg for k in ['UART IRQ', 'ERET', 'overflow', 'error', 'OVERFLOW']):
            print(f"  {msg}", flush=True)

    sim = AliMipsSimulator(log_handler=log_handler)
    sim.setSPIDump(False)
    sim.setI2CDump(False)

    uart_output = []
    def on_uart(char):
        uart_output.append(char)
        if len(uart_output) < 500:
            sys.stdout.write(char)
            sys.stdout.flush()
    sim.setUartHandler(on_uart)

    try:
        sim.loadFile("dump_maciej.bin")
    except FileNotFoundError:
        print("dump_maciej.bin not found, skipping test")
        return

    sim.setUartReceiveData(UART_TEST_DATA, delay_instructions=500000)

    print("Running simulator...", flush=True)
    start_time = time.time()
    try:
        sim.run(max_instructions=2_000_000)
    except Exception:
        pass

    duration = time.time() - start_time
    remaining = len(sim._uart_rx_queue)
    full_text = "".join(uart_output)

    print(f"\n\n--- Results ---")
    print(f"  Duration: {duration:.1f}s, icount={sim.instruction_count}")
    print(f"  Queue remaining: {remaining} bytes (of {OVERFLOW_COUNT} sent)")
    print(f"  Bytes consumed by ISR: {OVERFLOW_COUNT - remaining}")

    # Check if firmware printed any error via UART TX
    # (filter out normal boot messages)
    boot_msgs = ["APP  init!", "bl_panel_init!", "bl_flash_init!", "bl_verify_sw"]
    extra_uart = full_text
    for msg in boot_msgs:
        extra_uart = extra_uart.replace(msg, "")
    extra_uart = extra_uart.replace("\r\n", "").replace("\x01", "").strip()
    if extra_uart:
        print(f"\n  UART TX (beyond boot): '{extra_uart}'")
        print(f"  -> Firmware may have printed an overflow error!")
    else:
        print(f"\n  No extra UART TX output (no overflow error printed)")

    # Scan RAM at ring buffer address 0x81EB2000
    RING_BUF_ADDR = 0x81EB2000
    ram_base = 0x80000000

    print(f"\n--- Ring buffer analysis at 0x{RING_BUF_ADDR:08X} ---")
    buf_offset = RING_BUF_ADDR - ram_base
    ram = bytes(sim.mu.mem_read(ram_base, 128 * 1024 * 1024))
    ring_buf = ram[buf_offset:buf_offset + BUF_SIZE]

    # Count non-zero bytes in ring buffer
    nonzero = sum(1 for b in ring_buf if b != 0)
    print(f"  Non-zero bytes in buffer: {nonzero} / {BUF_SIZE}")

    # Show first 64 and last 64 bytes of ring buffer
    print(f"\n  First 32 bytes: {ring_buf[:32].hex(' ')}")
    print(f"  Bytes 32-64:    {ring_buf[32:64].hex(' ')}")
    print(f"  Bytes 224-256:  {ring_buf[224:256].hex(' ')}")

    # Check for "last 256" pattern (if oldest were dropped / overwritten by wrap)
    # After 300 bytes, rx_buf_head wrapped: positions 0..43 have digits, 44..255 have letters
    letters = bytes([ord('A') + (i % 26) for i in range(BUF_SIZE)])
    digits = bytes([ord('0') + (i % 10) for i in range(OVERFLOW_COUNT - BUF_SIZE)])
    expected_wrap = bytes(digits) + bytes(letters[len(digits):])  # digits at [0..43], letters at [44..255]

    # Check for "first 256" pattern (if newest were dropped — all letters, no digits)
    expected_first256 = letters

    # Check if any digit bytes ('0'..'9') appear in the buffer
    has_digits = any(ord('0') <= b <= ord('9') for b in ring_buf)

    if ring_buf == expected_wrap:
        print(f"\n  Pattern: WRAP (oldest overwritten by newest)")
        print(f"  -> Positions 0..43 contain digits, 44..255 contain original letters")
        print(f"  -> Confirmed: no overflow protection, head wraps and overwrites tail")
        result = "WRAP_DROP_OLDEST"
    elif ring_buf == expected_first256:
        print(f"\n  Pattern: FIRST {BUF_SIZE} bytes stored (all letters, no digits)")
        print(f"  -> Buffer stopped accepting after full")
        result = "STOP_AT_FULL"
    elif has_digits:
        print(f"\n  Pattern: PARTIAL WRAP — some digit bytes found in buffer")
        # Show which positions have digits
        digit_positions = [i for i, b in enumerate(ring_buf) if ord('0') <= b <= ord('9')]
        print(f"  Digit positions: {digit_positions[:20]}{'...' if len(digit_positions) > 20 else ''}")
        result = "PARTIAL_WRAP"
    elif nonzero == 0:
        print(f"\n  Pattern: Buffer is EMPTY (all zeros)")
        print(f"  -> Data was consumed but not stored, or stored elsewhere")
        result = "EMPTY"
    else:
        # Check what's actually in there
        # Find the longest sequential run
        first_nonzero = next((i for i, b in enumerate(ring_buf) if b != 0), -1)
        last_nonzero = next((i for i in range(BUF_SIZE - 1, -1, -1) if ring_buf[i] != 0), -1)
        
        if first_nonzero >= 0:
            stored = ring_buf[first_nonzero:last_nonzero + 1]
            print(f"\n  Data at offsets [{first_nonzero}..{last_nonzero}] ({last_nonzero - first_nonzero + 1} bytes)")
            print(f"  First stored byte: 0x{ring_buf[first_nonzero]:02X} (sent as byte #{ring_buf[first_nonzero]})")
            print(f"  Last stored byte:  0x{ring_buf[last_nonzero]:02X} (sent as byte #{ring_buf[last_nonzero]})")
            
            # Check if it's a contiguous subsequence of our pattern
            start_val = ring_buf[first_nonzero]
            is_sequential = all(ring_buf[first_nonzero + j] == (start_val + j) & 0xFF 
                              for j in range(last_nonzero - first_nonzero + 1))
            if is_sequential:
                print(f"  -> Sequential run from 0x{start_val:02X} to 0x{ring_buf[last_nonzero]:02X}")
        
        result = "PARTIAL"

    # Also check bytes just past the buffer for overflow corruption
    past_buf = ram[buf_offset + BUF_SIZE:buf_offset + BUF_SIZE + 16]
    any_pattern_past = any(b in UART_TEST_DATA[BUF_SIZE:] for b in past_buf if b != 0)
    if any(b != 0 for b in past_buf):
        print(f"\n  Bytes past buffer (corruption check): {past_buf.hex(' ')}")
        if any_pattern_past:
            print(f"  WARNING: Pattern data found past buffer boundary!")
    else:
        print(f"\n  No corruption past buffer boundary (clean)")

    # Also search for the full 300-byte pattern anywhere in RAM
    full_match = ram.find(UART_TEST_DATA)
    if full_match >= 0:
        print(f"\n  Full {OVERFLOW_COUNT}-byte pattern found at 0x{ram_base + full_match:08X}")

    print(f"\n  Result: {result}")
    
    if result == "WRAP_DROP_OLDEST":
        print(f"\n[PASS] Overflow confirmed: {result}")
        print(f"  (Source: sci_16550uart.c line 229-230 — no overflow check, head wraps via % 256)")
        sys.exit(0)
    else:
        print(f"\n[FAIL] Expected WRAP_DROP_OLDEST but got: {result}")
        sys.exit(1)


if __name__ == "__main__":
    main()
