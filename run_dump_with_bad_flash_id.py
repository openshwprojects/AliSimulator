"""
Test: runs dump.bin with a garbage flash JEDEC ID to verify the bootloader
correctly reports "Can't find FLASH device!" when the ID doesn't match.
"""
import sys
import time
from simulator import AliMipsSimulator

def main():
    print(f"=== Test: garbage flash JEDEC ID -> expect 'Can't find FLASH device!' ===")
    
    sim = AliMipsSimulator(log_handler=lambda msg: None)
    
    # Set a garbage JEDEC ID that won't match any device table entry
    sim._spi_jedec_id = [0xDE, 0xAD, 0xFF]
    
    uart_output = []
    
    def on_uart(char):
        uart_output.append(char)
        if len(uart_output) < 1000:
            sys.stdout.write(char)
            sys.stdout.flush()

    sim.setUartHandler(on_uart)
    
    try:
        sim.loadFile("dump.bin")
    except FileNotFoundError:
        print("dump.bin not found")
        sys.exit(1)

    print("Running simulator with garbage JEDEC ID [0xDE, 0xAD, 0xFF]...")
    start_time = time.time()
    
    try:
        sim.run(max_instructions=2_000_000)
    except Exception as e:
        print(f"\nSimulator stopped: {e}")

    duration = time.time() - start_time
    full_text = "".join(uart_output)
    
    print(f"\n\nTest finished in {duration:.2f}s")
    print(f"UART output: {full_text!r}")
    
    if "Can't find FLASH device!" in full_text:
        print("\n[PASS] Bad flash ID correctly detected: 'Can't find FLASH device!'")
        sys.exit(0)
    else:
        print("\n[FAIL] Expected 'Can't find FLASH device!' but didn't find it.")
        sys.exit(1)

if __name__ == "__main__":
    main()
