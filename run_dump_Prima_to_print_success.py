"""
Regression test: runs dump.bin until 'success!' is printed to UART.
"""
import sys
import time
from simulator import AliMipsSimulator

def main():
    print(f"=== Regression Test: catch 'success!' ===")
    
    sim = AliMipsSimulator(log_handler=lambda msg: None)
    
    # We'll capture UART output and check for the target string
    uart_output = []
    target_found = False
    
    def on_uart(char):
        nonlocal target_found
        uart_output.append(char)
        
        # Prevent flooding stdout
        if len(uart_output) < 1000:
            sys.stdout.write(char)
            sys.stdout.flush()
        elif len(uart_output) == 1000:
            sys.stdout.write("\n[... output suppressed due to flooding ...]\n")
        
        # Check for the key sequence
        # Optimization: only check the last N chars to avoid O(N^2) string builds
        # "success!" is 14 chars.
        end_str = "".join(uart_output[-20:])
        if "success!" in end_str:
            target_found = True
            sim.mu.emu_stop()
        
        # Alternative check: maybe it's in the accumulated buffer but not at the end
        # We do a full check every 100 chars to be safe but efficient
        if len(uart_output) % 100 == 0:
             full_text = "".join(uart_output)
             if "success!" in full_text:
                 target_found = True
                 sim.mu.emu_stop()

    sim.setUartHandler(on_uart)
    
    try:
        sim.loadFile("SRT_Prima_VIII_V1.0.6_20160114.abs")
    except FileNotFoundError:
        print("SRT_Prima_VIII_V1.0.6_20160114.abs not found")
        sys.exit(1)

    print("Running simulator until success!...")
    print("WARNING - this will take a long, long time!")
    start_time = time.time()
    
    # Run with a safety limit
    try:
        sim.run(max_instructions=2_000_000)
    except Exception as e:
        print(f"\nSimulator stopped: {e}")

    # Check results
    duration = time.time() - start_time
    print(f"\n\nTest finished in {duration:.2f}s")
    
    full_text = "".join(uart_output)
    if "success!" in full_text:
        print("\n[PASS] 'success!' found in UART output.")
        sys.exit(0)
    else:
        print("\n[FAIL] 'success!' NOT found.")
        print(f"UART Output captured: {full_text!r}")
        sys.exit(1)

if __name__ == "__main__":
    main()
