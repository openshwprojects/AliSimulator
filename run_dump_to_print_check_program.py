"""
Regression test: runs dump.bin until 'check_program!' is printed to UART.
Verifies the full boot sequence: APP init -> bl_flash_init -> bl_verify_sw -> check_program.
"""
import sys
import time
from simulator import AliMipsSimulator

EXPECTED_STRINGS = [
    "APP  init!",
    "bl_flash_init!",
    "bl_verify_sw",
    "check_program!",
]

def main():
    print(f"=== Regression Test: full boot sequence up to 'check_program!' ===")
    
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
        
        # Check for the last expected string
        end_str = "".join(uart_output[-20:])
        if "check_program!" in end_str:
            target_found = True
            sim.mu.emu_stop()
        
        # Full check every 100 chars
        if len(uart_output) % 100 == 0:
             full_text = "".join(uart_output)
             if "check_program!" in full_text:
                 target_found = True
                 sim.mu.emu_stop()

    sim.setUartHandler(on_uart)
    
    try:
        sim.loadFile("dump.bin")
    except FileNotFoundError:
        print("dump.bin not found")
        sys.exit(1)

    print("Running simulator...")
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
    
    all_passed = True
    for expected in EXPECTED_STRINGS:
        if expected in full_text:
            print(f"  [PASS] '{expected}' found in UART output.")
        else:
            print(f"  [FAIL] '{expected}' NOT found in UART output.")
            all_passed = False
    
    if all_passed:
        print(f"\n[PASS] Full boot sequence verified.")
        sys.exit(0)
    else:
        print(f"\n[FAIL] Boot sequence incomplete.")
        print(f"UART Output captured: {full_text!r}")
        sys.exit(1)

if __name__ == "__main__":
    main()
