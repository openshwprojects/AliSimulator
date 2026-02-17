"""
Regression test: runs dump_maciej.bin until 'bl_flash_init!' is printed to UART,
then verifies the UART output contains the expected boot sequence lines.
"""
import sys
import time
from simulator import AliMipsSimulator

EXPECTED_LINES = [
    "APP  init!",
    "bl_panel_init!",
    "bl_flash_init!",
]

def main():
    print(f"=== Regression Test: dump_maciej.bin -> 'bl_flash_init!' ===")
    
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
        # "bl_flash_init!" is 14 chars.
        end_str = "".join(uart_output[-20:])
        if "bl_flash_init!" in end_str:
            target_found = True
            sim.mu.emu_stop()
        
        # Full check every 100 chars to be safe but efficient
        if len(uart_output) % 100 == 0:
             full_text = "".join(uart_output)
             if "bl_flash_init!" in full_text:
                 target_found = True
                 sim.mu.emu_stop()

    sim.setUartHandler(on_uart)
    
    try:
        sim.loadFile("dump_maciej.bin")
    except FileNotFoundError:
        print("dump_maciej.bin not found")
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
    if "bl_flash_init!" not in full_text:
        print("\n[FAIL] 'bl_flash_init!' NOT found in UART output.")
        print(f"UART Output captured: {full_text!r}")
        sys.exit(1)
    
    # Normalize: strip control chars, normalize line endings, split into lines
    cleaned = full_text.replace("\r\n", "\n").replace("\r", "\n")
    # Remove non-printable control characters (keep newlines)
    cleaned = "".join(c for c in cleaned if c == "\n" or (c.isprintable()))
    lines = [l.strip() for l in cleaned.split("\n") if l.strip()]
    
    # Verify the expected lines appear at the start
    # The firmware prints extra '!' chars after bl_flash_init, so we use startswith
    ok = True
    for i, expected in enumerate(EXPECTED_LINES):
        if i >= len(lines):
            print(f"\n[FAIL] Expected line {i}: {expected!r} but only got {len(lines)} lines")
            ok = False
            break
        if not lines[i].startswith(expected):
            print(f"\n[FAIL] Line {i} mismatch:")
            print(f"  Expected (startswith): {expected!r}")
            print(f"  Got:                   {lines[i]!r}")
            ok = False
    
    if ok:
        print(f"\n[PASS] UART output contains expected boot sequence.")
        print(f"  Lines: {lines[:len(EXPECTED_LINES)]}")
        sys.exit(0)
    else:
        print(f"Full UART output: {full_text!r}")
        sys.exit(1)

if __name__ == "__main__":
    main()
