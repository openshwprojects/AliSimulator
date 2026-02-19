"""
Regression test: runs dump.bin until the simulator crashes or finishes.
"""
import sys
import time
from simulator import AliMipsSimulator

def main():
    print(f"=== Regression Test: run dump to end ===")
    
    sim = AliMipsSimulator(log_handler=lambda msg: print(msg) if "INVALID" in msg or "STOPPED" in msg or "Address:" in msg or "Type:" in msg or "Size:" in msg or "PC:" in msg else None)
    
    # We'll capture UART output
    uart_output = []
    
    def on_uart(char):
        uart_output.append(char)
        
        # Prevent flooding stdout
        if len(uart_output) < 1000:
            sys.stdout.write(char)
            sys.stdout.flush()
        elif len(uart_output) == 1000:
            sys.stdout.write("\n[... output suppressed due to flooding ...]\n")

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
        sim.run(max_instructions=55_000_000)
    except Exception as e:
        print(f"\nSimulator stopped with exception: {e}")

    # Check results
    duration = time.time() - start_time
    print(f"\n\nTest finished in {duration:.2f}s")
    
    full_text = "".join(uart_output)
    print(f"\nFull UART Output:\n{full_text}")
    
    # Print final PC
    try:
        pc = sim.mu.reg_read(sim.UC_MIPS_REG_PC) if hasattr(sim, 'UC_MIPS_REG_PC') else "unknown"
        print(f"\nFinal PC: {pc:#010x}" if isinstance(pc, int) else f"\nFinal PC: {pc}")
    except:
        pass
    
    print(f"\nInstructions executed info available from simulator logs.")

if __name__ == "__main__":
    main()
