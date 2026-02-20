"""
Regression test: runs dump.bin until the simulator crashes or finishes.
"""
import sys
import time
from simulator import AliMipsSimulator
from tm1650_decoder import TM1650Decoder

def main():
    print(f"=== Regression Test: run dump to end ===")
    
    sim = AliMipsSimulator(log_handler=lambda msg: print(msg) if "INVALID" in msg or "STOPPED" in msg or "Address:" in msg or "Type:" in msg or "Size:" in msg or "PC:" in msg else None)
    sim.setSPIDump(False)
    
    # TM1650 I2C LED display decoder
    tm1650 = TM1650Decoder(
        scl_gpio=31,   # CLK pin (GPIO#31, 191 toggles)
        sda_gpio=9,    # DATA pin (GPIO#9, 54 toggles)
        log_handler=lambda msg: print(msg)
    )
    sim.setGpioHandler(tm1650.on_gpio_write)
    sim.setI2CDump(False)
    
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
        sim.loadFile("dump_maciej.bin")
    except FileNotFoundError:
        print("dump_maciej.bin not found")
        sys.exit(1)

    print("Running simulator...")
    start_time = time.time()
    
    # Run with a safety limit
    try:
        sim.run(max_instructions=5000000)
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
    
    # TM1650 summary
    print(f"\n=== TM1650 I2C Decoder Stats ===")
    print(f"GPIO register change events: {tm1650.gpio_event_count}")
    print(f"I2C transactions: {tm1650.i2c_transaction_count}")
    print(f"Final display: [{tm1650.get_display_text()}]")
    print(f"GPIO offsets seen: {sorted(f'0x{o:03X}' for o in tm1650._offsets_seen)}")
    
    # Show top toggling bits — CLK will have the most toggles
    if tm1650._bit_toggle_counts:
        print(f"\n=== GPIO Bit Toggle Ranking (top 15) ===")
        sorted_bits = sorted(tm1650._bit_toggle_counts.items(), key=lambda x: -x[1])
        for (off, bit), count in sorted_bits[:15]:
            if off == 0x054: gpio = bit
            elif off == 0x0D4: gpio = 32 + bit
            elif off == 0x0E8: gpio = 64 + bit
            elif off == 0x0F4: gpio = 96 + bit
            else: gpio = -1
            print(f"  GPIO#{gpio:3d} (reg 0x{off:03X} bit {bit:2d}): {count:5d} toggles")

if __name__ == "__main__":
    main()
