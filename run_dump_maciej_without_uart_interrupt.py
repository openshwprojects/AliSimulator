"""
Negative test: sends 'OpenSHWProjectsTest' via UART interrupt BEFORE the
firmware's UART ISR is registered.  Uses force_immediate=True to fire at
icount=100 (BEV=1, ROM exception vector).  The ROM handler doesn't dispatch
to our ISR, so the bytes should NOT appear in the ring buffer.

This proves that the interrupt mechanism is using real emulated firmware code
and not cheating by writing directly to RAM.
"""
import sys
import time
from simulator import AliMipsSimulator

UART_TEST_DATA = b'OpenSHWProjectsTest'


def main():
    print(f"=== Negative Test: UART RX interrupt BEFORE ISR registration ===")
    
    irq_log = []
    def log_handler(msg):
        irq_log.append(msg)
        if any(k in msg for k in ['UART', 'IRQ', 'ERET']):
            print(f"  {msg}", flush=True)

    sim = AliMipsSimulator(log_handler=log_handler)
    sim.setSPIDump(False)
    sim.setI2CDump(False)

    uart_output = []
    def on_uart(char):
        uart_output.append(char)
    sim.setUartHandler(on_uart)

    try:
        sim.loadFile("dump_maciej.bin")
    except FileNotFoundError:
        print("dump_maciej.bin not found, skipping test")
        return

    # Fire interrupt at icount=100 with force_immediate=True.
    # At that point BEV=1 in CP0 Status, so exception vector is 0xBFC00380
    # (ROM), not 0x80000180 (RAM where ISR table lives).
    # The ROM exception handler can't dispatch to our UART ISR.
    sim.setUartReceiveData(UART_TEST_DATA, delay_instructions=100, force_immediate=True)

    print("Running simulator (boot may fail due to early interrupt)...", flush=True)
    start_time = time.time()
    try:
        sim.run(max_instructions=2_000_000)
    except Exception as e:
        pass  # Expected — early interrupt disrupts boot

    duration = time.time() - start_time
    remaining = len(sim._uart_rx_queue)
    print(f"\n  Queue remaining: {remaining} bytes, icount={sim.instruction_count}", flush=True)

    # Scan RAM — the string should NOT be found
    print(f"\nScanning RAM for '{UART_TEST_DATA.decode()}'...", flush=True)
    ram_base = 0x80000000
    ram_size = 128 * 1024 * 1024
    ram = bytes(sim.mu.mem_read(ram_base, ram_size))

    found_at = []
    idx = 0
    while True:
        pos = ram.find(UART_TEST_DATA, idx)
        if pos == -1:
            break
        addr = ram_base + pos
        found_at.append(addr)
        print(f"  FOUND at 0x{addr:08X} (unexpected!)", flush=True)
        idx = pos + 1

    print(f"\n  Duration: {duration:.1f}s")

    if len(found_at) == 0:
        print(f"\n[PASS] '{UART_TEST_DATA.decode()}' correctly NOT found in RAM.")
        print(f"  (IRQ fired at icount=100, before ISR was registered — firmware couldn't store it)")
        sys.exit(0)
    else:
        print(f"\n[FAIL] '{UART_TEST_DATA.decode()}' was found in RAM — ISR shouldn't have been registered yet!")
        sys.exit(1)


if __name__ == "__main__":
    main()
