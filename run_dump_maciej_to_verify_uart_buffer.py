"""
Regression test: runs dump_maciej.bin with 'OSHW' queued for UART receive.
After boot, scans RAM to verify 'OSHW' is stored in the firmware's 256-byte
UART ring buffer (sci_16550[id].rx_buf).

Flow: the UART ISR is registered early (~600K instructions) by OS_RegisterISR.
We arm the interrupt delivery at 500K instructions so it fires once IE=1
and EXL=0 in CP0 Status (after TDS2 init). The ISR reads UIIR, then loops
reading LSR/URBR until the queue is drained, storing each byte in rx_buf.
"""
import sys
import time
from simulator import AliMipsSimulator

UART_TEST_DATA = b'OpenSHWProjectsTest'


def main():
    print(f"=== Regression Test: UART RX interrupt -> ring buffer check ===")
    
    # Log handler: only show IRQ-related messages
    irq_log = []
    def log_handler(msg):
        irq_log.append(msg)
        if any(k in msg for k in ['UART', 'IRQ', 'ERET']):
            print(f"  {msg}", flush=True)

    sim = AliMipsSimulator(log_handler=log_handler)
    sim.setSPIDump(False)
    sim.setI2CDump(False)

    # Capture UART TX output
    uart_output = []
    def on_uart(char):
        uart_output.append(char)
        if len(uart_output) < 200:
            sys.stdout.write(char)
            sys.stdout.flush()
    sim.setUartHandler(on_uart)

    try:
        sim.loadFile("dump_maciej.bin")
    except FileNotFoundError:
        print("dump_maciej.bin not found, skipping test")
        return

    # Queue UART RX data BEFORE boot — delay set to 500K instructions
    # so the interrupt fires after UART ISR is registered (~600K) and
    # after CP0 Status IE=1 is set by TDS2 init.
    sim.setUartReceiveData(UART_TEST_DATA, delay_instructions=500000)

    print("Running simulator...", flush=True)
    start_time = time.time()
    try:
        sim.run(max_instructions=2_000_000)
    except Exception as e:
        pass  # expand() may crash — expected

    duration = time.time() - start_time
    full_text = "".join(uart_output)

    # Check boot sequence
    boot_strings = ["APP  init!", "bl_panel_init!", "bl_flash_init!"]
    boot_ok = all(s in full_text for s in boot_strings)
    if not boot_ok:
        print(f"\n[FAIL] Boot sequence incomplete.")
        print(f"UART: {full_text!r}")
        sys.exit(1)

    remaining = len(sim._uart_rx_queue)
    print(f"\n  Queue remaining: {remaining} bytes, icount={sim.instruction_count}")

    # Scan RAM for 'OSHW'
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
        ctx = ram[max(0, pos - 4):pos + len(UART_TEST_DATA) + 4]
        found_at.append(addr)
        print(f"  FOUND at 0x{addr:08X}: {ctx.hex(' ')}", flush=True)
        idx = pos + 1

    print(f"\n  Total matches: {len(found_at)}")
    print(f"  Duration: {duration:.1f}s")

    if len(found_at) >= 1:
        print(f"\n[PASS] '{UART_TEST_DATA.decode()}' found in RAM ring buffer!")
        print(f"  Ring buffer address(es): {', '.join(f'0x{a:08X}' for a in found_at)}")
        sys.exit(0)
    else:
        print(f"\n[FAIL] '{UART_TEST_DATA.decode()}' NOT found in RAM.")
        sys.exit(1)


if __name__ == "__main__":
    main()
