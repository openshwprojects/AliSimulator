"""
Regression test: runs dump_maciej.bin and checks TM1650 I2C display shows ' ON '.
Terminates with success once digits [0x00, 0x3F, 0x37, 0x00] are received.
"""
import sys
import time
from simulator import AliMipsSimulator
from tm1650_decoder import TM1650Decoder

EXPECTED_DIGITS = [0x00, 0x3F, 0x37, 0x00]  # ' ON '

def main():
    print(f"=== Regression Test: dump_maciej -> I2C display ' ON ' ===")
    
    sim = AliMipsSimulator(log_handler=lambda msg: None)
    sim.setSPIDump(False)
    
    # Track display state
    received_digits = [None, None, None, None]
    test_passed = [False]
    
    def on_i2c_transaction(addr, data):
        """Called on each decoded TM1650 I2C transaction."""
        digit_map = {0x68: 0, 0x6A: 1, 0x6C: 2, 0x6E: 3}
        if addr in digit_map:
            idx = digit_map[addr]
            received_digits[idx] = data
            # Check if all expected digits received
            if received_digits == EXPECTED_DIGITS:
                test_passed[0] = True
                sim.mu.emu_stop()
    
    tm1650 = TM1650Decoder(
        scl_gpio=31,
        sda_gpio=9,
        log_handler=lambda msg: print(msg) if msg.startswith('[TM1650]') else None,
        on_transaction=on_i2c_transaction,
    )
    sim.setGpioHandler(tm1650.on_gpio_write)
    sim.setI2CDump(False)
    
    # Capture UART (silent)
    sim.setUartHandler(lambda c: None)
    
    try:
        sim.loadFile("dump_maciej.bin")
    except FileNotFoundError:
        print("dump_maciej.bin not found, skipping test")
        return
    
    print("Running simulator...")
    start_time = time.time()
    
    try:
        sim.run(max_instructions=5_000_000)
    except Exception as e:
        pass
    
    duration = time.time() - start_time
    
    if test_passed[0]:
        display = tm1650.get_display_text()
        print(f"\n[PASS] TM1650 display shows [{display}] after {duration:.2f}s")
        print(f"  Digits: {['0x%02X' % (d if d is not None else 0) for d in received_digits]}")
        print(f"  I2C transactions: {tm1650.i2c_transaction_count}")
    else:
        display = tm1650.get_display_text()
        print(f"\n[FAIL] Expected digits {['0x%02X' % d for d in EXPECTED_DIGITS]}")
        print(f"  Got: {['0x%02X' % (d if d is not None else 0) for d in received_digits]}")
        print(f"  Display: [{display}]")
        print(f"  I2C transactions: {tm1650.i2c_transaction_count}")
        sys.exit(1)

if __name__ == "__main__":
    main()
