from simulator import AliMipsSimulator
from unicorn import *
from unicorn.mips_const import *
from mips16_decoder import MIPS16Decoder
import sys
from util_testVerifyAssembly import create_verification_hook, print_test_summary, run_until_trigger

def main():
    # Initialize simulator
    sim = AliMipsSimulator(log_handler=lambda msg: None)

    # Load firmware
    try:
        sim.loadFile("dump.bin")
    except FileNotFoundError:
        print("Error: dump.bin not found.")
        return

    # Define Test Cases
    # Format: Address -> {'hex': 'expected_hex', 'asm': 'expected_disassembly'}
    TEST_CASES = {
        0xafc00000: {'hex': '23 01 00 10', 'asm': 'b 0xafc00490'},
        0xafc00004: {'hex': '00 00 00 00', 'asm': 'nop'},
    }

    # We want to run enough to hit our test cases. 
    LIMIT_INSTRUCTIONS = 2
    
    print(f"Running auto-test with {len(TEST_CASES)} test cases...")
    TRIGGER_ADDRESS = 0xafc00000
    context = {"done": False}
    
    # Create verification hook using utility module
    hook_code, stats = create_verification_hook(
        sim, 
        TEST_CASES, 
        TRIGGER_ADDRESS, 
        context, 
        before=15, 
        after=80
    )
    
    sim.mu.hook_add(UC_HOOK_CODE, hook_code)

    # Run until trigger or limit
    run_until_trigger(sim, context, LIMIT_INSTRUCTIONS)

    exit_code = print_test_summary(stats, TEST_CASES)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
