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

    # Define Test Cases - flash ID area around 0x81E87A38
    # Expected values taken from Ghidra disassembly
    # Format: Address -> {'hex': 'expected_hex', 'asm': 'expected_disassembly'}
    TEST_CASES = {
        0x81E87A2E: {"hex": "03 10", "asm": "b        0x81e87a36"},
        0x81E87A30: {"hex": "00 6a", "asm": "li       v0,0x0"},
        0x81E87A32: {"hex": "10 f1 4c c8", "asm": "sh       v0,-0x7ef4(s0)"},
        0x81E87A36: {"hex": "40 99", "asm": "lw       v0,0x0(s1)"},
        0x81E87A38: {"hex": "10 f1 48 c8", "asm": "sh       v0,-0x7ef8(s0)"},
        0x81E87A3C: {"hex": "30 f0 54 98", "asm": "lw       v0,-0x7fcc(s0)"},
        0x81E87A40: {"hex": "09 69", "asm": "li       s1,0x9"},
        0x81E87A42: {"hex": "80 f0 39 c2", "asm": "sb       s1,0x99(v0)"},
        0x81E87A46: {"hex": "30 f0 74 98", "asm": "lw       v1,-0x7fcc(s0)"},
        0x81E87A4A: {"hex": "80 f0 59 a3", "asm": "lbu      v0,0x99(v1)"},
        0x81E87A4E: {"hex": "11 ea", "asm": "zeb      v0"},
        0x81E87A50: {"hex": "10 f1 50 d8", "asm": "sw       v0,-0x7ef0(s0)"},
        0x81E87A54: {"hex": "05 6a", "asm": "li       v0,0x5"},
        0x81E87A56: {"hex": "80 f0 58 c3", "asm": "sb       v0,0x98(v1)"},
        0x81E87A5A: {"hex": "30 f0 54 98", "asm": "lw       v0,-0x7fcc(s0)"},
        0x81E87A5E: {"hex": "80 f0 58 a2", "asm": "lbu      v0,0x98(v0)"},
    }

    # We want to run enough to hit the flash ID area.
    LIMIT_INSTRUCTIONS = 20000000
    
    print(f"Running auto-test with {len(TEST_CASES)} test cases...")
    TRIGGER_ADDRESS = 0x81E87A38
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
