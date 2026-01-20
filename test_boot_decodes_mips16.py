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
        0x81E84280: {"hex": "f7 64", "asm": "save     0x38,ra,s0-s5"},
        0x81E84282: {"hex": "00 6a", "asm": "li       v0,0x0"},
        0x81E84284: {"hex": "06 d2", "asm": "sw       v0,0x18(sp)"},
        0x81E84286: {"hex": "75 b2", "asm": "lw       v0,0x1d4(pc)"},
        0x81E8428C: {"hex": "74 b2", "asm": "lw       v0,0x1d0(pc)"},
        0x81E8428E: {"hex": "80 a2", "asm": "lbu      a0,0x0(v0)"},
        0x81E84290: {"hex": "43 1b 90 10", "asm": "jal      0x81e84240"},
        0x81E84294: {"hex": "00 65", "asm": "nop"},
        0x81E84296: {"hex": "43 1b 27 10", "asm": "jal      0x81e8409c"},
        0x81E8429A: {"hex": "00 65", "asm": "nop"},
        0x81E8429C: {"hex": "43 1f d5 36", "asm": "jalx     0x81e8db54"},
        0x81E842A0: {"hex": "00 65", "asm": "nop"},
        0x81E842A2: {"hex": "70 b3", "asm": "lw       v1,0x1c0(pc)"},
        0x81E842A4: {"hex": "70 b1", "asm": "lw       s1,0x1c0(pc)"},
        0x81E842A6: {"hex": "40 9b", "asm": "lw       v0,0x0(v1)"},
        0x81E842A8: {"hex": "2c ea", "asm": "and      v0,s1"},
        0x81E842AA: {"hex": "70 b0", "asm": "lw       s0,0x1c0(pc)"},
        0x81E842AC: {"hex": "0d ea", "asm": "or       v0,s0"},
        0x81E842AE: {"hex": "40 db", "asm": "sw       v0,0x0(v1)"},
        0x81E842B0: {"hex": "43 1f df 36", "asm": "jalx     0x81e8db7c"},
        0x81E842B4: {"hex": "00 65", "asm": "nop"},
        0x81E842B6: {"hex": "43 1f d5 36", "asm": "jalx     0x81e8db54"},
        0x81E842BA: {"hex": "00 65", "asm": "nop"},
        0x81E842BC: {"hex": "6c b3", "asm": "lw       v1,0x1b0(pc)"},
        0x81E842BE: {"hex": "40 9b", "asm": "lw       v0,0x0(v1)"},
        0x81E842C0: {"hex": "2c ea", "asm": "and      v0,s1"},
        0x81E842C2: {"hex": "0d ea", "asm": "or       v0,s0"},
        0x81E842C4: {"hex": "40 db", "asm": "sw       v0,0x0(v1)"},
        0x81E842C6: {"hex": "43 1f df 36", "asm": "jalx     0x81e8db7c"},
        0x81E842CA: {"hex": "00 65", "asm": "nop"},
        0x81E842CC: {"hex": "43 1b 34 10", "asm": "jal      0x81e840d0"},
        0x81E842D0: {"hex": "00 65", "asm": "nop"},
        0x81E842D2: {"hex": "43 1b 44 10", "asm": "jal      0x81e84110"},
        0x81E842D6: {"hex": "00 65", "asm": "nop"},
        0x81E842D8: {"hex": "43 1b 7d 10", "asm": "jal      0x81e841f4"},
        0x81E842DC: {"hex": "00 65", "asm": "nop"},
        0x81E842DE: {"hex": "7c 67", "asm": "move     v1,gp"},
        0x81E842E0: {"hex": "b0 f0 44 a3", "asm": "lbu      v0,-0x7f5c(v1)"},
        0x81E842E4: {"hex": "04 22", "asm": "beqz     v0,0x81e842ee"},
        0x81E842E6: {"hex": "90 f0 56 a3", "asm": "lbu      v0,-0x7f6a(v1)"},
        0x81E842EA: {"hex": "01 72", "asm": "cmpi     v0,0x1"},
        0x81E842EC: {"hex": "6b 61", "asm": "btnez    0x81e843c4"},
        0x81E842EE: {"hex": "7c 67", "asm": "move     v1,gp"},
        0x81E842F0: {"hex": "90 f0 56 a3", "asm": "lbu      v0,-0x7f6a(v1)"},
        0x81E842F4: {"hex": "06 22", "asm": "beqz     v0,0x81e84302"},
        0x81E842F6: {"hex": "5f b2", "asm": "lw       v0,0x17c(pc)"},
        0x81E842F8: {"hex": "05 d2", "asm": "sw       v0,0x14(sp)"},
        0x81E842FA: {"hex": "90 f0 58 9b", "asm": "lw       v0,-0x7f68(v1)"},
        0x81E842FE: {"hex": "06 d2", "asm": "sw       v0,0x18(sp)"},
        0x81E84300: {"hex": "1c 10", "asm": "b        0x81e8433a"},
        0x81E84302: {"hex": "7c 67", "asm": "move     v1,gp"},
        0x81E84304: {"hex": "b0 f0 44 a3", "asm": "lbu      v0,-0x7f5c(v1)"},
        0x81E84308: {"hex": "18 2a", "asm": "bnez     v0,0x81e8433a"},
        0x81E8430A: {"hex": "5b b2", "asm": "lw       v0,0x16c(pc)"},
        0x81E8430C: {"hex": "08 93", "asm": "lw       v1,0x20(sp)"},
        0x81E8430E: {"hex": "6e ea", "asm": "xor      v0,v1"},
        0x81E84310: {"hex": "0b 2a", "asm": "bnez     v0,0x81e84328"},
        0x81E84312: {"hex": "5a b2", "asm": "lw       v0,0x168(pc)"},
        0x81E84314: {"hex": "40 9a", "asm": "lw       v0,0x0(v0)"},
        0x81E84316: {"hex": "05 d2", "asm": "sw       v0,0x14(sp)"},
        0x81E84318: {"hex": "05 04", "asm": "addiu    a0,sp,0x14"},
        0x81E8431A: {"hex": "59 b2", "asm": "lw       v0,0x164(pc)"},
        0x81E8431C: {"hex": "a0 9a", "asm": "lw       a1,0x0(v0)"},
        0x81E8431E: {"hex": "01 6e", "asm": "li       a2,0x1"},
        0x81E84320: {"hex": "43 1b e0 19", "asm": "jal      0x81e86780"},
        0x81E84324: {"hex": "00 65", "asm": "nop"},
        0x81E84326: {"hex": "09 10", "asm": "b        0x81e8433a"},
        0x81E84328: {"hex": "56 b2", "asm": "lw       v0,0x158(pc)"},
        0x81E8432A: {"hex": "05 d2", "asm": "sw       v0,0x14(sp)"},
        0x81E8432C: {"hex": "05 04", "asm": "addiu    a0,sp,0x14"},
        0x81E8432E: {"hex": "56 b5", "asm": "lw       a1,0x158(pc)"},
        0x81E84330: {"hex": "01 6e", "asm": "li       a2,0x1"},
        0x81E84332: {"hex": "43 1b e0 19", "asm": "jal      0x81e86780"},
        0x81E84336: {"hex": "00 65", "asm": "nop"},
        0x81E84338: {"hex": "06 d2", "asm": "sw       v0,0x18(sp)"},
    }

    # We want to run enough to hit our test cases. 
    LIMIT_INSTRUCTIONS = 20000000 
    
    print(f"Running auto-test with {len(TEST_CASES)} test cases...")
    TRIGGER_ADDRESS = 0x81E84280
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
