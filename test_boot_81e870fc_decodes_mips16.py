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

    # Define Test Cases for FUN_ra2__81e870fc
    # Format: Address -> {'hex': 'expected_hex', 'asm': 'expected_disassembly'}
    TEST_CASES = {
        0x81E870FC: {"hex": "04 f0 f4 64", "asm": "save     a0,0x20,ra,s0-s1"},
        0x81E87100: {"hex": "47 b4", "asm": "lw       a0,0x11c(pc)"},
        0x81E87102: {"hex": "48 b5", "asm": "lw       a1,0x120(pc)"},
        0x81E87104: {"hex": "40 f4 18 6e", "asm": "li       a2,0x458"},
        0x81E87108: {"hex": "43 1b 24 26", "asm": "jal      0x81e89890"},
        0x81E8710C: {"hex": "00 65", "asm": "nop"},
        0x81E8710E: {"hex": "22 67", "asm": "move     s1,v0"},
        0x81E87110: {"hex": "03 2a", "asm": "bnez     v0,0x81e87118"},
        0x81E87112: {"hex": "01 6a", "asm": "li       v0,0x1"},
        0x81E87114: {"hex": "4b ea", "asm": "neg      v0,v0"},
        0x81E87116: {"hex": "7f 10", "asm": "b        0x81e87216"},
        0x81E87118: {"hex": "40 6c", "asm": "li       a0,0x40"},
        0x81E8711A: {"hex": "43 1b b2 11", "asm": "jal      0x81e846c8"},
        0x81E8711E: {"hex": "00 65", "asm": "nop"},
        0x81E87120: {"hex": "02 67", "asm": "move     s0,v0"},
        0x81E87122: {"hex": "07 2a", "asm": "bnez     v0,0x81e87132"},
        0x81E87124: {"hex": "91 67", "asm": "move     a0,s1"},
        0x81E87126: {"hex": "43 1b 48 26", "asm": "jal      0x81e89920"},
        0x81E8712A: {"hex": "00 65", "asm": "nop"},
        0x81E8712C: {"hex": "01 6a", "asm": "li       v0,0x1"},
        0x81E8712E: {"hex": "4b ea", "asm": "neg      v0,v0"},
        0x81E87130: {"hex": "72 10", "asm": "b        0x81e87216"},
        0x81E87132: {"hex": "82 67", "asm": "move     a0,v0"},
        0x81E87134: {"hex": "00 6d", "asm": "li       a1,0x0"},
        0x81E87136: {"hex": "40 6e", "asm": "li       a2,0x40"},
        0x81E87138: {"hex": "43 1b c5 16", "asm": "jal      0x81e85b14"},
        0x81E8713C: {"hex": "00 65", "asm": "nop"},
        0x81E8713E: {"hex": "07 d9", "asm": "sw       s0,0x1c(s1)"},
        0x81E87140: {"hex": "39 b2", "asm": "lw       v0,0xe4(pc)"},
        0x81E87142: {"hex": "49 d8", "asm": "sw       v0,0x24(s0)"},
        0x81E87144: {"hex": "39 b2", "asm": "lw       v0,0xe4(pc)"},
        0x81E87146: {"hex": "4a d8", "asm": "sw       v0,0x28(s0)"},
        0x81E87148: {"hex": "39 b2", "asm": "lw       v0,0xe4(pc)"},
        0x81E8714A: {"hex": "4b d8", "asm": "sw       v0,0x2c(s0)"},
        0x81E8714C: {"hex": "39 b2", "asm": "lw       v0,0xe4(pc)"},
        0x81E8714E: {"hex": "4c d8", "asm": "sw       v0,0x30(s0)"},
        0x81E87150: {"hex": "39 b2", "asm": "lw       v0,0xe4(pc)"},
        0x81E87152: {"hex": "4d d8", "asm": "sw       v0,0x34(s0)"},
        0x81E87154: {"hex": "39 b2", "asm": "lw       v0,0xe4(pc)"},
        0x81E87156: {"hex": "4e d8", "asm": "sw       v0,0x38(s0)"},
        0x81E87158: {"hex": "39 b2", "asm": "lw       v0,0xe4(pc)"},
        0x81E8715A: {"hex": "4f d8", "asm": "sw       v0,0x3c(s0)"},
        0x81E8715C: {"hex": "00 6a", "asm": "li       v0,0x0"},
        0x81E8715E: {"hex": "47 d8", "asm": "sw       v0,0x1c(s0)"},
        0x81E87160: {"hex": "48 d8", "asm": "sw       v0,0x20(s0)"},
        0x81E87162: {"hex": "46 d8", "asm": "sw       v0,0x18(s0)"},
        0x81E87164: {"hex": "08 92", "asm": "lw       v0,0x20(sp)"},
        0x81E87166: {"hex": "02 22", "asm": "beqz     v0,0x81e8716c"},
        0x81E87168: {"hex": "48 8a", "asm": "lh       v0,0x10(v0)"},
        0x81E8716A: {"hex": "0a 2a", "asm": "bnez     v0,0x81e87180"},
        0x81E8716C: {"hex": "35 b2", "asm": "lw       v0,0xd4(pc)"},
        0x81E8716E: {"hex": "40 d8", "asm": "sw       v0,0x0(s0)"},
        0x81E87170: {"hex": "35 b2", "asm": "lw       v0,0xd4(pc)"},
        0x81E87172: {"hex": "41 d8", "asm": "sw       v0,0x4(s0)"},
        0x81E87174: {"hex": "35 b2", "asm": "lw       v0,0xd4(pc)"},
        0x81E87176: {"hex": "42 d8", "asm": "sw       v0,0x8(s0)"},
        0x81E87178: {"hex": "35 b2", "asm": "lw       v0,0xd4(pc)"},
        0x81E8717A: {"hex": "40 aa", "asm": "lhu      v0,0x0(v0)"},
        0x81E8717C: {"hex": "46 c8", "asm": "sh       v0,0xc(s0)"},
        0x81E8717E: {"hex": "09 10", "asm": "b        0x81e87192"},
        0x81E87180: {"hex": "08 93", "asm": "lw       v1,0x20(sp)"},
        0x81E87182: {"hex": "45 9b", "asm": "lw       v0,0x14(v1)"},
        0x81E87184: {"hex": "40 d8", "asm": "sw       v0,0x0(s0)"},
        0x81E87186: {"hex": "46 9b", "asm": "lw       v0,0x18(v1)"},
        0x81E87188: {"hex": "41 d8", "asm": "sw       v0,0x4(s0)"},
        0x81E8718A: {"hex": "48 9b", "asm": "lw       v0,0x20(v1)"},
        0x81E8718C: {"hex": "42 d8", "asm": "sw       v0,0x8(s0)"},
        0x81E8718E: {"hex": "48 ab", "asm": "lhu      v0,0x10(v1)"},
        0x81E87190: {"hex": "46 c8", "asm": "sh       v0,0xc(s0)"},
        0x81E87192: {"hex": "91 67", "asm": "move     a0,s1"},
        0x81E87194: {"hex": "24 4c", "asm": "addiu    a0,0x24"},
        0x81E87196: {"hex": "00 6d", "asm": "li       a1,0x0"},
        0x81E87198: {"hex": "00 f4 00 6e", "asm": "li       a2,0x400"},
        0x81E8719C: {"hex": "43 1b c5 16", "asm": "jal      0x81e85b14"},
        0x81E871A0: {"hex": "00 65", "asm": "nop"},
        0x81E871A2: {"hex": "2c b2", "asm": "lw       v0,0xb0(pc)"},
        0x81E871A4: {"hex": "48 d9", "asm": "sw       v0,0x20(s1)"},
        0x81E871A6: {"hex": "91 67", "asm": "move     a0,s1"},
        0x81E871A8: {"hex": "00 6d", "asm": "li       a1,0x0"},
        0x81E871AA: {"hex": "43 1b 9a 1c", "asm": "jal      0x81e87268"},
    }

    # We want to run enough to hit our test cases. 
    LIMIT_INSTRUCTIONS = 20000000 
    
    print(f"Running auto-test with {len(TEST_CASES)} test cases...")
    TRIGGER_ADDRESS = 0x81E870FC
    context = {"done": False}
    
    # Create verification hook using utility module
    hook_code, stats = create_verification_hook(
        sim, 
        TEST_CASES, 
        TRIGGER_ADDRESS, 
        context, 
        before=15, 
        after=120
    )
    
    sim.mu.hook_add(UC_HOOK_CODE, hook_code)

    # Run until trigger or limit
    run_until_trigger(sim, context, LIMIT_INSTRUCTIONS)

    exit_code = print_test_summary(stats, TEST_CASES)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
