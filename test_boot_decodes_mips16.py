from simulator import AliMipsSimulator
from unicorn import *
from unicorn.mips_const import *
from mips16_decoder import MIPS16Decoder
import sys

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
    }

    stats = {
        "pass": 0,
        "fail": 0,
        "checked": set() # Avoid double counting if loop hits same addr
    }
    
    # We want to run enough to hit our test cases. 
    LIMIT_INSTRUCTIONS = 20000000 
    
    print(f"Running auto-test with {len(TEST_CASES)} test cases...")
    print("-" * 80)
    print(f"{'Status':<8} {'Address':<12} {'Hex':<20} {'Disassembly'}")
    print("-" * 80)

    def hook_code(uc, address, size, user_data):
        if address in TEST_CASES and address not in stats['checked']:
            stats['checked'].add(address)
            
            # Get Context
            instrs = sim.get_instructions_around_pc(address, before=5, after=5)
            
            for i in instrs:
                i_addr = i['address']
                
                # Default formatting
                hex_str = f"{i['bytes']:<11}"
                asm_str = f"{i['mnemonic']:<8} {i['operands']}"
                addr_str = f"0x{i_addr:08X}"
                
                # Check if this specific instruction is a test case
                if i_addr in TEST_CASES:
                    expected = TEST_CASES[i_addr]
                    
                    # Validate
                    act_hex = i['bytes'].replace(' ', '').strip() # remove spaces for comparison if needed? 
                    # Actually previous logic used spaced hex. Let's stick to what we had or robustify.
                    # The simulator returns 'XX XX' or 'XX XX XX XX'.
                    act_hex_spaced = i['bytes'].strip()
                    exp_hex_spaced = expected['hex'].strip()
                    
                    act_asm_norm = ' '.join(asm_str.split())
                    exp_asm_norm = ' '.join(expected['asm'].split())
                    
                    hex_match = (act_hex_spaced == exp_hex_spaced)
                    asm_match = (act_asm_norm == exp_asm_norm)
                    
                    status = "PASS" if (hex_match and asm_match) else "FAIL"
                    color_start = "\033[92m" if status == "PASS" else "\033[91m"
                    color_end = "\033[0m"
                    
                    print(f"{color_start}{status:<8}{color_end} {addr_str}   {hex_str:<20} {asm_str}")
                    
                    if not hex_match:
                         print(f"         Expected Hex: {exp_hex_spaced}")
                    if not asm_match:
                         print(f"         Expected Asm: {expected['asm']}")

                    if status == "PASS":
                        stats['pass'] += 1
                    else:
                        stats['fail'] += 1
                        
                else:
                    # Just print info
                    print(f"{'INFO':<8} {addr_str}   {hex_str:<20} {asm_str}")

            print("-" * 80)

    sim.mu.hook_add(UC_HOOK_CODE, hook_code)

    # Run loop
    end_addr = sim.base_addr + sim.rom_size
    cur_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    steps = 0
    
    while cur_pc < end_addr and steps < LIMIT_INSTRUCTIONS:
        if len(stats['checked']) >= len(TEST_CASES):
            break
            
        sim.apply_manual_fixes()
        sim.invalidate_jit(cur_pc)
        try:
            # Run in small bursts
            sim.mu.emu_start(cur_pc, end_addr, count=1000) 
        except UcError:
            pass 
        
        cur_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
        steps += 1000

    print("-" * 80)
    print(f"Test Finished. PASS: {stats['pass']}, FAIL: {stats['fail']}, Total: {len(TEST_CASES)}")
    if len(stats['checked']) < len(TEST_CASES):
        print(f"Warning: Only checked {len(stats['checked'])}/{len(TEST_CASES)} cases. execution constraints?")

if __name__ == "__main__":
    main()
