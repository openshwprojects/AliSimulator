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
    }

    stats = {
        "pass": 0,
        "fail": 0,
        "checked": set() # Avoid double counting if loop hits same addr
    }
    
    # We want to run enough to hit our test cases. 
    LIMIT_INSTRUCTIONS = 20000000 
    
    print(f"Running auto-test with {len(TEST_CASES)} test cases...")
    TRIGGER_ADDRESS = 0x81E84280
    context = {"done": False}
    
    def hook_code(uc, address, size, user_data):
        if address == TRIGGER_ADDRESS:
            # Stats tracking for this run
            run_stats = {"pass": 0, "fail": 0}
            
            # Get Context - large enough to cover all our test cases
            # We want to see from 0x81E84280 down to 0x81E842A2 and slightly beyond
            instrs = sim.get_instructions_around_pc(address, before=15, after=70)
            
            for i in instrs:
                i_addr = i['address']
                
                # Default formatting
                hex_str = f"{i['bytes']:<11}"
                asm_str = f"{i['mnemonic']:<8} {i['operands']}"
                addr_str = f"0x{i_addr:08X}"
                
                # Check if this specific instruction is a test case
                status_str = "INFO"
                color_start = ""
                color_end = ""
                
                if i_addr in TEST_CASES:
                    stats['checked'].add(i_addr)
                    expected = TEST_CASES[i_addr]
                    
                    # Validate
                    act_hex_spaced = i['bytes'].strip()
                    exp_hex_spaced = expected['hex'].strip()
                    
                    act_asm_norm = ' '.join(asm_str.split())
                    exp_asm_norm = ' '.join(expected['asm'].split())
                    
                    hex_match = (act_hex_spaced == exp_hex_spaced)
                    asm_match = (act_asm_norm == exp_asm_norm)
                    
                    if hex_match and asm_match:
                        status_str = "PASS"
                        color_start = "\033[92m"
                        run_stats['pass'] += 1
                        stats['pass'] += 1
                    else:
                        status_str = "FAIL"
                        color_start = "\033[91m"
                        run_stats['fail'] += 1
                        stats['fail'] += 1
                
                color_end = "\033[0m" if status_str != "INFO" else ""
                
                print(f"{color_start}{status_str:<8}{color_end} {addr_str}   {hex_str:<20} {asm_str}")
                
                if status_str == "FAIL":
                     if i_addr in TEST_CASES:
                         print(f"         Expected Hex: {TEST_CASES[i_addr]['hex']}")
                         print(f"         Expected Asm: {TEST_CASES[i_addr]['asm']}")

            print("-" * 80)
            
            # We are done after one check
            context["done"] = True
            uc.emu_stop()

    sim.mu.hook_add(UC_HOOK_CODE, hook_code)

    # Run Loop
    end_addr = sim.base_addr + sim.rom_size
    cur_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    steps = 0
    
    # Run until trigger or limit
    while cur_pc < end_addr and steps < LIMIT_INSTRUCTIONS:
        if context.get("done", False):
            break
            
        sim.apply_manual_fixes()
        sim.invalidate_jit(cur_pc)
        try:
            sim.mu.emu_start(cur_pc, end_addr) 
        except UcError:
            pass 
        
        cur_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
        steps += 1 # Rough counting blocks


    print("-" * 80)
    print(f"Test Finished. PASS: {stats['pass']}, FAIL: {stats['fail']}, Total: {len(TEST_CASES)}")
    
    missing = set(TEST_CASES.keys()) - stats['checked']
    if missing:
        print("\033[93m" + "MISSING TEST CASES (Not reached in execution window):" + "\033[0m")
        for addr in sorted(missing):
            print(f"\033[93mMISSING  0x{addr:08X}   Expected: {TEST_CASES[addr]['asm']}\033[0m")
    
    if stats['fail'] > 0 or len(missing) > 0:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
