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
        0xafc0049c: {'hex': 'ff ff 00 15', 'asm': 'bnez $t0, 0xafc0049c'},
        0xafc004a0: {'hex': 'ff ff 08 25', 'asm': 'addiu $t0, $t0, -1'},
        0xafc004a4: {'hex': '00 80 08 40', 'asm': 'mfc0 $t0, $s0, 0'},
        0xafc004a8: {'hex': 'f8 ff 09 24', 'asm': 'addiu $t1, $zero, -8'},
        0xafc004ac: {'hex': '24 40 09 01', 'asm': 'and $t0, $t0, $t1'},
        0xafc004b0: {'hex': '03 00 08 35', 'asm': 'ori $t0, $t0, 3'},
        0xafc004b4: {'hex': '00 80 88 40', 'asm': 'mtc0 $t0, $s0, 0'},
        0xafc004b8: {'hex': '07 80 08 40', 'asm': 'mfc0 $t0, $s0, 7'},
        0xafc004bc: {'hex': '30 00 08 35', 'asm': 'ori $t0, $t0, 0x30'},
        0xafc004c0: {'hex': '07 80 88 40', 'asm': 'mtc0 $t0, $s0, 7'},
        0xafc004c4: {'hex': 'c0 af 19 3c', 'asm': 'lui $t9, 0xafc0'},
        0xafc004c8: {'hex': '80 00 39 37', 'asm': 'ori $t9, $t9, 0x80'},
        0xafc004cc: {'hex': '48 00 2f 8f', 'asm': 'lw $t7, 0x48($t9)'},
        0xafc004d0: {'hex': '01 00 18 24', 'asm': 'addiu $t8, $zero, 1'},
        0xafc004d4: {'hex': '07 00 f8 11', 'asm': 'beq $t7, $t8, 0xafc004f4'},
        0xafc004d8: {'hex': '00 00 00 00', 'asm': 'nop'},
        0xafc004dc: {'hex': '02 00 0e 24', 'asm': 'addiu $t6, $zero, 2'},
        0xafc004e0: {'hex': '13 00 ee 11', 'asm': 'beq $t7, $t6, 0xafc00530'},
        0xafc004e4: {'hex': '00 00 00 00', 'asm': 'nop'},
        0xafc004e8: {'hex': '03 00 18 24', 'asm': 'addiu $t8, $zero, 3'},
        0xafc004ec: {'hex': '1f 00 f8 11', 'asm': 'beq $t7, $t8, 0xafc0056c'},
        0xafc004f0: {'hex': '00 00 00 00', 'asm': 'nop'},
        0xafc004f4: {'hex': '00 b8 0a 3c', 'asm': 'lui $t2, 0xb800'},
        0xafc004f8: {'hex': '74 00 48 8d', 'asm': 'lw $t0, 0x74($t2)'},
        0xafc004fc: {'hex': '7f fe 01 24', 'asm': 'addiu $at, $zero, -0x181'},
        0xafc00500: {'hex': '24 40 01 01', 'asm': 'and $t0, $t0, $at'},
        0xafc00504: {'hex': '40 00 01 3c', 'asm': 'lui $at, 0x40'},
        0xafc00508: {'hex': '80 00 21 34', 'asm': 'ori $at, $at, 0x80'},
        0xafc0050c: {'hex': '25 40 01 01', 'asm': 'or $t0, $t0, $at'},
        0xafc00510: {'hex': '8f ff 01 24', 'asm': 'addiu $at, $zero, -0x71'},
        0xafc00514: {'hex': '24 40 01 01', 'asm': 'and $t0, $t0, $at'},
        0xafc00518: {'hex': '20 00 01 3c', 'asm': 'lui $at, 0x20'},
        0xafc0051c: {'hex': '40 00 21 34', 'asm': 'ori $at, $at, 0x40'},
        0xafc00520: {'hex': '25 40 01 01', 'asm': 'or $t0, $t0, $at'},
        0xafc00524: {'hex': '74 00 48 ad', 'asm': 'sw $t0, 0x74($t2)'},
        0xafc00528: {'hex': '6a 01 f0 0b', 'asm': 'j 0xafc005a8'},
        0xafc0052c: {'hex': '00 00 00 00', 'asm': 'nop'},
        0xafc00530: {'hex': '00 b8 0a 3c', 'asm': 'lui $t2, 0xb800'},
        0xafc00534: {'hex': '74 00 48 8d', 'asm': 'lw $t0, 0x74($t2)'},
        0xafc00538: {'hex': '7f fe 01 24', 'asm': 'addiu $at, $zero, -0x181'},
        0xafc0053c: {'hex': '24 40 01 01', 'asm': 'and $t0, $t0, $at'},
        0xafc00540: {'hex': '40 00 01 3c', 'asm': 'lui $at, 0x40'},
        0xafc00544: {'hex': '80 00 21 34', 'asm': 'ori $at, $at, 0x80'},
        0xafc00548: {'hex': '25 40 01 01', 'asm': 'or $t0, $t0, $at'},
        0xafc0054c: {'hex': '8f ff 01 24', 'asm': 'addiu $at, $zero, -0x71'},
        0xafc00550: {'hex': '24 40 01 01', 'asm': 'and $t0, $t0, $at'},
        0xafc00554: {'hex': '20 00 01 3c', 'asm': 'lui $at, 0x20'},
        0xafc00558: {'hex': '40 00 21 34', 'asm': 'ori $at, $at, 0x40'},
        0xafc0055c: {'hex': '25 40 01 01', 'asm': 'or $t0, $t0, $at'},
        0xafc00560: {'hex': '74 00 48 ad', 'asm': 'sw $t0, 0x74($t2)'},
        0xafc00564: {'hex': '6a 01 f0 0b', 'asm': 'j 0xafc005a8'},
        0xafc00568: {'hex': '00 00 00 00', 'asm': 'nop'},
    }

    stats = {
        "pass": 0,
        "fail": 0,
        "checked": set() # Avoid double counting if loop hits same addr
    }
    
    # We want to run enough to hit our test cases. 
    LIMIT_INSTRUCTIONS = 2000
    
    print(f"Running auto-test with {len(TEST_CASES)} test cases...")
    TRIGGER_ADDRESS = 0xafc0049c
    context = {"done": False}
    
    def hook_code(uc, address, size, user_data):
        if address == TRIGGER_ADDRESS:
            # Stats tracking for this run
            run_stats = {"pass": 0, "fail": 0}
            
            # Get Context - large enough to cover all our test cases
            # We want to see from 0xafc00830 and slightly beyond
            instrs = sim.get_instructions_around_pc(address, before=15, after=80)
            
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
