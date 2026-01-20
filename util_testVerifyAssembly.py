"""
Utility functions for verifying assembly instructions in test files.

This module provides common functionality for testing MIPS/MIPS16 disassembly
accuracy by comparing simulator output against expected values.
"""

import sys


def create_verification_hook(sim, test_cases, trigger_address, context, before=15, after=80):
    """
    Create a verification hook function for testing assembly instruction decoding.
    
    Args:
        sim: The AliMipsSimulator instance
        test_cases: Dictionary mapping addresses to expected {'hex': str, 'asm': str}
        trigger_address: Address at which to trigger the verification
        context: Dictionary with 'done' flag to control execution
        before: Number of instructions to show before trigger address (default: 15)
        after: Number of instructions to show after trigger address (default: 80)
    
    Returns:
        A tuple of (hook_function, stats_dict) where:
        - hook_function is the unicorn hook callback
        - stats_dict tracks pass/fail/checked results
    """
    stats = {
        "pass": 0,
        "fail": 0,
        "checked": set()  # Avoid double counting if loop hits same addr
    }
    
    def hook_code(uc, address, size, user_data):
        if address == trigger_address:
            # Stats tracking for this run
            run_stats = {"pass": 0, "fail": 0}
            
            # Get Context - large enough to cover all our test cases
            instrs = sim.get_instructions_around_pc(address, before=before, after=after)
            
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
                
                if i_addr in test_cases:
                    stats['checked'].add(i_addr)
                    expected = test_cases[i_addr]
                    
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
                     if i_addr in test_cases:
                         print(f"         Expected Hex: {test_cases[i_addr]['hex']}")
                         print(f"         Expected Asm: {test_cases[i_addr]['asm']}")

            print("-" * 80)
            
            # We are done after one check
            context["done"] = True
            uc.emu_stop()
    
    return hook_code, stats


def run_until_trigger(sim, context, limit_instructions):
    """
    Run the simulator until the trigger address is hit or the instruction limit is reached.
    
    Args:
        sim: The AliMipsSimulator instance
        context: Dictionary with 'done' flag that will be set by the hook when trigger is hit
        limit_instructions: Maximum number of instruction blocks to execute
    """
    from unicorn import UcError
    from unicorn.mips_const import UC_MIPS_REG_PC
    
    end_addr = sim.base_addr + sim.rom_size
    cur_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    steps = 0
    
    # Run until trigger or limit
    while cur_pc < end_addr and steps < limit_instructions:
        if context.get("done", False):
            break
            
        sim.apply_manual_fixes()
        sim.invalidate_jit(cur_pc)
        try:
            sim.mu.emu_start(cur_pc, end_addr) 
        except UcError:
            pass 
        
        cur_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
        steps += 1  # Rough counting blocks


def print_test_summary(stats, test_cases):
    """
    Print the test summary with pass/fail counts and missing test cases.
    
    Args:
        stats: Dictionary with 'pass', 'fail', and 'checked' keys
        test_cases: Dictionary mapping addresses to expected values
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    print("-" * 80)
    
    # Color the summary based on pass/fail status
    if stats['fail'] == 0 and len(set(test_cases.keys()) - stats['checked']) == 0:
        color = "\033[92m"  # Green for all pass
    else:
        color = "\033[91m"  # Red for any failures
    
    print(f"{color}Test Finished. PASS: {stats['pass']}, FAIL: {stats['fail']}, Total: {len(test_cases)}\033[0m")
    
    missing = set(test_cases.keys()) - stats['checked']
    if missing:
        print("\033[93m" + "MISSING TEST CASES (Not reached in execution window):" + "\033[0m")
        for addr in sorted(missing):
            print(f"\033[93mMISSING  0x{addr:08X}   Expected: {test_cases[addr]['asm']}\033[0m")
    
    if stats['fail'] > 0 or len(missing) > 0:
        return 1
    return 0
