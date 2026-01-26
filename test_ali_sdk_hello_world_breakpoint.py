from simulator import AliMipsSimulator
import sys
import unicorn

# ANSI colors
GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

BP1 = 0xAFC00024
BP2 = 0xAFC00040

def test_run_approach():
    print(f"\n{GREEN}=== Testing Approach 1: sim.run() ==={RESET}")
    sim = AliMipsSimulator()
    sim.loadFile("ali_sdk.bin")
    
    print(f"Setting breakpoints at {hex(BP1)} and {hex(BP2)}")
    sim.addBreakpoint(BP1)
    sim.addBreakpoint(BP2)
    
    # First run until BP1
    print("Running until first breakpoint...")
    sim.run()
    pc = sim.mu.reg_read(unicorn.mips_const.UC_MIPS_REG_PC)
    if pc == BP1:
        print(f"SUCCESS: Hit BP1 at {hex(pc)}")
    else:
        print(f"FAILURE: Expected {hex(BP1)}, but stopped at {hex(pc)}")
        return False
        
    # Continue until BP2
    print("Continuing until second breakpoint...")
    sim.run()
    pc = sim.mu.reg_read(unicorn.mips_const.UC_MIPS_REG_PC)
    if pc == BP2:
        print(f"SUCCESS: Hit BP2 at {hex(pc)}")
    else:
        print(f"FAILURE: Expected {hex(BP2)}, but stopped at {hex(pc)}")
        return False
        
    return True

def test_step_approach():
    print(f"\n{GREEN}=== Testing Approach 2: Manual sim.step() ==={RESET}")
    sim = AliMipsSimulator()
    sim.loadFile("ali_sdk.bin")
    
    # Add breakpoints just to ensure they don't block manual stepping
    sim.addBreakpoint(BP1)
    sim.addBreakpoint(BP2)
    
    # 1. Step until BP1
    print(f"Stepping manually until {hex(BP1)}...")
    max_steps = 100
    steps = 0
    hit_bp1 = False
    while steps < max_steps:
        sim.step()
        steps += 1
        pc = sim.mu.reg_read(unicorn.mips_const.UC_MIPS_REG_PC)
        if pc == BP1:
            print(f"SUCCESS: Reached PC {hex(pc)} in {steps} steps")
            hit_bp1 = True
            break
            
    if not hit_bp1:
        print(f"FAILURE: Did not reach {hex(BP1)} within {max_steps} steps")
        return False

    # 2. Step until BP2
    print(f"Stepping manually until {hex(BP2)}...")
    hit_bp2 = False
    start_steps = steps
    while steps < max_steps:
        sim.step()
        steps += 1
        pc = sim.mu.reg_read(unicorn.mips_const.UC_MIPS_REG_PC)
        if pc == BP2:
            print(f"SUCCESS: Reached PC {hex(pc)} in {steps - start_steps} more steps (Total: {steps})")
            hit_bp2 = True
            break
            
    if not hit_bp2:
        print(f"FAILURE: Did not reach {hex(BP2)} within {max_steps} steps")
        return False
        
    return True

def main():
    success_run = test_run_approach()
    success_step = test_step_approach()
    
    if success_run and success_step:
        print(f"\n{GREEN}ALL APPROACHES PASSED{RESET}")
    else:
        print(f"\n{RED}SOME APPROACHES FAILED{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
