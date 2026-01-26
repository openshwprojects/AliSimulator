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
    
    # We don't necessarily NEED to add breakpoints for manual stepping, 
    # but let's see if adding them interferes.
    sim.addBreakpoint(BP1)
    
    print(f"Stepping manually until {hex(BP1)}...")
    
    max_steps = 100
    steps = 0
    hit = False
    
    while steps < max_steps:
        res = sim.step()
        steps += 1
        # Check if current instruction (address about to be executed or just executed?)
        # sim.step() returns result for the instruction AT address.
        # After sim.step(), the PC in mu is already at the NEXT instruction.
        # But res.address is the one we just did.
        
        # In a real debugger, we stop BEFORE executing the instruction at BP.
        # However, our sim.run() stops WHEN _hook_code hits the address.
        
        # Let's check the PC from registers after each step.
        pc = sim.mu.reg_read(unicorn.mips_const.UC_MIPS_REG_PC)
        if pc == BP1:
            print(f"SUCCESS: Reached PC {hex(pc)} in {steps} steps")
            hit = True
            break
            
    if not hit:
        print(f"FAILURE: Did not reach {hex(BP1)} within {max_steps} steps")
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
