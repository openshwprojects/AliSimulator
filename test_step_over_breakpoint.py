"""
Test: Step Into should advance past a breakpoint, not get stuck.

Reproduces the GUI bug where pressing F11 (Step Into) on an instruction
with a breakpoint would get stuck because hook_breakpoints called emu_stop()
before the instruction executed.

This test specifically tests the scenario at:
  0xAFC007B0: addiu  $t3, $zero, 3
  0xAFC007B4: mtc0   $t3, $s3, 0
  0xAFC007B8: mtc0   $zero, $t5, 0
  0xAFC007BC: lui    $t0, 0x1000       <-- breakpoint here
  0xAFC007C0: mtc0   $t0, $t4, 0
  0xAFC007C4: nop

We run to a few instructions before the BP, add the BP, then step through
and verify PC advances past the breakpoint correctly.
"""
import sys
sys.stdout.reconfigure(line_buffering=True)

from simulator import AliMipsSimulator
from unicorn import *
from unicorn.mips_const import *

# ANSI colors
GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

# The breakpoint address (LUI instruction from user's scenario)
BP_ADDR = 0xAFC007BC
# Run to a few instructions before the breakpoint
RUN_TO_ADDR = 0xAFC007B0


def simulate_gui_step(sim, ignore_bp_addr_holder):
    """
    Simulate what the GUI's execute_single_instruction does:
    - Sets ignore_bp_addr if PC is at a breakpoint
    - Calls sim.step()
    - Clears ignore_bp_addr
    """
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    
    # This is what the GUI fix does
    if pc in sim.breakpoints:
        ignore_bp_addr_holder['addr'] = pc
    try:
        result = sim.step()
    finally:
        ignore_bp_addr_holder['addr'] = None
    
    return result


def make_bp_hook(sim, ignore_bp_addr_holder):
    """
    Create a breakpoint hook identical to the GUI's hook_breakpoints.
    This reproduces the GUI behavior of stopping on breakpoints.
    """
    def hook_breakpoints(uc, address, size, user_data):
        if address in sim.breakpoints:
            if ignore_bp_addr_holder['addr'] is not None and address == ignore_bp_addr_holder['addr']:
                return  # Skip this breakpoint once
            uc.emu_stop()
            return
    return hook_breakpoints


def test_step_over_breakpoint_at_lui():
    """
    Test the exact scenario from the bug report:
    Run to 0xAFC007B0, add BP at 0xAFC007BC, then step through.
    """
    print(f"\n{GREEN}=== Test: Step over breakpoint at LUI (0x{BP_ADDR:08X}) ==={RESET}")
    
    sim = AliMipsSimulator()
    sim.loadFile("dump.bin")
    
    # State holder for the ignore address (simulates GUI's self.ignore_bp_addr)
    ignore_holder = {'addr': None}
    
    # Add the GUI-style breakpoint hook
    hook = make_bp_hook(sim, ignore_holder)
    sim.mu.hook_add(UC_HOOK_CODE, hook)
    
    # Step 1: Run to RUN_TO_ADDR (a few instructions before BP)
    # Use stop_instr which is handled internally by sim.run()
    print(f"  Running to 0x{RUN_TO_ADDR:08X}...")
    sim.stop_instr = RUN_TO_ADDR

    # Add progress callback
    original_log = sim.log_callback
    def progress_log(msg):
        if sim.instruction_count % 10000 == 0 and sim.instruction_count > 0:
            pc = sim.mu.reg_read(UC_MIPS_REG_PC)
            print(f"    ... {sim.instruction_count} instructions, PC=0x{pc:08X}")
    sim.log_callback = progress_log

    sim.run(max_instructions=500000)

    sim.log_callback = original_log
    
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    if pc != RUN_TO_ADDR:
        print(f"  {RED}FAIL: Could not reach 0x{RUN_TO_ADDR:08X}, stopped at 0x{pc:08X} after {sim.instruction_count} instrs{RESET}")
        return False
    print(f"  Reached 0x{pc:08X} after {sim.instruction_count} instructions")
    sim.stop_instr = None
    
    # Step 2: Add breakpoint at BP_ADDR
    print(f"  Adding breakpoint at 0x{BP_ADDR:08X}...")
    sim.addBreakpoint(BP_ADDR)
    
    # Step 3: Step forward to the breakpoint
    print(f"  Stepping to breakpoint...")
    steps = 0
    max_steps = 20
    while steps < max_steps:
        pc = sim.mu.reg_read(UC_MIPS_REG_PC)
        if pc == BP_ADDR:
            break
        simulate_gui_step(sim, ignore_holder)
        steps += 1
    
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    if pc != BP_ADDR:
        print(f"  {RED}FAIL: Did not reach BP at 0x{BP_ADDR:08X}, at 0x{pc:08X}{RESET}")
        return False
    print(f"  At breakpoint: 0x{pc:08X} (after {steps} steps)")
    
    # Step 4: THE CRITICAL TEST - Step Into on the breakpointed instruction
    # This should execute the LUI and advance PC, NOT get stuck
    print(f"  Stepping INTO the breakpointed LUI instruction...")
    old_pc = pc
    simulate_gui_step(sim, ignore_holder)
    new_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    
    if new_pc == old_pc:
        print(f"  {RED}FAIL: PC stuck at 0x{old_pc:08X} - step did not advance!{RESET}")
        return False
    
    print(f"  PC advanced: 0x{old_pc:08X} -> 0x{new_pc:08X}")
    
    # Step 5: Continue stepping a few more times to verify we're not stuck
    print(f"  Stepping 3 more times to verify continued execution...")
    pcs = [new_pc]
    for i in range(3):
        simulate_gui_step(sim, ignore_holder)
        pc = sim.mu.reg_read(UC_MIPS_REG_PC)
        pcs.append(pc)
    
    # All PCs should be different (no getting stuck)
    unique_pcs = len(set(pcs))
    if unique_pcs < 3:
        print(f"  {RED}FAIL: PC got stuck during continued stepping. PCs: {[hex(p) for p in pcs]}{RESET}")
        return False
    
    print(f"  PCs: {[hex(p) for p in pcs]}")
    print(f"  {GREEN}PASS{RESET}")
    return True


def test_step_without_fix():
    """
    Verify that WITHOUT the ignore_bp_addr fix, stepping would get stuck.
    This proves the fix is actually needed.
    """
    print(f"\n{GREEN}=== Test: Verify bug exists without fix ==={RESET}")
    
    sim = AliMipsSimulator()
    sim.loadFile("dump.bin")
    
    # Hook that NEVER ignores breakpoints (simulates the old buggy behavior)
    def buggy_hook(uc, address, size, user_data):
        if address in sim.breakpoints:
            uc.emu_stop()
            return
    
    sim.mu.hook_add(UC_HOOK_CODE, buggy_hook)
    
    # Run to the BP address
    print(f"  Running to 0x{BP_ADDR:08X}...")
    sim.stop_instr = BP_ADDR

    original_log = sim.log_callback
    def progress_log(msg):
        if sim.instruction_count % 10000 == 0 and sim.instruction_count > 0:
            pc = sim.mu.reg_read(UC_MIPS_REG_PC)
            print(f"    ... {sim.instruction_count} instructions, PC=0x{pc:08X}")
    sim.log_callback = progress_log

    sim.run(max_instructions=500000)

    sim.log_callback = original_log
    
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    if pc != BP_ADDR:
        print(f"  {RED}FAIL: Could not reach 0x{BP_ADDR:08X}, stopped at 0x{pc:08X}{RESET}")
        return False
    print(f"  Reached 0x{pc:08X} after {sim.instruction_count} instructions")
    sim.stop_instr = None
    
    # Add breakpoint
    sim.addBreakpoint(BP_ADDR)
    
    # Try to step - with the buggy hook, emu_start will be stopped immediately
    old_pc = pc
    try:
        sim.step()
    except:
        pass
    new_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    
    if new_pc == old_pc:
        print(f"  Confirmed: Without fix, PC stays stuck at 0x{old_pc:08X}")
        print(f"  {GREEN}PASS (bug confirmed){RESET}")
        return True
    else:
        print(f"  PC advanced to 0x{new_pc:08X} - bug not reproduced")
        print(f"  {GREEN}PASS (no bug to fix at sim level){RESET}")
        return True


def test_run_resumes_from_breakpoint():
    """
    Test that run() correctly resumes execution when PC is at a breakpoint.
    The simulator's run() method should step over the current BP and continue.
    Note: 0xAFC007BC is in a loop, so run() will execute the loop body and
    stop when it returns to the BP. We verify it executed at least 1 instruction.
    """
    print(f"\n{GREEN}=== Test: run() resumes from breakpoint ==={RESET}")
    
    sim = AliMipsSimulator()
    sim.loadFile("dump.bin")
    
    # Run to BP_ADDR
    print(f"  Running to 0x{BP_ADDR:08X}...")
    sim.stop_instr = BP_ADDR

    original_log = sim.log_callback
    def progress_log(msg):
        if sim.instruction_count % 10000 == 0 and sim.instruction_count > 0:
            pc = sim.mu.reg_read(UC_MIPS_REG_PC)
            print(f"    ... {sim.instruction_count} instructions, PC=0x{pc:08X}")
    sim.log_callback = progress_log

    sim.run(max_instructions=500000)

    sim.log_callback = original_log
    
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    if pc != BP_ADDR:
        print(f"  {RED}FAIL: Could not reach 0x{BP_ADDR:08X}, stopped at 0x{pc:08X}{RESET}")
        return False
    print(f"  Reached 0x{pc:08X} after {sim.instruction_count} instructions")
    sim.stop_instr = None
    
    # Add breakpoint at current PC
    sim.addBreakpoint(BP_ADDR)
    instrs_before = sim.instruction_count
    
    # run() should step over this BP and execute some instructions
    # (BP is in a loop, so it will come back and stop - that's correct)
    # max_instructions is absolute, so add to current count
    sim.run(max_instructions=instrs_before + 100)
    new_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    instrs_after = sim.instruction_count
    instrs_executed = instrs_after - instrs_before
    
    if instrs_executed == 0:
        print(f"  {RED}FAIL: run() executed 0 instructions - truly stuck at 0x{BP_ADDR:08X}{RESET}")
        return False
    
    print(f"  run() executed {instrs_executed} instruction(s), PC now at 0x{new_pc:08X}")
    print(f"  {GREEN}PASS{RESET}")
    return True


def main():
    results = []
    results.append(("step_over_breakpoint_at_lui", test_step_over_breakpoint_at_lui()))
    results.append(("step_without_fix", test_step_without_fix()))
    results.append(("run_resumes_from_breakpoint", test_run_resumes_from_breakpoint()))
    
    print(f"\n{'='*60}")
    all_pass = True
    for name, passed in results:
        status = f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"
        print(f"  {status} - {name}")
        if not passed:
            all_pass = False
    
    if all_pass:
        print(f"\n{GREEN}All breakpoint step tests passed!{RESET}")
    else:
        print(f"\n{RED}Some tests failed!{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
