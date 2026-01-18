from simulator import AliMipsSimulator
from unicorn import *
from unicorn.mips_const import *
import unittest

class TestBreakpointLogic(unittest.TestCase):
    def setUp(self):
        self.output_log = []
        self.breakpoints = {}
        self.ignore_bp_addr = None
        
        # Initialize simulator with minimal logging
        self.sim = AliMipsSimulator(log_handler=lambda msg: self.output_log.append(msg))
        
        # Load a simple program: 4 NOPs
        # 0x00000000 is NOP (SLL r0, r0, 0)
        code = b'\x00\x00\x00\x00' * 4
        
        # Map memory and write code
        self.sim.mu.mem_write(self.sim.base_addr, code)
        self.sim.mu.reg_write(UC_MIPS_REG_PC, self.sim.base_addr)
        
        # Attach hooks
        self.sim.mu.hook_add(UC_HOOK_CODE, self.hook_breakpoints)

    def hook_breakpoints(self, uc, address, size, user_data):
        if address in self.breakpoints:
            if self.ignore_bp_addr is not None and address == self.ignore_bp_addr:
                # Bypass logic active
                return
            
            # Breakpoint hit -> Force Stop
            uc.emu_stop()

    def step_over_breakpoint(self):
        """Standard bypass logic implementation for test"""
        pc = self.sim.mu.reg_read(UC_MIPS_REG_PC)
        self.ignore_bp_addr = pc
        try:
            self.sim.runStep()
        finally:
            self.ignore_bp_addr = None

    def test_resume_from_breakpoint(self):
        start_pc = self.sim.base_addr
        
        # 1. Set BP at current instruction
        self.breakpoints[start_pc] = "User"
        
        # 2. Verify just running step() stops (simulating the bug/default behavior)
        # Note: runStep() calls emu_start(count=1). If hook calls emu_stop(), it stops immediately.
        # But Unicorn 2.x behavior on stop-in-hook can be tricky. 
        # PC should NOT advance if we stop exactly at the start.
        try:
            self.sim.runStep()
            # If we reached here, did PC move?
            pc_after = self.sim.mu.reg_read(UC_MIPS_REG_PC)
            
            # It's possible runStep() executes 0 instructions if emu_stop is called immediately?
            # Actually, hook_code is called BEFORE instruction.
            # So emu_stop() prevents execution. PC remains start_pc.
            self.assertEqual(pc_after, start_pc, "Without bypass, PC should not advance from breakpoint")
        except UcError:
            pass
            
        # 3. Use bypass logic to step
        self.step_over_breakpoint()
        
        new_pc = self.sim.mu.reg_read(UC_MIPS_REG_PC)
        
        # 4. Verify PC advanced
        self.assertEqual(new_pc, start_pc + 4, "With bypass, PC should advance")

if __name__ == "__main__":
    unittest.main()
