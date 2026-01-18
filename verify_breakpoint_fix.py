from simulator import AliMipsSimulator
from unicorn import *
from unicorn.mips_const import *

class MockGUI:
    def __init__(self):
        self.output_log = []
        self.breakpoints = {}
        self.ignore_bp_addr = None
        self.sim = AliMipsSimulator(log_handler=self.log)
        # Load a simple program: nop; nop; nop; (0x00000000)
        # Base Addr: 0xAFC00000
        code = b'\x00\x00\x00\x00' * 4
        self.sim.mu.mem_write(self.sim.base_addr, code)
        self.sim.mu.reg_write(UC_MIPS_REG_PC, self.sim.base_addr)
        
        self.sim.mu.hook_add(UC_HOOK_CODE, self.hook_breakpoints)
        
    def log(self, msg):
        self.output_log.append(msg)
        # print(msg)

    def hook_breakpoints(self, uc, address, size, user_data):
        if address in self.breakpoints:
            if self.ignore_bp_addr is not None and address == self.ignore_bp_addr:
                # Bypass
                return
            
            # Stop
            # print(f"Hit BP at {hex(address)}")
            uc.emu_stop()

    def step_over_breakpoint(self):
        pc = self.sim.mu.reg_read(UC_MIPS_REG_PC)
        self.ignore_bp_addr = pc
        try:
            self.sim.runStep()
        finally:
            self.ignore_bp_addr = None

def test_resume_from_breakpoint():
    gui = MockGUI()
    start_pc = gui.sim.base_addr
    
    # 1. Set BP at start
    gui.breakpoints[start_pc] = "User"
    
    # 2. Try to run normally (should fail to advance if we didn't use the bypass, but here we test the bypass)
    # If we just called runStep(), the hook would fire and stop us at start_pc (effectively doing nothing or recursing if we weren't careful)
    
    # 3. Use bypass logic
    print(f"Initial PC: {hex(gui.sim.mu.reg_read(UC_MIPS_REG_PC))}")
    gui.step_over_breakpoint()
    
    new_pc = gui.sim.mu.reg_read(UC_MIPS_REG_PC)
    print(f"New PC: {hex(new_pc)}")
    
    if new_pc == start_pc + 4:
        print("SUCCESS: Advanced past breakpoint")
    else:
        print("FAILURE: Did not advance")

if __name__ == "__main__":
    test_resume_from_breakpoint()
