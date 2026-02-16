"""
Test JALX execution and mode switching
"""

from simulator import AliMipsSimulator

def main():
    print("Testing JALX execution...")
    
    # Create simulator
    sim = AliMipsSimulator()
    sim.loadFile("dump.bin")
    
    # Set PC to the JALX instruction at 0x81E8E1B8
    from unicorn.mips_const import UC_MIPS_REG_PC
    sim.mu.reg_write(UC_MIPS_REG_PC, 0x81E8E1B8)
    
    print(f"Initial PC: 0x{sim.mu.reg_read(UC_MIPS_REG_PC):08X}")
    print(f"Initial mode: {sim.isa_mode.value}")
    print()
    
    # Execute one step (should execute JALX)
    print("Executing first step (JALX)...")
    result = sim.step()
    
    print(f"\nResult:")
    print(f"  Instruction: {result.instruction} {result.operands}")
    print(f"  Mode before: {result.mode_before}")
    print(f"  Mode after: {result.mode_after}")
    print(f"  Mode switched: {result.mode_switched}")
    print(f"  Next PC: 0x{result.next_pc:08X}")
    print(f"  Current mode: {sim.isa_mode.value}")
    print()
    
    # Execute next step (should be MIPS16)
    print("Executing second step (should be MIPS16)...")
    result2 = sim.step()
    
    print(f"\nResult:")
    print(f"  Instruction: {result2.instruction} {result2.operands}")
    print(f"  Mode before: {result2.mode_before}")
    print(f"  Next PC: 0x{result2.next_pc:08X}")
    
if __name__ == "__main__":
    main()
