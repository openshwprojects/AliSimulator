from simulator import AliMipsSimulator
from unicorn import *
from unicorn.mips_const import *

def main():
    print("Initializing simulator...")
    sim = AliMipsSimulator()
    sim.loadFile("dump.bin")

    check_addr = 0x81e8e170
    check_size = 32

    print(f"Checking memory at {hex(check_addr)} (should be nulls)...")
    try:
        mem_before = sim.mu.mem_read(check_addr, check_size)
        print(f"Bytes: {mem_before.hex()}")
        assert mem_before == b'\x00' * check_size, "Memory was not null initially!"
    except UcError as e:
        print(f"Read failed: {e}")
        return

    print("Initial check passed.")

    stop_addr = 0xafc007f4
    print(f"Running until {hex(stop_addr)}...")
    
    # Custom run loop to handle stop address because sim.run() loops infinitely on stop_instr
    end_addr = sim.base_addr + sim.rom_size
    sim.stop_instr = stop_addr 
    
    cur_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    
    # Safety limit
    max_steps = 1000000
    steps = 0
    
    while cur_pc < end_addr and steps < max_steps:
        sim.apply_manual_fixes()
        sim.invalidate_jit(cur_pc)
        
        if cur_pc == stop_addr:
            print(f"Hit stop address {hex(stop_addr)} in run check.")
            break
            
        try:
            # Run!
            sim.mu.emu_start(cur_pc, end_addr)
        except UcError as e:
            # If we simply stopped, it might not be an error, but usually emu_stop via hook is fine.
            pass
            
        cur_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
        steps += 1
        
        if cur_pc == stop_addr:
             print("Reached stop address.")
             break

    print(f"Stopped at {hex(cur_pc)}")

    print(f"Checking memory at {hex(check_addr)} (should NOT be nulls)...")
    mem_after = sim.mu.mem_read(check_addr, check_size)
    print(f"Bytes: {mem_after.hex()}")
    assert mem_after != b'\x00' * check_size, "Memory is still null!"

    print("SUCCESS: Memory was modified.")

if __name__ == "__main__":
    main()
