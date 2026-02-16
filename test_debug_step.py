import sys
sys.stdout.reconfigure(line_buffering=True)

from simulator import AliMipsSimulator
from unicorn.mips_const import *

print("Creating simulator...")
sim = AliMipsSimulator()
print("Loading dump.bin...")
sim.loadFile("dump.bin")
pc = sim.mu.reg_read(UC_MIPS_REG_PC)
print(f"Initial PC: 0x{pc:08X}")

# Try run() - which uses emu_start without count limit
# This should handle the spin loop differently 
print("\nRunning with run() for max 50000 instructions...")
sim.run(max_instructions=50000)
pc = sim.mu.reg_read(UC_MIPS_REG_PC)
print(f"PC after run: 0x{pc:08X}")
print(f"Instructions executed: {sim.instruction_count}")

print("\nDone.")
