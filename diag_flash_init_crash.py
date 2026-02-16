"""Trace the new crash — step from 599100."""
import sys
sys.stdout.reconfigure(line_buffering=True)
from simulator import AliMipsSimulator
from unicorn.mips_const import *

trace = []
sim = AliMipsSimulator(log_handler=lambda msg: None)
sim.setUartHandler(lambda c: sys.stdout.write(c))
sim.loadFile("dump.bin")

# Run to just before crash
sim.run(max_instructions=599_100)
pc = sim.mu.reg_read(UC_MIPS_REG_PC)
print(f"\nAt step {sim.instruction_count}: PC=0x{pc:08X}")

# Enable tracing
sim.trace_instructions = True
sim.log_callback = lambda msg: trace.append(msg)

sim.run(max_instructions=600_000)

pc = sim.mu.reg_read(UC_MIPS_REG_PC)
ra = sim.mu.reg_read(UC_MIPS_REG_RA)
sp = sim.mu.reg_read(UC_MIPS_REG_SP)
v0 = sim.mu.reg_read(UC_MIPS_REG_V0)
print(f"\nFinal: PC=0x{pc:08X}, RA=0x{ra:08X}, SP=0x{sp:08X}, V0=0x{v0:08X}")
print(f"Step={sim.instruction_count}")

print(f"\n--- Last 60 trace lines ---")
for line in trace[-60:]:
    print(f"  {line}")
