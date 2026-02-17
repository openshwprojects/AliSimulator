"""
Reproduce the crash with external 100k batching (like run_dump_to_uart),
then trace the last batch that leads to the NULL jump.
"""
import sys, struct
sys.stdout.reconfigure(line_buffering=True)
from simulator import AliMipsSimulator, ISAMode
from unicorn.mips_const import *

sim = AliMipsSimulator(log_handler=lambda msg: None)
sim.setUartHandler(lambda c: None)
sim.loadFile("dump.bin")

BATCH = 100_000

# Run first 6 batches without trace (matches run_dump_to_uart.py)
for i in range(6):
    target = sim.instruction_count + BATCH
    sim.run(max_instructions=target)
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    print(f"Batch {i+1}: step={sim.instruction_count:,} PC=0x{pc:08X}")
    if (pc & ~1) == 0:
        print("CRASH already!")
        sys.exit(1)

# Now enable trace for the LAST batch (batch 7, where crash happens)
trace = []
def log_trace(msg):
    trace.append(msg)

sim.trace_instructions = True
sim.log_callback = log_trace

print(f"\nRunning batch 7 with trace (from step {sim.instruction_count:,}, PC=0x{pc:08X})...")
target = sim.instruction_count + BATCH
sim.run(max_instructions=target)
pc = sim.mu.reg_read(UC_MIPS_REG_PC)
ra = sim.mu.reg_read(UC_MIPS_REG_RA)
sp = sim.mu.reg_read(UC_MIPS_REG_SP)

print(f"\nFinal: step={sim.instruction_count:,} PC=0x{pc:08X} RA=0x{ra:08X} SP=0x{sp:08X}")

# Show last 80 trace lines (instruction trace leading to the crash)
n = min(80, len(trace))
print(f"\n--- Last {n} trace lines (of {len(trace)}) ---")
for line in trace[-n:]:
    print(line)

# Registers
print("\n--- Registers ---")
for name, reg in [('V0', UC_MIPS_REG_V0), ('V1', UC_MIPS_REG_V1),
                  ('A0', UC_MIPS_REG_A0), ('A1', UC_MIPS_REG_A1),
                  ('A2', UC_MIPS_REG_A2), ('A3', UC_MIPS_REG_A3),
                  ('T0', UC_MIPS_REG_T0), ('T1', UC_MIPS_REG_T1),
                  ('T8', UC_MIPS_REG_T8), ('T9', UC_MIPS_REG_T9),
                  ('S0', UC_MIPS_REG_S0), ('S1', UC_MIPS_REG_S1),
                  ('SP', UC_MIPS_REG_SP), ('FP', UC_MIPS_REG_FP),
                  ('RA', UC_MIPS_REG_RA), ('GP', UC_MIPS_REG_GP)]:
    print(f"  {name} = 0x{sim.mu.reg_read(reg):08X}")

# Stack walk
print("\n--- Stack walk ---")
try:
    for offset in range(0, 0x100, 4):
        addr = sp + offset
        val = struct.unpack('<I', bytes(sim.mu.mem_read(addr, 4)))[0]
        if (0x81E80000 <= val <= 0x81F00000) or (0xAFC00000 <= val <= 0xB0000000):
            print(f"  SP+0x{offset:03X} (0x{addr:08X}): 0x{val:08X}")
except:
    pass
