"""
Trace the last 50 instructions before the jump-to-0 crash.
ALL stepping, no run().
"""
import sys
sys.stdout.reconfigure(line_buffering=True)

from simulator import AliMipsSimulator
from unicorn.mips_const import *

sim = AliMipsSimulator(log_handler=lambda msg: None)
sim.loadFile("dump.bin")

# Keep a ring buffer of the last 100 steps
history = []
HISTORY_SIZE = 100

print("Stepping (pure step, no run)...")
try:
    for i in range(200000):
        pc = sim.mu.reg_read(UC_MIPS_REG_PC)
        mode = sim.isa_mode.value
        
        result = sim.step()
        new_pc = sim.mu.reg_read(UC_MIPS_REG_PC)
        new_mode = sim.isa_mode.value
        
        history.append({
            'step': i,
            'pc': pc,
            'mode': mode,
            'insn': result.instruction,
            'ops': result.operands,
            'next_pc': new_pc,
            'new_mode': new_mode,
            'mode_switched': result.mode_switched,
            'size': result.instruction_size,
        })
        if len(history) > HISTORY_SIZE:
            history.pop(0)
        
        if i % 20000 == 0:
            print(f"  Step {i}: PC=0x{new_pc:08X}, mode={new_mode}")
        
        if (new_pc & ~1) == 0:
            print(f"\n*** Jump to NULL at step {i}! ***")
            break

except Exception as e:
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    print(f"\n*** Exception at step {i}: {e}")

# Print last 100 entries
print(f"\nLast {len(history)} entries:")
for h in history:
    mode_chg = ""
    if h['mode_switched']:
        mode_chg = f" *** MODE_SWITCH:{h['mode']}->{h['new_mode']} ***"
    elif h['mode'] != h['new_mode']:
        mode_chg = f" (mode:{h['mode']}->{h['new_mode']})"
    
    print(f"  [{h['step']:6d}] 0x{h['pc']:08X} ({h['mode']:6s}): {h['insn']:<10} {h['ops']:<30} -> 0x{h['next_pc']:08X}{mode_chg}")

print("\nRegisters at crash:")
for name, reg in [('v0', UC_MIPS_REG_V0), ('v1', UC_MIPS_REG_V1), 
                   ('a0', UC_MIPS_REG_A0), ('a1', UC_MIPS_REG_A1),
                   ('ra', UC_MIPS_REG_RA), ('sp', UC_MIPS_REG_SP)]:
    print(f"  {name} = 0x{sim.mu.reg_read(reg):08X}")

print("Done.")
