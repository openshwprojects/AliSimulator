"""
Diagnostic: trace the exact NULL jump by running at full speed
to step 666,100 then single-stepping the remaining instructions.
"""
import sys
sys.stdout.reconfigure(line_buffering=True)
from simulator import AliMipsSimulator
from unicorn.mips_const import *

sim = AliMipsSimulator(log_handler=lambda msg: None)
sim.setUartHandler(lambda c: None)
sim.loadFile("dump.bin")

# Phase 1: Run at full speed to just before crash
TARGET = 666_100
print(f"Running {TARGET:,} instructions at full speed...")
sim.run(max_instructions=TARGET)
pc = sim.mu.reg_read(UC_MIPS_REG_PC)
ra = sim.mu.reg_read(UC_MIPS_REG_RA)
sp = sim.mu.reg_read(UC_MIPS_REG_SP)
print(f"After {sim.instruction_count:,} steps: PC=0x{pc:08X} RA=0x{ra:08X} SP=0x{sp:08X}")
print(f"Mode: {sim.isa_mode.value}")
print(f"SPI: INS=0x{sim._spi_ins:02X} FMT=0x{sim._spi_fmt:02X} status=0x{sim._spi_status:02X}")
print(f"SPI passthrough: {sim._spi_is_passthrough()}")
print()

# Phase 2: Single-step with full register dump
print("Single-stepping to crash:")
for i in range(200):
    pc = sim.mu.reg_read(UC_MIPS_REG_PC)
    ra = sim.mu.reg_read(UC_MIPS_REG_RA)
    v0 = sim.mu.reg_read(UC_MIPS_REG_V0)
    v1 = sim.mu.reg_read(UC_MIPS_REG_V1)
    a0 = sim.mu.reg_read(UC_MIPS_REG_A0)
    s0 = sim.mu.reg_read(UC_MIPS_REG_S0)
    s1 = sim.mu.reg_read(UC_MIPS_REG_S1)
    t9 = sim.mu.reg_read(UC_MIPS_REG_T9)
    
    if (pc & ~1) == 0:
        print(f"  #{i}: *** NULL PC! ***")
        print(f"       RA=0x{ra:08X} V0=0x{v0:08X} V1=0x{v1:08X}")
        print(f"       A0=0x{a0:08X} S0=0x{s0:08X} S1=0x{s1:08X} T9=0x{t9:08X}")
        
        # Dump stack
        print(f"\n  Stack around SP=0x{sim.mu.reg_read(UC_MIPS_REG_SP):08X}:")
        sp_val = sim.mu.reg_read(UC_MIPS_REG_SP)
        for off in range(0, 0x40, 4):
            try:
                word = int.from_bytes(sim.mu.mem_read(sp_val + off, 4), 'little')
                marker = " <-- RA" if word == ra else ""
                if 0x81E80000 <= word <= 0x81E90000:
                    marker += " (code)"
                print(f"    SP+0x{off:03X}: 0x{word:08X}{marker}")
            except:
                pass
        break
    
    # Read bytes at PC
    try:
        code_bytes = bytes(sim.mu.mem_read(pc, 4))
        hexstr = ' '.join(f'{b:02x}' for b in code_bytes)
    except:
        hexstr = '???'
    
    print(f"  #{i}: PC=0x{pc:08X} [{hexstr}] V0=0x{v0:08X} V1=0x{v1:08X} RA=0x{ra:08X} mode={sim.isa_mode.value}")
    
    try:
        result = sim.step()
    except Exception as e:
        print(f"  Error: {e}")
        pc2 = sim.mu.reg_read(UC_MIPS_REG_PC)
        ra2 = sim.mu.reg_read(UC_MIPS_REG_RA)
        print(f"  After error: PC=0x{pc2:08X} RA=0x{ra2:08X}")
        break

print("Done")
