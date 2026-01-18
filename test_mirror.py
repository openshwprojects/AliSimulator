from simulator import AliMipsSimulator
from unicorn.mips_const import *
import struct

def assemble_write(addr, val):
    # Returns bytes for:
    # LUI t0, hi(addr)
    # ORI t0, t0, lo(addr)
    # LUI t1, hi(val)
    # ORI t1, t1, lo(val)
    # SW t1, 0(t0)
    
    code = b''
    
    # t0 = addr
    hi_addr = (addr >> 16) & 0xFFFF
    lo_addr = addr & 0xFFFF
    code += struct.pack('<I', 0x3C080000 | hi_addr) # LUI t0, hi
    if lo_addr:
        code += struct.pack('<I', 0x35080000 | lo_addr) # ORI t0, t0, lo
        
    # t1 = val
    hi_val = (val >> 16) & 0xFFFF
    lo_val = val & 0xFFFF
    code += struct.pack('<I', 0x3C090000 | hi_val) # LUI t1, hi
    if lo_val:
        code += struct.pack('<I', 0x35290000 | lo_val) # ORI t1, t1, lo
        
    # SW t1, 0(t0)
    code += struct.pack('<I', 0xAD090000)
    
    return code

print("Initializing simulator...")
sim = AliMipsSimulator(ram_size=0x100000)

# Construct test code
# 1. Write 0xDEADBEEF to 0x80001000
code1 = assemble_write(0x80001000, 0xDEADBEEF)

# 2. Write 0xCAFEBABE to 0xA0002000
code2 = assemble_write(0xA0002000, 0xCAFEBABE)

# Sync test code
full_code = code1 + code2 
# Add a "wait" or loop at the end to stop cleanly if needed, but we'll step.
# NOPs
full_code += b'\x00\x00\x00\x00' * 4

# Write code to reset vector 0xAFC00000
sim.mu.mem_write(0xAFC00000, full_code)
# Also mirror at 0x0FC00000 (handled by loadFile implicitly but we did manual write)
try:
    sim.mu.mem_write(0x0FC00000, full_code)
except: pass

print("Running code...")
# Run enough steps to cover the writes.
# Each block is ~5 instructions. 2 blocks = 10. + some slack.
try:
    sim.run(max_instructions=20)
except Exception as e:
    print(f"Run finished: {e}")

print("\nVerifying KSEG0 -> KSEG1 sync")
val = sim.mu.mem_read(0xA0001000, 4)
print(f"Read from 0xA0001000: {val.hex()}")
if val == b'\xef\xbe\xad\xde':
    print("PASS")
else:
    print("FAIL")

print("\nVerifying KSEG1 -> KSEG0 sync")
val2 = sim.mu.mem_read(0x80002000, 4)
print(f"Read from 0x80002000: {val2.hex()}")
if val2 == b'\xbe\xba\xfe\xca':
    print("PASS")
else:
    print("FAIL")
