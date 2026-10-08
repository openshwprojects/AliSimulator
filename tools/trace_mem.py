import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
from simulator import AliMipsSimulator
import struct
from unicorn import UC_HOOK_MEM_WRITE
import unicorn.mips_const as mips

sim = AliMipsSimulator(log_handler=lambda x: None)
sim.setSPIDump(False)
sim.setI2CDump(False)

write_history = []

def hook(uc, access, addr, size, value, user_data):
    if addr == 0x81E948EC:
        pc = uc.reg_read(mips.UC_MIPS_REG_PC)
        write_history.append((pc, value))
        
sim.mu.hook_add(UC_HOOK_MEM_WRITE, hook)

try:
    sim.loadFile("dump_maciej.bin")
    sim.run(max_instructions=5000000)
except Exception as e:
    pass

print("Writes to 81E948EC:")
for pc, val in write_history:
    print(f"PC:{pc:08X} val:{val:08X}")
val = struct.unpack("<I", sim.mu.mem_read(0x81E948EC, 4))[0]
print(f"Final memory: {val:08X}")
