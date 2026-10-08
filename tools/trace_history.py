import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
from simulator import AliMipsSimulator
sim = AliMipsSimulator()
sim.setSPIDump(False)
sim.setI2CDump(False)
history = []
def hook(uc, addr, size, user_data):
    if len(history) >= 200:
        history.pop(0)
    history.append((addr, size))

sim.mu.hook_add(2, hook)

try:
    sim.loadFile("dump_maciej.bin")
    sim.run(max_instructions=5000000)
except Exception as e:
    pass

print("--- History ---")
import mips16_decoder
for addr, size in history[-30:]:
    opcode = sim.mu.mem_read(addr, size)
    d = mips16_decoder.MIPS16Decoder.decode(opcode, addr)
    print(f"{addr:08X}: {opcode.hex()} {d[0]} {d[1]}")
print(f"s1 is {sim.mu.reg_read(sim.UC_MIPS_REG_S1):08X}")
