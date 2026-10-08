import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
from simulator import AliMipsSimulator
import unicorn.mips_const as mips
from unicorn import UC_HOOK_CODE

sim = AliMipsSimulator(log_handler=lambda x: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
hist = []

last_a0 = 0
def hook(uc, addr, size, user_data):
    global last_a0
    a0 = uc.reg_read(mips.UC_MIPS_REG_A0)
    if a0 != last_a0:
        hist.append((addr, a0))
        last_a0 = a0
        if len(hist) > 1000:
            hist.pop(0)

sim.mu.hook_add(UC_HOOK_CODE, hook)

try:
    sim.loadFile('dump_maciej.bin')
    sim.run()
except Exception as e:
    pass

for pc, a0 in hist[-20:]:
    print(f"PC:{pc:08X} a0:{a0:08X}")
