import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))   # the simulator's modules
from simulator import AliMipsSimulator
import unicorn.mips_const as mips
from unicorn import UC_HOOK_CODE
history = []

sim = AliMipsSimulator(log_handler=lambda x: None)
sim.setSPIDump(False)
sim.setI2CDump(False)

def hook(uc, addr, size, user_data):
    if len(history) >= 200:
        history.pop(0)
    
    try:
        s0 = uc.reg_read(mips.UC_MIPS_REG_S0)
        a0 = uc.reg_read(mips.UC_MIPS_REG_A0)
        a1 = uc.reg_read(mips.UC_MIPS_REG_A1)
        sp = uc.reg_read(mips.UC_MIPS_REG_SP)
        s1 = uc.reg_read(mips.UC_MIPS_REG_S1)
        v0 = uc.reg_read(mips.UC_MIPS_REG_V0)
        v1 = uc.reg_read(mips.UC_MIPS_REG_V1)
        t8 = uc.reg_read(mips.UC_MIPS_REG_T8)
        a3 = uc.reg_read(mips.UC_MIPS_REG_A3)
        a2 = uc.reg_read(mips.UC_MIPS_REG_A2)
        ra = uc.reg_read(mips.UC_MIPS_REG_RA)
    except:
        s0 = a0 = a1 = sp = s1 = v0 = v1 = t8 = a3 = a2 = ra = 0

    history.append((addr, size, s0, a0, a1, sp, s1, v0, v1, t8, a3, a2, ra))

sim.mu.hook_add(UC_HOOK_CODE, hook)

try:
    sim.loadFile("dump_maciej.bin")
    sim.run(max_instructions=5000000)
except Exception as e:
    pass

import mips16_decoder
import io

out = io.StringIO()
for addr, size, s0, a0, a1, sp, s1, v0, v1, t8, a3, a2, ra in history[-200:]:
    try:
        opcode = sim.mu.mem_read(addr, size)
        d = mips16_decoder.MIPS16Decoder.decode(opcode, addr)
        out.write(f"{addr:08X}: {opcode.hex():8s} {d[0]:6s} {d[1]:20s} [s0={s0:08X} s1={s1:08X} a0={a0:08X} a1={a1:08X} a2={a2:08X} a3={a3:08X} v0={v0:08X} v1={v1:08X} t8={t8:08X} sp={sp:08X} ra={ra:08X}]\n")
    except:
        pass

with open('w:/GIT/AliSimulator/trace_output.txt', 'w', encoding='utf-8') as f:
    f.write(out.getvalue())
