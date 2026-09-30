from simulator import AliMipsSimulator
import mips16_decoder
from unicorn import UC_HOOK_CODE
import unicorn.mips_const as mips

sim = AliMipsSimulator(log_handler=lambda x: None)
sim.setSPIDump(False)
sim.setI2CDump(False)
history = []

def hook(uc, addr, size, user_data):
    if len(history) >= 200:
        history.pop(0)
    
    try:
        s0 = uc.reg_read(mips.UC_MIPS_REG_S0)
        v0 = uc.reg_read(mips.UC_MIPS_REG_V0)
        a0 = uc.reg_read(mips.UC_MIPS_REG_A0)
        a1 = uc.reg_read(mips.UC_MIPS_REG_A1)
    except:
        s0, v0, a0, a1 = 0, 0, 0, 0
    history.append((addr, size, s0, v0, a0, a1))

sim.mu.hook_add(UC_HOOK_CODE, hook)

try:
    sim.loadFile("dump_maciej.bin")
    sim.run(max_instructions=5000000)
except Exception as e:
    print(f"Exception: {e}")

for addr, size, s0, v0, a0, a1 in history[-100:]:
    try:
        opcode = sim.mu.mem_read(addr, size)
        d = mips16_decoder.MIPS16Decoder.decode(opcode, addr)
        print(f"{addr:08X}: {opcode.hex():8s} {d[0]:6s} {d[1]:20s} [s0={s0:08X} v0={v0:08X} a0={a0:08X} a1={a1:08X}]")
    except:
        print(f"{addr:08X}: err")
