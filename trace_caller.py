from simulator import AliMipsSimulator
import mips16_decoder
from unicorn import UC_HOOK_CODE

sim = AliMipsSimulator(log_handler=lambda x: None)
sim.setSPIDump(False)
sim.setI2CDump(False)

def hook(uc, addr, size, user_data):
    if addr == 0x81E83A98:
        for a in range(0x81E83A80, 0x81E83A9C+2, 2):
            try:
                opcode = sim.mu.mem_read(a, 2)
                d = mips16_decoder.MIPS16Decoder.decode(opcode, a)
                print(f"{a:08X}: {opcode.hex()} {d[0]} {d[1]}")
            except:
                pass
        uc.emu_stop()

sim.mu.hook_add(UC_HOOK_CODE, hook)

try:
    sim.loadFile("dump_maciej.bin")
    sim.run(max_instructions=5000000)
except Exception as e:
    pass
