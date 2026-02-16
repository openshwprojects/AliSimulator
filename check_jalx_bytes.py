"""
Check what's actually at the JALX address
"""

from simulator import AliMipsSimulator
from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN

def main():
    print("Checking bytes at 0x81E8E1B8...")
    
    # Create simulator
    sim = AliMipsSimulator()
    sim.loadFile("dump.bin")
    
    # Read bytes at the JALX address
    address = 0x81E8E1B8
    bytes_at_addr = sim.mu.mem_read(address, 4)
    
    print(f"Bytes at 0x{address:08X}: {' '.join(f'{b:02x}' for b in bytes_at_addr)}")
    
    # Try to disassemble
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    
    for i in md.disasm(bytes_at_addr, address):
        print(f"Capstone says: {i.mnemonic} {i.op_str}")
        
    print()
    print("Expected: jalx 0x81e84280")
    print("Expected bytes: a0 10 7a 74")
    
if __name__ == "__main__":
    main()
