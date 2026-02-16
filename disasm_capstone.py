"""Disassemble crash site using Capstone to verify opcode."""
import sys

try:
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS16
except ImportError:
    print("Capstone not found.")
    print(f"sys.path: {sys.path}")
    sys.exit(1)

# Bytes from previous step (0x81E87A70 onwards)
# 0x81E87A76: 4d 1d 00 65 (LE) -> 0x1D4D 0x6500
code = b'\x1f\x22\x01\x6c\x43\x1b\x4d\x1d\x00\x65\x30\xf0\x54\x98'
addr = 0x81E87A70

print(f"Disassembling {code.hex()} at 0x{addr:08X} (MIPS16 LE):")

try:
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN + CS_MODE_MIPS16)
    for i in md.disasm(code, addr):
        print(f"0x{i.address:08X}: {i.mnemonic} {i.op_str}")
except Exception as e:
    print(f"Disassembly error: {e}")
