"""Disassemble the valid code found at 0x81E87A7A."""
from mips16_decoder import MIPS16Decoder

# From the previous step output:
# Checking crash RA 0x81E87A7A:
#   30f0549880f039c230f0749880f059a3

code_hex = "30f0549880f039c230f0749880f059a3"
code_bytes = bytes.fromhex(code_hex)

start_addr = 0x81E87A7A

print(f"Disassembling code at 0x{start_addr:08X}:")

for i in range(0, len(code_bytes), 2):
    addr = start_addr + i
    chunk = code_bytes[i:i+2]
    # MIPS16 decoder handles 2-byte chunks
    # Note: Decoder likely doesn't handle extend automatically in this loop,
    # but let's see what it says.
    mnemonic, operands = MIPS16Decoder.decode(chunk)
    print(f"0x{addr:08X}: {chunk.hex()}  {mnemonic} {operands}")
