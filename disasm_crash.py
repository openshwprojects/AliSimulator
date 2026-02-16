"""Disassemble code around the crash RA 0x81E87A7B (MIPS16)."""
import sys
sys.stdout.reconfigure(line_buffering=True)
from simulator import AliMipsSimulator

sim = AliMipsSimulator(log_handler=lambda msg: None)
sim.loadFile("dump.bin")

# RA = 0x81E87A7B -> 0x81E87A7A (MIPS16)
# Instructions before this address caused the jump
start = 0x81E87A60
end = 0x81E87A80

print(f"Disassembly around RA=0x81E87A7B (0x{start:08X} - 0x{end:08X}):")

# Read bytes
code = sim.mu.mem_read(start, end - start)

# Use existing decoder logic or just hex dump + manual check
# MIPS16 instructions are 2 bytes. using `capstone` or internal logic
# But internal logic is buried. Let's simplpy dump hex and try do disassemble via unicorn/capstone mips16?
# Capstone doesn't support MIPS16 well.
from mips16_decoder import MIPS16Decoder

for i in range(0, len(code), 2):
    addr = start + i
    chunk = code[i:i+2]
    # Check if 4-byte instruction (extend)
    # But for now assume 2 bytes
    mnemonic, operands = MIPS16Decoder.decode(chunk)
    hex_bytes = chunk.hex()
    
    # Check if this instruction looks like a JALR or JAL
    is_trace = "*" if (addr == 0x81E87A7A or addr == 0x81E87A76 or addr == 0x81E87A78) else " "
    print(f"{is_trace} 0x{addr:08X}: {hex_bytes}  {mnemonic} {operands}")
