"""Disassemble code BEFORE the crash RA 0x81E87A7A to find the call."""
import sys
sys.stdout.reconfigure(line_buffering=True)
from simulator import AliMipsSimulator

sim = AliMipsSimulator(log_handler=lambda msg: None)
sim.loadFile("dump.bin")
# Run enough to populate RAM
sim.run(max_instructions=200_000)

start = 0x81E87A60
end = 0x81E87A80

print(f"Disassembly around RA=0x81E87A7B (valid RAM content):")
code = sim.mu.mem_read(start, end - start)

for i in range(0, len(code), 2):
    addr = start + i
    chunk = code[i:i+2]
    val = int.from_bytes(chunk, byteorder='little')
    print(f"0x{addr:08X}: {chunk.hex()} (0x{val:04X})")
