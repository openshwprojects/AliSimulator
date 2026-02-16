"""Check memory content at function start vs crash site."""
import sys
sys.stdout.reconfigure(line_buffering=True)
from simulator import AliMipsSimulator

sim = AliMipsSimulator(log_handler=lambda msg: None)
sim.loadFile("dump.bin")

# Run some instructions to let boot copy happen?
# The disassembly script ran 50000 steps roughly covering boot copy.
# Let's verify if copy happens.
sim.run(max_instructions=200_000)

start_func = 0x81E87268
crash_ra = 0x81E87A7B & ~1 # 0x81E87A7A

print(f"Checking function start 0x{start_func:08X}:")
code = sim.mu.mem_read(start_func, 16)
print(f"  {code.hex()}")

print(f"Checking crash RA 0x{crash_ra:08X}:")
code = sim.mu.mem_read(crash_ra, 16)
print(f"  {code.hex()}")

# Check where the zeros start
print("Scanning for zeros starting from 0x81E87268...")
addr = start_func
zero_start = None
for i in range(0, 0x10000, 2): # scan 64KB
    val = sim.mu.mem_read(addr + i, 2)
    if val == b'\x00\x00':
        if zero_start is None:
            zero_start = addr + i
    else:
        if zero_start is not None:
            # End of a zero block?
            # Or just a single NOP?
            # If block is large > 16 bytes, report it
            if (addr + i) - zero_start > 16:
                 print(f"Zero block: 0x{zero_start:08X} - 0x{addr+i:08X} (len {addr+i-zero_start})")
            zero_start = None

if zero_start is not None:
     print(f"Zero block: 0x{zero_start:08X} - end")
