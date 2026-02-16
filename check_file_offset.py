"""Check bytes in dump.bin at offset corresponding to 0x81E87A76."""
import sys

# Flash base 0xAFC00000
# RAM base 0x81E00000
# The boot copy src -> dst mapping needs to be known.
# Boot loop copies from 0xAFC01000 (approx) to 0x81E00000.
# Let's assume linear mapping: RAM_Addr - 0x81E00000 + 0xOffset = Flash_Addr.
# However, bootloader might copy segments.

# Let's search for the byte sequence 4d 1d 00 65 in the whole file.
target = b'\x4d\x1d\x00\x65'

with open("dump.bin", "rb") as f:
    data = f.read()

count = 0
start = 0
while True:
    idx = data.find(target, start)
    if idx == -1:
        break
    print(f"Found sequence at file offset 0x{idx:X}")
    # Calculate potential RAM address if loaded at 0x81E00000
    # RAM = 0x81E00000 + (idx - ???)
    # If file starts at 0xAFC00000.
    # What offset maps to 0x81E87A76?
    # 0x81E87A76 - 0x81E00000 = 0x87A76.
    # Check if idx is close to 0x87A76 (plus maybe 0x1000 header?)
    
    start = idx + 1
    count += 1

if count == 0:
    print("Sequence NOT found in dump.bin")
