"""
Probe: Find the Unicorn register ID for CP0 Count by testing different IDs.
"""
import sys
sys.stdout.reconfigure(line_buffering=True)

from unicorn import *
from unicorn.mips_const import *

# Create a minimal MIPS emulator
mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)
mu.mem_map(0x10000, 0x10000)

# Known CP0 reg IDs
print(f"UC_MIPS_REG_CP0_CONFIG3 = {UC_MIPS_REG_CP0_CONFIG3}")
print(f"UC_MIPS_REG_CP0_USERLOCAL = {UC_MIPS_REG_CP0_USERLOCAL}")
print(f"UC_MIPS_REG_CP0_STATUS = {UC_MIPS_REG_CP0_STATUS}")

# Try to find Count by probing register IDs from 100-200
print("\nProbing register IDs 100-200...")
for reg_id in range(100, 200):
    try:
        # Write a unique value
        mu.reg_write(reg_id, 0xDEAD0000 + reg_id)
    except:
        pass

for reg_id in range(100, 200):
    try:
        val = mu.reg_read(reg_id)
        expected = 0xDEAD0000 + reg_id
        if val == expected:
            print(f"  reg_id {reg_id}: 0x{val:08X} (writable)")
        elif val != 0:
            print(f"  reg_id {reg_id}: 0x{val:08X} (read-only or different)")
    except:
        pass

# Now put a mfc0 $v0, $9, 0 instruction at 0x10000 and run it
# After running, check what $v0 got, then try to find which reg_id matches
print("\n--- Testing mfc0 $v0, $9, 0 ---")
# mfc0 $v0, $9, 0 in big-endian: 40 02 48 00
mfc0_insn = bytes([0x40, 0x02, 0x48, 0x00])
nop = b'\x00\x00\x00\x00'
mu.mem_write(0x10000, mfc0_insn + nop)

# Set all v0 to known value first
mu.reg_write(UC_MIPS_REG_V0, 0xBAD0BAD0)

# Try writing known values to candidate reg IDs and check if mfc0 reads them
for candidate in [137, 138, 139, 140, 141, 142, 143, 144, 145]:
    try:
        mu.reg_write(candidate, 0x42424242)
    except:
        pass

# Execute the mfc0
try:
    mu.reg_write(UC_MIPS_REG_PC, 0x10000)
    mu.emu_start(0x10000, 0x10008, count=1)
    v0 = mu.reg_read(UC_MIPS_REG_V0)
    print(f"  After mfc0: V0 = 0x{v0:08X}")
except Exception as e:
    print(f"  Error: {e}")

print("\nDone.")
