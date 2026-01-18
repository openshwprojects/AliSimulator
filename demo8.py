

from unicorn import *
from unicorn.mips_const import *
from capstone import *
import os
import sys
import msvcrt

# Configuration
BINARY_FILE = "ali_sdk.bin"
BASE_ADDR = 0xAFC00000
ROM_SIZE = 8 * 1024 * 1024  # 8MB
INSTR_COUNT = 10000000
STOP_INSTR = None  
TRACE_INSTRUCTIONS = False
BREAK_ON_PRINTF = False

# Load binary
print(f"Loading {BINARY_FILE}...")
with open(BINARY_FILE, "rb") as f:
    code = f.read()

# Initialize Unicorn (MIPS32 + Little Endian)
mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)

# Map memory at virtual address (Unicorn doesn't do full MMU translation)
print(f"Mapping memory at {hex(BASE_ADDR)}")
mu.mem_map(BASE_ADDR, ROM_SIZE)
mu.mem_write(BASE_ADDR, code)

# Map the address Unicorn actually fetches from (0xAFC00000 -> 0x0FC00000)
# This is the minimal mirror needed for execution
print(f"Mapping mirror at 0x0FC00000")
mu.mem_map(0x0FC00000, ROM_SIZE)
mu.mem_write(0x0FC00000, code)

# Map RAM - needed for stack and data
# Standard MIPS RAM regions:
# KUSEG: 0x00000000
# KSEG0 (cached): 0x80000000
# KSEG1 (uncached): 0xA0000000
RAM_SIZE = 128 * 1024 * 1024  # 128MB

print(f"Mapping RAM at 0x80000000 (size: {RAM_SIZE // 1024 // 1024}MB)")
mu.mem_map(0x80000000, RAM_SIZE)

print(f"Mapping RAM mirror at 0xA0000000 (size: {RAM_SIZE // 1024 // 1024}MB)")
mu.mem_map(0xA0000000, RAM_SIZE)

# Map KUSEG/Physical RAM base (0x00000000 - 0x08000000) 
# This covers 0x01000000 and 0x02000000 as well.
print(f"Mapping RAM at 0x00000000 (size: {RAM_SIZE // 1024 // 1024}MB)")
mu.mem_map(0x00000000, RAM_SIZE)

# ========================================
# Map UART/MMIO regions (FIX FOR 0x18018301 CRASH)
# ========================================
# MIPS has three ways to access peripherals:
# - Physical: 0x18000000-0x18FFFFFF
# - KSEG0 (cached): 0x98000000-0x98FFFFFF  
# - KSEG1 (uncached): 0xB8000000-0xB8FFFFFF
# All three map to the same physical hardware!

MMIO_SIZE = 0x01000000  # 16MB for all peripherals

mmio_regions = [
    (0x18000000, "Physical"),
    (0x98000000, "KSEG0 cached"),
    (0xB8000000, "KSEG1 uncached"),
]

for base, name in mmio_regions:
    try:
        mu.mem_map(base, MMIO_SIZE)
        mu.mem_write(base, b'\x00' * MMIO_SIZE)
        print(f"Mapped {name} peripherals at {hex(base)}")
    except UcError as e:
        print(f"Warning: {name} at {hex(base)} - {e}")

# Set UART LSR (Line Status Register) to 0x20 (Transmitter Empty)
# This prevents the firmware from hanging while polling for "Ready to Transmit"
try:
    # 0xb8018305 is likely LSR (Base 0xb8018300 + 5)
    mu.mem_write(0xb8018305, b'\x20') 
    print("Initialized UART LSR at 0xb8018305 to 0x20")
except Exception as e:
    print(f"Failed to init UART LSR: {e}")

# Initialize Capstone (MIPS32 + Little Endian)
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)

print(f"\nExecuting first {INSTR_COUNT} instructions:\n")

instruction_count = 0
last_lui_addr = None
# Track how many times each address has been visited
visit_counts = {}


# Hook Code
def hook_code(uc, address, size, user_data):
    global instruction_count, visit_counts, pending_lui_fix
    
# Hook Code
def hook_code(uc, address, size, user_data):
    global instruction_count, visit_counts
    
    # Track visit count for this address
    if address not in visit_counts:
        visit_counts[address] = 0
    visit_counts[address] += 1
    
    # Read instruction bytes
    code_bytes = uc.mem_read(address, size)
    
    # Disassemble
    if TRACE_INSTRUCTIONS:
        for i in md.disasm(code_bytes, address):
            # format bytes as hex string, e.g. "00 80 08 40"
            bytes_str = ' '.join(f'{b:02x}' for b in i.bytes)
            
            # Format loop counter (only show if > 1)
            loop_str = f" [LOOP {visit_counts[address]}]" if visit_counts[address] > 1 else ""
            
            print(f"0x{i.address:08X}: {bytes_str:<15} {i.mnemonic}\t{i.op_str}{loop_str}")
    
    # Check if we should stop at this address
    if STOP_INSTR is not None and address == STOP_INSTR:
        print(f"\n[STOP] Reached stop address: 0x{address:08X}")
        uc.emu_stop()
        return
    
    instruction_count += 1
    if instruction_count >= INSTR_COUNT:
        uc.emu_stop()

# Hook for invalid memory access
def hook_mem_invalid(uc, access, address, size, value, user_data):
    access_types = {0: "READ", 1: "WRITE", 2: "FETCH", 16: "READ_UNMAPPED", 17: "WRITE_UNMAPPED", 18: "FETCH_UNMAPPED"}
    print(f"\n[!] INVALID MEMORY ACCESS")
    print(f"    Type: {access_types.get(access, access)}")
    print(f"    Address: 0x{address:08X}")
    print(f"    Size: {size}")
    print(f"    PC: 0x{uc.reg_read(UC_MIPS_REG_PC):08X}")
    return False

# Add invalid memory hook
mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)

# Hook to manually implement Store/Load instructions
# Helper for UART logging
# Helper for UART logging
def uart_log(address, value):
    char_val = chr(value)
    # print(f"[UART] Write to {hex(address)}: {hex(value)} ('{char_val}')")
    print(char_val, end='', flush=True)

# Hook to manually implement Store/Load instructions
def hook_instruction_fix(uc, address, size, user_data):
    # Read instruction
    try:
        insn_bytes = uc.mem_read(address, 4)
        insn = int.from_bytes(insn_bytes, byteorder='little')
        
        opcode = (insn >> 26) & 0x3F
        rs = (insn >> 21) & 0x1F
        rt = (insn >> 16) & 0x1F
        imm = insn & 0xFFFF
        if imm & 0x8000: imm -= 0x10000 # Sign extend

        # LUI (Load Upper Immediate) - Opcode 0x0F (15)
        if opcode == 0x0F:
            # LUI uses the immediate as unsigned 16-bit
            # But here imm is already sign-extended if we're not careful? 
            # insn & 0xFFFF is the raw immediate.
            # LUI behavior: rt = imm << 16. The imm is 16-bit.
            raw_imm = insn & 0xFFFF
            val = raw_imm << 16
            
            # Skip Native LUI and stop to let loop handle the fix
            # This avoids any context saving/restoring issues in hook
            global last_lui_addr
            last_lui_addr = address
            uc.reg_write(UC_MIPS_REG_PC, address + 4)
            uc.emu_stop()
            return

        # Calculate target address first
        
        # Calculate target address first
        base = uc.reg_read(UC_MIPS_REG_ZERO + rs)
        target = base + imm
        
        # Check if target is MMIO
        # MMIO Regions: 0x18000000, 0x98000000, 0xB8000000 (Size 16MB)
        is_mmio = False
        if (0x18000000 <= target < 0x19000000) or \
           (0x98000000 <= target < 0x99000000) or \
           (0xB8000000 <= target < 0xB9000000):
            is_mmio = True
            
        # If NOT MMIO (i.e. RAM), let Unicorn handle it natively
        # This ensures Branch Delay Slots are handled correctly for arithmetic/logic
        if not is_mmio:
            return

        val = 0
        
        # SB (Store Byte) - Opcode 0x28 (40)
        if opcode == 0x28:
            val = uc.reg_read(UC_MIPS_REG_ZERO + rt) & 0xFF
            uc.mem_write(target, val.to_bytes(1, byteorder='little'))
            
            # Debug specific SB at 0xAFC01188
            #if address == 0xAFC01188:
            #     print(f"[DEBUG SB] At 0x{address:08X} writing byte 0x{val:02X} to 0x{target:08X}")
            
            # Manual UART Hook Check              
            if target == 0xb8018300:
                uart_log(target, val)
                mu.mem_write(0xb8018305, b'\x20') 
            uc.reg_write(UC_MIPS_REG_PC, address + 4)
            
        # SH (Store Half) - Opcode 0x29 (41)
        elif opcode == 0x29:
            val = uc.reg_read(UC_MIPS_REG_ZERO + rt) & 0xFF # Masking might be needed for consistency, but SH stores 16 bits.
            # However, looking at original code: val = ... & 0xFFFF
            val = uc.reg_read(UC_MIPS_REG_ZERO + rt) & 0xFFFF
            uc.mem_write(target, val.to_bytes(2, byteorder='little'))
            uc.reg_write(UC_MIPS_REG_PC, address + 4)

        # SW (Store Word) - Opcode 0x2B (43)
        elif opcode == 0x2B:
            val = uc.reg_read(UC_MIPS_REG_ZERO + rt)
            uc.mem_write(target, val.to_bytes(4, byteorder='little'))
            if target <= 0xb8018300 < target + 4:
                offset = 0xb8018300 - target
                byte_val = (val >> (offset * 8)) & 0xFF
                uart_log(0xb8018300, byte_val)
            uc.reg_write(UC_MIPS_REG_PC, address + 4)

        # LW (Load Word) - Opcode 0x23 (35)
        elif opcode == 0x23:
            data = uc.mem_read(target, 4)
            val = int.from_bytes(data, byteorder='little', signed=False)
            uc.reg_write(UC_MIPS_REG_ZERO + rt, val)
            uc.reg_write(UC_MIPS_REG_PC, address + 4)

        # LB (Load Byte) - Opcode 0x20 (32)
        elif opcode == 0x20:
            data = uc.mem_read(target, 1)
            val = int.from_bytes(data, byteorder='little', signed=True)
            uc.reg_write(UC_MIPS_REG_ZERO + rt, val)
            uc.reg_write(UC_MIPS_REG_PC, address + 4)

        # LBU (Load Byte Unsigned) - Opcode 0x24 (36)
        elif opcode == 0x24:
            data = uc.mem_read(target, 1)
            val = int.from_bytes(data, byteorder='little', signed=False)
            uc.reg_write(UC_MIPS_REG_ZERO + rt, val)
            uc.reg_write(UC_MIPS_REG_PC, address + 4)
            
        # LH (Load Half) - Opcode 0x21 (33)
        elif opcode == 0x21:
            data = uc.mem_read(target, 2)
            val = int.from_bytes(data, byteorder='little', signed=True)
            uc.reg_write(UC_MIPS_REG_ZERO + rt, val)
            uc.reg_write(UC_MIPS_REG_PC, address + 4)

        # LHU (Load Half Unsigned) - Opcode 0x25 (37)
        elif opcode == 0x25:
            data = uc.mem_read(target, 2)
            val = int.from_bytes(data, byteorder='little', signed=False)
            uc.reg_write(UC_MIPS_REG_ZERO + rt, val)
            uc.reg_write(UC_MIPS_REG_PC, address + 4)


    except Exception as e:
        # print(f"Error in manual instruction at {hex(address)}: {e}")
        pass

# Add code hook globally to fix stores (This will be slow but necessary)
mu.hook_add(UC_HOOK_CODE, hook_instruction_fix)

# Hook function to replace fwrite
def hook_fwrite(uc, address, size, user_data):
    # Read arguments: $a0=ptr, $a1=size, $a2=count, $a3=stream
    ptr = uc.reg_read(UC_MIPS_REG_A0)
    size = uc.reg_read(UC_MIPS_REG_A1)
    count = uc.reg_read(UC_MIPS_REG_A2)
    
    length = size * count
    
    try:
        if length > 0:
            bytes_data = uc.mem_read(ptr, length)
            # Replace unprintables mostly for clean output, or just decode
            msg = bytes_data.decode('utf-8', 'replace')
    except Exception as e:
        msg = f"[Error reading memory: {e}]"
    
    print(f"[PYTHON HOOK] Message: {msg}")
    if BREAK_ON_PRINTF:
       print(f"[PYTHON HOOK] Press any key to continue...")
       msvcrt.getch()
    
    # Do not return from function, let it execute
    # This allows fwrite to call UART functions so we can see writes
    pass

# Add hook for fwrite function
#mu.hook_add(UC_HOOK_CODE, hook_fwrite, begin=0xafc06d18, end=0xafc06d18)

# Hook UART Write
def hook_uart_write(uc, access, address, size, value, user_data):
    # Print hex and ascii
    uart_log(address, value)

# Add hook for UART writes (Char address: 0xb8018300)
mu.hook_add(UC_HOOK_MEM_WRITE, hook_uart_write, begin=0xb8018300, end=0xb8018305)

# Add code hook for instruction tracing
mu.hook_add(UC_HOOK_CODE, hook_code)

# Enable CP0 (Access to Coprocessor 0) and ensure Kernel Mode
# Set CP0 Status Register: Bit 28 (CU0) = 1, bits 0-4 (KSU, EXL, ERL) = 0 for kernel mode
try:
    # Status register: CU0=1 (bit 28), Kernel mode (bits 1-2 = 0)
    # Also set BEV=1 (bit 22) for boot exception vectors
    status = 0x10400000  # CU0=1, BEV=1
    mu.reg_write(UC_MIPS_REG_CP0_STATUS, status)
    print(f"Set CP0 Status = 0x{status:08X}")
except Exception as e:
    print(f"Warning: Could not set CP0 Status: {e}")

# Verify memory
try:
    print(f"Memory Check at {hex(BASE_ADDR)}: {mu.mem_read(BASE_ADDR, 4).hex()}")
except Exception as e:
    print(f"Memory Check Failed: {e}")

# Start emulation
# Run until stopped by hook or error
# Start emulation
# Run until stopped by hook or error
try:
    print(f"Starting emulation at {hex(BASE_ADDR)}...")
    
    # Loop to handle emu_stop calls for manual instruction skipping
    cur_pc = BASE_ADDR
    end_addr = BASE_ADDR + ROM_SIZE
    
    while cur_pc < end_addr:
        # Patch LUI bug: If we just stopped at LUI, fix the register now
        if last_lui_addr is not None:
             # Disassemble instruction at last_lui_addr to get imm and rt
             try:
                 insn_bytes = mu.mem_read(last_lui_addr, 4)
                 insn = int.from_bytes(insn_bytes, byteorder='little')
                 rt = (insn >> 16) & 0x1F
                 imm = insn & 0xFFFF
                 val = imm << 16
                 
                 mu.reg_write(UC_MIPS_REG_ZERO + rt, val)
             except: pass
             
             last_lui_addr = None

        # Invalidate JIT cache by writing back the instruction
        # This helps ensure register updates are recognized
        try:
             insn_data = mu.mem_read(cur_pc, 4)
             mu.mem_write(cur_pc, insn_data)
        except: pass
             
        mu.emu_start(cur_pc, end_addr)
        
        # If emu_start returns, it means emu_stop was called.
        # We need to read the current PC to continue.
        # Note: emu_stop in hook might have already advanced PC.
        cur_pc = mu.reg_read(UC_MIPS_REG_PC)
        
except UcError as e:
    print(f"Unicorn Error: {e}")
    print(f"PC at error: {hex(mu.reg_read(UC_MIPS_REG_PC))}")
    print(f"Status at error: {hex(mu.reg_read(UC_MIPS_REG_CP0_STATUS))}")
except Exception as e:
    print(f"Error: {e}")
