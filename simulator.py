from unicorn import *
from unicorn.mips_const import *
from capstone import *
import sys
from enum import Enum
from dataclasses import dataclass
from typing import Optional
from mips16_decoder import MIPS16Decoder
from mips16_engine import MIPS16Engine, ExecutionResult

class ISAMode(Enum):
    """ISA mode enumeration"""
    MIPS32 = 'mips32'
    MIPS16 = 'mips16'


@dataclass
class StepResult:
    """Result of a single step execution"""
    address: int
    instruction: str
    operands: str
    next_pc: int
    mode_before: str
    mode_after: str
    is_branch: bool = False
    is_call: bool = False
    is_return: bool = False
    mode_switched: bool = False
    instruction_size: int = 4


class AliMipsSimulator:
    def __init__(self, rom_size=8*1024*1024, ram_size=128*1024*1024, log_handler=None):
        self.rom_size = rom_size
        self.ram_size = ram_size
        self.base_addr = 0xAFC00000
        self.mu = None
        self.md = None
        self.uart_callback = None
        self.log_callback = log_handler
        self.last_lui_addr = None
        self.instruction_count = 0
        self.visit_counts = {}
        self.instruction_sizes = {}
        self.trace_instructions = False
        self.stop_instr = None
        self.break_on_printf = False
        self.max_instructions = 10000000
        self.is_syncing = False
        self.prev_executed_pc = None
        self.current_executed_pc = None
        
        # NEW: Explicit ISA mode tracking
        self.isa_mode = ISAMode.MIPS32
        
        # Call stack tracking for step_out
        self.call_stack = []
        
        # Debug flag - only log after MIPS16 mode entered
        self.debug_enabled = False

        self._init_unicorn()
        self._init_capstone()
        self._init_mips16_engine()

        self.gpr_map = [
            UC_MIPS_REG_ZERO, UC_MIPS_REG_AT, UC_MIPS_REG_V0, UC_MIPS_REG_V1,
            UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3,
            UC_MIPS_REG_T0, UC_MIPS_REG_T1, UC_MIPS_REG_T2, UC_MIPS_REG_T3,
            UC_MIPS_REG_T4, UC_MIPS_REG_T5, UC_MIPS_REG_T6, UC_MIPS_REG_T7,
            UC_MIPS_REG_S0, UC_MIPS_REG_S1, UC_MIPS_REG_S2, UC_MIPS_REG_S3,
            UC_MIPS_REG_S4, UC_MIPS_REG_S5, UC_MIPS_REG_S6, UC_MIPS_REG_S7,
            UC_MIPS_REG_T8, UC_MIPS_REG_T9, UC_MIPS_REG_K0, UC_MIPS_REG_K1,
            UC_MIPS_REG_GP, UC_MIPS_REG_SP, UC_MIPS_REG_FP, UC_MIPS_REG_RA
        ]

    def _init_unicorn(self):
        # Initialize Unicorn (MIPS32 + Little Endian)
        self.mu = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN)
        
        # Map memory
        self.log(f"Mapping memory at {hex(self.base_addr)}")
        self.mu.mem_map(self.base_addr, self.rom_size)
        
        # Map mirror
        self.log(f"Mapping mirror at 0x0FC00000")
        self.mu.mem_map(0x0FC00000, self.rom_size)
        
        # Shared RAM Buffer
        import ctypes
        self.ram_buffer = ctypes.create_string_buffer(self.ram_size)
        ram_ptr = ctypes.addressof(self.ram_buffer)
        
        # Map RAM aliases to same buffer
        self.log(f"Mapping Shared RAM at 0x80000000, 0xA0000000, 0x00000000")
        self.mu.mem_map_ptr(0x80000000, self.ram_size, UC_PROT_ALL, ram_ptr)
        self.mu.mem_map_ptr(0xA0000000, self.ram_size, UC_PROT_ALL, ram_ptr)
        self.mu.mem_map_ptr(0x00000000, self.ram_size, UC_PROT_ALL, ram_ptr)
        
        # Map MMIO
        MMIO_SIZE = 0x01000000
        mmio_regions = [
            (0x18000000, "Physical"),
            (0x98000000, "KSEG0 cached"),
            (0xB8000000, "KSEG1 uncached"),
        ]
        
        for base, name in mmio_regions:
            try:
                self.mu.mem_map(base, MMIO_SIZE)
                self.mu.mem_write(base, b'\x00' * MMIO_SIZE)
                self.log(f"Mapped {name} peripherals at {hex(base)}")
            except UcError as e:
                self.log(f"Warning: {name} at {hex(base)} - {e}")

        # Set UART LSR
        try:
            self.mu.mem_write(0xb8018305, b'\x20')
            # Mirror LSR to Physical and KSEG0 to avoid polling loops
            self.mu.mem_write(0x18018305, b'\x20')
            self.mu.mem_write(0x98018305, b'\x20')
            self.log("Initialized UART LSR at 0xb8018305 (and mirrors) to 0x20")
        except Exception as e:
            self.log(f"Failed to init UART LSR: {e}")

        # Set Magic Value at 0xb8000002 for testing
        try:
            val_bytes = b'\x11\x38' # 0x3811 Little Endian
            self.mu.mem_write(0xb8000002, val_bytes)
            self.mu.mem_write(0x18000002, val_bytes)
            self.mu.mem_write(0x98000002, val_bytes)
            self.log("Initialized magic value 0x3811 at 0xb8000002 (and mirrors)")
        except Exception as e:
            self.log(f"Failed to init magic value: {e}")

        # Hooks
        self.mu.hook_add(UC_HOOK_MEM_INVALID, self._hook_mem_invalid)
        self.mu.hook_add(UC_HOOK_CODE, self._hook_instruction_fix)
        # Memory Sync Hook (KSEG0 <-> KSEG1)
        # KSEG0: 0x80000000, KSEG1: 0xA0000000
        # We hook both regions to sync writes
        kseg0_end = 0x80000000 + self.ram_size - 1
        kseg1_end = 0xA0000000 + self.ram_size - 1
        phys_end = self.ram_size - 1
        # RAM Sync Hooks REMOVED (Handled by mem_map_ptr)

        # UART Hooks (Aliased)
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_uart_write, begin=0x18018300, end=0x18018305)
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_uart_write, begin=0x98018300, end=0x98018305)
        self.mu.hook_add(UC_HOOK_MEM_WRITE, self._hook_uart_write, begin=0xb8018300, end=0xb8018305)

        self.mu.hook_add(UC_HOOK_CODE, self._hook_code)
        
        # CP0 Status configuration
        try:
            status = 0x10400000 # CU0=1, BEV=1
            self.mu.reg_write(UC_MIPS_REG_CP0_STATUS, status)
            self.log(f"Set CP0 Status = 0x{status:08X}")
        except Exception as e:
            self.log(f"Warning: Could not set CP0 Status: {e}")

    def _init_capstone(self):
        self.md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
    
    def _init_mips16_engine(self):
        """Initialize native MIPS16 execution engine"""
        self.mips16_engine = MIPS16Engine(
            memory_reader=self._mem_read_callback,
            memory_writer=self._mem_write_callback,
            register_reader=self._reg_read_callback,
            register_writer=self._reg_write_callback
        )
    
    def _mem_read_callback(self, address, size):
        """Memory read callback for MIPS16 engine"""
        return self.mu.mem_read(address, size)
    
    def _mem_write_callback(self, address, data):
        """Memory write callback for MIPS16 engine"""
        self.mu.mem_write(address, data)
    
    def _reg_read_callback(self, reg_name):
        """Register read callback for MIPS16 engine"""
        reg_id = self._get_reg_id(reg_name)
        return self.mu.reg_read(reg_id)
    
    def _reg_write_callback(self, reg_name, value):
        """Register write callback for MIPS16 engine"""
        reg_id = self._get_reg_id(reg_name)
        self.mu.reg_write(reg_id, value & 0xFFFFFFFF)

    def _get_reg_id(self, reg_name):
        reg_map = {
            'zero': UC_MIPS_REG_ZERO, 'at': UC_MIPS_REG_AT, 'v0': UC_MIPS_REG_V0, 'v1': UC_MIPS_REG_V1,
            'a0': UC_MIPS_REG_A0, 'a1': UC_MIPS_REG_A1, 'a2': UC_MIPS_REG_A2, 'a3': UC_MIPS_REG_A3,
            't0': UC_MIPS_REG_T0, 't1': UC_MIPS_REG_T1, 't2': UC_MIPS_REG_T2, 't3': UC_MIPS_REG_T3,
            't4': UC_MIPS_REG_T4, 't5': UC_MIPS_REG_T5, 't6': UC_MIPS_REG_T6, 't7': UC_MIPS_REG_T7,
            's0': UC_MIPS_REG_S0, 's1': UC_MIPS_REG_S1, 's2': UC_MIPS_REG_S2, 's3': UC_MIPS_REG_S3,
            's4': UC_MIPS_REG_S4, 's5': UC_MIPS_REG_S5, 's6': UC_MIPS_REG_S6, 's7': UC_MIPS_REG_S7,
            't8': UC_MIPS_REG_T8, 't9': UC_MIPS_REG_T9, 'k0': UC_MIPS_REG_K0, 'k1': UC_MIPS_REG_K1,
            'gp': UC_MIPS_REG_GP, 'sp': UC_MIPS_REG_SP, 'fp': UC_MIPS_REG_FP, 'ra': UC_MIPS_REG_RA,
            's8': UC_MIPS_REG_FP 
        }
        return reg_map.get(reg_name, UC_MIPS_REG_ZERO)

    def setLogHandler(self, handler):
        self.log_callback = handler

    def setUartHandler(self, handler):
        self.uart_callback = handler

    def log(self, msg):
        if self.log_callback:
            self.log_callback(msg)
        else:
            print(msg)

    def _uart_log(self, value):
        if self.uart_callback:
            # Pass the character code directly, let the handler decide format
            self.uart_callback(chr(value & 0xFF))
        else:
            print(chr(value & 0xFF), end='', flush=True)

    def loadFile(self, filename):
        self.log(f"Loading {filename}...")
        with open(filename, "rb") as f:
            code = f.read()
        self.mu.mem_write(self.base_addr, code)
        self.mu.mem_write(0x0FC00000, code)
        
        # Set PC to start address
        self.mu.reg_write(UC_MIPS_REG_PC, self.base_addr)
        
        # Re-initialize globals if re-running
        self.instruction_count = 0
        self.visit_counts = {}
        self.last_lui_addr = None

    def _hook_mem_invalid(self, uc, access, address, size, value, user_data):
        access_types = {0: "READ", 1: "WRITE", 2: "FETCH", 16: "READ_UNMAPPED", 17: "WRITE_UNMAPPED", 18: "FETCH_UNMAPPED"}
        self.log(f"\n[!] INVALID MEMORY ACCESS")
        self.log(f"    Type: {access_types.get(access, access)}")
        self.log(f"    Address: 0x{address:08X}")
        self.log(f"    Size: {size}")
        self.log(f"    PC: 0x{uc.reg_read(UC_MIPS_REG_PC):08X}")
        return False

    def _hook_uart_write(self, uc, access, address, size, value, user_data):
        # 0xb8018300 is base, store happens at offset 0 usually
        # Check all aliases: 0x18018300, 0x98018300, 0xB8018300
        if (address & 0xFFFFF) == 0x18300:
            self._uart_log(value)





    def _hook_code(self, uc, address, size, user_data):
        # Track history for jumps
        if not hasattr(self, 'current_executed_pc'): self.current_executed_pc = None
        self.prev_executed_pc = self.current_executed_pc
        self.current_executed_pc = address

        # Track visit count
        if address not in self.visit_counts:
            self.visit_counts[address] = 0
            # Track size on first visit (or every visit?)
            if not hasattr(self, 'instruction_sizes'): self.instruction_sizes = {}
            self.instruction_sizes[address] = size
        
        self.visit_counts[address] += 1
        self.instruction_sizes[address] = size # Ensure latest size is stored
        
        if self.trace_instructions:
            code_bytes = uc.mem_read(address, size)
            try:
                # Handle MIPS16 instructions (size == 2)
                if size == 2:
                    mnemonic, operands = MIPS16Decoder.decode(code_bytes)
                    bytes_str = ' '.join(f'{b:02x}' for b in code_bytes)
                    loop_str = f" [LOOP {self.visit_counts[address]}]" if self.visit_counts[address] > 1 else ""
                    self.log(f"0x{address:08X}: {bytes_str:<15} {mnemonic}\t{operands}{loop_str}")
                else:
                    # Standard MIPS32 disassembly
                    for i in self.md.disasm(code_bytes, address):
                        bytes_str = ' '.join(f'{b:02x}' for b in i.bytes)
                        loop_str = f" [LOOP {self.visit_counts[address]}]" if self.visit_counts[address] > 1 else ""
                        self.log(f"0x{i.address:08X}: {bytes_str:<15} {i.mnemonic}\t{i.op_str}{loop_str}")
            except: pass

        if self.stop_instr is not None and address == self.stop_instr:
            self.log(f"\n[STOP] Reached stop address: 0x{address:08X}")
            uc.emu_stop()
            return
            
        self.instruction_count += 1
        if self.max_instructions and self.instruction_count >= self.max_instructions:
            uc.emu_stop()

    def _hook_instruction_fix(self, uc, address, size, user_data):
        # JALX Support - Unicorn doesn't support JALX, so we emulate it manually
        if size == 4:
            try:
                insn_bytes = uc.mem_read(address, 4)
                insn = int.from_bytes(insn_bytes, byteorder='little')
                opcode = (insn >> 26) & 0x3F
                
                # JALX opcode is 0x1D (29)
                if opcode == 0x1D:
                    # Extract target address (26-bit)
                    target_index = insn & 0x3FFFFFF
                    target_addr = (address & 0xF0000000) | (target_index << 2)
                    
                    # Save return address
                    return_addr = address + 8  # PC+8 in delay slot
                    uc.reg_write(UC_MIPS_REG_RA, return_addr)
                    
                    # Jump to target (MIPS16 mode - target is even)
                    uc.reg_write(UC_MIPS_REG_PC, target_addr)
                    
                    self.log(f"[DEBUG] Manual JALX: 0x{address:08X} -> 0x{target_addr:08X}, RA=0x{return_addr:08X}")
                    
                    # Stop emulation to let our step() handle the mode switch
                    uc.emu_stop()
                    return
            except:
                pass
        
        # MIPS16 Support
        if size == 2:
            try:
                insn_bytes = uc.mem_read(address, 2)
                # Decode using MIPS16Decoder to know what we are dealing with
                mnemonic, ops = MIPS16Decoder.decode(insn_bytes, address)
                
                # Check for unimplemented instructions and emulate them
                # SEB / ZEB
                if mnemonic in ["seb", "zeb"]:
                    reg_name = ops.strip()
                    reg_id = self._get_reg_id(reg_name)
                    val = uc.reg_read(reg_id) & 0xFF
                    
                    if mnemonic == "seb":
                        # Sign extend byte
                        if val & 0x80:
                            val |= 0xFFFFFF00
                    # ZEB is just zero extend, which & 0xFF did.
                    
                    uc.reg_write(reg_id, val)
                    uc.reg_write(UC_MIPS_REG_PC, (address + 2) | 1)
                    return

                # MOVE
                elif mnemonic == "move":
                    # ops: "dest,src"
                    dest_name, src_name = ops.split(',')
                    dest_id = self._get_reg_id(dest_name)
                    src_id = self._get_reg_id(src_name)
                    
                    val = uc.reg_read(src_id)
                    uc.reg_write(dest_id, val)
                    uc.reg_write(UC_MIPS_REG_PC, (address + 2) | 1)
                    return

                # SLTI
                elif mnemonic == "slti":
                    # slti rx, imm
                    rx_name, imm_str = ops.split(',')
                    rx_id = self._get_reg_id(rx_name)
                    imm = int(imm_str.strip(), 0)
                    if imm & 0x8000: imm -= 0x10000 
                    if imm & 0x80: imm -= 0x100 # Sign extend 8-bit imm
                    
                    val = uc.reg_read(rx_id)
                    # Convert to signed 32-bit for comparison
                    if val & 0x80000000: val -= 0x100000000
                    
                    res = 1 if val < imm else 0
                    uc.reg_write(UC_MIPS_REG_T8, res) # Result goes to T8
                    uc.reg_write(UC_MIPS_REG_PC, (address + 2) | 1)
                    return
                
                # BNEZ
                elif mnemonic == "bnez":
                    # bnez rx, offset
                    rx_name, offset_str = ops.split(',')
                    rx_id = self._get_reg_id(rx_name)
                    offset = int(offset_str.strip(), 0)
                    
                    val = uc.reg_read(rx_id)
                    if val != 0:
                        # Branch taken
                        # Target = (PC + 2) + offset
                        target = (address + 2) + offset
                        uc.reg_write(UC_MIPS_REG_PC, target | 1)
                    else:
                        uc.reg_write(UC_MIPS_REG_PC, (address + 2) | 1)
                    return

                # LW PC-Rel
                elif mnemonic == "lw" and "(pc)" in ops:
                    # lw rx, offset(pc)
                    rx_name, rest = ops.split(',')
                    offset_str = rest.replace('(pc)', '')
                    offset = int(offset_str.strip(), 0)
                    rx_id = self._get_reg_id(rx_name)
                    
                    # PC-relative load address: (PC & ~3) + offset
                    base = (address & 0xFFFFFFFC)
                    target = base + offset
                    
                    data = uc.mem_read(target, 4)
                    val = int.from_bytes(data, byteorder='little')
                    uc.reg_write(rx_id, val)
                    uc.reg_write(UC_MIPS_REG_PC, (address + 2) | 1)
                    return

            except Exception as e:
                # self.log(f"MIPS16 Manual Error: {e}")
                pass
            
            # If not handled, return to let Unicorn try (or fail)
            return

        try:
            # Optimization: Only read if we need to (check opcode logic first?)
            # Actually we need to read to know opcode.
            insn_bytes = uc.mem_read(address, 4)
            insn = int.from_bytes(insn_bytes, byteorder='little')
            
            opcode = (insn >> 26) & 0x3F
            rs = (insn >> 21) & 0x1F
            rt = (insn >> 16) & 0x1F
            imm = insn & 0xFFFF
            if imm & 0x8000: imm -= 0x10000 

            # LUI
            if opcode == 0x0F:
                self.last_lui_addr = address
                uc.reg_write(UC_MIPS_REG_PC, address + 4)
                uc.emu_stop()
                return

            base = uc.reg_read(self.gpr_map[rs])
            target = base + imm
            
            # Check MMIO
            is_mmio = False
            if (0x18000000 <= target < 0x19000000) or \
               (0x98000000 <= target < 0x99000000) or \
               (0xB8000000 <= target < 0xB9000000):
                is_mmio = True
                
            # FORCE MANUAL EMULATION FOR ALL STORES TO ENSURE SYNC
            if not is_mmio:
                return

            val = 0
            
            if opcode == 0x28: # SB
                val = uc.reg_read(self.gpr_map[rt]) & 0xFF
                val_bytes = val.to_bytes(1, byteorder='little')
                uc.mem_write(target, val_bytes)
                # If target is UART, hook will handle it via uc.mem_write
                if target == 0xb8018300:
                    self._uart_log(val)
                    self.mu.mem_write(0xb8018305, b'\x20') 
                uc.reg_write(UC_MIPS_REG_PC, address + 4)

            elif opcode == 0x29: # SH
                val = uc.reg_read(self.gpr_map[rt]) & 0xFFFF
                val_bytes = val.to_bytes(2, byteorder='little')
                uc.mem_write(target, val_bytes)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)

            elif opcode == 0x2B: # SW
                val = uc.reg_read(self.gpr_map[rt])
                val_bytes = val.to_bytes(4, byteorder='little')
                uc.mem_write(target, val_bytes)
                if target <= 0xb8018300 < target + 4:
                    offset = 0xb8018300 - target
                    byte_val = (val >> (offset * 8)) & 0xFF
                    self._uart_log(byte_val)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)
                
            elif opcode == 0x23: # LW
                data = uc.mem_read(target, 4)
                val = int.from_bytes(data, byteorder='little', signed=False)
                uc.reg_write(self.gpr_map[rt], val)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)

            elif opcode == 0x20: # LB
                data = uc.mem_read(target, 1)
                val = int.from_bytes(data, byteorder='little', signed=True)
                uc.reg_write(self.gpr_map[rt], val)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)

            elif opcode == 0x24: # LBU
                data = uc.mem_read(target, 1)
                val = int.from_bytes(data, byteorder='little', signed=False)
                uc.reg_write(self.gpr_map[rt], val)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)
                
            elif opcode == 0x21: # LH
                data = uc.mem_read(target, 2)
                val = int.from_bytes(data, byteorder='little', signed=True)
                uc.reg_write(self.gpr_map[rt], val)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)

            elif opcode == 0x25: # LHU
                data = uc.mem_read(target, 2)
                val = int.from_bytes(data, byteorder='little', signed=False)
                uc.reg_write(self.gpr_map[rt], val)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)

        except Exception as e:
            # self.log(f"Error in manual instruction at {hex(address)}: {e}")
            pass

    def apply_manual_fixes(self):
        if self.last_lui_addr is not None:
             try:
                 # Manual LUI fix
                 insn_bytes = self.mu.mem_read(self.last_lui_addr, 4)
                 insn = int.from_bytes(insn_bytes, byteorder='little')
                 rt = (insn >> 16) & 0x1F
                 imm = insn & 0xFFFF
                 val = imm << 16
                 
                 # print(f"DEBUG: Manual LUI at {hex(self.last_lui_addr)}: rt={rt}, val={hex(val)}")
                 # print(f"DEBUG: Manual LUI at {hex(self.last_lui_addr)}: rt={rt}, val={hex(val)}")
                 self.mu.reg_write(self.gpr_map[rt], val)
             except Exception as e: 
                 # print(f"DEBUG: LUI fix error: {e}")
                 pass
             
             self.last_lui_addr = None

    def invalidate_jit(self, address):
         try:
              insn_data = self.mu.mem_read(address, 4)
              self.mu.mem_write(address, insn_data)
         except: pass

    def is_mips16_addr(self, address):
        """Heuristic to check if address is in known MIPS16 region"""
        # Main firmware body seems to be below 0x81E8E000
        # Loader/Trigger at 0x81E8E1B8 is MIPS32
        if (address & 0xFFE00000) == 0x81E00000:
             if address < 0x81E8E000:
                 return True
        return False

    def run(self, max_instructions=None):
        self.log(f"Starting emulation at {hex(self.base_addr)}...")
        
        if max_instructions is not None:
            self.max_instructions = max_instructions
        
        cur_pc = self.base_addr
        end_addr = self.base_addr + self.rom_size
        
        try:
            while cur_pc < end_addr:
                self.apply_manual_fixes()
                self.invalidate_jit(cur_pc)
                
                # Check for max instruction count stop
                if self.max_instructions and self.instruction_count >= self.max_instructions:
                    break
                
                # MIPS16 Mode Force
                start_pc = cur_pc
                if self.is_mips16_addr(start_pc):
                    start_pc |= 1

                # Run!
                self.mu.emu_start(start_pc, end_addr)
                
                # If we stopped, update PC and loop
                cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
        
        except UcError as e:
            self.log(f"Unicorn Error: {e}")
            self.log(f"PC at error: {hex(self.mu.reg_read(UC_MIPS_REG_PC))}")
            self.log(f"Status at error: {hex(self.mu.reg_read(UC_MIPS_REG_CP0_STATUS))}")
        except Exception as e:
            self.log(f"Error: {e}")

    def runStep(self):
        cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
        end_addr = self.base_addr + self.rom_size
        
        try:
             self.apply_manual_fixes()
             self.invalidate_jit(cur_pc)
              
             # MIPS16 Fix: If in MIPS16 region, force Thumb/MIPS16 mode by setting LSB
             start_pc = cur_pc
             if self.is_mips16_addr(start_pc):
                 start_pc |= 1
                 
             # Run 1 instruction
             self.mu.emu_start(start_pc, end_addr, count=1)
             
        except UcError as e:
            self.log(f"Unicorn Error: {e}")
            self.log(f"PC at error: {hex(self.mu.reg_read(UC_MIPS_REG_PC))}")
        except Exception as e:
            self.log(f"Error: {e}")
    
    # NEW: Unified Stepping APIs
    
    def step(self) -> StepResult:
        """
        Execute one instruction in the current ISA mode
        
        Returns:
            StepResult with execution details
        """
        pc = self.mu.reg_read(UC_MIPS_REG_PC)
        mode_before = self.isa_mode.value
        
        # DEBUG: Log current mode (only if debug enabled)
        if self.debug_enabled:
            self.log(f"[DEBUG] step() at PC=0x{pc:08X}, mode={mode_before}")
        
        if self.isa_mode == ISAMode.MIPS16:
            result = self._step_mips16(pc)
        else:
            result = self._step_mips32(pc)
        
        # Update mode if switched
        if result.mode_switched:
            self.isa_mode = ISAMode.MIPS32 if result.mode_after == 'mips32' else ISAMode.MIPS16
            
            # Enable debug logging when entering MIPS16 for first time
            if result.mode_after == 'mips16' and not self.debug_enabled:
                self.debug_enabled = True
                self.log("[DEBUG] MIPS16 mode entered - enabling debug logging")
            
            if self.debug_enabled:
                self.log(f"[DEBUG] Mode switched: {result.mode_before} -> {result.mode_after}")
        
        # Update instruction counter
        self.instruction_count += 1
        
        # Track call stack for step_out
        if result.is_call:
            self.call_stack.append(result.address)
        elif result.is_return and self.call_stack:
            self.call_stack.pop()
        
        return result
    
    def step_into(self) -> StepResult:
        """
        Step into function calls (same as step())
        
        Returns:
            StepResult with execution details
        """
        return self.step()
    
    def step_over(self) -> StepResult:
        """
        Step over function calls (execute entire function if next instruction is a call)
        
        Returns:
            StepResult with execution details
        """
        # Execute one step
        result = self.step()
        
        # If it's a call, keep executing until we return
        if result.is_call:
            return_address = result.next_pc
            max_steps = 100000  # Safety limit
            steps = 0
            
            while steps < max_steps:
                current_pc = self.mu.reg_read(UC_MIPS_REG_PC)
                if current_pc == return_address:
                    # We've returned from the call
                    break
                
                step_result = self.step()
                steps += 1
                
                # If we hit a breakpoint or stop condition, return immediately
                if self.stop_instr and current_pc == self.stop_instr:
                    break
        
        return result
    
    def step_out(self) -> StepResult:
        """
        Step out of current function (execute until return)
        
        Returns:
            StepResult with execution details
        """
        initial_stack_depth = len(self.call_stack)
        max_steps = 100000  # Safety limit
        steps = 0
        last_result = None
        
        while steps < max_steps:
            last_result = self.step()
            steps += 1
            
            # Check if we've returned from the function
            if len(self.call_stack) < initial_stack_depth:
                break
            
            # If we hit a stop condition, break
            current_pc = self.mu.reg_read(UC_MIPS_REG_PC)
            if self.stop_instr and current_pc == self.stop_instr:
                break
        
        return last_result if last_result else StepResult(
            address=self.mu.reg_read(UC_MIPS_REG_PC),
            instruction="???",
            operands="",
            next_pc=self.mu.reg_read(UC_MIPS_REG_PC),
            mode_before=self.isa_mode.value,
            mode_after=self.isa_mode.value
        )
    
    def _step_mips32(self, pc: int) -> StepResult:
        """Execute one MIPS32 instruction using Unicorn"""
        mode_before = 'mips32'
        
        # Read instruction
        insn_bytes = self.mu.mem_read(pc, 4)
        
        # Decode for display
        mnemonic = "???"
        operands = ""
        try:
            disasm = list(self.md.disasm(insn_bytes, pc))
            if disasm:
                mnemonic = disasm[0].mnemonic
                operands = disasm[0].op_str
        except:
            pass
        
        # DEBUG: Log JALX instructions (only if debug enabled)
        if mnemonic == 'jalx' and self.debug_enabled:
            self.log(f"[DEBUG] Executing JALX at 0x{pc:08X} -> target {operands}")
        
        # Execute one instruction with Unicorn
        end_addr = self.base_addr + self.rom_size
        try:
            self.apply_manual_fixes()
            self.invalidate_jit(pc)
            self.mu.emu_start(pc, end_addr, count=1)
        except Exception as e:
            pass  # Continue even on error
        
        next_pc = self.mu.reg_read(UC_MIPS_REG_PC)
        
        # DEBUG: Log PC after JALX (only if debug enabled)
        if mnemonic == 'jalx' and self.debug_enabled:
            self.log(f"[DEBUG] After JALX: PC = 0x{next_pc:08X}, switching to MIPS16 mode")
        
        # Check for mode switch (JALX instruction)
        mode_after = mode_before
        mode_switched = False
        if mnemonic == 'jalx':
            mode_after = 'mips16'
            mode_switched = True
        
        # Determine instruction type
        is_call = mnemonic in ['jal', 'jalr', 'jalx']
        is_return = mnemonic in ['jr'] and 'ra' in operands
        is_branch = mnemonic.startswith('b') or mnemonic.startswith('j')
        
        return StepResult(
            address=pc,
            instruction=mnemonic,
            operands=operands,
            next_pc=next_pc,
            mode_before=mode_before,
            mode_after=mode_after,
            is_branch=is_branch,
            is_call=is_call,
            is_return=is_return,
            mode_switched=mode_switched,
            instruction_size=4
        )
    
    def _step_mips16(self, pc: int) -> StepResult:
        """Execute one MIPS16 instruction using native engine"""
        mode_before = 'mips16'
        
        # Execute using native MIPS16 engine
        exec_result = self.mips16_engine.execute(pc)
        
        # Decode for display
        if exec_result.instruction_size == 4:
            insn_bytes = self.mu.mem_read(pc, 4)
        else:
            insn_bytes = self.mu.mem_read(pc, 2)
        
        mnemonic, operands = MIPS16Decoder.decode(insn_bytes, pc)
        
        # Update PC
        self.mu.reg_write(UC_MIPS_REG_PC, exec_result.next_pc)
        
        # Determine mode after execution
        mode_after = exec_result.mode_switch if exec_result.mode_switch else mode_before
        mode_switched = exec_result.mode_switch is not None
        
        return StepResult(
            address=pc,
            instruction=mnemonic,
            operands=operands,
            next_pc=exec_result.next_pc,
            mode_before=mode_before,
            mode_after=mode_after,
            is_branch=exec_result.is_branch,
            is_call=exec_result.is_call,
            is_return=exec_result.is_return,
            mode_switched=mode_switched,
            instruction_size=exec_result.instruction_size
        )

    def skipInstruction(self):
        """Skip the current instruction by advancing PC by 4"""
        try:
            cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
            # Try to determine size of instruction at PC
            # Default to 4
            incr = 4
            try:
                code = self.mu.mem_read(cur_pc, 4)
                # We need a disassembler that understands the current mode...
                # Sim's self.md is MIPS32. If we are in MIPS16, we might fail or get it wrong.
                # Heuristic: Check PC alignment? MIPS16 PC is usually odd in JALX but even in execution?
                # Actually, in Unicorn, PC is the address.
                # If we are in MIPS16 mode, we might need a separate disassembler.
                for i in self.md.disasm(code, cur_pc):
                    incr = i.size
                    break
            except: pass

            self.mu.reg_write(UC_MIPS_REG_PC, cur_pc + incr)
            self.log(f"Skipped instruction at 0x{cur_pc:08X} (size {incr})")
        except Exception as e:
            self.log(f"Error skipping instruction: {e}")

    def get_instructions_around_pc(self, pc, before=10, after=10, forced_mips16_addresses=None, breakpoints=None):
        if not self.mu: return []
        instructions = []
        forced_mips16_addresses = forced_mips16_addresses or set()
        breakpoints = breakpoints or {}
        
        # Backward scan (Tricky with variable length)
        # Strategy: Go back 'before * 4' bytes (approx), then disassemble forward.
        # If we desync at PC, adjust start point.
        
        start_attempts = [pc - (before * 4), pc - (before * 4) + 2]
        best_instrs = []
        
        for start_addr in start_attempts:
            if start_addr < 0: continue
            
            # Check if PC is a JALX target before scanning
            pc_is_jalx_target = False
            prev_exec = getattr(self, 'prev_executed_pc', None)
            if prev_exec:
                try:
                    prev_bytes = self.mu.mem_read(prev_exec, 4)
                    prev_disasm = list(self.md.disasm(prev_bytes, prev_exec))
                    if prev_disasm and prev_disasm[0].mnemonic == 'jalx':
                        pc_is_jalx_target = True
                        print(f"[DEBUG] PC 0x{pc:08X} is JALX target from 0x{prev_exec:08X}")
                except: pass
            
            temp_instrs = []
            curr = start_addr
            valid_sequence = False
            
            # Track if we're in a MIPS16 region (entered via JALX)
            in_mips16_region = False
            
            # Limit scan to reasonable amount to avoid infinite loops if something is wrong
            while curr <= pc + (after * 4): 
                # Decode one
                try:
                    # Check known size or Forced MIPS16
                    is_mips16 = False
                    
                    # 1. Execution History
                    known_size = self.instruction_sizes.get(curr)
                    if known_size == 2:
                        is_mips16 = True
                        # print(f"[DEBUG] 0x{curr:08X} is MIPS16 from execution history")
                    
                    # 2. Forced Address (Manual Toggle)
                    if curr in forced_mips16_addresses:
                        is_mips16 = True
                        # print(f"[DEBUG] 0x{curr:08X} is MIPS16 from forced addresses")
                    
                    # 3. JALX target detection
                    if not is_mips16 and curr == pc and pc_is_jalx_target:
                        is_mips16 = True
                        in_mips16_region = True  # Enter MIPS16 region
                        print(f"[DEBUG] 0x{curr:08X} is MIPS16 as JALX target - entering MIPS16 region")
                    
                    # 4. If we're in a MIPS16 region (and no execution history says otherwise), assume MIPS16
                    if not is_mips16 and in_mips16_region and known_size != 4:
                        is_mips16 = True
                        # print(f"[DEBUG] 0x{curr:08X} is MIPS16 from region continuation")

                    # 5. Check Simulator Heuristic (New)
                    if not is_mips16 and self.is_mips16_addr(curr):
                        is_mips16 = True
                        in_mips16_region = True

                    if is_mips16:
                        # It's MIPS16! Decode it properly
                        # Read first 2 bytes to check instruction type
                        first_word = self.mu.mem_read(curr, 2)
                        word1 = int.from_bytes(first_word, byteorder='little')
                        major_op = (word1 >> 11) & 0x1F
                        is_4byte = (major_op == 0x03 or major_op == 0x1E)  # JAL/JALX opcode or EXTEND
                        
                        # Read appropriate number of bytes
                        if is_4byte:
                            valid_bytes = self.mu.mem_read(curr, 4)
                            instr_size = 4
                        else:
                            valid_bytes = first_word
                            instr_size = 2
                        
                        # Decode MIPS16 instruction (with address for JAL target calculation)
                        mnemonic, operands = MIPS16Decoder.decode(valid_bytes, curr)
                        bytes_str = ' '.join(f'{b:02x}' for b in valid_bytes)
                        
                        temp_instrs.append({
                            'address': curr,
                            'bytes': bytes_str,
                            'mnemonic': mnemonic,
                            'operands': operands,
                            'loop_count': self.visit_counts.get(curr, 0),
                            'is_current': (curr == pc),
                            'is_breakpoint': (curr in breakpoints)
                        })
                        curr += instr_size
                        if curr == pc: valid_sequence = True
                        if curr > pc and not valid_sequence: break
                        if valid_sequence:
                             # check after count
                             count_after = sum(1 for i in temp_instrs if i['address'] > pc)
                             if count_after >= after: break
                        continue

                    # Try to disassemble as MIPS32 first
                    code = self.mu.mem_read(curr, 4)
                    disasm = list(self.md.disasm(code, curr))
                    
                    if not disasm:
                        # Fallback: treat as MIPS16 instruction
                        try:
                            # Read first 2 bytes to check instruction type
                            first_word = self.mu.mem_read(curr, 2)
                            word1 = int.from_bytes(first_word, 'little')
                            major_op = (word1 >> 11) & 0x1F
                            is_4byte = (major_op == 0x03 or major_op == 0x1E)
                            
                            # Read appropriate number of bytes
                            if is_4byte:
                                valid_bytes = self.mu.mem_read(curr, 4)
                                instr_size = 4
                            else:
                                valid_bytes = first_word
                                instr_size = 2
                            
                            mnemonic, operands = MIPS16Decoder.decode(valid_bytes, curr)
                            bytes_str = ' '.join(f'{b:02x}' for b in valid_bytes)
                            
                            temp_instrs.append({
                                'address': curr,
                                'bytes': bytes_str,
                                'mnemonic': mnemonic,
                                'operands': operands,
                                'loop_count': self.visit_counts.get(curr, 0),
                                'is_current': (curr == pc),
                                'is_breakpoint': (curr in breakpoints)
                            })
                            curr += instr_size
                        except:
                            curr += 4  # Skip if read fails
                        continue
                        
                    instr = disasm[0]
                    
                    item = {
                        'address': curr,
                        'bytes': ' '.join(f'{b:02x}' for b in instr.bytes),
                        'mnemonic': instr.mnemonic,
                        'operands': instr.op_str,
                        'loop_count': self.visit_counts.get(curr, 0),
                        'is_current': (curr == pc),
                        'is_breakpoint': (curr in breakpoints)
                    }
                    temp_instrs.append(item)
                    
                    if curr == pc:
                        valid_sequence = True
                        
                    curr += instr.size
                    
                    # If we passed PC
                    if curr > pc and not valid_sequence:
                         break # Desync
                         
                    # Stop if we have enough "after" instructions
                    if valid_sequence:
                        # Count how many after PC
                        count_after = 0
                        for i in reversed(temp_instrs):
                            if i['address'] > pc: count_after += 1
                            else: break
                        if count_after >= after: break
                        
                except:
                    curr += 4 # Fallback
            
            if valid_sequence:
                best_instrs = temp_instrs
                break
        
        if not best_instrs:
            # Ultimate fallback: Show raw hex dump around PC
            print(f"[DEBUG] No valid disassembly found, using hex dump fallback at PC=0x{pc:08X}")
            curr = max(0, pc - 20)  # Show a bit before PC
            for i in range(25):  # Show ~50 bytes
                try:
                    # Read first 2 bytes to check instruction type
                    first_word = self.mu.mem_read(curr, 2)
                    word1 = int.from_bytes(first_word, byteorder='little')
                    major_op = (word1 >> 11) & 0x1F
                    is_4byte = (major_op == 0x03 or major_op == 0x1E)
                    
                    # Read appropriate number of bytes
                    if is_4byte:
                        code = self.mu.mem_read(curr, 4)
                        instr_size = 4
                    else:
                        code = first_word
                        instr_size = 2
                    
                    mnemonic, operands = MIPS16Decoder.decode(code, curr)
                    bytes_str = ' '.join(f'{b:02x}' for b in code)
                    
                    best_instrs.append({
                        'address': curr,
                        'bytes': bytes_str,
                        'mnemonic': mnemonic,
                        'operands': operands,
                        'loop_count': self.visit_counts.get(curr, 0),
                        'is_current': (curr == pc),
                        'is_breakpoint': (curr in breakpoints)
                    })
                    curr += instr_size
                except:
                    curr += 2
                 
        # Filter to requested window
        # Find index of PC
        pc_idx = -1
        for i, item in enumerate(best_instrs):
            if item['address'] == pc: 
                pc_idx = i
                break
                
        if pc_idx != -1:
            start_idx = max(0, pc_idx - before)
            end_idx = min(len(best_instrs), pc_idx + after + 1)
            instructions = best_instrs[start_idx:end_idx]
        else:
            instructions = best_instrs[:before+after] # Fallback
            
        return instructions


