from unicorn import *
from unicorn.mips_const import *
from capstone import *
import sys

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
        self.trace_instructions = False
        self.stop_instr = None
        self.break_on_printf = False
        self.max_instructions = 10000000
        self.is_syncing = False

        self._init_unicorn()
        self._init_capstone()

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
        # Track visit count
        if address not in self.visit_counts:
            self.visit_counts[address] = 0
        self.visit_counts[address] += 1
        
        if self.trace_instructions:
            code_bytes = uc.mem_read(address, size)
            try:
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

                # Run!
                self.mu.emu_start(cur_pc, end_addr)
                
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
              
             # Run 1 instruction
             self.mu.emu_start(cur_pc, end_addr, count=1)
             
        except UcError as e:
            self.log(f"Unicorn Error: {e}")
            self.log(f"PC at error: {hex(self.mu.reg_read(UC_MIPS_REG_PC))}")
        except Exception as e:
            self.log(f"Error: {e}")
