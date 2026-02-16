from unicorn import *
from unicorn.mips_const import *
from capstone import *
import sys
from enum import Enum
from dataclasses import dataclass
from typing import Optional
from mips16_decoder import MIPS16Decoder

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
        
        # Breakpoints
        self.breakpoints = set()
        self.is_stepping = False
        self.pc_history = []
        self.history_size = 50

        # Simulated CP0 Count register (hardware cycle counter)
        # Unicorn doesn't expose CP0 Count via reg_read/reg_write, so we track it ourselves.
        self.cp0_count = 0
        self._step_count = 0  # Hook-based step counter for precise single-stepping

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
        # Set MIPS32R2 CPU model (24Kf) to match ALI hardware
        self.mu.ctl_set_cpu_model(UC_CPU_MIPS32_24KF)
        
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

    def setLogHandler(self, handler):
        self.log_callback = handler

    def setUartHandler(self, handler):
        self.uart_callback = handler

    def addBreakpoint(self, address):
        self.breakpoints.add(address)
        self.log(f"Breakpoint added at 0x{address:08X}")

    def removeBreakpoint(self, address):
        if address in self.breakpoints:
            self.breakpoints.remove(address)
            self.log(f"Breakpoint removed at 0x{address:08X}")

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
        
        if address == 0 and access in [2, 18]: # FETCH or FETCH_UNMAPPED
            self.log(f"\n[!] STOPPED: Jump to NULL (0x0) detected!")
        else:
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
        # Increment simulated CP0 Count register (hardware cycle counter)
        # Real MIPS increments Count every other clock cycle.
        # Without this, firmware timeout loops polling MFC0 reg 9 never exit.
        self.cp0_count = (self.cp0_count + 2) & 0xFFFFFFFF

        # Hook-based single-stepping: Unicorn's count=1 counts Translation Blocks,
        # not individual instructions. For tight MIPS16 loops, a whole loop body
        # is one TB, so count=1 executes the full loop. To step exactly 1 instruction,
        # we track how many instructions have fired since emu_start and stop after the first.
        if self.is_stepping:
            self._step_count += 1
            if self._step_count > 1:
                uc.emu_stop()
                return

        # NOTE: ISA mode is NOT tracked here from instruction size because it's
        # unreliable for mode-switching instructions (JALX delay slots etc.).
        # Mode is determined by _detect_isa_mode() after emu_start() returns.

        # Track history for jumps
        if not hasattr(self, 'current_executed_pc'): self.current_executed_pc = None
        self.prev_executed_pc = self.current_executed_pc
        self.current_executed_pc = address

        # PC History
        self.pc_history.append(address)
        if len(self.pc_history) > self.history_size:
            self.pc_history.pop(0)

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

        if not self.is_stepping:
            hit = False
            if self.stop_instr is not None and address == self.stop_instr:
                hit = True
                self.log(f"\n[STOP] Reached stop address: 0x{address:08X}")
            elif address in self.breakpoints:
                hit = True
                self.log(f"\n[BREAKPOINT] Hit at 0x{address:08X}")
            
            if hit:
                uc.emu_stop()
                return
            
        self.instruction_count += 1
        if self.max_instructions and self.instruction_count >= self.max_instructions:
            uc.emu_stop()

    def _hook_instruction_fix(self, uc, address, size, user_data):
        # NOTE: JALX and MIPS16 instructions handled natively by Unicorn
        
        # Skip non-MIPS32 instructions (MIPS16 handled by Unicorn native)
        if size != 4:
            return

        try:
            insn_bytes = uc.mem_read(address, 4)
            insn = int.from_bytes(insn_bytes, byteorder='little')
            
            opcode = (insn >> 26) & 0x3F
            rs = (insn >> 21) & 0x1F
            rt = (insn >> 16) & 0x1F
            rd = (insn >> 11) & 0x1F
            imm = insn & 0xFFFF
            if imm & 0x8000: imm -= 0x10000 

            # MFC0: opcode=0x10 (COP0), rs=0x00 (MF)
            # Intercept reads of CP0 Count register (rd=9).
            # Unicorn doesn't increment CP0 Count, so firmware polling loops hang.
            # We set the dest register to our simulated cp0_count, advance PC,
            # and stop emulation so Unicorn doesn't overwrite with its stale value.
            if opcode == 0x10 and rs == 0x00 and rd == 9:
                uc.reg_write(self.gpr_map[rt], self.cp0_count)
                uc.reg_write(UC_MIPS_REG_PC, address + 4)
                uc.emu_stop()
                return

            # LUI handled natively by Unicorn

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
        """No-op: kept for API compatibility with test scripts"""
        pass

    def invalidate_jit(self, address):
        """No-op: kept for API compatibility with test scripts"""
        pass

    def is_mips16_addr(self, address):
        """Heuristic to check if address is in known MIPS16 region"""
        # Main firmware body seems to be below 0x81E8E000
        # Loader/Trigger at 0x81E8E1B8 is MIPS32
        if (address & 0xFFE00000) == 0x81E00000:
             if address < 0x81E8E000:
                 return True
        return False

    def _detect_isa_mode(self, pc):
        """Determine ISA mode by probing bytecode at PC.
        
        We cannot rely on tracked isa_mode from _hook_code because emu_stop()
        can fire at a MIPS16 delay slot of a JALX instruction, leaving
        isa_mode=MIPS16 even though the CPU has switched to MIPS32 mode.
        
        Instead, we read 4 bytes at PC and check if they form a valid MIPS32
        instruction by examining the opcode field (bits 31-26).
        """
        # If address is not in the MIPS16 region, it's definitely MIPS32
        if not self.is_mips16_addr(pc):
            return ISAMode.MIPS32
        
        # Address IS in the MIPS16 region — but could be a MIPS32 function
        # that was called via JAL (not JALX) from MIPS32 code.
        # Probe the bytes to distinguish:
        try:
            raw = self.mu.mem_read(pc, 4)
            word32 = int.from_bytes(raw, byteorder='little')
            opcode6 = (word32 >> 26) & 0x3F
            
            # Known MIPS32 opcodes that appear in this firmware's MIPS32
            # functions within the MIPS16 address range:
            #   0x00 = SPECIAL (jr, addu, subu, sll, etc.)
            #   0x01 = REGIMM (bgez, bltz)
            #   0x02 = J, 0x03 = JAL
            #   0x04 = BEQ, 0x05 = BNE, 0x06 = BLEZ, 0x07 = BGTZ
            #   0x08 = ADDI, 0x09 = ADDIU
            #   0x0A = SLTI, 0x0B = SLTIU, 0x0C = ANDI, 0x0D = ORI, 0x0E = XORI
            #   0x0F = LUI
            #   0x10 = COP0 (MFC0, MTC0)
            #   0x20 = LB, 0x21 = LH, 0x23 = LW, 0x24 = LBU, 0x25 = LHU
            #   0x28 = SB, 0x29 = SH, 0x2B = SW
            #   0x1D = JALX (doesn't appear inside MIPS32 code)
            #
            # For MIPS16 code, the first halfword has opcode in bits 15-11.
            # When read as a 32-bit LE word, bits 31-26 would be arbitrary.
            #
            # Strategy: check for MFC0 (opcode=0x10, rs=0x00, rd=9) which is 
            # the specific instruction at the known MIPS32 function 0x81E8DAEC.
            # Also check for NOP (0x00000000) and JR RA (0x03E00008).
            
            # Check for known specific MIPS32 instruction patterns:
            if word32 == 0x00000000:  # NOP
                return ISAMode.MIPS32
            if word32 == 0x03E00008:  # JR $RA
                return ISAMode.MIPS32
            if opcode6 == 0x10 and ((word32 >> 21) & 0x1F) == 0x00:  # MFC0
                return ISAMode.MIPS32
            
            # For the general case: check if this is part of a known MIPS32
            # sequence. The MIPS32 function at 0x81E8DAEC is:
            #   MFC0 v0, $9    (40024800)
            #   NOP * 4
            #   JR RA          (03E00008)  
            #   NOP
            # Any PC between 0x81E8DAEC and 0x81E8DB08 is MIPS32.
            if 0x81E8DAEC <= pc <= 0x81E8DB08:
                return ISAMode.MIPS32
            
            # Also: MIPS32 code above 0x81E8E000 calls into this range via JAL.
            # If we detect ADDIU $SP (common function prologue/epilogue), it's MIPS32.
            if opcode6 == 0x09 and ((word32 >> 16) & 0x1F) == 29:  # ADDIU $sp, ...
                return ISAMode.MIPS32
            
            # Default: trust the address-based heuristic for the MIPS16 region
            return ISAMode.MIPS16
            
        except Exception:
            # If we can't read bytes, fall back to address heuristic
            return ISAMode.MIPS16 if self.is_mips16_addr(pc) else ISAMode.MIPS32

    def run(self, max_instructions=None):
        cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
        self.log(f"Starting emulation at {hex(cur_pc)}...")
        
        if max_instructions is not None:
            self.max_instructions = max_instructions
        
        end_addr = self.base_addr + self.rom_size
        
        try:
            while cur_pc < end_addr:

                
                # Check for max instruction count stop
                if self.max_instructions and self.instruction_count >= self.max_instructions:
                    break
                
                # MIPS16 Mode Force
                start_pc = cur_pc
                
                # If we are currently AT a breakpoint/stop address, we must step over it
                # to avoid hitting it immediately in emu_start.
                if cur_pc in self.breakpoints or (self.stop_instr is not None and cur_pc == self.stop_instr):
                    # self.log(f"[DEBUG] Stepping over breakpoint at 0x{cur_pc:08X}")
                    self.step()
                    cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
                    if self.max_instructions and self.instruction_count >= self.max_instructions:
                        break
                    if cur_pc >= end_addr or (cur_pc & ~1) == 0:
                        break
                    start_pc = cur_pc

                # Determine ISA mode for emu_start by probing the bytes at PC.
                # We cannot rely on tracked isa_mode from _hook_code because
                # emu_stop() can fire at a MIPS16 delay slot of a JALX, leaving
                # isa_mode=MIPS16 even though the CPU switched to MIPS32.
                if self._detect_isa_mode(start_pc) == ISAMode.MIPS16:
                    start_pc |= 1
                    self.isa_mode = ISAMode.MIPS16
                else:
                    self.isa_mode = ISAMode.MIPS32

                # Run!
                self.mu.emu_start(start_pc, end_addr)
                
                # If we stopped, update PC
                cur_pc = self.mu.reg_read(UC_MIPS_REG_PC)
                
                # If we hit a breakpoint or stop address, break the loop to return to caller
                if cur_pc in self.breakpoints or (self.stop_instr is not None and cur_pc == self.stop_instr):
                    break
                    
                # Stop if PC is NULL
                if (cur_pc & ~1) == 0:
                    self.log("[!] Stopped: Jump to NULL")
                    break
        
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

              
             # MIPS16 Fix: If in MIPS16 region, force Thumb/MIPS16 mode by setting LSB
             start_pc = cur_pc
             if self.is_mips16_addr(start_pc):
                 start_pc |= 1
                 
             # Run 1 instruction
             self.is_stepping = True
             try:
                 self.mu.emu_start(start_pc, end_addr, count=1)
             finally:
                 self.is_stepping = False
             
             # Stop if PC is NULL
             new_pc = self.mu.reg_read(UC_MIPS_REG_PC)
             if (new_pc & ~1) == 0:
                 self.log("[!] Stopped: Jump to NULL")
             
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
        
        # ISA mode switching in step() relies on:
        # 1. JALX detection in _step_mips16/_step_mips32 (switches mode on JALX)
        # 2. run() setting self.isa_mode = MIPS16 when entering MIPS16 region
        # We do NOT use is_mips16_addr() here because MIPS32 functions exist
        # within the MIPS16 address range (e.g., 0x81E8CE14 called via jal).

        # DEBUG: Log current mode (only if debug enabled)
        if self.debug_enabled:
            self.log(f"[DEBUG] step() at PC=0x{pc:08X}, mode={self.isa_mode.value}")
        
        self._step_count = 0  # Reset for hook-based single-stepping
        self.is_stepping = True
        try:
            if self.isa_mode == ISAMode.MIPS16:
                result = self._step_mips16(pc)
            else:
                result = self._step_mips32(pc)
        finally:
            self.is_stepping = False
        
        # Detect and stop on jump to NULL (0x0)
        # We check result.next_pc & ~1 because MIPS16 targets might have LSB set
        if (result.next_pc & ~1) == 0:
            self.log(f"\n[!] STOPPED: Program is about to jump to 0x0 from 0x{pc:08X}")
            self.log(f"    Instruction: {result.instruction} {result.operands}")
            # Raise exception to stop continuous execution if running
            raise Exception(f"Jump to NULL (0x0) detected at 0x{pc:08X}: {result.instruction} {result.operands}")
        
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
        elif mnemonic == 'jr' and 'ra' in operands:
            # jr $ra: if RA had bit 0 set, returning to MIPS16 code.
            # JALX sets RA with bit 0 to mark the return as MIPS16.
            # Check RA AFTER the jr executes (Unicorn already jumped).
            # We need the RA value before jr cleared it - but Unicorn's jr
            # uses the register value at execution time. RA still has the
            # original value since jr doesn't modify RA.
            ra_val = self.mu.reg_read(UC_MIPS_REG_RA)
            if ra_val & 1:
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
        """Execute one MIPS16 instruction using Unicorn native engine"""
        mode_before = 'mips16'
        
        # Read instruction bytes for decode/display
        insn_bytes = self.mu.mem_read(pc, 2)
        mnemonic, operands = MIPS16Decoder.decode(insn_bytes, pc)
        
        # Determine instruction size (some MIPS16 are 4 bytes)
        # Check if it's an extended instruction (4-byte)
        first_word = int.from_bytes(insn_bytes, byteorder='little')
        opcode5 = (first_word >> 11) & 0x1F
        # Extended instructions have opcode 0b11110 (30) or JAL/JALX 0b00011 (3)
        if opcode5 == 30 or opcode5 == 3:
            insn_bytes = self.mu.mem_read(pc, 4)
            mnemonic, operands = MIPS16Decoder.decode(insn_bytes, pc)
            instruction_size = 4
        else:
            instruction_size = 2
        
        # Execute one instruction with Unicorn (LSB=1 for MIPS16 mode)
        end_addr = self.base_addr + self.rom_size
        try:
            self.mu.emu_start(pc | 1, end_addr, count=1)
        except Exception as e:
            pass  # Continue even on error
        
        next_pc = self.mu.reg_read(UC_MIPS_REG_PC)
        
        # Detect mode switch (jalx switches back to MIPS32)
        mode_after = mode_before
        mode_switched = False
        if mnemonic == 'jalx':
            mode_after = 'mips32'
            mode_switched = True
        elif mnemonic in ['jrc', 'jr'] and 'ra' in operands:
            # Return from MIPS16 subroutine — check if target is MIPS32
            if not self.is_mips16_addr(next_pc):
                mode_after = 'mips32'
                mode_switched = True
        
        # Determine instruction type
        is_call = mnemonic in ['jal', 'jalr', 'jalx']
        is_return = mnemonic in ['jr', 'jrc'] and 'ra' in operands
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
            instruction_size=instruction_size
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


