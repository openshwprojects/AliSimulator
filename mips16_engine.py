"""
MIPS16 Native Execution Engine

Executes MIPS16 instructions natively without relying on Unicorn.
Provides clean execution results including mode transitions.
"""

from dataclasses import dataclass
from typing import Tuple, Optional
from mips16_decoder import MIPS16Decoder


@dataclass
class ExecutionResult:
    """Result of executing a MIPS16 instruction"""
    next_pc: int
    mode_switch: Optional[str] = None  # 'mips32' if switching to MIPS32, None otherwise
    is_branch: bool = False
    is_call: bool = False
    is_return: bool = False
    branch_taken: bool = False
    instruction_size: int = 2


class MIPS16Engine:
    """Native MIPS16 instruction execution engine"""
    
    def __init__(self, memory_reader, memory_writer, register_reader, register_writer):
        """
        Initialize MIPS16 engine with callbacks for memory/register access
        
        Args:
            memory_reader: function(address, size) -> bytes
            memory_writer: function(address, data: bytes)
            register_reader: function(reg_name: str) -> int
            register_writer: function(reg_name: str, value: int)
        """
        self.mem_read = memory_reader
        self.mem_write = memory_writer
        self.reg_read = register_reader
        self.reg_write = register_writer
        
    def execute(self, address: int) -> ExecutionResult:
        """
        Execute one MIPS16 instruction at the given address
        
        Args:
            address: PC address of instruction to execute
            
        Returns:
            ExecutionResult with next PC and execution details
        """
        # Read first 2 bytes to determine instruction size
        first_word = self.mem_read(address, 2)
        word1 = int.from_bytes(first_word, byteorder='little')
        major_op = (word1 >> 11) & 0x1F
        
        # Check if this is a 4-byte instruction (JAL/JALX/EXTEND)
        is_4byte = (major_op == 0x03 or major_op == 0x1E)
        
        if is_4byte:
            insn_bytes = self.mem_read(address, 4)
            insn_size = 4
        else:
            insn_bytes = first_word
            insn_size = 2
            
        # Decode instruction
        mnemonic, operands = MIPS16Decoder.decode(insn_bytes, address)
        
        # Execute the instruction
        return self._execute_instruction(address, insn_bytes, insn_size, mnemonic, operands)
    
    def _get_reg_id(self, reg_name: str) -> str:
        """Map register name to canonical form"""
        return reg_name
    
    def _execute_instruction(self, address: int, insn_bytes: bytes, 
                            insn_size: int, mnemonic: str, operands: str) -> ExecutionResult:
        """Execute decoded instruction and return result"""
        
        # Default: just advance PC
        next_pc = address + insn_size
        result = ExecutionResult(next_pc=next_pc, instruction_size=insn_size)
        
        # NOP
        if mnemonic == "nop":
            return result
        
        # ADDIU rx, sp, imm
        if mnemonic == "addiu" and "sp" in operands:
            parts = operands.split(',')
            rx = parts[0]
            imm_str = parts[2]
            imm = int(imm_str, 0)
            sp_val = self.reg_read('sp')
            self.reg_write(rx, (sp_val + imm) & 0xFFFFFFFF)
            return result
        
        # ADDIU rx, rx, imm (or ADDIU rx, imm shorthand)
        if mnemonic == "addiu":
            parts = operands.split(',')
            rx = parts[0]
            if len(parts) == 3:
                # ADDIU rx, ry, imm
                ry = parts[1]
                imm_str = parts[2]
                imm = int(imm_str, 0)
                ry_val = self.reg_read(ry)
                self.reg_write(rx, (ry_val + imm) & 0xFFFFFFFF)
            else:
                # ADDIU rx, imm
                imm_str = parts[1]
                imm = int(imm_str, 0)
                rx_val = self.reg_read(rx)
                self.reg_write(rx, (rx_val + imm) & 0xFFFFFFFF)
            return result
        
        # LI rx, imm
        if mnemonic == "li":
            parts = operands.split(',')
            rx = parts[0]
            imm = int(parts[1], 0)
            self.reg_write(rx, imm & 0xFFFFFFFF)
            return result
        
        # MOVE dest, src
        if mnemonic == "move":
            parts = operands.split(',')
            dest = parts[0]
            src = parts[1]
            val = self.reg_read(src)
            self.reg_write(dest, val)
            return result
        
        # SEB / ZEB rx
        if mnemonic in ["seb", "zeb"]:
            rx = operands.strip()
            val = self.reg_read(rx) & 0xFF
            if mnemonic == "seb":
                # Sign extend byte
                if val & 0x80:
                    val |= 0xFFFFFF00
            self.reg_write(rx, val)
            return result
        
        # SLTI rx, imm
        if mnemonic == "slti":
            parts = operands.split(',')
            rx = parts[0]
            imm = int(parts[1].strip(), 0)
            # Sign extend 8-bit immediate
            if imm & 0x80:
                imm -= 0x100
            
            rx_val = self.reg_read(rx)
            # Convert to signed for comparison
            if rx_val & 0x80000000:
                rx_val -= 0x100000000
            
            res = 1 if rx_val < imm else 0
            self.reg_write('t8', res)
            return result
        
        # CMPI rx, imm
        if mnemonic == "cmpi":
            parts = operands.split(',')
            rx = parts[0]
            imm = int(parts[1].strip(), 0)
            rx_val = self.reg_read(rx)
            # CMPI sets T8 to comparison result
            res = 1 if rx_val == imm else 0
            self.reg_write('t8', res)
            return result
        
        # LW rx, offset(base)
        if mnemonic == "lw":
            parts = operands.split(',')
            rx = parts[0]
            offset_base = parts[1]
            
            if "(pc)" in offset_base:
                # PC-relative
                offset_str = offset_base.replace('(pc)', '')
                offset = int(offset_str.strip(), 0)
                base_addr = address & 0xFFFFFFFC
                target = base_addr + offset
            elif "(sp)" in offset_base:
                # SP-relative
                offset_str = offset_base.replace('(sp)', '')
                offset = int(offset_str.strip(), 0)
                target = self.reg_read('sp') + offset
            else:
                # Register relative
                offset_str = offset_base[:offset_base.index('(')]
                base_reg = offset_base[offset_base.index('(')+1:offset_base.index(')')]
                offset = int(offset_str.strip(), 0)
                target = self.reg_read(base_reg) + offset
            
            data = self.mem_read(target, 4)
            val = int.from_bytes(data, byteorder='little')
            self.reg_write(rx, val)
            return result
        
        # SW rx, offset(base)
        if mnemonic == "sw":
            parts = operands.split(',')
            rx = parts[0]
            offset_base = parts[1]
            
            if "(sp)" in offset_base:
                # SP-relative
                offset_str = offset_base.replace('(sp)', '')
                offset = int(offset_str.strip(), 0)
                target = self.reg_read('sp') + offset
            else:
                # Register relative
                offset_str = offset_base[:offset_base.index('(')]
                base_reg = offset_base[offset_base.index('(')+1:offset_base.index(')')]
                offset = int(offset_str.strip(), 0)
                target = self.reg_read(base_reg) + offset
            
            val = self.reg_read(rx)
            data = val.to_bytes(4, byteorder='little')
            self.mem_write(target, data)
            return result
        
        # LBU ry, offset(rx)
        if mnemonic == "lbu":
            parts = operands.split(',')
            ry = parts[0]
            offset_base = parts[1]
            offset_str = offset_base[:offset_base.index('(')]
            base_reg = offset_base[offset_base.index('(')+1:offset_base.index(')')]
            offset = int(offset_str.strip(), 0)
            target = self.reg_read(base_reg) + offset
            
            data = self.mem_read(target, 1)
            val = int.from_bytes(data, byteorder='little', signed=False)
            self.reg_write(ry, val)
            return result
        
        # SB ry, offset(rx)
        if mnemonic == "sb":
            parts = operands.split(',')
            ry = parts[0]
            offset_base = parts[1]
            offset_str = offset_base[:offset_base.index('(')]
            base_reg = offset_base[offset_base.index('(')+1:offset_base.index(')')]
            offset = int(offset_str.strip(), 0)
            target = self.reg_read(base_reg) + offset
            
            val = self.reg_read(ry) & 0xFF
            data = val.to_bytes(1, byteorder='little')
            self.mem_write(target, data)
            return result
        
        # ADDU rz, rx, ry
        if mnemonic == "addu":
            parts = operands.split(',')
            rz = parts[0]
            rx = parts[1]
            ry = parts[2]
            result_val = (self.reg_read(rx) + self.reg_read(ry)) & 0xFFFFFFFF
            self.reg_write(rz, result_val)
            return result
        
        # SLTU rz, rx, ry
        if mnemonic == "sltu":
            parts = operands.split(',')
            rz = parts[0]
            rx = parts[1]
            ry = parts[2]
            rx_val = self.reg_read(rx)
            ry_val = self.reg_read(ry)
            result_val = 1 if rx_val < ry_val else 0
            self.reg_write(rz, result_val)
            return result
        
        # AND rx, ry
        if mnemonic == "and":
            parts = operands.split(',')
            rx = parts[0]
            ry = parts[1]
            result_val = self.reg_read(rx) & self.reg_read(ry)
            self.reg_write(rx, result_val)
            return result
        
        # OR rx, ry
        if mnemonic == "or":
            parts = operands.split(',')
            rx = parts[0]
            ry = parts[1]
            result_val = self.reg_read(rx) | self.reg_read(ry)
            self.reg_write(rx, result_val)
            return result
        
        # XOR rx, ry
        if mnemonic == "xor":
            parts = operands.split(',')
            rx = parts[0]
            ry = parts[1]
            result_val = self.reg_read(rx) ^ self.reg_read(ry)
            self.reg_write(rx, result_val)
            return result
        
        # NOT rx, ry
        if mnemonic == "not":
            parts = operands.split(',')
            rx = parts[0]
            ry = parts[1]
            result_val = (~self.reg_read(ry)) & 0xFFFFFFFF
            self.reg_write(rx, result_val)
            return result
        
        # BEQZ rx, target
        if mnemonic == "beqz":
            parts = operands.split(',')
            rx = parts[0]
            target = int(parts[1].strip(), 0)
            if self.reg_read(rx) == 0:
                result.next_pc = target
                result.branch_taken = True
            result.is_branch = True
            return result
        
        # BNEZ rx, target
        if mnemonic == "bnez":
            parts = operands.split(',')
            rx = parts[0]
            target = int(parts[1].strip(), 0)
            if self.reg_read(rx) != 0:
                result.next_pc = target
                result.branch_taken = True
            result.is_branch = True
            return result
        
        # BTEQZ target
        if mnemonic == "bteqz":
            target = int(operands.strip(), 0)
            if self.reg_read('t8') == 0:
                result.next_pc = target
                result.branch_taken = True
            result.is_branch = True
            return result
        
        # BTNEZ target
        if mnemonic == "btnez":
            target = int(operands.strip(), 0)
            if self.reg_read('t8') != 0:
                result.next_pc = target
                result.branch_taken = True
            result.is_branch = True
            return result
        
        # B target (unconditional branch)
        if mnemonic == "b":
            target = int(operands.strip(), 0)
            result.next_pc = target
            result.is_branch = True
            result.branch_taken = True
            return result
        
        # JAL target (4-byte instruction)
        if mnemonic == "jal":
            target = int(operands.strip(), 0)
            # Save return address
            self.reg_write('ra', address + 4)
            result.next_pc = target
            result.is_call = True
            return result
        
        # JALX target (4-byte instruction, switches to MIPS32)
        if mnemonic == "jalx":
            target = int(operands.strip(), 0)
            # Save return address
            self.reg_write('ra', address + 4)
            result.next_pc = target
            result.is_call = True
            result.mode_switch = 'mips32'  # Switch to MIPS32 mode
            return result
        
        # JR rx / JRC ra
        if mnemonic in ["jr", "jrc"]:
            if mnemonic == "jrc":
                target = self.reg_read('ra')
            else:
                rx = operands.strip()
                target = self.reg_read(rx)
            
            result.next_pc = target
            result.is_return = True
            
            # NOTE: JR/JRC do NOT change ISA mode
            # Only JALX explicitly switches modes
            # The target address alone doesn't tell us the mode
            
            return result
        
        # SAVE / RESTORE
        if mnemonic in ["save", "restore"]:
            # These manipulate stack, we need to parse the operands
            # Format: "0x20,ra,s0-s1"
            parts = operands.split(',')
            framesize = int(parts[0], 0)
            
            if mnemonic == "save":
                # Decrement SP
                sp_val = self.reg_read('sp')
                new_sp = (sp_val - framesize) & 0xFFFFFFFF
                self.reg_write('sp', new_sp)
                
                # Save registers (simplified - full implementation would save to stack)
                # For now, just update SP
            else:
                # RESTORE: increment SP
                sp_val = self.reg_read('sp')
                new_sp = (sp_val + framesize) & 0xFFFFFFFF
                self.reg_write('sp', new_sp)
            
            return result
        
        # If we get here, instruction is not implemented
        # Return default (just advance PC)
        return result
