"""
MIPS16 Instruction Decoder
Decodes 16-bit MIPS16 instructions into readable mnemonics and operands
"""

class MIPS16Decoder:
    # Register names for MIPS16
    REGS = ['$0', '$1', '$2', '$v0', '$v1', '$a0', '$a1', '$a2']
    REGS_EXTENDED = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
                     't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
                     's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
                     't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra']
    
    @staticmethod
    def decode(opcode_bytes):
        """
        Decode a 16-bit MIPS16 instruction
        Args:
            opcode_bytes: bytes object of length 2
        Returns:
            (mnemonic, operands) tuple
        """
        if len(opcode_bytes) != 2:
            return ("???", "")
        
        # Read as little-endian 16-bit value
        insn = int.from_bytes(opcode_bytes, byteorder='little')
        
        # Extract fields
        b0 = opcode_bytes[0]
        b1 = opcode_bytes[1]
        
        # Major opcode (bits 11-15 of insn after little-endian read)
        major_op = (insn >> 11) & 0x1F
        
        # Common field extractions
        rx = (insn >> 8) & 0x7
        ry = (insn >> 5) & 0x7
        rz = (insn >> 2) & 0x7
        funct = insn & 0x1F
        imm3 = insn & 0x7
        imm4 = insn & 0xF
        imm5 = insn & 0x1F
        imm8 = insn & 0xFF
        imm11 = insn & 0x7FF
        
        # Register names
        def reg(idx):
            if 0 <= idx < 8:
                return ['s0', 's1', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3'][idx]
            elif idx < 32:
                return MIPS16Decoder.REGS_EXTENDED[idx]
            return f'r{idx}'
        
        # Special case: SAVE/RESTORE instructions
        # From Ghidra: f7 64 => save 0x38,ra,s0-s1
        # In little endian: 0x64f7
        # Pattern for SAVE: bits [15:6] = 0b0110_0100_11 (0x193)
        # Full mask: 0xFFC0 (check bits 15:6)
        # Value: 0x64C0 for SAVE base pattern
        
        # Actually analyze the pattern more carefully:
        # f7 64 = 0x64f7
        # Binary: 0110_0100_1111_0111
        # Let's check if bits [15:11] = 01100 = 0x0C (major opcode 12)
        # and bits [10:8] = 100 (subop 4)
        
        # SAVE/RESTORE use I8 format with major = 0x0C and subfunc in bits [10:8]
        # Pattern: 0110_0xxx_xxxx_xxxx where first x's determine SAVE vs RESTORE
        if major_op == 0x0C:  # I8 format
            subfunc = (insn >> 8) & 0x7
            if subfunc == 0x4:  # SAVE
                xsregs = (insn >> 4) & 0xF
                aregs = xsregs & 0x3  # Low 2 bits for args
                sregs = (xsregs >> 2) & 0x3  # High 2 bits for s-regs
                framesize = (insn & 0xF) << 3
                
                # Build register list
                regs = "ra"
                total_sregs = sregs + aregs
                if total_sregs > 0:
                    if total_sregs == 1:
                        regs += ",s0"
                    else:
                        regs += f",s0-s{total_sregs-1}"
                
                return ("save", f"0x{framesize:x},{regs}")
            
            elif subfunc == 0x5:  # RESTORE
                xsregs = (insn >> 4) & 0xF
                aregs = xsregs & 0x3
                sregs = (xsregs >> 2) & 0x3
                framesize = (insn & 0xF) << 3
                
                regs = "ra"
                total_sregs = sregs + aregs
                if total_sregs > 0:
                    if total_sregs == 1:
                        regs += ",s0"
                    else:
                        regs += f",s0-s{total_sregs-1}"
                
                return ("restore", f"0x{framesize:x},{regs}")
            
            elif subfunc == 0x0:  # BTEQZ
                offset_raw = insn & 0xFF
                if offset_raw & 0x80:
                    offset = -(256 - offset_raw) * 2
                else:
                    offset = offset_raw * 2
                return ("bteqz", f"0x{offset:x}")
            
            elif subfunc == 0x1:  # BTNEZ
                offset_raw = insn & 0xFF
                if offset_raw & 0x80:
                    offset = -(256 - offset_raw) * 2
                else:
                    offset = offset_raw * 2
                return ("btnez", f"0x{offset:x}")
            
            elif subfunc == 0x2:  # SW ra, offset(sp)
                offset = imm8 * 4
                return ("sw", f"ra,{offset}(sp)")
            
            elif subfunc == 0x3:  # ADDIU sp, imm8
                imm_signed = MIPS16Decoder._sign_extend(imm8, 8) * 8
                return ("addiu", f"sp,sp,{imm_signed}")
            
            elif subfunc == 0x6:  # MOVE r32, rz
                r32 = (insn >> 3) & 0x1F
                r_src = (insn & 0x7) + 16
                return ("move", f"{reg(r32)},{reg(r_src)}")
            
            elif subfunc == 0x7:  # MOVE ry, r32
                r32 = (insn >> 3) & 0x1F
                r_dst = ((insn >> 5) & 0x7) + 16
                return ("move", f"{reg(r_dst)},{reg(r32)}")
        
        # LI instruction: 00 6a => li v0, 0x0
        # Pattern: 0110_1xxx_xxxx_xxxx for LI format
        # 0x6a00 (little endian of 00 6a) = 0110101000000000
        if (insn & 0xF800) == 0x6800:  # LI instruction
            imm = insn & 0xFF
            rd_code = (insn >> 8) & 0x7
            rd = reg(rd_code + 16)  # MIPS16 uses offset register numbering
            return ("li", f"{rd},0x{imm:x}")
        
        # SW instruction: 06 d2 => sw $s2,0x18(sp)
        # Pattern: 1101_00xx_xxxx_xxxx for SW rx, offset(sp)
        if (insn & 0xF800) == 0xD000:
            offset = (insn & 0xFF) * 4
            rx_code = (insn >> 8) & 0x7
            rx_reg = reg(rx_code + 16)
            return ("sw", f"{rx_reg},0x{offset:x}(sp)")
        
        # SW instruction: d2 format => sw ry, offset(rx)
        # Pattern: 1101_1xxx_xxxx_xxxx for SW ry, offset(rx)
        if (insn & 0xF800) == 0xD800:
            offset = (insn & 0x1F) * 4
            ry_code = (insn >> 5) & 0x7
            rx_code = (insn >> 8) & 0x7
            ry_reg = reg(ry_code + 16)
            rx_reg = reg(rx_code + 16)
            return ("sw", f"{ry_reg},0x{offset:x}({rx_reg})")
        
        # LW instruction: 75 b2 => lw v0, 0x1d4(pc)
        # Or: 9a 40 => lw v0, offset(rx)
        # Pattern: 1011_0xxx_xxxx_xxxx for LW ry, offset(rx)
        if (insn & 0xF800) == 0xB000:
            offset = (insn & 0x1F) * 4
            ry_code = (insn >> 5) & 0x7
            rx_code = (insn >> 8) & 0x7
            ry_reg = reg(ry_code + 16)
            rx_reg = reg(rx_code + 16)
            return ("lw", f"{ry_reg},0x{offset:x}({rx_reg})")
        
        # LW from PC: Pattern 1011_1xxx_xxxx_xxxx
        if (insn & 0xF800) == 0xB800:
            offset = (insn & 0xFF) * 4
            rx_code = (insn >> 8) & 0x7
            rx_reg = reg(rx_code + 16)
            return ("lw", f"{rx_reg},0x{offset:x}(pc)")
        
        # LW from SP: Pattern 1001_1xxx_xxxx_xxxx
        if (insn & 0xF800) == 0x9800:
            offset = (insn & 0xFF) * 4
            rx_code = (insn >> 8) & 0x7
            rx_reg = reg(rx_code + 16)
            return ("lw", f"{rx_reg},0x{offset:x}(sp)")
        
        # LBU instruction: 80 a2 => lbu a0, 0x0(v0)
        # Pattern: 1010_0xxx_xxxx_xxxx for LBU
        if (insn & 0xF800) == 0xA000:
            offset = insn & 0x1F
            ry_code = (insn >> 5) & 0x7
            rx_code = (insn >> 8) & 0x7
            ry_reg = reg(ry_code + 16)
            rx_reg = reg(rx_code + 16)
            return ("lbu", f"{ry_reg},0x{offset:x}({rx_reg})")
        
        # RR format instructions (major opcode 0x1D = 11101)
        # Pattern: 1110_1xxx_xxxx_xxxx
        if (insn & 0xF800) == 0xE800:
            funct_rr = insn & 0x1F
            rx_code = (insn >> 8) & 0x7
            ry_code = (insn >> 5) & 0x7
            
            # Specific RR instructions
            if funct_rr == 0x00:  # JR rx
                if rx_code == 7:
                    return ("jr", "ra")
                return ("jr", f"{reg(rx_code+16)}")
            elif funct_rr == 0x01:  # JR ra (JALRC in some docs)
                return ("jr", "ra")
            elif funct_rr == 0x02:  # JALR
                return ("jalr", f"{reg(rx_code+16)}")
            elif funct_rr == 0x0C:  # AND (actually MFHI in some encodings)
                return ("and", f"{reg(rx_code+16)},{reg(ry_code+16)}")
            elif funct_rr == 0x11:  # CMP (actually might be something else)
                # ec 91 might be a different pattern
                pass
            
            # Generic RR ops
            rr_ops = {
                0x0a: "slt", 0x0b: "sltu",
                0x0c: "sllv", 0x0e: "srlv", 0x0f: "srav",
                0x1a: "cmp", 0x1c: "neg", 0x1d: "and", 0x1e: "or", 0x1f: "xor"
            }
            
            if funct_rr in rr_ops:
                return (rr_ops[funct_rr], f"{reg(rx_code+16)},{reg(ry_code+16)}")
        
        # JAL instruction: Pattern 0_0011_xxxx_xxxx_xxxx (major = 0x03)
        # or 1_1111_xxxx_xxxx_xxxx (major = 0x1F)
        if major_op == 0x03 or major_op == 0x1F:
            target = insn & 0x7FF
            return ("jal", f"0x{target:x}")
        
        # NOP: 00 65 when it's actually a MOVE encoding that does nothing
        if insn == 0x6500:
            return ("_nop", "")
        
        # ADDIU sp, sp, imm
        if (insn >> 8) == 0x65 and (insn & 0xFF) == 0:
            return ("addiu", "sp,sp,0")
        
        # BEQZ/BNEZ branches
        if (insn & 0xF800) == 0x2000:  # BEQZ
            rx_code = (insn >> 8) & 0x7
            offset_raw = insn & 0xFF
            if offset_raw & 0x80:
                offset = -(256 - offset_raw) * 2
            else:
                offset = offset_raw * 2
            rx_reg = reg(rx_code + 16)
            return ("beqz", f"{rx_reg},0x{offset:x}")
        
        if (insn & 0xF800) == 0x2800:  # BNEZ
            rx_code = (insn >> 8) & 0x7
            offset_raw = insn & 0xFF
            if offset_raw & 0x80:
                offset = -(256 - offset_raw) * 2
            else:
                offset = offset_raw * 2
            rx_reg = reg(rx_code + 16)
            return ("bnez", f"{rx_reg},0x{offset:x}")
        
        # ADDIU rx, imm8: Pattern varies by major opcode
        if (insn & 0xF800) == 0x4800:
            rx_code = (insn >> 8) & 0x7
            imm_val = insn & 0xFF
            rx_reg = reg(rx_code + 16)
            return ("addiu", f"{rx_reg},0x{imm_val:x}")
        
        # SLL/SRL shift operations
        if major_op == 0x06:  # SLL
            shift = (insn >> 2) & 0x1F
            ry_code = (insn >> 5) & 0x7
            rx_code = (insn >> 8) & 0x7
            return ("sll", f"{reg(rx_code+16)},{reg(ry_code+16)},{shift}")
        
        if major_op == 0x07:  # SRL
            shift = (insn >> 2) & 0x1F
            ry_code = (insn >> 5) & 0x7
            rx_code = (insn >> 8) & 0x7
            return ("srl", f"{reg(rx_code+16)},{reg(ry_code+16)},{shift}")
        
        # ADDU/SUBU arithmetic
        if major_op == 0x02:  # ADDU
            return ("addu", f"{reg(rz+16)},{reg(rx+16)},{reg(ry+16)}")
        
        if major_op == 0x03:  # SUBU (but conflicts with JAL?)
            # Actually JAL is also major 0x03, need to check further
            pass
        
        # Default: show as unknown with hex code
        return (f"?_{insn:04x}", "")
    
    
    
    @staticmethod
    def _sign_extend(value, bits):
        """Sign extend a value"""
        sign_bit = 1 << (bits - 1)
        if value & sign_bit:
            return value - (1 << bits)
        return value
