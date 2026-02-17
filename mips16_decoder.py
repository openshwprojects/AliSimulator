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
    def reg_3bit(idx):
        """Map 3-bit MIPS16 register field to name"""
        # 0->s0, 1->s1, 2->v0, 3->v1, 4->a0, 5->a1, 6->a2, 7->a3
        return ['s0', 's1', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3'][idx & 7]

    @staticmethod
    def reg_5bit(idx):
        """Map 5-bit MIPS32 register index to name"""
        if idx < 32:
            return MIPS16Decoder.REGS_EXTENDED[idx]
        return f'r{idx}'

    @staticmethod
    def decode(opcode_bytes, address=0):
        """
        Decode a 16-bit or 32-bit MIPS16 instruction
        Args:
            opcode_bytes: bytes object (length 2 or 4)
            address: current instruction address (needed for JAL calculation)
        Returns:
            (mnemonic, operands) tuple
        """
        if len(opcode_bytes) == 4:
            # Handle 32-bit MIPS16 instructions (JAL, JALX, extended instructions)
            word1 = int.from_bytes(opcode_bytes[0:2], byteorder='little')
            word2 = int.from_bytes(opcode_bytes[2:4], byteorder='little')
            
            major_op = (word1 >> 11) & 0x1F
            
            if major_op == 0x03: # JAL / JALX
                x_bit = (word1 >> 10) & 1
                
                # Formula derived from 0x81E84290 (1b43 1090) and target 0x81E84240 (007A...)
                # Word 1 (1B43) bits:
                # 4-0: 03 (3)   -> High 5 bits (25-21)
                # 9-5: 1A (26)  -> Next 5 bits (20-16)
                # Word 2 (1090) -> Low 16 bits (15-0)
                
                imm25_21 = word1 & 0x1F
                imm20_16 = (word1 >> 5) & 0x1F
                
                target_index = (imm25_21 << 21) | (imm20_16 << 16) | word2
                target_addr = (address & 0xF0000000) | (target_index << 2)
                
                mnemonic = "jal" if x_bit == 0 else "jalx"
                return (mnemonic, f"0x{target_addr:x}")

            # EXTEND instructions (0xF000) - Major Op 0x1E (11110)
            if major_op == 0x1E:
                 # EXTEND format: 11110 imm10:5 imm15:11 imm4:0
                 # Unscramble immediate:
                 # word1 = 0xF0B0 -> 11110 00010 110000 -> ext_10_5=0x05, ext_15_11=0x10.
                 # ext_10_5  = (word1 >> 5) & 0x3F ? No, 0x1F is 5 bits. 0x3F is 6 bits.
                 # Wait, bits 10-5 is 6 bits. Bits 4-0 is 5 bits. Total 11 bits.
                 # My previous analysis:
                 # Bits 10-5 of word1 -> Bits 10-5 of Result.
                 # Bits 4-0 of word1 -> Bits 15-11 of Result.
                 
                 ext_10_5 = (word1 >> 5) & 0x3F # Bits 10-5 (6 bits)
                 ext_15_11 = word1 & 0x1F       # Bits 4-0 (5 bits)
                 
                 # Decode instruction in word2
                 insn = word2
                 op2 = (insn >> 11) & 0x1F
                 
                 # LBU (0x14) extended
                 if op2 == 0x14:
                     # LBU format: 10100 ry rx offset(5)
                     # Full Offset = (ext_15_11 << 11) | (ext_10_5 << 5) | imm5
                     imm5 = insn & 0x1F
                     full_imm = (ext_15_11 << 11) | (ext_10_5 << 5) | imm5
                     
                     # Sign extend 16-bit offset
                     if full_imm & 0x8000:
                         full_imm -= 0x10000
                         
                     rx_code = (insn >> 8) & 0x7
                     ry_code = (insn >> 5) & 0x7
                     rx = MIPS16Decoder.reg_3bit(rx_code)
                     ry = MIPS16Decoder.reg_3bit(ry_code)
                     
                     # MIPS16 LBU is ry, offset(rx)
                     return ("lbu", f"{ry},{hex(full_imm)}({rx})")
                     # Note: hex() handles negative sign correctly (-0x...)

                 # LHU (0x15) extended - Load Halfword Unsigned
                 if op2 == 0x15:
                     imm5 = insn & 0x1F
                     full_imm = (ext_15_11 << 11) | (ext_10_5 << 5) | imm5
                     if full_imm & 0x8000:
                         full_imm -= 0x10000
                     rx_code = (insn >> 8) & 0x7
                     ry_code = (insn >> 5) & 0x7
                     rx = MIPS16Decoder.reg_3bit(rx_code)
                     ry = MIPS16Decoder.reg_3bit(ry_code)
                     return ("lhu", f"{ry},{hex(full_imm)}({rx})")

                 # LW (0x13) extended
                 if op2 == 0x13:
                     # LW format: 10011 ry rx offset(5)
                     imm5 = insn & 0x1F
                     full_imm = (ext_15_11 << 11) | (ext_10_5 << 5) | imm5
                     
                     if full_imm & 0x8000:
                         full_imm -= 0x10000
                         
                     rx_code = (insn >> 8) & 0x7
                     ry_code = (insn >> 5) & 0x7
                     rx = MIPS16Decoder.reg_3bit(rx_code)
                     ry = MIPS16Decoder.reg_3bit(ry_code)
                     
                     return ("lw", f"{ry},{hex(full_imm)}({rx})")
                 
                 # SB (0x18) extended - Store Byte
                 if op2 == 0x18:
                     imm5 = insn & 0x1F
                     full_imm = (ext_15_11 << 11) | (ext_10_5 << 5) | imm5
                     if full_imm & 0x8000:
                         full_imm -= 0x10000
                     rx_code = (insn >> 8) & 0x7
                     ry_code = (insn >> 5) & 0x7
                     rx = MIPS16Decoder.reg_3bit(rx_code)
                     ry = MIPS16Decoder.reg_3bit(ry_code)
                     return ("sb", f"{ry},{hex(full_imm)}({rx})")

                 # SH (0x19) extended - Store Halfword
                 if op2 == 0x19:
                     imm5 = insn & 0x1F
                     full_imm = (ext_15_11 << 11) | (ext_10_5 << 5) | imm5
                     if full_imm & 0x8000:
                         full_imm -= 0x10000
                     rx_code = (insn >> 8) & 0x7
                     ry_code = (insn >> 5) & 0x7
                     rx = MIPS16Decoder.reg_3bit(rx_code)
                     ry = MIPS16Decoder.reg_3bit(ry_code)
                     return ("sh", f"{ry},{hex(full_imm)}({rx})")

                 # SW (0x1B) extended - Store Word (reg-rel)
                 if op2 == 0x1B:
                     imm5 = insn & 0x1F
                     full_imm = (ext_15_11 << 11) | (ext_10_5 << 5) | imm5
                     if full_imm & 0x8000:
                         full_imm -= 0x10000
                     rx_code = (insn >> 8) & 0x7
                     ry_code = (insn >> 5) & 0x7
                     rx = MIPS16Decoder.reg_3bit(rx_code)
                     ry = MIPS16Decoder.reg_3bit(ry_code)
                     return ("sw", f"{ry},{hex(full_imm)}({rx})")
                 
                 return (f"EXT_{word1:04x}_{word2:04x}", "")

            return (f"UNK32_{word1:04x}{word2:04x}", "")


        if len(opcode_bytes) != 2:
            return ("???", "")
        
        # Read as little-endian 16-bit value
        insn = int.from_bytes(opcode_bytes, byteorder='little')

        # NOP (Move $0, $0 ? or 0x6500)
        if insn == 0x6500: return ("nop", "")
        
        # Major opcode (bits 11-15)
        major_op = (insn >> 11) & 0x1F
        
        # Common fields
        rx_code = (insn >> 8) & 0x7
        ry_code = (insn >> 5) & 0x7
        rz_code = (insn >> 2) & 0x7
        
        rx = MIPS16Decoder.reg_3bit(rx_code)
        ry = MIPS16Decoder.reg_3bit(ry_code)
        rz = MIPS16Decoder.reg_3bit(rz_code)
        
        # RRR Format (3-register operations) - Major 0x1C (11100)
        # Format: 11100 rx ry rz func
        # ADDU: rz = rx + ry
        if major_op == 0x1C:
            funct = insn & 0x3  # bits [1:0] for function code
            if funct == 0x1:  # ADDU
                return ("addu", f"{rz},{rx},{ry}")
            # Other RRR instructions can be added here
            return (f"UNK_RRR_{funct:x}", "")

        # ADDIU rx, SP, imm - Major 0x00
        if major_op == 0x00:
            imm = (insn & 0xFF) << 2
            return ("addiu", f"{rx},sp,0x{imm:x}")
        
        # BEQZ rx, offset - Major 0x04 (00100)
        if major_op == 0x04:
            offset = (insn & 0xFF) * 2
            # Sign extend 8-bit offset
            if offset & 0x100:
                offset -= 0x200
            if address:
                target = (address + 2) + offset
                return ("beqz", f"{rx},0x{target:x}")
            return ("beqz", f"{rx},0x{offset:x}")
        
            # ADDIU rx, imm - Major 0x08 (01000) - ADDIU rx, rx, immediate
        if major_op == 0x08:
            imm = insn & 0xFF
            # Sign extend 8-bit immediate
            if imm & 0x80:
                imm_signed = imm - 0x100
                return ("addiu", f"{rx},{rx},-0x{-imm_signed:x}")
            return ("addiu", f"{rx},{rx},0x{imm:x}")

        # I8 Format (SAVE, RESTORE, etc) - Major 0x0C
        if major_op == 0x0C:
            subfunc = (insn >> 8) & 0x7 # bits 10:8
            
            if subfunc == 0x7:
                # MOVE ry, r32 format (bits 7:5 = ry, bits 4:0 = r32)
                # BUT also MOVE r32, ry format (bits 10:8 = rx, bits 4:0 = r32)
                # Check if this is move rx, ry (where ry is encoded in bits 4:0 as 3-bit)
                r32_field = insn & 0x1F
                
                # If r32_field < 8, it might be a MOVE rx, ry (3-bit encoding)
                # Ghidra shows: move t9,a0 for 0x653c
                # 0x653c = 0110 0101 0011 1100
                # Major op = 01100 (0x0C), subfunc = 101 (0x5... wait no)
                # Let me recalculate: bits 15:11 = 01100 (0x0C) ✓
                # bits 10:8 = 101 (0x5) - this is subfunc 5, not 7!
                # So 0x653c is handled by subfunc == 0x5 case below, not here
                
                # Original logic for subfunc 0x7:
                dest = ry
                src = MIPS16Decoder.reg_5bit(insn & 0x1F)
                return ("move", f"{dest},{src}")

            # MOVE32R: move ry, r32 (MIPS16 ← MIPS32) - subfunc=5
            # Note: There appear to be multiple MOVE encoding variants.
            # The standard encoding may not cover all cases (e.g., move t9, a0).
            # TODO: Investigate alternative MOVE formats or EXTEND prefix handling.
            if subfunc == 0x5:
                r32 = (insn >> 3) & 0x1F
                ry_reg = insn & 0x7
                return ("move", f"{MIPS16Decoder.reg_3bit(ry_reg)},{MIPS16Decoder.reg_5bit(r32)}")

            # MOVI32R: move r32, ry (MIPS32 ← MIPS16) - subfunc=6
            if subfunc == 0x6:
                r32 = (insn >> 3) & 0x1F
                ry_reg = insn & 0x7
                return ("move", f"{MIPS16Decoder.reg_5bit(r32)},{MIPS16Decoder.reg_3bit(ry_reg)}")
            
            # I8 Format Instructions (subfunc logic continued for Major Op 0xC)
            if subfunc == 0x4:  # SAVE / RESTORE (distinguished by bit 7)
                # Bit 7: 1 = SAVE, 0 = RESTORE
                is_save = (insn >> 7) & 0x1
                
                xsregs = (insn >> 4) & 0xF
                aregs = xsregs & 0x3
                sregs = (xsregs >> 2) & 0x3
                framesize = (insn & 0xF) << 3
                
                regs = "ra"
                
                # SAVE: uses both sregs and aregs
                # RESTORE: uses only sregs
                if is_save:
                    total_sregs = sregs + aregs
                else:
                    total_sregs = sregs
                
                if total_sregs > 0:
                    if total_sregs == 1:
                        regs += ",s0"
                    else:
                        regs += f",s0-s{total_sregs-1}"
                
                mnemonic = "save" if is_save else "restore"
                return (mnemonic, f"0x{framesize:x},{regs}")
                
            elif subfunc == 0x0: # BTEQZ
                offset = (insn & 0xFF) * 2
                # Sign extend 8-bit offset
                if offset & 0x100:
                    offset -= 0x200
                if address:
                    target = (address + 2) + offset
                    return ("bteqz", f"0x{target:x}")
                return ("bteqz", f"0x{offset:x}")
                
            elif subfunc == 0x1: # BTNEZ
                offset = (insn & 0xFF) * 2
                # Sign extend 8-bit offset
                if offset & 0x100:
                    offset -= 0x200
                if address:
                    target = (address + 2) + offset
                    return ("btnez", f"0x{target:x}")
                return ("btnez", f"0x{offset:x}")

        # SHIFT - Major Op 0x06 (00110): SLL, SRL, SRA
        # Format: 00110 rx ry sa[4:2] func[1:0]
        # func: 00=SLL, 10=SRA, 11=SRL (01=reserved/SLLV in MIPS16e)
        # sa=0 means shift-by-8 in MIPS16
        if major_op == 0x06:
            sa = (insn >> 2) & 0x7
            func = insn & 0x3
            if sa == 0:
                sa = 8
            shift_ops = {0: "sll", 2: "sra", 3: "srl"}
            mnemonic = shift_ops.get(func, f"shift_{func}")
            return (mnemonic, f"{rx},{ry},{sa}")

        # CMPI - Major Op 0xE (01110)
        if major_op == 0x0E:
            rx_code = (insn >> 8) & 0x7
            imm = insn & 0xFF
            rx = MIPS16Decoder.reg_3bit(rx_code)
            return ("cmpi", f"{rx},0x{imm:x}")

        # SLTI: 0x0A (01010)
        if major_op == 0x0A:
            imm = insn & 0xFF
            return ("slti", f"{rx},0x{imm:x}")

        # BNEZ: 0x05 (00101)
        if major_op == 0x05:
            offset = (insn & 0xFF) * 2
            # Sign extend 8-bit offset
            if offset & 0x100:
                offset -= 0x200
            if address:
                target = (address + 2) + offset
                return ("bnez", f"{rx},0x{target:x}")
            return ("bnez", f"{rx},0x{offset:x}")

        # LI: 0x0D (01101) => 01101 xxxxxxx ...
        if major_op == 0x0D:
            imm = insn & 0xFF
            return ("li", f"{rx},0x{imm:x}")

        # LW (PC-rel): 0x17 (10111)
        if major_op == 0x17: 
            offset = (insn & 0xFF) << 2
            return ("lw", f"{rx},0x{offset:x}(pc)")
            
        # LW (SP-rel): 0x12 (10010)
        if major_op == 0x12:
            offset = (insn & 0xFF) << 2
            return ("lw", f"{rx},0x{offset:x}(sp)")

        if major_op == 0x02:
            offset = (insn & 0x7FF) * 2
            # 11-bit immediate sign-extended
            if offset & 0x800:
                offset -= 0x1000
            if address:
                target = (address + 2) + offset
                return ("b", f"0x{target:x}")
            return ("b", f"0x{offset:x}")

        # LW (Reg-rel): 0x13 (10011) - LW ry, offset(rx)
        if major_op == 0x13:
             # rx is bits 10:8 (base)
             # ry is bits 7:5 (dest)
             offset = (insn & 0x1F) << 2 
             return ("lw", f"{ry},0x{offset:x}({rx})")

        # LW (PC-rel) Alias: 0x16 (10110)
        if major_op == 0x16: 
             offset = (insn & 0xFF) << 2
             return ("lw", f"{rx},0x{offset:x}(pc)")
            
        # SW (SP-rel): 0x1A (11010)
        if major_op == 0x1A:
             offset = (insn & 0xFF) << 2
             return ("sw", f"{rx},0x{offset:x}(sp)")

        # SW (Reg-rel): 0x1B (11011) - SW ry, offset(rx)
        if major_op == 0x1B:
             offset = (insn & 0x1F) << 2
             return ("sw", f"{ry},0x{offset:x}({rx})")

        if (insn & 0xF800) == 0xD000: # SW SP (0x1A) - Redundant but safe
             pass 
             
        if (insn & 0xF800) == 0xD800: # SW R-R (0x1B) - Redundant but safe
             pass

        # LBU: 0x14 (10100) -> 10100 ry rx offset
        # 10100 010 (ry) 100 (rx) . (LBU v0, 0(a0))
        # Ghidra: LBU a0, 0(v0) -> DEST=a0(4), BASE=v0(2). 
        # Enc: ry=2, rx=4.
        # So decoding ry=Dest, rx=Base?
        # But MIPS16 spec says: LBU ry, offset(rx).
        # if ry=2 (v0), rx=4 (a0) => LBU v0, 0(a0).
        # Ghidra: LBU a0, 0(v0).
        # This implies Swap? Or my bit reading is swapped?
        # A280 -> 1010_0010_1000_0000
        # 10100 (LBU)
        # 010 (2)
        # 100 (4)
        # 0000
        # If order is rx, ry?
        # Spec: LBU rx, offset(ry)? 
        # Ref: MIPS16e LBU: 10100 rx ry offset.
        # YES. rx is first (bits 10:8), ry is second (bits 7:5).
        # my current vars: rx_code = bits 8-10.
        # so code 'rx' IS 'rx' in spec.
        # And spec says "LBU rx, offset(ry)".
        # destination is rx. base is ry.
        # So: LBU rx, offset(ry).
        # msg: rx=2 (v0). ry=4 (a0). -> LBU v0, 0(a0).
        # Ghidra: LBU a0, 0(v0).
        # Did I swap bits? 
        # A280: 1010 0010 1000 0000
        #              ^^^ (bits 10:8) = 010 = 2. -> rx=2.
        #                   ^^^ (bits 7:5) = 100 = 4. -> ry=4.
        # So LBU v0, 0(a0).
        # Ghidra: LBU a0, 0(v0).
        # !!! 
        # Maybe 80 A2 is not A280?
        # '80 A2' in file. Little endian read -> A2 80 bytes? No.
        # Little endian file: byte 0 is LSB.
        # File: 80 A2
        # u16 = 0xA280.
        # Correct.
        # Maybe I am wrong about MIPS16 encoding for LBU.
        # Let's verify `SW` at 81e84284: `06 d2` -> `D206`.
        # 1101 0010 0000 0110
        # 11010 (SW SP) 
        # 010 (rx=2 -> v0).
        # 00000110 (imm=6 -> 24).
        # SW v0, 24(sp).
        # Ghidra: `sw v0,local_20(sp)` (local_20 is -0x20... wait. 24 is 0x18? hex 20? 0x20=32).
        # Ghidra stack: local_20 is at -0x20. Function saves 0x38 (56). 
        # SP moves down 56.
        # So `local_20` relative to NEW SP is ??
        # 56 - 32 = 24 (0x18).
        # So `sw v0, 24(sp)` is correct.
        # Matches my decode `SW rx, offset(sp)`.
        
        # Okay, back to LBU.
        # `80 a2`. `A280`. `1010 0010 1000 0000`.
        # rx=2 (v0), ry=4 (a0).
        # If output is `LBU v0, 0(a0)` -> Load byte into v0 from address in a0.
        # Ghidra: `lbu a0, 0(v0)`. -> Load byte into a0 from address in v0.
        # If Ghidra is right, then my registers are swapped.
        # Maybe instruction is `LBU ry, offset(rx)`?
        # Many sources say `LBU ry, offset(rx)`.
        # Then `ry` is dest. `rx` is base.
        # If `LBU ry, offset(rx)`:
        # dest=ry(4)=a0. base=rx(2)=v0.
        # This matches Ghidra!
        # So encoding is `LBU ry, offset(rx)`.
        # Note: Opcode 0x14?
        # Let's fix decode map accordingly.

        # LBU (0x14)
        if major_op == 0x14:
            imm = (insn & 0x1F)
            return ("lbu", f"{ry},0x{imm:x}({rx})")
        
        # SB (Store Byte) - Major 0x18 (11000)
        # Format: 11000 rx ry offset[4:0]
        if major_op == 0x18:
            imm = (insn & 0x1F)
            return ("sb", f"{ry},0x{imm:x}({rx})")

        # SW (0xD800? - 11011) -> SW ry, offset(rx)
        if major_op == 0x1B: # Wait, 11011 is SW SP? No.
            # 11011 is SW SP if sub-decode?
            # 0xD000 (11010) is SW SP.
            # 0xD800 (11011) is SW R-R.
            pass
        if (insn & 0xF800) == 0xD000: # SW SP
             imm = (insn & 0xFF) << 2
             return ("sw", f"{rx},0x{imm:x}(sp)")
             
        if (insn & 0xF800) == 0xD800: # SW R-R
             imm = (insn & 0x1F) << 2
             return ("sw", f"{ry},0x{imm:x}({rx})")

        # LW R-R (0x16? 10110? No)
        # 0xB000 (10110)
        if (insn & 0xF800) == 0xB000:
             imm = (insn & 0x1F) << 2
             return ("lw", f"{ry},0x{imm:x}({rx})")

        # RR instructions (Major 0x1D = 11101)
        if major_op == 0x1D:
            funct = insn & 0x1F
            if funct == 0:
                # JR vs JRC distinction:
                # JRC: rx=0, ry!=0 → Jump Register Compact (always RA, no delay slot)
                # JR: rx!=0 → Jump Register (specified register, has delay slot)
                if rx_code == 0 and ry_code != 0:
                    return ("jrc", "ra")
                return ("jr", f"{rx}")
            
            # ADDU - funct 0x01 (00001)
            # Format: 11101 rx ry rz 00001
            # Operation: rz = rx + ry
            if funct == 0x01:
                return ("addu", f"{rz},{rx},{ry}")
            
            # SLTU - funct 0x03 (00011)
            # Format: 11101 rx ry rz 00011
            # Operation: rz = (rx < ry) ? 1 : 0 (unsigned)
            if funct == 0x03:
                return ("sltu", f"{rz},{rx},{ry}")
            
            if funct == 0x11: # SEB / ZEB
                # RR format for CNV operations:
                # Format: 11101 rx(10-8) yyy(7-5) zzz(4-2) 10001
                # rx is the destination register (bits 10-8)
                # bits 7-5 indicate operation: 100 (4) = SEB, 000 (0) = ZEB
                variant = (insn >> 5) & 0x7
                
                # If variant == 4 (100) -> SEB
                if variant == 4:
                    return ("seb", f"{rx}")
                # If variant == 0 (000) -> ZEB
                if variant == 0:
                    return ("zeb", f"{rx}")
                # If variant == 1 (001) -> ZEH (Zero Extend Halfword)
                if variant == 1:
                    return ("zeh", f"{rx}")

            # NEG - funct 0x0B (01011)
            if funct == 0x0B:
                return ("neg", f"{rx},{ry}")

            # AND - funct 0x0C (01100)
            if funct == 0x0C:
                return ("and", f"{rx},{ry}")

            # OR - funct 0x0D (01101) - Proactive addition
            if funct == 0x0D:
                return ("or", f"{rx},{ry}")
                
            # XOR - funct 0x0E (01110) - Proactive addition
            if funct == 0x0E:
                return ("xor", f"{rx},{ry}")
            
            # NOT - funct 0x0F (01111) - Proactive addition
            if funct == 0x0F:
                return ("not", f"{rx},{ry}")

            return (f"UNK_RR_{funct:x}", "")
            
        # NOP (Move $0, $0 ? or 0x6500)
        if insn == 0x6500: return ("_nop", "")
        
        return (f"?_{insn:04x}", "")
