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

            # EXTEND instructions (0xF000)
            if (word1 & 0xF800) == 0xF000:
                pass

            return (f"UNK32_{word1:04x}{word2:04x}", "")


        if len(opcode_bytes) != 2:
            return ("???", "")
        
        # Read as little-endian 16-bit value
        insn = int.from_bytes(opcode_bytes, byteorder='little')
        
        # Major opcode (bits 11-15)
        major_op = (insn >> 11) & 0x1F
        
        # Common fields
        rx_code = (insn >> 8) & 0x7
        ry_code = (insn >> 5) & 0x7
        rz_code = (insn >> 2) & 0x7
        
        rx = MIPS16Decoder.reg_3bit(rx_code)
        ry = MIPS16Decoder.reg_3bit(ry_code)
        rz = MIPS16Decoder.reg_3bit(rz_code)

        # I8 Format (SAVE, RESTORE, etc) - Major 0x0C
        if major_op == 0x0C:
            subfunc = (insn >> 8) & 0x7 # bits 10:8
            
            if subfunc == 0x4:  # SAVE
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
                
            elif subfunc == 0x0: # BTEQZ
                offset = (insn & 0xFF) * 2 # simplified sign?
                return ("bteqz", f"0x{offset:x}") # Logic needs check?
                
            elif subfunc == 0x1: # BTNEZ
                offset = (insn & 0xFF) * 2
                return ("btnez", f"0x{offset:x}")

        # LI: 0x0D (01101) => 01101 xxxxxxx ...
        if major_op == 0x0D:
            imm = insn & 0xFF
            return ("li", f"{rx},0x{imm:x}")

        # LW (PC-rel): 0x17 (10111)
        if major_op == 0x17: 
            offset = (insn & 0xFF) << 2
            return ("lw", f"{rx},0x{offset:x}(pc)")
            
        # LW (SP-rel): 0x13 (10011)
        if major_op == 0x13:
            offset = (insn & 0xFF) << 2
            return ("lw", f"{rx},0x{offset:x}(sp)")

        # LW (Reg-rel): 0x16 (10110)
        # Format: 10110 ry rx offset(5)
        if major_op == 0x16: 
            offset = (insn & 0x1F) << 2
            return ("lw", f"{ry},0x{offset:x}({rx})")
            
        # SW (SP-rel): 0x1B (11011)
        if major_op == 0x1B:
             offset = (insn & 0xFF) << 2
             return ("sw", f"{rx},0x{offset:x}(sp)")

        # SW (Reg-rel): 0x1D (11101) - NO.
        # SW (Reg): 0x1B is rx, offset(sp).
        # SW (Reg-rel): 11011 is not reg-rel.
        # Format RRI-A for SW: 11011 ry rx offset ?? No.
        # Major 0x1B is SW sp.
        # Major 0x1D ?? 11101
        
        if (insn & 0xF800) == 0xD800: # 11011... wait 0xD800 is 1101_1...
            # 11011 = 0x1B.
            # 0xD800 is 1101_1000... -> 0x1B with sub?
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
                if rx_code == 0: return ("jr", f"{rx}") # rx_code 0 is s0?
                # JR: 01000 11101 xxx00000
                # If rx=7? `jr ra`?
                # jr rx.
                return ("jr", f"{rx}")
            
            # ... handle rest if needed ...
            return (f"UNK_RR_{funct:x}", "")
            
        # NOP (Move $0, $0 ? or 0x6500)
        if insn == 0x6500: return ("_nop", "")
        
        return (f"?_{insn:04x}", "")
