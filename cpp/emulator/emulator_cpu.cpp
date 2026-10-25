#include "emulator.h"

// ============================================================================
// Branch Helpers
// ============================================================================

void Emulator::do_branch(uint32_t target) {
  next_pc = target;
  in_delay_slot = true;
}

void Emulator::do_branch_isa(uint32_t target, bool target_isa) {
  next_pc = target & ~1u;
  next_isa_mode = target_isa;
  in_delay_slot = true;
}

void Emulator::do_branch_likely(uint32_t target, bool condition) {
  if (condition) {
    next_pc = target;
    in_delay_slot = true;
  } else {
    pc = pc + 4; // skip delay slot
    next_pc = pc + 4;
  }
}

// ============================================================================
// Unimplemented
// ============================================================================

void Emulator::unimplemented(uint32_t insn, const char *desc) {
  log("UNIMPLEMENTED @ PC=0x%08X: %s (insn=0x%08X)", pc - (isa_mode ? 2 : 4),
      desc, insn);
  stopped = true;
}

// ============================================================================
// Instruction Execution (MIPS32)
// ============================================================================

void Emulator::execute_instruction(uint32_t insn) {
  uint32_t opcode = (insn >> 26) & 0x3F;

  switch (opcode) {
  case 0x00:
    exec_r_type(insn);
    break;     // SPECIAL
  case 0x01: { // REGIMM (bltz, bgez, bltzal, bgezal, synci, etc.)
    uint32_t rt = (insn >> 16) & 0x1F;
    uint32_t rs = (insn >> 21) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t target = pc + (offset << 2); // pc already points to delay slot
    int32_t rs_val = (int32_t)regs[rs];

    switch (rt) {
    case 0x00: // BLTZ
      if (rs_val < 0)
        do_branch(target);
      break;
    case 0x01: // BGEZ
      if (rs_val >= 0)
        do_branch(target);
      break;
    case 0x02: // BLTZL
      do_branch_likely(target, rs_val < 0);
      break;
    case 0x03: // BGEZL
      do_branch_likely(target, rs_val >= 0);
      break;
    case 0x08: // TGEI
    case 0x09: // TGEIU
    case 0x0A: // TLTI
    case 0x0B: // TLTIU
    case 0x0C: // TEQI
    case 0x0E: // TNEI
    case 0x1F: // SYNCI
      break;
    case 0x10:           // BLTZAL
      regs[31] = pc + 4; // return address (after delay slot)
      if (rs_val < 0)
        do_branch(target);
      break;
    case 0x11: // BGEZAL
      regs[31] = pc + 4;
      if (rs_val >= 0)
        do_branch(target);
      break;
    case 0x12: // BLTZALL
      regs[31] = pc + 4;
      do_branch_likely(target, rs_val < 0);
      break;
    case 0x13: // BGEZALL
      regs[31] = pc + 4;
      do_branch_likely(target, rs_val >= 0);
      break;
    default:
      unimplemented(insn, "REGIMM unknown");
      break;
    }
    break;
  }
  case 0x02: // J
  case 0x03: // JAL
  case 0x1D: // JALX
    exec_j_type(insn, opcode);
    break;
  case 0x04:
  case 0x05:
  case 0x06:
  case 0x07: // BEQ, BNE, BLEZ, BGTZ
  case 0x08:
  case 0x09:
  case 0x0A:
  case 0x0B: // ADDI, ADDIU, SLTI, SLTIU
  case 0x0C:
  case 0x0D:
  case 0x0E:
  case 0x0F: // ANDI, ORI, XORI, LUI
    exec_i_type(insn, opcode);
    break;
  case 0x10:
    exec_cop0(insn);
    break; // COP0
  case 0x11:
    exec_cop1(insn);
    break; // COP1 (FPU)
  case 0x13:
    exec_cop1x(insn);
    break;     // COP1X (Indexed FP / MADD.S / MADD.D)
  case 0x14: { // BEQL
    uint32_t rs = (insn >> 21) & 0x1F;
    uint32_t rt = (insn >> 16) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t target = pc + (offset << 2);
    do_branch_likely(target, regs[rs] == regs[rt]);
    break;
  }
  case 0x15: { // BNEL
    uint32_t rs = (insn >> 21) & 0x1F;
    uint32_t rt = (insn >> 16) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t target = pc + (offset << 2);
    do_branch_likely(target, regs[rs] != regs[rt]);
    break;
  }
  case 0x16: { // BLEZL
    uint32_t rs = (insn >> 21) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t target = pc + (offset << 2);
    do_branch_likely(target, (int32_t)regs[rs] <= 0);
    break;
  }
  case 0x17: { // BGTZL
    uint32_t rs = (insn >> 21) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t target = pc + (offset << 2);
    do_branch_likely(target, (int32_t)regs[rs] > 0);
    break;
  }
  case 0x1C:
    exec_special2(insn);
    break; // SPECIAL2 (mul, madd, msub, clz, clo)
  case 0x1F:
    exec_special3(insn);
    break; // SPECIAL3 (ext, ins, wsbh, seb, seh, rdhwr)
  case 0x20:
  case 0x21:
  case 0x22:
  case 0x23: // LB, LH, LWL, LW
  case 0x24:
  case 0x25:
  case 0x26: // LBU, LHU, LWR
  case 0x28:
  case 0x29:
  case 0x2A:
  case 0x2B: // SB, SH, SWL, SW
  case 0x2E: // SWR
    exec_i_type(insn, opcode);
    break;
  case 0x2F: // CACHE (NOP in emulator)
    break;
  case 0x30: // LL (Load Linked)
    exec_i_type(insn, opcode);
    break;
  case 0x31: { // LWC1
    uint32_t ft = (insn >> 16) & 0x1F;
    uint32_t base = (insn >> 21) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t addr = regs[base] + offset;
    fpr[ft].w = mem_read32(addr);
    break;
  }
  case 0x38: // SC (Store Conditional)
    exec_i_type(insn, opcode);
    break;
  case 0x39: { // SWC1
    uint32_t ft = (insn >> 16) & 0x1F;
    uint32_t base = (insn >> 21) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t addr = regs[base] + offset;
    mem_write32(addr, fpr[ft].w);
    break;
  }
  case 0x33: { // PREF (prefetch hint — NOP in emulator)
    break;
  }
  case 0x35: { // LDC1 (Load Double to FPU)
    uint32_t ft = (insn >> 16) & 0x1F;
    uint32_t base = (insn >> 21) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t addr = regs[base] + offset;
    fpr[ft & ~1].w = mem_read32(addr);    // low word
    fpr[ft | 1].w = mem_read32(addr + 4); // high word
    break;
  }
  case 0x3D: { // SDC1 (Store Double from FPU)
    uint32_t ft = (insn >> 16) & 0x1F;
    uint32_t base = (insn >> 21) & 0x1F;
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t addr = regs[base] + offset;
    mem_write32(addr, fpr[ft & ~1].w);    // low word
    mem_write32(addr + 4, fpr[ft | 1].w); // high word
    break;
  }
  default:
    unimplemented(insn, "unknown opcode");
    break;
  }
}

// ============================================================================
// R-Type (opcode = 0x00, SPECIAL)
// ============================================================================

void Emulator::exec_r_type(uint32_t insn) {
  uint32_t rs = (insn >> 21) & 0x1F;
  uint32_t rt = (insn >> 16) & 0x1F;
  uint32_t rd = (insn >> 11) & 0x1F;
  uint32_t sa = (insn >> 6) & 0x1F;
  uint32_t func = insn & 0x3F;

  switch (func) {
  case 0x00: // SLL
    regs[rd] = regs[rt] << sa;
    break;
  case 0x01: // MOVCI (MOVF / MOVT based on FP condition code)
    if (fpu_cc == ((rt & 1) != 0))
      regs[rd] = regs[rs];
    break;
  case 0x02: // SRL / ROTR (MIPS32r2: rs & 1 selects ROTR)
    if ((rs & 1) && sa != 0)
      regs[rd] = (regs[rt] >> sa) | (regs[rt] << (32 - sa));
    else
      regs[rd] = regs[rt] >> sa;
    break;
  case 0x03: // SRA
    regs[rd] = (uint32_t)((int32_t)regs[rt] >> sa);
    break;
  case 0x04: // SLLV
    regs[rd] = regs[rt] << (regs[rs] & 0x1F);
    break;
  case 0x06: { // SRLV / ROTRV (MIPS32r2: sa & 1 selects ROTRV)
    uint32_t sh = regs[rs] & 0x1F;
    if ((sa & 1) && sh != 0)
      regs[rd] = (regs[rt] >> sh) | (regs[rt] << (32 - sh));
    else
      regs[rd] = regs[rt] >> sh;
    break;
  }
  case 0x07: // SRAV
    regs[rd] = (uint32_t)((int32_t)regs[rt] >> (regs[rs] & 0x1F));
    break;
  case 0x08: // JR (supports bit-0 MIPS16e ISA switch)
    do_branch_isa(regs[rs] & ~1u, (regs[rs] & 1u) != 0);
    break;
  case 0x09: { // JALR (supports bit-0 MIPS16e ISA switch)
    uint32_t target = regs[rs];
    regs[rd] = (pc + 4) | (isa_mode ? 1u : 0u);
    do_branch_isa(target & ~1u, (target & 1u) != 0);
    break;
  }
  case 0x0A: // MOVZ
    if (regs[rt] == 0)
      regs[rd] = regs[rs];
    break;
  case 0x0B: // MOVN
    if (regs[rt] != 0)
      regs[rd] = regs[rs];
    break;
  case 0x0C: // SYSCALL
    log("SYSCALL at PC=0x%08X", pc - 4);
    break;
  case 0x0D: // BREAK
    log("BREAK at PC=0x%08X", pc - 4);
    stopped = true;
    break;
  case 0x0F: // SYNC
    break;   // NOP for emulator
  case 0x10: // MFHI
    regs[rd] = hi;
    break;
  case 0x11: // MTHI
    hi = regs[rs];
    break;
  case 0x12: // MFLO
    regs[rd] = lo;
    break;
  case 0x13: // MTLO
    lo = regs[rs];
    break;
  case 0x18: { // MULT
    int64_t result = (int64_t)(int32_t)regs[rs] * (int64_t)(int32_t)regs[rt];
    lo = (uint32_t)(result & 0xFFFFFFFF);
    hi = (uint32_t)((result >> 32) & 0xFFFFFFFF);
    break;
  }
  case 0x19: { // MULTU
    uint64_t result = (uint64_t)regs[rs] * (uint64_t)regs[rt];
    lo = (uint32_t)(result & 0xFFFFFFFF);
    hi = (uint32_t)((result >> 32) & 0xFFFFFFFF);
    break;
  }
  case 0x1A: { // DIV
    if (regs[rt] != 0) {
      lo = (uint32_t)((int32_t)regs[rs] / (int32_t)regs[rt]);
      hi = (uint32_t)((int32_t)regs[rs] % (int32_t)regs[rt]);
    }
    break;
  }
  case 0x1B: { // DIVU
    if (regs[rt] != 0) {
      lo = regs[rs] / regs[rt];
      hi = regs[rs] % regs[rt];
    }
    break;
  }
  case 0x20: // ADD (with overflow trap — we ignore overflow)
    regs[rd] = regs[rs] + regs[rt];
    break;
  case 0x21: // ADDU
    regs[rd] = regs[rs] + regs[rt];
    break;
  case 0x22: // SUB
    regs[rd] = regs[rs] - regs[rt];
    break;
  case 0x23: // SUBU
    regs[rd] = regs[rs] - regs[rt];
    break;
  case 0x24: // AND
    regs[rd] = regs[rs] & regs[rt];
    break;
  case 0x25: // OR
    regs[rd] = regs[rs] | regs[rt];
    break;
  case 0x26: // XOR
    regs[rd] = regs[rs] ^ regs[rt];
    break;
  case 0x27: // NOR
    regs[rd] = ~(regs[rs] | regs[rt]);
    break;
  case 0x2A: // SLT
    regs[rd] = ((int32_t)regs[rs] < (int32_t)regs[rt]) ? 1 : 0;
    break;
  case 0x2B: // SLTU
    regs[rd] = (regs[rs] < regs[rt]) ? 1 : 0;
    break;
  case 0x30: // TGE
  case 0x31: // TGEU
  case 0x32: // TLT
  case 0x33: // TLTU
  case 0x34: // TEQ
  case 0x36: // TNE
    break;
  default:
    unimplemented(insn, "R-type unknown func");
    break;
  }
}

// ============================================================================
// MIPS16e Instruction Execution (16-bit and 32-bit EXTEND / JAL / JALX)
// ============================================================================

static const int kMips16Reg[8] = {16, 17, 2, 3, 4, 5, 6, 7};

void Emulator::execute_mips16(uint16_t word1, uint32_t insn_pc) {
  uint32_t major_op = (word1 >> 11) & 0x1F;

  // 1. 32-bit JAL / JALX (major_op == 0x03) with 16-bit delay slot at insn_pc + 4
  if (major_op == 0x03) {
    uint16_t word2 = mem_read16(insn_pc + 2);
    uint32_t x_bit = (word1 >> 10) & 1u;
    uint32_t target_idx = ((uint32_t)(word1 & 0x1Fu) << 21) |
                          ((uint32_t)((word1 >> 5) & 0x1Fu) << 16) | word2;
    uint32_t target = (insn_pc & 0xF0000000u) | (target_idx << 2);
    regs[31] = (insn_pc + 6) | 1u; // return address after 16-bit delay slot
    pc = insn_pc + 4;              // execute 16-bit delay slot next
    next_pc = target;
    next_isa_mode = (x_bit == 0); // JAL stays in MIPS16e; JALX switches to MIPS32
    in_delay_slot = true;
    return;
  }

  // 2. Check for 32-bit EXTEND prefix (major_op == 0x1E)
  bool extended = false;
  uint16_t ext_word = 0;
  uint16_t insn16 = word1;
  if (major_op == 0x1E) {
    extended = true;
    ext_word = word1;
    insn16 = mem_read16(insn_pc + 2);
    major_op = (insn16 >> 11) & 0x1F;
    pc = insn_pc + 4;
    next_pc = pc + 2;
  }

  int rx = kMips16Reg[(insn16 >> 8) & 0x7];
  int ry = kMips16Reg[(insn16 >> 5) & 0x7];
  int rz = kMips16Reg[(insn16 >> 2) & 0x7];

  uint32_t imm16 = 0;
  int32_t simm16 = 0;
  if (extended) {
    uint32_t ext_10_5 = (ext_word >> 5) & 0x3Fu;
    uint32_t ext_15_11 = ext_word & 0x1Fu;
    imm16 = (ext_15_11 << 11) | (ext_10_5 << 5) | (insn16 & 0x1Fu);
    simm16 = (int32_t)(int16_t)imm16;
  }

  switch (major_op) {
  case 0x00: // ADDIUSP: rx = sp + imm
    regs[rx] = regs[29] + (extended ? (uint32_t)simm16 : ((insn16 & 0xFFu) << 2));
    break;
  case 0x01: // ADDIUPC: rx = (insn_pc & ~3) + imm
    regs[rx] = (insn_pc & ~3u) +
               (extended ? (uint32_t)simm16 : ((insn16 & 0xFFu) << 2));
    break;
  case 0x02: { // B offset (unconditional compact branch, no delay slot)
    int32_t off = extended ? (simm16 << 1)
                           : (((int32_t)(insn16 & 0x7FFu) << 21) >> 20);
    pc = (insn_pc + (extended ? 4 : 2)) + off;
    next_pc = pc + 2;
    break;
  }
  case 0x04:   // BEQZ rx, offset (no delay slot)
  case 0x05: { // BNEZ rx, offset (no delay slot)
    bool take = (major_op == 0x04) ? (regs[rx] == 0) : (regs[rx] != 0);
    if (take) {
      int32_t off =
          extended ? (simm16 << 1) : ((int32_t)(int8_t)(insn16 & 0xFFu) << 1);
      pc = (insn_pc + (extended ? 4 : 2)) + off;
      next_pc = pc + 2;
    }
    break;
  }
  case 0x06: { // SHIFT (SLL=0, SRL=2, SRA=3)
    uint32_t sa = extended ? ((ext_word >> 6) & 0x1Fu) : ((insn16 >> 2) & 0x7u);
    if (!extended && sa == 0)
      sa = 8;
    switch (insn16 & 0x3) {
    case 0:
      regs[rx] = regs[ry] << sa;
      break;
    case 2:
      regs[rx] = regs[ry] >> sa;
      break;
    case 3:
      regs[rx] = (uint32_t)((int32_t)regs[ry] >> sa);
      break;
    default:
      unimplemented(insn16, "MIPS16 SHIFT unknown");
      break;
    }
    break;
  }
  case 0x08: { // RRI-A: ADDIU ry, rx, imm
    if (extended) {
      uint32_t imm15 = ((ext_word & 0x0Fu) << 11) |
                       (((ext_word >> 4) & 0x7Fu) << 4) | (insn16 & 0x0Fu);
      int32_t simm15 = ((int32_t)imm15 << 17) >> 17;
      regs[ry] = regs[rx] + (uint32_t)simm15;
    } else {
      int32_t simm4 = ((int32_t)(insn16 & 0x0Fu) << 28) >> 28;
      regs[ry] = regs[rx] + (uint32_t)simm4;
    }
    break;
  }
  case 0x09: // ADDIU8: rx += imm
    regs[rx] += extended ? (uint32_t)simm16
                         : (uint32_t)(int32_t)(int8_t)(insn16 & 0xFFu);
    break;
  case 0x0A: { // SLTI: T ($24) = (signed)rx < imm
    int32_t c = extended ? simm16 : (int32_t)(insn16 & 0xFFu);
    regs[24] = ((int32_t)regs[rx] < c) ? 1u : 0u;
    break;
  }
  case 0x0B: { // SLTIU: T ($24) = (unsigned)rx < imm
    uint32_t c = extended ? (uint32_t)simm16 : (uint32_t)(insn16 & 0xFFu);
    regs[24] = (regs[rx] < c) ? 1u : 0u;
    break;
  }
  case 0x0C: { // I8 format
    uint32_t subfunc = (insn16 >> 8) & 0x7u;
    switch (subfunc) {
    case 0x0:   // BTEQZ
    case 0x1: { // BTNEZ
      bool take = (subfunc == 0) ? (regs[24] == 0) : (regs[24] != 0);
      if (take) {
        int32_t off =
            extended ? (simm16 << 1) : ((int32_t)(int8_t)(insn16 & 0xFFu) << 1);
        pc = (insn_pc + (extended ? 4 : 2)) + off;
        next_pc = pc + 2;
      }
      break;
    }
    case 0x2: { // SWRASP: sw $ra, imm($sp)
      uint32_t off = extended ? (uint32_t)simm16 : ((insn16 & 0xFFu) << 2);
      mem_write32(regs[29] + off, regs[31]);
      break;
    }
    case 0x3: { // ADJSP: sp += imm
      int32_t off =
          extended ? simm16 : ((int32_t)(int8_t)(insn16 & 0xFFu) << 3);
      regs[29] += (uint32_t)off;
      break;
    }
    case 0x4: { // SAVE / RESTORE
      bool is_save = ((insn16 >> 7) & 1u) != 0;
      bool do_ra = ((insn16 >> 6) & 1u) != 0;
      bool do_s1 = ((insn16 >> 5) & 1u) != 0;
      bool do_s0 = ((insn16 >> 4) & 1u) != 0;
      uint32_t fsize4 = insn16 & 0xFu;
      uint32_t framesize = 0;
      uint32_t xsregs = 0;
      uint32_t aregs = 0;
      if (extended) {
        xsregs = (ext_word >> 8) & 0x7u;
        aregs = ext_word & 0xFu;
        framesize = (((ext_word >> 4) & 0xFu) << 7) | (fsize4 << 3);
      } else {
        framesize = (fsize4 == 0) ? 128u : (fsize4 << 3);
      }

      if (is_save) {
        uint32_t old_sp = regs[29];
        // Caller argument slots at old_sp + 0..12
        int caller_args = 0;
        if (aregs >= 4 && aregs <= 7)
          caller_args = 1;
        else if (aregs >= 8 && aregs <= 10)
          caller_args = 2;
        else if (aregs == 12 || aregs == 13)
          caller_args = 3;
        else if (aregs == 14)
          caller_args = 4;
        for (int i = 0; i < caller_args; i++) {
          mem_write32(old_sp + 4 * i, regs[4 + i]);
        }

        uint32_t temp = old_sp;
        if (do_ra) {
          temp -= 4;
          mem_write32(temp, regs[31]);
        }
        if (xsregs > 0) {
          for (int i = (int)xsregs - 1; i >= 0; i--) {
            temp -= 4;
            int r = (i == 6) ? 30 : (18 + i);
            mem_write32(temp, regs[r]);
          }
        }
        if (do_s1) {
          temp -= 4;
          mem_write32(temp, regs[17]);
        }
        if (do_s0) {
          temp -= 4;
          mem_write32(temp, regs[16]);
        }

        int static_aregs = 0;
        if (aregs == 1 || aregs == 5 || aregs == 9 || aregs == 13)
          static_aregs = 1;
        else if (aregs == 2 || aregs == 6 || aregs == 10)
          static_aregs = 2;
        else if (aregs == 3 || aregs == 7)
          static_aregs = 3;
        else if (aregs == 11)
          static_aregs = 4;
        for (int i = 0; i < static_aregs; i++) {
          temp -= 4;
          mem_write32(temp, regs[7 - i]);
        }
        regs[29] = old_sp - framesize;
      } else {
        uint32_t new_sp = regs[29] + framesize;
        uint32_t temp = new_sp;
        if (do_ra) {
          temp -= 4;
          regs[31] = mem_read32(temp);
        }
        if (xsregs > 0) {
          for (int i = (int)xsregs - 1; i >= 0; i--) {
            temp -= 4;
            int r = (i == 6) ? 30 : (18 + i);
            regs[r] = mem_read32(temp);
          }
        }
        if (do_s1) {
          temp -= 4;
          regs[17] = mem_read32(temp);
        }
        if (do_s0) {
          temp -= 4;
          regs[16] = mem_read32(temp);
        }
        regs[29] = new_sp;
      }
      break;
    }
    case 0x5: { // MOV32R: move r32, rz
      uint32_t r32 = ((insn16 >> 5) & 0x7u) | (((insn16 >> 3) & 0x3u) << 3);
      regs[r32] = regs[kMips16Reg[insn16 & 0x7u]];
      break;
    }
    case 0x7: { // MOVR32: move ry, r32
      regs[ry] = regs[insn16 & 0x1Fu];
      break;
    }
    default:
      unimplemented(insn16, "MIPS16 I8 unknown subfunc");
      break;
    }
    break;
  }
  case 0x0D: // LI rx, imm (zero-extended)
    regs[rx] = extended ? imm16 : (insn16 & 0xFFu);
    break;
  case 0x0E: // CMPI rx, imm (zero-extended)
    regs[24] = regs[rx] ^ (extended ? imm16 : (insn16 & 0xFFu));
    break;
  case 0x10: { // LB ry, off(rx)
    uint32_t off = extended ? (uint32_t)simm16 : (insn16 & 0x1Fu);
    regs[ry] = (uint32_t)(int32_t)(int8_t)mem_read8(regs[rx] + off);
    break;
  }
  case 0x11: { // LH ry, off(rx)
    uint32_t off = extended ? (uint32_t)simm16 : ((insn16 & 0x1Fu) << 1);
    regs[ry] = (uint32_t)(int32_t)(int16_t)mem_read16(regs[rx] + off);
    break;
  }
  case 0x12: { // LW rx, off(sp)
    uint32_t off = extended ? (uint32_t)simm16 : ((insn16 & 0xFFu) << 2);
    regs[rx] = mem_read32(regs[29] + off);
    break;
  }
  case 0x13: { // LW ry, off(rx)
    uint32_t off = extended ? (uint32_t)simm16 : ((insn16 & 0x1Fu) << 2);
    regs[ry] = mem_read32(regs[rx] + off);
    break;
  }
  case 0x14: { // LBU ry, off(rx)
    uint32_t off = extended ? (uint32_t)simm16 : (insn16 & 0x1Fu);
    regs[ry] = mem_read8(regs[rx] + off);
    break;
  }
  case 0x15: { // LHU ry, off(rx)
    uint32_t off = extended ? (uint32_t)simm16 : ((insn16 & 0x1Fu) << 1);
    regs[ry] = mem_read16(regs[rx] + off);
    break;
  }
  case 0x16: { // LW rx, off(pc)
    uint32_t off = extended ? (uint32_t)simm16 : ((insn16 & 0xFFu) << 2);
    regs[rx] = mem_read32((insn_pc & ~3u) + off);
    break;
  }
  case 0x18: { // SB ry, off(rx)
    uint32_t off = extended ? (uint32_t)simm16 : (insn16 & 0x1Fu);
    mem_write8(regs[rx] + off, (uint8_t)(regs[ry] & 0xFFu));
    break;
  }
  case 0x19: { // SH ry, off(rx)
    uint32_t off = extended ? (uint32_t)simm16 : ((insn16 & 0x1Fu) << 1);
    mem_write16(regs[rx] + off, (uint16_t)(regs[ry] & 0xFFFFu));
    break;
  }
  case 0x1A: { // SW rx, off(sp)
    uint32_t off = extended ? (uint32_t)simm16 : ((insn16 & 0xFFu) << 2);
    mem_write32(regs[29] + off, regs[rx]);
    break;
  }
  case 0x1B: { // SW ry, off(rx)
    uint32_t off = extended ? (uint32_t)simm16 : ((insn16 & 0x1Fu) << 2);
    mem_write32(regs[rx] + off, regs[ry]);
    break;
  }
  case 0x1C: { // RRR (ADDU=1, SUBU=3)
    if ((insn16 & 0x3) == 1)
      regs[rz] = regs[rx] + regs[ry];
    else if ((insn16 & 0x3) == 3)
      regs[rz] = regs[rx] - regs[ry];
    else
      unimplemented(insn16, "MIPS16 RRR unknown");
    break;
  }
  case 0x1D: { // RR format
    uint32_t funct = insn16 & 0x1Fu;
    switch (funct) {
    case 0x00: { // JR / JALR / JRC / JALRC
      uint32_t variant = (insn16 >> 5) & 0x7u;
      uint32_t target = (variant == 1 || variant == 5) ? regs[31] : regs[rx];
      bool tgt_isa = (target & 1u) != 0;
      uint32_t tgt_pc = target & ~1u;
      if (variant >= 4) { // JRC rx (4), JRC ra (5), JALRC rx (6) — compact (no delay slot)
        if (variant == 6)
          regs[31] = (insn_pc + 2) | 1u;
        isa_mode = next_isa_mode = tgt_isa;
        pc = tgt_pc;
        next_pc = pc + (isa_mode ? 2 : 4);
      } else { // JR rx (0), JR ra (1), JALR rx (2) — 16-bit delay slot
        if (variant == 2)
          regs[31] = (insn_pc + 4) | 1u;
        do_branch_isa(tgt_pc, tgt_isa);
      }
      break;
    }
    case 0x01: // SDBBP
      stopped = true;
      break;
    case 0x02: // SLT
      regs[24] = ((int32_t)regs[rx] < (int32_t)regs[ry]) ? 1u : 0u;
      break;
    case 0x03: // SLTU
      regs[24] = (regs[rx] < regs[ry]) ? 1u : 0u;
      break;
    case 0x04: // SLLV
      regs[ry] = regs[ry] << (regs[rx] & 0x1Fu);
      break;
    case 0x06: // SRLV
      regs[ry] = regs[ry] >> (regs[rx] & 0x1Fu);
      break;
    case 0x07: // SRAV
      regs[ry] = (uint32_t)((int32_t)regs[ry] >> (regs[rx] & 0x1Fu));
      break;
    case 0x0A: // CMP
      regs[24] = regs[rx] ^ regs[ry];
      break;
    case 0x0B: // NEG
      regs[rx] = (uint32_t)(-(int32_t)regs[ry]);
      break;
    case 0x0C: // AND
      regs[rx] &= regs[ry];
      break;
    case 0x0D: // OR
      regs[rx] |= regs[ry];
      break;
    case 0x0E: // XOR
      regs[rx] ^= regs[ry];
      break;
    case 0x0F: // NOT
      regs[rx] = ~regs[ry];
      break;
    case 0x10: // MFHI
      regs[rx] = hi;
      break;
    case 0x11: { // CNV (ZEB, ZEH, WSBH, SEB, SEH)
      switch ((insn16 >> 5) & 0x7u) {
      case 0: // ZEB
        regs[rx] &= 0xFFu;
        break;
      case 1: // ZEH
        regs[rx] &= 0xFFFFu;
        break;
      case 2: { // WSBH
        uint32_t v = regs[rx];
        regs[rx] = ((v & 0x00FF00FFu) << 8) | ((v & 0xFF00FF00u) >> 8);
        break;
      }
      case 4: // SEB
        regs[rx] = (uint32_t)(int32_t)(int8_t)(regs[rx] & 0xFFu);
        break;
      case 5: // SEH
        regs[rx] = (uint32_t)(int32_t)(int16_t)(regs[rx] & 0xFFFFu);
        break;
      default:
        unimplemented(insn16, "MIPS16 CNV unknown");
        break;
      }
      break;
    }
    case 0x12: // MFLO
      regs[rx] = lo;
      break;
    case 0x18: { // MULT
      int64_t r = (int64_t)(int32_t)regs[rx] * (int64_t)(int32_t)regs[ry];
      lo = (uint32_t)r;
      hi = (uint32_t)(r >> 32);
      break;
    }
    case 0x19: { // MULTU
      uint64_t r = (uint64_t)regs[rx] * (uint64_t)regs[ry];
      lo = (uint32_t)r;
      hi = (uint32_t)(r >> 32);
      break;
    }
    case 0x1A: { // DIV
      if (regs[ry] != 0) {
        lo = (uint32_t)((int32_t)regs[rx] / (int32_t)regs[ry]);
        hi = (uint32_t)((int32_t)regs[rx] % (int32_t)regs[ry]);
      }
      break;
    }
    case 0x1B: { // DIVU
      if (regs[ry] != 0) {
        lo = regs[rx] / regs[ry];
        hi = regs[rx] % regs[ry];
      }
      break;
    }
    default:
      unimplemented(insn16, "MIPS16 RR unknown funct");
      break;
    }
    break;
  }
  default:
    unimplemented(insn16, "MIPS16 unknown major_op");
    break;
  }
}
