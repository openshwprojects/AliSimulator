#include "emulator.h"

// ============================================================================
// Branch Helpers
// ============================================================================

void Emulator::do_branch(uint32_t target) {
  // In MIPS, branches take effect after the delay slot.
  // At this point pc has already been advanced to pc+4 (the delay slot).
  // The delay slot will execute next, and then we go to target.
  // So we set next_pc = target. The delay slot instruction at 'pc' will run,
  // and after it, pc will become next_pc = target.
  next_pc = target;
  in_delay_slot = true;
}

void Emulator::do_branch_likely(uint32_t target, bool condition) {
  // Branch likely: if condition is true, execute delay slot and branch.
  // If condition is false, NULLIFY the delay slot (skip it).
  if (condition) {
    next_pc = target;
    in_delay_slot = true;
  } else {
    // Skip the delay slot entirely
    pc = pc + 4; // skip delay slot
    next_pc = pc + 4;
  }
}

// ============================================================================
// Unimplemented
// ============================================================================

void Emulator::unimplemented(uint32_t insn, const char *desc) {
  log("UNIMPLEMENTED @ PC=0x%08X: %s (insn=0x%08X)", pc - 4, desc, insn);
  stopped = true;
}

// ============================================================================
// Instruction Execution
// ============================================================================

void Emulator::execute_instruction(uint32_t insn) {
  uint32_t opcode = (insn >> 26) & 0x3F;

  switch (opcode) {
  case 0x00:
    exec_r_type(insn);
    break;     // SPECIAL
  case 0x01: { // REGIMM (bltz, bgez, bltzal, bgezal, etc.)
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
    default:
      unimplemented(insn, "REGIMM unknown");
      break;
    }
    break;
  }
  case 0x02: // J
  case 0x03: // JAL
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
    break;     // COP1 (FPU)
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
    break; // SPECIAL2 (mul, clz, clo)
  case 0x1F:
    exec_special3(insn);
    break; // SPECIAL3 (ext, ins, etc.)
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
  case 0x02: // SRL
    regs[rd] = regs[rt] >> sa;
    break;
  case 0x03: // SRA
    regs[rd] = (uint32_t)((int32_t)regs[rt] >> sa);
    break;
  case 0x04: // SLLV
    regs[rd] = regs[rt] << (regs[rs] & 0x1F);
    break;
  case 0x06: // SRLV
    regs[rd] = regs[rt] >> (regs[rs] & 0x1F);
    break;
  case 0x07: // SRAV
    regs[rd] = (uint32_t)((int32_t)regs[rt] >> (regs[rs] & 0x1F));
    break;
  case 0x08: // JR
    do_branch(regs[rs]);
    break;
  case 0x09:           // JALR
    regs[rd] = pc + 4; // return address after delay slot
    do_branch(regs[rs]);
    break;
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
  case 0x30: // TGE (trap if greater/equal — ignore traps in emulation)
    break;
  case 0x34: // TEQ (trap — ignore)
    break;
  default:
    unimplemented(insn, "R-type unknown func");
    break;
  }
}
