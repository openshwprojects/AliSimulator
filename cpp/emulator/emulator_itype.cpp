#include "emulator.h"

// ============================================================================
// I-Type instructions
// ============================================================================

void Emulator::exec_i_type(uint32_t insn, uint32_t opcode) {
  uint32_t rs = (insn >> 21) & 0x1F;
  uint32_t rt = (insn >> 16) & 0x1F;
  int32_t imm_signed = (int16_t)(insn & 0xFFFF);
  uint32_t imm_unsigned = insn & 0xFFFF;

  switch (opcode) {
  case 0x04: { // BEQ
    uint32_t target = pc + (imm_signed << 2);
    if (regs[rs] == regs[rt])
      do_branch(target);
    break;
  }
  case 0x05: { // BNE
    uint32_t target = pc + (imm_signed << 2);
    if (regs[rs] != regs[rt])
      do_branch(target);
    break;
  }
  case 0x06: { // BLEZ
    uint32_t target = pc + (imm_signed << 2);
    if ((int32_t)regs[rs] <= 0)
      do_branch(target);
    break;
  }
  case 0x07: { // BGTZ
    uint32_t target = pc + (imm_signed << 2);
    if ((int32_t)regs[rs] > 0)
      do_branch(target);
    break;
  }
  case 0x08:
    regs[rt] = regs[rs] + imm_signed;
    break; // ADDI
  case 0x09:
    regs[rt] = regs[rs] + imm_signed;
    break; // ADDIU
  case 0x0A:
    regs[rt] = ((int32_t)regs[rs] < imm_signed) ? 1 : 0;
    break; // SLTI
  case 0x0B:
    regs[rt] = (regs[rs] < (uint32_t)imm_signed) ? 1 : 0;
    break; // SLTIU
  case 0x0C:
    regs[rt] = regs[rs] & imm_unsigned;
    break; // ANDI
  case 0x0D:
    regs[rt] = regs[rs] | imm_unsigned;
    break; // ORI
  case 0x0E:
    regs[rt] = regs[rs] ^ imm_unsigned;
    break; // XORI
  case 0x0F:
    regs[rt] = imm_unsigned << 16;
    break;     // LUI
  case 0x20: { // LB
    uint32_t addr = regs[rs] + imm_signed;
    regs[rt] = (uint32_t)(int32_t)(int8_t)mem_read8(addr);
    break;
  }
  case 0x21: { // LH
    uint32_t addr = regs[rs] + imm_signed;
    regs[rt] = (uint32_t)(int32_t)(int16_t)mem_read16(addr);
    break;
  }
  case 0x22: { // LWL
    uint32_t addr = regs[rs] + imm_signed;
    uint32_t aligned = addr & ~3;
    uint32_t word = mem_read32(aligned);
    int shift = (addr & 3);
    switch (shift) {
    case 0:
      regs[rt] = (regs[rt] & 0x00FFFFFF) | (word << 24);
      break;
    case 1:
      regs[rt] = (regs[rt] & 0x0000FFFF) | (word << 16);
      break;
    case 2:
      regs[rt] = (regs[rt] & 0x000000FF) | (word << 8);
      break;
    case 3:
      regs[rt] = word;
      break;
    }
    break;
  }
  case 0x23: { // LW
    uint32_t addr = regs[rs] + imm_signed;
    regs[rt] = mem_read32(addr);
    break;
  }
  case 0x24: { // LBU
    uint32_t addr = regs[rs] + imm_signed;
    regs[rt] = mem_read8(addr);
    break;
  }
  case 0x25: { // LHU
    uint32_t addr = regs[rs] + imm_signed;
    regs[rt] = mem_read16(addr);
    break;
  }
  case 0x26: { // LWR
    uint32_t addr = regs[rs] + imm_signed;
    uint32_t aligned = addr & ~3;
    uint32_t word = mem_read32(aligned);
    int shift = (addr & 3);
    switch (shift) {
    case 0:
      regs[rt] = word;
      break;
    case 1:
      regs[rt] = (regs[rt] & 0xFF000000) | (word >> 8);
      break;
    case 2:
      regs[rt] = (regs[rt] & 0xFFFF0000) | (word >> 16);
      break;
    case 3:
      regs[rt] = (regs[rt] & 0xFFFFFF00) | (word >> 24);
      break;
    }
    break;
  }
  case 0x28: { // SB
    uint32_t addr = regs[rs] + imm_signed;
    mem_write8(addr, (uint8_t)(regs[rt] & 0xFF));
    break;
  }
  case 0x29: { // SH
    uint32_t addr = regs[rs] + imm_signed;
    mem_write16(addr, (uint16_t)(regs[rt] & 0xFFFF));
    break;
  }
  case 0x2A: { // SWL
    uint32_t addr = regs[rs] + imm_signed;
    uint32_t aligned = addr & ~3;
    uint32_t word = mem_read32(aligned);
    int shift = (addr & 3);
    switch (shift) {
    case 0:
      word = (word & 0xFFFFFF00) | (regs[rt] >> 24);
      break;
    case 1:
      word = (word & 0xFFFF0000) | (regs[rt] >> 16);
      break;
    case 2:
      word = (word & 0xFF000000) | (regs[rt] >> 8);
      break;
    case 3:
      word = regs[rt];
      break;
    }
    mem_write32(aligned, word);
    break;
  }
  case 0x2B: { // SW
    uint32_t addr = regs[rs] + imm_signed;
    mem_write32(addr, regs[rt]);
    break;
  }
  case 0x2E: { // SWR
    uint32_t addr = regs[rs] + imm_signed;
    uint32_t aligned = addr & ~3;
    uint32_t word = mem_read32(aligned);
    int shift = (addr & 3);
    switch (shift) {
    case 0:
      word = regs[rt];
      break;
    case 1:
      word = (word & 0x000000FF) | (regs[rt] << 8);
      break;
    case 2:
      word = (word & 0x0000FFFF) | (regs[rt] << 16);
      break;
    case 3:
      word = (word & 0x00FFFFFF) | (regs[rt] << 24);
      break;
    }
    mem_write32(aligned, word);
    break;
  }
  case 0x30: { // LL
    uint32_t addr = regs[rs] + imm_signed;
    regs[rt] = mem_read32(addr);
    break;
  }
  case 0x38: { // SC
    uint32_t addr = regs[rs] + imm_signed;
    mem_write32(addr, regs[rt]);
    regs[rt] = 1;
    break;
  }
  default:
    unimplemented(insn, "I-type unknown");
    break;
  }
}

// ============================================================================
// J-Type
// ============================================================================

void Emulator::exec_j_type(uint32_t insn, uint32_t opcode) {
  uint32_t target_raw = insn & 0x03FFFFFF;
  uint32_t target = (pc & 0xF0000000) | (target_raw << 2);
  if (opcode == 0x03) { // JAL
    regs[31] = pc + 4;
  }
  do_branch(target);
}
