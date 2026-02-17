#include "emulator.h"
#include <cmath>

// ============================================================================
// COP0
// ============================================================================

void Emulator::exec_cop0(uint32_t insn) {
  uint32_t rs = (insn >> 21) & 0x1F;
  uint32_t rt = (insn >> 16) & 0x1F;
  uint32_t rd = (insn >> 11) & 0x1F;

  switch (rs) {
  case 0x00: // MFC0: rt = CP0[rd]
    switch (rd) {
    case 9:
      regs[rt] = cp0_count;
      break;
    case 11:
      regs[rt] = cp0_compare;
      break;
    case 12:
      regs[rt] = cp0_status;
      break;
    case 13:
      regs[rt] = cp0_cause;
      break;
    case 14:
      regs[rt] = cp0_epc;
      break;
    case 15:
      regs[rt] = 0x00019300;
      break; // PRId (MIPS 24K)
    case 16:
      regs[rt] = 0x80000000;
      break; // Config0
    default:
      regs[rt] = 0;
      break;
    }
    break;
  case 0x04: // MTC0: CP0[rd] = rt
    switch (rd) {
    case 9:
      cp0_count = regs[rt];
      break;
    case 11:
      cp0_compare = regs[rt];
      break;
    case 12:
      cp0_status = regs[rt];
      break;
    case 13:
      cp0_cause = regs[rt];
      break;
    case 14:
      cp0_epc = regs[rt];
      break;
    default:
      break;
    }
    break;
  case 0x10: // CO (ERET, TLBWI, etc.)
    if ((insn & 0x3F) == 0x18) {
      // ERET
      pc = cp0_epc;
      next_pc = pc + 4;
    } else if ((insn & 0x3F) == 0x20) {
      // WAIT — just NOP
    }
    break;
  default:
    unimplemented(insn, "COP0 unknown rs");
    break;
  }
}

// ============================================================================
// COP1 (FPU)
// ============================================================================

void Emulator::exec_cop1(uint32_t insn) {
  uint32_t fmt = (insn >> 21) & 0x1F;
  uint32_t ft = (insn >> 16) & 0x1F;
  uint32_t fs = (insn >> 11) & 0x1F;
  uint32_t fd = (insn >> 6) & 0x1F;
  uint32_t func = insn & 0x3F;

  switch (fmt) {
  case 0x00: // MFC1
    regs[ft] = fpr[fs].w;
    break;
  case 0x04: // MTC1
    fpr[fs].w = regs[ft];
    break;
  case 0x02: // CFC1
    if (fs == 31)
      regs[ft] = fcsr;
    else if (fs == 0)
      regs[ft] = 0;
    break;
  case 0x06: // CTC1
    if (fs == 31) {
      fcsr = regs[ft];
      fpu_cc = (fcsr >> 23) & 1;
    }
    break;
  case 0x08: { // BC1
    int32_t offset = (int16_t)(insn & 0xFFFF);
    uint32_t target = pc + (offset << 2);
    bool cc = fpu_cc;
    switch (ft & 0x03) {
    case 0x00:
      if (!cc)
        do_branch(target);
      break; // BC1F
    case 0x01:
      if (cc)
        do_branch(target);
      break; // BC1T
    case 0x02:
      do_branch_likely(target, !cc);
      break; // BC1FL
    case 0x03:
      do_branch_likely(target, cc);
      break; // BC1TL
    }
    break;
  }
  case 0x10: { // FMT = S (single precision)
    float fs_val = fpr[fs].f;
    float ft_val = fpr[ft].f;
    switch (func) {
    case 0x00:
      fpr[fd].f = fs_val + ft_val;
      break; // ADD.S
    case 0x01:
      fpr[fd].f = fs_val - ft_val;
      break; // SUB.S
    case 0x02:
      fpr[fd].f = fs_val * ft_val;
      break; // MUL.S
    case 0x03:
      if (ft_val != 0.0f)
        fpr[fd].f = fs_val / ft_val;
      break; // DIV.S
    case 0x04:
      fpr[fd].f = sqrtf(fs_val);
      break; // SQRT.S
    case 0x05:
      fpr[fd].f = fabsf(fs_val);
      break; // ABS.S
    case 0x06:
      fpr[fd].f = fs_val;
      break; // MOV.S
    case 0x07:
      fpr[fd].f = -fs_val;
      break; // NEG.S
    case 0x0C: {
      int32_t r = (int32_t)roundf(fs_val);
      fpr[fd].w = (uint32_t)r;
      break;
    } // ROUND.W.S
    case 0x0D: {
      int32_t r = (int32_t)fs_val;
      fpr[fd].w = (uint32_t)r;
      break;
    } // TRUNC.W.S
    case 0x0E: {
      int32_t r = (int32_t)ceilf(fs_val);
      fpr[fd].w = (uint32_t)r;
      break;
    } // CEIL.W.S
    case 0x0F: {
      int32_t r = (int32_t)floorf(fs_val);
      fpr[fd].w = (uint32_t)r;
      break;
    } // FLOOR.W.S
    case 0x21:
      write_fpr_double(fd, (double)fs_val);
      break; // CVT.D.S
    case 0x24: {
      int32_t r = (int32_t)fs_val;
      fpr[fd].w = (uint32_t)r;
      break;
    } // CVT.W.S
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x36:
    case 0x37:
    case 0x38:
    case 0x39:
    case 0x3A:
    case 0x3B:
    case 0x3C:
    case 0x3D:
    case 0x3E:
    case 0x3F: {
      uint32_t cond = func & 0x0F;
      bool result = false;
      bool unordered = (fs_val != fs_val) || (ft_val != ft_val);
      if (unordered) {
        result = (cond & 0x01) != 0;
      } else {
        bool eq = (fs_val == ft_val), lt = (fs_val < ft_val);
        if ((cond & 0x04) && lt)
          result = true;
        if ((cond & 0x02) && eq)
          result = true;
      }
      fpu_cc = result;
      if (result)
        fcsr |= (1 << 23);
      else
        fcsr &= ~(1 << 23);
      break;
    }
    default:
      unimplemented(insn, "COP1 S-format unknown func");
      break;
    }
    break;
  }
  case 0x11: { // FMT = D (double precision)
    double fs_dval = read_fpr_double(fs);
    double ft_dval = read_fpr_double(ft);
    switch (func) {
    case 0x00:
      write_fpr_double(fd, fs_dval + ft_dval);
      break; // ADD.D
    case 0x01:
      write_fpr_double(fd, fs_dval - ft_dval);
      break; // SUB.D
    case 0x02:
      write_fpr_double(fd, fs_dval * ft_dval);
      break; // MUL.D
    case 0x03:
      if (ft_dval != 0.0)
        write_fpr_double(fd, fs_dval / ft_dval);
      break; // DIV.D
    case 0x04:
      write_fpr_double(fd, sqrt(fs_dval));
      break; // SQRT.D
    case 0x05:
      write_fpr_double(fd, fabs(fs_dval));
      break; // ABS.D
    case 0x06:
      write_fpr_double(fd, fs_dval);
      break; // MOV.D
    case 0x07:
      write_fpr_double(fd, -fs_dval);
      break; // NEG.D
    case 0x0C: {
      int32_t r = (int32_t)round(fs_dval);
      fpr[fd].w = (uint32_t)r;
      break;
    } // ROUND.W.D
    case 0x0D: {
      int32_t r = (int32_t)fs_dval;
      fpr[fd].w = (uint32_t)r;
      break;
    } // TRUNC.W.D
    case 0x0E: {
      int32_t r = (int32_t)ceil(fs_dval);
      fpr[fd].w = (uint32_t)r;
      break;
    } // CEIL.W.D
    case 0x0F: {
      int32_t r = (int32_t)floor(fs_dval);
      fpr[fd].w = (uint32_t)r;
      break;
    } // FLOOR.W.D
    case 0x20:
      fpr[fd].f = (float)fs_dval;
      break; // CVT.S.D
    case 0x24: {
      int32_t r = (int32_t)fs_dval;
      fpr[fd].w = (uint32_t)r;
      break;
    } // CVT.W.D
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33:
    case 0x34:
    case 0x35:
    case 0x36:
    case 0x37:
    case 0x38:
    case 0x39:
    case 0x3A:
    case 0x3B:
    case 0x3C:
    case 0x3D:
    case 0x3E:
    case 0x3F: {
      uint32_t cond = func & 0x0F;
      bool result = false;
      bool unordered = (fs_dval != fs_dval) || (ft_dval != ft_dval);
      if (unordered) {
        result = (cond & 0x01) != 0;
      } else {
        bool eq = (fs_dval == ft_dval), lt = (fs_dval < ft_dval);
        if ((cond & 0x04) && lt)
          result = true;
        if ((cond & 0x02) && eq)
          result = true;
      }
      fpu_cc = result;
      if (result)
        fcsr |= (1 << 23);
      else
        fcsr &= ~(1 << 23);
      break;
    }
    default:
      unimplemented(insn, "COP1 D-format unknown func");
      break;
    }
    break;
  }
  case 0x14: { // FMT = W
    switch (func) {
    case 0x20: {
      int32_t v = (int32_t)fpr[fs].w;
      fpr[fd].f = (float)v;
      break;
    } // CVT.S.W
    case 0x21: {
      int32_t v = (int32_t)fpr[fs].w;
      write_fpr_double(fd, (double)v);
      break;
    } // CVT.D.W
    default:
      unimplemented(insn, "COP1 W-format unknown func");
      break;
    }
    break;
  }
  default:
    unimplemented(insn, "COP1 unknown fmt");
    break;
  }
}

// ============================================================================
// SPECIAL2 (opcode 0x1C)
// ============================================================================

void Emulator::exec_special2(uint32_t insn) {
  uint32_t rs = (insn >> 21) & 0x1F;
  uint32_t rt = (insn >> 16) & 0x1F;
  uint32_t rd = (insn >> 11) & 0x1F;
  uint32_t func = insn & 0x3F;

  switch (func) {
  case 0x02: // MUL
    regs[rd] = (uint32_t)((int32_t)regs[rs] * (int32_t)regs[rt]);
    break;
  case 0x00: { // MADD
    int64_t hilo = ((int64_t)(int32_t)hi << 32) | (uint32_t)lo;
    hilo += (int64_t)(int32_t)regs[rs] * (int64_t)(int32_t)regs[rt];
    lo = (uint32_t)(hilo & 0xFFFFFFFF);
    hi = (uint32_t)((hilo >> 32) & 0xFFFFFFFF);
    break;
  }
  case 0x01: { // MADDU
    uint64_t hilo = ((uint64_t)hi << 32) | (uint32_t)lo;
    hilo += (uint64_t)regs[rs] * (uint64_t)regs[rt];
    lo = (uint32_t)(hilo & 0xFFFFFFFF);
    hi = (uint32_t)((hilo >> 32) & 0xFFFFFFFF);
    break;
  }
  case 0x04: { // MSUB
    int64_t hilo = ((int64_t)(int32_t)hi << 32) | (uint32_t)lo;
    hilo -= (int64_t)(int32_t)regs[rs] * (int64_t)(int32_t)regs[rt];
    lo = (uint32_t)(hilo & 0xFFFFFFFF);
    hi = (uint32_t)((hilo >> 32) & 0xFFFFFFFF);
    break;
  }
  case 0x20: { // CLZ
    if (regs[rs] == 0)
      regs[rd] = 32;
    else {
      uint32_t n = 0, val = regs[rs];
      while (!(val & 0x80000000)) {
        n++;
        val <<= 1;
      }
      regs[rd] = n;
    }
    break;
  }
  case 0x21: { // CLO
    uint32_t val = regs[rs];
    if (val == 0xFFFFFFFF)
      regs[rd] = 32;
    else {
      uint32_t n = 0;
      while (val & 0x80000000) {
        n++;
        val <<= 1;
      }
      regs[rd] = n;
    }
    break;
  }
  default:
    unimplemented(insn, "SPECIAL2 unknown func");
    break;
  }
}

// ============================================================================
// SPECIAL3 (opcode 0x1F)
// ============================================================================

void Emulator::exec_special3(uint32_t insn) {
  uint32_t rs = (insn >> 21) & 0x1F;
  uint32_t rt = (insn >> 16) & 0x1F;
  uint32_t msbd = (insn >> 11) & 0x1F;
  uint32_t lsb = (insn >> 6) & 0x1F;
  uint32_t func = insn & 0x3F;

  switch (func) {
  case 0x00: { // EXT
    uint32_t size = msbd + 1;
    uint32_t mask = (size == 32) ? 0xFFFFFFFF : ((1u << size) - 1);
    regs[rt] = (regs[rs] >> lsb) & mask;
    break;
  }
  case 0x04: { // INS
    uint32_t msb = msbd;
    uint32_t size = msb - lsb + 1;
    uint32_t mask = (size == 32) ? 0xFFFFFFFF : ((1u << size) - 1);
    regs[rt] = (regs[rt] & ~(mask << lsb)) | ((regs[rs] & mask) << lsb);
    break;
  }
  case 0x3B: { // RDHWR
    uint32_t rd = (insn >> 11) & 0x1F;
    switch (rd) {
    case 29:
      regs[rt] = 0;
      break;
    default:
      regs[rt] = 0;
      break;
    }
    break;
  }
  case 0x20: { // BSHFL
    uint32_t rd = (insn >> 11) & 0x1F;
    uint32_t sa = (insn >> 6) & 0x1F;
    switch (sa) {
    case 0x02: { // WSBH
      uint32_t val = regs[rt];
      regs[rd] = ((val & 0x00FF00FF) << 8) | ((val & 0xFF00FF00) >> 8);
      break;
    }
    case 0x10: // SEB
      regs[(insn >> 11) & 0x1F] = (uint32_t)(int32_t)(int8_t)(regs[rt] & 0xFF);
      break;
    case 0x18: // SEH
      regs[(insn >> 11) & 0x1F] =
          (uint32_t)(int32_t)(int16_t)(regs[rt] & 0xFFFF);
      break;
    default:
      unimplemented(insn, "BSHFL unknown sa");
      break;
    }
    break;
  }
  default:
    unimplemented(insn, "SPECIAL3 unknown func");
    break;
  }
}
