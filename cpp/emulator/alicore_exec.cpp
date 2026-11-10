// AliSimulator C++ core: the interpreter (MIPS32r2, MIPS16e, the FPU) and its loop.
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <limits>

#include "alicore.h"

namespace ali {

// CPU exception codes (Cause.ExcCode), reported through Fault / fault_addr
enum { EXC_ADEL = 4, EXC_ADES = 5, EXC_SYS = 8, EXC_BP = 9, EXC_RI = 10, EXC_CPU = 11, EXC_OV = 12, EXC_TR = 13,
       EXC_FPE = 15, EXC_DBP = 16 };

static ALI_INLINE int32_t sext16(uint32_t v) { return (int32_t)(int16_t)(v & 0xFFFF); }
static ALI_INLINE int32_t sext8(uint32_t v) { return (int32_t)(int8_t)(v & 0xFF); }

static inline uint32_t clz32(uint32_t v) {
  if (!v) return 32;
  uint32_t n = 0;
  while (!(v & 0x80000000u)) { v <<= 1; n++; }
  return n;
}

// MIPS16 3-bit register fields
static const uint8_t XLAT[8] = {16, 17, 2, 3, 4, 5, 6, 7};

// An idle loop (`b .` with a nop in its delay slot, or MIPS16 `b .`): nothing but
// an interrupt or the end of the run ends it, so the time moves on to the next
// event.  Not with code hooks or breakpoints on its page (they would see every
// pass), nor in exact mode.
static ALI_INLINE void idle_jump(Core *c, uint64_t &icount, uint64_t next_event, uint32_t passes) {
  // icount after this instruction (and its delay slot, `passes` instructions per
  // pass) should land on the next event
  if (next_event > icount + passes && next_event != ~0ull) {
    uint64_t skip = next_event - icount - passes;
    skip -= skip % passes;
    icount += skip;
    c->idle_skipped += skip;
  }
}

// ------------------------------------------------------------------
// MIPS32
// ------------------------------------------------------------------
#define RS ((insn >> 21) & 31)
#define RT ((insn >> 16) & 31)
#define RD ((insn >> 11) & 31)
#define SA ((insn >> 6) & 31)
#define IMM16 (insn & 0xFFFF)
#define SIMM16 sext16(insn)
#define SETR(r, v) do { uint32_t _r = (r); uint32_t _v = (v); if (_r) gpr[_r] = _v; } while (0)

ALI_INLINE void Core::exec32(uint32_t insn) {
  uint32_t *R = gpr;
  switch (insn >> 26) {
    case 0x00: {   // SPECIAL
      switch (insn & 0x3F) {
        case 0x00: SETR(RD, R[RT] << SA); return;                                     // SLL (NOP, SSNOP, EHB)
        case 0x01: {                                                                    // MOVF / MOVT
          if (!fpu_usable()) exception(EXC_CPU);
          uint32_t cc = (insn >> 18) & 7, tf = (insn >> 16) & 1;
          uint32_t bit = cc ? (25 + cc - 1) : 23;
          if (((fcsr >> bit) & 1) == tf) SETR(RD, R[RS]);
          return;
        }
        case 0x02:                                                                      // SRL / ROTR
          if (RS & 1) { uint32_t s = SA, v = R[RT]; SETR(RD, s ? (v >> s) | (v << (32 - s)) : v); }
          else SETR(RD, R[RT] >> SA);
          return;
        case 0x03: SETR(RD, (uint32_t)((int32_t)R[RT] >> SA)); return;                  // SRA
        case 0x04: SETR(RD, R[RT] << (R[RS] & 31)); return;                             // SLLV
        case 0x06:                                                                      // SRLV / ROTRV
          if (SA & 1) { uint32_t s = R[RS] & 31, v = R[RT]; SETR(RD, s ? (v >> s) | (v << (32 - s)) : v); }
          else SETR(RD, R[RT] >> (R[RS] & 31));
          return;
        case 0x07: SETR(RD, (uint32_t)((int32_t)R[RT] >> (R[RS] & 31))); return;        // SRAV
        case 0x08: {                                                                    // JR
          uint32_t t = R[RS];
          br_taken_ = true; br_target_ = t & ~1u; br_m16_ = t & 1;
          return;
        }
        case 0x09: {                                                                    // JALR
          uint32_t t = R[RS];
          SETR(RD, cur_pc_ + 8);
          br_taken_ = true; br_target_ = t & ~1u; br_m16_ = t & 1;
          return;
        }
        case 0x0A: if (R[RT] == 0) SETR(RD, R[RS]); return;                            // MOVZ
        case 0x0B: if (R[RT] != 0) SETR(RD, R[RS]); return;                            // MOVN
        case 0x0C: exception(EXC_SYS);                                                  // SYSCALL
        case 0x0D: exception(EXC_BP);                                                   // BREAK
        case 0x0F: return;                                                              // SYNC
        case 0x10: { uint32_t a = RS & 3; SETR(RD, a ? ac_hi[a - 1] : hi); return; }    // MFHI
        case 0x11: { uint32_t a = RD & 3; if (a) ac_hi[a - 1] = R[RS]; else hi = R[RS]; return; }  // MTHI
        case 0x12: { uint32_t a = RS & 3; SETR(RD, a ? ac_lo[a - 1] : lo); return; }    // MFLO
        case 0x13: { uint32_t a = RD & 3; if (a) ac_lo[a - 1] = R[RS]; else lo = R[RS]; return; }  // MTLO
        case 0x18: {                                                                    // MULT
          int64_t p = (int64_t)(int32_t)R[RS] * (int64_t)(int32_t)R[RT];
          set_ac(RD & 3, (uint64_t)p);
          return;
        }
        case 0x19: {                                                                    // MULTU
          uint64_t p = (uint64_t)R[RS] * (uint64_t)R[RT];
          set_ac(RD & 3, p);
          return;
        }
        case 0x1A: {                                                                    // DIV
          int32_t a = (int32_t)R[RS], b = (int32_t)R[RT];
          if (b == 0 || (a == INT32_MIN && b == -1)) b = 1;
          lo = (uint32_t)(a / b); hi = (uint32_t)(a % b);
          return;
        }
        case 0x1B: {                                                                    // DIVU
          uint32_t a = R[RS], b = R[RT];
          if (b == 0) b = 1;
          lo = a / b; hi = a % b;
          return;
        }
        case 0x20: {                                                                    // ADD
          uint32_t a = R[RS], b = R[RT], r = a + b;
          if (((a ^ r) & (b ^ r)) >> 31) exception(EXC_OV);
          SETR(RD, r);
          return;
        }
        case 0x21: SETR(RD, R[RS] + R[RT]); return;                                     // ADDU
        case 0x22: {                                                                    // SUB
          uint32_t a = R[RS], b = R[RT], r = a - b;
          if (((a ^ b) & (a ^ r)) >> 31) exception(EXC_OV);
          SETR(RD, r);
          return;
        }
        case 0x23: SETR(RD, R[RS] - R[RT]); return;                                     // SUBU
        case 0x24: SETR(RD, R[RS] & R[RT]); return;                                     // AND
        case 0x25: SETR(RD, R[RS] | R[RT]); return;                                     // OR
        case 0x26: SETR(RD, R[RS] ^ R[RT]); return;                                     // XOR
        case 0x27: SETR(RD, ~(R[RS] | R[RT])); return;                                  // NOR
        case 0x2A: SETR(RD, (int32_t)R[RS] < (int32_t)R[RT] ? 1 : 0); return;           // SLT
        case 0x2B: SETR(RD, R[RS] < R[RT] ? 1 : 0); return;                             // SLTU
        case 0x30: if ((int32_t)R[RS] >= (int32_t)R[RT]) exception(EXC_TR); return;     // TGE
        case 0x31: if (R[RS] >= R[RT]) exception(EXC_TR); return;                       // TGEU
        case 0x32: if ((int32_t)R[RS] < (int32_t)R[RT]) exception(EXC_TR); return;      // TLT
        case 0x33: if (R[RS] < R[RT]) exception(EXC_TR); return;                        // TLTU
        case 0x34: if (R[RS] == R[RT]) exception(EXC_TR); return;                       // TEQ
        case 0x36: if (R[RS] != R[RT]) exception(EXC_TR); return;                       // TNE
      }
      exception(EXC_RI);
    }
    case 0x01: {   // REGIMM
      int32_t s = (int32_t)R[RS];
      uint32_t target = cur_pc_ + 4 + ((uint32_t)SIMM16 << 2);
      switch (RT) {
        case 0x00: br_taken_ = true; br_target_ = s < 0 ? target : cur_pc_ + 8; br_m16_ = false; return;    // BLTZ
        case 0x01: br_taken_ = true; br_target_ = s >= 0 ? target : cur_pc_ + 8; br_m16_ = false; return;   // BGEZ
        case 0x02: if (s < 0) { br_taken_ = true; br_target_ = target; br_m16_ = false; } else npc_ = cur_pc_ + 8; return;
        case 0x03: if (s >= 0) { br_taken_ = true; br_target_ = target; br_m16_ = false; } else npc_ = cur_pc_ + 8; return;
        case 0x08: if (s >= SIMM16) exception(EXC_TR); return;                          // TGEI
        case 0x09: if (R[RS] >= (uint32_t)SIMM16) exception(EXC_TR); return;            // TGEIU
        case 0x0A: if (s < SIMM16) exception(EXC_TR); return;                           // TLTI
        case 0x0B: if (R[RS] < (uint32_t)SIMM16) exception(EXC_TR); return;             // TLTIU
        case 0x0C: if (s == SIMM16) exception(EXC_TR); return;                          // TEQI
        case 0x0E: if (s != SIMM16) exception(EXC_TR); return;                          // TNEI
        case 0x10: R[31] = cur_pc_ + 8; br_taken_ = true; br_target_ = s < 0 ? target : cur_pc_ + 8; br_m16_ = false; return;
        case 0x11: R[31] = cur_pc_ + 8; br_taken_ = true; br_target_ = s >= 0 ? target : cur_pc_ + 8; br_m16_ = false; return;
        case 0x12: R[31] = cur_pc_ + 8; if (s < 0) { br_taken_ = true; br_target_ = target; br_m16_ = false; } else npc_ = cur_pc_ + 8; return;
        case 0x13: R[31] = cur_pc_ + 8; if (s >= 0) { br_taken_ = true; br_target_ = target; br_m16_ = false; } else npc_ = cur_pc_ + 8; return;
        case 0x1F: return;                                                              // SYNCI
      }
      exception(EXC_RI);
    }
    case 0x02:   // J
      br_taken_ = true; br_target_ = ((cur_pc_ + 4) & 0xF0000000u) | ((insn & 0x03FFFFFF) << 2); br_m16_ = false;
      return;
    case 0x03:   // JAL
      R[31] = cur_pc_ + 8;
      br_taken_ = true; br_target_ = ((cur_pc_ + 4) & 0xF0000000u) | ((insn & 0x03FFFFFF) << 2); br_m16_ = false;
      return;
    case 0x04: {   // BEQ
      uint32_t target = cur_pc_ + 4 + ((uint32_t)SIMM16 << 2);
      bool c = R[RS] == R[RT];
      if (c && target == cur_pc_ && idle_skip && !exact_mode && !cur_ds_ && (status & 7) == 1 &&
          !code_hook_at(cur_pc_) && !code_hook_at(cur_pc_ + 4) && fetch32(cur_pc_ + 4) == 0)
        idle_jump(this, icount, next_event_, 2);   // `b .` / nop: the idle loop
      br_taken_ = true; br_target_ = c ? target : cur_pc_ + 8; br_m16_ = false;
      return;
    }
    case 0x05: {   // BNE
      uint32_t target = cur_pc_ + 4 + ((uint32_t)SIMM16 << 2);
      br_taken_ = true; br_target_ = R[RS] != R[RT] ? target : cur_pc_ + 8; br_m16_ = false;
      return;
    }
    case 0x06: {   // BLEZ
      uint32_t target = cur_pc_ + 4 + ((uint32_t)SIMM16 << 2);
      br_taken_ = true; br_target_ = (int32_t)R[RS] <= 0 ? target : cur_pc_ + 8; br_m16_ = false;
      return;
    }
    case 0x07: {   // BGTZ
      uint32_t target = cur_pc_ + 4 + ((uint32_t)SIMM16 << 2);
      br_taken_ = true; br_target_ = (int32_t)R[RS] > 0 ? target : cur_pc_ + 8; br_m16_ = false;
      return;
    }
    case 0x08: {   // ADDI
      uint32_t a = R[RS], b = (uint32_t)SIMM16, r = a + b;
      if (((a ^ r) & (b ^ r)) >> 31) exception(EXC_OV);
      SETR(RT, r);
      return;
    }
    case 0x09: SETR(RT, R[RS] + (uint32_t)SIMM16); return;                              // ADDIU
    case 0x0A: SETR(RT, (int32_t)R[RS] < SIMM16 ? 1 : 0); return;                       // SLTI
    case 0x0B: SETR(RT, R[RS] < (uint32_t)SIMM16 ? 1 : 0); return;                      // SLTIU
    case 0x0C: SETR(RT, R[RS] & IMM16); return;                                         // ANDI
    case 0x0D: SETR(RT, R[RS] | IMM16); return;                                         // ORI
    case 0x0E: SETR(RT, R[RS] ^ IMM16); return;                                         // XORI
    case 0x0F: SETR(RT, IMM16 << 16); return;                                           // LUI
    case 0x10: {   // COP0
      uint32_t rs = RS;
      if (rs == 0x00) { SETR(RT, cp0_read(RD, insn & 7)); return; }                    // MFC0
      if (rs == 0x04) { cp0_write(RD, insn & 7, R[RT]); return; }                       // MTC0
      if (rs == 0x0B && RD == 12) {                                                      // DI / EI
        uint32_t old = status;
        if (insn & 0x20) status |= 1; else status &= ~1u;
        SETR(RT, old);
        poke_events();
        return;
      }
      if (rs == 0x0A) { SETR(RD, R[RT]); return; }                                      // RDPGPR (one shadow set)
      if (rs == 0x0E) { SETR(RD, R[RT]); return; }                                      // WRPGPR
      if (rs >= 0x10) {
        switch (insn & 0x3F) {
          case 0x01: case 0x02: case 0x06: case 0x08: return;                            // TLBR / TLBWI / TLBWR / TLBP
          case 0x18:                                                                      // ERET
            eret();
            npc_ = pc; nm16_ = m16;
            return;
          case 0x1F: exception(EXC_RI);                                                   // DERET (not in debug mode)
          case 0x20: {                                                                    // WAIT: until an interrupt
            if (idle_skip && !exact_mode && (status & 7) == 1) idle_jump(this, icount, next_event_, 1);
            return;
          }
        }
      }
      exception(EXC_RI);
    }
    case 0x11: exec_cop1(insn); return;
    case 0x12: exception(EXC_CPU);                                                      // COP2
    case 0x13: exec_cop1x(insn); return;
    case 0x14: {   // BEQL
      if (R[RS] == R[RT]) { br_taken_ = true; br_target_ = cur_pc_ + 4 + ((uint32_t)SIMM16 << 2); br_m16_ = false; }
      else npc_ = cur_pc_ + 8;
      return;
    }
    case 0x15: {   // BNEL
      if (R[RS] != R[RT]) { br_taken_ = true; br_target_ = cur_pc_ + 4 + ((uint32_t)SIMM16 << 2); br_m16_ = false; }
      else npc_ = cur_pc_ + 8;
      return;
    }
    case 0x16: {   // BLEZL
      if ((int32_t)R[RS] <= 0) { br_taken_ = true; br_target_ = cur_pc_ + 4 + ((uint32_t)SIMM16 << 2); br_m16_ = false; }
      else npc_ = cur_pc_ + 8;
      return;
    }
    case 0x17: {   // BGTZL
      if ((int32_t)R[RS] > 0) { br_taken_ = true; br_target_ = cur_pc_ + 4 + ((uint32_t)SIMM16 << 2); br_m16_ = false; }
      else npc_ = cur_pc_ + 8;
      return;
    }
    case 0x1C: {   // SPECIAL2
      switch (insn & 0x3F) {
        case 0x00: {                                                                     // MADD
          uint32_t a = RD & 3;
          set_ac(a, (uint64_t)((int64_t)get_ac(a) + (int64_t)(int32_t)R[RS] * (int64_t)(int32_t)R[RT]));
          return;
        }
        case 0x01: {                                                                     // MADDU
          uint32_t a = RD & 3;
          set_ac(a, get_ac(a) + (uint64_t)R[RS] * (uint64_t)R[RT]);
          return;
        }
        case 0x02: SETR(RD, (uint32_t)((int32_t)R[RS] * (int32_t)R[RT])); return;       // MUL
        case 0x04: {                                                                     // MSUB
          uint32_t a = RD & 3;
          set_ac(a, (uint64_t)((int64_t)get_ac(a) - (int64_t)(int32_t)R[RS] * (int64_t)(int32_t)R[RT]));
          return;
        }
        case 0x05: {                                                                     // MSUBU
          uint32_t a = RD & 3;
          set_ac(a, get_ac(a) - (uint64_t)R[RS] * (uint64_t)R[RT]);
          return;
        }
        case 0x20: SETR(RD, clz32(R[RS])); return;                                      // CLZ
        case 0x21: SETR(RD, clz32(~R[RS])); return;                                     // CLO
        case 0x3F: exception(EXC_DBP);                                                  // SDBBP
      }
      exception(EXC_RI);
    }
    case 0x1D:   // JALX: to MIPS16
      R[31] = cur_pc_ + 8;
      br_taken_ = true; br_target_ = ((cur_pc_ + 4) & 0xF0000000u) | ((insn & 0x03FFFFFF) << 2); br_m16_ = true;
      return;
    case 0x1F: {   // SPECIAL3
      switch (insn & 0x3F) {
        case 0x00: {                                                                     // EXT
          uint32_t lsb = SA, size = RD + 1;
          if (lsb + size > 32) exception(EXC_RI);
          uint32_t v = R[RS] >> lsb;
          SETR(RT, size == 32 ? v : v & ((1u << size) - 1));
          return;
        }
        case 0x04: {                                                                     // INS
          uint32_t lsb = SA, msb = RD;
          if (msb < lsb) exception(EXC_RI);
          uint32_t size = msb - lsb + 1;
          uint32_t mask = (size == 32 ? 0xFFFFFFFFu : ((1u << size) - 1)) << lsb;
          SETR(RT, (R[RT] & ~mask) | ((R[RS] << lsb) & mask));
          return;
        }
        case 0x0A: {                                                                     // LX (MIPS DSP)
          uint32_t a = R[RS] + R[RT];
          switch (SA) {
            case 0x00: SETR(RD, load<uint32_t>(a)); return;                              // LWX
            case 0x04: SETR(RD, (uint32_t)(int32_t)(int16_t)load<uint16_t>(a)); return;  // LHX
            case 0x06: SETR(RD, load<uint8_t>(a)); return;                               // LBUX
          }
          exception(EXC_RI);
        }
        case 0x10: {                                                                     // ADDQ / SUBQ (MIPS DSP)
          switch (SA) {
            case 0x10: {                                                                 // ADDSC
              uint64_t s = (uint64_t)R[RS] + (uint64_t)R[RT];
              dspc = (dspc & ~(1u << 13)) | ((uint32_t)((s >> 32) & 1) << 13);
              SETR(RD, (uint32_t)s);
              return;
            }
            case 0x11: {                                                                 // ADDWC
              int64_t s = (int64_t)(int32_t)R[RS] + (int64_t)(int32_t)R[RT] + ((dspc >> 13) & 1);
              if (s < INT32_MIN || s > INT32_MAX) dspc |= 1u << 20;
              SETR(RD, (uint32_t)s);
              return;
            }
            case 0x16: {                                                                 // ADDQ_S.W
              int64_t s = (int64_t)(int32_t)R[RS] + (int64_t)(int32_t)R[RT];
              if (s > INT32_MAX) { s = INT32_MAX; dspc |= 1u << 20; }
              else if (s < INT32_MIN) { s = INT32_MIN; dspc |= 1u << 20; }
              SETR(RD, (uint32_t)(int32_t)s);
              return;
            }
            case 0x17: {                                                                 // SUBQ_S.W
              int64_t s = (int64_t)(int32_t)R[RS] - (int64_t)(int32_t)R[RT];
              if (s > INT32_MAX) { s = INT32_MAX; dspc |= 1u << 20; }
              else if (s < INT32_MIN) { s = INT32_MIN; dspc |= 1u << 20; }
              SETR(RD, (uint32_t)(int32_t)s);
              return;
            }
          }
          exception(EXC_RI);
        }
        case 0x11: {                                                                     // PRECRQ (MIPS DSP)
          if (SA == 0x15) {                                                              // PRECRQ_RS.PH.W
            auto rnd_sat16 = [&](uint32_t w) -> uint32_t {
              int64_t t = (int64_t)(int32_t)w + 0x8000;
              if (t > 0x7FFFFFFFll) { t = 0x7FFFFFFFll; dspc |= 1u << 22; }
              return ((uint32_t)(int32_t)t >> 16) & 0xFFFFu;
            };
            uint32_t hi16 = rnd_sat16(R[RS]), lo16 = rnd_sat16(R[RT]);
            SETR(RD, (hi16 << 16) | lo16);
            return;
          }
          exception(EXC_RI);
        }
        case 0x13: {                                                                     // SHLL (MIPS DSP)
          if (SA == 0x14) {                                                              // SHLL_S.W
            uint32_t sa = RS;
            int32_t v = (int32_t)R[RT];
            if (!sa) { SETR(RD, (uint32_t)v); return; }
            int64_t s = (int64_t)v << sa;
            if (s > INT32_MAX) { s = INT32_MAX; dspc |= 1u << 22; }
            else if (s < INT32_MIN) { s = INT32_MIN; dspc |= 1u << 22; }
            SETR(RD, (uint32_t)(int32_t)s);
            return;
          }
          exception(EXC_RI);
        }
        case 0x20: {                                                                     // BSHFL
          uint32_t v = R[RT];
          switch (SA) {
            case 0x02: SETR(RD, ((v & 0x00FF00FFu) << 8) | ((v >> 8) & 0x00FF00FFu)); return;   // WSBH
            case 0x10: SETR(RD, (uint32_t)sext8(v)); return;                            // SEB
            case 0x18: SETR(RD, (uint32_t)sext16(v)); return;                           // SEH
          }
          exception(EXC_RI);
        }
        case 0x30: {                                                                     // DPAQ / DPSQ (MIPS DSP)
          if (SA == 0x0C || SA == 0x0D) {                                                // DPAQ_SA.L.W / DPSQ_SA.L.W
            uint32_t a = RD & 3;
            int64_t prod;
            if (R[RS] == 0x80000000u && R[RT] == 0x80000000u) {
              prod = INT64_MAX;
              dspc |= 1u << (16 + a);
            } else {
              prod = ((int64_t)(int32_t)R[RS] * (int64_t)(int32_t)R[RT]) << 1;
            }
            int64_t acc = (int64_t)get_ac(a);
            int64_t res;
            if (SA == 0x0C) {
              if (prod > 0 && acc > INT64_MAX - prod) { res = INT64_MAX; dspc |= 1u << (16 + a); }
              else if (prod < 0 && acc < INT64_MIN - prod) { res = INT64_MIN; dspc |= 1u << (16 + a); }
              else res = acc + prod;
            } else {
              if (prod < 0 && acc > INT64_MAX + prod) { res = INT64_MAX; dspc |= 1u << (16 + a); }
              else if (prod > 0 && acc < INT64_MIN + prod) { res = INT64_MIN; dspc |= 1u << (16 + a); }
              else res = acc - prod;
            }
            set_ac(a, (uint64_t)res);
            return;
          }
          exception(EXC_RI);
        }
        case 0x38: {                                                                     // EXTR.W / RDDSP / WRDSP (MIPS DSP)
          uint32_t a = RD & 3;
          switch (SA) {
            case 0x00: case 0x01: case 0x04: case 0x05: case 0x06: case 0x07: {
              uint32_t sh = (SA & 1) ? (R[RS] & 31) : RS;
              int64_t acc = (int64_t)get_ac(a);
              int64_t res = (SA >= 4 && sh) ? ((acc + (1ll << (sh - 1))) >> sh) : (acc >> sh);
              if (res > INT32_MAX) { dspc |= 1u << 23; if (SA >= 6) res = INT32_MAX; }
              else if (res < INT32_MIN) { dspc |= 1u << 23; if (SA >= 6) res = INT32_MIN; }
              SETR(RT, (uint32_t)(int32_t)res);
              return;
            }
            case 0x12: SETR(RD, dspc); return;                                           // RDDSP
            case 0x13: dspc = R[RS]; return;                                             // WRDSP
          }
          exception(EXC_RI);
        }
        case 0x3B: {                                                                     // RDHWR
          switch (RD) {
            case 0: SETR(RT, ebase & 0x3FF); return;
            case 1: SETR(RT, 32); return;
            case 2: SETR(RT, count_now()); return;
            case 3: SETR(RT, 2); return;
          }
          exception(EXC_RI);
        }
      }
      exception(EXC_RI);
    }
    case 0x20: { uint32_t a = R[RS] + (uint32_t)SIMM16; SETR(RT, (uint32_t)(int32_t)(int8_t)load<uint8_t>(a)); return; }    // LB
    case 0x21: { uint32_t a = R[RS] + (uint32_t)SIMM16; SETR(RT, (uint32_t)(int32_t)(int16_t)load<uint16_t>(a)); return; }  // LH
    case 0x22: {   // LWL
      uint32_t a = R[RS] + (uint32_t)SIMM16, b = a & 3;
      uint32_t w = load<uint32_t>(a & ~3u);
      uint32_t sh = 8 * (3 - b);
      uint32_t keep = sh ? (R[RT] & ((1u << sh) - 1)) : 0;
      SETR(RT, (w << sh) | keep);
      return;
    }
    case 0x23: { uint32_t a = R[RS] + (uint32_t)SIMM16; SETR(RT, load<uint32_t>(a)); return; }   // LW
    case 0x24: { uint32_t a = R[RS] + (uint32_t)SIMM16; SETR(RT, load<uint8_t>(a)); return; }    // LBU
    case 0x25: { uint32_t a = R[RS] + (uint32_t)SIMM16; SETR(RT, load<uint16_t>(a)); return; }   // LHU
    case 0x26: {   // LWR
      uint32_t a = R[RS] + (uint32_t)SIMM16, b = a & 3;
      uint32_t w = load<uint32_t>(a & ~3u);
      uint32_t sh = 8 * b;
      uint32_t keep = sh ? (R[RT] & ~(0xFFFFFFFFu >> sh)) : 0;
      SETR(RT, (w >> sh) | keep);
      return;
    }
    case 0x28: { uint32_t a = R[RS] + (uint32_t)SIMM16; store<uint8_t>(a, (uint8_t)R[RT]); return; }     // SB
    case 0x29: { uint32_t a = R[RS] + (uint32_t)SIMM16; store<uint16_t>(a, (uint16_t)R[RT]); return; }   // SH
    case 0x2A: {   // SWL
      uint32_t a = R[RS] + (uint32_t)SIMM16, b = a & 3, wa = a & ~3u;
      uint32_t sh = 8 * (3 - b);
      uint32_t v = R[RT] >> sh;
      if (b == 3) { store<uint32_t>(wa, v); return; }
      uint32_t m = load<uint32_t>(wa);
      uint32_t mask = 0xFFFFFFFFu >> sh;
      store<uint32_t>(wa, (m & ~mask) | v);
      return;
    }
    case 0x2B: { uint32_t a = R[RS] + (uint32_t)SIMM16; store<uint32_t>(a, R[RT]); return; }    // SW
    case 0x2E: {   // SWR
      uint32_t a = R[RS] + (uint32_t)SIMM16, b = a & 3, wa = a & ~3u;
      uint32_t sh = 8 * b;
      uint32_t v = R[RT] << sh;
      if (b == 0) { store<uint32_t>(wa, v); return; }
      uint32_t m = load<uint32_t>(wa);
      uint32_t mask = 0xFFFFFFFFu << sh;
      store<uint32_t>(wa, (m & ~mask) | v);
      return;
    }
    case 0x2F: return;   // CACHE
    case 0x30: {   // LL
      uint32_t a = R[RS] + (uint32_t)SIMM16;
      if (a & 3) { badvaddr = a; exception(EXC_ADEL); }   // (QEMU: an address error exception, not a fault)
      uint32_t v = load<uint32_t>(a);
      lladdr = phys_of(a);
      llval = v;
      llbit = true;
      SETR(RT, v);
      return;
    }
    case 0x31: {   // LWC1
      if (!fpu_usable()) exception(EXC_CPU);
      uint32_t a = R[RS] + (uint32_t)SIMM16;
      uint32_t v = load<uint32_t>(a);
      fpr[RT] = (fpr[RT] & 0xFFFFFFFF00000000ull) | v;
      return;
    }
    case 0x32: exception(EXC_CPU);   // LWC2
    case 0x33: return;               // PREF
    case 0x35: {   // LDC1
      if (!fpu_usable()) exception(EXC_CPU);
      uint32_t a = R[RS] + (uint32_t)SIMM16;
      if (a & 7) fault_unaligned(a, MEM_READ);
      uint64_t v = (uint64_t)load<uint32_t>(a) | ((uint64_t)load<uint32_t>(a + 4) << 32);
      uint32_t ft = RT;
      if (status & 0x04000000u) fpr[ft] = v;
      else {   // (FR = 0: the even / odd pair; QEMU does not check the register here)
        fpr[ft & ~1u] = (fpr[ft & ~1u] & 0xFFFFFFFF00000000ull) | (uint32_t)v;
        fpr[ft | 1u] = (fpr[ft | 1u] & 0xFFFFFFFF00000000ull) | (uint32_t)(v >> 32);
      }
      return;
    }
    case 0x36: exception(EXC_CPU);   // LDC2
    case 0x38: {   // SC
      uint32_t a = R[RS] + (uint32_t)SIMM16;
      // (QEMU compares the link address first: an unaligned SC just fails)
      bool ok = llbit && lladdr == phys_of(a) && load<uint32_t>(a) == llval;
      if (ok) store<uint32_t>(a, R[RT]);
      llbit = false;
      SETR(RT, ok ? 1 : 0);
      return;
    }
    case 0x39: {   // SWC1
      if (!fpu_usable()) exception(EXC_CPU);
      uint32_t a = R[RS] + (uint32_t)SIMM16;
      store<uint32_t>(a, (uint32_t)fpr[RT]);
      return;
    }
    case 0x3A: exception(EXC_CPU);   // SWC2
    case 0x3D: {   // SDC1
      if (!fpu_usable()) exception(EXC_CPU);
      uint32_t a = R[RS] + (uint32_t)SIMM16;
      if (a & 7) fault_unaligned(a, MEM_WRITE);
      uint32_t ft = RT;
      uint64_t v;
      if (status & 0x04000000u) v = fpr[ft];
      else v = (uint32_t)fpr[ft & ~1u] | ((uint64_t)(uint32_t)fpr[ft | 1u] << 32);
      store<uint32_t>(a, (uint32_t)v);
      store<uint32_t>(a + 4, (uint32_t)(v >> 32));
      return;
    }
    case 0x3E: exception(EXC_CPU);   // SDC2
  }
  exception(EXC_RI);
}

// (the FPU, COP1 / COP1X: alicore_fpu.cpp)

// ------------------------------------------------------------------
// MIPS16e
// ------------------------------------------------------------------
ALI_INLINE void Core::exec16() {
  uint32_t a = cur_pc_;
  uint32_t hw = fetch16(a);
  uint32_t op = hw >> 11;
  uint32_t *R = gpr;
  bool ext = false;
  uint32_t e = 0;   // the EXTEND halfword
  if (op == 0x1E) {
    ext = true;
    e = hw;
    hw = fetch16(a + 2);
    op = hw >> 11;
    npc_ = a + 4;
  } else if (op == 0x03) {
    // JAL / JALX
    uint32_t lo16 = fetch16(a + 2);
    uint32_t t26 = ((hw & 0x1F) << 21) | (((hw >> 5) & 0x1F) << 16) | lo16;
    R[31] = (a + 6) | 1;
    br_taken_ = true;
    br_target_ = ((a + 4) & 0xF0000000u) | (t26 << 2);
    br_m16_ = !(hw & 0x400);   // JALX switches to MIPS32
    npc_ = a + 4;
    nm16_ = true;
    return;
  } else {
    npc_ = a + 2;
  }
  nm16_ = true;
  uint32_t rx = XLAT[(hw >> 8) & 7], ry = XLAT[(hw >> 5) & 7];
  // the extended immediate: EXTEND imm[10:5] (bits 10..5), imm[15:11] (bits 4..0), insn imm[4:0]
  int32_t eimm = ext ? (int32_t)(int16_t)((((e >> 0) & 0x1F) << 11) | (((e >> 5) & 0x3F) << 5) | (hw & 0x1F)) : 0;
  // the PC-relative base: the instruction (or the jump whose delay slot it is), low 2 bits clear
  uint32_t pcbase = (cur_ds_ ? cur_branch_pc_ : a) & ~3u;

  switch (op) {
    case 0x00:   // ADDIUSP rx, sp, imm
      R[rx] = R[29] + (ext ? (uint32_t)eimm : ((hw & 0xFF) << 2));
      return;
    case 0x01:   // ADDIUPC rx, pc, imm
      R[rx] = pcbase + (ext ? (uint32_t)eimm : ((hw & 0xFF) << 2));
      return;
    case 0x02: {   // B
      int32_t off = ext ? eimm : ((int32_t)((hw & 0x7FF) << 21) >> 21);
      uint32_t target = a + (ext ? 4 : 2) + ((uint32_t)off << 1);
      if (target == a && idle_skip && !exact_mode && !cur_ds_ && (status & 7) == 1 && !code_hook_at(a))
        idle_jump(this, icount, next_event_, 1);   // `b .`
      npc_ = target;
      return;
    }
    case 0x04: case 0x05: {   // BEQZ / BNEZ
      int32_t off = ext ? eimm : sext8(hw);
      bool c = (op == 0x04) ? (R[rx] == 0) : (R[rx] != 0);
      if (c) npc_ = a + (ext ? 4 : 2) + ((uint32_t)off << 1);
      return;
    }
    case 0x06: {   // SHIFT: SLL / SRL / SRA rx, ry, sa
      uint32_t sa = ext ? ((e >> 6) & 0x1F) : ((hw >> 2) & 7);
      if (!ext && sa == 0) sa = 8;
      switch (hw & 3) {
        case 0: R[rx] = R[ry] << sa; return;
        case 2: R[rx] = R[ry] >> sa; return;
        case 3: R[rx] = (uint32_t)((int32_t)R[ry] >> sa); return;
      }
      exception(EXC_RI);
    }
    case 0x08: {   // RRI-A: ADDIU ry, rx, imm
      if (hw & 0x10) exception(EXC_RI);
      int32_t imm;
      if (ext) imm = (int32_t)((((e & 0xF) << 11) | (((e >> 4) & 0x7F) << 4) | (hw & 0xF)) << 17) >> 17;
      else imm = (int32_t)((hw & 0xF) << 28) >> 28;
      R[ry] = R[rx] + (uint32_t)imm;
      return;
    }
    case 0x09:   // ADDIU8 rx, imm
      R[rx] += ext ? (uint32_t)eimm : (uint32_t)sext8(hw);
      return;
    case 0x0A:   // SLTI rx, imm -> T
      R[24] = (int32_t)R[rx] < (ext ? eimm : (int32_t)(hw & 0xFF)) ? 1 : 0;
      return;
    case 0x0B:   // SLTIU rx, imm -> T
      R[24] = R[rx] < (ext ? (uint32_t)eimm : (hw & 0xFF)) ? 1 : 0;
      return;
    case 0x0C: {   // I8
      uint32_t f = (hw >> 8) & 7;
      switch (f) {
        case 0: case 1: {   // BTEQZ / BTNEZ
          int32_t off = ext ? eimm : sext8(hw);
          bool c = (f == 0) ? (R[24] == 0) : (R[24] != 0);
          if (c) npc_ = a + (ext ? 4 : 2) + ((uint32_t)off << 1);
          return;
        }
        case 2: {   // SWRASP: sw ra, imm(sp)
          uint32_t addr = R[29] + (ext ? (uint32_t)eimm : ((hw & 0xFF) << 2));
          store<uint32_t>(addr, R[31]);
          return;
        }
        case 3:     // ADJSP: addiu sp, imm
          R[29] += ext ? (uint32_t)eimm : ((uint32_t)sext8(hw) << 3);
          return;
        case 4: {   // SVRS: SAVE / RESTORE
          bool do_ra = hw & 0x40, do_s0 = hw & 0x20, do_s1 = hw & 0x10;
          uint32_t xsregs = 0, aregs = 0, framesize;
          if (ext) {
            xsregs = (e >> 8) & 7;
            aregs = e & 0xF;
            framesize = ((((e >> 4) & 0xF) << 4) | (hw & 0xF)) << 3;
          } else {
            framesize = hw & 0xF;
            framesize = framesize ? framesize << 3 : 128;
          }
          int args, astatic;
          switch (aregs) {
            case 0: case 1: case 2: case 3: case 11: args = 0; break;
            case 4: case 5: case 6: case 7: args = 1; break;
            case 8: case 9: case 10: args = 2; break;
            case 12: case 13: args = 3; break;
            case 14: args = 4; break;
            default: exception(EXC_RI);
          }
          switch (aregs) {
            case 0: case 4: case 8: case 12: case 14: astatic = 0; break;
            case 1: case 5: case 9: case 13: astatic = 1; break;
            case 2: case 6: case 10: astatic = 2; break;
            case 3: case 7: astatic = 3; break;
            case 11: astatic = 4; break;
            default: exception(EXC_RI);
          }
          static const uint8_t XS[7] = {18, 19, 20, 21, 22, 23, 30};
          if (hw & 0x80) {   // SAVE
            uint32_t sp = R[29];
            for (int i = args; i >= 1; i--) store<uint32_t>(sp + 4 * (i - 1), R[3 + i]);
            uint32_t t = sp;
            if (do_ra) { t -= 4; store<uint32_t>(t, R[31]); }
            for (int i = (int)xsregs; i >= 1; i--) { t -= 4; store<uint32_t>(t, R[XS[i - 1]]); }
            if (do_s1) { t -= 4; store<uint32_t>(t, R[17]); }
            if (do_s0) { t -= 4; store<uint32_t>(t, R[16]); }
            for (int i = 0; i < astatic; i++) { t -= 4; store<uint32_t>(t, R[7 - i]); }
            R[29] = sp - framesize;
          } else {           // RESTORE
            uint32_t t = R[29] + framesize;
            uint32_t vals[16];
            int regs[16], n = 0;
            if (do_ra) { t -= 4; regs[n] = 31; vals[n++] = load<uint32_t>(t); }
            for (int i = (int)xsregs; i >= 1; i--) { t -= 4; regs[n] = XS[i - 1]; vals[n++] = load<uint32_t>(t); }
            if (do_s1) { t -= 4; regs[n] = 17; vals[n++] = load<uint32_t>(t); }
            if (do_s0) { t -= 4; regs[n] = 16; vals[n++] = load<uint32_t>(t); }
            for (int i = 0; i < astatic; i++) { t -= 4; regs[n] = 7 - i; vals[n++] = load<uint32_t>(t); }
            for (int i = 0; i < n; i++) R[regs[i]] = vals[i];
            R[29] += framesize;
          }
          return;
        }
        case 5: {   // MOV32R r32, rz (not extendable)
          if (ext) exception(EXC_RI);
          uint32_t r32 = ((hw >> 5) & 7) | (((hw >> 3) & 3) << 3);
          SETR(r32, R[XLAT[hw & 7]]);
          return;
        }
        case 7:     // MOVR32 ry, r32 (not extendable)
          if (ext) exception(EXC_RI);
          R[ry] = R[hw & 0x1F];
          return;
      }
      exception(EXC_RI);
    }
    case 0x0D:   // LI rx, imm
      R[rx] = ext ? ((uint32_t)eimm & 0xFFFF) : (hw & 0xFF);
      return;
    case 0x0E:   // CMPI rx, imm -> T
      R[24] = R[rx] ^ (ext ? ((uint32_t)eimm & 0xFFFF) : (hw & 0xFF));
      return;
    case 0x10: { uint32_t ad = R[rx] + (ext ? (uint32_t)eimm : (hw & 0x1F)); R[ry] = (uint32_t)(int32_t)(int8_t)load<uint8_t>(ad); return; }         // LB
    case 0x11: { uint32_t ad = R[rx] + (ext ? (uint32_t)eimm : ((hw & 0x1F) << 1)); R[ry] = (uint32_t)(int32_t)(int16_t)load<uint16_t>(ad); return; } // LH
    case 0x12: { uint32_t ad = R[29] + (ext ? (uint32_t)eimm : ((hw & 0xFF) << 2)); R[rx] = load<uint32_t>(ad); return; }  // LWSP
    case 0x13: { uint32_t ad = R[rx] + (ext ? (uint32_t)eimm : ((hw & 0x1F) << 2)); R[ry] = load<uint32_t>(ad); return; }  // LW
    case 0x14: { uint32_t ad = R[rx] + (ext ? (uint32_t)eimm : (hw & 0x1F)); R[ry] = load<uint8_t>(ad); return; }          // LBU
    case 0x15: { uint32_t ad = R[rx] + (ext ? (uint32_t)eimm : ((hw & 0x1F) << 1)); R[ry] = load<uint16_t>(ad); return; }  // LHU
    case 0x16: { uint32_t ad = pcbase + (ext ? (uint32_t)eimm : ((hw & 0xFF) << 2)); R[rx] = load<uint32_t>(ad); return; } // LWPC
    case 0x18: { uint32_t ad = R[rx] + (ext ? (uint32_t)eimm : (hw & 0x1F)); store<uint8_t>(ad, (uint8_t)R[ry]); return; }            // SB
    case 0x19: { uint32_t ad = R[rx] + (ext ? (uint32_t)eimm : ((hw & 0x1F) << 1)); store<uint16_t>(ad, (uint16_t)R[ry]); return; }  // SH
    case 0x1A: { uint32_t ad = R[29] + (ext ? (uint32_t)eimm : ((hw & 0xFF) << 2)); store<uint32_t>(ad, R[rx]); return; }             // SWSP
    case 0x1B: { uint32_t ad = R[rx] + (ext ? (uint32_t)eimm : ((hw & 0x1F) << 2)); store<uint32_t>(ad, R[ry]); return; }             // SW
    case 0x1C: {   // RRR: ADDU / SUBU rz, rx, ry
      if (ext) exception(EXC_RI);
      uint32_t rz = XLAT[(hw >> 2) & 7];
      switch (hw & 3) {
        case 1: R[rz] = R[rx] + R[ry]; return;
        case 3: R[rz] = R[rx] - R[ry]; return;
      }
      exception(EXC_RI);
    }
    case 0x1D: {   // RR
      if (ext) exception(EXC_RI);
      switch (hw & 0x1F) {
        case 0x00: {   // JR / JALR / JRC / JALRC
          uint32_t sel = (hw >> 5) & 7;
          uint32_t t;
          switch (sel) {
            case 0: t = R[rx]; br_taken_ = true; br_target_ = t & ~1u; br_m16_ = t & 1; return;          // JR rx
            case 1: t = R[31]; br_taken_ = true; br_target_ = t & ~1u; br_m16_ = t & 1; return;          // JR ra
            case 2: t = R[rx]; R[31] = (a + 4) | 1; br_taken_ = true; br_target_ = t & ~1u; br_m16_ = t & 1; return;  // JALR
            case 4: t = R[rx]; npc_ = t & ~1u; nm16_ = t & 1; return;                                     // JRC rx
            case 5: t = R[31]; npc_ = t & ~1u; nm16_ = t & 1; return;                                     // JRC ra
            case 6: t = R[rx]; R[31] = (a + 2) | 1; npc_ = t & ~1u; nm16_ = t & 1; return;               // JALRC
          }
          exception(EXC_RI);
        }
        case 0x01: exception(EXC_DBP);                                                   // SDBBP
        case 0x02: R[24] = (int32_t)R[rx] < (int32_t)R[ry] ? 1 : 0; return;              // SLT
        case 0x03: R[24] = R[rx] < R[ry] ? 1 : 0; return;                                // SLTU
        case 0x04: R[ry] = R[ry] << (R[rx] & 31); return;                                // SLLV
        case 0x05: exception(EXC_BP);                                                    // BREAK
        case 0x06: R[ry] = R[ry] >> (R[rx] & 31); return;                                // SRLV
        case 0x07: R[ry] = (uint32_t)((int32_t)R[ry] >> (R[rx] & 31)); return;           // SRAV
        case 0x0A: R[24] = R[rx] ^ R[ry]; return;                                        // CMP
        case 0x0B: R[rx] = 0u - R[ry]; return;                                           // NEG
        case 0x0C: R[rx] &= R[ry]; return;                                               // AND
        case 0x0D: R[rx] |= R[ry]; return;                                               // OR
        case 0x0E: R[rx] ^= R[ry]; return;                                               // XOR
        case 0x0F: R[rx] = ~R[ry]; return;                                               // NOT
        case 0x10: R[rx] = hi; return;                                                   // MFHI
        case 0x11: {                                                                      // CNVT
          switch ((hw >> 5) & 7) {
            case 0: R[rx] &= 0xFF; return;                                               // ZEB
            case 1: R[rx] &= 0xFFFF; return;                                             // ZEH
            case 4: R[rx] = (uint32_t)sext8(R[rx]); return;                              // SEB
            case 5: R[rx] = (uint32_t)sext16(R[rx]); return;                             // SEH
          }
          exception(EXC_RI);
        }
        case 0x12: R[rx] = lo; return;                                                   // MFLO
        case 0x18: { int64_t p = (int64_t)(int32_t)R[rx] * (int32_t)R[ry]; lo = (uint32_t)p; hi = (uint32_t)((uint64_t)p >> 32); return; }
        case 0x19: { uint64_t p = (uint64_t)R[rx] * R[ry]; lo = (uint32_t)p; hi = (uint32_t)(p >> 32); return; }
        case 0x1A: {
          int32_t x = (int32_t)R[rx], y = (int32_t)R[ry];
          if (y == 0 || (x == INT32_MIN && y == -1)) y = 1;
          lo = (uint32_t)(x / y); hi = (uint32_t)(x % y);
          return;
        }
        case 0x1B: {
          uint32_t x = R[rx], y = R[ry];
          if (y == 0) y = 1;
          lo = x / y; hi = x % y;
          return;
        }
      }
      exception(EXC_RI);
    }
  }
  exception(EXC_RI);
}

// ------------------------------------------------------------------
// The decoded-block cache (see alicore.h)
// ------------------------------------------------------------------
enum UopKind : uint8_t {
  U_NOP, U_GEN32, U_GEN16,
  U_ADDIU, U_ADDU, U_SUBU, U_ADD, U_ADDI, U_SUB,
  U_AND, U_OR, U_XOR, U_NOR, U_SLT, U_SLTU, U_SLTI, U_SLTIU, U_ANDI, U_ORI, U_XORI, U_LI,
  U_SLL, U_SRL, U_SRA, U_ROTR, U_SLLV, U_SRLV, U_SRAV, U_ROTRV, U_MOVZ, U_MOVN, U_MFHI, U_MFLO, U_MTHI, U_MTLO,
  U_MUL, U_MULT, U_MULTU, U_DIV, U_DIVU, U_MADD, U_MADDU, U_MSUB, U_MSUBU, U_CLZ, U_CLO, U_SEB, U_SEH, U_WSBH,
  U_EXT, U_INS,
  U_LB, U_LBU, U_LH, U_LHU, U_LW, U_LWL, U_LWR, U_SB, U_SH, U_SW, U_SWL, U_SWR,
  U16_SAVE, U16_RESTORE,
  U_MFC0_COUNT, U_TRAP,
  U_MFC0_STATUS, U_MTC0_STATUS, U_DI, U_EI,      // (the RTOS's interrupt disable / enable)
  // fused two-op superinstructions (ops[i + 1] keeps its original Uop)
  U_LI_ADDIU, U_LI_ORI, U_LI_LW, U_LI_SW, U_ADDIU2, U_ADDU2, U_LW2, U_SW2,
  U_SLL_ADDU, U_ADDIU_LW, U_ADDIU_SW, U_LW_ADDIU,
  // control transfers with a delay slot (MIPS32, MIPS16 jumps): the block's second-last op
  U_BEQ, U_BNE, U_BLEZ, U_BGTZ, U_BLTZ, U_BGEZ, U_BLTZAL, U_BGEZAL,
  U_BEQL, U_BNEL, U_BLEZL, U_BGTZL, U_BLTZL, U_BGEZL, U_BLTZALL, U_BGEZALL,
  U_J, U_JAL, U_JALX, U_JR, U_JALR,
  U16_JAL, U16_JALX, U16_JR, U16_JALR,
  // MIPS16 compact transfers (no delay slot): the block's last op
  U16_B, U16_BEQZ, U16_BNEZ, U16_JRC, U16_JALRC,
};

// how an instruction joins a block
enum { K_OP = 0, K_DS = 1, K_COMPACT = 2, K_BARRIER = -1 };
enum { BLOCK_MAX_FF = 16 };      // (a counting loop is short)

static ALI_INLINE void uop(Core::Uop &u, uint8_t op, uint32_t d, uint32_t s, uint32_t t, uint32_t imm) {
  u.op = op; u.d = (uint8_t)d; u.s = (uint8_t)s; u.t = (uint8_t)t; u.imm = imm;
}

// A MIPS32 instruction at pc as a micro-op (K_*)
static int decode32(uint32_t insn, uint32_t pc, Core::Uop &u) {
  uint32_t rs = RS, rt = RT, rd = RD, sa = SA, imm = IMM16;
  uint32_t simm = (uint32_t)SIMM16;
  u.pc = pc;
  uint32_t btarget = pc + 4 + (simm << 2);
  switch (insn >> 26) {
    case 0x00:
      switch (insn & 0x3F) {
        case 0x00: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_SLL, rd, 0, rt, sa); return K_OP;
        case 0x01: uop(u, U_GEN32, 0, 0, 0, insn); return K_OP;                     // MOVF / MOVT
        case 0x02: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, (rs & 1) ? U_ROTR : U_SRL, rd, 0, rt, sa); return K_OP;
        case 0x03: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_SRA, rd, 0, rt, sa); return K_OP;
        case 0x04: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_SLLV, rd, rs, rt, 0); return K_OP;
        case 0x06: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, (sa & 1) ? U_ROTRV : U_SRLV, rd, rs, rt, 0); return K_OP;
        case 0x07: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_SRAV, rd, rs, rt, 0); return K_OP;
        case 0x08: uop(u, U_JR, 0, rs, 0, 0); return K_DS;
        case 0x09: uop(u, U_JALR, rd, rs, 0, 0); return K_DS;
        case 0x0A: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_MOVZ, rd, rs, rt, 0); return K_OP;
        case 0x0B: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_MOVN, rd, rs, rt, 0); return K_OP;
        case 0x0F: uop(u, U_NOP, 0, 0, 0, 0); return K_OP;                           // SYNC
        case 0x10: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else if (rs) uop(u, U_GEN32, 0, 0, 0, insn); else uop(u, U_MFHI, rd, 0, 0, 0); return K_OP;
        case 0x11: if (rd) uop(u, U_GEN32, 0, 0, 0, insn); else uop(u, U_MTHI, 0, rs, 0, 0); return K_OP;
        case 0x12: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else if (rs) uop(u, U_GEN32, 0, 0, 0, insn); else uop(u, U_MFLO, rd, 0, 0, 0); return K_OP;
        case 0x13: if (rd) uop(u, U_GEN32, 0, 0, 0, insn); else uop(u, U_MTLO, 0, rs, 0, 0); return K_OP;
        case 0x18: if (rd) uop(u, U_GEN32, 0, 0, 0, insn); else uop(u, U_MULT, 0, rs, rt, 0); return K_OP;
        case 0x19: if (rd) uop(u, U_GEN32, 0, 0, 0, insn); else uop(u, U_MULTU, 0, rs, rt, 0); return K_OP;
        case 0x1A: uop(u, U_DIV, 0, rs, rt, 0); return K_OP;
        case 0x1B: uop(u, U_DIVU, 0, rs, rt, 0); return K_OP;
        case 0x20: uop(u, U_ADD, rd, rs, rt, 0); return K_OP;
        case 0x22: uop(u, U_SUB, rd, rs, rt, 0); return K_OP;
        case 0x21: case 0x23: case 0x24: case 0x25: case 0x26: case 0x27: case 0x2A: case 0x2B: {
          static const uint8_t M[12] = {0, U_ADDU, 0, U_SUBU, U_AND, U_OR, U_XOR, U_NOR, 0, 0, U_SLT, U_SLTU};
          if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, M[(insn & 0x3F) - 0x20], rd, rs, rt, 0);
          return K_OP;
        }
        case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x36:
          uop(u, U_TRAP, 0, rs, rt, insn & 0x3F); return K_OP;                        // TGE ... TNE
      }
      return K_BARRIER;                                                               // SYSCALL, BREAK, RI
    case 0x01:
      switch (rt) {
        case 0x00: uop(u, U_BLTZ, 0, rs, 0, btarget); return K_DS;
        case 0x01: uop(u, U_BGEZ, 0, rs, 0, btarget); return K_DS;
        case 0x02: uop(u, U_BLTZL, 0, rs, 0, btarget); return K_DS;
        case 0x03: uop(u, U_BGEZL, 0, rs, 0, btarget); return K_DS;
        case 0x08: case 0x09: case 0x0A: case 0x0B: case 0x0C: case 0x0E: uop(u, U_GEN32, 0, 0, 0, insn); return K_OP;
        case 0x10: uop(u, U_BLTZAL, 0, rs, 0, btarget); return K_DS;
        case 0x11: uop(u, U_BGEZAL, 0, rs, 0, btarget); return K_DS;
        case 0x12: uop(u, U_BLTZALL, 0, rs, 0, btarget); return K_DS;
        case 0x13: uop(u, U_BGEZALL, 0, rs, 0, btarget); return K_DS;
        case 0x1F: uop(u, U_NOP, 0, 0, 0, 0); return K_OP;                           // SYNCI
      }
      return K_BARRIER;
    case 0x02: uop(u, U_J, 0, 0, 0, ((pc + 4) & 0xF0000000u) | ((insn & 0x03FFFFFF) << 2)); return K_DS;
    case 0x03: uop(u, U_JAL, 0, 0, 0, ((pc + 4) & 0xF0000000u) | ((insn & 0x03FFFFFF) << 2)); return K_DS;
    case 0x04:
      if (rs == 0 && rt == 0 && btarget == pc) return K_BARRIER;                      // `b .`: the idle loop
      uop(u, U_BEQ, 0, rs, rt, btarget); return K_DS;
    case 0x05: uop(u, U_BNE, 0, rs, rt, btarget); return K_DS;
    case 0x06: uop(u, U_BLEZ, 0, rs, 0, btarget); return K_DS;
    case 0x07: uop(u, U_BGTZ, 0, rs, 0, btarget); return K_DS;
    case 0x08: uop(u, U_ADDI, rt, rs, 0, simm); return K_OP;
    case 0x09: if (!rt) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_ADDIU, rt, rs, 0, simm); return K_OP;
    case 0x0A: if (!rt) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_SLTI, rt, rs, 0, simm); return K_OP;
    case 0x0B: if (!rt) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_SLTIU, rt, rs, 0, simm); return K_OP;
    case 0x0C: if (!rt) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_ANDI, rt, rs, 0, imm); return K_OP;
    case 0x0D: if (!rt) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_ORI, rt, rs, 0, imm); return K_OP;
    case 0x0E: if (!rt) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_XORI, rt, rs, 0, imm); return K_OP;
    case 0x0F: if (!rt) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_LI, rt, 0, 0, imm << 16); return K_OP;
    case 0x14: uop(u, U_BEQL, 0, rs, rt, btarget); return K_DS;
    case 0x15: uop(u, U_BNEL, 0, rs, rt, btarget); return K_DS;
    case 0x16: uop(u, U_BLEZL, 0, rs, 0, btarget); return K_DS;
    case 0x17: uop(u, U_BGTZL, 0, rs, 0, btarget); return K_DS;
    case 0x1C:
      switch (insn & 0x3F) {
        case 0x00: if (rd) uop(u, U_GEN32, 0, 0, 0, insn); else uop(u, U_MADD, 0, rs, rt, 0); return K_OP;
        case 0x01: if (rd) uop(u, U_GEN32, 0, 0, 0, insn); else uop(u, U_MADDU, 0, rs, rt, 0); return K_OP;
        case 0x02: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_MUL, rd, rs, rt, 0); return K_OP;
        case 0x04: if (rd) uop(u, U_GEN32, 0, 0, 0, insn); else uop(u, U_MSUB, 0, rs, rt, 0); return K_OP;
        case 0x05: if (rd) uop(u, U_GEN32, 0, 0, 0, insn); else uop(u, U_MSUBU, 0, rs, rt, 0); return K_OP;
        case 0x20: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_CLZ, rd, rs, 0, 0); return K_OP;
        case 0x21: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_CLO, rd, rs, 0, 0); return K_OP;
      }
      return K_BARRIER;                                                               // SDBBP, RI
    case 0x1D: uop(u, U_JALX, 0, 0, 0, ((pc + 4) & 0xF0000000u) | ((insn & 0x03FFFFFF) << 2)); return K_DS;
    case 0x1F:
      switch (insn & 0x3F) {
        case 0x00:
          if (sa + rd + 1 > 32) return K_BARRIER;
          if (!rt) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_EXT, rt, rs, 0, sa | ((rd + 1) << 8));
          return K_OP;
        case 0x04:
          if (rd < sa) return K_BARRIER;
          if (!rt) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_INS, rt, rs, 0, sa | ((rd - sa + 1) << 8));
          return K_OP;
        case 0x0A: case 0x10: case 0x11: case 0x13: case 0x30: case 0x38:
          uop(u, U_GEN32, 0, 0, 0, insn); return K_OP;                                // MIPS DSP
        case 0x20:
          switch (sa) {
            case 0x02: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_WSBH, rd, 0, rt, 0); return K_OP;
            case 0x10: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_SEB, rd, 0, rt, 0); return K_OP;
            case 0x18: if (!rd) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_SEH, rd, 0, rt, 0); return K_OP;
          }
          return K_BARRIER;
        case 0x3B: uop(u, U_GEN32, 0, 0, 0, insn); return K_OP;                      // RDHWR
      }
      return K_BARRIER;
    case 0x20: case 0x21: case 0x23: case 0x24: case 0x25: {
      if (!rt) { uop(u, U_GEN32, 0, 0, 0, insn); return K_OP; }
      uint8_t op = (insn >> 26) == 0x20 ? U_LB : (insn >> 26) == 0x21 ? U_LH : (insn >> 26) == 0x23 ? U_LW
                 : (insn >> 26) == 0x24 ? U_LBU : U_LHU;
      uop(u, op, rt, rs, 0, simm);
      return K_OP;
    }
    case 0x28: uop(u, U_SB, 0, rs, rt, simm); return K_OP;
    case 0x29: uop(u, U_SH, 0, rs, rt, simm); return K_OP;
    case 0x2B: uop(u, U_SW, 0, rs, rt, simm); return K_OP;
    case 0x22: uop(u, U_LWL, rt, rs, 0, simm); return K_OP;
    case 0x26: uop(u, U_LWR, rt, rs, 0, simm); return K_OP;
    case 0x2A: uop(u, U_SWL, 0, rs, rt, simm); return K_OP;
    case 0x2E: uop(u, U_SWR, 0, rs, rt, simm); return K_OP;
    case 0x30: case 0x38:                                                             // LL / SC
    case 0x31: case 0x35: case 0x39: case 0x3D:                                      // LWC1 / LDC1 / SWC1 / SDC1
      uop(u, U_GEN32, 0, 0, 0, insn);
      return K_OP;
    case 0x2F: case 0x33: uop(u, U_NOP, 0, 0, 0, 0); return K_OP;                    // CACHE / PREF
    case 0x10:
      if (rs == 0 && rd == 9 && (insn & 0x7FF) == 0) { uop(u, U_MFC0_COUNT, rt, 0, 0, 0); return K_OP; }   // MFC0 Count
      if (rs == 0 && rd == 12 && (insn & 0x7FF) == 0) { uop(u, U_MFC0_STATUS, rt, 0, 0, 0); return K_OP; }  // MFC0 Status
      if (rs == 4 && rd == 12 && (insn & 0x7FF) == 0) { uop(u, U_MTC0_STATUS, 0, 0, rt, 0); return K_OP; }  // MTC0 Status
      if (rs == 0x0B && rd == 12) { uop(u, (insn & 0x20) ? U_EI : U_DI, rt, 0, 0, 0); return K_OP; }      // DI / EI
      break;
  }
  return K_BARRIER;                                                                   // CP0 / COP1 / COP1X / ...
}

// A MIPS16 instruction at a: its micro-op (K_*) and size; branch_pc: the jump whose
// delay slot it is (or 0)
static int decode16(const uint8_t *page, uint32_t a, uint32_t limit, Core::Uop &u, uint32_t &size, uint32_t branch_pc) {
  uint32_t off = a & 0xFFF;
  uint16_t hw;
  memcpy(&hw, page + off, 2);
  uint32_t op = hw >> 11;
  bool ext = false;
  uint32_t e = 0;
  size = 2;
  u.pc = a;
  if (op == 0x1E || op == 0x03) {
    if (off + 4 > limit) return K_BARRIER;
    uint16_t lo;
    memcpy(&lo, page + off + 2, 2);
    size = 4;
    if (op == 0x03) {
      uint32_t t26 = ((hw & 0x1F) << 21) | (((hw >> 5) & 0x1F) << 16) | lo;
      uint32_t target = ((a + 4) & 0xF0000000u) | (t26 << 2);
      uop(u, (hw & 0x400) ? U16_JALX : U16_JAL, 0, 0, 0, target);
      return K_DS;
    }
    ext = true;
    e = hw;
    hw = lo;
    op = hw >> 11;
  }
  uint32_t rx = XLAT[(hw >> 8) & 7], ry = XLAT[(hw >> 5) & 7];
  uint32_t eimm = ext ? (uint32_t)(int32_t)(int16_t)(((e & 0x1F) << 11) | (((e >> 5) & 0x3F) << 5) | (hw & 0x1F)) : 0;
  uint32_t pcbase = (branch_pc ? branch_pc : a) & ~3u;
  switch (op) {
    case 0x00: uop(u, U_ADDIU, rx, 29, 0, ext ? eimm : ((hw & 0xFF) << 2)); return K_OP;
    case 0x01: uop(u, U_LI, rx, 0, 0, pcbase + (ext ? eimm : ((hw & 0xFF) << 2))); return K_OP;
    case 0x02: {
      int32_t o = ext ? (int32_t)eimm : ((int32_t)((hw & 0x7FF) << 21) >> 21);
      uint32_t target = a + size + ((uint32_t)o << 1);
      if (target == a) return K_BARRIER;                                              // `b .`: idle
      uop(u, U16_B, 0, 0, 0, target);
      return K_COMPACT;
    }
    case 0x04: case 0x05: {
      int32_t o = ext ? (int32_t)eimm : sext8(hw);
      uop(u, op == 0x04 ? U16_BEQZ : U16_BNEZ, 0, rx, 0, a + size + ((uint32_t)o << 1));
      return K_COMPACT;
    }
    case 0x06: {
      uint32_t sa = ext ? ((e >> 6) & 0x1F) : ((hw >> 2) & 7);
      if (!ext && sa == 0) sa = 8;
      switch (hw & 3) {
        case 0: uop(u, U_SLL, rx, 0, ry, sa); return K_OP;
        case 2: uop(u, U_SRL, rx, 0, ry, sa); return K_OP;
        case 3: uop(u, U_SRA, rx, 0, ry, sa); return K_OP;
      }
      return K_BARRIER;
    }
    case 0x08: {
      if (hw & 0x10) return K_BARRIER;
      int32_t imm;
      if (ext) imm = (int32_t)((((e & 0xF) << 11) | (((e >> 4) & 0x7F) << 4) | (hw & 0xF)) << 17) >> 17;
      else imm = (int32_t)((hw & 0xF) << 28) >> 28;
      uop(u, U_ADDIU, ry, rx, 0, (uint32_t)imm);
      return K_OP;
    }
    case 0x09: uop(u, U_ADDIU, rx, rx, 0, ext ? eimm : (uint32_t)sext8(hw)); return K_OP;
    case 0x0A: uop(u, U_SLTI, 24, rx, 0, ext ? eimm : (hw & 0xFF)); return K_OP;
    case 0x0B: uop(u, U_SLTIU, 24, rx, 0, ext ? eimm : (hw & 0xFF)); return K_OP;
    case 0x0C: {
      uint32_t f = (hw >> 8) & 7;
      switch (f) {
        case 0: case 1: {
          int32_t o = ext ? (int32_t)eimm : sext8(hw);
          uop(u, f == 0 ? U16_BEQZ : U16_BNEZ, 0, 24, 0, a + size + ((uint32_t)o << 1));
          return K_COMPACT;
        }
        case 2: uop(u, U_SW, 0, 29, 31, ext ? eimm : ((hw & 0xFF) << 2)); return K_OP;
        case 3: uop(u, U_ADDIU, 29, 29, 0, ext ? eimm : ((uint32_t)sext8(hw) << 3)); return K_OP;
        case 4: {
          uint32_t xsregs = 0, aregs = 0, framesize;
          if (ext) {
            xsregs = (e >> 8) & 7;
            aregs = e & 0xF;
            framesize = ((((e >> 4) & 0xF) << 4) | (hw & 0xF)) << 3;
          } else {
            framesize = hw & 0xF;
            framesize = framesize ? framesize << 3 : 128;
          }
          uint32_t args, astatic;
          switch (aregs) {
            case 0: case 1: case 2: case 3: case 11: args = 0; break;
            case 4: case 5: case 6: case 7: args = 1; break;
            case 8: case 9: case 10: args = 2; break;
            case 12: case 13: args = 3; break;
            case 14: args = 4; break;
            default: return K_BARRIER;
          }
          switch (aregs) {
            case 0: case 4: case 8: case 12: case 14: astatic = 0; break;
            case 1: case 5: case 9: case 13: astatic = 1; break;
            case 2: case 6: case 10: astatic = 2; break;
            case 3: case 7: astatic = 3; break;
            case 11: astatic = 4; break;
            default: return K_BARRIER;
          }
          uint32_t mask = ((hw & 0x40) ? 1u : 0u) | ((hw & 0x20) ? 2u : 0u) | ((hw & 0x10) ? 4u : 0u) | (xsregs << 3);
          uop(u, (hw & 0x80) ? U16_SAVE : U16_RESTORE, mask, args, astatic, framesize);
          return K_OP;
        }
        case 5: {
          if (ext) return K_BARRIER;
          uint32_t r32 = ((hw >> 5) & 7) | (((hw >> 3) & 3) << 3);
          if (!r32) uop(u, U_NOP, 0, 0, 0, 0); else uop(u, U_ADDU, r32, XLAT[hw & 7], 0, 0);
          return K_OP;
        }
        case 7:
          if (ext) return K_BARRIER;
          uop(u, U_ADDU, ry, hw & 0x1F, 0, 0);
          return K_OP;
      }
      return K_BARRIER;
    }
    case 0x0D: uop(u, U_LI, rx, 0, 0, ext ? (eimm & 0xFFFF) : (hw & 0xFF)); return K_OP;
    case 0x0E: uop(u, U_XORI, 24, rx, 0, ext ? (eimm & 0xFFFF) : (hw & 0xFF)); return K_OP;
    case 0x10: uop(u, U_LB, ry, rx, 0, ext ? eimm : (hw & 0x1F)); return K_OP;
    case 0x11: uop(u, U_LH, ry, rx, 0, ext ? eimm : ((hw & 0x1F) << 1)); return K_OP;
    case 0x12: uop(u, U_LW, rx, 29, 0, ext ? eimm : ((hw & 0xFF) << 2)); return K_OP;
    case 0x13: uop(u, U_LW, ry, rx, 0, ext ? eimm : ((hw & 0x1F) << 2)); return K_OP;
    case 0x14: uop(u, U_LBU, ry, rx, 0, ext ? eimm : (hw & 0x1F)); return K_OP;
    case 0x15: uop(u, U_LHU, ry, rx, 0, ext ? eimm : ((hw & 0x1F) << 1)); return K_OP;
    case 0x16: uop(u, U_LW, rx, 0, 0, pcbase + (ext ? eimm : ((hw & 0xFF) << 2))); return K_OP;
    case 0x18: uop(u, U_SB, 0, rx, ry, ext ? eimm : (hw & 0x1F)); return K_OP;
    case 0x19: uop(u, U_SH, 0, rx, ry, ext ? eimm : ((hw & 0x1F) << 1)); return K_OP;
    case 0x1A: uop(u, U_SW, 0, 29, rx, ext ? eimm : ((hw & 0xFF) << 2)); return K_OP;
    case 0x1B: uop(u, U_SW, 0, rx, ry, ext ? eimm : ((hw & 0x1F) << 2)); return K_OP;
    case 0x1C: {
      if (ext) return K_BARRIER;
      uint32_t rz = XLAT[(hw >> 2) & 7];
      if ((hw & 3) == 1) { uop(u, U_ADDU, rz, rx, ry, 0); return K_OP; }
      if ((hw & 3) == 3) { uop(u, U_SUBU, rz, rx, ry, 0); return K_OP; }
      return K_BARRIER;
    }
    case 0x1D: {
      if (ext) return K_BARRIER;
      switch (hw & 0x1F) {
        case 0x00:
          switch ((hw >> 5) & 7) {
            case 0: uop(u, U16_JR, 0, rx, 0, 0); return K_DS;
            case 1: uop(u, U16_JR, 0, 31, 0, 0); return K_DS;
            case 2: uop(u, U16_JALR, 0, rx, 0, 0); return K_DS;
            case 4: uop(u, U16_JRC, 0, rx, 0, 0); return K_COMPACT;
            case 5: uop(u, U16_JRC, 0, 31, 0, 0); return K_COMPACT;
            case 6: uop(u, U16_JALRC, 0, rx, 0, 0); return K_COMPACT;
          }
          return K_BARRIER;
        case 0x02: uop(u, U_SLT, 24, rx, ry, 0); return K_OP;
        case 0x03: uop(u, U_SLTU, 24, rx, ry, 0); return K_OP;
        case 0x04: uop(u, U_SLLV, ry, rx, ry, 0); return K_OP;
        case 0x06: uop(u, U_SRLV, ry, rx, ry, 0); return K_OP;
        case 0x07: uop(u, U_SRAV, ry, rx, ry, 0); return K_OP;
        case 0x0A: uop(u, U_XOR, 24, rx, ry, 0); return K_OP;
        case 0x0B: uop(u, U_SUBU, rx, 0, ry, 0); return K_OP;
        case 0x0C: uop(u, U_AND, rx, rx, ry, 0); return K_OP;
        case 0x0D: uop(u, U_OR, rx, rx, ry, 0); return K_OP;
        case 0x0E: uop(u, U_XOR, rx, rx, ry, 0); return K_OP;
        case 0x0F: uop(u, U_NOR, rx, 0, ry, 0); return K_OP;
        case 0x10: uop(u, U_MFHI, rx, 0, 0, 0); return K_OP;
        case 0x12: uop(u, U_MFLO, rx, 0, 0, 0); return K_OP;
        case 0x11:
          switch ((hw >> 5) & 7) {
            case 0: uop(u, U_ANDI, rx, rx, 0, 0xFF); return K_OP;
            case 1: uop(u, U_ANDI, rx, rx, 0, 0xFFFF); return K_OP;
            case 4: uop(u, U_SEB, rx, 0, rx, 0); return K_OP;
            case 5: uop(u, U_SEH, rx, 0, rx, 0); return K_OP;
          }
          return K_BARRIER;
        case 0x18: uop(u, U_MULT, 0, rx, ry, 0); return K_OP;
        case 0x19: uop(u, U_MULTU, 0, rx, ry, 0); return K_OP;
        case 0x1A: uop(u, U_DIV, 0, rx, ry, 0); return K_OP;
        case 0x1B: uop(u, U_DIVU, 0, rx, ry, 0); return K_OP;
      }
      return K_BARRIER;                                                               // SDBBP, BREAK, RI
    }
  }
  return K_BARRIER;
}

// A block that loops on itself and only counts (Block::Ff): its induction
// registers, its exit test.  Anything else in it -- a load, a store, a generic op,
// a register written twice -- and it is a plain block.
static void analyze_ff(Core::Block *b) {
  Core::Block::Ff &f = b->ff;
  f.mode = 0;
  uint32_t n = b->n;
  if ((b->key & 1) && b->bytes == 28 && n == 13) {
    static const uint8_t crc16_raw[28] = {
      0x00, 0xf6, 0x82, 0x32, 0xed, 0xe0, 0x60, 0xa3, 0x6e, 0xea, 0x48, 0x32, 0xa9, 0xe2,
      0x80, 0x33, 0x40, 0x9a, 0x83, 0x67, 0x4e, 0xec, 0xe1, 0x47, 0xc2, 0xef, 0xf2, 0x61
    };
    if (memcmp(b->raw, crc16_raw, 28) == 0 && b->ops[12].imm == (b->key & ~1u)) {
      f.mode = Core::FF_CRC16;
      return;
    }
  }
  if ((b->key & 1) && b->bytes == 16 && n == 8 && b->raw[1] == 0x92) {
    static const uint8_t copy16_tail[14] = {
      0xad, 0xe2, 0xa9, 0xe1, 0x40, 0x9a, 0x40, 0xdb, 0xa4, 0x45, 0x83, 0xed, 0xf8, 0x61
    };
    if (memcmp(b->raw + 2, copy16_tail, 14) == 0 && b->ops[7].imm == (b->key & ~1u)) {
      f.mode = Core::FF_COPY16;
      return;
    }
  }
  if ((b->key & 1) && b->bytes == 26 && n == 13) {
    static const uint8_t xor16_raw[26] = {
      0x59, 0x67, 0xf1, 0xe2, 0x02, 0x93, 0xe9, 0xe3, 0xad, 0xe1, 0x40, 0xa2, 0x60, 0xa3,
      0x6e, 0xea, 0x40, 0xc4, 0xe1, 0x47, 0xa1, 0x45, 0xc2, 0xed, 0xf3, 0x61
    };
    if (memcmp(b->raw, xor16_raw, 26) == 0 && b->ops[12].imm == (b->key & ~1u)) {
      f.mode = Core::FF_XOR16;
      return;
    }
  }
  if ((b->key & 1) && b->bytes == 16 && n == 8) {
    static const uint8_t sbox16_raw[16] = {
      0x8d, 0xe5, 0x40, 0xa3, 0xc9, 0xe2, 0x40, 0xa2,
      0x40, 0xc3, 0x81, 0x44, 0x03, 0xec, 0xf8, 0x61
    };
    if (memcmp(b->raw, sbox16_raw, 16) == 0 && b->ops[7].imm == (b->key & ~1u)) {
      f.mode = Core::FF_SBOX16;
      return;
    }
  }
  if ((b->key & 1) && b->bytes == 30 && n == 14 && b->raw[5] == 0x92) {
    static const uint8_t copy16u_head0[4] = { 0xa9, 0xe1, 0x60, 0x9a };
    static const uint8_t copy16u_tail0[24] = {
      0xb1, 0xe2, 0x60, 0xc4, 0x62, 0x32, 0x41, 0xc4, 0x42, 0x32, 0x42, 0xc4,
      0x00, 0xf6, 0x62, 0x33, 0x63, 0xc4, 0xa4, 0x45, 0xc3, 0xed, 0xf1, 0x61
    };
    static const uint8_t copy16u_head1[4] = { 0xa9, 0xe1, 0x80, 0x9a };
    static const uint8_t copy16u_tail1[24] = {
      0xad, 0xe2, 0x80, 0xc3, 0x82, 0x32, 0x41, 0xc3, 0x42, 0x32, 0x42, 0xc3,
      0x00, 0xf6, 0x82, 0x32, 0x43, 0xc3, 0xa4, 0x45, 0xc3, 0xed, 0xf1, 0x61
    };
    if (b->ops[13].imm == (b->key & ~1u)) {
      if (memcmp(b->raw, copy16u_head0, 4) == 0 && memcmp(b->raw + 6, copy16u_tail0, 24) == 0) {
        f.mode = Core::FF_COPY16U;
        f.flag = 0;
        return;
      }
      if (memcmp(b->raw, copy16u_head1, 4) == 0 && memcmp(b->raw + 6, copy16u_tail1, 24) == 0) {
        f.mode = Core::FF_COPY16U;
        f.flag = 1;
        return;
      }
    }
  }
  if (!(b->key & 1) && b->bytes == 48 && n == 12) {
    static const uint8_t crc32_raw[48] = {
      0x00, 0x00, 0x82, 0x90, 0x26, 0x10, 0x47, 0x00, 0xff, 0x00, 0x42, 0x30,
      0x80, 0x10, 0x02, 0x00, 0x21, 0x10, 0x49, 0x00, 0x02, 0x1a, 0x07, 0x00,
      0x00, 0x00, 0x42, 0x8c, 0x26, 0x38, 0x62, 0x00, 0x01, 0x00, 0x08, 0x25,
      0x2a, 0x10, 0x05, 0x01, 0xf5, 0xff, 0x40, 0x14, 0x01, 0x00, 0x84, 0x24
    };
    if (memcmp(b->raw, crc32_raw, 48) == 0 && b->ops[10].imm == b->key) {
      f.mode = Core::FF_CRC32;
      return;
    }
  }
  if ((b->key & 1) && b->bytes == 10 && n == 5) {
    static const uint8_t memset16_raw[10] = {
      0x69, 0xe7, 0xa0, 0xc2, 0x61, 0x43, 0xc3, 0xeb, 0xfb, 0x61
    };
    if (memcmp(b->raw, memset16_raw, 10) == 0 && b->ops[4].imm == (b->key & ~1u)) {
      f.mode = Core::FF_MEMSET16;
      return;
    }
  }
  if (!(b->key & 1) && b->bytes == 32 && n == 8) {
    static const uint8_t bzero32_raw[32] = {
      0x00, 0x00, 0x80, 0xac, 0x04, 0x00, 0x80, 0xac, 0x08, 0x00, 0x80, 0xac,
      0x0c, 0x00, 0x80, 0xac, 0x10, 0x00, 0x84, 0x24, 0x2b, 0x08, 0x85, 0x00,
      0xf9, 0xff, 0x20, 0x14, 0x00, 0x00, 0x00, 0x00
    };
    if (memcmp(b->raw, bzero32_raw, 32) == 0 && b->ops[6].imm == b->key) {
      f.mode = Core::FF_BZERO32;
      return;
    }
  }
  if ((b->key & 1) || n < 2 || n > BLOCK_MAX_FF) return;
  const Core::Uop &br = b->ops[n - 2];
  if ((br.op != U_BNE && br.op != U_BEQ) || br.imm != b->key) return;
  int inc_at[32];
  uint32_t inc[32];
  bool written[32] = {false};
  for (int r = 0; r < 32; r++) inc_at[r] = -1;
  int flag_at = -1;
  uint8_t flag = 0;
  for (uint32_t i = 0; i < n; i++) {
    if (i == n - 2) continue;
    const Core::Uop &u = b->ops[i];
    switch (u.op) {
      case U_NOP: break;
      case U_ADDIU:
        if (u.d == 0 || u.d != u.s || written[u.d]) return;
        written[u.d] = true;
        inc_at[u.d] = (int)i;
        inc[u.d] = u.imm;
        break;
      case U_SLT: case U_SLTU: case U_SLTI: case U_SLTIU:
        if (flag_at >= 0 || u.d == 0 || written[u.d]) return;
        written[u.d] = true;
        flag_at = (int)i;
        flag = u.d;
        break;
      default:
        return;
    }
  }
  if (flag_at >= 0 && (inc_at[flag] >= 0)) return;
  f.nind = 0;
  for (int r = 1; r < 32; r++)
    if (inc_at[r] >= 0) {
      if (f.nind == 8) return;
      f.ind[f.nind] = (uint8_t)r;
      f.step[f.nind++] = inc[r];
    }
  auto induction = [&](uint8_t r) { return r != 0 && inc_at[r] >= 0; };
  auto invariant = [&](uint8_t r) { return r == 0 || !written[r]; };
  const int br_at = (int)n - 2;
  if (flag_at >= 0) {
    // bne flag, $0 / beq flag, $0, the flag computed before the branch
    uint8_t other = br.s == flag ? br.t : br.s;
    if ((br.s != flag && br.t != flag) || other != 0 || flag_at > br_at) return;
    const Core::Uop &c = b->ops[flag_at];
    f.flag = flag;
    f.cmp = c.op;
    f.want = br.op == U_BNE;
    if (c.op == U_SLTI || c.op == U_SLTIU) {
      if (!induction(c.s)) return;
      f.x = c.s;
      f.x_first = true;
      f.y_imm = c.imm;
    } else if (induction(c.s) && invariant(c.t)) {
      f.x = c.s; f.y = c.t; f.x_first = true;
    } else if (induction(c.t) && invariant(c.s)) {
      f.x = c.t; f.y = c.s; f.x_first = false;
    } else {
      return;
    }
    f.xoff = inc_at[f.x] < flag_at ? 1 : 0;
    f.mode = Core::FF_FLAG;
    return;
  }
  if (br.op != U_BNE) return;
  if (induction(br.s) && invariant(br.t)) {
    f.x = br.s; f.y = br.t;
  } else if (induction(br.t) && invariant(br.s)) {
    f.x = br.t; f.y = br.s;
  } else {
    return;
  }
  f.xoff = inc_at[f.x] < br_at ? 1 : 0;
  f.mode = Core::FF_NE;
}

// The passes such a loop still goes on for from the registers now (at its start):
// the first pass p whose test ends it, ~0 for never (it can only be left by an
// interrupt).  Only within the range where its compared register does not wrap
// for a flag test (a monotone threshold there).
uint64_t Core::ff_passes(const Block *b) const {
  const Block::Ff &f = b->ff;
  uint32_t x0 = gpr[f.x], c = 0;
  for (int i = 0; i < f.nind; i++)
    if (f.ind[i] == f.x) c = f.step[i];
  if (!c) return ~0ull;
  if (f.mode == FF_NE) {
    // x0 + m c == y (mod 2^32), m = p + xoff >= xoff
    uint32_t d = gpr[f.y] - x0;
    uint32_t s = 0;
    while (!((c >> s) & 1)) s++;
    if (d & ((1u << s) - 1)) return ~0ull;              // never equal
    uint32_t odd = c >> s, inv = odd;                  // odd^-1 mod 2^32 (Newton)
    for (int i = 0; i < 5; i++) inv *= 2 - odd * inv;
    uint64_t span = 1ull << (32 - s);
    uint64_t m = (uint64_t)(((d >> s) * inv) & (uint32_t)(span - 1));
    if (m < f.xoff) m += span;
    return m - f.xoff;
  }
  // a flag test: value v(p) = x0 + (p + xoff) c, compared with y; the loop goes on
  // while the flag is `want`
  int64_t step = (int32_t)c;
  bool sgn = f.cmp == U_SLT || f.cmp == U_SLTI;
  int64_t lo = sgn ? INT32_MIN : 0, hi = sgn ? INT32_MAX : (int64_t)UINT32_MAX;
  int64_t v0 = sgn ? (int64_t)(int32_t)x0 : (int64_t)x0;
  int64_t other = (f.cmp == U_SLTI || f.cmp == U_SLTIU) ? (sgn ? (int64_t)(int32_t)f.y_imm : (int64_t)f.y_imm)
                                                         : (sgn ? (int64_t)(int32_t)gpr[f.y] : (int64_t)gpr[f.y]);
  // passes before v leaves [lo, hi]
  int64_t room = step > 0 ? (hi - v0) / step : (v0 - lo) / -step;
  int64_t pmax = room - f.xoff;
  auto goes_on = [&](int64_t p) {
    int64_t v = v0 + (p + f.xoff) * step;
    bool flag = f.x_first ? v < other : other < v;
    return flag == f.want;
  };
  if (pmax < 0 || !goes_on(0)) return 0;
  if (goes_on(pmax)) return (uint64_t)pmax;              // (then it wraps: on from there later)
  int64_t a = 0, z = pmax;                                // goes on at a, not at z
  while (z - a > 1) {
    int64_t mid = a + (z - a) / 2;
    if (goes_on(mid)) a = mid; else z = mid;
  }
  return (uint64_t)z;
}

static void fuse_block(Core::Block *b) {
  uint32_t limit = b->n;
  if (b->n >= 2 && b->ops[b->n - 2].op >= U_BEQ && b->ops[b->n - 2].op <= U16_JALR)
    limit = b->n - 2;
  else if (b->n >= 1 && b->ops[b->n - 1].op >= U16_B)
    limit = b->n - 1;
  for (uint32_t i = 0; i + 1 < limit; i++) {
    uint8_t a = b->ops[i].op, c = b->ops[i + 1].op;
    uint8_t f = 0;
    if (a == U_LI) {
      if (c == U_ADDIU) f = U_LI_ADDIU;
      else if (c == U_ORI) f = U_LI_ORI;
      else if (c == U_LW) f = U_LI_LW;
      else if (c == U_SW) f = U_LI_SW;
    } else if (a == U_ADDIU && c == U_ADDIU) {
      f = U_ADDIU2;
    } else if (a == U_ADDU && c == U_ADDU) {
      f = U_ADDU2;
    } else if (a == U_LW && c == U_LW) {
      f = U_LW2;
    } else if (a == U_SW && c == U_SW) {
      f = U_SW2;
    } else if (a == U_SLL && c == U_ADDU) {
      f = U_SLL_ADDU;
    } else if (a == U_ADDIU && c == U_LW) {
      f = U_ADDIU_LW;
    } else if (a == U_ADDIU && c == U_SW) {
      f = U_ADDIU_SW;
    } else if (a == U_LW && c == U_ADDIU) {
      f = U_LW_ADDIU;
    }
    if (f) {
      b->ops[i].op = f;
      i++;
    }
  }
}

Core::Block *Core::build_block(uint32_t pc0, bool mode16, uint8_t *page) {
  Block *b = new Block;
  b->key = pc0 | (mode16 ? 1u : 0u);
  b->n = 0;
  uint32_t off = 0, limit = 0x1000 - (pc0 & 0xFFF);
  const uint8_t *base = page + (pc0 & 0xFFF);
  bool hooked_page = code_hook_page_[pc0 >> 12] != 0;
  while (b->n < BLOCK_MAX - 1) {
    uint32_t a = pc0 + off;
    if (off + (mode16 ? 2u : 4u) > limit) break;
    if (hooked_page && off && code_hook_at(a)) break;   // (a hooked instruction runs on its own)
    Uop &u = b->ops[b->n];
    uint32_t size = 4;
    int k;
    if (mode16) {
      k = decode16(page, a, 0x1000, u, size, 0);
    } else {
      uint32_t w;
      memcpy(&w, base + off, 4);
      k = decode32(w, a, u);
    }
    if (k == K_BARRIER) break;
    if (k == K_OP) { b->n++; off += size; continue; }
    if (k == K_COMPACT) { b->n++; off += size; break; }
    // a transfer with a delay slot: the slot must be a plain op in the same page
    uint32_t ds_size = mode16 ? 2 : 4;
    if (off + size + ds_size > limit) break;
    if (hooked_page && code_hook_at(a + size)) break;
    Uop &d = b->ops[b->n + 1];
    int kd;
    if (mode16) {
      uint32_t s2 = 0;
      kd = decode16(page, a + size, 0x1000, d, s2, a);
      if (s2 != 2) kd = K_BARRIER;
    } else {
      uint32_t w;
      memcpy(&w, base + off + size, 4);
      kd = decode32(w, a + size, d);
    }
    if (kd != K_OP) break;
    b->n += 2;
    off += size + ds_size;
    break;
  }
  b->bytes = (uint16_t)off;
  b->end_pc = pc0 + off;
  b->loopy = false;
  b->poll_ok = true;
  for (int i = 0; i < b->n; i++) {
    uint8_t op = b->ops[i].op;
    if (op == U_GEN32 || op == U_GEN16 ||
        op == U_MFC0_STATUS || op == U_MTC0_STATUS || op == U_DI || op == U_EI) {
      b->poll_ok = false;
      break;
    }
  }
  if (b->n) {
    uint8_t t = b->ops[b->n - 1].op;
    if (b->n >= 2 && b->ops[b->n - 2].op >= U_BEQ && b->ops[b->n - 2].op <= U16_JALR) t = b->ops[b->n - 2].op;
    switch (t) {
      case U_BEQ: case U_BNE: case U_BLEZ: case U_BGTZ: case U_BLTZ: case U_BGEZ:
      case U_BEQL: case U_BNEL: case U_BLEZL: case U_BGTZL: case U_BLTZL: case U_BGEZL:
      case U_J: case U16_B: case U16_BEQZ: case U16_BNEZ:
        b->loopy = true;
    }
  }
  memcpy(b->raw, base, off);
  block_builds++;
  analyze_ff(b);
  fuse_block(b);
  return b;
}

// a block's slot in the table (a multiplicative hash: MIPS32 keys are multiples of 4)
static ALI_INLINE uint32_t block_slot(uint32_t key) {
  static_assert(Core::BLOCK_TABLE == 1 << 17, "block_slot's shift");
  return (key * 0x9E3779B1u) >> 15;
}

// whether the code is still what the block was decoded from (lengths are even)
static ALI_INLINE bool same_code(const uint8_t *a, const uint8_t *b, uint32_t n) {
  for (; n >= 8; a += 8, b += 8, n -= 8) {
    uint64_t x, y;
    memcpy(&x, a, 8);
    memcpy(&y, b, 8);
    if (x != y) return false;
  }
  if (n >= 4) {
    uint32_t x, y;
    memcpy(&x, a, 4);
    memcpy(&y, b, 4);
    if (x != y) return false;
    a += 4; b += 4; n -= 4;
  }
  if (n) {
    uint16_t x, y;
    memcpy(&x, a, 2);
    memcpy(&y, b, 2);
    if (x != y) return false;
  }
  return true;
}

ALI_INLINE Core::Block *Core::get_block(uint32_t pc0, bool mode16) {
  if (ALI_UNLIKELY(!btab_)) btab_ = new Block *[BLOCK_TABLE]();
  uint8_t *page = vx_[pc0 >> 12];
  if (ALI_UNLIKELY(!page)) return nullptr;
  chunk_reported_ = false;
  uint32_t key = pc0 | (mode16 ? 1u : 0u);
  Block *&slot = btab_[block_slot(key)];
  Block *b = slot;
  if (ALI_LIKELY(b && b->key == key && same_code(page + (pc0 & 0xFFF), b->raw, b->bytes))) return b;
  if (ALI_UNLIKELY(chunk_events)) {
    // code about to run for the first time in its chunk: reported first, as the
    // instruction-at-a-time path does (the host looks for routines to shortcut
    // there and may hook them); the loop then looks at this PC again
    uint32_t pa = phys_of(pc0);
    uint32_t c = pa >> chunk_shift;
    if (ALI_UNLIKELY(c < chunk_seen.size() && !chunk_seen[c])) {
      report_chunk(pa);
      chunk_reported_ = true;
      return nullptr;
    }
  }
  retire(b);
  slot = b = build_block(pc0, mode16, page);
  return b;
}

void Core::gen32_op(uint32_t insn, uint32_t pc0) {
  slow_++;
  cur_pc_ = pc0; cur_ds_ = false; br_taken_ = false; npc_ = pc0 + 4; nm16_ = false;
  exec32(insn);
}

void Core::gen16_op(uint32_t pc0) {
  slow_++;
  cur_pc_ = pc0; cur_ds_ = false; br_taken_ = false; npc_ = pc0 + 2; nm16_ = true;
  exec16();
}

void Core::flush_blocks() {
  if (!btab_) return;
  for (uint32_t i = 0; i < BLOCK_TABLE; i++) {
    retire(btab_[i]);
    btab_[i] = nullptr;
  }
}

static ALI_INLINE uint32_t clo32(uint32_t v) { return clz32(~v); }

void Core::run_block(Block *b) { run_blocks<false>(b); }
void Core::run_chain(Block *b) { run_blocks<true>(b); }

// A block's micro-ops; with CHAIN, the next block straight after, as long as the
// loop has nothing to do there (no event due, no hook, the until address not
// reached, not a loop head to watch).
template <bool CHAIN>
void Core::run_blocks(Block *b) {
  uint32_t *R = gpr;
  uint32_t n, next, i = 0;
  bool m, nm, in_block = false;
  try {
  for (;;) {
    in_block = true;
    n = b->n;
    m = b->key & 1;
    next = b->end_pc;
    nm = m;
    for (i = 0; i < n; i++) {
      const Uop &u = b->ops[i];
      switch (u.op) {
        case U_NOP: break;
        case U_ADDIU: R[u.d] = R[u.s] + u.imm; break;
        case U_ADDU: R[u.d] = R[u.s] + R[u.t]; break;
        case U_SUBU: R[u.d] = R[u.s] - R[u.t]; break;
        case U_ADD: {
          uint32_t a = R[u.s], c = R[u.t], r = a + c;
          if (ALI_UNLIKELY(((a ^ r) & (c ^ r)) >> 31)) { cur_pc_ = u.pc; exception(EXC_OV); }
          if (u.d) R[u.d] = r;
          break;
        }
        case U_ADDI: {
          uint32_t a = R[u.s], c = u.imm, r = a + c;
          if (ALI_UNLIKELY(((a ^ r) & (c ^ r)) >> 31)) { cur_pc_ = u.pc; exception(EXC_OV); }
          if (u.d) R[u.d] = r;
          break;
        }
        case U_SUB: {
          uint32_t a = R[u.s], c = R[u.t], r = a - c;
          if (ALI_UNLIKELY(((a ^ c) & (a ^ r)) >> 31)) { cur_pc_ = u.pc; exception(EXC_OV); }
          if (u.d) R[u.d] = r;
          break;
        }
        case U_AND: R[u.d] = R[u.s] & R[u.t]; break;
        case U_OR: R[u.d] = R[u.s] | R[u.t]; break;
        case U_XOR: R[u.d] = R[u.s] ^ R[u.t]; break;
        case U_NOR: R[u.d] = ~(R[u.s] | R[u.t]); break;
        case U_SLT: R[u.d] = (int32_t)R[u.s] < (int32_t)R[u.t] ? 1 : 0; break;
        case U_SLTU: R[u.d] = R[u.s] < R[u.t] ? 1 : 0; break;
        case U_SLTI: R[u.d] = (int32_t)R[u.s] < (int32_t)u.imm ? 1 : 0; break;
        case U_SLTIU: R[u.d] = R[u.s] < u.imm ? 1 : 0; break;
        case U_ANDI: R[u.d] = R[u.s] & u.imm; break;
        case U_ORI: R[u.d] = R[u.s] | u.imm; break;
        case U_XORI: R[u.d] = R[u.s] ^ u.imm; break;
        case U_LI: R[u.d] = u.imm; break;
        case U_SLL: R[u.d] = R[u.t] << u.imm; break;
        case U_SRL: R[u.d] = R[u.t] >> u.imm; break;
        case U_SRA: R[u.d] = (uint32_t)((int32_t)R[u.t] >> u.imm); break;
        case U_ROTR: { uint32_t s = u.imm, v = R[u.t]; R[u.d] = s ? (v >> s) | (v << (32 - s)) : v; break; }
        case U_SLLV: R[u.d] = R[u.t] << (R[u.s] & 31); break;
        case U_SRLV: R[u.d] = R[u.t] >> (R[u.s] & 31); break;
        case U_SRAV: R[u.d] = (uint32_t)((int32_t)R[u.t] >> (R[u.s] & 31)); break;
        case U_ROTRV: { uint32_t s = R[u.s] & 31, v = R[u.t]; R[u.d] = s ? (v >> s) | (v << (32 - s)) : v; break; }
        case U_MOVZ: if (R[u.t] == 0) R[u.d] = R[u.s]; break;
        case U_MOVN: if (R[u.t] != 0) R[u.d] = R[u.s]; break;
        case U_MFHI: R[u.d] = hi; break;
        case U_MFLO: R[u.d] = lo; break;
        case U_MTHI: hi = R[u.s]; break;
        case U_MTLO: lo = R[u.s]; break;
        case U_MUL: R[u.d] = (uint32_t)((int32_t)R[u.s] * (int32_t)R[u.t]); break;
        case U_MULT: { int64_t p = (int64_t)(int32_t)R[u.s] * (int64_t)(int32_t)R[u.t]; lo = (uint32_t)p; hi = (uint32_t)((uint64_t)p >> 32); break; }
        case U_MULTU: { uint64_t p = (uint64_t)R[u.s] * (uint64_t)R[u.t]; lo = (uint32_t)p; hi = (uint32_t)(p >> 32); break; }
        case U_DIV: {
          int32_t x = (int32_t)R[u.s], y = (int32_t)R[u.t];
          if (y == 0 || (x == INT32_MIN && y == -1)) y = 1;
          lo = (uint32_t)(x / y); hi = (uint32_t)(x % y);
          break;
        }
        case U_DIVU: { uint32_t x = R[u.s], y = R[u.t]; if (y == 0) y = 1; lo = x / y; hi = x % y; break; }
        case U_MADD: { int64_t acc = (int64_t)(((uint64_t)hi << 32) | lo) + (int64_t)(int32_t)R[u.s] * (int64_t)(int32_t)R[u.t]; lo = (uint32_t)acc; hi = (uint32_t)((uint64_t)acc >> 32); break; }
        case U_MADDU: { uint64_t acc = (((uint64_t)hi << 32) | lo) + (uint64_t)R[u.s] * (uint64_t)R[u.t]; lo = (uint32_t)acc; hi = (uint32_t)(acc >> 32); break; }
        case U_MSUB: { int64_t acc = (int64_t)(((uint64_t)hi << 32) | lo) - (int64_t)(int32_t)R[u.s] * (int64_t)(int32_t)R[u.t]; lo = (uint32_t)acc; hi = (uint32_t)((uint64_t)acc >> 32); break; }
        case U_MSUBU: { uint64_t acc = (((uint64_t)hi << 32) | lo) - (uint64_t)R[u.s] * (uint64_t)R[u.t]; lo = (uint32_t)acc; hi = (uint32_t)(acc >> 32); break; }
        case U_CLZ: R[u.d] = clz32(R[u.s]); break;
        case U_CLO: R[u.d] = clo32(R[u.s]); break;
        case U_SEB: R[u.d] = (uint32_t)sext8(R[u.t]); break;
        case U_SEH: R[u.d] = (uint32_t)sext16(R[u.t]); break;
        case U_WSBH: { uint32_t v = R[u.t]; R[u.d] = ((v & 0x00FF00FFu) << 8) | ((v >> 8) & 0x00FF00FFu); break; }
        case U_EXT: {
          uint32_t lsb = u.imm & 0xFF, size = u.imm >> 8, v = R[u.s] >> lsb;
          R[u.d] = size == 32 ? v : v & ((1u << size) - 1);
          break;
        }
        case U_INS: {
          uint32_t lsb = u.imm & 0xFF, size = u.imm >> 8;
          uint32_t mask = (size == 32 ? 0xFFFFFFFFu : ((1u << size) - 1)) << lsb;
          R[u.d] = (R[u.d] & ~mask) | ((R[u.s] << lsb) & mask);
          break;
        }
#define BLK_LOAD(T, CONV)                                                                    \
  {                                                                                          \
    uint32_t a = R[u.s] + u.imm;                                                             \
    if (ALI_UNLIKELY(a & (sizeof(T) - 1))) { cur_pc_ = u.pc; fault_unaligned(a, MEM_READ); } \
    uint8_t *p = vr_[a >> 12];                                                               \
    T v;                                                                                     \
    if (ALI_LIKELY(p != nullptr)) { memcpy(&v, p + (a & 0xFFF), sizeof(T)); R[u.d] = CONV; break; } \
    cur_pc_ = u.pc; v = (T)load_slow(a, sizeof(T)); R[u.d] = CONV;                           \
    goto check_slow;                                                                         \
  }
        case U_LB: BLK_LOAD(uint8_t, (uint32_t)(int32_t)(int8_t)v)
        case U_LBU: BLK_LOAD(uint8_t, (uint32_t)v)
        case U_LH: BLK_LOAD(uint16_t, (uint32_t)(int32_t)(int16_t)v)
        case U_LHU: BLK_LOAD(uint16_t, (uint32_t)v)
        case U_LW: BLK_LOAD(uint32_t, v)
#undef BLK_LOAD
#define BLK_STORE(T)                                                                          \
  {                                                                                           \
    uint32_t a = R[u.s] + u.imm;                                                              \
    if (ALI_UNLIKELY(a & (sizeof(T) - 1))) { cur_pc_ = u.pc; fault_unaligned(a, MEM_WRITE); } \
    uint8_t *p = vw_[a >> 12];                                                                \
    T v = (T)R[u.t];                                                                          \
    stores_++;                                                                                \
    if (ALI_LIKELY(p != nullptr)) {                                                           \
      T oldv; memcpy(&oldv, p + (a & 0xFFF), sizeof(T));                                      \
      if (oldv == v) { unchanged_stores_++; break; }                                          \
      if (ALI_UNLIKELY(probe_)) { cur_pc_ = u.pc; throw Fault{ERR_EXCEPTION}; }               \
      if (ALI_UNLIKELY(dirty_rec_)) record_dirty(p + (a & 0xFFF));                            \
      memcpy(p + (a & 0xFFF), &v, sizeof(T));                                                 \
      break;                                                                                  \
    }                                                                                         \
    cur_pc_ = u.pc; store_slow(a, sizeof(T), (uint64_t)v);                                    \
    goto check_slow;                                                                          \
  }
        case U_SB: BLK_STORE(uint8_t)
        case U_SH: BLK_STORE(uint16_t)
        case U_SW: BLK_STORE(uint32_t)
#undef BLK_STORE
        case U_LWL: {
          uint32_t a = R[u.s] + u.imm, b_off = a & 3, wa = a & ~3u;
          uint8_t *p = vr_[wa >> 12];
          uint32_t w;
          bool slow = (p == nullptr);
          if (ALI_LIKELY(!slow)) memcpy(&w, p + (wa & 0xFFF), 4);
          else { cur_pc_ = u.pc; w = (uint32_t)load_slow(wa, 4); }
          if (u.d) {
            uint32_t sh = 8 * (3 - b_off);
            uint32_t keep = sh ? (R[u.d] & ((1u << sh) - 1)) : 0;
            R[u.d] = (w << sh) | keep;
          }
          if (ALI_UNLIKELY(slow)) goto check_slow;
          break;
        }
        case U_LWR: {
          uint32_t a = R[u.s] + u.imm, b_off = a & 3, wa = a & ~3u;
          uint8_t *p = vr_[wa >> 12];
          uint32_t w;
          bool slow = (p == nullptr);
          if (ALI_LIKELY(!slow)) memcpy(&w, p + (wa & 0xFFF), 4);
          else { cur_pc_ = u.pc; w = (uint32_t)load_slow(wa, 4); }
          if (u.d) {
            uint32_t sh = 8 * b_off;
            uint32_t keep = sh ? (R[u.d] & ~(0xFFFFFFFFu >> sh)) : 0;
            R[u.d] = (w >> sh) | keep;
          }
          if (ALI_UNLIKELY(slow)) goto check_slow;
          break;
        }
        case U_SWL: {
          uint32_t a = R[u.s] + u.imm, b_off = a & 3, wa = a & ~3u;
          uint32_t sh = 8 * (3 - b_off);
          uint32_t v = R[u.t] >> sh;
          uint8_t *pw = vw_[wa >> 12], *pr = vr_[wa >> 12];
          if (ALI_LIKELY(pw != nullptr && (b_off == 3 || pr != nullptr))) {
            uint32_t nw = v;
            if (b_off != 3) {
              uint32_t m;
              memcpy(&m, pr + (wa & 0xFFF), 4);
              uint32_t mask = 0xFFFFFFFFu >> sh;
              nw = (m & ~mask) | v;
            }
            stores_++;
            uint32_t oldw;
            memcpy(&oldw, pw + (wa & 0xFFF), 4);
            if (oldw == nw) { unchanged_stores_++; break; }
            if (ALI_UNLIKELY(probe_)) { cur_pc_ = u.pc; throw Fault{ERR_EXCEPTION}; }
            if (ALI_UNLIKELY(dirty_rec_)) record_dirty(pw + (wa & 0xFFF));
            memcpy(pw + (wa & 0xFFF), &nw, 4);
            break;
          }
          cur_pc_ = u.pc;
          if (b_off == 3) { store<uint32_t>(wa, v); }
          else {
            uint32_t m = load<uint32_t>(wa);
            uint32_t mask = 0xFFFFFFFFu >> sh;
            store<uint32_t>(wa, (m & ~mask) | v);
          }
          goto check_slow;
        }
        case U_SWR: {
          uint32_t a = R[u.s] + u.imm, b_off = a & 3, wa = a & ~3u;
          uint32_t sh = 8 * b_off;
          uint32_t v = R[u.t] << sh;
          uint8_t *pw = vw_[wa >> 12], *pr = vr_[wa >> 12];
          if (ALI_LIKELY(pw != nullptr && (b_off == 0 || pr != nullptr))) {
            uint32_t nw = v;
            if (b_off != 0) {
              uint32_t m;
              memcpy(&m, pr + (wa & 0xFFF), 4);
              uint32_t mask = 0xFFFFFFFFu << sh;
              nw = (m & ~mask) | v;
            }
            stores_++;
            uint32_t oldw;
            memcpy(&oldw, pw + (wa & 0xFFF), 4);
            if (oldw == nw) { unchanged_stores_++; break; }
            if (ALI_UNLIKELY(probe_)) { cur_pc_ = u.pc; throw Fault{ERR_EXCEPTION}; }
            if (ALI_UNLIKELY(dirty_rec_)) record_dirty(pw + (wa & 0xFFF));
            memcpy(pw + (wa & 0xFFF), &nw, 4);
            break;
          }
          cur_pc_ = u.pc;
          if (b_off == 0) { store<uint32_t>(wa, v); }
          else {
            uint32_t m = load<uint32_t>(wa);
            uint32_t mask = 0xFFFFFFFFu << sh;
            store<uint32_t>(wa, (m & ~mask) | v);
          }
          goto check_slow;
        }
        case U16_SAVE: {
          cur_pc_ = u.pc;
          static const uint8_t XS[7] = {18, 19, 20, 21, 22, 23, 30};
          uint32_t mask = u.d, xsregs = mask >> 3, args = u.s, astatic = u.t, framesize = u.imm;
          uint32_t sp = R[29];
          uint64_t s0 = slow_;
          for (int k = (int)args; k >= 1; k--) store<uint32_t>(sp + 4 * (k - 1), R[3 + k]);
          uint32_t t = sp;
          if (mask & 1) { t -= 4; store<uint32_t>(t, R[31]); }
          for (int k = (int)xsregs; k >= 1; k--) { t -= 4; store<uint32_t>(t, R[XS[k - 1]]); }
          if (mask & 4) { t -= 4; store<uint32_t>(t, R[17]); }
          if (mask & 2) { t -= 4; store<uint32_t>(t, R[16]); }
          for (uint32_t k = 0; k < astatic; k++) { t -= 4; store<uint32_t>(t, R[7 - k]); }
          R[29] = sp - framesize;
          if (ALI_UNLIKELY(slow_ != s0)) goto check_slow;
          break;
        }
        case U16_RESTORE: {
          cur_pc_ = u.pc;
          static const uint8_t XS[7] = {18, 19, 20, 21, 22, 23, 30};
          uint32_t mask = u.d, xsregs = mask >> 3, astatic = u.t, framesize = u.imm;
          uint32_t t = R[29] + framesize;
          uint32_t vals[16];
          int regs[16], nr = 0;
          uint64_t s0 = slow_;
          if (mask & 1) { t -= 4; regs[nr] = 31; vals[nr++] = load<uint32_t>(t); }
          for (int k = (int)xsregs; k >= 1; k--) { t -= 4; regs[nr] = XS[k - 1]; vals[nr++] = load<uint32_t>(t); }
          if (mask & 4) { t -= 4; regs[nr] = 17; vals[nr++] = load<uint32_t>(t); }
          if (mask & 2) { t -= 4; regs[nr] = 16; vals[nr++] = load<uint32_t>(t); }
          for (uint32_t k = 0; k < astatic; k++) { t -= 4; regs[nr] = (int)(7 - k); vals[nr++] = load<uint32_t>(t); }
          for (int k = 0; k < nr; k++) R[regs[k]] = vals[k];
          R[29] += framesize;
          if (ALI_UNLIKELY(slow_ != s0)) goto check_slow;
          break;
        }
        // ---- fused two-op superinstructions ----
        case U_LI_ADDIU: {
          R[u.d] = u.imm;
          const Uop &u2 = b->ops[++i];
          R[u2.d] = R[u2.s] + u2.imm;
          break;
        }
        case U_LI_ORI: {
          R[u.d] = u.imm;
          const Uop &u2 = b->ops[++i];
          R[u2.d] = R[u2.s] | u2.imm;
          break;
        }
        case U_ADDIU2: {
          R[u.d] = R[u.s] + u.imm;
          const Uop &u2 = b->ops[++i];
          R[u2.d] = R[u2.s] + u2.imm;
          break;
        }
        case U_ADDU2: {
          R[u.d] = R[u.s] + R[u.t];
          const Uop &u2 = b->ops[++i];
          R[u2.d] = R[u2.s] + R[u2.t];
          break;
        }
        case U_SLL_ADDU: {
          R[u.d] = R[u.t] << u.imm;
          const Uop &u2 = b->ops[++i];
          R[u2.d] = R[u2.s] + R[u2.t];
          break;
        }
        case U_ADDIU_LW: {
          R[u.d] = R[u.s] + u.imm;
          const Uop &u2 = b->ops[++i];
          uint32_t a = R[u2.s] + u2.imm;
          if (ALI_UNLIKELY(a & 3)) { cur_pc_ = u2.pc; fault_unaligned(a, MEM_READ); }
          uint8_t *p = vr_[a >> 12];
          uint32_t v;
          if (ALI_LIKELY(p != nullptr)) { memcpy(&v, p + (a & 0xFFF), 4); R[u2.d] = v; break; }
          cur_pc_ = u2.pc; v = (uint32_t)load_slow(a, 4); R[u2.d] = v;
          goto check_slow;
        }
        case U_ADDIU_SW: {
          R[u.d] = R[u.s] + u.imm;
          const Uop &u2 = b->ops[++i];
          uint32_t a = R[u2.s] + u2.imm;
          if (ALI_UNLIKELY(a & 3)) { cur_pc_ = u2.pc; fault_unaligned(a, MEM_WRITE); }
          uint8_t *p = vw_[a >> 12];
          uint32_t v = R[u2.t];
          stores_++;
          if (ALI_LIKELY(p != nullptr)) {
            uint32_t oldv; memcpy(&oldv, p + (a & 0xFFF), 4);
            if (oldv == v) { unchanged_stores_++; break; }
            if (ALI_UNLIKELY(probe_)) { cur_pc_ = u2.pc; throw Fault{ERR_EXCEPTION}; }
            if (ALI_UNLIKELY(dirty_rec_)) record_dirty(p + (a & 0xFFF));
            memcpy(p + (a & 0xFFF), &v, 4);
            break;
          }
          cur_pc_ = u2.pc; store_slow(a, 4, (uint64_t)v);
          goto check_slow;
        }
        case U_LW_ADDIU: {
          uint32_t a = R[u.s] + u.imm;
          if (ALI_UNLIKELY(a & 3)) { cur_pc_ = u.pc; fault_unaligned(a, MEM_READ); }
          uint8_t *p = vr_[a >> 12];
          uint32_t v;
          if (ALI_UNLIKELY(p == nullptr)) {
            cur_pc_ = u.pc; v = (uint32_t)load_slow(a, 4); R[u.d] = v;
            goto check_slow;
          }
          memcpy(&v, p + (a & 0xFFF), 4); R[u.d] = v;
          const Uop &u2 = b->ops[++i];
          R[u2.d] = R[u2.s] + u2.imm;
          break;
        }
        case U_LI_LW: {
          R[u.d] = u.imm;
          const Uop &u2 = b->ops[++i];
          uint32_t a = R[u2.s] + u2.imm;
          if (ALI_UNLIKELY(a & 3)) { cur_pc_ = u2.pc; fault_unaligned(a, MEM_READ); }
          uint8_t *p = vr_[a >> 12];
          uint32_t v;
          if (ALI_LIKELY(p != nullptr)) { memcpy(&v, p + (a & 0xFFF), 4); R[u2.d] = v; break; }
          cur_pc_ = u2.pc; v = (uint32_t)load_slow(a, 4); R[u2.d] = v;
          goto check_slow;
        }
        case U_LI_SW: {
          R[u.d] = u.imm;
          const Uop &u2 = b->ops[++i];
          uint32_t a = R[u2.s] + u2.imm;
          if (ALI_UNLIKELY(a & 3)) { cur_pc_ = u2.pc; fault_unaligned(a, MEM_WRITE); }
          uint8_t *p = vw_[a >> 12];
          uint32_t v = R[u2.t];
          stores_++;
          if (ALI_LIKELY(p != nullptr)) {
            uint32_t oldv; memcpy(&oldv, p + (a & 0xFFF), 4);
            if (oldv == v) { unchanged_stores_++; break; }
            if (ALI_UNLIKELY(probe_)) { cur_pc_ = u2.pc; throw Fault{ERR_EXCEPTION}; }
            if (ALI_UNLIKELY(dirty_rec_)) record_dirty(p + (a & 0xFFF));
            memcpy(p + (a & 0xFFF), &v, 4);
            break;
          }
          cur_pc_ = u2.pc; store_slow(a, 4, (uint64_t)v);
          goto check_slow;
        }
        case U_LW2: {
          uint32_t a = R[u.s] + u.imm;
          if (ALI_UNLIKELY(a & 3)) { cur_pc_ = u.pc; fault_unaligned(a, MEM_READ); }
          uint8_t *p = vr_[a >> 12];
          uint32_t v;
          if (ALI_UNLIKELY(p == nullptr)) {
            cur_pc_ = u.pc; v = (uint32_t)load_slow(a, 4); R[u.d] = v;
            goto check_slow;
          }
          memcpy(&v, p + (a & 0xFFF), 4); R[u.d] = v;
          const Uop &u2 = b->ops[++i];
          uint32_t a2 = R[u2.s] + u2.imm;
          if (ALI_UNLIKELY(a2 & 3)) { cur_pc_ = u2.pc; fault_unaligned(a2, MEM_READ); }
          uint8_t *p2 = vr_[a2 >> 12];
          uint32_t v2;
          if (ALI_LIKELY(p2 != nullptr)) { memcpy(&v2, p2 + (a2 & 0xFFF), 4); R[u2.d] = v2; break; }
          cur_pc_ = u2.pc; v2 = (uint32_t)load_slow(a2, 4); R[u2.d] = v2;
          goto check_slow;
        }
        case U_SW2: {
          uint32_t a = R[u.s] + u.imm;
          if (ALI_UNLIKELY(a & 3)) { cur_pc_ = u.pc; fault_unaligned(a, MEM_WRITE); }
          uint8_t *p = vw_[a >> 12];
          uint32_t v = R[u.t];
          stores_++;
          if (ALI_UNLIKELY(p == nullptr)) {
            cur_pc_ = u.pc; store_slow(a, 4, (uint64_t)v);
            goto check_slow;
          }
          {
            uint32_t oldv; memcpy(&oldv, p + (a & 0xFFF), 4);
            if (oldv == v) unchanged_stores_++;
            else if (ALI_UNLIKELY(probe_)) { cur_pc_ = u.pc; throw Fault{ERR_EXCEPTION}; }
            else {
              if (ALI_UNLIKELY(dirty_rec_)) record_dirty(p + (a & 0xFFF));
              memcpy(p + (a & 0xFFF), &v, 4);
            }
          }
          const Uop &u2 = b->ops[++i];
          uint32_t a2 = R[u2.s] + u2.imm;
          if (ALI_UNLIKELY(a2 & 3)) { cur_pc_ = u2.pc; fault_unaligned(a2, MEM_WRITE); }
          uint8_t *p2 = vw_[a2 >> 12];
          uint32_t v2 = R[u2.t];
          stores_++;
          if (ALI_LIKELY(p2 != nullptr)) {
            uint32_t oldv2; memcpy(&oldv2, p2 + (a2 & 0xFFF), 4);
            if (oldv2 == v2) { unchanged_stores_++; break; }
            if (ALI_UNLIKELY(probe_)) { cur_pc_ = u2.pc; throw Fault{ERR_EXCEPTION}; }
            if (ALI_UNLIKELY(dirty_rec_)) record_dirty(p2 + (a2 & 0xFFF));
            memcpy(p2 + (a2 & 0xFFF), &v2, 4);
            break;
          }
          cur_pc_ = u2.pc; store_slow(a2, 4, (uint64_t)v2);
          goto check_slow;
        }
        case U_MFC0_COUNT: {
          // Count as at this instruction (the block's own icount is added at its end)
          uint32_t v;
          if (ALI_UNLIKELY(probe_)) {
            v = count_at(icount + i);
            if (u.d) R[u.d] = v;
            count_reads_++;
            break;
          }
          icount += i;
          v = cp0_read(9, 0);
          icount -= i;
          if (u.d) R[u.d] = v;
          count_reads_++;
          goto check_slow;     // (the timer may have latched: leave if an event is due)
        }
        case U_TRAP: {      // (a divide's zero check: an exception only when it holds)
          uint32_t a = R[u.s], c = R[u.t];
          bool t;
          switch (u.imm) {
            case 0x30: t = (int32_t)a >= (int32_t)c; break;
            case 0x31: t = a >= c; break;
            case 0x32: t = (int32_t)a < (int32_t)c; break;
            case 0x33: t = a < c; break;
            case 0x34: t = a == c; break;
            default: t = a != c; break;
          }
          if (ALI_UNLIKELY(t)) {
            cur_pc_ = u.pc;
            exception(EXC_TR);
          }
          break;
        }
        case U_GEN32:
          gen32_op(u.imm, u.pc);
          goto check_slow;
        // ---- Status (as exec32's COP0 path: still counted as slow ops, so no
        // loop pass with one is replayed or skipped, as before they ran in blocks) ----
        case U_MFC0_STATUS:
          if (ALI_UNLIKELY(probe_)) { cur_pc_ = u.pc; throw Fault{ERR_EXCEPTION}; }
          if (u.d) R[u.d] = status;
          break;
        case U_MTC0_STATUS:
          if (ALI_UNLIKELY(probe_)) { cur_pc_ = u.pc; throw Fault{ERR_EXCEPTION}; }
          status = (status & ~0x3678FF1Fu) | (R[u.t] & 0x3678FF1Fu);
          if (ALI_LIKELY(!uart_pending_ && !stop_request_ && icount + i + 1 < next_event_ &&
                         ((status & 7) != 1 || (!ti && !(cause & 0x300) && !ic_lines_ && !ic_lines_hi_ && doorbell_off_ < 0)))) {
            dev_callback_dirty_ = false;
            break;
          }
          status_events(icount + i + 1);
          goto check_slow;
        case U_DI:
        case U_EI: {
          if (ALI_UNLIKELY(probe_)) { cur_pc_ = u.pc; throw Fault{ERR_EXCEPTION}; }
          uint32_t old = status;
          if (u.op == U_EI) status |= 1; else status &= ~1u;
          if (u.d) R[u.d] = old;
          if (ALI_LIKELY(!uart_pending_ && !stop_request_ && icount + i + 1 < next_event_ &&
                         (u.op == U_DI || (status & 7) != 1 || (!ti && !(cause & 0x300) && !ic_lines_ && !ic_lines_hi_ && doorbell_off_ < 0)))) {
            dev_callback_dirty_ = false;
            break;
          }
          status_events(icount + i + 1);
          goto check_slow;
        }
        case U_GEN16:
          gen16_op(u.pc);
          goto check_slow;
        // ---- transfers with a delay slot (the block's second-last op) ----
        case U_BEQ: next = R[u.s] == R[u.t] ? u.imm : u.pc + 8; nm = false; break;
        case U_BNE: next = R[u.s] != R[u.t] ? u.imm : u.pc + 8; nm = false; break;
        case U_BLEZ: next = (int32_t)R[u.s] <= 0 ? u.imm : u.pc + 8; nm = false; break;
        case U_BGTZ: next = (int32_t)R[u.s] > 0 ? u.imm : u.pc + 8; nm = false; break;
        case U_BLTZ: next = (int32_t)R[u.s] < 0 ? u.imm : u.pc + 8; nm = false; break;
        case U_BGEZ: next = (int32_t)R[u.s] >= 0 ? u.imm : u.pc + 8; nm = false; break;
        case U_BLTZAL: { bool c = (int32_t)R[u.s] < 0; R[31] = u.pc + 8; next = c ? u.imm : u.pc + 8; nm = false; break; }
        case U_BGEZAL: { bool c = (int32_t)R[u.s] >= 0; R[31] = u.pc + 8; next = c ? u.imm : u.pc + 8; nm = false; break; }
#define LIKELY_BR(COND, LINK)                       \
  {                                                 \
    bool c = (COND);                                \
    if (LINK) R[31] = u.pc + 8;                     \
    nm = false;                                     \
    if (c) { next = u.imm; break; }                 \
    next = u.pc + 8;                                \
    i++;                                            \
    goto done;                                      \
  }
        case U_BEQL: LIKELY_BR(R[u.s] == R[u.t], false)
        case U_BNEL: LIKELY_BR(R[u.s] != R[u.t], false)
        case U_BLEZL: LIKELY_BR((int32_t)R[u.s] <= 0, false)
        case U_BGTZL: LIKELY_BR((int32_t)R[u.s] > 0, false)
        case U_BLTZL: LIKELY_BR((int32_t)R[u.s] < 0, false)
        case U_BGEZL: LIKELY_BR((int32_t)R[u.s] >= 0, false)
        case U_BLTZALL: LIKELY_BR((int32_t)R[u.s] >= 0 ? false : true, true)
        case U_BGEZALL: LIKELY_BR((int32_t)R[u.s] >= 0, true)
#undef LIKELY_BR
        case U_J: next = u.imm; nm = false; break;
        case U_JAL: R[31] = u.pc + 8; next = u.imm; nm = false; break;
        case U_JALX: R[31] = u.pc + 8; next = u.imm; nm = true; break;
        case U_JR: { uint32_t t = R[u.s]; next = t & ~1u; nm = t & 1; break; }
        case U_JALR: { uint32_t t = R[u.s]; if (u.d) R[u.d] = u.pc + 8; next = t & ~1u; nm = t & 1; break; }
        case U16_JAL: R[31] = (u.pc + 6) | 1; next = u.imm; nm = true; break;
        case U16_JALX: R[31] = (u.pc + 6) | 1; next = u.imm; nm = false; break;
        case U16_JR: { uint32_t t = R[u.s]; next = t & ~1u; nm = t & 1; break; }
        case U16_JALR: { uint32_t t = R[u.s]; R[31] = (u.pc + 4) | 1; next = t & ~1u; nm = t & 1; break; }
        // ---- MIPS16 compact transfers (the block's last op) ----
        case U16_B: next = u.imm; nm = true; break;
        case U16_BEQZ: if (R[u.s] == 0) next = u.imm; nm = true; break;
        case U16_BNEZ: if (R[u.s] != 0) next = u.imm; nm = true; break;
        case U16_JRC: { uint32_t t = R[u.s]; next = t & ~1u; nm = t & 1; break; }
        case U16_JALRC: { uint32_t t = R[u.s]; R[31] = (u.pc + 2) | 1; next = t & ~1u; nm = t & 1; break; }
        default: ALI_UNREACHABLE();
      }
      continue;
    check_slow:
      if (ALI_UNLIKELY(next_event_ <= icount + i + 1 && i + 1 < n)) {
        // a device access or a host call may have raised an interrupt, stopped the
        // run or changed code: leave after this instruction (never before a delay
        // slot: those ops end blocks, a slow op is never a transfer)
        i++;
        icount += i;
        executed += i;
        if (ALI_UNLIKELY(prof_insns_ != nullptr)) (*prof_insns_)[b->key] += i;
        pc = b->ops[i].pc;
        m16 = m;
        block_runs++;
        return;
      }
    }
  done:
    in_block = false;
    icount += i;
    executed += i;
    if (ALI_UNLIKELY(prof_insns_ != nullptr)) (*prof_insns_)[b->key] += i;
    if (ALI_UNLIKELY(rec_on_)) {
      if (rec_n_ < REC_MAX && i == n) rec_[rec_n_++] = b;
      else rec_over_ = true;
    }
    if (b->loopy && next < b->end_pc) back_key_ = next | (nm ? 1u : 0u);   // (a taken backward branch: a loop's head)
    pc = next;
    m16 = nm;
    block_runs++;
    i = 0;
    if (b->ff.mode && (next | (nm ? 1u : 0u)) == b->key && spin_skip && idle_skip && !exact_mode && !probe_ && !rec_on_ &&
        next_event_ != ~0ull && next_event_ > icount + 2 * (uint64_t)n) {
      uint64_t kmax = (next_event_ - icount) / n - 1;
      if (b->ff.mode == FF_CRC16) {
        int32_t i_cur = (int32_t)R[7], i_end = (int32_t)R[6];
        uint32_t tab_base = R[5];
        const uint8_t *tp0 = vr_[tab_base >> 12];
        if (i_cur < i_end - 1 && (tab_base & 3) == 0 && tp0 != nullptr &&
            ((tab_base & 0xFFF) <= 0xC00 || vr_[(tab_base + 0x3FC) >> 12] == tp0 + 0x1000)) {
          uint64_t k = (uint64_t)(int64_t)(i_end - 1) - (uint64_t)(int64_t)i_cur;
          if (k > kmax) k = kmax;
          const uint32_t *tab = (const uint32_t *)(tp0 + (tab_base & 0xFFF));
          uint32_t crc = R[4], buf_addr = R[16] + (uint32_t)i_cur;
          uint32_t last_shifted = R[3], last_tab = R[2];
          uint64_t done = 0;
          while (done < k) {
            uint32_t a = buf_addr + (uint32_t)done;
            const uint8_t *bp = vr_[a >> 12];
            if (ALI_UNLIKELY(!bp)) break;
            uint32_t page_rem = 0x1000 - (a & 0xFFF);
            uint64_t chunk = k - done;
            if (chunk > page_rem) chunk = page_rem;
            bp += a & 0xFFF;
            for (uint64_t p = 0; p < chunk; p++) {
              uint32_t idx = (crc >> 24) ^ bp[p];
              last_shifted = crc << 8;
              last_tab = tab[idx];
              crc = last_shifted ^ last_tab;
            }
            done += chunk;
          }
          if (done) {
            R[4] = crc;
            R[7] += (uint32_t)done;
            R[2] = last_tab;
            R[3] = last_shifted;
            R[24] = 1;
            icount += done * n;
            executed += done * n;
            ff_skipped += done * n;
          }
        }
      } else if (b->ff.mode == FF_COPY16 && !dirty_rec_) {
        uint32_t sp_addr = R[29] + b->ops[0].imm;
        const uint8_t *sp_page = vr_[sp_addr >> 12];
        if ((sp_addr & 3) == 0 && sp_page != nullptr) {
          uint32_t dst_base;
          memcpy(&dst_base, sp_page + (sp_addr & 0xFFF), 4);
          uint32_t i_cur = R[5], i_end = R[4], src_base = R[17];
          if ((dst_base & 3) == 0 && (src_base & 3) == 0 && (i_cur & 3) == 0 && i_cur + 4 < i_end) {
            uint64_t k = (i_end - 1 - i_cur) / 4;
            if (k > kmax) k = kmax;
            uint32_t d0 = dst_base + i_cur;
            if (d0 + 4 * k <= sp_addr || d0 >= sp_addr + 4) {
              uint32_t last_v0 = R[2], last_v1 = R[3];
              uint64_t done = 0;
              while (done < k) {
                uint32_t sa = src_base + i_cur + 4 * (uint32_t)done;
                uint32_t da = dst_base + i_cur + 4 * (uint32_t)done;
                const uint8_t *sp_p = vr_[sa >> 12];
                bool slow_src = false;
                if (!sp_p && !flash_cmd_ && (!spi.on || spi_passthrough())) {
                  uint32_t spa = phys_of(sa);
                  Region *sr = pregion_[spa >> 12];
                  if (sr && !sr->mmio && sr->ptr && (sr->perms & PROT_READ) && !(mem_hook_page_[spa >> 12] & 1) &&
                      !(dev_buf_ && spa >= dev_phys_ && spa - dev_phys_ < dev_size_)) {
                    sp_p = sr->ptr + ((spa & ~0xFFFu) - sr->base);
                    slow_src = true;
                  }
                }
                uint8_t *dp_p = vw_[da >> 12];
                if (ALI_UNLIKELY(!sp_p || !dp_p)) break;
                uint32_t s_rem = (0x1000 - (sa & 0xFFF)) >> 2;
                uint32_t d_rem = (0x1000 - (da & 0xFFF)) >> 2;
                uint64_t chunk = k - done;
                if (chunk > s_rem) chunk = s_rem;
                if (chunk > d_rem) chunk = d_rem;
                const uint32_t *src_w = (const uint32_t *)(sp_p + (sa & 0xFFF));
                uint32_t *dst_w = (uint32_t *)(dp_p + (da & 0xFFF));
                for (uint64_t p = 0; p < chunk; p++) {
                  uint32_t v = src_w[p];
                  if (dst_w[p] == v) unchanged_stores_++; else dst_w[p] = v;
                }
                if (slow_src) slow_ += chunk;
                last_v0 = src_w[chunk - 1];
                last_v1 = da + 4 * (uint32_t)(chunk - 1);
                done += chunk;
              }
              if (done) {
                stores_ += done;
                R[2] = last_v0;
                R[3] = last_v1;
                R[5] = i_cur + 4 * (uint32_t)done;
                R[24] = 1;
                icount += done * n;
                executed += done * n;
                ff_skipped += done * n;
              }
            }
          }
        }
      } else if (b->ff.mode == FF_XOR16 && !dirty_rec_) {
        int32_t j_cur = (int32_t)R[5], j_lim = (int32_t)R[6];
        if (j_cur >= 0 && j_lim > 1 && j_cur < j_lim - 1) {
          uint32_t sp_a = R[29] + 8;
          const uint8_t *sp_page = (sp_a & 3) == 0 ? vr_[sp_a >> 12] : nullptr;
          if (sp_page) {
            uint32_t src_base = *(const uint32_t *)(sp_page + (sp_a & 0xFFF));
            uint32_t dst_base = R[25], key_base = R[17], i_cur = R[7];
            uint32_t s0_rem = R[16];
            // Fast-forward complete 13-byte outer loop iterations when s0_rem > 26
            if (j_cur == 1 && j_lim == 13 && s0_rem > 26u && (key_base & 0xFFF) <= 0xFF3u) {
              const uint8_t *kp_p = vr_[key_base >> 12];
              uint32_t max_blk = (s0_rem - 14u) / 13u;
              uint64_t cap_blk = kmax / 14u;
              if (max_blk > cap_blk) max_blk = (uint32_t)cap_blk;
              if (kp_p && max_blk > 0) {
                const uint8_t *k13 = kp_p + (key_base & 0xFFF);
                uint32_t blk_done = 0;
                uint8_t blk_xb = 0;
                while (blk_done < max_blk) {
                  uint32_t sa = src_base + i_cur;
                  uint32_t da = dst_base + i_cur;
                  if (ALI_UNLIKELY((uint32_t)(da - sp_a) < 16u && (uint32_t)(sp_a - da) < 16u)) break;
                  const uint8_t *sp_p = vr_[sa >> 12];
                  uint8_t *dp_p = vw_[da >> 12];
                  if (ALI_UNLIKELY(!sp_p || !dp_p || (sa & 0xFFF) > 0xFF3u || (da & 0xFFF) > 0xFF3u)) break;
                  const uint8_t *s_ptr = sp_p + (sa & 0xFFF);
                  uint8_t *d_ptr = dp_p + (da & 0xFFF);
                  for (uint32_t p = 0; p < 12u; p++) {
                    uint8_t xb = s_ptr[p] ^ k13[p + 1u];
                    if (d_ptr[p] == xb) unchanged_stores_++; else d_ptr[p] = xb;
                  }
                  blk_xb = s_ptr[12] ^ k13[0];
                  if (d_ptr[12] == blk_xb) unchanged_stores_++; else d_ptr[12] = blk_xb;
                  i_cur += 13u;
                  s0_rem -= 13u;
                  blk_done++;
                }
                if (blk_done) {
                  uint64_t skipped_insns = (uint64_t)blk_done * (13u * n + 8u);
                  stores_ += (uint64_t)blk_done * 13u;
                  R[4] = dst_base + i_cur - 1u;
                  R[2] = blk_xb;
                  R[3] = k13[0];
                  R[7] = i_cur;
                  R[16] = s0_rem;
                  R[24] = 1;
                  icount += skipped_insns;
                  executed += skipped_insns;
                  ff_skipped += skipped_insns;
                  kmax = (next_event_ > icount + 2 * (uint64_t)n) ? (next_event_ - icount) / n - 1 : 0;
                }
              }
            }
            uint64_t k = (uint32_t)(j_lim - 1 - j_cur);
            if (k > kmax) k = kmax;
            uint64_t done = 0;
            uint8_t last_xb = 0, last_kb = 0;
            while (done < k) {
              uint32_t sa = src_base + i_cur + (uint32_t)done;
              uint32_t ka = key_base + (uint32_t)j_cur + (uint32_t)done;
              uint32_t da = dst_base + i_cur + (uint32_t)done;
              if (ALI_UNLIKELY((uint32_t)(da - sp_a) < 4u)) break;
              const uint8_t *sp_p = vr_[sa >> 12];
              const uint8_t *kp_p = vr_[ka >> 12];
              uint8_t *dp_p = vw_[da >> 12];
              if (ALI_UNLIKELY(!sp_p || !kp_p || !dp_p)) break;
              last_kb = kp_p[ka & 0xFFF];
              last_xb = sp_p[sa & 0xFFF] ^ last_kb;
              uint8_t &dst_b = dp_p[da & 0xFFF];
              if (dst_b == last_xb) unchanged_stores_++; else dst_b = last_xb;
              done++;
            }
            if (done) {
              stores_ += done;
              R[4] = dst_base + i_cur + (uint32_t)done - 1;
              R[2] = last_xb;
              R[3] = last_kb;
              R[7] = i_cur + (uint32_t)done;
              R[5] = (uint32_t)j_cur + (uint32_t)done;
              R[24] = 1;
              icount += done * n;
              executed += done * n;
              ff_skipped += done * n;
            }
          }
        }
      } else if (b->ff.mode == FF_SBOX16 && !dirty_rec_) {
        uint32_t i_cur = R[4], i_lim = R[16], buf_base = R[5], sbox_base = R[6];
        const uint8_t *sp0 = vr_[sbox_base >> 12];
        if (i_cur + 1 < i_lim && sp0 != nullptr &&
            ((sbox_base & 0xFFF) <= 0xF00 || vr_[(sbox_base + 0xFF) >> 12] == sp0 + 0x1000)) {
          uint64_t k = i_lim - 1 - i_cur;
          if (k > kmax) k = kmax;
          const uint8_t *sbox = sp0 + (sbox_base & 0xFFF);
          uint32_t last_v0 = R[2], last_v1 = R[3];
          uint64_t done = 0;
          while (done < k) {
            uint32_t a = buf_base + i_cur + (uint32_t)done;
            const uint8_t *rp = vr_[a >> 12];
            uint8_t *wp = vw_[a >> 12];
            if (ALI_UNLIKELY(!rp || !wp || (a < sbox_base + 256 && a + 0x1000 > sbox_base))) break;
            uint32_t page_rem = 0x1000 - (a & 0xFFF);
            uint64_t chunk = k - done;
            if (chunk > page_rem) chunk = page_rem;
            const uint8_t *src_b = rp + (a & 0xFFF);
            uint8_t *dst_b = wp + (a & 0xFFF);
            for (uint64_t p = 0; p < chunk; p++) {
              uint8_t ob = src_b[p];
              uint8_t nb = sbox[ob];
              if (ob == nb) unchanged_stores_++; else dst_b[p] = nb;
              last_v0 = nb;
            }
            last_v1 = a + (uint32_t)chunk - 1;
            done += chunk;
          }
          if (done) {
            stores_ += done;
            R[2] = last_v0;
            R[3] = last_v1;
            R[4] = i_cur + (uint32_t)done;
            R[24] = 1;
            icount += done * n;
            executed += done * n;
            ff_skipped += done * n;
          }
        }
      } else if (b->ff.mode == FF_COPY16U && !dirty_rec_) {
        uint32_t sp_addr = R[29] + b->ops[2].imm;
        const uint8_t *sp_page = vr_[sp_addr >> 12];
        if ((sp_addr & 3) == 0 && sp_page != nullptr) {
          uint32_t dst_base;
          memcpy(&dst_base, sp_page + (sp_addr & 0xFFF), 4);
          uint32_t i_cur = R[5], i_end = R[6], src_base = R[17];
          if ((src_base & 3) == 0 && (i_cur & 3) == 0 && i_cur + 4 < i_end) {
            uint64_t k = (i_end - 1 - i_cur) / 4;
            if (k > kmax) k = kmax;
            uint32_t d0 = dst_base + i_cur;
            if (d0 + 4 * k <= sp_addr || d0 >= sp_addr + 4) {
              uint32_t last_w = 0, last_da = b->ff.flag ? R[3] : R[4];
              uint64_t done = 0;
              while (done < k) {
                uint32_t sa = src_base + i_cur + 4 * (uint32_t)done;
                uint32_t da = dst_base + i_cur + 4 * (uint32_t)done;
                const uint8_t *sp_p = vr_[sa >> 12];
                bool slow_src = false;
                if (!sp_p && !flash_cmd_ && (!spi.on || spi_passthrough())) {
                  uint32_t spa = phys_of(sa);
                  Region *sr = pregion_[spa >> 12];
                  if (sr && !sr->mmio && sr->ptr && (sr->perms & PROT_READ) && !(mem_hook_page_[spa >> 12] & 1) &&
                      !(dev_buf_ && spa >= dev_phys_ && spa - dev_phys_ < dev_size_)) {
                    sp_p = sr->ptr + ((spa & ~0xFFFu) - sr->base);
                    slow_src = true;
                  }
                }
                uint8_t *dp_p = vw_[da >> 12];
                if (ALI_UNLIKELY(!sp_p || !dp_p || (da & 0xFFF) > 0xFFC)) break;
                uint32_t s_rem = (0x1000 - (sa & 0xFFF)) >> 2;
                uint32_t d_rem = (0x1000 - (da & 0xFFF)) >> 2;
                uint64_t chunk = k - done;
                if (chunk > s_rem) chunk = s_rem;
                if (chunk > d_rem) chunk = d_rem;
                if (!chunk) break;
                const uint32_t *src_w = (const uint32_t *)(sp_p + (sa & 0xFFF));
                uint8_t *dst_b = dp_p + (da & 0xFFF);
                for (uint64_t p = 0; p < chunk; p++) {
                  uint32_t v = src_w[p];
                  uint8_t *db = dst_b + 4 * p;
                  for (int bi = 0; bi < 4; bi++) {
                    uint8_t bv = (uint8_t)(v >> (8 * bi));
                    if (db[bi] == bv) unchanged_stores_++; else db[bi] = bv;
                  }
                  last_w = v;
                }
                if (slow_src) slow_ += chunk;
                last_da = da + 4 * (uint32_t)(chunk - 1);
                done += chunk;
              }
              if (done) {
                stores_ += 4 * done;
                if (b->ff.flag) {
                  R[2] = last_w >> 24;
                  R[3] = last_da;
                  R[4] = last_w;
                } else {
                  R[2] = (last_w >> 16) & 0xFFFFu;
                  R[3] = last_w >> 24;
                  R[4] = last_da;
                }
                R[5] = i_cur + 4 * (uint32_t)done;
                R[24] = 1;
                icount += done * n;
                executed += done * n;
                ff_skipped += done * n;
              }
            }
          }
        }
      } else if (b->ff.mode == FF_CRC32) {
        int32_t i_cur = (int32_t)R[8], i_end = (int32_t)R[5];
        uint32_t tab_base = R[9];
        const uint8_t *tp0 = vr_[tab_base >> 12];
        if (i_cur < i_end - 1 && (tab_base & 3) == 0 && tp0 != nullptr &&
            ((tab_base & 0xFFF) <= 0xC00 || vr_[(tab_base + 0x3FC) >> 12] == tp0 + 0x1000)) {
          uint64_t k = (uint64_t)(int64_t)(i_end - 1) - (uint64_t)(int64_t)i_cur;
          if (k > kmax) k = kmax;
          const uint32_t *tab = (const uint32_t *)(tp0 + (tab_base & 0xFFF));
          uint32_t crc = R[7], buf_addr = R[4];
          uint32_t last_shifted = R[3];
          uint64_t done = 0;
          while (done < k) {
            uint32_t a = buf_addr + (uint32_t)done;
            const uint8_t *bp = vr_[a >> 12];
            if (ALI_UNLIKELY(!bp)) break;
            uint32_t page_rem = 0x1000 - (a & 0xFFF);
            uint64_t chunk = k - done;
            if (chunk > page_rem) chunk = page_rem;
            bp += a & 0xFFF;
            for (uint64_t p = 0; p < chunk; p++) {
              uint32_t idx = (crc ^ bp[p]) & 0xFFu;
              last_shifted = crc >> 8;
              crc = last_shifted ^ tab[idx];
            }
            done += chunk;
          }
          if (done) {
            R[4] = buf_addr + (uint32_t)done;
            R[7] = crc;
            R[8] += (uint32_t)done;
            R[2] = 1;
            R[3] = last_shifted;
            icount += done * n;
            executed += done * n;
            ff_skipped += done * n;
          }
        }
      } else if (b->ff.mode == FF_MEMSET16 && !dirty_rec_) {
        uint32_t i_cur = R[3], i_end = R[6], dst_base = R[7];
        uint8_t val = (uint8_t)R[5];
        if (i_cur + 1 < i_end) {
          uint64_t k = i_end - 1 - i_cur;
          if (k > kmax) k = kmax;
          uint64_t done = 0;
          while (done < k) {
            uint32_t a = dst_base + i_cur + (uint32_t)done;
            uint8_t *wp = vw_[a >> 12];
            if (ALI_UNLIKELY(!wp)) break;
            uint32_t page_rem = 0x1000 - (a & 0xFFF);
            uint64_t chunk = k - done;
            if (chunk > page_rem) chunk = page_rem;
            uint8_t *dst_b = wp + (a & 0xFFF);
            for (uint64_t p = 0; p < chunk; p++) {
              if (dst_b[p] == val) unchanged_stores_++; else dst_b[p] = val;
            }
            done += chunk;
          }
          if (done) {
            stores_ += done;
            R[2] = dst_base + i_cur + (uint32_t)done - 1;
            R[3] = i_cur + (uint32_t)done;
            R[24] = 1;
            icount += done * n;
            executed += done * n;
            ff_skipped += done * n;
          }
        }
      } else if (b->ff.mode == FF_BZERO32 && !dirty_rec_) {
        uint32_t a0_cur = R[4], a1_end = R[5];
        if ((a0_cur & 3) == 0 && a0_cur + 16 < a1_end) {
          uint64_t k = (a1_end - 1 - a0_cur) / 16;
          if (k > kmax) k = kmax;
          uint64_t done = 0;
          while (done < k) {
            uint32_t a = a0_cur + 16 * (uint32_t)done;
            uint8_t *wp = vw_[a >> 12];
            if (ALI_UNLIKELY(!wp || (a & 0xFFF) > 0xFF0)) break;
            uint32_t page_rem = (0x1000 - (a & 0xFFF)) >> 4;
            uint64_t chunk = k - done;
            if (chunk > page_rem) chunk = page_rem;
            if (!chunk) break;
            uint32_t *dst_w = (uint32_t *)(wp + (a & 0xFFF));
            for (uint64_t p = 0; p < 4 * chunk; p++) {
              if (dst_w[p] == 0) unchanged_stores_++; else dst_w[p] = 0;
            }
            done += chunk;
          }
          if (done) {
            stores_ += 4 * done;
            R[4] = a0_cur + 16 * (uint32_t)done;
            R[1] = 1;
            icount += done * n;
            executed += done * n;
            ff_skipped += done * n;
          }
        }
      } else {
        // a counting loop back at its start: on to its last pass (or the event) at once
        uint64_t k = ff_passes(b);
        if (k > kmax) k = kmax;
        if (k) {
          const Block::Ff &f = b->ff;
          for (int j = 0; j < f.nind; j++) R[f.ind[j]] += (uint32_t)k * f.step[j];
          if (f.mode == FF_FLAG) R[f.flag] = f.want ? 1u : 0u;
          icount += k * n;
          executed += k * n;
          ff_skipped += k * n;
        }
      }
    }
    if (!CHAIN) return;
    if (icount >= next_event_ || (uint64_t)pc == until_ || code_hook_page_[pc >> 12]) return;
    Block *nb = get_block(pc, nm);
    if (!nb || !nb->n || icount + nb->n > next_event_ || (until_ - pc) < nb->bytes) return;
    if ((pc | (nm ? 1u : 0u)) == back_key_ && spin_skip && idle_skip && !exact_mode) {
      spin_check();
      if (icount + nb->n > next_event_) return;     // (skipped to the event)
    }
    b = nb;
  }
  } catch (Fault &) {
    if (!in_block) throw;     // (between blocks: the state is the last block's end)
    // the op that faulted: every path that can throw set cur_pc_ to its PC first
    // (so the loop's index needs no copy in memory for this handler)
    uint32_t k = 0;
    while (k + 1 < n && b->ops[k].pc != cur_pc_) k++;
    icount += k;
    executed += k;
    // Only the completed prefix belongs to the profile, not the faulting op.
    if (ALI_UNLIKELY(prof_insns_ != nullptr) && k) (*prof_insns_)[b->key] += k;
    pc = b->ops[k].pc;
    m16 = m;
    if (k > 0 && k == n - 1 && b->ops[k - 1].op >= U_BEQ && b->ops[k - 1].op <= U16_JALR) {
      ds_active = true;                       // (the fault is in the delay slot)
      ds_target = next;
      ds_m16 = nm;
      cur_branch_pc_ = b->ops[k - 1].pc;
    }
    cur_pc_ = pc;
    throw;
  }
}

// What a micro-op reads and writes (bits 0..31 the GPRs, 32 HI, 33 LO; link: its
// write is a return address); false for one it cannot tell (a generic op).
static bool uop_rw(const Core::Uop &u, uint64_t &rd, uint64_t &wr, bool &link) {
  auto R = [](uint32_t r) { return r ? (1ull << r) : 0ull; };
  const uint64_t HI = 1ull << 32, LO = 1ull << 33;
  rd = wr = 0;
  link = false;
  switch (u.op) {
    case U_NOP: return true;
    case U_ADDIU: case U_ADDIU2: case U_ADDIU_LW: case U_ADDIU_SW:
    case U_ADDI: case U_SLTI: case U_SLTIU: case U_ANDI: case U_ORI: case U_XORI:
    case U_CLZ: case U_CLO: case U_EXT:
    case U_LB: case U_LBU: case U_LH: case U_LHU: case U_LW: case U_LW2: case U_LW_ADDIU:
      rd = R(u.s); wr = R(u.d); return true;
    case U_LWL: case U_LWR:
      rd = R(u.s) | R(u.d); wr = R(u.d); return true;
    case U_ADDU: case U_ADDU2: case U_SUBU: case U_ADD: case U_SUB:
    case U_AND: case U_OR: case U_XOR: case U_NOR: case U_SLT: case U_SLTU:
    case U_SLLV: case U_SRLV: case U_SRAV: case U_ROTRV: case U_MUL:
      rd = R(u.s) | R(u.t); wr = R(u.d); return true;
    case U_LI: case U_LI_ADDIU: case U_LI_ORI: case U_LI_LW: case U_LI_SW: case U_MFC0_COUNT:
      wr = R(u.d); return true;
    case U_SLL: case U_SLL_ADDU: case U_SRL: case U_SRA: case U_ROTR: case U_SEB: case U_SEH: case U_WSBH:
      rd = R(u.t); wr = R(u.d); return true;
    case U_MOVZ: case U_MOVN: rd = R(u.s) | R(u.t) | R(u.d); wr = R(u.d); return true;
    case U_INS: rd = R(u.s) | R(u.d); wr = R(u.d); return true;
    case U_MFHI: rd = HI; wr = R(u.d); return true;
    case U_MFLO: rd = LO; wr = R(u.d); return true;
    case U_MTHI: rd = R(u.s); wr = HI; return true;
    case U_MTLO: rd = R(u.s); wr = LO; return true;
    case U_MULT: case U_MULTU: case U_DIV: case U_DIVU:
      rd = R(u.s) | R(u.t); wr = HI | LO; return true;
    case U_MADD: case U_MADDU: case U_MSUB: case U_MSUBU:
      rd = R(u.s) | R(u.t) | HI | LO; wr = HI | LO; return true;
    case U_SB: case U_SH: case U_SW: case U_SW2: case U_SWL: case U_SWR: case U_TRAP:
      rd = R(u.s) | R(u.t); return true;
    case U16_SAVE: {
      static const uint8_t XS[7] = {18, 19, 20, 21, 22, 23, 30};
      rd = R(29); wr = R(29);
      if (u.d & 1) rd |= R(31);
      if (u.d & 2) rd |= R(16);
      if (u.d & 4) rd |= R(17);
      for (uint32_t i = 0; i < (u.d >> 3); i++) rd |= R(XS[i]);
      for (uint32_t i = 0; i < u.s; i++) rd |= R(4 + i);
      for (uint32_t i = 0; i < u.t; i++) rd |= R(7 - i);
      return true;
    }
    case U16_RESTORE: {
      static const uint8_t XS[7] = {18, 19, 20, 21, 22, 23, 30};
      rd = R(29); wr = R(29);
      if (u.d & 1) wr |= R(31);
      if (u.d & 2) wr |= R(16);
      if (u.d & 4) wr |= R(17);
      for (uint32_t i = 0; i < (u.d >> 3); i++) wr |= R(XS[i]);
      for (uint32_t i = 0; i < u.t; i++) wr |= R(7 - i);
      return true;
    }
    case U_BEQ: case U_BNE: case U_BEQL: case U_BNEL:
      rd = R(u.s) | R(u.t); return true;
    case U_BLEZ: case U_BGTZ: case U_BLTZ: case U_BGEZ: case U_BLEZL: case U_BGTZL: case U_BLTZL: case U_BGEZL:
    case U_JR: case U16_JR: case U16_BEQZ: case U16_BNEZ: case U16_JRC:
      rd = R(u.s); return true;
    case U_BLTZAL: case U_BGEZAL: case U_BLTZALL: case U_BGEZALL:
      rd = R(u.s); wr = R(31); link = true; return true;
    case U_J: case U16_B:
      return true;
    case U_JAL: case U_JALX: case U16_JAL: case U16_JALX:
      wr = R(31); link = true; return true;
    case U_JALR:
      rd = R(u.s); wr = R(u.d); link = true; return true;
    case U16_JALR: case U16_JALRC:
      rd = R(u.s); wr = R(31); link = true; return true;
  }
  return false;
}

// Whether a pass can leave the loop at this transfer: a conditional branch, or a
// jump through a register this pass did not set as a return address.
static bool may_exit(const Core::Uop &t, uint64_t linked) {
  switch (t.op) {
    case U_J: case U_JAL: case U_JALX: case U16_JAL: case U16_JALX: case U16_B:
      return false;
    case U_BEQ:
      return t.s != t.t;                       // (beq r, r: `b`)
    case U_JR: case U_JALR: case U16_JR: case U16_JALR: case U16_JRC: case U16_JALRC:
      return !(linked >> t.s & 1);
  }
  return true;
}

// The registers the recorded pass writes before it reads them and before the
// first point it may leave the loop at (see rec_ign_); ok false if an op is not known.
uint64_t Core::pass_ignorable(bool &ok, uint64_t &all_wr) const {
  uint64_t written = 0, read_first = 0, linked = 0;
  all_wr = 0;
  bool left = false;
  ok = false;
  for (int j = 0; j < rec_n_; j++) {
    const Block *b = rec_[j];
    bool exit_here = false;
    for (int i = 0; i < b->n; i++) {
      const Uop &u = b->ops[i];
      uint64_t rd, wr;
      bool link;
      if (!uop_rw(u, rd, wr, link)) return 0;
      if (u.op >= U_BEQ && may_exit(u, linked)) exit_here = true;
      all_wr |= wr;
      read_first |= rd & ~written;
      if (!left) written |= wr;
      linked = link ? (linked | wr) : (linked & ~wr);
    }
    if (exit_here) left = true;               // (after the block: its delay slot ran)
  }
  ok = true;
  return written & ~read_first & ~1ull;
}

void Core::spin_check() {
  uint32_t key = pc | (m16 ? 1u : 0u);
  bool same = key == loop_key_ && (stores_ - unchanged_stores_) == (loop_stores_ - loop_ustores_) && slow_ == loop_slow_;
  spin_dbg[0]++;
  if (ALI_UNLIKELY(dirty_rec_)) {
    if (slow_ != dirty_slow_ || count_reads_ != dirty_creads_ || (icount - dirty_icount_) > 65536) {
      dirty_rec_ = false;
    } else if (key == dirty_head_) {
      dirty_rec_ = false;
      uint64_t pass = icount - dirty_icount_;
      if (!dirty_over_ && pass && status == dirty_status_ &&
          memcmp(dirty_regs_, gpr, sizeof(gpr)) == 0 && dirty_regs_[32] == hi && dirty_regs_[33] == lo) {
        bool clean = true;
        for (uint32_t i = 0; i < dirty_n_; i++) {
          uint32_t cur;
          memcpy(&cur, dirty_words_[i].ptr, 4);
          if (cur != dirty_words_[i].orig) { clean = false; break; }
        }
        if (clean) {
          OuterLoop &ol = outer_[((key * 0x9E3779B1u) >> 28) & (OUTER_SLOTS - 1)];
          ol.verified = true;
          if (next_event_ != ~0ull && next_event_ > icount + pass) {
            spin_dbg[5]++;
            uint64_t k = (next_event_ - icount - 1) / pass;
            icount += k * pass;
            spin_skipped += k * pass;
          }
        }
      }
    }
  }
  if (rec_on_) {
    // a pass of a loop that reads Count was recorded: if it goes round with the
    // same registers (but those it sets before it reads them), skip whole passes
    rec_on_ = false;
    if (same) {
      if (!rec_over_ && rec_n_ > 0) {
        bool ok;
        uint64_t all_wr = 0;
        uint64_t ign = pass_ignorable(ok, all_wr);
        uint64_t chk = all_wr & ~ign & ~1ull;
        if (ok && (chk ? loop_regs_match_mask(~chk) : (loop_regs_[34] == status))) {
          rec_ign_ = ign;
          rec_chk_ = chk;
          PollLoop &pl = poll_cache_[poll_slot(key)];
          uint64_t guess = pl.key == key ? pl.last_k : 0;
          pl.key = key;
          pl.n = rec_n_;
          pl.ign = ign;
          pl.chk = chk;
          memcpy(pl.seq, rec_, sizeof(Block *) * rec_n_);
          for (int j = 0; j < rec_n_; j++) pl.keys[j] = rec_[j]->key;
          pl.last_k = poll_skip(key, guess);
          loop_poll_tried_ = false;
        }
      }
      loop_key_ = key;
      loop_stores_ = stores_;
      loop_ustores_ = unchanged_stores_;
      loop_slow_ = slow_;
      loop_creads_ = count_reads_;
      loop_passes_ = 0;
      loop_snap_ = false;
      return;
    }
  }
  if (!same) {
    spin_dbg[1]++;
    poll_done_ = false;
    PollLoop &pl = poll_cache_[poll_slot(key)];
    if (pl.key == key && spin_skip && poll_seq_valid(pl)) {
      // a Count-polling loop seen before: its pass from these registers, at once
      if (pl.chk) {
        memcpy(loop_regs_, gpr, sizeof(gpr));
        loop_regs_[32] = hi;
        loop_regs_[33] = lo;
      }
      loop_regs_[34] = status;
      memcpy(rec_, pl.seq, sizeof(Block *) * pl.n);
      rec_n_ = pl.n;
      rec_ign_ = pl.ign;
      rec_chk_ = pl.chk;
      uint64_t k = poll_skip(key, pl.last_k);
      if (k) pl.last_k = k;       // (a guess only: 0 -- the loop ending at once -- keeps the last one)
    } else if (!dirty_rec_) {
      OuterLoop &ol = outer_[((key * 0x9E3779B1u) >> 28) & (OUTER_SLOTS - 1)];
      uint64_t cur_ustores = stores_ - unchanged_stores_;
      bool regs_eq = (ol.key == key && status == ol.status &&
                      memcmp(ol.regs, gpr, sizeof(gpr)) == 0 && ol.regs[32] == hi && ol.regs[33] == lo);
      if (regs_eq && slow_ == ol.slow && count_reads_ == ol.creads) {
        uint64_t pass = icount - ol.icount;
        if (pass > 0 && pass <= 65536) {
          if (cur_ustores == ol.ustores) {
            ol.verified = true;
            if (next_event_ != ~0ull && next_event_ > icount + pass) {
              spin_dbg[5]++;
              uint64_t k = (next_event_ - icount - 1) / pass;
              icount += k * pass;
              spin_skipped += k * pass;
            }
          } else if (cur_ustores - ol.ustores <= 256 && next_event_ != ~0ull && next_event_ > icount + 2 * pass) {
            dirty_rec_ = true;
            dirty_over_ = false;
            dirty_head_ = key;
            dirty_n_ = 0;
            dirty_icount_ = icount;
            dirty_slow_ = slow_;
            dirty_creads_ = count_reads_;
            dirty_status_ = status;
            memcpy(dirty_regs_, gpr, sizeof(gpr));
            dirty_regs_[32] = hi;
            dirty_regs_[33] = lo;
          }
        }
      } else if (regs_eq && ol.verified) {
        dirty_rec_ = true;
        dirty_over_ = false;
        dirty_head_ = key;
        dirty_n_ = 0;
        dirty_icount_ = icount;
        dirty_slow_ = slow_;
        dirty_creads_ = count_reads_;
        dirty_status_ = status;
        memcpy(dirty_regs_, gpr, sizeof(gpr));
        dirty_regs_[32] = hi;
        dirty_regs_[33] = lo;
      } else if (ol.key != key) {
        ol.verified = false;
      }
      ol.key = key;
      ol.icount = icount;
      ol.slow = slow_;
      ol.creads = count_reads_;
      ol.ustores = cur_ustores;
      ol.status = status;
      memcpy(ol.regs, gpr, sizeof(gpr));
      ol.regs[32] = hi;
      ol.regs[33] = lo;
    }
    loop_key_ = key;
    loop_stores_ = stores_;
    loop_ustores_ = unchanged_stores_;
    loop_slow_ = slow_;
    loop_creads_ = count_reads_;
    loop_passes_ = 0;
    loop_snap_ = false;
    loop_interval_ = 1;
    loop_poll_tried_ = false;
    return;
  }
  if (count_reads_ != loop_creads_) {
    // the last pass read Count: replay the cached pass (across slice boundaries) or
    // record the next one (once per entry into the loop)
    loop_creads_ = count_reads_;
    PollLoop &pl = poll_cache_[poll_slot(key)];
    if (poll_done_) {
      // (a skip in this loop entry found its last pass: nothing left to skip or record)
    } else if (!loop_poll_tried_ && pl.key == key && spin_skip && poll_seq_valid(pl)) {
      if (pl.chk) {
        memcpy(loop_regs_, gpr, sizeof(gpr));
        loop_regs_[32] = hi;
        loop_regs_[33] = lo;
      }
      loop_regs_[34] = status;
      memcpy(rec_, pl.seq, sizeof(Block *) * pl.n);
      rec_n_ = pl.n;
      rec_ign_ = pl.ign;
      rec_chk_ = pl.chk;
      uint64_t k = poll_skip(key, pl.last_k);
      if (k) pl.last_k = k;
      loop_creads_ = count_reads_;
    } else if (!loop_poll_tried_) {
      loop_poll_tried_ = true;
      memcpy(loop_regs_, gpr, sizeof(gpr));
      loop_regs_[32] = hi;
      loop_regs_[33] = lo;
      loop_regs_[34] = status;
      rec_on_ = true;
      rec_over_ = false;
      rec_n_ = 0;
    }
    loop_snap_ = false;
    loop_passes_ = 0;
    return;
  }
  // a loop that neither stores, nor reaches a device, nor reads Count
  if (++loop_passes_ < loop_interval_) return;
  const uint32_t n = loop_interval_;
  if (loop_snap_ && !loop_regs_match() && loop_interval_ < LOOP_CHECK_MAX) loop_interval_ *= 2;
  else if (loop_snap_ && loop_regs_match()) {
    spin_dbg[5]++;
    uint64_t span = icount - loop_icount_;
    uint64_t pass = span / n;
    if (pass && span % n == 0 && next_event_ != ~0ull && next_event_ > icount + 2 * pass) {
      uint64_t k = (next_event_ - icount) / pass - 1;    // (a pass short: the event comes inside the loop)
      icount += k * pass;
      spin_skipped += k * pass;
    }
  }
  memcpy(loop_regs_, gpr, sizeof(gpr));
  loop_regs_[32] = hi;
  loop_regs_[33] = lo;
  loop_regs_[34] = status;
  loop_snap_ = true;
  loop_icount_ = icount;
  loop_passes_ = 0;
}

// The pass replayed k passes later: whether the loop still goes on after it
// (back at its head with the same registers).  Everything is rolled back.
bool Core::poll_probe(uint64_t k, uint32_t pass, uint32_t head) {
  uint32_t save_gpr[32];
  memcpy(save_gpr, gpr, sizeof(gpr));
  uint32_t save_hi = hi, save_lo = lo, save_pc = pc, save_back = back_key_;
  bool save_m16 = m16;
  uint64_t save_icount = icount, save_executed = executed, save_runs = block_runs, save_creads = count_reads_;
  uint64_t save_stores = stores_, save_ustores = unchanged_stores_;
  auto *save_prof = prof_insns_;
  prof_insns_ = nullptr;
  icount += k * pass;
  probe_ = true;
  bool ok = true;
  try {
    for (int j = 0; j < rec_n_; j++) {
      Block *b = rec_[j];
      if ((pc | (m16 ? 1u : 0u)) != b->key) { ok = false; break; }
      uint64_t before = icount;
      run_block(b);
      if (icount - before != b->n) { ok = false; break; }
    }
    ok = ok && (pc | (m16 ? 1u : 0u)) == head && (rec_chk_ ? loop_regs_match_mask(~rec_chk_) : (loop_regs_[34] == status));
  } catch (Fault &) {
    ok = false;
  }
  probe_ = false;
  memcpy(gpr, save_gpr, sizeof(gpr));
  hi = save_hi; lo = save_lo; pc = save_pc; m16 = save_m16; back_key_ = save_back;
  icount = save_icount; executed = save_executed; block_runs = save_runs; count_reads_ = save_creads;
  stores_ = save_stores; unchanged_stores_ = save_ustores;
  prof_insns_ = save_prof;
  return ok;
}

// Whether a cached pass can be replayed: each block still the table's for its
// PC (so not freed), still the code in memory, with no generic or status op.
bool Core::poll_seq_valid(const PollLoop &pl) {
  if (!btab_) return false;
  for (int j = 0; j < pl.n; j++) {
    Block *b = pl.seq[j];
    if (btab_[block_slot(pl.keys[j])] != b || !b->poll_ok) return false;
    uint32_t pc0 = b->key & ~1u;
    uint8_t *page = vx_[pc0 >> 12];
    if (!page || !same_code(page + (pc0 & 0xFFF), b->raw, b->bytes)) return false;
  }
  return pl.n > 0;
}

// Returns the passes skipped (the next call's guess).
uint64_t Core::poll_skip(uint32_t head, uint64_t guess) {
  uint64_t pass = 0;
  for (int j = 0; j < rec_n_; j++) pass += rec_[j]->n;
  if (!pass) return 0;
  uint64_t room = next_event_ == ~0ull ? (1ull << 40) : next_event_ - icount;
  if (room < 3 * pass) return guess;
  uint64_t kmax = (room - 1) / pass - 1;      // (the pass after the skip fits before the event)
  uint64_t lo_k = 0, hi_k = kmax + 1;          // goes on after lo_k passes; not known past hi_k - 1
  if (guess && guess <= kmax) {                // the last call's: often the same again
    spin_dbg[3]++;
    if (poll_probe(guess, (uint32_t)pass, head)) {
      lo_k = guess;
      if (guess < kmax) {
        spin_dbg[3]++;
        if (poll_probe(guess + 1, (uint32_t)pass, head)) lo_k = guess + 1;
        else hi_k = guess + 1;
      }
    } else {
      hi_k = guess;
    }
  }
  if (hi_k == kmax + 1) {
    for (uint64_t k = lo_k ? 2 * lo_k : 1; k <= kmax; k *= 2) {
      spin_dbg[3]++;
      if (!poll_probe(k, (uint32_t)pass, head)) { hi_k = k; break; }
      lo_k = k;
    }
    if (hi_k == kmax + 1 && lo_k < kmax) {
      spin_dbg[3]++;
      if (poll_probe(kmax, (uint32_t)pass, head)) lo_k = kmax;
      else hi_k = kmax;
    }
  }
  while (hi_k - lo_k > 1) {
    uint64_t mid = lo_k + (hi_k - lo_k) / 2;
    spin_dbg[3]++;
    if (poll_probe(mid, (uint32_t)pass, head)) lo_k = mid;
    else hi_k = mid;
  }
  if (lo_k == kmax) spin_dbg[2]++;
  spin_dbg[4] += kmax;
  if (lo_k) {
    icount += lo_k * pass;
    poll_skipped += lo_k * pass;
    poll_skips++;
    // the pass after lo_k ends the loop (probed): another try in this loop
    // would find nothing to skip -- and would cost probes and clobber the guess
    if (lo_k < kmax) poll_done_ = true;
  } else {
    loop_poll_tried_ = true;
  }
  return lo_k;
}

// ------------------------------------------------------------------
// The loop
// ------------------------------------------------------------------
static ALI_INLINE uint32_t m16_size_of(uint16_t hw) {
  uint32_t op = hw >> 11;
  return (op == 0x1E || op == 0x03) ? 4 : 2;
}

int Core::run_loop() {
  running_ = true;
  stop_reason_ = STOP_NONE;
  err_ = 0;
  next_event_ = 0;
  hooks_done_ = false;
  try {
    for (;;) {
      if (ALI_UNLIKELY(!retired_.empty())) free_retired();
      if (ALI_UNLIKELY(icount >= next_event_)) {
        if (events()) break;
      }
      if (ALI_UNLIKELY((uint64_t)pc == until_)) {
        stop_reason_ = STOP_UNTIL;
        break;
      }
      if (ALI_LIKELY(code_hook_page_[pc >> 12] == 0) || !code_hook_at(pc)) {
        if (blocks_on && !ds_active) {
          Block *b = get_block(pc, m16);
          if (!b && chunk_reported_) continue;
          if (b && b->n && icount + b->n <= next_event_ && (until_ - pc) >= b->bytes) {
            if ((pc | (m16 ? 1u : 0u)) == back_key_ && spin_skip && idle_skip && !exact_mode) {
              spin_check();
              if (icount + b->n > next_event_) continue;     // (skipped to the event)
            }
            run_chain(b);
            continue;
          }
        }
      } else if (!(hooks_done_ && hooks_pc_ == pc)) {
        uint32_t size = 4;
        if (m16) {
          cur_pc_ = pc;
          size = m16_size_of(fetch16(pc));
        }
        if (code_hooks(pc, size)) {
          if (stop_request_) {
            stop_request_ = false;
            stop_reason_ = STOP_REQUEST;
            break;
          }
          if (stop_reason_ == STOP_BREAKPOINT) break;
          continue;   // a hook moved the PC
        }
        if (ALI_UNLIKELY(icount >= next_event_)) {
          // (a hook raised an interrupt line or moved the time: the event first, then this
          // instruction without its hooks again, unless the event moved the PC)
          hooks_done_ = true;
          hooks_pc_ = pc;
          continue;
        }
      }
      hooks_done_ = false;
      step_over_bp_once = false;
      slow_++;
      // ERET and host callbacks may change pc/m16 while the instruction runs.
      const uint32_t prof_pc = pc | (m16 ? 1u : 0u);

      // ---- one instruction ----
      cur_pc_ = pc;
      cur_ds_ = ds_active;
      br_taken_ = false;
      if (!m16) {
        if (ALI_UNLIKELY(pc & 3)) fault_unaligned(pc, MEM_FETCH);
        npc_ = pc + 4;
        nm16_ = false;
        exec32(fetch32(pc));
      } else {
        exec16();
      }
      icount++;
      executed++;
      if (ALI_UNLIKELY(prof_insns_ != nullptr)) (*prof_insns_)[prof_pc]++;
      if (cur_ds_) {
        pc = ds_target;
        m16 = ds_m16;
        ds_active = false;
      } else if (br_taken_) {
        pc = npc_;
        m16 = nm16_;
        ds_active = true;
        ds_target = br_target_;
        ds_m16 = br_m16_;
        cur_branch_pc_ = cur_pc_;
      } else {
        pc = npc_;
        m16 = nm16_;
      }
    }
  } catch (Fault &f) {
    err_ = f.err;
    stop_reason_ = STOP_ERROR;
    pc = cur_pc_;     // (the faulting instruction; a delay slot stays one)
  }
  running_ = false;
  hooks_.erase(std::remove_if(hooks_.begin(), hooks_.end(), [](const Hook &h) { return h.dead; }), hooks_.end());
  return stop_reason_;
}

int Core::step_one() {
  uint64_t save_limit = limit_;
  limit_ = ~0ull;
  next_event_ = ~0ull;
  int r = 0;
  try {
    const uint32_t prof_pc = pc | (m16 ? 1u : 0u);
    cur_pc_ = pc;
    cur_ds_ = ds_active;
    br_taken_ = false;
    if (!m16) {
      if (pc & 3) fault_unaligned(pc, MEM_FETCH);
      npc_ = pc + 4;
      nm16_ = false;
      exec32(fetch32(pc));
    } else {
      exec16();
    }
    icount++;
    executed++;
    if (ALI_UNLIKELY(prof_insns_ != nullptr)) (*prof_insns_)[prof_pc]++;
    if (cur_ds_) { pc = ds_target; m16 = ds_m16; ds_active = false; }
    else if (br_taken_) {
      pc = npc_; m16 = nm16_; ds_active = true; ds_target = br_target_; ds_m16 = br_m16_; cur_branch_pc_ = cur_pc_;
    } else { pc = npc_; m16 = nm16_; }
  } catch (Fault &f) {
    err_ = f.err;
    r = f.err;
    pc = cur_pc_;
  }
  limit_ = save_limit;
  host_sync();
  return r;
}


}  // namespace ali
