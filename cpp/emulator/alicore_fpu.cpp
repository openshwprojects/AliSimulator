// AliSimulator C++ core: the FPU (COP1 / COP1X) of the 24Kf as QEMU / Unicorn
// models it: 64-bit registers (Status.FR = 0 pairs them for doubles, L-format
// operations need FR = 1), legacy NaNs (a NaN result is the default NaN
// 0x7FBFFFFF / 0x7FF7FFFFFFFFFFFF, a set fraction MSB marks a signalling NaN),
// FCSR's cause / flag / enable bits from the host's IEEE exceptions, its
// rounding mode applied to every operation.
#include <cfenv>
#include <cmath>
#include <cstring>

#include "alicore.h"

#if defined(_MSC_VER)
#pragma fenv_access(on)
#endif

namespace ali {

enum { EXC_RI = 10, EXC_CPU = 11, EXC_FPE = 15 };
// MIPS exception bits (cause / flags / enables order)
enum : uint32_t { FX_I = 1, FX_U = 2, FX_O = 4, FX_Z = 8, FX_V = 16 };

namespace {

inline bool nan32(uint32_t v) { return (v & 0x7F800000u) == 0x7F800000u && (v & 0x007FFFFFu); }
inline bool snan32(uint32_t v) { return nan32(v) && (v & 0x00400000u); }
inline bool nan64(uint64_t v) { return (v & 0x7FF0000000000000ull) == 0x7FF0000000000000ull && (v & 0x000FFFFFFFFFFFFFull); }
inline bool snan64(uint64_t v) { return nan64(v) && (v & 0x0008000000000000ull); }
const uint32_t DNAN32 = 0x7FBFFFFFu;
const uint64_t DNAN64 = 0x7FF7FFFFFFFFFFFFull;

inline float f32(uint32_t v) { float x; memcpy(&x, &v, 4); return x; }
inline double f64(uint64_t v) { double x; memcpy(&x, &v, 8); return x; }
inline uint32_t u32(float x) { uint32_t v; memcpy(&v, &x, 4); return v; }
inline uint64_t u64(double x) { uint64_t v; memcpy(&v, &x, 8); return v; }

struct Fpu {
  Core *c;
  uint32_t exc = 0;       // this operation's exceptions (FX_*)
  bool arith = false;     // it updates FCSR's cause (an arithmetic / conversion / compare)

  bool fr() const { return (c->status & 0x04000000u) != 0; }
  uint32_t rs32(int r) const { return (uint32_t)c->fpr[r]; }
  void ws32(int r, uint32_t v) { c->fpr[r] = (c->fpr[r] & 0xFFFFFFFF00000000ull) | v; }
  uint64_t rd64(int r) const {
    if (fr()) return c->fpr[r];
    if (r & 1) c->exception(EXC_RI);
    return (uint32_t)c->fpr[r] | ((uint64_t)(uint32_t)c->fpr[r + 1] << 32);
  }
  void wd64(int r, uint64_t v) {
    if (fr()) { c->fpr[r] = v; return; }
    if (r & 1) c->exception(EXC_RI);
    c->fpr[r] = (c->fpr[r] & 0xFFFFFFFF00000000ull) | (uint32_t)v;
    c->fpr[r + 1] = (c->fpr[r + 1] & 0xFFFFFFFF00000000ull) | (uint32_t)(v >> 32);
  }
  // loads / stores: FR = 0 takes the even / odd pair without a register check
  uint64_t rd64_mem(int r) const {
    if (fr()) return c->fpr[r];
    return (uint32_t)c->fpr[r & ~1] | ((uint64_t)(uint32_t)c->fpr[r | 1] << 32);
  }
  void wd64_mem(int r, uint64_t v) {
    if (fr()) { c->fpr[r] = v; return; }
    c->fpr[r & ~1] = (c->fpr[r & ~1] & 0xFFFFFFFF00000000ull) | (uint32_t)v;
    c->fpr[r | 1] = (c->fpr[r | 1] & 0xFFFFFFFF00000000ull) | (uint32_t)(v >> 32);
  }
  void need_fr() const {
    if (!fr()) c->exception(EXC_RI);   // (L format / 64-bit conversions: FR = 1 only)
  }
  bool fcc(int cc) const { return (c->fcsr >> (cc ? 24 + cc : 23)) & 1; }
  void set_fcc(int cc, bool v) {
    uint32_t bit = 1u << (cc ? 24 + cc : 23);
    c->fcsr = v ? (c->fcsr | bit) : (c->fcsr & ~bit);
  }

  // ---- host IEEE state around one operation ----
  static int host_rm(int mips_rm) {
    switch (mips_rm & 3) {
      case 0: return FE_TONEAREST;
      case 1: return FE_TOWARDZERO;
      case 2: return FE_UPWARD;
      default: return FE_DOWNWARD;
    }
  }
  void begin(int mips_rm) {
    arith = true;
    std::feclearexcept(FE_ALL_EXCEPT);
    std::fesetround(host_rm(mips_rm));
  }
  void begin() { begin(c->fcsr & 3); }
  void end() {
    int f = std::fetestexcept(FE_ALL_EXCEPT);
    std::fesetround(FE_TONEAREST);
    if (f & FE_INEXACT) exc |= FX_I;
    if (f & FE_UNDERFLOW) exc |= FX_U;
    if (f & FE_OVERFLOW) exc |= FX_O;
    if (f & FE_DIVBYZERO) exc |= FX_Z;
    if (f & FE_INVALID) exc |= FX_V;
  }
  // QEMU's update_fcr31: the cause is this operation's exceptions; an enabled one
  // traps (FPE), else they add to the flags
  void commit() {
    if (!arith) return;
    c->fcsr = (c->fcsr & ~0x0003F000u) | (exc << 12);
    if (exc) {
      if (exc & ((c->fcsr >> 7) & 0x1F)) c->exception(EXC_FPE);
      c->fcsr |= exc << 2;
    }
  }

  // ---- NaN operands (QEMU 5 pickNaN, MIPS legacy): a signalling one raises
  // invalid and gives the default NaN, else the first quiet one passes through
  uint32_t pick32(uint32_t a, uint32_t b) {
    if (snan32(a) || snan32(b)) { exc |= FX_V; return DNAN32; }
    return nan32(a) ? a : b;
  }
  uint64_t pick64(uint64_t a, uint64_t b) {
    if (snan64(a) || snan64(b)) { exc |= FX_V; return DNAN64; }
    return nan64(a) ? a : b;
  }

  // ---- operations ----
  uint32_t op_s(int op, uint32_t a, uint32_t b) {
    arith = true;
    if (nan32(a) || nan32(b)) return pick32(a, b);
    begin();
    float x = f32(a), y = f32(b), r;
    switch (op) {
      case 0: r = x + y; break;
      case 1: r = x - y; break;
      case 2: r = x * y; break;
      default: r = x / y; break;
    }
    end();
    return std::isnan(r) ? DNAN32 : u32(r);
  }
  uint64_t op_d(int op, uint64_t a, uint64_t b) {
    arith = true;
    if (nan64(a) || nan64(b)) return pick64(a, b);
    begin();
    double x = f64(a), y = f64(b), r;
    switch (op) {
      case 0: r = x + y; break;
      case 1: r = x - y; break;
      case 2: r = x * y; break;
      default: r = x / y; break;
    }
    end();
    return std::isnan(r) ? DNAN64 : u64(r);
  }
  uint32_t sqrt_s(uint32_t a) {
    arith = true;
    if (nan32(a)) return pick32(a, a);
    begin();
    float r = std::sqrt(f32(a));
    end();
    return std::isnan(r) ? DNAN32 : u32(r);
  }
  uint64_t sqrt_d(uint64_t a) {
    arith = true;
    if (nan64(a)) return pick64(a, a);
    begin();
    double r = std::sqrt(f64(a));
    end();
    return std::isnan(r) ? DNAN64 : u64(r);
  }
  uint32_t cvt_s_d(uint64_t a) {
    arith = true;
    if (nan64(a)) {   // (a quiet NaN keeps its sign and the top of its payload)
      if (snan64(a)) { exc |= FX_V; return DNAN32; }
      uint32_t frac = (uint32_t)((a >> 29) & 0x7FFFFFu);
      return frac ? ((uint32_t)(a >> 32) & 0x80000000u) | 0x7F800000u | frac : DNAN32;
    }
    begin();
    float r = (float)f64(a);
    end();
    return u32(r);
  }
  uint64_t cvt_d_s(uint32_t a) {
    arith = true;
    if (nan32(a)) {
      if (snan32(a)) { exc |= FX_V; return DNAN64; }
      return ((uint64_t)(a & 0x80000000u) << 32) | 0x7FF0000000000000ull | ((uint64_t)(a & 0x7FFFFFu) << 29);
    }
    begin();
    double r = (double)f32(a);
    end();
    return u64(r);
  }
  // float -> int32 / int64, rounding mode `mode` (MIPS RM encoding)
  uint32_t to_w(double x, bool isnan_, int mode) {
    arith = true;
    if (isnan_) { exc |= FX_V; return 0x7FFFFFFFu; }
    begin(mode);
    double r = std::rint(x);
    end();
    if (r >= 2147483648.0 || r < -2147483648.0) {
      exc = (exc & ~FX_I) | FX_V;
      return 0x7FFFFFFFu;
    }
    return (uint32_t)(int32_t)r;
  }
  uint64_t to_l(double x, bool isnan_, int mode) {
    arith = true;
    if (isnan_) { exc |= FX_V; return 0x7FFFFFFFFFFFFFFFull; }
    begin(mode);
    double r = std::rint(x);
    end();
    if (r >= 9223372036854775808.0 || r < -9223372036854775808.0) {
      exc = (exc & ~FX_I) | FX_V;
      return 0x7FFFFFFFFFFFFFFFull;
    }
    return (uint64_t)(int64_t)r;
  }
  // C.cond: cond bit 0 unordered, 1 equal, 2 less; 3 (the upper 8): signalling
  bool cmp(double x, double y, bool na, bool nb, bool sa, bool sb, int cond) {
    arith = true;
    bool un = na || nb;
    if (un && ((cond & 8) || sa || sb)) exc |= FX_V;
    bool eq = !un && x == y;
    bool lt = !un && x < y;
    return ((cond & 1) && un) || ((cond & 2) && eq) || ((cond & 4) && lt);
  }
  uint32_t from_w_s(int32_t w) { begin(); float r = (float)w; end(); return u32(r); }
  uint64_t from_w_d(int32_t w) { arith = true; return u64((double)w); }
  uint32_t from_l_s(int64_t l) { begin(); float r = (float)l; end(); return u32(r); }
  uint64_t from_l_d(int64_t l) { begin(); double r = (double)l; end(); return u64(r); }
  // fused-free multiply-add: (a * b) op c with two roundings (the R2 MADD family)
  uint32_t madd_s(int op, uint32_t a, uint32_t b, uint32_t r) {
    uint32_t p = op_s(2, a, b);
    uint32_t q = op_s((op & 1) ? 1 : 0, p, r);
    if ((op & 2) && !nan32(q)) q ^= 0x80000000u;
    return q;
  }
  uint64_t madd_d(int op, uint64_t a, uint64_t b, uint64_t r) {
    uint64_t p = op_d(2, a, b);
    uint64_t q = op_d((op & 1) ? 1 : 0, p, r);
    if ((op & 2) && !nan64(q)) q ^= 0x8000000000000000ull;
    return q;
  }
};

}  // namespace

#define RS ((insn >> 21) & 31)
#define RT ((insn >> 16) & 31)
#define RD ((insn >> 11) & 31)
#define SA ((insn >> 6) & 31)

void Core::exec_cop1(uint32_t insn) {
  if (!fpu_usable()) exception(EXC_CPU);
  Fpu F{this};
  uint32_t fmt = RS, ft = RT, fs = RD, fd = SA, funct = insn & 0x3F;
  switch (fmt) {
    case 0x00: if (ft) gpr[ft] = F.rs32(fs); return;                                    // MFC1
    case 0x02: {                                                                         // CFC1
      uint32_t v;
      switch (fs) {
        case 0: v = fir; break;
        case 25: v = ((fcsr >> 24) & 0xFE) | ((fcsr >> 23) & 1); break;
        case 26: v = fcsr & 0x0003F07Cu; break;
        case 28: v = (fcsr & 0xF83u) | ((fcsr >> 22) & 4); break;
        case 31: v = fcsr; break;
        default: exception(EXC_RI);
      }
      if (ft) gpr[ft] = v;
      return;
    }
    case 0x03: { uint32_t v = F.fr() ? (uint32_t)(fpr[fs] >> 32) : F.rs32(fs | 1); if (ft) gpr[ft] = v; return; }  // MFHC1
    case 0x04: F.ws32(fs, gpr[ft]); return;                                              // MTC1
    case 0x06: {                                                                         // CTC1
      uint32_t v = gpr[ft];
      switch (fs) {
        case 25: if (v & 0xFFFFFF00u) return; fcsr = (fcsr & 0x017FFFFFu) | ((v & 0xFE) << 24) | ((v & 1) << 23); break;
        case 26: if (v & 0xFFFC0F83u) return; fcsr = (fcsr & 0xFFFC0F83u) | (v & 0x0003F07Cu); break;
        case 28: if (v & 0xFFFFF07Cu) return; fcsr = (fcsr & 0xFEFFF07Cu) | (v & 0xF83u) | ((v & 4) << 22); break;
        case 31: fcsr = v & 0xFF83FFFFu; break;
        default: exception(EXC_RI);
      }
      if (((((fcsr >> 7) & 0x1F) | 0x20) & ((fcsr >> 12) & 0x3F))) exception(EXC_FPE);
      return;
    }
    case 0x07:                                                                           // MTHC1
      if (F.fr()) fpr[fs] = (fpr[fs] & 0xFFFFFFFFull) | ((uint64_t)gpr[ft] << 32);
      else F.ws32(fs | 1, gpr[ft]);
      return;
    case 0x08: {                                                                         // BC1F / BC1T (L)
      uint32_t cc = (insn >> 18) & 7, nd = (insn >> 17) & 1, tf = (insn >> 16) & 1;
      bool cnd = F.fcc(cc) == (tf != 0);
      uint32_t target = cur_pc_ + 4 + ((uint32_t)(int32_t)(int16_t)(insn & 0xFFFF) << 2);
      if (nd) {
        if (cnd) { br_taken_ = true; br_target_ = target; br_m16_ = false; }
        else npc_ = cur_pc_ + 8;
      } else {
        br_taken_ = true; br_target_ = cnd ? target : cur_pc_ + 8; br_m16_ = false;
      }
      return;
    }
    case 0x10: {   // S
      uint32_t a = F.rs32(fs);
      switch (funct) {
        case 0x00: case 0x01: case 0x02: case 0x03: {
          uint32_t r = F.op_s((int)funct, a, F.rs32(ft));
          F.commit(); F.ws32(fd, r); return;
        }
        case 0x04: { uint32_t r = F.sqrt_s(a); F.commit(); F.ws32(fd, r); return; }
        case 0x05: F.ws32(fd, a & 0x7FFFFFFFu); return;                                 // ABS
        case 0x06: F.ws32(fd, a); return;                                               // MOV
        case 0x07: F.ws32(fd, a ^ 0x80000000u); return;                                 // NEG
        case 0x08: case 0x09: case 0x0A: case 0x0B: {                                   // ROUND / TRUNC / CEIL / FLOOR.L
          F.need_fr();
          static const int M[4] = {0, 1, 2, 3};
          uint64_t r = F.to_l(f32(a), nan32(a), M[funct & 3]);
          F.commit(); F.wd64(fd, r); return;
        }
        case 0x0C: case 0x0D: case 0x0E: case 0x0F: {                                   // ... .W
          uint32_t r = F.to_w(f32(a), nan32(a), (int)(funct & 3));
          F.commit(); F.ws32(fd, r); return;
        }
        case 0x11: { uint32_t cc = ft >> 2, tf = ft & 1; if (F.fcc(cc) == (tf != 0)) F.ws32(fd, a); return; }
        case 0x12: if (gpr[ft] == 0) F.ws32(fd, a); return;
        case 0x13: if (gpr[ft] != 0) F.ws32(fd, a); return;
        case 0x15: { uint32_t r = F.op_s(3, 0x3F800000u, a); F.commit(); F.ws32(fd, r); return; }        // RECIP
        case 0x16: { uint32_t q = F.sqrt_s(a); uint32_t r = F.op_s(3, 0x3F800000u, q); F.commit(); F.ws32(fd, r); return; }  // RSQRT
        case 0x21: { uint64_t r = F.cvt_d_s(a); F.commit(); F.wd64(fd, r); return; }   // CVT.D.S
        case 0x24: { uint32_t r = F.to_w(f32(a), nan32(a), (int)(fcsr & 3)); F.commit(); F.ws32(fd, r); return; }  // CVT.W.S
        case 0x25: { F.need_fr(); uint64_t r = F.to_l(f32(a), nan32(a), (int)(fcsr & 3)); F.commit(); F.wd64(fd, r); return; }
      }
      if (funct >= 0x30) {                                                               // C.cond.S
        uint32_t b = F.rs32(ft);
        bool r = F.cmp(f32(a), f32(b), nan32(a), nan32(b), snan32(a), snan32(b), (int)(funct & 15));
        F.commit();
        F.set_fcc(fd >> 2, r);
        return;
      }
      exception(EXC_RI);
    }
    case 0x11: {   // D
      uint64_t a = F.rd64(fs);
      switch (funct) {
        case 0x00: case 0x01: case 0x02: case 0x03: {
          uint64_t r = F.op_d((int)funct, a, F.rd64(ft));
          F.commit(); F.wd64(fd, r); return;
        }
        case 0x04: { uint64_t r = F.sqrt_d(a); F.commit(); F.wd64(fd, r); return; }
        case 0x05: F.wd64(fd, a & 0x7FFFFFFFFFFFFFFFull); return;
        case 0x06: F.wd64(fd, a); return;
        case 0x07: F.wd64(fd, a ^ 0x8000000000000000ull); return;
        case 0x08: case 0x09: case 0x0A: case 0x0B: {
          F.need_fr();
          uint64_t r = F.to_l(f64(a), nan64(a), (int)(funct & 3));
          F.commit(); F.wd64(fd, r); return;
        }
        case 0x0C: case 0x0D: case 0x0E: case 0x0F: {
          uint32_t r = F.to_w(f64(a), nan64(a), (int)(funct & 3));
          F.commit(); F.ws32(fd, r); return;
        }
        case 0x11: { uint32_t cc = ft >> 2, tf = ft & 1; if (F.fcc(cc) == (tf != 0)) F.wd64(fd, a); return; }
        case 0x12: if (gpr[ft] == 0) F.wd64(fd, a); return;
        case 0x13: if (gpr[ft] != 0) F.wd64(fd, a); return;
        case 0x15: { uint64_t r = F.op_d(3, 0x3FF0000000000000ull, a); F.commit(); F.wd64(fd, r); return; }
        case 0x16: { uint64_t q = F.sqrt_d(a); uint64_t r = F.op_d(3, 0x3FF0000000000000ull, q); F.commit(); F.wd64(fd, r); return; }
        case 0x20: { uint32_t r = F.cvt_s_d(a); F.commit(); F.ws32(fd, r); return; }   // CVT.S.D
        case 0x24: { uint32_t r = F.to_w(f64(a), nan64(a), (int)(fcsr & 3)); F.commit(); F.ws32(fd, r); return; }
        case 0x25: { F.need_fr(); uint64_t r = F.to_l(f64(a), nan64(a), (int)(fcsr & 3)); F.commit(); F.wd64(fd, r); return; }
      }
      if (funct >= 0x30) {                                                               // C.cond.D
        uint64_t b = F.rd64(ft);
        bool r = F.cmp(f64(a), f64(b), nan64(a), nan64(b), snan64(a), snan64(b), (int)(funct & 15));
        F.commit();
        F.set_fcc(fd >> 2, r);
        return;
      }
      exception(EXC_RI);
    }
    case 0x14: {   // W
      int32_t w = (int32_t)F.rs32(fs);
      if (funct == 0x20) { uint32_t r = F.from_w_s(w); F.commit(); F.ws32(fd, r); return; }
      if (funct == 0x21) { uint64_t r = F.from_w_d(w); F.commit(); F.wd64(fd, r); return; }
      exception(EXC_RI);
    }
    case 0x15: {   // L (FR = 1 only)
      F.need_fr();
      int64_t l = (int64_t)F.rd64(fs);
      if (funct == 0x20) { uint32_t r = F.from_l_s(l); F.commit(); F.ws32(fd, r); return; }
      if (funct == 0x21) { uint64_t r = F.from_l_d(l); F.commit(); F.wd64(fd, r); return; }
      exception(EXC_RI);
    }
  }
  exception(EXC_RI);
}

void Core::exec_cop1x(uint32_t insn) {
  if (!fpu_usable()) exception(EXC_CPU);
  Fpu F{this};
  uint32_t base = RS, index = RT, fs = RD, fd = SA, funct = insn & 0x3F;
  uint32_t a = gpr[base] + gpr[index];
  switch (funct) {
    case 0x00: F.ws32(fd, load<uint32_t>(a)); return;                                   // LWXC1
    case 0x01: {                                                                         // LDXC1
      if (a & 7) fault_unaligned(a, MEM_READ);
      uint64_t v = (uint64_t)load<uint32_t>(a) | ((uint64_t)load<uint32_t>(a + 4) << 32);
      F.wd64_mem(fd, v);
      return;
    }
    case 0x08: store<uint32_t>(a, F.rs32(fs)); return;                                  // SWXC1
    case 0x09: {                                                                         // SDXC1
      if (a & 7) fault_unaligned(a, MEM_WRITE);
      uint64_t v = F.rd64_mem(fs);
      store<uint32_t>(a, (uint32_t)v);
      store<uint32_t>(a + 4, (uint32_t)(v >> 32));
      return;
    }
    case 0x0F: return;                                                                   // PREFX
  }
  uint32_t op = funct >> 3, fmt = funct & 7, fr = RS, ft = RT;
  if (op >= 4 && op <= 7 && (fmt == 0 || fmt == 1)) {
    // MADD (4) / MSUB (5) / NMADD (6) / NMSUB (7): bit 0 subtract, bit 1 negate
    int kind = (int)(op - 4);
    if (fmt == 0) {
      uint32_t r = F.madd_s(kind, F.rs32(fs), F.rs32(ft), F.rs32(fr));
      F.commit();
      F.ws32(fd, r);
    } else {
      uint64_t r = F.madd_d(kind, F.rd64(fs), F.rd64(ft), F.rd64(fr));
      F.commit();
      F.wd64(fd, r);
    }
    return;
  }
  exception(EXC_RI);
}

}  // namespace ali
