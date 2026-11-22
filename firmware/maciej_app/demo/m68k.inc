/* The 68000, an interpreter: shared by amiga.c and md.c, #included by each
   (so that its memory accesses stay inlined against the machine's own map).

   Each of the 65536 opcodes is decoded once, at the start, into a byte
   naming its handler (optab, 64 KB of RAM); a handler reads the opcode's
   fields itself.  Memory is kept the way the 68000 sees it, a 16-bit word in
   each host u16 (so a word access is one load, a byte one is the word's
   other half: address ^ 1).  The 16 MB address space is 256 pages of 64 KB:
   a page of plain memory is a pointer (rmap / wmap), the rest goes through
   the machine's io_read / io_write.  The cycle counts are the 68000's own
   (from its manual's tables); address errors are taken at the end of the
   instruction that made them; the trace exception is there; the bus error
   and the exact prefetch are not.  Checked against the SingleStepTests/m68000
   files (MAME's 68000): every test passes but those of address errors (not
   compared) and STOP's (its PC as those tests count it).  The flags are kept
   Musashi's way: N in bit 7 of n (after a shift by the size), Z set when z is
   0, V in bit 7 of v, C and X in bit 8 of c and x.

   The includer defines before it: u8 u16 u32 s32 s8 s16, INLINE, and may
   define
     M68K_IACK(level)    the interrupt acknowledge (an autovectored interrupt
                         of that level being taken: after its stack frame and
                         vector, before the next instruction) -- the Mega
                         Drive's VDP clears its pending interrupt there;
     M68K_TAS_READ_ONLY  TAS on memory reads and sets the flags but does not
                         write (the Mega Drive's bus does not take its write);
     M68K_BRANCH(at)     a Bcc / BRA at `at` taken (m.pc: where it went) --
                         md.c looks there for a loop waiting on RAM.
   It defines after it: io_read, io_write (the accesses of pages without
   memory, a = the 24-bit address, size 1 or 2) and cpu_reset_line (the RESET
   instruction).  The 68000's state is `m`; m.ipl the interrupt level asked
   for (check_pending() after changing it); cpu_run(until) runs it until
   m.clock reaches `until`. */
#ifndef M68K_IACK
#define M68K_IACK(level)
#endif
#ifndef M68K_BRANCH
#define M68K_BRANCH(at)
#endif

static struct m68k {
    u32 r[16];                          /* D0..D7, A0..A7 (A7: the stack pointer of the mode it is in) */
    u32 pc, op;
    u32 other_sp;                       /* the other mode's stack pointer (USP in supervisor mode, SSP in user) */
    u32 s, t, im;                       /* SR's supervisor and trace bits, its interrupt mask */
    u32 n, z, v, c, x;
    s32 clock;                          /* cycles since the frame started */
    u32 ipl;                            /* the interrupt level Paula asks for (0: none) */
    u32 pending;                        /* something to take before the next instruction (an interrupt, a trace) */
    u32 stopped;                        /* STOP: waiting for an interrupt */
    u32 fault, fault_write;             /* an address error in this instruction: the address | 1, read or write */
    u32 fault_pc;
#ifdef M68K_BUS_ERROR
    u32 bus_err, bus_addr, bus_write;
#endif
} m;

static u8 *rmap[256], *wmap[256];       /* each 64 KB page's memory (0: the chips, through io_read / io_write) */
static u32 io_read(u32 a, int size);
static void io_write(u32 a, u32 v, int size);
static void cpu_reset_line(void);       /* RESET: the chips back to their power-on state */

static u32 odd(u32 a, int write)
{
    if (!m.fault) {
        m.fault = a | 1;
        m.fault_write = (u32)write;
    }
    return 0;
}

INLINE u32 rb(u32 a)
{
    const u8 *p = rmap[(a >> 16) & 0xFF];
    return p ? p[(a & 0xFFFF) ^ 1] : io_read(a & 0xFFFFFF, 1);
}

INLINE u32 rw(u32 a)
{
    if (a & 1)
        return odd(a, 0);
    const u8 *p = rmap[(a >> 16) & 0xFF];
    return p ? *(const u16 *)(p + (a & 0xFFFF)) : io_read(a & 0xFFFFFF, 2);
}

static u32 rl(u32 a)
{
    u32 hi = rw(a);
    return hi << 16 | rw(a + 2);
}

INLINE void wb(u32 a, u32 v)
{
    u8 *p = wmap[(a >> 16) & 0xFF];
    if (p)
        p[(a & 0xFFFF) ^ 1] = (u8)v;
    else
        io_write(a & 0xFFFFFF, v & 0xFF, 1);
}

INLINE void ww(u32 a, u32 v)
{
    if (a & 1) {
        odd(a, 1);
        return;
    }
    u8 *p = wmap[(a >> 16) & 0xFF];
    if (p)
        *(u16 *)(p + (a & 0xFFFF)) = (u16)v;
    else
        io_write(a & 0xFFFFFF, v & 0xFFFF, 2);
}

static void wl(u32 a, u32 v)
{
    ww(a, v >> 16);
    ww(a + 2, v);
}

INLINE u32 fetch(void)
{
#ifdef M68K_FETCH
    u32 v = M68K_FETCH(m.pc);
#else
    u32 v = rw(m.pc);
#endif
    m.pc += 2;
    return v;
}

static u32 fetch32(void)
{
    u32 hi = fetch();
    return hi << 16 | fetch();
}

INLINE u32 msk(int s)
{
    return s == 1 ? 0xFFu : s == 2 ? 0xFFFFu : 0xFFFFFFFFu;
}

INLINE u32 nf(u32 r, int s)              /* N: the sign bit into bit 7 */
{
    return s == 1 ? r : s == 2 ? r >> 8 : r >> 24;
}

INLINE u32 sx(u32 v, int s)
{
    return s == 1 ? (u32)(s32)(s8)v : s == 2 ? (u32)(s32)(s16)v : v;
}

INLINE u32 rd(u32 a, int s)
{
    return s == 1 ? rb(a) : s == 2 ? rw(a) : rl(a);
}

INLINE void wr(u32 a, u32 v, int s)
{
    if (s == 1)
        wb(a, v);
    else if (s == 2)
        ww(a, v);
    else
        wl(a, v);
}

INLINE void set_dn(u32 r, u32 v, int s)
{
    if (s == 4)
        m.r[r] = v;
    else
        m.r[r] = (m.r[r] & ~msk(s)) | (v & msk(s));
}

static u32 get_sr(void)
{
    return m.t << 15 | m.s << 13 | m.im << 8 | ((m.x & 0x100) >> 4) | ((m.n & 0x80) >> 4) | (u32)(!m.z) << 2 |
           ((m.v & 0x80) >> 6) | ((m.c & 0x100) >> 8);
}

static void set_ccr(u32 v)
{
    m.x = (v << 4) & 0x100;
    m.n = (v << 4) & 0x80;
    m.z = !(v & 4);
    m.v = (v << 6) & 0x80;
    m.c = (v << 8) & 0x100;
}

static void check_pending(void)
{
    m.pending = m.ipl > m.im || m.t;
}

static void set_sr(u32 v)
{
    set_ccr(v);
    m.t = (v >> 15) & 1;
    m.im = (v >> 8) & 7;
    u32 s = (v >> 13) & 1;
    if (s != m.s) {
        u32 sp = m.r[15];
        m.r[15] = m.other_sp;
        m.other_sp = sp;
        m.s = s;
    }
    check_pending();
}

static void supervisor(void)
{
    if (!m.s) {
        u32 sp = m.r[15];
        m.r[15] = m.other_sp;
        m.other_sp = sp;
        m.s = 1;
    }
    m.t = 0;
}

/* an exception of group 1 or 2: SR and the PC pushed, the vector's handler */
static void exception(u32 vector, u32 pc)
{
    u32 sr = get_sr();
    supervisor();
    m.r[15] -= 4;
    wl(m.r[15], pc);
    m.r[15] -= 2;
    ww(m.r[15], sr);
    m.pc = rl(vector * 4);
    m.clock += 34;
    check_pending();
}

/* an address error: the 14-byte frame of group 0 (the access, the opcode, SR, PC) */
static void address_error(void)
{
    u32 a = m.fault & ~1u, w = m.fault_write;
    m.fault = 0;
    u32 sr = get_sr();
    supervisor();
    m.r[15] -= 4;
    wl(m.r[15], m.pc);
    m.r[15] -= 2;
    ww(m.r[15], sr);
    m.r[15] -= 2;
    ww(m.r[15], m.op);
    m.r[15] -= 4;
    wl(m.r[15], a | 1u);
    m.r[15] -= 2;
    ww(m.r[15], (w ? 0 : 0x10) | (m.s ? 5 : 1));
    m.pc = rl(3 * 4);
    m.fault = 0;
    m.clock += 50;
    check_pending();
}

#ifdef M68K_BUS_ERROR
static void m68k_bus_error(u32 a, int write)
{
    if (!m.bus_err) {
        m.bus_err = 1;
        m.bus_addr = a;
        m.bus_write = (u32)write;
    }
}

static void bus_error(void)
{
    u32 a = m.bus_addr, w = m.bus_write, was_s = m.s;
    m.bus_err = 0;
    u32 sr = get_sr();
    supervisor();
    m.r[15] -= 4;
    wl(m.r[15], m.pc);
    m.r[15] -= 2;
    ww(m.r[15], sr);
    m.r[15] -= 2;
    ww(m.r[15], m.op);
    m.r[15] -= 4;
    wl(m.r[15], a);
    m.r[15] -= 2;
    ww(m.r[15], (w ? 0 : 0x10) | (was_s ? 5 : 1));
    m.pc = rl(2 * 4);
    m.bus_err = 0;
    m.clock += 50;
    check_pending();
}
#endif

#define OP   m.op
#define RX   ((m.op >> 9) & 7)
#define RY   (m.op & 7)
#define MODE ((m.op >> 3) & 7)

static u32 indexed(u32 base)
{
    u32 ext = fetch();
    u32 x = m.r[ext >> 12];
    if (!(ext & 0x800))
        x = (u32)(s32)(s16)x;
    return base + x + (u32)(s32)(s8)ext;
}

/* the address of a memory operand (modes 2..7) of `s` bytes, the time to fetch it counted; #imm: where it is */
static u32 ea(u32 mode, u32 reg, int s)
{
    u32 a, l = s == 4 ? 4 : 0;
    switch (mode) {
    case 2:
        m.clock += 4 + l;
        return m.r[8 + reg];
    case 3:
        a = m.r[8 + reg];
        m.r[8 + reg] += (s == 1 && reg == 7) ? 2 : (u32)s;
        m.clock += 4 + l;
        return a;
    case 4:
        m.r[8 + reg] -= (s == 1 && reg == 7) ? 2 : (u32)s;
        m.clock += 6 + l;
        return m.r[8 + reg];
    case 5:
        a = m.r[8 + reg];
        m.clock += 8 + l;
        return a + (u32)(s32)(s16)fetch();
    case 6:
        m.clock += 10 + l;
        return indexed(m.r[8 + reg]);
    default:
        switch (reg) {
        case 0:
            m.clock += 8 + l;
            return (u32)(s32)(s16)fetch();
        case 1:
            m.clock += 12 + l;
            return fetch32();
        case 2:
            a = m.pc;
            m.clock += 8 + l;
            return a + (u32)(s32)(s16)fetch();
        case 3:
            m.clock += 10 + l;
            return indexed(m.pc);
        default:
            a = m.pc + (s == 1);
            m.pc += s == 4 ? 4 : 2;
            m.clock += 4 + l;
            return a;
        }
    }
}

/* the address of a control operand (LEA, PEA, JMP, JSR, MOVEM): no time counted */
static u32 ea_ctl(u32 mode, u32 reg)
{
    u32 a;
    switch (mode) {
    case 2:
        return m.r[8 + reg];
    case 5:
        a = m.r[8 + reg];
        return a + (u32)(s32)(s16)fetch();
    case 6:
        return indexed(m.r[8 + reg]);
    default:
        switch (reg) {
        case 0:
            return (u32)(s32)(s16)fetch();
        case 1:
            return fetch32();
        case 2:
            a = m.pc;
            return a + (u32)(s32)(s16)fetch();
        default:
            return indexed(m.pc);
        }
    }
}

/* a control operand's time, by its mode (Dn An (An) (An)+ -(An) d16 d8 abs.W abs.L d16(PC) d8(PC) #): LEA's,
   JMP's (PEA's is LEA's + 8, JSR's JMP's + 8), MOVEM's beyond its (An) */
static const u8 lea_time[12] = {0, 0, 4, 0, 0, 8, 12, 8, 12, 8, 12, 0};
static const u8 jmp_time[12] = {0, 0, 8, 0, 0, 10, 14, 10, 12, 10, 14, 0};
static const u8 movem_time[12] = {0, 0, 0, 0, 0, 4, 6, 4, 8, 4, 6, 0};

INLINE int ctl(u32 mode, u32 reg)
{
    return mode < 7 ? (int)mode : 7 + (int)reg;
}

INLINE u32 src(int s)                    /* the operand of the low six bits */
{
    u32 mode = MODE, reg = RY;
    if (mode == 0)
        return m.r[reg] & msk(s);
    if (mode == 1)
        return m.r[8 + reg] & msk(s);
    if (mode == 7 && reg == 4) {
        m.clock += s == 4 ? 8 : 4;
        return (s == 4 ? fetch32() : fetch()) & msk(s);
    }
    return rd(ea(mode, reg, s), s);
}

static int cond(u32 cc)
{
    switch (cc & 15) {
    case 0: return 1;
    case 1: return 0;
    case 2: return !(m.c & 0x100) && m.z;
    case 3: return (m.c & 0x100) || !m.z;
    case 4: return !(m.c & 0x100);
    case 5: return (m.c & 0x100) != 0;
    case 6: return m.z != 0;
    case 7: return !m.z;
    case 8: return !(m.v & 0x80);
    case 9: return (m.v & 0x80) != 0;
    case 10: return !(m.n & 0x80);
    case 11: return (m.n & 0x80) != 0;
    case 12: return !((m.n ^ m.v) & 0x80);
    case 13: return ((m.n ^ m.v) & 0x80) != 0;
    case 14: return m.z && !((m.n ^ m.v) & 0x80);
    default: return !m.z || ((m.n ^ m.v) & 0x80);
    }
}

INLINE void logic(u32 r, int s)
{
    m.n = nf(r, s);
    m.z = r & msk(s);
    m.v = 0;
    m.c = 0;
}

INLINE u32 add_flags(u32 sv, u32 d, int s, u32 xin, int addx)
{
    u32 r = d + sv + xin;
    if (s == 4) {
        m.c = m.x = ((sv & d) | (~r & (sv | d))) >> 23;
        m.v = ((sv ^ r) & (d ^ r)) >> 24;
    } else {
        m.c = m.x = s == 1 ? r : r >> 8;
        m.v = s == 1 ? (sv ^ r) & (d ^ r) : ((sv ^ r) & (d ^ r)) >> 8;
    }
    m.n = nf(r, s);
    if (addx)
        m.z |= r & msk(s);
    else
        m.z = r & msk(s);
    return r & msk(s);
}

INLINE u32 sub_flags(u32 sv, u32 d, int s, u32 xin, int subx, int cmp)
{
    u32 r = d - sv - xin;
    if (s == 4) {
        m.c = ((sv & r) | (~d & (sv | r))) >> 23;
        m.v = ((sv ^ d) & (r ^ d)) >> 24;
    } else {
        m.c = s == 1 ? r : r >> 8;
        m.v = s == 1 ? (sv ^ d) & (r ^ d) : ((sv ^ d) & (r ^ d)) >> 8;
    }
    if (!cmp)
        m.x = m.c;
    m.n = nf(r, s);
    if (subx)
        m.z |= r & msk(s);
    else
        m.z = r & msk(s);
    return r & msk(s);
}

/* a read-modify-write of the low six bits' operand: d the value, EXPR makes res */
#define RMW(s, EXPR)                                                                                                \
    do {                                                                                                            \
        u32 mode_ = MODE, reg_ = RY, a_ = 0, d, res;                                                                \
        if (mode_ == 0)                                                                                             \
            d = m.r[reg_] & msk(s);                                                                                 \
        else {                                                                                                      \
            a_ = ea(mode_, reg_, s);                                                                                \
            d = rd(a_, s);                                                                                          \
        }                                                                                                           \
        EXPR;                                                                                                       \
        if (mode_ == 0)                                                                                             \
            set_dn(reg_, res, s);                                                                                   \
        else                                                                                                        \
            wr(a_, res, s);                                                                                         \
    } while (0)

/* ---- the instructions ---- */
static void op_illegal(void)            /* ILLEGAL and the opcodes that are not the 68000's; lines A and F */
{
    u32 v = (OP & 0xF000) == 0xA000 ? 10 : (OP & 0xF000) == 0xF000 ? 11 : 4;
    exception(v, m.pc - 2);
}

static void privileged(void)
{
    exception(8, m.pc - 2);
}

/* MOVE, MOVEA */
INLINE void move(int s)
{
    u32 v = src(s), mode = (OP >> 6) & 7, reg = RX;
    if (mode == 0) {
        logic(v, s);
        set_dn(reg, v, s);
        m.clock += 4;
        return;
    }
    if (mode == 1) {                    /* MOVEA: the word sign-extended, no flags */
        m.r[8 + reg] = sx(v, s);
        m.clock += 4;
        return;
    }
    logic(v, s);
    u32 a = ea(mode, reg, s);
    if (mode == 4)
        m.clock -= 2;                   /* (-(An) as a destination takes no longer than (An)) */
    wr(a, v, s);
    m.clock += 4;
}
static void op_move_b(void) { move(1); }
static void op_move_w(void) { move(2); }
static void op_move_l(void) { move(4); }

static void op_moveq(void)
{
    u32 v = (u32)(s32)(s8)OP;
    m.r[RX] = v;
    logic(v, 4);
    m.clock += 4;
}

/* the arithmetic and logic of lines 8, 9, B, C, D: <ea>,Dn and Dn,<ea> */
enum { K_OR, K_AND, K_SUB, K_ADD, K_CMP, K_EOR };

INLINE u32 alu(int k, u32 sv, u32 d, int s)
{
    switch (k) {
    case K_OR: d |= sv; logic(d, s); return d;
    case K_AND: d &= sv; logic(d, s); return d;
    case K_EOR: d ^= sv; logic(d, s); return d;
    case K_ADD: return add_flags(sv, d, s, 0, 0);
    case K_SUB: return sub_flags(sv, d, s, 0, 0, 0);
    default: return sub_flags(sv, d, s, 0, 0, 1);
    }
}

INLINE void alu_to_dn(int k, int s)      /* <ea> op Dn -> Dn */
{
    u32 mode = MODE;
    u32 sv = src(s), r = RX;
    u32 res = alu(k, sv, m.r[r] & msk(s), s);
    if (k != K_CMP)
        set_dn(r, res, s);
    if (s != 4)
        m.clock += 4;
    else
        m.clock += k != K_CMP && (mode == 0 || mode == 1 || (mode == 7 && (m.op & 7) == 4)) ? 8 : 6;
}

INLINE void alu_to_ea(int k, int s)      /* Dn op <ea> -> <ea> */
{
    u32 sv = m.r[RX] & msk(s);
    if (MODE == 0) {                    /* (EOR Dn,Dn) */
        u32 r = RY;
        set_dn(r, alu(k, sv, m.r[r] & msk(s), s), s);
        m.clock += s == 4 ? 8 : 4;
        return;
    }
    RMW(s, res = alu(k, sv, d, s));
    m.clock += s == 4 ? 12 : 8;
}

#define ALU_EA(name, k)                                                                                             \
    static void op_##name##_b_ea(void) { alu_to_ea(k, 1); }                                                         \
    static void op_##name##_w_ea(void) { alu_to_ea(k, 2); }                                                         \
    static void op_##name##_l_ea(void) { alu_to_ea(k, 4); }
#define ALU(name, k)                                                                                                \
    static void op_##name##_b_dn(void) { alu_to_dn(k, 1); }                                                         \
    static void op_##name##_w_dn(void) { alu_to_dn(k, 2); }                                                         \
    static void op_##name##_l_dn(void) { alu_to_dn(k, 4); }                                                         \
    ALU_EA(name, k)
ALU(or, K_OR)
ALU(and, K_AND)
ALU(sub, K_SUB)
ALU(add, K_ADD)
ALU_EA(eor, K_EOR)

static void op_cmp_b(void) { alu_to_dn(K_CMP, 1); }
static void op_cmp_w(void) { alu_to_dn(K_CMP, 2); }
static void op_cmp_l(void) { alu_to_dn(K_CMP, 4); }

/* ADDA, SUBA, CMPA */
INLINE void adda(int kind, int s)        /* 0 ADDA, 1 SUBA, 2 CMPA */
{
    u32 mode = MODE;
    u32 sv = sx(src(s), s), r = 8 + RX;
    if (kind == 0)
        m.r[r] += sv;
    else if (kind == 1)
        m.r[r] -= sv;
    else
        sub_flags(sv, m.r[r], 4, 0, 0, 1);
    if (kind == 2)
        m.clock += 6;
    else
        m.clock += s == 2 ? 8 : (mode == 0 || mode == 1 || (mode == 7 && RY == 4)) ? 8 : 6;
}
static void op_adda_w(void) { adda(0, 2); }
static void op_adda_l(void) { adda(0, 4); }
static void op_suba_w(void) { adda(1, 2); }
static void op_suba_l(void) { adda(1, 4); }
static void op_cmpa_w(void) { adda(2, 2); }
static void op_cmpa_l(void) { adda(2, 4); }

/* ORI, ANDI, SUBI, ADDI, EORI, CMPI */
INLINE void imm_op(int k, int s)
{
    u32 iv = s == 4 ? fetch32() : fetch() & msk(s);
    if (MODE == 0) {
        u32 r = RY;
        u32 res = alu(k, iv, m.r[r] & msk(s), s);
        if (k != K_CMP)
            set_dn(r, res, s);
        m.clock += s == 4 ? (k == K_CMP ? 14 : 16) : 8;
        return;
    }
    if (k == K_CMP) {
        u32 a = ea(MODE, RY, s);
        alu(k, iv, rd(a, s), s);
        m.clock += s == 4 ? 12 : 8;
        return;
    }
    RMW(s, res = alu(k, iv, d, s));
    m.clock += s == 4 ? 20 : 12;
}
#define IMM(name, k)                                                                                                \
    static void op_##name##_b(void) { imm_op(k, 1); }                                                               \
    static void op_##name##_w(void) { imm_op(k, 2); }                                                               \
    static void op_##name##_l(void) { imm_op(k, 4); }
IMM(ori, K_OR)
IMM(andi, K_AND)
IMM(subi, K_SUB)
IMM(addi, K_ADD)
IMM(eori, K_EOR)
IMM(cmpi, K_CMP)

/* ORI / ANDI / EORI to CCR and to SR */
static void op_ccr_sr(void)
{
    u32 to_sr = OP & 0x40, k = (OP >> 9) & 7;
    if (to_sr && !m.s) {
        privileged();
        return;
    }
    u32 iv = fetch();
    u32 v = get_sr();
    if (!to_sr)
        iv &= 0x1F;
    if (k == 0)
        v |= iv;
    else if (k == 1)
        v &= to_sr ? iv : (iv | 0xFF00);
    else
        v ^= iv;
    if (to_sr)
        set_sr(v);
    else
        set_ccr(v);
    m.clock += 20;
}

/* ADDQ, SUBQ */
INLINE void addq(int sub, int s)
{
    u32 q = ((OP >> 9) & 7) ? (OP >> 9) & 7 : 8;
    if (MODE == 1) {                    /* to An: the whole register, no flags */
        if (sub)
            m.r[8 + RY] -= q;
        else
            m.r[8 + RY] += q;
        m.clock += 8;
        return;
    }
    if (MODE == 0) {
        u32 r = RY;
        set_dn(r, sub ? sub_flags(q, m.r[r] & msk(s), s, 0, 0, 0) : add_flags(q, m.r[r] & msk(s), s, 0, 0), s);
        m.clock += s == 4 ? 8 : 4;
        return;
    }
    RMW(s, res = sub ? sub_flags(q, d, s, 0, 0, 0) : add_flags(q, d, s, 0, 0));
    m.clock += s == 4 ? 12 : 8;
}
static void op_addq_b(void) { addq(0, 1); }
static void op_addq_w(void) { addq(0, 2); }
static void op_addq_l(void) { addq(0, 4); }
static void op_subq_b(void) { addq(1, 1); }
static void op_subq_w(void) { addq(1, 2); }
static void op_subq_l(void) { addq(1, 4); }

/* ADDX, SUBX (Dy,Dx or -(Ay),-(Ax)) */
INLINE void addx(int sub, int s)
{
    u32 xin = (m.x >> 8) & 1;
    if (!(OP & 8)) {
        u32 sv = m.r[RY] & msk(s), d = m.r[RX] & msk(s);
        set_dn(RX, sub ? sub_flags(sv, d, s, xin, 1, 0) : add_flags(sv, d, s, xin, 1), s);
        m.clock += s == 4 ? 8 : 4;
        return;
    }
    u32 dec = (s == 1) ? 1 : (u32)s, ry = 8 + RY, rx = 8 + RX;
    m.r[ry] -= (s == 1 && ry == 15) ? 2 : dec;
    u32 sv = rd(m.r[ry], s);
    m.r[rx] -= (s == 1 && rx == 15) ? 2 : dec;
    u32 d = rd(m.r[rx], s);
    wr(m.r[rx], sub ? sub_flags(sv, d, s, xin, 1, 0) : add_flags(sv, d, s, xin, 1), s);
    m.clock += s == 4 ? 30 : 18;
}
static void op_addx_b(void) { addx(0, 1); }
static void op_addx_w(void) { addx(0, 2); }
static void op_addx_l(void) { addx(0, 4); }
static void op_subx_b(void) { addx(1, 1); }
static void op_subx_w(void) { addx(1, 2); }
static void op_subx_l(void) { addx(1, 4); }

/* CMPM (Ay)+,(Ax)+ */
INLINE void cmpm(int s)
{
    u32 ry = 8 + RY, rx = 8 + RX;
    u32 sv = rd(m.r[ry], s);
    m.r[ry] += (s == 1 && ry == 15) ? 2 : (u32)s;
    u32 d = rd(m.r[rx], s);
    m.r[rx] += (s == 1 && rx == 15) ? 2 : (u32)s;
    sub_flags(sv, d, s, 0, 0, 1);
    m.clock += s == 4 ? 20 : 12;
}
static void op_cmpm_b(void) { cmpm(1); }
static void op_cmpm_w(void) { cmpm(2); }
static void op_cmpm_l(void) { cmpm(4); }

/* CLR, NEG, NEGX, NOT, TST */
INLINE void unary(int k, int s)          /* 0 CLR, 1 NEG, 2 NEGX */
{
    u32 mode = MODE;
    if (k == 0) {                       /* (no read first: a register of the chips is not read) */
        if (mode == 0)
            set_dn(RY, 0, s);
        else
            wr(ea(mode, RY, s), 0, s);
        logic(0, s);
        m.clock += mode == 0 ? (s == 4 ? 6 : 4) : (s == 4 ? 12 : 8);
        return;
    }
    u32 xin = (m.x >> 8) & 1;
    RMW(s, res = k == 1 ? sub_flags(d, 0, s, 0, 0, 0) : sub_flags(d, 0, s, xin, 1, 0));
    m.clock += mode == 0 ? (s == 4 ? 6 : 4) : (s == 4 ? 12 : 8);
}
static void op_clr_b(void) { unary(0, 1); }
static void op_clr_w(void) { unary(0, 2); }
static void op_clr_l(void) { unary(0, 4); }
static void op_neg_b(void) { unary(1, 1); }
static void op_neg_w(void) { unary(1, 2); }
static void op_neg_l(void) { unary(1, 4); }
static void op_negx_b(void) { unary(2, 1); }
static void op_negx_w(void) { unary(2, 2); }
static void op_negx_l(void) { unary(2, 4); }

INLINE void op_not(int s)
{
    RMW(s, res = ~d & msk(s); logic(res, s));
    m.clock += MODE == 0 ? (s == 4 ? 6 : 4) : (s == 4 ? 12 : 8);
}
static void op_not_b(void) { op_not(1); }
static void op_not_w(void) { op_not(2); }
static void op_not_l(void) { op_not(4); }

INLINE void tst(int s)
{
    logic(src(s), s);
    m.clock += 4;
}
static void op_tst_b(void) { tst(1); }
static void op_tst_w(void) { tst(2); }
static void op_tst_l(void) { tst(4); }

static void op_tas(void)
{
#ifdef M68K_TAS_READ_ONLY
    if (MODE) {                         /* (memory: read, the flags set, no write) */
        logic(rd(ea(MODE, RY, 1), 1), 1);
        m.clock += 10;
        return;
    }
#endif
    RMW(1, logic(d, 1); res = d | 0x80);
    m.clock += MODE == 0 ? 4 : 10;
}

/* Bcc, BRA, BSR */
static void op_bcc(void)
{
    u32 base = m.pc, cc = (OP >> 8) & 15;
    u32 d = (u32)(s32)(s8)OP;
    if (!(OP & 0xFF))
        d = (u32)(s32)(s16)fetch();
    if (cc == 1) {                      /* BSR */
        m.r[15] -= 4;
        wl(m.r[15], m.pc);
        m.pc = base + d;
        m.clock += 18;
        return;
    }
    if (cond(cc)) {
        m.pc = base + d;
        m.clock += 10;
        M68K_BRANCH(base - 2);
    } else {
        m.clock += (OP & 0xFF) ? 8 : 12;
    }
}

static void op_dbcc(void)
{
    u32 base = m.pc;
    u32 d = (u32)(s32)(s16)fetch();
    if (cond(OP >> 8)) {
        m.clock += 12;
        return;
    }
    u32 r = RY, n = (m.r[r] - 1) & 0xFFFF;
    m.r[r] = (m.r[r] & 0xFFFF0000u) | n;
    if (n != 0xFFFF) {
        m.pc = base + d;
        m.clock += 10;
    } else {
        m.clock += 14;
    }
}

static void op_scc(void)
{
    u32 v = cond(OP >> 8) ? 0xFF : 0;
    if (MODE == 0) {
        set_dn(RY, v, 1);
        m.clock += v ? 6 : 4;
        return;
    }
    wb(ea(MODE, RY, 1), v);
    m.clock += 8;
}

/* LEA, PEA, JMP, JSR */
static void op_lea(void)
{
    u32 mode = MODE, reg = RY;
    m.clock += lea_time[ctl(mode, reg)];
    m.r[8 + RX] = ea_ctl(mode, reg);
}

static void op_pea(void)
{
    u32 mode = MODE, reg = RY;
    u32 a = ea_ctl(mode, reg);
    m.r[15] -= 4;
    wl(m.r[15], a);
    m.clock += 8 + lea_time[ctl(mode, reg)];
}

static void op_jmp(void)
{
    u32 mode = MODE, reg = RY;
    m.clock += jmp_time[ctl(mode, reg)];
    m.pc = ea_ctl(mode, reg);
}

static void op_jsr(void)
{
    u32 mode = MODE, reg = RY;
    u32 a = ea_ctl(mode, reg);
    m.r[15] -= 4;
    wl(m.r[15], m.pc);
    m.pc = a;
    m.clock += 8 + jmp_time[ctl(mode, reg)];
}

static void op_rts(void)
{
    m.pc = rl(m.r[15]);
    m.r[15] += 4;
    m.clock += 16;
}

static void op_rtr(void)
{
    set_ccr(rw(m.r[15]));
    m.pc = rl(m.r[15] + 2);
    m.r[15] += 6;
    m.clock += 20;
}

static void op_rte(void)
{
    if (!m.s) {
        privileged();
        return;
    }
    u32 sp = m.r[15], sr = rw(sp);
    m.pc = rl(sp + 2);
    m.r[15] = sp + 6;
    set_sr(sr);
    m.clock += 20;
}

static void op_nop(void)
{
    m.clock += 4;
}

static void op_stop(void)
{
    if (!m.s) {
        privileged();
        return;
    }
    set_sr(fetch());
    m.stopped = 1;
    m.clock += 4;
}

static void op_reset(void)
{
    if (!m.s) {
        privileged();
        return;
    }
    cpu_reset_line();
    m.clock += 132;
}

static void op_trapv(void)
{
    m.clock += 4;
    if (m.v & 0x80)
        exception(7, m.pc);
}

static void op_trap(void)
{
    exception(32 + (OP & 15), m.pc);
}

static void op_link(void)
{
    u32 r = 8 + RY, v = m.r[r];
    m.r[15] -= 4;
    wl(m.r[15], v);
    m.r[r] = m.r[15];
    m.r[15] += (u32)(s32)(s16)fetch();
    m.clock += 16;
}

static void op_unlk(void)
{
    u32 r = 8 + RY;
    m.r[15] = m.r[r];
    m.r[r] = rl(m.r[15]);
    if (r != 15)
        m.r[15] += 4;
    m.clock += 12;
}

static void op_move_usp(void)
{
    if (!m.s) {
        privileged();
        return;
    }
    if (OP & 8)
        m.r[8 + RY] = m.other_sp;
    else
        m.other_sp = m.r[8 + RY];
    m.clock += 4;
}

static void op_swap(void)
{
    u32 r = RY, v = m.r[r] >> 16 | m.r[r] << 16;
    m.r[r] = v;
    logic(v, 4);
    m.clock += 4;
}

static void op_ext_w(void)
{
    u32 r = RY, v = (u32)(s32)(s8)m.r[r] & 0xFFFF;
    set_dn(r, v, 2);
    logic(v, 2);
    m.clock += 4;
}

static void op_ext_l(void)
{
    u32 r = RY, v = (u32)(s32)(s16)m.r[r];
    m.r[r] = v;
    logic(v, 4);
    m.clock += 4;
}

static void op_exg(void)
{
    u32 a, b;
    switch ((OP >> 3) & 0x1F) {
    case 0x08: a = RX, b = RY; break;
    case 0x09: a = 8 + RX, b = 8 + RY; break;
    default: a = RX, b = 8 + RY; break;
    }
    u32 t = m.r[a];
    m.r[a] = m.r[b];
    m.r[b] = t;
    m.clock += 6;
}

/* MOVE from SR, to CCR, to SR */
static void op_move_from_sr(void)
{
    u32 v = get_sr();
    if (MODE == 0) {
        set_dn(RY, v, 2);
        m.clock += 6;
        return;
    }
    u32 a = ea(MODE, RY, 2);
    ww(a, v);
    m.clock += 8;
}

static void op_move_to_ccr(void)
{
    set_ccr(src(2));
    m.clock += 12;
}

static void op_move_to_sr(void)
{
    if (!m.s) {
        privileged();
        return;
    }
    set_sr(src(2));
    m.clock += 12;
}

/* MOVEM */
static void op_movem(void)
{
    u32 mask = fetch(), mode = MODE, reg = RY, to_regs = OP & 0x400, s = (OP & 0x40) ? 4 : 2;
    u32 n = 0;
    if (!to_regs && mode == 4) {        /* registers to -(An): from A7 down to D0 */
        u32 a = m.r[8 + reg], start = a;
        for (int i = 15; i >= 0; i--)
            if (mask & (1u << (15 - i))) {
                a -= s;
                u32 v = (u32)i == 8 + reg ? start : m.r[i];
                if (s == 4)
                    wl(a, v);
                else
                    ww(a, v);
                n++;
            }
        m.r[8 + reg] = a;
        m.clock += 8 + (int)(n * (s == 4 ? 8 : 4));
        return;
    }
    u32 a = mode == 3 ? m.r[8 + reg] : ea_ctl(mode, reg);
    int t = movem_time[ctl(mode, reg)];
    for (int i = 0; i < 16; i++)
        if (mask & (1u << i)) {
            if (to_regs)
                m.r[i] = s == 4 ? rl(a) : (u32)(s32)(s16)rw(a);
            else if (s == 4)
                wl(a, m.r[i]);
            else
                ww(a, m.r[i]);
            a += s;
            n++;
        }
    if (mode == 3)
        m.r[8 + reg] = a;
    m.clock += (to_regs ? 12 : 8) + t + (int)(n * (s == 4 ? 8 : 4));
}

/* MOVEP: bytes at every other address */
static void op_movep(void)
{
    u32 a = m.r[8 + RY] + (u32)(s32)(s16)fetch(), r = RX;
    switch ((OP >> 6) & 3) {
    case 0:
        set_dn(r, rb(a) << 8 | rb(a + 2), 2);
        m.clock += 16;
        break;
    case 1:
        m.r[r] = rb(a) << 24 | rb(a + 2) << 16 | rb(a + 4) << 8 | rb(a + 6);
        m.clock += 24;
        break;
    case 2:
        wb(a, m.r[r] >> 8);
        wb(a + 2, m.r[r]);
        m.clock += 16;
        break;
    default:
        wb(a, m.r[r] >> 24);
        wb(a + 2, m.r[r] >> 16);
        wb(a + 4, m.r[r] >> 8);
        wb(a + 6, m.r[r]);
        m.clock += 24;
        break;
    }
}

/* BTST, BCHG, BCLR, BSET: the bit number from Dn or an extension word */
static void op_bitop(void)
{
    u32 bit = (OP & 0x100) ? m.r[RX] : fetch(), kind = (OP >> 6) & 3, mode = MODE;
    if (mode == 0) {
        u32 r = RY, b = 1u << (bit & 31);
        m.z = m.r[r] & b;
        if (kind == 1)
            m.r[r] ^= b;
        else if (kind == 2)
            m.r[r] &= ~b;
        else if (kind == 3)
            m.r[r] |= b;
        m.clock += (kind == 0 ? 6 : kind == 2 ? 10 : 8) + ((OP & 0x100) ? 0 : 4);
        return;
    }
    u32 b = 1u << (bit & 7);
    if (kind == 0) {
        m.z = src(1) & b;
        m.clock += (OP & 0x100) ? 4 : 8;
        return;
    }
    RMW(1, m.z = d & b; res = kind == 1 ? d ^ b : kind == 2 ? d & ~b : d | b);
    m.clock += (OP & 0x100) ? 8 : 12;
}

/* MULU, MULS, DIVU, DIVS */
static void op_mulu(void)
{
    u32 sv = src(2), r = RX, v = (m.r[r] & 0xFFFF) * sv;
    m.r[r] = v;
    logic(v, 4);
    int n = 0;
    for (u32 b = sv; b; b >>= 1)
        n += b & 1;
    m.clock += 38 + 2 * n;
}

static void op_muls(void)
{
    u32 sv = src(2), r = RX;
    u32 v = (u32)((s32)(s16)m.r[r] * (s32)(s16)sv);
    m.r[r] = v;
    logic(v, 4);
    int n = 0;
    for (u32 b = ((sv << 1) ^ sv) & 0xFFFF; b; b >>= 1)
        n += b & 1;
    m.clock += 38 + 2 * n;
}

static void op_divu(void)
{
    u32 sv = src(2), r = RX;
    if (!sv) {
        m.c = 0;
        exception(5, m.pc);
        return;
    }
    u32 q = m.r[r] / sv, rem = m.r[r] % sv;
    m.clock += 140;
    if (q > 0xFFFF) {
        m.v = 0x80;
        m.n = 0x80;
        m.z = 1;
        m.c = 0;
        return;
    }
    m.r[r] = q | rem << 16;
    m.n = q >> 8;
    m.z = q;
    m.v = 0;
    m.c = 0;
}

static void op_divs(void)
{
    s32 sv = (s16)src(2);
    u32 r = RX;
    if (!sv) {
        m.c = 0;
        exception(5, m.pc);
        return;
    }
    s32 d = (s32)m.r[r];
    m.clock += 158;
    if (d == (s32)0x80000000 && sv == -1) {
        m.v = 0x80;
        m.n = 0x80;
        m.z = 1;
        m.c = 0;
        return;
    }
    s32 q = d / sv, rem = d % sv;
    if (q < -32768 || q > 32767) {
        m.v = 0x80;
        m.n = 0x80;
        m.z = 1;
        m.c = 0;
        return;
    }
    m.r[r] = ((u32)q & 0xFFFF) | (u32)rem << 16;
    m.n = (u32)q >> 8;
    m.z = (u32)q & 0xFFFF;
    m.v = 0;
    m.c = 0;
}

static void op_chk(void)
{
    s32 bound = (s16)src(2), v = (s16)m.r[RX];
    m.clock += 10;
    m.z = (u32)v & 0xFFFF;
    m.v = 0;
    m.c = 0;
    m.n = v < 0 ? 0x80 : 0;
    if (v < 0 || v > bound)
        exception(6, m.pc);
}

/* ABCD, SBCD, NBCD: the decimal corrections and the (undocumented) V the 68000 really gives */
static u32 bcd_add(u32 sv, u32 d)
{
    u32 ss = sv + d + ((m.x >> 8) & 1);
    u32 bc = ((sv & d) | (~ss & (sv | d))) & 0x88;
    u32 dc = (((ss + 0x66) ^ ss) & 0x110) >> 1;
    u32 corf = (bc | dc) - ((bc | dc) >> 2);
    u32 r = ss + corf;
    m.x = m.c = (((bc | (ss & ~r)) >> 7) & 1) << 8;
    m.v = ~ss & r & 0x80;
    r &= 0xFF;
    m.n = r;
    m.z |= r;
    return r;
}

static u32 bcd_sub(u32 sv, u32 d)
{
    u32 dd = d - sv - ((m.x >> 8) & 1);
    u32 bc = ((~d & sv) | (dd & ~(d ^ sv))) & 0x88;
    u32 corf = bc - (bc >> 2);
    u32 r = dd - corf;
    m.x = m.c = (((bc | (~dd & r)) >> 7) & 1) << 8;
    m.v = dd & ~r & 0x80;
    r &= 0xFF;
    m.n = r;
    m.z |= r;
    return r;
}

static void op_abcd_sbcd(void)
{
    int sub = (OP & 0xF000) == 0x8000;
    if (!(OP & 8)) {
        u32 r = RX;
        set_dn(r, sub ? bcd_sub(m.r[RY] & 0xFF, m.r[r] & 0xFF) : bcd_add(m.r[RY] & 0xFF, m.r[r] & 0xFF), 1);
        m.clock += 6;
        return;
    }
    u32 ry = 8 + RY, rx = 8 + RX;
    m.r[ry] -= ry == 15 ? 2 : 1;
    u32 sv = rb(m.r[ry]);
    m.r[rx] -= rx == 15 ? 2 : 1;
    u32 d = rb(m.r[rx]);
    wb(m.r[rx], sub ? bcd_sub(sv, d) : bcd_add(sv, d));
    m.clock += 18;
}

static void op_nbcd(void)
{
    RMW(1, res = bcd_sub(d, 0));
    m.clock += MODE == 0 ? 6 : 8;
}

/* the shifts and rotations: register (count in the opcode or a register), memory (by one, a word) */
INLINE u32 shift(u32 type, u32 left, u32 v, u32 n, int s)
{
    u32 bits = (u32)s * 8, mk = msk(s), sign = 1u << (bits - 1), r = v;
    if (!n) {
        m.c = type == 2 ? m.x : 0;
        m.v = 0;
        m.n = nf(v, s);
        m.z = v;
        return v;
    }
    switch (type) {
    case 0:                             /* AS */
        if (left) {
            u32 top;
            if (n < bits) {
                r = (v << n) & mk;
                m.c = m.x = ((v >> (bits - n)) & 1) << 8;
                top = (bits - n - 1) ? v >> (bits - n - 1) : v;
                u32 all = n + 1 >= 32 ? 0xFFFFFFFFu : (1u << (n + 1)) - 1;
                m.v = (top != 0 && top != all) ? 0x80 : 0;
            } else {
                r = 0;
                m.c = m.x = (n == bits ? (v & 1) : 0) << 8;
                m.v = v ? 0x80 : 0;
            }
        } else {
            u32 neg = v & sign;
            if (n < bits) {
                r = v >> n;
                if (neg)
                    r |= mk & ~(mk >> n);
                m.c = m.x = ((v >> (n - 1)) & 1) << 8;
            } else {
                r = neg ? mk : 0;
                m.c = m.x = neg ? 0x100 : 0;
            }
            m.v = 0;
        }
        break;
    case 1:                             /* LS */
        if (left) {
            if (n < bits) {
                r = (v << n) & mk;
                m.c = m.x = ((v >> (bits - n)) & 1) << 8;
            } else {
                r = 0;
                m.c = m.x = (n == bits ? (v & 1) : 0) << 8;
            }
        } else {
            if (n < bits) {
                r = v >> n;
                m.c = m.x = ((v >> (n - 1)) & 1) << 8;
            } else {
                r = 0;
                m.c = m.x = (n == bits ? (v >> (bits - 1)) & 1 : 0) << 8;
            }
        }
        m.v = 0;
        break;
    case 2: {                           /* ROX: through X, bits + 1 wide */
        u32 x = (m.x >> 8) & 1;
        n %= bits + 1;
        for (u32 i = 0; i < n; i++) {
            u32 out;
            if (left) {
                out = (r >> (bits - 1)) & 1;
                r = ((r << 1) | x) & mk;
            } else {
                out = r & 1;
                r = (r >> 1) | (x << (bits - 1));
            }
            x = out;
        }
        m.c = m.x = x << 8;
        m.v = 0;
        break;
    }
    default: {                          /* RO */
        u32 k = n & (bits - 1);
        if (k)
            r = left ? ((v << k) | (v >> (bits - k))) & mk : ((v >> k) | (v << (bits - k))) & mk;
        m.c = (left ? r & 1 : (r >> (bits - 1)) & 1) << 8;
        m.v = 0;
        break;
    }
    }
    m.n = nf(r, s);
    m.z = r;
    return r;
}

INLINE void shift_reg(int s)
{
    u32 n = (OP & 0x20) ? m.r[RX] & 63 : (((OP >> 9) & 7) ? (OP >> 9) & 7 : 8);
    u32 r = RY;
    set_dn(r, shift((OP >> 3) & 3, OP & 0x100, m.r[r] & msk(s), n, s), s);
    m.clock += (s == 4 ? 8 : 6) + 2 * (int)n;
}
static void op_shift_b(void) { shift_reg(1); }
static void op_shift_w(void) { shift_reg(2); }
static void op_shift_l(void) { shift_reg(4); }

static void op_shift_mem(void)
{
    u32 a = ea(MODE, RY, 2);
    ww(a, shift((OP >> 9) & 3, OP & 0x100, rw(a), 1, 2));
    m.clock += 8;
}

/* ---- the decoder ---- */
#define EA_DN    0x001u
#define EA_AN    0x002u
#define EA_MEM   0x1FCu                 /* (An) (An)+ -(An) d16(An) d8(An,Xn) abs.W abs.L */
#define EA_DA    (EA_DN | EA_MEM)       /* data alterable */
#define EA_ALT   (EA_DA | EA_AN)
#define EA_DATA  (EA_DA | 0xE00u)       /* + d16(PC) d8(PC,Xn) #imm */
#define EA_ALL   (EA_DATA | EA_AN)
#define EA_CTL   0x7E4u                 /* (An) d16(An) d8(An,Xn) abs.W abs.L d16(PC) d8(PC,Xn) */

static int ea_ok(u32 op, u32 allowed)
{
    u32 mode = (op >> 3) & 7, reg = op & 7, k = mode < 7 ? mode : reg <= 4 ? 7 + reg : 12;
    return k < 12 && (allowed >> k & 1);
}

#define HANDLERS(X)                                                                                                 \
    X(illegal) X(move_b) X(move_w) X(move_l) X(moveq)                                                               \
    X(or_b_dn) X(or_w_dn) X(or_l_dn) X(or_b_ea) X(or_w_ea) X(or_l_ea)                                               \
    X(and_b_dn) X(and_w_dn) X(and_l_dn) X(and_b_ea) X(and_w_ea) X(and_l_ea)                                         \
    X(sub_b_dn) X(sub_w_dn) X(sub_l_dn) X(sub_b_ea) X(sub_w_ea) X(sub_l_ea)                                         \
    X(add_b_dn) X(add_w_dn) X(add_l_dn) X(add_b_ea) X(add_w_ea) X(add_l_ea)                                         \
    X(eor_b_ea) X(eor_w_ea) X(eor_l_ea) X(cmp_b) X(cmp_w) X(cmp_l)                                                  \
    X(adda_w) X(adda_l) X(suba_w) X(suba_l) X(cmpa_w) X(cmpa_l)                                                     \
    X(ori_b) X(ori_w) X(ori_l) X(andi_b) X(andi_w) X(andi_l) X(subi_b) X(subi_w) X(subi_l)                          \
    X(addi_b) X(addi_w) X(addi_l) X(eori_b) X(eori_w) X(eori_l) X(cmpi_b) X(cmpi_w) X(cmpi_l) X(ccr_sr)             \
    X(addq_b) X(addq_w) X(addq_l) X(subq_b) X(subq_w) X(subq_l)                                                     \
    X(addx_b) X(addx_w) X(addx_l) X(subx_b) X(subx_w) X(subx_l) X(cmpm_b) X(cmpm_w) X(cmpm_l)                       \
    X(clr_b) X(clr_w) X(clr_l) X(neg_b) X(neg_w) X(neg_l) X(negx_b) X(negx_w) X(negx_l)                             \
    X(not_b) X(not_w) X(not_l) X(tst_b) X(tst_w) X(tst_l) X(tas)                                                    \
    X(bcc) X(dbcc) X(scc) X(lea) X(pea) X(jmp) X(jsr) X(rts) X(rtr) X(rte) X(nop) X(stop) X(reset) X(trapv)         \
    X(trap) X(link) X(unlk) X(move_usp) X(swap) X(ext_w) X(ext_l) X(exg)                                            \
    X(move_from_sr) X(move_to_ccr) X(move_to_sr) X(movem) X(movep) X(bitop)                                         \
    X(mulu) X(muls) X(divu) X(divs) X(chk) X(abcd_sbcd) X(nbcd) X(shift_b) X(shift_w) X(shift_l) X(shift_mem)

#define ENUM(name) H_##name,
enum { HANDLERS(ENUM) H_COUNT };
#define PTR(name) op_##name,
static void (*const handler[H_COUNT])(void) = {HANDLERS(PTR)};
static u8 optab[65536];

static int decode(u32 op)
{
    u32 hi = op >> 12, sz = (op >> 6) & 3, mode = (op >> 3) & 7, opm = (op >> 6) & 7;
    switch (hi) {
    case 0x0:
        if (op & 0x100) {
            if (mode == 1)
                return H_movep;
            return ea_ok(op, sz == 0 ? (EA_DATA & ~0u) : EA_DA) ? H_bitop : H_illegal;
        }
        switch ((op >> 9) & 7) {
        case 4:                         /* static bit operations */
            if (sz == 0)
                return ea_ok(op, EA_DATA & ~0x800u) ? H_bitop : H_illegal;
            return ea_ok(op, EA_DA) ? H_bitop : H_illegal;
        case 0: case 1: case 5:         /* ORI ANDI EORI: to CCR (.b) / SR (.w) when the operand is #imm */
            if ((op & 0x3F) == 0x3C && sz < 2)
                return H_ccr_sr;
            /* fall through */
        case 2: case 3: case 6: {
            static const u8 base[8] = {H_ori_b, H_andi_b, H_subi_b, H_addi_b, 0, H_eori_b, H_cmpi_b, 0};
            if (sz == 3 || !ea_ok(op, EA_DA))
                return H_illegal;
            return base[(op >> 9) & 7] + (int)sz;
        }
        default:
            return H_illegal;
        }
    case 0x1: case 0x2: case 0x3: {
        u32 dmode = (op >> 6) & 7, dreg = (op >> 9) & 7;
        int h = hi == 1 ? H_move_b : hi == 3 ? H_move_w : H_move_l;
        if (!ea_ok(op, hi == 1 ? EA_DATA : EA_ALL))
            return H_illegal;
        if (dmode == 1)
            return hi == 1 ? H_illegal : h;
        if (dmode == 7 && dreg > 1)
            return H_illegal;
        return h;
    }
    case 0x4:
        if (op & 0x100) {
            if (sz == 3)
                return ea_ok(op, EA_CTL) ? H_lea : H_illegal;
            if (sz == 2)
                return ea_ok(op, EA_DATA) ? H_chk : H_illegal;
            return H_illegal;
        }
        switch ((op >> 8) & 0xF) {
        case 0x0:
            if (sz == 3)
                return ea_ok(op, EA_DA) ? H_move_from_sr : H_illegal;
            return ea_ok(op, EA_DA) ? H_negx_b + (int)sz : H_illegal;
        case 0x2:
            return sz < 3 && ea_ok(op, EA_DA) ? H_clr_b + (int)sz : H_illegal;
        case 0x4:
            if (sz == 3)
                return ea_ok(op, EA_DATA) ? H_move_to_ccr : H_illegal;
            return ea_ok(op, EA_DA) ? H_neg_b + (int)sz : H_illegal;
        case 0x6:
            if (sz == 3)
                return ea_ok(op, EA_DATA) ? H_move_to_sr : H_illegal;
            return ea_ok(op, EA_DA) ? H_not_b + (int)sz : H_illegal;
        case 0x8:
            if (sz == 0)
                return ea_ok(op, EA_DA) ? H_nbcd : H_illegal;
            if (sz == 1)
                return mode == 0 ? H_swap : ea_ok(op, EA_CTL) ? H_pea : H_illegal;
            if (mode == 0)
                return sz == 2 ? H_ext_w : H_ext_l;
            return ea_ok(op, EA_CTL & ~0x600u) || mode == 4 ? H_movem : H_illegal;
        case 0xA:
            if (op == 0x4AFC)
                return H_illegal;
            if (sz == 3)
                return ea_ok(op, EA_DA) ? H_tas : H_illegal;
            return ea_ok(op, EA_DA) ? H_tst_b + (int)sz : H_illegal;
        case 0xC:
            if (sz < 2)
                return H_illegal;
            return ea_ok(op, EA_CTL) || mode == 3 ? H_movem : H_illegal;
        case 0xE:
            if (sz == 1) {
                switch ((op >> 3) & 7) {
                case 0: case 1: return H_trap;
                case 2: return H_link;
                case 3: return H_unlk;
                case 4: case 5: return H_move_usp;
                case 6:
                    switch (op & 7) {
                    case 0: return H_reset;
                    case 1: return H_nop;
                    case 2: return H_stop;
                    case 3: return H_rte;
                    case 5: return H_rts;
                    case 6: return H_trapv;
                    case 7: return H_rtr;
                    default: return H_illegal;
                    }
                default: return H_illegal;
                }
            }
            if (sz == 2)
                return ea_ok(op, EA_CTL) ? H_jsr : H_illegal;
            if (sz == 3)
                return ea_ok(op, EA_CTL) ? H_jmp : H_illegal;
            return H_illegal;
        default:
            return H_illegal;
        }
    case 0x5:
        if (sz == 3) {
            if (mode == 1)
                return H_dbcc;
            return ea_ok(op, EA_DA) ? H_scc : H_illegal;
        }
        if (!ea_ok(op, EA_ALT) || (mode == 1 && sz == 0))
            return H_illegal;
        return ((op & 0x100) ? H_subq_b : H_addq_b) + (int)sz;
    case 0x6:
        return H_bcc;
    case 0x7:
        return (op & 0x100) ? H_illegal : H_moveq;
    case 0x8: case 0xC: {
        int and = hi == 0xC;
        if (opm == 3)
            return ea_ok(op, EA_DATA) ? (and ? H_mulu : H_divu) : H_illegal;
        if (opm == 7)
            return ea_ok(op, EA_DATA) ? (and ? H_muls : H_divs) : H_illegal;
        if (opm == 4 && mode < 2)
            return H_abcd_sbcd;
        if (and && (opm == 5 || opm == 6) && mode < 2) {
            u32 k = (op >> 3) & 0x1F;
            return (k == 0x08 || k == 0x09 || k == 0x11) ? H_exg : H_illegal;
        }
        if (opm < 3)
            return ea_ok(op, EA_DATA) ? (and ? H_and_b_dn : H_or_b_dn) + (int)opm : H_illegal;
        return ea_ok(op, EA_MEM) ? (and ? H_and_b_ea : H_or_b_ea) + (int)(opm - 4) : H_illegal;
    }
    case 0x9: case 0xD: {
        int add = hi == 0xD;
        if (opm == 3 || opm == 7)
            return ea_ok(op, EA_ALL) ? (add ? H_adda_w : H_suba_w) + (opm == 7) : H_illegal;
        if (opm < 3) {
            if (!ea_ok(op, EA_ALL) || (opm == 0 && mode == 1))
                return H_illegal;
            return (add ? H_add_b_dn : H_sub_b_dn) + (int)opm;
        }
        if (mode < 2)
            return (add ? H_addx_b : H_subx_b) + (int)(opm - 4);
        return ea_ok(op, EA_MEM) ? (add ? H_add_b_ea : H_sub_b_ea) + (int)(opm - 4) : H_illegal;
    }
    case 0xB:
        if (opm == 3 || opm == 7)
            return ea_ok(op, EA_ALL) ? H_cmpa_w + (opm == 7) : H_illegal;
        if (opm < 3) {
            if (!ea_ok(op, EA_ALL) || (opm == 0 && mode == 1))
                return H_illegal;
            return H_cmp_b + (int)opm;
        }
        if (mode == 1)
            return H_cmpm_b + (int)(opm - 4);
        return ea_ok(op, EA_DA) ? H_eor_b_ea + (int)(opm - 4) : H_illegal;
    case 0xE:
        if (sz == 3) {
            if (op & 0x800)
                return H_illegal;
            return ea_ok(op, EA_MEM) ? H_shift_mem : H_illegal;
        }
        return H_shift_b + (int)sz;
    default:
        return H_illegal;
    }
}

static void cpu_init(void)
{
    for (u32 op = 0; op < 65536; op++)
        optab[op] = (u8)decode(op);
}

static void cpu_reset(void)
{
    for (int i = 0; i < 16; i++)
        m.r[i] = 0;
    m.s = 1, m.t = 0, m.im = 7;
    m.other_sp = 0;
    set_ccr(0);
    m.stopped = 0, m.fault = 0, m.ipl = 0;
#ifdef M68K_BUS_ERROR
    m.bus_err = 0;
#endif
    m.r[15] = rl(0);
    m.pc = rl(4);
    check_pending();
}

/* an interrupt (autovectored: 25..31), a trace, before the next instruction */
static void take_pending(void)
{
    if (m.ipl > m.im) {
        u32 level = m.ipl, sr = get_sr();
        supervisor();
        m.im = level;
        m.r[15] -= 4;
        wl(m.r[15], m.pc);
        m.r[15] -= 2;
        ww(m.r[15], sr);
#ifdef M68K_INT_VEC
        u32 vec = M68K_INT_VEC(level);
#else
        u32 vec = 24 + level;
#endif
        m.pc = rl(vec * 4);
        m.stopped = 0;
        m.clock += 44;
        M68K_IACK(level);
    }
    check_pending();
}

/* the 68000 until `until` cycles of the frame */
static void cpu_run(s32 until)
{
    while (m.clock < until) {
        if (m.pending) {
            if (m.ipl > m.im) {
                take_pending();
                continue;
            }
            if (m.stopped) {
                m.clock = until;
                break;
            }
            m.op = fetch();             /* the trace: an exception after the instruction run with T set */
            handler[optab[m.op]]();
            if (m.fault)
                address_error();
#ifdef M68K_BUS_ERROR
            else if (m.bus_err) {
                bus_error();
                continue;
            }
#endif
            exception(9, m.pc);
            continue;
        }
        if (m.stopped) {
            m.clock = until;
            break;
        }
        m.op = fetch();
        handler[optab[m.op]]();
        if (m.fault)
            address_error();
#ifdef M68K_BUS_ERROR
        else if (m.bus_err)
            bus_error();
#endif
    }
}
