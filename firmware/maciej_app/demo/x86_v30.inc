/* x86_v30.inc: Shared 8086 / 80186 / 80286 / 80386 Real-Mode & NEC V30/V33 CPU engine.
   Zero static .bss (all mutable state lives in `struct x86_cpu`); zero 64-bit libgcc division.
   Used by pc98.c (NEC PC-9801 V30/286/386) and irem.c (Irem M72/M92 NEC V30/V33).

   Before including, define:
     X86_ADDR_MASK          (u32 mask applied to linear addresses, e.g. 0xFFFFFu or a20_mask)
     X86_RB(addr)           -> u8
     X86_WB(addr, val)      -> void
     X86_INB(port)          -> u8
     X86_INW(port)          -> u16
     X86_OUTB(port, val)    -> void
     X86_OUTW(port, val)    -> void
   Optional:
     X86_RW(addr)           -> u16
     X86_WW(addr, val)      -> void
     X86_TRAP(cpu, id)      -> void  (invoked on 3-byte HLE escape `0F FF <id>`) */

#ifndef X86_INLINE
#define X86_INLINE static inline __attribute__((always_inline))
#endif

enum { X86_ES = 0, X86_CS = 1, X86_SS = 2, X86_DS = 3, X86_FS = 4, X86_GS = 5 };

#define X86_F_CF   0x0001u
#define X86_F_PF   0x0004u
#define X86_F_AF   0x0010u
#define X86_F_ZF   0x0040u
#define X86_F_SF   0x0080u
#define X86_F_TF   0x0100u
#define X86_F_IF   0x0200u
#define X86_F_DF   0x0400u
#define X86_F_OF   0x0800u
#define X86_F_IOPL 0x3000u
#define X86_F_NT   0x4000u
#define X86_F_MD   0x8000u

struct x86_cpu {
    union { u32 d; u16 w[2]; u8 b[4]; } reg[8]; /* EAX ECX EDX EBX ESP EBP ESI EDI */
    u16 sr[6];                                  /* ES CS SS DS FS GS */
    u32 base[6];
    u16 ip, op_ip, op_cs;
    u16 flags;
    s32 cycles;
    u8  halted;
    u8  int_inhibit;
    u8  is_v30;
    u8  rep_active;
};

#define X86_R32(cpu, n) ((cpu)->reg[(n) & 7].d)
#define X86_R16(cpu, n) ((cpu)->reg[(n) & 7].w[0])
#define X86_R8(cpu, n)  ((cpu)->reg[(n) & 3].b[((n) >> 2) & 1])

#define X86_EAX(cpu) X86_R32(cpu, 0)
#define X86_ECX(cpu) X86_R32(cpu, 1)
#define X86_EDX(cpu) X86_R32(cpu, 2)
#define X86_EBX(cpu) X86_R32(cpu, 3)
#define X86_ESP(cpu) X86_R32(cpu, 4)
#define X86_EBP(cpu) X86_R32(cpu, 5)
#define X86_ESI(cpu) X86_R32(cpu, 6)
#define X86_EDI(cpu) X86_R32(cpu, 7)

#define X86_AX(cpu)  X86_R16(cpu, 0)
#define X86_CX(cpu)  X86_R16(cpu, 1)
#define X86_DX(cpu)  X86_R16(cpu, 2)
#define X86_BX(cpu)  X86_R16(cpu, 3)
#define X86_SP(cpu)  X86_R16(cpu, 4)
#define X86_BP(cpu)  X86_R16(cpu, 5)
#define X86_SI(cpu)  X86_R16(cpu, 6)
#define X86_DI(cpu)  X86_R16(cpu, 7)

#define X86_AL(cpu)  X86_R8(cpu, 0)
#define X86_CL(cpu)  X86_R8(cpu, 1)
#define X86_DL(cpu)  X86_R8(cpu, 2)
#define X86_BL(cpu)  X86_R8(cpu, 3)
#define X86_AH(cpu)  X86_R8(cpu, 4)
#define X86_CH(cpu)  X86_R8(cpu, 5)
#define X86_DH(cpu)  X86_R8(cpu, 6)
#define X86_BH(cpu)  X86_R8(cpu, 7)

static const u8 x86_parity_tab[256] = {
    4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4, 0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0,
    0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0, 4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4,
    0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0, 4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4,
    4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4, 0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0,
    0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0, 4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4,
    4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4, 0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0,
    4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4, 0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0,
    0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0, 4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4
};

#ifndef X86_RW
X86_INLINE u16 x86_def_rw(u32 a)
{
    return (u16)X86_RB(a & X86_ADDR_MASK) | ((u16)X86_RB((a + 1u) & X86_ADDR_MASK) << 8);
}
#define X86_RW(a) x86_def_rw(a)
#endif

#ifndef X86_WW
X86_INLINE void x86_def_ww(u32 a, u16 v)
{
    X86_WB(a & X86_ADDR_MASK, (u8)v);
    X86_WB((a + 1u) & X86_ADDR_MASK, (u8)(v >> 8));
}
#define X86_WW(a, v) x86_def_ww(a, v)
#endif

#ifndef X86_TRAP
#define X86_TRAP(cpu, id) ((void)(cpu), (void)(id))
#endif

X86_INLINE u32 x86_rd32(u32 a)
{
    return (u32)X86_RW(a) | ((u32)X86_RW(a + 2u) << 16);
}

X86_INLINE void x86_wr32(u32 a, u32 v)
{
    X86_WW(a, (u16)v);
    X86_WW(a + 2u, (u16)(v >> 16));
}

X86_INLINE u8 x86_seg_rb(const struct x86_cpu *cpu, int s, u16 off)
{
    u32 la = (cpu->base[s] + (u32)off) & X86_ADDR_MASK;
#ifdef X86_FAST_RAM
    if (__builtin_expect(la < X86_FAST_LIM, 1))
        return X86_FAST_RAM[la];
#endif
    return X86_RB(la);
}

X86_INLINE u16 x86_seg_rw(const struct x86_cpu *cpu, int s, u16 off)
{
    u32 b = cpu->base[s];
    if (__builtin_expect(off != 0xFFFFu, 1)) {
        u32 la = (b + (u32)off) & X86_ADDR_MASK;
#ifdef X86_FAST_RAM
        if (__builtin_expect(la + 1u < X86_FAST_LIM, 1))
            return (u16)X86_FAST_RAM[la] | ((u16)X86_FAST_RAM[la + 1u] << 8);
#endif
        return X86_RW(la);
    }
    return (u16)X86_RB((b + 0xFFFFu) & X86_ADDR_MASK) | ((u16)X86_RB(b & X86_ADDR_MASK) << 8);
}

X86_INLINE u32 x86_seg_rd(const struct x86_cpu *cpu, int s, u16 off)
{
    return (u32)x86_seg_rw(cpu, s, off) | ((u32)x86_seg_rw(cpu, s, (u16)(off + 2u)) << 16);
}

X86_INLINE void x86_seg_wb(const struct x86_cpu *cpu, int s, u16 off, u8 v)
{
    u32 la = (cpu->base[s] + (u32)off) & X86_ADDR_MASK;
#ifdef X86_FAST_RAM
    if (__builtin_expect(la < X86_FAST_LIM, 1)) {
        X86_FAST_RAM[la] = v;
        return;
    }
#endif
    X86_WB(la, v);
}

X86_INLINE void x86_seg_ww(const struct x86_cpu *cpu, int s, u16 off, u16 v)
{
    u32 b = cpu->base[s];
    if (__builtin_expect(off != 0xFFFFu, 1)) {
        u32 la = (b + (u32)off) & X86_ADDR_MASK;
#ifdef X86_FAST_RAM
        if (__builtin_expect(la + 1u < X86_FAST_LIM, 1)) {
            X86_FAST_RAM[la] = (u8)v;
            X86_FAST_RAM[la + 1u] = (u8)(v >> 8);
            return;
        }
#endif
        X86_WW(la, v);
    } else {
        X86_WB((b + 0xFFFFu) & X86_ADDR_MASK, (u8)v);
        X86_WB(b & X86_ADDR_MASK, (u8)(v >> 8));
    }
}

X86_INLINE void x86_seg_wd(const struct x86_cpu *cpu, int s, u16 off, u32 v)
{
    x86_seg_ww(cpu, s, off, (u16)v);
    x86_seg_ww(cpu, s, (u16)(off + 2u), (u16)(v >> 16));
}

X86_INLINE void x86_set_sr(struct x86_cpu *cpu, int s, u16 v)
{
    cpu->sr[s] = v;
    cpu->base[s] = (u32)v << 4;
}

X86_INLINE u8 x86_fetch8(struct x86_cpu *cpu)
{
    u32 la = (cpu->base[X86_CS] + (u32)cpu->ip) & X86_ADDR_MASK;
    cpu->ip++;
#ifdef X86_FAST_RAM
    if (__builtin_expect(la < X86_FAST_LIM, 1))
        return X86_FAST_RAM[la];
#endif
    return X86_RB(la);
}

X86_INLINE u16 x86_fetch16(struct x86_cpu *cpu)
{
    u16 lo = x86_fetch8(cpu);
    u16 hi = x86_fetch8(cpu);
    return (u16)(lo | (hi << 8));
}

X86_INLINE u32 x86_fetch32(struct x86_cpu *cpu)
{
    u32 lo = x86_fetch16(cpu);
    u32 hi = x86_fetch16(cpu);
    return lo | (hi << 16);
}

X86_INLINE void x86_push16(struct x86_cpu *cpu, u16 v)
{
    u16 sp = (u16)(X86_SP(cpu) - 2u);
    X86_SP(cpu) = sp;
    x86_seg_ww(cpu, X86_SS, sp, v);
}

X86_INLINE u16 x86_pop16(struct x86_cpu *cpu)
{
    u16 sp = X86_SP(cpu);
    u16 v = x86_seg_rw(cpu, X86_SS, sp);
    X86_SP(cpu) = (u16)(sp + 2u);
    return v;
}

X86_INLINE void x86_push32(struct x86_cpu *cpu, u32 v)
{
    u16 sp = (u16)(X86_SP(cpu) - 4u);
    X86_SP(cpu) = sp;
    x86_seg_wd(cpu, X86_SS, sp, v);
}

X86_INLINE u32 x86_pop32(struct x86_cpu *cpu)
{
    u16 sp = X86_SP(cpu);
    u32 v = x86_seg_rd(cpu, X86_SS, sp);
    X86_SP(cpu) = (u16)(sp + 4u);
    return v;
}

static void x86_reset(struct x86_cpu *cpu, int is_v30)
{
    for (int i = 0; i < 8; i++)
        cpu->reg[i].d = 0;
    for (int i = 0; i < 6; i++)
        x86_set_sr(cpu, i, 0);
    x86_set_sr(cpu, X86_CS, 0xFFFFu);
    cpu->ip = 0x0000u;
    cpu->op_ip = 0;
    cpu->op_cs = 0xFFFFu;
    cpu->is_v30 = (u8)is_v30;
    cpu->flags = is_v30 ? 0x8002u : 0x0002u;
    cpu->cycles = 0;
    cpu->halted = 0;
    cpu->int_inhibit = 0;
    cpu->rep_active = 0;
}

static void x86_interrupt(struct x86_cpu *cpu, u8 vec)
{
    cpu->halted = 0;
    u16 fl = (u16)(cpu->flags | 0x0002u);
    if (cpu->is_v30)
        fl |= 0xF000u;
    x86_push16(cpu, fl);
    cpu->flags = (u16)(cpu->flags & ~(X86_F_IF | X86_F_TF));
    x86_push16(cpu, cpu->sr[X86_CS]);
    x86_push16(cpu, cpu->ip);
    u32 va = (u32)vec * 4u;
    u16 nip = X86_RW(va);
    u16 ncs = X86_RW(va + 2u);
    x86_set_sr(cpu, X86_CS, ncs);
    cpu->ip = nip;
    cpu->cycles += 28;
}

static inline int x86_irq(struct x86_cpu *cpu, u8 vec)
{
    if ((cpu->flags & X86_F_IF) && !cpu->int_inhibit) {
        x86_interrupt(cpu, vec);
        return 1;
    }
    return 0;
}

/* 64/32 unsigned division without libgcc __udivdi3 (returns 1 on overflow/div0, 0 on success) */
static int x86_u64_div32(u32 hi, u32 lo, u32 d, u32 *q_out, u32 *r_out)
{
    if (d == 0 || hi >= d)
        return 1;
    for (int i = 0; i < 32; i++) {
        u32 c = hi >> 31;
        hi = (hi << 1) | (lo >> 31);
        lo <<= 1;
        if (c || hi >= d) {
            hi -= d;
            lo |= 1u;
        }
    }
    *q_out = lo;
    *r_out = hi;
    return 0;
}

X86_INLINE void x86_set_szp8(struct x86_cpu *cpu, u8 r)
{
    u16 f = (u16)(cpu->flags & ~(X86_F_ZF | X86_F_SF | X86_F_PF));
    if (r == 0) f |= X86_F_ZF;
    if (r & 0x80u) f |= X86_F_SF;
    f |= x86_parity_tab[r];
    cpu->flags = f;
}

X86_INLINE void x86_set_szp16(struct x86_cpu *cpu, u16 r)
{
    u16 f = (u16)(cpu->flags & ~(X86_F_ZF | X86_F_SF | X86_F_PF));
    if (r == 0) f |= X86_F_ZF;
    if (r & 0x8000u) f |= X86_F_SF;
    f |= x86_parity_tab[r & 0xFFu];
    cpu->flags = f;
}

X86_INLINE void x86_set_szp32(struct x86_cpu *cpu, u32 r)
{
    u16 f = (u16)(cpu->flags & ~(X86_F_ZF | X86_F_SF | X86_F_PF));
    if (r == 0) f |= X86_F_ZF;
    if (r & 0x80000000u) f |= X86_F_SF;
    f |= x86_parity_tab[r & 0xFFu];
    cpu->flags = f;
}

static u8 x86_alu8(struct x86_cpu *cpu, int op, u8 a, u8 b)
{
    u32 cf = (cpu->flags & X86_F_CF) ? 1u : 0u;
    u32 res;
    u16 f = (u16)(cpu->flags & ~(X86_F_CF | X86_F_PF | X86_F_AF | X86_F_ZF | X86_F_SF | X86_F_OF));
    switch (op & 7) {
    case 0: /* ADD */
        res = (u32)a + (u32)b;
        if (res & 0x100u) f |= X86_F_CF;
        if (((a ^ b ^ res) & 0x10u)) f |= X86_F_AF;
        if (((~(a ^ b) & (a ^ res)) & 0x80u)) f |= X86_F_OF;
        break;
    case 1: res = (u32)(a | b); break;
    case 2: /* ADC */
        res = (u32)a + (u32)b + cf;
        if (res & 0x100u) f |= X86_F_CF;
        if (((a ^ b ^ res) & 0x10u)) f |= X86_F_AF;
        if (((~(a ^ b) & (a ^ res)) & 0x80u)) f |= X86_F_OF;
        break;
    case 3: /* SBB */
        res = (u32)a - (u32)b - cf;
        if (res & 0x100u) f |= X86_F_CF;
        if (((a ^ b ^ res) & 0x10u)) f |= X86_F_AF;
        if ((((a ^ b) & (a ^ res)) & 0x80u)) f |= X86_F_OF;
        break;
    case 4: res = (u32)(a & b); break;
    case 5: /* SUB */
    case 7: /* CMP */
        res = (u32)a - (u32)b;
        if (res & 0x100u) f |= X86_F_CF;
        if (((a ^ b ^ res) & 0x10u)) f |= X86_F_AF;
        if ((((a ^ b) & (a ^ res)) & 0x80u)) f |= X86_F_OF;
        break;
    default: res = (u32)(a ^ b); break;
    }
    u8 r8 = (u8)res;
    if (r8 == 0) f |= X86_F_ZF;
    if (r8 & 0x80u) f |= X86_F_SF;
    f |= x86_parity_tab[r8];
    cpu->flags = f;
    return ((op & 7) == 7) ? a : r8;
}

static u16 x86_alu16(struct x86_cpu *cpu, int op, u16 a, u16 b)
{
    u32 cf = (cpu->flags & X86_F_CF) ? 1u : 0u;
    u32 res;
    u16 f = (u16)(cpu->flags & ~(X86_F_CF | X86_F_PF | X86_F_AF | X86_F_ZF | X86_F_SF | X86_F_OF));
    switch (op & 7) {
    case 0:
        res = (u32)a + (u32)b;
        if (res & 0x10000u) f |= X86_F_CF;
        if (((a ^ b ^ res) & 0x10u)) f |= X86_F_AF;
        if (((~(a ^ b) & (a ^ res)) & 0x8000u)) f |= X86_F_OF;
        break;
    case 1: res = (u32)(a | b); break;
    case 2:
        res = (u32)a + (u32)b + cf;
        if (res & 0x10000u) f |= X86_F_CF;
        if (((a ^ b ^ res) & 0x10u)) f |= X86_F_AF;
        if (((~(a ^ b) & (a ^ res)) & 0x8000u)) f |= X86_F_OF;
        break;
    case 3:
        res = (u32)a - (u32)b - cf;
        if (res & 0x10000u) f |= X86_F_CF;
        if (((a ^ b ^ res) & 0x10u)) f |= X86_F_AF;
        if ((((a ^ b) & (a ^ res)) & 0x8000u)) f |= X86_F_OF;
        break;
    case 4: res = (u32)(a & b); break;
    case 5:
    case 7:
        res = (u32)a - (u32)b;
        if (res & 0x10000u) f |= X86_F_CF;
        if (((a ^ b ^ res) & 0x10u)) f |= X86_F_AF;
        if ((((a ^ b) & (a ^ res)) & 0x8000u)) f |= X86_F_OF;
        break;
    default: res = (u32)(a ^ b); break;
    }
    u16 r16 = (u16)res;
    if (r16 == 0) f |= X86_F_ZF;
    if (r16 & 0x8000u) f |= X86_F_SF;
    f |= x86_parity_tab[r16 & 0xFFu];
    cpu->flags = f;
    return ((op & 7) == 7) ? a : r16;
}

static u32 x86_alu32(struct x86_cpu *cpu, int op, u32 a, u32 b)
{
    u32 cf = (cpu->flags & X86_F_CF) ? 1u : 0u;
    u32 res;
    u16 f = (u16)(cpu->flags & ~(X86_F_CF | X86_F_PF | X86_F_AF | X86_F_ZF | X86_F_SF | X86_F_OF));
    switch (op & 7) {
    case 0:
        res = a + b;
        if (res < a) f |= X86_F_CF;
        if (((a ^ b ^ res) & 0x10u)) f |= X86_F_AF;
        if (((~(a ^ b) & (a ^ res)) & 0x80000000u)) f |= X86_F_OF;
        break;
    case 1: res = a | b; break;
    case 2:
        res = a + b + cf;
        if (cf ? (res <= a) : (res < a)) f |= X86_F_CF;
        if (((a ^ b ^ res) & 0x10u)) f |= X86_F_AF;
        if (((~(a ^ b) & (a ^ res)) & 0x80000000u)) f |= X86_F_OF;
        break;
    case 3:
        res = a - b - cf;
        if (cf ? (a <= b) : (a < b)) f |= X86_F_CF;
        if (((a ^ b ^ res) & 0x10u)) f |= X86_F_AF;
        if ((((a ^ b) & (a ^ res)) & 0x80000000u)) f |= X86_F_OF;
        break;
    case 4: res = a & b; break;
    case 5:
    case 7:
        res = a - b;
        if (a < b) f |= X86_F_CF;
        if (((a ^ b ^ res) & 0x10u)) f |= X86_F_AF;
        if ((((a ^ b) & (a ^ res)) & 0x80000000u)) f |= X86_F_OF;
        break;
    default: res = a ^ b; break;
    }
    if (res == 0) f |= X86_F_ZF;
    if (res & 0x80000000u) f |= X86_F_SF;
    f |= x86_parity_tab[res & 0xFFu];
    cpu->flags = f;
    return ((op & 7) == 7) ? a : res;
}

static u8 x86_shift8(struct x86_cpu *cpu, int op, u8 v, u8 cnt)
{
    cnt &= 31u;
    if (!cnt)
        return v;
    u16 f = cpu->flags;
    u32 c = (f & X86_F_CF) ? 1u : 0u;
    switch (op & 7) {
    case 0: /* ROL */
        cnt &= 7u;
        if (cnt) { v = (u8)((v << cnt) | (v >> (8u - cnt))); c = v & 1u; }
        f = (u16)((f & ~(X86_F_CF | X86_F_OF)) | (c ? X86_F_CF : 0) | ((((v >> 7) ^ c) & 1u) ? X86_F_OF : 0));
        cpu->flags = f;
        return v;
    case 1: /* ROR */
        cnt &= 7u;
        if (cnt) { v = (u8)((v >> cnt) | (v << (8u - cnt))); c = (v >> 7) & 1u; }
        f = (u16)((f & ~(X86_F_CF | X86_F_OF)) | (c ? X86_F_CF : 0) | ((((v >> 7) ^ (v >> 6)) & 1u) ? X86_F_OF : 0));
        cpu->flags = f;
        return v;
    case 2: /* RCL */
        cnt %= 9u;
        for (u8 i = 0; i < cnt; i++) { u32 nc = (v >> 7) & 1u; v = (u8)((v << 1) | c); c = nc; }
        f = (u16)((f & ~(X86_F_CF | X86_F_OF)) | (c ? X86_F_CF : 0) | ((((v >> 7) ^ c) & 1u) ? X86_F_OF : 0));
        cpu->flags = f;
        return v;
    case 3: /* RCR */
        cnt %= 9u;
        for (u8 i = 0; i < cnt; i++) { u32 nc = v & 1u; v = (u8)((v >> 1) | (c << 7)); c = nc; }
        f = (u16)((f & ~(X86_F_CF | X86_F_OF)) | (c ? X86_F_CF : 0) | ((((v >> 7) ^ (v >> 6)) & 1u) ? X86_F_OF : 0));
        cpu->flags = f;
        return v;
    case 4:
    case 6: /* SHL / SAL */
        if (cnt > 8u) { c = 0; v = 0; }
        else { c = (v >> (8u - cnt)) & 1u; v = (u8)(v << cnt); }
        cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF | X86_F_AF)) | (c ? X86_F_CF : 0) | ((((v >> 7) ^ c) & 1u) ? X86_F_OF : 0));
        x86_set_szp8(cpu, v);
        return v;
    case 5: /* SHR */
        {
            u8 orig = v;
            if (cnt > 8u) { c = 0; v = 0; }
            else { c = (v >> (cnt - 1u)) & 1u; v = (u8)(v >> cnt); }
            cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF | X86_F_AF)) | (c ? X86_F_CF : 0) | ((cnt == 1u && (orig & 0x80u)) ? X86_F_OF : 0));
            x86_set_szp8(cpu, v);
            return v;
        }
    default: /* SAR */
        if (cnt >= 8u) { c = (v >> 7) & 1u; v = c ? 0xFFu : 0x00u; }
        else { c = (v >> (cnt - 1u)) & 1u; v = (u8)((s8)v >> cnt); }
        cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF | X86_F_AF)) | (c ? X86_F_CF : 0));
        x86_set_szp8(cpu, v);
        return v;
    }
}

static u16 x86_shift16(struct x86_cpu *cpu, int op, u16 v, u8 cnt)
{
    cnt &= 31u;
    if (!cnt)
        return v;
    u16 f = cpu->flags;
    u32 c = (f & X86_F_CF) ? 1u : 0u;
    switch (op & 7) {
    case 0:
        cnt &= 15u;
        if (cnt) { v = (u16)((v << cnt) | (v >> (16u - cnt))); c = v & 1u; }
        cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF)) | (c ? X86_F_CF : 0) | ((((v >> 15) ^ c) & 1u) ? X86_F_OF : 0));
        return v;
    case 1:
        cnt &= 15u;
        if (cnt) { v = (u16)((v >> cnt) | (v << (16u - cnt))); c = (v >> 15) & 1u; }
        cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF)) | (c ? X86_F_CF : 0) | ((((v >> 15) ^ (v >> 14)) & 1u) ? X86_F_OF : 0));
        return v;
    case 2:
        cnt %= 17u;
        for (u8 i = 0; i < cnt; i++) { u32 nc = (v >> 15) & 1u; v = (u16)((v << 1) | c); c = nc; }
        cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF)) | (c ? X86_F_CF : 0) | ((((v >> 15) ^ c) & 1u) ? X86_F_OF : 0));
        return v;
    case 3:
        cnt %= 17u;
        for (u8 i = 0; i < cnt; i++) { u32 nc = v & 1u; v = (u16)((v >> 1) | (c << 15)); c = nc; }
        cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF)) | (c ? X86_F_CF : 0) | ((((v >> 15) ^ (v >> 14)) & 1u) ? X86_F_OF : 0));
        return v;
    case 4:
    case 6:
        if (cnt > 16u) { c = 0; v = 0; }
        else { c = (v >> (16u - cnt)) & 1u; v = (u16)(v << cnt); }
        cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF | X86_F_AF)) | (c ? X86_F_CF : 0) | ((((v >> 15) ^ c) & 1u) ? X86_F_OF : 0));
        x86_set_szp16(cpu, v);
        return v;
    case 5:
        {
            u16 orig = v;
            if (cnt > 16u) { c = 0; v = 0; }
            else { c = (v >> (cnt - 1u)) & 1u; v = (u16)(v >> cnt); }
            cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF | X86_F_AF)) | (c ? X86_F_CF : 0) | ((cnt == 1u && (orig & 0x8000u)) ? X86_F_OF : 0));
            x86_set_szp16(cpu, v);
            return v;
        }
    default:
        if (cnt >= 16u) { c = (v >> 15) & 1u; v = c ? 0xFFFFu : 0x0000u; }
        else { c = (v >> (cnt - 1u)) & 1u; v = (u16)((s16)v >> cnt); }
        cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF | X86_F_AF)) | (c ? X86_F_CF : 0));
        x86_set_szp16(cpu, v);
        return v;
    }
}

static u32 x86_shift32(struct x86_cpu *cpu, int op, u32 v, u8 cnt)
{
    cnt &= 31u;
    if (!cnt)
        return v;
    u16 f = cpu->flags;
    u32 c = (f & X86_F_CF) ? 1u : 0u;
    switch (op & 7) {
    case 0:
        v = (v << cnt) | (v >> (32u - cnt));
        c = v & 1u;
        cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF)) | (c ? X86_F_CF : 0) | ((((v >> 31) ^ c) & 1u) ? X86_F_OF : 0));
        return v;
    case 1:
        v = (v >> cnt) | (v << (32u - cnt));
        c = (v >> 31) & 1u;
        cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF)) | (c ? X86_F_CF : 0) | ((((v >> 31) ^ (v >> 30)) & 1u) ? X86_F_OF : 0));
        return v;
    case 2:
        for (u8 i = 0; i < cnt; i++) { u32 nc = v >> 31; v = (v << 1) | c; c = nc; }
        cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF)) | (c ? X86_F_CF : 0) | ((((v >> 31) ^ c) & 1u) ? X86_F_OF : 0));
        return v;
    case 3:
        for (u8 i = 0; i < cnt; i++) { u32 nc = v & 1u; v = (v >> 1) | (c << 31); c = nc; }
        cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF)) | (c ? X86_F_CF : 0) | ((((v >> 31) ^ (v >> 30)) & 1u) ? X86_F_OF : 0));
        return v;
    case 4:
    case 6:
        c = (v >> (32u - cnt)) & 1u;
        v <<= cnt;
        cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF | X86_F_AF)) | (c ? X86_F_CF : 0) | ((((v >> 31) ^ c) & 1u) ? X86_F_OF : 0));
        x86_set_szp32(cpu, v);
        return v;
    case 5:
        {
            u32 orig = v;
            c = (v >> (cnt - 1u)) & 1u;
            v >>= cnt;
            cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF | X86_F_AF)) | (c ? X86_F_CF : 0) | ((cnt == 1u && (orig & 0x80000000u)) ? X86_F_OF : 0));
            x86_set_szp32(cpu, v);
            return v;
        }
    default:
        c = (v >> (cnt - 1u)) & 1u;
        v = (u32)((s32)v >> cnt);
        cpu->flags = (u16)((f & ~(X86_F_CF | X86_F_OF | X86_F_AF)) | (c ? X86_F_CF : 0));
        x86_set_szp32(cpu, v);
        return v;
    }
}

X86_INLINE int x86_cond(const struct x86_cpu *cpu, u8 cc)
{
    u16 f = cpu->flags;
    int r;
    switch ((cc >> 1) & 7) {
    case 0: r = (f & X86_F_OF) != 0; break;
    case 1: r = (f & X86_F_CF) != 0; break;
    case 2: r = (f & X86_F_ZF) != 0; break;
    case 3: r = (f & (X86_F_CF | X86_F_ZF)) != 0; break;
    case 4: r = (f & X86_F_SF) != 0; break;
    case 5: r = (f & X86_F_PF) != 0; break;
    case 6: r = ((f & X86_F_SF) != 0) != ((f & X86_F_OF) != 0); break;
    default: r = ((f & X86_F_ZF) != 0) || (((f & X86_F_SF) != 0) != ((f & X86_F_OF) != 0)); break;
    }
    return (cc & 1u) ? !r : r;
}

/* Decode 16-bit or 32-bit ModR/M effective address */
static void x86_ea_decode(struct x86_cpu *cpu, u8 modrm, int ad32, int sego, int *seg_out, u16 *off_out)
{
    int mod = modrm >> 6;
    int rm  = modrm & 7;
    int def_seg = X86_DS;
    u32 off = 0;

    if (!ad32) {
        switch (rm) {
        case 0: off = (u16)(X86_BX(cpu) + X86_SI(cpu)); break;
        case 1: off = (u16)(X86_BX(cpu) + X86_DI(cpu)); break;
        case 2: off = (u16)(X86_BP(cpu) + X86_SI(cpu)); def_seg = X86_SS; break;
        case 3: off = (u16)(X86_BP(cpu) + X86_DI(cpu)); def_seg = X86_SS; break;
        case 4: off = X86_SI(cpu); break;
        case 5: off = X86_DI(cpu); break;
        case 6:
            if (mod == 0) { off = x86_fetch16(cpu); }
            else          { off = X86_BP(cpu); def_seg = X86_SS; }
            break;
        default: off = X86_BX(cpu); break;
        }
        if (mod == 1)
            off = (u16)(off + (s16)(s8)x86_fetch8(cpu));
        else if (mod == 2)
            off = (u16)(off + x86_fetch16(cpu));
    } else {
        if (rm == 4) {
            u8 sib = x86_fetch8(cpu);
            int scale = sib >> 6;
            int idx   = (sib >> 3) & 7;
            int base  = sib & 7;
            u32 bval = 0;
            if (base == 5 && mod == 0) {
                bval = x86_fetch32(cpu);
            } else {
                bval = X86_R32(cpu, base);
                if (base == 4 || base == 5)
                    def_seg = X86_SS;
            }
            u32 ival = (idx == 4) ? 0u : (X86_R32(cpu, idx) << scale);
            off = bval + ival;
        } else if (rm == 5 && mod == 0) {
            off = x86_fetch32(cpu);
        } else {
            off = X86_R32(cpu, rm);
            if (rm == 5)
                def_seg = X86_SS;
        }
        if (mod == 1)
            off += (u32)(s32)(s8)x86_fetch8(cpu);
        else if (mod == 2)
            off += x86_fetch32(cpu);
    }

    *seg_out = (sego >= 0) ? sego : def_seg;
    *off_out = (u16)off;
}

static void x86_run(struct x86_cpu *cpu, s32 target_cycles)
{
    while (cpu->cycles < target_cycles) {
        if (cpu->halted) {
            cpu->cycles = target_cycles;
            return;
        }
        u8 prev_inhibit = cpu->int_inhibit;
        cpu->int_inhibit = 0;
        cpu->op_ip = cpu->ip;
        cpu->op_cs = cpu->sr[X86_CS];

        int sego = -1;
        int op32 = 0, ad32 = 0;
        int rep = 0; /* 0=none, 1=REPNZ(F2), 2=REP/REPZ(F3) */
        u8 op;

        for (;;) {
            op = x86_fetch8(cpu);
            if (op == 0x26u) { sego = X86_ES; continue; }
            if (op == 0x2Eu) { sego = X86_CS; continue; }
            if (op == 0x36u) { sego = X86_SS; continue; }
            if (op == 0x3Eu) { sego = X86_DS; continue; }
            if (op == 0x64u && !cpu->is_v30) { sego = X86_FS; continue; }
            if (op == 0x65u && !cpu->is_v30) { sego = X86_GS; continue; }
            if (op == 0x66u && !cpu->is_v30) { op32 ^= 1; continue; }
            if (op == 0x67u && !cpu->is_v30) { ad32 ^= 1; continue; }
            if (op == 0xF0u) { continue; } /* LOCK */
            if (op == 0xF2u) { rep = 1; continue; }
            if (op == 0xF3u) { rep = 2; continue; }
            break;
        }

        cpu->cycles += 4;

        /* Standard ALU 0x00..0x3D (`ADD, OR, ADC, SBB, AND, SUB, XOR, CMP`) */
        if (op < 0x40u && (op & 7u) < 6u) {
            int alu = (op >> 3) & 7;
            switch (op & 7u) {
            case 0: { /* r/m8, r8 */
                u8 m = x86_fetch8(cpu);
                u8 b = X86_R8(cpu, (m >> 3) & 7);
                if ((m >> 6) == 3) {
                    u8 r = x86_alu8(cpu, alu, X86_R8(cpu, m & 7), b);
                    if (alu != 7) X86_R8(cpu, m & 7) = r;
                } else {
                    int s; u16 o;
                    x86_ea_decode(cpu, m, ad32, sego, &s, &o);
                    u8 r = x86_alu8(cpu, alu, x86_seg_rb(cpu, s, o), b);
                    if (alu != 7) x86_seg_wb(cpu, s, o, r);
                    cpu->cycles += 6;
                }
                break;
            }
            case 1: { /* r/m16/32, r16/32 */
                u8 m = x86_fetch8(cpu);
                if (!op32) {
                    u16 b = X86_R16(cpu, (m >> 3) & 7);
                    if ((m >> 6) == 3) {
                        u16 r = x86_alu16(cpu, alu, X86_R16(cpu, m & 7), b);
                        if (alu != 7) X86_R16(cpu, m & 7) = r;
                    } else {
                        int s; u16 o;
                        x86_ea_decode(cpu, m, ad32, sego, &s, &o);
                        u16 r = x86_alu16(cpu, alu, x86_seg_rw(cpu, s, o), b);
                        if (alu != 7) x86_seg_ww(cpu, s, o, r);
                        cpu->cycles += 6;
                    }
                } else {
                    u32 b = X86_R32(cpu, (m >> 3) & 7);
                    if ((m >> 6) == 3) {
                        u32 r = x86_alu32(cpu, alu, X86_R32(cpu, m & 7), b);
                        if (alu != 7) X86_R32(cpu, m & 7) = r;
                    } else {
                        int s; u16 o;
                        x86_ea_decode(cpu, m, ad32, sego, &s, &o);
                        u32 r = x86_alu32(cpu, alu, x86_seg_rd(cpu, s, o), b);
                        if (alu != 7) x86_seg_wd(cpu, s, o, r);
                        cpu->cycles += 6;
                    }
                }
                break;
            }
            case 2: { /* r8, r/m8 */
                u8 m = x86_fetch8(cpu);
                int reg = (m >> 3) & 7;
                u8 b;
                if ((m >> 6) == 3) b = X86_R8(cpu, m & 7);
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); b = x86_seg_rb(cpu, s, o); cpu->cycles += 4; }
                u8 r = x86_alu8(cpu, alu, X86_R8(cpu, reg), b);
                if (alu != 7) X86_R8(cpu, reg) = r;
                break;
            }
            case 3: { /* r16/32, r/m16/32 */
                u8 m = x86_fetch8(cpu);
                int reg = (m >> 3) & 7;
                if (!op32) {
                    u16 b;
                    if ((m >> 6) == 3) b = X86_R16(cpu, m & 7);
                    else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); b = x86_seg_rw(cpu, s, o); cpu->cycles += 4; }
                    u16 r = x86_alu16(cpu, alu, X86_R16(cpu, reg), b);
                    if (alu != 7) X86_R16(cpu, reg) = r;
                } else {
                    u32 b;
                    if ((m >> 6) == 3) b = X86_R32(cpu, m & 7);
                    else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); b = x86_seg_rd(cpu, s, o); cpu->cycles += 4; }
                    u32 r = x86_alu32(cpu, alu, X86_R32(cpu, reg), b);
                    if (alu != 7) X86_R32(cpu, reg) = r;
                }
                break;
            }
            case 4: { /* AL, imm8 */
                u8 b = x86_fetch8(cpu);
                u8 r = x86_alu8(cpu, alu, X86_AL(cpu), b);
                if (alu != 7) X86_AL(cpu) = r;
                break;
            }
            case 5: { /* AX/EAX, imm16/32 */
                if (!op32) {
                    u16 b = x86_fetch16(cpu);
                    u16 r = x86_alu16(cpu, alu, X86_AX(cpu), b);
                    if (alu != 7) X86_AX(cpu) = r;
                } else {
                    u32 b = x86_fetch32(cpu);
                    u32 r = x86_alu32(cpu, alu, X86_EAX(cpu), b);
                    if (alu != 7) X86_EAX(cpu) = r;
                }
                break;
            }
            }
            continue;
        }

        switch (op) {
        case 0x06: x86_push16(cpu, cpu->sr[X86_ES]); break;
        case 0x07: x86_set_sr(cpu, X86_ES, x86_pop16(cpu)); break;
        case 0x0E: x86_push16(cpu, cpu->sr[X86_CS]); break;
        case 0x16: x86_push16(cpu, cpu->sr[X86_SS]); break;
        case 0x17: x86_set_sr(cpu, X86_SS, x86_pop16(cpu)); cpu->int_inhibit = 1; break;
        case 0x1E: x86_push16(cpu, cpu->sr[X86_DS]); break;
        case 0x1F: x86_set_sr(cpu, X86_DS, x86_pop16(cpu)); break;

        case 0x27: { /* DAA */
            u8 al = X86_AL(cpu);
            u16 f = cpu->flags;
            u8 old_al = al;
            int cf = (f & X86_F_CF) != 0;
            if ((al & 0x0Fu) > 9u || (f & X86_F_AF)) {
                al = (u8)(al + 6u);
                f |= X86_F_AF;
                if (old_al > 0xF9u) cf = 1;
            } else {
                f &= ~X86_F_AF;
            }
            if (old_al > 0x99u || cf) {
                al = (u8)(al + 0x60u);
                f |= X86_F_CF;
            } else {
                f &= ~X86_F_CF;
            }
            X86_AL(cpu) = al;
            cpu->flags = f;
            x86_set_szp8(cpu, al);
            break;
        }
        case 0x2F: { /* DAS */
            u8 al = X86_AL(cpu);
            u16 f = cpu->flags;
            u8 old_al = al;
            int cf = (f & X86_F_CF) != 0;
            if ((al & 0x0Fu) > 9u || (f & X86_F_AF)) {
                if (al < 6u) cf = 1;
                al = (u8)(al - 6u);
                f |= X86_F_AF;
            } else {
                f &= ~X86_F_AF;
            }
            if (old_al > 0x99u || cf) {
                al = (u8)(al - 0x60u);
                f |= X86_F_CF;
            } else {
                f &= ~X86_F_CF;
            }
            X86_AL(cpu) = al;
            cpu->flags = f;
            x86_set_szp8(cpu, al);
            break;
        }
        case 0x37: { /* AAA */
            if ((X86_AL(cpu) & 0x0Fu) > 9u || (cpu->flags & X86_F_AF)) {
                X86_AX(cpu) = (u16)(X86_AX(cpu) + 0x0106u);
                cpu->flags |= (X86_F_AF | X86_F_CF);
            } else {
                cpu->flags &= ~(X86_F_AF | X86_F_CF);
            }
            X86_AL(cpu) &= 0x0Fu;
            break;
        }
        case 0x3F: { /* AAS */
            if ((X86_AL(cpu) & 0x0Fu) > 9u || (cpu->flags & X86_F_AF)) {
                X86_AX(cpu) = (u16)(X86_AX(cpu) - 6u);
                X86_AH(cpu)--;
                cpu->flags |= (X86_F_AF | X86_F_CF);
            } else {
                cpu->flags &= ~(X86_F_AF | X86_F_CF);
            }
            X86_AL(cpu) &= 0x0Fu;
            break;
        }

        /* 0x40..0x47 INC reg16/32, 0x48..0x4F DEC reg16/32 */
        case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47: {
            u16 cf = cpu->flags & X86_F_CF;
            if (!op32) X86_R16(cpu, op & 7) = x86_alu16(cpu, 0, X86_R16(cpu, op & 7), 1u);
            else       X86_R32(cpu, op & 7) = x86_alu32(cpu, 0, X86_R32(cpu, op & 7), 1u);
            cpu->flags = (u16)((cpu->flags & ~X86_F_CF) | cf);
            break;
        }
        case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
            u16 cf = cpu->flags & X86_F_CF;
            if (!op32) X86_R16(cpu, op & 7) = x86_alu16(cpu, 5, X86_R16(cpu, op & 7), 1u);
            else       X86_R32(cpu, op & 7) = x86_alu32(cpu, 5, X86_R32(cpu, op & 7), 1u);
            cpu->flags = (u16)((cpu->flags & ~X86_F_CF) | cf);
            break;
        }

        /* 0x50..0x57 PUSH reg, 0x58..0x5F POP reg */
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
            if (!op32) x86_push16(cpu, X86_R16(cpu, op & 7));
            else       x86_push32(cpu, X86_R32(cpu, op & 7));
            break;
        case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            if (!op32) X86_R16(cpu, op & 7) = x86_pop16(cpu);
            else       X86_R32(cpu, op & 7) = x86_pop32(cpu);
            break;

        case 0x60: /* PUSHA / PUSHAD */
            if (!op32) {
                u16 sp = X86_SP(cpu);
                for (int r = 0; r < 8; r++)
                    x86_push16(cpu, r == 4 ? sp : X86_R16(cpu, r));
            } else {
                u32 esp = X86_ESP(cpu);
                for (int r = 0; r < 8; r++)
                    x86_push32(cpu, r == 4 ? esp : X86_R32(cpu, r));
            }
            cpu->cycles += 10;
            break;
        case 0x61: /* POPA / POPAD */
            if (!op32) {
                for (int r = 7; r >= 0; r--) {
                    u16 v = x86_pop16(cpu);
                    if (r != 4) X86_R16(cpu, r) = v;
                }
            } else {
                for (int r = 7; r >= 0; r--) {
                    u32 v = x86_pop32(cpu);
                    if (r != 4) X86_R32(cpu, r) = v;
                }
            }
            cpu->cycles += 10;
            break;
        case 0x62: { /* BOUND */
            u8 m = x86_fetch8(cpu);
            int reg = (m >> 3) & 7;
            if ((m >> 6) != 3) {
                int s; u16 o;
                x86_ea_decode(cpu, m, ad32, sego, &s, &o);
                s16 lo = (s16)x86_seg_rw(cpu, s, o);
                s16 hi = (s16)x86_seg_rw(cpu, s, (u16)(o + 2u));
                s16 val = (s16)X86_R16(cpu, reg);
                if (val < lo || val > hi)
                    x86_interrupt(cpu, 5);
            }
            break;
        }
        case 0x68: /* PUSH imm16/32 */
            if (!op32) x86_push16(cpu, x86_fetch16(cpu));
            else       x86_push32(cpu, x86_fetch32(cpu));
            break;
        case 0x6A: /* PUSH imm8 */
            if (!op32) x86_push16(cpu, (u16)(s16)(s8)x86_fetch8(cpu));
            else       x86_push32(cpu, (u32)(s32)(s8)x86_fetch8(cpu));
            break;
        case 0x69:
        case 0x6B: { /* IMUL r16/32, r/m16/32, imm16/8 */
            u8 m = x86_fetch8(cpu);
            int reg = (m >> 3) & 7;
            if (!op32) {
                s32 a;
                if ((m >> 6) == 3) a = (s16)X86_R16(cpu, m & 7);
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); a = (s16)x86_seg_rw(cpu, s, o); }
                s32 b = (op == 0x69u) ? (s16)x86_fetch16(cpu) : (s32)(s8)x86_fetch8(cpu);
                s32 p = a * b;
                X86_R16(cpu, reg) = (u16)p;
                if (p < -32768 || p > 32767) cpu->flags |= (X86_F_CF | X86_F_OF);
                else                         cpu->flags &= ~(X86_F_CF | X86_F_OF);
            } else {
                s32 a;
                if ((m >> 6) == 3) a = (s32)X86_R32(cpu, m & 7);
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); a = (s32)x86_seg_rd(cpu, s, o); }
                s32 b = (op == 0x69u) ? (s32)x86_fetch32(cpu) : (s32)(s8)x86_fetch8(cpu);
                long long p = (long long)a * (long long)b;
                X86_R32(cpu, reg) = (u32)p;
                if (p != (s32)p) cpu->flags |= (X86_F_CF | X86_F_OF);
                else             cpu->flags &= ~(X86_F_CF | X86_F_OF);
            }
            cpu->cycles += 12;
            break;
        }
        case 0x6C: case 0x6D: case 0x6E: case 0x6F: /* INSB/W, OUTSB/W */
            goto do_string_op;

        /* 0x70..0x7F Jcc rel8 */
        case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
            s8 rel = (s8)x86_fetch8(cpu);
            if (x86_cond(cpu, op & 15u)) {
                cpu->ip = (u16)(cpu->ip + (s16)rel);
                cpu->cycles += 4;
            }
            break;
        }

        /* 0x80..0x83 Group 1 ALU r/m, imm */
        case 0x80: case 0x82: {
            u8 m = x86_fetch8(cpu);
            int alu = (m >> 3) & 7;
            if ((m >> 6) == 3) {
                u8 b = x86_fetch8(cpu);
                u8 r = x86_alu8(cpu, alu, X86_R8(cpu, m & 7), b);
                if (alu != 7) X86_R8(cpu, m & 7) = r;
            } else {
                int s; u16 o;
                x86_ea_decode(cpu, m, ad32, sego, &s, &o);
                u8 b = x86_fetch8(cpu);
                u8 r = x86_alu8(cpu, alu, x86_seg_rb(cpu, s, o), b);
                if (alu != 7) x86_seg_wb(cpu, s, o, r);
                cpu->cycles += 6;
            }
            break;
        }
        case 0x81: case 0x83: {
            u8 m = x86_fetch8(cpu);
            int alu = (m >> 3) & 7;
            if (!op32) {
                int s = 0; u16 o = 0;
                u16 a;
                if ((m >> 6) == 3) a = X86_R16(cpu, m & 7);
                else { x86_ea_decode(cpu, m, ad32, sego, &s, &o); a = x86_seg_rw(cpu, s, o); cpu->cycles += 6; }
                u16 b = (op == 0x81u) ? x86_fetch16(cpu) : (u16)(s16)(s8)x86_fetch8(cpu);
                u16 r = x86_alu16(cpu, alu, a, b);
                if (alu != 7) {
                    if ((m >> 6) == 3) X86_R16(cpu, m & 7) = r;
                    else x86_seg_ww(cpu, s, o, r);
                }
            } else {
                int s = 0; u16 o = 0;
                u32 a;
                if ((m >> 6) == 3) a = X86_R32(cpu, m & 7);
                else { x86_ea_decode(cpu, m, ad32, sego, &s, &o); a = x86_seg_rd(cpu, s, o); cpu->cycles += 6; }
                u32 b = (op == 0x81u) ? x86_fetch32(cpu) : (u32)(s32)(s8)x86_fetch8(cpu);
                u32 r = x86_alu32(cpu, alu, a, b);
                if (alu != 7) {
                    if ((m >> 6) == 3) X86_R32(cpu, m & 7) = r;
                    else x86_seg_wd(cpu, s, o, r);
                }
            }
            break;
        }

        case 0x84: { /* TEST r/m8, r8 */
            u8 m = x86_fetch8(cpu);
            u8 b = X86_R8(cpu, (m >> 3) & 7);
            u8 a;
            if ((m >> 6) == 3) a = X86_R8(cpu, m & 7);
            else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); a = x86_seg_rb(cpu, s, o); cpu->cycles += 4; }
            (void)x86_alu8(cpu, 4, a, b);
            break;
        }
        case 0x85: { /* TEST r/m16/32, r16/32 */
            u8 m = x86_fetch8(cpu);
            if (!op32) {
                u16 b = X86_R16(cpu, (m >> 3) & 7), a;
                if ((m >> 6) == 3) a = X86_R16(cpu, m & 7);
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); a = x86_seg_rw(cpu, s, o); cpu->cycles += 4; }
                (void)x86_alu16(cpu, 4, a, b);
            } else {
                u32 b = X86_R32(cpu, (m >> 3) & 7), a;
                if ((m >> 6) == 3) a = X86_R32(cpu, m & 7);
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); a = x86_seg_rd(cpu, s, o); cpu->cycles += 4; }
                (void)x86_alu32(cpu, 4, a, b);
            }
            break;
        }
        case 0x86: { /* XCHG r/m8, r8 */
            u8 m = x86_fetch8(cpu);
            int reg = (m >> 3) & 7;
            u8 b = X86_R8(cpu, reg);
            if ((m >> 6) == 3) {
                X86_R8(cpu, reg) = X86_R8(cpu, m & 7);
                X86_R8(cpu, m & 7) = b;
            } else {
                int s; u16 o;
                x86_ea_decode(cpu, m, ad32, sego, &s, &o);
                X86_R8(cpu, reg) = x86_seg_rb(cpu, s, o);
                x86_seg_wb(cpu, s, o, b);
                cpu->cycles += 6;
            }
            break;
        }
        case 0x87: { /* XCHG r/m16/32, r16/32 */
            u8 m = x86_fetch8(cpu);
            int reg = (m >> 3) & 7;
            if (!op32) {
                u16 b = X86_R16(cpu, reg);
                if ((m >> 6) == 3) { X86_R16(cpu, reg) = X86_R16(cpu, m & 7); X86_R16(cpu, m & 7) = b; }
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); X86_R16(cpu, reg) = x86_seg_rw(cpu, s, o); x86_seg_ww(cpu, s, o, b); cpu->cycles += 6; }
            } else {
                u32 b = X86_R32(cpu, reg);
                if ((m >> 6) == 3) { X86_R32(cpu, reg) = X86_R32(cpu, m & 7); X86_R32(cpu, m & 7) = b; }
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); X86_R32(cpu, reg) = x86_seg_rd(cpu, s, o); x86_seg_wd(cpu, s, o, b); cpu->cycles += 6; }
            }
            break;
        }
        case 0x88: { /* MOV r/m8, r8 */
            u8 m = x86_fetch8(cpu);
            u8 b = X86_R8(cpu, (m >> 3) & 7);
            if ((m >> 6) == 3) X86_R8(cpu, m & 7) = b;
            else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); x86_seg_wb(cpu, s, o, b); cpu->cycles += 4; }
            break;
        }
        case 0x89: { /* MOV r/m16/32, r16/32 */
            u8 m = x86_fetch8(cpu);
            if (!op32) {
                u16 b = X86_R16(cpu, (m >> 3) & 7);
                if ((m >> 6) == 3) X86_R16(cpu, m & 7) = b;
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); x86_seg_ww(cpu, s, o, b); cpu->cycles += 4; }
            } else {
                u32 b = X86_R32(cpu, (m >> 3) & 7);
                if ((m >> 6) == 3) X86_R32(cpu, m & 7) = b;
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); x86_seg_wd(cpu, s, o, b); cpu->cycles += 4; }
            }
            break;
        }
        case 0x8A: { /* MOV r8, r/m8 */
            u8 m = x86_fetch8(cpu);
            int reg = (m >> 3) & 7;
            if ((m >> 6) == 3) X86_R8(cpu, reg) = X86_R8(cpu, m & 7);
            else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); X86_R8(cpu, reg) = x86_seg_rb(cpu, s, o); cpu->cycles += 4; }
            break;
        }
        case 0x8B: { /* MOV r16/32, r/m16/32 */
            u8 m = x86_fetch8(cpu);
            int reg = (m >> 3) & 7;
            if (!op32) {
                if ((m >> 6) == 3) X86_R16(cpu, reg) = X86_R16(cpu, m & 7);
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); X86_R16(cpu, reg) = x86_seg_rw(cpu, s, o); cpu->cycles += 4; }
            } else {
                if ((m >> 6) == 3) X86_R32(cpu, reg) = X86_R32(cpu, m & 7);
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); X86_R32(cpu, reg) = x86_seg_rd(cpu, s, o); cpu->cycles += 4; }
            }
            break;
        }
        case 0x8C: { /* MOV r/m16, Sreg */
            u8 m = x86_fetch8(cpu);
            int sr = (m >> 3) & 7;
            u16 v = (sr < 6) ? cpu->sr[sr] : 0u;
            if ((m >> 6) == 3) {
                if (!op32) X86_R16(cpu, m & 7) = v;
                else       X86_R32(cpu, m & 7) = v;
            } else {
                int s; u16 o;
                x86_ea_decode(cpu, m, ad32, sego, &s, &o);
                x86_seg_ww(cpu, s, o, v);
            }
            break;
        }
        case 0x8D: { /* LEA */
            u8 m = x86_fetch8(cpu);
            int reg = (m >> 3) & 7;
            if ((m >> 6) != 3) {
                int s; u16 o;
                x86_ea_decode(cpu, m, ad32, sego, &s, &o);
                if (!op32) X86_R16(cpu, reg) = o;
                else       X86_R32(cpu, reg) = o;
            }
            break;
        }
        case 0x8E: { /* MOV Sreg, r/m16 */
            u8 m = x86_fetch8(cpu);
            int sr = (m >> 3) & 7;
            u16 v;
            if ((m >> 6) == 3) v = X86_R16(cpu, m & 7);
            else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); v = x86_seg_rw(cpu, s, o); }
            if (sr < 6) {
                x86_set_sr(cpu, sr, v);
                if (sr == X86_SS) cpu->int_inhibit = 1;
            }
            break;
        }
        case 0x8F: { /* POP r/m16/32 */
            u8 m = x86_fetch8(cpu);
            if (!op32) {
                u16 v = x86_pop16(cpu);
                if ((m >> 6) == 3) X86_R16(cpu, m & 7) = v;
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); x86_seg_ww(cpu, s, o, v); }
            } else {
                u32 v = x86_pop32(cpu);
                if ((m >> 6) == 3) X86_R32(cpu, m & 7) = v;
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); x86_seg_wd(cpu, s, o, v); }
            }
            break;
        }

        case 0x90: break; /* NOP */
        case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
            if (!op32) { u16 t = X86_AX(cpu); X86_AX(cpu) = X86_R16(cpu, op & 7); X86_R16(cpu, op & 7) = t; }
            else       { u32 t = X86_EAX(cpu); X86_EAX(cpu) = X86_R32(cpu, op & 7); X86_R32(cpu, op & 7) = t; }
            break;
        case 0x98: /* CBW / CWDE */
            if (!op32) X86_AX(cpu)  = (u16)(s16)(s8)X86_AL(cpu);
            else       X86_EAX(cpu) = (u32)(s32)(s16)X86_AX(cpu);
            break;
        case 0x99: /* CWD / CDQ */
            if (!op32) X86_DX(cpu)  = (X86_AX(cpu) & 0x8000u) ? 0xFFFFu : 0x0000u;
            else       X86_EDX(cpu) = (X86_EAX(cpu) & 0x80000000u) ? 0xFFFFFFFFu : 0x00000000u;
            break;
        case 0x9A: { /* CALL ptr16:16 */
            u16 nip = x86_fetch16(cpu);
            u16 ncs = x86_fetch16(cpu);
            x86_push16(cpu, cpu->sr[X86_CS]);
            x86_push16(cpu, cpu->ip);
            x86_set_sr(cpu, X86_CS, ncs);
            cpu->ip = nip;
            cpu->cycles += 12;
            break;
        }
        case 0x9B: break; /* WAIT */
        case 0x9C: /* PUSHF / PUSHFD */
            if (!op32) x86_push16(cpu, (u16)(cpu->flags | 0x0002u));
            else       x86_push32(cpu, (u32)(cpu->flags | 0x0002u));
            break;
        case 0x9D: /* POPF / POPFD */
            if (!op32) cpu->flags = (u16)((x86_pop16(cpu) & 0x7FD5u) | 0x0002u | (cpu->is_v30 ? 0x8000u : 0u));
            else       cpu->flags = (u16)((x86_pop32(cpu) & 0x7FD5u) | 0x0002u);
            break;
        case 0x9E: /* SAHF */
            cpu->flags = (u16)((cpu->flags & 0xFF00u) | (X86_AH(cpu) & 0xD5u) | 0x02u);
            break;
        case 0x9F: /* LAHF */
            X86_AH(cpu) = (u8)((cpu->flags & 0xD5u) | 0x02u);
            break;

        /* 0xA0..0xA3 MOV AL/AX, moffs */
        case 0xA0: {
            u16 o = ad32 ? (u16)x86_fetch32(cpu) : x86_fetch16(cpu);
            X86_AL(cpu) = x86_seg_rb(cpu, sego >= 0 ? sego : X86_DS, o);
            break;
        }
        case 0xA1: {
            u16 o = ad32 ? (u16)x86_fetch32(cpu) : x86_fetch16(cpu);
            int s = sego >= 0 ? sego : X86_DS;
            if (!op32) X86_AX(cpu)  = x86_seg_rw(cpu, s, o);
            else       X86_EAX(cpu) = x86_seg_rd(cpu, s, o);
            break;
        }
        case 0xA2: {
            u16 o = ad32 ? (u16)x86_fetch32(cpu) : x86_fetch16(cpu);
            x86_seg_wb(cpu, sego >= 0 ? sego : X86_DS, o, X86_AL(cpu));
            break;
        }
        case 0xA3: {
            u16 o = ad32 ? (u16)x86_fetch32(cpu) : x86_fetch16(cpu);
            int s = sego >= 0 ? sego : X86_DS;
            if (!op32) x86_seg_ww(cpu, s, o, X86_AX(cpu));
            else       x86_seg_wd(cpu, s, o, X86_EAX(cpu));
            break;
        }

        /* String operations */
        case 0xA4: case 0xA5: case 0xA6: case 0xA7:
        case 0xAA: case 0xAB: case 0xAC: case 0xAD: case 0xAE: case 0xAF:
        do_string_op: {
            int s = (sego >= 0) ? sego : X86_DS;
            int step1 = (cpu->flags & X86_F_DF) ? -1 : 1;
            int step2 = step1 * (op32 ? 4 : 2);
            int check_zf = (op == 0xA6u || op == 0xA7u || op == 0xAEu || op == 0xAFu);

            if (!rep) {
                switch (op) {
                case 0x6C: x86_seg_wb(cpu, X86_ES, X86_DI(cpu), X86_INB(X86_DX(cpu))); X86_DI(cpu) = (u16)(X86_DI(cpu) + step1); break;
                case 0x6D: x86_seg_ww(cpu, X86_ES, X86_DI(cpu), X86_INW(X86_DX(cpu))); X86_DI(cpu) = (u16)(X86_DI(cpu) + step2); break;
                case 0x6E: X86_OUTB(X86_DX(cpu), x86_seg_rb(cpu, s, X86_SI(cpu))); X86_SI(cpu) = (u16)(X86_SI(cpu) + step1); break;
                case 0x6F: X86_OUTW(X86_DX(cpu), x86_seg_rw(cpu, s, X86_SI(cpu))); X86_SI(cpu) = (u16)(X86_SI(cpu) + step2); break;
                case 0xA4: x86_seg_wb(cpu, X86_ES, X86_DI(cpu), x86_seg_rb(cpu, s, X86_SI(cpu))); X86_SI(cpu) = (u16)(X86_SI(cpu) + step1); X86_DI(cpu) = (u16)(X86_DI(cpu) + step1); break;
                case 0xA5:
                    if (!op32) x86_seg_ww(cpu, X86_ES, X86_DI(cpu), x86_seg_rw(cpu, s, X86_SI(cpu)));
                    else       x86_seg_wd(cpu, X86_ES, X86_DI(cpu), x86_seg_rd(cpu, s, X86_SI(cpu)));
                    X86_SI(cpu) = (u16)(X86_SI(cpu) + step2); X86_DI(cpu) = (u16)(X86_DI(cpu) + step2);
                    break;
                case 0xA6: (void)x86_alu8(cpu, 7, x86_seg_rb(cpu, s, X86_SI(cpu)), x86_seg_rb(cpu, X86_ES, X86_DI(cpu))); X86_SI(cpu) = (u16)(X86_SI(cpu) + step1); X86_DI(cpu) = (u16)(X86_DI(cpu) + step1); break;
                case 0xA7:
                    if (!op32) (void)x86_alu16(cpu, 7, x86_seg_rw(cpu, s, X86_SI(cpu)), x86_seg_rw(cpu, X86_ES, X86_DI(cpu)));
                    else       (void)x86_alu32(cpu, 7, x86_seg_rd(cpu, s, X86_SI(cpu)), x86_seg_rd(cpu, X86_ES, X86_DI(cpu)));
                    X86_SI(cpu) = (u16)(X86_SI(cpu) + step2); X86_DI(cpu) = (u16)(X86_DI(cpu) + step2);
                    break;
                case 0xAA: x86_seg_wb(cpu, X86_ES, X86_DI(cpu), X86_AL(cpu)); X86_DI(cpu) = (u16)(X86_DI(cpu) + step1); break;
                case 0xAB:
                    if (!op32) x86_seg_ww(cpu, X86_ES, X86_DI(cpu), X86_AX(cpu));
                    else       x86_seg_wd(cpu, X86_ES, X86_DI(cpu), X86_EAX(cpu));
                    X86_DI(cpu) = (u16)(X86_DI(cpu) + step2);
                    break;
                case 0xAC: X86_AL(cpu) = x86_seg_rb(cpu, s, X86_SI(cpu)); X86_SI(cpu) = (u16)(X86_SI(cpu) + step1); break;
                case 0xAD:
                    if (!op32) X86_AX(cpu)  = x86_seg_rw(cpu, s, X86_SI(cpu));
                    else       X86_EAX(cpu) = x86_seg_rd(cpu, s, X86_SI(cpu));
                    X86_SI(cpu) = (u16)(X86_SI(cpu) + step2);
                    break;
                case 0xAE: (void)x86_alu8(cpu, 7, X86_AL(cpu), x86_seg_rb(cpu, X86_ES, X86_DI(cpu))); X86_DI(cpu) = (u16)(X86_DI(cpu) + step1); break;
                default:
                    if (!op32) (void)x86_alu16(cpu, 7, X86_AX(cpu),  x86_seg_rw(cpu, X86_ES, X86_DI(cpu)));
                    else       (void)x86_alu32(cpu, 7, X86_EAX(cpu), x86_seg_rd(cpu, X86_ES, X86_DI(cpu)));
                    X86_DI(cpu) = (u16)(X86_DI(cpu) + step2);
                    break;
                }
                cpu->cycles += 4;
            } else {
                u32 cnt = ad32 ? X86_ECX(cpu) : (u32)X86_CX(cpu);
                while (cnt > 0) {
                    switch (op) {
                    case 0x6C: x86_seg_wb(cpu, X86_ES, X86_DI(cpu), X86_INB(X86_DX(cpu))); X86_DI(cpu) = (u16)(X86_DI(cpu) + step1); break;
                    case 0x6D: x86_seg_ww(cpu, X86_ES, X86_DI(cpu), X86_INW(X86_DX(cpu))); X86_DI(cpu) = (u16)(X86_DI(cpu) + step2); break;
                    case 0x6E: X86_OUTB(X86_DX(cpu), x86_seg_rb(cpu, s, X86_SI(cpu))); X86_SI(cpu) = (u16)(X86_SI(cpu) + step1); break;
                    case 0x6F: X86_OUTW(X86_DX(cpu), x86_seg_rw(cpu, s, X86_SI(cpu))); X86_SI(cpu) = (u16)(X86_SI(cpu) + step2); break;
                    case 0xA4: x86_seg_wb(cpu, X86_ES, X86_DI(cpu), x86_seg_rb(cpu, s, X86_SI(cpu))); X86_SI(cpu) = (u16)(X86_SI(cpu) + step1); X86_DI(cpu) = (u16)(X86_DI(cpu) + step1); break;
                    case 0xA5:
                        if (!op32) x86_seg_ww(cpu, X86_ES, X86_DI(cpu), x86_seg_rw(cpu, s, X86_SI(cpu)));
                        else       x86_seg_wd(cpu, X86_ES, X86_DI(cpu), x86_seg_rd(cpu, s, X86_SI(cpu)));
                        X86_SI(cpu) = (u16)(X86_SI(cpu) + step2); X86_DI(cpu) = (u16)(X86_DI(cpu) + step2);
                        break;
                    case 0xA6: (void)x86_alu8(cpu, 7, x86_seg_rb(cpu, s, X86_SI(cpu)), x86_seg_rb(cpu, X86_ES, X86_DI(cpu))); X86_SI(cpu) = (u16)(X86_SI(cpu) + step1); X86_DI(cpu) = (u16)(X86_DI(cpu) + step1); break;
                    case 0xA7:
                        if (!op32) (void)x86_alu16(cpu, 7, x86_seg_rw(cpu, s, X86_SI(cpu)), x86_seg_rw(cpu, X86_ES, X86_DI(cpu)));
                        else       (void)x86_alu32(cpu, 7, x86_seg_rd(cpu, s, X86_SI(cpu)), x86_seg_rd(cpu, X86_ES, X86_DI(cpu)));
                        X86_SI(cpu) = (u16)(X86_SI(cpu) + step2); X86_DI(cpu) = (u16)(X86_DI(cpu) + step2);
                        break;
                    case 0xAA: x86_seg_wb(cpu, X86_ES, X86_DI(cpu), X86_AL(cpu)); X86_DI(cpu) = (u16)(X86_DI(cpu) + step1); break;
                    case 0xAB:
                        if (!op32) x86_seg_ww(cpu, X86_ES, X86_DI(cpu), X86_AX(cpu));
                        else       x86_seg_wd(cpu, X86_ES, X86_DI(cpu), X86_EAX(cpu));
                        X86_DI(cpu) = (u16)(X86_DI(cpu) + step2);
                        break;
                    case 0xAC: X86_AL(cpu) = x86_seg_rb(cpu, s, X86_SI(cpu)); X86_SI(cpu) = (u16)(X86_SI(cpu) + step1); break;
                    case 0xAD:
                        if (!op32) X86_AX(cpu)  = x86_seg_rw(cpu, s, X86_SI(cpu));
                        else       X86_EAX(cpu) = x86_seg_rd(cpu, s, X86_SI(cpu));
                        X86_SI(cpu) = (u16)(X86_SI(cpu) + step2);
                        break;
                    case 0xAE: (void)x86_alu8(cpu, 7, X86_AL(cpu), x86_seg_rb(cpu, X86_ES, X86_DI(cpu))); X86_DI(cpu) = (u16)(X86_DI(cpu) + step1); break;
                    default:
                        if (!op32) (void)x86_alu16(cpu, 7, X86_AX(cpu),  x86_seg_rw(cpu, X86_ES, X86_DI(cpu)));
                        else       (void)x86_alu32(cpu, 7, X86_EAX(cpu), x86_seg_rd(cpu, X86_ES, X86_DI(cpu)));
                        X86_DI(cpu) = (u16)(X86_DI(cpu) + step2);
                        break;
                    }
                    cnt--;
                    cpu->cycles += 2;
                    if (check_zf) {
                        int zf = (cpu->flags & X86_F_ZF) != 0;
                        if ((rep == 2 && !zf) || (rep == 1 && zf))
                            break;
                    }
                    if (cpu->cycles >= target_cycles && cnt > 0) {
                        /* Interruptible long REP: rewind IP to prefix start so IRQs/timers can fire mid-REP! */
                        cpu->ip = cpu->op_ip;
                        break;
                    }
                }
                if (ad32) X86_ECX(cpu) = cnt;
                else      X86_CX(cpu)  = (u16)cnt;
            }
            break;
        }

        case 0xA8: (void)x86_alu8(cpu, 4, X86_AL(cpu), x86_fetch8(cpu)); break;
        case 0xA9:
            if (!op32) (void)x86_alu16(cpu, 4, X86_AX(cpu),  x86_fetch16(cpu));
            else       (void)x86_alu32(cpu, 4, X86_EAX(cpu), x86_fetch32(cpu));
            break;

        /* 0xB0..0xB7 MOV r8, imm8; 0xB8..0xBF MOV r16/32, imm16/32 */
        case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7:
            X86_R8(cpu, op & 7) = x86_fetch8(cpu);
            break;
        case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF:
            if (!op32) X86_R16(cpu, op & 7) = x86_fetch16(cpu);
            else       X86_R32(cpu, op & 7) = x86_fetch32(cpu);
            break;

        /* 0xC0/0xC1/0xD0..0xD3 Group 2 Shifts */
        case 0xC0: case 0xD0: case 0xD2: {
            u8 m = x86_fetch8(cpu);
            int sop = (m >> 3) & 7;
            if ((m >> 6) == 3) {
                u8 cnt = (op == 0xC0u) ? x86_fetch8(cpu) : (op == 0xD0u ? 1u : X86_CL(cpu));
                X86_R8(cpu, m & 7) = x86_shift8(cpu, sop, X86_R8(cpu, m & 7), cnt);
            } else {
                int s; u16 o;
                x86_ea_decode(cpu, m, ad32, sego, &s, &o);
                u8 cnt = (op == 0xC0u) ? x86_fetch8(cpu) : (op == 0xD0u ? 1u : X86_CL(cpu));
                x86_seg_wb(cpu, s, o, x86_shift8(cpu, sop, x86_seg_rb(cpu, s, o), cnt));
                cpu->cycles += 6;
            }
            break;
        }
        case 0xC1: case 0xD1: case 0xD3: {
            u8 m = x86_fetch8(cpu);
            int sop = (m >> 3) & 7;
            if (!op32) {
                if ((m >> 6) == 3) {
                    u8 cnt = (op == 0xC1u) ? x86_fetch8(cpu) : (op == 0xD1u ? 1u : X86_CL(cpu));
                    X86_R16(cpu, m & 7) = x86_shift16(cpu, sop, X86_R16(cpu, m & 7), cnt);
                } else {
                    int s; u16 o;
                    x86_ea_decode(cpu, m, ad32, sego, &s, &o);
                    u8 cnt = (op == 0xC1u) ? x86_fetch8(cpu) : (op == 0xD1u ? 1u : X86_CL(cpu));
                    x86_seg_ww(cpu, s, o, x86_shift16(cpu, sop, x86_seg_rw(cpu, s, o), cnt));
                    cpu->cycles += 6;
                }
            } else {
                if ((m >> 6) == 3) {
                    u8 cnt = (op == 0xC1u) ? x86_fetch8(cpu) : (op == 0xD1u ? 1u : X86_CL(cpu));
                    X86_R32(cpu, m & 7) = x86_shift32(cpu, sop, X86_R32(cpu, m & 7), cnt);
                } else {
                    int s; u16 o;
                    x86_ea_decode(cpu, m, ad32, sego, &s, &o);
                    u8 cnt = (op == 0xC1u) ? x86_fetch8(cpu) : (op == 0xD1u ? 1u : X86_CL(cpu));
                    x86_seg_wd(cpu, s, o, x86_shift32(cpu, sop, x86_seg_rd(cpu, s, o), cnt));
                    cpu->cycles += 6;
                }
            }
            break;
        }

        case 0xC2: { u16 popb = x86_fetch16(cpu); cpu->ip = x86_pop16(cpu); X86_SP(cpu) = (u16)(X86_SP(cpu) + popb); cpu->cycles += 8; break; }
        case 0xC3: cpu->ip = x86_pop16(cpu); cpu->cycles += 8; break;
        case 0xC4: /* LES */
        case 0xC5: { /* LDS */
            u8 m = x86_fetch8(cpu);
            int reg = (m >> 3) & 7;
            if ((m >> 6) != 3) {
                int s; u16 o;
                x86_ea_decode(cpu, m, ad32, sego, &s, &o);
                u16 off = x86_seg_rw(cpu, s, o);
                u16 seg = x86_seg_rw(cpu, s, (u16)(o + 2u));
                X86_R16(cpu, reg) = off;
                x86_set_sr(cpu, op == 0xC4u ? X86_ES : X86_DS, seg);
                cpu->cycles += 8;
            }
            break;
        }
        case 0xC6: { /* MOV r/m8, imm8 */
            u8 m = x86_fetch8(cpu);
            if ((m >> 6) == 3) X86_R8(cpu, m & 7) = x86_fetch8(cpu);
            else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); x86_seg_wb(cpu, s, o, x86_fetch8(cpu)); cpu->cycles += 4; }
            break;
        }
        case 0xC7: { /* MOV r/m16/32, imm16/32 */
            u8 m = x86_fetch8(cpu);
            if (!op32) {
                if ((m >> 6) == 3) X86_R16(cpu, m & 7) = x86_fetch16(cpu);
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); x86_seg_ww(cpu, s, o, x86_fetch16(cpu)); cpu->cycles += 4; }
            } else {
                if ((m >> 6) == 3) X86_R32(cpu, m & 7) = x86_fetch32(cpu);
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); x86_seg_wd(cpu, s, o, x86_fetch32(cpu)); cpu->cycles += 4; }
            }
            break;
        }
        case 0xC8: { /* ENTER imm16, imm8 */
            u16 alloc = x86_fetch16(cpu);
            u8  lvl   = x86_fetch8(cpu) & 31u;
            x86_push16(cpu, X86_BP(cpu));
            u16 fp = X86_SP(cpu);
            if (lvl > 0) {
                for (u8 i = 1; i < lvl; i++) {
                    X86_BP(cpu) = (u16)(X86_BP(cpu) - 2u);
                    x86_push16(cpu, x86_seg_rw(cpu, X86_SS, X86_BP(cpu)));
                }
                x86_push16(cpu, fp);
            }
            X86_BP(cpu) = fp;
            X86_SP(cpu) = (u16)(X86_SP(cpu) - alloc);
            cpu->cycles += 12;
            break;
        }
        case 0xC9: /* LEAVE */
            X86_SP(cpu) = X86_BP(cpu);
            X86_BP(cpu) = x86_pop16(cpu);
            cpu->cycles += 4;
            break;
        case 0xCA: { u16 popb = x86_fetch16(cpu); cpu->ip = x86_pop16(cpu); x86_set_sr(cpu, X86_CS, x86_pop16(cpu)); X86_SP(cpu) = (u16)(X86_SP(cpu) + popb); cpu->cycles += 12; break; }
        case 0xCB: cpu->ip = x86_pop16(cpu); x86_set_sr(cpu, X86_CS, x86_pop16(cpu)); cpu->cycles += 12; break;
        case 0xCC: x86_interrupt(cpu, 3); break;
        case 0xCD: x86_interrupt(cpu, x86_fetch8(cpu)); break;
        case 0xCE: if (cpu->flags & X86_F_OF) x86_interrupt(cpu, 4); break;
        case 0xCF: { /* IRET */
            cpu->ip = x86_pop16(cpu);
            x86_set_sr(cpu, X86_CS, x86_pop16(cpu));
            cpu->flags = (u16)((x86_pop16(cpu) & 0x7FD5u) | 0x0002u | (cpu->is_v30 ? 0x8000u : 0u));
            cpu->cycles += 16;
            break;
        }

        case 0xD4: { /* AAM imm8 */
            u8 base = x86_fetch8(cpu);
            if (base == 0) { x86_interrupt(cpu, 0); break; }
            u8 al = X86_AL(cpu);
            X86_AH(cpu) = (u8)(al / base);
            X86_AL(cpu) = (u8)(al % base);
            x86_set_szp8(cpu, X86_AL(cpu));
            break;
        }
        case 0xD5: { /* AAD imm8 */
            u8 base = x86_fetch8(cpu);
            X86_AL(cpu) = (u8)(X86_AL(cpu) + X86_AH(cpu) * base);
            X86_AH(cpu) = 0;
            x86_set_szp8(cpu, X86_AL(cpu));
            break;
        }
        case 0xD6: /* SALC */
            X86_AL(cpu) = (cpu->flags & X86_F_CF) ? 0xFFu : 0x00u;
            break;
        case 0xD7: { /* XLAT */
            int s = (sego >= 0) ? sego : X86_DS;
            X86_AL(cpu) = x86_seg_rb(cpu, s, (u16)(X86_BX(cpu) + X86_AL(cpu)));
            break;
        }
        /* 0xD8..0xDF 8087 FPU escape: consume ModR/M cleanly (no FPU present) */
        case 0xD8: case 0xD9: case 0xDA: case 0xDB: case 0xDC: case 0xDD: case 0xDE: case 0xDF: {
            u8 m = x86_fetch8(cpu);
            if ((m >> 6) != 3) {
                int s; u16 o;
                x86_ea_decode(cpu, m, ad32, sego, &s, &o);
                (void)s; (void)o;
            }
            break;
        }

        case 0xE0: case 0xE1: case 0xE2: { /* LOOPNZ, LOOPZ, LOOP */
            s8 rel = (s8)x86_fetch8(cpu);
            u32 c;
            if (!ad32) { X86_CX(cpu)--; c = X86_CX(cpu); }
            else       { X86_ECX(cpu)--; c = X86_ECX(cpu); }
            int zf = (cpu->flags & X86_F_ZF) != 0;
            int go = (c != 0) && (op == 0xE2u || (op == 0xE1u ? zf : !zf));
            if (go) { cpu->ip = (u16)(cpu->ip + (s16)rel); cpu->cycles += 6; }
            break;
        }
        case 0xE3: { /* JCXZ */
            s8 rel = (s8)x86_fetch8(cpu);
            if ((ad32 ? X86_ECX(cpu) : (u32)X86_CX(cpu)) == 0) {
                cpu->ip = (u16)(cpu->ip + (s16)rel);
                cpu->cycles += 6;
            }
            break;
        }
        case 0xE4: X86_AL(cpu) = X86_INB(x86_fetch8(cpu)); cpu->cycles += 6; break;
        case 0xE5: X86_AX(cpu) = X86_INW(x86_fetch8(cpu)); cpu->cycles += 6; break;
        case 0xE6: { u8 p = x86_fetch8(cpu); X86_OUTB(p, X86_AL(cpu)); cpu->cycles += 6; break; }
        case 0xE7: { u8 p = x86_fetch8(cpu); X86_OUTW(p, X86_AX(cpu)); cpu->cycles += 6; break; }

        case 0xE8: { /* CALL rel16 */
            u16 rel = op32 ? (u16)x86_fetch32(cpu) : x86_fetch16(cpu);
            x86_push16(cpu, cpu->ip);
            cpu->ip = (u16)(cpu->ip + rel);
            cpu->cycles += 8;
            break;
        }
        case 0xE9: { /* JMP rel16 */
            u16 rel = op32 ? (u16)x86_fetch32(cpu) : x86_fetch16(cpu);
            cpu->ip = (u16)(cpu->ip + rel);
            cpu->cycles += 6;
            break;
        }
        case 0xEA: { /* JMP ptr16:16 */
            u16 nip = x86_fetch16(cpu);
            u16 ncs = x86_fetch16(cpu);
            x86_set_sr(cpu, X86_CS, ncs);
            cpu->ip = nip;
            cpu->cycles += 8;
            break;
        }
        case 0xEB: { /* JMP rel8 */
            s8 rel = (s8)x86_fetch8(cpu);
            cpu->ip = (u16)(cpu->ip + (s16)rel);
            cpu->cycles += 4;
            break;
        }
        case 0xEC: X86_AL(cpu) = X86_INB(X86_DX(cpu)); cpu->cycles += 6; break;
        case 0xED: X86_AX(cpu) = X86_INW(X86_DX(cpu)); cpu->cycles += 6; break;
        case 0xEE: X86_OUTB(X86_DX(cpu), X86_AL(cpu)); cpu->cycles += 6; break;
        case 0xEF: X86_OUTW(X86_DX(cpu), X86_AX(cpu)); cpu->cycles += 6; break;

        case 0xF4: /* HLT */
            cpu->halted = 1;
            cpu->cycles = target_cycles;
            return;
        case 0xF5: cpu->flags ^= X86_F_CF; break;

        /* 0xF6 / 0xF7 Group 3: TEST, NOT, NEG, MUL, IMUL, DIV, IDIV */
        case 0xF6: {
            u8 m = x86_fetch8(cpu);
            int sub = (m >> 3) & 7;
            int s = 0; u16 o = 0;
            u8 v;
            if ((m >> 6) == 3) v = X86_R8(cpu, m & 7);
            else { x86_ea_decode(cpu, m, ad32, sego, &s, &o); v = x86_seg_rb(cpu, s, o); cpu->cycles += 4; }
            switch (sub) {
            case 0: case 1: (void)x86_alu8(cpu, 4, v, x86_fetch8(cpu)); break;
            case 2: v = (u8)~v; if ((m >> 6) == 3) X86_R8(cpu, m & 7) = v; else x86_seg_wb(cpu, s, o, v); break;
            case 3: v = x86_alu8(cpu, 5, 0, v); if ((m >> 6) == 3) X86_R8(cpu, m & 7) = v; else x86_seg_wb(cpu, s, o, v); break;
            case 4: {
                u16 p = (u16)X86_AL(cpu) * (u16)v;
                X86_AX(cpu) = p;
                if (p & 0xFF00u) cpu->flags |= (X86_F_CF | X86_F_OF);
                else             cpu->flags &= ~(X86_F_CF | X86_F_OF);
                cpu->cycles += 12;
                break;
            }
            case 5: {
                s16 p = (s16)(s8)X86_AL(cpu) * (s16)(s8)v;
                X86_AX(cpu) = (u16)p;
                if (p < -128 || p > 127) cpu->flags |= (X86_F_CF | X86_F_OF);
                else                     cpu->flags &= ~(X86_F_CF | X86_F_OF);
                cpu->cycles += 12;
                break;
            }
            case 6: {
                if (v == 0) { x86_interrupt(cpu, 0); break; }
                u32 q = (u32)X86_AX(cpu) / (u32)v;
                u32 r = (u32)X86_AX(cpu) % (u32)v;
                if (q > 0xFFu) { x86_interrupt(cpu, 0); break; }
                X86_AL(cpu) = (u8)q;
                X86_AH(cpu) = (u8)r;
                cpu->cycles += 16;
                break;
            }
            default: {
                if (v == 0) { x86_interrupt(cpu, 0); break; }
                s32 n = (s16)X86_AX(cpu), d = (s8)v;
                s32 q = n / d, r = n % d;
                if (q < -128 || q > 127) { x86_interrupt(cpu, 0); break; }
                X86_AL(cpu) = (u8)q;
                X86_AH(cpu) = (u8)r;
                cpu->cycles += 16;
                break;
            }
            }
            break;
        }
        case 0xF7: {
            u8 m = x86_fetch8(cpu);
            int sub = (m >> 3) & 7;
            int s = 0; u16 o = 0;
            if (!op32) {
                u16 v;
                if ((m >> 6) == 3) v = X86_R16(cpu, m & 7);
                else { x86_ea_decode(cpu, m, ad32, sego, &s, &o); v = x86_seg_rw(cpu, s, o); cpu->cycles += 4; }
                switch (sub) {
                case 0: case 1: (void)x86_alu16(cpu, 4, v, x86_fetch16(cpu)); break;
                case 2: v = (u16)~v; if ((m >> 6) == 3) X86_R16(cpu, m & 7) = v; else x86_seg_ww(cpu, s, o, v); break;
                case 3: v = x86_alu16(cpu, 5, 0, v); if ((m >> 6) == 3) X86_R16(cpu, m & 7) = v; else x86_seg_ww(cpu, s, o, v); break;
                case 4: {
                    u32 p = (u32)X86_AX(cpu) * (u32)v;
                    X86_AX(cpu) = (u16)p;
                    X86_DX(cpu) = (u16)(p >> 16);
                    if (X86_DX(cpu)) cpu->flags |= (X86_F_CF | X86_F_OF);
                    else             cpu->flags &= ~(X86_F_CF | X86_F_OF);
                    cpu->cycles += 14;
                    break;
                }
                case 5: {
                    s32 p = (s32)(s16)X86_AX(cpu) * (s32)(s16)v;
                    X86_AX(cpu) = (u16)p;
                    X86_DX(cpu) = (u16)((u32)p >> 16);
                    if (p < -32768 || p > 32767) cpu->flags |= (X86_F_CF | X86_F_OF);
                    else                         cpu->flags &= ~(X86_F_CF | X86_F_OF);
                    cpu->cycles += 14;
                    break;
                }
                case 6: {
                    if (v == 0 || X86_DX(cpu) >= v) { x86_interrupt(cpu, 0); break; }
                    u32 num = ((u32)X86_DX(cpu) << 16) | X86_AX(cpu);
                    X86_AX(cpu) = (u16)(num / v);
                    X86_DX(cpu) = (u16)(num % v);
                    cpu->cycles += 20;
                    break;
                }
                default: {
                    if (v == 0) { x86_interrupt(cpu, 0); break; }
                    s32 num = (s32)(((u32)X86_DX(cpu) << 16) | X86_AX(cpu));
                    s32 d = (s16)v;
                    if (num == (s32)0x80000000u && d == -1) { x86_interrupt(cpu, 0); break; }
                    s32 q = num / d, r = num % d;
                    if (q < -32768 || q > 32767) { x86_interrupt(cpu, 0); break; }
                    X86_AX(cpu) = (u16)q;
                    X86_DX(cpu) = (u16)r;
                    cpu->cycles += 20;
                    break;
                }
                }
            } else {
                u32 v;
                if ((m >> 6) == 3) v = X86_R32(cpu, m & 7);
                else { x86_ea_decode(cpu, m, ad32, sego, &s, &o); v = x86_seg_rd(cpu, s, o); cpu->cycles += 4; }
                switch (sub) {
                case 0: case 1: (void)x86_alu32(cpu, 4, v, x86_fetch32(cpu)); break;
                case 2: v = ~v; if ((m >> 6) == 3) X86_R32(cpu, m & 7) = v; else x86_seg_wd(cpu, s, o, v); break;
                case 3: v = x86_alu32(cpu, 5, 0, v); if ((m >> 6) == 3) X86_R32(cpu, m & 7) = v; else x86_seg_wd(cpu, s, o, v); break;
                case 4: {
                    unsigned long long p = (unsigned long long)X86_EAX(cpu) * (unsigned long long)v;
                    X86_EAX(cpu) = (u32)p;
                    X86_EDX(cpu) = (u32)(p >> 32);
                    if (X86_EDX(cpu)) cpu->flags |= (X86_F_CF | X86_F_OF);
                    else              cpu->flags &= ~(X86_F_CF | X86_F_OF);
                    cpu->cycles += 16;
                    break;
                }
                case 5: {
                    long long p = (long long)(s32)X86_EAX(cpu) * (long long)(s32)v;
                    X86_EAX(cpu) = (u32)p;
                    X86_EDX(cpu) = (u32)((unsigned long long)p >> 32);
                    if (p != (s32)p) cpu->flags |= (X86_F_CF | X86_F_OF);
                    else             cpu->flags &= ~(X86_F_CF | X86_F_OF);
                    cpu->cycles += 16;
                    break;
                }
                case 6: {
                    u32 q, r;
                    if (x86_u64_div32(X86_EDX(cpu), X86_EAX(cpu), v, &q, &r)) { x86_interrupt(cpu, 0); break; }
                    X86_EAX(cpu) = q;
                    X86_EDX(cpu) = r;
                    cpu->cycles += 24;
                    break;
                }
                default: {
                    if (v == 0) { x86_interrupt(cpu, 0); break; }
                    u32 hi = X86_EDX(cpu), lo = X86_EAX(cpu);
                    int neg_n = (hi & 0x80000000u) != 0;
                    int neg_d = (v & 0x80000000u) != 0;
                    if (neg_n) { lo = ~lo + 1u; hi = ~hi + (lo == 0 ? 1u : 0u); }
                    u32 ud = neg_d ? (~v + 1u) : v;
                    u32 q, r;
                    if (x86_u64_div32(hi, lo, ud, &q, &r)) { x86_interrupt(cpu, 0); break; }
                    if ((neg_n ^ neg_d) ? (q > 0x80000000u) : (q > 0x7FFFFFFFu)) { x86_interrupt(cpu, 0); break; }
                    X86_EAX(cpu) = (neg_n ^ neg_d) ? (~q + 1u) : q;
                    X86_EDX(cpu) = neg_n ? (~r + 1u) : r;
                    cpu->cycles += 24;
                    break;
                }
                }
            }
            break;
        }

        case 0xF8: cpu->flags &= ~X86_F_CF; break;
        case 0xF9: cpu->flags |=  X86_F_CF; break;
        case 0xFA: cpu->flags &= ~X86_F_IF; break;
        case 0xFB: cpu->flags |=  X86_F_IF; if (!prev_inhibit) cpu->int_inhibit = 1; break;
        case 0xFC: cpu->flags &= ~X86_F_DF; break;
        case 0xFD: cpu->flags |=  X86_F_DF; break;

        /* 0xFE Group 4 (INC/DEC r/m8) */
        case 0xFE: {
            u8 m = x86_fetch8(cpu);
            int sub = (m >> 3) & 7;
            u16 cf = cpu->flags & X86_F_CF;
            int s = 0; u16 o = 0;
            u8 v;
            if ((m >> 6) == 3) v = X86_R8(cpu, m & 7);
            else { x86_ea_decode(cpu, m, ad32, sego, &s, &o); v = x86_seg_rb(cpu, s, o); cpu->cycles += 6; }
            if (sub == 0) v = x86_alu8(cpu, 0, v, 1u);
            else          v = x86_alu8(cpu, 5, v, 1u);
            cpu->flags = (u16)((cpu->flags & ~X86_F_CF) | cf);
            if ((m >> 6) == 3) X86_R8(cpu, m & 7) = v;
            else x86_seg_wb(cpu, s, o, v);
            break;
        }

        /* 0xFF Group 5 (INC, DEC, CALL r/m, CALL far, JMP r/m, JMP far, PUSH r/m) */
        case 0xFF: {
            u8 m = x86_fetch8(cpu);
            int sub = (m >> 3) & 7;
            int s = 0; u16 o = 0;
            if ((m >> 6) != 3)
                x86_ea_decode(cpu, m, ad32, sego, &s, &o);
            switch (sub) {
            case 0: case 1: {
                u16 cf = cpu->flags & X86_F_CF;
                if (!op32) {
                    u16 v = ((m >> 6) == 3) ? X86_R16(cpu, m & 7) : x86_seg_rw(cpu, s, o);
                    v = x86_alu16(cpu, sub ? 5 : 0, v, 1u);
                    if ((m >> 6) == 3) X86_R16(cpu, m & 7) = v; else x86_seg_ww(cpu, s, o, v);
                } else {
                    u32 v = ((m >> 6) == 3) ? X86_R32(cpu, m & 7) : x86_seg_rd(cpu, s, o);
                    v = x86_alu32(cpu, sub ? 5 : 0, v, 1u);
                    if ((m >> 6) == 3) X86_R32(cpu, m & 7) = v; else x86_seg_wd(cpu, s, o, v);
                }
                cpu->flags = (u16)((cpu->flags & ~X86_F_CF) | cf);
                break;
            }
            case 2: { /* CALL r/m16 */
                u16 dst = ((m >> 6) == 3) ? X86_R16(cpu, m & 7) : x86_seg_rw(cpu, s, o);
                x86_push16(cpu, cpu->ip);
                cpu->ip = dst;
                cpu->cycles += 10;
                break;
            }
            case 3: { /* CALL m16:16 */
                u16 nip = x86_seg_rw(cpu, s, o);
                u16 ncs = x86_seg_rw(cpu, s, (u16)(o + 2u));
                x86_push16(cpu, cpu->sr[X86_CS]);
                x86_push16(cpu, cpu->ip);
                x86_set_sr(cpu, X86_CS, ncs);
                cpu->ip = nip;
                cpu->cycles += 14;
                break;
            }
            case 4: { /* JMP r/m16 */
                cpu->ip = ((m >> 6) == 3) ? X86_R16(cpu, m & 7) : x86_seg_rw(cpu, s, o);
                cpu->cycles += 8;
                break;
            }
            case 5: { /* JMP m16:16 */
                u16 nip = x86_seg_rw(cpu, s, o);
                u16 ncs = x86_seg_rw(cpu, s, (u16)(o + 2u));
                x86_set_sr(cpu, X86_CS, ncs);
                cpu->ip = nip;
                cpu->cycles += 12;
                break;
            }
            default: { /* PUSH r/m16/32 */
                if (!op32) {
                    u16 v = ((m >> 6) == 3) ? X86_R16(cpu, m & 7) : x86_seg_rw(cpu, s, o);
                    x86_push16(cpu, v);
                } else {
                    u32 v = ((m >> 6) == 3) ? X86_R32(cpu, m & 7) : x86_seg_rd(cpu, s, o);
                    x86_push32(cpu, v);
                }
                cpu->cycles += 6;
                break;
            }
            }
            break;
        }

        /* 0x0F Two-byte extended opcodes (NEC V30 bit/nibble/BCD + 286/386 Jcc/MOVZX/MOVSX/BT/SHLD/IMUL + HLE trap) */
        case 0x0F: {
            u8 op2 = x86_fetch8(cpu);
            cpu->cycles += 4;
            switch (op2) {
            case 0xFF: { /* Clean-room HLE BIOS/OS trap */
                u8 id = x86_fetch8(cpu);
                X86_TRAP(cpu, id);
                break;
            }
            /* NEC V30 bit ops: TEST1 (10/11/18/19), CLR1 (12/13/1A/1B), SET1 (14/15/1C/1D), NOT1 (16/17/1E/1F) */
            case 0x10: case 0x12: case 0x14: case 0x16:
            case 0x18: case 0x1A: case 0x1C: case 0x1E: {
                u8 m = x86_fetch8(cpu);
                int s = 0; u16 o = 0;
                u8 v = ((m >> 6) == 3) ? X86_R8(cpu, m & 7) : (x86_ea_decode(cpu, m, ad32, sego, &s, &o), x86_seg_rb(cpu, s, o));
                u8 bit = ((op2 & 8u) ? x86_fetch8(cpu) : X86_CL(cpu)) & 7u;
                u8 mask = (u8)(1u << bit);
                int bop = (op2 >> 1) & 3;
                if (bop == 0) {
                    cpu->flags = (u16)((cpu->flags & ~(X86_F_ZF | X86_F_CF | X86_F_OF)) | ((v & mask) ? 0 : X86_F_ZF));
                } else {
                    if (bop == 1) v &= (u8)~mask;
                    else if (bop == 2) v |= mask;
                    else v ^= mask;
                    if ((m >> 6) == 3) X86_R8(cpu, m & 7) = v; else x86_seg_wb(cpu, s, o, v);
                }
                break;
            }
            case 0x11: case 0x13: case 0x15: case 0x17:
            case 0x19: case 0x1B: case 0x1D: case 0x1F: {
                u8 m = x86_fetch8(cpu);
                int s = 0; u16 o = 0;
                u16 v = ((m >> 6) == 3) ? X86_R16(cpu, m & 7) : (x86_ea_decode(cpu, m, ad32, sego, &s, &o), x86_seg_rw(cpu, s, o));
                u8 bit = ((op2 & 8u) ? x86_fetch8(cpu) : X86_CL(cpu)) & 15u;
                u16 mask = (u16)(1u << bit);
                int bop = (op2 >> 1) & 3;
                if (bop == 0) {
                    cpu->flags = (u16)((cpu->flags & ~(X86_F_ZF | X86_F_CF | X86_F_OF)) | ((v & mask) ? 0 : X86_F_ZF));
                } else {
                    if (bop == 1) v &= (u16)~mask;
                    else if (bop == 2) v |= mask;
                    else v ^= mask;
                    if ((m >> 6) == 3) X86_R16(cpu, m & 7) = v; else x86_seg_ww(cpu, s, o, v);
                }
                break;
            }
            /* NEC V30 ROL4 (0x28) / ROR4 (0x2A) */
            case 0x28: case 0x2A: {
                u8 m = x86_fetch8(cpu);
                int s = 0; u16 o = 0;
                u8 v = ((m >> 6) == 3) ? X86_R8(cpu, m & 7) : (x86_ea_decode(cpu, m, ad32, sego, &s, &o), x86_seg_rb(cpu, s, o));
                u8 al = X86_AL(cpu);
                if (op2 == 0x28u) {
                    u8 nv = (u8)((v << 4) | (al & 0x0Fu));
                    X86_AL(cpu) = (u8)((al & 0xF0u) | (v >> 4));
                    v = nv;
                } else {
                    u8 nv = (u8)((v >> 4) | ((al & 0x0Fu) << 4));
                    X86_AL(cpu) = (u8)((al & 0xF0u) | (v & 0x0Fu));
                    v = nv;
                }
                if ((m >> 6) == 3) X86_R8(cpu, m & 7) = v; else x86_seg_wb(cpu, s, o, v);
                break;
            }
            /* NEC V30 packed BCD string ADD4S (0x20), SUB4S (0x22), CMP4S (0x26) */
            case 0x20: case 0x22: case 0x26: {
                int s = (sego >= 0) ? sego : X86_DS;
                u16 bytes = (u16)((X86_CL(cpu) + 1u) >> 1);
                u8 carry = 0, nz = 0;
                for (u16 i = 0; i < bytes; i++) {
                    u8 src = x86_seg_rb(cpu, s, (u16)(X86_SI(cpu) + i));
                    u8 dst = x86_seg_rb(cpu, X86_ES, (u16)(X86_DI(cpu) + i));
                    u8 res = 0;
                    for (int nib = 0; nib < 2; nib++) {
                        int sn = (src >> (nib * 4)) & 15;
                        int dn = (dst >> (nib * 4)) & 15;
                        int rn;
                        if (op2 == 0x20u) {
                            rn = dn + sn + carry;
                            carry = (rn >= 10) ? 1 : 0;
                            if (carry) rn -= 10;
                        } else {
                            rn = dn - sn - carry;
                            carry = (rn < 0) ? 1 : 0;
                            if (carry) rn += 10;
                        }
                        res |= (u8)((rn & 15) << (nib * 4));
                    }
                    if (res) nz = 1;
                    if (op2 != 0x26u)
                        x86_seg_wb(cpu, X86_ES, (u16)(X86_DI(cpu) + i), res);
                }
                cpu->flags = (u16)((cpu->flags & ~(X86_F_CF | X86_F_ZF)) | (carry ? X86_F_CF : 0) | (nz ? 0 : X86_F_ZF));
                cpu->cycles += (s32)bytes * 6;
                break;
            }

            /* 386 Jcc rel16 (0F 80..8F) */
            case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
            case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E: case 0x8F: {
                u16 rel = op32 ? (u16)x86_fetch32(cpu) : x86_fetch16(cpu);
                if (x86_cond(cpu, op2 & 15u)) {
                    cpu->ip = (u16)(cpu->ip + rel);
                    cpu->cycles += 4;
                }
                break;
            }
            /* 386 SETcc r/m8 (0F 90..9F) */
            case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
            case 0x98: case 0x99: case 0x9A: case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F: {
                u8 m = x86_fetch8(cpu);
                u8 v = x86_cond(cpu, op2 & 15u) ? 1u : 0u;
                if ((m >> 6) == 3) X86_R8(cpu, m & 7) = v;
                else { int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); x86_seg_wb(cpu, s, o, v); }
                break;
            }
            case 0xA0: x86_push16(cpu, cpu->sr[X86_FS]); break;
            case 0xA1: x86_set_sr(cpu, X86_FS, x86_pop16(cpu)); break;
            case 0xA8: x86_push16(cpu, cpu->sr[X86_GS]); break;
            case 0xA9: x86_set_sr(cpu, X86_GS, x86_pop16(cpu)); break;

            /* SHLD (0F A4/A5) & SHRD (0F AC/AD) */
            case 0xA4: case 0xA5: case 0xAC: case 0xAD: {
                u8 m = x86_fetch8(cpu);
                int reg = (m >> 3) & 7;
                int s = 0; u16 o = 0;
                if (!op32) {
                    u16 dst = ((m >> 6) == 3) ? X86_R16(cpu, m & 7) : (x86_ea_decode(cpu, m, ad32, sego, &s, &o), x86_seg_rw(cpu, s, o));
                    u16 src = X86_R16(cpu, reg);
                    u8 cnt = ((op2 & 1u) ? X86_CL(cpu) : x86_fetch8(cpu)) & 31u;
                    if (cnt) {
                        u32 cf;
                        if (op2 < 0xA8u) {
                            u32 pair = ((u32)dst << 16) | src;
                            cf = (pair >> (32u - cnt)) & 1u;
                            dst = (u16)((pair << cnt) >> 16);
                        } else {
                            u32 pair = ((u32)src << 16) | dst;
                            cf = (pair >> (cnt - 1u)) & 1u;
                            dst = (u16)(pair >> cnt);
                        }
                        cpu->flags = (u16)((cpu->flags & ~X86_F_CF) | (cf ? X86_F_CF : 0));
                        x86_set_szp16(cpu, dst);
                        if ((m >> 6) == 3) X86_R16(cpu, m & 7) = dst; else x86_seg_ww(cpu, s, o, dst);
                    }
                } else {
                    u32 dst = ((m >> 6) == 3) ? X86_R32(cpu, m & 7) : (x86_ea_decode(cpu, m, ad32, sego, &s, &o), x86_seg_rd(cpu, s, o));
                    u32 src = X86_R32(cpu, reg);
                    u8 cnt = ((op2 & 1u) ? X86_CL(cpu) : x86_fetch8(cpu)) & 31u;
                    if (cnt) {
                        u32 cf;
                        if (op2 < 0xA8u) {
                            cf = (dst >> (32u - cnt)) & 1u;
                            dst = (dst << cnt) | (src >> (32u - cnt));
                        } else {
                            cf = (dst >> (cnt - 1u)) & 1u;
                            dst = (dst >> cnt) | (src << (32u - cnt));
                        }
                        cpu->flags = (u16)((cpu->flags & ~X86_F_CF) | (cf ? X86_F_CF : 0));
                        x86_set_szp32(cpu, dst);
                        if ((m >> 6) == 3) X86_R32(cpu, m & 7) = dst; else x86_seg_wd(cpu, s, o, dst);
                    }
                }
                break;
            }
            case 0xAF: { /* IMUL r16/32, r/m16/32 */
                u8 m = x86_fetch8(cpu);
                int reg = (m >> 3) & 7;
                if (!op32) {
                    s32 b = ((m >> 6) == 3) ? (s16)X86_R16(cpu, m & 7) : ({ int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); (s16)x86_seg_rw(cpu, s, o); });
                    s32 p = (s32)(s16)X86_R16(cpu, reg) * b;
                    X86_R16(cpu, reg) = (u16)p;
                    if (p < -32768 || p > 32767) cpu->flags |= (X86_F_CF | X86_F_OF);
                    else                         cpu->flags &= ~(X86_F_CF | X86_F_OF);
                } else {
                    s32 b = ((m >> 6) == 3) ? (s32)X86_R32(cpu, m & 7) : ({ int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); (s32)x86_seg_rd(cpu, s, o); });
                    long long p = (long long)(s32)X86_R32(cpu, reg) * (long long)b;
                    X86_R32(cpu, reg) = (u32)p;
                    if (p != (s32)p) cpu->flags |= (X86_F_CF | X86_F_OF);
                    else             cpu->flags &= ~(X86_F_CF | X86_F_OF);
                }
                break;
            }
            case 0xB2: case 0xB4: case 0xB5: { /* LSS, LFS, LGS */
                u8 m = x86_fetch8(cpu);
                int reg = (m >> 3) & 7;
                if ((m >> 6) != 3) {
                    int s; u16 o;
                    x86_ea_decode(cpu, m, ad32, sego, &s, &o);
                    X86_R16(cpu, reg) = x86_seg_rw(cpu, s, o);
                    int dst_sr = (op2 == 0xB2u) ? X86_SS : ((op2 == 0xB4u) ? X86_FS : X86_GS);
                    x86_set_sr(cpu, dst_sr, x86_seg_rw(cpu, s, (u16)(o + 2u)));
                    if (dst_sr == X86_SS) cpu->int_inhibit = 1;
                }
                break;
            }
            case 0xB6: { /* MOVZX r16/32, r/m8 */
                u8 m = x86_fetch8(cpu);
                int reg = (m >> 3) & 7;
                u8 v = ((m >> 6) == 3) ? X86_R8(cpu, m & 7) : ({ int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); x86_seg_rb(cpu, s, o); });
                if (!op32) X86_R16(cpu, reg) = v;
                else       X86_R32(cpu, reg) = v;
                break;
            }
            case 0xB7: { /* MOVZX r32, r/m16 */
                u8 m = x86_fetch8(cpu);
                int reg = (m >> 3) & 7;
                u16 v = ((m >> 6) == 3) ? X86_R16(cpu, m & 7) : ({ int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); x86_seg_rw(cpu, s, o); });
                if (!op32) X86_R16(cpu, reg) = v;
                else       X86_R32(cpu, reg) = v;
                break;
            }
            case 0xBE: { /* MOVSX r16/32, r/m8 */
                u8 m = x86_fetch8(cpu);
                int reg = (m >> 3) & 7;
                s8 v = (s8)(((m >> 6) == 3) ? X86_R8(cpu, m & 7) : ({ int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); x86_seg_rb(cpu, s, o); }));
                if (!op32) X86_R16(cpu, reg) = (u16)(s16)v;
                else       X86_R32(cpu, reg) = (u32)(s32)v;
                break;
            }
            case 0xBF: { /* MOVSX r32, r/m16 */
                u8 m = x86_fetch8(cpu);
                int reg = (m >> 3) & 7;
                s16 v = (s16)(((m >> 6) == 3) ? X86_R16(cpu, m & 7) : ({ int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); x86_seg_rw(cpu, s, o); }));
                if (!op32) X86_R16(cpu, reg) = (u16)v;
                else       X86_R32(cpu, reg) = (u32)(s32)v;
                break;
            }
            case 0xA3: case 0xAB: case 0xB3: case 0xBB: case 0xBA: { /* BT, BTS, BTR, BTC */
                u8 m = x86_fetch8(cpu);
                int bop = (op2 == 0xBAu) ? ((m >> 3) & 3) : (((op2 >> 3) - 4) & 3);
                int s = 0; u16 o = 0;
                u16 v = ((m >> 6) == 3) ? X86_R16(cpu, m & 7) : (x86_ea_decode(cpu, m, ad32, sego, &s, &o), x86_seg_rw(cpu, s, o));
                u8 bit = ((op2 == 0xBAu) ? x86_fetch8(cpu) : X86_R8(cpu, (m >> 3) & 7)) & 15u;
                u16 mask = (u16)(1u << bit);
                cpu->flags = (u16)((cpu->flags & ~X86_F_CF) | ((v & mask) ? X86_F_CF : 0));
                if (bop != 0) {
                    if (bop == 1) v |= mask;
                    else if (bop == 2) v &= (u16)~mask;
                    else v ^= mask;
                    if ((m >> 6) == 3) X86_R16(cpu, m & 7) = v; else x86_seg_ww(cpu, s, o, v);
                }
                break;
            }
            case 0xBC: case 0xBD: { /* BSF / BSR */
                u8 m = x86_fetch8(cpu);
                int reg = (m >> 3) & 7;
                u16 v = ((m >> 6) == 3) ? X86_R16(cpu, m & 7) : ({ int s; u16 o; x86_ea_decode(cpu, m, ad32, sego, &s, &o); x86_seg_rw(cpu, s, o); });
                if (v == 0) {
                    cpu->flags |= X86_F_ZF;
                } else {
                    cpu->flags &= ~X86_F_ZF;
                    int idx = 0;
                    if (op2 == 0xBCu) { while (!(v & (1u << idx))) idx++; }
                    else              { idx = 15; while (!(v & (1u << idx))) idx--; }
                    X86_R16(cpu, reg) = (u16)idx;
                }
                break;
            }
            default:
                break;
            }
            break;
        }

        default:
            break;
        }
    }
}
