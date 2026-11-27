/* m6809.inc: Shared Motorola MC6809E 8/16-bit CPU engine.
   Zero static .bss (all mutable state lives in `struct m6809`).
   Shared by konami.c (Contra / Golden-Era Konami) and williams.c (Defender, Robotron, Joust, Sinistar).

   Before including, define:
     M6809_RB(ctx, addr)        -> u8
     M6809_WB(ctx, addr, val)   -> void
   Optional:
     M6809_OP(ctx, addr)        -> u8  (opcode fetch hook for Konami-1 encrypted opcodes; defaults to M6809_RB) */

#ifndef DEMO_M6809_INC
#define DEMO_M6809_INC

#define M6809_C  0x01u
#define M6809_V  0x02u
#define M6809_Z  0x04u
#define M6809_N  0x08u
#define M6809_I  0x10u
#define M6809_H  0x20u
#define M6809_F  0x40u
#define M6809_E  0x80u

struct m6809 {
    u8  a, b, dp, cc;
    u16 x, y, u, s, pc;
    s32 cycles;
    u8  irq_line, firq_line, nmi_pending;
    u8  halted, cwai;
    void *ctx;
};

#ifndef M6809_OP
#define M6809_OP(ctx, a) M6809_RB(ctx, a)
#endif

static inline u16 m6809_get_d(const struct m6809 *c) { return ((u16)c->a << 8) | c->b; }
static inline void m6809_set_d(struct m6809 *c, u16 v) { c->a = (u8)(v >> 8); c->b = (u8)v; }

static inline u16 m6809_rw(struct m6809 *c, u16 a)
{
    u16 hi = M6809_RB(c->ctx, a);
    u16 lo = M6809_RB(c->ctx, (u16)(a + 1u));
    return (u16)((hi << 8) | lo);
}

static inline void m6809_ww(struct m6809 *c, u16 a, u16 v)
{
    M6809_WB(c->ctx, a, (u8)(v >> 8));
    M6809_WB(c->ctx, (u16)(a + 1u), (u8)v);
}

static inline u8 m6809_fetch8(struct m6809 *c)
{
    return M6809_RB(c->ctx, c->pc++);
}

static inline u8 m6809_fetch_op(struct m6809 *c)
{
    return M6809_OP(c->ctx, c->pc++);
}

static inline u16 m6809_fetch16(struct m6809 *c)
{
    u16 hi = m6809_fetch8(c);
    u16 lo = m6809_fetch8(c);
    return (u16)((hi << 8) | lo);
}

static inline void m6809_push8(struct m6809 *c, u16 *sp, u8 v)
{
    (*sp)--;
    M6809_WB(c->ctx, *sp, v);
}

static inline void m6809_push16(struct m6809 *c, u16 *sp, u16 v)
{
    m6809_push8(c, sp, (u8)v);
    m6809_push8(c, sp, (u8)(v >> 8));
}

static inline u8 m6809_pull8(struct m6809 *c, u16 *sp)
{
    return M6809_RB(c->ctx, (*sp)++);
}

static inline u16 m6809_pull16(struct m6809 *c, u16 *sp)
{
    u16 hi = m6809_pull8(c, sp);
    u16 lo = m6809_pull8(c, sp);
    return (u16)((hi << 8) | lo);
}

static void m6809_push_state(struct m6809 *c, int entire)
{
    if (entire) c->cc |= M6809_E;
    else        c->cc &= (u8)~M6809_E;
    m6809_push16(c, &c->s, c->pc);
    if (entire) {
        m6809_push16(c, &c->s, c->u);
        m6809_push16(c, &c->s, c->y);
        m6809_push16(c, &c->s, c->x);
        m6809_push8(c, &c->s, c->dp);
        m6809_push8(c, &c->s, c->b);
        m6809_push8(c, &c->s, c->a);
    }
    m6809_push8(c, &c->s, c->cc);
}

static void m6809_reset(struct m6809 *c, void *ctx)
{
    c->ctx = ctx;
    c->a = c->b = c->dp = 0;
    c->x = c->y = c->u = c->s = 0;
    c->cc = M6809_I | M6809_F;
    c->cycles = 0;
    c->irq_line = c->firq_line = c->nmi_pending = 0;
    c->halted = c->cwai = 0;
    c->pc = m6809_rw(c, 0xFFFEu);
}

static void m6809_take_interrupts(struct m6809 *c)
{
    if (c->nmi_pending) {
        c->nmi_pending = 0;
        c->halted = 0;
        if (!c->cwai) m6809_push_state(c, 1);
        c->cwai = 0;
        c->cc |= (M6809_I | M6809_F);
        c->pc = m6809_rw(c, 0xFFFCu);
        c->cycles += 19;
        return;
    }
    if (c->firq_line && !(c->cc & M6809_F)) {
        c->halted = 0;
        if (!c->cwai) m6809_push_state(c, 0);
        c->cwai = 0;
        c->cc |= (M6809_I | M6809_F);
        c->pc = m6809_rw(c, 0xFFF6u);
        c->cycles += 10;
        return;
    }
    if (c->irq_line && !(c->cc & M6809_I)) {
        c->halted = 0;
        if (!c->cwai) m6809_push_state(c, 1);
        c->cwai = 0;
        c->cc |= M6809_I;
        c->pc = m6809_rw(c, 0xFFF8u);
        c->cycles += 19;
    }
}

static u16 *m6809_idx_reg(struct m6809 *c, int r)
{
    switch (r & 3) {
    case 0: return &c->x;
    case 1: return &c->y;
    case 2: return &c->u;
    default: return &c->s;
    }
}

static u16 m6809_ea_indexed(struct m6809 *c)
{
    u8 pb = m6809_fetch8(c);
    if (!(pb & 0x80u)) {
        u16 *rp = m6809_idx_reg(c, pb >> 5);
        s8 off5 = (s8)((s8)(pb << 3) >> 3);
        c->cycles += 1;
        return (u16)(*rp + (s16)off5);
    }
    u16 *rp = m6809_idx_reg(c, pb >> 5);
    u16 ea = 0;
    int ind = (pb & 0x10u) != 0;
    switch (pb & 0x0Fu) {
    case 0x00: ea = *rp; (*rp)++; c->cycles += 2; break;
    case 0x01: ea = *rp; (*rp) += 2u; c->cycles += 3; break;
    case 0x02: (*rp)--; ea = *rp; c->cycles += 2; break;
    case 0x03: (*rp) -= 2u; ea = *rp; c->cycles += 3; break;
    case 0x04: ea = *rp; break;
    case 0x05: ea = (u16)(*rp + (s16)(s8)c->b); c->cycles += 1; break;
    case 0x06: ea = (u16)(*rp + (s16)(s8)c->a); c->cycles += 1; break;
    case 0x08: ea = (u16)(*rp + (s16)(s8)m6809_fetch8(c)); c->cycles += 1; break;
    case 0x09: ea = (u16)(*rp + m6809_fetch16(c)); c->cycles += 4; break;
    case 0x0B: ea = (u16)(*rp + (s16)m6809_get_d(c)); c->cycles += 4; break;
    case 0x0C: { s8 d = (s8)m6809_fetch8(c); ea = (u16)(c->pc + (s16)d); c->cycles += 1; break; }
    case 0x0D: { u16 d = m6809_fetch16(c); ea = (u16)(c->pc + d); c->cycles += 5; break; }
    case 0x0F: ea = m6809_fetch16(c); c->cycles += 2; break;
    default: ea = *rp; break;
    }
    if (ind) {
        ea = m6809_rw(c, ea);
        c->cycles += 3;
    }
    return ea;
}

static inline void m6809_nz8(struct m6809 *c, u8 v)
{
    c->cc = (u8)((c->cc & ~(M6809_N | M6809_Z | M6809_V)) | ((v & 0x80u) ? M6809_N : 0) | (v == 0 ? M6809_Z : 0));
}

static inline void m6809_nz16(struct m6809 *c, u16 v)
{
    c->cc = (u8)((c->cc & ~(M6809_N | M6809_Z | M6809_V)) | ((v & 0x8000u) ? M6809_N : 0) | (v == 0 ? M6809_Z : 0));
}

static u8 m6809_add8(struct m6809 *c, u8 a, u8 b, u8 cy)
{
    u16 r = (u16)a + (u16)b + cy;
    u8 r8 = (u8)r;
    u8 f = (u8)(c->cc & ~(M6809_H | M6809_N | M6809_Z | M6809_V | M6809_C));
    if ((a ^ b ^ r) & 0x10u) f |= M6809_H;
    if (r8 & 0x80u) f |= M6809_N;
    if (r8 == 0)    f |= M6809_Z;
    if ((~(a ^ b) & (a ^ r)) & 0x80u) f |= M6809_V;
    if (r & 0x100u) f |= M6809_C;
    c->cc = f;
    return r8;
}

static u8 m6809_sub8(struct m6809 *c, u8 a, u8 b, u8 cy)
{
    u16 r = (u16)a - (u16)b - cy;
    u8 r8 = (u8)r;
    u8 f = (u8)(c->cc & ~(M6809_N | M6809_Z | M6809_V | M6809_C));
    if (r8 & 0x80u) f |= M6809_N;
    if (r8 == 0)    f |= M6809_Z;
    if (((a ^ b) & (a ^ r)) & 0x80u) f |= M6809_V;
    if (r & 0x100u) f |= M6809_C;
    c->cc = f;
    return r8;
}

static u16 m6809_add16(struct m6809 *c, u16 a, u16 b)
{
    u32 r = (u32)a + (u32)b;
    u16 r16 = (u16)r;
    u8 f = (u8)(c->cc & ~(M6809_N | M6809_Z | M6809_V | M6809_C));
    if (r16 & 0x8000u) f |= M6809_N;
    if (r16 == 0)      f |= M6809_Z;
    if ((~(a ^ b) & (a ^ r)) & 0x8000u) f |= M6809_V;
    if (r & 0x10000u)  f |= M6809_C;
    c->cc = f;
    return r16;
}

static u16 m6809_sub16(struct m6809 *c, u16 a, u16 b)
{
    u32 r = (u32)a - (u32)b;
    u16 r16 = (u16)r;
    u8 f = (u8)(c->cc & ~(M6809_N | M6809_Z | M6809_V | M6809_C));
    if (r16 & 0x8000u) f |= M6809_N;
    if (r16 == 0)      f |= M6809_Z;
    if (((a ^ b) & (a ^ r)) & 0x8000u) f |= M6809_V;
    if (r & 0x10000u)  f |= M6809_C;
    c->cc = f;
    return r16;
}

static u8 m6809_rmw8(struct m6809 *c, u8 sub, u8 v)
{
    switch (sub & 0x0Fu) {
    case 0x0: return m6809_sub8(c, 0, v, 0); /* NEG */
    case 0x3: { u8 r = (u8)~v; m6809_nz8(c, r); c->cc |= M6809_C; return r; } /* COM */
    case 0x4: { u8 cy = v & 1u; u8 r = v >> 1; m6809_nz8(c, r); c->cc = (u8)((c->cc & ~M6809_C) | cy); return r; } /* LSR */
    case 0x6: { u8 cy = v & 1u; u8 r = (u8)((v >> 1) | ((c->cc & M6809_C) ? 0x80u : 0)); m6809_nz8(c, r); c->cc = (u8)((c->cc & ~M6809_C) | cy); return r; } /* ROR */
    case 0x7: { u8 cy = v & 1u; u8 r = (u8)((s8)v >> 1); m6809_nz8(c, r); c->cc = (u8)((c->cc & ~M6809_C) | cy); return r; } /* ASR */
    case 0x8: { u8 cy = (v >> 7) & 1u; u8 r = (u8)(v << 1); m6809_nz8(c, r); c->cc = (u8)((c->cc & ~(M6809_C | M6809_V)) | cy | ((((v >> 7) ^ (v >> 6)) & 1u) ? M6809_V : 0)); return r; } /* ASL */
    case 0x9: { u8 cy = (v >> 7) & 1u; u8 r = (u8)((v << 1) | (c->cc & M6809_C)); m6809_nz8(c, r); c->cc = (u8)((c->cc & ~(M6809_C | M6809_V)) | cy | ((((v >> 7) ^ (v >> 6)) & 1u) ? M6809_V : 0)); return r; } /* ROL */
    case 0xA: { u8 r = (u8)(v - 1u); m6809_nz8(c, r); if (v == 0x80u) c->cc |= M6809_V; return r; } /* DEC */
    case 0xC: { u8 r = (u8)(v + 1u); m6809_nz8(c, r); if (v == 0x7Fu) c->cc |= M6809_V; return r; } /* INC */
    case 0xD: m6809_nz8(c, v); return v; /* TST */
    case 0xF: c->cc = (u8)((c->cc & ~(M6809_N | M6809_V | M6809_C)) | M6809_Z); return 0; /* CLR */
    default: return v;
    }
}

static int m6809_cond(const struct m6809 *c, u8 cc_op)
{
    u8 f = c->cc;
    int n = (f & M6809_N) != 0, v = (f & M6809_V) != 0, z = (f & M6809_Z) != 0, cy = (f & M6809_C) != 0;
    switch (cc_op & 0x0Fu) {
    case 0x0: return 1;              /* BRA */
    case 0x1: return 0;              /* BRN */
    case 0x2: return !(cy || z);     /* BHI */
    case 0x3: return (cy || z);      /* BLS */
    case 0x4: return !cy;            /* BCC */
    case 0x5: return cy;             /* BCS */
    case 0x6: return !z;             /* BNE */
    case 0x7: return z;              /* BEQ */
    case 0x8: return !v;             /* BVC */
    case 0x9: return v;              /* BVS */
    case 0xA: return !n;             /* BPL */
    case 0xB: return n;              /* BMI */
    case 0xC: return n == v;         /* BGE */
    case 0xD: return n != v;         /* BLT */
    case 0xE: return !z && (n == v); /* BGT */
    default:  return z || (n != v);  /* BLE */
    }
}

static u16 m6809_get_r(const struct m6809 *c, int id)
{
    switch (id & 15) {
    case 0: return m6809_get_d(c);
    case 1: return c->x;
    case 2: return c->y;
    case 3: return c->u;
    case 4: return c->s;
    case 5: return c->pc;
    case 8: return 0xFF00u | c->a;
    case 9: return 0xFF00u | c->b;
    case 10: return 0xFF00u | c->cc;
    case 11: return 0xFF00u | c->dp;
    default: return 0xFFFFu;
    }
}

static void m6809_set_r(struct m6809 *c, int id, u16 v)
{
    switch (id & 15) {
    case 0: m6809_set_d(c, v); break;
    case 1: c->x = v; break;
    case 2: c->y = v; break;
    case 3: c->u = v; break;
    case 4: c->s = v; break;
    case 5: c->pc = v; break;
    case 8: c->a = (u8)v; break;
    case 9: c->b = (u8)v; break;
    case 10: c->cc = (u8)v; break;
    case 11: c->dp = (u8)v; break;
    default: break;
    }
}

static void __attribute__((optimize("Os"))) m6809_run(struct m6809 *c, s32 target)
{
    while (c->cycles < target) {
        m6809_take_interrupts(c);
        if (c->halted) {
            c->cycles = target;
            return;
        }

        u8 op = m6809_fetch_op(c);
        c->cycles += 2;

        /* 0x00..0x0F Direct, 0x60..0x6F Indexed, 0x70..0x7F Extended RMW / JMP */
        if ((op & 0xF0u) == 0x00u || (op & 0xF0u) == 0x60u || (op & 0xF0u) == 0x70u) {
            u16 ea = ((op & 0xF0u) == 0x00u) ? (u16)(((u16)c->dp << 8) | m6809_fetch8(c))
                   : ((op & 0xF0u) == 0x60u) ? m6809_ea_indexed(c)
                   : m6809_fetch16(c);
            u8 sub = op & 0x0Fu;
            if (sub == 0x0Eu) { c->pc = ea; c->cycles += 1; continue; } /* JMP */
            u8 v = M6809_RB(c->ctx, ea);
            u8 nv = m6809_rmw8(c, sub, v);
            if (sub != 0x0Du) M6809_WB(c->ctx, ea, nv);
            c->cycles += 4;
            continue;
        }

        /* 0x40..0x4F A inherent, 0x50..0x5F B inherent */
        if ((op & 0xE0u) == 0x40u) {
            u8 *reg = (op & 0x10u) ? &c->b : &c->a;
            *reg = m6809_rmw8(c, op & 0x0Fu, *reg);
            continue;
        }

        /* 0x20..0x2F Short Branches */
        if ((op & 0xF0u) == 0x20u) {
            s8 rel = (s8)m6809_fetch8(c);
            if (m6809_cond(c, op & 0x0Fu))
                c->pc = (u16)(c->pc + (s16)rel);
            c->cycles += 1;
            continue;
        }

        /* 0x80..0xFF Register/Memory ALU & Load/Store */
        if (op >= 0x80u) {
            int side = (op >> 6) & 1; /* 0 = A/D/X/S, 1 = B/D/U */
            int mode = (op >> 4) & 3; /* 0=imm, 1=dir, 2=idx, 3=ext */
            int fn   = op & 0x0F;
            u16 ea = 0;
            if (mode == 1)      { ea = (u16)(((u16)c->dp << 8) | m6809_fetch8(c)); c->cycles += 2; }
            else if (mode == 2) { ea = m6809_ea_indexed(c); c->cycles += 2; }
            else if (mode == 3) { ea = m6809_fetch16(c); c->cycles += 3; }

            /* 8-bit ops: 0=SUB, 1=CMP, 2=SBC, 4=AND, 5=BIT, 6=LD, 7=ST, 8=EOR, 9=ADC, A=OR, B=ADD */
            if (fn == 0 || fn == 1 || fn == 2 || fn == 4 || fn == 5 || fn == 6 || fn == 7 || fn == 8 || fn == 9 || fn == 10 || fn == 11) {
                u8 *acc = side ? &c->b : &c->a;
                if (fn == 7) { /* STA / STB */
                    M6809_WB(c->ctx, ea, *acc);
                    m6809_nz8(c, *acc);
                    continue;
                }
                u8 m = (mode == 0) ? m6809_fetch8(c) : M6809_RB(c->ctx, ea);
                switch (fn) {
                case 0: *acc = m6809_sub8(c, *acc, m, 0); break;
                case 1: (void)m6809_sub8(c, *acc, m, 0); break;
                case 2: *acc = m6809_sub8(c, *acc, m, c->cc & M6809_C); break;
                case 4: *acc &= m; m6809_nz8(c, *acc); break;
                case 5: m6809_nz8(c, (u8)(*acc & m)); break;
                case 6: *acc = m; m6809_nz8(c, *acc); break;
                case 8: *acc ^= m; m6809_nz8(c, *acc); break;
                case 9: *acc = m6809_add8(c, *acc, m, c->cc & M6809_C); break;
                case 10: *acc |= m; m6809_nz8(c, *acc); break;
                default: *acc = m6809_add8(c, *acc, m, 0); break;
                }
                continue;
            }

            /* 16-bit ops: fn 3 (SUBD/ADDD), C (CMPX/LDD), D (BSR/JSR/STD), E (LDX/LDU), F (STX/STU) */
            if (!side && fn == 0x0Du && mode == 0) { /* 0x8D BSR */
                s8 rel = (s8)m6809_fetch8(c);
                m6809_push16(c, &c->s, c->pc);
                c->pc = (u16)(c->pc + (s16)rel);
                c->cycles += 5;
                continue;
            }
            if (!side && fn == 0x0Du) { /* 0x9D/AD/BD JSR */
                m6809_push16(c, &c->s, c->pc);
                c->pc = ea;
                c->cycles += 5;
                continue;
            }
            if (side && fn == 0x0Du) { /* STD */
                u16 d = m6809_get_d(c);
                m6809_ww(c, ea, d);
                m6809_nz16(c, d);
                c->cycles += 1;
                continue;
            }
            if (fn == 0x0Fu) { /* STX / STU */
                u16 v = side ? c->u : c->x;
                m6809_ww(c, ea, v);
                m6809_nz16(c, v);
                c->cycles += 1;
                continue;
            }
            u16 m16 = (mode == 0) ? m6809_fetch16(c) : m6809_rw(c, ea);
            c->cycles += 2;
            if (fn == 0x03) {
                if (!side) m6809_set_d(c, m6809_sub16(c, m6809_get_d(c), m16)); /* SUBD */
                else       m6809_set_d(c, m6809_add16(c, m6809_get_d(c), m16)); /* ADDD */
            } else if (fn == 0x0C) {
                if (!side) (void)m6809_sub16(c, c->x, m16);                     /* CMPX */
                else { m6809_set_d(c, m16); m6809_nz16(c, m16); }               /* LDD */
            } else if (fn == 0x0E) {
                if (!side) c->x = m16; else c->u = m16;
                m6809_nz16(c, m16);
            }
            continue;
        }

        switch (op) {
        case 0x12: break; /* NOP */
        case 0x13: c->halted = 1; break; /* SYNC */
        case 0x16: { u16 rel = m6809_fetch16(c); c->pc = (u16)(c->pc + rel); c->cycles += 3; break; } /* LBRA */
        case 0x17: { u16 rel = m6809_fetch16(c); m6809_push16(c, &c->s, c->pc); c->pc = (u16)(c->pc + rel); c->cycles += 7; break; } /* LBSR */
        case 0x19: { /* DAA */
            u8 cf = 0;
            u8 msn = c->a & 0xF0u, lsn = c->a & 0x0Fu;
            if (lsn > 0x09u || (c->cc & M6809_H)) cf |= 0x06u;
            if (msn > 0x80u && lsn > 0x09u) cf |= 0x60u;
            if (msn > 0x90u || (c->cc & M6809_C)) cf |= 0x60u;
            u16 t = (u16)c->a + cf;
            c->a = (u8)t;
            m6809_nz8(c, c->a);
            if (t & 0x100u) c->cc |= M6809_C;
            break;
        }
        case 0x1A: c->cc |= m6809_fetch8(c); break; /* ORCC */
        case 0x1C: c->cc &= m6809_fetch8(c); break; /* ANDCC */
        case 0x1D: c->a = (c->b & 0x80u) ? 0xFFu : 0x00u; m6809_nz16(c, m6809_get_d(c)); break; /* SEX */
        case 0x1E: { /* EXG */
            u8 pb = m6809_fetch8(c);
            u16 r1 = m6809_get_r(c, pb >> 4), r2 = m6809_get_r(c, pb & 15);
            m6809_set_r(c, pb >> 4, r2);
            m6809_set_r(c, pb & 15, r1);
            c->cycles += 6;
            break;
        }
        case 0x1F: { /* TFR */
            u8 pb = m6809_fetch8(c);
            m6809_set_r(c, pb & 15, m6809_get_r(c, pb >> 4));
            c->cycles += 4;
            break;
        }

        /* 0x30..0x33 LEAX, LEAY, LEAS, LEAU */
        case 0x30: c->x = m6809_ea_indexed(c); c->cc = (u8)((c->cc & ~M6809_Z) | (c->x == 0 ? M6809_Z : 0)); break;
        case 0x31: c->y = m6809_ea_indexed(c); c->cc = (u8)((c->cc & ~M6809_Z) | (c->y == 0 ? M6809_Z : 0)); break;
        case 0x32: c->s = m6809_ea_indexed(c); break;
        case 0x33: c->u = m6809_ea_indexed(c); break;

        case 0x34: case 0x36: { /* PSHS / PSHU */
            u8 m = m6809_fetch8(c);
            u16 *sp = (op == 0x34u) ? &c->s : &c->u;
            u16 other = (op == 0x34u) ? c->u : c->s;
            if (m & 0x80u) { m6809_push16(c, sp, c->pc); c->cycles += 2; }
            if (m & 0x40u) { m6809_push16(c, sp, other); c->cycles += 2; }
            if (m & 0x20u) { m6809_push16(c, sp, c->y);  c->cycles += 2; }
            if (m & 0x10u) { m6809_push16(c, sp, c->x);  c->cycles += 2; }
            if (m & 0x08u) { m6809_push8(c, sp, c->dp);  c->cycles += 1; }
            if (m & 0x04u) { m6809_push8(c, sp, c->b);   c->cycles += 1; }
            if (m & 0x02u) { m6809_push8(c, sp, c->a);   c->cycles += 1; }
            if (m & 0x01u) { m6809_push8(c, sp, c->cc);  c->cycles += 1; }
            c->cycles += 3;
            break;
        }
        case 0x35: case 0x37: { /* PULS / PULU */
            u8 m = m6809_fetch8(c);
            u16 *sp = (op == 0x35u) ? &c->s : &c->u;
            u16 *other = (op == 0x35u) ? &c->u : &c->s;
            if (m & 0x01u) { c->cc = m6809_pull8(c, sp); c->cycles += 1; }
            if (m & 0x02u) { c->a  = m6809_pull8(c, sp); c->cycles += 1; }
            if (m & 0x04u) { c->b  = m6809_pull8(c, sp); c->cycles += 1; }
            if (m & 0x08u) { c->dp = m6809_pull8(c, sp); c->cycles += 1; }
            if (m & 0x10u) { c->x  = m6809_pull16(c, sp); c->cycles += 2; }
            if (m & 0x20u) { c->y  = m6809_pull16(c, sp); c->cycles += 2; }
            if (m & 0x40u) { *other= m6809_pull16(c, sp); c->cycles += 2; }
            if (m & 0x80u) { c->pc = m6809_pull16(c, sp); c->cycles += 2; }
            c->cycles += 3;
            break;
        }
        case 0x39: c->pc = m6809_pull16(c, &c->s); c->cycles += 3; break; /* RTS */
        case 0x3A: c->x = (u16)(c->x + c->b); c->cycles += 1; break; /* ABX */
        case 0x3B: { /* RTI */
            c->cc = m6809_pull8(c, &c->s);
            if (c->cc & M6809_E) {
                c->a  = m6809_pull8(c, &c->s);
                c->b  = m6809_pull8(c, &c->s);
                c->dp = m6809_pull8(c, &c->s);
                c->x  = m6809_pull16(c, &c->s);
                c->y  = m6809_pull16(c, &c->s);
                c->u  = m6809_pull16(c, &c->s);
                c->cycles += 9;
            }
            c->pc = m6809_pull16(c, &c->s);
            c->cycles += 4;
            break;
        }
        case 0x3C: { /* CWAI */
            c->cc &= m6809_fetch8(c);
            m6809_push_state(c, 1);
            c->cwai = 1;
            c->halted = 1;
            break;
        }
        case 0x3D: { /* MUL */
            u16 p = (u16)c->a * (u16)c->b;
            m6809_set_d(c, p);
            c->cc = (u8)((c->cc & ~(M6809_Z | M6809_C)) | (p == 0 ? M6809_Z : 0) | ((p & 0x80u) ? M6809_C : 0));
            c->cycles += 9;
            break;
        }
        case 0x3F: /* SWI */
            m6809_push_state(c, 1);
            c->cc |= (M6809_I | M6809_F);
            c->pc = m6809_rw(c, 0xFFFAu);
            c->cycles += 17;
            break;

        /* Page 0x10 & Page 0x11 extended instructions */
        case 0x10: {
            u8 op2 = m6809_fetch_op(c);
            c->cycles += 1;
            if ((op2 & 0xF0u) == 0x20u) {
                u16 rel = m6809_fetch16(c);
                if (m6809_cond(c, op2 & 0x0Fu)) { c->pc = (u16)(c->pc + rel); c->cycles += 1; }
                c->cycles += 3;
                break;
            }
            if (op2 == 0x3Fu) { /* SWI2 */
                m6809_push_state(c, 1);
                c->pc = m6809_rw(c, 0xFFF4u);
                c->cycles += 18;
                break;
            }
            int mode = (op2 >> 4) & 3;
            int fn = op2 & 0x0F;
            int side = (op2 >> 6) & 1;
            u16 ea = 0;
            if (mode == 1) ea = (u16)(((u16)c->dp << 8) | m6809_fetch8(c));
            else if (mode == 2) ea = m6809_ea_indexed(c);
            else if (mode == 3) ea = m6809_fetch16(c);
            if (!side && fn == 0x0F) { m6809_ww(c, ea, c->y); m6809_nz16(c, c->y); break; } /* STY */
            if (side  && fn == 0x0F) { m6809_ww(c, ea, c->s); m6809_nz16(c, c->s); break; } /* STS */
            u16 m16 = (mode == 0) ? m6809_fetch16(c) : m6809_rw(c, ea);
            if (!side && fn == 0x03) (void)m6809_sub16(c, m6809_get_d(c), m16); /* CMPD */
            else if (!side && fn == 0x0C) (void)m6809_sub16(c, c->y, m16);       /* CMPY */
            else if (!side && fn == 0x0E) { c->y = m16; m6809_nz16(c, m16); }    /* LDY */
            else if (side  && fn == 0x0E) { c->s = m16; m6809_nz16(c, m16); }    /* LDS */
            c->cycles += 3;
            break;
        }
        case 0x11: {
            u8 op2 = m6809_fetch_op(c);
            c->cycles += 1;
            if (op2 == 0x3Fu) { /* SWI3 */
                m6809_push_state(c, 1);
                c->pc = m6809_rw(c, 0xFFF2u);
                c->cycles += 18;
                break;
            }
            int mode = (op2 >> 4) & 3;
            int fn = op2 & 0x0F;
            u16 ea = 0;
            if (mode == 1) ea = (u16)(((u16)c->dp << 8) | m6809_fetch8(c));
            else if (mode == 2) ea = m6809_ea_indexed(c);
            else if (mode == 3) ea = m6809_fetch16(c);
            u16 m16 = (mode == 0) ? m6809_fetch16(c) : m6809_rw(c, ea);
            if (fn == 0x03) (void)m6809_sub16(c, c->u, m16);      /* CMPU */
            else if (fn == 0x0C) (void)m6809_sub16(c, c->s, m16); /* CMPS */
            c->cycles += 3;
            break;
        }
        default:
            break;
        }
    }
}

#endif
