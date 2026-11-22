/* A Zilog Z80: see z80.h.

   One instruction at a time, each counted the way the chip spends its
   T-states: an opcode fetch 4 (and R counts one), a memory read or write
   3, an I/O access 4, and the cycles where the chip only works inside
   (an ADD HL,rr's 7, a JR's 5, ...) one by one, each with the address the
   chip then leaves on its bus -- which is what a Spectrum's ULA looks at
   when it holds the CPU up (`idle`).  Without contention (cont_n 0) all of
   that is just additions.

   The prefixes: DD and FD put IX or IY where HL was (and their halves for H
   and L, except in an instruction that also uses (HL), which then is
   (IX+d)); a prefix followed by another prefix is a NOP of its own.  CB,
   ED, DDCB and FDCB are their own tables.

   The unnamed flags (bits 3 and 5, X and Y): from the result mostly, from
   the operand on CP, from MEMPTR's high byte on BIT n,(HL), from the PC's
   high byte when a block instruction repeats; SCF and CCF take them from
   ((the flags the previous instruction set) ^ F) | A, as a Zilog chip does. */
#include "z80.h"

typedef signed char s8;

#define FC Z80_FC
#define FN Z80_FN
#define FP Z80_FP
#define FX Z80_FX
#define FH Z80_FH
#define FY Z80_FY
#define FZ Z80_FZ
#define FS Z80_FS

static u8 sz53[256], sz53p[256];        /* S, Z, Y, X of a result (and P: its parity is even) */
static u8 roff[3][8];                   /* where B C D E H L - A are in struct z80: plain, with IX, with IY */

#define A  c->af.b.h
#define F  c->af.b.l
#define B  c->bc.b.h
#define C  c->bc.b.l
#define D  c->de.b.h
#define E  c->de.b.l
#define BC c->bc.w
#define DE c->de.w
#define HL c->hl.w
#define SP c->sp.w
#define PC c->pc.w
#define WZ c->wz.w
#define T  c->cycles
#define IR ((u16)(c->i << 8 | (c->r & 0x7F)))
#define SETF(v) (c->q = F = (u8)(v))    /* the flags, as an instruction that sets them */
#define CONTENDED(a) ((u16)((a) - c->cont_lo) < c->cont_n)

/* ---- the bus ---- */
static inline void cont(struct z80 *c, u16 a)
{
    if (CONTENDED(a))
        T += c->cont[T];
}

static inline u8 rd(struct z80 *c, u16 a)
{
    cont(c, a);
    T += 3;
    const u8 *p = c->rd[a >> 10];
    return p ? p[a & 0x3FF] : c->read(c, a);
}

static inline void wr(struct z80 *c, u16 a, u8 v)
{
    cont(c, a);
    T += 3;
    u8 *p = c->wr[a >> 10];
    if (p)
        p[a & 0x3FF] = v;
    else
        c->write(c, a, v);
}

static inline u8 fetch(struct z80 *c)
{
    u16 a = PC++;
    cont(c, a);
    T += 4;
    c->r++;
    const u8 *p = c->op[a >> 10] ? c->op[a >> 10] : c->rd[a >> 10];
    return p ? p[a & 0x3FF] : c->read(c, a);
}

/* n T-states of the CPU working inside, address a on the bus */
static inline void idle(struct z80 *c, u16 a, int n)
{
    if (CONTENDED(a))
        do
            T += c->cont[T] + 1;
        while (--n);
    else
        T += n;
}

static inline u8 imm(struct z80 *c)
{
    return rd(c, PC++);
}

static inline u16 imm16(struct z80 *c)
{
    u8 lo = imm(c);
    return (u16)(imm(c) << 8 | lo);
}

static inline void push(struct z80 *c, u16 v)
{
    wr(c, --SP, (u8)(v >> 8));
    wr(c, --SP, (u8)v);
}

static inline u16 pop(struct z80 *c)
{
    u8 lo = rd(c, SP++);
    return (u16)(rd(c, SP++) << 8 | lo);
}

/* I/O: the ULA's way of holding the CPU up (a port with bit 0 clear is the ULA's own: it holds the CPU
   whatever the high byte; a high byte in contended memory's range holds it at every T-state) */
static void port_early(struct z80 *c, u16 port)
{
    cont(c, port);
    T++;
}

static void port_late(struct z80 *c, u16 port)
{
    if (!c->cont_n)
        T += 3;
    else if (!(port & 1))
        T += c->cont[T] + 3;
    else
        idle(c, port, 3);
}

static u8 in(struct z80 *c, u16 port)
{
    if (!c->cont_n) {                   /* (the byte is taken in the I/O cycle's third T-state) */
        T += 3;
        u8 v = c->in(c, port);
        T++;
        return v;
    }
    port_early(c, port);
    port_late(c, port);
    return c->in(c, port);
}

static void out(struct z80 *c, u16 port, u8 v)
{
    port_early(c, port);
    c->out(c, port, v);
    port_late(c, port);
}

/* ---- arithmetic ---- */
static inline void add8(struct z80 *c, u8 v, u32 carry)
{
    u32 a = A, r = a + v + carry;
    SETF(sz53[r & 0xFF] | (r >> 8) | ((a ^ v ^ r) & FH) | (((a ^ v ^ 0x80) & (a ^ r) & 0x80) >> 5));
    A = (u8)r;
}

static inline u8 sub8(struct z80 *c, u8 v, u32 carry)
{
    u32 a = A, r = a - v - carry;
    SETF(sz53[r & 0xFF] | FN | ((r >> 8) & 1) | ((a ^ v ^ r) & FH) | (((a ^ v) & (a ^ r) & 0x80) >> 5));
    return (u8)r;
}

static void alu(struct z80 *c, int op, u8 v)
{
    switch (op) {
    case 0: add8(c, v, 0); break;
    case 1: add8(c, v, F & FC); break;
    case 2: A = sub8(c, v, 0); break;
    case 3: A = sub8(c, v, F & FC); break;
    case 4: A &= v; SETF(sz53p[A] | FH); break;
    case 5: A ^= v; SETF(sz53p[A]); break;
    case 6: A |= v; SETF(sz53p[A]); break;
    default:                            /* CP: X and Y from the operand */
        sub8(c, v, 0);
        SETF((F & ~(FX | FY)) | (v & (FX | FY)));
        break;
    }
}

static inline u8 inc8(struct z80 *c, u8 v)
{
    v++;
    SETF((F & FC) | sz53[v] | (v == 0x80 ? FP : 0) | ((v & 0x0F) ? 0 : FH));
    return v;
}

static inline u8 dec8(struct z80 *c, u8 v)
{
    v--;
    SETF((F & FC) | FN | sz53[v] | (v == 0x7F ? FP : 0) | ((v & 0x0F) == 0x0F ? FH : 0));
    return v;
}

static void add16(struct z80 *c, union z80_pair *to, u16 v)
{
    u32 a = to->w, r = a + v;
    idle(c, IR, 7);
    WZ = (u16)(a + 1);
    SETF((F & (FS | FZ | FP)) | ((r >> 16) & FC) | ((r >> 8) & (FX | FY)) | (((a ^ v ^ r) >> 8) & FH));
    to->w = (u16)r;
}

static void adc16(struct z80 *c, u16 v)
{
    u32 a = HL, r = a + v + (F & FC);
    idle(c, IR, 7);
    WZ = (u16)(a + 1);
    SETF(((r >> 16) & FC) | ((r >> 8) & (FS | FX | FY)) | (((a ^ v ^ r) >> 8) & FH) |
         (((a ^ v ^ 0x8000) & (a ^ r) & 0x8000) >> 13) | ((r & 0xFFFF) ? 0 : FZ));
    HL = (u16)r;
}

static void sbc16(struct z80 *c, u16 v)
{
    u32 a = HL, r = a - v - (F & FC);
    idle(c, IR, 7);
    WZ = (u16)(a + 1);
    SETF(FN | ((r >> 16) & FC) | ((r >> 8) & (FS | FX | FY)) | (((a ^ v ^ r) >> 8) & FH) |
         (((a ^ v) & (a ^ r) & 0x8000) >> 13) | ((r & 0xFFFF) ? 0 : FZ));
    HL = (u16)r;
}

static inline int cond(struct z80 *c, int n)
{
    static const u8 flag[4] = {FZ, FC, FP, FS};
    return ((F & flag[n >> 1]) != 0) == (n & 1);
}

/* the CB table's rotations and shifts (op 0..7: RLC RRC RL RR SLA SRA SLL SRL) */
static u8 shift(struct z80 *c, int op, u8 v)
{
    u8 carry;
    switch (op) {
    case 0: carry = v >> 7; v = (u8)(v << 1 | carry); break;
    case 1: carry = v & 1; v = (u8)(v >> 1 | carry << 7); break;
    case 2: carry = v >> 7; v = (u8)(v << 1 | (F & FC)); break;
    case 3: carry = v & 1; v = (u8)(v >> 1 | (F & FC) << 7); break;
    case 4: carry = v >> 7; v = (u8)(v << 1); break;
    case 5: carry = v & 1; v = (u8)(v >> 1 | (v & 0x80)); break;
    case 6: carry = v >> 7; v = (u8)(v << 1 | 1); break;
    default: carry = v & 1; v >>= 1; break;
    }
    SETF(sz53p[v] | carry);
    return v;
}

/* BIT n: X and Y from `xy` (the register; MEMPTR's high byte for a byte in memory) */
static inline void bit(struct z80 *c, int n, u8 v, u8 xy)
{
    u8 f = (u8)((F & FC) | FH | (xy & (FX | FY)));
    if (v & (1u << n))
        f |= n == 7 ? FS : 0;
    else
        f |= FZ | FP;
    SETF(f);
}

/* ---- the CB table: 0..7 the register (6: (HL)) ---- */
static void cb(struct z80 *c)
{
    u8 op = fetch(c), *r = (u8 *)c + roff[0][op & 7], v;
    int n = (op >> 3) & 7;
    if ((op & 7) == 6) {
        v = rd(c, HL);
        idle(c, HL, 1);
        switch (op >> 6) {
        case 0: wr(c, HL, shift(c, n, v)); break;
        case 1: bit(c, n, v, c->wz.b.h); break;
        case 2: wr(c, HL, (u8)(v & ~(1u << n))); break;
        default: wr(c, HL, (u8)(v | (1u << n))); break;
        }
        return;
    }
    switch (op >> 6) {
    case 0: *r = shift(c, n, *r); break;
    case 1: bit(c, n, *r, *r); break;
    case 2: *r &= (u8)~(1u << n); break;
    default: *r |= (u8)(1u << n); break;
    }
}

/* DDCB d op / FDCB d op: always on (IX+d); the result also into the register the op names (but BIT) */
static void xcb(struct z80 *c, u16 base)
{
    s8 d = (s8)rd(c, PC++);
    u8 op = rd(c, PC);                  /* (not an opcode fetch: R does not count it) */
    idle(c, PC, 2);
    PC++;
    u16 a = (u16)(base + d);
    WZ = a;
    u8 v = rd(c, a);
    idle(c, a, 1);
    int n = (op >> 3) & 7;
    switch (op >> 6) {
    case 0: v = shift(c, n, v); break;
    case 1: bit(c, n, v, (u8)(a >> 8)); return;
    case 2: v &= (u8)~(1u << n); break;
    default: v |= (u8)(1u << n); break;
    }
    wr(c, a, v);
    if ((op & 7) != 6)
        ((u8 *)c)[roff[0][op & 7]] = v;
}

/* ---- the ED table ---- */

/* a block instruction about to repeat: the PC back on it; X and Y from its high byte */
static void again(struct z80 *c)
{
    PC -= 2;
    WZ = (u16)(PC + 1);
    F = (u8)((F & ~(FX | FY)) | (c->pc.b.h & (FX | FY)));
    c->q = F;
}

/* INI / IND / OUTI / OUTD's flags: v the byte moved, k v plus C +- 1 (in) or plus L (out) */
static void io_flags(struct z80 *c, u8 v, u32 k)
{
    SETF(sz53[B] | ((v & 0x80) ? FN : 0) | (k > 255 ? FH | FC : 0) | (sz53p[(k & 7) ^ B] & FP));
}

/* ... and when it repeats (INIR and the others with B not 0 yet): H and P as the chip leaves them then */
static void io_again(struct z80 *c, u8 v)
{
    again(c);
    u8 f = F;
    if (f & FC) {
        f &= (u8)~FH;
        if (v & 0x80) {
            f ^= (sz53p[(B - 1) & 7] ^ FP) & FP;
            if ((B & 0x0F) == 0x00)
                f |= FH;
        } else {
            f ^= (sz53p[(B + 1) & 7] ^ FP) & FP;
            if ((B & 0x0F) == 0x0F)
                f |= FH;
        }
    } else {
        f ^= (sz53p[B & 7] ^ FP) & FP;
    }
    SETF(f);
}

static void ed(struct z80 *c)
{
    u8 op = fetch(c), v;
    u16 a;
    union z80_pair *pair[4] = {&c->bc, &c->de, &c->hl, &c->sp};
    if (op >= 0x40 && op < 0x80) {
        int r = (op >> 3) & 7;
        u8 *reg = (u8 *)c + roff[0][r];
        switch (op & 7) {
        case 0:                         /* IN r,(C) (ED 70: only the flags) */
            WZ = (u16)(BC + 1);
            v = in(c, BC);
            SETF((F & FC) | sz53p[v]);
            if (r != 6)
                *reg = v;
            return;
        case 1:                         /* OUT (C),r (ED 71: 0) */
            WZ = (u16)(BC + 1);
            out(c, BC, r == 6 ? 0 : *reg);
            return;
        case 2:
            if (op & 8)
                adc16(c, pair[r >> 1]->w);
            else
                sbc16(c, pair[r >> 1]->w);
            return;
        case 3:
            a = imm16(c);
            if (op & 8) {
                u8 lo = rd(c, a);
                pair[r >> 1]->w = (u16)(rd(c, (u16)(a + 1)) << 8 | lo);
            } else {
                wr(c, a, pair[r >> 1]->b.l);
                wr(c, (u16)(a + 1), pair[r >> 1]->b.h);
            }
            WZ = (u16)(a + 1);
            return;
        case 4:                         /* NEG */
            v = A;
            A = 0;
            A = sub8(c, v, 0);
            return;
        case 5:                         /* RETN, RETI */
            c->iff1 = c->iff2;
            PC = WZ = pop(c);
            return;
        case 6:
            c->im = (u8)((r & 3) < 2 ? 0 : (r & 3) - 1);       /* 0 0 1 2 */
            return;
        }
        switch (op) {
        case 0x47: idle(c, IR, 1); c->i = A; return;
        case 0x4F: idle(c, IR, 1); c->r = A; c->r7 = A & 0x80; return;
        case 0x57:
            idle(c, IR, 1);
            A = c->i;
            SETF((F & FC) | sz53[A] | (c->iff2 ? FP : 0));
            return;
        case 0x5F:
            idle(c, IR, 1);
            A = (u8)((c->r & 0x7F) | c->r7);
            SETF((F & FC) | sz53[A] | (c->iff2 ? FP : 0));
            return;
        case 0x67:                      /* RRD */
            v = rd(c, HL);
            idle(c, HL, 4);
            wr(c, HL, (u8)(A << 4 | v >> 4));
            A = (u8)((A & 0xF0) | (v & 0x0F));
            SETF((F & FC) | sz53p[A]);
            WZ = (u16)(HL + 1);
            return;
        case 0x6F:                      /* RLD */
            v = rd(c, HL);
            idle(c, HL, 4);
            wr(c, HL, (u8)(v << 4 | (A & 0x0F)));
            A = (u8)((A & 0xF0) | (v >> 4));
            SETF((F & FC) | sz53p[A]);
            WZ = (u16)(HL + 1);
            return;
        }
        return;                         /* ED 77, ED 7F: nothing */
    }
    if ((op & 0xE4) != 0xA0)
        return;                        /* the rest of the table: NOPs of 8 T-states */
    int down = op & 8, repeat = op & 0x10;
    switch (op & 3) {
    case 0: {                           /* LDI LDD LDIR LDDR */
        v = rd(c, HL);
        wr(c, DE, v);
        idle(c, DE, 2);
        u32 n = (u32)v + A;
        BC--;
        SETF((F & (FS | FZ | FC)) | (BC ? FP : 0) | (n & FX) | ((n << 4) & FY));
        if (repeat && BC) {
            idle(c, DE, 5);
            again(c);
        }
        HL += down ? (u16)-1 : 1;
        DE += down ? (u16)-1 : 1;
        return;
    }
    case 1: {                           /* CPI CPD CPIR CPDR */
        v = rd(c, HL);
        idle(c, HL, 5);
        u32 r = (u32)A - v, h = (A ^ v ^ r) & FH, n = r - (h ? 1 : 0);
        BC--;
        SETF((F & FC) | FN | (sz53[r & 0xFF] & (FS | FZ)) | h | (BC ? FP : 0) | (n & FX) | ((n << 4) & FY));
        WZ += down ? (u16)-1 : 1;
        if (repeat && BC && (r & 0xFF)) {
            idle(c, HL, 5);
            again(c);
        }
        HL += down ? (u16)-1 : 1;
        return;
    }
    case 2:                             /* INI IND INIR INDR */
        idle(c, IR, 1);
        v = in(c, BC);
        WZ = (u16)(BC + (down ? -1 : 1));
        B--;
        wr(c, HL, v);
        io_flags(c, v, (u32)v + (u8)(C + (down ? -1 : 1)));
        if (repeat && B) {
            idle(c, HL, 5);
            io_again(c, v);
        }
        HL += down ? (u16)-1 : 1;
        return;
    default:                            /* OUTI OUTD OTIR OTDR */
        idle(c, IR, 1);
        v = rd(c, HL);
        B--;
        WZ = (u16)(BC + (down ? -1 : 1));
        out(c, BC, v);
        HL += down ? (u16)-1 : 1;
        io_flags(c, v, (u32)v + c->hl.b.l);
        if (repeat && B) {
            idle(c, BC, 5);
            io_again(c, v);
        }
        return;
    }
}

/* ---- the main table, with HL (x 0), IX (1) or IY (2) ---- */

/* (HL), or (IX+d): d read, 5 T-states of adding */
static inline u16 at_hl(struct z80 *c, union z80_pair *xy, int x)
{
    if (!x)
        return HL;
    s8 d = (s8)rd(c, PC);
    idle(c, PC, 5);
    PC++;
    return WZ = (u16)(xy->w + d);
}

static void exec(struct z80 *c, u8 op)
{
    int x = 0;
    union z80_pair *xy = &c->hl;
    const u8 *ro = roff[0];
    u8 v;
    u16 a;
prefixed:
#define R8(n) (((u8 *)c)[ro[n]])        /* B C D E H L - A, H and L being IX's or IY's halves after a prefix */
#define R8H(n) (((u8 *)c)[roff[0][n]])  /* the same, H and L always */
    if (op >= 0x40 && op < 0xC0) {
        int d = (op >> 3) & 7, s = op & 7;
        if (op < 0x80) {
            if (op == 0x76) {           /* HALT: NOPs until an interrupt */
                c->halted = 1;
                return;
            }
            if (s == 6)
                R8H(d) = rd(c, at_hl(c, xy, x));
            else if (d == 6)
                wr(c, at_hl(c, xy, x), R8H(s));
            else
                R8(d) = R8(s);
            return;
        }
        alu(c, d, s == 6 ? rd(c, at_hl(c, xy, x)) : R8(s));
        return;
    }
    switch (op) {
    case 0x00: return;
    case 0x01: BC = imm16(c); return;
    case 0x11: DE = imm16(c); return;
    case 0x21: xy->w = imm16(c); return;
    case 0x31: SP = imm16(c); return;
    case 0x02: wr(c, BC, A); WZ = (u16)(A << 8 | ((BC + 1) & 0xFF)); return;
    case 0x12: wr(c, DE, A); WZ = (u16)(A << 8 | ((DE + 1) & 0xFF)); return;
    case 0x0A: A = rd(c, BC); WZ = (u16)(BC + 1); return;
    case 0x1A: A = rd(c, DE); WZ = (u16)(DE + 1); return;
    case 0x22:
        a = imm16(c);
        wr(c, a, xy->b.l);
        wr(c, (u16)(a + 1), xy->b.h);
        WZ = (u16)(a + 1);
        return;
    case 0x2A:
        a = imm16(c);
        v = rd(c, a);
        xy->w = (u16)(rd(c, (u16)(a + 1)) << 8 | v);
        WZ = (u16)(a + 1);
        return;
    case 0x32:
        a = imm16(c);
        wr(c, a, A);
        WZ = (u16)(A << 8 | ((a + 1) & 0xFF));
        return;
    case 0x3A:
        a = imm16(c);
        A = rd(c, a);
        WZ = (u16)(a + 1);
        return;
    case 0x03: idle(c, IR, 2); BC++; return;
    case 0x13: idle(c, IR, 2); DE++; return;
    case 0x23: idle(c, IR, 2); xy->w++; return;
    case 0x33: idle(c, IR, 2); SP++; return;
    case 0x0B: idle(c, IR, 2); BC--; return;
    case 0x1B: idle(c, IR, 2); DE--; return;
    case 0x2B: idle(c, IR, 2); xy->w--; return;
    case 0x3B: idle(c, IR, 2); SP--; return;
    case 0x09: add16(c, xy, BC); return;
    case 0x19: add16(c, xy, DE); return;
    case 0x29: add16(c, xy, xy->w); return;
    case 0x39: add16(c, xy, SP); return;
    case 0x04: case 0x0C: case 0x14: case 0x1C: case 0x24: case 0x2C: case 0x3C:
        R8(op >> 3) = inc8(c, R8(op >> 3));
        return;
    case 0x05: case 0x0D: case 0x15: case 0x1D: case 0x25: case 0x2D: case 0x3D:
        R8(op >> 3) = dec8(c, R8(op >> 3));
        return;
    case 0x34: case 0x35:
        a = at_hl(c, xy, x);
        v = rd(c, a);
        idle(c, a, 1);
        wr(c, a, op & 1 ? dec8(c, v) : inc8(c, v));
        return;
    case 0x06: case 0x0E: case 0x16: case 0x1E: case 0x26: case 0x2E: case 0x3E:
        R8(op >> 3) = imm(c);
        return;
    case 0x36:
        if (!x) {
            v = imm(c);
            wr(c, HL, v);
        } else {
            s8 d = (s8)imm(c);
            v = rd(c, PC);
            idle(c, PC, 2);
            PC++;
            a = WZ = (u16)(xy->w + d);
            wr(c, a, v);
        }
        return;
    case 0x07:                          /* RLCA */
        A = (u8)(A << 1 | A >> 7);
        SETF((F & (FS | FZ | FP)) | (A & (FX | FY | FC)));
        return;
    case 0x0F:                          /* RRCA */
        v = A & 1;
        A = (u8)(A >> 1 | A << 7);
        SETF((F & (FS | FZ | FP)) | (A & (FX | FY)) | v);
        return;
    case 0x17:                          /* RLA */
        v = A >> 7;
        A = (u8)(A << 1 | (F & FC));
        SETF((F & (FS | FZ | FP)) | (A & (FX | FY)) | v);
        return;
    case 0x1F:                          /* RRA */
        v = A & 1;
        A = (u8)(A >> 1 | (F & FC) << 7);
        SETF((F & (FS | FZ | FP)) | (A & (FX | FY)) | v);
        return;
    case 0x08: {
        u16 t = c->af.w;
        c->af.w = c->af2;
        c->af2 = t;
        return;
    }
    case 0x10:                          /* DJNZ */
        idle(c, IR, 1);
        v = rd(c, PC);
        if (--B) {
            idle(c, PC, 5);
            PC = WZ = (u16)(PC + 1 + (s8)v);
        } else {
            PC++;
        }
        return;
    case 0x18:
        v = rd(c, PC);
        idle(c, PC, 5);
        PC = WZ = (u16)(PC + 1 + (s8)v);
        return;
    case 0x20: case 0x28: case 0x30: case 0x38:
        v = rd(c, PC);
        if (cond(c, (op >> 3) & 3)) {
            idle(c, PC, 5);
            PC = WZ = (u16)(PC + 1 + (s8)v);
        } else {
            PC++;
        }
        return;
    case 0x27: {                        /* DAA */
        u8 f = F, diff = 0, carry = f & FC, h;
        v = A;
        if ((f & FH) || (v & 0x0F) > 9)
            diff = 6;
        if (carry || v > 0x99)
            diff |= 0x60, carry = FC;
        if (f & FN) {
            h = ((f & FH) && (v & 0x0F) < 6) ? FH : 0;
            A = (u8)(v - diff);
        } else {
            h = (v & 0x0F) > 9 ? FH : 0;
            A = (u8)(v + diff);
        }
        SETF(sz53p[A] | carry | (f & FN) | h);
        return;
    }
    case 0x2F:                          /* CPL */
        A = (u8)~A;
        SETF((F & (FS | FZ | FP | FC)) | FH | FN | (A & (FX | FY)));
        return;
    case 0x37:                          /* SCF */
        SETF((F & (FS | FZ | FP)) | FC | (((c->q_was ^ F) | A) & (FX | FY)));
        return;
    case 0x3F:                          /* CCF */
        SETF((F & (FS | FZ | FP)) | ((F & FC) ? FH : FC) | (((c->q_was ^ F) | A) & (FX | FY)));
        return;
    case 0xC0: case 0xC8: case 0xD0: case 0xD8: case 0xE0: case 0xE8: case 0xF0: case 0xF8:
        idle(c, IR, 1);
        if (cond(c, (op >> 3) & 7))
            PC = WZ = pop(c);
        return;
    case 0xC9: PC = WZ = pop(c); return;
    case 0xC1: BC = pop(c); return;
    case 0xD1: DE = pop(c); return;
    case 0xE1: xy->w = pop(c); return;
    case 0xF1: c->af.w = pop(c); return;
    case 0xC5: idle(c, IR, 1); push(c, BC); return;
    case 0xD5: idle(c, IR, 1); push(c, DE); return;
    case 0xE5: idle(c, IR, 1); push(c, xy->w); return;
    case 0xF5: idle(c, IR, 1); push(c, c->af.w); return;
    case 0xC2: case 0xCA: case 0xD2: case 0xDA: case 0xE2: case 0xEA: case 0xF2: case 0xFA:
        a = WZ = imm16(c);
        if (cond(c, (op >> 3) & 7))
            PC = a;
        return;
    case 0xC3: PC = WZ = imm16(c); return;
    case 0xC4: case 0xCC: case 0xD4: case 0xDC: case 0xE4: case 0xEC: case 0xF4: case 0xFC:
        a = WZ = imm16(c);
        if (cond(c, (op >> 3) & 7)) {
            idle(c, (u16)(PC - 1), 1);
            push(c, PC);
            PC = a;
        }
        return;
    case 0xCD:
        a = WZ = imm16(c);
        idle(c, (u16)(PC - 1), 1);
        push(c, PC);
        PC = a;
        return;
    case 0xC6: case 0xCE: case 0xD6: case 0xDE: case 0xE6: case 0xEE: case 0xF6: case 0xFE:
        alu(c, (op >> 3) & 7, imm(c));
        return;
    case 0xC7: case 0xCF: case 0xD7: case 0xDF: case 0xE7: case 0xEF: case 0xF7: case 0xFF:
        idle(c, IR, 1);
        push(c, PC);
        PC = WZ = op & 0x38;
        return;
    case 0xCB:
        if (x)
            xcb(c, xy->w);
        else
            cb(c);
        return;
    case 0xD3:
        v = imm(c);
        out(c, (u16)(A << 8 | v), A);
        WZ = (u16)(A << 8 | ((v + 1) & 0xFF));
        return;
    case 0xDB:
        v = imm(c);
        a = (u16)(A << 8 | v);
        A = in(c, a);
        WZ = (u16)(a + 1);
        return;
    case 0xD9: {
        u16 t = BC;
        BC = c->bc2, c->bc2 = t;
        t = DE, DE = c->de2, c->de2 = t;
        t = HL, HL = c->hl2, c->hl2 = t;
        return;
    }
    case 0xE3: {                        /* EX (SP),HL */
        u8 lo = rd(c, SP), hi = rd(c, (u16)(SP + 1));
        idle(c, (u16)(SP + 1), 1);
        wr(c, (u16)(SP + 1), xy->b.h);
        wr(c, SP, xy->b.l);
        idle(c, SP, 2);
        xy->w = WZ = (u16)(hi << 8 | lo);
        return;
    }
    case 0xE9: PC = xy->w; return;
    case 0xEB: {
        u16 t = DE;
        DE = HL, HL = t;
        return;
    }
    case 0xED: ed(c); return;
    case 0xF3: c->iff1 = c->iff2 = 0; return;
    case 0xFB: c->iff1 = c->iff2 = 1; c->ei_block = 1; return;
    case 0xF9: idle(c, IR, 2); SP = xy->w; return;
    case 0xDD: case 0xFD: {
        /* a prefix: the next opcode with IX or IY; but a prefix followed by another is a NOP of its own (the
           next one starts the instruction; no interrupt in between) */
        const u8 *page = c->rd[PC >> 10];
        u8 next = page ? page[PC & 0x3FF] : c->read(c, PC);
        if (next == 0xDD || next == 0xFD) {
            c->ei_block = 1;
            return;
        }
        x = op == 0xDD ? 1 : 2;
        xy = x == 1 ? &c->ix : &c->iy;
        ro = roff[x];
        op = fetch(c);
        goto prefixed;
    }
    }
#undef R8
#undef R8H
}

/* ---- interrupts ---- */
static void take_nmi(struct z80 *c)
{
    c->nmi = 0;
    c->halted = 0;
    c->iff1 = 0;
    c->r++;
    T += 5;
    push(c, PC);
    PC = WZ = 0x66;
}

static void take_irq(struct z80 *c)
{
    c->halted = 0;
    c->iff1 = c->iff2 = 0;
    c->r++;
    T += 7;                             /* (the acknowledge: an M1 of 6 T-states and one more) */
    push(c, PC);
    if (c->im == 2) {
        u16 v = (u16)(c->i << 8 | c->bus);
        u8 lo = rd(c, v);
        PC = (u16)(rd(c, (u16)(v + 1)) << 8 | lo);
    } else {
        PC = (c->im == 0 && (c->bus & 0xC7) == 0xC7) ? c->bus & 0x38 : 0x38;     /* (mode 0: the bus's RST) */
    }
    WZ = PC;
}

int z80_run(struct z80 *c, s32 until)
{
    while (T < until) {
        if ((s32)PC == c->trap)
            return 1;
        if (c->nmi) {
            take_nmi(c);
            continue;
        }
        if (c->irq && c->iff1 && !c->ei_block) {
            take_irq(c);
            continue;
        }
        c->ei_block = 0;
        if (c->halted) {                /* NOPs (R counts them) until the run's end, or an interrupt */
            if (CONTENDED(PC)) {
                cont(c, PC);
                T += 4;
                c->r++;
            } else {
                s32 n = (until - T + 3) >> 2;
                T += n * 4;
                c->r = (u8)(c->r + n);
            }
            continue;
        }
        c->q_was = c->q;
        c->q = 0;
        exec(c, fetch(c));
    }
    return 0;
}

void z80_reset(struct z80 *c)
{
    PC = 0;
    c->i = c->r = c->r7 = 0;
    c->iff1 = c->iff2 = c->im = c->halted = c->ei_block = 0;
    c->nmi = 0;
    c->wz.w = 0;
}

void z80_init(struct z80 *c)
{
    for (int i = 0; i < 256; i++) {
        u8 f = (u8)((i & (FS | FX | FY)) | (i ? 0 : FZ)), p = 1;
        for (int k = 0; k < 8; k++)
            p ^= (u8)((i >> k) & 1);
        sz53[i] = f;
        sz53p[i] = (u8)(f | (p ? FP : 0));
    }
    static const u8 plain[8] = {
        __builtin_offsetof(struct z80, bc.b.h), __builtin_offsetof(struct z80, bc.b.l),
        __builtin_offsetof(struct z80, de.b.h), __builtin_offsetof(struct z80, de.b.l),
        __builtin_offsetof(struct z80, hl.b.h), __builtin_offsetof(struct z80, hl.b.l),
        __builtin_offsetof(struct z80, hl.b.l), __builtin_offsetof(struct z80, af.b.h)};
    for (int x = 0; x < 3; x++)
        for (int n = 0; n < 8; n++)
            roff[x][n] = plain[n];
    roff[1][4] = __builtin_offsetof(struct z80, ix.b.h), roff[1][5] = __builtin_offsetof(struct z80, ix.b.l);
    roff[2][4] = __builtin_offsetof(struct z80, iy.b.h), roff[2][5] = __builtin_offsetof(struct z80, iy.b.l);
    c->af.w = c->sp.w = 0xFFFF;
    c->bc.w = c->de.w = c->hl.w = c->ix.w = c->iy.w = 0xFFFF;
    c->af2 = c->bc2 = c->de2 = c->hl2 = 0xFFFF;
    c->q = c->q_was = 0;
    c->irq = 0;
    c->bus = 0xFF;
    c->cycles = 0;
    c->trap = -1;
    c->cont_n = 0;
    for (int i = 0; i < 64; i++)
        c->op[i] = 0;
    z80_reset(c);
}
