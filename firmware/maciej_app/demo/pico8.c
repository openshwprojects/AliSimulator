/* PICO-8 Fantasy Console Emulator: see pico8.h.
   Zero static .bss (all 32 KB PICO-8 RAM/ROM, AST/symbol/table/string pools,
   PNG steganography buffers & 48 kHz 4-ch synth ring live in EMU_RAM_PHYS). */
#include "pico8.h"
#include "image.h"
#include "zip.h"

#ifndef PICO8_HOST
#include "hw.h"
#endif

typedef signed char s8;

#pragma GCC optimize("O2")

#define P8_SND_RING     8192
#define P8_LUA_CAP      65536u
#define P8_MAX_TOKS     16384
#define P8_MAX_NODES    16384
#define P8_MAX_SYMS     512
#define P8_MAX_TABS     512
#define P8_TAB_CAP      96
#define P8_MAX_STRS     1024
#define P8_STR_LEN      64
#define P8_MAX_LOCALS   256
#define P8_STEP_BUDGET  120000u

/* Official PICO-8 32-Colour Palette (0..15 standard + 16..31 secret 128..143 extended!)
   Preconverted to play.c 15-bit 0BBBBBGGGGGRRRRR */
#define P8_RGB15(r, g, b) ((u16)((((b) >> 3) << 10) | (((g) >> 3) << 5) | ((r) >> 3)))
static const u16 p8_master_pal15[32] = {
    P8_RGB15(  0,   0,   0), P8_RGB15( 29,  43,  83), P8_RGB15(126,  37,  83), P8_RGB15(  0, 135,  81),
    P8_RGB15(171,  82,  54), P8_RGB15( 95,  87,  79), P8_RGB15(194, 195, 199), P8_RGB15(255, 241, 232),
    P8_RGB15(255,   0,  77), P8_RGB15(255, 163,   0), P8_RGB15(255, 236,  39), P8_RGB15(  0, 228,  54),
    P8_RGB15( 41, 173, 255), P8_RGB15(131, 118, 156), P8_RGB15(255, 119, 168), P8_RGB15(255, 204, 170),
    /* Extended 16..31 (selected via pal(c, 128..143, 1)) */
    P8_RGB15( 41,  24,  20), P8_RGB15( 17,  29,  53), P8_RGB15( 66,  33,  54), P8_RGB15( 18,  83,  89),
    P8_RGB15(116,  47,  41), P8_RGB15( 73,  51,  59), P8_RGB15(162, 136, 121), P8_RGB15(243, 239, 125),
    P8_RGB15(190,  18,  80), P8_RGB15(255, 108,  36), P8_RGB15(168, 231,  46), P8_RGB15(  0, 181,  67),
    P8_RGB15(  6,  90, 181), P8_RGB15(117,  70, 101), P8_RGB15(255, 110,  89), P8_RGB15(255, 157, 129)
};

/* Quarter-wave sine table (0..64 -> 0..0x10000 in 16.16 fixed point) */
static const u32 p8_qsin[65] = {
        0,  1608,  3216,  4821,  6424,  8022,  9616, 11204,
    12785, 14359, 15924, 17479, 19024, 20557, 22078, 23586,
    25080, 26558, 28020, 29466, 30893, 32303, 33692, 35062,
    36410, 37736, 39040, 40320, 41576, 42806, 44011, 45190,
    46341, 47464, 48559, 49624, 50660, 51665, 52639, 53581,
    54491, 55368, 56212, 57022, 57798, 58538, 59244, 59914,
    60547, 61145, 61705, 62228, 62714, 63162, 63572, 63944,
    64277, 64571, 64827, 65043, 65220, 65358, 65457, 65516, 65536
};

/* 64-pitch PICO-8 note frequencies (C-0..D#5 in Hz * 16) */
static const u16 p8_note_hz16[64] = {
     1047,  1109,  1175,  1245,  1319,  1397,  1480,  1568,
     1661,  1760,  1865,  1976,  2093,  2217,  2349,  2489,
     2637,  2794,  2960,  3136,  3322,  3520,  3729,  3951,
     4186,  4435,  4699,  4978,  5274,  5588,  5920,  6272,
     6645,  7040,  7459,  7902,  8372,  8870,  9397,  9956,
    10548, 11175, 11840, 12544, 13290, 14080, 14917, 15804,
    16744, 17740, 18795, 19912, 21096, 22351, 23680, 25088,
    26580, 28160, 29834, 31609, 33488, 35479, 37589, 39824
};

/* ---- Value, Table & AST Representations ---- */
enum {
    V_NIL = 0, V_BOOL = 1, V_NUM = 2, V_STR = 3, V_TAB = 4, V_FUNC = 5, V_BUILTIN = 6, V_ITER = 7
};

struct p8_val {
    u8  type;
    u8  pad;
    u16 u;      /* str idx, tab idx, func node, builtin id, or iter tab */
    s32 n;      /* 16.16 fixed-point number, bool (0/1), or iter index */
};

struct p8_kv {
    struct p8_val k, v;
};

struct p8_tab {
    u8  used, mark;
    u16 count;
    struct p8_kv items[P8_TAB_CAP];
};

struct p8_str {
    u8  used, mark, len;
    char s[P8_STR_LEN];
};

enum {
    TK_EOF = 0, TK_NUM, TK_STR, TK_ID,
    TK_LOCAL, TK_FUNC, TK_IF, TK_THEN, TK_ELSEIF, TK_ELSE, TK_END,
    TK_WHILE, TK_DO, TK_REPEAT, TK_UNTIL, TK_FOR, TK_IN, TK_RETURN, TK_BREAK,
    TK_AND, TK_OR, TK_NOT, TK_TRUE, TK_FALSE, TK_NIL,
    TK_EQ, TK_NE, TK_LE, TK_GE, TK_SHL, TK_SHR, TK_LSHR, TK_CONCAT,
    TK_ADDEQ, TK_SUBEQ, TK_MULEQ, TK_DIVEQ, TK_MODEQ, TK_CATEQ,
    TK_PRINTQ   /* '?' start-of-line print shorthand */
};

struct p8_tok {
    u16 kind;       /* TK_* or ASCII punctuation char */
    u16 line;
    s32 val;        /* 16.16 number, sym_id, or str_id */
};

enum {
    ND_NOP = 0, ND_BLOCK, ND_SEQ, ND_NUM, ND_STR, ND_BOOL, ND_NIL, ND_VAR,
    ND_UNOP, ND_BINOP, ND_INDEX, ND_CALL, ND_TABLE, ND_KV,
    ND_ASSIGN, ND_COMPOUND, ND_LOCAL, ND_IF, ND_WHILE, ND_REPEAT,
    ND_FOR_NUM, ND_FOR_IN, ND_FUNC, ND_RETURN, ND_BREAK
};

struct p8_node {
    u8  kind;
    u8  op;
    s16 a, b, c, d;
    s32 val;
};

struct p8_local {
    u16 sym;
    struct p8_val v;
};

struct p8_chan {
    s8  sfx_id;
    u8  note_idx;
    u8  active;
    u32 tick_samples, sample_in_note;
    u32 phase, prev_phase;
    u32 inc_base, inc_prev;
    u32 lfsr;
};

struct pico8_state {
    u8  jammed, cartdata_dirty, is_60fps, half_flip;
    u16 pad_cur, pad_prev;
    u8  hold_frames[16];
    u32 rng_hi, rng_lo;
    u32 frame_count;
    u32 steps_left;
    u16 fill_pat;

    /* Sym/Token/AST/Pool Counters */
    int n_syms, n_toks, tok_pos, n_nodes;
    s16 root_block;
    int local_top, break_flag, ret_flag;
    struct p8_val ret_vals[4];
    int ret_count;

    /* 4-Channel Synthesizer & Music Sequencer */
    u32 sample_rate;
    s8  music_pat;
    u32 music_tick_rem;
    struct p8_chan ch[4];
    u32 snd_head, snd_tail;

    char parse_err[80];
    char info[96];
};

struct pico8_mem {
    struct pico8_state st;
    u8  ram[0x8000];                /* 32 KB PICO-8 Address Space ($0000..$7FFF) */
    u8  rom[0x4300];                /* Cartridge ROM backup for reload() */
    char lua_src[P8_LUA_CAP];       /* Extracted / decompressed Lua source */
    char syms[P8_MAX_SYMS][24];
    struct p8_val globals[P8_MAX_SYMS];
    struct p8_local locals[P8_MAX_LOCALS];
    struct p8_tok toks[P8_MAX_TOKS];
    struct p8_node nodes[P8_MAX_NODES];
    struct p8_tab tabs[P8_MAX_TABS];
    struct p8_str strs[P8_MAX_STRS];

    /* PNG .p8.png steganography & ZIP work buffers */
    u8  cart_raw[0x8100];           /* 32,800 bytes from 160x205 RGBA steganography */
    u8  png_zbuf[0x40000];          /* 256 KB concatenated IDAT stream */
    u8  png_raw[0x40000];           /* 256 KB inflated PNG scanlines */
    u8  inflate_work[0x20000];      /* Scratch for zip/deflate */

    s16 snd_ring[P8_SND_RING];
};

#ifdef PICO8_HOST
static struct pico8_mem p8_host_mem;
#define M (&p8_host_mem)
#else
#define M ((struct pico8_mem *)KSEG0(EMU_RAM_PHYS))
_Static_assert(sizeof(struct pico8_mem) <= EMU_RAM_SIZE, "pico8_mem exceeds EMU_RAM_SIZE");
#endif

#define S (M->st)

/* ============================================================================
   Pure 32-bit 16.16 Fixed-Point Arithmetic (Zero 64-bit Division!)
   ============================================================================ */

static void p8_zero(void *p, u32 n)
{
    u8 *b = (u8 *)p;
    for (u32 i = 0; i < n; i++) b[i] = 0;
}

static int p8_strlen(const char *s)
{
    int n = 0;
    while (s[n]) n++;
    return n;
}

static int p8_streq(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static inline s32 fix_from_int(int x) { return (s32)((u32)x << 16); }
static inline int fix_to_int(s32 x)   { return x >> 16; }   /* floor toward -inf! */

static s32 fix_mul(s32 a, s32 b)
{
    int neg = (a < 0) ^ (b < 0);
    u32 ua = (a < 0) ? (0u - (u32)a) : (u32)a;
    u32 ub = (b < 0) ? (0u - (u32)b) : (u32)b;
    u32 ah = ua >> 16, al = ua & 0xFFFFu;
    u32 bh = ub >> 16, bl = ub & 0xFFFFu;
    u32 res = ((ah * bh) << 16) + ah * bl + al * bh + ((al * bl) >> 16);
    return neg ? (s32)(0u - res) : (s32)res;
}

static s32 fix_div(s32 a, s32 b)
{
    if (b == 0) return (a < 0) ? (s32)0x80000001u : 0x7FFFFFFF;
    int neg = (a < 0) ^ (b < 0);
    u32 ua = (a < 0) ? (0u - (u32)a) : (u32)a;
    u32 ub = (b < 0) ? (0u - (u32)b) : (u32)b;
    u32 q_int = ua / ub;
    u32 rem   = ua - q_int * ub;
    u32 q_frac = 0;
    for (int i = 15; i >= 0; i--) {
        int hi = (rem >> 31) != 0;
        rem <<= 1;
        if (hi || rem >= ub) {
            rem -= ub;
            q_frac |= (1u << i);
        }
    }
    u32 res = (q_int << 16) | q_frac;
    return neg ? (s32)(0u - res) : (s32)res;
}

static s32 fix_mod(s32 a, s32 b)
{
    if (b == 0) return 0;
    s32 q = fix_div(a, b) & (s32)0xFFFF0000u;   /* flr(a / b) in 16.16 */
    return a - fix_mul(q, b);
}

static s32 fix_sqrt(s32 a)
{
    if (a <= 0) return 0;
    /* sqrt(a_16_16) in 16.16 = integer sqrt(a << 16): use 16-step bit-by-bit Newton/restoring */
    u32 hi = (u32)a >> 16, lo = (u32)a << 16;
    u32 rem = 0, root = 0;
    for (int i = 0; i < 32; i++) {
        root <<= 1;
        rem = (rem << 2) | (hi >> 30);
        hi = (hi << 2) | (lo >> 30);
        lo <<= 2;
        u32 cand = (root << 1) | 1u;
        if (rem >= cand) {
            rem -= cand;
            root |= 1u;
        }
    }
    return (s32)root;
}

/* PICO-8 sin(x): x in 0..1 turns counter-clockwise (sin(0.25) = -1.0, sin(0.75) = +1.0!) */
static s32 p8_sin_turns(s32 x)
{
    u32 t = (u32)x & 0xFFFFu;   /* fractional turn 0..65535 */
    u32 idx8 = t >> 8;          /* 0..255 */
    u32 frac = t & 0xFFu;
    u32 q = idx8 >> 6;          /* quadrant 0..3 */
    u32 p = idx8 & 63u;
    u32 s0, s1;
    if ((q & 1u) == 0) { s0 = p8_qsin[p]; s1 = p8_qsin[p + 1u]; }
    else               { s0 = p8_qsin[64u - p]; s1 = p8_qsin[63u - p]; }
    s32 mag = (s32)s0 + (((s32)s1 - (s32)s0) * (s32)frac >> 8);
    /* PICO-8 inverts sin(): quadrants 0..1 (0..0.5) are NEGATIVE, quadrants 2..3 (0.5..1.0) are POSITIVE! */
    return (q < 2u) ? -mag : mag;
}

static s32 p8_cos_turns(s32 x)
{
    /* cos(0) = +1.0 = p8_sin_turns(x - 0.25) -> since sin(0.75) = +1.0! */
    return p8_sin_turns(x - 0x4000);
}

static s32 p8_atan2(s32 dx, s32 dy)
{
    if (dx == 0 && dy == 0) return 0;
    s32 ax = dx < 0 ? -dx : dx;
    s32 ay = dy < 0 ? -dy : dy;
    s32 r = (ax > ay) ? fix_div(ay, ax) : fix_div(ax, ay);
    /* Octant polynomial approx -> 0..0.125 turns (0..8192 in 16.16) */
    s32 ang = fix_mul(r, 0x2000 - fix_mul(0x0700, fix_mul(r, r - 0x10000)));
    if (ay > ax) ang = 0x4000 - ang;
    if (dx < 0)  ang = 0x8000 - ang;
    /* PICO-8 screen-Y inverted: dy < 0 is UP (0..0.5), dy > 0 is DOWN (0.5..1.0) */
    if (dy > 0)  ang = (0x10000 - ang) & 0xFFFF;
    return ang & 0xFFFF;
}

static u32 p8_rand_u32(void)
{
    S.rng_hi = ((S.rng_hi << 16) | (S.rng_hi >> 16)) + S.rng_lo;
    S.rng_lo += S.rng_hi;
    return S.rng_hi;
}

/* ============================================================================
   PICO-8 Low-Level VRAM, Sprite, Map, Font & Draw State Helpers
   ============================================================================ */

static void p8_reset_draw_state(void)
{
    for (int i = 0; i < 16; i++) {
        M->ram[0x5F00 + i] = (u8)(i == 0 ? 0x10u : (u32)i);  /* color 0 transparent by default */
        M->ram[0x5F10 + i] = (u8)i;
    }
    M->ram[0x5F20] = 0;   M->ram[0x5F21] = 0;
    M->ram[0x5F22] = 128; M->ram[0x5F23] = 128;
    M->ram[0x5F25] = 6;   /* default light-grey pen */
    M->ram[0x5F26] = 0;   M->ram[0x5F27] = 0;
    M->ram[0x5F28] = 0;   M->ram[0x5F29] = 0;
    M->ram[0x5F2A] = 0;   M->ram[0x5F2B] = 0;
    S.fill_pat = 0;
}

static inline int p8_cam_x(void) { return (s16)((u16)M->ram[0x5F28] | ((u16)M->ram[0x5F29] << 8)); }
static inline int p8_cam_y(void) { return (s16)((u16)M->ram[0x5F2A] | ((u16)M->ram[0x5F2B] << 8)); }

static inline void p8_raw_pset(int sx, int sy, u8 col)
{
    if (sx < (int)M->ram[0x5F20] || sy < (int)M->ram[0x5F21] ||
        sx >= (int)M->ram[0x5F22] || sy >= (int)M->ram[0x5F23])
        return;
    if ((unsigned)sx >= 128u || (unsigned)sy >= 128u)
        return;
    if (S.fill_pat) {
        u16 bit = (u16)(1u << (15 - (((sy & 3) << 2) | (sx & 3))));
        if (S.fill_pat & bit) return;
    }
    u8 mapped = M->ram[0x5F00 + (col & 15u)] & 15u;
    u32 a = 0x6000u + (u32)sy * 64u + (u32)(sx >> 1);
    if (sx & 1) M->ram[a] = (M->ram[a] & 0x0Fu) | (mapped << 4);
    else        M->ram[a] = (M->ram[a] & 0xF0u) | mapped;
}

static inline void p8_pset(int x, int y, u8 col)
{
    p8_raw_pset(x - p8_cam_x(), y - p8_cam_y(), col);
}

static inline u8 p8_pget(int x, int y)
{
    if ((unsigned)x >= 128u || (unsigned)y >= 128u) return 0;
    u8 b = M->ram[0x6000u + (u32)y * 64u + (u32)(x >> 1)];
    return (x & 1) ? (b >> 4) : (b & 15u);
}

static inline u8 p8_sget(int x, int y)
{
    if ((unsigned)x >= 128u || (unsigned)y >= 128u) return 0;
    u8 b = M->ram[(u32)y * 64u + (u32)(x >> 1)];
    return (x & 1) ? (b >> 4) : (b & 15u);
}

static inline void p8_sset(int x, int y, u8 col)
{
    if ((unsigned)x >= 128u || (unsigned)y >= 128u) return;
    u32 a = (u32)y * 64u + (u32)(x >> 1);
    col &= 15u;
    if (x & 1) M->ram[a] = (M->ram[a] & 0x0Fu) | (col << 4);
    else       M->ram[a] = (M->ram[a] & 0xF0u) | col;
}

static inline u8 p8_mget(int mx, int my)
{
    if ((unsigned)mx >= 128u || (unsigned)my >= 64u) return 0;
    u32 a = (my < 32) ? (0x2000u + (u32)my * 128u + (u32)mx)
                      : (0x1000u + (u32)(my - 32) * 128u + (u32)mx);
    return M->ram[a];
}

static inline void p8_mset(int mx, int my, u8 v)
{
    if ((unsigned)mx >= 128u || (unsigned)my >= 64u) return;
    u32 a = (my < 32) ? (0x2000u + (u32)my * 128u + (u32)mx)
                      : (0x1000u + (u32)(my - 32) * 128u + (u32)mx);
    M->ram[a] = v;
}

static void p8_cls(u8 col)
{
    u8 c = col & 15u;
    u8 pair = (u8)(c | (c << 4));
    for (u32 i = 0; i < 0x2000u; i++)
        M->ram[0x6000u + i] = pair;
    M->ram[0x5F26] = 0;
    M->ram[0x5F27] = 0;
}

static void p8_line(int x0, int y0, int x1, int y1, u8 col)
{
    int dx = x1 - x0; if (dx < 0) dx = -dx;
    int sx = x0 < x1 ? 1 : -1;
    int dy = y1 - y0; if (dy > 0) dy = -dy;
    int sy = y0 < y1 ? 1 : -1;
    int err = dx + dy;
    for (int guard = 0; guard < 512; guard++) {
        p8_pset(x0, y0, col);
        if (x0 == x1 && y0 == y1) break;
        int e2 = err * 2;
        if (e2 >= dy) { err += dy; x0 += sx; }
        if (e2 <= dx) { err += dx; y0 += sy; }
    }
}

static void p8_rectfill(int x0, int y0, int x1, int y1, u8 col)
{
    if (x0 > x1) { int t = x0; x0 = x1; x1 = t; }
    if (y0 > y1) { int t = y0; y0 = y1; y1 = t; }
    int cx = p8_cam_x(), cy = p8_cam_y();
    int sx0 = x0 - cx, sy0 = y0 - cy, sx1 = x1 - cx, sy1 = y1 - cy;
    if (sx0 < 0) sx0 = 0;
    if (sy0 < 0) sy0 = 0;
    if (sx1 > 127) sx1 = 127;
    if (sy1 > 127) sy1 = 127;
    for (int sy = sy0; sy <= sy1; sy++)
        for (int sx = sx0; sx <= sx1; sx++)
            p8_raw_pset(sx, sy, col);
}

static void p8_rect(int x0, int y0, int x1, int y1, u8 col)
{
    if (x0 > x1) { int t = x0; x0 = x1; x1 = t; }
    if (y0 > y1) { int t = y0; y0 = y1; y1 = t; }
    p8_line(x0, y0, x1, y0, col);
    p8_line(x0, y1, x1, y1, col);
    p8_line(x0, y0, x0, y1, col);
    p8_line(x1, y0, x1, y1, col);
}

static void p8_circ(int xm, int ym, int r, u8 col, int fill)
{
    if (r < 0) return;
    int x = r, y = 0, err = 1 - r;
    while (x >= y) {
        if (fill) {
            for (int px = xm - x; px <= xm + x; px++) { p8_pset(px, ym + y, col); p8_pset(px, ym - y, col); }
            for (int px = xm - y; px <= xm + y; px++) { p8_pset(px, ym + x, col); p8_pset(px, ym - x, col); }
        } else {
            p8_pset(xm + x, ym + y, col); p8_pset(xm + y, ym + x, col);
            p8_pset(xm - y, ym + x, col); p8_pset(xm - x, ym + y, col);
            p8_pset(xm - x, ym - y, col); p8_pset(xm - y, ym - x, col);
            p8_pset(xm + y, ym - x, col); p8_pset(xm + x, ym - y, col);
        }
        y++;
        if (err < 0) err += 2 * y + 1;
        else { x--; err += 2 * (y - x) + 1; }
    }
}

static void p8_spr_blit(int n, int dx, int dy, int w8, int h8, int fx, int fy)
{
    if (n < 0 || n >= 256 || w8 <= 0 || h8 <= 0) return;
    int sx0 = (n & 15) * 8;
    int sy0 = (n >> 4) * 8;
    int pw = w8 * 8, ph = h8 * 8;
    for (int py = 0; py < ph; py++) {
        int sy = sy0 + (fy ? (ph - 1 - py) : py);
        for (int px = 0; px < pw; px++) {
            int sx = sx0 + (fx ? (pw - 1 - px) : px);
            u8 c = p8_sget(sx, sy);
            if (M->ram[0x5F00 + (c & 15u)] & 0x10u) continue; /* palt transparent! */
            p8_pset(dx + px, dy + py, c);
        }
    }
}

static void p8_sspr(int sx, int sy, int sw, int sh, int dx, int dy, int dw, int dh, int fx, int fy)
{
    if (sw <= 0 || sh <= 0 || dw <= 0 || dh <= 0) return;
    for (int py = 0; py < dh; py++) {
        int r_y = fy ? (dh - 1 - py) : py;
        int src_y = sy + (r_y * sh) / dh;
        for (int px = 0; px < dw; px++) {
            int r_x = fx ? (dw - 1 - px) : px;
            int src_x = sx + (r_x * sw) / dw;
            u8 c = p8_sget(src_x, src_y);
            if (M->ram[0x5F00 + (c & 15u)] & 0x10u) continue;
            p8_pset(dx + px, dy + py, c);
        }
    }
}

static void p8_draw_map(int cel_x, int cel_y, int sx, int sy, int cel_w, int cel_h, u8 layer_mask)
{
    for (int my = 0; my < cel_h; my++) {
        for (int mx = 0; mx < cel_w; mx++) {
            u8 tile = p8_mget(cel_x + mx, cel_y + my);
            if (tile == 0) continue;    /* PICO-8 sprite 0 is empty in map()! */
            if (layer_mask && (M->ram[0x3000 + tile] & layer_mask) != layer_mask)
                continue;
            p8_spr_blit(tile, sx + mx * 8, sy + my * 8, 1, 1, 0, 0);
        }
    }
}

/* Authentic PICO-8 3x5 pixel-art font (4x6 cell; 7=### 6=##. 5=#.# 4=#.. 3=.## 2=.#. 1=..# 0=...) */
#define P8F(a,b,c,d,e) ((u16)(((a)<<12)|((b)<<9)|((c)<<6)|((d)<<3)|(e)))
static const u16 p8_font3x5[95] = {
    P8F(0,0,0,0,0), P8F(2,2,2,0,2), P8F(5,5,0,0,0), P8F(5,7,5,7,5), /*   ! " # */
    P8F(3,6,2,3,6), P8F(5,1,2,4,5), P8F(6,4,6,5,3), P8F(2,2,0,0,0), /* $ % & ' */
    P8F(1,2,2,2,1), P8F(4,2,2,2,4), P8F(5,2,7,2,5), P8F(0,2,7,2,0), /* ( ) * + */
    P8F(0,0,0,2,4), P8F(0,0,7,0,0), P8F(0,0,0,0,2), P8F(1,1,2,4,4), /* , - . / */
    P8F(7,5,5,5,7), P8F(2,6,2,2,7), P8F(7,1,7,4,7), P8F(7,1,7,1,7), /* 0 1 2 3 */
    P8F(5,5,7,1,1), P8F(7,4,7,1,7), P8F(7,4,7,5,7), P8F(7,1,2,2,2), /* 4 5 6 7 */
    P8F(7,5,7,5,7), P8F(7,5,7,1,7), P8F(0,2,0,2,0), P8F(0,2,0,2,4), /* 8 9 : ; */
    P8F(1,2,4,2,1), P8F(0,7,0,7,0), P8F(4,2,1,2,4), P8F(7,1,2,0,2), /* < = > ? */
    P8F(7,5,7,4,7), P8F(2,5,7,5,5), P8F(6,5,6,5,6), P8F(7,4,4,4,7), /* @ A B C */
    P8F(6,5,5,5,6), P8F(7,4,7,4,7), P8F(7,4,7,4,4), P8F(7,4,5,5,7), /* D E F G */
    P8F(5,5,7,5,5), P8F(7,2,2,2,7), P8F(3,1,1,5,2), P8F(5,5,6,5,5), /* H I J K */
    P8F(4,4,4,4,7), P8F(5,7,7,5,5), P8F(6,5,5,5,5), P8F(7,5,5,5,7), /* L M N O */
    P8F(7,5,7,4,4), P8F(7,5,5,7,3), P8F(6,5,6,5,5), P8F(7,4,7,1,7), /* P Q R S */
    P8F(7,2,2,2,2), P8F(5,5,5,5,7), P8F(5,5,5,5,2), P8F(5,5,7,7,5), /* T U V W */
    P8F(5,5,2,5,5), P8F(5,5,2,2,2), P8F(7,1,2,4,7), P8F(3,2,2,2,3), /* X Y Z [ */
    P8F(4,4,2,1,1), P8F(6,2,2,2,6), P8F(2,5,0,0,0), P8F(0,0,0,0,7), /* \ ] ^ _ */
    P8F(4,2,0,0,0), P8F(2,5,7,5,5), P8F(6,5,6,5,6), P8F(7,4,4,4,7), /* ` a b c */
    P8F(6,5,5,5,6), P8F(7,4,7,4,7), P8F(7,4,7,4,4), P8F(7,4,5,5,7), /* d e f g */
    P8F(5,5,7,5,5), P8F(7,2,2,2,7), P8F(3,1,1,5,2), P8F(5,5,6,5,5), /* h i j k */
    P8F(4,4,4,4,7), P8F(5,7,7,5,5), P8F(6,5,5,5,5), P8F(7,5,5,5,7), /* l m n o */
    P8F(7,5,7,4,4), P8F(7,5,5,7,3), P8F(6,5,6,5,5), P8F(7,4,7,1,7), /* p q r s */
    P8F(7,2,2,2,2), P8F(5,5,5,5,7), P8F(5,5,5,5,2), P8F(5,5,7,7,5), /* t u v w */
    P8F(5,5,2,5,5), P8F(5,5,2,2,2), P8F(7,1,2,4,7), P8F(1,2,6,2,1), /* x y z { */
    P8F(2,2,2,2,2), P8F(4,2,3,2,4), P8F(2,5,2,0,0)                  /* | } ~   */
};

static void p8_print_str(const char *str, int x, int y, u8 col)
{
    int cx = x;
    for (int i = 0; str[i]; i++) {
        u8 ch = (u8)str[i];
        if (ch == '\n') { cx = x; y += 6; continue; }
        if (ch >= 32 && ch <= 126) {
            u16 bits = p8_font3x5[ch - 32];
            for (int gy = 0; gy < 5; gy++) {
                u16 row = (bits >> ((4 - gy) * 3)) & 7u;
                if (row & 4u) p8_pset(cx + 0, y + gy, col);
                if (row & 2u) p8_pset(cx + 1, y + gy, col);
                if (row & 1u) p8_pset(cx + 2, y + gy, col);
            }
        }
        cx += 4;
    }
    M->ram[0x5F26] = (u8)x;
    M->ram[0x5F27] = (u8)(y + 6);
}

/* ============================================================================
   4-Channel 48 kHz PICO-8 Synthesizer & Pattern Music Engine
   ============================================================================ */

static void p8_trigger_sfx(int n, int chan, int offset)
{
    if (n == -1) {
        if (chan >= 0 && chan < 4) S.ch[chan].active = 0;
        else for (int i = 0; i < 4; i++) S.ch[i].active = 0;
        return;
    }
    if (n == -2) {
        if (chan >= 0 && chan < 4) S.ch[chan].sfx_id = -1;
        return;
    }
    if (n < 0 || n >= 64) return;
    if (chan < 0 || chan >= 4) {
        chan = 0;
        for (int i = 0; i < 4; i++)
            if (!S.ch[i].active) { chan = i; break; }
    }
    u32 base = 0x3200u + (u32)n * 68u;
    u8 spd = M->ram[base + 65u];
    if (!spd) spd = 16u;
    u32 sr = S.sample_rate ? S.sample_rate : 48000u;
    struct p8_chan *c = &S.ch[chan];
    c->sfx_id         = (s8)n;
    c->note_idx       = (u8)(offset & 31);
    c->sample_in_note = 0;
    c->tick_samples   = (sr * (u32)spd * 183u) >> 15; /* ~1/183s per PICO-8 speed unit */
    if (c->tick_samples < 64u) c->tick_samples = 64u;
    c->lfsr           = 0x7FFFu;
    c->active         = 1u;
}

static void p8_trigger_music(int pat)
{
    if (pat < 0 || pat >= 64) {
        S.music_pat = -1;
        for (int i = 0; i < 4; i++) S.ch[i].active = 0;
        return;
    }
    S.music_pat = (s8)pat;
    u32 pbase = 0x3100u + (u32)pat * 4u;
    u32 max_samples = 0;
    for (int i = 0; i < 4; i++) {
        u8 b = M->ram[pbase + (u32)i];
        if (b & 0x40u) continue;    /* channel disabled in this pattern */
        p8_trigger_sfx(b & 63u, i, 0);
        u32 len = S.ch[i].tick_samples * 32u;
        if (len > max_samples) max_samples = len;
    }
    S.music_tick_rem = max_samples ? max_samples : 16000u;
}

static s16 p8_audio_sample_48k(void)
{
    u32 sr = S.sample_rate ? S.sample_rate : 48000u;
    if (S.music_pat >= 0) {
        if (S.music_tick_rem > 0) {
            S.music_tick_rem--;
        } else {
            u32 pbase = 0x3100u + (u32)S.music_pat * 4u;
            int next_pat = S.music_pat + 1;
            if (M->ram[pbase + 2u] & 0x80u) next_pat = -1;         /* stop at loop end */
            else if (M->ram[pbase + 1u] & 0x80u) {                 /* jump back to loop start */
                int p = S.music_pat;
                while (p > 0 && !(M->ram[0x3100u + (u32)p * 4u] & 0x80u)) p--;
                next_pat = p;
            }
            if (next_pat >= 64) next_pat = 0;
            p8_trigger_music(next_pat);
        }
    }

    s32 mix = 0;
    for (int i = 0; i < 4; i++) {
        struct p8_chan *c = &S.ch[i];
        if (!c->active || c->sfx_id < 0) continue;
        u32 sbase = 0x3200u + (u32)c->sfx_id * 68u;
        u32 n_off = sbase + (u32)c->note_idx * 2u;
        u16 nw = (u16)M->ram[n_off] | ((u16)M->ram[n_off + 1u] << 8);

        u8 pitch = nw & 63u;
        u8 wave  = (nw >> 6) & 7u;
        u8 vol   = (nw >> 9) & 7u;
        u8 eff   = (nw >> 12) & 7u;

        if (vol > 0) {
            u32 hz16 = p8_note_hz16[pitch];
            u32 inc = ((hz16 << 12) / sr) << 4; /* 20-bit phase (0..0xFFFFF) */
            if (eff == 3 && c->tick_samples > 0) {
                /* Drop effect: frequency sweeps down to 0 across note! */
                u32 rem = c->tick_samples - c->sample_in_note;
                inc = (inc * (rem >> 4)) / ((c->tick_samples >> 4) + 1u);
            } else if (eff == 2) {
                /* Vibrato */
                if ((c->sample_in_note & 512u) != 0) inc += (inc >> 6);
            }
            u8 eff_vol = vol;
            if (eff == 4 && c->sample_in_note < (c->tick_samples >> 1))
                eff_vol = (u8)((vol * c->sample_in_note) / ((c->tick_samples >> 1) + 1u));
            else if (eff == 5 && c->sample_in_note > (c->tick_samples >> 1))
                eff_vol = (u8)((vol * (c->tick_samples - c->sample_in_note)) / ((c->tick_samples >> 1) + 1u));

            c->phase = (c->phase + inc) & 0xFFFFFu;
            u32 ph = c->phase >> 10;    /* 0..1023 */
            s32 w = 0;
            switch (wave) {
            case 0: /* Triangle */
                w = (ph < 512u) ? ((s32)ph * 4 - 1024) : (3072 - (s32)ph * 4);
                break;
            case 1: /* Tilted Saw */
                w = (ph < 896u) ? ((s32)ph * 2048 / 896 - 1024) : ((1024 - (s32)ph) * 8 - 1024);
                break;
            case 2: /* Sawtooth */
                w = (s32)ph * 2 - 1024;
                break;
            case 3: /* Square */
                w = (ph < 512u) ? 820 : -820;
                break;
            case 4: /* Pulse */
                w = (ph < 320u) ? 820 : -820;
                break;
            case 5: { /* Organ */
                u32 p2 = (ph * 2u) & 1023u;
                s32 t1 = (ph < 512u) ? ((s32)ph * 4 - 1024) : (3072 - (s32)ph * 4);
                s32 t2 = (p2 < 512u) ? ((s32)p2 * 4 - 1024) : (3072 - (s32)p2 * 4);
                w = (t1 + (t2 >> 1)) * 2 / 3;
                break;
            }
            case 6: /* Noise */
                if ((c->phase & 0x7FFFu) < inc) {
                    u32 bit = ((c->lfsr ^ (c->lfsr >> 1)) & 1u);
                    c->lfsr = (c->lfsr >> 1) | (bit << 14);
                }
                w = (c->lfsr & 1u) ? 720 : -720;
                break;
            default: { /* Phaser */
                u32 p2 = ((c->phase * 127u) >> 17) & 1023u;
                s32 t1 = (ph < 512u) ? ((s32)ph * 4 - 1024) : (3072 - (s32)ph * 4);
                s32 t2 = (p2 < 512u) ? ((s32)p2 * 4 - 1024) : (3072 - (s32)p2 * 4);
                w = (t1 + t2) >> 1;
                break;
            }
            }
            mix += (w * (s32)eff_vol);
        }

        if (++c->sample_in_note >= c->tick_samples) {
            c->sample_in_note = 0;
            u8 ls = M->ram[sbase + 66u] & 63u;
            u8 le = M->ram[sbase + 67u] & 63u;
            c->note_idx++;
            if (le > ls && c->note_idx >= le)
                c->note_idx = ls;
            else if (c->note_idx >= 32u)
                c->active = 0;
        }
    }
    if (mix > 32767) mix = 32767;
    else if (mix < -32768) mix = -32768;
    return (s16)mix;
}

/* ============================================================================
   .p8 Text & .p8.png RGBA Steganography Cartridge Decoders (:c:\0 & \0pxa!)
   ============================================================================ */

static int p8_hex_nib(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int p8_match_hdr(const char *line, int len, const char *tag)
{
    int tl = p8_strlen(tag);
    if (len < tl) return 0;
    for (int i = 0; i < tl; i++)
        if (line[i] != tag[i]) return 0;
    return 1;
}

static const char *p8_load_text_cart(const u8 *src, u32 size)
{
    enum { SEC_NONE = 0, SEC_LUA, SEC_GFX, SEC_GFF, SEC_MAP, SEC_SFX, SEC_MUSIC };
    int sec = SEC_NONE;
    u32 lua_len = 0;
    int gfx_y = 0, gff_row = 0, map_y = 0, sfx_idx = 0, mus_idx = 0;

    u32 pos = 0;
    while (pos < size) {
        u32 ls = pos;
        while (pos < size && src[pos] != '\n') pos++;
        u32 le = pos;
        if (pos < size && src[pos] == '\n') pos++;
        if (le > ls && src[le - 1] == '\r') le--;
        const char *ln = (const char *)(src + ls);
        int llen = (int)(le - ls);

        if (llen >= 5 && ln[0] == '_' && ln[1] == '_') {
            if (p8_match_hdr(ln, llen, "__lua__"))   { sec = SEC_LUA; continue; }
            if (p8_match_hdr(ln, llen, "__gfx__"))   { sec = SEC_GFX; gfx_y = 0; continue; }
            if (p8_match_hdr(ln, llen, "__gff__"))   { sec = SEC_GFF; gff_row = 0; continue; }
            if (p8_match_hdr(ln, llen, "__map__"))   { sec = SEC_MAP; map_y = 0; continue; }
            if (p8_match_hdr(ln, llen, "__sfx__"))   { sec = SEC_SFX; sfx_idx = 0; continue; }
            if (p8_match_hdr(ln, llen, "__music__")) { sec = SEC_MUSIC; mus_idx = 0; continue; }
            if (p8_match_hdr(ln, llen, "__label__")) { sec = SEC_NONE; continue; }
        }

        if (sec == SEC_LUA) {
            if (lua_len + (u32)llen + 2u < P8_LUA_CAP) {
                for (int i = 0; i < llen; i++)
                    M->lua_src[lua_len++] = ln[i];
                M->lua_src[lua_len++] = '\n';
            }
        } else if (sec == SEC_GFX && gfx_y < 128 && llen >= 2) {
            for (int x = 0; x < 128 && x < llen; x++) {
                int v = p8_hex_nib(ln[x]);
                if (v >= 0) p8_sset(x, gfx_y, (u8)v);
            }
            gfx_y++;
        } else if (sec == SEC_GFF && gff_row < 2 && llen >= 2) {
            for (int i = 0; i + 1 < llen && (gff_row * 128 + (i >> 1)) < 256; i += 2) {
                int hi = p8_hex_nib(ln[i]), lo = p8_hex_nib(ln[i + 1]);
                if (hi >= 0 && lo >= 0)
                    M->ram[0x3000 + gff_row * 128 + (i >> 1)] = (u8)((hi << 4) | lo);
            }
            gff_row++;
        } else if (sec == SEC_MAP && map_y < 32 && llen >= 2) {
            for (int x = 0; x < 128 && x * 2 + 1 < llen; x++) {
                int hi = p8_hex_nib(ln[x * 2]), lo = p8_hex_nib(ln[x * 2 + 1]);
                if (hi >= 0 && lo >= 0)
                    M->ram[0x2000 + map_y * 128 + x] = (u8)((hi << 4) | lo);
            }
            map_y++;
        } else if (sec == SEC_SFX && sfx_idx < 64 && llen >= 168) {
            u32 b = 0x3200u + (u32)sfx_idx * 68u;
            int e0 = p8_hex_nib(ln[0]), e1 = p8_hex_nib(ln[1]);
            int s0 = p8_hex_nib(ln[2]), s1 = p8_hex_nib(ln[3]);
            int l0 = p8_hex_nib(ln[4]), l1 = p8_hex_nib(ln[5]);
            int k0 = p8_hex_nib(ln[6]), k1 = p8_hex_nib(ln[7]);
            if (e0 >= 0 && e1 >= 0) M->ram[b + 64u] = (u8)((e0 << 4) | e1);
            if (s0 >= 0 && s1 >= 0) M->ram[b + 65u] = (u8)((s0 << 4) | s1);
            if (l0 >= 0 && l1 >= 0) M->ram[b + 66u] = (u8)((l0 << 4) | l1);
            if (k0 >= 0 && k1 >= 0) M->ram[b + 67u] = (u8)((k0 << 4) | k1);
            for (int n = 0; n < 32; n++) {
                const char *np = ln + 8 + n * 5;
                int p_hi = p8_hex_nib(np[0]), p_lo = p8_hex_nib(np[1]);
                int wv   = p8_hex_nib(np[2]);
                int vl   = p8_hex_nib(np[3]);
                int ef   = p8_hex_nib(np[4]);
                if (p_hi >= 0 && p_lo >= 0 && wv >= 0 && vl >= 0 && ef >= 0) {
                    u16 pitch = (u16)(((p_hi << 4) | p_lo) & 63);
                    u16 word = pitch | ((u16)(wv & 7) << 6) | ((u16)(vl & 7) << 9) | ((u16)(ef & 7) << 12);
                    M->ram[b + (u32)n * 2u]     = (u8)word;
                    M->ram[b + (u32)n * 2u + 1] = (u8)(word >> 8);
                }
            }
            sfx_idx++;
        } else if (sec == SEC_MUSIC && mus_idx < 64 && llen >= 11) {
            /* Format: "FF C0C1C2C3" (e.g. "00 01024344") */
            int f0 = p8_hex_nib(ln[0]), f1 = p8_hex_nib(ln[1]);
            int flags = (f0 >= 0 && f1 >= 0) ? ((f0 << 4) | f1) : 0;
            u32 mb = 0x3100u + (u32)mus_idx * 4u;
            for (int c = 0; c < 4; c++) {
                int c0 = p8_hex_nib(ln[3 + c * 2]), c1 = p8_hex_nib(ln[4 + c * 2]);
                u8 cv = (c0 >= 0 && c1 >= 0) ? (u8)((c0 << 4) | c1) : 0x40u;
                if (c < 3 && (flags & (1 << c))) cv |= 0x80u;
                M->ram[mb + (u32)c] = cv;
            }
            mus_idx++;
        }
    }
    M->lua_src[lua_len] = 0;
    for (u32 i = 0; i < 0x4300u; i++)
        M->rom[i] = M->ram[i];
    return 0;
}

static u32 be32_rd(const u8 *p)
{
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

static u8 paeth_pred(int a, int b, int c)
{
    int p = a + b - c;
    int pa = p - a; if (pa < 0) pa = -pa;
    int pb = p - b; if (pb < 0) pb = -pb;
    int pc = p - c; if (pc < 0) pc = -pc;
    if (pa <= pb && pa <= pc) return (u8)a;
    if (pb <= pc) return (u8)b;
    return (u8)c;
}

static void p8_decompress_legacy_c(const u8 *in, u32 in_cap)
{
    static const char lut[60] = "\n 0123456789abcdefghijklmnopqrstuvwxyz!#%(){}[]<>+=/*:;.,~_";
    u32 want = ((u32)in[4] << 8) | in[5];
    if (want >= P8_LUA_CAP) want = P8_LUA_CAP - 1u;
    u32 ip = 8, op = 0;
    while (ip < in_cap && op < want) {
        u8 code = in[ip++];
        if (code == 0x00u) {
            if (ip < in_cap) M->lua_src[op++] = (char)in[ip++];
        } else if (code <= 0x3Bu) {
            M->lua_src[op++] = lut[code - 1u];
        } else {
            if (ip >= in_cap) break;
            u8 b2 = in[ip++];
            u32 back = (u32)(code - 0x3Cu) * 16u + (b2 & 0x0Fu);
            u32 len  = (u32)(b2 >> 4) + 2u;
            if (back == 0 || back > op) continue;
            for (u32 k = 0; k < len && op < want; k++) {
                M->lua_src[op] = M->lua_src[op - back];
                op++;
            }
        }
    }
    M->lua_src[op] = 0;
}

struct pxa_bits { const u8 *buf; u32 len, bit_pos; };
static u32 pxa_get1(struct pxa_bits *b)
{
    u32 byte_idx = b->bit_pos >> 3;
    if (byte_idx >= b->len) return 0;
    u32 v = (b->buf[byte_idx] >> (b->bit_pos & 7u)) & 1u;
    b->bit_pos++;
    return v;
}
static u32 pxa_getn(struct pxa_bits *b, int n)
{
    u32 v = 0;
    for (int i = 0; i < n; i++) v |= (pxa_get1(b) << i);
    return v;
}

static void p8_decompress_pxa(const u8 *in, u32 in_cap)
{
    u32 want = ((u32)in[4] << 8) | in[5];
    if (want >= P8_LUA_CAP) want = P8_LUA_CAP - 1u;
    u8 mtf[256];
    for (int i = 0; i < 256; i++) mtf[i] = (u8)i;
    struct pxa_bits bs = { in + 8, in_cap > 8u ? in_cap - 8u : 0u, 0 };
    u32 op = 0;
    while (op < want && (bs.bit_pos >> 3) < bs.len) {
        if (pxa_get1(&bs)) {
            int unary = 0;
            while (pxa_get1(&bs) && unary < 16) unary++;
            int bits = unary + 4;
            u32 base = ((1u << unary) - 1u) << 4;
            u32 idx = (base + pxa_getn(&bs, bits)) & 255u;
            u8 ch = mtf[idx];
            for (u32 k = idx; k > 0; k--) mtf[k] = mtf[k - 1u];
            mtf[0] = ch;
            M->lua_src[op++] = (char)ch;
        } else {
            int off_bits = pxa_get1(&bs) ? (pxa_get1(&bs) ? 5 : 10) : 15;
            u32 offset = pxa_getn(&bs, off_bits) + 1u;
            if (off_bits == 10 && offset == 1u) {
                /* Raw uncompressed literal block until 0x00 byte */
                for (;;) {
                    u8 ch = (u8)pxa_getn(&bs, 8);
                    if (!ch || op >= want) break;
                    M->lua_src[op++] = (char)ch;
                }
                continue;
            }
            u32 len = 3u;
            for (;;) {
                u32 part = pxa_getn(&bs, 3);
                len += part;
                if (part != 7u) break;
            }
            if (offset > op) continue;
            for (u32 k = 0; k < len && op < want; k++) {
                M->lua_src[op] = M->lua_src[op - offset];
                op++;
            }
        }
    }
    M->lua_src[op] = 0;
}

static const char *p8_load_png_cart(const u8 *png, u32 size)
{
    if (size < 33 || png[0] != 0x89 || png[1] != 'P' || png[2] != 'N' || png[3] != 'G')
        return "invalid .p8.png header";

    u32 w = 0, h = 0, zlen = 0;
    u8 depth = 0, ctype = 0;
    u32 pos = 8;
    while (pos + 12u <= size) {
        u32 clen = be32_rd(png + pos);
        const u8 *ctag = png + pos + 4u;
        const u8 *cdat = png + pos + 8u;
        if (pos + 12u + clen > size) break;
        if (ctag[0] == 'I' && ctag[1] == 'H' && ctag[2] == 'D' && ctag[3] == 'R' && clen >= 13u) {
            w = be32_rd(cdat);
            h = be32_rd(cdat + 4u);
            depth = cdat[8];
            ctype = cdat[9];
        } else if (ctag[0] == 'I' && ctag[1] == 'D' && ctag[2] == 'A' && ctag[3] == 'T') {
            if (zlen + clen <= sizeof(M->png_zbuf)) {
                for (u32 i = 0; i < clen; i++) M->png_zbuf[zlen++] = cdat[i];
            }
        } else if (ctag[0] == 'I' && ctag[1] == 'E' && ctag[2] == 'N' && ctag[3] == 'D') {
            break;
        }
        pos += 12u + clen;
    }

    int bpp = (ctype == 6u) ? 4 : ((ctype == 2u) ? 3 : 0);
    if (depth != 8u || !bpp || w < 160u || h < 205u || zlen < 6u)
        return "expected 160x205 8-bit RGBA .p8.png cartridge";

    u32 zskip = (M->png_zbuf[1] & 0x20u) ? 6u : 2u;
    u32 made = 0;
    const char *inf_err = image_inflate(M->png_zbuf + zskip, zlen - zskip, M->png_raw, sizeof(M->png_raw), &made);
    if (inf_err)
        return inf_err;

    u32 stride = w * (u32)bpp;
    if (made < 205u * (stride + 1u))
        return "truncated .p8.png image data";

    /* Unfilter PNG rows in-place and extract 32,800 PICO-8 steganography bytes! */
    u32 out_idx = 0;
    for (u32 y = 0; y < 205u; y++) {
        u8 *f_ptr = M->png_raw + y * (stride + 1u);
        u8 ft = f_ptr[0];
        u8 *cur = f_ptr + 1u;
        const u8 *prv = (y > 0) ? (f_ptr - stride) : 0;
        for (u32 x = 0; x < stride; x++) {
            int a = (x >= (u32)bpp) ? cur[x - (u32)bpp] : 0;
            int b = prv ? prv[x] : 0;
            int c = (prv && x >= (u32)bpp) ? prv[x - (u32)bpp] : 0;
            if (ft == 1u)      cur[x] = (u8)(cur[x] + a);
            else if (ft == 2u) cur[x] = (u8)(cur[x] + b);
            else if (ft == 3u) cur[x] = (u8)(cur[x] + ((a + b) >> 1));
            else if (ft == 4u) cur[x] = (u8)(cur[x] + paeth_pred(a, b, c));
        }
        for (u32 px = 0; px < 160u && out_idx < 0x8000u; px++) {
            const u8 *p = cur + px * (u32)bpp;
            u8 r = p[0], g = p[1], b = p[2], al = (bpp == 4) ? p[3] : 0;
            M->cart_raw[out_idx++] = (u8)(((al & 3u) << 6) | ((r & 3u) << 4) | ((g & 3u) << 2) | (b & 3u));
        }
    }

    for (u32 i = 0; i < 0x4300u; i++)
        M->ram[i] = M->rom[i] = M->cart_raw[i];

    const u8 *code = M->cart_raw + 0x4300u;
    u32 code_cap = 0x8000u - 0x4300u;
    if (code[0] == ':' && code[1] == 'c' && code[2] == ':' && code[3] == 0) {
        p8_decompress_legacy_c(code, code_cap);
    } else if (code[0] == 0 && code[1] == 'p' && code[2] == 'x' && code[3] == 'a') {
        p8_decompress_pxa(code, code_cap);
    } else {
        u32 k = 0;
        for (; k < code_cap && code[k]; k++)
            M->lua_src[k] = (char)code[k];
        M->lua_src[k] = 0;
    }
    return 0;
}

/* ============================================================================
   PICO-8 Lua String / Table / GC Manager & Lexer + Parser + AST Evaluator
   ============================================================================ */

static struct p8_val val_nil(void)       { struct p8_val v = {V_NIL, 0, 0, 0}; return v; }
static struct p8_val val_bool(int b)     { struct p8_val v = {V_BOOL, 0, 0, b ? 1 : 0}; return v; }
static struct p8_val val_num(s32 f)      { struct p8_val v = {V_NUM, 0, 0, f}; return v; }
static struct p8_val val_int(int x)      { return val_num(fix_from_int(x)); }

static void p8_gc_mark_val(struct p8_val v)
{
    if (v.type == V_STR && v.u < P8_MAX_STRS) {
        M->strs[v.u].mark = 1u;
    } else if ((v.type == V_TAB || v.type == V_ITER) && v.u < P8_MAX_TABS) {
        struct p8_tab *t = &M->tabs[v.u];
        if (t->mark) return;
        t->mark = 1u;
        for (u16 i = 0; i < t->count; i++) {
            p8_gc_mark_val(t->items[i].k);
            p8_gc_mark_val(t->items[i].v);
        }
    }
}

static void p8_gc_collect(void)
{
    for (int i = 0; i < P8_MAX_TABS; i++) M->tabs[i].mark = 0;
    for (int i = 0; i < P8_MAX_STRS; i++) M->strs[i].mark = 0;
    /* Keep string literals referenced in AST nodes! */
    for (int i = 0; i < S.n_nodes; i++)
        if (M->nodes[i].kind == ND_STR && M->nodes[i].val >= 0 && M->nodes[i].val < P8_MAX_STRS)
            M->strs[M->nodes[i].val].mark = 1u;
    for (int i = 0; i < S.n_syms; i++)
        p8_gc_mark_val(M->globals[i]);
    for (int i = 0; i < S.local_top; i++)
        p8_gc_mark_val(M->locals[i].v);
    for (int i = 0; i < S.ret_count; i++)
        p8_gc_mark_val(S.ret_vals[i]);

    for (int i = 0; i < P8_MAX_TABS; i++)
        if (M->tabs[i].used && !M->tabs[i].mark) M->tabs[i].used = 0;
    for (int i = 0; i < P8_MAX_STRS; i++)
        if (M->strs[i].used && !M->strs[i].mark) M->strs[i].used = 0;
}

static struct p8_val p8_make_str(const char *s, int len)
{
    if (len < 0) len = p8_strlen(s);
    if (len >= P8_STR_LEN) len = P8_STR_LEN - 1;
    for (int i = 0; i < P8_MAX_STRS; i++) {
        if (M->strs[i].used && M->strs[i].len == (u8)len) {
            int ok = 1;
            for (int k = 0; k < len; k++)
                if (M->strs[i].s[k] != s[k]) { ok = 0; break; }
            if (ok) { struct p8_val v = {V_STR, 0, (u16)i, 0}; return v; }
        }
    }
    int slot = -1;
    for (int pass = 0; pass < 2 && slot < 0; pass++) {
        if (pass == 1) p8_gc_collect();
        for (int i = 0; i < P8_MAX_STRS; i++)
            if (!M->strs[i].used) { slot = i; break; }
    }
    if (slot < 0) slot = 0;
    M->strs[slot].used = 1u;
    M->strs[slot].len  = (u8)len;
    for (int k = 0; k < len; k++) M->strs[slot].s[k] = s[k];
    M->strs[slot].s[len] = 0;
    struct p8_val v = {V_STR, 0, (u16)slot, 0};
    return v;
}

static struct p8_val p8_make_tab(void)
{
    int slot = -1;
    for (int pass = 0; pass < 2 && slot < 0; pass++) {
        if (pass == 1) p8_gc_collect();
        for (int i = 0; i < P8_MAX_TABS; i++)
            if (!M->tabs[i].used) { slot = i; break; }
    }
    if (slot < 0) slot = 0;
    M->tabs[slot].used  = 1u;
    M->tabs[slot].count = 0;
    struct p8_val v = {V_TAB, 0, (u16)slot, 0};
    return v;
}

static int p8_val_eq(struct p8_val a, struct p8_val b)
{
    if (a.type != b.type) return 0;
    if (a.type == V_NIL)  return 1;
    if (a.type == V_NUM || a.type == V_BOOL) return a.n == b.n;
    if (a.type == V_STR)  return p8_streq(M->strs[a.u].s, M->strs[b.u].s);
    return a.u == b.u && a.n == b.n;
}

static struct p8_val p8_tab_get(u16 ti, struct p8_val k)
{
    if (ti >= P8_MAX_TABS || k.type == V_NIL) return val_nil();
    struct p8_tab *t = &M->tabs[ti];
    for (u16 i = 0; i < t->count; i++)
        if (p8_val_eq(t->items[i].k, k)) return t->items[i].v;
    return val_nil();
}

static void p8_tab_set(u16 ti, struct p8_val k, struct p8_val v)
{
    if (ti >= P8_MAX_TABS || k.type == V_NIL) return;
    struct p8_tab *t = &M->tabs[ti];
    for (u16 i = 0; i < t->count; i++) {
        if (p8_val_eq(t->items[i].k, k)) {
            if (v.type == V_NIL) {
                for (u16 j = i; j + 1u < t->count; j++) t->items[j] = t->items[j + 1u];
                t->count--;
            } else {
                t->items[i].v = v;
            }
            return;
        }
    }
    if (v.type != V_NIL && t->count < P8_TAB_CAP) {
        t->items[t->count].k = k;
        t->items[t->count].v = v;
        t->count++;
    }
}

static int p8_tab_seq_len(u16 ti)
{
    int n = 0;
    while (p8_tab_get(ti, val_int(n + 1)).type != V_NIL) n++;
    return n;
}

static void p8_val_tostr(struct p8_val v, char *out, int cap)
{
    if (cap < 2) { if (cap > 0) out[0] = 0; return; }
    if (v.type == V_STR) {
        const char *s = M->strs[v.u].s;
        int i = 0;
        for (; s[i] && i < cap - 1; i++) out[i] = s[i];
        out[i] = 0;
        return;
    }
    if (v.type == V_NIL)  { out[0]='n'; out[1]='i'; out[2]='l'; out[3]=0; return; }
    if (v.type == V_BOOL) {
        const char *s = v.n ? "true" : "false";
        int i = 0; while (s[i]) { out[i] = s[i]; i++; } out[i] = 0;
        return;
    }
    if (v.type == V_NUM) {
        s32 x = v.n;
        int pos = 0;
        if (x < 0) { out[pos++] = '-'; x = -x; }
        u32 ip = (u32)x >> 16;
        u32 fp = (u32)x & 0xFFFFu;
        char rev[16]; int rl = 0;
        if (ip == 0) rev[rl++] = '0';
        else while (ip > 0) { rev[rl++] = (char)('0' + (ip % 10u)); ip /= 10u; }
        while (rl > 0 && pos < cap - 1) out[pos++] = rev[--rl];
        if (fp != 0 && pos < cap - 6) {
            out[pos++] = '.';
            u32 dec = (fp * 10000u + 32768u) >> 16;
            char fd[4] = {
                (char)('0' + (dec / 1000u) % 10u), (char)('0' + (dec / 100u) % 10u),
                (char)('0' + (dec / 10u) % 10u),   (char)('0' + dec % 10u)
            };
            int fl = 4;
            while (fl > 1 && fd[fl - 1] == '0') fl--;
            for (int i = 0; i < fl && pos < cap - 1; i++) out[pos++] = fd[i];
        }
        out[pos] = 0;
        return;
    }
    out[0] = '['; out[1] = ']'; out[2] = 0;
}

static int p8_intern(const char *name, int len)
{
    if (len >= 23) len = 23;
    for (int i = 0; i < S.n_syms; i++) {
        int ok = 1;
        for (int k = 0; k < len; k++)
            if (M->syms[i][k] != name[k]) { ok = 0; break; }
        if (ok && M->syms[i][len] == 0) return i;
    }
    if (S.n_syms >= P8_MAX_SYMS) return 0;
    int id = S.n_syms++;
    for (int k = 0; k < len; k++) M->syms[id][k] = name[k];
    M->syms[id][len] = 0;
    M->globals[id] = val_nil();
    return id;
}

/* ---- Lexer ---- */
static void p8_push_tok(u16 kind, u16 line, s32 val)
{
    if (S.n_toks < P8_MAX_TOKS - 1) {
        M->toks[S.n_toks].kind = kind;
        M->toks[S.n_toks].line = line;
        M->toks[S.n_toks].val  = val;
        S.n_toks++;
    }
}

static void p8_tokenize(const char *src)
{
    S.n_toks = 0;
    u16 line = 1;
    int bol = 1;    /* beginning of line (for PICO-8 '?expr' print shorthand!) */
    int i = 0;
    while (src[i]) {
        char c = src[i];
        if (c == '\n') { line++; bol = 1; i++; continue; }
        if (c == ' ' || c == '\t' || c == '\r') { i++; continue; }

        /* Comments: --, --[[ ... ]], and PICO-8 // */
        if ((c == '-' && src[i + 1] == '-') || (c == '/' && src[i + 1] == '/')) {
            int is_lua_c = (c == '-');
            i += 2;
            if (is_lua_c && src[i] == '[' && src[i + 1] == '[') {
                i += 2;
                while (src[i] && !(src[i] == ']' && src[i + 1] == ']')) {
                    if (src[i] == '\n') line++;
                    i++;
                }
                if (src[i]) i += 2;
            } else {
                while (src[i] && src[i] != '\n') i++;
            }
            continue;
        }

        if (bol && c == '?') {
            p8_push_tok(TK_PRINTQ, line, 0);
            bol = 0;
            i++;
            continue;
        }
        bol = 0;

        /* Number literal: decimal, 0x hex, 0b binary (with optional fractional part!) */
        if ((c >= '0' && c <= '9') || (c == '.' && src[i + 1] >= '0' && src[i + 1] <= '9')) {
            u32 ip = 0, fp = 0;
            if (c == '0' && (src[i + 1] == 'x' || src[i + 1] == 'X')) {
                i += 2;
                while (p8_hex_nib(src[i]) >= 0) { ip = (ip << 4) | (u32)p8_hex_nib(src[i]); i++; }
                if (src[i] == '.') {
                    i++;
                    u32 sh = 12;
                    while (p8_hex_nib(src[i]) >= 0) {
                        if (sh < 16u) fp |= (u32)p8_hex_nib(src[i]) << sh;
                        sh -= 4u;
                        i++;
                    }
                }
            } else if (c == '0' && (src[i + 1] == 'b' || src[i + 1] == 'B')) {
                i += 2;
                while (src[i] == '0' || src[i] == '1') { ip = (ip << 1) | (u32)(src[i] - '0'); i++; }
            } else {
                while (src[i] >= '0' && src[i] <= '9') { ip = ip * 10u + (u32)(src[i] - '0'); i++; }
                if (src[i] == '.' && src[i + 1] != '.') {
                    i++;
                    u32 num = 0, den = 1u;
                    while (src[i] >= '0' && src[i] <= '9') {
                        if (den < 100000u) { num = num * 10u + (u32)(src[i] - '0'); den *= 10u; }
                        i++;
                    }
                    fp = ((num << 16) + (den >> 1)) / den;
                }
            }
            p8_push_tok(TK_NUM, line, (s32)((ip << 16) + fp));
            continue;
        }

        /* String literal */
        if (c == '"' || c == '\'') {
            char q = src[i++];
            char buf[P8_STR_LEN];
            int bl = 0;
            while (src[i] && src[i] != q && src[i] != '\n') {
                char ch = src[i++];
                if (ch == '\\' && src[i]) {
                    char e = src[i++];
                    if (e == 'n') ch = '\n';
                    else if (e == 't') ch = '\t';
                    else ch = e;
                }
                if (bl < P8_STR_LEN - 1) buf[bl++] = ch;
            }
            if (src[i] == q) i++;
            buf[bl] = 0;
            struct p8_val sv = p8_make_str(buf, bl);
            p8_push_tok(TK_STR, line, sv.u);
            continue;
        }

        /* Identifier or Keyword */
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
            int st = i;
            while ((src[i] >= 'a' && src[i] <= 'z') || (src[i] >= 'A' && src[i] <= 'Z') ||
                   (src[i] >= '0' && src[i] <= '9') || src[i] == '_')
                i++;
            int len = i - st;
            char kw[24];
            int kl = len < 23 ? len : 23;
            for (int k = 0; k < kl; k++) kw[k] = src[st + k];
            kw[kl] = 0;
            static const struct { const char *w; u16 tk; } kws[] = {
                {"local", TK_LOCAL}, {"function", TK_FUNC}, {"if", TK_IF}, {"then", TK_THEN},
                {"elseif", TK_ELSEIF}, {"else", TK_ELSE}, {"end", TK_END}, {"while", TK_WHILE},
                {"do", TK_DO}, {"repeat", TK_REPEAT}, {"until", TK_UNTIL}, {"for", TK_FOR},
                {"in", TK_IN}, {"return", TK_RETURN}, {"break", TK_BREAK}, {"and", TK_AND},
                {"or", TK_OR}, {"not", TK_NOT}, {"true", TK_TRUE}, {"false", TK_FALSE}, {"nil", TK_NIL},
                {0, 0}
            };
            u16 found = 0;
            for (int k = 0; kws[k].w; k++)
                if (p8_streq(kw, kws[k].w)) { found = kws[k].tk; break; }
            if (found) p8_push_tok(found, line, 0);
            else       p8_push_tok(TK_ID, line, p8_intern(src + st, len));
            continue;
        }

        /* Multi-char operators */
        char n1 = src[i + 1], n2 = src[i + 2];
        if (c == '=' && n1 == '=') { p8_push_tok(TK_EQ, line, 0); i += 2; continue; }
        if ((c == '~' || c == '!') && n1 == '=') { p8_push_tok(TK_NE, line, 0); i += 2; continue; }
        if (c == '<' && n1 == '=') { p8_push_tok(TK_LE, line, 0); i += 2; continue; }
        if (c == '>' && n1 == '=') { p8_push_tok(TK_GE, line, 0); i += 2; continue; }
        if (c == '<' && n1 == '<') { p8_push_tok(TK_SHL, line, 0); i += 2; continue; }
        if (c == '>' && n1 == '>' && n2 == '>') { p8_push_tok(TK_LSHR, line, 0); i += 3; continue; }
        if (c == '>' && n1 == '>') { p8_push_tok(TK_SHR, line, 0); i += 2; continue; }
        if (c == '.' && n1 == '.' && n2 == '=') { p8_push_tok(TK_CATEQ, line, 0); i += 3; continue; }
        if (c == '.' && n1 == '.') { p8_push_tok(TK_CONCAT, line, 0); i += 2; continue; }
        if (c == '+' && n1 == '=') { p8_push_tok(TK_ADDEQ, line, 0); i += 2; continue; }
        if (c == '-' && n1 == '=') { p8_push_tok(TK_SUBEQ, line, 0); i += 2; continue; }
        if (c == '*' && n1 == '=') { p8_push_tok(TK_MULEQ, line, 0); i += 2; continue; }
        if (c == '/' && n1 == '=') { p8_push_tok(TK_DIVEQ, line, 0); i += 2; continue; }
        if (c == '%' && n1 == '=') { p8_push_tok(TK_MODEQ, line, 0); i += 2; continue; }
        if (c == '^' && n1 == '^') { p8_push_tok('~', line, 0); i += 2; continue; }
        if (c == '\\') { p8_push_tok('\\', line, 0); i++; continue; }   /* PICO-8 integer divide '\' */

        p8_push_tok((u16)(u8)c, line, 0);
        i++;
    }
    p8_push_tok(TK_EOF, line, 0);
}

/* ---- Recursive-Descent AST Parser ---- */
static s16 new_node(u8 kind, u8 op, s16 a, s16 b, s16 c, s16 d, s32 val)
{
    if (S.n_nodes >= P8_MAX_NODES) return 0;
    s16 idx = (s16)S.n_nodes++;
    struct p8_node *n = &M->nodes[idx];
    n->kind = kind; n->op = op;
    n->a = a; n->b = b; n->c = c; n->d = d;
    n->val = val;
    return idx;
}

static inline struct p8_tok *cur_tok(void) { return &M->toks[S.tok_pos]; }
static inline int match_tk(u16 k) { if (cur_tok()->kind == k) { S.tok_pos++; return 1; } return 0; }

static s16 parse_expr(int min_prec);
static s16 parse_stmt(void);
static s16 parse_block(void);

static s16 append_seq(s16 head, s16 item)
{
    if (item < 0) return head;
    if (head < 0) return item;
    return new_node(ND_SEQ, 0, head, item, -1, -1, 0);
}

static s16 parse_func_body(void)
{
    match_tk('(');
    s16 params = -1;
    if (cur_tok()->kind != ')') {
        while (cur_tok()->kind == TK_ID) {
            s16 pv = new_node(ND_VAR, 0, -1, -1, -1, -1, cur_tok()->val);
            S.tok_pos++;
            params = append_seq(params, pv);
            if (!match_tk(',')) break;
        }
    }
    match_tk(')');
    s16 body = parse_block();
    match_tk(TK_END);
    return new_node(ND_FUNC, 0, params, body, -1, -1, 0);
}

static s16 parse_primary(void)
{
    u16 k = cur_tok()->kind;
    if (k == TK_NUM)   { s32 v = cur_tok()->val; S.tok_pos++; return new_node(ND_NUM, 0, -1, -1, -1, -1, v); }
    if (k == TK_STR)   { s32 v = cur_tok()->val; S.tok_pos++; return new_node(ND_STR, 0, -1, -1, -1, -1, v); }
    if (k == TK_TRUE)  { S.tok_pos++; return new_node(ND_BOOL, 0, -1, -1, -1, -1, 1); }
    if (k == TK_FALSE) { S.tok_pos++; return new_node(ND_BOOL, 0, -1, -1, -1, -1, 0); }
    if (k == TK_NIL)   { S.tok_pos++; return new_node(ND_NIL, 0, -1, -1, -1, -1, 0); }
    if (k == TK_FUNC)  { S.tok_pos++; return parse_func_body(); }
    if (k == '(') {
        S.tok_pos++;
        s16 e = parse_expr(1);
        match_tk(')');
        return e;
    }
    if (k == '{') {
        S.tok_pos++;
        s16 items = -1;
        while (cur_tok()->kind != '}' && cur_tok()->kind != TK_EOF) {
            s16 key = -1, val = -1;
            if (cur_tok()->kind == '[') {
                S.tok_pos++;
                key = parse_expr(1);
                match_tk(']');
                match_tk('=');
                val = parse_expr(1);
            } else if (cur_tok()->kind == TK_ID && M->toks[S.tok_pos + 1].kind == '=') {
                s32 sym = cur_tok()->val;
                S.tok_pos += 2;
                struct p8_val sv = p8_make_str(M->syms[sym], -1);
                key = new_node(ND_STR, 0, -1, -1, -1, -1, sv.u);
                val = parse_expr(1);
            } else {
                val = parse_expr(1);
            }
            items = append_seq(items, new_node(ND_KV, 0, key, val, -1, -1, 0));
            if (!match_tk(',') && !match_tk(';')) break;
        }
        match_tk('}');
        return new_node(ND_TABLE, 0, items, -1, -1, -1, 0);
    }
    if (k == TK_ID) {
        s32 sym = cur_tok()->val;
        S.tok_pos++;
        return new_node(ND_VAR, 0, -1, -1, -1, -1, sym);
    }
    S.tok_pos++;
    return new_node(ND_NIL, 0, -1, -1, -1, -1, 0);
}

static s16 parse_postfix(void)
{
    s16 lhs = parse_primary();
    for (;;) {
        u16 k = cur_tok()->kind;
        if (k == '.') {
            S.tok_pos++;
            if (cur_tok()->kind == TK_ID) {
                struct p8_val sv = p8_make_str(M->syms[cur_tok()->val], -1);
                S.tok_pos++;
                s16 kn = new_node(ND_STR, 0, -1, -1, -1, -1, sv.u);
                lhs = new_node(ND_INDEX, 0, lhs, kn, -1, -1, 0);
            }
        } else if (k == '[') {
            S.tok_pos++;
            s16 idx = parse_expr(1);
            match_tk(']');
            lhs = new_node(ND_INDEX, 0, lhs, idx, -1, -1, 0);
        } else if (k == '(') {
            S.tok_pos++;
            s16 args = -1;
            if (cur_tok()->kind != ')') {
                for (;;) {
                    args = append_seq(args, parse_expr(1));
                    if (!match_tk(',')) break;
                }
            }
            match_tk(')');
            lhs = new_node(ND_CALL, 0, lhs, args, -1, -1, 0);
        } else if (k == TK_STR) {
            s16 arg = new_node(ND_STR, 0, -1, -1, -1, -1, cur_tok()->val);
            S.tok_pos++;
            lhs = new_node(ND_CALL, 0, lhs, arg, -1, -1, 0);
        } else {
            break;
        }
    }
    return lhs;
}

static s16 parse_unary(void)
{
    u16 k = cur_tok()->kind;
    if (k == '+') { S.tok_pos++; return parse_unary(); }
    if (k == '-' || k == TK_NOT || k == '#' || k == '~') {
        S.tok_pos++;
        s16 sub = parse_unary();
        return new_node(ND_UNOP, (u8)k, sub, -1, -1, -1, 0);
    }
    return parse_postfix();
}

static int bin_prec(u16 k)
{
    switch (k) {
    case TK_OR:     return 1;
    case TK_AND:    return 2;
    case '<': case '>': case TK_LE: case TK_GE: case TK_EQ: case TK_NE: return 3;
    case '|':       return 4;
    case '~':       return 5;
    case '&':       return 6;
    case TK_SHL: case TK_SHR: case TK_LSHR: return 7;
    case TK_CONCAT: return 8;
    case '+': case '-': return 9;
    case '*': case '/': case '\\': case '%': return 10;
    case '^':       return 11;
    default:        return 0;
    }
}

static s16 parse_expr(int min_prec)
{
    s16 lhs = parse_unary();
    for (;;) {
        u16 op = cur_tok()->kind;
        int p = bin_prec(op);
        if (p < min_prec) break;
        S.tok_pos++;
        int next_p = (op == '^' || op == TK_CONCAT) ? p : (p + 1);
        s16 rhs = parse_expr(next_p);
        lhs = new_node(ND_BINOP, (u8)op, lhs, rhs, -1, -1, 0);
    }
    return lhs;
}

static int is_block_end(u16 k)
{
    return k == TK_EOF || k == TK_END || k == TK_ELSE || k == TK_ELSEIF || k == TK_UNTIL;
}

static s16 parse_if_stmt(void)
{
    /* Supports BOTH standard `if cond then ... end` AND PICO-8 single-line `if (cond) stmt`! */
    u16 if_line = M->toks[S.tok_pos - 1].line;
    int started_paren = (cur_tok()->kind == '(');
    int save_pos = S.tok_pos;
    s16 cond = parse_expr(1);

    if (match_tk(TK_THEN)) {
        s16 th = parse_block();
        s16 el = -1;
        if (match_tk(TK_ELSEIF)) {
            el = parse_if_stmt();
            return new_node(ND_IF, 0, cond, th, el, -1, 0);
        }
        if (match_tk(TK_ELSE))
            el = parse_block();
        match_tk(TK_END);
        return new_node(ND_IF, 0, cond, th, el, -1, 0);
    }

    /* PICO-8 short single-line `if (cond) stmt [else stmt]`!
       Re-parse `(cond)` cleanly as a single parenthesized group so `if (a) b = 1` doesn't swallow `(b)` as a call! */
    if (started_paren) {
        S.tok_pos = save_pos + 1;
        cond = parse_expr(1);
        match_tk(')');
    }
    s16 th = -1, el = -1;
    while (cur_tok()->line == if_line && !is_block_end(cur_tok()->kind)) {
        if (cur_tok()->kind == TK_ELSE) break;
        th = append_seq(th, parse_stmt());
    }
    if (cur_tok()->line == if_line && match_tk(TK_ELSE)) {
        while (cur_tok()->line == if_line && !is_block_end(cur_tok()->kind))
            el = append_seq(el, parse_stmt());
    }
    return new_node(ND_IF, 0, cond, th, el, -1, 0);
}

static s16 parse_stmt(void)
{
    while (match_tk(';')) {}
    u16 k = cur_tok()->kind;
    if (is_block_end(k)) return -1;

    if (match_tk(TK_PRINTQ)) {
        u16 pline = M->toks[S.tok_pos - 1].line;
        s16 args = -1;
        while (cur_tok()->line == pline && !is_block_end(cur_tok()->kind)) {
            args = append_seq(args, parse_expr(1));
            if (!match_tk(',')) break;
        }
        s16 pvar = new_node(ND_VAR, 0, -1, -1, -1, -1, p8_intern("print", 5));
        return new_node(ND_CALL, 0, pvar, args, -1, -1, 0);
    }

    if (match_tk(TK_IF))
        return parse_if_stmt();

    if (match_tk(TK_WHILE)) {
        s16 cond = parse_expr(1);
        match_tk(TK_DO);
        s16 body = parse_block();
        match_tk(TK_END);
        return new_node(ND_WHILE, 0, cond, body, -1, -1, 0);
    }

    if (match_tk(TK_REPEAT)) {
        s16 body = parse_block();
        match_tk(TK_UNTIL);
        s16 cond = parse_expr(1);
        return new_node(ND_REPEAT, 0, body, cond, -1, -1, 0);
    }

    if (match_tk(TK_FOR)) {
        if (cur_tok()->kind == TK_ID && M->toks[S.tok_pos + 1].kind == '=') {
            s32 vsym = cur_tok()->val;
            S.tok_pos += 2;
            s16 e1 = parse_expr(1);
            match_tk(',');
            s16 e2 = parse_expr(1);
            s16 e3 = match_tk(',') ? parse_expr(1) : -1;
            match_tk(TK_DO);
            s16 body = parse_block();
            match_tk(TK_END);
            return new_node(ND_FOR_NUM, 0, e1, e2, e3, body, vsym);
        } else {
            s32 ksym = cur_tok()->val; S.tok_pos++;
            s32 vsym = -1;
            if (match_tk(',')) { vsym = cur_tok()->val; S.tok_pos++; }
            match_tk(TK_IN);
            s16 iter = parse_expr(1);
            match_tk(TK_DO);
            s16 body = parse_block();
            match_tk(TK_END);
            return new_node(ND_FOR_IN, 0, (s16)ksym, (s16)vsym, iter, body, 0);
        }
    }

    if (match_tk(TK_FUNC)) {
        s16 target = -1;
        if (cur_tok()->kind == TK_ID) {
            target = new_node(ND_VAR, 0, -1, -1, -1, -1, cur_tok()->val);
            S.tok_pos++;
            while (match_tk('.') && cur_tok()->kind == TK_ID) {
                struct p8_val sv = p8_make_str(M->syms[cur_tok()->val], -1);
                S.tok_pos++;
                s16 kn = new_node(ND_STR, 0, -1, -1, -1, -1, sv.u);
                target = new_node(ND_INDEX, 0, target, kn, -1, -1, 0);
            }
        }
        s16 fn = parse_func_body();
        return new_node(ND_ASSIGN, 0, target, fn, -1, -1, 0);
    }

    if (match_tk(TK_LOCAL)) {
        if (match_tk(TK_FUNC)) {
            s32 sym = cur_tok()->val; S.tok_pos++;
            s16 fn = parse_func_body();
            s16 lv = new_node(ND_VAR, 0, -1, -1, -1, -1, sym);
            return new_node(ND_LOCAL, 0, lv, fn, -1, -1, 0);
        }
        s16 vars = -1, vals = -1;
        for (;;) {
            if (cur_tok()->kind == TK_ID) {
                vars = append_seq(vars, new_node(ND_VAR, 0, -1, -1, -1, -1, cur_tok()->val));
                S.tok_pos++;
            }
            if (!match_tk(',')) break;
        }
        if (match_tk('=')) {
            for (;;) {
                vals = append_seq(vals, parse_expr(1));
                if (!match_tk(',')) break;
            }
        }
        return new_node(ND_LOCAL, 0, vars, vals, -1, -1, 0);
    }

    if (match_tk(TK_RETURN)) {
        s16 vals = -1;
        u16 rk = cur_tok()->kind;
        if (!is_block_end(rk) && rk != ';') {
            for (;;) {
                vals = append_seq(vals, parse_expr(1));
                if (!match_tk(',')) break;
            }
        }
        return new_node(ND_RETURN, 0, vals, -1, -1, -1, 0);
    }

    if (match_tk(TK_BREAK))
        return new_node(ND_BREAK, 0, -1, -1, -1, -1, 0);

    s16 lhs = parse_postfix();
    u16 ck = cur_tok()->kind;
    if (ck == TK_ADDEQ || ck == TK_SUBEQ || ck == TK_MULEQ || ck == TK_DIVEQ || ck == TK_MODEQ || ck == TK_CATEQ) {
        S.tok_pos++;
        s16 rhs = parse_expr(1);
        return new_node(ND_COMPOUND, (u8)ck, lhs, rhs, -1, -1, 0);
    }
    if (ck == '=' || ck == ',') {
        s16 targets = lhs;
        while (match_tk(','))
            targets = append_seq(targets, parse_postfix());
        match_tk('=');
        s16 vals = -1;
        for (;;) {
            vals = append_seq(vals, parse_expr(1));
            if (!match_tk(',')) break;
        }
        return new_node(ND_ASSIGN, 0, targets, vals, -1, -1, 0);
    }
    return lhs;
}

static s16 parse_block(void)
{
    s16 seq = -1;
    while (!is_block_end(cur_tok()->kind)) {
        s16 st = parse_stmt();
        if (st >= 0) seq = append_seq(seq, st);
        else if (!is_block_end(cur_tok()->kind)) S.tok_pos++;
    }
    return new_node(ND_BLOCK, 0, seq, -1, -1, -1, 0);
}

/* ============================================================================
   PICO-8 Standard Library Builtins & AST Evaluator
   ============================================================================ */

enum {
    BI_CLS = 1, BI_PSET, BI_PGET, BI_LINE, BI_RECT, BI_RECTFILL, BI_CIRC, BI_CIRCFILL,
    BI_SPR, BI_SSPR, BI_SGET, BI_SSET, BI_FGET, BI_FSET, BI_MAP, BI_MGET, BI_MSET,
    BI_PRINT, BI_CURSOR, BI_COLOR, BI_PAL, BI_PALT, BI_CAMERA, BI_CLIP, BI_FILLP,
    BI_BTN, BI_BTNP, BI_SFX, BI_MUSIC,
    BI_FLR, BI_CEIL, BI_ABS, BI_SGN, BI_MIN, BI_MAX, BI_MID, BI_SQRT,
    BI_SIN, BI_COS, BI_ATAN2, BI_RND, BI_SRAND,
    BI_BAND, BI_BOR, BI_BXOR, BI_BNOT, BI_SHL, BI_SHR, BI_LSHR,
    BI_ADD, BI_DEL, BI_DELI, BI_COUNT, BI_ALL, BI_FOREACH, BI_PAIRS,
    BI_SUB, BI_CHR, BI_ORD, BI_TOSTR, BI_TONUM,
    BI_PEEK, BI_POKE, BI_PEEK2, BI_POKE2, BI_PEEK4, BI_POKE4,
    BI_MEMCPY, BI_MEMSET, BI_RELOAD, BI_CARTDATA, BI_DGET, BI_DSET, BI_TIME, BI_STAT
};

static struct p8_val eval_node(s16 ni);
static void exec_stmt(s16 ni);
static struct p8_val call_val(struct p8_val fn, struct p8_val *args, int argc);

static int flatten_list(s16 seq, s16 *out, int max)
{
    if (seq < 0) return 0;
    if (M->nodes[seq].kind == ND_SEQ) {
        int n = flatten_list(M->nodes[seq].a, out, max);
        if (n < max) n += flatten_list(M->nodes[seq].b, out + n, max - n);
        return n;
    }
    if (max > 0) { out[0] = seq; return 1; }
    return 0;
}

static inline int arg_int(struct p8_val *a, int argc, int idx, int def)
{
    if (idx >= argc || a[idx].type != V_NUM) return def;
    return fix_to_int(a[idx].n);
}

static inline u8 arg_col(struct p8_val *a, int argc, int idx)
{
    if (idx < argc && a[idx].type == V_NUM) {
        u8 c = (u8)(fix_to_int(a[idx].n) & 15);
        M->ram[0x5F25] = c;
        return c;
    }
    return M->ram[0x5F25] & 15u;
}

static int p8_btn_state(int b)
{
    /* PICO-8 buttons 0..5: 0=Left, 1=Right, 2=Up, 3=Down, 4=O(Z/B), 5=X(A) */
    u16 p = S.pad_cur;
    switch (b) {
    case 0: return (p & 0x0040u) != 0;
    case 1: return (p & 0x0080u) != 0;
    case 2: return (p & 0x0010u) != 0;
    case 3: return (p & 0x0020u) != 0;
    case 4: return (p & 0x0002u) != 0;  /* Z -> O */
    case 5: return (p & 0x0001u) != 0;  /* X -> X */
    default: return 0;
    }
}

static int p8_btnp_state(int b)
{
    if (b < 0 || b >= 6) return 0;
    u8 h = S.hold_frames[b];
    if (h == 1u) return 1;
    if (h >= 16u && ((h - 16u) & 3u) == 0) return 1;
    return 0;
}

static struct p8_val p8_run_builtin(int id, struct p8_val *a, int n)
{
    switch (id) {
    case BI_CLS:      p8_cls((u8)arg_int(a, n, 0, 0)); return val_nil();
    case BI_PSET:     p8_pset(arg_int(a, n, 0, 0), arg_int(a, n, 1, 0), arg_col(a, n, 2)); return val_nil();
    case BI_PGET:     return val_int(p8_pget(arg_int(a, n, 0, 0), arg_int(a, n, 1, 0)));
    case BI_LINE:     p8_line(arg_int(a, n, 0, 0), arg_int(a, n, 1, 0), arg_int(a, n, 2, 0), arg_int(a, n, 3, 0), arg_col(a, n, 4)); return val_nil();
    case BI_RECT:     p8_rect(arg_int(a, n, 0, 0), arg_int(a, n, 1, 0), arg_int(a, n, 2, 0), arg_int(a, n, 3, 0), arg_col(a, n, 4)); return val_nil();
    case BI_RECTFILL: p8_rectfill(arg_int(a, n, 0, 0), arg_int(a, n, 1, 0), arg_int(a, n, 2, 0), arg_int(a, n, 3, 0), arg_col(a, n, 4)); return val_nil();
    case BI_CIRC:     p8_circ(arg_int(a, n, 0, 0), arg_int(a, n, 1, 0), arg_int(a, n, 2, 1), arg_col(a, n, 3), 0); return val_nil();
    case BI_CIRCFILL: p8_circ(arg_int(a, n, 0, 0), arg_int(a, n, 1, 0), arg_int(a, n, 2, 1), arg_col(a, n, 3), 1); return val_nil();
    case BI_SPR: {
        int fx = (n > 5 && a[5].type == V_BOOL) ? a[5].n : arg_int(a, n, 5, 0);
        int fy = (n > 6 && a[6].type == V_BOOL) ? a[6].n : arg_int(a, n, 6, 0);
        p8_spr_blit(arg_int(a, n, 0, 0), arg_int(a, n, 1, 0), arg_int(a, n, 2, 0),
                    arg_int(a, n, 3, 1), arg_int(a, n, 4, 1), fx, fy);
        return val_nil();
    }
    case BI_SSPR: {
        int sw = arg_int(a, n, 2, 8), sh = arg_int(a, n, 3, 8);
        int fx = (n > 8 && a[8].type == V_BOOL) ? a[8].n : arg_int(a, n, 8, 0);
        int fy = (n > 9 && a[9].type == V_BOOL) ? a[9].n : arg_int(a, n, 9, 0);
        p8_sspr(arg_int(a, n, 0, 0), arg_int(a, n, 1, 0), sw, sh,
                arg_int(a, n, 4, 0), arg_int(a, n, 5, 0), arg_int(a, n, 6, sw), arg_int(a, n, 7, sh), fx, fy);
        return val_nil();
    }
    case BI_SGET: return val_int(p8_sget(arg_int(a, n, 0, 0), arg_int(a, n, 1, 0)));
    case BI_SSET: p8_sset(arg_int(a, n, 0, 0), arg_int(a, n, 1, 0), arg_col(a, n, 2)); return val_nil();
    case BI_FGET: {
        int sp = arg_int(a, n, 0, 0) & 255;
        u8 fl = M->ram[0x3000 + sp];
        if (n >= 2 && a[1].type == V_NUM) return val_bool((fl >> (arg_int(a, n, 1, 0) & 7)) & 1);
        return val_int(fl);
    }
    case BI_FSET: {
        int sp = arg_int(a, n, 0, 0) & 255;
        if (n >= 3) {
            int bit = arg_int(a, n, 1, 0) & 7;
            int on  = (a[2].type == V_BOOL) ? a[2].n : (a[2].type != V_NIL && a[2].n != 0);
            if (on) M->ram[0x3000 + sp] |= (u8)(1u << bit);
            else    M->ram[0x3000 + sp] &= (u8)~(1u << bit);
        } else if (n >= 2) {
            M->ram[0x3000 + sp] = (u8)arg_int(a, n, 1, 0);
        }
        return val_nil();
    }
    case BI_MAP:
        p8_draw_map(arg_int(a, n, 0, 0), arg_int(a, n, 1, 0), arg_int(a, n, 2, 0), arg_int(a, n, 3, 0),
                    arg_int(a, n, 4, 16), arg_int(a, n, 5, 16), (u8)arg_int(a, n, 6, 0));
        return val_nil();
    case BI_MGET: return val_int(p8_mget(arg_int(a, n, 0, 0), arg_int(a, n, 1, 0)));
    case BI_MSET: p8_mset(arg_int(a, n, 0, 0), arg_int(a, n, 1, 0), (u8)arg_int(a, n, 2, 0)); return val_nil();
    case BI_PRINT: {
        char buf[64];
        if (n == 0) return val_nil();
        p8_val_tostr(a[0], buf, sizeof(buf));
        int x = (n >= 3) ? arg_int(a, n, 1, 0) : (int)M->ram[0x5F26];
        int y = (n >= 3) ? arg_int(a, n, 2, 0) : (int)M->ram[0x5F27];
        u8  c = (n >= 4) ? arg_col(a, n, 3) : (n == 2 ? arg_col(a, n, 1) : (M->ram[0x5F25] & 15u));
        p8_print_str(buf, x, y, c);
        return val_nil();
    }
    case BI_CURSOR:
        M->ram[0x5F26] = (u8)arg_int(a, n, 0, 0);
        M->ram[0x5F27] = (u8)arg_int(a, n, 1, 0);
        if (n >= 3) M->ram[0x5F25] = (u8)(arg_int(a, n, 2, 6) & 15);
        return val_nil();
    case BI_COLOR:
        M->ram[0x5F25] = (u8)(arg_int(a, n, 0, 6) & 15);
        return val_nil();
    case BI_PAL:
        if (n == 0) {
            for (int i = 0; i < 16; i++) {
                M->ram[0x5F00 + i] = (u8)((M->ram[0x5F00 + i] & 0x10u) | i);
                M->ram[0x5F10 + i] = (u8)i;
            }
        } else if (n >= 2 && a[0].type == V_NUM && a[1].type == V_NUM) {
            int c0 = arg_int(a, n, 0, 0) & 15;
            int c1 = arg_int(a, n, 1, 0);
            int p_kind = arg_int(a, n, 2, 0);
            if (p_kind == 1) {
                u8 sc = (c1 >= 128) ? (u8)(16 + (c1 & 15)) : (u8)(c1 & 15);
                M->ram[0x5F10 + c0] = sc;
            } else {
                M->ram[0x5F00 + c0] = (u8)((M->ram[0x5F00 + c0] & 0x10u) | (c1 & 15));
            }
        }
        return val_nil();
    case BI_PALT:
        if (n == 0) {
            for (int i = 0; i < 16; i++)
                M->ram[0x5F00 + i] = (u8)((M->ram[0x5F00 + i] & 15u) | (i == 0 ? 0x10u : 0u));
        } else if (n >= 2) {
            int c = arg_int(a, n, 0, 0) & 15;
            int tr = (a[1].type == V_BOOL) ? a[1].n : arg_int(a, n, 1, 0);
            if (tr) M->ram[0x5F00 + c] |= 0x10u;
            else    M->ram[0x5F00 + c] &= 0x0Fu;
        }
        return val_nil();
    case BI_CAMERA: {
        s16 cx = (s16)arg_int(a, n, 0, 0), cy = (s16)arg_int(a, n, 1, 0);
        M->ram[0x5F28] = (u8)cx; M->ram[0x5F29] = (u8)((u16)cx >> 8);
        M->ram[0x5F2A] = (u8)cy; M->ram[0x5F2B] = (u8)((u16)cy >> 8);
        return val_nil();
    }
    case BI_CLIP:
        if (n == 0) {
            M->ram[0x5F20] = 0; M->ram[0x5F21] = 0; M->ram[0x5F22] = 128; M->ram[0x5F23] = 128;
        } else {
            int x = arg_int(a, n, 0, 0), y = arg_int(a, n, 1, 0);
            int w = arg_int(a, n, 2, 128), h = arg_int(a, n, 3, 128);
            M->ram[0x5F20] = (u8)(x < 0 ? 0 : x);
            M->ram[0x5F21] = (u8)(y < 0 ? 0 : y);
            M->ram[0x5F22] = (u8)(x + w > 128 ? 128 : x + w);
            M->ram[0x5F23] = (u8)(y + h > 128 ? 128 : y + h);
        }
        return val_nil();
    case BI_FILLP:
        S.fill_pat = (n > 0 && a[0].type == V_NUM) ? (u16)(a[0].n >> 16) : 0;
        return val_nil();
    case BI_BTN:
        if (n == 0) {
            int msk = 0;
            for (int i = 0; i < 6; i++) if (p8_btn_state(i)) msk |= (1 << i);
            return val_int(msk);
        }
        return val_bool(p8_btn_state(arg_int(a, n, 0, 0)));
    case BI_BTNP:
        if (n == 0) {
            int msk = 0;
            for (int i = 0; i < 6; i++) if (p8_btnp_state(i)) msk |= (1 << i);
            return val_int(msk);
        }
        return val_bool(p8_btnp_state(arg_int(a, n, 0, 0)));
    case BI_SFX:
        p8_trigger_sfx(arg_int(a, n, 0, -1), arg_int(a, n, 1, -1), arg_int(a, n, 2, 0));
        return val_nil();
    case BI_MUSIC:
        p8_trigger_music(arg_int(a, n, 0, -1));
        return val_nil();

    /* Math */
    case BI_FLR:  return val_num((n > 0 && a[0].type == V_NUM) ? (a[0].n & (s32)0xFFFF0000u) : 0);
    case BI_CEIL: {
        s32 x = (n > 0 && a[0].type == V_NUM) ? a[0].n : 0;
        return val_num((x & 0xFFFF) ? ((x & (s32)0xFFFF0000u) + 0x10000) : x);
    }
    case BI_ABS: {
        s32 x = (n > 0 && a[0].type == V_NUM) ? a[0].n : 0;
        return val_num(x < 0 ? -x : x);
    }
    case BI_SGN: {
        s32 x = (n > 0 && a[0].type == V_NUM) ? a[0].n : 0;
        return val_num(x < 0 ? -0x10000 : 0x10000);
    }
    case BI_MIN: {
        s32 x = (n > 0 && a[0].type == V_NUM) ? a[0].n : 0;
        s32 y = (n > 1 && a[1].type == V_NUM) ? a[1].n : 0;
        return val_num(x < y ? x : y);
    }
    case BI_MAX: {
        s32 x = (n > 0 && a[0].type == V_NUM) ? a[0].n : 0;
        s32 y = (n > 1 && a[1].type == V_NUM) ? a[1].n : 0;
        return val_num(x > y ? x : y);
    }
    case BI_MID: {
        s32 x = (n > 0 && a[0].type == V_NUM) ? a[0].n : 0;
        s32 y = (n > 1 && a[1].type == V_NUM) ? a[1].n : 0;
        s32 z = (n > 2 && a[2].type == V_NUM) ? a[2].n : 0;
        if (x > y) { s32 t = x; x = y; y = t; }
        if (y > z) { y = z; if (x > y) y = x; }
        return val_num(y);
    }
    case BI_SQRT:  return val_num(fix_sqrt((n > 0 && a[0].type == V_NUM) ? a[0].n : 0));
    case BI_SIN:   return val_num(p8_sin_turns((n > 0 && a[0].type == V_NUM) ? a[0].n : 0));
    case BI_COS:   return val_num(p8_cos_turns((n > 0 && a[0].type == V_NUM) ? a[0].n : 0));
    case BI_ATAN2: return val_num(p8_atan2((n > 0 && a[0].type == V_NUM) ? a[0].n : 0,
                                           (n > 1 && a[1].type == V_NUM) ? a[1].n : 0));
    case BI_RND: {
        if (n > 0 && a[0].type == V_TAB) {
            int len = p8_tab_seq_len(a[0].u);
            if (len <= 0) return val_nil();
            return p8_tab_get(a[0].u, val_int((int)(p8_rand_u32() % (u32)len) + 1));
        }
        s32 lim = (n > 0 && a[0].type == V_NUM) ? a[0].n : 0x10000;
        if (lim <= 0) return val_num(0);
        return val_num((s32)(p8_rand_u32() % (u32)lim));
    }
    case BI_SRAND: {
        u32 sd = (n > 0 && a[0].type == V_NUM) ? (u32)a[0].n : 1u;
        if (!sd) sd = 0xDEADBEEFu;
        S.rng_hi = sd ^ 0xBEEF1234u;
        S.rng_lo = (sd << 7) ^ 0x5A5AA5A5u;
        return val_nil();
    }

    /* Bitwise */
    case BI_BAND: return val_num((n > 1 ? a[0].n & a[1].n : 0));
    case BI_BOR:  return val_num((n > 1 ? a[0].n | a[1].n : 0));
    case BI_BXOR: return val_num((n > 1 ? a[0].n ^ a[1].n : 0));
    case BI_BNOT: return val_num(n > 0 ? ~a[0].n : -1);
    case BI_SHL:  return val_num(n > 1 ? (s32)((u32)a[0].n << (arg_int(a, n, 1, 0) & 31)) : 0);
    case BI_SHR:  return val_num(n > 1 ? (a[0].n >> (arg_int(a, n, 1, 0) & 31)) : 0);
    case BI_LSHR: return val_num(n > 1 ? (s32)((u32)a[0].n >> (arg_int(a, n, 1, 0) & 31)) : 0);

    /* Table Helpers */
    case BI_ADD:
        if (n >= 2 && a[0].type == V_TAB) {
            int len = p8_tab_seq_len(a[0].u);
            p8_tab_set(a[0].u, val_int(len + 1), a[1]);
            return a[1];
        }
        return val_nil();
    case BI_DEL:
        if (n >= 2 && a[0].type == V_TAB) {
            int len = p8_tab_seq_len(a[0].u);
            for (int i = 1; i <= len; i++) {
                if (p8_val_eq(p8_tab_get(a[0].u, val_int(i)), a[1])) {
                    for (int j = i; j < len; j++)
                        p8_tab_set(a[0].u, val_int(j), p8_tab_get(a[0].u, val_int(j + 1)));
                    p8_tab_set(a[0].u, val_int(len), val_nil());
                    return a[1];
                }
            }
        }
        return val_nil();
    case BI_DELI:
        if (n >= 1 && a[0].type == V_TAB) {
            int len = p8_tab_seq_len(a[0].u);
            int idx = (n >= 2 && a[1].type == V_NUM) ? fix_to_int(a[1].n) : len;
            if (idx >= 1 && idx <= len) {
                struct p8_val old = p8_tab_get(a[0].u, val_int(idx));
                for (int j = idx; j < len; j++)
                    p8_tab_set(a[0].u, val_int(j), p8_tab_get(a[0].u, val_int(j + 1)));
                p8_tab_set(a[0].u, val_int(len), val_nil());
                return old;
            }
        }
        return val_nil();
    case BI_COUNT:
        return val_int((n >= 1 && a[0].type == V_TAB) ? p8_tab_seq_len(a[0].u) : 0);
    case BI_ALL:
    case BI_PAIRS:
        if (n >= 1 && a[0].type == V_TAB) {
            struct p8_val it = {V_ITER, (u8)(id == BI_PAIRS ? 1 : 0), a[0].u, 0};
            return it;
        }
        return val_nil();
    case BI_FOREACH:
        if (n >= 2 && a[0].type == V_TAB) {
            /* Snapshot elements first so del(t, v) inside foreach works just like PICO-8! */
            struct p8_val snap[P8_TAB_CAP];
            int len = p8_tab_seq_len(a[0].u);
            if (len > P8_TAB_CAP) len = P8_TAB_CAP;
            for (int i = 0; i < len; i++) snap[i] = p8_tab_get(a[0].u, val_int(i + 1));
            for (int i = 0; i < len; i++) (void)call_val(a[1], &snap[i], 1);
        }
        return val_nil();

    /* Strings */
    case BI_SUB:
        if (n >= 2 && a[0].type == V_STR) {
            const char *s = M->strs[a[0].u].s;
            int sl = M->strs[a[0].u].len;
            int i0 = arg_int(a, n, 1, 1);
            int i1 = (n >= 3 && a[2].type == V_NUM) ? fix_to_int(a[2].n) : sl;
            if (i0 < 0) i0 = sl + 1 + i0;
            if (i1 < 0) i1 = sl + 1 + i1;
            if (i0 < 1) i0 = 1;
            if (i1 > sl) i1 = sl;
            if (i0 > i1) return p8_make_str("", 0);
            return p8_make_str(s + (i0 - 1), i1 - i0 + 1);
        }
        return p8_make_str("", 0);
    case BI_CHR: { char c = (char)arg_int(a, n, 0, 32); return p8_make_str(&c, 1); }
    case BI_ORD:
        if (n >= 1 && a[0].type == V_STR) {
            int idx = arg_int(a, n, 1, 1) - 1;
            if (idx >= 0 && idx < M->strs[a[0].u].len)
                return val_int((u8)M->strs[a[0].u].s[idx]);
        }
        return val_nil();
    case BI_TOSTR: {
        char buf[64];
        p8_val_tostr(n > 0 ? a[0] : val_nil(), buf, sizeof(buf));
        return p8_make_str(buf, -1);
    }
    case BI_TONUM:
        if (n > 0 && a[0].type == V_NUM) return a[0];
        return val_num(0);

    /* Memory & Cartdata */
    case BI_PEEK:  return val_int(M->ram[arg_int(a, n, 0, 0) & 0x7FFF]);
    case BI_POKE: {
        int ad = arg_int(a, n, 0, 0) & 0x7FFF;
        M->ram[ad] = (u8)arg_int(a, n, 1, 0);
        if (ad >= 0x5E00 && ad < 0x5F00) S.cartdata_dirty = 1u;
        return val_nil();
    }
    case BI_PEEK2: {
        int ad = arg_int(a, n, 0, 0) & 0x7FFF;
        return val_int((s16)((u16)M->ram[ad] | ((u16)M->ram[(ad + 1) & 0x7FFF] << 8)));
    }
    case BI_POKE2: {
        int ad = arg_int(a, n, 0, 0) & 0x7FFF;
        u16 w = (u16)arg_int(a, n, 1, 0);
        M->ram[ad] = (u8)w; M->ram[(ad + 1) & 0x7FFF] = (u8)(w >> 8);
        return val_nil();
    }
    case BI_PEEK4: {
        int ad = arg_int(a, n, 0, 0) & 0x7FFC;
        s32 v = (s32)((u32)M->ram[ad] | ((u32)M->ram[ad + 1] << 8) |
                      ((u32)M->ram[ad + 2] << 16) | ((u32)M->ram[ad + 3] << 24));
        return val_num(v);
    }
    case BI_POKE4: {
        int ad = arg_int(a, n, 0, 0) & 0x7FFC;
        u32 v = (n > 1 && a[1].type == V_NUM) ? (u32)a[1].n : 0u;
        M->ram[ad] = (u8)v; M->ram[ad + 1] = (u8)(v >> 8);
        M->ram[ad + 2] = (u8)(v >> 16); M->ram[ad + 3] = (u8)(v >> 24);
        return val_nil();
    }
    case BI_MEMCPY: {
        int d = arg_int(a, n, 0, 0), s = arg_int(a, n, 1, 0), len = arg_int(a, n, 2, 0);
        for (int i = 0; i < len && i < 0x8000; i++)
            M->ram[(d + i) & 0x7FFF] = M->ram[(s + i) & 0x7FFF];
        return val_nil();
    }
    case BI_MEMSET: {
        int d = arg_int(a, n, 0, 0), v = arg_int(a, n, 1, 0), len = arg_int(a, n, 2, 0);
        for (int i = 0; i < len && i < 0x8000; i++)
            M->ram[(d + i) & 0x7FFF] = (u8)v;
        return val_nil();
    }
    case BI_RELOAD: {
        int d = arg_int(a, n, 0, 0), s = arg_int(a, n, 1, 0), len = arg_int(a, n, 2, 0x4300);
        for (int i = 0; i < len; i++)
            if ((unsigned)(s + i) < 0x4300u)
                M->ram[(d + i) & 0x7FFF] = M->rom[s + i];
        return val_nil();
    }
    case BI_CARTDATA: return val_bool(1);
    case BI_DGET: {
        int idx = (arg_int(a, n, 0, 0) & 63) * 4 + 0x5E00;
        s32 v = (s32)((u32)M->ram[idx] | ((u32)M->ram[idx + 1] << 8) |
                      ((u32)M->ram[idx + 2] << 16) | ((u32)M->ram[idx + 3] << 24));
        return val_num(v);
    }
    case BI_DSET: {
        int idx = (arg_int(a, n, 0, 0) & 63) * 4 + 0x5E00;
        u32 v = (n > 1 && a[1].type == V_NUM) ? (u32)a[1].n : 0u;
        M->ram[idx] = (u8)v; M->ram[idx + 1] = (u8)(v >> 8);
        M->ram[idx + 2] = (u8)(v >> 16); M->ram[idx + 3] = (u8)(v >> 24);
        S.cartdata_dirty = 1u;
        return val_nil();
    }
    case BI_TIME:
        return val_num((s32)((S.frame_count * 0x10000u) / 60u));
    case BI_STAT: {
        int q = arg_int(a, n, 0, 0);
        if (q == 7 || q == 8 || q == 9) return val_int(S.is_60fps ? 60 : 30);
        return val_int(0);
    }
    default: return val_nil();
    }
}

/* Variable lookup / assignment (innermost local first, then global) */
static struct p8_val get_sym(u16 sym)
{
    for (int i = S.local_top - 1; i >= 0; i--)
        if (M->locals[i].sym == sym) return M->locals[i].v;
    return M->globals[sym];
}

static void set_sym(u16 sym, struct p8_val v)
{
    for (int i = S.local_top - 1; i >= 0; i--) {
        if (M->locals[i].sym == sym) { M->locals[i].v = v; return; }
    }
    M->globals[sym] = v;
}

static inline int is_truthy(struct p8_val v)
{
    return !(v.type == V_NIL || (v.type == V_BOOL && v.n == 0));
}

static struct p8_val eval_binop(u8 op, struct p8_val a, struct p8_val b)
{
    if (op == TK_EQ) return val_bool(p8_val_eq(a, b));
    if (op == TK_NE) return val_bool(!p8_val_eq(a, b));
    if (op == TK_CONCAT) {
        char ba[64], bb[64], bc[P8_STR_LEN];
        p8_val_tostr(a, ba, sizeof(ba));
        p8_val_tostr(b, bb, sizeof(bb));
        int p = 0;
        for (int i = 0; ba[i] && p < P8_STR_LEN - 1; i++) bc[p++] = ba[i];
        for (int i = 0; bb[i] && p < P8_STR_LEN - 1; i++) bc[p++] = bb[i];
        bc[p] = 0;
        return p8_make_str(bc, p);
    }
    s32 na = (a.type == V_NUM) ? a.n : 0;
    s32 nb = (b.type == V_NUM) ? b.n : 0;
    switch (op) {
    case '+': return val_num(na + nb);
    case '-': return val_num(na - nb);
    case '*': return val_num(fix_mul(na, nb));
    case '/': return val_num(fix_div(na, nb));
    case '\\': return val_num(fix_div(na, nb) & (s32)0xFFFF0000u);
    case '%': return val_num(fix_mod(na, nb));
    case '^': {
        int exp = fix_to_int(nb);
        s32 acc = 0x10000;
        for (int i = 0; i < exp && i < 16; i++) acc = fix_mul(acc, na);
        return val_num(acc);
    }
    case '&': return val_num(na & nb);
    case '|': return val_num(na | nb);
    case '~': return val_num(na ^ nb);
    case TK_SHL:  return val_num((s32)((u32)na << ((nb >> 16) & 31)));
    case TK_SHR:  return val_num(na >> ((nb >> 16) & 31));
    case TK_LSHR: return val_num((s32)((u32)na >> ((nb >> 16) & 31)));
    case '<':   return val_bool(na < nb);
    case '>':   return val_bool(na > nb);
    case TK_LE: return val_bool(na <= nb);
    case TK_GE: return val_bool(na >= nb);
    default:    return val_nil();
    }
}

static struct p8_val call_val(struct p8_val fn, struct p8_val *args, int argc)
{
    if (fn.type == V_BUILTIN)
        return p8_run_builtin(fn.u, args, argc);
    if (fn.type == V_FUNC && fn.u < S.n_nodes) {
        struct p8_node *nd = &M->nodes[fn.u];
        int saved_top = S.local_top;
        int saved_ret = S.ret_flag;
        int saved_brk = S.break_flag;
        S.ret_flag = 0; S.break_flag = 0;

        s16 plist[16];
        int np = flatten_list(nd->a, plist, 16);
        for (int i = 0; i < np && S.local_top < P8_MAX_LOCALS; i++) {
            M->locals[S.local_top].sym = (u16)M->nodes[plist[i]].val;
            M->locals[S.local_top].v   = (i < argc) ? args[i] : val_nil();
            S.local_top++;
        }
        exec_stmt(nd->b);
        struct p8_val res = (S.ret_flag && S.ret_count > 0) ? S.ret_vals[0] : val_nil();
        S.local_top  = saved_top;
        S.ret_flag   = saved_ret;
        S.break_flag = saved_brk;
        return res;
    }
    return val_nil();
}

static struct p8_val eval_node(s16 ni)
{
    if (ni < 0 || ni >= S.n_nodes || S.steps_left == 0) return val_nil();
    S.steps_left--;
    struct p8_node *n = &M->nodes[ni];
    switch (n->kind) {
    case ND_NUM:  return val_num(n->val);
    case ND_STR:  { struct p8_val v = {V_STR, 0, (u16)n->val, 0}; return v; }
    case ND_BOOL: return val_bool(n->val);
    case ND_NIL:  return val_nil();
    case ND_VAR:  return get_sym((u16)n->val);
    case ND_FUNC: { struct p8_val v = {V_FUNC, 0, (u16)ni, 0}; return v; }
    case ND_UNOP: {
        struct p8_val sub = eval_node(n->a);
        if (n->op == '-') return val_num(sub.type == V_NUM ? -sub.n : 0);
        if (n->op == '~') return val_num(sub.type == V_NUM ? ~sub.n : -1);
        if (n->op == TK_NOT) return val_bool(!is_truthy(sub));
        if (n->op == '#') {
            if (sub.type == V_TAB) return val_int(p8_tab_seq_len(sub.u));
            if (sub.type == V_STR) return val_int(M->strs[sub.u].len);
            return val_int(0);
        }
        return val_nil();
    }
    case ND_BINOP: {
        if (n->op == TK_AND) {
            struct p8_val a = eval_node(n->a);
            return is_truthy(a) ? eval_node(n->b) : a;
        }
        if (n->op == TK_OR) {
            struct p8_val a = eval_node(n->a);
            return is_truthy(a) ? a : eval_node(n->b);
        }
        struct p8_val a = eval_node(n->a);
        struct p8_val b = eval_node(n->b);
        return eval_binop(n->op, a, b);
    }
    case ND_INDEX: {
        struct p8_val t = eval_node(n->a);
        struct p8_val k = eval_node(n->b);
        if (t.type == V_TAB) return p8_tab_get(t.u, k);
        return val_nil();
    }
    case ND_TABLE: {
        struct p8_val tv = p8_make_tab();
        s16 items[P8_TAB_CAP];
        int cnt = flatten_list(n->a, items, P8_TAB_CAP);
        int seq_idx = 1;
        for (int i = 0; i < cnt; i++) {
            struct p8_node *kv = &M->nodes[items[i]];
            struct p8_val k = (kv->a >= 0) ? eval_node(kv->a) : val_int(seq_idx++);
            struct p8_val v = eval_node(kv->b);
            p8_tab_set(tv.u, k, v);
        }
        return tv;
    }
    case ND_CALL: {
        struct p8_val fn = eval_node(n->a);
        s16 alist[16];
        int ac = flatten_list(n->b, alist, 16);
        struct p8_val av[16];
        for (int i = 0; i < ac; i++) av[i] = eval_node(alist[i]);
        return call_val(fn, av, ac);
    }
    default:
        return val_nil();
    }
}

static void assign_lval(s16 target, struct p8_val v)
{
    if (target < 0) return;
    struct p8_node *t = &M->nodes[target];
    if (t->kind == ND_VAR) {
        set_sym((u16)t->val, v);
    } else if (t->kind == ND_INDEX) {
        struct p8_val tab = eval_node(t->a);
        struct p8_val key = eval_node(t->b);
        if (tab.type == V_TAB) p8_tab_set(tab.u, key, v);
    }
}

static void exec_stmt(s16 ni)
{
    if (ni < 0 || ni >= S.n_nodes || S.ret_flag || S.break_flag || S.steps_left == 0)
        return;
    S.steps_left--;
    struct p8_node *n = &M->nodes[ni];
    switch (n->kind) {
    case ND_SEQ:
        exec_stmt(n->a);
        exec_stmt(n->b);
        break;
    case ND_BLOCK: {
        int saved_top = S.local_top;
        exec_stmt(n->a);
        S.local_top = saved_top;
        break;
    }
    case ND_LOCAL: {
        s16 vlist[8], elist[8];
        int nv = flatten_list(n->a, vlist, 8);
        int ne = flatten_list(n->b, elist, 8);
        struct p8_val ev[8];
        for (int i = 0; i < ne; i++) {
            ev[i] = eval_node(elist[i]);
            if (i == ne - 1 && M->nodes[elist[i]].kind == ND_CALL && S.ret_count > 1) {
                for (int r = 1; r < S.ret_count && i + r < 8; r++)
                    ev[i + r] = S.ret_vals[r];
                ne += S.ret_count - 1;
                if (ne > 8) ne = 8;
                break;
            }
        }
        for (int i = 0; i < nv && S.local_top < P8_MAX_LOCALS; i++) {
            M->locals[S.local_top].sym = (u16)M->nodes[vlist[i]].val;
            M->locals[S.local_top].v   = (i < ne) ? ev[i] : val_nil();
            S.local_top++;
        }
        break;
    }
    case ND_ASSIGN: {
        s16 tlist[8], elist[8];
        int nt = flatten_list(n->a, tlist, 8);
        int ne = flatten_list(n->b, elist, 8);
        struct p8_val ev[8];
        for (int i = 0; i < ne; i++) {
            ev[i] = eval_node(elist[i]);
            if (i == ne - 1 && M->nodes[elist[i]].kind == ND_CALL && S.ret_count > 1) {
                for (int r = 1; r < S.ret_count && i + r < 8; r++)
                    ev[i + r] = S.ret_vals[r];
                ne += S.ret_count - 1;
                if (ne > 8) ne = 8;
                break;
            }
        }
        for (int i = 0; i < nt; i++)
            assign_lval(tlist[i], (i < ne) ? ev[i] : val_nil());
        break;
    }
    case ND_COMPOUND: {
        struct p8_val cur = eval_node(n->a);
        struct p8_val rhs = eval_node(n->b);
        u8 bop = '+';
        if (n->op == TK_SUBEQ) bop = '-';
        else if (n->op == TK_MULEQ) bop = '*';
        else if (n->op == TK_DIVEQ) bop = '/';
        else if (n->op == TK_MODEQ) bop = '%';
        else if (n->op == TK_CATEQ) bop = TK_CONCAT;
        assign_lval(n->a, eval_binop(bop, cur, rhs));
        break;
    }
    case ND_IF:
        if (is_truthy(eval_node(n->a))) exec_stmt(n->b);
        else if (n->c >= 0)             exec_stmt(n->c);
        break;
    case ND_WHILE:
        while (!S.ret_flag && !S.break_flag && S.steps_left > 0 && is_truthy(eval_node(n->a)))
            exec_stmt(n->b);
        S.break_flag = 0;
        break;
    case ND_REPEAT:
        do {
            exec_stmt(n->a);
        } while (!S.ret_flag && !S.break_flag && S.steps_left > 0 && !is_truthy(eval_node(n->b)));
        S.break_flag = 0;
        break;
    case ND_FOR_NUM: {
        s32 cur  = eval_node(n->a).n;
        s32 lim  = eval_node(n->b).n;
        s32 step = (n->c >= 0) ? eval_node(n->c).n : 0x10000;
        if (step == 0) break;
        int saved_top = S.local_top;
        if (S.local_top >= P8_MAX_LOCALS) break;
        int slot = S.local_top++;
        M->locals[slot].sym = (u16)n->val;
        while (!S.ret_flag && !S.break_flag && S.steps_left > 0 &&
               ((step > 0) ? (cur <= lim) : (cur >= lim))) {
            M->locals[slot].v = val_num(cur);
            exec_stmt(n->d);
            cur += step;
        }
        S.local_top = saved_top;
        S.break_flag = 0;
        break;
    }
    case ND_FOR_IN: {
        struct p8_val it = eval_node(n->c);
        if (it.type == V_ITER && it.u < P8_MAX_TABS) {
            int saved_top = S.local_top;
            if (S.local_top + 2 > P8_MAX_LOCALS) break;
            int s0 = S.local_top++;
            int s1 = (n->b >= 0) ? S.local_top++ : -1;
            M->locals[s0].sym = (u16)n->a;
            if (s1 >= 0) M->locals[s1].sym = (u16)n->b;

            if (it.pad == 0) {  /* all(t): snapshot sequence so del() during iteration is safe! */
                struct p8_val snap[P8_TAB_CAP];
                int len = p8_tab_seq_len(it.u);
                if (len > P8_TAB_CAP) len = P8_TAB_CAP;
                for (int i = 0; i < len; i++) snap[i] = p8_tab_get(it.u, val_int(i + 1));
                for (int i = 0; i < len && !S.ret_flag && !S.break_flag && S.steps_left > 0; i++) {
                    M->locals[s0].v = snap[i];
                    exec_stmt(n->d);
                }
            } else {            /* pairs(t) */
                struct p8_tab *tb = &M->tabs[it.u];
                u16 cnt = tb->count;
                for (u16 i = 0; i < cnt && i < tb->count && !S.ret_flag && !S.break_flag && S.steps_left > 0; i++) {
                    M->locals[s0].v = tb->items[i].k;
                    if (s1 >= 0) M->locals[s1].v = tb->items[i].v;
                    exec_stmt(n->d);
                }
            }
            S.local_top = saved_top;
            S.break_flag = 0;
        }
        break;
    }
    case ND_RETURN: {
        s16 rlist[4];
        int nr = flatten_list(n->a, rlist, 4);
        for (int i = 0; i < nr; i++) S.ret_vals[i] = eval_node(rlist[i]);
        S.ret_count = nr;
        S.ret_flag = 1;
        break;
    }
    case ND_BREAK:
        S.break_flag = 1;
        break;
    default:
        (void)eval_node(ni);
        break;
    }
}

static void p8_register_builtins(void)
{
    static const struct { const char *name; u16 id; } defs[] = {
        {"cls", BI_CLS}, {"pset", BI_PSET}, {"pget", BI_PGET}, {"line", BI_LINE},
        {"rect", BI_RECT}, {"rectfill", BI_RECTFILL}, {"circ", BI_CIRC}, {"circfill", BI_CIRCFILL},
        {"oval", BI_CIRC}, {"ovalfill", BI_CIRCFILL},
        {"spr", BI_SPR}, {"sspr", BI_SSPR}, {"sget", BI_SGET}, {"sset", BI_SSET},
        {"fget", BI_FGET}, {"fset", BI_FSET}, {"map", BI_MAP}, {"mget", BI_MGET}, {"mset", BI_MSET},
        {"mled", BI_MAP}, {"print", BI_PRINT}, {"cursor", BI_CURSOR}, {"color", BI_COLOR},
        {"pal", BI_PAL}, {"palt", BI_PALT}, {"camera", BI_CAMERA}, {"clip", BI_CLIP}, {"fillp", BI_FILLP},
        {"btn", BI_BTN}, {"btnp", BI_BTNP}, {"sfx", BI_SFX}, {"music", BI_MUSIC},
        {"flr", BI_FLR}, {"ceil", BI_CEIL}, {"abs", BI_ABS}, {"sgn", BI_SGN},
        {"min", BI_MIN}, {"max", BI_MAX}, {"mid", BI_MID}, {"sqrt", BI_SQRT},
        {"sin", BI_SIN}, {"cos", BI_COS}, {"atan2", BI_ATAN2}, {"rnd", BI_RND}, {"srand", BI_SRAND},
        {"band", BI_BAND}, {"bor", BI_BOR}, {"bxor", BI_BXOR}, {"bnot", BI_BNOT},
        {"shl", BI_SHL}, {"shr", BI_SHR}, {"lshr", BI_LSHR},
        {"add", BI_ADD}, {"del", BI_DEL}, {"deli", BI_DELI}, {"count", BI_COUNT},
        {"all", BI_ALL}, {"foreach", BI_FOREACH}, {"pairs", BI_PAIRS}, {"ipairs", BI_PAIRS},
        {"sub", BI_SUB}, {"chr", BI_CHR}, {"ord", BI_ORD}, {"tostr", BI_TOSTR}, {"tonum", BI_TONUM},
        {"peek", BI_PEEK}, {"poke", BI_POKE}, {"peek2", BI_PEEK2}, {"poke2", BI_POKE2},
        {"peek4", BI_PEEK4}, {"poke4", BI_POKE4},
        {"memcpy", BI_MEMCPY}, {"memset", BI_MEMSET}, {"reload", BI_RELOAD}, {"cstore", BI_RELOAD},
        {"cartdata", BI_CARTDATA}, {"dget", BI_DGET}, {"dset", BI_DSET},
        {"time", BI_TIME}, {"t", BI_TIME}, {"stat", BI_STAT},
        {0, 0}
    };
    for (int i = 0; defs[i].name; i++) {
        int sym = p8_intern(defs[i].name, p8_strlen(defs[i].name));
        struct p8_val bv = {V_BUILTIN, 0, defs[i].id, 0};
        M->globals[sym] = bv;
    }
}

static void p8_call_hook(const char *name)
{
    int sym = p8_intern(name, p8_strlen(name));
    struct p8_val fn = M->globals[sym];
    if (fn.type == V_FUNC) {
        S.steps_left = P8_STEP_BUDGET;
        S.ret_flag = S.break_flag = 0;
        (void)call_val(fn, 0, 0);
    }
}

/* ============================================================================
   Built-in Playable PICO-8 Cartridge (""): "CELESTEPEAK-8"
   Genuine .p8 cartridge loaded & executed by the exact same PICO-8 Lua VM!
   ============================================================================ */

static const char builtin_celestepeak_p8[] =
    "pico-8 cartridge // http://www.pico-8.com\n"
    "version 41\n"
    "__lua__\n"
    "-- celestepeak-8 (built-in pico-8)\n"
    "function _init()\n"
    "  srand(42)\n"
    "  px=24 py=96 vx=0 vy=0 dsh=1 score=0 f=0\n"
    "  bx=88 by=44\n"
    "  snow={} trail={}\n"
    "  for i=1,28 do\n"
    "    add(snow,{x=rnd(128),y=rnd(128),s=0.4+rnd(0.9),c=6+(i%2)})\n"
    "  end\n"
    "  plats={{x=8,y=110,w=44},{x=60,y=92,w=48},{x=20,y=72,w=42},{x=72,y=56,w=46}}\n"
    "  music(0)\n"
    "end\n"
    "function _update60()\n"
    "  f+=1\n"
    "  local l=btn(0) local r=btn(1) local j=btnp(4) local d=btnp(5)\n"
    "  if not (l or r or btn(2) or btn(3) or btn(4) or btn(5)) then\n"
    "    if px<bx-4 then r=true elseif px>bx+4 then l=true end\n"
    "    if (f%42)==0 then j=true end\n"
    "    if (f%85)==0 then d=true end\n"
    "  end\n"
    "  if l then vx=-1.3 elseif r then vx=1.3 else vx*=0.7 end\n"
    "  vy+=0.22\n"
    "  if vy>2.8 then vy=2.8 end\n"
    "  if j and on_g then vy=-3.8 sfx(1) end\n"
    "  if d and dsh>0 then\n"
    "    dsh=0 vy=-2.8 vx=(l and -2.8 or 2.8) sfx(2)\n"
    "    for k=1,5 do add(trail,{x=px+4,y=py+4,t=12}) end\n"
    "  end\n"
    "  px+=vx py+=vy\n"
    "  if px<4 then px=4 end\n"
    "  if px>116 then px=116 end\n"
    "  on_g=false\n"
    "  if py>=112 then py=112 vy=0 on_g=true dsh=1 end\n"
    "  for p in all(plats) do\n"
    "    if vy>=0 and px+6>p.x and px<p.x+p.w and py+8>=p.y and py+8<=p.y+5 then\n"
    "      py=p.y-8 vy=0 on_g=true dsh=1\n"
    "    end\n"
    "  end\n"
    "  if abs(px-bx)<8 and abs(py-by)<8 then\n"
    "    score+=100 sfx(2)\n"
    "    bx=16+flr(rnd(92)) by=32+flr(rnd(64))\n"
    "  end\n"
    "  for s in all(snow) do\n"
    "    s.x+=0.35 s.y+=s.s\n"
    "    if s.x>127 then s.x-=128 end\n"
    "    if s.y>127 then s.y-=128 end\n"
    "  end\n"
    "  for tr in all(trail) do\n"
    "    tr.t-=1\n"
    "    if tr.t<=0 then del(trail,tr) end\n"
    "  end\n"
    "end\n"
    "function _draw()\n"
    "  cls(1)\n"
    "  -- distant mountain silhouettes\n"
    "  for x=0,127,2 do\n"
    "    local mh=84+flr(sin(x/96)*16)\n"
    "    line(x,mh,x,127,2)\n"
    "  end\n"
    "  rectfill(0,120,127,127,13)\n"
    "  rectfill(0,120,127,121,7)\n"
    "  for p in all(plats) do\n"
    "    rectfill(p.x,p.y+2,p.x+p.w,p.y+5,5)\n"
    "    rectfill(p.x,p.y,p.x+p.w,p.y+1,7)\n"
    "  end\n"
    "  for tr in all(trail) do circfill(tr.x,tr.y,tr.t/4,12) end\n"
    "  -- winged strawberry\n"
    "  local bob=flr(sin(f/30)*2)\n"
    "  spr(2,bx,by+bob)\n"
    "  -- climber + hair colour (8=red ready, 12=blue dashed!)\n"
    "  local hc=(dsh>0) and 8 or 12\n"
    "  circfill(px+3,py+2,3,hc)\n"
    "  spr(1,px,py)\n"
    "  for s in all(snow) do pset(s.x,s.y,s.c) end\n"
    "  rectfill(0,0,127,8,0)\n"
    "  print(\"CELESTEPEAK-8  \"..score,4,2,7)\n"
    "end\n"
    "__gfx__\n"
    "000000000088880000033300\n"
    "000000000888888000887880\n"
    "00000000088ff88008888888\n"
    "0000000008f1f18008878788\n"
    "0000000000ffff0008888888\n"
    "0000000000cccc0000887880\n"
    "000000000cc99cc000088800\n"
    "000000000040040000008000\n"
    "__sfx__\n"
    "00100020185501c55020550235502755023550205501c5501a5501e5502155025550215501e5501a55017550185501c55020550275502555023550205501c5501a5501d550225502655025550225501f5501c550\n"
    "00040000180711c0712007124071280612c0513004134031000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\n"
    "0004000024371283712c3713036134351383413b3313f321000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\n"
    "__music__\n"
    "01 00414243\n"
    "02 00414243\n";

/* ============================================================================
   Public Lifecycle, Explorer Helper & 60 Hz Frame Entry Points
   ============================================================================ */

int pico8_is_p8_png_name(const char *name)
{
    if (!name) return 0;
    int l = p8_strlen(name);
    if (l < 7) return 0;
    const char *e = name + l - 7;
    return e[0] == '.' && (e[1] | 32) == 'p' && e[2] == '8' &&
           e[3] == '.' && (e[4] | 32) == 'p' && (e[5] | 32) == 'n' && (e[6] | 32) == 'g';
}

void pico8_reset(void)
{
    for (u32 i = 0; i < 0x4300u; i++)
        M->ram[i] = M->rom[i];
    p8_zero(&M->ram[0x4300], 0x5E00u - 0x4300u);
    p8_zero(&M->ram[0x5F00], 0x8000u - 0x5F00u);
    p8_reset_draw_state();

    S.jammed       = 0;
    S.frame_count  = 0;
    S.half_flip    = 0;
    S.pad_cur      = S.pad_prev = 0;
    p8_zero(S.hold_frames, sizeof(S.hold_frames));
    S.rng_hi       = 0x12345678u;
    S.rng_lo       = 0x9ABCDEF0u;
    S.music_pat    = -1;
    S.music_tick_rem = 0;
    p8_zero(S.ch, sizeof(S.ch));
    S.snd_head     = S.snd_tail = 0;

    S.n_syms    = 0;
    S.n_toks    = 0;
    S.tok_pos   = 0;
    S.n_nodes   = 0;
    S.local_top = 0;
    S.ret_flag  = S.break_flag = 0;
    S.ret_count = 0;
    p8_zero(M->tabs, sizeof(M->tabs));
    p8_zero(M->strs, sizeof(M->strs));

    p8_register_builtins();
    p8_tokenize(M->lua_src);
    S.root_block = parse_block();

    S.steps_left = P8_STEP_BUDGET * 2u;
    exec_stmt(S.root_block);

    int sym_u60 = p8_intern("_update60", 9);
    S.is_60fps = (M->globals[sym_u60].type == V_FUNC) ? 1u : 0u;

    p8_call_hook("_init");
}

const char *pico8_load(const u8 *image, u32 size, const char *path)
{
    u32 keep_rate = S.sample_rate;
    if (keep_rate != 48000u && keep_rate != 44100u && keep_rate != 32000u && keep_rate != 22050u)
        keep_rate = 48000u;

    p8_zero(&S, sizeof(S));
    p8_zero(M->ram, sizeof(M->ram));
    p8_zero(M->rom, sizeof(M->rom));
    M->lua_src[0] = 0;
    S.sample_rate = keep_rate;

    if (!path || !*path || !image || size == 0) {
        const char *err = p8_load_text_cart((const u8 *)builtin_celestepeak_p8, sizeof(builtin_celestepeak_p8) - 1u);
        if (err) return err;
        static const char bi[] = "CelestePeak-8 (Built-in PICO-8 128x128 Lua Cartridge + 4-ch Synth)";
        for (u32 i = 0; i < sizeof(bi); i++) S.info[i] = bi[i];
        pico8_reset();
        return 0;
    }

    const u8 *cart_ptr = image;
    u32 cart_sz = size;
    char zname[96];
    if (zip_is(image, size)) {
        u32 unpacked = 0;
        const char *zerr = zip_unpack(image, size, 0, M->png_raw, sizeof(M->png_raw), &unpacked, zname, sizeof(zname));
        if (zerr) return zerr;
        /* Note: if .p8.png was unpacked into M->png_raw, copy to png_zbuf temporary or inflate_work first! */
        if (unpacked > sizeof(M->inflate_work))
            return "unpacked PICO-8 cart exceeds 128 KB";
        for (u32 i = 0; i < unpacked; i++) M->inflate_work[i] = M->png_raw[i];
        cart_ptr = M->inflate_work;
        cart_sz  = unpacked;
    }

    const char *err = 0;
    if (cart_sz >= 8 && cart_ptr[0] == 0x89 && cart_ptr[1] == 'P' && cart_ptr[2] == 'N' && cart_ptr[3] == 'G') {
        err = p8_load_png_cart(cart_ptr, cart_sz);
        static const char tg[] = "PICO-8 .p8.png Steganography Cartridge (128x128 16c + 4-ch Synth)";
        for (u32 i = 0; i < sizeof(tg); i++) S.info[i] = tg[i];
    } else {
        err = p8_load_text_cart(cart_ptr, cart_sz);
        static const char tg[] = "PICO-8 .p8 Cartridge (128x128 16c Lua VM + 4-ch Synth)";
        for (u32 i = 0; i < sizeof(tg); i++) S.info[i] = tg[i];
    }
    if (err) return err;

    pico8_reset();
    return 0;
}

void pico8_pad2(u16 pad) { (void)pad; }

void pico8_frame(u16 pad, u16 *picture)
{
    S.pad_prev = S.pad_cur;
    S.pad_cur  = pad;
    for (int b = 0; b < 6; b++) {
        if (p8_btn_state(b)) {
            if (S.hold_frames[b] < 250u) S.hold_frames[b]++;
        } else {
            S.hold_frames[b] = 0;
        }
    }

    if (S.is_60fps) {
        p8_call_hook("_update60");
        p8_call_hook("_draw");
    } else {
        S.half_flip ^= 1u;
        if (S.half_flip) {
            p8_call_hook("_update");
            p8_call_hook("_draw");
        }
    }

    if (picture) {
        u16 lut15[16];
        for (int i = 0; i < 16; i++)
            lut15[i] = p8_master_pal15[M->ram[0x5F10 + i] & 31u];
        for (int y = 0; y < 128; y++) {
            const u8 *src = &M->ram[0x6000u + (u32)y * 64u];
            u16 *dst = picture + y * 128;
            for (int bx = 0; bx < 64; bx++) {
                u8 pair = src[bx];
                dst[bx * 2]     = lut15[pair & 15u];
                dst[bx * 2 + 1] = lut15[pair >> 4];
            }
        }
    }

    u32 target = (S.sample_rate ? S.sample_rate : 48000u) / 60u;
    for (u32 i = 0; i < target; i++) {
        s16 s = p8_audio_sample_48k();
        if (S.snd_head - S.snd_tail < P8_SND_RING)
            M->snd_ring[S.snd_head++ & (P8_SND_RING - 1u)] = s;
    }

    S.frame_count++;
}

const char *pico8_info(void) { return S.info; }

u8 *pico8_save_ram(u32 *size, int *battery)
{
    if (size) *size = 256u;
    if (battery) *battery = 1;
    return &M->ram[0x5E00];
}

int pico8_save_changed(void)
{
    int d = S.cartdata_dirty;
    S.cartdata_dirty = 0;
    return d;
}

int pico8_jammed(void) { return S.jammed; }

void pico8_audio_rate(u32 hz)
{
    S.sample_rate = hz ? hz : 48000u;
}

int pico8_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && S.snd_tail != S.snd_head)
        out[n++] = M->snd_ring[S.snd_tail++ & (P8_SND_RING - 1u)];
    return n;
}
