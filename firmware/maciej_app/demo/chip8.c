/* CHIP-8 / SUPER-CHIP 1.1 / XO-CHIP (.ch8, .sc8, .xo8): see chip8.h. */
#pragma GCC optimize("O2")
#include "chip8.h"

#ifndef CHIP8_HOST
#include "hw.h"
#endif

typedef signed char s8;

#define SND_RING 4096

enum { MODE_CHIP8 = 0, MODE_SCHIP = 1, MODE_XOCHIP = 2 };

struct chip8_mem {
    u8 ram[0x10000];                    /* Full 64 KB address space (XO-CHIP F000 NNNN) */
    u8 vram[CHIP8_W * CHIP8_H];         /* 4-bit plane mask (0..15) per 128x64 pixel */
    u8 rpl[16];                         /* FX75 / FX85 persistent flag registers (.sav) */
    s16 snd_ring[SND_RING];
};

#ifdef CHIP8_HOST
static struct chip8_mem chip8_host_mem;
#define M (&chip8_host_mem)
#else
#define M ((struct chip8_mem *)KSEG0(EMU_RAM_PHYS))
#endif

static struct {
    const u8 *rom;
    u32 rom_size;
    u8 mode;                            /* MODE_CHIP8, MODE_SCHIP, MODE_XOCHIP */
    u32 ipf;                            /* instructions per 60 Hz frame */

    u16 pc, idx;
    u16 stack[16];
    u8 sp;
    u8 v[16];
    u8 dt, st;
    u8 hires;
    u8 plane;                           /* active bitplane mask (1..15) */
    u8 halted, exited;
    s8 wait_key;                        /* -1: not waiting, >=0: key pressed, waiting release */
    u32 rng;
    u16 keys;                           /* 16-bit mask of held hex keys 0..F */

    /* XO-CHIP 128-bit audio pattern & pitch */
    u8 pat[16];
    u8 has_pat;
    u32 step_hz;                        /* pattern bit rate in Hz (default 4000 Hz, pitch=64) */
    u32 pat_pos;                        /* 0..127 bit index */
    u32 pat_acc;

    u32 snd_hz;
    u32 buzz_phase;
    u32 snd_head, snd_count;
    u8 rpl_dirty;

    u16 pal[16];
    char info[96];
} S;

/* Built-in 4x5 CHIP-8 font (0..F, 80 bytes at 0x050) */
static const u8 font5[80] = {
    0xF0,0x90,0x90,0x90,0xF0, 0x20,0x60,0x20,0x20,0x70, 0xF0,0x10,0xF0,0x80,0xF0, 0xF0,0x10,0xF0,0x10,0xF0,
    0x90,0x90,0xF0,0x10,0x10, 0xF0,0x80,0xF0,0x10,0xF0, 0xF0,0x80,0xF0,0x90,0xF0, 0xF0,0x10,0x20,0x40,0x40,
    0xF0,0x90,0xF0,0x90,0xF0, 0xF0,0x90,0xF0,0x10,0xF0, 0xF0,0x90,0xF0,0x90,0x90, 0xE0,0x90,0xE0,0x90,0xE0,
    0xF0,0x80,0x80,0x80,0xF0, 0xE0,0x90,0x90,0x90,0xE0, 0xF0,0x80,0xF0,0x80,0xF0, 0xF0,0x80,0xF0,0x80,0x80,
};

/* Built-in 8x10 SUPER-CHIP / XO-CHIP big font (0..F, 160 bytes at 0x0A0) */
static const u8 font10[160] = {
    0x3C,0x7E,0xE7,0xC3,0xC3,0xC3,0xC3,0xE7,0x7E,0x3C, 0x18,0x38,0x58,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,
    0x3E,0x7F,0xC3,0x06,0x0C,0x18,0x30,0x60,0xFF,0xFF, 0x3C,0x7E,0xC3,0x03,0x0E,0x0E,0x03,0xC3,0x7E,0x3C,
    0x06,0x0E,0x1E,0x36,0x66,0xC6,0xFF,0xFF,0x06,0x06, 0xFF,0xFF,0xC0,0xC0,0xFC,0xFE,0x03,0xC3,0x7E,0x3C,
    0x3E,0x7C,0xC0,0xC0,0xFC,0xFE,0xC3,0xC3,0x7E,0x3C, 0xFF,0xFF,0x03,0x06,0x0C,0x18,0x30,0x60,0x60,0x60,
    0x3C,0x7E,0xC3,0xC3,0x7E,0x7E,0xC3,0xC3,0x7E,0x3C, 0x3C,0x7E,0xC3,0xC3,0x7F,0x3F,0x03,0x03,0x3E,0x7C,
    0x18,0x3C,0x66,0xC3,0xC3,0xFF,0xFF,0xC3,0xC3,0xC3, 0xFC,0xFE,0xC3,0xC3,0xFC,0xFC,0xC3,0xC3,0xFE,0xFC,
    0x3C,0x7E,0xE7,0xC0,0xC0,0xC0,0xC0,0xE7,0x7E,0x3C, 0xFC,0xFE,0xC7,0xC3,0xC3,0xC3,0xC3,0xC7,0xFE,0xFC,
    0xFF,0xFF,0xC0,0xC0,0xFC,0xFC,0xC0,0xC0,0xFF,0xFF, 0xFF,0xFF,0xC0,0xC0,0xFC,0xFC,0xC0,0xC0,0xC0,0xC0,
};

/* Octo-inspired 16-colour 4-plane palette (RGB -> 0bbbbbgggggrrrrr) */
static const u8 c8_rgb[16][3] = {
    {0x12, 0x14, 0x20},                 /* 0: deep midnight background */
    {0xFF, 0xCC, 0x33},                 /* 1: classic CHIP-8 warm gold/amber (plane 1) */
    {0x33, 0xBB, 0xEE},                 /* 2: bright cyan (plane 2) */
    {0xFF, 0xFF, 0xFF},                 /* 3: crisp white (planes 1+2) */
    {0xEE, 0x44, 0x55},                 /* 4: coral red (plane 3) */
    {0xFF, 0x88, 0x22},                 /* 5: orange */
    {0xAA, 0x55, 0xEE},                 /* 6: violet */
    {0xFF, 0xDD, 0xCC},                 /* 7: warm cream */
    {0x33, 0xCC, 0x66},                 /* 8: emerald green (plane 4) */
    {0xBB, 0xEE, 0x44},                 /* 9: lime */
    {0x22, 0xAA, 0xAA},                 /* 10: teal */
    {0xCC, 0xFF, 0xEE},                 /* 11: mint */
    {0x88, 0x55, 0x33},                 /* 12: brown */
    {0xDD, 0xAA, 0x66},                 /* 13: tan */
    {0x77, 0x88, 0x99},                 /* 14: slate */
    {0xEE, 0xEE, 0xEE},                 /* 15: silver */
};

/* Q12 fixed-point table of 2^(k/48) for k = 0..47 (4096 .. 8074) for XO-CHIP FX3A pitch */
static const u16 exp2_q12[48] = {
    4096,4156,4216,4277,4339,4403,4467,4532,4598,4664,4732,4801,
    4871,4942,5014,5087,5161,5236,5312,5389,5468,5547,5628,5710,
    5793,5877,5962,6049,6137,6226,6317,6409,6502,6597,6693,6790,
    6889,6989,7091,7194,7299,7405,7512,7622,7733,7845,7959,8075,
};

static u32 calc_pitch_hz(u8 vx)
{
    s32 d = (s32)vx - 64;
    s32 q = d >= 0 ? (d / 48) : -((47 - d) / 48);
    s32 r = d - q * 48;
    u32 base = (4000u * (u32)exp2_q12[r]) >> 12;
    if (q >= 0)
        return q >= 5 ? 128000u : (base << q);
    return (-q) >= 8 ? 16u : (base >> (-q));
}

static u8 rand8(void)
{
    S.rng = S.rng * 1664525u + 1013904223u;
    return (u8)(S.rng >> 24);
}

static void clear_planes(u8 mask)
{
    u8 keep = (u8)~mask;
    for (int i = 0; i < CHIP8_W * CHIP8_H; i++)
        M->vram[i] &= keep;
}

static void scroll_down(int n, u8 mask)
{
    if (n <= 0) return;
    int step = S.hires ? n : n * 2;
    u8 keep = (u8)~mask;
    for (int y = CHIP8_H - 1; y >= 0; y--) {
        for (int x = 0; x < CHIP8_W; x++) {
            u8 src = (y >= step) ? (M->vram[(y - step) * CHIP8_W + x] & mask) : 0;
            M->vram[y * CHIP8_W + x] = (u8)((M->vram[y * CHIP8_W + x] & keep) | src);
        }
    }
}

static void scroll_up(int n, u8 mask)
{
    if (n <= 0) return;
    int step = S.hires ? n : n * 2;
    u8 keep = (u8)~mask;
    for (int y = 0; y < CHIP8_H; y++) {
        for (int x = 0; x < CHIP8_W; x++) {
            u8 src = (y + step < CHIP8_H) ? (M->vram[(y + step) * CHIP8_W + x] & mask) : 0;
            M->vram[y * CHIP8_W + x] = (u8)((M->vram[y * CHIP8_W + x] & keep) | src);
        }
    }
}

static void scroll_right(u8 mask)
{
    int step = S.hires ? 4 : 8;
    u8 keep = (u8)~mask;
    for (int y = 0; y < CHIP8_H; y++) {
        u8 *row = M->vram + y * CHIP8_W;
        for (int x = CHIP8_W - 1; x >= 0; x--) {
            u8 src = (x >= step) ? (row[x - step] & mask) : 0;
            row[x] = (u8)((row[x] & keep) | src);
        }
    }
}

static void scroll_left(u8 mask)
{
    int step = S.hires ? 4 : 8;
    u8 keep = (u8)~mask;
    for (int y = 0; y < CHIP8_H; y++) {
        u8 *row = M->vram + y * CHIP8_W;
        for (int x = 0; x < CHIP8_W; x++) {
            u8 src = (x + step < CHIP8_W) ? (row[x + step] & mask) : 0;
            row[x] = (u8)((row[x] & keep) | src);
        }
    }
}

static u8 draw_sprite(u8 vx, u8 vy, u8 n)
{
    int lw = S.hires ? 128 : 64;
    int lh = S.hires ? 64 : 32;
    int x0 = vx & (lw - 1);
    int y0 = vy & (lh - 1);
    int wrap = (S.mode == MODE_XOCHIP);
    int sw = (n == 0) ? 16 : 8;
    int sh = (n == 0) ? 16 : (int)n;
    u16 mem = S.idx;
    u8 hit = 0;

    for (int p = 0; p < 4; p++) {
        u8 pbit = (u8)(1u << p);
        if (!(S.plane & pbit))
            continue;
        for (int row = 0; row < sh; row++) {
            u16 bits = (n == 0)
                ? (u16)(((u16)M->ram[(u16)(mem + row * 2)] << 8) | M->ram[(u16)(mem + row * 2 + 1)])
                : (u16)((u16)M->ram[(u16)(mem + row)] << 8);
            int ly = y0 + row;
            if (!wrap && ly >= lh)
                continue;
            ly &= (lh - 1);
            for (int col = 0; col < sw; col++) {
                if (!(bits & (0x8000u >> col)))
                    continue;
                int lx = x0 + col;
                if (!wrap && lx >= lw)
                    continue;
                lx &= (lw - 1);
                if (S.hires) {
                    u8 *px = &M->vram[ly * CHIP8_W + lx];
                    if (*px & pbit) hit = 1;
                    *px ^= pbit;
                } else {
                    int bx = lx * 2, by = ly * 2;
                    if (M->vram[by * CHIP8_W + bx] & pbit) hit = 1;
                    M->vram[by * CHIP8_W + bx] ^= pbit;
                    M->vram[by * CHIP8_W + bx + 1] ^= pbit;
                    M->vram[(by + 1) * CHIP8_W + bx] ^= pbit;
                    M->vram[(by + 1) * CHIP8_W + bx + 1] ^= pbit;
                }
            }
        }
        mem = (u16)(mem + (n == 0 ? 32u : (u16)n));
    }
    return hit;
}

static u16 fetch16(void)
{
    u16 hi = M->ram[S.pc];
    u16 lo = M->ram[(u16)(S.pc + 1u)];
    S.pc = (u16)(S.pc + 2u);
    return (u16)((hi << 8) | lo);
}

/* Skip one instruction (handles XO-CHIP 4-byte F000 NNNN cleanly!) */
static void skip_next(void)
{
    u16 next = fetch16();
    if (next == 0xF000u)
        S.pc = (u16)(S.pc + 2u);
}

static int step_one(void)
{
    if (S.exited || S.halted)
        return 0;

    u16 op = fetch16();
    u8 x = (op >> 8) & 0x0Fu;
    u8 y = (op >> 4) & 0x0Fu;
    u8 n = op & 0x0Fu;
    u8 kk = op & 0xFFu;
    u16 nnn = op & 0x0FFFu;

    switch (op >> 12) {
    case 0x0:
        if ((op & 0xFFF0u) == 0x00C0u) { scroll_down(n, S.plane); break; }
        if ((op & 0xFFF0u) == 0x00D0u) { scroll_up(n, S.plane); break; }
        switch (op) {
        case 0x00E0: clear_planes(S.plane); break;
        case 0x00EE: if (S.sp) S.pc = S.stack[--S.sp]; break;
        case 0x00FB: scroll_right(S.plane); break;
        case 0x00FC: scroll_left(S.plane); break;
        case 0x00FD: S.exited = 1; return 0;
        case 0x00FE:
            if (S.mode == MODE_XOCHIP) clear_planes(0x0Fu);
            S.hires = 0;
            break;
        case 0x00FF:
            if (S.mode == MODE_XOCHIP) clear_planes(0x0Fu);
            S.hires = 1;
            break;
        }
        break;
    case 0x1:
        if (nnn == (u16)(S.pc - 2u) && S.dt == 0 && S.st == 0) {
            S.pc = nnn;
            return 0;                   /* Tight infinite jump loop: yield rest of frame! */
        }
        S.pc = nnn;
        break;
    case 0x2:
        if (S.sp < 16) S.stack[S.sp++] = S.pc;
        S.pc = nnn;
        break;
    case 0x3:
        if (S.v[x] == kk) skip_next();
        break;
    case 0x4:
        if (S.v[x] != kk) skip_next();
        break;
    case 0x5:
        if (n == 0) {
            if (S.v[x] == S.v[y]) skip_next();
        } else if (n == 2) {             /* XO-CHIP 5XY2: save Vx..Vy */
            int step = (x <= y) ? 1 : -1;
            u16 off = 0;
            for (int r = x;; r += step, off++) {
                M->ram[(u16)(S.idx + off)] = S.v[r];
                if (r == y) break;
            }
        } else if (n == 3) {             /* XO-CHIP 5XY3: load Vx..Vy */
            int step = (x <= y) ? 1 : -1;
            u16 off = 0;
            for (int r = x;; r += step, off++) {
                S.v[r] = M->ram[(u16)(S.idx + off)];
                if (r == y) break;
            }
        }
        break;
    case 0x6:
        S.v[x] = kk;
        break;
    case 0x7:
        S.v[x] = (u8)(S.v[x] + kk);
        break;
    case 0x8:
        switch (n) {
        case 0x0: S.v[x] = S.v[y]; break;
        case 0x1: S.v[x] |= S.v[y]; if (S.mode == MODE_CHIP8) S.v[15] = 0; break;
        case 0x2: S.v[x] &= S.v[y]; if (S.mode == MODE_CHIP8) S.v[15] = 0; break;
        case 0x3: S.v[x] ^= S.v[y]; if (S.mode == MODE_CHIP8) S.v[15] = 0; break;
        case 0x4: {
            u16 s = (u16)S.v[x] + (u16)S.v[y];
            S.v[x] = (u8)s;
            S.v[15] = s > 0xFFu ? 1u : 0u;
            break;
        }
        case 0x5: {
            u8 nb = S.v[x] >= S.v[y] ? 1u : 0u;
            S.v[x] = (u8)(S.v[x] - S.v[y]);
            S.v[15] = nb;
            break;
        }
        case 0x6: {
            u8 src = (S.mode == MODE_SCHIP) ? S.v[x] : S.v[y];
            u8 c = src & 1u;
            S.v[x] = src >> 1;
            S.v[15] = c;
            break;
        }
        case 0x7: {
            u8 nb = S.v[y] >= S.v[x] ? 1u : 0u;
            S.v[x] = (u8)(S.v[y] - S.v[x]);
            S.v[15] = nb;
            break;
        }
        case 0xE: {
            u8 src = (S.mode == MODE_SCHIP) ? S.v[x] : S.v[y];
            u8 c = (src >> 7) & 1u;
            S.v[x] = (u8)(src << 1);
            S.v[15] = c;
            break;
        }
        }
        break;
    case 0x9:
        if (n == 0 && S.v[x] != S.v[y]) skip_next();
        break;
    case 0xA:
        S.idx = nnn;
        break;
    case 0xB:
        S.pc = (u16)(nnn + S.v[(S.mode == MODE_SCHIP) ? x : 0]);
        break;
    case 0xC:
        S.v[x] = (u8)(rand8() & kk);
        break;
    case 0xD:
        S.v[15] = draw_sprite(S.v[x], S.v[y], n);
        if (S.mode == MODE_CHIP8)
            return 0;                   /* Original CHIP-8 display wait (1 sprite / 60 Hz frame) */
        break;
    case 0xE:
        if (kk == 0x9Eu) {
            if (S.keys & (1u << (S.v[x] & 15u))) skip_next();
        } else if (kk == 0xA1u) {
            if (!(S.keys & (1u << (S.v[x] & 15u)))) skip_next();
        }
        break;
    case 0xF:
        if (op == 0xF000u) {            /* XO-CHIP 16-bit I = NNNN */
            S.idx = fetch16();
            break;
        }
        if (op == 0xF002u) {            /* XO-CHIP load 16-byte audio pattern */
            for (int i = 0; i < 16; i++)
                S.pat[i] = M->ram[(u16)(S.idx + i)];
            S.has_pat = 1;
            S.pat_pos = 0;
            break;
        }
        switch (kk) {
        case 0x01:
            S.plane = x & 0x0Fu;
            break;
        case 0x07:
            S.v[x] = S.dt;
            break;
        case 0x0A:
            if (S.wait_key < 0) {
                for (int k = 0; k < 16; k++) {
                    if (S.keys & (1u << k)) {
                        S.wait_key = (s8)k;
                        break;
                    }
                }
                S.pc = (u16)(S.pc - 2u);
                return 0;
            } else if (S.keys & (1u << S.wait_key)) {
                S.pc = (u16)(S.pc - 2u);
                return 0;
            } else {
                S.v[x] = (u8)S.wait_key;
                S.wait_key = -1;
            }
            break;
        case 0x15: S.dt = S.v[x]; break;
        case 0x18:
            S.st = S.v[x];
            if (S.st == 0) S.pat_pos = 0;
            break;
        case 0x1E: S.idx = (u16)(S.idx + S.v[x]); break;
        case 0x29: S.idx = (u16)(0x050u + (S.v[x] & 0x0Fu) * 5u); break;
        case 0x30: S.idx = (u16)(0x0A0u + (S.v[x] & 0x0Fu) * 10u); break;
        case 0x33:
            M->ram[S.idx]              = (u8)(S.v[x] / 100u);
            M->ram[(u16)(S.idx + 1u)]  = (u8)((S.v[x] / 10u) % 10u);
            M->ram[(u16)(S.idx + 2u)]  = (u8)(S.v[x] % 10u);
            break;
        case 0x3A:
            S.step_hz = calc_pitch_hz(S.v[x]);
            break;
        case 0x55:
            for (u8 i = 0; i <= x; i++)
                M->ram[(u16)(S.idx + i)] = S.v[i];
            if (S.mode != MODE_SCHIP)
                S.idx = (u16)(S.idx + x + 1u);
            break;
        case 0x65:
            for (u8 i = 0; i <= x; i++)
                S.v[i] = M->ram[(u16)(S.idx + i)];
            if (S.mode != MODE_SCHIP)
                S.idx = (u16)(S.idx + x + 1u);
            break;
        case 0x75: {
            u8 lim = (S.mode == MODE_XOCHIP) ? 15u : 7u;
            u8 top = x < lim ? x : lim;
            for (u8 i = 0; i <= top; i++) {
                if (M->rpl[i] != S.v[i]) {
                    M->rpl[i] = S.v[i];
                    S.rpl_dirty = 1;
                }
            }
            break;
        }
        case 0x85: {
            u8 lim = (S.mode == MODE_XOCHIP) ? 15u : 7u;
            u8 top = x < lim ? x : lim;
            for (u8 i = 0; i <= top; i++)
                S.v[i] = M->rpl[i];
            break;
        }
        }
        break;
    }
    return 1;
}

static u16 map_keys(u16 pad, const u8 *hid, int hid_n)
{
    u16 k = 0;
    /* Gamepad / remote / UART ergonomic mapping (standard Octo WASD+QE -> 5/8/7/9 + 4/6) */
    if (pad & 0x10u) k |= (1u << 0x5);  /* UP    -> 5 (W) */
    if (pad & 0x20u) k |= (1u << 0x8);  /* DOWN  -> 8 (S) */
    if (pad & 0x40u) k |= (1u << 0x7);  /* LEFT  -> 7 (A) */
    if (pad & 0x80u) k |= (1u << 0x9);  /* RIGHT -> 9 (D) */
    if (pad & 0x01u) k |= (1u << 0x6);  /* A     -> 6 (E, primary action in Octo games) */
    if (pad & 0x02u) k |= (1u << 0x4);  /* B     -> 4 (Q) */
    if (pad & 0x08u) k |= (1u << 0x5);  /* START -> 5 */
    if (pad & 0x04u) k |= (1u << 0xA);  /* SELECT-> A */

    /* Full 4x4 COSMAC VIP USB keyboard hex matrix:
       1 2 3 4 -> 1 2 3 C | Q W E R -> 4 5 6 D | A S D F -> 7 8 9 E | Z X C V -> A 0 B F */
    for (int i = 0; i < hid_n; i++) {
        switch (hid[i]) {
        case 0x1E: k |= (1u << 0x1); break; /* 1 */
        case 0x1F: k |= (1u << 0x2); break; /* 2 */
        case 0x20: k |= (1u << 0x3); break; /* 3 */
        case 0x21: k |= (1u << 0xC); break; /* 4 */
        case 0x14: k |= (1u << 0x4); break; /* Q */
        case 0x1A: k |= (1u << 0x5); break; /* W */
        case 0x08: k |= (1u << 0x6); break; /* E */
        case 0x15: k |= (1u << 0xD); break; /* R */
        case 0x04: k |= (1u << 0x7); break; /* A */
        case 0x16: k |= (1u << 0x8); break; /* S */
        case 0x07: k |= (1u << 0x9); break; /* D */
        case 0x09: k |= (1u << 0xE); break; /* F */
        case 0x1D: k |= (1u << 0xA); break; /* Z */
        case 0x1B: k |= (1u << 0x0); break; /* X */
        case 0x06: k |= (1u << 0xB); break; /* C */
        case 0x19: k |= (1u << 0xF); break; /* V */
        case 0x52: k |= (1u << 0x5); break; /* Arrow Up */
        case 0x51: k |= (1u << 0x8); break; /* Arrow Down */
        case 0x50: k |= (1u << 0x7); break; /* Arrow Left */
        case 0x4F: k |= (1u << 0x9); break; /* Arrow Right */
        case 0x2C: case 0x28: k |= (1u << 0x6); break; /* Space / Enter -> 6 */
        }
    }
    return k;
}

static void gen_audio_frame(void)
{
    if (!S.snd_hz)
        return;
    u32 n = S.snd_hz / 60u;
    for (u32 i = 0; i < n; i++) {
        s16 s = 0;
        if (S.st > 0) {
            if (S.has_pat) {
                u8 b = S.pat[S.pat_pos >> 3];
                u8 bit = (b >> (7u - (S.pat_pos & 7u))) & 1u;
                s = bit ? 4500 : -4500;
                S.pat_acc += S.step_hz;
                while (S.pat_acc >= S.snd_hz) {
                    S.pat_acc -= S.snd_hz;
                    S.pat_pos = (S.pat_pos + 1u) & 127u;
                }
            } else {
                S.buzz_phase += 440u;
                if (S.buzz_phase >= S.snd_hz)
                    S.buzz_phase -= S.snd_hz;
                s = (S.buzz_phase * 2u < S.snd_hz) ? 4000 : -4000;
            }
        }
        if (S.snd_count < SND_RING) {
            M->snd_ring[(S.snd_head + S.snd_count) % SND_RING] = s;
            S.snd_count++;
        } else {
            M->snd_ring[S.snd_head] = s;
            S.snd_head = (S.snd_head + 1u) % SND_RING;
        }
    }
}

static void put_str(char **p, const char *s)
{
    while (*s && *p < S.info + sizeof(S.info) - 1)
        *(*p)++ = *s++;
    **p = 0;
}

static void put_u32(char **p, u32 v)
{
    char d[12];
    int n = 0;
    do d[n++] = (char)('0' + (v % 10u)); while (v /= 10u);
    while (n && *p < S.info + sizeof(S.info) - 1)
        *(*p)++ = d[--n];
    **p = 0;
}

const char *chip8_load(u8 *image, u32 size, const char *path)
{
    if (!image || size < 2u || size > 0xFE00u)
        return "not a CHIP-8 / SCHIP / XO-CHIP program (expected 2 .. 65024 bytes)";

    for (int i = 0; i < 16; i++)
        S.pal[i] = (u16)((c8_rgb[i][0] >> 3) | ((c8_rgb[i][1] >> 3) << 5) | ((c8_rgb[i][2] >> 3) << 10));

    S.rom = image;
    S.rom_size = size;

    /* Detect target variant from extension (.xo8, .sc8, .ch8) orXO-CHIP / SCHIP opcodes */
    S.mode = MODE_CHIP8;
    if (path) {
        int n = 0;
        while (path[n]) n++;
        if (n >= 4 && path[n - 4] == '.') {
            char c0 = (char)(path[n - 3] | 32), c1 = (char)(path[n - 2] | 32), c2 = (char)(path[n - 1] | 32);
            if (c0 == 'x' && c1 == 'o' && c2 == '8')
                S.mode = MODE_XOCHIP;
            else if (c0 == 's' && c1 == 'c' && (c2 == '8' || c2 == 'h'))
                S.mode = MODE_SCHIP;
        }
    }
    if (size > 3584u)
        S.mode = MODE_XOCHIP;
    else if (S.mode == MODE_CHIP8) {
        for (u32 i = 0; i + 1 < size; i += 2) {
            u16 w = (u16)(((u16)image[i] << 8) | image[i + 1]);
            if (w == 0xF000u || w == 0xF002u || (w & 0xF0FFu) == 0xF001u || (w & 0xFFF0u) == 0x00D0u) {
                S.mode = MODE_XOCHIP;
                break;
            }
            if (w == 0x00FEu || w == 0x00FFu || w == 0x00FBu || w == 0x00FCu || (w & 0xFFF0u) == 0x00C0u) {
                S.mode = MODE_SCHIP;
            }
        }
    }
    S.ipf = (S.mode == MODE_XOCHIP) ? 1000u : (S.mode == MODE_SCHIP ? 30u : 15u);

    for (int i = 0; i < 16; i++)
        M->rpl[i] = 0;
    S.rpl_dirty = 0;

    char *p = S.info;
    put_str(&p, S.mode == MODE_XOCHIP ? "XO-CHIP (4-plane, 64 KB), "
              : S.mode == MODE_SCHIP  ? "SUPER-CHIP 1.1 (128x64), "
                                      : "COSMAC VIP CHIP-8, ");
    put_u32(&p, size);
    put_str(&p, " bytes");

    chip8_reset();
    return 0;
}

void chip8_reset(void)
{
    for (u32 i = 0; i < sizeof(M->ram); i++)
        M->ram[i] = 0;
    for (int i = 0; i < 80; i++)
        M->ram[0x050 + i] = font5[i];
    for (int i = 0; i < 160; i++)
        M->ram[0x0A0 + i] = font10[i];
    for (u32 i = 0; i < S.rom_size && 0x200u + i < 0x10000u; i++)
        M->ram[0x200u + i] = S.rom[i];

    for (int i = 0; i < CHIP8_W * CHIP8_H; i++)
        M->vram[i] = 0;

    S.pc = 0x0200u;
    S.idx = 0;
    S.sp = 0;
    for (int i = 0; i < 16; i++)
        S.v[i] = 0, S.stack[i] = 0, S.pat[i] = 0;
    S.dt = S.st = 0;
    S.hires = 0;
    S.plane = 1u;
    S.halted = S.exited = 0;
    S.wait_key = -1;
    S.rng = 0xC051AC08u;
    S.keys = 0;
    S.has_pat = 0;
    S.step_hz = 4000u;
    S.pat_pos = S.pat_acc = 0;
    S.buzz_phase = 0;
}

void chip8_frame(u16 pad, const u8 *hid, int hid_n, u16 *picture)
{
    S.keys = map_keys(pad, hid, hid_n);

    for (u32 i = 0; i < S.ipf; i++) {
        if (!step_one())
            break;
    }

    gen_audio_frame();

    if (S.dt > 0) S.dt--;
    if (S.st > 0) S.st--;

    if (picture) {
        for (int i = 0; i < CHIP8_W * CHIP8_H; i++)
            picture[i] = S.pal[M->vram[i] & 15u];
    }
}

const char *chip8_info(void)
{
    return S.info;
}

u8 *chip8_save_ram(u32 *size, int *battery)
{
    *size = 16u;
    *battery = 1;
    return M->rpl;
}

int chip8_save_changed(void)
{
    int was = S.rpl_dirty;
    S.rpl_dirty = 0;
    return was;
}

int chip8_jammed(void)
{
    return 0;
}

void chip8_audio_rate(u32 hz)
{
    S.snd_hz = (hz >= 8000u && hz <= 192000u) ? hz : 0;
    S.snd_head = S.snd_count = 0;
    S.pat_acc = S.buzz_phase = 0;
}

int chip8_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && S.snd_count) {
        out[n++] = M->snd_ring[S.snd_head];
        S.snd_head = (S.snd_head + 1u) % SND_RING;
        S.snd_count--;
    }
    return n;
}
