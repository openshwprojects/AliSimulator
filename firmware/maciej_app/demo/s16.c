/* Sega System 16A, System 16B & OutRun-Road arcade hardware: see s16.h. */
#pragma GCC optimize("O2")
#include "s16.h"
#include "z80.h"
#include "zip.h"

#ifndef S16_HOST
#include "hw.h"
#endif

#define INLINE static inline __attribute__((always_inline))

static u8 *fmap[256];
static void s16_iack(u32 level);
static void s16_branch(u32 at);
INLINE u32 s16_fetch(u32 a);

#define M68K_IACK(level) s16_iack(level)
#define M68K_BRANCH(at)  s16_branch(at)
#define M68K_FETCH(pc)   s16_fetch(pc)
#include "m68k.inc"

INLINE u32 s16_fetch(u32 a)
{
    if (a & 1u)
        return odd(a, 0);
    const u8 *p = fmap[(a >> 16) & 0xFFu];
    return p ? *(const u16 *)(p + (a & 0xFFFFu)) : rw(a);
}

#define TOTAL_LINES     262
#define VIS_LINES       224
#define SND_RING        8192

struct s16_mem {
    u8 wram[0x10000];                   /* 64 KB 68000 Work RAM / NVRAM (word-swapped) */
    u8 tileram[0x10000];                /* 64 KB 315-5197 Tilemap RAM: 4 pages x 64x32 words */
    u8 textram[0x1000];                 /* 4 KB 315-5197 Text/Fix + scroll/page regs */
    u8 sprram[0x1000];                  /* 4 KB Sprite Object RAM (128 x 16B) */
    u8 palram[0x1000];                  /* 4 KB Palette CRAM (2048 x 16-bit colors) */
    u8 roadram[0x2000];                 /* 8 KB OutRun-style Road Generator RAM */
    u8 zram[0x800];                     /* 2 KB Z80 Sound RAM ($F800..$FFFF) */
    u8 pcm_regs[0x100];                 /* Sega 315-5218 16-channel PCM registers ($F000..$F0FF) */
    u8 nvram_sav[0x4000];               /* 16 KB battery-backed NVRAM (.sav) */
    s16 audio_ring[SND_RING];
};

#define ROM_CAP         0x00400000u
#define CODE_CAP        0x00400000u
#define ZROM_CAP        0x00080000u
#define PCM_CAP         0x00400000u
#define TILES_CAP       0x00400000u     /* Up to 131,072 8x8 4bpp tiles (32 B/tile) */
#define SPR_CAP         0x00400000u     /* Up to 2M 16-bit sprite words */
#define SCRATCH_CAP     0x00800000u

#ifdef S16_HOST
static struct s16_mem s16_host_mem;
static u8 host_rom[ROM_CAP], host_code[CODE_CAP], host_zrom[ZROM_CAP];
static u8 host_pcm[PCM_CAP], host_tiles[TILES_CAP], host_spr[SPR_CAP], host_scratch[SCRATCH_CAP];
#define M            (&s16_host_mem)
#define ROM_BUF      host_rom
#define CODE_BUF     host_code
#define ZROM_BUF     host_zrom
#define PCM_BUF      host_pcm
#define TILES_BUF    host_tiles
#define SPR_BUF      host_spr
#define SCRATCH_BUF  host_scratch
#else
#define M            ((struct s16_mem *)KSEG0(EMU_RAM_PHYS))
#define TILES_BUF    ((u8 *)KSEG0(0x03500000u))
#define SPR_BUF      ((u8 *)KSEG0(0x03900000u))
#define ROM_BUF      ((u8 *)KSEG0(0x05800000u))
#define CODE_BUF     ((u8 *)KSEG0(0x05C00000u))
#define ZROM_BUF     ((u8 *)KSEG0(0x06900000u))
#define PCM_BUF      ((u8 *)KSEG0(0x06980000u))
#define SCRATCH_BUF  ((u8 *)KSEG0(0x07580000u))
#endif

/* ---- YM2151 (OPM) + NEC uPD7759 + Sega 16-Ch PCM structures ---- */
enum { EG_ATT = 0, EG_DEC, EG_SUS, EG_REL };

struct opm_op {
    u32 phase, inc;
    s32 att, out, out1;
    u32 env;
    u8 dt1, mul, tl, ks, ar, am, d1r, dt2, d2r, d1l, rr;
    u8 state;
    u8 rate[4];
};

struct opm_ch {
    struct opm_op op[4];
    u8 rl, fb, alg, kc, kf, quiet;
};

struct s16_upd7759 {
    u8 playing, reset_n, start_n, bank;
    u8 fifo_latch;
    u32 pos, end, step_acc;
    s32 sample, state;
};

struct s16_pcm_ch {
    u32 pos24;                          /* 16.8 fixed-point offset inside 64 KB bank */
    u8 active;
};

static struct {
    u8 cpu_inited;
    u8 board_type;                      /* 0 = S16A, 1 = S16B, 2 = S16R (OutRun road) */
    u32 flags;
    u8 dip1, dip2, hw_cfg;
    u32 m68k_hz, z80_hz;
    s32 cyc_per_frame, zcyc_per_frame;

    u8 *rom, *code, *zrom, *pcm, *tiles, *sprites;
    u32 rom_len, code_len, zrom_len, pcm_len, tile_count, spr_words;

    /* Sega 315-5195 Memory Mapper */
    u8 mapper_regs[32];
    u8 mapper_active;
    u8 vid_enable, flip_screen;
    u8 tilebank[2];

    /* Inputs & Sound Latch */
    u16 pad_p1;
    u8 snd_latch, snd_pending;
    u8 vbl_irq;
    u8 nvram_dirty;

    /* Pre-converted 15-bit 0bbbbbgggggrrrrr palettes:
       [0x000..0x7FF] = normal, [0x800..0xFFF] = shadow (50%), [0x1000..0x17FF] = highlight (+50%) */
    u16 cram_all[0x1800];

    /* Sound CPU & Synthesizers */
    struct z80 z;
    struct {
        struct opm_ch ch[8];
        u8 addr, status, timer_ctrl, tb_load, noise_en, noise_freq, noise_cnt, eg_div;
        u16 ta_load;
        s32 ta_cnt, tb_cnt;
        u32 eg_cnt, lfsr;
        s32 prev_smp;
    } opm;
    struct s16_upd7759 upd;
    struct s16_pcm_ch pcm_ch[16];

    u32 sample_rate;
    u32 rendered_samples;
    int audio_count;
    s32 slice_end_cyc;
    u8  tile0_blank;
} S;

static char info_buf[96];

/* ---- Endian helpers for word-swapped 68000 buffers ---- */
INLINE u16 ws_rw(const u8 *buf, u32 off)
{
    return *(const u16 *)(buf + (off & ~1u));
}

INLINE void ws_ww(u8 *buf, u32 off, u16 v)
{
    *(u16 *)(buf + (off & ~1u)) = v;
}

INLINE u8 ws_rb(const u8 *buf, u32 off)
{
    return buf[off ^ 1u];
}

INLINE void ws_wb(u8 *buf, u32 off, u8 v)
{
    buf[off ^ 1u] = v;
}

/* ---- Palette CRAM conversion (Sega System 16 15-bit + Shadow/Highlight) ---- */
static void s16_update_cram(u32 idx)
{
    idx &= 2047u;
    u16 w = ws_rw(M->palram, idx * 2u);
    /* Sega System 16 15-bit RGB: R = (w[3:0]<<1)|w[12], G = (w[7:4]<<1)|w[13], B = (w[11:8]<<1)|w[14] */
    u32 r5 = (((w >> 0) & 0x0Fu) << 1) | ((w >> 12) & 1u);
    u32 g5 = (((w >> 4) & 0x0Fu) << 1) | ((w >> 13) & 1u);
    u32 b5 = (((w >> 8) & 0x0Fu) << 1) | ((w >> 14) & 1u);
    S.cram_all[idx]          = (u16)(r5 | (g5 << 5) | (b5 << 10));
    S.cram_all[0x800u + idx] = (u16)((r5 >> 1) | ((g5 >> 1) << 5) | ((b5 >> 1) << 10));
    u32 rh = r5 + ((31u - r5) >> 1);
    u32 gh = g5 + ((31u - g5) >> 1);
    u32 bh = b5 + ((31u - b5) >> 1);
    S.cram_all[0x1000u + idx] = (u16)(rh | (gh << 5) | (bh << 10));
}

/* ---- Audio: Yamaha YM2151 (OPM) + NEC uPD7759 ADPCM + Sega 16-Ch PCM ---- */
static const u16 opm_logsin[256] = {
    2137,1731,1543,1419,1326,1252,1190,1137,1091,1050,1013,979,949,920,894,869,
    846,825,804,785,767,749,732,717,701,687,672,659,646,633,621,609,
    598,587,576,566,556,546,536,527,518,509,500,492,484,476,468,460,
    453,445,438,431,424,417,410,404,397,391,385,379,373,367,361,356,
    350,345,339,334,329,324,319,314,309,304,299,295,290,286,281,277,
    273,268,264,260,256,252,248,244,240,237,233,229,226,222,219,215,
    212,209,205,202,199,196,193,190,187,184,181,178,175,172,169,167,
    164,161,159,156,153,151,148,146,143,141,139,136,134,132,129,127,
    125,123,121,119,117,115,113,111,109,107,105,103,101,99,97,96,
    94,92,90,89,87,85,84,82,81,79,78,76,75,73,72,70,
    69,68,66,65,64,62,61,60,59,57,56,55,54,53,52,50,
    49,48,47,46,45,44,43,42,41,40,39,38,37,36,36,35,
    34,33,32,31,31,30,29,28,27,27,26,25,25,24,23,23,
    22,21,21,20,19,19,18,18,17,17,16,16,15,15,14,14,
    13,13,12,12,11,11,11,10,10,9,9,9,8,8,8,7,
    7,7,6,6,6,5,5,5,5,4,4,4,4,4,3,3
};

static const u16 opm_exp2[256] = {
    1018,1013,1007,1002,996,991,986,980,975,970,965,959,954,949,944,939,
    934,929,924,919,914,909,904,899,895,890,885,880,876,871,866,862,
    857,852,848,843,839,834,830,826,821,817,812,808,804,800,795,791,
    787,783,779,774,770,766,762,758,754,750,746,742,738,734,730,726,
    723,719,715,711,707,704,700,696,693,689,685,682,678,675,671,667,
    664,660,657,653,650,647,643,640,636,633,630,626,623,620,617,613,
    610,607,604,601,597,594,591,588,585,582,579,576,573,570,567,564,
    561,558,555,552,549,547,544,541,538,535,532,530,527,524,521,519,
    516,513,511,508,505,503,500,498,495,492,490,487,485,482,480,477,
    475,472,470,467,465,463,460,458,455,453,451,448,446,444,441,439,
    437,435,432,430,428,426,423,421,419,417,415,413,410,408,406,404,
    402,400,398,396,394,392,390,388,386,384,382,380,378,376,374,372,
    370,368,366,365,363,361,359,357,355,353,352,350,348,346,344,343,
    341,339,337,336,334,332,331,329,327,325,324,322,320,319,317,316,
    314,312,311,309,308,306,304,303,301,300,298,297,295,294,292,291,
    289,288,286,285,283,282,280,279,278,276,275,273,272,270,269,268
};

static const u8 opm_dt1_tab[4][32] = {
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0,0,0,0,1,1,1,1,1,1,1,1,2,2,2,2,2,3,3,3,4,4,4,5,5,6,6,7,8,8,8,8},
    {1,1,1,1,2,2,2,2,2,3,3,3,4,4,4,5,5,6,6,7,8,8,9,10,11,12,13,14,16,16,16,16},
    {2,2,2,2,2,3,3,3,4,4,4,5,5,6,6,7,8,8,9,10,11,12,13,14,16,17,19,20,22,22,22,22}
};

static const u8 opm_eg_steps[20][8] = {
    {0,1,0,1,0,1,0,1}, {0,1,0,1,1,1,0,1}, {0,1,1,1,0,1,1,1}, {0,1,1,1,1,1,1,1},
    {1,1,1,1,1,1,1,1}, {1,1,1,2,1,1,1,2}, {1,2,1,2,1,2,1,2}, {1,2,2,2,1,2,2,2},
    {2,2,2,2,2,2,2,2}, {2,2,2,4,2,2,2,4}, {2,4,2,4,2,4,2,4}, {2,4,4,4,2,4,4,4},
    {4,4,4,4,4,4,4,4}, {4,4,4,8,4,4,4,8}, {4,8,4,8,4,8,4,8}, {4,8,8,8,4,8,8,8},
    {8,8,8,8,8,8,8,8}, {8,8,8,8,8,8,8,8}, {8,8,8,8,8,8,8,8}, {8,8,8,8,8,8,8,8}
};

static const u32 opm_inc7[13] = {
    96887, 102648, 108751, 115217, 122068, 129327,
    137017, 145164, 153796, 162941, 172630, 182895, 193774
};
static const u8 opm_kc_to_semi[16] = {0, 1, 2, 2, 3, 4, 5, 5, 6, 7, 8, 8, 9, 10, 11, 11};
static const u16 opm_dt2_kf[4] = {0, 384, 500, 608};

/* NEC uPD7759 ADPCM differential table */
static const s16 upd_step_tab[16][16] = {
    { 0,  0,  1,  2,  3,   5,   7,  10,  0,   0,  -1,  -2,  -3,   -5,   -7,  -10},
    { 0,  1,  2,  3,  4,   6,   8,  13,  0,  -1,  -2,  -3,  -4,   -6,   -8,  -13},
    { 0,  1,  2,  4,  5,   7,  10,  15,  0,  -1,  -2,  -4,  -5,   -7,  -10,  -15},
    { 0,  1,  3,  4,  6,   9,  13,  19,  0,  -1,  -3,  -4,  -6,   -9,  -13,  -19},
    { 0,  2,  3,  5,  8,  11,  15,  23,  0,  -2,  -3,  -5,  -8,  -11,  -15,  -23},
    { 0,  2,  4,  7, 10,  14,  19,  29,  0,  -2,  -4,  -7, -10,  -14,  -19,  -29},
    { 0,  3,  5,  8, 12,  16,  22,  33,  0,  -3,  -5,  -8, -12,  -16,  -22,  -33},
    { 1,  4,  7, 10, 15,  20,  29,  43, -1,  -4,  -7, -10, -15,  -20,  -29,  -43},
    { 1,  4,  8, 13, 18,  25,  35,  53, -1,  -4,  -8, -13, -18,  -25,  -35,  -53},
    { 1,  6, 10, 16, 22,  31,  43,  64, -1,  -6, -10, -16, -22,  -31,  -43,  -64},
    { 2,  7, 12, 19, 27,  37,  51,  76, -2,  -7, -12, -19, -27,  -37,  -51,  -76},
    { 2,  9, 16, 24, 34,  46,  64,  96, -2,  -9, -16, -24, -34,  -46,  -64,  -96},
    { 3, 11, 19, 29, 41,  57,  79, 117, -3, -11, -19, -29, -41,  -57,  -79, -117},
    { 4, 13, 24, 36, 50,  69,  96, 143, -4, -13, -24, -36, -50,  -69,  -96, -143},
    { 4, 16, 29, 44, 62,  85, 118, 175, -4, -16, -29, -44, -62,  -85, -118, -175},
    { 6, 20, 36, 54, 76, 104, 144, 214, -6, -20, -36, -54, -76, -104, -144, -214}
};
static const s8 upd_state_delta[16] = {-1, -1, 0, 0, 1, 2, 2, 3, -1, -1, 0, 0, 1, 2, 2, 3};

static void opm_op_env(struct opm_op *o)
{
    u32 e = (u32)o->att + ((u32)o->tl << 3);
    o->env = e > 0x3FFu ? 0x3FFu : e;
}

static u8 opm_eff_rate(u8 r, u8 kcode, u8 ks)
{
    if (!r) return 0;
    u32 v = (u32)r * 2u + (kcode >> (3u - (ks & 3u)));
    return (u8)(v > 63u ? 63u : v);
}

static void opm_op_update(struct opm_ch *c, int n)
{
    struct opm_op *o = &c->op[n];
    u32 oct = (c->kc >> 4) & 7u;
    u32 semi = opm_kc_to_semi[c->kc & 15u];
    u32 kcode = (oct << 2) | (semi >> 2);
    u32 total_kf = oct * 768u + semi * 64u + (c->kf & 63u) + opm_dt2_kf[o->dt2 & 3u];
    u32 eo = total_kf / 768u;
    u32 rem = total_kf - eo * 768u;
    u32 es = rem >> 6;
    u32 ef = rem & 63u;
    u32 base = opm_inc7[es] + (((opm_inc7[es + 1u] - opm_inc7[es]) * ef) >> 6);
    u32 inc = (eo <= 7u) ? (base >> (7u - eo)) : (base << (eo - 7u));
    if (S.sample_rate && S.sample_rate != 48000u)
        inc = (inc * 48000u) / S.sample_rate;
    u32 dt = opm_dt1_tab[o->dt1 & 3u][kcode & 31u] * 2u;
    inc = (o->dt1 & 4u) ? (inc > dt ? inc - dt : 0u) : (inc + dt);
    o->inc = (o->mul ? inc * o->mul : (inc >> 1)) & 0xFFFFFu;
    o->rate[EG_ATT] = opm_eff_rate(o->ar, (u8)kcode, o->ks);
    o->rate[EG_DEC] = opm_eff_rate(o->d1r, (u8)kcode, o->ks);
    o->rate[EG_SUS] = opm_eff_rate(o->d2r, (u8)kcode, o->ks);
    o->rate[EG_REL] = opm_eff_rate((u8)(o->rr * 2u + 1u), (u8)kcode, o->ks);
}

static void opm_key(struct opm_ch *c, int n, int on)
{
    struct opm_op *o = &c->op[n];
    if (on) {
        if (o->state == EG_REL) {
            o->phase = 0;
            o->state = EG_ATT;
            if (o->rate[EG_ATT] >= 62u) {
                o->att = 0;
                o->state = o->d1l ? EG_DEC : EG_SUS;
            }
            opm_op_env(o);
            c->quiet = 0;
        }
    } else if (o->state != EG_REL) {
        o->state = EG_REL;
    }
}

static void opm_update_irq(void)
{
    u8 msk = (u8)((S.opm.timer_ctrl >> 2) & 3u);
    S.z.irq = (S.opm.status & msk) ? 1u : 0u;
}

static s32 opm_ta_zcyc(void) { return (s32)(1024u - S.opm.ta_load) * 72; }
static s32 opm_tb_zcyc(void) { return (s32)(256u - S.opm.tb_load) * 1144; }

static void s16_audio_sync(void);

static void opm_write_reg(u8 r, u8 v)
{
    s16_audio_sync();
    static const u8 slot_map[4] = {0, 2, 1, 3};
    if (r == 0x08u) {
        struct opm_ch *c = &S.opm.ch[v & 7u];
        opm_key(c, 0, (v >> 3) & 1);
        opm_key(c, 1, (v >> 4) & 1);
        opm_key(c, 2, (v >> 5) & 1);
        opm_key(c, 3, (v >> 6) & 1);
        return;
    }
    if (r == 0x0Fu) {
        S.opm.noise_en = (v >> 7) & 1u;
        S.opm.noise_freq = v & 0x1Fu;
        return;
    }
    if (r == 0x10u) { S.opm.ta_load = (u16)((S.opm.ta_load & 3u) | ((u16)v << 2)); return; }
    if (r == 0x11u) { S.opm.ta_load = (u16)((S.opm.ta_load & ~3u) | (v & 3u)); return; }
    if (r == 0x12u) { S.opm.tb_load = v; return; }
    if (r == 0x14u) {
        u8 prev = S.opm.timer_ctrl;
        S.opm.timer_ctrl = v;
        if (!(prev & 1u) && (v & 1u)) S.opm.ta_cnt = opm_ta_zcyc();
        if (!(prev & 2u) && (v & 2u)) S.opm.tb_cnt = opm_tb_zcyc();
        if (v & 0x10u) S.opm.status &= ~1u;
        if (v & 0x20u) S.opm.status &= ~2u;
        opm_update_irq();
        return;
    }
    if (r >= 0x20u && r < 0x28u) {
        struct opm_ch *c = &S.opm.ch[r & 7u];
        c->rl = (v >> 6) & 3u;
        c->fb = (v >> 3) & 7u;
        c->alg = v & 7u;
        return;
    }
    if (r >= 0x28u && r < 0x30u) {
        struct opm_ch *c = &S.opm.ch[r & 7u];
        c->kc = v & 0x7Fu;
        for (int i = 0; i < 4; i++) opm_op_update(c, i);
        return;
    }
    if (r >= 0x30u && r < 0x38u) {
        struct opm_ch *c = &S.opm.ch[r & 7u];
        c->kf = (v >> 2) & 0x3Fu;
        for (int i = 0; i < 4; i++) opm_op_update(c, i);
        return;
    }
    if (r >= 0x40u) {
        struct opm_ch *c = &S.opm.ch[r & 7u];
        int op_idx = slot_map[(r >> 3) & 3u];
        struct opm_op *o = &c->op[op_idx];
        switch (r & 0xE0u) {
        case 0x40u: o->dt1 = (v >> 4) & 7u; o->mul = v & 0x0Fu; opm_op_update(c, op_idx); break;
        case 0x60u: o->tl = v & 0x7Fu; opm_op_env(o); break;
        case 0x80u: o->ks = (v >> 6) & 3u; o->ar = v & 0x1Fu; opm_op_update(c, op_idx); break;
        case 0xA0u: o->am = (v >> 7) & 1u; o->d1r = v & 0x1Fu; opm_op_update(c, op_idx); break;
        case 0xC0u: o->dt2 = (v >> 6) & 3u; o->d2r = v & 0x1Fu; opm_op_update(c, op_idx); break;
        case 0xE0u:
            o->d1l = (v >> 4) & 0x0Fu;
            if (o->d1l == 15u) o->d1l = 31u;
            o->rr = v & 0x0Fu;
            opm_op_update(c, op_idx);
            break;
        }
    }
}

INLINE s32 opm_calc_op(struct opm_op *o, s32 mod)
{
    u32 p = ((o->phase >> 10) + (u32)mod) & 0x3FFu;
    o->phase = (o->phase + o->inc) & 0xFFFFFu;
    if (o->env >= 0x340u)
        return 0;
    u32 idx = (p & 0x100u) ? (~p & 0xFFu) : (p & 0xFFu);
    u32 lv = (u32)opm_logsin[idx] + (o->env << 2);
    if (lv >= 0x1A00u)
        return 0;
    s32 mag = ((s32)opm_exp2[~lv & 0xFFu] << 2) >> (lv >> 8);
    return (p & 0x200u) ? -mag : mag;
}

static s32 opm_step_24khz(void)
{
    S.opm.eg_div ^= 1u;
    if (!S.opm.eg_div)
        S.opm.eg_cnt++;
    int do_eg = !S.opm.eg_div;
    u32 egc = S.opm.eg_cnt;

    s32 total = 0;
    for (int ch = 0; ch < 8; ch++) {
        struct opm_ch *c = &S.opm.ch[ch];
        if (c->quiet)
            continue;
        if (do_eg) {
            int all_rel = 1;
            for (int n = 0; n < 4; n++) {
                struct opm_op *o = &c->op[n];
                if (o->state != EG_REL || o->att < 0x3FF)
                    all_rel = 0;
                u8 r = o->rate[o->state];
                if (!r)
                    continue;
                u32 sh = (r < 48u) ? (11u - (r >> 2)) : 0u;
                if ((egc & ((1u << sh) - 1u)) != 0)
                    continue;
                u32 st_row = (r < 48u) ? (r & 3u) : ((r - 44u) < 20u ? (r - 44u) : 19u);
                u8 inc = opm_eg_steps[st_row][(egc >> sh) & 7u];
                if (o->state == EG_ATT) {
                    o->att += (~o->att * (s32)inc) >> 4;
                    if (o->att <= 0) {
                        o->att = 0;
                        o->state = o->d1l ? EG_DEC : EG_SUS;
                    }
                } else {
                    o->att += (s32)inc;
                    if (o->state == EG_DEC && o->att >= ((s32)o->d1l << 5)) {
                        o->att = (s32)o->d1l << 5;
                        o->state = EG_SUS;
                    }
                    if (o->att >= 0x3FF)
                        o->att = 0x3FF;
                }
                opm_op_env(o);
            }
            if (all_rel) {
                c->quiet = 1;
                continue;
            }
        }
        struct opm_op *o0 = &c->op[0], *o1 = &c->op[1], *o2 = &c->op[2], *o3 = &c->op[3];
        s32 fb = c->fb ? ((o0->out + o0->out1) >> (9 - c->fb)) : 0;
        o0->out1 = o0->out;
        o0->out = opm_calc_op(o0, fb);
        s32 v0 = o0->out, out = 0;
        switch (c->alg) {
        case 0: o1->out = opm_calc_op(o1, v0 >> 1); o2->out = opm_calc_op(o2, o1->out >> 1); out = opm_calc_op(o3, o2->out >> 1); break;
        case 1: o1->out = opm_calc_op(o1, 0); o2->out = opm_calc_op(o2, (v0 + o1->out) >> 1); out = opm_calc_op(o3, o2->out >> 1); break;
        case 2: o1->out = opm_calc_op(o1, 0); o2->out = opm_calc_op(o2, o1->out >> 1); out = opm_calc_op(o3, (v0 + o2->out) >> 1); break;
        case 3: o1->out = opm_calc_op(o1, v0 >> 1); o2->out = opm_calc_op(o2, 0); out = opm_calc_op(o3, (o1->out + o2->out) >> 1); break;
        case 4: o1->out = opm_calc_op(o1, v0 >> 1); o2->out = opm_calc_op(o2, 0); out = o1->out + opm_calc_op(o3, o2->out >> 1); break;
        case 5: out = opm_calc_op(o1, v0 >> 1) + opm_calc_op(o2, v0 >> 1) + opm_calc_op(o3, v0 >> 1); break;
        case 6: o1->out = opm_calc_op(o1, v0 >> 1); out = o1->out + opm_calc_op(o2, 0) + opm_calc_op(o3, 0); break;
        default: out = v0 + opm_calc_op(o1, 0) + opm_calc_op(o2, 0) + opm_calc_op(o3, 0); break;
        }
        if (ch == 7 && S.opm.noise_en && o3->env < 0x340u) {
            u32 period = (32u - S.opm.noise_freq);
            if (!period) period = 1u;
            if (++S.opm.noise_cnt >= period) {
                S.opm.noise_cnt = 0;
                S.opm.lfsr = (S.opm.lfsr >> 1) ^ ((S.opm.lfsr & 1u) ? 0x10008u : 0u);
            }
            s32 nmag = (s32)(0x800u >> (o3->env >> 6));
            out += (S.opm.lfsr & 1u) ? nmag : -nmag;
        }
        if (c->rl)
            total += out;
    }
    return total;
}

/* NEC uPD7759 trigger */
static void upd7759_start_voice(u8 sample_idx)
{
    if (!S.pcm || S.pcm_len < 16u)
        return;
    u32 bank_base = ((u32)S.upd.bank * 0x10000u) % S.pcm_len;
    const u8 *rom = S.pcm + bank_base;
    u32 max_len = S.pcm_len - bank_base;

    /* Check standard uPD7759 MD-mode ROM header: [max_sample, 0x5A, 0xA5, 0x69, 0x55] */
    if (max_len >= 10u && rom[1] == 0x5Au && rom[2] == 0xA5u && rom[3] == 0x69u && rom[4] == 0x55u) {
        if (sample_idx <= rom[0]) {
            u32 h_off = 5u + (u32)sample_idx * 2u;
            if (h_off + 2u <= max_len) {
                u32 start = (((u32)rom[h_off] << 8) | rom[h_off + 1u]) * 2u;
                /* Scan nibbles or play up to 16 KB */
                if (start + 4u < max_len) {
                    S.upd.pos = (bank_base + start + 2u) * 2u;  /* nibble index */
                    S.upd.end = (bank_base + ((start + 0x3000u < max_len) ? (start + 0x3000u) : max_len)) * 2u;
                    S.upd.sample = 0;
                    S.upd.state = 0;
                    S.upd.playing = 1;
                    return;
                }
            }
        }
    }

    /* Simple direct table fallback for custom .s16 sample banks:
       Header at 0: 16 x (u32 offset_le, u32 len_le) */
    if (sample_idx < 16u && max_len >= 128u && rom[0] == 'U' && rom[1] == 'P' && rom[2] == 'D' && rom[3] == '0') {
        u32 p = 4u + (u32)sample_idx * 8u;
        u32 off = (u32)rom[p] | ((u32)rom[p+1] << 8) | ((u32)rom[p+2] << 16) | ((u32)rom[p+3] << 24);
        u32 len = (u32)rom[p+4] | ((u32)rom[p+5] << 8) | ((u32)rom[p+6] << 16) | ((u32)rom[p+7] << 24);
        if (off < max_len && len > 0) {
            if (off + len > max_len) len = max_len - off;
            S.upd.pos = (bank_base + off) * 2u;
            S.upd.end = (bank_base + off + len) * 2u;
            S.upd.sample = 0;
            S.upd.state = 0;
            S.upd.playing = 1;
        }
    }
}

static void s16_render_samples(u32 target)
{
    if (!S.sample_rate)
        return;
    if (target > SND_RING)
        target = SND_RING;
    if (target <= S.rendered_samples)
        return;

    u32 start = S.rendered_samples;
    u32 count = target - start;
    s16 *ring = M->audio_ring + S.audio_count;
    int has_upd = (S.upd.playing && S.pcm);

    /* Pass 1: YM2151 (24 kHz -> 48 kHz) + NEC uPD7759 ADPCM */
    for (u32 i = 0; i < count; i++) {
        if (((start + i) & 1u) == 0)
            S.opm.prev_smp = opm_step_24khz();
        s32 mix = S.opm.prev_smp;

        if (has_upd) {
            S.upd.step_acc += 8000u;
            if (S.upd.step_acc >= S.sample_rate) {
                S.upd.step_acc -= S.sample_rate;
                if (S.upd.pos >= S.upd.end || (S.upd.pos >> 1) >= S.pcm_len) {
                    S.upd.playing = 0;
                    has_upd = 0;
                } else {
                    u8 byte = S.pcm[S.upd.pos >> 1];
                    u8 nib = (S.upd.pos & 1u) ? (byte & 15u) : (byte >> 4);
                    S.upd.pos++;
                    S.upd.sample += (s32)upd_step_tab[S.upd.state & 15][nib] * 28;
                    if (S.upd.sample > 16000) S.upd.sample = 16000;
                    if (S.upd.sample < -16000) S.upd.sample = -16000;
                    S.upd.state += upd_state_delta[nib];
                    if (S.upd.state < 0) S.upd.state = 0;
                    if (S.upd.state > 15) S.upd.state = 15;
                }
            }
            if (has_upd)
                mix += S.upd.sample;
        }

        if (mix > 32767) mix = 32767;
        if (mix < -32768) mix = -32768;
        ring[i] = (s16)mix;
    }

    /* Pass 2: Sega 315-5218 16-Channel PCM (channel-outer loop, zero per-sample divisions) */
    if ((S.flags & 4u) && S.pcm && S.pcm_len) {
        u32 pcm_len = S.pcm_len;
        const u8 *pcm = S.pcm;
        for (int ch = 0; ch < 16; ch++) {
            u8 ctrl = M->pcm_regs[0x86 + ch * 8];
            if (ctrl & 1u) {
                S.pcm_ch[ch].active = 0;
                continue;
            }
            u8 *r = M->pcm_regs + ch * 8;
            if (!S.pcm_ch[ch].active) {
                u16 st = (u16)(M->pcm_regs[0x84 + ch * 8] | ((u16)M->pcm_regs[0x85 + ch * 8] << 8));
                S.pcm_ch[ch].pos24 = (u32)st << 8;
                S.pcm_ch[ch].active = 1;
            }
            s32 vol = (s32)((r[2] & 0x7Fu) + (r[3] & 0x7Fu));
            u32 adv = ((u32)r[7] * 167u) >> 8;
            u32 end_hi = r[6];
            u32 loop_pos24 = (u32)(r[4] | ((u16)r[5] << 8)) << 8;
            u32 bank = ((u32)(ctrl >> 3) & 7u) * 0x10000u;
            if (bank >= pcm_len)
                bank %= pcm_len;
            u32 pos24 = S.pcm_ch[ch].pos24;

            for (u32 i = 0; i < count; i++) {
                u32 off = bank + (pos24 >> 8);
                if (off >= pcm_len)
                    off %= pcm_len;
                s32 smp = ((s32)pcm[off] - 128) * vol;
                s32 s = (s32)ring[i] + (smp >> 2);
                if (s > 32767) s = 32767;
                if (s < -32768) s = -32768;
                ring[i] = (s16)s;

                pos24 += adv;
                if ((pos24 >> 16) > end_hi) {
                    if (ctrl & 2u) {
                        M->pcm_regs[0x86 + ch * 8] |= 1u;
                        S.pcm_ch[ch].active = 0;
                        break;
                    }
                    pos24 = loop_pos24;
                }
            }
            if (S.pcm_ch[ch].active)
                S.pcm_ch[ch].pos24 = pos24;
        }
    }

    S.audio_count += (int)count;
    S.rendered_samples = target;
}

static void s16_audio_sync(void)
{
    if (!S.sample_rate || S.zcyc_per_frame <= 0)
        return;
    s32 zc = S.z.cycles;
    if (zc < 0) zc = 0;
    if (zc > S.zcyc_per_frame) zc = S.zcyc_per_frame;
    u32 frame_smp = S.sample_rate / 60u;
    u32 target = ((u32)zc * frame_smp) / (u32)S.zcyc_per_frame;
    s16_render_samples(target);
}

/* ---- Z80 Sound CPU Memory & I/O ---- */
static u8 s16_z80_rd(struct z80 *c, u16 a)
{
    (void)c;
    if (a < 0xE000u)
        return (S.zrom && a < S.zrom_len) ? S.zrom[a] : 0xFFu;
    if (a >= 0xE800u && a < 0xF000u) {  /* Sound command latch at $E800 */
        S.snd_pending = 0;
        return S.snd_latch;
    }
    if (a >= 0xF000u && a < 0xF100u)
        return M->pcm_regs[a & 0xFFu];
    if (a >= 0xF800u)
        return M->zram[a & 0x7FFu];
    return 0xFFu;
}

static void s16_z80_wr(struct z80 *c, u16 a, u8 v)
{
    (void)c;
    if (a >= 0xF000u && a < 0xF100u) {
        s16_audio_sync();
        M->pcm_regs[a & 0xFFu] = v;
        return;
    }
    if (a >= 0xF800u)
        M->zram[a & 0x7FFu] = v;
}

static u8 s16_z80_in(struct z80 *c, u16 port)
{
    (void)c;
    u8 p = (u8)port;
    if (p == 0x01u)                     /* YM2151 status (bit 7 = busy = 0, bits 1..0 = Timer B/A) */
        return S.opm.status;
    if (p == 0x80u)                     /* uPD7759 /BUSY (1 = idle, 0 = busy playing) */
        return S.upd.playing ? 0x00u : 0x80u;
    if (p == 0xE0u || p == 0xC0u) {     /* Sound command latch read */
        S.snd_pending = 0;
        return S.snd_latch;
    }
    return 0xFFu;
}

static void s16_z80_out(struct z80 *c, u16 port, u8 v)
{
    (void)c;
    u8 p = (u8)port;
    if (p == 0x00u) {
        S.opm.addr = v;
    } else if (p == 0x01u) {
        opm_write_reg(S.opm.addr, v);
    } else if (p == 0x40u) {            /* uPD7759 data / sample index */
        s16_audio_sync();
        S.upd.fifo_latch = v;
        upd7759_start_voice(v);
    } else if (p == 0x80u) {            /* uPD7759 control (/RESET bit 7, /START bit 6) */
        s16_audio_sync();
        if (!(v & 0x80u))
            S.upd.playing = 0;
        if ((S.upd.start_n & 0x40u) && !(v & 0x40u))
            upd7759_start_voice(S.upd.fifo_latch);
        S.upd.start_n = v;
    } else if (p == 0xC0u) {            /* uPD7759 ROM bank select */
        S.upd.bank = v & 7u;
    }
}

/* ---- 68000 Memory Map & Sega 315-5195 Mapper ---- */
static void s16_rebuild_68k_map(void)
{
    for (int i = 0; i < 256; i++) {
        rmap[i] = 0;
        wmap[i] = 0;
        fmap[i] = 0;
    }

    /* Default System 16A / 16B / S16R baseline map */
    u32 rom_pages = (S.rom_len + 0xFFFFu) >> 16;
    if (rom_pages > 16u) rom_pages = 16u;
    for (u32 p = 0; p < rom_pages; p++) {
        rmap[p] = S.rom + p * 0x10000u;
        fmap[p] = (S.code ? S.code : S.rom) + p * 0x10000u;
    }

    rmap[0x40] = M->tileram;
    wmap[0x40] = M->tileram;

    /* Work RAM at $FE0000..$FEFFFF (16A); $FF0000..$FFFFFF goes through io_read/io_write
       so $FF0000..$FF003F 315-5195 mapper regs and $FF8000..$FFFFFF Work RAM coexist cleanly! */
    rmap[0xFE] = M->wram;
    wmap[0xFE] = M->wram;

    /* Apply Sega 315-5195 custom region mappings when programmed by a System 16B game */
    if (S.mapper_active) {
        static const u8 sz_pages[4] = {1, 2, 4, 8}; /* 64K, 128K, 256K, 512K */
        for (int r = 0; r < 8; r++) {
            u8 cfg  = S.mapper_regs[0x10 + r * 2];
            u8 base = S.mapper_regs[0x11 + r * 2];
            if ((cfg & 0x08u) || (r != 0 && base == 0))
                continue;
            u32 npg = sz_pages[cfg & 3u];
            u32 p0  = base & ~(npg - 1u);
            if (r == 0 || r == 1) {     /* ROM regions */
                u32 rom_off = (r == 1) ? 0x40000u : 0u;
                for (u32 k = 0; k < npg && p0 + k < 255u; k++) {
                    u32 off = rom_off + k * 0x10000u;
                    if (off < S.rom_len) {
                        rmap[p0 + k] = S.rom + off;
                        fmap[p0 + k] = (S.code ? S.code : S.rom) + off;
                    }
                }
            } else if (r == 3 && p0 < 255u) {   /* Tilegen RAM */
                rmap[p0] = M->tileram;
                wmap[p0] = M->tileram;
            } else if (r == 6 && p0 < 0xFFu) {  /* Work RAM if mapped below $FF0000 */
                rmap[p0] = M->wram;
                wmap[p0] = M->wram;
                fmap[p0] = M->wram;
            }
        }
    }
}

static void s16_send_sound_cmd(u8 cmd)
{
    S.snd_latch = cmd;
    S.snd_pending = 1;
    S.z.nmi = 1;
}

static u16 s16_read_inputs(u32 off)
{
    /* Active-low arcade inputs:
       Word 0 ($C40000): Service/Coins/Start (bit 0=Coin1, bit 2=Service, bit 4=1P Start, bit 5=2P Start)
       Word 2 ($C40002 / $C40004): P1 Joystick + Buttons:
         bit 0 = Button 1 (Attack/Accel -> PAD_A)
         bit 1 = Button 2 (Jump/Brake   -> PAD_B)
         bit 2 = Button 3 (Magic/Gear   -> PAD_SELECT)
         bit 4 = Up, bit 5 = Down, bit 6 = Left, bit 7 = Right
       Word 4 ($C40008): DIP Switch 1 (low byte) & DIP Switch 2 (high byte) */
    u16 p = S.pad_p1;
    u32 idx = (off >> 1) & 7u;
    if (idx == 0) {
        u16 v = 0xFFFFu;
        if (p & 0x0004u) v &= (u16)~0x0001u;    /* SELECT also inserts Coin 1! */
        if (p & 0x0008u) v &= (u16)~0x0010u;    /* START = 1P Start */
        return v;
    }
    if (idx == 1 || idx == 2) {
        u16 v = 0xFFFFu;
        if (p & 0x0001u) v &= (u16)~0x0001u;    /* A = Button 1 */
        if (p & 0x0002u) v &= (u16)~0x0002u;    /* B = Button 2 */
        if (p & 0x0004u) v &= (u16)~0x0004u;    /* Select = Button 3 */
        if (p & 0x0100u) v &= (u16)~0x0004u;    /* X = Button 3 */
        if (p & 0x0010u) v &= (u16)~0x0010u;    /* Up */
        if (p & 0x0020u) v &= (u16)~0x0020u;    /* Down */
        if (p & 0x0040u) v &= (u16)~0x0040u;    /* Left */
        if (p & 0x0080u) v &= (u16)~0x0080u;    /* Right */
        return v;
    }
    if (idx == 4 || idx == 6)
        return (u16)(((u16)S.dip2 << 8) | S.dip1);
    return 0xFFFFu;
}

static u32 io_read(u32 a, int size)
{
    /* Text/Fix RAM ($410000..$41FFFF mirror of 4 KB M->textram) */
    if ((a & 0xFF0000u) == 0x410000u) {
        u32 off = a & 0x0FFFu;
        return (size == 1) ? ws_rb(M->textram, off) : ws_rw(M->textram, off);
    }
    /* Sprite Object RAM ($440000..$44FFFF) */
    if ((a & 0xFF0000u) == 0x440000u) {
        u32 off = a & 0x0FFFu;
        return (size == 1) ? ws_rb(M->sprram, off) : ws_rw(M->sprram, off);
    }
    /* Road Generator RAM ($800000..$80FFFF) */
    if ((a & 0xFF0000u) == 0x800000u) {
        u32 off = a & 0x1FFFu;
        return (size == 1) ? ws_rb(M->roadram, off) : ws_rw(M->roadram, off);
    }
    /* Palette CRAM ($840000..$84FFFF) */
    if ((a & 0xFF0000u) == 0x840000u) {
        u32 off = a & 0x0FFFu;
        return (size == 1) ? ws_rb(M->palram, off) : ws_rw(M->palram, off);
    }
    /* Arcade I/O Ports ($C00000..$C7FFFF) */
    if (a >= 0xC00000u && a < 0xC80000u) {
        u16 w = s16_read_inputs(a & 0xFFFFu);
        return (size == 1) ? ((a & 1u) ? (w & 0xFFu) : (w >> 8)) : w;
    }
    /* Page $FF: $FF0000..$FF003F = 315-5195 Mapper; $FF8000..$FFFFFF = Work RAM */
    if ((a & 0xFF0000u) == 0xFF0000u) {
        if (a < 0xFF0040u) {
            u8 r = S.mapper_regs[(a >> 1) & 31u];
            return (size == 1) ? ((a & 1u) ? r : 0xFFu) : (0xFF00u | r);
        }
        u32 off = a & 0xFFFFu;
        return (size == 1) ? ws_rb(M->wram, off) : ws_rw(M->wram, off);
    }
    return (size == 1) ? 0xFFu : 0xFFFFu;
}

static void io_write(u32 a, u32 v, int size)
{
    if ((a & 0xFF0000u) == 0x410000u) {
        u32 off = a & 0x0FFFu;
        if (size == 1) ws_wb(M->textram, off, (u8)v);
        else           ws_ww(M->textram, off, (u16)v);
        return;
    }
    if ((a & 0xFF0000u) == 0x440000u) {
        u32 off = a & 0x0FFFu;
        if (size == 1) ws_wb(M->sprram, off, (u8)v);
        else           ws_ww(M->sprram, off, (u16)v);
        return;
    }
    if ((a & 0xFF0000u) == 0x800000u) {
        u32 off = a & 0x1FFFu;
        if (size == 1) ws_wb(M->roadram, off, (u8)v);
        else           ws_ww(M->roadram, off, (u16)v);
        return;
    }
    if ((a & 0xFF0000u) == 0x840000u) {
        u32 off = a & 0x0FFFu;
        if (size == 1) ws_wb(M->palram, off, (u8)v);
        else           ws_ww(M->palram, off, (u16)v);
        s16_update_cram(off >> 1);
        return;
    }
    if (a >= 0xC00000u && a < 0xC80000u) {
        u32 lo = a & 0xFFu;
        if (lo == 0x10u || lo == 0x11u || lo == 0x06u || lo == 0x07u) {
            s16_send_sound_cmd((u8)v);
        } else if (lo == 0x20u || lo == 0x21u) {
            S.vid_enable = (v & 0x20u) ? 1 : 1;
            S.flip_screen = (v & 0x40u) ? 1 : 0;
        } else if (lo == 0x30u || lo == 0x31u) {
            S.tilebank[0] = v & 15u;
            S.tilebank[1] = (v >> 4) & 15u;
        }
        return;
    }
    if ((a & 0xFF0000u) == 0xFF0000u) {
        if (a < 0xFF0040u) {
            u32 idx = (a >> 1) & 31u;
            u8 b = (u8)v;
            S.mapper_regs[idx] = b;
            if (idx == 2u) {
                s16_send_sound_cmd(b);
            } else if (idx >= 0x10u) {
                S.mapper_active = 1;
                s16_rebuild_68k_map();
            }
            return;
        }
        u32 off = a & 0xFFFFu;
        if (size == 1) ws_wb(M->wram, off, (u8)v);
        else           ws_ww(M->wram, off, (u16)v);
        if (off >= 0xC000u)
            S.nvram_dirty = 1;
    }
}

static void cpu_reset_line(void) {}

static void s16_iack(u32 level)
{
    if (level == 4)
        S.vbl_irq = 0;
    m.ipl = S.vbl_irq ? 4u : 0u;
}

static void s16_branch(u32 at)
{
    /* Cycle-exact fast-forward of tight VBlank spinloops (`BRA.S *` or `TST.x $FE/$FFxxxx; Bcc *-6`) */
    if (m.im >= 4u || m.pending || S.slice_end_cyc <= m.clock)
        return;
    if (at == m.pc) {
        s32 rem = S.slice_end_cyc - m.clock;
        m.clock += ((rem + 9) / 10) * 10;
        return;
    }
    if (at > m.pc && at - m.pc == 6u && !(m.pc & 1u)) {
        u32 op = s16_fetch(m.pc);
        u32 hi = s16_fetch(m.pc + 2u);
        if ((op == 0x4A39u || op == 0x4A79u || op == 0x4AB9u) && (hi == 0x00FFu || hi == 0x00FEu)) {
            s32 per = (op == 0x4AB9u) ? 30 : 26;
            s32 rem = S.slice_end_cyc - m.clock;
            m.clock += ((rem + per - 1) / per) * per;
        }
    }
}

/* ---- Video Composer: Direct-to-RGB555 Painter's Pipeline (Road -> BG -> FG -> Text -> Zoomed Sprites) ---- */
INLINE void s16_fill_span(u16 *out, int x0, int x1, u16 col)
{
    if (x0 < 0) x0 = 0;
    if (x1 >= S16_W) x1 = S16_W - 1;
    if (x0 > x1)
        return;
    if (x0 & 1)
        out[x0++] = col;
    int rem = x1 - x0 + 1;
    if (rem >= 2) {
        u32 pair = (u32)col | ((u32)col << 16);
        u32 *p32 = (u32 *)(out + x0);
        int n2 = rem >> 1;
        for (int i = 0; i < n2; i++)
            p32[i] = pair;
        x0 += n2 << 1;
    }
    if (x0 <= x1)
        out[x0] = col;
}

static void s16_render_road_frame(u16 *picture)
{
    u16 bg0 = S.cram_all[0];
    u32 bg0_pair = (u32)bg0 | ((u32)bg0 << 16);

    for (int y = 0; y < S16_H; y++) {
        int draw_y = S.flip_screen ? (S16_H - 1 - y) : y;
        u16 *out = picture + draw_y * S16_W;
        u32 base = (u32)y * 8u;
        u16 cfg = (S.flags & 16u) ? ws_rw(M->roadram, base + 6u) : 0u;
        if (!(cfg & 0x8000u)) {
            u32 *out32 = (u32 *)out;
            for (int i = 0; i < S16_W / 2; i++)
                out32[i] = bg0_pair;
            continue;
        }
        int cx = (s16)ws_rw(M->roadram, base + 0u);
        int hw = ws_rw(M->roadram, base + 2u);
        u16 zp = ws_rw(M->roadram, base + 4u);
        const u16 *pal = S.cram_all + ((cfg & 0x7Fu) * 16u);
        int alt = (zp >> 6) & 1;

        u16 c_grass = pal[alt ? 2u : 1u];
        u16 c_curb  = pal[alt ? 4u : 3u];
        u16 c_road  = pal[alt ? 6u : 5u];
        u16 c_lane  = pal[7u];

        if (hw <= 0) {
            u32 gp = (u32)c_grass | ((u32)c_grass << 16);
            u32 *out32 = (u32 *)out;
            for (int i = 0; i < S16_W / 2; i++)
                out32[i] = gp;
            continue;
        }

        int curb_w = (hw >> 3) + 2;
        int outer  = hw + curb_w;

        s16_fill_span(out, 0, cx - outer - 1, c_grass);
        s16_fill_span(out, cx - outer, cx - hw - 1, c_curb);
        s16_fill_span(out, cx - hw, cx + hw, c_road);
        s16_fill_span(out, cx + hw + 1, cx + outer, c_curb);
        s16_fill_span(out, cx + outer + 1, S16_W - 1, c_grass);

        if (!alt) {
            int lane1  = (hw * 21845) >> 16;
            int dash_w = (hw >> 5) + 1;
            int r_lo = cx - hw, r_hi = cx + hw;
            int a0, a1;

            a0 = cx - lane1 - dash_w; if (a0 < r_lo) a0 = r_lo;
            a1 = cx - lane1 + dash_w; if (a1 > r_hi) a1 = r_hi;
            s16_fill_span(out, a0, a1, c_lane);

            a0 = cx - dash_w; if (a0 < r_lo) a0 = r_lo;
            a1 = cx + dash_w; if (a1 > r_hi) a1 = r_hi;
            s16_fill_span(out, a0, a1, c_lane);

            a0 = cx + lane1 - dash_w; if (a0 < r_lo) a0 = r_lo;
            a1 = cx + lane1 + dash_w; if (a1 > r_hi) a1 = r_hi;
            s16_fill_span(out, a0, a1, c_lane);
        }
    }
}

static void s16_draw_scroll_pass(u16 *picture, int is_fg, int want_hi, u32 bank_base, int fill_bg0)
{
    u32 tcnt = S.tile_count;
    if (!tcnt)
        return;
    u16 pages = ws_rw(M->textram, is_fg ? 0xDF8u : 0xDFAu);
    u16 h_reg_base = ws_rw(M->textram, is_fg ? 0xF80u : 0xF98u);
    u16 v_reg = ws_rw(M->textram, is_fg ? 0xF16u : 0xF18u);
    u32 pal_hi = (S.tilebank[is_fg] >> 1) & 0x78u;
    u16 want_bit = want_hi ? 0x8000u : 0x0000u;

    /* Quick scan of the 4 mapped 64x32 pages when want_hi==1: skip entire pass if no hi-pri tile exists! */
    if (want_hi) {
        int any_hi = 0;
        u8 checked = 0;
        for (int q = 0; q < 4 && !any_hi; q++) {
            u32 pg = (pages >> (q * 4)) & 3u;
            if (checked & (1u << pg))
                continue;
            checked |= (u8)(1u << pg);
            const u32 *w32 = (const u32 *)(M->tileram + pg * 4096u);
            for (int i = 0; i < 1024; i++) {
                if (w32[i] & 0x80008000u) { any_hi = 1; break; }
            }
        }
        if (!any_hi)
            return;
    }

    if (!(v_reg & 0x8000u)) {
        u16 bg0 = S.cram_all[0];
        u32 bg0_pair = (u32)bg0 | ((u32)bg0 << 16);
        int row_step = S.flip_screen ? -S16_W : S16_W;
        u16 bpal[16];
        bpal[0] = bg0;

        for (int y = 0; y < S16_H;) {
            u16 h_reg = h_reg_base;
            if (h_reg & 0x8000u) {
                u32 roff = (is_fg ? 0xF80u : 0xFC0u) + (u32)((y >> 3) & 31) * 2u;
                h_reg = ws_rw(M->textram, roff);
            }
            int hscroll = h_reg & 0x3FFu;
            int sy = (y + (v_reg & 0x1FF)) & 0x1FF;
            int chunk = 8 - (sy & 7);
            if ((h_reg_base & 0x8000u) && (8 - (y & 7)) < chunk)
                chunk = 8 - (y & 7);
            if (y + chunk > S16_H)
                chunk = S16_H - y;

            u32 ty = (u32)(sy >> 3) & 31u;
            u32 row_off0 = (u32)(sy & 7) * 4u;
            int qy = (sy >> 8) << 1;
            int draw_y0 = S.flip_screen ? (S16_H - 1 - y) : y;
            u16 *out_base = picture + draw_y0 * S16_W;

            for (int x = 0; x < S16_W;) {
                int sx = (x + hscroll) & 0x3FF;
                int sub = sx & 7;
                int span = 8 - sub;
                if (x + span > S16_W)
                    span = S16_W - x;

                u32 pg = (pages >> ((qy | (sx >> 9)) * 4)) & 3u;
                u32 tx = (u32)(sx >> 3) & 63u;
                u16 entry = ws_rw(M->tileram, (pg * 2048u + ty * 64u + tx) * 2u);
                u32 low_code = entry & 0x0FFFu;

                if ((entry & 0x8000u) != want_bit || (!low_code && !bank_base && S.tile0_blank)) {
                    if (fill_bg0) {
                        u16 *dst = out_base + x;
                        if (span == 8 && !(x & 1)) {
                            for (int r = 0; r < chunk; r++, dst += row_step) {
                                u32 *d32 = (u32 *)dst;
                                d32[0] = bg0_pair; d32[1] = bg0_pair; d32[2] = bg0_pair; d32[3] = bg0_pair;
                            }
                        } else {
                            for (int r = 0; r < chunk; r++, dst += row_step)
                                for (int k = 0; k < span; k++)
                                    dst[k] = bg0;
                        }
                    }
                    x += span;
                    continue;
                }

                u32 code = bank_base + low_code;
                if (code >= tcnt)
                    code %= tcnt;

                const u8 *tptr = S.tiles + code * 32u + row_off0;
                const u16 *pal = S.cram_all + (((((entry >> 12) & 7u) | pal_hi) * 8u) & 0x3FFu);
                u16 *dst = out_base + x;

                if (fill_bg0) {
                    for (int k = 1; k < 16; k++)
                        bpal[k] = pal[k];
                    if (span == 8 && !(x & 1)) {
                        for (int r = 0; r < chunk; r++, tptr += 4, dst += row_step) {
                            u32 row32 = *(const u32 *)tptr;
                            u32 *d32 = (u32 *)dst;
                            if (!row32) {
                                d32[0] = bg0_pair; d32[1] = bg0_pair; d32[2] = bg0_pair; d32[3] = bg0_pair;
                            } else {
                                d32[0] = (u32)bpal[(row32 >> 4) & 15u]  | ((u32)bpal[row32 & 15u] << 16);
                                d32[1] = (u32)bpal[(row32 >> 12) & 15u] | ((u32)bpal[(row32 >> 8) & 15u] << 16);
                                d32[2] = (u32)bpal[(row32 >> 20) & 15u] | ((u32)bpal[(row32 >> 16) & 15u] << 16);
                                d32[3] = (u32)bpal[row32 >> 28]         | ((u32)bpal[(row32 >> 24) & 15u] << 16);
                            }
                        }
                    } else if (span == 8) {
                        for (int r = 0; r < chunk; r++, tptr += 4, dst += row_step) {
                            u32 row32 = *(const u32 *)tptr;
                            dst[0] = bpal[(row32 >> 4) & 15u];
                            dst[1] = bpal[row32 & 15u];
                            dst[2] = bpal[(row32 >> 12) & 15u];
                            dst[3] = bpal[(row32 >> 8) & 15u];
                            dst[4] = bpal[(row32 >> 20) & 15u];
                            dst[5] = bpal[(row32 >> 16) & 15u];
                            dst[6] = bpal[row32 >> 28];
                            dst[7] = bpal[(row32 >> 24) & 15u];
                        }
                    } else {
                        for (int r = 0; r < chunk; r++, tptr += 4, dst += row_step) {
                            for (int k = 0; k < span; k++) {
                                int s2 = sub + k;
                                u8 pair = tptr[s2 >> 1];
                                dst[k] = bpal[(s2 & 1) ? (pair & 15u) : (pair >> 4)];
                            }
                        }
                    }
                } else if (span == 8) {
                    for (int r = 0; r < chunk; r++, tptr += 4, dst += row_step) {
                        u32 row32 = *(const u32 *)tptr;
                        if (!row32)
                            continue;
                        u32 p;
                        if ((p = (row32 >> 4) & 15u) != 0u)  dst[0] = pal[p];
                        if ((p = row32 & 15u) != 0u)         dst[1] = pal[p];
                        if ((p = (row32 >> 12) & 15u) != 0u) dst[2] = pal[p];
                        if ((p = (row32 >> 8) & 15u) != 0u)  dst[3] = pal[p];
                        if ((p = (row32 >> 20) & 15u) != 0u) dst[4] = pal[p];
                        if ((p = (row32 >> 16) & 15u) != 0u) dst[5] = pal[p];
                        if ((p = row32 >> 28) != 0u)         dst[6] = pal[p];
                        if ((p = (row32 >> 24) & 15u) != 0u) dst[7] = pal[p];
                    }
                } else {
                    for (int r = 0; r < chunk; r++, tptr += 4, dst += row_step) {
                        u32 row32 = *(const u32 *)tptr;
                        if (!row32)
                            continue;
                        for (int k = 0; k < span; k++) {
                            int s2 = sub + k;
                            u8 pair = tptr[s2 >> 1];
                            u32 pen = (s2 & 1) ? (pair & 15u) : (pair >> 4);
                            if (pen)
                                dst[k] = pal[pen];
                        }
                    }
                }
                x += span;
            }
            y += chunk;
        }
        return;
    }

    for (int y = 0; y < S16_H; y++) {
        int draw_y = S.flip_screen ? (S16_H - 1 - y) : y;
        u16 *out = picture + draw_y * S16_W;
        u16 h_reg = h_reg_base;
        if (h_reg & 0x8000u) {
            u32 roff = (is_fg ? 0xF80u : 0xFC0u) + (u32)((y >> 3) & 31) * 2u;
            h_reg = ws_rw(M->textram, roff);
        }
        int hscroll = h_reg & 0x3FFu;

        for (int x = 0; x < S16_W; x++) {
            u32 coff = (is_fg ? 0xF16u : 0xF50u) + (u32)((x >> 4) & 31) * 2u;
            int vscroll = (coff < 0x1000u) ? ws_rw(M->textram, coff) : v_reg;
            int sx = (x + hscroll) & 0x3FF;
            int sy = (y + (vscroll & 0x1FF)) & 0x1FF;
            int q = ((sy >> 8) << 1) | (sx >> 9);
            u32 pg = (pages >> (q * 4)) & 3u;
            u16 entry = ws_rw(M->tileram, (pg * 2048u + ((u32)(sy >> 3) & 31u) * 64u + ((u32)(sx >> 3) & 63u)) * 2u);
            if ((entry & 0x8000u) != want_bit)
                continue;
            u32 code = bank_base + (entry & 0x0FFFu);
            if (code >= tcnt)
                code %= tcnt;
            const u8 *tptr = S.tiles + code * 32u + (u32)(sy & 7) * 4u;
            u8 pair = tptr[(sx & 7) >> 1];
            u8 pen = (sx & 1) ? (pair & 15u) : (pair >> 4);
            if (pen)
                out[x] = S.cram_all[(((((entry >> 12) & 7u) | pal_hi) * 8u) + pen) & 0x3FFu];
        }
    }
}

static void s16_draw_text_pass(u16 *picture, int want_hi)
{
    u32 tcnt = S.tile_count;
    if (!tcnt)
        return;
    int col_bias = (ws_rw(M->textram, 0x0F00u) == 0xFFFFu) ? 24 : 0;
    u16 want_bit = want_hi ? 0x8000u : 0x0000u;
    int row_step = S.flip_screen ? -S16_W : S16_W;

    for (u32 ty = 0; ty < 28u; ty++) {
        int draw_y0 = S.flip_screen ? (S16_H - 1 - (int)(ty * 8u)) : (int)(ty * 8u);
        u16 *row0 = picture + draw_y0 * S16_W;
        for (int col = 0; col < 40; col++) {
            u16 entry = ws_rw(M->textram, (ty * 64u + (u32)(col + col_bias)) * 2u);
            if (!entry || (entry & 0x8000u) != want_bit)
                continue;
            u32 code = entry & 0x01FFu;
            if (!code && S.tile0_blank)
                continue;
            if (code >= tcnt)
                code %= tcnt;
            const u8 *tbase = S.tiles + code * 32u;
            const u16 *pal = S.cram_all + ((((entry >> 9) & 15u) * 8u) & 0x3FFu);
            u16 *dst = row0 + col * 8;
            for (int ry = 0; ry < 8; ry++, tbase += 4, dst += row_step) {
                u32 row32 = *(const u32 *)tbase;
                if (!row32)
                    continue;
                u32 p;
                if ((p = (row32 >> 4) & 15u) != 0u)  dst[0] = pal[p];
                if ((p = row32 & 15u) != 0u)         dst[1] = pal[p];
                if ((p = (row32 >> 12) & 15u) != 0u) dst[2] = pal[p];
                if ((p = (row32 >> 8) & 15u) != 0u)  dst[3] = pal[p];
                if ((p = (row32 >> 20) & 15u) != 0u) dst[4] = pal[p];
                if ((p = (row32 >> 16) & 15u) != 0u) dst[5] = pal[p];
                if ((p = row32 >> 28) != 0u)         dst[6] = pal[p];
                if ((p = (row32 >> 24) & 15u) != 0u) dst[7] = pal[p];
            }
        }
    }
}

struct s16_spr_act {
    s16 top, bot, xpos;
    u16 out_w, vz, hz, pal;
    u32 base_w, pitch_w, src_px_w, total_src_h;
    u8  pri_idx, sh_mode, hflip, vflip;
};

static int s16_collect_sprites(struct s16_spr_act *act)
{
    u32 sw_cnt = S.spr_words;
    if (!sw_cnt)
        return 0;
    int n = 0;
    for (int i = 0; i < 128; i++) {
        u32 sb = (u32)i * 16u;
        u16 w2 = ws_rw(M->sprram, sb + 4u);
        if (w2 & 0x8000u)
            break;
        if (w2 & 0x4000u)
            continue;
        u16 w0 = ws_rw(M->sprram, sb + 0u);
        int top = w0 & 0xFF;
        int bot = (w0 >> 8) & 0xFF;
        if (bot <= top || bot <= 0 || top >= S16_H)
            continue;

        u32 pitch_w = ((w2 >> 8) & 15u) + 1u;
        u32 bank = w2 & 15u;
        u32 base_w = (bank << 16) | ws_rw(M->sprram, sb + 6u);
        if (base_w >= sw_cnt)
            base_w %= sw_cnt;

        u16 w4 = ws_rw(M->sprram, sb + 8u);
        u16 w6 = ws_rw(M->sprram, sb + 12u);
        u32 vz = w4 ? w4 : 0x0400u;
        u32 hz = w6 ? w6 : vz;
        u32 src_px_w = pitch_w * 4u;
        u32 out_w = (hz == 0x0400u) ? src_px_w : ((src_px_w << 10) / (hz ? hz : 1u));
        if (out_w > 512u) out_w = 512u;

        int xpos = (s16)ws_rw(M->sprram, sb + 2u);
        if (xpos >= S16_W || xpos + (int)out_w <= 0)
            continue;

        u16 w5 = ws_rw(M->sprram, sb + 10u);
        struct s16_spr_act *s = &act[n++];
        s->top = (s16)top;
        s->bot = (s16)bot;
        s->xpos = (s16)xpos;
        s->out_w = (u16)out_w;
        s->vz = (u16)vz;
        s->hz = (u16)hz;
        s->pal = (u16)(0x400u + ((u32)(w5 & 0x3Fu) << 4));
        s->base_w = base_w;
        s->pitch_w = pitch_w;
        s->src_px_w = src_px_w;
        s->total_src_h = (((u32)(bot - top) * vz) + 0x3FFu) >> 10;
        s->pri_idx = (u8)((w5 >> 14) & 3u);
        s->sh_mode = (u8)((w5 >> 12) & 3u);
        s->hflip = (w2 & 0x2000u) ? 1 : 0;
        s->vflip = (w2 & 0x1000u) ? 1 : 0;
    }
    return n;
}

static void s16_draw_sprite_bucket(u16 *picture, const struct s16_spr_act *act, int n_act, u8 pri_min, u8 pri_max)
{
    u32 sw_cnt = S.spr_words;
    const u16 *spr_words = (const u16 *)S.sprites;

    for (int i = 0; i < n_act; i++) {
        const struct s16_spr_act *s = &act[i];
        if (s->pri_idx < pri_min || s->pri_idx > pri_max)
            continue;

        int y0 = s->top < 0 ? 0 : s->top;
        int y1 = s->bot > S16_H ? S16_H : s->bot;
        u32 dx0 = 0, dx1 = s->out_w;
        u32 hz = s->hz;
        u32 sx_fp0 = 0;
        if (s->xpos < 0) {
            dx0 = (u32)(-s->xpos);
            sx_fp0 = dx0 * hz;
        }
        if (s->xpos + (int)dx1 > S16_W)
            dx1 = (u32)(S16_W - s->xpos);
        if (dx0 >= dx1)
            continue;

        const u16 *pal = S.cram_all + s->pal;
        u8 sh_mode = s->sh_mode;
        u32 src_px_w = s->src_px_w;
        u32 pitch_w = s->pitch_w;
        int hflip = s->hflip;

        for (int y = y0; y < y1; y++) {
            int draw_y = S.flip_screen ? (S16_H - 1 - y) : y;
            u16 *dst_base = picture + draw_y * S16_W + s->xpos;
            u32 dy = (u32)(y - s->top);
            u32 sy = (dy * s->vz) >> 10;
            if (s->vflip && s->total_src_h > 0)
                sy = (sy < s->total_src_h) ? (s->total_src_h - 1u - sy) : 0u;
            u32 row_w = s->base_w + sy * pitch_w;
            if (row_w >= sw_cnt)
                row_w %= sw_cnt;

            u32 sx_fp = sx_fp0;
            if (row_w + pitch_w <= sw_cnt && sh_mode == 0u && !hflip) {
                const u16 *srow = spr_words + row_w;
                for (u32 dx = dx0; dx < dx1; dx++, sx_fp += hz) {
                    u32 sx = sx_fp >> 10;
                    if (sx >= src_px_w)
                        break;
                    u16 sw = srow[sx >> 2];
                    u32 pen = (sw >> ((3u - (sx & 3u)) << 2)) & 15u;
                    if (pen != 0u && pen != 15u)
                        dst_base[dx] = pal[pen];
                }
                continue;
            }

            for (u32 dx = dx0; dx < dx1; dx++, sx_fp += hz) {
                u32 sx = sx_fp >> 10;
                if (sx >= src_px_w)
                    break;
                if (hflip)
                    sx = src_px_w - 1u - sx;
                u32 wi = row_w + (sx >> 2);
                if (wi >= sw_cnt)
                    wi %= sw_cnt;
                u16 sw = spr_words[wi];
                u32 pen = (sw >> ((3u - (sx & 3u)) << 2)) & 15u;
                if (pen == 0u || pen == 15u)
                    continue;

                if (sh_mode == 0u) {
                    dst_base[dx] = pal[pen];
                } else if (sh_mode == 2u || (sh_mode == 1u && pen == 14u)) {
                    dst_base[dx] = (u16)((dst_base[dx] >> 1) & 0x3DEFu);
                } else if (sh_mode == 3u && pen == 14u) {
                    u32 px = dst_base[dx];
                    u32 r = px & 31u, g = (px >> 5) & 31u, b = (px >> 10) & 31u;
                    dst_base[dx] = (u16)((r + ((31u - r) >> 1)) | ((g + ((31u - g) >> 1)) << 5) | ((b + ((31u - b) >> 1)) << 10));
                } else {
                    dst_base[dx] = pal[pen];
                }
            }
        }
    }
}

static void s16_render_frame(u16 *picture)
{
    if (!picture)
        return;
    if (!S.vid_enable) {
        u16 bg = S.cram_all[0];
        for (int i = 0; i < S16_W * S16_H; i++)
            picture[i] = bg;
        return;
    }

    struct s16_spr_act act[128];
    int n_act = s16_collect_sprites(act);
    u32 tcnt = S.tile_count;
    u32 bg_bank_base = tcnt ? (((u32)(S.tilebank[0] & 15u) << 12) % tcnt) : 0u;
    u32 fg_bank_base = tcnt ? (((u32)(S.tilebank[1] & 15u) << 12) % tcnt) : 0u;
    int bg_fills_backdrop = !(S.flags & 16u) && tcnt > 0 && !(ws_rw(M->textram, 0xF18u) & 0x8000u);

    /* Hardware Painter's Priority Composition:
       0. Backdrop / OutRun Road (merged into BG low when no road or BG colscroll)
       1. BG low  (pri 1) -> Sprites pri 0 (1)
       2. FG low  (pri 2) -> Text low (3) -> Sprites pri 1 (3)
       3. BG high (pri 4) -> FG high  (5) -> Sprites pri 2..3 (5..6)
       4. Text high (pri 7) */
    if (!bg_fills_backdrop)
        s16_render_road_frame(picture);
    s16_draw_scroll_pass(picture, 0, 0, bg_bank_base, bg_fills_backdrop);
    if (n_act > 0) s16_draw_sprite_bucket(picture, act, n_act, 0, 0);
    s16_draw_scroll_pass(picture, 1, 0, fg_bank_base, 0);
    s16_draw_text_pass(picture, 0);
    if (n_act > 0) s16_draw_sprite_bucket(picture, act, n_act, 1, 1);
    s16_draw_scroll_pass(picture, 0, 1, bg_bank_base, 0);
    s16_draw_scroll_pass(picture, 1, 1, fg_bank_base, 0);
    if (n_act > 0) s16_draw_sprite_bucket(picture, act, n_act, 2, 3);
    s16_draw_text_pass(picture, 1);
}

/* ---- Graphics Decoders & Cartridge / MAME .zip Loaders ---- */
static void decode_3plane_tiles(const u8 *src, u32 tile_bytes, int pre_4bpp)
{
    if (!tile_bytes) {
        S.tile_count = 0;
        return;
    }
    if (pre_4bpp) {
        u32 cap = tile_bytes < TILES_CAP ? tile_bytes : TILES_CAP;
        for (u32 i = 0; i < cap; i++)
            TILES_BUF[i] = src[i];
        S.tiles = TILES_BUF;
        S.tile_count = cap / 32u;
        S.tile0_blank = 1;
        if (S.tile_count > 0) {
            for (u32 i = 0; i < 32u; i++)
                if (TILES_BUF[i]) { S.tile0_blank = 0; break; }
        }
        return;
    }

    /* Standard Sega System 16 3-plane 8x8 tiles: 3 equal planar regions (p0, p1, p2), 8 bytes/tile/plane */
    u32 plane_sz = tile_bytes / 3u;
    u32 n_tiles = plane_sz / 8u;
    if (n_tiles * 32u > TILES_CAP)
        n_tiles = TILES_CAP / 32u;
    const u8 *p0 = src;
    const u8 *p1 = src + plane_sz;
    const u8 *p2 = src + plane_sz * 2u;

    for (u32 t = 0; t < n_tiles; t++) {
        u8 *dst = TILES_BUF + t * 32u;
        for (u32 r = 0; r < 8u; r++) {
            u8 b0 = p0[t * 8u + r];
            u8 b1 = p1[t * 8u + r];
            u8 b2 = p2[t * 8u + r];
            for (u32 px = 0; px < 8u; px += 2u) {
                u32 sh0 = 7u - px, sh1 = 6u - px;
                u8 c_hi = (u8)((((b0 >> sh0) & 1u) << 0) | (((b1 >> sh0) & 1u) << 1) | (((b2 >> sh0) & 1u) << 2));
                u8 c_lo = (u8)((((b0 >> sh1) & 1u) << 0) | (((b1 >> sh1) & 1u) << 1) | (((b2 >> sh1) & 1u) << 2));
                *dst++ = (u8)((c_hi << 4) | c_lo);
            }
        }
    }
    S.tiles = TILES_BUF;
    S.tile_count = n_tiles;
    S.tile0_blank = 1;
    if (n_tiles > 0) {
        for (u32 i = 0; i < 32u; i++)
            if (TILES_BUF[i]) { S.tile0_blank = 0; break; }
    }
}

static u32 get_le32(const u8 *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

int s16_is_zip(const u8 *zip, u32 size)
{
    if (!zip_is(zip, size))
        return 0;
    u32 cnt = zip_count(zip, size);
    if (!cnt || cnt > 64u)
        return 0;
    for (u32 i = 0; i < cnt; i++) {
        char nm[64];
        u32 msz = 0;
        if (zip_unpack_at(zip, size, i, 0, 0, &msz, nm, sizeof(nm)) != 0)
            continue;
        /* Check for .s16 inside .zip OR Sega EPR-/OPR-/MPR- MAME ROM naming! */
        int n = 0;
        while (nm[n]) n++;
        if (n >= 4 && nm[n-4]=='.' && (nm[n-3]|32)=='s' && nm[n-2]=='1' && nm[n-1]=='6')
            return 1;
        if ((nm[0]|32)=='e' && (nm[1]|32)=='p' && (nm[2]|32)=='r' && nm[3]=='-')
            return 1;
        if ((nm[0]|32)=='o' && (nm[1]|32)=='p' && (nm[2]|32)=='r' && nm[3]=='-')
            return 1;
    }
    return 0;
}

static const char *s16_load_s16_blob(const u8 *img, u32 size)
{
    if (size < 256u)
        return "too small for a Sega System 16 (.s16) image";
    if (!(img[0] == 'S' && img[1] == '1' && img[2] == '6' &&
          (img[3] == 'A' || img[3] == 'B' || img[3] == 'R')))
        return "not a Sega System 16 cartridge (expected S16A / S16B / S16R header)";

    S.board_type = (img[3] == 'A') ? 0 : (img[3] == 'R') ? 2 : 1;
    S.flags      = get_le32(img + 0x04);
    u32 p_sz     = get_le32(img + 0x08);
    u32 c_sz     = get_le32(img + 0x0C);
    u32 z_sz     = get_le32(img + 0x10);
    u32 pcm_sz   = get_le32(img + 0x14);
    u32 tile_sz  = get_le32(img + 0x18);
    u32 spr_sz   = get_le32(img + 0x1C);
    S.dip1       = img[0x20] ? img[0x20] : 0xFFu;
    S.dip2       = img[0x21] ? img[0x21] : 0xFFu;
    S.hw_cfg     = img[0x22];
    u8 zmhz      = img[0x23] ? img[0x23] : 5u;

    u32 total = 256u + p_sz + c_sz + z_sz + pcm_sz + tile_sz + spr_sz;
    if (total > size || p_sz < 64u || p_sz > ROM_CAP)
        return "corrupt or truncated .s16 section sizes";

    u32 pos = 256u;
    /* 1. 68000 Program ROM (word-swap big-endian 68000 words into host u16) */
    S.rom = ROM_BUF;
    S.rom_len = (p_sz + 1u) & ~1u;
    for (u32 i = 0; i < p_sz; i += 2u) {
        u16 w = (u16)(((u16)img[pos + i] << 8) | (i + 1u < p_sz ? img[pos + i + 1u] : 0));
        ws_ww(S.rom, i, w);
    }
    pos += p_sz;

    /* 2. Optional Decrypted 68000 Opcode ROM (FD1089 / FD1094) */
    if (c_sz > 0 && c_sz <= CODE_CAP) {
        S.code = CODE_BUF;
        S.code_len = (c_sz + 1u) & ~1u;
        for (u32 i = 0; i < c_sz; i += 2u) {
            u16 w = (u16)(((u16)img[pos + i] << 8) | (i + 1u < c_sz ? img[pos + i + 1u] : 0));
            ws_ww(S.code, i, w);
        }
    } else {
        S.code = 0;
        S.code_len = 0;
    }
    pos += c_sz;

    /* 3. Z80 Sound ROM */
    S.zrom_len = z_sz < ZROM_CAP ? z_sz : ZROM_CAP;
    S.zrom = S.zrom_len ? ZROM_BUF : 0;
    for (u32 i = 0; i < S.zrom_len; i++)
        ZROM_BUF[i] = img[pos + i];
    pos += z_sz;

    /* 4. uPD7759 / Sega PCM Sample ROM */
    S.pcm_len = pcm_sz < PCM_CAP ? pcm_sz : PCM_CAP;
    S.pcm = S.pcm_len ? PCM_BUF : 0;
    for (u32 i = 0; i < S.pcm_len; i++)
        PCM_BUF[i] = img[pos + i];
    pos += pcm_sz;

    /* 5. 315-5197 8x8 Tile ROM */
    decode_3plane_tiles(img + pos, tile_sz, (S.flags & 8u) != 0);
    pos += tile_sz;

    /* 6. 16-bit Sprite ROM (word-swapped into SPR_BUF) */
    u32 scopy = spr_sz < SPR_CAP ? spr_sz : SPR_CAP;
    S.sprites = SPR_BUF;
    S.spr_words = scopy >> 1;
    for (u32 i = 0; i + 1u < scopy; i += 2u) {
        u16 w = (u16)(((u16)img[pos + i] << 8) | img[pos + i + 1u]);
        ws_ww(SPR_BUF, i, w);
    }

    S.m68k_hz = (S.board_type == 2) ? 12500000u : 10000000u;
    S.z80_hz  = (u32)zmhz * 1000000u;
    S.cyc_per_frame  = (s32)(S.m68k_hz / 60u);
    S.zcyc_per_frame = (s32)(S.z80_hz / 60u);

    /* Format info string */
    char *p = info_buf;
    const char *pre = (S.board_type == 0) ? "Sega System 16A: " :
                      (S.board_type == 2) ? "Sega OutRun/S16R: " : "Sega System 16B: ";
    while (*pre) *p++ = *pre++;
    const char *title = (const char *)(img + 0x40);
    if (title[0]) {
        for (int i = 0; i < 56 && title[i] && p < info_buf + sizeof(info_buf) - 1; i++)
            *p++ = title[i];
    } else {
        const char *u = "Arcade Cartridge";
        while (*u) *p++ = *u++;
    }
    *p = 0;
    return 0;
}

const char *s16_load(u8 *rom, u32 size, const char *path)
{
    (void)path;
    if (!rom || size < 64u)
        return "empty or invalid Sega System 16 file";

    u8 was_inited = S.cpu_inited;
    for (u32 i = 0; i < sizeof(S); i++)
        ((u8 *)&S)[i] = 0;
    S.cpu_inited = was_inited;
    if (!S.cpu_inited) {
        cpu_init();
        S.cpu_inited = 1;
    }

    if (zip_is(rom, size)) {
        char member_name[64];
        u32 unpacked_sz = 0;
        const char *zerr = zip_unpack(rom, size, ".s16", SCRATCH_BUF, SCRATCH_CAP, &unpacked_sz,
                                      member_name, sizeof(member_name));
        if (!zerr && unpacked_sz >= 256u && SCRATCH_BUF[0] == 'S' && SCRATCH_BUF[1] == '1' && SCRATCH_BUF[2] == '6') {
            const char *err = s16_load_s16_blob(SCRATCH_BUF, unpacked_sz);
            if (!err)
                s16_reset();
            return err;
        }
        return "MAME System 16 .zip has no .s16 image inside (pack with tools/s16_pack.py first)";
    }

    const char *err = s16_load_s16_blob(rom, size);
    if (err)
        return err;

    s16_reset();
    return 0;
}

void s16_reset(void)
{
    for (u32 i = 0; i < sizeof(*M); i++)
        ((u8 *)M)[i] = 0;

    for (int i = 0; i < 32; i++)
        S.mapper_regs[i] = 0;
    S.mapper_active = 0;
    S.vid_enable = 1;
    S.flip_screen = 0;
    S.tilebank[0] = 0;
    S.tilebank[1] = 1;
    S.snd_latch = 0;
    S.snd_pending = 0;
    S.vbl_irq = 0;

    for (int i = 0; i < 0x1800; i++)
        S.cram_all[i] = 0;

    s16_rebuild_68k_map();
    m.clock = 0;
    cpu_reset();

    /* Init Z80 Sound CPU + YM2151 + uPD7759 + Sega PCM */
    z80_init(&S.z);
    S.z.read  = s16_z80_rd;
    S.z.write = s16_z80_wr;
    S.z.in    = s16_z80_in;
    S.z.out   = s16_z80_out;
    S.z.trap  = -1;
    for (int i = 0; i < 56; i++) {
        u32 off = (u32)i * 0x400u;
        if (S.zrom && off + 0x400u <= S.zrom_len)
            S.z.rd[i] = S.zrom + off;
    }
    S.z.rd[62] = M->zram;       S.z.wr[62] = M->zram;
    S.z.rd[63] = M->zram + 0x400; S.z.wr[63] = M->zram + 0x400;
    z80_reset(&S.z);

    for (u32 i = 0; i < sizeof(S.opm); i++)
        ((u8 *)&S.opm)[i] = 0;
    S.opm.lfsr = 1u;
    for (int ch = 0; ch < 8; ch++) {
        S.opm.ch[ch].rl = 3u;
        S.opm.ch[ch].quiet = 1;
        for (int n = 0; n < 4; n++) {
            S.opm.ch[ch].op[n].att = 0x3FF;
            S.opm.ch[ch].op[n].env = 0x3FFu;
            S.opm.ch[ch].op[n].state = EG_REL;
        }
    }

    for (u32 i = 0; i < sizeof(S.upd); i++)
        ((u8 *)&S.upd)[i] = 0;
    S.upd.start_n = 0xC0u;

    for (int ch = 0; ch < 16; ch++) {
        S.pcm_ch[ch].active = 0;
        M->pcm_regs[0x86 + ch * 8] = 1u;
    }
}

static void s16_sync_z80(s32 z_target)
{
    if (!S.zrom_len || z_target <= S.z.cycles)
        return;
    s32 z_delta = z_target - S.z.cycles;
    /* Fast-forward tight JR * (18 FE) idle loops when no NMI or unmasked IRQ is pending */
    if (!S.z.nmi && !(S.z.irq && S.z.iff1)) {
        u16 pc = S.z.pc.w;
        const u8 *p = S.z.rd[pc >> 10];
        if (p && (pc & 0x3FFu) < 0x3FFu && p[pc & 0x3FFu] == 0x18u && p[(pc + 1u) & 0x3FFu] == 0xFEu)
            S.z.cycles = z_target;
    }
    if (S.z.cycles < z_target)
        z80_run(&S.z, z_target);
    if (S.opm.timer_ctrl & 1u) {
        S.opm.ta_cnt -= z_delta;
        while (S.opm.ta_cnt <= 0) {
            S.opm.ta_cnt += opm_ta_zcyc();
            if (S.opm.timer_ctrl & 4u) { S.opm.status |= 1u; opm_update_irq(); }
        }
    }
    if (S.opm.timer_ctrl & 2u) {
        S.opm.tb_cnt -= z_delta;
        while (S.opm.tb_cnt <= 0) {
            S.opm.tb_cnt += opm_tb_zcyc();
            if (S.opm.timer_ctrl & 8u) { S.opm.status |= 2u; opm_update_irq(); }
        }
    }
}

void s16_frame(u16 pad, u16 *picture)
{
    S.pad_p1 = pad;
    S.audio_count = 0;
    S.rendered_samples = 0;

    s32 m_per_line = S.cyc_per_frame / TOTAL_LINES;
    s32 m_act = VIS_LINES * m_per_line;
    s32 m_tot = TOTAL_LINES * m_per_line;

    /* Run active display in 4 slices so sound commands & YM2151 timers interleave smoothly */
    for (int s = 1; s <= 4; s++) {
        S.slice_end_cyc = (m_act * s) >> 2;
        cpu_run(S.slice_end_cyc);
        s16_sync_z80(((S.zcyc_per_frame * VIS_LINES / TOTAL_LINES) * s) >> 2);
    }

    s16_render_frame(picture);

    S.vbl_irq = 1;
    m.ipl = 4u;
    check_pending();

    S.slice_end_cyc = m_tot;
    cpu_run(m_tot);
    s16_sync_z80(S.zcyc_per_frame);

    if (S.sample_rate)
        s16_render_samples(S.sample_rate / 60u);

    m.clock -= m_tot;
    if (S.zrom_len)
        S.z.cycles -= S.zcyc_per_frame;
}

const char *s16_info(void) { return info_buf; }

u8 *s16_save_ram(u32 *size, int *battery)
{
    *size = 0x4000u;
    *battery = 1;
    return M->wram + 0xC000u;
}

int s16_save_changed(void)
{
    int d = S.nvram_dirty;
    S.nvram_dirty = 0;
    for (u32 i = 0; i < 0x4000u; i++) {
        if (M->nvram_sav[i] != M->wram[0xC000u + i]) {
            M->nvram_sav[i] = M->wram[0xC000u + i];
            d = 1;
        }
    }
    return d;
}

int s16_jammed(void)
{
    return m.stopped && m.im == 7;
}

void s16_audio_rate(u32 hz)
{
    S.sample_rate = hz;
    S.rendered_samples = 0;
    S.audio_count = 0;
}

int s16_audio(s16 *out, int max)
{
    int n = S.audio_count < max ? S.audio_count : max;
    for (int i = 0; i < n; i++)
        out[i] = M->audio_ring[i];
    S.audio_count = 0;
    return n;
}
