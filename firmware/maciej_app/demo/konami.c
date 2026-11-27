/* Konami Classic Arcade Multi-Board Emulator: see konami.h.
   Zero static .bss (all CPUs, optab, RAM, ASICs, palettes & audio ring live in
   EMU_RAM_PHYS; unpacked ROMs & pre-decoded tiles/sprites in upper EMU_RAM_PHYS,
   0x05800000 & IMAGE_WORK_PHYS). */
#include "konami.h"
#include "z80.h"
#include "zip.h"
#include "font5x7.h"

#ifndef KONAMI_HOST
#include "hw.h"
#endif

#define INLINE static inline __attribute__((always_inline))

enum {
    KON_BOARD_SSRIDERS = 0,     /* 68000 + Z80 + K052109 + K053245 + K053251 + YM2151 + K053260 */
    KON_BOARD_TMNT     = 1,     /* 68000 + Z80 + K052109 + K051960 + YM2151 + K007232 */
    KON_BOARD_NEMESIS  = 2,     /* 68000 + Z80 + GX400 dynamic charram + dual AY-3-8910 + K005289 */
    KON_BOARD_CONTRA   = 3      /* MC6809E/Konami-1 + Z80 + dual K007121 + YM2151 */
};

enum {
    KON_SUB_GENERIC  = 0,
    KON_SUB_SSRIDERS = 1,
    KON_SUB_TMNT2    = 2,
    KON_SUB_XMEN     = 3,
    KON_SUB_TMNT     = 4,
    KON_SUB_MIA      = 5,
    KON_SUB_NEMESIS  = 6,
    KON_SUB_CONTRA   = 7
};

#define KON_SND_RING    8192
#define KON_MAX_TILES   131072u         /* 131,072 8x8 4bpp tiles (4 MB pre-decoded u32x8) */
#define KON_MAX_SPR16   65536u          /* 65,536 16x16 4bpp cells (8 MB nibble-packed 128 B/cell) */
#define KON_ROM_CAP     0x00400000u     /* 4 MB 68000 / 6809 Program ROM */
#define KON_ZROM_CAP    0x00040000u     /* 256 KB Z80 Sound ROM */
#define KON_PCM_CAP     0x00800000u     /* 8 MB K053260 / K007232 PCM ROM */
#define KON_STAGE_CAP   0x00580000u     /* 5.5 MB .zip unpack staging */

#pragma GCC push_options
#pragma GCC optimize("O2")
#include "ym2151.inc"
#pragma GCC pop_options

/* K053260 (KDSC) 4-channel PCM / 4-bit Konami ADPCM voice */
struct k053260_ch {
    u32 start;
    u16 length;
    u16 pitch;
    u8  vol;
    u8  pan;
    u8  playing, loop, kadpcm, reverse;
    u32 pos_frac;       /* 12-bit fractional step */
    u32 idx;            /* byte or nibble index */
    s16 adpcm_acc;
};

/* K007232 dual-channel PCM voice (TMNT / MIA) */
struct k007232_ch {
    u32 start, addr_frac;
    u16 step;
    u8  vol_l, vol_r, playing, loop;
};

/* AY-3-8910 PSG state (Nemesis / GX400) */
struct kon_ay {
    u8  sel, regs[16], out[3];
    u32 cnt[3], ncnt, lfsr, env_cnt;
    u8  env_vol;
};

struct konami_state {
    u8  board, sub;
    u8  konami1_enc;            /* 1 if Contra variant uses Konami-1 opcode XOR */
    u8  jammed, nvram_dirty;
    int scr_w, scr_h;
    u16 pad1, pad2;
    u8  coin_prev, coin_pulse;
    u32 rom_size, zrom_size, pcm_size, pcm_mask;
    u32 tile_count, spr16_count;
    u32 tile_mask, spr16_mask;
    u32 frame_no;
    u8  act_spr[128];
    int n_act_spr;

    /* Interrupt & latch state */
    u8  vblank_irq_en, sound_irq_pending;
    u8  snd_latch;
    u8  contra_bank;
    u8  tmnt_romsubbank;

    /* K052109 state */
    u8  k2109_scrollctrl;       /* $1C80 */
    u8  k2109_irq_en;           /* $1D00: bit 2 = VBlank IRQ */
    u8  k2109_rombank[4];       /* $1D80 / $1F00 */
    u8  k2109_flip;             /* $1E80 */

    /* K051937 / K051960 & K053244 / K053245 sprite state */
    u8  k1937_regs[8];
    u16 k3244_regs[8];
    s16 spr_dx, spr_dy;
    u8  spr_bank;

    /* K053251 PCU1 priority encoder (16 registers) */
    u8  pcu_regs[16];
    u8  pal_base_f, pal_base_a, pal_base_b, pal_base_spr;
    u8  pri_f, pri_a, pri_b;

    /* Audio: 3.579545 MHz Z80 + YM2151 + K053260 + K007232 + dual AY */
    u32 sample_rate;
    u32 snd_head, snd_tail;
    u8  k3260_regs[64];
    u8  k3260_mail_m2s[2];
    u8  k3260_mail_s2m[2];
    struct k053260_ch k3260[4];
    u8  k7232_regs[16];
    u8  k7232_sle;
    struct k007232_ch k7232[2];
    struct kon_ay ay[2];

    char info[96];
};

#pragma GCC optimize("O2")

static __attribute__((noinline)) u8 kon_m6809_rb(void *ctx, u16 a);
static __attribute__((noinline)) void kon_m6809_wb(void *ctx, u16 a, u8 v);
static __attribute__((noinline)) u8 kon_m6809_op(void *ctx, u16 a);
#define M6809_RB(ctx, a)        kon_m6809_rb(ctx, a)
#define M6809_WB(ctx, a, v)     kon_m6809_wb(ctx, a, v)
#define M6809_OP(ctx, a)        kon_m6809_op(ctx, a)
#include "m6809.inc"

static void kon_iack(u32 level);
#define M68K_IACK(level) kon_iack(level)

#define M68K_EXTERNAL_STATE                                                     \
    struct konami_mem {                                                         \
        struct konami_state st;                                                 \
        struct m68k m_cpu;                                                      \
        u8 *m_rmap[256];                                                        \
        u8 *m_wmap[256];                                                        \
        u8  m_optab[65536];                                                     \
        struct m6809 cpu09;                                                     \
        struct z80 zcpu;                                                        \
        struct ym2151 opm;                                                      \
        u8  wram[0x20000];              /* 128 KB 68000 Work RAM (word-swap) */ \
        u8  k2109_ram[0x8000];          /* 32 KB K052109 Color/Code/Scroll */   \
        u32 k2109_cell[3 * 2048];       /* Contiguous packed (code12<<8)|attr */\
        u8  spr_ram[0x2000];            /* 8 KB K051960/K053245/GX400 Obj */    \
        u8  pal_ram[0x2000];            /* 8 KB raw BE Palette RAM (4096w) */   \
        u16 pal15[4096];                /* Preconverted 0BBBBBGGGGGRRRRR */     \
        u16 pal15_shd[4096];            /* 50% darkened shadow LUT */           \
        u8  gx_charram[0x10000];        /* 64 KB GX400 dynamic charram (BE) */  \
        u32 gx_tiles[2048 * 8];         /* Live-decoded GX400 8x8 4bpp rows */  \
        u8  gx_tile_nz[2048];           /* Non-zero pen mask per GX400 tile */  \
        u8  gx_vram[0x6000];            /* GX400 vram1/2 + color1/2 + scroll */ \
        u8  k7121_ram[2][0x2000];       /* Contra dual K007121 8 KB VRAMs */    \
        u8  k7121_ctrl[2][8];           /* Contra dual K007121 ctrl regs */     \
        u8  contra_ram[0x4000];         /* Contra 6809 work RAM */              \
        u8  zram[0x2000];               /* 8 KB Z80 Sound RAM */                \
        u8  nvram[0x0800];              /* 2 KB EEPROM / NVRAM (.sav) */        \
        u8  tile_nz[KON_MAX_TILES];     /* 1 if tile has any non-zero pen */    \
        u8  spr_nz[KON_MAX_SPR16];      /* 1 if 16x16 sprite cell non-empty */  \
        u16 line_col[KONAMI_W_MAX];                                             \
        u8  line_pri[KONAMI_W_MAX] __attribute__((aligned(4)));                 \
        u8  line_shd[KONAMI_W_MAX] __attribute__((aligned(4)));                 \
        s16 snd_ring[KON_SND_RING];                                             \
    };                                                                          \
    KON_MEM_BIND

#ifdef KONAMI_HOST
#define KON_MEM_BIND static struct konami_mem kon_host_mem;
static u32 kon_host_tiles[KON_MAX_TILES * 8u];
static u8  kon_host_spr[KON_MAX_SPR16 * 128u];
static u8  kon_host_rom[KON_ROM_CAP];
static u8  kon_host_zrom[KON_ZROM_CAP];
static u8  kon_host_pcm[KON_PCM_CAP];
static u8  kon_host_stage[KON_STAGE_CAP];
#define M           (&kon_host_mem)
#define TILE_BUF    kon_host_tiles
#define SPR_BUF     kon_host_spr
#define ROM_BUF     kon_host_rom
#define ZROM_BUF    kon_host_zrom
#define PCM_BUF     kon_host_pcm
#define ZIP_STAGE   kon_host_stage
#define KON_POLL()  ((void)0)
#else
#define KON_MEM_BIND
/* Physical layout during konami_play:
   0x03400000..0x0357FFFF (1.5 MB) : struct konami_mem M (~980 KB)
   0x03580000..0x0397FFFF (4.0 MB) : TILE_BUF (131,072 x 32 B pre-decoded 8x8 tiles)
   0x05800000..0x05BFFFFF (4.0 MB) : ROM_BUF  (68000 / 6809 program ROM)
   0x06900000..0x0693FFFF (256 KB) : ZROM_BUF (Z80 sound ROM)
   0x06940000..0x0713FFFF (8.0 MB) : PCM_BUF  (K053260 / K007232 PCM samples)
   0x07140000..0x0793FFFF (8.0 MB) : SPR_BUF  (65,536 x 128 B pre-decoded 16x16 sprites)
   0x07940000..0x07EBFFFF (5.5 MB) : ZIP_STAGE (MAME .zip unpack scratch) */
#define M           ((struct konami_mem *)KSEG0(EMU_RAM_PHYS))
#define TILE_BUF    ((u32 *)KSEG0(0x03580000u))
#define ROM_BUF     ((u8 *)KSEG0(0x05800000u))
#define ZROM_BUF    ((u8 *)KSEG0(0x06900000u))
#define PCM_BUF     ((u8 *)KSEG0(0x06940000u))
#define SPR_BUF     ((u8 *)KSEG0(0x07140000u))
#define ZIP_STAGE   ((u8 *)KSEG0(0x07940000u))
#define KON_POLL()  ((void)now_ms())
#endif

#define S     (M->st)
#define m     (M->m_cpu)
#define rmap  (M->m_rmap)
#define wmap  (M->m_wmap)
#define optab (M->m_optab)

#include "m68k.inc"
#pragma GCC optimize("O2")

#ifndef KONAMI_HOST
_Static_assert(sizeof(struct konami_mem) <= 0x00180000u, "konami_mem exceeds 1.5 MB slot");
#endif

static void kon_zero(void *p, u32 n)
{
    u8 *b = (u8 *)p;
    for (u32 i = 0; i < n; i++)
        b[i] = 0;
}

static int kon_ci_has(const char *s, const char *sub)
{
    if (!s) return 0;
    for (; *s; s++) {
        const char *p = s, *q = sub;
        while (*p && *q && ((*p | 32) == (*q | 32))) {
            p++;
            q++;
        }
        if (!*q) return 1;
    }
    return 0;
}

static const char *kon_basename(const char *p)
{
    if (!p) return "";
    const char *b = p;
    for (; *p; p++)
        if (*p == '/' || *p == '\\' || *p == ':')
            b = p + 1;
    return b;
}

static int kon_starts_ci(const char *s, const char *pre)
{
    while (*pre) {
        if ((*s | 32) != (*pre | 32))
            return 0;
        s++;
        pre++;
    }
    return 1;
}

/* ---- Palette Conversion (Konami xBBBBBGGGGGRRRRR -> S3811 0BBBBBGGGGGRRRRR) ---- */
INLINE void kon_update_pal_entry(u32 idx)
{
    idx &= 0xFFFu;
    u16 raw = ((u16)M->pal_ram[idx * 2u] << 8) | M->pal_ram[idx * 2u + 1u];
    u16 c15 = raw & 0x7FFFu; /* Konami arcade RGB555 already matches 0BBBBBGGGGGRRRRR! */
    M->pal15[idx] = c15;
    M->pal15_shd[idx] = (c15 >> 1) & 0x3DEFu; /* 50% brightness per channel for shadow pen */
}

static void kon_update_pcu_bases(void)
{
    /* K053251 PCU1 registers:
       reg 9  = Layer F (CI0) palette base (in 16-color banks)
       reg 10 = Sprite (CI1) palette base (in 16-color banks)
       reg 11 = Layer A/B palette bases
       regs 0..2 = Layer F/A/B priority codes (0..63, lower = further back or front per Konami convention:
       in K053251, HIGHER 6-bit value is closer to viewer / higher priority, or in TMNT2/Sunset Riders:
       reg 0 = CI0/F pri, reg 1 = CI3/A pri, reg 2 = CI4/B pri) */
    if (S.board == KON_BOARD_SSRIDERS) {
        S.pri_f = S.pcu_regs[0] & 0x3Fu;
        S.pri_a = S.pcu_regs[1] & 0x3Fu;
        S.pri_b = S.pcu_regs[2] & 0x3Fu;
        if (!S.pri_f && !S.pri_a && !S.pri_b) {
            /* Sensible defaults before game initializes K053251 */
            S.pri_b = 0x10u;
            S.pri_a = 0x20u;
            S.pri_f = 0x38u;
        }
        if (S.pcu_regs[9] || S.pcu_regs[10] || S.pcu_regs[11]) {
            S.pal_base_f   = (u8)((S.pcu_regs[9]  & 0x3Fu) << 2);
            S.pal_base_spr = (u8)((S.pcu_regs[10] & 0x3Fu) << 2);
            S.pal_base_a   = (u8)(((S.pcu_regs[11] >> 0) & 0x0Fu) << 4);
            S.pal_base_b   = (u8)(((S.pcu_regs[11] >> 4) & 0x0Fu) << 4);
        }
    }
}

/* ---- GX400 Dynamic Character RAM Tile Decoder ---- */
static void gx400_decode_tile_row(u32 tile, u32 y)
{
    /* GX400 8x8 4bpp planar/packed tile: 32 bytes per tile in gx_charram */
    const u8 *src = &M->gx_charram[(tile & 2047u) * 32u + (y & 7u) * 4u];
    /* Standard Konami GX400 4bpp byte layout: 2 pixels per byte (4 bytes per 8-pixel row) */
    u32 row = 0;
    for (int i = 0; i < 4; i++) {
        u8 b = src[i];
        u32 p0 = (b >> 4) & 0x0Fu;
        u32 p1 = b & 0x0Fu;
        row |= (p0 << (i * 8)) | (p1 << (i * 8 + 4));
    }
    M->gx_tiles[(tile & 2047u) * 8u + (y & 7u)] = row;
    u8 nz = 0;
    const u32 *tr = &M->gx_tiles[(tile & 2047u) * 8u];
    for (int r = 0; r < 8; r++)
        if (tr[r]) { nz = 1; break; }
    M->gx_tile_nz[tile & 2047u] = nz;
}

/* ---- K053260 (KDSC) & K007232 Audio Synthesis @ 48 kHz ---- */
static const s8 k053260_dpcm_tab[16] = {
    0, 1, 2, 4, 8, 16, 32, 64, -128, -64, -32, -16, -8, -4, -2, -1
};

static void k053260_write(u32 off, u8 v)
{
    off &= 0x3Fu;
    u8 prev_ko = S.k3260_regs[0x28];
    S.k3260_regs[off] = v;

    if (off == 0x02u || off == 0x03u) {
        S.k3260_mail_s2m[off - 2u] = v;
        return;
    }
    if (off >= 0x08u && off < 0x28u) {
        int ch = (int)((off - 0x08u) >> 3);
        struct k053260_ch *c = &S.k3260[ch];
        const u8 *r = &S.k3260_regs[0x08u + ch * 8];
        c->pitch  = (u16)(r[0] | ((r[1] & 0x0Fu) << 8));
        c->length = (u16)(r[2] | (r[3] << 8));
        c->start  = (u32)r[4] | ((u32)r[5] << 8) | ((u32)(r[6] & 0x1Fu) << 16);
        c->vol    = r[7] & 0x7Fu;
        return;
    }
    if (off == 0x28u) {
        for (int ch = 0; ch < 4; ch++) {
            struct k053260_ch *c = &S.k3260[ch];
            c->reverse = (v >> (4 + ch)) & 1u;
            u8 mask = (u8)(1u << ch);
            if ((v & mask) && !(prev_ko & mask)) {
                c->playing   = (c->length > 0 && S.pcm_size > 0) ? 1u : 0u;
                c->pos_frac  = 0;
                c->idx       = 0;
                c->adpcm_acc = 0;
            } else if (!(v & mask)) {
                c->playing = 0;
            }
        }
        return;
    }
    if (off == 0x2Au) {
        for (int ch = 0; ch < 4; ch++) {
            S.k3260[ch].loop   = (v >> ch) & 1u;
            S.k3260[ch].kadpcm = (v >> (4 + ch)) & 1u;
        }
        return;
    }
    if (off == 0x2Cu) {
        S.k3260[0].pan = v & 7u;
        S.k3260[1].pan = (v >> 3) & 7u;
    } else if (off == 0x2Du) {
        S.k3260[2].pan = v & 7u;
        S.k3260[3].pan = (v >> 3) & 7u;
    }
}

static u8 k053260_read(u32 off)
{
    off &= 0x3Fu;
    if (off == 0x00u || off == 0x01u)
        return S.k3260_mail_m2s[off];
    if (off == 0x29u) {
        u8 st = 0;
        for (int ch = 0; ch < 4; ch++)
            if (S.k3260[ch].playing)
                st |= (u8)(1u << ch);
        return st;
    }
    return S.k3260_regs[off];
}

static s32 k053260_step_48k(void)
{
    if (!(S.k3260_regs[0x2F] & 2u) || !S.pcm_size)
        return 0;
    s32 sum = 0;
    /* K053260 clock = 3,579,545 Hz; counter ticks once per (4096 - pitch) clocks.
       At 48,000 Hz output: clocks_per_sample = 3579545 / 48000 ~= 74.5738 (305454 >> 12). */
    for (int ch = 0; ch < 4; ch++) {
        struct k053260_ch *c = &S.k3260[ch];
        if (!c->playing) continue;
        u32 period = 4096u - (c->pitch & 0xFFFu);
        if (period < 2u) period = 2u;
        /* Advance fractional index (12-bit frac): step_48k = (74.5738 * 4096) / period = 305454 / period */
        u32 step = 305454u / period;
        c->pos_frac += step;
        u32 adv = c->pos_frac >> 12;
        c->pos_frac &= 0xFFFu;
        while (adv > 0 && c->playing) {
            adv--;
            c->idx++;
            u32 max_units = c->kadpcm ? ((u32)c->length * 2u) : (u32)c->length;
            if (c->idx >= max_units) {
                if (c->loop && max_units > 0) {
                    c->idx = 0;
                    c->adpcm_acc = 0;
                } else {
                    c->playing = 0;
                    break;
                }
            }
            if (c->kadpcm) {
                u32 byte_off = c->reverse ? (c->start - (c->idx >> 1)) : (c->start + (c->idx >> 1));
                u8 b = PCM_BUF[byte_off & S.pcm_mask];
                u8 nib = (c->idx & 1u) ? (b >> 4) : (b & 0x0Fu);
                s32 acc = (s32)c->adpcm_acc + (s32)k053260_dpcm_tab[nib];
                if (acc > 127) acc = 127;
                else if (acc < -128) acc = -128;
                c->adpcm_acc = (s16)acc;
            }
        }
        if (!c->playing) continue;
        s32 smp;
        if (c->kadpcm) {
            smp = c->adpcm_acc;
        } else {
            u32 byte_off = c->reverse ? (c->start - c->idx) : (c->start + c->idx);
            smp = (s8)PCM_BUF[byte_off & S.pcm_mask];
        }
        sum += (smp * (s32)c->vol) >> 1;
    }
    return sum;
}

static void k007232_write(u32 off, u8 v)
{
    off &= 0x0Fu;
    S.k7232_regs[off] = v;
    if (off == 0x05u || off == 0x0Bu) {
        int ch = (off == 0x0Bu) ? 1 : 0;
        struct k007232_ch *c = &S.k7232[ch];
        const u8 *r = &S.k7232_regs[ch * 6];
        c->step  = (u16)(r[0] | ((r[1] & 0x0Fu) << 8));
        c->start = ((u32)r[2] | ((u32)r[3] << 8) | ((u32)(r[4] & 1u) << 16)) & 0x1FFFFu;
        c->addr_frac = 0;
        c->playing = S.pcm_size ? 1u : 0u;
    } else if (off == 0x0Cu) {
        S.k7232_sle = v;
        S.k7232[0].loop = (v >> 0) & 1u;
        S.k7232[1].loop = (v >> 1) & 1u;
    } else if (off == 0x0Du) {
        S.k7232[0].vol_l = (v >> 4) & 0x0Fu;
        S.k7232[1].vol_r = v & 0x0Fu;
    }
}

static s32 k007232_step_48k(void)
{
    if (!S.pcm_size) return 0;
    s32 sum = 0;
    for (int ch = 0; ch < 2; ch++) {
        struct k007232_ch *c = &S.k7232[ch];
        if (!c->playing) continue;
        u32 period = 4096u - (c->step & 0xFFFu);
        if (period < 4u) period = 4u;
        c->addr_frac += 305454u / period;
        u32 idx = c->addr_frac >> 12;
        u32 off = (c->start + idx) & S.pcm_mask;
        u8 b = PCM_BUF[off];
        if (b & 0x80u) {
            if (c->loop) {
                c->addr_frac = 0;
                b = PCM_BUF[c->start & S.pcm_mask];
            } else {
                c->playing = 0;
                continue;
            }
        }
        s32 smp = (s32)(b & 0x7Fu) - 64;
        u8 vol = ch ? c->vol_r : c->vol_l;
        if (!vol) vol = 12u;
        sum += smp * (s32)vol * 4;
    }
    return sum;
}

static s32 kon_ay_step_48k(struct kon_ay *ay)
{
    /* 1.789772 MHz / 16 = 111,860 Hz internal clock -> ~2.33 ticks per 48 kHz sample */
    static const s16 ay_vol[16] = {
        0, 24, 34, 48, 68, 96, 136, 192, 272, 384, 544, 768, 1086, 1536, 2172, 3072
    };
    for (int c = 0; c < 3; c++) {
        u32 per = ((u32)(ay->regs[c * 2 + 1] & 0x0Fu) << 8) | ay->regs[c * 2];
        if (per < 1u) per = 1u;
        ay->cnt[c] += 2u;
        if (ay->cnt[c] >= per) {
            ay->cnt[c] = 0;
            ay->out[c] ^= 1u;
        }
    }
    u32 nper = ay->regs[6] & 0x1Fu;
    if (nper < 1u) nper = 1u;
    ay->ncnt += 2u;
    if (ay->ncnt >= nper * 2u) {
        ay->ncnt = 0;
        if (!ay->lfsr) ay->lfsr = 1u;
        u32 bit = (ay->lfsr ^ (ay->lfsr >> 3)) & 1u;
        ay->lfsr = (ay->lfsr >> 1) | (bit << 16);
    }
    s32 sum = 0;
    u8 mix = ay->regs[7];
    for (int c = 0; c < 3; c++) {
        u8 t_dis = (mix >> c) & 1u;
        u8 n_dis = (mix >> (c + 3)) & 1u;
        u8 gate = (t_dis | ay->out[c]) & (n_dis | (u8)(ay->lfsr & 1u));
        u8 v = ay->regs[8 + c] & 0x0Fu;
        if (gate) sum += ay_vol[v];
    }
    return sum;
}

/* ---- Sound Z80 Bus ---- */
static u8 kon_z80_read(struct z80 *z, u16 a)
{
    (void)z;
    if (a < 0x8000u)
        return ZROM_BUF[a % (S.zrom_size ? S.zrom_size : 0x8000u)];
    if (S.board == KON_BOARD_SSRIDERS) {
        if (a < 0xE000u)
            return ZROM_BUF[a % (S.zrom_size ? S.zrom_size : 0x10000u)];
        if (a < 0xF000u)
            return M->zram[a & 0x0FFFu];
        if (a == 0xF001u)
            return M->opm.status;
        if (a >= 0xF800u && a < 0xF840u)
            return k053260_read(a - 0xF800u);
    } else if (S.board == KON_BOARD_TMNT) {
        if (a < 0x8800u)
            return M->zram[a & 0x07FFu];
        if (a == 0xA000u)
            return S.snd_latch;
        if (a == 0xB001u)
            return M->opm.status;
        if (a >= 0xC000u && a < 0xC010u)
            return S.k7232_regs[a & 0x0Fu];
    } else if (S.board == KON_BOARD_NEMESIS) {
        if (a < 0x4000u)
            return ZROM_BUF[a % (S.zrom_size ? S.zrom_size : 0x4000u)];
        if (a >= 0x4000u && a < 0x4800u)
            return M->zram[a & 0x07FFu];
        if (a == 0x6000u)
            return S.snd_latch;
        if (a == 0xE001u)
            return S.ay[0].regs[S.ay[0].sel & 15u];
        if (a == 0xE003u)
            return S.ay[1].regs[S.ay[1].sel & 15u];
    } else { /* KON_BOARD_CONTRA */
        if (a >= 0x8000u && a < 0x8800u)
            return M->zram[a & 0x07FFu];
        if (a == 0xA000u)
            return S.snd_latch;
        if (a == 0xC001u)
            return M->opm.status;
    }
    return 0xFFu;
}

static void kon_z80_write(struct z80 *z, u16 a, u8 v)
{
    (void)z;
    if (S.board == KON_BOARD_SSRIDERS) {
        if (a >= 0xE000u && a < 0xF000u) {
            M->zram[a & 0x0FFFu] = v;
        } else if (a == 0xF000u) {
            M->opm.addr_latch = v;
        } else if (a == 0xF001u) {
            ym2151_write_reg(&M->opm, M->opm.addr_latch, v, 3579545u);
        } else if (a >= 0xF800u && a < 0xF840u) {
            k053260_write(a - 0xF800u, v);
        } else if (a == 0xFC00u) {
            M->zcpu.irq = 0;
        }
    } else if (S.board == KON_BOARD_TMNT) {
        if (a >= 0x8000u && a < 0x8800u) {
            M->zram[a & 0x07FFu] = v;
        } else if (a == 0xB000u) {
            M->opm.addr_latch = v;
        } else if (a == 0xB001u) {
            ym2151_write_reg(&M->opm, M->opm.addr_latch, v, 3579545u);
        } else if (a >= 0xC000u && a < 0xC010u) {
            k007232_write(a & 0x0Fu, v);
        } else if (a == 0x9000u) {
            M->zcpu.irq = 0;
        }
    } else if (S.board == KON_BOARD_NEMESIS) {
        if (a >= 0x4000u && a < 0x4800u) {
            M->zram[a & 0x07FFu] = v;
        } else if (a == 0xC000u) {
            M->zcpu.irq = 0;
        } else if (a == 0xE000u) {
            S.ay[0].sel = v & 15u;
        } else if (a == 0xE001u) {
            S.ay[0].regs[S.ay[0].sel & 15u] = v;
        } else if (a == 0xE002u) {
            S.ay[1].sel = v & 15u;
        } else if (a == 0xE003u) {
            S.ay[1].regs[S.ay[1].sel & 15u] = v;
        }
    } else { /* KON_BOARD_CONTRA */
        if (a >= 0x8000u && a < 0x8800u) {
            M->zram[a & 0x07FFu] = v;
        } else if (a == 0xC000u) {
            M->opm.addr_latch = v;
        } else if (a == 0xC001u) {
            ym2151_write_reg(&M->opm, M->opm.addr_latch, v, 3579545u);
        } else if (a == 0xE000u) {
            M->zcpu.irq = 0;
        }
    }
}

static u8 kon_z80_in(struct z80 *z, u16 port)  { (void)z; (void)port; return 0xFFu; }
static void kon_z80_out(struct z80 *z, u16 port, u8 v) { (void)z; (void)port; (void)v; }

/* ---- Arcade Controls Mapping (Active-LOW for Konami PCBs) ---- */
static u8 kon_in_p1(void)
{
    /* Standard Konami JAMMA player byte (active LOW):
       b0=Left, b1=Right, b2=Up, b3=Down, b4=Btn1(Shot/Attack), b5=Btn2(Jump), b6=Btn3, b7=Start */
    u8 v = 0xFFu;
    u16 p = S.pad1;
    if (p & 0x0040u) v &= (u8)~0x01u;   /* Left */
    if (p & 0x0080u) v &= (u8)~0x02u;   /* Right */
    if (p & 0x0010u) v &= (u8)~0x04u;   /* Up */
    if (p & 0x0020u) v &= (u8)~0x08u;   /* Down */
    if (p & 0x0001u) v &= (u8)~0x10u;   /* A -> Button 1 */
    if (p & 0x0002u) v &= (u8)~0x20u;   /* B -> Button 2 */
    if (p & 0x0100u) v &= (u8)~0x40u;   /* X -> Button 3 */
    if (p & 0x0008u) v &= (u8)~0x80u;   /* Start */
    return v;
}

static u8 kon_in_p2(void)
{
    u8 v = 0xFFu;
    u16 p = S.pad2;
    if (p & 0x0040u) v &= (u8)~0x01u;
    if (p & 0x0080u) v &= (u8)~0x02u;
    if (p & 0x0010u) v &= (u8)~0x04u;
    if (p & 0x0020u) v &= (u8)~0x08u;
    if (p & 0x0001u) v &= (u8)~0x10u;
    if (p & 0x0002u) v &= (u8)~0x20u;
    if (p & 0x0100u) v &= (u8)~0x40u;
    if (p & 0x0008u) v &= (u8)~0x80u;
    return v;
}

static u8 kon_in_coin(void)
{
    /* b0=Coin1, b1=Coin2, b2=Service1, b3=Start1, b4=Start2 (active LOW) */
    u8 v = 0xFFu;
    if (S.coin_pulse > 0 || (S.pad1 & 0x0004u))
        v &= (u8)~0x01u;
    if (S.pad1 & 0x0008u)
        v &= (u8)~0x08u;
    if (S.pad2 & 0x0008u)
        v &= (u8)~0x10u;
    return v;
}

/* ---- K052109 Register & RAM Access ---- */
static u8 k052109_rb(u32 off)
{
    off &= 0x7FFFu;
    if (off == 0x1C80u) return S.k2109_scrollctrl;
    if (off == 0x1D00u) return S.k2109_irq_en;
    if (off == 0x1D80u) return (u8)(S.k2109_rombank[0] | (S.k2109_rombank[1] << 4));
    if (off == 0x1E80u) return S.k2109_flip;
    if (off == 0x1F00u) return (u8)(S.k2109_rombank[2] | (S.k2109_rombank[3] << 4));
    return M->k2109_ram[off];
}

static void k052109_wb(u32 off, u8 v)
{
    off &= 0x7FFFu;
    M->k2109_ram[off] = v;
    if (off < 0x1800u) {
        u32 cell_idx = off;
        M->k2109_cell[cell_idx] = (M->k2109_cell[cell_idx] & 0xFFFF00u) | v;
        return;
    }
    if (off >= 0x2000u && off < 0x3800u) {
        u32 cell_idx = off - 0x2000u;
        M->k2109_cell[cell_idx] = (M->k2109_cell[cell_idx] & 0xFF00FFu) | ((u32)v << 8);
        return;
    }
    if (off >= 0x4000u && off < 0x5800u) {
        u32 cell_idx = off - 0x4000u;
        M->k2109_cell[cell_idx] = (M->k2109_cell[cell_idx] & 0x00FFFFu) | ((u32)(v & 0x0Fu) << 16);
        return;
    }
    if (off == 0x1C80u) {
        S.k2109_scrollctrl = v;
    } else if (off == 0x1D00u) {
        S.k2109_irq_en = v;
        if (!(v & 0x04u) && m.ipl == 5u) {
            m.ipl = 0;
            check_pending();
        }
    } else if (off == 0x1D80u) {
        S.k2109_rombank[0] = v & 0x0Fu;
        S.k2109_rombank[1] = (v >> 4) & 0x0Fu;
    } else if (off == 0x1E80u) {
        S.k2109_flip = v;
    } else if (off == 0x1F00u) {
        S.k2109_rombank[2] = v & 0x0Fu;
        S.k2109_rombank[3] = (v >> 4) & 0x0Fu;
    }
}

/* ---- 68000 Memory Bus (SSRIDERS / TMNT / NEMESIS) ---- */
static void kon_iack(u32 level)
{
    if (level == m.ipl) {
        m.ipl = 0;
        check_pending();
    }
}

static void cpu_reset_line(void)
{
    z80_reset(&M->zcpu);
}

static u8 kon_io_rb(u32 a)
{
    a &= 0xFFFFFFu;
    if (S.board == KON_BOARD_SSRIDERS) {
        /* Palette RAM: $120000..$121FFF (and $300000..$301FFF on X-Men) */
        if ((a >= 0x120000u && a < 0x122000u) || (a >= 0x300000u && a < 0x302000u))
            return M->pal_ram[a & 0x1FFFu];
        /* Inputs & EEPROM: $140000..$14001F (and $200000..$20001F on X-Men) */
        if ((a >= 0x140000u && a < 0x140020u) || (a >= 0x200000u && a < 0x200020u)) {
            u32 r = a & 0x1Fu;
            if (r == 0x00u || r == 0x01u) return kon_in_coin();
            if (r == 0x02u || r == 0x03u) return kon_in_p1();
            if (r == 0x04u || r == 0x05u) return kon_in_p2();
            if (r == 0x06u || r == 0x07u) return 0xFFu; /* P3 */
            if (r == 0x08u || r == 0x09u) return 0xFFu; /* P4 */
            if (r == 0x0Au || r == 0x0Bu) return 0xFFu; /* DSW1 (Free/Standard) */
            if (r == 0x0Cu || r == 0x0Du) return 0xFFu; /* DSW2 */
            if (r == 0x0Eu || r == 0x0Fu) return 0xFFu; /* EEPROM ready */
            return 0xFFu;
        }
        /* K053251 PCU1: $160000..$16001F */
        if (a >= 0x160000u && a < 0x160020u)
            return S.pcu_regs[(a >> 1) & 0x0Fu];
        /* K053260 main<->sub mailbox: $1A0000..$1A0007 */
        if (a >= 0x1A0000u && a < 0x1A0008u) {
            u32 r = (a >> 1) & 3u;
            return (r >= 2u) ? S.k3260_mail_s2m[r - 2u] : S.k3260_mail_m2s[r];
        }
        /* K052109 noA12 word-mapped: $1C0000..$1C7FFF */
        if (a >= 0x1C0000u && a < 0x1C8000u)
            return (a & 1u) ? k052109_rb((a - 0x1C0000u) >> 1) : 0u;
        /* X-Men K052109: $380000..$38BFFF */
        if (a >= 0x380000u && a < 0x38C000u)
            return (a & 1u) ? k052109_rb((a - 0x380000u) >> 1) : 0u;
        /* K053245 Sprite RAM: $1E0000..$1E0FFF (and $340000..$340FFF on X-Men) */
        if ((a >= 0x1E0000u && a < 0x1E1000u) || (a >= 0x340000u && a < 0x341000u))
            return M->spr_ram[a & 0x0FFFu];
        return 0xFFu;
    }

    if (S.board == KON_BOARD_TMNT) {
        if (a >= 0x080000u && a < 0x081000u)
            return M->pal_ram[a & 0x0FFFu];
        if (a >= 0x0A0000u && a < 0x0A0040u) {
            u32 r = a & 0x3Fu;
            if (r == 0x01u) return kon_in_coin();
            if (r == 0x03u) return kon_in_p1();
            if (r == 0x05u) return kon_in_p2();
            if (r == 0x07u || r == 0x09u) return 0xFFu;
            if (r == 0x11u || r == 0x13u || r == 0x15u) return 0xFFu; /* DSWs */
            return 0xFFu;
        }
        if (a >= 0x100000u && a < 0x108000u)
            return (a & 1u) ? k052109_rb((a - 0x100000u) >> 1) : 0u;
        if (a >= 0x140000u && a < 0x140010u)
            return S.k1937_regs[(a >> 1) & 7u];
        if (a >= 0x140400u && a < 0x140C00u) {
            u32 off = a - 0x140400u;
            return (off < 0x400u) ? M->spr_ram[off] : M->spr_ram[(off >> 1) & 0x3FFu];
        }
        return 0xFFu;
    }

    /* KON_BOARD_NEMESIS (GX400) */
    if (a >= 0x040000u && a < 0x050000u)
        return M->gx_charram[a - 0x040000u];
    if (a >= 0x050000u && a < 0x056000u)
        return M->gx_vram[a - 0x050000u];
    if (a >= 0x056000u && a < 0x058000u)
        return M->spr_ram[a & 0x1FFFu];
    if (a >= 0x05A000u && a < 0x05C000u)
        return M->pal_ram[a & 0x1FFFu];
    if (a >= 0x05C000u && a < 0x05F000u) {
        u32 r = a & 0xFFFu;
        if (r < 0x010u) return kon_in_coin();
        if (r >= 0x400u && r < 0x410u) return kon_in_p1();
        if (r >= 0x410u && r < 0x420u) return kon_in_p2();
        return 0xFFu;
    }
    return 0xFFu;
}

static void kon_io_wb(u32 a, u8 v)
{
    a &= 0xFFFFFFu;
    if (S.board == KON_BOARD_SSRIDERS) {
        if ((a >= 0x120000u && a < 0x122000u) || (a >= 0x300000u && a < 0x302000u)) {
            u32 off = a & 0x1FFFu;
            M->pal_ram[off] = v;
            kon_update_pal_entry(off >> 1);
            return;
        }
        if (a >= 0x160000u && a < 0x160020u) {
            if (a & 1u) {
                S.pcu_regs[(a >> 1) & 0x0Fu] = v;
                kon_update_pcu_bases();
            }
            return;
        }
        if (a >= 0x180000u && a < 0x180010u) {
            u32 idx = (a >> 1) & 7u;
            if (a & 1u) S.k3244_regs[idx] = (u16)((S.k3244_regs[idx] & 0xFF00u) | v);
            else        S.k3244_regs[idx] = (u16)((S.k3244_regs[idx] & 0x00FFu) | ((u16)v << 8));
            S.spr_dx = (s16)S.k3244_regs[0];
            S.spr_dy = (s16)S.k3244_regs[1];
            S.spr_bank = (u8)(S.k3244_regs[3] & 0x0Fu);
            return;
        }
        if (a >= 0x1A0000u && a < 0x1A0010u) {
            u32 r = (a >> 1) & 7u;
            if (r < 2u && (a & 1u)) {
                S.k3260_mail_m2s[r] = v;
            } else if (r >= 4u) {
                M->zcpu.irq = 1;
            }
            return;
        }
        if (a >= 0x1C0000u && a < 0x1C8000u) {
            if (a & 1u) k052109_wb((a - 0x1C0000u) >> 1, v);
            return;
        }
        if (a >= 0x380000u && a < 0x38C000u) {
            if (a & 1u) k052109_wb((a - 0x380000u) >> 1, v);
            return;
        }
        if ((a >= 0x1E0000u && a < 0x1E1000u) || (a >= 0x340000u && a < 0x341000u)) {
            M->spr_ram[a & 0x0FFFu] = v;
            return;
        }
        return;
    }

    if (S.board == KON_BOARD_TMNT) {
        if (a >= 0x080000u && a < 0x081000u) {
            u32 off = a & 0x0FFFu;
            M->pal_ram[off] = v;
            kon_update_pal_entry(off >> 1);
            return;
        }
        if (a >= 0x0A0000u && a < 0x0A0040u) {
            u32 r = a & 0x3Fu;
            if (r == 0x09u) {
                S.snd_latch = v;
            } else if (r == 0x0Bu) {
                M->zcpu.irq = 1;
            }
            return;
        }
        if (a >= 0x100000u && a < 0x108000u) {
            if (a & 1u) k052109_wb((a - 0x100000u) >> 1, v);
            return;
        }
        if (a >= 0x140000u && a < 0x140010u) {
            if (a & 1u) S.k1937_regs[(a >> 1) & 7u] = v;
            return;
        }
        if (a >= 0x140400u && a < 0x140C00u) {
            u32 off = a - 0x140400u;
            if (off < 0x400u) M->spr_ram[off] = v;
            else if (a & 1u)  M->spr_ram[(off >> 1) & 0x3FFu] = v;
            return;
        }
        return;
    }

    /* KON_BOARD_NEMESIS */
    if (a >= 0x040000u && a < 0x050000u) {
        u32 off = a - 0x040000u;
        M->gx_charram[off] = v;
        gx400_decode_tile_row(off >> 5, (off >> 2) & 7u);
        return;
    }
    if (a >= 0x050000u && a < 0x056000u) {
        M->gx_vram[a - 0x050000u] = v;
        return;
    }
    if (a >= 0x056000u && a < 0x058000u) {
        M->spr_ram[a & 0x1FFFu] = v;
        return;
    }
    if (a >= 0x05A000u && a < 0x05C000u) {
        u32 off = a & 0x1FFFu;
        M->pal_ram[off] = v;
        kon_update_pal_entry(off >> 1);
        return;
    }
    if (a >= 0x05C000u && a < 0x05F000u) {
        u32 r = a & 0xFFFu;
        if (r == 0x001u) S.vblank_irq_en = v & 1u;
        else if (r >= 0x400u && r < 0x404u) S.snd_latch = v;
        else if (r >= 0x800u && r < 0x804u) M->zcpu.irq = 1;
    }
}

static u32 io_read(u32 a, int size)
{
    if (size == 1)
        return kon_io_rb(a);
    return ((u32)kon_io_rb(a) << 8) | kon_io_rb(a + 1u);
}

static void io_write(u32 a, u32 v, int size)
{
    if (size == 1) {
        kon_io_wb(a, (u8)v);
    } else {
        kon_io_wb(a, (u8)(v >> 8));
        kon_io_wb(a + 1u, (u8)v);
    }
}

/* ---- Contra MC6809E / Konami-1 Bus (m6809.inc) ---- */
static u8 kon_m6809_rb(void *ctx, u16 a)
{
    (void)ctx;
    if (a >= 0xC000u)
        return ROM_BUF[0x4000u + (a - 0xC000u)];
    if (a >= 0x8000u) {
        u32 bank_off = 0x8000u + (u32)(S.contra_bank & 7u) * 0x4000u;
        if (bank_off + 0x4000u > S.rom_size && S.rom_size >= 0x4000u)
            bank_off %= S.rom_size;
        return ROM_BUF[bank_off + (a - 0x8000u)];
    }
    if (a >= 0x6000u)
        return M->contra_ram[0x2000u + (a - 0x6000u)];
    if (a >= 0x4000u)
        return M->k7121_ram[1][a - 0x4000u];
    if (a >= 0x2000u)
        return M->k7121_ram[0][a - 0x2000u];
    if (a >= 0x0C00u)
        return M->contra_ram[a - 0x0C00u];
    if (a >= 0x0020u && a < 0x00A0u)
        return M->pal_ram[a - 0x0020u];
    if (a == 0x0010u) return kon_in_coin();
    if (a == 0x0011u) return kon_in_p1();
    if (a == 0x0012u) return kon_in_p2();
    if (a >= 0x0014u && a <= 0x0017u) return 0xFFu;
    return 0xFFu;
}

static void kon_m6809_wb(void *ctx, u16 a, u8 v)
{
    (void)ctx;
    if (a < 0x0008u) {
        M->k7121_ctrl[0][a] = v;
        if (a == 0x0007u) S.vblank_irq_en = v & 2u;
        return;
    }
    if (a >= 0x0080u && a < 0x0088u) {
        M->k7121_ctrl[1][a - 0x0080u] = v;
        return;
    }
    if (a == 0x000Cu || a == 0x0018u) {
        S.contra_bank = v & 0x0Fu;
        return;
    }
    if (a == 0x001Au) {
        S.snd_latch = v;
        return;
    }
    if (a == 0x001Cu) {
        M->zcpu.irq = 1;
        return;
    }
    if (a >= 0x0020u && a < 0x00A0u) {
        u32 off = a - 0x0020u;
        M->pal_ram[off] = v;
        kon_update_pal_entry(off >> 1);
        return;
    }
    if (a >= 0x0C00u && a < 0x2000u) {
        M->contra_ram[a - 0x0C00u] = v;
        return;
    }
    if (a >= 0x2000u && a < 0x4000u) {
        M->k7121_ram[0][a - 0x2000u] = v;
        return;
    }
    if (a >= 0x4000u && a < 0x6000u) {
        M->k7121_ram[1][a - 0x4000u] = v;
        return;
    }
    if (a >= 0x6000u && a < 0x8000u) {
        M->contra_ram[0x2000u + (a - 0x6000u)] = v;
    }
}

static u8 kon_m6809_op(void *ctx, u16 a)
{
    u8 b = kon_m6809_rb(ctx, a);
    if (!S.konami1_enc)
        return b;
    /* Konami-1 opcode XOR decryption based on A1 and A3 */
    switch (a & 0x0Au) {
    case 0x02u: return b ^ 0x02u;
    case 0x08u: return b ^ 0x08u;
    case 0x0Au: return b ^ 0x0Au;
    default:    return b;
    }
}

/* ---- Scanline Renderer: K052109 + K053245 / K051960 + GX400 + K007121 ---- */
INLINE u32 kon_map_k2109_tile(int layer, u8 attr, u16 code)
{
    u32 slot = attr & 3u;
    u32 bank = S.k2109_rombank[slot];
    u32 full = (u32)(code & 0xFFu) | ((u32)((attr >> 2) & 3u) << 8) | (bank << 10);
    if (S.sub == KON_SUB_XMEN) {
        full = (u32)code | (bank << 12);
    } else if (S.sub == KON_SUB_SSRIDERS || S.sub == KON_SUB_TMNT2) {
        u32 b4 = (attr & 0x03u) | ((attr >> 2) & 0x0Cu);
        u32 rb = S.k2109_rombank[b4 >> 2];
        if (rb || (attr & 0x0Fu))
            full = (u32)(code & 0xFFu) | ((b4 & 3u) << 8) | ((u32)rb << 10);
    }
    (void)layer;
    return full & S.tile_mask;
}

static void kon_draw_k2109_layer(int layer, int y, u8 pri_val, u8 pal_base_4bpp, u16 *dst)
{
    /* layer: 0 = F, 1 = A, 2 = B -- reads contiguous k2109_cell[layer*2048 + idx] (zero 8KB cache aliasing!) */
    if (!S.tile_count) return;
    int w = S.scr_w;
    const u32 *cells = &M->k2109_cell[(u32)layer * 2048u];

    int xscroll = 0, yscroll = 0;
    int col_scroll = 0;
    if (layer == 1 || layer == 2) {
        u32 xram = (layer == 1) ? 0x1A00u : 0x3A00u;
        u32 yram = (layer == 1) ? 0x1800u : 0x3800u;
        u8 ctrl = (layer == 1) ? (S.k2109_scrollctrl & 7u) : ((S.k2109_scrollctrl >> 3) & 7u);
        u32 xrow = 0;
        if ((ctrl & 3u) == 2u)      xrow = (u32)(y >> 3) * 8u;
        else if ((ctrl & 3u) == 3u) xrow = (u32)y;
        xscroll = (s16)(((u16)M->k2109_ram[xram + xrow * 2u] << 8) | M->k2109_ram[xram + xrow * 2u + 1u]);
        if (ctrl & 4u)
            col_scroll = 1;
        else
            yscroll = M->k2109_ram[yram + 0x0Cu];
    }

    u8 flip_x_mask = (S.k2109_flip & 0x02u) ? 0x08u : 0u;
    u8 flip_y_mask = (S.k2109_flip & 0x04u) ? 0x04u : 0u;

    for (int x = 0; x < w;) {
        int sx = (x + xscroll) & 511;
        int tx0 = sx & 7;
        int span = 8 - tx0;
        if (x + span > w) span = w - x;

        int sy = y + (col_scroll ? M->k2109_ram[((layer == 1) ? 0x1800u : 0x3800u) + ((sx >> 3) & 63)] : yscroll);
        sy &= 255;

        u32 packed = cells[(u32)(sy >> 3) * 64u + (u32)(sx >> 3)];
        u8  attr = (u8)packed;
        u16 code = (u16)((packed >> 8) & 0x0FFFu);
        u32 t = kon_map_k2109_tile(layer, attr, code);
        if (!M->tile_nz[t]) {
            x += span;
            continue;
        }

        int ty = (attr & flip_y_mask) ? (7 - (sy & 7)) : (sy & 7);
        u32 row32 = TILE_BUF[t * 8u + (u32)ty];
        if (!row32) {
            x += span;
            continue;
        }

        const u16 *pal_row = &M->pal15[(((u32)pal_base_4bpp + ((attr >> 4) & 0x0Fu)) << 4) & 0xFF0u];
        if (!(attr & flip_x_mask)) {
            u32 r_sh = row32 >> (tx0 * 4);
            for (int k = 0; k < span; k++, r_sh >>= 4) {
                u32 pen = r_sh & 0x0Fu;
                if (pen && pri_val >= M->line_pri[x + k]) {
                    dst[x + k] = pal_row[pen];
                    M->line_pri[x + k] = pri_val;
                }
            }
        } else {
            for (int k = 0; k < span; k++) {
                int px = 7 - (tx0 + k);
                u32 pen = (row32 >> (px * 4)) & 0x0Fu;
                if (pen && pri_val >= M->line_pri[x + k]) {
                    dst[x + k] = pal_row[pen];
                    M->line_pri[x + k] = pri_val;
                }
            }
        }
        x += span;
    }
}

static int kon_draw_k053245_sprites_line(int y, u16 *dst)
{
    if (!S.spr16_count || !S.n_act_spr) return 0;
    int w = S.scr_w, any_shd = 0;
    static const u8 dim_w[16] = {1, 2, 1, 2, 4, 2, 4, 8, 1, 2, 4, 8, 4, 8, 8, 8};
    static const u8 dim_h[16] = {1, 1, 2, 2, 2, 4, 4, 4, 4, 4, 1, 1, 8, 2, 8, 8};

    for (int ai = 0; ai < S.n_act_spr; ai++) {
        int s = S.act_spr[ai];
        const u8 *p = &M->spr_ram[s * 16];
        u16 w0 = ((u16)p[0] << 8) | p[1];

        u16 code  = (((u16)p[2] << 8) | p[3]) & 0x7FFFu;
        s32 sy    = (s16)(((u16)p[4] << 8) | p[5]);
        s32 sx    = (s16)(((u16)p[6] << 8) | p[7]);
        u16 zoomy = ((u16)p[8] << 8) | p[9];
        u16 zoomx = ((u16)p[10] << 8) | p[11];
        u16 w6    = ((u16)p[12] << 8) | p[13];

        sx = ((sx + S.spr_dx + 512) & 1023) - 512;
        sy = ((sy + S.spr_dy + 512) & 1023) - 512;

        u32 sz_code = (w0 >> 8) & 0x0Fu;
        int cw = dim_w[sz_code], ch = dim_h[sz_code];
        int src_w = cw * 16, src_h = ch * 16;

        if (!zoomx) zoomx = 0x40u;
        if (!zoomy) zoomy = 0x40u;
        if (y < sy) continue;
        int v = ((y - sy) * (int)zoomy) >> 6;
        if (v >= src_h) continue;

        int dst_w = (zoomx == 0x40u) ? src_w : ((src_w * 0x40) / (int)zoomx);
        if (dst_w < 1 || sx >= w || sx + dst_w <= 0) continue;

        int flip_x = (w0 & 0x1000u) != 0;
        int flip_y = (w0 & 0x2000u) != 0;
        int shadow = (w6 & 0x0400u) != 0;
        u8  pri    = (u8)(w0 & 0x7Fu);
        if (!pri) pri = 0x28u;
        const u16 *pal_row = &M->pal15[(((u32)S.pal_base_spr + (w6 & 0x7Fu)) << 4) & 0xFF0u];

        if (flip_y) v = src_h - 1 - v;
        int cell_y = v >> 4, in_y = v & 15;

        int x0 = sx < 0 ? 0 : sx;
        int x1 = (sx + dst_w > w) ? w : (sx + dst_w);
        u32 u_fp = (u32)(x0 - sx) * (u32)zoomx;

        for (int x = x0; x < x1; x++, u_fp += zoomx) {
            int u = (int)(u_fp >> 6);
            if (u >= src_w) break;
            int eff_u = flip_x ? (src_w - 1 - u) : u;
            int cell_x = eff_u >> 4, in_x = eff_u & 15;
            u32 cell = ((u32)code + (u32)(cell_y * cw + cell_x)) & S.spr16_mask;
            if (!M->spr_nz[cell]) continue;

            u8 packed = SPR_BUF[cell * 128u + (u32)in_y * 8u + (u32)(in_x >> 1)];
            u8 pen = (in_x & 1) ? (packed >> 4) : (packed & 0x0Fu);
            if (!pen) continue;

            if (shadow && pen == 15u) {
                if (!any_shd) {
                    u32 *sh32 = (u32 *)M->line_shd;
                    for (int i = 0; i < (w + 3) >> 2; i++) sh32[i] = 0;
                    any_shd = 1;
                }
                M->line_shd[x] = 1u;
            } else if (pri >= M->line_pri[x]) {
                dst[x] = pal_row[pen];
                M->line_pri[x] = pri;
                if (any_shd) M->line_shd[x] = 0;
            }
        }
    }
    return any_shd;
}

static int kon_draw_k051960_sprites_line(int y, u16 *dst)
{
    if (!S.spr16_count) return 0;
    int w = S.scr_w, any_shd = 0;
    static const u8 dim_w[8] = {1, 2, 1, 2, 4, 2, 4, 8};
    static const u8 dim_h[8] = {1, 1, 2, 2, 2, 4, 4, 8};

    for (int s = 127; s >= 0; s--) {
        const u8 *p = &M->spr_ram[s * 8];
        if (!(p[0] & 0x80u)) continue;

        u8  pri   = (u8)((p[0] & 0x7Fu) >> 1);
        u8  sz    = (p[1] >> 5) & 7u;
        u32 code  = ((u32)(p[1] & 0x1Fu) << 8) | p[2];
        u8  color = p[3] & 0x0Fu;
        int shd   = (p[3] & 0x80u) != 0;
        u32 zoomy = ((u32)(p[4] & 0xFCu) >> 2) + 0x40u;
        int fy    = (p[4] & 0x02u) != 0;
        s32 sy    = 256 - (s32)(((u32)(p[4] & 1u) << 8) | p[5]);
        u32 zoomx = ((u32)(p[6] & 0xFCu) >> 2) + 0x40u;
        int fx    = (p[6] & 0x02u) != 0;
        s32 sx    = (s32)(((u32)(p[6] & 1u) << 8) | p[7]) - 60;

        int cw = dim_w[sz], ch = dim_h[sz];
        int src_w = cw * 16, src_h = ch * 16;
        int dst_h = (src_h * 0x40) / (int)zoomy;
        int dst_w = (src_w * 0x40) / (int)zoomx;
        if (dst_h < 1 || y < sy || y >= sy + dst_h) continue;
        if (dst_w < 1 || sx >= w || sx + dst_w <= 0) continue;

        u32 pal_hi = (0x100u + ((u32)color << 4)) & 0xFF0u;
        int v = ((y - sy) * (int)zoomy) >> 6;
        if (v >= src_h) v = src_h - 1;
        if (fy) v = src_h - 1 - v;
        int cell_y = v >> 4, in_y = v & 15;

        int x0 = sx < 0 ? 0 : sx;
        int x1 = (sx + dst_w > w) ? w : (sx + dst_w);
        u32 u_fp = (u32)(x0 - sx) * zoomx;

        for (int x = x0; x < x1; x++, u_fp += zoomx) {
            int u = (int)(u_fp >> 6);
            if (u >= src_w) break;
            int eff_u = fx ? (src_w - 1 - u) : u;
            u32 cell = (code + (u32)(cell_y * cw + (eff_u >> 4))) & S.spr16_mask;
            if (!M->spr_nz[cell]) continue;
            u8 packed = SPR_BUF[cell * 128u + (u32)in_y * 8u + (u32)((eff_u & 15) >> 1)];
            u8 pen = (eff_u & 1) ? (packed >> 4) : (packed & 0x0Fu);
            if (!pen) continue;
            if (shd && pen == 15u) {
                if (!any_shd) {
                    u32 *sh32 = (u32 *)M->line_shd;
                    for (int i = 0; i < (w + 3) >> 2; i++) sh32[i] = 0;
                    any_shd = 1;
                }
                M->line_shd[x] = 1u;
            } else if (pri + 0x18u >= M->line_pri[x]) {
                dst[x] = M->pal15[(pal_hi + pen) & 0xFFFu];
                M->line_pri[x] = (u8)(pri + 0x18u);
            }
        }
    }
    return any_shd;
}

static void kon_render_gx400_line(int y, u16 *dst)
{
    int w = S.scr_w;
    u16 bg = M->pal15[0];
    for (int x = 0; x < w; x++) {
        M->line_col[x] = bg;
        M->line_pri[x] = 0;
    }
    /* GX400 Layer 2 (back) & Layer 1 (front): 64x32 8x8 tiles in gx_vram */
    for (int ly = 1; ly >= 0; ly--) {
        u32 vbase = ly ? 0x1000u : 0x0000u;
        u32 cbase = ly ? 0x3000u : 0x2000u;
        u32 sbase = ly ? 0x4400u : 0x4000u;
        int xscr = (((u16)M->gx_vram[sbase + (u32)y * 2u] << 8) | M->gx_vram[sbase + (u32)y * 2u + 1u]) & 511;
        int yscr = M->gx_vram[ly ? 0x4F81u : 0x4801u];
        int sy = (y + yscr) & 255;
        for (int x = 0; x < w; x++) {
            int sx = (x + xscr) & 511;
            u32 idx = ((u32)(sy >> 3) * 64u + (u32)(sx >> 3)) * 2u;
            u16 vw = ((u16)M->gx_vram[vbase + idx] << 8) | M->gx_vram[vbase + idx + 1u];
            u16 cw = ((u16)M->gx_vram[cbase + idx] << 8) | M->gx_vram[cbase + idx + 1u];
            u32 tile = vw & 0x7FFu;
            if (!M->gx_tile_nz[tile]) continue;
            int fx = (vw & 0x1000u) != 0, fy = (vw & 0x2000u) != 0;
            int ty = fy ? (7 - (sy & 7)) : (sy & 7);
            int tx = fx ? (7 - (sx & 7)) : (sx & 7);
            u8 pen = (u8)((M->gx_tiles[tile * 8u + (u32)ty] >> (tx * 4)) & 0x0Fu);
            if (pen) {
                u32 pal = ((cw & 0x7Fu) << 4) + pen;
                M->line_col[x] = M->pal15[pal & 0x7FFu];
            }
        }
    }
    /* GX400 Sprites in spr_ram (256 x 16 bytes, using dynamic gx_tiles!) */
    for (int s = 255; s >= 0; s--) {
        const u8 *p = &M->spr_ram[s * 16];
        u16 w0 = ((u16)p[0] << 8) | p[1];
        u16 w1 = ((u16)p[2] << 8) | p[3];
        if (!w0 && !w1) continue;
        int sy = p[13], sx = (((u16)p[8] << 8) | p[9]) & 511;
        if (sx >= 384) sx -= 512;
        u32 tile_base = (w0 & 0x7FFu);
        u32 pal = (u32)((p[7] >> 1) & 0x3Fu) << 4;
        if (y < sy || y >= sy + 16) continue;
        int ty = y - sy;
        for (int dx = 0; dx < 16; dx++) {
            int px = sx + dx;
            if (px < 0 || px >= w) continue;
            u32 t = (tile_base + (u32)((ty >> 3) * 2 + (dx >> 3))) & 2047u;
            u8 pen = (u8)((M->gx_tiles[t * 8u + (u32)(ty & 7)] >> ((dx & 7) * 4)) & 0x0Fu);
            if (pen) M->line_col[px] = M->pal15[(pal + pen) & 0x7FFu];
        }
    }
    for (int x = 0; x < w; x++)
        dst[x] = M->line_col[x];
}

static void kon_render_contra_line(int y, u16 *dst)
{
    int w = S.scr_w;
    u16 bg = M->pal15[0];
    for (int x = 0; x < w; x++)
        M->line_col[x] = bg;
    if (!S.tile_count) {
        for (int x = 0; x < w; x++) dst[x] = bg;
        return;
    }
    /* Dual K007121: chip 1 (background) then chip 0 (foreground + HUD) */
    for (int chip = 1; chip >= 0; chip--) {
        const u8 *vr = M->k7121_ram[chip];
        const u8 *cr = M->k7121_ctrl[chip];
        int xscr = cr[0] | ((cr[2] & 1u) << 8);
        int yscr = cr[1];
        int sy = (y + yscr) & 255;
        for (int x = 0; x < w;) {
            int sx = (x + xscr) & 511;
            int tx0 = sx & 7;
            int span = 8 - tx0;
            if (x + span > w) span = w - x;
            u32 off = ((sx >= 256) ? 0x0400u : 0x0000u) + (u32)(sy >> 3) * 32u + (u32)((sx & 255) >> 3);
            u8 attr = vr[off];
            u32 code = (u32)vr[0x0800u + off] | ((u32)(attr & 0x0Fu) << 8) | ((u32)chip << 12);
            u32 t = code & S.tile_mask;
            if (!M->tile_nz[t]) { x += span; continue; }
            u32 row32 = TILE_BUF[t * 8u + (u32)(sy & 7)];
            if (!row32) { x += span; continue; }
            const u16 *pal_row = &M->pal15[(((u32)chip * 32u) + (((attr >> 4) & 1u) << 4)) & 0x3Fu];
            u32 r_sh = row32 >> (tx0 * 4);
            for (int k = 0; k < span; k++, r_sh >>= 4) {
                u32 pen = r_sh & 0x0Fu;
                if (pen) M->line_col[x + k] = pal_row[pen];
            }
            x += span;
        }
        /* K007121 Sprites at +0x1000 (64 x 5 bytes) */
        if (S.spr16_count) {
            for (int s = 0; s < 64; s++) {
                const u8 *sp = &vr[0x1000u + s * 5];
                int sy_s = 240 - sp[3];
                if (y < sy_s || y >= sy_s + 16) continue;
                int sx_s = sp[2] - ((sp[4] & 1u) ? 256 : 0);
                if (sx_s >= w || sx_s + 16 <= 0) continue;
                u32 cell = ((u32)sp[0] | ((u32)(sp[1] & 0x30u) << 4)) & S.spr16_mask;
                if (!M->spr_nz[cell]) continue;
                int ty = (sp[4] & 0x20u) ? (15 - (y - sy_s)) : (y - sy_s);
                int fx = (sp[4] & 0x10u) != 0;
                u32 pal = ((u32)chip * 32u) + 16u + ((sp[1] & 1u) << 4);
                for (int dx = 0; dx < 16; dx++) {
                    int px = sx_s + dx;
                    if (px < 0 || px >= w) continue;
                    int ix = fx ? (15 - dx) : dx;
                    u8 pk = SPR_BUF[cell * 128u + (u32)ty * 8u + (u32)(ix >> 1)];
                    u8 pen = (ix & 1) ? (pk >> 4) : (pk & 0x0Fu);
                    if (pen) M->line_col[px] = M->pal15[(pal + pen) & 0x3Fu];
                }
            }
        }
    }
    for (int x = 0; x < w; x++)
        dst[x] = M->line_col[x];
}

static void kon_render_line(int y, u16 *dst)
{
    if (S.board == KON_BOARD_NEMESIS) {
        kon_render_gx400_line(y, dst);
        return;
    }
    if (S.board == KON_BOARD_CONTRA) {
        kon_render_contra_line(y, dst);
        return;
    }

    int w = S.scr_w;
    u16 bg = M->pal15[0];
    u32 bg32 = (u32)bg | ((u32)bg << 16);
    u32 *d32 = (u32 *)dst;
    for (int i = 0; i < (w >> 1); i++)
        d32[i] = bg32;
    if (w & 1)
        dst[w - 1] = bg;
    u32 *p32 = (u32 *)M->line_pri;
    for (int i = 0; i < (w + 3) >> 2; i++)
        p32[i] = 0;

    int any_shd = 0;
    if (S.board == KON_BOARD_TMNT) {
        kon_draw_k2109_layer(2, y, 0x10u, 0x20u, dst);   /* Layer B */
        kon_draw_k2109_layer(1, y, 0x20u, 0x00u, dst);   /* Layer A */
        any_shd = kon_draw_k051960_sprites_line(y, dst);
        kon_draw_k2109_layer(0, y, 0x38u, 0x00u, dst);   /* Layer F (HUD) */
    } else {
        /* KON_BOARD_SSRIDERS (K052109 + K053245 + K053251 PCU1 priority) */
        kon_draw_k2109_layer(2, y, S.pri_b, S.pal_base_b, dst);
        kon_draw_k2109_layer(1, y, S.pri_a, S.pal_base_a, dst);
        any_shd = kon_draw_k053245_sprites_line(y, dst);
        kon_draw_k2109_layer(0, y, S.pri_f, S.pal_base_f, dst);
    }

    if (any_shd) {
        for (int x = 0; x < w; x++) {
            if (M->line_shd[x])
                dst[x] = (dst[x] >> 1) & 0x3DEFu;
        }
    }
}

/* ---- Built-in Playable Konami-Hardware Game ("") : "VIPER STRIKE GX" ----
   Executes genuine 68000 machine code (ROM_BUF) + Z80 sound driver (ZROM_BUF)
   driving K052109 3-layer parallax scrolling, K053245 hardware-zoomed sprites
   & shadow pens, K053251 priority, YM2151 4-ch FM soundtrack & K053260 PCM SFX! */

static void emit16(u8 *rom, u32 *p, u16 w)
{
    /* m68k.inc word-swapped storage: *(u16 *)(rom + off) = w */
    u32 o = *p;
    rom[o]     = (u8)(w & 0xFFu);
    rom[o + 1] = (u8)(w >> 8);
    *p = o + 2u;
}

static void emit32(u8 *rom, u32 *p, u32 l)
{
    emit16(rom, p, (u16)(l >> 16));
    emit16(rom, p, (u16)(l & 0xFFFFu));
}

static void kon_put_tile_px(u32 tile, int x, int y, u8 pen)
{
    u32 *r = &TILE_BUF[tile * 8u + (u32)y];
    u32 sh = (u32)x * 4u;
    *r = (*r & ~(0x0Fu << sh)) | ((u32)(pen & 0x0Fu) << sh);
    if (pen) M->tile_nz[tile] = 1u;
}

static void kon_put_spr_px(u32 cell, int x, int y, u8 pen)
{
    u8 *b = &SPR_BUF[cell * 128u + (u32)y * 8u + (u32)(x >> 1)];
    if (x & 1) *b = (u8)((*b & 0x0Fu) | ((pen & 0x0Fu) << 4));
    else       *b = (u8)((*b & 0xF0u) | (pen & 0x0Fu));
    if (pen) M->spr_nz[cell] = 1u;
}

static void build_builtin_gfx_and_pcm(void)
{
    kon_zero(TILE_BUF, 512u * 32u);
    kon_zero(M->tile_nz, 512u);
    kon_zero(SPR_BUF, 64u * 128u);
    kon_zero(M->spr_nz, 64u);

    /* Tiles 32..126: 8x8 arcade font from font5x7 (7 rows, bit 4 = leftmost) with drop shadow */
    for (int ch = 32; ch <= 126; ch++) {
        const u8 *gl = font5x7[ch - 32];
        u32 t = (u32)ch;
        for (int y = 0; y < 7; y++) {
            u8 row = gl[y];
            for (int x = 0; x < 5; x++) {
                if ((row & (0x10u >> x)) && x + 2 < 8 && y + 1 < 8)
                    kon_put_tile_px(t, x + 2, y + 1, 3u);
            }
        }
        for (int y = 0; y < 7; y++) {
            u8 row = gl[y];
            for (int x = 0; x < 5; x++) {
                if (row & (0x10u >> x))
                    kon_put_tile_px(t, x + 1, y, (y < 3) ? 1u : 2u);
            }
        }
    }

    /* Tiles 128..135: Deep-space Layer B starfield & glowing nebula grid tiles */
    for (int st = 0; st < 8; st++) {
        u32 t = 128u + (u32)st;
        int sx = (st * 5 + 1) & 7, sy = (st * 3 + 2) & 7;
        kon_put_tile_px(t, sx, sy, (u8)(4 + (st & 3)));
        if (st & 1) kon_put_tile_px(t, (sx + 4) & 7, (sy + 5) & 7, 2u);
        if (st == 6 || st == 7) {
            for (int i = 0; i < 8; i++) {
                kon_put_tile_px(t, i, 7, 8u);
                if (st == 7) kon_put_tile_px(t, 7, i, 8u);
            }
        }
    }

    /* Tiles 140..147: Layer A metallic Bacterian fortress & glowing crystal Moai cavern tiles */
    for (int y = 0; y < 8; y++) {
        for (int x = 0; x < 8; x++) {
            /* 140: Armored ceiling/floor plating with rivets */
            u8 c = ((x == 0 || y == 0) ? 5u : ((x == 7 || y == 7) ? 1u : 3u));
            if ((x == 2 || x == 5) && (y == 2 || y == 5)) c = 6u;
            kon_put_tile_px(140u, x, y, c);
            /* 141: Glowing plasma conduit */
            u8 p = (y >= 2 && y <= 5) ? (u8)(9u + ((x + y) & 3)) : 4u;
            kon_put_tile_px(141u, x, y, p);
            /* 142: Crystal spire top */
            if (x >= (7 - y) / 2 && x <= 7 - (7 - y) / 2)
                kon_put_tile_px(142u, x, y, (u8)(6u + (x & 1)));
            /* 143: Crystal spire inverted */
            if (x >= y / 2 && x <= 7 - y / 2)
                kon_put_tile_px(143u, x, y, (u8)(6u + (x & 1)));
            /* 144: Power-up meter active box */
            u8 mpen = (x == 0 || x == 7 || y == 0 || y == 7) ? 1u : 10u;
            kon_put_tile_px(144u, x, y, mpen);
            /* 145: Power-up meter dim box */
            u8 dpen = (x == 0 || x == 7 || y == 0 || y == 7) ? 3u : 0u;
            kon_put_tile_px(145u, x, y, dpen);
        }
    }

    /* Sprite 0: Vic Viper starfighter (16x16, sleek white/blue hull + orange thruster + cyan canopy) */
    for (int y = 0; y < 16; y++) {
        int dy = y < 8 ? (7 - y) : (y - 8);
        int max_x = 15 - dy * 2;
        for (int x = 2; x <= max_x; x++) {
            u8 pen = (dy == 0) ? 1u : (dy <= 2 ? 2u : 3u);
            if (x >= 9 && x <= 12 && dy <= 1) pen = 6u; /* Cyan cockpit */
            kon_put_spr_px(0u, x, y, pen);
        }
        if (dy <= 2) {
            kon_put_spr_px(0u, 0, y, 9u);  /* Thruster flame outer */
            kon_put_spr_px(0u, 1, y, 10u); /* Thruster flame core */
        }
    }
    /* Sprite 1: Glowing Gradius Option orb (16x16) */
    for (int y = 3; y <= 12; y++) {
        for (int x = 3; x <= 12; x++) {
            int dx = x - 7, dy = y - 7;
            int d2 = dx * dx + dy * dy;
            if (d2 <= 22)
                kon_put_spr_px(1u, x, y, (d2 <= 5) ? 11u : (d2 <= 12 ? 10u : 9u));
        }
    }
    /* Sprite 2: Twin Laser bolt (16x16) */
    for (int x = 0; x < 16; x++) {
        kon_put_spr_px(2u, x, 5, 6u);
        kon_put_spr_px(2u, x, 6, 1u);
        kon_put_spr_px(2u, x, 9, 1u);
        kon_put_spr_px(2u, x, 10, 6u);
    }
    /* Sprite 3: Bacterian Fighter / Spinner enemy (16x16) */
    for (int y = 1; y < 15; y++) {
        for (int x = 1; x < 15; x++) {
            int dx = x - 7, dy = y - 7;
            int d2 = dx * dx + dy * dy;
            if (d2 <= 42 && (d2 >= 10 || (dx * dy >= 0))) {
                u8 pen = (d2 <= 10) ? 11u : ((x + y) & 2 ? 4u : 5u);
                kon_put_spr_px(3u, x, y, pen);
            }
        }
    }
    /* Sprites 4..7: 32x32 (2x2 cells) Big Core Boss with glowing blue core + shadow rim (pen 15)! */
    for (int cy = 0; cy < 2; cy++) {
        for (int cx = 0; cx < 2; cx++) {
            u32 cell = 4u + (u32)(cy * 2 + cx);
            for (int y = 0; y < 16; y++) {
                for (int x = 0; x < 16; x++) {
                    int gx = cx * 16 + x - 16;
                    int gy = cy * 16 + y - 16;
                    int r2 = gx * gx + gy * gy;
                    if (r2 <= 240) {
                        u8 pen = 3u;
                        if (r2 <= 28) pen = 6u;         /* Bright cyan core */
                        else if (r2 <= 56) pen = 2u;    /* Inner ring */
                        else if (gy >= -3 && gy <= 3 && gx < 0) pen = 9u; /* Core shutter */
                        else if (r2 >= 195) pen = 15u;  /* K053245 hardware shadow rim! */
                        else if ((gx + gy) & 4) pen = 7u;
                        kon_put_spr_px(cell, x, y, pen);
                    }
                }
            }
        }
    }
    /* Sprite 8: Enemy plasma bullet / Power capsule (16x16) */
    for (int y = 4; y <= 11; y++) {
        for (int x = 4; x <= 11; x++) {
            int dx = x - 7, dy = y - 7;
            if (dx * dx + dy * dy <= 14)
                kon_put_spr_px(8u, x, y, (dx * dx + dy * dy <= 4) ? 1u : 12u);
        }
    }
    /* Sprite 9: Expanding explosion ring (16x16, zoomed dynamically via K053245!) */
    for (int y = 0; y < 16; y++) {
        for (int x = 0; x < 16; x++) {
            int dx = x - 7, dy = y - 7;
            int r2 = dx * dx + dy * dy;
            if (r2 >= 16 && r2 <= 52)
                kon_put_spr_px(9u, x, y, (r2 < 30) ? 11u : 9u);
        }
    }

    S.tile_count  = 512u;
    S.spr16_count = 64u;

    /* Synthesize 4 crisp K053260 8-bit signed PCM arcade samples in PCM_BUF:
       0x0000 (1024 B): Punchy Konami Drum Kick
       0x0400 (1024 B): Crisp Snare
       0x0800 (1024 B): Twin-Laser Zap
       0x0C00 (2048 B): Deep Boss Explosion */
    u32 lfsr = 0xACE1u;
    for (u32 i = 0; i < 1024u; i++) {
        /* Kick: pitch-dropping triangle/sine */
        u32 ph = (i * (180u - (i >> 3))) >> 4;
        s32 tri = (s32)((ph & 31u) < 16u ? ((ph & 15u) * 8 - 60) : (60 - (ph & 15u) * 8));
        s32 env = (s32)(1024u - i);
        PCM_BUF[0x0000u + i] = (u8)(s8)((tri * env) >> 10);

        /* Snare: noise + tone burst */
        lfsr = (lfsr >> 1) ^ ((lfsr & 1u) ? 0xB400u : 0u);
        s32 nz = (lfsr & 1u) ? 70 : -70;
        PCM_BUF[0x0400u + i] = (u8)(s8)((nz * env) >> 10);

        /* Laser zap: fast frequency sweep */
        u32 lph = (i * (240u - (i >> 2))) >> 3;
        s32 sq = (lph & 16u) ? 75 : -75;
        PCM_BUF[0x0800u + i] = (u8)(s8)((sq * env) >> 10);
    }
    for (u32 i = 0; i < 2048u; i++) {
        if ((i & 3u) == 0)
            lfsr = (lfsr >> 1) ^ ((lfsr & 1u) ? 0xB400u : 0u);
        s32 nz = (lfsr & 1u) ? 96 : -96;
        s32 env = (s32)(2048u - i);
        PCM_BUF[0x0C00u + i] = (u8)(s8)((nz * env) >> 11);
    }
    S.pcm_size = 0x1400u;
}

static void build_builtin_z80_driver(void)
{
    /* Genuine Z80 sound driver in ZROM_BUF ($0000..):
       - Initializes YM2151 FM channels 0..2 (Bass, Lead, Harmony) + K053260 enable ($F82F = 0x02)
       - Loops polling K053260 mailbox ($F800) from 68000 for SFX triggers (1=Laser, 2=Explosion, 3=Powerup)
       - Steps a lively 16-note Konami synthwave bass + lead sequence on YM2151! */
    kon_zero(ZROM_BUF, 0x2000u);
    static const u8 zprog[] = {
        0xF3,                   /* 0000: DI */
        0x31, 0xFF, 0xEF,       /* 0001: LD SP, $EFFF */
        0x3E, 0x02,             /* 0004: LD A, $02 (enable K053260 audio) */
        0x32, 0x2F, 0xF8,       /* 0006: LD ($F82F), A */
        0x3E, 0xFF,             /* 0009: LD A, $FF */
        0x32, 0x2C, 0xF8,       /* 000B: LD ($F82C), A (center pan) */
        0x32, 0x2D, 0xF8,       /* 000E: LD ($F82D), A */
        /* Configure YM2151 Ch 0 (Synth Bass, Alg 4) & Ch 1 (Lead Brass, Alg 4) via table at $0100 */
        0x21, 0x00, 0x01,       /* 0011: LD HL, $0100 */
        /* init_loop ($0014): */
        0x7E,                   /* 0014: LD A, (HL) */
        0xFE, 0xFF,             /* 0015: CP $FF */
        0x28, 0x0C,             /* 0017: JR Z, +12 ($0025) */
        0x32, 0x00, 0xF0,       /* 0019: LD ($F000), A */
        0x23,                   /* 001C: INC HL */
        0x7E,                   /* 001D: LD A, (HL) */
        0x32, 0x01, 0xF0,       /* 001E: LD ($F001), A */
        0x23,                   /* 0021: INC HL */
        0x18, 0xF1,             /* 0022: JR $0014 */
        /* $0024 pad */ 0x00,
        /* main_loop ($0025): */
        0x0E, 0x00,             /* 0025: LD C, 0 (note index 0..15) */
        /* seq_step ($0027): */
        /* Key-off Ch 0 & Ch 1 */
        0x3E, 0x08, 0x32, 0x00, 0xF0, 0x3E, 0x00, 0x32, 0x01, 0xF0,
        0x3E, 0x08, 0x32, 0x00, 0xF0, 0x3E, 0x01, 0x32, 0x01, 0xF0,
        /* Lookup Bass KC at $0140 + C */
        0x26, 0x01, 0x79, 0xC6, 0x40, 0x6F, /* LD H,$01; LD A,C; ADD $40; LD L,A */
        0x3E, 0x28, 0x32, 0x00, 0xF0, 0x7E, 0x32, 0x01, 0xF0,
        /* Lookup Lead KC at $0150 + C */
        0x79, 0xC6, 0x50, 0x6F,
        0x3E, 0x29, 0x32, 0x00, 0xF0, 0x7E, 0x32, 0x01, 0xF0,
        /* Key-on Ch 0 ($78) & Ch 1 ($79) */
        0x3E, 0x08, 0x32, 0x00, 0xF0, 0x3E, 0x78, 0x32, 0x01, 0xF0,
        0x3E, 0x08, 0x32, 0x00, 0xF0, 0x3E, 0x79, 0x32, 0x01, 0xF0,
        /* Trigger K053260 Kick (ch 0) on even steps, Snare (ch 1) on step%4==2 */
        0x79, 0xE6, 0x03, 0x20, 0x1A, /* BIT check: step%4 == 0 -> Kick on K053260 ch 0 */
        0x3E, 0xC0, 0x32, 0x08, 0xF8, 0x3E, 0x0F, 0x32, 0x09, 0xF8,
        0x3E, 0x00, 0x32, 0x0A, 0xF8, 0x3E, 0x04, 0x32, 0x0B, 0xF8,
        0x3E, 0x00, 0x32, 0x0C, 0xF8, 0x32, 0x0D, 0xF8, 0x32, 0x0E, 0xF8,
        0x3E, 0x58, 0x32, 0x0F, 0xF8,
        0x3E, 0x00, 0x32, 0x28, 0xF8, 0x3E, 0x01, 0x32, 0x28, 0xF8,
        /* Delay loop while polling 68000 mailbox ($F800) */
        0x11, 0x00, 0x16,       /* LD DE, $1600 (~120ms @ 3.58 MHz) */
        /* wait_sfx: */
        0x3A, 0x00, 0xF8,       /* LD A, ($F800) */
        0x47,                   /* LD B, A */
        0x3A, 0x00, 0xE0,       /* LD A, ($E000) last_seq */
        0xB8,                   /* CP B */
        0x28, 0x26,             /* JR Z, no_sfx */
        0x78, 0x32, 0x00, 0xE0, /* LD ($E000), B */
        /* Trigger Laser ($0800) or Explosion ($0C00) on K053260 ch 2 based on B bit 0 */
        0x3E, 0xD0, 0x32, 0x18, 0xF8, 0x3E, 0x0F, 0x32, 0x19, 0xF8,
        0x3E, 0x00, 0x32, 0x1A, 0xF8, 0x3E, 0x04, 0x32, 0x1B, 0xF8,
        0x3E, 0x00, 0x32, 0x1C, 0xF8,
        0xCB, 0x40,             /* BIT 0, B */
        0x3E, 0x08, 0x20, 0x02, 0x3E, 0x0C,
        0x32, 0x1D, 0xF8, 0xAF, 0x32, 0x1E, 0xF8,
        0x3E, 0x68, 0x32, 0x1F, 0xF8,
        0x3E, 0x01, 0x32, 0x28, 0xF8, 0x3E, 0x05, 0x32, 0x28, 0xF8,
        /* no_sfx: */
        0x1B, 0x7A, 0xB3, 0x20, 0xCF, /* DEC DE; LD A,D; OR E; JR NZ, wait_sfx */
        0x0C, 0x79, 0xE6, 0x0F, 0x4F, /* INC C; LD A,C; AND 15; LD C,A */
        0xC3, 0x27, 0x00        /* JP seq_step */
    };
    for (u32 i = 0; i < sizeof(zprog); i++)
        ZROM_BUF[i] = zprog[i];

    /* YM2151 patch table at $0100 */
    static const u8 ympatch[] = {
        0x20, 0xEA,  0x21, 0xDC,  /* Ch 0: RL=3, FB=5, Alg=2; Ch 1: RL=3, FB=3, Alg=4 */
        0x40, 0x01,  0x48, 0x02,  0x50, 0x01,  0x58, 0x01,
        0x60, 0x18,  0x68, 0x14,  0x70, 0x16,  0x78, 0x08, /* Ch 0 TL */
        0x80, 0x1F,  0x88, 0x1F,  0x90, 0x1F,  0x98, 0x1F, /* Ch 0 AR */
        0xA0, 0x0C,  0xA8, 0x0C,  0xB0, 0x0A,  0xB8, 0x08, /* Ch 0 D1R */
        0xE0, 0x2A,  0xE8, 0x2A,  0xF0, 0x2A,  0xF8, 0x1A, /* Ch 0 D1L/RR */
        0x41, 0x12,  0x49, 0x01,  0x51, 0x32,  0x59, 0x01,
        0x61, 0x16,  0x69, 0x0A,  0x71, 0x14,  0x79, 0x0A, /* Ch 1 TL */
        0x81, 0x1E,  0x89, 0x1E,  0x91, 0x1E,  0x99, 0x1E, /* Ch 1 AR */
        0xA1, 0x08,  0xA9, 0x06,  0xB1, 0x08,  0xB9, 0x06, /* Ch 1 D1R */
        0xE1, 0x28,  0xE9, 0x18,  0xF1, 0x28,  0xF9, 0x18, /* Ch 1 D1L/RR */
        0xFF
    };
    for (u32 i = 0; i < sizeof(ympatch); i++)
        ZROM_BUF[0x0100u + i] = ympatch[i];

    /* 16-step Konami Gradius-inspired synth bass ($0140) & brass lead ($0150) KC notes */
    static const u8 bass_kc[16] = {
        0x1A, 0x1A, 0x2A, 0x1A,  0x1D, 0x1D, 0x2D, 0x1D,
        0x20, 0x20, 0x30, 0x20,  0x22, 0x20, 0x1D, 0x18
    };
    static const u8 lead_kc[16] = {
        0x4A, 0x4E, 0x51, 0x56,  0x55, 0x51, 0x4E, 0x51,
        0x56, 0x58, 0x5A, 0x58,  0x56, 0x55, 0x51, 0x4E
    };
    for (int i = 0; i < 16; i++) {
        ZROM_BUF[0x0140u + i] = bass_kc[i];
        ZROM_BUF[0x0150u + i] = lead_kc[i];
    }
    S.zrom_size = 0x2000u;
}

static u32 emit_bcc_w(u8 *rom, u32 *p, u16 op16)
{
    emit16(rom, p, (u16)(op16 & 0xFF00u));
    u32 at = *p;
    emit16(rom, p, 0u);
    return at;
}

static void patch_bcc_w(u8 *rom, u32 at, u32 target)
{
    u32 tmp = at;
    emit16(rom, &tmp, (u16)(s16)((s32)target - (s32)at));
}

static void emit_dbf(u8 *rom, u32 *p, u32 dn, u32 loop_start)
{
    emit16(rom, p, (u16)(0x51C8u | (dn & 7u)));
    u32 at = *p;
    emit16(rom, p, (u16)(s16)((s32)loop_start - (s32)at));
}

static void build_builtin_68k_rom(void)
{
    /* Assemble genuine Motorola 68000 machine code for "VIPER STRIKE GX" into ROM_BUF! */
    kon_zero(ROM_BUF, 0x10000u);
    u32 p = 0;

    /* Vectors $000000..$0000FF: SSP = $10FFF0, PC = $000400, Level 5 VBlank = $000600, others = $0005FA (RTE) */
    emit32(ROM_BUF, &p, 0x0010FFF0u);
    emit32(ROM_BUF, &p, 0x00000400u);
    while (p < 0x74u)
        emit32(ROM_BUF, &p, 0x000005FAu);
    emit32(ROM_BUF, &p, 0x00000600u);   /* Vector 29 (Level 5 Autovector VBlank) */
    while (p < 0x100u)
        emit32(ROM_BUF, &p, 0x000005FAu);

    /* $000100: Palette table (64 colors: 4 x 16-color palettes in Konami 0BBBBBGGGGGRRRRR) */
    p = 0x0100u;
    static const u16 pal_init[64] = {
        /* Pal 0 (Layer F HUD: white/cyan/gold/navy) */
        0x0421, 0x7FFF, 0x7FE0, 0x1863, 0x03FF, 0x02BF, 0x7E00, 0x03E0,
        0x5AD6, 0x01DF, 0x03FF, 0x7FFF, 0x7C1F, 0x001F, 0x4210, 0x0000,
        /* Pal 1 (Layer A Fortress: steel blue, purple armor, glowing plasma) */
        0x0000, 0x18C6, 0x294A, 0x39CE, 0x1488, 0x4E73, 0x7FE0, 0x6539,
        0x2084, 0x01DF, 0x02FF, 0x2FFF, 0x7C1F, 0x03E0, 0x5EF7, 0x0000,
        /* Pal 2 (Layer B Nebula Starfield: deep indigo, stars, neon grid) */
        0x0421, 0x7FFF, 0x7FE0, 0x318C, 0x7FFF, 0x5EF7, 0x7E28, 0x3FE8,
        0x28A6, 0x310A, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        /* Pal 3 (Sprites: Vic Viper white/blue, cyan laser, orange Options, Big Core & shadow pen 15) */
        0x0000, 0x7FFF, 0x7E90, 0x5188, 0x4018, 0x681F, 0x7FE0, 0x4A52,
        0x2108, 0x019F, 0x02DF, 0x3FFF, 0x4C1F, 0x001F, 0x7FFF, 0x0000
    };
    for (int i = 0; i < 64; i++)
        emit16(ROM_BUF, &p, pal_init[i]);

    /* $000180: HUD Banner strings (38 chars each) */
    p = 0x0180u;
    static const char hud_top[] = " 1UP 000000   VIPER STRIKE GX   STG 01";
    static const char hud_bot[] = " [SPD][MSL][DBL][LSR][OPT]  KONAMI 68K";
    for (int i = 0; i < 38; i++)
        emit16(ROM_BUF, &p, (u8)hud_top[i]);
    for (int i = 0; i < 38; i++)
        emit16(ROM_BUF, &p, (u8)hud_bot[i]);

    /* $000400: Reset Entry Point */
    p = 0x0400u;
    emit16(ROM_BUF, &p, 0x41F9u); emit32(ROM_BUF, &p, 0x00000100u); /* LEA $000100, A0 */
    emit16(ROM_BUF, &p, 0x43F9u); emit32(ROM_BUF, &p, 0x00120000u); /* LEA $120000, A1 */
    emit16(ROM_BUF, &p, 0x703Fu);                                   /* MOVEQ #63, D0 */
    u32 l_pal = p;
    emit16(ROM_BUF, &p, 0x32D8u);                                   /* MOVE.W (A0)+, (A1)+ */
    emit_dbf(ROM_BUF, &p, 0u, l_pal);

    /* Configure K053251 PCU1 priority ($160001/$03/$05) */
    emit16(ROM_BUF, &p, 0x13FCu); emit16(ROM_BUF, &p, 0x0038u); emit32(ROM_BUF, &p, 0x00160001u);
    emit16(ROM_BUF, &p, 0x13FCu); emit16(ROM_BUF, &p, 0x0020u); emit32(ROM_BUF, &p, 0x00160003u);
    emit16(ROM_BUF, &p, 0x13FCu); emit16(ROM_BUF, &p, 0x0010u); emit32(ROM_BUF, &p, 0x00160005u);

    /* Enable K052109 per-8-line X-scroll ($1C3901 = 0x12) & VBlank IRQ ($1C3A01 = 0x04) */
    emit16(ROM_BUF, &p, 0x13FCu); emit16(ROM_BUF, &p, 0x0012u); emit32(ROM_BUF, &p, 0x001C3901u);
    emit16(ROM_BUF, &p, 0x13FCu); emit16(ROM_BUF, &p, 0x0004u); emit32(ROM_BUF, &p, 0x001C3A01u);

    /* Populate Layer B (64x32 starfield/grid: color=$20 at $1C2001, code=128+((idx^(idx>>3))&7) at $1C6001) */
    emit16(ROM_BUF, &p, 0x43F9u); emit32(ROM_BUF, &p, 0x001C2001u);
    emit16(ROM_BUF, &p, 0x45F9u); emit32(ROM_BUF, &p, 0x001C6001u);
    emit16(ROM_BUF, &p, 0x303Cu); emit16(ROM_BUF, &p, 2047u);
    emit16(ROM_BUF, &p, 0x7207u);
    u32 l_lb = p;
    emit16(ROM_BUF, &p, 0x12BCu); emit16(ROM_BUF, &p, 0x0020u);
    emit16(ROM_BUF, &p, 0x3400u);
    emit16(ROM_BUF, &p, 0xE64Au);
    emit16(ROM_BUF, &p, 0xB142u);
    emit16(ROM_BUF, &p, 0xC441u);
    emit16(ROM_BUF, &p, 0x0642u); emit16(ROM_BUF, &p, 0x0080u);
    emit16(ROM_BUF, &p, 0x1482u);
    emit16(ROM_BUF, &p, 0x5489u);
    emit16(ROM_BUF, &p, 0x548Au);
    emit_dbf(ROM_BUF, &p, 0u, l_lb);

    /* Populate Layer A (top & bottom armored fortress + crystals on rows 2..3 and 24..25) */
    emit16(ROM_BUF, &p, 0x43F9u); emit32(ROM_BUF, &p, 0x001C1101u);
    emit16(ROM_BUF, &p, 0x45F9u); emit32(ROM_BUF, &p, 0x001C5101u);
    emit16(ROM_BUF, &p, 0x703Fu);
    u32 l_la = p;
    emit16(ROM_BUF, &p, 0x12BCu); emit16(ROM_BUF, &p, 0x0010u);
    emit16(ROM_BUF, &p, 0x14BCu); emit16(ROM_BUF, &p, 140u);
    emit16(ROM_BUF, &p, 0x137Cu); emit16(ROM_BUF, &p, 0x0010u); emit16(ROM_BUF, &p, 0x0080u);
    emit16(ROM_BUF, &p, 0x157Cu); emit16(ROM_BUF, &p, 143u);    emit16(ROM_BUF, &p, 0x0080u);
    emit16(ROM_BUF, &p, 0x137Cu); emit16(ROM_BUF, &p, 0x0010u); emit16(ROM_BUF, &p, 0x0B00u);
    emit16(ROM_BUF, &p, 0x157Cu); emit16(ROM_BUF, &p, 142u);    emit16(ROM_BUF, &p, 0x0B00u);
    emit16(ROM_BUF, &p, 0x137Cu); emit16(ROM_BUF, &p, 0x0010u); emit16(ROM_BUF, &p, 0x0B80u);
    emit16(ROM_BUF, &p, 0x157Cu); emit16(ROM_BUF, &p, 141u);    emit16(ROM_BUF, &p, 0x0B80u);
    emit16(ROM_BUF, &p, 0x5489u);
    emit16(ROM_BUF, &p, 0x548Au);
    emit_dbf(ROM_BUF, &p, 0u, l_la);

    /* Populate Layer F HUD top row (row 1: $1C4081) & bottom row (row 26: $1C4D01) from $000180 */
    emit16(ROM_BUF, &p, 0x41F9u); emit32(ROM_BUF, &p, 0x00000180u);
    emit16(ROM_BUF, &p, 0x43F9u); emit32(ROM_BUF, &p, 0x001C4081u);
    emit16(ROM_BUF, &p, 0x45F9u); emit32(ROM_BUF, &p, 0x001C4D01u);
    emit16(ROM_BUF, &p, 0x7025u);
    u32 l_hud = p;
    emit16(ROM_BUF, &p, 0x3218u);
    emit16(ROM_BUF, &p, 0x1281u);
    emit16(ROM_BUF, &p, 0x3428u); emit16(ROM_BUF, &p, 0x004Au);
    emit16(ROM_BUF, &p, 0x1482u);
    emit16(ROM_BUF, &p, 0x5489u);
    emit16(ROM_BUF, &p, 0x548Au);
    emit_dbf(ROM_BUF, &p, 0u, l_hud);

    /* Initialize game state in Work RAM ($100000) */
    emit16(ROM_BUF, &p, 0x41F9u); emit32(ROM_BUF, &p, 0x00100000u);
    emit16(ROM_BUF, &p, 0x4290u);
    emit16(ROM_BUF, &p, 0x317Cu); emit16(ROM_BUF, &p, 44u);     emit16(ROM_BUF, &p, 2u);
    emit16(ROM_BUF, &p, 0x317Cu); emit16(ROM_BUF, &p, 104u);    emit16(ROM_BUF, &p, 4u);
    emit16(ROM_BUF, &p, 0x317Cu); emit16(ROM_BUF, &p, 0xFFFFu); emit16(ROM_BUF, &p, 6u);
    emit16(ROM_BUF, &p, 0x317Cu); emit16(ROM_BUF, &p, 92u);     emit16(ROM_BUF, &p, 10u);
    emit16(ROM_BUF, &p, 0x317Cu); emit16(ROM_BUF, &p, 1u);      emit16(ROM_BUF, &p, 12u);

    /* Unmask interrupts (SR = $2000) and enter idle STOP loop */
    emit16(ROM_BUF, &p, 0x46FCu); emit16(ROM_BUF, &p, 0x2000u);
    u32 l_idle = p;
    emit16(ROM_BUF, &p, 0x4E72u); emit16(ROM_BUF, &p, 0x2000u);
    u32 br_idle = emit_bcc_w(ROM_BUF, &p, 0x6000u);
    patch_bcc_w(ROM_BUF, br_idle, l_idle);

    /* $0005FA: Default exception RTE */
    p = 0x05FAu;
    emit16(ROM_BUF, &p, 0x4E73u);

    /* $000600: Level 5 VBlank Interrupt Service Routine (60 Hz game update!) */
    p = 0x0600u;
    emit16(ROM_BUF, &p, 0x48E7u); emit16(ROM_BUF, &p, 0xFFFEu);
    emit16(ROM_BUF, &p, 0x41F9u); emit32(ROM_BUF, &p, 0x00100000u);

    /* 1. Advance frame_cnt & update K052109 multi-band parallax X-scroll */
    emit16(ROM_BUF, &p, 0x5250u);
    emit16(ROM_BUF, &p, 0x3010u);
    emit16(ROM_BUF, &p, 0x3200u);
    emit16(ROM_BUF, &p, 0xE341u);
    emit16(ROM_BUF, &p, 0x43F9u); emit32(ROM_BUF, &p, 0x001C3401u);
    emit16(ROM_BUF, &p, 0x45F9u); emit32(ROM_BUF, &p, 0x001C7401u);
    emit16(ROM_BUF, &p, 0x741Bu);
    u32 l_scr = p;
    emit16(ROM_BUF, &p, 0x3601u);
    emit16(ROM_BUF, &p, 0xE04Bu);
    emit16(ROM_BUF, &p, 0x1283u);
    emit16(ROM_BUF, &p, 0x1341u); emit16(ROM_BUF, &p, 0x0002u);
    emit16(ROM_BUF, &p, 0x3600u);
    emit16(ROM_BUF, &p, 0x3802u);
    emit16(ROM_BUF, &p, 0x0244u); emit16(ROM_BUF, &p, 0x0003u);
    emit16(ROM_BUF, &p, 0x3A00u);
    emit16(ROM_BUF, &p, 0xE86Du);
    emit16(ROM_BUF, &p, 0xD645u);
    emit16(ROM_BUF, &p, 0x3803u);
    emit16(ROM_BUF, &p, 0xE04Cu);
    emit16(ROM_BUF, &p, 0x1484u);
    emit16(ROM_BUF, &p, 0x1543u); emit16(ROM_BUF, &p, 0x0002u);
    emit16(ROM_BUF, &p, 0x43E9u); emit16(ROM_BUF, &p, 0x0020u);
    emit16(ROM_BUF, &p, 0x45EAu); emit16(ROM_BUF, &p, 0x0020u);
    emit_dbf(ROM_BUF, &p, 2u, l_scr);

    /* 2. Read JAMMA Player 1 inputs ($140003, active LOW) & move Vic Viper */
    emit16(ROM_BUF, &p, 0x1239u); emit32(ROM_BUF, &p, 0x00140003u);
    emit16(ROM_BUF, &p, 0x4601u);
    emit16(ROM_BUF, &p, 0x3428u); emit16(ROM_BUF, &p, 2u);
    emit16(ROM_BUF, &p, 0x3628u); emit16(ROM_BUF, &p, 4u);

    /* Left (b0) */
    emit16(ROM_BUF, &p, 0x0801u); emit16(ROM_BUF, &p, 0u);
    u32 b_no_l = emit_bcc_w(ROM_BUF, &p, 0x6700u);
    emit16(ROM_BUF, &p, 0x5542u);
    emit16(ROM_BUF, &p, 0x0C42u); emit16(ROM_BUF, &p, 12u);
    u32 b_lok = emit_bcc_w(ROM_BUF, &p, 0x6C00u);
    emit16(ROM_BUF, &p, 0x740Cu);
    patch_bcc_w(ROM_BUF, b_lok, p);
    patch_bcc_w(ROM_BUF, b_no_l, p);

    /* Right (b1) */
    emit16(ROM_BUF, &p, 0x0801u); emit16(ROM_BUF, &p, 1u);
    u32 b_no_r = emit_bcc_w(ROM_BUF, &p, 0x6700u);
    emit16(ROM_BUF, &p, 0x5442u);
    emit16(ROM_BUF, &p, 0x0C42u); emit16(ROM_BUF, &p, 200u);
    u32 b_rok = emit_bcc_w(ROM_BUF, &p, 0x6F00u);
    emit16(ROM_BUF, &p, 0x343Cu); emit16(ROM_BUF, &p, 200u);
    patch_bcc_w(ROM_BUF, b_rok, p);
    patch_bcc_w(ROM_BUF, b_no_r, p);

    /* Up (b2) */
    emit16(ROM_BUF, &p, 0x0801u); emit16(ROM_BUF, &p, 2u);
    u32 b_no_u = emit_bcc_w(ROM_BUF, &p, 0x6700u);
    emit16(ROM_BUF, &p, 0x5543u);
    emit16(ROM_BUF, &p, 0x0C43u); emit16(ROM_BUF, &p, 36u);
    u32 b_uok = emit_bcc_w(ROM_BUF, &p, 0x6C00u);
    emit16(ROM_BUF, &p, 0x7624u);
    patch_bcc_w(ROM_BUF, b_uok, p);
    patch_bcc_w(ROM_BUF, b_no_u, p);

    /* Down (b3) */
    emit16(ROM_BUF, &p, 0x0801u); emit16(ROM_BUF, &p, 3u);
    u32 b_no_d = emit_bcc_w(ROM_BUF, &p, 0x6700u);
    emit16(ROM_BUF, &p, 0x5443u);
    emit16(ROM_BUF, &p, 0x0C43u); emit16(ROM_BUF, &p, 172u);
    u32 b_dok = emit_bcc_w(ROM_BUF, &p, 0x6F00u);
    emit16(ROM_BUF, &p, 0x363Cu); emit16(ROM_BUF, &p, 172u);
    patch_bcc_w(ROM_BUF, b_dok, p);
    patch_bcc_w(ROM_BUF, b_no_d, p);

    /* Demo attract auto-pilot weave when no pad input pressed (D1 == 0) */
    emit16(ROM_BUF, &p, 0x4A01u);
    u32 b_man = emit_bcc_w(ROM_BUF, &p, 0x6600u);
    emit16(ROM_BUF, &p, 0x0800u); emit16(ROM_BUF, &p, 6u);
    u32 b_aw = emit_bcc_w(ROM_BUF, &p, 0x6700u);
    emit16(ROM_BUF, &p, 0x5243u);
    u32 b_aw_done = emit_bcc_w(ROM_BUF, &p, 0x6000u);
    patch_bcc_w(ROM_BUF, b_aw, p);
    emit16(ROM_BUF, &p, 0x5343u);
    patch_bcc_w(ROM_BUF, b_aw_done, p);
    emit16(ROM_BUF, &p, 0x0001u); emit16(ROM_BUF, &p, 0x0010u);
    patch_bcc_w(ROM_BUF, b_man, p);

    emit16(ROM_BUF, &p, 0x3142u); emit16(ROM_BUF, &p, 2u);
    emit16(ROM_BUF, &p, 0x3143u); emit16(ROM_BUF, &p, 4u);

    /* 3. Twin-Laser firing & movement */
    emit16(ROM_BUF, &p, 0x3828u); emit16(ROM_BUF, &p, 6u);
    u32 b_chk_fire = emit_bcc_w(ROM_BUF, &p, 0x6B00u);
    emit16(ROM_BUF, &p, 0x0644u); emit16(ROM_BUF, &p, 8u);
    emit16(ROM_BUF, &p, 0x0C44u); emit16(ROM_BUF, &p, 304u);
    u32 b_laser_in = emit_bcc_w(ROM_BUF, &p, 0x6D00u);
    emit16(ROM_BUF, &p, 0x383Cu); emit16(ROM_BUF, &p, 0xFFFFu);
    u32 b_save_l1 = emit_bcc_w(ROM_BUF, &p, 0x6000u);

    patch_bcc_w(ROM_BUF, b_chk_fire, p);
    emit16(ROM_BUF, &p, 0x0801u); emit16(ROM_BUF, &p, 4u);
    u32 b_no_fire = emit_bcc_w(ROM_BUF, &p, 0x6700u);
    emit16(ROM_BUF, &p, 0x3802u);
    emit16(ROM_BUF, &p, 0x0644u); emit16(ROM_BUF, &p, 16u);
    emit16(ROM_BUF, &p, 0x3143u); emit16(ROM_BUF, &p, 8u);
    emit16(ROM_BUF, &p, 0x5468u); emit16(ROM_BUF, &p, 0x0016u);
    emit16(ROM_BUF, &p, 0x3A28u); emit16(ROM_BUF, &p, 0x0016u);
    emit16(ROM_BUF, &p, 0x0045u); emit16(ROM_BUF, &p, 0x0001u);
    emit16(ROM_BUF, &p, 0x13C5u); emit32(ROM_BUF, &p, 0x001A0001u);

    patch_bcc_w(ROM_BUF, b_laser_in, p);
    patch_bcc_w(ROM_BUF, b_save_l1, p);
    patch_bcc_w(ROM_BUF, b_no_fire, p);
    emit16(ROM_BUF, &p, 0x3144u); emit16(ROM_BUF, &p, 6u);

    /* 4. Big Core Boss vertical patrol + hit detection */
    emit16(ROM_BUF, &p, 0x3A28u); emit16(ROM_BUF, &p, 10u);
    emit16(ROM_BUF, &p, 0xDA68u); emit16(ROM_BUF, &p, 12u);
    emit16(ROM_BUF, &p, 0x0C45u); emit16(ROM_BUF, &p, 44u);
    u32 b_bmin = emit_bcc_w(ROM_BUF, &p, 0x6C00u);
    emit16(ROM_BUF, &p, 0x317Cu); emit16(ROM_BUF, &p, 1u); emit16(ROM_BUF, &p, 12u);
    patch_bcc_w(ROM_BUF, b_bmin, p);
    emit16(ROM_BUF, &p, 0x0C45u); emit16(ROM_BUF, &p, 148u);
    u32 b_bmax = emit_bcc_w(ROM_BUF, &p, 0x6F00u);
    emit16(ROM_BUF, &p, 0x317Cu); emit16(ROM_BUF, &p, 0xFFFFu); emit16(ROM_BUF, &p, 12u);
    patch_bcc_w(ROM_BUF, b_bmax, p);
    emit16(ROM_BUF, &p, 0x3145u); emit16(ROM_BUF, &p, 10u);

    emit16(ROM_BUF, &p, 0x0C44u); emit16(ROM_BUF, &p, 224u);
    u32 b_no_hit1 = emit_bcc_w(ROM_BUF, &p, 0x6D00u);
    emit16(ROM_BUF, &p, 0x3C28u); emit16(ROM_BUF, &p, 8u);
    emit16(ROM_BUF, &p, 0x9C45u);
    emit16(ROM_BUF, &p, 0x0646u); emit16(ROM_BUF, &p, 8u);
    emit16(ROM_BUF, &p, 0x0C46u); emit16(ROM_BUF, &p, 32u);
    u32 b_no_hit2 = emit_bcc_w(ROM_BUF, &p, 0x6400u);

    emit16(ROM_BUF, &p, 0x317Cu); emit16(ROM_BUF, &p, 0xFFFFu); emit16(ROM_BUF, &p, 6u);
    emit16(ROM_BUF, &p, 0x5268u); emit16(ROM_BUF, &p, 14u);
    emit16(ROM_BUF, &p, 0x317Cu); emit16(ROM_BUF, &p, 16u);  emit16(ROM_BUF, &p, 16u);
    emit16(ROM_BUF, &p, 0x317Cu); emit16(ROM_BUF, &p, 232u); emit16(ROM_BUF, &p, 18u);
    emit16(ROM_BUF, &p, 0x3145u); emit16(ROM_BUF, &p, 20u);
    emit16(ROM_BUF, &p, 0x5468u); emit16(ROM_BUF, &p, 0x0016u);
    emit16(ROM_BUF, &p, 0x3C28u); emit16(ROM_BUF, &p, 0x0016u);
    emit16(ROM_BUF, &p, 0x0246u); emit16(ROM_BUF, &p, 0xFFFEu);
    emit16(ROM_BUF, &p, 0x13C6u); emit32(ROM_BUF, &p, 0x001A0001u);

    patch_bcc_w(ROM_BUF, b_no_hit1, p);
    patch_bcc_w(ROM_BUF, b_no_hit2, p);

    /* Update HUD score digits on Layer F */
    emit16(ROM_BUF, &p, 0x3C28u); emit16(ROM_BUF, &p, 14u);
    emit16(ROM_BUF, &p, 0x3E06u);
    emit16(ROM_BUF, &p, 0x0247u); emit16(ROM_BUF, &p, 0x0007u);
    emit16(ROM_BUF, &p, 0x0647u); emit16(ROM_BUF, &p, 0x0030u);
    emit16(ROM_BUF, &p, 0x13C7u); emit32(ROM_BUF, &p, 0x001C4091u);
    emit16(ROM_BUF, &p, 0xE64Eu);
    emit16(ROM_BUF, &p, 0x0246u); emit16(ROM_BUF, &p, 0x0007u);
    emit16(ROM_BUF, &p, 0x0646u); emit16(ROM_BUF, &p, 0x0030u);
    emit16(ROM_BUF, &p, 0x13C6u); emit32(ROM_BUF, &p, 0x001C408Fu);

    /* 5. Write K053245 Hardware Sprite Table ($1E0000) */
    emit16(ROM_BUF, &p, 0x43F9u); emit32(ROM_BUF, &p, 0x001E0000u);

    /* Obj 0: Vic Viper */
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x8028u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0000u);
    emit16(ROM_BUF, &p, 0x32C3u);
    emit16(ROM_BUF, &p, 0x32C2u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0040u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0040u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0003u);
    emit16(ROM_BUF, &p, 0x4259u);

    /* Pulsing Option zoom in D6: $38 + ((frame >> 1) & 15) */
    emit16(ROM_BUF, &p, 0x3C00u);
    emit16(ROM_BUF, &p, 0xE24Eu);
    emit16(ROM_BUF, &p, 0x0246u); emit16(ROM_BUF, &p, 0x000Fu);
    emit16(ROM_BUF, &p, 0x0646u); emit16(ROM_BUF, &p, 0x0038u);

    /* Obj 1: Option Top */
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x8027u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0001u);
    emit16(ROM_BUF, &p, 0x3E03u); emit16(ROM_BUF, &p, 0x0447u); emit16(ROM_BUF, &p, 18u);
    emit16(ROM_BUF, &p, 0x32C7u);
    emit16(ROM_BUF, &p, 0x3E02u); emit16(ROM_BUF, &p, 0x0447u); emit16(ROM_BUF, &p, 14u);
    emit16(ROM_BUF, &p, 0x32C7u);
    emit16(ROM_BUF, &p, 0x32C6u);
    emit16(ROM_BUF, &p, 0x32C6u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0003u);
    emit16(ROM_BUF, &p, 0x4259u);

    /* Obj 2: Option Bottom */
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x8027u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0001u);
    emit16(ROM_BUF, &p, 0x3E03u); emit16(ROM_BUF, &p, 0x0647u); emit16(ROM_BUF, &p, 18u);
    emit16(ROM_BUF, &p, 0x32C7u);
    emit16(ROM_BUF, &p, 0x3E02u); emit16(ROM_BUF, &p, 0x0447u); emit16(ROM_BUF, &p, 14u);
    emit16(ROM_BUF, &p, 0x32C7u);
    emit16(ROM_BUF, &p, 0x32C6u);
    emit16(ROM_BUF, &p, 0x32C6u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0003u);
    emit16(ROM_BUF, &p, 0x4259u);

    /* Obj 3: Twin Laser */
    emit16(ROM_BUF, &p, 0x3828u); emit16(ROM_BUF, &p, 6u);
    u32 b_las_off = emit_bcc_w(ROM_BUF, &p, 0x6B00u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x802Au);
    u32 b_las_on = emit_bcc_w(ROM_BUF, &p, 0x6000u);
    patch_bcc_w(ROM_BUF, b_las_off, p);
    emit16(ROM_BUF, &p, 0x4259u);
    patch_bcc_w(ROM_BUF, b_las_on, p);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0002u);
    emit16(ROM_BUF, &p, 0x32E8u); emit16(ROM_BUF, &p, 8u);
    emit16(ROM_BUF, &p, 0x32C4u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0040u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0028u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0003u);
    emit16(ROM_BUF, &p, 0x4259u);

    /* Obj 4: Big Core Boss (32x32, hardware shadow $0403, breathing K053245 zoom!) */
    emit16(ROM_BUF, &p, 0x3C00u);
    emit16(ROM_BUF, &p, 0xE44Eu);
    emit16(ROM_BUF, &p, 0x0246u); emit16(ROM_BUF, &p, 0x000Fu);
    emit16(ROM_BUF, &p, 0x0646u); emit16(ROM_BUF, &p, 0x0032u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x8326u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0004u);
    emit16(ROM_BUF, &p, 0x32C5u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 232u);
    emit16(ROM_BUF, &p, 0x32C6u);
    emit16(ROM_BUF, &p, 0x32C6u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0403u);
    emit16(ROM_BUF, &p, 0x4259u);

    /* Obj 5..7: 3 Bacterian Spinner enemies */
    for (int e = 0; e < 3; e++) {
        emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x8025u);
        emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0003u);
        emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, (u16)(56 + e * 48));
        emit16(ROM_BUF, &p, 0x3E00u);
        emit16(ROM_BUF, &p, 0xE347u);
        emit16(ROM_BUF, &p, 0x0647u); emit16(ROM_BUF, &p, (u16)(e * 85));
        emit16(ROM_BUF, &p, 0x0247u); emit16(ROM_BUF, &p, 0x00FFu);
        emit16(ROM_BUF, &p, 0x4447u);
        emit16(ROM_BUF, &p, 0x0647u); emit16(ROM_BUF, &p, 288u);
        emit16(ROM_BUF, &p, 0x32C7u);
        emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0040u);
        emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0040u);
        emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0003u);
        emit16(ROM_BUF, &p, 0x4259u);
    }

    /* Obj 8: Boss Aimed Plasma Shot */
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x8029u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0008u);
    emit16(ROM_BUF, &p, 0x3E05u); emit16(ROM_BUF, &p, 0x0647u); emit16(ROM_BUF, &p, 10u);
    emit16(ROM_BUF, &p, 0x32C7u);
    emit16(ROM_BUF, &p, 0x3E00u); emit16(ROM_BUF, &p, 0xE547u);
    emit16(ROM_BUF, &p, 0x0247u); emit16(ROM_BUF, &p, 0x00FFu);
    emit16(ROM_BUF, &p, 0x4447u); emit16(ROM_BUF, &p, 0x0647u); emit16(ROM_BUF, &p, 232u);
    emit16(ROM_BUF, &p, 0x32C7u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0040u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0040u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0003u);
    emit16(ROM_BUF, &p, 0x4259u);

    /* Obj 9: Expanding Hardware-Zoomed Explosion Ring */
    emit16(ROM_BUF, &p, 0x3E28u); emit16(ROM_BUF, &p, 16u);
    u32 b_no_exp = emit_bcc_w(ROM_BUF, &p, 0x6F00u);
    emit16(ROM_BUF, &p, 0x5368u); emit16(ROM_BUF, &p, 16u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x802Fu);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0009u);
    emit16(ROM_BUF, &p, 0x32E8u); emit16(ROM_BUF, &p, 20u);
    emit16(ROM_BUF, &p, 0x32E8u); emit16(ROM_BUF, &p, 18u);
    emit16(ROM_BUF, &p, 0xE547u);
    emit16(ROM_BUF, &p, 0x0647u); emit16(ROM_BUF, &p, 0x0014u);
    emit16(ROM_BUF, &p, 0x32C7u);
    emit16(ROM_BUF, &p, 0x32C7u);
    emit16(ROM_BUF, &p, 0x32FCu); emit16(ROM_BUF, &p, 0x0003u);
    emit16(ROM_BUF, &p, 0x4259u);
    u32 b_exp_done = emit_bcc_w(ROM_BUF, &p, 0x6000u);

    patch_bcc_w(ROM_BUF, b_no_exp, p);
    emit16(ROM_BUF, &p, 0x4299u);
    emit16(ROM_BUF, &p, 0x4259u);
    patch_bcc_w(ROM_BUF, b_exp_done, p);

    emit16(ROM_BUF, &p, 0x4CDFu); emit16(ROM_BUF, &p, 0x7FFFu);
    emit16(ROM_BUF, &p, 0x4E73u);

    S.rom_size = 0x10000u;
}

/* ---- MAME .zip Romset Detector & Unpacker ---- */
struct kon_game_def {
    const char *zip_tag;
    const char *prefix;
    const char *title;
    u8 board, sub;
    u16 w, h;
};

static const struct kon_game_def kon_games[] = {
    {"ssriders", "064", "Sunset Riders (Konami GX064)",           KON_BOARD_SSRIDERS, KON_SUB_SSRIDERS, 304, 224},
    {"tmnt2",    "063", "TMNT: Turtles in Time (Konami GX063)",   KON_BOARD_SSRIDERS, KON_SUB_TMNT2,    304, 224},
    {"xmen",     "065", "X-Men (Konami GX065)",                   KON_BOARD_SSRIDERS, KON_SUB_XMEN,     304, 224},
    {"lgtnfght", "939", "Lightning Fighters (Konami GX939)",      KON_BOARD_SSRIDERS, KON_SUB_GENERIC,  304, 224},
    {"blswhstl", "060", "Detana!! TwinBee (Konami GX060)",        KON_BOARD_SSRIDERS, KON_SUB_GENERIC,  304, 224},
    {"tmnt",     "963", "Teenage Mutant Ninja Turtles (GX963)",   KON_BOARD_TMNT,     KON_SUB_TMNT,     304, 224},
    {"mia",      "875", "M.I.A. Missing in Action (GX875)",       KON_BOARD_TMNT,     KON_SUB_MIA,      304, 224},
    {"punkshot", "907", "Punk Shot (Konami GX907)",               KON_BOARD_TMNT,     KON_SUB_GENERIC,  304, 224},
    {"nemesis",  "400", "Nemesis / Gradius (Konami GX400)",       KON_BOARD_NEMESIS,  KON_SUB_NEMESIS,  256, 224},
    {"gradius",  "400", "Gradius (Konami GX400)",                 KON_BOARD_NEMESIS,  KON_SUB_NEMESIS,  256, 224},
    {"twinbee",  "412", "TwinBee (Konami GX412)",                 KON_BOARD_NEMESIS,  KON_SUB_NEMESIS,  256, 224},
    {"contra",   "633", "Contra (Konami GX633)",                  KON_BOARD_CONTRA,   KON_SUB_CONTRA,   280, 224},
    {"gryzor",   "633", "Gryzor (Konami GX633)",                  KON_BOARD_CONTRA,   KON_SUB_CONTRA,   280, 224}
};

static const struct kon_game_def *kon_match_zip(const u8 *zip, u32 size, const char *path)
{
    const char *bn = kon_basename(path);
    for (u32 g = 0; g < sizeof(kon_games) / sizeof(kon_games[0]); g++) {
        if (kon_starts_ci(bn, kon_games[g].zip_tag)) {
            /* Distinguish tmnt vs tmnt2! */
            if (g == 5 && kon_starts_ci(bn, "tmnt2")) continue;
            return &kon_games[g];
        }
    }
    if (zip && size >= 30u && zip_is(zip, size)) {
        u32 cnt = zip_count(zip, size);
        for (u32 i = 0; i < cnt && i < 32u; i++) {
            char mname[96];
            u32 msz = 0;
            if (zip_unpack_at(zip, size, i, 0, 0, &msz, mname, sizeof(mname)) != 0)
                continue;
            const char *mb = kon_basename(mname);
            if (kon_ci_has(mb, "konami") || kon_starts_ci(mb, "k052109"))
                return &kon_games[0];
            for (u32 g = 0; g < sizeof(kon_games) / sizeof(kon_games[0]); g++)
                if (kon_starts_ci(mb, kon_games[g].prefix))
                    return &kon_games[g];
        }
    }
    return 0;
}

int konami_is_zip(const u8 *zip, u32 size, const char *name)
{
    return kon_match_zip(zip, size, name) != 0;
}

static void kon_decode_packed_tiles(const u8 *src, u32 bytes)
{
    /* Decode linear 4bpp packed 8x8 tiles (32 bytes/tile, 2 pixels/byte) into TILE_BUF */
    u32 n = bytes >> 5;
    if (n > KON_MAX_TILES) n = KON_MAX_TILES;
    for (u32 t = 0; t < n; t++) {
        const u8 *p = src + t * 32u;
        u8 nz = 0;
        for (u32 y = 0; y < 8u; y++) {
            u32 row = 0;
            for (u32 i = 0; i < 4u; i++) {
                u8 b = p[y * 4u + i];
                u32 p0 = (b >> 4) & 0x0Fu;
                u32 p1 = b & 0x0Fu;
                row |= (p0 << (i * 8u)) | (p1 << (i * 8u + 4u));
            }
            TILE_BUF[t * 8u + y] = row;
            if (row) nz = 1u;
        }
        M->tile_nz[t] = nz;
    }
    S.tile_count = n;
}

static void kon_decode_packed_sprites(const u8 *src, u32 bytes)
{
    /* Copy/decode 16x16 4bpp sprite cells (128 bytes/cell: 8 bytes/row, low nibble=even x, high nibble=odd x) */
    u32 n = bytes >> 7;
    if (n > KON_MAX_SPR16) n = KON_MAX_SPR16;
    for (u32 c = 0; c < n; c++) {
        const u8 *sp = src + c * 128u;
        u8 *dp = &SPR_BUF[c * 128u];
        u8 nz = 0;
        for (u32 i = 0; i < 128u; i++) {
            u8 b = sp[i];
            /* Accept standard MSB-first nibble order: swap so low nibble = left pixel, high nibble = right pixel */
            u8 sw = (u8)(((b >> 4) & 0x0Fu) | ((b & 0x0Fu) << 4));
            dp[i] = sw;
            if (sw) nz = 1u;
        }
        M->spr_nz[c] = nz;
    }
    S.spr16_count = n;
}

static const char *kon_load_zip(const u8 *zip, u32 size, const char *path)
{
    const struct kon_game_def *gd = kon_match_zip(zip, size, path);
    S.board = gd ? gd->board : KON_BOARD_SSRIDERS;
    S.sub   = gd ? gd->sub   : KON_SUB_GENERIC;
    S.scr_w = gd ? gd->w     : 304;
    S.scr_h = gd ? gd->h     : 224;

    u32 cnt = zip_count(zip, size);
    if (!cnt) return "empty or invalid Konami .zip archive";

    /* First check for clean-room explicit role ROMs inside .zip (main.rom / main_even+main_odd, z80.rom,
       tiles.rom, sprites.rom, pcm.rom, contra.rom, prom.rom) OR MAME split ROM chips! */
    int has_explicit = 0;
    u32 rom_cur = 0, tile_raw_cur = 0, spr_raw_cur = 0;
    u8 *even_odd[2] = {0, 0};
    u32 eo_sz[2] = {0, 0};

    kon_zero(ROM_BUF, 0x100000u);
    kon_zero(ZROM_BUF, 0x20000u);

    for (u32 i = 0; i < cnt; i++) {
        char mname[96];
        u32 msz = 0;
        if (zip_unpack_at(zip, size, i, 0, 0, &msz, mname, sizeof(mname)) != 0 || !msz)
            continue;
        if (msz > KON_STAGE_CAP) continue;
        KON_POLL();
        const char *bn = kon_basename(mname);

        if (kon_ci_has(bn, "board_contra")) { S.board = KON_BOARD_CONTRA; S.sub = KON_SUB_CONTRA; S.scr_w = 280; continue; }
        if (kon_ci_has(bn, "board_tmnt"))   { S.board = KON_BOARD_TMNT;   S.sub = KON_SUB_TMNT;   S.scr_w = 304; continue; }
        if (kon_ci_has(bn, "board_nemesis")){ S.board = KON_BOARD_NEMESIS;S.sub = KON_SUB_NEMESIS;S.scr_w = 256; continue; }

        if (zip_unpack_at(zip, size, i, ZIP_STAGE, KON_STAGE_CAP, &msz, mname, sizeof(mname)) != 0)
            continue;

        if (kon_starts_ci(bn, "main.rom") || kon_starts_ci(bn, "68k.rom") || kon_starts_ci(bn, "6809.rom")) {
            has_explicit = 1;
            u32 lim = msz > KON_ROM_CAP ? KON_ROM_CAP : msz;
            if (S.board == KON_BOARD_CONTRA) {
                for (u32 b = 0; b < lim; b++) ROM_BUF[b] = ZIP_STAGE[b];
            } else {
                /* Convert big-endian 68000 binary to m68k.inc word-swapped layout */
                for (u32 b = 0; b + 1u < lim; b += 2u) {
                    ROM_BUF[b]     = ZIP_STAGE[b + 1u];
                    ROM_BUF[b + 1] = ZIP_STAGE[b];
                }
            }
            S.rom_size = lim;
        } else if (kon_starts_ci(bn, "z80.rom") || kon_starts_ci(bn, "snd.rom") ||
                   kon_ci_has(bn, "01.") || kon_ci_has(bn, "_01")) {
            u32 lim = msz > KON_ZROM_CAP ? KON_ZROM_CAP : msz;
            for (u32 b = 0; b < lim; b++) ZROM_BUF[b] = ZIP_STAGE[b];
            S.zrom_size = lim;
        } else if (kon_starts_ci(bn, "tiles.rom") || kon_starts_ci(bn, "k052109.rom") || kon_starts_ci(bn, "k007121.rom")) {
            has_explicit = 1;
            kon_decode_packed_tiles(ZIP_STAGE, msz);
        } else if (kon_starts_ci(bn, "sprites.rom") || kon_starts_ci(bn, "k053245.rom") || kon_starts_ci(bn, "k051960.rom")) {
            has_explicit = 1;
            kon_decode_packed_sprites(ZIP_STAGE, msz);
        } else if (kon_starts_ci(bn, "pcm.rom") || kon_starts_ci(bn, "k053260.rom") || kon_starts_ci(bn, "k007232.rom")) {
            u32 lim = msz > KON_PCM_CAP ? KON_PCM_CAP : msz;
            for (u32 b = 0; b < lim; b++) PCM_BUF[b] = ZIP_STAGE[b];
            S.pcm_size = lim;
        }
    }

    /* Fallback MAME split-chip heuristic for any regions not provided via explicit names */
    if (!S.rom_size || !S.tile_count) {
        (void)has_explicit;
        for (u32 i = 0; i < cnt; i++) {
            char mname[96];
            u32 msz = 0;
            if (zip_unpack_at(zip, size, i, 0, 0, &msz, mname, sizeof(mname)) != 0 || msz < 256u || msz > KON_STAGE_CAP)
                continue;
            const char *bn = kon_basename(mname);
            if (kon_starts_ci(bn, "tiles.rom") || kon_starts_ci(bn, "sprites.rom") ||
                kon_starts_ci(bn, "pcm.rom") || kon_starts_ci(bn, "z80.rom") ||
                kon_ci_has(bn, "01.") || kon_ci_has(bn, "_01"))
                continue;
            KON_POLL();
            if (zip_unpack_at(zip, size, i, ZIP_STAGE, KON_STAGE_CAP, &msz, mname, sizeof(mname)) != 0)
                continue;

            if (S.board == KON_BOARD_CONTRA) {
                if (!S.rom_size || kon_ci_has(bn, "03.") || kon_ci_has(bn, "02.")) {
                    u32 dst_off = kon_ci_has(bn, "02.") ? 0x8000u : 0u;
                    for (u32 b = 0; b < msz && dst_off + b < KON_ROM_CAP; b++)
                        ROM_BUF[dst_off + b] = ZIP_STAGE[b];
                    if (dst_off + msz > S.rom_size) S.rom_size = dst_off + msz;
                } else if (msz >= 0x10000u && tile_raw_cur == 0 && !S.tile_count) {
                    kon_decode_packed_tiles(ZIP_STAGE, msz);
                    kon_decode_packed_sprites(ZIP_STAGE, msz);
                    tile_raw_cur = msz;
                }
                continue;
            }

            /* 68000 interleaved ROM pairs (ROM_LOAD16_BYTE: >= 16 KB per chip) */
            if (!S.zrom_size && msz == 0x8000u && !even_odd[0] && rom_cur > 0) {
                for (u32 b = 0; b < msz; b++) ZROM_BUF[b] = ZIP_STAGE[b];
                S.zrom_size = msz;
            } else if (msz >= 0x4000u && msz <= 0x80000u && rom_cur < 0x100000u &&
                       (!S.rom_size || even_odd[0] || msz <= 0x40000u)) {
                if (!even_odd[0]) {
                    even_odd[0] = ROM_BUF + rom_cur;
                    eo_sz[0] = msz;
                    /* High byte of 68000 word goes to odd host byte in m68k.inc! */
                    for (u32 b = 0; b < msz; b++)
                        even_odd[0][b * 2u + 1u] = ZIP_STAGE[b];
                } else {
                    u32 pair_sz = msz < eo_sz[0] ? msz : eo_sz[0];
                    for (u32 b = 0; b < pair_sz; b++)
                        even_odd[0][b * 2u] = ZIP_STAGE[b];
                    rom_cur += eo_sz[0] * 2u;
                    S.rom_size = rom_cur;
                    even_odd[0] = 0;
                }
            } else if (msz >= 0x40000u && !S.tile_count) {
                kon_decode_packed_tiles(ZIP_STAGE, msz);
            } else if (msz >= 0x40000u && !S.spr16_count) {
                kon_decode_packed_sprites(ZIP_STAGE, msz);
            } else if (msz >= 0x20000u && !S.pcm_size) {
                u32 lim = msz > KON_PCM_CAP ? KON_PCM_CAP : msz;
                for (u32 b = 0; b < lim; b++) PCM_BUF[b] = ZIP_STAGE[b];
                S.pcm_size = lim;
                (void)spr_raw_cur;
            }
        }
    }

    if (!S.rom_size)
        return "no Konami main CPU program ROM found in .zip";

    const char *title = gd ? gd->title : "Konami Classic Arcade (.zip)";
    int k = 0;
    while (title[k] && k < (int)sizeof(S.info) - 1) {
        S.info[k] = title[k];
        k++;
    }
    S.info[k] = 0;
    return 0;
}

static void kon_setup_68k_map(void)
{
    for (int i = 0; i < 256; i++)
        rmap[i] = wmap[i] = 0;

    if (S.board == KON_BOARD_SSRIDERS) {
        /* $000000..$0FFFFF: 68000 ROM, $100000..$11FFFF: 128 KB Work RAM */
        for (int i = 0; i < 16; i++)
            rmap[i] = ROM_BUF + ((u32)i << 16);
        rmap[0x10] = wmap[0x10] = M->wram;
        rmap[0x11] = wmap[0x11] = M->wram + 0x10000u;
        rmap[0xFF] = wmap[0xFF] = M->wram;
    } else if (S.board == KON_BOARD_TMNT) {
        for (int i = 0; i < 6; i++)
            rmap[i] = ROM_BUF + ((u32)i << 16);
        rmap[0x06] = wmap[0x06] = M->wram;
    } else if (S.board == KON_BOARD_NEMESIS) {
        for (int i = 0; i < 4; i++)
            rmap[i] = ROM_BUF + ((u32)i << 16);
        rmap[0x06] = wmap[0x06] = M->wram;
    }
}

static u32 kon_pow2_mask(u32 n, u32 max_cap)
{
    if (n <= 1u) return 0u;
    u32 p = 1u;
    while (p < n && p < max_cap)
        p <<= 1;
    return p - 1u;
}

static void kon_setup_z80_map(void)
{
    u32 zr_mask = kon_pow2_mask(S.zrom_size ? S.zrom_size : 0x8000u, KON_ZROM_CAP);
    if (S.board == KON_BOARD_SSRIDERS) {
        /* $0000..$DFFF: Z80 ROM, $E000..$EFFF: 4 KB Z80 RAM */
        for (u32 p = 0; p < 56u; p++)
            M->zcpu.rd[p] = ZROM_BUF + ((p * 1024u) & zr_mask);
        for (u32 p = 56u; p < 60u; p++)
            M->zcpu.rd[p] = M->zcpu.wr[p] = M->zram + (p - 56u) * 1024u;
    } else if (S.board == KON_BOARD_TMNT || S.board == KON_BOARD_CONTRA) {
        /* $0000..$7FFF: Z80 ROM, $8000..$87FF: 2 KB Z80 RAM */
        for (u32 p = 0; p < 32u; p++)
            M->zcpu.rd[p] = ZROM_BUF + ((p * 1024u) & zr_mask);
        M->zcpu.rd[32] = M->zcpu.wr[32] = M->zram;
        M->zcpu.rd[33] = M->zcpu.wr[33] = M->zram + 1024u;
    } else { /* KON_BOARD_NEMESIS */
        /* $0000..$3FFF: Z80 ROM, $4000..$47FF: 2 KB Z80 RAM */
        for (u32 p = 0; p < 16u; p++)
            M->zcpu.rd[p] = ZROM_BUF + ((p * 1024u) & zr_mask);
        M->zcpu.rd[16] = M->zcpu.wr[16] = M->zram;
        M->zcpu.rd[17] = M->zcpu.wr[17] = M->zram + 1024u;
    }
}

void konami_reset(void)
{
    kon_zero(M->wram, sizeof(M->wram));
    kon_zero(M->k2109_ram, sizeof(M->k2109_ram));
    kon_zero(M->k2109_cell, sizeof(M->k2109_cell));
    kon_zero(M->spr_ram, sizeof(M->spr_ram));
    kon_zero(M->pal_ram, sizeof(M->pal_ram));
    kon_zero(M->pal15, sizeof(M->pal15));
    kon_zero(M->pal15_shd, sizeof(M->pal15_shd));
    kon_zero(M->gx_charram, sizeof(M->gx_charram));
    kon_zero(M->gx_tiles, sizeof(M->gx_tiles));
    kon_zero(M->gx_tile_nz, sizeof(M->gx_tile_nz));
    kon_zero(M->gx_vram, sizeof(M->gx_vram));
    kon_zero(M->k7121_ram, sizeof(M->k7121_ram));
    kon_zero(M->k7121_ctrl, sizeof(M->k7121_ctrl));
    kon_zero(M->contra_ram, sizeof(M->contra_ram));
    kon_zero(M->zram, sizeof(M->zram));

    S.tile_mask  = kon_pow2_mask(S.tile_count, KON_MAX_TILES);
    S.spr16_mask = kon_pow2_mask(S.spr16_count, KON_MAX_SPR16);
    S.pcm_mask   = kon_pow2_mask(S.pcm_size, KON_PCM_CAP);
    S.n_act_spr  = 0;

    S.jammed = 0;
    S.frame_no = 0;
    S.vblank_irq_en = 0;
    S.k2109_scrollctrl = 0;
    S.k2109_irq_en = 0;
    S.k2109_flip = 0;
    for (int i = 0; i < 4; i++) S.k2109_rombank[i] = (u8)i;
    S.spr_dx = S.spr_dy = 0;
    S.spr_bank = 0;
    kon_zero(S.pcu_regs, sizeof(S.pcu_regs));
    S.pal_base_f = 0; S.pal_base_a = 0; S.pal_base_b = 0; S.pal_base_spr = 0;
    S.pri_b = 0x10u; S.pri_a = 0x20u; S.pri_f = 0x38u;
    S.contra_bank = 0;

    /* Reset Sound Z80 + YM2151 + K053260 + K007232 + AY */
    kon_zero(&M->zcpu, sizeof(M->zcpu));
    z80_init(&M->zcpu);
    M->zcpu.read  = kon_z80_read;
    M->zcpu.write = kon_z80_write;
    M->zcpu.in    = kon_z80_in;
    M->zcpu.out   = kon_z80_out;
    M->zcpu.trap  = -1;
    kon_setup_z80_map();
    z80_reset(&M->zcpu);

    ym2151_init(&M->opm, 3579545u, S.sample_rate ? S.sample_rate : 48000u);
    kon_zero(S.k3260_regs, sizeof(S.k3260_regs));
    kon_zero(S.k3260_mail_m2s, sizeof(S.k3260_mail_m2s));
    kon_zero(S.k3260_mail_s2m, sizeof(S.k3260_mail_s2m));
    kon_zero(S.k3260, sizeof(S.k3260));
    kon_zero(S.k7232_regs, sizeof(S.k7232_regs));
    kon_zero(S.k7232, sizeof(S.k7232));
    kon_zero(S.ay, sizeof(S.ay));
    S.snd_head = S.snd_tail = 0;

    if (S.board == KON_BOARD_CONTRA) {
        m6809_reset(&M->cpu09, 0);
    } else {
        cpu_init();
        kon_setup_68k_map();
        cpu_reset();
    }
}

const char *konami_load(const u8 *image, u32 size, const char *path)
{
    u32 keep_rate = S.sample_rate;
    if (keep_rate != 48000u && keep_rate != 44100u && keep_rate != 32000u && keep_rate != 22050u)
        keep_rate = 48000u;
    kon_zero(&S, sizeof(S));
    S.sample_rate = keep_rate;

    if (!path || !*path || !image || size == 0) {
        /* Built-in playable Konami-hardware shooter: "VIPER STRIKE GX" */
        S.board = KON_BOARD_SSRIDERS;
        S.sub   = KON_SUB_GENERIC;
        S.scr_w = 304;
        S.scr_h = 224;
        build_builtin_gfx_and_pcm();
        build_builtin_z80_driver();
        build_builtin_68k_rom();
        static const char bi[] = "Viper Strike GX (Built-in Konami 68000 + K052109 + K053245 + YM2151)";
        for (u32 i = 0; i < sizeof(bi); i++)
            S.info[i] = bi[i];
        konami_reset();
        return 0;
    }

    if (zip_is(image, size)) {
        const char *err = kon_load_zip(image, size, path);
        if (err) return err;
        konami_reset();
        return 0;
    }

    return "expected a Konami arcade .zip romset";
}

void konami_pad2(u16 pad)
{
    S.pad2 = pad;
}

void konami_frame(u16 pad, u16 *picture)
{
    S.pad1 = pad;
    u8 coin_now = (pad & 0x0004u) ? 1u : 0u;
    if (coin_now && !S.coin_prev)
        S.coin_pulse = 4u;
    S.coin_prev = coin_now;

    /* 262 scanlines @ 60 Hz:
       - 68000 @ 12 MHz = ~763 cycles/line (200,000/frame)
       - MC6809E @ 3 MHz = ~190 cycles/line (49,780/frame)
       - Sound Z80 @ 3.58 MHz = ~228 cycles/line (59,736/frame) */
    const int total_lines = 262;
    const int vis_h = S.scr_h;
    const int cyc_68k = (S.board == KON_BOARD_SSRIDERS) ? 760 : 636;
    const int cyc_09  = 190;
    const int cyc_z80 = 228;

    u32 target_samples = (S.sample_rate ? S.sample_rate : 48000u) / 60u;
    u32 samp_acc = 0;

    if (S.board == KON_BOARD_CONTRA)
        M->cpu09.cycles = 0;
    else
        m.clock = 0;
    M->zcpu.cycles = 0;

    /* Pre-collect active K053245 sprites once before visible scanout */
    S.n_act_spr = 0;
    if (S.board == KON_BOARD_SSRIDERS && picture) {
        for (int s = 127; s >= 0; s--) {
            if (M->spr_ram[s * 16] & 0x80u)
                S.act_spr[S.n_act_spr++] = (u8)s;
        }
    }

    for (int line = 0; line < total_lines; line++) {
        if (S.board == KON_BOARD_CONTRA)
            m6809_run(&M->cpu09, (line + 1) * cyc_09);
        else
            cpu_run((line + 1) * cyc_68k);

        if (S.zrom_size > 0) {
            z80_run(&M->zcpu, (line + 1) * cyc_z80);
            if (ym2151_tick_timers(&M->opm, cyc_z80, 3579545u)) {
                if (S.board == KON_BOARD_SSRIDERS)
                    M->zcpu.nmi = 1;
                else
                    M->zcpu.irq = 1;
            }
        }

        if (line < vis_h && picture)
            kon_render_line(line, picture + (u32)line * (u32)S.scr_w);

        if (line == vis_h) {
            /* VBlank interrupt */
            if (S.board == KON_BOARD_CONTRA) {
                if (S.vblank_irq_en) {
                    M->cpu09.irq_line = 1;
                }
            } else if (S.board == KON_BOARD_NEMESIS) {
                if (S.vblank_irq_en) {
                    m.ipl = 1u;
                    check_pending();
                }
            } else {
                if (S.k2109_irq_en & 0x04u) {
                    m.ipl = (S.board == KON_BOARD_TMNT) ? 5u : 5u;
                    check_pending();
                }
            }
        }
        if (line == total_lines - 1 && S.board == KON_BOARD_CONTRA)
            M->cpu09.irq_line = 0;

        /* Render 48 kHz audio samples proportional to scanline (zero division) */
        samp_acc += target_samples;
        while (samp_acc >= (u32)total_lines) {
            samp_acc -= (u32)total_lines;
            s32 mix = 0;
            if (S.board == KON_BOARD_NEMESIS) {
                mix = kon_ay_step_48k(&S.ay[0]) + kon_ay_step_48k(&S.ay[1]);
            } else {
                s32 fm_l = 0, fm_r = 0;
                ym2151_sample_48khz(&M->opm, &fm_l, &fm_r);
                mix = (fm_l + fm_r) >> 1;
                if (S.board == KON_BOARD_SSRIDERS)
                    mix += k053260_step_48k();
                else if (S.board == KON_BOARD_TMNT)
                    mix += k007232_step_48k();
            }
            if (mix > 32767) mix = 32767;
            else if (mix < -32768) mix = -32768;
            if (S.snd_head - S.snd_tail < KON_SND_RING)
                M->snd_ring[S.snd_head++ & (KON_SND_RING - 1u)] = (s16)mix;
        }
    }

    if (S.coin_pulse > 0)
        S.coin_pulse--;
    S.frame_no++;
}

int konami_width(void)  { return S.scr_w ? S.scr_w : 304; }
int konami_height(void) { return S.scr_h ? S.scr_h : 224; }
const char *konami_info(void) { return S.info; }

u8 *konami_save_ram(u32 *size, int *battery)
{
    if (size) *size = 0;
    if (battery) *battery = 0;
    return 0;
}

int konami_save_changed(void) { return 0; }
int konami_jammed(void)       { return S.jammed; }

void konami_audio_rate(u32 hz)
{
    S.sample_rate = hz ? hz : 48000u;
    M->opm.sample_rate = S.sample_rate;
}

int konami_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && S.snd_tail != S.snd_head)
        out[n++] = M->snd_ring[S.snd_tail++ & (KON_SND_RING - 1u)];
    return n;
}
