/* Golden-Age Classic Arcade Multi-Board Emulator: see arcade.h.
   Pass-optimized for 594 MHz MIPS32 (0 B static .bss via EMU_RAM_PHYS,
   64-page Z80 direct pointer map, precomputed 15-bit RGB555 color PROMs,
   sequential scanline output, and 48 kHz fixed-point WSG / AY / discrete audio). */
#pragma GCC optimize("O2")
#include "arcade.h"
#include "z80.h"
#include "zip.h"

#ifndef ARCADE_HOST
#include "hw.h"
#endif

enum {
    BOARD_PACMAN = 0,
    BOARD_GALAXIAN,
    BOARD_FROGGER,
    BOARD_SCRAMBLE,
    BOARD_DKONG
};

#define SND_RING 4096

struct arcade_ws {
    struct z80 cpu;
    struct z80 scpu;                    /* Second Z80 for Konami Frogger / Scramble */

    u8  rom[0x10000];                   /* 64 KB Main Z80 ROM space */
    u8  srom[0x4000];                   /* 16 KB Sound Z80 ROM space */
    u8  ram[0x4000];                    /* Main work RAM */
    u8  sram[0x1000];                   /* Sound Z80 RAM */
    u8  vram[0x1000];                   /* Tile VRAM */
    u8  cram[0x1000];                   /* Color / Attribute RAM */
    u8  obj[0x0400];                    /* Sprite / Bullet RAM */

    u8  gfx_tiles[0x4000];              /* Tile bitplanes */
    u8  gfx_sprites[0x4000];            /* Sprite bitplanes */
    u8  color_prom[0x0400];             /* Palette + lookup PROMs */
    u8  wave_prom[0x0200];              /* Namco WSG 32x8 waveform PROM */

    /* Pre-decoded tiles & sprites (1 byte = pixel 0..3) for ultra-fast blitting! */
    u8  dec_tiles[512][64];             /* 512 x 8x8 tiles */
    u8  dec_sprites[256][256];          /* 256 x 16x16 sprites */
    u16 pal15[64];                      /* Master RGB555 colors */
    u16 clut15[256][4];                 /* 256 4-color groups -> RGB555 */

    /* Starfield (Galaxian / Scramble) */
    u16 star_x[256];
    u8  star_y[256];
    u16 star_col[256];
    u8  stars_on, star_scroll;

    /* Board state & I/O */
    u8  board, mspac_aux_en;
    int scr_w, scr_h;
    u16 pad;
    u8  irq_en, irq_vec, flip_screen, pal_bank;
    u8  coin_prev;
    u8  coin_pulse;

    /* Namco WSG 3-voice synth ($5040..$505F) */
    u8  wsg_regs[32];
    u32 wsg_acc[3];
    u8  sound_en;

    /* Konami Dual-Z80 + 8255 + AY-3-8910 */
    u8  snd_latch, snd_irq_last;
    u8  ay_sel, ay_regs[16], ay_out[3];
    u32 ay_cnt[3], ay_ncnt, ay_lfsr, ay_env_cnt;
    u8  ay_env_step, ay_env_vol;

    /* Galaxian / Donkey Kong discrete + DAC synth */
    u8  gal_pitch, gal_lfo_freq, gal_vol, gal_fire, gal_hit, gal_fs[3];
    u32 gal_tone_ph, gal_lfo_ph, gal_lfsr, gal_fire_env, gal_hit_env;
    u8  dk_walk, dk_jump, dk_stomp, dk_dac;
    u32 dk_jump_env, dk_stomp_env, dk_walk_ph;

    /* 48 kHz audio ring */
    u32 sample_rate, snd_frac;
    u32 snd_head, snd_tail;
    s16 snd_ring[SND_RING];

    u8  zip_stage[0x40000];             /* 256 KB scratch for MAME .zip unpacking */
    char info[96];
};

#ifdef ARCADE_HOST
static struct arcade_ws host_ws;
#define WS (&host_ws)
#else
#define WS ((struct arcade_ws *)KSEG0(EMU_RAM_PHYS))
#endif

static void ws_zero(void *p, u32 n)
{
    u8 *b = (u8 *)p;
    for (u32 i = 0; i < n; i++)
        b[i] = 0;
}

static int ci_eq(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a++, cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return 0;
    }
    return *a == 0 && *b == 0;
}

static int ci_has(const char *s, const char *sub)
{
    for (; *s; s++) {
        const char *p = s, *q = sub;
        while (*p && *q && ((*p | 32) == (*q | 32))) {
            p++; q++;
        }
        if (!*q) return 1;
    }
    return 0;
}

static u16 prom_byte_to_rgb15(u8 v)
{
    /* Standard Namco / Galaxian / Frogger 8-bit 3-3-2 resistor DAC:
       bits 0..2 = Red (220/470/1k), bits 3..5 = Green, bits 6..7 = Blue (220/470) */
    static const u8 w3[8] = {0, 33, 71, 104, 151, 184, 222, 255};
    static const u8 w2[4] = {0, 81, 174, 255};
    u8 r = w3[v & 7u];
    u8 g = w3[(v >> 3) & 7u];
    u8 b = w2[(v >> 6) & 3u];
    return (u16)(((u16)(b >> 3) << 10) | ((u16)(g >> 3) << 5) | (u16)(r >> 3));
}

/* ---- Pre-decoders for Pac-Man, Galaxian/Frogger, and Donkey Kong ---- */

static void decode_pacman_gfx(u32 n_tiles, u32 n_spr)
{
    for (u32 t = 0; t < n_tiles && t < 512u; t++) {
        const u8 *src = WS->gfx_tiles + t * 16u;
        u8 *dst = WS->dec_tiles[t];
        /* Pac-Man 8x8 tile: bytes 0..7 = bottom half cols R->L, bytes 8..15 = top half cols R->L */
        for (int half = 0; half < 2; half++) {
            int y_base = half ? 0 : 4;
            const u8 *b = src + (half ? 8 : 0);
            for (int col = 0; col < 8; col++) {
                u8 cbyte = b[7 - col];
                for (int r = 0; r < 4; r++) {
                    u8 p0 = (cbyte >> r) & 1u;
                    u8 p1 = (cbyte >> (r + 4)) & 1u;
                    dst[(y_base + (3 - r)) * 8 + col] = (u8)(p0 | (p1 << 1));
                }
            }
        }
    }
    for (u32 s = 0; s < n_spr && s < 128u; s++) {
        const u8 *src = WS->gfx_sprites + s * 64u;
        u8 *dst = WS->dec_sprites[s];
        /* Pac-Man 16x16 sprite: 8 strips of 8 bytes; right half (cols 8..15) strips: 2(y12..15), 3(y0..3), 0(y4..7), 1(y8..11)?
           Exact Namco 16x16 layout:
           cols 8..15 (right): +0=y12..15, +8=y0..3, +16=y4..7, +24=y8..11
           cols 0..7  (left) : +32=y12..15, +40=y0..3, +48=y4..7, +56=y8..11 */
        static const u8 y_offs[4] = {12, 0, 4, 8};
        for (int xhalf = 0; xhalf < 2; xhalf++) {
            int x_base = xhalf ? 0 : 8;
            for (int blk = 0; blk < 4; blk++) {
                int y_base = y_offs[blk];
                const u8 *b = src + xhalf * 32 + blk * 8;
                for (int col = 0; col < 8; col++) {
                    u8 cbyte = b[7 - col];
                    for (int r = 0; r < 4; r++) {
                        u8 p0 = (cbyte >> r) & 1u;
                        u8 p1 = (cbyte >> (r + 4)) & 1u;
                        dst[(y_base + (3 - r)) * 16 + x_base + col] = (u8)(p0 | (p1 << 1));
                    }
                }
            }
        }
    }
}

static void decode_galaxian_gfx(int frogger_swap)
{
    /* Galaxian / Frogger / Scramble rotated 90 deg CCW:
       2 bitplanes separated in gfx_tiles[0..0x7FF] (plane 0) and gfx_tiles[0x800..0xFFF] (plane 1).
       On Frogger, plane 1 has bits 0 and 1 swapped on the ROM data bus? Actually Frogger swaps D0/D1 on second GFX ROM! */
    for (u32 t = 0; t < 256u; t++) {
        const u8 *p0 = WS->gfx_tiles + t * 8u;
        const u8 *p1 = WS->gfx_tiles + 0x800u + t * 8u;
        u8 *dst = WS->dec_tiles[t];
        for (int r = 0; r < 8; r++) {
            u8 b0 = p0[r], b1 = p1[r];
            if (frogger_swap)
                b1 = (u8)((b1 & 0xFCu) | ((b1 & 1u) << 1) | ((b1 >> 1) & 1u));
            for (int c = 0; c < 8; c++) {
                u8 px = (u8)((((b0 >> (7 - c)) & 1u)) | (((b1 >> (7 - c)) & 1u) << 1));
                /* Rotate 90 deg CCW for vertical monitor: (x=r, y=7-c) */
                dst[(7 - c) * 8 + r] = px;
            }
        }
    }
    for (u32 s = 0; s < 64u; s++) {
        const u8 *p0 = WS->gfx_tiles + s * 32u;
        const u8 *p1 = WS->gfx_tiles + 0x800u + s * 32u;
        u8 *dst = WS->dec_sprites[s];
        for (int q = 0; q < 4; q++) {
            int qx = (q & 2) ? 8 : 0;
            int qy = (q & 1) ? 8 : 0;
            for (int r = 0; r < 8; r++) {
                u8 b0 = p0[q * 8 + r], b1 = p1[q * 8 + r];
                if (frogger_swap)
                    b1 = (u8)((b1 & 0xFCu) | ((b1 & 1u) << 1) | ((b1 >> 1) & 1u));
                for (int c = 0; c < 8; c++) {
                    u8 px = (u8)((((b0 >> (7 - c)) & 1u)) | (((b1 >> (7 - c)) & 1u) << 1));
                    int hx = qx + r, hy = qy + c;
                    dst[(15 - hy) * 16 + hx] = px;
                }
            }
        }
    }
}

static void decode_dkong_gfx(void)
{
    /* Donkey Kong: 256 tiles (v_5h_b = plane 0, v_3pt = plane 1 at +0x800) &
       128 16x16 sprites across 4 x 2KB ROMs (l_4m, l_4n, l_4r, l_4s) */
    for (u32 t = 0; t < 256u; t++) {
        const u8 *p0 = WS->gfx_tiles + t * 8u;
        const u8 *p1 = WS->gfx_tiles + 0x800u + t * 8u;
        u8 *dst = WS->dec_tiles[t];
        for (int r = 0; r < 8; r++) {
            u8 b0 = p0[r], b1 = p1[r];
            for (int c = 0; c < 8; c++) {
                u8 px = (u8)(((b0 >> (7 - c)) & 1u) | (((b1 >> (7 - c)) & 1u) << 1));
                dst[(7 - c) * 8 + r] = px;
            }
        }
    }
    for (u32 s = 0; s < 128u; s++) {
        u8 *dst = WS->dec_sprites[s];
        const u8 *r0 = WS->gfx_sprites + 0x0000u + s * 16u;
        const u8 *r1 = WS->gfx_sprites + 0x0800u + s * 16u;
        const u8 *r2 = WS->gfx_sprites + 0x1000u + s * 16u;
        const u8 *r3 = WS->gfx_sprites + 0x1800u + s * 16u;
        for (int r = 0; r < 16; r++) {
            u8 a0 = (r < 8) ? r0[r] : r1[r - 8];
            u8 a1 = (r < 8) ? r2[r] : r3[r - 8];
            u8 b0 = (r < 8) ? r0[r + 8] : r1[r];
            u8 b1 = (r < 8) ? r2[r + 8] : r3[r];
            for (int c = 0; c < 8; c++) {
                u8 p_top = (u8)(((a0 >> (7 - c)) & 1u) | (((a1 >> (7 - c)) & 1u) << 1));
                u8 p_bot = (u8)(((b0 >> (7 - c)) & 1u) | (((b1 >> (7 - c)) & 1u) << 1));
                dst[(15 - c) * 16 + r] = p_top;
                dst[(7 - c) * 16 + r]  = p_bot;
            }
        }
    }
}

static void init_stars(void)
{
    u32 lfsr = 0x1FFFFu;
    int n = 0;
    for (u32 i = 0; i < 65536u && n < 252; i++) {
        u32 bit = ((lfsr >> 16) ^ (lfsr >> 4)) & 1u;
        lfsr = ((lfsr << 1) | bit) & 0x1FFFFu;
        if ((lfsr & 0xFF00u) == 0xFF00u && (i & 1u)) {
            WS->star_x[n] = (u16)(i & 0xFFu);
            WS->star_y[n] = (u8)((i >> 8) & 0xFFu);
            u8 c6 = (u8)((lfsr >> 2) & 0x3Fu);
            u8 r = ((c6 & 1u) ? 85 : 0) + ((c6 & 2u) ? 170 : 0);
            u8 g = ((c6 & 4u) ? 85 : 0) + ((c6 & 8u) ? 170 : 0);
            u8 b = ((c6 & 16u) ? 85 : 0) + ((c6 & 32u) ? 170 : 0);
            WS->star_col[n] = (u16)(((u16)(b >> 3) << 10) | ((u16)(g >> 3) << 5) | (u16)(r >> 3));
            n++;
        }
    }
}

/* ---- Z80 Memory & I/O Handlers ---- */

static u8 pac_in0(void)
{
    u8 v = 0xFFu;
    if (WS->pad & 0x10u) v &= ~0x01u;           /* Up */
    if (WS->pad & 0x40u) v &= ~0x02u;           /* Left */
    if (WS->pad & 0x80u) v &= ~0x04u;           /* Right */
    if (WS->pad & 0x20u) v &= ~0x08u;           /* Down */
    if (WS->coin_pulse)  v &= ~0x20u;           /* Coin 1 */
    return v;
}

static u8 pac_in1(void)
{
    u8 v = 0xFFu;
    if (WS->pad & 0x10u) v &= ~0x01u;
    if (WS->pad & 0x40u) v &= ~0x02u;
    if (WS->pad & 0x80u) v &= ~0x04u;
    if (WS->pad & 0x20u) v &= ~0x08u;
    if (WS->pad & 0x08u) v &= ~0x20u;           /* Start 1 (Enter) */
    if (WS->pad & 0x01u) v &= ~0x10u;           /* Fire / Rack / Action */
    return v;
}

static u8 arc_mem_read(struct z80 *c, u16 a)
{
    (void)c;
    switch (WS->board) {
    case BOARD_PACMAN:
        if (a < 0x4000u)
            return WS->mspac_aux_en ? WS->rom[0x8000u + a] : WS->rom[a];
        if (a < 0x4400u) return WS->vram[a & 0x3FFu];
        if (a < 0x4800u) return WS->cram[a & 0x3FFu];
        if (a < 0x5000u) return WS->ram[a & 0x7FFu];
        if (a < 0x5100u) {
            u8 sub = (u8)((a >> 6) & 3u);
            if (sub == 0u) return pac_in0();
            if (sub == 1u) return pac_in1();
            if (sub == 2u) return 0xC9u;        /* DIP: 1 coin 1 credit, 3 Pacs, bonus 10000 */
            return 0xFFu;
        }
        if (a >= 0x8000u && a < 0x9800u && WS->mspac_aux_en)
            return WS->rom[0x4000u + (a - 0x8000u)];
        return WS->rom[a & 0x3FFFu];

    case BOARD_GALAXIAN:
        if (a < 0x4000u) return WS->rom[a];
        if (a < 0x4800u) return WS->ram[a & 0x3FFu];
        if (a >= 0x5000u && a < 0x5800u) return WS->vram[a & 0x3FFu];
        if (a >= 0x5800u && a < 0x6000u) return WS->obj[a & 0xFFu];
        if (a >= 0x6000u && a < 0x6800u) {      /* IN0 */
            u8 v = 0x00u;
            if (WS->coin_pulse)  v |= 0x01u;
            if (WS->pad & 0x40u) v |= 0x04u;    /* Left */
            if (WS->pad & 0x80u) v |= 0x08u;    /* Right */
            if (WS->pad & 0x03u) v |= 0x10u;    /* Fire (X or Z) */
            return v;
        }
        if (a >= 0x6800u && a < 0x7000u) {      /* IN1 */
            u8 v = 0x00u;
            if (WS->pad & 0x08u) v |= 0x01u;    /* Start 1 */
            return v;
        }
        if (a >= 0x7000u && a < 0x7800u) return 0x00u;
        return 0xFFu;

    case BOARD_FROGGER:
        if (a < 0x4000u) return WS->rom[a];
        if (a >= 0x8000u && a < 0x8800u) return WS->ram[a & 0x7FFu];
        if (a >= 0xA800u && a < 0xAC00u) return WS->vram[a & 0x3FFu];
        if (a >= 0xB000u && a < 0xB100u) return WS->obj[a & 0xFFu];
        if (a >= 0xC000u) {
            /* Frogger swaps A1 and A12 on the 8255s! */
            u16 fa = (u16)((a & 0xEFFDu) | ((a & 2u) << 11) | ((a >> 11) & 2u));
            if (fa == 0xE000u) {                /* IN0 */
                u8 v = 0xFFu;
                if (WS->pad & 0x10u) v &= ~0x01u; /* Up */
                if (WS->pad & 0x80u) v &= ~0x10u; /* Right */
                if (WS->coin_pulse)  v &= ~0x80u; /* Coin 1 */
                if (WS->pad & 0x40u) v &= ~0x20u; /* Left */
                if (WS->pad & 0x03u) v &= ~0x08u; /* Jump / Fire */
                return v;
            }
            if (fa == 0xE002u) {                /* IN1 */
                u8 v = 0xFCu;                   /* 3 lives */
                if (WS->pad & 0x08u) v &= ~0x80u; /* Start 1 */
                return v;
            }
            if (fa == 0xE004u) {                /* IN2 */
                u8 v = 0xFFu;
                if (WS->pad & 0x20u) v &= ~0x01u; /* Down */
                return v;
            }
        }
        return 0xFFu;

    case BOARD_SCRAMBLE:
        if (a < 0x4000u) return WS->rom[a];
        if (a < 0x4800u) return WS->ram[a & 0x7FFu];
        if (a < 0x4C00u) return WS->vram[a & 0x3FFu];
        if (a >= 0x5000u && a < 0x5100u) return WS->obj[a & 0xFFu];
        if (a == 0x8100u) {
            u8 v = 0xFFu;
            if (WS->pad & 0x10u) v &= ~0x01u;
            if (WS->pad & 0x02u) v &= ~0x02u;   /* Bomb (Z) */
            if (WS->pad & 0x01u) v &= ~0x08u;   /* Laser (X) */
            if (WS->pad & 0x80u) v &= ~0x10u;
            if (WS->pad & 0x40u) v &= ~0x20u;
            if (WS->coin_pulse)  v &= ~0x80u;
            return v;
        }
        if (a == 0x8101u) {
            u8 v = 0xFDu;
            if (WS->pad & 0x08u) v &= ~0x80u;
            return v;
        }
        if (a == 0x8102u) {
            u8 v = 0xFFu;
            if (WS->pad & 0x20u) v &= ~0x40u;
            return v;
        }
        if (a == 0x7000u) return 0x00u;         /* Watchdog */
        return 0xFFu;

    case BOARD_DKONG:
        if (a < 0x4000u) return WS->rom[a];
        if (a >= 0x6000u && a < 0x7000u) return WS->ram[a & 0xFFFu];
        if (a >= 0x7000u && a < 0x7400u) return WS->obj[a & 0x3FFu];
        if (a >= 0x7400u && a < 0x7800u) return WS->vram[a & 0x3FFu];
        if (a == 0x7C00u) {                     /* IN0: P1 */
            u8 v = 0x00u;
            if (WS->pad & 0x80u) v |= 0x01u;    /* Right */
            if (WS->pad & 0x40u) v |= 0x02u;    /* Left */
            if (WS->pad & 0x10u) v |= 0x04u;    /* Up */
            if (WS->pad & 0x20u) v |= 0x08u;    /* Down */
            if (WS->pad & 0x03u) v |= 0x10u;    /* Jump (X or Z) */
            return v;
        }
        if (a == 0x7C80u) return 0x00u;         /* IN1: P2 */
        if (a == 0x7D00u) {                     /* IN2: Start / Coin / 8035 status */
            u8 v = 0x00u;
            if (WS->pad & 0x08u) v |= 0x04u;    /* Start 1 */
            if (WS->coin_pulse)  v |= 0x80u;    /* Coin */
            return v;
        }
        if (a == 0x7D80u) return 0x80u;         /* DSW0: 3 lives, 7000 bonus, 1 coin 1 play, upright */
        return 0x00u;
    }
    return 0xFFu;
}

static void arc_mem_write(struct z80 *c, u16 a, u8 v)
{
    (void)c;
    switch (WS->board) {
    case BOARD_PACMAN:
        if (a >= 0x4000u && a < 0x4400u) { WS->vram[a & 0x3FFu] = v; return; }
        if (a >= 0x4400u && a < 0x4800u) { WS->cram[a & 0x3FFu] = v; return; }
        if (a >= 0x4800u && a < 0x5000u) { WS->ram[a & 0x7FFu] = v; return; }
        if (a >= 0x5000u && a < 0x5040u) {
            u8 r = (u8)(a & 7u);
            if (r == 0u) {
                WS->irq_en = v & 1u;
                if (!WS->irq_en) WS->cpu.irq = 0;
            } else if (r == 1u) {
                WS->sound_en = v & 1u;
            } else if (r == 3u) {
                WS->flip_screen = v & 1u;
            }
            return;
        }
        if (a >= 0x5040u && a < 0x5060u) { WS->wsg_regs[a - 0x5040u] = v & 0x0Fu; return; }
        if (a >= 0x5060u && a < 0x5070u) { WS->obj[a - 0x5060u] = v; return; }
        return;

    case BOARD_GALAXIAN:
        if (a >= 0x4000u && a < 0x4800u) { WS->ram[a & 0x3FFu] = v; return; }
        if (a >= 0x5000u && a < 0x5800u) { WS->vram[a & 0x3FFu] = v; return; }
        if (a >= 0x5800u && a < 0x6000u) { WS->obj[a & 0xFFu] = v; return; }
        if (a >= 0x6004u && a <= 0x6007u) {
            if (a == 0x6007u && (v & 1u)) WS->gal_fire_env = 8000u;
            WS->gal_vol = v & 3u;
            return;
        }
        if (a >= 0x6800u && a <= 0x6807u) {
            if (a <= 0x6802u) WS->gal_fs[a - 0x6800u] = v & 1u;
            else if (a == 0x6803u && (v & 1u)) WS->gal_hit_env = 12000u;
            else if (a == 0x6805u && (v & 1u)) WS->gal_fire_env = 9000u;
            return;
        }
        if (a == 0x7001u || a == 0x7000u) { WS->irq_en = v & 1u; return; }
        if (a == 0x7004u) { WS->stars_on = v & 1u; return; }
        if (a == 0x7800u) { WS->gal_pitch = v; return; }
        return;

    case BOARD_FROGGER:
        if (a >= 0x8000u && a < 0x8800u) { WS->ram[a & 0x7FFu] = v; return; }
        if (a >= 0xA800u && a < 0xAC00u) { WS->vram[a & 0x3FFu] = v; return; }
        if (a >= 0xB000u && a < 0xB100u) { WS->obj[a & 0xFFu] = v; return; }
        if (a == 0xB808u) { WS->irq_en = v & 1u; return; }
        if (a >= 0xC000u) {
            u16 fa = (u16)((a & 0xEFFDu) | ((a & 2u) << 11) | ((a >> 11) & 2u));
            if (fa == 0xD000u) {
                WS->snd_latch = v;
            } else if (fa == 0xD002u) {
                u8 bit = (v >> 3) & 1u;
                if (!bit && WS->snd_irq_last)
                    WS->scpu.irq = 1;
                WS->snd_irq_last = bit;
            }
        }
        return;

    case BOARD_SCRAMBLE:
        if (a >= 0x4000u && a < 0x4800u) { WS->ram[a & 0x7FFu] = v; return; }
        if (a >= 0x4800u && a < 0x4C00u) { WS->vram[a & 0x3FFu] = v; return; }
        if (a >= 0x5000u && a < 0x5100u) { WS->obj[a & 0xFFu] = v; return; }
        if (a == 0x6801u) { WS->irq_en = v & 1u; return; }
        if (a == 0x6804u) { WS->stars_on = v & 1u; return; }
        if (a == 0x8200u) { WS->snd_latch = v; return; }
        if (a == 0x8201u) {
            u8 bit = (v >> 3) & 1u;
            if (!bit && WS->snd_irq_last)
                WS->scpu.irq = 1;
            WS->snd_irq_last = bit;
        }
        return;

    case BOARD_DKONG:
        if (a >= 0x6000u && a < 0x7000u) { WS->ram[a & 0xFFFu] = v; return; }
        if (a >= 0x7000u && a < 0x7400u) { WS->obj[a & 0x3FFu] = v; return; }
        if (a >= 0x7400u && a < 0x7800u) { WS->vram[a & 0x3FFu] = v; return; }
        if (a == 0x7808u && (v & 1u)) {
            /* Hardware 8257 Sprite DMA from $6900 -> $7000 */
            for (u32 i = 0; i < 0x180u; i++)
                WS->obj[i] = WS->ram[0x900u + i];
            return;
        }
        if (a == 0x7C00u) { WS->dk_dac = v; return; }
        if (a == 0x7D00u) { WS->dk_walk = v & 1u; return; }
        if (a == 0x7D01u) { if ((v & 1u) && !WS->dk_jump) WS->dk_jump_env = 10000u; WS->dk_jump = v & 1u; return; }
        if (a == 0x7D02u) { if ((v & 1u) && !WS->dk_stomp) WS->dk_stomp_env = 9000u; WS->dk_stomp = v & 1u; return; }
        if (a == 0x7D84u) { WS->irq_en = v & 1u; return; }
        if (a == 0x7D86u) { WS->pal_bank = (u8)((WS->pal_bank & 2u) | (v & 1u)); return; }
        if (a == 0x7D87u) { WS->pal_bank = (u8)((WS->pal_bank & 1u) | ((v & 1u) << 1)); return; }
        return;
    }
}

static u8 arc_io_in(struct z80 *c, u16 port)
{
    (void)c; (void)port;
    return 0xFFu;
}

static void arc_io_out(struct z80 *c, u16 port, u8 v)
{
    (void)c;
    if (WS->board == BOARD_PACMAN && (port & 0xFFu) == 0u) {
        WS->irq_vec = v;
        WS->cpu.bus = v;
    }
}

static void arc_irq_ack(struct z80 *c)
{
    c->irq = 0;
}

/* Sound Z80 (Frogger / Scramble) */
static u8 snd_mem_read(struct z80 *c, u16 a)
{
    (void)c;
    if (a < 0x4000u) return WS->srom[a];
    if (a < 0x5000u) return WS->sram[a & 0x3FFu];
    return 0xFFu;
}

static void snd_mem_write(struct z80 *c, u16 a, u8 v)
{
    (void)c;
    if (a >= 0x4000u && a < 0x5000u)
        WS->sram[a & 0x3FFu] = v;
}

static u8 snd_io_in(struct z80 *c, u16 port)
{
    u8 p = (u8)(port & 0xFFu);
    if (p & 0x40u) {                            /* Frogger AY data read ($40) or Scramble ($20) */
        if (WS->ay_sel == 14u)
            return WS->snd_latch;
        if (WS->ay_sel == 15u) {
            static const u8 clk_lut[8] = {0x00, 0x10, 0x08, 0x18, 0x40, 0x50, 0x48, 0x58};
            return clk_lut[((u32)c->cycles >> 10) & 7u];
        }
        return WS->ay_regs[WS->ay_sel & 15u];
    }
    if (WS->board == BOARD_SCRAMBLE && (p & 0x20u)) {
        if (WS->ay_sel == 14u) return WS->snd_latch;
        return WS->ay_regs[WS->ay_sel & 15u];
    }
    return 0xFFu;
}

static void snd_io_out(struct z80 *c, u16 port, u8 v)
{
    (void)c;
    u8 p = (u8)(port & 0xFFu);
    if (WS->board == BOARD_FROGGER) {
        if (p & 0x80u) WS->ay_sel = v & 15u;
        else if (p & 0x40u) {
            WS->ay_regs[WS->ay_sel] = v;
            if (WS->ay_sel == 13u) { WS->ay_env_step = 0; WS->ay_env_cnt = 0; }
        }
    } else {
        if (p & 0x10u) WS->ay_sel = v & 15u;
        else if (p & 0x20u) WS->ay_regs[WS->ay_sel] = v;
    }
}

static void setup_z80_maps(void)
{
    z80_init(&WS->cpu);
    WS->cpu.read = arc_mem_read;
    WS->cpu.write = arc_mem_write;
    WS->cpu.in = arc_io_in;
    WS->cpu.out = arc_io_out;
    WS->cpu.irq_ack = arc_irq_ack;
    WS->cpu.trap = -1;
    for (int i = 0; i < 64; i++)
        WS->cpu.rd[i] = WS->cpu.wr[i] = WS->cpu.op[i] = 0;

    /* Map ROM & RAM pages directly for maximum MIPS speed */
    if (!WS->mspac_aux_en) {
        for (int i = 0; i < 16; i++)
            WS->cpu.rd[i] = WS->rom + i * 1024;
    }
    if (WS->board == BOARD_PACMAN) {
        WS->cpu.rd[16] = WS->cpu.wr[16] = WS->vram;
        WS->cpu.rd[17] = WS->cpu.wr[17] = WS->cram;
        WS->cpu.rd[19] = WS->cpu.wr[19] = WS->ram + 0x400;
    } else if (WS->board == BOARD_GALAXIAN) {
        WS->cpu.rd[16] = WS->cpu.wr[16] = WS->ram;
        WS->cpu.rd[20] = WS->cpu.wr[20] = WS->vram;
    } else if (WS->board == BOARD_FROGGER) {
        WS->cpu.rd[32] = WS->cpu.wr[32] = WS->ram;
        WS->cpu.rd[33] = WS->cpu.wr[33] = WS->ram + 0x400;
        WS->cpu.rd[42] = WS->cpu.wr[42] = WS->vram;
    } else if (WS->board == BOARD_DKONG) {
        for (int i = 0; i < 4; i++)
            WS->cpu.rd[24 + i] = WS->cpu.wr[24 + i] = WS->ram + i * 1024;
        WS->cpu.rd[29] = WS->cpu.wr[29] = WS->vram;
    }

    z80_init(&WS->scpu);
    WS->scpu.read = snd_mem_read;
    WS->scpu.write = snd_mem_write;
    WS->scpu.in = snd_io_in;
    WS->scpu.out = snd_io_out;
    WS->scpu.irq_ack = arc_irq_ack;
    WS->scpu.trap = -1;
    for (int i = 0; i < 64; i++)
        WS->scpu.rd[i] = WS->scpu.wr[i] = WS->scpu.op[i] = 0;
    for (int i = 0; i < 16; i++)
        WS->scpu.rd[i] = WS->srom + i * 1024;
    WS->scpu.rd[16] = WS->scpu.wr[16] = WS->sram;
}

/* ---- Rendering ---- */

static void render_pacman(u16 *pic)
{
    if (!pic) return;
    u16 bg = WS->pal15[0];
    for (int i = 0; i < 224 * 288; i++)
        pic[i] = bg;

    for (int ty = 0; ty < 36; ty++) {
        for (int tx = 0; tx < 28; tx++) {
            u32 off;
            if (ty < 2)
                off = (0x3DDu - (u32)tx) + (ty ? 0x20u : 0u);
            else if (ty >= 34)
                off = (0x01Du - (u32)tx) + ((ty - 34) ? 0x20u : 0u);
            else
                off = 0x040u + (u32)(ty - 2) + (u32)(27 - tx) * 32u;
            u8 tile = WS->vram[off & 0x3FFu];
            u8 col  = WS->cram[off & 0x3FFu] & 0x3Fu;
            const u16 *clut = WS->clut15[col];
            const u8 *td = WS->dec_tiles[tile];
            u16 *dst = pic + ty * 8 * 224 + tx * 8;
            for (int r = 0; r < 8; r++) {
                for (int c = 0; c < 8; c++)
                    dst[c] = clut[td[r * 8 + c]];
                dst += 224;
            }
        }
    }

    /* 8 Sprites (drawn in reverse priority 7..0; attrs at $4FF0..$4FFF, coords at $5060..$506F) */
    for (int s = 7; s >= 0; s--) {
        u8 code_fl = WS->ram[0x7F0u + s * 2];
        u8 col     = WS->ram[0x7F1u + s * 2] & 0x3Fu;
        u8 sx_raw  = WS->obj[s * 2];
        u8 sy_raw  = WS->obj[s * 2 + 1];
        int sx = 240 - (int)sx_raw - 1;
        int sy = 272 - (int)sy_raw;
        if (s < 3) sx++;
        int fx = (code_fl >> 1) & 1;
        int fy = code_fl & 1;
        const u8 *sd = WS->dec_sprites[(code_fl >> 2) & 0x3Fu];
        const u16 *clut = WS->clut15[col];
        for (int r = 0; r < 16; r++) {
            int dy = sy + r;
            if (dy < 16 || dy >= 272) continue;
            int sr = fy ? (15 - r) : r;
            u16 *row = pic + dy * 224;
            for (int c = 0; c < 16; c++) {
                int dx = (sx + c) & 0xFF;
                if (dx >= 224) continue;
                int sc = fx ? (15 - c) : c;
                u8 px = sd[sr * 16 + sc];
                if (px) {
                    u16 rgb = clut[px];
                    if (rgb != bg)
                        row[dx] = rgb;
                }
            }
        }
    }
}

static void render_gal_frogger(u16 *pic)
{
    if (!pic) return;
    int is_frog = (WS->board == BOARD_FROGGER);
    u16 water_blue = (u16)((14u << 10) | (2u << 5) | 0u);
    for (int y = 0; y < 256; y++) {
        u16 bg = (is_frog && y < 128) ? water_blue : 0u;
        u16 *row = pic + y * 224;
        for (int x = 0; x < 224; x++)
            row[x] = bg;
    }

    if (WS->stars_on && !is_frog) {
        WS->star_scroll++;
        for (int i = 0; i < 252; i++) {
            int sx = WS->star_x[i];
            int sy = (WS->star_y[i] + WS->star_scroll) & 0xFF;
            if (sx < 224 && (((i + (WS->star_scroll >> 3)) & 3) != 0))
                pic[sy * 224 + sx] = WS->star_col[i];
        }
    }

    /* 28 visible columns (out of 32) x 32 rows rotated: screen X = (31 - vram_row)*8 - 16?
       Standard Galaxian/Frogger rotated CCW:
       vram[vy * 32 + vx]: vx = 0..31 -> vertical Y = (31 - vx) * 8; vy = 2..29 -> horizontal X = (29 - vy) * 8! */
    for (int vy = 2; vy < 30; vy++) {
        int sx = (29 - vy) * 8;
        u8 scroll = WS->obj[vy * 2];
        if (is_frog)
            scroll = (u8)(((scroll >> 4) & 0x0Fu) | ((scroll & 0x0Fu) << 4));
        u8 col = WS->obj[vy * 2 + 1] & 7u;
        if (is_frog)
            col = (u8)(((col >> 1) & 3u) | ((col & 1u) << 2));
        const u16 *clut = WS->clut15[col];

        for (int vx = 0; vx < 32; vx++) {
            u8 tile = WS->vram[vy * 32 + vx];
            const u8 *td = WS->dec_tiles[tile];
            int base_y = (31 - vx) * 8;
            for (int r = 0; r < 8; r++) {
                int dy = (base_y + r + scroll) & 0xFF;
                u16 *row = pic + dy * 224 + sx;
                for (int c = 0; c < 8; c++) {
                    u8 px = td[r * 8 + c];
                    if (px)
                        row[c] = clut[px];
                }
            }
        }
    }

    /* 8 Sprites at $5840..$585F (or $B040 on Frogger) */
    for (int s = 7; s >= 0; s--) {
        u8 sy_raw = WS->obj[0x40 + s * 4];
        u8 code   = WS->obj[0x41 + s * 4];
        u8 attr   = WS->obj[0x42 + s * 4];
        u8 sx_raw = WS->obj[0x43 + s * 4];
        if (is_frog)
            sy_raw = (u8)(((sy_raw >> 4) & 0x0Fu) | ((sy_raw & 0x0Fu) << 4));
        int sx = 224 - 16 - (int)sx_raw;
        int sy = 240 - (int)sy_raw;
        int fx = (attr >> 6) & 1;
        int fy = (attr >> 7) & 1;
        u8 col = attr & 7u;
        if (is_frog)
            col = (u8)(((col >> 1) & 3u) | ((col & 1u) << 2));
        const u8 *sd = WS->dec_sprites[code & 0x3Fu];
        const u16 *clut = WS->clut15[col];
        for (int r = 0; r < 16; r++) {
            int dy = (sy + r) & 0xFF;
            int sr = fy ? (15 - r) : r;
            u16 *row = pic + dy * 224;
            for (int c = 0; c < 16; c++) {
                int dx = sx + c;
                if (dx < 0 || dx >= 224) continue;
                int sc = fx ? (15 - c) : c;
                u8 px = sd[sr * 16 + sc];
                if (px)
                    row[dx] = clut[px];
            }
        }
    }

    /* Galaxian / Scramble 8 Shells + Player Yellow Missile ($5860..$587F) */
    if (!is_frog) {
        for (int b = 0; b < 8; b++) {
            u8 bx_raw = WS->obj[0x60 + b * 4 + 1];
            u8 by_raw = WS->obj[0x60 + b * 4 + 3];
            if (by_raw == 0xFFu || by_raw == 0u) continue;
            int bx = 224 - (int)bx_raw;
            int by = 255 - (int)by_raw;
            u16 bcol = (b == 7) ? (u16)((0u << 10) | (31u << 5) | 31u) : 0x7FFFu;
            if (bx >= 0 && bx < 224) {
                for (int dy = 0; dy < 4; dy++)
                    pic[((by + dy) & 0xFF) * 224 + bx] = bcol;
            }
        }
    }
}

static void render_dkong(u16 *pic)
{
    if (!pic) return;
    for (int i = 0; i < 224 * 256; i++)
        pic[i] = 0;

    for (int vy = 2; vy < 30; vy++) {
        int sx = (29 - vy) * 8;
        for (int vx = 0; vx < 32; vx++) {
            u32 off = (u32)vy * 32u + (u32)vx;
            u8 tile = WS->vram[off & 0x3FFu];
            u8 col = (u8)((WS->color_prom[0x200u + ((off >> 5) & 0x1Fu) + ((vx >> 2) << 5)] & 0x0Fu) |
                          (WS->pal_bank << 4));
            const u16 *clut = WS->clut15[col & 0x3Fu];
            const u8 *td = WS->dec_tiles[tile];
            int sy = vx * 8;
            for (int r = 0; r < 8; r++) {
                u16 *row = pic + (sy + (7 - r)) * 224 + sx;
                for (int c = 0; c < 8; c++) {
                    u8 px = td[r * 8 + c];
                    if (px)
                        row[7 - c] = clut[px];
                }
            }
        }
    }

    for (int s = 0; s < 96; s++) {
        u8 sx_raw = WS->obj[s * 4];
        u8 code   = WS->obj[s * 4 + 1];
        u8 attr   = WS->obj[s * 4 + 2];
        u8 sy_raw = WS->obj[s * 4 + 3];
        if (!sx_raw && !sy_raw) continue;
        int sx = (int)sy_raw - 16;
        int sy = 240 - (int)sx_raw;
        int fx = (attr >> 7) & 1;
        int fy = (code >> 7) & 1;
        u8 spr_id = (u8)((code & 0x7Fu) | ((attr & 0x40u) << 1));
        u8 col = (u8)((attr & 0x0Fu) | (WS->pal_bank << 4));
        const u8 *sd = WS->dec_sprites[spr_id & 0x7Fu];
        const u16 *clut = WS->clut15[col & 0x3Fu];
        for (int r = 0; r < 16; r++) {
            int dy = sy + r;
            if (dy < 0 || dy >= 256) continue;
            int sr = fy ? r : (15 - r);
            u16 *row = pic + dy * 224;
            for (int c = 0; c < 16; c++) {
                int dx = sx + c;
                if (dx < 0 || dx >= 224) continue;
                int sc = fx ? c : (15 - c);
                u8 px = sd[sr * 16 + sc];
                if (px)
                    row[dx] = clut[px];
            }
        }
    }
}

/* ---- 48 kHz Audio Synthesis ---- */

static void step_audio_frame(void)
{
    if (!WS->sample_rate) return;
    /* 60.606 Hz -> sample_rate * 1000 / 60606 samples per frame */
    u32 num = WS->sample_rate * 1000u + WS->snd_frac;
    u32 n_samp = num / 60606u;
    WS->snd_frac = num % 60606u;

    /* Namco WSG native rate = 96000 Hz = 2x 48000 Hz! */
    static const u16 ay_vol[16] = {
        0, 60, 90, 130, 190, 270, 380, 540, 770, 1090, 1550, 2200, 3110, 4400, 6220, 8800
    };

    for (u32 s = 0; s < n_samp; s++) {
        s32 out = 0;

        if (WS->board == BOARD_PACMAN) {
            if (WS->sound_en) {
                /* Advance WSG twice for 96 kHz effective rate at 48 kHz output */
                for (int step2 = 0; step2 < 2; step2++) {
                    u32 f0 = (u32)WS->wsg_regs[0x10] | ((u32)WS->wsg_regs[0x11] << 4) |
                             ((u32)WS->wsg_regs[0x12] << 8) | ((u32)WS->wsg_regs[0x13] << 12) |
                             ((u32)WS->wsg_regs[0x14] << 16);
                    WS->wsg_acc[0] = (WS->wsg_acc[0] + f0) & 0xFFFFFu;
                    for (int v = 1; v <= 2; v++) {
                        u32 b = 0x10u + (u32)v * 5u;
                        u32 fv = (u32)WS->wsg_regs[b + 1] | ((u32)WS->wsg_regs[b + 2] << 4) |
                                 ((u32)WS->wsg_regs[b + 3] << 8) | ((u32)WS->wsg_regs[b + 4] << 12);
                        WS->wsg_acc[v] = (WS->wsg_acc[v] + fv) & 0xFFFFu;
                    }
                }
                for (int v = 0; v < 3; v++) {
                    u8 vol = WS->wsg_regs[0x15 + v * 5];
                    if (!vol) continue;
                    u8 wave = WS->wsg_regs[0x05 + v * 5] & 7u;
                    u32 ph = (v == 0) ? ((WS->wsg_acc[0] >> 15) & 31u) : ((WS->wsg_acc[v] >> 11) & 31u);
                    s32 smp = (s32)(WS->wave_prom[wave * 32u + ph] & 15u) - 8;
                    out += smp * (s32)vol * 48;
                }
            }
        } else if (WS->board == BOARD_FROGGER || WS->board == BOARD_SCRAMBLE) {
            /* 1.789772 MHz / 16 = 111,861 Hz AY clock -> ~2.33 ticks per 48 kHz sample */
            for (int sub = 0; sub < 2; sub++) {
                for (int c = 0; c < 3; c++) {
                    u32 per = (u32)WS->ay_regs[c * 2] | (((u32)WS->ay_regs[c * 2 + 1] & 15u) << 8);
                    if (per < 1u) per = 1u;
                    if (++WS->ay_cnt[c] >= per) {
                        WS->ay_cnt[c] = 0;
                        WS->ay_out[c] ^= 1u;
                    }
                }
                u32 nper = ((u32)(WS->ay_regs[6] & 31u)) * 2u;
                if (nper < 2u) nper = 2u;
                if (++WS->ay_ncnt >= nper) {
                    WS->ay_ncnt = 0;
                    u32 fb = (WS->ay_lfsr ^ (WS->ay_lfsr >> 3)) & 1u;
                    WS->ay_lfsr = (WS->ay_lfsr >> 1) | (fb << 16);
                }
            }
            u8 mix = WS->ay_regs[7];
            for (int c = 0; c < 3; c++) {
                int ton = ((mix >> c) & 1u) ? 1 : WS->ay_out[c];
                int non = ((mix >> (c + 3)) & 1u) ? 1 : (int)(WS->ay_lfsr & 1u);
                if (ton && non)
                    out += ay_vol[WS->ay_regs[8 + c] & 15u];
            }
            out -= 4000;
        } else if (WS->board == BOARD_GALAXIAN) {
            if (WS->gal_pitch != 0xFFu && WS->gal_pitch != 0u) {
                u32 hz = 18432000u / (256u * (256u - WS->gal_pitch));
                WS->gal_tone_ph += (hz << 16) / WS->sample_rate;
                out += (WS->gal_tone_ph & 0x8000u) ? (1800 * (1 + WS->gal_vol)) : -(1800 * (1 + WS->gal_vol));
            }
            if (WS->gal_fs[0] || WS->gal_fs[1] || WS->gal_fs[2]) {
                u32 lhz = 110u + WS->gal_fs[0] * 30u + WS->gal_fs[1] * 55u + WS->gal_fs[2] * 90u;
                WS->gal_lfo_ph += (lhz << 16) / WS->sample_rate;
                out += (WS->gal_lfo_ph & 0x8000u) ? 1600 : -1600;
            }
            u32 fb = ((WS->gal_lfsr ^ (WS->gal_lfsr >> 3)) & 1u);
            WS->gal_lfsr = (WS->gal_lfsr >> 1) | (fb << 16);
            if (WS->gal_fire_env > 0u) {
                WS->gal_fire_env -= (WS->gal_fire_env > 3u) ? 3u : WS->gal_fire_env;
                u32 fhz = 300u + (WS->gal_fire_env >> 3);
                WS->gal_tone_ph += (fhz << 16) / WS->sample_rate;
                out += (WS->gal_tone_ph & 0x8000u) ? (s32)(WS->gal_fire_env >> 1) : -(s32)(WS->gal_fire_env >> 1);
            }
            if (WS->gal_hit_env > 0u) {
                WS->gal_hit_env -= (WS->gal_hit_env > 2u) ? 2u : WS->gal_hit_env;
                out += (WS->gal_lfsr & 1u) ? (s32)(WS->gal_hit_env >> 1) : -(s32)(WS->gal_hit_env >> 1);
            }
        } else if (WS->board == BOARD_DKONG) {
            out += ((s32)WS->dk_dac - 128) * 64;
            if (WS->dk_walk) {
                WS->dk_walk_ph += (220u << 16) / WS->sample_rate;
                out += (WS->dk_walk_ph & 0x8000u) ? 2200 : -2200;
            }
            if (WS->dk_jump_env > 0u) {
                WS->dk_jump_env -= (WS->dk_jump_env > 3u) ? 3u : WS->dk_jump_env;
                u32 jhz = 950u - (WS->dk_jump_env >> 4);
                WS->dk_walk_ph += (jhz << 16) / WS->sample_rate;
                out += (WS->dk_walk_ph & 0x8000u) ? (s32)(WS->dk_jump_env >> 1) : -(s32)(WS->dk_jump_env >> 1);
            }
            if (WS->dk_stomp_env > 0u) {
                WS->dk_stomp_env -= (WS->dk_stomp_env > 4u) ? 4u : WS->dk_stomp_env;
                u32 fb = ((WS->gal_lfsr ^ (WS->gal_lfsr >> 2)) & 1u);
                WS->gal_lfsr = (WS->gal_lfsr >> 1) | (fb << 16);
                out += (WS->gal_lfsr & 1u) ? (s32)(WS->dk_stomp_env >> 1) : -(s32)(WS->dk_stomp_env >> 1);
            }
        }

        if (out > 32767) out = 32767;
        else if (out < -32768) out = -32768;
        WS->snd_ring[WS->snd_head & (SND_RING - 1)] = (s16)out;
        WS->snd_head++;
        if (WS->snd_head - WS->snd_tail > SND_RING)
            WS->snd_tail = WS->snd_head - SND_RING;
    }
}

/* ---- Built-in Default Pac-Man PROMs & Playable Z80 "MAZE CHOMP" Game ---- */

static void load_default_pacman_proms(void)
{
    /* Authentic 16-color Pac-Man RGB PROM + 64-entry 4-color CLUT */
    static const u8 rgb32[32] = {
        0x00, 0x07, 0xDF, 0xB7, 0xFF, 0xF9, 0xFB, 0x15,
        0x3F, 0x0F, 0x56, 0x0E, 0x38, 0xD0, 0x62, 0xAC,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    for (int i = 0; i < 32; i++)
        WS->pal15[i] = prom_byte_to_rgb15(rgb32[i]);

    /* CLUT groups: 0=white, 1=red(Blinky), 2=pink(Pinky), 3=cyan(Inky), 4=orange(Clyde),
       5=yellow(Pac), 6=maze blue, 7=pellet salmon/white */
    static const u8 groups[16][4] = {
        {0, 4, 2, 1}, {0, 4, 14, 1}, {0, 4, 5, 3}, {0, 4, 7, 5},
        {0, 4, 8, 9}, {0, 9, 1, 13}, {0, 13, 1, 4}, {0, 6, 4, 1},
        {0, 12, 9, 4},{0, 13, 4, 9}, {0, 1, 9, 4},  {0, 3, 5, 4},
        {0, 7, 1, 4}, {0, 8, 9, 4},  {0, 13, 6, 4}, {0, 4, 9, 1}
    };
    for (int g = 0; g < 64; g++) {
        const u8 *gr = groups[g & 15];
        for (int c = 0; c < 4; c++)
            WS->clut15[g][c] = WS->pal15[gr[c]];
    }

    /* Namco WSG 8 waveforms (sine, organ, triangle, square, pulse, saw, harmonic,organ2) */
    static const u8 sine32[32] = {
        8,10,11,13,14,15,15,15,15,15,14,13,11,10,8,6,
        5,3,2,1,0,0,0,0,1,2,3,5,6,8,8,8
    };
    for (int i = 0; i < 32; i++) {
        WS->wave_prom[0 * 32 + i] = sine32[i];
        WS->wave_prom[1 * 32 + i] = (u8)((sine32[i] + sine32[(i * 2) & 31]) >> 1);
        WS->wave_prom[2 * 32 + i] = (u8)(i < 16 ? i : 31 - i);
        WS->wave_prom[3 * 32 + i] = (u8)(i < 16 ? 14 : 1);
        WS->wave_prom[4 * 32 + i] = (u8)(i < 8 ? 15 : 2);
        WS->wave_prom[5 * 32 + i] = (u8)(i >> 1);
        WS->wave_prom[6 * 32 + i] = (u8)((sine32[i] + ((i & 4) ? 4 : 0)) & 15u);
        WS->wave_prom[7 * 32 + i] = sine32[(i * 3) & 31];
    }
}

static void build_builtin_maze_chomp(void)
{
    WS->board = BOARD_PACMAN;
    WS->scr_w = 224;
    WS->scr_h = 288;
    load_default_pacman_proms();

    /* Direct decoded 8x8 tiles: 0=empty, 1=wall block, 2=dot, 3=power pellet, '0'..'9','A'..'Z' */
    ws_zero(WS->dec_tiles, sizeof(WS->dec_tiles));
    for (int r = 1; r < 7; r++)
        for (int c = 1; c < 7; c++)
            WS->dec_tiles[1][r * 8 + c] = (r == 1 || r == 6 || c == 1 || c == 6) ? 1 : 2;
    for (int r = 3; r <= 4; r++)
        for (int c = 3; c <= 4; c++)
            WS->dec_tiles[2][r * 8 + c] = 1;
    for (int r = 2; r <= 5; r++)
        for (int c = 2; c <= 5; c++)
            if (!((r == 2 || r == 5) && (c == 2 || c == 5)))
                WS->dec_tiles[3][r * 8 + c] = 1;

    /* Simple 5x7 HUD digits 0..9 at tiles 16..25 & letters SCORE (tiles 32..36) */
    static const u8 font16[15][7] = {
        {0x3E,0x63,0x67,0x6B,0x73,0x63,0x3E}, {0x0C,0x1C,0x0C,0x0C,0x0C,0x0C,0x3F},
        {0x3E,0x63,0x03,0x1E,0x30,0x60,0x7F}, {0x3E,0x63,0x03,0x1E,0x03,0x63,0x3E},
        {0x06,0x0E,0x1E,0x36,0x7F,0x06,0x06}, {0x7F,0x60,0x7E,0x03,0x03,0x63,0x3E},
        {0x1E,0x30,0x60,0x7E,0x63,0x63,0x3E}, {0x7F,0x63,0x06,0x0C,0x18,0x18,0x18},
        {0x3E,0x63,0x63,0x3E,0x63,0x63,0x3E}, {0x3E,0x63,0x63,0x3F,0x03,0x06,0x3C},
        {0x3E,0x60,0x3E,0x03,0x63,0x3E,0x00}, /* S */
        {0x3E,0x63,0x60,0x60,0x63,0x3E,0x00}, /* C */
        {0x3E,0x63,0x63,0x63,0x63,0x3E,0x00}, /* O */
        {0x7E,0x63,0x7E,0x6C,0x66,0x63,0x00}, /* R */
        {0x7F,0x60,0x7C,0x60,0x60,0x7F,0x00}  /* E */
    };
    for (int f = 0; f < 15; f++) {
        int tid = (f < 10) ? (16 + f) : (32 + (f - 10));
        for (int r = 0; r < 7; r++)
            for (int c = 0; c < 8; c++)
                if ((font16[f][r] >> (7 - c)) & 1u)
                    WS->dec_tiles[tid][r * 8 + c] = 1;
    }

    /* Sprites: 0 = Pac closed, 1 = Pac open, 2 = Ghost frame A, 3 = Ghost frame B */
    ws_zero(WS->dec_sprites, sizeof(WS->dec_sprites));
    for (int y = 0; y < 16; y++) {
        for (int x = 0; x < 16; x++) {
            int dx = x - 7, dy = y - 7;
            if (dx * dx + dy * dy <= 45) {
                WS->dec_sprites[0][y * 16 + x] = 1;
                if (!(x >= 8 && (y >= 5 && y <= 10) && (x - 7) >= (y > 7 ? y - 7 : 7 - y)))
                    WS->dec_sprites[1][y * 16 + x] = 1;
            }
            /* Ghost dome + wavy skirt + white/blue eyes */
            if ((y >= 1 && y <= 7 && dx * dx + (y - 7) * (y - 7) <= 46) ||
                (y > 7 && y < 13 && x >= 1 && x <= 14) ||
                (y >= 13 && y <= 14 && x >= 1 && x <= 14 && (((x + 0) / 3) & 1) == 0)) {
                WS->dec_sprites[2][y * 16 + x] = 2;
            }
            if ((y >= 1 && y <= 7 && dx * dx + (y - 7) * (y - 7) <= 46) ||
                (y > 7 && y < 13 && x >= 1 && x <= 14) ||
                (y >= 13 && y <= 14 && x >= 1 && x <= 14 && (((x + 2) / 3) & 1) == 0)) {
                WS->dec_sprites[3][y * 16 + x] = 2;
            }
            if (y >= 4 && y <= 7 && ((x >= 3 && x <= 5) || (x >= 9 && x <= 11))) {
                WS->dec_sprites[2][y * 16 + x] = (y >= 5 && (x == 4 || x == 10)) ? 3 : 1;
                WS->dec_sprites[3][y * 16 + x] = (y >= 5 && (x == 4 || x == 10)) ? 3 : 1;
            }
        }
    }

    /* Real Z80 ROM ($0000): initializes maze in $4000/$4400, enables VBlank IM 1 ($0038),
       moves Pac + 4 ghosts, animates Namco WSG 3-voice siren + wakka-wakka! */
    static const u8 zprog[] = {
        0xF3, 0x31, 0xF0, 0x4E, 0xED, 0x56,             /* $0000: DI; LD SP,$4EF0; IM 1 */
        0xC3, 0x50, 0x00,                               /* $0006: JP $0050 */
    };
    ws_zero(WS->rom, sizeof(WS->rom));
    for (u32 i = 0; i < sizeof(zprog); i++)
        WS->rom[i] = zprog[i];

    /* $0038 IM 1 VBlank ISR: increments ($4C00), re-arms $5000, EI, RETI */
    static const u8 zisr[] = {
        0xF5, 0x21, 0x00, 0x4C, 0x34,
        0xAF, 0x32, 0x00, 0x50, 0x3C, 0x32, 0x00, 0x50,
        0xF1, 0xFB, 0xED, 0x4D
    };
    for (u32 i = 0; i < sizeof(zisr); i++)
        WS->rom[0x0038 + i] = zisr[i];

    /* $0050 Main game: builds classic symmetric maze into VRAM ($4000) & CRAM ($4400) from $0200 bitmap,
       then runs 60 Hz Pac + 4 Ghosts + WSG synth loop! */
    static const u8 zmain[] = {
        /* Copy 1024 bytes of pre-laid maze tiles ($1000..$13FF -> $4000) and colors ($1400..$17FF -> $4400) */
        0x21, 0x00, 0x10, 0x11, 0x00, 0x40, 0x01, 0x00, 0x04, 0xED, 0xB0,
        0x21, 0x00, 0x14, 0x11, 0x00, 0x44, 0x01, 0x00, 0x04, 0xED, 0xB0,
        /* Enable sound ($5001=1) and VBlank IRQ ($5000=1), set WSG waveforms */
        0x3E, 0x01, 0x32, 0x01, 0x50, 0x32, 0x00, 0x50,
        0xAF, 0x32, 0x45, 0x50, 0x3E, 0x02, 0x32, 0x4A, 0x50, 0x3E, 0x03, 0x32, 0x4F, 0x50,
        0x3E, 0x0C, 0x32, 0x55, 0x50, 0x3E, 0x09, 0x32, 0x5A, 0x50, 0x3E, 0x08, 0x32, 0x5F, 0x50,
        /* Initial Pac X ($4C10=120), Y ($4C11=88) */
        0x3E, 0x78, 0x32, 0x10, 0x4C,
        0x3E, 0x58, 0x32, 0x11, 0x4C,
        0xFB,                                           /* EI */
        /* Frame loop: HALT until VBlank! */
        0x76,                                           /* loop: HALT */
        /* Read IN0 ($5000) -> steer Pac or patrol smoothly in attract mode */
        0x3A, 0x00, 0x50, 0x2F, 0xE6, 0x0F, 0x47,       /* B = ~IN0 & $0F */
        0x20, 0x0E,                                     /* JR NZ,manual (+14) */
        /* Attract mode patrol: Pac circles perimeter smoothly */
        0x3A, 0x00, 0x4C, 0x87, 0xC6, 0x30, 0x32, 0x10, 0x4C,
        0x2F, 0xE6, 0x3F, 0xC6, 0x50, 0x32, 0x11, 0x4C,
        0x18, 0x1E,                                     /* JR draw_objs (+30) */
        /* manual: bit0=Up(+Y), bit1=Left(+X in Pac coords), bit2=Right(-X), bit3=Down(-Y) */
        0x21, 0x10, 0x4C,
        0xCB, 0x48, 0x28, 0x02, 0x34, 0x34,             /* Left -> X += 2 */
        0xCB, 0x50, 0x28, 0x02, 0x35, 0x35,             /* Right -> X -= 2 */
        0x23,
        0xCB, 0x40, 0x28, 0x02, 0x34, 0x34,             /* Up -> Y += 2 */
        0xCB, 0x58, 0x28, 0x02, 0x35, 0x35,             /* Down -> Y -= 2 */
        /* draw_objs: Sprite 0 = Pac (color 5), Sprites 1..4 = 4 Ghosts (colors 1,2,3,4) */
        0x3A, 0x00, 0x4C, 0x0F, 0x0F, 0xE6, 0x01,       /* mouth anim 0/1 */
        0x07, 0x07, 0x32, 0xF0, 0x4F,
        0x3E, 0x05, 0x32, 0xF1, 0x4F,
        0x3A, 0x10, 0x4C, 0x32, 0x60, 0x50,
        0x3A, 0x11, 0x4C, 0x32, 0x61, 0x50,
        /* 4 Ghosts patrolling lanes */
        0x3A, 0x00, 0x4C, 0x4F,                         /* C = frame */
        0x0F, 0x0F, 0xE6, 0x01, 0xC6, 0x02, 0x07, 0x07, /* ghost code 2 or 3 << 2 */
        0x32, 0xF2, 0x4F, 0x32, 0xF4, 0x4F, 0x32, 0xF6, 0x4F, 0x32, 0xF8, 0x4F,
        0x3E, 0x01, 0x32, 0xF3, 0x4F,
        0x3E, 0x02, 0x32, 0xF5, 0x4F,
        0x3E, 0x03, 0x32, 0xF7, 0x4F,
        0x3E, 0x04, 0x32, 0xF9, 0x4F,
        0x79, 0xC6, 0x28, 0x32, 0x62, 0x50, 0x3E, 0xB8, 0x32, 0x63, 0x50,
        0x79, 0x2F, 0xC6, 0x30, 0x32, 0x64, 0x50, 0x3E, 0x90, 0x32, 0x65, 0x50,
        0x79, 0x87, 0xC6, 0x40, 0x32, 0x66, 0x50, 0x3E, 0x68, 0x32, 0x67, 0x50,
        0x79, 0xC6, 0x70, 0x32, 0x68, 0x50, 0x3E, 0x40, 0x32, 0x69, 0x50,
        /* WSG Siren (voice 0) + Wakka (voice 1) + Bass (voice 2) */
        0x79, 0xE6, 0x1F, 0xFE, 0x10, 0x38, 0x04, 0x2F, 0xE6, 0x1F,
        0xC6, 0x04, 0x32, 0x53, 0x50,                   /* Siren freq hi */
        0x79, 0x0F, 0x0F, 0xE6, 0x07, 0xC6, 0x05, 0x32, 0x58, 0x50,
        0x3E, 0x03, 0x32, 0x5D, 0x50,
        0x18, 0x8E                                      /* JR loop ($0050 + 46 = $007E) */
    };
    /* Patch exact JR loop offset */
    u8 zcopy[sizeof(zmain)];
    for (u32 i = 0; i < sizeof(zmain); i++) zcopy[i] = zmain[i];
    /* Find HALT (0x76) offset */
    int halt_idx = 0;
    for (u32 i = 0; i < sizeof(zcopy); i++)
        if (zcopy[i] == 0x76u) { halt_idx = (int)i; break; }
    zcopy[sizeof(zcopy) - 1] = (u8)((halt_idx - (int)sizeof(zcopy)) & 0xFF);
    for (u32 i = 0; i < sizeof(zcopy); i++)
        WS->rom[0x0050 + i] = zcopy[i];

    /* Build pre-formatted Pac-Man VRAM ($1000..$13FF) & CRAM ($1400..$17FF) maze! */
    static const char *const maze[36] = {
        "    SCORE  012480           ",
        "                            ",
        "############################",
        "#............##............#",
        "#.####.#####.##.#####.####.#",
        "#o####.#####.##.#####.####o#",
        "#.####.#####.##.#####.####.#",
        "#..........................#",
        "#.####.##.########.##.####.#",
        "#.####.##.########.##.####.#",
        "#......##....##....##......#",
        "######.##### ## #####.######",
        "     #.##### ## #####.#     ",
        "     #.##          ##.#     ",
        "     #.## ###  ### ##.#     ",
        "######.## #      # ##.######",
        "      .   #      #   .      ",
        "######.## #      # ##.######",
        "     #.## ######## ##.#     ",
        "     #.##          ##.#     ",
        "     #.## ######## ##.#     ",
        "######.## ######## ##.######",
        "#............##............#",
        "#.####.#####.##.#####.####.#",
        "#.####.#####.##.#####.####.#",
        "#o..##................##..o#",
        "###.##.##.########.##.##.###",
        "###.##.##.########.##.##.###",
        "#......##....##....##......#",
        "#.##########.##.##########.#",
        "#.##########.##.##########.#",
        "#..........................#",
        "############################",
        "                            ",
        "  P P P                     ",
        "                            "
    };
    for (int ty = 0; ty < 36; ty++) {
        for (int tx = 0; tx < 28; tx++) {
            u32 off;
            if (ty < 2)
                off = (0x3DDu - (u32)tx) + (ty ? 0x20u : 0u);
            else if (ty >= 34)
                off = (0x01Du - (u32)tx) + ((ty - 34) ? 0x20u : 0u);
            else
                off = 0x040u + (u32)(ty - 2) + (u32)(27 - tx) * 32u;
            char ch = maze[ty][tx];
            u8 tid = 0, col = 0;
            if (ch == '#') { tid = 1; col = 6; }
            else if (ch == '.') { tid = 2; col = 7; }
            else if (ch == 'o') { tid = 3; col = 7; }
            else if (ch >= '0' && ch <= '9') { tid = (u8)(16 + (ch - '0')); col = 0; }
            else if (ch == 'S') { tid = 32; col = 1; }
            else if (ch == 'C') { tid = 33; col = 1; }
            else if (ch == 'O') { tid = 34; col = 1; }
            else if (ch == 'R') { tid = 35; col = 1; }
            else if (ch == 'E') { tid = 36; col = 1; }
            else if (ch == 'P') { tid = 3; col = 5; }
            WS->rom[0x1000 + (off & 0x3FFu)] = tid;
            WS->rom[0x1400 + (off & 0x3FFu)] = col;
        }
    }
}

/* ---- MAME .zip Romset Loader ---- */

static int zip_load_named(const u8 *z, u32 zn, const char *want, u8 *dst, u32 cap, u32 *got_out)
{
    u32 cnt = zip_count(z, zn);
    for (u32 i = 0; i < cnt; i++) {
        char mname[96];
        u32 msz = 0;
        if (zip_unpack_at(z, zn, i, 0, 0, &msz, mname, sizeof(mname)) != 0)
            continue;
        const char *base = mname;
        for (const char *p = mname; *p; p++)
            if (*p == '/' || *p == '\\') base = p + 1;
        if (ci_eq(base, want)) {
            if (zip_unpack_at(z, zn, i, dst, cap, &msz, mname, sizeof(mname)) == 0) {
                if (got_out) *got_out = msz;
                return 1;
            }
        }
    }
    return 0;
}

static void setup_pacman_proms_from_buf(void)
{
    for (int i = 0; i < 32; i++)
        WS->pal15[i] = prom_byte_to_rgb15(WS->color_prom[i]);
    for (int g = 0; g < 64; g++)
        for (int c = 0; c < 4; c++)
            WS->clut15[g][c] = WS->pal15[WS->color_prom[0x20 + g * 4 + c] & 0x1Fu];
}

static void setup_gal_proms_from_buf(void)
{
    for (int i = 0; i < 32; i++)
        WS->pal15[i] = prom_byte_to_rgb15(WS->color_prom[i]);
    for (int g = 0; g < 8; g++) {
        WS->clut15[g][0] = 0;
        for (int c = 1; c < 4; c++)
            WS->clut15[g][c] = WS->pal15[g * 4 + c];
    }
}

static void setup_dkong_proms_from_buf(void)
{
    for (int i = 0; i < 256; i++) {
        u8 hi = WS->color_prom[i] & 0x0Fu;
        u8 lo = WS->color_prom[0x100 + i] & 0x0Fu;
        u8 v = (u8)((hi << 4) | lo);
        /* Donkey Kong inverted 3-3-2 resistor network */
        WS->pal15[i & 63] = prom_byte_to_rgb15((u8)~v);
        WS->clut15[i >> 2][i & 3] = prom_byte_to_rgb15((u8)~v);
    }
}

static void set_info(const char *title, const char *hw)
{
    char *p = WS->info;
    while (*title && p - WS->info < 48) *p++ = *title++;
    const char *sep = " (";
    while (*sep) *p++ = *sep++;
    while (*hw && p - WS->info < 92) *p++ = *hw++;
    *p++ = ')';
    *p = 0;
}

const char *arcade_load(const u8 *image, u32 size, const char *path)
{
#ifdef ARCADE_HOST
    u32 saved_rate = WS->sample_rate;
#endif
    /* If image overlaps EMU_RAM_PHYS? No, play.c loads cartridges into MEDIA_PHYS (0x02400000). */
    ws_zero(WS, sizeof(*WS) - sizeof(WS->zip_stage));
#ifdef ARCADE_HOST
    WS->sample_rate = saved_rate ? saved_rate : 48000u;
#else
    WS->sample_rate = 48000u;
#endif
    WS->gal_lfsr = 1u;
    WS->ay_lfsr = 1u;
    init_stars();

    if (!image || size == 0 || (path && !*path)) {
        build_builtin_maze_chomp();
        set_info("Maze Chomp", "Namco Pac-Man Z80 + WSG");
        arcade_reset();
        return 0;
    }

    if (!zip_is(image, size))
        return "not a Golden-Age Arcade .zip romset";
    if (size > sizeof(WS->zip_stage))
        return "arcade .zip too large";
    for (u32 i = 0; i < size; i++)
        WS->zip_stage[i] = image[i];
    const u8 *z = WS->zip_stage;

    /* 1. Pac-Man / Ms. Pac-Man / Homebrew Pac-Man (.6e/.6f/.6h/.6j or pacman.rom) */
    if (zip_load_named(z, size, "pacman.6e", WS->rom, 0x1000, 0) ||
        zip_load_named(z, size, "namcopac.6e", WS->rom, 0x1000, 0) ||
        zip_load_named(z, size, "pac.rom", WS->rom, 0x4000, 0)) {
        WS->board = BOARD_PACMAN;
        WS->scr_w = 224; WS->scr_h = 288;
        load_default_pacman_proms();
        zip_load_named(z, size, "pacman.6f", WS->rom + 0x1000, 0x1000, 0);
        zip_load_named(z, size, "pacman.6h", WS->rom + 0x2000, 0x1000, 0);
        zip_load_named(z, size, "pacman.6j", WS->rom + 0x3000, 0x1000, 0);
        zip_load_named(z, size, "namcopac.6f", WS->rom + 0x1000, 0x1000, 0);
        zip_load_named(z, size, "namcopac.6h", WS->rom + 0x2000, 0x1000, 0);
        zip_load_named(z, size, "namcopac.6j", WS->rom + 0x3000, 0x1000, 0);
        int has_t = zip_load_named(z, size, "pacman.5e", WS->gfx_tiles, 0x1000, 0);
        int has_s = zip_load_named(z, size, "pacman.5f", WS->gfx_sprites, 0x1000, 0);
        if (zip_load_named(z, size, "5e", WS->gfx_tiles, 0x1000, 0)) has_t = 1;
        if (zip_load_named(z, size, "5f", WS->gfx_sprites, 0x1000, 0)) has_s = 1;
        if (has_t || has_s)
            decode_pacman_gfx(256, 64);
        if (zip_load_named(z, size, "82s123.7f", WS->color_prom, 32, 0) &&
            zip_load_named(z, size, "82s126.4a", WS->color_prom + 0x20, 256, 0))
            setup_pacman_proms_from_buf();
        zip_load_named(z, size, "82s126.1m", WS->wave_prom, 256, 0);
        set_info((path && ci_has(path, "mspac")) ? "Ms. Pac-Man" : "Pac-Man Hardware", "3.072 MHz Z80 + Namco WSG");
        arcade_reset();
        return 0;
    }

    /* 2. Galaxian (galmidw.u / galaxian.rom) */
    if (zip_load_named(z, size, "galmidw.u", WS->rom, 0x800, 0) ||
        zip_load_named(z, size, "galaxian.rom", WS->rom, 0x4000, 0)) {
        WS->board = BOARD_GALAXIAN;
        WS->scr_w = 224; WS->scr_h = 256;
        zip_load_named(z, size, "galmidw.v", WS->rom + 0x0800, 0x800, 0);
        zip_load_named(z, size, "galmidw.w", WS->rom + 0x1000, 0x800, 0);
        zip_load_named(z, size, "galmidw.y", WS->rom + 0x1800, 0x800, 0);
        zip_load_named(z, size, "7l", WS->rom + 0x2000, 0x800, 0);
        zip_load_named(z, size, "1h.bin", WS->gfx_tiles, 0x800, 0);
        zip_load_named(z, size, "1k.bin", WS->gfx_tiles + 0x800, 0x800, 0);
        if (zip_load_named(z, size, "6l.bpr", WS->color_prom, 32, 0))
            setup_gal_proms_from_buf();
        decode_galaxian_gfx(0);
        set_info("Galaxian Hardware", "3.072 MHz Z80 + Starfield");
        arcade_reset();
        return 0;
    }

    /* 3. Konami Frogger / Scramble (frogger.26 / frogger.rom / scramble.rom) */
    if (zip_load_named(z, size, "frogger.26", WS->rom, 0x1000, 0) ||
        zip_load_named(z, size, "frogger.rom", WS->rom, 0x4000, 0)) {
        WS->board = BOARD_FROGGER;
        WS->scr_w = 224; WS->scr_h = 256;
        zip_load_named(z, size, "frogger.27", WS->rom + 0x1000, 0x1000, 0);
        zip_load_named(z, size, "frsm3.7", WS->rom + 0x2000, 0x1000, 0);
        zip_load_named(z, size, "frogger.608", WS->srom, 0x1000, 0);
        zip_load_named(z, size, "frogger.609", WS->srom + 0x0800, 0x800, 0);
        zip_load_named(z, size, "frogger.610", WS->srom + 0x1000, 0x800, 0);
        zip_load_named(z, size, "srom.bin", WS->srom, 0x2000, 0);
        int is_raw_gfx = zip_load_named(z, size, "gfx.bin", WS->gfx_tiles, 0x1000, 0);
        if (!is_raw_gfx) {
            zip_load_named(z, size, "frogger.606", WS->gfx_tiles, 0x800, 0);
            zip_load_named(z, size, "frogger.607", WS->gfx_tiles + 0x800, 0x800, 0);
        }
        if (zip_load_named(z, size, "pr-91.6l", WS->color_prom, 32, 0))
            setup_gal_proms_from_buf();
        decode_galaxian_gfx(is_raw_gfx ? 0 : 1);
        set_info("Konami Frogger Hardware", "Dual Z80 + AY-3-8910");
        arcade_reset();
        return 0;
    }

    /* 4. Nintendo Donkey Kong (c_5et_g.bin / dkong.rom) */
    if (zip_load_named(z, size, "c_5et_g.bin", WS->rom, 0x1000, 0) ||
        zip_load_named(z, size, "dkong.rom", WS->rom, 0x4000, 0)) {
        WS->board = BOARD_DKONG;
        WS->scr_w = 224; WS->scr_h = 256;
        zip_load_named(z, size, "c_5ct_g.bin", WS->rom + 0x1000, 0x1000, 0);
        zip_load_named(z, size, "c_5bt_g.bin", WS->rom + 0x2000, 0x1000, 0);
        zip_load_named(z, size, "c_5at_g.bin", WS->rom + 0x3000, 0x1000, 0);
        zip_load_named(z, size, "v_5h_b.bin", WS->gfx_tiles, 0x800, 0);
        zip_load_named(z, size, "v_3pt.bin", WS->gfx_tiles + 0x800, 0x800, 0);
        zip_load_named(z, size, "l_4m_b.bin", WS->gfx_sprites + 0x0000, 0x800, 0);
        zip_load_named(z, size, "l_4n_b.bin", WS->gfx_sprites + 0x0800, 0x800, 0);
        zip_load_named(z, size, "l_4r_b.bin", WS->gfx_sprites + 0x1000, 0x800, 0);
        zip_load_named(z, size, "l_4s_b.bin", WS->gfx_sprites + 0x1800, 0x800, 0);
        if (zip_load_named(z, size, "c-2k.bpr", WS->color_prom, 256, 0) &&
            zip_load_named(z, size, "c-2j.bpr", WS->color_prom + 0x100, 256, 0)) {
            zip_load_named(z, size, "v-5e.bpr", WS->color_prom + 0x200, 256, 0);
            setup_dkong_proms_from_buf();
        }
        decode_dkong_gfx();
        set_info("Donkey Kong Hardware", "3.072 MHz Z80 + DMA Sprites");
        arcade_reset();
        return 0;
    }

    return "unsupported arcade .zip (expected Pac-Man, Galaxian, Frogger or Donkey Kong romset)";
}

void arcade_reset(void)
{
    setup_z80_maps();
    z80_reset(&WS->cpu);
    z80_reset(&WS->scpu);
    WS->irq_en = 0;
    WS->sound_en = 0;
    WS->snd_head = WS->snd_tail = 0;
    WS->ay_regs[7] = 0x3Fu;
}

void arcade_frame(u16 pad, u16 *picture)
{
    WS->pad = pad;
    u8 sel_now = (pad & 0x04u) != 0;            /* Tab / Space = Coin */
    if (sel_now && !WS->coin_prev)
        WS->coin_pulse = 4u;
    WS->coin_prev = sel_now;

    /* 3,072,000 Hz / 60.606 Hz = 50,688 T-states per frame (192 T-states x 264 lines) */
    const s32 main_frame = 50688;
    const s32 snd_frame  = 29531;               /* 1.789772 MHz / 60.606 Hz */
    WS->cpu.cycles = 0;
    WS->scpu.cycles = 0;

    for (int slice = 1; slice <= 8; slice++) {
        z80_run(&WS->cpu, (main_frame * slice) / 8);
        if (WS->board == BOARD_FROGGER || WS->board == BOARD_SCRAMBLE)
            z80_run(&WS->scpu, (snd_frame * slice) / 8);
    }

    if (WS->irq_en) {
        if (WS->board == BOARD_PACMAN) {
            WS->cpu.bus = WS->irq_vec;
            WS->cpu.irq = 1;
        } else {
            WS->cpu.nmi = 1;
        }
    }
    if (WS->coin_pulse)
        WS->coin_pulse--;

    switch (WS->board) {
    case BOARD_PACMAN:
        render_pacman(picture);
        break;
    case BOARD_GALAXIAN:
    case BOARD_FROGGER:
    case BOARD_SCRAMBLE:
        render_gal_frogger(picture);
        break;
    case BOARD_DKONG:
        render_dkong(picture);
        break;
    }

    step_audio_frame();
}

int arcade_width(void)  { return WS->scr_w ? WS->scr_w : 224; }
int arcade_height(void) { return WS->scr_h ? WS->scr_h : 288; }
const char *arcade_info(void) { return WS->info; }
int arcade_jammed(void) { return WS->cpu.halted && !WS->irq_en && !WS->cpu.iff1; }

void arcade_audio_rate(u32 hz)
{
    WS->sample_rate = hz;
    WS->snd_frac = 0;
    WS->snd_head = WS->snd_tail = 0;
}

int arcade_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && WS->snd_tail != WS->snd_head) {
        out[n++] = WS->snd_ring[WS->snd_tail & (SND_RING - 1)];
        WS->snd_tail++;
    }
    return n;
}
