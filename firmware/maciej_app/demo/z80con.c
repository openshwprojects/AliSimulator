/* Casio PV-1000 & Bally Astrocade: see z80con.h. */
#pragma GCC optimize("O2")
#include "z80con.h"
#include "z80.h"
#ifndef Z80CON_HOST
#include "hw.h"
#endif

typedef signed char s8;

enum { SYS_PV1000 = 0, SYS_ASTRO = 1 };

/* Pad bits from play.c: A=0x01, B=0x02, SELECT=0x04, START=0x08,
   UP=0x10, DOWN=0x20, LEFT=0x40, RIGHT=0x80 */
#define PAD_A      0x01u
#define PAD_B      0x02u
#define PAD_SELECT 0x04u
#define PAD_START  0x08u
#define PAD_UP     0x10u
#define PAD_DOWN   0x20u
#define PAD_LEFT   0x40u
#define PAD_RIGHT  0x80u

#define AUDIO_RING_MAX 2048

struct pv_voice {
    u32 count;
    u16 period;
    u8  val;
};

struct z80con_ws {
    struct z80 cpu;
    u8  sys;
    u8  ext_bios;
    u16 pad;

    /* Shared/per-system memory in EMU_RAM_PHYS (zero static .bss!) */
    u8  rom[0x80000];           /* up to 512 KB cart ROM (PV-1000 8-32K, Astrocade 8-512K) */
    u32 rom_size;
    u8  bios[0x2000];           /* 8 KB Bally Astrocade BIOS ($0000..$1FFF) */
    u8  ram[0x10000];           /* 64 KB address space RAM ($B800..$BFFF on PV-1000; $4000..$FFFF on Astrocade) */
    u8  ff_page[0x400];         /* 1 KB 0xFF unmapped read page */

    /* Casio PV-1000 state */
    u8  pv_io[8];
    u8  pv_irq_en;
    u8  pv_irq_act;
    u8  pv_pcg_bank;
    u8  pv_force_pat;
    u8  pv_render_dis;
    u8  pv_border;
    u8  pv_snd_ctrl;
    struct pv_voice pv_v[3];
    u16 pv_pal[8];

    /* Bally Astrocade video & Magic RAM state */
    u8  ac_colors[8];
    u8  ac_line_colors[ASTRO_H][8];
    u8  ac_line_split[ASTRO_H];
    u8  ac_line_bg[ASTRO_H];
    u8  ac_line_vblank[ASTRO_H];
    u8  ac_line_mode[ASTRO_H];
    u8  ac_colorsplit;
    u8  ac_bgdata;
    u8  ac_vblank;
    u8  ac_vmode;
    u8  ac_fg_exp_col[2];
    u8  ac_fg_ctrl;
    u8  ac_fg_exp_cnt;
    u8  ac_fg_rot_cnt;
    u8  ac_fg_rot_buf[4];
    u8  ac_fg_prev;
    u8  ac_fg_intercept;
    u8  ac_int_en;
    u8  ac_int_fb;
    u8  ac_int_vec;
    u8  ac_int_line;
    u8  ac_int_clr_ack;
    u8  ac_vfeed;
    u8  ac_hfeed;
    u8  ac_cart_mapper;         /* 0: std 8K, 1: 256K, 2: 512K */
    u8  ac_cart_bank;
    u8  ac_knob;
    u8  ac_keypad[4];
    u8  ac_key_ttl[4];
    u8  ac_bitswap[256];
    u16 ac_pal[512];            /* 32 hues x 16 luma levels -> 15-bit 0bbbbbgggggrrrrr */

    /* Bally Astrocade custom sound chip */
    u8  ac_sreg[8];
    u8  ac_m_cnt;
    u8  ac_n_clk;
    u16 ac_n_lfsr;
    u16 ac_vib_clk;
    u8  ac_a_cnt, ac_a_st;
    u8  ac_b_cnt, ac_b_st;
    u8  ac_c_cnt, ac_c_st;

    /* Audio synthesis */
    u32 sample_rate;
    u32 snd_frac;
    u32 chip_frac;
    s32 dc_prev_in, dc_prev_out;
    s16 audio_ring[AUDIO_RING_MAX];
    int audio_count;

    char info[96];
};

#ifdef Z80CON_HOST
static struct z80con_ws host_ws;
#define WS (&host_ws)
#else
#define WS ((struct z80con_ws *)KSEG0(EMU_RAM_PHYS))
#endif

static inline u16 bgr555(int r, int g, int b)
{
    if (r < 0) r = 0; else if (r > 255) r = 255;
    if (g < 0) g = 0; else if (g > 255) g = 255;
    if (b < 0) b = 0; else if (b > 255) b = 255;
    return (u16)((((u32)b >> 3) << 10) | (((u32)g >> 3) << 5) | ((u32)r >> 3));
}

/* Precomputed R-Y and B-Y chrominance offsets (scaled by 256) for Astrocade's 32 YUV hues:
   color 0 is neutral grey (0,0); colors 1..31 circle 2*pi*(color/32) with ry=0.75*sin, by=1.15*cos */
static const s16 ac_ry_tab[32] = {
       0,   37,   73,  107,  136,  160,  177,  188,
     192,  188,  177,  160,  136,  107,   73,   37,
       0,  -37,  -73, -107, -136, -160, -177, -188,
    -192, -188, -177, -160, -136, -107,  -73,  -37
};

static const s16 ac_by_tab[32] = {
       0,  289,  272,  244,  208,  164,  113,   57,
       0,  -57, -113, -164, -208, -244, -272, -289,
    -294, -289, -272, -244, -208, -164, -113,  -57,
       0,   57,  113,  164,  208,  244,  272,  289
};

static void init_palettes(void)
{
    /* Casio PV-1000: 3-bit digital RGB (bit 2 = R, bit 1 = G, bit 0 = B) */
    for (int i = 0; i < 8; i++) {
        int r = (i & 4) ? 255 : 0;
        int g = (i & 2) ? 255 : 0;
        int b = (i & 1) ? 255 : 0;
        WS->pv_pal[i] = bgr555(r, g, b);
    }

    /* Bally Astrocade: 32 hues x 16 luminance steps */
    for (int col = 0; col < 32; col++) {
        s32 ry = ac_ry_tab[col];
        s32 by = ac_by_tab[col];
        for (int luma = 0; luma < 16; luma++) {
            s32 y = (luma * 256) / 15;
            s32 r = ry + y;
            s32 b = by + y;
            /* g = (y - 0.299*r - 0.114*b) / 0.587 ~= (1000*y - 299*r - 114*b) / 587 */
            s32 g = (1000 * y - 299 * r - 114 * b) / 587;
            WS->ac_pal[col * 16 + luma] = bgr555((int)r, (int)g, (int)b);
        }
    }

    for (int i = 0; i < 256; i++) {
        u8 b = 0;
        for (int k = 0; k < 8; k++)
            if (i & (1 << k))
                b |= (u8)(0x80u >> k);
        WS->ac_bitswap[i] = b;
    }
}

/* ========================================================================
 * CASIO PV-1000
 * ======================================================================== */

static u8 pv_joy_read(void)
{
    u8 sel = WS->pv_io[5];
    u16 p = WS->pad;
    u8 d = 0;
    if (sel & 0x01u) {
        if (p & PAD_SELECT) d |= 0x01u;
        if (p & PAD_START)  d |= 0x02u;
    }
    if (sel & 0x02u) {
        if (p & PAD_DOWN)   d |= 0x01u;
        if (p & PAD_RIGHT)  d |= 0x02u;
    }
    if (sel & 0x04u) {
        if (p & PAD_LEFT)   d |= 0x01u;
        if (p & PAD_UP)     d |= 0x02u;
    }
    if (sel & 0x08u) {
        if (p & PAD_A)      d |= 0x01u;
        if (p & PAD_B)      d |= 0x02u;
    }
    return d & 0x0Fu;
}

static __attribute__((noinline)) u8 pv_mem_read(struct z80 *c, u16 a)
{
    (void)c;
    if (a < 0x8000u)
        return (a < WS->rom_size) ? WS->rom[a] : 0xFFu;
    if (a >= 0xB800u && a < 0xC000u)
        return WS->ram[a];
    return 0xFFu;
}

static __attribute__((noinline)) void pv_mem_write(struct z80 *c, u16 a, u8 v)
{
    (void)c;
    if (a >= 0xB800u && a < 0xC000u)
        WS->ram[a] = v;
}

static __attribute__((noinline)) u8 pv_io_in(struct z80 *c, u16 port)
{
    u8 p = (u8)(port & 0xFFu);
    if (p == 0xFCu)
        return (u8)(0x80u | (pv_joy_read() & 0x0Cu) | (WS->pv_irq_act & 3u));
    if (p == 0xFDu) {
        if (WS->pv_irq_act & 2u) {
            WS->pv_irq_act &= (u8)~2u;
            if (!WS->pv_irq_act)
                c->irq = 0;
        }
        return (u8)(0x80u | pv_joy_read());
    }
    return 0xFFu;
}

static __attribute__((noinline)) void pv_io_out(struct z80 *c, u16 port, u8 v)
{
    u8 p = (u8)(port & 0xFFu);
    if (p < 0xF8u)
        return;
    u8 off = (u8)(p - 0xF8u);
    WS->pv_io[off] = v;
    switch (off) {
    case 0:
    case 1:
    case 2: {
        u8 per = (u8)((~v) & 0x3Fu);
        if (per == 0 && WS->pv_v[off].period != 0)
            WS->pv_v[off].val ^= 1u;
        WS->pv_v[off].period = per;
        break;
    }
    case 3:
        WS->pv_snd_ctrl = v;
        break;
    case 4: /* $FC: IRQ enable (bit 1 = matrix, bit 0 = prerender) */
        WS->pv_irq_en = v & 3u;
        WS->pv_irq_act &= WS->pv_irq_en;
        if (!WS->pv_irq_act)
            c->irq = 0;
        break;
    case 5: /* $FD: joystick mux + acknowledge prerender IRQ */
        if (WS->pv_irq_act & 1u) {
            WS->pv_irq_act &= (u8)~1u;
            if (!WS->pv_irq_act)
                c->irq = 0;
        }
        break;
    case 7: /* $FF: PCG bank, force_pattern, render_disable, border */
        WS->pv_pcg_bank = (v >> 5) & 7u;
        WS->pv_force_pat = (v >> 4) & 1u;
        WS->pv_render_dis = (v >> 3) & 1u;
        WS->pv_border = v & 7u;
        break;
    }
}

/* Step PV-1000 sound for one scanline (~66.69 us -> ~1.166 ticks of 17478.25 Hz) */
static void pv_sound_step_lines(u32 n_lines)
{
    if (!WS->sample_rate)
        return;
    /* 262 lines * 59.9227 Hz = 15699.75 Hz line rate.
       PV-1000 sound clock = 17897725 / 1024 = 17478.247 Hz.
       Generate output samples at WS->sample_rate, advancing 17478.25 Hz counter per sample! */
    u32 total_mclk_div5 = n_lines * 228u; /* 3.579545 MHz Z80 T-states */
    u32 num = total_mclk_div5 * WS->sample_rate + WS->snd_frac;
    u32 n_samp = num / 3579545u;
    WS->snd_frac = num % 3579545u;

    while (n_samp--) {
        WS->chip_frac += 17478u;
        while (WS->chip_frac >= WS->sample_rate) {
            WS->chip_frac -= WS->sample_rate;
            for (int i = 0; i < 3; i++) {
                WS->pv_v[i].count++;
                if (WS->pv_v[i].period > 0 && WS->pv_v[i].count >= WS->pv_v[i].period) {
                    WS->pv_v[i].count = 0;
                    WS->pv_v[i].val ^= 1u;
                }
            }
        }
        s32 sum = 0;
        if (WS->pv_snd_ctrl & 2u) {
            if (WS->pv_snd_ctrl & 1u) {
                sum += ((WS->pv_v[0].val ^ WS->pv_v[1].val) & 1u) ? 3500 : -3500;
                sum += ((WS->pv_v[1].val ^ WS->pv_v[2].val) & 1u) ? 5200 : -5200;
            } else {
                sum += WS->pv_v[0].val ? 3500 : -3500;
                sum += WS->pv_v[1].val ? 5200 : -5200;
            }
            sum += WS->pv_v[2].val ? 7000 : -7000;
        }
        if (WS->audio_count < AUDIO_RING_MAX)
            WS->audio_ring[WS->audio_count++] = (s16)sum;
    }
}

static void pv_render_frame(u16 *pic)
{
    if (!pic)
        return;
    u16 border = WS->pv_pal[WS->pv_border & 7u];
    u16 black = WS->pv_pal[0];
    if (WS->pv_render_dis) {
        for (int i = 0; i < PV1000_W * PV1000_H; i++)
            pic[i] = border;
        return;
    }
    const u8 *vram = &WS->ram[0xB800];
    const u8 *pcgram = &WS->ram[0xBC00];
    for (int ty = 0; ty < 24; ty++) {
        /* Left & right 2 columns (16 px each) are blanked/border */
        for (int row = 0; row < 8; row++) {
            u16 *dst = pic + (ty * 8 + row) * PV1000_W;
            for (int x = 0; x < 16; x++) {
                dst[x] = black;
                dst[240 + x] = black;
            }
        }
        for (int tx = 2; tx < 30; tx++) {
            u32 tile = vram[ty * 32 + tx];
            const u8 *pat;
            if (tile < 0xE0u || WS->pv_force_pat) {
                u32 idx = (((u32)WS->pv_pcg_bank << 8) + tile) * 32u;
                pat = (idx + 32u <= WS->rom_size) ? &WS->rom[idx] : WS->ff_page;
            } else {
                u32 idx = (tile - 0xE0u) * 32u;
                pat = &pcgram[idx & 0x3E0u];
            }
            /* Bytes 8..15 = R (bit 2), 16..23 = G (bit 1), 24..31 = B (bit 0) */
            for (int row = 0; row < 8; row++) {
                u8 pr = (pat == WS->ff_page) ? 0 : pat[8 + row];
                u8 pg = (pat == WS->ff_page) ? 0 : pat[16 + row];
                u8 pb = (pat == WS->ff_page) ? 0 : pat[24 + row];
                u16 *dst = pic + (ty * 8 + row) * PV1000_W + tx * 8;
                for (int bit = 7; bit >= 0; bit--) {
                    u8 col = (u8)((((pr >> bit) & 1u) << 2) |
                                  (((pg >> bit) & 1u) << 1) |
                                  (((pb >> bit) & 1u) << 0));
                    *dst++ = WS->pv_pal[col];
                }
            }
        }
    }
}

static void pv_frame(u16 *picture)
{
    /* 262 scanlines:
       Active display lines 26..217 (192 lines): BUSREQ steals ~48 T-states when rendering enabled.
       VBlank Matrix IRQs fire every 4 lines at: 222, 226, 230, 234, 238, 242, 246, 250, 254, 258,
       0, 4, 8, 12, 16, 20 (and line 20 also asserts Prerender IRQ bit 0!). */
    WS->cpu.cycles = 0;
    s32 target = 0;
    for (int line = 0; line < 262; line++) {
        if ((line >= 222 && ((line - 222) & 3) == 0) || (line <= 20 && (line & 3) == 0)) {
            WS->pv_irq_act |= (u8)(2u & WS->pv_irq_en);
            if (line == 20)
                WS->pv_irq_act |= (u8)(1u & WS->pv_irq_en);
            if (WS->pv_irq_act)
                WS->cpu.irq = 1;
        }
        s32 cyc = (line >= 26 && line < 218 && !WS->pv_render_dis) ? 172 : 228;
        target += cyc;
        z80_run(&WS->cpu, target);
        pv_sound_step_lines(1);
    }
    pv_render_frame(picture);
}

/* ========================================================================
 * BALLY ASTROCADE
 * ======================================================================== */

static void ac_irq_ack(struct z80 *c)
{
    if (WS->ac_int_clr_ack)
        c->irq = 0;
}

/* Data Chip Magic RAM Function Generator ($0000..$0FFF write -> $4000..$4FFF) */
static void ac_funcgen_write(u16 offset, u8 data)
{
    u8 ctrl = WS->ac_fg_ctrl;
    if (ctrl & 0x08u) { /* Expand 1bpp nibble -> 2bpp byte */
        u8 sh = (u8)(4u * WS->ac_fg_exp_cnt);
        WS->ac_fg_exp_cnt ^= 1u;
        u8 nib = (u8)(data >> sh);
        data = (u8)((WS->ac_fg_exp_col[(nib >> 3) & 1u] << 6) |
                    (WS->ac_fg_exp_col[(nib >> 2) & 1u] << 4) |
                    (WS->ac_fg_exp_col[(nib >> 1) & 1u] << 2) |
                    (WS->ac_fg_exp_col[(nib >> 0) & 1u] << 0));
    }
    u8 prev = WS->ac_fg_prev;
    WS->ac_fg_prev = data;

    if (ctrl & 0x04u) { /* Rotate 4x4 2bpp block */
        if ((WS->ac_fg_rot_cnt & 4u) == 0u) {
            WS->ac_fg_rot_buf[WS->ac_fg_rot_cnt & 3u] = data;
            WS->ac_fg_rot_cnt++;
            return;
        } else {
            u8 shift = (u8)(2u * ((~WS->ac_fg_rot_cnt) & 3u));
            WS->ac_fg_rot_cnt++;
            data = (u8)((((WS->ac_fg_rot_buf[3] >> shift) & 3u) << 6) |
                        (((WS->ac_fg_rot_buf[2] >> shift) & 3u) << 4) |
                        (((WS->ac_fg_rot_buf[1] >> shift) & 3u) << 2) |
                        (((WS->ac_fg_rot_buf[0] >> shift) & 3u) << 0));
        }
    } else { /* Shift by 0..3 2-bit pixels */
        u8 shift = (u8)(2u * (ctrl & 3u));
        if (shift)
            data = (u8)((data >> shift) | (prev << (8u - shift)));
    }

    if (ctrl & 0x40u) { /* Horizontal flop (mirror 4 2-bit pixels) */
        data = (u8)((data >> 6) | ((data >> 2) & 0x0Cu) | ((data << 2) & 0x30u) | (data << 6));
    }

    u16 dst = (u16)(0x4000u + (offset & 0x0FFFu));
    if (ctrl & 0x30u) { /* OR (0x10) / XOR (0x20) + collision intercept */
        u8 old = WS->ram[dst];
        WS->ac_fg_intercept &= 0x0Fu;
        if ((old & 0xC0u) && (data & 0xC0u)) WS->ac_fg_intercept |= 0x11u;
        if ((old & 0x30u) && (data & 0x30u)) WS->ac_fg_intercept |= 0x22u;
        if ((old & 0x0Cu) && (data & 0x0Cu)) WS->ac_fg_intercept |= 0x44u;
        if ((old & 0x03u) && (data & 0x03u)) WS->ac_fg_intercept |= 0x88u;
        if (ctrl & 0x10u)
            data |= old;
        else if (ctrl & 0x20u)
            data ^= old;
    }
    WS->ram[dst] = data;
}

static __attribute__((noinline)) u8 ac_mem_read(struct z80 *c, u16 a)
{
    (void)c;
    if (a < 0x2000u)
        return WS->bios[a];
    if (a < 0x4000u) {
        u16 off = (u16)(a - 0x2000u);
        if (WS->ac_cart_mapper == 1) { /* 256 KB */
            if (off < 0x1000u)
                return WS->rom[(0x3Fu * 0x1000u + off) % WS->rom_size];
            if (off < 0x1FC0u)
                return WS->rom[((u32)WS->ac_cart_bank * 0x1000u + (off & 0x0FFFu)) % WS->rom_size];
            WS->ac_cart_bank = (u8)(off & 0x3Fu);
            return WS->ac_cart_bank;
        }
        if (WS->ac_cart_mapper == 2) { /* 512 KB */
            if (off < 0x1000u)
                return WS->rom[(0x7Fu * 0x1000u + off) % WS->rom_size];
            if (off < 0x1F80u)
                return WS->rom[((u32)WS->ac_cart_bank * 0x1000u + (off & 0x0FFFu)) % WS->rom_size];
            WS->ac_cart_bank = (u8)(off & 0x7Fu);
            return WS->ac_cart_bank;
        }
        return (off < WS->rom_size) ? WS->rom[off] : 0xFFu;
    }
    return WS->ram[a];
}

static __attribute__((noinline)) void ac_mem_write(struct z80 *c, u16 a, u8 v)
{
    (void)c;
    if (a < 0x1000u) {
        ac_funcgen_write(a, v);
        return;
    }
    if (a >= 0x4000u)
        WS->ram[a] = v;
}

static __attribute__((noinline)) u8 ac_io_in(struct z80 *c, u16 port)
{
    (void)c;
    u8 p = (u8)(port & 0xFFu);
    if (p < 0x10u) {
        switch (p) {
        case 0x08: {
            u8 r = WS->ac_fg_intercept;
            WS->ac_fg_intercept = 0;
            return r;
        }
        case 0x0E: return WS->ac_vfeed;
        case 0x0F: return WS->ac_hfeed;
        default:   return 0xFFu;
        }
    }
    if (p < 0x20u) {
        u8 sub = (u8)(p & 0x0Fu);
        if (sub < 4u) {
            /* Hand controllers 1..4: Up=0x01, Down=0x02, Left=0x04, Right=0x08, Trigger=0x10 */
            if (sub != 0u)
                return 0;
            u8 h = 0;
            if (WS->pad & PAD_UP)    h |= 0x01u;
            if (WS->pad & PAD_DOWN)  h |= 0x02u;
            if (WS->pad & PAD_LEFT)  h |= 0x04u;
            if (WS->pad & PAD_RIGHT) h |= 0x08u;
            if (WS->pad & (PAD_A | PAD_B)) h |= 0x10u;
            return h;
        }
        if (sub < 8u) {
            u8 col = (u8)(sub & 3u);
            u8 k = WS->ac_keypad[col];
            /* Map Start -> '1' (col 3 bit 4) or 'GO' (col 3 bit 0); Select -> '2' (col 2 bit 4) */
            if (col == 3u && (WS->pad & PAD_START))
                k |= 0x11u;
            if (col == 2u && (WS->pad & PAD_SELECT))
                k |= 0x10u;
            return k;
        }
        if (sub >= 0x0Cu)
            return (sub == 0x0Cu) ? WS->ac_knob : 0x80u;
    }
    return 0xFFu;
}

static __attribute__((noinline)) void ac_io_out(struct z80 *c, u16 port, u8 v)
{
    u8 p = (u8)(port & 0xFFu);
    if (p < 0x10u) {
        switch (p) {
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x04: case 0x05: case 0x06: case 0x07:
            WS->ac_colors[p & 7u] = v;
            break;
        case 0x08:
            WS->ac_vmode = v & 1u;
            break;
        case 0x09:
            WS->ac_colorsplit = (u8)(2u * (v & 0x3Fu));
            WS->ac_bgdata = (u8)(((v >> 6) & 3u) * 0x55u);
            break;
        case 0x0A:
            WS->ac_vblank = v;
            break;
        case 0x0B: /* Color block transfer (OTIR / OUT (C),r uses B & 7) */
            WS->ac_colors[(port >> 8) & 7u] = v;
            break;
        case 0x0C:
            WS->ac_fg_ctrl = v;
            WS->ac_fg_exp_cnt = 0;
            WS->ac_fg_rot_cnt = 0;
            WS->ac_fg_prev = 0;
            break;
        case 0x0D:
            WS->ac_int_fb = v;
            c->irq = 0;
            break;
        case 0x0E:
            WS->ac_int_en = v;
            c->irq = 0;
            break;
        case 0x0F:
            WS->ac_int_line = v;
            c->irq = 0;
            break;
        }
        return;
    }
    if (p >= 0x10u && p <= 0x18u) {
        u8 reg = (p & 8u) ? (u8)((port >> 8) & 7u) : (u8)(p & 7u);
        WS->ac_sreg[reg] = v;
        return;
    }
    if (p == 0x19u) {
        WS->ac_fg_exp_col[0] = v & 3u;
        WS->ac_fg_exp_col[1] = (v >> 2) & 3u;
    }
}

/* Step Bally Astrocade 3-voice + vibrato + 15-bit LFSR noise sound for `z_cyc` 1.7897725 MHz clocks */
static void ac_sound_step(u32 z_cyc)
{
    if (!WS->sample_rate || !z_cyc)
        return;
    /* Step the hardware counters in exact chunks up to master oscillator / noise boundaries */
    u32 rem = z_cyc;
    while (rem > 0) {
        u32 step = rem;
        u32 to_m = 256u - WS->ac_m_cnt;
        u32 to_n = 64u - WS->ac_n_clk;
        if (step > to_m) step = to_m;
        if (step > to_n) step = to_n;

        s32 cur = 0;
        if (WS->ac_a_st) cur += (WS->ac_sreg[6] & 0x0Fu);
        if (WS->ac_b_st) cur += (WS->ac_sreg[6] >> 4);
        if (WS->ac_c_st) cur += (WS->ac_sreg[5] & 0x0Fu);
        if ((WS->ac_sreg[5] & 0x20u) && (WS->ac_n_lfsr & 0x4000u))
            cur += (WS->ac_sreg[7] >> 4);

        /* Emit resampled 48 kHz samples across `step` 1.7897725 MHz ticks */
        u32 num = step * WS->sample_rate + WS->snd_frac;
        u32 ns = num / 1789772u;
        WS->snd_frac = num % 1789772u;
        while (ns--) {
            /* DC-blocker keeps centered waveform crisp without speaker thump */
            s32 x = cur * 520;
            s32 y = x - WS->dc_prev_in + ((WS->dc_prev_out * 253) >> 8);
            WS->dc_prev_in = x;
            WS->dc_prev_out = y;
            if (y > 32767) y = 32767;
            if (y < -32768) y = -32768;
            if (WS->audio_count < AUDIO_RING_MAX)
                WS->audio_ring[WS->audio_count++] = (s16)y;
        }

        WS->ac_n_clk = (u8)(WS->ac_n_clk + step);
        if (WS->ac_n_clk >= 64u) {
            WS->ac_n_clk -= 64u;
            u16 fb = (u16)((~((WS->ac_n_lfsr >> 14) ^ (WS->ac_n_lfsr >> 13))) & 1u);
            WS->ac_n_lfsr = (u16)((WS->ac_n_lfsr << 1) | fb);
            WS->ac_vib_clk++;
        }

        WS->ac_m_cnt = (u8)(WS->ac_m_cnt + step);
        if (WS->ac_m_cnt == 0u) {
            u8 reload = (u8)(~WS->ac_sreg[0]);
            if ((WS->ac_sreg[5] & 0x10u) == 0u) {
                if (!((WS->ac_vib_clk >> (WS->ac_sreg[4] >> 6)) & 0x0200u))
                    reload = (u8)(reload + (WS->ac_sreg[4] & 0x3Fu));
            } else {
                reload = (u8)(reload + (WS->ac_bitswap[(WS->ac_n_lfsr >> 7) & 0xFFu] & WS->ac_sreg[7]));
            }
            WS->ac_m_cnt = reload;
            if (++WS->ac_a_cnt == 0u) { WS->ac_a_st ^= 1u; WS->ac_a_cnt = (u8)(~WS->ac_sreg[1]); }
            if (++WS->ac_b_cnt == 0u) { WS->ac_b_st ^= 1u; WS->ac_b_cnt = (u8)(~WS->ac_sreg[2]); }
            if (++WS->ac_c_cnt == 0u) { WS->ac_c_st ^= 1u; WS->ac_c_cnt = (u8)(~WS->ac_sreg[3]); }
        }
        rem -= step;
    }
}

/* Clean-room Bally Astrocade 8 KB System BIOS + built-in Star Blaster game when no cart is loaded */
static void ac_build_bios(void)
{
    for (u32 i = 0; i < sizeof(WS->bios); i++)
        WS->bios[i] = 0xC9u; /* RET safe default */

    /* 5x7 compact bitmap glyphs at $1C00..$1DFF for built-in banner/HUD */
    static const u8 mini_glyphs[16][5] = {
        {0x3E,0x51,0x49,0x45,0x3E}, /* 0 */
        {0x00,0x42,0x7F,0x40,0x00}, /* 1 */
        {0x42,0x61,0x51,0x49,0x46}, /* 2 */
        {0x21,0x41,0x45,0x4B,0x31}, /* 3 */
        {0x18,0x14,0x12,0x7F,0x10}, /* 4 */
        {0x27,0x45,0x45,0x45,0x39}, /* 5 */
        {0x3C,0x4A,0x49,0x49,0x30}, /* 6 */
        {0x01,0x71,0x09,0x05,0x03}, /* 7 */
        {0x36,0x49,0x49,0x49,0x36}, /* 8 */
        {0x06,0x49,0x49,0x29,0x1E}, /* 9 */
        {0x7E,0x11,0x11,0x11,0x7E}, /* A */
        {0x7F,0x49,0x49,0x49,0x36}, /* B */
        {0x46,0x49,0x49,0x49,0x31}, /* S */
        {0x01,0x01,0x7F,0x01,0x01}, /* T */
        {0x7F,0x09,0x19,0x29,0x46}, /* R */
        {0x3E,0x41,0x41,0x41,0x3E}, /* O */
    };
    for (int i = 0; i < 16; i++)
        for (int k = 0; k < 5; k++)
            WS->bios[0x1C00 + i * 8 + k] = mini_glyphs[i][k];

    /* $0000: Reset entry -> JP $0200 */
    WS->bios[0x0000] = 0xF3; /* DI */
    WS->bios[0x0001] = 0xC3; WS->bios[0x0002] = 0x00; WS->bios[0x0003] = 0x02;

    /* $0038: RST 38H / IM 1 / UPI SYSTEM dispatcher -> JP $0180 */
    WS->bios[0x0038] = 0xC3; WS->bios[0x0039] = 0x80; WS->bios[0x003A] = 0x01;

    /* $0066: NMI -> RETN */
    WS->bios[0x0066] = 0xED; WS->bios[0x0067] = 0x45;

    /* $0080..$00FE: Default IM 2 vector table (I = $00) pointing to $0100 ISR */
    for (u32 v = 0x0080; v < 0x0100; v += 2) {
        WS->bios[v]     = 0x00;
        WS->bios[v + 1] = 0x01;
    }

    /* $0100: Default VBlank ISR: increments frame counter at $4FF8, acks IRQ via OUT ($0D),A, EI, RETI */
    static const u8 isr_code[] = {
        0xF5,                   /* PUSH AF */
        0xE5,                   /* PUSH HL */
        0x21, 0xF8, 0x4F,       /* LD HL,$4FF8 */
        0x34,                   /* INC (HL) */
        0x3E, 0xD0,             /* LD A,$D0 */
        0xD3, 0x0D,             /* OUT ($0D),A */
        0xE1,                   /* POP HL */
        0xF1,                   /* POP AF */
        0xFB,                   /* EI */
        0xED, 0x4D              /* RETI */
    };
    for (u32 i = 0; i < sizeof(isr_code); i++)
        WS->bios[0x0100 + i] = isr_code[i];

    /* $0180: UPI RST 38H handler (trap address $0180 handled by C HLE helper for UPI system calls!) */
    WS->bios[0x0180] = 0xFB; /* EI */
    WS->bios[0x0181] = 0xC9; /* RET */

    /* $0200: Hardware init & cartridge boot / built-in game launcher */
    static const u8 boot_code[] = {
        0xF3,                   /* DI */
        0x31, 0xE0, 0x4F,       /* LD SP,$4FE0 */
        0xAF,                   /* XOR A */
        0xED, 0x47,             /* LD I,A */
        0xED, 0x5E,             /* IM 2 */
        /* Set default palette ($00..$07), split ($09=$28 -> full 160px left pal), vblank ($0A=$CC -> 204 lines) */
        0x21, 0x60, 0x02,       /* LD HL,$0260 (init table) */
        0x06, 0x08,             /* LD B,8 */
        0x0E, 0x0B,             /* LD C,$0B (color block port) */
        0xED, 0xB3,             /* OTIR */
        0xAF,                   /* XOR A */
        0xD3, 0x08,             /* OUT ($08),A (160x102 low-res) */
        0xD3, 0x0C,             /* OUT ($0C),A (funcgen normal) */
        0x3E, 0x28,             /* LD A,$28 (colorsplit = 80 bytes = full screen left colors 4..7) */
        0xD3, 0x09,             /* OUT ($09),A */
        0x3E, 0xCC,             /* LD A,204 */
        0xD3, 0x0A,             /* OUT ($0A),A */
        0x3E, 0xD0,             /* LD A,$D0 (IM2 vector $00D0) */
        0xD3, 0x0D,             /* OUT ($0D),A */
        0x3E, 0xCC,             /* LD A,204 (VBlank line) */
        0xD3, 0x0F,             /* OUT ($0F),A */
        0x3E, 0x08,             /* LD A,$08 (enable line IRQ) */
        0xD3, 0x0E,             /* OUT ($0E),A */
        /* Clear screen RAM $4000..$4FDF */
        0x21, 0x00, 0x40,       /* LD HL,$4000 */
        0x11, 0x01, 0x40,       /* LD DE,$4001 */
        0x01, 0xDF, 0x0F,       /* LD BC,$0FDF */
        0x36, 0x00,             /* LD (HL),0 */
        0xED, 0xB0,             /* LDIR */
        /* Check cartridge at $2000:
           - $55: standard Astrocade cart header -> jump to ($2005)
           - $33: autostart cart -> jump to ($2001)
           - != $FF: raw code at $2000 -> jump to $2000
           - $FF: no cart -> jump to built-in Star Blaster at $0300 */
        0x3A, 0x00, 0x20,       /* LD A,($2000) */
        0xFE, 0x55,             /* CP $55 */
        0xCA, 0x50, 0x02,       /* JP Z,$0250 (boot_55) */
        0xFE, 0x33,             /* CP $33 */
        0xCA, 0x58, 0x02,       /* JP Z,$0258 (boot_33) */
        0xFE, 0xFF,             /* CP $FF */
        0xCA, 0x00, 0x03,       /* JP Z,$0300 (no_cart -> built-in game) */
        0xFB,                   /* EI */
        0xC3, 0x00, 0x20        /* JP $2000 (raw cart) */
    };
    for (u32 i = 0; i < sizeof(boot_code); i++)
        WS->bios[0x0200 + i] = boot_code[i];

    /* $0250: boot_55 -> LD HL,($2005); EI; JP (HL) */
    WS->bios[0x0250] = 0x2A; WS->bios[0x0251] = 0x05; WS->bios[0x0252] = 0x20;
    WS->bios[0x0253] = 0xFB; WS->bios[0x0254] = 0xE9;
    /* $0258: boot_33 -> LD HL,($2001); EI; JP (HL) */
    WS->bios[0x0258] = 0x2A; WS->bios[0x0259] = 0x01; WS->bios[0x025A] = 0x20;
    WS->bios[0x025B] = 0xFB; WS->bios[0x025C] = 0xE9;

    /* $0260: OTIR color palette (loaded backwards B=8..1 -> ports 0..7; colors[4..7] are active left split):
       col 0 = $00 (black), col 1 = $A7 (bright cyan), col 2 = $37 (gold/orange), col 3 = $07 (white) */
    static const u8 init_pal[8] = {
        0x07, 0x37, 0xA7, 0x00, /* B=8->0(r0), 7->r7(white), 6->r6(gold), 5->r5(cyan), 4->r4(black) */
        0x07, 0x37, 0xA7, 0x00
    };
    /* Note: OTIR sends (HL) to port (C) with B=8,7,6,5,4,3,2,1, and port>>8 = B BEFORE or AFTER?
       In Z80 OTIR, B is decremented BEFORE placing BC on the bus (so B=7,6,5,4,3,2,1,0)! */
    static const u8 otir_pal[8] = {
        0x0F, /* B=7 -> color 7 (pixel 3: bright white) */
        0x67, /* B=6 -> color 6 (pixel 2: warm gold/orange) */
        0xDF, /* B=5 -> color 5 (pixel 1: electric cyan/blue) */
        0x00, /* B=4 -> color 4 (pixel 0: deep space black) */
        0x0F, /* B=3 -> color 3 */
        0x67, /* B=2 -> color 2 */
        0xDF, /* B=1 -> color 1 */
        0x00  /* B=0 -> color 0 */
    };
    (void)init_pal;
    for (int i = 0; i < 8; i++)
        WS->bios[0x0260 + i] = otir_pal[i];

    /* $0300: Built-in Z80 mini-game (Astro Starfield & Laser Ship) when launched without a cartridge */
    static const u8 builtin_game[] = {
        0xFB,                   /* $0300: EI */
        0x3E, 0x4F,             /* $0301: LD A,79 (master osc) */
        0xD3, 0x10,             /* $0303: OUT ($10),A */
        0x3E, 0x88,             /* $0305: LD A,$88 (ch A & B vol) */
        0xD3, 0x16,             /* $0307: OUT ($16),A */
        0x3E, 0x12,             /* $0309: LD A,18 (ship X 0..38) */
        0x32, 0xF0, 0x4F,       /* $030B: LD ($4FF0),A */
        /* loop ($030E): wait VBlank change on $4FF8 */
        0x21, 0xF8, 0x4F,       /* $030E: LD HL,$4FF8 */
        0x7E,                   /* $0311: LD A,(HL) */
        0xBE,                   /* $0312: CP (HL) */
        0x28, 0xFD,             /* $0313: JR Z,-3 ($0312) */
        /* Read joystick port $10 and move ship X ($4FF0) */
        0xDB, 0x10,             /* $0315: IN A,($10) */
        0x47,                   /* $0317: LD B,A */
        0x3A, 0xF0, 0x4F,       /* $0318: LD A,($4FF0) */
        0xCB, 0x50,             /* $031B: BIT 2,B (Left) */
        0x28, 0x05,             /* $031D: JR Z,+5 */
        0xFE, 0x02,             /* $031F: CP 2 */
        0x38, 0x01,             /* $0321: JR C,+1 */
        0x3D,                   /* $0323: DEC A */
        0xCB, 0x58,             /* $0324: BIT 3,B (Right) */
        0x28, 0x05,             /* $0326: JR Z,+5 */
        0xFE, 0x24,             /* $0328: CP 36 */
        0x30, 0x01,             /* $032A: JR NC,+1 */
        0x3C,                   /* $032C: INC A */
        0x32, 0xF0, 0x4F,       /* $032D: LD ($4FF0),A */
        /* Sound: play space arpeggio + laser chirp on trigger (bit 4) */
        0x3A, 0xF8, 0x4F,       /* LD A,($4FF8) */
        0xE6, 0x3F,             /* AND $3F */
        0xC6, 0x60,             /* ADD A,$60 */
        0xD3, 0x11,             /* OUT ($11),A (tone A) */
        0xCB, 0x60,             /* BIT 4,B (Trigger) */
        0x28, 0x05,             /* JR Z,+5 (skips CPL; OUT ($12),A; JR +3) */
        0x2F,                   /* CPL */
        0xD3, 0x12,             /* OUT ($12),A */
        0x18, 0x03,             /* JR +3 (skips XOR A; OUT ($12),A) */
        0xAF,                   /* XOR A */
        0xD3, 0x12,             /* OUT ($12),A */
        /* Clear playfield $4000..$4EDF */
        0xAF,                   /* XOR A */
        0xD3, 0x0C,             /* OUT ($0C),A (funcgen normal) */
        0x21, 0x00, 0x40,       /* LD HL,$4000 */
        0x11, 0x01, 0x40,       /* LD DE,$4001 */
        0x01, 0xDF, 0x0E,       /* LD BC,$0EDF */
        0x36, 0x00,             /* LD (HL),0 */
        0xED, 0xB0,             /* LDIR */
        /* Draw top cyber border ($4028..$404F) */
        0x21, 0x28, 0x40,       /* LD HL,$4028 */
        0x06, 0x28,             /* LD B,40 */
        0x36, 0xAA,             /* LD (HL),$AA */
        0x23,                   /* INC HL */
        0x10, 0xFB,             /* DJNZ -5 */
        /* Draw 24 scrolling stars & alien cruisers */
        0x3A, 0xF8, 0x4F,       /* LD A,($4FF8) */
        0x4F,                   /* LD C,A */
        0x06, 0x18,             /* LD B,24 */
        0x21, 0x84, 0x40,       /* LD HL,$4084 */
        0x79,                   /* star_lp: LD A,C */
        0x80,                   /* ADD A,B */
        0xE6, 0x03,             /* AND 3 */
        0xC6, 0x0C,             /* ADD A,$0C */
        0x77,                   /* LD (HL),A */
        0x11, 0x5B, 0x00,       /* LD DE,91 */
        0x19,                   /* ADD HL,DE */
        0x10, 0xF2,             /* DJNZ -14 */
        /* Draw player starfighter at row 88 ($0DC0 + X -> Magic RAM $4DC0 + X) */
        0x3E, 0x10,             /* LD A,$10 (Magic RAM OR mode) */
        0xD3, 0x0C,             /* OUT ($0C),A */
        0x3A, 0xF0, 0x4F,       /* LD A,($4FF0) */
        0xC6, 0xC0,             /* ADD A,$C0 */
        0x6F,                   /* LD L,A */
        0x26, 0x0D,             /* LD H,$0D */
        0x30, 0x01,             /* JR NC,+1 */
        0x24,                   /* INC H */
        0x11, 0x28, 0x00,       /* LD DE,40 */
        0x36, 0x3C,             /* LD (HL),$3C (nose) */
        0x19,                   /* ADD HL,DE */
        0x36, 0x7E,             /* LD (HL),$7E (cockpit) */
        0x19,                   /* ADD HL,DE */
        0x36, 0xFF,             /* LD (HL),$FF (wings) */
        0x19,                   /* ADD HL,DE */
        0x36, 0xA5,             /* LD (HL),$A5 (engines) */
        0xC3, 0x0E, 0x03        /* JP $030E */
    };
    for (u32 i = 0; i < sizeof(builtin_game); i++)
        WS->bios[0x0300 + i] = builtin_game[i];
}

/* HLE trap for Bally UPI RST 38H ($0180) when running built-in BIOS:
   Supports the core Bally EXEC calls used by cartridges when no external astro.bin is provided. */
static void ac_hle_upi(struct z80 *c)
{
    u16 ret = (u16)(ac_mem_read(c, c->sp.w) | ((u16)ac_mem_read(c, (u16)(c->sp.w + 1u)) << 8));
    u8 cmd = ac_mem_read(c, ret);
    ret++;
    u8 op = (u8)(cmd & 0x7Eu);
    switch (op) {
    case 0x00: /* INTPC: start UPI bytecode interpreter -> skip to EXIT ($02) */
        while (ret < 0xFFFEu) {
            u8 b = ac_mem_read(c, ret++);
            if (b == 0x02u) /* EXIT */
                break;
        }
        break;
    case 0x10: /* CLEAR: clear screen RAM */
        for (u32 a = 0x4000; a < 0x4FE0; a++)
            WS->ram[a] = 0;
        break;
    case 0x12: { /* FILL: fill BC bytes at HL with A */
        u16 hl = c->hl.w, bc = c->bc.w;
        u8 val = c->af.b.h;
        while (bc--) {
            ac_mem_write(c, hl++, val);
        }
        c->hl.w = hl;
        c->bc.w = 0;
        break;
    }
    case 0x08: /* SETOUT: inline 4 bytes (vblank, colorsplit, color0..3...) */
        WS->ac_vblank = ac_mem_read(c, ret++);
        WS->ac_colorsplit = (u8)(2u * (ac_mem_read(c, ret++) & 0x3Fu));
        break;
    case 0x28: /* ACTINT: enable VBlank interrupts */
        WS->ac_int_en = 0x08u;
        WS->ac_int_line = WS->ac_vblank ? WS->ac_vblank : 204u;
        c->iff1 = c->iff2 = 1;
        break;
    default:
        break;
    }
    WS->ram[c->sp.w] = (u8)(ret & 0xFFu);
    WS->ram[(u16)(c->sp.w + 1u)] = (u8)(ret >> 8);
    c->pc.w = 0x0181u; /* RET */
}

static void ac_render_frame(u16 *pic)
{
    if (!pic)
        return;
    for (int y = 0; y < ASTRO_H; y++) {
        u16 *dst = pic + y * ASTRO_W;
        u8 mode = WS->ac_line_mode[y];
        int xystep = 2 - mode; /* 2 in 160x102 low-res, 1 in 320x204 high-res */
        u16 vram_off = (u16)((y / xystep) * (80 / xystep));
        u8 split = WS->ac_line_split[y];
        u8 bgdata = WS->ac_line_bg[y];
        u8 vblank = WS->ac_line_vblank[y];
        const u8 *cols = WS->ac_line_colors[y];

        for (int x = 0; x < 80; x += xystep) {
            const u8 *cbase = &cols[(x < split) ? 4 : 0];
            u8 data = (y < vblank && (u32)vram_off < 0x1000u) ? WS->ram[0x4000u + vram_off++] : bgdata;
            for (int p = 0; p < 4; p++) {
                u8 pix = (u8)((data >> 6) & 3u);
                u16 rgb = WS->ac_pal[((u32)cbase[pix] << 1) & 0x1FFu];
                *dst++ = rgb;
                if (xystep == 2)
                    *dst++ = rgb;
                data <<= 2;
            }
        }
    }
}

static void ac_frame(u16 *picture)
{
    /* Decay transient UART/typed keypad presses */
    for (int i = 0; i < 4; i++) {
        if (WS->ac_key_ttl[i]) {
            WS->ac_key_ttl[i]--;
            if (!WS->ac_key_ttl[i])
                WS->ac_keypad[i] = 0;
        }
    }
    /* Rotate paddle knob smoothly when Select + Left/Right held */
    if (WS->pad & PAD_SELECT) {
        if (WS->pad & PAD_LEFT)  WS->ac_knob = (u8)(WS->ac_knob + 4u);
        if (WS->pad & PAD_RIGHT) WS->ac_knob = (u8)(WS->ac_knob - 4u);
    }

    WS->cpu.cycles = 0;
    s32 target = 0;
    /* 262 scanlines x 114 Z80 T-states/line (~29,868 cycles/frame at 1.7897725 MHz) */
    for (int sl = 0; sl < 262; sl++) {
        int ay = sl - 22;
        if (ay < 0)
            ay += 262;

        if (ay == (int)WS->ac_int_line && (WS->ac_int_en & 0x08u)) {
            WS->ac_int_vec = WS->ac_int_fb;
            WS->cpu.bus = WS->ac_int_vec;
            WS->cpu.irq = 1;
            WS->ac_int_clr_ack = ((WS->ac_int_en & 0x04u) == 0u) ? 1u : 0u;
        }

        s32 prev_cyc = WS->cpu.cycles;
        target += 114;
        while (WS->cpu.cycles < target) {
            int hit = z80_run(&WS->cpu, target);
            if (hit && WS->cpu.pc.w == 0x0180u && !WS->ext_bios)
                ac_hle_upi(&WS->cpu);
            else
                break;
        }
        if ((WS->ac_int_en & 0x04u) && WS->cpu.irq)
            WS->cpu.irq = 0; /* mode 1 pulse lasts one instruction/line */

        s32 ran = WS->cpu.cycles - prev_cyc;
        if (ran > 0)
            ac_sound_step((u32)ran);

        if (ay >= 0 && ay < ASTRO_H) {
            for (int c = 0; c < 8; c++)
                WS->ac_line_colors[ay][c] = WS->ac_colors[c];
            WS->ac_line_split[ay] = WS->ac_colorsplit;
            WS->ac_line_bg[ay] = WS->ac_bgdata;
            WS->ac_line_vblank[ay] = WS->ac_vblank;
            WS->ac_line_mode[ay] = WS->ac_vmode;
        }
    }
    ac_render_frame(picture);
}

/* ========================================================================
 * PUBLIC INTERFACE
 * ======================================================================== */

static void fmt_info_str(const char *prefix, u32 sz)
{
    char *p = WS->info;
    while (*prefix) *p++ = *prefix++;
    if (sz) {
        const char *s = ", ROM ";
        while (*s) *p++ = *s++;
        u32 kb = (sz + 1023u) >> 10;
        char d[12];
        int n = 0;
        do { d[n++] = (char)('0' + (kb % 10u)); kb /= 10u; } while (kb);
        while (n--) *p++ = d[n];
        *p++ = ' '; *p++ = 'K'; *p++ = 'B';
    }
    *p = 0;
}

static void common_clear(void)
{
    u32 keep_rate = WS->sample_rate;
    for (u32 i = 0; i < sizeof(*WS); i++)
        ((u8 *)WS)[i] = 0;
    for (u32 i = 0; i < sizeof(WS->ff_page); i++)
        WS->ff_page[i] = 0xFFu;
    WS->sample_rate = keep_rate;
    init_palettes();
}

const char *pv1000_load(const u8 *rom, u32 rom_size)
{
    if (!rom || rom_size < 1024u)
        return "too small for a Casio PV-1000 cartridge";
    if (rom_size > 0x8000u)
        rom_size = 0x8000u;

    common_clear();
    WS->sys = SYS_PV1000;
    WS->rom_size = rom_size;
    for (u32 i = 0; i < rom_size; i++)
        WS->rom[i] = rom[i];
    /* Mirror 8 KB / 16 KB cartridges cleanly across $0000..$3FFF if needed */
    if (rom_size <= 0x2000u) {
        for (u32 i = 0; i < 0x2000u; i++)
            WS->rom[0x2000u + i] = WS->rom[i % rom_size];
    }

    z80con_reset();
    fmt_info_str("Casio PV-1000", rom_size);
    return 0;
}

const char *astro_load(const u8 *bios, u32 bios_size, const u8 *rom, u32 rom_size)
{
    if (rom_size > sizeof(WS->rom))
        rom_size = sizeof(WS->rom);

    common_clear();
    WS->sys = SYS_ASTRO;
    for (u32 i = 0; i < sizeof(WS->rom); i++)
        WS->rom[i] = 0xFFu;

    if (bios && bios_size >= 0x2000u) {
        for (u32 i = 0; i < 0x2000u; i++)
            WS->bios[i] = bios[i];
        WS->ext_bios = 1;
    } else {
        ac_build_bios();
        WS->ext_bios = 0;
    }

    if (rom && rom_size > 0) {
        for (u32 i = 0; i < rom_size; i++)
            WS->rom[i] = rom[i];
        WS->rom_size = rom_size;
        if (rom_size == 0x40000u)
            WS->ac_cart_mapper = 1;
        else if (rom_size == 0x80000u)
            WS->ac_cart_mapper = 2;
    }

    z80con_reset();
    fmt_info_str(WS->ext_bios ? "Bally Astrocade (ROM BIOS)" : "Bally Astrocade", rom_size);
    return 0;
}

void z80con_reset(void)
{
    z80_init(&WS->cpu);
    for (u32 i = 0; i < 64; i++) {
        WS->cpu.rd[i] = 0;
        WS->cpu.wr[i] = 0;
        WS->cpu.op[i] = 0;
    }

    if (WS->sys == SYS_PV1000) {
        WS->cpu.read = pv_mem_read;
        WS->cpu.write = pv_mem_write;
        WS->cpu.in = pv_io_in;
        WS->cpu.out = pv_io_out;
        /* Fast direct 1 KB page map for $0000..$7FFF ROM and $B800..$BFFF RAM */
        u32 map_sz = (WS->rom_size <= 0x2000u) ? 0x4000u : WS->rom_size;
        for (u32 p = 0; p < 32; p++) {
            WS->cpu.rd[p] = (p * 0x400u < map_sz) ? &WS->rom[p * 0x400u] : WS->ff_page;
        }
        WS->cpu.rd[46] = WS->cpu.wr[46] = &WS->ram[0xB800];
        WS->cpu.rd[47] = WS->cpu.wr[47] = &WS->ram[0xBC00];
        for (int i = 0; i < 3; i++) {
            WS->pv_v[i].count = 0;
            WS->pv_v[i].period = 0;
            WS->pv_v[i].val = 1;
        }
        WS->pv_irq_en = 0;
        WS->pv_irq_act = 0;
        WS->pv_snd_ctrl = 0;
    } else {
        WS->cpu.read = ac_mem_read;
        WS->cpu.write = ac_mem_write;
        WS->cpu.in = ac_io_in;
        WS->cpu.out = ac_io_out;
        WS->cpu.irq_ack = ac_irq_ack;
        WS->cpu.trap = WS->ext_bios ? -1 : 0x0180;
        /* Fast direct 1 KB page map for $0000..$1FFF BIOS reads and $4000..$FFFF RAM */
        for (u32 p = 0; p < 8; p++)
            WS->cpu.rd[p] = &WS->bios[p * 0x400u];
        if (WS->ac_cart_mapper == 0) {
            for (u32 p = 0; p < 8; p++)
                WS->cpu.rd[8 + p] = (p * 0x400u < WS->rom_size) ? &WS->rom[p * 0x400u] : WS->ff_page;
        }
        for (u32 p = 16; p < 64; p++)
            WS->cpu.rd[p] = WS->cpu.wr[p] = &WS->ram[p * 0x400u];
        WS->ac_vblank = 204;
        WS->ac_colorsplit = 80;
        WS->ac_knob = 0x80;
        WS->ac_n_lfsr = 0x7FFFu;
    }
}

void z80con_frame(u16 pad, u16 *picture)
{
    WS->pad = pad;
    WS->audio_count = 0;
    if (WS->sys == SYS_PV1000)
        pv_frame(picture);
    else
        ac_frame(picture);
}

int z80con_width(void)  { return WS->sys == SYS_PV1000 ? PV1000_W : ASTRO_W; }
int z80con_height(void) { return WS->sys == SYS_PV1000 ? PV1000_H : ASTRO_H; }
const char *z80con_info(void) { return WS->info; }
int z80con_jammed(void) { return WS->cpu.halted && !WS->cpu.iff1; }

/* Map USB keyboard digits 0..9 / Enter / Space to Bally Astrocade 24-key keypad */
void z80con_keyboard(const u8 *usages, int n)
{
    if (WS->sys != SYS_ASTRO)
        return;
    for (int i = 0; i < 4; i++)
        if (!WS->ac_key_ttl[i])
            WS->ac_keypad[i] = 0;
    for (int i = 0; i < n; i++) {
        u8 u = usages[i];
        if (u == 0x27) WS->ac_keypad[2] |= 0x20u; /* '0' */
        else if (u == 0x1E) WS->ac_keypad[3] |= 0x10u; /* '1' */
        else if (u == 0x1F) WS->ac_keypad[2] |= 0x10u; /* '2' */
        else if (u == 0x20) WS->ac_keypad[1] |= 0x10u; /* '3' */
        else if (u == 0x21) WS->ac_keypad[3] |= 0x08u; /* '4' */
        else if (u == 0x22) WS->ac_keypad[2] |= 0x08u; /* '5' */
        else if (u == 0x23) WS->ac_keypad[1] |= 0x08u; /* '6' */
        else if (u == 0x24) WS->ac_keypad[3] |= 0x04u; /* '7' */
        else if (u == 0x25) WS->ac_keypad[2] |= 0x04u; /* '8' */
        else if (u == 0x26) WS->ac_keypad[1] |= 0x04u; /* '9' */
        else if (u == 0x28 || u == 0x06) WS->ac_keypad[3] |= 0x01u; /* Enter / C -> GO */
        else if (u == 0x57 || u == 0x2E) WS->ac_keypad[0] |= 0x20u; /* = */
    }
}

void z80con_typed(char c)
{
    if (WS->sys != SYS_ASTRO)
        return;
    int col = -1;
    u8 bit = 0;
    if (c == '0')      { col = 2; bit = 0x20u; }
    else if (c == '1') { col = 3; bit = 0x10u; }
    else if (c == '2') { col = 2; bit = 0x10u; }
    else if (c == '3') { col = 1; bit = 0x10u; }
    else if (c == '4') { col = 3; bit = 0x08u; }
    else if (c == '5') { col = 2; bit = 0x08u; }
    else if (c == '6') { col = 1; bit = 0x08u; }
    else if (c == '7') { col = 3; bit = 0x04u; }
    else if (c == '8') { col = 2; bit = 0x04u; }
    else if (c == '9') { col = 1; bit = 0x04u; }
    else if (c == '\r' || c == '\n' || c == 'g' || c == 'G') { col = 3; bit = 0x01u; }
    if (col >= 0) {
        WS->ac_keypad[col] |= bit;
        WS->ac_key_ttl[col] = 6;
    }
}

void z80con_audio_rate(u32 hz)
{
    WS->sample_rate = hz;
    WS->snd_frac = 0;
    WS->chip_frac = 0;
    WS->audio_count = 0;
}

int z80con_audio(s16 *out, int max)
{
    int n = WS->audio_count < max ? WS->audio_count : max;
    for (int i = 0; i < n; i++)
        out[i] = WS->audio_ring[i];
    WS->audio_count = 0;
    return n;
}
