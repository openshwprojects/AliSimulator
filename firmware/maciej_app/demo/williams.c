/* Williams & Midway Classic Arcade Multi-Board Emulator: see williams.h.
   Zero static .bss (all CPUs, TMS34010 GSP, PIAs, VRAMs, palettes & audio ring
   live in EMU_RAM_PHYS; ROMs, OKI6295 ADPCM, DMA2 GFX & .zip scratch live in
   0x05800000 & IMAGE_WORK_PHYS). */
#include "williams.h"
#include "zip.h"
#include "font5x7.h"

#ifndef WILLIAMS_HOST
#include "hw.h"
#endif

#define INLINE static inline __attribute__((always_inline))

enum {
    WIL_BOARD_BLITTER  = 0,     /* Dual MC6809E + Williams SC1/SC2 Blitter + PIAs + DAC */
    WIL_BOARD_TMS34010 = 1      /* Midway Y/T-Unit: TMS34010 32-bit GSP + DMA2 + YM2151/OKI6295 */
};

enum {
    WIL_SUB_GENERIC  = 0,       /* Clean SC2 (xor=0) / Built-in Cybertron 2084 */
    WIL_SUB_ROBOTRON = 1,       /* Robotron: 2084 (SC1 xor=4, dual-stick PIA0) */
    WIL_SUB_JOUST    = 2,       /* Joust (SC1 xor=4) */
    WIL_SUB_STARGATE = 3,       /* Stargate (SC1 xor=4) */
    WIL_SUB_BUBBLES  = 4,       /* Bubbles / Splat! (SC2 xor=0) */
    WIL_SUB_SINISTAR = 5,       /* Sinistar (SC1 xor=4, $7400 blitter clip) */
    WIL_SUB_DEFENDER = 6,       /* Defender ($D000 bank select, no blitter needed) */
    WIL_SUB_YUNIT    = 7,       /* Midway Y-Unit / Smash TV / MK1 (TMS34010 + DMA2) */
    WIL_SUB_TUNIT    = 8        /* Midway T-Unit / MK2 / NBA Jam (TMS34010 + DMA2) */
};

#define WIL_SND_RING    8192
#define WIL_ROM_CAP     0x00200000u     /* 2 MB Main 6809 / TMS34010 Program ROM */
#define WIL_SROM_CAP    0x00040000u     /* 256 KB Sound 6809 ROM */
#define WIL_PCM_CAP     0x00400000u     /* 4 MB OKI MSM6295 ADPCM ROM */
#define WIL_GFX_CAP     0x00800000u     /* 8 MB Midway Y/T-Unit DMA2 Graphics ROM */
#define WIL_STAGE_CAP   0x00500000u     /* 5 MB .zip unpack scratch */

#pragma GCC push_options
#pragma GCC optimize("O2")
#include "ym2151.inc"
#pragma GCC pop_options

/* Motorola MC6821 Peripheral Interface Adapter (PIA) */
struct mc6821 {
    u8 ora, ddra, cra, in_a;
    u8 orb, ddrb, crb, in_b;
    u8 ca2_out, cb2_out;
};

/* OKI MSM6295 4-channel 4-bit ADPCM voice */
struct oki6295_ch {
    u32 start, end, pos;
    u32 step_acc;
    s32 sig, step_idx;
    u8  playing, nib_hi, vol;
};

/* Texas Instruments TMS34010 32-bit Graphics System Processor state */
struct tms34010 {
    u32 a[16];          /* A0..A14 + A15(SP) */
    u32 b[16];          /* B0..B14 (SPTCH,DPTCH,OFFSET,WSTART,WEND,DYDX,COLOR0,COLOR1,...) + SP */
    u32 pc;             /* Bit address (word-aligned = multiple of 16) */
    u32 st;             /* N(31), C(30), Z(29), V(28), IE(21), FE1(11), FS1(6..10), FE0(5), FS0(0..4) */
    s32 cycles;
    u8  halted;
    u16 io[64];         /* $C0000000..$C00003FF GSP I/O registers */
};

struct williams_state {
    u8  board, sub;
    u8  jammed, nvram_dirty;
    int scr_w, scr_h;
    u16 pad1, pad2;
    u8  coin_prev, coin_pulse;
    u32 rom_size, srom_size, pcm_size, gfx_size;
    u32 rom_mask, pcm_mask, gfx_mask;
    u32 frame_no;
    int cur_scanline;

    /* Early Williams banking & SC1/SC2 Blitter */
    u8  vram_bank;              /* $C900: bit 0 = read ROM at $0000..$8FFF */
    u8  def_bank;               /* Defender $D000: bank 0 = I/O, 1..7 = paged ROM at $C000..$CFFF */
    u8  blitter_xor;            /* 4 for SC1 (Robotron/Joust/Sinistar), 0 for SC2 (Bubbles/Clean) */
    u16 blitter_clip;           /* $FFFF normal, $7400 on Sinistar */
    u8  blit_regs[8];           /* $CA00..$CA07 */
    u8  raw_pal[16];            /* $C000..$C00F BBGGGRRR */
    struct mc6821 pia[3];       /* 0: Widget ($C804), 1: ROM/Sound/IRQ ($C80C), 2: Sound ($0400) */

    /* Midway Y/T-Unit DMA2 & latches */
    u16 dma_regs[16];           /* $01A80000..$01A800FF */
    u8  snd_latch;
    u8  oki_cmd_latch;

    /* Audio: Sound 6809 8-bit DAC + YM2151 + OKI6295 @ 48 kHz */
    u32 sample_rate;
    s16 dac_sample;
    struct oki6295_ch oki[4];
    u32 snd_head, snd_tail;

    char info[96];
};

#pragma GCC optimize("O2")

static __attribute__((noinline)) u8 wil_m6809_rb(void *ctx, u16 a);
static __attribute__((noinline)) void wil_m6809_wb(void *ctx, u16 a, u8 v);
#define M6809_RB(ctx, a)        wil_m6809_rb(ctx, a)
#define M6809_WB(ctx, a, v)     wil_m6809_wb(ctx, a, v)
#include "m6809.inc"
#pragma GCC optimize("O2")

struct williams_mem {
    struct williams_state st;
    struct m6809 cpu_main;
    struct m6809 cpu_snd;
    struct tms34010 tms;
    struct ym2151 opm;
    u8  vram[0x10000];          /* 64 KB Early Williams 4bpp VRAM ($0000..$BFFF + scratch RAM) */
    u8  snd_ram[0x1000];        /* 4 KB Sound 6809 RAM */
    u8  cmos[0x0400];           /* 1 KB Battery-backed CMOS NVRAM ($CC00..$CFFF, .sav) */
    u16 pal15[4096];            /* Preconverted 0BBBBBGGGGGRRRRR palette (16 for Williams, 4096 Midway) */
    u32 pair15[256];            /* 2-pixel LUT for Early Williams 4bpp (hi<<4|lo -> 2x u16) */
    u8  gsp_vram[0x40000];      /* 256 KB Midway TMS34010 512x512x8bpp VRAM */
    u8  gsp_wram[0x80000];      /* 512 KB Midway TMS34010 Work RAM */
    u8  gsp_pal_raw[0x2000];    /* 8 KB Midway Palette RAM (4096 x 16-bit LE) */
    s16 snd_ring[WIL_SND_RING];
};

#ifdef WILLIAMS_HOST
static struct williams_mem wil_host_mem;
static u8 wil_host_rom[WIL_ROM_CAP];
static u8 wil_host_srom[WIL_SROM_CAP];
static u8 wil_host_pcm[WIL_PCM_CAP];
static u8 wil_host_gfx[WIL_GFX_CAP];
static u8 wil_host_stage[WIL_STAGE_CAP];
#define M           (&wil_host_mem)
#define ROM_BUF     wil_host_rom
#define SROM_BUF    wil_host_srom
#define PCM_BUF     wil_host_pcm
#define GFX_BUF     wil_host_gfx
#define ZIP_STAGE   wil_host_stage
#define WIL_POLL()  ((void)0)
#else
/* Physical layout during williams_play:
   0x03400000..0x0357FFFF (1.5 MB) : struct williams_mem M (~908 KB, 0 B static .bss!)
   0x05800000..0x059FFFFF (2.0 MB) : ROM_BUF  (6809 / TMS34010 Program ROM)
   0x06900000..0x0693FFFF (256 KB) : SROM_BUF (Sound 6809 ROM)
   0x06940000..0x06D3FFFF (4.0 MB) : PCM_BUF  (OKI MSM6295 ADPCM ROM)
   0x06D40000..0x0753FFFF (8.0 MB) : GFX_BUF  (Midway Y/T-Unit DMA2 Graphics ROM)
   0x07540000..0x07A3FFFF (5.0 MB) : ZIP_STAGE (MAME .zip unpack scratch) */
#define M           ((struct williams_mem *)KSEG0(EMU_RAM_PHYS))
#define ROM_BUF     ((u8 *)KSEG0(0x05800000u))
#define SROM_BUF    ((u8 *)KSEG0(0x06900000u))
#define PCM_BUF     ((u8 *)KSEG0(0x06940000u))
#define GFX_BUF     ((u8 *)KSEG0(0x06D40000u))
#define ZIP_STAGE   ((u8 *)KSEG0(0x07540000u))
#define WIL_POLL()  ((void)now_ms())
_Static_assert(sizeof(struct williams_mem) <= 0x00180000u, "williams_mem exceeds 1.5 MB slot");
#endif

#define S (M->st)

static void wil_zero(void *p, u32 n)
{
    u8 *b = (u8 *)p;
    for (u32 i = 0; i < n; i++)
        b[i] = 0;
}

static int wil_ci_has(const char *s, const char *sub)
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

static int wil_ci_ends(const char *s, const char *ext)
{
    int ls = 0, le = 0;
    while (s[ls]) ls++;
    while (ext[le]) le++;
    if (ls < le) return 0;
    for (int i = 0; i < le; i++)
        if ((s[ls - le + i] | 32) != (ext[i] | 32))
            return 0;
    return 1;
}

/* ---- Palette Conversion Helpers ---- */
static u16 wil_bbgggrrr_to_15(u8 v)
{
    /* Williams 8-bit BBGGGRRR resistor DAC -> 0BBBBBGGGGGRRRRR */
    static const u8 w3[8] = {0, 4, 9, 13, 18, 22, 27, 31};
    static const u8 w2[4] = {0, 10, 21, 31};
    u32 r = w3[v & 7u];
    u32 g = w3[(v >> 3) & 7u];
    u32 b = w2[(v >> 6) & 3u];
    return (u16)((b << 10) | (g << 5) | r);
}

static void wil_rebuild_pair15(void)
{
    for (u32 hi = 0; hi < 16u; hi++) {
        u32 c0 = M->pal15[hi];
        for (u32 lo = 0; lo < 16u; lo++)
            M->pair15[(hi << 4) | lo] = c0 | ((u32)M->pal15[lo] << 16);
    }
}

static void wil_write_pal(u32 idx, u8 v)
{
    idx &= 15u;
    S.raw_pal[idx] = v;
    M->pal15[idx] = wil_bbgggrrr_to_15(v);
    wil_rebuild_pair15();
}

/* Midway xRRRRRGGGGGBBBBB -> 0BBBBBGGGGGRRRRR */
INLINE u16 wil_midway_col15(u16 c)
{
    u32 r = (c >> 10) & 31u;
    u32 g = (c >> 5)  & 31u;
    u32 b =  c        & 31u;
    return (u16)((b << 10) | (g << 5) | r);
}

/* ---- MC6821 PIA Emulation ---- */
static int pia_irq_active(const struct mc6821 *p)
{
    int ia = ((p->cra & 0x80u) && (p->cra & 0x01u)) || ((p->cra & 0x40u) && (p->cra & 0x08u) && !(p->cra & 0x20u));
    int ib = ((p->crb & 0x80u) && (p->crb & 0x01u)) || ((p->crb & 0x40u) && (p->crb & 0x08u) && !(p->crb & 0x20u));
    return ia || ib;
}

static void wil_update_pia_irqs(void)
{
    M->cpu_main.irq_line = (pia_irq_active(&S.pia[0]) || pia_irq_active(&S.pia[1])) ? 1u : 0u;
    M->cpu_snd.irq_line  = pia_irq_active(&S.pia[2]) ? 1u : 0u;
}

static u8 pia_read(int idx, u8 reg, u8 ext_a, u8 ext_b)
{
    struct mc6821 *p = &S.pia[idx];
    switch (reg & 3u) {
    case 0:
        if (!(p->cra & 0x04u))
            return p->ddra;
        p->cra &= (u8)~0xC0u;
        wil_update_pia_irqs();
        return (p->ora & p->ddra) | (ext_a & (u8)~p->ddra);
    case 1:
        return p->cra;
    case 2:
        if (!(p->crb & 0x04u))
            return p->ddrb;
        p->crb &= (u8)~0xC0u;
        wil_update_pia_irqs();
        return (p->orb & p->ddrb) | (ext_b & (u8)~p->ddrb);
    default:
        return p->crb;
    }
}

static void pia_write(int idx, u8 reg, u8 v)
{
    struct mc6821 *p = &S.pia[idx];
    switch (reg & 3u) {
    case 0:
        if (p->cra & 0x04u) {
            p->ora = v;
            if (idx == 2) {
                /* Sound Board PIA2 Port A = 8-bit unsigned Williams DAC ($0400)! */
                u8 out = (p->ora & p->ddra) | (u8)~p->ddra;
                S.dac_sample = (s16)(((int)out - 128) * 168);
            }
        } else {
            p->ddra = v;
        }
        break;
    case 1:
        p->cra = (p->cra & 0xC0u) | (v & 0x3Fu);
        if ((v & 0x30u) == 0x30u) p->ca2_out = (v >> 3) & 1u;
        wil_update_pia_irqs();
        break;
    case 2:
        if (p->crb & 0x04u) {
            u8 prev = p->orb & p->ddrb;
            p->orb = v;
            u8 now = p->orb & p->ddrb;
            if (idx == 1) {
                /* Main PIA1 Port B ($C80E) -> Sound Board PIA2 Port B ($0402) + CB1 IRQ strobe! */
                u8 cmd = now & 0x3Fu;
                S.pia[2].in_b = (u8)(0xC0u | cmd);
                if ((cmd != (prev & 0x3Fu)) && cmd != 0x3Fu) {
                    S.pia[2].crb |= 0x80u;
                    wil_update_pia_irqs();
                }
            }
        } else {
            p->ddrb = v;
        }
        break;
    default:
        p->crb = (p->crb & 0xC0u) | (v & 0x3Fu);
        if ((v & 0x30u) == 0x30u) p->cb2_out = (v >> 3) & 1u;
        wil_update_pia_irqs();
        break;
    }
}

/* ---- Early Williams Controls (Active-HIGH on Williams 6821 PIAs!) ---- */
static u8 wil_widget_porta(void)
{
    u16 p = S.pad1;
    if (S.sub == WIL_SUB_ROBOTRON) {
        /* Robotron: 2084 PIA0 Port A (active HIGH):
           b0=Move Up, b1=Move Down, b2=Move Left, b3=Move Right,
           b4=Start1, b5=Start2, b6=Fire Up, b7=Fire Down (or muxed via CB2) */
        u8 v = 0;
        if (!S.pia[0].cb2_out) {
            if (p & 0x0010u) v |= 0x01u;    /* Move Up */
            if (p & 0x0020u) v |= 0x02u;    /* Move Down */
            if (p & 0x0040u) v |= 0x04u;    /* Move Left */
            if (p & 0x0080u) v |= 0x08u;    /* Move Right */
            if (p & 0x0008u) v |= 0x10u;    /* Start 1 */
            if (p & 0x0800u) v |= 0x20u;    /* Start 2 */
            if ((p & 0x0200u) || ((p & 0x0001u) && (p & 0x0010u))) v |= 0x40u; /* Fire Up */
            if ((p & 0x0002u) || ((p & 0x0001u) && (p & 0x0020u))) v |= 0x80u; /* Fire Down */
        } else {
            if ((p & 0x0100u) || ((p & 0x0001u) && (p & 0x0040u))) v |= 0x01u; /* Fire Left */
            if ((p & 0x0001u) && !(p & 0x0070u))                   v |= 0x02u; /* Fire Right */
        }
        return v;
    }
    /* Standard Williams / Joust / Defender / Cybertron 2084 PIA0 Port A (active HIGH):
       b0=Up, b1=Down, b2=Left, b3=Right, b4=Fire/Flap (A), b5=Bomb/Alt (B), b6=Hyper (X), b7=Start1 */
    u8 v = 0;
    if (p & 0x0010u) v |= 0x01u;
    if (p & 0x0020u) v |= 0x02u;
    if (p & 0x0040u) v |= 0x04u;
    if (p & 0x0080u) v |= 0x08u;
    if (p & 0x0001u) v |= 0x10u;
    if (p & 0x0002u) v |= 0x20u;
    if (p & 0x0100u) v |= 0x40u;
    if (p & 0x0008u) v |= 0x80u;
    return v;
}

static u8 wil_widget_portb(void)
{
    u16 p2 = S.pad2;
    u8 v = 0;
    if (S.pad1 & 0x0008u) v |= 0x01u;       /* 1P Start mirror */
    if (S.pad1 & 0x0800u) v |= 0x02u;       /* 2P Start */
    if (p2 & 0x0040u)     v |= 0x04u;
    if (p2 & 0x0080u)     v |= 0x08u;
    if (p2 & 0x0001u)     v |= 0x10u;
    return v;
}

static u8 wil_rom_pia_porta(void)
{
    /* PIA1 Port A ($C80C): Auto-Up=1 (bit 0, normal game mode, not service diagnostic!),
       Coin=bit 4 (active HIGH pulse) */
    u8 v = 0x01u;                           /* Auto-Up switch CLOSED = Game Mode */
    if (S.coin_pulse > 0)
        v |= 0x10u;                         /* Left Coin */
    return v;
}

/* ---- Early Williams Main 6809 & Blitter Bus ---- */
INLINE u8 wil_main_read_mem(u16 a)
{
    if (S.sub == WIL_SUB_DEFENDER) {
        if (a < 0xC000u)
            return M->vram[a];
        if (a < 0xD000u && S.def_bank != 0) {
            u32 off = 0x03000u + ((u32)(S.def_bank & 7u) * 0x1000u) + (a & 0x0FFFu);
            return ROM_BUF[off & S.rom_mask];
        }
        if (a >= 0xD000u)
            return ROM_BUF[(a - 0xD000u) & S.rom_mask];
    } else {
        if (a < 0x9000u)
            return (S.vram_bank & 1u) ? ROM_BUF[a & S.rom_mask] : M->vram[a];
        if (a < 0xC000u)
            return M->vram[a];
        if (a >= 0xD000u)
            return ROM_BUF[a & S.rom_mask];
    }
    if (a < 0xC010u)
        return S.raw_pal[a & 15u];
    if (a >= 0xC804u && a <= 0xC807u)
        return pia_read(0, a & 3u, wil_widget_porta(), wil_widget_portb());
    if (a >= 0xC80Cu && a <= 0xC80Fu)
        return pia_read(1, a & 3u, wil_rom_pia_porta(), 0xFFu);
    if (a >= 0xCB00u && a < 0xCB20u)
        return (u8)(S.cur_scanline & 0xFCu);    /* 6-bit vertical beam counter */
    if (a >= 0xCC00u && a < 0xD000u)
        return 0xF0u | (M->cmos[a - 0xCC00u] & 0x0Fu);
    return M->vram[a];
}

/* Williams Special Chip 1 / 2 Hardware Blitter ($CA00..$CA07) */
static void wil_blitter_run(u8 ctrl)
{
    S.blit_regs[0] = ctrl;
    int fg_only  = (ctrl & 0x02u) != 0;
    int solid    = (ctrl & 0x04u) != 0;
    int shift    = (ctrl & 0x08u) != 0;
    int lo_only  = (ctrl & 0x10u) != 0;
    int s_vram   = (ctrl & 0x20u) != 0;     /* 1 = columnar +256 X / +1 Y, 0 = linear */
    int d_vram   = (ctrl & 0x40u) != 0;

    u8  solid_val = S.blit_regs[1];
    u16 sbase     = ((u16)S.blit_regs[2] << 8) | S.blit_regs[3];
    u16 dbase     = ((u16)S.blit_regs[4] << 8) | S.blit_regs[5];
    int w         = (int)(S.blit_regs[6] ^ S.blitter_xor);
    int h         = (int)(S.blit_regs[7] ^ S.blitter_xor);
    if (w <= 0) w = 1;
    if (h <= 0) h = 1;

    u16 srow_start = sbase;
    u16 drow_start = dbase;

    for (int y = 0; y < h; y++) {
        u16 sa = srow_start;
        u16 da = drow_start;
        u8  prev_raw = 0;

        for (int x = 0; x < w; x++) {
            u8 raw = wil_main_read_mem(sa);
            u8 pix = shift ? (u8)((prev_raw << 4) | (raw >> 4)) : raw;
            prev_raw = raw;

            if (da < S.blitter_clip && da < 0xC000u) {
                u8 dst = M->vram[da];
                u8 keep = lo_only ? 0xF0u : 0x00u;
                if (fg_only) {
                    if (!(pix & 0xF0u)) keep |= 0xF0u;
                    if (!(pix & 0x0Fu)) keep |= 0x0Fu;
                }
                u8 src_col = solid ? solid_val : pix;
                M->vram[da] = (dst & keep) | (src_col & (u8)~keep);
            }

            sa = (u16)(sa + (s_vram ? 0x0100u : 1u));
            da = (u16)(da + (d_vram ? 0x0100u : 1u));
        }

        if (s_vram)
            srow_start = (srow_start & 0xFF00u) | ((srow_start + 1u) & 0x00FFu);
        else
            srow_start = (u16)(srow_start + (u16)w);

        if (d_vram)
            drow_start = (drow_start & 0xFF00u) | ((drow_start + 1u) & 0x00FFu);
        else
            drow_start = (u16)(drow_start + (u16)w);
    }

    /* Blitter halts the Main 6809 during DMA (~1 or 2 cycles per byte) */
    M->cpu_main.cycles += w * h * ((ctrl & 1u) ? 2 : 1);
}

static void wil_main_write_mem(u16 a, u8 v)
{
    if (a < 0xC000u) {
        M->vram[a] = v;
        return;
    }
    if (S.sub == WIL_SUB_DEFENDER && a >= 0xD000u && a < 0xE000u) {
        S.def_bank = v & 7u;
        return;
    }
    if (a < 0xC010u) {
        wil_write_pal(a & 15u, v);
        return;
    }
    if (a >= 0xC804u && a <= 0xC807u) {
        pia_write(0, a & 3u, v);
        return;
    }
    if (a >= 0xC80Cu && a <= 0xC80Fu) {
        pia_write(1, a & 3u, v);
        return;
    }
    if (a >= 0xC900u && a < 0xCA00u) {
        S.vram_bank = v;
        return;
    }
    if (a >= 0xCA00u && a <= 0xCA07u) {
        if (a == 0xCA00u)
            wil_blitter_run(v);
        else
            S.blit_regs[a & 7u] = v;
        return;
    }
    if (a >= 0xCC00u && a < 0xD000u) {
        u8 n = v & 0x0Fu;
        if (M->cmos[a - 0xCC00u] != n) {
            M->cmos[a - 0xCC00u] = n;
            S.nvram_dirty = 1;
        }
        return;
    }
}

/* ---- Sound 6809 Bus ($0000..$03FF RAM, $0400..$0403 PIA2 DAC, $B000..$FFFF ROM) ---- */
static u8 wil_snd_read_mem(u16 a)
{
    if (a < 0x0400u)
        return M->snd_ram[a & 0x0FFFu];
    if (a >= 0x0400u && a <= 0x0403u)
        return pia_read(2, a & 3u, 0xFFu, S.pia[2].in_b);
    if (a >= 0x2000u && a <= 0x2001u && S.board == WIL_BOARD_TMS34010)
        return M->opm.status;
    if (a >= 0x3000u && a < 0x3100u && S.board == WIL_BOARD_TMS34010) {
        u8 st = 0;
        for (int c = 0; c < 4; c++)
            if (S.oki[c].playing) st |= (u8)(1u << c);
        return st;
    }
    if (a >= 0x8000u && S.srom_size > 0)
        return SROM_BUF[a & (S.srom_size - 1u)];
    return 0xFFu;
}

static void oki6295_write(u8 v)
{
    static const u8 oki_atten[16] = {32, 22, 16, 11, 8, 6, 4, 3, 2, 1, 1, 0, 0, 0, 0, 0};
    if (S.oki_cmd_latch) {
        u8 phrase = S.oki_cmd_latch & 0x7Fu;
        S.oki_cmd_latch = 0;
        u8 ch_mask = (v >> 4) & 0x0Fu;
        u8 vol = oki_atten[v & 0x0Fu];
        if (!S.pcm_size) return;
        u32 hdr = (u32)phrase * 8u;
        u32 st_a = (((u32)PCM_BUF[(hdr + 0u) & S.pcm_mask] << 16) |
                    ((u32)PCM_BUF[(hdr + 1u) & S.pcm_mask] << 8) |
                     PCM_BUF[(hdr + 2u) & S.pcm_mask]) & 0x3FFFFu;
        u32 en_a = (((u32)PCM_BUF[(hdr + 3u) & S.pcm_mask] << 16) |
                    ((u32)PCM_BUF[(hdr + 4u) & S.pcm_mask] << 8) |
                     PCM_BUF[(hdr + 5u) & S.pcm_mask]) & 0x3FFFFu;
        for (int c = 0; c < 4; c++) {
            if ((ch_mask & (1u << c)) && en_a > st_a) {
                S.oki[c].start    = st_a;
                S.oki[c].end      = en_a;
                S.oki[c].pos      = st_a;
                S.oki[c].step_acc = 0;
                S.oki[c].sig      = 0;
                S.oki[c].step_idx = 0;
                S.oki[c].nib_hi   = 1;
                S.oki[c].vol      = vol;
                S.oki[c].playing  = 1;
            }
        }
    } else if (v & 0x80u) {
        S.oki_cmd_latch = v;
    } else {
        u8 stop_mask = (v >> 3) & 0x0Fu;
        for (int c = 0; c < 4; c++)
            if (stop_mask & (1u << c))
                S.oki[c].playing = 0;
    }
}

static s32 oki6295_step_48k(void)
{
    static const u16 oki_steps[49] = {
        16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66,
        73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307,
        337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552
    };
    static const s8 oki_idx_adj[8] = {-1, -1, -1, -1, 2, 4, 6, 8};
    if (!S.pcm_size) return 0;
    s32 sum = 0;
    for (int c = 0; c < 4; c++) {
        struct oki6295_ch *v = &S.oki[c];
        if (!v->playing) continue;
        /* ~7.575 kHz native OKI6295 rate -> 647 / 4096 step per 48 kHz sample */
        v->step_acc += 647u;
        while (v->step_acc >= 4096u) {
            v->step_acc -= 4096u;
            if (v->pos >= v->end) {
                v->playing = 0;
                break;
            }
            u8 b = PCM_BUF[v->pos & S.pcm_mask];
            u8 nib = v->nib_hi ? (b >> 4) : (b & 0x0Fu);
            if (v->nib_hi) {
                v->nib_hi = 0;
            } else {
                v->nib_hi = 1;
                v->pos++;
            }
            s32 step = oki_steps[v->step_idx];
            s32 diff = step >> 3;
            if (nib & 1u) diff += step >> 2;
            if (nib & 2u) diff += step >> 1;
            if (nib & 4u) diff += step;
            if (nib & 8u) v->sig -= diff;
            else          v->sig += diff;
            if (v->sig >  2047) v->sig =  2047;
            if (v->sig < -2048) v->sig = -2048;
            v->step_idx += oki_idx_adj[nib & 7u];
            if (v->step_idx < 0)  v->step_idx = 0;
            if (v->step_idx > 48) v->step_idx = 48;
        }
        sum += (v->sig * (s32)v->vol) >> 2;
    }
    return sum;
}

static void wil_snd_write_mem(u16 a, u8 v)
{
    if (a < 0x0400u) {
        M->snd_ram[a & 0x0FFFu] = v;
        return;
    }
    if (a >= 0x0400u && a <= 0x0403u) {
        pia_write(2, a & 3u, v);
        return;
    }
    if (S.board == WIL_BOARD_TMS34010) {
        if (a == 0x2000u) {
            M->opm.addr_latch = v;
        } else if (a == 0x2001u) {
            ym2151_write_reg(&M->opm, M->opm.addr_latch, v, 3579545u);
        } else if (a >= 0x3000u && a < 0x3100u) {
            oki6295_write(v);
        } else if (a >= 0x5000u && a < 0x5100u) {
            S.dac_sample = (s16)(((int)v - 128) * 168);
        }
    }
}

static __attribute__((noinline)) u8 wil_m6809_rb(void *ctx, u16 a)
{
    return (ctx == (void *)1) ? wil_snd_read_mem(a) : wil_main_read_mem(a);
}

static __attribute__((noinline)) void wil_m6809_wb(void *ctx, u16 a, u8 v)
{
    if (ctx == (void *)1)
        wil_snd_write_mem(a, v);
    else
        wil_main_write_mem(a, v);
}

/* ============================================================================
   Midway Y-Unit / T-Unit: Texas Instruments TMS34010 32-bit GSP + DMA2 Blitter
   ============================================================================ */

/* Midway DMA2 Hardware Sprite Blitter ($01A80000..$01A800FF, 16 x 16-bit regs) */
static void midway_dma2_run(u16 ctrl)
{
    /* Regs:
       0..1: Source bit offset in GFX_BUF (32-bit)
       2:    Dest X (pixels, 0..511)
       3:    Dest Y (scanlines, 0..255)
       4:    Width (pixels)
       5:    Height (scanlines)
       6:    Palette upper 8 bits (pal_hi << 8)
       7:    Constant color (low 8 bits)
       8:    Control: b0=Go, b1=Transparent0, b2=SolidConst, b4=FlipX, b5=FlipY, b7=8bpp(else 4bpp) */
    S.dma_regs[8] = ctrl & (u16)~0x0001u;
    if (!(ctrl & 0x0001u) || !S.gfx_size)
        return;

    u32 bit_off = ((u32)S.dma_regs[1] << 16) | S.dma_regs[0];
    int dx0     = (s16)S.dma_regs[2];
    int dy0     = (s16)S.dma_regs[3];
    int w       = S.dma_regs[4] & 0x3FFu;
    int h       = S.dma_regs[5] & 0x3FFu;
    u8  pal_hi  = (u8)S.dma_regs[6];
    u8  cst_col = (u8)S.dma_regs[7];
    int transp0 = (ctrl & 0x0002u) != 0;
    int solid   = (ctrl & 0x0004u) != 0;
    int flip_x  = (ctrl & 0x0010u) != 0;
    int flip_y  = (ctrl & 0x0020u) != 0;
    int bpp8    = (ctrl & 0x0080u) != 0;

    u32 row_bits = (u32)w * (bpp8 ? 8u : 4u);
    for (int ry = 0; ry < h; ry++) {
        int y = dy0 + (flip_y ? (h - 1 - ry) : ry);
        if (y >= 0 && y < 512) {
            u8 *vrow = &M->gsp_vram[(u32)y * 512u];
            u32 bp = bit_off + (u32)ry * row_bits;
            for (int rx = 0; rx < w; rx++, bp += (bpp8 ? 8u : 4u)) {
                int x = dx0 + (flip_x ? (w - 1 - rx) : rx);
                if (x < 0 || x >= 512) continue;
                u8 raw = GFX_BUF[(bp >> 3) & S.gfx_mask];
                u8 pen = bpp8 ? raw : ((bp & 4u) ? (raw >> 4) : (raw & 0x0Fu));
                if (transp0 && pen == 0) continue;
                vrow[x] = solid ? cst_col : (u8)((pal_hi & 0xF0u) | pen);
            }
        }
    }
}

/* TMS34010 Bit-Addressed Memory Read/Write (8-bit byte at `bit_addr >> 3`) */
static u8 tms_read8(u32 bit_addr)
{
    u32 byte_a = bit_addr >> 3;
    if (bit_addr < 0x00200000u)
        return M->gsp_vram[byte_a & 0x3FFFFu];
    if (bit_addr >= 0x01000000u && bit_addr < 0x01400000u)
        return M->gsp_wram[byte_a & 0x7FFFFu];
    if (bit_addr >= 0x01800000u && bit_addr < 0x01880000u)
        return M->gsp_pal_raw[byte_a & 0x1FFFu];
    if (bit_addr >= 0x01A80000u && bit_addr < 0x01A80200u) {
        u32 r = (bit_addr - 0x01A80000u) >> 4;
        u16 w = S.dma_regs[r & 15u];
        return (byte_a & 1u) ? (u8)(w >> 8) : (u8)w;
    }
    if (bit_addr >= 0x01C00000u && bit_addr < 0x01D00000u) {
        /* Midway JAMMA Inputs (active LOW) */
        u32 sub = (bit_addr >> 4) & 7u;
        if (sub == 0) {
            u8 v = 0xFFu;
            u16 p = S.pad1;
            if (p & 0x0010u) v &= (u8)~0x01u;   /* Up */
            if (p & 0x0020u) v &= (u8)~0x02u;   /* Down */
            if (p & 0x0040u) v &= (u8)~0x04u;   /* Left */
            if (p & 0x0080u) v &= (u8)~0x08u;   /* Right */
            if (p & 0x0001u) v &= (u8)~0x10u;   /* High Punch / Fire */
            if (p & 0x0002u) v &= (u8)~0x20u;   /* Block / Action */
            if (p & 0x0100u) v &= (u8)~0x40u;   /* Low Punch / Turbo */
            if (p & 0x0200u) v &= (u8)~0x80u;   /* High Kick */
            return (byte_a & 1u) ? 0xFFu : v;
        }
        if (sub == 2) {
            u8 v = 0xFFu;
            if (S.coin_pulse > 0) v &= (u8)~0x01u;
            if (S.pad1 & 0x0008u) v &= (u8)~0x04u; /* Start 1 */
            if (S.pad1 & 0x0800u) v &= (u8)~0x20u; /* Start 2 */
            return (byte_a & 1u) ? 0xFFu : v;
        }
        return 0xFFu;
    }
    if (bit_addr >= 0x02000000u && bit_addr < 0x08000000u && S.gfx_size)
        return GFX_BUF[((bit_addr - 0x02000000u) >> 3) & S.gfx_mask];
    if (bit_addr >= 0xC0000000u && bit_addr < 0xC0000400u) {
        u32 idx = (bit_addr - 0xC0000000u) >> 4;
        u16 w = (idx == 0x1Cu) ? (u16)S.cur_scanline : M->tms.io[idx & 63u];
        return (byte_a & 1u) ? (u8)(w >> 8) : (u8)w;
    }
    if (bit_addr >= 0xFF000000u && S.rom_size)
        return ROM_BUF[byte_a & S.rom_mask];
    return 0;
}

static void tms_write8(u32 bit_addr, u8 v)
{
    u32 byte_a = bit_addr >> 3;
    if (bit_addr < 0x00200000u) {
        M->gsp_vram[byte_a & 0x3FFFFu] = v;
        return;
    }
    if (bit_addr >= 0x01000000u && bit_addr < 0x01400000u) {
        M->gsp_wram[byte_a & 0x7FFFFu] = v;
        return;
    }
    if (bit_addr >= 0x01800000u && bit_addr < 0x01880000u) {
        u32 off = byte_a & 0x1FFFu;
        M->gsp_pal_raw[off] = v;
        u32 idx = off >> 1;
        u16 raw = (u16)M->gsp_pal_raw[idx * 2u] | ((u16)M->gsp_pal_raw[idx * 2u + 1u] << 8);
        M->pal15[idx] = wil_midway_col15(raw);
        return;
    }
    if (bit_addr >= 0x01A80000u && bit_addr < 0x01A80200u) {
        u32 r = ((bit_addr - 0x01A80000u) >> 4) & 15u;
        if (byte_a & 1u)
            S.dma_regs[r] = (S.dma_regs[r] & 0x00FFu) | ((u16)v << 8);
        else
            S.dma_regs[r] = (S.dma_regs[r] & 0xFF00u) | v;
        if (r == 8u && (byte_a & 1u))
            midway_dma2_run(S.dma_regs[8]);
        return;
    }
    if (bit_addr >= 0x01D00000u && bit_addr < 0x01E00000u && !(byte_a & 1u)) {
        S.snd_latch = v;
        S.pia[2].in_b = v;
        S.pia[2].crb |= 0x80u;
        wil_update_pia_irqs();
        return;
    }
    if (bit_addr >= 0xC0000000u && bit_addr < 0xC0000400u) {
        u32 idx = ((bit_addr - 0xC0000000u) >> 4) & 63u;
        if (byte_a & 1u)
            M->tms.io[idx] = (M->tms.io[idx] & 0x00FFu) | ((u16)v << 8);
        else
            M->tms.io[idx] = (M->tms.io[idx] & 0xFF00u) | v;
        if (idx == 0x0Eu && !(byte_a & 1u)) {
            /* INTPEND ($C00000E0): writing 0 bits clears pending interrupts */
            M->tms.io[0x0Eu] &= ((u16)v | 0xFF00u);
        }
    }
}

INLINE u16 tms_rw16(u32 bit_addr)
{
    return (u16)tms_read8(bit_addr) | ((u16)tms_read8(bit_addr + 8u) << 8);
}

INLINE void tms_ww16(u32 bit_addr, u16 v)
{
    tms_write8(bit_addr, (u8)v);
    tms_write8(bit_addr + 8u, (u8)(v >> 8));
}

INLINE u32 tms_rl32(u32 bit_addr)
{
    return (u32)tms_rw16(bit_addr) | ((u32)tms_rw16(bit_addr + 16u) << 16);
}

INLINE void tms_wl32(u32 bit_addr, u32 v)
{
    tms_ww16(bit_addr, (u16)v);
    tms_ww16(bit_addr + 16u, (u16)(v >> 16));
}

static u32 tms_rfield(u32 bit_addr, u32 fs, int sext)
{
    if (fs == 0) fs = 32u;
    if ((bit_addr & 7u) == 0) {
        if (fs == 16u) {
            u32 v = tms_rw16(bit_addr);
            return sext ? (u32)(s32)(s16)v : v;
        }
        if (fs == 32u)
            return tms_rl32(bit_addr);
        if (fs == 8u) {
            u32 v = tms_read8(bit_addr);
            return sext ? (u32)(s32)(s8)v : v;
        }
    }
    u32 val = 0;
    for (u32 i = 0; i < fs; i++) {
        u32 ba = bit_addr + i;
        u8 b = tms_read8(ba & ~7u);
        if (b & (1u << (ba & 7u)))
            val |= (1u << i);
    }
    if (sext && fs < 32u && (val & (1u << (fs - 1u))))
        val |= (~0u << fs);
    return val;
}

static void tms_wfield(u32 bit_addr, u32 val, u32 fs)
{
    if (fs == 0) fs = 32u;
    if ((bit_addr & 7u) == 0) {
        if (fs == 16u) { tms_ww16(bit_addr, (u16)val); return; }
        if (fs == 32u) { tms_wl32(bit_addr, val);      return; }
        if (fs == 8u)  { tms_write8(bit_addr, (u8)val); return; }
    }
    for (u32 i = 0; i < fs; i++) {
        u32 ba = bit_addr + i;
        u8 b = tms_read8(ba & ~7u);
        if (val & (1u << i)) b |=  (u8)(1u << (ba & 7u));
        else                 b &= (u8)~(1u << (ba & 7u));
        tms_write8(ba & ~7u, b);
    }
}

#define TMS_N   0x80000000u
#define TMS_C   0x40000000u
#define TMS_Z   0x20000000u
#define TMS_V   0x10000000u
#define TMS_IE  0x00200000u

INLINE u32 *tms_reg_ptr(u16 op_r, int use_b)
{
    u32 idx = op_r & 15u;
    if (idx == 15u) return &M->tms.a[15];   /* Shared SP */
    return use_b ? &M->tms.b[idx] : &M->tms.a[idx];
}

INLINE void tms_set_nz(u32 res)
{
    M->tms.st &= ~(TMS_N | TMS_Z | TMS_V);
    if (res == 0)          M->tms.st |= TMS_Z;
    if (res & 0x80000000u) M->tms.st |= TMS_N;
}

static int tms_cond(u32 cc)
{
    u32 st = M->tms.st;
    int n = (st & TMS_N) != 0, c = (st & TMS_C) != 0;
    int z = (st & TMS_Z) != 0, v = (st & TMS_V) != 0;
    switch (cc & 15u) {
    case 0x0: return 1;                 /* UC */
    case 0x1: return !c && !z;          /* P / HI (unsigned >) */
    case 0x2: return c || z;            /* LS */
    case 0x3: return !c;                /* HS / NC */
    case 0x4: return c;                 /* LO / C */
    case 0x5: return !z;                /* NE */
    case 0x6: return z;                 /* EQ */
    case 0x7: return !v;                /* NV */
    case 0x8: return v;                 /* V */
    case 0x9: return !n;                /* NN */
    case 0xA: return n;                 /* N */
    case 0xB: return n == v;            /* GE */
    case 0xC: return n != v;            /* LT */
    case 0xD: return !z && (n == v);    /* GT */
    case 0xE: return z || (n != v);     /* LE */
    default:  return 0;
    }
}

/* TMS34010 Hardware FILL XY & PIXBLT B,XY / L,XY Accelerators */
static void tms_fill_xy(void)
{
    /* B2=OFFSET (linear bit base), B1=DPTCH (bits/row), B7=DYDX (H<<16|W), B3=DADDR (Y<<16|X), B9/B7=COLOR1 (B7=COLOR1, B5=DYDX!) */
    /* Standard TMS34010 B-file mapping:
       B0=SADDR, B1=SPTCH, B2=DADDR, B3=DPTCH, B4=OFFSET, B5=WSTART, B6=WEND, B7=DYDX, B8=COLOR0, B9=COLOR1 */
    u32 daddr  = M->tms.b[2];
    u32 dptch  = M->tms.b[3] ? M->tms.b[3] : (512u * 8u);
    u32 offset = M->tms.b[4];
    int dx0    = (s16)(daddr & 0xFFFFu);
    int dy0    = (s16)(daddr >> 16);
    int w      = (int)(M->tms.b[7] & 0xFFFFu);
    int h      = (int)(M->tms.b[7] >> 16);
    u8  col    = (u8)M->tms.b[9];

    for (int ry = 0; ry < h; ry++) {
        int y = dy0 + ry;
        if (y < 0 || y >= 512) continue;
        u32 row_bit = offset + (u32)y * dptch;
        for (int rx = 0; rx < w; rx++) {
            int x = dx0 + rx;
            if (x >= 0 && x < 512)
                tms_write8(row_bit + (u32)x * 8u, col);
        }
    }
    M->tms.cycles += w * h + 16;
}

static void tms_pixblt_b_xy(void)
{
    /* Expand 1bpp bitmap at B0 (SADDR, linear bit address, pitch B1 SPTCH) to 8bpp XY at B2 (DADDR),
       size B7 (DYDX), fg=B9 (COLOR1), bg=B8 (COLOR0), transparency in CONTROL (io[6] bit 5) */
    u32 saddr  = M->tms.b[0];
    u32 sptch  = M->tms.b[1];
    u32 daddr  = M->tms.b[2];
    u32 dptch  = M->tms.b[3] ? M->tms.b[3] : (512u * 8u);
    u32 offset = M->tms.b[4];
    int dx0    = (s16)(daddr & 0xFFFFu);
    int dy0    = (s16)(daddr >> 16);
    int w      = (int)(M->tms.b[7] & 0xFFFFu);
    int h      = (int)(M->tms.b[7] >> 16);
    u8  col0   = (u8)M->tms.b[8];
    u8  col1   = (u8)M->tms.b[9];
    int transp = (M->tms.io[6] & 0x0020u) != 0;
    if (!sptch) sptch = (u32)w;

    for (int ry = 0; ry < h; ry++) {
        int y = dy0 + ry;
        u32 sbit = saddr + (u32)ry * sptch;
        if (y >= 0 && y < 512) {
            u32 drow = offset + (u32)y * dptch;
            for (int rx = 0; rx < w; rx++, sbit++) {
                int x = dx0 + rx;
                if (x < 0 || x >= 512) continue;
                u8 b = tms_read8(sbit & ~7u);
                int on = (b >> (sbit & 7u)) & 1;
                if (on)
                    tms_write8(drow + (u32)x * 8u, col1);
                else if (!transp)
                    tms_write8(drow + (u32)x * 8u, col0);
            }
        }
    }
    M->tms.cycles += w * h * 2 + 20;
}

static void tms_pixblt_l_xy(void)
{
    /* Copy 8bpp linear source at B0 (pitch B1 bits) to 8bpp XY at B2 (DADDR), size B7 (DYDX) */
    u32 saddr  = M->tms.b[0];
    u32 sptch  = M->tms.b[1] ? M->tms.b[1] : ((M->tms.b[7] & 0xFFFFu) * 8u);
    u32 daddr  = M->tms.b[2];
    u32 dptch  = M->tms.b[3] ? M->tms.b[3] : (512u * 8u);
    u32 offset = M->tms.b[4];
    int dx0    = (s16)(daddr & 0xFFFFu);
    int dy0    = (s16)(daddr >> 16);
    int w      = (int)(M->tms.b[7] & 0xFFFFu);
    int h      = (int)(M->tms.b[7] >> 16);
    int transp = (M->tms.io[6] & 0x0020u) != 0;

    for (int ry = 0; ry < h; ry++) {
        int y = dy0 + ry;
        u32 sbit = saddr + (u32)ry * sptch;
        if (y >= 0 && y < 512) {
            u32 drow = offset + (u32)y * dptch;
            for (int rx = 0; rx < w; rx++, sbit += 8u) {
                int x = dx0 + rx;
                if (x < 0 || x >= 512) continue;
                u8 c = tms_read8(sbit);
                if (transp && c == 0) continue;
                tms_write8(drow + (u32)x * 8u, c);
            }
        }
    }
    M->tms.cycles += w * h * 2 + 20;
}

static void tms_run(s32 target_cycles)
{
    while (M->tms.cycles < target_cycles) {
        /* Check Display Interrupt (DIP = bit 10 / 0x0400 in INTPEND io[0x0E] & INTENB io[0x0D]) */
        if ((M->tms.st & TMS_IE) && (M->tms.io[0x0Du] & M->tms.io[0x0Eu] & 0x0400u)) {
            M->tms.halted = 0;
            M->tms.a[15] -= 32u;
            tms_wl32(M->tms.a[15], M->tms.pc);
            M->tms.a[15] -= 32u;
            tms_wl32(M->tms.a[15], M->tms.st);
            M->tms.st &= ~TMS_IE;
            M->tms.pc = tms_rl32(0xFFFFFEC0u);      /* Vector 10: Display Interrupt ($FFFFFEC0) */
            M->tms.cycles += 12;
        }
        if (M->tms.halted) {
            M->tms.cycles = target_cycles;
            break;
        }

        u16 op = tms_rw16(M->tms.pc);
        M->tms.pc += 16u;
        int rf_b = (op & 0x0010u) != 0;
        u32 *rd  = tms_reg_ptr(op, rf_b);
        u32 *rs  = tms_reg_ptr(op >> 5, rf_b);
        u32 fs0  = M->tms.st & 0x1Fu;
        int fe0  = (M->tms.st & 0x20u) != 0;
        u32 fs1  = (M->tms.st >> 6) & 0x1Fu;
        int fe1  = (M->tms.st & 0x800u) != 0;

        switch (op >> 12) {
        case 0x0:
            if (op == 0x0300u) {                        /* NOP */
                M->tms.cycles += 1;
            } else if (op == 0x0040u) {                 /* IDLE */
                M->tms.halted = 1;
                M->tms.cycles += 1;
            } else if (op == 0x0360u) {                 /* DINT */
                M->tms.st &= ~TMS_IE;
                M->tms.cycles += 3;
            } else if (op == 0x0D60u) {                 /* EINT */
                M->tms.st |= TMS_IE;
                M->tms.cycles += 3;
            } else if (op == 0x0960u) {                 /* RETI */
                M->tms.st = tms_rl32(M->tms.a[15]);
                M->tms.a[15] += 32u;
                M->tms.pc = tms_rl32(M->tms.a[15]);
                M->tms.a[15] += 32u;
                M->tms.cycles += 8;
            } else if ((op & 0xFFE0u) == 0x0940u) {     /* RETS N */
                u32 n = op & 0x1Fu;
                M->tms.pc = tms_rl32(M->tms.a[15]);
                M->tms.a[15] += 32u + n * 16u;
                M->tms.cycles += 6;
            } else if (op == 0x0D3Fu) {                 /* CALLA addr32 */
                u32 dst = tms_rl32(M->tms.pc);
                M->tms.pc += 32u;
                M->tms.a[15] -= 32u;
                tms_wl32(M->tms.a[15], M->tms.pc);
                M->tms.pc = dst;
                M->tms.cycles += 4;
            } else if (op == 0x0D5Fu) {                 /* CALLR disp16 */
                s16 d = (s16)tms_rw16(M->tms.pc);
                M->tms.pc += 16u;
                M->tms.a[15] -= 32u;
                tms_wl32(M->tms.a[15], M->tms.pc);
                M->tms.pc += (u32)((s32)d * 16);
                M->tms.cycles += 3;
            } else if ((op & 0xFFE0u) == 0x0160u) {     /* JUMP Rd */
                M->tms.pc = *rd;
                M->tms.cycles += 2;
            } else if ((op & 0xFFE0u) == 0x09C0u) {     /* MOVI IW, Rd */
                *rd = (u32)(s32)(s16)tms_rw16(M->tms.pc);
                M->tms.pc += 16u;
                tms_set_nz(*rd);
                M->tms.cycles += 2;
            } else if ((op & 0xFFE0u) == 0x09E0u) {     /* MOVI IL, Rd */
                *rd = tms_rl32(M->tms.pc);
                M->tms.pc += 32u;
                tms_set_nz(*rd);
                M->tms.cycles += 3;
            } else if ((op & 0xFFE0u) == 0x0B00u) {     /* ADDI IW, Rd */
                u32 imm = (u32)(s32)(s16)tms_rw16(M->tms.pc);
                M->tms.pc += 16u;
                *rd += imm;
                tms_set_nz(*rd);
                M->tms.cycles += 2;
            } else if ((op & 0xFFE0u) == 0x0B20u) {     /* ADDI IL, Rd */
                u32 imm = tms_rl32(M->tms.pc);
                M->tms.pc += 32u;
                *rd += imm;
                tms_set_nz(*rd);
                M->tms.cycles += 3;
            } else if ((op & 0xFFE0u) == 0x0B40u) {     /* CMPI IW, Rd */
                u32 imm = (u32)(s32)(s16)tms_rw16(M->tms.pc);
                M->tms.pc += 16u;
                u32 r = *rd - imm;
                tms_set_nz(r);
                if (*rd < imm) M->tms.st |= TMS_C; else M->tms.st &= ~TMS_C;
                M->tms.cycles += 2;
            } else if ((op & 0xFFE0u) == 0x0B60u) {     /* CMPI IL, Rd */
                u32 imm = tms_rl32(M->tms.pc);
                M->tms.pc += 32u;
                u32 r = *rd - imm;
                tms_set_nz(r);
                if (*rd < imm) M->tms.st |= TMS_C; else M->tms.st &= ~TMS_C;
                M->tms.cycles += 3;
            } else if ((op & 0xFFE0u) == 0x0B80u) {     /* ANDNI IL, Rd */
                u32 imm = tms_rl32(M->tms.pc);
                M->tms.pc += 32u;
                *rd &= ~imm;
                tms_set_nz(*rd);
                M->tms.cycles += 3;
            } else if ((op & 0xFFE0u) == 0x0BA0u) {     /* ORI IL, Rd */
                u32 imm = tms_rl32(M->tms.pc);
                M->tms.pc += 32u;
                *rd |= imm;
                tms_set_nz(*rd);
                M->tms.cycles += 3;
            } else if ((op & 0xFFE0u) == 0x0BC0u) {     /* XORI IL, Rd */
                u32 imm = tms_rl32(M->tms.pc);
                M->tms.pc += 32u;
                *rd ^= imm;
                tms_set_nz(*rd);
                M->tms.cycles += 3;
            } else if ((op & 0xFFE0u) == 0x0BE0u) {     /* SUBI IW, Rd */
                u32 imm = (u32)(s32)(s16)tms_rw16(M->tms.pc);
                M->tms.pc += 16u;
                *rd -= imm;
                tms_set_nz(*rd);
                M->tms.cycles += 2;
            } else if ((op & 0xFFE0u) == 0x0580u) {     /* MOVE Rd, @IL, 0 */
                u32 a = tms_rl32(M->tms.pc);
                M->tms.pc += 32u;
                tms_wfield(a, *rd, fs0);
                M->tms.cycles += 4;
            } else if ((op & 0xFFE0u) == 0x0780u) {     /* MOVE Rd, @IL, 1 */
                u32 a = tms_rl32(M->tms.pc);
                M->tms.pc += 32u;
                tms_wfield(a, *rd, fs1);
                M->tms.cycles += 4;
            } else if ((op & 0xFFE0u) == 0x05A0u) {     /* MOVE @IL, Rd, 0 */
                u32 a = tms_rl32(M->tms.pc);
                M->tms.pc += 32u;
                *rd = tms_rfield(a, fs0, fe0);
                tms_set_nz(*rd);
                M->tms.cycles += 4;
            } else if ((op & 0xFFE0u) == 0x07A0u) {     /* MOVE @IL, Rd, 1 */
                u32 a = tms_rl32(M->tms.pc);
                M->tms.pc += 32u;
                *rd = tms_rfield(a, fs1, fe1);
                tms_set_nz(*rd);
                M->tms.cycles += 4;
            } else if ((op & 0xFFC0u) == 0x0F00u) {     /* FILL L / FILL XY */
                tms_fill_xy();
            } else if ((op & 0xFFE0u) == 0x0F80u) {     /* PIXBLT B,XY */
                tms_pixblt_b_xy();
            } else if ((op & 0xFFE0u) == 0x0F20u) {     /* PIXBLT L,XY */
                tms_pixblt_l_xy();
            } else if ((op & 0xFFE0u) == 0x0500u) {     /* SETF FS,FE,0 */
                M->tms.st = (M->tms.st & ~0x3Fu) | (op & 0x3Fu);
                M->tms.cycles += 1;
            } else if ((op & 0xFFE0u) == 0x0700u) {     /* SETF FS,FE,1 */
                M->tms.st = (M->tms.st & ~(0x3Fu << 6)) | ((u32)(op & 0x3Fu) << 6);
                M->tms.cycles += 1;
            } else {
                M->tms.cycles += 2;
            }
            break;

        case 0x1: { /* ADDK / SUBK / CMPK / MOVK (5-bit K = 1..32, where 0 means 32) */
            u32 k = (op >> 5) & 0x1Fu;
            if (k == 0) k = 32u;
            u32 subop = (op >> 10) & 3u;
            if (subop == 0) { *rd += k; tms_set_nz(*rd); }          /* ADDK */
            else if (subop == 1) { *rd -= k; tms_set_nz(*rd); }     /* SUBK */
            else if (subop == 2) {                                  /* CMPK */
                u32 r = *rd - k;
                tms_set_nz(r);
                if (*rd < k) M->tms.st |= TMS_C; else M->tms.st &= ~TMS_C;
            } else { *rd = k; }                                     /* MOVK */
            M->tms.cycles += 1;
            break;
        }

        case 0x2: { /* SLA / SLL / SRA / SRL / RL immediate K */
            u32 k = (~(op >> 5)) & 0x1Fu;
            u32 subop = (op >> 10) & 3u;
            if (subop == 1)      *rd = k ? (*rd << k) : *rd;
            else if (subop == 2) *rd = k ? (u32)((s32)*rd >> k) : *rd;
            else if (subop == 3) *rd = k ? (*rd >> k) : *rd;
            else                 *rd = k ? ((*rd << k) | (*rd >> (32u - k))) : *rd;
            tms_set_nz(*rd);
            M->tms.cycles += 1;
            break;
        }

        case 0x3: { /* DSJ / DSJS */
            if (op & 0x0800u) {                         /* DSJS disp5, Rd */
                s32 d = (op >> 5) & 0x1Fu;
                if (op & 0x0400u) d = -d;
                (*rd)--;
                if (*rd != 0) M->tms.pc += (u32)(d * 16);
                M->tms.cycles += 2;
            } else {                                    /* DSJ Rd, disp16 */
                s16 d = (s16)tms_rw16(M->tms.pc);
                M->tms.pc += 16u;
                (*rd)--;
                if (*rd != 0) M->tms.pc += (u32)((s32)d * 16);
                M->tms.cycles += 3;
            }
            break;
        }

        case 0x4:   /* Register-to-register MOVE / ALU */
            if ((op & 0xFC00u) == 0x4C00u) {            /* MOVE Rs, Rd (same or cross file!) */
                u32 *src_cross = tms_reg_ptr(op >> 5, (op & 0x0200u) ? !rf_b : rf_b);
                *rd = *src_cross;
                tms_set_nz(*rd);
            } else if ((op & 0xFE00u) == 0x4000u) {     /* ADD Rs, Rd */
                *rd += *rs; tms_set_nz(*rd);
            } else if ((op & 0xFE00u) == 0x4400u) {     /* SUB Rs, Rd */
                *rd -= *rs; tms_set_nz(*rd);
            } else if ((op & 0xFE00u) == 0x4800u) {     /* CMP Rs, Rd */
                u32 r = *rd - *rs;
                tms_set_nz(r);
                if (*rd < *rs) M->tms.st |= TMS_C; else M->tms.st &= ~TMS_C;
            }
            M->tms.cycles += 1;
            break;

        case 0x5:
            if ((op & 0xFE00u) == 0x5000u) { *rd &= *rs;  tms_set_nz(*rd); }       /* AND */
            else if ((op & 0xFE00u) == 0x5200u) { *rd &= ~*rs; tms_set_nz(*rd); }  /* ANDN */
            else if ((op & 0xFE00u) == 0x5400u) { *rd |= *rs;  tms_set_nz(*rd); }  /* OR */
            else if ((op & 0xFE00u) == 0x5600u) { *rd ^= *rs;  tms_set_nz(*rd); }  /* XOR / CLR */
            else if ((op & 0xFE00u) == 0x5800u) { *rd = (u32)((s32)(*rs & 0xFFFFu) * (s32)(*rd & 0xFFFFu)); tms_set_nz(*rd); }
            else if ((op & 0xFE00u) == 0x5A00u) { *rd = (*rs & 0xFFFFu) * (*rd & 0xFFFFu); tms_set_nz(*rd); }
            else if ((op & 0xFFE0u) == 0x5E00u) { *rd = 0; tms_set_nz(0); }        /* CLR Rd */
            else if ((op & 0xFFE0u) == 0x5E40u) { *rd = ~*rd; tms_set_nz(*rd); }   /* NOT Rd */
            else if ((op & 0xFFE0u) == 0x5E60u) { *rd = 0u - *rd; tms_set_nz(*rd); } /* NEG Rd */
            M->tms.cycles += 1;
            break;

        case 0x8:   /* MOVE Rs / *Rs / *Rs+, Rd / *Rd / *Rd+ (Field 0 / 1) */
        case 0x9: {
            int f1 = (op & 0x0200u) != 0;
            u32 fs = f1 ? fs1 : fs0;
            int fe = f1 ? fe1 : fe0;
            u32 eff_fs = fs ? fs : 32u;
            u32 mode = (op >> 10) & 7u;
            if (mode == 0) {                            /* MOVE Rs, *Rd */
                tms_wfield(*rd, *rs, fs);
            } else if (mode == 1) {                     /* MOVE *Rs, Rd */
                *rd = tms_rfield(*rs, fs, fe);
                tms_set_nz(*rd);
            } else if (mode == 2) {                     /* MOVE *Rs, *Rd */
                tms_wfield(*rd, tms_rfield(*rs, fs, fe), fs);
            } else if (mode == 4) {                     /* MOVE Rs, *Rd+ */
                tms_wfield(*rd, *rs, fs);
                *rd += eff_fs;
            } else if (mode == 5) {                     /* MOVE *Rs+, Rd */
                *rd = tms_rfield(*rs, fs, fe);
                *rs += eff_fs;
                tms_set_nz(*rd);
            } else if (mode == 6) {                     /* MOVE Rs, -*Rd */
                *rd -= eff_fs;
                tms_wfield(*rd, *rs, fs);
            } else if (mode == 7) {                     /* MOVE -*Rs, Rd */
                *rs -= eff_fs;
                *rd = tms_rfield(*rs, fs, fe);
                tms_set_nz(*rd);
            }
            M->tms.cycles += 3;
            break;
        }

        case 0xA:   /* MOVE with 16-bit displacement *Rs(disp) / *Rd(disp) */
        case 0xB: {
            int f1 = (op & 0x0200u) != 0;
            u32 fs = f1 ? fs1 : fs0;
            int fe = f1 ? fe1 : fe0;
            s16 disp = (s16)tms_rw16(M->tms.pc);
            M->tms.pc += 16u;
            if ((op & 0x1C00u) == 0x0000u) {            /* MOVE Rs, *Rd(disp) */
                tms_wfield(*rd + (u32)(s32)disp, *rs, fs);
            } else if ((op & 0x1C00u) == 0x0400u) {     /* MOVE *Rs(disp), Rd */
                *rd = tms_rfield(*rs + (u32)(s32)disp, fs, fe);
                tms_set_nz(*rd);
            }
            M->tms.cycles += 4;
            break;
        }

        case 0xC: { /* JRcc (8-bit or 16-bit word displacement) / JAxx */
            u32 cc = (op >> 8) & 15u;
            u8  d8 = (u8)op;
            if (d8 != 0) {
                if (tms_cond(cc))
                    M->tms.pc += (u32)((s32)(s8)d8 * 16);
                M->tms.cycles += 2;
            } else if ((op & 0x00FFu) == 0x0080u) {     /* JAxx absolute 32-bit */
                u32 dst = tms_rl32(M->tms.pc);
                M->tms.pc += 32u;
                if (tms_cond(cc))
                    M->tms.pc = dst;
                M->tms.cycles += 3;
            } else {                                    /* JRcc 16-bit displacement */
                s16 d16 = (s16)tms_rw16(M->tms.pc);
                M->tms.pc += 16u;
                if (tms_cond(cc))
                    M->tms.pc += (u32)((s32)d16 * 16);
                M->tms.cycles += 3;
            }
            break;
        }

        default:
            M->tms.cycles += 2;
            break;
        }
    }
}

/* ============================================================================
   Built-in Playable Williams Blitter Arcade Game ("") : "CYBERTRON: 2084"
   Executes genuine MC6809E machine code on BOTH CPUs (Main + Sound) plus the
   Williams Special Chip Hardware Blitter ($CA00..$CA07) & 8-bit DAC ($0400)!
   ============================================================================ */

static void emit09_b(u8 *rom, u32 *p, u8 v)
{
    rom[(*p)++] = v;
}

static void emit09_w(u8 *rom, u32 *p, u16 v)
{
    rom[(*p)++] = (u8)(v >> 8);
    rom[(*p)++] = (u8)v;
}

static u32 emit09_br(u8 *rom, u32 *p, u8 op)
{
    rom[(*p)++] = op;
    u32 disp_at = (*p)++;
    rom[disp_at] = 0;
    return disp_at;
}

static void patch09_br(u8 *rom, u32 disp_at, u32 dst)
{
    rom[disp_at] = (u8)(dst - (disp_at + 1u));
}

static void build_builtin_sprites_and_font(void)
{
    /* Banked Graphics ROM at ROM_BUF[$0000..$1FFF] (read at $0000..$8FFF when $C900 = 1!):
       $0000..$007F (8x16 bytes = 16x16 px 4bpp): Cyber-Hero (visor + neon armor + plasma gun)
       $0080..$00FF (8x16 bytes = 16x16 px 4bpp): Grunt Cyber-Drone (glowing red/orange)
       $0100..$017F (8x16 bytes = 16x16 px 4bpp): Enforcer / Brain Mech (magenta/cyan)
       $0180..$01FF (8x16 bytes = 16x16 px 4bpp): Humanoid Colonist (gold/green)
       $0200..$021F (4x8  bytes = 8x8   px 4bpp): Plasma Bolt (white/yellow)
       $0280..$02FF (8x16 bytes = 16x16 px 4bpp): Williams Scatter Explosion Burst
       $0400..$0BFF (64 glyphs x 32 bytes = 8x8 4bpp): Arcade HUD Font (ASCII 32..95) */
    wil_zero(ROM_BUF, 0x10000u);

    #define PUT_GFX4(base, stride_b, x, y, pen) do {                        \
        u32 _o = (u32)(base) + (u32)(y) * (u32)(stride_b) + ((u32)(x) >> 1);\
        if ((x) & 1) ROM_BUF[_o] = (ROM_BUF[_o] & 0xF0u) | ((pen) & 0x0Fu); \
        else         ROM_BUF[_o] = (ROM_BUF[_o] & 0x0Fu) | (((pen) & 0x0Fu) << 4); \
    } while (0)

    /* 1. Cyber-Hero ($0000, 16x16, stride 8 B): helmet + glowing cyan visor + twin thrusters */
    static const char *const hero_art[16] = {
        ".....222222.....",
        "....21111112....",
        "....23333332....",
        "....23111132....",
        ".....222222.....",
        "...6624444266...",
        "..616241142616..",
        "..66.244442.66..",
        ".....242242.....",
        "....244..442....",
        "....24....42....",
        "...224....422...",
        "...55......55...",
        "...77......77...",
        "................",
        "................"
    };
    for (int y = 0; y < 16; y++)
        for (int x = 0; x < 16; x++) {
            char c = hero_art[y][x];
            if (c != '.') PUT_GFX4(0x0000u, 8u, x, y, (u8)(c - '0'));
        }

    /* 2. Grunt Cyber-Drone ($0080, 16x16, stride 8 B): menacing red/yellow robot */
    static const char *const grunt_art[16] = {
        "....88888888....",
        "...8999999998...",
        "..891199991198..",
        "..897799997798..",
        "..899999999998..",
        "...8897777988...",
        "..888888888888..",
        ".898.899998.898.",
        ".898.895598.898.",
        ".88..899998..88.",
        ".....88..88.....",
        "....898..898....",
        "...8998..8998...",
        "...8888..8888...",
        "................",
        "................"
    };
    for (int y = 0; y < 16; y++)
        for (int x = 0; x < 16; x++) {
            char c = grunt_art[y][x];
            if (c != '.') PUT_GFX4(0x0080u, 8u, x, y, (u8)(c - '0'));
        }

    /* 3. Enforcer / Brain Mech ($0100, 16x16, stride 8 B): magenta/cyan/violet */
    for (int y = 0; y < 16; y++) {
        for (int x = 0; x < 16; x++) {
            int dx = x - 7, dy = y - 7;
            int r2 = dx * dx + dy * dy;
            if (r2 <= 46) {
                u8 pen = (r2 <= 8) ? 1u : (r2 <= 20) ? 3u : ((x ^ y) & 2) ? 10u : 11u;
                PUT_GFX4(0x0100u, 8u, x, y, pen);
            }
        }
    }

    /* 4. Humanoid Colonist ($0180, 16x16, stride 8 B): green/gold */
    static const char *const hum_art[16] = {
        "......7777......",
        ".....717717.....",
        ".....777777.....",
        "......cccc......",
        "....cccccccc....",
        "...cc.cccc.cc...",
        "...c..cccc..c...",
        "......cccc......",
        ".....cc..cc.....",
        ".....cc..cc.....",
        "....cc....cc....",
        "....77....77....",
        "................",
        "................",
        "................",
        "................"
    };
    for (int y = 0; y < 16; y++)
        for (int x = 0; x < 16; x++) {
            char c = hum_art[y][x];
            if (c != '.') {
                u8 pen = (c >= 'a') ? (u8)(10 + c - 'a') : (u8)(c - '0');
                PUT_GFX4(0x0180u, 8u, x, y, pen);
            }
        }

    /* 5. Plasma Bolt ($0200, 8x8, stride 4 B) */
    for (int y = 1; y < 7; y++)
        for (int x = 1; x < 7; x++) {
            int d = (x - 3) * (x - 3) + (y - 3) * (y - 3);
            if (d <= 6) PUT_GFX4(0x0200u, 4u, x, y, (d <= 2) ? 1u : 7u);
        }

    /* 6. Williams Scatter Explosion ($0280, 16x16, stride 8 B) */
    for (int y = 0; y < 16; y++)
        for (int x = 0; x < 16; x++) {
            int dx = x - 7, dy = y - 7, r2 = dx * dx + dy * dy;
            if (r2 >= 9 && r2 <= 54 && ((x * 5 + y * 3) & 3) != 0)
                PUT_GFX4(0x0280u, 8u, x, y, (r2 < 26) ? 1u : (r2 < 40) ? 7u : 8u);
        }

    /* 7. 8x8 4bpp HUD Font at $0400 + (ch - 32) * 32 (4 bytes/row x 8 rows) */
    for (int ch = 32; ch < 96; ch++) {
        u32 base = 0x0400u + (u32)(ch - 32) * 32u;
        const u8 *gl = font5x7[ch - 32];
        for (int r = 0; r < 7; r++) {
            u8 bits = gl[r];
            for (int c = 0; c < 5; c++) {
                if (bits & (0x10u >> c))
                    PUT_GFX4(base, 4u, c + 1, r, (r < 3) ? 1u : 3u);
            }
        }
    }
    #undef PUT_GFX4
}

static void build_builtin_snd_rom(void)
{
    /* Genuine MC6809E Williams Sound ROM in SROM_BUF ($0000..$0FFF mapped at $F000..$FFFF):
       - Configures PIA2 ($0400..$0403): DDRA=$FF (8-bit DAC output), CRA=$04, DDRB=$00, CRB=$05 (CB1 IRQ on!)
       - Main loop synthesizes pulsing Williams cyber-bassline on $0400 DAC
       - IRQ handler ($F060) reads Sound Command from PIA2 Port B ($0402) & synthesizes:
         cmd 1: Williams Laser Chirp (fast descending pitch sweep!)
         cmd 2: Williams Explosion Roar (LFSR noise + sub-bass!) */
    wil_zero(SROM_BUF, 0x1000u);
    S.srom_size = 0x1000u;
    u32 p = 0x0000u;        /* Mapped at $F000 */

    /* $F000: Reset entry */
    emit09_b(SROM_BUF, &p, 0x10); emit09_b(SROM_BUF, &p, 0xCE); emit09_w(SROM_BUF, &p, 0x007E); /* LDS #$007E */
    emit09_b(SROM_BUF, &p, 0x7F); emit09_w(SROM_BUF, &p, 0x0401); /* CLR $0401 (select DDRA) */
    emit09_b(SROM_BUF, &p, 0x86); emit09_b(SROM_BUF, &p, 0xFF);   /* LDA #$FF */
    emit09_b(SROM_BUF, &p, 0xB7); emit09_w(SROM_BUF, &p, 0x0400); /* STA $0400 (DDRA = output) */
    emit09_b(SROM_BUF, &p, 0x86); emit09_b(SROM_BUF, &p, 0x04);   /* LDA #$04 */
    emit09_b(SROM_BUF, &p, 0xB7); emit09_w(SROM_BUF, &p, 0x0401); /* STA $0401 (CRA = ORA) */
    emit09_b(SROM_BUF, &p, 0x7F); emit09_w(SROM_BUF, &p, 0x0403); /* CLR $0403 (select DDRB) */
    emit09_b(SROM_BUF, &p, 0x7F); emit09_w(SROM_BUF, &p, 0x0402); /* CLR $0402 (DDRB = input) */
    emit09_b(SROM_BUF, &p, 0x86); emit09_b(SROM_BUF, &p, 0x05);   /* LDA #$05 (ORB + CB1 IRQ enable!) */
    emit09_b(SROM_BUF, &p, 0xB7); emit09_w(SROM_BUF, &p, 0x0403); /* STA $0403 */
    emit09_b(SROM_BUF, &p, 0x86); emit09_b(SROM_BUF, &p, 0x24);
    emit09_b(SROM_BUF, &p, 0x97); emit09_b(SROM_BUF, &p, 0x10);   /* $0010 = bass period */
    emit09_b(SROM_BUF, &p, 0x7F); emit09_w(SROM_BUF, &p, 0x0012); /* $0012 = sfx timer */
    emit09_b(SROM_BUF, &p, 0x1C); emit09_b(SROM_BUF, &p, 0xEF);   /* ANDCC #$EF (enable IRQ!) */

    /* main_synth_loop: */
    u32 l_main = p;
    /* Check if SFX timer ($0012) > 0 */
    emit09_b(SROM_BUF, &p, 0x96); emit09_b(SROM_BUF, &p, 0x12);   /* LDA <$12 */
    u32 b_bass = emit09_br(SROM_BUF, &p, 0x27);                   /* BEQ bass_only */
    emit09_b(SROM_BUF, &p, 0x0A); emit09_b(SROM_BUF, &p, 0x12);   /* DEC <$12 */
    /* Laser chirp: toggle DAC between $D8 and $28 with sweeping delay */
    emit09_b(SROM_BUF, &p, 0x86); emit09_b(SROM_BUF, &p, 0xD8);
    emit09_b(SROM_BUF, &p, 0xB7); emit09_w(SROM_BUF, &p, 0x0400);
    emit09_b(SROM_BUF, &p, 0xD6); emit09_b(SROM_BUF, &p, 0x12);   /* LDB <$12 */
    emit09_b(SROM_BUF, &p, 0x5A); emit09_b(SROM_BUF, &p, 0x26); emit09_b(SROM_BUF, &p, 0xFD);
    emit09_b(SROM_BUF, &p, 0x86); emit09_b(SROM_BUF, &p, 0x28);
    emit09_b(SROM_BUF, &p, 0xB7); emit09_w(SROM_BUF, &p, 0x0400);
    emit09_b(SROM_BUF, &p, 0xD6); emit09_b(SROM_BUF, &p, 0x12);
    emit09_b(SROM_BUF, &p, 0x5A); emit09_b(SROM_BUF, &p, 0x26); emit09_b(SROM_BUF, &p, 0xFD);
    emit09_b(SROM_BUF, &p, 0x20); emit09_b(SROM_BUF, &p, (u8)(l_main - (p + 1u)));

    /* bass_only: subtle Williams heartbeat pulse */
    patch09_br(SROM_BUF, b_bass, p);
    emit09_b(SROM_BUF, &p, 0x0C); emit09_b(SROM_BUF, &p, 0x11);   /* INC <$11 */
    emit09_b(SROM_BUF, &p, 0x96); emit09_b(SROM_BUF, &p, 0x11);
    emit09_b(SROM_BUF, &p, 0x84); emit09_b(SROM_BUF, &p, 0x40);   /* ANDA #$40 */
    emit09_b(SROM_BUF, &p, 0x8B); emit09_b(SROM_BUF, &p, 0x60);   /* ADDA #$60 ($60..$A0) */
    emit09_b(SROM_BUF, &p, 0xB7); emit09_w(SROM_BUF, &p, 0x0400);
    emit09_b(SROM_BUF, &p, 0xC6); emit09_b(SROM_BUF, &p, 0x18);   /* LDB #$18 */
    emit09_b(SROM_BUF, &p, 0x5A); emit09_b(SROM_BUF, &p, 0x26); emit09_b(SROM_BUF, &p, 0xFD);
    emit09_b(SROM_BUF, &p, 0x20); emit09_b(SROM_BUF, &p, (u8)(l_main - (p + 1u)));

    /* $F080: IRQ Handler (reads $0402 to clear CB1 IRQ & arms SFX sweep in $0012!) */
    p = 0x0080u;
    emit09_b(SROM_BUF, &p, 0xB6); emit09_w(SROM_BUF, &p, 0x0402); /* LDA $0402 (clears CB1!) */
    emit09_b(SROM_BUF, &p, 0x84); emit09_b(SROM_BUF, &p, 0x03);
    emit09_b(SROM_BUF, &p, 0x27); emit09_b(SROM_BUF, &p, 0x04);
    emit09_b(SROM_BUF, &p, 0x86); emit09_b(SROM_BUF, &p, 0x38);
    emit09_b(SROM_BUF, &p, 0x97); emit09_b(SROM_BUF, &p, 0x12);   /* STA <$12 */
    emit09_b(SROM_BUF, &p, 0x3B);                                 /* RTI */

    /* Vectors at $FFF0..$FFFF (offset $0FF0..$0FFF) */
    p = 0x0FF8u;
    emit09_w(SROM_BUF, &p, 0xF080u);    /* IRQ */
    emit09_w(SROM_BUF, &p, 0xF080u);    /* SWI */
    emit09_w(SROM_BUF, &p, 0xF080u);    /* NMI */
    emit09_w(SROM_BUF, &p, 0xF000u);    /* RESET */
}

static void build_builtin_main_rom(void)
{
    /* Genuine MC6809E Main Game Program at ROM_BUF[$D000..$FFFF] ("CYBERTRON: 2084"):
       Work RAM in M->vram[$9800..$98FF] (outside visible columns $00..$97 = 0..151!):
         $9800: frame_cnt     $9801: hero_x (16..272)   $9802: hero_y (36..216)
         $9803: prev_hx       $9804: prev_hy
         $9805: shot_active   $9806: shot_x             $9807: shot_y
         $9808: prev_sx       $9809: prev_sy            $980A: shot_dx (signed)
         $980B: shot_dy
         $9810..$9813: 4 Grunt X     $9814..$9817: 4 Grunt Y
         $9818..$981B: prev Grunt X  $981C..$981F: prev Grunt Y
         $9820: expl_timer    $9821: expl_x             $9822: expl_y
         $9823: score_bcd     $9824: snd_toggle */
    S.rom_size = 0x10000u;
    S.rom_mask = 0xFFFFu;

    /* Palette table at $DF00 (16 BBGGGRRR colors):
       0: Black ($00)        1: Bright White ($FF)   2: Cobalt Blue ($C0)
       3: Electric Cyan ($F8)4: Laser Blue ($D2)     5: Neon Magenta ($C7)
       6:Gold/Amber ($2F)    7: Bright Yellow ($3F)  8: Hot Red ($07)
       9: Fiery Orange ($1F) 10: Neon Violet ($85)   11: Deep Purple ($83)
       12: Emerald ($38)     13: Matrix Green ($28)  14: Steel ($92)  15: Border Cyan ($F9) */
    static const u8 pal16[16] = {
        0x00, 0xFF, 0xC0, 0xF8, 0xD2, 0xC7, 0x2F, 0x3F,
        0x07, 0x1F, 0x85, 0x83, 0x38, 0x28, 0x92, 0xF9
    };
    for (int i = 0; i < 16; i++)
        ROM_BUF[0xDF00u + i] = pal16[i];

    /* HUD Banner at $DF20 */
    static const char hud_txt[] = "CYBERTRON 2084   WAVE 01   SCORE 00";
    for (u32 i = 0; i < sizeof(hud_txt); i++)
        ROM_BUF[0xDF20u + i] = (u8)hud_txt[i];

    /* Helper subroutine at $DE00: Blit sprite from banked ROM!
       Inputs: X = ROM src ($0000..$1FFF), U = VRAM dst ((x_byte<<8)|y),
               A = width_bytes, B = height_lines, $9830 = ctrl ($42 fg or $46 solid) */
    u32 p = 0xDE00u;
    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA06);   /* STA $CA06 (width) */
    emit09_b(ROM_BUF, &p, 0xF7); emit09_w(ROM_BUF, &p, 0xCA07);   /* STB $CA07 (height) */
    emit09_b(ROM_BUF, &p, 0xBF); emit09_w(ROM_BUF, &p, 0xCA02);   /* STX $CA02 (saddr) */
    emit09_b(ROM_BUF, &p, 0xFF); emit09_w(ROM_BUF, &p, 0xCA04);   /* STU $CA04 (daddr) */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x01);     /* LDA #1 (ROM bank on) */
    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xC900);   /* STA $C900 */
    emit09_b(ROM_BUF, &p, 0xB6); emit09_w(ROM_BUF, &p, 0x9830);   /* LDA $9830 (ctrl) */
    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA00);   /* STA $CA00 (RUN BLITTER!) */
    emit09_b(ROM_BUF, &p, 0x7F); emit09_w(ROM_BUF, &p, 0xC900);   /* CLR $C900 (VRAM bank) */
    emit09_b(ROM_BUF, &p, 0x39);                                  /* RTS */

    /* Helper subroutine at $DE40: Erase 16x16 box (9 bytes wide to cover +1px shift, 16 high) at X=(xb<<8)|y */
    p = 0xDE40u;
    emit09_b(ROM_BUF, &p, 0x7F); emit09_w(ROM_BUF, &p, 0xCA01);   /* CLR $CA01 (solid color 0) */
    emit09_b(ROM_BUF, &p, 0xBF); emit09_w(ROM_BUF, &p, 0xCA04);   /* STX $CA04 (daddr) */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 9);        /* LDA #9 bytes */
    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA06);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 16);       /* LDA #16 lines */
    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA07);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x44);     /* d_vram(0x40) | solid(0x04) */
    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA00);
    emit09_b(ROM_BUF, &p, 0x39);                                  /* RTS */

    /* Helper at $DE70: Convert pixel X (in A), Y (in B) -> U = ((A>>1)<<8)|B, sets $9830 = $42 or $4A (shift!) */
    p = 0xDE70u;
    emit09_b(ROM_BUF, &p, 0x34); emit09_b(ROM_BUF, &p, 0x04);     /* PSHS B */
    emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 0x42);     /* LDB #$42 (d_vram + fg_only) */
    emit09_b(ROM_BUF, &p, 0x85); emit09_b(ROM_BUF, &p, 0x01);     /* BITA #1 (odd pixel?) */
    emit09_b(ROM_BUF, &p, 0x27); emit09_b(ROM_BUF, &p, 0x02);     /* BEQ +2 */
    emit09_b(ROM_BUF, &p, 0xCA); emit09_b(ROM_BUF, &p, 0x08);     /* ORB #$08 (hardware 4-bit shift!) */
    emit09_b(ROM_BUF, &p, 0xF7); emit09_w(ROM_BUF, &p, 0x9830);   /* STB $9830 */
    emit09_b(ROM_BUF, &p, 0x44);                                  /* LSRA (x_byte = x >> 1) */
    emit09_b(ROM_BUF, &p, 0x35); emit09_b(ROM_BUF, &p, 0x04);     /* PULS B */
    emit09_b(ROM_BUF, &p, 0x1F); emit09_b(ROM_BUF, &p, 0x03);     /* TFR D, U */
    emit09_b(ROM_BUF, &p, 0x39);                                  /* RTS */

    /* ---- $D000: Main Reset Entry ---- */
    p = 0xD000u;
    emit09_b(ROM_BUF, &p, 0x10); emit09_b(ROM_BUF, &p, 0xCE); emit09_w(ROM_BUF, &p, 0x9FF0); /* LDS #$9FF0 */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x98);
    emit09_b(ROM_BUF, &p, 0x1F); emit09_b(ROM_BUF, &p, 0x8B);     /* TFR A, DP (DP = $98!) */

    /* Configure PIA0 ($C804) & PIA1 ($C80C) */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x04);
    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xC805);
    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xC807);
    emit09_b(ROM_BUF, &p, 0x7F); emit09_w(ROM_BUF, &p, 0xC80F);   /* select PIA1 DDRB */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x3F);
    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xC80E);   /* PIA1 DDRB = $3F sound out */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x04);
    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xC80D);
    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xC80F);

    /* Copy 16-color BBGGGRRR palette $DF00 -> $C000 */
    emit09_b(ROM_BUF, &p, 0x8E); emit09_w(ROM_BUF, &p, 0xDF00);   /* LDX #$DF00 */
    emit09_b(ROM_BUF, &p, 0xCE); emit09_w(ROM_BUF, &p, 0xC000);   /* LDU #$C000 */
    emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 16);       /* LDB #16 */
    u32 l_pal = p;
    emit09_b(ROM_BUF, &p, 0xA6); emit09_b(ROM_BUF, &p, 0x80);     /* LDA ,X+ */
    emit09_b(ROM_BUF, &p, 0xA7); emit09_b(ROM_BUF, &p, 0xC0);     /* STA ,U+ */
    emit09_b(ROM_BUF, &p, 0x5A);                                  /* DECB */
    emit09_b(ROM_BUF, &p, 0x26); emit09_b(ROM_BUF, &p, (u8)(l_pal - (p + 1u)));

    /* Clear 304x256 VRAM via Blitter ($0000, width=152 bytes, height=255, solid=0) */
    emit09_b(ROM_BUF, &p, 0x7F); emit09_w(ROM_BUF, &p, 0xCA01);
    emit09_b(ROM_BUF, &p, 0x8E); emit09_w(ROM_BUF, &p, 0x0000);
    emit09_b(ROM_BUF, &p, 0xBF); emit09_w(ROM_BUF, &p, 0xCA04);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 152);
    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA06);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 255);
    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA07);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x44);
    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA00);

    /* Draw Williams glowing double-border arena ($02..$95, Y=26..244) using Blitter solid bars! */
    /* Top cyan bar: daddr=$021A, w=148, h=2, solid=$FF (pen 15) */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0xFF); emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA01);
    emit09_b(ROM_BUF, &p, 0x8E); emit09_w(ROM_BUF, &p, 0x021A); emit09_b(ROM_BUF, &p, 0xBF); emit09_w(ROM_BUF, &p, 0xCA04);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 148);  emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA06);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 2);    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA07);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x44); emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA00);
    /* Bottom magenta bar: daddr=$02F2, w=148, h=2, solid=$55 (pen 5) */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x55); emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA01);
    emit09_b(ROM_BUF, &p, 0x8E); emit09_w(ROM_BUF, &p, 0x02F2); emit09_b(ROM_BUF, &p, 0xBF); emit09_w(ROM_BUF, &p, 0xCA04);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x44); emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA00);
    /* Left & Right neon pillars: daddr=$021A & $951A, w=1, h=218, solid=$33 (pen 3) */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x33); emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA01);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 1);    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA06);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 218);  emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA07);
    emit09_b(ROM_BUF, &p, 0x8E); emit09_w(ROM_BUF, &p, 0x021A); emit09_b(ROM_BUF, &p, 0xBF); emit09_w(ROM_BUF, &p, 0xCA04);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x44); emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA00);
    emit09_b(ROM_BUF, &p, 0x8E); emit09_w(ROM_BUF, &p, 0x951A); emit09_b(ROM_BUF, &p, 0xBF); emit09_w(ROM_BUF, &p, 0xCA04);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x44); emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xCA00);

    /* Blit HUD string at $DF20 onto Y=12, X_byte = $06, $0A, $0E ... (+4 bytes = 8px per char!) */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x42); emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x30);
    emit09_b(ROM_BUF, &p, 0x10); emit09_b(ROM_BUF, &p, 0x8E); emit09_w(ROM_BUF, &p, 0xDF20); /* LDY #$DF20 */
    emit09_b(ROM_BUF, &p, 0xCE); emit09_w(ROM_BUF, &p, 0x060C);   /* LDU #$060C */
    u32 l_hud = p;
    emit09_b(ROM_BUF, &p, 0xE6); emit09_b(ROM_BUF, &p, 0xA0);     /* LDB ,Y+ */
    u32 b_hud_done = emit09_br(ROM_BUF, &p, 0x27);                /* BEQ hud_done */
    emit09_b(ROM_BUF, &p, 0xC0); emit09_b(ROM_BUF, &p, 32);       /* SUBB #32 */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 32);       /* LDA #32 */
    emit09_b(ROM_BUF, &p, 0x3D);                                  /* MUL -> D = (ch-32)*32 */
    emit09_b(ROM_BUF, &p, 0xC3); emit09_w(ROM_BUF, &p, 0x0400);   /* ADDD #$0400 */
    emit09_b(ROM_BUF, &p, 0x1F); emit09_b(ROM_BUF, &p, 0x01);     /* TFR D, X */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 4);        /* w = 4 bytes */
    emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 8);        /* h = 8 lines */
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE00);   /* JSR $DE00 */
    emit09_b(ROM_BUF, &p, 0x33); emit09_b(ROM_BUF, &p, 0xC9); emit09_w(ROM_BUF, &p, 0x0400); /* LEAU $0400, U */
    emit09_b(ROM_BUF, &p, 0x20); emit09_b(ROM_BUF, &p, (u8)(l_hud - (p + 1u)));
    patch09_br(ROM_BUF, b_hud_done, p);

    /* Initialize Hero & 4 Grunt Drones & Humanoids in $9800..$982F */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 136); emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x01);
    emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x03);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 128); emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x02);
    emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x04);
    emit09_b(ROM_BUF, &p, 0x0F); emit09_b(ROM_BUF, &p, 0x05);     /* CLR <$05 (shot_active) */
    emit09_b(ROM_BUF, &p, 0x0F); emit09_b(ROM_BUF, &p, 0x20);     /* CLR <$20 (expl_timer) */
    emit09_b(ROM_BUF, &p, 0x0F); emit09_b(ROM_BUF, &p, 0x23);     /* CLR <$23 (score) */

    static const u8 gx_init[4] = {28, 244, 32, 240};
    static const u8 gy_init[4] = {44, 48, 212, 208};
    for (int i = 0; i < 4; i++) {
        emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, gx_init[i]);
        emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, (u8)(0x10 + i));
        emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, (u8)(0x18 + i));
        emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, gy_init[i]);
        emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, (u8)(0x14 + i));
        emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, (u8)(0x1C + i));
    }

    /* Draw 2 static Humanoids + Enforcer Orbs in corners */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 84);
    emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 80);
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE70);
    emit09_b(ROM_BUF, &p, 0x8E); emit09_w(ROM_BUF, &p, 0x0180);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 8); emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 16);
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE00);

    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 208);
    emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 176);
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE70);
    emit09_b(ROM_BUF, &p, 0x8E); emit09_w(ROM_BUF, &p, 0x0100);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 8); emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 16);
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE00);

    /* ==== 60 Hz Beam-Synced Main Game Loop ==== */
    u32 l_frame = p;
    /* 1. Sync to rising edge of scanline 16 ($CB00 == $10) so all erase+blit finishes well before VBlank! */
    u32 w_vb1 = p;
    emit09_b(ROM_BUF, &p, 0xB6); emit09_w(ROM_BUF, &p, 0xCB00);
    emit09_b(ROM_BUF, &p, 0x81); emit09_b(ROM_BUF, &p, 0x10);
    emit09_b(ROM_BUF, &p, 0x27); emit09_b(ROM_BUF, &p, (u8)(w_vb1 - (p + 1u)));
    u32 w_vb2 = p;
    emit09_b(ROM_BUF, &p, 0xB6); emit09_w(ROM_BUF, &p, 0xCB00);
    emit09_b(ROM_BUF, &p, 0x81); emit09_b(ROM_BUF, &p, 0x10);
    emit09_b(ROM_BUF, &p, 0x26); emit09_b(ROM_BUF, &p, (u8)(w_vb2 - (p + 1u)));

    emit09_b(ROM_BUF, &p, 0x0C); emit09_b(ROM_BUF, &p, 0x00);     /* INC <$00 (frame_cnt) */

    /* Erase active explosion if timer > 0 */
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x20);
    u32 b_no_ers_ex = emit09_br(ROM_BUF, &p, 0x27);
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x21);
    emit09_b(ROM_BUF, &p, 0x44);
    emit09_b(ROM_BUF, &p, 0xD6); emit09_b(ROM_BUF, &p, 0x22);
    emit09_b(ROM_BUF, &p, 0x1F); emit09_b(ROM_BUF, &p, 0x01);
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE40);
    emit09_b(ROM_BUF, &p, 0x0A); emit09_b(ROM_BUF, &p, 0x20);     /* DEC expl_timer */
    patch09_br(ROM_BUF, b_no_ers_ex, p);

    /* 2. Erase Hero at prev_hx/prev_hy */
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x03);     /* LDA <$03 */
    emit09_b(ROM_BUF, &p, 0x44);                                  /* LSRA */
    emit09_b(ROM_BUF, &p, 0xD6); emit09_b(ROM_BUF, &p, 0x04);     /* LDB <$04 */
    emit09_b(ROM_BUF, &p, 0x1F); emit09_b(ROM_BUF, &p, 0x01);     /* TFR D, X */
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE40);   /* JSR erase_16x16 */

    /* Erase active Plasma Bolt if any */
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x05);
    u32 b_no_ers_s = emit09_br(ROM_BUF, &p, 0x27);                /* BEQ no_erase_shot */
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x08);
    emit09_b(ROM_BUF, &p, 0x44);
    emit09_b(ROM_BUF, &p, 0xD6); emit09_b(ROM_BUF, &p, 0x09);
    emit09_b(ROM_BUF, &p, 0x1F); emit09_b(ROM_BUF, &p, 0x01);
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE40);
    patch09_br(ROM_BUF, b_no_ers_s, p);

    /* 3. Read PIA0 ($C804) inputs (b0=Up, b1=Down, b2=Left, b3=Right, b4=Fire) */
    emit09_b(ROM_BUF, &p, 0xB6); emit09_w(ROM_BUF, &p, 0xC804);   /* LDA $C804 */
    u32 b_manual = emit09_br(ROM_BUF, &p, 0x26);                  /* BNE manual_ctrl */
    /* Attract AI patrol + periodic fire! */
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x00);
    emit09_b(ROM_BUF, &p, 0x85); emit09_b(ROM_BUF, &p, 0x40);
    u32 b_ai2 = emit09_br(ROM_BUF, &p, 0x27);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x15);     /* Up + Left + Fire */
    u32 b_ai_end = emit09_br(ROM_BUF, &p, 0x20);
    patch09_br(ROM_BUF, b_ai2, p);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 0x1A);     /* Down + Right + Fire */
    patch09_br(ROM_BUF, b_ai_end, p);
    patch09_br(ROM_BUF, b_manual, p);

    /* manual_ctrl: A = input mask */
    emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x32);     /* save input in <$32 */
    emit09_b(ROM_BUF, &p, 0xD6); emit09_b(ROM_BUF, &p, 0x02);     /* LDB hero_y */
    emit09_b(ROM_BUF, &p, 0x85); emit09_b(ROM_BUF, &p, 0x01);     /* Up? */
    u32 b_nu = emit09_br(ROM_BUF, &p, 0x27);
    emit09_b(ROM_BUF, &p, 0xC0); emit09_b(ROM_BUF, &p, 2);
    emit09_b(ROM_BUF, &p, 0xC1); emit09_b(ROM_BUF, &p, 34);
    u32 b_uok = emit09_br(ROM_BUF, &p, 0x24);
    emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 34);
    patch09_br(ROM_BUF, b_uok, p);
    patch09_br(ROM_BUF, b_nu, p);

    emit09_b(ROM_BUF, &p, 0x85); emit09_b(ROM_BUF, &p, 0x02);     /* Down? */
    u32 b_nd = emit09_br(ROM_BUF, &p, 0x27);
    emit09_b(ROM_BUF, &p, 0xCB); emit09_b(ROM_BUF, &p, 2);
    emit09_b(ROM_BUF, &p, 0xC1); emit09_b(ROM_BUF, &p, 220);
    u32 b_dok = emit09_br(ROM_BUF, &p, 0x23);
    emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 220);
    patch09_br(ROM_BUF, b_dok, p);
    patch09_br(ROM_BUF, b_nd, p);
    emit09_b(ROM_BUF, &p, 0xD7); emit09_b(ROM_BUF, &p, 0x02);
    emit09_b(ROM_BUF, &p, 0xD7); emit09_b(ROM_BUF, &p, 0x04);

    emit09_b(ROM_BUF, &p, 0xD6); emit09_b(ROM_BUF, &p, 0x01);     /* LDB hero_x (16..244) */
    emit09_b(ROM_BUF, &p, 0x85); emit09_b(ROM_BUF, &p, 0x04);     /* Left? */
    u32 b_nl = emit09_br(ROM_BUF, &p, 0x27);
    emit09_b(ROM_BUF, &p, 0xC0); emit09_b(ROM_BUF, &p, 2);
    emit09_b(ROM_BUF, &p, 0xC1); emit09_b(ROM_BUF, &p, 16);
    u32 b_lok = emit09_br(ROM_BUF, &p, 0x24);
    emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 16);
    patch09_br(ROM_BUF, b_lok, p);
    patch09_br(ROM_BUF, b_nl, p);

    emit09_b(ROM_BUF, &p, 0x85); emit09_b(ROM_BUF, &p, 0x08);     /* Right? */
    u32 b_nr = emit09_br(ROM_BUF, &p, 0x27);
    emit09_b(ROM_BUF, &p, 0xCB); emit09_b(ROM_BUF, &p, 2);
    emit09_b(ROM_BUF, &p, 0xC1); emit09_b(ROM_BUF, &p, 244);
    u32 b_rok = emit09_br(ROM_BUF, &p, 0x23);
    emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 244);
    patch09_br(ROM_BUF, b_rok, p);
    patch09_br(ROM_BUF, b_nr, p);
    emit09_b(ROM_BUF, &p, 0xD7); emit09_b(ROM_BUF, &p, 0x01);
    emit09_b(ROM_BUF, &p, 0xD7); emit09_b(ROM_BUF, &p, 0x03);

    /* 4. Fire & Advance Plasma Bolt */
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x05);
    u32 b_step_shot = emit09_br(ROM_BUF, &p, 0x26);               /* BNE step_shot */
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x32);
    emit09_b(ROM_BUF, &p, 0x85); emit09_b(ROM_BUF, &p, 0x10);     /* Fire button? */
    u32 b_no_fire = emit09_br(ROM_BUF, &p, 0x27);                 /* BEQ done_shot */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 1);
    emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x05);
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x01);
    emit09_b(ROM_BUF, &p, 0x8B); emit09_b(ROM_BUF, &p, 8);
    emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x06);
    emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x08);
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x02);
    emit09_b(ROM_BUF, &p, 0x8B); emit09_b(ROM_BUF, &p, 4);
    emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x07);
    emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x09);
    /* Trigger Sound 6809 Laser Chirp via PIA1 Port B ($C80E)! */
    emit09_b(ROM_BUF, &p, 0x0C); emit09_b(ROM_BUF, &p, 0x24);
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x24);
    emit09_b(ROM_BUF, &p, 0x84); emit09_b(ROM_BUF, &p, 0x03);
    emit09_b(ROM_BUF, &p, 0x8A); emit09_b(ROM_BUF, &p, 0x01);
    emit09_b(ROM_BUF, &p, 0xB7); emit09_w(ROM_BUF, &p, 0xC80E);
    u32 b_shot_spawned = emit09_br(ROM_BUF, &p, 0x20);            /* BRA done_shot */

    /* step_shot: */
    patch09_br(ROM_BUF, b_step_shot, p);
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x06);
    emit09_b(ROM_BUF, &p, 0x8B); emit09_b(ROM_BUF, &p, 5);        /* shot_x += 5 */
    u32 b_ovf = emit09_br(ROM_BUF, &p, 0x25);                     /* BCS clear_shot */
    emit09_b(ROM_BUF, &p, 0x81); emit09_b(ROM_BUF, &p, 248);
    u32 b_keep_s = emit09_br(ROM_BUF, &p, 0x23);                  /* BLS keep_shot */
    patch09_br(ROM_BUF, b_ovf, p);
    emit09_b(ROM_BUF, &p, 0x0F); emit09_b(ROM_BUF, &p, 0x05);     /* CLR shot_active */
    u32 b_clr_done = emit09_br(ROM_BUF, &p, 0x20);
    /* keep_shot: */
    patch09_br(ROM_BUF, b_keep_s, p);
    emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x06);
    emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x08);
    /* done_shot: */
    patch09_br(ROM_BUF, b_no_fire, p);
    patch09_br(ROM_BUF, b_shot_spawned, p);
    patch09_br(ROM_BUF, b_clr_done, p);

    /* 5. Update & Blit 4 Pursuing Grunt Cyber-Drones (march toward Hero every 2nd frame!) */
    emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 0);        /* B = drone idx 0..3 */
    u32 l_drone = p;
    emit09_b(ROM_BUF, &p, 0xF7); emit09_w(ROM_BUF, &p, 0x9834);   /* save idx */
    emit09_b(ROM_BUF, &p, 0x8E); emit09_w(ROM_BUF, &p, 0x9810);
    emit09_b(ROM_BUF, &p, 0x3A);                                  /* ABX -> X = &gx[i] */
    /* Erase old drone at prev_gx (X+8), prev_gy (X+12) */
    emit09_b(ROM_BUF, &p, 0xA6); emit09_b(ROM_BUF, &p, 8);
    emit09_b(ROM_BUF, &p, 0x44);
    emit09_b(ROM_BUF, &p, 0xE6); emit09_b(ROM_BUF, &p, 12);
    emit09_b(ROM_BUF, &p, 0x34); emit09_b(ROM_BUF, &p, 0x10);     /* PSHS X */
    emit09_b(ROM_BUF, &p, 0x1F); emit09_b(ROM_BUF, &p, 0x01);     /* TFR D, X */
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE40);
    emit09_b(ROM_BUF, &p, 0x35); emit09_b(ROM_BUF, &p, 0x10);     /* PULS X */

    /* Move drone 1 px toward Hero on odd frames */
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x00);
    emit09_b(ROM_BUF, &p, 0x85); emit09_b(ROM_BUF, &p, 0x01);
    u32 b_skip_mv = emit09_br(ROM_BUF, &p, 0x27);                 /* BEQ skip_move */
    emit09_b(ROM_BUF, &p, 0xA6); emit09_b(ROM_BUF, &p, 0x84);     /* LDA ,X (gx) */
    emit09_b(ROM_BUF, &p, 0x91); emit09_b(ROM_BUF, &p, 0x01);     /* CMPA hero_x */
    u32 b_gx_ge = emit09_br(ROM_BUF, &p, 0x24);
    emit09_b(ROM_BUF, &p, 0x4C);
    u32 b_gx_dn = emit09_br(ROM_BUF, &p, 0x20);
    patch09_br(ROM_BUF, b_gx_ge, p);
    emit09_b(ROM_BUF, &p, 0x4A);
    patch09_br(ROM_BUF, b_gx_dn, p);
    emit09_b(ROM_BUF, &p, 0xA7); emit09_b(ROM_BUF, &p, 0x84);

    emit09_b(ROM_BUF, &p, 0xA6); emit09_b(ROM_BUF, &p, 4);        /* LDA 4,X (gy) */
    emit09_b(ROM_BUF, &p, 0x91); emit09_b(ROM_BUF, &p, 0x02);     /* CMPA hero_y */
    u32 b_gy_ge = emit09_br(ROM_BUF, &p, 0x24);
    emit09_b(ROM_BUF, &p, 0x4C);
    u32 b_gy_dn = emit09_br(ROM_BUF, &p, 0x20);
    patch09_br(ROM_BUF, b_gy_ge, p);
    emit09_b(ROM_BUF, &p, 0x4A);
    patch09_br(ROM_BUF, b_gy_dn, p);
    emit09_b(ROM_BUF, &p, 0xA7); emit09_b(ROM_BUF, &p, 4);
    patch09_br(ROM_BUF, b_skip_mv, p);

    /* Check if active Plasma Bolt (<$05) hits this Grunt (,X / 4,X)! */
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x05);
    u32 b_nh0 = emit09_br(ROM_BUF, &p, 0x27);
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x06);     /* shot_x */
    emit09_b(ROM_BUF, &p, 0x8B); emit09_b(ROM_BUF, &p, 8);
    emit09_b(ROM_BUF, &p, 0xA0); emit09_b(ROM_BUF, &p, 0x84);     /* SUBA ,X */
    emit09_b(ROM_BUF, &p, 0x81); emit09_b(ROM_BUF, &p, 20);
    u32 b_nh1 = emit09_br(ROM_BUF, &p, 0x22);                     /* BHI no_hit */
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x07);     /* shot_y */
    emit09_b(ROM_BUF, &p, 0x8B); emit09_b(ROM_BUF, &p, 8);
    emit09_b(ROM_BUF, &p, 0xA0); emit09_b(ROM_BUF, &p, 4);        /* SUBA 4,X */
    emit09_b(ROM_BUF, &p, 0x81); emit09_b(ROM_BUF, &p, 20);
    u32 b_nh2 = emit09_br(ROM_BUF, &p, 0x22);                     /* BHI no_hit */
    /* HIT! Spawn explosion ($9820=12), respawn Grunt at right edge (244), increment HUD score! */
    emit09_b(ROM_BUF, &p, 0x0F); emit09_b(ROM_BUF, &p, 0x05);     /* CLR shot_active */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 12);
    emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x20);     /* expl_timer = 12 */
    emit09_b(ROM_BUF, &p, 0xA6); emit09_b(ROM_BUF, &p, 0x84);
    emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x21);     /* expl_x */
    emit09_b(ROM_BUF, &p, 0xA6); emit09_b(ROM_BUF, &p, 4);
    emit09_b(ROM_BUF, &p, 0x97); emit09_b(ROM_BUF, &p, 0x22);     /* expl_y */
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 244);
    emit09_b(ROM_BUF, &p, 0xA7); emit09_b(ROM_BUF, &p, 0x84);     /* respawn gx = 244 */
    emit09_b(ROM_BUF, &p, 0x0C); emit09_b(ROM_BUF, &p, 0x23);     /* INC score */
    patch09_br(ROM_BUF, b_nh0, p);
    patch09_br(ROM_BUF, b_nh1, p);
    patch09_br(ROM_BUF, b_nh2, p);

    /* skip_move: save prev & draw Grunt ($0080) */
    emit09_b(ROM_BUF, &p, 0xA6); emit09_b(ROM_BUF, &p, 0x84);
    emit09_b(ROM_BUF, &p, 0xA7); emit09_b(ROM_BUF, &p, 8);
    emit09_b(ROM_BUF, &p, 0xE6); emit09_b(ROM_BUF, &p, 4);
    emit09_b(ROM_BUF, &p, 0xE7); emit09_b(ROM_BUF, &p, 12);
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE70);
    emit09_b(ROM_BUF, &p, 0x8E); emit09_w(ROM_BUF, &p, 0x0080);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 8);
    emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 16);
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE00);

    emit09_b(ROM_BUF, &p, 0xF6); emit09_w(ROM_BUF, &p, 0x9834);
    emit09_b(ROM_BUF, &p, 0x5C);                                  /* INCB */
    emit09_b(ROM_BUF, &p, 0xC1); emit09_b(ROM_BUF, &p, 4);
    emit09_b(ROM_BUF, &p, 0x25); emit09_b(ROM_BUF, &p, (u8)(l_drone - (p + 1u)));

    /* 6. Blit Hero ($0000) & Active Plasma Bolt ($0200) */
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x01);
    emit09_b(ROM_BUF, &p, 0xD6); emit09_b(ROM_BUF, &p, 0x02);
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE70);
    emit09_b(ROM_BUF, &p, 0x8E); emit09_w(ROM_BUF, &p, 0x0000);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 8);
    emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 16);
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE00);

    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x05);
    u32 b_no_ds = emit09_br(ROM_BUF, &p, 0x27);                   /* BEQ no_draw_shot */
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x06);
    emit09_b(ROM_BUF, &p, 0xD6); emit09_b(ROM_BUF, &p, 0x07);
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE70);
    emit09_b(ROM_BUF, &p, 0x8E); emit09_w(ROM_BUF, &p, 0x0200);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 4);
    emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 8);
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE00);
    patch09_br(ROM_BUF, b_no_ds, p);

    /* Draw Williams Scatter Explosion ($0280) if expl_timer > 0! */
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x20);
    u32 b_no_dex = emit09_br(ROM_BUF, &p, 0x27);
    emit09_b(ROM_BUF, &p, 0x96); emit09_b(ROM_BUF, &p, 0x21);
    emit09_b(ROM_BUF, &p, 0xD6); emit09_b(ROM_BUF, &p, 0x22);
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE70);
    emit09_b(ROM_BUF, &p, 0x8E); emit09_w(ROM_BUF, &p, 0x0280);
    emit09_b(ROM_BUF, &p, 0x86); emit09_b(ROM_BUF, &p, 8);
    emit09_b(ROM_BUF, &p, 0xC6); emit09_b(ROM_BUF, &p, 16);
    emit09_b(ROM_BUF, &p, 0xBD); emit09_w(ROM_BUF, &p, 0xDE00);
    patch09_br(ROM_BUF, b_no_dex, p);

    /* Loop back to next frame! */
    emit09_b(ROM_BUF, &p, 0x7E); emit09_w(ROM_BUF, &p, (u16)l_frame); /* JMP l_frame */

    /* Default IRQ/FIRQ/NMI handler at $DFA0 (reads PIA0/PIA1 to ack & RTI) */
    p = 0xDFA0u;
    emit09_b(ROM_BUF, &p, 0xB6); emit09_w(ROM_BUF, &p, 0xC80C);
    emit09_b(ROM_BUF, &p, 0xB6); emit09_w(ROM_BUF, &p, 0xC80E);
    emit09_b(ROM_BUF, &p, 0x3B);                                  /* RTI */

    /* MC6809E Vectors at $FFF0..$FFFF */
    p = 0xFFF6u;
    emit09_w(ROM_BUF, &p, 0xDFA0u);     /* FIRQ */
    emit09_w(ROM_BUF, &p, 0xDFA0u);     /* IRQ */
    emit09_w(ROM_BUF, &p, 0xDFA0u);     /* SWI */
    emit09_w(ROM_BUF, &p, 0xDFA0u);     /* NMI */
    emit09_w(ROM_BUF, &p, 0xD000u);     /* RESET */
}

/* ============================================================================
   MAME .zip Romset Detection & Loader (Early Williams & Midway TMS34010)
   ============================================================================ */

int williams_is_zip(const u8 *zip, u32 size, const char *name)
{
    if (!zip_is(zip, size))
        return 0;
    static const char *const wil_sets[] = {
        "robotron", "joust", "defender", "stargate", "bubbles", "splat", "sinistar",
        "smashtv", "totcarn", "mk.", "mk1", "mk2", "nbajam", "term2", "narc", "trog", 0
    };
    for (int i = 0; wil_sets[i]; i++)
        if (wil_ci_has(name, wil_sets[i]))
            return 1;

    u32 cnt = zip_count(zip, size);
    char mname[96];
    u32 msz = 0;
    for (u32 i = 0; i < cnt; i++) {
        if (zip_unpack_at(zip, size, i, 0, 0, &msz, mname, sizeof(mname)) != 0)
            continue;
        if (wil_ci_has(mname, "board_williams") || wil_ci_has(mname, "board_midway") ||
            wil_ci_has(mname, "tms34010") || wil_ci_has(mname, "robotron") ||
            wil_ci_has(mname, "joust.") || wil_ci_has(mname, "defend."))
            return 1;
    }
    return 0;
}

static u32 wil_pow2_mask(u32 sz)
{
    if (!sz) return 0;
    u32 p2 = 1u;
    while (p2 < sz && p2 < 0x40000000u)
        p2 <<= 1;
    return p2 - 1u;
}

static const char *wil_load_zip(const u8 *zip, u32 size, const char *path)
{
    u32 cnt = zip_count(zip, size);
    if (!cnt)
        return "corrupt Williams/Midway .zip archive";

    wil_zero(ROM_BUF, 0x100000u);
    wil_zero(SROM_BUF, 0x10000u);
    wil_zero(PCM_BUF, 0x40000u);
    wil_zero(GFX_BUF, 0x40000u);

    S.board       = WIL_BOARD_BLITTER;
    S.sub         = WIL_SUB_GENERIC;
    S.blitter_xor = 0;
    S.blitter_clip = 0xC000u;
    S.scr_w       = 304;
    S.scr_h       = 240;

    if (wil_ci_has(path, "robotron")) {
        S.sub = WIL_SUB_ROBOTRON; S.blitter_xor = 4u;
    } else if (wil_ci_has(path, "joust")) {
        S.sub = WIL_SUB_JOUST;    S.blitter_xor = 4u;
    } else if (wil_ci_has(path, "stargate")) {
        S.sub = WIL_SUB_STARGATE; S.blitter_xor = 4u;
    } else if (wil_ci_has(path, "sinistar")) {
        S.sub = WIL_SUB_SINISTAR; S.blitter_xor = 4u; S.blitter_clip = 0x7400u;
    } else if (wil_ci_has(path, "bubbles") || wil_ci_has(path, "splat")) {
        S.sub = WIL_SUB_BUBBLES;  S.blitter_xor = 0u;
    } else if (wil_ci_has(path, "defender")) {
        S.sub = WIL_SUB_DEFENDER;
    } else if (wil_ci_has(path, "smashtv") || wil_ci_has(path, "mk") ||
               wil_ci_has(path, "nbajam")  || wil_ci_has(path, "midway") ||
               wil_ci_has(path, "totcarn") || wil_ci_has(path, "trog")) {
        S.board = WIL_BOARD_TMS34010;
        S.sub   = WIL_SUB_YUNIT;
        S.scr_w = 400;
        S.scr_h = 254;
    }

    u32 seq_4k = 0;
    char mname[96];
    u32 msz = 0;

    for (u32 i = 0; i < cnt; i++) {
        WIL_POLL();
        if (zip_unpack_at(zip, size, i, 0, 0, &msz, mname, sizeof(mname)) != 0 || !msz)
            continue;
        if (wil_ci_has(mname, "board_midway") || wil_ci_has(mname, "tms34010")) {
            S.board = WIL_BOARD_TMS34010;
            S.sub   = WIL_SUB_YUNIT;
            S.scr_w = 400;
            S.scr_h = 254;
            if (wil_ci_has(mname, "board_midway"))
                continue;
        }
        if (wil_ci_has(mname, "board_sc1")) {
            S.blitter_xor = 4u;
            continue;
        }
        if (msz > WIL_STAGE_CAP)
            continue;
        if (zip_unpack_at(zip, size, i, ZIP_STAGE, WIL_STAGE_CAP, &msz, mname, sizeof(mname)) != 0)
            continue;

        if (wil_ci_ends(mname, "tms34010.rom") || wil_ci_ends(mname, "gsp.rom")) {
            /* Explicit TMS34010 program ROM placed at end of 1 MB ($FFF00000..$FFFFFFFF = bytes 0xE0000..0xFFFFF) */
            S.board = WIL_BOARD_TMS34010;
            S.scr_w = 400; S.scr_h = 254;
            u32 cap = msz < 0x100000u ? msz : 0x100000u;
            u32 dst0 = 0x100000u - cap;
            for (u32 k = 0; k < cap; k++)
                ROM_BUF[dst0 + k] = ZIP_STAGE[k];
            S.rom_size = 0x100000u;
        } else if (wil_ci_ends(mname, "main.rom") || wil_ci_ends(mname, "6809.rom")) {
            u32 cap = msz < 0x10000u ? msz : 0x10000u;
            u32 dst0 = (cap <= 0x3000u) ? (0x10000u - cap) : 0u;
            for (u32 k = 0; k < cap; k++)
                ROM_BUF[dst0 + k] = ZIP_STAGE[k];
            if (dst0 + cap > S.rom_size) S.rom_size = dst0 + cap;
        } else if (wil_ci_ends(mname, "bank.rom")) {
            u32 cap = msz < 0x9000u ? msz : 0x9000u;
            for (u32 k = 0; k < cap; k++)
                ROM_BUF[k] = ZIP_STAGE[k];
            if (0x10000u > S.rom_size) S.rom_size = 0x10000u;
        } else if (wil_ci_ends(mname, "snd.rom") || wil_ci_ends(mname, "sound.rom") ||
                   wil_ci_has(mname, "snd") || wil_ci_ends(mname, ".snd")) {
            u32 cap = msz < 0x10000u ? msz : 0x10000u;
            /* Mirror 4 KB sound ROM across 4 KB..64 KB */
            for (u32 k = 0; k < cap; k++)
                SROM_BUF[k] = ZIP_STAGE[k];
            S.srom_size = cap;
        } else if (wil_ci_ends(mname, "oki.rom") || wil_ci_ends(mname, "adpcm.rom")) {
            u32 cap = msz < WIL_PCM_CAP ? msz : WIL_PCM_CAP;
            for (u32 k = 0; k < cap; k++)
                PCM_BUF[k] = ZIP_STAGE[k];
            S.pcm_size = cap;
        } else if (wil_ci_ends(mname, "gfx.rom") || wil_ci_ends(mname, "dma.rom")) {
            u32 cap = msz < WIL_GFX_CAP ? msz : WIL_GFX_CAP;
            for (u32 k = 0; k < cap; k++)
                GFX_BUF[k] = ZIP_STAGE[k];
            S.gfx_size = cap;
        } else if (S.board == WIL_BOARD_BLITTER && msz == 0x1000u) {
            /* Standard MAME Early Williams 12 x 4 KB ROMs:
               0..8  (9 x 4 KB = $0000..$8FFF banked ROM),
               9..11 (3 x 4 KB = $D000..$FFFF main program ROM)! */
            static const u16 slot_map[12] = {
                0x0000, 0x1000, 0x2000, 0x3000, 0x4000, 0x5000,
                0x6000, 0x7000, 0x8000, 0xD000, 0xE000, 0xF000
            };
            if (seq_4k < 12u) {
                u32 base = slot_map[seq_4k++];
                for (u32 k = 0; k < 0x1000u; k++)
                    ROM_BUF[base + k] = ZIP_STAGE[k];
                S.rom_size = 0x10000u;
            } else if (!S.srom_size) {
                for (u32 k = 0; k < 0x1000u; k++)
                    SROM_BUF[k] = ZIP_STAGE[k];
                S.srom_size = 0x1000u;
            }
        }
    }

    if (!S.rom_size)
        return "no recognizable Williams 6809 or Midway TMS34010 ROMs found in .zip";

    S.rom_mask = wil_pow2_mask(S.rom_size);
    S.pcm_mask = wil_pow2_mask(S.pcm_size);
    S.gfx_mask = wil_pow2_mask(S.gfx_size);

    const char *tag = (S.board == WIL_BOARD_TMS34010) ? "Midway TMS34010 GSP + DMA2" :
                      (S.sub == WIL_SUB_ROBOTRON)     ? "Robotron: 2084 (Williams Dual-6809 + SC1)" :
                      (S.sub == WIL_SUB_JOUST)        ? "Joust (Williams Dual-6809 + SC1)" :
                                                        "Williams Dual-6809 + Special Chip Blitter";
    int n = 0;
    for (; tag[n] && n < (int)sizeof(S.info) - 1; n++)
        S.info[n] = tag[n];
    S.info[n] = 0;
    return 0;
}

/* ============================================================================
   Lifecycle, Scanline Rendering & 48 kHz Frame Execution
   ============================================================================ */

void williams_reset(void)
{
    wil_zero(M->vram, sizeof(M->vram));
    wil_zero(M->snd_ram, sizeof(M->snd_ram));
    wil_zero(S.pia, sizeof(S.pia));
    wil_zero(S.blit_regs, sizeof(S.blit_regs));
    wil_zero(S.dma_regs, sizeof(S.dma_regs));
    wil_zero(S.oki, sizeof(S.oki));
    wil_zero(M->pal15, sizeof(M->pal15));
    wil_rebuild_pair15();

    S.vram_bank = 0;
    S.def_bank  = 0;
    S.dac_sample = 0;
    S.oki_cmd_latch = 0;
    S.pia[2].in_b = 0xFFu;
    S.snd_head = S.snd_tail = 0;
    S.jammed = 0;
    S.frame_no = 0;

    ym2151_init(&M->opm, 3579545u, S.sample_rate ? S.sample_rate : 48000u);

    if (S.board == WIL_BOARD_TMS34010) {
        wil_zero(&M->tms, sizeof(M->tms));
        wil_zero(M->gsp_vram, sizeof(M->gsp_vram));
        wil_zero(M->gsp_wram, sizeof(M->gsp_wram));
        wil_zero(M->gsp_pal_raw, sizeof(M->gsp_pal_raw));
        M->tms.st = 0x00000010u;                /* Default FS0 = 16 bits */
        M->tms.a[15] = 0x013FFFE0u;             /* SP top of WRAM */
        M->tms.io[0x01u] = 40;                  /* HEBLNK */
        M->tms.io[0x02u] = 440;                 /* HSBLNK (400 px) */
        M->tms.io[0x05u] = 16;                  /* VEBLNK */
        M->tms.io[0x06u] = 270;                 /* VSBLNK (254 lines) */
        M->tms.io[0x0Bu] = 254;                 /* DPYINT */
        M->tms.pc = tms_rl32(0xFFFFFFE0u);      /* TMS34010 Reset Vector ($FFFFFFE0) */
    } else {
        m6809_reset(&M->cpu_main, (void *)0);
    }

    if (S.srom_size > 0)
        m6809_reset(&M->cpu_snd, (void *)1);
}

const char *williams_load(const u8 *image, u32 size, const char *path)
{
    u32 keep_rate = S.sample_rate;
    if (keep_rate != 48000u && keep_rate != 44100u && keep_rate != 32000u && keep_rate != 22050u)
        keep_rate = 48000u;
    wil_zero(&S, sizeof(S));
    wil_zero(M->cmos, sizeof(M->cmos));
    S.sample_rate = keep_rate;

    if (!path || !*path || !image || size == 0) {
        S.board        = WIL_BOARD_BLITTER;
        S.sub          = WIL_SUB_GENERIC;
        S.blitter_xor  = 0;
        S.blitter_clip = 0xC000u;
        S.scr_w        = 304;
        S.scr_h        = 240;
        build_builtin_sprites_and_font();
        build_builtin_snd_rom();
        build_builtin_main_rom();
        S.rom_mask = 0xFFFFu;
        static const char bi[] = "Cybertron: 2084 (Built-in Williams Dual-MC6809E + Special Chip Blitter + DAC)";
        for (u32 i = 0; i < sizeof(bi); i++)
            S.info[i] = bi[i];
        williams_reset();
        return 0;
    }

    if (zip_is(image, size)) {
        const char *err = wil_load_zip(image, size, path);
        if (err) return err;
        williams_reset();
        return 0;
    }

    return "expected a Williams or Midway arcade .zip romset";
}

void williams_pad2(u16 pad)
{
    S.pad2 = pad;
}

static void wil_render_blitter_frame(u16 *picture)
{
    /* Ultra-fast 2-pixel u32 LUT scanout: 304x240 visible (y = 8..247 of 304x256 VRAM) */
    for (int ry = 0; ry < 240; ry++) {
        u32 vy = (u32)(ry + 8);
        u32 *dst32 = (u32 *)(picture + (u32)ry * 304u);
        for (u32 xb = 0; xb < 152u; xb++)
            dst32[xb] = M->pair15[M->vram[(xb << 8) | vy]];
    }
}

static void wil_render_tms_line(int y, u16 *dst)
{
    int w = S.scr_w;
    const u8 *src = &M->gsp_vram[(u32)(y & 511) * 512u];
    for (int x = 0; x < w; x++)
        dst[x] = M->pal15[src[x]];
}

void williams_frame(u16 pad, u16 *picture)
{
    S.pad1 = pad;
    u8 coin_now = (pad & 0x0004u) ? 1u : 0u;
    if (coin_now && !S.coin_prev)
        S.coin_pulse = 6u;
    S.coin_prev = coin_now;

    const int total_lines = 262;
    u32 target_samples = (S.sample_rate ? S.sample_rate : 48000u) / 60u;
    u32 samp_acc = 0;

    if (S.board == WIL_BOARD_TMS34010) {
        /* Midway TMS34010 GSP @ 6.25 MHz MIPS (~400 GSP cycles/line) + Sound 6809 */
        M->tms.cycles = 0;
        M->cpu_snd.cycles = 0;
        int dpyint = M->tms.io[0x0Bu] ? (int)M->tms.io[0x0Bu] : 254;

        for (int line = 0; line < total_lines; line++) {
            S.cur_scanline = line;
            tms_run((line + 1) * 420);

            if (S.srom_size > 0) {
                m6809_run(&M->cpu_snd, (line + 1) * 114);
                (void)ym2151_tick_timers(&M->opm, 114, 3579545u);
            }

            if (line < S.scr_h && picture)
                wil_render_tms_line(line, picture + (u32)line * (u32)S.scr_w);

            if (line == dpyint)
                M->tms.io[0x0Eu] |= 0x0400u;    /* Assert DIP (Display Interrupt Pending) */

            samp_acc += target_samples;
            while (samp_acc >= (u32)total_lines) {
                samp_acc -= (u32)total_lines;
                s32 fm_l = 0, fm_r = 0;
                ym2151_sample_48khz(&M->opm, &fm_l, &fm_r);
                s32 mix = ((fm_l + fm_r) >> 1) + oki6295_step_48k() + S.dac_sample;
                if (mix > 32767) mix = 32767;
                else if (mix < -32768) mix = -32768;
                if (S.snd_head - S.snd_tail < WIL_SND_RING)
                    M->snd_ring[S.snd_head++ & (WIL_SND_RING - 1u)] = (s16)mix;
            }
        }
    } else {
        /* Early Williams Dual MC6809E:
           Main 6809 @ 1.00 MHz (~64 cycles/scanline, 16,667/frame)
           Sound 6809 @ 0.895 MHz (~57 cycles/scanline, 14,915/frame) */
        M->cpu_main.cycles = 0;
        M->cpu_snd.cycles  = 0;

        for (int line = 0; line < 256; line++) {
            S.cur_scanline = line;
            m6809_run(&M->cpu_main, (line + 1) * 65);
            if (S.srom_size > 0)
                m6809_run(&M->cpu_snd, (line + 1) * 58);

            /* Williams 240 Hz VA11 Interrupt on PIA1 (lines 64, 128, 192, 240) */
            if (line == 64 || line == 128 || line == 192 || line == 240) {
                S.pia[1].cra |= 0x80u;
                S.pia[1].crb |= 0x80u;
                wil_update_pia_irqs();
            }

            samp_acc += target_samples;
            while (samp_acc >= 256u) {
                samp_acc -= 256u;
                if (S.snd_head - S.snd_tail < WIL_SND_RING)
                    M->snd_ring[S.snd_head++ & (WIL_SND_RING - 1u)] = S.dac_sample;
            }
        }

        if (picture)
            wil_render_blitter_frame(picture);
    }

    if (S.coin_pulse > 0)
        S.coin_pulse--;
    S.frame_no++;
}

int williams_width(void)  { return S.scr_w ? S.scr_w : 304; }
int williams_height(void) { return S.scr_h ? S.scr_h : 240; }
const char *williams_info(void) { return S.info; }

u8 *williams_save_ram(u32 *size, int *battery)
{
    if (S.board == WIL_BOARD_BLITTER && S.sub != WIL_SUB_GENERIC) {
        if (size) *size = sizeof(M->cmos);
        if (battery) *battery = 1;
        return M->cmos;
    }
    if (size) *size = 0;
    if (battery) *battery = 0;
    return 0;
}

int williams_save_changed(void)
{
    int d = S.nvram_dirty;
    S.nvram_dirty = 0;
    return d;
}

int williams_jammed(void) { return S.jammed; }

void williams_audio_rate(u32 hz)
{
    S.sample_rate = hz ? hz : 48000u;
    M->opm.sample_rate = S.sample_rate;
}

int williams_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && S.snd_tail != S.snd_head)
        out[n++] = M->snd_ring[S.snd_tail++ & (WIL_SND_RING - 1u)];
    return n;
}
