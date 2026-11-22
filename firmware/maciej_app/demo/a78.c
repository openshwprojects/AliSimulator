/* An Atari 7800 ProSystem (.a78): see a78.h. */
#pragma GCC optimize("O2")
#include "a78.h"

#ifdef A78_HOST
typedef unsigned long long u64;
#else
#include "hw.h"
#endif

#define INLINE static inline __attribute__((always_inline))

/* Clock & scanline geometry:
   Master clock = 7.15909 MHz (NTSC) / 7.09379 MHz (PAL)
   CPU clock    = 1.7897725 MHz (114 fast cycles / scanline = 456 MARIA clocks)
   NTSC: 262 lines (MARIA active 16..258, visible 20..243 = 224 lines)
   PAL:  312 lines (MARIA active 34..291, visible 38..277 = 240 lines) */
#define LINE_CPU_CYC      114
#define NTSC_TOTAL_LINES  262
#define NTSC_ACT_START    16
#define NTSC_ACT_END      259
#define NTSC_VIS_START    20

#define PAL_TOTAL_LINES   312
#define PAL_ACT_START     34
#define PAL_ACT_END       292
#define PAL_VIS_START     38

#define SND_RING          8192

/* 6502 status flags */
#define FN 0x80u
#define FV 0x40u
#define FB 0x10u
#define FD 0x08u
#define FI 0x04u
#define FZ 0x02u
#define FC 0x01u

/* Mapper types */
enum {
    MAP_LINEAR = 0,
    MAP_SUPERGAME,
    MAP_ACTIVISION,
    MAP_ABSOLUTE
};

struct a78_mem {
    u8 ram[0x1000];                      /* 4 KB system RAM ($1800..$27FF) */
    u8 cram[0x8000];                     /* Up to 32 KB cart RAM ($4000..$7FFF) */
    u8 hsram[0x800];                     /* 2 KB High-Score SRAM ($1000..$17FF, .sav) */
    u8 maria[0x40];                      /* MARIA registers ($0020..$003F) */
    u8 tia[0x20];                        /* TIA registers ($0000..$001F) */
    u16 pal_ntsc[256];                   /* 256-colour NTSC YIQ -> BGR555 palette */
    u16 pal_pal[256];                    /* 256-colour PAL  YUV -> BGR555 palette */
    u8 line_col[A78_W];                  /* 320-pixel MARIA scanline colour buffer */
    s16 snd_ring[SND_RING];              /* 48 kHz mono output ring */
};

#ifdef A78_HOST
static struct a78_mem a78_host_mem;
#define M (&a78_host_mem)
#else
#define M ((struct a78_mem *)KSEG0(EMU_RAM_PHYS))
#endif

static struct {
    const u8 *rom;
    u32 rom_size;

    /* SALLY 6502C CPU */
    u16 pc;
    u8 a, x, y, sp, p;
    s32 cyc;
    u8 nmi_pend, irq_pend, jammed;

    /* Cartridge configuration */
    u8 is_pal;
    u8 mapper;
    u8 has_cram;
    u8 has_exfix;
    u8 has_pokey_4000;
    u8 has_pokey_0450;
    u8 has_hsc_sram;
    u8 sg_bank;
    u8 act_bank;
    u8 abs_bank;
    u16 n_banks16;
    const u8 *page4[4];                  /* $4000, $8000, $C000 16 KB read pointers (idx 1..3) */

    /* 6532 RIOT I/O & timer */
    u8 swcha_out, swacnt, swchb_out, swbcnt;
    u8 riot_intim, riot_underflow;
    u16 riot_shift;
    s32 riot_sub;
    u16 pad;

    /* MARIA scanline / DLL state */
    u16 dpp;
    u16 dl_addr;
    u8 zone_off;
    u8 zone_dli;
    u8 zone_h16;
    u8 zone_h8;
    u8 in_vblank;
    u8 sticky_wm;

    /* TIA 2-channel polynomial audio */
    u8 audc[2], audf[2], audv[2];
    u32 tia_div[2], tia_p4[2], tia_p5[2], tia_p9[2];
    u8 tia_out[2];

    /* POKEY 4-channel audio ($4000 and/or $0450) */
    u8 pokey_audf[4], pokey_audc[4], pokey_audctl;
    u8 pokey_irqen, pokey_irqst, pokey_skctl;
    u32 pokey_cnt[4], pokey_out[4], pokey_lfsr17;

    /* 48 kHz output resampler */
    u32 snd_rate;
    u32 snd_phase;
    u32 snd_rd, snd_wr;
    s32 dc_est;
    u8  dma_was_on;

    int save_dirty;
    int pals_ready;
    char title[40];
    char info[128];
} S;

static void mem_zero(void *dst, u32 n)
{
    u8 *p = (u8 *)dst;
    for (u32 i = 0; i < n; i++)
        p[i] = 0;
}

/* ---- Atari 7800 256-colour NTSC & PAL palette generation (BGR555) ---- */
static void init_palettes(void)
{
    if (S.pals_ready)
        return;

    /* 16-entry hue phase unit vectors (cos, sin) in Q10 around the Atari colorburst wheel */
    static const s16 ntsc_i[16] = {
           0,  960,  760,  430,   50, -340, -690, -930,
       -1024, -930, -690, -340,   50,  430,  760,  960
    };
    static const s16 ntsc_q[16] = {
           0, -360, -680, -930,-1020, -940, -720, -390,
           0,  390,  720,  940, 1020,  930,  680,  360
    };
    /* Standard Atari 7800 hue angles: hue 0 = greyscale, hues 1..15 sweep gold->orange->red->purple->blue->green */
    static const u8 ntsc_map[16] = { 0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1 };
    static const u8 pal_map[16]  = { 0, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 2 };

    for (int mode = 0; mode < 2; mode++) {
        u16 *out = mode ? M->pal_pal : M->pal_ntsc;
        for (int c = 0; c < 256; c++) {
            int hue = (c >> 4) & 15;
            int lum = c & 15;
            s32 y = (lum * 255) / 15;
            s32 r = y, g = y, b = y;
            if (hue != 0) {
                int idx = mode ? pal_map[hue] : ntsc_map[hue];
                s32 ci = ntsc_i[idx];
                s32 cq = ntsc_q[idx];
                /* YIQ -> RGB (chroma amplitude ~ 72/255) */
                r = y + (( 98 * ci +  61 * cq) >> 10);
                g = y + ((-27 * ci -  64 * cq) >> 10);
                b = y + ((-109 * ci + 168 * cq) >> 10);
            }
            if (r < 0) r = 0; else if (r > 255) r = 255;
            if (g < 0) g = 0; else if (g > 255) g = 255;
            if (b < 0) b = 0; else if (b > 255) b = 255;
            out[c] = (u16)(((r >> 3) & 31) | (((g >> 3) & 31) << 5) | (((b >> 3) & 31) << 10));
        }
    }
    S.pals_ready = 1;
}

/* ---- Bank mapping ---- */
static void update_banks(void)
{
    const u8 *rom = S.rom;
    u32 sz = S.rom_size;
    S.page4[1] = 0;
    S.page4[2] = 0;
    S.page4[3] = 0;
    if (!rom || !sz)
        return;

    if (S.mapper == MAP_SUPERGAME && S.n_banks16 >= 2) {
        /* Last 16 KB fixed at $C000..$FFFF */
        S.page4[3] = rom + (u32)(S.n_banks16 - 1u) * 0x4000u;
        /* Switchable 16 KB at $8000..$BFFF */
        u16 b = S.sg_bank % S.n_banks16;
        if (S.n_banks16 == 9u) {
            /* 144 KB 9-bank SuperGame: page 0 fixed at $4000, banks 0..7 map to pages 1..8! */
            S.page4[1] = rom;
            S.page4[2] = rom + (u32)((S.sg_bank & 7u) + 1u) * 0x4000u;
        } else {
            S.page4[2] = rom + (u32)b * 0x4000u;
            if (S.has_exfix && !S.has_cram)
                S.page4[1] = rom + (u32)(S.n_banks16 - 2u) * 0x4000u;
        }
        return;
    }

    if (S.mapper == MAP_ABSOLUTE && sz >= 0x10000u) {
        /* 64 KB Absolute (F-18 Hornet): $4000..$7FFF switches bank 0 or 1; $8000..$FFFF fixed to upper 32 KB */
        S.page4[1] = rom + ((S.abs_bank == 2u) ? 0x4000u : 0u);
        S.page4[2] = rom + 0x8000u;
        S.page4[3] = rom + 0xC000u;
        return;
    }

    /* Linear 8K / 16K / 32K / 48K / 52K right-aligned to $FFFF */
    if (sz >= 0x4000u)
        S.page4[3] = rom + sz - 0x4000u;
    if (sz >= 0x8000u)
        S.page4[2] = rom + sz - 0x8000u;
    if (sz >= 0xC000u)
        S.page4[1] = rom + sz - 0xC000u;
}

/* ---- POKEY & TIA Audio ---- */
static void pokey_write(u32 off, u8 val)
{
    switch (off & 0xFu) {
    case 0x0: S.pokey_audf[0] = val; break;
    case 0x1: S.pokey_audc[0] = val; break;
    case 0x2: S.pokey_audf[1] = val; break;
    case 0x3: S.pokey_audc[1] = val; break;
    case 0x4: S.pokey_audf[2] = val; break;
    case 0x5: S.pokey_audc[2] = val; break;
    case 0x6: S.pokey_audf[3] = val; break;
    case 0x7: S.pokey_audc[3] = val; break;
    case 0x8: S.pokey_audctl  = val; break;
    case 0xE:
        S.pokey_irqen = val;
        S.pokey_irqst |= (u8)~val;
        break;
    case 0xF: S.pokey_skctl = val; break;
    default: break;
    }
}

static u8 pokey_read(u32 off)
{
    switch (off & 0xFu) {
    case 0xA: /* RANDOM */
        S.pokey_lfsr17 = (S.pokey_lfsr17 >> 1) | (((S.pokey_lfsr17 ^ (S.pokey_lfsr17 >> 5)) & 1u) << 16);
        return (u8)(S.pokey_lfsr17 & 0xFFu);
    case 0xE:
        return S.pokey_irqst;
    default:
        return 0xFFu;
    }
}

static void audio_step_line(void)
{
    /* Advance TIA (~31.4 kHz base = 2 ticks per scanline) & POKEY (64 kHz / 15 kHz base) */
    for (int t = 0; t < 2; t++) {
        for (int c = 0; c < 2; c++) {
            u8 ctrl = S.audc[c] & 0xFu;
            u8 vol  = S.audv[c] & 0xFu;
            if (ctrl == 0u || ctrl == 11u) {
                S.tia_out[c] = vol;
                continue;
            }
            if (++S.tia_div[c] > (u32)(S.audf[c] & 0x1Fu)) {
                S.tia_div[c] = 0;
                u32 b4 = ((S.tia_p4[c] >> 1) ^ S.tia_p4[c]) & 1u;
                S.tia_p4[c] = ((S.tia_p4[c] >> 1) | (b4 << 3)) & 0xFu;
                u32 b5 = ((S.tia_p5[c] >> 2) ^ S.tia_p5[c]) & 1u;
                S.tia_p5[c] = ((S.tia_p5[c] >> 1) | (b5 << 4)) & 0x1Fu;
                u32 b9 = ((S.tia_p9[c] >> 4) ^ S.tia_p9[c]) & 1u;
                S.tia_p9[c] = ((S.tia_p9[c] >> 1) | (b9 << 8)) & 0x1FFu;

                int high = 0;
                switch (ctrl) {
                case 1:  high = S.tia_p4[c] & 1; break;
                case 2:  high = (S.tia_p5[c] < 2u) ? (S.tia_p4[c] & 1) : 0; break;
                case 3:  high = (S.tia_p5[c] & 1) ? (S.tia_p4[c] & 1) : 0; break;
                case 4: case 5: high = !S.tia_out[c]; break;
                case 6: case 10: high = (S.tia_p5[c] & 0x1Fu) < 15u; break;
                case 7: case 9:  high = S.tia_p5[c] & 1; break;
                case 8:  high = S.tia_p9[c] & 1; break;
                default: high = (S.tia_p5[c] % 3u) == 0 ? !S.tia_out[c] : (S.tia_out[c] != 0); break;
                }
                S.tia_out[c] = high ? vol : 0u;
            }
        }
    }

    if (S.has_pokey_4000 || S.has_pokey_0450) {
        u32 base_ticks = (S.pokey_audctl & 0x01u) ? 1u : 4u; /* 15 kHz (~1/line) or 64 kHz (~4/line) */
        for (u32 t = 0; t < base_ticks; t++) {
            S.pokey_lfsr17 = (S.pokey_lfsr17 >> 1) | (((S.pokey_lfsr17 ^ (S.pokey_lfsr17 >> 5)) & 1u) << 16);
            for (int c = 0; c < 4; c++) {
                u32 reload = (u32)S.pokey_audf[c] + 1u;
                /* 16-bit linked ch0+ch1 or ch2+ch3 */
                if (c == 1 && (S.pokey_audctl & 0x10u))
                    reload = ((u32)S.pokey_audf[0] | ((u32)S.pokey_audf[1] << 8)) + 1u;
                if (c == 3 && (S.pokey_audctl & 0x08u))
                    reload = ((u32)S.pokey_audf[2] | ((u32)S.pokey_audf[3] << 8)) + 1u;
                /* 1.79 MHz clock on ch0 / ch2 scales reload down into 64 kHz units (~ /28) */
                if ((c == 0 && (S.pokey_audctl & 0x40u)) || (c == 2 && (S.pokey_audctl & 0x20u)) ||
                    (c == 1 && (S.pokey_audctl & 0x50u) == 0x50u) || (c == 3 && (S.pokey_audctl & 0x28u) == 0x28u)) {
                    reload = (reload > 28u) ? (reload / 28u) : 1u;
                }
                if (++S.pokey_cnt[c] >= reload) {
                    S.pokey_cnt[c] = 0;
                    if (S.pokey_audc[c] & 0x20u) /* pure tone */
                        S.pokey_out[c] ^= 1u;
                    else
                        S.pokey_out[c] = S.pokey_lfsr17 & 1u;
                }
            }
        }
    }

    if (!S.snd_rate)
        return;

    u32 rate_num = S.snd_rate * LINE_CPU_CYC;
    u32 clk_hz   = S.is_pal ? 1773447u : 1789772u;
    S.snd_phase += rate_num;
    if (S.snd_phase < clk_hz)
        return;

    s32 raw = ((s32)S.tia_out[0] + (s32)S.tia_out[1]) * 900;
    if (S.has_pokey_4000 || S.has_pokey_0450) {
        s32 psum = 0;
        for (int c = 0; c < 4; c++) {
            u8 ac = S.pokey_audc[c];
            s32 v = ac & 0xFu;
            if (ac & 0x10u)
                psum += v * 2;                   /* volume-only DAC */
            else if (v)
                psum += S.pokey_out[c] ? v : -(s32)v;
        }
        raw += psum * 420;
    }
    S.dc_est += ((raw << 8) - S.dc_est) >> 8;
    s32 mix = raw - (S.dc_est >> 8);
    if (mix >  32767) mix =  32767;
    if (mix < -32768) mix = -32768;

    while (S.snd_phase >= clk_hz) {
        S.snd_phase -= clk_hz;
        if (S.snd_wr - S.snd_rd < SND_RING) {
            M->snd_ring[S.snd_wr & (SND_RING - 1u)] = (s16)mix;
            S.snd_wr++;
        }
    }
}

/* ---- Memory Bus ($0000..$FFFF) ---- */
static u8 riot_read(u16 addr)
{
    switch (addr & 7u) {
    case 0: { /* SWCHA (active-low joystick directions) */
        u8 in = 0xFFu;
        if (S.pad & A78_PAD_RIGHT) in &= (u8)~0x80u;
        if (S.pad & A78_PAD_LEFT)  in &= (u8)~0x40u;
        if (S.pad & A78_PAD_DOWN)  in &= (u8)~0x20u;
        if (S.pad & A78_PAD_UP)    in &= (u8)~0x10u;
        return (u8)((in & ~S.swacnt) | (S.swcha_out & S.swacnt));
    }
    case 1: return S.swacnt;
    case 2: { /* SWCHB (Reset b0, Select b1, Pause b3 active-low; b2/b4/b5 latchable) */
        u8 sw = 0x3Bu;
        if (S.pad & A78_PAD_RESET)  sw &= (u8)~0x01u;
        if (S.pad & A78_PAD_SELECT) sw &= (u8)~0x02u;
        if (S.pad & A78_PAD_START)  sw &= (u8)~0x08u;
        return (u8)((sw & ~S.swbcnt) | (S.swchb_out & S.swbcnt));
    }
    case 3: return S.swbcnt;
    case 4: case 6:
        S.riot_underflow &= (u8)~0x40u;
        return S.riot_intim;
    case 5: case 7: {
        u8 st = S.riot_underflow;
        S.riot_underflow &= (u8)~0x40u;
        return st;
    }
    }
    return 0xFFu;
}

static void riot_write(u16 addr, u8 val)
{
    if (addr & 0x04u) {
        if (addr & 0x10u) {
            static const u16 sh[4] = { 0, 3, 6, 10 }; /* 1, 8, 64, 1024 */
            S.riot_intim = val;
            S.riot_shift = sh[addr & 3u];
            S.riot_sub   = (s32)(1u << S.riot_shift);
            S.riot_underflow = 0;
        }
        return;
    }
    switch (addr & 3u) {
    case 0: S.swcha_out = val; break;
    case 1: S.swacnt    = val; break;
    case 2: S.swchb_out = val; break;
    case 3: S.swbcnt    = val; break;
    }
}

static u8 bus_read(u16 addr)
{
    if (addr >= 0x4000u) {
        if (S.has_pokey_4000 && addr < 0x8000u && (addr & 0xFFF0u) == 0x4000u)
            return pokey_read(addr);
        if (S.mapper == MAP_ACTIVISION) {
            if (addr < 0xA000u) {
                /* $4000..$9FFF fixed pages from bank 6/7 */
                u32 off = (addr < 0x6000u) ? (0x18000u + (addr - 0x4000u) + 0x2000u)
                        : (addr < 0x8000u) ? (0x18000u + (addr - 0x6000u))
                                           : (0x1C000u + (addr - 0x8000u));
                return (off < S.rom_size) ? S.rom[off] : 0xFFu;
            }
            if (addr < 0xE000u) {
                u32 off = (u32)(S.act_bank & 7u) * 0x4000u + (addr - 0xA000u);
                return (off < S.rom_size) ? S.rom[off] : 0xFFu;
            }
            u32 off = 0x1E000u + (addr - 0xE000u);
            return (off < S.rom_size) ? S.rom[off] : 0xFFu;
        }
        if (addr < 0x8000u && S.has_cram)
            return M->cram[addr - 0x4000u];
        if (addr >= 0xC000u && S.mapper == MAP_LINEAR && S.rom_size < 0x4000u && S.rom_size > 0u)
            return S.rom[(addr - 0xC000u) % S.rom_size];
        const u8 *pg = S.page4[addr >> 14];
        return pg ? pg[addr & 0x3FFFu] : 0xFFu;
    }

    /* $2000..$3FFF: 2 KB RAM1 ($1800+0x800) mirrored across $2000..$3FFF (unless 52K cart has $3000..$3FFF) */
    if (addr >= 0x2000u) {
        if (addr >= 0x3000u && S.mapper == MAP_LINEAR && S.rom_size >= 0xD000u)
            return S.rom[addr - 0x3000u];
        return M->ram[0x800u | (addr & 0x7FFu)];
    }
    if (addr >= 0x1800u)
        return M->ram[addr - 0x1800u];
    if (addr >= 0x1000u)
        return S.has_hsc_sram ? M->hsram[addr & 0x7FFu] : 0xFFu;
    if (S.has_pokey_0450 && (addr & 0xFFF0u) == 0x0450u)
        return pokey_read(addr);
    /* YM2151 ($0460..$0461): status bit 7 = 0 (ready / not busy) */
    if ((addr & 0xFFF0u) == 0x0460u)
        return 0x00u;
    /* $0400..$0FFF is cartridge / XM expansion space, NEVER mirrored to TIA/MARIA! */
    if (addr >= 0x0400u)
        return 0xFFu;
    if ((addr & 0xFF80u) == 0x0280u)
        return riot_read(addr);

    /* $0040..$00FF mirrors $2040..$20FF; $0140..$01FF mirrors $2140..$21FF */
    if ((addr >= 0x0040u && addr <= 0x00FFu) || (addr >= 0x0140u && addr <= 0x01FFu))
        return M->ram[0x800u | (addr & 0x1FFu)];

    /* TIA ($00..$1F) & MARIA ($20..$3F) mirrored at $0100..$013F / $0200..$023F / $0300..$033F */
    u16 low = addr & 0x3Fu;
    if (low < 0x20u) {
        u8 u = (u8)(low & 0x0Fu);
        /* ProLine 2-button / 1-button joystick circuit:
           When SWBCNT bit 2 = 1 and SWCHB bit 2 = 0 (2-button mode active for P0):
             INPT0 ($08) b7 = 1 when Fire 2 (PAD_B) held
             INPT1 ($09) b7 = 1 when Fire 1 (PAD_A) held
           INPT4 ($0C) b7 = 0 when either Fire 1 or Fire 2 held (active low!) */
        int two_btn = (S.swbcnt & 0x04u) && !(S.swchb_out & 0x04u);
        if (u == 0x08u) return (two_btn && (S.pad & A78_PAD_B)) ? 0x80u : 0x00u;
        if (u == 0x09u) return (two_btn && (S.pad & A78_PAD_A)) ? 0x80u : 0x00u;
        if (u == 0x0Au || u == 0x0Bu) return 0x00u;
        if (u == 0x0Cu) return (S.pad & (A78_PAD_A | A78_PAD_B)) ? 0x00u : 0x80u;
        if (u == 0x0Du) return 0x80u;
        return 0x00u;
    }
    /* MARIA read: $28 (and odd/even mirrors, specifically $28) returns MSTAT (b7 = VBLANK) */
    if ((low & 0x07u) == 0u && low >= 0x28u)
        return S.in_vblank ? 0x80u : 0x00u;
    return M->maria[low - 0x20u];
}

static void bus_write(u16 addr, u8 val)
{
    if (addr >= 0x4000u) {
        if (S.has_pokey_4000 && addr < 0x8000u && (addr & 0xFFF0u) == 0x4000u) {
            pokey_write(addr, val);
            return;
        }
        if (S.mapper == MAP_ACTIVISION && (addr & 0xFFF8u) == 0xFF80u) {
            S.act_bank = (u8)(addr & 7u);
            return;
        }
        if (S.mapper == MAP_ABSOLUTE && addr == 0x8000u) {
            S.abs_bank = val;
            update_banks();
            return;
        }
        if (addr < 0x8000u && S.has_cram) {
            M->cram[addr - 0x4000u] = val;
            return;
        }
        if (S.mapper == MAP_SUPERGAME && addr >= 0x8000u && addr < 0xC000u) {
            S.sg_bank = val;
            update_banks();
            return;
        }
        return;
    }

    if (addr >= 0x2000u) {
        if (addr < 0x3000u || S.mapper != MAP_LINEAR || S.rom_size < 0xD000u)
            M->ram[0x800u | (addr & 0x7FFu)] = val;
        return;
    }
    if (addr >= 0x1800u) {
        M->ram[addr - 0x1800u] = val;
        return;
    }
    if (addr >= 0x1000u) {
        if (S.has_hsc_sram && M->hsram[addr & 0x7FFu] != val) {
            M->hsram[addr & 0x7FFu] = val;
            S.save_dirty = 1;
        }
        return;
    }
    if (S.has_pokey_0450 && (addr & 0xFFF0u) == 0x0450u) {
        pokey_write(addr, val);
        return;
    }
    /* $0400..$0FFF is cartridge / XM expansion space, NEVER mirrored to TIA/MARIA! */
    if (addr >= 0x0400u)
        return;
    if ((addr & 0xFF80u) == 0x0280u) {
        riot_write(addr, val);
        return;
    }
    if ((addr >= 0x0040u && addr <= 0x00FFu) || (addr >= 0x0140u && addr <= 0x01FFu)) {
        M->ram[0x800u | (addr & 0x1FFu)] = val;
        return;
    }

    u16 low = addr & 0x3Fu;
    if (low < 0x20u) {
        M->tia[low] = val;
        switch (low) {
        case 0x02: S.cyc = 0; break; /* TIA WSYNC */
        case 0x15: S.audc[0] = val; break;
        case 0x16: S.audc[1] = val; break;
        case 0x17: S.audf[0] = val; break;
        case 0x18: S.audf[1] = val; break;
        case 0x19: S.audv[0] = val; break;
        case 0x1A: S.audv[1] = val; break;
        }
        return;
    }
    if (low == 0x32u) { /* WSYNC ($24 / $32 / $24? Wait: on MARIA, WSYNC is $24!) */
        /* Handled below */
    }
    if (low == 0x24u) { /* MARIA WSYNC: halts SALLY until end of current scanline! */
        S.cyc = 0;
        return;
    }
    M->maria[low - 0x20u] = val;
}

/* ---- SALLY 6502C CPU ---- */
INLINE void set_nz(u8 v)
{
    S.p = (u8)((S.p & ~(FN | FZ)) | (v & FN) | (v == 0 ? FZ : 0u));
}

INLINE void push8(u8 v)
{
    M->ram[0x900u | S.sp] = v;
    S.sp--;
}

INLINE u8 pull8(void)
{
    S.sp++;
    return M->ram[0x900u | S.sp];
}

INLINE void push16(u16 v)
{
    push8((u8)(v >> 8));
    push8((u8)v);
}

INLINE u16 pull16(void)
{
    u16 lo = pull8();
    return (u16)(lo | ((u16)pull8() << 8));
}

INLINE u16 rd16_zp(u8 zp)
{
    return (u16)bus_read(zp) | ((u16)bus_read((u8)(zp + 1u)) << 8);
}

INLINE u16 rd16_abs(u16 a)
{
    return (u16)bus_read(a) | ((u16)bus_read((u16)(a + 1u)) << 8);
}

static void adc6502(u8 v)
{
    u32 c = S.p & FC;
    if (S.p & FD) {
        u32 lo = (S.a & 0x0Fu) + (v & 0x0Fu) + c;
        u32 hi = (S.a & 0xF0u) + (v & 0xF0u);
        if (lo > 0x09u) { lo += 0x06u; hi += 0x10u; }
        u32 bin = (u32)S.a + (u32)v + c;
        u8 z = ((bin & 0xFFu) == 0) ? FZ : 0u;
        u8 n = (hi & 0x80u) ? FN : 0u;
        u8 ov = ((~(S.a ^ v) & (S.a ^ hi)) & 0x80u) ? FV : 0u;
        if (hi > 0x90u) hi += 0x60u;
        S.a = (u8)((hi & 0xF0u) | (lo & 0x0Fu));
        S.p = (u8)((S.p & ~(FN | FV | FZ | FC)) | n | ov | z | (hi > 0xFFu ? FC : 0u));
    } else {
        u32 sum = (u32)S.a + (u32)v + c;
        u8 ov = ((~(S.a ^ v) & (S.a ^ sum)) & 0x80u) ? FV : 0u;
        S.a = (u8)sum;
        S.p = (u8)((S.p & ~(FN | FV | FZ | FC)) | (S.a & FN) | (S.a == 0 ? FZ : 0u) | ov | (sum > 0xFFu ? FC : 0u));
    }
}

static void sbc6502(u8 v)
{
    u32 c = S.p & FC;
    u32 diff = (u32)S.a - (u32)v - (1u - c);
    u8 ov = (((S.a ^ v) & (S.a ^ diff)) & 0x80u) ? FV : 0u;
    if (S.p & FD) {
        s32 lo = (s32)(S.a & 0x0Fu) - (s32)(v & 0x0Fu) - (s32)(1u - c);
        s32 hi = (s32)(S.a >> 4) - (s32)(v >> 4);
        if (lo < 0) { lo -= 6; hi--; }
        if (hi < 0) hi -= 6;
        S.a = (u8)(((u32)(hi & 0xFu) << 4) | (u32)(lo & 0xFu));
    } else {
        S.a = (u8)diff;
    }
    u8 res8 = (u8)diff;
    S.p = (u8)((S.p & ~(FN | FV | FZ | FC)) | (res8 & FN) | (res8 == 0 ? FZ : 0u) | ov | (diff < 0x100u ? FC : 0u));
}

INLINE void cmp6502(u8 r, u8 v)
{
    u16 d = (u16)r - (u16)v;
    S.p = (u8)((S.p & ~(FN | FZ | FC)) | (d & FN) | ((d & 0xFFu) == 0 ? FZ : 0u) | (r >= v ? FC : 0u));
}

INLINE void branch6502(int cond)
{
    s8 rel = (s8)bus_read(S.pc++);
    if (cond) {
        u16 old = S.pc;
        S.pc = (u16)(S.pc + rel);
        S.cyc -= ((old ^ S.pc) & 0xFF00u) ? 2 : 1;
    }
}

static void step_6502(void)
{
    if (S.nmi_pend) {
        S.nmi_pend = 0;
        push16(S.pc);
        push8((u8)((S.p & ~FB) | 0x20u));
        S.p |= FI;
        S.pc = rd16_abs(0xFFFAu);
        S.cyc -= 7;
        return;
    }
    if (S.irq_pend && !(S.p & FI)) {
        push16(S.pc);
        push8((u8)((S.p & ~FB) | 0x20u));
        S.p |= FI;
        S.pc = rd16_abs(0xFFFEu);
        S.cyc -= 7;
        return;
    }

    u8 op = bus_read(S.pc++);
    u16 addr;
    u8 v;

    switch (op) {
    case 0x00: /* BRK */
        S.pc++;
        push16(S.pc);
        push8((u8)(S.p | FB | 0x20u));
        S.p |= FI;
        S.pc = rd16_abs(0xFFFEu);
        S.cyc -= 7;
        break;

    /* ORA */
    case 0x09: S.a |= bus_read(S.pc++); set_nz(S.a); S.cyc -= 2; break;
    case 0x05: S.a |= bus_read(bus_read(S.pc++)); set_nz(S.a); S.cyc -= 3; break;
    case 0x15: S.a |= bus_read((u8)(bus_read(S.pc++) + S.x)); set_nz(S.a); S.cyc -= 4; break;
    case 0x0D: S.a |= bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x1D: S.a |= bus_read((u16)(rd16_abs(S.pc) + S.x)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x19: S.a |= bus_read((u16)(rd16_abs(S.pc) + S.y)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x01: S.a |= bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x))); set_nz(S.a); S.cyc -= 6; break;
    case 0x11: S.a |= bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y)); set_nz(S.a); S.cyc -= 5; break;

    /* AND */
    case 0x29: S.a &= bus_read(S.pc++); set_nz(S.a); S.cyc -= 2; break;
    case 0x25: S.a &= bus_read(bus_read(S.pc++)); set_nz(S.a); S.cyc -= 3; break;
    case 0x35: S.a &= bus_read((u8)(bus_read(S.pc++) + S.x)); set_nz(S.a); S.cyc -= 4; break;
    case 0x2D: S.a &= bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x3D: S.a &= bus_read((u16)(rd16_abs(S.pc) + S.x)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x39: S.a &= bus_read((u16)(rd16_abs(S.pc) + S.y)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x21: S.a &= bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x))); set_nz(S.a); S.cyc -= 6; break;
    case 0x31: S.a &= bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y)); set_nz(S.a); S.cyc -= 5; break;

    /* EOR */
    case 0x49: S.a ^= bus_read(S.pc++); set_nz(S.a); S.cyc -= 2; break;
    case 0x45: S.a ^= bus_read(bus_read(S.pc++)); set_nz(S.a); S.cyc -= 3; break;
    case 0x55: S.a ^= bus_read((u8)(bus_read(S.pc++) + S.x)); set_nz(S.a); S.cyc -= 4; break;
    case 0x4D: S.a ^= bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x5D: S.a ^= bus_read((u16)(rd16_abs(S.pc) + S.x)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x59: S.a ^= bus_read((u16)(rd16_abs(S.pc) + S.y)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x41: S.a ^= bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x))); set_nz(S.a); S.cyc -= 6; break;
    case 0x51: S.a ^= bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y)); set_nz(S.a); S.cyc -= 5; break;

    /* ADC */
    case 0x69: adc6502(bus_read(S.pc++)); S.cyc -= 2; break;
    case 0x65: adc6502(bus_read(bus_read(S.pc++))); S.cyc -= 3; break;
    case 0x75: adc6502(bus_read((u8)(bus_read(S.pc++) + S.x))); S.cyc -= 4; break;
    case 0x6D: adc6502(bus_read(rd16_abs(S.pc))); S.pc += 2; S.cyc -= 4; break;
    case 0x7D: adc6502(bus_read((u16)(rd16_abs(S.pc) + S.x))); S.pc += 2; S.cyc -= 4; break;
    case 0x79: adc6502(bus_read((u16)(rd16_abs(S.pc) + S.y))); S.pc += 2; S.cyc -= 4; break;
    case 0x61: adc6502(bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x)))); S.cyc -= 6; break;
    case 0x71: adc6502(bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y))); S.cyc -= 5; break;

    /* SBC */
    case 0xE9: case 0xEB: sbc6502(bus_read(S.pc++)); S.cyc -= 2; break;
    case 0xE5: sbc6502(bus_read(bus_read(S.pc++))); S.cyc -= 3; break;
    case 0xF5: sbc6502(bus_read((u8)(bus_read(S.pc++) + S.x))); S.cyc -= 4; break;
    case 0xED: sbc6502(bus_read(rd16_abs(S.pc))); S.pc += 2; S.cyc -= 4; break;
    case 0xFD: sbc6502(bus_read((u16)(rd16_abs(S.pc) + S.x))); S.pc += 2; S.cyc -= 4; break;
    case 0xF9: sbc6502(bus_read((u16)(rd16_abs(S.pc) + S.y))); S.pc += 2; S.cyc -= 4; break;
    case 0xE1: sbc6502(bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x)))); S.cyc -= 6; break;
    case 0xF1: sbc6502(bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y))); S.cyc -= 5; break;

    /* CMP / CPX / CPY */
    case 0xC9: cmp6502(S.a, bus_read(S.pc++)); S.cyc -= 2; break;
    case 0xC5: cmp6502(S.a, bus_read(bus_read(S.pc++))); S.cyc -= 3; break;
    case 0xD5: cmp6502(S.a, bus_read((u8)(bus_read(S.pc++) + S.x))); S.cyc -= 4; break;
    case 0xCD: cmp6502(S.a, bus_read(rd16_abs(S.pc))); S.pc += 2; S.cyc -= 4; break;
    case 0xDD: cmp6502(S.a, bus_read((u16)(rd16_abs(S.pc) + S.x))); S.pc += 2; S.cyc -= 4; break;
    case 0xD9: cmp6502(S.a, bus_read((u16)(rd16_abs(S.pc) + S.y))); S.pc += 2; S.cyc -= 4; break;
    case 0xC1: cmp6502(S.a, bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x)))); S.cyc -= 6; break;
    case 0xD1: cmp6502(S.a, bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y))); S.cyc -= 5; break;

    case 0xE0: cmp6502(S.x, bus_read(S.pc++)); S.cyc -= 2; break;
    case 0xE4: cmp6502(S.x, bus_read(bus_read(S.pc++))); S.cyc -= 3; break;
    case 0xEC: cmp6502(S.x, bus_read(rd16_abs(S.pc))); S.pc += 2; S.cyc -= 4; break;

    case 0xC0: cmp6502(S.y, bus_read(S.pc++)); S.cyc -= 2; break;
    case 0xC4: cmp6502(S.y, bus_read(bus_read(S.pc++))); S.cyc -= 3; break;
    case 0xCC: cmp6502(S.y, bus_read(rd16_abs(S.pc))); S.pc += 2; S.cyc -= 4; break;

    /* BIT */
    case 0x24: v = bus_read(bus_read(S.pc++)); S.p = (u8)((S.p & ~(FN | FV | FZ)) | (v & (FN | FV)) | ((S.a & v) == 0 ? FZ : 0u)); S.cyc -= 3; break;
    case 0x2C: v = bus_read(rd16_abs(S.pc)); S.pc += 2; S.p = (u8)((S.p & ~(FN | FV | FZ)) | (v & (FN | FV)) | ((S.a & v) == 0 ? FZ : 0u)); S.cyc -= 4; break;

    /* LDA / LDX / LDY */
    case 0xA9: S.a = bus_read(S.pc++); set_nz(S.a); S.cyc -= 2; break;
    case 0xA5: S.a = bus_read(bus_read(S.pc++)); set_nz(S.a); S.cyc -= 3; break;
    case 0xB5: S.a = bus_read((u8)(bus_read(S.pc++) + S.x)); set_nz(S.a); S.cyc -= 4; break;
    case 0xAD: S.a = bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0xBD: S.a = bus_read((u16)(rd16_abs(S.pc) + S.x)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0xB9: S.a = bus_read((u16)(rd16_abs(S.pc) + S.y)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0xA1: S.a = bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x))); set_nz(S.a); S.cyc -= 6; break;
    case 0xB1: S.a = bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y)); set_nz(S.a); S.cyc -= 5; break;

    case 0xA2: S.x = bus_read(S.pc++); set_nz(S.x); S.cyc -= 2; break;
    case 0xA6: S.x = bus_read(bus_read(S.pc++)); set_nz(S.x); S.cyc -= 3; break;
    case 0xB6: S.x = bus_read((u8)(bus_read(S.pc++) + S.y)); set_nz(S.x); S.cyc -= 4; break;
    case 0xAE: S.x = bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.x); S.cyc -= 4; break;
    case 0xBE: S.x = bus_read((u16)(rd16_abs(S.pc) + S.y)); S.pc += 2; set_nz(S.x); S.cyc -= 4; break;

    case 0xA0: S.y = bus_read(S.pc++); set_nz(S.y); S.cyc -= 2; break;
    case 0xA4: S.y = bus_read(bus_read(S.pc++)); set_nz(S.y); S.cyc -= 3; break;
    case 0xB4: S.y = bus_read((u8)(bus_read(S.pc++) + S.x)); set_nz(S.y); S.cyc -= 4; break;
    case 0xAC: S.y = bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.y); S.cyc -= 4; break;
    case 0xBC: S.y = bus_read((u16)(rd16_abs(S.pc) + S.x)); S.pc += 2; set_nz(S.y); S.cyc -= 4; break;

    /* STA / STX / STY */
    case 0x85: bus_write(bus_read(S.pc++), S.a); S.cyc -= 3; break;
    case 0x95: bus_write((u8)(bus_read(S.pc++) + S.x), S.a); S.cyc -= 4; break;
    case 0x8D: bus_write(rd16_abs(S.pc), S.a); S.pc += 2; S.cyc -= 4; break;
    case 0x9D: bus_write((u16)(rd16_abs(S.pc) + S.x), S.a); S.pc += 2; S.cyc -= 5; break;
    case 0x99: bus_write((u16)(rd16_abs(S.pc) + S.y), S.a); S.pc += 2; S.cyc -= 5; break;
    case 0x81: bus_write(rd16_zp((u8)(bus_read(S.pc++) + S.x)), S.a); S.cyc -= 6; break;
    case 0x91: bus_write((u16)(rd16_zp(bus_read(S.pc++)) + S.y), S.a); S.cyc -= 6; break;

    case 0x86: bus_write(bus_read(S.pc++), S.x); S.cyc -= 3; break;
    case 0x96: bus_write((u8)(bus_read(S.pc++) + S.y), S.x); S.cyc -= 4; break;
    case 0x8E: bus_write(rd16_abs(S.pc), S.x); S.pc += 2; S.cyc -= 4; break;

    case 0x84: bus_write(bus_read(S.pc++), S.y); S.cyc -= 3; break;
    case 0x94: bus_write((u8)(bus_read(S.pc++) + S.x), S.y); S.cyc -= 4; break;
    case 0x8C: bus_write(rd16_abs(S.pc), S.y); S.pc += 2; S.cyc -= 4; break;

    /* Shifts & Rotates */
    case 0x0A: S.p = (u8)((S.p & ~FC) | (S.a >> 7)); S.a <<= 1; set_nz(S.a); S.cyc -= 2; break;
    case 0x06: addr = bus_read(S.pc++); goto do_asl;
    case 0x16: addr = (u8)(bus_read(S.pc++) + S.x); goto do_asl;
    case 0x0E: addr = rd16_abs(S.pc); S.pc += 2; goto do_asl;
    case 0x1E: addr = (u16)(rd16_abs(S.pc) + S.x); S.pc += 2; do_asl:
        v = bus_read(addr); S.p = (u8)((S.p & ~FC) | (v >> 7)); v <<= 1; bus_write(addr, v); set_nz(v); S.cyc -= 6; break;

    case 0x4A: S.p = (u8)((S.p & ~FC) | (S.a & 1u)); S.a >>= 1; set_nz(S.a); S.cyc -= 2; break;
    case 0x46: addr = bus_read(S.pc++); goto do_lsr;
    case 0x56: addr = (u8)(bus_read(S.pc++) + S.x); goto do_lsr;
    case 0x4E: addr = rd16_abs(S.pc); S.pc += 2; goto do_lsr;
    case 0x5E: addr = (u16)(rd16_abs(S.pc) + S.x); S.pc += 2; do_lsr:
        v = bus_read(addr); S.p = (u8)((S.p & ~FC) | (v & 1u)); v >>= 1; bus_write(addr, v); set_nz(v); S.cyc -= 6; break;

    case 0x2A: { u8 c = S.p & FC; S.p = (u8)((S.p & ~FC) | (S.a >> 7)); S.a = (u8)((S.a << 1) | c); set_nz(S.a); S.cyc -= 2; break; }
    case 0x26: addr = bus_read(S.pc++); goto do_rol;
    case 0x36: addr = (u8)(bus_read(S.pc++) + S.x); goto do_rol;
    case 0x2E: addr = rd16_abs(S.pc); S.pc += 2; goto do_rol;
    case 0x3E: addr = (u16)(rd16_abs(S.pc) + S.x); S.pc += 2; do_rol:
        { u8 c = S.p & FC; v = bus_read(addr); S.p = (u8)((S.p & ~FC) | (v >> 7)); v = (u8)((v << 1) | c); bus_write(addr, v); set_nz(v); S.cyc -= 6; break; }

    case 0x6A: { u8 c = (u8)((S.p & FC) << 7); S.p = (u8)((S.p & ~FC) | (S.a & 1u)); S.a = (u8)((S.a >> 1) | c); set_nz(S.a); S.cyc -= 2; break; }
    case 0x66: addr = bus_read(S.pc++); goto do_ror;
    case 0x76: addr = (u8)(bus_read(S.pc++) + S.x); goto do_ror;
    case 0x6E: addr = rd16_abs(S.pc); S.pc += 2; goto do_ror;
    case 0x7E: addr = (u16)(rd16_abs(S.pc) + S.x); S.pc += 2; do_ror:
        { u8 c = (u8)((S.p & FC) << 7); v = bus_read(addr); S.p = (u8)((S.p & ~FC) | (v & 1u)); v = (u8)((v >> 1) | c); bus_write(addr, v); set_nz(v); S.cyc -= 6; break; }

    /* INC / DEC */
    case 0xE6: addr = bus_read(S.pc++); goto do_inc;
    case 0xF6: addr = (u8)(bus_read(S.pc++) + S.x); goto do_inc;
    case 0xEE: addr = rd16_abs(S.pc); S.pc += 2; goto do_inc;
    case 0xFE: addr = (u16)(rd16_abs(S.pc) + S.x); S.pc += 2; do_inc:
        v = (u8)(bus_read(addr) + 1u); bus_write(addr, v); set_nz(v); S.cyc -= 6; break;

    case 0xC6: addr = bus_read(S.pc++); goto do_dec;
    case 0xD6: addr = (u8)(bus_read(S.pc++) + S.x); goto do_dec;
    case 0xCE: addr = rd16_abs(S.pc); S.pc += 2; goto do_dec;
    case 0xDE: addr = (u16)(rd16_abs(S.pc) + S.x); S.pc += 2; do_dec:
        v = (u8)(bus_read(addr) - 1u); bus_write(addr, v); set_nz(v); S.cyc -= 6; break;

    case 0xE8: S.x++; set_nz(S.x); S.cyc -= 2; break;
    case 0xCA: S.x--; set_nz(S.x); S.cyc -= 2; break;
    case 0xC8: S.y++; set_nz(S.y); S.cyc -= 2; break;
    case 0x88: S.y--; set_nz(S.y); S.cyc -= 2; break;

    /* Transfers & Stack */
    case 0xAA: S.x = S.a; set_nz(S.x); S.cyc -= 2; break;
    case 0x8A: S.a = S.x; set_nz(S.a); S.cyc -= 2; break;
    case 0xA8: S.y = S.a; set_nz(S.y); S.cyc -= 2; break;
    case 0x98: S.a = S.y; set_nz(S.a); S.cyc -= 2; break;
    case 0xBA: S.x = S.sp; set_nz(S.x); S.cyc -= 2; break;
    case 0x9A: S.sp = S.x; S.cyc -= 2; break;

    case 0x48: push8(S.a); S.cyc -= 3; break;
    case 0x68: S.a = pull8(); set_nz(S.a); S.cyc -= 4; break;
    case 0x08: push8((u8)(S.p | FB | 0x20u)); S.cyc -= 3; break;
    case 0x28: S.p = (u8)((pull8() & ~FB) | 0x20u); S.cyc -= 4; break;

    /* Branches */
    case 0x10: branch6502(!(S.p & FN)); S.cyc -= 2; break;
    case 0x30: branch6502( (S.p & FN)); S.cyc -= 2; break;
    case 0x50: branch6502(!(S.p & FV)); S.cyc -= 2; break;
    case 0x70: branch6502( (S.p & FV)); S.cyc -= 2; break;
    case 0x90: branch6502(!(S.p & FC)); S.cyc -= 2; break;
    case 0xB0: branch6502( (S.p & FC)); S.cyc -= 2; break;
    case 0xD0: branch6502(!(S.p & FZ)); S.cyc -= 2; break;
    case 0xF0: branch6502( (S.p & FZ)); S.cyc -= 2; break;

    /* Jumps & Subroutines */
    case 0x4C: S.pc = rd16_abs(S.pc); S.cyc -= 3; break;
    case 0x6C: {
        u16 ptr = rd16_abs(S.pc);
        u16 hi_addr = (u16)((ptr & 0xFF00u) | ((ptr + 1u) & 0x00FFu)); /* NMOS 6502 page-wrap bug */
        S.pc = (u16)(bus_read(ptr) | ((u16)bus_read(hi_addr) << 8));
        S.cyc -= 5;
        break;
    }
    case 0x20: {
        u16 dst = rd16_abs(S.pc);
        push16((u16)(S.pc + 1u));
        S.pc = dst;
        S.cyc -= 6;
        break;
    }
    case 0x60: S.pc = (u16)(pull16() + 1u); S.cyc -= 6; break;
    case 0x40: S.p = (u8)((pull8() & ~FB) | 0x20u); S.pc = pull16(); S.cyc -= 6; break;

    /* Flags */
    case 0x18: S.p &= (u8)~FC; S.cyc -= 2; break;
    case 0x38: S.p |= FC;      S.cyc -= 2; break;
    case 0x58: S.p &= (u8)~FI; S.cyc -= 2; break;
    case 0x78: S.p |= FI;      S.cyc -= 2; break;
    case 0xB8: S.p &= (u8)~FV; S.cyc -= 2; break;
    case 0xD8: S.p &= (u8)~FD; S.cyc -= 2; break;
    case 0xF8: S.p |= FD;      S.cyc -= 2; break;

    /* Common undocumented NMOS 6502 opcodes (LAX, SAX, DCP, ISC, ALR, ANC, SBX, NOPs) */
    case 0xA7: S.a = S.x = bus_read(bus_read(S.pc++)); set_nz(S.a); S.cyc -= 3; break;
    case 0xB7: S.a = S.x = bus_read((u8)(bus_read(S.pc++) + S.y)); set_nz(S.a); S.cyc -= 4; break;
    case 0xAF: S.a = S.x = bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0xBF: S.a = S.x = bus_read((u16)(rd16_abs(S.pc) + S.y)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0xA3: S.a = S.x = bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x))); set_nz(S.a); S.cyc -= 6; break;
    case 0xB3: S.a = S.x = bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y)); set_nz(S.a); S.cyc -= 5; break;

    case 0x87: bus_write(bus_read(S.pc++), (u8)(S.a & S.x)); S.cyc -= 3; break;
    case 0x97: bus_write((u8)(bus_read(S.pc++) + S.y), (u8)(S.a & S.x)); S.cyc -= 4; break;
    case 0x8F: bus_write(rd16_abs(S.pc), (u8)(S.a & S.x)); S.pc += 2; S.cyc -= 4; break;
    case 0x83: bus_write(rd16_zp((u8)(bus_read(S.pc++) + S.x)), (u8)(S.a & S.x)); S.cyc -= 6; break;

    case 0x4B: S.a &= bus_read(S.pc++); S.p = (u8)((S.p & ~FC) | (S.a & 1u)); S.a >>= 1; set_nz(S.a); S.cyc -= 2; break;
    case 0x0B: case 0x2B: S.a &= bus_read(S.pc++); set_nz(S.a); S.p = (u8)((S.p & ~FC) | (S.a >> 7)); S.cyc -= 2; break;
    case 0xCB: { u8 imm = bus_read(S.pc++); u8 ax = (u8)(S.a & S.x); cmp6502(ax, imm); S.x = (u8)(ax - imm); S.cyc -= 2; break; }

    case 0x04: case 0x44: case 0x64:
    case 0x80: case 0x82: case 0x89: case 0xC2: case 0xE2:
    case 0x14: case 0x34: case 0x54: case 0x74: case 0xD4: case 0xF4:
        S.pc++; S.cyc -= 3; break;
    case 0x0C: case 0x1C: case 0x3C: case 0x5C: case 0x7C: case 0xDC: case 0xFC:
        S.pc += 2; S.cyc -= 4; break;

    case 0x02: case 0x12: case 0x22: case 0x32: case 0x42: case 0x52:
    case 0x62: case 0x72: case 0x92: case 0xB2: case 0xD2: case 0xF2:
        S.jammed = 1; S.pc--; S.cyc = 0; break;

    default: /* NOPs & remaining unofficials */
        S.cyc -= 2;
        break;
    }
}

static void riot_step(s32 cyc)
{
    if (cyc <= 0)
        return;
    S.riot_sub -= cyc;
    while (S.riot_sub <= 0) {
        if (S.riot_intim == 0) {
            S.riot_intim = 0xFFu;
            S.riot_underflow = 0xC0u;
            S.riot_shift = 0;            /* Once underflowed, counts every 1 cycle! */
        } else {
            S.riot_intim--;
        }
        S.riot_sub += (s32)(1u << S.riot_shift);
    }
}

/* ---- MARIA GCC1702 Display Processor ---- */
INLINE u8 maria_fetch(u16 addr)
{
    if (addr >= 0x8000u) {
        if (S.zone_h16 && (addr & 0x1000u))
            return 0u;
        if (S.zone_h8 && (addr & 0x0800u))
            return 0u;
    }
    return bus_read(addr);
}

INLINE u8 maria_pal(u32 p, u32 c)
{
    return M->maria[((p & 7u) << 2) | (c & 3u)];
}

static void maria_load_dll(void)
{
    u8 b0 = bus_read(S.dpp);
    u8 hi = bus_read((u16)(S.dpp + 1u));
    u8 lo = bus_read((u16)(S.dpp + 2u));
    S.zone_dli = (b0 >> 7) & 1u;
    S.zone_h16 = (b0 >> 6) & 1u;
    S.zone_h8  = (b0 >> 5) & 1u;
    S.zone_off = b0 & 0x0Fu;
    S.dl_addr  = (u16)(((u16)hi << 8) | lo);
}

static s32 maria_render_line(void)
{
    u8 bg = M->maria[0x00];
    for (int i = 0; i < A78_W; i++)
        M->line_col[i] = bg;

    u8 ctrl = M->maria[0x1C];            /* $3C CTRL */
    if ((ctrl & 0x60u) != 0x40u)
        return 0;                        /* MARIA DMA disabled */

    int kangaroo = (ctrl >> 2) & 1;
    int cw_2byte = (ctrl >> 4) & 1;      /* CTRL b4: 0 = 1 byte/char, 1 = 2 bytes/char */
    u32 rm       = ctrl & 3u;
    u8 charbase  = M->maria[0x14];       /* $34 CHARBASE */

    u16 dl = S.dl_addr;
    s32 maria_clks = 28;                 /* DLL / startup overhead */

    for (int entries = 0; entries < 96; entries++) {
        u8 b0 = bus_read(dl);
        u8 b1 = bus_read((u16)(dl + 1u));
        if (b1 == 0u) {
            maria_clks += 8;
            break;
        }

        u8 gfx_lo, gfx_hi, pal, width, hpos, ind;
        if ((b1 & 0x5Fu) == 0x40u) {
            /* 5-byte extended header */
            gfx_lo = b0;
            S.sticky_wm = (b1 >> 7) & 1u;
            ind    = (b1 >> 5) & 1u;
            gfx_hi = bus_read((u16)(dl + 2u));
            u8 b3  = bus_read((u16)(dl + 3u));
            pal    = (b3 >> 5) & 7u;
            u8 wr  = b3 & 0x1Fu;
            width  = (u8)((32u - wr) & 0x3Fu);
            if (wr == 0u) width = 32u;
            hpos   = bus_read((u16)(dl + 4u));
            dl = (u16)(dl + 5u);
            maria_clks += 10;
        } else {
            /* 4-byte normal header (WM is sticky on GCC1702!) */
            gfx_lo = b0;
            pal    = (b1 >> 5) & 7u;
            width  = (u8)(32u - (b1 & 0x1Fu));
            gfx_hi = bus_read((u16)(dl + 2u));
            hpos   = bus_read((u16)(dl + 3u));
            ind    = 0u;
            dl = (u16)(dl + 4u);
            maria_clks += 8;
        }

        u8 wm = S.sticky_wm;
        u8 gbytes[64];
        int ng = 0;

        if (!ind) {
            u16 row_base = (u16)(((u16)(u8)(gfx_hi + S.zone_off) << 8) | gfx_lo);
            for (u8 k = 0; k < width && ng < 64; k++)
                gbytes[ng++] = maria_fetch((u16)(row_base + k));
            maria_clks += (s32)width * 3;
        } else {
            u16 map_ptr = (u16)(((u16)gfx_hi << 8) | gfx_lo);
            u16 ch_row  = (u16)((u8)(charbase + S.zone_off) << 8);
            for (u8 k = 0; k < width && ng < 63; k++) {
                u8 ch = bus_read((u16)(map_ptr + k));
                if (!cw_2byte) {
                    gbytes[ng++] = maria_fetch((u16)(ch_row | ch));
                    maria_clks += 6;
                } else {
                    gbytes[ng++] = maria_fetch((u16)(ch_row | ch));
                    gbytes[ng++] = maria_fetch((u16)(ch_row | (u8)(ch + 1u)));
                    maria_clks += 9;
                }
            }
        }

        u32 hp = hpos;
        for (int k = 0; k < ng; k++) {
            u8 gb = gbytes[k];
            if (rm == 0u && !wm) {
                /* 160A: 4 160-pixels (2bpp) -> 8 320-pixels */
                for (int p = 0; p < 4; p++) {
                    u32 ci = (gb >> (6 - p * 2)) & 3u;
                    u32 x = ((hp + (u32)p) & 0xFFu) * 2u;
                    if (x < A78_W) {
                        if (ci) {
                            u8 col = maria_pal(pal, ci);
                            M->line_col[x] = M->line_col[x + 1u] = col;
                        } else if (kangaroo) {
                            M->line_col[x] = M->line_col[x + 1u] = bg;
                        }
                    }
                }
                hp += 4u;
            } else if (rm == 0u && wm) {
                /* 160B: 2 160-pixels (4bpp, 12 colours) -> 4 320-pixels */
                for (int p = 0; p < 2; p++) {
                    u32 ci = p ? ((gb >> 4) & 3u) : ((gb >> 6) & 3u);
                    u32 sp = p ? (gb & 3u)        : ((gb >> 2) & 3u);
                    u32 x = ((hp + (u32)p) & 0xFFu) * 2u;
                    if (x < A78_W) {
                        if (ci) {
                            u8 col = maria_pal((pal & 4u) | sp, ci);
                            M->line_col[x] = M->line_col[x + 1u] = col;
                        } else if (kangaroo) {
                            M->line_col[x] = M->line_col[x + 1u] = bg;
                        }
                    }
                }
                hp += 2u;
            } else if (rm == 3u && !wm) {
                /* 320A: 8 320-pixels (1bpp using P{pal}C2!) */
                u8 fg = maria_pal(pal, 2u);
                for (int p = 0; p < 8; p++) {
                    u32 x = ((hp & 0xFFu) * 2u) + (u32)p;
                    if (x >= 512u) x -= 512u;
                    if (x < A78_W) {
                        if ((gb >> (7 - p)) & 1u)
                            M->line_col[x] = fg;
                        else if (kangaroo)
                            M->line_col[x] = bg;
                    }
                }
                hp += 4u;
            } else if (rm == 2u && wm) {
                /* 320B: 4 320-pixels (2bpp paired bits 7-p & 3-p) */
                u32 pbase = pal & 4u;
                for (int p = 0; p < 4; p++) {
                    u32 ci = (((gb >> (7 - p)) & 1u) << 1) | ((gb >> (3 - p)) & 1u);
                    u32 x = ((hp & 0xFFu) * 2u) + (u32)p;
                    if (x >= 512u) x -= 512u;
                    if (x < A78_W) {
                        if (ci)
                            M->line_col[x] = maria_pal(pbase, ci);
                        else if (kangaroo)
                            M->line_col[x] = bg;
                    }
                }
                hp += 2u;
            } else if (rm == 3u && wm) {
                /* 320C: 4 320-pixels (bits 7..4 pixels, bits 3..0 sub-palettes using C2) */
                for (int p = 0; p < 4; p++) {
                    u32 on = (gb >> (7 - p)) & 1u;
                    u32 sp = (p < 2) ? ((gb >> 2) & 3u) : (gb & 3u);
                    u32 x = ((hp & 0xFFu) * 2u) + (u32)p;
                    if (x >= 512u) x -= 512u;
                    if (x < A78_W) {
                        if (on)
                            M->line_col[x] = maria_pal((pal & 4u) | sp, 2u);
                        else if (kangaroo)
                            M->line_col[x] = bg;
                    }
                }
                hp += 2u;
            } else {
                /* 320D: 8 320-pixels */
                for (int p = 0; p < 8; p++) {
                    u32 bit = (gb >> (7 - p)) & 1u;
                    u32 pbit = (pal >> (1 - (p & 1))) & 1u;
                    u32 ci = (bit << 1) | pbit;
                    u32 x = ((hp & 0xFFu) * 2u) + (u32)p;
                    if (x >= 512u) x -= 512u;
                    if (x < A78_W && ci)
                        M->line_col[x] = maria_pal(pal & 4u, ci);
                }
                hp += 4u;
            }
        }
    }

    if (maria_clks > 400)
        maria_clks = 400;
    return maria_clks >> 2;              /* 4 MARIA clocks = 1 SALLY CPU cycle */
}

/* ---- Public Interface ---- */
static void fmt_a78_info(void)
{
    static const char * const map_names[] = { "Linear", "SuperGame", "Activision", "Absolute" };
    char *d = S.info;
    const char *t = S.title[0] ? S.title : "Atari 7800 ROM";
    for (int i = 0; t[i] && d - S.info < 44; i++)
        *d++ = t[i];
    const char *s1 = S.is_pal ? " (PAL, " : " (NTSC, ";
    while (*s1) *d++ = *s1++;
    u32 kb = S.rom_size >> 10;
    if (!kb) kb = 1;
    char nb[16]; int ni = 0; u32 v = kb;
    while (v > 0) { nb[ni++] = (char)('0' + (v % 10u)); v /= 10u; }
    while (ni > 0) *d++ = nb[--ni];
    const char *s2 = " KB ";
    while (*s2) *d++ = *s2++;
    const char *mn = map_names[S.mapper];
    while (*mn) *d++ = *mn++;
    if (S.has_pokey_4000 || S.has_pokey_0450) {
        const char *pk = "+POKEY";
        while (*pk) *d++ = *pk++;
    }
    *d++ = ')';
    *d = 0;
}

const char *a78_load(u8 *image, u32 size)
{
    if (!image || size < 0x1000u)
        return "too small to be an Atari 7800 cartridge (under 4 KB)";
    if (size > 0x100080u)
        return "larger than 1 MB Atari 7800 cartridge limit";

    init_palettes();
    mem_zero(&S, sizeof(S));

    int has_hdr = 0;
    if (size >= 128u + 0x1000u) {
        const char *m = "ATARI7800";
        has_hdr = 1;
        for (int i = 0; i < 9; i++) {
            if (image[1 + i] != (u8)m[i]) { has_hdr = 0; break; }
        }
    }

    if (has_hdr) {
        int ti = 0;
        for (int i = 0; i < 32; i++) {
            u8 c = image[17 + i];
            if (c >= 0x20u && c < 0x7Fu)
                S.title[ti++] = (char)c;
        }
        while (ti > 0 && S.title[ti - 1] == ' ')
            ti--;
        S.title[ti] = 0;

        u16 ctype = (u16)(((u16)image[53] << 8) | image[54]);
        S.is_pal         = image[57] & 1u;
        S.has_hsc_sram   = (image[58] != 0u) ? 1u : 0u;
        S.has_pokey_4000 = (ctype & 0x0001u) ? 1u : 0u;
        S.has_pokey_0450 = (ctype & 0x0040u) ? 1u : 0u;
        S.has_cram       = (ctype & 0x0004u) ? 1u : 0u;
        S.has_exfix      = (ctype & 0x0008u) ? 1u : 0u;

        if (ctype & 0x0100u)      S.mapper = MAP_ACTIVISION;
        else if (ctype & 0x0200u) S.mapper = MAP_ABSOLUTE;
        else if ((ctype & 0x0002u) || (size - 128u) > 0xD000u)
            S.mapper = MAP_SUPERGAME;
        else
            S.mapper = MAP_LINEAR;

        S.rom = image + 128u;
        S.rom_size = size - 128u;
    } else {
        /* Headerless .a78: verify power-of-2 or valid 16K/32K/48K/128K size & valid reset vector */
        if ((size & 0xFFFu) != 0u)
            return "not a valid Atari 7800 ROM (no ATARI7800 header and unaligned size)";
        u16 rst = (u16)(image[size - 4u] | ((u16)image[size - 3u] << 8));
        if (rst < 0x4000u || rst == 0xFFFFu)
            return "not a valid Atari 7800 ROM (invalid 6502 reset vector)";
        S.rom = image;
        S.rom_size = size;
        S.mapper = (size > 0xC000u) ? MAP_SUPERGAME : MAP_LINEAR;
    }

    S.n_banks16 = (u16)(S.rom_size / 0x4000u);
    mem_zero(M->hsram, sizeof(M->hsram));
    S.save_dirty = 0;

    a78_reset();
    fmt_a78_info();
    return 0;
}

void a78_reset(void)
{
    mem_zero(M->ram, sizeof(M->ram));
    mem_zero(M->cram, sizeof(M->cram));
    mem_zero(M->maria, sizeof(M->maria));
    mem_zero(M->tia, sizeof(M->tia));

    S.sg_bank = 0;
    S.act_bank = 0;
    S.abs_bank = 1;
    update_banks();

    S.a = S.x = S.y = 0;
    S.sp = 0xFDu;
    S.p  = FI | 0x20u;
    S.pc = rd16_abs(0xFFFCu);
    S.cyc = 0;
    S.nmi_pend = S.irq_pend = S.jammed = 0;

    S.swcha_out = 0xFFu;
    S.swacnt    = 0x00u;
    S.swchb_out = 0x3Fu;
    S.swbcnt    = 0x00u;
    S.riot_intim = 0xFFu;
    S.riot_shift = 10u;
    S.riot_sub   = 1024;
    S.riot_underflow = 0;

    S.in_vblank = 1;
    S.sticky_wm = 0;
    S.dma_was_on = 0;
    S.dc_est = 0;

    for (int i = 0; i < 2; i++) {
        S.audc[i] = S.audf[i] = S.audv[i] = 0;
        S.tia_p4[i] = 0x0Fu;
        S.tia_p5[i] = 0x1Fu;
        S.tia_p9[i] = 0x1FFu;
        S.tia_div[i] = S.tia_out[i] = 0;
    }
    for (int i = 0; i < 4; i++) {
        S.pokey_audf[i] = S.pokey_audc[i] = 0;
        S.pokey_cnt[i] = S.pokey_out[i] = 0;
    }
    S.pokey_audctl = 0;
    S.pokey_irqen  = 0;
    S.pokey_irqst  = 0xFFu;
    S.pokey_lfsr17 = 0x1FFFFu;
}

void a78_frame(u16 pad, u16 *picture)
{
    S.pad = pad;

    int total_lines = S.is_pal ? PAL_TOTAL_LINES : NTSC_TOTAL_LINES;
    int act_start   = S.is_pal ? PAL_ACT_START   : NTSC_ACT_START;
    int act_end     = S.is_pal ? PAL_ACT_END     : NTSC_ACT_END;
    int vis_start   = S.is_pal ? PAL_VIS_START   : NTSC_VIS_START;
    int vis_h       = S.is_pal ? A78_H_PAL       : A78_H_NTSC;
    const u16 *pal_lut = S.is_pal ? M->pal_pal   : M->pal_ntsc;

    for (int line = 0; line < total_lines; line++) {
        int active = (line >= act_start && line < act_end);
        S.in_vblank = active ? 0u : 1u;

        if (line == act_start) {
            S.dpp = (u16)(((u16)M->maria[0x0C] << 8) | M->maria[0x10]); /* DPPH:DPPL */
            S.sticky_wm = 0;
            S.dma_was_on = ((M->maria[0x1C] & 0x60u) == 0x40u) ? 1u : 0u;
            if (S.dma_was_on)
                maria_load_dll();
        }

        s32 dma_cyc = 0;
        if (active) {
            int dma_on = ((M->maria[0x1C] & 0x60u) == 0x40u);
            if (dma_on && !S.dma_was_on) {
                S.dpp = (u16)(((u16)M->maria[0x0C] << 8) | M->maria[0x10]);
                S.sticky_wm = 0;
                maria_load_dll();
                S.dma_was_on = 1u;
            }
            dma_cyc = maria_render_line();
            if (picture && line >= vis_start && line < vis_start + vis_h) {
                u16 *out = picture + (u32)(line - vis_start) * A78_W;
                for (int x = 0; x < A78_W; x++)
                    out[x] = pal_lut[M->line_col[x]];
            }
            if (dma_on) {
                if (S.zone_off == 0u) {
                    if (S.zone_dli)
                        S.nmi_pend = 1u;
                    S.dpp = (u16)(S.dpp + 3u);
                    if (line + 1 < act_end)
                        maria_load_dll();
                } else {
                    S.zone_off--;
                }
            }
        }

        s32 cpu_budget = LINE_CPU_CYC - dma_cyc;
        if (cpu_budget < 8)
            cpu_budget = 8;
        S.cyc += cpu_budget;
        while (S.cyc > 0 && !S.jammed)
            step_6502();
        riot_step(LINE_CPU_CYC);
        audio_step_line();
    }
}

int a78_width(void)
{
    return A78_W;
}

int a78_height(void)
{
    return S.is_pal ? A78_H_PAL : A78_H_NTSC;
}

int a78_pal(void)
{
    return S.is_pal;
}

const char *a78_info(void)
{
    return S.info;
}

u8 *a78_save_ram(u32 *size, int *battery)
{
    *size = 0x800u;
    *battery = S.has_hsc_sram ? 1 : 0;
    return M->hsram;
}

int a78_save_changed(void)
{
    int c = S.save_dirty;
    S.save_dirty = 0;
    return c;
}

int a78_jammed(void)
{
    return S.jammed;
}

void a78_audio_rate(u32 hz)
{
    S.snd_rate = hz;
    S.snd_phase = 0;
    S.snd_rd = S.snd_wr = 0;
}

int a78_audio(s16 *out, int max)
{
    int avail = (int)(S.snd_wr - S.snd_rd);
    if (avail > max)
        avail = max;
    for (int i = 0; i < avail; i++) {
        out[i] = M->snd_ring[S.snd_rd & (SND_RING - 1u)];
        S.snd_rd++;
    }
    return avail;
}
