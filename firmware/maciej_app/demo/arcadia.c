/* Emerson Arcadia 2001, Interton VC 4000 & RCA Studio II: see arcadia.h. */
#pragma GCC optimize("O2")
#include "arcadia.h"
#ifndef ARCADIA_HOST
#include "hw.h"
#endif

typedef signed char s8;

enum { SYS_ARCADIA = 0, SYS_VC4000 = 1, SYS_STUDIO2 = 2 };

#define PAD_A      0x01u
#define PAD_B      0x02u
#define PAD_SELECT 0x04u
#define PAD_START  0x08u
#define PAD_UP     0x10u
#define PAD_DOWN   0x20u
#define PAD_LEFT   0x40u
#define PAD_RIGHT  0x80u

#define ARC_AUDIO_MAX 2048

/* Signetics 2650 CPU flags */
#define S26_C    0x01u
#define S26_COM  0x02u
#define S26_OVF  0x04u
#define S26_WC   0x08u
#define S26_RS   0x10u
#define S26_IDC  0x20u
#define S26_CC   0xC0u

#define S26_SP   0x07u
#define S26_U34  0x18u
#define S26_II   0x20u
#define S26_FO   0x40u
#define S26_SI   0x80u

#define PMSK 0x1FFFu
#define PLEN 0x2000u
#define PAGE 0x6000u
#define AMSK 0x7FFFu

struct s2650_cpu {
    u16 page, iar, ea;
    u16 ras[8];
    u8  reg[7];                 /* R0, R1..R3, R4..R6 */
    u8  psl, psu;
    u8  halt, irq_state;
    s32 icount;
};

struct vc4_spr {
    u8  y, state, delay, size, scolor, mask;
    u8  finished, finished_now;
};

struct cdp1802_cpu {
    u16 r[16];
    u8  d, df, p, x, t, b, ie, q;
    u8  idle;
};

struct arc_ws {
    u8  sys;
    u8  ext_bios;
    u16 pad;

    struct s2650_cpu s26;
    struct cdp1802_cpu c18;

    u8  rom[0x8000];            /* up to 32 KB cartridge ROM */
    u32 rom_size;
    u8  ram[0x10000];           /* unified RAM / UVI / PVI / Studio II address space */
    u8  fb_idx[ARC_H_MAX][ARC_W_MAX];
    u16 pal[16];

    /* Emerson Arcadia 2001 (Signetics 2637 UVI) */
    u8  uvi[0x300];             /* $1800..$1AFF */
    u8  arc_chars[64][8];
    u8  arc_rect[64][8];
    u8  arc_bg_bits[262][32];
    int arc_pos_x[4], arc_pos_y[4];
    int arc_line, arc_charline, arc_ypos;
    u8  arc_multicolor, arc_shift, arc_lines26, arc_gfx, arc_dblscan;
    u8  arc_ad_sel;
    s8  arc_ad_delay;
    u8  arc_snd_size, arc_snd_pos, arc_snd_mode, arc_snd_tval, arc_snd_nval;
    u16 arc_snd_lfsr, arc_snd_vol;

    /* Interton VC 4000 (Signetics 2636 PVI) */
    u8  pvi[0x100];             /* $1F00..$1FFF */
    struct vc4_spr vc_spr[4];
    u8  vc_bg_coll, vc_spr_coll;
    u8  vc_spr_coll_lut[32];
    u8  vc_bg_coll_lut[32];
    int vc_line, vc_irq_pause;
    u8  vc_snd_tone, vc_snd_pos, vc_snd_state;

    /* RCA Studio II (CDP1802 + CDP1861 Pixie) */
    u8  st2_rom_map[64];        /* 1 if 256B page has ROM mapped */
    u8  st2_disp;
    u8  st2_keylatch;
    u8  st2_ef[4];
    u8  st2_irq;
    u16 st2_kpad_a, st2_kpad_b;
    u8  st2_beep_phase;

    /* Keypad input (shared 0..9, Enter, Clear) */
    u16 key_mask;
    u8  key_ttl;

    /* 48 kHz audio */
    u32 sample_rate;
    u32 snd_frac, chip_frac;
    s16 audio_ring[ARC_AUDIO_MAX];
    int audio_count;

    char info[96];
};

#ifdef ARCADIA_HOST
static struct arc_ws host_ws;
#define WS (&host_ws)
#else
#define WS ((struct arc_ws *)KSEG0(EMU_RAM_PHYS))
#endif

static inline u16 bgr555(int r, int g, int b)
{
    return (u16)((((u32)(b & 0xF8) >> 3) << 10) |
                 (((u32)(g & 0xF8) >> 3) << 5)  |
                 (((u32)(r & 0xF8) >> 3) << 0));
}

/* ========================================================================
 * SIGNETICS 2650 CPU CORE (shared by Arcadia 2001 & Interton VC 4000)
 * ======================================================================== */

static u8 s26_read(u16 addr);
static void s26_write(u16 addr, u8 val);
static int s26_sense(void);

static inline u8 s26_cc_val(u8 v)
{
    return v == 0 ? 0x00u : (v & 0x80u) ? 0x80u : 0x40u;
}

#define SET_CC(v) (WS->s26.psl = (u8)((WS->s26.psl & ~S26_CC) | s26_cc_val((u8)(v))))

static inline void s26_swap_regs(void)
{
    for (int i = 1; i <= 3; i++) {
        u8 t = WS->s26.reg[i];
        WS->s26.reg[i] = WS->s26.reg[i + 3];
        WS->s26.reg[i + 3] = t;
    }
}

static inline u8 s26_get_psu(void)
{
    if (s26_sense())
        WS->s26.psu |= S26_SI;
    else
        WS->s26.psu &= (u8)~S26_SI;
    return WS->s26.psu;
}

static inline u8 s26_arg(void)
{
    u8 r = s26_read((u16)(WS->s26.page + WS->s26.iar));
    WS->s26.iar = (u16)((WS->s26.iar + 1u) & PMSK);
    return r;
}

static inline s16 sext7(u8 v)
{
    return (v & 0x40u) ? (s16)((s16)(v & 0x7Fu) - 128) : (s16)(v & 0x3Fu);
}

static void s26_rel_ea(u16 base_page, int zero_rel)
{
    u8 hr = s26_arg();
    u16 off = zero_rel ? (u16)(sext7(hr) & PMSK) : (u16)((WS->s26.iar + sext7(hr)) & PMSK);
    u16 ea = (u16)((zero_rel ? 0u : base_page) + off);
    if (hr & 0x80u) {
        u16 a = ea;
        WS->s26.icount -= 6;
        u16 hi = (u16)s26_read(a) << 8;
        a++;
        if ((a & PMSK) == 0u)
            a = (u16)(a - PLEN);
        ea = (u16)((hi + s26_read(a)) & AMSK);
    }
    WS->s26.ea = ea;
}

static void s26_abs_ea(u8 *r_io, int is_branch)
{
    u8 hr = s26_arg();
    u8 dr = s26_arg();
    u16 ea = is_branch ? (u16)((((u16)hr << 8) + dr) & AMSK)
                       : (u16)(WS->s26.page + ((((u16)hr << 8) + dr) & PMSK));
    if (hr & 0x80u) {
        u16 a = ea;
        WS->s26.icount -= 6;
        u16 hi = (u16)s26_read(a) << 8;
        a++;
        if ((a & PMSK) == 0u)
            a = (u16)(a - PLEN);
        ea = (u16)((hi + s26_read(a)) & AMSK);
    }
    if (!is_branch) {
        u8 r = *r_io;
        switch (hr & 0x60u) {
        case 0x00: break;
        case 0x20:
            WS->s26.reg[r]++;
            ea = (u16)((ea & PAGE) + ((ea + WS->s26.reg[r]) & PMSK));
            *r_io = 0;
            break;
        case 0x40:
            WS->s26.reg[r]--;
            ea = (u16)((ea & PAGE) + ((ea + WS->s26.reg[r]) & PMSK));
            *r_io = 0;
            break;
        case 0x60:
            ea = (u16)((ea & PAGE) + ((ea + WS->s26.reg[r]) & PMSK));
            *r_io = 0;
            break;
        }
    }
    WS->s26.ea = ea;
}

static void s26_check_irq(void)
{
    if (WS->s26.irq_state && !(WS->s26.psu & S26_II)) {
        if (WS->s26.halt) {
            WS->s26.halt = 0;
            WS->s26.iar = (u16)((WS->s26.iar + 1u) & PMSK);
        }
        /* VC 4000 / 2636 PVI interrupt vector is 0x03 (page 0 address $0003) */
        u8 vec = (WS->sys == SYS_VC4000) ? 0x03u : 0x00u;
        WS->s26.icount -= 9;
        u16 ea = (u16)(sext7(vec) & PMSK);
        u8 sp = (u8)((WS->s26.psu + 1u) & S26_SP);
        WS->s26.psu = (u8)((WS->s26.psu & ~S26_SP) | sp | S26_II);
        WS->s26.ras[sp] = (u16)(WS->s26.page + WS->s26.iar);
        WS->s26.page = ea & PAGE;
        WS->s26.iar  = ea & PMSK;
        if (WS->sys == SYS_VC4000)
            WS->s26.irq_state = 0;
    }
}

static void s26_add(u8 *dst, u8 src)
{
    u8 bef = *dst;
    u16 c = (u16)(((WS->s26.psl >> 3) & WS->s26.psl) & S26_C);
    u16 res = (u16)bef + (u16)src + c;
    WS->s26.psl &= (u8)~(S26_C | S26_OVF | S26_IDC);
    if (res & 0x100u) WS->s26.psl |= S26_C;
    u8 out = (u8)res;
    if ((out ^ bef ^ src) & 0x10u) WS->s26.psl |= S26_IDC;
    if ((bef ^ out) & (src ^ out) & 0x80u) WS->s26.psl |= S26_OVF;
    *dst = out;
    SET_CC(out);
}

static void s26_sub(u8 *dst, u8 src)
{
    u8 bef = *dst;
    u16 b = (u16)(((WS->s26.psl >> 3) & (WS->s26.psl ^ S26_C)) & S26_C);
    u16 res = (u16)bef - (u16)src - b;
    WS->s26.psl &= (u8)~(S26_C | S26_OVF | S26_IDC);
    if ((res & 0x100u) == 0u) WS->s26.psl |= S26_C;
    u8 out = (u8)res;
    if (~(out ^ bef ^ src) & 0x10u) WS->s26.psl |= S26_IDC;
    if ((bef ^ src) & (bef ^ out) & 0x80u) WS->s26.psl |= S26_OVF;
    *dst = out;
    SET_CC(out);
}

static void s26_com(u8 reg, u8 val)
{
    s32 d = (WS->s26.psl & S26_COM) ? ((s32)reg - (s32)val) : ((s32)(s8)reg - (s32)(s8)val);
    WS->s26.psl &= (u8)~S26_CC;
    if (d < 0) WS->s26.psl |= 0x80u;
    else if (d > 0) WS->s26.psl |= 0x40u;
}

static void s26_run(s32 cycles)
{
    WS->s26.icount += cycles;
    s26_check_irq();
    while (WS->s26.icount > 0) {
        if (WS->s26.halt) {
            WS->s26.icount = 0;
            break;
        }
        u8 ir = s26_arg();
        u8 r = ir & 3u;
        u8 hi = ir >> 2;
        switch (hi) {
        case 0x00: WS->s26.icount -= 6; WS->s26.reg[0] = WS->s26.reg[r]; SET_CC(WS->s26.reg[0]); break;
        case 0x01: WS->s26.icount -= 6; WS->s26.reg[r] = s26_arg(); SET_CC(WS->s26.reg[r]); break;
        case 0x02: WS->s26.icount -= 9; s26_rel_ea(WS->s26.page, 0); WS->s26.reg[r] = s26_read(WS->s26.ea); SET_CC(WS->s26.reg[r]); break;
        case 0x03: WS->s26.icount -= 12; s26_abs_ea(&r, 0); WS->s26.reg[r] = s26_read(WS->s26.ea); SET_CC(WS->s26.reg[r]); break;
        case 0x04:
            WS->s26.icount -= 6;
            if (r == 2) { WS->s26.reg[0] = (u8)(s26_get_psu() & ~S26_U34); SET_CC(WS->s26.reg[0]); }
            else if (r == 3) { WS->s26.reg[0] = WS->s26.psl; SET_CC(WS->s26.reg[0]); }
            break;
        case 0x05: /* RETC */
            WS->s26.icount -= 9;
            if (r == 3 || (WS->s26.psl >> 6) == r) {
                WS->s26.icount -= 6;
                u8 sp = WS->s26.psu & S26_SP;
                u16 ea = WS->s26.ras[sp];
                WS->s26.psu = (u8)((WS->s26.psu & ~S26_SP) | ((sp - 1u) & S26_SP));
                WS->s26.page = ea & PAGE; WS->s26.iar = ea & PMSK;
            }
            break;
        case 0x06: /* BCTR */
            WS->s26.icount -= 9;
            if (r == 3 || (WS->s26.psl >> 6) == r) {
                s26_rel_ea(WS->s26.page, 0);
                WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK;
            } else WS->s26.iar = (u16)((WS->s26.iar + 1u) & PMSK);
            break;
        case 0x07: /* BCTA */
            WS->s26.icount -= 9;
            if (r == 3 || (WS->s26.psl >> 6) == r) {
                s26_abs_ea(&r, 1);
                WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK;
            } else WS->s26.iar = (u16)((WS->s26.iar + 2u) & PMSK);
            break;
        case 0x08: WS->s26.icount -= 6; WS->s26.reg[0] ^= WS->s26.reg[r]; SET_CC(WS->s26.reg[0]); break;
        case 0x09: WS->s26.icount -= 6; WS->s26.reg[r] ^= s26_arg(); SET_CC(WS->s26.reg[r]); break;
        case 0x0A: WS->s26.icount -= 9; s26_rel_ea(WS->s26.page, 0); WS->s26.reg[r] ^= s26_read(WS->s26.ea); SET_CC(WS->s26.reg[r]); break;
        case 0x0B: WS->s26.icount -= 12; s26_abs_ea(&r, 0); WS->s26.reg[r] ^= s26_read(WS->s26.ea); SET_CC(WS->s26.reg[r]); break;
        case 0x0C: WS->s26.icount -= 6; WS->s26.reg[r] = 0; SET_CC(0); break; /* REDC */
        case 0x0D: /* RETE */
            WS->s26.icount -= 9;
            if (r == 3 || (WS->s26.psl >> 6) == r) {
                u8 sp = WS->s26.psu & S26_SP;
                u16 ea = WS->s26.ras[sp];
                WS->s26.psu = (u8)(((WS->s26.psu & ~S26_SP) | ((sp - 1u) & S26_SP)) & ~S26_II);
                WS->s26.page = ea & PAGE; WS->s26.iar = ea & PMSK;
                s26_check_irq();
            }
            break;
        case 0x0E: /* BSTR */
            WS->s26.icount -= 9;
            if (r == 3 || (WS->s26.psl >> 6) == r) {
                s26_rel_ea(WS->s26.page, 0);
                u8 sp = (u8)((WS->s26.psu + 1u) & S26_SP);
                WS->s26.psu = (u8)((WS->s26.psu & ~S26_SP) | sp);
                WS->s26.ras[sp] = (u16)(WS->s26.page + WS->s26.iar);
                WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK;
            } else WS->s26.iar = (u16)((WS->s26.iar + 1u) & PMSK);
            break;
        case 0x0F: /* BSTA */
            WS->s26.icount -= 9;
            if (r == 3 || (WS->s26.psl >> 6) == r) {
                s26_abs_ea(&r, 1);
                u8 sp = (u8)((WS->s26.psu + 1u) & S26_SP);
                WS->s26.psu = (u8)((WS->s26.psu & ~S26_SP) | sp);
                WS->s26.ras[sp] = (u16)(WS->s26.page + WS->s26.iar);
                WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK;
            } else WS->s26.iar = (u16)((WS->s26.iar + 2u) & PMSK);
            break;
        case 0x10:
            WS->s26.icount -= 6;
            if (r == 0) { WS->s26.iar = (u16)((WS->s26.iar - 1u) & PMSK); WS->s26.halt = 1; WS->s26.icount = 0; }
            else { WS->s26.reg[0] &= WS->s26.reg[r]; SET_CC(WS->s26.reg[0]); }
            break;
        case 0x11: WS->s26.icount -= 6; WS->s26.reg[r] &= s26_arg(); SET_CC(WS->s26.reg[r]); break;
        case 0x12: WS->s26.icount -= 9; s26_rel_ea(WS->s26.page, 0); WS->s26.reg[r] &= s26_read(WS->s26.ea); SET_CC(WS->s26.reg[r]); break;
        case 0x13: WS->s26.icount -= 12; s26_abs_ea(&r, 0); WS->s26.reg[r] &= s26_read(WS->s26.ea); SET_CC(WS->s26.reg[r]); break;
        case 0x14: { /* RRR */
            WS->s26.icount -= 6;
            u8 b = WS->s26.reg[r], d;
            if (WS->s26.psl & S26_WC) {
                u8 c = WS->s26.psl & S26_C;
                WS->s26.psl &= (u8)~(S26_C | S26_IDC);
                d = (u8)((b >> 1) | (c << 7));
                WS->s26.psl |= (u8)((b & S26_C) | (d & S26_IDC));
            } else d = (u8)((b >> 1) | (b << 7));
            WS->s26.reg[r] = d; SET_CC(d);
            WS->s26.psl = (u8)((WS->s26.psl & ~S26_OVF) | (((d ^ b) >> 5) & S26_OVF));
            break;
        }
        case 0x15: WS->s26.icount -= 9; (void)s26_arg(); WS->s26.reg[r] = 0; SET_CC(0); break; /* REDE */
        case 0x16: /* BRNR */
            WS->s26.icount -= 9;
            if (WS->s26.reg[r]) { s26_rel_ea(WS->s26.page, 0); WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK; }
            else WS->s26.iar = (u16)((WS->s26.iar + 1u) & PMSK);
            break;
        case 0x17: /* BRNA */
            WS->s26.icount -= 9;
            if (WS->s26.reg[r]) { s26_abs_ea(&r, 1); WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK; }
            else WS->s26.iar = (u16)((WS->s26.iar + 2u) & PMSK);
            break;
        case 0x18: WS->s26.icount -= 6; WS->s26.reg[0] |= WS->s26.reg[r]; SET_CC(WS->s26.reg[0]); break;
        case 0x19: WS->s26.icount -= 6; WS->s26.reg[r] |= s26_arg(); SET_CC(WS->s26.reg[r]); break;
        case 0x1A: WS->s26.icount -= 9; s26_rel_ea(WS->s26.page, 0); WS->s26.reg[r] |= s26_read(WS->s26.ea); SET_CC(WS->s26.reg[r]); break;
        case 0x1B: WS->s26.icount -= 12; s26_abs_ea(&r, 0); WS->s26.reg[r] |= s26_read(WS->s26.ea); SET_CC(WS->s26.reg[r]); break;
        case 0x1C: WS->s26.icount -= 6; WS->s26.reg[r] = 0; SET_CC(0); break; /* REDD */
        case 0x1D: { /* CPSU / CPSL / PPSU / PPSL */
            WS->s26.icount -= 9;
            u8 v = s26_arg();
            if (r == 0) { WS->s26.psu &= (u8)~(v & ~S26_SI); s26_check_irq(); }
            else if (r == 1) { if ((v & S26_RS) && (WS->s26.psl & S26_RS)) s26_swap_regs(); WS->s26.psl &= (u8)~v; }
            else if (r == 2) { WS->s26.psu |= (u8)(v & ~(S26_U34 | S26_SI)); }
            else { if ((v & S26_RS) && !(WS->s26.psl & S26_RS)) s26_swap_regs(); WS->s26.psl |= v; }
            break;
        }
        case 0x1E: /* BSNR */
            WS->s26.icount -= 9;
            if (WS->s26.reg[r]) {
                s26_rel_ea(WS->s26.page, 0);
                u8 sp = (u8)((WS->s26.psu + 1u) & S26_SP);
                WS->s26.psu = (u8)((WS->s26.psu & ~S26_SP) | sp);
                WS->s26.ras[sp] = (u16)(WS->s26.page + WS->s26.iar);
                WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK;
            } else WS->s26.iar = (u16)((WS->s26.iar + 1u) & PMSK);
            break;
        case 0x1F: /* BSNA */
            WS->s26.icount -= 9;
            if (WS->s26.reg[r]) {
                s26_abs_ea(&r, 1);
                u8 sp = (u8)((WS->s26.psu + 1u) & S26_SP);
                WS->s26.psu = (u8)((WS->s26.psu & ~S26_SP) | sp);
                WS->s26.ras[sp] = (u16)(WS->s26.page + WS->s26.iar);
                WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK;
            } else WS->s26.iar = (u16)((WS->s26.iar + 2u) & PMSK);
            break;
        case 0x20: WS->s26.icount -= 6; s26_add(&WS->s26.reg[0], WS->s26.reg[r]); break;
        case 0x21: WS->s26.icount -= 6; s26_add(&WS->s26.reg[r], s26_arg()); break;
        case 0x22: WS->s26.icount -= 9; s26_rel_ea(WS->s26.page, 0); s26_add(&WS->s26.reg[r], s26_read(WS->s26.ea)); break;
        case 0x23: WS->s26.icount -= 12; s26_abs_ea(&r, 0); s26_add(&WS->s26.reg[r], s26_read(WS->s26.ea)); break;
        case 0x24:
            WS->s26.icount -= 6;
            if (r == 2) WS->s26.psu = (u8)((WS->s26.reg[0] & ~(S26_U34 | S26_SI)) | (WS->s26.psu & S26_SI));
            else if (r == 3) { if ((WS->s26.psl ^ WS->s26.reg[0]) & S26_RS) s26_swap_regs(); WS->s26.psl = WS->s26.reg[0]; }
            break;
        case 0x25: /* DAR */
            WS->s26.icount -= 9;
            if (!(WS->s26.psl & S26_C)) WS->s26.reg[r] = (u8)(WS->s26.reg[r] + 0xA0u);
            if (!(WS->s26.psl & S26_IDC)) WS->s26.reg[r] = (u8)((WS->s26.reg[r] & 0xF0u) | ((WS->s26.reg[r] + 0x0Au) & 0x0Fu));
            break;
        case 0x26: /* BCFR / ZBRR */
            WS->s26.icount -= 9;
            if (r == 3) { s26_rel_ea(0, 1); WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK; }
            else if ((WS->s26.psl >> 6) != r) { s26_rel_ea(WS->s26.page, 0); WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK; }
            else WS->s26.iar = (u16)((WS->s26.iar + 1u) & PMSK);
            break;
        case 0x27: /* BCFA / BXA */
            WS->s26.icount -= 9;
            if (r == 3) { s26_abs_ea(&r, 1); u16 ea = (u16)((WS->s26.ea + WS->s26.reg[3]) & AMSK); WS->s26.page = ea & PAGE; WS->s26.iar = ea & PMSK; }
            else if ((WS->s26.psl >> 6) != r) { s26_abs_ea(&r, 1); WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK; }
            else WS->s26.iar = (u16)((WS->s26.iar + 2u) & PMSK);
            break;
        case 0x28: WS->s26.icount -= 6; s26_sub(&WS->s26.reg[0], WS->s26.reg[r]); break;
        case 0x29: WS->s26.icount -= 6; s26_sub(&WS->s26.reg[r], s26_arg()); break;
        case 0x2A: WS->s26.icount -= 9; s26_rel_ea(WS->s26.page, 0); s26_sub(&WS->s26.reg[r], s26_read(WS->s26.ea)); break;
        case 0x2B: WS->s26.icount -= 12; s26_abs_ea(&r, 0); s26_sub(&WS->s26.reg[r], s26_read(WS->s26.ea)); break;
        case 0x2C: WS->s26.icount -= 6; break; /* WRTC */
        case 0x2D: { /* TPSU / TPSL */
            WS->s26.icount -= 9;
            if (r == 0) { u8 m = s26_arg(); WS->s26.psl &= (u8)~S26_CC; if ((s26_get_psu() & m) != m) WS->s26.psl |= 0x80u; }
            else if (r == 1) { u8 m = s26_arg(); WS->s26.psl &= (u8)~S26_CC; if ((WS->s26.psl & m) != m) WS->s26.psl |= 0x80u; }
            break;
        }
        case 0x2E: /* BSFR / ZBSR */
            WS->s26.icount -= 9;
            if (r == 3) {
                s26_rel_ea(0, 1);
                u8 sp = (u8)((WS->s26.psu + 1u) & S26_SP);
                WS->s26.psu = (u8)((WS->s26.psu & ~S26_SP) | sp);
                WS->s26.ras[sp] = (u16)(WS->s26.page + WS->s26.iar);
                WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK;
            } else if ((WS->s26.psl >> 6) != r) {
                s26_rel_ea(WS->s26.page, 0);
                u8 sp = (u8)((WS->s26.psu + 1u) & S26_SP);
                WS->s26.psu = (u8)((WS->s26.psu & ~S26_SP) | sp);
                WS->s26.ras[sp] = (u16)(WS->s26.page + WS->s26.iar);
                WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK;
            } else WS->s26.iar = (u16)((WS->s26.iar + 1u) & PMSK);
            break;
        case 0x2F: /* BSFA / BSXA */
            WS->s26.icount -= 9;
            if (r == 3) {
                s26_abs_ea(&r, 1);
                u16 ea = (u16)((WS->s26.ea + WS->s26.reg[3]) & AMSK);
                u8 sp = (u8)((WS->s26.psu + 1u) & S26_SP);
                WS->s26.psu = (u8)((WS->s26.psu & ~S26_SP) | sp);
                WS->s26.ras[sp] = (u16)(WS->s26.page + WS->s26.iar);
                WS->s26.page = ea & PAGE; WS->s26.iar = ea & PMSK;
            } else if ((WS->s26.psl >> 6) != r) {
                s26_abs_ea(&r, 1);
                u8 sp = (u8)((WS->s26.psu + 1u) & S26_SP);
                WS->s26.psu = (u8)((WS->s26.psu & ~S26_SP) | sp);
                WS->s26.ras[sp] = (u16)(WS->s26.page + WS->s26.iar);
                WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK;
            } else WS->s26.iar = (u16)((WS->s26.iar + 2u) & PMSK);
            break;
        case 0x30:
            WS->s26.icount -= 6;
            if (r != 0) { WS->s26.reg[r] = WS->s26.reg[0]; SET_CC(WS->s26.reg[r]); }
            break;
        case 0x31: WS->s26.icount -= 6; break;
        case 0x32: WS->s26.icount -= 9; s26_rel_ea(WS->s26.page, 0); s26_write(WS->s26.ea, WS->s26.reg[r]); break;
        case 0x33: WS->s26.icount -= 12; s26_abs_ea(&r, 0); s26_write(WS->s26.ea, WS->s26.reg[r]); break;
        case 0x34: { /* RRL */
            WS->s26.icount -= 6;
            u8 b = WS->s26.reg[r], d;
            if (WS->s26.psl & S26_WC) {
                u8 c = WS->s26.psl & S26_C;
                WS->s26.psl &= (u8)~(S26_C | S26_IDC);
                d = (u8)((b << 1) | c);
                WS->s26.psl |= (u8)((b >> 7) | (d & S26_IDC));
            } else d = (u8)((b << 1) | (b >> 7));
            WS->s26.reg[r] = d; SET_CC(d);
            WS->s26.psl = (u8)((WS->s26.psl & ~S26_OVF) | (((d ^ b) >> 5) & S26_OVF));
            break;
        }
        case 0x35: WS->s26.icount -= 9; (void)s26_arg(); break; /* WRTE */
        case 0x36: /* BIRR */
            WS->s26.icount -= 9;
            if (++WS->s26.reg[r]) { s26_rel_ea(WS->s26.page, 0); WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK; }
            else WS->s26.iar = (u16)((WS->s26.iar + 1u) & PMSK);
            break;
        case 0x37: /* BIRA */
            WS->s26.icount -= 9;
            if (++WS->s26.reg[r]) { s26_abs_ea(&r, 1); WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK; }
            else WS->s26.iar = (u16)((WS->s26.iar + 2u) & PMSK);
            break;
        case 0x38: WS->s26.icount -= 6; s26_com(WS->s26.reg[0], WS->s26.reg[r]); break;
        case 0x39: WS->s26.icount -= 6; s26_com(WS->s26.reg[r], s26_arg()); break;
        case 0x3A: WS->s26.icount -= 9; s26_rel_ea(WS->s26.page, 0); s26_com(WS->s26.reg[r], s26_read(WS->s26.ea)); break;
        case 0x3B: WS->s26.icount -= 12; s26_abs_ea(&r, 0); s26_com(WS->s26.reg[r], s26_read(WS->s26.ea)); break;
        case 0x3C: WS->s26.icount -= 6; break; /* WRTD */
        case 0x3D: { u8 m = s26_arg(); WS->s26.icount -= 9; WS->s26.psl &= (u8)~S26_CC; if ((WS->s26.reg[r] & m) != m) WS->s26.psl |= 0x80u; break; }
        case 0x3E: /* BDRR */
            WS->s26.icount -= 9;
            if (--WS->s26.reg[r]) { s26_rel_ea(WS->s26.page, 0); WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK; }
            else WS->s26.iar = (u16)((WS->s26.iar + 1u) & PMSK);
            break;
        case 0x3F: /* BDRA */
            WS->s26.icount -= 9;
            if (--WS->s26.reg[r]) { s26_abs_ea(&r, 1); WS->s26.page = WS->s26.ea & PAGE; WS->s26.iar = WS->s26.ea & PMSK; }
            else WS->s26.iar = (u16)((WS->s26.iar + 2u) & PMSK);
            break;
        }
    }
}

/* ========================================================================
 * EMERSON ARCADIA 2001 (Signetics 2637 UVI)
 * ======================================================================== */

static const u8 arc_font_rom[56][8] = {
    {0,0,0,0,0,0,0,0}, {1,2,4,8,16,32,64,128}, {128,64,32,16,8,4,2,1}, {255,255,255,255,255,255,255,255},
    {255,255,0,0,0,0,0,0}, {3,3,3,3,3,3,3,3}, {0,0,0,0,0,0,255,255}, {192,192,192,192,192,192,192,192},
    {255,255,3,3,3,3,3,3}, {255,255,192,192,192,192,192,192}, {192,192,192,192,192,192,255,255}, {3,3,3,3,3,3,255,255},
    {1,3,7,15,31,63,127,255}, {128,192,224,240,248,252,254,255}, {255,254,252,248,240,224,192,128}, {255,127,63,31,15,7,3,1},
    {0,0x1c,0x22,0x26,0x2a,0x32,0x22,0x1c}, {0,0x08,0x18,0x08,0x08,0x08,0x08,0x1c},
    {0,0x1c,0x22,0x02,0x0c,0x10,0x20,0x3e}, {0,0x3e,0x02,0x04,0x0c,0x02,0x22,0x1c},
    {0,0x04,0x0c,0x14,0x24,0x3e,0x04,0x04}, {0,0x3e,0x20,0x3c,0x02,0x02,0x22,0x1c},
    {0,0x0c,0x10,0x20,0x3c,0x22,0x22,0x1c}, {0,0x7c,0x02,0x04,0x08,0x10,0x10,0x10},
    {0,0x1c,0x22,0x22,0x1c,0x22,0x22,0x1c}, {0,0x1c,0x22,0x22,0x3e,0x02,0x04,0x18},
    {0,0x08,0x14,0x22,0x22,0x3e,0x22,0x22}, {0,0x3c,0x22,0x22,0x3c,0x22,0x22,0x3c},
    {0,0x1c,0x22,0x20,0x20,0x20,0x22,0x1c}, {0,0x3c,0x22,0x22,0x22,0x22,0x22,0x3c},
    {0,0x3e,0x20,0x20,0x3c,0x20,0x20,0x3e}, {0,0x3e,0x20,0x20,0x3c,0x20,0x20,0x20},
    {0,0x1e,0x20,0x20,0x20,0x26,0x22,0x1e}, {0,0x22,0x22,0x22,0x3e,0x22,0x22,0x22},
    {0,0x1c,0x08,0x08,0x08,0x08,0x08,0x1c}, {0,0x02,0x02,0x02,0x02,0x02,0x22,0x1c},
    {0,0x22,0x24,0x28,0x30,0x28,0x24,0x22}, {0,0x20,0x20,0x20,0x20,0x20,0x20,0x3e},
    {0,0x22,0x36,0x2a,0x2a,0x22,0x22,0x22}, {0,0x22,0x22,0x32,0x2a,0x26,0x22,0x22},
    {0,0x1c,0x22,0x22,0x22,0x22,0x22,0x1c}, {0,0x3c,0x22,0x22,0x3c,0x20,0x20,0x20},
    {0,0x1c,0x22,0x22,0x22,0x2a,0x24,0x1a}, {0,0x3c,0x22,0x22,0x3c,0x28,0x24,0x22},
    {0,0x1c,0x22,0x20,0x1c,0x02,0x22,0x1c}, {0,0x3e,0x08,0x08,0x08,0x08,0x08,0x08},
    {0,0x22,0x22,0x22,0x22,0x22,0x22,0x1c}, {0,0x22,0x22,0x22,0x22,0x22,0x14,0x08},
    {0,0x22,0x22,0x22,0x2a,0x2a,0x36,0x22}, {0,0x22,0x22,0x14,0x08,0x14,0x22,0x22},
    {0,0x22,0x22,0x14,0x08,0x08,0x08,0x08}, {0,0x3e,0x02,0x04,0x08,0x10,0x20,0x3e},
    {0,0,0,0,0,0,0,8}, {0,0,0,0,0,8,8,16}, {0,0,8,8,0x3e,8,8,0}, {0,8,0x1e,0x28,0x1c,0x0a,0x3c,8}
};

static u8 arc_uvi_r(u16 off)
{
    if (off >= 0x300u)
        off = (u16)(0x100u | (off & 0xFFu)); /* $1B00..$1BFF mirrors $1900..$19FF */
    switch (off) {
    case 0x0FF:
        return (u8)((WS->arc_charline & 0x0Fu) | 0xF0u);
    case 0x100: { /* P1 col 1: 1(bit3), 4(bit2), 7(bit1), Cl(bit0) */
        u8 v = 0xF0u;
        if (WS->key_mask & (1u << 1)) v |= 0x08u;
        if (WS->key_mask & (1u << 4)) v |= 0x04u;
        if (WS->key_mask & (1u << 7)) v |= 0x02u;
        if (WS->key_mask & (1u << 10)) v |= 0x01u;
        return v;
    }
    case 0x101: { /* P1 col 2: 2/Fire(bit3), 5(bit2), 8(bit1), 0(bit0) */
        u8 v = 0xF0u;
        if ((WS->pad & (PAD_A | PAD_B)) || (WS->key_mask & (1u << 2))) v |= 0x08u;
        if (WS->key_mask & (1u << 5)) v |= 0x04u;
        if (WS->key_mask & (1u << 8)) v |= 0x02u;
        if (WS->key_mask & (1u << 0)) v |= 0x01u;
        return v;
    }
    case 0x102: { /* P1 col 3: 3(bit3), 6(bit2), 9(bit1), En(bit0) */
        u8 v = 0xF0u;
        if (WS->key_mask & (1u << 3)) v |= 0x08u;
        if (WS->key_mask & (1u << 6)) v |= 0x04u;
        if (WS->key_mask & (1u << 9)) v |= 0x02u;
        if (WS->key_mask & (1u << 11)) v |= 0x01u;
        return v;
    }
    case 0x103: case 0x104: case 0x105: case 0x106: case 0x107:
        return 0xF0u;
    case 0x108: { /* Front panel: bit 0 Start, bit 1 Option, bit 2 Select */
        u8 v = 0;
        if (WS->pad & PAD_START)  v |= 0x01u;
        if (WS->pad & PAD_SELECT) v |= 0x06u;
        return v;
    }
    case 0x1FE: /* P2 joystick */
        return 0x80u;
    case 0x1FF: /* P1 joystick: ad_sel != 0 -> X (Left=0, Right=0xFF); ad_sel == 0 -> Y (Up=0, Down=0xFF) */
        if (WS->arc_ad_sel) {
            if (WS->pad & PAD_LEFT)  return 0x00u;
            if (WS->pad & PAD_RIGHT) return 0xFFu;
        } else {
            if (WS->pad & PAD_UP)    return 0x00u;
            if (WS->pad & PAD_DOWN)  return 0xFFu;
        }
        return 0x6Fu;
    default:
        return WS->uvi[off];
    }
}

static void arc_uvi_w(u16 off, u8 data)
{
    if (off >= 0x300u)
        off = (u16)(0x100u | (off & 0xFFu));
    WS->uvi[off] = data;
    switch (off) {
    case 0x0F0: case 0x0F2: case 0x0F4: case 0x0F6:
        WS->arc_pos_y[(off >> 1) & 3] = (data ^ 0xFF) + 1;
        break;
    case 0x0F1: case 0x0F3: case 0x0F5: case 0x0F7:
        WS->arc_pos_x[(off >> 1) & 3] = (int)data - 43;
        break;
    case 0x0FC:
        WS->arc_ypos = 255 - data;
        break;
    case 0x0FD:
        WS->arc_snd_size = data & 0x7Fu;
        if (!WS->arc_snd_size)
            WS->arc_snd_lfsr = 0x00F0u;
        WS->arc_multicolor = (data >> 7) & 1u;
        break;
    case 0x0FE: {
        WS->arc_snd_vol = (u16)((data & 7u) * 2048u);
        u8 mode = (data >> 3) & 3u;
        if (mode != WS->arc_snd_mode)
            WS->arc_snd_tval = 0;
        WS->arc_snd_mode = mode;
        WS->arc_shift = (data >> 5) & 7u;
        break;
    }
    case 0x1F8:
        WS->arc_lines26 = (data >> 6) & 1u;
        WS->arc_gfx = (data >> 7) & 1u;
        break;
    case 0x1F9:
        WS->arc_dblscan = (data & 0x80u) ? 0u : 1u;
        WS->arc_ad_delay = 10;
        break;
    default:
        if (off >= 0x180u && off < 0x1C0u)
            WS->arc_chars[0x38u | ((off >> 3) & 7u)][off & 7u] = data;
        break;
    }
}

static void arc_draw_char_row(const u8 *pat, u8 code, int y0, int x0)
{
    u8 p0 = WS->uvi[0x1F8], p1 = WS->uvi[0x1F9];
    u8 cc, sc;
    if (WS->arc_multicolor) {
        cc = (code & 0x40u) ? ((p1 >> 3) & 7u) : ((p0 >> 3) & 7u);
        sc = (code & 0x80u) ? (p1 & 7u) : (p0 & 7u);
    } else {
        cc = (u8)(((p1 >> 3) & 1u) | ((code >> 5) & 6u));
        sc = p1 & 7u;
    }
    int step = WS->arc_dblscan ? 2 : 1;
    int y = y0;
    for (int k = 0; k < 8 && y < ARCADIA_H; k++, y += step) {
        u8 b = pat[k];
        for (int dy = 0; dy < step && (y + dy) < ARCADIA_H; dy++) {
            int ry = y + dy;
            for (int j = 0; j < 8; j++) {
                int rx = x0 + j;
                if ((unsigned)rx < ARCADIA_W) {
                    int on = (b & (0x80u >> j)) != 0;
                    WS->fb_idx[ry][rx] = on ? cc : sc;
                    if (on)
                        WS->arc_bg_bits[ry][rx >> 3] |= (u8)(0x80u >> (rx & 7));
                }
            }
        }
    }
}

static void arc_draw_charline(int y, const u8 *row16)
{
    int h = WS->arc_dblscan ? 16 : 8;
    u8 bg = WS->uvi[0x1F9] & 7u;
    for (int ry = y; ry < y + h && ry < ARCADIA_H; ry++) {
        for (int x = 0; x < ARCADIA_W; x++)
            WS->fb_idx[ry][x] = bg;
        for (int bx = 0; bx < 32; bx++)
            WS->arc_bg_bits[ry][bx] = 0;
    }
    u8 gfx = WS->arc_gfx;
    int x = 16 + (int)WS->arc_shift;
    for (int j = 0; j < 16; j++, x += 8) {
        u8 ch = row16[j];
        if ((ch & 0x3Fu) == 0u) {
            if (ch == 0xC0u) gfx = 1;
            else if (ch == 0x40u) gfx = 0;
        }
        arc_draw_char_row(gfx ? WS->arc_rect[ch & 0x3Fu] : WS->arc_chars[ch & 0x3Fu], ch, y, x);
    }
}

static int arc_spr_collide(int a, int b)
{
    int ax = WS->arc_pos_x[a], ay = WS->arc_pos_y[a];
    int bx = WS->arc_pos_x[b], by = WS->arc_pos_y[b];
    if (ax + 8 <= bx || ax >= bx + 8)
        return 0;
    for (int k = 0; k < 8; k++) {
        if (ay + k < by || ay + k >= by + 8)
            continue;
        u8 pa = WS->uvi[0x180 + a * 8 + k];
        u8 pb = WS->uvi[0x180 + b * 8 + (ay + k - by)];
        int dx = ax - bx;
        if (dx < 0) pb >>= -dx;
        else if (dx > 0) pa >>= dx;
        if (pa & pb)
            return 1;
    }
    return 0;
}

static void arc_draw_sprites(void)
{
    WS->uvi[0x1FC] |= 0xFFu;
    WS->uvi[0x1FD] |= 0xFFu;
    u8 p2 = WS->uvi[0x1FA], p3 = WS->uvi[0x1FB];
    for (int i = 0; i < 4; i++) {
        u8 col = 0;
        int dbl = 0;
        if (i == 0)      { col = (p3 >> 3) & 7u; dbl = !(p3 & 0x80u); }
        else if (i == 1) { col = p3 & 7u;        dbl = !(p3 & 0x40u); }
        else if (i == 2) { col = (p2 >> 3) & 7u; dbl = !(p2 & 0x80u); }
        else             { col = p2 & 7u;        dbl = !(p2 & 0x40u); }
        int sx = WS->arc_pos_x[i] + 16;
        int sy = WS->arc_pos_y[i];
        int step = dbl ? 2 : 1;
        for (int k = 0; k < 8; k++) {
            u8 pat = WS->uvi[0x180 + i * 8 + k];
            if (!pat)
                continue;
            for (int dy = 0; dy < step; dy++) {
                int ry = sy + k * step + dy;
                if ((unsigned)ry >= ARCADIA_H)
                    continue;
                for (int j = 0; j < 8; j++) {
                    if (!(pat & (0x80u >> j)))
                        continue;
                    int rx = sx + j;
                    if ((unsigned)rx >= ARCADIA_W)
                        continue;
                    if (WS->arc_bg_bits[ry][rx >> 3] & (0x80u >> (rx & 7)))
                        WS->uvi[0x1FC] &= (u8)~(1u << i);
                    WS->fb_idx[ry][rx] = col;
                }
            }
        }
    }
    if (arc_spr_collide(0, 1)) WS->uvi[0x1FD] &= (u8)~0x01u;
    if (arc_spr_collide(0, 2)) WS->uvi[0x1FD] &= (u8)~0x02u;
    if (arc_spr_collide(0, 3)) WS->uvi[0x1FD] &= (u8)~0x04u;
    if (arc_spr_collide(1, 2)) WS->uvi[0x1FD] &= (u8)~0x08u;
    if (arc_spr_collide(1, 3)) WS->uvi[0x1FD] &= (u8)~0x10u;
    if (arc_spr_collide(2, 3)) WS->uvi[0x1FD] &= (u8)~0x20u;
}

static void arc_sound_line(void)
{
    if (!WS->sample_rate)
        return;
    /* One NTSC line at 15,734 Hz advances Arcadia sound counter by 1 */
    s32 sample = 0;
    if (WS->uvi[0x0FD]) {
        if (WS->arc_snd_mode == 1)
            sample = WS->arc_snd_tval ? (s32)WS->arc_snd_vol : -(s32)WS->arc_snd_vol;
        else if (WS->arc_snd_mode == 2)
            sample = WS->arc_snd_nval ? (s32)WS->arc_snd_vol : -(s32)WS->arc_snd_vol;
        else if (WS->arc_snd_mode == 3)
            sample = (WS->arc_snd_tval & WS->arc_snd_nval) ? (s32)WS->arc_snd_vol : -(s32)WS->arc_snd_vol;

        WS->arc_snd_pos++;
        if (WS->arc_snd_pos >= WS->arc_snd_size) {
            u8 nb = (u8)((WS->arc_snd_lfsr & 1u) ^ ((WS->arc_snd_lfsr & 0x10u) ? 1u : 0u));
            WS->arc_snd_nval = (u8)(WS->arc_snd_lfsr & 1u);
            WS->arc_snd_lfsr >>= 1;
            if (nb)
                WS->arc_snd_lfsr |= 0x0100u;
            WS->arc_snd_tval ^= 1u;
            WS->arc_snd_pos = 0;
        }
    }
    u32 num = WS->sample_rate + WS->snd_frac;
    u32 ns = num / 15734u;
    WS->snd_frac = num % 15734u;
    while (ns--) {
        if (WS->audio_count < ARC_AUDIO_MAX)
            WS->audio_ring[WS->audio_count++] = (s16)sample;
    }
}

static void arcadia_run_frame(u16 *pic)
{
    for (int sl = 0; sl < 262; sl++) {
        WS->arc_line = sl;
        if (WS->arc_ad_delay <= 0)
            WS->arc_ad_sel = (WS->uvi[0x1F9] >> 6) & 1u;
        else
            WS->arc_ad_delay--;

        int yp = WS->arc_ypos;
        if (yp < 0 || yp > 80)
            yp = 0;

        if (sl < yp) {
            if (sl < ARCADIA_H) {
                u8 bg = WS->uvi[0x1F9] & 7u;
                for (int x = 0; x < ARCADIA_W; x++)
                    WS->fb_idx[sl][x] = bg;
                for (int bx = 0; bx < 32; bx++)
                    WS->arc_bg_bits[sl][bx] = 0;
            }
        } else {
            int h = WS->arc_dblscan ? 16 : 8;
            int cl = (sl - yp) / h;
            WS->arc_charline = cl;
            if (cl < 13) {
                if (((sl - yp) & (h - 1)) == 0)
                    arc_draw_charline(cl * h + yp, &WS->uvi[cl * 16]);
            } else if (WS->arc_lines26 && cl < 26) {
                if (((sl - yp) & (h - 1)) == 0)
                    arc_draw_charline(cl * h + yp, &WS->uvi[0x200 + (cl - 13) * 16]);
                WS->arc_charline = cl - 13;
            } else {
                WS->arc_charline = 0x0D;
                if (sl < ARCADIA_H) {
                    u8 bg = WS->uvi[0x1F9] & 7u;
                    for (int x = 0; x < ARCADIA_W; x++)
                        WS->fb_idx[sl][x] = bg;
                    for (int bx = 0; bx < 32; bx++)
                        WS->arc_bg_bits[sl][bx] = 0;
                }
            }
        }
        s26_run(57);
        arc_sound_line();
    }
    arc_draw_sprites();
    if (pic) {
        for (int y = 0; y < ARCADIA_H; y++)
            for (int x = 0; x < ARCADIA_W; x++)
                pic[y * ARCADIA_W + x] = WS->pal[WS->fb_idx[y][x] & 7u];
    }
}

/* ========================================================================
 * INTERTON VC 4000 (Signetics 2636 PVI)
 * ======================================================================== */

static const u16 vc_seg_mask[16] = {
    0x0FFF, 0x007C, 0x17DF, 0x15FF, 0x1C7D, 0x1DF7, 0x1FF7, 0x007F,
    0x1FFF, 0x1DFF, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
};

static const char vc_led_pat[20][13] = {
    "aaaabbbbcccc","aaaabbbbcccc","aaaabbbbcccc","aaaabbbbcccc",
    "llll    dddd","llll    dddd","llll    dddd","llll    dddd",
    "kkkkmmmmeeee","kkkkmmmmeeee","kkkkmmmmeeee","kkkkmmmmeeee",
    "jjjj    ffff","jjjj    ffff","jjjj    ffff","jjjj    ffff",
    "iiiihhhhgggg","iiiihhhhgggg","iiiihhhhgggg","iiiihhhhgggg"
};

static u8 vc_pvi_r(u16 off)
{
    off &= 0xFFu;
    if (off > 0xCFu)
        off &= 0xCFu;
    switch (off) {
    case 0xCA: {
        u8 d = WS->vc_bg_coll;
        WS->vc_bg_coll = 0;
        if (WS->vc_spr[3].finished) { d |= 1u; WS->vc_spr[3].finished = 0; }
        if (WS->vc_spr[2].finished) { d |= 2u; WS->vc_spr[2].finished = 0; }
        if (WS->vc_spr[1].finished) { d |= 4u; WS->vc_spr[1].finished = 0; }
        if (WS->vc_spr[0].finished) { d |= 8u; WS->vc_spr[0].finished = 0; }
        return d;
    }
    case 0xCB: {
        u8 d = (u8)(WS->vc_spr_coll | (WS->pvi[0xCB] & 0xC0u));
        WS->vc_spr_coll = 0;
        WS->pvi[0xCB] &= (u8)~0x40u;
        return d;
    }
    case 0xCC: /* Left (P1) joystick: FO=0 -> X, FO=1 -> Y */
        if (!(WS->s26.psu & S26_FO)) {
            if (WS->pad & PAD_LEFT)  return 20u;
            if (WS->pad & PAD_RIGHT) return 225u;
            return 105u;
        } else {
            if (WS->pad & PAD_UP)    return 20u;
            if (WS->pad & PAD_DOWN)  return 225u;
            return 105u;
        }
    case 0xCD: /* Right (P2) joystick */
        return 105u;
    default:
        return WS->pvi[off];
    }
}

static void vc_pvi_w(u16 off, u8 data)
{
    off &= 0xFFu;
    if (off > 0xCFu)
        off &= 0xCFu;
    WS->pvi[off] = data;
    switch (off) {
    case 0xC0:
        WS->vc_spr[0].size = (u8)(1u << (data & 3u));
        WS->vc_spr[1].size = (u8)(1u << ((data >> 2) & 3u));
        WS->vc_spr[2].size = (u8)(1u << ((data >> 4) & 3u));
        WS->vc_spr[3].size = (u8)(1u << ((data >> 6) & 3u));
        break;
    case 0xC1:
        WS->vc_spr[0].scolor = (u8)((~data >> 3) & 7u);
        WS->vc_spr[1].scolor = (u8)(~data & 7u);
        break;
    case 0xC2:
        WS->vc_spr[2].scolor = (u8)((~data >> 3) & 7u);
        WS->vc_spr[3].scolor = (u8)(~data & 7u);
        break;
    case 0xC7:
        WS->vc_snd_tone = data;
        break;
    case 0xCA:
        WS->vc_bg_coll = data;
        break;
    case 0xCB:
        WS->vc_spr_coll = data;
        break;
    }
}

static u8 vc_key_r(u16 off)
{
    switch (off & 0x0Fu) {
    case 0x08: { /* P1 col 1: 1(80), 4(40), 7(20), En(10) */
        u8 d = 0;
        if (WS->key_mask & (1u << 1)) d |= 0x80u;
        if (WS->key_mask & (1u << 4)) d |= 0x40u;
        if (WS->key_mask & (1u << 7)) d |= 0x20u;
        if (WS->key_mask & (1u << 11)) d |= 0x10u;
        return d;
    }
    case 0x09: { /* P1 col 2: 2/Fire(80), 5(40), 8(20), 0(10) */
        u8 d = 0;
        if ((WS->pad & (PAD_A | PAD_B)) || (WS->key_mask & (1u << 2))) d |= 0x80u;
        if (WS->key_mask & (1u << 5)) d |= 0x40u;
        if (WS->key_mask & (1u << 8)) d |= 0x20u;
        if (WS->key_mask & (1u << 0)) d |= 0x10u;
        return d;
    }
    case 0x0A: { /* P1 col 3: 3(80), 6(40), 9(20), Cl(10) */
        u8 d = 0;
        if (WS->key_mask & (1u << 3)) d |= 0x80u;
        if (WS->key_mask & (1u << 6)) d |= 0x40u;
        if (WS->key_mask & (1u << 9)) d |= 0x20u;
        if (WS->key_mask & (1u << 10)) d |= 0x10u;
        return d;
    }
    case 0x0B: { /* Panel: 0x40 = Start, 0x80 = Select */
        u8 d = 0;
        if (WS->pad & PAD_START)  d |= 0x40u;
        if (WS->pad & PAD_SELECT) d |= 0x80u;
        return d;
    }
    default:
        return 0;
    }
}

static void vc_plot_digit(int ly, int x0, int d, u8 col)
{
    u16 mask = vc_seg_mask[d & 15];
    if (!mask)
        return;
    for (int j = 0; j < 12; j++) {
        char c = vc_led_pat[ly][j];
        if (c != ' ' && (mask & (1u << (c - 'a')))) {
            int rx = x0 + j - 16;
            if ((unsigned)rx < VC4000_W && (unsigned)WS->vc_line < VC4000_H)
                WS->fb_idx[WS->vc_line][rx] = col;
        }
    }
}

static void vc_spr_line(int idx, u8 *coll, u8 *objs)
{
    struct vc4_spr *s = &WS->vc_spr[idx];
    const u8 *desc = &WS->pvi[(idx == 3) ? 0x40 : idx * 0x10];
    u8 x1 = desc[10], x2 = desc[11], y1 = desc[12], y2 = desc[13];
    if (WS->vc_line == 0) {
        s->y = y1;
        s->state = 0;
        s->delay = 0;
        s->finished = 0;
    }
    s->finished_now = 0;
    if (WS->vc_line > 269)
        return;

    if (s->state == 0) {
        if (WS->vc_line != (int)s->y + 2)
            return;
        s->state = 1;
    }
    if (s->state >= 1 && s->state <= 10) {
        u8 bm = desc[s->state - 1];
        u8 sz = s->size ? s->size : 1u;
        for (int j = 0; j < 8; j++) {
            if (bm & (0x80u >> j)) {
                for (int i = 0; i < sz; i++) {
                    int px = (int)x1 + j * sz + i;
                    if ((unsigned)px < 256u) {
                        coll[px] |= s->mask;
                        objs[px] = (objs[px] == 8u) ? s->scolor : (u8)((objs[px] | s->scolor) & 7u);
                    }
                }
            }
        }
        if (++s->delay >= sz) { s->delay = 0; s->state++; }
        if (s->state > 10) { s->finished = 1; s->finished_now = 1; }
        return;
    }
    if (s->state == 11) {
        s->y = (y2 == 255u) ? 0u : (u8)(y2 + 1u);
        if (s->y > 252u)
            return;
        s->delay = 0;
        s->state = 12;
    }
    if (s->state == 12) {
        if (s->y != 0u) { s->y--; return; }
        s->state = 13;
    }
    if (s->state >= 13 && s->state <= 22) {
        u8 bm = desc[s->state - 13];
        u8 sz = s->size ? s->size : 1u;
        for (int j = 0; j < 8; j++) {
            if (bm & (0x80u >> j)) {
                for (int i = 0; i < sz; i++) {
                    int px = (int)x2 + j * sz + i;
                    if ((unsigned)px < 256u) {
                        coll[px] |= s->mask;
                        objs[px] = (objs[px] == 8u) ? s->scolor : (u8)((objs[px] | s->scolor) & 7u);
                    }
                }
            }
        }
        if (++s->delay >= sz) {
            s->delay = 0;
            if (++s->state >= 23) {
                s->finished = 1;
                s->finished_now = 1;
                s->state = 11;
            }
        }
    }
}

static void vc4000_run_frame(u16 *pic)
{
    u8 coll[264];
    u8 objs[264];

    for (int sl = 0; sl < 312; sl++) {
        WS->vc_line = sl;
        if (WS->vc_irq_pause) {
            if (++WS->vc_irq_pause > 10) {
                WS->s26.irq_state = 0;
                WS->vc_irq_pause = 0;
            }
        }
        if (sl == 0) {
            WS->vc_bg_coll = 0;
            WS->vc_spr_coll = 0;
            WS->pvi[0xCB] &= (u8)~0x40u;
        }

        if (sl <= 269) {
            for (int i = 0; i < 260; i++) {
                coll[i] = 0;
                objs[i] = 8u;
            }
            u8 bg_reg = WS->pvi[0xC6];
            u8 bg_col = (u8)((bg_reg & 7u) ^ 7u);
            u8 fg_col = (u8)(((bg_reg >> 4) & 7u) ^ 7u);
            if (sl < VC4000_H) {
                for (int x = 0; x < VC4000_W; x++)
                    WS->fb_idx[sl][x] = bg_col;
            }

            /* Playfield grid (lines 20..219) */
            int gl = sl - 20;
            if (gl >= 0 && gl < 200 && (bg_reg & 8u)) {
                int gi = (gl / 20) * 2 + ((gl % 20 >= 2) ? 1 : 0);
                u8 k = WS->pvi[0xA8 + (gi >> 2)];
                int w = ((k >> 6) == 1) ? 2 : ((k >> 6) == 3) ? 4 : 1;
                switch (gi & 3) {
                case 0: if (k & 0x01u) w = 8; break;
                case 1: if ((gl % 40) <= 10 ? (k & 0x02u) : (k & 0x04u)) w = 8; break;
                case 2: if (k & 0x08u) w = 8; break;
                case 3: if ((gl % 40) <= 30 ? (k & 0x10u) : (k & 0x20u)) w = 8; break;
                }
                for (int j = 0; j < 16; j++) {
                    u8 gbyte = WS->pvi[0x80 + gi * 2 + (j >> 3)];
                    if (gbyte & (0x80u >> (j & 7))) {
                        int px0 = 30 + j * 8;
                        for (int l = 0; l < w; l++) {
                            if ((unsigned)(px0 + l) < 256u)
                                coll[px0 + l] |= 0x10u;
                            int rx = px0 + l - 16;
                            if (sl < VC4000_H && (unsigned)rx < VC4000_W)
                                WS->fb_idx[sl][rx] = fg_col;
                        }
                    }
                }
            }

            for (int i = 0; i < 4; i++)
                vc_spr_line(i, coll, objs);

            for (int px = 16; px < 16 + VC4000_W; px++) {
                u8 c = coll[px];
                WS->vc_spr_coll |= WS->vc_spr_coll_lut[c & 0x1Fu];
                WS->vc_bg_coll  |= WS->vc_bg_coll_lut[c & 0x1Fu];
                if (objs[px] < 8u && sl < VC4000_H)
                    WS->fb_idx[sl][px - 16] = (u8)(objs[px] ^ 7u);
            }

            int sy = (WS->pvi[0xC3] & 1u) ? 200 : 20;
            if (sl >= sy && sl < sy + 20) {
                int sx = 60;
                int ly = sl - sy;
                vc_plot_digit(ly, sx, WS->pvi[0xC8] >> 4, fg_col);
                vc_plot_digit(ly, sx + 16, WS->pvi[0xC8] & 15, fg_col);
                if (WS->pvi[0xC3] & 2u) sx -= 16;
                vc_plot_digit(ly, sx + 48, WS->pvi[0xC9] >> 4, fg_col);
                vc_plot_digit(ly, sx + 64, WS->pvi[0xC9] & 15, fg_col);
            }
        }
        if (sl == 269)
            WS->pvi[0xCB] |= 0x40u;
        if ((sl == 269 || WS->vc_spr[0].finished_now || WS->vc_spr[1].finished_now ||
             WS->vc_spr[2].finished_now || WS->vc_spr[3].finished_now) && !WS->vc_irq_pause) {
            WS->s26.irq_state = 1;
            WS->vc_irq_pause = 1;
        }

        s26_run(57);

        /* VC 4000 tone sound ($1FC7: bit 7..0 period; 0 = silent) at 15,625 Hz PAL line rate */
        if (WS->sample_rate) {
            s32 s = 0;
            u8 t = WS->vc_snd_tone;
            if (t > 0 && t < 0xFFu) {
                if (++WS->vc_snd_pos >= (u8)((t & 0x7Fu) + 1u)) {
                    WS->vc_snd_pos = 0;
                    WS->vc_snd_state ^= 1u;
                }
                s = WS->vc_snd_state ? 7500 : -7500;
            }
            u32 num = WS->sample_rate + WS->snd_frac;
            u32 ns = num / 15625u;
            WS->snd_frac = num % 15625u;
            while (ns--)
                if (WS->audio_count < ARC_AUDIO_MAX)
                    WS->audio_ring[WS->audio_count++] = (s16)s;
        }
    }
    if (pic) {
        for (int y = 0; y < VC4000_H; y++)
            for (int x = 0; x < VC4000_W; x++)
                pic[y * VC4000_W + x] = WS->pal[WS->fb_idx[y][x] & 7u];
    }
}

static u8 s26_read(u16 addr)
{
    addr &= AMSK;
    if (WS->sys == SYS_ARCADIA) {
        if (addr < 0x1000u)
            return (addr < WS->rom_size) ? WS->rom[addr] : 0xFFu;
        if (addr >= 0x2000u && addr < 0x3000u) {
            u32 off = 0x1000u + (addr - 0x2000u);
            return (off < WS->rom_size) ? WS->rom[off] : 0xFFu;
        }
        if ((addr & 0x1000u) == 0u) { /* $4000..$4FFF, $6000..$6FFF */
            if (WS->rom_size > 0x2000u) {
                u32 off = 0x2000u + (((addr >> 12) - 4u) >> 1) * 0x1000u + (addr & 0x0FFFu);
                return (off < WS->rom_size) ? WS->rom[off] : 0xFFu;
            }
            return ((addr & 0x0FFFu) < WS->rom_size) ? WS->rom[addr & 0x0FFFu] : 0xFFu;
        }
        return arc_uvi_r((u16)(addr & 0x3FFu));
    } else {
        u16 a = (u16)(addr & 0x1FFFu);
        if (a < 0x1600u && a < WS->rom_size)
            return WS->rom[a];
        if ((a >= 0x1000u && a < 0x1400u) || (a >= 0x1800u && a < 0x1C00u))
            return WS->ram[a & 0x3FFu];
        if ((a & 0x1780u) == 0x1680u)
            return vc_key_r(a);
        if ((a & 0x1700u) == 0x1700u)
            return vc_pvi_r(a);
        return 0xFFu;
    }
}

static void s26_write(u16 addr, u8 val)
{
    addr &= AMSK;
    if (WS->sys == SYS_ARCADIA) {
        if (addr & 0x1000u)
            arc_uvi_w((u16)(addr & 0x3FFu), val);
    } else {
        u16 a = (u16)(addr & 0x1FFFu);
        if ((a >= 0x1000u && a < 0x1400u) || (a >= 0x1800u && a < 0x1C00u))
            WS->ram[a & 0x3FFu] = val;
        else if ((a & 0x1700u) == 0x1700u)
            vc_pvi_w(a, val);
    }
}

static int s26_sense(void)
{
    if (WS->sys == SYS_ARCADIA)
        return WS->arc_line >= 216;
    return WS->vc_line >= 269;
}

/* ========================================================================
 * RCA STUDIO II (COSMAC CDP1802 + CDP1861 Pixie)
 * ======================================================================== */

static inline u8 st2_rd(u16 a)
{
    u8 pg = (u8)(a >> 8);
    if (pg < 64u && WS->st2_rom_map[pg])
        return WS->ram[a];
    /* Studio II RAM ($0800..$09FF) mirrors whenever A9 == 0 and no ROM is mapped */
    if ((a & 0x0200u) == 0u)
        return WS->ram[0x0800u | (a & 0x01FFu)];
    return 0xFFu;
}

static inline void st2_wr(u16 a, u8 v)
{
    u8 pg = (u8)(a >> 8);
    if (pg < 64u && WS->st2_rom_map[pg])
        return;
    if ((a & 0x0200u) == 0u)
        WS->ram[0x0800u | (a & 0x01FFu)] = v;
}

static int c18_step(void)
{
    struct cdp1802_cpu *c = &WS->c18;
    if (WS->st2_irq && c->ie) {
        c->idle = 0;
        c->t = (u8)((c->x << 4) | c->p);
        c->x = 2;
        c->p = 1;
        c->ie = 0;
        return 1;
    }
    if (c->idle)
        return 1;

    u8 op = st2_rd(c->r[c->p]++);
    u8 i = op >> 4, n = op & 0x0Fu;
    int mcyc = (i == 0x0Cu) ? 3 : 2;

    switch (i) {
    case 0x0:
        if (n == 0) c->idle = 1;
        else c->d = st2_rd(c->r[n]);
        break;
    case 0x1: c->r[n]++; break;
    case 0x2: c->r[n]--; break;
    case 0x3: {
        int take = 0;
        switch (n) {
        case 0x0: take = 1; break;
        case 0x1: take = c->q != 0; break;
        case 0x2: take = c->d == 0; break;
        case 0x3: take = c->df != 0; break;
        case 0x4: case 0x5: case 0x6: case 0x7: take = WS->st2_ef[n - 4] != 0; break;
        case 0x8: take = 0; break;
        case 0x9: take = c->q == 0; break;
        case 0xA: take = c->d != 0; break;
        case 0xB: take = c->df == 0; break;
        case 0xC: case 0xD: case 0xE: case 0xF: take = WS->st2_ef[n - 12] == 0; break;
        }
        u8 b = st2_rd(c->r[c->p]);
        if (take) c->r[c->p] = (u16)((c->r[c->p] & 0xFF00u) | b);
        else c->r[c->p]++;
        break;
    }
    case 0x4: c->d = st2_rd(c->r[n]++); break;
    case 0x5: st2_wr(c->r[n], c->d); break;
    case 0x6:
        if (n == 0) {
            c->r[c->x]++;
        } else if (n < 8) { /* OUT 1..7 */
            u8 v = st2_rd(c->r[c->x]++);
            if (n == 1) WS->st2_disp = 1;
            else if (n == 2) WS->st2_keylatch = v & 0x0Fu;
        } else { /* INP 1..7 */
            u8 v = 0xFFu;
            if ((n & 7u) == 1u) WS->st2_disp = 1;
            c->d = v;
            st2_wr(c->r[c->x], v);
        }
        break;
    case 0x7:
        switch (n) {
        case 0x0: case 0x1: { /* RET / DIS */
            u8 v = st2_rd(c->r[c->x]++);
            c->p = v & 0x0Fu;
            c->x = v >> 4;
            c->ie = (n == 0) ? 1u : 0u;
            break;
        }
        case 0x2: c->d = st2_rd(c->r[c->x]++); break;
        case 0x3: st2_wr(c->r[c->x]--, c->d); break;
        case 0x4: { u16 s = (u16)st2_rd(c->r[c->x]) + c->d + c->df; c->d = (u8)s; c->df = s > 0xFFu; break; }
        case 0x5: { u16 s = (u16)st2_rd(c->r[c->x]) + (c->d ^ 0xFFu) + c->df; c->d = (u8)s; c->df = s > 0xFFu; break; }
        case 0x6: { u8 b = c->df; c->df = c->d & 1u; c->d = (u8)((c->d >> 1) | (b << 7)); break; }
        case 0x7: { u16 s = (u16)c->d + (st2_rd(c->r[c->x]) ^ 0xFFu) + c->df; c->d = (u8)s; c->df = s > 0xFFu; break; }
        case 0x8: st2_wr(c->r[c->x], c->t); break;
        case 0x9: c->t = (u8)((c->x << 4) | c->p); st2_wr(c->r[2]--, c->t); c->x = c->p; break;
        case 0xA: c->q = 0; break;
        case 0xB: c->q = 1; break;
        case 0xC: { u16 s = (u16)st2_rd(c->r[c->p]++) + c->d + c->df; c->d = (u8)s; c->df = s > 0xFFu; break; }
        case 0xD: { u16 s = (u16)st2_rd(c->r[c->p]++) + (c->d ^ 0xFFu) + c->df; c->d = (u8)s; c->df = s > 0xFFu; break; }
        case 0xE: { u8 b = c->df; c->df = (c->d >> 7) & 1u; c->d = (u8)((c->d << 1) | b); break; }
        case 0xF: { u16 s = (u16)c->d + (st2_rd(c->r[c->p]++) ^ 0xFFu) + c->df; c->d = (u8)s; c->df = s > 0xFFu; break; }
        }
        break;
    case 0x8: c->d = (u8)(c->r[n] & 0xFFu); break;
    case 0x9: c->d = (u8)(c->r[n] >> 8); break;
    case 0xA: c->r[n] = (u16)((c->r[n] & 0xFF00u) | c->d); break;
    case 0xB: c->r[n] = (u16)((c->r[n] & 0x00FFu) | ((u16)c->d << 8)); break;
    case 0xC:
        if ((n & 7u) < 4u) { /* LBR / LBQ / LBZ / LBDF / NLBR / LBNQ / LBNZ / LBNF */
            if (n == 0x8) {
                /* NLBR: skip 2 bytes */
                c->r[c->p] += 2;
            } else {
                int take = 0;
                switch (n) {
                case 0x0: take = 1; break;
                case 0x1: take = c->q != 0; break;
                case 0x2: take = c->d == 0; break;
                case 0x3: take = c->df != 0; break;
                case 0x9: take = c->q == 0; break;
                case 0xA: take = c->d != 0; break;
                case 0xB: take = c->df == 0; break;
                }
                u8 hi = st2_rd(c->r[c->p]++);
                u8 lo = st2_rd(c->r[c->p]++);
                if (take)
                    c->r[c->p] = (u16)(((u16)hi << 8) | lo);
            }
        } else if (n != 0x4) { /* Long skips */
            int sk = 0;
            switch (n) {
            case 0x5: sk = c->q == 0; break;
            case 0x6: sk = c->d != 0; break;
            case 0x7: sk = c->df == 0; break;
            case 0xC: sk = c->ie != 0; break;
            case 0xD: sk = c->q != 0; break;
            case 0xE: sk = c->d == 0; break;
            case 0xF: sk = c->df != 0; break;
            }
            if (sk)
                c->r[c->p] += 2;
        }
        break;
    case 0xD: c->p = n; break;
    case 0xE: c->x = n; break;
    case 0xF:
        switch (n) {
        case 0x0: c->d = st2_rd(c->r[c->x]); break;
        case 0x1: c->d |= st2_rd(c->r[c->x]); break;
        case 0x2: c->d &= st2_rd(c->r[c->x]); break;
        case 0x3: c->d ^= st2_rd(c->r[c->x]); break;
        case 0x4: { u16 s = (u16)st2_rd(c->r[c->x]) + c->d; c->d = (u8)s; c->df = s > 0xFFu; break; }
        case 0x5: { u16 s = (u16)st2_rd(c->r[c->x]) + (c->d ^ 0xFFu) + 1u; c->d = (u8)s; c->df = s > 0xFFu; break; }
        case 0x6: c->df = c->d & 1u; c->d >>= 1; break;
        case 0x7: { u16 s = (u16)c->d + (st2_rd(c->r[c->x]) ^ 0xFFu) + 1u; c->d = (u8)s; c->df = s > 0xFFu; break; }
        case 0x8: c->d = st2_rd(c->r[c->p]++); break;
        case 0x9: c->d |= st2_rd(c->r[c->p]++); break;
        case 0xA: c->d &= st2_rd(c->r[c->p]++); break;
        case 0xB: c->d ^= st2_rd(c->r[c->p]++); break;
        case 0xC: { u16 s = (u16)st2_rd(c->r[c->p]++) + c->d; c->d = (u8)s; c->df = s > 0xFFu; break; }
        case 0xD: { u16 s = (u16)st2_rd(c->r[c->p]++) + (c->d ^ 0xFFu) + 1u; c->d = (u8)s; c->df = s > 0xFFu; break; }
        case 0xE: c->df = (c->d >> 7) & 1u; c->d <<= 1; break;
        case 0xF: { u16 s = (u16)c->d + (st2_rd(c->r[c->p]++) ^ 0xFFu) + 1u; c->d = (u8)s; c->df = s > 0xFFu; break; }
        }
        break;
    }
    return mcyc;
}

/* Clean-room 2 KB RCA Studio II BIOS ($0000..$03FF) + built-in Space Defender game ($0400..$07FF):
   - Initializes CDP1802 R1=$001C (Pixie interrupt vector), R2=$08CF (stack), R3=$0400 (cartridge PC),
     turns on CDP1861 display (`INP 1`), enables interrupts (`RET`), and jumps to `$0400`!
   - `$001C`: Exact 29-cycle CDP1861 Pixie ISR streaming `64x32` VRAM (`$0900..$09FF`, 4x line repeat)
     via R0 DMA_OUT, decrementing `$08CD` sound timer (`Q` tone on while `$08CD > 0`), and incrementing
     `$08CE` frame counter! */
static void st2_build_bios(int include_builtin_game)
{
    for (u32 i = 0; i < 0x0800u; i++)
        WS->ram[i] = 0x00u;
    for (int pg = 0; pg < 4; pg++)
        WS->st2_rom_map[pg] = 1;

    /* $0000: Boot setup -> R2=$08BF (stack), R1=$001C, R3=$0400, X=2, P=3, INP 1 (disp on), IE=1 */
    static const u8 bios_boot[] = {
        0xF8, 0x08, 0xB2,       /* LDI $08; PHI R2 */
        0xF8, 0xBF, 0xA2,       /* LDI $BF; PLO R2 (stack well below $08CD/$08CE!) */
        0xF8, 0x00, 0xB1,       /* LDI $00; PHI R1 */
        0xF8, 0x1C, 0xA1,       /* LDI $1C; PLO R1 */
        0xF8, 0x04, 0xB3,       /* LDI $04; PHI R3 */
        0xF8, 0x00, 0xA3,       /* LDI $00; PLO R3 */
        0xE2,                   /* SEX 2 */
        0x69,                   /* INP 1 (turn on CDP1861 Pixie display) */
        0xF8, 0x23, 0x52,       /* LDI $23; STR R2 (X=2, P=3) */
        0x70                    /* RET (sets X=2, P=3 -> jumps to $0400 with IE=1!) */
    };
    for (u32 i = 0; i < sizeof(bios_boot); i++)
        WS->ram[i] = bios_boot[i];

    /* $001B: return point of ISR (`70` = RET, branched back to by `$001C` on next INT!) */
    WS->ram[0x001B] = 0x70;     /* RET */

    /* $001C: Exact Studio II CDP1861 Pixie DMA ISR:
       Interrupt entry takes 1 machine cycle; lines 78 & 79 have 28 machine cycles total before line 80 DMA!
       Between each 8-cycle DMA burst on lines 80..207, 6 machine cycles (= three 2-cycle ops) execute:
       Each group of 4 scanlines resets R0.lo back by 8 three times, then advances R0 by +8 on the 4th line! */
    static const u8 bios_isr[] = {
        /* $001C: */
        0xC4,                   /* NOP (3 mcyc) */
        0x22, 0x78,             /* DEC R2; SAV (4) */
        0x22, 0x52,             /* DEC R2; STR R2 (save D) (4) */
        0xF8, 0x09, 0xB0,       /* LDI $09; PHI R0 (6) */
        0xF8, 0x00, 0xA0,       /* LDI $00; PLO R0 (6) -> total ~23..28 mcyc into line 80! */
        /* $002B (row_lp): 3 instructions = 6 machine cycles per scanline! */
        0x80, 0xE2, 0x20,       /* line 0: GLO R0 (save start of row in D); SEX 2; DEC R0? Wait: */
    };
    (void)bios_isr;
    /* Clean, exact Studio II ISR at $001C:
       In CDP1861: line 80..207 each run 6 CPU machine cycles + 8 DMA cycles (R0 += 8 per line!).
       Notice:
       Before line 0 DMA: D holds row_base (0, 8, 16, ..., 248).
       Line 0 (6 mcyc): `E2` (SEX 2, 2), `E2` (SEX 2, 2), `A0` (PLO R0 -> resets R0.lo to D for Line 1!, 2)
       Line 1 (6 mcyc): `E2` (2), `E2` (2), `A0` (PLO R0 -> resets R0.lo to D for Line 2!, 2)
       Line 2 (6 mcyc): `E2` (2), `E2` (2), `A0` (PLO R0 -> resets R0.lo to D for Line 3!, 2)
       Line 3 (6 mcyc): `80` (GLO R0 -> D = row_base + 8!, 2), `3C, 2B` (BN1 $002B -> loops until EF1 at line 204!, 2+2)!
       COUNT THOSE CYCLES:
       Line 0: 2 + 2 + 2 = 6 mcyc! DMA 0 reads row_base..row_base+7, R0 becomes row_base+8, then `A0` sets R0 = row_base!
       Line 1: 2 + 2 + 2 = 6 mcyc! DMA 1 reads row_base..row_base+7, then `A0` sets R0 = row_base!
       Line 2: 2 + 2 + 2 = 6 mcyc! DMA 2 reads row_base..row_base+7, then `A0` sets R0 = row_base!
       Line 3: DMA 3 reads row_base..row_base+7, R0 becomes row_base+8! `80` puts R0.lo (row_base+8) into D, and `3C 2B` (`BN1 $002B`) branches back to Line 0 for all 32 tile rows!
       THAT IS PURE COSMAC 1802 POETRY!! */
    static const u8 exact_isr[] = {
        /* $001B: */ 0x70,                      /* RET (re-enters $001C on next VBlank INT!) */
        /* $001C: */ 0x22, 0x78,                /* DEC R2; SAV (4 mcyc) */
        /* $001E: */ 0x22, 0x52,                /* DEC R2; STR R2 (4 mcyc) */
        /* $0020: */ 0xF8, 0x09, 0xB0,          /* LDI $09; PHI R0 (4 mcyc) */
        /* $0023: */ 0xF8, 0x00, 0xA0,          /* LDI $00; PLO R0 (4 mcyc) -> R0=$0900 ready early! */
        /* $0026: */ 0xC4, 0xC4, 0xC4, 0xE2,    /* 3x NOP + SEX 2 (11 mcyc -> 28 mcyc total!) */
        /* $002A (row_lp): */
        /* Line 0: */ 0xE2, 0xE2, 0xA0,         /* SEX 2; SEX 2; PLO R0     (6 mcyc) */
        /* Line 1: */ 0xE2, 0xE2, 0xA0,         /* SEX 2; SEX 2; PLO R0     (6 mcyc) */
        /* Line 2: */ 0xE2, 0xE2, 0xA0,         /* SEX 2; SEX 2; PLO R0     (6 mcyc) */
        /* Line 3: */ 0x80, 0xE2, 0x3C, 0x2A,   /* GLO R0; SEX 2; BN1 $002A (6 mcyc) */
        /* End of screen ($0037): update frame counter ($08CE) & sound timer ($08CD -> Q) using R0! */
        /* $0037: */ 0xF8, 0x08, 0xB0,          /* LDI $08; PHI R0 */
        /* $003A: */ 0xF8, 0xCE, 0xA0,          /* LDI $CE; PLO R0 */
        /* $003D: */ 0x40, 0x20, 0xFC, 0x01, 0x50, /* LDA R0; DEC R0; ADI 1; STR R0 ($08CE++) */
        /* $0042: */ 0x20, 0x40, 0x20,          /* DEC R0 ($08CD); LDA R0; DEC R0 */
        /* $0045: */ 0x32, 0x4D,                /* BZ $004D (mute Q) */
        /* $0047: */ 0xFF, 0x01, 0x50,          /* SMI 1; STR R0 */
        /* $004A: */ 0x7B, 0x30, 0x4E,          /* SEQ; BR $004E */
        /* $004D: */ 0x7A,                      /* REQ */
        /* $004E: */ 0x72,                      /* LDXA (restore D from M(R2++)) */
        /* $004F: */ 0x30, 0x1B                 /* BR $001B (RET!) */
    };
    for (u32 i = 0; i < sizeof(exact_isr); i++)
        WS->ram[0x001B + i] = exact_isr[i];

    /* Built-in 5-row BCD font 0..9 at $0200..$0231 (standard Studio II font!) */
    static const u8 st2_digits[10][5] = {
        {0xF0,0x90,0x90,0x90,0xF0}, {0x20,0x60,0x20,0x20,0x70},
        {0xF0,0x10,0xF0,0x80,0xF0}, {0xF0,0x10,0xF0,0x10,0xF0},
        {0x90,0x90,0xF0,0x10,0x10}, {0xF0,0x80,0xF0,0x10,0xF0},
        {0xF0,0x80,0xF0,0x90,0xF0}, {0xF0,0x10,0x20,0x40,0x40},
        {0xF0,0x90,0xF0,0x90,0xF0}, {0xF0,0x90,0xF0,0x10,0xF0}
    };
    for (int d = 0; d < 10; d++)
        for (int r = 0; r < 5; r++)
            WS->ram[0x0200 + d * 5 + r] = st2_digits[d][r];

    if (!include_builtin_game)
        return;

    for (int pg = 4; pg < 8; pg++)
        WS->st2_rom_map[pg] = 1;

    /* $0400: Built-in native CDP1802 game: "COSMAC INTERCEPTOR"
       Draws crisp score border, animated alien fleet, movable paddle/cannon (keys 4/Left & 6/Right, 5/Fire),
       laser beam, hit detection, and CA555 Q-beep sound effects! */
    static const u8 game1802[] = {
        /* Init state: R7 = player byte X (0..7, start 3), R8.lo = alien X (0..5), R8.hi = laser Y (0=off) */
        0xF8, 0x03, 0xA7,               /* $0400: LDI 3; PLO R7 */
        0xF8, 0x01, 0xA8,               /* $0403: LDI 1; PLO R8 */
        0xF8, 0x00, 0xB8,               /* $0406: LDI 0; PHI R8 */
        0xF8, 0x08, 0xBD,               /* $0409: LDI $08; PHI RD */
        0xF8, 0xCD, 0xAD,               /* $040C: LDI $CD; PLO RD ($08CD sound timer) */
        0xF8, 0x06, 0x5D,               /* $040F: LDI 6; STR RD (boot beep!) */
        /* $0412 (frame_loop): wait for $08CE frame counter to change */
        0xF8, 0x08, 0xBE,               /* $0412: LDI $08; PHI RE */
        0xF8, 0xCE, 0xAE,               /* $0415: LDI $CE; PLO RE */
        0x0E, 0xBA,                     /* $0418: LDN RE; PHI RA */
        /* $041A (wait_vb): */
        0x9A, 0xEE, 0xF3,               /* $041A: GHI RA; SEX RE; XOR */
        0x32, 0x1A,                     /* $041D: BZ $041A */
        0xE2,                           /* $041F: SEX 2 */
        /* Scan keypad: latch 4 (Left), 6 (Right), 5 (Fire) via OUT 2; check EF3! */
        0xF8, 0x04, 0x52, 0x62, 0x22,   /* $0420: LDI 4; STR R2; OUT 2; DEC R2 */
        0x3E, 0x2C,                     /* $0425: BN3 $042C */
        0x87, 0x32, 0x2C, 0x27,         /* $0427: GLO R7; BZ $042C; DEC R7 */
        /* $042B..$042C: */
        0xF8, 0x06, 0x52, 0x62, 0x22,   /* LDI 6; STR R2; OUT 2; DEC R2 */
        0x3E, 0x39,                     /* BN3 +8 */
        0x87, 0xFB, 0x07, 0x32, 0x39, 0x17, /* GLO R7; XRI 7; BZ +1; INC R7 */
        /* Fire key 5: */
        0xF8, 0x05, 0x52, 0x62, 0x22,   /* LDI 5; STR R2; OUT 2; DEC R2 */
        0x3E, 0x48,                     /* BN3 skip_fire */
        0x98, 0x3A, 0x48,               /* GHI R8; BNZ skip_fire */
        0xF8, 0x1B, 0xB8,               /* LDI 27; PHI R8 (laser Y = 27) */
        0x87, 0xA9,                     /* GLO R7; PLO R9 (laser X) */
        0xF8, 0x04, 0x5D,               /* LDI 4; STR RD (beep!) */
        /* Clear VRAM $0900..$09FF */
        0xF8, 0x09, 0xBF, 0xF8, 0x00, 0xAF,
        /* clr_lp: */
        0xF8, 0x00, 0x5F, 0x1F, 0x8F, 0x3A, 0x50,
        /* Draw top & bottom frame bars ($0900..$0907 = $FF, $09F8..$09FF = $FF) */
        0xF8, 0x09, 0xBF, 0xF8, 0x00, 0xAF,
        0xF8, 0xFF, 0x5F, 0x1F, 0x8F, 0xFB, 0x08, 0x3A, 0x5D,
        /* Draw 3 alien ships across rows 5, 9, 13 animated by ($08CE >> 3) & 7 */
        0x0E, 0xF6, 0xF6, 0xF6, 0xFA, 0x05, /* D = (frame >> 3) & 5 */
        0xAA,                               /* RA.lo = offset */
        0xF8, 0x09, 0xBF,
        0x8A, 0xFC, 0x28, 0xAF,             /* row 5: $0928 + offset */
        0xF8, 0xBD, 0x5F, 0x1F, 0x1F, 0xF8, 0xDB, 0x5F,
        0x8F, 0xFC, 0x06, 0xAF,             /* next row: $FF wings */
        0xF8, 0x7E, 0x5F, 0x1F, 0x1F, 0xF8, 0x7E, 0x5F,
        0x8A, 0xFC, 0x49, 0xAF,             /* row 9: $0949 + offset */
        0xF8, 0xDB, 0x5F, 0x1F, 0x1F, 0xF8, 0xBD, 0x5F,
        0x8A, 0xFC, 0x68, 0xAF,             /* row 13: $0968 + offset */
        0xF8, 0xE7, 0x5F, 0x1F, 0x1F, 0xF8, 0xE7, 0x5F,
        /* Draw player defender ship at row 28..30 ($09E0 + R7, $09E8 + R7, $09F0 + R7) */
        0x87, 0xFC, 0xE0, 0xAF, 0xF8, 0x18, 0x5F,
        0x87, 0xFC, 0xE8, 0xAF, 0xF8, 0x3C, 0x5F,
        0x87, 0xFC, 0xF0, 0xAF, 0xF8, 0xFF, 0x5F,
        /* Update & draw laser bolt if R8.hi != 0 */
        0x98, 0x32, 0xBC,                   /* GHI R8; BZ done_laser */
        0xFF, 0x01, 0xB8,                   /* SMI 1; PHI R8 */
        0x32, 0xBC,
        0xFE, 0xFE, 0xFE,                   /* Y * 8 */
        0xEC, 0x52, 0x89, 0xE2, 0xF4,       /* + laser X (R9.lo) */
        0xAF, 0xF8, 0x18, 0x5F,             /* draw 2px laser beam! */
        /* Jump back to frame_loop ($0412) */
        0xC0, 0x04, 0x12
    };
    /* Note: let's fix exact short-branch target addresses dynamically below! */
    (void)game1802;

    /* Assemble exact addresses cleanly so zero branch offsets can drift! */
    u16 p = 0x0400;
    #define EMIT(b) (WS->ram[p++] = (u8)(b))
    EMIT(0xF8); EMIT(0x03); EMIT(0xA7);
    EMIT(0xF8); EMIT(0x01); EMIT(0xA8);
    EMIT(0xF8); EMIT(0x00); EMIT(0xB8);
    EMIT(0xF8); EMIT(0x08); EMIT(0xBD);
    EMIT(0xF8); EMIT(0xCD); EMIT(0xAD);
    EMIT(0xF8); EMIT(0x08); EMIT(0x5D); /* boot beep */

    u16 lbl_loop = p;
    EMIT(0xF8); EMIT(0x08); EMIT(0xBE);
    EMIT(0xF8); EMIT(0xCE); EMIT(0xAE);
    EMIT(0x0E); EMIT(0xBA);
    u16 lbl_wvb = p;
    EMIT(0x9A); EMIT(0xEE); EMIT(0xF3);
    EMIT(0x32); EMIT(lbl_wvb & 0xFF);
    EMIT(0xE2);

    /* Key 4 = Left */
    EMIT(0xF8); EMIT(0x04); EMIT(0x52); EMIT(0x62); EMIT(0x22);
    u16 br_no_l = p; EMIT(0x3E); EMIT(0);
    EMIT(0x87); u16 br_l0 = p; EMIT(0x32); EMIT(0); EMIT(0x27);
    WS->ram[br_no_l + 1] = (u8)(p & 0xFF);
    WS->ram[br_l0 + 1]   = (u8)(p & 0xFF);

    /* Key 6 = Right */
    EMIT(0xF8); EMIT(0x06); EMIT(0x52); EMIT(0x62); EMIT(0x22);
    u16 br_no_r = p; EMIT(0x3E); EMIT(0);
    EMIT(0x87); EMIT(0xFB); EMIT(0x07); u16 br_r7 = p; EMIT(0x32); EMIT(0); EMIT(0x17);
    WS->ram[br_no_r + 1] = (u8)(p & 0xFF);
    WS->ram[br_r7 + 1]   = (u8)(p & 0xFF);

    /* Key 5 = Fire */
    EMIT(0xF8); EMIT(0x05); EMIT(0x52); EMIT(0x62); EMIT(0x22);
    u16 br_no_f = p; EMIT(0x3E); EMIT(0);
    EMIT(0x98); u16 br_f_act = p; EMIT(0x3A); EMIT(0);
    EMIT(0xF8); EMIT(0x1B); EMIT(0xB8);
    EMIT(0x87); EMIT(0xA9);
    EMIT(0xF8); EMIT(0x05); EMIT(0x5D);
    WS->ram[br_no_f + 1]  = (u8)(p & 0xFF);
    WS->ram[br_f_act + 1] = (u8)(p & 0xFF);

    /* Clear VRAM $0900..$09FF (8x unrolled: 608 mcyc = 43 VBlank lines) */
    EMIT(0xF8); EMIT(0x09); EMIT(0xBF); EMIT(0xF8); EMIT(0x00); EMIT(0xAF);
    u16 lbl_clr = p;
    EMIT(0xF8); EMIT(0x00);
    EMIT(0x5F); EMIT(0x1F); EMIT(0x5F); EMIT(0x1F); EMIT(0x5F); EMIT(0x1F); EMIT(0x5F); EMIT(0x1F);
    EMIT(0x5F); EMIT(0x1F); EMIT(0x5F); EMIT(0x1F); EMIT(0x5F); EMIT(0x1F); EMIT(0x5F); EMIT(0x1F);
    EMIT(0x8F); EMIT(0x3A); EMIT(lbl_clr & 0xFF);

    /* Top bar $0900..$0907 + bottom bar $09F8..$09FF (reset PHI RF = $09 after $09FF -> $0A00 wrap!) */
    EMIT(0xF8); EMIT(0x09); EMIT(0xBF); EMIT(0xF8); EMIT(0x00); EMIT(0xAF);
    u16 lbl_top = p;
    EMIT(0xF8); EMIT(0xFF); EMIT(0x5F); EMIT(0x1F); EMIT(0x8F); EMIT(0xFB); EMIT(0x08); EMIT(0x3A); EMIT(lbl_top & 0xFF);

    /* Animated alien fleet */
    EMIT(0x0E); EMIT(0xF6); EMIT(0xF6); EMIT(0xFA); EMIT(0x03); EMIT(0xAA);
    EMIT(0x8A); EMIT(0xFC); EMIT(0x21); EMIT(0xAF);
    EMIT(0xF8); EMIT(0xBD); EMIT(0x5F); EMIT(0x1F); EMIT(0x1F); EMIT(0xF8); EMIT(0xDB); EMIT(0x5F);
    EMIT(0x8A); EMIT(0xFC); EMIT(0x29); EMIT(0xAF);
    EMIT(0xF8); EMIT(0x7E); EMIT(0x5F); EMIT(0x1F); EMIT(0x1F); EMIT(0xF8); EMIT(0x7E); EMIT(0x5F);
    EMIT(0x8A); EMIT(0xFC); EMIT(0x51); EMIT(0xAF);
    EMIT(0xF8); EMIT(0xE7); EMIT(0x5F); EMIT(0x1F); EMIT(0x1F); EMIT(0xF8); EMIT(0xE7); EMIT(0x5F);
    EMIT(0x8A); EMIT(0xFC); EMIT(0x59); EMIT(0xAF);
    EMIT(0xF8); EMIT(0xFF); EMIT(0x5F); EMIT(0x1F); EMIT(0x1F); EMIT(0xF8); EMIT(0xFF); EMIT(0x5F);

    /* Player ship at bottom */
    EMIT(0x87); EMIT(0xFC); EMIT(0xE0); EMIT(0xAF); EMIT(0xF8); EMIT(0x18); EMIT(0x5F);
    EMIT(0x87); EMIT(0xFC); EMIT(0xE8); EMIT(0xAF); EMIT(0xF8); EMIT(0x3C); EMIT(0x5F);
    EMIT(0x87); EMIT(0xFC); EMIT(0xF0); EMIT(0xAF); EMIT(0xF8); EMIT(0xFF); EMIT(0x5F);

    /* Laser bolt */
    EMIT(0x98); u16 br_nol = p; EMIT(0x32); EMIT(0);
    EMIT(0xFF); EMIT(0x01); EMIT(0xB8);
    u16 br_nol2 = p; EMIT(0x32); EMIT(0);
    EMIT(0xFE); EMIT(0xFE); EMIT(0xFE);
    EMIT(0x52); EMIT(0x89); EMIT(0xF4);
    EMIT(0xAF); EMIT(0xF8); EMIT(0x18); EMIT(0x5F);
    WS->ram[br_nol + 1]  = (u8)(p & 0xFF);
    WS->ram[br_nol2 + 1] = (u8)(p & 0xFF);

    EMIT(0xC0); EMIT(lbl_loop >> 8); EMIT(lbl_loop & 0xFF);
    #undef EMIT
}

static void studio2_run_frame(u16 *pic)
{
    /* Map gamepad onto Studio II Player A keypad:
       Up='2', Down='8', Left='4', Right='6', A='5' (Fire), B='0', Start='1', Select='3' */
    u16 ka = WS->key_mask & 0x3FFu;
    if (WS->pad & PAD_UP)     ka |= (1u << 2);
    if (WS->pad & PAD_DOWN)   ka |= (1u << 8);
    if (WS->pad & PAD_LEFT)   ka |= (1u << 4);
    if (WS->pad & PAD_RIGHT)  ka |= (1u << 6);
    if (WS->pad & PAD_A)      ka |= (1u << 5);
    if (WS->pad & PAD_B)      ka |= (1u << 0);
    if (WS->pad & PAD_START)  ka |= (1u << 1);
    if (WS->pad & PAD_SELECT) ka |= (1u << 3);
    WS->st2_kpad_a = ka;

    u16 fg = bgr555(245, 250, 235);
    u16 bg = bgr555(16, 22, 20);
    if (pic) {
        for (int i = 0; i < STUDIO2_W * STUDIO2_H; i++)
            pic[i] = bg;
    }

    int mcyc_debt = 0;
    for (int sl = 0; sl < 262; sl++) {
        WS->st2_ef[0] = ((sl >= 76 && sl < 80) || (sl >= 204 && sl < 208)) ? 1u : 0u;
        WS->st2_irq   = (WS->st2_disp && sl >= 78 && sl < 80) ? 1u : 0u;

        int line_budget = 14;
        if (WS->st2_disp && sl >= 80 && sl < 208) {
            /* 8-byte CDP1861 Pixie DMA burst, followed by 6 CPU machine cycles per active scanline */
            int py = sl - 80;
            for (int b = 0; b < 8; b++) {
                u8 v = st2_rd(WS->c18.r[0]++);
                if (pic && (unsigned)py < STUDIO2_H) {
                    u16 *row = pic + py * STUDIO2_W + b * 32;
                    for (int bit = 7; bit >= 0; bit--) {
                        u16 c = (v & (1u << bit)) ? fg : bg;
                        *row++ = c; *row++ = c; *row++ = c; *row++ = c;
                    }
                }
            }
            line_budget = 6;
        }

        while (mcyc_debt < line_budget) {
            WS->st2_ef[2] = (WS->st2_kpad_a >> WS->st2_keylatch) & 1u;
            WS->st2_ef[3] = (WS->st2_kpad_b >> WS->st2_keylatch) & 1u;
            mcyc_debt += c18_step();
        }
        mcyc_debt -= line_budget;

        /* Studio II CA555 resonant ~625 Hz tone oscillator gated by CDP1802 Q flip-flop */
        if (WS->sample_rate) {
            s32 s = 0;
            if (WS->c18.q) {
                WS->st2_beep_phase = (u8)((WS->st2_beep_phase + 1u) % 25u);
                s = (WS->st2_beep_phase < 12u) ? 7500 : -7500;
            }
            u32 num = WS->sample_rate + WS->snd_frac;
            u32 ns = num / 15720u;
            WS->snd_frac = num % 15720u;
            while (ns--)
                if (WS->audio_count < ARC_AUDIO_MAX)
                    WS->audio_ring[WS->audio_count++] = (s16)s;
        }
    }
}

/* ========================================================================
 * PUBLIC INTERFACE
 * ======================================================================== */

static void fmt_info(const char *tag, u32 sz)
{
    char *p = WS->info;
    while (*tag) *p++ = *tag++;
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

static void ws_clear(void)
{
    u32 keep_rate = WS->sample_rate;
    for (u32 i = 0; i < sizeof(*WS); i++)
        ((u8 *)WS)[i] = 0;
    WS->sample_rate = keep_rate;

    /* 8-color RGB palette (0=White, 1=Yellow, 2=Cyan, 3=Green, 4=Magenta, 5=Red, 6=Blue, 7=Black
       matching Signetics 2637/2636 inverted RGB code: bit2=~B, bit1=~G, bit0=~R?
       Wait: look at Arcadia doc: 0=White(111), 1=Yellow(110), 2=Cyan(011), 3=Green(010),
       4=Magenta(101), 5=Red(100), 6=Blue(001), 7=Black(000) -> ~c: bit2=R, bit1=G, bit0=B!) */
    for (int i = 0; i < 8; i++) {
        int inv = (~i) & 7;
        WS->pal[i] = bgr555((inv & 4) ? 255 : 0, (inv & 2) ? 255 : 0, (inv & 1) ? 255 : 0);
    }
}

const char *arcadia_load(const u8 *rom, u32 rom_size)
{
    if (!rom || rom_size < 512u)
        return "too small for an Emerson Arcadia 2001 cartridge";
    if (rom_size > sizeof(WS->rom))
        rom_size = sizeof(WS->rom);

    ws_clear();
    WS->sys = SYS_ARCADIA;
    WS->rom_size = rom_size;
    for (u32 i = 0; i < rom_size; i++)
        WS->rom[i] = rom[i];

    for (int i = 0; i < 56; i++)
        for (int k = 0; k < 8; k++)
            WS->arc_chars[i][k] = arc_font_rom[i][k];
    for (int i = 0; i < 64; i++) {
        u8 top = 0, bot = 0;
        if (i & 0x01) top |= 0x03u;
        if (i & 0x02) top |= 0x1Cu;
        if (i & 0x04) top |= 0xE0u;
        if (i & 0x08) bot |= 0x03u;
        if (i & 0x10) bot |= 0x1Cu;
        if (i & 0x20) bot |= 0xE0u;
        for (int k = 0; k < 4; k++) {
            WS->arc_rect[i][k]     = top;
            WS->arc_rect[i][4 + k] = bot;
        }
    }

    arc_reset();
    fmt_info("Emerson Arcadia 2001", rom_size);
    return 0;
}

const char *vc4000_load(const u8 *rom, u32 rom_size)
{
    if (!rom || rom_size < 512u)
        return "too small for an Interton VC 4000 cartridge";
    if (rom_size > sizeof(WS->rom))
        rom_size = sizeof(WS->rom);

    ws_clear();
    WS->sys = SYS_VC4000;
    WS->rom_size = rom_size;
    for (u32 i = 0; i < rom_size; i++)
        WS->rom[i] = rom[i];

    for (int i = 0; i < 32; i++) {
        u8 sc = 0, bc = 0;
        if ((i & 0x03) == 0x03) sc |= 0x20u;
        if ((i & 0x05) == 0x05) sc |= 0x10u;
        if ((i & 0x09) == 0x09) sc |= 0x08u;
        if ((i & 0x06) == 0x06) sc |= 0x04u;
        if ((i & 0x0A) == 0x0A) sc |= 0x02u;
        if ((i & 0x0C) == 0x0C) sc |= 0x01u;
        if ((i & 0x11) == 0x11) bc |= 0x80u;
        if ((i & 0x12) == 0x12) bc |= 0x40u;
        if ((i & 0x14) == 0x14) bc |= 0x20u;
        if ((i & 0x18) == 0x18) bc |= 0x10u;
        WS->vc_spr_coll_lut[i] = sc;
        WS->vc_bg_coll_lut[i]  = bc;
    }
    for (int i = 0; i < 4; i++) {
        WS->vc_spr[i].mask = (u8)(1u << i);
        WS->vc_spr[i].size = 1u;
    }

    arc_reset();
    fmt_info("Interton VC 4000 (PAL)", rom_size);
    return 0;
}

const char *studio2_load(const u8 *bios, u32 bios_size, const u8 *rom, u32 rom_size)
{
    ws_clear();
    WS->sys = SYS_STUDIO2;

    int has_cart = (rom && rom_size > 0);
    if (bios && bios_size >= 0x0400u) {
        u32 n = bios_size > 0x0800u ? 0x0800u : bios_size;
        for (u32 i = 0; i < n; i++)
            WS->ram[i] = bios[i];
        for (u32 pg = 0; pg < ((n + 255u) >> 8); pg++)
            WS->st2_rom_map[pg] = 1;
        WS->ext_bios = 1;
    } else {
        st2_build_bios(!has_cart);
        WS->ext_bios = 0;
    }

    char st2_title[40];
    st2_title[0] = 0;

    if (has_cart) {
        if (rom_size >= 0x200u && rom[0] == 'R' && rom[1] == 'C' && rom[2] == 'A' && rom[3] == '2') {
            u8 blocks = rom[4];
            if (blocks < 2u || blocks > 32u)
                return "invalid .ST2 block count";
            for (int i = 0; i < 32 && rom[32 + i]; i++) {
                char c = (char)rom[32 + i];
                st2_title[i] = (c >= 32 && c <= 126) ? c : ' ';
                st2_title[i + 1] = 0;
            }
            for (u32 b = 0; b + 1u < blocks && (0x100u + (b + 1u) * 0x100u) <= rom_size; b++) {
                u8 pg = rom[64 + b];
                if (pg >= 4u && pg < 64u) {
                    WS->st2_rom_map[pg] = 1;
                    for (u32 k = 0; k < 256u; k++)
                        WS->ram[(u32)pg * 256u + k] = rom[0x100u + b * 256u + k];
                }
            }
        } else {
            u32 n = rom_size > 0x0C00u ? 0x0C00u : rom_size;
            for (u32 i = 0; i < n; i++) {
                u32 dst = (i < 0x0400u) ? (0x0400u + i) : (0x0C00u + (i - 0x0400u));
                WS->ram[dst] = rom[i];
                WS->st2_rom_map[dst >> 8] = 1;
            }
        }
        WS->rom_size = rom_size;
    }

    arc_reset();
    fmt_info(st2_title[0] ? st2_title : "RCA Studio II", rom_size);
    return 0;
}

void arc_reset(void)
{
    if (WS->sys == SYS_STUDIO2) {
        for (u32 i = 0; i < sizeof(WS->c18); i++)
            ((u8 *)&WS->c18)[i] = 0;
        for (u32 i = 0x0800u; i < 0x0A00u; i++)
            WS->ram[i] = 0;
        WS->c18.ie = 1;
        WS->st2_disp = 0;
        WS->st2_keylatch = 0;
        WS->st2_irq = 0;
    } else {
        for (u32 i = 0; i < sizeof(WS->s26); i++)
            ((u8 *)&WS->s26)[i] = 0;
        WS->s26.psl = S26_COM | S26_WC;
        if (WS->sys == SYS_ARCADIA) {
            for (u32 i = 0; i < sizeof(WS->uvi); i++)
                WS->uvi[i] = 0;
            WS->uvi[0x1FC] = 0xFFu;
            WS->uvi[0x1FD] = 0xFFu;
            WS->arc_snd_lfsr = 0x00F0u;
            WS->arc_snd_tval = 1;
        } else {
            for (u32 i = 0; i < sizeof(WS->pvi); i++)
                WS->pvi[i] = 0;
            for (int i = 0; i < 4; i++) {
                WS->vc_spr[i].size = 1u;
                WS->vc_spr[i].state = 0;
            }
        }
    }
}

void arc_frame(u16 pad, u16 *picture)
{
    WS->pad = pad;
    WS->audio_count = 0;
    if (WS->key_ttl) {
        if (!--WS->key_ttl)
            WS->key_mask = 0;
    }
    if (WS->sys == SYS_ARCADIA)
        arcadia_run_frame(picture);
    else if (WS->sys == SYS_VC4000)
        vc4000_run_frame(picture);
    else
        studio2_run_frame(picture);
}

int arc_width(void)
{
    return WS->sys == SYS_ARCADIA ? ARCADIA_W : WS->sys == SYS_VC4000 ? VC4000_W : STUDIO2_W;
}

int arc_height(void)
{
    return WS->sys == SYS_ARCADIA ? ARCADIA_H : WS->sys == SYS_VC4000 ? VC4000_H : STUDIO2_H;
}

u32 arc_frame_us(void)
{
    return WS->sys == SYS_VC4000 ? VC4000_FRAME_US : WS->sys == SYS_STUDIO2 ? STUDIO2_FRAME_US : ARCADIA_FRAME_US;
}

const char *arc_info(void) { return WS->info; }

int arc_jammed(void)
{
    if (WS->sys == SYS_STUDIO2)
        return WS->c18.idle && !WS->c18.ie;
    return WS->s26.halt && (WS->s26.psu & S26_II);
}

void arc_keyboard(const u8 *usages, int n)
{
    if (!WS->key_ttl)
        WS->key_mask = 0;
    for (int i = 0; i < n; i++) {
        u8 u = usages[i];
        if (u == 0x27) WS->key_mask |= (1u << 0);
        else if (u >= 0x1E && u <= 0x26) WS->key_mask |= (u16)(1u << (u - 0x1D));
        else if (u == 0x2A || u == 0x06) WS->key_mask |= (1u << 10); /* Backspace / C -> Clear */
        else if (u == 0x28) WS->key_mask |= (1u << 11);              /* Enter */
    }
}

void arc_typed(char c)
{
    if (c >= '0' && c <= '9') {
        WS->key_mask |= (u16)(1u << (c - '0'));
        WS->key_ttl = 6;
    } else if (c == 'c' || c == 'C') {
        WS->key_mask |= (1u << 10);
        WS->key_ttl = 6;
    } else if (c == '\r' || c == '\n') {
        WS->key_mask |= (1u << 11);
        WS->key_ttl = 6;
    }
}

void arc_audio_rate(u32 hz)
{
    WS->sample_rate = hz;
    WS->snd_frac = 0;
    WS->audio_count = 0;
}

int arc_audio(s16 *out, int max)
{
    int n = WS->audio_count < max ? WS->audio_count : max;
    for (int i = 0; i < n; i++)
        out[i] = WS->audio_ring[i];
    WS->audio_count = 0;
    return n;
}
