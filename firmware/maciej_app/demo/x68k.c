/* Sharp X68000 home computer / arcade workstation (1987): see x68k.h.
   - 10 MHz Motorola MC68000 (24-bit bus, /BERR on unmapped expansion & >2 MB RAM probe)
   - 2 MB Main RAM ($000000..$1FFFFF), 512 KB Graphic VRAM ($C00000..$DFFFFF: 16c / 256c / 65536c / 1024x1024),
     512 KB 4-plane Text VRAM ($E00000..$E7FFFF with CRTC R21 multi-plane write, R23 bitmask & R22 raster copy),
     16 KB CMOS SRAM ($ED0000..$ED3FFF)
   - CRTC ($E80000) + Video Controller ($E82000: G5R5B5I1 Graphic & Text/Sprite palettes, layer priority)
   - Cynthia Sprite & BG chip ($EB0000: 128 16x16 sprites, BG0/BG1 8x8 & 16x16 tilemaps, 32 KB PCG RAM)
   - MC68901 MFP ($E88000: VDISP/HSYNC/CRTC-IRQ/FM-IRQ, Timers A/B/C/D, Keyboard USART)
   - HD63450 4-ch DMAC ($E84000: FDD, SASI, Mem, ADPCM normal/array/link-array chain)
   - NEC uPD72065 FDC ($E94000) + IOSC ($E9C000) + SASI HDD ($E96000) + RP5C15 RTC ($E8A000) + 8255 PPI ($E9A000)
   - 4.000 MHz Yamaha YM2151 OPM ($E90000) + OKI MSM6258V 4-bit ADPCM ($E92000) mixed at 48 kHz
   - Optional external iplrom.dat (128 KB) & cgrom.dat (768 KB), plus built-in clean-room IPL/IOCS ROM & CGROM */
#pragma GCC optimize("O2")
#include "x68k.h"
#include "font5x7.h"

#ifndef X68K_HOST
#include "hw.h"
#endif

typedef signed char s8;
typedef signed int s32;
typedef long long s64;
typedef unsigned long long u64;

#define INLINE static inline __attribute__((always_inline))

/* ---- Memory & Work Buffer Layout ---- */
#define X68K_RAM_SIZE   0x200000u       /* 2 MB Main RAM */
#define X68K_TVRAM_SIZE 0x080000u       /* 512 KB Text VRAM (4 x 128 KB planes) */
#define X68K_PCG_SIZE   0x008000u       /* 32 KB Sprite/BG PCG + tilemap RAM ($EB8000..$EBFFFF) */
#define X68K_SRAM_SIZE  0x004000u       /* 16 KB battery-backed SRAM ($ED0000..$ED3FFF) */
#define X68K_IPL_SIZE   0x020000u       /* 128 KB IPL/IOCS ROM ($FE0000..$FFFFFF) */
#define X68K_CG_MAX     0x0C0000u       /* 768 KB CGROM ($F00000..$FBFFFF) */
#define X68K_DISK_MAX   0x160000u       /* Up to 1.375 MB unpacked floppy per drive (2HD = 1,261,568 B) */
#define X68K_SND_RING   8192

#define X68K_CPU_HZ     10000000u       /* 10 MHz MC68000 */
#define X68K_LINES      568             /* 31.5 kHz: 512 active + 56 blanking (~55.45 Hz) */
#define X68K_VIS_LINES  512
#define X68K_CYC_LINE   318             /* ~180,624 cycles/frame @ 55.45 Hz */

#define M68K_BUS_ERROR
static u32 x68k_int_vec(u32 level);
static void x68k_iack(u32 level);
#define M68K_INT_VEC(level) x68k_int_vec(level)
#define M68K_IACK(level)    x68k_iack(level)

struct x68k_dmac_ch {
    u8 csr, cer, dcr, ocr, scr, ccr, niv, eiv, cpr;
    u16 mtc, btc;
    u32 mar, dar, bar;
};

struct x68k_mfp {
    u8 gpip_in, aer, ddr;
    u8 iera, ierb, ipra, iprb, isra, isrb, imra, imrb, vr;
    u8 tacr, tbcr, tcdcr;
    u8 tadr, tbdr, tcdr, tddr;
    u8 ta_reload, tb_reload, tc_reload, td_reload;
    s32 ta_acc, tb_acc, tc_acc, td_acc;
    u8 usart_rsr, usart_tsr, usart_udr;
};

struct x68k_fdc {
    u8 msr, cmd, st0, st1, st2, st3;
    u8 buf[16], res[16];
    u8 buf_len, buf_need, res_len, res_pos;
    u8 cur_c[2], cur_h[2], cur_r[2], cur_n[2];
    u8 drv_sel, motor, opt_stat, irq;
};

struct x68k_disk {
    u8 present, is_dim, media, dirty;
    u8 trk_present[256];
    u32 raw_size;
    u8 bps_shift;                       /* 10 = 1024 B, 9 = 512 B */
    u8 spt, heads, tracks;
};

#include "ym2151.inc"

struct x68k_mem {
    u8 ram[X68K_RAM_SIZE];              /* Word-swapped 2 MB Main RAM */
    u16 gvram[512 * 512];               /* 512 KB Graphic VRAM (512x512 x 16-bit) */
    u8 tvram[X68K_TVRAM_SIZE];          /* 4 x 128 KB Text VRAM planes (big-endian bytes) */
    u8 spr_reg[0x400];                  /* 128 x 8 B Sprite attributes ($EB0000..$EB03FF, big-endian) */
    u8 pcg[X68K_PCG_SIZE];              /* 32 KB PCG + BG0/BG1 RAM ($EB8000..$EBFFFF, big-endian) */
    u8 sram[X68K_SRAM_SIZE];            /* 16 KB CMOS SRAM ($ED0000..$ED3FFF, big-endian) */
    u8 ipl[X68K_IPL_SIZE];              /* Word-swapped 128 KB IPL/IOCS ROM ($FE0000..$FFFFFF) */
    u8 cg[X68K_CG_MAX];                 /* 768 KB CGROM ($F00000..$FBFFFF, big-endian) */
    u8 disk0[X68K_DISK_MAX];            /* Unpacked Drive 0 floppy image */
    u8 disk1[X68K_DISK_MAX];            /* Unpacked Drive 1 floppy image */
    s16 snd_ring[X68K_SND_RING];
};

#ifdef X68K_HOST
static struct x68k_mem x68k_host_mem;
#define M (&x68k_host_mem)
#else
/* Total struct x68k_mem = ~6.85 MB, fits comfortably inside 9.5 MB EMU_RAM_PHYS (zero .bss!) */
#define M ((struct x68k_mem *)KSEG0(EMU_RAM_PHYS))
#endif

#pragma GCC optimize("O2")
#include "m68k.inc"

static struct {
    u8 cpu_inited;
    u8 has_ext_ipl, has_ext_cg, has_ext_disk2;
    const u8 *ext_ipl, *ext_cg, *ext_disk2;
    u32 ext_ipl_sz, ext_cg_sz, ext_disk2_sz;
    const u8 *hdd_img;
    u32 hdd_size;
    u8 boot_is_hdd, boot_is_x, jammed_flag, sram_dirty, sram_unlock;
    char info_str[96];

    /* Video: CRTC, VC, Cynthia */
    u16 crtc[24];
    u16 crtc_op;                        /* $E80480: bit 3 = raster copy, bit 1 = fast GVRAM clear */
    u16 vc_r0, vc_r1, vc_r2;
    u16 gpal[256], tpal[256];           /* Raw X68000 G5R5B5I1 words */
    u16 gpal15[256], tpal15[256];       /* Preconverted 0bbbbbgggggrrrrr words */
    u16 bg_reg[9];                      /* $EB0800..$EB0810 */
    int out_w, out_h, cur_line, in_vdisp;
    u8 sys_contrast, sys_tvctrl, sys_keyctrl;

    /* Peripherals */
    struct x68k_mfp mfp;
    struct x68k_dmac_ch dmac[4];
    u8 dmac_gcr;
    struct x68k_fdc fdc;
    struct x68k_disk drv[2];
    u8 iosc_stat, iosc_en, iosc_vec;    /* $E9C001 / $E9C003 (IRQ 1) */

    /* SASI Hard Disk ($E96000) */
    u8 sasi_phase, sasi_cmd[6], sasi_cmd_pos, sasi_status, sasi_msg;
    u32 sasi_off, sasi_rem;

    /* Keyboard, Mouse, Joypad & Console state */
    u16 pad_now;
    u8 key_bits[16];                    /* 128 X68000 scancodes held bitmap (groups 0..15) */
    u8 hid_bits[16], pad_bits[16], prev_eff_bits[16];
    u8 kbd_rx[64];                      /* MFP USART scancode FIFO */
    u8 kbd_rx_r, kbd_rx_w;
    u16 iocs_key_q[64];                 /* (scan<<8)|ascii queue for IOCS _B_KEYINP / _B_KEYSNS */
    u8 ikq_r, ikq_w;
    char type_q[128];
    u8 tq_r, tq_w, tq_hold, tq_code;
    s16 mouse_dx, mouse_dy;
    u8 mouse_btn, scc_reg_sel, scc_pkt[3], scc_pkt_len, scc_pkt_pos;
    u8 ppi_porta, ppi_portb, ppi_portc, ppi_ctrl;

    /* IOCS text console & graphics state */
    u16 cur_x, cur_y, con_y0, con_h, txt_color;
    u8 crt_mode, esc_state, esc_params[4], esc_n;
    u16 apage, vpage_mask;
    u32 opm_iocs_cb, timerd_iocs_cb;

    /* Audio: 4 MHz YM2151 OPM + OKI MSM6258V ADPCM */
    struct ym2151 opm;
    struct {
        u8 play, rec, nib_hi, cur_byte, has_byte;
        s32 est, step_idx;
        u32 phase, step_48k;
        s32 out_sample;
        s32 dma_cyc_acc, dma_cyc_per_byte;
    } adpcm;
    u32 snd_rate, snd_rendered, snd_r, snd_w;
    u32 frame_count;
} X;

/* Convert X68000 G5R5B5I1 color to 15-bit 0bbbbbgggggrrrrr */
INLINE u16 x68k_col15(u16 c)
{
    return (u16)(((c >> 6) & 0x03FFu) | ((c & 0x003Eu) << 9));
}

/* Big-endian access helpers on word-swapped m68k RAM/ROM */
INLINE u8 ram_rb(u32 a)  { return M->ram[(a & (X68K_RAM_SIZE - 1u)) ^ 1u]; }
INLINE void ram_wb(u32 a, u8 v) { M->ram[(a & (X68K_RAM_SIZE - 1u)) ^ 1u] = v; }
INLINE u16 ram_rw(u32 a) { return ((u16)ram_rb(a) << 8) | ram_rb(a + 1u); }
INLINE void ram_ww(u32 a, u16 v) { ram_wb(a, (u8)(v >> 8)); ram_wb(a + 1u, (u8)v); }
INLINE u32 ram_rl(u32 a) { return ((u32)ram_rw(a) << 16) | ram_rw(a + 2u); }
INLINE void ram_wl(u32 a, u32 v) { ram_ww(a, (u16)(v >> 16)); ram_ww(a + 2u, (u16)v); }

INLINE void ipl_ww(u32 off, u16 v)
{
    *(u16 *)(M->ipl + (off & (X68K_IPL_SIZE - 2u))) = v;
}
INLINE void ipl_wl(u32 off, u32 v)
{
    ipl_ww(off, (u16)(v >> 16));
    ipl_ww(off + 2u, (u16)v);
}

/* ---- Interrupt Priority & Vector Routing ---- */
/* X68000 IRQ levels:
   Level 6: MC68901 MFP ($E88000, vectors VR|0..15)
   Level 5: Z8530 SCC ($E98000)
   Level 3: HD63450 DMAC ($E84000, vectors NIV/EIV)
   Level 1: IOSC ($E9C000: FDD / FDC / HDD / Printer) */

static int mfp_top_bit(void)
{
    u16 pend = (u16)(((u16)(X.mfp.ipra & X.mfp.imra) << 8) | (X.mfp.iprb & X.mfp.imrb));
    if (!pend)
        return -1;
    u16 in_svc = (X.mfp.vr & 8u) ? (u16)(((u16)X.mfp.isra << 8) | X.mfp.isrb) : 0u;
    for (int b = 15; b >= 0; b--) {
        if (in_svc & (1u << b))
            return -1;                  /* Higher/equal MFP IRQ still in service */
        if (pend & (1u << b))
            return b;
    }
    return -1;
}

static int dmac_irq_ch(void)
{
    for (int ch = 0; ch < 4; ch++) {
        if ((X.dmac[ch].ccr & 0x08u) && (X.dmac[ch].csr & 0xF0u))
            return ch;
    }
    return -1;
}

static int iosc_irq_src(void)
{
    /* iosc_stat: b7=FDC, b6=FDD, b5=PRN, b4=HDD; iosc_en: b3=PRN, b2=FDD, b1=FDC, b0=HDD */
    if ((X.iosc_stat & 0x80u) && (X.iosc_en & 0x02u)) return 1; /* FDC */
    if ((X.iosc_stat & 0x40u) && (X.iosc_en & 0x04u)) return 0; /* FDD */
    if ((X.iosc_stat & 0x10u) && (X.iosc_en & 0x01u)) return 2; /* HDD */
    if ((X.iosc_stat & 0x20u) && (X.iosc_en & 0x08u)) return 3; /* PRN */
    return -1;
}

static void x68k_update_ipl(void)
{
    u32 lvl = 0;
    if (mfp_top_bit() >= 0)       lvl = 6u;
    else if (dmac_irq_ch() >= 0)  lvl = 3u;
    else if (iosc_irq_src() >= 0) lvl = 1u;
    m.ipl = lvl;
    check_pending();
}

static void mfp_raise(int bit)
{
    if (bit >= 8) {
        u8 msk = (u8)(1u << (bit - 8));
        if (X.mfp.iera & msk) X.mfp.ipra |= msk;
    } else {
        u8 msk = (u8)(1u << bit);
        if (X.mfp.ierb & msk) X.mfp.iprb |= msk;
    }
    x68k_update_ipl();
}

static void mfp_set_gpip_bit(int bit, int val)
{
    u8 msk = (u8)(1u << bit);
    u8 old = X.mfp.gpip_in & msk;
    u8 now = val ? msk : 0u;
    if (old == now)
        return;
    X.mfp.gpip_in = (u8)((X.mfp.gpip_in & ~msk) | now);
    /* AER bit: 1 = rising edge (0->1), 0 = falling edge (1->0) */
    int want_rise = (X.mfp.aer & msk) != 0;
    if ((want_rise && now) || (!want_rise && !now)) {
        static const s8 gpip_vec[8] = {0, 1, 2, 3, 14, -1, 14, 15};
        /* Map GPIP bits to MFP interrupt bit indices (0..15):
           GPIP0->0, GPIP1->1, GPIP2->2, GPIP3(FM)->3, GPIP4(VDISP)->6+8=14, GPIP5->7, GPIP6(CIRQ)->6+8?
           Exact MC68901 MFP bit numbers:
           15:GPIP7, 14:GPIP6, 13:TimerA, 12:RxFull, 11:RxErr, 10:TxEmpty, 9:TxErr, 8:TimerB,
           7:GPIP5, 6:GPIP4(VDISP!), 5:TimerC, 4:TimerD, 3:GPIP3(FMIRQ!), 2:GPIP2, 1:GPIP1, 0:GPIP0 */
        (void)gpip_vec;
        static const u8 exact_mfp_bit[8] = {0, 1, 2, 3, 6, 7, 14, 15};
        mfp_raise(exact_mfp_bit[bit & 7]);
    }
}

static u32 x68k_int_vec(u32 level)
{
    if (level == 6u) {
        int b = mfp_top_bit();
        if (b >= 0) {
            if (b >= 8) {
                u8 msk = (u8)(1u << (b - 8));
                X.mfp.ipra &= ~msk;
                if (X.mfp.vr & 8u) X.mfp.isra |= msk;
            } else {
                u8 msk = (u8)(1u << b);
                X.mfp.iprb &= ~msk;
                if (X.mfp.vr & 8u) X.mfp.isrb |= msk;
            }
            return (u32)((X.mfp.vr & 0xF0u) | (u32)b);
        }
    }
    if (level == 3u) {
        int ch = dmac_irq_ch();
        if (ch >= 0) {
            u8 vec = (X.dmac[ch].csr & 0x10u) ? X.dmac[ch].eiv : X.dmac[ch].niv;
            X.dmac[ch].ccr &= ~0x08u;   /* Disarm until software clears CSR or restarts */
            return vec ? vec : (24u + level);
        }
    }
    if (level == 1u) {
        int src = iosc_irq_src();
        if (src >= 0) {
            if (src == 1) X.iosc_stat &= ~0x80u;
            else if (src == 0) X.iosc_stat &= ~0x40u;
            else if (src == 2) X.iosc_stat &= ~0x10u;
            else X.iosc_stat &= ~0x20u;
            return (u32)((X.iosc_vec & 0xFCu) | (u32)src);
        }
    }
    return 24u + level;
}

static void x68k_iack(u32 level)
{
    (void)level;
    x68k_update_ipl();
}

static void cpu_reset_line(void)
{
}

/* ---- Audio: OKI MSM6258V 4-bit ADPCM + HD63450 Ch 3 DMA + YM2151 OPM ---- */

static const s16 msm_step_tab[49] = {
    16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66,
    73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307,
    337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552
};
static const s8 msm_idx_tab[8] = {-1, -1, -1, -1, 2, 4, 6, 8};

static void adpcm_update_rate(void)
{
    /* PPI Port C ($E9A005) bits 3..2: 0=/1024, 1=/768, 2=/512; OPM CT2 (bit 1 of opm.ct): 0=8MHz, 1=4MHz */
    static const u16 div_tab[4] = {1024, 768, 512, 512};
    u32 osc = (X.opm.ct & 2u) ? 4000000u : 8000000u;
    u32 hz = osc / div_tab[(X.ppi_portc >> 2) & 3u];
    u32 sr = X.snd_rate ? X.snd_rate : 48000u;
    X.adpcm.step_48k = (hz << 16) / sr;
    /* 1 ADPCM byte = 2 samples -> CPU cycles per byte */
    X.adpcm.dma_cyc_per_byte = (s32)((X68K_CPU_HZ * 2u) / (hz ? hz : 15625u));
    if (X.adpcm.dma_cyc_per_byte < 64)
        X.adpcm.dma_cyc_per_byte = 64;
}

static void adpcm_decode_nibble(u8 nib)
{
    s32 step = msm_step_tab[X.adpcm.step_idx];
    s32 diff = step >> 3;
    if (nib & 1u) diff += step >> 2;
    if (nib & 2u) diff += step >> 1;
    if (nib & 4u) diff += step;
    if (nib & 8u) diff = -diff;
    X.adpcm.est += diff;
    if (X.adpcm.est > 2047)  X.adpcm.est = 2047;
    if (X.adpcm.est < -2048) X.adpcm.est = -2048;
    X.adpcm.step_idx += msm_idx_tab[nib & 7u];
    if (X.adpcm.step_idx < 0)  X.adpcm.step_idx = 0;
    if (X.adpcm.step_idx > 48) X.adpcm.step_idx = 48;
    X.adpcm.out_sample = X.adpcm.est * 12;
}

/* Pull one byte from HD63450 Channel 3 (supports normal, array chain, and link array chain) */
static int dmac_ch3_pull_byte(u8 *out_b)
{
    struct x68k_dmac_ch *d = &X.dmac[3];
    if (!(d->csr & 0x08u))              /* Not active */
        return 0;
    if (d->mtc == 0) {
        u8 chain = d->ocr & 3u;
        if (chain == 2u && d->btc > 0) {
            /* Array chain: [MAR.L, MTC.W] at BAR */
            d->mar = ram_rl(d->bar) & 0xFFFFFFu;
            d->mtc = ram_rw(d->bar + 4u);
            d->bar = (d->bar + 6u) & 0xFFFFFFu;
            d->btc--;
        } else if (chain == 3u && d->bar != 0) {
            /* Link array chain: [MAR.L, MTC.W, NEXT_BAR.L] at BAR */
            d->mar = ram_rl(d->bar) & 0xFFFFFFu;
            d->mtc = ram_rw(d->bar + 4u);
            d->bar = ram_rl(d->bar + 6u) & 0xFFFFFFu;
        }
        if (d->mtc == 0) {
            d->csr = (u8)((d->csr & ~0x08u) | 0x80u); /* Clear ACT, set COC */
            x68k_update_ipl();
            return 0;
        }
    }
    u32 addr = d->mar & 0xFFFFFFu;
    *out_b = (addr < X68K_RAM_SIZE) ? ram_rb(addr) : 0x80u;
    u8 mdir = (d->scr >> 2) & 3u;
    if (mdir == 1u) d->mar = (d->mar + 1u) & 0xFFFFFFu;
    else if (mdir == 2u) d->mar = (d->mar - 1u) & 0xFFFFFFu;
    d->mtc--;
    if (d->mtc == 0) {
        u8 chain = d->ocr & 3u;
        if (chain == 2u && d->btc > 0) {
            d->mar = ram_rl(d->bar) & 0xFFFFFFu;
            d->mtc = ram_rw(d->bar + 4u);
            d->bar = (d->bar + 6u) & 0xFFFFFFu;
            d->btc--;
        } else if (chain == 3u && d->bar != 0) {
            d->mar = ram_rl(d->bar) & 0xFFFFFFu;
            d->mtc = ram_rw(d->bar + 4u);
            d->bar = ram_rl(d->bar + 6u) & 0xFFFFFFu;
        }
        if (d->mtc == 0) {
            d->csr = (u8)((d->csr & ~0x08u) | 0x80u);
            x68k_update_ipl();
        }
    }
    return 1;
}

static void snd_render_to_line(int line)
{
    if (!X.snd_rate)
        return;
    u32 frame_samples = (X.snd_rate * 100u) / 5545u;
    u32 target = ((u32)(line + 1) * frame_samples) / X68K_LINES;
    while (X.snd_rendered < target) {
        X.snd_rendered++;
        s32 fl = 0, fr = 0;
        ym2151_sample_48khz(&X.opm, &fl, &fr);

        if (X.adpcm.play) {
            X.adpcm.phase += X.adpcm.step_48k;
            while (X.adpcm.phase >= 0x10000u) {
                X.adpcm.phase -= 0x10000u;
                if (!X.adpcm.nib_hi) {
                    u8 b = X.adpcm.cur_byte;
                    if (!X.adpcm.has_byte) {
                        if (!dmac_ch3_pull_byte(&b)) {
                            X.adpcm.out_sample = (X.adpcm.out_sample * 15) >> 4;
                            break;
                        }
                    }
                    X.adpcm.cur_byte = b;
                    X.adpcm.has_byte = 0;
                    adpcm_decode_nibble(b & 0x0Fu); /* MSM6258: low nibble first */
                    X.adpcm.nib_hi = 1u;
                } else {
                    adpcm_decode_nibble((X.adpcm.cur_byte >> 4) & 0x0Fu);
                    X.adpcm.nib_hi = 0u;
                }
            }
            /* PPI Port C bits 1..0: 0=L+R, 1=R, 2=L, 3=Mute */
            u8 pan = X.ppi_portc & 3u;
            if ((pan & 1u) == 0) fl += X.adpcm.out_sample;
            if ((pan & 2u) == 0) fr += X.adpcm.out_sample;
        }
        s32 mono = (fl + fr) >> 1;
        if (mono > 32767)  mono = 32767;
        if (mono < -32768) mono = -32768;
        if ((u32)(X.snd_w - X.snd_r) < X68K_SND_RING)
            M->snd_ring[X.snd_w++ & (X68K_SND_RING - 1u)] = (s16)mono;
    }
}

/* Step ADPCM DMA even when sound output is disabled (-f benchmark mode) so games waiting on DMA COC never stall */
static void adpcm_tick_silent(s32 cyc)
{
    if (X.snd_rate || !X.adpcm.play || !(X.dmac[3].csr & 0x08u))
        return;
    X.adpcm.dma_cyc_acc += cyc;
    while (X.adpcm.dma_cyc_acc >= X.adpcm.dma_cyc_per_byte) {
        X.adpcm.dma_cyc_acc -= X.adpcm.dma_cyc_per_byte;
        u8 dummy;
        if (!dmac_ch3_pull_byte(&dummy))
            break;
    }
}

/* ---- Floppy Disk Image Access (.dim, .xdf, .hdm, .2hd, .dup) ---- */

static int parse_floppy_image(int unit, const u8 *img, u32 size)
{
    struct x68k_disk *d = &X.drv[unit];
    u8 *dst = unit == 0 ? M->disk0 : M->disk1;
    for (u32 i = 0; i < sizeof(*d); i++) ((u8 *)d)[i] = 0;
    for (u32 i = 0; i < X68K_DISK_MAX; i++) dst[i] = 0xE5u;
    if (!img || size < 0x1000u)
        return -1;

    /* Check for 256-byte DIFC (.dim) header */
    if (size > 256u && img[0xAB] == 'D' && img[0xAC] == 'I' && img[0xAD] == 'F' && img[0xAE] == 'C') {
        d->is_dim = 1u;
        d->media = img[0];
        /* Media byte: 0=2HD (77*2*8*1024), 1=2HS (80*2*9*1024), 2=2HC (80*2*15*512), 3=2HDE (80*2*9*1024) */
        if (d->media == 2u) {
            d->bps_shift = 9; d->spt = 15; d->heads = 2; d->tracks = 80;
        } else if (d->media == 1u || d->media == 3u) {
            d->bps_shift = 10; d->spt = 9; d->heads = 2; d->tracks = 80;
        } else {
            d->bps_shift = 10; d->spt = 8; d->heads = 2; d->tracks = 77;
        }
        u32 trk_bytes = (u32)d->spt << d->bps_shift;
        u32 total_tracks = (u32)d->tracks * d->heads;
        u32 src_off = 256u;
        /* Some .dim tools leave track bitmap all-zero when all tracks are sequential */
        int any_flag = 0;
        for (u32 t = 0; t < total_tracks && t < 170u; t++)
            if (img[1u + t]) any_flag = 1;
        for (u32 t = 0; t < total_tracks && t < 170u; t++) {
            u32 dst_off = t * trk_bytes;
            if (dst_off + trk_bytes > X68K_DISK_MAX)
                break;
            if (!any_flag || img[1u + t]) {
                if (src_off + trk_bytes <= size) {
                    for (u32 k = 0; k < trk_bytes; k++)
                        dst[dst_off + k] = img[src_off + k];
                    src_off += trk_bytes;
                    d->trk_present[t] = 1u;
                }
            }
        }
        d->raw_size = total_tracks * trk_bytes;
        d->present = 1u;
        return 0;
    }

    /* Raw sector images: 2HD (1,261,568), 2HS (1,474,560), 2HC (1,228,800), 2DD (737,280 / 655,360) */
    if (size == 1228800u) {
        d->bps_shift = 9; d->spt = 15; d->heads = 2; d->tracks = 80;
    } else if (size == 1474560u) {
        d->bps_shift = 10; d->spt = 9; d->heads = 2; d->tracks = 80;
    } else if (size == 737280u) {
        d->bps_shift = 9; d->spt = 9; d->heads = 2; d->tracks = 80;
    } else {
        d->bps_shift = 10; d->spt = 8; d->heads = 2; d->tracks = 77;
    }
    u32 copy_n = size < X68K_DISK_MAX ? size : X68K_DISK_MAX;
    for (u32 i = 0; i < copy_n; i++)
        dst[i] = img[i];
    d->raw_size = copy_n;
    d->present = 1u;
    return 0;
}

static int fdd_rw_sector(int unit, u32 c, u32 h, u32 r, int write, u8 *buf, u32 bytes)
{
    if ((unsigned)unit >= 2u || !X.drv[unit].present)
        return -1;
    struct x68k_disk *d = &X.drv[unit];
    if (r < 1u || r > d->spt || h >= d->heads || c >= d->tracks)
        return -1;
    u32 bps = 1u << d->bps_shift;
    u32 lba = ((c * d->heads + h) * d->spt) + (r - 1u);
    u32 off = lba * bps;
    u8 *img = unit == 0 ? M->disk0 : M->disk1;
    if (off + bytes > X68K_DISK_MAX)
        return -1;
    if (write) {
        for (u32 i = 0; i < bytes; i++)
            img[off + i] = buf[i];
        d->dirty = 1u;
    } else {
        for (u32 i = 0; i < bytes; i++)
            buf[i] = img[off + i];
    }
    return 0;
}

/* Execute uPD72065 FDC command + HD63450 Ch 0 DMA */
static void fdc_exec(void)
{
    u8 op = X.fdc.cmd & 0x1Fu;
    int unit = X.fdc.buf_len >= 2 ? (X.fdc.buf[1] & 3) : (X.fdc.drv_sel & 3);
    int head = X.fdc.buf_len >= 2 ? ((X.fdc.buf[1] >> 2) & 1) : 0;
    X.fdc.res_pos = 0;
    X.fdc.res_len = 0;

    switch (op) {
    case 0x03: /* SPECIFY */
        X.fdc.msr = 0x80u;
        return;
    case 0x04: /* SENSE DEVICE STATUS */
        X.fdc.st3 = (u8)(0x20u | (head << 2) | (unit & 3));
        if (unit < 2 && X.drv[unit].present) X.fdc.st3 |= 0x20u;
        if (unit < 2 && X.fdc.cur_c[unit] == 0) X.fdc.st3 |= 0x10u;
        X.fdc.res[0] = X.fdc.st3;
        X.fdc.res_len = 1;
        X.fdc.msr = 0xD0u;
        return;
    case 0x07: /* RECALIBRATE */
        unit = X.fdc.buf[1] & 3;
        if (unit < 2) X.fdc.cur_c[unit] = 0;
        X.fdc.st0 = (u8)(0x20u | (unit & 3));
        X.fdc.msr = 0x80u;
        X.iosc_stat |= 0x80u;
        x68k_update_ipl();
        return;
    case 0x08: /* SENSE INTERRUPT STATUS */
        X.fdc.res[0] = X.fdc.st0;
        X.fdc.res[1] = X.fdc.cur_c[X.fdc.st0 & 1];
        X.fdc.res_len = 2;
        X.fdc.st0 = 0x80u;
        X.fdc.msr = 0xD0u;
        X.iosc_stat &= ~0x80u;
        x68k_update_ipl();
        return;
    case 0x0F: /* SEEK */
        unit = X.fdc.buf[1] & 3;
        if (unit < 2) X.fdc.cur_c[unit] = X.fdc.buf[2];
        X.fdc.st0 = (u8)(0x20u | (head << 2) | (unit & 3));
        X.fdc.msr = 0x80u;
        X.iosc_stat |= 0x80u;
        x68k_update_ipl();
        return;
    case 0x0A: /* READ ID */
        if (unit < 2 && X.drv[unit].present) {
            X.fdc.st0 = (u8)((head << 2) | unit);
            X.fdc.st1 = X.fdc.st2 = 0;
            X.fdc.res[0] = X.fdc.st0; X.fdc.res[1] = 0; X.fdc.res[2] = 0;
            X.fdc.res[3] = X.fdc.cur_c[unit];
            X.fdc.res[4] = (u8)head;
            X.fdc.res[5] = 1u;
            X.fdc.res[6] = X.drv[unit].bps_shift - 7u;
        } else {
            X.fdc.st0 = (u8)(0x40u | unit);
            X.fdc.res[0] = X.fdc.st0; X.fdc.res[1] = 0x01u; X.fdc.res[2] = 0;
            X.fdc.res[3] = X.fdc.res[4] = X.fdc.res[5] = X.fdc.res[6] = 0;
        }
        X.fdc.res_len = 7;
        X.fdc.msr = 0xD0u;
        X.iosc_stat |= 0x80u;
        x68k_update_ipl();
        return;
    case 0x05: /* WRITE DATA */
    case 0x06: /* READ DATA */
    case 0x11: /* SCAN EQUAL */ {
        int is_wr = (op == 0x05);
        int mt = (X.fdc.cmd >> 7) & 1;
        u32 c = X.fdc.buf[2], h = X.fdc.buf[3], r = X.fdc.buf[4], n = X.fdc.buf[5], eot = X.fdc.buf[6];
        u32 bps = 128u << (n & 7u);
        struct x68k_dmac_ch *dm = &X.dmac[0];
        u32 rem = dm->mtc ? dm->mtc : bps;
        u8 sec_buf[1024];
        int err = 0;
        while (rem > 0) {
            u32 chunk = rem < bps ? rem : bps;
            if (bps > sizeof(sec_buf)) { err = 1; break; }
            if (is_wr) {
                for (u32 i = 0; i < chunk; i++) {
                    u32 ma = (dm->mar + i) & 0xFFFFFFu;
                    sec_buf[i] = ma < X68K_RAM_SIZE ? ram_rb(ma) : 0;
                }
                if (fdd_rw_sector(unit, c, h, r, 1, sec_buf, chunk) < 0) { err = 1; break; }
            } else {
                if (fdd_rw_sector(unit, c, h, r, 0, sec_buf, chunk) < 0) { err = 1; break; }
                if (op == 0x06) {
                    for (u32 i = 0; i < chunk; i++) {
                        u32 ma = (dm->mar + i) & 0xFFFFFFu;
                        if (ma < X68K_RAM_SIZE) ram_wb(ma, sec_buf[i]);
                    }
                }
            }
            dm->mar = (dm->mar + chunk) & 0xFFFFFFu;
            dm->mtc = (u16)(dm->mtc > chunk ? dm->mtc - chunk : 0);
            rem -= chunk;
            if (rem == 0) break;
            r++;
            if (r > eot) {
                r = 1u;
                if (mt && h == 0) h = 1u;
                else { h = 0; c++; }
            }
        }
        if (unit < 2) X.fdc.cur_c[unit] = (u8)c;
        dm->csr = (u8)((dm->csr & ~0x08u) | 0x80u);
        X.fdc.st0 = (u8)((err ? 0x40u : 0x00u) | (h << 2) | (unit & 3));
        X.fdc.st1 = err ? 0x04u : 0x00u;
        X.fdc.st2 = 0;
        X.fdc.res[0] = X.fdc.st0; X.fdc.res[1] = X.fdc.st1; X.fdc.res[2] = X.fdc.st2;
        X.fdc.res[3] = (u8)c; X.fdc.res[4] = (u8)h; X.fdc.res[5] = (u8)r; X.fdc.res[6] = (u8)n;
        X.fdc.res_len = 7;
        X.fdc.msr = 0xD0u;
        X.iosc_stat |= 0x80u;
        x68k_update_ipl();
        return;
    }
    default:
        X.fdc.st0 = 0x80u;
        X.fdc.res[0] = 0x80u;
        X.fdc.res_len = 1;
        X.fdc.msr = 0xD0u;
        return;
    }
}

static void fdc_write_data(u8 v)
{
    if (X.fdc.buf_need == 0) {
        X.fdc.cmd = v;
        X.fdc.buf[0] = v;
        X.fdc.buf_len = 1;
        u8 op = v & 0x1Fu;
        switch (op) {
        case 0x03: X.fdc.buf_need = 3; break;
        case 0x04: case 0x07: case 0x0A: X.fdc.buf_need = 2; break;
        case 0x08: X.fdc.buf_need = 1; break;
        case 0x0F: X.fdc.buf_need = 3; break;
        case 0x05: case 0x06: case 0x11: X.fdc.buf_need = 9; break;
        default:   X.fdc.buf_need = 1; break;
        }
    } else {
        if (X.fdc.buf_len < sizeof(X.fdc.buf))
            X.fdc.buf[X.fdc.buf_len++] = v;
    }
    if (X.fdc.buf_len >= X.fdc.buf_need) {
        X.fdc.buf_need = 0;
        fdc_exec();
    }
}

/* ---- Built-in CGROM (8x16, 8x8, 16x16 ANK/Katakana/Kanji) ---- */

static void build_clean_cgrom(void)
{
    if (X.has_ext_cg && X.ext_cg && X.ext_cg_sz > 0) {
        u32 n = X.ext_cg_sz < X68K_CG_MAX ? X.ext_cg_sz : X68K_CG_MAX;
        for (u32 i = 0; i < n; i++) M->cg[i] = X.ext_cg[i];
        return;
    }
    for (u32 i = 0; i < X68K_CG_MAX; i++)
        M->cg[i] = 0;

    /* X68000 CGROM standard offsets:
       $F00000 (+0x00000): 16x16 JIS Kanji/Non-Kanji (32 bytes/glyph)
       $F3A000 (+0x3A000): 8x16 ANK (16 bytes/char, 256 chars = 4 KB)
       $F3A800 (+0x3A800? Wait: 256 * 16 = 0x1000 -> $F3B000 is 8x8 ANK, 8 bytes/char!)
       Actually on X68000:
       $F3A000..$F3A7FF: 8x8 ANK (256 * 8 = 2 KB)
       $F3A800..$F3B7FF: 8x16 ANK (256 * 16 = 4 KB) */
    for (u32 ch = 0; ch < 256u; ch++) {
        u8 rows8[8];
        for (int y = 0; y < 8; y++) {
            u8 b = 0;
            if (ch >= FONT_FIRST && ch <= FONT_LAST && y < FONT_H) {
                b = (u8)(font5x7[ch - FONT_FIRST][y] << 2);
            } else if (ch >= 0xA1u && ch <= 0xDFu) {
                /* Half-width Katakana clean geometric strokes */
                u32 k = ch - 0xA1u;
                if (y == 1) b = (u8)(0x7Cu ^ ((k & 3u) << 3));
                else if (y == 4) b = (u8)(0x38u | ((k & 4u) << 3));
                else if (y >= 2 && y <= 6) b = (u8)(0x10u << (k & 1u));
            } else if (ch >= 0x80u && y >= 1 && y <= 6) {
                b = (y == 1 || y == 6) ? 0x7Eu : 0x42u;
            }
            rows8[y] = b;
            M->cg[0x3A000u + ch * 8u + (u32)y] = b;
            M->cg[0x3A800u + ch * 16u + (u32)(y * 2)] = b;
            M->cg[0x3A800u + ch * 16u + (u32)(y * 2 + 1)] = (y < 7) ? (b & rows8[y]) : 0;
        }
    }

    /* Populate 16x16 non-kanji (rows 1..8: ASCII/digits/kana/symbols) & legible Kanji glyph patterns */
    for (u32 ku = 0; ku < 84u; ku++) {
        for (u32 ten = 0; ten < 94u; ten++) {
            u32 idx = ku * 94u + ten;
            u32 off = idx * 32u;
            if (off + 32u > 0x3A000u)
                break;
            if (ku == 2 && ten >= 15 && ten <= 89) {
                /* JIS Row 3: Full-width '0'..'9', 'A'..'Z', 'a'..'z' -> scale 8x16 ANK 2x horizontally */
                u32 ach = (ten <= 24) ? ('0' + ten - 15) :
                          (ten <= 57 && ten >= 32) ? ('A' + ten - 32) :
                          (ten >= 64 && ten <= 89) ? ('a' + ten - 64) : ' ';
                for (u32 y = 0; y < 16u; y++) {
                    u8 src = M->cg[0x3A800u + ach * 16u + y];
                    u16 wide = 0;
                    for (int b = 0; b < 8; b++)
                        if (src & (0x80u >> b))
                            wide |= (u16)(3u << (14 - b * 2));
                    M->cg[off + y * 2u] = (u8)(wide >> 8);
                    M->cg[off + y * 2u + 1u] = (u8)wide;
                }
            } else {
                /* Distinct, clean 14x14 CJK radical pattern keyed by (ku, ten) so Japanese dialogs are readable/distinct */
                u32 seed = (ku * 131u + ten * 17u + 0x5A3Cu) & 0xFFFFu;
                for (u32 y = 1; y < 15u; y++) {
                    u16 row = 0;
                    if (y == 1 || y == 14) row = (u16)(0x3FFCu & (0x7FFEu ^ ((seed & 7u) << 4)));
                    else if (y == 7)       row = (u16)(0x1FF8u ^ ((seed >> 3) & 0x0FF0u));
                    else                   row = (u16)(0x2004u | (((seed >> (y & 7u)) & 0x3Fu) << 5));
                    M->cg[off + y * 2u] = (u8)(row >> 8);
                    M->cg[off + y * 2u + 1u] = (u8)row;
                }
            }
        }
    }
}

/* ---- TVRAM Text Rendering & Screen Mode Control ---- */

static void tvram_clear_rect(u32 x0_byte, u32 y0, u32 w_bytes, u32 h)
{
    for (u32 p = 0; p < 4u; p++) {
        u8 *plane = M->tvram + p * 0x20000u;
        for (u32 y = 0; y < h && (y0 + y) < 1024u; y++) {
            u32 row = (y0 + y) * 128u + x0_byte;
            for (u32 x = 0; x < w_bytes && (x0_byte + x) < 128u; x++)
                plane[row + x] = 0;
        }
    }
}

static void tvram_scroll_up(u32 y_px, u32 h_px, u32 step_px)
{
    if (h_px <= step_px) {
        tvram_clear_rect(0, y_px, 128u, h_px);
        return;
    }
    u32 copy_lines = h_px - step_px;
    for (u32 p = 0; p < 4u; p++) {
        u8 *plane = M->tvram + p * 0x20000u;
        for (u32 y = 0; y < copy_lines; y++) {
            u8 *dst = plane + (y_px + y) * 128u;
            const u8 *src = plane + (y_px + step_px + y) * 128u;
            for (u32 x = 0; x < 128u; x++) dst[x] = src[x];
        }
        for (u32 y = copy_lines; y < h_px; y++) {
            u8 *dst = plane + (y_px + y) * 128u;
            for (u32 x = 0; x < 128u; x++) dst[x] = 0;
        }
    }
}

static void tvram_draw_ank(u32 col, u32 row, u8 ch, u8 color)
{
    u32 x_byte = col & 127u;
    u32 y_px = (row * 16u) & 1008u;
    const u8 *glyph = M->cg + 0x3A800u + (u32)ch * 16u;
    for (u32 p = 0; p < 4u; p++) {
        u8 *plane = M->tvram + p * 0x20000u;
        u8 on = (color & (1u << p)) ? 0xFFu : 0x00u;
        for (u32 y = 0; y < 16u; y++)
            plane[(y_px + y) * 128u + x_byte] = glyph[y] & on;
    }
}

/* Convert Shift-JIS lead+trail bytes to 0-based JIS (ku, ten) */
static void sjis_to_kuten(u8 b1, u8 b2, u32 *ku, u32 *ten)
{
    u32 j1 = (b1 <= 0x9Fu) ? ((u32)(b1 - 0x81u) * 2u + 0x21u) : ((u32)(b1 - 0xE0u) * 2u + 0x5Fu);
    u32 j2;
    if (b2 >= 0x9Fu) {
        j1++;
        j2 = (u32)b2 - 0x7Eu;
    } else {
        j2 = (u32)b2 - (b2 >= 0x80u ? 0x20u : 0x1Fu);
    }
    *ku  = (j1 >= 0x21u && j1 <= 0x7Eu) ? (j1 - 0x21u) : 0u;
    *ten = (j2 >= 0x21u && j2 <= 0x7Eu) ? (j2 - 0x21u) : 0u;
}

static void tvram_draw_kanji(u32 col, u32 row, u8 b1, u8 b2, u8 color)
{
    u32 ku, ten;
    sjis_to_kuten(b1, b2, &ku, &ten);
    u32 idx = ku * 94u + ten;
    u32 off = idx * 32u;
    if (off + 32u > X68K_CG_MAX) off = 0;
    const u8 *glyph = M->cg + off;
    u32 x_byte = col & 126u;
    u32 y_px = (row * 16u) & 1008u;
    for (u32 p = 0; p < 4u; p++) {
        u8 *plane = M->tvram + p * 0x20000u;
        u8 on = (color & (1u << p)) ? 0xFFu : 0x00u;
        for (u32 y = 0; y < 16u; y++) {
            plane[(y_px + y) * 128u + x_byte]      = glyph[y * 2u]      & on;
            plane[(y_px + y) * 128u + x_byte + 1u] = glyph[y * 2u + 1u] & on;
        }
    }
}

static void con_newline(void)
{
    X.cur_x = 0;
    X.cur_y++;
    u16 max_rows = X.con_h ? X.con_h : 31u;
    if (X.cur_y >= max_rows) {
        X.cur_y = max_rows - 1u;
        tvram_scroll_up(X.con_y0, (u32)max_rows * 16u, 16u);
    }
}

static void con_putc(u8 c)
{
    static u8 sjis_hi;
    u16 max_cols = (X.out_w >= 768) ? 96u : (X.out_w >= 512 ? 64u : 32u);
    if (sjis_hi) {
        u8 hi = sjis_hi;
        sjis_hi = 0;
        if (X.cur_x + 2u > max_cols) con_newline();
        tvram_draw_kanji(X.cur_x, X.cur_y, hi, c, (u8)X.txt_color);
        X.cur_x += 2u;
        return;
    }
    /* Minimal VT/ANSI escape parser (used by Pac-Man boot sector & Human68k!) */
    if (X.esc_state == 1u) {
        if (c == '[') {
            X.esc_state = 2u;
            X.esc_n = 0;
            X.esc_params[0] = X.esc_params[1] = 0;
            return;
        }
        X.esc_state = 0;
        return;
    }
    if (X.esc_state == 2u) {
        if (c >= '0' && c <= '9') {
            if (X.esc_n < 4u)
                X.esc_params[X.esc_n] = (u8)(X.esc_params[X.esc_n] * 10u + (c - '0'));
            return;
        }
        if (c == ';') {
            if (X.esc_n < 3u) X.esc_n++;
            return;
        }
        X.esc_state = 0;
        if (c == 'H' || c == 'f') {
            X.cur_y = X.esc_params[0] > 0 ? (u16)(X.esc_params[0] - 1u) : 0u;
            X.cur_x = X.esc_params[1] > 0 ? (u16)(X.esc_params[1] - 1u) : 0u;
        } else if (c == 'J') {
            tvram_clear_rect(0, 0, 128u, 512u);
            X.cur_x = X.cur_y = 0;
        } else if (c == 'K') {
            tvram_clear_rect(X.cur_x, (u32)X.cur_y * 16u, 128u - X.cur_x, 16u);
        }
        return;
    }
    if (c == 0x1Bu) { X.esc_state = 1u; return; }
    if (c == '\r')  { X.cur_x = 0; return; }
    if (c == '\n')  { con_newline(); return; }
    if (c == 0x08u) { if (X.cur_x > 0) { X.cur_x--; tvram_draw_ank(X.cur_x, X.cur_y, ' ', 0); } return; }
    if (c == 0x0Cu || c == 0x1Au) { tvram_clear_rect(0, 0, 128u, 512u); X.cur_x = X.cur_y = 0; return; }
    if (c == '\t')  { X.cur_x = (u16)((X.cur_x + 8u) & ~7u); if (X.cur_x >= max_cols) con_newline(); return; }
    if ((c >= 0x81u && c <= 0x9Fu) || (c >= 0xE0u && c <= 0xFCu)) {
        sjis_hi = c;
        return;
    }
    if (c >= 0x20u) {
        if (X.cur_x >= max_cols) con_newline();
        tvram_draw_ank(X.cur_x++, X.cur_y, c, (u8)X.txt_color);
    }
}

static void update_resolution_from_crtc(void)
{
    u32 hmode = X.crtc[20] & 3u;
    u32 vmode = (X.crtc[20] >> 2) & 3u;
    int w = (hmode == 0) ? 256 : (hmode == 1 ? 512 : 768);
    int h = (vmode == 0) ? 256 : 512;
    /* Also honor explicit CRTC active window (R3 - R2) * 8 when valid */
    int cw = ((int)X.crtc[3] - (int)X.crtc[2]) * 8;
    int ch = (int)X.crtc[7] - (int)X.crtc[6];
    if (cw == 256 || cw == 384 || cw == 512 || cw == 768) w = cw;
    if (ch >= 224 && ch <= 256 && vmode == 0) h = ch;
    else if (ch >= 400 && ch <= 512 && vmode != 0) h = ch;
    if (w > X68K_W_MAX) w = X68K_W_MAX;
    if (h > X68K_H_MAX) h = X68K_H_MAX;
    X.out_w = w;
    X.out_h = h;
}

static void set_default_palettes(void)
{
    static const u16 def_tpal[16] = {
        0x0000u, 0x5294u, 0x003Eu, 0x07FEu, 0xF800u, 0xF83Eu, 0xFFC0u, 0xFFFEu,
        0x8410u, 0x002Au, 0x0540u, 0x056Au, 0xA800u, 0xA82Au, 0xAD40u, 0xAD6Au
    };
    for (int i = 0; i < 16; i++) {
        X.tpal[i] = def_tpal[i];
        X.tpal15[i] = x68k_col15(def_tpal[i]);
        X.gpal[i] = def_tpal[i];
        X.gpal15[i] = x68k_col15(def_tpal[i]);
    }
    /* In 65,536-color mode X68000 VC uses gpal[0..255] as identity lookup table: initialize standard ramp */
    for (int i = 16; i < 256; i++) {
        u16 w = (u16)((i << 8) | i);
        X.gpal[i] = w;
        X.gpal15[i] = x68k_col15(w);
    }
}

static void apply_crtmod(u32 mode, int no_clear)
{
    X.crt_mode = (u8)(mode & 0x1Fu);
    u16 r20 = 0x0016u, vc0 = 0, vc2 = 0x0020u;
    int w = 768, h = 512;
    switch (X.crt_mode) {
    case 0: case 1: case 4: case 5:
        w = 512; h = 512; r20 = (X.crt_mode & 1) ? 0x0005u : 0x0015u; vc0 = 0; vc2 = 0x002Fu; break;
    case 2: case 3: case 6: case 7:
        w = 256; h = 256; r20 = (X.crt_mode & 1) ? 0x0000u : 0x0010u; vc0 = 0; vc2 = 0x006Fu; break;
    case 8: case 9:
        w = 512; h = 512; r20 = (X.crt_mode & 1) ? 0x0105u : 0x0115u; vc0 = 1; vc2 = 0x0023u; break;
    case 10: case 11:
        w = 256; h = 256; r20 = (X.crt_mode & 1) ? 0x0100u : 0x0110u; vc0 = 1; vc2 = 0x0063u; break;
    case 12: case 13:
        w = 512; h = 512; r20 = (X.crt_mode & 1) ? 0x0305u : 0x0315u; vc0 = 3; vc2 = 0x0021u; break;
    case 14: case 15:
        w = 256; h = 256; r20 = (X.crt_mode & 1) ? 0x0300u : 0x0310u; vc0 = 3; vc2 = 0x0061u; break;
    default:
        w = 768; h = 512; r20 = 0x0016u; vc0 = 0; vc2 = 0x0020u; break;
    }
    X.crtc[2] = 0; X.crtc[3] = (u16)(w / 8);
    X.crtc[6] = 0; X.crtc[7] = (u16)h;
    X.crtc[20] = r20;
    X.vc_r0 = vc0;
    X.vc_r1 = 0x24E4u;                  /* Default prio: SP/BG (0) > Text (1) > Graphic (2), GP0..3 = 0,1,2,3 */
    X.vc_r2 = vc2;
    X.bg_reg[8] = (w == 256) ? 0x0000u : 0x0011u;
    X.out_w = w;
    X.out_h = h;
    X.apage = 0;
    if (!X.has_ext_ipl) {
        ram_wb(0x000924u, X.crt_mode);
        ram_ww(0x00093Cu, (u16)(w - 1));
        ram_ww(0x00093Eu, (u16)(h - 1));
        ram_wl(0x00095Cu, 0x00C00000u); /* Active GVRAM base pointer (_GVRAM_PTR) */
        ram_ww(0x000960u, (X.crtc[20] & 0x0400u) ? 2048u : 1024u);
    }
    if (!no_clear) {
        for (u32 i = 0; i < 512u * 512u; i++) M->gvram[i] = 0;
        for (u32 i = 0; i < X68K_TVRAM_SIZE; i++) M->tvram[i] = 0;
        X.cur_x = X.cur_y = 0;
    }
}

/* ---- Clean-Room IOCS Handler ($FF1000 + fn*8 -> io_write $FFF800 + fn*2) ---- */

static void x68k_iocs(u32 fn)
{
    switch (fn & 0xFFu) {
    case 0x00: /* _B_KEYINP */
        if (X.ikq_r != X.ikq_w) {
            m.r[0] = X.iocs_key_q[X.ikq_r++ & 63u];
        } else {
            m.r[0] = 0xFFFFFFFFu;       /* Signals ROM stub to STOP #$2000 and retry */
        }
        break;
    case 0x01: /* _B_KEYSNS */
        m.r[0] = (X.ikq_r != X.ikq_w) ? X.iocs_key_q[X.ikq_r & 63u] : 0u;
        break;
    case 0x02: /* _B_SFTSNS */
        m.r[0] = (X.key_bits[14] & 1u) ? 1u : 0u;
        break;
    case 0x04: /* _BITSNS */
        m.r[0] = X.key_bits[m.r[1] & 15u];
        break;
    case 0x05: /* _SKEYSET */
        m.r[0] = 0;
        break;
    case 0x0C: case 0x0D: case 0x0E: case 0x0F: /* _LEDMOD / _TGUSEMD / _DEFCHR */
        m.r[0] = 0;
        break;
    case 0x10: /* _CRTMOD */ {
        u16 d1 = (u16)m.r[1];
        u32 old = X.crt_mode;
        if (d1 != 0xFFFFu)
            apply_crtmod(d1 & 0xFFu, (d1 & 0x100u) != 0);
        m.r[0] = old;
        break;
    }
    case 0x11: /* _CONTRAST */ {
        u32 old = X.sys_contrast & 15u;
        if ((s16)m.r[1] >= 0) X.sys_contrast = (u8)(m.r[1] & 15u);
        m.r[0] = old;
        break;
    }
    case 0x13: /* _TPALET */
    case 0x14: /* _TPALET2 */ {
        u32 idx = m.r[1] & 255u;
        u32 old = X.tpal[idx];
        if ((s32)m.r[2] >= 0) {
            X.tpal[idx] = (u16)m.r[2];
            X.tpal15[idx] = x68k_col15((u16)m.r[2]);
        }
        m.r[0] = old;
        break;
    }
    case 0x15: /* _TCOLOR */ {
        u32 old = X.txt_color;
        if ((s16)m.r[1] >= 0) X.txt_color = m.r[1] & 15u;
        m.r[0] = old;
        break;
    }
    case 0x19: /* _FNTGET */ {
        u32 sz_kind = (m.r[1] >> 16) & 0xFFu;
        u32 code = m.r[1] & 0xFFFFu;
        u32 dst = m.r[9] & 0xFFFFFFu;
        if (code < 0x100u) {
            u32 h = (sz_kind == 8u) ? 8u : 16u;
            ram_ww(dst, 8u); ram_ww(dst + 2u, (u16)h);
            u32 base = (h == 8u) ? (0x3A000u + code * 8u) : (0x3A800u + code * 16u);
            for (u32 i = 0; i < h; i++) ram_wb(dst + 4u + i, M->cg[base + i]);
        } else {
            u32 j1 = (code >> 8) & 0x7Fu, j2 = code & 0x7Fu;
            u32 ku = j1 >= 0x21u ? j1 - 0x21u : 0u;
            u32 ten = j2 >= 0x21u ? j2 - 0x21u : 0u;
            u32 base = (ku * 94u + ten) * 32u;
            if (base + 32u > X68K_CG_MAX) base = 0;
            ram_ww(dst, 16u); ram_ww(dst + 2u, 16u);
            for (u32 i = 0; i < 32u; i++) ram_wb(dst + 4u + i, M->cg[base + i]);
        }
        m.r[0] = 0;
        break;
    }
    case 0x1B: case 0x1C: case 0x1D:
    case 0x1E: case 0x1F: /* _B_CURON / _B_CUROFF */
    case 0xAE: case 0xAF: /* _OS_CUROF / _OS_CURON */
        m.r[0] = 0;
        break;
    case 0x20: /* _B_PUTC */
        con_putc((u8)m.r[1]);
        m.r[0] = ((u32)X.cur_x << 16) | X.cur_y;
        break;
    case 0x21: /* _B_PRINT */ {
        u32 p = m.r[9] & 0xFFFFFFu;
        for (int lim = 0; lim < 4096; lim++) {
            u8 c = p < X68K_RAM_SIZE ? ram_rb(p++) : 0;
            if (!c) break;
            con_putc(c);
        }
        m.r[9] = p;
        m.r[0] = ((u32)X.cur_x << 16) | X.cur_y;
        break;
    }
    case 0x22: /* _B_COLOR */ {
        u32 old = X.txt_color;
        if ((s16)m.r[1] >= 0) X.txt_color = m.r[1] & 15u;
        m.r[0] = old;
        break;
    }
    case 0x23: /* _B_LOCATE */ {
        u32 old = ((u32)X.cur_x << 16) | X.cur_y;
        if (m.r[1] != 0xFFFFFFFFu) {
            X.cur_x = (u16)m.r[1];
            X.cur_y = (u16)m.r[2];
        }
        m.r[0] = old;
        break;
    }
    case 0x24: con_newline(); m.r[0] = 0; break;
    case 0x25: if (X.cur_y > 0) X.cur_y--; m.r[0] = 0; break;
    case 0x26: X.cur_y = (X.cur_y > (u16)m.r[1]) ? (u16)(X.cur_y - (u16)m.r[1]) : 0; m.r[0] = 0; break;
    case 0x27: X.cur_y = (u16)(X.cur_y + (u16)m.r[1]); m.r[0] = 0; break;
    case 0x28: X.cur_x = (u16)(X.cur_x + (u16)m.r[1]); m.r[0] = 0; break;
    case 0x29: X.cur_x = (X.cur_x > (u16)m.r[1]) ? (u16)(X.cur_x - (u16)m.r[1]) : 0; m.r[0] = 0; break;
    case 0x2A: /* _B_CLR_ST */ {
        u8 mode = (u8)m.r[1];
        if (mode == 2u) { tvram_clear_rect(0, 0, 128u, 512u); X.cur_x = X.cur_y = 0; }
        else if (mode == 0u) tvram_clear_rect(0, (u32)X.cur_y * 16u, 128u, 512u - (u32)X.cur_y * 16u);
        else tvram_clear_rect(0, 0, 128u, (u32)(X.cur_y + 1u) * 16u);
        m.r[0] = 0;
        break;
    }
    case 0x2B: /* _B_ERA_ST */
        tvram_clear_rect(0, (u32)X.cur_y * 16u, 128u, 16u);
        m.r[0] = 0;
        break;
    case 0x2C: case 0x2D: m.r[0] = 0; break;
    case 0x2E: /* _B_CONSOL */ {
        u32 old = ((u32)X.con_y0 << 16) | X.con_h;
        if (m.r[1] != 0xFFFFFFFFu) X.con_y0 = (u16)m.r[1];
        if (m.r[2] != 0xFFFFFFFFu) X.con_h = (u16)((m.r[2] >> 4) ? (m.r[2] >> 4) : 31u);
        m.r[0] = old;
        break;
    }
    case 0x2F: /* _B_PUTMES */ {
        u8 col = (u8)(m.r[1] & 15u);
        u16 x = (u16)m.r[2], y = (u16)m.r[3];
        u32 n = (m.r[4] & 0xFFFFu) + 1u;
        u32 p = m.r[9] & 0xFFFFFFu;
        u16 sx = X.cur_x, sy = X.cur_y, sc = X.txt_color;
        X.cur_x = x; X.cur_y = y; X.txt_color = col;
        for (u32 i = 0; i < n; i++) {
            u8 c = p < X68K_RAM_SIZE ? ram_rb(p++) : 0;
            if (!c) break;
            con_putc(c);
        }
        m.r[2] = X.cur_x;
        X.cur_x = sx; X.cur_y = sy; X.txt_color = sc;
        m.r[0] = 0;
        break;
    }
    case 0x3B: /* _JOYGET */
        if ((m.r[1] & 1u) == 0) {
            u8 j = 0xFFu;
            if (X.pad_now & X68K_PAD_UP)    j &= ~0x01u;
            if (X.pad_now & X68K_PAD_DOWN)  j &= ~0x02u;
            if (X.pad_now & X68K_PAD_LEFT)  j &= ~0x04u;
            if (X.pad_now & X68K_PAD_RIGHT) j &= ~0x08u;
            if (X.pad_now & X68K_PAD_A)     j &= ~0x20u;
            if (X.pad_now & X68K_PAD_B)     j &= ~0x40u;
            m.r[0] = j;
        } else {
            m.r[0] = 0xFFu;
        }
        break;

    /* Disk IOCS ($40..$4F) */
    case 0x45: /* _B_WRITE */
    case 0x46: /* _B_READ */ {
        int is_wr = (fn == 0x45u);
        u16 pda = (u16)m.r[1];
        u8 dev = (u8)(pda >> 8);
        u32 d2 = m.r[2], len = m.r[3], buf_a = m.r[9] & 0xFFFFFFu;
        if ((dev & 0xF0u) == 0x80u && X.hdd_img) {
            /* SASI Hard Disk: D2 = 256-byte/512-byte/1024-byte logical record */
            u32 bps = 256u;
            u32 off = d2 * bps;
            for (u32 i = 0; i < len; i++) {
                if (!is_wr && buf_a + i < X68K_RAM_SIZE)
                    ram_wb(buf_a + i, (off + i < X.hdd_size) ? X.hdd_img[off + i] : 0);
            }
            m.r[0] = 0;
            break;
        }
        int unit = dev & 3;
        if ((dev & 0xF0u) != 0x90u || unit >= 2 || !X.drv[unit].present) {
            m.r[0] = 0x40000000u;       /* ST0 abnormal termination (bit 30 = 1) */
            break;
        }
        u32 n_code = (d2 >> 24) & 7u;
        u32 c = (d2 >> 16) & 0xFFu;
        u32 h = (d2 >> 8)  & 0xFFu;
        u32 r = d2 & 0xFFu;
        u32 bps = n_code ? (128u << n_code) : (1u << X.drv[unit].bps_shift);
        u8 tmp[1024];
        int err = 0;
        u32 pos = 0;
        while (pos < len) {
            u32 chunk = (len - pos) < bps ? (len - pos) : bps;
            if (chunk > sizeof(tmp)) chunk = sizeof(tmp);
            if (is_wr) {
                for (u32 i = 0; i < chunk; i++)
                    tmp[i] = (buf_a + pos + i < X68K_RAM_SIZE) ? ram_rb(buf_a + pos + i) : 0;
                if (fdd_rw_sector(unit, c, h, r, 1, tmp, chunk) < 0) { err = 1; break; }
            } else {
                if (fdd_rw_sector(unit, c, h, r, 0, tmp, chunk) < 0) { err = 1; break; }
                for (u32 i = 0; i < chunk; i++)
                    if (buf_a + pos + i < X68K_RAM_SIZE) ram_wb(buf_a + pos + i, tmp[i]);
            }
            pos += chunk;
            if (pos < len) {
                r++;
                if (r > X.drv[unit].spt) {
                    r = 1u;
                    h++;
                    if (h >= X.drv[unit].heads) { h = 0; c++; }
                }
            }
        }
        m.r[0] = err ? 0x40000000u : (((h & 1u) << 26) | ((u32)(unit & 3) << 24));
        break;
    }
    case 0x40: case 0x41: case 0x42: case 0x43: case 0x44:
    case 0x47: /* _B_RECALI */
    case 0x49: case 0x4B: case 0x4C: case 0x4D: case 0x4E:
        m.r[0] = 0;
        break;
    case 0x4A: /* _B_READID */ {
        int unit = (m.r[1] >> 8) & 3;
        if (unit < 2 && X.drv[unit].present) {
            m.r[2] = 0x00000100u | (X.drv[unit].bps_shift - 7u);
            m.r[0] = 0;
        } else {
            m.r[0] = 0x40000000u;
        }
        break;
    }
    case 0x4F: /* _B_DRVCHK */ {
        u8 dev = (u8)(m.r[1] >> 8);
        int unit = dev & 3;
        if ((dev & 0xF0u) == 0x90u && unit < 2 && X.drv[unit].present)
            m.r[0] = 0x06u;             /* Disk inserted (bit 1) + Ready (bit 2) */
        else if ((dev & 0xF0u) == 0x80u && X.hdd_img)
            m.r[0] = 0x06u;
        else
            m.r[0] = 0x00u;
        break;
    }

    /* RTC & System Timer ($50..$5B, $7F) */
    case 0x52: case 0x56: m.r[0] = 0x00120000u; break; /* 12:00:00 BCD */
    case 0x54: case 0x57: m.r[0] = 0x03141125u; break; /* Wed, year 14 (1994 = 1980+14), Nov 25 BCD */
    case 0x50: case 0x51: case 0x53: case 0x55: case 0x58: case 0x59: case 0x5B: m.r[0] = 0; break;
    case 0x5A: m.r[0] = 3; break;
    case 0x7F: /* _ONTIME */
        m.r[0] = (X.frame_count * 100u) / 55u;
        m.r[1] = 0;
        break;

    /* ADPCM & OPM IOCS ($60..$6F) */
    case 0x60: /* _ADPCMOUT */ {
        u16 mode = (u16)m.r[1];
        X.ppi_portc = (u8)((X.ppi_portc & 0xF0u) | ((mode & 3u)) | (((mode >> 8) & 3u) << 2));
        adpcm_update_rate();
        struct x68k_dmac_ch *d = &X.dmac[3];
        d->mar = m.r[9] & 0xFFFFFFu;
        d->mtc = (u16)(m.r[2] > 0xFFFFu ? 0xFFFFu : m.r[2]);
        d->ocr = 0x00u; d->scr = 0x04u;
        d->csr = 0x08u;
        X.adpcm.play = 1u; X.adpcm.nib_hi = 0; X.adpcm.has_byte = 0;
        X.adpcm.est = 0; X.adpcm.step_idx = 0;
        m.r[0] = 0;
        break;
    }
    case 0x62: /* _ADPCMAOT (array chain) */
    case 0x64: /* _ADPCMLOT (link array chain) */ {
        u16 mode = (u16)m.r[1];
        X.ppi_portc = (u8)((X.ppi_portc & 0xF0u) | ((mode & 3u)) | (((mode >> 8) & 3u) << 2));
        adpcm_update_rate();
        struct x68k_dmac_ch *d = &X.dmac[3];
        d->bar = m.r[9] & 0xFFFFFFu;
        d->btc = (u16)m.r[2];
        d->mtc = 0;
        d->ocr = (fn == 0x62u) ? 0x02u : 0x03u;
        d->scr = 0x04u;
        d->csr = 0x08u;
        X.adpcm.play = 1u; X.adpcm.nib_hi = 0; X.adpcm.has_byte = 0;
        X.adpcm.est = 0; X.adpcm.step_idx = 0;
        m.r[0] = 0;
        break;
    }
    case 0x66: /* _ADPCMMOD */
        if ((m.r[1] & 0xFFu) == 0u) { X.adpcm.play = 0; X.dmac[3].csr &= ~0x08u; }
        else if ((m.r[1] & 0xFFu) == 1u) X.adpcm.play = 0;
        else if ((m.r[1] & 0xFFu) == 2u) X.adpcm.play = 1u;
        m.r[0] = 0;
        break;
    case 0x67: /* _ADPCMSNS */
        m.r[0] = (X.adpcm.play && (X.dmac[3].csr & 0x08u)) ? 0x02u : 0x00u;
        break;
    case 0x68: /* _OPMSET */
        snd_render_to_line(X.cur_line);
        ym2151_write_reg(&X.opm, (u8)m.r[1], (u8)m.r[2], X68K_CPU_HZ);
        adpcm_update_rate();
        mfp_set_gpip_bit(3, ym2151_irq_active(&X.opm) ? 0 : 1);
        m.r[0] = 0;
        break;
    case 0x69: /* _OPMSNS */
        m.r[0] = X.opm.status;
        break;
    case 0x6A: /* _OPMINTST */ {
        u32 old = X.opm_iocs_cb;
        X.opm_iocs_cb = m.r[9] & 0xFFFFFFu;
        if (X.opm_iocs_cb) {
            /* Enable MFP GPIP3 (FMIRQ) falling-edge interrupt pointing to IPL OPM dispatcher ($FF0200) */
            ram_wl(((X.mfp.vr & 0xF0u) + 3u) * 4u, 0x00FF0200u);
            X.mfp.aer &= ~0x08u;
            X.mfp.ierb |= 0x08u;
            X.mfp.imrb |= 0x08u;
        }
        m.r[0] = old ? 0u : 0u;
        break;
    }
    case 0x6B: /* _TIMERDST */ {
        X.timerd_iocs_cb = m.r[9] & 0xFFFFFFu;
        if (X.timerd_iocs_cb) {
            ram_wl(((X.mfp.vr & 0xF0u) + 4u) * 4u, 0x00FF0220u);
            X.mfp.tcdcr = (u8)((X.mfp.tcdcr & 0xF0u) | (m.r[1] & 7u));
            X.mfp.tddr = X.mfp.td_reload = (u8)(m.r[1] >> 8);
            X.mfp.ierb |= 0x10u;
            X.mfp.imrb |= 0x10u;
        } else {
            X.mfp.ierb &= ~0x10u;
            X.mfp.imrb &= ~0x10u;
        }
        m.r[0] = 0;
        break;
    }

    /* System / Supervisor / Memory IOCS ($80..$8F) */
    case 0x80: /* _B_INTVCS */ {
        u32 vec = m.r[1] & 0xFFFFu;
        u32 addr = (vec < 0x200u) ? (vec * 4u) : ((vec & 0xFFu) * 4u);
        u32 old = ram_rl(addr);
        if (m.r[9] != 0xFFFFFFFFu)
            ram_wl(addr, m.r[9] & 0xFFFFFFu);
        m.r[0] = old;
        break;
    }
    case 0x81: /* _B_SUPER */ {
        /* Stack layout on entry to x68k_iocs from TRAP #15:
           [SSP + 0..3] = $00FF0106 (return to RTE stub)
           [SSP + 4..5] = caller SR
           [SSP + 6..9] = caller PC */
        u32 ssp = m.r[15] & 0xFFFFFFu;
        if (ram_rl(ssp) == 0x00FF0106u) {
            u16 caller_sr = ram_rw(ssp + 4u);
            u32 caller_pc = ram_rl(ssp + 6u);
            if (m.r[9] == 0u) {
                if (caller_sr & 0x2000u) {
                    m.r[0] = 0xFFFFFFFFu; /* Already in supervisor mode */
                } else {
                    u32 old_ssp = ssp + 10u;
                    u32 new_sp = (m.other_sp - 10u) & 0xFFFFFFu;
                    ram_wl(new_sp, 0x00FF0106u);
                    ram_ww(new_sp + 4u, (u16)(caller_sr | 0x2000u));
                    ram_wl(new_sp + 6u, caller_pc);
                    m.r[15] = new_sp;
                    m.r[0] = old_ssp;
                }
            } else {
                u32 cur_sp = ssp + 10u;
                u32 target_ssp = (m.r[9] - 10u) & 0xFFFFFFu;
                m.other_sp = cur_sp;
                ram_wl(target_ssp, 0x00FF0106u);
                ram_ww(target_ssp + 4u, (u16)(caller_sr & ~0x2000u));
                ram_wl(target_ssp + 6u, caller_pc);
                m.r[15] = target_ssp;
                m.r[0] = 0;
            }
        } else {
            m.r[0] = 0xFFFFFFFFu;
        }
        break;
    }
    case 0x82: /* _B_BPEEK */
        m.r[0] = rb(m.r[9] & 0xFFFFFFu) & 0xFFu;
        m.r[9] = (m.r[9] + 1u) & 0xFFFFFFu;
        break;
    case 0x83: /* _B_WPEEK */
        m.r[0] = rw(m.r[9] & 0xFFFFFFu) & 0xFFFFu;
        m.r[9] = (m.r[9] + 2u) & 0xFFFFFFu;
        break;
    case 0x84: /* _B_LPEEK */
        m.r[0] = rl(m.r[9] & 0xFFFFFFu);
        m.r[9] = (m.r[9] + 4u) & 0xFFFFFFu;
        break;
    case 0x85: /* _B_MEMSTR: (A1)+ -> (A2)+ for D1.L bytes */ {
        u32 src = m.r[9] & 0xFFFFFFu, dst = m.r[10] & 0xFFFFFFu, len = m.r[1];
        for (u32 i = 0; i < len; i++) wb((dst + i) & 0xFFFFFFu, rb((src + i) & 0xFFFFFFu));
        m.r[9] = (src + len) & 0xFFFFFFu;
        m.r[10] = (dst + len) & 0xFFFFFFu;
        m.r[0] = 0;
        break;
    }
    case 0x86: /* _B_BPOKE */
        wb(m.r[9] & 0xFFFFFFu, m.r[1] & 0xFFu);
        m.r[9] = (m.r[9] + 1u) & 0xFFFFFFu;
        break;
    case 0x87: /* _B_WPOKE */
        ww(m.r[9] & 0xFFFFFFu, m.r[1] & 0xFFFFu);
        m.r[9] = (m.r[9] + 2u) & 0xFFFFFFu;
        break;
    case 0x88: /* _B_LPOKE */
        wl(m.r[9] & 0xFFFFFFu, m.r[1]);
        m.r[9] = (m.r[9] + 4u) & 0xFFFFFFu;
        break;
    case 0x89: /* _B_MEMSET: (A2)+ -> (A1)+ for D1.L bytes */ {
        u32 dst = m.r[9] & 0xFFFFFFu, src = m.r[10] & 0xFFFFFFu, len = m.r[1];
        for (u32 i = 0; i < len; i++) wb((dst + i) & 0xFFFFFFu, rb((src + i) & 0xFFFFFFu));
        m.r[9] = (dst + len) & 0xFFFFFFu;
        m.r[10] = (src + len) & 0xFFFFFFu;
        m.r[0] = 0;
        break;
    }
    case 0x8A: /* _DMAMOVE: A1 -> A2, D2.L bytes */ {
        u32 src = m.r[9] & 0xFFFFFFu, dst = m.r[10] & 0xFFFFFFu, len = m.r[2];
        for (u32 i = 0; i < len; i++) wb((dst + i) & 0xFFFFFFu, rb((src + i) & 0xFFFFFFu));
        m.r[0] = 0;
        break;
    }
    case 0x8E: /* _BOOTINF */
        m.r[0] = X.boot_is_hdd ? 0x80u : (X.boot_is_x ? 0x00u : 0x90u);
        break;
    case 0x8F: /* _ROMVER */
        m.r[0] = 0x13900124u;           /* X68000 IPL 1.30 (clean ROM table expectations for Human68k 1.x - 3.x) */
        break;

    /* Graphic & Sprite/BG IOCS ($90..$DF) */
    case 0x90: /* _G_CLR_ON */
        for (u32 i = 0; i < 512u * 512u; i++) M->gvram[i] = 0;
        set_default_palettes();
        X.vc_r2 |= 0x000Fu;
        m.r[0] = 0;
        break;
    case 0x94: /* _GPALET */ {
        u32 idx = m.r[1] & 255u;
        u32 old = X.gpal[idx];
        if ((s32)m.r[2] >= 0) {
            X.gpal[idx] = (u16)m.r[2];
            X.gpal15[idx] = x68k_col15((u16)m.r[2]);
        }
        m.r[0] = old;
        break;
    }
    case 0xB0: /* _APAGE */ {
        X.apage = (u16)(m.r[1] & 3u);
        u32 depth = (X.crtc[20] >> 8) & 3u;
        u32 gptr = 0x00C00000u;
        if (!(X.crtc[20] & 0x0400u)) {
            if (depth == 0u)      gptr += (u32)(X.apage & 3u) * 0x80000u;
            else if (depth == 1u) gptr += (u32)(X.apage & 1u) * 0x80000u;
        }
        ram_wl(0x00095Cu, gptr);
        m.r[0] = 0;
        break;
    }
    case 0xB1: /* _VPAGE */
        X.vc_r2 = (u16)((X.vc_r2 & ~0x000Fu) | (m.r[1] & 0x0Fu));
        m.r[0] = 0;
        break;
    case 0xB2: /* _HOME */ {
        u32 pg = m.r[1] & 3u;
        X.crtc[12u + pg * 2u] = (u16)(m.r[2] & 0x3FFu);
        X.crtc[13u + pg * 2u] = (u16)(m.r[3] & 0x3FFu);
        m.r[0] = 0;
        break;
    }
    case 0xB4: /* _WIPE */
        for (u32 i = 0; i < 512u * 512u; i++) M->gvram[i] = 0;
        m.r[0] = 0;
        break;
    case 0xC0: /* _SP_INIT */
        for (u32 i = 0; i < sizeof(M->spr_reg); i++) M->spr_reg[i] = 0;
        for (u32 i = 0; i < X68K_PCG_SIZE; i++) M->pcg[i] = 0;
        X.bg_reg[0] = X.bg_reg[1] = X.bg_reg[2] = X.bg_reg[3] = 0;
        X.bg_reg[4] = 0x0209u;
        m.r[0] = 0;
        break;
    case 0xC1: /* _SP_ON */
        X.bg_reg[4] |= 0x0200u;
        X.vc_r2 |= 0x0040u;
        m.r[0] = 0;
        break;
    case 0xC2: /* _SP_OFF */
        X.bg_reg[4] &= ~0x0200u;
        X.vc_r2 &= ~0x0040u;
        m.r[0] = 0;
        break;
    case 0xC3: /* _SP_CGCLR */ {
        u32 idx = m.r[1] & 255u;
        for (u32 i = 0; i < 128u; i++) M->pcg[(idx * 128u + i) & (X68K_PCG_SIZE - 1u)] = 0;
        m.r[0] = 0;
        break;
    }
    case 0xC4: /* _SP_DEFCG */ {
        u32 idx = m.r[1] & 255u;
        u32 sz = (m.r[2] & 1u) ? 128u : 32u;
        u32 base = (m.r[2] & 1u) ? (idx * 128u) : (idx * 32u);
        u32 src = m.r[9] & 0xFFFFFFu;
        for (u32 i = 0; i < sz; i++)
            M->pcg[(base + i) & (X68K_PCG_SIZE - 1u)] = rb((src + i) & 0xFFFFFFu);
        m.r[0] = 0;
        break;
    }
    case 0xC6: /* _SP_REGST */ {
        u32 sp = (m.r[1] & 127u) * 8u;
        M->spr_reg[sp + 0] = (u8)(m.r[2] >> 8); M->spr_reg[sp + 1] = (u8)m.r[2];
        M->spr_reg[sp + 2] = (u8)(m.r[3] >> 8); M->spr_reg[sp + 3] = (u8)m.r[3];
        M->spr_reg[sp + 4] = (u8)(m.r[4] >> 8); M->spr_reg[sp + 5] = (u8)m.r[4];
        M->spr_reg[sp + 6] = (u8)(m.r[5] >> 8); M->spr_reg[sp + 7] = (u8)m.r[5];
        m.r[0] = 0;
        break;
    }
    case 0xC8: /* _BGSCRLST */
        if (m.r[1] & 1u) { X.bg_reg[2] = (u16)m.r[2]; X.bg_reg[3] = (u16)m.r[3]; }
        else             { X.bg_reg[0] = (u16)m.r[2]; X.bg_reg[1] = (u16)m.r[3]; }
        m.r[0] = 0;
        break;
    case 0xCA: /* _BGCTRLST */
        X.bg_reg[4] = (u16)((X.bg_reg[4] & 0x0200u) | (m.r[1] & 0x3Fu));
        m.r[0] = 0;
        break;
    case 0xCC: /* _BGTEXTCL */ {
        u32 base = (m.r[1] & 1u) ? 0x6000u : 0x4000u;
        u16 val = (u16)m.r[2];
        for (u32 i = 0; i < 64u * 64u; i++) {
            M->pcg[base + i * 2u] = (u8)(val >> 8);
            M->pcg[base + i * 2u + 1u] = (u8)val;
        }
        m.r[0] = 0;
        break;
    }
    case 0xCD: /* _BGTEXTST */ {
        u32 base = (m.r[1] & 1u) ? 0x6000u : 0x4000u;
        u32 off = base + (((m.r[3] & 63u) * 64u + (m.r[2] & 63u)) * 2u);
        M->pcg[off] = (u8)(m.r[4] >> 8);
        M->pcg[off + 1u] = (u8)m.r[4];
        m.r[0] = 0;
        break;
    }
    case 0xCF: /* _SPALET */ {
        u32 idx = (((m.r[2] & 15u) << 4) | (m.r[1] & 15u)) & 255u;
        u32 old = X.tpal[idx];
        if ((s32)m.r[3] >= 0) {
            X.tpal[idx] = (u16)m.r[3];
            X.tpal15[idx] = x68k_col15((u16)m.r[3]);
        }
        m.r[0] = old;
        break;
    }
    default:
        /* Unhandled/optional IOCS calls succeed cleanly with D0 = 0 */
        m.r[0] = 0;
        break;
    }
}

/* ---- 24-Bit Hardware Bus ($200000..$FFFFFF) ---- */

static u16 gvram_cpu_read(u32 a)
{
    u32 depth = (X.crtc[20] >> 8) & 3u;
    if (X.crtc[20] & 0x0400u) {
        /* 1024x1024 16-color virtual GVRAM */
        u32 y = (a >> 11) & 1023u, x = (a >> 1) & 1023u;
        u32 sh = (((y >> 9) << 1) | (x >> 9)) * 4u;
        return (M->gvram[(y & 511u) * 512u + (x & 511u)] >> sh) & 0x000Fu;
    }
    u32 pix = (a >> 1) & 0x3FFFFu;      /* 512 * 512 = 262,144 pixels */
    u16 w = M->gvram[pix];
    if (depth == 0u) {                  /* 16 colors: 4 pages of 512 KB */
        u32 pg = (a >> 19) & 3u;
        return (w >> (pg * 4u)) & 0x000Fu;
    }
    if (depth == 1u) {                  /* 256 colors: 2 pages of 512 KB */
        u32 pg = (a >> 19) & 1u;
        return (w >> (pg * 8u)) & 0x00FFu;
    }
    return w;                           /* 65,536 colors */
}

static void gvram_cpu_write(u32 a, u16 v, int size)
{
    /* Byte write to odd address in GVRAM writes low byte; even address is ignored or high byte in 16bpp */
    u32 depth = (X.crtc[20] >> 8) & 3u;
    if (size == 1 && !(a & 1u) && depth < 2u)
        return;
    if (X.crtc[20] & 0x0400u) {
        u32 y = (a >> 11) & 1023u, x = (a >> 1) & 1023u;
        u32 sh = (((y >> 9) << 1) | (x >> 9)) * 4u;
        u16 *p = &M->gvram[(y & 511u) * 512u + (x & 511u)];
        *p = (u16)((*p & ~(0x000Fu << sh)) | ((v & 0x000Fu) << sh));
        return;
    }
    u32 pix = (a >> 1) & 0x3FFFFu;
    u16 *p = &M->gvram[pix];
    if (depth == 0u) {
        u32 sh = ((a >> 19) & 3u) * 4u;
        *p = (u16)((*p & ~(0x000Fu << sh)) | ((v & 0x000Fu) << sh));
    } else if (depth == 1u) {
        u32 sh = ((a >> 19) & 1u) * 8u;
        *p = (u16)((*p & ~(0x00FFu << sh)) | ((v & 0x00FFu) << sh));
    } else {
        if (size == 2) *p = v;
        else if (a & 1u) *p = (u16)((*p & 0xFF00u) | (v & 0xFFu));
        else             *p = (u16)((*p & 0x00FFu) | ((v & 0xFFu) << 8));
    }
}

static void tvram_write_byte(u32 off, u8 v)
{
    if (X.crtc[21] & 0x0100u) {
        /* Simultaneous multi-plane write (CRTC R21[3:0]) with R23 bitmask */
        u32 sub = off & 0x1FFFFu;
        u8 mask = (X.crtc[21] & 0x0200u) ? (u8)((sub & 1u) ? (X.crtc[23] & 0xFFu) : (X.crtc[23] >> 8)) : 0x00u;
        u8 pmask = (u8)(X.crtc[21] & 0x0Fu);
        for (u32 p = 0; p < 4u; p++) {
            if (pmask & (1u << p)) {
                u8 *dst = &M->tvram[p * 0x20000u + sub];
                *dst = (u8)((*dst & mask) | (v & ~mask));
            }
        }
    } else {
        M->tvram[off & 0x7FFFFu] = v;
    }
}

static void crtc_exec_op(u16 v)
{
    X.crtc_op = v;
    if (v & 0x0008u) {
        /* Raster copy: 4 scanlines (512 bytes) per block from src=(R22>>8) to dst=(R22&0xFF) */
        u32 src = ((u32)(X.crtc[22] >> 8) & 0xFFu) * 512u;
        u32 dst = ((u32)(X.crtc[22] & 0xFFu)) * 512u;
        u8 pmask = (u8)(X.crtc[21] & 0x0Fu);
        for (u32 p = 0; p < 4u; p++) {
            if (pmask & (1u << p)) {
                u8 *pl = M->tvram + p * 0x20000u;
                for (u32 i = 0; i < 512u; i++)
                    pl[(dst + i) & 0x1FFFFu] = pl[(src + i) & 0x1FFFFu];
            }
        }
        X.crtc_op &= ~0x0008u;
    }
    if (v & 0x0002u) {
        /* Fast GVRAM clear across pages selected in R21[3:0] */
        u16 keep = 0xFFFFu;
        for (u32 p = 0; p < 4u; p++)
            if (X.crtc[21] & (1u << p))
                keep &= (u16)~(0x000Fu << (p * 4u));
        for (u32 i = 0; i < 512u * 512u; i++)
            M->gvram[i] &= keep;
        X.crtc_op &= ~0x0002u;
    }
}

static u8 mfp_read_byte(u32 reg)
{
    switch (reg) {
    case 0x00: {
        u8 g = X.mfp.gpip_in;
        /* Toggle HSYNC bit 7 subtly on polling so HBlank wait loops never deadlock */
        X.mfp.gpip_in ^= 0x80u;
        return g;
    }
    case 0x01: return X.mfp.aer;
    case 0x02: return X.mfp.ddr;
    case 0x03: return X.mfp.iera;
    case 0x04: return X.mfp.ierb;
    case 0x05: return X.mfp.ipra;
    case 0x06: return X.mfp.iprb;
    case 0x07: return X.mfp.isra;
    case 0x08: return X.mfp.isrb;
    case 0x09: return X.mfp.imra;
    case 0x0A: return X.mfp.imrb;
    case 0x0B: return X.mfp.vr;
    case 0x0C: return X.mfp.tacr;
    case 0x0D: return X.mfp.tbcr;
    case 0x0E: return X.mfp.tcdcr;
    case 0x0F: return X.mfp.tadr;
    case 0x10: return X.mfp.tbdr;
    case 0x11: return X.mfp.tcdr;
    case 0x12: return X.mfp.tddr;
    case 0x15: return (u8)((X.kbd_rx_r != X.kbd_rx_w ? 0x80u : 0x00u) | 0x01u);
    case 0x16: return 0x81u;            /* USART TX buffer empty */
    case 0x17:
        if (X.kbd_rx_r != X.kbd_rx_w)
            return X.kbd_rx[X.kbd_rx_r++ & 63u];
        return X.mfp.usart_udr;
    default: return 0;
    }
}

static void mfp_write_byte(u32 reg, u8 v)
{
    switch (reg) {
    case 0x01: X.mfp.aer = v; break;
    case 0x02: X.mfp.ddr = v; break;
    case 0x03: X.mfp.iera = v; X.mfp.ipra &= v; break;
    case 0x04: X.mfp.ierb = v; X.mfp.iprb &= v; break;
    case 0x05: X.mfp.ipra &= v; break;
    case 0x06: X.mfp.iprb &= v; break;
    case 0x07: X.mfp.isra &= v; break;
    case 0x08: X.mfp.isrb &= v; break;
    case 0x09: X.mfp.imra = v; break;
    case 0x0A: X.mfp.imrb = v; break;
    case 0x0B: X.mfp.vr = v; if (!(v & 8u)) X.mfp.isra = X.mfp.isrb = 0; break;
    case 0x0C: X.mfp.tacr = v & 15u; break;
    case 0x0D: X.mfp.tbcr = v & 15u; break;
    case 0x0E: X.mfp.tcdcr = v & 0x77u; break;
    case 0x0F: X.mfp.ta_reload = v; if ((X.mfp.tacr & 7u) == 0) X.mfp.tadr = v; break;
    case 0x10: X.mfp.tb_reload = v; if ((X.mfp.tbcr & 7u) == 0) X.mfp.tbdr = v; break;
    case 0x11: X.mfp.tc_reload = v; if (((X.mfp.tcdcr >> 4) & 7u) == 0) X.mfp.tcdr = v; break;
    case 0x12: X.mfp.td_reload = v; if ((X.mfp.tcdcr & 7u) == 0) X.mfp.tddr = v; break;
    case 0x17:
        X.mfp.usart_udr = v;
        break;
    }
    x68k_update_ipl();
}

static u8 dmac_read_byte(u32 off)
{
    if (off == 0xFFu) return X.dmac_gcr;
    struct x68k_dmac_ch *d = &X.dmac[(off >> 6) & 3u];
    switch (off & 0x3Fu) {
    case 0x00: return d->csr;
    case 0x01: return d->cer;
    case 0x04: return d->dcr;
    case 0x05: return d->ocr;
    case 0x06: return d->scr;
    case 0x07: return d->ccr;
    case 0x0A: return (u8)(d->mtc >> 8);
    case 0x0B: return (u8)d->mtc;
    case 0x0C: return (u8)(d->mar >> 24);
    case 0x0D: return (u8)(d->mar >> 16);
    case 0x0E: return (u8)(d->mar >> 8);
    case 0x0F: return (u8)d->mar;
    case 0x14: return (u8)(d->dar >> 24);
    case 0x15: return (u8)(d->dar >> 16);
    case 0x16: return (u8)(d->dar >> 8);
    case 0x17: return (u8)d->dar;
    case 0x1A: return (u8)(d->btc >> 8);
    case 0x1B: return (u8)d->btc;
    case 0x1C: return (u8)(d->bar >> 24);
    case 0x1D: return (u8)(d->bar >> 16);
    case 0x1E: return (u8)(d->bar >> 8);
    case 0x1F: return (u8)d->bar;
    case 0x25: return d->niv;
    case 0x27: return d->eiv;
    case 0x2D: return d->cpr;
    default: return 0;
    }
}

static void dmac_write_byte(u32 off, u8 v)
{
    if (off == 0xFFu) { X.dmac_gcr = v; return; }
    int ch = (int)((off >> 6) & 3u);
    struct x68k_dmac_ch *d = &X.dmac[ch];
    switch (off & 0x3Fu) {
    case 0x00: d->csr &= (u8)~(v & 0xF6u); x68k_update_ipl(); break;
    case 0x04: d->dcr = v; break;
    case 0x05: d->ocr = v; break;
    case 0x06: d->scr = v; break;
    case 0x07:
        d->ccr = (u8)((d->ccr & 0x08u) | (v & 0x48u));
        if (v & 0x10u) {                /* SAB: software abort */
            d->csr = (u8)((d->csr & ~0x08u) | 0x90u);
            d->cer = 0x11u;
        } else if (v & 0x80u) {         /* STR: start channel */
            d->cer = 0;
            d->csr = (u8)((d->csr & ~0xF0u) | 0x08u);
            if (ch == 2) {
                /* Memory-to-memory DMA on Channel 2 */
                u32 cnt = d->mtc ? d->mtc : 0x10000u;
                for (u32 i = 0; i < cnt; i++) {
                    u8 b = rb(d->mar & 0xFFFFFFu);
                    wb(d->dar & 0xFFFFFFu, b);
                    if (((d->scr >> 2) & 3u) == 1u) d->mar++;
                    if ((d->scr & 3u) == 1u) d->dar++;
                }
                d->mtc = 0;
                d->csr = (u8)((d->csr & ~0x08u) | 0x80u);
            }
        }
        x68k_update_ipl();
        break;
    case 0x0A: d->mtc = (u16)(((u16)v << 8) | (d->mtc & 0xFFu)); break;
    case 0x0B: d->mtc = (u16)((d->mtc & 0xFF00u) | v); break;
    case 0x0C: d->mar = (d->mar & 0x00FFFFFFu) | ((u32)v << 24); break;
    case 0x0D: d->mar = (d->mar & 0xFF00FFFFu) | ((u32)v << 16); break;
    case 0x0E: d->mar = (d->mar & 0xFFFF00FFu) | ((u32)v << 8); break;
    case 0x0F: d->mar = (d->mar & 0xFFFFFF00u) | v; break;
    case 0x14: d->dar = (d->dar & 0x00FFFFFFu) | ((u32)v << 24); break;
    case 0x15: d->dar = (d->dar & 0xFF00FFFFu) | ((u32)v << 16); break;
    case 0x16: d->dar = (d->dar & 0xFFFF00FFu) | ((u32)v << 8); break;
    case 0x17: d->dar = (d->dar & 0xFFFFFF00u) | v; break;
    case 0x1A: d->btc = (u16)(((u16)v << 8) | (d->btc & 0xFFu)); break;
    case 0x1B: d->btc = (u16)((d->btc & 0xFF00u) | v); break;
    case 0x1C: d->bar = (d->bar & 0x00FFFFFFu) | ((u32)v << 24); break;
    case 0x1D: d->bar = (d->bar & 0xFF00FFFFu) | ((u32)v << 16); break;
    case 0x1E: d->bar = (d->bar & 0xFFFF00FFu) | ((u32)v << 8); break;
    case 0x1F: d->bar = (d->bar & 0xFFFFFF00u) | v; break;
    case 0x25: d->niv = v; break;
    case 0x27: d->eiv = v; break;
    case 0x2D: d->cpr = v; break;
    }
}

static u32 io_read(u32 a, int size)
{
    /* Unpopulated RAM ($200000..$BFFFFF) -> Bus Error (/BERR) for HUMAN.SYS RAM sizing */
    if (a >= X68K_RAM_SIZE && a < 0xC00000u) {
        m68k_bus_error(a, 0);
        return size == 2 ? 0xFFFFu : 0xFFu;
    }
    /* Graphic VRAM ($C00000..$DFFFFF) */
    if (a >= 0xC00000u && a < 0xE00000u) {
        u16 w = gvram_cpu_read(a & ~1u);
        if (size == 2) return w;
        return (a & 1u) ? (w & 0xFFu) : (w >> 8);
    }
    /* Text VRAM ($E00000..$E7FFFF) */
    if (a >= 0xE00000u && a < 0xE80000u) {
        u32 off = a - 0xE00000u;
        if (size == 2) return ((u32)M->tvram[off] << 8) | M->tvram[off + 1u];
        return M->tvram[off];
    }
    /* CRTC ($E80000..$E81FFF) */
    if (a >= 0xE80000u && a < 0xE82000u) {
        u16 w = 0;
        if ((a & 0x1FFFu) < 0x30u) w = X.crtc[(a & 0x3Fu) >> 1];
        else if ((a & 0x1FFEu) == 0x0480u) w = X.crtc_op;
        if (size == 2) return w;
        return (a & 1u) ? (w & 0xFFu) : (w >> 8);
    }
    /* Video Controller & Palettes ($E82000..$E83FFF) */
    if (a >= 0xE82000u && a < 0xE84000u) {
        u32 off = a & 0x07FEu;
        u16 w = 0;
        if (off < 0x200u)      w = X.gpal[off >> 1];
        else if (off < 0x400u) w = X.tpal[(off - 0x200u) >> 1];
        else if (off < 0x500u) w = X.vc_r0;
        else if (off < 0x600u) w = X.vc_r1;
        else                   w = X.vc_r2;
        if (size == 2) return w;
        return (a & 1u) ? (w & 0xFFu) : (w >> 8);
    }
    /* HD63450 DMAC ($E84000..$E85FFF) */
    if (a >= 0xE84000u && a < 0xE86000u) {
        if (size == 2)
            return ((u32)dmac_read_byte(a & 0xFFu) << 8) | dmac_read_byte((a + 1u) & 0xFFu);
        return dmac_read_byte(a & 0xFFu);
    }
    /* CPU Area Set ($E86000..$E87FFF) */
    if (a >= 0xE86000u && a < 0xE88000u)
        return 0;
    /* MC68901 MFP ($E88000..$E89FFF, odd bytes) */
    if (a >= 0xE88000u && a < 0xE8A000u) {
        u8 b = mfp_read_byte((a & 0x3Fu) >> 1);
        return (size == 2) ? b : ((a & 1u) ? b : 0u);
    }
    /* RP5C15 RTC ($E8A000..$E8BFFF, odd bytes: valid 1994-11-25 12:00:00) */
    if (a >= 0xE8A000u && a < 0xE8C000u) {
        static const u8 rtc_nib[16] = {0, 0, 0, 0, 2, 1, 3, 5, 2, 1, 1, 4, 1, 8, 0, 0};
        u8 b = rtc_nib[(a >> 1) & 15u];
        return (size == 2) ? b : ((a & 1u) ? b : 0u);
    }
    /* Printer ($E8C000) & System Port ($E8E000) */
    if (a >= 0xE8C000u && a < 0xE90000u) {
        if (a < 0xE8E000u) return 0x01u; /* Printer ready */
        u8 b = 0xFFu;
        switch (a & 0x0Fu) {
        case 0x01: b = X.sys_contrast & 15u; break;
        case 0x03: b = X.sys_tvctrl; break;
        case 0x0B: b = 0xFFu; break;    /* 10 MHz 68000 */
        }
        return (size == 2) ? b : ((a & 1u) ? b : 0u);
    }
    /* YM2151 OPM ($E90000..$E91FFF, odd bytes: $E90003 = status) */
    if (a >= 0xE90000u && a < 0xE92000u) {
        u8 b = X.opm.status;
        return (size == 2) ? b : ((a & 1u) ? b : 0u);
    }
    /* OKI MSM6258V ADPCM ($E92000..$E93FFF, odd bytes: bit 7 = 0 ready / 1 idle) */
    if (a >= 0xE92000u && a < 0xE94000u) {
        u8 b = X.adpcm.play ? 0x00u : 0x80u;
        return (size == 2) ? b : ((a & 1u) ? b : 0u);
    }
    /* uPD72065 FDC ($E94000..$E95FFF) */
    if (a >= 0xE94000u && a < 0xE96000u) {
        u8 b = 0;
        switch (a & 7u) {
        case 1: b = X.fdc.msr; break;
        case 3:
            if (X.fdc.res_pos < X.fdc.res_len) {
                b = X.fdc.res[X.fdc.res_pos++];
                if (X.fdc.res_pos >= X.fdc.res_len) X.fdc.msr = 0x80u;
            }
            break;
        case 5: {
            int u = X.fdc.opt_stat & 3;
            b = (u < 2 && X.drv[u].present) ? 0x80u : 0x00u; /* Disk inserted bit 7 */
            break;
        }
        }
        return (size == 2) ? b : ((a & 1u) ? b : 0u);
    }
    /* SASI HDD ($E96000..$E97FFF) */
    if (a >= 0xE96000u && a < 0xE98000u) {
        if (!X.hdd_img) return 0;
        u8 b = 0;
        if ((a & 7u) == 1u) {
            if (X.sasi_phase == 2u && X.sasi_rem > 0) {
                b = (X.sasi_off < X.hdd_size) ? X.hdd_img[X.sasi_off++] : 0;
                if (--X.sasi_rem == 0) X.sasi_phase = 3u;
            } else if (X.sasi_phase == 3u) { b = X.sasi_status; X.sasi_phase = 4u; }
            else if (X.sasi_phase == 4u)   { b = X.sasi_msg; X.sasi_phase = 0; }
        } else if ((a & 7u) == 3u) {
            /* SASI status: b0=REQ, b1=BUSY, b2=I/O, b3=C/D, b4=MSG */
            if (X.sasi_phase == 1u)      b = 0x0Bu; /* Command: REQ|BUSY|C/D */
            else if (X.sasi_phase == 2u) b = 0x07u; /* Data In: REQ|BUSY|I/O */
            else if (X.sasi_phase == 3u) b = 0x0Fu; /* Status:  REQ|BUSY|I/O|C/D */
            else if (X.sasi_phase == 4u) b = 0x1Fu; /* Message: REQ|BUSY|I/O|C/D|MSG */
        }
        return (size == 2) ? b : ((a & 1u) ? b : 0u);
    }
    /* Z8530 SCC ($E98000..$E99FFF: Mouse & RS-232C) */
    if (a >= 0xE98000u && a < 0xE9A000u) {
        u8 b = 0x04u;                   /* Tx buffer empty */
        u32 r = a & 7u;
        if (r == 1u) {                  /* Ch B (Mouse) RR0/RRx */
            b = (X.scc_pkt_pos < X.scc_pkt_len) ? 0x05u : 0x04u;
            X.scc_reg_sel = 0;
        } else if (r == 3u) {           /* Ch B Data */
            if (X.scc_pkt_pos < X.scc_pkt_len)
                b = X.scc_pkt[X.scc_pkt_pos++];
            else b = 0;
        }
        return (size == 2) ? b : ((a & 1u) ? b : 0u);
    }
    /* 8255 PPI ($E9A000..$E9BFFF: Joypad 1, Joypad 2, ADPCM ctrl) */
    if (a >= 0xE9A000u && a < 0xE9C000u) {
        u8 b = 0xFFu;
        switch (a & 7u) {
        case 1:                         /* Port A: Joypad 1 (active-low) */
            if (X.pad_now & X68K_PAD_UP)    b &= ~0x01u;
            if (X.pad_now & X68K_PAD_DOWN)  b &= ~0x02u;
            if (X.pad_now & X68K_PAD_LEFT)  b &= ~0x04u;
            if (X.pad_now & X68K_PAD_RIGHT) b &= ~0x08u;
            if (X.pad_now & X68K_PAD_A)     b &= ~0x20u;
            if (X.pad_now & X68K_PAD_B)     b &= ~0x40u;
            break;
        case 3: b = 0xFFu; break;       /* Port B: Joypad 2 */
        case 5: b = X.ppi_portc; break;
        case 7: b = X.ppi_ctrl; break;
        }
        return (size == 2) ? b : ((a & 1u) ? b : 0u);
    }
    /* IOSC ($E9C000..$E9DFFF) */
    if (a >= 0xE9C000u && a < 0xE9E000u) {
        u8 b = ((a & 3u) == 1u) ? (u8)(X.iosc_stat | (X.iosc_en & 0x0Fu)) : X.iosc_vec;
        return (size == 2) ? b : ((a & 1u) ? b : 0u);
    }
    /* Cynthia Sprite / BG / PCG ($EB0000..$EBFFFF) */
    if (a >= 0xEB0000u && a < 0xEC0000u) {
        u32 off = a - 0xEB0000u;
        if (off < 0x400u) {
            if (size == 2) return ((u32)M->spr_reg[off] << 8) | M->spr_reg[off + 1u];
            return M->spr_reg[off];
        }
        if (off >= 0x800u && off < 0x812u) {
            u16 w = X.bg_reg[(off - 0x800u) >> 1];
            return (size == 2) ? w : ((a & 1u) ? (w & 0xFFu) : (w >> 8));
        }
        if (off >= 0x8000u) {
            u32 po = off - 0x8000u;
            if (size == 2) return ((u32)M->pcg[po] << 8) | M->pcg[po + 1u];
            return M->pcg[po];
        }
        return 0;
    }
    /* 16 KB CMOS SRAM ($ED0000..$ED3FFF) */
    if (a >= 0xED0000u && a < 0xED4000u) {
        u32 off = a - 0xED0000u;
        if (size == 2) return ((u32)M->sram[off] << 8) | M->sram[off + 1u];
        return M->sram[off];
    }
    /* Unpopulated SRAM ($ED4000..$EFFFFF) & Expansion ($E9E000..$EAFFFF, $EC0000..$ECFFFF): Bus Error */
    if (a < 0xF00000u) {
        m68k_bus_error(a, 0);
        return size == 2 ? 0xFFFFu : 0xFFu;
    }
    /* 768 KB CGROM ($F00000..$FBFFFF, mirrored across $FC0000..$FDFFFF if read) */
    if (a >= 0xF00000u && a < 0xFE0000u) {
        u32 off = (a - 0xF00000u) % X68K_CG_MAX;
        if (size == 2) return ((u32)M->cg[off] << 8) | M->cg[off + 1u];
        return M->cg[off];
    }
    return size == 2 ? 0xFFFFu : 0xFFu;
}

static void io_write(u32 a, u32 v, int size)
{
    /* Clean-room IPL ROM HLE Trap Ports ($FFF800..$FFFBFE, read-only ROM on real hardware) */
    if (!X.has_ext_ipl && a >= 0xFFF800u && a < 0xFFFC00u && size == 2) {
        if (a == 0xFFFBFCu) {
            /* TRAP #15 dispatcher: lookup vector at $000400 + (D0.B)*4, push $00FF0106 return, jump! */
            u32 fn = m.r[0] & 0xFFu;
            ram_wb(0x0009FFu, (u8)fn);
            u32 target = ram_rl(0x000400u + fn * 4u) & 0xFFFFFFu;
            m.r[15] = (m.r[15] - 4u) & 0xFFFFFFu;
            ram_wl(m.r[15], 0x00FF0106u);
            m.pc = target;
            return;
        }
        if (a == 0xFFFBF8u) {
            /* OPM IOCS _OPMINTST callback trampoline ($FF0200) */
            if (X.opm_iocs_cb) {
                m.r[15] = (m.r[15] - 4u) & 0xFFFFFFu;
                ram_wl(m.r[15], m.pc);
                m.pc = X.opm_iocs_cb;
            }
            return;
        }
        if (a == 0xFFFBF4u) {
            /* Timer D IOCS _TIMERDST callback trampoline ($FF0220) */
            if (X.timerd_iocs_cb) {
                m.r[15] = (m.r[15] - 4u) & 0xFFFFFFu;
                ram_wl(m.r[15], m.pc);
                m.pc = X.timerd_iocs_cb;
            }
            return;
        }
        if (a == 0xFFFBF0u) {
            /* Reset boot loader at $FF0000: read boot sector (FDD0 or SASI0) into $002000 or jump to .X */
            if (X.boot_is_x)
                return;
            if (X.drv[0].present) {
                u8 sec[1024];
                if (fdd_rw_sector(0, 0, 0, 1, 0, sec, 1024u) == 0) {
                    for (u32 i = 0; i < 1024u; i++) ram_wb(0x002000u + i, sec[i]);
                    m.r[15] = 0x002000u;
                    m.pc = 0x002000u;
                    return;
                }
            }
            if (X.hdd_img && X.hdd_size >= 1024u) {
                for (u32 i = 0; i < 1024u; i++) ram_wb(0x002000u + i, X.hdd_img[i]);
                X.boot_is_hdd = 1u;
                m.r[15] = 0x002000u;
                m.pc = 0x002000u;
                return;
            }
            return;
        }
        if (a >= 0xFFF800u && a < 0xFFFA00u) {
            x68k_iocs((a - 0xFFF800u) >> 1);
            return;
        }
    }

    if (a >= X68K_RAM_SIZE && a < 0xC00000u) {
        m68k_bus_error(a, 1);
        return;
    }
    if (a >= 0xC00000u && a < 0xE00000u) {
        gvram_cpu_write(a, (u16)v, size);
        return;
    }
    if (a >= 0xE00000u && a < 0xE80000u) {
        u32 off = a - 0xE00000u;
        if (size == 2) {
            tvram_write_byte(off, (u8)(v >> 8));
            tvram_write_byte(off + 1u, (u8)v);
        } else {
            tvram_write_byte(off, (u8)v);
        }
        return;
    }
    if (a >= 0xE80000u && a < 0xE82000u) {
        u32 r = a & 0x1FFFu;
        if (r < 0x30u) {
            u32 idx = r >> 1;
            if (size == 2) X.crtc[idx] = (u16)v;
            else if (a & 1u) X.crtc[idx] = (u16)((X.crtc[idx] & 0xFF00u) | (v & 0xFFu));
            else             X.crtc[idx] = (u16)((X.crtc[idx] & 0x00FFu) | ((v & 0xFFu) << 8));
            if (idx <= 7u || idx == 20u) update_resolution_from_crtc();
        } else if ((r & ~1u) == 0x0480u) {
            u16 op = (size == 2) ? (u16)v : ((a & 1u) ? (u16)v : (u16)(v << 8));
            crtc_exec_op(op);
        }
        return;
    }
    if (a >= 0xE82000u && a < 0xE84000u) {
        u32 off = a & 0x07FFu;
        if (off < 0x200u) {
            u32 idx = off >> 1;
            if (size == 2) X.gpal[idx] = (u16)v;
            else if (a & 1u) X.gpal[idx] = (u16)((X.gpal[idx] & 0xFF00u) | (v & 0xFFu));
            else             X.gpal[idx] = (u16)((X.gpal[idx] & 0x00FFu) | ((v & 0xFFu) << 8));
            X.gpal15[idx] = x68k_col15(X.gpal[idx]);
        } else if (off < 0x400u) {
            u32 idx = (off - 0x200u) >> 1;
            if (size == 2) X.tpal[idx] = (u16)v;
            else if (a & 1u) X.tpal[idx] = (u16)((X.tpal[idx] & 0xFF00u) | (v & 0xFFu));
            else             X.tpal[idx] = (u16)((X.tpal[idx] & 0x00FFu) | ((v & 0xFFu) << 8));
            X.tpal15[idx] = x68k_col15(X.tpal[idx]);
        } else {
            u16 *reg = (off < 0x500u) ? &X.vc_r0 : (off < 0x600u ? &X.vc_r1 : &X.vc_r2);
            if (size == 2) *reg = (u16)v;
            else if (a & 1u) *reg = (u16)((*reg & 0xFF00u) | (v & 0xFFu));
            else             *reg = (u16)((*reg & 0x00FFu) | ((v & 0xFFu) << 8));
        }
        return;
    }
    if (a >= 0xE84000u && a < 0xE86000u) {
        if (size == 2) {
            dmac_write_byte(a & 0xFFu, (u8)(v >> 8));
            dmac_write_byte((a + 1u) & 0xFFu, (u8)v);
        } else {
            dmac_write_byte(a & 0xFFu, (u8)v);
        }
        return;
    }
    if (a >= 0xE86000u && a < 0xE88000u)
        return;
    if (a >= 0xE88000u && a < 0xE8A000u) {
        if (size == 2 || (a & 1u))
            mfp_write_byte((a & 0x3Fu) >> 1, (u8)v);
        return;
    }
    if (a >= 0xE8A000u && a < 0xE8E000u)
        return;
    if (a >= 0xE8E000u && a < 0xE90000u) {
        u8 b = (u8)v;
        switch (a & 0x0Fu) {
        case 0x01: X.sys_contrast = b & 15u; break;
        case 0x03: X.sys_tvctrl = b; break;
        case 0x07: X.sys_keyctrl = b; break;
        case 0x0D: X.sram_unlock = b; break;
        }
        return;
    }
    if (a >= 0xE90000u && a < 0xE92000u) {
        if (size == 2 || (a & 1u)) {
            if ((a & 3u) == 1u) {
                X.opm.addr_latch = (u8)v;
            } else {
                snd_render_to_line(X.cur_line);
                ym2151_write_reg(&X.opm, X.opm.addr_latch, (u8)v, X68K_CPU_HZ);
                adpcm_update_rate();
                mfp_set_gpip_bit(3, ym2151_irq_active(&X.opm) ? 0 : 1);
            }
        }
        return;
    }
    if (a >= 0xE92000u && a < 0xE94000u) {
        if (size == 2 || (a & 1u)) {
            u8 b = (u8)v;
            if ((a & 3u) == 1u) {
                snd_render_to_line(X.cur_line);
                if (b & 1u) { X.adpcm.play = 0; X.adpcm.rec = 0; }
                if (b & 2u) {
                    X.adpcm.play = 1u; X.adpcm.nib_hi = 0; X.adpcm.has_byte = 0;
                    X.adpcm.est = 0; X.adpcm.step_idx = 0;
                }
            } else {
                X.adpcm.cur_byte = b;
                X.adpcm.has_byte = 1u;
            }
        }
        return;
    }
    if (a >= 0xE94000u && a < 0xE96000u) {
        if (size == 2 || (a & 1u)) {
            u8 b = (u8)v;
            switch (a & 7u) {
            case 3: fdc_write_data(b); break;
            case 5: X.fdc.opt_stat = b; break;
            case 7: X.fdc.drv_sel = b; X.fdc.motor = (b >> 7) & 1u; break;
            }
        }
        return;
    }
    if (a >= 0xE96000u && a < 0xE98000u) {
        if (!X.hdd_img) return;
        u8 b = (u8)v;
        switch (a & 7u) {
        case 1:
            if (X.sasi_phase == 1u) {
                X.sasi_cmd[X.sasi_cmd_pos++] = b;
                if (X.sasi_cmd_pos >= 6u) {
                    u8 op = X.sasi_cmd[0];
                    u32 lba = (((u32)X.sasi_cmd[1] & 0x1Fu) << 16) | ((u32)X.sasi_cmd[2] << 8) | X.sasi_cmd[3];
                    u32 blks = X.sasi_cmd[4] ? X.sasi_cmd[4] : 256u;
                    X.sasi_status = 0; X.sasi_msg = 0;
                    if (op == 0x08u) {  /* READ(6) */
                        X.sasi_off = lba * 256u;
                        X.sasi_rem = blks * 256u;
                        if (X.dmac[1].csr & 0x08u) {
                            u32 cnt = X.dmac[1].mtc ? X.dmac[1].mtc : X.sasi_rem;
                            for (u32 i = 0; i < cnt; i++) {
                                u8 db = (X.sasi_off + i < X.hdd_size) ? X.hdd_img[X.sasi_off + i] : 0;
                                u32 ma = (X.dmac[1].mar + i) & 0xFFFFFFu;
                                if (ma < X68K_RAM_SIZE) ram_wb(ma, db);
                            }
                            X.dmac[1].mar += cnt; X.dmac[1].mtc = 0;
                            X.dmac[1].csr = (u8)((X.dmac[1].csr & ~0x08u) | 0x80u);
                            X.sasi_rem = 0; X.sasi_phase = 3u;
                            X.iosc_stat |= 0x10u;
                            x68k_update_ipl();
                        } else {
                            X.sasi_phase = 2u;
                        }
                    } else {
                        X.sasi_phase = 3u;
                        X.iosc_stat |= 0x10u;
                        x68k_update_ipl();
                    }
                }
            }
            break;
        case 3: X.sasi_phase = 0; break;
        case 7: X.sasi_phase = 1u; X.sasi_cmd_pos = 0; break;
        }
        return;
    }
    if (a >= 0xE98000u && a < 0xE9A000u) {
        if ((a & 7u) == 1u) {
            u8 b = (u8)v;
            /* SCC Ch B RTS edge triggers a 3-byte X68000 mouse packet: [status, dx, dy] */
            if (X.scc_reg_sel == 5u && (b & 2u)) {
                s16 dx = X.mouse_dx, dy = X.mouse_dy;
                if (dx > 127) dx = 127; else if (dx < -128) dx = -128;
                if (dy > 127) dy = 127; else if (dy < -128) dy = -128;
                X.mouse_dx -= dx; X.mouse_dy -= dy;
                X.scc_pkt[0] = (u8)(X.mouse_btn & 3u);
                X.scc_pkt[1] = (u8)(s8)dx;
                X.scc_pkt[2] = (u8)(s8)dy;
                X.scc_pkt_len = 3u; X.scc_pkt_pos = 0;
            } else {
                X.scc_reg_sel = b & 15u;
            }
        }
        return;
    }
    if (a >= 0xE9A000u && a < 0xE9C000u) {
        if (size == 2 || (a & 1u)) {
            u8 b = (u8)v;
            if ((a & 7u) == 5u) {
                snd_render_to_line(X.cur_line);
                X.ppi_portc = b;
                adpcm_update_rate();
            } else if ((a & 7u) == 7u) {
                if (b & 0x80u) {
                    X.ppi_ctrl = b;
                } else {
                    /* 8255 BSR mode: bit 3..1 = Port C bit#, bit 0 = set/reset! (Used heavily for ADPCM pan/rate!) */
                    snd_render_to_line(X.cur_line);
                    u8 bit = (b >> 1) & 7u;
                    if (b & 1u) X.ppi_portc |= (u8)(1u << bit);
                    else        X.ppi_portc &= (u8)~(1u << bit);
                    adpcm_update_rate();
                }
            }
        }
        return;
    }
    if (a >= 0xE9C000u && a < 0xE9E000u) {
        if (size == 2 || (a & 1u)) {
            if ((a & 3u) == 1u) X.iosc_en = (u8)(v & 0x0Fu);
            else                X.iosc_vec = (u8)(v & 0xFCu);
            x68k_update_ipl();
        }
        return;
    }
    if (a >= 0xEB0000u && a < 0xEC0000u) {
        u32 off = a - 0xEB0000u;
        if (off < 0x400u) {
            if (size == 2) { M->spr_reg[off] = (u8)(v >> 8); M->spr_reg[off + 1u] = (u8)v; }
            else M->spr_reg[off] = (u8)v;
        } else if (off >= 0x800u && off < 0x812u) {
            u32 idx = (off - 0x800u) >> 1;
            if (size == 2) X.bg_reg[idx] = (u16)v;
            else if (a & 1u) X.bg_reg[idx] = (u16)((X.bg_reg[idx] & 0xFF00u) | (v & 0xFFu));
            else             X.bg_reg[idx] = (u16)((X.bg_reg[idx] & 0x00FFu) | ((v & 0xFFu) << 8));
        } else if (off >= 0x8000u) {
            u32 po = off - 0x8000u;
            if (size == 2) { M->pcg[po] = (u8)(v >> 8); M->pcg[po + 1u] = (u8)v; }
            else M->pcg[po] = (u8)v;
        }
        return;
    }
    if (a >= 0xED0000u && a < 0xED4000u) {
        if (X.sram_unlock == 0x31u) {
            u32 off = a - 0xED0000u;
            if (size == 2) { M->sram[off] = (u8)(v >> 8); M->sram[off + 1u] = (u8)v; }
            else M->sram[off] = (u8)v;
            X.sram_dirty = 1u;
        }
        return;
    }
    if (a < 0xF00000u)
        m68k_bus_error(a, 1);
}

/* ---- Scanline Video Compositor (GVRAM 16/256/65536c + Text VRAM + Cynthia BG0/BG1 + 128 Sprites) ---- */

struct x68k_act_spr {
    s16 sx, sy;
    u16 attr;
};

static int __attribute__((optimize("O2")))
render_sp_bg_line(int y, u16 *sp_col, u8 *sp_nz,
                  const struct x68k_act_spr act_spr[3][128], const int n_act[3])
{
    int w = X.out_w;
    if (!(X.vc_r2 & 0x0040u))
        return 0;

    u16 bg_ctrl = X.bg_reg[4];
    if (!(bg_ctrl & 0x0209u))
        return 0;

    int any_px = 0;
    u32 *snz32 = (u32 *)(void *)sp_nz;
    for (int i = 0, n32 = (w + 3) >> 2; i < n32; i++) snz32[i] = 0;
    int tile16 = (X.bg_reg[8] & 3u) != 0;

    /* Priorities 1 (back), BG1, 2 (mid), BG0, 3 (front) */
    for (int pass = 1; pass <= 5; pass++) {
        if (pass == 1 || pass == 3 || pass == 5) {
            if (!(bg_ctrl & 0x0200u))
                continue;
            int pidx = (pass >> 1);
            int cnt = n_act[pidx];
            const struct x68k_act_spr *list = act_spr[pidx];
            for (int i = 0; i < cnt; i++) {
                int ry = y - list[i].sy;
                if ((unsigned)ry >= 16u)
                    continue;
                int sx = list[i].sx;
                u16 attr = list[i].attr;
                int fy = (attr & 0x8000u) ? (15 - ry) : ry;
                int hflip = (attr & 0x4000u) != 0;
                const u16 *pal = X.tpal15 + (((attr >> 8) & 15u) << 4);
                const u8 *blk = M->pcg + ((attr & 0xFFu) * 128u);
                u32 off_y = ((fy >= 8) ? 32u : 0u) + (u32)(fy & 7) * 4u;
                const u8 *rl_p = blk + off_y;
                const u8 *rr_p = blk + 64u + off_y;
                for (int px = 0; px < 16; px++) {
                    int dx = sx + px;
                    if ((unsigned)dx >= (unsigned)w)
                        continue;
                    int fx = hflip ? (15 - px) : px;
                    u8 b = (fx < 8) ? rl_p[fx >> 1] : rr_p[(fx - 8) >> 1];
                    u8 pen = (fx & 1) ? (b & 0x0Fu) : (b >> 4);
                    if (pen) {
                        sp_col[dx] = pal[pen];
                        sp_nz[dx] = 1u;
                        any_px = 1;
                    }
                }
            }
        } else {
            int is_bg0 = (pass == 4);
            if (is_bg0 ? !(bg_ctrl & 0x0001u) : !(bg_ctrl & 0x0008u))
                continue;
            u32 map_page = is_bg0 ? ((bg_ctrl >> 1) & 3u) : ((bg_ctrl >> 4) & 3u);
            const u8 *tmap = M->pcg + ((map_page & 1u) ? 0x6000u : 0x4000u);
            u32 scx = X.bg_reg[is_bg0 ? 0 : 2] & 0x3FFu;
            u32 scy = X.bg_reg[is_bg0 ? 1 : 3] & 0x3FFu;
            if (!tile16) {
                /* 64x64 map of 8x8 tiles (512x512 wrap) */
                u32 by = ((u32)y + scy) & 511u;
                u32 ty = by >> 3, py = by & 7u;
                const u8 *mrow = tmap + ty * 128u;
                int x = 0;
                while (x < w) {
                    u32 bx = ((u32)x + scx) & 511u;
                    u32 tx = bx >> 3, px = bx & 7u;
                    u16 entry = (u16)(((u16)mrow[tx * 2u] << 8) | mrow[tx * 2u + 1u]);
                    u32 fy = (entry & 0x8000u) ? (7u - py) : py;
                    const u8 *rp = M->pcg + ((entry & 0xFFu) * 32u) + fy * 4u;
                    if (px == 0 && x + 8 <= w) {
                        if (!(rp[0] | rp[1] | rp[2] | rp[3])) {
                            x += 8;
                            continue;
                        }
                        const u16 *pal = X.tpal15 + (((entry >> 8) & 15u) << 4);
                        if (!(entry & 0x4000u)) {
                            for (int k = 0; k < 4; k++) {
                                u8 b = rp[k];
                                if (b >> 4)   { sp_col[x + k * 2]     = pal[b >> 4];   sp_nz[x + k * 2]     = 1u; }
                                if (b & 0x0Fu){ sp_col[x + k * 2 + 1] = pal[b & 0x0Fu];sp_nz[x + k * 2 + 1] = 1u; }
                            }
                        } else {
                            for (int k = 0; k < 4; k++) {
                                u8 b = rp[3 - k];
                                if (b & 0x0Fu){ sp_col[x + k * 2]     = pal[b & 0x0Fu];sp_nz[x + k * 2]     = 1u; }
                                if (b >> 4)   { sp_col[x + k * 2 + 1] = pal[b >> 4];   sp_nz[x + k * 2 + 1] = 1u; }
                            }
                        }
                        any_px = 1;
                        x += 8;
                        continue;
                    }
                    u32 fx = (entry & 0x4000u) ? (7u - px) : px;
                    u8 b = rp[fx >> 1];
                    u8 pen = (fx & 1u) ? (b & 0x0Fu) : (b >> 4);
                    if (pen) {
                        sp_col[x] = X.tpal15[(((entry >> 8) & 15u) << 4) | pen];
                        sp_nz[x] = 1u;
                        any_px = 1;
                    }
                    x++;
                }
            } else {
                /* 64x64 map of 16x16 tiles (1024x1024 wrap) */
                u32 by = ((u32)y + scy) & 1023u;
                u32 ty = by >> 4, py = by & 15u;
                const u8 *mrow = tmap + ty * 128u;
                int x = 0;
                while (x < w) {
                    u32 bx = ((u32)x + scx) & 1023u;
                    u32 tx = bx >> 4, px = bx & 15u;
                    u16 entry = (u16)(((u16)mrow[tx * 2u] << 8) | mrow[tx * 2u + 1u]);
                    u32 fy = (entry & 0x8000u) ? (15u - py) : py;
                    const u8 *blk = M->pcg + ((entry & 0xFFu) * 128u);
                    u32 yoff = ((fy >= 8u) ? 32u : 0u) + (fy & 7u) * 4u;
                    const u8 *rl_p = blk + yoff;
                    const u8 *rr_p = blk + 64u + yoff;
                    if (px == 0 && x + 16 <= w) {
                        if (!(rl_p[0] | rl_p[1] | rl_p[2] | rl_p[3] |
                              rr_p[0] | rr_p[1] | rr_p[2] | rr_p[3])) {
                            x += 16;
                            continue;
                        }
                        const u16 *pal = X.tpal15 + (((entry >> 8) & 15u) << 4);
                        if (!(entry & 0x4000u)) {
                            for (int k = 0; k < 4; k++) {
                                u8 bl = rl_p[k], br = rr_p[k];
                                if (bl >> 4)   { sp_col[x + k * 2]      = pal[bl >> 4];   sp_nz[x + k * 2]      = 1u; }
                                if (bl & 0x0Fu){ sp_col[x + k * 2 + 1]  = pal[bl & 0x0Fu];sp_nz[x + k * 2 + 1]  = 1u; }
                                if (br >> 4)   { sp_col[x + 8 + k * 2]  = pal[br >> 4];   sp_nz[x + 8 + k * 2]  = 1u; }
                                if (br & 0x0Fu){ sp_col[x + 9 + k * 2]  = pal[br & 0x0Fu];sp_nz[x + 9 + k * 2]  = 1u; }
                            }
                        } else {
                            for (int k = 0; k < 4; k++) {
                                u8 br = rr_p[3 - k], bl = rl_p[3 - k];
                                if (br & 0x0Fu){ sp_col[x + k * 2]      = pal[br & 0x0Fu];sp_nz[x + k * 2]      = 1u; }
                                if (br >> 4)   { sp_col[x + k * 2 + 1]  = pal[br >> 4];   sp_nz[x + k * 2 + 1]  = 1u; }
                                if (bl & 0x0Fu){ sp_col[x + 8 + k * 2]  = pal[bl & 0x0Fu];sp_nz[x + 8 + k * 2]  = 1u; }
                                if (bl >> 4)   { sp_col[x + 9 + k * 2]  = pal[bl >> 4];   sp_nz[x + 9 + k * 2]  = 1u; }
                            }
                        }
                        any_px = 1;
                        x += 16;
                        continue;
                    }
                    u32 fx = (entry & 0x4000u) ? (15u - px) : px;
                    u8 b = (fx < 8u) ? rl_p[fx >> 1] : rr_p[(fx - 8u) >> 1];
                    u8 pen = (fx & 1u) ? (b & 0x0Fu) : (b >> 4);
                    if (pen) {
                        sp_col[x] = X.tpal15[(((entry >> 8) & 15u) << 4) | pen];
                        sp_nz[x] = 1u;
                        any_px = 1;
                    }
                    x++;
                }
            }
        }
    }
    return any_px;
}

static void __attribute__((optimize("O2"))) render_frame(u16 *pic)
{
    int w = X.out_w, h = X.out_h;
    u16 bg_backdrop = X.gpal15[0];
    u32 gdepth = X.vc_r0 & 3u;
    int g1024 = (X.vc_r0 & 4u) || (X.crtc[20] & 0x0400u);
    int txt_on = (X.vc_r2 & 0x0020u) != 0;
    int sp_on  = (X.vc_r2 & 0x0040u) != 0;
    int grp_on = (X.vc_r2 & (g1024 ? 0x001Fu : 0x000Fu)) != 0;

    /* VC R1 priority ranks (0 = frontmost, 2 = backmost; paint from 3 down to 0!) */
    int pr_sp  = (X.vc_r1 >> 12) & 3;
    int pr_txt = (X.vc_r1 >> 10) & 3;
    int pr_grp = (X.vc_r1 >> 8)  & 3;

    /* Pre-group visible sprites once per frame instead of 384 checks per scanline */
    struct x68k_act_spr act_spr[3][128];
    int n_act[3] = {0, 0, 0};
    if (sp_on && (X.bg_reg[4] & 0x0200u)) {
        for (int s = 127; s >= 0; s--) {
            const u8 *sr = M->spr_reg + s * 8;
            u8 prw = sr[7] & 3u;
            if (!prw) continue;
            int sy = ((sr[2] << 8 | sr[3]) & 0x3FF) - 16;
            if (sy >= h || sy + 16 <= 0) continue;
            int sx = ((sr[0] << 8 | sr[1]) & 0x3FF) - 16;
            if (sx >= w || sx + 16 <= 0) continue;
            int idx = n_act[prw - 1]++;
            act_spr[prw - 1][idx].sx = (s16)sx;
            act_spr[prw - 1][idx].sy = (s16)sy;
            act_spr[prw - 1][idx].attr = (u16)((sr[4] << 8) | sr[5]);
        }
    }

    u16 grp_col[X68K_W_MAX], txt_col[X68K_W_MAX], sp_col[X68K_W_MAX];
    u8  grp_nz[X68K_W_MAX + 4] __attribute__((aligned(4)));
    u8  txt_nz[X68K_W_MAX + 4] __attribute__((aligned(4)));
    u8  sp_nz[X68K_W_MAX + 4]  __attribute__((aligned(4)));

    int act_sh[4], n_act_pg = 0, same_gscroll = 1;
    u16 act_nib_mask = 0;
    u32 g0_scx = 0, g0_scy = 0;
    if (grp_on && !g1024 && gdepth == 0u) {
        for (int rank = 0; rank < 4; rank++) {
            u32 pg = (X.vc_r1 >> (rank * 2)) & 3u;
            if (!(X.vc_r2 & (1u << pg))) continue;
            u32 sx = X.crtc[12u + pg * 2u] & 511u;
            u32 sy = X.crtc[13u + pg * 2u] & 511u;
            if (n_act_pg == 0) { g0_scx = sx; g0_scy = sy; }
            else if (sx != g0_scx || sy != g0_scy) same_gscroll = 0;
            act_sh[n_act_pg++] = (int)(pg * 4u);
            act_nib_mask |= (u16)(0x000Fu << (pg * 4u));
        }
    }
    u32 act_nib_mask32 = (u32)act_nib_mask | ((u32)act_nib_mask << 16);
    u32 bg32 = (u32)bg_backdrop | ((u32)bg_backdrop << 16);
    int grp_direct = (!txt_on || pr_grp >= pr_txt) && (!sp_on || pr_grp >= pr_sp);

    for (int y = 0; y < h; y++) {
        u16 *dst = pic + y * w;
        int dst_aligned = (((__UINTPTR_TYPE__)dst) & 3u) == 0u;
        if (dst_aligned) {
            u32 *d32 = (u32 *)(void *)dst;
            for (int i = 0; i < (w >> 1); i++) d32[i] = bg32;
            if (w & 1) dst[w - 1] = bg_backdrop;
        } else {
            for (int x = 0; x < w; x++) dst[x] = bg_backdrop;
        }

        int grp_any = 0, txt_any = 0, sp_any = 0;

        /* 1. Graphic layer(s) */
        if (grp_on) {
            int gw = w < 512 ? w : 512;
            u16 *gout = grp_direct ? dst : grp_col;
            if (!grp_direct) {
                u32 *gnz32 = (u32 *)(void *)grp_nz;
                for (int i = 0, n32 = (w + 3) >> 2; i < n32; i++) gnz32[i] = 0;
            }
            if (g1024) {
                u32 scx = X.crtc[12] & 1023u, scy = ((u32)y + X.crtc[13]) & 1023u;
                u32 qy = (scy >> 9) << 1, ry = (scy & 511u) * 512u;
                for (int x = 0; x < gw; x++) {
                    u32 gx = (scx + (u32)x) & 1023u;
                    u32 sh = (qy | (gx >> 9)) * 4u;
                    u8 pen = (u8)((M->gvram[ry + (gx & 511u)] >> sh) & 15u);
                    if (pen) { gout[x] = X.gpal15[pen]; if (!grp_direct) { grp_nz[x] = 1u; grp_any = 1; } }
                }
            } else if (gdepth >= 2u) {
                /* 65,536-color mode */
                u32 scx = X.crtc[12] & 511u, scy = ((u32)y + X.crtc[13]) & 511u;
                const u16 *grow = M->gvram + scy * 512u;
                if (scx == 0 && !(gw & 1)) {
                    const u32 *g32 = (const u32 *)(const void *)grow;
                    if (grp_direct && dst_aligned) {
                        u32 *d32 = (u32 *)(void *)dst;
                        for (int x = 0; x < gw; x += 2) {
#ifdef __mips__
                            if (!(x & 15))
                                __asm__ volatile("pref 0, 64(%0)" : : "r"(g32 + (x >> 1)));
#endif
                            u32 w2 = g32[x >> 1];
                            if (!w2) continue;
                            u32 out2 = ((w2 >> 6) & 0x03FF03FFu) | ((w2 & 0x003E003Eu) << 9);
                            if ((w2 & 0xFFFFu) && (w2 >> 16)) d32[x >> 1] = out2;
                            else if (w2 & 0xFFFFu) dst[x] = (u16)out2;
                            else dst[x + 1] = (u16)(out2 >> 16);
                        }
                    } else {
                        for (int x = 0; x < gw; x += 2) {
                            u32 w2 = g32[x >> 1];
                            if (!w2) continue;
                            u32 out2 = ((w2 >> 6) & 0x03FF03FFu) | ((w2 & 0x003E003Eu) << 9);
                            if (w2 & 0xFFFFu) { gout[x]     = (u16)out2;         if (!grp_direct) { grp_nz[x]     = 1u; grp_any = 1; } }
                            if (w2 >> 16)     { gout[x + 1] = (u16)(out2 >> 16); if (!grp_direct) { grp_nz[x + 1] = 1u; grp_any = 1; } }
                        }
                    }
                } else {
                    for (int x = 0; x < gw; x++) {
                        u16 raw = grow[(scx + (u32)x) & 511u];
                        if (raw) { gout[x] = x68k_col15(raw); if (!grp_direct) { grp_nz[x] = 1u; grp_any = 1; } }
                    }
                }
            } else if (gdepth == 1u) {
                /* 256-color mode (2 pages: back-to-front per VC R1) */
                for (int rank = 1; rank >= 0; rank--) {
                    u32 pg = (X.vc_r1 >> (rank * 4)) & 1u;
                    if (!(X.vc_r2 & (1u << (pg * 2u)))) continue;
                    u32 scx = X.crtc[12u + pg * 4u] & 511u;
                    u32 scy = ((u32)y + X.crtc[13u + pg * 4u]) & 511u;
                    const u16 *grow = M->gvram + scy * 512u;
                    u32 sh = pg * 8u;
                    for (int x = 0; x < gw; x++) {
                        u8 pen = (u8)((grow[(scx + (u32)x) & 511u] >> sh) & 0xFFu);
                        if (pen) { gout[x] = X.gpal15[pen]; if (!grp_direct) { grp_nz[x] = 1u; grp_any = 1; } }
                    }
                }
            } else if (same_gscroll) {
                /* 16-color mode fast single-pass (reads 512 KB GVRAM once instead of 4x!) */
                if (n_act_pg > 0) {
                    u32 scy = ((u32)y + g0_scy) & 511u;
                    const u16 *grow = M->gvram + scy * 512u;
                    if (g0_scx == 0u && !(gw & 1)) {
                        const u32 *g32 = (const u32 *)(const void *)grow;
                        for (int x = 0; x < gw; x += 2) {
#ifdef __mips__
                            if (!(x & 15))
                                __asm__ volatile("pref 0, 64(%0)" : : "r"(g32 + (x >> 1)));
#endif
                            u32 w2 = g32[x >> 1] & act_nib_mask32;
                            if (!w2) continue;
                            u32 w0 = w2 & 0xFFFFu, w1 = w2 >> 16;
                            if (w0) {
                                for (int k = 0; k < n_act_pg; k++) {
                                    u32 pen = (w0 >> act_sh[k]) & 0x0Fu;
                                    if (pen) { gout[x] = X.gpal15[pen]; if (!grp_direct) { grp_nz[x] = 1u; grp_any = 1; } break; }
                                }
                            }
                            if (w1) {
                                for (int k = 0; k < n_act_pg; k++) {
                                    u32 pen = (w1 >> act_sh[k]) & 0x0Fu;
                                    if (pen) { gout[x + 1] = X.gpal15[pen]; if (!grp_direct) { grp_nz[x + 1] = 1u; grp_any = 1; } break; }
                                }
                            }
                        }
                    } else {
                        for (int x = 0; x < gw; x++) {
                            u32 w0 = grow[(g0_scx + (u32)x) & 511u] & act_nib_mask;
                            if (!w0) continue;
                            for (int k = 0; k < n_act_pg; k++) {
                                u32 pen = (w0 >> act_sh[k]) & 0x0Fu;
                                if (pen) { gout[x] = X.gpal15[pen]; if (!grp_direct) { grp_nz[x] = 1u; grp_any = 1; } break; }
                            }
                        }
                    }
                }
            } else {
                /* 16-color mode (4 pages with independent scrolls: paint from rank 3 down to 0) */
                for (int rank = 3; rank >= 0; rank--) {
                    u32 pg = (X.vc_r1 >> (rank * 2)) & 3u;
                    if (!(X.vc_r2 & (1u << pg))) continue;
                    u32 scx = X.crtc[12u + pg * 2u] & 511u;
                    u32 scy = ((u32)y + X.crtc[13u + pg * 2u]) & 511u;
                    const u16 *grow = M->gvram + scy * 512u;
                    u32 sh = pg * 4u;
                    for (int x = 0; x < gw; x++) {
                        u8 pen = (u8)((grow[(scx + (u32)x) & 511u] >> sh) & 0x0Fu);
                        if (pen) { gout[x] = X.gpal15[pen]; if (!grp_direct) { grp_nz[x] = 1u; grp_any = 1; } }
                    }
                }
            }
        }

        /* 2. Text layer (4 bitplanes, 1024x1024 — 32-pixel u32 fast skip & lazy clear) */
        if (txt_on) {
            u32 tx0 = X.crtc[10] & 1023u;
            u32 ty  = ((u32)y + X.crtc[11]) & 1023u;
            u32 roff = ty * 128u;
            const u8 *p0 = M->tvram + roff;
            const u8 *p1 = p0 + 0x20000u, *p2 = p0 + 0x40000u, *p3 = p0 + 0x60000u;
            if ((tx0 & 31u) == 0 && (w & 31) == 0) {
                int words = w >> 5;
                u32 wo0 = tx0 >> 5;
                const u32 *q0 = (const u32 *)(const void *)p0;
                const u32 *q1 = (const u32 *)(const void *)p1;
                const u32 *q2 = (const u32 *)(const void *)p2;
                const u32 *q3 = (const u32 *)(const void *)p3;
                for (int q = 0; q < words; q++) {
                    u32 wi = (wo0 + (u32)q) & 31u;
                    u32 a32 = q0[wi] | q1[wi] | q2[wi] | q3[wi];
                    int x32 = q << 5;
                    if (!a32) {
                        if (txt_any) {
                            u32 *tnz = (u32 *)(void *)(txt_nz + x32);
                            tnz[0] = 0; tnz[1] = 0; tnz[2] = 0; tnz[3] = 0;
                            tnz[4] = 0; tnz[5] = 0; tnz[6] = 0; tnz[7] = 0;
                        }
                        continue;
                    }
                    if (!txt_any) {
                        u32 *tnz0 = (u32 *)(void *)txt_nz;
                        for (int z = 0; z < (x32 >> 2); z++) tnz0[z] = 0;
                        txt_any = 1;
                    }
                    u32 bo_base = wi << 2;
                    for (int b = 0; b < 4; b++) {
                        u32 bo = bo_base + (u32)b;
                        u8 v0 = p0[bo], v1 = p1[bo], v2 = p2[bo], v3 = p3[bo];
                        int x8 = x32 + (b << 3);
                        if (!(v0 | v1 | v2 | v3)) {
                            *(u32 *)(void *)(txt_nz + x8) = 0;
                            *(u32 *)(void *)(txt_nz + x8 + 4) = 0;
                            continue;
                        }
                        for (int k = 0; k < 8; k++) {
                            u32 sh = 7u - (u32)k;
                            u8 pen = (u8)(((v0 >> sh) & 1u) |
                                          (((v1 >> sh) & 1u) << 1) |
                                          (((v2 >> sh) & 1u) << 2) |
                                          (((v3 >> sh) & 1u) << 3));
                            txt_nz[x8 + k] = pen;
                            if (pen) txt_col[x8 + k] = X.tpal15[pen];
                        }
                    }
                }
            } else if ((tx0 & 7u) == 0 && (w & 7) == 0) {
                int bytes = w >> 3;
                u32 bo0 = tx0 >> 3;
                for (int b = 0; b < bytes; b++) {
                    u32 bo = (bo0 + (u32)b) & 127u;
                    u8 v0 = p0[bo], v1 = p1[bo], v2 = p2[bo], v3 = p3[bo];
                    u8 any = v0 | v1 | v2 | v3;
                    int x8 = b << 3;
                    if (!any) {
                        *(u32 *)(txt_nz + x8) = 0;
                        *(u32 *)(txt_nz + x8 + 4) = 0;
                        continue;
                    }
                    txt_any = 1;
                    for (int k = 0; k < 8; k++) {
                        u32 sh = 7u - (u32)k;
                        u8 pen = (u8)(((v0 >> sh) & 1u) |
                                      (((v1 >> sh) & 1u) << 1) |
                                      (((v2 >> sh) & 1u) << 2) |
                                      (((v3 >> sh) & 1u) << 3));
                        txt_nz[x8 + k] = pen;
                        if (pen) txt_col[x8 + k] = X.tpal15[pen];
                    }
                }
            } else {
                for (int x = 0; x < w; x++) {
                    u32 tx = (tx0 + (u32)x) & 1023u;
                    u32 bo = tx >> 3, bit = 7u - (tx & 7u);
                    u8 pen = (u8)((((p0[bo] >> bit) & 1u)) |
                                  (((p1[bo] >> bit) & 1u) << 1) |
                                  (((p2[bo] >> bit) & 1u) << 2) |
                                  (((p3[bo] >> bit) & 1u) << 3));
                    txt_nz[x] = pen;
                    if (pen) { txt_col[x] = X.tpal15[pen]; txt_any = 1; }
                }
            }
        }

        /* 3. Cynthia Sprite + BG0/BG1 layer */
        if (sp_on)
            sp_any = render_sp_bg_line(y, sp_col, sp_nz, act_spr, n_act);

        /* 4. Composite back-to-front according to VC R1 priority (3=back .. 0=front; ties: SP > TXT > GRP) */
        for (int rank = 3; rank >= 0; rank--) {
            if (grp_any && pr_grp == rank) {
                int x = 0;
                for (; x + 4 <= w; x += 4) {
                    u32 nz4 = *(const u32 *)(const void *)&grp_nz[x];
                    if (!nz4) continue;
                    if (nz4 & 0x000000FFu) dst[x]     = grp_col[x];
                    if (nz4 & 0x0000FF00u) dst[x + 1] = grp_col[x + 1];
                    if (nz4 & 0x00FF0000u) dst[x + 2] = grp_col[x + 2];
                    if (nz4 & 0xFF000000u) dst[x + 3] = grp_col[x + 3];
                }
                for (; x < w; x++) if (grp_nz[x]) dst[x] = grp_col[x];
            }
            if (txt_any && pr_txt == rank) {
                int x = 0;
                for (; x + 4 <= w; x += 4) {
                    u32 nz4 = *(const u32 *)(const void *)&txt_nz[x];
                    if (!nz4) continue;
                    if (nz4 & 0x000000FFu) dst[x]     = txt_col[x];
                    if (nz4 & 0x0000FF00u) dst[x + 1] = txt_col[x + 1];
                    if (nz4 & 0x00FF0000u) dst[x + 2] = txt_col[x + 2];
                    if (nz4 & 0xFF000000u) dst[x + 3] = txt_col[x + 3];
                }
                for (; x < w; x++) if (txt_nz[x]) dst[x] = txt_col[x];
            }
            if (sp_any && pr_sp == rank) {
                int x = 0;
                for (; x + 4 <= w; x += 4) {
                    u32 nz4 = *(const u32 *)(const void *)&sp_nz[x];
                    if (!nz4) continue;
                    if (nz4 & 0x000000FFu) dst[x]     = sp_col[x];
                    if (nz4 & 0x0000FF00u) dst[x + 1] = sp_col[x + 1];
                    if (nz4 & 0x00FF0000u) dst[x + 2] = sp_col[x + 2];
                    if (nz4 & 0xFF000000u) dst[x + 3] = sp_col[x + 3];
                }
                for (; x < w; x++) if (sp_nz[x]) dst[x] = sp_col[x];
            }
        }
    }
}

/* ---- Keyboard & Input Queueing ---- */

static const u8 x68k_ascii_to_scan[128] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x0F,0x10,0x1D,0x00,0x00,0x1D,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,
    0x35,0x02,0x03,0x04,0x05,0x06,0x07,0x08, 0x09,0x0A,0x27,0x26,0x30,0x0C,0x31,0x32,
    0x0B,0x02,0x03,0x04,0x05,0x06,0x07,0x08, 0x09,0x0A,0x27,0x26,0x30,0x0C,0x31,0x32,
    0x1B,0x1E,0x2D,0x2B,0x20,0x13,0x21,0x22, 0x23,0x18,0x24,0x25,0x26,0x2F,0x2E,0x19,
    0x1A,0x11,0x14,0x1F,0x15,0x17,0x2C,0x12, 0x2A,0x16,0x29,0x1C,0x0E,0x28,0x0D,0x33,
    0x1B,0x1E,0x2D,0x2B,0x20,0x13,0x21,0x22, 0x23,0x18,0x24,0x25,0x26,0x2F,0x2E,0x19,
    0x1A,0x11,0x14,0x1F,0x15,0x17,0x2C,0x12, 0x2A,0x16,0x29,0x1C,0x0E,0x28,0x0D,0x0F
};

static const u8 x68k_scan_to_ascii[128] = {
    0, 27, '1','2','3','4','5','6','7','8','9','0','-','^','\\', 8,
    9, 'q','w','e','r','t','y','u','i','o','p','@','[', 13,'a','s',
    'd','f','g','h','j','k','l',';',':',']','z','x','c','v','b','n',
    'm',',','.','/','_',' ', 0,  0,  0,  0,  0, 0x13,0x05,0x04,0x18, 0
};
/* Note exact X68000 keycodes:
   0x01=ESC, 0x1D=CR, 0x2A='z'(42), 0x2B='x'(43), 0x35=SPACE(53),
   0x3B=LEFT(59), 0x3C=UP(60), 0x3D=RIGHT(61), 0x3E=DOWN(62) */

static void push_x68k_key(u8 scan, int pressed)
{
    if (!scan || scan >= 128u)
        return;
    u8 raw = pressed ? scan : (u8)(scan | 0x80u);
    if ((u8)(X.kbd_rx_w - X.kbd_rx_r) < 63u) {
        X.kbd_rx[X.kbd_rx_w++ & 63u] = raw;
        mfp_raise(12);                  /* MFP USART Rx Buffer Full (vector VR|12) */
    }
    if (pressed && (u8)(X.ikq_w - X.ikq_r) < 63u) {
        u8 asc = x68k_scan_to_ascii[scan];
        if (scan == 0x1Du) asc = 13u;
        else if (scan == 0x01u) asc = 27u;
        else if (scan == 0x35u) asc = ' ';
        X.iocs_key_q[X.ikq_w++ & 63u] = (u16)(((u16)scan << 8) | asc);
    }
}

static void sync_key_matrix(u16 pad)
{
    X.pad_now = pad;
    for (int i = 0; i < 16; i++) X.pad_bits[i] = 0;

    #define SET_K(bits, sc) ((bits)[(sc) >> 3] |= (u8)(1u << ((sc) & 7)))
    if (pad & X68K_PAD_LEFT)   { SET_K(X.pad_bits, 0x3Bu); SET_K(X.pad_bits, 0x47u); }
    if (pad & X68K_PAD_UP)     { SET_K(X.pad_bits, 0x3Cu); SET_K(X.pad_bits, 0x44u); }
    if (pad & X68K_PAD_RIGHT)  { SET_K(X.pad_bits, 0x3Du); SET_K(X.pad_bits, 0x49u); }
    if (pad & X68K_PAD_DOWN)   { SET_K(X.pad_bits, 0x3Eu); SET_K(X.pad_bits, 0x4Cu); }
    if (pad & X68K_PAD_A)      { SET_K(X.pad_bits, 0x2Au); SET_K(X.pad_bits, 0x35u); } /* Z + Space */
    if (pad & X68K_PAD_B)      { SET_K(X.pad_bits, 0x2Bu); }                           /* X */
    if (pad & X68K_PAD_START)  { SET_K(X.pad_bits, 0x1Du); }                           /* Return */
    if (pad & X68K_PAD_SELECT) { SET_K(X.pad_bits, 0x55u); }                           /* XF1 */

    if (X.tq_hold > 0) {
        X.tq_hold--;
        if (X.tq_hold >= 2u && X.tq_code) SET_K(X.pad_bits, X.tq_code);
    } else if (X.tq_r != X.tq_w) {
        u8 ch = (u8)X.type_q[X.tq_r++ & 127u];
        X.tq_code = (ch < 128u) ? x68k_ascii_to_scan[ch] : 0;
        if (X.tq_code) {
            SET_K(X.pad_bits, X.tq_code);
            X.tq_hold = 4u;
        }
    }
    #undef SET_K

    for (int g = 0; g < 16; g++) {
        u8 eff = X.hid_bits[g] | X.pad_bits[g];
        u8 diff = eff ^ X.prev_eff_bits[g];
        if (diff) {
            for (int b = 0; b < 8; b++) {
                if (diff & (1u << b))
                    push_x68k_key((u8)(g * 8 + b), (eff >> b) & 1);
            }
        }
        X.prev_eff_bits[g] = eff;
        X.key_bits[g] = eff;
        /* Keep IOCS/Human68k _MP_KEY bitmap at $000800..$00080F updated when unhooked */
        if (!X.has_ext_ipl)
            ram_wb(0x000800u + (u32)g, eff);
    }
}

void x68k_keys_from_hid(const u8 *usages, int n)
{
    for (int i = 0; i < 16; i++) X.hid_bits[i] = 0;
    for (int i = 0; i < n; i++) {
        u8 u = usages[i], sc = 0;
        if (u >= 0x04u && u <= 0x1Du) {
            static const u8 az[26] = {
                0x1E,0x2E,0x2C,0x20,0x13,0x21,0x22,0x23,0x18,0x24,0x25,0x26,0x30,
                0x2F,0x19,0x1A,0x11,0x14,0x1F,0x15,0x17,0x2D,0x12,0x2B,0x16,0x2A
            };
            sc = az[u - 0x04u];
        } else if (u >= 0x1Eu && u <= 0x27u) sc = (u8)(0x02u + (u - 0x1Eu));
        else if (u == 0x28u) sc = 0x1Du; /* Enter */
        else if (u == 0x29u) sc = 0x01u; /* Esc */
        else if (u == 0x2Au) sc = 0x0Fu; /* Backspace */
        else if (u == 0x2Bu) sc = 0x10u; /* Tab */
        else if (u == 0x2Cu) sc = 0x35u; /* Space */
        else if (u == 0x4Fu) sc = 0x3Du; /* Right */
        else if (u == 0x50u) sc = 0x3Bu; /* Left */
        else if (u == 0x51u) sc = 0x3Eu; /* Down */
        else if (u == 0x52u) sc = 0x3Cu; /* Up */
        else if (u >= 0x3Au && u <= 0x3Eu) sc = (u8)(0x55u + (u - 0x3Au)); /* F1..F5 -> XF1..XF5 */
        if (sc) X.hid_bits[sc >> 3] |= (u8)(1u << (sc & 7));
    }
}

void x68k_type(const char *s)
{
    while (s && *s && (u8)(X.tq_w - X.tq_r) < 127u)
        X.type_q[X.tq_w++ & 127u] = *s++;
}

void x68k_mouse(int dx, int dy, int buttons)
{
    X.mouse_dx = (s16)(X.mouse_dx + dx);
    X.mouse_dy = (s16)(X.mouse_dy + dy);
    X.mouse_btn = (u8)((buttons & 1) | ((buttons & 2) ? 2 : 0));
}

/* ---- Clean-Room IPL ROM ($FE0000..$FFFFFF) & .X Loader ---- */

static void build_clean_ipl_and_sram(void)
{
    /* Initialize 16 KB CMOS SRAM ($ED0000) with authentic X68000 signature & 2 MB RAM config */
    for (u32 i = 0; i < X68K_SRAM_SIZE; i++) M->sram[i] = 0;
    static const u8 sram_hdr[16] = {
        0xFF, 'X','6','8','0','0','0','W',
        0x00, 0x20, 0x00, 0x00,             /* $ED0008: RAM top = $00200000 (2 MB) */
        0x00, 0xFF, 0x00, 0x00              /* $ED000C: ROM start */
    };
    for (int i = 0; i < 16; i++) M->sram[i] = sram_hdr[i];
    M->sram[0x10] = 0x00; M->sram[0x11] = 0xED; M->sram[0x12] = 0x01; M->sram[0x13] = 0x00;
    M->sram[0x2A] = 0x0E;                   /* Contrast 14 */
    M->sram[0x6F] = 0x00;

    if (X.has_ext_ipl && X.ext_ipl && X.ext_ipl_sz == X68K_IPL_SIZE) {
        for (u32 i = 0; i < X68K_IPL_SIZE; i += 2u) {
            u16 w = ((u16)X.ext_ipl[i] << 8) | X.ext_ipl[i + 1u];
            ipl_ww(i, w);
        }
        /* Initial SSP & PC in first 8 bytes of RAM mirror IPL $FE0000 / $FF0000 */
        u32 boot_off = (X.ext_ipl[0x10004] || X.ext_ipl[0x10005]) ? 0x10000u : 0u;
        for (u32 i = 0; i < 8u; i++)
            ram_wb(i, X.ext_ipl[boot_off + i]);
        return;
    }

    for (u32 i = 0; i < X68K_IPL_SIZE; i += 2u)
        ipl_ww(i, 0x4E75u);                 /* Default RTS */

    /* $FF0000 (offset 0x10000 in 128 KB IPL): Initial SSP + Reset PC + bootstrap */
    ipl_wl(0x10000u, 0x00002000u);          /* Initial SSP */
    ipl_wl(0x10004u, 0x00FF0010u);          /* Initial PC */
    /* $FF0010: MOVE.W #$2000, SR ; MOVE.W SR, ($00FFFBF0).L ; JMP ($002000).L */
    ipl_ww(0x10010u, 0x46FCu); ipl_ww(0x10012u, 0x2000u);
    ipl_ww(0x10014u, 0x40F9u); ipl_wl(0x10016u, 0x00FFFBF0u);
    ipl_ww(0x1001Au, 0x4EF9u); ipl_wl(0x1001Cu, 0x00002000u);

    /* $FF0080: Default exception / interrupt handler: RTE ($4E73) */
    ipl_ww(0x10080u, 0x4E73u);

    /* $FF0100: TRAP #15 (IOCS) entry:
       $FF0100: MOVE.W SR, ($00FFFBFC).L   (pushes $00FF0106 & jumps to [$0400 + D0.B*4])
       $FF0106: RTE */
    ipl_ww(0x10100u, 0x40F9u); ipl_wl(0x10102u, 0x00FFFBFCu);
    ipl_ww(0x10106u, 0x4E73u);

    /* $FF0200: OPM IRQ trampoline (saves D0-D7/A0-A6, calls opm_iocs_cb via $FFFBF8, restores, RTE) */
    ipl_ww(0x10200u, 0x48E7u); ipl_ww(0x10202u, 0xFFFEu); /* MOVEM.L D0-D7/A0-A6, -(SP) */
    ipl_ww(0x10204u, 0x40F9u); ipl_wl(0x10206u, 0x00FFFBF8u);
    ipl_ww(0x1020Au, 0x4CDFu); ipl_ww(0x1020Cu, 0x7FFFu); /* MOVEM.L (SP)+, D0-D7/A0-A6 */
    ipl_ww(0x1020Eu, 0x4E73u);                            /* RTE */

    /* $FF0220: Timer D IRQ trampoline */
    ipl_ww(0x10220u, 0x48E7u); ipl_ww(0x10222u, 0xFFFEu);
    ipl_ww(0x10224u, 0x40F9u); ipl_wl(0x10226u, 0x00FFFBF4u);
    ipl_ww(0x1022Au, 0x4CDFu); ipl_ww(0x1022Cu, 0x7FFFu);
    ipl_ww(0x1022Eu, 0x4E73u);

    /* $FF1000..$FF1FFF: 256 IOCS stubs (16 bytes each at $FF1000 + fn*16) */
    for (u32 fn = 0; fn < 256u; fn++) {
        u32 off = 0x11000u + fn * 16u;
        if (fn == 0x00u) {
            /* _B_KEYINP: MOVE.W SR, ($00FFF800).L ; TST.L D0 ; BPL.S +4 ; STOP #$2000 ; BRA.S -14 ; RTS */
            ipl_ww(off + 0,  0x40F9u); ipl_wl(off + 2, 0x00FFF800u);
            ipl_ww(off + 6,  0x4A80u);
            ipl_ww(off + 8,  0x6A06u);
            ipl_ww(off + 10, 0x4E72u); ipl_ww(off + 12, 0x2000u);
            ipl_ww(off + 14, 0x60F0u);
            /* Put RTS right after at off + 16? Give fn=0 18 bytes by placing fn>=1 at 0x11020 + fn*8! */
        }
    }
    ipl_ww(0x11010u, 0x4E75u);              /* RTS for _B_KEYINP */
    for (u32 fn = 1; fn < 256u; fn++) {
        u32 off = 0x11020u + fn * 8u;
        ipl_ww(off + 0, 0x40F9u);
        ipl_wl(off + 2, 0x00FFF800u + fn * 2u);
        ipl_ww(off + 6, 0x4E75u);           /* RTS */
    }

    /* Populate 68000 exception vectors ($000000..$0003FF) & IOCS vector table ($000400..$0007FF) in RAM */
    ram_wl(0x000000u, 0x00002000u);
    ram_wl(0x000004u, 0x00FF0010u);
    for (u32 v = 2; v < 256u; v++)
        ram_wl(v * 4u, 0x00FF0080u);
    ram_wl(47u * 4u, 0x00FF0100u);          /* Vector 47 = TRAP #15 */
    ram_wl(0x000400u, 0x00FF1000u);         /* IOCS $00 (_B_KEYINP) */
    for (u32 fn = 1; fn < 256u; fn++)
        ram_wl(0x000400u + fn * 4u, 0x00FF1020u + fn * 8u);

    /* Initialize IOCS system work variables in $000800..$000FFF */
    ram_wl(0x000CECu, X68K_RAM_SIZE);       /* Memory ceiling = 2 MB */
    ram_wb(0x0009DDu, 0x90u);               /* Boot drive = FDD0 */
}

/* Direct loader for standalone Human68k 'HU' .x executables */
static int load_human68k_x(const u8 *data, u32 size)
{
    if (size < 64u || data[0] != 'H' || data[1] != 'U')
        return -1;
    u32 base_a = ((u32)data[4] << 24) | ((u32)data[5] << 16) | ((u32)data[6] << 8) | data[7];
    u32 exec_a = ((u32)data[8] << 24) | ((u32)data[9] << 16) | ((u32)data[10] << 8) | data[11];
    u32 text_sz = ((u32)data[12] << 24) | ((u32)data[13] << 16) | ((u32)data[14] << 8) | data[15];
    u32 data_sz = ((u32)data[16] << 24) | ((u32)data[17] << 16) | ((u32)data[18] << 8) | data[19];
    u32 bss_sz  = ((u32)data[20] << 24) | ((u32)data[21] << 16) | ((u32)data[22] << 8) | data[23];
    u32 rel_sz  = ((u32)data[24] << 24) | ((u32)data[25] << 16) | ((u32)data[26] << 8) | data[27];

    u32 load_a = base_a ? base_a : 0x010100u;
    u32 td = text_sz + data_sz;
    if (64u + td > size || load_a + td + bss_sz > X68K_RAM_SIZE - 0x4000u)
        return -1;
    for (u32 i = 0; i < td; i++)
        ram_wb(load_a + i, data[64u + i]);
    for (u32 i = 0; i < bss_sz; i++)
        ram_wb(load_a + td + i, 0);

    u32 rel_delta = load_a - base_a;
    u32 roff = 64u + td, rptr = load_a;
    while (roff + 2u <= 64u + td + rel_sz && roff + 2u <= size) {
        u32 step = ((u32)data[roff] << 8) | data[roff + 1u];
        roff += 2u;
        if (step == 0x0001u && roff + 4u <= size) {
            step = ((u32)data[roff] << 24) | ((u32)data[roff + 1u] << 16) |
                   ((u32)data[roff + 2u] << 8) | data[roff + 3u];
            roff += 4u;
        }
        rptr += step & ~1u;
        if (step & 1u) ram_ww(rptr, (u16)(ram_rw(rptr) + rel_delta));
        else           ram_wl(rptr, ram_rl(rptr) + rel_delta);
    }

    /* Minimal PSP at load_a - 0x100 */
    u32 psp = load_a - 0x100u;
    for (u32 i = 0; i < 0x100u; i++) ram_wb(psp + i, 0);
    ram_wl(psp + 0x00u, psp - 0x10u);
    ram_wl(psp + 0x08u, X68K_RAM_SIZE - 0x1000u);
    ram_wl(psp + 0x30u, load_a);
    ram_wl(psp + 0x34u, load_a + text_sz);
    ram_wl(psp + 0x38u, load_a + td);
    X.boot_is_x = 1u;
    m.r[8] = psp;
    m.r[9] = load_a + td + bss_sz;
    m.r[15] = X68K_RAM_SIZE - 0x1000u;
    m.other_sp = X68K_RAM_SIZE - 0x2000u;
    m.pc = load_a + (exec_a - base_a);
    return 0;
}

/* ---- Public Player Interface ---- */

static int ends_ci(const char *s, const char *ext)
{
    if (!s) return 0;
    int ls = 0, le = 0;
    while (s[ls]) ls++;
    while (ext[le]) le++;
    if (ls < le) return 0;
    for (int i = 0; i < le; i++) {
        char a = s[ls - le + i], b = ext[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
        if (a != b) return 0;
    }
    return 1;
}

int x68k_is_image(const u8 *head, u32 size, const char *name)
{
    if (size > 256u && head && head[0xAB] == 'D' && head[0xAC] == 'I' && head[0xAD] == 'F' && head[0xAE] == 'C')
        return 1;
    if (ends_ci(name, ".dim") || ends_ci(name, ".xdf") || ends_ci(name, ".hdm") ||
        ends_ci(name, ".2hd") || ends_ci(name, ".dup") || ends_ci(name, ".hdf"))
        return 1;
    if (ends_ci(name, ".x") && size >= 64u && head && head[0] == 'H' && head[1] == 'U')
        return 1;
    return 0;
}

void x68k_set_roms(const u8 *ipl, u32 ipl_size, const u8 *cg, u32 cg_size)
{
    X.ext_ipl = ipl; X.ext_ipl_sz = ipl_size; X.has_ext_ipl = (ipl && ipl_size == X68K_IPL_SIZE) ? 1u : 0u;
    X.ext_cg  = cg;  X.ext_cg_sz  = cg_size;  X.has_ext_cg  = (cg && cg_size >= 0x40000u) ? 1u : 0u;
}

void x68k_set_disk2(const u8 *disk2, u32 disk2_size)
{
    X.ext_disk2 = disk2;
    X.ext_disk2_sz = disk2_size;
    X.has_ext_disk2 = (disk2 && disk2_size >= 0x1000u) ? 1u : 0u;
}

const char *x68k_load(const u8 *image, u32 size, const char *name)
{
    if (!image || size < 64u)
        return "empty X68000 image";

    /* Preserve external ROM / Disk 2 pointers across X state clear */
    const u8 *ei = X.ext_ipl, *ec = X.ext_cg, *ed2 = X.ext_disk2;
    u32 eisz = X.ext_ipl_sz, ecsz = X.ext_cg_sz, ed2sz = X.ext_disk2_sz;
    u8 hi = X.has_ext_ipl, hc = X.has_ext_cg, hd2 = X.has_ext_disk2;
    u8 inited = X.cpu_inited;

    for (u32 i = 0; i < sizeof(X); i++) ((u8 *)&X)[i] = 0;
    X.ext_ipl = ei; X.ext_ipl_sz = eisz; X.has_ext_ipl = hi;
    X.ext_cg  = ec; X.ext_cg_sz  = ecsz; X.has_ext_cg  = hc;
    X.ext_disk2 = ed2; X.ext_disk2_sz = ed2sz; X.has_ext_disk2 = hd2;
    X.cpu_inited = inited;

    /* Clear shared EMU_RAM_PHYS buffers completely (prevents cross-player shared-memory hazards!) */
    for (u32 i = 0; i < X68K_RAM_SIZE; i++) M->ram[i] = 0;
    for (u32 i = 0; i < 512u * 512u; i++)   M->gvram[i] = 0;
    for (u32 i = 0; i < X68K_TVRAM_SIZE; i++) M->tvram[i] = 0;
    for (u32 i = 0; i < sizeof(M->spr_reg); i++) M->spr_reg[i] = 0;
    for (u32 i = 0; i < X68K_PCG_SIZE; i++) M->pcg[i] = 0;

    if (!X.cpu_inited) {
        cpu_init();
        X.cpu_inited = 1u;
    }

    /* Map $000000..$1FFFFF (32 x 64 KB pages) to word-swapped RAM, and $FE0000..$FFFFFF (2 pages) read-only to IPL */
    for (int i = 0; i < 256; i++) rmap[i] = wmap[i] = 0;
    for (int i = 0; i < 32; i++) {
        rmap[i] = M->ram + (u32)i * 0x10000u;
        wmap[i] = M->ram + (u32)i * 0x10000u;
    }
    rmap[0xFE] = M->ipl;
    rmap[0xFF] = M->ipl + 0x10000u;

    /* Initialize video, MFP, FDC, YM2151, ADPCM */
    X.txt_color = 3u;
    X.con_h = 31u;
    X.sys_contrast = 15u;
    set_default_palettes();
    apply_crtmod(16u, 1);               /* Default 768x512 text console on boot */

    X.mfp.gpip_in = 0xDFu;              /* HSYNC=1, CIRQ=1, VDISP=1, FMIRQ=1, ALARM=1 */
    X.mfp.vr = 0x40u;                   /* MFP vectors $40..$4F */
    X.fdc.msr = 0x80u;
    X.iosc_vec = 0x60u;                 /* IOSC vectors $60..$63 */
    X.ppi_portc = 0x08u;                /* 15.6 kHz ADPCM stereo */

    ym2151_init(&X.opm, 4000000u, 48000u);
    adpcm_update_rate();
    build_clean_cgrom();

    const char *kind = "2HD Floppy";
    if (ends_ci(name, ".hdf") || size >= 0x200000u) {
        X.hdd_img = image;
        X.hdd_size = size;
        kind = "SASI Hard Disk";
    } else if (size >= 64u && image[0] == 'H' && image[1] == 'U' && ends_ci(name, ".x")) {
        kind = "Human68k .X";
    } else {
        if (parse_floppy_image(0, image, size) < 0)
            return "unsupported X68000 disk image";
        if (X.drv[0].is_dim) kind = "DIFC .DIM Floppy";
        if (X.has_ext_disk2)
            parse_floppy_image(1, X.ext_disk2, X.ext_disk2_sz);
    }

    build_clean_ipl_and_sram();
    cpu_reset();

    if (size >= 64u && image[0] == 'H' && image[1] == 'U' && ends_ci(name, ".x")) {
        if (load_human68k_x(image, size) < 0)
            return "invalid Human68k .X executable";
    }

    /* Format short description */
    const char *bios_tag = X.has_ext_ipl ? "iplrom.dat" : "built-in IPL/IOCS";
    int p = 0;
    const char *prefix = "Sharp X68000 (2 MB, ";
    while (*prefix && p < 90) X.info_str[p++] = *prefix++;
    while (*kind && p < 90)   X.info_str[p++] = *kind++;
    const char *sep = ", ";
    while (*sep && p < 90)    X.info_str[p++] = *sep++;
    while (*bios_tag && p < 94) X.info_str[p++] = *bios_tag++;
    X.info_str[p++] = ')';
    X.info_str[p] = 0;

    /* Reset Disk 2 staging so subsequent single-disk loads don't inherit an old Disk 2 */
    X.has_ext_disk2 = 0; X.ext_disk2 = 0; X.ext_disk2_sz = 0;
    return 0;
}

const char *x68k_info(void) { return X.info_str; }
int x68k_width(void)        { return X.out_w > 0 ? X.out_w : 512; }
int x68k_height(void)       { return X.out_h > 0 ? X.out_h : 512; }
int x68k_jammed(void)       { return X.jammed_flag; }

u8 *x68k_save_ram(u32 *size, int *battery)
{
    *size = X68K_SRAM_SIZE;
    *battery = 1;
    return M->sram;
}

int x68k_save_changed(void)
{
    return X.sram_dirty;
}

void x68k_audio_rate(u32 hz)
{
    X.snd_rate = hz;
    X.opm.sample_rate = hz ? hz : 48000u;
    adpcm_update_rate();
}

int x68k_audio(s16 *out, int max_samples)
{
    int n = 0;
    while (n < max_samples && X.snd_r != X.snd_w)
        out[n++] = M->snd_ring[X.snd_r++ & (X68K_SND_RING - 1u)];
    return n;
}

/* Tick MC68901 MFP delay-mode timers (4.000 MHz MFP crystal on X68000 = 0.4 * 10 MHz CPU clock) */
static void mfp_tick_timers(s32 cpu_cycles)
{
    static const u16 presc[8] = {0, 4, 10, 16, 50, 64, 100, 200};
    /* Convert 10 MHz CPU cycles -> 4 MHz MFP ticks (* 2 / 5): keep fractional remainder in timer accumulators */
    s32 mfp_x5 = cpu_cycles * 2;

    if ((X.mfp.tacr & 7u) != 0 && X.mfp.tacr < 8u) {
        s32 step = (s32)presc[X.mfp.tacr & 7u] * 5;
        X.mfp.ta_acc += mfp_x5;
        while (X.mfp.ta_acc >= step) {
            X.mfp.ta_acc -= step;
            if (--X.mfp.tadr == 0) {
                X.mfp.tadr = X.mfp.ta_reload;
                mfp_raise(13);
            }
        }
    }
    if ((X.mfp.tbcr & 7u) != 0 && X.mfp.tbcr < 8u) {
        s32 step = (s32)presc[X.mfp.tbcr & 7u] * 5;
        X.mfp.tb_acc += mfp_x5;
        while (X.mfp.tb_acc >= step) {
            X.mfp.tb_acc -= step;
            if (--X.mfp.tbdr == 0) {
                X.mfp.tbdr = X.mfp.tb_reload;
                mfp_raise(8);
            }
        }
    }
    u8 tcm = (X.mfp.tcdcr >> 4) & 7u;
    if (tcm) {
        s32 step = (s32)presc[tcm] * 5;
        X.mfp.tc_acc += mfp_x5;
        while (X.mfp.tc_acc >= step) {
            X.mfp.tc_acc -= step;
            if (--X.mfp.tcdr == 0) {
                X.mfp.tcdr = X.mfp.tc_reload;
                mfp_raise(5);
            }
        }
    }
    u8 tdm = X.mfp.tcdcr & 7u;
    if (tdm) {
        s32 step = (s32)presc[tdm] * 5;
        X.mfp.td_acc += mfp_x5;
        while (X.mfp.td_acc >= step) {
            X.mfp.td_acc -= step;
            if (--X.mfp.tddr == 0) {
                X.mfp.tddr = X.mfp.td_reload;
                mfp_raise(4);
            }
        }
    }
}

void x68k_frame(u16 pad, u16 *picture)
{
    sync_key_matrix(pad);
    m.clock = 0;
    X.snd_rendered = 0;
    X.frame_count++;

    s32 cyc_target = 0;
    int vdisp_lines = X.out_h > 0 ? X.out_h : 512;
    if (vdisp_lines <= 256) vdisp_lines *= 2; /* Double-scanned in 31 kHz */

    for (int line = 0; line < X68K_LINES; line++) {
        X.cur_line = line;

        /* GPIP4 (VDISP): 1 during active display (0..vdisp_lines-1), 0 during VBlank */
        if (line == 0) {
            mfp_set_gpip_bit(4, 1);
        } else if (line == vdisp_lines) {
            mfp_set_gpip_bit(4, 0);
            /* Timer A in event-count mode (TACR == 8) counts VDISP once per frame */
            if (X.mfp.tacr == 8u) {
                if (--X.mfp.tadr == 0) {
                    X.mfp.tadr = X.mfp.ta_reload;
                    mfp_raise(13);
                }
            }
        }

        /* GPIP6 (CIRQ): 0 on CRTC R9 raster match line, 1 otherwise */
        int cirq_match = (X.crtc[9] > 0 && line == (int)(X.crtc[9] & 0x3FFu));
        mfp_set_gpip_bit(6, cirq_match ? 0 : 1);

        s32 before = m.clock;
        cyc_target += X68K_CYC_LINE;
        cpu_run(cyc_target);
        s32 ran = m.clock - before;
        if (ran < X68K_CYC_LINE) ran = X68K_CYC_LINE;

        mfp_tick_timers(ran);
        if (ym2151_tick_timers(&X.opm, ran, X68K_CPU_HZ))
            mfp_set_gpip_bit(3, ym2151_irq_active(&X.opm) ? 0 : 1);
        adpcm_tick_silent(ran);
    }

    snd_render_to_line(X68K_LINES - 1);
    if (picture)
        render_frame(picture);
}
