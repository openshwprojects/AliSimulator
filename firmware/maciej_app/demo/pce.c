/* A NEC PC Engine / TurboGrafx-16: see pce.h. */
#include "pce.h"
#ifndef PCE_HOST
#include "hw.h"
#endif

#define FC 0x01
#define FZ 0x02
#define FI 0x04
#define FD 0x08
#define FB 0x10
#define FT 0x20
#define FV 0x40
#define FN 0x80

#define LINE_CYC   455u                 /* 1365 master clocks / 3 = 455 CPU clocks at 7.15909 MHz */
#define LINES_DEF  263u                 /* 263 lines (262 when VCE bit 2 is set) */

struct pce_psg_ch {
    u16 freq;
    u8 ctrl, balance, wave[32], wave_idx, dda;
    u8 noise_ctrl;
    u32 phase, noise_phase, lfsr;
    s32 noise_out;
};

struct pce_mem {
    u8 wram[0x8000];                    /* 8 KB on standard PCE ($F8), 32 KB on SuperGrafx/CD ($F8..$FB) */
    u8 bram[0x800];                     /* 2 KB backup RAM at $F7 (unlocked by $1807 = 0x80) */
    u8 pad_ram[0x2000];                 /* scratch page for unmapped writes */
    u8 ff_page[0x2000];                 /* 0xFF open-bus page */
    u16 vram[0x8000];                   /* 32K words (64 KB) */
    u16 satb[256];                      /* 64 sprites x 4 words */
    u16 vce_raw[512];                   /* 9-bit GRB */
    u16 vce_pal[512];                   /* 15-bit 0bbbbbgggggrrrrr */
    u32 spread8[256], spread8_rev[256]; /* bitplane byte -> 8 x 4-bit nibbles (normal and X-flipped) */
    s16 audio_ring[4096];
};

#ifdef PCE_HOST
static struct pce_mem pce_mem_buf;
#define M (&pce_mem_buf)
#ifdef PCE_CPU_TEST
u8 pce_sst_ram[0x200000];
#endif
#else
#define M ((struct pce_mem *)KSEG0(EMU_RAM_PHYS))
#endif

static struct {
    u8 a, x, y, s, p;
    u16 pc;
    u8 mpr[8], mpr_latch;
    u8 speed;                           /* 1 = 7.16 MHz (CSH), 4 = 1.79 MHz (CSL; reset state) */
    u8 irq_mask, irq_lines;             /* bit 0: IRQ2, bit 1: IRQ1 (VDC), bit 2: TIQ (timer) */
    u8 jammed, io_buf;
    u32 cycles;
    /* timer: 7-bit counter clocked every 1024 7.16 MHz cycles */
    u8 tmr_reload, tmr_cnt, tmr_on;
    s32 tmr_prescale;
    /* VDC */
    u8 vdc_reg, vdc_status, vdc_latch_lo;
    u16 vdc[20], vram_rbuf;
    u16 bg_y;
    u8 byr_latched, satb_dirty;
    u8 burst_mode, sat_dma_slcounter;
    u16 frame_counter, display_counter, rcr_count;
    u16 lat_vds, lat_vsw, lat_vdw, lat_vcr, vblank_fl;
    /* VCE */
    u8 vce_ctrl;
    u16 vce_addr;
    /* Joypad & BRAM */
    u16 pad_state;
    u8 joy_sel, joy_clr, joy_six_toggle;
    u8 bram_unlocked, bram_dirty;
    /* Cartridge */
    u8 *rom;
    u32 rom_size, rom_pages, rom_p2;
    u8 sf2_bank, sf2_mapper, populous_ram, us_region;
    const u8 *page_r[256];
    u8 *page_w[256];
    const u8 *mpr_r[8];                 /* direct fast-path pointers for MPR0..7 (0 = I/O or BRAM) */
    u8 *mpr_w[8];
    /* Frame geometry */
    int out_w, out_h;
    /* PSG */
    u8 psg_sel, psg_vol, lfo_freq, lfo_ctrl;
    struct pce_psg_ch psg[6];
    u32 sample_rate, audio_cyc_last, audio_frac;
    int audio_count;
} S;

static char info_buf[96];

/* 30-step 1.5 dB attenuation LUT for PSG (0 = silence, 31 = max) */
static const u16 psg_vol_tab[32] = {
    0,   18,   21,   25,   30,   35,   42,   50,
   59,   70,   83,   99,  118,  140,  166,  198,
  235,  279,  332,  395,  469,  558,  663,  789,
  937, 1115, 1325, 1575, 1873, 2227, 2648, 3150
};

static u16 grb9_to_bgr15(u16 c)
{
    u32 b = c & 7u, r = (c >> 3) & 7u, g = (c >> 6) & 7u;
    u32 r5 = (r << 2) | (r >> 1);
    u32 g5 = (g << 2) | (g >> 1);
    u32 b5 = (b << 2) | (b >> 1);
    return (u16)((b5 << 10) | (g5 << 5) | r5);
}

static void sync_mpr(int i)
{
    u8 p = S.mpr[i];
    if (p == 0xFF || p == 0xF7) {
        S.mpr_r[i] = 0;
        S.mpr_w[i] = 0;
    } else {
        S.mpr_r[i] = S.page_r[p];
        S.mpr_w[i] = S.page_w[p];
    }
}

static void rebuild_pages(void)
{
    for (int p = 0; p < 256; p++) {
        S.page_r[p] = M->ff_page;
        S.page_w[p] = 0;
    }
    if (S.rom && S.rom_pages) {
        for (u32 p = 0; p < 0x80; p++) {
            u32 idx;
            if (S.sf2_mapper) {
                if (p < 0x40)
                    idx = p % S.rom_pages;
                else
                    idx = (0x40u + (u32)S.sf2_bank * 0x40u + (p - 0x40u)) % S.rom_pages;
            } else if (S.populous_ram && p >= 0x40 && p < 0x44) {
                S.page_r[p] = M->wram + 0x2000u + (p - 0x40u) * 0x2000u;
                S.page_w[p] = M->wram + 0x2000u + (p - 0x40u) * 0x2000u;
                continue;
            } else if (S.rom_pages <= 0x40) {
                if (p < 0x40 || S.rom_pages == S.rom_p2)
                    idx = p % S.rom_p2;
                else
                    idx = S.rom_p2 + ((p - 0x40u) % (S.rom_pages - S.rom_p2));
            } else {
                if (p < 0x40)
                    idx = p;
                else
                    idx = 0x40u + ((p - 0x40u) % (S.rom_pages - 0x40u));
            }
            S.page_r[p] = S.rom + idx * 0x2000u;
        }
    }
    S.page_r[0xF8] = M->wram;
    S.page_w[0xF8] = M->wram;
    for (int i = 0; i < 8; i++)
        sync_mpr(i);
}

/* ---- PSG lazy synthesis ---- */
static void psg_step_samples(u32 cyc_7m)
{
    if (!S.sample_rate || !cyc_7m)
        return;
    u32 count = 0;
    while (cyc_7m) {
        u32 chunk = cyc_7m > 8000u ? 8000u : cyc_7m;
        cyc_7m -= chunk;
        u32 num = chunk * S.sample_rate + S.audio_frac;
        count += num / 7159090u;
        S.audio_frac = num % 7159090u;
    }
    if (!count)
        return;

    /* 3579545 Hz per sample in 24.8 fixed point (916363520 fits in 32-bit u32) */
    u32 psg_step = 916363520u / S.sample_rate;
    int lm = (S.psg_vol >> 4) & 0x0F, rm = S.psg_vol & 0x0F;

    while (count--) {
        s32 mix_l = 0, mix_r = 0;
        for (int ch = 0; ch < 6; ch++) {
            struct pce_psg_ch *c = &S.psg[ch];
            if (!(c->ctrl & 0x80))
                continue;
            if (ch == 1 && (S.lfo_ctrl & 0x80))
                continue;                       /* channel 1 muted when used as LFO modulator */
            int sample5;
            if ((c->ctrl & 0xC0) == 0xC0) {     /* DDA direct sample mode */
                sample5 = c->dda & 0x1F;
            } else if (ch >= 4 && (c->noise_ctrl & 0x80)) {
                u32 nf = (c->noise_ctrl & 0x1F) ^ 0x1F;
                u32 nperiod = (nf ? nf * 64u : 32u) << 8;
                c->noise_phase += psg_step;
                while (c->noise_phase >= nperiod) {
                    c->noise_phase -= nperiod;
                    u32 bit = ((c->lfsr >> 0) ^ (c->lfsr >> 1) ^ (c->lfsr >> 11) ^ (c->lfsr >> 12) ^ (c->lfsr >> 17)) & 1u;
                    c->lfsr = (c->lfsr >> 1) | (bit << 17);
                    c->noise_out = (c->lfsr & 1u) ? 31 : 0;
                }
                sample5 = c->noise_out;
            } else {
                u32 period = c->freq ? c->freq : 4096u;
                if (ch == 0 && (S.lfo_ctrl & 0x03) && !(S.lfo_ctrl & 0x80)) {
                    struct pce_psg_ch *m = &S.psg[1];
                    u32 mp = (m->freq ? m->freq : 4096u) * (S.lfo_freq ? S.lfo_freq : 256u);
                    if (mp) {
                        m->phase += psg_step;
                        u32 mp8 = mp << 8;
                        while (m->phase >= mp8) {
                            m->phase -= mp8;
                            m->wave_idx = (m->wave_idx + 1) & 31;
                        }
                        s32 mod = (s32)(m->wave[m->wave_idx] & 0x1F) - 16;
                        int shift = ((S.lfo_ctrl & 3) - 1) * 2;
                        s32 adj = (s32)period + (mod << shift);
                        period = adj < 1 ? 1u : adj > 4095 ? 4095u : (u32)adj;
                    }
                }
                u32 p8 = period << 8;
                c->phase += psg_step;
                while (c->phase >= p8) {
                    c->phase -= p8;
                    c->wave_idx = (c->wave_idx + 1) & 31;
                }
                sample5 = c->wave[c->wave_idx] & 0x1F;
            }
            int cv = c->ctrl & 0x1F;
            int lv = cv + ((c->balance >> 4) & 0x0F) + lm - 30;
            int rv = cv + (c->balance & 0x0F) + rm - 30;
            s32 centered = sample5 - 15;
            if (lv > 0)
                mix_l += centered * (s32)psg_vol_tab[lv > 31 ? 31 : lv];
            if (rv > 0)
                mix_r += centered * (s32)psg_vol_tab[rv > 31 ? 31 : rv];
        }
        s32 mono = (mix_l + mix_r) >> 4;
        if (mono > 32767) mono = 32767;
        if (mono < -32768) mono = -32768;
        if (S.audio_count < 4096)
            M->audio_ring[S.audio_count++] = (s16)mono;
    }
}

static void psg_catch_up(void)
{
    if (!S.sample_rate)
        return;
    u32 delta = S.cycles - S.audio_cyc_last;
    S.audio_cyc_last = S.cycles;
    if (delta)
        psg_step_samples(delta);
}

/* ---- VDC helpers ---- */
static u16 vdc_inc(void)
{
    static const u16 incs[4] = {1, 32, 64, 128};
    return incs[(S.vdc[5] >> 11) & 3];
}

static void vdc_update_irq(void)
{
    if (S.vdc_status & 0x3F)
        S.irq_lines |= 0x02;
    else
        S.irq_lines &= (u8)~0x02;
}

static void vdc_satb_dma(void)
{
    u16 src = S.vdc[19];
    for (int i = 0; i < 256; i++) {
        u16 a = (u16)(src + i);
        M->satb[i] = M->vram[a & 0x7FFFu];
    }
    S.satb_dirty = 0;
    S.sat_dma_slcounter = 2;
}

static void vdc_vram_dma(void)
{
    u16 src = S.vdc[16], dst = S.vdc[17], len = S.vdc[18];
    s32 ds = (S.vdc[15] & 0x04) ? -1 : 1;
    s32 dd = (S.vdc[15] & 0x08) ? -1 : 1;
    u32 count = (u32)len + 1u;
    while (count--) {
        u16 v = src < 0x8000 ? M->vram[src] : 0;
        if (dst < 0x8000)
            M->vram[dst] = v;
        src = (u16)(src + ds);
        dst = (u16)(dst + dd);
    }
    S.vdc[16] = src;
    S.vdc[17] = dst;
    S.vdc[18] = 0xFFFF;
    if (S.vdc[15] & 0x02) {
        S.vdc_status |= 0x10;           /* DV */
        vdc_update_irq();
    }
}

/* ---- Hardware I/O page ($FF: $1FE000..$1FFFFF) ---- */
static u8 io_read(u16 off)
{
    switch (off & 0x1C00) {
    case 0x0000:                        /* HuC6270 VDC */
        switch (off & 3) {
        case 0: {
            u8 st = S.vdc_status;
            S.vdc_status &= (u8)~0x3F;
            vdc_update_irq();
            return st;
        }
        case 1:
            return 0;
        case 2:
            return (u8)(S.vram_rbuf & 0xFF);
        case 3: {
            u8 hi = (u8)(S.vram_rbuf >> 8);
            if (S.vdc_reg == 2) {
                S.vdc[1] = (u16)(S.vdc[1] + vdc_inc());
                S.vram_rbuf = S.vdc[1] < 0x8000 ? M->vram[S.vdc[1]] : 0;
            }
            return hi;
        }
        }
        return 0;

    case 0x0400:                        /* HuC6260 VCE */
        switch (off & 7) {
        case 4:
            return (u8)(M->vce_raw[S.vce_addr & 0x1FF] & 0xFF);
        case 5: {
            u8 hi = (u8)((M->vce_raw[S.vce_addr & 0x1FF] >> 8) | 0xFE);
            S.vce_addr = (S.vce_addr + 1) & 0x1FF;
            return hi;
        }
        default:
            return 0xFF;
        }

    case 0x0800:                        /* PSG: returns last I/O latch */
        return S.io_buf;

    case 0x0C00:                        /* Timer */
        S.io_buf = (S.io_buf & 0x80) | (S.tmr_cnt & 0x7F);
        return S.io_buf;

    case 0x1000: {                      /* Joypad */
        u8 lo = 0x0F;
        if (!S.joy_clr) {
            int six = (S.pad_state & 0x0F00) != 0;
            if (six && S.joy_six_toggle) {
                if (!S.joy_sel) {
                    lo = 0;             /* 6-button signature nibble: all low */
                } else {
                    if (S.pad_state & PCE_III) lo &= (u8)~0x01;
                    if (S.pad_state & PCE_IV)  lo &= (u8)~0x02;
                    if (S.pad_state & PCE_V)   lo &= (u8)~0x04;
                    if (S.pad_state & PCE_VI)  lo &= (u8)~0x08;
                }
            } else if (S.joy_sel) {     /* Directions: U R D L */
                if (S.pad_state & PCE_UP)    lo &= (u8)~0x01;
                if (S.pad_state & PCE_RIGHT) lo &= (u8)~0x02;
                if (S.pad_state & PCE_DOWN)  lo &= (u8)~0x04;
                if (S.pad_state & PCE_LEFT)  lo &= (u8)~0x08;
            } else {                    /* Buttons: I II Select Run */
                if (S.pad_state & PCE_I)      lo &= (u8)~0x01;
                if (S.pad_state & PCE_II)     lo &= (u8)~0x02;
                if (S.pad_state & PCE_SELECT) lo &= (u8)~0x04;
                if (S.pad_state & PCE_RUN)    lo &= (u8)~0x08;
            }
        }
        S.io_buf = (u8)(0x80 | (S.us_region ? 0x00 : 0x40) | 0x30 | lo);
        return S.io_buf;
    }

    case 0x1400:                        /* Interrupt controller */
        if ((off & 3) == 2) {
            S.io_buf = (S.io_buf & 0xF8) | (S.irq_mask & 0x07);
            return S.io_buf;
        }
        if ((off & 3) == 3) {
            S.io_buf = (S.io_buf & 0xF8) | (S.irq_lines & 0x07);
            return S.io_buf;
        }
        return S.io_buf;

    case 0x1800:                        /* CD / BRAM */
        if ((off & 0x0F) == 3)
            S.bram_unlocked = 0;
        return 0xFF;
    }
    return 0xFF;
}

static void vdc_write_port(u8 port, u8 v)
{
    switch (port & 3) {
    case 0:
        S.vdc_reg = v & 0x1F;
        break;
    case 2:
        if (S.vdc_reg == 2) {
            S.vdc_latch_lo = v;
        } else if (S.vdc_reg < 20) {
            S.vdc[S.vdc_reg] = (S.vdc[S.vdc_reg] & 0xFF00u) | v;
            if (S.vdc_reg == 8) {       /* BYR LSB */
                S.bg_y = S.vdc[8] & 0x1FFu;
                S.byr_latched = 1;
            } else if (S.vdc_reg == 19) {
                S.satb_dirty = 1;
            }
        }
        break;
    case 3:
        if (S.vdc_reg == 2) {
            u16 a = S.vdc[0];
            if (a < 0x8000)
                M->vram[a] = (u16)(((u16)v << 8) | S.vdc_latch_lo);
            S.vdc[0] = (u16)(a + vdc_inc());
        } else if (S.vdc_reg < 20) {
            S.vdc[S.vdc_reg] = (S.vdc[S.vdc_reg] & 0x00FFu) | ((u16)v << 8);
            if (S.vdc_reg == 1) {       /* MARR MSB latches read buffer */
                S.vram_rbuf = S.vdc[1] < 0x8000 ? M->vram[S.vdc[1]] : 0;
            } else if (S.vdc_reg == 8) { /* BYR MSB */
                S.bg_y = S.vdc[8] & 0x1FFu;
                S.byr_latched = 1;
            } else if (S.vdc_reg == 18) { /* LENR MSB triggers VRAM->VRAM DMA */
                vdc_vram_dma();
            } else if (S.vdc_reg == 19) { /* DVSSR MSB schedules SATB DMA */
                S.satb_dirty = 1;
            }
        }
        break;
    }
}

static void io_write(u16 off, u8 v)
{
    S.io_buf = v;
    switch (off & 0x1C00) {
    case 0x0000:
        vdc_write_port((u8)(off & 3), v);
        break;

    case 0x0400:
        switch (off & 7) {
        case 0:
            S.vce_ctrl = v;
            break;
        case 2:
            S.vce_addr = (S.vce_addr & 0x100u) | v;
            break;
        case 3:
            S.vce_addr = (S.vce_addr & 0x0FFu) | (((u16)v & 1u) << 8);
            break;
        case 4: {
            u16 idx = S.vce_addr & 0x1FFu;
            M->vce_raw[idx] = (M->vce_raw[idx] & 0x100u) | v;
            M->vce_pal[idx] = grb9_to_bgr15(M->vce_raw[idx]);
            break;
        }
        case 5: {
            u16 idx = S.vce_addr & 0x1FFu;
            M->vce_raw[idx] = (M->vce_raw[idx] & 0x0FFu) | (((u16)v & 1u) << 8);
            M->vce_pal[idx] = grb9_to_bgr15(M->vce_raw[idx]);
            S.vce_addr = (S.vce_addr + 1) & 0x1FFu;
            break;
        }
        }
        break;

    case 0x0800: {                      /* PSG */
        psg_catch_up();
        struct pce_psg_ch *c = &S.psg[S.psg_sel];
        switch (off & 0x0F) {
        case 0: S.psg_sel = (v & 7) < 6 ? (v & 7) : 5; break;
        case 1: S.psg_vol = v; break;
        case 2: c->freq = (c->freq & 0x0F00u) | v; break;
        case 3: c->freq = (c->freq & 0x00FFu) | (((u16)v & 0x0Fu) << 8); break;
        case 4:
            if ((v & 0xC0) == 0x40)
                c->wave_idx = 0;        /* reset waveform write pointer */
            c->ctrl = v;
            break;
        case 5: c->balance = v; break;
        case 6:
            if ((c->ctrl & 0xC0) == 0xC0) {
                c->dda = v & 0x1F;
            } else if (!(c->ctrl & 0x80)) {
                c->wave[c->wave_idx & 31] = v & 0x1F;
                c->wave_idx = (c->wave_idx + 1) & 31;
            }
            break;
        case 7:
            if (S.psg_sel >= 4)
                c->noise_ctrl = v;
            break;
        case 8: S.lfo_freq = v; break;
        case 9:
            S.lfo_ctrl = v;
            if (v & 0x80)
                S.psg[1].wave_idx = 0;
            break;
        }
        break;
    }

    case 0x0C00:                        /* Timer */
        if (!(off & 1)) {
            S.tmr_reload = v & 0x7F;
        } else {
            u8 on = v & 1;
            if (!S.tmr_on && on) {
                S.tmr_cnt = S.tmr_reload;
                S.tmr_prescale = 1024;
            }
            S.tmr_on = on;
        }
        break;

    case 0x1000: {                      /* Joypad */
        u8 new_clr = (v >> 1) & 1;
        if (!S.joy_clr && new_clr)
            S.joy_six_toggle ^= 1;
        S.joy_sel = v & 1;
        S.joy_clr = new_clr;
        break;
    }

    case 0x1400:                        /* Interrupt controller */
        if ((off & 3) == 2)
            S.irq_mask = v & 0x07;
        else if ((off & 3) == 3)
            S.irq_lines &= (u8)~0x04;   /* writing $1403 acknowledges Timer TIQ */
        break;

    case 0x1800:                        /* BRAM unlock */
        if ((off & 0x0F) == 7 && (v & 0x80))
            S.bram_unlocked = 1;
        break;
    }
}

/* ---- Bus read / write ---- */
static inline u8 bus_read(u16 a)
{
#ifdef PCE_CPU_TEST
    u32 phys = ((u32)S.mpr[a >> 13] << 13) | (a & 0x1FFFu);
    return pce_sst_ram[phys & 0x1FFFFFu];
#else
    const u8 *r = S.mpr_r[a >> 13];
    u16 off = a & 0x1FFFu;
    if (r)
        return r[off];
    if (S.mpr[a >> 13] == 0xFF)
        return io_read(off);
    return (S.bram_unlocked && off < 0x800) ? M->bram[off] : 0xFF;
#endif
}

static inline void bus_write(u16 a, u8 v)
{
#ifdef PCE_CPU_TEST
    u32 phys = ((u32)S.mpr[a >> 13] << 13) | (a & 0x1FFFu);
    pce_sst_ram[phys & 0x1FFFFFu] = v;
#else
    u8 *w = S.mpr_w[a >> 13];
    u16 off = a & 0x1FFFu;
    if (w) {
        w[off] = v;
        return;
    }
    u8 page = S.mpr[a >> 13];
    if (page == 0xFF) {
        io_write(off, v);
        return;
    }
    if (page == 0xF7) {
        if (S.bram_unlocked && off < 0x800 && M->bram[off] != v) {
            M->bram[off] = v;
            S.bram_dirty = 1;
        }
        return;
    }
    if (S.sf2_mapper && (a & 0xFFF0u) == 0x1FF0u) {
        S.sf2_bank = (u8)(a & 3u);
        rebuild_pages();
    }
#endif
}

static inline u8 zp_read(u8 zp)   { return bus_read((u16)(0x2000u | zp)); }
static inline void zp_write(u8 zp, u8 v) { bus_write((u16)(0x2000u | zp), v); }
static inline void push8(u8 v)    { bus_write((u16)(0x2100u | S.s), v); S.s--; }
static inline u8 pull8(void)      { S.s++; return bus_read((u16)(0x2100u | S.s)); }
static inline void push16(u16 v)  { push8((u8)(v >> 8)); push8((u8)v); }
static inline u16 pull16(void)    { u16 lo = pull8(); return lo | ((u16)pull8() << 8); }
static inline u8 fetch8(void)     { return bus_read(S.pc++); }
static inline u16 fetch16(void)   { u16 lo = fetch8(); return lo | ((u16)fetch8() << 8); }

static inline void set_nz(u8 v)
{
    S.p = (S.p & (u8)~(FN | FZ)) | (v & FN) | (v ? 0 : FZ);
}

static inline u16 zp_ind(u8 zp)
{
    u16 lo = zp_read(zp);
    return lo | ((u16)zp_read((u8)(zp + 1)) << 8);
}

static u8 do_adc(u8 lhs, u8 rhs, u32 *extra_cyc)
{
    u32 c = S.p & FC;
    if (S.p & FD) {
        *extra_cyc += 1;
        u32 lo = (lhs & 0x0Fu) + (rhs & 0x0Fu) + c;
        u32 hi = (lhs >> 4) + (rhs >> 4);
        if (lo > 9) {
            lo += 6;
            hi += 1;
        }
        if (hi > 9)
            hi += 6;
        u8 res = (u8)((hi << 4) | (lo & 0x0Fu));
        /* HuC6280 decimal mode leaves V unchanged */
        S.p = (S.p & (u8)~(FC | FN | FZ)) | (hi > 15 ? FC : 0) | (res & FN) | (res ? 0 : FZ);
        return res;
    } else {
        u32 sum = (u32)lhs + (u32)rhs + c;
        u8 res = (u8)sum;
        u8 ov = (u8)((~(lhs ^ rhs) & (lhs ^ res) & 0x80u) ? FV : 0);
        S.p = (S.p & (u8)~(FC | FV | FN | FZ)) | (sum > 0xFF ? FC : 0) | ov | (res & FN) | (res ? 0 : FZ);
        return res;
    }
}

static u8 do_sbc(u8 lhs, u8 rhs, u32 *extra_cyc)
{
    u32 c = (S.p & FC) ^ 1u;
    u32 diff = (u32)lhs - (u32)rhs - c;
    if (S.p & FD) {
        *extra_cyc += 1;
        s32 lo = (s32)(lhs & 0x0Fu) - (s32)(rhs & 0x0Fu) - (s32)c;
        s32 hi = (s32)(lhs >> 4) - (s32)(rhs >> 4);
        if (lo < 0) {
            lo -= 6;
            hi -= 1;
        }
        if (hi < 0)
            hi -= 6;
        u8 res = (u8)(((u32)hi << 4) | ((u32)lo & 0x0Fu));
        /* HuC6280 decimal mode leaves V unchanged */
        S.p = (S.p & (u8)~(FC | FN | FZ)) | (diff < 0x100 ? FC : 0) | (res & FN) | (res ? 0 : FZ);
        return res;
    } else {
        u8 res = (u8)diff;
        u8 ov = (u8)(((lhs ^ rhs) & (lhs ^ diff) & 0x80u) ? FV : 0);
        S.p = (S.p & (u8)~(FC | FV | FN | FZ)) | (diff < 0x100 ? FC : 0) | ov | (res & FN) | (res ? 0 : FZ);
        return res;
    }
}

static void do_cmp(u8 reg, u8 v)
{
    u32 d = (u32)reg - (u32)v;
    u8 r = (u8)d;
    S.p = (S.p & (u8)~(FC | FN | FZ)) | (d < 0x100 ? FC : 0) | (r & FN) | (r ? 0 : FZ);
}

static u32 do_branch(int cond)
{
    s32 rel = (signed char)fetch8();
    if (!cond)
        return 2;
    S.pc = (u16)(S.pc + rel);
    return 4;
}

static u32 do_block(int mode)
{
    u16 src = fetch16();
    u16 dst = fetch16();
    u16 len = fetch16();
    u32 count = len ? (u32)len : 0x10000u;
    push8(S.y);
    push8(S.a);
    push8(S.x);
    u16 alt = 0;
    for (u32 i = 0; i < count; i++) {
        u16 rs = (mode == 4) ? (u16)(src + alt) : src;
        u16 wd = (mode == 3) ? (u16)(dst + alt) : dst;
        u8 v = bus_read(rs);
        bus_write(wd, v);
        alt ^= 1u;
        if (mode == 0)      { src++; dst++; }       /* TII */
        else if (mode == 1) { src--; dst--; }       /* TDD */
        else if (mode == 2) { src++; }              /* TIN */
        else if (mode == 3) { src++; }              /* TIA */
        else                { dst++; }              /* TAI */
    }
    S.x = pull8();
    S.a = pull8();
    S.y = pull8();
    return 17u + count * 6u;
}

/* Execute one HuC6280 instruction; returns instruction cycles (at CPU's own clock) */
static u32 cpu_step(void)
{
    u8 op = fetch8();
    u8 tflag = S.p & FT;
    S.p &= (u8)~FT;                     /* every instruction other than SET clears T (PLP/RTI overwrite P) */
    u32 cyc = 2, extra = 0;
    u16 ea;
    u8 v, zp;

    /* BBRi / BBSi / RMBi / SMBi ($x7 / $xF) */
    if ((op & 0x0F) == 0x07) {
        u8 bit = (u8)(1u << ((op >> 4) & 7));
        zp = fetch8();
        v = zp_read(zp);
        if (op & 0x80) zp_write(zp, (u8)(v | bit));
        else           zp_write(zp, (u8)(v & ~bit));
        return 7;
    }
    if ((op & 0x0F) == 0x0F) {
        u8 bit = (u8)(1u << ((op >> 4) & 7));
        zp = fetch8();
        v = zp_read(zp);
        s32 rel = (signed char)fetch8();
        int hit = (op & 0x80) ? ((v & bit) != 0) : ((v & bit) == 0);
        if (hit) {
            S.pc = (u16)(S.pc + rel);
            return 8;
        }
        return 6;
    }

    switch (op) {
    /* Control & HuC6280 specials */
    case 0x00: /* BRK */
        S.pc++;
        push16(S.pc);
        push8((u8)(S.p | FB));
        S.p = (S.p & (u8)~FD) | FI;
        S.pc = bus_read(0xFFF6) | ((u16)bus_read(0xFFF7) << 8);
        return 8;
    case 0x40: /* RTI */
        S.p = (u8)(pull8() & ~FB);
        S.pc = pull16();
        return 7;
    case 0x60: /* RTS */
        S.pc = (u16)(pull16() + 1u);
        return 7;
    case 0x20: /* JSR abs */
        ea = fetch16();
        push16((u16)(S.pc - 1u));
        S.pc = ea;
        return 7;
    case 0x44: { /* BSR rel */
        s32 rel = (signed char)fetch8();
        push16((u16)(S.pc - 1u));
        S.pc = (u16)(S.pc + rel);
        return 8;
    }
    case 0x4C: /* JMP abs */
        S.pc = fetch16();
        return 4;
    case 0x6C: /* JMP (abs) -- no page-wrap bug on 65C02/HuC6280 */
        ea = fetch16();
        S.pc = bus_read(ea) | ((u16)bus_read((u16)(ea + 1)) << 8);
        return 7;
    case 0x7C: /* JMP (abs,X) */
        ea = (u16)(fetch16() + S.x);
        S.pc = bus_read(ea) | ((u16)bus_read((u16)(ea + 1)) << 8);
        return 7;

    case 0x02: v = S.x; S.x = S.y; S.y = v; return 3;      /* SXY */
    case 0x22: v = S.a; S.a = S.x; S.x = v; return 3;      /* SAX */
    case 0x42: v = S.a; S.a = S.y; S.y = v; return 3;      /* SAY */
    case 0x62: S.a = 0; return 2;                          /* CLA */
    case 0x82: S.x = 0; return 2;                          /* CLX */
    case 0xC2: S.y = 0; return 2;                          /* CLY */
    case 0x54: S.speed = 4; return 3;                      /* CSL */
    case 0xD4: S.speed = 1; return 3;                      /* CSH */
    case 0xF4: S.p |= FT; return 2;                        /* SET */

    case 0x03: /* ST0 #imm */
        v = fetch8();
#ifdef PCE_CPU_TEST
        pce_sst_ram[0x1FE000] = v;
        return 4;
#else
        vdc_write_port(0, v);
        return 5;
#endif
    case 0x13: /* ST1 #imm */
        v = fetch8();
#ifdef PCE_CPU_TEST
        pce_sst_ram[0x1FE002] = v;
        return 4;
#else
        vdc_write_port(2, v);
        return 5;
#endif
    case 0x23: /* ST2 #imm */
        v = fetch8();
#ifdef PCE_CPU_TEST
        pce_sst_ram[0x1FE003] = v;
        return 4;
#else
        vdc_write_port(3, v);
        return 5;
#endif

    case 0x43: /* TMA #imm */
        v = fetch8();
        if (v) {
            u8 ored = 0;
            for (int i = 0; i < 8; i++)
                if (v & (1u << i))
                    ored |= S.mpr[i];
            S.mpr_latch = ored;
        }
        S.a = S.mpr_latch;
        return 4;
    case 0x53: /* TAM #imm */
        v = fetch8();
        if (v) {
            S.mpr_latch = S.a;
            for (int i = 0; i < 8; i++) {
                if (v & (1u << i)) {
                    S.mpr[i] = S.a;
#ifndef PCE_CPU_TEST
                    sync_mpr(i);
#endif
                }
            }
        }
        return 5;

    case 0x73: return do_block(0);      /* TII */
    case 0xC3: return do_block(1);      /* TDD */
    case 0xD3: return do_block(2);      /* TIN */
    case 0xE3: return do_block(3);      /* TIA */
    case 0xF3: return do_block(4);      /* TAI */

    /* TST #imm, ... */
    case 0x83: v = fetch8(); zp = fetch8(); ea = zp_read(zp); goto do_tst7;
    case 0xA3: v = fetch8(); zp = (u8)(fetch8() + S.x); ea = zp_read(zp); goto do_tst7;
    case 0x93: v = fetch8(); ea = bus_read(fetch16()); cyc = 8; goto do_tst;
    case 0xB3: v = fetch8(); ea = bus_read((u16)(fetch16() + S.x)); cyc = 8; goto do_tst;
    do_tst7:
        cyc = 7;
    do_tst:
        S.p = (S.p & (u8)~(FN | FV | FZ)) | ((u8)ea & (FN | FV)) | ((v & (u8)ea) ? 0 : FZ);
        return cyc;

    /* Branches */
    case 0x80: return do_branch(1);
    case 0x10: return do_branch(!(S.p & FN));
    case 0x30: return do_branch((S.p & FN) != 0);
    case 0x50: return do_branch(!(S.p & FV));
    case 0x70: return do_branch((S.p & FV) != 0);
    case 0x90: return do_branch(!(S.p & FC));
    case 0xB0: return do_branch((S.p & FC) != 0);
    case 0xD0: return do_branch(!(S.p & FZ));
    case 0xF0: return do_branch((S.p & FZ) != 0);

    /* Flag & register ops */
    case 0x18: S.p &= (u8)~FC; return 2;
    case 0x38: S.p |= FC; return 2;
    case 0x58: S.p &= (u8)~FI; return 2;
    case 0x78: S.p |= FI; return 2;
    case 0xB8: S.p &= (u8)~FV; return 2;
    case 0xD8: S.p &= (u8)~FD; return 2;
    case 0xF8: S.p |= FD; return 2;

    case 0x48: push8(S.a); return 3;
    case 0x68: S.a = pull8(); set_nz(S.a); return 4;
    case 0xDA: push8(S.x); return 3;
    case 0xFA: S.x = pull8(); set_nz(S.x); return 4;
    case 0x5A: push8(S.y); return 3;
    case 0x7A: S.y = pull8(); set_nz(S.y); return 4;
    case 0x08: push8((u8)(S.p | FB)); return 3;             /* PHP pushes P with T cleared, B set */
    case 0x28: S.p = (u8)(pull8() & ~FB); return 4;         /* PLP can load T */

    case 0xAA: S.x = S.a; set_nz(S.x); return 2;
    case 0x8A: S.a = S.x; set_nz(S.a); return 2;
    case 0xA8: S.y = S.a; set_nz(S.y); return 2;
    case 0x98: S.a = S.y; set_nz(S.a); return 2;
    case 0xBA: S.x = S.s; set_nz(S.x); return 2;
    case 0x9A: S.s = S.x; return 2;

    case 0xEA: return 2;                                    /* NOP */
    case 0xE8: S.x++; set_nz(S.x); return 2;
    case 0xCA: S.x--; set_nz(S.x); return 2;
    case 0xC8: S.y++; set_nz(S.y); return 2;
    case 0x88: S.y--; set_nz(S.y); return 2;
    case 0x1A: S.a++; set_nz(S.a); return 2;
    case 0x3A: S.a--; set_nz(S.a); return 2;

    /* ORA (supports T flag: M[$2000+X] |= operand, +3 cycles) */
    case 0x09: v = fetch8(); cyc = 2; goto op_ora;
    case 0x05: v = zp_read(fetch8()); cyc = 4; goto op_ora;
    case 0x15: v = zp_read((u8)(fetch8() + S.x)); cyc = 4; goto op_ora;
    case 0x0D: v = bus_read(fetch16()); cyc = 5; goto op_ora;
    case 0x1D: v = bus_read((u16)(fetch16() + S.x)); cyc = 5; goto op_ora;
    case 0x19: v = bus_read((u16)(fetch16() + S.y)); cyc = 5; goto op_ora;
    case 0x01: v = bus_read(zp_ind((u8)(fetch8() + S.x))); cyc = 7; goto op_ora;
    case 0x11: v = bus_read((u16)(zp_ind(fetch8()) + S.y)); cyc = 7; goto op_ora;
    case 0x12: v = bus_read(zp_ind(fetch8())); cyc = 7; goto op_ora;
    op_ora:
        if (tflag) { u8 m = (u8)(zp_read(S.x) | v); zp_write(S.x, m); set_nz(m); return cyc + 3; }
        S.a |= v; set_nz(S.a); return cyc;

    /* AND (supports T flag) */
    case 0x29: v = fetch8(); cyc = 2; goto op_and;
    case 0x25: v = zp_read(fetch8()); cyc = 4; goto op_and;
    case 0x35: v = zp_read((u8)(fetch8() + S.x)); cyc = 4; goto op_and;
    case 0x2D: v = bus_read(fetch16()); cyc = 5; goto op_and;
    case 0x3D: v = bus_read((u16)(fetch16() + S.x)); cyc = 5; goto op_and;
    case 0x39: v = bus_read((u16)(fetch16() + S.y)); cyc = 5; goto op_and;
    case 0x21: v = bus_read(zp_ind((u8)(fetch8() + S.x))); cyc = 7; goto op_and;
    case 0x31: v = bus_read((u16)(zp_ind(fetch8()) + S.y)); cyc = 7; goto op_and;
    case 0x32: v = bus_read(zp_ind(fetch8())); cyc = 7; goto op_and;
    op_and:
        if (tflag) { u8 m = (u8)(zp_read(S.x) & v); zp_write(S.x, m); set_nz(m); return cyc + 3; }
        S.a &= v; set_nz(S.a); return cyc;

    /* EOR (supports T flag) */
    case 0x49: v = fetch8(); cyc = 2; goto op_eor;
    case 0x45: v = zp_read(fetch8()); cyc = 4; goto op_eor;
    case 0x55: v = zp_read((u8)(fetch8() + S.x)); cyc = 4; goto op_eor;
    case 0x4D: v = bus_read(fetch16()); cyc = 5; goto op_eor;
    case 0x5D: v = bus_read((u16)(fetch16() + S.x)); cyc = 5; goto op_eor;
    case 0x59: v = bus_read((u16)(fetch16() + S.y)); cyc = 5; goto op_eor;
    case 0x41: v = bus_read(zp_ind((u8)(fetch8() + S.x))); cyc = 7; goto op_eor;
    case 0x51: v = bus_read((u16)(zp_ind(fetch8()) + S.y)); cyc = 7; goto op_eor;
    case 0x52: v = bus_read(zp_ind(fetch8())); cyc = 7; goto op_eor;
    op_eor:
        if (tflag) { u8 m = (u8)(zp_read(S.x) ^ v); zp_write(S.x, m); set_nz(m); return cyc + 3; }
        S.a ^= v; set_nz(S.a); return cyc;

    /* ADC (supports T flag) */
    case 0x69: v = fetch8(); cyc = 2; goto op_adc;
    case 0x65: v = zp_read(fetch8()); cyc = 4; goto op_adc;
    case 0x75: v = zp_read((u8)(fetch8() + S.x)); cyc = 4; goto op_adc;
    case 0x6D: v = bus_read(fetch16()); cyc = 5; goto op_adc;
    case 0x7D: v = bus_read((u16)(fetch16() + S.x)); cyc = 5; goto op_adc;
    case 0x79: v = bus_read((u16)(fetch16() + S.y)); cyc = 5; goto op_adc;
    case 0x61: v = bus_read(zp_ind((u8)(fetch8() + S.x))); cyc = 7; goto op_adc;
    case 0x71: v = bus_read((u16)(zp_ind(fetch8()) + S.y)); cyc = 7; goto op_adc;
    case 0x72: v = bus_read(zp_ind(fetch8())); cyc = 7; goto op_adc;
    op_adc:
        if (tflag) { u8 m = do_adc(zp_read(S.x), v, &extra); zp_write(S.x, m); return cyc + 3 + extra; }
        S.a = do_adc(S.a, v, &extra); return cyc + extra;

    /* SBC */
    case 0xE9: v = fetch8(); cyc = 2; goto op_sbc;
    case 0xE5: v = zp_read(fetch8()); cyc = 4; goto op_sbc;
    case 0xF5: v = zp_read((u8)(fetch8() + S.x)); cyc = 4; goto op_sbc;
    case 0xED: v = bus_read(fetch16()); cyc = 5; goto op_sbc;
    case 0xFD: v = bus_read((u16)(fetch16() + S.x)); cyc = 5; goto op_sbc;
    case 0xF9: v = bus_read((u16)(fetch16() + S.y)); cyc = 5; goto op_sbc;
    case 0xE1: v = bus_read(zp_ind((u8)(fetch8() + S.x))); cyc = 7; goto op_sbc;
    case 0xF1: v = bus_read((u16)(zp_ind(fetch8()) + S.y)); cyc = 7; goto op_sbc;
    case 0xF2: v = bus_read(zp_ind(fetch8())); cyc = 7; goto op_sbc;
    op_sbc:
        S.a = do_sbc(S.a, v, &extra); return cyc + extra;

    /* CMP / CPX / CPY */
    case 0xC9: do_cmp(S.a, fetch8()); return 2;
    case 0xC5: do_cmp(S.a, zp_read(fetch8())); return 4;
    case 0xD5: do_cmp(S.a, zp_read((u8)(fetch8() + S.x))); return 4;
    case 0xCD: do_cmp(S.a, bus_read(fetch16())); return 5;
    case 0xDD: do_cmp(S.a, bus_read((u16)(fetch16() + S.x))); return 5;
    case 0xD9: do_cmp(S.a, bus_read((u16)(fetch16() + S.y))); return 5;
    case 0xC1: do_cmp(S.a, bus_read(zp_ind((u8)(fetch8() + S.x)))); return 7;
    case 0xD1: do_cmp(S.a, bus_read((u16)(zp_ind(fetch8()) + S.y))); return 7;
    case 0xD2: do_cmp(S.a, bus_read(zp_ind(fetch8()))); return 7;

    case 0xE0: do_cmp(S.x, fetch8()); return 2;
    case 0xE4: do_cmp(S.x, zp_read(fetch8())); return 4;
    case 0xEC: do_cmp(S.x, bus_read(fetch16())); return 5;
    case 0xC0: do_cmp(S.y, fetch8()); return 2;
    case 0xC4: do_cmp(S.y, zp_read(fetch8())); return 4;
    case 0xCC: do_cmp(S.y, bus_read(fetch16())); return 5;

    /* BIT */
    case 0x89: v = fetch8(); cyc = 2; goto op_bit;
    case 0x24: v = zp_read(fetch8()); cyc = 4; goto op_bit;
    case 0x34: v = zp_read((u8)(fetch8() + S.x)); cyc = 4; goto op_bit;
    case 0x2C: v = bus_read(fetch16()); cyc = 5; goto op_bit;
    case 0x3C: v = bus_read((u16)(fetch16() + S.x)); cyc = 5; goto op_bit;
    op_bit:
        S.p = (S.p & (u8)~(FN | FV | FZ)) | (v & (FN | FV)) | ((S.a & v) ? 0 : FZ);
        return cyc;

    /* LDA / LDX / LDY */
    case 0xA9: S.a = fetch8(); set_nz(S.a); return 2;
    case 0xA5: S.a = zp_read(fetch8()); set_nz(S.a); return 4;
    case 0xB5: S.a = zp_read((u8)(fetch8() + S.x)); set_nz(S.a); return 4;
    case 0xAD: S.a = bus_read(fetch16()); set_nz(S.a); return 5;
    case 0xBD: S.a = bus_read((u16)(fetch16() + S.x)); set_nz(S.a); return 5;
    case 0xB9: S.a = bus_read((u16)(fetch16() + S.y)); set_nz(S.a); return 5;
    case 0xA1: S.a = bus_read(zp_ind((u8)(fetch8() + S.x))); set_nz(S.a); return 7;
    case 0xB1: S.a = bus_read((u16)(zp_ind(fetch8()) + S.y)); set_nz(S.a); return 7;
    case 0xB2: S.a = bus_read(zp_ind(fetch8())); set_nz(S.a); return 7;

    case 0xA2: S.x = fetch8(); set_nz(S.x); return 2;
    case 0xA6: S.x = zp_read(fetch8()); set_nz(S.x); return 4;
    case 0xB6: S.x = zp_read((u8)(fetch8() + S.y)); set_nz(S.x); return 4;
    case 0xAE: S.x = bus_read(fetch16()); set_nz(S.x); return 5;
    case 0xBE: S.x = bus_read((u16)(fetch16() + S.y)); set_nz(S.x); return 5;

    case 0xA0: S.y = fetch8(); set_nz(S.y); return 2;
    case 0xA4: S.y = zp_read(fetch8()); set_nz(S.y); return 4;
    case 0xB4: S.y = zp_read((u8)(fetch8() + S.x)); set_nz(S.y); return 4;
    case 0xAC: S.y = bus_read(fetch16()); set_nz(S.y); return 5;
    case 0xBC: S.y = bus_read((u16)(fetch16() + S.x)); set_nz(S.y); return 5;

    /* STA / STX / STY / STZ */
    case 0x85: zp_write(fetch8(), S.a); return 4;
    case 0x95: zp_write((u8)(fetch8() + S.x), S.a); return 4;
    case 0x8D: bus_write(fetch16(), S.a); return 5;
    case 0x9D: bus_write((u16)(fetch16() + S.x), S.a); return 5;
    case 0x99: bus_write((u16)(fetch16() + S.y), S.a); return 5;
    case 0x81: bus_write(zp_ind((u8)(fetch8() + S.x)), S.a); return 7;
    case 0x91: bus_write((u16)(zp_ind(fetch8()) + S.y), S.a); return 7;
    case 0x92: bus_write(zp_ind(fetch8()), S.a); return 7;

    case 0x86: zp_write(fetch8(), S.x); return 4;
    case 0x96: zp_write((u8)(fetch8() + S.y), S.x); return 4;
    case 0x8E: bus_write(fetch16(), S.x); return 5;

    case 0x84: zp_write(fetch8(), S.y); return 4;
    case 0x94: zp_write((u8)(fetch8() + S.x), S.y); return 4;
    case 0x8C: bus_write(fetch16(), S.y); return 5;

    case 0x64: zp_write(fetch8(), 0); return 4;
    case 0x74: zp_write((u8)(fetch8() + S.x), 0); return 4;
    case 0x9C: bus_write(fetch16(), 0); return 5;
    case 0x9E: bus_write((u16)(fetch16() + S.x), 0); return 5;

    /* Shifts & RMW: ASL, LSR, ROL, ROR, INC, DEC, TSB, TRB */
    case 0x0A: S.p = (S.p & (u8)~FC) | (S.a >> 7); S.a <<= 1; set_nz(S.a); return 2;
    case 0x4A: S.p = (S.p & (u8)~FC) | (S.a & 1u); S.a >>= 1; set_nz(S.a); return 2;
    case 0x2A: v = S.p & FC; S.p = (S.p & (u8)~FC) | (S.a >> 7); S.a = (u8)((S.a << 1) | v); set_nz(S.a); return 2;
    case 0x6A: v = (u8)((S.p & FC) << 7); S.p = (S.p & (u8)~FC) | (S.a & 1u); S.a = (u8)((S.a >> 1) | v); set_nz(S.a); return 2;

    case 0x06: zp = fetch8(); v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v >> 7); v <<= 1; zp_write(zp, v); set_nz(v); return 6;
    case 0x16: zp = (u8)(fetch8() + S.x); v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v >> 7); v <<= 1; zp_write(zp, v); set_nz(v); return 6;
    case 0x0E: ea = fetch16(); v = bus_read(ea); S.p = (S.p & (u8)~FC) | (v >> 7); v <<= 1; bus_write(ea, v); set_nz(v); return 7;
    case 0x1E: ea = (u16)(fetch16() + S.x); v = bus_read(ea); S.p = (S.p & (u8)~FC) | (v >> 7); v <<= 1; bus_write(ea, v); set_nz(v); return 7;

    case 0x46: zp = fetch8(); v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v & 1u); v >>= 1; zp_write(zp, v); set_nz(v); return 6;
    case 0x56: zp = (u8)(fetch8() + S.x); v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v & 1u); v >>= 1; zp_write(zp, v); set_nz(v); return 6;
    case 0x4E: ea = fetch16(); v = bus_read(ea); S.p = (S.p & (u8)~FC) | (v & 1u); v >>= 1; bus_write(ea, v); set_nz(v); return 7;
    case 0x5E: ea = (u16)(fetch16() + S.x); v = bus_read(ea); S.p = (S.p & (u8)~FC) | (v & 1u); v >>= 1; bus_write(ea, v); set_nz(v); return 7;

    case 0x26: zp = fetch8(); ea = S.p & FC; v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v >> 7); v = (u8)((v << 1) | ea); zp_write(zp, v); set_nz(v); return 6;
    case 0x36: zp = (u8)(fetch8() + S.x); ea = S.p & FC; v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v >> 7); v = (u8)((v << 1) | ea); zp_write(zp, v); set_nz(v); return 6;
    case 0x2E: ea = fetch16(); v = bus_read(ea); cyc = S.p & FC; S.p = (S.p & (u8)~FC) | (v >> 7); v = (u8)((v << 1) | cyc); bus_write(ea, v); set_nz(v); return 7;
    case 0x3E: ea = (u16)(fetch16() + S.x); v = bus_read(ea); cyc = S.p & FC; S.p = (S.p & (u8)~FC) | (v >> 7); v = (u8)((v << 1) | cyc); bus_write(ea, v); set_nz(v); return 7;

    case 0x66: zp = fetch8(); ea = (u16)((S.p & FC) << 7); v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v & 1u); v = (u8)((v >> 1) | ea); zp_write(zp, v); set_nz(v); return 6;
    case 0x76: zp = (u8)(fetch8() + S.x); ea = (u16)((S.p & FC) << 7); v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v & 1u); v = (u8)((v >> 1) | ea); zp_write(zp, v); set_nz(v); return 6;
    case 0x6E: ea = fetch16(); v = bus_read(ea); cyc = (u32)((S.p & FC) << 7); S.p = (S.p & (u8)~FC) | (v & 1u); v = (u8)((v >> 1) | cyc); bus_write(ea, v); set_nz(v); return 7;
    case 0x7E: ea = (u16)(fetch16() + S.x); v = bus_read(ea); cyc = (u32)((S.p & FC) << 7); S.p = (S.p & (u8)~FC) | (v & 1u); v = (u8)((v >> 1) | cyc); bus_write(ea, v); set_nz(v); return 7;

    case 0xE6: zp = fetch8(); v = (u8)(zp_read(zp) + 1u); zp_write(zp, v); set_nz(v); return 6;
    case 0xF6: zp = (u8)(fetch8() + S.x); v = (u8)(zp_read(zp) + 1u); zp_write(zp, v); set_nz(v); return 6;
    case 0xEE: ea = fetch16(); v = (u8)(bus_read(ea) + 1u); bus_write(ea, v); set_nz(v); return 7;
    case 0xFE: ea = (u16)(fetch16() + S.x); v = (u8)(bus_read(ea) + 1u); bus_write(ea, v); set_nz(v); return 7;

    case 0xC6: zp = fetch8(); v = (u8)(zp_read(zp) - 1u); zp_write(zp, v); set_nz(v); return 6;
    case 0xD6: zp = (u8)(fetch8() + S.x); v = (u8)(zp_read(zp) - 1u); zp_write(zp, v); set_nz(v); return 6;
    case 0xCE: ea = fetch16(); v = (u8)(bus_read(ea) - 1u); bus_write(ea, v); set_nz(v); return 7;
    case 0xDE: ea = (u16)(fetch16() + S.x); v = (u8)(bus_read(ea) - 1u); bus_write(ea, v); set_nz(v); return 7;

    /* TSB / TRB: N and V come from memory before modification, Z from (A & old_mem) == 0 */
    case 0x04:
        zp = fetch8(); v = zp_read(zp);
        S.p = (S.p & (u8)~(FN | FV | FZ)) | (v & (FN | FV)) | ((S.a & v) ? 0 : FZ);
        zp_write(zp, (u8)(v | S.a));
        return 6;
    case 0x0C:
        ea = fetch16(); v = bus_read(ea);
        S.p = (S.p & (u8)~(FN | FV | FZ)) | (v & (FN | FV)) | ((S.a & v) ? 0 : FZ);
        bus_write(ea, (u8)(v | S.a));
        return 7;
    case 0x14:
        zp = fetch8(); v = zp_read(zp);
        S.p = (S.p & (u8)~(FN | FV | FZ)) | (v & (FN | FV)) | ((S.a & v) ? 0 : FZ);
        zp_write(zp, (u8)(v & (u8)~S.a));
        return 6;
    case 0x1C:
        ea = fetch16(); v = bus_read(ea);
        S.p = (S.p & (u8)~(FN | FV | FZ)) | (v & (FN | FV)) | ((S.a & v) ? 0 : FZ);
        bus_write(ea, (u8)(v & (u8)~S.a));
        return 7;

    /* Unassigned opcodes on HuC6280 are 2-cycle 1-byte NOPs */
    default:
        return 2;
    }
}

static void check_interrupts(void)
{
    if (S.p & FI)
        return;
    u8 active = S.irq_lines & (u8)~S.irq_mask;
    if (!active)
        return;
    /* Priority on HuC6280: TIQ ($FFFA) > IRQ1 ($FFF8) > IRQ2 ($FFF6) */
    u16 vec = (active & 0x04) ? 0xFFFA : (active & 0x02) ? 0xFFF8 : 0xFFF6;
    push16(S.pc);
    push8((u8)(S.p & ~FB));
    S.p = (S.p & (u8)~(FD | FT)) | FI;
    S.pc = bus_read(vec) | ((u16)bus_read((u16)(vec + 1)) << 8);
    S.cycles += 8u * S.speed;
}

static void run_cycles_7m(u32 budget)
{
    u32 target = S.cycles + budget;
    while (S.cycles < target) {
        check_interrupts();
#ifndef PCE_CPU_TEST
        if (!(S.p & FT) && S.cycles < target) {
            const u8 *code_page = S.mpr_r[S.pc >> 13];
            u16 off = S.pc & 0x1FFFu;
            if (code_page && off <= 0x1FFAu) {
                const u8 *code = code_page + off;
                u32 loop_cpu = 0;
                int set_a = -1;
                if (code[0] == 0x80 && code[1] == 0xFE) {
                    loop_cpu = 4;                               /* BRA -2 */
                } else if (code[0] == 0x4C && (u16)(code[1] | ((u16)code[2] << 8)) == S.pc) {
                    loop_cpu = 4;                               /* JMP self */
                } else if ((code[0] & 0x0F) == 0x0F && code[2] == 0xFD && S.mpr_r[1] == M->wram) {
                    u8 bit = (u8)(1u << ((code[0] >> 4) & 7));
                    u8 zv = M->wram[code[1]];
                    if ((code[0] & 0x80) ? ((zv & bit) != 0) : ((zv & bit) == 0))
                        loop_cpu = 8;                           /* BBRi/BBSi zp, -3 */
                } else if (code[0] == 0xA5 && (code[2] == 0xD0 || code[2] == 0xF0) &&
                           code[3] == 0xFC && S.mpr_r[1] == M->wram) {
                    u8 zv = M->wram[code[1]];
                    if ((code[2] == 0xD0) ? (zv != 0) : (zv == 0)) {
                        loop_cpu = 8;                           /* LDA zp; BNE/BEQ -4 */
                        set_a = zv;
                    }
                } else if (code[0] == 0xAD && (code[3] == 0xD0 || code[3] == 0xF0) && code[4] == 0xFB) {
                    u16 ea = (u16)(code[1] | ((u16)code[2] << 8));
                    const u8 *rp = S.mpr_r[ea >> 13];
                    if (rp) {
                        u8 mv = rp[ea & 0x1FFFu];
                        if ((code[3] == 0xD0) ? (mv != 0) : (mv == 0)) {
                            loop_cpu = 9;                       /* LDA abs; BNE/BEQ -5 */
                            set_a = mv;
                        }
                    }
                }
                if (loop_cpu) {
                    u32 loop_cyc = loop_cpu * S.speed;
                    u32 rem = target - S.cycles;
                    if (rem > loop_cyc) {
                        u32 iters = (rem - 1u) / loop_cyc;
                        if (S.tmr_on) {
                            u32 t_iters = S.tmr_prescale > (s32)loop_cyc
                                        ? (u32)(S.tmr_prescale - 1) / loop_cyc : 0;
                            if (iters > t_iters)
                                iters = t_iters;
                        }
                        if (iters > 0) {
                            if (set_a >= 0) {
                                S.a = (u8)set_a;
                                set_nz(S.a);
                            }
                            u32 adv = iters * loop_cyc;
                            S.cycles += adv;
                            if (S.tmr_on)
                                S.tmr_prescale -= (s32)adv;
                        }
                    }
                }
            }
        }
#endif
        u32 c = cpu_step() * S.speed;
        S.cycles += c;
        if (S.tmr_on) {
            S.tmr_prescale -= (s32)c;
            while (S.tmr_prescale <= 0) {
                S.tmr_prescale += 1024;
                if (S.tmr_cnt == 0) {
                    S.tmr_cnt = S.tmr_reload;
                    S.irq_lines |= 0x04;        /* TIQ */
                } else {
                    S.tmr_cnt--;
                }
            }
        }
    }
}

/* ---- Scanline renderer ---- */
static int calc_width(void)
{
    int hdw = ((S.vdc[11] & 0x7Fu) + 1) * 8;
    int dot = S.vce_ctrl & 3;
    int def_w = dot == 0 ? 256 : dot == 1 ? 320 : 512;
    if (hdw >= 128 && hdw <= PCE_W_MAX)
        return hdw;
    return def_w;
}

static void render_scanline(int y, u16 *dst, int w)
{
    u16 cr = S.vdc[5];
    u16 bg0 = M->vce_pal[0];
    u16 overscan = M->vce_pal[0x100];
    u8 bg_opaque[PCE_W_MAX];

    if (cr & 0x80) {                            /* Background enabled */
        static const int bat_w_tab[8] = {32, 64, 128, 128, 32, 64, 128, 128};
        int mwr = (S.vdc[9] >> 4) & 7;
        int bw_mask = bat_w_tab[mwr] - 1;
        int bh_mask = (mwr & 4) ? 63 : 31;
        int bat_stride = bat_w_tab[mwr];

        u32 sy = S.bg_y & (u32)((bh_mask << 3) | 7);
        u32 row_bat = (sy >> 3) * (u32)bat_stride;
        u32 ty = sy & 7u;
        u32 bxr = S.vdc[7] & 0x3FFu;

        int tx = (int)(bxr >> 3);
        int fine_x = (int)(bxr & 7u);
        int x = -fine_x;
        while (x < w) {
            u16 entry = M->vram[(row_bat + (u32)(tx & bw_mask)) & 0x7FFFu];
            u32 tile_base = ((u32)(entry & 0x0FFFu) << 4);
            const u16 *pal = &M->vce_pal[(entry >> 12) << 4];
            u16 w01 = (tile_base + ty) < 0x8000u ? M->vram[tile_base + ty] : 0;
            u16 w23 = (tile_base + 8u + ty) < 0x8000u ? M->vram[tile_base + 8u + ty] : 0;
            u32 pix8 = M->spread8[w01 & 0xFFu] | (M->spread8[w01 >> 8] << 1) |
                       (M->spread8[w23 & 0xFFu] << 2) | (M->spread8[w23 >> 8] << 3);
            if (x >= 0 && x + 8 <= w) {
                if (!pix8) {
                    for (int b = 0; b < 8; b++) {
                        bg_opaque[x + b] = 0;
                        dst[x + b] = bg0;
                    }
                } else {
                    for (int b = 0; b < 8; b++) {
                        u8 px = (u8)(pix8 & 0x0Fu);
                        pix8 >>= 4;
                        bg_opaque[x + b] = px;
                        dst[x + b] = px ? pal[px] : bg0;
                    }
                }
            } else {
                int b_start = x < 0 ? -x : 0;
                int b_end = (x + 8 > w) ? (w - x) : 8;
                for (int b = b_start; b < b_end; b++) {
                    u8 px = (u8)((pix8 >> (b * 4)) & 0x0Fu);
                    int dx = x + b;
                    bg_opaque[dx] = px;
                    dst[dx] = px ? pal[px] : bg0;
                }
            }
            x += 8;
            tx++;
        }
    } else {
        for (int x = 0; x < w; x++) {
            bg_opaque[x] = 0;
            dst[x] = overscan;
        }
    }

    if (!(cr & 0x40))                           /* Sprites disabled */
        return;

    /* Evaluate up to 16 sprites (32 16-px cells) on line y; Sprite 0 has top priority */
    u8 spr_drawn[PCE_W_MAX];
    u8 spr0_mask[PCE_W_MAX];
    for (int x = 0; x < w; x++) {
        spr_drawn[x] = 0;
        spr0_mask[x] = 0;
    }

    int cells = 0, hit0 = 0;
    for (int i = 0; i < 64; i++) {
        const u16 *s = &M->satb[i * 4];
        int sy = (int)(s[0] & 0x3FFu) - 64;
        int cgy = (s[3] >> 12) & 3;
        int sh = cgy == 0 ? 16 : cgy == 1 ? 32 : 64;
        if (y < sy || y >= sy + sh)
            continue;
        int cgx = (s[3] >> 8) & 1;
        int orig_cells = cgx ? 2 : 1;
        int sw_cells = orig_cells;
        if (cells + sw_cells > 16) {
            if (cells >= 16) {
                if (cr & 0x02) {
                    S.vdc_status |= 0x02;       /* Sprite overflow OR */
                    vdc_update_irq();
                }
                break;
            }
            sw_cells = 1;
            if (cr & 0x02) {
                S.vdc_status |= 0x02;
                vdc_update_irq();
            }
        }
        cells += sw_cells;

        int sx = (int)(s[1] & 0x3FFu) - 32;
        u32 pat = (s[2] >> 1) & 0x3FFu;
        if (cgx) pat &= ~1u;
        if (cgy == 1) pat &= ~2u;
        else if (cgy >= 2) pat &= ~6u;

        int row = y - sy;
        if (s[3] & 0x8000u)
            row = (sh - 1) - row;
        u32 pat_y = pat + (u32)((row >> 4) * 2);
        u32 line_in_cell = (u32)(row & 15);
        int xflip = (s[3] & 0x0800u) != 0;
        int fg = (s[3] & 0x0080u) != 0;
        const u16 *pal = &M->vce_pal[0x100u + ((s[3] & 0x0Fu) << 4)];

        for (int c = 0; c < sw_cells; c++) {
            int cx = sx + c * 16;
            if (cx + 16 <= 0 || cx >= w)
                continue;
            u32 cell_pat = pat_y + (u32)(xflip ? (orig_cells - 1 - c) : c);
            u32 base = (cell_pat << 6) + line_in_cell;
            if (base + 48u >= 0x8000u)
                continue;
            u16 p0 = M->vram[base];
            u16 p1 = M->vram[base + 16u];
            u16 p2 = M->vram[base + 32u];
            u16 p3 = M->vram[base + 48u];
            if (!(p0 | p1 | p2 | p3))
                continue;
            u32 left8, right8;
            if (!xflip) {
                left8  = M->spread8[p0 >> 8]   | (M->spread8[p1 >> 8] << 1) |
                         (M->spread8[p2 >> 8] << 2)   | (M->spread8[p3 >> 8] << 3);
                right8 = M->spread8[p0 & 0xFF] | (M->spread8[p1 & 0xFF] << 1) |
                         (M->spread8[p2 & 0xFF] << 2) | (M->spread8[p3 & 0xFF] << 3);
            } else {
                left8  = M->spread8_rev[p0 & 0xFF] | (M->spread8_rev[p1 & 0xFF] << 1) |
                         (M->spread8_rev[p2 & 0xFF] << 2) | (M->spread8_rev[p3 & 0xFF] << 3);
                right8 = M->spread8_rev[p0 >> 8]   | (M->spread8_rev[p1 >> 8] << 1) |
                         (M->spread8_rev[p2 >> 8] << 2)   | (M->spread8_rev[p3 >> 8] << 3);
            }
            for (int half = 0; half < 2; half++) {
                u32 pack = half ? right8 : left8;
                if (!pack)
                    continue;
                int bx = cx + half * 8;
                for (int b = 0; b < 8; b++) {
                    u8 px = (u8)(pack & 0x0Fu);
                    pack >>= 4;
                    if (!px)
                        continue;
                    int dx = bx + b;
                    if ((unsigned)dx >= (unsigned)w)
                        continue;
                    if (i == 0) {
                        spr0_mask[dx] = 1;
                    } else if (spr0_mask[dx]) {
                        hit0 = 1;
                    }
                    if (!spr_drawn[dx]) {
                        spr_drawn[dx] = 1;      /* higher-priority sprite claims pixel even if behind BG */
                        if (fg || !bg_opaque[dx])
                            dst[dx] = pal[px];
                    }
                }
            }
        }
    }

    if (hit0 && (cr & 0x01)) {
        S.vdc_status |= 0x01;                   /* Sprite 0 collision CR */
        vdc_update_irq();
    }
}

/* ---- Public player interface ---- */
static u8 bitrev8(u8 b)
{
    b = (u8)(((b & 0xF0u) >> 4) | ((b & 0x0Fu) << 4));
    b = (u8)(((b & 0xCCu) >> 2) | ((b & 0x33u) << 2));
    return (u8)(((b & 0xAAu) >> 1) | ((b & 0x55u) << 1));
}

static void fmt_info(void)
{
    char *p = info_buf;
    const char *tag = S.sf2_mapper ? "HuCard (SF2 mapper)" : S.us_region ? "TurboGrafx-16 HuCard" : "PC Engine HuCard";
    while (*tag) *p++ = *tag++;
    const char *sep = ", ROM ";
    while (*sep) *p++ = *sep++;
    u32 kb = S.rom_size >> 10;
    char tmp[16];
    int n = 0;
    do { tmp[n++] = (char)('0' + kb % 10); kb /= 10; } while (kb);
    while (n--) *p++ = tmp[n];
    const char *suf = " KB";
    while (*suf) *p++ = *suf++;
    *p = 0;
}

const char *pce_load(u8 *image, u32 size)
{
    if (!image || size < 8192)
        return "too small for a PC Engine HuCard (at least 8 KB)";
    if (size > 512 && (size & 0x1FFFu) == 512u) {
        image += 512;
        size -= 512;
    }
    if (size < 8192)
        return "too small for a PC Engine HuCard";

    for (u32 i = 0; i < sizeof(*M); i++)
        ((u8 *)M)[i] = 0;
    for (u32 i = 0; i < sizeof(M->ff_page); i++)
        M->ff_page[i] = 0xFF;
    for (u32 b = 0; b < 256; b++) {
        u32 n = 0, r = 0;
        for (int k = 0; k < 8; k++) {
            n |= ((b >> (7 - k)) & 1u) << (k * 4);
            r |= ((b >> k) & 1u) << (k * 4);
        }
        M->spread8[b] = n;
        M->spread8_rev[b] = r;
    }
    /* Standard Hub/BRAM signature ("HUBM\x00\x88\x10\x80") so games with save support see formatted BRAM */
    M->bram[0] = 'H'; M->bram[1] = 'U'; M->bram[2] = 'B'; M->bram[3] = 'M';
    M->bram[4] = 0x00; M->bram[5] = 0x88; M->bram[6] = 0x10; M->bram[7] = 0x80;

    for (u32 i = 0; i < sizeof(S); i++)
        ((u8 *)&S)[i] = 0;

    S.rom = image;
    S.rom_size = size;
    S.rom_pages = (size + 0x1FFFu) >> 13;
    S.rom_p2 = 1;
    while (S.rom_p2 * 2 <= S.rom_pages && S.rom_p2 < 0x40)
        S.rom_p2 *= 2;
    S.sf2_mapper = S.rom_pages > 128;

    /* Check for bit-reversed US TurboGrafx-16 dump: reset vector at $1FFF should point to >= $E000 (or $C000) */
    u8 rst_hi = S.rom[0x1FFF];
    if (rst_hi < 0xC0 && bitrev8(rst_hi) >= 0xE0) {
        for (u32 i = 0; i < size; i++)
            S.rom[i] = bitrev8(S.rom[i]);
        S.us_region = 1;
    }
    /* Populous has 32 KB on-cart RAM at $40..$43 ("POPULOUS" in ROM) */
    for (u32 i = 0x1F00; i + 8 < size && i < 0x2000; i++)
        if (S.rom[i] == 'P' && S.rom[i + 1] == 'O' && S.rom[i + 2] == 'P' && S.rom[i + 3] == 'U')
            S.populous_ram = 1;

    pce_reset();
    fmt_info();
    return 0;
}

void pce_reset(void)
{
    S.a = S.x = S.y = 0;
    S.s = 0xFF;
    S.p = FI;
    for (int i = 0; i < 7; i++)
        S.mpr[i] = 0;
    S.mpr[7] = 0;                       /* MPR7 maps page $00 at $E000..$FFFF on reset */
    S.mpr_latch = 0;
    S.speed = 4;                        /* HuC6280 boots in 1.79 MHz CSL mode until CSH */
    S.irq_mask = 0;
    S.irq_lines = 0;
    S.jammed = 0;
    S.tmr_on = 0;
    S.tmr_cnt = S.tmr_reload = 0;
    S.tmr_prescale = 1024;
    S.sf2_bank = 0;
    S.out_w = PCE_W_DEF;
    S.out_h = PCE_H_DEF;
    /* Default VDC geometry (256 x 240) before game initializes it */
    S.vdc[10] = 0x0202;
    S.vdc[11] = 0x041F;                 /* HDW = 31 -> 256 px */
    S.vdc[12] = 0x0F02;
    S.vdc[13] = 239;                    /* VDW = 239 -> 240 lines */
    S.vdc[14] = 0x000C;
    S.frame_counter = 0;
    S.display_counter = 0;
    S.rcr_count = 0;
    S.lat_vds = 0x0F;
    S.lat_vsw = 0x02;
    S.lat_vdw = 239;
    S.lat_vcr = 0x0C;
    S.vblank_fl = 0x0F + 0x02 + 239 + 1;
    S.burst_mode = 1;
    S.sat_dma_slcounter = 0;
    for (int i = 0; i < 6; i++)
        S.psg[i].lfsr = 1u;
    rebuild_pages();
    S.pc = bus_read(0xFFFE) | ((u16)bus_read(0xFFFF) << 8);
}

static u32 calc_line_leadin(void)
{
    int hds = (S.vdc[10] >> 8) & 0x7F;
    int hdw = S.vdc[11] & 0x7F;
    int hde = (S.vdc[11] >> 8) & 0x7F;
    int magical = ((hds + hdw + 1 + hde + 2) & ~1) - (hdw + 1);
    int cyc = magical * 8 - 2;
    int dc = S.vce_ctrl & 1;
    if (S.vce_ctrl & 2)
        dc = 2;
    if (dc == 0)
        cyc = (cyc * 4) / 3;
    else if (dc == 2)
        cyc = (cyc * 2) / 3;
    if (cyc < 16)
        cyc = 16;
    if (cyc > 380)
        cyc = 380;
    return (u32)cyc;
}

void pce_frame(u16 pad, u16 *picture)
{
    S.pad_state = pad;
    S.audio_count = 0;
    S.audio_cyc_last = S.cycles;

    int w = calc_width();
    int h_latched = 0;
    int h = S.out_h;
    int safety = 0;

    do {
        if (S.frame_counter == 0) {
            S.lat_vsw = S.vdc[12] & 0x1Fu;
            S.lat_vds = (S.vdc[12] >> 8) & 0xFFu;
            S.lat_vdw = S.vdc[13] & 0x1FFu;
            S.lat_vcr = S.vdc[14] & 0xFFu;
            S.vblank_fl = S.lat_vds + S.lat_vsw + S.lat_vdw + 1u;
            if (S.vblank_fl > 261u)
                S.vblank_fl = 261u;
            S.display_counter = 0;
            S.burst_mode = !(S.vdc[5] & 0xC0u);
        }

        u16 active_dc = S.lat_vds + S.lat_vsw;
        if (S.display_counter == active_dc) {
            S.burst_mode = !(S.vdc[5] & 0xC0u);
            S.rcr_count = 0;
            w = calc_width();
            int vdw = (int)S.lat_vdw + 1;
            h = vdw < 160 ? PCE_H_DEF : vdw > PCE_H_MAX ? PCE_H_MAX : vdw;
            S.out_w = w;
            S.out_h = h;
            h_latched = 1;
        }

        int need_vbi = 0;
        if (S.display_counter == S.vblank_fl) {
            need_vbi = 1;
            if (S.satb_dirty || (S.vdc[15] & 0x10u))
                vdc_satb_dma();
        }

        if ((int)S.rcr_count == ((int)(S.vdc[6] & 0x3FFu) - 0x40) && (S.vdc[5] & 0x04u)) {
            S.vdc_status |= 0x04u;      /* RR */
            vdc_update_irq();
        }

        u32 leadin = calc_line_leadin();
        run_cycles_7m(leadin);

        if (!S.burst_mode && S.display_counter >= active_dc &&
            S.display_counter < active_dc + S.lat_vdw + 1u) {
            if (S.display_counter == active_dc)
                S.bg_y = S.vdc[8] & 0x1FFu;
            else
                S.bg_y = (S.bg_y + 1u) & 0x1FFu;

            int ay = (int)(S.display_counter - active_dc);
            if (picture && ay >= 0 && ay < h)
                render_scanline(ay, picture + ay * w, w);
        } else if (S.burst_mode && S.display_counter >= active_dc &&
                   S.display_counter < active_dc + S.lat_vdw + 1u) {
            int ay = (int)(S.display_counter - active_dc);
            if (picture && ay >= 0 && ay < h) {
                u16 os = M->vce_pal[0x100];
                u16 *row = picture + ay * w;
                for (int x = 0; x < w; x++)
                    row[x] = os;
            }
        }

        if (need_vbi && (S.vdc[5] & 0x08u))
            S.vdc_status |= 0x20u;      /* VD (VBlank) */

        run_cycles_7m(2);

        if (S.vdc_status & 0x20u)
            vdc_update_irq();

        run_cycles_7m(LINE_CYC - leadin - 2u);

        S.rcr_count++;
        S.display_counter++;

        if (S.sat_dma_slcounter) {
            S.sat_dma_slcounter--;
            if (!S.sat_dma_slcounter && (S.vdc[15] & 0x01u)) {
                S.vdc_status |= 0x08u;  /* DS */
                vdc_update_irq();
            }
        }

        if (S.display_counter == active_dc + S.lat_vdw + S.lat_vcr + 3u)
            S.display_counter = 0;

        u16 total_lines = (S.vce_ctrl & 0x04u) ? 263u : 262u;
        S.frame_counter = (u16)((S.frame_counter + 1u) % total_lines);
    } while (S.frame_counter != S.vblank_fl && ++safety < 300);

    if (!h_latched) {
        S.out_w = w;
        S.out_h = h;
    }
    psg_catch_up();
}

int pce_width(void)   { return S.out_w; }
int pce_height(void)  { return S.out_h; }
const char *pce_info(void) { return info_buf; }

u8 *pce_save_ram(u32 *size, int *battery)
{
    *size = sizeof(M->bram);
    *battery = 1;
    return M->bram;
}

int pce_save_changed(void)
{
    int d = S.bram_dirty;
    S.bram_dirty = 0;
    return d;
}

u32 pce_cpu_cycles(void) { return S.cycles; }
int pce_jammed(void)     { return S.jammed; }

void pce_audio_rate(u32 hz)
{
    S.sample_rate = hz;
    S.audio_frac = 0;
    S.audio_count = 0;
    S.audio_cyc_last = S.cycles;
}

int pce_audio(s16 *out, int max)
{
    int n = S.audio_count < max ? S.audio_count : max;
    for (int i = 0; i < n; i++)
        out[i] = M->audio_ring[i];
    S.audio_count = 0;
    return n;
}

#ifdef PCE_CPU_TEST
void pce_sst_set(u8 a, u8 x, u8 y, u8 s, u8 p, u16 pc, const u8 mpr[8])
{
    S.a = a; S.x = x; S.y = y; S.s = s; S.p = p; S.pc = pc;
    for (int i = 0; i < 8; i++)
        S.mpr[i] = mpr[i];
    S.speed = 1;
}

void pce_sst_get(u8 *a, u8 *x, u8 *y, u8 *s, u8 *p, u16 *pc, u8 mpr[8])
{
    *a = S.a; *x = S.x; *y = S.y; *s = S.s; *p = S.p; *pc = S.pc;
    for (int i = 0; i < 8; i++)
        mpr[i] = S.mpr[i];
}

u32 pce_sst_step(void)
{
    (void)io_read;
    (void)io_write;
    return cpu_step();
}
#endif
