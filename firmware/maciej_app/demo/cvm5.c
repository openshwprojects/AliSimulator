/* VTech CreatiVision / Dick Smith Wizzard (cv) + Sord M5 / CGL M5 (m5): see cvm5.h.
 * Zero static .bss footprint: all RAM, BIOS, cartridge, VRAM and audio buffers live in KSEG0(EMU_RAM_PHYS).
 */
#pragma GCC optimize("O2")
#include "cvm5.h"
#include "z80.h"

#ifndef CVM5_HOST
#include "hw.h"
#endif

#define CV_LINES        312u            /* 50 Hz PAL TMS9929A */
#define CV_CYC_LINE     128u            /* 312 * 128 = 39,936 cycles @ 2.0 MHz */
#define CV_CLOCK_HZ     2000000u

#define M5_LINES        262u            /* 59.92 Hz NTSC TMS9918A */
#define M5_CYC_LINE     228u            /* 262 * 228 = 59,736 T-states @ 3.579545 MHz */
#define M5_CLOCK_HZ     3579545u

#define CVM5_RING_LEN   4096u

struct cvm5_ws {
    u8 bios[0x2000];                    /* 2 KB CreatiVision BIOS or 8 KB Sord M5 Monitor BIOS */
    u8 cart[0x8000];                    /* 32 KB CreatiVision ($4000..$BFFF) or 20 KB Sord M5 ($2000..$6FFF) */
    u8 ram[0x10000];                    /* 1 KB CV RAM ($0000..$03FF) or 36 KB M5 RAM ($7000..$FFFF) */
    u8 vram[0x4000];                    /* 16 KB TMS9918A / TMS9929A VRAM */
    u8 open_bus[0x400];                 /* 0xFF 1 KB page for unmapped Z80 space */
    s16 snd_ring[CVM5_RING_LEN];
    u16 tms_pal[16];
};

#ifdef CVM5_HOST
static struct cvm5_ws cvm5_host_ws;
#define WS (&cvm5_host_ws)
#else
#define WS ((struct cvm5_ws *)KSEG0(EMU_RAM_PHYS))
#endif

struct sn76489_st {
    u16 period[4];
    u8 atten[4];
    u8 latch;
    u32 phase[4];
    u8 out_bit[3];
    u16 lfsr;
};

struct z80_ctc_ch {
    u8 ctrl, tc, running, await_tc;
    u16 down;
    u32 presc_acc;
};

static struct {
    u8 is_m5;                           /* 0 = VTech CreatiVision (6502), 1 = Sord M5 (Z80) */
    u8 ext_bios;
    u32 cart_size;

    /* MOS 6502 CPU (CreatiVision) */
    u8 a, x, y, sp, p;
    u16 pc;
    u8 jam, nmi_pend;
    u32 cv_cyc;

    /* Zilog Z80 CPU + Z80 CTC (Sord M5) */
    struct z80 zcpu;
    u8 ctc_vec, ctc_irq_pend;
    struct z80_ctc_ch ctc[4];

    /* CreatiVision MC6821 PIA ($1000..$1003) */
    u8 pia_ora, pia_ddra, pia_cra;
    u8 pia_orb, pia_ddrb, pia_crb;

    /* TMS9918A / TMS9929A VDP */
    u8 vdp_reg[8];
    u16 vdp_addr;
    u8 vdp_first, vdp_latch, vdp_buf, vdp_status, vdp_int_prev;

    /* Input state */
    u16 pad_state;
    u8 usb_m5_ports[8];                 /* Active-high M5 ports $30..$37 from USB keyboard */
    u8 m5_ports[8];
    u8 usb_cv_pb[4];                    /* Active-low CV PA0..PA3 keyboard bits from USB keyboard */
    u8 cv_pb[4];
    char type_q[256];
    u16 type_head, type_tail;
    u8 type_hold, type_ch;

    /* TI SN76489A PSG Audio */
    struct sn76489_st sn;
    u32 snd_hz, snd_frac, snd_last_cyc;
    u32 snd_head, snd_count;
    s32 snd_dc;

    char info[96];
} S;

static const s16 sn_vol_tab[16] = {
    4800, 3812, 3028, 2405, 1910, 1517, 1205, 957,
     760,  604,  480,  381,  303,  240,  191,   0
};

/* Clean 8x8 ASCII font (0x20..0x7F) for built-in CreatiVision & Sord M5 BIOSes */
static const u8 clean_font96[96][8] = {
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, {0x10,0x10,0x10,0x10,0x10,0x00,0x10,0x00},
    {0x28,0x28,0x28,0x00,0x00,0x00,0x00,0x00}, {0x28,0x28,0x7C,0x28,0x7C,0x28,0x28,0x00},
    {0x10,0x3C,0x50,0x38,0x14,0x78,0x10,0x00}, {0x60,0x64,0x08,0x10,0x20,0x4C,0x0C,0x00},
    {0x30,0x48,0x50,0x20,0x54,0x48,0x34,0x00}, {0x10,0x10,0x20,0x00,0x00,0x00,0x00,0x00},
    {0x08,0x10,0x20,0x20,0x20,0x10,0x08,0x00}, {0x20,0x10,0x08,0x08,0x08,0x10,0x20,0x00},
    {0x00,0x10,0x54,0x38,0x54,0x10,0x00,0x00}, {0x00,0x10,0x10,0x7C,0x10,0x10,0x00,0x00},
    {0x00,0x00,0x00,0x00,0x00,0x10,0x10,0x20}, {0x00,0x00,0x00,0x7C,0x00,0x00,0x00,0x00},
    {0x00,0x00,0x00,0x00,0x00,0x10,0x10,0x00}, {0x00,0x04,0x08,0x10,0x20,0x40,0x00,0x00},
    {0x38,0x44,0x4C,0x54,0x64,0x44,0x38,0x00}, {0x10,0x30,0x10,0x10,0x10,0x10,0x38,0x00},
    {0x38,0x44,0x04,0x18,0x20,0x40,0x7C,0x00}, {0x7C,0x08,0x10,0x18,0x04,0x44,0x38,0x00},
    {0x08,0x18,0x28,0x48,0x7C,0x08,0x08,0x00}, {0x7C,0x40,0x78,0x04,0x04,0x44,0x38,0x00},
    {0x18,0x20,0x40,0x78,0x44,0x44,0x38,0x00}, {0x7C,0x04,0x08,0x10,0x20,0x20,0x20,0x00},
    {0x38,0x44,0x44,0x38,0x44,0x44,0x38,0x00}, {0x38,0x44,0x44,0x3C,0x04,0x08,0x30,0x00},
    {0x00,0x10,0x10,0x00,0x10,0x10,0x00,0x00}, {0x00,0x10,0x10,0x00,0x10,0x10,0x20,0x00},
    {0x08,0x10,0x20,0x40,0x20,0x10,0x08,0x00}, {0x00,0x00,0x7C,0x00,0x7C,0x00,0x00,0x00},
    {0x20,0x10,0x08,0x04,0x08,0x10,0x20,0x00}, {0x38,0x44,0x04,0x18,0x10,0x00,0x10,0x00},
    {0x38,0x44,0x5C,0x54,0x5C,0x40,0x38,0x00}, {0x38,0x44,0x44,0x7C,0x44,0x44,0x44,0x00},
    {0x78,0x44,0x44,0x78,0x44,0x44,0x78,0x00}, {0x38,0x44,0x40,0x40,0x40,0x44,0x38,0x00},
    {0x70,0x48,0x44,0x44,0x44,0x48,0x70,0x00}, {0x7C,0x40,0x40,0x78,0x40,0x40,0x7C,0x00},
    {0x7C,0x40,0x40,0x78,0x40,0x40,0x40,0x00}, {0x38,0x44,0x40,0x5C,0x44,0x44,0x38,0x00},
    {0x44,0x44,0x44,0x7C,0x44,0x44,0x44,0x00}, {0x38,0x10,0x10,0x10,0x10,0x10,0x38,0x00},
    {0x1C,0x08,0x08,0x08,0x08,0x48,0x30,0x00}, {0x44,0x48,0x50,0x60,0x50,0x48,0x44,0x00},
    {0x40,0x40,0x40,0x40,0x40,0x40,0x7C,0x00}, {0x44,0x6C,0x54,0x54,0x44,0x44,0x44,0x00},
    {0x44,0x64,0x54,0x4C,0x44,0x44,0x44,0x00}, {0x38,0x44,0x44,0x44,0x44,0x44,0x38,0x00},
    {0x78,0x44,0x44,0x78,0x40,0x40,0x40,0x00}, {0x38,0x44,0x44,0x44,0x54,0x48,0x34,0x00},
    {0x78,0x44,0x44,0x78,0x50,0x48,0x44,0x00}, {0x38,0x44,0x40,0x38,0x04,0x44,0x38,0x00},
    {0x7C,0x10,0x10,0x10,0x10,0x10,0x10,0x00}, {0x44,0x44,0x44,0x44,0x44,0x44,0x38,0x00},
    {0x44,0x44,0x44,0x44,0x44,0x28,0x10,0x00}, {0x44,0x44,0x44,0x54,0x54,0x54,0x28,0x00},
    {0x44,0x44,0x28,0x10,0x28,0x44,0x44,0x00}, {0x44,0x44,0x28,0x10,0x10,0x10,0x10,0x00},
    {0x7C,0x04,0x08,0x10,0x20,0x40,0x7C,0x00}, {0x38,0x20,0x20,0x20,0x20,0x20,0x38,0x00},
    {0x00,0x40,0x20,0x10,0x08,0x04,0x00,0x00}, {0x38,0x08,0x08,0x08,0x08,0x08,0x38,0x00},
    {0x10,0x28,0x44,0x00,0x00,0x00,0x00,0x00}, {0x00,0x00,0x00,0x00,0x00,0x00,0x7C,0x00},
    {0x20,0x10,0x08,0x00,0x00,0x00,0x00,0x00}, {0x00,0x00,0x38,0x04,0x3C,0x44,0x3C,0x00},
    {0x40,0x40,0x58,0x64,0x44,0x44,0x78,0x00}, {0x00,0x00,0x38,0x40,0x40,0x44,0x38,0x00},
    {0x04,0x04,0x34,0x4C,0x44,0x44,0x3C,0x00}, {0x00,0x00,0x38,0x44,0x7C,0x40,0x38,0x00},
    {0x18,0x24,0x20,0x70,0x20,0x20,0x20,0x00}, {0x00,0x00,0x3C,0x44,0x44,0x3C,0x04,0x38},
    {0x40,0x40,0x58,0x64,0x44,0x44,0x44,0x00}, {0x10,0x00,0x30,0x10,0x10,0x10,0x38,0x00},
    {0x08,0x00,0x18,0x08,0x08,0x08,0x48,0x30}, {0x40,0x40,0x48,0x50,0x60,0x50,0x48,0x00},
    {0x30,0x10,0x10,0x10,0x10,0x10,0x38,0x00}, {0x00,0x00,0x68,0x54,0x54,0x44,0x44,0x00},
    {0x00,0x00,0x58,0x64,0x44,0x44,0x44,0x00}, {0x00,0x00,0x38,0x44,0x44,0x44,0x38,0x00},
    {0x00,0x00,0x78,0x44,0x44,0x78,0x40,0x40}, {0x00,0x00,0x3C,0x44,0x44,0x3C,0x04,0x04},
    {0x00,0x00,0x58,0x64,0x40,0x40,0x40,0x00}, {0x00,0x00,0x3C,0x40,0x38,0x04,0x78,0x00},
    {0x20,0x20,0x70,0x20,0x20,0x24,0x18,0x00}, {0x00,0x00,0x44,0x44,0x44,0x4C,0x34,0x00},
    {0x00,0x00,0x44,0x44,0x44,0x28,0x10,0x00}, {0x00,0x00,0x44,0x44,0x54,0x54,0x28,0x00},
    {0x00,0x00,0x44,0x28,0x10,0x28,0x44,0x00}, {0x00,0x00,0x44,0x44,0x44,0x3C,0x04,0x38},
    {0x00,0x00,0x7C,0x08,0x10,0x20,0x7C,0x00}, {0x08,0x10,0x10,0x20,0x10,0x10,0x08,0x00},
    {0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x00}, {0x20,0x10,0x10,0x08,0x10,0x10,0x20,0x00},
    {0x00,0x20,0x54,0x08,0x00,0x00,0x00,0x00}, {0x38,0x44,0x5C,0x50,0x5C,0x44,0x38,0x00}
};

static void cm_zero(void *dst, u32 n)
{
    u8 *p = (u8 *)dst;
    for (u32 i = 0; i < n; i++) p[i] = 0;
}

static void cm_copy(void *dst, const void *src, u32 n)
{
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    for (u32 i = 0; i < n; i++) d[i] = s[i];
}

static void put_s(char **p, const char *end, const char *s)
{
    while (*s && *p < end) *(*p)++ = *s++;
    **p = 0;
}

static void put_u(char **p, const char *end, u32 v)
{
    char d[12]; int n = 0;
    do d[n++] = (char)('0' + (v % 10u)); while (v /= 10u);
    while (n && *p < end) *(*p)++ = d[--n];
    **p = 0;
}

/* ---- TI SN76489A PSG Synthesis ---- */
static u32 cur_cpu_cycles(void)
{
    return S.is_m5 ? (u32)S.zcpu.cycles : S.cv_cyc;
}

static void audio_step(u32 cyc_delta)
{
    if (!S.snd_hz || !cyc_delta) return;
    u32 clock_hz = S.is_m5 ? M5_CLOCK_HZ : CV_CLOCK_HZ;
    u32 count = 0;
    while (cyc_delta) {
        u32 chunk = cyc_delta > 16000u ? 16000u : cyc_delta;
        cyc_delta -= chunk;
        u32 num = chunk * S.snd_hz + S.snd_frac;
        count += num / clock_hz;
        S.snd_frac = num % clock_hz;
    }
    if (!count) return;

    /* SN76489 internal clock = clock_hz / 16 -> 24.8 step = (clock_hz * 16) / snd_hz */
    u32 sn_step = (clock_hz * 16u) / S.snd_hz;

    while (count--) {
        s32 mix = 0;
        for (int ch = 0; ch < 3; ch++) {
            u32 p = S.sn.period[ch];
            if (p <= 1u) {
                S.sn.out_bit[ch] = 1;
            } else {
                u32 p8 = p << 8;
                S.sn.phase[ch] += sn_step;
                while (S.sn.phase[ch] >= p8) {
                    S.sn.phase[ch] -= p8;
                    S.sn.out_bit[ch] ^= 1u;
                }
            }
            s16 v = sn_vol_tab[S.sn.atten[ch] & 15u];
            mix += S.sn.out_bit[ch] ? v : -v;
        }
        {
            u32 nmode = S.sn.period[3] & 3u;
            u32 np = (nmode == 3u) ? ((u32)S.sn.period[2] << 1) : (16u << nmode);
            if (np < 2u) np = 2u;
            u32 np8 = np << 8;
            S.sn.phase[3] += sn_step;
            while (S.sn.phase[3] >= np8) {
                S.sn.phase[3] -= np8;
                u16 fb = (S.sn.period[3] & 4u)
                       ? (u16)(((S.sn.lfsr >> 0) ^ (S.sn.lfsr >> 1)) & 1u)
                       : (u16)(S.sn.lfsr & 1u);
                S.sn.lfsr = (u16)((S.sn.lfsr >> 1) | (fb << 14));
            }
            s16 v = sn_vol_tab[S.sn.atten[3] & 15u];
            mix += (S.sn.lfsr & 1u) ? v : -v;
        }

        S.snd_dc += (mix - S.snd_dc) >> 8;
        s32 out = mix - S.snd_dc;
        if (out > 32767) out = 32767;
        if (out < -32768) out = -32768;
        if (S.snd_count < CVM5_RING_LEN) {
            WS->snd_ring[(S.snd_head + S.snd_count) % CVM5_RING_LEN] = (s16)out;
            S.snd_count++;
        }
    }
}

static void audio_catch_up(void)
{
    if (!S.snd_hz) return;
    u32 now = cur_cpu_cycles();
    if (now > S.snd_last_cyc) {
        audio_step(now - S.snd_last_cyc);
        S.snd_last_cyc = now;
    }
}

static void sn_write(u8 v)
{
    audio_catch_up();
    if (v & 0x80u) {
        S.sn.latch = v;
        int ch = (v >> 5) & 3;
        if (v & 0x10u) {
            S.sn.atten[ch] = v & 0x0Fu;
        } else if (ch == 3) {
            S.sn.period[3] = v & 0x07u;
            S.sn.lfsr = 0x4000u;
        } else {
            S.sn.period[ch] = (u16)((S.sn.period[ch] & 0x3F0u) | (v & 0x0Fu));
        }
    } else {
        int ch = (S.sn.latch >> 5) & 3;
        if (S.sn.latch & 0x10u) {
            S.sn.atten[ch] = v & 0x0Fu;
        } else if (ch == 3) {
            S.sn.period[3] = v & 0x07u;
            S.sn.lfsr = 0x4000u;
        } else {
            S.sn.period[ch] = (u16)(((u16)(v & 0x3Fu) << 4) | (S.sn.period[ch] & 0x0Fu));
        }
    }
}

/* ---- Z80 CTC (Sord M5 Ports $00..$03) & VDP Interrupt Chaining ---- */
static void m5_update_z80_irq(void)
{
    if (!S.ctc_irq_pend) {
        S.zcpu.irq = 0;
        return;
    }
    for (int ch = 0; ch < 4; ch++) {
        if (S.ctc_irq_pend & (1u << ch)) {
            S.zcpu.bus = (u8)(S.ctc_vec | (ch << 1));
            S.zcpu.irq = 1;
            return;
        }
    }
}

static void m5_irq_ack(struct z80 *c)
{
    for (int ch = 0; ch < 4; ch++) {
        if (S.ctc_irq_pend & (1u << ch)) {
            c->bus = (u8)(S.ctc_vec | (ch << 1));
            S.ctc_irq_pend &= (u8)~(1u << ch);
            break;
        }
    }
    c->irq = (S.ctc_irq_pend != 0u) ? 1u : 0u;
}

static void ctc_trg3_edge(void)
{
    struct z80_ctc_ch *ch = &S.ctc[3];
    if (!ch->running || !(ch->ctrl & 0x40u)) return;
    if (ch->down > 0) ch->down--;
    if (ch->down == 0) {
        ch->down = ch->tc ? ch->tc : 256u;
        if (ch->ctrl & 0x80u) {
            S.ctc_irq_pend |= 0x08u;
            m5_update_z80_irq();
        }
    }
}

static void ctc_step_timers(u32 tstates)
{
    for (int i = 0; i < 4; i++) {
        struct z80_ctc_ch *ch = &S.ctc[i];
        if (!ch->running || (ch->ctrl & 0x40u)) continue; /* Counter mode only ticks on external edge */
        u32 presc = (ch->ctrl & 0x20u) ? 256u : 16u;
        ch->presc_acc += tstates;
        while (ch->presc_acc >= presc) {
            ch->presc_acc -= presc;
            if (ch->down > 0) ch->down--;
            if (ch->down == 0) {
                ch->down = ch->tc ? ch->tc : 256u;
                if (ch->ctrl & 0x80u) {
                    S.ctc_irq_pend |= (u8)(1u << i);
                    m5_update_z80_irq();
                }
            }
        }
    }
}

static void ctc_write(u8 ch_idx, u8 v)
{
    struct z80_ctc_ch *ch = &S.ctc[ch_idx & 3u];
    if (ch->await_tc) {
        ch->tc = v;
        ch->down = v ? v : 256u;
        ch->await_tc = 0;
        ch->running = 1;
        return;
    }
    if (!(v & 0x01u)) {
        if ((ch_idx & 3u) == 0u)
            S.ctc_vec = (u8)(v & 0xF8u);
        return;
    }
    ch->ctrl = v;
    if (v & 0x02u) {
        ch->running = 0;
        ch->presc_acc = 0;
        S.ctc_irq_pend &= (u8)~(1u << (ch_idx & 3u));
        m5_update_z80_irq();
    }
    if (v & 0x04u) ch->await_tc = 1;
    else if (!(v & 0x02u)) ch->running = 1;
}

static u8 ctc_read(u8 ch_idx)
{
    return (u8)(S.ctc[ch_idx & 3u].down & 0xFFu);
}

/* ---- TMS9918A / TMS9929A VDP ---- */
static void vdp_update_int(void)
{
    u8 line_on = (u8)(((S.vdp_status & 0x80u) && (S.vdp_reg[1] & 0x20u)) ? 1u : 0u);
    if (S.is_m5 && line_on && !S.vdp_int_prev)
        ctc_trg3_edge();
    S.vdp_int_prev = line_on;
}

static void vdp_data_write(u8 v)
{
    S.vdp_first = 0;
    WS->vram[S.vdp_addr & 0x3FFFu] = v;
    S.vdp_buf = v;
    S.vdp_addr = (u16)((S.vdp_addr + 1u) & 0x3FFFu);
}

static u8 vdp_data_read(void)
{
    u8 v = S.vdp_buf;
    S.vdp_first = 0;
    S.vdp_buf = WS->vram[S.vdp_addr & 0x3FFFu];
    S.vdp_addr = (u16)((S.vdp_addr + 1u) & 0x3FFFu);
    return v;
}

static void vdp_ctrl_write(u8 v)
{
    if (!S.vdp_first) {
        S.vdp_first = 1;
        S.vdp_latch = v;
        S.vdp_addr = (u16)((S.vdp_addr & 0x3F00u) | v);
        return;
    }
    S.vdp_first = 0;
    S.vdp_addr = (u16)(((u16)(v & 0x3Fu) << 8) | S.vdp_latch);
    if (v & 0x80u) {
        S.vdp_reg[v & 7u] = S.vdp_latch;
        vdp_update_int();
    } else if (!(v & 0x40u)) {
        S.vdp_buf = WS->vram[S.vdp_addr & 0x3FFFu];
        S.vdp_addr = (u16)((S.vdp_addr + 1u) & 0x3FFFu);
    }
}

static u8 vdp_status_read(void)
{
    u8 v = S.vdp_status;
    S.vdp_status &= 0x1Fu;
    S.vdp_first = 0;
    vdp_update_int();
    return v;
}

static void tms_init_palette(void)
{
    static const u8 rgb[16][3] = {
        {0x00, 0x00, 0x00}, {0x00, 0x00, 0x00}, {0x21, 0xC8, 0x42}, {0x5E, 0xDC, 0x78},
        {0x54, 0x55, 0xED}, {0x7D, 0x76, 0xFC}, {0xD4, 0x52, 0x4D}, {0x42, 0xEB, 0xF5},
        {0xFC, 0x55, 0x54}, {0xFF, 0x79, 0x78}, {0xD4, 0xC1, 0x54}, {0xE6, 0xCE, 0x80},
        {0x21, 0xB0, 0x3B}, {0xC9, 0x5B, 0xBA}, {0xCC, 0xCC, 0xCC}, {0xFF, 0xFF, 0xFF}
    };
    for (int i = 0; i < 16; i++)
        WS->tms_pal[i] = (u16)((rgb[i][0] >> 3) | ((rgb[i][1] >> 3) << 5) | ((rgb[i][2] >> 3) << 10));
}

static void render_tms_sprites(int y, u8 *row)
{
    int size = (S.vdp_reg[1] & 2u) ? 16 : 8;
    int mag = S.vdp_reg[1] & 1u;
    int h = size << mag;
    const u8 *sat = WS->vram + ((S.vdp_reg[5] & 0x7Fu) << 7);
    u32 patterns = (u32)(S.vdp_reg[6] & 7u) << 11;
    u8 taken[256];
    int n = 0, i;
    for (i = 0; i < 32; i++, sat += 4) {
        if (sat[0] == 0xD0u) break;
        int r = (u8)(y - sat[0] - 1);
        if (r >= h) continue;
        if (n == 4) {
            if (!(S.vdp_status & 0x40u))
                S.vdp_status = (u8)((S.vdp_status & 0xA0u) | 0x40u | i);
            break;
        }
        if (!n++)
            for (int x = 0; x < 256; x++) taken[x] = 0;
        r >>= mag;
        u32 a = patterns | ((u32)(size == 16 ? (sat[2] & 0xFCu) : sat[2]) << 3) | (u32)r;
        u32 bits = ((u32)WS->vram[a & 0x3FFFu] << 8) | (size == 16 ? WS->vram[(a + 16u) & 0x3FFFu] : 0);
        int x0 = sat[1] - ((sat[3] & 0x80u) ? 32 : 0);
        u8 c = sat[3] & 15u;
        for (int k = 0; k < h; k++) {
            if (!(bits & (0x8000u >> (k >> mag)))) continue;
            int x = x0 + k;
            if ((unsigned)x >= 256u) continue;
            if (taken[x] & 1u) S.vdp_status |= 0x20u;
            taken[x] |= 1u;
            if (c && !(taken[x] & 2u)) {
                taken[x] |= 2u;
                row[x] = c;
            }
        }
    }
    if (!(S.vdp_status & 0x40u))
        S.vdp_status = (u8)((S.vdp_status & 0xE0u) | (i < 32 ? i : 31));
}

static void render_tms_line(int y, u16 *out)
{
    u8 row[256];
    u16 back = WS->tms_pal[S.vdp_reg[7] & 15u];
    if (!(S.vdp_reg[1] & 0x40u)) {
        if (out)
            for (int x = 0; x < CVM5_W; x++) out[x] = back;
        return;
    }
    const u8 *names = WS->vram + ((S.vdp_reg[2] & 0x0Fu) << 10);
    if (S.vdp_reg[1] & 0x10u) {         /* Text mode (40x24) */
        const u8 *p = WS->vram + ((S.vdp_reg[4] & 7u) << 11) + (y & 7);
        const u8 *n = names + (y >> 3) * 40;
        u8 fg = S.vdp_reg[7] >> 4, bg = S.vdp_reg[7] & 15u;
        for (int x = 0; x < 8; x++) row[x] = row[248 + x] = 0;
        for (int k = 0; k < 40; k++) {
            u8 bits = p[n[k] * 8];
            for (int i = 0; i < 6; i++)
                row[8 + k * 6 + i] = (bits & (0x80u >> i)) ? fg : bg;
        }
    } else if (S.vdp_reg[1] & 0x08u) {  /* Multicolor mode (64x48) */
        const u8 *p = WS->vram + ((S.vdp_reg[4] & 7u) << 11) + ((y >> 3) & 3) * 2 + ((y >> 2) & 1);
        const u8 *n = names + (y >> 3) * 32;
        for (int k = 0; k < 32; k++) {
            u8 v = p[n[k] * 8];
            for (int i = 0; i < 4; i++) {
                row[k * 8 + i] = v >> 4;
                row[k * 8 + 4 + i] = v & 15u;
            }
        }
    } else {                            /* Graphics I & II */
        const u8 *n = names + (y >> 3) * 32;
        for (int k = 0; k < 32; k++) {
            u8 bits, c;
            if (S.vdp_reg[0] & 0x02u) {
                u32 idx = (u32)(((y >> 6) << 11) | (n[k] << 3) | (y & 7));
                bits = WS->vram[(((u32)(S.vdp_reg[4] & 4u) << 11) | (idx & (((u32)(S.vdp_reg[4] & 3u) << 11) | 0x7FFu))) & 0x3FFFu];
                c    = WS->vram[(((u32)(S.vdp_reg[3] & 0x80u) << 6) | (idx & (((u32)(S.vdp_reg[3] & 0x7Fu) << 6) | 0x3Fu))) & 0x3FFFu];
            } else {
                bits = WS->vram[(((S.vdp_reg[4] & 7u) << 11) + n[k] * 8 + (y & 7)) & 0x3FFFu];
                c    = WS->vram[((S.vdp_reg[3] << 6) + (n[k] >> 3)) & 0x3FFFu];
            }
            u8 fg = c >> 4, bg = c & 15u;
            for (int i = 0; i < 8; i++)
                row[k * 8 + i] = (bits & (0x80u >> i)) ? fg : bg;
        }
    }
    if (!(S.vdp_reg[1] & 0x10u))
        render_tms_sprites(y, row);
    if (out)
        for (int x = 0; x < CVM5_W; x++)
            out[x] = row[x] ? WS->tms_pal[row[x]] : back;
}

/* ---- VTech CreatiVision PIA & 6502 Bus ---- */
static u8 cv_read_pia_pb(void)
{
    u8 pa_out = (u8)((S.pia_ora & S.pia_ddra) | (~S.pia_ddra & 0xFFu));
    u8 pb = 0xFFu;
    for (int i = 0; i < 4; i++) {
        if (!(pa_out & (1u << i)))
            pb &= S.cv_pb[i];
    }
    return pb;
}

static __attribute__((noinline)) u8 cv_io_read(u16 addr)
{
    u8 hi = (u8)(addr >> 8);
    if (hi >= 0x10u && hi < 0x20u) {    /* MC6821 PIA ($1000..$1003) */
        switch (addr & 3u) {
        case 0:
            if (S.pia_cra & 0x04u) {
                S.pia_cra &= 0x3Fu;
                return (u8)((S.pia_ora & S.pia_ddra) | (~S.pia_ddra & 0xFFu));
            }
            return S.pia_ddra;
        case 1: return S.pia_cra;
        case 2:
            if (S.pia_crb & 0x04u) {
                S.pia_crb &= 0x3Fu;
                return (u8)((S.pia_orb & S.pia_ddrb) | (cv_read_pia_pb() & ~S.pia_ddrb));
            }
            return S.pia_ddrb;
        case 3: return S.pia_crb;
        }
    }
    if (hi >= 0x20u && hi < 0x30u)
        return (addr & 1u) ? vdp_status_read() : vdp_data_read();
    return 0xFFu;
}

static __attribute__((noinline)) void cv_io_write(u16 addr, u8 val)
{
    u8 hi = (u8)(addr >> 8);
    if (hi >= 0x10u && hi < 0x20u) {    /* MC6821 PIA */
        switch (addr & 3u) {
        case 0:
            if (S.pia_cra & 0x04u) S.pia_ora = val;
            else S.pia_ddra = val;
            break;
        case 1: S.pia_cra = (u8)((S.pia_cra & 0xC0u) | (val & 0x3Fu)); break;
        case 2:
            if (S.pia_crb & 0x04u) {
                S.pia_orb = val;
                if (S.pia_ddrb != 0u) {
                    sn_write(val);
                    S.pia_crb |= 0x80u; /* SN76489 /READY ack on PIA CB1! */
                }
            } else {
                S.pia_ddrb = val;
            }
            break;
        case 3: S.pia_crb = (u8)((S.pia_crb & 0xC0u) | (val & 0x3Fu)); break;
        }
        return;
    }
    if (hi >= 0x30u && hi < 0x40u) {    /* TMS9929A Write ($3000/$3001) */
        if (addr & 1u) vdp_ctrl_write(val);
        else           vdp_data_write(val);
    }
}

static inline u8 cv_rd(u16 addr)
{
    S.cv_cyc++;
    if (addr < 0x1000u) return WS->ram[addr & 0x03FFu];
    if (addr >= 0x4000u && addr < 0xC000u) return WS->cart[addr - 0x4000u];
    if (addr >= 0xF800u) return WS->bios[addr - 0xF800u];
    return cv_io_read(addr);
}

static inline void cv_wr(u16 addr, u8 val)
{
    S.cv_cyc++;
    if (addr < 0x1000u) { WS->ram[addr & 0x03FFu] = val; return; }
    if (addr < 0x4000u) cv_io_write(addr, val);
}

/* ---- MOS 6502 CPU Core (CreatiVision) ---- */
#define FC 0x01u
#define FZ 0x02u
#define FI 0x04u
#define FD 0x08u
#define FB 0x10u
#define FU 0x20u
#define FV 0x40u
#define FN 0x80u

static inline void set_nz(u8 v) { S.p = (u8)((S.p & ~(FN | FZ)) | (v & FN) | (v ? 0u : FZ)); }
static inline void push8(u8 v)  { cv_wr((u16)(0x0100u | S.sp--), v); }
static inline u8 pull8(void)    { return cv_rd((u16)(0x0100u | ++S.sp)); }

static void op_adc(u8 v)
{
    u32 a = S.a, c = S.p & FC, bin = a + v + c;
    if (S.p & FD) {
        u32 lo = (a & 15u) + (v & 15u) + c;
        if (lo > 9u) lo += 6u;
        u32 r = (a & 0xF0u) + (v & 0xF0u) + (lo > 15u ? 0x10u : 0u) + (lo & 15u);
        S.p &= (u8)~(FN | FV | FZ | FC);
        if (~(a ^ v) & (a ^ r) & 0x80u) S.p |= FV;
        if (r > 0x99u) r += 0x60u;
        if (r > 0xFFu) S.p |= FC;
        S.a = (u8)r;
        set_nz(S.a);
    } else {
        S.p = (u8)((S.p & ~(FN | FV | FZ | FC)) | (bin & FN) | ((bin & 0xFFu) ? 0u : FZ) |
                   ((~(a ^ v) & (a ^ bin) & 0x80u) ? FV : 0u) | (bin > 0xFFu ? FC : 0u));
        S.a = (u8)bin;
    }
}

static void op_sbc(u8 v)
{
    u32 a = S.a, nb = S.p & FC, dif = a - v - (1u - nb);
    if (S.p & FD) {
        s32 lo = (s32)(a & 15u) - (s32)(v & 15u) - (s32)(1u - nb);
        s32 r = (s32)dif;
        if (r < 0) r -= 0x60;
        if (lo < 0) r -= 0x06;
        S.p = (u8)((S.p & ~(FN | FV | FZ | FC)) | (((a ^ v) & (a ^ dif) & 0x80u) ? FV : 0u) |
                   (dif < 0x100u ? FC : 0u));
        S.a = (u8)r;
        set_nz(S.a);
    } else {
        S.p = (u8)((S.p & ~(FN | FV | FZ | FC)) | (dif & FN) | ((dif & 0xFFu) ? 0u : FZ) |
                   (((a ^ v) & (a ^ dif) & 0x80u) ? FV : 0u) | (dif < 0x100u ? FC : 0u));
        S.a = (u8)dif;
    }
}

static inline void op_cmp(u8 r, u8 v) { S.p = (u8)((S.p & ~FC) | (r >= v ? FC : 0u)); set_nz((u8)(r - v)); }
static inline u8 op_asl(u8 v) { S.p = (u8)((S.p & ~FC) | (v >> 7)); v = (u8)(v << 1); set_nz(v); return v; }
static inline u8 op_lsr(u8 v) { S.p = (u8)((S.p & ~FC) | (v & 1u)); v >>= 1; set_nz(v); return v; }
static inline u8 op_rol(u8 v) { u8 c = S.p & FC; S.p = (u8)((S.p & ~FC) | (v >> 7)); v = (u8)((v << 1) | c); set_nz(v); return v; }
static inline u8 op_ror(u8 v) { u8 c = S.p & FC; S.p = (u8)((S.p & ~FC) | (v & 1u)); v = (u8)((v >> 1) | (c << 7)); set_nz(v); return v; }

static inline u16 ea_zp(void)  { return cv_rd(S.pc++); }
static inline u16 ea_zpx(void) { u8 z = cv_rd(S.pc++); S.cv_cyc++; return (u8)(z + S.x); }
static inline u16 ea_zpy(void) { u8 z = cv_rd(S.pc++); S.cv_cyc++; return (u8)(z + S.y); }
static inline u16 ea_abs(void) { u16 a = cv_rd(S.pc++); return (u16)(a | ((u16)cv_rd(S.pc++) << 8)); }
static inline u16 ea_abx(int wr) { u16 b = ea_abs(), a = (u16)(b + S.x); if (wr || ((b ^ a) & 0xFF00u)) S.cv_cyc++; return a; }
static inline u16 ea_aby(int wr) { u16 b = ea_abs(), a = (u16)(b + S.y); if (wr || ((b ^ a) & 0xFF00u)) S.cv_cyc++; return a; }
static inline u16 ea_izx(void) { u8 z = cv_rd(S.pc++); S.cv_cyc++; z = (u8)(z + S.x); u16 a = cv_rd(z); return (u16)(a | ((u16)cv_rd((u8)(z + 1u)) << 8)); }
static inline u16 ea_izy(int wr) { u8 z = cv_rd(S.pc++); u16 b = cv_rd(z); b |= (u16)(cv_rd((u8)(z + 1u)) << 8); u16 a = (u16)(b + S.y); if (wr || ((b ^ a) & 0xFF00u)) S.cv_cyc++; return a; }

static void cv_cpu_step(void)
{
    if (S.jam) { S.cv_cyc += 4u; return; }
    if (S.nmi_pend) {
        S.nmi_pend = 0;
        S.cv_cyc += 2u;
        push8((u8)(S.pc >> 8)); push8((u8)S.pc); push8((u8)((S.p & ~FB) | FU));
        S.p |= FI;
        u8 lo = cv_rd(0xFFFAu);
        S.pc = (u16)(lo | ((u16)cv_rd(0xFFFBu) << 8));
        return;
    }
    if (S.vdp_int_prev && !(S.p & FI)) {
        S.cv_cyc += 2u;
        push8((u8)(S.pc >> 8)); push8((u8)S.pc); push8((u8)((S.p & ~FB) | FU));
        S.p |= FI;
        u8 lo = cv_rd(0xFFFEu);
        S.pc = (u16)(lo | ((u16)cv_rd(0xFFFFu) << 8));
        return;
    }

    u8 op = cv_rd(S.pc++);
    u16 ea;
    u8 v;

#define BR(cond) do { s32 off = (signed char)cv_rd(S.pc++); if (cond) { u16 t = (u16)(S.pc + off); S.cv_cyc += ((S.pc ^ t) & 0xFF00u) ? 2u : 1u; S.pc = t; } } while (0)
#define RMW(ae, fn) do { ea = (ae); v = cv_rd(ea); S.cv_cyc++; v = (fn); cv_wr(ea, v); } while (0)

    switch (op) {
    case 0x09: set_nz(S.a |= cv_rd(S.pc++)); break;
    case 0x05: set_nz(S.a |= cv_rd(ea_zp())); break;
    case 0x15: set_nz(S.a |= cv_rd(ea_zpx())); break;
    case 0x0D: set_nz(S.a |= cv_rd(ea_abs())); break;
    case 0x1D: set_nz(S.a |= cv_rd(ea_abx(0))); break;
    case 0x19: set_nz(S.a |= cv_rd(ea_aby(0))); break;
    case 0x01: set_nz(S.a |= cv_rd(ea_izx())); break;
    case 0x11: set_nz(S.a |= cv_rd(ea_izy(0))); break;

    case 0x29: set_nz(S.a &= cv_rd(S.pc++)); break;
    case 0x25: set_nz(S.a &= cv_rd(ea_zp())); break;
    case 0x35: set_nz(S.a &= cv_rd(ea_zpx())); break;
    case 0x2D: set_nz(S.a &= cv_rd(ea_abs())); break;
    case 0x3D: set_nz(S.a &= cv_rd(ea_abx(0))); break;
    case 0x39: set_nz(S.a &= cv_rd(ea_aby(0))); break;
    case 0x21: set_nz(S.a &= cv_rd(ea_izx())); break;
    case 0x31: set_nz(S.a &= cv_rd(ea_izy(0))); break;

    case 0x49: set_nz(S.a ^= cv_rd(S.pc++)); break;
    case 0x45: set_nz(S.a ^= cv_rd(ea_zp())); break;
    case 0x55: set_nz(S.a ^= cv_rd(ea_zpx())); break;
    case 0x4D: set_nz(S.a ^= cv_rd(ea_abs())); break;
    case 0x5D: set_nz(S.a ^= cv_rd(ea_abx(0))); break;
    case 0x59: set_nz(S.a ^= cv_rd(ea_aby(0))); break;
    case 0x41: set_nz(S.a ^= cv_rd(ea_izx())); break;
    case 0x51: set_nz(S.a ^= cv_rd(ea_izy(0))); break;

    case 0x69: op_adc(cv_rd(S.pc++)); break;
    case 0x65: op_adc(cv_rd(ea_zp())); break;
    case 0x75: op_adc(cv_rd(ea_zpx())); break;
    case 0x6D: op_adc(cv_rd(ea_abs())); break;
    case 0x7D: op_adc(cv_rd(ea_abx(0))); break;
    case 0x79: op_adc(cv_rd(ea_aby(0))); break;
    case 0x61: op_adc(cv_rd(ea_izx())); break;
    case 0x71: op_adc(cv_rd(ea_izy(0))); break;

    case 0xE9: case 0xEB: op_sbc(cv_rd(S.pc++)); break;
    case 0xE5: op_sbc(cv_rd(ea_zp())); break;
    case 0xF5: op_sbc(cv_rd(ea_zpx())); break;
    case 0xED: op_sbc(cv_rd(ea_abs())); break;
    case 0xFD: op_sbc(cv_rd(ea_abx(0))); break;
    case 0xF9: op_sbc(cv_rd(ea_aby(0))); break;
    case 0xE1: op_sbc(cv_rd(ea_izx())); break;
    case 0xF1: op_sbc(cv_rd(ea_izy(0))); break;

    case 0x85: cv_wr(ea_zp(), S.a); break;
    case 0x95: cv_wr(ea_zpx(), S.a); break;
    case 0x8D: cv_wr(ea_abs(), S.a); break;
    case 0x9D: cv_wr(ea_abx(1), S.a); break;
    case 0x99: cv_wr(ea_aby(1), S.a); break;
    case 0x81: cv_wr(ea_izx(), S.a); break;
    case 0x91: cv_wr(ea_izy(1), S.a); break;
    case 0x86: cv_wr(ea_zp(), S.x); break;
    case 0x96: cv_wr(ea_zpy(), S.x); break;
    case 0x8E: cv_wr(ea_abs(), S.x); break;
    case 0x84: cv_wr(ea_zp(), S.y); break;
    case 0x94: cv_wr(ea_zpx(), S.y); break;
    case 0x8C: cv_wr(ea_abs(), S.y); break;

    case 0xA9: set_nz(S.a = cv_rd(S.pc++)); break;
    case 0xA5: set_nz(S.a = cv_rd(ea_zp())); break;
    case 0xB5: set_nz(S.a = cv_rd(ea_zpx())); break;
    case 0xAD: set_nz(S.a = cv_rd(ea_abs())); break;
    case 0xBD: set_nz(S.a = cv_rd(ea_abx(0))); break;
    case 0xB9: set_nz(S.a = cv_rd(ea_aby(0))); break;
    case 0xA1: set_nz(S.a = cv_rd(ea_izx())); break;
    case 0xB1: set_nz(S.a = cv_rd(ea_izy(0))); break;
    case 0xA2: set_nz(S.x = cv_rd(S.pc++)); break;
    case 0xA6: set_nz(S.x = cv_rd(ea_zp())); break;
    case 0xB6: set_nz(S.x = cv_rd(ea_zpy())); break;
    case 0xAE: set_nz(S.x = cv_rd(ea_abs())); break;
    case 0xBE: set_nz(S.x = cv_rd(ea_aby(0))); break;
    case 0xA0: set_nz(S.y = cv_rd(S.pc++)); break;
    case 0xA4: set_nz(S.y = cv_rd(ea_zp())); break;
    case 0xB4: set_nz(S.y = cv_rd(ea_zpx())); break;
    case 0xAC: set_nz(S.y = cv_rd(ea_abs())); break;
    case 0xBC: set_nz(S.y = cv_rd(ea_abx(0))); break;

    case 0xC9: op_cmp(S.a, cv_rd(S.pc++)); break;
    case 0xC5: op_cmp(S.a, cv_rd(ea_zp())); break;
    case 0xD5: op_cmp(S.a, cv_rd(ea_zpx())); break;
    case 0xCD: op_cmp(S.a, cv_rd(ea_abs())); break;
    case 0xDD: op_cmp(S.a, cv_rd(ea_abx(0))); break;
    case 0xD9: op_cmp(S.a, cv_rd(ea_aby(0))); break;
    case 0xC1: op_cmp(S.a, cv_rd(ea_izx())); break;
    case 0xD1: op_cmp(S.a, cv_rd(ea_izy(0))); break;
    case 0xE0: op_cmp(S.x, cv_rd(S.pc++)); break;
    case 0xE4: op_cmp(S.x, cv_rd(ea_zp())); break;
    case 0xEC: op_cmp(S.x, cv_rd(ea_abs())); break;
    case 0xC0: op_cmp(S.y, cv_rd(S.pc++)); break;
    case 0xC4: op_cmp(S.y, cv_rd(ea_zp())); break;
    case 0xCC: op_cmp(S.y, cv_rd(ea_abs())); break;

    case 0x24: v = cv_rd(ea_zp());  S.p = (u8)((S.p & ~(FN|FV|FZ)) | (v & 0xC0u) | ((v & S.a) ? 0u : FZ)); break;
    case 0x2C: v = cv_rd(ea_abs()); S.p = (u8)((S.p & ~(FN|FV|FZ)) | (v & 0xC0u) | ((v & S.a) ? 0u : FZ)); break;

    case 0x0A: S.cv_cyc++; S.a = op_asl(S.a); break;
    case 0x2A: S.cv_cyc++; S.a = op_rol(S.a); break;
    case 0x4A: S.cv_cyc++; S.a = op_lsr(S.a); break;
    case 0x6A: S.cv_cyc++; S.a = op_ror(S.a); break;
    case 0x06: RMW(ea_zp(),   op_asl(v)); break;
    case 0x16: RMW(ea_zpx(),  op_asl(v)); break;
    case 0x0E: RMW(ea_abs(),  op_asl(v)); break;
    case 0x1E: RMW(ea_abx(1), op_asl(v)); break;
    case 0x26: RMW(ea_zp(),   op_rol(v)); break;
    case 0x36: RMW(ea_zpx(),  op_rol(v)); break;
    case 0x2E: RMW(ea_abs(),  op_rol(v)); break;
    case 0x3E: RMW(ea_abx(1), op_rol(v)); break;
    case 0x46: RMW(ea_zp(),   op_lsr(v)); break;
    case 0x56: RMW(ea_zpx(),  op_lsr(v)); break;
    case 0x4E: RMW(ea_abs(),  op_lsr(v)); break;
    case 0x5E: RMW(ea_abx(1), op_lsr(v)); break;
    case 0x66: RMW(ea_zp(),   op_ror(v)); break;
    case 0x76: RMW(ea_zpx(),  op_ror(v)); break;
    case 0x6E: RMW(ea_abs(),  op_ror(v)); break;
    case 0x7E: RMW(ea_abx(1), op_ror(v)); break;
    case 0xC6: RMW(ea_zp(),   (u8)(v - 1u)); set_nz(v); break;
    case 0xD6: RMW(ea_zpx(),  (u8)(v - 1u)); set_nz(v); break;
    case 0xCE: RMW(ea_abs(),  (u8)(v - 1u)); set_nz(v); break;
    case 0xDE: RMW(ea_abx(1), (u8)(v - 1u)); set_nz(v); break;
    case 0xE6: RMW(ea_zp(),   (u8)(v + 1u)); set_nz(v); break;
    case 0xF6: RMW(ea_zpx(),  (u8)(v + 1u)); set_nz(v); break;
    case 0xEE: RMW(ea_abs(),  (u8)(v + 1u)); set_nz(v); break;
    case 0xFE: RMW(ea_abx(1), (u8)(v + 1u)); set_nz(v); break;

    case 0x4C: S.pc = ea_abs(); break;
    case 0x6C: {
        u16 p = ea_abs();
        u8 lo = cv_rd(p);
        u16 hi_a = (u16)((p & 0xFF00u) | ((p + 1u) & 0x00FFu)); /* NMOS 6502 page-wrap */
        S.pc = (u16)(lo | ((u16)cv_rd(hi_a) << 8));
        break;
    }
    case 0x20: { u8 lo = cv_rd(S.pc++); S.cv_cyc++; push8((u8)(S.pc >> 8)); push8((u8)S.pc); S.pc = (u16)(lo | ((u16)cv_rd(S.pc) << 8)); break; }
    case 0x60: { S.cv_cyc += 2u; u8 lo = pull8(); S.pc = (u16)((lo | ((u16)pull8() << 8)) + 1u); S.cv_cyc++; break; }
    case 0x40: { S.cv_cyc += 2u; S.p = (u8)((pull8() & ~FB) | FU); u8 lo = pull8(); S.pc = (u16)(lo | ((u16)pull8() << 8)); break; }
    case 0x00: { (void)cv_rd(S.pc++); push8((u8)(S.pc >> 8)); push8((u8)S.pc); push8((u8)(S.p | FB | FU)); S.p |= FI; u8 lo = cv_rd(0xFFFEu); S.pc = (u16)(lo | ((u16)cv_rd(0xFFFFu) << 8)); break; }

    case 0x10: BR(!(S.p & FN)); break;
    case 0x30: BR(S.p & FN); break;
    case 0x50: BR(!(S.p & FV)); break;
    case 0x70: BR(S.p & FV); break;
    case 0x90: BR(!(S.p & FC)); break;
    case 0xB0: BR(S.p & FC); break;
    case 0xD0: BR(!(S.p & FZ)); break;
    case 0xF0: BR(S.p & FZ); break;

    case 0x08: S.cv_cyc++; push8((u8)(S.p | FB | FU)); break;
    case 0x28: S.cv_cyc += 2u; S.p = (u8)((pull8() & ~FB) | FU); break;
    case 0x48: S.cv_cyc++; push8(S.a); break;
    case 0x68: S.cv_cyc += 2u; set_nz(S.a = pull8()); break;
    case 0x18: S.cv_cyc++; S.p &= ~FC; break;
    case 0x38: S.cv_cyc++; S.p |= FC; break;
    case 0x58: S.cv_cyc++; S.p &= ~FI; break;
    case 0x78: S.cv_cyc++; S.p |= FI; break;
    case 0xB8: S.cv_cyc++; S.p &= ~FV; break;
    case 0xD8: S.cv_cyc++; S.p &= ~FD; break;
    case 0xF8: S.cv_cyc++; S.p |= FD; break;
    case 0x88: S.cv_cyc++; set_nz(--S.y); break;
    case 0xC8: S.cv_cyc++; set_nz(++S.y); break;
    case 0xCA: S.cv_cyc++; set_nz(--S.x); break;
    case 0xE8: S.cv_cyc++; set_nz(++S.x); break;
    case 0x98: S.cv_cyc++; set_nz(S.a = S.y); break;
    case 0xA8: S.cv_cyc++; set_nz(S.y = S.a); break;
    case 0x8A: S.cv_cyc++; set_nz(S.a = S.x); break;
    case 0xAA: S.cv_cyc++; set_nz(S.x = S.a); break;
    case 0x9A: S.cv_cyc++; S.sp = S.x; break;
    case 0xBA: S.cv_cyc++; set_nz(S.x = S.sp); break;
    case 0xEA: S.cv_cyc++; break;
    case 0x02: case 0x12: case 0x22: case 0x32: case 0x42: case 0x52:
    case 0x62: case 0x72: case 0x92: case 0xB2: case 0xD2: case 0xF2:
        S.jam = 1; S.pc--; break;
    default:
        S.cv_cyc++;
        break;
    }
#undef BR
#undef RMW
}

/* ---- Sord M5 Z80 Memory & I/O ---- */
static u8 m5_z80_read(struct z80 *c, u16 a)
{
    u8 *p = c->rd[a >> 10];
    return p ? p[a & 0x3FFu] : 0xFFu;
}

static void m5_z80_write(struct z80 *c, u16 a, u8 v)
{
    u8 *p = c->wr[a >> 10];
    if (p) p[a & 0x3FFu] = v;
}

static u8 m5_z80_in(struct z80 *c, u16 port)
{
    (void)c;
    u8 p = (u8)port;
    switch (p & 0xF0u) {
    case 0x00: return ctc_read(p & 3u);
    case 0x10: return (p & 1u) ? vdp_status_read() : vdp_data_read();
    case 0x30: return S.m5_ports[p & 7u];
    case 0x40: return 0x00u;            /* Printer / cassette ready */
    }
    return 0xFFu;
}

static void m5_z80_out(struct z80 *c, u16 port, u8 v)
{
    (void)c;
    u8 p = (u8)port;
    switch (p & 0xF0u) {
    case 0x00: ctc_write(p & 3u, v); break;
    case 0x10:
        if (p & 1u) vdp_ctrl_write(v);
        else        vdp_data_write(v);
        break;
    case 0x20: sn_write(v); break;
    }
}

/* ---- Clean-Room Built-In CreatiVision & Sord M5 BIOS Builders ---- */
static void build_cv_bios(void)
{
    /* Fill $F800..$FFFF with RTS ($60) so any undocumented BIOS JSR returns cleanly */
    for (u32 i = 0; i < 0x0800u; i++) WS->bios[i] = 0x60u;

    /* 8x8 ASCII font at $FA00..$FCFF (offset 0x0200..0x04FF) */
    for (u32 ch = 0; ch < 96u; ch++)
        for (u32 r = 0; r < 8u; r++)
            WS->bios[0x0200u + ch * 8u + r] = clean_font96[ch][r];

    /* $F804: NMI -> JMP ($BFFC); $F808: Default NMI target -> RTI; $F810: IRQ -> JMP ($BFFE) */
    WS->bios[0x0004] = 0x6Cu; WS->bios[0x0005] = 0xFCu; WS->bios[0x0006] = 0xBFu;
    WS->bios[0x0008] = 0x40u; /* RTI */
    WS->bios[0x0010] = 0x6Cu; WS->bios[0x0011] = 0xFEu; WS->bios[0x0012] = 0xBFu;
    /* $F814: Safe fallback IRQ handler (LDA $2001 ; RTI) */
    WS->bios[0x0014] = 0xADu; WS->bios[0x0015] = 0x01u; WS->bios[0x0016] = 0x20u; WS->bios[0x0017] = 0x40u;

    /* $FE57 / $FE67 / $FE77 entry trampolines -> $FE90 / $FEB0 / $FED0 (zero overlap!) */
    WS->bios[0x0657] = 0x4Cu; WS->bios[0x0658] = 0x90u; WS->bios[0x0659] = 0xFEu;
    WS->bios[0x0667] = 0x4Cu; WS->bios[0x0668] = 0xB0u; WS->bios[0x0669] = 0xFEu;
    WS->bios[0x0677] = 0x4Cu; WS->bios[0x0678] = 0xD0u; WS->bios[0x0679] = 0xFEu;

    /* $FE90: BIOS_SN_INIT - silence all 4 SN76489 channels, preserving X & Y! */
    static const u8 sn_init[] = {
        0x48,               /* PHA */
        0x20, 0x67, 0xFE,   /* JSR $FE67 (PreparePort) */
        0xA9, 0x9F, 0x20, 0x77, 0xFE,
        0xA9, 0xBF, 0x20, 0x77, 0xFE,
        0xA9, 0xDF, 0x20, 0x77, 0xFE,
        0xA9, 0xFF, 0x20, 0x77, 0xFE,
        0x68,               /* PLA */
        0x60                /* RTS */
    };
    cm_copy(WS->bios + 0x0690u, sn_init, sizeof(sn_init));

    /* $FEB0: BIOS_PREPARE_PORT - configure PIA PB ($1002/$1003) as SN76489 output */
    static const u8 prep_port[] = {
        0x48,               /* PHA */
        0xA9, 0x22, 0x8D, 0x03, 0x10,
        0xA9, 0xFF, 0x8D, 0x02, 0x10,
        0xA9, 0x26, 0x8D, 0x03, 0x10,
        0x68,               /* PLA */
        0x60                /* RTS */
    };
    cm_copy(WS->bios + 0x06B0u, prep_port, sizeof(prep_port));

    /* $FED0: BIOS_SN_WRITE - write A to SN76489 via PIA PB, preserving A, X, Y! */
    static const u8 sn_wr[] = {
        0x48,               /* PHA */
        0x8D, 0x02, 0x10,   /* STA $1002 */
        0x2C, 0x03, 0x10,   /* wait: BIT $1003 */
        0x10, 0xFB,         /* BPL wait (-5) */
        0xAD, 0x02, 0x10,   /* LDA $1002 (clear CB1 flag) */
        0x68,               /* PLA */
        0x60                /* RTS */
    };
    cm_copy(WS->bios + 0x06D0u, sn_wr, sizeof(sn_wr));

    /* $F820 (offset 0x0020): Hardware RESET routine */
    static const u8 cv_rst[] = {
        0x78, 0xD8,         /* SEI ; CLD */
        0xA2, 0xFF, 0x9A,   /* LDX #$FF ; TXS */
        /* Clear 1 KB RAM ($0000..$03FF) */
        0xA9, 0x00, 0xAA,
        0x9D, 0x00, 0x00,   /* clr_ram: STA $0000,X */
        0x9D, 0x00, 0x01,
        0x9D, 0x00, 0x02,
        0x9D, 0x00, 0x03,
        0xE8, 0xD0, 0xF1,   /* INX ; BNE clr_ram (-15) */
        /* Silence SN76489 + init PIA */
        0x20, 0x57, 0xFE,   /* JSR $FE57 */
        0xA9, 0x00, 0x8D, 0x01, 0x10,
        0xA9, 0x0F, 0x8D, 0x00, 0x10,
        0xA9, 0x04, 0x8D, 0x01, 0x10,
        /* Clear 16 KB VRAM ($0000..$3FFF) */
        0xA9, 0x00, 0x8D, 0x01, 0x30,
        0xA9, 0x40, 0x8D, 0x01, 0x30,
        0xA0, 0x40, 0xA2, 0x00, 0xA9, 0x00,
        0x8D, 0x00, 0x30,   /* clr_vram: STA $3000 */
        0xE8, 0xD0, 0xFA,   /* INX ; BNE clr_vram (-6) */
        0x88, 0xD0, 0xF7,   /* DEY ; BNE clr_vram (-9) */
        /* Load initial VDP R0..R7 from cartridge header $BFF0..$BFF7! */
        0xA2, 0x00,
        0xBD, 0xF0, 0xBF,   /* vdp_lp: LDA $BFF0,X */
        0x8D, 0x01, 0x30,   /* STA $3001 */
        0x8A, 0x09, 0x80,   /* TXA ; ORA #$80 */
        0x8D, 0x01, 0x30,   /* STA $3001 */
        0xE8, 0xE0, 0x08,   /* INX ; CPX #8 */
        0xD0, 0xEF,         /* BNE vdp_lp (-17) */
        /* Clear any stale VDP status flag, then jump via cartridge entry ($BFE8)! */
        0xAD, 0x01, 0x20,   /* LDA $2001 */
        0x6C, 0xE8, 0xBF    /* JMP ($BFE8) */
    };
    cm_copy(WS->bios + 0x0020u, cv_rst, sizeof(cv_rst));

    /* Hardware vectors: NMI=$F804, RESET=$F820, IRQ=$F810 */
    WS->bios[0x07FA] = 0x04u; WS->bios[0x07FB] = 0xF8u;
    WS->bios[0x07FC] = 0x20u; WS->bios[0x07FD] = 0xF8u;
    WS->bios[0x07FE] = 0x10u; WS->bios[0x07FF] = 0xF8u;
}

static void build_m5_bios(void)
{
    /* Fill $0000..$1FFF with RET ($C9) so $002E and any Monitor hook return cleanly! */
    for (u32 i = 0; i < 0x2000u; i++) WS->bios[i] = 0xC9u;

    /* 8x8 ASCII font at $0800..$0AFF */
    for (u32 ch = 0; ch < 96u; ch++)
        for (u32 r = 0; r < 8u; r++)
            WS->bios[0x0800u + ch * 8u + r] = clean_font96[ch][r];

    /* $0000: DI ; LD SP,$7FF0 ; JP $0100 (keeps $002E=RET, $0038=IM1, $0066=NMI intact!) */
    static const u8 rst0[] = { 0xF3, 0x31, 0xF0, 0x7F, 0xC3, 0x00, 0x01 };
    cm_copy(WS->bios + 0x0000u, rst0, sizeof(rst0));

    /* $0038: EI ; RETI */
    WS->bios[0x0038] = 0xFBu; WS->bios[0x0039] = 0xEDu; WS->bios[0x003A] = 0x4Du;
    /* $0066: RETN */
    WS->bios[0x0066] = 0xEDu; WS->bios[0x0067] = 0x45u;

    /* $0080: Default IM2 VDP IRQ handler (stored at $7006..$7007) */
    static const u8 def_isr[] = {
        0xF5,               /* PUSH AF */
        0xDB, 0x11,         /* IN A,($11) - clear VDP status */
        0xF1,               /* POP AF */
        0xFB,               /* EI */
        0xED, 0x4D          /* RETI */
    };
    cm_copy(WS->bios + 0x0080u, def_isr, sizeof(def_isr));

    /* $0090: JP (HL) helper */
    WS->bios[0x0090] = 0xE9u;

    /* $0100: Sord M5 Monitor Cold Init + Cartridge Boot */
    static const u8 m5_init[] = {
        /* Clear $7000..$7FEF internal RAM */
        0x21, 0x00, 0x70,   /* LD HL,$7000 */
        0x11, 0x01, 0x70,   /* LD DE,$7001 */
        0x01, 0xEF, 0x0F,   /* LD BC,$0FEF */
        0x36, 0x00,         /* LD (HL),0 */
        0xED, 0xB0,         /* LDIR */
        /* Set I = $70, IM 2, and default IM2 vectors $7000..$7007 -> $0080 */
        0x3E, 0x70, 0xED, 0x47, /* LD A,$70 ; LD I,A */
        0xED, 0x5E,         /* IM 2 */
        0x21, 0x80, 0x00,   /* LD HL,$0080 */
        0x22, 0x00, 0x70,   /* LD ($7000),HL */
        0x22, 0x02, 0x70,   /* LD ($7002),HL */
        0x22, 0x04, 0x70,   /* LD ($7004),HL */
        0x22, 0x06, 0x70,   /* LD ($7006),HL */
        /* Program Z80 CTC: vector $00, reset ch0..2, ch3 = VDP /INT counter ($D7, TC=1) */
        0xAF, 0xD3, 0x00,   /* XOR A ; OUT ($00),A */
        0x3E, 0x03, 0xD3, 0x00, 0xD3, 0x01, 0xD3, 0x02,
        0x3E, 0xD7, 0xD3, 0x03, /* LD A,$D7 ; OUT ($03),A */
        0x3E, 0x01, 0xD3, 0x03, /* LD A,$01 ; OUT ($03),A */
        /* Silence SN76489 ($20) */
        0x3E, 0x9F, 0xD3, 0x20,
        0x3E, 0xBF, 0xD3, 0x20,
        0x3E, 0xDF, 0xD3, 0x20,
        0x3E, 0xFF, 0xD3, 0x20,
        /* Clear 16 KB VRAM */
        0xAF, 0xD3, 0x11, 0x3E, 0x40, 0xD3, 0x11,
        0x01, 0x00, 0x40,   /* LD BC,$4000 */
        0xAF,               /* clr_v: XOR A */
        0xD3, 0x10,         /* OUT ($10),A */
        0x0B, 0x78, 0xB1,   /* DEC BC ; LD A,B ; OR C */
        0x20, 0xF8,         /* JR NZ,clr_v (-8) */
        /* Call cartridge boot_init ($2003), then jump to cartridge start_addr ($2001)! */
        0x2A, 0x03, 0x20,   /* LD HL,($2003) */
        0xCD, 0x90, 0x00,   /* CALL $0090 (JP (HL)) */
        0x2A, 0x01, 0x20,   /* LD HL,($2001) */
        0xE9                /* JP (HL) */
    };
    cm_copy(WS->bios + 0x0100u, m5_init, sizeof(m5_init));
}

/* ---- Keyboard & Gamepad Mapping ---- */
static void m5_press_ascii(u8 c)
{
    if (c >= 'a' && c <= 'z') c = (u8)(c - 32u);
    if (c == ' ')  { S.m5_ports[0] |= 0x40u; return; }
    if (c == '\r') { S.m5_ports[0] |= 0x80u; return; }
    if (c >= '1' && c <= '8') { S.m5_ports[1] |= (u8)(1u << (c - '1')); return; }
    if (c == '9')  { S.m5_ports[5] |= 0x01u; return; }
    if (c == '0')  { S.m5_ports[5] |= 0x02u; return; }
    /* Sord M5 key matrix (ports $32..$35) */
    static const struct { char ch; u8 p, bit; } km[] = {
        {'Q',2,0},{'W',2,1},{'E',2,2},{'R',2,3},{'T',2,4},{'Y',2,5},{'U',2,6},{'I',2,7},
        {'A',3,0},{'S',3,1},{'D',3,2},{'F',3,3},{'G',3,4},{'H',3,5},{'J',3,6},{'K',3,7},
        {'Z',4,0},{'X',4,1},{'C',4,2},{'V',4,3},{'B',4,4},{'N',4,5},{'M',4,6},
        {'O',5,6},{'P',5,7},{'L',6,0},
    };
    for (u32 i = 0; i < sizeof(km) / sizeof(km[0]); i++)
        if ((u8)km[i].ch == c) { S.m5_ports[km[i].p] |= (u8)(1u << km[i].bit); return; }
}

static void cv_press_ascii(u8 c)
{
    if (c >= 'a' && c <= 'z') c = (u8)(c - 32u);
    if (c == ' ')  { S.cv_pb[1] &= (u8)~0x80u; return; } /* Fire 1 */
    if (c == '\r') { S.cv_pb[0] &= (u8)~0x80u; return; } /* Fire 2 */
    if (c == '1')  { S.cv_pb[0] &= (u8)~0x10u; return; }
    if (c == '2')  { S.cv_pb[1] &= (u8)~0x40u; return; }
    if (c == '3')  { S.cv_pb[1] &= (u8)~0x20u; return; }
    if (c == '4')  { S.cv_pb[1] &= (u8)~0x10u; return; }
}

void cvm5_typed(char c)
{
    u8 ch = (u8)c;
    if (ch == '\n') ch = '\r';
    u16 next = (u16)((S.type_tail + 1u) % sizeof(S.type_q));
    if (next != S.type_head) {
        S.type_q[S.type_tail] = (char)ch;
        S.type_tail = next;
    }
}

void cvm5_keyboard(const u8 *usages, int n)
{
    cm_zero(S.m5_ports, sizeof(S.m5_ports));
    for (int i = 0; i < 4; i++) S.cv_pb[i] = 0xFFu;

    for (int i = 0; i < n; i++) {
        u8 u = usages[i];
        if (u == 0xE0 || u == 0xE4) { S.m5_ports[0] |= 0x01u; S.cv_pb[1] &= (u8)~0x80u; } /* Ctrl -> Fire 1 */
        else if (u == 0xE1 || u == 0xE5) { S.m5_ports[0] |= 0x04u; S.cv_pb[0] &= (u8)~0x80u; } /* Shift -> Fire 2 */
        else if (u >= 0x04 && u <= 0x1D) {
            u8 ch = (u8)('A' + (u - 0x04));
            m5_press_ascii(ch); cv_press_ascii(ch);
        } else if (u >= 0x1E && u <= 0x26) {
            u8 ch = (u8)('1' + (u - 0x1E));
            m5_press_ascii(ch); cv_press_ascii(ch);
        } else if (u == 0x27) { m5_press_ascii('0'); }
        else if (u == 0x2C) { m5_press_ascii(' '); cv_press_ascii(' '); }
        else if (u == 0x28 || u == 0x58) { m5_press_ascii('\r'); cv_press_ascii('\r'); }
        else if (u == 0x4F) { S.m5_ports[7] |= 0x01u; S.cv_pb[0] &= (u8)~0x04u; } /* Right */
        else if (u == 0x52) { S.m5_ports[7] |= 0x02u; S.cv_pb[0] &= (u8)~0x08u; } /* Up */
        else if (u == 0x50) { S.m5_ports[7] |= 0x04u; S.cv_pb[0] &= (u8)~0x20u; } /* Left */
        else if (u == 0x51) { S.m5_ports[7] |= 0x08u; S.cv_pb[0] &= (u8)~0x02u; } /* Down */
        else if (u == 0x3B) { S.nmi_pend = 1; } /* F2 -> CreatiVision Reset/Select NMI */
    }
    cm_copy(S.usb_m5_ports, S.m5_ports, sizeof(S.usb_m5_ports));
    cm_copy(S.usb_cv_pb, S.cv_pb, sizeof(S.usb_cv_pb));
}

/* ---- Reset, Cartridge Loaders & Frame Execution ---- */
void cvm5_reset(void)
{
    cm_zero(WS->ram, sizeof(WS->ram));
    cm_zero(WS->vram, sizeof(WS->vram));
    cm_zero(S.vdp_reg, sizeof(S.vdp_reg));
    S.vdp_addr = 0;
    S.vdp_first = S.vdp_latch = S.vdp_buf = S.vdp_status = S.vdp_int_prev = 0;

    cm_zero(&S.sn, sizeof(S.sn));
    S.sn.atten[0] = S.sn.atten[1] = S.sn.atten[2] = S.sn.atten[3] = 0x0Fu;
    S.sn.lfsr = 0x4000u;
    S.snd_last_cyc = 0;

    for (int i = 0; i < 4; i++) S.usb_cv_pb[i] = S.cv_pb[i] = 0xFFu;
    cm_zero(S.usb_m5_ports, sizeof(S.usb_m5_ports));
    cm_zero(S.m5_ports, sizeof(S.m5_ports));

    if (!S.is_m5) {
        S.pia_ora = S.pia_ddra = S.pia_cra = 0;
        S.pia_orb = S.pia_ddrb = S.pia_crb = 0;
        S.a = S.x = S.y = 0;
        S.sp = 0xFDu;
        S.p = FI | FU;
        S.jam = S.nmi_pend = 0;
        S.cv_cyc = 0;
        S.pc = (u16)WS->bios[0x07FCu] | ((u16)WS->bios[0x07FDu] << 8);
    } else {
        cm_zero(S.ctc, sizeof(S.ctc));
        S.ctc_vec = 0;
        S.ctc_irq_pend = 0;
        z80_init(&S.zcpu);
        z80_reset(&S.zcpu);
        S.zcpu.read = m5_z80_read;
        S.zcpu.write = m5_z80_write;
        S.zcpu.in = m5_z80_in;
        S.zcpu.out = m5_z80_out;
        S.zcpu.irq_ack = m5_irq_ack;
        for (int i = 0; i < 64; i++) {
            S.zcpu.rd[i] = WS->open_bus;
            S.zcpu.wr[i] = 0;
        }
        /* $0000..$1FFF: 8 KB Monitor BIOS */
        for (int i = 0; i < 8; i++)
            S.zcpu.rd[i] = WS->bios + i * 0x400;
        /* $2000..$6FFF: Cartridge ROM (up to 20 KB) */
        u32 cart_pages = (S.cart_size + 0x3FFu) >> 10;
        if (cart_pages > 20u) cart_pages = 20u;
        for (u32 i = 0; i < cart_pages; i++)
            S.zcpu.rd[8 + i] = WS->cart + i * 0x400u;
        /* $7000..$FFFF: 4 KB internal RAM + 32 KB EM-5 RAM */
        for (int i = 28; i < 64; i++) {
            S.zcpu.rd[i] = WS->ram + i * 0x400;
            S.zcpu.wr[i] = WS->ram + i * 0x400;
        }
    }
}

static int valid_cv_vec(const u8 *hdr16)
{
    u8 entry_hi = hdr16[0x09];          /* $BFE9 */
    u8 irq_hi   = hdr16[0x1F];          /* $BFFF */
    return (entry_hi >= 0x40u && entry_hi < 0xC0u) &&
           ((irq_hi >= 0x40u && irq_hi < 0xC0u) || irq_hi >= 0xF8u);
}

const char *cv_load(const u8 *ext_bios2k, const u8 *cart, u32 cart_size)
{
    if (!cart || cart_size < 0x1000u || cart_size > 0x8000u)
        return "CreatiVision cartridge must be 4 KB .. 32 KB";

    cm_zero(&S, sizeof(S));
    for (u32 i = 0; i < sizeof(WS->cart); i++) WS->cart[i] = 0xFFu;
    tms_init_palette();

    S.is_m5 = 0;
    S.cart_size = cart_size;
    if (ext_bios2k) {
        S.ext_bios = 1;
        cm_copy(WS->bios, ext_bios2k, 0x0800u);
    } else {
        S.ext_bios = 0;
        build_cv_bios();
    }

    /* Map CreatiVision cartridge into $4000..$BFFF (WS->cart[0x0000..0x7FFF]) */
    if (cart_size == 0x1000u) {         /* 4 KB mirrored across $8000..$BFFF */
        for (int m = 0; m < 4; m++) cm_copy(WS->cart + 0x4000u + m * 0x1000u, cart, 0x1000u);
    } else if (cart_size == 0x1800u) {  /* 6 KB: 4K at $8000..$9FFF + 2K mirrored at $A000..$BFFF */
        cm_copy(WS->cart + 0x4000u, cart, 0x1000u);
        cm_copy(WS->cart + 0x6000u, cart + 0x1000u, 0x0800u);
        cm_copy(WS->cart + 0x6800u, cart + 0x1000u, 0x0800u);
        cm_copy(WS->cart + 0x7000u, cart + 0x1000u, 0x0800u);
        cm_copy(WS->cart + 0x7800u, cart + 0x1000u, 0x0800u);
    } else if (cart_size == 0x2000u) {  /* 8 KB mirrored across $8000..$BFFF */
        cm_copy(WS->cart + 0x4000u, cart, 0x2000u);
        cm_copy(WS->cart + 0x6000u, cart, 0x2000u);
    } else if (cart_size == 0x2800u) {  /* 10 KB: 8K at $A000..$BFFF + 2K mirrored at $4000..$7FFF */
        cm_copy(WS->cart + 0x6000u, cart, 0x2000u);
        for (int m = 0; m < 8; m++) cm_copy(WS->cart + m * 0x0800u, cart + 0x2000u, 0x0800u);
    } else if (cart_size == 0x3000u) {  /* 12 KB: check whether vectors are at end (linear) or +0x1FE0 (MAME 8K+4K) */
        if (valid_cv_vec(cart + 0x2FE0u)) {
            cm_copy(WS->cart + 0x4000u, cart, 0x1000u);
            cm_copy(WS->cart + 0x5000u, cart, 0x1000u);
            cm_copy(WS->cart + 0x6000u, cart + 0x1000u, 0x2000u);
        } else {
            cm_copy(WS->cart + 0x6000u, cart, 0x2000u);
            cm_copy(WS->cart + 0x4000u, cart + 0x2000u, 0x1000u);
            cm_copy(WS->cart + 0x5000u, cart + 0x2000u, 0x1000u);
        }
    } else if (cart_size == 0x4000u) {  /* 16 KB: linear $8000..$BFFF vs MAME swapped 8K+8K */
        if (valid_cv_vec(cart + 0x3FE0u) || !valid_cv_vec(cart + 0x1FE0u)) {
            cm_copy(WS->cart + 0x4000u, cart, 0x4000u);
        } else {
            cm_copy(WS->cart + 0x6000u, cart, 0x2000u);
            cm_copy(WS->cart + 0x4000u, cart + 0x2000u, 0x2000u);
        }
    } else if (cart_size == 0x4800u) {  /* 18 KB */
        cm_copy(WS->cart + 0x4000u, cart, 0x4000u);
        for (int m = 0; m < 8; m++) cm_copy(WS->cart + m * 0x0800u, cart + 0x4000u, 0x0800u);
    } else if (cart_size == 0x8000u) {  /* 32 KB: linear $4000..$BFFF vs swapped 16K+16K */
        if (valid_cv_vec(cart + 0x7FE0u) || !valid_cv_vec(cart + 0x3FE0u)) {
            cm_copy(WS->cart, cart, 0x8000u);
        } else {
            cm_copy(WS->cart + 0x4000u, cart, 0x4000u);
            cm_copy(WS->cart, cart + 0x4000u, 0x4000u);
        }
    } else {                            /* Other <= 32 KB sizes */
        u32 off = (cart_size <= 0x4000u) ? (0x8000u - cart_size) : 0u;
        cm_copy(WS->cart + off, cart, cart_size);
    }

    /* Ensure IRQ vector ($BFFE..$BFFF) is valid */
    if (WS->cart[0x7FFFu] < 0x40u) {
        WS->cart[0x7FFEu] = 0x14u;
        WS->cart[0x7FFFu] = 0xF8u;
    }

    char *p = S.info, *end = S.info + sizeof(S.info) - 1;
    put_s(&p, end, "VTech CreatiVision PAL");
    if (!S.ext_bios) put_s(&p, end, " (built-in BIOS)");
    put_s(&p, end, ", ");
    put_u(&p, end, (cart_size + 1023u) >> 10);
    put_s(&p, end, " KB");

    cvm5_reset();
    return 0;
}

const char *m5_load(const u8 *ext_bios8k, const u8 *cart, u32 cart_size)
{
    if (!cart || cart_size < 0x0800u || cart_size > 0x5000u)
        return "Sord M5 cartridge must be 2 KB .. 20 KB";

    cm_zero(&S, sizeof(S));
    for (u32 i = 0; i < sizeof(WS->open_bus); i++) WS->open_bus[i] = 0xFFu;
    for (u32 i = 0; i < sizeof(WS->cart); i++) WS->cart[i] = 0xFFu;
    tms_init_palette();

    S.is_m5 = 1;
    S.cart_size = cart_size;
    if (ext_bios8k) {
        S.ext_bios = 1;
        cm_copy(WS->bios, ext_bios8k, 0x2000u);
    } else {
        S.ext_bios = 0;
        build_m5_bios();
    }
    cm_copy(WS->cart, cart, cart_size);

    char *p = S.info, *end = S.info + sizeof(S.info) - 1;
    put_s(&p, end, "Sord M5 NTSC");
    if (!S.ext_bios) put_s(&p, end, " (built-in BIOS)");
    put_s(&p, end, ", ");
    put_u(&p, end, (cart_size + 1023u) >> 10);
    put_s(&p, end, " KB");

    cvm5_reset();
    return 0;
}

void cvm5_frame(u16 pad, u16 *picture)
{
    S.pad_state = pad;

    /* Rebuild input state from USB keyboard + typed queue + gamepad */
    cm_copy(S.m5_ports, S.usb_m5_ports, sizeof(S.m5_ports));
    cm_copy(S.cv_pb, S.usb_cv_pb, sizeof(S.cv_pb));

    if (S.type_hold > 0) {
        S.type_hold--;
        if (S.type_hold >= 1u) {
            m5_press_ascii(S.type_ch);
            cv_press_ascii(S.type_ch);
        }
    } else if (S.type_head != S.type_tail) {
        S.type_ch = (u8)S.type_q[S.type_head];
        S.type_head = (u16)((S.type_head + 1u) % sizeof(S.type_q));
        S.type_hold = 3u;
        m5_press_ascii(S.type_ch);
        cv_press_ascii(S.type_ch);
    }

    if (pad) {
        /* CreatiVision Left Hand Joystick + Buttons (active-low on PA0/PA1 -> PB) */
        if (pad & 0x20u) S.cv_pb[0] &= (u8)~0x02u;      /* Down */
        if (pad & 0x80u) S.cv_pb[0] &= (u8)~0x04u;      /* Right */
        if (pad & 0x10u) S.cv_pb[0] &= (u8)~0x08u;      /* Up */
        if (pad & 0x40u) S.cv_pb[0] &= (u8)~0x20u;      /* Left */
        if (pad & 0x02u) S.cv_pb[0] &= (u8)~0x80u;      /* B -> Button 1 (Fire 2) */
        if (pad & 0x09u) S.cv_pb[1] &= (u8)~0x80u;      /* A / Start -> Button 0 (Fire 1) */
        if (pad & 0x04u) S.cv_pb[0] &= (u8)~0x10u;      /* Select -> Key '1' */

        /* Sord M5 Joy 1 ($37 active-high) + Fire 1/2 ($30 Ctrl/Space/Shift + $31 '1'/'2') */
        if (pad & 0x80u) S.m5_ports[7] |= 0x01u;        /* Right */
        if (pad & 0x10u) S.m5_ports[7] |= 0x02u;        /* Up */
        if (pad & 0x40u) S.m5_ports[7] |= 0x04u;        /* Left */
        if (pad & 0x20u) S.m5_ports[7] |= 0x08u;        /* Down */
        if (pad & 0x09u) S.m5_ports[0] |= 0x41u;        /* A / Start -> Space + Ctrl (Button 0) */
        if (pad & 0x02u) S.m5_ports[0] |= 0x04u;        /* B -> Shift (Button 1) */
        if (pad & 0x04u) S.m5_ports[1] |= 0x01u;        /* Select -> Key '1' */
    }

    if (!S.is_m5) {
        S.cv_cyc = 0;
        S.snd_last_cyc = 0;
        u32 target = 0;
        for (u32 line = 0; line < CV_LINES; line++) {
            if (line < CVM5_H)
                render_tms_line((int)line, picture ? (picture + line * CVM5_W) : 0);
            if (line == CVM5_H) {
                S.vdp_status |= 0x80u;
                vdp_update_int();
            }
            target += CV_CYC_LINE;
            while (S.cv_cyc < target)
                cv_cpu_step();
        }
        audio_catch_up();
    } else {
        S.zcpu.cycles = 0;
        S.snd_last_cyc = 0;
        s32 target = 0;
        for (u32 line = 0; line < M5_LINES; line++) {
            if (line < CVM5_H)
                render_tms_line((int)line, picture ? (picture + line * CVM5_W) : 0);
            if (line == CVM5_H) {
                S.vdp_status |= 0x80u;
                vdp_update_int();
            }
            s32 prev_c = S.zcpu.cycles;
            target += (s32)M5_CYC_LINE;
            z80_run(&S.zcpu, target);
            if (S.zcpu.cycles > prev_c)
                ctc_step_timers((u32)(S.zcpu.cycles - prev_c));
        }
        audio_catch_up();
        S.zcpu.cycles -= (s32)(M5_LINES * M5_CYC_LINE);
    }
}

int cvm5_width(void)  { return CVM5_W; }
int cvm5_height(void) { return CVM5_H; }
const char *cvm5_info(void) { return S.info; }
int cvm5_jammed(void) { return S.is_m5 ? 0 : S.jam; }

void cvm5_audio_rate(u32 hz)
{
    S.snd_hz = (hz >= 8000u && hz <= 192000u) ? hz : 0;
    S.snd_frac = 0;
    S.snd_head = S.snd_count = 0;
    S.snd_last_cyc = 0;
}

int cvm5_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && S.snd_count) {
        out[n++] = WS->snd_ring[S.snd_head];
        S.snd_head = (S.snd_head + 1u) % CVM5_RING_LEN;
        S.snd_count--;
    }
    return n;
}
