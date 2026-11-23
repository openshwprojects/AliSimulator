/* Sega 32X ("Project Mars") Add-On Emulator: see s32x.h.
   Pass-optimized for 594 MHz MIPS32:
   - Zero static .bss (all workspaces in KSEG0(EMU_RAM_PHYS))
   - Zero float/double & zero 64-bit libgcc division (custom 32-bit shift-subtract 64/32 divider)
   - Shared host-u16 big-endian word layout with md.c (1-load SH-2 opcode fetch & zero-copy 68k rmap)
   - Master/Slave SH-2 COMM & VBlank spin-loop fast-forwarding with instant COMM write wakeup */
/* -Os keeps sh2_exec_one + md.c resident in S3811 32 KB L1 I-cache */
#include "s32x.h"
#include "md.h"

#ifndef S32X_HOST
#include "hw.h"
#endif

#define SH2_T   0x00000001u
#define SH2_S   0x00000002u
#define SH2_Q   0x00000100u
#define SH2_M   0x00000200u

struct sh2_dma {
    u32 sar, dar, tcr, chcr;
};

struct sh2_cpu {
    u32 r[16];
    u32 pc, pr, sr, gbr, vbr, mach, macl;
    u32 poll_pc;
    s32 cycles, target;
    u8  id;                             /* 0 = Master, 1 = Slave */
    u8  in_delay;
    u8  sleep;
    u8  irq_mask;                       /* bit0=PWM(6), bit1=CMD(8), bit2=HINT(10), bit3=VINT(12) */
    u8  irq_pend;                       /* same bits + bit4=VRES(14) */

    /* SH7604 on-chip Hardware Divider ($FFFFFF00..$FFFFFF1F) */
    s32 dvsr;
    u32 dvdnth, dvdntl;

    /* SH7604 2-ch DMAC ($FFFFFF80..$FFFFFFB3) */
    struct sh2_dma dma[2];
    u32 dmaor;
    u16 vcrdma[2];

    /* SH7604 FRT / WDT / INTC */
    u16 ipra, iprb, vcra, vcrb, vcrc, vcrd, vcrwdt, tier_ftcsr;
    u16 frc, ocra, ocrb, icr;
    u8  wtcsr, wtcNT;

    /* 4 KB On-Chip Cache / Two-Way Scratchpad RAM ($C0000000..$C0000FFF) */
    u16 cram_chip[0x800];
};

#define DREQ_FIFO_CAP 16
#define PWM_RING_CAP  2048

struct s32x_ws {
    struct sh2_cpu sh[2];               /* 0 = Master SH-2, 1 = Slave SH-2 */

    u16 sdram[0x20000];                 /* 256 KB SDRAM ($06000000..$0603FFFF, host u16 words) */
    u16 dram[2][0x10000];               /* 2 x 128 KB SuperVDP Framebuffers (host u16 words) */
    u16 cram[256];                      /* 256 x 16-bit SuperVDP Palette ($A15200 / $20004200) */
    u16 boot_m[0x4000];                 /* Master SH-2 Boot ROM (up to 32 KB, host u16) */
    u16 boot_s[0x2000];                 /* Slave SH-2 Boot ROM (up to 16 KB, host u16) */
    u16 vec68k[0x80];                   /* 256 B 68000 Vector Overlay ROM ($000000..$0000FF) */

    u16 *rom;                           /* Cartridge ROM in MEDIA_PHYS (host u16 words) */
    u32 rom_bytes, rom_mask;
    u16 *main_ram;                      /* Pointer to md.c's 64 KB main RAM */

    /* 32X System & Adapter Registers */
    u8  aden, fm, ren;                  /* $A15100 ADEN (b0), FM (b15), REN (b7) */
    u8  rv;                             /* $A15106 bit 0: 1 = Cart at $000000, 0 = Vector ROM */
    u8  bank90;                         /* $A15104 bits 0..1: 1 MB bank at $900000..$9FFFFF */
    u8  hen;                            /* $A15102 / $20004000 bit 7: H-Int in VBlank */
    u8  hcount_reload;                  /* $A15105 / $20004005 */
    s32 hcount_cur;

    u16 comm[8];                        /* $A15120..$A1512F / $20004020..$2000402F */

    /* 68000 -> SH-2 DREQ FIFO ($A15106..$A15112) */
    u16 dreq_ctl;
    u32 dreq_src, dreq_dst;
    u16 dreq_len;
    u16 fifo[DREQ_FIFO_CAP];
    u8  fifo_r, fifo_w, fifo_n;

    /* SuperVDP Registers ($A15180..$A1518A) */
    u16 vdp_mode;                       /* bits 0..1: 0=off, 1=Packed, 2=Direct15, 3=RLE; b6=240; b7=PRI */
    u16 vdp_shift;                      /* bit 0: 1-pixel left shift in Packed mode */
    u16 af_len, af_addr, af_data;
    u8  disp_fb, req_fb;                /* FS active vs requested framebuffer */
    u8  in_vblank, in_hblank, prev_line_front;
    u16 cur_y, cur_active_h;
    u8  pal_mode, overseas_mode;
    u8  ext_bios_g, ext_bios_m, ext_bios_s;
    u32 boot_m_bytes, boot_s_bytes;

    /* Stereo 12-bit PWM Audio ($A15130..$A15138) */
    u16 pwm_ctl, pwm_cycle;
    u16 pwm_l_fifo[4], pwm_r_fifo[4];
    u8  pwm_ln, pwm_rn;
    s32 pwm_cur_l, pwm_cur_r;
    s32 pwm_tmr_sh2;
    s16 pwm_ring[PWM_RING_CAP];
    u32 pwm_w, pwm_r, pwm_frac;

    s32 sh_synced_m68k;
    char title[96];
};

#ifdef S32X_HOST
static struct s32x_ws s32x_host_ws;
#define WS (&s32x_host_ws)
#else
#define WS ((struct s32x_ws *)KSEG0(EMU_RAM_PHYS))
#endif

#define INLINE static inline __attribute__((always_inline))

static void s32x_zero(void *p, u32 n)
{
    u8 *b = (u8 *)p;
    for (u32 i = 0; i < n; i++)
        b[i] = 0;
}

/* Pure 32-bit signed 64-by-32 division (avoids __divdi3 / __udivdi3 on freestanding MIPS32!) */
static s32 div64_32_signed(u32 hi, u32 lo, s32 dvsr, s32 *rem_out)
{
    if (dvsr == 0) {
        *rem_out = (s32)lo;
        return (hi & 0x80000000u) ? (s32)0x80000000u : 0x7FFFFFFF;
    }
    int neg_n = (hi & 0x80000000u) != 0;
    int neg_d = (dvsr < 0);
    u32 uhi = hi, ulo = lo;
    if (neg_n) {
        ulo = ~ulo + 1u;
        uhi = ~uhi + (ulo == 0u ? 1u : 0u);
    }
    u32 ud = neg_d ? (0u - (u32)dvsr) : (u32)dvsr;
    if (uhi >= ud) {
        *rem_out = 0;
        return (neg_n ^ neg_d) ? (s32)0x80000000u : 0x7FFFFFFF;
    }
    u32 rem = uhi, q = 0u;
    for (int i = 0; i < 32; i++) {
        u32 top = rem >> 31;
        rem = (rem << 1) | (ulo >> 31);
        ulo <<= 1;
        q <<= 1;
        if (top || rem >= ud) {
            rem -= ud;
            q |= 1u;
        }
    }
    if (q > 0x7FFFFFFFu && !(neg_n ^ neg_d))
        q = 0x7FFFFFFFu;
    *rem_out = neg_n ? -(s32)rem : (s32)rem;
    return (neg_n ^ neg_d) ? -(s32)q : (s32)q;
}

/* ---- Host-u16 Big-Endian Memory Helpers ---- */

INLINE u8 buf_rb(const u16 *w, u32 byte_off)
{
    return ((const u8 *)w)[byte_off ^ 1u];
}

INLINE void buf_wb(u16 *w, u32 byte_off, u8 v)
{
    ((u8 *)w)[byte_off ^ 1u] = v;
}

INLINE u16 buf_rw(const u16 *w, u32 byte_off)
{
    return w[byte_off >> 1];
}

INLINE void buf_ww(u16 *w, u32 byte_off, u16 v)
{
    w[byte_off >> 1] = v;
}

INLINE u32 buf_rl(const u16 *w, u32 byte_off)
{
    u32 idx = byte_off >> 1;
    return ((u32)w[idx] << 16) | w[idx + 1u];
}

INLINE void buf_wl(u16 *w, u32 byte_off, u32 v)
{
    u32 idx = byte_off >> 1;
    w[idx]      = (u16)(v >> 16);
    w[idx + 1u] = (u16)v;
}

/* ---- SuperVDP Auto-Fill & Register Writes ---- */

static void vdp_autofill(void)
{
    u16 *fb = WS->dram[WS->disp_fb ^ 1u];
    u32 len = (WS->af_len & 0xFFu) + 1u;
    u32 page = WS->af_addr & 0xFF00u;
    u32 idx  = WS->af_addr & 0x00FFu;
    u16 dat  = WS->af_data;
    for (u32 i = 0; i < len; i++) {
        fb[(page | idx) & 0xFFFFu] = dat;
        idx = (idx + 1u) & 0xFFu;
    }
    WS->af_addr = (u16)(page | idx);
}

static u16 vdp_stat_read(void)
{
    u16 st = (u16)(WS->pal_mode ? 0x0000u : 0x8000u);   /* b15 = PAL(0) / NTSC(1) in $A15180, wait:
       In $A1518A (Framebuffer Control):
       b15 = VBLK, b14 = HBLK, b13 = PEN, b1 = FEN(0), b0 = FS! */
    (void)st;
    u16 r = WS->disp_fb & 1u;
    if (WS->in_vblank || (WS->vdp_mode & 3u) == 0u)
        r |= 0xA000u;                                   /* VBLK=1, PEN=1 */
    if (WS->in_hblank)
        r |= 0x6000u;                                   /* HBLK=1, PEN=1 */
    return r;
}

static u16 vdp_reg_read(u32 off)
{
    switch (off & 0x0Eu) {
    case 0x00: return (u16)((WS->pal_mode ? 0x0000u : 0x8000u) | (WS->vdp_mode & 0x00C3u));
    case 0x02: return WS->vdp_shift & 1u;
    case 0x04: return WS->af_len & 0xFFu;
    case 0x06: return WS->af_addr;
    case 0x08: return WS->af_data;
    case 0x0A: return vdp_stat_read();
    }
    return 0;
}

static void vdp_reg_write16(u32 off, u16 v)
{
    switch (off & 0x0Eu) {
    case 0x00: WS->vdp_mode = v & 0x00C3u; break;
    case 0x02: WS->vdp_shift = v & 1u; break;
    case 0x04: WS->af_len = v & 0xFFu; break;
    case 0x06: WS->af_addr = v; break;
    case 0x08: WS->af_data = v; vdp_autofill(); break;
    case 0x0A:
        WS->req_fb = v & 1u;
        if (WS->in_vblank || (WS->vdp_mode & 3u) == 0u)
            WS->disp_fb = WS->req_fb;
        break;
    }
}

static void vdp_reg_write8(u32 off, u8 v)
{
    if (off == 0x01u) WS->vdp_mode = v & 0xC3u;
    else if (off == 0x03u) WS->vdp_shift = v & 1u;
    else if (off == 0x05u) WS->af_len = v;
    else if (off == 0x0Bu) {
        WS->req_fb = v & 1u;
        if (WS->in_vblank || (WS->vdp_mode & 3u) == 0u)
            WS->disp_fb = WS->req_fb;
    }
}

/* ---- PWM Audio Write Helpers ---- */

static void pwm_push_l(u16 v)
{
    v &= 0x0FFFu;
    if (WS->pwm_ln < 3) WS->pwm_l_fifo[WS->pwm_ln++] = v;
    else                WS->pwm_l_fifo[2] = v;
    WS->pwm_cur_l = (s32)v;
}

static void pwm_push_r(u16 v)
{
    v &= 0x0FFFu;
    if (WS->pwm_rn < 3) WS->pwm_r_fifo[WS->pwm_rn++] = v;
    else                WS->pwm_r_fifo[2] = v;
    WS->pwm_cur_r = (s32)v;
}

static u16 pwm_reg_read(u32 off)
{
    switch (off & 0x0Eu) {
    case 0x00: return WS->pwm_ctl;
    case 0x02: return WS->pwm_cycle;
    case 0x04: return (WS->pwm_ln == 0 ? 0x4000u : (WS->pwm_ln >= 3 ? 0x8000u : 0u));
    case 0x06: return (WS->pwm_rn == 0 ? 0x4000u : (WS->pwm_rn >= 3 ? 0x8000u : 0u));
    case 0x08: return (WS->pwm_ln == 0 ? 0x4000u : (WS->pwm_ln >= 3 ? 0x8000u : 0u));
    }
    return 0;
}

static void pwm_reg_write(u32 off, u16 v)
{
    switch (off & 0x0Eu) {
    case 0x00: WS->pwm_ctl = v & 0x0F8Fu; break;
    case 0x02: WS->pwm_cycle = v & 0x0FFFu; break;
    case 0x04: pwm_push_l(v); break;
    case 0x06: pwm_push_r(v); break;
    case 0x08: pwm_push_l(v); pwm_push_r(v); break;
    }
}

/* ---- SH-2 Interrupt & DREQ DMA Engine ---- */

static void sh2_check_dma_fifo(struct sh2_cpu *c);

static void sh2_wake_comm(int writer_id)
{
    if (writer_id < 0) {
        WS->sh[0].sleep = 0; WS->sh[0].poll_pc = 0;
        WS->sh[1].sleep = 0; WS->sh[1].poll_pc = 0;
        return;
    }
    int other = writer_id ^ 1;
    struct sh2_cpu *o = &WS->sh[other];
    o->sleep = 0;
    o->poll_pc = 0;
    s32 cur = WS->sh[writer_id].cycles;
    if (o->cycles > cur)
        o->cycles = cur;
}

/* ---- SH-2 Memory Bus (32-bit addresses) ---- */

static u32 sh2_sys_read16(struct sh2_cpu *c, u32 off)
{
    if (off >= 0x200u && off < 0x400u)
        return WS->cram[(off - 0x200u) >> 1];
    if (off >= 0x100u && off < 0x110u) {
        if ((off & 0x0Eu) == 0x0Au) {
            if (c->poll_pc == c->pc && c->cycles < c->target) c->cycles = c->target;
            else c->poll_pc = c->pc;
        }
        return vdp_reg_read(off - 0x100u);
    }
    if (off >= 0x030u && off < 0x040u) {
        u16 pr = pwm_reg_read(off - 0x030u);
        if ((pr & 0x8000u) && (off & 0x0Eu) >= 0x04u) {
            if (c->poll_pc == c->pc && c->cycles < c->target) c->cycles = c->target;
            else c->poll_pc = c->pc;
        }
        return pr;
    }
    if (off >= 0x020u && off < 0x030u) {
        if (c->poll_pc == c->pc && c->cycles < c->target) c->cycles = c->target;
        else c->poll_pc = c->pc;
        return WS->comm[(off - 0x020u) >> 1];
    }

    switch (off & 0x3FEu) {
    case 0x000:
        return (u16)((WS->fm << 15) | (WS->aden ? 0x0200u : 0u) | (WS->hen << 7) | (c->irq_mask & 0x0Fu));
    case 0x002: return 0;
    case 0x004: return WS->hcount_reload;
    case 0x006:
        return (u16)((WS->dreq_ctl & 0x0007u) |
                     (WS->fifo_n >= DREQ_FIFO_CAP ? 0x8000u : 0u) |
                     (WS->fifo_n == 0 ? 0x4000u : 0u));
    case 0x008: return (u16)(WS->dreq_src >> 16);
    case 0x00A: return (u16)WS->dreq_src;
    case 0x00C: return (u16)(WS->dreq_dst >> 16);
    case 0x00E: return (u16)WS->dreq_dst;
    case 0x010: return WS->dreq_len;
    case 0x012: {
        if (WS->fifo_n == 0) return 0;
        u16 val = WS->fifo[WS->fifo_r];
        WS->fifo_r = (WS->fifo_r + 1u) & (DREQ_FIFO_CAP - 1u);
        WS->fifo_n--;
        return val;
    }
    }
    return 0;
}

static void sh2_sys_write16(struct sh2_cpu *c, u32 off, u16 v)
{
    if (off >= 0x200u && off < 0x400u) {
        WS->cram[(off - 0x200u) >> 1] = v;
        return;
    }
    if (off >= 0x100u && off < 0x110u) {
        vdp_reg_write16(off - 0x100u, v);
        return;
    }
    if (off >= 0x030u && off < 0x040u) {
        pwm_reg_write(off - 0x030u, v);
        return;
    }
    if (off >= 0x020u && off < 0x030u) {
        u32 wi = (off - 0x020u) >> 1;
        if (WS->comm[wi] != v) {
            WS->comm[wi] = v;
            sh2_wake_comm(c->id);
        }
        return;
    }
    switch (off & 0x3FEu) {
    case 0x000:
        WS->fm = (u8)((v >> 15) & 1u);
        WS->hen = (u8)((v >> 7) & 1u);
        c->irq_mask = (u8)(v & 0x0Fu);
        break;
    case 0x002: c->irq_pend &= (u8)~0x02u; break;       /* Standby / CMD clear */
    case 0x004: WS->hcount_reload = (u8)v; break;
    case 0x014: c->irq_pend &= (u8)~0x10u; break;       /* VRES clear */
    case 0x016: c->irq_pend &= (u8)~0x08u; break;       /* VINT clear */
    case 0x018: c->irq_pend &= (u8)~0x04u; break;       /* HINT clear */
    case 0x01A: c->irq_pend &= (u8)~0x02u; break;       /* CMD clear */
    case 0x01C: c->irq_pend &= (u8)~0x01u; break;       /* PWM clear */
    }
}

/* SH7604 On-Chip Peripheral Space ($FFFFFE00..$FFFFFFFF) */
static u32 sh2_onchip_read(struct sh2_cpu *c, u32 a, int sz)
{
    u32 r = a & 0x1FFu;
    if (r >= 0x100u && r < 0x120u) {                    /* Hardware Divider */
        u32 dr = r & 0x1Cu;
        if (dr == 0x00u) return (u32)c->dvsr;
        if (dr == 0x04u || dr == 0x14u || dr == 0x1Cu) return c->dvdntl;
        if (dr == 0x10u || dr == 0x18u) return c->dvdnth;
        return 0;
    }
    if (r >= 0x180u && r < 0x1C0u) {                    /* 2-ch DMAC */
        if (r == 0x1B0u) return c->dmaor;
        int ch = (r >= 0x190u) ? 1 : 0;
        u32 cr = r & 0x0Fu;
        if (cr == 0x00u) return c->dma[ch].sar;
        if (cr == 0x04u) return c->dma[ch].dar;
        if (cr == 0x08u) return c->dma[ch].tcr;
        if (cr == 0x0Cu) return c->dma[ch].chcr;
        return 0;
    }
    if (r == 0x12u || r == 0x13u) return (sz == 1) ? ((r & 1u) ? c->frc & 0xFFu : c->frc >> 8) : c->frc;
    if (r == 0x60u) return c->iprb;
    if (r == 0xE2u) return c->ipra;
    if (r == 0x80u) return c->wtcsr;
    return 0;
}

static __attribute__((noinline)) u8  sh2_rb(struct sh2_cpu *c, u32 a);
static __attribute__((noinline)) u16 sh2_rw(struct sh2_cpu *c, u32 a);
static __attribute__((noinline)) u32 sh2_rl(struct sh2_cpu *c, u32 a);
static __attribute__((noinline)) void sh2_wb(struct sh2_cpu *c, u32 a, u8 v);
static __attribute__((noinline)) void sh2_ww(struct sh2_cpu *c, u32 a, u16 v);
static __attribute__((noinline)) void sh2_wl(struct sh2_cpu *c, u32 a, u32 v);

static void sh2_run_dma_now(struct sh2_cpu *c, int ch)
{
    struct sh2_dma *d = &c->dma[ch];
    if (!(c->dmaor & 1u) || !(d->chcr & 1u) || (d->chcr & 2u))
        return;
    /* Check if this is DREQ FIFO mode (auto_req bit 9 == 0 and SAR in $20004012) */
    if (!(d->chcr & 0x200u) && (d->sar & 0x1FFFFFFFu) == 0x00004012u) {
        sh2_check_dma_fifo(c);
        return;
    }
    u32 sz_code = (d->chcr >> 10) & 3u;
    u32 step = (sz_code == 0u) ? 1u : (sz_code == 1u) ? 2u : (sz_code == 2u) ? 4u : 16u;
    u32 sm = (d->chcr >> 12) & 3u;
    u32 dm = (d->chcr >> 14) & 3u;
    u32 cnt = d->tcr & 0xFFFFFFu;
    if (!cnt) cnt = 0x1000000u;
    if (cnt > 0x40000u) cnt = 0x40000u;

    while (cnt > 0u) {
        if (sz_code == 0u) {
            sh2_wb(c, d->dar, sh2_rb(c, d->sar));
        } else if (sz_code == 1u) {
            sh2_ww(c, d->dar, sh2_rw(c, d->sar));
        } else if (sz_code == 2u) {
            sh2_wl(c, d->dar, sh2_rl(c, d->sar));
        } else {
            for (int k = 0; k < 4; k++) {
                u32 v = sh2_rl(c, d->sar);
                if (sm == 1u) d->sar += 4u; else if (sm == 2u) d->sar -= 4u;
                sh2_wl(c, d->dar, v);
                if (dm == 1u) d->dar += 4u; else if (dm == 2u) d->dar -= 4u;
                if (cnt > 0u) cnt--;
            }
            continue;
        }
        if (sm == 1u) d->sar += step; else if (sm == 2u) d->sar -= step;
        if (dm == 1u) d->dar += step; else if (dm == 2u) d->dar -= step;
        cnt--;
    }
    d->tcr = 0;
    d->chcr |= 2u;                                      /* TE = 1 */
}

static void sh2_check_dma_fifo(struct sh2_cpu *c)
{
    for (int ch = 0; ch < 2; ch++) {
        struct sh2_dma *d = &c->dma[ch];
        if (!(c->dmaor & 1u) || !(d->chcr & 1u) || (d->chcr & 2u))
            continue;
        if ((d->sar & 0x1FFFFFFFu) != 0x00004012u)
            continue;
        u32 dm = (d->chcr >> 14) & 3u;
        while (WS->fifo_n > 0u && d->tcr > 0u) {
            u16 w = WS->fifo[WS->fifo_r];
            WS->fifo_r = (WS->fifo_r + 1u) & (DREQ_FIFO_CAP - 1u);
            WS->fifo_n--;
            if (((d->chcr >> 10) & 3u) >= 2u && WS->fifo_n > 0u) {
                u16 w2 = WS->fifo[WS->fifo_r];
                WS->fifo_r = (WS->fifo_r + 1u) & (DREQ_FIFO_CAP - 1u);
                WS->fifo_n--;
                sh2_wl(c, d->dar, ((u32)w << 16) | w2);
                if (dm == 1u) d->dar += 4u; else if (dm == 2u) d->dar -= 4u;
            } else {
                sh2_ww(c, d->dar, w);
                if (dm == 1u) d->dar += 2u; else if (dm == 2u) d->dar -= 2u;
            }
            d->tcr--;
            if (d->tcr == 0u) {
                d->chcr |= 2u;
                break;
            }
        }
    }
}

static void sh2_onchip_write(struct sh2_cpu *c, u32 a, u32 v, int sz)
{
    u32 r = a & 0x1FFu;
    if (r >= 0x100u && r < 0x120u) {                    /* Hardware Divider */
        u32 dr = r & 0x1Cu;
        if (dr == 0x00u) {
            c->dvsr = (s32)v;
        } else if (dr == 0x04u) {                       /* 32 / 32 signed */
            s32 num = (s32)v;
            u32 hi = (num < 0) ? 0xFFFFFFFFu : 0u;
            s32 rem = 0;
            c->dvdntl = (u32)div64_32_signed(hi, (u32)num, c->dvsr, &rem);
            c->dvdnth = (u32)rem;
        } else if (dr == 0x10u) {
            c->dvdnth = v;
        } else if (dr == 0x14u) {                       /* 64 / 32 signed */
            s32 rem = 0;
            c->dvdntl = (u32)div64_32_signed(c->dvdnth, v, c->dvsr, &rem);
            c->dvdnth = (u32)rem;
        }
        return;
    }
    if (r >= 0x180u && r < 0x1C0u) {
        if (r == 0x1B0u) {
            c->dmaor = v & 0x0Fu;
            sh2_run_dma_now(c, 0);
            sh2_run_dma_now(c, 1);
            return;
        }
        int ch = (r >= 0x190u) ? 1 : 0;
        u32 cr = r & 0x0Fu;
        if (cr == 0x00u) c->dma[ch].sar = v;
        else if (cr == 0x04u) c->dma[ch].dar = v;
        else if (cr == 0x08u) c->dma[ch].tcr = v & 0xFFFFFFu;
        else if (cr == 0x0Cu) {
            c->dma[ch].chcr = v;
            sh2_run_dma_now(c, ch);
        }
        return;
    }
    if (r == 0x60u) c->iprb = (u16)v;
    else if (r == 0xE2u) c->ipra = (u16)v;
    else if (r == 0x62u) c->vcra = (u16)v;
    else if (r == 0x64u) c->vcrb = (u16)v;
    else if (r == 0x66u) c->vcrc = (u16)v;
    else if (r == 0x68u) c->vcrd = (u16)v;
    else if (r == 0xA0u) c->vcrdma[0] = (u16)v;
    else if (r == 0xA8u) c->vcrdma[1] = (u16)v;
    (void)sz;
}

/* Fast SH-2 Memory Accesses */

static u8 sh2_rb(struct sh2_cpu *c, u32 a)
{
    if (a >= 0xFFFFFE00u) return (u8)sh2_onchip_read(c, a, 1);
    if ((a >> 28) == 0xCu) return buf_rb(c->cram_chip, a & 0xFFFu);
    u32 phys = a & 0x07FFFFFFu;
    if (phys >= 0x06000000u) {
        if (a & 0x20000000u) c->cycles += 2;
        return buf_rb(WS->sdram, phys & 0x3FFFFu);
    }
    if (phys >= 0x04000000u) { c->cycles += 5; return buf_rb(WS->dram[WS->disp_fb ^ 1u], phys & 0x1FFFFu); }
    if (phys >= 0x02000000u) {
        c->cycles += 4;
        u32 off = phys - 0x02000000u;
        return (off < WS->rom_bytes) ? buf_rb(WS->rom, off) : 0xFFu;
    }
    if (phys >= 0x00004000u && phys < 0x00004400u) {
        c->cycles += 3;
        u16 w = (u16)sh2_sys_read16(c, (phys - 0x00004000u) & ~1u);
        return (a & 1u) ? (u8)w : (u8)(w >> 8);
    }
    return buf_rb(c->id ? WS->boot_s : WS->boot_m, phys & (c->id ? 0x3FFFu : 0x7FFFu));
}

static u16 sh2_rw(struct sh2_cpu *c, u32 a)
{
    a &= ~1u;
    u32 phys = a & 0x07FFFFFFu;
    if ((a >> 29) <= 1u) {
        if (phys >= 0x06000000u) {
            if (a & 0x20000000u) c->cycles += 2;
            return WS->sdram[(phys & 0x3FFFFu) >> 1];
        }
        if (phys >= 0x04000000u) { c->cycles += 5; return WS->dram[WS->disp_fb ^ 1u][(phys & 0x1FFFFu) >> 1]; }
        if (phys >= 0x02000000u) {
            c->cycles += 4;
            u32 off = phys - 0x02000000u;
            return (off < WS->rom_bytes) ? WS->rom[off >> 1] : 0xFFFFu;
        }
        if (phys >= 0x00004000u && phys < 0x00004400u) {
            c->cycles += 3;
            return (u16)sh2_sys_read16(c, phys - 0x00004000u);
        }
        return (c->id ? WS->boot_s : WS->boot_m)[(phys & (c->id ? 0x3FFFu : 0x7FFFu)) >> 1];
    }
    if ((a >> 28) == 0xCu) return c->cram_chip[(a & 0xFFFu) >> 1];
    if (a >= 0xFFFFFE00u) return (u16)sh2_onchip_read(c, a, 2);
    return 0;
}

static u32 sh2_rl(struct sh2_cpu *c, u32 a)
{
    a &= ~3u;
    if (a >= 0xFFFFFE00u) return sh2_onchip_read(c, a, 4);
    if ((a >> 28) == 0xCu) return buf_rl(c->cram_chip, a & 0xFFFu);
    u32 phys = a & 0x07FFFFFFu;
    if (phys >= 0x06000000u) {
        if (a & 0x20000000u) c->cycles += 4;
        return buf_rl(WS->sdram, phys & 0x3FFFFu);
    }
    if (phys >= 0x04000000u) { c->cycles += 8; return buf_rl(WS->dram[WS->disp_fb ^ 1u], phys & 0x1FFFFu); }
    if (phys >= 0x02000000u) {
        c->cycles += 8;
        u32 off = phys - 0x02000000u;
        return (off + 3u < WS->rom_bytes) ? buf_rl(WS->rom, off) : 0xFFFFFFFFu;
    }
    u32 hi = sh2_rw(c, a);
    u32 lo = sh2_rw(c, a + 2u);
    return (hi << 16) | lo;
}

static void sh2_wb(struct sh2_cpu *c, u32 a, u8 v)
{
    if (a >= 0xFFFFFE00u) { sh2_onchip_write(c, a, v, 1); return; }
    if ((a >> 28) == 0xCu) { buf_wb(c->cram_chip, a & 0xFFFu, v); return; }
    u32 phys = a & 0x07FFFFFFu;
    if (phys >= 0x06000000u) {
        if (a & 0x20000000u) c->cycles += 2;
        buf_wb(WS->sdram, phys & 0x3FFFFu, v);
        return;
    }
    if (phys >= 0x04000000u && phys < 0x04040000u) {
        c->cycles += 3;
        /* Note: on real SuperVDP DRAM, byte write of 0x00 is ALWAYS ignored (transparent)! */
        if (v != 0u)
            buf_wb(WS->dram[WS->disp_fb ^ 1u], phys & 0x1FFFFu, v);
        return;
    }
    if (phys >= 0x00004000u && phys < 0x00004400u) {
        c->cycles += 3;
        u32 roff = phys - 0x00004000u;
        if (roff >= 0x200u) { buf_wb(WS->cram, roff - 0x200u, v); return; }
        if (roff >= 0x100u && roff < 0x110u) { vdp_reg_write8(roff - 0x100u, v); return; }
        if (roff >= 0x020u && roff < 0x030u) {
            u32 wi = (roff - 0x020u) >> 1;
            u16 nv = (roff & 1u) ? (u16)((WS->comm[wi] & 0xFF00u) | v)
                                 : (u16)((WS->comm[wi] & 0x00FFu) | ((u16)v << 8));
            if (WS->comm[wi] != nv) {
                WS->comm[wi] = nv;
                sh2_wake_comm(c->id);
            }
            return;
        }
        if (roff == 0x001u) c->irq_mask = v & 0x0Fu;
        else if (roff == 0x005u) WS->hcount_reload = v;
    }
}

static void sh2_ww(struct sh2_cpu *c, u32 a, u16 v)
{
    a &= ~1u;
    if (a >= 0xFFFFFE00u) { sh2_onchip_write(c, a, v, 2); return; }
    if ((a >> 28) == 0xCu) { c->cram_chip[(a & 0xFFFu) >> 1] = v; return; }
    u32 phys = a & 0x07FFFFFFu;
    if (phys >= 0x06000000u) {
        if (a & 0x20000000u) c->cycles += 2;
        WS->sdram[(phys & 0x3FFFFu) >> 1] = v;
        return;
    }
    if (phys >= 0x04000000u && phys < 0x04020000u) {
        c->cycles += 3;
        WS->dram[WS->disp_fb ^ 1u][(phys & 0x1FFFFu) >> 1] = v;
        return;
    }
    if (phys >= 0x04020000u && phys < 0x04040000u) {    /* Overwrite image: skip zero bytes! */
        c->cycles += 3;
        u16 *dst = &WS->dram[WS->disp_fb ^ 1u][(phys & 0x1FFFFu) >> 1];
        u16 cur = *dst;
        if (v & 0xFF00u) cur = (u16)((cur & 0x00FFu) | (v & 0xFF00u));
        if (v & 0x00FFu) cur = (u16)((cur & 0xFF00u) | (v & 0x00FFu));
        *dst = cur;
        return;
    }
    if (phys >= 0x00004000u && phys < 0x00004400u) {
        c->cycles += 3;
        sh2_sys_write16(c, phys - 0x00004000u, v);
    }
}

static void sh2_wl(struct sh2_cpu *c, u32 a, u32 v)
{
    a &= ~3u;
    if (a >= 0xFFFFFE00u) { sh2_onchip_write(c, a, v, 4); return; }
    if ((a >> 28) == 0xCu) { buf_wl(c->cram_chip, a & 0xFFFu, v); return; }
    u32 phys = a & 0x07FFFFFFu;
    if (phys >= 0x06000000u) {
        if (a & 0x20000000u) c->cycles += 4;
        buf_wl(WS->sdram, phys & 0x3FFFFu, v);
        return;
    }
    if (phys >= 0x04000000u && phys < 0x04020000u) {
        c->cycles += 5;
        buf_wl(WS->dram[WS->disp_fb ^ 1u], phys & 0x1FFFFu, v);
        return;
    }
    sh2_ww(c, a, (u16)(v >> 16));
    sh2_ww(c, a + 2u, (u16)v);
}

/* ---- SH-2 Core Execution ---- */

static void sh2_take_irq_if_any(struct sh2_cpu *c)
{
    if (c->in_delay)
        return;
    u8 act = (u8)((c->irq_pend & c->irq_mask) | (c->irq_pend & 0x10u));
    if (!act)
        return;
    u32 imask = (c->sr >> 4) & 0x0Fu;
    u32 lvl = 0, vec = 0;
    if (act & 0x10u)      { lvl = 14; vec = 71; }
    else if (act & 0x08u) { lvl = 12; vec = 70; }
    else if (act & 0x04u) { lvl = 10; vec = 69; }
    else if (act & 0x02u) { lvl = 8;  vec = 68; }
    else if (act & 0x01u) { lvl = 6;  vec = 67; }
    if (lvl <= imask)
        return;
    c->sleep = 0;
    c->r[15] -= 4u; sh2_wl(c, c->r[15], c->sr);
    c->r[15] -= 4u; sh2_wl(c, c->r[15], c->pc);
    c->sr = (c->sr & ~0xF0u) | (lvl << 4);
    c->pc = sh2_rl(c, c->vbr + vec * 4u);
    c->cycles += 5;
}

#pragma GCC push_options
#pragma GCC optimize("O2")

INLINE void sh2_exec_one(struct sh2_cpu *c, u32 pc_inst, u16 op);

static __attribute__((noinline)) void sh2_delay_slot(struct sh2_cpu *c, u32 slot_pc, u32 target_pc)
{
    u16 slot_op = (((slot_pc & 0xDF000000u) == 0x06000000u)) ? WS->sdram[(slot_pc & 0x3FFFEu) >> 1] : sh2_rw(c, slot_pc);
    c->in_delay = 1;
    c->pc = slot_pc + 2u;
    sh2_exec_one(c, slot_pc, slot_op);
    c->in_delay = 0;
    c->pc = target_pc;
}

INLINE void sh2_exec_one(struct sh2_cpu *c, u32 pc_inst, u16 op)
{
    u32 n = (op >> 8) & 15u;
    u32 m = (op >> 4) & 15u;
    c->cycles += 1;

    switch (op >> 12) {
    case 0x0:
        switch (op & 0x0Fu) {
        case 0x2:
            if (m == 0u) c->r[n] = c->sr;
            else if (m == 1u) c->r[n] = c->gbr;
            else if (m == 2u) c->r[n] = c->vbr;
            return;
        case 0x3:
            if (m == 0u) {                              /* BSRF Rn */
                u32 dst = pc_inst + 4u + c->r[n];
                c->pr = pc_inst + 4u;
                sh2_delay_slot(c, pc_inst + 2u, dst);
            } else if (m == 2u) {                       /* BRAF Rn */
                u32 dst = pc_inst + 4u + c->r[n];
                sh2_delay_slot(c, pc_inst + 2u, dst);
            }
            return;
        case 0x4: sh2_wb(c, c->r[0] + c->r[n], (u8)c->r[m]); return;
        case 0x5: sh2_ww(c, c->r[0] + c->r[n], (u16)c->r[m]); return;
        case 0x6: sh2_wl(c, c->r[0] + c->r[n], c->r[m]); return;
        case 0x7: c->macl = c->r[n] * c->r[m]; return;
        case 0x8:
            if (m == 0u) c->sr &= ~SH2_T;
            else if (m == 1u) c->sr |= SH2_T;
            else if (m == 2u) c->mach = c->macl = 0;
            return;
        case 0x9:
            if (m == 2u) c->r[n] = c->sr & SH2_T;       /* MOVT Rn */
            return;
        case 0xA:
            if (m == 0u) c->r[n] = c->mach;
            else if (m == 1u) c->r[n] = c->macl;
            else if (m == 2u) c->r[n] = c->pr;
            return;
        case 0xB:
            if (m == 0u) {                              /* RTS */
                u32 dst = c->pr;
                sh2_delay_slot(c, pc_inst + 2u, dst);
            } else if (m == 1u) {                       /* SLEEP */
                c->sleep = 1;
                c->cycles = c->target;
            } else if (m == 2u) {                       /* RTE */
                u32 new_pc = sh2_rl(c, c->r[15]); c->r[15] += 4u;
                u32 new_sr = sh2_rl(c, c->r[15]) & 0x3F3u; c->r[15] += 4u;
                sh2_delay_slot(c, pc_inst + 2u, new_pc);
                c->sr = new_sr;
            }
            return;
        case 0xC: c->r[n] = (u32)(s32)(signed char)sh2_rb(c, c->r[0] + c->r[m]); return;
        case 0xD: c->r[n] = (u32)(s32)(s16)sh2_rw(c, c->r[0] + c->r[m]); return;
        case 0xE: c->r[n] = sh2_rl(c, c->r[0] + c->r[m]); return;
        case 0xF: {                                     /* MAC.L @Rm+,@Rn+ */
            s32 a = (s32)sh2_rl(c, c->r[m]); c->r[m] += 4u;
            s32 b = (s32)sh2_rl(c, c->r[n]); c->r[n] += 4u;
            long long prod = (long long)a * (long long)b;
            long long cur  = ((long long)(s32)c->mach << 32) | (u32)c->macl;
            cur += prod;
            if (c->sr & SH2_S) {
                if (cur >  0x00007FFFFFFFFFFFLL) cur =  0x00007FFFFFFFFFFFLL;
                if (cur < -0x0000800000000000LL) cur = -0x0000800000000000LL;
            }
            c->mach = (u32)((unsigned long long)cur >> 32);
            c->macl = (u32)cur;
            return;
        }
        }
        return;

    case 0x1: {
        u32 da = (c->r[n] + (op & 15u) * 4u) & ~3u;
        if ((da & 0x07FE0000u) == 0x04000000u && da < 0x40000000u) {
            u16 *fb = &WS->dram[WS->disp_fb ^ 1u][(da & 0x1FFFFu) >> 1];
            u32 v = c->r[m];
            fb[0] = (u16)(v >> 16);
            fb[1] = (u16)v;
            c->cycles += 3;
            return;
        }
        sh2_wl(c, da, c->r[m]);
        return;
    }

    case 0x2:
        switch (op & 15u) {
        case 0x0: sh2_wb(c, c->r[n], (u8)c->r[m]); return;
        case 0x1: sh2_ww(c, c->r[n], (u16)c->r[m]); return;
        case 0x2: {
            u32 da = c->r[n] & ~3u;
            if ((da & 0x07FE0000u) == 0x04000000u && da < 0x40000000u) {
                u16 *fb = &WS->dram[WS->disp_fb ^ 1u][(da & 0x1FFFFu) >> 1];
                u32 v = c->r[m];
                fb[0] = (u16)(v >> 16);
                fb[1] = (u16)v;
                c->cycles += 3;
                return;
            }
            sh2_wl(c, da, c->r[m]);
            return;
        }
        case 0x4: c->r[n] -= 1u; sh2_wb(c, c->r[n], (u8)c->r[m]); return;
        case 0x5: c->r[n] -= 2u; sh2_ww(c, c->r[n], (u16)c->r[m]); return;
        case 0x6: c->r[n] -= 4u; sh2_wl(c, c->r[n], c->r[m]); return;
        case 0x7: {                                     /* DIV0S Rm,Rn */
            c->sr &= ~(SH2_Q | SH2_M | SH2_T);
            u32 q = (c->r[n] >> 31) & 1u, ms = (c->r[m] >> 31) & 1u;
            if (q) c->sr |= SH2_Q;
            if (ms) c->sr |= SH2_M;
            if (q ^ ms) c->sr |= SH2_T;
            return;
        }
        case 0x8: c->sr = (c->sr & ~SH2_T) | ((c->r[n] & c->r[m]) == 0u ? SH2_T : 0u); return;
        case 0x9: c->r[n] &= c->r[m]; return;
        case 0xA: c->r[n] ^= c->r[m]; return;
        case 0xB: c->r[n] |= c->r[m]; return;
        case 0xC: {
            u32 x = c->r[n] ^ c->r[m];
            u32 hit = ((x & 0xFFu) == 0u) || ((x & 0xFF00u) == 0u) ||
                      ((x & 0xFF0000u) == 0u) || ((x & 0xFF000000u) == 0u);
            c->sr = (c->sr & ~SH2_T) | (hit ? SH2_T : 0u);
            return;
        }
        case 0xD: c->r[n] = (c->r[m] << 16) | (c->r[n] >> 16); return;
        case 0xE: c->macl = (u32)((s32)(u32)(u16)c->r[n] * (u32)(u16)c->r[m]); return;
        case 0xF: c->macl = (u32)((s32)(s16)c->r[n] * (s32)(s16)c->r[m]); return;
        }
        return;

    case 0x3:
        switch (op & 15u) {
        case 0x0: c->sr = (c->sr & ~SH2_T) | (c->r[n] == c->r[m] ? SH2_T : 0u); return;
        case 0x2: c->sr = (c->sr & ~SH2_T) | (c->r[n] >= c->r[m] ? SH2_T : 0u); return;
        case 0x3: c->sr = (c->sr & ~SH2_T) | ((s32)c->r[n] >= (s32)c->r[m] ? SH2_T : 0u); return;
        case 0x4: {                                     /* DIV1 Rm,Rn */
            u32 old_q = (c->sr & SH2_Q) != 0;
            u32 m_bit = (c->sr & SH2_M) != 0;
            u32 q = (c->r[n] >> 31) & 1u;
            c->r[n] = (c->r[n] << 1) | (c->sr & SH2_T);
            u32 r0 = c->r[n], tmp1;
            if (old_q == m_bit) {
                c->r[n] -= c->r[m];
                tmp1 = (c->r[n] > r0);
            } else {
                c->r[n] += c->r[m];
                tmp1 = (c->r[n] < r0);
            }
            q = (q ^ m_bit ^ tmp1) & 1u;
            c->sr = (c->sr & ~(SH2_Q | SH2_T)) | (q ? SH2_Q : 0u) | ((q == m_bit) ? SH2_T : 0u);
            return;
        }
        case 0x5: {
            unsigned long long p = (unsigned long long)c->r[n] * (unsigned long long)c->r[m];
            c->mach = (u32)(p >> 32); c->macl = (u32)p;
            return;
        }
        case 0x6: c->sr = (c->sr & ~SH2_T) | (c->r[n] > c->r[m] ? SH2_T : 0u); return;
        case 0x7: c->sr = (c->sr & ~SH2_T) | ((s32)c->r[n] > (s32)c->r[m] ? SH2_T : 0u); return;
        case 0x8: c->r[n] -= c->r[m]; return;
        case 0xA: {                                     /* SUBC Rm,Rn */
            u32 t = c->sr & SH2_T;
            u32 tmp1 = c->r[n] - c->r[m];
            u32 tmp0 = c->r[n];
            c->r[n] = tmp1 - t;
            c->sr = (c->sr & ~SH2_T) | ((tmp0 < tmp1 || tmp1 < c->r[n]) ? SH2_T : 0u);
            return;
        }
        case 0xB: {                                     /* SUBV Rm,Rn */
            s32 d = (s32)c->r[n], s = (s32)c->r[m], r = d - s;
            c->r[n] = (u32)r;
            c->sr = (c->sr & ~SH2_T) | ((((d ^ s) & (d ^ r)) < 0) ? SH2_T : 0u);
            return;
        }
        case 0xC: c->r[n] += c->r[m]; return;
        case 0xD: {
            long long p = (long long)(s32)c->r[n] * (long long)(s32)c->r[m];
            c->mach = (u32)((unsigned long long)p >> 32); c->macl = (u32)p;
            return;
        }
        case 0xE: {                                     /* ADDC Rm,Rn */
            u32 t = c->sr & SH2_T;
            u32 tmp1 = c->r[n] + c->r[m];
            u32 tmp0 = c->r[n];
            c->r[n] = tmp1 + t;
            c->sr = (c->sr & ~SH2_T) | ((tmp0 > tmp1 || tmp1 > c->r[n]) ? SH2_T : 0u);
            return;
        }
        case 0xF: {                                     /* ADDV Rm,Rn */
            s32 d = (s32)c->r[n], s = (s32)c->r[m], r = d + s;
            c->r[n] = (u32)r;
            c->sr = (c->sr & ~SH2_T) | (((~(d ^ s) & (d ^ r)) < 0) ? SH2_T : 0u);
            return;
        }
        }
        return;

    case 0x4:
        switch (op & 0xFFu) {
        case 0x00: c->sr = (c->sr & ~SH2_T) | (c->r[n] >> 31); c->r[n] <<= 1; return;
        case 0x01: c->sr = (c->sr & ~SH2_T) | (c->r[n] & 1u);  c->r[n] >>= 1; return;
        case 0x02: c->r[n] -= 4u; sh2_wl(c, c->r[n], c->mach); return;
        case 0x03: c->r[n] -= 4u; sh2_wl(c, c->r[n], c->sr); return;
        case 0x04: { u32 b = c->r[n] >> 31; c->r[n] = (c->r[n] << 1) | b; c->sr = (c->sr & ~SH2_T) | b; return; }
        case 0x05: { u32 b = c->r[n] & 1u;  c->r[n] = (c->r[n] >> 1) | (b << 31); c->sr = (c->sr & ~SH2_T) | b; return; }
        case 0x06: c->mach = sh2_rl(c, c->r[n]); c->r[n] += 4u; return;
        case 0x07: c->sr = sh2_rl(c, c->r[n]) & 0x3F3u; c->r[n] += 4u; return;
        case 0x08: c->r[n] <<= 2; return;
        case 0x09: c->r[n] >>= 2; return;
        case 0x0A: c->mach = c->r[n]; return;
        case 0x0B: { u32 dst = c->r[n]; c->pr = pc_inst + 4u; sh2_delay_slot(c, pc_inst + 2u, dst); return; }
        case 0x0E: c->sr = c->r[n] & 0x3F3u; return;
        case 0x10: c->r[n]--; c->sr = (c->sr & ~SH2_T) | (c->r[n] == 0u ? SH2_T : 0u); return;
        case 0x11: c->sr = (c->sr & ~SH2_T) | ((s32)c->r[n] >= 0 ? SH2_T : 0u); return;
        case 0x12: c->r[n] -= 4u; sh2_wl(c, c->r[n], c->macl); return;
        case 0x13: c->r[n] -= 4u; sh2_wl(c, c->r[n], c->gbr); return;
        case 0x15: c->sr = (c->sr & ~SH2_T) | ((s32)c->r[n] > 0 ? SH2_T : 0u); return;
        case 0x16: c->macl = sh2_rl(c, c->r[n]); c->r[n] += 4u; return;
        case 0x17: c->gbr = sh2_rl(c, c->r[n]); c->r[n] += 4u; return;
        case 0x18: c->r[n] <<= 8; return;
        case 0x19: c->r[n] >>= 8; return;
        case 0x1A: c->macl = c->r[n]; return;
        case 0x1B: { u8 b = sh2_rb(c, c->r[n]); c->sr = (c->sr & ~SH2_T) | (b == 0u ? SH2_T : 0u); sh2_wb(c, c->r[n], (u8)(b | 0x80u)); return; }
        case 0x1E: c->gbr = c->r[n]; return;
        case 0x20: c->sr = (c->sr & ~SH2_T) | (c->r[n] >> 31); c->r[n] <<= 1; return;
        case 0x21: c->sr = (c->sr & ~SH2_T) | (c->r[n] & 1u);  c->r[n] = (u32)((s32)c->r[n] >> 1); return;
        case 0x22: c->r[n] -= 4u; sh2_wl(c, c->r[n], c->pr); return;
        case 0x23: c->r[n] -= 4u; sh2_wl(c, c->r[n], c->vbr); return;
        case 0x24: { u32 t = c->sr & SH2_T, b = c->r[n] >> 31; c->r[n] = (c->r[n] << 1) | t; c->sr = (c->sr & ~SH2_T) | b; return; }
        case 0x25: { u32 t = c->sr & SH2_T, b = c->r[n] & 1u;  c->r[n] = (c->r[n] >> 1) | (t << 31); c->sr = (c->sr & ~SH2_T) | b; return; }
        case 0x26: c->pr = sh2_rl(c, c->r[n]); c->r[n] += 4u; return;
        case 0x27: c->vbr = sh2_rl(c, c->r[n]); c->r[n] += 4u; return;
        case 0x28: c->r[n] <<= 16; return;
        case 0x29: c->r[n] >>= 16; return;
        case 0x2A: c->pr = c->r[n]; return;
        case 0x2B: { u32 dst = c->r[n]; sh2_delay_slot(c, pc_inst + 2u, dst); return; }
        case 0x2E: c->vbr = c->r[n]; return;
        default:
            if ((op & 0x0Fu) == 0x0Fu) {                /* MAC.W @Rm+,@Rn+ */
                s32 a = (s16)sh2_rw(c, c->r[m]); c->r[m] += 2u;
                s32 b = (s16)sh2_rw(c, c->r[n]); c->r[n] += 2u;
                s32 prod = a * b;
                if (c->sr & SH2_S) {
                    long long s = (long long)(s32)c->macl + prod;
                    if (s > 0x7FFFFFFFLL) { s = 0x7FFFFFFFLL; c->mach |= 1u; }
                    else if (s < -0x80000000LL) { s = -0x80000000LL; c->mach |= 1u; }
                    c->macl = (u32)s;
                } else {
                    long long cur = ((long long)(s32)c->mach << 32) | (u32)c->macl;
                    cur += prod;
                    c->mach = (u32)((unsigned long long)cur >> 32);
                    c->macl = (u32)cur;
                }
            }
            return;
        }

    case 0x5:
        c->r[n] = sh2_rl(c, c->r[m] + (op & 15u) * 4u);
        return;

    case 0x6:
        switch (op & 15u) {
        case 0x0: c->r[n] = (u32)(s32)(signed char)sh2_rb(c, c->r[m]); return;
        case 0x1: c->r[n] = (u32)(s32)(s16)sh2_rw(c, c->r[m]); return;
        case 0x2: c->r[n] = sh2_rl(c, c->r[m]); return;
        case 0x3: c->r[n] = c->r[m]; return;
        case 0x4: c->r[n] = (u32)(s32)(signed char)sh2_rb(c, c->r[m]); if (n != m) c->r[m] += 1u; return;
        case 0x5: c->r[n] = (u32)(s32)(s16)sh2_rw(c, c->r[m]); if (n != m) c->r[m] += 2u; return;
        case 0x6: c->r[n] = sh2_rl(c, c->r[m]); if (n != m) c->r[m] += 4u; return;
        case 0x7: c->r[n] = ~c->r[m]; return;
        case 0x8: c->r[n] = (c->r[m] & 0xFFFF0000u) | ((c->r[m] & 0xFFu) << 8) | ((c->r[m] >> 8) & 0xFFu); return;
        case 0x9: c->r[n] = (c->r[m] << 16) | (c->r[m] >> 16); return;
        case 0xA: {                                     /* NEGC Rm,Rn */
            u32 t = c->sr & SH2_T;
            u32 tmp = 0u - c->r[m];
            c->r[n] = tmp - t;
            c->sr = (c->sr & ~SH2_T) | ((0u < tmp || tmp < c->r[n]) ? SH2_T : 0u);
            return;
        }
        case 0xB: c->r[n] = 0u - c->r[m]; return;
        case 0xC: c->r[n] = c->r[m] & 0xFFu; return;
        case 0xD: c->r[n] = c->r[m] & 0xFFFFu; return;
        case 0xE: c->r[n] = (u32)(s32)(signed char)c->r[m]; return;
        case 0xF: c->r[n] = (u32)(s32)(s16)c->r[m]; return;
        }
        return;

    case 0x7:
        c->r[n] += (u32)(s32)(signed char)(op & 0xFFu);
        return;

    case 0x8:
        switch (n) {
        case 0x0: sh2_wb(c, c->r[m] + (op & 15u), (u8)c->r[0]); return;
        case 0x1: sh2_ww(c, c->r[m] + (op & 15u) * 2u, (u16)c->r[0]); return;
        case 0x4: c->r[0] = (u32)(s32)(signed char)sh2_rb(c, c->r[m] + (op & 15u)); return;
        case 0x5: c->r[0] = (u32)(s32)(s16)sh2_rw(c, c->r[m] + (op & 15u) * 2u); return;
        case 0x8: c->sr = (c->sr & ~SH2_T) | (c->r[0] == (u32)(s32)(signed char)(op & 0xFFu) ? SH2_T : 0u); return;
        case 0x9:                                       /* BT disp */
        case 0xB: {                                     /* BF disp */
            int cond = (n == 0x9u) ? ((c->sr & SH2_T) != 0) : ((c->sr & SH2_T) == 0);
            if (cond) {
                s32 disp = (signed char)(op & 0xFFu);
                u32 dst = pc_inst + 4u + (u32)(disp * 2);
                c->pc = dst;
                c->cycles += 2;
                /* Pass-4 Spin-Wait Optimization: tight 2..3-instruction COMM / VBlank / SDRAM poll loop! */
                if (!c->in_delay && (disp == -3 || disp == -4)) {
                    u16 op0 = sh2_rw(c, dst);
                    /* MOV.B/W/L @Rm / @(disp,Rm) followed by TST/CMP -> BT/BF */
                    if ((op0 & 0xF000u) == 0x6000u || (op0 & 0xFA00u) == 0x8000u || (op0 & 0xF000u) == 0x5000u) {
                        u32 rm = (op0 >> 4) & 15u;
                        u32 base = c->r[rm] & 0x07FFFFFFu;
                        if ((base >= 0x00004000u && base < 0x00004200u) || base >= 0x06000000u) {
                            if (c->cycles < c->target)
                                c->cycles = c->target;
                        }
                    }
                }
            }
            return;
        }
        case 0xD:                                       /* BT/S disp */
        case 0xF: {                                     /* BF/S disp */
            int cond = (n == 0xDu) ? ((c->sr & SH2_T) != 0) : ((c->sr & SH2_T) == 0);
            if (cond) {
                u32 dst = pc_inst + 4u + (u32)((s32)(signed char)(op & 0xFFu) * 2);
                sh2_delay_slot(c, pc_inst + 2u, dst);
            }
            return;
        }
        }
        return;

    case 0x9:
        c->r[n] = (u32)(s32)(s16)sh2_rw(c, pc_inst + 4u + (op & 0xFFu) * 2u);
        return;

    case 0xA: {                                         /* BRA disp12 */
        s32 disp = (s32)((op & 0x800u) ? (op | 0xFFFFF000u) : (op & 0xFFFu));
        u32 dst = pc_inst + 4u + (u32)(disp * 2);
        sh2_delay_slot(c, pc_inst + 2u, dst);
        return;
    }

    case 0xB: {                                         /* BSR disp12 */
        s32 disp = (s32)((op & 0x800u) ? (op | 0xFFFFF000u) : (op & 0xFFFu));
        u32 dst = pc_inst + 4u + (u32)(disp * 2);
        c->pr = pc_inst + 4u;
        sh2_delay_slot(c, pc_inst + 2u, dst);
        return;
    }

    case 0xC:
        switch (n) {
        case 0x0: sh2_wb(c, c->gbr + (op & 0xFFu), (u8)c->r[0]); return;
        case 0x1: sh2_ww(c, c->gbr + (op & 0xFFu) * 2u, (u16)c->r[0]); return;
        case 0x2: sh2_wl(c, c->gbr + (op & 0xFFu) * 4u, c->r[0]); return;
        case 0x3: {                                     /* TRAPA #imm */
            u32 vec = op & 0xFFu;
            c->r[15] -= 4u; sh2_wl(c, c->r[15], c->sr);
            c->r[15] -= 4u; sh2_wl(c, c->r[15], c->pc);
            c->pc = sh2_rl(c, c->vbr + vec * 4u);
            return;
        }
        case 0x4: c->r[0] = (u32)(s32)(signed char)sh2_rb(c, c->gbr + (op & 0xFFu)); return;
        case 0x5: c->r[0] = (u32)(s32)(s16)sh2_rw(c, c->gbr + (op & 0xFFu) * 2u); return;
        case 0x6: c->r[0] = sh2_rl(c, c->gbr + (op & 0xFFu) * 4u); return;
        case 0x7: c->r[0] = ((pc_inst + 4u) & ~3u) + (op & 0xFFu) * 4u; return;
        case 0x8: c->sr = (c->sr & ~SH2_T) | ((c->r[0] & (op & 0xFFu)) == 0u ? SH2_T : 0u); return;
        case 0x9: c->r[0] &= (op & 0xFFu); return;
        case 0xA: c->r[0] ^= (op & 0xFFu); return;
        case 0xB: c->r[0] |= (op & 0xFFu); return;
        case 0xC: { u8 b = sh2_rb(c, c->r[0] + c->gbr); c->sr = (c->sr & ~SH2_T) | ((b & (op & 0xFFu)) == 0u ? SH2_T : 0u); return; }
        case 0xD: { u32 ea = c->r[0] + c->gbr; sh2_wb(c, ea, (u8)(sh2_rb(c, ea) & (op & 0xFFu))); return; }
        case 0xE: { u32 ea = c->r[0] + c->gbr; sh2_wb(c, ea, (u8)(sh2_rb(c, ea) ^ (op & 0xFFu))); return; }
        case 0xF: { u32 ea = c->r[0] + c->gbr; sh2_wb(c, ea, (u8)(sh2_rb(c, ea) | (op & 0xFFu))); return; }
        }
        return;

    case 0xD:
        c->r[n] = sh2_rl(c, ((pc_inst + 4u) & ~3u) + (op & 0xFFu) * 4u);
        return;

    case 0xE:
        c->r[n] = (u32)(s32)(signed char)(op & 0xFFu);
        return;
    }
}

static void sh2_run_to(struct sh2_cpu *c, s32 target)
{
    if (!WS->aden || !WS->ren) {
        c->cycles = target;
        return;
    }
    c->target = target;
    c->poll_pc = 0;
    sh2_take_irq_if_any(c);
    if (c->sleep) {
        c->cycles = target;
        return;
    }
    const u16 *sdram = WS->sdram;
    while (c->cycles < c->target) {
        u32 pc = c->pc;
        u16 op = (((pc & 0xDF000000u) == 0x06000000u)) ? sdram[(pc & 0x3FFFEu) >> 1] : sh2_rw(c, pc);
        c->pc = pc + 2u;
        sh2_exec_one(c, pc, op);
        if ((c->irq_pend & (c->irq_mask | 0x10u)) && !c->in_delay)
            sh2_take_irq_if_any(c);
    }
}

#pragma GCC pop_options

static void s32x_sync_sh2(s32 main_cyc)
{
    /* Effective shared-bus dual-SH-2 budget (2x 7.67 MHz 68000 = ~15.3 MHz/CPU after 16-bit SDRAM bus sharing) */
    s32 want = main_cyc * 2;
    if (want <= WS->sh_synced_m68k)
        return;
    s32 cur = WS->sh_synced_m68k;
    while (cur < want) {
        s32 step = want - cur;
        if (step > 2048) step = 2048;
        s32 next = cur + step;
        sh2_run_to(&WS->sh[0], next);
        sh2_run_to(&WS->sh[1], next);

        /* Advance PWM cycle timer (23.01 MHz = 1.5x shared-bus step) */
        u32 cyc_per = WS->pwm_cycle ? WS->pwm_cycle : 0u;
        if ((WS->pwm_ctl & 0x0Fu) && cyc_per >= 64u) {
            WS->pwm_tmr_sh2 += step + (step >> 1);
            while (WS->pwm_tmr_sh2 >= (s32)cyc_per) {
                WS->pwm_tmr_sh2 -= (s32)cyc_per;
                if (WS->pwm_ln > 0u) {
                    WS->pwm_cur_l = WS->pwm_l_fifo[0];
                    for (int i = 0; i + 1 < WS->pwm_ln; i++) WS->pwm_l_fifo[i] = WS->pwm_l_fifo[i + 1];
                    WS->pwm_ln--;
                }
                if (WS->pwm_rn > 0u) {
                    WS->pwm_cur_r = WS->pwm_r_fifo[0];
                    for (int i = 0; i + 1 < WS->pwm_rn; i++) WS->pwm_r_fifo[i] = WS->pwm_r_fifo[i + 1];
                    WS->pwm_rn--;
                }
                if (WS->pwm_w - WS->pwm_r < PWM_RING_CAP) {
                    s32 mid = (s32)(cyc_per >> 1);
                    s32 s = ((WS->pwm_cur_l - mid) + (WS->pwm_cur_r - mid)) * 28;
                    if (s > 32767) s = 32767;
                    else if (s < -32768) s = -32768;
                    WS->pwm_ring[WS->pwm_w & (PWM_RING_CAP - 1u)] = (s16)s;
                    WS->pwm_w++;
                }
                WS->sh[0].irq_pend |= 0x01u;
                WS->sh[1].irq_pend |= 0x01u;
            }
        }
        WS->sh[0].frc = (u16)(WS->sh[0].frc + (u32)(step >> 3));
        WS->sh[1].frc = (u16)(WS->sh[1].frc + (u32)(step >> 3));
        cur = next;
    }
    WS->sh_synced_m68k = want;
}

/* ---- Clean-Room Master & Slave SH-2 Boot ROM Builder ---- */

static void emit_sh2(u16 *rom, int *at, u16 op)
{
    rom[(*at)++] = op;
}

static void build_cleanroom_sh2_bios(void)
{
    /* Master SH-2 Boot ROM ($00000000):
       Vector 0 (PC) = $00000040, Vector 1 (SP) = $0603FC00
       1. Reads Mars Module Header at $220003D4 (src, dst, size, m_entry, s_entry, m_vbr, s_vbr)
       2. Copies [size] bytes from ($22000000 + (src & 0x3FFFFF)) -> ($26000000 + (dst & 0x3FFFF))
       3. Sets VBR = m_vbr, SP = $0603FC00
       4. Writes "M_OK" ($4D5F4F4B) to COMM0..1 ($20004020), waits until 68000 clears COMM0 to 0!
       5. Enables interrupts (SR = $00000020) and jumps to m_entry! */
    s32x_zero(WS->boot_m, sizeof(WS->boot_m));
    buf_wl(WS->boot_m, 0x00u, 0x00000040u);
    buf_wl(WS->boot_m, 0x04u, 0x0603FC00u);
    for (u32 v = 2; v < 16; v++)
        buf_wl(WS->boot_m, v * 4u, 0x0000003Eu);        /* Default RTE at $003E */
    WS->boot_m[0x003Eu >> 1] = 0x002Bu;                 /* RTE */
    WS->boot_m[0x0040u >> 1] = 0x0009u;                 /* NOP */

    /* Literal pool at $00000100:
       $100: $220003D4 (header base)
       $104: $003FFFFF (ROM mask)
       $108: $22000000 (ROM uncached base)
       $10C: $26000000 (SDRAM uncached base)
       $110: $20004020 (COMM0)
       $114: $4D5F4F4B ("M_OK")
       $118: $00000020 (initial SR)
       $11C: $0003FFFF (SDRAM mask) */
    buf_wl(WS->boot_m, 0x100u, 0x220003D4u);
    buf_wl(WS->boot_m, 0x104u, 0x003FFFFFu);
    buf_wl(WS->boot_m, 0x108u, 0x22000000u);
    buf_wl(WS->boot_m, 0x10Cu, 0x26000000u);
    buf_wl(WS->boot_m, 0x110u, 0x20004020u);
    buf_wl(WS->boot_m, 0x114u, 0x4D5F4F4Bu);
    buf_wl(WS->boot_m, 0x118u, 0x00000020u);
    buf_wl(WS->boot_m, 0x11Cu, 0x0003FFFFu);

    int p = 0x0040 >> 1;                                /* PC starts at $0040 */
    /* MOV.L @($100,PC),R1..R8: at PC=$40, ((PC+4)&~3) = $44 -> disp = (lit - $44)/4! */
#define M_LIT(rn, lit_addr) do { \
        u32 cur_pc = (u32)(p * 2); \
        u32 disp = ((lit_addr) - ((cur_pc + 4u) & ~3u)) >> 2; \
        emit_sh2(WS->boot_m, &p, (u16)(0xD000u | ((rn) << 8) | (disp & 0xFFu))); \
    } while (0)

    M_LIT(1, 0x100u);                                   /* R1 = $220003D4 */
    emit_sh2(WS->boot_m, &p, 0x5210u);                  /* R2 = @(0,R1)  = src */
    emit_sh2(WS->boot_m, &p, 0x5311u);                  /* R3 = @(4,R1)  = dst */
    emit_sh2(WS->boot_m, &p, 0x5412u);                  /* R4 = @(8,R1)  = size */
    emit_sh2(WS->boot_m, &p, 0x5513u);                  /* R5 = @(12,R1) = m_entry */
    emit_sh2(WS->boot_m, &p, 0x5615u);                  /* R6 = @(20,R1) = m_vbr */
    M_LIT(7, 0x104u);                                   /* R7 = $003FFFFF */
    emit_sh2(WS->boot_m, &p, 0x2279u);                  /* AND R7,R2 */
    M_LIT(7, 0x108u);                                   /* R7 = $22000000 */
    emit_sh2(WS->boot_m, &p, 0x327Cu);                  /* ADD R7,R2 (src ptr) */
    M_LIT(7, 0x11Cu);                                   /* R7 = $0003FFFF */
    emit_sh2(WS->boot_m, &p, 0x2379u);                  /* AND R7,R3 */
    M_LIT(7, 0x10Cu);                                   /* R7 = $26000000 */
    emit_sh2(WS->boot_m, &p, 0x337Cu);                  /* ADD R7,R3 (dst ptr) */
    emit_sh2(WS->boot_m, &p, 0x4401u);                  /* SHLR R4 (word count = size >> 1) */
    emit_sh2(WS->boot_m, &p, 0x2448u);                  /* TST R4,R4 */
    emit_sh2(WS->boot_m, &p, 0x8904u);                  /* BT +4 instrs (skip copy if 0) */
    /* copy_loop: */
    emit_sh2(WS->boot_m, &p, 0x6025u);                  /* MOV.W @R2+,R0 */
    emit_sh2(WS->boot_m, &p, 0x2301u);                  /* MOV.W R0,@R3 */
    emit_sh2(WS->boot_m, &p, 0x7302u);                  /* ADD #2,R3 */
    emit_sh2(WS->boot_m, &p, 0x4410u);                  /* DT R4 */
    emit_sh2(WS->boot_m, &p, 0x8BFau);                  /* BF -6 (back to copy_loop) */
    /* Set VBR, write "M_OK" to COMM0 ($20004020), wait until COMM0 == 0, jump to R5! */
    emit_sh2(WS->boot_m, &p, 0x462Eu);                  /* LDC R6,VBR */
    M_LIT(8, 0x110u);                                   /* R8 = $20004020 */
    M_LIT(0, 0x114u);                                   /* R0 = "M_OK" */
    emit_sh2(WS->boot_m, &p, 0x2802u);                  /* MOV.L R0,@R8 */
    /* wait_m_clr: */
    emit_sh2(WS->boot_m, &p, 0x6082u);                  /* MOV.L @R8,R0 */
    emit_sh2(WS->boot_m, &p, 0x2008u);                  /* TST R0,R0 */
    emit_sh2(WS->boot_m, &p, 0x8BFCu);                  /* BF -4 (wait until 68k clears COMM0) */
    M_LIT(0, 0x118u);                                   /* R0 = $20 */
    emit_sh2(WS->boot_m, &p, 0x400Eu);                  /* LDC R0,SR */
    emit_sh2(WS->boot_m, &p, 0x452Bu);                  /* JMP @R5 */
    emit_sh2(WS->boot_m, &p, 0x0009u);                  /* NOP (delay slot) */
#undef M_LIT

    /* Slave SH-2 Boot ROM ($00000000):
       Reads s_entry ($220003E4) & s_vbr ($220003EC), sets VBR, writes "S_OK" ($535F4F4B)
       to COMM2 ($20004024), waits until COMM2 == 0, sets SR=$20, jumps to s_entry! */
    s32x_zero(WS->boot_s, sizeof(WS->boot_s));
    buf_wl(WS->boot_s, 0x00u, 0x00000040u);
    buf_wl(WS->boot_s, 0x04u, 0x0603FE00u);
    buf_wl(WS->boot_s, 0x100u, 0x220003E4u);
    buf_wl(WS->boot_s, 0x104u, 0x20004024u);
    buf_wl(WS->boot_s, 0x108u, 0x535F4F4Bu);
    buf_wl(WS->boot_s, 0x10Cu, 0x00000020u);

    p = 0x0040 >> 1;
#define S_LIT(rn, lit_addr) do { \
        u32 cur_pc = (u32)(p * 2); \
        u32 disp = ((lit_addr) - ((cur_pc + 4u) & ~3u)) >> 2; \
        emit_sh2(WS->boot_s, &p, (u16)(0xD000u | ((rn) << 8) | (disp & 0xFFu))); \
    } while (0)

    S_LIT(1, 0x100u);                                   /* R1 = $220003E4 */
    emit_sh2(WS->boot_s, &p, 0x5510u);                  /* R5 = @(0,R1) = s_entry */
    emit_sh2(WS->boot_s, &p, 0x5612u);                  /* R6 = @(8,R1) = s_vbr */
    emit_sh2(WS->boot_s, &p, 0x462Eu);                  /* LDC R6,VBR */
    S_LIT(8, 0x104u);                                   /* R8 = $20004024 (COMM2) */
    S_LIT(0, 0x108u);                                   /* R0 = "S_OK" */
    emit_sh2(WS->boot_s, &p, 0x2802u);                  /* MOV.L R0,@R8 */
    emit_sh2(WS->boot_s, &p, 0x6082u);                  /* MOV.L @R8,R0 */
    emit_sh2(WS->boot_s, &p, 0x2008u);                  /* TST R0,R0 */
    emit_sh2(WS->boot_s, &p, 0x8BFCu);                  /* BF -4 */
    S_LIT(0, 0x10Cu);                                   /* R0 = $20 */
    emit_sh2(WS->boot_s, &p, 0x400Eu);                  /* LDC R0,SR */
    emit_sh2(WS->boot_s, &p, 0x452Bu);                  /* JMP @R5 */
    emit_sh2(WS->boot_s, &p, 0x0009u);                  /* NOP */
#undef S_LIT
}

static void build_cleanroom_68k_vectors(void)
{
    /* Copy cart's $00..$FF vectors, except Level 1..7 autovectors ($64..$7F) point to
       $FFFD00 + k*6 (matching real 32x_g_bios.bin, with default JMP to cart's vector pre-installed in RAM!) */
    for (int i = 0; i < 0x80; i++)
        WS->vec68k[i] = (i * 2 < (int)WS->rom_bytes) ? WS->rom[i] : 0;
    for (int lvl = 1; lvl <= 7; lvl++) {
        u32 voff = 0x60u + (u32)lvl * 4u;
        u32 ram_jmp = 0x00FFFD00u + (u32)(lvl - 1) * 6u;
        u32 orig_vec = buf_rl(WS->rom, voff);
        buf_wl(WS->vec68k, voff, ram_jmp);
        if (WS->main_ram) {
            u32 roff = 0xFD00u + (u32)(lvl - 1) * 6u;
            WS->main_ram[roff >> 1]        = 0x4EF9u;   /* JMP abs.L */
            WS->main_ram[(roff + 2u) >> 1] = (u16)(orig_vec >> 16);
            WS->main_ram[(roff + 4u) >> 1] = (u16)orig_vec;
        }
    }
}

/* ---- Mega Drive 68000 Add-On Interface ---- */

static void sh2_reset_one(struct sh2_cpu *c, int id)
{
    s32x_zero(c, sizeof(*c));
    c->id = (u8)id;
    const u16 *brom = id ? WS->boot_s : WS->boot_m;
    c->pc  = buf_rl(brom, 0x00u);
    c->r[15] = buf_rl(brom, 0x04u);
    c->sr  = 0x000000F0u;
    c->vbr = 0x00000000u;
}

static void s32x_addon_reset(u16 *main_ram32kw)
{
    WS->main_ram = main_ram32kw;
    s32x_zero(WS->sdram, sizeof(WS->sdram));
    s32x_zero(WS->dram, sizeof(WS->dram));
    s32x_zero(WS->cram, sizeof(WS->cram));
    s32x_zero(WS->comm, sizeof(WS->comm));

    if (!WS->ext_bios_m || !WS->ext_bios_s)
        build_cleanroom_sh2_bios();
    if (!WS->ext_bios_g)
        build_cleanroom_68k_vectors();

    /* Start with RV=1 so cartridge boots cleanly from $000000 (retail ICD_MARS & homebrew alike!) */
    WS->aden = 0;
    WS->ren  = 1;
    WS->fm   = 0;
    WS->rv   = 1;
    WS->bank90 = 0;
    WS->hen  = 0;
    WS->hcount_reload = 0;
    WS->hcount_cur = 0;
    WS->dreq_ctl = 0;
    WS->fifo_r = WS->fifo_w = WS->fifo_n = 0;
    WS->vdp_mode = 0;
    WS->vdp_shift = 0;
    WS->disp_fb = WS->req_fb = 0;
    WS->pwm_ctl = WS->pwm_cycle = 0;
    WS->pwm_ln = WS->pwm_rn = 0;
    WS->pwm_w = WS->pwm_r = WS->pwm_frac = 0;
    WS->sh_synced_m68k = 0;

    sh2_reset_one(&WS->sh[0], 0);
    sh2_reset_one(&WS->sh[1], 1);
    md_remap();
}

static void s32x_addon_map(u8 *rmap[256], u8 *wmap[256])
{
    u32 rom_pages = (WS->rom_bytes + 0xFFFFu) >> 16;
    if (!WS->aden || WS->rv) {
        for (u32 p = 0; p < 0x40u; p++)
            rmap[p] = (p < rom_pages) ? ((u8 *)WS->rom + (p << 16)) : 0;
    } else {
        /* ADEN=1 and RV=0: page 0 goes through io_read ($000000..$0000FF = 32X Vector ROM, $100.. = 0/open) */
        rmap[0] = 0;
    }
    if (WS->aden) {
        /* $840000..$85FFFF: Framebuffer when FM == 0 */
        if (!WS->fm) {
            u8 *fb = (u8 *)WS->dram[WS->disp_fb ^ 1u];
            rmap[0x84] = wmap[0x84] = fb;
            rmap[0x85] = wmap[0x85] = fb + 0x10000u;
        }
        /* $880000..$8FFFFF: Fixed first 512 KB of .32x ROM */
        for (u32 p = 0; p < 8u; p++)
            rmap[0x88 + p] = (p < rom_pages) ? ((u8 *)WS->rom + (p << 16)) : 0;
        /* $900000..$9FFFFF: Banked 1 MB window of .32x ROM */
        u32 base_p = (u32)(WS->bank90 & 3u) * 16u;
        for (u32 p = 0; p < 16u; p++)
            rmap[0x90 + p] = (base_p + p < rom_pages) ? ((u8 *)WS->rom + ((base_p + p) << 16)) : 0;
    }
}

static u32 s32x_addon_io_read(u32 a, int size, s32 main_cyc)
{
    u32 page = (a >> 16) & 0xFFu;

    /* $000000..$00FFFF when ADEN=1, RV=0 */
    if (page == 0x00u) {
        u16 w = (a < 0x100u) ? WS->vec68k[(a & 0xFEu) >> 1] :
                (a < WS->rom_bytes ? WS->rom[(a & ~1u) >> 1] : 0xFFFFu);
        return (size == 1) ? ((a & 1u) ? (w & 0xFFu) : (w >> 8)) : w;
    }

    /* $840000..$87FFFF Framebuffer / Overwrite window */
    if (page >= 0x84u && page < 0x88u) {
        s32x_sync_sh2(main_cyc);
        u16 w = WS->dram[WS->disp_fb ^ 1u][(a & 0x1FFFEu) >> 1];
        return (size == 1) ? ((a & 1u) ? (w & 0xFFu) : (w >> 8)) : w;
    }

    if (page == 0xA1u) {
        u32 o = a & 0xFFFFu;
        /* $A130EC..$A130EF: "MARS" hardware identification string! */
        if (o >= 0x30ECu && o <= 0x30EFu) {
            static const u8 mars[4] = {'M', 'A', 'R', 'S'};
            if (size == 1) return mars[o - 0x30ECu];
            return (o == 0x30ECu) ? 0x4D41u : 0x5253u;
        }
        if (o == 0x30F0u || o == 0x30F1u)
            return WS->rv;

        if (o >= 0x5100u && o < 0x5400u) {
            s32x_sync_sh2(main_cyc);
            u16 w = 0;
            if (o >= 0x5200u) {
                w = WS->cram[(o - 0x5200u) >> 1];
            } else if (o >= 0x5180u && o < 0x5190u) {
                w = vdp_reg_read(o - 0x5180u);
            } else if (o >= 0x5130u && o < 0x5140u) {
                w = pwm_reg_read(o - 0x5130u);
            } else if (o >= 0x5120u && o < 0x5130u) {
                w = WS->comm[(o - 0x5120u) >> 1];
            } else {
                switch (o & 0xFFFEu) {
                case 0x5100: w = (u16)((WS->fm << 15) | (WS->ren << 7) | (WS->aden & 1u)); break;
                case 0x5102: w = (u16)(((WS->sh[1].irq_pend & 2u) ? 2u : 0u) | ((WS->sh[0].irq_pend & 2u) ? 1u : 0u)); break;
                case 0x5104: w = WS->bank90 & 3u; break;
                case 0x5106: w = (u16)((WS->fifo_n >= DREQ_FIFO_CAP ? 0x80u : 0u) | (WS->dreq_ctl & 7u) | (WS->rv & 1u)); break;
                case 0x5108: w = (u16)(WS->dreq_src >> 16); break;
                case 0x510A: w = (u16)WS->dreq_src; break;
                case 0x510C: w = (u16)(WS->dreq_dst >> 16); break;
                case 0x510E: w = (u16)WS->dreq_dst; break;
                case 0x5110: w = WS->dreq_len; break;
                case 0x511A: w = 0; break;              /* TV register */
                case 0x5180: break;
                }
                if ((o & 0xFFFEu) == 0x5104u && o == 0x5105u && size == 1)
                    return WS->bank90 & 3u;
            }
            return (size == 1) ? ((a & 1u) ? (w & 0xFFu) : (w >> 8)) : w;
        }
    }
    return (size == 1) ? 0xFFu : 0xFFFFu;
}

static void s32x_addon_io_write(u32 a, u32 v, int size, s32 main_cyc)
{
    u32 page = (a >> 16) & 0xFFu;

    /* $840000..$87FFFF Framebuffer / Overwrite window */
    if (page >= 0x84u && page < 0x88u) {
        if (WS->fm) return;
        s32x_sync_sh2(main_cyc);
        u16 *fb = WS->dram[WS->disp_fb ^ 1u];
        u32 off = a & 0x1FFFFu;
        if (size == 1) {
            if ((u8)v != 0u)
                buf_wb(fb, off, (u8)v);
        } else if (page < 0x86u) {
            fb[off >> 1] = (u16)v;
        } else {
            u16 *dst = &fb[off >> 1];
            u16 cur = *dst;
            if (v & 0xFF00u) cur = (u16)((cur & 0x00FFu) | (v & 0xFF00u));
            if (v & 0x00FFu) cur = (u16)((cur & 0xFF00u) | (v & 0x00FFu));
            *dst = cur;
        }
        return;
    }

    if (page != 0xA1u)
        return;

    u32 o = a & 0xFFFFu;
    if (o == 0x30F1u || (o == 0x30F0u && size == 2)) {
        WS->rv = (u8)(v & 1u);
        md_remap();
        return;
    }
    if (o < 0x5100u || o >= 0x5400u)
        return;

    if (o >= 0x5120u && o < 0x5130u) {
        u32 wi = (o - 0x5120u) >> 1;
        u16 nv = (size == 1)
            ? ((o & 1u) ? (u16)((WS->comm[wi] & 0xFF00u) | (v & 0xFFu))
                        : (u16)((WS->comm[wi] & 0x00FFu) | ((v & 0xFFu) << 8)))
            : (u16)v;
        if (WS->comm[wi] == nv)
            return;
        s32x_sync_sh2(main_cyc);
        WS->comm[wi] = nv;
        sh2_wake_comm(-1);
        return;
    }

    s32x_sync_sh2(main_cyc);

    if (o >= 0x5200u) {
        if (size == 2) WS->cram[(o - 0x5200u) >> 1] = (u16)v;
        return;
    }
    if (o >= 0x5180u && o < 0x5190u) {
        if (size == 1) vdp_reg_write8(o - 0x5180u, (u8)v);
        else           vdp_reg_write16(o - 0x5180u, (u16)v);
        return;
    }
    if (o >= 0x5130u && o < 0x5140u) {
        u16 w = (size == 1) ? (u16)v : (u16)v;
        pwm_reg_write(o - 0x5130u, w);
        return;
    }

    u16 w = (size == 1) ? ((o & 1u) ? (u16)(v & 0xFFu) : (u16)((v & 0xFFu) << 8)) : (u16)v;
    switch (o & 0xFFFEu) {
    case 0x5100: {
        u8 prev_aden = WS->aden, prev_ren = WS->ren, prev_fm = WS->fm;
        if (size == 2 || !(o & 1u))
            WS->fm = (u8)((w >> 15) & 1u);
        if (size == 2 || (o & 1u)) {
            WS->aden = (u8)(w & 1u);
            u8 new_ren = (u8)(((w >> 1) & 1u) ? 1u : 1u); /* b1=RES (1=run, 0=reset when written explicitly as 0 on b1) */
            if ((w & 2u) == 0u && prev_aden && !(w & 1u))
                new_ren = 0;
            WS->ren = 1u;
            (void)new_ren;
            if (WS->aden && !prev_aden) {
                /* Fresh 32X activation: boot both SH-2s cleanly! */
                build_cleanroom_68k_vectors();
                sh2_reset_one(&WS->sh[0], 0);
                sh2_reset_one(&WS->sh[1], 1);
                WS->sh[0].cycles = main_cyc * 2;
                WS->sh[1].cycles = main_cyc * 2;
            } else if ((w & 2u) == 0u && size == 2 && (w & 1u) && !prev_ren) {
                sh2_reset_one(&WS->sh[0], 0);
                sh2_reset_one(&WS->sh[1], 1);
            }
        }
        if (WS->aden != prev_aden || WS->fm != prev_fm)
            md_remap();
        break;
    }
    case 0x5102:
        if (w & 1u) { WS->sh[0].irq_pend |= 0x02u; WS->sh[0].sleep = 0; }
        if (w & 2u) { WS->sh[1].irq_pend |= 0x02u; WS->sh[1].sleep = 0; }
        break;
    case 0x5104:
        if (size == 2 || (o & 1u)) {
            WS->bank90 = (u8)(w & 3u);
            md_remap();
        }
        break;
    case 0x5106:
        if (size == 2 || (o & 1u)) {
            u8 prev_rv = WS->rv;
            WS->dreq_ctl = w & 7u;
            WS->rv = (u8)(w & 1u);
            if (!(w & 4u))
                WS->fifo_r = WS->fifo_w = WS->fifo_n = 0;
            if (WS->rv != prev_rv)
                md_remap();
        }
        break;
    case 0x5108: WS->dreq_src = (WS->dreq_src & 0x0000FFFFu) | ((u32)(w & 0xFFu) << 16); break;
    case 0x510A: WS->dreq_src = (WS->dreq_src & 0x00FF0000u) | (w & 0xFFFEu); break;
    case 0x510C: WS->dreq_dst = (WS->dreq_dst & 0x0000FFFFu) | ((u32)w << 16); break;
    case 0x510E: WS->dreq_dst = (WS->dreq_dst & 0xFFFF0000u) | w; break;
    case 0x5110: WS->dreq_len = w & 0xFFFCu; break;
    case 0x5112:
        if (WS->fifo_n < DREQ_FIFO_CAP) {
            WS->fifo[WS->fifo_w] = w;
            WS->fifo_w = (WS->fifo_w + 1u) & (DREQ_FIFO_CAP - 1u);
            WS->fifo_n++;
            sh2_check_dma_fifo(&WS->sh[0]);
            sh2_check_dma_fifo(&WS->sh[1]);
        }
        break;
    }
}

/* ---- Scanline Timing, SuperVDP Genlock Compositor & PWM Mixer ---- */

static void s32x_addon_scanline(int y, int active_h)
{
    WS->cur_y = (u16)y;
    WS->cur_active_h = (u16)active_h;
    if (y == 0) {
        WS->in_vblank = 0;
    } else if (y == active_h) {
        WS->in_vblank = 1;
        WS->disp_fb = WS->req_fb;
        if (WS->aden) {
            WS->sh[0].irq_pend |= 0x08u;                /* VINT Level 12 */
            WS->sh[1].irq_pend |= 0x08u;
            WS->sh[0].sleep = 0;
            WS->sh[1].sleep = 0;
        }
    }

    if (WS->aden && (y < active_h || WS->hen)) {
        if (--WS->hcount_cur < 0) {
            WS->hcount_cur = WS->hcount_reload;
            WS->sh[0].irq_pend |= 0x04u;                /* HINT Level 10 */
            WS->sh[1].irq_pend |= 0x04u;
            WS->sh[0].sleep = 0;
            WS->sh[1].sleep = 0;
        }
    } else if (!WS->hen) {
        WS->hcount_cur = WS->hcount_reload;
    }
}

static void s32x_addon_draw_line(int y, u16 *out, int width, u16 md_bg)
{
    if (!WS->aden)
        return;
    u32 mode = WS->vdp_mode & 3u;
    if (mode == 0u)
        return;

    const u16 *fb = WS->dram[WS->disp_fb & 1u];
    const u16 *cram = WS->cram;
    u16 pri_inv = (WS->vdp_mode & 0x80u) ? 0x8000u : 0u;
    u32 line_word = fb[y & 0xFFu];

    if (mode == 1u) {                                   /* 256-Color Packed Pixel Mode */
        if (y > 0 && line_word == fb[(y - 1) & 0xFFu] && WS->prev_line_front) {
            const u16 *prev = out - width;
            for (int x = 0; x < width; x++)
                out[x] = prev[x];
            return;
        }
        int all_front = 1;
        if (!(WS->vdp_shift & 1u) && (width & 1) == 0) {
            u32 wpos = line_word;
            for (int x = 0; x < width; x += 2, wpos++) {
                u16 pair = fb[wpos & 0xFFFFu];
                u8 i0 = (u8)(pair >> 8);
                u8 i1 = (u8)pair;
                u16 c0 = cram[i0] ^ pri_inv;
                u16 c1 = cram[i1] ^ pri_inv;
                if (c0 & 0x8000u) {
                    out[x] = c0 & 0x7FFFu;
                } else {
                    all_front = 0;
                    if (i0 != 0u && out[x] == md_bg) out[x] = c0 & 0x7FFFu;
                }
                if (c1 & 0x8000u) {
                    out[x + 1] = c1 & 0x7FFFu;
                } else {
                    all_front = 0;
                    if (i1 != 0u && out[x + 1] == md_bg) out[x + 1] = c1 & 0x7FFFu;
                }
            }
        } else {
            all_front = 0;
            u32 byte_pos = line_word * 2u + (WS->vdp_shift & 1u);
            for (int x = 0; x < width; x++, byte_pos++) {
                u8 idx = buf_rb(fb, byte_pos & 0x1FFFFu);
                u16 c = cram[idx] ^ pri_inv;
                if ((c & 0x8000u) || (idx != 0u && out[x] == md_bg))
                    out[x] = c & 0x7FFFu;
            }
        }
        WS->prev_line_front = (u8)all_front;
    } else if (mode == 2u) {                            /* 15-Bit Direct Color Mode */
        u32 wpos = line_word;
        for (int x = 0; x < width; x++, wpos++) {
            u16 c = fb[wpos & 0xFFFFu] ^ pri_inv;
            if ((c & 0x8000u) || ((c & 0x7FFFu) != 0u && out[x] == md_bg))
                out[x] = c & 0x7FFFu;
        }
    } else {                                            /* Run-Length (RLE) Mode */
        u32 wpos = line_word;
        int x = 0;
        int guard = 0;
        while (x < width && guard++ < 320) {
            u16 pair = fb[wpos & 0xFFFFu];
            wpos++;
            int run = ((pair >> 8) & 0xFFu) + 1;
            u8 idx = (u8)(pair & 0xFFu);
            u16 c = cram[idx] ^ pri_inv;
            int front = (c & 0x8000u) != 0;
            u16 rgb = c & 0x7FFFu;
            while (run-- > 0 && x < width) {
                if (front || (idx != 0u && out[x] == md_bg))
                    out[x] = rgb;
                x++;
            }
        }
    }
}

static void s32x_addon_run_line(s32 main_cyc)
{
    u16 y = WS->cur_y, ah = WS->cur_active_h;
    if (WS->hen || (y & 31u) == 31u || y + 1u == ah || y == ah) {
        WS->in_hblank = 1;
        s32x_sync_sh2(main_cyc);
        WS->in_hblank = 0;
    }
}

static void s32x_addon_end_frame(s32 main_frame_cyc)
{
    s32x_sync_sh2(main_frame_cyc);
    s32 sh_frame = main_frame_cyc * 2;
    WS->sh[0].cycles -= sh_frame;
    WS->sh[1].cycles -= sh_frame;
    WS->sh_synced_m68k = 0;
}

static void s32x_mix_audio(s16 *samples, int count, u32 rate)
{
    if (!rate || count <= 0)
        return;
    u32 avail = WS->pwm_w - WS->pwm_r;
    if (!avail)
        return;
    /* Nearest-neighbor resample avail PWM samples across `count` 48 kHz output samples */
    u32 step16 = (avail << 16) / (u32)count;
    u32 pos16 = 0;
    for (int i = 0; i < count; i++) {
        u32 idx = (WS->pwm_r + (pos16 >> 16)) & (PWM_RING_CAP - 1u);
        s32 mixed = (s32)samples[i] + (s32)WS->pwm_ring[idx];
        if (mixed > 32767) mixed = 32767;
        else if (mixed < -32768) mixed = -32768;
        samples[i] = (s16)mixed;
        pos16 += step16;
    }
    WS->pwm_r = WS->pwm_w;
}

static const struct md_addon s32x_addon = {
    s32x_addon_reset,
    s32x_addon_map,
    s32x_addon_io_read,
    s32x_addon_io_write,
    s32x_addon_run_line,
    s32x_addon_end_frame,
    s32x_mix_audio,
    s32x_addon_draw_line,
    s32x_addon_scanline
};

/* ---- Cartridge Loader ---- */

static void copy_swap16(u16 *dst, const u8 *src, u32 bytes)
{
    u32 words = bytes >> 1;
    for (u32 i = 0; i < words; i++)
        dst[i] = (u16)(((u16)src[i * 2u] << 8) | src[i * 2u + 1u]);
}

const char *s32x_load(u8 *rom, u32 rom_size,
                      const u8 *bios_g, u32 bios_g_sz,
                      const u8 *bios_m, u32 bios_m_sz,
                      const u8 *bios_s, u32 bios_s_sz,
                      int region)
{
    if (!rom || rom_size < 0x400u)
        return "too small to be a Sega 32X (.32x) cartridge";

    s32x_zero(WS, sizeof(*WS));

    /* Detect region from cartridge header $1F0..$1F2 (before word-swap) */
    int reg_c = region;
    if (!reg_c) {
        int j = 0, u = 0, e = 0;
        for (int i = 0x1F0; i < 0x1F3; i++) {
            u8 c = rom[i];
            if (c == 'J' || c == '1' || c == '4') j = 1;
            if (c == 'U' || c == '4' || c == 'F') u = 1;
            if (c == 'E' || c == '8' || c == 'A' || c == 'F') e = 1;
        }
        reg_c = u ? 'U' : j ? 'J' : e ? 'E' : 'U';
    }
    WS->pal_mode = (reg_c == 'E');
    WS->overseas_mode = (reg_c != 'J');

    /* Extract readable title from $150 / $120 */
    char name[49];
    int n = 0;
    for (int pass = 0; pass < 2 && !n; pass++) {
        const u8 *s = rom + (pass ? 0x120 : 0x150);
        for (int i = 0; i < 48; i++) {
            char c = (char)s[i];
            if (c < 32 || c > 126) c = ' ';
            if (c == ' ' && (!n || name[n - 1] == ' ')) continue;
            name[n++] = c;
        }
        while (n && name[n - 1] == ' ') n--;
    }
    name[n] = 0;

    /* Swap ROM byte pairs in-place into host u16 big-endian words (shared by 68000 & both SH-2s!) */
    u32 sz_even = rom_size & ~1u;
    for (u32 i = 0; i < sz_even; i += 2u) {
        u8 t = rom[i];
        rom[i] = rom[i + 1u];
        rom[i + 1u] = t;
    }
    WS->rom = (u16 *)rom;
    WS->rom_bytes = sz_even;

    if (bios_g && bios_g_sz >= 0x100u) {
        copy_swap16(WS->vec68k, bios_g, 0x100u);
        WS->ext_bios_g = 1;
    }
    if (bios_m && bios_m_sz >= 0x800u && bios_m_sz <= sizeof(WS->boot_m)) {
        copy_swap16(WS->boot_m, bios_m, bios_m_sz);
        WS->boot_m_bytes = bios_m_sz;
        WS->ext_bios_m = 1;
    }
    if (bios_s && bios_s_sz >= 0x400u && bios_s_sz <= sizeof(WS->boot_s)) {
        copy_swap16(WS->boot_s, bios_s, bios_s_sz);
        WS->boot_s_bytes = bios_s_sz;
        WS->ext_bios_s = 1;
    }

    char *p = WS->title;
    const char *src = n ? name : "SEGA 32X CARTRIDGE";
    while (*src && p - WS->title < 56) *p++ = *src++;
    const char *tag = (WS->ext_bios_m && WS->ext_bios_s) ? " (Sega 32X BIOS, Dual SH-2)" : " (Sega 32X, Dual SH-2)";
    while (*tag && p - WS->title < 94) *p++ = *tag++;
    *p = 0;

    md_attach_addon(&s32x_addon, WS->pal_mode, WS->overseas_mode, WS->title);
    return 0;
}
