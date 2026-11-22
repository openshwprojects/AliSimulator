/* Atari 520ST / 1040STFM / STE-Blitter home computer: see st.h. */
#pragma GCC optimize("O2")
#include "st.h"

#ifndef ST_HOST
#include "hw.h"
#endif

#define INLINE static inline __attribute__((always_inline))

#define M68K_BUS_ERROR
static u32 st_int_vec(u32 level);
static void st_iack(u32 level);
#define M68K_INT_VEC(level) st_int_vec(level)
#define M68K_IACK(level)    st_iack(level)
#include "m68k.inc"

#define ST_RAM_SIZE     0x200000u       /* 2 MB ST-RAM ($000000..$1FFFFF) */
#define ST_ROM_MAX      0x40000u        /* 256 KB TOS / EmuTOS ROM */
#define ST_FLOPPY_MAX   0x180000u       /* Up to 1.5 MB floppy image */
#define ST_CYCLES_LINE  512
#define ST_LINES_PAL    313             /* 50.05 Hz */
#define ST_LINES_NTSC   263             /* 59.82 Hz */
#define ST_VIS_START    63
#define SND_RING        4096

struct st_mem {
    u8 ram[ST_RAM_SIZE];                /* Word-swapped 2 MB ST-RAM */
    u8 rom[ST_ROM_MAX];                 /* Word-swapped 192K / 256K ROM */
    u8 floppy[ST_FLOPPY_MAX];           /* Unpacked .st / .msa / virtual .prg FAT12 image */
    s16 audio_ring[SND_RING];
};

#ifdef ST_HOST
static struct st_mem st_host_mem;
#define M (&st_host_mem)
#else
#define M ((struct st_mem *)KSEG0(EMU_RAM_PHYS))
#endif

struct st_ym {
    u8 sel;
    u8 reg[16];
    u32 phase[3], noise_phase, env_phase;
    u8 out_bit[3];
    u32 lfsr;
    u8 env_step, env_vol, env_hold, env_att;
};

struct st_mfp {
    u8 gpip, aer, ddr;
    u8 iera, ierb, ipra, iprb, isra, isrb, imra, imrb, vr;
    u8 tacr, tbcr, tcdcr;
    u8 tadr, tbdr, tcdr, tddr;          /* Current countdown counters */
    u8 ta_reload, tb_reload, tc_reload, td_reload;
    u32 ta_acc, tb_acc, tc_acc, td_acc;
    u8 usart_scr, usart_ucr, usart_rsr, usart_tsr, usart_udr;
};

struct st_ikbd {
    u8 acia_ctrl, midi_ctrl;
    u8 rx_fifo[256];
    u8 rx_r, rx_w;
    u8 cmd_buf[16];
    u8 cmd_len, cmd_need;
    u8 mouse_disabled, joy_mode;
    u8 joy0, joy1, prev_joy0, prev_joy1;
    u8 held_keys[128];                  /* Atari ST scancodes currently held */
    char type_q[128];
    u8 tq_r, tq_w, tq_wait;
};

struct st_fdc {
    u32 dma_addr;
    u16 dma_mode, dma_sec_cnt, dma_status;
    u8 cmd, status, track, sector, data;
    u8 irq, busy_polls;
    u8 spt, sides, tracks;              /* Geometry of mounted floppy */
    u8 n_bad_sec;                       /* Pasti .stx per-sector FDC error table */
    struct { u8 trk, side, sec, st; } bad_sec[32];
};

struct st_blitter {
    u16 halftone[16];
    s16 src_x_inc, src_y_inc;
    u32 src_addr;
    u16 endmask1, endmask2, endmask3;
    s16 dst_x_inc, dst_y_inc;
    u32 dst_addr;
    u16 x_count, y_count;
    u8 hop, op, line_num, skew;
};

static struct {
    u8 cpu_inited;
    u8 ext_rom, rom_is_256k, has_floppy, floppy_dirty;
    u32 rom_base, rom_size, floppy_size;
    u8 mmu_cfg;

    /* Shifter */
    u8 vbase_hi, vbase_mid, vbase_lo;
    u8 sync_mode;                       /* bit 1: 1 = 50 Hz PAL, 0 = 60 Hz NTSC */
    u8 shift_res;                       /* 0 = 320x200x4, 1 = 640x200x2, 2 = 640x400x1 */
    u8 hscroll, line_wid;               /* STE $FF8265 / $FF820F */
    u8 ste_pal_used;
    u16 pal_raw[16];
    u16 pal_rgb[16];
    int cur_w, cur_h, cur_line;
    s32 line_start_clk;

    /* Interrupts */
    u8 vbl_pending, hbl_pending;

    /* Subsystems */
    struct st_ym ym;
    struct st_mfp mfp;
    struct st_ikbd ikbd;
    struct st_fdc fdc;
    struct st_blitter blt;

    /* Clean-room HLE TOS state (used only when ext_rom == 0) */
    u32 hle_dta;
    u32 hle_heap;
    u16 hle_fs_idx;
    char hle_fs_pat[12];
    struct {
        u8 used;
        u32 pos, size;
        u16 start_cl;
    } hle_fd[16];

    /* Audio */
    u32 sample_rate, audio_frac;
    s32 audio_last_clk;
    int audio_count;
} ST;

static char info_buf[96];

static const s16 ym_vol_tab[16] = {
       0,   120,   170,   240,   340,   480,   680,   960,
    1360,  1920,  2720,  3840,  5440,  7680, 10880, 15000
};

/* ---- Endian-clean ST-RAM & ROM helpers (m68k.inc word-swapped layout) ---- */
INLINE u8 st_ram_rb(u32 a)
{
    return M->ram[(a & (ST_RAM_SIZE - 1u)) ^ 1u];
}

INLINE void st_ram_wb(u32 a, u8 v)
{
    M->ram[(a & (ST_RAM_SIZE - 1u)) ^ 1u] = v;
}

INLINE u16 st_ram_rw(u32 a)
{
    return *(const u16 *)(M->ram + (a & (ST_RAM_SIZE - 2u)));
}

INLINE void st_ram_ww(u32 a, u16 v)
{
    *(u16 *)(M->ram + (a & (ST_RAM_SIZE - 2u))) = v;
}

static u32 st_ram_rl(u32 a)
{
    return ((u32)st_ram_rw(a) << 16) | st_ram_rw(a + 2u);
}

static void st_ram_wl(u32 a, u32 v)
{
    st_ram_ww(a, (u16)(v >> 16));
    st_ram_ww(a + 2u, (u16)v);
}

INLINE u8 st_rom_rb(u32 off)
{
    return M->rom[(off & (ST_ROM_MAX - 1u)) ^ 1u];
}

INLINE u16 st_rom_rw(u32 off)
{
    return *(const u16 *)(M->rom + (off & (ST_ROM_MAX - 2u)));
}

static void st_rom_put_be16(u32 off, u16 v)
{
    *(u16 *)(M->rom + (off & (ST_ROM_MAX - 2u))) = v;
}

static void st_rom_put_be32(u32 off, u32 v)
{
    st_rom_put_be16(off, (u16)(v >> 16));
    st_rom_put_be16(off + 2u, (u16)v);
}

/* ---- Palette conversion ---- */
static void st_update_pal_entry(int idx)
{
    u16 v = ST.pal_raw[idx] & 0x0FFFu;
    u32 r5, g5, b5;
    if (ST.ste_pal_used) {
        u32 r4 = (((v >> 8) & 7u) << 1) | ((v >> 11) & 1u);
        u32 g4 = (((v >> 4) & 7u) << 1) | ((v >> 7) & 1u);
        u32 b4 = ((v & 7u) << 1) | ((v >> 3) & 1u);
        r5 = (r4 * 31u + 7u) / 15u;
        g5 = (g4 * 31u + 7u) / 15u;
        b5 = (b4 * 31u + 7u) / 15u;
    } else {
        r5 = (((v >> 8) & 7u) * 31u + 3u) / 7u;
        g5 = (((v >> 4) & 7u) * 31u + 3u) / 7u;
        b5 = ((v & 7u) * 31u + 3u) / 7u;
    }
    ST.pal_rgb[idx] = (u16)(r5 | (g5 << 5) | (b5 << 10));
}

/* ---- Audio synthesis: Yamaha YM2149F (2.0 MHz master -> 125 kHz PSG tick) ---- */
static void audio_step(u32 cycles)
{
    if (!ST.sample_rate || !cycles)
        return;
    u32 count = 0;
    while (cycles) {
        u32 chunk = cycles > 16000u ? 16000u : cycles;
        cycles -= chunk;
        u32 num = chunk * ST.sample_rate + ST.audio_frac;
        count += num / 8021247u;
        ST.audio_frac = num % 8021247u;
    }
    if (!count)
        return;

    /* 2.0053 MHz / 16 = 125332 Hz -> *256 = 32084992 */
    u32 ym_step = 32084992u / ST.sample_rate;

    while (count--) {
        s32 mix = 0;
        u32 ep = (u32)ST.ym.reg[11] | ((u32)ST.ym.reg[12] << 8);
        if (!ep) ep = 1u;
        u32 ep8 = ep << 8;
        ST.ym.env_phase += ym_step;
        while (ST.ym.env_phase >= ep8) {
            ST.ym.env_phase -= ep8;
            if (!ST.ym.env_hold) {
                ST.ym.env_step++;
                if (ST.ym.env_step >= 16) {
                    ST.ym.env_step = 0;
                    u8 sh = ST.ym.reg[13] & 0x0Fu;
                    if (!(sh & 0x08u)) {
                        ST.ym.env_att = 0;
                        ST.ym.env_hold = 1;
                    } else {
                        if (sh & 0x02u) ST.ym.env_att ^= 0x0Fu;
                        if (sh & 0x01u) { ST.ym.env_hold = 1; ST.ym.env_step = 15; }
                    }
                }
            }
            ST.ym.env_vol = (ST.ym.env_step ^ ST.ym.env_att) & 15u;
        }

        u32 np = ST.ym.reg[6] & 0x1Fu;
        if (!np) np = 1u;
        u32 np8 = np << 8;
        ST.ym.noise_phase += ym_step;
        while (ST.ym.noise_phase >= np8) {
            ST.ym.noise_phase -= np8;
            u32 fb = ((ST.ym.lfsr >> 0) ^ (ST.ym.lfsr >> 3)) & 1u;
            ST.ym.lfsr = (ST.ym.lfsr >> 1) | (fb << 16);
        }

        u8 mixer = ST.ym.reg[7];
        for (int ch = 0; ch < 3; ch++) {
            u32 tp = (u32)ST.ym.reg[ch * 2] | (((u32)ST.ym.reg[ch * 2 + 1] & 0x0Fu) << 8);
            if (!tp) tp = 1u;
            u32 tp8 = tp << 8;
            ST.ym.phase[ch] += ym_step;
            while (ST.ym.phase[ch] >= tp8) {
                ST.ym.phase[ch] -= tp8;
                ST.ym.out_bit[ch] ^= 1u;
            }
            int t_ok = (mixer & (1u << ch)) || ST.ym.out_bit[ch];
            int n_ok = (mixer & (8u << ch)) || (ST.ym.lfsr & 1u);
            u8 vr = ST.ym.reg[8 + ch];
            u8 vol = (vr & 0x10u) ? ST.ym.env_vol : (vr & 0x0Fu);
            if (vol && t_ok && n_ok)
                mix += ym_vol_tab[vol & 15u] >> 1;
        }

        if (mix > 32767) mix = 32767;
        if (mix < -32768) mix = -32768;
        if (ST.audio_count < SND_RING)
            M->audio_ring[ST.audio_count++] = (s16)mix;
    }
}

static void audio_catch_up(void)
{
    if (!ST.sample_rate)
        return;
    s32 now = m.clock;
    if (now > ST.audio_last_clk) {
        audio_step((u32)(now - ST.audio_last_clk));
        ST.audio_last_clk = now;
    }
}

static void ym_write_reg(u8 r, u8 v)
{
    if (r >= 16)
        return;
    audio_catch_up();
    static const u8 mask[16] = {
        0xFF, 0x0F, 0xFF, 0x0F, 0xFF, 0x0F, 0x1F, 0xFF,
        0x1F, 0x1F, 0x1F, 0xFF, 0xFF, 0x0F, 0xFF, 0xFF
    };
    ST.ym.reg[r] = v & mask[r];
    if (r == 13) {
        ST.ym.env_phase = 0;
        ST.ym.env_step = 0;
        ST.ym.env_hold = 0;
        ST.ym.env_att = (v & 0x04u) ? 0x0Fu : 0x00u;
        ST.ym.env_vol = ST.ym.env_att ^ 0x0Fu;
    }
}

/* ---- Interrupts & MC68901 MFP ---- */
static int ikbd_has_rx(void)
{
    return ST.ikbd.rx_r != ST.ikbd.rx_w;
}

static int ikbd_irq_active(void)
{
    return ikbd_has_rx() && ((ST.ikbd.acia_ctrl & 0x80u) != 0);
}

static int mfp_top_irq_bit(void)
{
    u16 ier = (u16)(((u16)ST.mfp.iera << 8) | ST.mfp.ierb);
    u16 ipr = (u16)(((u16)ST.mfp.ipra << 8) | ST.mfp.iprb);
    u16 imr = (u16)(((u16)ST.mfp.imra << 8) | ST.mfp.imrb);
    u16 isr = (u16)(((u16)ST.mfp.isra << 8) | ST.mfp.isrb);
    u16 active = ipr & ier & imr;
    if (!active)
        return -1;
    int sw_eoi = (ST.mfp.vr & 0x08u) != 0;
    for (int b = 15; b >= 0; b--) {
        if (sw_eoi && (isr & (1u << b)))
            return -1;                  /* Higher or equal priority ISR still in service */
        if (active & (1u << b))
            return b;
    }
    return -1;
}

static void st_update_ipl(void)
{
    u32 lvl = 0;
    if (mfp_top_irq_bit() >= 0)
        lvl = 6;
    else if (ST.vbl_pending)
        lvl = 4;
    else if (ST.hbl_pending)
        lvl = 2;
    if (m.ipl != lvl) {
        m.ipl = lvl;
        check_pending();
    }
}

static void mfp_raise_irq(int bit)
{
    if (bit >= 8) {
        u8 mask = (u8)(1u << (bit - 8));
        if (ST.mfp.iera & mask)
            ST.mfp.ipra |= mask;
    } else {
        u8 mask = (u8)(1u << bit);
        if (ST.mfp.ierb & mask)
            ST.mfp.iprb |= mask;
    }
    st_update_ipl();
}

static u32 st_int_vec(u32 level)
{
    if (level == 6) {
        int b = mfp_top_irq_bit();
        if (b >= 0) {
            if (b >= 8) ST.mfp.ipra &= (u8)~(1u << (b - 8));
            else        ST.mfp.iprb &= (u8)~(1u << b);
            if (ST.mfp.vr & 0x08u) {
                if (b >= 8) ST.mfp.isra |= (u8)(1u << (b - 8));
                else        ST.mfp.isrb |= (u8)(1u << b);
            }
            return (u32)((ST.mfp.vr & 0xF0u) | (u32)b);
        }
        return 24 + 6;
    }
    if (level == 4) {
        ST.vbl_pending = 0;
        return 28;
    }
    if (level == 2) {
        ST.hbl_pending = 0;
        return 26;
    }
    return 24 + level;
}

static void st_iack(u32 level)
{
    (void)level;
    /* Re-assert ACIA MFP bit 6 if more IKBD bytes remain queued */
    if (ikbd_irq_active())
        mfp_raise_irq(6);
    st_update_ipl();
}

/* Step MFP Timers A, B (delay modes), C, D by `cpu_cycles` (8.021 MHz CPU vs 2.4576 MHz MFP XTAL) */
static void mfp_step_timers(u32 cpu_cycles)
{
    static const u16 prescale[8] = {0, 4, 10, 16, 50, 64, 100, 200};
    /* MFP XTAL ticks * 256 per CPU cycle = 2457600 * 256 / 8021247 = 78 */
    u32 ticks256 = cpu_cycles * 78u;

    /* Timer A (IERA bit 5 -> irq bit 13) */
    u8 ta_mode = ST.mfp.tacr & 7u;
    if (ta_mode >= 1 && ta_mode <= 7) {
        u32 step = (u32)prescale[ta_mode] << 8;
        ST.mfp.ta_acc += ticks256;
        while (ST.mfp.ta_acc >= step) {
            ST.mfp.ta_acc -= step;
            if (--ST.mfp.tadr == 0) {
                ST.mfp.tadr = ST.mfp.ta_reload ? ST.mfp.ta_reload : 255u;
                mfp_raise_irq(13);
            }
        }
    }

    /* Timer B delay mode (TBCR 1..7 -> irq bit 8; TBCR == 8 is HBL event count!) */
    u8 tb_mode = ST.mfp.tbcr & 15u;
    if (tb_mode >= 1 && tb_mode <= 7) {
        u32 step = (u32)prescale[tb_mode] << 8;
        ST.mfp.tb_acc += ticks256;
        while (ST.mfp.tb_acc >= step) {
            ST.mfp.tb_acc -= step;
            if (--ST.mfp.tbdr == 0) {
                ST.mfp.tbdr = ST.mfp.tb_reload ? ST.mfp.tb_reload : 255u;
                mfp_raise_irq(8);
            }
        }
    }

    /* Timer C (TCDCR bits 6..4 -> irq bit 5: 200 Hz system timer!) */
    u8 tc_mode = (ST.mfp.tcdcr >> 4) & 7u;
    if (tc_mode >= 1) {
        u32 step = (u32)prescale[tc_mode] << 8;
        ST.mfp.tc_acc += ticks256;
        while (ST.mfp.tc_acc >= step) {
            ST.mfp.tc_acc -= step;
            if (--ST.mfp.tcdr == 0) {
                ST.mfp.tcdr = ST.mfp.tc_reload ? ST.mfp.tc_reload : 255u;
                mfp_raise_irq(5);
            }
        }
    }

    /* Timer D (TCDCR bits 2..0 -> irq bit 4) */
    u8 td_mode = ST.mfp.tcdcr & 7u;
    if (td_mode >= 1) {
        u32 step = (u32)prescale[td_mode] << 8;
        ST.mfp.td_acc += ticks256;
        while (ST.mfp.td_acc >= step) {
            ST.mfp.td_acc -= step;
            if (--ST.mfp.tddr == 0) {
                ST.mfp.tddr = ST.mfp.td_reload ? ST.mfp.td_reload : 255u;
                mfp_raise_irq(4);
            }
        }
    }
}

static void mfp_hbl_event_tick(void)
{
    if ((ST.mfp.tbcr & 15u) == 8u) {    /* Event Count mode */
        if (--ST.mfp.tbdr == 0) {
            ST.mfp.tbdr = ST.mfp.tb_reload ? ST.mfp.tb_reload : 255u;
            mfp_raise_irq(8);
        }
    }
}

/* ---- Hitachi HD6301 IKBD + MC6850 ACIA ---- */
static void ikbd_push(u8 b)
{
    u8 next = (u8)(ST.ikbd.rx_w + 1u);
    if (next != ST.ikbd.rx_r) {
        ST.ikbd.rx_fifo[ST.ikbd.rx_w] = b;
        ST.ikbd.rx_w = next;
        if (ST.ikbd.acia_ctrl & 0x80u)
            mfp_raise_irq(6);
    }
}

static void ikbd_tx_byte(u8 v)
{
    if (ST.ikbd.cmd_need) {
        ST.ikbd.cmd_buf[ST.ikbd.cmd_len++] = v;
        if (ST.ikbd.cmd_len < ST.ikbd.cmd_need)
            return;
        ST.ikbd.cmd_need = 0;
        u8 cmd = ST.ikbd.cmd_buf[0];
        if (cmd == 0x80u && ST.ikbd.cmd_buf[1] == 0x01u) {
            ST.ikbd.rx_r = ST.ikbd.rx_w = 0;
            ST.ikbd.mouse_disabled = 0;
            ST.ikbd.joy_mode = 1;       /* Event reporting */
            ikbd_push(0xF1u);           /* IKBD self-test OK */
        }
        ST.ikbd.cmd_len = 0;
        return;
    }

    ST.ikbd.cmd_buf[0] = v;
    ST.ikbd.cmd_len = 1;
    switch (v) {
    case 0x80: ST.ikbd.cmd_need = 2; break;                 /* Reset (80 01) */
    case 0x07: ST.ikbd.cmd_need = 2; break;                 /* Mouse button action */
    case 0x08: ST.ikbd.mouse_disabled = 0; ST.ikbd.cmd_len = 0; break; /* Relative mouse */
    case 0x09: ST.ikbd.cmd_need = 5; break;                 /* Abs mouse */
    case 0x0A: ST.ikbd.cmd_need = 3; break;                 /* Mouse keycode */
    case 0x0B: case 0x0C: ST.ikbd.cmd_need = 3; break;
    case 0x10: case 0x0F: ST.ikbd.cmd_len = 0; break;
    case 0x12: ST.ikbd.mouse_disabled = 1; ST.ikbd.cmd_len = 0; break;
    case 0x14: ST.ikbd.joy_mode = 1; ST.ikbd.cmd_len = 0; break;       /* Joy event reporting */
    case 0x15: ST.ikbd.joy_mode = 2; ST.ikbd.cmd_len = 0; break;       /* Joy interrogation */
    case 0x16:                                              /* Interrogate joysticks */
        ikbd_push(0xFDu);
        ikbd_push(ST.ikbd.joy0);
        ikbd_push(ST.ikbd.joy1);
        ST.ikbd.cmd_len = 0;
        break;
    case 0x17: ST.ikbd.cmd_need = 2; break;
    case 0x19: ST.ikbd.cmd_need = 7; break;
    case 0x1A: ST.ikbd.joy_mode = 0; ST.ikbd.cmd_len = 0; break;       /* Disable joysticks */
    case 0x1B: ST.ikbd.cmd_need = 7; break;                 /* Set clock */
    case 0x1C:                                              /* Read BCD clock: 26-11-20 12:00:00 */
        ikbd_push(0xFCu);
        ikbd_push(0x26u); ikbd_push(0x11u); ikbd_push(0x20u);
        ikbd_push(0x12u); ikbd_push(0x00u); ikbd_push(0x00u);
        ST.ikbd.cmd_len = 0;
        break;
    default:
        ST.ikbd.cmd_len = 0;
        break;
    }
}

/* Map USB HID usage -> Atari ST scancode */
static u8 st_hid_to_scancode(u8 u)
{
    static const u8 alpha[26] = {
        0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32,
        0x31, 0x18, 0x19, 0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C
    };
    if (u >= 0x04 && u <= 0x1D) return alpha[u - 0x04];
    if (u >= 0x1E && u <= 0x26) return (u8)(0x02 + (u - 0x1E)); /* 1..9 */
    if (u == 0x27) return 0x0B;                                 /* 0 */
    if (u == 0x28 || u == 0x58) return 0x1C;                    /* Return */
    if (u == 0x29) return 0x01;                                 /* Esc */
    if (u == 0x2A) return 0x0E;                                 /* Backspace */
    if (u == 0x2B) return 0x0F;                                 /* Tab */
    if (u == 0x2C) return 0x39;                                 /* Space */
    if (u == 0x2D) return 0x0C;                                 /* - */
    if (u == 0x2E) return 0x0D;                                 /* = */
    if (u == 0x2F) return 0x1A;                                 /* [ */
    if (u == 0x30) return 0x1B;                                 /* ] */
    if (u == 0x33) return 0x27;                                 /* ; */
    if (u == 0x34) return 0x28;                                 /* ' */
    if (u == 0x36) return 0x33;                                 /* , */
    if (u == 0x37) return 0x34;                                 /* . */
    if (u == 0x38) return 0x35;                                 /* / */
    if (u >= 0x3A && u <= 0x43) return (u8)(0x3B + (u - 0x3A)); /* F1..F10 */
    if (u == 0x4F) return 0x4D;                                 /* Right */
    if (u == 0x50) return 0x4B;                                 /* Left */
    if (u == 0x51) return 0x50;                                 /* Down */
    if (u == 0x52) return 0x48;                                 /* Up */
    if (u == 0xE0 || u == 0xE4) return 0x1D;                    /* Control */
    if (u == 0xE1) return 0x2A;                                 /* LShift */
    if (u == 0xE5) return 0x36;                                 /* RShift */
    if (u == 0xE2 || u == 0xE6) return 0x38;                    /* Alternate */
    return 0;
}

static u8 st_ascii_to_scancode(char c, int *need_shift)
{
    *need_shift = 0;
    if (c >= 'a' && c <= 'z') return st_hid_to_scancode((u8)(0x04 + (c - 'a')));
    if (c >= 'A' && c <= 'Z') { *need_shift = 1; return st_hid_to_scancode((u8)(0x04 + (c - 'A'))); }
    if (c >= '1' && c <= '9') return (u8)(0x02 + (c - '1'));
    if (c == '0') return 0x0B;
    if (c == ' ') return 0x39;
    if (c == '\r' || c == '\n') return 0x1C;
    if (c == '\b') return 0x0E;
    if (c == '\t') return 0x0F;
    if (c == '.') return 0x34;
    if (c == ',') return 0x33;
    if (c == '-') return 0x0C;
    if (c == '/') return 0x35;
    if (c == ':') { *need_shift = 1; return 0x27; }
    return 0;
}

void st_type(char c)
{
    u8 next = (u8)((ST.ikbd.tq_w + 1u) & 127u);
    if (next != ST.ikbd.tq_r) {
        ST.ikbd.type_q[ST.ikbd.tq_w] = c;
        ST.ikbd.tq_w = next;
    }
}

static void st_poll_inputs(u16 pad, const u8 *hid_usages, int hid_n)
{
    u8 now[128];
    for (int i = 0; i < 128; i++)
        now[i] = 0;
    for (int i = 0; i < hid_n; i++) {
        u8 sc = st_hid_to_scancode(hid_usages[i]);
        if (sc && sc < 128u)
            now[sc] = 1;
    }
    /* Pad secondary bindings: B = Space, Start = F1 (0x3B) / Return, Select = F2 (0x3C) */
    if (pad & ST_B)      now[0x39] = 1;
    if (pad & ST_START)  now[0x3B] = 1;
    if (pad & ST_SELECT) now[0x3C] = 1;

    for (u8 sc = 1; sc < 128u; sc++) {
        if (now[sc] && !ST.ikbd.held_keys[sc])
            ikbd_push(sc);
        else if (!now[sc] && ST.ikbd.held_keys[sc])
            ikbd_push((u8)(sc | 0x80u));
        ST.ikbd.held_keys[sc] = now[sc];
    }

    /* Typed character queue */
    if (ST.ikbd.tq_wait) {
        ST.ikbd.tq_wait--;
    } else if (ST.ikbd.tq_r != ST.ikbd.tq_w) {
        char ch = ST.ikbd.type_q[ST.ikbd.tq_r];
        ST.ikbd.tq_r = (u8)((ST.ikbd.tq_r + 1u) & 127u);
        int sh = 0;
        u8 sc = st_ascii_to_scancode(ch, &sh);
        if (sc) {
            if (sh) ikbd_push(0x2Au);
            ikbd_push(sc);
            ikbd_push((u8)(sc | 0x80u));
            if (sh) ikbd_push(0xAAu);
            ST.ikbd.tq_wait = 4;
        }
    }

    /* Joystick 1 (Atari ST primary game port!) */
    u8 j1 = 0;
    if (pad & ST_UP)    j1 |= 0x01u;
    if (pad & ST_DOWN)  j1 |= 0x02u;
    if (pad & ST_LEFT)  j1 |= 0x04u;
    if (pad & ST_RIGHT) j1 |= 0x08u;
    if (pad & ST_A)     j1 |= 0x80u;
    ST.ikbd.joy1 = j1;
    if (j1 != ST.ikbd.prev_joy1 && ST.ikbd.joy_mode == 1) {
        ikbd_push(0xFFu);               /* Joystick 1 packet header */
        ikbd_push(j1);
    }
    ST.ikbd.prev_joy1 = j1;
}

/* ---- Atari DMA + Western Digital WD1772 FDC ---- */
static u32 fdc_lba_offset(u8 track, u8 side, u8 sec1)
{
    u32 sides = ST.fdc.sides ? ST.fdc.sides : 1u;
    u32 spt = ST.fdc.spt ? ST.fdc.spt : 9u;
    u32 s = (sec1 >= 1u && sec1 <= spt) ? (u32)(sec1 - 1u) : 0u;
    u32 lba = ((u32)track * sides + (side & (sides - 1u))) * spt + s;
    return lba * 512u;
}

static u8 fdc_sector_err(u8 track, u8 side, u8 sec1)
{
    for (u8 i = 0; i < ST.fdc.n_bad_sec; i++) {
        if (ST.fdc.bad_sec[i].trk == track && ST.fdc.bad_sec[i].side == side && ST.fdc.bad_sec[i].sec == sec1)
            return ST.fdc.bad_sec[i].st;
    }
    return 0;
}

static void fdc_complete_irq(void)
{
    ST.fdc.irq = 1;
    mfp_raise_irq(7);                   /* MFP GPIP5 / IERB bit 7 -> Vector VR+7 ($11C) */
}

static void fdc_exec_cmd(u8 cmd)
{
    ST.fdc.cmd = cmd;
    ST.fdc.irq = 0;
    u8 hi = cmd & 0xF0u;
    /* YM2149 Port A (R#14): bit 0 = active-low side 1, bit 1 = active-low Drive A, bit 2 = active-low Drive B */
    u8 pa = ST.ym.reg[14];
    int drv_a = (pa & 0x02u) == 0;
    u8 side = (pa & 0x01u) ? 0u : 1u;

    if (hi == 0x00u) {                  /* RESTORE */
        ST.fdc.track = 0;
        ST.fdc.status = 0x84u;          /* MotorOn | TR00 */
        fdc_complete_irq();
    } else if (hi == 0x10u) {           /* SEEK */
        ST.fdc.track = ST.fdc.data < 86u ? ST.fdc.data : 85u;
        ST.fdc.status = (u8)(0x80u | (ST.fdc.track == 0 ? 0x04u : 0x00u));
        fdc_complete_irq();
    } else if (hi >= 0x20u && hi <= 0x70u) { /* STEP / STEP-IN / STEP-OUT */
        int dir = (hi >= 0x60u) ? -1 : 1;
        int nt = (int)ST.fdc.track + dir;
        if (nt < 0) nt = 0;
        if (nt > 85) nt = 85;
        if ((cmd & 0x10u) || hi >= 0x40u)
            ST.fdc.track = (u8)nt;
        ST.fdc.status = (u8)(0x80u | (ST.fdc.track == 0 ? 0x04u : 0x00u));
        fdc_complete_irq();
    } else if (hi == 0x80u || hi == 0x90u) { /* READ SECTOR / MULTIPLE */
        int multi = (hi == 0x90u);
        if (!ST.has_floppy || !drv_a || ST.fdc.sector < 1u || ST.fdc.sector > ST.fdc.spt ||
            (side >= ST.fdc.sides)) {
            ST.fdc.status = 0x90u;      /* MotorOn | RNF */
            ST.fdc.dma_status = 0x01u;
            fdc_complete_irq();
            return;
        }
        u8 err_st = 0;
        while (ST.fdc.dma_sec_cnt > 0 && ST.fdc.sector <= ST.fdc.spt) {
            u32 off = fdc_lba_offset(ST.fdc.track, side, ST.fdc.sector);
            for (u32 i = 0; i < 512u; i++) {
                u8 b = (off + i < ST.floppy_size) ? M->floppy[off + i] : 0;
                if (ST.fdc.dma_addr < ST_RAM_SIZE)
                    st_ram_wb(ST.fdc.dma_addr, b);
                ST.fdc.dma_addr = (ST.fdc.dma_addr + 1u) & 0xFFFFFFu;
            }
            err_st = fdc_sector_err(ST.fdc.track, side, ST.fdc.sector);
            ST.fdc.dma_sec_cnt--;
            if (err_st || !multi)
                break;
            ST.fdc.sector++;
        }
        ST.fdc.status = (u8)(0x80u | (err_st & 0x7Fu)); /* MotorOn | Pasti FDC error bits */
        ST.fdc.dma_status = (ST.fdc.dma_sec_cnt ? 0x03u : 0x01u);
        fdc_complete_irq();
    } else if (hi == 0xA0u || hi == 0xB0u) { /* WRITE SECTOR / MULTIPLE */
        int multi = (hi == 0xB0u);
        if (!ST.has_floppy || !drv_a || ST.fdc.sector < 1u || ST.fdc.sector > ST.fdc.spt ||
            (side >= ST.fdc.sides)) {
            ST.fdc.status = 0x90u;
            ST.fdc.dma_status = 0x01u;
            fdc_complete_irq();
            return;
        }
        while (ST.fdc.dma_sec_cnt > 0 && ST.fdc.sector <= ST.fdc.spt) {
            u32 off = fdc_lba_offset(ST.fdc.track, side, ST.fdc.sector);
            for (u32 i = 0; i < 512u; i++) {
                u8 b = (ST.fdc.dma_addr < ST_RAM_SIZE) ? st_ram_rb(ST.fdc.dma_addr) : 0;
                if (off + i < ST_FLOPPY_MAX) {
                    M->floppy[off + i] = b;
                    if (off + i >= ST.floppy_size)
                        ST.floppy_size = off + i + 1u;
                }
                ST.fdc.dma_addr = (ST.fdc.dma_addr + 1u) & 0xFFFFFFu;
            }
            ST.floppy_dirty = 1;
            ST.fdc.dma_sec_cnt--;
            if (!multi)
                break;
            ST.fdc.sector++;
        }
        ST.fdc.status = 0x80u;
        ST.fdc.dma_status = (ST.fdc.dma_sec_cnt ? 0x03u : 0x01u);
        fdc_complete_irq();
    } else if (hi == 0xC0u) {           /* READ ADDRESS */
        if (!ST.has_floppy || !drv_a) {
            ST.fdc.status = 0x90u;
        } else {
            u8 hdr[6] = { ST.fdc.track, side, 1, 2, 0, 0 };
            for (int i = 0; i < 6; i++) {
                if (ST.fdc.dma_addr < ST_RAM_SIZE)
                    st_ram_wb(ST.fdc.dma_addr, hdr[i]);
                ST.fdc.dma_addr = (ST.fdc.dma_addr + 1u) & 0xFFFFFFu;
            }
            ST.fdc.status = 0x80u;
        }
        fdc_complete_irq();
    } else if (hi == 0xD0u) {           /* FORCE INTERRUPT */
        ST.fdc.status = (u8)(0x80u | (ST.fdc.track == 0 ? 0x04u : 0x00u));
        if (cmd & 0x0Fu)
            fdc_complete_irq();
        else
            ST.fdc.irq = 0;
    } else {
        ST.fdc.status = 0x80u;
        fdc_complete_irq();
    }
}

/* ---- Atari STE Hardware Blitter ($FF8A00..$FF8A3D) ---- */
static u16 blt_apply_op(u8 op, u16 s, u16 d)
{
    switch (op & 15u) {
    case 0:  return 0x0000u;
    case 1:  return s & d;
    case 2:  return s & (u16)~d;
    case 3:  return s;
    case 4:  return (u16)~s & d;
    case 5:  return d;
    case 6:  return s ^ d;
    case 7:  return s | d;
    case 8:  return (u16)~(s | d);
    case 9:  return (u16)~(s ^ d);
    case 10: return (u16)~d;
    case 11: return s | (u16)~d;
    case 12: return (u16)~s;
    case 13: return (u16)~s | d;
    case 14: return (u16)~(s & d);
    default: return 0xFFFFu;
    }
}

static void blt_execute(void)
{
    u32 xcnt = ST.blt.x_count ? ST.blt.x_count : 65536u;
    u32 ycnt = ST.blt.y_count;
    if (!ycnt) {
        ST.blt.line_num &= (u8)~0x80u;
        return;
    }
    int skew = ST.blt.skew & 15u;
    int nfsr = (ST.blt.skew & 0x40u) != 0;
    int fxsr = (ST.blt.skew & 0x80u) != 0;
    int smudge = (ST.blt.line_num & 0x20u) != 0;
    u8 hop = ST.blt.hop & 3u;
    u8 op = ST.blt.op & 15u;
    int rev = ST.blt.src_x_inc < 0;

    while (ycnt--) {
        u32 sbuf = 0;
        if (fxsr && (hop & 2u)) {
            u16 w = (ST.blt.src_addr < ST_RAM_SIZE) ? st_ram_rw(ST.blt.src_addr) : 0;
            ST.blt.src_addr = (u32)((s32)ST.blt.src_addr + ST.blt.src_x_inc) & 0xFFFFFFu;
            sbuf = w;
        }
        for (u32 x = 0; x < xcnt; x++) {
            u16 mask = (x == 0) ? ST.blt.endmask1 : (x == xcnt - 1u) ? ST.blt.endmask3 : ST.blt.endmask2;
            u16 src_w = 0xFFFFu;
            if (hop & 2u) {
                int do_read = !(nfsr && x == xcnt - 1u && xcnt > 1u);
                u16 nw = 0;
                if (do_read) {
                    nw = (ST.blt.src_addr < ST_RAM_SIZE) ? st_ram_rw(ST.blt.src_addr) : 0;
                    if (x < xcnt - 1u)
                        ST.blt.src_addr = (u32)((s32)ST.blt.src_addr + ST.blt.src_x_inc) & 0xFFFFFFu;
                }
                if (rev)
                    sbuf = ((u32)nw << 16) | (sbuf & 0xFFFFu);
                else
                    sbuf = (sbuf << 16) | nw;
                src_w = (u16)(sbuf >> skew);
                if (rev)
                    sbuf >>= 16;
            }
            u8 ht_idx = smudge ? (src_w & 15u) : (ST.blt.line_num & 15u);
            u16 ht = ST.blt.halftone[ht_idx];
            u16 hop_out = (hop == 0) ? 0xFFFFu : (hop == 1) ? ht : (hop == 2) ? src_w : (src_w & ht);

            u16 dst_old = (ST.blt.dst_addr < ST_RAM_SIZE) ? st_ram_rw(ST.blt.dst_addr) : 0;
            u16 res = blt_apply_op(op, hop_out, dst_old);
            u16 dst_new = (res & mask) | (dst_old & (u16)~mask);
            if (ST.blt.dst_addr < ST_RAM_SIZE)
                st_ram_ww(ST.blt.dst_addr, dst_new);

            if (x < xcnt - 1u)
                ST.blt.dst_addr = (u32)((s32)ST.blt.dst_addr + ST.blt.dst_x_inc) & 0xFFFFFFu;
        }
        ST.blt.src_addr = (u32)((s32)ST.blt.src_addr + ST.blt.src_y_inc) & 0xFFFFFFu;
        ST.blt.dst_addr = (u32)((s32)ST.blt.dst_addr + ST.blt.dst_y_inc) & 0xFFFFFFu;
        if (ST.blt.dst_y_inc >= 0)
            ST.blt.line_num = (u8)((ST.blt.line_num & 0xF0u) | ((ST.blt.line_num + 1u) & 15u));
        else
            ST.blt.line_num = (u8)((ST.blt.line_num & 0xF0u) | ((ST.blt.line_num - 1u) & 15u));
    }
    ST.blt.y_count = 0;
    ST.blt.line_num &= (u8)~0x80u;      /* Clear BUSY */
}

/* ---- Clean-room Built-in TOS / GEMDOS / BIOS / XBIOS Fallback ---- */
static u16 fat12_get_le16(const u8 *p) { return (u16)(p[0] | ((u16)p[1] << 8)); }
static u32 fat12_get_le32(const u8 *p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); }

static u16 st_fat12_next(u16 cl)
{
    u16 bps = fat12_get_le16(M->floppy + 11); if (!bps) bps = 512;
    u16 rsvd = fat12_get_le16(M->floppy + 14); if (!rsvd) rsvd = 1;
    const u8 *fat = M->floppy + (u32)rsvd * bps;
    u32 off = cl + (cl >> 1);
    u16 v = (u16)(fat[off] | ((u16)fat[off + 1] << 8));
    return (cl & 1u) ? (v >> 4) : (v & 0xFFFu);
}

static int st_fat12_find_entry(const char *path, u8 *out_ent)
{
    if (!ST.has_floppy) return -1;
    u16 bps = fat12_get_le16(M->floppy + 11); if (bps != 512) return -1;
    u8 spc = M->floppy[13]; if (!spc) spc = 2;
    u16 rsvd = fat12_get_le16(M->floppy + 14); if (!rsvd) rsvd = 1;
    u8 nfats = M->floppy[16]; if (!nfats) nfats = 2;
    u16 nroot = fat12_get_le16(M->floppy + 17); if (!nroot) nroot = 112;
    u16 spf = fat12_get_le16(M->floppy + 22); if (!spf) spf = 3;

    u32 root_off = (u32)(rsvd + nfats * spf) * 512u;
    u32 data_off = root_off + ((u32)nroot * 32u + 511u) / 512u * 512u;
    u32 cl_bytes = (u32)spc * 512u;

    /* Skip drive prefix "A:" */
    if (path[0] && path[1] == ':') path += 2;
    while (*path == '\\' || *path == '/') path++;

    u16 cur_cl = 0;                     /* 0 = root directory */
    while (*path) {
        char want[11];
        for (int i = 0; i < 11; i++) want[i] = ' ';
        int p = 0;
        while (*path && *path != '\\' && *path != '/' && *path != '.') {
            char c = *path++;
            if (c == '*') {
                while (p < 8) want[p++] = '?';
            } else {
                if (c >= 'a' && c <= 'z') c = (char)(c - 32);
                if (p < 8) want[p++] = c;
            }
        }
        if (*path == '.') {
            path++;
            p = 8;
            while (*path && *path != '\\' && *path != '/') {
                char c = *path++;
                if (c == '*') {
                    while (p < 11) want[p++] = '?';
                } else {
                    if (c >= 'a' && c <= 'z') c = (char)(c - 32);
                    if (p < 11) want[p++] = c;
                }
            }
        }
        int is_last = (*path == 0);
        while (*path == '\\' || *path == '/') path++;

        int found = 0;
        if (cur_cl == 0) {
            for (u32 e = 0; e < nroot && root_off + e * 32u + 32u <= ST.floppy_size; e++) {
                const u8 *de = M->floppy + root_off + e * 32u;
                if (de[0] == 0) break;
                if (de[0] == 0xE5u || (de[11] & 0x08u)) continue;
                int m11 = 1;
                for (int k = 0; k < 11; k++)
                    if (want[k] != '?' && want[k] != '*' && de[k] != (u8)want[k]) { m11 = 0; break; }
                if (m11) {
                    for (int k = 0; k < 32; k++) out_ent[k] = de[k];
                    cur_cl = fat12_get_le16(de + 26);
                    found = 1;
                    break;
                }
            }
        } else {
            u16 cl = cur_cl;
            while (cl >= 2u && cl < 0xFF8u && !found) {
                u32 off = data_off + (u32)(cl - 2u) * cl_bytes;
                for (u32 e = 0; e < cl_bytes / 32u && off + e * 32u + 32u <= ST.floppy_size; e++) {
                    const u8 *de = M->floppy + off + e * 32u;
                    if (de[0] == 0) break;
                    if (de[0] == 0xE5u || (de[11] & 0x08u)) continue;
                    int m11 = 1;
                    for (int k = 0; k < 11; k++)
                        if (want[k] != '?' && want[k] != '*' && de[k] != (u8)want[k]) { m11 = 0; break; }
                    if (m11) {
                        for (int k = 0; k < 32; k++) out_ent[k] = de[k];
                        cur_cl = fat12_get_le16(de + 26);
                        found = 1;
                        break;
                    }
                }
                cl = st_fat12_next(cl);
            }
        }
        if (!found) return -1;
        if (is_last) return 0;
    }
    return -1;
}

static u32 st_fat12_read_chain(u16 start_cl, u32 file_off, u32 count, u32 dst_ram, u32 fsize)
{
    if (file_off >= fsize) return 0;
    if (file_off + count > fsize) count = fsize - file_off;
    u16 bps = fat12_get_le16(M->floppy + 11); if (!bps) bps = 512;
    u8 spc = M->floppy[13]; if (!spc) spc = 2;
    u16 rsvd = fat12_get_le16(M->floppy + 14); if (!rsvd) rsvd = 1;
    u8 nfats = M->floppy[16]; if (!nfats) nfats = 2;
    u16 nroot = fat12_get_le16(M->floppy + 17); if (!nroot) nroot = 112;
    u16 spf = fat12_get_le16(M->floppy + 22); if (!spf) spf = 3;
    u32 data_off = (u32)(rsvd + nfats * spf) * 512u + ((u32)nroot * 32u + 511u) / 512u * 512u;
    u32 cl_bytes = (u32)spc * 512u;

    u32 skip_cl = file_off / cl_bytes;
    u32 in_cl = file_off % cl_bytes;
    u16 cl = start_cl;
    for (u32 i = 0; i < skip_cl && cl >= 2u && cl < 0xFF8u; i++)
        cl = st_fat12_next(cl);

    u32 got = 0;
    while (got < count && cl >= 2u && cl < 0xFF8u) {
        u32 base = data_off + (u32)(cl - 2u) * cl_bytes;
        while (in_cl < cl_bytes && got < count) {
            u8 b = (base + in_cl < ST.floppy_size) ? M->floppy[base + in_cl] : 0;
            if (dst_ram + got < ST_RAM_SIZE)
                st_ram_wb(dst_ram + got, b);
            got++;
            in_cl++;
        }
        in_cl = 0;
        cl = st_fat12_next(cl);
    }
    return got;
}

/* Relocate & launch an Atari ST .PRG/.TOS image from `src_buf` (size `src_len`) into ST-RAM! */
static u32 st_load_and_reloc_prg(const u8 *src, u32 src_len, u32 *out_bp)
{
    if (src_len < 28u || src[0] != 0x60u || src[1] != 0x1Au)
        return 0;
    u32 tlen = ((u32)src[2] << 24) | ((u32)src[3] << 16) | ((u32)src[4] << 8) | src[5];
    u32 dlen = ((u32)src[6] << 24) | ((u32)src[7] << 16) | ((u32)src[8] << 8) | src[9];
    u32 blen = ((u32)src[10] << 24) | ((u32)src[11] << 16) | ((u32)src[12] << 8) | src[13];
    u32 slen = ((u32)src[14] << 24) | ((u32)src[15] << 16) | ((u32)src[16] << 8) | src[17];
    u16 absflag = (u16)((src[26] << 8) | src[27]);

    u32 bp = (ST.hle_heap + 255u) & ~255u;
    u32 text_base = bp + 256u;
    u32 data_base = text_base + tlen;
    u32 bss_base  = data_base + dlen;
    u32 end_addr  = (bss_base + blen + 15u) & ~15u;
    if (end_addr >= 0x1F0000u)
        return 0;

    /* Populate 256-byte Basepage */
    for (u32 i = 0; i < 256u; i++)
        st_ram_wb(bp + i, 0);
    st_ram_wl(bp + 0x00u, bp);          /* p_lowtpa */
    st_ram_wl(bp + 0x04u, 0x1F0000u);   /* p_hitpa */
    st_ram_wl(bp + 0x08u, text_base);   /* p_tbase */
    st_ram_wl(bp + 0x0Cu, tlen);        /* p_tlen */
    st_ram_wl(bp + 0x10u, data_base);   /* p_dbase */
    st_ram_wl(bp + 0x14u, dlen);        /* p_dlen */
    st_ram_wl(bp + 0x18u, bss_base);    /* p_bbase */
    st_ram_wl(bp + 0x1Cu, blen);        /* p_blen */
    st_ram_wl(bp + 0x20u, bp + 0x80u);  /* p_dta */
    ST.hle_dta = bp + 0x80u;

    /* Copy TEXT + DATA */
    u32 td_len = tlen + dlen;
    for (u32 i = 0; i < td_len; i++) {
        u8 b = (28u + i < src_len) ? src[28u + i] : 0;
        st_ram_wb(text_base + i, b);
    }
    /* Clear BSS */
    for (u32 i = 0; i < blen && bss_base + i < ST_RAM_SIZE; i++)
        st_ram_wb(bss_base + i, 0);

    /* Apply 32-bit GEMDOS fixups */
    u32 rel_off = 28u + td_len + slen;
    if (!absflag && rel_off + 4u <= src_len) {
        u32 first = ((u32)src[rel_off] << 24) | ((u32)src[rel_off + 1] << 16) |
                    ((u32)src[rel_off + 2] << 8) | src[rel_off + 3];
        rel_off += 4u;
        if (first != 0) {
            u32 addr = text_base + first;
            st_ram_wl(addr, st_ram_rl(addr) + text_base);
            while (rel_off < src_len) {
                u8 d = src[rel_off++];
                if (d == 0) break;
                if (d == 1) {
                    addr += 254u;
                } else {
                    addr += d;
                    st_ram_wl(addr, st_ram_rl(addr) + text_base);
                }
            }
        }
    }

    ST.hle_heap = end_addr;
    if (out_bp) *out_bp = bp;
    return text_base;
}

/* Trap #1 (GEMDOS), Trap #13 (BIOS), Trap #14 (XBIOS) for clean-room built-in ROM */
static u32 hle_caller_sp(void)
{
    /* Inside exception handler: supervisor SP has [SR (2B), PC (4B)] at m.r[15].
       If caller SR had S=1, args start at m.r[15] + 6; if S=0, args start at USP (m.other_sp)! */
    u16 caller_sr = st_ram_rw(m.r[15]);
    return (caller_sr & 0x2000u) ? (m.r[15] + 6u) : m.other_sp;
}

static void hle_gemdos_trap(void)
{
    u32 sp = hle_caller_sp();
    u16 fn = st_ram_rw(sp);
    switch (fn) {
    case 0x00: case 0x4C:               /* Pterm0 / Pterm */
        m.stopped = 1;
        break;
    case 0x01: case 0x07: case 0x08:    /* Cconin / Crawcin / Cnecin */
        if (ikbd_has_rx()) {
            u8 sc = ST.ikbd.rx_fifo[ST.ikbd.rx_r++];
            m.r[0] = ((u32)sc << 16) | (sc == 0x39 ? ' ' : sc == 0x1C ? '\r' : 0);
        } else {
            m.r[0] = 0;
        }
        break;
    case 0x02: case 0x09:               /* Cconout / Cconws */
        m.r[0] = 0;
        break;
    case 0x06: {                        /* Crawio */
        u16 w = st_ram_rw(sp + 2u);
        if (w == 0xFFu) {
            while (ikbd_has_rx() && (ST.ikbd.rx_fifo[ST.ikbd.rx_r] & 0x80u))
                ST.ikbd.rx_r++;
            if (ikbd_has_rx()) {
                u8 sc = ST.ikbd.rx_fifo[ST.ikbd.rx_r++];
                m.r[0] = ((u32)sc << 16) | (sc == 0x39 ? ' ' : sc == 0x1C ? '\r' : 0);
            } else {
                m.r[0] = 0;
            }
        } else {
            m.r[0] = 0;
        }
        break;
    }
    case 0x0B:                          /* Cconis */
        m.r[0] = ikbd_has_rx() ? 0xFFFFFFFFu : 0u;
        break;
    case 0x0E: m.r[0] = 1; break;       /* Dsetdrv -> bitmask of A: */
    case 0x19: m.r[0] = 0; break;       /* Dgetdrv -> 0 (A:) */
    case 0x1A:                          /* Fsetdta */
        ST.hle_dta = st_ram_rl(sp + 2u);
        m.r[0] = 0;
        break;
    case 0x20: {                        /* Super(stack) */
        u32 arg = st_ram_rl(sp + 2u);
        u16 csr = st_ram_rw(m.r[15]);
        if (arg == 1u) {
            m.r[0] = (csr & 0x2000u) ? 0xFFFFFFFFu : 0u;
        } else if (csr & 0x2000u) {
            /* Switch supervisor -> user */
            st_ram_ww(m.r[15], (u16)(csr & ~0x2000u));
            if (arg) m.other_sp = arg;
            m.r[0] = 0;
        } else {
            /* Switch user -> supervisor! Move 6-byte exception frame onto new SSP */
            u32 old_usp = m.other_sp;
            u32 ret_pc = st_ram_rl(m.r[15] + 2u);
            u32 new_ssp = arg ? arg : m.r[15] + 6u;
            m.r[15] = new_ssp - 6u;
            st_ram_ww(m.r[15], (u16)(csr | 0x2000u));
            st_ram_wl(m.r[15] + 2u, ret_pc);
            m.r[0] = old_usp;
        }
        break;
    }
    case 0x2F: m.r[0] = ST.hle_dta; break;  /* Fgetdta */
    case 0x30: m.r[0] = 0x1500u; break;     /* Sversion */
    case 0x48: {                            /* Malloc(size) */
        u32 sz = st_ram_rl(sp + 2u);
        u32 free_bytes = (ST.hle_heap < 0x1F0000u) ? (0x1F0000u - ST.hle_heap) : 0u;
        if (sz == 0xFFFFFFFFu) {
            m.r[0] = free_bytes;
        } else if (sz <= free_bytes) {
            m.r[0] = ST.hle_heap;
            ST.hle_heap = (ST.hle_heap + sz + 15u) & ~15u;
        } else {
            m.r[0] = 0;
        }
        break;
    }
    case 0x49: m.r[0] = 0; break;           /* Mfree */
    case 0x4A: {                            /* Mshrink(0, block, newsize) */
        u32 blk = st_ram_rl(sp + 4u);
        u32 nsz = st_ram_rl(sp + 8u);
        u32 end = (blk + nsz + 15u) & ~15u;
        if (blk < ST.hle_heap && end < ST.hle_heap)
            ST.hle_heap = end;
        m.r[0] = 0;
        break;
    }
    case 0x3D: {                            /* Fopen(fname, mode) */
        u32 p_fn = st_ram_rl(sp + 2u);
        char name[96];
        for (int i = 0; i < 95; i++) {
            name[i] = (char)st_ram_rb(p_fn + (u32)i);
            if (!name[i]) break;
        }
        name[95] = 0;
        u8 ent[32];
        if (st_fat12_find_entry(name, ent) < 0) {
            m.r[0] = (u32)(s32)-33;         /* EFILNF */
        } else {
            int h = -1;
            for (int i = 6; i < 16; i++)
                if (!ST.hle_fd[i].used) { h = i; break; }
            if (h < 0) {
                m.r[0] = (u32)(s32)-35;
            } else {
                ST.hle_fd[h].used = 1;
                ST.hle_fd[h].pos = 0;
                ST.hle_fd[h].size = fat12_get_le32(ent + 28);
                ST.hle_fd[h].start_cl = fat12_get_le16(ent + 26);
                m.r[0] = (u32)h;
            }
        }
        break;
    }
    case 0x3E: {                            /* Fclose(handle) */
        u16 h = st_ram_rw(sp + 2u);
        if (h < 16u) ST.hle_fd[h].used = 0;
        m.r[0] = 0;
        break;
    }
    case 0x3F: {                            /* Fread(handle, count, buf) */
        u16 h = st_ram_rw(sp + 2u);
        u32 cnt = st_ram_rl(sp + 4u);
        u32 buf = st_ram_rl(sp + 8u);
        if (h >= 16u || !ST.hle_fd[h].used) {
            m.r[0] = (u32)(s32)-37;
        } else {
            u32 got = st_fat12_read_chain(ST.hle_fd[h].start_cl, ST.hle_fd[h].pos, cnt, buf, ST.hle_fd[h].size);
            ST.hle_fd[h].pos += got;
            m.r[0] = got;
        }
        break;
    }
    case 0x42: {                            /* Fseek(offset, handle, seekmode) */
        s32 off = (s32)st_ram_rl(sp + 2u);
        u16 h = st_ram_rw(sp + 6u);
        u16 sm = st_ram_rw(sp + 8u);
        if (h >= 16u || !ST.hle_fd[h].used) {
            m.r[0] = (u32)(s32)-37;
        } else {
            s32 np = (sm == 0) ? off : (sm == 1) ? ((s32)ST.hle_fd[h].pos + off) : ((s32)ST.hle_fd[h].size + off);
            if (np < 0) np = 0;
            if ((u32)np > ST.hle_fd[h].size) np = (s32)ST.hle_fd[h].size;
            ST.hle_fd[h].pos = (u32)np;
            m.r[0] = (u32)np;
        }
        break;
    }
    case 0x4E: {                            /* Fsfirst(fspec, attr) */
        u32 p_fn = st_ram_rl(sp + 2u);
        char name[96];
        for (int i = 0; i < 95; i++) {
            name[i] = (char)st_ram_rb(p_fn + (u32)i);
            if (!name[i]) break;
        }
        name[95] = 0;
        u8 ent[32];
        if (st_fat12_find_entry(name, ent) < 0) {
            m.r[0] = (u32)(s32)-33;
        } else {
            st_ram_wb(ST.hle_dta + 21u, ent[11]);
            st_ram_wl(ST.hle_dta + 26u, fat12_get_le32(ent + 28));
            int out = 0;
            for (int i = 0; i < 8 && ent[i] != ' '; i++)
                st_ram_wb(ST.hle_dta + 30u + (u32)out++, ent[i]);
            if (ent[8] != ' ') {
                st_ram_wb(ST.hle_dta + 30u + (u32)out++, '.');
                for (int i = 8; i < 11 && ent[i] != ' '; i++)
                    st_ram_wb(ST.hle_dta + 30u + (u32)out++, ent[i]);
            }
            st_ram_wb(ST.hle_dta + 30u + (u32)out, 0);
            m.r[0] = 0;
        }
        break;
    }
    default:
        m.r[0] = 0;
        break;
    }
}

static void hle_bios_trap(void)
{
    u32 sp = hle_caller_sp();
    u16 fn = st_ram_rw(sp);
    switch (fn) {
    case 0x01: m.r[0] = ikbd_has_rx() ? 0xFFFFFFFFu : 0u; break;    /* Bconstat */
    case 0x02:                                                      /* Bconin */
        if (ikbd_has_rx()) {
            u8 sc = ST.ikbd.rx_fifo[ST.ikbd.rx_r++];
            m.r[0] = ((u32)sc << 16) | (sc == 0x39 ? ' ' : sc == 0x1C ? '\r' : 0);
        } else {
            m.r[0] = 0;
        }
        break;
    case 0x04: {                                                    /* Rwabs(rw, buf, count, recno, dev) */
        u16 rw_f = st_ram_rw(sp + 2u);
        u32 buf  = st_ram_rl(sp + 4u);
        u16 cnt  = st_ram_rw(sp + 8u);
        u16 rec  = st_ram_rw(sp + 10u);
        for (u32 i = 0; i < (u32)cnt * 512u; i++) {
            u32 off = (u32)rec * 512u + i;
            if (!(rw_f & 1u)) {
                u8 b = (ST.has_floppy && off < ST.floppy_size) ? M->floppy[off] : 0;
                if (buf + i < ST_RAM_SIZE) st_ram_wb(buf + i, b);
            } else if (ST.has_floppy && off < ST_FLOPPY_MAX) {
                M->floppy[off] = (buf + i < ST_RAM_SIZE) ? st_ram_rb(buf + i) : 0;
                ST.floppy_dirty = 1;
            }
        }
        m.r[0] = 0;
        break;
    }
    case 0x05: {                                                    /* Setexc(vecnum, vec) */
        u16 vn = st_ram_rw(sp + 2u);
        u32 nv = st_ram_rl(sp + 4u);
        u32 old = st_ram_rl((u32)vn * 4u);
        if (nv != 0xFFFFFFFFu)
            st_ram_wl((u32)vn * 4u, nv);
        m.r[0] = old;
        break;
    }
    case 0x06: m.r[0] = 20; break;                                  /* Tickcal: 20 ms */
    case 0x0A: m.r[0] = 1;  break;                                  /* Drvmap: A: */
    case 0x0B: {                                                    /* Kbshift */
        u8 msk = 0;
        if (ST.ikbd.held_keys[0x36]) msk |= 0x01u;
        if (ST.ikbd.held_keys[0x2A]) msk |= 0x02u;
        if (ST.ikbd.held_keys[0x1D]) msk |= 0x04u;
        if (ST.ikbd.held_keys[0x38]) msk |= 0x08u;
        m.r[0] = msk;
        break;
    }
    default: m.r[0] = 0; break;
    }
}

static void hle_xbios_trap(void)
{
    u32 sp = hle_caller_sp();
    u16 fn = st_ram_rw(sp);
    switch (fn) {
    case 0x02:                                                      /* Physbase */
        m.r[0] = ((u32)ST.vbase_hi << 16) | ((u32)ST.vbase_mid << 8) | ST.vbase_lo;
        break;
    case 0x03:                                                      /* Logbase */
        m.r[0] = st_ram_rl(0x044Eu);
        break;
    case 0x04: m.r[0] = ST.shift_res & 3u; break;                   /* Getrez */
    case 0x05: {                                                    /* Setscreen(log, phys, rez) */
        u32 loga  = st_ram_rl(sp + 2u);
        u32 physa = st_ram_rl(sp + 6u);
        s16 rez   = (s16)st_ram_rw(sp + 10u);
        if (loga != 0xFFFFFFFFu)
            st_ram_wl(0x044Eu, loga);
        if (physa != 0xFFFFFFFFu) {
            ST.vbase_hi  = (u8)(physa >> 16);
            ST.vbase_mid = (u8)(physa >> 8);
            ST.vbase_lo  = (u8)(physa & 0xFEu);
        }
        if (rez >= 0 && rez <= 2)
            ST.shift_res = (u8)rez;
        m.r[0] = 0;
        break;
    }
    case 0x06: {                                                    /* Setpalette(palptr) */
        u32 ptr = st_ram_rl(sp + 2u);
        for (int i = 0; i < 16; i++) {
            ST.pal_raw[i] = st_ram_rw(ptr + (u32)i * 2u) & 0x0FFFu;
            st_update_pal_entry(i);
        }
        m.r[0] = 0;
        break;
    }
    case 0x07: {                                                    /* Setcolor(num, col) */
        u16 idx = st_ram_rw(sp + 2u) & 15u;
        s16 col = (s16)st_ram_rw(sp + 4u);
        u16 old = ST.pal_raw[idx];
        if (col >= 0) {
            ST.pal_raw[idx] = (u16)col & 0x0FFFu;
            st_update_pal_entry(idx);
        }
        m.r[0] = old;
        break;
    }
    case 0x08: {                                                    /* Floprd(buf, filler, dev, sect, trk, side, count) */
        u32 buf  = st_ram_rl(sp + 2u);
        u16 sect = st_ram_rw(sp + 10u);
        u16 trk  = st_ram_rw(sp + 12u);
        u16 side = st_ram_rw(sp + 14u);
        u16 cnt  = st_ram_rw(sp + 16u);
        u32 ret  = 0;
        for (u16 s = 0; s < cnt; s++) {
            u8 s_id = (u8)(sect + s);
            u32 off = fdc_lba_offset((u8)trk, (u8)side, s_id);
            for (u32 i = 0; i < 512u; i++) {
                u8 b = (ST.has_floppy && off + i < ST.floppy_size) ? M->floppy[off + i] : 0;
                if (buf + (u32)s * 512u + i < ST_RAM_SIZE)
                    st_ram_wb(buf + (u32)s * 512u + i, b);
            }
            u8 err = fdc_sector_err((u8)trk, (u8)side, s_id);
            if (err & 0x10u) { ret = (u32)-8; break; }              /* E_SEEK / RNF */
            if (err & 0x08u) { ret = (u32)-4; break; }              /* E_CRC */
        }
        m.r[0] = ret;
        break;
    }
    case 0x11:                                                      /* Random (24-bit) */
        ST.ym.lfsr = ST.ym.lfsr * 1103515245u + 12345u;
        m.r[0] = (ST.ym.lfsr >> 8) & 0xFFFFFFu;
        break;
    case 0x1C: {                                                    /* Giaccess(data, reg) */
        u16 dat = st_ram_rw(sp + 2u);
        u16 reg = st_ram_rw(sp + 4u);
        if (reg & 0x80u)
            ym_write_reg((u8)(reg & 15u), (u8)dat);
        m.r[0] = ST.ym.reg[reg & 15u];
        break;
    }
    case 0x22:                                                      /* Kbdvbase -> pointer to kbdvecs table at $0E00 */
        m.r[0] = 0x000E00u;
        break;
    case 0x25:                                                      /* Vsync */
        m.r[0] = 0;
        break;
    case 0x26: {                                                    /* Supexec(funcptr): call in supervisor mode! */
        u32 fn_ptr = st_ram_rl(sp + 2u);
        /* Push return trampoline ($FC0200: RTE) so func's RTS returns to $FC0200 which RTEs to caller! */
        m.r[15] -= 4u;
        st_ram_wl(m.r[15], 0xFC0200u);
        m.pc = fn_ptr;
        break;
    }
    default:
        m.r[0] = 0;
        break;
    }
}

/* Build clean-room 192 KB TOS fallback ROM at $FC0000 when no external tos.img / etos*.img is supplied */
static void build_clean_tos(void)
{
    for (u32 i = 0; i < ST_ROM_MAX; i += 2u)
        st_rom_put_be16(i, 0x4E73u);    /* RTE default */

    /* OS Header at $FC0000: BRA.S $FC0030; version $0104; _os_beg = $FC0000 */
    st_rom_put_be16(0x0000u, 0x602Eu);
    st_rom_put_be16(0x0002u, 0x0104u);
    st_rom_put_be32(0x0004u, 0x00FC0030u);
    st_rom_put_be32(0x0008u, 0x00FC0000u);
    st_rom_put_be32(0x000Cu, 0x00010000u);
    st_rom_put_be32(0x0010u, 0x00FC0030u);

    /* Initial SSP ($000000) & Reset PC ($000004) come from first 8 bytes of ROM on Atari ST?
       Wait: real TOS puts BRA.S ($602E) at offset 0 (which happens to be $602E0104 as initial SSP, immediately
       reloaded by LEA $2000,SP at $FC0030!). Let's match that exact Atari TOS convention! */

    /* $FC0030: Reset entry -> MOVE #$2700,SR; LEA $1FE000,SP; MOVE.W #0,$FFFE00 (pushes SR+PC); RTE */
    static const u16 reset_code[] = {
        0x46FC, 0x2700,                 /* MOVE #$2700, SR */
        0x4FF9, 0x001F, 0xE000,         /* LEA $1FE000, SP */
        0x33FC, 0x0000, 0x00FF, 0xFE00, /* MOVE.W #0, $00FFFE00 (HLE boot setup -> pushes SR + entry PC) */
        0x4E73,                         /* RTE */
        0x60FE                          /* BRA.S * */
    };
    for (u32 i = 0; i < sizeof(reset_code) / 2u; i++)
        st_rom_put_be16(0x0030u + i * 2u, reset_code[i]);

    /* $FC0100: VBL ISR (Vector 28 = $70): ADDQ.L #1,$462 (_vbclock); ADDQ.L #1,$466 (_frclock); RTE */
    static const u16 vbl_isr[] = {
        0x52B8, 0x0462,
        0x52B8, 0x0466,
        0x4E73
    };
    for (u32 i = 0; i < sizeof(vbl_isr) / 2u; i++)
        st_rom_put_be16(0x0100u + i * 2u, vbl_isr[i]);

    /* $FC0120: Timer C 200 Hz ISR (Vector $45 = $114): ADDQ.L #1,$4BA (_hz_200); BCLR #5,$FFFFFA11.w; RTE */
    static const u16 tc_isr[] = {
        0x52B8, 0x04BA,
        0x08B8, 0x0005, 0xFA11,
        0x4E73
    };
    for (u32 i = 0; i < sizeof(tc_isr) / 2u; i++)
        st_rom_put_be16(0x0120u + i * 2u, tc_isr[i]);

    /* $FC0140: IKBD ACIA ISR (Vector $46 = $118): MOVE.W #4,$FFFE00 (HLE IKBD packet dispatch); BCLR #6,$FFFFFA11.w; RTE */
    static const u16 ikbd_isr[] = {
        0x33FC, 0x0004, 0x00FF, 0xFE00,
        0x08B8, 0x0006, 0xFA11,
        0x4E73
    };
    for (u32 i = 0; i < sizeof(ikbd_isr) / 2u; i++)
        st_rom_put_be16(0x0140u + i * 2u, ikbd_isr[i]);

    /* $FC0160: FDC ISR (Vector $47 = $11C): BCLR #7,$FFFFFA11.w; RTE */
    static const u16 fdc_isr[] = {
        0x08B8, 0x0007, 0xFA11,
        0x4E73
    };
    for (u32 i = 0; i < sizeof(fdc_isr) / 2u; i++)
        st_rom_put_be16(0x0160u + i * 2u, fdc_isr[i]);

    /* $FC0180: Trap #1 (GEMDOS): MOVE.W #1,$FFFE00; RTE */
    st_rom_put_be16(0x0180u, 0x33FCu); st_rom_put_be16(0x0182u, 0x0001u);
    st_rom_put_be32(0x0184u, 0x00FFFE00u); st_rom_put_be16(0x0188u, 0x4E73u);

    /* $FC0190: Trap #13 (BIOS): MOVE.W #2,$FFFE00; RTE */
    st_rom_put_be16(0x0190u, 0x33FCu); st_rom_put_be16(0x0192u, 0x0002u);
    st_rom_put_be32(0x0194u, 0x00FFFE00u); st_rom_put_be16(0x0198u, 0x4E73u);

    /* $FC01A0: Trap #14 (XBIOS): MOVE.W #3,$FFFE00; RTE */
    st_rom_put_be16(0x01A0u, 0x33FCu); st_rom_put_be16(0x01A2u, 0x0003u);
    st_rom_put_be32(0x01A4u, 0x00FFFE00u); st_rom_put_be16(0x01A8u, 0x4E73u);

    /* $FC01B0: Line-A ($28): MOVE.W #5,$FFFE00; RTE */
    st_rom_put_be16(0x01B0u, 0x33FCu); st_rom_put_be16(0x01B2u, 0x0005u);
    st_rom_put_be32(0x01B4u, 0x00FFFE00u); st_rom_put_be16(0x01B8u, 0x4E73u);

    /* $FC0200: Supexec return trampoline -> RTE; $FC0204: idle RTS */
    st_rom_put_be16(0x0200u, 0x4E73u);
    st_rom_put_be16(0x0204u, 0x4E75u);

    /* $FC0210: Idle desktop loop when no disk/program is present */
    st_rom_put_be16(0x0210u, 0x4E72u); st_rom_put_be16(0x0212u, 0x2300u); /* STOP #$2300 */
    st_rom_put_be16(0x0214u, 0x60FAu);                                    /* BRA.S -6 */
}

static void hle_tos_boot_setup(void)
{
    /* Initialize exception vectors in ST-RAM ($0008..$03FF) */
    for (u32 v = 2u; v < 256u; v++)
        st_ram_wl(v * 4u, 0x00FC0020u); /* Default RTE */
    st_ram_wl(0x0028u, 0x00FC01B0u);    /* Line-A */
    st_ram_wl(0x0068u, 0x00FC0020u);    /* HBL (RTE) */
    st_ram_wl(0x0070u, 0x00FC0100u);    /* VBL */
    st_ram_wl(0x0084u, 0x00FC0180u);    /* Trap #1 (GEMDOS) */
    st_ram_wl(0x00B4u, 0x00FC0190u);    /* Trap #13 (BIOS) */
    st_ram_wl(0x00B8u, 0x00FC01A0u);    /* Trap #14 (XBIOS) */
    st_ram_wl(0x0114u, 0x00FC0120u);    /* MFP Timer C (200 Hz) */
    st_ram_wl(0x0118u, 0x00FC0140u);    /* MFP ACIA (IKBD) */
    st_ram_wl(0x011Cu, 0x00FC0160u);    /* MFP FDC */

    /* Standard Atari ST low-memory system variables */
    u32 screen_addr = 0x1F8000u;
    ST.vbase_hi = 0x1Fu; ST.vbase_mid = 0x80u; ST.vbase_lo = 0x00u;
    ST.shift_res = 0;
    ST.sync_mode = 0x02u;               /* PAL 50 Hz */

    /* Default TOS desktop palette */
    static const u16 def_pal[16] = {
        0x0777, 0x0700, 0x0070, 0x0770, 0x0007, 0x0707, 0x0077, 0x0555,
        0x0333, 0x0733, 0x0373, 0x0773, 0x0337, 0x0737, 0x0377, 0x0000
    };
    for (int i = 0; i < 16; i++) {
        ST.pal_raw[i] = def_pal[i];
        st_update_pal_entry(i);
        st_ram_ww(0xFF8240u & 0xFFFFu, 0); /* (real regs updated above) */
    }

    st_ram_wl(0x042Eu, ST_RAM_SIZE);    /* _phystop = $200000 */
    st_ram_wl(0x0432u, 0x00020000u);    /* _membot */
    st_ram_wl(0x0436u, 0x001F0000u);    /* _memtop */
    st_ram_wl(0x044Eu, screen_addr);    /* _v_bas_ad */
    st_ram_ww(0x0446u, 0);              /* _bootdev = A: */
    st_ram_wb(0x044Cu, 0);              /* _sshiftmd = 0 (320x200) */
    st_ram_wl(0x04C2u, 1u);             /* _drvbits = A: */
    st_ram_wl(0x04C6u, 0x00010000u);    /* _dskbufp */
    st_ram_wl(0x04F2u, 0x00FC0000u);    /* _sysbase */

    /* Kbdvbase table at $0E00: mousevec(+16), joyvec(+24) all pointing to $FC0204 (RTS) */
    for (int i = 0; i < 9; i++)
        st_ram_wl(0x0E00u + (u32)i * 4u, 0x00FC0204u);

    /* Configure MFP: VR = $48 (vectored $40..$4F, software EOI), Timer C 200 Hz (div 64, count 192), ACIA + FDC */
    ST.mfp.vr = 0x48u;
    ST.mfp.tcdcr = 0x50u;
    ST.mfp.tcdr = ST.mfp.tc_reload = 192u;
    ST.mfp.iera = 0x00u;
    ST.mfp.ierb = 0xE0u;                /* FDC (bit 7), ACIA (bit 6), Timer C (bit 5) */
    ST.mfp.imra = 0x00u;
    ST.mfp.imrb = 0xE0u;
    ST.ikbd.acia_ctrl = 0x96u;          /* RX IRQ enabled */
    ST.ikbd.joy_mode = 1;

    ST.hle_heap = 0x00020000u;
    ST.hle_dta  = 0x00018000u;

    u32 entry_pc = 0x00FC0210u;
    u16 entry_sr = 0x2300u;

    if (ST.has_floppy && ST.floppy_size >= 512u) {
        /* 1. Check for executable bootsector (16-bit big-endian sum of 256 words == $1234)! */
        u16 sum = 0;
        for (u32 i = 0; i < 512u; i += 2u)
            sum = (u16)(sum + (((u16)M->floppy[i] << 8) | M->floppy[i + 1u]));
        if (sum == 0x1234u && M->floppy[0] == 0x60u) {
            u32 dskbuf = 0x00010000u;
            for (u32 i = 0; i < 512u; i++)
                st_ram_wb(dskbuf + i, M->floppy[i]);
            m.r[8 + 5] = dskbuf;
            entry_pc = dskbuf;
        } else {
            /* 2. Search \AUTO\*.PRG first, then root *.PRG / *.TOS */
            u8 ent[32];
            int found = (st_fat12_find_entry("AUTO\\*.PRG", ent) == 0);
            if (!found) found = (st_fat12_find_entry("*.PRG", ent) == 0);
            if (!found) found = (st_fat12_find_entry("*.TOS", ent) == 0);
            if (!found) found = (st_fat12_find_entry("*.TTP", ent) == 0);
            if (found) {
                u32 fsz = fat12_get_le32(ent + 28);
                u16 cl0 = fat12_get_le16(ent + 26);
                /* Read raw PRG into top temporary scratch inside ST-RAM ($120000) or straight via floppy chain */
                u32 scratch = 0x00120000u;
                if (fsz + scratch < 0x001F0000u) {
                    st_fat12_read_chain(cl0, 0, fsz, scratch, fsz);
                    /* Un-wordswap into linear temp in floppy tail or relocate directly */
                    /* Even simpler: copy linear bytes into M->floppy tail if room, else read bytewise */
                    u32 bp = 0;
                    /* Build temporary linear view at M->rom + 0x30000? No, let's relocate directly from st_ram_rb! */
                    u32 tlen = st_ram_rl(scratch + 2u);
                    u32 dlen = st_ram_rl(scratch + 6u);
                    u32 blen = st_ram_rl(scratch + 10u);
                    u32 slen = st_ram_rl(scratch + 14u);
                    u16 absf = st_ram_rw(scratch + 26u);
                    if (fsz >= 28u && st_ram_rw(scratch) == 0x601Au) {
                        bp = (ST.hle_heap + 255u) & ~255u;
                        u32 tbase = bp + 256u;
                        u32 dbase = tbase + tlen;
                        u32 bbase = dbase + dlen;
                        u32 end_a = (bbase + blen + 15u) & ~15u;
                        if (end_a < scratch) {
                            for (u32 i = 0; i < 256u; i++) st_ram_wb(bp + i, 0);
                            st_ram_wl(bp + 0x00u, bp);
                            st_ram_wl(bp + 0x04u, 0x1F0000u);
                            st_ram_wl(bp + 0x08u, tbase);
                            st_ram_wl(bp + 0x0Cu, tlen);
                            st_ram_wl(bp + 0x10u, dbase);
                            st_ram_wl(bp + 0x14u, dlen);
                            st_ram_wl(bp + 0x18u, bbase);
                            st_ram_wl(bp + 0x1Cu, blen);
                            st_ram_wl(bp + 0x20u, bp + 0x80u);
                            ST.hle_dta = bp + 0x80u;
                            u32 td = tlen + dlen;
                            for (u32 i = 0; i < td; i++)
                                st_ram_wb(tbase + i, st_ram_rb(scratch + 28u + i));
                            for (u32 i = 0; i < blen; i++)
                                st_ram_wb(bbase + i, 0);
                            u32 roff = scratch + 28u + td + slen;
                            if (!absf && roff + 4u <= scratch + fsz) {
                                u32 first = st_ram_rl(roff);
                                roff += 4u;
                                if (first) {
                                    u32 a = tbase + first;
                                    st_ram_wl(a, st_ram_rl(a) + tbase);
                                    while (roff < scratch + fsz) {
                                        u8 d = st_ram_rb(roff++);
                                        if (!d) break;
                                        if (d == 1) a += 254u;
                                        else { a += d; st_ram_wl(a, st_ram_rl(a) + tbase); }
                                    }
                                }
                            }
                            for (u32 i = 0; i < fsz; i++) st_ram_wb(scratch + i, 0);
                            ST.hle_heap = end_a;
                            /* Push [0.L, basepage.L] onto user stack at $1EFF00! */
                            u32 usp = 0x001EFF00u;
                            st_ram_wl(usp, 0);
                            st_ram_wl(usp + 4u, bp);
                            m.other_sp = usp;
                            entry_pc = tbase;
                            entry_sr = 0x0300u;
                        }
                    }
                }
            }
        }
    }

    if (!m.other_sp)
        m.other_sp = 0x001EFF00u;
    m.r[15] -= 6u;
    st_ram_ww(m.r[15], entry_sr);
    st_ram_wl(m.r[15] + 2u, entry_pc);
}

static void hle_ikbd_packet_isr(void)
{
    while (ikbd_has_rx()) {
        u8 b = ST.ikbd.rx_fifo[ST.ikbd.rx_r++];
        if (b == 0xFFu || b == 0xFEu) { /* Joystick packet: pass packet ptr to joyvec ($0E18) */
            if (ikbd_has_rx()) {
                u8 j = ST.ikbd.rx_fifo[ST.ikbd.rx_r++];
                st_ram_wb(0x0E40u, b);
                st_ram_wb(0x0E41u, (b == 0xFEu) ? j : ST.ikbd.joy0);
                st_ram_wb(0x0E42u, (b == 0xFFu) ? j : ST.ikbd.joy1);
                u32 jvec = st_ram_rl(0x0E18u);
                if (jvec && jvec != 0x00FC0204u) {
                    m.r[8] = 0x000E40u; /* A0 = packet pointer */
                    st_ram_wl(m.r[15] - 4u, m.pc);
                    m.r[15] -= 4u;
                    m.pc = jvec;
                    return;
                }
            }
        }
    }
}

/* ---- 68000 Memory-Mapped I/O ($000000..$FFFFFF) ---- */
static void st_setup_maps(void)
{
    for (int i = 0; i < 256; i++) {
        rmap[i] = 0;
        wmap[i] = 0;
    }
    /* Page 0 ($000000..$00FFFF) goes through io_read/io_write so $0..$7 ROM overlay & User-mode < $800 BERR work!
       Pages 1..31 ($010000..$1FFFFF) point directly to M->ram for full native speed! */
    for (int i = 1; i < 32; i++) {
        rmap[i] = M->ram + (u32)i * 0x10000u;
        wmap[i] = M->ram + (u32)i * 0x10000u;
    }
    if (ST.rom_is_256k) {
        for (int i = 0; i < 4; i++)
            rmap[0xE0 + i] = M->rom + (u32)i * 0x10000u;
        for (int i = 0; i < 3; i++)
            rmap[0xFC + i] = M->rom + (u32)i * 0x10000u;
    } else {
        for (int i = 0; i < 3; i++)
            rmap[0xFC + i] = M->rom + (u32)i * 0x10000u;
    }
}

static u8 st_io_rb_byte(u32 a)
{
    /* MMU Config ($FF8001) */
    if (a == 0xFF8001u)
        return ST.mmu_cfg;

    /* Shifter Video ($FF8200..$FF827F) */
    if (a >= 0xFF8200u && a < 0xFF8280u) {
        u32 vbase = ((u32)ST.vbase_hi << 16) | ((u32)ST.vbase_mid << 8) | ST.vbase_lo;
        u32 vcnt = vbase;
        if (ST.cur_line >= ST_VIS_START && ST.cur_line < ST_VIS_START + 200) {
            u32 lbytes = (ST.shift_res == 2) ? 160u : 160u;
            u32 in_line = (u32)((m.clock - ST.line_start_clk) * 160 / ST_CYCLES_LINE) & ~1u;
            if (in_line > 160u) in_line = 160u;
            vcnt = vbase + (u32)(ST.cur_line - ST_VIS_START) * lbytes + in_line;
        }
        switch (a) {
        case 0xFF8201: return ST.vbase_hi;
        case 0xFF8203: return ST.vbase_mid;
        case 0xFF8205: return (u8)(vcnt >> 16);
        case 0xFF8207: return (u8)(vcnt >> 8);
        case 0xFF8209: return (u8)vcnt;
        case 0xFF820A: return ST.sync_mode;
        case 0xFF820D: return ST.vbase_lo;
        case 0xFF820F: return ST.line_wid;
        case 0xFF8260: return ST.shift_res;
        case 0xFF8265: return ST.hscroll;
        default:
            if (a >= 0xFF8240u && a < 0xFF8260u) {
                u32 idx = (a - 0xFF8240u) >> 1;
                return (a & 1u) ? (u8)ST.pal_raw[idx] : (u8)(ST.pal_raw[idx] >> 8);
            }
            return 0xFFu;
        }
    }

    /* DMA / WD1772 ($FF8600..$FF860F) */
    if (a >= 0xFF8600u && a < 0xFF8610u) {
        switch (a) {
        case 0xFF8609: return (u8)(ST.fdc.dma_addr >> 16);
        case 0xFF860B: return (u8)(ST.fdc.dma_addr >> 8);
        case 0xFF860D: return (u8)ST.fdc.dma_addr;
        default: return 0;
        }
    }

    /* YM2149F ($FF8800..$FF88FF: ST mirrors across $FF88xx, bit 1 selects data vs reg) */
    if (a >= 0xFF8800u && a < 0xFF8900u) {
        if (!(a & 2u))
            return ST.ym.reg[ST.ym.sel & 15u];
        return 0xFFu;
    }

    /* Atari Blitter ($FF8A00..$FF8A3F) */
    if (a >= 0xFF8A00u && a < 0xFF8A40u) {
        u32 r = a - 0xFF8A00u;
        if (r < 0x20u) {
            u16 w = ST.blt.halftone[r >> 1];
            return (r & 1u) ? (u8)w : (u8)(w >> 8);
        }
        switch (a) {
        case 0xFF8A20: return (u8)((u16)ST.blt.src_x_inc >> 8);
        case 0xFF8A21: return (u8)ST.blt.src_x_inc;
        case 0xFF8A22: return (u8)((u16)ST.blt.src_y_inc >> 8);
        case 0xFF8A23: return (u8)ST.blt.src_y_inc;
        case 0xFF8A24: return 0;
        case 0xFF8A25: return (u8)(ST.blt.src_addr >> 16);
        case 0xFF8A26: return (u8)(ST.blt.src_addr >> 8);
        case 0xFF8A27: return (u8)ST.blt.src_addr;
        case 0xFF8A28: return (u8)(ST.blt.endmask1 >> 8);
        case 0xFF8A29: return (u8)ST.blt.endmask1;
        case 0xFF8A2A: return (u8)(ST.blt.endmask2 >> 8);
        case 0xFF8A2B: return (u8)ST.blt.endmask2;
        case 0xFF8A2C: return (u8)(ST.blt.endmask3 >> 8);
        case 0xFF8A2D: return (u8)ST.blt.endmask3;
        case 0xFF8A2E: return (u8)((u16)ST.blt.dst_x_inc >> 8);
        case 0xFF8A2F: return (u8)ST.blt.dst_x_inc;
        case 0xFF8A30: return (u8)((u16)ST.blt.dst_y_inc >> 8);
        case 0xFF8A31: return (u8)ST.blt.dst_y_inc;
        case 0xFF8A32: return 0;
        case 0xFF8A33: return (u8)(ST.blt.dst_addr >> 16);
        case 0xFF8A34: return (u8)(ST.blt.dst_addr >> 8);
        case 0xFF8A35: return (u8)ST.blt.dst_addr;
        case 0xFF8A36: return (u8)(ST.blt.x_count >> 8);
        case 0xFF8A37: return (u8)ST.blt.x_count;
        case 0xFF8A38: return (u8)(ST.blt.y_count >> 8);
        case 0xFF8A39: return (u8)ST.blt.y_count;
        case 0xFF8A3A: return ST.blt.hop;
        case 0xFF8A3B: return ST.blt.op;
        case 0xFF8A3C: return ST.blt.line_num;
        case 0xFF8A3D: return ST.blt.skew;
        default: return 0;
        }
    }

    /* MC68901 MFP ($FFFA00..$FFFA3F, odd byte addresses) */
    if (a >= 0xFFFA00u && a < 0xFFFA40u) {
        if (!(a & 1u))
            return 0xFFu;
        switch (a) {
        case 0xFFFA01: {
            /* Bit 7=1 (Color monitor), Bit 5=/FDC_IRQ, Bit 4=/ACIA_IRQ, Bit 0=0 (Centronics ready) */
            u8 in = 0x86u;
            if (!ST.fdc.irq) in |= 0x20u;
            if (!ikbd_irq_active()) in |= 0x10u;
            return (ST.mfp.gpip & ST.mfp.ddr) | (in & (u8)~ST.mfp.ddr);
        }
        case 0xFFFA03: return ST.mfp.aer;
        case 0xFFFA05: return ST.mfp.ddr;
        case 0xFFFA07: return ST.mfp.iera;
        case 0xFFFA09: return ST.mfp.ierb;
        case 0xFFFA0B: return ST.mfp.ipra;
        case 0xFFFA0D: return ST.mfp.iprb;
        case 0xFFFA0F: return ST.mfp.isra;
        case 0xFFFA11: return ST.mfp.isrb;
        case 0xFFFA13: return ST.mfp.imra;
        case 0xFFFA15: return ST.mfp.imrb;
        case 0xFFFA17: return ST.mfp.vr;
        case 0xFFFA19: return ST.mfp.tacr;
        case 0xFFFA1B: return ST.mfp.tbcr;
        case 0xFFFA1D: return ST.mfp.tcdcr;
        case 0xFFFA1F: return ST.mfp.tadr;
        case 0xFFFA21: return ST.mfp.tbdr;
        case 0xFFFA23: return ST.mfp.tcdr;
        case 0xFFFA25: return ST.mfp.tddr;
        case 0xFFFA27: return ST.mfp.usart_scr;
        case 0xFFFA29: return ST.mfp.usart_ucr;
        case 0xFFFA2B: return ST.mfp.usart_rsr;
        case 0xFFFA2D: return ST.mfp.usart_tsr | 0x80u;
        case 0xFFFA2F: return ST.mfp.usart_udr;
        default: return 0xFFu;
        }
    }

    /* Dual MC6850 ACIA ($FFFC00..$FFFC07) */
    if (a >= 0xFFFC00u && a < 0xFFFC08u) {
        switch (a) {
        case 0xFFFC00: {
            u8 st = 0x02u;              /* TDRE = 1 (ready to transmit) */
            if (ikbd_has_rx()) st |= 0x01u;
            if (ikbd_irq_active()) st |= 0x80u;
            return st;
        }
        case 0xFFFC02: {
            u8 b = 0;
            if (ikbd_has_rx())
                b = ST.ikbd.rx_fifo[ST.ikbd.rx_r++];
            st_update_ipl();
            return b;
        }
        case 0xFFFC04: return 0x02u;    /* MIDI TDRE = 1 */
        case 0xFFFC06: return 0x00u;
        default: return 0xFFu;
        }
    }

    /* All other optional hardware addresses ($FF8900 DMA sound, $FF8E00 VME, $FFFA40 FPU, $FFF000 IDE, etc.)
       assert /BERR (Vector 2) on a real Atari 1040STFM! */
    m68k_bus_error(a, 0);
    return 0xFFu;
}

static void st_io_wb_byte(u32 a, u8 v)
{
    if (a == 0xFF8001u) {
        ST.mmu_cfg = v;
        return;
    }

    if (a >= 0xFF8200u && a < 0xFF8280u) {
        switch (a) {
        case 0xFF8201: ST.vbase_hi = v; ST.vbase_lo = 0; break;
        case 0xFF8203: ST.vbase_mid = v; ST.vbase_lo = 0; break;
        case 0xFF820A: ST.sync_mode = v; break;
        case 0xFF820D: ST.vbase_lo = v & 0xFEu; break;
        case 0xFF820F: ST.line_wid = v; break;
        case 0xFF8260: ST.shift_res = v & 3u; break;
        case 0xFF8265: ST.hscroll = v & 15u; break;
        default:
            if (a >= 0xFF8240u && a < 0xFF8260u) {
                u32 idx = (a - 0xFF8240u) >> 1;
                if (a & 1u)
                    ST.pal_raw[idx] = (u16)((ST.pal_raw[idx] & 0x0F00u) | v);
                else
                    ST.pal_raw[idx] = (u16)((ST.pal_raw[idx] & 0x00FFu) | (((u16)v & 0x0Fu) << 8));
                if (ST.pal_raw[idx] & 0x0888u)
                    ST.ste_pal_used = 1;
                st_update_pal_entry((int)idx);
            }
            break;
        }
        return;
    }

    if (a >= 0xFF8600u && a < 0xFF8610u) {
        switch (a) {
        case 0xFF8609: ST.fdc.dma_addr = (ST.fdc.dma_addr & 0x00FFFFu) | ((u32)(v & 0x3Fu) << 16); break;
        case 0xFF860B: ST.fdc.dma_addr = (ST.fdc.dma_addr & 0xFF00FFu) | ((u32)v << 8); break;
        case 0xFF860D: ST.fdc.dma_addr = (ST.fdc.dma_addr & 0xFFFF00u) | (v & 0xFEu); break;
        }
        return;
    }

    if (a >= 0xFF8800u && a < 0xFF8900u) {
        if (!(a & 2u))
            ST.ym.sel = v & 15u;
        else
            ym_write_reg(ST.ym.sel, v);
        return;
    }

    if (a >= 0xFF8A00u && a < 0xFF8A40u) {
        u32 r = a - 0xFF8A00u;
        if (r < 0x20u) {
            u32 idx = r >> 1;
            if (r & 1u) ST.blt.halftone[idx] = (u16)((ST.blt.halftone[idx] & 0xFF00u) | v);
            else        ST.blt.halftone[idx] = (u16)((ST.blt.halftone[idx] & 0x00FFu) | ((u16)v << 8));
            return;
        }
        switch (a) {
        case 0xFF8A20: ST.blt.src_x_inc = (s16)(((u16)v << 8) | ((u16)ST.blt.src_x_inc & 0xFFu)); break;
        case 0xFF8A21: ST.blt.src_x_inc = (s16)(((u16)ST.blt.src_x_inc & 0xFF00u) | (v & 0xFEu)); break;
        case 0xFF8A22: ST.blt.src_y_inc = (s16)(((u16)v << 8) | ((u16)ST.blt.src_y_inc & 0xFFu)); break;
        case 0xFF8A23: ST.blt.src_y_inc = (s16)(((u16)ST.blt.src_y_inc & 0xFF00u) | (v & 0xFEu)); break;
        case 0xFF8A25: ST.blt.src_addr = (ST.blt.src_addr & 0x00FFFFu) | ((u32)v << 16); break;
        case 0xFF8A26: ST.blt.src_addr = (ST.blt.src_addr & 0xFF00FFu) | ((u32)v << 8); break;
        case 0xFF8A27: ST.blt.src_addr = (ST.blt.src_addr & 0xFFFF00u) | (v & 0xFEu); break;
        case 0xFF8A28: ST.blt.endmask1 = (u16)((ST.blt.endmask1 & 0x00FFu) | ((u16)v << 8)); break;
        case 0xFF8A29: ST.blt.endmask1 = (u16)((ST.blt.endmask1 & 0xFF00u) | v); break;
        case 0xFF8A2A: ST.blt.endmask2 = (u16)((ST.blt.endmask2 & 0x00FFu) | ((u16)v << 8)); break;
        case 0xFF8A2B: ST.blt.endmask2 = (u16)((ST.blt.endmask2 & 0xFF00u) | v); break;
        case 0xFF8A2C: ST.blt.endmask3 = (u16)((ST.blt.endmask3 & 0x00FFu) | ((u16)v << 8)); break;
        case 0xFF8A2D: ST.blt.endmask3 = (u16)((ST.blt.endmask3 & 0xFF00u) | v); break;
        case 0xFF8A2E: ST.blt.dst_x_inc = (s16)(((u16)v << 8) | ((u16)ST.blt.dst_x_inc & 0xFFu)); break;
        case 0xFF8A2F: ST.blt.dst_x_inc = (s16)(((u16)ST.blt.dst_x_inc & 0xFF00u) | (v & 0xFEu)); break;
        case 0xFF8A30: ST.blt.dst_y_inc = (s16)(((u16)v << 8) | ((u16)ST.blt.dst_y_inc & 0xFFu)); break;
        case 0xFF8A31: ST.blt.dst_y_inc = (s16)(((u16)ST.blt.dst_y_inc & 0xFF00u) | (v & 0xFEu)); break;
        case 0xFF8A33: ST.blt.dst_addr = (ST.blt.dst_addr & 0x00FFFFu) | ((u32)v << 16); break;
        case 0xFF8A34: ST.blt.dst_addr = (ST.blt.dst_addr & 0xFF00FFu) | ((u32)v << 8); break;
        case 0xFF8A35: ST.blt.dst_addr = (ST.blt.dst_addr & 0xFFFF00u) | (v & 0xFEu); break;
        case 0xFF8A36: ST.blt.x_count = (u16)((ST.blt.x_count & 0x00FFu) | ((u16)v << 8)); break;
        case 0xFF8A37: ST.blt.x_count = (u16)((ST.blt.x_count & 0xFF00u) | v); break;
        case 0xFF8A38: ST.blt.y_count = (u16)((ST.blt.y_count & 0x00FFu) | ((u16)v << 8)); break;
        case 0xFF8A39: ST.blt.y_count = (u16)((ST.blt.y_count & 0xFF00u) | v); break;
        case 0xFF8A3A: ST.blt.hop = v & 3u; break;
        case 0xFF8A3B: ST.blt.op = v & 15u; break;
        case 0xFF8A3C:
            ST.blt.line_num = v;
            if (v & 0x80u)
                blt_execute();
            break;
        case 0xFF8A3D: ST.blt.skew = v; break;
        }
        return;
    }

    if (a >= 0xFFFA00u && a < 0xFFFA40u) {
        if (!(a & 1u))
            return;
        switch (a) {
        case 0xFFFA01: ST.mfp.gpip = v; break;
        case 0xFFFA03: ST.mfp.aer = v; break;
        case 0xFFFA05: ST.mfp.ddr = v; break;
        case 0xFFFA07: ST.mfp.iera = v; ST.mfp.ipra &= v; st_update_ipl(); break;
        case 0xFFFA09: ST.mfp.ierb = v; ST.mfp.iprb &= v; st_update_ipl(); break;
        case 0xFFFA0B: ST.mfp.ipra &= v; st_update_ipl(); break;
        case 0xFFFA0D: ST.mfp.iprb &= v; st_update_ipl(); break;
        case 0xFFFA0F: ST.mfp.isra &= v; st_update_ipl(); break;
        case 0xFFFA11: ST.mfp.isrb &= v; st_update_ipl(); break;
        case 0xFFFA13: ST.mfp.imra = v; st_update_ipl(); break;
        case 0xFFFA15: ST.mfp.imrb = v; st_update_ipl(); break;
        case 0xFFFA17:
            ST.mfp.vr = v;
            if (!(v & 0x08u))
                ST.mfp.isra = ST.mfp.isrb = 0;
            st_update_ipl();
            break;
        case 0xFFFA19: ST.mfp.tacr = v & 15u; break;
        case 0xFFFA1B: ST.mfp.tbcr = v & 15u; break;
        case 0xFFFA1D: ST.mfp.tcdcr = v & 0x77u; break;
        case 0xFFFA1F:
            ST.mfp.ta_reload = v;
            if ((ST.mfp.tacr & 15u) == 0) ST.mfp.tadr = v;
            break;
        case 0xFFFA21:
            ST.mfp.tb_reload = v;
            if ((ST.mfp.tbcr & 15u) == 0) ST.mfp.tbdr = v;
            break;
        case 0xFFFA23:
            ST.mfp.tc_reload = v;
            if (((ST.mfp.tcdcr >> 4) & 7u) == 0) ST.mfp.tcdr = v;
            break;
        case 0xFFFA25:
            ST.mfp.td_reload = v;
            if ((ST.mfp.tcdcr & 7u) == 0) ST.mfp.tddr = v;
            break;
        case 0xFFFA27: ST.mfp.usart_scr = v; break;
        case 0xFFFA29: ST.mfp.usart_ucr = v; break;
        case 0xFFFA2B: ST.mfp.usart_rsr = v; break;
        case 0xFFFA2D: ST.mfp.usart_tsr = v; break;
        case 0xFFFA2F: ST.mfp.usart_udr = v; break;
        }
        return;
    }

    if (a >= 0xFFFC00u && a < 0xFFFC08u) {
        switch (a) {
        case 0xFFFC00:
            if ((v & 3u) == 3u) {       /* Master reset */
                ST.ikbd.acia_ctrl = 0;
            } else {
                ST.ikbd.acia_ctrl = v;
                if (ikbd_irq_active())
                    mfp_raise_irq(6);
            }
            st_update_ipl();
            break;
        case 0xFFFC02:
            ikbd_tx_byte(v);
            break;
        case 0xFFFC04:
            ST.ikbd.midi_ctrl = ((v & 3u) == 3u) ? 0 : v;
            break;
        }
        return;
    }

    m68k_bus_error(a, 1);
}

static u32 io_read(u32 a, int size)
{
    /* Page 0 ($000000..$00FFFF): $000000..$000007 reads ROM reset vectors; $000008..$00FFFF reads ST-RAM */
    if (a < 0x010000u) {
        if (a < 8u) {
            if (!ST.ext_rom) {
                /* Built-in clean-room ROM: SSP = $1FE000, PC = $FC0030 */
                static const u8 rst_vec[8] = { 0x00, 0x1F, 0xE0, 0x00, 0x00, 0xFC, 0x00, 0x30 };
                return (size == 1) ? rst_vec[a] : (u32)(((u16)rst_vec[a] << 8) | rst_vec[a + 1u]);
            }
            return (size == 1) ? st_rom_rb(a) : st_rom_rw(a);
        }
        return (size == 1) ? st_ram_rb(a) : st_ram_rw(a);
    }

    /* Diagnostic / ROM Cartridge space ($FA0000..$FBFFFF): unpopulated, returns 0xFF/0xFFFF without Bus Error */
    if (a >= 0xFA0000u && a < 0xFC0000u)
        return (size == 1) ? 0xFFu : 0xFFFFu;

    /* Hardware I/O ($FF8000..$FFFFFF) */
    if (a >= 0xFF8000u) {
        if (!m.s) {
            m68k_bus_error(a, 0);
            return 0xFFFFu;
        }
        /* Word-wide DMA / WD1772 registers ($FF8604 / $FF8606) */
        if (size == 2 && a == 0xFF8604u) {
            if (ST.fdc.dma_mode & 0x10u)
                return ST.fdc.dma_sec_cnt;
            u8 rsel = (ST.fdc.dma_mode >> 1) & 3u;
            if (rsel == 0) { ST.fdc.irq = 0; st_update_ipl(); return ST.fdc.status; }
            if (rsel == 1) return ST.fdc.track;
            if (rsel == 2) return ST.fdc.sector;
            return ST.fdc.data;
        }
        if (size == 2 && a == 0xFF8606u)
            return ST.fdc.dma_status;

        if (size == 1)
            return st_io_rb_byte(a);
        u8 hi = st_io_rb_byte(a);
        u8 lo = m.bus_err ? 0xFFu : st_io_rb_byte(a + 1u);
        return ((u32)hi << 8) | lo;
    }

    /* Unpopulated ST-RAM Bank 1 ($200000..$3FFFFF): Atari MMU asserts /DTACK (no /BERR!), reads open bus */
    if (a >= 0x200000u && a < 0x400000u)
        return (size == 1) ? 0xFFu : 0xFFFFu;

    /* Unmapped memory ($400000..$DFFFFF, $E40000..$F9FFFF, $FF0000..$FF7FFF) -> Bus Error */
    m68k_bus_error(a, 0);
    return (size == 1) ? 0xFFu : 0xFFFFu;
}

static void io_write(u32 a, u32 v, int size)
{
    if (a < 0x010000u) {
        if (a < 8u || (a < 0x0800u && !m.s)) {
            m68k_bus_error(a, 1);
            return;
        }
        if (size == 1) st_ram_wb(a, (u8)v);
        else           st_ram_ww(a, (u16)v);
        return;
    }

    /* Unpopulated ST-RAM Bank 1 ($200000..$3FFFFF): Atari MMU asserts /DTACK (no /BERR!), writes ignored */
    if (a >= 0x200000u && a < 0x400000u)
        return;

    if (a >= 0xFA0000u && a < 0xFF8000u) {
        if (a < 0xFC0000u || a >= 0xFF0000u)
            m68k_bus_error(a, 1);
        return;                         /* ROM writes ignored */
    }
    if (ST.rom_is_256k && a >= 0xE00000u && a < 0xE40000u)
        return;                         /* ROM writes ignored */

    if (a >= 0xFF8000u) {
        if (!m.s) {
            m68k_bus_error(a, 1);
            return;
        }
        /* Internal HLE dispatch port ($FFFE00) when built-in clean-room ROM is active */
        if (!ST.ext_rom && a == 0xFFFE00u && size == 2) {
            if (v == 0)      hle_tos_boot_setup();
            else if (v == 1) hle_gemdos_trap();
            else if (v == 2) hle_bios_trap();
            else if (v == 3) hle_xbios_trap();
            else if (v == 4) hle_ikbd_packet_isr();
            return;
        }

        if (size == 2 && a == 0xFF8604u) {
            if (ST.fdc.dma_mode & 0x10u) {
                ST.fdc.dma_sec_cnt = (u16)v;
            } else {
                u8 rsel = (ST.fdc.dma_mode >> 1) & 3u;
                if (rsel == 0)      fdc_exec_cmd((u8)v);
                else if (rsel == 1) ST.fdc.track = (u8)v;
                else if (rsel == 2) ST.fdc.sector = (u8)v;
                else                ST.fdc.data = (u8)v;
            }
            return;
        }
        if (size == 2 && a == 0xFF8606u) {
            if ((ST.fdc.dma_mode ^ v) & 0x0100u)
                ST.fdc.dma_status = 0x01u;
            ST.fdc.dma_mode = (u16)v;
            return;
        }

        if (size == 1) {
            st_io_wb_byte(a, (u8)v);
        } else {
            st_io_wb_byte(a, (u8)(v >> 8));
            if (!m.bus_err)
                st_io_wb_byte(a + 1u, (u8)v);
        }
        return;
    }

    m68k_bus_error(a, 1);
}

static void cpu_reset_line(void)
{
    ST.fdc.irq = 0;
    ST.mfp.ipra = ST.mfp.iprb = ST.mfp.isra = ST.mfp.isrb = 0;
    st_update_ipl();
}

/* ---- Shifter Per-Scanline Renderer ---- */
static void st_render_line(int y, u16 *picture)
{
    if (!picture)
        return;
    u32 vbase = ((u32)ST.vbase_hi << 16) | ((u32)ST.vbase_mid << 8) | ST.vbase_lo;
    u8 res = ST.shift_res & 3u;

    if (res == 0) {                     /* 320 x 200, 4 bitplanes (16 colors) */
        u32 row_a = vbase + (u32)y * 160u;
        u16 *out = picture + y * 320;
        for (int grp = 0; grp < 20; grp++, row_a += 8u, out += 16) {
            u16 w0 = st_ram_rw(row_a + 0u);
            u16 w1 = st_ram_rw(row_a + 2u);
            u16 w2 = st_ram_rw(row_a + 4u);
            u16 w3 = st_ram_rw(row_a + 6u);
            for (int b = 15; b >= 0; b--) {
                u32 pen = ((w0 >> b) & 1u) | (((w1 >> b) & 1u) << 1) |
                          (((w2 >> b) & 1u) << 2) | (((w3 >> b) & 1u) << 3);
                *out++ = ST.pal_rgb[pen];
            }
            out -= 16;
        }
    } else if (res == 1) {              /* 640 x 200, 2 bitplanes (4 colors) */
        u32 row_a = vbase + (u32)y * 160u;
        u16 *out = picture + y * 640;
        for (int grp = 0; grp < 40; grp++, row_a += 4u, out += 16) {
            u16 w0 = st_ram_rw(row_a + 0u);
            u16 w1 = st_ram_rw(row_a + 2u);
            for (int b = 15; b >= 0; b--) {
                u32 pen = ((w0 >> b) & 1u) | (((w1 >> b) & 1u) << 1);
                *out++ = ST.pal_rgb[pen];
            }
            out -= 16;
        }
    } else {                            /* 640 x 400 monochrome (2 lines per y) */
        int inv = (ST.pal_raw[0] & 1u) != 0;
        u16 c0 = inv ? 0x7FFFu : 0x0000u;
        u16 c1 = inv ? 0x0000u : 0x7FFFu;
        for (int sub = 0; sub < 2; sub++) {
            int ly = y * 2 + sub;
            u32 row_a = vbase + (u32)ly * 80u;
            u16 *out = picture + ly * 640;
            for (int grp = 0; grp < 40; grp++, row_a += 2u) {
                u16 w0 = st_ram_rw(row_a);
                for (int b = 15; b >= 0; b--)
                    *out++ = ((w0 >> b) & 1u) ? c1 : c0;
            }
        }
    }
}

/* ---- Floppy Image Loaders (.st, .msa RLE, and bare .prg/.tos virtual FAT12 wrapper) ---- */
static void detect_floppy_geometry(void)
{
    ST.fdc.spt = 9;
    ST.fdc.sides = 2;
    ST.fdc.tracks = 80;

    if (ST.floppy_size >= 32u) {
        u16 bps = fat12_get_le16(M->floppy + 11);
        u16 spt = fat12_get_le16(M->floppy + 24);
        u16 sides = fat12_get_le16(M->floppy + 26);
        u16 nsec = fat12_get_le16(M->floppy + 19);
        if (bps == 512u && spt >= 8u && spt <= 18u && (sides == 1u || sides == 2u)) {
            ST.fdc.spt = (u8)spt;
            ST.fdc.sides = (u8)sides;
            if (nsec)
                ST.fdc.tracks = (u8)(nsec / (spt * sides));
            return;
        }
    }
    u32 sectors = ST.floppy_size / 512u;
    if (sectors <= 820u) {
        ST.fdc.sides = 1;
        ST.fdc.spt = (sectors >= 800u && sectors % 10u == 0) ? 10 : 9;
        ST.fdc.tracks = (u8)(sectors / ST.fdc.spt);
    } else {
        ST.fdc.sides = 2;
        if (sectors % 22u == 0 && sectors >= 1760u)      ST.fdc.spt = 11;
        else if (sectors % 20u == 0 && sectors >= 1600u) ST.fdc.spt = 10;
        else                                             ST.fdc.spt = 9;
        ST.fdc.tracks = (u8)(sectors / ((u32)ST.fdc.spt * 2u));
    }
}

static const char *load_msa(const u8 *src, u32 size)
{
    if (size < 10u || src[0] != 0x0Eu || src[1] != 0x0Fu)
        return "not a valid .msa disk archive (missing 0x0E0F signature)";
    u16 spt   = (u16)((src[2] << 8) | src[3]);
    u16 sides = (u16)(((src[4] << 8) | src[5]) + 1u);
    u16 s_trk = (u16)((src[6] << 8) | src[7]);
    u16 e_trk = (u16)((src[8] << 8) | src[9]);
    if (spt < 1u || spt > 22u || sides < 1u || sides > 2u || e_trk < s_trk || e_trk > 86u)
        return "unsupported .msa disk geometry";

    u32 trk_bytes = (u32)spt * 512u;
    u32 total = (u32)(e_trk + 1u) * sides * trk_bytes;
    if (total > ST_FLOPPY_MAX)
        return ".msa unpacked size exceeds 1.5 MB floppy buffer";

    for (u32 i = 0; i < total; i++)
        M->floppy[i] = 0;

    u32 pos = 10u;
    for (u16 trk = s_trk; trk <= e_trk; trk++) {
        for (u16 sd = 0; sd < sides; sd++) {
            if (pos + 2u > size)
                return "truncated .msa track header";
            u16 dlen = (u16)((src[pos] << 8) | src[pos + 1u]);
            pos += 2u;
            if (pos + dlen > size)
                return "truncated .msa track payload";
            u8 *dst = M->floppy + ((u32)trk * sides + sd) * trk_bytes;
            if (dlen == trk_bytes) {
                for (u32 i = 0; i < trk_bytes; i++)
                    dst[i] = src[pos + i];
            } else {
                u32 i = 0, o = 0;
                while (i < dlen && o < trk_bytes) {
                    u8 b = src[pos + i++];
                    if (b == 0xE5u && i + 3u <= dlen) {
                        u8 val = src[pos + i++];
                        u16 run = (u16)((src[pos + i] << 8) | src[pos + i + 1u]);
                        i += 2u;
                        for (u16 k = 0; k < run && o < trk_bytes; k++)
                            dst[o++] = val;
                    } else {
                        dst[o++] = b;
                    }
                }
            }
            pos += dlen;
        }
    }
    ST.has_floppy = 1;
    ST.floppy_size = total;
    ST.fdc.spt = (u8)spt;
    ST.fdc.sides = (u8)sides;
    ST.fdc.tracks = (u8)(e_trk + 1u);
    return 0;
}

/* Load Pasti .stx ("RSY\0") copy-protected disk image, preserving per-sector WD1772 FDC status flags (e.g. CRC errors) */
static const char *load_stx(const u8 *src, u32 size)
{
    if (size < 16u || src[0] != 'R' || src[1] != 'S' || src[2] != 'Y' || src[3] != 0)
        return "not a valid Pasti .stx disk image (missing RSY\\0 header)";
    u8 trk_cnt = src[10];
    u8 max_cyl = 79u, max_side = 0u, max_spt = 9u;

    u32 off = 16u;
    for (u8 t = 0; t < trk_cnt && off + 16u <= size; t++) {
        u32 rec_sz  = fat12_get_le32(src + off);
        u16 sec_cnt = fat12_get_le16(src + off + 8u);
        u16 flags   = fat12_get_le16(src + off + 10u);
        u8  trk_num = src[off + 14u];
        if (rec_sz < 16u || off + rec_sz > size)
            break;
        u8 cyl  = trk_num & 0x7Fu;
        u8 side = (trk_num >> 7) & 1u;
        if (cyl < 86u && cyl > max_cyl) max_cyl = cyl;
        if (side > max_side) max_side = side;
        if ((flags & 1u) && off + 16u + (u32)sec_cnt * 16u <= off + rec_sz) {
            for (u16 s = 0; s < sec_cnt; s++) {
                u8 id_sec = src[off + 16u + (u32)s * 16u + 10u];
                if (id_sec >= 1u && id_sec <= 22u && id_sec > max_spt)
                    max_spt = id_sec;
            }
        }
        off += rec_sz;
    }

    u32 tracks = (u32)max_cyl + 1u;
    u32 sides  = (u32)max_side + 1u;
    u32 spt    = (u32)max_spt;
    u32 total  = tracks * sides * spt * 512u;
    if (total > ST_FLOPPY_MAX)
        return ".stx unpacked geometry exceeds 1.5 MB floppy buffer";

    for (u32 i = 0; i < total; i++)
        M->floppy[i] = 0;
    ST.fdc.n_bad_sec = 0;

    off = 16u;
    for (u8 t = 0; t < trk_cnt && off + 16u <= size; t++) {
        u32 rec_sz   = fat12_get_le32(src + off);
        u32 fuzzy_sz = fat12_get_le32(src + off + 4u);
        u16 sec_cnt  = fat12_get_le16(src + off + 8u);
        u16 flags    = fat12_get_le16(src + off + 10u);
        u8  trk_num  = src[off + 14u];
        if (rec_sz < 16u || off + rec_sz > size)
            break;
        u8 cyl  = trk_num & 0x7Fu;
        u8 side = (trk_num >> 7) & 1u;
        if ((flags & 1u) && cyl < tracks && side < sides &&
            off + 16u + (u32)sec_cnt * 16u + fuzzy_sz <= off + rec_sz) {
            u32 doff_base = off + 16u + (u32)sec_cnt * 16u + fuzzy_sz;
            for (u16 s = 0; s < sec_cnt; s++) {
                const u8 *sh = src + off + 16u + (u32)s * 16u;
                u32 data_off = fat12_get_le32(sh);
                u8  id_sec   = sh[10];
                u8  id_sz    = sh[11];
                u8  fdc_st   = sh[14];
                if (id_sec >= 1u && id_sec <= spt) {
                    u32 sec_bytes = 128u << (id_sz & 3u);
                    if (sec_bytes > 512u) sec_bytes = 512u;
                    u32 dst_off = (((u32)cyl * sides + side) * spt + (id_sec - 1u)) * 512u;
                    if (doff_base + data_off + sec_bytes <= off + rec_sz && dst_off + 512u <= total) {
                        for (u32 k = 0; k < sec_bytes; k++)
                            M->floppy[dst_off + k] = src[doff_base + data_off + k];
                    }
                    if (fdc_st != 0 && ST.fdc.n_bad_sec < 32u) {
                        u8 idx = ST.fdc.n_bad_sec++;
                        ST.fdc.bad_sec[idx].trk  = cyl;
                        ST.fdc.bad_sec[idx].side = side;
                        ST.fdc.bad_sec[idx].sec  = id_sec;
                        ST.fdc.bad_sec[idx].st   = fdc_st;
                    }
                }
            }
        }
        off += rec_sz;
    }

    ST.has_floppy = 1;
    ST.floppy_size = total;
    ST.fdc.spt = (u8)spt;
    ST.fdc.sides = (u8)sides;
    ST.fdc.tracks = (u8)tracks;
    return 0;
}

/* Wrap a standalone .PRG / .TOS executable into a bootable 720 KB FAT12 floppy containing \AUTO\BOOT.PRG
   so EmuTOS, Atari TOS, AND our built-in ROM all launch it automatically at boot! */
static const char *wrap_prg_in_fat12(const u8 *prg, u32 prg_size)
{
    if (prg_size < 28u || prg[0] != 0x60u || prg[1] != 0x1Au)
        return "not an Atari ST .prg/.tos executable (missing 0x601A GEMDOS header)";
    if (prg_size > 700u * 1024u)
        return ".prg executable too large for a 720 KB AUTO boot disk";

    u32 dsk_sz = 737280u;               /* 80 tracks x 2 sides x 9 sectors x 512 B */
    for (u32 i = 0; i < dsk_sz; i++)
        M->floppy[i] = 0;

    /* Boot sector BPB (512 B/sec, 2 sec/cl = 1024 B, 1 rsvd, 2 FATs, 112 root entries, 1440 sec, 3 sec/FAT) */
    M->floppy[0] = 0xEBu; M->floppy[1] = 0x34u; M->floppy[2] = 0x90u;
    M->floppy[8] = 'A'; M->floppy[9] = 'L'; M->floppy[10] = 'I';
    M->floppy[11] = 0x00u; M->floppy[12] = 0x02u;   /* 512 B/sec */
    M->floppy[13] = 2;                              /* 2 sec/cluster */
    M->floppy[14] = 1; M->floppy[15] = 0;           /* 1 reserved sector */
    M->floppy[16] = 2;                              /* 2 FATs */
    M->floppy[17] = 112; M->floppy[18] = 0;         /* 112 root entries (7 sectors) */
    M->floppy[19] = 0xA0u; M->floppy[20] = 0x05u;   /* 1440 sectors */
    M->floppy[21] = 0xF9u;                          /* Media descriptor */
    M->floppy[22] = 3; M->floppy[23] = 0;           /* 3 sectors/FAT */
    M->floppy[24] = 9; M->floppy[25] = 0;           /* 9 sectors/track */
    M->floppy[26] = 2; M->floppy[27] = 0;           /* 2 sides */

    u8 *fat1 = M->floppy + 512u;
    u8 *fat2 = M->floppy + 512u * 4u;
    u8 *root = M->floppy + 512u * 7u;
    u8 *data = M->floppy + 512u * 14u;              /* Cluster 2 starts at sector 14 */

    auto_fat_set: ;
    (void)0;
    /* Helper lambda-style FAT12 writer: Cluster 2 = \AUTO dir (1 cluster), Clusters 3..3+N-1 = BOOT.PRG */
    u32 n_cl = (prg_size + 1023u) / 1024u;
    if (!n_cl) n_cl = 1;

    fat1[0] = 0xF9u; fat1[1] = 0xFFu; fat1[2] = 0xFFu;
    for (u32 c = 2u; c < 3u + n_cl; c++) {
        u16 val = (c == 2u || c == 2u + n_cl) ? 0xFFFu : (u16)(c + 1u);
        u32 o = c + (c >> 1);
        if (c & 1u) {
            fat1[o] = (u8)((fat1[o] & 0x0Fu) | ((val & 0x0Fu) << 4));
            fat1[o + 1u] = (u8)(val >> 4);
        } else {
            fat1[o] = (u8)val;
            fat1[o + 1u] = (u8)((fat1[o + 1u] & 0xF0u) | ((val >> 8) & 0x0Fu));
        }
    }
    for (u32 i = 0; i < 512u * 3u; i++)
        fat2[i] = fat1[i];

    /* Root entry 0: "AUTO       " subdirectory (attr 0x10, start cluster 2) */
    static const char auto_nm[11] = {'A','U','T','O',' ',' ',' ',' ',' ',' ',' '};
    for (int i = 0; i < 11; i++) root[i] = (u8)auto_nm[i];
    root[11] = 0x10u;
    root[26] = 2; root[27] = 0;

    /* Cluster 2 (\AUTO directory): '.', '..', and 'BOOT    PRG' (start cluster 3) */
    u8 *adir = data;
    for (int i = 0; i < 11; i++) { adir[i] = ' '; adir[32 + i] = ' '; }
    adir[0] = '.'; adir[11] = 0x10u; adir[26] = 2;
    adir[32] = '.'; adir[33] = '.'; adir[32 + 11] = 0x10u; adir[32 + 26] = 0;

    u8 *bent = adir + 64u;
    static const char boot_nm[11] = {'B','O','O','T',' ',' ',' ',' ','P','R','G'};
    for (int i = 0; i < 11; i++) bent[i] = (u8)boot_nm[i];
    bent[11] = 0x20u;
    bent[26] = 3; bent[27] = 0;
    bent[28] = (u8)prg_size;
    bent[29] = (u8)(prg_size >> 8);
    bent[30] = (u8)(prg_size >> 16);
    bent[31] = (u8)(prg_size >> 24);

    /* Copy PRG payload starting at Cluster 3 (data + 1024) */
    for (u32 i = 0; i < prg_size; i++)
        data[1024u + i] = prg[i];

    goto done_wrap;
done_wrap:
    (void)&&auto_fat_set;
    ST.has_floppy = 1;
    ST.floppy_size = dsk_sz;
    ST.fdc.spt = 9;
    ST.fdc.sides = 2;
    ST.fdc.tracks = 80;
    return 0;
}

static int ends_with_ci(const char *name, const char *ext)
{
    if (!name) return 0;
    int n = 0, e = 0;
    while (name[n]) n++;
    while (ext[e]) e++;
    if (n < e) return 0;
    for (int i = 0; i < e; i++) {
        char c = name[n - e + i];
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        if (c != ext[i]) return 0;
    }
    return 1;
}

static void fmt_st_info(const char *media_kind)
{
    char *p = info_buf;
    const char *r = !ST.ext_rom ? "Atari 1040ST (built-in ROM), " :
                    ST.rom_is_256k ? "Atari 1040ST (EmuTOS/TOS 256K), " : "Atari 1040ST (EmuTOS/TOS 192K), ";
    while (*r) *p++ = *r++;
    while (*media_kind && p < info_buf + sizeof(info_buf) - 16) *p++ = *media_kind++;
    if (ST.has_floppy) {
        *p++ = ' ';
        u32 kb = (ST.floppy_size + 1023u) >> 10;
        char d[12];
        int n = 0;
        do { d[n++] = (char)('0' + kb % 10); kb /= 10; } while (kb);
        while (n--) *p++ = d[n];
        const char *s = " KB";
        while (*s) *p++ = *s++;
    }
    *p = 0;
}

const char *st_load(const u8 *tos_rom, u32 tos_size, u8 *media, u32 media_size, const char *name)
{
    u8 was_inited = ST.cpu_inited;
    for (u32 i = 0; i < sizeof(ST); i++)
        ((u8 *)&ST)[i] = 0;
    ST.cpu_inited = was_inited;
    if (!ST.cpu_inited) {
        cpu_init();
        ST.cpu_inited = 1;
    }

    for (u32 i = 0; i < ST_ROM_MAX; i++)
        M->rom[i] = 0xFFu;

    if (tos_rom && tos_size) {
        if (tos_size != 0x30000u && tos_size != 0x40000u)
            return "TOS / EmuTOS ROM must be 192 KB (196608 B) or 256 KB (262144 B)";
        for (u32 i = 0; i < tos_size; i += 2u) {
            u16 w = (u16)(((u16)tos_rom[i] << 8) | tos_rom[i + 1u]);
            st_rom_put_be16(i, w);
        }
        ST.ext_rom = 1;
        ST.rom_is_256k = (tos_size == 0x40000u) ? 1 : 0;
        ST.rom_size = tos_size;
    } else {
        build_clean_tos();
        ST.ext_rom = 0;
        ST.rom_is_256k = 0;
        ST.rom_size = 0x30000u;
    }

    const char *kind = "Desktop";
    if (media && media_size) {
        const char *why = 0;
        if (ends_with_ci(name, ".stx") ||
            (media_size >= 16u && media[0] == 'R' && media[1] == 'S' && media[2] == 'Y' && media[3] == 0)) {
            why = load_stx(media, media_size);
            kind = ".stx Pasti disk";
        } else if (ends_with_ci(name, ".msa") || (media_size >= 10u && media[0] == 0x0Eu && media[1] == 0x0Fu)) {
            why = load_msa(media, media_size);
            kind = ".msa disk";
        } else if (ends_with_ci(name, ".prg") || ends_with_ci(name, ".tos") || ends_with_ci(name, ".ttp") ||
                   (media_size >= 28u && media[0] == 0x60u && media[1] == 0x1Au && media_size < 360u * 1024u)) {
            why = wrap_prg_in_fat12(media, media_size);
            kind = ".prg AUTO boot";
        } else {
            if (media_size < 512u || media_size > ST_FLOPPY_MAX)
                return "Atari ST .st disk image must be between 512 B and 1.5 MB";
            for (u32 i = 0; i < media_size; i++)
                M->floppy[i] = media[i];
            ST.has_floppy = 1;
            ST.floppy_size = media_size;
            detect_floppy_geometry();
            kind = ".st disk";
        }
        if (why)
            return why;
    }
    (void)st_load_and_reloc_prg;

    st_reset();
    fmt_st_info(kind);
    return 0;
}

void st_reset(void)
{
    for (u32 i = 0; i < ST_RAM_SIZE; i++)
        M->ram[i] = 0;

    ST.mmu_cfg = 0x09u;                 /* 2 MB Bank 0 */
    ST.vbase_hi = 0x1Fu;
    ST.vbase_mid = 0x80u;
    ST.vbase_lo = 0x00u;
    ST.sync_mode = 0x02u;               /* 50 Hz PAL */
    ST.shift_res = 0;
    ST.cur_w = ST_W_LOW;
    ST.cur_h = ST_H_LOW;
    ST.vbl_pending = ST.hbl_pending = 0;

    for (u32 i = 0; i < sizeof(ST.ym); i++)
        ((u8 *)&ST.ym)[i] = 0;
    ST.ym.reg[7] = 0x3Fu;
    ST.ym.reg[14] = 0x07u;              /* Drives deselected, Side 0 */
    ST.ym.lfsr = 1u;

    for (u32 i = 0; i < sizeof(ST.mfp); i++)
        ((u8 *)&ST.mfp)[i] = 0;
    ST.mfp.vr = 0x40u;

    for (u32 i = 0; i < sizeof(ST.ikbd); i++)
        ((u8 *)&ST.ikbd)[i] = 0;
    ST.ikbd.joy_mode = 1;

    ST.fdc.dma_addr = 0;
    ST.fdc.dma_mode = 0;
    ST.fdc.dma_sec_cnt = 0;
    ST.fdc.dma_status = 0x01u;
    ST.fdc.track = 0;
    ST.fdc.sector = 1;
    ST.fdc.status = 0x04u;
    ST.fdc.irq = 0;

    for (u32 i = 0; i < sizeof(ST.blt); i++)
        ((u8 *)&ST.blt)[i] = 0;

    for (int i = 0; i < 16; i++) {
        ST.pal_raw[i] = (i == 0) ? 0x0777u : 0x0000u;
        st_update_pal_entry(i);
    }

    st_setup_maps();
    m.clock = 0;
    cpu_reset();
}

void st_frame(u16 pad, const u8 *hid_usages, int hid_n, u16 *picture)
{
    st_poll_inputs(pad, hid_usages, hid_n);
    ST.audio_count = 0;
    ST.audio_last_clk = m.clock;

    u8 res = ST.shift_res & 3u;
    ST.cur_w = (res == 0) ? 320 : 640;
    ST.cur_h = (res == 2) ? 400 : 200;

    int total_lines = (ST.sync_mode & 0x02u) ? ST_LINES_PAL : ST_LINES_NTSC;
    int vis_start = (total_lines == ST_LINES_PAL) ? 63 : 34;

    for (int line = 0; line < total_lines; line++) {
        ST.cur_line = line;
        ST.line_start_clk = line * ST_CYCLES_LINE;
        s32 line_end = (line + 1) * ST_CYCLES_LINE;

        /* Render active display line mid-scanline so early-line raster writes apply cleanly */
        cpu_run(ST.line_start_clk + 376);
        if (line >= vis_start && line < vis_start + 200) {
            st_render_line(line - vis_start, picture);
            mfp_hbl_event_tick();
        }
        cpu_run(line_end);

        mfp_step_timers(ST_CYCLES_LINE);

        /* HBL autovector (IPL 2, masked by default since TOS runs at SR $2300 = IM 3!) */
        ST.hbl_pending = 1;
        if (line == vis_start + 200)
            ST.vbl_pending = 1;         /* VBL autovector (IPL 4) at bottom border! */
        st_update_ipl();
    }

    audio_catch_up();
    m.clock -= total_lines * ST_CYCLES_LINE;
}

int st_width(void)  { return ST.cur_w ? ST.cur_w : ST_W_LOW; }
int st_height(void) { return ST.cur_h ? ST.cur_h : ST_H_LOW; }
int st_pal(void)    { return (ST.sync_mode & 0x02u) ? 1 : 0; }

const char *st_info(void) { return info_buf; }

u8 *st_save_ram(u32 *size, int *battery)
{
    *size = 0;
    *battery = 0;
    return M->ram;
}

int st_save_changed(void) { return 0; }

int st_jammed(void)
{
    return m.stopped && m.im == 7;
}

void st_audio_rate(u32 hz)
{
    ST.sample_rate = hz;
    ST.audio_frac = 0;
    ST.audio_count = 0;
    ST.audio_last_clk = m.clock;
}

int st_audio(s16 *out, int max)
{
    int n = ST.audio_count < max ? ST.audio_count : max;
    for (int i = 0; i < n; i++)
        out[i] = M->audio_ring[i];
    ST.audio_count = 0;
    return n;
}
