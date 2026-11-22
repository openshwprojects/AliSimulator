/* A ColecoVision (with MegaCart & Super Game Module): see col.h. */
#include "col.h"
#include "z80.h"
#ifndef COL_HOST
#include "hw.h"
#endif

#define LINE_T   228
#define LINES    262
#define FRAME_T  (LINE_T * LINES)       /* 59736 T-states @ 3.579545 MHz = 59.92 Hz */

struct col_mem {
    u8 bios[0x2000];                    /* 8 KB OS-7 / built-in BIOS at $0000..$1FFF */
    u8 ram[0x8000];                     /* 1 KB base RAM (mirrored $6000..$7FFF) or 32 KB SGM RAM ($0000..$7FFF) */
    u8 vram[0x4000];                    /* 16 KB TMS9928A VRAM */
    u8 open_bus[0x400];                 /* 0xFF unmapped page */
    u8 sav_dummy[256];
    s16 audio_ring[4096];
};

#ifdef COL_HOST
static struct col_mem col_mem_buf;
#define M (&col_mem_buf)
#else
#define M ((struct col_mem *)KSEG0(EMU_RAM_PHYS))
#endif

struct sn76489 {
    u16 period[4];
    u8 atten[4];
    u8 latch;
    u32 phase[4];
    u8 out_bit[3];
    u16 lfsr;
};

struct ay8910 {
    u8 reg_sel;
    u8 reg[16];
    u32 phase[3], noise_phase, env_phase;
    u8 out_bit[3];
    u32 lfsr;
    u8 env_step, env_vol, env_hold, env_alt, env_att;
};

static struct {
    struct z80 cpu;
    u8 *rom;
    u32 rom_size, num_banks;            /* 16 KB banks for MegaCart / Activision PCB */
    u8 megacart, pcb_mapper, fixed_bank, cur_bank;
    u8 ext_bios;
    u8 sgm_ram24, sgm_low_ram;          /* SGM ports 0x53 & 0x7F */
    u8 port_7f;

    /* TMS9928A VDP */
    u8 vdp_reg[8];
    u16 vdp_addr;
    u8 vdp_first, vdp_latch, vdp_buf, vdp_status, vdp_int_prev;
    u16 tms_pal[16];

    /* Controllers */
    u16 pad_state;
    u8 key_override;                    /* 0..11 or 0xFF */
    u8 joy_mode;                        /* 0 = keypad + right fire, 1 = joystick + left fire */

    /* Audio (SN76489A + SGM AY-3-8910) */
    struct sn76489 sn;
    struct ay8910 ay;
    u32 sample_rate, audio_frac;
    s32 audio_last_cyc;
    int audio_count;

    /* HLE OS-7 Sound Manager state (for BIOS sound-table games) */
    u16 snd_tab;
    u8 snd_slots;
    struct {
        u8 active;
        u16 area, ptr, freq;
        u8 ch, atten, ticks, rem;
        s16 freq_step;
        u8 fstep_per, fstep_cnt;
        s8 att_step;
        u8 astep_per, astep_cnt;
    } hle_snd[6];
} S;

static char info_buf[96];

/* 15-step 2 dB attenuation table for SN76489 & AY-3-8910 */
static const s16 vol_tab16[16] = {
    4096, 3254, 2584, 2053, 1631, 1295, 1029, 817,
     649,  516,  410,  325,  258,  205,  163,   0
};

/* Compact 8x8 ASCII font (0x20..0x7F) for built-in BIOS $15A3 */
static const u8 bios_font96[96][8] = {
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

/* ---- Audio synthesis (SN76489A + optional SGM AY-3-8910) ---- */
static void audio_step(u32 tstates)
{
    if (!S.sample_rate || !tstates)
        return;
    u32 count = 0;
    while (tstates) {
        u32 chunk = tstates > 16000u ? 16000u : tstates;
        tstates -= chunk;
        u32 num = chunk * S.sample_rate + S.audio_frac;
        count += num / 3579545u;
        S.audio_frac = num % 3579545u;
    }
    if (!count)
        return;

    /* SN76489 clock = 3579545 / 16 = 223721.56 Hz -> 223721.56 * 256 = 57272720 */
    u32 sn_step = 57272720u / S.sample_rate;
    /* AY-3-8910 clock = 3579545 / 16 = 223721.56 Hz -> same 24.8 step */
    u32 ay_step = sn_step;

    while (count--) {
        s32 mix = 0;
        /* SN76489A 3 square tones + 1 LFSR noise */
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
            s16 v = vol_tab16[S.sn.atten[ch] & 15];
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
                /* TI SN76489A 15-bit LFSR: white noise taps bits 0 & 1, periodic taps bit 0 */
                u16 fb = (S.sn.period[3] & 4u)
                       ? (u16)(((S.sn.lfsr >> 0) ^ (S.sn.lfsr >> 1)) & 1u)
                       : (u16)(S.sn.lfsr & 1u);
                S.sn.lfsr = (u16)((S.sn.lfsr >> 1) | (fb << 14));
            }
            s16 v = vol_tab16[S.sn.atten[3] & 15];
            mix += (S.sn.lfsr & 1u) ? v : -v;
        }

        /* SGM AY-3-8910 (active when SGM writes registers 8..10) */
        if ((S.ay.reg[8] | S.ay.reg[9] | S.ay.reg[10]) & 0x1Fu) {
            u32 ep = (u32)S.ay.reg[11] | ((u32)S.ay.reg[12] << 8);
            if (!ep) ep = 1u;
            u32 ep8 = ep << 9;
            S.ay.env_phase += ay_step;
            while (S.ay.env_phase >= ep8) {
                S.ay.env_phase -= ep8;
                if (!S.ay.env_hold) {
                    S.ay.env_step++;
                    if (S.ay.env_step >= 16) {
                        S.ay.env_step = 0;
                        u8 sh = S.ay.reg[13] & 0x0Fu;
                        if (!(sh & 0x08)) {
                            S.ay.env_att = 0;
                            S.ay.env_hold = 1;
                        } else {
                            if (sh & 0x02) S.ay.env_att ^= 0x0Fu;
                            if (sh & 0x01) { S.ay.env_hold = 1; S.ay.env_step = 15; }
                        }
                    }
                }
                S.ay.env_vol = (S.ay.env_step ^ S.ay.env_att) & 15u;
            }
            u32 np = S.ay.reg[6] & 0x1Fu;
            if (!np) np = 1u;
            u32 np8 = np << 9;
            S.ay.noise_phase += ay_step;
            while (S.ay.noise_phase >= np8) {
                S.ay.noise_phase -= np8;
                u32 fb = ((S.ay.lfsr >> 0) ^ (S.ay.lfsr >> 3)) & 1u;
                S.ay.lfsr = (S.ay.lfsr >> 1) | (fb << 16);
            }
            u8 mixer = S.ay.reg[7];
            for (int ch = 0; ch < 3; ch++) {
                u32 tp = (u32)S.ay.reg[ch * 2] | (((u32)S.ay.reg[ch * 2 + 1] & 0x0Fu) << 8);
                if (!tp) tp = 1u;
                u32 tp8 = tp << 8;
                S.ay.phase[ch] += ay_step;
                while (S.ay.phase[ch] >= tp8) {
                    S.ay.phase[ch] -= tp8;
                    S.ay.out_bit[ch] ^= 1u;
                }
                int t_ok = (mixer & (1u << ch)) || S.ay.out_bit[ch];
                int n_ok = (mixer & (8u << ch)) || (S.ay.lfsr & 1u);
                u8 vr = S.ay.reg[8 + ch];
                u8 vol = (vr & 0x10u) ? S.ay.env_vol : (vr & 0x0Fu);
                s16 amp = vol_tab16[15 - vol];
                if (t_ok && n_ok)
                    mix += amp;
            }
        }

        mix = (mix * 3) >> 2;
        if (mix > 32767) mix = 32767;
        if (mix < -32768) mix = -32768;
        if (S.audio_count < 4096)
            M->audio_ring[S.audio_count++] = (s16)mix;
    }
}

static void audio_catch_up(void)
{
    if (!S.sample_rate)
        return;
    s32 now = S.cpu.cycles;
    if (now > S.audio_last_cyc) {
        audio_step((u32)(now - S.audio_last_cyc));
        S.audio_last_cyc = now;
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
            S.sn.period[ch] = (S.sn.period[ch] & 0x3F0u) | (v & 0x0Fu);
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

static void ay_write_reg(u8 r, u8 v)
{
    if (r >= 16)
        return;
    audio_catch_up();
    S.ay.reg[r] = v;
    if (r == 13) {
        S.ay.env_phase = 0;
        S.ay.env_step = 0;
        S.ay.env_hold = 0;
        S.ay.env_att = (v & 0x04u) ? 0x00u : 0x0Fu;
        S.ay.env_vol = S.ay.env_att;
    }
}

/* ---- TMS9928A VDP & NMI edge ---- */
static void vdp_check_nmi(void)
{
    u8 line_on = (u8)(((S.vdp_status & 0x80u) && (S.vdp_reg[1] & 0x20u)) ? 1 : 0);
    if (line_on && !S.vdp_int_prev)
        S.cpu.nmi = 1;
    S.vdp_int_prev = line_on;
}

static void vdp_data_write(u8 v)
{
    S.vdp_first = 0;
    M->vram[S.vdp_addr & 0x3FFFu] = v;
    S.vdp_buf = v;
    S.vdp_addr = (S.vdp_addr + 1u) & 0x3FFFu;
}

static u8 vdp_data_read(void)
{
    u8 v = S.vdp_buf;
    S.vdp_first = 0;
    S.vdp_buf = M->vram[S.vdp_addr & 0x3FFFu];
    S.vdp_addr = (S.vdp_addr + 1u) & 0x3FFFu;
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
        vdp_check_nmi();
    } else if (!(v & 0x40u)) {
        S.vdp_buf = M->vram[S.vdp_addr & 0x3FFFu];
        S.vdp_addr = (S.vdp_addr + 1u) & 0x3FFFu;
    }
}

static u8 vdp_status_read(void)
{
    u8 v = S.vdp_status;
    S.vdp_status &= 0x1Fu;
    S.vdp_first = 0;
    vdp_check_nmi();
    return v;
}

/* ---- Memory map ---- */
static void rebuild_map(void)
{
    for (int i = 0; i < 64; i++) {
        S.cpu.rd[i] = M->open_bus;
        S.cpu.wr[i] = 0;
    }
    /* $0000..$1FFF: 8 KB BIOS or SGM low RAM */
    for (int i = 0; i < 8; i++) {
        if (S.sgm_low_ram) {
            S.cpu.rd[i] = M->ram + i * 0x400;
            S.cpu.wr[i] = M->ram + i * 0x400;
        } else {
            S.cpu.rd[i] = M->bios + i * 0x400;
        }
    }
    /* $2000..$5FFF: unmapped unless SGM 24 KB RAM enabled */
    if (S.sgm_ram24) {
        for (int i = 8; i < 32; i++) {
            S.cpu.rd[i] = M->ram + i * 0x400;
            S.cpu.wr[i] = M->ram + i * 0x400;
        }
    } else {
        /* $6000..$7FFF: 1 KB base RAM mirrored 8 times */
        for (int i = 24; i < 32; i++) {
            S.cpu.rd[i] = M->ram + 0x6000;
            S.cpu.wr[i] = M->ram + 0x6000;
        }
    }
    /* $8000..$FFFF: Cartridge */
    if (S.rom && S.rom_size) {
        if (S.megacart) {
            u8 *b_lo = S.rom + (u32)S.fixed_bank * 0x4000u;
            u8 *b_hi = S.rom + (u32)(S.cur_bank % S.num_banks) * 0x4000u;
            for (int i = 0; i < 16; i++)
                S.cpu.rd[32 + i] = b_lo + i * 0x400;
            for (int i = 0; i < 15; i++)
                S.cpu.rd[48 + i] = b_hi + i * 0x400;
            /* Page 63 ($FC00..$FFFF) goes through cpu_read so $FFC0..$FFFF triggers MegaCart bank switch */
            S.cpu.rd[63] = 0;
        } else {
            for (u32 i = 0; i < 32; i++) {
                u32 off = i * 0x400u;
                if (off < S.rom_size)
                    S.cpu.rd[32 + i] = S.rom + off;
            }
        }
    }
}

static inline void switch_cart_bank(u16 a, int is_write)
{
    if (S.pcb_mapper) {
        /* Activision / Pixelboy PCB: writes to $FF90/$FFA0/$FFB0 (and $FF80) switch 16 KB bank;
           $FFC0..$FFFF are serial EEPROM SCL/SDA lines and must NOT switch ROM banks */
        if (is_write && a >= 0xFF80u && a < 0xFFC0u) {
            S.cur_bank = (u8)(((a - 0xFF80u) >> 4) % S.num_banks);
            rebuild_map();
        }
    } else if (a >= 0xFFC0u) {
        S.cur_bank = (u8)((a & 0x3Fu) % S.num_banks);
        rebuild_map();
    }
}

static inline u8 mem_rd8(u16 a)
{
    u8 *p = S.cpu.rd[a >> 10];
    if (p)
        return p[a & 0x3FFu];
    if (S.megacart && a >= 0xFC00u) {
        if (S.pcb_mapper && a == 0xFF80u)
            return 0xFFu;
        switch_cart_bank(a, 0);
        return S.rom[(u32)S.cur_bank * 0x4000u + (a - 0xC000u)];
    }
    return 0xFF;
}

static inline void mem_wr8(u16 a, u8 v)
{
    u8 *p = S.cpu.wr[a >> 10];
    if (p) {
        p[a & 0x3FFu] = v;
        return;
    }
    if (S.megacart && a >= 0xFF80u)
        switch_cart_bank(a, 1);
}

static u8 cpu_read(struct z80 *c, u16 a)
{
    (void)c;
    return mem_rd8(a);
}

static void cpu_write(struct z80 *c, u16 a, u8 v)
{
    (void)c;
    mem_wr8(a, v);
}

/* ---- Controller decoding ---- */
static u8 keypad_code_for_pad(void)
{
    /* Hardware keypad codes (active-low pattern index into OS-7 keypad_table) */
    static const u8 hw_code[12] = {
        0x0A, /* 0 */  0x0D, /* 1 */  0x07, /* 2 */  0x0C, /* 3 */
        0x02, /* 4 */  0x03, /* 5 */  0x0E, /* 6 */  0x05, /* 7 */
        0x01, /* 8 */  0x0B, /* 9 */  0x09, /* * */  0x06  /* # */
    };
    if (S.key_override < 12)
        return hw_code[S.key_override];
    if (S.pad_state & COL_START)  return hw_code[1];
    if (S.pad_state & COL_SELECT) return hw_code[10];   /* * */
    if (S.pad_state & COL_SHARP)  return hw_code[11];   /* # */
    if (S.pad_state & COL_KEY2)   return hw_code[2];
    if (S.pad_state & COL_KEY3)   return hw_code[3];
    if (S.pad_state & COL_KEY4)   return hw_code[4];
    return 0x0Fu;                                       /* no key pressed */
}

static u8 read_controller(int port2)
{
    if (port2)
        return 0x7Fu;
    if (S.joy_mode) {                                   /* Joystick + Left Fire */
        u8 v = 0x7Fu;
        if (S.pad_state & COL_UP)    v &= (u8)~0x01u;
        if (S.pad_state & COL_RIGHT) v &= (u8)~0x02u;
        if (S.pad_state & COL_DOWN)  v &= (u8)~0x04u;
        if (S.pad_state & COL_LEFT)  v &= (u8)~0x08u;
        if (S.pad_state & COL_FIRE1) v &= (u8)~0x40u;
        return v;
    } else {                                            /* Keypad + Right Fire */
        u8 v = (u8)(0x70u | keypad_code_for_pad());
        if (S.pad_state & COL_FIRE2) v &= (u8)~0x40u;
        return v;
    }
}

/* ---- Clean-room HLE OS-7 BIOS routines ---- */
static void hle_snd_silence(void)
{
    sn_write(0x9Fu);
    sn_write(0xBFu);
    sn_write(0xDFu);
    sn_write(0xFFu);
}

static void hle_snd_apply_ch(u8 ch, u16 freq, u8 att)
{
    if (ch == 0) {                                      /* Noise */
        sn_write((u8)(0xE0u | (freq & 7u)));
        sn_write((u8)(0xF0u | (att & 0x0Fu)));
    } else {                                            /* Tone 1..3 -> SN ch 0..2 */
        u8 c = (u8)((ch - 1u) & 3u);
        sn_write((u8)(0x80u | (c << 5) | (freq & 0x0Fu)));
        sn_write((u8)((freq >> 4) & 0x3Fu));
        sn_write((u8)(0x90u | (c << 5) | (att & 0x0Fu)));
    }
}

static void hle_snd_load_note(int s)
{
    u16 p = S.hle_snd[s].ptr;
    u8 cmd = mem_rd8(p);
    u8 ch = (cmd >> 6) & 3u;
    u8 sub = cmd & 0x3Fu;
    S.hle_snd[s].ch = ch;
    if (cmd == 0xFFu || sub == 0x10u) {
        S.hle_snd[s].active = 0;
        mem_wr8(S.hle_snd[s].area, 0xFFu);
        hle_snd_apply_ch(ch, 0, 15);
        return;
    }
    if (sub == 0x18u) {
        S.hle_snd[s].atten = 15;
        S.hle_snd[s].rem = mem_rd8((u16)(p + 1u));
        S.hle_snd[s].ptr = (u16)(p + 2u);
        S.hle_snd[s].fstep_per = 0;
        S.hle_snd[s].astep_per = 0;
        hle_snd_apply_ch(ch, 0, 15);
        return;
    }
    u8 kind = cmd & 3u;
    u8 b1 = mem_rd8((u16)(p + 1u));
    u8 b2 = mem_rd8((u16)(p + 2u));
    u8 b3 = mem_rd8((u16)(p + 3u));
    if (ch == 0) {
        S.hle_snd[s].freq = (u16)(cmd & 0x04u ? (b1 & 7u) : ((b2 & 7u) ? (b2 & 7u) : (b1 & 7u)));
        S.hle_snd[s].atten = (b1 >> 4) & 0x0Fu;
        S.hle_snd[s].rem = (kind == 2u) ? b2 : b3;
    } else {
        S.hle_snd[s].freq = (u16)(b1 | ((u16)(b2 & 0x03u) << 8));
        S.hle_snd[s].atten = (b2 >> 4) & 0x0Fu;
        S.hle_snd[s].rem = b3;
    }
    S.hle_snd[s].fstep_per = 0;
    S.hle_snd[s].astep_per = 0;
    if (kind == 0u) {
        S.hle_snd[s].ptr = (u16)(p + 4u);
    } else if (kind == 1u) {
        u8 b4 = mem_rd8((u16)(p + 4u)), b5 = mem_rd8((u16)(p + 5u));
        S.hle_snd[s].fstep_per = b4 & 0x0Fu;
        S.hle_snd[s].fstep_cnt = S.hle_snd[s].fstep_per;
        S.hle_snd[s].freq_step = (s16)((signed char)b5 * 16 + (b4 >> 4));
        S.hle_snd[s].ptr = (u16)(p + 6u);
    } else if (kind == 2u) {
        u8 off = (ch == 0) ? 3u : 4u;
        u8 v1 = mem_rd8((u16)(p + off)), v2 = mem_rd8((u16)(p + off + 1u));
        S.hle_snd[s].astep_per = v2 & 0x0Fu;
        S.hle_snd[s].astep_cnt = S.hle_snd[s].astep_per;
        S.hle_snd[s].att_step = (v1 & 0x10u) ? 1 : -1;
        S.hle_snd[s].ptr = (u16)(p + off + 2u);
    } else {
        u8 b4 = mem_rd8((u16)(p + 4u)), b5 = mem_rd8((u16)(p + 5u));
        u8 b6 = mem_rd8((u16)(p + 6u)), b7 = mem_rd8((u16)(p + 7u));
        S.hle_snd[s].fstep_per = b4 & 0x0Fu;
        S.hle_snd[s].fstep_cnt = S.hle_snd[s].fstep_per;
        S.hle_snd[s].freq_step = (s16)((signed char)b5 * 16 + (b4 >> 4));
        S.hle_snd[s].astep_per = b7 & 0x0Fu;
        S.hle_snd[s].astep_cnt = S.hle_snd[s].astep_per;
        S.hle_snd[s].att_step = (b6 & 0x10u) ? 1 : -1;
        S.hle_snd[s].ptr = (u16)(p + 8u);
    }
    if (!S.hle_snd[s].rem)
        S.hle_snd[s].rem = 1;
    hle_snd_apply_ch(S.hle_snd[s].ch, S.hle_snd[s].freq, S.hle_snd[s].atten);
}

static void hle_snd_tick(void)
{
    for (int s = 0; s < 6; s++) {
        if (!S.hle_snd[s].active)
            continue;
        if (mem_rd8(S.hle_snd[s].area) == 0xFFu) {
            S.hle_snd[s].active = 0;
            hle_snd_apply_ch(S.hle_snd[s].ch, 0, 15);
            continue;
        }
        if (S.hle_snd[s].rem > 1) {
            S.hle_snd[s].rem--;
            int dirty = 0;
            if (S.hle_snd[s].fstep_per) {
                if (--S.hle_snd[s].fstep_cnt == 0) {
                    S.hle_snd[s].fstep_cnt = S.hle_snd[s].fstep_per;
                    S.hle_snd[s].freq = (u16)((S.hle_snd[s].freq + S.hle_snd[s].freq_step) & 0x3FFu);
                    dirty = 1;
                }
            }
            if (S.hle_snd[s].astep_per) {
                if (--S.hle_snd[s].astep_cnt == 0) {
                    S.hle_snd[s].astep_cnt = S.hle_snd[s].astep_per;
                    int na = (int)S.hle_snd[s].atten + S.hle_snd[s].att_step;
                    if (na < 0) na = 0;
                    if (na > 15) na = 15;
                    S.hle_snd[s].atten = (u8)na;
                    dirty = 1;
                }
            }
            if (dirty)
                hle_snd_apply_ch(S.hle_snd[s].ch, S.hle_snd[s].freq, S.hle_snd[s].atten);
        } else {
            hle_snd_load_note(s);
        }
    }
}

static u32 os7_vram_count(u8 b, u8 c)
{
    u32 outer = b ? b : 1u;
    u32 first_run = c ? c : 256u;
    return first_run + (outer - 1u) * 256u;
}

static void hle_write_reg(u8 r, u8 val)
{
    r &= 7u;
    if (r == 0) mem_wr8(0x73C3u, val);
    else if (r == 1) mem_wr8(0x73C4u, val);
    vdp_ctrl_write(val);
    vdp_ctrl_write((u8)(0x80u | r));
}

static void hle_init_table(u8 code, u16 base)
{
    if (code > 4)
        return;
    u16 slot = (u16)(0x73F2u + (u16)code * 2u);
    mem_wr8(slot, (u8)base);
    mem_wr8((u16)(slot + 1u), (u8)(base >> 8));
    u8 m2 = mem_rd8(0x73C3u) & 0x02u;
    switch (code) {
    case 0: hle_write_reg(5, (u8)(base >> 7)); break;
    case 1: hle_write_reg(6, (u8)(base >> 11)); break;
    case 2: hle_write_reg(2, (u8)(base >> 10)); break;
    case 3: hle_write_reg(4, (u8)((base >> 11) | (m2 ? 0x03u : 0x00u))); break;
    case 4: hle_write_reg(3, (u8)((base >> 6) | (m2 ? 0x7Fu : 0x00u))); break;
    }
}

static void hle_mode_1(void)
{
    hle_write_reg(0, 0x00u);
    hle_write_reg(1, 0x80u);
    hle_init_table(0, 0x1B00u);
    hle_init_table(1, 0x3800u);
    hle_init_table(2, 0x1800u);
    hle_init_table(3, 0x0000u);
    hle_init_table(4, 0x2000u);
    hle_write_reg(7, 0x00u);
}

static void hle_bios_dispatch(int vec_idx)
{
    struct z80 *c = &S.cpu;
    u16 addr = (u16)(0x1F61u + vec_idx * 3);
    if (vec_idx == 63) {                /* Boot init ($1E00) */
        hle_snd_silence();
        hle_mode_1();
        for (u32 i = 0; i < 0x4000u; i++)
            M->vram[i] = 0;
        u16 seed = 0x0033u;
        mem_wr8(0x73C8u, (u8)seed);
        mem_wr8(0x73C9u, (u8)(seed >> 8));
        /* Copy built-in ASCII font into pattern table $0100 ($20 * 8) as real OS-7 startup does */
        for (u32 ch = 0; ch < 96; ch++)
            for (u32 r = 0; r < 8; r++)
                M->vram[0x0100u + ch * 8u + r] = M->bios[0x15A3u + ch * 8u + r];
        for (u32 i = 0; i < 32; i++)
            M->vram[0x2000u + i] = 0xF1u;
        return;
    }

    switch (addr) {
    case 0x1F61:                        /* PLAY_SONGS */
        hle_snd_tick();
        break;
    case 0x1F76: {                      /* CONTROLLER_SCAN */
        S.joy_mode = 1;
        mem_wr8(0x73EEu, (u8)~read_controller(0));
        mem_wr8(0x73EFu, (u8)~read_controller(1));
        S.joy_mode = 0;
        mem_wr8(0x73F0u, (u8)~read_controller(0));
        mem_wr8(0x73F1u, (u8)~read_controller(1));
        c->cycles += 120;
        break;
    }
    case 0x1F7F: {                      /* LOAD_ASCII */
        u16 pbase = (u16)(mem_rd8(0x73F8u) | ((u16)mem_rd8(0x73F9u) << 8));
        for (u32 ch = 0; ch < 96; ch++)
            for (u32 r = 0; r < 8; r++)
                M->vram[(pbase + 0x100u + ch * 8u + r) & 0x3FFFu] = M->bios[0x15A3u + ch * 8u + r];
        c->cycles += 4096;
        break;
    }
    case 0x1F82: {                      /* FILL_VRAM: HL = vram, DE = count, A = val */
        u16 dst = c->hl.w;
        u32 cnt = c->de.w ? c->de.w : 0x10000u;
        u8 val = c->af.b.h;
        S.vdp_first = 0;
        for (u32 i = 0; i < cnt; i++)
            M->vram[(dst + i) & 0x3FFFu] = val;
        S.vdp_addr = (u16)((dst + cnt) & 0x3FFFu);
        c->de.w = 0;
        c->cycles += (s32)(cnt * 20u);
        break;
    }
    case 0x1F85:                        /* MODE_1 */
        hle_mode_1();
        c->cycles += 200;
        break;
    case 0x1F88:                        /* UPDATE_SPINNER */
        break;
    case 0x1FB8:                        /* INIT_TABLE: A = code, HL = vram base */
        hle_init_table(c->af.b.h, c->hl.w);
        c->cycles += 80;
        break;
    case 0x1FBB:                        /* GET_VRAM: A = table, DE = offset, HL = dst, BC = count */
    case 0x1FBE: {                      /* PUT_VRAM: A = table, DE = offset, HL = src, BC = count */
        u8 code = c->af.b.h;
        if (code <= 4) {
            u16 slot = (u16)(0x73F2u + (u16)code * 2u);
            u16 base = (u16)(mem_rd8(slot) | ((u16)mem_rd8((u16)(slot + 1u)) << 8));
            u16 va = (u16)(base + c->de.w);
            u32 cnt = c->bc.w ? c->bc.w : 1u;
            S.vdp_first = 0;
            for (u32 i = 0; i < cnt; i++) {
                if (addr == 0x1FBE)
                    M->vram[(va + i) & 0x3FFFu] = mem_rd8((u16)(c->hl.w + i));
                else
                    mem_wr8((u16)(c->hl.w + i), M->vram[(va + i) & 0x3FFFu]);
            }
            S.vdp_addr = (u16)((va + cnt) & 0x3FFFu);
            c->cycles += (s32)(cnt * 24u);
        }
        break;
    }
    case 0x1FC1: {                      /* INIT_SPR_ORDER: B = count */
        u16 ord = (u16)(mem_rd8(0x8004u) | ((u16)mem_rd8(0x8005u) << 8));
        u32 cnt = c->bc.b.h ? c->bc.b.h : 32u;
        if (ord >= 0x6000u && ord < 0x8000u)
            for (u32 i = 0; i < cnt; i++)
                mem_wr8((u16)(ord + i), (u8)i);
        break;
    }
    case 0x1FC4: {                      /* WR_SPR_NM_TBL: B = count */
        u16 src = (u16)(mem_rd8(0x8002u) | ((u16)mem_rd8(0x8003u) << 8));
        u16 ord = (u16)(mem_rd8(0x8004u) | ((u16)mem_rd8(0x8005u) << 8));
        u16 sat = (u16)(mem_rd8(0x73F2u) | ((u16)mem_rd8(0x73F3u) << 8));
        u32 cnt = c->bc.b.h ? c->bc.b.h : 32u;
        if (cnt > 32u) cnt = 32u;
        for (u32 i = 0; i < cnt; i++) {
            u8 idx = (ord >= 0x6000u && ord < 0x8000u) ? (mem_rd8((u16)(ord + i)) & 31u) : (u8)i;
            for (u32 k = 0; k < 4; k++)
                M->vram[(sat + i * 4u + k) & 0x3FFFu] = mem_rd8((u16)(src + idx * 4u + k));
        }
        c->cycles += (s32)(cnt * 60u);
        break;
    }
    case 0x1FD6:                        /* TURN_OFF_SOUND */
        for (int s = 0; s < 6; s++)
            S.hle_snd[s].active = 0;
        hle_snd_silence();
        break;
    case 0x1FD9:                        /* WRITE_REGISTER: B = reg, C = val */
        hle_write_reg(c->bc.b.h, c->bc.b.l);
        c->cycles += 40;
        break;
    case 0x1FDC: {                      /* READ_REGISTER -> A and ($73C5) */
        u8 st = vdp_status_read();
        c->af.b.h = st;
        c->af.b.l = (u8)((st & 0x80u) | (st ? 0 : Z80_FZ));
        mem_wr8(0x73C5u, st);
        c->cycles += 32;
        break;
    }
    case 0x1FDF: {                      /* WRITE_VRAM: HL = src, DE = dst, BC = OS-7 count */
        u32 cnt = os7_vram_count(c->bc.b.h, c->bc.b.l);
        u16 src = c->hl.w, dst = c->de.w;
        S.vdp_first = 0;
        for (u32 i = 0; i < cnt; i++)
            M->vram[(dst + i) & 0x3FFFu] = mem_rd8((u16)(src + i));
        S.vdp_addr = (u16)((dst + cnt) & 0x3FFFu);
        c->hl.w = (u16)(src + cnt);
        c->bc.b.h = 0;
        c->bc.b.l = 0xBEu;
        c->de.b.h = 0;
        c->cycles += (s32)(cnt * 24u);
        break;
    }
    case 0x1FE2: {                      /* READ_VRAM: HL = dst, DE = src, BC = OS-7 count */
        u32 cnt = os7_vram_count(c->bc.b.h, c->bc.b.l);
        u16 dst = c->hl.w, src = c->de.w;
        S.vdp_first = 0;
        for (u32 i = 0; i < cnt; i++)
            mem_wr8((u16)(dst + i), M->vram[(src + i) & 0x3FFFu]);
        S.vdp_addr = (u16)((src + cnt) & 0x3FFFu);
        S.vdp_buf = M->vram[S.vdp_addr];
        c->hl.w = (u16)(dst + cnt);
        c->bc.b.h = 0;
        c->bc.b.l = 0xBEu;
        c->de.b.h = 0;
        c->cycles += (s32)(cnt * 24u);
        break;
    }
    case 0x1FEE: {                      /* SOUND_INIT: B = slots, HL = sound_t table */
        S.snd_slots = c->bc.b.h > 6 ? 6 : c->bc.b.h;
        S.snd_tab = c->hl.w;
        mem_wr8(0x7020u, (u8)S.snd_tab);
        mem_wr8(0x7021u, (u8)(S.snd_tab >> 8));
        for (int s = 0; s < 6; s++) {
            S.hle_snd[s].active = 0;
            if (s < S.snd_slots) {
                u16 ent = (u16)(S.snd_tab + s * 4);
                u16 area = (u16)(mem_rd8((u16)(ent + 2)) | ((u16)mem_rd8((u16)(ent + 3)) << 8));
                S.hle_snd[s].area = area;
                if (area >= 0x6000u && area < 0x8000u)
                    mem_wr8(area, 0xFFu);
            }
        }
        hle_snd_silence();
        break;
    }
    case 0x1FF1: {                      /* PLAY_IT: B = sound# (1..N) */
        u8 num = c->bc.b.h;
        if (num >= 1 && S.snd_tab) {
            u16 ent = (u16)(S.snd_tab + (u16)(num - 1u) * 4u);
            u16 data = (u16)(mem_rd8(ent) | ((u16)mem_rd8((u16)(ent + 1u)) << 8));
            u16 area = (u16)(mem_rd8((u16)(ent + 2u)) | ((u16)mem_rd8((u16)(ent + 3u)) << 8));
            int slot = -1;
            for (int s = 0; s < 6; s++)
                if (S.hle_snd[s].area == area) { slot = s; break; }
            if (slot < 0) {
                for (int s = 0; s < 6; s++)
                    if (!S.hle_snd[s].active) { slot = s; break; }
            }
            if (slot < 0) slot = 0;
            S.hle_snd[slot].area = area;
            S.hle_snd[slot].ptr = data;
            S.hle_snd[slot].active = 1;
            if (area >= 0x6000u && area < 0x8000u)
                mem_wr8(area, num);
            hle_snd_load_note(slot);
        }
        break;
    }
    case 0x1FF4:                        /* SOUND_MAN */
        break;
    case 0x1FFD: {                      /* RAND_GEN -> HL & A, seed at $73C8..$73C9 */
        u16 r = (u16)(mem_rd8(0x73C8u) | ((u16)mem_rd8(0x73C9u) << 8));
        if (!r) r = 0x6A35u;
        u16 bit = (u16)(((r >> 0) ^ (r >> 2) ^ (r >> 3) ^ (r >> 5)) & 1u);
        r = (u16)((r >> 1) | (bit << 15));
        mem_wr8(0x73C8u, (u8)r);
        mem_wr8(0x73C9u, (u8)(r >> 8));
        c->hl.w = r;
        c->af.b.h = (u8)r;
        break;
    }
    default:
        break;
    }
}

static void build_builtin_bios(void)
{
    for (u32 i = 0; i < sizeof(M->bios); i++)
        M->bios[i] = 0xC9u;             /* RET on any unpopulated entry */

    /* Reset at $0000: DI; LD SP,$73B9; IM 1; CALL $1EFC (boot init); LD HL,($800A); JP (HL) */
    static const u8 boot_code[] = {
        0xF3,                           /* DI */
        0x31, 0xB9, 0x73,               /* LD SP, 0x73B9 */
        0xED, 0x56,                     /* IM 1 */
        0xCD, 0xFC, 0x1E,               /* CALL 0x1EFC (vec_idx 63) */
        0x2A, 0x0A, 0x80,               /* LD HL, (0x800A) */
        0xE9                            /* JP (HL) */
    };
    /* Wait: RST 08h is at $0008! Put the boot body at $0100 and jump there from $0000! */
    M->bios[0x0000] = 0xF3;             /* DI */
    M->bios[0x0001] = 0xC3;             /* JP 0x0100 */
    M->bios[0x0002] = 0x00;
    M->bios[0x0003] = 0x01;
    for (u32 i = 0; i < sizeof(boot_code); i++)
        M->bios[0x0100 + i] = boot_code[i];

    /* RST 08h..38h ($0008, $0010, ..., $0038) forward to cartridge $800C, $800F, ..., $801E */
    for (int r = 0; r < 7; r++) {
        u16 rst_addr = (u16)((r + 1) * 8);
        u16 cart_vec = (u16)(0x800Cu + r * 3);
        M->bios[rst_addr + 0] = 0xC3;   /* JP cart_vec */
        M->bios[rst_addr + 1] = (u8)cart_vec;
        M->bios[rst_addr + 2] = (u8)(cart_vec >> 8);
    }

    /* NMI vector at $0066 -> JP $8021; NTSC 60 Hz byte at $0069 = 60 (0x3C) */
    M->bios[0x0066] = 0xC3;
    M->bios[0x0067] = 0x21;
    M->bios[0x0068] = 0x80;
    M->bios[0x0069] = 60;

    /* Internal OS-7 CALC_OFFSET at $08C0 (called directly by Hi-Tech C / coleco.lib):
       DE = D (row) * 32 + E (col), preserving AF, BC, and HL */
    static const u8 calc_offset[] = {
        0xF5,                           /* PUSH AF */
        0xE5,                           /* PUSH HL */
        0x26, 0x00,                     /* LD H, 0 */
        0x6A,                           /* LD L, D */
        0x29, 0x29, 0x29, 0x29, 0x29,   /* ADD HL, HL x 5 (* 32) */
        0x16, 0x00,                     /* LD D, 0 */
        0x19,                           /* ADD HL, DE */
        0xEB,                           /* EX DE, HL */
        0xE1,                           /* POP HL */
        0xF1,                           /* POP AF */
        0xC9                            /* RET */
    };
    for (u32 i = 0; i < sizeof(calc_offset); i++)
        M->bios[0x08C0u + i] = calc_offset[i];

    /* 8x8 ASCII font at $15A3 (0x20..0x7F), plus (C) symbol at $158B (0x1D) */
    for (u32 i = 0; i < 8; i++)
        M->bios[0x158Bu + i] = bios_font96[95][i];
    for (u32 ch = 0; ch < 96; ch++)
        for (u32 r = 0; r < 8; r++)
            M->bios[0x15A3u + ch * 8u + r] = bios_font96[ch][r];

    /* OS-7 VDP port constants read directly by Hi-Tech C / libcv at $1D43 (ctrl) and $1D47 (data) */
    M->bios[0x1D43u] = 0xBFu;
    M->bios[0x1D47u] = 0xBEu;

    /* HLE stubs at $1E00 + idx*4 ("OUT (0x4F), A; RET") and OS-7 jump vectors at $1F61..$1FFD */
    for (int idx = 0; idx < 64; idx++) {
        u16 stub = (u16)(0x1E00u + idx * 4);
        M->bios[stub + 0] = 0xD3u;      /* OUT (0x4F), A */
        M->bios[stub + 1] = 0x4Fu;
        M->bios[stub + 2] = 0xC9u;      /* RET */
        M->bios[stub + 3] = 0x00u;
        if (idx < 53) {                 /* 0x1F61 + 52*3 = 0x1FFD */
            u16 jv = (u16)(0x1F61u + idx * 3);
            M->bios[jv + 0] = 0xC3u;    /* JP stub */
            M->bios[jv + 1] = (u8)stub;
            M->bios[jv + 2] = (u8)(stub >> 8);
        }
    }
}

/* ---- Z80 I/O ports ---- */
static u8 col_in(struct z80 *c, u16 port)
{
    (void)c;
    u8 p = (u8)port;
    if (p == 0x52u)
        return S.ay.reg_sel < 16 ? S.ay.reg[S.ay.reg_sel] : 0xFFu;
    if (p == 0x7Fu)
        return S.port_7f;

    switch (p & 0xE0u) {
    case 0xA0:
        return (p & 1u) ? vdp_status_read() : vdp_data_read();
    case 0xE0:
        return read_controller((p & 2u) != 0);
    }
    return 0xFFu;
}

static void col_out(struct z80 *c, u16 port, u8 v)
{
    u8 p = (u8)port;
    if (!S.ext_bios && !S.sgm_low_ram && p == 0x4Fu && c->pc.w >= 0x1E02u && c->pc.w <= 0x1EFEu) {
        hle_bios_dispatch((int)((c->pc.w - 0x1E02u) >> 2));
        return;
    }
    if (p == 0x50u) { S.ay.reg_sel = v & 0x0Fu; return; }
    if (p == 0x51u) { ay_write_reg(S.ay.reg_sel, v); return; }
    if (p == 0x53u) {
        u8 en = v & 1u;
        if (S.sgm_ram24 != en) { S.sgm_ram24 = en; rebuild_map(); }
        return;
    }
    if (p == 0x7Fu) {
        S.port_7f = v;
        u8 low_ram = (v & 2u) ? 0 : 1;
        if (S.sgm_low_ram != low_ram) { S.sgm_low_ram = low_ram; rebuild_map(); }
        return;
    }

    switch (p & 0xE0u) {
    case 0x80: S.joy_mode = 0; break;
    case 0xA0:
        if (p & 1u) vdp_ctrl_write(v);
        else        vdp_data_write(v);
        break;
    case 0xC0: S.joy_mode = 1; break;
    case 0xE0: sn_write(v); break;
    }
}

/* ---- TMS9928A scanline renderer ---- */
static void tms_init_palette(void)
{
    static const u8 rgb[16][3] = {
        {0x00, 0x00, 0x00}, {0x00, 0x00, 0x00}, {0x21, 0xC8, 0x42}, {0x5E, 0xDC, 0x78},
        {0x54, 0x55, 0xED}, {0x7D, 0x76, 0xFC}, {0xD4, 0x52, 0x4D}, {0x42, 0xEB, 0xF5},
        {0xFC, 0x55, 0x54}, {0xFF, 0x79, 0x78}, {0xD4, 0xC1, 0x54}, {0xE6, 0xCE, 0x80},
        {0x21, 0xB0, 0x3B}, {0xC9, 0x5B, 0xBA}, {0xCC, 0xCC, 0xCC}, {0xFF, 0xFF, 0xFF}
    };
    for (int i = 0; i < 16; i++)
        S.tms_pal[i] = (u16)((rgb[i][0] >> 3) | ((rgb[i][1] >> 3) << 5) | ((rgb[i][2] >> 3) << 10));
}

static void render_tms_sprites(int y, u8 *row)
{
    int size = (S.vdp_reg[1] & 2u) ? 16 : 8;
    int mag = S.vdp_reg[1] & 1u;
    int h = size << mag;
    const u8 *sat = M->vram + ((S.vdp_reg[5] & 0x7Fu) << 7);
    u32 patterns = (u32)(S.vdp_reg[6] & 7u) << 11;
    u8 taken[256];
    int n = 0, i;
    for (i = 0; i < 32; i++, sat += 4) {
        if (sat[0] == 0xD0u)
            break;
        int r = (u8)(y - sat[0] - 1);
        if (r >= h)
            continue;
        if (n == 4) {
            if (!(S.vdp_status & 0x40u))
                S.vdp_status = (u8)((S.vdp_status & 0xA0u) | 0x40u | i);
            break;
        }
        if (!n++)
            for (int x = 0; x < 256; x++)
                taken[x] = 0;
        r >>= mag;
        u32 a = patterns | ((u32)(size == 16 ? (sat[2] & 0xFCu) : sat[2]) << 3) | (u32)r;
        u32 bits = ((u32)M->vram[a & 0x3FFFu] << 8) | (size == 16 ? M->vram[(a + 16u) & 0x3FFFu] : 0);
        int x0 = sat[1] - ((sat[3] & 0x80u) ? 32 : 0);
        u8 c = sat[3] & 15u;
        for (int k = 0; k < h; k++) {
            if (!(bits & (0x8000u >> (k >> mag))))
                continue;
            int x = x0 + k;
            if ((unsigned)x >= 256u)
                continue;
            if (taken[x] & 1u)
                S.vdp_status |= 0x20u;
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
    u16 back = S.tms_pal[S.vdp_reg[7] & 15u];
    if (!(S.vdp_reg[1] & 0x40u)) {
        if (out)
            for (int x = 0; x < COL_W; x++)
                out[x] = back;
        return;
    }
    const u8 *names = M->vram + ((S.vdp_reg[2] & 0x0Fu) << 10);
    if (S.vdp_reg[1] & 0x10u) {         /* Text mode (40x24) */
        const u8 *p = M->vram + ((S.vdp_reg[4] & 7u) << 11) + (y & 7);
        const u8 *n = names + (y >> 3) * 40;
        u8 fg = S.vdp_reg[7] >> 4, bg = S.vdp_reg[7] & 15u;
        for (int x = 0; x < 8; x++)
            row[x] = row[248 + x] = 0;
        for (int k = 0; k < 40; k++) {
            u8 bits = p[n[k] * 8];
            for (int i = 0; i < 6; i++)
                row[8 + k * 6 + i] = (bits & (0x80u >> i)) ? fg : bg;
        }
    } else if (S.vdp_reg[1] & 0x08u) {  /* Multicolor mode (64x48) */
        const u8 *p = M->vram + ((S.vdp_reg[4] & 7u) << 11) + ((y >> 3) & 3) * 2 + ((y >> 2) & 1);
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
                bits = M->vram[(((u32)(S.vdp_reg[4] & 4u) << 11) | (idx & (((u32)(S.vdp_reg[4] & 3u) << 11) | 0x7FFu))) & 0x3FFFu];
                c    = M->vram[(((u32)(S.vdp_reg[3] & 0x80u) << 6) | (idx & (((u32)(S.vdp_reg[3] & 0x7Fu) << 6) | 0x3Fu))) & 0x3FFFu];
            } else {
                bits = M->vram[(((S.vdp_reg[4] & 7u) << 11) + n[k] * 8 + (y & 7)) & 0x3FFFu];
                c    = M->vram[((S.vdp_reg[3] << 6) + (n[k] >> 3)) & 0x3FFFu];
            }
            u8 fg = c >> 4, bg = c & 15u;
            for (int i = 0; i < 8; i++)
                row[k * 8 + i] = (bits & (0x80u >> i)) ? fg : bg;
        }
    }
    if (!(S.vdp_reg[1] & 0x10u))
        render_tms_sprites(y, row);
    if (out)
        for (int x = 0; x < COL_W; x++)
            out[x] = row[x] ? S.tms_pal[row[x]] : back;
}

/* ---- Public API ---- */
static void fmt_info(void)
{
    char *p = info_buf;
    const char *tag = S.megacart ? "ColecoVision MegaCart" : "ColecoVision";
    while (*tag) *p++ = *tag++;
    if (!S.ext_bios) {
        const char *hb = " (built-in BIOS)";
        while (*hb) *p++ = *hb++;
    }
    const char *sep = ", ROM ";
    while (*sep) *p++ = *sep++;
    u32 kb = (S.rom_size + 1023u) >> 10;
    char tmp[16];
    int n = 0;
    do { tmp[n++] = (char)('0' + kb % 10); kb /= 10; } while (kb);
    while (n--) *p++ = tmp[n];
    const char *suf = " KB";
    while (*suf) *p++ = *suf++;
    *p = 0;
}

void col_set_key(u8 key)
{
    S.key_override = key;
}

const char *col_load(const u8 *bios8k, u8 *cart, u32 cart_size)
{
    if (!cart || cart_size < 0x1000u)
        return "too small for a ColecoVision cartridge (at least 4 KB)";
    if (cart_size > 0x100000u)
        return "too large for a ColecoVision cartridge (over 1 MB)";

    int hdr_start = (cart[0] == 0x55u && cart[1] == 0xAAu) || (cart[0] == 0xAAu && cart[1] == 0x55u);
    int hdr_end = 0;
    if (cart_size >= 0x8000u && (cart_size & 0x3FFFu) == 0) {
        u32 last = cart_size - 0x4000u;
        hdr_end = (cart[last] == 0x55u && cart[last + 1] == 0xAAu) ||
                  (cart[last] == 0xAAu && cart[last + 1] == 0x55u);
    }
    if (!hdr_start && !hdr_end)
        return "not a ColecoVision cartridge (missing 55 AA / AA 55 header)";

    for (u32 i = 0; i < sizeof(*M); i++)
        ((u8 *)M)[i] = 0;
    for (u32 i = 0; i < sizeof(M->open_bus); i++)
        M->open_bus[i] = 0xFFu;
    for (u32 i = 0; i < sizeof(S); i++)
        ((u8 *)&S)[i] = 0;

    S.rom = cart;
    S.rom_size = cart_size;
    S.key_override = 0xFFu;

    if (cart_size > 0x8000u) {
        S.megacart = 1;
        S.num_banks = (cart_size + 0x3FFFu) >> 14;
        for (u32 i = 0; i + 2 < cart_size; i++) {
            if ((cart[i] == 0x32u || cart[i] == 0x3Au) && cart[i + 2] == 0xFFu &&
                cart[i + 1] >= 0x80u && cart[i + 1] < 0xC0u) {
                S.pcb_mapper = 1;
                break;
            }
        }
        if (hdr_end && !hdr_start) {
            S.fixed_bank = (u8)(S.num_banks - 1u);
            S.cur_bank = 0;
        } else {
            S.fixed_bank = 0;
            S.cur_bank = S.num_banks > 1 ? 1 : 0;
        }
    }

    if (bios8k) {
        for (u32 i = 0; i < 0x2000u; i++)
            M->bios[i] = bios8k[i];
        S.ext_bios = 1;
    } else {
        build_builtin_bios();
        S.ext_bios = 0;
    }

    col_reset();
    fmt_info();
    return 0;
}

void col_reset(void)
{
    z80_init(&S.cpu);
    S.cpu.read = cpu_read;
    S.cpu.write = cpu_write;
    S.cpu.in = col_in;
    S.cpu.out = col_out;
    S.cpu.trap = -1;

    for (u32 i = 0; i < sizeof(M->ram); i++)
        M->ram[i] = 0;
    for (u32 i = 0; i < sizeof(M->vram); i++)
        M->vram[i] = 0;

    S.sgm_ram24 = 0;
    S.sgm_low_ram = 0;
    S.port_7f = 0x0Fu;
    S.joy_mode = 0;
    S.vdp_addr = 0;
    S.vdp_first = S.vdp_latch = S.vdp_buf = S.vdp_status = S.vdp_int_prev = 0;
    for (int i = 0; i < 8; i++)
        S.vdp_reg[i] = 0;

    for (int i = 0; i < 4; i++) {
        S.sn.period[i] = 0;
        S.sn.atten[i] = 15;
        S.sn.phase[i] = 0;
    }
    S.sn.lfsr = 0x4000u;
    for (int i = 0; i < 16; i++)
        S.ay.reg[i] = 0;
    S.ay.reg[7] = 0x3Fu;
    S.ay.lfsr = 1u;

    if (S.megacart)
        S.cur_bank = (S.fixed_bank == 0 && S.num_banks > 1) ? 1 : 0;

    tms_init_palette();
    rebuild_map();
    z80_reset(&S.cpu);
}

void col_frame(u16 pad, u16 *picture)
{
    S.pad_state = pad;
    S.audio_count = 0;
    S.audio_last_cyc = S.cpu.cycles;

    for (int line = 0; line < LINES; line++) {
        if (line < COL_H)
            render_tms_line(line, picture ? picture + line * COL_W : 0);
        z80_run(&S.cpu, line * LINE_T + 2);
        if (line == COL_H) {
            S.vdp_status |= 0x80u;
            vdp_check_nmi();
        }
        z80_run(&S.cpu, (line + 1) * LINE_T);
    }
    audio_catch_up();
    S.cpu.cycles -= FRAME_T;
}

const char *col_info(void) { return info_buf; }

u8 *col_save_ram(u32 *size, int *battery)
{
    *size = sizeof(M->sav_dummy);
    *battery = 0;
    return M->sav_dummy;
}

int col_save_changed(void) { return 0; }

int col_jammed(void)
{
    return S.cpu.halted && !S.cpu.iff1 && !(S.vdp_reg[1] & 0x20u);
}

void col_audio_rate(u32 hz)
{
    S.sample_rate = hz;
    S.audio_frac = 0;
    S.audio_count = 0;
    S.audio_last_cyc = S.cpu.cycles;
}

int col_audio(s16 *out, int max)
{
    int n = S.audio_count < max ? S.audio_count : max;
    for (int i = 0; i < n; i++)
        out[i] = M->audio_ring[i];
    S.audio_count = 0;
    return n;
}
