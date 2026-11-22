/* A GCE / Milton Bradley Vectrex (.vec): see vec.h. */
#pragma GCC optimize("O2")
#include "vec.h"

#ifdef VEC_HOST
typedef unsigned long long u64;
#else
#include "hw.h"
#endif

#define INLINE static inline __attribute__((always_inline))

/* Clock & analog CRT coordinate range (matches GCE Vectrex integrator span):
   CPU = 1.5 MHz, nominal 50 Hz Wait_Recal frame = 30,000 cycles. */
#define VEC_CPU_HZ       1500000u
#define FRAME_CYC        30000
#define ALG_MAX_X        33000
#define ALG_MAX_Y        41000
#define ALG_CENTER_X     16500
#define ALG_CENTER_Y     20500

#define MAX_VECS         8192
#define SND_RING         8192

/* 6809 CC flags */
#define CC_C 0x01u
#define CC_V 0x02u
#define CC_Z 0x04u
#define CC_N 0x08u
#define CC_I 0x10u
#define CC_H 0x20u
#define CC_F 0x40u
#define CC_E 0x80u

struct vec_seg {
    s32 x0, y0, x1, y1;
    u8  z;
    u8  pad[3];
};

struct vec_mem {
    u8 ram[0x0400];                      /* 1 KB system RAM ($C800..$CBFF, mirrored $C000..$CFFF) */
    u8 sysrom[0x2000];                   /* 8 KB Executive + built-in game ($E000..$FFFF) */
    u8 cart_ram[0x2000];                 /* Optional VecRAM ($8000..$9FFF) */
    struct vec_seg vecs[MAX_VECS];       /* Current frame's captured analog vector segments */
    u16 fb[VEC_W * VEC_H];               /* Persistent phosphor accumulation buffer (BGR555) */
    s16 snd_ring[SND_RING];              /* 48 kHz mono output ring */
};

#ifdef VEC_HOST
static struct vec_mem vec_host_mem;
#define M (&vec_host_mem)
#else
#define M ((struct vec_mem *)KSEG0(EMU_RAM_PHYS))
#endif

static struct {
    const u8 *cart;
    u32 cart_size;
    int has_cart;
    u8  cart_bank;                       /* PB6 bank select for 64 KB 2-bank carts */

    const u8 *ext_bios;
    u32 ext_bios_size;
    int using_hle_bios;

    /* Motorola MC6809 CPU */
    u16 pc, x, y, u, s;
    u8  a, b, dp, cc;
    u8  halted_sync, halted_cwai, jammed;
    u8  nmi_armed, nmi_pend, firq_pend;
    u8  hle_in_frame, hle_end_frame;
    s32 step_cyc;
    s32 cyc_carry;

    /* MOS 6522 VIA ($D000..$D00F) */
    u8  ora, orb, ddra, ddrb;
    u16 t1c, t2c;
    u8  t1l_l, t1l_h, t2l_l;
    u8  t1_running, t2_running, t1pb7;
    u8  sr, srb, sr_clk;
    u8  acr, pcr, ifr, ier;
    u8  ca2, cb2;

    /* Analog S/H MUX & X/Y/Z beam integrators */
    s8  dac_x;
    s8  alg_ysh, alg_xsh, alg_ash;
    u8  alg_zsh;
    s32 alg_x, alg_y;
    u8  alg_vectoring;
    s32 vec_x0, vec_y0, vec_x1, vec_y1;
    s32 vec_dx, vec_dy;
    u8  vec_z;
    u32 n_vecs;

    /* AY-3-8912 PSG + 4-button / analog stick inputs */
    u8  psg_latch;
    u8  psg_reg[16];
    u32 psg_cnt[3], psg_out[3];
    u32 psg_ncnt, psg_lfsr;
    u32 psg_ecnt;
    u8  psg_epos, psg_ehold, psg_ealt, psg_eatt, psg_evol;
    s8  joy_pot[4];                      /* 0=J1X, 1=J1Y, 2=J2X, 3=J2Y (-127..+127) */
    u8  btn_mask;                        /* Active-low buttons in PSG Reg 14 (b0..b3 = Btn 1..4) */

    /* Built-in Vector Storm state (used when size==0 and no external vectrex.rom) */
    int builtin_game;
    s16 vs_angle;
    s32 vs_px, vs_py, vs_vx, vs_vy;
    struct { s32 x, y, vx, vy; u8 active, life; } vs_shot[4];
    struct { s32 x, y, vx, vy; u8 size, active; } vs_mine[12];
    u32 vs_score;
    u8  vs_cooldown, vs_boom_tmr, vs_pew_tmr;
    u32 vs_rng;

    /* Audio resampler */
    u32 snd_rate;
    u32 snd_phase, psg_sub;
    u32 snd_rd, snd_wr;
    s32 dc_est;

    u16 pad;
    char title[40];
    char info[128];
} S;

static void mem_zero(void *dst, u32 n)
{
    u8 *p = (u8 *)dst;
    for (u32 i = 0; i < n; i++)
        p[i] = 0;
}

static void mem_copy(void *dst, const void *src, u32 n)
{
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    for (u32 i = 0; i < n; i++)
        d[i] = s[i];
}

/* ---- Clean-room 5x7 Raster / Vector ASCII Font (0x20..0x5F) ----
   7 rows x 5 bits placed in bits 6..2 (bit 7 = 0, bits 1..0 = 0), matching GCE $F9D4 layout! */
static const u8 clean_font5x7[64][7] = {
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00}, /* ' ' */
    {0x10,0x10,0x10,0x10,0x10,0x00,0x10}, /* '!' */
    {0x28,0x28,0x28,0x00,0x00,0x00,0x00}, /* '"' */
    {0x28,0x28,0x7C,0x28,0x7C,0x28,0x28}, /* '#' */
    {0x10,0x3C,0x50,0x38,0x14,0x78,0x10}, /* '$' */
    {0x60,0x64,0x08,0x10,0x20,0x4C,0x0C}, /* '%' */
    {0x30,0x48,0x50,0x20,0x54,0x48,0x34}, /* '&' */
    {0x10,0x10,0x20,0x00,0x00,0x00,0x00}, /* '\'' */
    {0x08,0x10,0x20,0x20,0x20,0x10,0x08}, /* '(' */
    {0x20,0x10,0x08,0x08,0x08,0x10,0x20}, /* ')' */
    {0x00,0x10,0x54,0x38,0x54,0x10,0x00}, /* '*' */
    {0x00,0x10,0x10,0x7C,0x10,0x10,0x00}, /* '+' */
    {0x00,0x00,0x00,0x00,0x10,0x10,0x20}, /* ',' */
    {0x00,0x00,0x00,0x7C,0x00,0x00,0x00}, /* '-' */
    {0x00,0x00,0x00,0x00,0x00,0x10,0x10}, /* '.' */
    {0x00,0x04,0x08,0x10,0x20,0x40,0x00}, /* '/' */
    {0x38,0x44,0x4C,0x54,0x64,0x44,0x38}, /* '0' */
    {0x10,0x30,0x10,0x10,0x10,0x10,0x38}, /* '1' */
    {0x38,0x44,0x04,0x18,0x20,0x40,0x7C}, /* '2' */
    {0x7C,0x08,0x10,0x18,0x04,0x44,0x38}, /* '3' */
    {0x08,0x18,0x28,0x48,0x7C,0x08,0x08}, /* '4' */
    {0x7C,0x40,0x78,0x04,0x04,0x44,0x38}, /* '5' */
    {0x18,0x20,0x40,0x78,0x44,0x44,0x38}, /* '6' */
    {0x7C,0x04,0x08,0x10,0x20,0x20,0x20}, /* '7' */
    {0x38,0x44,0x44,0x38,0x44,0x44,0x38}, /* '8' */
    {0x38,0x44,0x44,0x3C,0x04,0x08,0x30}, /* '9' */
    {0x00,0x10,0x10,0x00,0x10,0x10,0x00}, /* ':' */
    {0x00,0x10,0x10,0x00,0x10,0x10,0x20}, /* ';' */
    {0x08,0x10,0x20,0x40,0x20,0x10,0x08}, /* '<' */
    {0x00,0x00,0x7C,0x00,0x7C,0x00,0x00}, /* '=' */
    {0x20,0x10,0x08,0x04,0x08,0x10,0x20}, /* '>' */
    {0x38,0x44,0x04,0x18,0x10,0x00,0x10}, /* '?' */
    {0x38,0x44,0x5C,0x54,0x5C,0x40,0x38}, /* '@' */
    {0x38,0x44,0x44,0x7C,0x44,0x44,0x44}, /* 'A' */
    {0x78,0x44,0x44,0x78,0x44,0x44,0x78}, /* 'B' */
    {0x38,0x44,0x40,0x40,0x40,0x44,0x38}, /* 'C' */
    {0x70,0x48,0x44,0x44,0x44,0x48,0x70}, /* 'D' */
    {0x7C,0x40,0x40,0x78,0x40,0x40,0x7C}, /* 'E' */
    {0x7C,0x40,0x40,0x78,0x40,0x40,0x40}, /* 'F' */
    {0x38,0x44,0x40,0x5C,0x44,0x44,0x38}, /* 'G' */
    {0x44,0x44,0x44,0x7C,0x44,0x44,0x44}, /* 'H' */
    {0x38,0x10,0x10,0x10,0x10,0x10,0x38}, /* 'I' */
    {0x1C,0x08,0x08,0x08,0x08,0x48,0x30}, /* 'J' */
    {0x44,0x48,0x50,0x60,0x50,0x48,0x44}, /* 'K' */
    {0x40,0x40,0x40,0x40,0x40,0x40,0x7C}, /* 'L' */
    {0x44,0x6C,0x54,0x54,0x44,0x44,0x44}, /* 'M' */
    {0x44,0x64,0x54,0x4C,0x44,0x44,0x44}, /* 'N' */
    {0x38,0x44,0x44,0x44,0x44,0x44,0x38}, /* 'O' */
    {0x78,0x44,0x44,0x78,0x40,0x40,0x40}, /* 'P' */
    {0x38,0x44,0x44,0x44,0x54,0x48,0x34}, /* 'Q' */
    {0x78,0x44,0x44,0x78,0x50,0x48,0x44}, /* 'R' */
    {0x3C,0x40,0x40,0x38,0x04,0x04,0x78}, /* 'S' */
    {0x7C,0x10,0x10,0x10,0x10,0x10,0x10}, /* 'T' */
    {0x44,0x44,0x44,0x44,0x44,0x44,0x38}, /* 'U' */
    {0x44,0x44,0x44,0x44,0x44,0x28,0x10}, /* 'V' */
    {0x44,0x44,0x44,0x54,0x54,0x6C,0x44}, /* 'W' */
    {0x44,0x44,0x28,0x10,0x28,0x44,0x44}, /* 'X' */
    {0x44,0x44,0x28,0x10,0x10,0x10,0x10}, /* 'Y' */
    {0x7C,0x04,0x08,0x10,0x20,0x40,0x7C}, /* 'Z' */
    {0x38,0x20,0x20,0x20,0x20,0x20,0x38}, /* '[' */
    {0x00,0x40,0x20,0x10,0x08,0x04,0x00}, /* '\\' */
    {0x38,0x08,0x08,0x08,0x08,0x08,0x38}, /* ']' */
    {0x10,0x28,0x44,0x00,0x00,0x00,0x00}, /* '^' */
    {0x00,0x00,0x00,0x00,0x00,0x00,0x7C}, /* '_' */
};

/* 64-step quarter-turn / full-circle sine table (-127..+127) for Rise_Run / Rot_VL */
static const s8 vec_sin64[64] = {
       0,   12,   25,   37,   49,   60,   71,   81,
      90,   98,  106,  112,  117,  122,  125,  126,
     127,  126,  125,  122,  117,  112,  106,   98,
      90,   81,   71,   60,   49,   37,   25,   12,
       0,  -12,  -25,  -37,  -49,  -60,  -71,  -81,
     -90,  -98, -106, -112, -117, -122, -125, -126,
    -127, -126, -125, -122, -117, -112, -106,  -98,
     -90,  -81,  -71,  -60,  -49,  -37,  -25,  -12
};

/* ---- AY-3-8912 PSG ---- */
static const s16 psg_vol_lut[16] = {
    0, 64, 96, 136, 192, 272, 384, 544,
    768, 1088, 1536, 2176, 3072, 4352, 6144, 8192
};

static void psg_write_reg(u8 r, u8 v)
{
    r &= 0x0Fu;
    S.psg_reg[r] = v;
    if (r == 13u) {
        S.psg_ecnt  = 0;
        S.psg_epos  = 0;
        S.psg_ehold = (v & 0x01u) ? 1u : 0u;
        S.psg_ealt  = (v & 0x02u) ? 1u : 0u;
        S.psg_eatt  = (v & 0x04u) ? 1u : 0u;
        if (!(v & 0x08u)) {
            S.psg_ehold = 1u;
            S.psg_ealt  = S.psg_eatt;
        }
        S.psg_evol = S.psg_eatt ? 0u : 15u;
    }
}

static u8 psg_read_reg(u8 r)
{
    r &= 0x0Fu;
    if (r == 14u)
        return S.btn_mask;               /* IOA = active-low controller buttons */
    return S.psg_reg[r];
}

/* Advance AY-3-8912 at 1.5 MHz / 16 = 93.75 kHz (called every 16 CPU cycles) */
static void psg_tick_16cyc(void)
{
    for (int c = 0; c < 3; c++) {
        u32 per = ((u32)(S.psg_reg[c * 2 + 1] & 0x0Fu) << 8) | S.psg_reg[c * 2];
        if (per == 0u) per = 1u;
        if (++S.psg_cnt[c] >= per) {
            S.psg_cnt[c] = 0;
            S.psg_out[c] ^= 1u;
        }
    }

    u32 nper = (u32)(S.psg_reg[6] & 0x1Fu) * 2u;
    if (nper == 0u) nper = 2u;
    if (++S.psg_ncnt >= nper) {
        S.psg_ncnt = 0;
        u32 bit = (S.psg_lfsr ^ (S.psg_lfsr >> 3)) & 1u;
        S.psg_lfsr = (S.psg_lfsr >> 1) | (bit << 16);
    }

    u32 eper = ((u32)S.psg_reg[12] << 8) | S.psg_reg[11];
    if (eper == 0u) eper = 1u;
    if (++S.psg_ecnt >= eper) {
        S.psg_ecnt = 0;
        if (S.psg_epos < 16u) {
            S.psg_evol = S.psg_eatt ? S.psg_epos : (u8)(15u - S.psg_epos);
            S.psg_epos++;
            if (S.psg_epos >= 16u) {
                if (S.psg_ehold) {
                    if (S.psg_ealt)
                        S.psg_evol = S.psg_eatt ? 0u : 15u;
                } else {
                    if (S.psg_ealt)
                        S.psg_eatt ^= 1u;
                    S.psg_epos = 0;
                }
            }
        }
    }
}

static void audio_step(int cyc)
{
    S.psg_sub += (u32)cyc;
    while (S.psg_sub >= 16u) {
        S.psg_sub -= 16u;
        psg_tick_16cyc();
    }

    if (!S.snd_rate)
        return;

    S.snd_phase += S.snd_rate * (u32)cyc;
    if (S.snd_phase < VEC_CPU_HZ)
        return;

    u8 mix_en = S.psg_reg[7];
    u32 nbit = S.psg_lfsr & 1u;
    s32 sum = 0;
    for (int c = 0; c < 3; c++) {
        u32 t_ok = ((mix_en >> c) & 1u) | S.psg_out[c];
        u32 n_ok = ((mix_en >> (c + 3)) & 1u) | nbit;
        u8 vr = S.psg_reg[8 + c];
        u8 vol = (vr & 0x10u) ? S.psg_evol : (vr & 0x0Fu);
        if (t_ok & n_ok)
            sum += psg_vol_lut[vol];
    }
    /* Add direct MUX DAC voice channel (Spike / digitized speech) */
    sum += (s32)S.alg_ash * 96;

    S.dc_est += ((sum << 8) - S.dc_est) >> 8;
    s32 out = sum - (S.dc_est >> 8);
    if (out >  32767) out =  32767;
    if (out < -32768) out = -32768;

    while (S.snd_phase >= VEC_CPU_HZ) {
        S.snd_phase -= VEC_CPU_HZ;
        if (S.snd_wr - S.snd_rd < SND_RING) {
            M->snd_ring[S.snd_wr & (SND_RING - 1u)] = (s16)out;
            S.snd_wr++;
        }
    }
}

/* ---- Analog Vector Capture & VIA 6522 ---- */
INLINE void emit_seg(s32 x0, s32 y0, s32 x1, s32 y1, u8 z)
{
    if (S.n_vecs >= MAX_VECS || z == 0u || (z & 0x80u))
        return;
    if (x0 < -4096 && x1 < -4096) return;
    if (y0 < -4096 && y1 < -4096) return;
    if (x0 > ALG_MAX_X + 4096 && x1 > ALG_MAX_X + 4096) return;
    if (y0 > ALG_MAX_Y + 4096 && y1 > ALG_MAX_Y + 4096) return;

    struct vec_seg *v = &M->vecs[S.n_vecs++];
    v->x0 = x0 < -16000 ? -16000 : x0 > 48000 ? 48000 : x0;
    v->y0 = y0 < -16000 ? -16000 : y0 > 56000 ? 56000 : y0;
    v->x1 = x1 < -16000 ? -16000 : x1 > 48000 ? 48000 : x1;
    v->y1 = y1 < -16000 ? -16000 : y1 > 56000 ? 56000 : y1;
    v->z  = z;
}

INLINE void flush_active_vec(void)
{
    if (S.alg_vectoring) {
        emit_seg(S.vec_x0, S.vec_y0, S.vec_x1, S.vec_y1, S.vec_z);
        S.alg_vectoring = 0;
    }
}

static void update_mux_snh(void)
{
    S.dac_x = (s8)S.ora;
    if ((S.orb & 0x01u) == 0u) {
        switch ((S.orb >> 1) & 3u) {
        case 0: S.alg_ysh = S.dac_x; break;
        case 1: S.alg_xsh = S.dac_x; break;
        case 2: S.alg_zsh = S.ora;   break;
        case 3: S.alg_ash = S.dac_x; break;
        }
    }
}

static void update_psg_bus(void)
{
    u8 bus = (S.orb >> 3) & 3u;          /* b0 = BC1, b1 = BDIR */
    if (bus == 3u)                       /* BDIR=1, BC1=1: Latch register */
        S.psg_latch = S.ora & 0x0Fu;
    else if (bus == 2u)                  /* BDIR=1, BC1=0: Write register */
        psg_write_reg(S.psg_latch, S.ora);
}

static void update_pcr_lines(void)
{
    u8 ca2_m = (S.pcr >> 1) & 7u;
    if (ca2_m == 6u)      S.ca2 = 0u;
    else if (ca2_m == 7u) S.ca2 = 1u;

    if ((S.acr & 0x1Cu) == 0u) {
        u8 cb2_m = (S.pcr >> 5) & 7u;
        if (cb2_m == 6u)      S.cb2 = 0u;
        else if (cb2_m == 7u) S.cb2 = 1u;
    }
}

static u8 via_read(u16 addr)
{
    switch (addr & 0x0Fu) {
    case 0x0: { /* IRB */
        u8 out_b = S.orb & S.ddrb;
        if (S.acr & 0x80u)
            out_b = (u8)((out_b & 0x7Fu) | (S.t1pb7 ? 0x80u : 0x00u));
        u8 in_b = 0xDFu;                 /* Default pulled high except comparator b5 */
        s8 pot = S.joy_pot[(S.orb >> 1) & 3u];
        if (pot > S.dac_x)
            in_b |= 0x20u;
        S.ifr &= (u8)~0x18u;             /* Clear CB1/CB2 flags */
        return (u8)(out_b | (in_b & ~S.ddrb));
    }
    case 0x1:   /* IRA (with CA handshake) */
        if (((S.pcr >> 1) & 5u) == 4u)
            S.ca2 = 0u;
        S.ifr &= (u8)~0x03u;
        /* fall through */
    case 0xF: { /* IRA_NH */
        u8 in_a = 0xFFu;
        if (((S.orb >> 3) & 3u) == 1u)   /* BDIR=0, BC1=1: PSG driving Port A */
            in_a = psg_read_reg(S.psg_latch);
        return (u8)((S.ora & S.ddra) | (in_a & ~S.ddra));
    }
    case 0x2: return S.ddrb;
    case 0x3: return S.ddra;
    case 0x4:
        S.ifr &= (u8)~0x40u;
        return (u8)S.t1c;
    case 0x5:
        return (u8)(S.t1c >> 8);
    case 0x6: return S.t1l_l;
    case 0x7: return S.t1l_h;
    case 0x8:
        S.ifr &= (u8)~0x20u;
        return (u8)S.t2c;
    case 0x9:
        return (u8)(S.t2c >> 8);
    case 0xA:
        S.ifr &= (u8)~0x04u;
        S.srb = 0;
        S.sr_clk = 1;
        return S.sr;
    case 0xB: return S.acr;
    case 0xC: return S.pcr;
    case 0xD: {
        u8 top = (S.ifr & S.ier & 0x7Fu) ? 0x80u : 0x00u;
        return (u8)((S.ifr & 0x7Fu) | top);
    }
    case 0xE:
        return (u8)(S.ier | 0x80u);
    }
    return 0xFFu;
}

static void via_write(u16 addr, u8 val)
{
    switch (addr & 0x0Fu) {
    case 0x0: /* ORB */
        S.orb = val;
        S.ifr &= (u8)~0x18u;
        if (S.ddrb & 0x40u)
            S.cart_bank = (val >> 6) & 1u;
        update_mux_snh();
        update_psg_bus();
        break;
    case 0x1: /* ORA */
        if (((S.pcr >> 1) & 5u) == 4u)
            S.ca2 = 0u;
        S.ifr &= (u8)~0x03u;
        /* fall through */
    case 0xF: /* ORA_NH */
        S.ora = val;
        update_mux_snh();
        update_psg_bus();
        break;
    case 0x2:
        S.ddrb = val;
        if (S.ddrb & 0x40u)
            S.cart_bank = (S.orb >> 6) & 1u;
        else
            S.cart_bank = 1u;            /* Pulled high on 64K PB6 carts at boot */
        break;
    case 0x3:
        S.ddra = val;
        break;
    case 0x4:
    case 0x6:
        S.t1l_l = val;
        break;
    case 0x5:
        S.t1l_h = val;
        S.t1c = (u16)(((u16)val << 8) | S.t1l_l);
        S.ifr &= (u8)~0x40u;
        S.t1_running = 1u;
        S.t1pb7 = 0u;                    /* ~RAMP asserted low -> start integrating! */
        break;
    case 0x7:
        S.t1l_h = val;
        S.ifr &= (u8)~0x40u;
        break;
    case 0x8:
        S.t2l_l = val;
        break;
    case 0x9:
        S.t2c = (u16)(((u16)val << 8) | S.t2l_l);
        S.ifr &= (u8)~0x20u;
        S.t2_running = 1u;
        break;
    case 0xA:
        S.sr = val;
        S.ifr &= (u8)~0x04u;
        S.srb = 0;
        S.sr_clk = 1;
        break;
    case 0xB:
        S.acr = val;
        update_pcr_lines();
        break;
    case 0xC:
        S.pcr = val;
        update_pcr_lines();
        break;
    case 0xD:
        S.ifr &= (u8)~(val & 0x7Fu);
        break;
    case 0xE:
        if (val & 0x80u) S.ier |= (u8)(val & 0x7Fu);
        else             S.ier &= (u8)~(val & 0x7Fu);
        break;
    }
}

/* Cycle-exact VIA timers + shift-register + analog beam integrator */
static void via_step(int cyc)
{
    if (cyc > 1 &&
        ((S.acr & 0x1Cu) == 0u || S.srb >= 8u) &&
        (((S.pcr >> 1) & 7u) != 5u) &&
        (u32)cyc <= (u32)S.t1c &&
        ((S.acr & 0x20u) != 0u || (u32)cyc <= (u32)S.t2c)) {
        s32 dx = 0, dy = 0;
        if (S.ca2 != 0u) {
            int ramp_n = (S.acr & 0x80u) ? S.t1pb7 : ((S.orb >> 7) & 1u);
            if (!ramp_n) {
                dx = (s32)S.dac_x - (s32)S.alg_xsh;
                dy = (s32)S.alg_ysh - (s32)S.alg_xsh;
            }
        }
        s32 nx = (S.ca2 == 0u) ? ALG_CENTER_X : (S.alg_x + dx * cyc);
        s32 ny = (S.ca2 == 0u) ? ALG_CENTER_Y : (S.alg_y + dy * cyc);
        if (nx >= -16000 && nx <= 49000 && ny >= -16000 && ny <= 57000) {
            if (S.ca2 == 0u) {
                flush_active_vec();
            } else {
                int beam_on = (S.cb2 != 0u) && (S.alg_zsh > 0u) && !(S.alg_zsh & 0x80u);
                if (beam_on) {
                    if (!S.alg_vectoring) {
                        S.alg_vectoring = 1u;
                        S.vec_x0 = S.alg_x;
                        S.vec_y0 = S.alg_y;
                        S.vec_x1 = nx;
                        S.vec_y1 = ny;
                        S.vec_dx = dx;
                        S.vec_dy = dy;
                        S.vec_z  = S.alg_zsh;
                    } else if (dx == S.vec_dx && dy == S.vec_dy && S.alg_zsh == S.vec_z) {
                        S.vec_x1 = nx;
                        S.vec_y1 = ny;
                    } else {
                        flush_active_vec();
                        S.alg_vectoring = 1u;
                        S.vec_x0 = S.alg_x;
                        S.vec_y0 = S.alg_y;
                        S.vec_x1 = nx;
                        S.vec_y1 = ny;
                        S.vec_dx = dx;
                        S.vec_dy = dy;
                        S.vec_z  = S.alg_zsh;
                    }
                } else if (S.alg_vectoring) {
                    flush_active_vec();
                }
            }
            S.alg_x = nx;
            S.alg_y = ny;
            S.t1c = (u16)(S.t1c - (u16)cyc);
            if ((S.acr & 0x20u) == 0u)
                S.t2c = (u16)(S.t2c - (u16)cyc);
            return;
        }
    }

    for (int i = 0; i < cyc; i++) {
        /* 1. Integrate current beam velocity BEFORE updating next-cycle VIA latches */
        s32 dx = 0, dy = 0;
        if (S.ca2 == 0u) {
            /* ~ZERO active: pull beam back to CRT center */
            flush_active_vec();
            S.alg_x = ALG_CENTER_X;
            S.alg_y = ALG_CENTER_Y;
        } else {
            int ramp_n = (S.acr & 0x80u) ? S.t1pb7 : ((S.orb >> 7) & 1u);
            if (!ramp_n) {
                dx = (s32)S.dac_x - (s32)S.alg_xsh;
                dy = (s32)S.alg_ysh - (s32)S.alg_xsh;
            }
        }

        int beam_on = (S.ca2 != 0u) && (S.cb2 != 0u) && (S.alg_zsh > 0u) && !(S.alg_zsh & 0x80u);
        if (beam_on) {
            if (!S.alg_vectoring) {
                S.alg_vectoring = 1u;
                S.vec_x0 = S.alg_x;
                S.vec_y0 = S.alg_y;
                S.vec_x1 = S.alg_x + dx;
                S.vec_y1 = S.alg_y + dy;
                S.vec_dx = dx;
                S.vec_dy = dy;
                S.vec_z  = S.alg_zsh;
            } else if (dx == S.vec_dx && dy == S.vec_dy && S.alg_zsh == S.vec_z) {
                S.vec_x1 = S.alg_x + dx;
                S.vec_y1 = S.alg_y + dy;
            } else {
                flush_active_vec();
                S.alg_vectoring = 1u;
                S.vec_x0 = S.alg_x;
                S.vec_y0 = S.alg_y;
                S.vec_x1 = S.alg_x + dx;
                S.vec_y1 = S.alg_y + dy;
                S.vec_dx = dx;
                S.vec_dy = dy;
                S.vec_z  = S.alg_zsh;
            }
        } else if (S.alg_vectoring) {
            flush_active_vec();
        }

        S.alg_x += dx;
        S.alg_y += dy;
        if (S.alg_x < -16000) S.alg_x = -16000;
        else if (S.alg_x > 49000) S.alg_x = 49000;
        if (S.alg_y < -16000) S.alg_y = -16000;
        else if (S.alg_y > 57000) S.alg_y = 57000;

        /* 2. CA2 pulse auto-restore */
        if (((S.pcr >> 1) & 7u) == 5u)
            S.ca2 = 1u;

        /* 3. Timer 1 countdown */
        if (S.t1c == 0u) {
            S.t1c = 0xFFFFu;
            if (S.acr & 0x40u) {
                S.ifr |= 0x40u;
                S.t1c = (u16)(((u16)S.t1l_h << 8) | S.t1l_l);
                S.t1pb7 ^= 1u;
            } else if (S.t1_running) {
                S.ifr |= 0x40u;
                S.t1_running = 0u;
                S.t1pb7 = 1u;            /* ~RAMP deasserted high -> stop beam! */
            }
        } else {
            S.t1c--;
        }

        /* 4. Timer 2 countdown */
        if ((S.acr & 0x20u) == 0u) {
            if (S.t2c == 0u) {
                S.t2c = 0xFFFFu;
                if (S.t2_running) {
                    S.ifr |= 0x20u;
                    S.t2_running = 0u;
                }
            } else {
                S.t2c--;
            }
        }

        /* 5. Shift Register (~BLANK beam/raster modulator, shifts every 2 Phi2 cycles) */
        if ((S.acr & 0x1Cu) != 0u && S.srb < 8u) {
            S.sr_clk ^= 1u;
            if (S.sr_clk == 0u) {
                u8 b7 = (S.sr >> 7) & 1u;
                S.cb2 = b7;
                S.sr  = (u8)((S.sr << 1) | b7);
                S.srb++;
                if (S.srb == 8u)
                    S.ifr |= 0x04u;
            }
        }
    }
}

/* ---- 64 KB Vectrex Memory Bus ---- */
static u8 bus_read(u16 addr)
{
    if (addr < 0x8000u) {
        if (!S.has_cart || !S.cart || !S.cart_size)
            return 0xFFu;
        u32 off = addr;
        if (S.cart_size > 0x8000u && S.cart_bank)
            off += 0x8000u;
        return (off < S.cart_size) ? S.cart[off] : 0xFFu;
    }
    if (addr < 0xA000u)
        return M->cart_ram[addr - 0x8000u];
    if (addr >= 0xC000u && addr < 0xD000u)
        return M->ram[addr & 0x03FFu];
    if (addr >= 0xD000u && addr < 0xE000u)
        return via_read(addr);
    if (addr >= 0xE000u)
        return M->sysrom[addr - 0xE000u];
    return 0xFFu;
}

static void bus_write(u16 addr, u8 val)
{
    if (addr >= 0x8000u && addr < 0xA000u) {
        M->cart_ram[addr - 0x8000u] = val;
        return;
    }
    if (addr >= 0xC000u && addr < 0xD000u) {
        M->ram[addr & 0x03FFu] = val;
        return;
    }
    if (addr >= 0xD000u && addr < 0xE000u) {
        via_write(addr, val);
        return;
    }
}

INLINE u16 rd16(u16 a)
{
    return (u16)(((u16)bus_read(a) << 8) | bus_read((u16)(a + 1u)));
}

INLINE void wr16(u16 a, u16 v)
{
    bus_write(a, (u8)(v >> 8));
    bus_write((u16)(a + 1u), (u8)v);
}

INLINE u8 fetch8(void)
{
    return bus_read(S.pc++);
}

INLINE u16 fetch16(void)
{
    u16 hi = fetch8();
    return (u16)((hi << 8) | fetch8());
}

/* ---- Built-in Clean-Room Vectrex Executive BIOS ($F000..$FFFF) & Vector Storm ----
   Used ONLY when no external vectrex.rom is supplied! */
static void hle_draw_text(s32 x, s32 y, s8 h_scale, s8 w_scale, const char *str_mem, u16 str_addr, u8 z)
{
    /* Draw crisp clean-room 5x7 raster/dot-row characters using standard Vectrex height/width params:
       On Vectrex, height is negative (-8 typical), width is positive (+72 typical). */
    s32 ch_h = (h_scale < 0) ? -(s32)h_scale * 42 : (s32)h_scale * 42;
    if (ch_h < 180) ch_h = 340;
    s32 ch_w = (w_scale > 0) ? (s32)w_scale * 7 : (-(s32)w_scale * 7);
    if (ch_w < 160) ch_w = 480;

    s32 cur_x = x;
    for (int idx = 0; idx < 48; idx++) {
        u8 ch = str_mem ? (u8)str_mem[idx] : bus_read((u16)(str_addr + (u16)idx));
        if (ch == 0x80u || (str_mem && ch == 0u))
            break;
        u8 c = (ch >= 0x20u && ch < 0x60u) ? (u8)(ch - 0x20u)
             : (ch >= 0x60u && ch < 0x80u) ? (u8)(ch - 0x40u) : 0u;
        const u8 *glyph = clean_font5x7[c];
        for (int row = 0; row < 7; row++) {
            u8 bits = glyph[row];
            if (!bits) continue;
            s32 ry = y - (row * ch_h) / 6;
            int in_run = 0;
            s32 rx0 = 0;
            for (int col = 0; col < 6; col++) {
                int on = (col < 5) && ((bits >> (6 - col)) & 1u);
                s32 rx = cur_x + (col * ch_w) / 6;
                if (on && !in_run) {
                    in_run = 1;
                    rx0 = rx;
                } else if (!on && in_run) {
                    emit_seg(rx0, ry, rx - (ch_w / 12), ry, z);
                    in_run = 0;
                }
            }
        }
        cur_x += ch_w;
    }
}

static void hle_reset0ref(void)
{
    flush_active_vec();
    S.alg_x = ALG_CENTER_X;
    S.alg_y = ALG_CENTER_Y;
    S.ca2 = 1u;
    S.cb2 = 0u;
}

static void hle_moveto(s8 dy, s8 dx, u8 scale)
{
    flush_active_vec();
    S.alg_x += (s32)dx * ((s32)scale + 2);
    S.alg_y += (s32)dy * ((s32)scale + 2);
}

static void hle_draw_line(s8 dy, s8 dx, u8 scale, u8 pat)
{
    s32 steps = (s32)scale + 2;
    s32 nx = S.alg_x + (s32)dx * steps;
    s32 ny = S.alg_y + (s32)dy * steps;
    if (pat == 0xFFu) {
        emit_seg(S.alg_x, S.alg_y, nx, ny, S.alg_zsh);
    } else if (pat != 0u) {
        for (int s = 0; s < 8; s++) {
            if ((pat >> (7 - s)) & 1u) {
                s32 sx0 = S.alg_x + ((nx - S.alg_x) * s) / 8;
                s32 sy0 = S.alg_y + ((ny - S.alg_y) * s) / 8;
                s32 sx1 = S.alg_x + ((nx - S.alg_x) * (s + 1)) / 8;
                s32 sy1 = S.alg_y + ((ny - S.alg_y) * (s + 1)) / 8;
                emit_seg(sx0, sy0, sx1, sy1, S.alg_zsh);
            }
        }
    }
    S.alg_x = nx;
    S.alg_y = ny;
}

static void vs_spawn_mine(int idx, s32 x, s32 y, u8 size)
{
    S.vs_rng = S.vs_rng * 1664525u + 1013904223u;
    s32 vx = (s32)((S.vs_rng >> 16) & 0x7Fu) - 64;
    s32 vy = (s32)((S.vs_rng >> 23) & 0x7Fu) - 64;
    if (vx > -18 && vx < 18) vx = (vx >= 0) ? 28 : -28;
    if (vy > -18 && vy < 18) vy = (vy >= 0) ? 28 : -28;
    S.vs_mine[idx].x = x;
    S.vs_mine[idx].y = y;
    S.vs_mine[idx].vx = vx * (4 - size);
    S.vs_mine[idx].vy = vy * (4 - size);
    S.vs_mine[idx].size = size;
    S.vs_mine[idx].active = 1u;
}

static void vs_init(void)
{
    S.vs_angle = 0;
    S.vs_px = ALG_CENTER_X;
    S.vs_py = ALG_CENTER_Y;
    S.vs_vx = S.vs_vy = 0;
    S.vs_score = 0;
    S.vs_cooldown = S.vs_boom_tmr = S.vs_pew_tmr = 0;
    S.vs_rng = 0x56454358u;
    mem_zero(S.vs_shot, sizeof(S.vs_shot));
    mem_zero(S.vs_mine, sizeof(S.vs_mine));
    vs_spawn_mine(0,  5500, 32000, 2);
    vs_spawn_mine(1, 27500, 31000, 2);
    vs_spawn_mine(2,  6000,  8500, 2);
    vs_spawn_mine(3, 27000,  9500, 2);
}

static void vs_step_frame(void)
{
    /* Controls: Left/Right rotate, Up or B/3 thrusts, A/4 fires! */
    if (S.pad & VEC_PAD_LEFT)  S.vs_angle = (S.vs_angle - 1) & 63;
    if (S.pad & VEC_PAD_RIGHT) S.vs_angle = (S.vs_angle + 1) & 63;

    s32 dir_x = vec_sin64[S.vs_angle & 63];
    s32 dir_y = vec_sin64[(S.vs_angle + 16) & 63];

    if (S.pad & (VEC_PAD_UP | VEC_PAD_B)) {
        S.vs_vx += (dir_x * 3) >> 4;
        S.vs_vy += (dir_y * 3) >> 4;
        if (S.vs_vx >  320) S.vs_vx =  320;
        if (S.vs_vx < -320) S.vs_vx = -320;
        if (S.vs_vy >  320) S.vs_vy =  320;
        if (S.vs_vy < -320) S.vs_vy = -320;
    } else {
        S.vs_vx = (S.vs_vx * 63) / 64;
        S.vs_vy = (S.vs_vy * 63) / 64;
    }

    S.vs_px += S.vs_vx;
    S.vs_py += S.vs_vy;
    if (S.vs_px < 1500)  S.vs_px += 30000;
    if (S.vs_px > 31500) S.vs_px -= 30000;
    if (S.vs_py < 1500)  S.vs_py += 36000;
    if (S.vs_py > 37500) S.vs_py -= 36000;

    if (S.vs_cooldown > 0) S.vs_cooldown--;
    if ((S.pad & (VEC_PAD_A | VEC_PAD_R | VEC_PAD_START)) && S.vs_cooldown == 0) {
        for (int i = 0; i < 4; i++) {
            if (!S.vs_shot[i].active) {
                S.vs_shot[i].active = 1u;
                S.vs_shot[i].life   = 36u;
                S.vs_shot[i].x  = S.vs_px + dir_x * 6;
                S.vs_shot[i].y  = S.vs_py + dir_y * 6;
                S.vs_shot[i].vx = S.vs_vx + dir_x * 4;
                S.vs_shot[i].vy = S.vs_vy + dir_y * 4;
                S.vs_cooldown = 8u;
                S.vs_pew_tmr  = 6u;
                break;
            }
        }
    }

    /* Update PSG sound effects */
    if (S.vs_pew_tmr > 0) {
        u16 per = (u16)(120u + (6u - S.vs_pew_tmr) * 45u);
        psg_write_reg(0, (u8)per);
        psg_write_reg(1, (u8)(per >> 8));
        psg_write_reg(7, 0x3Eu);
        psg_write_reg(8, 13u);
        S.vs_pew_tmr--;
    } else {
        psg_write_reg(8, 0u);
    }
    if (S.vs_boom_tmr > 0) {
        psg_write_reg(6, 0x16u);
        psg_write_reg(7, (S.vs_pew_tmr > 0) ? 0x2Eu : 0x2Fu);
        psg_write_reg(9, (u8)(S.vs_boom_tmr > 15 ? 15 : S.vs_boom_tmr));
        S.vs_boom_tmr--;
    } else {
        psg_write_reg(9, 0u);
    }

    /* Draw HUD border & score */
    char hud[24];
    hud[0] = 'V'; hud[1] = 'E'; hud[2] = 'C'; hud[3] = 'T'; hud[4] = 'O'; hud[5] = 'R';
    hud[6] = ' '; hud[7] = 'S'; hud[8] = 'T'; hud[9] = 'O'; hud[10]= 'R'; hud[11]= 'M';
    hud[12]= ' '; hud[13]= ' ';
    u32 sc = S.vs_score;
    for (int d = 5; d >= 0; d--) {
        hud[14 + d] = (char)('0' + (sc % 10u));
        sc /= 10u;
    }
    hud[20] = 0;
    hle_draw_text(2200, 39200, -7, 52, hud, 0, 0x5Fu);

    /* Draw player vector ship */
    s32 nx = S.vs_px + dir_x * 9;
    s32 ny = S.vs_py + dir_y * 9;
    s32 lwx = S.vs_px + vec_sin64[(S.vs_angle + 25) & 63] * 7;
    s32 lwy = S.vs_py + vec_sin64[(S.vs_angle + 41) & 63] * 7;
    s32 rwx = S.vs_px + vec_sin64[(S.vs_angle + 39) & 63] * 7;
    s32 rwy = S.vs_py + vec_sin64[(S.vs_angle + 55) & 63] * 7;
    s32 tx  = S.vs_px - dir_x * 4;
    s32 ty  = S.vs_py - dir_y * 4;
    emit_seg(nx, ny, lwx, lwy, 0x7Fu);
    emit_seg(lwx, lwy, tx, ty, 0x7Fu);
    emit_seg(tx, ty, rwx, rwy, 0x7Fu);
    emit_seg(rwx, rwy, nx, ny, 0x7Fu);
    if (S.pad & (VEC_PAD_UP | VEC_PAD_B)) {
        emit_seg(tx, ty, S.vs_px - dir_x * 10, S.vs_py - dir_y * 10, 0x5Fu);
    }

    /* Update & draw shots */
    for (int i = 0; i < 4; i++) {
        if (!S.vs_shot[i].active) continue;
        s32 ox = S.vs_shot[i].x, oy = S.vs_shot[i].y;
        S.vs_shot[i].x += S.vs_shot[i].vx;
        S.vs_shot[i].y += S.vs_shot[i].vy;
        if (S.vs_shot[i].x < 1500)  { S.vs_shot[i].x += 30000; ox = S.vs_shot[i].x; }
        if (S.vs_shot[i].x > 31500) { S.vs_shot[i].x -= 30000; ox = S.vs_shot[i].x; }
        if (S.vs_shot[i].y < 1500)  { S.vs_shot[i].y += 36000; oy = S.vs_shot[i].y; }
        if (S.vs_shot[i].y > 37500) { S.vs_shot[i].y -= 36000; oy = S.vs_shot[i].y; }
        emit_seg(ox, oy, S.vs_shot[i].x, S.vs_shot[i].y, 0x7Fu);
        if (--S.vs_shot[i].life == 0u)
            S.vs_shot[i].active = 0u;
    }

    /* Update & draw 4-point star mines + collision */
    int any_mine = 0;
    for (int m = 0; m < 12; m++) {
        if (!S.vs_mine[m].active) continue;
        any_mine = 1;
        S.vs_mine[m].x += S.vs_mine[m].vx;
        S.vs_mine[m].y += S.vs_mine[m].vy;
        if (S.vs_mine[m].x < 1500)  S.vs_mine[m].x += 30000;
        if (S.vs_mine[m].x > 31500) S.vs_mine[m].x -= 30000;
        if (S.vs_mine[m].y < 1500)  S.vs_mine[m].y += 36000;
        if (S.vs_mine[m].y > 37500) S.vs_mine[m].y -= 36000;

        s32 mx = S.vs_mine[m].x, my = S.vs_mine[m].y;
        s32 r_out = (s32)S.vs_mine[m].size * 680;
        s32 r_in  = r_out / 3;
        u8  mz    = (S.vs_mine[m].size == 2) ? 0x64u : 0x78u;
        emit_seg(mx, my + r_out, mx + r_in, my + r_in, mz);
        emit_seg(mx + r_in, my + r_in, mx + r_out, my, mz);
        emit_seg(mx + r_out, my, mx + r_in, my - r_in, mz);
        emit_seg(mx + r_in, my - r_in, mx, my - r_out, mz);
        emit_seg(mx, my - r_out, mx - r_in, my - r_in, mz);
        emit_seg(mx - r_in, my - r_in, mx - r_out, my, mz);
        emit_seg(mx - r_out, my, mx - r_in, my + r_in, mz);
        emit_seg(mx - r_in, my + r_in, mx, my + r_out, mz);

        for (int i = 0; i < 4; i++) {
            if (!S.vs_shot[i].active) continue;
            s32 dx = S.vs_shot[i].x - mx;
            s32 dy = S.vs_shot[i].y - my;
            if (dx < 0) dx = -dx;
            if (dy < 0) dy = -dy;
            if (dx < r_out && dy < r_out) {
                S.vs_shot[i].active = 0;
                S.vs_mine[m].active = 0;
                S.vs_score += (S.vs_mine[m].size == 2) ? 100u : 200u;
                S.vs_boom_tmr = 14u;
                if (S.vs_mine[m].size > 1) {
                    int spawned = 0;
                    for (int k = 0; k < 12 && spawned < 2; k++) {
                        if (!S.vs_mine[k].active) {
                            vs_spawn_mine(k, mx, my, 1);
                            spawned++;
                        }
                    }
                }
                break;
            }
        }
    }
    if (!any_mine) {
        for (int k = 0; k < 4; k++)
            vs_spawn_mine(k, 4000 + k * 7500, (k & 1) ? 32000 : 9000, 2);
    }

    audio_step(FRAME_CYC);
}

static void hle_rts(void)
{
    S.pc = rd16(S.s);
    S.s  = (u16)(S.s + 2u);
    S.step_cyc += 24;
}

static int handle_hle_exec(void)
{
    u16 pc = S.pc;
    switch (pc) {
    case 0xF000: { /* Cold Start: parse cartridge header at $0000 and jump to entry! */
        S.dp = 0xD0u;
        S.s  = 0xCBEA;
        M->ram[0x02A] = 0xF8u;           /* Vec_Text_Height = -8 */
        M->ram[0x02B] = 0x48u;           /* Vec_Text_Width  = +72 */
        M->ram[0x01F] = 1u;              /* Vec_Joy_Mux_1_X */
        M->ram[0x020] = 3u;              /* Vec_Joy_Mux_1_Y */
        M->ram[0x077] = 0x7Eu;           /* Random seed non-zero */
        M->ram[0x078] = 0x5Au;
        M->ram[0x079] = 0xC3u;
        via_write(0x2, 0x9Fu);
        via_write(0x3, 0xFFu);
        via_write(0xB, 0x98u);
        via_write(0xC, 0xCCu);
        via_write(0x8, 0x30u);
        via_write(0x9, 0x75u);
        if (!S.has_cart) {
            S.builtin_game = 1;
            vs_init();
            return 1;
        }
        /* Skip "g GCE YYYY\x80", 2-byte music ptr, then title list (pairs of h,w,y,x + str\x80 until 0x00) */
        u16 p = 5u;
        while (p < 0x0400u && (bus_read(p) & 0x80u) == 0u)
            p++;
        p++;                             /* past 0x80 of copyright */
        p = (u16)(p + 2u);               /* past 2-byte music pointer */
        while (p < 0x0800u) {
            u8 b = bus_read(p++);
            if (b == 0x00u)
                break;
            p = (u16)(p + 3u);           /* skip w, y, x (already read h) */
            while (p < 0x0800u && (bus_read(p++) & 0x80u) == 0u)
                ;
        }
        S.pc = p;
        S.step_cyc += 64;
        return 1;
    }

    case 0xF14C: /* Init_VIA */
        S.dp = 0xD0u;
        via_write(0x2, 0x9Fu);
        via_write(0x3, 0xFFu);
        via_write(0xB, 0x98u);
        via_write(0xC, 0xCCu);
        via_write(0x8, 0x30u);
        via_write(0x9, 0x75u);
        hle_rts();
        return 1;

    case 0xF164: /* Init_OS_RAM */
        S.dp = 0xC8u;
        for (int i = 0; i < 0x7B; i++) M->ram[i] = 0;
        M->ram[0x077] = 0x7Eu; M->ram[0x078] = 0x5Au; M->ram[0x079] = 0xC3u;
        M->ram[0x02A] = 0xF8u; M->ram[0x02B] = 0x48u;
        M->ram[0x01F] = 1u;    M->ram[0x020] = 3u;
        hle_rts();
        return 1;

    case 0xF18B: /* Init_OS */
        for (int i = 0; i < 0x7B; i++) M->ram[i] = 0;
        M->ram[0x077] = 0x7Eu; M->ram[0x078] = 0x5Au; M->ram[0x079] = 0xC3u;
        M->ram[0x02A] = 0xF8u; M->ram[0x02B] = 0x48u;
        M->ram[0x01F] = 1u;    M->ram[0x020] = 3u;
        for (int r = 0; r < 14; r++) psg_write_reg((u8)r, (r == 7) ? 0x3Fu : 0u);
        S.dp = 0xD0u;
        via_write(0x2, 0x9Fu);
        via_write(0x3, 0xFFu);
        via_write(0xB, 0x98u);
        via_write(0xC, 0xCCu);
        via_write(0x8, 0x30u);
        via_write(0x9, 0x75u);
        hle_rts();
        return 1;

    case 0xF192: /* Wait_Recal */
    case 0xF2FC: /* Recalibrate */
        if (pc == 0xF192u) {
            u16 cnt = (u16)(((u16)M->ram[0x025] << 8) | M->ram[0x026]) + 1u;
            M->ram[0x025] = (u8)(cnt >> 8);
            M->ram[0x026] = (u8)cnt;
            via_write(0x8, M->ram[0x03E] ? M->ram[0x03E] : 0x30u);
            via_write(0x9, M->ram[0x03D] ? M->ram[0x03D] : 0x75u);
            if (S.hle_in_frame)
                S.hle_end_frame = 1u;
            else
                S.hle_in_frame = 1u;
        }
        S.dp = 0xD0u;
        hle_reset0ref();
        hle_rts();
        return 1;

    case 0xF1AA: S.dp = 0xD0u; S.a = 0xD0u; hle_rts(); return 1; /* DP_to_D0 */
    case 0xF1AF: S.dp = 0xC8u; S.a = 0xC8u; hle_rts(); return 1; /* DP_to_C8 */

    case 0xF1B4: /* Read_Btns_Mask (A = auto-repeat mask: 0 = level-triggered, 1 = edge-triggered) */
    case 0xF1BA: { /* Read_Btns */
        u8 prev = M->ram[0x00F];
        if (pc == 0xF1B4u)
            prev &= S.a;
        u8 cur  = (u8)(~S.btn_mask) & 0x0Fu;
        M->ram[0x00E] = prev;
        M->ram[0x00F] = cur;
        u8 trig = (u8)(cur & ~prev);
        M->ram[0x011] = trig;
        for (int i = 0; i < 4; i++)
            M->ram[0x012 + i] = (trig & (1u << i)) ? (u8)(1u << i) : 0u;
        S.a = trig;
        S.cc = (u8)((S.cc & ~(CC_N | CC_Z)) | (S.a == 0 ? CC_Z : 0u));
        hle_rts();
        return 1;
    }

    case 0xF1F5: /* Joy_Digital */
    case 0xF1F8: { /* Joy_Analog */
        for (int i = 0; i < 4; i++) {
            u8 mux = M->ram[0x01F + i];
            if (mux == 0u) {
                M->ram[0x01B + i] = 0u;
            } else {
                s8 v = S.joy_pot[((mux - 1u) >> 1) & 3u];
                if (pc == 0xF1F5u)
                    v = (v > 32) ? 64 : (v < -32) ? -64 : 0;
                M->ram[0x01B + i] = (u8)v;
            }
        }
        hle_rts();
        return 1;
    }

    case 0xF256: /* Sound_Byte (A=reg, B=val) */
        M->ram[0x000 + (S.a & 0x0Fu)] = S.b;
        psg_write_reg(S.a, S.b);
        hle_rts();
        return 1;
    case 0xF259: /* Sound_Byte_x */
        bus_write((u16)(S.x + (S.a & 0x0Fu)), S.b);
        psg_write_reg(S.a, S.b);
        hle_rts();
        return 1;
    case 0xF272: /* Clear_Sound */
        for (int r = 0; r < 14; r++) {
            u8 v = (r == 7) ? 0x3Fu : 0u;
            M->ram[r] = v;
            psg_write_reg((u8)r, v);
        }
        hle_rts();
        return 1;
    case 0xF27D: /* Sound_Bytes (U -> (reg, val) pairs until reg < 0) */
    case 0xF284:
        while ((bus_read(S.u) & 0x80u) == 0u) {
            u8 r = bus_read(S.u++) & 0x0Fu;
            u8 v = bus_read(S.u++);
            M->ram[r] = v;
            psg_write_reg(r, v);
        }
        hle_rts();
        return 1;
    case 0xF289: /* Do_Sound */
    case 0xF28C:
        for (int r = 0; r < 14; r++)
            psg_write_reg((u8)r, M->ram[0x000 + r]);
        M->ram[0x056] = 0;               /* Vec_Music_Flag cleared once copied */
        hle_rts();
        return 1;

    case 0xF29D: S.a = 0x1Fu; goto do_inten;
    case 0xF2A1: S.a = 0x3Fu; goto do_inten;
    case 0xF2A5: S.a = 0x5Fu; goto do_inten;
    case 0xF2A9: S.a = 0x7Fu; /* fall through */
    case 0xF2AB: do_inten: /* Intensity_a */
        S.alg_zsh = S.a;
        M->ram[0x027] = S.a;
        hle_rts();
        return 1;

    case 0xF2BE: S.t1l_l = S.b; /* fall through */
    case 0xF2C1: S.a = bus_read(S.x++); S.b = bus_read(S.x++); /* fall through */
    case 0xF2C3: hle_moveto((s8)S.a, (s8)S.b, S.t1l_l); /* fall through */
    case 0xF2C5: /* Dot_here */
        emit_seg(S.alg_x, S.alg_y, S.alg_x, S.alg_y, S.alg_zsh);
        hle_rts();
        return 1;
    case 0xF2D5: { /* Dot_List: (C823)+1 dots at X */
        u8 cnt = M->ram[0x023];
        do {
            s8 dy = (s8)bus_read(S.x++);
            s8 dx = (s8)bus_read(S.x++);
            hle_moveto(dy, dx, S.t1l_l);
            emit_seg(S.alg_x, S.alg_y, S.alg_x, S.alg_y, S.alg_zsh);
        } while (cnt-- > 0u);
        M->ram[0x023] = 0;
        hle_rts();
        return 1;
    }
    case 0xF2DE: /* Dot_List_Reset: Y, X pairs until flag > 0 */
        for (int g = 0; g < 256; g++) {
            hle_reset0ref();
            u8 flag = bus_read(S.x++);
            if (flag > 0u && flag < 0x80u) break;
            s8 dy = (s8)bus_read(S.x++);
            s8 dx = (s8)bus_read(S.x++);
            hle_moveto(dy, dx, S.t1l_l);
            emit_seg(S.alg_x, S.alg_y, S.alg_x, S.alg_y, S.alg_zsh);
        }
        hle_rts();
        return 1;

    case 0xF308: S.b = bus_read((u16)(S.x + 1u)); S.a = bus_read(S.x); S.x += 2u; S.t1l_l = 0x7Fu; hle_moveto((s8)S.a, (s8)S.b, 0x7Fu); hle_rts(); return 1;
    case 0xF30C: S.t1l_l = 0x7Fu; hle_moveto((s8)S.a, (s8)S.b, 0x7Fu); hle_rts(); return 1;
    case 0xF30E: S.t1l_l = 0xFFu; goto do_mv_ix;
    case 0xF310: S.t1l_l = 0x7Fu; goto do_mv_ix;
    case 0xF312: S.t1l_l = S.b; /* fall through */
    case 0xF314: do_mv_ix:
        S.a = bus_read(S.x++);
        S.b = bus_read(S.x++);
        /* fall through */
    case 0xF318: /* Moveto_d */
        hle_moveto((s8)S.a, (s8)S.b, S.t1l_l);
        hle_rts();
        return 1;

    case 0xF34A: S.dp = 0xD0u; hle_reset0ref(); hle_rts(); return 1;
    case 0xF34F: if (M->ram[0x024]) hle_reset0ref(); hle_rts(); return 1;
    case 0xF354:
    case 0xF35B:
    case 0xF36B:
        hle_reset0ref();
        hle_rts();
        return 1;

    case 0xF373: /* Print_Str_hwyx (U -> h, w, y, x, chars...\x80) */
        M->ram[0x02A] = bus_read(S.u++);
        M->ram[0x02B] = bus_read(S.u++);
        /* fall through */
    case 0xF378: /* Print_Str_yx (U -> y, x, chars...\x80) */
        S.a = bus_read(S.u++);
        S.b = bus_read(S.u++);
        /* fall through */
    case 0xF37A: { /* Print_Str_d (A=y, B=x, U -> chars...\x80) */
        hle_reset0ref();
        hle_moveto((s8)S.a, (s8)S.b, 0x7Fu);
        hle_draw_text(S.alg_x, S.alg_y, (s8)M->ram[0x02A], (s8)M->ram[0x02B], 0, S.u, S.alg_zsh);
        while ((bus_read(S.u++) & 0x80u) == 0u)
            ;
        hle_reset0ref();
        hle_rts();
        return 1;
    }
    case 0xF385: /* Print_List_hw */
    case 0xF38A: /* Print_List */
    case 0xF38C: {
        int has_hw = (pc == 0xF385u);
        for (int g = 0; g < 32; g++) {
            u8 b0 = bus_read(S.u);
            if (b0 == 0u) { S.u++; break; }
            if (has_hw) {
                M->ram[0x02A] = bus_read(S.u++);
                M->ram[0x02B] = bus_read(S.u++);
            }
            s8 py = (s8)bus_read(S.u++);
            s8 px = (s8)bus_read(S.u++);
            hle_reset0ref();
            hle_moveto(py, px, 0x7Fu);
            hle_draw_text(S.alg_x, S.alg_y, (s8)M->ram[0x02A], (s8)M->ram[0x02B], 0, S.u, S.alg_zsh);
            while ((bus_read(S.u++) & 0x80u) == 0u)
                ;
            if (pc == 0xF38Cu && bus_read(S.u) > 0u && bus_read(S.u) < 0x80u)
                break;
        }
        hle_reset0ref();
        hle_rts();
        return 1;
    }

    /* Mov_Draw_VL family ($F3AD..$F3BE) */
    case 0xF3AD: S.a = bus_read(S.x++); S.b = bus_read(S.x++); goto do_md_vl_ab;
    case 0xF3B1: S.t1l_l = S.b; goto do_md_vl;
    case 0xF3B5: S.a = bus_read(S.x++); S.b = bus_read(S.x++); /* fall through */
    case 0xF3B7: do_md_vl_ab: S.t1l_l = S.b; /* fall through */
    case 0xF3B9: M->ram[0x023] = S.a; /* fall through */
    case 0xF3BC: do_md_vl: {
        s8 my = (s8)bus_read(S.x++);
        s8 mx = (s8)bus_read(S.x++);
        hle_moveto(my, mx, S.t1l_l);
        u8 cnt = M->ram[0x023];
        for (u8 i = 0; i < cnt; i++) {
            s8 dy = (s8)bus_read(S.x++);
            s8 dx = (s8)bus_read(S.x++);
            hle_draw_line(dy, dx, S.t1l_l, 0xFFu);
        }
        M->ram[0x023] = 0;
        if (M->ram[0x024]) hle_reset0ref();
        hle_rts();
        return 1;
    }

    /* Draw_VL family ($F3CE..$F410) */
    case 0xF3CE: S.a = bus_read(S.x++); goto do_d_vl_a;
    case 0xF3D2: S.t1l_l = S.b; goto do_d_vl;
    case 0xF3D6: S.a = bus_read(S.x++); S.b = bus_read(S.x++); /* fall through */
    case 0xF3D8: S.t1l_l = S.b; /* fall through */
    case 0xF3DA: do_d_vl_a: M->ram[0x023] = S.a; /* fall through */
    case 0xF3DD: do_d_vl: {
        u8 cnt = M->ram[0x023];
        do {
            s8 dy = (s8)bus_read(S.x++);
            s8 dx = (s8)bus_read(S.x++);
            hle_draw_line(dy, dx, S.t1l_l, 0xFFu);
        } while (cnt-- > 0u);
        M->ram[0x023] = 0;
        if (M->ram[0x024]) hle_reset0ref();
        hle_rts();
        return 1;
    }

    /* Draw_VLp pattern-list family ($F3DF..$F404): (mode, y, x)... until mode > 0 */
    case 0xF3DF: S.b = 0xFFu; goto do_vlp_b;
    case 0xF3E2: S.b = 0x7Fu; goto do_vlp_b;
    case 0xF3E4: S.b = bus_read(S.x++); /* fall through */
    case 0xF3EA: do_vlp_b: S.t1l_l = S.b; /* fall through */
    case 0xF404:
        for (int g = 0; g < 256; g++) {
            s8 m = (s8)bus_read(S.x++);
            if (m > 0) break;
            s8 dy = (s8)bus_read(S.x++);
            s8 dx = (s8)bus_read(S.x++);
            if (m == 0) hle_moveto(dy, dx, S.t1l_l);
            else        hle_draw_line(dy, dx, S.t1l_l, (u8)m);
        }
        if (M->ram[0x024]) hle_reset0ref();
        hle_rts();
        return 1;

    case 0xF408: M->ram[0x023] = S.a; /* fall through */
    case 0xF40C: {
        u8 pat = M->ram[0x029];
        u8 cnt = M->ram[0x023];
        do {
            s8 dy = (s8)bus_read(S.x++);
            s8 dx = (s8)bus_read(S.x++);
            hle_draw_line(dy, dx, S.t1l_l, pat);
        } while (cnt-- > 0u);
        M->ram[0x023] = 0;
        if (M->ram[0x024]) hle_reset0ref();
        hle_rts();
        return 1;
    }
    case 0xF40E:
        hle_draw_line((s8)S.a, (s8)S.b, S.t1l_l, M->ram[0x029]);
        if (M->ram[0x024]) hle_reset0ref();
        hle_rts();
        return 1;
    case 0xF410: /* Draw_VL_mode: (mode, y, x)... mode > 0 ends, 0 moves, -1 draws, else pattern */
        for (int g = 0; g < 256; g++) {
            s8 m = (s8)bus_read(S.x++);
            if (m > 0) break;
            s8 dy = (s8)bus_read(S.x++);
            s8 dx = (s8)bus_read(S.x++);
            if (m == 0) hle_moveto(dy, dx, S.t1l_l);
            else        hle_draw_line(dy, dx, S.t1l_l, (u8)m);
        }
        if (M->ram[0x024]) hle_reset0ref();
        hle_rts();
        return 1;

    /* Random / Clear / Counters / Math / Score helpers */
    case 0xF511:
    case 0xF517: {
        int n = (pc == 0xF511u) ? 3 : 1;
        for (int i = 0; i < n; i++) {
            u8 s0 = M->ram[0x077], s1 = M->ram[0x078], s2 = M->ram[0x079];
            if (!(s0 | s1 | s2)) s0 = 1u;
            u8 bit = (u8)((s0 ^ (s2 >> 5) ^ (s2 >> 4)) & 1u);
            M->ram[0x077] = (u8)((s0 << 1) | (s1 >> 7));
            M->ram[0x078] = (u8)((s1 << 1) | (s2 >> 7));
            M->ram[0x079] = (u8)((s2 << 1) | bit);
        }
        S.a = M->ram[0x077];
        hle_rts();
        return 1;
    }
    case 0xF533:
        for (int i = 0; i < 14; i++) M->ram[i] = (i == 7) ? 0x3Fu : 0u;
        hle_rts();
        return 1;
    case 0xF53F: { u16 n = (u16)S.b + 1u; for (u16 i = 0; i < n; i++) bus_write((u16)(S.x + i), 0u); hle_rts(); return 1; }
    case 0xF542: S.x = 0xC800u; /* fall through */
    case 0xF545: for (u16 i = 0; i < 256u; i++) bus_write((u16)(S.x + i), 0u); hle_rts(); return 1;
    case 0xF548: { u16 n = (u16)(((u16)S.a << 8) | S.b) + 1u; for (u16 i = 0; i < n; i++) bus_write((u16)(S.x + i), 0u); hle_rts(); return 1; }
    case 0xF550: S.a = 0x80u; /* fall through */
    case 0xF552: { u16 n = (u16)S.b + 1u; for (u16 i = 0; i < n; i++) bus_write((u16)(S.x + i), S.a); hle_rts(); return 1; }
    case 0xF55A: S.b = 2u; S.x = 0xC82Eu; goto do_dec_cnt;
    case 0xF55E: S.b = 5u; S.x = 0xC82Eu; /* fall through */
    case 0xF563: do_dec_cnt:
        for (u16 i = 0; i <= S.b; i++) {
            u8 v = bus_read((u16)(S.x + i));
            if (v) bus_write((u16)(S.x + i), (u8)(v - 1u));
        }
        hle_rts();
        return 1;
    case 0xF56D: case 0xF571: case 0xF575: case 0xF579: case 0xF57A: case 0xF57D:
        hle_rts();
        return 1;
    case 0xF584: S.a = (u8)(1u << (S.a & 7u)); hle_rts(); return 1;
    case 0xF58B: if (S.a & 0x80u) S.a = (S.a == 0x80u) ? 0x7Fu : (u8)(-(s8)S.a); /* fall through */
    case 0xF593: if (S.b & 0x80u) S.b = (S.b == 0x80u) ? 0x7Fu : (u8)(-(s8)S.b); hle_rts(); return 1;

    case 0xF601: S.a = (u8)vec_sin64[(S.a + 16u) & 63u]; S.b = 0; hle_rts(); return 1;
    case 0xF603: S.a = (u8)(-vec_sin64[S.a & 63u]);      S.b = 0; hle_rts(); return 1;
    case 0xF610: case 0xF613: case 0xF616: {
        u8 ang = (pc == 0xF610u) ? (u8)(S.b + 16u) : (pc == 0xF613u) ? (u8)(S.b - 16u) : S.b;
        s32 mag = (s8)S.a;
        s32 rise = (mag * vec_sin64[(ang + 16u) & 63u]) / 127;
        s32 run  = (mag * (-vec_sin64[ang & 63u])) / 127;
        S.a = (u8)rise;
        S.b = (u8)run;
        hle_rts();
        return 1;
    }
    case 0xF61F: /* Rot_VL_ab (A=angle, B=cnt-1, X=src, U=dst) */
        M->ram[0x036] = S.a;
        M->ram[0x023] = S.b;
        /* fall through */
    case 0xF62B: { /* Rot_VL */
        u8 ang = M->ram[0x036] & 63u;
        s32 cs = vec_sin64[(ang + 16u) & 63u];
        s32 sn = vec_sin64[ang & 63u];
        u8 cnt = M->ram[0x023];
        do {
            s32 y = (s8)bus_read(S.x++);
            s32 x = (s8)bus_read(S.x++);
            s32 ny = (y * cs + x * sn) / 127;
            s32 nx = (x * cs - y * sn) / 127;
            bus_write(S.u++, (u8)ny);
            bus_write(S.u++, (u8)nx);
        } while (cnt-- > 0u);
        M->ram[0x023] = 0;
        hle_rts();
        return 1;
    }
    case 0xF637: { /* Rot_VL_Mode (A=angle, X=src (mode,y,x)..., U=dst) */
        u8 ang = S.a & 63u;
        s32 cs = vec_sin64[(ang + 16u) & 63u];
        s32 sn = vec_sin64[ang & 63u];
        for (int g = 0; g < 256; g++) {
            s8 m = (s8)bus_read(S.x++);
            bus_write(S.u++, (u8)m);
            if (m > 0) break;
            s32 y = (s8)bus_read(S.x++);
            s32 x = (s8)bus_read(S.x++);
            bus_write(S.u++, (u8)((y * cs + x * sn) / 127));
            bus_write(S.u++, (u8)((x * cs - y * sn) / 127));
        }
        hle_rts();
        return 1;
    }
    case 0xF67F: { for (int i = S.a; i >= 0; i--) bus_write((u16)(S.x + (u16)i), bus_read((u16)(S.u + (u16)i))); hle_rts(); return 1; }
    case 0xF683: { for (int i = (int)S.a - 1; i >= 0; i--) bus_write((u16)(S.x + (u16)i), bus_read((u16)(S.u + (u16)i))); hle_rts(); return 1; }
    case 0xF687: case 0xF68D: case 0xF692:
        M->ram[0x056] = 0;               /* Music finished / silent clean fallback */
        hle_rts();
        return 1;
    case 0xF7A9: /* Select_Game (A=max players, B=max options) */
        M->ram[0x079] = 1u;
        M->ram[0x07A] = 1u;
        hle_rts();
        return 1;
    case 0xF84F: /* Clear_Score (X -> 6 ASCII digits + 0x80) */
        for (int i = 0; i < 5; i++) bus_write((u16)(S.x + (u16)i), ' ');
        bus_write((u16)(S.x + 5u), '0');
        bus_write((u16)(S.x + 6u), 0x80u);
        hle_rts();
        return 1;
    case 0xF85E: /* Add_Score_a (A = BCD, X -> 6-char score) */
    case 0xF87C: { /* Add_Score_d (D = 4-digit BCD, X -> 6-char score) */
        u32 add = (pc == 0xF85Eu)
            ? (((u32)(S.a >> 4) * 10u) + (S.a & 0x0Fu))
            : (((u32)(S.a >> 4) * 1000u) + ((u32)(S.a & 0x0Fu) * 100u) + ((u32)(S.b >> 4) * 10u) + (S.b & 0x0Fu));
        u32 cur = 0;
        for (int i = 0; i < 6; i++) {
            u8 ch = bus_read((u16)(S.x + (u16)i));
            u32 d = (ch >= '0' && ch <= '9') ? (u32)(ch - '0') : 0u;
            cur = cur * 10u + d;
        }
        cur += add;
        for (int i = 5; i >= 0; i--) {
            u32 dig = cur % 10u;
            cur /= 10u;
            bus_write((u16)(S.x + (u16)i), (cur == 0 && dig == 0 && i < 5) ? ' ' : (u8)('0' + dig));
        }
        hle_rts();
        return 1;
    }
    case 0xF8E5: case 0xF8F3: case 0xF8FF: { /* Obj_Hit (Y=pos1, X=pos2, D=half-box h,w; C=1 on hit) */
        s32 dy = (s8)(S.y >> 8) - (s8)(S.x >> 8);
        s32 dx = (s8)(S.y & 0xFFu) - (s8)(S.x & 0xFFu);
        if (dy < 0) dy = -dy;
        if (dx < 0) dx = -dx;
        if (dy <= (s32)S.a && dx <= (s32)S.b) S.cc |= CC_C;
        else                                  S.cc &= (u8)~CC_C;
        hle_rts();
        return 1;
    }
    case 0xF92E: /* Explosion_Snd */
        hle_rts();
        return 1;
    }
    return 0;
}

static void build_clean_sysrom(void)
{
    for (int i = 0; i < 0x2000; i++)
        M->sysrom[i] = 0x39u;            /* RTS safe fallback across $E000..$FFFF */

    /* Populate clean-room 5x7 font at $F9D4 (offset 0x19D4: 7 rows x 64 chars) */
    for (int row = 0; row < 7; row++) {
        for (int ch = 0; ch < 64; ch++)
            M->sysrom[0x19D4 + row * 64 + ch] = clean_font5x7[ch][row];
    }

    /* Hardware interrupt indirection jumps at $FFF0..$FFFF matching GCE layout */
    M->sysrom[0x1FF0] = 0x00u; M->sysrom[0x1FF1] = 0x00u;
    M->sysrom[0x1FF2] = 0xCBu; M->sysrom[0x1FF3] = 0xF2u; /* SWI3  -> $CBF2 */
    M->sysrom[0x1FF4] = 0xCBu; M->sysrom[0x1FF5] = 0xF2u; /* SWI2  -> $CBF2 */
    M->sysrom[0x1FF6] = 0xCBu; M->sysrom[0x1FF7] = 0xF5u; /* FIRQ  -> $CBF5 */
    M->sysrom[0x1FF8] = 0xCBu; M->sysrom[0x1FF9] = 0xF8u; /* IRQ   -> $CBF8 */
    M->sysrom[0x1FFA] = 0xCBu; M->sysrom[0x1FFBu] = 0xFBu; /* SWI   -> $CBFB */
    M->sysrom[0x1FFC] = 0xCBu; M->sysrom[0x1FFDu] = 0xFBu; /* NMI   -> $CBFB */
    M->sysrom[0x1FFE] = 0xF0u; M->sysrom[0x1FFFu] = 0x00u; /* RESET -> $F000 */
}

/* ---- Full Motorola MC6809 CPU ---- */
INLINE u16 get_d(void)
{
    return (u16)(((u16)S.a << 8) | S.b);
}

INLINE void set_d(u16 v)
{
    S.a = (u8)(v >> 8);
    S.b = (u8)v;
}

INLINE void nz8(u8 v)
{
    S.cc = (u8)((S.cc & ~(CC_N | CC_Z | CC_V)) | ((v & 0x80u) ? CC_N : 0u) | (v == 0 ? CC_Z : 0u));
}

INLINE void nz16(u16 v)
{
    S.cc = (u8)((S.cc & ~(CC_N | CC_Z | CC_V)) | ((v & 0x8000u) ? CC_N : 0u) | (v == 0 ? CC_Z : 0u));
}

INLINE void push8_s(u8 v)  { S.s--; bus_write(S.s, v); }
INLINE u8   pull8_s(void)  { return bus_read(S.s++); }
INLINE void push16_s(u16 v){ push8_s((u8)v); push8_s((u8)(v >> 8)); }
INLINE u16  pull16_s(void) { u16 hi = pull8_s(); return (u16)((hi << 8) | pull8_s()); }

INLINE void push8_u(u8 v)  { S.u--; bus_write(S.u, v); }
INLINE u8   pull8_u(void)  { return bus_read(S.u++); }
INLINE void push16_u(u16 v){ push8_u((u8)v); push8_u((u8)(v >> 8)); }
INLINE u16  pull16_u(void) { u16 hi = pull8_u(); return (u16)((hi << 8) | pull8_u()); }

static void push_entire_state(void)
{
    S.cc |= CC_E;
    push16_s(S.pc);
    push16_s(S.u);
    push16_s(S.y);
    push16_s(S.x);
    push8_s(S.dp);
    push8_s(S.b);
    push8_s(S.a);
    push8_s(S.cc);
}

static u16 *idx_reg_ptr(u8 rr)
{
    switch (rr & 3u) {
    case 0: return &S.x;
    case 1: return &S.y;
    case 2: return &S.u;
    default:
        S.nmi_armed = 1u;
        return &S.s;
    }
}

static u16 ea_indexed(void)
{
    u8 post = fetch8();
    u16 *rp = idx_reg_ptr((post >> 5) & 3u);

    if ((post & 0x80u) == 0u) {
        s8 off5 = (post & 0x10u) ? (s8)(post | 0xE0u) : (s8)(post & 0x0Fu);
        S.step_cyc += 1;
        return (u16)(*rp + off5);
    }

    u16 ea = 0;
    switch (post & 0x0Fu) {
    case 0x0: ea = *rp; (*rp)++; S.step_cyc += 2; break;
    case 0x1: ea = *rp; (*rp) += 2u; S.step_cyc += 3; break;
    case 0x2: (*rp)--; ea = *rp; S.step_cyc += 2; break;
    case 0x3: (*rp) -= 2u; ea = *rp; S.step_cyc += 3; break;
    case 0x4: ea = *rp; break;
    case 0x5: ea = (u16)(*rp + (s8)S.b); S.step_cyc += 1; break;
    case 0x6: ea = (u16)(*rp + (s8)S.a); S.step_cyc += 1; break;
    case 0x8: { s8 d8 = (s8)fetch8(); ea = (u16)(*rp + d8); S.step_cyc += 1; break; }
    case 0x9: { u16 d16 = fetch16();  ea = (u16)(*rp + d16); S.step_cyc += 4; break; }
    case 0xB: ea = (u16)(*rp + (s16)get_d()); S.step_cyc += 4; break;
    case 0xC: { s8 d8 = (s8)fetch8(); ea = (u16)(S.pc + d8); S.step_cyc += 1; break; }
    case 0xD: { u16 d16 = fetch16();  ea = (u16)(S.pc + d16); S.step_cyc += 5; break; }
    case 0xF: ea = fetch16(); S.step_cyc += 2; break;
    default:  ea = *rp; break;
    }

    if (post & 0x10u) {
        ea = rd16(ea);
        S.step_cyc += 3;
    }
    return ea;
}

INLINE u16 ea_direct(void)
{
    return (u16)(((u16)S.dp << 8) | fetch8());
}

static u8 alu_add8(u8 a, u8 b, u32 c)
{
    u32 r = (u32)a + (u32)b + c;
    u8 res = (u8)r;
    u8 flags = 0;
    if (((a & 0x0Fu) + (b & 0x0Fu) + c) & 0x10u) flags |= CC_H;
    if (res & 0x80u) flags |= CC_N;
    if (res == 0u)   flags |= CC_Z;
    if ((~(a ^ b) & (a ^ res)) & 0x80u) flags |= CC_V;
    if (r & 0x100u)  flags |= CC_C;
    S.cc = (u8)((S.cc & ~(CC_H | CC_N | CC_Z | CC_V | CC_C)) | flags);
    return res;
}

static u8 alu_sub8(u8 a, u8 b, u32 borrow)
{
    u32 r = (u32)a - (u32)b - borrow;
    u8 res = (u8)r;
    u8 flags = 0;
    if (res & 0x80u) flags |= CC_N;
    if (res == 0u)   flags |= CC_Z;
    if (((a ^ b) & (a ^ res)) & 0x80u) flags |= CC_V;
    if (r & 0x100u)  flags |= CC_C;
    S.cc = (u8)((S.cc & ~(CC_N | CC_Z | CC_V | CC_C)) | flags);
    return res;
}

static u16 alu_add16(u16 a, u16 b)
{
    u32 r = (u32)a + (u32)b;
    u16 res = (u16)r;
    u8 flags = 0;
    if (res & 0x8000u) flags |= CC_N;
    if (res == 0u)     flags |= CC_Z;
    if ((~(a ^ b) & (a ^ res)) & 0x8000u) flags |= CC_V;
    if (r & 0x10000u)  flags |= CC_C;
    S.cc = (u8)((S.cc & ~(CC_N | CC_Z | CC_V | CC_C)) | flags);
    return res;
}

static u16 alu_sub16(u16 a, u16 b)
{
    u32 r = (u32)a - (u32)b;
    u16 res = (u16)r;
    u8 flags = 0;
    if (res & 0x8000u) flags |= CC_N;
    if (res == 0u)     flags |= CC_Z;
    if (((a ^ b) & (a ^ res)) & 0x8000u) flags |= CC_V;
    if (r & 0x10000u)  flags |= CC_C;
    S.cc = (u8)((S.cc & ~(CC_N | CC_Z | CC_V | CC_C)) | flags);
    return res;
}

static u8 rmw8_op(u8 subop, u8 v)
{
    u8 c;
    switch (subop) {
    case 0x0: /* NEG */
        return alu_sub8(0u, v, 0u);
    case 0x3: /* COM */
        v = (u8)~v;
        nz8(v);
        S.cc |= CC_C;
        return v;
    case 0x4: /* LSR */
        c = v & 1u;
        v >>= 1;
        nz8(v);
        S.cc = (u8)((S.cc & ~CC_C) | c);
        return v;
    case 0x6: /* ROR */
        c = v & 1u;
        v = (u8)((v >> 1) | ((S.cc & CC_C) << 7));
        nz8(v);
        S.cc = (u8)((S.cc & ~CC_C) | c);
        return v;
    case 0x7: /* ASR */
        c = v & 1u;
        v = (u8)(((s8)v) >> 1);
        nz8(v);
        S.cc = (u8)((S.cc & ~CC_C) | c);
        return v;
    case 0x8: /* ASL / LSL */
        c = (v >> 7) & 1u;
        {
            u8 nv = (u8)(v << 1);
            u8 ov = ((v ^ nv) & 0x80u) ? CC_V : 0u;
            nz8(nv);
            S.cc = (u8)((S.cc & ~(CC_V | CC_C)) | ov | c);
            return nv;
        }
    case 0x9: /* ROL */
        c = (v >> 7) & 1u;
        {
            u8 nv = (u8)((v << 1) | (S.cc & CC_C));
            u8 ov = ((v ^ nv) & 0x80u) ? CC_V : 0u;
            nz8(nv);
            S.cc = (u8)((S.cc & ~(CC_V | CC_C)) | ov | c);
            return nv;
        }
    case 0xA: /* DEC */
        {
            u8 ov = (v == 0x80u) ? CC_V : 0u;
            v--;
            nz8(v);
            S.cc |= ov;
            return v;
        }
    case 0xC: /* INC */
        {
            u8 ov = (v == 0x7Fu) ? CC_V : 0u;
            v++;
            nz8(v);
            S.cc |= ov;
            return v;
        }
    case 0xD: /* TST */
        nz8(v);
        return v;
    case 0xF: /* CLR */
        S.cc = (u8)((S.cc & ~(CC_N | CC_V | CC_C)) | CC_Z);
        return 0u;
    default:
        return v;
    }
}

static int cond_true(u8 code)
{
    int n = (S.cc & CC_N) != 0;
    int z = (S.cc & CC_Z) != 0;
    int v = (S.cc & CC_V) != 0;
    int c = (S.cc & CC_C) != 0;
    switch (code & 0x0Fu) {
    case 0x0: return 1;                  /* BRA */
    case 0x1: return 0;                  /* BRN */
    case 0x2: return !c && !z;           /* BHI */
    case 0x3: return c || z;             /* BLS */
    case 0x4: return !c;                 /* BCC / BHS */
    case 0x5: return c;                  /* BCS / BLO */
    case 0x6: return !z;                 /* BNE */
    case 0x7: return z;                  /* BEQ */
    case 0x8: return !v;                 /* BVC */
    case 0x9: return v;                  /* BVS */
    case 0xA: return !n;                 /* BPL */
    case 0xB: return n;                  /* BMI */
    case 0xC: return n == v;             /* BGE */
    case 0xD: return n != v;             /* BLT */
    case 0xE: return !z && (n == v);     /* BGT */
    case 0xF: return z || (n != v);      /* BLE */
    }
    return 0;
}

static u16 tfr_get(u8 r)
{
    switch (r & 0x0Fu) {
    case 0x0: return get_d();
    case 0x1: return S.x;
    case 0x2: return S.y;
    case 0x3: return S.u;
    case 0x4: return S.s;
    case 0x5: return S.pc;
    case 0x8: return (u16)(0xFF00u | S.a);
    case 0x9: return (u16)(0xFF00u | S.b);
    case 0xA: return (u16)((S.cc << 8) | S.cc);
    case 0xB: return (u16)((S.dp << 8) | S.dp);
    default:  return 0xFFFFu;
    }
}

static void tfr_set(u8 r, u16 v)
{
    switch (r & 0x0Fu) {
    case 0x0: set_d(v); break;
    case 0x1: S.x  = v; break;
    case 0x2: S.y  = v; break;
    case 0x3: S.u  = v; break;
    case 0x4: S.s  = v; S.nmi_armed = 1u; break;
    case 0x5: S.pc = v; break;
    case 0x8: S.a  = (u8)v; break;
    case 0x9: S.b  = (u8)v; break;
    case 0xA: S.cc = (u8)v; break;
    case 0xB: S.dp = (u8)v; break;
    default: break;
    }
}

static int step_6809(void)
{
    S.step_cyc = 0;

    int irq_line = (S.ifr & S.ier & 0x7Fu) != 0;
    if (S.nmi_pend && S.nmi_armed) {
        S.nmi_pend = 0;
        S.halted_sync = 0;
        if (!S.halted_cwai) push_entire_state();
        S.halted_cwai = 0;
        S.cc |= CC_I | CC_F;
        S.pc = rd16(0xFFFCu);
        return 19;
    }
    if (S.firq_pend) {
        S.halted_sync = 0;
        if (!(S.cc & CC_F)) {
            S.firq_pend = 0;
            if (!S.halted_cwai) {
                S.cc &= (u8)~CC_E;
                push16_s(S.pc);
                push8_s(S.cc);
            }
            S.halted_cwai = 0;
            S.cc |= CC_I | CC_F;
            S.pc = rd16(0xFFF6u);
            return 10;
        }
    }
    if (irq_line) {
        S.halted_sync = 0;
        if (!(S.cc & CC_I)) {
            if (!S.halted_cwai) push_entire_state();
            S.halted_cwai = 0;
            S.cc |= CC_I;
            S.pc = rd16(0xFFF8u);
            return 19;
        }
    }
    if (S.halted_sync || S.halted_cwai)
        return 2;

    if (S.using_hle_bios && S.pc >= 0xF000u) {
        if (handle_hle_exec())
            return S.step_cyc ? S.step_cyc : 16;
    }

    u8 op = fetch8();
    u16 ea, v16;
    u8 v8;

    /* Direct-page RMW + JMP ($00..$0F) */
    if (op < 0x10u) {
        ea = ea_direct();
        if (op == 0x0Eu) { S.pc = ea; return S.step_cyc + 3; }
        if (op == 0x0Du) { (void)rmw8_op(0xDu, bus_read(ea)); return S.step_cyc + 6; }
        bus_write(ea, rmw8_op(op, bus_read(ea)));
        return S.step_cyc + 6;
    }

    /* Short branches ($20..$2F) */
    if (op >= 0x20u && op < 0x30u) {
        s8 rel = (s8)fetch8();
        if (cond_true(op))
            S.pc = (u16)(S.pc + rel);
        return 3;
    }

    /* Inherent A / B RMW ($40..$5F) */
    if (op >= 0x40u && op < 0x50u) {
        S.a = rmw8_op(op & 0x0Fu, S.a);
        return 2;
    }
    if (op >= 0x50u && op < 0x60u) {
        S.b = rmw8_op(op & 0x0Fu, S.b);
        return 2;
    }

    /* Indexed RMW + JMP ($60..$6F) */
    if (op >= 0x60u && op < 0x70u) {
        ea = ea_indexed();
        if (op == 0x6Eu) { S.pc = ea; return S.step_cyc + 3; }
        if (op == 0x6Du) { (void)rmw8_op(0xDu, bus_read(ea)); return S.step_cyc + 6; }
        bus_write(ea, rmw8_op(op & 0x0Fu, bus_read(ea)));
        return S.step_cyc + 6;
    }

    /* Extended RMW + JMP ($70..$7F) */
    if (op >= 0x70u && op < 0x80u) {
        ea = fetch16();
        if (op == 0x7Eu) { S.pc = ea; return 4; }
        if (op == 0x7Du) { (void)rmw8_op(0xDu, bus_read(ea)); return 7; }
        bus_write(ea, rmw8_op(op & 0x0Fu, bus_read(ea)));
        return 7;
    }

    /* Page $10 & Page $11 extended opcodes */
    if (op == 0x10u) {
        u8 op2 = fetch8();
        if (op2 >= 0x21u && op2 <= 0x2Fu) {
            s16 rel16 = (s16)fetch16();
            if (cond_true(op2)) {
                S.pc = (u16)(S.pc + rel16);
                return 6;
            }
            return 5;
        }
        switch (op2) {
        case 0x3F: /* SWI2 */
            push_entire_state();
            S.pc = rd16(0xFFF4u);
            return 20;
        case 0x83: v16 = fetch16(); (void)alu_sub16(get_d(), v16); return 5;
        case 0x93: ea = ea_direct();  (void)alu_sub16(get_d(), rd16(ea)); return 7;
        case 0xA3: ea = ea_indexed(); (void)alu_sub16(get_d(), rd16(ea)); return S.step_cyc + 7;
        case 0xB3: ea = fetch16();    (void)alu_sub16(get_d(), rd16(ea)); return 8;

        case 0x8C: v16 = fetch16();   (void)alu_sub16(S.y, v16); return 5;
        case 0x9C: ea = ea_direct();  (void)alu_sub16(S.y, rd16(ea)); return 7;
        case 0xAC: ea = ea_indexed(); (void)alu_sub16(S.y, rd16(ea)); return S.step_cyc + 7;
        case 0xBC: ea = fetch16();    (void)alu_sub16(S.y, rd16(ea)); return 8;

        case 0x8E: S.y = fetch16();   nz16(S.y); return 4;
        case 0x9E: ea = ea_direct();  S.y = rd16(ea); nz16(S.y); return 6;
        case 0xAE: ea = ea_indexed(); S.y = rd16(ea); nz16(S.y); return S.step_cyc + 6;
        case 0xBE: ea = fetch16();    S.y = rd16(ea); nz16(S.y); return 7;

        case 0x9F: ea = ea_direct();  wr16(ea, S.y); nz16(S.y); return 6;
        case 0xAF: ea = ea_indexed(); wr16(ea, S.y); nz16(S.y); return S.step_cyc + 6;
        case 0xBF: ea = fetch16();    wr16(ea, S.y); nz16(S.y); return 7;

        case 0xCE: S.s = fetch16();   S.nmi_armed = 1u; nz16(S.s); return 4;
        case 0xDE: ea = ea_direct();  S.s = rd16(ea); S.nmi_armed = 1u; nz16(S.s); return 6;
        case 0xEE: ea = ea_indexed(); S.s = rd16(ea); S.nmi_armed = 1u; nz16(S.s); return S.step_cyc + 6;
        case 0xFE: ea = fetch16();    S.s = rd16(ea); S.nmi_armed = 1u; nz16(S.s); return 7;

        case 0xDF: ea = ea_direct();  wr16(ea, S.s); nz16(S.s); return 6;
        case 0xEF: ea = ea_indexed(); wr16(ea, S.s); nz16(S.s); return S.step_cyc + 6;
        case 0xFF: ea = fetch16();    wr16(ea, S.s); nz16(S.s); return 7;
        default: return 2;
        }
    }

    if (op == 0x11u) {
        u8 op2 = fetch8();
        switch (op2) {
        case 0x3F: /* SWI3 */
            push_entire_state();
            S.pc = rd16(0xFFF2u);
            return 20;
        case 0x83: v16 = fetch16();   (void)alu_sub16(S.u, v16); return 5;
        case 0x93: ea = ea_direct();  (void)alu_sub16(S.u, rd16(ea)); return 7;
        case 0xA3: ea = ea_indexed(); (void)alu_sub16(S.u, rd16(ea)); return S.step_cyc + 7;
        case 0xB3: ea = fetch16();    (void)alu_sub16(S.u, rd16(ea)); return 8;

        case 0x8C: v16 = fetch16();   (void)alu_sub16(S.s, v16); return 5;
        case 0x9C: ea = ea_direct();  (void)alu_sub16(S.s, rd16(ea)); return 7;
        case 0xAC: ea = ea_indexed(); (void)alu_sub16(S.s, rd16(ea)); return S.step_cyc + 7;
        case 0xBC: ea = fetch16();    (void)alu_sub16(S.s, rd16(ea)); return 8;
        default: return 2;
        }
    }

    /* Group $10..$3F misc & stack / LEA */
    switch (op) {
    case 0x12: return 2;                 /* NOP */
    case 0x13: S.halted_sync = 1u; return 4; /* SYNC */
    case 0x16: { s16 r = (s16)fetch16(); S.pc = (u16)(S.pc + r); return 5; } /* LBRA */
    case 0x17: { s16 r = (s16)fetch16(); push16_s(S.pc); S.pc = (u16)(S.pc + r); return 9; } /* LBSR */
    case 0x19: { /* DAA */
        u32 corr = 0;
        u8 msn = S.a & 0xF0u, lsn = S.a & 0x0Fu;
        if ((S.cc & CC_H) || lsn > 0x09u) corr |= 0x06u;
        if ((S.cc & CC_C) || msn > 0x90u || (msn > 0x80u && lsn > 0x09u)) corr |= 0x60u;
        u32 res = (u32)S.a + corr;
        S.a = (u8)res;
        S.cc = (u8)((S.cc & ~(CC_N | CC_Z | CC_V)) | ((S.a & 0x80u) ? CC_N : 0u) |
                    (S.a == 0 ? CC_Z : 0u) | ((res & 0x100u) ? CC_C : 0u));
        return 2;
    }
    case 0x1A: S.cc |= fetch8(); return 3;           /* ORCC */
    case 0x1C: S.cc &= fetch8(); return 3;           /* ANDCC */
    case 0x1D: S.a = (S.b & 0x80u) ? 0xFFu : 0x00u; nz16(get_d()); return 2; /* SEX */
    case 0x1E: { /* EXG */
        u8 pb = fetch8();
        u8 r1 = pb >> 4, r2 = pb & 0x0Fu;
        u16 a1 = tfr_get(r1), a2 = tfr_get(r2);
        tfr_set(r1, a2);
        tfr_set(r2, a1);
        return 8;
    }
    case 0x1F: { /* TFR */
        u8 pb = fetch8();
        tfr_set(pb & 0x0Fu, tfr_get(pb >> 4));
        return 6;
    }

    case 0x30: S.x = ea_indexed(); S.cc = (u8)((S.cc & ~CC_Z) | (S.x == 0 ? CC_Z : 0u)); return S.step_cyc + 4;
    case 0x31: S.y = ea_indexed(); S.cc = (u8)((S.cc & ~CC_Z) | (S.y == 0 ? CC_Z : 0u)); return S.step_cyc + 4;
    case 0x32: S.s = ea_indexed(); S.nmi_armed = 1u; return S.step_cyc + 4;
    case 0x33: S.u = ea_indexed(); return S.step_cyc + 4;

    case 0x34: { /* PSHS */
        u8 m = fetch8();
        int cyc = 5;
        if (m & 0x80u) { push16_s(S.pc); cyc += 2; }
        if (m & 0x40u) { push16_s(S.u);  cyc += 2; }
        if (m & 0x20u) { push16_s(S.y);  cyc += 2; }
        if (m & 0x10u) { push16_s(S.x);  cyc += 2; }
        if (m & 0x08u) { push8_s(S.dp);  cyc += 1; }
        if (m & 0x04u) { push8_s(S.b);   cyc += 1; }
        if (m & 0x02u) { push8_s(S.a);   cyc += 1; }
        if (m & 0x01u) { push8_s(S.cc);  cyc += 1; }
        return cyc;
    }
    case 0x35: { /* PULS */
        u8 m = fetch8();
        int cyc = 5;
        if (m & 0x01u) { S.cc = pull8_s();  cyc += 1; }
        if (m & 0x02u) { S.a  = pull8_s();  cyc += 1; }
        if (m & 0x04u) { S.b  = pull8_s();  cyc += 1; }
        if (m & 0x08u) { S.dp = pull8_s();  cyc += 1; }
        if (m & 0x10u) { S.x  = pull16_s(); cyc += 2; }
        if (m & 0x20u) { S.y  = pull16_s(); cyc += 2; }
        if (m & 0x40u) { S.u  = pull16_s(); cyc += 2; }
        if (m & 0x80u) { S.pc = pull16_s(); cyc += 2; }
        return cyc;
    }
    case 0x36: { /* PSHU */
        u8 m = fetch8();
        int cyc = 5;
        if (m & 0x80u) { push16_u(S.pc); cyc += 2; }
        if (m & 0x40u) { push16_u(S.s);  cyc += 2; }
        if (m & 0x20u) { push16_u(S.y);  cyc += 2; }
        if (m & 0x10u) { push16_u(S.x);  cyc += 2; }
        if (m & 0x08u) { push8_u(S.dp);  cyc += 1; }
        if (m & 0x04u) { push8_u(S.b);   cyc += 1; }
        if (m & 0x02u) { push8_u(S.a);   cyc += 1; }
        if (m & 0x01u) { push8_u(S.cc);  cyc += 1; }
        return cyc;
    }
    case 0x37: { /* PULU */
        u8 m = fetch8();
        int cyc = 5;
        if (m & 0x01u) { S.cc = pull8_u();  cyc += 1; }
        if (m & 0x02u) { S.a  = pull8_u();  cyc += 1; }
        if (m & 0x04u) { S.b  = pull8_u();  cyc += 1; }
        if (m & 0x08u) { S.dp = pull8_u();  cyc += 1; }
        if (m & 0x10u) { S.x  = pull16_u(); cyc += 2; }
        if (m & 0x20u) { S.y  = pull16_u(); cyc += 2; }
        if (m & 0x40u) { S.s  = pull16_u(); S.nmi_armed = 1u; cyc += 2; }
        if (m & 0x80u) { S.pc = pull16_u(); cyc += 2; }
        return cyc;
    }

    case 0x39: S.pc = pull16_s(); return 5;          /* RTS */
    case 0x3A: S.x = (u16)(S.x + S.b); return 3;     /* ABX */
    case 0x3B: { /* RTI */
        S.cc = pull8_s();
        if (S.cc & CC_E) {
            S.a  = pull8_s();
            S.b  = pull8_s();
            S.dp = pull8_s();
            S.x  = pull16_s();
            S.y  = pull16_s();
            S.u  = pull16_s();
            S.pc = pull16_s();
            return 15;
        }
        S.pc = pull16_s();
        return 6;
    }
    case 0x3C: { /* CWAI */
        u8 imm = fetch8();
        S.cc &= imm;
        push_entire_state();
        S.halted_cwai = 1u;
        return 20;
    }
    case 0x3D: { /* MUL */
        u16 prod = (u16)S.a * (u16)S.b;
        set_d(prod);
        S.cc = (u8)((S.cc & ~(CC_Z | CC_C)) | (prod == 0 ? CC_Z : 0u) | ((S.b >> 7) & 1u));
        return 11;
    }
    case 0x3F: /* SWI */
        push_entire_state();
        S.cc |= CC_I | CC_F;
        S.pc = rd16(0xFFFAu);
        return 19;
    }

    /* Group $80..$FF: Immediate / Direct / Indexed / Extended ALU & Load/Store */
    u8 mode = (op >> 4) & 3u;
    u8 sub  = op & 0x0Fu;
    int is_b = (op & 0x40u) != 0;

    if (op == 0x8Du) { /* BSR */
        s8 rel = (s8)fetch8();
        push16_s(S.pc);
        S.pc = (u16)(S.pc + rel);
        return 7;
    }
    if (!is_b && sub == 0x0Du) { /* JSR dir/idx/ext */
        ea = (mode == 1u) ? ea_direct() : (mode == 2u) ? ea_indexed() : fetch16();
        push16_s(S.pc);
        S.pc = ea;
        return S.step_cyc + ((mode == 1u) ? 7 : (mode == 2u) ? 7 : 8);
    }

    /* 16-bit subops: 0x3 (SUBD/ADDD), 0xC (CMPX/LDD), 0xD (STD), 0xE (LDX/LDU), 0xF (STX/STU) */
    if (sub == 0x03u || sub == 0x0Cu || (is_b && sub == 0x0Du) || sub == 0x0Eu || sub == 0x0Fu) {
        int base_c = (mode == 0u) ? 4 : (mode == 1u) ? 6 : (mode == 2u) ? 6 : 7;
        if (sub == 0x0Fu || (is_b && sub == 0x0Du)) {
            ea = (mode == 1u) ? ea_direct() : (mode == 2u) ? ea_indexed() : fetch16();
            u16 val = (sub == 0x0Du) ? get_d() : is_b ? S.u : S.x;
            wr16(ea, val);
            nz16(val);
            return S.step_cyc + base_c - 1;
        }
        v16 = (mode == 0u) ? fetch16()
            : (mode == 1u) ? rd16(ea_direct())
            : (mode == 2u) ? rd16(ea_indexed())
                           : rd16(fetch16());
        if (sub == 0x03u) {
            set_d(is_b ? alu_add16(get_d(), v16) : alu_sub16(get_d(), v16));
            return S.step_cyc + base_c;
        }
        if (sub == 0x0Cu) {
            if (is_b) { set_d(v16); nz16(v16); return S.step_cyc + base_c - 1; }
            (void)alu_sub16(S.x, v16);
            return S.step_cyc + base_c;
        }
        if (is_b) { S.u = v16; nz16(v16); }
        else      { S.x = v16; nz16(v16); }
        return S.step_cyc + base_c - 1;
    }

    /* 8-bit STA / STB (sub == 0x07) */
    if (sub == 0x07u) {
        if (mode == 0u) return 2;
        ea = (mode == 1u) ? ea_direct() : (mode == 2u) ? ea_indexed() : fetch16();
        v8 = is_b ? S.b : S.a;
        bus_write(ea, v8);
        nz8(v8);
        return S.step_cyc + ((mode == 1u) ? 4 : (mode == 2u) ? 4 : 5);
    }

    /* 8-bit Read/ALU ops */
    v8 = (mode == 0u) ? fetch8()
       : (mode == 1u) ? bus_read(ea_direct())
       : (mode == 2u) ? bus_read(ea_indexed())
                      : bus_read(fetch16());
    u8 *acc = is_b ? &S.b : &S.a;
    switch (sub) {
    case 0x0: *acc = alu_sub8(*acc, v8, 0u); break;              /* SUB */
    case 0x1: (void)alu_sub8(*acc, v8, 0u);  break;              /* CMP */
    case 0x2: *acc = alu_sub8(*acc, v8, S.cc & CC_C); break;     /* SBC */
    case 0x4: *acc &= v8; nz8(*acc); break;                      /* AND */
    case 0x5: nz8((u8)(*acc & v8));  break;                      /* BIT */
    case 0x6: *acc = v8;  nz8(*acc); break;                      /* LD  */
    case 0x8: *acc ^= v8; nz8(*acc); break;                      /* EOR */
    case 0x9: *acc = alu_add8(*acc, v8, S.cc & CC_C); break;     /* ADC */
    case 0xA: *acc |= v8; nz8(*acc); break;                      /* OR  */
    case 0xB: *acc = alu_add8(*acc, v8, 0u); break;              /* ADD */
    }
    return S.step_cyc + ((mode == 0u) ? 2 : (mode == 1u) ? 4 : (mode == 2u) ? 4 : 5);
}

/* ---- Phosphor Vector Framebuffer Renderer (270 x 360 BGR555) ---- */
INLINE void blend_px(int x, int y, u32 r5, u32 g5, u32 b5)
{
    if ((unsigned)x >= VEC_W || (unsigned)y >= VEC_H)
        return;
    u16 cur = M->fb[y * VEC_W + x];
    u32 cr = cur & 31u;
    u32 cg = (cur >> 5) & 31u;
    u32 cb = (cur >> 10) & 31u;
    if (r5 > cr) cr = r5;
    if (g5 > cg) cg = g5;
    if (b5 > cb) cb = b5;
    M->fb[y * VEC_W + x] = (u16)(cr | (cg << 5) | (cb << 10));
}

static void rasterize_vectors(u16 *picture)
{
    /* 1. Fast 32-bit SWAR phosphor decay (~37% persistence for authentic CRT trail without ghosting!) */
    u32 *fb32 = (u32 *)M->fb;
    for (int i = 0; i < (VEC_W * VEC_H) / 2; i++) {
        u32 v = fb32[i];
        if (v) {
            /* Divide each 5-bit channel by 4 (>>2): subtle smooth phosphor afterglow */
            fb32[i] = (v >> 2) & 0x1CE71CE7u;
        }
    }

    /* 2. Draw all captured vectors with cool cyan-white Vectrex phosphor intensity & soft halo */
    for (u32 i = 0; i < S.n_vecs; i++) {
        const struct vec_seg *v = &M->vecs[i];
        s32 x0 = ((s32)v->x0 * VEC_W) / ALG_MAX_X;
        s32 y0 = VEC_H - 1 - (((s32)v->y0 * VEC_H) / ALG_MAX_Y);
        s32 x1 = ((s32)v->x1 * VEC_W) / ALG_MAX_X;
        s32 y1 = VEC_H - 1 - (((s32)v->y1 * VEC_H) / ALG_MAX_Y);

        /* Intensity 1..127 -> bright white-cyan core + subtle blue-cyan glow */
        u32 z = (v->z > 127u) ? 127u : v->z;
        u32 lum = 8u + (z * 23u) / 127u;     /* 8..31 */
        u32 cr = (lum > 3u) ? (lum - 2u) : lum;
        u32 cg = lum;
        u32 cb = (lum + 2u > 31u) ? 31u : (lum + 2u);

        u32 hr = cr >> 2;
        u32 hg = (cg * 3u) >> 3;
        u32 hb = cb >> 1;

        if (x0 == x1 && y0 == y1) {
            /* Bright phosphor dot with 4-neighbour bloom */
            blend_px(x0, y0, 31u, 31u, 31u);
            blend_px(x0 - 1, y0, hr + 2u, hg + 3u, hb + 4u);
            blend_px(x0 + 1, y0, hr + 2u, hg + 3u, hb + 4u);
            blend_px(x0, y0 - 1, hr + 2u, hg + 3u, hb + 4u);
            blend_px(x0, y0 + 1, hr + 2u, hg + 3u, hb + 4u);
            continue;
        }

        /* Clip completely off-screen segments */
        if ((x0 < 0 && x1 < 0) || (x0 >= VEC_W && x1 >= VEC_W) ||
            (y0 < 0 && y1 < 0) || (y0 >= VEC_H && y1 >= VEC_H))
            continue;

        s32 dx = x1 - x0; if (dx < 0) dx = -dx;
        s32 dy = y1 - y0; if (dy < 0) dy = -dy;
        s32 sx = (x0 < x1) ? 1 : -1;
        s32 sy = (y0 < y1) ? 1 : -1;
        s32 err = dx - dy;

        int steep = (dy > dx);
        for (int guard = 0; guard < 1024; guard++) {
            blend_px(x0, y0, cr, cg, cb);
            if (steep) {
                blend_px(x0 - 1, y0, hr, hg, hb);
                blend_px(x0 + 1, y0, hr, hg, hb);
            } else {
                blend_px(x0, y0 - 1, hr, hg, hb);
                blend_px(x0, y0 + 1, hr, hg, hb);
            }
            if (x0 == x1 && y0 == y1)
                break;
            s32 e2 = err * 2;
            if (e2 > -dy) { err -= dy; x0 += sx; }
            if (e2 <  dx) { err += dx; y0 += sy; }
        }
    }

    if (picture) {
        u32 *dst32 = (u32 *)picture;
        for (int i = 0; i < (VEC_W * VEC_H) / 2; i++)
            dst32[i] = fb32[i];
    }
}

/* ---- Public Interface ---- */
void vec_set_bios(const u8 *rom, u32 size)
{
    if (rom && (size == 0x2000u || size == 0x1000u)) {
        S.ext_bios = rom;
        S.ext_bios_size = size;
    } else {
        S.ext_bios = 0;
        S.ext_bios_size = 0;
    }
}

static void fmt_vec_info(void)
{
    char *d = S.info;
    const char *t = S.title[0] ? S.title : (S.has_cart ? "Vectrex Cartridge" : (S.ext_bios_size == 0x2000u ? "Mine Storm (Built-in)" : "Vector Storm (Built-in)"));
    for (int i = 0; t[i] && d - S.info < 44; i++)
        *d++ = t[i];
    if (S.has_cart) {
        const char *s1 = " (";
        while (*s1) *d++ = *s1++;
        u32 kb = (S.cart_size + 512u) >> 10;
        if (!kb) kb = 1;
        char nb[16]; int ni = 0; u32 v = kb;
        while (v > 0) { nb[ni++] = (char)('0' + (v % 10u)); v /= 10u; }
        while (ni > 0) *d++ = nb[--ni];
        const char *s2 = S.using_hle_bios ? " KB Vectrex, built-in BIOS)" : " KB Vectrex)";
        while (*s2) *d++ = *s2++;
    }
    *d = 0;
}

const char *vec_load(u8 *image, u32 size)
{
    const u8 *saved_bios = S.ext_bios;
    u32 saved_bios_sz = S.ext_bios_size;
    mem_zero(&S, sizeof(S));
    S.ext_bios = saved_bios;
    S.ext_bios_size = saved_bios_sz;

    if (size == 0u) {
        /* Empty path (""): launch built-in Mine Storm (if 8KB vectrex.rom present) or built-in Vector Storm! */
        S.has_cart = 0;
        S.cart = 0;
        S.cart_size = 0;
    } else {
        if (!image || size < 16u)
            return "too small to be a Vectrex cartridge (under 16 bytes)";
        if (size > 0x10000u)
            return "larger than 64 KB Vectrex cartridge limit";
        /* Every valid Vectrex cartridge starts with "g GCE" at $0000! */
        if (image[0] != 'g' || image[1] != ' ' || image[2] != 'G' || image[3] != 'C' || image[4] != 'E')
            return "not a valid Vectrex cartridge (missing 'g GCE' header)";

        S.has_cart  = 1;
        S.cart      = image;
        S.cart_size = size;

        /* Extract game title from first title entry after copyright + music ptr */
        u32 p = 5u;
        while (p < size && (image[p] & 0x80u) == 0u) p++;
        p += 3u;                         /* past 0x80 + 2-byte music ptr */
        if (p + 5u < size && image[p] != 0u) {
            p += 4u;                     /* skip h, w, y, x */
            int ti = 0;
            while (p < size && (image[p] & 0x80u) == 0u && ti < 36) {
                u8 c = image[p++];
                if (c >= 0x20u && c < 0x7Fu)
                    S.title[ti++] = (char)c;
            }
            while (ti > 0 && S.title[ti - 1] == ' ')
                ti--;
            S.title[ti] = 0;
        }
    }

    vec_reset();
    fmt_vec_info();
    return 0;
}

void vec_reset(void)
{
    mem_zero(M->ram, sizeof(M->ram));
    mem_zero(M->cart_ram, sizeof(M->cart_ram));
    mem_zero(M->fb, sizeof(M->fb));

    build_clean_sysrom();
    if (S.ext_bios && S.ext_bios_size == 0x2000u) {
        mem_copy(M->sysrom, S.ext_bios, 0x2000u);
        S.using_hle_bios = 0;
    } else if (S.ext_bios && S.ext_bios_size == 0x1000u) {
        mem_copy(M->sysrom + 0x1000u, S.ext_bios, 0x1000u);
        S.using_hle_bios = 0;
    } else {
        S.using_hle_bios = 1;
    }

    S.builtin_game = 0;
    S.cart_bank = (S.cart_size > 0x8000u) ? 1u : 0u;

    S.a = S.b = S.dp = 0;
    S.x = S.y = S.u = S.s = 0;
    S.cc = CC_I | CC_F;
    S.halted_sync = S.halted_cwai = S.jammed = 0;
    S.nmi_armed = S.nmi_pend = S.firq_pend = 0;
    S.hle_in_frame = S.hle_end_frame = 0;
    S.cyc_carry = 0;

    S.ora = S.orb = S.ddra = S.ddrb = 0;
    S.t1c = S.t2c = 0xFFFFu;
    S.t1l_l = S.t1l_h = S.t2l_l = 0;
    S.t1_running = S.t2_running = 0;
    S.t1pb7 = 1u;
    S.sr = 0; S.srb = 8u; S.sr_clk = 1u;
    S.acr = S.pcr = S.ifr = S.ier = 0;
    S.ca2 = 1u; S.cb2 = 0u;

    S.dac_x = S.alg_ysh = S.alg_xsh = S.alg_ash = 0;
    S.alg_zsh = 0;
    S.alg_x = ALG_CENTER_X;
    S.alg_y = ALG_CENTER_Y;
    S.alg_vectoring = 0;
    S.n_vecs = 0;

    S.psg_latch = 0;
    mem_zero(S.psg_reg, sizeof(S.psg_reg));
    S.psg_reg[7] = 0x3Fu;
    S.psg_lfsr = 0x1FFFFu;
    S.btn_mask = 0xFFu;

    S.pc = rd16(0xFFFEu);
}

void vec_frame(u16 pad, u16 *picture)
{
    S.pad = pad;

    /* Map digital D-pad to Vectrex analog pot (-120, 0, +120) + 4 active-low buttons */
    S.joy_pot[0] = (pad & VEC_PAD_LEFT) ? -120 : (pad & VEC_PAD_RIGHT) ? 120 : 0;
    S.joy_pot[1] = (pad & VEC_PAD_DOWN) ? -120 : (pad & VEC_PAD_UP)    ? 120 : 0;
    S.joy_pot[2] = 0;
    S.joy_pot[3] = 0;

    u8 btns = 0xFFu;
    if (pad & (VEC_PAD_START | VEC_PAD_X | VEC_PAD_L)) btns &= (u8)~0x01u; /* Button 1 */
    if (pad & (VEC_PAD_SELECT | VEC_PAD_Y))            btns &= (u8)~0x02u; /* Button 2 */
    if (pad & VEC_PAD_B)                               btns &= (u8)~0x04u; /* Button 3 */
    if (pad & (VEC_PAD_A | VEC_PAD_R))                 btns &= (u8)~0x08u; /* Button 4 */
    S.btn_mask = btns;

    flush_active_vec();
    S.n_vecs = 0;

    if (S.builtin_game) {
        vs_step_frame();
        rasterize_vectors(picture);
        return;
    }

    int rem = FRAME_CYC;
    if (S.cyc_carry > 0) {
        int c0 = (S.cyc_carry < rem) ? S.cyc_carry : rem;
        via_step(c0);
        audio_step(c0);
        S.cyc_carry -= c0;
        rem -= c0;
    }
    while (rem > 0 && !S.jammed) {
        int cyc = step_6809();
        if (S.builtin_game) {
            vs_step_frame();
            break;
        }
        if (S.hle_end_frame) {
            S.hle_end_frame = 0u;
            audio_step(rem);
            S.cyc_carry = 0;
            break;
        }
        if (cyc <= rem) {
            via_step(cyc);
            audio_step(cyc);
            rem -= cyc;
        } else {
            via_step(rem);
            audio_step(rem);
            S.cyc_carry = cyc - rem;
            rem = 0;
        }
    }
    flush_active_vec();
    rasterize_vectors(picture);
}

const char *vec_info(void)
{
    return S.info;
}

u8 *vec_save_ram(u32 *size, int *battery)
{
    *size = 0;
    *battery = 0;
    return M->cart_ram;
}

int vec_save_changed(void)
{
    return 0;
}

int vec_jammed(void)
{
    return S.jammed;
}

void vec_audio_rate(u32 hz)
{
    S.snd_rate = hz;
    S.snd_phase = S.psg_sub = 0;
    S.snd_rd = S.snd_wr = 0;
    S.dc_est = 0;
}

int vec_audio(s16 *out, int max)
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
