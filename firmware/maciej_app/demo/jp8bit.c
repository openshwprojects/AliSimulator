/* Japanese 8-Bit Home Computer Legends ('pc88', 'mz700', 'x1'): see jp8bit.h.
   Pass-optimized for 594 MHz MIPS32:
   - Zero static .bss (all RAM, GVRAM, PCG, D88 disk images, YM2203 FM tables & audio in EMU_RAM_PHYS)
   - Fast 64-entry 1 KB Z80 page maps for PC-88, MZ-700, and Sharp X1
   - Full integer Yamaha YM2203 OPN (3-ch 4-operator FM + 3-ch SSG) + 8253 PIT + 2 MHz AY-3-8910 @ 48 kHz
   - Clean-room N88 Disk Sub-CPU HLE ($37CC/$37D2/$3847), Sharp 1Z-009A Monitor & CGROM, and X1 IPL */
#pragma GCC optimize("O2")
#include "jp8bit.h"
#include "z80.h"

#ifndef JP8BIT_HOST
#include "hw.h"
#endif

enum {
    SYS_PC88 = 0,
    SYS_MZ700,
    SYS_X1
};

#define SND_RING 4096
#define DSK_MAX  0x80000u       /* Up to 512 KB D88 / 2D floppy image */

/* Yamaha YM2203 4-operator FM state */
struct opn_op {
    u32 phase, inc;
    s32 env;                    /* 0 (max) .. 1023 (silent) */
    u8  state;                  /* 0=OFF, 1=ATT, 2=DEC, 3=SUS, 4=REL */
    u8  dt, mul, tl, ks, ar, dr, sr, sl, rr;
};

struct opn_ch {
    struct opn_op op[4];
    u16 fnum;
    u8  block, fnum_hi_latch;
    u8  fb, alg;
    s32 fb_buf[2];
};

struct jp8bit_ws {
    u8  sys;                    /* SYS_PC88, SYS_MZ700, SYS_X1 */
    u8  basic_mode;
    u8  has_prog, has_dsk;
    u16 prog_load, prog_exec, prog_size;
    u32 dsk_size;
    u32 frames;

    struct z80 cpu;

    /* Main memory + ROM + Video RAM */
    u8  ram[0x10000];           /* 64 KB Main Z80 RAM */
    u8  rom[0x10000];           /* N88 ROM (32K) / MZ-700 1Z-009A (4K) + CGROM (4K) / X1 IPL (4K) + ANK (2K) */
    u8  gvram[3][0x4000];       /* 3 x 16 KB Blue/Red/Green GVRAM (PC-88 & Sharp X1) */
    u8  tvram[0x1000];          /* Text VRAM (X1 $3000..$37FF / MZ-700 $D000..$D3FF) */
    u8  avram[0x1000];          /* Attr VRAM (X1 $2000..$27FF / MZ-700 $D800..$DBFF) */
    u8  pcg[3][256][8];         /* Sharp X1 256-char x 3-plane Programmable Character Generator */

    /* PC-88 banking, ALU, palette & Disk Sub-CPU HLE */
    u8  p88_port31, p88_port32, p88_port40, p88_port5x;
    u8  p88_pal[8];             /* Digital/analog palette indices -> RGB555 */
    u16 p88_pal15[8];
    u8  p88_irq_en, p88_vrtc, p88_beep;
    u32 p88_beep_toggles, p88_beep_ph;
    u8  p88_keys[16], p88_usb[16];
    u8  sub_cmd, sub_arg_n, sub_args[8], sub_stat_pend;
    u32 sub_rpos, sub_rlen;
    u8  sub_rbuf[0x4000];       /* Up to 64 sectors queued per Sub-CPU read */

    /* MZ-700 banking ($E000..$E006), 8255 PPI & 8253 PIT */
    u8  mz_lo_ram;              /* 0 = Monitor ROM at $0000..$0FFF, 1 = RAM */
    u8  mz_hi_mode;             /* 0 = VRAM/MMIO at $D000..$FFFF, 1 = RAM, 2 = Inhibit */
    u8  mz_key_row, mz_vblk, mz_intmsk, mz_gate;
    u8  mz_keys[10], mz_usb[10];
    u16 pit_reload[3], pit_cnt[3];
    u8  pit_mode[3], pit_lsb_st[3], pit_msb_pend[3], pit_lsb_latch[3];
    u32 pit0_ph;

    /* Sharp X1 I/O state */
    u8  x1_rom_en;              /* $1E00 reset / $1FD0 set */
    u8  x1_crtc_sel, x1_crtc[18];
    u8  x1_pal[3];              /* $1000=B, $1100=R, $1200=G */
    u8  x1_prio;                /* $1300 */
    u8  x1_pcg_latch;           /* Last char written to $3000..$37FF */
    u8  x1_vblank;
    u8  x1_sub_q[8], x1_sub_r, x1_sub_w;
    u8  x1_last_ascii;

    /* YM2203 OPN (PC-88) + AY-3-8910 / SSG (PC-88 & X1) */
    u8  ym_sel, ym_regs[256];
    struct opn_ch fm[3];
    u32 fm_eg_cnt;
    u16 sin_tab[1024];          /* Quarter-sine / full-sine LUT (-4095..+4095) */
    u32 ssg_cnt[3], ssg_ncnt, ssg_lfsr, ssg_ecnt;
    u8  ssg_out[3], ssg_estep, ssg_evol, ssg_ehold, ssg_ealt;

    /* Shared input, disk buffer & interactive BASIC/Monitor */
    u16 pad;
    char type_q[64];
    u8  type_r, type_w, type_hold;
    char type_ch;
    u8  bas_x, bas_y, bas_len;
    char bas_line[48];

    u8  dsk[DSK_MAX];           /* D88 / 2D / MZT raw image backup */

    /* 48 kHz Audio Ring */
    u32 sample_rate, snd_frac, chip_frac;
    u32 snd_head, snd_tail;
    s16 snd_ring[SND_RING];

    char title[32];
    char info[96];
};

#ifdef JP8BIT_HOST
static struct jp8bit_ws jp8bit_host_ws;
#define WS (&jp8bit_host_ws)
#else
#define WS ((struct jp8bit_ws *)KSEG0(EMU_RAM_PHYS))
#ifndef JP8BIT_NO_ASSERT
_Static_assert(sizeof(struct jp8bit_ws) <= EMU_RAM_SIZE, "jp8bit_ws exceeds EMU_RAM_SIZE");
#endif
#endif

#define INLINE static inline __attribute__((always_inline))
#define RGB15(r, g, b) ((u16)((((b) >> 3) << 10) | (((g) >> 3) << 5) | ((r) >> 3)))

static void ws_zero(void *p, u32 n)
{
    u8 *b = (u8 *)p;
    for (u32 i = 0; i < n; i++)
        b[i] = 0;
}

static int ci_ends(const char *s, const char *ext)
{
    if (!s) return 0;
    int sl = 0, el = 0;
    while (s[sl]) sl++;
    while (ext[el]) el++;
    if (sl < el) return 0;
    for (int i = 0; i < el; i++)
        if ((s[sl - el + i] | 32) != (ext[i] | 32)) return 0;
    return 1;
}

/* Digital 8-color BRG/GRB tables */
static const u16 digital_brg15[8] = {
    RGB15(  0,   0,   0), /* 0: Black   */
    RGB15(  0,   0, 255), /* 1: Blue    */
    RGB15(255,   0,   0), /* 2: Red     */
    RGB15(255,   0, 255), /* 3: Magenta */
    RGB15(  0, 255,   0), /* 4: Green   */
    RGB15(  0, 255, 255), /* 5: Cyan    */
    RGB15(255, 255,   0), /* 6: Yellow  */
    RGB15(255, 255, 255)  /* 7: White   */
};

/* MZ-700 3-bit GRB palette (b2=Green, b1=Red, b0=Blue) */
static const u16 mz_grb15[8] = {
    RGB15(  0,   0,   0), /* 0: Black   */
    RGB15(  0,   0, 255), /* 1: Blue    */
    RGB15(255,   0,   0), /* 2: Red     */
    RGB15(255,   0, 255), /* 3: Magenta */
    RGB15(  0, 255,   0), /* 4: Green   */
    RGB15(  0, 255, 255), /* 5: Cyan    */
    RGB15(255, 255,   0), /* 6: Yellow  */
    RGB15(255, 255, 255)  /* 7: White   */
};

/* Clean-room 5x7 ASCII font (0x20..0x7F) */
static const u8 font5x7[96][5] = {
    {0x00,0x00,0x00,0x00,0x00},{0x00,0x00,0x5F,0x00,0x00},{0x00,0x07,0x00,0x07,0x00},{0x14,0x7F,0x14,0x7F,0x14},
    {0x24,0x2A,0x7F,0x2A,0x12},{0x23,0x13,0x08,0x64,0x62},{0x36,0x49,0x55,0x22,0x50},{0x00,0x05,0x03,0x00,0x00},
    {0x00,0x1C,0x22,0x41,0x00},{0x00,0x41,0x22,0x1C,0x00},{0x14,0x08,0x3E,0x08,0x14},{0x08,0x08,0x3E,0x08,0x08},
    {0x00,0x50,0x30,0x00,0x00},{0x08,0x08,0x08,0x08,0x08},{0x00,0x60,0x60,0x00,0x00},{0x20,0x10,0x08,0x04,0x02},
    {0x3E,0x51,0x49,0x45,0x3E},{0x00,0x42,0x7F,0x40,0x00},{0x42,0x61,0x51,0x49,0x46},{0x21,0x41,0x45,0x4B,0x31},
    {0x18,0x14,0x12,0x7F,0x10},{0x27,0x45,0x45,0x45,0x39},{0x3C,0x4A,0x49,0x49,0x30},{0x01,0x71,0x09,0x05,0x03},
    {0x36,0x49,0x49,0x49,0x36},{0x06,0x49,0x49,0x29,0x1E},{0x00,0x36,0x36,0x00,0x00},{0x00,0x56,0x36,0x00,0x00},
    {0x08,0x14,0x22,0x41,0x00},{0x14,0x14,0x14,0x14,0x14},{0x00,0x41,0x22,0x14,0x08},{0x02,0x01,0x51,0x09,0x06},
    {0x32,0x49,0x79,0x41,0x3E},{0x7E,0x11,0x11,0x11,0x7E},{0x7F,0x49,0x49,0x49,0x36},{0x3E,0x41,0x41,0x41,0x22},
    {0x7F,0x41,0x41,0x22,0x1C},{0x7F,0x49,0x49,0x49,0x41},{0x7F,0x09,0x09,0x09,0x01},{0x3E,0x41,0x49,0x49,0x7A},
    {0x7F,0x08,0x08,0x08,0x7F},{0x00,0x41,0x7F,0x41,0x00},{0x20,0x40,0x41,0x3F,0x01},{0x7F,0x08,0x14,0x22,0x41},
    {0x7F,0x40,0x40,0x40,0x40},{0x7F,0x02,0x0C,0x02,0x7F},{0x7F,0x04,0x08,0x10,0x7F},{0x3E,0x41,0x41,0x41,0x3E},
    {0x7F,0x09,0x09,0x09,0x06},{0x3E,0x41,0x51,0x21,0x5E},{0x7F,0x09,0x19,0x29,0x46},{0x46,0x49,0x49,0x49,0x31},
    {0x01,0x01,0x7F,0x01,0x01},{0x3F,0x40,0x40,0x40,0x3F},{0x1F,0x20,0x40,0x20,0x1F},{0x3F,0x40,0x38,0x40,0x3F},
    {0x63,0x14,0x08,0x14,0x63},{0x07,0x08,0x70,0x08,0x07},{0x61,0x51,0x49,0x45,0x43},{0x00,0x7F,0x41,0x41,0x00},
    {0x02,0x04,0x08,0x10,0x20},{0x00,0x41,0x41,0x7F,0x00},{0x04,0x02,0x01,0x02,0x04},{0x40,0x40,0x40,0x40,0x40},
    {0x00,0x01,0x02,0x04,0x00},{0x20,0x54,0x54,0x54,0x78},{0x7F,0x48,0x44,0x44,0x38},{0x38,0x44,0x44,0x44,0x20},
    {0x38,0x44,0x44,0x48,0x7F},{0x38,0x54,0x54,0x54,0x18},{0x08,0x7E,0x09,0x01,0x02},{0x0C,0x52,0x52,0x52,0x3E},
    {0x7F,0x08,0x04,0x04,0x78},{0x00,0x44,0x7D,0x40,0x00},{0x20,0x40,0x44,0x3D,0x00},{0x7F,0x10,0x28,0x44,0x00},
    {0x00,0x41,0x7F,0x40,0x00},{0x7C,0x04,0x18,0x04,0x78},{0x7C,0x08,0x04,0x04,0x78},{0x38,0x44,0x44,0x44,0x38},
    {0x7C,0x14,0x14,0x14,0x08},{0x08,0x14,0x14,0x18,0x7C},{0x7C,0x08,0x04,0x04,0x08},{0x48,0x54,0x54,0x54,0x20},
    {0x04,0x3F,0x44,0x40,0x20},{0x3C,0x40,0x40,0x20,0x7C},{0x1C,0x20,0x40,0x20,0x1C},{0x3C,0x40,0x30,0x40,0x3C},
    {0x44,0x28,0x10,0x28,0x44},{0x0C,0x50,0x50,0x50,0x3C},{0x44,0x64,0x54,0x4C,0x44},{0x00,0x08,0x36,0x41,0x00},
    {0x00,0x00,0x7F,0x00,0x00},{0x00,0x41,0x36,0x08,0x00},{0x10,0x08,0x08,0x10,0x08},{0x7F,0x7F,0x7F,0x7F,0x7F}
};

enum {
    PAD_A      = 0x001, /* X: Fire 1 / Space */
    PAD_B      = 0x002, /* Z: Fire 2 / Shift / GRPH */
    PAD_SELECT = 0x004,
    PAD_START  = 0x008, /* Enter: Return */
    PAD_UP     = 0x010,
    PAD_DOWN   = 0x020,
    PAD_LEFT   = 0x040,
    PAD_RIGHT  = 0x080
};

/* ============================================================================
 * D88 FLOPPY PARSER (Shared by NEC PC-8801 & Sharp X1)
 * ============================================================================ */

static int d88_read_sector(u32 trk, u8 r_want, u8 dst[256], u16 *nsec_out)
{
    if (!WS->has_dsk || WS->dsk_size < 0x2B0u || trk >= 164u)
        return 0;

    /* Raw .2d (320 KB = 80 tracks * 16 sectors * 256 B) */
    if (WS->dsk_size == 327680u && WS->dsk[0x20] != 0xB0u && WS->dsk[0x21] != 0x02u) {
        if (r_want < 1u || r_want > 16u) return 0;
        u32 off = (trk * 16u + (r_want - 1u)) * 256u;
        if (off + 256u > WS->dsk_size) return 0;
        for (int i = 0; i < 256; i++) dst[i] = WS->dsk[off + i];
        if (nsec_out) *nsec_out = 16u;
        return 1;
    }

    u32 toff_pos = 0x20u + trk * 4u;
    u32 cur = (u32)WS->dsk[toff_pos] | ((u32)WS->dsk[toff_pos + 1] << 8) |
              ((u32)WS->dsk[toff_pos + 2] << 16) | ((u32)WS->dsk[toff_pos + 3] << 24);
    if (!cur || cur + 16u > WS->dsk_size)
        return 0;

    u16 nsec = (u16)(WS->dsk[cur + 4] | ((u16)WS->dsk[cur + 5] << 8));
    if (nsec_out) *nsec_out = nsec;
    if (!nsec || nsec > 64u) nsec = 32u;

    for (u16 s = 0; s < nsec && cur + 16u <= WS->dsk_size; s++) {
        u8 r = WS->dsk[cur + 2];
        u16 ssz = (u16)(WS->dsk[cur + 14] | ((u16)WS->dsk[cur + 15] << 8));
        if (!ssz || cur + 16u + ssz > WS->dsk_size)
            break;
        if (r == r_want) {
            u32 cp = ssz < 256u ? ssz : 256u;
            for (u32 i = 0; i < cp; i++) dst[i] = WS->dsk[cur + 16u + i];
            for (u32 i = cp; i < 256u; i++) dst[i] = 0;
            return 1;
        }
        cur += 16u + ssz;
    }
    return 0;
}

/* ============================================================================
 * YAMAHA YM2203 OPN (3-Ch 4-Op FM + 3-Ch SSG) + AY-3-8910 @ 48 kHz
 * ============================================================================ */

static const s16 ssg_vol_lut[16] = {
       0,   72,  102,  144,  204,  288,  408,  577,
     816, 1154, 1632, 2308, 3264, 4616, 6528, 8600
};

static void init_fm_tables(void)
{
    /* Bhaskara I pure-integer sine approximation: sin(x) ~= 16x(pi-x) / (5*pi^2 - 4x(pi-x)) */
    for (int i = 0; i < 512; i++) {
        u32 x = (u32)i;
        u32 p = x * (512u - x);
        u32 num = 16u * p * 4095u;
        u32 den = 5u * 512u * 512u - 4u * p;
        s16 s = (s16)(num / den);
        WS->sin_tab[i]       = s;
        WS->sin_tab[512 + i] = (s16)-s;
    }
}

static void ym_recalc_ch(int ch)
{
    struct opn_ch *c = &WS->fm[ch];
    u32 sr = WS->sample_rate ? WS->sample_rate : 48000u;
    /* YM2203 @ 3.9936 MHz: FM native rate = 3,993,600 / 72 = 55,467 Hz.
       20-bit phase increment per sample = ((fnum << block) >> 1) * 55467 / sr */
    u32 base_inc = ((u32)c->fnum << c->block) >> 1;
    u32 sr10 = (sr >= 100u) ? (sr / 10u) : 4800u;
    base_inc = (base_inc * 5547u) / sr10;

    static const signed char dt_off[8] = { 0, 1, 2, 3, 0, -1, -2, -3 };
    for (int o = 0; o < 4; o++) {
        struct opn_op *op = &c->op[o];
        s32 inc = (s32)base_inc + (s32)dt_off[op->dt & 7u] * 4;
        if (inc < 0) inc = 0;
        u32 mul = op->mul;
        op->inc = mul ? ((u32)inc * mul) : ((u32)inc >> 1);
    }
}

static void ym_write(u8 r, u8 v)
{
    WS->ym_regs[r] = v;
    if (r == 13u) {
        WS->ssg_ecnt = 0;
        WS->ssg_estep = 0;
        WS->ssg_ehold = 0;
        WS->ssg_ealt = (v & 4u) ? 0u : 15u;
        WS->ssg_evol = WS->ssg_ealt;
        return;
    }
    if (r == 0x28u) {
        u8 ch = v & 3u;
        if (ch < 3u) {
            /* OPN slot order: bit4=S1(op0), bit5=S2(op2), bit6=S3(op1), bit7=S4(op3) */
            static const u8 slot_to_op[4] = { 0, 2, 1, 3 };
            for (int s = 0; s < 4; s++) {
                struct opn_op *op = &WS->fm[ch].op[slot_to_op[s]];
                if (v & (0x10u << s)) {
                    if (op->state == 0u || op->state == 4u) {
                        op->phase = 0;
                        op->state = 1u;
                        if (op->ar >= 30u) { op->env = 0; op->state = 2u; }
                    }
                } else if (op->state != 0u) {
                    op->state = 4u;
                }
            }
        }
        return;
    }
    if (r >= 0x30u && r < 0xA0u) {
        u8 ch = r & 3u;
        if (ch >= 3u) return;
        static const u8 reg_to_op[4] = { 0, 2, 1, 3 };
        u8 o = reg_to_op[(r >> 2) & 3u];
        struct opn_op *op = &WS->fm[ch].op[o];
        switch (r & 0xF0u) {
        case 0x30u: op->dt = (v >> 4) & 7u; op->mul = v & 0x0Fu; ym_recalc_ch(ch); break;
        case 0x40u: op->tl = v & 0x7Fu; break;
        case 0x50u: op->ks = (v >> 6) & 3u; op->ar = v & 0x1Fu; break;
        case 0x60u: op->dr = v & 0x1Fu; break;
        case 0x70u: op->sr = v & 0x1Fu; break;
        case 0x80u: op->sl = (v >> 4) & 0x0Fu; if (op->sl == 15u) op->sl = 31u; op->rr = v & 0x0Fu; break;
        }
        return;
    }
    if (r >= 0xA4u && r <= 0xA6u) {
        WS->fm[r - 0xA4u].fnum_hi_latch = v & 0x3Fu;
        return;
    }
    if (r >= 0xA0u && r <= 0xA2u) {
        u8 ch = r - 0xA0u;
        u8 hi = WS->fm[ch].fnum_hi_latch;
        WS->fm[ch].fnum  = (u16)(((u16)(hi & 7u) << 8) | v);
        WS->fm[ch].block = (hi >> 3) & 7u;
        ym_recalc_ch(ch);
        return;
    }
    if (r >= 0xB0u && r <= 0xB2u) {
        u8 ch = r - 0xB0u;
        WS->fm[ch].fb  = (v >> 3) & 7u;
        WS->fm[ch].alg = v & 7u;
    }
}

INLINE s32 eval_fm_op(struct opn_op *op, s32 mod)
{
    if (op->state == 0u) return 0;
    u32 idx = ((op->phase >> 10) + (u32)(mod >> 2)) & 0x3FFu;
    op->phase = (op->phase + op->inc) & 0xFFFFFu;
    s32 att = op->env + ((s32)op->tl << 3);
    if (att >= 1020) return 0;
    s32 s = (s16)WS->sin_tab[idx];
    /* Attenuate by 2^(-att/128): shift by (att >> 7), linear fine scale by (128 - (att & 127)) */
    s = (s * (128 - (att & 127))) >> 7;
    return s >> (att >> 7);
}

static void step_ssg_and_fm_sample(u32 ssg_div_hz, int with_fm)
{
    u32 sr = WS->sample_rate ? WS->sample_rate : 48000u;
    WS->chip_frac += ssg_div_hz;
    s32 ssg_acc = 0, ticks = 0;

    while (WS->chip_frac >= sr) {
        WS->chip_frac -= sr;
        ticks++;
        for (int c = 0; c < 3; c++) {
            u32 per = ((u32)(WS->ym_regs[c * 2 + 1] & 0x0Fu) << 8) | WS->ym_regs[c * 2];
            if (!per) per = 1u;
            if (++WS->ssg_cnt[c] >= per) {
                WS->ssg_cnt[c] = 0;
                WS->ssg_out[c] ^= 1u;
            }
        }
        u32 nper = (u32)(WS->ym_regs[6] & 0x1Fu) * 2u;
        if (!nper) nper = 2u;
        if (++WS->ssg_ncnt >= nper) {
            WS->ssg_ncnt = 0;
            u32 fb = ((WS->ssg_lfsr ^ (WS->ssg_lfsr >> 3)) & 1u);
            WS->ssg_lfsr = (WS->ssg_lfsr >> 1) | (fb << 16);
        }
        u32 eper = (((u32)WS->ym_regs[12] << 8) | WS->ym_regs[11]) * 2u;
        if (!eper) eper = 2u;
        if (!WS->ssg_ehold && ++WS->ssg_ecnt >= eper) {
            WS->ssg_ecnt = 0;
            if (++WS->ssg_estep >= 16u) {
                u8 sh = WS->ym_regs[13] & 0x0Fu;
                if (!(sh & 8u)) { WS->ssg_evol = 0; WS->ssg_ehold = 1; }
                else if (sh & 1u) { WS->ssg_evol = (sh & 2u) ? (WS->ssg_ealt ^ 15u) : WS->ssg_ealt; WS->ssg_ehold = 1; }
                else { if (sh & 2u) WS->ssg_ealt ^= 15u; WS->ssg_estep = 0; }
            }
            if (!WS->ssg_ehold)
                WS->ssg_evol = (u8)((WS->ssg_estep & 15u) ^ WS->ssg_ealt);
        }

        u8 mix = WS->ym_regs[7];
        u8 nb  = (u8)(WS->ssg_lfsr & 1u);
        s32 s = 0;
        for (int c = 0; c < 3; c++) {
            int tok = ((mix >> c) & 1u) | WS->ssg_out[c];
            int nok = ((mix >> (c + 3)) & 1u) | nb;
            u8 vr = WS->ym_regs[8 + c];
            u8 vol = (vr & 0x10u) ? WS->ssg_evol : (vr & 0x0Fu);
            if (tok && nok) s += ssg_vol_lut[vol & 15u];
        }
        ssg_acc += s - 4200;
    }

    s32 out = ticks ? (ssg_acc / ticks) : 0;

    if (with_fm) {
        int do_eg = ((++WS->fm_eg_cnt & 15u) == 0u);
        s32 fm_sum = 0;
        for (int ch = 0; ch < 3; ch++) {
            struct opn_ch *c = &WS->fm[ch];
            if (do_eg) {
                for (int o = 0; o < 4; o++) {
                    struct opn_op *op = &c->op[o];
                    if (op->state == 1u) {
                        op->env -= (s32)(op->ar * 3u + 2u);
                        if (op->env <= 0) { op->env = 0; op->state = 2u; }
                    } else if (op->state == 2u) {
                        s32 sl_lv = (s32)op->sl << 5;
                        op->env += (s32)(op->dr);
                        if (op->env >= sl_lv) { op->env = sl_lv; op->state = 3u; }
                    } else if (op->state == 3u) {
                        op->env += (s32)(op->sr >> 1);
                        if (op->env >= 1023) { op->env = 1023; op->state = 0u; }
                    } else if (op->state == 4u) {
                        op->env += (s32)(op->rr * 4u + 2u);
                        if (op->env >= 1023) { op->env = 1023; op->state = 0u; }
                    }
                }
            }
            s32 fb_mod = c->fb ? ((c->fb_buf[0] + c->fb_buf[1]) >> (9 - c->fb)) : 0;
            s32 o0 = eval_fm_op(&c->op[0], fb_mod);
            c->fb_buf[1] = c->fb_buf[0];
            c->fb_buf[0] = o0;
            s32 o1, o2, o3, mix = 0;
            switch (c->alg & 7u) {
            case 0: o1 = eval_fm_op(&c->op[1], o0); o2 = eval_fm_op(&c->op[2], o1); mix = eval_fm_op(&c->op[3], o2); break;
            case 1: o1 = eval_fm_op(&c->op[1], 0);  o2 = eval_fm_op(&c->op[2], o0 + o1); mix = eval_fm_op(&c->op[3], o2); break;
            case 2: o1 = eval_fm_op(&c->op[1], 0);  o2 = eval_fm_op(&c->op[2], o1); mix = eval_fm_op(&c->op[3], o0 + o2); break;
            case 3: o1 = eval_fm_op(&c->op[1], o0); o2 = eval_fm_op(&c->op[2], 0);  mix = eval_fm_op(&c->op[3], o1 + o2); break;
            case 4: o1 = eval_fm_op(&c->op[1], o0); o2 = eval_fm_op(&c->op[2], 0);  o3 = eval_fm_op(&c->op[3], o2); mix = (o1 + o3) >> 1; break;
            case 5: o1 = eval_fm_op(&c->op[1], o0); o2 = eval_fm_op(&c->op[2], o0); o3 = eval_fm_op(&c->op[3], o0); mix = (o1 + o2 + o3) / 3; break;
            case 6: o1 = eval_fm_op(&c->op[1], o0); o2 = eval_fm_op(&c->op[2], 0);  o3 = eval_fm_op(&c->op[3], 0);  mix = (o1 + o2 + o3) / 3; break;
            default:o1 = eval_fm_op(&c->op[1], 0);  o2 = eval_fm_op(&c->op[2], 0);  o3 = eval_fm_op(&c->op[3], 0);  mix = (o0 + o1 + o2 + o3) >> 2; break;
            }
            fm_sum += mix * 2;
        }
        out += fm_sum;
    }

    if (out > 32767) out = 32767;
    if (out < -32768) out = -32768;
    u32 nxt = (WS->snd_head + 1u) & (SND_RING - 1u);
    if (nxt != WS->snd_tail) {
        WS->snd_ring[WS->snd_head] = (s16)out;
        WS->snd_head = nxt;
    }
}

/* ============================================================================
 * SYSTEM 1: NEC PC-8801mkIISR ('pc88')
 * ============================================================================ */

static void p88_sync_mmu(void)
{
    int ram_mode = (WS->p88_port31 & 0x02u) != 0;
    for (int i = 0; i < 32; i++) {
        WS->cpu.rd[i] = ram_mode ? (WS->ram + i * 0x400) : (WS->rom + i * 0x400);
        WS->cpu.wr[i] = WS->ram + i * 0x400;
    }
    for (int i = 32; i < 48; i++) {
        WS->cpu.rd[i] = WS->ram + i * 0x400;
        WS->cpu.wr[i] = WS->ram + i * 0x400;
    }
    u8 *hi = (WS->p88_port5x < 3u) ? WS->gvram[WS->p88_port5x] : (WS->ram + 0xC000u);
    for (int i = 0; i < 16; i++) {
        WS->cpu.rd[48 + i] = hi + i * 0x400;
        WS->cpu.wr[48 + i] = hi + i * 0x400;
    }
}

static u8 p88_zread(struct z80 *c, u16 a)
{
    const u8 *p = c->rd[a >> 10];
    return p ? p[a & 0x3FFu] : WS->ram[a];
}

static void p88_zwrite(struct z80 *c, u16 a, u8 v)
{
    u8 *p = c->wr[a >> 10];
    if (p) p[a & 0x3FFu] = v;
}

static u8 p88_zin(struct z80 *c, u16 port)
{
    (void)c;
    u8 p = (u8)(port & 0xFFu);
    if (p < 0x10u) return WS->p88_keys[p];
    if (p == 0x31u) return 0xB9u;       /* Bit 7 = 1 -> direct CPU GVRAM mode ($5C..$5E) + YM2203 OPN */
    if (p == 0x32u) return WS->p88_port32;
    if (p == 0x40u) return (u8)((WS->p88_vrtc ? 0x20u : 0x00u) | 0x02u); /* b5=VRTC, b1=24kHz monitor */
    if (p == 0x44u) return 0x00u;       /* YM2203 status: bit 7 = 0 (ready) */
    if (p == 0x45u) {
        if (WS->ym_sel == 14u) {
            u8 j = 0xFFu;
            if (WS->pad & PAD_UP)    j &= (u8)~0x01u;
            if (WS->pad & PAD_DOWN)  j &= (u8)~0x02u;
            if (WS->pad & PAD_LEFT)  j &= (u8)~0x04u;
            if (WS->pad & PAD_RIGHT) j &= (u8)~0x08u;
            return j;
        }
        if (WS->ym_sel == 15u) {
            u8 j = 0xFFu;
            if (WS->pad & (PAD_A | PAD_SELECT)) j &= (u8)~0x01u;
            if (WS->pad & (PAD_B | PAD_START))  j &= (u8)~0x02u;
            return j;
        }
        return WS->ym_regs[WS->ym_sel];
    }
    if (p == 0xFDu) {
        if (WS->sub_stat_pend) {
            WS->sub_stat_pend = 0;
            return 0x00u;
        }
        return (WS->sub_rpos < WS->sub_rlen) ? WS->sub_rbuf[WS->sub_rpos++] : 0x00u;
    }
    return 0xFFu;
}

static void p88_zout(struct z80 *c, u16 port, u8 v)
{
    (void)c;
    u8 p = (u8)(port & 0xFFu);
    if (p == 0x31u) {
        WS->p88_port31 = v;
        p88_sync_mmu();
        return;
    }
    if (p == 0x32u) { WS->p88_port32 = v; return; }
    if (p >= 0x54u && p <= 0x5Bu) {
        int idx = p - 0x54u;
        if (WS->p88_port32 & 0x80u) {
            /* Analog 9-bit GRB palette: bits 5..3=Red, bits 2..0=Blue, bits 7..6? Standard PC-88SR:
               b5..3=Red(0..7)? Actually PC-88 analog port $54..$5B: b5..3=R, b2..0=B, b7..6/G: if (v & 0x40) G hi!
               Even simpler: if v < 8 (digital color code 0..7), use digital_brg15[v & 7]; else 3-3-3 GRB (G=b7..6, R=b5..3, B=b2..0)! */
            if ((v & 0xF8u) == 0u) {
                WS->p88_pal15[idx] = digital_brg15[v & 7u];
            } else {
                u32 r = ((v >> 3) & 7u) * 36u;
                u32 b = (v & 7u) * 36u;
                u32 g = ((v >> 6) & 3u) * 85u;
                WS->p88_pal15[idx] = RGB15(r, g, b);
            }
        } else {
            WS->p88_pal15[idx] = digital_brg15[v & 7u];
        }
        return;
    }
    if (p >= 0x5Cu && p <= 0x5Fu) {
        WS->p88_port5x = (u8)(p - 0x5Cu);
        p88_sync_mmu();
        return;
    }
    if (p == 0x40u) {
        u8 b = (v >> 5) & 1u;
        if (b != WS->p88_beep) {
            WS->p88_beep = b;
            WS->p88_beep_toggles++;
        }
        return;
    }
    if (p == 0x44u) { WS->ym_sel = v; return; }
    if (p == 0x45u) { ym_write(WS->ym_sel, v); return; }
    if (p == 0xE6u) { WS->p88_irq_en = v; return; }

    /* Clean-room Disk Sub-CPU HLE ports $FC (PUTCOM) & $FD (PUTDAT) */
    if (p == 0xFCu) {
        WS->sub_cmd = v;
        WS->sub_arg_n = 0;
        if (v == 0x06u)      { WS->sub_stat_pend = 1u; }
        else if (v == 0x03u) { WS->sub_stat_pend = 0u; WS->sub_rpos = 0; }
        return;
    }
    if (p == 0xFDu) {
        if (WS->sub_arg_n < 8u) WS->sub_args[WS->sub_arg_n++] = v;
        if (WS->sub_cmd == 0x02u && WS->sub_arg_n == 4u) {
            u32 cnt = WS->sub_args[0] ? WS->sub_args[0] : 1u;
            if (cnt > 64u) cnt = 64u;
            u32 trk = WS->sub_args[2];
            u8  sec = WS->sub_args[3];
            WS->sub_rlen = 0;
            WS->sub_rpos = 0;
            for (u32 k = 0; k < cnt; k++) {
                u16 nsec = 16u;
                if (!d88_read_sector(trk, sec, WS->sub_rbuf + k * 256u, &nsec))
                    ws_zero(WS->sub_rbuf + k * 256u, 256u);
                WS->sub_rlen += 256u;
                sec++;
                if (sec > nsec) { sec = 1u; trk++; }
            }
        }
    }
}

static void p88_update_keys(u16 pad)
{
    WS->pad = pad;
    for (int i = 0; i < 16; i++) WS->p88_keys[i] = WS->p88_usb[i];
    if (pad & PAD_LEFT)   { WS->p88_keys[0] &= (u8)~0x10u; WS->p88_keys[10] &= (u8)~0x04u; } /* KP4 + Left */
    if (pad & PAD_RIGHT)  { WS->p88_keys[0] &= (u8)~0x40u; WS->p88_keys[8]  &= (u8)~0x04u; } /* KP6 + Right */
    if (pad & PAD_DOWN)   { WS->p88_keys[0] &= (u8)~0x04u; WS->p88_keys[10] &= (u8)~0x02u; } /* KP2 + Down */
    if (pad & PAD_UP)     { WS->p88_keys[1] &= (u8)~0x01u; WS->p88_keys[8]  &= (u8)~0x02u; } /* KP8 + Up */
    if (pad & (PAD_A | PAD_SELECT)) WS->p88_keys[9] &= (u8)~0x40u; /* Space */
    if (pad & PAD_B)      WS->p88_keys[8] &= (u8)~0x10u;           /* GRPH */
    if (pad & PAD_START)  WS->p88_keys[1] &= (u8)~0x80u;           /* Return */
}

static void render_pc88(u16 *pic)
{
    for (int y = 0; y < PC88_H; y++) {
        u16 *dst = pic + y * PC88_W;
        u32 row_off = (u32)y * 80u;
        const u8 *pb = WS->gvram[0] + row_off;
        const u8 *pr = WS->gvram[1] + row_off;
        const u8 *pg = WS->gvram[2] + row_off;
        const u8 *tv = WS->tvram + (y >> 3) * 80;
        int py = y & 7;

        for (int col = 0; col < 80; col++) {
            u8 b = pb[col], r = pr[col], g = pg[col];
            u8 t = tv[col];
            u8 tg = (t >= 32u && t < 128u && py < 7) ? 1u : 0u;
            u16 *cell = dst + col * 8;
            if ((b | r | g | tg) == 0u) {
                u16 bg = WS->p88_pal15[0];
                cell[0] = cell[1] = cell[2] = cell[3] = cell[4] = cell[5] = cell[6] = cell[7] = bg;
                continue;
            }
            u8 tbits = 0;
            if (tg) {
                const u8 *fg = font5x7[t - 32u];
                for (int px = 0; px < 5; px++)
                    if (fg[px] & (1u << py)) tbits |= (u8)(0x40u >> px);
            }
            for (int px = 0; px < 8; px++) {
                u8 sh = (u8)(7 - px);
                if (tbits & (1u << sh)) {
                    cell[px] = 0x7FFFu;
                } else {
                    u8 idx = (u8)(((b >> sh) & 1u) | (((r >> sh) & 1u) << 1) | (((g >> sh) & 1u) << 2));
                    cell[px] = WS->p88_pal15[idx];
                }
            }
        }
    }
}

/* ============================================================================
 * SYSTEM 2: SHARP MZ-700 ('mz700')
 * ============================================================================ */

static void build_mz700_cgrom(void)
{
    /* Build 4 KB Sharp MZ-700 CGROM in WS->rom[0x1000..0x1FFF] (2 banks x 256 x 8 bytes) */
    ws_zero(WS->rom + 0x1000u, 0x1000u);

    #define PUT_ASCII_GLYPH(mz_code, asc_ch) do { \
        const u8 *f = font5x7[(asc_ch) - 32]; \
        u8 *g = WS->rom + 0x1000u + (u32)(mz_code) * 8u; \
        g[0] = 0; \
        for (int py = 0; py < 7; py++) { \
            u8 r = 0; \
            for (int px = 0; px < 5; px++) if (f[px] & (1u << py)) r |= (u8)(0x40u >> px); \
            g[1 + py] = r; \
        } \
    } while (0)

    /* Sharp Display Codes (Bank 0):
       0x00=' ', 0x01..0x1A='A'..'Z', 0x20..0x29='0'..'9',
       0x2A='*', 0x2B='+', 0x2C='<', 0x2D='-', 0x2E='.', 0x2F='/',
       0x49='?', 0x4F=':', 0x51='=', 0x52='[', 0x54=']', 0x57='>',
       0x61='!', 0x62='"', 0x63='#', 0x64='$', 0x65='%', 0x66='&', 0x67='\'', 0x68='(', 0x69=')' */
    PUT_ASCII_GLYPH(0x00, ' ');
    for (int i = 0; i < 26; i++) PUT_ASCII_GLYPH(0x01 + i, 'A' + i);
    for (int i = 0; i < 10; i++) PUT_ASCII_GLYPH(0x20 + i, '0' + i);
    PUT_ASCII_GLYPH(0x2A, '*'); PUT_ASCII_GLYPH(0x2B, '+'); PUT_ASCII_GLYPH(0x2C, '<');
    PUT_ASCII_GLYPH(0x2D, '-'); PUT_ASCII_GLYPH(0x2E, '.'); PUT_ASCII_GLYPH(0x2F, '/');
    PUT_ASCII_GLYPH(0x49, '?'); PUT_ASCII_GLYPH(0x4F, ':'); PUT_ASCII_GLYPH(0x51, '=');
    PUT_ASCII_GLYPH(0x52, '['); PUT_ASCII_GLYPH(0x54, ']'); PUT_ASCII_GLYPH(0x57, '>');
    for (int i = 0; i < 9; i++) PUT_ASCII_GLYPH(0x61 + i, '!' + i);
    #undef PUT_ASCII_GLYPH

    /* 0xF0..0xFF: 2x2 Quadrant Semigraphics (b0=TL, b1=BL, b2=TR, b3=BR — verified from Chars.asm!) */
    for (int q = 0; q < 16; q++) {
        u8 top = ((q & 1) ? 0xF0u : 0u) | ((q & 4) ? 0x0Fu : 0u);
        u8 bot = ((q & 2) ? 0xF0u : 0u) | ((q & 8) ? 0x0Fu : 0u);
        u8 *g0 = WS->rom + 0x1000u + (0xF0u + q) * 8u;
        u8 *g1 = WS->rom + 0x1800u + (0xF0u + q) * 8u;
        for (int y = 0; y < 4; y++) g0[y] = g1[y] = top;
        for (int y = 4; y < 8; y++) g0[y] = g1[y] = bot;
    }
}

static void build_mz700_cgrom_icons(void)
{
    static const struct { u16 code; u8 b[8]; } icons[] = {
        { 0x03Bu, {0x07,0x0F,0x1F,0x1F,0x1F,0x1F,0x0F,0x07} },
        { 0x03Fu, {0x3C,0x7E,0xC3,0xC3,0xC3,0xC3,0x7E,0x3C} },
        { 0x042u, {0x3C,0x7E,0xDB,0xFF,0xFF,0xDB,0x66,0xC3} },
        { 0x043u, {0x3C,0x7E,0xBD,0xFF,0xFF,0xBD,0x42,0xA5} },
        { 0x04Eu, {0x18,0x18,0x3C,0x3C,0x7E,0x7E,0xFF,0xFF} },
        { 0x056u, {0x18,0x3C,0x7E,0xDB,0xFF,0x7E,0x24,0x5A} },
        { 0x07Au, {0xFF,0xAA,0x55,0xFF,0xAA,0x55,0xFF,0x00} },
        { 0x07Bu, {0xE0,0xF0,0xF8,0xF8,0xF8,0xF8,0xF0,0xE0} },
        { 0x0C1u, {0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00} },
        { 0x0C2u, {0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF} },
        { 0x0C3u, {0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00} },
        { 0x0C4u, {0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF} },
        { 0x101u, {0x3C,0x42,0x81,0x81,0x81,0x81,0x42,0x3C} },
        { 0x107u, {0x3C,0x7E,0xFF,0xFF,0xFF,0xFF,0x7E,0x3C} },
        { 0x10Cu, {0x18,0x3C,0x7E,0xFF,0xFF,0x7E,0x3C,0x18} },
        { 0x10Fu, {0xFF,0x81,0xBD,0xA5,0xA5,0xBD,0x81,0xFF} }
    };
    for (unsigned i = 0; i < sizeof(icons) / sizeof(icons[0]); i++) {
        u8 *dst = WS->rom + 0x1000u + (u32)icons[i].code * 8u;
        for (int y = 0; y < 8; y++) dst[y] = icons[i].b[y];
    }
}

static void mz_sync_mmu(void)
{
    for (int i = 0; i < 4; i++) {
        WS->cpu.rd[i] = WS->mz_lo_ram ? (WS->ram + i * 0x400) : (WS->rom + i * 0x400);
        WS->cpu.wr[i] = WS->mz_lo_ram ? (WS->ram + i * 0x400) : 0;
    }
    for (int i = 4; i < 52; i++) {
        WS->cpu.rd[i] = WS->ram + i * 0x400;
        WS->cpu.wr[i] = WS->ram + i * 0x400;
    }
    if (WS->mz_hi_mode == 1u) {
        for (int i = 52; i < 64; i++) {
            WS->cpu.rd[i] = WS->ram + i * 0x400;
            WS->cpu.wr[i] = WS->ram + i * 0x400;
        }
    } else {
        /* $D000..$D3FF TVRAM, $D800..$DBFF AVRAM, $E000..$FFFF MMIO */
        for (int i = 52; i < 64; i++) {
            WS->cpu.rd[i] = 0;
            WS->cpu.wr[i] = 0;
        }
        if (WS->mz_hi_mode == 0u) {
            WS->cpu.rd[52] = WS->cpu.wr[52] = WS->tvram;
            WS->cpu.rd[54] = WS->cpu.wr[54] = WS->avram;
        }
    }
}

static u8 mz_zread(struct z80 *c, u16 a)
{
    const u8 *p = c->rd[a >> 10];
    if (p) return p[a & 0x3FFu];
    if (WS->mz_hi_mode != 0u) return 0xFFu;
    if (a >= 0xD000u && a < 0xD800u) return WS->tvram[a & 0x3FFu];
    if (a >= 0xD800u && a < 0xE000u) return WS->avram[a & 0x3FFu];
    if (a >= 0xE000u && a <= 0xE008u) {
        switch (a & 0x0Fu) {
        case 0x1: return (WS->mz_key_row < 10u) ? WS->mz_keys[WS->mz_key_row] : 0xFFu;
        case 0x2: return (u8)((WS->mz_vblk ? 0x80u : 0x00u) | 0x40u);
        case 0x8: return (u8)((WS->mz_vblk ? 0x80u : 0x00u) | (WS->mz_gate & 1u));
        default:  return 0xFFu;
        }
    }
    return 0xFFu;
}

static void mz_zwrite(struct z80 *c, u16 a, u8 v)
{
    u8 *p = c->wr[a >> 10];
    if (p) { p[a & 0x3FFu] = v; return; }
    if (WS->mz_hi_mode != 0u) return;
    if (a >= 0xD000u && a < 0xD800u) { WS->tvram[a & 0x3FFu] = v; return; }
    if (a >= 0xD800u && a < 0xE000u) { WS->avram[a & 0x3FFu] = v; return; }
    if (a >= 0xE000u && a <= 0xE008u) {
        switch (a & 0x0Fu) {
        case 0x0: WS->mz_key_row = v & 0x0Fu; break;
        case 0x3:
            if (!(v & 0x80u)) {
                u8 bit = (v >> 1) & 7u;
                if (bit == 2u) WS->mz_intmsk = v & 1u;
                if (bit == 0u) WS->mz_gate   = v & 1u;
            }
            break;
        case 0x4:
        case 0x5:
        case 0x6: {
            int ch = (a & 0x0Fu) - 4;
            u8 rl = (WS->pit_mode[ch] >> 4) & 3u;
            if (rl == 3u) {
                if (!WS->pit_msb_pend[ch]) {
                    WS->pit_lsb_latch[ch] = v;
                    WS->pit_msb_pend[ch] = 1;
                } else {
                    WS->pit_reload[ch] = (u16)(((u16)v << 8) | WS->pit_lsb_latch[ch]);
                    WS->pit_cnt[ch] = WS->pit_reload[ch];
                    WS->pit_msb_pend[ch] = 0;
                }
            } else if (rl == 2u) {
                WS->pit_reload[ch] = (u16)((u16)v << 8);
            } else {
                WS->pit_reload[ch] = v;
            }
            break;
        }
        case 0x7: {
            int sc = (v >> 6) & 3;
            if (sc < 3 && ((v >> 4) & 3u) != 0u) {
                WS->pit_mode[sc] = v;
                WS->pit_msb_pend[sc] = 0;
            }
            break;
        }
        case 0x8:
            WS->mz_gate = v & 1u;
            break;
        }
    }
}

static u8 mz_zin(struct z80 *c, u16 port) { (void)c; (void)port; return 0xFFu; }

static void mz_zout(struct z80 *c, u16 port, u8 v)
{
    (void)c; (void)v;
    u8 p = (u8)(port & 0xFFu);
    if (p == 0xE0u) { WS->mz_lo_ram = 1; mz_sync_mmu(); }
    else if (p == 0xE1u) { WS->mz_hi_mode = 1; mz_sync_mmu(); }
    else if (p == 0xE2u) { WS->mz_lo_ram = 0; mz_sync_mmu(); }
    else if (p == 0xE3u) { WS->mz_hi_mode = 0; mz_sync_mmu(); }
    else if (p == 0xE4u) { WS->mz_lo_ram = 0; WS->mz_hi_mode = 0; mz_sync_mmu(); }
    else if (p == 0xE5u) { WS->mz_hi_mode = 2; mz_sync_mmu(); }
    else if (p == 0xE6u) { WS->mz_hi_mode = 0; mz_sync_mmu(); }
}

static void mz_update_keys(u16 pad)
{
    WS->pad = pad;
    for (int r = 0; r < 10; r++) WS->mz_keys[r] = WS->mz_usb[r];
    if (pad & PAD_LEFT)   WS->mz_keys[7] &= (u8)~0x04u;
    if (pad & PAD_RIGHT)  WS->mz_keys[7] &= (u8)~0x08u;
    if (pad & PAD_DOWN)   WS->mz_keys[7] &= (u8)~0x10u;
    if (pad & PAD_UP)     WS->mz_keys[7] &= (u8)~0x20u;
    if (pad & (PAD_A | PAD_SELECT)) WS->mz_keys[6] &= (u8)~0x10u; /* Space */
    if (pad & PAD_B)      WS->mz_keys[8] &= (u8)~0x01u;           /* Shift */
    if (pad & PAD_START)  WS->mz_keys[0] &= (u8)~0x80u;           /* CR */
}

static void mz_step_sample(void)
{
    u32 sr = WS->sample_rate ? WS->sample_rate : 48000u;
    s16 s = 0;
    u32 div = WS->pit_reload[0];
    if ((WS->mz_gate & 1u) && div >= 2u) {
        /* 8253 Ch 0 clock = 894,886 Hz -> toggle frequency = 894,886 / div */
        u32 inc = (894886u << 8) / div;
        WS->pit0_ph += inc / sr;
        s = (WS->pit0_ph & 0x80u) ? 5800 : -5800;
    }
    u32 nxt = (WS->snd_head + 1u) & (SND_RING - 1u);
    if (nxt != WS->snd_tail) {
        WS->snd_ring[WS->snd_head] = s;
        WS->snd_head = nxt;
    }
}

static void render_mz700(u16 *pic)
{
    for (int row = 0; row < 25; row++) {
        for (int col = 0; col < 40; col++) {
            u8 ch = WS->tvram[row * 40 + col];
            u8 at = WS->avram[row * 40 + col];
            u16 fg = mz_grb15[(at >> 4) & 7u];
            u16 bg = mz_grb15[at & 7u];
            const u8 *g = WS->rom + 0x1000u + (((u32)(at & 0x80u) << 1) | ch) * 8u;
            for (int py = 0; py < 8; py++) {
                u8 bits = g[py];
                u16 *dst = pic + (row * 8 + py) * MZ700_W + col * 8;
                for (int px = 0; px < 8; px++)
                    dst[px] = (bits & (0x80u >> px)) ? fg : bg;
            }
        }
    }
}

/* ============================================================================
 * SYSTEM 3: SHARP X1 ('x1')
 * ============================================================================ */

static void x1_sync_mmu(void)
{
    for (int i = 0; i < 64; i++) {
        WS->cpu.wr[i] = WS->ram + i * 0x400;
        WS->cpu.rd[i] = (WS->x1_rom_en && i < 32) ? (WS->rom + (i & 7) * 0x400) : (WS->ram + i * 0x400);
    }
}

static u8 x1_zread(struct z80 *c, u16 a)
{
    const u8 *p = c->rd[a >> 10];
    return p ? p[a & 0x3FFu] : WS->ram[a];
}

static void x1_zwrite(struct z80 *c, u16 a, u8 v)
{
    WS->ram[a] = v;
    (void)c;
}

static u8 x1_zin(struct z80 *c, u16 port)
{
    (void)c;
    if (port >= 0x4000u) {
        u32 pl = (port - 0x4000u) >> 14;
        return WS->gvram[pl][port & 0x3FFFu];
    }
    if (port >= 0x3000u && port < 0x3800u)
        return WS->tvram[port & 0x7FFu];
    if (port >= 0x2000u && port < 0x2800u)
        return WS->avram[port & 0x7FFu];
    if (port >= 0x1500u && port < 0x1800u)
        return WS->pcg[(port >> 8) - 0x15u][WS->x1_pcg_latch][port & 7u];
    if (port == 0x1A01u) {
        /* Accelerate tight `IN A,(C); AND $80; JR Z/NZ, *-6` PCG upload VBlank spin-wait! */
        if (WS->ram[c->pc.w] == 0xE6u && WS->ram[(u16)(c->pc.w + 1u)] == 0x80u &&
            WS->ram[(u16)(c->pc.w + 3u)] == 0xFAu)
            WS->x1_vblank ^= 1u;
        return (u8)(WS->x1_vblank ? 0x80u : 0x00u);
    }
    if (port == 0x1900u) {
        if (WS->x1_sub_r != WS->x1_sub_w) {
            u8 b = WS->x1_sub_q[WS->x1_sub_r];
            WS->x1_sub_r = (WS->x1_sub_r + 1u) & 7u;
            return b;
        }
        return 0x00u;
    }
    if ((port & 0xFF00u) == 0x1B00u) {
        if (WS->ym_sel == 14u) {
            u8 j = 0xFFu;
            if (WS->pad & PAD_UP)    j &= (u8)~0x01u;
            if (WS->pad & PAD_DOWN)  j &= (u8)~0x02u;
            if (WS->pad & PAD_LEFT)  j &= (u8)~0x04u;
            if (WS->pad & PAD_RIGHT) j &= (u8)~0x08u;
            if (WS->pad & (PAD_A | PAD_SELECT)) j &= (u8)~0x20u; /* Trigger 1 (bit 5) */
            if (WS->pad & (PAD_B | PAD_START))  j &= (u8)~0x40u; /* Trigger 2 (bit 6) */
            return j;
        }
        return WS->ym_regs[WS->ym_sel & 15u];
    }
    return 0xFFu;
}

static void x1_zout(struct z80 *c, u16 port, u8 v)
{
    (void)c;
    if (port >= 0x4000u) {
        u32 pl = (port - 0x4000u) >> 14;
        WS->gvram[pl][port & 0x3FFFu] = v;
        return;
    }
    if (port >= 0x3800u && port < 0x4000u) {
        WS->tvram[port & 0x7FFu] = v;
        WS->avram[port & 0x7FFu] = WS->x1_pcg_latch;
        return;
    }
    if (port >= 0x3000u && port < 0x3800u) {
        WS->tvram[port & 0x7FFu] = v;
        WS->x1_pcg_latch = v;           /* Sharp X1 hardware latches PCG index on Text VRAM access! */
        return;
    }
    if (port >= 0x2000u && port < 0x2800u) {
        WS->avram[port & 0x7FFu] = v;
        return;
    }
    if (port >= 0x1500u && port < 0x1800u) {
        WS->pcg[(port >> 8) - 0x15u][WS->x1_pcg_latch][port & 7u] = v;
        return;
    }
    if ((port & 0xFF00u) == 0x1000u) { WS->x1_pal[0] = v; return; }
    if ((port & 0xFF00u) == 0x1100u) { WS->x1_pal[1] = v; return; }
    if ((port & 0xFF00u) == 0x1200u) { WS->x1_pal[2] = v; return; }
    if ((port & 0xFF00u) == 0x1300u) { WS->x1_prio   = v; return; }
    if (port == 0x1800u) { WS->x1_crtc_sel = v & 31u; return; }
    if (port == 0x1801u) { if (WS->x1_crtc_sel < 18u) WS->x1_crtc[WS->x1_crtc_sel] = v; return; }
    if ((port & 0xFF00u) == 0x1C00u) { WS->ym_sel = v & 15u; return; }
    if ((port & 0xFF00u) == 0x1B00u) { ym_write(WS->ym_sel & 15u, v); return; }
    if ((port & 0xFF00u) == 0x1E00u) { if (WS->x1_rom_en) { WS->x1_rom_en = 0; x1_sync_mmu(); } return; }
    if ((port & 0xFF00u) == 0x1F00u) { if (!WS->x1_rom_en) { WS->x1_rom_en = 1; x1_sync_mmu(); } return; }
    if (port == 0x1900u) {
        /* 8049 Sub-CPU command $E6: Read Key Status (2 bytes: shift_mod, ascii) */
        if (v == 0xE6u) {
            WS->x1_sub_r = 0;
            WS->x1_sub_w = 2;
            WS->x1_sub_q[0] = 0xFFu;
            WS->x1_sub_q[1] = WS->x1_last_ascii;
        }
    }
}

static void render_x1(u16 *pic)
{
    int cols = (WS->x1_crtc[1] == 80u) ? 80 : 40;
    u16 gpal[8];
    for (int i = 0; i < 8; i++) {
        u8 sh = (u8)i;
        u8 idx = (u8)(((WS->x1_pal[0] >> sh) & 1u) | (((WS->x1_pal[1] >> sh) & 1u) << 1) | (((WS->x1_pal[2] >> sh) & 1u) << 2));
        gpal[i] = digital_brg15[idx];
    }

    for (int y = 0; y < X1_H; y++) {
        u16 *dst = pic + y * X1_W;
        int row = y >> 3, py = y & 7;
        u32 goff_base = (u32)py * 0x800u + (u32)row * (u32)cols;

        for (int col = 0; col < 40; col++) {
            int vcol = (cols == 80) ? (col * 2) : col;
            u32 toff = (u32)(row * cols + vcol) & 0x7FFu;
            u8 ch = WS->tvram[toff];
            u8 at = WS->avram[toff];
            u8 t_col = at & 7u;
            int is_pcg = (at & 0x20u) != 0;
            int rev    = (at & 0x08u) != 0;

            u32 goff = (goff_base + (u32)vcol) & 0x3FFFu;
            u8 gb = WS->gvram[0][goff];
            u8 gr = WS->gvram[1][goff];
            u8 gg = WS->gvram[2][goff];

            u8 pb = 0, pr = 0, pg = 0;
            if (is_pcg) {
                pb = WS->pcg[0][ch][py];
                pr = WS->pcg[1][ch][py];
                pg = WS->pcg[2][ch][py];
            } else if (ch >= 32u && ch < 128u && py < 7) {
                const u8 *f = font5x7[ch - 32u];
                u8 mask = 0;
                for (int px = 0; px < 5; px++)
                    if (f[px] & (1u << py)) mask |= (u8)(0x40u >> px);
                if (rev) mask ^= 0xFFu;
                if (t_col & 1u) pb = mask;
                if (t_col & 2u) pr = mask;
                if (t_col & 4u) pg = mask;
            } else if (rev) {
                if (t_col & 1u) pb = 0xFFu;
                if (t_col & 2u) pr = 0xFFu;
                if (t_col & 4u) pg = 0xFFu;
            }

            u16 *cell = dst + col * 8;
            if (!(pb | pr | pg | gb | gr | gg)) {
                u32 bg2 = (u32)gpal[0] | ((u32)gpal[0] << 16);
                u32 *c32 = (u32 *)cell;
                c32[0] = bg2; c32[1] = bg2; c32[2] = bg2; c32[3] = bg2;
                continue;
            }
            for (int px = 0; px < 8; px++) {
                u8 sh = (u8)(7 - px);
                u8 tc = (u8)(((pb >> sh) & 1u) | (((pr >> sh) & 1u) << 1) | (((pg >> sh) & 1u) << 2));
                u8 gc = (u8)(((gb >> sh) & 1u) | (((gr >> sh) & 1u) << 1) | (((gg >> sh) & 1u) << 2));
                if (tc)
                    cell[px] = digital_brg15[tc];
                else
                    cell[px] = gpal[gc];
            }
        }
    }
}

/* ============================================================================
 * CLEAN-ROOM BIOS / BASIC / LOADERS & PUBLIC API
 * ============================================================================ */

static void fmt_info(void)
{
    char *o = WS->info;
    const char *p = (WS->sys == SYS_PC88) ? "NEC PC-8801mkIISR (Z80 + YM2203 OPN, " :
                    (WS->sys == SYS_MZ700)? "Sharp MZ-700 (Z80 + 1Z-009A + 8253, " :
                                            "Sharp X1 (Z80 + Color PCG/GVRAM + AY, ";
    while (*p) *o++ = *p++;
    const char *s = WS->basic_mode ? "Monitor/BASIC)" : (WS->title[0] ? WS->title : "Program)");
    while (*s) *o++ = *s++;
    if (!WS->basic_mode && WS->title[0]) *o++ = ')';
    *o = 0;
}

static void extract_d88_title(const u8 *d)
{
    int k = 0;
    for (int i = 0; i < 16 && k < 24; i++) {
        u8 ch = d[i];
        if (!ch) break;
        if (ch >= 32u && ch < 127u) WS->title[k++] = (char)ch;
    }
    while (k > 0 && WS->title[k - 1] == ' ') k--;
    WS->title[k] = 0;
}

const char *pc88_load(const u8 *image, u32 size, const char *path)
{
    (void)path;
#ifdef JP8BIT_HOST
    u32 sr = WS->sample_rate;
#endif
    ws_zero(WS, sizeof(*WS));
#ifdef JP8BIT_HOST
    WS->sample_rate = sr ? sr : 48000u;
#else
    WS->sample_rate = 48000u;
#endif
    WS->sys = SYS_PC88;
    init_fm_tables();
    for (int i = 0; i < 16; i++) WS->p88_keys[i] = WS->p88_usb[i] = 0xFFu;

    if (!image || size == 0) {
        WS->basic_mode = 1;
        jp8bit_reset();
        fmt_info();
        return 0;
    }
    if (size < 256u) return "PC-88 image is too small";

    u32 n = size > DSK_MAX ? DSK_MAX : size;
    for (u32 i = 0; i < n; i++) WS->dsk[i] = image[i];
    WS->dsk_size = n;
    WS->has_dsk = 1;
    extract_d88_title(image);

    jp8bit_reset();
    fmt_info();
    return 0;
}

const char *mz700_load(const u8 *image, u32 size, const char *path)
{
    (void)path;
#ifdef JP8BIT_HOST
    u32 sr = WS->sample_rate;
#endif
    ws_zero(WS, sizeof(*WS));
#ifdef JP8BIT_HOST
    WS->sample_rate = sr ? sr : 48000u;
#else
    WS->sample_rate = 48000u;
#endif
    WS->sys = SYS_MZ700;
    for (int r = 0; r < 10; r++) WS->mz_keys[r] = WS->mz_usb[r] = 0xFFu;

    if (!image || size == 0) {
        WS->basic_mode = 1;
        jp8bit_reset();
        fmt_info();
        return 0;
    }
    if (size < 130u) return "Sharp MZ-700 .mzt/.mzf tape is too small";

    u16 psz  = (u16)(image[0x12] | ((u16)image[0x13] << 8));
    u16 load = (u16)(image[0x14] | ((u16)image[0x15] << 8));
    u16 exec = (u16)(image[0x16] | ((u16)image[0x17] << 8));
    u32 avail = size - 0x80u;
    if (psz > avail) psz = (u16)avail;
    if ((u32)load + psz > 0x10000u) psz = (u16)(0x10000u - load);

    int k = 0;
    for (int i = 1; i < 18 && k < 24; i++) {
        u8 ch = image[i];
        if (ch == 0x0Du || ch == 0x00u) break;
        if (ch >= 32u && ch < 127u) WS->title[k++] = (char)ch;
    }
    while (k > 0 && WS->title[k - 1] == ' ') k--;
    WS->title[k] = 0;

    for (u32 i = 0; i < psz; i++) WS->dsk[i] = image[0x80u + i];
    WS->prog_load = load;
    WS->prog_exec = exec ? exec : load;
    WS->prog_size = psz;
    WS->has_prog  = 1;

    jp8bit_reset();
    fmt_info();
    return 0;
}

const char *x1_load(const u8 *image, u32 size, const char *path)
{
#ifdef JP8BIT_HOST
    u32 sr = WS->sample_rate;
#endif
    ws_zero(WS, sizeof(*WS));
#ifdef JP8BIT_HOST
    WS->sample_rate = sr ? sr : 48000u;
#else
    WS->sample_rate = 48000u;
#endif
    WS->sys = SYS_X1;

    if (!image || size == 0) {
        WS->basic_mode = 1;
        jp8bit_reset();
        fmt_info();
        return 0;
    }
    if (size < 256u) return "Sharp X1 disk/tape image is too small";

    u32 n = size > DSK_MAX ? DSK_MAX : size;
    for (u32 i = 0; i < n; i++) WS->dsk[i] = image[i];
    WS->dsk_size = n;
    WS->has_dsk = !ci_ends(path, ".tap");
    extract_d88_title(image);

    jp8bit_reset();
    fmt_info();
    return 0;
}

void jp8bit_reset(void)
{
    ws_zero(WS->ram, sizeof(WS->ram));
    ws_zero(WS->gvram, sizeof(WS->gvram));
    ws_zero(WS->tvram, sizeof(WS->tvram));
    ws_zero(WS->avram, sizeof(WS->avram));
    ws_zero(WS->pcg, sizeof(WS->pcg));
    ws_zero(WS->ym_regs, sizeof(WS->ym_regs));
    ws_zero(WS->fm, sizeof(WS->fm));
    WS->ssg_lfsr = 1u;
    WS->ym_regs[7] = 0x3Fu;
    WS->frames = 0;

    z80_init(&WS->cpu);
    z80_reset(&WS->cpu);
    WS->cpu.trap = -1;

    if (WS->sys == SYS_PC88) {
        ws_zero(WS->rom, 0x8000u);
        for (int i = 0; i < 8; i++) WS->p88_pal15[i] = digital_brg15[i];
        WS->p88_port31 = 0x39u;         /* ROM active ($0000..$7FFF), 64K mode off */
        WS->p88_port32 = 0x00u;
        WS->p88_port5x = 3u;            /* Main RAM at $C000..$FFFF */
        WS->ram[0xE6C2u] = 0x31u;
        WS->ram[0xEF0Eu] = 0x00u;

        /* Clean-room N88 ROM stubs:
           $0038: PUSH HL; LD HL, ($F302); ex (sp), hl; RET -> dispatches to ($F302) VRTC vector!
           $0100 (default $F302): EI; RETI
           $37CC (PUTCOM): OUT ($FC), A; RET
           $37D2 (PUTDAT): OUT ($FD), A; RET
           $3847 (GETDAT): IN  A, ($FD); RET
           $6FD1: RET */
        WS->rom[0x0038] = WS->ram[0x0038] = 0xE5u;
        WS->rom[0x0039] = WS->ram[0x0039] = 0x2Au;
        WS->rom[0x003A] = WS->ram[0x003A] = 0x02u;
        WS->rom[0x003B] = WS->ram[0x003B] = 0xF3u;
        WS->rom[0x003C] = WS->ram[0x003C] = 0xE3u;
        WS->rom[0x003D] = WS->ram[0x003D] = 0xC9u;
        WS->rom[0x0100] = WS->ram[0x0100] = 0xFBu;
        WS->rom[0x0101] = WS->ram[0x0101] = 0xEDu;
        WS->rom[0x0102] = WS->ram[0x0102] = 0x4Du;
        WS->ram[0xF302] = 0x00u; WS->ram[0xF303] = 0x01u;

        WS->rom[0x37CC] = 0xD3u; WS->rom[0x37CD] = 0xFCu; WS->rom[0x37CE] = 0xC9u;
        WS->rom[0x37D2] = 0xD3u; WS->rom[0x37D3] = 0xFDu; WS->rom[0x37D4] = 0xC9u;
        WS->rom[0x3847] = 0xDBu; WS->rom[0x3848] = 0xFDu; WS->rom[0x3849] = 0xC9u;
        WS->rom[0x6FD1] = 0xC9u;

        u16 boot_pc = 0x0050u;
        WS->rom[0x0050] = 0x18u; WS->rom[0x0051] = 0xFEu;
        if (WS->has_dsk) {
            u8 boot[256];
            if (d88_read_sector(0u, 1u, boot, 0)) {
                for (int i = 0; i < 256; i++) WS->ram[0xC000u + i] = boot[i];
                boot_pc = 0xC000u;
            }
        } else {
            const char *b = "NEC PC-8801mkIISR N88-BASIC V2.0";
            for (int i = 0; b[i]; i++) WS->tvram[1 * 80 + 2 + i] = (u8)b[i];
            const char *ok = "How many files(0-15)? Ok";
            for (int i = 0; ok[i]; i++) WS->tvram[3 * 80 + 2 + i] = (u8)ok[i];
        }
        WS->rom[0x0000] = 0x31u; WS->rom[0x0001] = 0x00u; WS->rom[0x0002] = 0xF0u;
        WS->rom[0x0003] = 0xC3u; WS->rom[0x0004] = (u8)(boot_pc & 0xFFu); WS->rom[0x0005] = (u8)(boot_pc >> 8);

        WS->cpu.read  = p88_zread;
        WS->cpu.write = p88_zwrite;
        WS->cpu.in    = p88_zin;
        WS->cpu.out   = p88_zout;
        WS->cpu.im    = 1;
        p88_sync_mmu();
    } else if (WS->sys == SYS_MZ700) {
        ws_zero(WS->rom, 0x2000u);
        build_mz700_cgrom();
        build_mz700_cgrom_icons();
        WS->mz_lo_ram  = 0;
        WS->mz_hi_mode = 0;
        WS->mz_intmsk  = 0;
        WS->mz_gate    = 0;

        /* Clean-room Sharp 1Z-009A Monitor ($0000..$0FFF):
           $0038: JP $1038 (RAM IRQ jump slot at $1038..$103A = C3 60 00 -> EI : RET!) */
        WS->rom[0x0038] = 0xC3u; WS->rom[0x0039] = 0x38u; WS->rom[0x003A] = 0x10u;
        WS->rom[0x0060] = 0xFBu; WS->rom[0x0061] = 0xC9u;
        WS->ram[0x1038] = 0xC3u; WS->ram[0x1039] = 0x60u; WS->ram[0x103A] = 0x00u;

        u16 exec_pc = 0x0070u;
        WS->rom[0x0070] = 0x18u; WS->rom[0x0071] = 0xFEu;
        if (WS->has_prog) {
            for (u32 i = 0; i < WS->prog_size; i++)
                WS->ram[WS->prog_load + i] = WS->dsk[i];
            exec_pc = WS->prog_exec;
        } else {
            for (int i = 0; i < 1000; i++) WS->avram[i] = 0x71u; /* White on Blue */
            const char *m = "** MONITOR 1Z-009A **";
            for (int i = 0; m[i]; i++) {
                char c = m[i];
                u8 dc = (c == '*') ? 0x2Au : (c == '-') ? 0x2Du : (c >= 'A' && c <= 'Z') ? (u8)(c - 'A' + 1) :
                        (c >= '0' && c <= '9') ? (u8)(0x20 + c - '0') : 0x00u;
                WS->tvram[1 * 40 + 2 + i] = dc;
            }
            WS->tvram[3 * 40 + 2] = 0x2Au; /* '*' prompt */
        }
        WS->rom[0x0000] = 0x31u; WS->rom[0x0001] = 0xF0u; WS->rom[0x0002] = 0x10u;
        WS->rom[0x0003] = 0xC3u; WS->rom[0x0004] = (u8)(exec_pc & 0xFFu); WS->rom[0x0005] = (u8)(exec_pc >> 8);

        WS->cpu.read  = mz_zread;
        WS->cpu.write = mz_zwrite;
        WS->cpu.in    = mz_zin;
        WS->cpu.out   = mz_zout;
        WS->cpu.im    = 1;
        mz_sync_mmu();
    } else {
        /* Sharp X1 */
        ws_zero(WS->rom, 0x2000u);
        WS->x1_pal[0] = 0xAAu;
        WS->x1_pal[1] = 0xCCu;
        WS->x1_pal[2] = 0xF0u;
        WS->x1_crtc[1] = 40u;

        u16 exec_pc = 0x0010u;
        WS->x1_rom_en = 1;
        WS->rom[0x0010] = 0x76u; WS->rom[0x0011] = 0x18u; WS->rom[0x0012] = 0xFDu; /* HALT; JR $-1 */

        if (WS->has_dsk) {
            u8 s1[256];
            if (d88_read_sector(0u, 1u, s1, 0) && s1[0] == 0x01u) {
                /* Standard Sharp X1 IPL "Sys" descriptor in Track 0 Sector 1 */
                u16 bsz   = (u16)(s1[0x12] | ((u16)s1[0x13] << 8));
                u16 bload = (u16)(s1[0x14] | ((u16)s1[0x15] << 8));
                u16 bexec = (u16)(s1[0x16] | ((u16)s1[0x17] << 8));
                u16 ssec  = (u16)(s1[0x1E] | ((u16)s1[0x1F] << 8));
                int k = 0;
                for (int i = 1; i < 14 && k < 24; i++) {
                    if (s1[i] >= 32u && s1[i] < 127u) WS->title[k++] = (char)s1[i];
                }
                while (k > 0 && WS->title[k - 1] == ' ') k--;
                if (k > 0) WS->title[k] = 0;

                u32 loaded = 0;
                u32 cur_s = ssec;
                while (loaded < bsz) {
                    u8 buf[256];
                    u32 trk = cur_s >> 4;
                    u8  r   = (u8)((cur_s & 15u) + 1u);
                    if (!d88_read_sector(trk, r, buf, 0))
                        ws_zero(buf, 256u);
                    for (u32 i = 0; i < 256u && loaded < bsz; i++, loaded++)
                        WS->ram[(u16)(bload + loaded)] = buf[i];
                    cur_s++;
                }
                WS->x1_rom_en = 0;
                exec_pc = bexec ? bexec : bload;
            }
        } else {
            for (int i = 0; i < 800; i++) { WS->tvram[i] = ' '; WS->avram[i] = 0x07u; }
            const char *x1b = "SHARP X1 IPL & HU-BASIC READY";
            for (int i = 0; x1b[i]; i++) { WS->tvram[1 * 40 + 2 + i] = (u8)x1b[i]; WS->avram[1 * 40 + 2 + i] = 0x06u; }
        }

        WS->cpu.read  = x1_zread;
        WS->cpu.write = x1_zwrite;
        WS->cpu.in    = x1_zin;
        WS->cpu.out   = x1_zout;
        x1_sync_mmu();
        WS->cpu.pc.w = exec_pc;
        WS->cpu.sp.w = (exec_pc >= 0x8000u) ? 0x8000u : 0xFFFEu;
    }
}

void jp8bit_frame(u16 pad, u16 *picture)
{
    u32 sr = WS->sample_rate ? WS->sample_rate : 48000u;
    WS->cpu.cycles = 0;

    if (WS->sys == SYS_PC88) {
        p88_update_keys(pad);
        WS->p88_beep_toggles = 0;
        /* 4.0 MHz Z80 @ 60 Hz = 66,667 T-states: 53,000 active + 13,667 VRTC */
        WS->p88_vrtc = 0;
        z80_run(&WS->cpu, 53000);
        WS->p88_vrtc = 1;
        if (WS->p88_irq_en & 0x02u) {
            WS->cpu.irq = 1;
            z80_run(&WS->cpu, 53128);
            WS->cpu.irq = 0;
        }
        z80_run(&WS->cpu, 66667);

        u32 samps = sr / 60u;
        u32 beep_inc = (WS->p88_beep_toggles >= 4u) ? (((WS->p88_beep_toggles * 30u) << 16) / sr) : 0u;
        for (u32 i = 0; i < samps; i++) {
            u32 wr_idx = WS->snd_head;
            step_ssg_and_fm_sample(124800u, 1); /* 3.9936 MHz / 32 = 124.8 kHz SSG + FM */
            if (beep_inc && WS->snd_head != wr_idx) {
                WS->p88_beep_ph += beep_inc;
                s32 mix = (s32)WS->snd_ring[wr_idx] + ((WS->p88_beep_ph & 0x8000u) ? 4800 : -4800);
                if (mix > 32767) mix = 32767;
                else if (mix < -32768) mix = -32768;
                WS->snd_ring[wr_idx] = (s16)mix;
            }
        }

        render_pc88(picture);
    } else if (WS->sys == SYS_MZ700) {
        mz_update_keys(pad);
        /* 3.58 MHz Z80 @ 60 Hz = 59,659 T-states:
           Active display ($E002 bit 7 = 1!), then VBlank ($E002 bit 7 = 0!).
           Look at mz700 Startup.asm: Handler spins WHILE ($E002 & 80h) != 0!
           So fire the 8253 interrupt right as VBLK transitions to 0 (or spin completes in VBlank)! */
        WS->mz_vblk = 1;
        z80_run(&WS->cpu, 44000);
        WS->mz_vblk = 0;
        if (WS->mz_intmsk) {
            WS->cpu.irq = 1;
            z80_run(&WS->cpu, 44128);
            WS->cpu.irq = 0;
        }
        z80_run(&WS->cpu, 59659);

        u32 samps = sr / 60u;
        for (u32 i = 0; i < samps; i++)
            mz_step_sample();

        render_mz700(picture);
    } else {
        /* Sharp X1: 4.0 MHz Z80 @ 60 Hz = 66,667 T-states */
        WS->pad = pad;
        WS->x1_last_ascii = 0;
        if (pad & PAD_LEFT)  WS->x1_last_ascii = '4';
        if (pad & PAD_RIGHT) WS->x1_last_ascii = '6';
        if (pad & PAD_UP)    WS->x1_last_ascii = '8';
        if (pad & PAD_DOWN)  WS->x1_last_ascii = '2';
        if (pad & (PAD_A | PAD_SELECT)) WS->x1_last_ascii = ' ';
        if (pad & PAD_START) WS->x1_last_ascii = 0x0Du;

        WS->x1_vblank = 0;
        z80_run(&WS->cpu, 52000);
        WS->x1_vblank = 1;
        z80_run(&WS->cpu, 66667);

        u32 samps = sr / 60u;
        for (u32 i = 0; i < samps; i++)
            step_ssg_and_fm_sample(125000u, 0); /* 2 MHz AY-3-8910 / 16 = 125 kHz */

        render_x1(picture);
    }
    WS->frames++;
}

void jp8bit_keyboard(const u8 *usages, int n)
{
    if (WS->sys == SYS_PC88) {
        for (int i = 0; i < 16; i++) WS->p88_usb[i] = 0xFFu;
        for (int i = 0; i < n; i++) {
            u8 u = usages[i];
            if (u == 0x2Cu) WS->p88_usb[9] &= (u8)~0x40u;
            else if (u == 0x28u) WS->p88_usb[1] &= (u8)~0x80u;
            else if (u == 0x52u) WS->p88_usb[8] &= (u8)~0x02u;
            else if (u == 0x51u) WS->p88_usb[10] &= (u8)~0x02u;
            else if (u == 0x50u) WS->p88_usb[10] &= (u8)~0x04u;
            else if (u == 0x4Fu) WS->p88_usb[8] &= (u8)~0x04u;
            else if (u == 0xE2u || u == 0xE6u) WS->p88_usb[8] &= (u8)~0x10u;
        }
    } else if (WS->sys == SYS_MZ700) {
        for (int i = 0; i < 10; i++) WS->mz_usb[i] = 0xFFu;
        for (int i = 0; i < n; i++) {
            u8 u = usages[i];
            if (u == 0x2Cu) WS->mz_usb[6] &= (u8)~0x10u;
            else if (u == 0x28u) WS->mz_usb[0] &= (u8)~0x80u;
            else if (u == 0xE1u || u == 0xE5u) WS->mz_usb[8] &= (u8)~0x01u;
            else if (u == 0x52u) WS->mz_usb[7] &= (u8)~0x20u;
            else if (u == 0x51u) WS->mz_usb[7] &= (u8)~0x10u;
            else if (u == 0x4Fu) WS->mz_usb[7] &= (u8)~0x08u;
            else if (u == 0x50u) WS->mz_usb[7] &= (u8)~0x04u;
        }
    }
}

void jp8bit_typed(char c)
{
    u8 nxt = (WS->type_w + 1u) & 63u;
    if (nxt != WS->type_r) {
        WS->type_q[WS->type_w] = c;
        WS->type_w = nxt;
    }
}

const char *jp8bit_info(void)
{
    return WS->info;
}

int jp8bit_jammed(void)
{
    return 0;
}

void jp8bit_audio_rate(u32 hz)
{
    WS->sample_rate = hz ? hz : 48000u;
    WS->snd_head = WS->snd_tail = 0;
    if (WS->sys == SYS_PC88) {
        for (int c = 0; c < 3; c++) ym_recalc_ch(c);
    }
}

int jp8bit_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && WS->snd_tail != WS->snd_head) {
        out[n++] = WS->snd_ring[WS->snd_tail];
        WS->snd_tail = (WS->snd_tail + 1u) & (SND_RING - 1u);
    }
    return n;
}
