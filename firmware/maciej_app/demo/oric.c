/* Tangerine Oric-1 & Oric Atmos ('oric'): see oric.h.
   Pass-optimized for 594 MHz MIPS32:
   - Zero static .bss (all 64 KB RAM, 16 KB ROM, disk buffer & 48 kHz audio ring in EMU_RAM_PHYS)
   - 256-entry direct 6502 page pointers (zero-overhead RAM/ROM reads & writes except page $03 VIA/FDC)
   - Exact Atmos v1.1 IRQ vectoring ($FFFE -> $0244) + 6522 VIA Timer 1 100 Hz free-run
   - Scanline-accurate serial-attribute HCS10017 ULA renderer + 48 kHz AY-3-8912 PSG */
#pragma GCC optimize("O2")
#include "oric.h"

#ifndef ORIC_HOST
#include "hw.h"
#endif

#define FC 0x01u
#define FZ 0x02u
#define FI 0x04u
#define FD 0x08u
#define FB 0x10u
#define FU 0x20u
#define FV 0x40u
#define FN 0x80u

#define SND_RING 4096
#define DSK_MAX  0x90000u       /* Up to 576 KB MFM_DISK image */

struct oric_ws {
    /* 1.0 MHz MOS 6502 CPU */
    u8  a, x, y, s, p;
    u16 pc;
    u8  jam, nmi_pend;
    s32 cycles;
    u8 *rdp[256], *wrp[256];

    /* 64 KB RAM ($0000..$BFFF + 16 KB overlay RAM when FDC disables ROM) + 16 KB Atmos ROM */
    u8  ram[0x10000];
    u8  rom[0x4000];
    u8  rom_dis;                /* Microdisc $0314 bit 1 = 0 disables ROM */
    u8  ext_rom_loaded;
    u8  basic_mode;
    u8  has_prog;
    u16 prog_entry;

    /* HCS10017 ULA Video state */
    u8  hires;                  /* Persistent across frames: 0=Text, 1=Hires */
    u32 frames;

    /* MOS 6522 VIA ($0300..$030F) */
    u8  via_ora, via_orb, via_ddra, via_ddrb;
    u16 via_t1c, via_t1l, via_t2c;
    u8  via_t2l_lo, via_t2_armed;
    u8  via_sr, via_acr, via_pcr, via_ifr, via_ier;

    /* Microdisc FDC ($0310..$0318) & .dsk storage */
    u8  has_dsk;
    u32 dsk_size;
    u8  fdc_cmd, fdc_stat, fdc_trk, fdc_sec, fdc_dat, fdc_ctrl, fdc_drq;
    u16 fdc_idx, fdc_len;
    u8  fdc_buf[256];
    u8  dsk[DSK_MAX];

    /* General Instrument AY-3-8912 (1.0 MHz) */
    u8  ay_latch;
    u8  ay_regs[16];
    u32 ay_cnt[3], ay_ncnt, ay_lfsr, ay_ecnt;
    u8  ay_out[3], ay_estep, ay_evol, ay_ehold, ay_ealt;

    /* Oric 8x8 Keyboard Matrix: key_mat[row 0..7] = 8-bit column bitmask (1 = pressed) */
    u8  key_mat[8];
    u8  usb_mat[8];
    u16 pad;
    char type_q[64];
    u8  type_r, type_w, type_hold;
    char type_ch;

    /* Interactive Atmos BASIC state */
    u8  bas_x, bas_y;
    char bas_line[40];
    u8  bas_len;

    /* 48 kHz Audio Ring */
    u32 sample_rate, snd_frac, chip_frac;
    u32 snd_head, snd_tail;
    s16 snd_ring[SND_RING];

    u32 tap_len;
    u8  tap_buf[0x10000];

    char title[32];
    char info[96];
};

#ifdef ORIC_HOST
static struct oric_ws oric_host_ws;
#define WS (&oric_host_ws)
#else
#define WS ((struct oric_ws *)KSEG0(EMU_RAM_PHYS))
#ifndef ORIC_NO_ASSERT
_Static_assert(sizeof(struct oric_ws) <= EMU_RAM_SIZE, "oric_ws exceeds EMU_RAM_SIZE");
#endif
#endif

#define INLINE static inline __attribute__((always_inline))

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

/* Oric 8-color RGB palette in 0bbbbbgggggrrrrr (b0=Red, b1=Green, b2=Blue) */
static const u16 oric_pal15[8] = {
    0x0000u, /* 0: Black   */
    0x001Fu, /* 1: Red     */
    0x03E0u, /* 2: Green   */
    0x03FFu, /* 3: Yellow  */
    0x7C00u, /* 4: Blue    */
    0x7C1Fu, /* 5: Magenta */
    0x7FE0u, /* 6: Cyan    */
    0x7FFFu  /* 7: White   */
};

/* Clean-room 5x7 ASCII font rendered into Oric 6x8 character cells ($B400 & $9800) */
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

/* ---- 1.0 MHz AY-3-8912 3-Channel PSG @ 48 kHz ---- */

static const s16 ay_vol_lut[16] = {
       0,   92,  130,  184,  260,  368,  520,  735,
    1040, 1470, 2080, 2941, 4160, 5883, 8320, 10800
};

static void ay_write_reg(u8 r, u8 v)
{
    if (r >= 16u) return;
    WS->ay_regs[r] = v;
    if (r == 13u) {
        WS->ay_ecnt = 0;
        WS->ay_estep = 0;
        WS->ay_ehold = 0;
        WS->ay_ealt = (v & 4u) ? 0u : 15u;
        WS->ay_evol = WS->ay_ealt;
    }
}

static void ay_bus_update(void)
{
    /* VIA PCR CA2 (bits 3..1) = BC1, CB2 (bits 7..5) = BDIR:
       CA2=7(111)->BC1=1, CA2=6(110)->BC1=0; CB2=7(111)->BDIR=1, CB2=6(110)->BDIR=0 */
    int bc1  = ((WS->via_pcr >> 1) & 7u) == 7u;
    int bdir = ((WS->via_pcr >> 5) & 7u) == 7u;
    if (bc1 && bdir) {
        WS->ay_latch = WS->via_ora & 15u;
    } else if (!bc1 && bdir) {
        ay_write_reg(WS->ay_latch, WS->via_ora);
    }
}

static void ay_step_sample(void)
{
    /* 1.0 MHz AY-3-8912 internal divider / 8 = 125,000 Hz */
    WS->chip_frac += 125000u;
    u32 sr = WS->sample_rate ? WS->sample_rate : 48000u;
    s32 acc = 0, ticks = 0;
    while (WS->chip_frac >= sr) {
        WS->chip_frac -= sr;
        ticks++;

        for (int c = 0; c < 3; c++) {
            u32 per = ((u32)(WS->ay_regs[c * 2 + 1] & 0x0Fu) << 8) | WS->ay_regs[c * 2];
            if (!per) per = 1u;
            if (++WS->ay_cnt[c] >= per) {
                WS->ay_cnt[c] = 0;
                WS->ay_out[c] ^= 1u;
            }
        }

        u32 nper = (u32)(WS->ay_regs[6] & 0x1Fu) * 2u;
        if (!nper) nper = 2u;
        if (++WS->ay_ncnt >= nper) {
            WS->ay_ncnt = 0;
            u32 fb = ((WS->ay_lfsr ^ (WS->ay_lfsr >> 3)) & 1u);
            WS->ay_lfsr = (WS->ay_lfsr >> 1) | (fb << 16);
        }

        u32 eper = (((u32)WS->ay_regs[12] << 8) | WS->ay_regs[11]) * 2u;
        if (!eper) eper = 2u;
        if (!WS->ay_ehold && ++WS->ay_ecnt >= eper) {
            WS->ay_ecnt = 0;
            WS->ay_estep++;
            if (WS->ay_estep >= 16u) {
                u8 sh = WS->ay_regs[13] & 0x0Fu;
                if (!(sh & 8u)) {
                    WS->ay_evol = 0;
                    WS->ay_ehold = 1;
                } else if (sh & 1u) {
                    WS->ay_evol = ((sh & 2u) ? (WS->ay_ealt ^ 15u) : WS->ay_ealt);
                    WS->ay_ehold = 1;
                } else {
                    if (sh & 2u) WS->ay_ealt ^= 15u;
                    WS->ay_estep = 0;
                }
            }
            if (!WS->ay_ehold)
                WS->ay_evol = (u8)((WS->ay_estep & 15u) ^ WS->ay_ealt);
        }

        u8 mix = WS->ay_regs[7];
        u8 nbit = (u8)(WS->ay_lfsr & 1u);
        s32 s = 0;
        for (int c = 0; c < 3; c++) {
            int t_ok = ((mix >> c) & 1u) | WS->ay_out[c];
            int n_ok = ((mix >> (c + 3)) & 1u) | nbit;
            u8 vr = WS->ay_regs[8 + c];
            u8 vol = (vr & 0x10u) ? WS->ay_evol : (vr & 0x0Fu);
            if (t_ok && n_ok)
                s += ay_vol_lut[vol & 15u];
        }
        acc += s - 6000;
    }
    s32 out = ticks ? (acc / ticks) : 0;
    if (out > 32767) out = 32767;
    if (out < -32768) out = -32768;
    u32 nxt = (WS->snd_head + 1u) & (SND_RING - 1u);
    if (nxt != WS->snd_tail) {
        WS->snd_ring[WS->snd_head] = (s16)out;
        WS->snd_head = nxt;
    }
}

/* ---- Oric 8x8 Keyboard Matrix & Gamepad ---- */

enum {
    PAD_A      = 0x001, /* X -> Space (Fire 1) */
    PAD_B      = 0x002, /* Z -> Return (Fire 2) */
    PAD_SELECT = 0x004, /* Tab -> Space */
    PAD_START  = 0x008, /* Enter -> Return */
    PAD_UP     = 0x010,
    PAD_DOWN   = 0x020,
    PAD_LEFT   = 0x040,
    PAD_RIGHT  = 0x080
};

/* Oric Atmos 8x8 matrix (row 0..7 in VIA Port B b0..b2, active-low column in AY Reg 14 b0..b7):
   Row 0: 7(b0), N(b1), 5(b2), V(b3), RAlt(b4), 1(b5), X(b6), 3(b7)
   Row 1: J(b0), T(b1), R(b2), F(b3), ---(b4), Esc(b5), Q(b6), D(b7)
   Row 2: M(b0), 6(b1), B(b2), 4(b3), LCtrl(b4), Z(b5), 2(b6), C(b7)
   Row 3: K(b0), 9(b1), ;(b2), -(b3), ---(b4), ---(b5), \(b6), '(b7)
   Row 4: Space(b0), ,(b1), .(b2), Up(b3), LShift(b4), Left(b5), Down(b6), Right(b7)
   Row 5: U(b0), I(b1), O(b2), P(b3), LAlt(b4), Del(b5), ](b6), [(b7)
   Row 6: Y(b0), H(b1), G(b2), E(b3), ---(b4), A(b5), S(b6), W(b7)
   Row 7: 8(b0), L(b1), 0(b2), /(b3), RShift(b4), Return(b5), ---(b6), =(b7) */
static void press_oric_ascii(char ch, u8 mat[8])
{
    if (ch >= 'a' && ch <= 'z') ch = (char)(ch - 32);
    switch (ch) {
    case ' ':  mat[4] |= 0x01u; break;
    case '\r': case '\n': mat[7] |= 0x20u; break;
    case 8: case 127: mat[5] |= 0x20u; break;
    case '0': mat[7] |= 0x04u; break;
    case '1': mat[0] |= 0x20u; break;
    case '2': mat[2] |= 0x40u; break;
    case '3': mat[0] |= 0x80u; break;
    case '4': mat[2] |= 0x08u; break;
    case '5': mat[0] |= 0x04u; break;
    case '6': mat[2] |= 0x02u; break;
    case '7': mat[0] |= 0x01u; break;
    case '8': mat[7] |= 0x01u; break;
    case '9': mat[3] |= 0x02u; break;
    case 'A': mat[6] |= 0x20u; break;
    case 'B': mat[2] |= 0x04u; break;
    case 'C': mat[2] |= 0x80u; break;
    case 'D': mat[1] |= 0x80u; break;
    case 'E': mat[6] |= 0x08u; break;
    case 'F': mat[1] |= 0x08u; break;
    case 'G': mat[6] |= 0x04u; break;
    case 'H': mat[6] |= 0x02u; break;
    case 'I': mat[5] |= 0x02u; break;
    case 'J': mat[1] |= 0x01u; break;
    case 'K': mat[3] |= 0x01u; break;
    case 'L': mat[7] |= 0x02u; break;
    case 'M': mat[2] |= 0x01u; break;
    case 'N': mat[0] |= 0x02u; break;
    case 'O': mat[5] |= 0x04u; break;
    case 'P': mat[5] |= 0x08u; break;
    case 'Q': mat[1] |= 0x40u; break;
    case 'R': mat[1] |= 0x04u; break;
    case 'S': mat[6] |= 0x40u; break;
    case 'T': mat[1] |= 0x02u; break;
    case 'U': mat[5] |= 0x01u; break;
    case 'V': mat[0] |= 0x08u; break;
    case 'W': mat[6] |= 0x80u; break;
    case 'X': mat[0] |= 0x40u; break;
    case 'Y': mat[6] |= 0x01u; break;
    case 'Z': mat[2] |= 0x20u; break;
    case '"': mat[2] |= 0x40u; mat[4] |= 0x10u; break;
    case '=': mat[7] |= 0x80u; break;
    case '-': mat[3] |= 0x08u; break;
    case ';': mat[3] |= 0x04u; break;
    case ',': mat[4] |= 0x02u; break;
    case '.': mat[4] |= 0x04u; break;
    case '/': mat[7] |= 0x08u; break;
    default: break;
    }
}

static void update_oric_keys(u16 pad)
{
    WS->pad = pad;
    for (int r = 0; r < 8; r++)
        WS->key_mat[r] = WS->usb_mat[r];

    if (pad & PAD_UP)     WS->key_mat[4] |= 0x08u;      /* Up arrow */
    if (pad & PAD_LEFT)   WS->key_mat[4] |= 0x20u;      /* Left arrow */
    if (pad & PAD_DOWN)   WS->key_mat[4] |= 0x40u;      /* Down arrow */
    if (pad & PAD_RIGHT)  WS->key_mat[4] |= 0x80u;      /* Right arrow */
    if (pad & (PAD_A | PAD_SELECT)) WS->key_mat[4] |= 0x01u; /* Space */
    if (pad & (PAD_B | PAD_START))  WS->key_mat[7] |= 0x20u; /* Return */

    if (WS->type_hold > 0) {
        WS->type_hold--;
        press_oric_ascii(WS->type_ch, WS->key_mat);
    } else if (WS->type_r != WS->type_w && !WS->basic_mode) {
        WS->type_ch = WS->type_q[WS->type_r];
        WS->type_r = (WS->type_r + 1u) & 63u;
        WS->type_hold = 3;
        press_oric_ascii(WS->type_ch, WS->key_mat);
    }
}

/* ---- MOS 6522 VIA ($0300..$030F) & Microdisc FDC ($0310..$0318) ---- */

static void setup_mmu(void)
{
    for (int i = 0; i < 256; i++) {
        if (i == 0x03) {
            WS->rdp[i] = 0;
            WS->wrp[i] = 0;
        } else if (i >= 0xC0 && !WS->rom_dis) {
            WS->rdp[i] = WS->rom + (i - 0xC0) * 256;
            WS->wrp[i] = 0;
        } else {
            WS->rdp[i] = WS->ram + i * 256;
            WS->wrp[i] = WS->ram + i * 256;
        }
    }
}

static void via_recalc_ifr(void)
{
    if (WS->via_ifr & WS->via_ier & 0x7Fu)
        WS->via_ifr |= 0x80u;
    else
        WS->via_ifr &= ~0x80u;
}

static int dsk_read_sector(u8 side, u8 trk, u8 sec, u8 dst[256])
{
    if (!WS->has_dsk || WS->dsk_size < 256u) return 0;
    if (WS->dsk[0] == 'M' && WS->dsk[1] == 'F' && WS->dsk[2] == 'M' && WS->dsk[3] == '_') {
        u32 sides  = (u32)WS->dsk[8]  | ((u32)WS->dsk[9] << 8);
        u32 tracks = (u32)WS->dsk[12] | ((u32)WS->dsk[13] << 8);
        u32 geom   = (u32)WS->dsk[16] | ((u32)WS->dsk[17] << 8);
        if (!tracks || trk >= tracks) return 0;
        u32 t_idx = (geom == 1u) ? ((u32)side * tracks + trk) : ((u32)trk * sides + side);
        u32 t_off = 256u + t_idx * 6400u;
        if (t_off + 6400u > WS->dsk_size) return 0;
        const u8 *tp = WS->dsk + t_off;
        for (u32 i = 0; i + 270u < 6400u; i++) {
            if (tp[i] == 0xA1u && tp[i + 1] == 0xA1u && tp[i + 2] == 0xFEu) {
                if (tp[i + 3] == trk && tp[i + 5] == sec) {
                    for (u32 j = i + 7u; j < i + 80u && j + 260u <= 6400u; j++) {
                        if (tp[j] == 0xA1u && tp[j + 1] == 0xA1u && (tp[j + 2] == 0xFBu || tp[j + 2] == 0xF8u)) {
                            for (int k = 0; k < 256; k++) dst[k] = tp[j + 3u + k];
                            return 1;
                        }
                    }
                }
            }
        }
        return 0;
    }
    /* ORICDISK linear 17 sectors/track (or 16) */
    u32 lin = ((u32)trk * 17u + (sec > 0 ? sec - 1u : 0u)) * 256u + 256u;
    if (lin + 256u <= WS->dsk_size) {
        for (int k = 0; k < 256; k++) dst[k] = WS->dsk[lin + k];
        return 1;
    }
    return 0;
}

static u8 page03_read(u16 addr)
{
    if (WS->has_dsk && addr >= 0x0310u && addr <= 0x031Fu) {
        switch (addr & 0x0Fu) {
        case 0x0: return WS->fdc_stat;
        case 0x1: return WS->fdc_trk;
        case 0x2: return WS->fdc_sec;
        case 0x3:
            if (WS->fdc_drq && WS->fdc_idx < WS->fdc_len) {
                WS->fdc_dat = WS->fdc_buf[WS->fdc_idx++];
                if (WS->fdc_idx >= WS->fdc_len) {
                    WS->fdc_drq = 0;
                    WS->fdc_stat &= ~0x03u;
                }
            }
            return WS->fdc_dat;
        case 0x4: return (u8)((WS->fdc_stat & 1u) ? 0x7Fu : 0xFFu);
        case 0x8: return WS->fdc_drq ? 0x00u : 0x80u;
        default:  return 0xFFu;
        }
    }

    switch (addr & 0x0Fu) {
    case 0x0: { /* VIA IORB: bit 3 = 1 when selected row & (~AY_R14) has a pressed key! */
        u8 row = WS->via_orb & 7u;
        u8 col_mask = (u8)~WS->ay_regs[14];
        u8 hit = (WS->key_mat[row] & col_mask) ? 0x08u : 0x00u;
        u8 in_pins = (u8)(hit | 0x70u);
        WS->via_ifr &= ~0x18u;
        via_recalc_ifr();
        return (u8)((WS->via_orb & WS->via_ddrb) | (in_pins & ~WS->via_ddrb));
    }
    case 0x1:
        WS->via_ifr &= ~0x03u;
        via_recalc_ifr();
        /* fallthrough */
    case 0xF: {
        int bc1  = ((WS->via_pcr >> 1) & 7u) == 7u;
        int bdir = ((WS->via_pcr >> 5) & 7u) == 7u;
        if (bc1 && !bdir && WS->ay_latch < 16u)
            return WS->ay_regs[WS->ay_latch];
        return WS->via_ora;
    }
    case 0x2: return WS->via_ddrb;
    case 0x3: return WS->via_ddra;
    case 0x4:
        WS->via_ifr &= ~0x40u;
        via_recalc_ifr();
        return (u8)(WS->via_t1c & 0xFFu);
    case 0x5: return (u8)(WS->via_t1c >> 8);
    case 0x6: return (u8)(WS->via_t1l & 0xFFu);
    case 0x7: return (u8)(WS->via_t1l >> 8);
    case 0x8:
        WS->via_ifr &= ~0x20u;
        via_recalc_ifr();
        return (u8)(WS->via_t2c & 0xFFu);
    case 0x9: return (u8)(WS->via_t2c >> 8);
    case 0xA: return WS->via_sr;
    case 0xB: return WS->via_acr;
    case 0xC: return WS->via_pcr;
    case 0xD: return WS->via_ifr;
    case 0xE: return (u8)(WS->via_ier | 0x80u);
    }
    return 0xFFu;
}

static void page03_write(u16 addr, u8 v)
{
    if (WS->has_dsk && addr >= 0x0310u && addr <= 0x031Fu) {
        switch (addr & 0x0Fu) {
        case 0x0: {
            WS->fdc_cmd = v;
            u8 hi = v & 0xF0u;
            if (hi == 0x00u) { WS->fdc_trk = 0; WS->fdc_stat = 0x04u; WS->fdc_drq = 0; }
            else if (hi == 0x10u) { WS->fdc_trk = WS->fdc_dat; WS->fdc_stat = (WS->fdc_trk == 0) ? 0x04u : 0u; }
            else if (hi >= 0x40u && hi < 0x60u) { WS->fdc_trk++; WS->fdc_stat = 0; }
            else if (hi == 0x80u || hi == 0x90u) {
                u8 side = (WS->fdc_ctrl >> 4) & 1u;
                if (dsk_read_sector(side, WS->fdc_trk, WS->fdc_sec, WS->fdc_buf)) {
                    WS->fdc_idx = 0; WS->fdc_len = 256; WS->fdc_drq = 1; WS->fdc_stat = 0x03u;
                } else {
                    WS->fdc_drq = 0; WS->fdc_stat = 0x10u;
                }
            } else {
                WS->fdc_drq = 0; WS->fdc_stat = 0;
            }
            break;
        }
        case 0x1: WS->fdc_trk = v; break;
        case 0x2: WS->fdc_sec = v; break;
        case 0x3: WS->fdc_dat = v; break;
        case 0x4: {
            WS->fdc_ctrl = v;
            u8 dis = (v & 0x02u) ? 0u : 1u;
            if (dis != WS->rom_dis) {
                WS->rom_dis = dis;
                setup_mmu();
            }
            break;
        }
        }
        return;
    }

    switch (addr & 0x0Fu) {
    case 0x0:
        WS->via_orb = v;
        WS->via_ifr &= ~0x18u;
        via_recalc_ifr();
        break;
    case 0x1:
        WS->via_ifr &= ~0x03u;
        via_recalc_ifr();
        /* fallthrough */
    case 0xF:
        WS->via_ora = v;
        ay_bus_update();
        break;
    case 0x2: WS->via_ddrb = v; break;
    case 0x3: WS->via_ddra = v; break;
    case 0x4:
    case 0x6:
        WS->via_t1l = (u16)((WS->via_t1l & 0xFF00u) | v);
        break;
    case 0x5:
        WS->via_t1l = (u16)(((u16)v << 8) | (WS->via_t1l & 0xFFu));
        WS->via_t1c = WS->via_t1l;
        WS->via_ifr &= ~0x40u;
        via_recalc_ifr();
        break;
    case 0x7:
        WS->via_t1l = (u16)(((u16)v << 8) | (WS->via_t1l & 0xFFu));
        WS->via_ifr &= ~0x40u;
        via_recalc_ifr();
        break;
    case 0x8: WS->via_t2l_lo = v; break;
    case 0x9:
        WS->via_t2c = (u16)(((u16)v << 8) | WS->via_t2l_lo);
        WS->via_t2_armed = 1;
        WS->via_ifr &= ~0x20u;
        via_recalc_ifr();
        break;
    case 0xA: WS->via_sr = v; break;
    case 0xB: WS->via_acr = v; break;
    case 0xC:
        WS->via_pcr = v;
        ay_bus_update();
        break;
    case 0xD:
        WS->via_ifr &= (u8)~(v & 0x7Fu);
        via_recalc_ifr();
        break;
    case 0xE:
        if (v & 0x80u) WS->via_ier |= (u8)(v & 0x7Fu);
        else           WS->via_ier &= (u8)~(v & 0x7Fu);
        via_recalc_ifr();
        break;
    }
}

static void via_step(s32 dt)
{
    if (dt <= 0) return;
    if ((s32)WS->via_t1c <= dt) {
        WS->via_ifr |= 0x40u;
        via_recalc_ifr();
        if (WS->via_acr & 0x40u) {
            u32 period = (u32)WS->via_t1l + 2u;
            s32 rem = dt - (s32)WS->via_t1c;
            WS->via_t1c = (u16)(period - ((u32)rem % period));
        } else {
            WS->via_t1c = (u16)(WS->via_t1c - dt);
        }
    } else {
        WS->via_t1c = (u16)(WS->via_t1c - dt);
    }

    if (WS->via_t2_armed && !(WS->via_acr & 0x20u)) {
        if ((s32)WS->via_t2c <= dt) {
            WS->via_t2_armed = 0;
            WS->via_ifr |= 0x20u;
            via_recalc_ifr();
        }
        WS->via_t2c = (u16)(WS->via_t2c - dt);
    }
}

/* ---- Fast 1.0 MHz MOS 6502 CPU ---- */

INLINE u8 rd6502(u16 a)
{
    const u8 *pg = WS->rdp[a >> 8];
    return pg ? pg[a & 0xFFu] : page03_read(a);
}

INLINE void wr6502(u16 a, u8 v)
{
    u8 *pg = WS->wrp[a >> 8];
    if (pg) pg[a & 0xFFu] = v;
    else if ((a >> 8) == 0x03u) page03_write(a, v);
}

INLINE u16 rd16_6502(u16 a)
{
    return (u16)(rd6502(a) | ((u16)rd6502((u16)(a + 1u)) << 8));
}

INLINE void push8(u8 v) { WS->ram[0x0100u + WS->s--] = v; }
INLINE u8   pull8(void) { return WS->ram[0x0100u + ++WS->s]; }

INLINE void set_nz(u8 v)
{
    WS->p = (u8)((WS->p & ~(FN | FZ)) | (v & FN) | (v ? 0u : FZ));
}

static void adc6502(u8 m)
{
    u32 c = WS->p & FC;
    if (WS->p & FD) {
        u32 lo = (WS->a & 0x0Fu) + (m & 0x0Fu) + c;
        u32 hi = (WS->a >> 4) + (m >> 4) + (lo > 9u ? 1u : 0u);
        if (lo > 9u) lo += 6u;
        u8 bin = (u8)(WS->a + m + c);
        WS->p &= ~(FC | FZ | FV | FN);
        if (!bin) WS->p |= FZ;
        if (((hi << 4) & 0x80u)) WS->p |= FN;
        if ((~(WS->a ^ m) & (WS->a ^ (u8)((hi << 4) | (lo & 0x0Fu)))) & 0x80u) WS->p |= FV;
        if (hi > 9u) hi += 6u;
        if (hi > 15u) WS->p |= FC;
        WS->a = (u8)((hi << 4) | (lo & 0x0Fu));
    } else {
        u32 sum = (u32)WS->a + m + c;
        u8 r = (u8)sum;
        WS->p &= ~(FC | FZ | FV | FN);
        if (sum > 0xFFu) WS->p |= FC;
        if ((~(WS->a ^ m) & (WS->a ^ r)) & 0x80u) WS->p |= FV;
        WS->a = r;
        set_nz(r);
    }
}

static void sbc6502(u8 m)
{
    if (WS->p & FD) {
        u32 c = (WS->p & FC) ^ 1u;
        s32 lo = (s32)(WS->a & 0x0Fu) - (s32)(m & 0x0Fu) - (s32)c;
        s32 hi = (s32)(WS->a >> 4) - (s32)(m >> 4) - (lo < 0 ? 1 : 0);
        u32 diff = (u32)WS->a - m - c;
        u8 bin = (u8)diff;
        WS->p &= ~(FC | FZ | FV | FN);
        if (diff < 0x100u) WS->p |= FC;
        if (!bin) WS->p |= FZ;
        if (bin & 0x80u) WS->p |= FN;
        if (((WS->a ^ m) & (WS->a ^ bin)) & 0x80u) WS->p |= FV;
        if (lo < 0) lo -= 6;
        if (hi < 0) hi -= 6;
        WS->a = (u8)(((u32)hi << 4) | ((u32)lo & 0x0Fu));
    } else {
        adc6502((u8)~m);
    }
}

INLINE void cmp6502(u8 reg, u8 m)
{
    u16 d = (u16)reg - m;
    WS->p = (u8)((WS->p & ~(FC | FZ | FN)) | (reg >= m ? FC : 0u) | ((u8)d ? 0u : FZ) | ((u8)d & FN));
}

INLINE void branch6502(int cond)
{
    s32 off = (signed char)rd6502(WS->pc++);
    if (cond) {
        u16 np = (u16)(WS->pc + off);
        WS->cycles += ((np ^ WS->pc) & 0xFF00u) ? 2 : 1;
        WS->pc = np;
    }
}

static s32 step6502(void)
{
    if (WS->nmi_pend) {
        WS->nmi_pend = 0;
        push8((u8)(WS->pc >> 8));
        push8((u8)WS->pc);
        push8((u8)((WS->p | FU) & ~FB));
        WS->p |= FI;
        WS->pc = rd16_6502(0xFFFAu);
        return 7;
    }
    if ((WS->via_ifr & 0x80u) && !(WS->p & FI)) {
        push8((u8)(WS->pc >> 8));
        push8((u8)WS->pc);
        push8((u8)((WS->p | FU) & ~FB));
        WS->p |= FI;
        WS->pc = rd16_6502(0xFFFEu);
        return 7;
    }

    s32 c0 = WS->cycles;
    u8 op = rd6502(WS->pc++);
    u16 ea = 0;
    u8 v = 0;

#define IMM()   (WS->pc++)
#define ZP()    ((u16)rd6502(WS->pc++))
#define ZPX()   ((u16)((rd6502(WS->pc++) + WS->x) & 0xFFu))
#define ZPY()   ((u16)((rd6502(WS->pc++) + WS->y) & 0xFFu))
#define ABS()   (ea = rd16_6502(WS->pc), WS->pc += 2, ea)
#define ABX()   (ea = rd16_6502(WS->pc), WS->pc += 2, (u16)(ea + WS->x))
#define ABY()   (ea = rd16_6502(WS->pc), WS->pc += 2, (u16)(ea + WS->y))
#define INDX()  (v = (u8)(rd6502(WS->pc++) + WS->x), (u16)(WS->ram[v] | ((u16)WS->ram[(u8)(v + 1u)] << 8)))
#define INDY()  (v = rd6502(WS->pc++), (u16)((WS->ram[v] | ((u16)WS->ram[(u8)(v + 1u)] << 8)) + WS->y))

    switch (op) {
    case 0x00: WS->pc++; push8((u8)(WS->pc >> 8)); push8((u8)WS->pc); push8((u8)(WS->p | FU | FB));
               WS->p |= FI; WS->pc = rd16_6502(0xFFFEu); WS->cycles += 7; break;
    case 0x01: WS->a |= rd6502(INDX()); set_nz(WS->a); WS->cycles += 6; break;
    case 0x05: WS->a |= WS->ram[ZP()];  set_nz(WS->a); WS->cycles += 3; break;
    case 0x06: ea = ZP(); v = WS->ram[ea]; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v <<= 1; WS->ram[ea] = v; set_nz(v); WS->cycles += 5; break;
    case 0x08: push8((u8)(WS->p | FU | FB)); WS->cycles += 3; break;
    case 0x09: WS->a |= rd6502(IMM()); set_nz(WS->a); WS->cycles += 2; break;
    case 0x0A: WS->p = (u8)((WS->p & ~FC) | (WS->a >> 7)); WS->a <<= 1; set_nz(WS->a); WS->cycles += 2; break;
    case 0x0D: WS->a |= rd6502(ABS()); set_nz(WS->a); WS->cycles += 4; break;
    case 0x0E: ea = ABS(); v = rd6502(ea); WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v <<= 1; wr6502(ea, v); set_nz(v); WS->cycles += 6; break;
    case 0x10: branch6502(!(WS->p & FN)); WS->cycles += 2; break;
    case 0x11: WS->a |= rd6502(INDY()); set_nz(WS->a); WS->cycles += 5; break;
    case 0x15: WS->a |= WS->ram[ZPX()]; set_nz(WS->a); WS->cycles += 4; break;
    case 0x16: ea = ZPX(); v = WS->ram[ea]; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v <<= 1; WS->ram[ea] = v; set_nz(v); WS->cycles += 6; break;
    case 0x18: WS->p &= ~FC; WS->cycles += 2; break;
    case 0x19: WS->a |= rd6502(ABY()); set_nz(WS->a); WS->cycles += 4; break;
    case 0x1D: WS->a |= rd6502(ABX()); set_nz(WS->a); WS->cycles += 4; break;
    case 0x1E: ea = ABX(); v = rd6502(ea); WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v <<= 1; wr6502(ea, v); set_nz(v); WS->cycles += 7; break;

    case 0x20: ea = ABS(); WS->pc--; push8((u8)(WS->pc >> 8)); push8((u8)WS->pc); WS->pc = ea; WS->cycles += 6; break;
    case 0x21: WS->a &= rd6502(INDX()); set_nz(WS->a); WS->cycles += 6; break;
    case 0x24: v = WS->ram[ZP()]; WS->p = (u8)((WS->p & ~(FZ | FV | FN)) | (v & (FV | FN)) | ((WS->a & v) ? 0u : FZ)); WS->cycles += 3; break;
    case 0x25: WS->a &= WS->ram[ZP()]; set_nz(WS->a); WS->cycles += 3; break;
    case 0x26: ea = ZP(); v = WS->ram[ea]; { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v = (u8)((v << 1) | c); } WS->ram[ea] = v; set_nz(v); WS->cycles += 5; break;
    case 0x28: WS->p = (u8)((pull8() & ~FB) | FU); WS->cycles += 4; break;
    case 0x29: WS->a &= rd6502(IMM()); set_nz(WS->a); WS->cycles += 2; break;
    case 0x2A: { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (WS->a >> 7)); WS->a = (u8)((WS->a << 1) | c); } set_nz(WS->a); WS->cycles += 2; break;
    case 0x2C: v = rd6502(ABS()); WS->p = (u8)((WS->p & ~(FZ | FV | FN)) | (v & (FV | FN)) | ((WS->a & v) ? 0u : FZ)); WS->cycles += 4; break;
    case 0x2D: WS->a &= rd6502(ABS()); set_nz(WS->a); WS->cycles += 4; break;
    case 0x2E: ea = ABS(); v = rd6502(ea); { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v = (u8)((v << 1) | c); } wr6502(ea, v); set_nz(v); WS->cycles += 6; break;
    case 0x30: branch6502((WS->p & FN) != 0); WS->cycles += 2; break;
    case 0x31: WS->a &= rd6502(INDY()); set_nz(WS->a); WS->cycles += 5; break;
    case 0x35: WS->a &= WS->ram[ZPX()]; set_nz(WS->a); WS->cycles += 4; break;
    case 0x36: ea = ZPX(); v = WS->ram[ea]; { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v = (u8)((v << 1) | c); } WS->ram[ea] = v; set_nz(v); WS->cycles += 6; break;
    case 0x38: WS->p |= FC; WS->cycles += 2; break;
    case 0x39: WS->a &= rd6502(ABY()); set_nz(WS->a); WS->cycles += 4; break;
    case 0x3D: WS->a &= rd6502(ABX()); set_nz(WS->a); WS->cycles += 4; break;
    case 0x3E: ea = ABX(); v = rd6502(ea); { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v = (u8)((v << 1) | c); } wr6502(ea, v); set_nz(v); WS->cycles += 7; break;

    case 0x40: WS->p = (u8)((pull8() & ~FB) | FU); v = pull8(); WS->pc = (u16)(v | ((u16)pull8() << 8)); WS->cycles += 6; break;
    case 0x41: WS->a ^= rd6502(INDX()); set_nz(WS->a); WS->cycles += 6; break;
    case 0x45: WS->a ^= WS->ram[ZP()]; set_nz(WS->a); WS->cycles += 3; break;
    case 0x46: ea = ZP(); v = WS->ram[ea]; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v >>= 1; WS->ram[ea] = v; set_nz(v); WS->cycles += 5; break;
    case 0x48: push8(WS->a); WS->cycles += 3; break;
    case 0x49: WS->a ^= rd6502(IMM()); set_nz(WS->a); WS->cycles += 2; break;
    case 0x4A: WS->p = (u8)((WS->p & ~FC) | (WS->a & 1u)); WS->a >>= 1; set_nz(WS->a); WS->cycles += 2; break;
    case 0x4C: WS->pc = ABS(); WS->cycles += 3; break;
    case 0x4D: WS->a ^= rd6502(ABS()); set_nz(WS->a); WS->cycles += 4; break;
    case 0x4E: ea = ABS(); v = rd6502(ea); WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v >>= 1; wr6502(ea, v); set_nz(v); WS->cycles += 6; break;
    case 0x50: branch6502(!(WS->p & FV)); WS->cycles += 2; break;
    case 0x51: WS->a ^= rd6502(INDY()); set_nz(WS->a); WS->cycles += 5; break;
    case 0x55: WS->a ^= WS->ram[ZPX()]; set_nz(WS->a); WS->cycles += 4; break;
    case 0x56: ea = ZPX(); v = WS->ram[ea]; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v >>= 1; WS->ram[ea] = v; set_nz(v); WS->cycles += 6; break;
    case 0x58: WS->p &= ~FI; WS->cycles += 2; break;
    case 0x59: WS->a ^= rd6502(ABY()); set_nz(WS->a); WS->cycles += 4; break;
    case 0x5D: WS->a ^= rd6502(ABX()); set_nz(WS->a); WS->cycles += 4; break;
    case 0x5E: ea = ABX(); v = rd6502(ea); WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v >>= 1; wr6502(ea, v); set_nz(v); WS->cycles += 7; break;

    case 0x60: v = pull8(); WS->pc = (u16)((v | ((u16)pull8() << 8)) + 1u); WS->cycles += 6; break;
    case 0x61: adc6502(rd6502(INDX())); WS->cycles += 6; break;
    case 0x65: adc6502(WS->ram[ZP()]); WS->cycles += 3; break;
    case 0x66: ea = ZP(); v = WS->ram[ea]; { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v = (u8)((v >> 1) | (c << 7)); } WS->ram[ea] = v; set_nz(v); WS->cycles += 5; break;
    case 0x68: WS->a = pull8(); set_nz(WS->a); WS->cycles += 4; break;
    case 0x69: adc6502(rd6502(IMM())); WS->cycles += 2; break;
    case 0x6A: { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (WS->a & 1u)); WS->a = (u8)((WS->a >> 1) | (c << 7)); } set_nz(WS->a); WS->cycles += 2; break;
    case 0x6C: ea = ABS(); WS->pc = (u16)(rd6502(ea) | ((u16)rd6502((u16)((ea & 0xFF00u) | ((ea + 1u) & 0xFFu))) << 8)); WS->cycles += 5; break;
    case 0x6D: adc6502(rd6502(ABS())); WS->cycles += 4; break;
    case 0x6E: ea = ABS(); v = rd6502(ea); { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v = (u8)((v >> 1) | (c << 7)); } wr6502(ea, v); set_nz(v); WS->cycles += 6; break;
    case 0x70: branch6502((WS->p & FV) != 0); WS->cycles += 2; break;
    case 0x71: adc6502(rd6502(INDY())); WS->cycles += 5; break;
    case 0x75: adc6502(WS->ram[ZPX()]); WS->cycles += 4; break;
    case 0x76: ea = ZPX(); v = WS->ram[ea]; { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v = (u8)((v >> 1) | (c << 7)); } WS->ram[ea] = v; set_nz(v); WS->cycles += 6; break;
    case 0x78: WS->p |= FI; WS->cycles += 2; break;
    case 0x79: adc6502(rd6502(ABY())); WS->cycles += 4; break;
    case 0x7D: adc6502(rd6502(ABX())); WS->cycles += 4; break;
    case 0x7E: ea = ABX(); v = rd6502(ea); { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v = (u8)((v >> 1) | (c << 7)); } wr6502(ea, v); set_nz(v); WS->cycles += 7; break;

    case 0x81: wr6502(INDX(), WS->a); WS->cycles += 6; break;
    case 0x84: WS->ram[ZP()] = WS->y; WS->cycles += 3; break;
    case 0x85: WS->ram[ZP()] = WS->a; WS->cycles += 3; break;
    case 0x86: WS->ram[ZP()] = WS->x; WS->cycles += 3; break;
    case 0x88: WS->y--; set_nz(WS->y); WS->cycles += 2; break;
    case 0x8A: WS->a = WS->x; set_nz(WS->a); WS->cycles += 2; break;
    case 0x8C: wr6502(ABS(), WS->y); WS->cycles += 4; break;
    case 0x8D: wr6502(ABS(), WS->a); WS->cycles += 4; break;
    case 0x8E: wr6502(ABS(), WS->x); WS->cycles += 4; break;
    case 0x90: branch6502(!(WS->p & FC)); WS->cycles += 2; break;
    case 0x91: wr6502(INDY(), WS->a); WS->cycles += 6; break;
    case 0x94: WS->ram[ZPX()] = WS->y; WS->cycles += 4; break;
    case 0x95: WS->ram[ZPX()] = WS->a; WS->cycles += 4; break;
    case 0x96: WS->ram[ZPY()] = WS->x; WS->cycles += 4; break;
    case 0x98: WS->a = WS->y; set_nz(WS->a); WS->cycles += 2; break;
    case 0x99: wr6502(ABY(), WS->a); WS->cycles += 5; break;
    case 0x9A: WS->s = WS->x; WS->cycles += 2; break;
    case 0x9D: wr6502(ABX(), WS->a); WS->cycles += 5; break;

    case 0xA0: WS->y = rd6502(IMM()); set_nz(WS->y); WS->cycles += 2; break;
    case 0xA1: WS->a = rd6502(INDX()); set_nz(WS->a); WS->cycles += 6; break;
    case 0xA2: WS->x = rd6502(IMM()); set_nz(WS->x); WS->cycles += 2; break;
    case 0xA4: WS->y = WS->ram[ZP()]; set_nz(WS->y); WS->cycles += 3; break;
    case 0xA5: WS->a = WS->ram[ZP()]; set_nz(WS->a); WS->cycles += 3; break;
    case 0xA6: WS->x = WS->ram[ZP()]; set_nz(WS->x); WS->cycles += 3; break;
    case 0xA8: WS->y = WS->a; set_nz(WS->y); WS->cycles += 2; break;
    case 0xA9: WS->a = rd6502(IMM()); set_nz(WS->a); WS->cycles += 2; break;
    case 0xAA: WS->x = WS->a; set_nz(WS->x); WS->cycles += 2; break;
    case 0xAC: WS->y = rd6502(ABS()); set_nz(WS->y); WS->cycles += 4; break;
    case 0xAD: WS->a = rd6502(ABS()); set_nz(WS->a); WS->cycles += 4; break;
    case 0xAE: WS->x = rd6502(ABS()); set_nz(WS->x); WS->cycles += 4; break;
    case 0xB0: branch6502((WS->p & FC) != 0); WS->cycles += 2; break;
    case 0xB1: WS->a = rd6502(INDY()); set_nz(WS->a); WS->cycles += 5; break;
    case 0xB4: WS->y = WS->ram[ZPX()]; set_nz(WS->y); WS->cycles += 4; break;
    case 0xB5: WS->a = WS->ram[ZPX()]; set_nz(WS->a); WS->cycles += 4; break;
    case 0xB6: WS->x = WS->ram[ZPY()]; set_nz(WS->x); WS->cycles += 4; break;
    case 0xB8: WS->p &= ~FV; WS->cycles += 2; break;
    case 0xB9: WS->a = rd6502(ABY()); set_nz(WS->a); WS->cycles += 4; break;
    case 0xBA: WS->x = WS->s; set_nz(WS->x); WS->cycles += 2; break;
    case 0xBC: WS->y = rd6502(ABX()); set_nz(WS->y); WS->cycles += 4; break;
    case 0xBD: WS->a = rd6502(ABX()); set_nz(WS->a); WS->cycles += 4; break;
    case 0xBE: WS->x = rd6502(ABY()); set_nz(WS->x); WS->cycles += 4; break;

    case 0xC0: cmp6502(WS->y, rd6502(IMM())); WS->cycles += 2; break;
    case 0xC1: cmp6502(WS->a, rd6502(INDX())); WS->cycles += 6; break;
    case 0xC4: cmp6502(WS->y, WS->ram[ZP()]); WS->cycles += 3; break;
    case 0xC5: cmp6502(WS->a, WS->ram[ZP()]); WS->cycles += 3; break;
    case 0xC6: ea = ZP(); v = (u8)(WS->ram[ea] - 1u); WS->ram[ea] = v; set_nz(v); WS->cycles += 5; break;
    case 0xC8: WS->y++; set_nz(WS->y); WS->cycles += 2; break;
    case 0xC9: cmp6502(WS->a, rd6502(IMM())); WS->cycles += 2; break;
    case 0xCA: WS->x--; set_nz(WS->x); WS->cycles += 2; break;
    case 0xCC: cmp6502(WS->y, rd6502(ABS())); WS->cycles += 4; break;
    case 0xCD: cmp6502(WS->a, rd6502(ABS())); WS->cycles += 4; break;
    case 0xCE: ea = ABS(); v = (u8)(rd6502(ea) - 1u); wr6502(ea, v); set_nz(v); WS->cycles += 6; break;
    case 0xD0: branch6502(!(WS->p & FZ)); WS->cycles += 2; break;
    case 0xD1: cmp6502(WS->a, rd6502(INDY())); WS->cycles += 5; break;
    case 0xD5: cmp6502(WS->a, WS->ram[ZPX()]); WS->cycles += 4; break;
    case 0xD6: ea = ZPX(); v = (u8)(WS->ram[ea] - 1u); WS->ram[ea] = v; set_nz(v); WS->cycles += 6; break;
    case 0xD8: WS->p &= ~FD; WS->cycles += 2; break;
    case 0xD9: cmp6502(WS->a, rd6502(ABY())); WS->cycles += 4; break;
    case 0xDD: cmp6502(WS->a, rd6502(ABX())); WS->cycles += 4; break;
    case 0xDE: ea = ABX(); v = (u8)(rd6502(ea) - 1u); wr6502(ea, v); set_nz(v); WS->cycles += 7; break;

    case 0xE0: cmp6502(WS->x, rd6502(IMM())); WS->cycles += 2; break;
    case 0xE1: sbc6502(rd6502(INDX())); WS->cycles += 6; break;
    case 0xE4: cmp6502(WS->x, WS->ram[ZP()]); WS->cycles += 3; break;
    case 0xE5: sbc6502(WS->ram[ZP()]); WS->cycles += 3; break;
    case 0xE6: ea = ZP(); v = (u8)(WS->ram[ea] + 1u); WS->ram[ea] = v; set_nz(v); WS->cycles += 5; break;
    case 0xE8: WS->x++; set_nz(WS->x); WS->cycles += 2; break;
    case 0xE9: case 0xEB: sbc6502(rd6502(IMM())); WS->cycles += 2; break;
    case 0xEA: WS->cycles += 2; break;
    case 0xEC: cmp6502(WS->x, rd6502(ABS())); WS->cycles += 4; break;
    case 0xED: sbc6502(rd6502(ABS())); WS->cycles += 4; break;
    case 0xEE: ea = ABS(); v = (u8)(rd6502(ea) + 1u); wr6502(ea, v); set_nz(v); WS->cycles += 6; break;
    case 0xF0: branch6502((WS->p & FZ) != 0); WS->cycles += 2; break;
    case 0xF1: sbc6502(rd6502(INDY())); WS->cycles += 5; break;
    case 0xF5: sbc6502(WS->ram[ZPX()]); WS->cycles += 4; break;
    case 0xF6: ea = ZPX(); v = (u8)(WS->ram[ea] + 1u); WS->ram[ea] = v; set_nz(v); WS->cycles += 6; break;
    case 0xF8: WS->p |= FD; WS->cycles += 2; break;
    case 0xF9: sbc6502(rd6502(ABY())); WS->cycles += 4; break;
    case 0xFD: sbc6502(rd6502(ABX())); WS->cycles += 4; break;
    case 0xFE: ea = ABX(); v = (u8)(rd6502(ea) + 1u); wr6502(ea, v); set_nz(v); WS->cycles += 7; break;

    /* Common 6502 undocumented NOPs + LAX/SAX */
    case 0xA7: WS->a = WS->x = WS->ram[ZP()]; set_nz(WS->a); WS->cycles += 3; break;
    case 0xB7: WS->a = WS->x = WS->ram[ZPY()]; set_nz(WS->a); WS->cycles += 4; break;
    case 0xAF: WS->a = WS->x = rd6502(ABS()); set_nz(WS->a); WS->cycles += 4; break;
    case 0xBF: WS->a = WS->x = rd6502(ABY()); set_nz(WS->a); WS->cycles += 4; break;
    case 0x87: WS->ram[ZP()] = (u8)(WS->a & WS->x); WS->cycles += 3; break;
    case 0x8F: wr6502(ABS(), (u8)(WS->a & WS->x)); WS->cycles += 4; break;
    case 0x04: case 0x44: case 0x64: WS->pc++; WS->cycles += 3; break;
    case 0x0C: WS->pc += 2; WS->cycles += 4; break;
    case 0x14: case 0x34: case 0x54: case 0x74: case 0xD4: case 0xF4: WS->pc++; WS->cycles += 4; break;
    case 0x1C: case 0x3C: case 0x5C: case 0x7C: case 0xDC: case 0xFC: WS->pc += 2; WS->cycles += 4; break;
    case 0x02: case 0x12: case 0x22: case 0x32: case 0x42: case 0x52:
    case 0x62: case 0x72: case 0x92: case 0xB2: case 0xD2: case 0xF2:
        WS->jam = 1; WS->pc--; WS->cycles += 2; break;
    default:
        WS->cycles += 2; break;
    }

    return WS->cycles - c0;
}

/* ---- HCS10017 Serial-Attribute ULA Video Renderer (240 x 224) ---- */

static void render_oric_ula(u16 *pic)
{
    u8 hires = WS->hires;
    int flash_off = (WS->frames & 16u) != 0;

    for (int y = 0; y < ORIC_H; y++) {
        u16 *dst = pic + y * ORIC_W;
        u8 ink = 7u, paper = 0u, alt = 0u, dbl = 0u, blink = 0u;

        for (int col = 0; col < 40; col++) {
            int cell_hires = hires && (y < 200);
            u8 b = cell_hires
                ? WS->ram[0xA000u + y * 40 + col]
                : WS->ram[0xBB80u + (y >> 3) * 40 + col];

            int inv = (b & 0x80u) != 0;
            u8 code = b & 0x7Fu;
            u8 bits = 0;

            if (code < 0x20u) {
                if (code < 0x08u) {
                    ink = code & 7u;
                } else if (code < 0x10u) {
                    alt   = code & 1u;
                    dbl   = (code >> 1) & 1u;
                    blink = (code >> 2) & 1u;
                } else if (code < 0x18u) {
                    paper = code & 7u;
                } else if (code < 0x1Cu) {
                    hires = 0u;
                } else {
                    hires = 1u;
                }
                bits = 0u;
            } else if (cell_hires) {
                bits = b & 0x3Fu;
            } else {
                u16 fbase = hires ? (alt ? 0x9C00u : 0x9800u) : (alt ? 0xB800u : 0xB400u);
                int py = dbl ? ((y & 15) >> 1) : (y & 7);
                bits = (blink && flash_off) ? 0u : (u8)(WS->ram[fbase + (u16)code * 8u + py] & 0x3Fu);
            }

            u16 c_on  = oric_pal15[inv ? (ink ^ 7u)   : ink];
            u16 c_off = oric_pal15[inv ? (paper ^ 7u) : paper];
            u16 *cell = dst + col * 6;
            cell[0] = (bits & 0x20u) ? c_on : c_off;
            cell[1] = (bits & 0x10u) ? c_on : c_off;
            cell[2] = (bits & 0x08u) ? c_on : c_off;
            cell[3] = (bits & 0x04u) ? c_on : c_off;
            cell[4] = (bits & 0x02u) ? c_on : c_off;
            cell[5] = (bits & 0x01u) ? c_on : c_off;
        }
    }
    WS->hires = hires;
}

/* ---- Clean-Room Oric Atmos v1.1 OS/BASIC ROM & Font ---- */

static void load_oric_fonts(void)
{
    for (int c = 32; c < 128; c++) {
        const u8 *g = font5x7[c - 32];
        for (int py = 0; py < 8; py++) {
            u8 row = 0;
            if (py < 7) {
                for (int px = 0; px < 5; px++)
                    if (g[px] & (1u << py)) row |= (u8)(0x20u >> px);
            }
            WS->ram[0xB400u + c * 8 + py] = row;
            WS->ram[0x9800u + c * 8 + py] = row;
        }
    }
}

static void build_cleanroom_atmos_rom(u16 boot_pc)
{
    if (WS->ext_rom_loaded) return;
    ws_zero(WS->rom, sizeof(WS->rom));
    for (u32 i = 0; i < sizeof(WS->rom); i++) WS->rom[i] = 0xEAu; /* NOP */

    /* Put standard font in ROM at $F900 ($3900) as on Atmos v1.1 */
    for (int c = 32; c < 128; c++)
        for (int py = 0; py < 8; py++)
            WS->rom[0x3800u + c * 8 + py] = WS->ram[0xB400u + c * 8 + py];

    /* Default IRQ handler at $EE22 ($2E22):
       PHA; LDA #$7F; STA $030D; PLA; RTI */
    u32 ih = 0x2E22u;
    WS->rom[ih + 0] = 0x48u;
    WS->rom[ih + 1] = 0xA9u; WS->rom[ih + 2] = 0x7Fu;
    WS->rom[ih + 3] = 0x8Du; WS->rom[ih + 4] = 0x0Du; WS->rom[ih + 5] = 0x03u;
    WS->rom[ih + 6] = 0x68u;
    WS->rom[ih + 7] = 0x40u;

    /* Atmos v1.1 Reset Routine at $F88F ($388F):
       SEI; CLD; LDX #$FF; TXS
       Set $0230 = $00 (Atmos v1.1 marker), $0244 = JMP $EE22 (default IRQ)
       Configure 6522 VIA Timer 1 = $2710 (100 Hz), ACR = $40 (free-run), IER = $C0
       CLI; JMP boot_pc */
    u32 r = 0x388Fu;
    #define EMIT(b) WS->rom[r++] = (u8)(b)
    EMIT(0x78); EMIT(0xD8); EMIT(0xA2); EMIT(0xFF); EMIT(0x9A);
    EMIT(0xA9); EMIT(0x00); EMIT(0x8D); EMIT(0x30); EMIT(0x02); /* STA $0230 */
    EMIT(0xA9); EMIT(0x28); EMIT(0x85); EMIT(0x28);             /* ZP $28 = 40 (VramWidth safety!) */
    EMIT(0xA9); EMIT(0x4C); EMIT(0x8D); EMIT(0x44); EMIT(0x02); /* JMP $EE22 at $0244 */
    EMIT(0xA9); EMIT(0x22); EMIT(0x8D); EMIT(0x45); EMIT(0x02);
    EMIT(0xA9); EMIT(0xEE); EMIT(0x8D); EMIT(0x46); EMIT(0x02);
    /* VIA setup: DDRB=$F7, DDRA=$FF, ACR=$40, PCR=$CC, T1L=$270E (10,000 us = 100 Hz), IER=$C0 */
    EMIT(0xA9); EMIT(0xF7); EMIT(0x8D); EMIT(0x02); EMIT(0x03);
    EMIT(0xA9); EMIT(0xFF); EMIT(0x8D); EMIT(0x03); EMIT(0x03);
    EMIT(0xA9); EMIT(0x40); EMIT(0x8D); EMIT(0x0B); EMIT(0x03);
    EMIT(0xA9); EMIT(0xCC); EMIT(0x8D); EMIT(0x0C); EMIT(0x03);
    EMIT(0xA9); EMIT(0x0E); EMIT(0x8D); EMIT(0x04); EMIT(0x03);
    EMIT(0xA9); EMIT(0x27); EMIT(0x8D); EMIT(0x05); EMIT(0x03);
    EMIT(0xA9); EMIT(0xC0); EMIT(0x8D); EMIT(0x0E); EMIT(0x03);
    EMIT(0x58);                                                 /* CLI */
    if (boot_pc) {
        EMIT(0x4C); EMIT(boot_pc & 0xFFu); EMIT(boot_pc >> 8);
    } else {
        u32 spin = 0xC000u + r;
        EMIT(0x4C); EMIT(spin & 0xFFu); EMIT(spin >> 8);        /* Spin in BASIC interactive mode */
    }
    #undef EMIT

    /* Vectors: NMI=$EE22, RESET=$F88F, IRQ=$0244 (Atmos v1.1 RAM vector!) */
    WS->rom[0x3FFA] = 0x22u; WS->rom[0x3FFB] = 0xEEu;
    WS->rom[0x3FFC] = 0x8Fu; WS->rom[0x3FFD] = 0xF8u;
    WS->rom[0x3FFE] = 0x44u; WS->rom[0x3FFF] = 0x02u;
}

static void basic_puts(int x, int y, const char *s)
{
    while (*s && y < 28) {
        if (*s == '\n') { x = 2; y++; s++; continue; }
        if (x >= 39) { x = 2; y++; if (y >= 28) break; }
        WS->ram[0xBB80u + y * 40 + x] = (u8)*s++;
        x++;
    }
    WS->bas_x = (u8)x;
    WS->bas_y = (u8)y;
}

static void basic_init(void)
{
    /* Classic Oric Atmos Red/White status bar + Black/Yellow/White prompt */
    for (int i = 0; i < 40 * 28; i++) WS->ram[0xBB80u + i] = ' ';
    WS->ram[0xBB80u + 0] = 0x11u;       /* Red paper */
    WS->ram[0xBB80u + 1] = 0x07u;       /* White ink */
    basic_puts(2, 0, "ORIC EXTENDED BASIC V1.1");
    for (int y = 1; y < 28; y++) {
        WS->ram[0xBB80u + y * 40 + 0] = 0x14u; /* Blue paper */
        WS->ram[0xBB80u + y * 40 + 1] = 0x07u; /* White ink */
    }
    basic_puts(2, 2, "(C) 1983 TANGERINE");
    basic_puts(2, 4, "37631 BYTES FREE");
    basic_puts(2, 6, "Ready");
    basic_puts(2, 7, "");
    WS->bas_len = 0;
}

static void basic_step(void)
{
    while (WS->type_r != WS->type_w) {
        char c = WS->type_q[WS->type_r];
        WS->type_r = (WS->type_r + 1u) & 63u;
        if (c == '\r' || c == '\n') {
            WS->ram[0xBB80u + WS->bas_y * 40 + WS->bas_x] = ' ';
            if (WS->bas_y < 26) WS->bas_y++;
            basic_puts(2, WS->bas_y, "Ready");
            if (WS->bas_y < 26) WS->bas_y++;
            WS->bas_x = 2;
            WS->bas_len = 0;
        } else if ((c == 8 || c == 127) && WS->bas_len > 0) {
            WS->ram[0xBB80u + WS->bas_y * 40 + WS->bas_x] = ' ';
            WS->bas_len--;
            if (WS->bas_x > 2) WS->bas_x--;
        } else if (c >= 32 && c < 127 && WS->bas_x < 39) {
            WS->bas_line[WS->bas_len < 38 ? WS->bas_len++ : 38] = c;
            WS->ram[0xBB80u + WS->bas_y * 40 + WS->bas_x++] = (u8)c;
        }
    }
    WS->ram[0xBB80u + WS->bas_y * 40 + WS->bas_x] = (WS->frames & 16u) ? (u8)(' ' | 0x80u) : ' ';
}

static int parse_oric_tap(const u8 *data, u32 size)
{
    u32 p = 0;
    int blocks = 0;
    u16 entry = 0;
    while (p < size) {
        u32 syncs = 0;
        while (p < size && data[p] == 0x16u) { p++; syncs++; }
        if (!syncs) { p++; continue; }
        if (p >= size || data[p] != 0x24u) continue;
        p++;
        if (p + 9u > size) break;
        u8 is_ml = data[p + 2];
        u8 auto_run = data[p + 3];
        u16 end_addr   = (u16)(((u16)data[p + 4] << 8) | data[p + 5]);
        u16 start_addr = (u16)(((u16)data[p + 6] << 8) | data[p + 7]);
        p += 9u;

        int k = 0;
        while (p < size && data[p] != 0u) {
            if (blocks == 0 && k < 28 && data[p] >= 32u && data[p] < 127u)
                WS->title[k++] = (char)data[p];
            p++;
        }
        if (blocks == 0) WS->title[k] = 0;
        if (p < size && data[p] == 0u) p++;

        if (end_addr < start_addr) break;
        u32 len = (u32)(end_addr - start_addr) + 1u;
        u32 avail = (p < size) ? (size - p) : 0u;
        if (len > avail) len = avail;
        for (u32 i = 0; i < len; i++) {
            u16 dst = (u16)(start_addr + i);
            if (dst < 0xC000u) WS->ram[dst] = data[p + i];
        }
        p += len;
        blocks++;
        if (is_ml >= 0x80u || (auto_run && !entry))
            entry = start_addr;
        else if (!entry)
            entry = start_addr;
    }
    if (blocks > 0) {
        WS->has_prog = 1;
        WS->prog_entry = entry ? entry : 0x0400u;
        return 1;
    }
    return 0;
}

static void fmt_info(void)
{
    char *o = WS->info;
    const char *p = "Tangerine Oric Atmos 48K (6502 + ULA + AY-3-8912, ";
    while (*p) *o++ = *p++;
    const char *s = WS->basic_mode ? "BASIC v1.1)" :
                    WS->has_dsk    ? "MFM Disk)" :
                    WS->title[0]   ? WS->title : "Tape)";
    while (*s) *o++ = *s++;
    if (!WS->basic_mode && !WS->has_dsk && WS->title[0]) *o++ = ')';
    *o = 0;
}

const char *oric_load(const u8 *image, u32 size, const char *path,
                      const u8 *ext_rom, u32 ext_rom_sz)
{
#ifdef ORIC_HOST
    u32 sr = WS->sample_rate;
#endif
    ws_zero(WS, sizeof(*WS));
#ifdef ORIC_HOST
    WS->sample_rate = sr ? sr : 48000u;
#else
    WS->sample_rate = 48000u;
#endif

    if (ext_rom && ext_rom_sz == 0x4000u) {
        for (u32 i = 0; i < 0x4000u; i++) WS->rom[i] = ext_rom[i];
        WS->ext_rom_loaded = 1;
    }

    if (!image || size == 0) {
        WS->basic_mode = 1;
        oric_reset();
        fmt_info();
        return 0;
    }

    if (ci_ends(path, ".dsk") ||
        (size >= 256u && image[0] == 'M' && image[1] == 'F' && image[2] == 'M' && image[3] == '_') ||
        (size >= 256u && image[0] == 'O' && image[1] == 'R' && image[2] == 'I' && image[3] == 'C')) {
        u32 n = size > DSK_MAX ? DSK_MAX : size;
        for (u32 i = 0; i < n; i++) WS->dsk[i] = image[i];
        WS->dsk_size = n;
        WS->has_dsk = 1;
        oric_reset();
        fmt_info();
        return 0;
    }

    WS->tap_len = size > sizeof(WS->tap_buf) ? (u32)sizeof(WS->tap_buf) : size;
    for (u32 i = 0; i < WS->tap_len; i++)
        WS->tap_buf[i] = image[i];

    oric_reset();
    if (!WS->has_prog)
        return "not a valid Oric .tap or .dsk image";
    fmt_info();
    return 0;
}

void oric_reset(void)
{
    ws_zero(WS->ram, sizeof(WS->ram));
    WS->rom_dis = 0;
    WS->hires = 0;
    WS->frames = 0;
    WS->jam = 0;
    WS->nmi_pend = 0;
    WS->cycles = 0;
    WS->ay_lfsr = 1u;
    WS->ay_regs[7] = 0x3Fu;
    WS->ay_regs[14] = 0xFFu;

    for (int i = 0; i < 40 * 28; i++)
        WS->ram[0xBB80u + i] = ' ';
    load_oric_fonts();

    WS->has_prog = 0;
    WS->prog_entry = 0;
    if (WS->has_dsk) {
        u8 sec1[256];
        if (dsk_read_sector(0, 0, 1, sec1)) {
            for (int i = 0; i < 256; i++) WS->ram[0x0400u + i] = sec1[i];
            WS->has_prog = 1;
            WS->prog_entry = 0x0400u;
        }
    } else if (!WS->basic_mode && WS->tap_len > 0) {
        parse_oric_tap(WS->tap_buf, WS->tap_len);
    }

    build_cleanroom_atmos_rom(WS->has_prog ? WS->prog_entry : 0u);
    if (WS->basic_mode && !WS->ext_rom_loaded)
        basic_init();

    setup_mmu();
    WS->s = 0xFDu;
    WS->p = FI | FU;
    WS->a = WS->x = WS->y = 0;
    WS->pc = rd16_6502(0xFFFCu);
}

void oric_frame(u16 pad, u16 *picture)
{
    update_oric_keys(pad);
    WS->cycles = 0;

    /* 1.0 MHz 6502 @ 50 Hz = 20,000 cycles/frame across 312 PAL lines (64 cyc/line) */
    u32 sr = WS->sample_rate ? WS->sample_rate : 48000u;
    const s32 frame_cyc = 20000;

    while (WS->cycles < frame_cyc && !WS->jam) {
        s32 dt = step6502();
        if (dt <= 0) dt = 2;
        via_step(dt);

        WS->snd_frac += (u32)dt * sr;
        while (WS->snd_frac >= 1000000u) {
            WS->snd_frac -= 1000000u;
            ay_step_sample();
        }
    }

    if (WS->basic_mode && !WS->ext_rom_loaded)
        basic_step();

    render_oric_ula(picture);
    WS->frames++;
}

void oric_keyboard(const u8 *usages, int n)
{
    for (int r = 0; r < 8; r++)
        WS->usb_mat[r] = 0;
    for (int i = 0; i < n; i++) {
        u8 u = usages[i];
        if (u >= 0x04u && u <= 0x1Du) {
            press_oric_ascii((char)('A' + (u - 0x04u)), WS->usb_mat);
        } else if (u >= 0x1Eu && u <= 0x26u) {
            press_oric_ascii((char)('1' + (u - 0x1Eu)), WS->usb_mat);
        } else if (u == 0x27u) {
            press_oric_ascii('0', WS->usb_mat);
        } else if (u == 0x28u) {
            WS->usb_mat[7] |= 0x20u;    /* Return */
        } else if (u == 0x29u) {
            WS->usb_mat[1] |= 0x20u;    /* Esc */
        } else if (u == 0x2Au) {
            WS->usb_mat[5] |= 0x20u;    /* Del */
        } else if (u == 0x2Cu) {
            WS->usb_mat[4] |= 0x01u;    /* Space */
        } else if (u == 0xE1u) {
            WS->usb_mat[4] |= 0x10u;    /* LShift */
        } else if (u == 0xE5u) {
            WS->usb_mat[7] |= 0x10u;    /* RShift */
        } else if (u == 0xE0u || u == 0xE4u) {
            WS->usb_mat[2] |= 0x10u;    /* Ctrl */
        } else if (u == 0x52u) {
            WS->usb_mat[4] |= 0x08u;    /* Up */
        } else if (u == 0x50u) {
            WS->usb_mat[4] |= 0x20u;    /* Left */
        } else if (u == 0x51u) {
            WS->usb_mat[4] |= 0x40u;    /* Down */
        } else if (u == 0x4Fu) {
            WS->usb_mat[4] |= 0x80u;    /* Right */
        }
    }
}

void oric_typed(char c)
{
    u8 nxt = (WS->type_w + 1u) & 63u;
    if (nxt != WS->type_r) {
        WS->type_q[WS->type_w] = c;
        WS->type_w = nxt;
    }
}

const char *oric_info(void)
{
    return WS->info;
}

int oric_jammed(void)
{
    return WS->jam;
}

void oric_audio_rate(u32 hz)
{
    WS->sample_rate = hz ? hz : 48000u;
    WS->snd_head = WS->snd_tail = 0;
}

int oric_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && WS->snd_tail != WS->snd_head) {
        out[n++] = WS->snd_ring[WS->snd_tail];
        WS->snd_tail = (WS->snd_tail + 1u) & (SND_RING - 1u);
    }
    return n;
}
