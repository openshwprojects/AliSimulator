/* BBC Micro Model B & Acorn Electron ('bbc'): see bbc.h.
   Pass-optimized for 594 MHz MIPS32:
   - Zero static .bss (all RAM, Sideways banks, OS ROM, UEF/DFS buffers & tables in EMU_RAM_PHYS)
   - Fast 256-entry 6502 page pointer map (rdp[256] / wrp[256])
   - Full Acorn Video ULA Modes 0..6 + Mullard SAA5050 Teletext Mode 7 + Acorn Electron ULA ($FE00..$FE09)
   - Dual 6522 VIAs (100 Hz Timer 1 + VSync CA1 + direct keyboard matrix) + SN76489 & Electron ULA 48 kHz audio */
#pragma GCC optimize("O2")
#include "bbc.h"
#include "zip.h"

#ifndef BBC_HOST
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

struct bbc_via {
    u8  ora, orb, ira, irb, ddra, ddrb;
    u16 t1c, t1l, t2c, t2l;
    u8  sr, acr, pcr, ifr, ier;
    u8  t1_fired, t2_fired;
};

struct bbc_ws {
    /* 2 MHz 6502 CPU + 256-page fast MMU */
    u8  a, x, y, s, p;
    u16 pc;
    u8  jam;
    s32 cycles;
    u8 *rdp[256], *wrp[256];

    /* 32 KB Main RAM + 4 x 16 KB Sideways ROM/RAM + 16 KB MOS ROM */
    u8  ram[0x8000];
    u8  sw_rom[4][0x4000];
    u8  os_rom[0x4000];
    u8  romsel;

    /* Machine variant & boot payload */
    u8  is_electron;
    u8  ext_os, ext_basic;
    u8  has_prog;
    u16 prog_load, prog_exec, prog_len;
    u8  prog_buf[0x8000];               /* Loaded UEF / DFS program image */

    /* MC6845 CRTC ($FE00/$FE01) & Acorn Video ULA ($FE20/$FE21) */
    u8  crtc_sel, crtc[18];
    u8  vula_ctrl;
    u8  vula_pal[16];                   /* Logical 0..15 -> Physical color 0..15 (bit 3 = flash) */
    u8  ic32;                           /* System VIA addressable latch */
    u8  flash_state, flash_cnt;

    /* Acorn Electron ULA ($FE00..$FE09) */
    u8  elk_isr, elk_ier;               /* $FE00: b2=DISP_END, b3=50Hz_RTC */
    u8  elk_scr_lo, elk_scr_hi;         /* $FE02, $FE03 */
    u8  elk_rom_pg;                     /* $FE05 */
    u8  elk_snd_div;                    /* $FE06 */
    u8  elk_misc;                       /* $FE07: b5..3=mode, b2..1=caps/snd_mode */
    u8  elk_pal[16];                    /* $FE08..$FE0F */

    /* Dual 6522 VIAs */
    struct bbc_via sys_via, usr_via;

    /* BBC 10x8 Keyboard Matrix (row 0..7, col 0..9; 1 = pressed) + Electron 14x4 Matrix */
    u8  bbc_keys[8][16];
    u8  elk_keys[14];
    u8  last_usages[16];
    int last_n;
    u16 pad;
    char type_q[64];
    u8  type_r, type_w;

    /* 4 MHz TI SN76489 PSG + Electron 1-bit ULA Sound */
    u8  sn_latch;
    u16 sn_tone[3], sn_cnt[3];
    u8  sn_out[3], sn_vol[4], sn_noise_ctrl, sn_n_out;
    u16 sn_ncnt, sn_lfsr;
    u32 elk_ph;

    /* 48 kHz Audio Ring */
    u32 sample_rate, snd_frac, chip_frac;
    u32 snd_head, snd_tail;
    s16 snd_ring[SND_RING];

    /* Interactive Teletext BASIC cursor (when launched with "") */
    u8  basic_col, basic_row;
    char basic_line[40];
    u8  basic_len;

    u32 frames;
    char info[96];
    u8  gz_scratch[0x20000];            /* 128 KB scratch for .gz UEF unpack (MUST stay last!) */
};

#ifdef BBC_HOST
static struct bbc_ws bbc_host_ws;
#define WS (&bbc_host_ws)
#else
#define WS ((struct bbc_ws *)KSEG0(EMU_RAM_PHYS))
#endif

#define INLINE static inline __attribute__((always_inline))

static void bbc_zero(void *p, u32 n)
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

/* ---- BBC Physical 8-Color RGB555 Table ---- */
static const u16 bbc_rgb15[8] = {
    0x0000u,                            /* 0: Black */
    0x001Fu,                            /* 1: Red */
    0x03E0u,                            /* 2: Green */
    0x03FFu,                            /* 3: Yellow */
    0x7C00u,                            /* 4: Blue */
    0x7C1Fu,                            /* 5: Magenta */
    0x7FE0u,                            /* 6: Cyan */
    0x7FFFu                             /* 7: White */
};

/* Compact 5x7 ASCII font (0x20..0x7F) for Mode 7 Teletext & Clean-Room OSWRCH */
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
    {0x00,0x00,0x7F,0x00,0x00},{0x00,0x41,0x36,0x08,0x00},{0x08,0x04,0x08,0x10,0x08},{0x7F,0x7F,0x7F,0x7F,0x7F}
};

/* ---- TI SN76489 PSG ---- */

static void sn_write(u8 v)
{
    if (v & 0x80u) {
        WS->sn_latch = (v >> 4) & 7u;
        u8 ch = WS->sn_latch >> 1;
        if (WS->sn_latch & 1u) {
            WS->sn_vol[ch] = v & 0x0Fu;
        } else if (ch < 3u) {
            WS->sn_tone[ch] = (u16)((WS->sn_tone[ch] & 0x3F0u) | (v & 0x0Fu));
        } else {
            WS->sn_noise_ctrl = v & 7u;
            WS->sn_lfsr = 0x4000u;
        }
    } else {
        u8 ch = WS->sn_latch >> 1;
        if (WS->sn_latch & 1u) {
            WS->sn_vol[ch] = v & 0x0Fu;
        } else if (ch < 3u) {
            WS->sn_tone[ch] = (u16)((WS->sn_tone[ch] & 0x00Fu) | ((u16)(v & 0x3Fu) << 4));
        } else {
            WS->sn_noise_ctrl = v & 7u;
            WS->sn_lfsr = 0x4000u;
        }
    }
}

/* ---- Keyboard Mapping (Pad + USB Keyboard -> BBC & Electron Matrices) ---- */

static void set_bbc_key(u8 id)
{
    WS->bbc_keys[(id >> 4) & 7u][id & 15u] = 1u;
}

static void set_elk_key(int col, u8 mask)
{
    WS->elk_keys[col] |= mask;
}

static void rebuild_key_matrices(const u8 *usages, int n)
{
    bbc_zero(WS->bbc_keys, sizeof(WS->bbc_keys));
    bbc_zero(WS->elk_keys, sizeof(WS->elk_keys));

    /* Map gamepad / arrows / X / Z / Enter / Tab */
    if (WS->pad & 0x10u) { set_bbc_key(0x39u); set_elk_key(2, 0x02u); } /* Up */
    if (WS->pad & 0x20u) { set_bbc_key(0x29u); set_elk_key(1, 0x02u); } /* Down */
    if (WS->pad & 0x40u) { set_bbc_key(0x19u); set_elk_key(1, 0x01u); } /* Left */
    if (WS->pad & 0x80u) { set_bbc_key(0x79u); set_elk_key(0, 0x01u); } /* Right */
    if (WS->pad & 0x01u) { set_bbc_key(0x62u); set_elk_key(0, 0x08u); } /* X -> Space (Fire1) */
    if (WS->pad & 0x02u) { set_bbc_key(0x00u); set_elk_key(13, 0x08u); }/* Z -> Shift (Fire2) */
    if (WS->pad & 0x08u) { set_bbc_key(0x49u); set_elk_key(1, 0x04u); } /* Enter -> Return */
    if (WS->pad & 0x04u) { set_bbc_key(0x62u); set_elk_key(0, 0x08u); } /* Tab -> Space */

    for (int i = 0; i < n; i++) {
        u8 u = usages[i];
        switch (u) {
        case 0x52: set_bbc_key(0x39u); set_elk_key(2, 0x02u); break;    /* Up */
        case 0x51: set_bbc_key(0x29u); set_elk_key(1, 0x02u); break;    /* Down */
        case 0x50: set_bbc_key(0x19u); set_elk_key(1, 0x01u); break;    /* Left */
        case 0x4F: set_bbc_key(0x79u); set_elk_key(0, 0x01u); break;    /* Right */
        case 0x2C: set_bbc_key(0x62u); set_elk_key(0, 0x08u); break;    /* Space */
        case 0x28: set_bbc_key(0x49u); set_elk_key(1, 0x04u); break;    /* Return */
        case 0xE1: case 0xE5: set_bbc_key(0x00u); set_elk_key(13, 0x08u); break; /* Shift */
        case 0xE0: case 0xE4: set_bbc_key(0x01u); set_elk_key(13, 0x02u); break; /* Ctrl */
        case 0x1D: set_bbc_key(0x61u); set_elk_key(12, 0x08u); break;   /* Z */
        case 0x1B: set_bbc_key(0x42u); set_elk_key(11, 0x08u); break;   /* X */
        case 0x0C: set_bbc_key(0x25u); set_elk_key(5, 0x02u); break;    /* I */
        case 0x0D: set_bbc_key(0x45u); set_elk_key(6, 0x04u); break;    /* J */
        case 0x0E: set_bbc_key(0x46u); set_elk_key(5, 0x04u); break;    /* K */
        case 0x10: set_bbc_key(0x65u); set_elk_key(6, 0x08u); break;    /* M */
        case 0x33: set_bbc_key(0x48u); set_elk_key(2, 0x04u); break;    /* : / * */
        case 0x38: set_bbc_key(0x68u); set_elk_key(3, 0x08u); break;    /* / / ? */
        }
    }
}

void bbc_keyboard(const u8 *usages, int n)
{
    if (n < 0) n = 0;
    if (n > 16) n = 16;
    WS->last_n = n;
    for (int i = 0; i < n; i++)
        WS->last_usages[i] = usages ? usages[i] : 0u;
    rebuild_key_matrices(WS->last_usages, WS->last_n);
}

void bbc_typed(char c)
{
    u8 nw = (WS->type_w + 1u) & 63u;
    if (nw != WS->type_r) {
        WS->type_q[WS->type_w] = c;
        WS->type_w = nw;
    }
}

/* ---- 6522 VIA & SHEILA ($FE00..$FEFF) ---- */

static int irq_pending_now(void)
{
    if (WS->is_electron)
        return (WS->elk_isr & WS->elk_ier & 0x0Cu) != 0;
    int sys_irq = (WS->sys_via.ifr & WS->sys_via.ier & 0x7Fu) != 0;
    int usr_irq = (WS->usr_via.ifr & WS->usr_via.ier & 0x7Fu) != 0;
    return sys_irq || usr_irq;
}

static void update_mmu_map(void)
{
    for (int i = 0; i < 0x80; i++)
        WS->rdp[i] = WS->wrp[i] = WS->ram + (i << 8);
    if (WS->is_electron && ((WS->elk_rom_pg & 0x0Eu) == 0x08u)) {
        /* Electron Keyboard ROM pages 8 & 9 go through sheila/mmio read! */
        for (int i = 0x80; i < 0xC0; i++) {
            WS->rdp[i] = 0;
            WS->wrp[i] = 0;
        }
    } else {
        u8 bank = (WS->is_electron ? WS->elk_rom_pg : WS->romsel) & 3u;
        for (int i = 0x80; i < 0xC0; i++) {
            WS->rdp[i] = WS->sw_rom[bank] + ((i - 0x80) << 8);
            WS->wrp[i] = (bank == 2u) ? WS->rdp[i] : 0; /* Slot 2 = 16 KB Sideways RAM */
        }
    }
    for (int i = 0xC0; i < 0x100; i++) {
        WS->rdp[i] = WS->os_rom + ((i - 0xC0) << 8);
        WS->wrp[i] = 0;
    }
    /* $FC00..$FEFF = FRED / JIM / SHEILA I/O -> go through slow path! */
    WS->rdp[0xFC] = WS->rdp[0xFD] = WS->rdp[0xFE] = 0;
}

static u8 via_read(struct bbc_via *v, int is_sys, u8 reg)
{
    switch (reg & 15u) {
    case 0:                                             /* ORB / IRB */
        v->ifr &= (u8)~0x18u;
        if (is_sys) {
            u8 in_b = 0xFFu;                            /* Joystick buttons b4, b5 active-low */
            if (WS->pad & 0x01u) in_b &= (u8)~0x10u;
            if (WS->pad & 0x02u) in_b &= (u8)~0x20u;
            return (u8)((v->orb & v->ddrb) | (in_b & ~v->ddrb));
        }
        return (u8)((v->orb & v->ddrb) | (~v->ddrb & 0xFFu));
    case 1:
        v->ifr &= (u8)~0x03u;
        /* fall through */
    case 15: {                                          /* ORA / IRA (no handshake at 15) */
        if (is_sys) {
            u8 out_a = v->ora & v->ddra;
            u8 res = out_a;
            /* When IC32 bit 3 == 0 (keyboard write/scan enabled), bit 7 = 1 if (row,col) pressed! */
            if (!(WS->ic32 & 0x08u)) {
                u8 row = (out_a >> 4) & 7u;
                u8 col = out_a & 15u;
                if (row >= 1u && WS->bbc_keys[row][col])
                    res |= 0x80u;
                else if (row == 0u && WS->bbc_keys[0][col])
                    res |= 0x80u;
            }
            return res;
        }
        return (u8)(v->ora & v->ddra);
    }
    case 2:  return v->ddrb;
    case 3:  return v->ddra;
    case 4:  v->ifr &= (u8)~0x40u; return (u8)v->t1c;
    case 5:  return (u8)(v->t1c >> 8);
    case 6:  return (u8)v->t1l;
    case 7:  return (u8)(v->t1l >> 8);
    case 8:  v->ifr &= (u8)~0x20u; return (u8)v->t2c;
    case 9:  return (u8)(v->t2c >> 8);
    case 10: return v->sr;
    case 11: return v->acr;
    case 12: return v->pcr;
    case 13: {
        u8 flg = v->ifr & 0x7Fu;
        return (flg & v->ier) ? (u8)(flg | 0x80u) : flg;
    }
    case 14: return (u8)(v->ier | 0x80u);
    }
    return 0xFFu;
}

static void via_write(struct bbc_via *v, int is_sys, u8 reg, u8 val)
{
    switch (reg & 15u) {
    case 0: {                                           /* ORB */
        u8 prev_ic32 = WS->ic32;
        v->orb = val;
        v->ifr &= (u8)~0x18u;
        if (is_sys) {
            u8 bit_idx = val & 7u;
            if (val & 8u) WS->ic32 |= (u8)(1u << bit_idx);
            else          WS->ic32 &= (u8)~(1u << bit_idx);
            /* IC32 bit 0 going low (0) latches Port A onto SN76489 sound bus! */
            if (!(WS->ic32 & 1u) && (prev_ic32 & 1u))
                sn_write(v->ora);
            else if (!(WS->ic32 & 1u) && !(val & 8u) && bit_idx == 0u)
                sn_write(v->ora);
        }
        break;
    }
    case 1:
        v->ifr &= (u8)~0x03u;
        /* fall through */
    case 15:
        v->ora = val;
        if (is_sys && !(WS->ic32 & 1u))
            sn_write(val);
        break;
    case 2: v->ddrb = val; break;
    case 3: v->ddra = val; break;
    case 4: case 6:
        v->t1l = (u16)((v->t1l & 0xFF00u) | val);
        break;
    case 5:
        v->t1l = (u16)((v->t1l & 0x00FFu) | ((u16)val << 8));
        v->t1c = v->t1l;
        v->t1_fired = 0;
        v->ifr &= (u8)~0x40u;
        break;
    case 7:
        v->t1l = (u16)((v->t1l & 0x00FFu) | ((u16)val << 8));
        v->ifr &= (u8)~0x40u;
        break;
    case 8:
        v->t2l = (u16)((v->t2l & 0xFF00u) | val);
        break;
    case 9:
        v->t2c = (u16)(((u16)val << 8) | (v->t2l & 0xFFu));
        v->t2_fired = 0;
        v->ifr &= (u8)~0x20u;
        break;
    case 10: v->sr = val; break;
    case 11: v->acr = val; break;
    case 12: v->pcr = val; break;
    case 13: v->ifr &= (u8)~(val & 0x7Fu); break;
    case 14:
        if (val & 0x80u) v->ier |= (val & 0x7Fu);
        else             v->ier &= (u8)~(val & 0x7Fu);
        break;
    }
}

static void via_step(struct bbc_via *v, u32 cyc1mhz)
{
    if (v->t1c <= cyc1mhz) {
        if (!v->t1_fired || (v->acr & 0x40u)) {
            v->ifr |= 0x40u;
            v->t1_fired = 1;
        }
        if (v->acr & 0x40u) {
            u32 per = (u32)v->t1l + 2u;
            u32 rem = (cyc1mhz - v->t1c) % per;
            v->t1c = (u16)(per - 1u - rem);
        } else {
            v->t1c = (u16)(v->t1c - cyc1mhz);
        }
    } else {
        v->t1c = (u16)(v->t1c - cyc1mhz);
    }

    if (!(v->acr & 0x20u)) {
        if (!v->t2_fired && v->t2c <= cyc1mhz) {
            v->ifr |= 0x20u;
            v->t2_fired = 1;
        }
        v->t2c = (u16)(v->t2c - cyc1mhz);
    }
}

static u8 mmio_read(u16 a)
{
    /* Electron Keyboard Matrix ($8000..$BFFF when page 8/9 selected) */
    if (a >= 0x8000u && a < 0xC000u) {
        u8 res = 0;
        for (int col = 0; col < 14; col++) {
            if (!(a & (1u << col)))
                res |= WS->elk_keys[col];
        }
        return res;
    }

    if (a >= 0xFE00u && a < 0xFF00u) {
        if (WS->is_electron && a <= 0xFE0Fu) {
            if ((a & 15u) == 0u) {
                u8 st = (u8)(0x82u | (WS->elk_isr & 0x7Cu));
                if (WS->elk_isr & WS->elk_ier & 0x7Cu) st |= 0x01u;
                return st;
            }
            return 0xFFu;
        }
        u8 sub = (u8)(a & 0xFFu);
        if (sub < 0x08u) return (sub & 1u) ? WS->crtc[WS->crtc_sel & 17u] : 0u;
        if (sub >= 0x30u && sub < 0x34u) return WS->romsel;
        if (sub >= 0x40u && sub < 0x60u) return via_read(&WS->sys_via, 1, sub & 15u);
        if (sub >= 0x60u && sub < 0x80u) return via_read(&WS->usr_via, 0, sub & 15u);
        if (sub >= 0xC0u && sub < 0xE0u) {              /* uPD7002 ADC (Analog Joystick) */
            if ((sub & 3u) == 0u) return 0x40u;         /* Conversion complete */
            if ((sub & 3u) == 1u) return 0x80u;         /* Center 0x8000 */
            return 0x00u;
        }
    }
    return 0xFFu;
}

static void mmio_write(u16 a, u8 v)
{
    if (a < 0xFE00u || a >= 0xFF00u)
        return;

    /* Acorn Electron ULA registers ($FE00..$FE0F when running an Electron title) */
    u8 sub = (u8)(a & 0xFFu);
    if (WS->is_electron && sub <= 0x0Fu) {
        switch (sub) {
        case 0x00: WS->elk_ier = v; break;
        case 0x02: WS->elk_scr_lo = v; break;
        case 0x03: WS->elk_scr_hi = v; break;
        case 0x05:
            if (v & 0x20u) WS->elk_isr &= (u8)~0x04u; /* Clear 50 Hz RTC ($04) */
            if (v & 0x10u) WS->elk_isr &= (u8)~0x08u; /* Clear Display End ($08) */
            if ((v & 0x0Fu) <= 0x0Bu || !(WS->elk_rom_pg & 0x08u)) {
                WS->elk_rom_pg = v & 0x0Fu;
                update_mmu_map();
            }
            break;
        case 0x06: WS->elk_snd_div = v; break;
        case 0x07: WS->elk_misc = v; break;
        default:
            if (sub >= 0x08u)
                WS->elk_pal[sub - 0x08u] = v;
            break;
        }
        return;
    }

    if (sub < 0x08u) {
        if (sub & 1u) {
            if (WS->crtc_sel < 18u) WS->crtc[WS->crtc_sel] = v;
        } else {
            WS->crtc_sel = v & 31u;
        }
        return;
    }
    if (sub >= 0x20u && sub < 0x30u) {
        if (sub & 1u) WS->vula_pal[(v >> 4) & 15u] = (u8)((v & 15u) ^ 7u);
        else          WS->vula_ctrl = v;
        return;
    }
    if (sub >= 0x30u && sub < 0x40u) {
        WS->romsel = v & 15u;
        update_mmu_map();
        return;
    }
    if (sub >= 0x40u && sub < 0x60u) {
        via_write(&WS->sys_via, 1, sub & 15u, v);
        return;
    }
    if (sub >= 0x60u && sub < 0x80u) {
        via_write(&WS->usr_via, 0, sub & 15u, v);
        return;
    }
}

INLINE u8 rd6502(u16 a)
{
    u8 *p = WS->rdp[a >> 8];
    return p ? p[a & 0xFFu] : mmio_read(a);
}

INLINE void wr6502(u16 a, u8 v)
{
    u8 *p = WS->wrp[a >> 8];
    if (p) p[a & 0xFFu] = v;
    else   mmio_write(a, v);
}

static u16 rd16_6502(u16 a)
{
    return (u16)rd6502(a) | ((u16)rd6502((u16)(a + 1u)) << 8);
}

/* ---- Clean-Room Acorn MOS HLE & 6502 Step ---- */

static void teletext_putc(char c)
{
    u8 *scr = WS->ram + 0x7C00u;
    if (c == '\r') {
        WS->basic_col = 0;
        return;
    }
    if (c == '\n') {
        WS->basic_col = 0;
        if (WS->basic_row < 24u) {
            WS->basic_row++;
        } else {
            for (int r = 1; r < 24; r++)
                for (int k = 0; k < 40; k++)
                    scr[r * 40 + k] = scr[(r + 1) * 40 + k];
            for (int k = 0; k < 40; k++)
                scr[24 * 40 + k] = ' ';
        }
        return;
    }
    if (c == 0x08 || c == 0x7F) {
        if (WS->basic_col > 1u) {
            WS->basic_col--;
            scr[WS->basic_row * 40u + WS->basic_col] = ' ';
        }
        return;
    }
    if (c >= 0x20 && c < 0x7F) {
        if (WS->basic_col < 40u) {
            scr[WS->basic_row * 40u + WS->basic_col++] = (u8)c;
        }
        if (WS->basic_col >= 40u) {
            WS->basic_col = 0;
            teletext_putc('\n');
        }
    }
}

static void teletext_puts(const char *s)
{
    while (*s) teletext_putc(*s++);
}

static int mos_hle_trap(void)
{
    if (WS->ext_os)
        return 0;
    switch (WS->pc) {
    case 0xFFF4:                                        /* OSBYTE */
        if (WS->a == 154u) {                            /* Set Video ULA Control ($FE20 + $0248) */
            WS->ram[0x0248] = WS->x;
            WS->vula_ctrl = WS->x;
        } else if (WS->a == 155u) {                     /* Set Video ULA Palette */
            WS->vula_pal[(WS->x >> 4) & 15u] = (u8)((WS->x & 15u) ^ 7u);
        } else if (WS->a == 129u && WS->y == 0xFFu) {   /* INKEY(-n): X = internal key EOR $FF */
            u8 ikey = (u8)(WS->x ^ 0xFFu);
            u8 pressed = WS->bbc_keys[(ikey >> 4) & 7u][ikey & 15u];
            WS->x = pressed ? 0xFFu : 0x00u;
            WS->y = WS->x;
            if (pressed) WS->p |= FC; else WS->p &= (u8)~FC;
        }
        /* RTS */
        WS->pc = (u16)(WS->ram[0x100u | (u8)(WS->s + 1u)] | ((u16)WS->ram[0x100u | (u8)(WS->s + 2u)] << 8)) + 1u;
        WS->s = (u8)(WS->s + 2u);
        return 12;

    case 0xFFEE:                                        /* OSWRCH */
    case 0xFFE3:                                        /* OSASCI */
        if (WS->pc == 0xFFE3u && WS->a == 0x0Du)
            teletext_putc('\n');
        teletext_putc((char)WS->a);
        WS->pc = (u16)(WS->ram[0x100u | (u8)(WS->s + 1u)] | ((u16)WS->ram[0x100u | (u8)(WS->s + 2u)] << 8)) + 1u;
        WS->s = (u8)(WS->s + 2u);
        return 12;

    case 0xFFE7:                                        /* OSNEWL */
        teletext_putc('\r');
        teletext_putc('\n');
        WS->pc = (u16)(WS->ram[0x100u | (u8)(WS->s + 1u)] | ((u16)WS->ram[0x100u | (u8)(WS->s + 2u)] << 8)) + 1u;
        WS->s = (u8)(WS->s + 2u);
        return 12;
    }
    return 0;
}

INLINE void set_nz(u8 v)
{
    WS->p = (u8)((WS->p & ~(FN | FZ)) | (v & 0x80u) | (v ? 0u : FZ));
}

static void push6502(u8 v) { WS->ram[0x100u | WS->s--] = v; }
static u8   pull6502(void) { return WS->ram[0x100u | ++WS->s]; }

static void adc6502(u8 v)
{
    u32 c = WS->p & FC;
    if (WS->p & FD) {
        u32 lo = (WS->a & 0x0Fu) + (v & 0x0Fu) + c;
        u32 hi = (WS->a >> 4) + (v >> 4) + (lo > 9u ? 1u : 0u);
        if (lo > 9u) lo += 6u;
        u8 bin = (u8)(WS->a + v + c);
        WS->p &= (u8)~(FC | FV | FZ | FN);
        if (!bin) WS->p |= FZ;
        if (hi & 8u) WS->p |= FN;
        if ((~(WS->a ^ v) & (WS->a ^ (hi << 4))) & 0x80u) WS->p |= FV;
        if (hi > 9u) hi += 6u;
        if (hi > 15u) WS->p |= FC;
        WS->a = (u8)((hi << 4) | (lo & 0x0Fu));
    } else {
        u16 sum = (u16)(WS->a + v + c);
        WS->p = (u8)((WS->p & ~(FC | FV)) | (sum > 0xFFu ? FC : 0u) |
                     (((~(WS->a ^ v) & (WS->a ^ sum)) & 0x80u) ? FV : 0u));
        WS->a = (u8)sum;
        set_nz(WS->a);
    }
}

static void sbc6502(u8 v)
{
    if (WS->p & FD) {
        u32 c = (WS->p & FC) ^ 1u;
        s32 lo = (s32)(WS->a & 0x0Fu) - (s32)(v & 0x0Fu) - (s32)c;
        s32 hi = (s32)(WS->a >> 4) - (s32)(v >> 4) - (lo < 0 ? 1 : 0);
        u16 diff = (u16)(WS->a - v - c);
        if (lo < 0) lo -= 6;
        if (hi < 0) hi -= 6;
        WS->p = (u8)((WS->p & ~(FC | FV | FZ | FN)) | (diff < 0x100u ? FC : 0u) |
                     ((((WS->a ^ v) & (WS->a ^ diff)) & 0x80u) ? FV : 0u));
        set_nz((u8)diff);
        WS->a = (u8)(((u32)hi << 4) | ((u32)lo & 0x0Fu));
    } else {
        adc6502((u8)~v);
    }
}

static u32 step6502(void)
{
    if (!(WS->p & FI) && irq_pending_now()) {
        push6502((u8)(WS->pc >> 8));
        push6502((u8)WS->pc);
        push6502((u8)((WS->p & ~FB) | FU));
        WS->p |= FI;
        WS->pc = rd16_6502(0xFFFEu);
        return 7;
    }

    if (WS->pc >= 0xFFD0u) {
        int hc = mos_hle_trap();
        if (hc) return (u32)hc;
    }

    u8 op = rd6502(WS->pc++);
    u16 ea = 0;
    u8 v;

#define ZP()   ((u16)rd6502(WS->pc++))
#define ZPX()  ((u16)(u8)(rd6502(WS->pc++) + WS->x))
#define ZPY()  ((u16)(u8)(rd6502(WS->pc++) + WS->y))
#define ABS()  (WS->pc = (u16)(WS->pc + 2u), ea = rd16_6502((u16)(WS->pc - 2u)))
#define ABX()  (WS->pc = (u16)(WS->pc + 2u), ea = (u16)(rd16_6502((u16)(WS->pc - 2u)) + WS->x))
#define ABY()  (WS->pc = (u16)(WS->pc + 2u), ea = (u16)(rd16_6502((u16)(WS->pc - 2u)) + WS->y))
#define IZX()  (v = (u8)(rd6502(WS->pc++) + WS->x), (u16)(WS->ram[v] | ((u16)WS->ram[(u8)(v + 1u)] << 8)))
#define IZY()  (v = rd6502(WS->pc++), (u16)((WS->ram[v] | ((u16)WS->ram[(u8)(v + 1u)] << 8)) + WS->y))
#define BR(cond) do { signed char d = (signed char)rd6502(WS->pc++); if (cond) { WS->pc = (u16)(WS->pc + d); return 3; } return 2; } while (0)
#define CMP(r, val) do { u8 vv = (val); WS->p = (u8)((WS->p & ~FC) | ((r) >= vv ? FC : 0u)); set_nz((u8)((r) - vv)); } while (0)

    switch (op) {
    case 0x00: WS->pc++; push6502((u8)(WS->pc >> 8)); push6502((u8)WS->pc); push6502((u8)(WS->p | FB | FU)); WS->p |= FI; WS->pc = rd16_6502(0xFFFEu); return 7;
    case 0x01: set_nz(WS->a |= rd6502(IZX())); return 6;
    case 0x05: set_nz(WS->a |= WS->ram[ZP()]); return 3;
    case 0x06: ea = ZP(); v = WS->ram[ea]; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); set_nz(WS->ram[ea] = (u8)(v << 1)); return 5;
    case 0x08: push6502((u8)(WS->p | FB | FU)); return 3;
    case 0x09: set_nz(WS->a |= rd6502(WS->pc++)); return 2;
    case 0x0A: WS->p = (u8)((WS->p & ~FC) | (WS->a >> 7)); set_nz(WS->a = (u8)(WS->a << 1)); return 2;
    case 0x0D: set_nz(WS->a |= rd6502(ABS())); return 4;
    case 0x0E: ABS(); v = rd6502(ea); WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v <<= 1; wr6502(ea, v); set_nz(v); return 6;
    case 0x10: BR(!(WS->p & FN));
    case 0x11: set_nz(WS->a |= rd6502(IZY())); return 5;
    case 0x15: set_nz(WS->a |= WS->ram[ZPX()]); return 4;
    case 0x16: ea = ZPX(); v = WS->ram[ea]; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); set_nz(WS->ram[ea] = (u8)(v << 1)); return 6;
    case 0x18: WS->p &= (u8)~FC; return 2;
    case 0x19: set_nz(WS->a |= rd6502(ABY())); return 4;
    case 0x1D: set_nz(WS->a |= rd6502(ABX())); return 4;
    case 0x1E: ABX(); v = rd6502(ea); WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v <<= 1; wr6502(ea, v); set_nz(v); return 7;

    case 0x20: ea = rd16_6502(WS->pc); WS->pc++; push6502((u8)(WS->pc >> 8)); push6502((u8)WS->pc); WS->pc = ea; return 6;
    case 0x21: set_nz(WS->a &= rd6502(IZX())); return 6;
    case 0x24: v = WS->ram[ZP()]; WS->p = (u8)((WS->p & ~(FN | FV | FZ)) | (v & 0xC0u) | ((WS->a & v) ? 0u : FZ)); return 3;
    case 0x25: set_nz(WS->a &= WS->ram[ZP()]); return 3;
    case 0x26: ea = ZP(); v = WS->ram[ea]; { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); set_nz(WS->ram[ea] = (u8)((v << 1) | c)); } return 5;
    case 0x28: WS->p = (u8)((pull6502() & ~FB) | FU); return 4;
    case 0x29: set_nz(WS->a &= rd6502(WS->pc++)); return 2;
    case 0x2A: { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (WS->a >> 7)); set_nz(WS->a = (u8)((WS->a << 1) | c)); } return 2;
    case 0x2C: v = rd6502(ABS()); WS->p = (u8)((WS->p & ~(FN | FV | FZ)) | (v & 0xC0u) | ((WS->a & v) ? 0u : FZ)); return 4;
    case 0x2D: set_nz(WS->a &= rd6502(ABS())); return 4;
    case 0x2E: ABS(); v = rd6502(ea); { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v = (u8)((v << 1) | c); wr6502(ea, v); set_nz(v); } return 6;
    case 0x30: BR(WS->p & FN);
    case 0x31: set_nz(WS->a &= rd6502(IZY())); return 5;
    case 0x35: set_nz(WS->a &= WS->ram[ZPX()]); return 4;
    case 0x36: ea = ZPX(); v = WS->ram[ea]; { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); set_nz(WS->ram[ea] = (u8)((v << 1) | c)); } return 6;
    case 0x38: WS->p |= FC; return 2;
    case 0x39: set_nz(WS->a &= rd6502(ABY())); return 4;
    case 0x3D: set_nz(WS->a &= rd6502(ABX())); return 4;
    case 0x3E: ABX(); v = rd6502(ea); { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v = (u8)((v << 1) | c); wr6502(ea, v); set_nz(v); } return 7;

    case 0x40: WS->p = (u8)((pull6502() & ~FB) | FU); WS->pc = pull6502(); WS->pc |= (u16)pull6502() << 8; return 6;
    case 0x41: set_nz(WS->a ^= rd6502(IZX())); return 6;
    case 0x45: set_nz(WS->a ^= WS->ram[ZP()]); return 3;
    case 0x46: ea = ZP(); v = WS->ram[ea]; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); set_nz(WS->ram[ea] = (u8)(v >> 1)); return 5;
    case 0x48: push6502(WS->a); return 3;
    case 0x49: set_nz(WS->a ^= rd6502(WS->pc++)); return 2;
    case 0x4A: WS->p = (u8)((WS->p & ~FC) | (WS->a & 1u)); set_nz(WS->a >>= 1); return 2;
    case 0x4C: WS->pc = rd16_6502(WS->pc); return 3;
    case 0x4D: set_nz(WS->a ^= rd6502(ABS())); return 4;
    case 0x4E: ABS(); v = rd6502(ea); WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v >>= 1; wr6502(ea, v); set_nz(v); return 6;
    case 0x50: BR(!(WS->p & FV));
    case 0x51: set_nz(WS->a ^= rd6502(IZY())); return 5;
    case 0x55: set_nz(WS->a ^= WS->ram[ZPX()]); return 4;
    case 0x56: ea = ZPX(); v = WS->ram[ea]; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); set_nz(WS->ram[ea] = (u8)(v >> 1)); return 6;
    case 0x58: WS->p &= (u8)~FI; return 2;
    case 0x59: set_nz(WS->a ^= rd6502(ABY())); return 4;
    case 0x5D: set_nz(WS->a ^= rd6502(ABX())); return 4;
    case 0x5E: ABX(); v = rd6502(ea); WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v >>= 1; wr6502(ea, v); set_nz(v); return 7;

    case 0x60: WS->pc = pull6502(); WS->pc |= (u16)pull6502() << 8; WS->pc++; return 6;
    case 0x61: adc6502(rd6502(IZX())); return 6;
    case 0x65: adc6502(WS->ram[ZP()]); return 3;
    case 0x66: ea = ZP(); v = WS->ram[ea]; { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); set_nz(WS->ram[ea] = (u8)((v >> 1) | (c << 7))); } return 5;
    case 0x68: set_nz(WS->a = pull6502()); return 4;
    case 0x69: adc6502(rd6502(WS->pc++)); return 2;
    case 0x6A: { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (WS->a & 1u)); set_nz(WS->a = (u8)((WS->a >> 1) | (c << 7))); } return 2;
    case 0x6C: { u16 p = rd16_6502(WS->pc); WS->pc = (u16)(rd6502(p) | ((u16)rd6502((u16)((p & 0xFF00u) | ((p + 1u) & 0xFFu))) << 8)); return 5; }
    case 0x6D: adc6502(rd6502(ABS())); return 4;
    case 0x6E: ABS(); v = rd6502(ea); { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v = (u8)((v >> 1) | (c << 7)); wr6502(ea, v); set_nz(v); } return 6;
    case 0x70: BR(WS->p & FV);
    case 0x71: adc6502(rd6502(IZY())); return 5;
    case 0x75: adc6502(WS->ram[ZPX()]); return 4;
    case 0x76: ea = ZPX(); v = WS->ram[ea]; { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); set_nz(WS->ram[ea] = (u8)((v >> 1) | (c << 7))); } return 6;
    case 0x78: WS->p |= FI; return 2;
    case 0x79: adc6502(rd6502(ABY())); return 4;
    case 0x7D: adc6502(rd6502(ABX())); return 4;
    case 0x7E: ABX(); v = rd6502(ea); { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v = (u8)((v >> 1) | (c << 7)); wr6502(ea, v); set_nz(v); } return 7;

    case 0x81: wr6502(IZX(), WS->a); return 6;
    case 0x84: WS->ram[ZP()] = WS->y; return 3;
    case 0x85: WS->ram[ZP()] = WS->a; return 3;
    case 0x86: WS->ram[ZP()] = WS->x; return 3;
    case 0x88: set_nz(--WS->y); return 2;
    case 0x8A: set_nz(WS->a = WS->x); return 2;
    case 0x8C: wr6502(ABS(), WS->y); return 4;
    case 0x8D: wr6502(ABS(), WS->a); return 4;
    case 0x8E: wr6502(ABS(), WS->x); return 4;
    case 0x90: BR(!(WS->p & FC));
    case 0x91: wr6502(IZY(), WS->a); return 6;
    case 0x94: WS->ram[ZPX()] = WS->y; return 4;
    case 0x95: WS->ram[ZPX()] = WS->a; return 4;
    case 0x96: WS->ram[ZPY()] = WS->x; return 4;
    case 0x98: set_nz(WS->a = WS->y); return 2;
    case 0x99: wr6502(ABY(), WS->a); return 5;
    case 0x9A: WS->s = WS->x; return 2;
    case 0x9D: wr6502(ABX(), WS->a); return 5;

    case 0xA0: set_nz(WS->y = rd6502(WS->pc++)); return 2;
    case 0xA1: set_nz(WS->a = rd6502(IZX())); return 6;
    case 0xA2: set_nz(WS->x = rd6502(WS->pc++)); return 2;
    case 0xA4: set_nz(WS->y = WS->ram[ZP()]); return 3;
    case 0xA5: set_nz(WS->a = WS->ram[ZP()]); return 3;
    case 0xA6: set_nz(WS->x = WS->ram[ZP()]); return 3;
    case 0xA8: set_nz(WS->y = WS->a); return 2;
    case 0xA9: set_nz(WS->a = rd6502(WS->pc++)); return 2;
    case 0xAA: set_nz(WS->x = WS->a); return 2;
    case 0xAC: set_nz(WS->y = rd6502(ABS())); return 4;
    case 0xAD: set_nz(WS->a = rd6502(ABS())); return 4;
    case 0xAE: set_nz(WS->x = rd6502(ABS())); return 4;
    case 0xB0: BR(WS->p & FC);
    case 0xB1: set_nz(WS->a = rd6502(IZY())); return 5;
    case 0xB4: set_nz(WS->y = WS->ram[ZPX()]); return 4;
    case 0xB5: set_nz(WS->a = WS->ram[ZPX()]); return 4;
    case 0xB6: set_nz(WS->x = WS->ram[ZPY()]); return 4;
    case 0xB8: WS->p &= (u8)~FV; return 2;
    case 0xB9: set_nz(WS->a = rd6502(ABY())); return 4;
    case 0xBA: set_nz(WS->x = WS->s); return 2;
    case 0xBC: set_nz(WS->y = rd6502(ABX())); return 4;
    case 0xBD: set_nz(WS->a = rd6502(ABX())); return 4;
    case 0xBE: set_nz(WS->x = rd6502(ABY())); return 4;

    case 0xC0: CMP(WS->y, rd6502(WS->pc++)); return 2;
    case 0xC1: CMP(WS->a, rd6502(IZX())); return 6;
    case 0xC4: CMP(WS->y, WS->ram[ZP()]); return 3;
    case 0xC5: CMP(WS->a, WS->ram[ZP()]); return 3;
    case 0xC6: ea = ZP(); set_nz(--WS->ram[ea]); return 5;
    case 0xC8: set_nz(++WS->y); return 2;
    case 0xC9: CMP(WS->a, rd6502(WS->pc++)); return 2;
    case 0xCA: set_nz(--WS->x); return 2;
    case 0xCC: CMP(WS->y, rd6502(ABS())); return 4;
    case 0xCD: CMP(WS->a, rd6502(ABS())); return 4;
    case 0xCE: ABS(); v = (u8)(rd6502(ea) - 1u); wr6502(ea, v); set_nz(v); return 6;
    case 0xD0: BR(!(WS->p & FZ));
    case 0xD1: CMP(WS->a, rd6502(IZY())); return 5;
    case 0xD5: CMP(WS->a, WS->ram[ZPX()]); return 4;
    case 0xD6: ea = ZPX(); set_nz(--WS->ram[ea]); return 6;
    case 0xD8: WS->p &= (u8)~FD; return 2;
    case 0xD9: CMP(WS->a, rd6502(ABY())); return 4;
    case 0xDD: CMP(WS->a, rd6502(ABX())); return 4;
    case 0xDE: ABX(); v = (u8)(rd6502(ea) - 1u); wr6502(ea, v); set_nz(v); return 7;

    case 0xE0: CMP(WS->x, rd6502(WS->pc++)); return 2;
    case 0xE1: sbc6502(rd6502(IZX())); return 6;
    case 0xE4: CMP(WS->x, WS->ram[ZP()]); return 3;
    case 0xE5: sbc6502(WS->ram[ZP()]); return 3;
    case 0xE6: ea = ZP(); set_nz(++WS->ram[ea]); return 5;
    case 0xE8: set_nz(++WS->x); return 2;
    case 0xE9: sbc6502(rd6502(WS->pc++)); return 2;
    case 0xEA: return 2;
    case 0xEC: CMP(WS->x, rd6502(ABS())); return 4;
    case 0xED: sbc6502(rd6502(ABS())); return 4;
    case 0xEE: ABS(); v = (u8)(rd6502(ea) + 1u); wr6502(ea, v); set_nz(v); return 6;
    case 0xF0: BR(WS->p & FZ);
    case 0xF1: sbc6502(rd6502(IZY())); return 5;
    case 0xF5: sbc6502(WS->ram[ZPX()]); return 4;
    case 0xF6: ea = ZPX(); set_nz(++WS->ram[ea]); return 6;
    case 0xF8: WS->p |= FD; return 2;
    case 0xF9: sbc6502(rd6502(ABY())); return 4;
    case 0xFD: sbc6502(rd6502(ABX())); return 4;
    case 0xFE: ABX(); v = (u8)(rd6502(ea) + 1u); wr6502(ea, v); set_nz(v); return 7;

    default:
        if ((op & 0x0Fu) == 0x02u) { WS->jam = 1; return 2; }
        return 2;
    }
#undef ZP
#undef ZPX
#undef ZPY
#undef ABS
#undef ABX
#undef ABY
#undef IZX
#undef IZY
#undef BR
#undef CMP
}

/* ---- Video Rendering (SAA5050 Teletext Mode 7, BBC Modes 0..6, Electron Modes 0..6) ---- */

static u16 bbc_logical_rgb(u8 idx)
{
    u8 phys = WS->vula_pal[idx & 15u];
    if ((phys & 8u) && WS->flash_state)
        phys ^= 7u;
    return bbc_rgb15[phys & 7u];
}

static void render_mode7_teletext(u16 *pic)
{
    for (int i = 0; i < BBC_W * BBC_H; i++)
        pic[i] = 0;

    const u8 *vram = WS->ram + 0x7C00u;
    for (int row = 0; row < 25; row++) {
        u8 fg = 7u, bg = 0u, gfx_mode = 0u, sep = 0u, hold = 0u, held_ch = ' ';
        int y0 = 3 + row * 10;
        for (int col = 0; col < 40; col++) {
            u8 ch = vram[row * 40 + col] & 0x7Fu;
            u8 draw_ch = ' ';
            if (ch < 0x20u) {
                if (ch >= 0x01u && ch <= 0x07u)      { fg = ch; gfx_mode = 0; held_ch = ' '; }
                else if (ch >= 0x11u && ch <= 0x17u) { fg = (u8)(ch - 0x10u); gfx_mode = 1; }
                else if (ch == 0x19u) sep = 0;
                else if (ch == 0x1Au) sep = 1;
                else if (ch == 0x1Cu) bg = 0;
                else if (ch == 0x1Du) bg = fg;
                else if (ch == 0x1Eu) hold = 1;
                else if (ch == 0x1Fu) { hold = 0; held_ch = ' '; }
                draw_ch = hold ? held_ch : ' ';
            } else {
                draw_ch = ch;
                if (gfx_mode && ((ch >= 0x20u && ch < 0x40u) || (ch >= 0x60u)))
                    held_ch = ch;
            }

            u16 fg15 = bbc_rgb15[fg & 7u], bg15 = bbc_rgb15[bg & 7u];
            int x0 = col * 8;
            if (gfx_mode && ((draw_ch >= 0x20u && draw_ch < 0x40u) || draw_ch >= 0x60u)) {
                /* SAA5050 2x3 sixel mosaic: b0=TL, b1=TR, b2=ML, b3=MR, b4=BL, b6=BR! */
                u8 s6 = (u8)((draw_ch & 0x1Fu) | ((draw_ch & 0x40u) >> 1));
                for (int py = 0; py < 10; py++) {
                    int sy = (py < 3) ? 0 : (py < 7 ? 1 : 2);
                    int gap_y = sep && (py == 2 || py == 6 || py == 9);
                    u16 *dst = pic + (y0 + py) * BBC_W + x0;
                    for (int px = 0; px < 8; px++) {
                        int sx = (px >= 4) ? 1 : 0;
                        int gap_x = sep && (px == 3 || px == 7);
                        int on = !gap_x && !gap_y && ((s6 >> (sy * 2 + sx)) & 1u);
                        dst[px] = on ? fg15 : bg15;
                    }
                }
            } else {
                const u8 *gl = font5x7[(draw_ch >= 0x20u && draw_ch < 0x80u) ? (draw_ch - 0x20u) : 0];
                for (int py = 0; py < 10; py++) {
                    int gy = (py * 7) / 10;
                    u16 *dst = pic + (y0 + py) * BBC_W + x0;
                    dst[0] = bg15;
                    for (int gx = 0; gx < 5; gx++) {
                        u16 c = ((gl[gx] >> gy) & 1u) ? fg15 : bg15;
                        dst[1 + gx] = c;
                    }
                    dst[6] = bg15;
                    dst[7] = bg15;
                }
            }
        }
    }
}

static void render_electron(u16 *pic)
{
    for (int i = 0; i < BBC_W * BBC_H; i++)
        pic[i] = 0;

    u8 mode = (WS->elk_misc >> 3) & 7u;
    if (mode == 7u) mode = 4u;
    u32 start = (((u32)(WS->elk_scr_hi & 0x3Fu) << 9) | (((u32)WS->elk_scr_lo & 0xE0u) << 1)) & 0x7FFFu;
    u32 wrap_base = (mode <= 2u) ? 0x3000u : (mode == 3u ? 0x4000u : (mode == 6u ? 0x6000u : 0x5800u));
    u32 bytes_per_row = (mode <= 3u) ? 640u : 320u;
    int chars_per_row = (mode <= 3u) ? 80 : 40;
    int bpp = (mode == 0u || mode == 3u || mode == 4u || mode == 6u) ? 1 : (mode == 1u || mode == 5u ? 2 : 4);
    int rows = (mode == 3u || mode == 6u) ? 25 : 32;
    int cell_h = (mode == 3u || mode == 6u) ? 10 : 8;

    /* Decode Electron ULA palette registers ($FE08..$FE0F) -> 4-color / 2-color / 16-color RGB15! */
    u16 epal[16];
    for (int i = 0; i < 16; i++) epal[i] = bbc_rgb15[i & 7];
    if (bpp == 2) {
        /* Mode 1 / Mode 5: $FE08 (p0), $FE09 (p1) encode Red(lo nib), Green(hi nib of $FE09), Blue(hi nib of $FE08) inverted! */
        u8 p0 = (u8)~WS->elk_pal[0], p1 = (u8)~WS->elk_pal[1];
        static const u8 rbit[4] = {0, 1, 2, 3};
        static const u8 gbit[4] = {0, 1, 2, 3};
        static const u8 bbit[4] = {4, 5, 6, 7};
        for (int c = 0; c < 4; c++) {
            u8 r = (p0 >> rbit[c]) & 1u;
            u8 g = (p1 >> (4 + gbit[c])) & 1u;
            u8 b = (p1 >> bbit[c]) & 1u;
            /* Note: on Electron Mode 5: $FE08: b7=B3,b6=B2,b5=B1,b4=B0, b3=R3,b2=R2,b1=R1,b0=R0;
               $FE09: b7=G3,b6=G2,b5=G1,b4=G0! Verify against Hopman: $FE08=$70 (~$70=$8F -> B=1000, R=1111?
               Wait: in Hopman Electron: $FE08=$70 -> ~=$8F: c=0: R0=1? Wait: c=0 must be Black (0,0,0)!)
               Check bits of $70 (0111_0000) and $35 (0011_0101):
               c=0 -> Black (R=0,G=0,B=0) => inverted bits for c=0 are all 1 in raw ($70 has b6,5,4=1, $35 has b5,4,2,0=1)!
               Look at raw $70 = 0111_0000 and $35 = 0011_0101:
               c=0 (Black -> raw R=1,G=1,B=1): $70 b4=1(B0), $35 b4=1(G0), $35 b0=1(R0)!
               c=1 (Red   -> raw R=0,G=1,B=1): $70 b5=1(B1), $35 b5=1(G1), $35 b1=0(R1)!
               c=2 (Green -> raw R=1,G=0,B=1): $70 b6=1(B2), $35 b6=0(G2), $35 b2=1(R2)!
               c=3 (White -> raw R=0,G=0,B=0): $70 b7=0(B3), $35 b7=0(G3), $35 b3=0(R3)!
               BINGO!! $FE08 bits 7..4 = ~B3..B0; $FE09 bits 7..4 = ~G3..G0, bits 3..0 = ~R3..R0!! */
            (void)r; (void)g; (void)b;
            u8 rr = ((~WS->elk_pal[1]) >> c) & 1u;
            u8 gg = ((~WS->elk_pal[1]) >> (4 + c)) & 1u;
            u8 bb = ((~WS->elk_pal[0]) >> (4 + c)) & 1u;
            epal[c] = bbc_rgb15[rr | (gg << 1) | (bb << 2)];
        }
    } else if (bpp == 1) {
        u8 rr0 = (~WS->elk_pal[1]) & 1u, gg0 = ((~WS->elk_pal[1]) >> 4) & 1u, bb0 = ((~WS->elk_pal[0]) >> 4) & 1u;
        u8 rr1 = ((~WS->elk_pal[1]) >> 2) & 1u, gg1 = ((~WS->elk_pal[1]) >> 6) & 1u, bb1 = ((~WS->elk_pal[0]) >> 6) & 1u;
        epal[0] = bbc_rgb15[rr0 | (gg0 << 1) | (bb0 << 2)];
        epal[1] = bbc_rgb15[rr1 | (gg1 << 1) | (bb1 << 2)];
    }

    u32 row_addr = start;
    for (int cr = 0; cr < rows; cr++) {
        for (int ra = 0; ra < 8; ra++) {
            int sy = cr * cell_h + ra;
            if (sy >= BBC_H) break;
            u16 *dst = pic + sy * BBC_W;
            u32 ba = row_addr + (u32)ra;
            for (int cc = 0; cc < chars_per_row; cc++) {
                if (ba >= 0x8000u) ba = wrap_base + ((ba - 0x8000u) & 0x7FFFu);
                u8 d = WS->ram[ba & 0x7FFFu];
                ba += 8u;
                if (chars_per_row == 80) {
                    /* 640 px -> downsample 2:1 to 320 px */
                    if (bpp == 1) {
                        for (int p = 0; p < 4; p++)
                            dst[cc * 4 + p] = epal[((d >> (7 - p * 2)) | (d >> (6 - p * 2))) & 1u];
                    } else {
                        for (int p = 0; p < 4; p++) {
                            u8 idx = (u8)((((d >> (7 - p)) & 1u) << 1) | ((d >> (3 - p)) & 1u));
                            dst[cc * 4 + p] = epal[idx];
                        }
                    }
                } else {
                    if (bpp == 1) {
                        for (int p = 0; p < 8; p++)
                            dst[cc * 8 + p] = epal[(d >> (7 - p)) & 1u];
                    } else if (bpp == 2) {
                        for (int p = 0; p < 4; p++) {
                            u8 idx = (u8)((((d >> (7 - p)) & 1u) << 1) | ((d >> (3 - p)) & 1u));
                            u16 rgb = epal[idx];
                            dst[cc * 8 + p * 2] = rgb;
                            dst[cc * 8 + p * 2 + 1] = rgb;
                        }
                    } else {
                        for (int p = 0; p < 2; p++) {
                            u8 idx = (u8)((((d >> (7 - p)) & 1u) << 3) | (((d >> (5 - p)) & 1u) << 2) |
                                          (((d >> (3 - p)) & 1u) << 1) | ((d >> (1 - p)) & 1u));
                            u16 rgb = epal[idx];
                            for (int k = 0; k < 4; k++) dst[cc * 8 + p * 4 + k] = rgb;
                        }
                    }
                }
            }
        }
        row_addr += bytes_per_row;
        if (row_addr >= 0x8000u)
            row_addr = wrap_base + (row_addr - 0x8000u);
    }
    (void)bytes_per_row;
}

static void render_bbc(u16 *pic)
{
    if (!pic) return;
    if (WS->is_electron) {
        render_electron(pic);
        return;
    }
    if (WS->vula_ctrl & 0x02u) {                        /* Teletext Mode 7 */
        render_mode7_teletext(pic);
        return;
    }

    for (int i = 0; i < BBC_W * BBC_H; i++)
        pic[i] = 0;

    int cols = WS->crtc[1] ? WS->crtc[1] : 40;
    int rows = WS->crtc[6] ? WS->crtc[6] : 32;
    int cell_h = (WS->crtc[9] & 0x1Fu) + 1;
    u32 ma_row = (((u32)WS->crtc[12] & 0x3Fu) << 8) | WS->crtc[13];
    static const u16 wrap_tbl[4] = {0x4000u, 0x3000u, 0x6000u, 0x5800u};
    u32 wrap_base = wrap_tbl[(WS->ic32 >> 4) & 3u];
    u8 chars_sel = (WS->vula_ctrl >> 2) & 3u;           /* 0=10ch(16c), 1=20ch(4c/16c), 2=40ch(2c/4c), 3=80ch(2c) */

    for (int cr = 0; cr < rows; cr++) {
        for (int ra = 0; ra < cell_h && ra < 8; ra++) {
            int sy = cr * cell_h + ra;
            if (sy >= BBC_H) break;
            u16 *dst = pic + sy * BBC_W;
            u32 ma = ma_row;
            for (int cc = 0; cc < cols; cc++, ma = (ma + 1u) & 0x3FFFu) {
                u32 addr = (ma << 3) | (u32)ra;
                if (addr & 0x8000u)
                    addr = (addr + wrap_base) & 0x7FFFu;
                u8 d = WS->ram[addr & 0x7FFFu];

                if (cols >= 80) {                       /* 80 bytes/line (Modes 0, 1, 2, 3) -> 4 out pixels/byte */
                    if (chars_sel == 3u) {              /* Mode 0 / 3: 1bpp (640 -> 320) */
                        for (int p = 0; p < 4; p++) {
                            u8 idx0 = ((d >> (7 - p * 2)) & 1u) ? 8u : 0u;
                            u8 idx1 = ((d >> (6 - p * 2)) & 1u) ? 8u : 0u;
                            u32 c0 = bbc_logical_rgb(idx0), c1 = bbc_logical_rgb(idx1);
                            if (cc * 4 + p < BBC_W)
                                dst[cc * 4 + p] = (u16)(((c0 & 0x7BDEu) >> 1) + ((c1 & 0x7BDEu) >> 1) + (c0 & c1 & 0x0421u));
                        }
                    } else if (chars_sel == 2u) {       /* Mode 1: 2bpp (320 px exact!) */
                        for (int p = 0; p < 4; p++) {
                            u8 idx = (u8)((((d >> (7 - p)) & 1u) << 3) | (((d >> (3 - p)) & 1u) << 1));
                            if (cc * 4 + p < BBC_W)
                                dst[cc * 4 + p] = bbc_logical_rgb(idx);
                        }
                    } else {                            /* Mode 2: 4bpp (160 -> 320) */
                        for (int p = 0; p < 2; p++) {
                            u8 idx = (u8)((((d >> (7 - p)) & 1u) << 3) | (((d >> (5 - p)) & 1u) << 2) |
                                          (((d >> (3 - p)) & 1u) << 1) | ((d >> (1 - p)) & 1u));
                            u16 rgb = bbc_logical_rgb(idx);
                            if (cc * 4 + p * 2 + 1 < BBC_W) {
                                dst[cc * 4 + p * 2] = rgb;
                                dst[cc * 4 + p * 2 + 1] = rgb;
                            }
                        }
                    }
                } else {                                /* 40 bytes/line (Modes 4, 5, 6) -> 8 out pixels/byte */
                    if (chars_sel >= 2u) {              /* Mode 4 / 6: 1bpp (320 px exact!) */
                        for (int p = 0; p < 8; p++) {
                            u8 idx = ((d >> (7 - p)) & 1u) ? 8u : 0u;
                            if (cc * 8 + p < BBC_W)
                                dst[cc * 8 + p] = bbc_logical_rgb(idx);
                        }
                    } else {                            /* Mode 5: 2bpp (160 -> 320, used by Hopman!) */
                        for (int p = 0; p < 4; p++) {
                            /* Mode 5 maps 2bpp bits (b7,b3) to Video ULA palette entries 0, 2, 8, 10! */
                            u8 idx = (u8)((((d >> (7 - p)) & 1u) << 3) | (((d >> (3 - p)) & 1u) << 1));
                            u16 rgb = bbc_logical_rgb(idx);
                            if (cc * 8 + p * 2 + 1 < BBC_W) {
                                dst[cc * 8 + p * 2] = rgb;
                                dst[cc * 8 + p * 2 + 1] = rgb;
                            }
                        }
                    }
                }
            }
        }
        ma_row = (ma_row + (u32)cols) & 0x3FFFu;
    }
}

/* ---- 48 kHz Audio Synthesis (4 MHz SN76489 + Electron ULA Tone) ---- */

static void step_audio_frame(void)
{
    if (!WS->sample_rate) return;
    u32 n_samp = WS->sample_rate / 50u;
    static const s16 vol_lut[16] = {
        4800, 3810, 3025, 2400, 1908, 1515, 1203, 955,
        758,  602,  478,  380,  301,  239,  190,  0
    };

    for (u32 s = 0; s < n_samp; s++) {
        s32 sum = 0;
        if (WS->is_electron) {
            if (((WS->elk_misc >> 1) & 3u) == 1u) {
                u32 hz = 1000000u / (16u * ((u32)WS->elk_snd_div + 1u));
                WS->elk_ph += (hz << 16) / WS->sample_rate;
                sum = (WS->elk_ph & 0x8000u) ? 5500 : -5500;
            }
        } else {
            /* 4 MHz / 16 = 250,000 Hz SN76489 clock */
            WS->chip_frac += 250000u;
            while (WS->chip_frac >= WS->sample_rate) {
                WS->chip_frac -= WS->sample_rate;
                for (int c = 0; c < 3; c++) {
                    if (WS->sn_cnt[c] > 0u) WS->sn_cnt[c]--;
                    if (WS->sn_cnt[c] == 0u) {
                        WS->sn_cnt[c] = WS->sn_tone[c] ? WS->sn_tone[c] : 1u;
                        WS->sn_out[c] ^= 1u;
                    }
                }
                if (WS->sn_ncnt > 0u) WS->sn_ncnt--;
                if (WS->sn_ncnt == 0u) {
                    u8 r = WS->sn_noise_ctrl & 3u;
                    WS->sn_ncnt = (r == 3u) ? (WS->sn_tone[2] ? WS->sn_tone[2] : 1u) : (u16)(0x10u << r);
                    WS->sn_n_out ^= 1u;
                    if (WS->sn_n_out) {
                        u16 fb = (WS->sn_noise_ctrl & 4u)
                               ? (u16)(((WS->sn_lfsr & 1u) ^ ((WS->sn_lfsr >> 1) & 1u)) & 1u)
                               : (u16)(WS->sn_lfsr & 1u);
                        WS->sn_lfsr = (u16)((WS->sn_lfsr >> 1) | (fb << 14));
                    }
                }
            }
            for (int c = 0; c < 3; c++) {
                s16 v = vol_lut[WS->sn_vol[c] & 15u];
                sum += (WS->sn_tone[c] <= 1u || WS->sn_out[c]) ? v : -v;
            }
            s16 nv = vol_lut[WS->sn_vol[3] & 15u];
            sum += (WS->sn_lfsr & 1u) ? nv : -nv;
        }
        if (sum > 32767) sum = 32767;
        else if (sum < -32768) sum = -32768;
        WS->snd_ring[WS->snd_head & (SND_RING - 1u)] = (s16)sum;
        WS->snd_head++;
        if (WS->snd_head - WS->snd_tail > SND_RING)
            WS->snd_tail = WS->snd_head - SND_RING;
    }
}

/* ---- UEF & Acorn DFS (.ssd / .dsd) Parsers ---- */

static int parse_uef(const u8 *data, u32 size)
{
    if (size < 12u || data[0] != 'U' || data[1] != 'E' || data[2] != 'F')
        return 0;
    u32 pos = 12u;
    int blocks_ok = 0;
    u32 base_load = 0, exec_addr = 0, total_end = 0;

    while (pos + 6u <= size) {
        u16 cid = (u16)data[pos] | ((u16)data[pos + 1u] << 8);
        u32 clen = (u32)data[pos + 2u] | ((u32)data[pos + 3u] << 8) |
                   ((u32)data[pos + 4u] << 16) | ((u32)data[pos + 5u] << 24);
        pos += 6u;
        if (pos + clen > size) break;
        const u8 *blk = data + pos;
        if (cid == 0x0100u && clen >= 22u && blk[0] == 0x2Au) {
            u32 fn = 1u;
            while (fn < clen && blk[fn] != 0u) fn++;
            if (fn + 20u <= clen) {
                const u8 *h = blk + fn + 1u;
                u32 ld = (u32)h[0] | ((u32)h[1] << 8);
                u32 ex = (u32)h[4] | ((u32)h[5] << 8);
                u16 bno = (u16)h[8] | ((u16)h[9] << 8);
                u16 blen = (u16)h[10] | ((u16)h[11] << 8);
                u32 pay_off = fn + 20u;
                if (pay_off + blen <= clen) {
                    if (!blocks_ok) { base_load = ld; exec_addr = ex; }
                    u32 dst_off = (ld + (u32)bno * 256u) & 0x7FFFu;
                    for (u32 i = 0; i < blen && dst_off + i < sizeof(WS->prog_buf); i++)
                        WS->prog_buf[dst_off + i] = blk[pay_off + i];
                    if (dst_off + blen > total_end) total_end = dst_off + blen;
                    blocks_ok++;
                }
            }
        }
        pos += clen;
    }
    if (!blocks_ok) return 0;
    WS->has_prog = 1;
    WS->prog_load = (u16)(base_load & 0x7FFFu);
    WS->prog_exec = (u16)((exec_addr ? exec_addr : base_load) & 0x7FFFu);
    WS->prog_len  = (u16)((total_end > WS->prog_load) ? (total_end - WS->prog_load) : 0u);
    return 1;
}

static int parse_dfs_ssd(const u8 *data, u32 size, int is_dsd)
{
    if (size < 512u) return 0;
    u32 n_files = (data[0x105] >> 3) & 31u;
    if (!n_files) return 0;

    /* Pick first file with valid load/exec in $0800..$7FFF (or !BOOT if machine code) */
    int pick = 0;
    for (u32 f = 0; f < n_files; f++) {
        const u8 *m = data + 0x108u + f * 8u;
        u32 ld = (u32)m[0] | ((u32)m[1] << 8);
        u32 ex = (u32)m[2] | ((u32)m[3] << 8);
        if (ld >= 0x0800u && ld < 0x7C00u && ex >= 0x0800u && ex < 0x8000u) {
            pick = (int)f;
            break;
        }
    }
    const u8 *m = data + 0x108u + (u32)pick * 8u;
    u32 hi = m[6];
    u32 ld  = (u32)m[0] | ((u32)m[1] << 8);
    u32 ex  = (u32)m[2] | ((u32)m[3] << 8);
    u32 len = (u32)m[4] | ((u32)m[5] << 8) | (((hi >> 4) & 3u) << 16);
    u32 sec = (u32)m[7] | ((hi & 3u) << 8);
    if (len == 0u || len > 0x7800u) return 0;

    u32 dst = ld & 0x7FFFu;
    for (u32 b = 0; b < len && dst + b < sizeof(WS->prog_buf); b++) {
        u32 cur_sec = sec + (b >> 8);
        u32 byte_in_sec = b & 0xFFu;
        u32 disk_off = is_dsd
                     ? (((cur_sec / 10u) * 20u + (cur_sec % 10u)) * 256u + byte_in_sec)
                     : (cur_sec * 256u + byte_in_sec);
        if (disk_off < size)
            WS->prog_buf[dst + b] = data[disk_off];
    }
    WS->has_prog = 1;
    WS->prog_load = (u16)(ld & 0x7FFFu);
    WS->prog_exec = (u16)((ex >= 0x0400u && ex < 0x8000u) ? ex : ld);
    WS->prog_len  = (u16)len;
    return 1;
}

/* ---- Clean-Room BBC MOS & Electron Boot Setup ---- */

static void build_cleanroom_os(void)
{
    bbc_zero(WS->os_rom, sizeof(WS->os_rom));

    /* $F800 ($3800 in os_rom): Default IRQ1V handler! */
    static const u8 def_irq1v_bbc[] = {
        0xA9, 0x7F, 0x8D, 0x4D, 0xFE,                   /* LDA #$7F : STA $FE4D */
        0xA5, 0xFC, 0x40                                /* LDA $FC : RTI */
    };
    static const u8 def_irq1v_elk[] = {
        0xA5, 0xF4, 0x29, 0x0F, 0x09, 0x30,             /* LDA $F4 : AND #$0F : ORA #$30 */
        0x8D, 0x05, 0xFE,                               /* STA $FE05 */
        0xA5, 0xFC, 0x40                                /* LDA $FC : RTI */
    };
    if (WS->is_electron) {
        for (u32 i = 0; i < sizeof(def_irq1v_elk); i++)
            WS->os_rom[0x3800u + i] = def_irq1v_elk[i];
    } else {
        for (u32 i = 0; i < sizeof(def_irq1v_bbc); i++)
            WS->os_rom[0x3800u + i] = def_irq1v_bbc[i];
    }

    /* $F820: Hardware CPU IRQ entry ($FFFE/$FFFF -> $F820):
       STA $FC : JMP ($0204) -- exact Acorn MOS 1.20 / Electron OS 1.00 convention! */
    static const u8 hw_irq[] = {
        0x85, 0xFC,                                     /* STA $FC */
        0x6C, 0x04, 0x02                                /* JMP ($0204) */
    };
    for (u32 i = 0; i < sizeof(hw_irq); i++)
        WS->os_rom[0x3820u + i] = hw_irq[i];

    /* $F840: Interactive BBC BASIC Mode 7 Shell (when launched with no file "") */
    static const u8 shell_loop[] = {
        0x58,                                           /* CLI */
        0xEA, 0x4C, 0x41, 0xF8                          /* NOP : JMP $F841 */
    };
    for (u32 i = 0; i < sizeof(shell_loop); i++)
        WS->os_rom[0x3840u + i] = shell_loop[i];

    /* Safe RTS stubs at all standard Acorn MOS entry points ($FFD0..$FFF7) */
    for (u32 a = 0x3FD0u; a < 0x3FFAu; a++)
        WS->os_rom[a] = 0x60u;                          /* RTS */

    /* Vectors: NMI=$F80F (RTI at $F810), RESET=$F840, IRQ=$F820 */
    WS->os_rom[0x3830u] = 0x40u;                        /* RTI */
    WS->os_rom[0x3FFAu] = 0x30u; WS->os_rom[0x3FFBu] = 0xF8u;
    WS->os_rom[0x3FFCu] = 0x40u; WS->os_rom[0x3FFDu] = 0xF8u;
    WS->os_rom[0x3FFEu] = 0x20u; WS->os_rom[0x3FFFu] = 0xF8u;
}

void bbc_reset(void)
{
    bbc_zero(WS->ram, sizeof(WS->ram));
    bbc_zero(&WS->sys_via, sizeof(WS->sys_via));
    bbc_zero(&WS->usr_via, sizeof(WS->usr_via));
    WS->sn_vol[0] = WS->sn_vol[1] = WS->sn_vol[2] = WS->sn_vol[3] = 15u;
    WS->sn_lfsr = 0x4000u;

    if (!WS->ext_os)
        build_cleanroom_os();

    /* Initialize OS workspace & default IRQ1V ($0204 = $F800) */
    WS->ram[0x0204] = 0x00u; WS->ram[0x0205] = 0xF8u;
    WS->ram[0x00F4] = 0x0Au;
    WS->ram[0x0282] = 0x28u;
    WS->elk_rom_pg = 0x0Au;
    WS->elk_misc = 0x38u;

    /* Default System VIA: Timer 1 free-running at 100 Hz ($270E = 9998 us), IER = $C0! */
    WS->sys_via.t1l = 0x270Eu;
    WS->sys_via.t1c = 0x270Eu;
    WS->sys_via.acr = 0x40u;
    WS->sys_via.ier = 0xC2u;                            /* Timer 1 (100 Hz) + CA1 (VSync) */
    WS->ic32 = 0x39u;                                   /* Mode 7 wrap + Sound WE high + Kbd auto */

    /* Default Mode 7 Teletext banner ($7C00) */
    WS->vula_ctrl = 0x4Bu;
    for (int i = 0; i < 16; i++)
        WS->vula_pal[i] = (u8)(i & 7u);
    for (int i = 0; i < 1024; i++)
        WS->ram[0x7C00 + i] = ' ';
    WS->basic_col = 0;
    WS->basic_row = 0;

    update_mmu_map();

    WS->a = WS->x = WS->y = 0;
    WS->s = 0xFFu;
    WS->p = FU;
    WS->jam = 0;

    if (WS->has_prog) {
        for (u32 i = 0; i < WS->prog_len && (u32)WS->prog_load + i < 0x8000u; i++)
            WS->ram[WS->prog_load + i] = WS->prog_buf[WS->prog_load + i];
        WS->pc = WS->prog_exec;
    } else if (WS->ext_os) {
        WS->pc = rd16_6502(0xFFFCu);
    } else {
        teletext_puts("\x03" "BBC Computer 32K\r\n\r\nAcorn DFS\r\n\r\nBASIC\r\n>");
        WS->pc = 0xF840u;
    }
}

const char *bbc_load(const u8 *image, u32 size, const char *path,
                     const u8 *os_rom, u32 os_sz, const u8 *bas_rom, u32 bas_sz)
{
#ifdef BBC_HOST
    u32 saved_rate = WS->sample_rate;
#endif
    bbc_zero(WS, sizeof(*WS) - sizeof(WS->gz_scratch));
#ifdef BBC_HOST
    WS->sample_rate = saved_rate ? saved_rate : 48000u;
#else
    WS->sample_rate = 48000u;
#endif

    if (os_rom && os_sz == 0x4000u) {
        for (u32 i = 0; i < 0x4000u; i++) WS->os_rom[i] = os_rom[i];
        WS->ext_os = 1;
    }
    if (bas_rom && bas_sz == 0x4000u) {
        for (u32 i = 0; i < 0x4000u; i++) WS->sw_rom[0][i] = bas_rom[i];
        WS->ext_basic = 1;
    }

    WS->is_electron = (ci_ends(path, "_el.uef") || ci_ends(path, ".elk")) ? 1u : 0u;

    if (image && size > 0 && path && *path) {
        const u8 *src = image;
        u32 src_sz = size;
        if (gz_is(image, size)) {
            char gname[64];
            u32 unp = 0;
            if (gz_unpack(image, size, WS->gz_scratch, sizeof(WS->gz_scratch), &unp, gname, sizeof(gname)) == 0) {
                src = WS->gz_scratch;
                src_sz = unp;
            }
        }
        if (src_sz >= 12u && src[0] == 'U' && src[1] == 'E' && src[2] == 'F') {
            if (!parse_uef(src, src_sz))
                return "no loadable Acorn tape blocks in .uef";
        } else if (ci_ends(path, ".rom") && src_sz <= 0x4000u) {
            for (u32 i = 0; i < src_sz; i++) WS->sw_rom[3][i] = src[i];
            WS->romsel = 3u;
        } else if (ci_ends(path, ".ssd") || ci_ends(path, ".dsd") || src_sz >= 2560u) {
            if (!parse_dfs_ssd(src, src_sz, ci_ends(path, ".dsd")))
                return "no bootable machine-code file found on BBC .ssd/.dsd disk";
        } else {
            return "unsupported BBC Micro / Electron file (expected .uef, .ssd, .dsd or .rom)";
        }
    }

    const char *mname = WS->is_electron ? "Acorn Electron (ULA" : "BBC Micro Model B 32K (6502 + Video ULA";
    char *p = WS->info;
    while (*mname) *p++ = *mname++;
    const char *suf = WS->has_prog ? ", auto-boot)" : ", Teletext BASIC)";
    while (*suf) *p++ = *suf++;
    *p = 0;

    bbc_reset();
    return 0;
}

void bbc_frame(u16 pad, u16 *picture)
{
    WS->pad = pad;
    rebuild_key_matrices(WS->last_usages, WS->last_n);
    if (WS->type_r != WS->type_w && !WS->has_prog && !WS->ext_os) {
        char c = WS->type_q[WS->type_r];
        WS->type_r = (WS->type_r + 1u) & 63u;
        if (c == '\r' || c == '\n') {
            teletext_puts("\r\n>");
        } else {
            teletext_putc(c);
        }
    }

    /* 2 MHz 6502 @ 50 Hz PAL = 40,000 CPU cycles (20,000 1 MHz VIA ticks) across 312 lines */
    const s32 cyc_per_line = 128;
    for (int line = 0; line < 312; line++) {
        s32 rem = cyc_per_line;
        while (rem > 0 && !WS->jam) {
            u32 c = step6502();
            rem -= (s32)c;
        }
        /* Advance 1 MHz VIA timers by 64 ticks per scanline */
        via_step(&WS->sys_via, 64u);
        via_step(&WS->usr_via, 64u);

        if (line == 256) {
            /* VSync CA1 on System VIA + Electron Display End + 50 Hz RTC */
            WS->sys_via.ifr |= 0x02u;
            WS->elk_isr |= 0x0Cu;
        }
    }

    if (++WS->flash_cnt >= 25u) {
        WS->flash_cnt = 0;
        WS->flash_state ^= 1u;
    }

    render_bbc(picture);
    step_audio_frame();
    WS->frames++;
}

const char *bbc_info(void) { return WS->info; }
int bbc_jammed(void) { return WS->jam; }

void bbc_audio_rate(u32 hz)
{
    WS->sample_rate = hz;
    WS->snd_frac = WS->chip_frac = 0;
    WS->snd_head = WS->snd_tail = 0;
}

int bbc_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && WS->snd_tail != WS->snd_head) {
        out[n++] = WS->snd_ring[WS->snd_tail & (SND_RING - 1u)];
        WS->snd_tail++;
    }
    return n;
}
