/* Texas Instruments TI-99/4A ('ti99'): see ti99.h.
   Pass-optimized for 594 MHz MIPS32:
   - Zero static .bss (all console ROM, 32K RAM, banked cartridge ROM, GROM, VRAM & audio in EMU_RAM_PHYS)
   - Direct Scratchpad ($8300..$83FF) fast-path + 64-entry 1 KB big-endian CPU page map
   - Cycle-accurate VDP status polling ($8802) + scanline sprite/tile renderer
   - 48 kHz fixed-point TMS9919 3-tone + LFSR noise synthesizer */
#pragma GCC optimize("O2")
#include "ti99.h"
#include "zip.h"

#ifndef TI99_HOST
#include "hw.h"
#endif

#define ST_LGT 0x8000u
#define ST_AGT 0x4000u
#define ST_EQ  0x2000u
#define ST_C   0x1000u
#define ST_OV  0x0800u
#define ST_OP  0x0400u
#define ST_X   0x0200u
#define ST_IM  0x000Fu

#define SND_RING 4096
#define CART_MAX 0x80000u       /* Up to 512 KB banked 378/379i cartridge ROM */
#define GROM_MAX 0x10000u       /* 64 KB GROM space ($0000..$5FFF console, $6000..$FFFF cart) */

struct ti99_ws {
    /* TMS9900 16-bit CPU state */
    u16 pc, wp, st;
    u8  idle, jam;
    s32 cycles;

    /* 64 x 1 KB page pointer map (0 = MMIO slow path) */
    u8 *rdp[64], *wrp[64];

    /* Memory regions */
    u8  sys_rom[0x2000];        /* $0000..$1FFF 8 KB Console ROM */
    u8  exp_lo[0x2000];         /* $2000..$3FFF 8 KB Low Expansion RAM */
    u8  dsr_rom[0x2000];        /* $4000..$5FFF DSR space */
    u8  exp_hi[0x6000];         /* $A000..$FFFF 24 KB High Expansion RAM */
    u8  pad_ram[0x0100];        /* $8300..$83FF 256 B 16-bit Scratchpad RAM */
    u8  cart_rom[CART_MAX];     /* Banked cartridge ROM ($6000..$7FFF) */
    u8  cart_ram[0x2000];       /* Mini-Memory RAM ($7000..$7FFF when unbanked) */
    u8  grom[GROM_MAX];         /* 64 KB GROM/GRAM */
    u8  vram[0x4000];           /* 16 KB TMS9918A VRAM */
    u8  zip_tmp[0x40000];       /* 256 KB scratch for .rpk / .zip unpacking */

    /* Cartridge banking & GROM state */
    u32 cart_banks;             /* Number of 8 KB ROM banks */
    u32 cur_bank;
    u8  bank_inverted;          /* 1 = 379i inverted, 0 = 378 non-inverted */
    u8  has_cart_rom, has_grom, basic_mode;
    u16 grom_addr;
    u8  grom_latch;

    /* TMS9901 PSI / CRU Keyboard & Joystick */
    u8  cru_sys[32];            /* System CRU output bits 0..31 */
    u8  kbd_col;                /* Selected column 0..7 (CRU bits 18..20) */
    u8  alpha_lock;
    u8  cru_cols[8];            /* Active-LOW 8-bit row mask per column 0..7 */
    u8  usb_cols[8];
    u16 pad;
    char type_q[64];
    u8  type_r, type_w, type_hold;
    char type_ch;
    u16 tms9901_timer, tms9901_clock;
    u8  tms9901_mode;

    /* TMS9918A VDP */
    u8  vdp_reg[8];
    u16 vdp_addr;
    u8  vdp_latch, vdp_first, vdp_read_buf, vdp_status;

    /* TMS9919 / SN76489 Audio */
    u8  sn_latch;
    u16 sn_tone[4], sn_cnt[4];
    u8  sn_vol[4], sn_out[4];
    u16 sn_lfsr;
    u32 sample_rate, snd_frac, chip_frac;
    u32 snd_head, snd_tail;
    s16 snd_ring[SND_RING];

    /* Interactive TI BASIC state (when launched with "") */
    u8  bas_x, bas_y;
    char bas_line[64];
    u8  bas_len;
    u32 frames;

    char title[40];
    char info[96];
};

#ifdef TI99_HOST
static struct ti99_ws ti99_host_ws;
#define WS (&ti99_host_ws)
#else
#define WS ((struct ti99_ws *)KSEG0(EMU_RAM_PHYS))
#ifndef TI99_NO_ASSERT
_Static_assert(sizeof(struct ti99_ws) <= EMU_RAM_SIZE, "ti99_ws exceeds EMU_RAM_SIZE");
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

static int ci_contains(const char *s, u32 n, const char *sub)
{
    u32 m = 0;
    while (sub[m]) m++;
    if (n < m) return 0;
    for (u32 i = 0; i + m <= n; i++) {
        u32 k = 0;
        while (k < m && ((s[i + k] | 32) == (sub[k] | 32))) k++;
        if (k == m) return 1;
    }
    return 0;
}

/* TMS9918A 16-color palette in 0bbbbbgggggrrrrr (play.c 15-bit format) */
#define RGB15(r, g, b) ((u16)((((b) >> 3) << 10) | (((g) >> 3) << 5) | ((r) >> 3)))
static const u16 tms_pal15[16] = {
    RGB15(  0,   0,   0),       /*  0: Transparent (backdrop) */
    RGB15(  0,   0,   0),       /*  1: Black */
    RGB15( 33, 200,  66),       /*  2: Medium Green */
    RGB15( 94, 220, 120),       /*  3: Light Green */
    RGB15( 84,  85, 237),       /*  4: Dark Blue */
    RGB15(125, 118, 252),       /*  5: Light Blue */
    RGB15(212,  82,  77),       /*  6: Dark Red */
    RGB15( 66, 235, 245),       /*  7: Cyan */
    RGB15(252,  85,  84),       /*  8: Medium Red */
    RGB15(255, 121, 120),       /*  9: Light Red */
    RGB15(212, 193,  84),       /* 10: Dark Yellow */
    RGB15(230, 206, 128),       /* 11: Light Yellow */
    RGB15( 33, 176,  59),       /* 12: Dark Green */
    RGB15(201,  91, 186),       /* 13: Magenta */
    RGB15(204, 204, 204),       /* 14: Gray */
    RGB15(255, 255, 255)        /* 15: White */
};

/* Clean-room 5x7 ASCII font (0x20..0x7F) loaded into Console GROM & TI BASIC VRAM */
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

/* Odd-parity lookup table for TMS9900 byte operations (ST_OP = 0x0400) */
static const u8 odd_par[256] = {
    0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0, 1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
    1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1, 0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,
    1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1, 0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,
    0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0, 1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
    1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1, 0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0,
    0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0, 1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
    0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0, 1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1,
    1,0,0,1,0,1,1,0,0,1,1,0,1,0,0,1, 0,1,1,0,1,0,0,1,1,0,0,1,0,1,1,0
};

/* ---- TMS9919 / SN76489 4-Channel PSG @ 48 kHz ---- */

static const s16 sn_vol_lut[16] = {
    4400, 3495, 2776, 2205, 1752, 1391, 1105,  878,
     697,  554,  440,  349,  278,  220,  175,    0
};

static void sn_write(u8 v)
{
    if (v & 0x80u) {
        u8 reg = (v >> 4) & 7u;
        WS->sn_latch = reg;
        u8 ch = reg >> 1;
        if (reg & 1u) {
            WS->sn_vol[ch] = v & 0x0Fu;
        } else if (ch < 3u) {
            WS->sn_tone[ch] = (u16)((WS->sn_tone[ch] & 0x3F0u) | (v & 0x0Fu));
        } else {
            WS->sn_tone[3] = v & 0x07u;
            WS->sn_lfsr = 0x8000u;
        }
    } else {
        u8 reg = WS->sn_latch;
        u8 ch = reg >> 1;
        if (reg & 1u) {
            WS->sn_vol[ch] = v & 0x0Fu;
        } else if (ch < 3u) {
            WS->sn_tone[ch] = (u16)(((u16)(v & 0x3Fu) << 4) | (WS->sn_tone[ch] & 0x0Fu));
        } else {
            WS->sn_tone[3] = v & 0x07u;
            WS->sn_lfsr = 0x8000u;
        }
    }
}

static void sn_step_sample(void)
{
    /* TMS9919 clock = 3,579,545 Hz / 16 = 223,721.56 Hz */
    WS->chip_frac += 223722u;
    u32 sr = WS->sample_rate ? WS->sample_rate : 48000u;
    s32 acc = 0, ticks = 0;
    while (WS->chip_frac >= sr) {
        WS->chip_frac -= sr;
        ticks++;
        for (int c = 0; c < 3; c++) {
            if (WS->sn_cnt[c] > 0) WS->sn_cnt[c]--;
            if (WS->sn_cnt[c] == 0) {
                u16 p = WS->sn_tone[c];
                WS->sn_cnt[c] = p ? p : 1u;
                if (p <= 1u) WS->sn_out[c] = 1u;
                else         WS->sn_out[c] ^= 1u;
            }
        }
        if (WS->sn_cnt[3] > 0) WS->sn_cnt[3]--;
        if (WS->sn_cnt[3] == 0) {
            u8 nf = WS->sn_tone[3] & 3u;
            u16 np = (nf == 0) ? 0x10u : (nf == 1) ? 0x20u : (nf == 2) ? 0x40u : WS->sn_tone[2];
            WS->sn_cnt[3] = np ? np : 1u;
            WS->sn_out[3] ^= 1u;
            if (WS->sn_out[3]) {
                u16 fb = (WS->sn_tone[3] & 4u)
                    ? (u16)(((WS->sn_lfsr & 1u) ^ ((WS->sn_lfsr >> 3) & 1u)) & 1u)
                    : (u16)(WS->sn_lfsr & 1u);
                WS->sn_lfsr = (u16)((WS->sn_lfsr >> 1) | (fb << 15));
            }
        }
        s32 s = 0;
        for (int c = 0; c < 3; c++) {
            s16 v = sn_vol_lut[WS->sn_vol[c] & 15u];
            s += WS->sn_out[c] ? v : -v;
        }
        s16 nv = sn_vol_lut[WS->sn_vol[3] & 15u];
        s += (WS->sn_lfsr & 1u) ? nv : -nv;
        acc += s;
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

/* ---- Cartridge Bank Mapping & Memory Bus ---- */

static void map_cart_bank(u32 raw_bank)
{
    if (!WS->cart_banks) {
        for (int i = 0; i < 8; i++) {
            WS->rdp[24 + i] = (i >= 4) ? (WS->cart_ram + (i - 4) * 0x400) : WS->cart_rom + i * 0x400;
            WS->wrp[24 + i] = 0;        /* Writes to $6000..$7FFF go to slow path for banking / MiniMem RAM */
        }
        return;
    }
    u32 b = raw_bank % WS->cart_banks;
    if (WS->bank_inverted)
        b = (WS->cart_banks - 1u) - b;
    WS->cur_bank = b;
    u8 *base = WS->cart_rom + b * 0x2000u;
    for (int i = 0; i < 8; i++) {
        WS->rdp[24 + i] = base + i * 0x400;
        WS->wrp[24 + i] = 0;
    }
}

static void setup_mem_map(void)
{
    for (int i = 0; i < 64; i++) {
        WS->rdp[i] = 0;
        WS->wrp[i] = 0;
    }
    /* $0000..$1FFF: 8 KB Console ROM */
    for (int i = 0; i < 8; i++)
        WS->rdp[i] = WS->sys_rom + i * 0x400;
    /* $2000..$3FFF: 8 KB Low Expansion RAM */
    for (int i = 0; i < 8; i++)
        WS->rdp[8 + i] = WS->wrp[8 + i] = WS->exp_lo + i * 0x400;
    /* $4000..$5FFF: DSR ROM */
    for (int i = 0; i < 8; i++)
        WS->rdp[16 + i] = WS->dsr_rom + i * 0x400;
    /* $6000..$7FFF: Cartridge ROM/RAM */
    map_cart_bank(0);
    /* $A000..$FFFF: 24 KB High Expansion RAM */
    for (int i = 0; i < 24; i++)
        WS->rdp[40 + i] = WS->wrp[40 + i] = WS->exp_hi + i * 0x400;
}

static u8 vdp_read_data(void)
{
    u8 v = WS->vdp_read_buf;
    WS->vdp_read_buf = WS->vram[WS->vdp_addr & 0x3FFFu];
    WS->vdp_addr = (WS->vdp_addr + 1u) & 0x3FFFu;
    WS->vdp_first = 0;
    return v;
}

static u8 vdp_read_status(void)
{
    u8 st = WS->vdp_status;
    WS->vdp_status &= 0x1Fu;            /* Clear INT (0x80), 5S (0x40), Collision (0x20) */
    WS->vdp_first = 0;
    return st;
}

static void vdp_write_data(u8 v)
{
    WS->vram[WS->vdp_addr & 0x3FFFu] = v;
    WS->vdp_read_buf = v;
    WS->vdp_addr = (WS->vdp_addr + 1u) & 0x3FFFu;
    WS->vdp_first = 0;
}

static void vdp_write_ctrl(u8 v)
{
    if (!WS->vdp_first) {
        WS->vdp_latch = v;
        WS->vdp_first = 1;
    } else {
        WS->vdp_first = 0;
        if (v & 0x80u) {
            WS->vdp_reg[v & 7u] = WS->vdp_latch;
        } else {
            WS->vdp_addr = (u16)(((u16)(v & 0x3Fu) << 8) | WS->vdp_latch);
            if (!(v & 0x40u)) {
                WS->vdp_read_buf = WS->vram[WS->vdp_addr & 0x3FFFu];
                WS->vdp_addr = (WS->vdp_addr + 1u) & 0x3FFFu;
            }
        }
    }
}

static u8 mmio_read8(u16 addr)
{
    if ((addr & 0xFC00u) == 0x8000u)
        return WS->pad_ram[addr & 0xFFu];
    if ((addr & 0xFC00u) == 0x8800u) {
        if (addr & 1u) return 0;
        return (addr & 2u) ? vdp_read_status() : vdp_read_data();
    }
    if ((addr & 0xFC00u) == 0x9800u) {
        if (addr & 1u) return 0;
        if (addr & 2u) {
            u16 next = (u16)((WS->grom_addr + 1u) & 0xFFFFu);
            u8 out = WS->grom_latch ? (u8)(next & 0xFFu) : (u8)(next >> 8);
            WS->grom_latch ^= 1u;
            return out;
        } else {
            u8 v = WS->grom[WS->grom_addr];
            WS->grom_addr = (u16)((WS->grom_addr & 0xE000u) | ((WS->grom_addr + 1u) & 0x1FFFu));
            WS->grom_latch = 0;
            return v;
        }
    }
    return 0;
}

static void mmio_write8(u16 addr, u8 v)
{
    if (addr >= 0x6000u && addr < 0x8000u) {
        if (WS->cart_banks > 1u)
            map_cart_bank((u32)(addr - 0x6000u) >> 1);
        else if (addr >= 0x7000u)
            WS->cart_ram[addr - 0x7000u] = v;
        return;
    }
    if ((addr & 0xFC00u) == 0x8000u) {
        WS->pad_ram[addr & 0xFFu] = v;
        return;
    }
    if ((addr & 0xFC00u) == 0x8400u) {
        if (!(addr & 1u)) sn_write(v);
        return;
    }
    if ((addr & 0xFC00u) == 0x8C00u) {
        if (addr & 1u) return;
        if (addr & 2u) vdp_write_ctrl(v);
        else           vdp_write_data(v);
        return;
    }
    if ((addr & 0xFC00u) == 0x9C00u) {
        if (addr & 1u) return;
        if (addr & 2u) {
            if (!WS->grom_latch) {
                WS->grom_addr = (u16)(((u16)v << 8) | (WS->grom_addr & 0xFFu));
                WS->grom_latch = 1;
            } else {
                WS->grom_addr = (u16)((WS->grom_addr & 0xFF00u) | v);
                WS->grom_latch = 0;
            }
        } else {
            WS->grom[WS->grom_addr] = v;
            WS->grom_addr = (u16)((WS->grom_addr & 0xE000u) | ((WS->grom_addr + 1u) & 0x1FFFu));
            WS->grom_latch = 0;
        }
    }
}

INLINE u16 mem_rd16(u16 addr)
{
    addr &= 0xFFFEu;
    if ((addr & 0xFF00u) == 0x8300u) {
        const u8 *p = WS->pad_ram + (addr & 0xFEu);
        return (u16)(((u16)p[0] << 8) | p[1]);
    }
    const u8 *pg = WS->rdp[addr >> 10];
    if (pg) {
        const u8 *p = pg + (addr & 0x3FEu);
        return (u16)(((u16)p[0] << 8) | p[1]);
    }
    u8 hi = mmio_read8(addr);
    u8 lo = mmio_read8((u16)(addr + 1u));
    return (u16)(((u16)hi << 8) | lo);
}

INLINE void mem_wr16(u16 addr, u16 val)
{
    addr &= 0xFFFEu;
    if ((addr & 0xFF00u) == 0x8300u) {
        u8 *p = WS->pad_ram + (addr & 0xFEu);
        p[0] = (u8)(val >> 8);
        p[1] = (u8)(val & 0xFFu);
        return;
    }
    u8 *pg = WS->wrp[addr >> 10];
    if (pg) {
        u8 *p = pg + (addr & 0x3FEu);
        p[0] = (u8)(val >> 8);
        p[1] = (u8)(val & 0xFFu);
        return;
    }
    mmio_write8(addr, (u8)(val >> 8));
    mmio_write8((u16)(addr + 1u), (u8)(val & 0xFFu));
}

INLINE u8 mem_rd8(u16 addr)
{
    if ((addr & 0xFF00u) == 0x8300u)
        return WS->pad_ram[addr & 0xFFu];
    const u8 *pg = WS->rdp[addr >> 10];
    if (pg)
        return pg[addr & 0x3FFu];
    return mmio_read8(addr);
}

INLINE void mem_wr8(u16 addr, u8 val)
{
    /* Authentic TMS9900 byte write: reads 16-bit word first on RAM, or hits byte MMIO directly for VDP/PSG */
    if ((addr & 0xFF00u) == 0x8300u) {
        WS->pad_ram[addr & 0xFFu] = val;
        return;
    }
    u8 *pg = WS->wrp[addr >> 10];
    if (pg) {
        pg[addr & 0x3FFu] = val;
        return;
    }
    mmio_write8(addr, val);
}

INLINE u16 reg_rd(int r)
{
    return mem_rd16((u16)(WS->wp + ((r & 15) << 1)));
}

INLINE void reg_wr(int r, u16 v)
{
    mem_wr16((u16)(WS->wp + ((r & 15) << 1)), v);
}

/* ---- TMS9901 PSI / CRU Keyboard & Joystick Matrix ---- */

enum {
    PAD_A      = 0x001, /* X: Fire 1 */
    PAD_B      = 0x002, /* Z: Fire 2 */
    PAD_SELECT = 0x004, /* Tab/Space: Space / Back (FCTN+9) */
    PAD_START  = 0x008, /* Enter: Enter / 1 */
    PAD_UP     = 0x010,
    PAD_DOWN   = 0x020,
    PAD_LEFT   = 0x040,
    PAD_RIGHT  = 0x080,
    PAD_X      = 0x100, /* C: 2 (Selection 2 on TI menu) */
    PAD_Y      = 0x200  /* V: Redo / Proceed */
};

static void set_key_rc(u8 col, u8 row_bit)
{
    if (col < 8u && row_bit < 8u)
        WS->cru_cols[col] &= (u8)~(1u << row_bit);
}

/* Map ASCII char onto TI-99/4A 8x8 CRU matrix (row_bit 0..7 corresponds to CRU bits 3..10) */
static void press_ascii(char ch, u8 cols[8])
{
    if (ch >= 'a' && ch <= 'z')
        ch = (char)(ch - 32);
    switch (ch) {
    case ' ':  cols[0] &= (u8)~0x02u; break;
    case '\r': case '\n': cols[0] &= (u8)~0x04u; break;
    case '=':  cols[0] &= (u8)~0x01u; break;
    case '.':  cols[1] &= (u8)~0x02u; break;
    case ',':  cols[2] &= (u8)~0x02u; break;
    case 'M':  cols[3] &= (u8)~0x02u; break;
    case 'N':  cols[4] &= (u8)~0x02u; break;
    case '/':  cols[5] &= (u8)~0x02u; break;
    case 'L':  cols[1] &= (u8)~0x08u; break;
    case 'K':  cols[2] &= (u8)~0x08u; break;
    case 'J':  cols[3] &= (u8)~0x08u; break;
    case 'H':  cols[4] &= (u8)~0x08u; break;
    case ';':  cols[5] &= (u8)~0x08u; break;
    case '9':  cols[1] &= (u8)~0x10u; break;
    case '8':  cols[2] &= (u8)~0x10u; break;
    case '7':  cols[3] &= (u8)~0x10u; break;
    case '6':  cols[4] &= (u8)~0x10u; break;
    case '0':  cols[5] &= (u8)~0x10u; break;
    case '2':  cols[1] &= (u8)~0x10u; cols[1] |= 0x10u; cols[1] &= (u8)~0x10u; break;
    default: break;
    }
    /* Exact TI-99/4A 6x8 keyboard matrix (CRU bit 3+r -> bit r):
       r=1 (bit 4): Space(c0), .(c1), ,(c2), M(c3), N(c4), /(c5)
       r=2 (bit 5): Enter(c0), O(c1), I(c2), U(c3), Y(c4), P(c5)
       r=3 (bit 6): (c0), 9(c1), 8(c2), 7(c3), 6(c4), 0(c5)
       r=4 (bit 7): FCTN(c0), 2(c1), 3(c2), 4(c3), 5(c4), 1(c5)
       r=5 (bit 8): SHIFT(c0), S(c1), D(c2), F(c3), G(c4), A(c5)
       r=6 (bit 9): CTRL(c0), W(c1), E(c2), R(c3), T(c4), Q(c5)
       r=7 (bit 10): (c0), X(c1), C(c2), V(c3), B(c4), Z(c5) */
    switch (ch) {
    case 'O': cols[1] &= (u8)~0x04u; break;
    case 'I': cols[2] &= (u8)~0x04u; break;
    case 'U': cols[3] &= (u8)~0x04u; break;
    case 'Y': cols[4] &= (u8)~0x04u; break;
    case 'P': cols[5] &= (u8)~0x04u; break;
    case '9': cols[1] |= 0x10u; cols[1] &= (u8)~0x08u; break;
    case '8': cols[2] |= 0x10u; cols[2] &= (u8)~0x08u; break;
    case '7': cols[3] |= 0x10u; cols[3] &= (u8)~0x08u; break;
    case '6': cols[4] |= 0x10u; cols[4] &= (u8)~0x08u; break;
    case '0': cols[5] |= 0x10u; cols[5] &= (u8)~0x08u; break;
    case '2': cols[1] &= (u8)~0x10u; break;
    case '3': cols[2] &= (u8)~0x10u; break;
    case '4': cols[3] &= (u8)~0x10u; break;
    case '5': cols[4] &= (u8)~0x10u; break;
    case '1': cols[5] &= (u8)~0x10u; break;
    case 'S': cols[1] &= (u8)~0x20u; break;
    case 'D': cols[2] &= (u8)~0x20u; break;
    case 'F': cols[3] &= (u8)~0x20u; break;
    case 'G': cols[4] &= (u8)~0x20u; break;
    case 'A': cols[5] &= (u8)~0x20u; break;
    case 'W': cols[1] &= (u8)~0x40u; break;
    case 'E': cols[2] &= (u8)~0x40u; break;
    case 'R': cols[3] &= (u8)~0x40u; break;
    case 'T': cols[4] &= (u8)~0x40u; break;
    case 'Q': cols[5] &= (u8)~0x40u; break;
    case 'X': cols[1] &= (u8)~0x80u; break;
    case 'C': cols[2] &= (u8)~0x80u; break;
    case 'V': cols[3] &= (u8)~0x80u; break;
    case 'B': cols[4] &= (u8)~0x80u; break;
    case 'Z': cols[5] &= (u8)~0x80u; break;
    case 'L': cols[1] |= 0x08u; cols[1] &= (u8)~0x02u; break;
    default: break;
    }
}

static void update_cru_inputs(u16 pad)
{
    WS->pad = pad;
    for (int c = 0; c < 8; c++)
        WS->cru_cols[c] = WS->usb_cols[c];

    /* Joystick 1 on Column 6 (active-LOW bits 0..4 = CRU bits 3..7) + ESDX / Space / Q / Shift mirror */
    if (pad & PAD_A)      { set_key_rc(6, 0); set_key_rc(0, 1); set_key_rc(5, 6); }
    if (pad & PAD_B)      { set_key_rc(0, 5); set_key_rc(6, 0); }
    if (pad & PAD_LEFT)   { set_key_rc(6, 1); set_key_rc(1, 5); }
    if (pad & PAD_RIGHT)  { set_key_rc(6, 2); set_key_rc(2, 5); }
    if (pad & PAD_DOWN)   { set_key_rc(6, 3); set_key_rc(1, 7); }
    if (pad & PAD_UP)     { set_key_rc(6, 4); set_key_rc(2, 6); }
    if (pad & PAD_START)  { set_key_rc(0, 2); set_key_rc(5, 4); } /* Enter + '1' */
    if (pad & PAD_SELECT) { set_key_rc(0, 1); }                   /* Space */
    if (pad & PAD_X)      { set_key_rc(1, 4); }                   /* '2' */

    if (WS->type_hold > 0) {
        WS->type_hold--;
        press_ascii(WS->type_ch, WS->cru_cols);
    } else if (WS->type_r != WS->type_w) {
        WS->type_ch = WS->type_q[WS->type_r];
        WS->type_r = (WS->type_r + 1u) & 63u;
        WS->type_hold = 3;
        press_ascii(WS->type_ch, WS->cru_cols);
    }
}

static u8 cru_read_bit(u16 bit)
{
    if (bit == 0u) return WS->tms9901_mode;
    if (bit == 2u) return (WS->vdp_status & 0x80u) ? 0u : 1u;   /* VDP INT* active-low on CRU bit 2 */
    if (bit >= 3u && bit <= 10u) {
        if (WS->tms9901_mode && bit <= 14u)
            return (u8)((WS->tms9901_clock >> (bit - 1u)) & 1u);
        u8 col = WS->kbd_col & 7u;
        u8 r = (u8)(bit - 3u);
        return (u8)((WS->cru_cols[col] >> r) & 1u);
    }
    if (bit < 32u)
        return WS->cru_sys[bit];
    return 1u;
}

static void cru_write_bit(u16 bit, u8 v)
{
    v &= 1u;
    if (bit < 32u)
        WS->cru_sys[bit] = v;
    if (bit == 0u)
        WS->tms9901_mode = v;
    else if (WS->tms9901_mode && bit >= 1u && bit <= 14u) {
        u16 m = (u16)(1u << (bit - 1u));
        WS->tms9901_timer = v ? (u16)(WS->tms9901_timer | m) : (u16)(WS->tms9901_timer & ~m);
        WS->tms9901_clock = WS->tms9901_timer;
    } else if (bit >= 18u && bit <= 20u) {
        u8 sh = (u8)(bit - 18u);
        WS->kbd_col = v ? (u8)(WS->kbd_col | (1u << sh)) : (u8)(WS->kbd_col & ~(1u << sh));
    } else if (bit == 21u) {
        WS->alpha_lock = v;
    }
}

/* ---- TMS9900 16-bit CPU Core ---- */

INLINE void set_lae16(u16 v)
{
    WS->st &= ~(ST_LGT | ST_AGT | ST_EQ);
    if (v == 0u)          WS->st |= ST_EQ;
    else if (v & 0x8000u) WS->st |= ST_LGT;
    else                  WS->st |= (ST_LGT | ST_AGT);
}

INLINE void set_lae8(u8 v)
{
    WS->st &= ~(ST_LGT | ST_AGT | ST_EQ | ST_OP);
    if (v == 0u)         WS->st |= ST_EQ;
    else if (v & 0x80u)  WS->st |= ST_LGT;
    else                 WS->st |= (ST_LGT | ST_AGT);
    if (odd_par[v])      WS->st |= ST_OP;
}

INLINE void set_cmp16(u16 s, u16 d)
{
    WS->st &= ~(ST_LGT | ST_AGT | ST_EQ);
    if (s == d) WS->st |= ST_EQ;
    else {
        if (s > d) WS->st |= ST_LGT;
        if ((s16)s > (s16)d) WS->st |= ST_AGT;
    }
}

INLINE void set_cmp8(u8 s, u8 d)
{
    WS->st &= ~(ST_LGT | ST_AGT | ST_EQ | ST_OP);
    if (s == d) WS->st |= ST_EQ;
    else {
        if (s > d) WS->st |= ST_LGT;
        if ((signed char)s > (signed char)d) WS->st |= ST_AGT;
    }
    if (odd_par[s]) WS->st |= ST_OP;
}

INLINE u16 fetch16(void)
{
    u16 v = mem_rd16(WS->pc);
    WS->pc = (u16)(WS->pc + 2u);
    return v;
}

/* Decode Ts/Td effective address; advances R on *R+ according to is_byte (+1 except R0..R15 workspace is always word,
   wait: on TMS9900 *R+ increments R by 1 for byte ops and by 2 for word ops!) */
INLINE u16 decode_ea(int mode, int reg, int is_byte)
{
    u16 ra = (u16)(WS->wp + ((reg & 15) << 1));
    switch (mode & 3) {
    case 0:
        return ra;
    case 1:
        WS->cycles += 4;
        return mem_rd16(ra);
    case 2: {
        u16 disp = fetch16();
        WS->cycles += 8;
        return reg ? (u16)(mem_rd16(ra) + disp) : disp;
    }
    default: {
        u16 ea = mem_rd16(ra);
        mem_wr16(ra, (u16)(ea + (is_byte ? 1u : 2u)));
        WS->cycles += is_byte ? 6 : 8;
        return ea;
    }
    }
}

static void tms9900_context_switch(u16 vec)
{
    u16 new_wp = mem_rd16(vec);
    u16 new_pc = mem_rd16((u16)(vec + 2u));
    u16 old_wp = WS->wp, old_pc = WS->pc, old_st = WS->st;
    WS->wp = new_wp;
    WS->pc = new_pc;
    reg_wr(13, old_wp);
    reg_wr(14, old_pc);
    reg_wr(15, old_st);
    WS->idle = 0;
}

static void tms9900_exec_op(u16 op)
{
    /* Format I: Dual-operand instructions (0x4000..0xFFFF) */
    if (op >= 0x4000u) {
        int oc = (op >> 12) & 0xF;
        int is_byte = (oc & 1);
        int td = (op >> 10) & 3;
        int rd = (op >> 6) & 15;
        int ts = (op >> 4) & 3;
        int rs = op & 15;
        u16 sea = decode_ea(ts, rs, is_byte);
        u16 dea = decode_ea(td, rd, is_byte);
        WS->cycles += 14;

        if (!is_byte) {
            u16 s = mem_rd16(sea);
            switch (oc) {
            case 0x4: { /* SZC */
                u16 r = (u16)(mem_rd16(dea) & ~s);
                mem_wr16(dea, r);
                set_lae16(r);
                break;
            }
            case 0x6: { /* S: D - S */
                u16 d = mem_rd16(dea);
                u16 ns = (u16)(s ^ 0xFFFFu);
                u32 sum = (u32)d + (u32)ns + 1u;
                u16 r = (u16)sum;
                mem_wr16(dea, r);
                set_lae16(r);
                WS->st &= ~(ST_C | ST_OV);
                if (sum & 0x10000u) WS->st |= ST_C;
                if (((d ^ s) & (d ^ r)) & 0x8000u) WS->st |= ST_OV;
                break;
            }
            case 0x8: /* C */
                set_cmp16(s, mem_rd16(dea));
                break;
            case 0xA: { /* A: D + S */
                u16 d = mem_rd16(dea);
                u32 sum = (u32)d + (u32)s;
                u16 r = (u16)sum;
                mem_wr16(dea, r);
                set_lae16(r);
                WS->st &= ~(ST_C | ST_OV);
                if (sum & 0x10000u) WS->st |= ST_C;
                if ((~(d ^ s) & (d ^ r)) & 0x8000u) WS->st |= ST_OV;
                break;
            }
            case 0xC: /* MOV */
                mem_wr16(dea, s);
                set_lae16(s);
                break;
            case 0xE: { /* SOC */
                u16 r = (u16)(mem_rd16(dea) | s);
                mem_wr16(dea, r);
                set_lae16(r);
                break;
            }
            }
        } else {
            u8 s = mem_rd8(sea);
            switch (oc) {
            case 0x5: { /* SZCB */
                u8 r = (u8)(mem_rd8(dea) & ~s);
                mem_wr8(dea, r);
                set_lae8(r);
                break;
            }
            case 0x7: { /* SB: D - S */
                u8 d = mem_rd8(dea);
                u32 sum = (u32)d + (u32)(u8)(s ^ 0xFFu) + 1u;
                u8 r = (u8)sum;
                mem_wr8(dea, r);
                set_lae8(r);
                WS->st &= ~(ST_C | ST_OV);
                if (sum & 0x100u) WS->st |= ST_C;
                if (((d ^ s) & (d ^ r)) & 0x80u) WS->st |= ST_OV;
                break;
            }
            case 0x9: /* CB */
                set_cmp8(s, mem_rd8(dea));
                break;
            case 0xB: { /* AB */
                u8 d = mem_rd8(dea);
                u32 sum = (u32)d + (u32)s;
                u8 r = (u8)sum;
                mem_wr8(dea, r);
                set_lae8(r);
                WS->st &= ~(ST_C | ST_OV);
                if (sum & 0x100u) WS->st |= ST_C;
                if ((~(d ^ s) & (d ^ r)) & 0x80u) WS->st |= ST_OV;
                break;
            }
            case 0xD: /* MOVB */
                mem_wr8(dea, s);
                set_lae8(s);
                break;
            case 0xF: { /* SOCB */
                u8 r = (u8)(mem_rd8(dea) | s);
                mem_wr8(dea, r);
                set_lae8(r);
                break;
            }
            }
        }
        return;
    }

    /* Format III / IX: 0x2000..0x3FFF (COC, CZC, XOR, XOP, LDCR, STCR, MPY, DIV) */
    if (op >= 0x2000u) {
        int sub = (op >> 10) & 7;
        int rd  = (op >> 6) & 15;
        int ts  = (op >> 4) & 3;
        int rs  = op & 15;
        int is_byte = (sub == 4 || sub == 5) && (rd >= 1 && rd <= 8);
        u16 sea = decode_ea(ts, rs, is_byte);

        switch (sub) {
        case 0: { /* COC */
            u16 s = mem_rd16(sea), d = reg_rd(rd);
            if ((s & d) == s) WS->st |= ST_EQ;
            else              WS->st &= ~ST_EQ;
            WS->cycles += 14;
            break;
        }
        case 1: { /* CZC */
            u16 s = mem_rd16(sea), d = reg_rd(rd);
            if ((s & d) == 0u) WS->st |= ST_EQ;
            else               WS->st &= ~ST_EQ;
            WS->cycles += 14;
            break;
        }
        case 2: { /* XOR */
            u16 r = (u16)(reg_rd(rd) ^ mem_rd16(sea));
            reg_wr(rd, r);
            set_lae16(r);
            WS->cycles += 14;
            break;
        }
        case 3: { /* XOP */
            u16 vec = (u16)(0x0040u + (rd << 2));
            tms9900_context_switch(vec);
            reg_wr(11, sea);
            WS->st |= ST_X;
            WS->cycles += 36;
            break;
        }
        case 4: { /* LDCR */
            int cnt = rd ? rd : 16;
            u16 base = (u16)((reg_rd(12) >> 1) & 0xFFFu);
            u16 val = is_byte ? (u16)mem_rd8(sea) : mem_rd16(sea);
            if (is_byte) set_lae8((u8)val);
            else         set_lae16(val);
            for (int i = 0; i < cnt; i++)
                cru_write_bit((u16)(base + i), (u8)((val >> i) & 1u));
            WS->cycles += 20 + cnt * 2;
            break;
        }
        case 5: { /* STCR */
            int cnt = rd ? rd : 16;
            u16 base = (u16)((reg_rd(12) >> 1) & 0xFFFu);
            u16 val = 0;
            for (int i = 0; i < cnt; i++)
                val |= (u16)((u16)cru_read_bit((u16)(base + i)) << i);
            if (is_byte) {
                mem_wr8(sea, (u8)val);
                set_lae8((u8)val);
            } else {
                mem_wr16(sea, val);
                set_lae16(val);
            }
            WS->cycles += 42 + cnt * 2;
            break;
        }
        case 6: { /* MPY */
            u32 prod = (u32)mem_rd16(sea) * (u32)reg_rd(rd);
            reg_wr(rd, (u16)(prod >> 16));
            reg_wr((rd + 1) & 15, (u16)prod);
            WS->cycles += 52;
            break;
        }
        case 7: { /* DIV */
            u16 dvsr = mem_rd16(sea);
            u16 hi = reg_rd(rd), lo = reg_rd((rd + 1) & 15);
            if (dvsr <= hi) {
                WS->st |= ST_OV;
                WS->cycles += 16;
            } else {
                WS->st &= ~ST_OV;
                u32 num = ((u32)hi << 16) | lo;
                reg_wr(rd, (u16)(num / dvsr));
                reg_wr((rd + 1) & 15, (u16)(num % dvsr));
                WS->cycles += 92;
            }
            break;
        }
        }
        return;
    }

    /* Format II: Jumps & single-bit CRU (0x1000..0x1FFF) */
    if (op >= 0x1000u) {
        int sub = (op >> 8) & 0xF;
        s32 disp = (signed char)(op & 0xFFu);
        u16 st = WS->st;
        if (sub <= 0xC) {
            int take = 0;
            switch (sub) {
            case 0x0: take = 1; break;                                          /* JMP */
            case 0x1: take = !(st & (ST_AGT | ST_EQ)); break;                   /* JLT */
            case 0x2: take = !(st & ST_AGT) || (st & ST_EQ); break;             /* JLE */
            case 0x3: take = (st & ST_EQ) != 0; break;                          /* JEQ */
            case 0x4: take = (st & (ST_LGT | ST_EQ)) != 0; break;               /* JHE */
            case 0x5: take = (st & ST_AGT) != 0; break;                         /* JGT */
            case 0x6: take = !(st & ST_EQ); break;                              /* JNE */
            case 0x7: take = !(st & ST_C); break;                               /* JNC */
            case 0x8: take = (st & ST_C) != 0; break;                           /* JOC */
            case 0x9: take = !(st & ST_OV); break;                              /* JNO */
            case 0xA: take = !(st & (ST_LGT | ST_EQ)); break;                   /* JL  */
            case 0xB: take = (st & ST_LGT) && !(st & ST_EQ); break;             /* JH  */
            case 0xC: take = (st & ST_OP) != 0; break;                          /* JOP */
            }
            if (take) {
                WS->pc = (u16)(WS->pc + (disp << 1));
                WS->cycles += 10;
            } else {
                WS->cycles += 8;
            }
        } else {
            u16 bit = (u16)(((s32)(reg_rd(12) >> 1) + disp) & 0xFFFu);
            if (sub == 0xD)      cru_write_bit(bit, 1u);                        /* SBO */
            else if (sub == 0xE) cru_write_bit(bit, 0u);                        /* SBZ */
            else {                                                              /* TB  */
                if (cru_read_bit(bit)) WS->st |= ST_EQ;
                else                   WS->st &= ~ST_EQ;
            }
            WS->cycles += 12;
        }
        return;
    }

    /* Format V: Shifts (0x0800..0x0BFF) */
    if (op >= 0x0800u && op < 0x0C00u) {
        int kind = (op >> 8) & 3;
        int cnt  = (op >> 4) & 15;
        int r    = op & 15;
        if (cnt == 0) {
            cnt = reg_rd(0) & 15;
            if (cnt == 0) cnt = 16;
            WS->cycles += 20 + cnt * 2;
        } else {
            WS->cycles += 12 + cnt * 2;
        }
        u16 v = reg_rd(r);
        WS->st &= ~ST_C;
        switch (kind) {
        case 0: /* SRA */
            if ((v >> (cnt - 1)) & 1u) WS->st |= ST_C;
            v = (u16)(((s16)v) >> (cnt == 16 ? 15 : cnt));
            break;
        case 1: /* SRL */
            if ((v >> (cnt - 1)) & 1u) WS->st |= ST_C;
            v = (cnt == 16) ? 0u : (u16)(v >> cnt);
            break;
        case 2: { /* SLA */
            WS->st &= ~ST_OV;
            u16 sign0 = v & 0x8000u;
            for (int i = 0; i < cnt; i++) {
                if (v & 0x8000u) WS->st |= ST_C;
                else             WS->st &= ~ST_C;
                v = (u16)(v << 1);
                if ((v & 0x8000u) != sign0) WS->st |= ST_OV;
            }
            break;
        }
        case 3: /* SRC */
            if ((v >> (cnt - 1)) & 1u) WS->st |= ST_C;
            if (cnt < 16) v = (u16)((v >> cnt) | (v << (16 - cnt)));
            break;
        }
        reg_wr(r, v);
        set_lae16(v);
        return;
    }

    /* Format VI: Single-operand instructions (0x0400..0x07FF) */
    if (op >= 0x0400u && op < 0x0800u) {
        int sub = (op >> 6) & 0xF;
        int ts  = (op >> 4) & 3;
        int rs  = op & 15;
        u16 ea  = decode_ea(ts, rs, 0);
        WS->cycles += 12;
        switch (sub) {
        case 0x0: /* BLWP */
            tms9900_context_switch(ea);
            WS->cycles += 14;
            break;
        case 0x1: /* B */
            WS->pc = ea;
            break;
        case 0x2: /* X (Execute instruction at EA) */
            tms9900_exec_op(mem_rd16(ea));
            break;
        case 0x3: /* CLR */
            mem_wr16(ea, 0);
            break;
        case 0x4: { /* NEG */
            u16 d = mem_rd16(ea);
            u16 r = (u16)(0u - d);
            mem_wr16(ea, r);
            set_lae16(r);
            WS->st &= ~(ST_C | ST_OV);
            if (r == 0u) WS->st |= ST_C;
            if (d == 0x8000u) WS->st |= ST_OV;
            break;
        }
        case 0x5: { /* INV */
            u16 r = (u16)~mem_rd16(ea);
            mem_wr16(ea, r);
            set_lae16(r);
            break;
        }
        case 0x6: /* INC */
        case 0x7: { /* INCT */
            u16 d = mem_rd16(ea), step = (sub == 0x7) ? 2u : 1u;
            u32 sum = (u32)d + step;
            u16 r = (u16)sum;
            mem_wr16(ea, r);
            set_lae16(r);
            WS->st &= ~(ST_C | ST_OV);
            if (sum & 0x10000u) WS->st |= ST_C;
            if ((~(d ^ step) & (d ^ r)) & 0x8000u) WS->st |= ST_OV;
            break;
        }
        case 0x8: /* DEC */
        case 0x9: { /* DECT */
            u16 d = mem_rd16(ea), add = (sub == 0x9) ? 0xFFFEu : 0xFFFFu;
            u32 sum = (u32)d + add;
            u16 r = (u16)sum;
            mem_wr16(ea, r);
            set_lae16(r);
            WS->st &= ~(ST_C | ST_OV);
            if (sum & 0x10000u) WS->st |= ST_C;
            if ((~(d ^ add) & (d ^ r)) & 0x8000u) WS->st |= ST_OV;
            break;
        }
        case 0xA: /* BL */
            reg_wr(11, WS->pc);
            WS->pc = ea;
            WS->cycles += 4;
            break;
        case 0xB: { /* SWPB */
            u16 d = mem_rd16(ea);
            mem_wr16(ea, (u16)((d << 8) | (d >> 8)));
            break;
        }
        case 0xC: /* SETO */
            mem_wr16(ea, 0xFFFFu);
            break;
        case 0xD: { /* ABS */
            u16 d = mem_rd16(ea);
            set_lae16(d);
            WS->st &= ~(ST_C | ST_OV);
            if (d == 0x8000u) WS->st |= ST_OV;
            if (d & 0x8000u) {
                u16 r = (u16)(0u - d);
                mem_wr16(ea, r);
                if (r == 0u) WS->st |= ST_C;
            }
            break;
        }
        }
        return;
    }

    /* Format VIII / VII: Immediate & Control instructions (0x0200..0x03FF) */
    if (op >= 0x0200u && op < 0x0400u) {
        int r = op & 15;
        switch ((op >> 5) & 0xF) {
        case 0x0: { /* LI */
            u16 imm = fetch16();
            reg_wr(r, imm);
            set_lae16(imm);
            WS->cycles += 12;
            break;
        }
        case 0x1: { /* AI */
            u16 imm = fetch16(), d = reg_rd(r);
            u32 sum = (u32)d + (u32)imm;
            u16 res = (u16)sum;
            reg_wr(r, res);
            set_lae16(res);
            WS->st &= ~(ST_C | ST_OV);
            if (sum & 0x10000u) WS->st |= ST_C;
            if ((~(d ^ imm) & (d ^ res)) & 0x8000u) WS->st |= ST_OV;
            WS->cycles += 14;
            break;
        }
        case 0x2: { /* ANDI */
            u16 res = (u16)(reg_rd(r) & fetch16());
            reg_wr(r, res);
            set_lae16(res);
            WS->cycles += 14;
            break;
        }
        case 0x3: { /* ORI */
            u16 res = (u16)(reg_rd(r) | fetch16());
            reg_wr(r, res);
            set_lae16(res);
            WS->cycles += 14;
            break;
        }
        case 0x4: { /* CI */
            u16 imm = fetch16();
            set_cmp16(reg_rd(r), imm);
            WS->cycles += 14;
            break;
        }
        case 0x5: /* STWP */
            reg_wr(r, WS->wp);
            WS->cycles += 8;
            break;
        case 0x6: /* STST */
            reg_wr(r, WS->st);
            WS->cycles += 8;
            break;
        case 0x7: /* LWPI */
            WS->wp = fetch16();
            WS->cycles += 10;
            break;
        case 0x8: /* LIMI */
            WS->st = (u16)((WS->st & ~ST_IM) | (fetch16() & ST_IM));
            WS->cycles += 16;
            break;
        case 0xA: /* IDLE */
            WS->idle = 1;
            WS->cycles += 12;
            break;
        case 0xB: /* RSET */
            WS->st &= ~ST_IM;
            WS->cycles += 12;
            break;
        case 0xC: /* RTWP */
            WS->st = reg_rd(15);
            WS->pc = reg_rd(14);
            WS->wp = reg_rd(13);
            WS->cycles += 14;
            break;
        default:
            WS->cycles += 12;
            break;
        }
        return;
    }

    WS->cycles += 8;
}

static void tms9900_run(s32 target_cyc)
{
    while (WS->cycles < target_cyc) {
        /* Level 1 VDP / PSI interrupt check */
        if ((WS->st & ST_IM) >= 1u && (WS->vdp_status & 0x80u) && (WS->vdp_reg[1] & 0x20u) && WS->cru_sys[2]) {
            tms9900_context_switch(0x0004u);
            WS->st = (u16)((WS->st & ~ST_IM) | 0u);
            WS->cycles += 22;
        }
        if (WS->idle) {
            WS->cycles = target_cyc;
            break;
        }
        u16 op = fetch16();
        tms9900_exec_op(op);
    }
}

/* ---- TMS9918A Frame & Sprite Renderer (256 x 192) ---- */

static void render_tms9918a(u16 *pic)
{
    u8 r0 = WS->vdp_reg[0], r1 = WS->vdp_reg[1];
    u16 backdrop = tms_pal15[WS->vdp_reg[7] & 0x0Fu];
    if ((WS->vdp_reg[7] & 0x0Fu) == 0u)
        backdrop = tms_pal15[1];

    if (!(r1 & 0x40u)) {
        for (int i = 0; i < TI99_W * TI99_H; i++)
            pic[i] = backdrop;
        return;
    }

    int mode_m1 = (r1 >> 4) & 1;        /* Text 40x24 */
    int mode_m2 = (r0 >> 1) & 1;        /* Graphics II / Bitmap */
    int mode_m3 = (r1 >> 3) & 1;        /* Multicolor 64x48 */

    u16 name_base = (u16)((WS->vdp_reg[2] & 0x0Fu) << 10);
    u16 col_base  = (u16)(WS->vdp_reg[3] << 6);
    u16 pat_base  = (u16)((WS->vdp_reg[4] & 0x07u) << 11);

    if (mode_m1) {
        /* 40x24 Text mode (6x8 cells + 8px left/right border) */
        u16 fg = (WS->vdp_reg[7] >> 4) ? tms_pal15[WS->vdp_reg[7] >> 4] : backdrop;
        for (int y = 0; y < 192; y++) {
            u16 *dst = pic + y * TI99_W;
            for (int x = 0; x < 8; x++) dst[x] = dst[248 + x] = backdrop;
            int row = y >> 3, py = y & 7;
            for (int col = 0; col < 40; col++) {
                u8 ch = WS->vram[(name_base + row * 40 + col) & 0x3FFFu];
                u8 bits = WS->vram[(pat_base + ch * 8 + py) & 0x3FFFu];
                u16 *cell = dst + 8 + col * 6;
                for (int px = 0; px < 6; px++)
                    cell[px] = (bits & (0x80u >> px)) ? fg : backdrop;
            }
        }
        return;
    }

    if (mode_m3) {
        /* 64x48 Multicolor mode */
        for (int y = 0; y < 192; y++) {
            u16 *dst = pic + y * TI99_W;
            int row = y >> 3;
            int sub = (y >> 2) & 7;
            for (int col = 0; col < 32; col++) {
                u8 ch = WS->vram[(name_base + row * 32 + col) & 0x3FFFu];
                u8 cb = WS->vram[(pat_base + ch * 8 + sub) & 0x3FFFu];
                u8 c0 = cb >> 4, c1 = cb & 0x0Fu;
                u16 p0 = c0 ? tms_pal15[c0] : backdrop;
                u16 p1 = c1 ? tms_pal15[c1] : backdrop;
                u16 *cell = dst + col * 8;
                cell[0] = cell[1] = cell[2] = cell[3] = p0;
                cell[4] = cell[5] = cell[6] = cell[7] = p1;
            }
        }
    } else if (mode_m2) {
        /* Graphics II (256x192 Bitmap / 3-third tile mode) */
        u16 pg_base = (u16)((WS->vdp_reg[4] & 0x04u) << 11);
        u16 ct_base = (u16)((WS->vdp_reg[3] & 0x80u) << 6);
        u16 pg_mask = (u16)(((WS->vdp_reg[4] & 0x03u) << 11) | 0x07FFu);
        u16 ct_mask = (u16)(((WS->vdp_reg[3] & 0x7Fu) << 6)  | 0x003Fu);
        for (int y = 0; y < 192; y++) {
            u16 *dst = pic + y * TI99_W;
            int row = y >> 3, py = y & 7, third = y >> 6;
            u16 third_off = (u16)(third << 11);
            for (int col = 0; col < 32; col++) {
                u8 ch = WS->vram[(name_base + row * 32 + col) & 0x3FFFu];
                u16 idx = (u16)(third_off + (u16)ch * 8u + (u16)py);
                u8 bits = WS->vram[(pg_base + (idx & pg_mask)) & 0x3FFFu];
                u8 colb = WS->vram[(ct_base + (idx & ct_mask)) & 0x3FFFu];
                u8 c1 = colb >> 4, c0 = colb & 0x0Fu;
                u16 fg = c1 ? tms_pal15[c1] : backdrop;
                u16 bg = c0 ? tms_pal15[c0] : backdrop;
                u16 *cell = dst + col * 8;
                for (int px = 0; px < 8; px++)
                    cell[px] = (bits & (0x80u >> px)) ? fg : bg;
            }
        }
    } else {
        /* Graphics I (32x24 tiles, 1 byte per 8-tile group in color table) */
        for (int y = 0; y < 192; y++) {
            u16 *dst = pic + y * TI99_W;
            int row = y >> 3, py = y & 7;
            for (int col = 0; col < 32; col++) {
                u8 ch = WS->vram[(name_base + row * 32 + col) & 0x3FFFu];
                u8 bits = WS->vram[(pat_base + (u16)ch * 8u + (u16)py) & 0x3FFFu];
                u8 colb = WS->vram[(col_base + (ch >> 3)) & 0x3FFFu];
                u8 c1 = colb >> 4, c0 = colb & 0x0Fu;
                u16 fg = c1 ? tms_pal15[c1] : backdrop;
                u16 bg = c0 ? tms_pal15[c0] : backdrop;
                u16 *cell = dst + col * 8;
                for (int px = 0; px < 8; px++)
                    cell[px] = (bits & (0x80u >> px)) ? fg : bg;
            }
        }
    }

    /* Hardware Sprites (up to 32 sprites, max 4 per scanline + collision flag) */
    u16 sat_base = (u16)((WS->vdp_reg[5] & 0x7Fu) << 7);
    u16 sgt_base = (u16)((WS->vdp_reg[6] & 0x07u) << 11);
    int size16 = (r1 >> 1) & 1;
    int mag    = r1 & 1;
    int sh     = (size16 ? 16 : 8) << mag;
    u8 spr_occ[TI99_W];

    for (int y = 0; y < 192; y++) {
        for (int x = 0; x < TI99_W; x++) spr_occ[x] = 0;
        u16 *dst = pic + y * TI99_W;
        int on_line = 0;
        int line_idx[4];

        for (int s = 0; s < 32; s++) {
            const u8 *sa = WS->vram + ((sat_base + s * 4) & 0x3FFFu);
            u8 sy_raw = sa[0];
            if (sy_raw == 0xD0u) break;
            int sy = (sy_raw >= 0xE0u) ? ((int)sy_raw - 256 + 1) : ((int)sy_raw + 1);
            if (y >= sy && y < sy + sh) {
                if (on_line == 4) {
                    if (!(WS->vdp_status & 0x40u))
                        WS->vdp_status = (u8)((WS->vdp_status & 0xE0u) | 0x40u | (u8)s);
                    break;
                }
                line_idx[on_line++] = s;
            }
        }

        /* Draw back-to-front so sprite 0 has highest priority */
        for (int k = on_line - 1; k >= 0; k--) {
            int s = line_idx[k];
            const u8 *sa = WS->vram + ((sat_base + s * 4) & 0x3FFFu);
            u8 sy_raw = sa[0];
            int sy = (sy_raw >= 0xE0u) ? ((int)sy_raw - 256 + 1) : ((int)sy_raw + 1);
            int sx = (int)sa[1] - ((sa[3] & 0x80u) ? 32 : 0);
            u8 pat = size16 ? (u8)(sa[2] & 0xFCu) : sa[2];
            u8 col = sa[3] & 0x0Fu;
            int ry = (y - sy) >> mag;
            u8 row0 = WS->vram[(sgt_base + (u16)pat * 8u + (u16)ry) & 0x3FFFu];
            u8 row1 = size16 ? WS->vram[(sgt_base + (u16)pat * 8u + 16u + (u16)ry) & 0x3FFFu] : 0u;
            u16 bits16 = (u16)(((u16)row0 << 8) | row1);
            int sw = size16 ? 16 : 8;
            for (int px = 0; px < sw; px++) {
                if (!(bits16 & (0x8000u >> px))) continue;
                for (int m = 0; m <= mag; m++) {
                    int x = sx + (px << mag) + m;
                    if ((unsigned)x < (unsigned)TI99_W) {
                        if (spr_occ[x]) WS->vdp_status |= 0x20u;
                        spr_occ[x] = 1;
                        if (col) dst[x] = tms_pal15[col];
                    }
                }
            }
        }
    }
}

/* ---- Clean-Room Console ROM, Font & Interactive TI BASIC ---- */

static void load_font_to_vram(u16 pat_base, int bias)
{
    for (int c = 32; c < 128; c++) {
        u16 dst = (u16)(pat_base + (u16)((c + bias) & 0xFFu) * 8u);
        const u8 *g = font5x7[c - 32];
        WS->vram[dst + 0] = 0;
        for (int py = 0; py < 7; py++) {
            u8 row = 0;
            for (int px = 0; px < 5; px++)
                if (g[px] & (1u << py)) row |= (u8)(0x40u >> px);
            WS->vram[dst + 1 + py] = row;
        }
    }
}

static void basic_puts(int x, int y, const char *s)
{
    while (*s && y < 24) {
        if (*s == '\n') { x = 2; y++; s++; continue; }
        if (x >= 30) { x = 2; y++; if (y >= 24) break; }
        WS->vram[y * 32 + x] = (u8)*s++;
        x++;
    }
    WS->bas_x = (u8)x;
    WS->bas_y = (u8)y;
}

static void basic_newline(void)
{
    WS->vram[WS->bas_y * 32 + WS->bas_x] = ' ';
    WS->bas_x = 2;
    if (WS->bas_y < 22) {
        WS->bas_y++;
    } else {
        for (int y = 0; y < 22; y++)
            for (int x = 0; x < 32; x++)
                WS->vram[y * 32 + x] = WS->vram[(y + 1) * 32 + x];
        for (int x = 0; x < 32; x++)
            WS->vram[22 * 32 + x] = ' ';
    }
}

static void basic_init(void)
{
    /* Authentic TI BASIC cyan backdrop (color 7), black ink on cyan (0x17) */
    WS->vdp_reg[0] = 0x00u;
    WS->vdp_reg[1] = 0xE0u;
    WS->vdp_reg[2] = 0x00u;             /* Name table $0000 */
    WS->vdp_reg[3] = 0x0Eu;             /* Color table $0380 */
    WS->vdp_reg[4] = 0x01u;             /* Pattern table $0800 */
    WS->vdp_reg[5] = 0x06u;             /* Sprite table $0300 */
    WS->vdp_reg[6] = 0x01u;
    WS->vdp_reg[7] = 0x17u;             /* Black on Cyan */
    for (int i = 0; i < 768; i++) WS->vram[i] = ' ';
    WS->vram[0x0300] = 0xD0u;
    for (int i = 0; i < 32; i++) WS->vram[0x0380 + i] = 0x17u;
    load_font_to_vram(0x0800u, 0);

    /* Draw iconic TI-99/4A 16-color bar header on row 1 */
    for (int c = 0; c < 16; c++) {
        u8 ch = (u8)(128 + c);
        for (int py = 0; py < 8; py++) WS->vram[0x0800 + ch * 8 + py] = 0xFFu;
        WS->vram[0x0380 + (ch >> 3)] = (u8)(((c ? c : 15) << 4) | ((c + 1 <= 15) ? (c + 1) : 1));
        WS->vram[1 * 32 + 8 + c] = ch;
    }

    basic_puts(3, 3, "TEXAS INSTRUMENTS");
    basic_puts(5, 5, "TI-99/4A HOME COMPUTER");
    basic_puts(2, 8, "TI BASIC READY");
    basic_puts(2, 10, "> ");
    WS->bas_len = 0;
    sn_write(0x80u | 0x0Eu);
    sn_write(0x06u);                    /* Classic ~997 Hz TI power-up beep */
    sn_write(0x92u);
}

static void basic_step(void)
{
    if (WS->frames == 8u)
        sn_write(0x9Fu);                /* Silence power-up beep after ~130 ms */

    while (WS->type_r != WS->type_w) {
        char c = WS->type_q[WS->type_r];
        WS->type_r = (WS->type_r + 1u) & 63u;
        if (c == '\r' || c == '\n') {
            WS->bas_line[WS->bas_len] = 0;
            basic_newline();
            if (ci_contains(WS->bas_line, WS->bas_len, "CALL CLEAR")) {
                for (int i = 0; i < 768; i++) WS->vram[i] = ' ';
                WS->bas_x = 2; WS->bas_y = 2;
            } else if (ci_contains(WS->bas_line, WS->bas_len, "PRINT")) {
                const char *p = WS->bas_line;
                while (*p && *p != '"') p++;
                if (*p == '"') {
                    p++;
                    char msg[40]; int k = 0;
                    while (*p && *p != '"' && k < 38) msg[k++] = *p++;
                    msg[k] = 0;
                    basic_puts(2, WS->bas_y, msg);
                    basic_newline();
                } else {
                    basic_puts(2, WS->bas_y, " 42 ");
                    basic_newline();
                }
            } else if (WS->bas_len > 0) {
                basic_puts(2, WS->bas_y, "OK");
                basic_newline();
            }
            basic_puts(2, WS->bas_y, "> ");
            WS->bas_len = 0;
        } else if ((c == 8 || c == 127) && WS->bas_len > 0) {
            WS->vram[WS->bas_y * 32 + WS->bas_x] = ' ';
            WS->bas_len--;
            if (WS->bas_x > 4) WS->bas_x--;
        } else if (c >= 32 && c < 127 && WS->bas_len < 24 && WS->bas_x < 30) {
            if (c >= 'a' && c <= 'z') c = (char)(c - 32);
            WS->bas_line[WS->bas_len++] = c;
            WS->vram[WS->bas_y * 32 + WS->bas_x++] = (u8)c;
        }
    }
    WS->vram[WS->bas_y * 32 + WS->bas_x] = (WS->frames & 16u) ? '_' : ' ';
}

static void put_be16(u8 *b, u32 off, u16 v)
{
    b[off]     = (u8)(v >> 8);
    b[off + 1] = (u8)(v & 0xFFu);
}

static void build_cleanroom_rom(u16 cart_entry)
{
    ws_zero(WS->sys_rom, sizeof(WS->sys_rom));
    /* Vector 0 ($0000): WP = $83E0, PC = $0080 */
    put_be16(WS->sys_rom, 0x0000, 0x83E0u);
    put_be16(WS->sys_rom, 0x0002, 0x0080u);
    /* Vector 1 ($0004, Level 1 VDP ISR): WP = $83C0, PC = $00A0 */
    put_be16(WS->sys_rom, 0x0004, 0x83C0u);
    put_be16(WS->sys_rom, 0x0006, 0x00A0u);

    /* $0080: LIMI 0; LI R10, $83DC; B @cart_entry (or idle loop if basic_mode) */
    put_be16(WS->sys_rom, 0x0080, 0x0300u);
    put_be16(WS->sys_rom, 0x0082, 0x0000u);
    put_be16(WS->sys_rom, 0x0084, 0x020Au);
    put_be16(WS->sys_rom, 0x0086, 0x83DCu);
    if (cart_entry) {
        put_be16(WS->sys_rom, 0x0088, 0x0460u); /* B @cart_entry */
        put_be16(WS->sys_rom, 0x008A, cart_entry);
    } else {
        put_be16(WS->sys_rom, 0x0088, 0x10FFu); /* JMP $ */
    }

    /* $00A0: Default Level-1 VDP ISR: read $8802, increment $8379 VSync counter, call hook @$83C4 if set, RTWP */
    put_be16(WS->sys_rom, 0x00A0, 0xD020u);     /* MOVB @$8802, R0 */
    put_be16(WS->sys_rom, 0x00A2, 0x8802u);
    put_be16(WS->sys_rom, 0x00A4, 0x05A0u);     /* INC @$8378 */
    put_be16(WS->sys_rom, 0x00A6, 0x8378u);
    put_be16(WS->sys_rom, 0x00A8, 0xC060u);     /* MOV @$83C4, R1 */
    put_be16(WS->sys_rom, 0x00AA, 0x83C4u);
    put_be16(WS->sys_rom, 0x00AC, 0x1301u);     /* JEQ +2 */
    put_be16(WS->sys_rom, 0x00AE, 0x0691u);     /* BL *R1 */
    put_be16(WS->sys_rom, 0x00B0, 0x0380u);     /* RTWP */

    /* Populate standard ASCII font in Console GROM ($06B4 = space..Z, 7 bytes per char) */
    for (int c = 32; c < 96; c++) {
        u16 ga = (u16)(0x06B4u + (c - 32) * 7);
        const u8 *g = font5x7[c - 32];
        for (int py = 0; py < 7; py++) {
            u8 row = 0;
            for (int px = 0; px < 5; px++)
                if (g[px] & (1u << py)) row |= (u8)(0x40u >> px);
            WS->grom[ga + py] = row;
        }
    }
}

static u16 find_cart_entry_and_title(const u8 *hdr6000)
{
    WS->title[0] = 0;
    if (hdr6000[0] != 0xAAu)
        return 0x6000u;
    u16 plist = (u16)(((u16)hdr6000[6] << 8) | hdr6000[7]);
    if (plist >= 0x6008u && plist < 0x7FF0u) {
        u32 off = plist - 0x6000u;
        u16 entry = (u16)(((u16)hdr6000[off + 2] << 8) | hdr6000[off + 3]);
        u8 nlen = hdr6000[off + 4];
        if (nlen > 36u) nlen = 36u;
        int k = 0;
        for (u8 i = 0; i < nlen && off + 5u + i < 0x2000u; i++) {
            u8 ch = hdr6000[off + 5u + i];
            if (ch >= 32u && ch < 127u) WS->title[k++] = (char)ch;
        }
        while (k > 0 && WS->title[k - 1] == ' ') k--;
        WS->title[k] = 0;
        if (entry >= 0x6000u || entry >= 0x2000u)
            return entry;
    }
    return 0x6000u;
}

static void fmt_info(void)
{
    char *o = WS->info;
    const char *p = "TI-99/4A (TMS9900 + 32K + TMS9918A, ";
    while (*p) *o++ = *p++;
    if (WS->basic_mode) {
        const char *b = "TI BASIC)";
        while (*b) *o++ = *b++;
        *o = 0;
        return;
    }
    if (WS->title[0]) {
        const char *t = WS->title;
        while (*t) *o++ = *t++;
        *o++ = ','; *o++ = ' ';
    }
    u32 kb = (WS->cart_banks ? WS->cart_banks * 8u : 8u);
    if (kb >= 100u) *o++ = (char)('0' + (kb / 100u) % 10u);
    if (kb >= 10u)  *o++ = (char)('0' + (kb / 10u) % 10u);
    *o++ = (char)('0' + kb % 10u);
    const char *s = WS->bank_inverted ? " KB 379i)" : " KB 378)";
    while (*s) *o++ = *s++;
    *o = 0;
}

const char *ti99_load(const u8 *image, u32 size, const char *path)
{
#ifdef TI99_HOST
    u32 saved_sr = WS->sample_rate;
#endif
    ws_zero(WS, sizeof(*WS));
#ifdef TI99_HOST
    WS->sample_rate = saved_sr ? saved_sr : 48000u;
#else
    WS->sample_rate = 48000u;
#endif
    for (int c = 0; c < 8; c++)
        WS->cru_cols[c] = WS->usb_cols[c] = 0xFFu;

    if (!image || size == 0) {
        WS->basic_mode = 1;
        ti99_reset();
        fmt_info();
        return 0;
    }

    if (zip_is(image, size)) {
        /* TI-99/4A .rpk or .zip package: inspect layout.xml + ROM/GROM members */
        u32 cnt = zip_count(image, size);
        u32 rom_bytes = 0;
        int got_c = 0, got_d = 0;
        for (u32 i = 0; i < cnt; i++) {
            char mname[96];
            u32 msz = 0;
            if (zip_unpack_at(image, size, i, 0, 0, &msz, mname, sizeof(mname)) != 0 || !msz)
                continue;
            if (ci_ends(mname, ".xml") && msz < sizeof(WS->zip_tmp)) {
                if (zip_unpack_at(image, size, i, WS->zip_tmp, sizeof(WS->zip_tmp), &msz, mname, sizeof(mname)) == 0) {
                    if (ci_contains((const char *)WS->zip_tmp, msz, "paged379i"))
                        WS->bank_inverted = 1;
                }
                continue;
            }
            if (ci_ends(mname, "g.bin") || ci_ends(mname, ".g") || ci_ends(mname, "grom.bin")) {
                u32 cap = GROM_MAX - 0x6000u;
                if (msz <= sizeof(WS->zip_tmp) &&
                    zip_unpack_at(image, size, i, WS->zip_tmp, sizeof(WS->zip_tmp), &msz, mname, sizeof(mname)) == 0) {
                    if (msz > cap) msz = cap;
                    for (u32 k = 0; k < msz; k++) WS->grom[0x6000u + k] = WS->zip_tmp[k];
                    WS->has_grom = 1;
                }
                continue;
            }
            if (ci_ends(mname, "d.bin") || ci_ends(mname, ".d")) {
                if (msz <= sizeof(WS->zip_tmp) &&
                    zip_unpack_at(image, size, i, WS->zip_tmp, sizeof(WS->zip_tmp), &msz, mname, sizeof(mname)) == 0) {
                    u32 n = msz > 0x2000u ? 0x2000u : msz;
                    for (u32 k = 0; k < n; k++) WS->cart_rom[0x2000u + k] = WS->zip_tmp[k];
                    got_d = 1;
                    if (rom_bytes < 0x4000u) rom_bytes = 0x4000u;
                }
                continue;
            }
            if (ci_ends(mname, ".bin") || ci_ends(mname, ".c") || ci_ends(mname, ".rom")) {
                if (ci_ends(mname, "3.bin") || ci_ends(mname, "9.bin"))
                    WS->bank_inverted = 1;
                u32 dst_off = (got_c && !got_d) ? rom_bytes : 0u;
                u32 cap = CART_MAX - dst_off;
                if (zip_unpack_at(image, size, i, WS->cart_rom + dst_off, cap, &msz, mname, sizeof(mname)) == 0) {
                    got_c = 1;
                    if (dst_off + msz > rom_bytes)
                        rom_bytes = dst_off + msz;
                    WS->has_cart_rom = 1;
                }
            }
        }
        if (!WS->has_cart_rom && !WS->has_grom)
            return "no TI-99/4A ROM or GROM found in .rpk/.zip";
        WS->cart_banks = (rom_bytes + 0x1FFFu) >> 13;
        if (!WS->cart_banks) WS->cart_banks = 1u;
    } else {
        if (size < 64u)
            return "TI-99/4A cartridge image is too small";
        if (ci_ends(path, "3.bin") || ci_ends(path, "9.bin"))
            WS->bank_inverted = 1;
        if (ci_ends(path, "g.bin") || ci_ends(path, ".g")) {
            u32 n = size > (GROM_MAX - 0x6000u) ? (GROM_MAX - 0x6000u) : size;
            for (u32 i = 0; i < n; i++) WS->grom[0x6000u + i] = image[i];
            WS->has_grom = 1;
            WS->cart_banks = 1u;
        } else {
            u32 n = size > CART_MAX ? CART_MAX : size;
            for (u32 i = 0; i < n; i++) WS->cart_rom[i] = image[i];
            WS->has_cart_rom = 1;
            WS->cart_banks = (n + 0x1FFFu) >> 13;
            if (!WS->cart_banks) WS->cart_banks = 1u;
        }
    }

    ti99_reset();
    fmt_info();
    return 0;
}

void ti99_reset(void)
{
    ws_zero(WS->exp_lo, sizeof(WS->exp_lo));
    ws_zero(WS->exp_hi, sizeof(WS->exp_hi));
    ws_zero(WS->pad_ram, sizeof(WS->pad_ram));
    ws_zero(WS->vram, sizeof(WS->vram));
    ws_zero(WS->cru_sys, sizeof(WS->cru_sys));

    WS->sn_vol[0] = WS->sn_vol[1] = WS->sn_vol[2] = WS->sn_vol[3] = 15u;
    WS->sn_lfsr = 0x8000u;
    WS->vdp_status = 0;
    WS->vdp_first = 0;
    WS->vdp_addr = 0;
    WS->grom_addr = 0;
    WS->grom_latch = 0;
    WS->idle = 0;
    WS->jam = 0;
    WS->cycles = 0;
    WS->frames = 0;

    setup_mem_map();
    map_cart_bank(0);

    if (WS->basic_mode) {
        build_cleanroom_rom(0);
        basic_init();
    } else {
        /* Pre-initialize TMS9918A Graphics I + standard ASCII font at $0800 */
        WS->vdp_reg[0] = 0x00u;
        WS->vdp_reg[1] = 0xE0u;
        WS->vdp_reg[2] = 0x00u;
        WS->vdp_reg[3] = 0x0Eu;
        WS->vdp_reg[4] = 0x01u;
        WS->vdp_reg[5] = 0x06u;
        WS->vdp_reg[6] = 0x01u;
        WS->vdp_reg[7] = 0xF4u;
        for (int i = 0; i < 768; i++) WS->vram[i] = ' ';
        for (int i = 0; i < 32; i++)  WS->vram[0x0380 + i] = 0xF1u;
        WS->vram[0x0300] = 0xD0u;
        load_font_to_vram(0x0800u, 0);

        const u8 *b0 = WS->rdp[24];
        u16 entry = (WS->has_cart_rom && b0) ? find_cart_entry_and_title(b0) : 0u;
        build_cleanroom_rom(entry);
    }

    WS->wp = mem_rd16(0x0000u);
    WS->pc = mem_rd16(0x0002u);
    WS->st = 0;
}

void ti99_frame(u16 pad, u16 *picture)
{
    update_cru_inputs(pad);
    WS->cycles = 0;

    if (WS->basic_mode) {
        basic_step();
        render_tms9918a(picture);
        u32 samps = (WS->sample_rate ? WS->sample_rate : 48000u) / 60u;
        for (u32 i = 0; i < samps; i++)
            sn_step_sample();
        WS->frames++;
        return;
    }

    /* 3.0 MHz TMS9900 @ 59.94 Hz = ~50,050 cycles/frame across 262 NTSC lines (~191 cyc/line) */
    const s32 cyc_per_line = 191;
    u32 sr = WS->sample_rate ? WS->sample_rate : 48000u;

    for (int line = 0; line < 262; line++) {
        if (line == 192) {
            render_tms9918a(picture);
            WS->vdp_status |= 0x80u;    /* VBlank interrupt / PollVSync_ status flag */
        }
        tms9900_run((line + 1) * cyc_per_line);
        if (WS->tms9901_timer && WS->tms9901_clock > 0) {
            if (WS->tms9901_clock > 3u) WS->tms9901_clock -= 3u;
            else                        WS->tms9901_clock = WS->tms9901_timer;
        }
        WS->snd_frac += sr;
        while (WS->snd_frac >= 15720u) { /* 262 lines * 60 Hz = 15,720 lines/sec */
            WS->snd_frac -= 15720u;
            sn_step_sample();
        }
    }
    WS->frames++;
}

void ti99_keyboard(const u8 *usages, int n)
{
    for (int c = 0; c < 8; c++)
        WS->usb_cols[c] = 0xFFu;
    for (int i = 0; i < n; i++) {
        u8 u = usages[i];
        if (u >= 0x04u && u <= 0x1Du) {
            press_ascii((char)('A' + (u - 0x04u)), WS->usb_cols);
        } else if (u >= 0x1Eu && u <= 0x26u) {
            press_ascii((char)('1' + (u - 0x1Eu)), WS->usb_cols);
        } else if (u == 0x27u) {
            press_ascii('0', WS->usb_cols);
        } else if (u == 0x28u) {
            press_ascii('\r', WS->usb_cols);
        } else if (u == 0x2Cu) {
            press_ascii(' ', WS->usb_cols);
        } else if (u == 0xE1u || u == 0xE5u) {
            WS->usb_cols[0] &= (u8)~0x20u; /* Shift */
        } else if (u == 0xE2u || u == 0xE6u) {
            WS->usb_cols[0] &= (u8)~0x10u; /* Alt -> FCTN */
        } else if (u == 0xE0u || u == 0xE4u) {
            WS->usb_cols[0] &= (u8)~0x40u; /* Ctrl */
        } else if (u == 0x50u) {
            WS->usb_cols[6] &= (u8)~0x02u; /* Left */
        } else if (u == 0x4Fu) {
            WS->usb_cols[6] &= (u8)~0x04u; /* Right */
        } else if (u == 0x51u) {
            WS->usb_cols[6] &= (u8)~0x08u; /* Down */
        } else if (u == 0x52u) {
            WS->usb_cols[6] &= (u8)~0x10u; /* Up */
        }
    }
}

void ti99_typed(char c)
{
    u8 nxt = (WS->type_w + 1u) & 63u;
    if (nxt != WS->type_r) {
        WS->type_q[WS->type_w] = c;
        WS->type_w = nxt;
    }
}

const char *ti99_info(void)
{
    return WS->info;
}

int ti99_jammed(void)
{
    return WS->jam;
}

void ti99_audio_rate(u32 hz)
{
    WS->sample_rate = hz ? hz : 48000u;
    WS->snd_head = WS->snd_tail = 0;
}

int ti99_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && WS->snd_tail != WS->snd_head) {
        out[n++] = WS->snd_ring[WS->snd_tail];
        WS->snd_tail = (WS->snd_tail + 1u) & (SND_RING - 1u);
    }
    return n;
}
