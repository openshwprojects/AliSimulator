/* An SNK Neo Geo AES / MVS cartridge system: see neo.h. */
#pragma GCC optimize("O2")
#include "neo.h"
#include "z80.h"

#ifndef NEO_HOST
#include "hw.h"
#endif

#define INLINE static inline __attribute__((always_inline))

static void neo_iack(u32 level);
static void idle_branch(u32 at);
#define M68K_IACK(level) neo_iack(level)
#define M68K_BRANCH(at)  idle_branch(at)
#include "m68k.inc"

/* Timing: 24 MHz master clock -> 12 MHz 68000 (768 cyc/line), 4 MHz Z80 (256 cyc/line),
   6 MHz LSPC2 pixel clock (384 px/line), 264 scanlines/frame (202,752 68000 cyc/frame). */
#define M68K_LINE_CYC      768
#define Z80_LINE_CYC       256
#define TOTAL_LINES        264
#define FRAME_M68K_CYC     (M68K_LINE_CYC * TOTAL_LINES)
#define LINE_BUFSTART      6
#define LINE_ACTIVE_START  8
#define LINE_ACTIVE_END    248          /* 240 active lines: 16 top overscan + 224 visible + 16 bottom */
#define VIS_LINE_START     24           /* 8 + 16: first visible line of the 320x224 picture */
#define VIS_LINE_END       248          /* 24 + 224 */
#define SPR_LIMIT          96

/* IRQ2 timer control bits (REG_LSPCMODE $3C0006 bits 4..7) */
#define TMR_IRQ_EN         0x10u
#define TMR_RELOAD_WRITE   0x20u
#define TMR_RELOAD_VBL     0x40u
#define TMR_RELOAD_ZERO    0x80u

/* HLE BIOS trap port ($3FFFE0 in 68000 I/O space) */
#define HLE_TRAP_PORT      0x3FFFE0u
#define HLE_INIT_HW        1
#define HLE_SYS_INT1       2
#define HLE_SYS_RETURN     3
#define HLE_SYS_IO_PRE     4
#define HLE_SYS_IO_POST    5
#define HLE_CREDIT_CHECK   6
#define HLE_CREDIT_DOWN    7
#define HLE_READ_CAL       8
#define HLE_CARD           9
#define HLE_FIX_CLEAR      10
#define HLE_LSP_1ST        11
#define HLE_MESS_OUT       12

#define SND_RING           8192
#define WLOG_MAX           2048
#define YM_STEP            2            /* FM evaluated every 2 chip samples (27.78 kHz), mixed at 55.56 kHz */

struct ym_op {
    u32 phase, inc;
    s32 att;
    u32 env;
    s32 out, out1;
    u8 dt, mul, tl, ks, ar, am, d1r, d2r, sl, rr;
    u8 state;
    u8 rate[4];
};

struct ym_ch {
    struct ym_op op[4];
    u16 fnum, fnum3[3];
    u8 block, block3[3];
    u8 kc, kc3[3];
    u8 alg, fb, on, ams, pms, quiet;
};

struct adpcm_a_ch {
    u8 on, cvol;
    u16 start_raw, end_raw;
    u32 addr, end_addr;
    u8 nibble_hi;
    s32 acc, step_idx, out;
};

struct adpcm_b_ch {
    u8 on, repeat, lrsel, vol;
    u16 start_raw, end_raw, delta_n;
    u32 addr, end_addr, phase;
    u8 nibble_hi;
    s32 adpcm_acc, step, prev_out, cur_out;
};

struct ssg_state {
    u8 reg[16];
    u32 count[3], noise_cnt, env_cnt;
    u8 out_bit[3];
    u32 lfsr;
    u8 env_step, env_vol, env_hold, env_alt, env_att, env_cont;
};

struct neo_mem {
    u8 wram[0x10000];                   /* $100000..$10FFFF (host u16 word order for m68k.inc) */
    u8 page0[0x10000];                  /* $000000..$00FFFF with active vector table in 0x00..0x7F */
    u8 p_tail[0x10000];                 /* zero/mirror-padded 64 KB buffer when PSize % 64KB != 0 */
    u8 bios[0x20000];                   /* $C00000..$C1FFFF active BIOS (host u16 word order) */
    u8 ext_bios[0x20000];               /* optional user-supplied BIOS */
    u8 nvram[0x10000];                  /* $D00000..$D0FFFF MVS Backup RAM (host u16 word order) */
    u8 nvram_save[0x10000];             /* big-endian export/import buffer for .sav */
    u8 cartram[0x2000];                 /* $2FE000..$2FFFFF PVC / cartridge RAM */
    u8 memcard[0x800];                  /* $800000 2 KB formatted memory card */
    u8 zram[0x800];                     /* Z80 $F800..$FFFF 2 KB work RAM */
    u8 sfix_rom[0x20000];               /* built-in 128 KB SFIX 8x8 ASCII font */
    u8 sm1_rom[0x10000];                /* built-in 64 KB SM1 Z80 sound stub */
    u8 lo_lut[256][256];                /* algorithmic L0 vertical shrink table */
    u32 c_lut[256];                     /* 8-pixel planar sliver unpack (normal) */
    u32 c_lut_flip[256];                /* 8-pixel planar sliver unpack (H-flipped) */
    u16 vram[0x8800];                   /* 68 KB LSPC2 VRAM (34K words) */
    u16 palram[0x2000];                 /* 2 banks x 4096 16-bit Neo Geo colors */
    u16 pal15[2][0x2000];               /* [shadow][bank*4096 + idx] -> 15-bit BGR555 */
    u16 linebuf[2][NEO_W];              /* LSPC2 2-line-ahead sprite palette indices */
    u16 active_spr[382];                /* non-zero height sprite strips (heads + sticky chains) */
    s16 snd_ring[SND_RING];
    struct {
        u32 zcyc;
        u8 part, reg, val;
    } wlog[WLOG_MAX];
};

#ifdef NEO_HOST
static struct neo_mem neo_host_mem;
#define M (&neo_host_mem)
#else
#define M ((struct neo_mem *)KSEG0(EMU_RAM_PHYS))
#endif

static struct {
    u8 *p_rom, *s_rom, *m_rom, *v1_rom, *v2_rom, *c_rom;
    u32 p_size, s_size, m_size, v1_size, v2_size, c_size;
    u32 c_tile_mask, p_bank_mask;
    u32 ngh, year;
    u8 has_ext_bios, use_hle_bios;
    u8 vectable;                        /* 0: BIOS vectors, 1: Cart vectors */
    u8 crtfix;                          /* 0: Board SFIX/SM1, 1: Cart S/M1 */
    u8 fix_banksw;                      /* 0: none, 1: per-line, 2: per-tile */
    u8 board;                           /* 0: standard, 1: PVC, 2: CT0, 3: Linkable */
    u8 sram_lock, crd_lock1, crd_lock2, poutput;
    u8 nvram_dirty;
    u32 p2_offset;
    u32 prot_reg;
    u16 cart_reg0;

    /* LSPC2 & Interrupts */
    u16 vram_addr, vram_bank;
    s16 vram_mod;
    u8 pal_bank, shadow;
    u8 aa_counter, aa_reload, aa_timer, aa_disable;
    u8 lb_active, scb_dirty;
    u16 n_active_spr;
    u32 scanline;
    u8 irq_pending;                     /* bit 0: VBL(1), bit 1: TMR(2), bit 2: RST(3) */
    u8 irq2_ctrl;
    u32 irq2_reload, irq2_counter, irq2_rem;
    u32 watchdog_frames;
    u16 pads[2];
    u16 *pic;

    /* Z80 & Sound */
    struct z80 z;
    u8 z_nmi_en;
    u8 sound_code, sound_reply;
    u32 zbank[4];
    s32 z_done_cyc;                     /* Z80 cycles executed in this frame */
    s32 z_target;
    s32 z_poll_at;
    u16 z_poll_pc;
    u8 z_poll_st;

    /* YM2610 */
    struct {
        struct ym_ch ch[6];
        struct adpcm_a_ch pa[6];
        struct adpcm_b_ch pb;
        struct ssg_state ssg;
        u8 addr_latch[2];
        u8 freq_latch[2], freq_latch3;
        u16 ta_load;
        u8 tb_load, mode, status0;
        s32 ta_cnt, tb_cnt;             /* in Z80 cycles (4 MHz) */
        u8 pa_mvol;
        u8 eos_raw, eos_mask;
        u8 lfo_on, lfo_freq, lfo_step;
        u16 lfo_cnt;
        u8 eg_div, step_cnt, pa_div;
        u32 eg_cnt;
        s32 fm_cached, pa_cached;
    } ym;

    u32 wlog_n;
    u32 syn_zcyc, syn_rem;              /* Z80 cycles synthesized so far (72 Z80 cyc = 1 YM 55.56 kHz sample) */
    u32 snd_rate, snd_acc;
    s32 snd_sum, snd_n, snd_lp, snd_lp_was, snd_hp;
    u32 snd_head, snd_tail;

    u8 tables_ready;
    char info[128];
} S;

/* ---- Lookup tables & clean-room built-in ROMs ---- */

static const u16 lut_hshrink16[16] = {
    0x0100, 0x0110, 0x1110, 0x1114,
    0x5114, 0x5154, 0x5554, 0x5555,
    0x5755, 0x575D, 0xD75D, 0xD7DD,
    0xF7DD, 0xF7DF, 0xFFDF, 0xFFFF
};

/* Compact clean-room 5x7 ASCII glyphs for 0x20..0x7E (used in SFIX when cart switches to board fix) */
static const u8 mini_ascii[95][5] = {
    {0x00,0x00,0x00,0x00,0x00}, {0x00,0x00,0x5F,0x00,0x00}, {0x00,0x07,0x00,0x07,0x00}, {0x14,0x7F,0x14,0x7F,0x14},
    {0x24,0x2A,0x7F,0x2A,0x12}, {0x23,0x13,0x08,0x64,0x62}, {0x36,0x49,0x55,0x22,0x50}, {0x00,0x05,0x03,0x00,0x00},
    {0x00,0x1C,0x22,0x41,0x00}, {0x00,0x41,0x22,0x1C,0x00}, {0x14,0x08,0x3E,0x08,0x14}, {0x08,0x08,0x3E,0x08,0x08},
    {0x00,0x50,0x30,0x00,0x00}, {0x08,0x08,0x08,0x08,0x08}, {0x00,0x60,0x60,0x00,0x00}, {0x20,0x10,0x08,0x04,0x02},
    {0x3E,0x51,0x49,0x45,0x3E}, {0x00,0x42,0x7F,0x40,0x00}, {0x42,0x61,0x51,0x49,0x46}, {0x21,0x41,0x45,0x4B,0x31},
    {0x18,0x14,0x12,0x7F,0x10}, {0x27,0x45,0x45,0x45,0x39}, {0x3C,0x4A,0x49,0x49,0x30}, {0x01,0x71,0x09,0x05,0x03},
    {0x36,0x49,0x49,0x49,0x36}, {0x06,0x49,0x49,0x29,0x1E}, {0x00,0x36,0x36,0x00,0x00}, {0x00,0x56,0x36,0x00,0x00},
    {0x08,0x14,0x22,0x41,0x00}, {0x14,0x14,0x14,0x14,0x14}, {0x00,0x41,0x22,0x14,0x08}, {0x02,0x01,0x51,0x09,0x06},
    {0x32,0x49,0x79,0x41,0x3E}, {0x7E,0x11,0x11,0x11,0x7E}, {0x7F,0x49,0x49,0x49,0x36}, {0x3E,0x41,0x41,0x41,0x22},
    {0x7F,0x41,0x41,0x22,0x1C}, {0x7F,0x49,0x49,0x49,0x41}, {0x7F,0x09,0x09,0x09,0x01}, {0x3E,0x41,0x49,0x49,0x7A},
    {0x7F,0x08,0x08,0x08,0x7F}, {0x00,0x41,0x7F,0x41,0x00}, {0x20,0x40,0x41,0x3F,0x01}, {0x7F,0x08,0x14,0x22,0x41},
    {0x7F,0x40,0x40,0x40,0x40}, {0x7F,0x02,0x0C,0x02,0x7F}, {0x7F,0x04,0x08,0x10,0x7F}, {0x3E,0x41,0x41,0x41,0x3E},
    {0x7F,0x09,0x09,0x09,0x06}, {0x3E,0x41,0x51,0x21,0x5E}, {0x7F,0x09,0x19,0x29,0x46}, {0x46,0x49,0x49,0x49,0x31},
    {0x01,0x01,0x7F,0x01,0x01}, {0x3F,0x40,0x40,0x40,0x3F}, {0x1F,0x20,0x40,0x20,0x1F}, {0x3F,0x40,0x38,0x40,0x3F},
    {0x63,0x14,0x08,0x14,0x63}, {0x07,0x08,0x70,0x08,0x07}, {0x61,0x51,0x49,0x45,0x43}, {0x00,0x7F,0x41,0x41,0x00},
    {0x02,0x04,0x08,0x10,0x20}, {0x00,0x41,0x41,0x7F,0x00}, {0x04,0x02,0x01,0x02,0x04}, {0x40,0x40,0x40,0x40,0x40},
    {0x00,0x01,0x02,0x04,0x00}, {0x20,0x54,0x54,0x54,0x78}, {0x7F,0x48,0x44,0x44,0x38}, {0x38,0x44,0x44,0x44,0x20},
    {0x38,0x44,0x44,0x48,0x7F}, {0x38,0x54,0x54,0x54,0x18}, {0x08,0x7E,0x09,0x01,0x02}, {0x0C,0x52,0x52,0x52,0x3E},
    {0x7F,0x08,0x04,0x04,0x78}, {0x00,0x44,0x7D,0x40,0x00}, {0x20,0x40,0x44,0x3D,0x00}, {0x7F,0x10,0x28,0x44,0x00},
    {0x00,0x41,0x7F,0x40,0x00}, {0x7C,0x04,0x18,0x04,0x78}, {0x7C,0x08,0x04,0x04,0x78}, {0x38,0x44,0x44,0x44,0x38},
    {0x7C,0x14,0x14,0x14,0x08}, {0x08,0x14,0x14,0x18,0x7C}, {0x7C,0x08,0x04,0x04,0x08}, {0x48,0x54,0x54,0x54,0x20},
    {0x04,0x3F,0x44,0x40,0x20}, {0x3C,0x40,0x40,0x20,0x7C}, {0x1C,0x20,0x40,0x20,0x1C}, {0x3C,0x40,0x30,0x40,0x3C},
    {0x44,0x28,0x10,0x28,0x44}, {0x0C,0x50,0x50,0x50,0x3C}, {0x44,0x64,0x54,0x4C,0x44}, {0x00,0x08,0x36,0x41,0x00},
    {0x00,0x00,0x7F,0x00,0x00}, {0x00,0x41,0x36,0x08,0x00}, {0x08,0x04,0x08,0x10,0x08}
};

/* Put a 4bpp pixel into an 8x8 S-ROM fix tile (32 bytes, column layout 0x10, 0x18, 0x00, 0x08) */
static void sfix_put_px(u8 *tile, int x, int y, u8 col)
{
    static const u8 col_off[4] = {0x10, 0x18, 0x00, 0x08};
    u8 *b = &tile[col_off[(x >> 1) & 3] + (y & 7)];
    if (x & 1)
        *b = (u8)((*b & 0x0Fu) | ((col & 0x0Fu) << 4));
    else
        *b = (u8)((*b & 0xF0u) | (col & 0x0Fu));
}

static void build_static_tables(void)
{
    if (S.tables_ready)
        return;

    cpu_init();

    /* 1. C-ROM 8-pixel planar sliver unpack tables */
    for (u32 b = 0; b < 256; b++) {
        u32 v = 0, vf = 0;
        for (int k = 0; k < 8; k++) {
            v  |= ((b >> k) & 1u) << (k * 4);
            vf |= ((b >> (7 - k)) & 1u) << (k * 4);
        }
        M->c_lut[b] = v;
        M->c_lut_flip[b] = vf;
    }

    /* 2. Algorithmic L0 vertical shrink table (256 levels x 256 bytes) */
    static const s16 seq_i[8] = {8, 12, 10, 14, 9, 13, 11, 15};
    static const s16 seq_j[4] = {0, 16, -8, 8};
    static const s16 seq_k[8] = {0, -128, 64, -64, 32, -96, 96, -32};
    s16 zoom[256];
    for (int j = 0; j < 256; j++)
        zoom[j] = -1;
    int lv = 0;
    for (int ii = 0; ii < 8; ii++) {
        for (int jj = 0; jj < 4; jj++) {
            for (int kk = 0; kk < 8; kk++) {
                int off = 128 + seq_i[ii] + seq_j[jj] + seq_k[kk];
                zoom[off & 255] = (s16)(off & 255);
                int dst = 0;
                for (int q = 0; q < 256; q++)
                    if (zoom[q] >= 0)
                        M->lo_lut[lv][dst++] = (u8)zoom[q];
                while (dst < 256)
                    M->lo_lut[lv][dst++] = 0xFF;
                lv++;
            }
        }
    }

    /* 3. Clean-room SFIX 8x8 ASCII font (banks 0 and 3, tile 0x20 opaque border, 0xFF transparent) */
    for (u32 i = 0; i < sizeof(M->sfix_rom); i++)
        M->sfix_rom[i] = 0;
    /* Tile 0x0020 in Neo Geo SFIX is opaque color 1 (used by FIX_CLEAR for side borders);
       ASCII printable characters live at 0x0320..0x037E (and mirrored at 0x0021..0x007E). */
    for (int y = 0; y < 8; y++)
        for (int x = 0; x < 8; x++)
            sfix_put_px(&M->sfix_rom[0x20 * 32], x, y, 1);
    for (int ch = 32; ch <= 126; ch++) {
        const u8 *g = mini_ascii[ch - 32];
        int banks[2] = {0x000 + ch, 0x300 + ch};
        for (int bi = 0; bi < 2; bi++) {
            int tid = banks[bi];
            if (tid == 0x20)
                continue;
            u8 *tile = &M->sfix_rom[tid * 32];
            for (int x = 0; x < 5; x++) {
                u8 col_bits = g[x];
                for (int y = 0; y < 7; y++)
                    if ((col_bits >> y) & 1)
                        sfix_put_px(tile, x + 1, y + 1, 1);
            }
        }
    }

    /* 4. Clean-room SM1 Z80 sound stub (answers slot-switch $01/$03 and idles cleanly) */
    for (u32 i = 0; i < sizeof(M->sm1_rom); i++)
        M->sm1_rom[i] = 0x00;
    /* $0000: F3 (DI), 31 FC FF (LD SP,$FFFC), ED 56 (IM 1), 3E 01 (LD A,1), D3 08 (OUT ($08),A: enable NMI),
              FB (EI), 76 (HALT), 18 FD (JR -3) */
    static const u8 sm1_boot[] = {0xF3, 0x31, 0xFC, 0xFF, 0xED, 0x56, 0x3E, 0x01, 0xD3, 0x08, 0xFB, 0x76, 0x18, 0xFD};
    for (u32 i = 0; i < sizeof(sm1_boot); i++)
        M->sm1_rom[i] = sm1_boot[i];
    /* $0038 (IM 1 IRQ): F5 (PUSH AF), 3E 30, D3 04, 3E 27, D3 04, 3E 30, D3 05 (ack timers), F1, FB, ED 4D (RETI) */
    static const u8 sm1_irq[] = {0xF5, 0x3E, 0x27, 0xD3, 0x04, 0x3E, 0x30, 0xD3, 0x05, 0xF1, 0xFB, 0xED, 0x4D};
    for (u32 i = 0; i < sizeof(sm1_irq); i++)
        M->sm1_rom[0x0038 + i] = sm1_irq[i];
    /* $0066 (NMI): F5 (PUSH AF), DB 00 (IN A,($00)), D3 0C (OUT ($0C),A reply), AF (XOR A), D3 00 (clear latch),
                    F1 (POP AF), ED 45 (RETN) */
    static const u8 sm1_nmi[] = {0xF5, 0xDB, 0x00, 0xD3, 0x0C, 0xAF, 0xD3, 0x00, 0xF1, 0xED, 0x45};
    for (u32 i = 0; i < sizeof(sm1_nmi); i++)
        M->sm1_rom[0x0066 + i] = sm1_nmi[i];

    S.tables_ready = 1;
}

/* ---- Palette DAC conversion (Neo Geo 16-bit color + dark/shadow -> 15-bit BGR555) ---- */

static void pal_update_entry(u32 idx)
{
    /* Neo Geo 16-bit color format:
       bit 15: Dark (active high = 1 enables 8.2k pulldown -> slightly darker; 0 = bright LSB)
       bit 14..12: R0, G0, B0
       bit 11..8:  R4..R1
       bit 7..4:   G4..G1
       bit 3..0:   B4..B1 */
    u16 d = M->palram[idx & 0x1FFF];
    u32 dark_inv = ((d >> 15) & 1u) ^ 1u;
    u32 r6 = (((d >> 8) & 0x0Fu) << 2) | (((d >> 14) & 1u) << 1) | dark_inv;
    u32 g6 = (((d >> 4) & 0x0Fu) << 2) | (((d >> 13) & 1u) << 1) | dark_inv;
    u32 b6 = (((d >> 0) & 0x0Fu) << 2) | (((d >> 12) & 1u) << 1) | dark_inv;

    u32 r5 = (r6 * 31u + 31u) / 63u;
    u32 g5 = (g6 * 31u + 31u) / 63u;
    u32 b5 = (b6 * 31u + 31u) / 63u;
    M->pal15[0][idx & 0x1FFF] = (u16)(r5 | (g5 << 5) | (b5 << 10));
    M->pal15[1][idx & 0x1FFF] = (u16)((r5 >> 1) | ((g5 >> 1) << 5) | ((b5 >> 1) << 10));
}

/* ---- Clean-room 68000 System BIOS builder & HLE handlers ---- */

static void bios_w16(u32 a, u16 v)
{
    *(u16 *)(M->bios + (a & 0x1FFFEu)) = v;
}

static void bios_w32(u32 a, u32 v)
{
    bios_w16(a, (u16)(v >> 16));
    bios_w16(a + 2, (u16)v);
}

static u8 wram_rb(u32 a)
{
    return M->wram[(a & 0xFFFFu) ^ 1u];
}

static void wram_wb(u32 a, u8 v)
{
    M->wram[(a & 0xFFFFu) ^ 1u] = v;
}

static u16 wram_rw(u32 a)
{
    return *(const u16 *)(M->wram + (a & 0xFFFEu));
}

static void wram_ww(u32 a, u16 v)
{
    *(u16 *)(M->wram + (a & 0xFFFEu)) = v;
}

static u32 wram_rl(u32 a)
{
    return ((u32)wram_rw(a) << 16) | wram_rw(a + 2);
}

static void wram_wl(u32 a, u32 v)
{
    wram_ww(a, (u16)(v >> 16));
    wram_ww(a + 2, (u16)v);
}

static void build_hle_bios(void)
{
    for (u32 i = 0; i < 0x20000; i += 2)
        *(u16 *)(M->bios + i) = 0x4E75; /* RTS fill */

    /* 68000 exception vectors ($C00000..$C000FF) */
    bios_w32(0x00, 0x0010F300u);        /* Initial SSP */
    bios_w32(0x04, 0x00C00402u);        /* Initial PC: BIOS_INIT_HARDWARE */
    for (u32 v = 2; v < 24; v++)
        bios_w32(v * 4, 0x00C00426u);
    bios_w32(0x60, 0x00C00432u);        /* Spurious */
    bios_w32(0x64, 0x00C00438u);        /* Level 1: VBlank */
    bios_w32(0x68, 0x00C0043Eu);        /* Level 2: Timer */
    bios_w32(0x6C, 0x00C00432u);        /* Level 3: Cold Reset */
    for (u32 v = 28; v < 64; v++)
        bios_w32(v * 4, 0x00C00426u);

    /* $C00400: AES Home (0x00), USA (0x01) */
    M->bios[0x400 ^ 1] = 0x00;
    M->bios[0x401 ^ 1] = 0x01;

    /* Standard Neo Geo BIOS jump table ($C00402..$C0056A, 6-byte JMP.L entries) */
    bios_w16(0x0402, 0x4EF9); bios_w32(0x0404, 0x00C01000u); /* BIOS_INIT_HARDWARE */
    for (u32 a = 0x0408; a <= 0x0432; a += 6) {
        bios_w16(a, 0x4EF9); bios_w32(a + 2, 0x00C01080u);   /* Exception / Spurious RTE */
    }
    bios_w16(0x0438, 0x4EF9); bios_w32(0x043A, 0x00C01090u); /* SYSTEM_INT1 */
    bios_w16(0x043E, 0x4EF9); bios_w32(0x0440, 0x00C010B0u); /* SYSTEM_INT2 */
    bios_w16(0x0444, 0x4EF9); bios_w32(0x0446, 0x00C010D0u); /* SYSTEM_RETURN */
    bios_w16(0x044A, 0x4EF9); bios_w32(0x044C, 0x00C01100u); /* SYSTEM_IO */
    bios_w16(0x0450, 0x4EF9); bios_w32(0x0452, 0x00C01150u); /* CREDIT_CHECK */
    bios_w16(0x0456, 0x4EF9); bios_w32(0x0458, 0x00C01160u); /* CREDIT_DOWN */
    bios_w16(0x045C, 0x4EF9); bios_w32(0x045E, 0x00C01170u); /* READ_CALENDAR */
    bios_w16(0x0462, 0x4EF9); bios_w32(0x0464, 0x00C01180u); /* SETUP_CALENDAR */
    bios_w16(0x0468, 0x4EF9); bios_w32(0x046A, 0x00C01190u); /* CARD */
    bios_w16(0x046E, 0x4EF9); bios_w32(0x0470, 0x00C01180u); /* CARD_ERROR */
    bios_w16(0x0474, 0x4EF9); bios_w32(0x0476, 0x00C011A0u); /* HOW_TO_PLAY */
    bios_w16(0x047A, 0x4EF9); bios_w32(0x047C, 0x00C01180u); /* CHECKSUM */
    for (u32 a = 0x0480; a < 0x04C2; a += 6) {
        bios_w16(a, 0x4EF9); bios_w32(a + 2, 0x00C01180u);
    }
    bios_w16(0x04C2, 0x4EF9); bios_w32(0x04C4, 0x00C011B0u); /* FIX_CLEAR */
    bios_w16(0x04C8, 0x4EF9); bios_w32(0x04CA, 0x00C011C0u); /* LSP_1st */
    bios_w16(0x04CE, 0x4EF9); bios_w32(0x04D0, 0x00C011D0u); /* MESS_OUT */
    bios_w16(0x04D4, 0x4EF9); bios_w32(0x04D6, 0x00C01180u); /* CONTROLLER_SETUP */
    for (u32 a = 0x04DA; a <= 0x056A; a += 6) {
        bios_w16(a, 0x4EF9); bios_w32(a + 2, 0x00C01180u);
    }

    /* $C01000: Boot & main USER loop:
       MOVE    #$2700, SR
       LEA     $0010F300, SP
       MOVE.W  #HLE_INIT_HW, $003FFFE0   ; initializes BIOS RAM, DIPs, cart vectors, fix/sprites
       MOVE    #$2000, SR
       JSR     $000122.L                 ; USER(request = 0: Init; homebrew may stay here!)
     .loop:
       MOVE    #$2700, SR
       LEA     $0010F300, SP
       MOVE.W  #HLE_SYS_RETURN, $003FFFE0 ; prepares USER_REQUEST=2, USER_MODE=1, SYSTEM_MODE=$80
       MOVE    #$2000, SR
       JSR     $000122.L                 ; USER(request = 2: Demo / Title / Game)
       BRA.S   .loop */
    u32 pc = 0x1000;
    bios_w16(pc, 0x46FC); bios_w16(pc + 2, 0x2700); pc += 4;
    bios_w16(pc, 0x4FF9); bios_w32(pc + 2, 0x0010F300u); pc += 6;
    bios_w16(pc, 0x33FC); bios_w16(pc + 2, HLE_INIT_HW); bios_w32(pc + 4, HLE_TRAP_PORT); pc += 8;
    bios_w16(pc, 0x46FC); bios_w16(pc + 2, 0x2000); pc += 4;
    bios_w16(pc, 0x4EB9); bios_w32(pc + 2, 0x00000122u); pc += 6;
    u32 loop_pc = pc;
    bios_w16(pc, 0x46FC); bios_w16(pc + 2, 0x2700); pc += 4;
    bios_w16(pc, 0x4FF9); bios_w32(pc + 2, 0x0010F300u); pc += 6;
    bios_w16(pc, 0x33FC); bios_w16(pc + 2, HLE_SYS_RETURN); bios_w32(pc + 4, HLE_TRAP_PORT); pc += 8;
    bios_w16(pc, 0x46FC); bios_w16(pc + 2, 0x2000); pc += 4;
    bios_w16(pc, 0x4EB9); bios_w32(pc + 2, 0x00000122u); pc += 6;
    bios_w16(pc, (u16)(0x6000u | ((u16)((s32)loop_pc - (s32)(pc + 2)) & 0xFFu))); pc += 2;

    /* $C01080: Generic exception / IRQ3 ack + RTE */
    pc = 0x1080;
    bios_w16(pc, 0x33FC); bios_w16(pc + 2, 0x0001); bios_w32(pc + 4, 0x003C000Cu); pc += 8;
    bios_w16(pc, 0x4E73); /* RTE */

    /* $C01090: SYSTEM_INT1 (VBlank): run HLE_SYS_INT1, call SYSTEM_IO (so Start can JSR $128!), RTE */
    pc = 0x1090;
    bios_w16(pc, 0x48E7); bios_w16(pc + 2, 0xFFFE); pc += 4; /* MOVEM.L D0-D7/A0-A6, -(SP) */
    bios_w16(pc, 0x33FC); bios_w16(pc + 2, HLE_SYS_INT1); bios_w32(pc + 4, HLE_TRAP_PORT); pc += 8;
    bios_w16(pc, 0x4EB9); bios_w32(pc + 2, 0x00C01100u); pc += 6; /* JSR SYSTEM_IO */
    bios_w16(pc, 0x4CDF); bios_w16(pc + 2, 0x7FFF); pc += 4; /* MOVEM.L (SP)+, D0-D7/A0-A6 */
    bios_w16(pc, 0x4E73); /* RTE */

    /* $C010B0: SYSTEM_INT2 (Timer): ack IRQ2, kick watchdog, RTE */
    pc = 0x10B0;
    bios_w16(pc, 0x33FC); bios_w16(pc + 2, 0x0002); bios_w32(pc + 4, 0x003C000Cu); pc += 8;
    bios_w16(pc, 0x13C0); bios_w32(pc + 2, 0x00300001u); pc += 6;
    bios_w16(pc, 0x4E73); /* RTE */

    /* $C010D0: SYSTEM_RETURN: game jumped here to return from USER -> RTS back to $C01000 loop! */
    pc = 0x10D0;
    bios_w16(pc, 0x4E75); /* RTS */

    /* $C01100: SYSTEM_IO: update inputs; if $10FEF8 set (Start pressed in Title/Demo), call PLAYER_START ($128) */
    pc = 0x1100;
    bios_w16(pc, 0x33FC); bios_w16(pc + 2, HLE_SYS_IO_PRE); bios_w32(pc + 4, HLE_TRAP_PORT); pc += 8;
    bios_w16(pc, 0x4A39); bios_w32(pc + 2, 0x0010FEF8u); pc += 6; /* TST.B $10FEF8 */
    bios_w16(pc, 0x671C); pc += 2;                                /* BEQ.S +28 (.done) */
    bios_w16(pc, 0x4239); bios_w32(pc + 2, 0x0010FEF8u); pc += 6; /* CLR.B $10FEF8 */
    bios_w16(pc, 0x48E7); bios_w16(pc + 2, 0xFFFE); pc += 4;      /* MOVEM.L D0-D7/A0-A6, -(SP) */
    bios_w16(pc, 0x4EB9); bios_w32(pc + 2, 0x00000128u); pc += 6; /* JSR PLAYER_START */
    bios_w16(pc, 0x4CDF); bios_w16(pc + 2, 0x7FFF); pc += 4;      /* MOVEM.L (SP)+, D0-D7/A0-A6 */
    bios_w16(pc, 0x33FC); bios_w16(pc + 2, HLE_SYS_IO_POST); bios_w32(pc + 4, HLE_TRAP_PORT); pc += 8;
    bios_w16(pc, 0x4E75); /* .done: RTS */

    /* Simple trap + RTS stubs */
    static const struct { u32 addr; u16 id; } stubs[] = {
        {0x1150, HLE_CREDIT_CHECK},
        {0x1160, HLE_CREDIT_DOWN},
        {0x1170, HLE_READ_CAL},
        {0x1190, HLE_CARD},
        {0x11A0, HLE_FIX_CLEAR},
        {0x11B0, HLE_FIX_CLEAR},
        {0x11C0, HLE_LSP_1ST},
        {0x11D0, HLE_MESS_OUT},
    };
    for (unsigned i = 0; i < sizeof(stubs) / sizeof(stubs[0]); i++) {
        u32 a = stubs[i].addr;
        bios_w16(a, 0x33FC); bios_w16(a + 2, stubs[i].id); bios_w32(a + 4, HLE_TRAP_PORT);
        bios_w16(a + 8, 0x4E75);
    }
    bios_w16(0x1180, 0x4E75);           /* no-op RTS */
}

static void sync_page0_vectors(void)
{
    const u8 *vec_src = S.vectable ? S.p_rom : M->bios;
    u32 limit = (!S.vectable || S.p_size >= 0x80) ? 0x80u : S.p_size;
    for (u32 i = 0; i < limit; i++)
        M->page0[i] = vec_src[i];
}

static void update_p2_rmap(void)
{
    int direct = (S.board == 0);
    for (int i = 0; i < 16; i++) {
        if (!direct || !S.p_size) {
            rmap[0x20 + i] = 0;
        } else {
            u32 off = (S.p2_offset + ((u32)i << 16)) % S.p_size;
            rmap[0x20 + i] = (off + 0x10000u <= S.p_size) ? (S.p_rom + off) : M->p_tail;
        }
    }
}

static u8 p1_cnt_byte(int port)
{
    u16 p = S.pads[port & 1];
    u8 active = 0;
    if (p & NEO_PAD_UP)    active |= 0x01;
    if (p & NEO_PAD_DOWN)  active |= 0x02;
    if (p & NEO_PAD_LEFT)  active |= 0x04;
    if (p & NEO_PAD_RIGHT) active |= 0x08;
    if (p & NEO_PAD_A)     active |= 0x10;
    if (p & NEO_PAD_B)     active |= 0x20;
    if (p & NEO_PAD_C)     active |= 0x40;
    if (p & NEO_PAD_D)     active |= 0x80;
    return (u8)~active;
}

static u8 status_b_byte(void)
{
    u8 active = 0;
    if (S.pads[0] & NEO_PAD_START)  active |= 0x01;
    if (S.pads[0] & NEO_PAD_SELECT) active |= 0x02;
    if (S.pads[1] & NEO_PAD_START)  active |= 0x04;
    if (S.pads[1] & NEO_PAD_SELECT) active |= 0x08;
    /* Bits 4..5 = 00 (memory card inserted), bit 6 = 0 (writable), bit 7 = 0 (AES home console) */
    return (u8)(0x0Fu ^ active);
}

static void hle_fix_clear(void)
{
    for (u32 x = 0; x < 40; x++) {
        u16 val = (x == 0 || x == 39) ? 0x0020u : 0x00FFu;
        for (u32 y = 0; y < 32; y++)
            M->vram[0x7000 + (x << 5) + y] = val;
    }
    S.vram_addr = 0x7500;
    S.vram_bank = 0;
    S.vram_mod = 1;
}

static void hle_lsp_1st(void)
{
    for (u32 i = 0; i < 512; i++) {
        M->vram[0x8000 + i] = 0x0FFFu;
        M->vram[0x8200 + i] = 0x0000u;
        M->vram[0x8400 + i] = (u16)(380u << 7);
    }
    for (u32 i = 0; i < 64; i += 2)
        M->vram[i] = 0x00FFu;
    S.vram_addr = 0x0040;
    S.vram_bank = 0;
    S.vram_mod = 2;
    S.scb_dirty = 1;
}

/* Neo Geo BIOS MESS_OUT ($C004CE) command list interpreter */
static void hle_mess_out_stream(u32 addr, int depth)
{
    if (depth > 4)
        return;
    u16 fmt_hi = 0, fmt_mode = 0, end_code = 0x00FFu;
    u16 saved_vram = S.vram_addr;
    for (int guard = 0; guard < 1024; guard++) {
        u16 cmd = (u16)rw(addr);
        addr += 2;
        u8 op = (u8)(cmd & 0xFFu);
        if (op == 0x00)
            break;
        switch (op) {
        case 0x01:
            fmt_hi = (u16)(cmd & 0xFF00u);
            fmt_mode = (u16)rw(addr);
            addr += 2;
            end_code = (u16)(fmt_mode >> 8);
            break;
        case 0x02: {
            s8 step = (s8)(cmd >> 8);
            S.vram_mod = step ? (s16)step : (s16)rw(addr);
            if (!step)
                addr += 2;
            break;
        }
        case 0x03:
            S.vram_addr = (u16)rw(addr);
            S.vram_bank = S.vram_addr & 0x8000u;
            addr += 2;
            break;
        case 0x04: {
            u32 src = rl(addr);
            addr += 4;
            int is_word = fmt_mode & 1;
            int by_len  = (fmt_mode >> 1) & 1;
            for (int k = 0; k < 256; k++) {
                if (by_len && k >= (int)end_code)
                    break;
                u16 w;
                if (is_word) {
                    w = (u16)rw(src); src += 2;
                    if (!by_len && w == end_code) break;
                } else {
                    u8 ch = (u8)rb(src++);
                    if (!by_len && ch == (u8)end_code) break;
                    w = (u16)(fmt_hi | ch);
                }
                if (S.vram_addr < 0x8800u)
                    M->vram[S.vram_addr] = w;
                S.vram_addr = (u16)(((S.vram_addr + (u16)S.vram_mod) & 0x7FFFu) | S.vram_bank);
            }
            break;
        }
        case 0x05:
            S.vram_addr = (u16)(S.vram_addr + (u16)rw(addr));
            S.vram_bank = S.vram_addr & 0x8000u;
            addr += 2;
            break;
        case 0x06:
            S.vram_addr = saved_vram;
            S.vram_bank = S.vram_addr & 0x8000u;
            break;
        case 0x07: {
            int is_word = fmt_mode & 1;
            int by_len  = (fmt_mode >> 1) & 1;
            for (int k = 0; k < 256; k++) {
                if (by_len && k >= (int)end_code)
                    break;
                u16 w;
                if (is_word) {
                    w = (u16)rw(addr); addr += 2;
                    if (!by_len && w == end_code) break;
                } else {
                    u8 ch = (u8)rb(addr++);
                    if (!by_len && ch == (u8)end_code) break;
                    w = (u16)(fmt_hi | ch);
                }
                if (S.vram_addr < 0x8800u)
                    M->vram[S.vram_addr] = w;
                S.vram_addr = (u16)(((S.vram_addr + (u16)S.vram_mod) & 0x7FFFu) | S.vram_bank);
            }
            if (addr & 1u)
                addr++;
            break;
        }
        case 0x09: {
            u32 sub = rl(addr);
            addr += 4;
            saved_vram = S.vram_addr;
            hle_mess_out_stream(sub, depth + 1);
            break;
        }
        default:
            return;
        }
    }
}

static void hle_mess_out(void)
{
    if (wram_rb(0xFDC2))
        return;
    u32 end_ptr = wram_rl(0xFDBE);
    if (end_ptr > 0x0010FF00u && end_ptr <= 0x00110000u) {
        for (u32 p = 0xFD00u + 0x0200u; p < (end_ptr & 0xFFFFu); p += 4) {
            u32 cmd_ptr = wram_rl(p);
            if (!cmd_ptr)
                break;
            hle_mess_out_stream(cmd_ptr & 0xFFFFFFu, 0);
        }
    }
    wram_wl(0xFDBE, 0x0010FF00u);
}

static void irq_refresh(void)
{
    u32 lv = (S.irq_pending & 4) ? 3u : (S.irq_pending & 2) ? 2u : (S.irq_pending & 1) ? 1u : 0u;
    m.ipl = lv;
    check_pending();
}

static void neo_iack(u32 level)
{
    (void)level;
}

static void hle_update_controllers(int check_start)
{
    for (int i = 0; i < 2; i++) {
        u32 base = 0xFD94u + (u32)(i * 6);
        u8 prev = wram_rb(base + 2);
        u8 cur  = (u8)~p1_cnt_byte(i);
        u8 chg  = (u8)(cur & ~prev);
        u8 rep  = 0;
        u8 tmr  = wram_rb(base + 5);
        if (chg) {
            rep = chg;
            tmr = 16;
        } else if (cur) {
            if (tmr <= 1) {
                rep = cur;
                tmr = 8;
            } else {
                tmr--;
            }
        } else {
            tmr = 16;
        }
        wram_wb(base + 0, 1);
        wram_wb(base + 1, prev);
        wram_wb(base + 2, cur);
        wram_wb(base + 3, chg);
        wram_wb(base + 4, rep);
        wram_wb(base + 5, tmr);
    }

    u8 prev_st = wram_rb(0xFEAC);
    u8 cur_st  = (u8)(~status_b_byte() & 0x0Fu);
    u8 chg_st  = (u8)(cur_st & ~prev_st);
    wram_wb(0xFEAC, cur_st);
    wram_wb(0xFEAD, chg_st);
    wram_wb(0xFDAC, cur_st);
    wram_wb(0xFDAD, chg_st);

    /* Trigger PLAYER_START ($000128) when Start is pressed during Title/Demo (USER_MODE == 1) */
    if (check_start && wram_rb(0xFDAF) == 1) {
        u8 trig = (u8)((chg_st & 1u) | ((chg_st >> 1) & 2u));
        if (trig) {
            wram_wb(0xFDB4, trig);
            wram_wb(0xFEF8, 1);
        }
    }
}

static void z80_send_sound(u8 code);

static void hle_trap(u16 id)
{
    switch (id) {
    case HLE_INIT_HW: {
        for (u32 i = 0; i < 0x10000; i++)
            M->wram[i] = 0;
        S.irq_pending = 0;
        irq_refresh();
        S.watchdog_frames = 0;

        /* Switch to cartridge vectors & cartridge FIX/M1 before USER(0) so both
           commercial carts (which return via SYSTEM_RETURN) and single-entry
           homebrew (PeterLemon, NeoBitz/NeoThunder) have cart vectors & S-ROM ready! */
        S.vectable = 1;
        sync_page0_vectors();
        S.crtfix = 1;

        wram_wb(0xFD80, 0x80);          /* BIOS_SYSTEM_MODE: Game mode */
        wram_wb(0xFD82, 0x00);          /* BIOS_MVS_FLAG: 0 (AES home) */
        wram_wb(0xFD83, 0x01);          /* BIOS_COUNTRY_CODE: 1 (USA) */
        wram_wb(0xFD94, 0x01);          /* P1 connected */
        wram_wb(0xFD9A, 0x01);          /* P2 connected */
        wram_wb(0xFDAE, 0x00);          /* BIOS_USER_REQUEST = 0 (Init) */
        wram_wb(0xFDAF, 0x00);          /* BIOS_USER_MODE = 0 */
        wram_wb(0xFDB0, 0x01);          /* CREDIT_DEC1 */
        wram_wb(0xFDB1, 0x01);          /* CREDIT_DEC2 */
        wram_wl(0xFDBE, 0x0010FF00u);   /* BIOS_MESS_POINT */
        M->nvram[0x0034 ^ 1] = 0x09;    /* Credits in BCD if checked */
        M->nvram[0x0035 ^ 1] = 0x09;

        /* Load default Soft-DIPs from cartridge's US DIP table pointer ($11A) */
        if (S.p_size >= 0x122) {
            u32 dip_ptr = rl(0x00011Au) & 0xFFFFFFu;
            if (dip_ptr && dip_ptr + 32 <= S.p_size) {
                for (int i = 0; i < 6; i++)
                    wram_wb(0xFD84u + (u32)i, (u8)rb(dip_ptr + 16u + (u32)i));
                for (int i = 0; i < 10; i++)
                    wram_wb(0xFD8Au + (u32)i, (u8)(rb(dip_ptr + 22u + (u32)i) >> 4));
            }
        }

        hle_fix_clear();
        hle_lsp_1st();
        z80_send_sound(0x03);           /* Standard Neo Geo sound driver init command */
        break;
    }
    case HLE_SYS_RETURN:
        S.irq_pending = 0;
        irq_refresh();
        S.watchdog_frames = 0;
        S.vectable = 1;
        sync_page0_vectors();
        S.crtfix = 1;
        wram_wb(0xFD80, 0x80);
        if (wram_rb(0xFDAE) == 0)
            wram_wb(0xFDAE, 2);         /* Attract / Title */
        wram_wb(0xFDAF, 1);             /* Title / Demo mode */
        break;
    case HLE_SYS_INT1:
        S.irq_pending &= ~1u;
        irq_refresh();
        S.watchdog_frames = 0;
        wram_wl(0xFE88, wram_rl(0xFE88) + 1u);
        wram_wl(0xFDD4, wram_rl(0xFDD4) + 1u);
        wram_wb(0xFE8D, 0);
        hle_mess_out();
        break;
    case HLE_SYS_IO_PRE:
        hle_update_controllers(1);
        break;
    case HLE_SYS_IO_POST:
        if (wram_rb(0xFDAF) == 2) {
            u8 sf = wram_rb(0xFDB4);
            if (sf & 1) wram_wb(0xFDB6, 1);
            if (sf & 2) wram_wb(0xFDB7, 1);
            wram_wb(0xFD81, 3);
        }
        break;
    case HLE_CREDIT_CHECK:
        /* Home / Free-play: credits always available */
        break;
    case HLE_CREDIT_DOWN: {
        u8 sf = wram_rb(0xFDB4);
        if (sf & 1) wram_wb(0xFDB6, 1);
        if (sf & 2) wram_wb(0xFDB7, 1);
        break;
    }
    case HLE_READ_CAL:
        /* BCD: Year 26, Month 11, Day 19, Weekday 4, Hour 12, Min 00, Sec 00 */
        wram_wb(0xFDD2, 0x26);
        wram_wb(0xFDD3, 0x11);
        wram_wb(0xFDD4, 0x19);
        wram_wb(0xFDD5, 0x04);
        wram_wb(0xFDD6, 0x12);
        wram_wb(0xFDD7, 0x00);
        wram_wb(0xFDD8, 0x00);
        break;
    case HLE_CARD: {
        u8 cmd = wram_rb(0xFDC4);
        /* 0: format -> OK (0x00), 1/2: search/load -> not found (0x82), 3..5: save/del -> OK (0x00) */
        wram_wb(0xFDC6, (cmd == 1 || cmd == 2) ? 0x82 : 0x00);
        break;
    }
    case HLE_FIX_CLEAR:
        hle_fix_clear();
        break;
    case HLE_LSP_1ST:
        hle_lsp_1st();
        break;
    case HLE_MESS_OUT:
        hle_mess_out();
        break;
    }
}

/* ---- YM2610 (OPNB): 4-ch FM + 3-ch SSG + 6-ch ADPCM-A + 1-ch ADPCM-B ---- */

enum { EG_ATTACK, EG_DECAY, EG_SUSTAIN, EG_RELEASE };

static const u16 opn_logsin[256] = {
    2137,1731,1543,1419,1326,1252,1190,1137,1091,1050,1013,979,949,920,894,869,
    846,825,804,785,767,749,732,717,701,687,672,659,646,633,621,609,
    598,587,576,566,556,546,536,527,518,509,500,492,484,476,468,460,
    453,445,438,431,424,417,410,404,397,391,385,379,373,367,361,356,
    350,345,339,334,329,324,319,314,309,304,299,295,290,286,281,277,
    273,268,264,260,256,252,248,244,240,237,233,229,226,222,219,215,
    212,209,205,202,199,196,193,190,187,184,181,178,175,172,169,167,
    164,161,159,156,153,151,148,146,143,141,139,136,134,132,129,127,
    125,123,121,119,117,115,113,111,109,107,105,103,101,99,97,96,
    94,92,90,89,87,85,84,82,81,79,78,76,75,73,72,70,
    69,68,66,65,64,62,61,60,59,57,56,55,54,53,52,50,
    49,48,47,46,45,44,43,42,41,40,39,38,37,36,36,35,
    34,33,32,31,31,30,29,28,27,27,26,25,25,24,23,23,
    22,21,21,20,19,19,18,18,17,17,16,16,15,15,14,14,
    13,13,12,12,11,11,11,10,10,9,9,9,8,8,8,7,
    7,7,6,6,6,5,5,5,5,4,4,4,4,4,3,3
};

static const u16 opn_exp2[256] = {
    1018,1013,1007,1002,996,991,986,980,975,970,965,959,954,949,944,939,
    934,929,924,919,914,909,904,899,895,890,885,880,876,871,866,862,
    857,852,848,843,839,834,830,826,821,817,812,808,804,800,795,791,
    787,783,779,774,770,766,762,758,754,750,746,742,738,734,730,726,
    723,719,715,711,707,704,700,696,693,689,685,682,678,675,671,667,
    664,660,657,653,650,647,643,640,636,633,630,626,623,620,617,613,
    610,607,604,601,597,594,591,588,585,582,579,576,573,570,567,564,
    561,558,555,552,549,547,544,541,538,535,532,530,527,524,521,519,
    516,513,511,508,505,503,500,498,495,492,490,487,485,482,480,477,
    475,472,470,467,465,463,460,458,455,453,451,448,446,444,441,439,
    437,435,432,430,428,426,423,421,419,417,415,413,410,408,406,404,
    402,400,398,396,394,392,390,388,386,384,382,380,378,376,374,372,
    370,368,366,365,363,361,359,357,355,353,352,350,348,346,344,343,
    341,339,337,336,334,332,331,329,327,325,324,322,320,319,317,316,
    314,312,311,309,308,306,304,303,301,300,298,297,295,294,292,291,
    289,288,286,285,283,282,280,279,278,276,275,273,272,270,269,268
};

static const u8 opn_dt_tab[4][32] = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 6, 6, 7, 8, 8, 8, 8},
    {1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 6, 6, 7, 8, 8, 9,10,11,12,13,14,16,16,16,16},
    {2, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 6, 6, 7, 8, 8, 9,10,11,12,13,14,16,17,19,20,22,22,22,22}
};

static const u8 opn_eg_steps[20][8] = {
    {0,1,0,1,0,1,0,1}, {0,1,0,1,1,1,0,1}, {0,1,1,1,0,1,1,1}, {0,1,1,1,1,1,1,1},
    {1,1,1,1,1,1,1,1}, {1,1,1,2,1,1,1,2}, {1,2,1,2,1,2,1,2}, {1,2,2,2,1,2,2,2},
    {2,2,2,2,2,2,2,2}, {2,2,2,4,2,2,2,4}, {2,4,2,4,2,4,2,4}, {2,4,4,4,2,4,4,4},
    {4,4,4,4,4,4,4,4}, {4,4,4,8,4,4,4,8}, {4,8,4,8,4,8,4,8}, {4,8,8,8,4,8,8,8},
    {8,8,8,8,8,8,8,8}, {8,8,8,8,8,8,8,8}, {8,8,8,8,8,8,8,8}, {8,8,8,8,8,8,8,8}
};

static const u8 opn_lfo_period[8] = {108, 77, 71, 67, 62, 44, 8, 5};
static const u8 opn_ams_shift[4]  = {8, 3, 1, 0};
static const u8 opn_pm_depth[8]   = {0, 4, 6, 9, 12, 18, 36, 72};
static const s8 opn_pm_wave[32]   = {
    0, 1, 2, 3, 4, 5, 6, 7, 6, 5, 4, 3, 2, 1, 0, 0,
    0,-1,-2,-3,-4,-5,-6,-7,-6,-5,-4,-3,-2,-1, 0, 0
};

/* ADPCM-A 12-bit JEDI step table (49 entries) & index delta */
static const u16 jedi_step[49] = {
    16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66,
    73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307,
    337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552
};
static const s8 jedi_idx_chg[8] = {-1, -1, -1, -1, 2, 5, 7, 9};

/* ADPCM-B Delta-T step scale */
static const u8 deltat_scale[8] = {57, 57, 57, 57, 77, 102, 128, 153};

/* SSG 4-bit logarithmic volume table */
static const s16 ssg_vol_tab[16] = {
    0, 32, 46, 65, 92, 130, 184, 260, 368, 520, 735, 1040, 1470, 2080, 2941, 4160
};

static u8 opn_key_code(u16 fnum, u8 block)
{
    static const u8 fk[16] = {0,0,0,0,0,0,0,1,2,3,3,3,3,3,3,3};
    return (u8)((block << 2) | fk[fnum >> 7]);
}

static void opn_op_env(struct ym_op *o)
{
    u32 e = (u32)o->att + ((u32)o->tl << 3);
    o->env = e > 0x3FFu ? 0x3FFu : e;
}

static u8 opn_eff_rate(u8 r, u8 kc, u8 ks)
{
    if (!r)
        return 0;
    u32 v = (u32)r * 2u + (kc >> (3 - ks));
    return (u8)(v > 63u ? 63u : v);
}

static void opn_op_update(struct ym_ch *c, int n)
{
    struct ym_op *o = &c->op[n];
    u16 fn = c->fnum;
    u8 bl = c->block, kc = c->kc;
    if (c == &S.ym.ch[2] && (S.ym.mode & 0xC0) && n != 3) {
        int k = n == 0 ? 1 : n == 1 ? 2 : 0;
        fn = c->fnum3[k], bl = c->block3[k], kc = c->kc3[k];
    }
    u32 inc = ((u32)fn << bl) >> 1;
    s32 dt = opn_dt_tab[o->dt & 3][kc];
    inc = (o->dt & 4) ? (inc > (u32)dt ? inc - (u32)dt : 0u) : inc + (u32)dt;
    o->inc = (o->mul ? inc * o->mul : inc >> 1) & 0xFFFFFu;
    o->rate[EG_ATTACK]  = opn_eff_rate(o->ar, kc, o->ks);
    o->rate[EG_DECAY]   = opn_eff_rate(o->d1r, kc, o->ks);
    o->rate[EG_SUSTAIN] = opn_eff_rate(o->d2r, kc, o->ks);
    o->rate[EG_RELEASE] = opn_eff_rate((u8)(o->rr * 2 + 1), kc, o->ks);
}

static void opn_key(struct ym_ch *c, int n, int on)
{
    struct ym_op *o = &c->op[n];
    if (on) {
        if (o->state == EG_RELEASE) {
            o->phase = 0;
            o->state = EG_ATTACK;
            if (o->rate[EG_ATTACK] >= 62) {
                o->att = 0;
                o->state = o->sl ? EG_DECAY : EG_SUSTAIN;
            }
            opn_op_env(o);
            c->quiet = 0;
        }
    } else if (o->state != EG_RELEASE) {
        o->state = EG_RELEASE;
    }
}

static void ym_irq_update(void)
{
    u8 mask = (u8)((S.ym.mode >> 2) & 3u);
    S.z.irq = (S.ym.status0 & mask) != 0;
}

static s32 ta_period_zcyc(void)
{
    return (s32)(1024u - S.ym.ta_load) * 36;
}

static s32 tb_period_zcyc(void)
{
    return (s32)(256u - S.ym.tb_load) * 576;
}

static void ssg_reset_env(struct ssg_state *ssg)
{
    u8 sh = ssg->reg[13] & 0x0Fu;
    ssg->env_cnt = 0;
    ssg->env_step = 0;
    ssg->env_cont = (sh >> 3) & 1u;
    ssg->env_att  = (sh >> 2) & 1u;
    ssg->env_alt  = (sh >> 1) & 1u;
    ssg->env_hold = sh & 1u;
    if (!ssg->env_cont) {
        ssg->env_hold = 1;
        ssg->env_alt = ssg->env_att;
    }
    ssg->env_vol = ssg->env_att ? 0 : 15;
}

static void ym_apply_reg(int part, u8 r, u8 v)
{
    if (part == 0) {
        if (r < 0x10) {
            S.ym.ssg.reg[r] = v;
            if (r == 13)
                ssg_reset_env(&S.ym.ssg);
            return;
        }
        if (r >= 0x10 && r <= 0x1C) {
            struct adpcm_b_ch *pb = &S.ym.pb;
            switch (r) {
            case 0x10:
                if (v & 0x01) {
                    pb->on = 0;
                }
                pb->repeat = (v >> 4) & 1u;
                if (v & 0x80) {
                    pb->addr = (u32)pb->start_raw << 8;
                    pb->end_addr = ((u32)pb->end_raw << 8) | 0xFFu;
                    pb->nibble_hi = 1;
                    pb->phase = 0;
                    pb->adpcm_acc = 0;
                    pb->step = 127;
                    pb->prev_out = pb->cur_out = 0;
                    pb->on = 1;
                    S.ym.eos_raw &= ~0x80u;
                } else if (!(v & 0x80) && (v & 0x01)) {
                    pb->on = 0;
                }
                break;
            case 0x11: pb->lrsel = v; break;
            case 0x12: pb->start_raw = (u16)((pb->start_raw & 0xFF00u) | v); break;
            case 0x13: pb->start_raw = (u16)((pb->start_raw & 0x00FFu) | ((u16)v << 8)); break;
            case 0x14: pb->end_raw = (u16)((pb->end_raw & 0xFF00u) | v); break;
            case 0x15: pb->end_raw = (u16)((pb->end_raw & 0x00FFu) | ((u16)v << 8)); break;
            case 0x19: pb->delta_n = (u16)((pb->delta_n & 0xFF00u) | v); break;
            case 0x1A: pb->delta_n = (u16)((pb->delta_n & 0x00FFu) | ((u16)v << 8)); break;
            case 0x1B: pb->vol = v; break;
            case 0x1C:
                S.ym.eos_raw &= (u8)~v;
                S.ym.eos_mask = (u8)(v & 0xBFu);
                break;
            }
            return;
        }
        if (r < 0x30) {
            switch (r) {
            case 0x22: S.ym.lfo_on = (v >> 3) & 1u; S.ym.lfo_freq = v & 7u; break;
            case 0x24: S.ym.ta_load = (u16)((S.ym.ta_load & 3u) | ((u16)v << 2)); break;
            case 0x25: S.ym.ta_load = (u16)((S.ym.ta_load & ~3u) | (v & 3u)); break;
            case 0x26: S.ym.tb_load = v; break;
            case 0x27: {
                u8 prev = S.ym.mode;
                S.ym.mode = v;
                if (!(prev & 1u) && (v & 1u))
                    S.ym.ta_cnt = ta_period_zcyc();
                if (!(prev & 2u) && (v & 2u))
                    S.ym.tb_cnt = tb_period_zcyc();
                if (v & 0x10u) S.ym.status0 &= ~1u;
                if (v & 0x20u) S.ym.status0 &= ~2u;
                ym_irq_update();
                for (int n = 0; n < 3; n++)
                    opn_op_update(&S.ym.ch[2], n);
                break;
            }
            case 0x28: {
                int ch = v & 3;
                if (ch == 3)
                    break;
                ch += (v & 4) ? 3 : 0;
                for (int n = 0; n < 4; n++)
                    opn_key(&S.ym.ch[ch], n, (v >> (4 + n)) & 1);
                break;
            }
            }
            return;
        }
    } else {
        /* Part 1 (Port B): $00..$2F are ADPCM-A 6-channel registers */
        if (r < 0x30) {
            if (r == 0x00) {
                int dump = (v & 0x80) != 0;
                for (int i = 0; i < 6; i++) {
                    if (v & (1u << i)) {
                        struct adpcm_a_ch *pa = &S.ym.pa[i];
                        if (dump) {
                            pa->on = 0;
                        } else {
                            pa->addr = (u32)pa->start_raw << 8;
                            pa->end_addr = ((u32)pa->end_raw << 8) | 0xFFu;
                            pa->nibble_hi = 1;
                            pa->acc = 0;
                            pa->step_idx = 0;
                            pa->out = 0;
                            pa->on = 1;
                            S.ym.eos_raw &= (u8)~(1u << i);
                        }
                    }
                }
            } else if (r == 0x01) {
                S.ym.pa_mvol = v & 0x3Fu;
            } else if (r >= 0x08 && r <= 0x0D) {
                S.ym.pa[r - 0x08].cvol = v;
            } else if (r >= 0x10 && r <= 0x15) {
                int i = r - 0x10;
                S.ym.pa[i].start_raw = (u16)((S.ym.pa[i].start_raw & 0xFF00u) | v);
            } else if (r >= 0x18 && r <= 0x1D) {
                int i = r - 0x18;
                S.ym.pa[i].start_raw = (u16)((S.ym.pa[i].start_raw & 0x00FFu) | ((u16)v << 8));
            } else if (r >= 0x20 && r <= 0x25) {
                int i = r - 0x20;
                S.ym.pa[i].end_raw = (u16)((S.ym.pa[i].end_raw & 0xFF00u) | v);
            } else if (r >= 0x28 && r <= 0x2D) {
                int i = r - 0x28;
                S.ym.pa[i].end_raw = (u16)((S.ym.pa[i].end_raw & 0x00FFu) | ((u16)v << 8));
            }
            return;
        }
    }

    int ch = r & 3;
    if (ch == 3)
        return;
    struct ym_ch *c = &S.ym.ch[ch + 3 * part];
    if (r < 0xA0) {
        static const u8 slot[4] = {0, 2, 1, 3};
        int n = slot[(r >> 2) & 3];
        struct ym_op *o = &c->op[n];
        switch (r & 0xF0) {
        case 0x30: o->dt = (v >> 4) & 7u; o->mul = v & 15u; break;
        case 0x40: o->tl = v & 0x7Fu; opn_op_env(o); break;
        case 0x50: o->ks = v >> 6; o->ar = v & 31u; break;
        case 0x60: o->am = v >> 7; o->d1r = v & 31u; break;
        case 0x70: o->d2r = v & 31u; break;
        case 0x80: o->sl = v >> 4; o->rr = v & 15u; break;
        }
        opn_op_update(c, n);
        return;
    }
    switch (r & 0xFC) {
    case 0xA0:
        c->fnum = (u16)(((u16)(S.ym.freq_latch[part] & 7u) << 8) | v);
        c->block = (S.ym.freq_latch[part] >> 3) & 7u;
        c->kc = opn_key_code(c->fnum, c->block);
        for (int n = 0; n < 4; n++)
            opn_op_update(c, n);
        break;
    case 0xA4: S.ym.freq_latch[part] = v; break;
    case 0xA8:
        if (!part) {
            struct ym_ch *c3 = &S.ym.ch[2];
            c3->fnum3[ch] = (u16)(((u16)(S.ym.freq_latch3 & 7u) << 8) | v);
            c3->block3[ch] = (S.ym.freq_latch3 >> 3) & 7u;
            c3->kc3[ch] = opn_key_code(c3->fnum3[ch], c3->block3[ch]);
            for (int n = 0; n < 3; n++)
                opn_op_update(c3, n);
        }
        break;
    case 0xAC: if (!part) S.ym.freq_latch3 = v; break;
    case 0xB0: c->alg = v & 7u; c->fb = (v >> 3) & 7u; break;
    case 0xB4: c->on = (v & 0xC0u) != 0; c->ams = (v >> 4) & 3u; c->pms = v & 7u; break;
    }
}

/* Advance YM2610 timers during Z80 execution (and ADPCM EOS when audio synthesis is off) */
static void ym_timers_step(s32 dz)
{
    if (dz <= 0)
        return;
    if (S.ym.mode & 1u) {
        S.ym.ta_cnt -= dz;
        if (S.ym.ta_cnt <= 0) {
            s32 p = ta_period_zcyc();
            while (S.ym.ta_cnt <= 0)
                S.ym.ta_cnt += p;
            if (S.ym.mode & 4u)
                S.ym.status0 |= 1u;
            ym_irq_update();
        }
    }
    if (S.ym.mode & 2u) {
        S.ym.tb_cnt -= dz;
        if (S.ym.tb_cnt <= 0) {
            s32 p = tb_period_zcyc();
            while (S.ym.tb_cnt <= 0)
                S.ym.tb_cnt += p;
            if (S.ym.mode & 8u)
                S.ym.status0 |= 2u;
            ym_irq_update();
        }
    }
}

static void opn_eg_tick(void)
{
    u32 t = ++S.ym.eg_cnt;
    for (int ch = 0; ch < 6; ch++) {
        struct ym_ch *c = &S.ym.ch[ch];
        if (c->quiet)
            continue;
        int quiet = 1;
        for (int n = 0; n < 4; n++) {
            struct ym_op *o = &c->op[n];
            if (o->state == EG_RELEASE && o->att >= 0x3FF)
                continue;
            quiet = 0;
            u32 rate = o->rate[o->state];
            if (rate < 2)
                continue;
            u32 inc;
            if (rate < 48) {
                u32 shift = 11u - (rate >> 2);
                if (t & ((1u << shift) - 1u))
                    continue;
                inc = opn_eg_steps[rate & 3u][(t >> shift) & 7u];
            } else {
                inc = opn_eg_steps[rate - 44u][t & 7u];
            }
            if (o->state == EG_ATTACK) {
                if (rate < 62)
                    o->att += (~o->att * (s32)inc) >> 4;
                if (o->att <= 0 || rate >= 62) {
                    o->att = 0;
                    o->state = EG_DECAY;
                }
            } else {
                o->att += (s32)inc;
                if (o->att > 0x3FF)
                    o->att = 0x3FF;
                if (o->state == EG_DECAY && o->att >= (o->sl == 15 ? 0x3E0 : (s32)o->sl << 5))
                    o->state = EG_SUSTAIN;
            }
            opn_op_env(o);
        }
        c->quiet = (u8)quiet;
    }
}

INLINE s32 opn_op_out(struct ym_op *o, s32 mod, u32 am)
{
    u32 env = o->env + (o->am ? am : 0u);
    if (env >= 0x3FFu)
        return 0;
    u32 p = ((o->phase >> 10) + (u32)mod) & 0x3FFu;
    u32 i = (p & 0x100u) ? (~p & 0xFFu) : (p & 0xFFu);
    u32 a = opn_logsin[i] + (env << 2);
    s32 v = a >= 0x1A00u ? 0 : (s32)(((u32)opn_exp2[a & 0xFFu] << 2) >> (a >> 8));
    return (p & 0x200u) ? -v : v;
}

static s32 opn_ch_out(struct ym_ch *c, u32 am_lfo, s32 pm, u32 steps)
{
    struct ym_op *o = c->op;
    if (c->quiet)
        return 0;
    u32 am = am_lfo >> opn_ams_shift[c->ams];
    for (int n = 0; n < 4; n++) {
        u32 inc = o[n].inc;
        if (pm && c->pms)
            inc += (u32)(((s32)(inc >> 4) * pm * (s32)opn_pm_depth[c->pms]) >> 12);
        o[n].phase = (o[n].phase + inc * steps) & 0xFFFFFu;
    }
    s32 fb = c->fb ? (o[0].out + o[0].out1) >> (10 - c->fb) : 0;
    o[0].out1 = o[0].out;
    s32 s1 = o[0].out = opn_op_out(&o[0], fb, am), s2, s3, out;
    switch (c->alg) {
    case 0: s2 = opn_op_out(&o[1], s1 >> 1, am); s3 = opn_op_out(&o[2], s2 >> 1, am); out = opn_op_out(&o[3], s3 >> 1, am); break;
    case 1: s2 = opn_op_out(&o[1], 0, am); s3 = opn_op_out(&o[2], (s1 + s2) >> 1, am); out = opn_op_out(&o[3], s3 >> 1, am); break;
    case 2: s2 = opn_op_out(&o[1], 0, am); s3 = opn_op_out(&o[2], s2 >> 1, am); out = opn_op_out(&o[3], (s1 + s3) >> 1, am); break;
    case 3: s2 = opn_op_out(&o[1], s1 >> 1, am); s3 = opn_op_out(&o[2], 0, am); out = opn_op_out(&o[3], (s2 + s3) >> 1, am); break;
    case 4: s3 = opn_op_out(&o[2], 0, am); out = opn_op_out(&o[1], s1 >> 1, am) + opn_op_out(&o[3], s3 >> 1, am); break;
    case 5: out = opn_op_out(&o[1], s1 >> 1, am) + opn_op_out(&o[2], s1 >> 1, am) + opn_op_out(&o[3], s1 >> 1, am); break;
    case 6: out = opn_op_out(&o[1], s1 >> 1, am) + opn_op_out(&o[2], 0, am) + opn_op_out(&o[3], 0, am); break;
    default: out = s1 + opn_op_out(&o[1], 0, am) + opn_op_out(&o[2], 0, am) + opn_op_out(&o[3], 0, am); break;
    }
    if (out > 8191) out = 8191;
    else if (out < -8192) out = -8192;
    return out;
}

static s32 adpcm_a_tick(void)
{
    s32 sum = 0;
    for (int i = 0; i < 6; i++) {
        struct adpcm_a_ch *pa = &S.ym.pa[i];
        if (!pa->on)
            continue;
        if ((pa->addr & 0xFFFFFFu) > (pa->end_addr & 0xFFFFFFu)) {
            pa->on = 0;
            S.ym.eos_raw |= (u8)(1u << i);
            continue;
        }
        u8 byte = (pa->addr < S.v1_size) ? S.v1_rom[pa->addr] : 0x00;
        u8 nib;
        if (pa->nibble_hi) {
            nib = byte >> 4;
            pa->nibble_hi = 0;
        } else {
            nib = byte & 0x0Fu;
            pa->nibble_hi = 1;
            pa->addr = (pa->addr + 1u) & 0xFFFFFFu;
        }
        s32 step = jedi_step[pa->step_idx];
        s32 diff = (((nib & 7) * 2 + 1) * step) >> 3;
        if (nib & 8)
            pa->acc -= diff;
        else
            pa->acc += diff;
        if (pa->acc > 2047) pa->acc = 2047;
        else if (pa->acc < -2048) pa->acc = -2048;

        pa->step_idx += jedi_idx_chg[nib & 7];
        if (pa->step_idx < 0) pa->step_idx = 0;
        else if (pa->step_idx > 48) pa->step_idx = 48;

        if (!(pa->cvol & 0xC0u))
            continue;
        u32 att = (0x3Fu - S.ym.pa_mvol) + (0x1Fu - (pa->cvol & 0x1Fu));
        if (att < 64u) {
            /* ~0.75 dB per step (8 steps = 6 dB = >> 1) */
            static const u8 att_mul[8] = {16, 15, 13, 12, 11, 10, 9, 8};
            s32 s = (pa->acc * (s32)att_mul[att & 7u]) >> (1 + (att >> 3));
            sum += s;
        }
    }
    return sum;
}

static s32 adpcm_b_sample(void)
{
    struct adpcm_b_ch *pb = &S.ym.pb;
    if (!pb->on)
        return 0;
    pb->phase += pb->delta_n;
    while (pb->phase >= 0x10000u) {
        pb->phase -= 0x10000u;
        pb->prev_out = pb->cur_out;
        if ((pb->addr & 0xFFFFFFu) > (pb->end_addr & 0xFFFFFFu)) {
            if (pb->repeat) {
                pb->addr = (u32)pb->start_raw << 8;
                pb->nibble_hi = 1;
                pb->adpcm_acc = 0;
                pb->step = 127;
            } else {
                pb->on = 0;
                S.ym.eos_raw |= 0x80u;
                return 0;
            }
        }
        u8 byte = (pb->addr < S.v2_size) ? S.v2_rom[pb->addr] : 0x00;
        u8 nib;
        if (pb->nibble_hi) {
            nib = byte >> 4;
            pb->nibble_hi = 0;
        } else {
            nib = byte & 0x0Fu;
            pb->nibble_hi = 1;
            pb->addr = (pb->addr + 1u) & 0xFFFFFFu;
        }
        s32 diff = ((((s32)(nib & 7u) * 2 + 1) * pb->step) >> 3);
        if (nib & 8u)
            pb->adpcm_acc -= diff;
        else
            pb->adpcm_acc += diff;
        if (pb->adpcm_acc > 32767) pb->adpcm_acc = 32767;
        else if (pb->adpcm_acc < -32768) pb->adpcm_acc = -32768;

        pb->step = (pb->step * (s32)deltat_scale[nib & 7u]) >> 6;
        if (pb->step < 127) pb->step = 127;
        else if (pb->step > 24576) pb->step = 24576;
        pb->cur_out = pb->adpcm_acc;
    }
    if (!(pb->lrsel & 0xC0u) || !pb->vol)
        return 0;
    s32 interp = pb->prev_out + (((pb->cur_out - pb->prev_out) * (s32)(pb->phase >> 8)) >> 8);
    return (interp * (s32)pb->vol) >> 10;
}

static s32 ssg_sample(void)
{
    struct ssg_state *ssg = &S.ym.ssg;
    /* SSG clock is 2 MHz -> tone base 125 kHz; at 55.56 kHz YM sample rate, ~2.25 SSG ticks per YM sample */
    for (int step = 0; step < 2; step++) {
        for (int i = 0; i < 3; i++) {
            u32 per = (u32)ssg->reg[i * 2] | ((u32)(ssg->reg[i * 2 + 1] & 0x0Fu) << 8);
            if (!per) per = 1;
            if (++ssg->count[i] >= per) {
                ssg->count[i] = 0;
                ssg->out_bit[i] ^= 1u;
            }
        }
        u32 nper = ssg->reg[6] & 0x1Fu;
        if (!nper) nper = 1;
        if (++ssg->noise_cnt >= (nper << 1)) {
            ssg->noise_cnt = 0;
            u32 bit = (ssg->lfsr ^ (ssg->lfsr >> 3)) & 1u;
            ssg->lfsr = (ssg->lfsr >> 1) | (bit << 16);
        }
        u32 eper = (u32)ssg->reg[11] | ((u32)ssg->reg[12] << 8);
        if (!eper) eper = 1;
        if (++ssg->env_cnt >= (eper << 1)) {
            ssg->env_cnt = 0;
            if (!ssg->env_hold) {
                if (++ssg->env_step >= 16) {
                    ssg->env_step = 0;
                    if (!ssg->env_cont) {
                        ssg->env_hold = 1;
                        ssg->env_vol = 0;
                    } else if (ssg->env_hold) {
                        if (ssg->env_alt)
                            ssg->env_att ^= 1u;
                        ssg->env_vol = ssg->env_att ? 15 : 0;
                    } else if (ssg->env_alt) {
                        ssg->env_att ^= 1u;
                    }
                }
                if (!ssg->env_hold)
                    ssg->env_vol = ssg->env_att ? ssg->env_step : (u8)(15 - ssg->env_step);
            }
        }
    }

    u8 mix_reg = ssg->reg[7];
    s32 sum = 0;
    for (int i = 0; i < 3; i++) {
        int tone_dis  = (mix_reg >> i) & 1;
        int noise_dis = (mix_reg >> (i + 3)) & 1;
        int gate = (tone_dis || ssg->out_bit[i]) && (noise_dis || (ssg->lfsr & 1u));
        if (gate) {
            u8 vr = ssg->reg[8 + i];
            u8 v = (vr & 0x10u) ? ssg->env_vol : (vr & 0x0Fu);
            sum += ssg_vol_tab[v & 15u];
        }
    }
    return sum;
}

/* Advance ADPCM EOS state even when audio synthesis is disabled (-f benchmark mode) */
static void ym_silent_eos(u32 n_samples)
{
    for (u32 s = 0; s < n_samples; s++) {
        if (++S.ym.pa_div >= 3) {
            S.ym.pa_div = 0;
            for (int i = 0; i < 6; i++) {
                struct adpcm_a_ch *pa = &S.ym.pa[i];
                if (!pa->on)
                    continue;
                if ((pa->addr & 0xFFFFFFu) > (pa->end_addr & 0xFFFFFFu)) {
                    pa->on = 0;
                    S.ym.eos_raw |= (u8)(1u << i);
                } else if (pa->nibble_hi) {
                    pa->nibble_hi = 0;
                } else {
                    pa->nibble_hi = 1;
                    pa->addr = (pa->addr + 1u) & 0xFFFFFFu;
                }
            }
        }
        struct adpcm_b_ch *pb = &S.ym.pb;
        if (pb->on) {
            pb->phase += pb->delta_n;
            while (pb->phase >= 0x10000u) {
                pb->phase -= 0x10000u;
                if ((pb->addr & 0xFFFFFFu) > (pb->end_addr & 0xFFFFFFu)) {
                    if (pb->repeat) {
                        pb->addr = (u32)pb->start_raw << 8;
                        pb->nibble_hi = 1;
                    } else {
                        pb->on = 0;
                        S.ym.eos_raw |= 0x80u;
                        break;
                    }
                } else if (pb->nibble_hi) {
                    pb->nibble_hi = 0;
                } else {
                    pb->nibble_hi = 1;
                    pb->addr = (pb->addr + 1u) & 0xFFFFFFu;
                }
            }
        }
    }
}

static void ym_synth(u32 n_samples)
{
    if (!S.snd_rate) {
        ym_silent_eos(n_samples);
        return;
    }
    while (n_samples--) {
        u32 am = 0;
        s32 pm = 0;
        if (S.ym.lfo_on) {
            if (++S.ym.lfo_cnt >= opn_lfo_period[S.ym.lfo_freq]) {
                S.ym.lfo_cnt = 0;
                S.ym.lfo_step = (S.ym.lfo_step + 1u) & 127u;
            }
            am = S.ym.lfo_step < 64u ? (u32)S.ym.lfo_step * 2u : (u32)(127u - S.ym.lfo_step) * 2u;
            pm = opn_pm_wave[S.ym.lfo_step >> 2];
        }
        if (++S.ym.eg_div == 3) {
            S.ym.eg_div = 0;
            opn_eg_tick();
        }
        if (++S.ym.step_cnt >= YM_STEP) {
            S.ym.step_cnt = 0;
            s32 fm = 0;
            /* YM2610's 4 FM channels are ch[1], ch[2], ch[4], ch[5] */
            for (int ch = 0; ch < 6; ch++)
                if (S.ym.ch[ch].on)
                    fm += opn_ch_out(&S.ym.ch[ch], am, pm, YM_STEP);
            S.ym.fm_cached = fm;
        }
        if (++S.ym.pa_div >= 3) {
            S.ym.pa_div = 0;
            S.ym.pa_cached = adpcm_a_tick();
        }
        s32 pb = adpcm_b_sample();
        s32 ssg = ssg_sample();
        s32 mix = (S.ym.fm_cached >> 1) + S.ym.pa_cached * 2 + pb + ssg;

        /* Resample 55,555.56 Hz (500,000 / 9) -> S.snd_rate (e.g. 48,000 Hz) */
        S.snd_sum += mix;
        S.snd_n++;
        S.snd_acc += S.snd_rate * 9u;
        if (S.snd_acc >= 500000u) {
            S.snd_acc -= 500000u;
            s32 v = S.snd_n <= 1 ? S.snd_sum : S.snd_n == 2 ? (S.snd_sum >> 1) : (S.snd_sum / S.snd_n);
            S.snd_sum = S.snd_n = 0;
            S.snd_lp += ((v << 8) - S.snd_lp) >> 1;
            S.snd_hp += S.snd_lp - S.snd_lp_was - (S.snd_hp >> 8) - (S.snd_hp >> 9);
            S.snd_lp_was = S.snd_lp;
            v = S.snd_hp >> 8;
            if (v > 32767) v = 32767;
            else if (v < -32768) v = -32768;
            if (S.snd_head - S.snd_tail < SND_RING)
                M->snd_ring[S.snd_head++ & (SND_RING - 1u)] = (s16)v;
        }
    }
}

/* 1 YM2610 internal sample (8 MHz / 144 = 55.56 kHz) = 72 Z80 cycles (4 MHz) */
static void syn_to(u32 zcyc)
{
    for (u32 i = 0; i <= S.wlog_n; i++) {
        u32 t = i < S.wlog_n ? M->wlog[i].zcyc : zcyc;
        if (t > S.syn_zcyc) {
            u32 tot = (t - S.syn_zcyc) + S.syn_rem;
            S.syn_zcyc = t;
            u32 n = tot / 72u;
            S.syn_rem = tot % 72u;
            if (n)
                ym_synth(n);
        }
        if (i < S.wlog_n)
            ym_apply_reg(M->wlog[i].part, M->wlog[i].reg, M->wlog[i].val);
    }
    S.wlog_n = 0;
}

static void ym_write_logged(int part, u8 r, u8 v, u32 zcyc)
{
    /* Timer registers ($24..$27) & EOS/ADPCM control affect Z80 IRQ/status immediately */
    if (!S.snd_rate ||
        (part == 0 && (r == 0x24 || r == 0x25 || r == 0x26 || r == 0x27 || r == 0x1C || r == 0x10)) ||
        (part == 1 && r == 0x00)) {
        syn_to(zcyc);
        ym_apply_reg(part, r, v);
        return;
    }
    if (S.wlog_n == WLOG_MAX)
        syn_to(zcyc);
    M->wlog[S.wlog_n].zcyc = zcyc;
    M->wlog[S.wlog_n].part = (u8)part;
    M->wlog[S.wlog_n].reg  = r;
    M->wlog[S.wlog_n].val  = v;
    S.wlog_n++;
}

/* ---- Z80 Sound CPU (4 MHz) & NEO-ZMC banking ---- */

static const u8 *active_mrom(u32 *sz_out)
{
    if (S.crtfix && S.m_size) {
        *sz_out = S.m_size;
        return S.m_rom;
    }
    *sz_out = sizeof(M->sm1_rom);
    return M->sm1_rom;
}

static void z_map_banks(void)
{
    u32 msz = 0;
    u8 *mrom = (u8 *)active_mrom(&msz);
    for (int p = 0; p < 32; p++) {
        u32 off = (u32)p << 10;
        S.z.rd[p] = (off + 1024u <= msz) ? (mrom + off) : 0;
        S.z.wr[p] = 0;
    }
    static const u8 p0[4] = {32, 48, 56, 60};
    static const u8 pn[4] = {16,  8,  4,  2};
    for (int b = 0; b < 4; b++) {
        u32 base = msz ? (S.zbank[b] % msz) : 0;
        for (int i = 0; i < pn[b]; i++) {
            u32 off = base + ((u32)i << 10);
            S.z.rd[p0[b] + i] = (msz && off + 1024u <= msz) ? (mrom + off) : 0;
            S.z.wr[p0[b] + i] = 0;
        }
    }
    S.z.rd[62] = S.z.wr[62] = M->zram;
    S.z.rd[63] = S.z.wr[63] = M->zram + 0x400;
}

static u8 z_mem_rd(struct z80 *c, u16 a)
{
    (void)c;
    if (a >= 0xF800u)
        return M->zram[a & 0x7FFu];
    u32 msz = 0;
    const u8 *mrom = active_mrom(&msz);
    if (!msz)
        return 0xFF;
    u32 off;
    if (a < 0x8000u)      off = a;
    else if (a < 0xC000u) off = S.zbank[0] + (a & 0x3FFFu);
    else if (a < 0xE000u) off = S.zbank[1] + (a & 0x1FFFu);
    else if (a < 0xF000u) off = S.zbank[2] + (a & 0x0FFFu);
    else                  off = S.zbank[3] + (a & 0x07FFu);
    return mrom[off % msz];
}

static void z_mem_wr(struct z80 *c, u16 a, u8 v)
{
    (void)c;
    if (a >= 0xF800u)
        M->zram[a & 0x7FFu] = v;
}

static u8 z_port_in(struct z80 *c, u16 port)
{
    u32 zc = c->cycles > 0 ? (u32)c->cycles : 0u;
    switch (port & 0xFFu) {
    case 0x00:
        c->nmi = 0;
        return S.sound_code;
    case 0x04: {
        s32 dz = c->cycles - S.z_done_cyc;
        if (dz > 0) {
            ym_timers_step(dz);
            S.z_done_cyc = c->cycles;
        }
        u8 st = S.ym.status0;
        s32 loop = c->cycles - S.z_poll_at;
        if (c->pc.w == S.z_poll_pc && st == S.z_poll_st && loop > 0 && loop < 800) {
            /* Fast-forward tight YM2610 timer status polling loops cleanly */
            s32 next = S.z_target;
            if ((S.ym.mode & 5u) == 5u && !(st & 1u) && c->cycles + S.ym.ta_cnt < next)
                next = c->cycles + S.ym.ta_cnt;
            if ((S.ym.mode & 10u) == 10u && !(st & 2u) && c->cycles + S.ym.tb_cnt < next)
                next = c->cycles + S.ym.tb_cnt;
            if (next - loop > c->cycles)
                c->cycles = next - loop;
        }
        S.z_poll_pc = c->pc.w;
        S.z_poll_at = c->cycles;
        S.z_poll_st = st;
        return st;
    }
    case 0x05:
        return S.ym.addr_latch[0] < 16 ? S.ym.ssg.reg[S.ym.addr_latch[0]] : 0;
    case 0x06: {
        if (zc >= S.syn_zcyc + 72u || S.wlog_n)
            syn_to(zc);
        u8 eos = (u8)(S.ym.eos_raw & ~S.ym.eos_mask);
        s32 loop = c->cycles - S.z_poll_at;
        if (c->pc.w == S.z_poll_pc && eos == S.z_poll_st && loop > 0 && loop < 800) {
            s32 rem = S.z_target - c->cycles;
            if (rem > 576) rem = 576;
            if (rem > loop)
                c->cycles += rem - loop;
        }
        S.z_poll_pc = c->pc.w;
        S.z_poll_at = c->cycles;
        S.z_poll_st = eos;
        return eos;
    }
    case 0x07:
        return 0;
    case 0x08: S.zbank[3] = (u32)((port >> 8) & 0x7Fu) << 11; z_map_banks(); return 0;
    case 0x09: S.zbank[2] = (u32)((port >> 8) & 0x3Fu) << 12; z_map_banks(); return 0;
    case 0x0A: S.zbank[1] = (u32)((port >> 8) & 0x1Fu) << 13; z_map_banks(); return 0;
    case 0x0B: S.zbank[0] = (u32)((port >> 8) & 0x0Fu) << 14; z_map_banks(); return 0;
    default:
        return 0;
    }
}

static void z_port_out(struct z80 *c, u16 port, u8 v)
{
    u32 zc = c->cycles > 0 ? (u32)c->cycles : 0u;
    switch (port & 0xFFu) {
    case 0x00:
    case 0xC0:
        S.sound_code = 0;
        break;
    case 0x04:
        S.ym.addr_latch[0] = v;
        break;
    case 0x05: {
        s32 dz = c->cycles - S.z_done_cyc;
        if (dz > 0) {
            ym_timers_step(dz);
            S.z_done_cyc = c->cycles;
        }
        ym_write_logged(0, S.ym.addr_latch[0], v, zc);
        break;
    }
    case 0x06:
        S.ym.addr_latch[1] = v;
        break;
    case 0x07:
        ym_write_logged(1, S.ym.addr_latch[1], v, zc);
        break;
    case 0x08: case 0x09: case 0x0A: case 0x0B:
        S.z_nmi_en = 1;
        break;
    case 0x0C:
        S.sound_reply = v;
        break;
    case 0x18:
        S.z_nmi_en = 0;
        break;
    }
}

static int z_ram_idle(struct z80 *c)
{
    if (c->nmi || (c->irq && c->iff1))
        return 0;
    u16 pc = c->pc.w;
    const u8 *pg = c->rd[pc >> 10];
    if (!pg || (pc & 0x3FFu) > 0x3F0u)
        return 0;
    const u8 *p = pg + (pc & 0x3FFu);
    /* Pattern A: LD A,($F8xx); CP imm; JP Z,exit; JP pc (NeoBitz M1) or JR Z/NZ,pc */
    if (p[0] == 0x3Au && p[2] >= 0xF8u && p[3] == 0xFEu) {
        u8 val = M->zram[(((u32)p[2] << 8) | p[1]) & 0x7FFu];
        u8 imm = p[4];
        if (p[5] == 0xCAu && p[8] == 0xC3u && ((u16)p[9] | ((u16)p[10] << 8)) == pc && val != imm)
            return 1;
        if (p[5] == 0x20u && (u16)(pc + 7u + (u16)(s16)(s8)p[6]) == pc && val != imm)
            return 1;
        if (p[5] == 0x28u && (u16)(pc + 7u + (u16)(s16)(s8)p[6]) == pc && val == imm)
            return 1;
    }
    /* Pattern B: [EI;] LD A,($F8xx); LD B,A; LD A,($F8yy); CP B; JR Z,pc (SNK / Makoto M1) */
    u32 ei = (p[0] == 0xFBu) ? 1u : 0u;
    const u8 *q = p + ei;
    if (q[0] == 0x3Au && q[2] >= 0xF8u && q[3] == 0x47u &&
        q[4] == 0x3Au && q[6] >= 0xF8u && q[7] == 0xB8u && q[8] == 0x28u) {
        u16 dest = (u16)(pc + ei + 10u + (u16)(s16)(s8)q[9]);
        if (dest == pc) {
            u8 v1 = M->zram[(((u32)q[2] << 8) | q[1]) & 0x7FFu];
            u8 v2 = M->zram[(((u32)q[6] << 8) | q[5]) & 0x7FFu];
            if (v1 == v2) {
                if (ei)
                    c->iff1 = c->iff2 = 1, c->ei_block = 0;
                return 1;
            }
        }
    }
    return 0;
}

static void z80_catch_up(void)
{
    s32 target = m.clock > 0 ? (m.clock / 3) : 0;
    S.z_target = target;
    while (S.z.cycles < target) {
        s32 step_to = target;
        if ((S.ym.mode & 5u) == 5u && S.ym.ta_cnt > 0 && S.z.cycles + S.ym.ta_cnt < step_to)
            step_to = S.z.cycles + S.ym.ta_cnt;
        if ((S.ym.mode & 10u) == 10u && S.ym.tb_cnt > 0 && S.z.cycles + S.ym.tb_cnt < step_to)
            step_to = S.z.cycles + S.ym.tb_cnt;
        if (step_to <= S.z.cycles)
            step_to = S.z.cycles + 1;
        /* Step a couple of instructions if needed so Z80 lands cleanly on its idle-loop head */
        for (int k = 0; k < 6 && S.z.cycles < step_to; k++) {
            if (z_ram_idle(&S.z)) {
                S.z.cycles = step_to;
                break;
            }
            s32 mini = S.z.cycles + 16;
            if (mini > step_to)
                mini = step_to;
            z80_run(&S.z, mini);
        }
        if (S.z.cycles < step_to) {
            if (z_ram_idle(&S.z))
                S.z.cycles = step_to;
            else
                z80_run(&S.z, step_to);
        }
        s32 dz = S.z.cycles - S.z_done_cyc;
        if (dz > 0) {
            ym_timers_step(dz);
            S.z_done_cyc = S.z.cycles;
        }
    }
}

static void z80_send_sound(u8 code)
{
    z80_catch_up();
    S.sound_code = code;
    if (S.z_nmi_en)
        S.z.nmi = 1;
}

/* ---- 68000 Bus & Special Cartridge Protection ---- */

static void pvc_unpack(void)
{
    u8 b0 = M->cartram[0x1FE0], b1 = M->cartram[0x1FE1];
    M->cartram[0x1FE5] = b1 >> 7;
    M->cartram[0x1FE4] = (u8)(((b1 & 0x40u) >> 6) | ((b1 & 0x0Fu) << 1));
    M->cartram[0x1FE3] = (u8)(((b1 & 0x20u) >> 5) | ((b0 & 0xF0u) >> 3));
    M->cartram[0x1FE2] = (u8)(((b1 & 0x10u) >> 4) | ((b0 & 0x0Fu) << 1));
}

static void pvc_pack(void)
{
    u8 d = M->cartram[0x1FEB] & 1u;
    u8 r = M->cartram[0x1FEA] & 0x1Fu;
    u8 g = M->cartram[0x1FE9] & 0x1Fu;
    u8 b = M->cartram[0x1FE8] & 0x1Fu;
    M->cartram[0x1FEC] = (u8)((b >> 1) | ((g & 0x1Eu) << 3));
    M->cartram[0x1FED] = (u8)((r >> 1) | ((b & 1u) << 4) | ((g & 1u) << 5) | ((r & 1u) << 6) | (d << 7));
}

static void pvc_bankswap(void)
{
    u32 ba = ((u32)M->cartram[0x1FF3] << 16) | ((u32)M->cartram[0x1FF2] << 8) | M->cartram[0x1FF1];
    M->cartram[0x1FF0] = 0xA0;
    M->cartram[0x1FF1] &= 0xFEu;
    M->cartram[0x1FF3] &= 0x7Fu;
    S.p2_offset = (ba + 0x100000u) & 0xFFFFFFu;
    if (S.p_size)
        S.p2_offset %= S.p_size;
}

static u8 p_read_byte(u32 off)
{
    if (!S.p_size)
        return 0xFF;
    off %= S.p_size;
    return S.p_rom[off ^ 1u];
}

static u16 p_read_word(u32 off)
{
    if (!S.p_size)
        return 0xFFFF;
    off = (off & ~1u) % S.p_size;
    if (off + 2u <= S.p_size)
        return *(const u16 *)(S.p_rom + off);
    return 0xFFFF;
}

static u32 io_read(u32 a, int size)
{
    if (a < 0x100000u) {
        return size == 1 ? p_read_byte(a) : p_read_word(a);
    }
    if (a >= 0x200000u && a < 0x300000u) {
        if (S.board == 1 && a >= 0x2FE000u) { /* NEO-PVC */
            u32 ca = a & 0x1FFFu;
            if (size == 1)
                return M->cartram[ca ^ 1u];
            return ((u32)M->cartram[ca + 1u] << 8) | M->cartram[ca];
        }
        if (S.board == 2) {                   /* PRO-CT0 */
            u8 ret = (u8)(S.prot_reg >> 24);
            u32 ea = a & ~1u;
            if (ea == 0x200000u || ea == 0x236000u || ea == 0x236008u ||
                ea == 0x255550u || ea == 0x2FF000u || ea == 0x2FFFF0u)
                return ret;
            if (ea == 0x236004u || ea == 0x23600Cu)
                return (u32)(((ret & 0x0Fu) << 4) | (ret >> 4));
        }
        if (S.board == 3 && (a & ~1u) == 0x200000u) {
            if (a == 0x200000u) {
                S.cart_reg0 ^= 0x08u;
                return size == 2 ? ((u32)S.cart_reg0 << 8) : S.cart_reg0;
            }
            return 0;
        }
        u32 off = S.p2_offset + (a & 0xFFFFFu);
        return size == 1 ? p_read_byte(off) : p_read_word(off);
    }
    if (a >= 0x300000u && a < 0x400000u) {
        if (a < 0x320000u) {
            if ((a & 0x80u) != 0) {     /* $300080/$300081 REG_SYSTYPE */
                u8 st = (S.pads[0] & NEO_PAD_TEST) ? 0x3Fu : 0xBFu;
                return size == 2 ? ((u32)st << 8) | st : st;
            }
            u8 p1 = p1_cnt_byte(0);
            u8 dip = 0xFFu;             /* Active-low hardware DIPs: all off */
            if (size == 2)
                return ((u32)p1 << 8) | dip;
            return (a & 1u) ? dip : p1;
        }
        if (a < 0x340000u) {            /* $320000 REG_SOUND / $320001 REG_STATUS_A */
            z80_catch_up();
            u8 sr = S.sound_reply;
            u8 sa = 0x3Fu;
            if (S.pads[0] & NEO_PAD_COIN) sa &= ~0x01u;
            if (S.pads[1] & NEO_PAD_COIN) sa &= ~0x02u;
            if (size == 2)
                return ((u32)sr << 8) | sa;
            return (a & 1u) ? sa : sr;
        }
        if (a < 0x380000u) {            /* $340000 REG_P2CNT */
            u8 p2 = p1_cnt_byte(1);
            if (size == 2)
                return ((u32)p2 << 8) | 0xFFu;
            return (a & 1u) ? 0xFFu : p2;
        }
        if (a < 0x3C0000u) {            /* $380000 REG_STATUS_B */
            u8 sb = status_b_byte();
            if (size == 2)
                return ((u32)sb << 8) | 0xFFu;
            return (a & 1u) ? 0xFFu : sb;
        }
        /* $3C0000..$3DFFFF LSPC2 read */
        u16 w = 0;
        switch (a & 0x0Eu) {
        case 0x00: case 0x02: case 0x08: case 0x0A:
            w = S.vram_addr < 0x8800u ? M->vram[S.vram_addr] : 0;
            break;
        case 0x04: case 0x0C:
            w = (u16)S.vram_mod;
            break;
        case 0x06: case 0x0E:
            w = (u16)((((S.scanline + 0xF8u) & 0x1FFu) << 7) | (S.aa_counter & 7u));
            break;
        }
        if (size == 2)
            return w;
        return (a & 1u) ? (w & 0xFFu) : (w >> 8);
    }
    if (a >= 0x400000u && a < 0x800000u) {
        u32 idx = ((a >> 1) & 0x0FFFu) + ((u32)S.pal_bank << 12);
        u16 w = M->palram[idx];
        return size == 2 ? w : ((a & 1u) ? (w & 0xFFu) : (w >> 8));
    }
    if (a >= 0x800000u && a < 0xC00000u) {
        u8 cb = M->memcard[(a >> 1) & 0x7FFu];
        if (size == 2)
            return 0xFF00u | cb;
        return (a & 1u) ? cb : 0xFFu;
    }
    return size == 2 ? 0xFFFFu : 0xFFu;
}

static void io_write(u32 a, u32 v, int size)
{
    if (a < 0x100000u)
        return;

    if (a >= 0x200000u && a < 0x300000u) {
        if (S.board == 1 && a >= 0x2FE000u) { /* NEO-PVC */
            u32 ca = a & 0x1FFFu;
            if (size == 1) {
                M->cartram[ca ^ 1u] = (u8)v;
            } else {
                M->cartram[ca] = (u8)v;
                M->cartram[ca + 1u] = (u8)(v >> 8);
            }
            u32 ea = a & ~1u;
            if (ea == 0x2FFFE0u) pvc_unpack();
            else if (ea >= 0x2FFFE8u && ea <= 0x2FFFEAu) pvc_pack();
            else if (ea >= 0x2FFFF0u && ea <= 0x2FFFF2u) pvc_bankswap();
            return;
        }
        if (S.board == 2) {                   /* PRO-CT0 */
            if (size == 2) {
                switch (a) {
                case 0x211112u: S.prot_reg = 0xFF000000u; return;
                case 0x233332u: S.prot_reg = 0x0000FFFFu; return;
                case 0x242812u: S.prot_reg = 0x81422418u; return;
                case 0x244442u: S.prot_reg = 0x00FF0000u; return;
                case 0x255552u: S.prot_reg = 0xFF00FF00u; return;
                case 0x256782u: S.prot_reg = 0xF05A3601u; return;
                }
            } else if (a == 0x236001u || a == 0x236005u || a == 0x236009u || a == 0x23600Du ||
                       a == 0x255551u || a == 0x2FF001u || a == 0x2FFFF1u) {
                S.prot_reg <<= 8;
                return;
            }
        }
        if (a >= 0x2FFFF0u && S.p_size > 0x100000u) {
            u32 bank = v & S.p_bank_mask;
            S.p2_offset = (bank + 1u) << 20;
            if (S.p2_offset >= S.p_size)
                S.p2_offset %= S.p_size;
            update_p2_rmap();
        }
        return;
    }

    if (a >= 0x300000u && a < 0x400000u) {
        if (S.use_hle_bios && a == HLE_TRAP_PORT) {
            hle_trap((u16)v);
            return;
        }
        if (a < 0x320000u) {
            if ((a & 1u) || size == 2)
                S.watchdog_frames = 0;
            return;
        }
        if (a < 0x340000u) {
            if ((a & ~1u) == 0x320000u && !(a & 1u)) {
                u8 code = size == 2 ? (u8)(v >> 8) : (u8)v;
                z80_send_sound(code);
            }
            return;
        }
        if (a >= 0x380000u && a < 0x3A0000u) {
            if (a == 0x380001u || a == 0x380021u)
                S.poutput = (u8)v;
            return;
        }
        if (a >= 0x3A0000u && a < 0x3C0000u) {
            switch (a & 0x1Eu) {
            case 0x00: S.shadow = 0; break;
            case 0x02: S.vectable = 0; sync_page0_vectors(); break;
            case 0x04: S.crd_lock1 = 0; break;
            case 0x06: S.crd_lock2 = 1; break;
            case 0x0A: S.crtfix = 0; z_map_banks(); break;
            case 0x0C: S.sram_lock = 1; break;
            case 0x0E: S.pal_bank = 1; break;
            case 0x10: S.shadow = 1; break;
            case 0x12: S.vectable = 1; sync_page0_vectors(); break;
            case 0x14: S.crd_lock1 = 1; break;
            case 0x16: S.crd_lock2 = 0; break;
            case 0x1A: S.crtfix = 1; z_map_banks(); break;
            case 0x1C: S.sram_lock = 0; break;
            case 0x1E: S.pal_bank = 0; break;
            }
            return;
        }
        if (a >= 0x3C0000u && a < 0x3E0000u) {
            if (size == 1 && (a & 1u))
                return;                 /* Odd byte writes to LSPC2 are ignored on hardware */
            u16 w = size == 2 ? (u16)v : (u16)((v << 8) | (v & 0xFFu));
            switch (a & 0x0Eu) {
            case 0x00:
                S.vram_addr = w;
                S.vram_bank = w & 0x8000u;
                break;
            case 0x02:
                if (S.vram_addr < 0x8800u) {
                    if (S.vram_addr >= 0x8200u && S.vram_addr < 0x8400u && M->vram[S.vram_addr] != w)
                        S.scb_dirty = 1;
                    M->vram[S.vram_addr] = w;
                }
                S.vram_addr = (u16)(((S.vram_addr + (u16)S.vram_mod) & 0x7FFFu) | S.vram_bank);
                break;
            case 0x04:
                S.vram_mod = (s16)w;
                break;
            case 0x06: {
                S.aa_reload = (u8)(w >> 8);
                S.aa_disable = (w >> 3) & 1u;
                u8 prev = S.irq2_ctrl;
                S.irq2_ctrl = (u8)(w & 0xF0u);
                if (!(prev & TMR_RELOAD_VBL) && (S.irq2_ctrl & TMR_RELOAD_VBL) && S.scanline >= LINE_ACTIVE_END)
                    S.irq2_counter = S.irq2_reload;
                break;
            }
            case 0x08:
                S.irq2_reload = (S.irq2_reload & 0x0000FFFFu) | ((u32)w << 16);
                break;
            case 0x0A:
                S.irq2_reload = (S.irq2_reload & 0xFFFF0000u) | w;
                if (S.irq2_ctrl & TMR_RELOAD_WRITE)
                    S.irq2_counter = S.irq2_reload;
                break;
            case 0x0C:
                if (w & 4u) S.irq_pending &= ~1u;
                if (w & 2u) S.irq_pending &= ~2u;
                if (w & 1u) S.irq_pending &= ~4u;
                irq_refresh();
                break;
            case 0x0E:
                break;
            }
            return;
        }
        return;
    }

    if (a >= 0x400000u && a < 0x800000u) {
        u32 idx = ((a >> 1) & 0x0FFFu) + ((u32)S.pal_bank << 12);
        if (size == 2) {
            M->palram[idx] = (u16)v;
        } else if (a & 1u) {
            M->palram[idx] = (u16)((M->palram[idx] & 0xFF00u) | (v & 0xFFu));
        } else {
            M->palram[idx] = (u16)((M->palram[idx] & 0x00FFu) | ((v & 0xFFu) << 8));
        }
        pal_update_entry(idx);
        return;
    }

    if (a >= 0x800000u && a < 0xC00000u) {
        if (!S.crd_lock1 && !S.crd_lock2) {
            if (size == 2 || (a & 1u))
                M->memcard[(a >> 1) & 0x7FFu] = (u8)v;
        }
        return;
    }

    if (a >= 0xD00000u && a < 0xE00000u) {
        if (!S.sram_lock) {
            u32 na = a & 0xFFFFu;
            if (size == 2) {
                *(u16 *)(M->nvram + (na & ~1u)) = (u16)v;
            } else {
                M->nvram[na ^ 1u] = (u8)v;
            }
            S.nvram_dirty = 1;
        }
    }
}

static void cpu_reset_line(void)
{
    z80_reset(&S.z);
    S.z_nmi_en = 0;
}

/* Safe 68000 busy-wait loop fast-forward up to the next scanline / IRQ2 event */
static s32 slice_end_cyc;

static void idle_branch(u32 at)
{
    if (m.pending || m.clock >= slice_end_cyc)
        return;
    u32 t = m.pc;
    if (t == at) {                          /* BRA.S / BRA.W to self */
        m.clock = slice_end_cyc;
        return;
    }
    if (t > at || at - t > 10u || (t & 1u))
        return;
    const u8 *p = rmap[(t >> 16) & 0xFFu];
    if (!p || ((t + 10u) >> 16) != (t >> 16))
        return;
    u32 op = *(const u16 *)(p + (t & 0xFFFFu)), len, a;
    if ((op & 0xFF00u) == 0x4A00u && (op & 0xC0u) != 0xC0u)
        len = 2;                            /* TST */
    else if ((op & 0xFF00u) == 0x0C00u && (op & 0xC0u) != 0xC0u)
        len = (op & 0xC0u) == 0x80u ? 6u : 4u; /* CMPI */
    else if ((op & 0xFFC0u) == 0x0800u)
        len = 4;                            /* BTST #n */
    else
        return;
    u32 mode = (op >> 3) & 7u, r = op & 7u;
    const u16 *w = (const u16 *)(p + ((t + len) & 0xFFFFu));
    if (mode == 2u) {
        a = m.r[8u + r];
    } else if (mode == 5u) {
        a = m.r[8u + r] + (u32)(s32)(s16)w[0];
        len += 2u;
    } else if (mode == 7u && r < 2u) {
        a = r ? ((u32)w[0] << 16 | w[1]) : (u32)(s32)(s16)w[0];
        len += r ? 4u : 2u;
    } else {
        return;
    }
    if (t + len != at || (a & 0xF00000u) != 0x100000u)
        return;
    m.clock = slice_end_cyc;
}

/* ---- LSPC2 Sprite-Strip & Fix-Layer Scanline Renderer ---- */

INLINE u32 decode_c_half(const u8 *c, u32 base, const u32 *lut)
{
    return lut[c[base + 0]] |
          (lut[c[base + 2]] << 1) |
          (lut[c[base + 1]] << 2) |
          (lut[c[base + 3]] << 3);
}

static void rebuild_active_spr(void)
{
    const u16 *vram = M->vram;
    u16 n = 0;
    u32 head_sz = 0;
    for (u32 i = 1; i < 382; i++) {
        u16 scb3 = vram[0x8200u + i];
        if (!(scb3 & 0x0040u))
            head_sz = scb3 & 0x3Fu;
        if (head_sz)
            M->active_spr[n++] = (u16)i;
    }
    S.n_active_spr = n;
    S.scb_dirty = 0;
}

static void lspc_sprcalc(u32 buf_line)
{
    u16 *lb = M->linebuf[S.lb_active];
    if (S.c_size < 128u) {
        S.lb_active ^= 1u;
        return;
    }
    if (S.scb_dirty)
        rebuild_active_spr();
    if (!S.n_active_spr) {
        S.lb_active ^= 1u;
        return;
    }

    u32 sprcount = 0;
    u32 xpos = 0, ypos = 0, sprsize = 0;
    u32 hshrink = 0x0Fu, vshrink = 0xFFu;
    const u16 *vram = M->vram;
    const u8 *crom = S.c_rom;
    u32 csz = S.c_size;
    u32 cmask = S.c_tile_mask;
    u32 pal_bank_off = (u32)S.pal_bank << 12;
    u32 n_act = S.n_active_spr;

    for (u32 idx = 0; idx < n_act; idx++) {
        u32 i = M->active_spr[idx];
        u16 scb3 = vram[0x8200u + i];
        if (scb3 & 0x0040u) {
            xpos = (xpos + hshrink + 1u) & 0x1FFu;
        } else {
            xpos    = (vram[0x8400u + i] >> 7) & 0x1FFu;
            ypos    = (scb3 >> 7) & 0x1FFu;
            sprsize = scb3 & 0x3Fu;
            vshrink = vram[0x8000u + i] & 0xFFu;
        }
        hshrink = (vram[0x8000u + i] >> 8) & 0x0Fu;

        if (!sprsize)
            continue;
        u32 srow = (buf_line - (0x200u - ypos)) & 0x1FFu;
        if (srow >= (sprsize << 4))
            continue;

        if (sprcount++ >= SPR_LIMIT)
            break;

        u32 invert = srow > 0xFFu;
        u32 zrow = srow & 0xFFu;
        if (invert)
            zrow ^= 0xFFu;
        if (sprsize == 33u) {
            u32 mod = (vshrink + 1u) << 1;
            zrow %= mod;
            if (zrow > vshrink) {
                zrow = mod - 1u - zrow;
                invert ^= 1u;
            }
        }
        srow = M->lo_lut[vshrink][zrow];
        if (invert)
            srow ^= 0x1FFu;

        u32 tmap = (i << 6) + ((srow >> 3) & 0x3Eu);
        u16 w0 = vram[tmap];
        u16 w1 = vram[tmap + 1u];
        u32 tnum = ((u32)w0 | (((u32)w1 & 0x00F0u) << 12)) & cmask;
        if (!S.aa_disable && (w1 & 0x000Cu)) {
            if (w1 & 0x0008u)
                tnum = (tnum & ~7u) | (S.aa_counter & 7u);
            else
                tnum = (tnum & ~3u) | (S.aa_counter & 3u);
        }

        u32 toff = tnum << 7;
        if (toff + 128u > csz)
            toff %= (csz & ~127u);

        u32 y = (w1 & 0x0002u) ? (15u - (srow & 15u)) : (srow & 15u);
        u32 poff = (((u32)w1 >> 4) & 0x0FF0u) + pal_bank_off;

        u32 left8, right8;
        if (w1 & 0x0001u) {             /* H-flip */
            left8  = decode_c_half(crom, toff + (y << 2), M->c_lut_flip);
            right8 = decode_c_half(crom, toff + 64u + (y << 2), M->c_lut_flip);
        } else {
            left8  = decode_c_half(crom, toff + 64u + (y << 2), M->c_lut);
            right8 = decode_c_half(crom, toff + (y << 2), M->c_lut);
        }

        if (!(left8 | right8))
            continue;

        if (hshrink == 0x0Fu) {
            if (left8) {
                u32 v = left8;
                for (u32 p = 0; p < 8; p++, v >>= 4) {
                    u32 px = v & 0x0Fu;
                    if (px) {
                        u32 xc = (xpos + p) & 0x1FFu;
                        if (xc < NEO_W)
                            lb[xc] = (u16)(poff + px);
                    }
                }
            }
            if (right8) {
                u32 v = right8;
                for (u32 p = 8; p < 16; p++, v >>= 4) {
                    u32 px = v & 0x0Fu;
                    if (px) {
                        u32 xc = (xpos + p) & 0x1FFu;
                        if (xc < NEO_W)
                            lb[xc] = (u16)(poff + px);
                    }
                }
            }
        } else {
            u16 hmask = lut_hshrink16[hshrink];
            u32 drawpos = 0;
            for (u32 p = 0; p < 16; p++) {
                if ((hmask >> p) & 1u) {
                    u32 px = ((p < 8u ? left8 : right8) >> ((p & 7u) << 2)) & 0x0Fu;
                    u32 xc = (xpos + drawpos) & 0x1FFu;
                    if (px && xc < NEO_W)
                        lb[xc] = (u16)(poff + px);
                    drawpos++;
                }
            }
        }
    }

    S.lb_active ^= 1u;
}

static void lspc_render_fix(u32 active_line, u16 *dst, const u16 *pal)
{
    const u8 *fix = (S.crtfix && S.s_size >= 32u) ? S.s_rom : M->sfix_rom;
    u32 fix_sz = (S.crtfix && S.s_size >= 32u) ? S.s_size : sizeof(M->sfix_rom);
    u32 trow = active_line >> 3;
    u32 row  = active_line & 7u;
    u32 pal_bank_off = (u32)S.pal_bank << 12;
    const u16 *vram = M->vram;

    u32 line_bank_off = 0;
    if (S.crtfix && S.fix_banksw == 1) {
        u32 offsets[34];
        u32 bank = 0, k = 0, y = 0;
        while (y < 32) {
            if (vram[0x7500u + k] == 0x0200u && (vram[0x7580u + k] & 0xFF00u) == 0xFF00u) {
                bank = (~(u32)vram[0x7580u + k] & 3u) << 12;
                offsets[y++] = bank;
            }
            offsets[y++] = bank;
            k += 2;
        }
        line_bank_off = offsets[(trow - 2u) & 31u];
    }

    for (u32 x = 0; x < 40; x++) {
        u16 entry = vram[0x7000u + trow + (x << 5)];
        u32 tnum = entry & 0x0FFFu;
        if (S.crtfix) {
            if (S.fix_banksw == 1) {
                tnum += line_bank_off;
            } else if (S.fix_banksw == 2) {
                u32 shift = (5u - (x % 6u)) * 2u;
                u32 b = (~((u32)vram[0x7500u + ((trow - 1u) & 31u) + 32u * (x / 6u)] >> shift)) & 3u;
                tnum += b << 12;
            }
        }
        u32 toff = tnum << 5;
        if (toff + 32u > fix_sz)
            toff %= (fix_sz & ~31u);
        const u8 *td = fix + toff + row;

        /* Quick zero check on all 4 column bytes of this 8-pixel row! */
        u8 b0 = td[0x10], b1 = td[0x18], b2 = td[0x00], b3 = td[0x08];
        if (!(b0 | b1 | b2 | b3))
            continue;

        u32 poff = (((u32)entry >> 8) & 0xF0u) + pal_bank_off;
        u16 *out = dst + (x << 3);
        if (b0) {
            if (b0 & 0x0Fu) out[0] = pal[poff + (b0 & 0x0Fu)];
            if (b0 >> 4)    out[1] = pal[poff + (b0 >> 4)];
        }
        if (b1) {
            if (b1 & 0x0Fu) out[2] = pal[poff + (b1 & 0x0Fu)];
            if (b1 >> 4)    out[3] = pal[poff + (b1 >> 4)];
        }
        if (b2) {
            if (b2 & 0x0Fu) out[4] = pal[poff + (b2 & 0x0Fu)];
            if (b2 >> 4)    out[5] = pal[poff + (b2 >> 4)];
        }
        if (b3) {
            if (b3 & 0x0Fu) out[6] = pal[poff + (b3 & 0x0Fu)];
            if (b3 >> 4)    out[7] = pal[poff + (b3 >> 4)];
        }
    }
}

static void lspc_do_scanline(u32 sl)
{
    if (sl >= LINE_ACTIVE_START && sl < LINE_ACTIVE_END) {
        u16 *lb = M->linebuf[S.lb_active];
        if (S.pic && sl >= VIS_LINE_START && sl < VIS_LINE_END) {
            const u16 *pal = M->pal15[S.shadow & 1u];
            u16 bd = pal[((u32)S.pal_bank << 12) + 4095u];
            u16 *dst = S.pic + (sl - VIS_LINE_START) * NEO_W;
            for (u32 x = 0; x < NEO_W; x++) {
                u16 idx = lb[x];
                dst[x] = idx ? pal[idx] : bd;
                lb[x] = 0;
            }
            lspc_sprcalc(sl - LINE_BUFSTART);
            lspc_render_fix(sl - LINE_ACTIVE_START, dst, pal);
        } else {
            for (u32 x = 0; x < NEO_W; x++)
                lb[x] = 0;
            if (S.pic)
                lspc_sprcalc(sl - LINE_BUFSTART);
            else
                S.lb_active ^= 1u;
        }
    } else if (sl == LINE_BUFSTART || sl == LINE_BUFSTART + 1u) {
        u16 *lb = M->linebuf[S.lb_active];
        for (u32 x = 0; x < NEO_W; x++)
            lb[x] = 0;
        if (S.pic)
            lspc_sprcalc(sl - LINE_BUFSTART);
        else
            S.lb_active ^= 1u;
    }
}

/* Run 68000 for `cycs` cycles while accurately ticking LSPC2 6 MHz IRQ2 timer */
static void run_m68k_segment(s32 target_clock)
{
    while (m.clock < target_clock) {
        s32 rem = target_clock - m.clock;
        s32 step = rem;
        /* If IRQ2 timer is enabled or reloads on 0, step right up to its expiration if within this segment! */
        if ((S.irq2_ctrl & (TMR_IRQ_EN | TMR_RELOAD_ZERO)) && S.irq2_counter > 0 && S.irq2_counter < 0x100000u) {
            s32 due_m68k = (s32)(S.irq2_counter * 2u) - (s32)S.irq2_rem;
            if (due_m68k < 2)
                due_m68k = 2;
            if (due_m68k < step)
                step = due_m68k;
        }
        slice_end_cyc = m.clock + step;
        s32 before = m.clock;
        cpu_run(slice_end_cyc);
        u32 ran = (u32)(m.clock - before);

        u32 px_tot = ran + S.irq2_rem;
        u32 px_dec = px_tot >> 1;
        S.irq2_rem = px_tot & 1u;

        if (S.irq2_counter > px_dec) {
            S.irq2_counter -= px_dec;
        } else if (px_dec) {
            for (u32 i = 0; i < px_dec; i++) {
                if (--S.irq2_counter == 0) {
                    if (S.irq2_ctrl & TMR_RELOAD_ZERO)
                        S.irq2_counter = S.irq2_reload;
                    if (S.irq2_ctrl & TMR_IRQ_EN) {
                        S.irq_pending |= 2u;
                        irq_refresh();
                    }
                }
            }
        }
    }
}

/* ---- Public API ---- */

static u32 calc_pow2_mask(u32 val)
{
    if (val <= 1u)
        return 0u;
    u32 v = val - 1u;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return v;
}

static u32 le32(const u8 *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static char *put_str(char *d, const char *s)
{
    while (*s)
        *d++ = *s++;
    *d = 0;
    return d;
}

static char *put_u32(char *d, u32 v)
{
    char tmp[12];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    } while (v);
    while (n--)
        *d++ = tmp[n];
    *d = 0;
    return d;
}

void neo_set_bios(const u8 *rom, u32 size)
{
    build_static_tables();
    if (!rom || size < 0x10000u) {
        S.has_ext_bios = 0;
        return;
    }
    u32 n = size > 0x20000u ? 0x20000u : size;
    for (u32 i = 0; i < 0x20000u; i++)
        M->ext_bios[i] = rom[i % n];
    /* Auto-detect big-endian BIOS (00 10 F3 00) vs MAME .sp1 swapped (10 00 00 F3) */
    if (M->ext_bios[0] == 0x00 && (M->ext_bios[1] == 0x10 || M->ext_bios[1] == 0x11)) {
        for (u32 i = 0; i + 1u < 0x20000u; i += 2) {
            u8 t = M->ext_bios[i];
            M->ext_bios[i] = M->ext_bios[i + 1u];
            M->ext_bios[i + 1u] = t;
        }
    }
    S.has_ext_bios = 1;
}

void neo_reset(void)
{
    build_static_tables();

    if (S.has_ext_bios) {
        for (u32 i = 0; i < 0x20000u; i++)
            M->bios[i] = M->ext_bios[i];
        S.use_hle_bios = 0;
    } else {
        build_hle_bios();
        S.use_hle_bios = 1;
    }

    for (u32 i = 0; i < 0x10000u; i++)
        M->wram[i] = 0;
    for (u32 i = 0; i < 0x8800u; i++)
        M->vram[i] = 0;
    for (u32 i = 0; i < 0x2000u; i++) {
        M->palram[i] = 0;
        M->pal15[0][i] = M->pal15[1][i] = 0;
    }
    for (u32 i = 0; i < 2u; i++)
        for (u32 x = 0; x < NEO_W; x++)
            M->linebuf[i][x] = 0;
    for (u32 i = 0; i < 0x800u; i++)
        M->zram[i] = 0;

    /* Pre-format memory card header if blank */
    if (M->memcard[0] != 0x80u) {
        for (u32 i = 0; i < 0x800u; i++)
            M->memcard[i] = 0;
        M->memcard[0] = 0x80;
    }

    /* Bare-metal cart check: if cart has no "NEO-GEO" header and its reset PC < $100000, boot cart directly */
    int has_ng_hdr = S.p_size >= 0x108u &&
                     *(const u16 *)(S.p_rom + 0x100) == 0x4E45u &&
                     *(const u16 *)(S.p_rom + 0x102) == 0x4F2Du;
    u32 cart_pc = S.p_size >= 8u ? (((u32)*(const u16 *)(S.p_rom + 4) << 16) | *(const u16 *)(S.p_rom + 6)) : 0x00C00402u;
    int bare_metal = !has_ng_hdr && cart_pc < 0x100000u && cart_pc >= 0x80u;

    S.vectable = bare_metal ? 1 : 0;
    S.crtfix   = (bare_metal || S.use_hle_bios) ? 1 : 0;
    S.pal_bank = 0;
    S.shadow   = 0;
    S.sram_lock = 0;
    S.crd_lock1 = S.crd_lock2 = 0;
    S.vram_addr = S.vram_bank = 0;
    S.vram_mod  = 1;
    S.aa_counter = S.aa_reload = S.aa_timer = S.aa_disable = 0;
    S.lb_active = 0;
    S.scb_dirty = 1;
    S.n_active_spr = 0;
    S.scanline  = 0;
    S.irq_pending = S.has_ext_bios ? 4u : 0u; /* Real BIOS expects cold-reset IRQ3 pending */
    S.irq2_ctrl = 0;
    S.irq2_reload = S.irq2_counter = S.irq2_rem = 0;
    S.watchdog_frames = 0;
    S.p2_offset = S.p_size > 0x100000u ? 0x100000u : 0u;
    S.prot_reg = 0;
    S.cart_reg0 = 0;

    /* Populate page0 ($000000..$00FFFF) and tail page, then set 68000 rmap/wmap */
    for (u32 i = 0; i < 0x10000u; i++) {
        M->page0[i]  = S.p_size ? S.p_rom[i % S.p_size] : 0xFFu;
        u32 tail_base = S.p_size & ~0xFFFFu;
        M->p_tail[i] = (tail_base + i < S.p_size) ? S.p_rom[tail_base + i] : 0xFFu;
    }
    sync_page0_vectors();

    for (int i = 0; i < 256; i++)
        rmap[i] = wmap[i] = 0;
    rmap[0] = M->page0;
    for (int i = 1; i < 16; i++) {
        u32 off = ((u32)i << 16) % (S.p_size ? S.p_size : 0x10000u);
        rmap[i] = (off + 0x10000u <= S.p_size) ? (S.p_rom + off) : M->p_tail;
    }
    for (int i = 0x10; i < 0x20; i++)
        rmap[i] = wmap[i] = M->wram;
    update_p2_rmap();
    for (int i = 0xC0; i < 0xD0; i++)
        rmap[i] = M->bios + ((i & 1) << 16);
    for (int i = 0xD0; i < 0xE0; i++)
        rmap[i] = M->nvram;

    /* Reset 68000 */
    cpu_reset();
    m.clock = 0;
    irq_refresh();

    /* Reset Z80 & YM2610 */
    z80_init(&S.z);
    S.z.read  = z_mem_rd;
    S.z.write = z_mem_wr;
    S.z.in    = z_port_in;
    S.z.out   = z_port_out;
    z80_reset(&S.z);
    S.z.cycles = 0;
    S.z_done_cyc = 0;
    S.z_nmi_en = 0;
    S.sound_code = S.sound_reply = 0;
    S.zbank[0] = 0x8000u;
    S.zbank[1] = 0xC000u;
    S.zbank[2] = 0xE000u;
    S.zbank[3] = 0xF000u;
    z_map_banks();

    /* Reset YM2610 state */
    for (u32 i = 0; i < sizeof(S.ym); i++)
        ((u8 *)&S.ym)[i] = 0;
    for (int ch = 0; ch < 6; ch++) {
        S.ym.ch[ch].on = 1;
        S.ym.ch[ch].quiet = 1;
        for (int n = 0; n < 4; n++) {
            S.ym.ch[ch].op[n].att = 0x3FF;
            S.ym.ch[ch].op[n].env = 0x3FF;
            S.ym.ch[ch].op[n].state = EG_RELEASE;
        }
    }
    S.ym.ssg.reg[7] = 0x38;             /* Tone enabled, noise disabled */
    S.ym.ssg.lfsr   = 1u;
    S.ym.pb.step    = 127;
    S.wlog_n = 0;
    S.syn_zcyc = S.syn_rem = 0;
}

const char *neo_load(u8 *image, u32 size)
{
    if (!image || size <= 4096u)
        return "not a .neo cartridge (too small)";
    if (image[0] != 'N' || image[1] != 'E' || image[2] != 'O' || image[3] != 0x01u)
        return "not a .neo cartridge (bad NEO\\x01 magic)";

    u32 psz  = le32(image + 4);
    u32 ssz  = le32(image + 8);
    u32 msz  = le32(image + 12);
    u32 v1sz = le32(image + 16);
    u32 v2sz = le32(image + 20);
    u32 csz  = le32(image + 24);

    if (psz < 64u || (psz & 1u) || psz > 0x900000u)
        return "invalid P-ROM size in .neo header";

    /* Overflow-safe sequential bounds verification */
    u32 off = 4096u;
    u32 parts[6] = {psz, ssz, msz, v1sz, v2sz, csz};
    for (int i = 0; i < 6; i++) {
        if (parts[i] > size - off)
            return "truncated .neo cartridge (ROM section exceeds file size)";
        off += parts[i];
    }

    S.year = le32(image + 28);
    S.ngh  = le32(image + 40);

    S.p_rom  = image + 4096u;
    S.p_size = psz;
    S.s_rom  = S.p_rom + psz;
    S.s_size = ssz;
    S.m_rom  = S.s_rom + ssz;
    S.m_size = msz;
    S.v1_rom = S.m_rom + msz;
    S.v1_size = v1sz;
    if (v2sz) {
        S.v2_rom  = S.v1_rom + v1sz;
        S.v2_size = v2sz;
    } else {
        S.v2_rom  = S.v1_rom;
        S.v2_size = v1sz;
    }
    S.c_rom  = S.v1_rom + v1sz + v2sz;
    S.c_size = csz;

    /* Auto-detect big-endian P-ROM ("NEO-GEO" at 0x100 or big-endian SSP 00 10 xx xx at 0x00)
       vs standard TerraOnion .neo / MAME .p1 little-endian words ("EN-OEGO" at 0x100). */
    int big_endian_p = 0;
    if (psz >= 0x108u && S.p_rom[0x100] == 'N' && S.p_rom[0x101] == 'E' && S.p_rom[0x102] == 'O')
        big_endian_p = 1;
    else if ((psz < 0x108u || (S.p_rom[0x100] != 'E' || S.p_rom[0x101] != 'N')) &&
             S.p_rom[0] == 0x00 && (S.p_rom[1] == 0x10 || S.p_rom[1] == 0x11))
        big_endian_p = 1;

    if (big_endian_p) {
        for (u32 i = 0; i + 1u < psz; i += 2) {
            u8 t = S.p_rom[i];
            S.p_rom[i] = S.p_rom[i + 1u];
            S.p_rom[i + 1u] = t;
        }
    }

    S.c_tile_mask = csz >= 128u ? calc_pow2_mask(csz >> 7) : 0u;
    S.p_bank_mask = psz > 0x100000u ? calc_pow2_mask((psz - 0x100000u + 0xFFFFFu) >> 20) : 0u;

    /* Board & Fix bankswitching quirks by NGH */
    S.board = 0;
    S.fix_banksw = 0;
    if (S.ngh == 0x047u || S.ngh == 0x052u) S.board = 2; /* Fatal Fury 2, Super Sidekicks (PRO-CT0) */
    else if (S.ngh == 0x006u || S.ngh == 0x019u || S.ngh == 0x038u) S.board = 3;
    else if (S.ngh == 0x268u || S.ngh == 0x269u || S.ngh == 0x271u) S.board = 1; /* PVC */
    if (S.ngh == 0x253u || S.ngh == 0x256u || S.ngh == 0x263u) S.fix_banksw = 1;
    else if (S.ngh == 0x257u || S.ngh == 0x266u || S.ngh == 0x271u) S.fix_banksw = 2;

    /* (the tables once more at every load: they are in the players' shared memory, which the next machine
       played writes over -- with the flag still set they were that machine's bytes after it) */
    S.tables_ready = 0;
    build_static_tables();
    for (u32 i = 0; i < 0x10000u; i++)
        M->nvram[i] = M->nvram_save[i] = 0;
    for (u32 i = 0; i < 0x2000u; i++)
        M->cartram[i] = 0;
    S.nvram_dirty = 0;

    /* Format info string */
    char title[34];
    int tn = 0;
    for (int i = 0; i < 33 && image[44 + i]; i++) {
        char c = (char)image[44 + i];
        if (c >= 32 && c <= 126)
            title[tn++] = c;
    }
    while (tn > 0 && title[tn - 1] == ' ')
        tn--;
    title[tn] = 0;

    char *p = put_str(S.info, tn ? title : "Neo Geo Cartridge");
    p = put_str(p, ", P ");
    p = put_u32(p, psz >> 10);
    p = put_str(p, " KB, C ");
    p = put_u32(p, csz >> 10);
    p = put_str(p, " KB, V ");
    p = put_u32(p, (v1sz + v2sz) >> 10);
    p = put_str(p, " KB");
    if (S.has_ext_bios)
        p = put_str(p, ", BIOS");
    else
        p = put_str(p, ", HLE BIOS");

    neo_reset();
    return 0;
}

void neo_pad2(u16 pad)
{
    S.pads[1] = pad;
}

void neo_frame(u16 pad, u16 *picture)
{
    S.pads[0] = pad;
    S.pic = picture;

    /* If external BIOS is not running and cart overwrote VBlank without calling SYSTEM_IO,
       only update BIOS controller RAM automatically when cart is NOT calling $C0044A itself;
       note: games using BIOS call $C0044A or $C00438 once per frame. */

    for (u32 sl = 0; sl < TOTAL_LINES; sl++) {
        S.scanline = sl;
        s32 line_base = (s32)(sl * M68K_LINE_CYC);

        /* Cycle 30: Auto-animation tick at active top; VBlank IRQ1 at line 249 */
        run_m68k_segment(line_base + 30);
        if (sl == LINE_ACTIVE_START) {
            if (--S.aa_timer == 0xFFu) {
                S.aa_counter = (S.aa_counter + 1u) & 7u;
                S.aa_timer = S.aa_reload;
            }
        } else if (sl == LINE_ACTIVE_END + 1u) {
            S.irq_pending |= 1u;
            irq_refresh();
        }

        /* Cycle 574: Scanline render & VBlank timer reload at line 248 */
        run_m68k_segment(line_base + 574);
        lspc_do_scanline(sl);
        if (sl == LINE_ACTIVE_END && (S.irq2_ctrl & TMR_RELOAD_VBL))
            S.irq2_counter = S.irq2_reload;

        /* Cycle 768: End of scanline + periodic Z80 catch-up */
        run_m68k_segment(line_base + M68K_LINE_CYC);
        if ((sl & 15u) == 15u || sl == TOTAL_LINES - 1u)
            z80_catch_up();
    }

    /* Synthesize remaining YM2610 audio for the frame */
    u32 frame_zcyc = S.z.cycles > 0 ? (u32)S.z.cycles : (u32)(TOTAL_LINES * Z80_LINE_CYC);
    syn_to(frame_zcyc);

    m.clock -= FRAME_M68K_CYC;
    if (m.clock < 0)
        m.clock = 0;
    s32 z_frame = TOTAL_LINES * Z80_LINE_CYC;
    if (S.z.cycles >= z_frame) {
        S.z.cycles -= z_frame;
        S.z_done_cyc -= z_frame;
        S.z_poll_at -= z_frame;
        S.syn_zcyc = S.syn_zcyc >= (u32)z_frame ? S.syn_zcyc - (u32)z_frame : 0u;
    } else {
        S.z.cycles = S.z_done_cyc = S.z_poll_at = 0;
        S.syn_zcyc = 0;
    }

    /* Hardware watchdog: resets after ~8 frames (~135 ms) if $300001 not kicked (allow generous 24 frames for homebrew) */
    if (++S.watchdog_frames >= 32u) {
        S.watchdog_frames = 0;
        neo_reset();
    }
}

const char *neo_info(void)
{
    return S.info;
}

u8 *neo_save_ram(u32 *size, int *battery)
{
    /* Sync big-endian nvram_save <-> host-word M->nvram:
       Note play.c calls neo_save_ram() at start to read .sav into the returned buffer
       (and calls neo_save_changed() right after), then calls neo_save_ram() at exit! */
    if (S.nvram_dirty) {
        for (u32 i = 0; i < 0x10000u; i += 2) {
            M->nvram_save[i]      = M->nvram[i + 1u];
            M->nvram_save[i + 1u] = M->nvram[i];
        }
    }
    *size = 0x10000u;
    *battery = 1;
    return M->nvram_save;
}

int neo_save_changed(void)
{
    /* If play.c just loaded .sav into M->nvram_save (when !S.nvram_dirty), import it into M->nvram! */
    if (!S.nvram_dirty) {
        int any = 0;
        for (u32 i = 0; i < 0x10000u; i++)
            any |= M->nvram_save[i];
        if (any) {
            for (u32 i = 0; i < 0x10000u; i += 2) {
                M->nvram[i]      = M->nvram_save[i + 1u];
                M->nvram[i + 1u] = M->nvram_save[i];
            }
        }
        return 0;
    }
    for (u32 i = 0; i < 0x10000u; i += 2) {
        M->nvram_save[i]      = M->nvram[i + 1u];
        M->nvram_save[i + 1u] = M->nvram[i];
    }
    S.nvram_dirty = 0;
    return 1;
}

int neo_jammed(void)
{
    return m.stopped && m.im == 7;
}

void neo_audio_rate(u32 hz)
{
    S.snd_rate = hz;
    S.snd_acc = 0;
    S.snd_sum = S.snd_n = 0;
    S.snd_lp = S.snd_lp_was = S.snd_hp = 0;
    S.snd_head = S.snd_tail = 0;
}

int neo_audio(s16 *out, int max)
{
    int k = 0;
    while (k < max && S.snd_tail != S.snd_head)
        out[k++] = M->snd_ring[S.snd_tail++ & (SND_RING - 1u)];
    return k;
}

