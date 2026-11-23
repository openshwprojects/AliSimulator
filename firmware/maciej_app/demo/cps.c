/* Capcom CPS-1, CPS-1.5 (QSound Dash) & CPS-2 arcade system: see cps.h. */
#pragma GCC optimize("O2")
#include "cps.h"
#include "z80.h"
#include "zip.h"

#ifndef CPS_HOST
#include "hw.h"
#endif

#define INLINE static inline __attribute__((always_inline))

static u8 *fmap[256];
static void cps_iack(u32 level);
static void cps_branch(u32 at);
INLINE u32 cps_fetch(u32 a);

#define M68K_IACK(level) cps_iack(level)
#define M68K_BRANCH(at)  cps_branch(at)
#define M68K_FETCH(pc)   cps_fetch(pc)
#include "m68k.inc"

INLINE u32 cps_fetch(u32 a)
{
    if (a & 1)
        return odd(a, 0);
    const u8 *p = fmap[(a >> 16) & 0xFF];
    return p ? *(const u16 *)(p + (a & 0xFFFF)) : rw(a);
}

#define MAX_RASTER      10
#define TOTAL_LINES     262
#define FIRST_VIS_LINE  16
#define VIS_LINES       224
#define SND_RING        8192

/* CPS-B chip IDs */
enum {
    CPS_B_01 = 0, CPS_B_02, CPS_B_03, CPS_B_04, CPS_B_05,
    CPS_B_11, CPS_B_12, CPS_B_13, CPS_B_14, CPS_B_15, CPS_B_16, CPS_B_17, CPS_B_18,
    CPS_B_21_DEF, CPS_B_21_BT1, CPS_B_21_BT2, CPS_B_21_BT3, CPS_B_21_BT4,
    CPS_B_21_BT5, CPS_B_21_BT6, CPS_B_21_BT7,
    CPS_B_21_QS1, CPS_B_21_QS2, CPS_B_21_QS3, CPS_B_21_QS4, CPS_B_21_QS5
};

#define GFXTYPE_SPRITES (1 << 0)
#define GFXTYPE_SCROLL1 (1 << 1)
#define GFXTYPE_SCROLL2 (1 << 2)
#define GFXTYPE_SCROLL3 (1 << 3)
#define GFXTYPE_STARS   (1 << 4)

/* YM2151 (OPM) 8-channel 4-operator FM state */
struct opm_op {
    u32 phase, inc;
    s32 att;
    u32 env;
    s32 out, out1;
    u8 dt1, dt2, mul, tl, ks, ar, am, d1r, d2r, d1l, rr;
    u8 state;
    u8 rate[4];
};

struct opm_ch {
    struct opm_op op[4];                /* 0:M1, 1:C1, 2:M2, 3:C2 */
    u8 kc, kf, alg, fb, rl, pms, ams, quiet;
};

/* OKIM6295 4-channel ADPCM state */
struct oki_ch {
    u8 playing, vol_idx, nib_shift;
    u32 pos, end;
    s32 acc, step_idx, cur_out, prev_out;
};

/* Capcom DL-1425 QSound 16-voice DSP state */
struct q_chan {
    u8 key, bank;
    const s8 *bank_ptr;
    s32 play_start, start, end, loop, pos, adv;
    s32 master_vol, vol_l, vol_r, pitch;
};

struct cps_obj_snap {
    s32 shift_x, shift_y;
    s32 count;
    u16 list[1024 * 4];
};

struct cps_mem {
    u8 ram90[0x30000];                  /* $900000..$92FFFF 192 KB GFX/Scroll/Pal/Obj RAM (host u16) */
    u8 ramff[0x10000];                  /* $FF0000..$FFFFFF 64 KB 68000 work RAM (host u16) */
    u8 ram660[0x10000];                 /* $660000..$663FFF extra RAM padded to 64 KB page (host u16) */
    u8 ram708[0x4000];                  /* $708000..$70FFFF 2 x 8 KB CPS-2 sprite banks (host u16) */
    u8 zram_c0[0x1000];                 /* Z80 $C000..$CFFF QSound shared RAM */
    u8 zram_f0[0x2000];                 /* Z80 $D000..$D7FF (CPS-1) / $F000..$FFFF (CPS-2) */
    u8 kabuki_op[0x8000];               /* Kabuki decoded Z80 M1 opcodes ($0000..$7FFF) */
    u8 kabuki_data[0x8000];             /* Kabuki decoded Z80 data ($0000..$7FFF) */
    u8 eeprom[0x80];                    /* 128-byte 93C46 EEPROM (.sav) */
    u16 pal_save[0xC00];                /* 6 x 512 latched 16-bit CPS palette entries */
    u16 pal15[0xC00];                   /* 6 x 512 precalculated BGR555 colors (pen^15 indexed) */
    u16 zbuf[CPS_W * CPS_H];            /* CPS-2 per-pixel sprite Z-priority buffer */
    u32 sep_tab[256];                   /* Planar bit-unpack + invert lookup table */
    struct cps_obj_snap obj_snap[2];    /* Double-buffered sprite snapshot */
    u8 save_reg[MAX_RASTER + 1][0x100];
    u8 save_frg[MAX_RASTER + 1][0x10];
    s16 snd_ring[SND_RING];
};

#ifdef CPS_HOST
static struct cps_mem cps_host_mem;
static u8 cps_host_rom[0x400000];
static u8 cps_host_code[0x400000];
static u8 cps_host_zrom[0x80000];
static u8 cps_host_snd[0x1000000];
static u8 cps_host_gfx[0x2000000];
static u8 cps_host_scratch[0x400000];
#define M            (&cps_host_mem)
#define ROM_BUF      cps_host_rom
#define ROM_CAP      ((u32)sizeof(cps_host_rom))
#define CODE_BUF     cps_host_code
#define CODE_CAP     ((u32)sizeof(cps_host_code))
#define ZROM_BUF     cps_host_zrom
#define ZROM_CAP     ((u32)sizeof(cps_host_zrom))
#define SND_BUF      cps_host_snd
#define SND_CAP      ((u32)sizeof(cps_host_snd))
#define GFX_BUF      cps_host_gfx
#define GFX_CAP      ((u32)sizeof(cps_host_gfx))
#define SCRATCH_BUF  cps_host_scratch
#define SCRATCH_CAP  ((u32)sizeof(cps_host_scratch))
#define CPS_FEED_DOG() ((void)0)
#else
/* Physical memory map during cps_play (view.c / av.c inactive):
   0x02400000..0x03C60000 (24.375 MB): GFX_BUF (MEDIA_PHYS + lower EMU_RAM_PHYS)
   0x03C60000..0x03D80000 (1.125 MB) : struct cps_mem M
   0x05800000..0x05C00000 (4.0 MB)   : ROM_BUF (68000 data ROM)
   0x05C00000..0x06000000 (4.0 MB)   : CODE_BUF (68000 decrypted opcode ROM)
   0x06900000..0x06980000 (512 KB)   : ZROM_BUF (Z80 ROM)
   0x06980000..0x07580000 (12.0 MB)  : SND_BUF (QSound PCM / OKIM6295 ADPCM)
   0x07580000..0x07F00000 (9.5 MB)   : SCRATCH_BUF (ZIP staging & ROM interleave) */
#define M            ((struct cps_mem *)KSEG0(0x03C60000u))
#define ROM_BUF      ((u8 *)KSEG0(0x05800000u))
#define ROM_CAP      0x00400000u
#define CODE_BUF     ((u8 *)KSEG0(0x05C00000u))
#define CODE_CAP     0x00400000u
#define ZROM_BUF     ((u8 *)KSEG0(0x06900000u))
#define ZROM_CAP     0x00080000u
#define SND_BUF      ((u8 *)KSEG0(0x06980000u))
#define SND_CAP      0x00C00000u
#define GFX_BUF      ((u8 *)KSEG0(MEDIA_PHYS))
#define GFX_CAP      0x01860000u
#define SCRATCH_BUF  ((u8 *)KSEG0(0x07580000u))
#define SCRATCH_CAP  0x00980000u
#define CPS_FEED_DOG() ((void)now_ms())
#endif

struct gfx_range {
    u8 type;
    u32 start, end;
    u8 bank;
};

static struct {
    u8 *rom, *code, *zrom, *ad_rom, *gfx;
    s8 *qsam;
    u32 rom_len, code_len, zrom_len, snd_len, gfx_len, gfx_mask;
    u32 gfx_scroll[4];
    const u8 *extra_ptr;
    u32 extra_len;

    u8 cps_ver;                         /* 1 = CPS-1, 2 = CPS-2 */
    u8 use_qsound;                      /* 0 = YM2151 + OKIM6295, 1 = QSound */
    u8 has_kabuki;
    u8 has_eeprom;
    u8 eeprom_16bit;                    /* 1 = CPS-2 (64x16), 0 = CPS-1.5 (128x8) */
    u8 eeprom_dirty;
    u8 ssf2t, xmcota;

    u32 m68k_hz, z80_hz;
    s32 cyc_per_frame, zcyc_per_frame;
    s32 extra_cyc, z_extra_cyc;

    /* CPS-A / CPS-B configuration */
    u8 cps_reg[0x100];                  /* Big-endian bytes of $800100..$8001FF */
    u8 cps_frg[0x10];                   /* Big-endian bytes of $400000..$40000F */
    u8 mprot[4], bid[3];
    u8 lc_reg, pal_ctrl_reg;
    u8 mask_addr[4];
    u8 lay_en[6];
    s16 lay_xoffs[3], lay_yoffs[3];
    u32 calc[2];
    const struct gfx_range *gfx_mapper;
    u32 gfx_bank_sizes[4];

    /* Interrupts, raster & object banks */
    u8 irq_pending;                     /* bit 2: VBlank IRQ2, bit 4: Raster IRQ4 */
    u8 obj_bank, obj_bank_used1;
    u8 snap_idx;
    u8 r664001;
    u8 pal_latched_once, zbuf_dirty;
    s32 cur_scanline, slice_end_cyc;
    s32 irq_line50, irq_line52;
    s32 raster_lines[MAX_RASTER + 2];
    s32 n_rasters;

    /* Inputs (active-high internal bits; inverted on port read) */
    u16 pads[2];
    u8 inp000, inp001, inp010, inp011, inp018, inp020, inp021, inp177;
    u8 dip_a, dip_b, dip_c;

    /* 93C46 Serial EEPROM state */
    struct {
        u8 cs, clk, di, do_bit, write_en;
        u8 state;                       /* 0:idle, 1:start, 2:cmd_addr, 3:reading, 4:writing */
        u32 shift, bits, write_addr;
    } eep;

    /* Z80 & Sound */
    struct z80 z;
    u8 z_bank;
    u8 psnd_code, psnd_fade;
    u8 qsc_cmd[2];
    s32 q_irq_next;

    /* QSound */
    struct q_chan qch[16];
    u32 q_pitch_scale;                  /* (24096 << 12) / snd_rate */

    /* CPS-1 YM2151 + OKIM6295 */
    struct {
        struct opm_ch ch[8];
        u8 addr_latch;
        u16 ta_load;
        u8 tb_load, timer_ctrl, status;
        s32 ta_cnt, tb_cnt;
        u8 noise_en, noise_freq;
        u32 lfsr, noise_cnt, eg_cnt;
        u8 eg_div;
        s32 cached_sample;
        u8 sample_toggle;
    } opm;

    struct {
        struct oki_ch ch[4];
        u8 cmd_latch;
        u32 rate_hz, phase_acc;
    } oki;

    u32 snd_rate, snd_rendered;
    u32 snd_head, snd_tail;
    u32 frame_num;
    u8 sep_ready, cpu_ready;
    char info[128];
} S;

/* ---- Freestanding memory & string helpers ---- */

static void cps_zero(void *dst, u32 n)
{
    u8 *p = (u8 *)dst;
    while (n && ((__UINTPTR_TYPE__)p & 3u)) {
        *p++ = 0;
        n--;
    }
    u32 *p32 = (u32 *)p;
    u32 w = n >> 2;
    for (u32 i = 0; i < w; i++)
        p32[i] = 0;
    p = (u8 *)(p32 + w);
    n &= 3u;
    for (u32 i = 0; i < n; i++)
        p[i] = 0;
}

static void cps_copy(void *dst, const void *src, u32 n)
{
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    if (d == s || !n)
        return;
    if (d < s) {
        for (u32 i = 0; i < n; i++)
            d[i] = s[i];
    } else {
        for (u32 i = n; i-- > 0;)
            d[i] = s[i];
    }
}

static char cps_low(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

static int cps_streq_ci(const char *a, const char *b)
{
    while (*a && *b) {
        if (cps_low(*a) != cps_low(*b))
            return 0;
        a++;
        b++;
    }
    return *a == *b;
}

static int cps_ends_ci(const char *s, const char *ext)
{
    int sl = 0, el = 0;
    while (s[sl]) sl++;
    while (ext[el]) el++;
    if (sl < el)
        return 0;
    for (int i = 0; i < el; i++)
        if (cps_low(s[sl - el + i]) != cps_low(ext[i]))
            return 0;
    return 1;
}

static u32 cps_le32(const u8 *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

INLINE u16 reg16(const u8 *r, u32 off)
{
    return (u16)(((u16)r[off & 0xFEu] << 8) | r[(off & 0xFEu) + 1u]);
}

/* ---- Planar bit-separation LUT (8 pixels -> u32 AAAABBBB..GGGGHHHH, inverted so 0 = transparent pen 15) ---- */

static void init_sep_table(void)
{
    if (S.sep_ready)
        return;
    for (u32 i = 0; i < 256; i++) {
        u32 a = 255u - i;
        a = ((a & 0xF0u) << 12) | (a & 0x0Fu);
        a = ((a & 0x000C000Cu) << 6) | (a & 0x00030003u);
        a = ((a & 0x02020202u) << 3) | (a & 0x01010101u);
        M->sep_tab[i] = a;
    }
    S.sep_ready = 1;
}

/* ---- CPS-1 GFX Bank Mapper & CPS-B Board Configurations ---- */

enum {
    MAP_DIRECT = 0, MAP_LWCHR, MAP_DM620, MAP_ST24M1, MAP_DM22A, MAP_DAM63B,
    MAP_ST22B, MAP_TK22B, MAP_WL24B, MAP_S224B, MAP_YI24B, MAP_AR24B, MAP_AR22B,
    MAP_O224B, MAP_MS24B, MAP_CK24B, MAP_NM24B, MAP_CA24B, MAP_CA22B, MAP_STF29,
    MAP_RT24B, MAP_RT22B, MAP_KD29B, MAP_CC63B, MAP_KR63B, MAP_S9263B, MAP_VA63B,
    MAP_Q522B, MAP_TK263B, MAP_CD63B, MAP_PS63B, MAP_MB63B, MAP_QD22B, MAP_CPS2
};

static const struct gfx_range map_lwchr[] = {
    {GFXTYPE_SPRITES, 0x00000, 0x07FFF, 0}, {GFXTYPE_SCROLL1, 0x00000, 0x1FFFF, 0},
    {GFXTYPE_STARS | GFXTYPE_SCROLL2 | GFXTYPE_SCROLL3, 0x00000, 0x1FFFF, 1}, {0, 0, 0, 0}
};
static const struct gfx_range map_dm620[] = {
    {GFXTYPE_SCROLL3, 0x8000, 0xBFFF, 1}, {GFXTYPE_SPRITES, 0x2000, 0x3FFF, 2},
    {0x1F, 0x00000, 0x1FFFF, 0}, {0, 0, 0, 0}
};
static const struct gfx_range map_st24m1[] = {
    {GFXTYPE_STARS, 0x0000, 0x03FF, 0}, {GFXTYPE_SPRITES, 0x0000, 0x4FFF, 0}, {GFXTYPE_SCROLL2, 0x4000, 0x7FFF, 0},
    {GFXTYPE_SCROLL3, 0x0000, 0x7FFF, 1}, {GFXTYPE_SCROLL1, 0x7000, 0x7FFF, 1}, {0, 0, 0, 0}
};
static const struct gfx_range map_dm22a[] = {
    {GFXTYPE_SPRITES, 0x0000, 0x1FFF, 0}, {GFXTYPE_SCROLL1, 0x2000, 0x3FFF, 0},
    {GFXTYPE_SCROLL2, 0x4000, 0x7FFF, 1}, {GFXTYPE_SCROLL3, 0x0000, 0x1FFFF, 2},
    {GFXTYPE_SPRITES, 0x2000, 0x3FFF, 3}, {0, 0, 0, 0}
};
static const struct gfx_range map_dam63b[] = {
    {GFXTYPE_SPRITES, 0x0000, 0x1FFF, 0}, {GFXTYPE_SCROLL1, 0x2000, 0x2FFF, 0}, {GFXTYPE_SCROLL2, 0x4000, 0x7FFF, 0},
    {GFXTYPE_SCROLL3, 0x0000, 0x1FFFF, 1}, {GFXTYPE_SPRITES, 0x2000, 0x3FFF, 1}, {0, 0, 0, 0}
};
static const struct gfx_range map_tk22b[] = {
    {GFXTYPE_SPRITES, 0x0000, 0x3FFF, 0}, {GFXTYPE_SPRITES, 0x4000, 0x5FFF, 1}, {GFXTYPE_SCROLL1, 0x6000, 0x7FFF, 1},
    {GFXTYPE_SCROLL3, 0x0000, 0x3FFF, 2}, {GFXTYPE_SCROLL2, 0x4000, 0x7FFF, 3}, {0, 0, 0, 0}
};
static const struct gfx_range map_wl24b[] = {
    {GFXTYPE_SPRITES, 0x0000, 0x4FFF, 0}, {GFXTYPE_SCROLL3, 0x5000, 0x6FFF, 0}, {GFXTYPE_SCROLL1, 0x7000, 0x7FFF, 0},
    {GFXTYPE_SCROLL2, 0x0000, 0x3FFF, 1}, {0, 0, 0, 0}
};
static const struct gfx_range map_s224b[] = {
    {GFXTYPE_SPRITES, 0x0000, 0x43FF, 0}, {GFXTYPE_SCROLL1, 0x4400, 0x4BFF, 0},
    {GFXTYPE_SCROLL3, 0x4C00, 0x5FFF, 0}, {GFXTYPE_SCROLL2, 0x6000, 0x7FFF, 0}, {0, 0, 0, 0}
};
static const struct gfx_range map_yi24b[] = {
    {GFXTYPE_SPRITES, 0x0000, 0x1FFF, 0}, {GFXTYPE_SCROLL3, 0x2000, 0x3FFF, 0},
    {GFXTYPE_SCROLL1, 0x4000, 0x47FF, 0}, {GFXTYPE_SCROLL2, 0x4800, 0x7FFF, 0}, {0, 0, 0, 0}
};
static const struct gfx_range map_ar24b[] = {
    {GFXTYPE_SPRITES, 0x0000, 0x2FFF, 0}, {GFXTYPE_SCROLL1, 0x3000, 0x3FFF, 0},
    {GFXTYPE_SCROLL2, 0x4000, 0x5FFF, 0}, {GFXTYPE_SCROLL3, 0x6000, 0x7FFF, 0}, {0, 0, 0, 0}
};
static const struct gfx_range map_ms24b[] = {
    {GFXTYPE_SPRITES, 0x0000, 0x3FFF, 0}, {GFXTYPE_SCROLL1, 0x4000, 0x4FFF, 0},
    {GFXTYPE_SCROLL2, 0x5000, 0x6FFF, 0}, {GFXTYPE_SCROLL3, 0x7000, 0x7FFF, 0}, {0, 0, 0, 0}
};
static const struct gfx_range map_ck24b[] = {
    {GFXTYPE_SPRITES, 0x0000, 0x2FFF, 0}, {GFXTYPE_SCROLL1, 0x3000, 0x3FFF, 0},
    {GFXTYPE_SCROLL2, 0x4000, 0x6FFF, 0}, {GFXTYPE_SCROLL3, 0x7000, 0x7FFF, 0}, {0, 0, 0, 0}
};
static const struct gfx_range map_nm24b[] = {
    {GFXTYPE_SPRITES | GFXTYPE_SCROLL2, 0x0000, 0x3FFF, 0}, {GFXTYPE_SCROLL1, 0x4000, 0x47FF, 0},
    {GFXTYPE_SPRITES | GFXTYPE_SCROLL2, 0x4800, 0x67FF, 0}, {GFXTYPE_SCROLL3, 0x6800, 0x7FFF, 0}, {0, 0, 0, 0}
};
static const struct gfx_range map_ca24b[] = {
    {GFXTYPE_SPRITES | GFXTYPE_SCROLL2, 0x0000, 0x2FFF, 0}, {GFXTYPE_SCROLL3, 0x3000, 0x4FFF, 0},
    {GFXTYPE_SCROLL1, 0x5000, 0x57FF, 0}, {GFXTYPE_SPRITES | GFXTYPE_SCROLL2, 0x5800, 0x7FFF, 0}, {0, 0, 0, 0}
};
static const struct gfx_range map_stf29[] = {
    {GFXTYPE_SPRITES, 0x00000, 0x07FFF, 0}, {GFXTYPE_SPRITES, 0x08000, 0x0FFFF, 1},
    {GFXTYPE_SPRITES, 0x10000, 0x11FFF, 2}, {GFXTYPE_SCROLL3, 0x02000, 0x03FFF, 2},
    {GFXTYPE_SCROLL1, 0x04000, 0x04FFF, 2}, {GFXTYPE_SCROLL2, 0x05000, 0x07FFF, 2}, {0, 0, 0, 0}
};
static const struct gfx_range map_rt24b[] = {
    {GFXTYPE_SPRITES, 0x0000, 0x53FF, 0}, {GFXTYPE_SCROLL1, 0x5400, 0x6FFF, 0}, {GFXTYPE_SCROLL3, 0x7000, 0x7FFF, 0},
    {GFXTYPE_SCROLL3, 0x0000, 0x3FFF, 1}, {GFXTYPE_SCROLL2, 0x2800, 0x7FFF, 1}, {GFXTYPE_SPRITES, 0x5400, 0x7FFF, 1},
    {0, 0, 0, 0}
};
static const struct gfx_range map_kd29b[] = {
    {GFXTYPE_SPRITES, 0x0000, 0x7FFF, 0}, {GFXTYPE_SPRITES, 0x8000, 0x8FFF, 1},
    {GFXTYPE_SCROLL2, 0x9000, 0xBFFF, 1}, {GFXTYPE_SCROLL1, 0xC000, 0xD7FF, 1}, {GFXTYPE_SCROLL3, 0xD800, 0xFFFF, 1},
    {0, 0, 0, 0}
};
static const struct gfx_range map_cc63b[] = {
    {GFXTYPE_SPRITES | GFXTYPE_SCROLL2, 0x0000, 0x7FFF, 0},
    {0x0F, 0x8000, 0xFFFF, 1}, {0, 0, 0, 0}
};
static const struct gfx_range map_kr63b[] = {
    {GFXTYPE_SPRITES | GFXTYPE_SCROLL2, 0x0000, 0x7FFF, 0}, {GFXTYPE_SCROLL1, 0x8000, 0x9FFF, 1},
    {GFXTYPE_SPRITES | GFXTYPE_SCROLL2, 0x8000, 0xCFFF, 1}, {GFXTYPE_SCROLL3, 0xD000, 0xFFFF, 1}, {0, 0, 0, 0}
};
static const struct gfx_range map_va63b[] = {
    {0x0F, 0x0000, 0x7FFF, 0}, {0, 0, 0, 0}
};
static const struct gfx_range map_q522b[] = {
    {GFXTYPE_SPRITES | GFXTYPE_SCROLL2, 0x0000, 0x6FFF, 0},
    {GFXTYPE_SCROLL3, 0x7000, 0x77FF, 0}, {GFXTYPE_SCROLL1, 0x7800, 0x7FFF, 0}, {0, 0, 0, 0}
};
static const struct gfx_range map_tk263b[] = {
    {0x0F, 0x00000, 0x07FFF, 0}, {0x0F, 0x08000, 0x0FFFF, 1}, {0, 0, 0, 0}
};
static const struct gfx_range map_cd63b[] = {
    {GFXTYPE_SCROLL1, 0x0000, 0x0FFF, 0}, {GFXTYPE_SPRITES, 0x1000, 0x7FFF, 0},
    {GFXTYPE_SPRITES | GFXTYPE_SCROLL2, 0x8000, 0xDFFF, 1}, {GFXTYPE_SCROLL3, 0xE000, 0xFFFF, 1}, {0, 0, 0, 0}
};
static const struct gfx_range map_ps63b[] = {
    {GFXTYPE_SCROLL1, 0x0000, 0x0FFF, 0}, {GFXTYPE_SPRITES, 0x1000, 0x7FFF, 0},
    {GFXTYPE_SPRITES | GFXTYPE_SCROLL2, 0x8000, 0xDBFF, 1}, {GFXTYPE_SCROLL3, 0xDC00, 0xFFFF, 1}, {0, 0, 0, 0}
};
static const struct gfx_range map_mb63b[] = {
    {GFXTYPE_SCROLL1, 0x00000, 0x00FFF, 0}, {GFXTYPE_SPRITES | GFXTYPE_SCROLL2, 0x01000, 0x07FFF, 0},
    {GFXTYPE_SPRITES | GFXTYPE_SCROLL2, 0x08000, 0x0FFFF, 1},
    {GFXTYPE_SPRITES | GFXTYPE_SCROLL2, 0x10000, 0x167FF, 2}, {GFXTYPE_SCROLL3, 0x16800, 0x17FFF, 2}, {0, 0, 0, 0}
};

static void set_gfx_mapper(int id)
{
    S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = S.gfx_bank_sizes[2] = S.gfx_bank_sizes[3] = 0;
    S.gfx_mapper = 0;
    switch (id) {
    case MAP_LWCHR:  S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = 0x8000; S.gfx_mapper = map_lwchr; break;
    case MAP_DM620:  S.gfx_bank_sizes[0] = 0x8000; S.gfx_bank_sizes[1] = S.gfx_bank_sizes[2] = 0x2000; S.gfx_mapper = map_dm620; break;
    case MAP_ST24M1: S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = 0x8000; S.gfx_mapper = map_st24m1; break;
    case MAP_DM22A:  S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = 0x4000; S.gfx_bank_sizes[2] = S.gfx_bank_sizes[3] = 0x2000; S.gfx_mapper = map_dm22a; break;
    case MAP_DAM63B: S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = 0x8000; S.gfx_mapper = map_dam63b; break;
    case MAP_TK22B:  S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = S.gfx_bank_sizes[2] = S.gfx_bank_sizes[3] = 0x4000; S.gfx_mapper = map_tk22b; break;
    case MAP_WL24B:  S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = 0x8000; S.gfx_mapper = map_wl24b; break;
    case MAP_S224B:  S.gfx_bank_sizes[0] = 0x8000; S.gfx_mapper = map_s224b; break;
    case MAP_YI24B:  S.gfx_bank_sizes[0] = 0x8000; S.gfx_mapper = map_yi24b; break;
    case MAP_AR24B:  S.gfx_bank_sizes[0] = 0x8000; S.gfx_mapper = map_ar24b; break;
    case MAP_MS24B:  S.gfx_bank_sizes[0] = 0x8000; S.gfx_mapper = map_ms24b; break;
    case MAP_CK24B:  S.gfx_bank_sizes[0] = 0x8000; S.gfx_mapper = map_ck24b; break;
    case MAP_NM24B:  S.gfx_bank_sizes[0] = 0x8000; S.gfx_mapper = map_nm24b; break;
    case MAP_CA24B:  S.gfx_bank_sizes[0] = 0x8000; S.gfx_mapper = map_ca24b; break;
    case MAP_STF29:
    case MAP_S9263B: S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = S.gfx_bank_sizes[2] = 0x8000; S.gfx_mapper = map_stf29; break;
    case MAP_RT24B:  S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = 0x8000; S.gfx_mapper = map_rt24b; break;
    case MAP_KD29B:  S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = 0x8000; S.gfx_mapper = map_kd29b; break;
    case MAP_CC63B:  S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = 0x8000; S.gfx_mapper = map_cc63b; break;
    case MAP_KR63B:  S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = 0x8000; S.gfx_mapper = map_kr63b; break;
    case MAP_VA63B:  S.gfx_bank_sizes[0] = 0x8000; S.gfx_mapper = map_va63b; break;
    case MAP_Q522B:  S.gfx_bank_sizes[0] = 0x8000; S.gfx_mapper = map_q522b; break;
    case MAP_TK263B: S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = 0x8000; S.gfx_mapper = map_tk263b; break;
    case MAP_CD63B:  S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = 0x8000; S.gfx_mapper = map_cd63b; break;
    case MAP_PS63B:  S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = 0x8000; S.gfx_mapper = map_ps63b; break;
    case MAP_MB63B:  S.gfx_bank_sizes[0] = S.gfx_bank_sizes[1] = S.gfx_bank_sizes[2] = 0x8000; S.gfx_mapper = map_mb63b; break;
    default:         S.gfx_mapper = 0; break;
    }
}

INLINE s32 map_gfx_tile(u8 type, u32 code)
{
    if (!S.gfx_mapper)
        return (s32)code;
    u32 shift = (type == GFXTYPE_SCROLL3) ? 3u : (type == GFXTYPE_SCROLL1 ? 0u : 1u);
    u32 c = code << shift;
    for (const struct gfx_range *r = S.gfx_mapper; r->type; r++) {
        if (c >= r->start && c <= r->end && (r->type & type)) {
            u32 base = 0;
            for (u32 i = 0; i < r->bank; i++)
                base += S.gfx_bank_sizes[i];
            u32 bsz = S.gfx_bank_sizes[r->bank];
            return bsz ? (s32)((base + (c & (bsz - 1u))) >> shift) : -1;
        }
    }
    return -1;
}

struct cpsb_cfg {
    u8 id;
    u8 bid[3];
    u8 mprot[4];
    u8 lc, m0, m1, m2, m3, pal;
    u8 le1, le2, le3;
};

static const struct cpsb_cfg cpsb_table[] = {
    {CPS_B_01,     {0x00,0x00,0x00}, {0,0,0,0},             0x66, 0x68,0x6A,0x6C,0x6E, 0x70, 0x02,0x04,0x08},
    {CPS_B_02,     {0x60,0x00,0x02}, {0,0,0,0},             0x6C, 0x6A,0x68,0x66,0x64, 0x62, 0x02,0x04,0x08},
    {CPS_B_03,     {0x00,0x00,0x00}, {0,0,0,0},             0x70, 0x6E,0x6C,0x6A,0x68, 0x66, 0x20,0x10,0x08},
    {CPS_B_04,     {0x60,0x00,0x04}, {0,0,0,0},             0x6E, 0x66,0x70,0x68,0x72, 0x6A, 0x02,0x04,0x08},
    {CPS_B_05,     {0x60,0x00,0x05}, {0,0,0,0},             0x68, 0x6A,0x6C,0x6E,0x70, 0x72, 0x02,0x08,0x20},
    {CPS_B_11,     {0x72,0x04,0x01}, {0,0,0,0},             0x66, 0x68,0x6A,0x6C,0x6E, 0x70, 0x08,0x10,0x20},
    {CPS_B_12,     {0x60,0x04,0x02}, {0,0,0,0},             0x6C, 0x6A,0x68,0x66,0x64, 0x62, 0x02,0x04,0x08},
    {CPS_B_13,     {0x6E,0x04,0x03}, {0,0,0,0},             0x62, 0x64,0x66,0x68,0x6A, 0x6C, 0x20,0x02,0x04},
    {CPS_B_14,     {0x5E,0x04,0x04}, {0,0,0,0},             0x52, 0x54,0x56,0x58,0x5A, 0x5C, 0x08,0x20,0x10},
    {CPS_B_15,     {0x4E,0x04,0x05}, {0,0,0,0},             0x42, 0x44,0x46,0x48,0x4A, 0x4C, 0x04,0x02,0x20},
    {CPS_B_16,     {0x40,0x04,0x06}, {0,0,0,0},             0x4C, 0x4A,0x48,0x46,0x44, 0x42, 0x10,0x0A,0x0A},
    {CPS_B_17,     {0x48,0x04,0x07}, {0,0,0,0},             0x54, 0x52,0x50,0x4E,0x4C, 0x4A, 0x08,0x10,0x02},
    {CPS_B_18,     {0xD0,0x04,0x08}, {0,0,0,0},             0xDC, 0xDA,0xD8,0xD6,0xD4, 0xD2, 0x10,0x08,0x02},
    {CPS_B_21_DEF, {0x32,0x00,0x00}, {0x40,0x42,0x44,0x46}, 0x66, 0x68,0x6A,0x6C,0x6E, 0x70, 0x02,0x04,0x08},
    {CPS_B_21_BT1, {0x72,0x08,0x00}, {0x4E,0x4C,0x4A,0x48}, 0x68, 0x66,0x64,0x62,0x60, 0x70, 0x20,0x04,0x08},
    {CPS_B_21_BT2, {0x00,0x00,0x00}, {0x5E,0x5C,0x5A,0x58}, 0x60, 0x6E,0x6C,0x6A,0x68, 0x70, 0x30,0x08,0x30},
    {CPS_B_21_BT3, {0x00,0x00,0x00}, {0x46,0x44,0x42,0x40}, 0x60, 0x6E,0x6C,0x6A,0x68, 0x70, 0x20,0x12,0x12},
    {CPS_B_21_BT4, {0x00,0x00,0x00}, {0x46,0x44,0x42,0x40}, 0x68, 0x66,0x64,0x62,0x60, 0x70, 0x20,0x10,0x02},
    {CPS_B_21_BT5, {0x32,0x00,0x00}, {0x4E,0x4C,0x4A,0x48}, 0x60, 0x6E,0x6C,0x6A,0x68, 0x70, 0x20,0x04,0x02},
    {CPS_B_21_BT6, {0x00,0x00,0x00}, {0,0,0,0},             0x60, 0x6E,0x6C,0x6A,0x68, 0x70, 0x20,0x14,0x14},
    {CPS_B_21_BT7, {0x00,0x00,0x00}, {0,0,0,0},             0x6C, 0x00,0x00,0x00,0x00, 0x52, 0x14,0x02,0x14},
    {CPS_B_21_QS1, {0x00,0x00,0x00}, {0,0,0,0},             0x62, 0x64,0x66,0x68,0x6A, 0x6C, 0x10,0x08,0x04},
    {CPS_B_21_QS2, {0x00,0x00,0x00}, {0,0,0,0},             0x4A, 0x4C,0x4E,0x40,0x42, 0x44, 0x16,0x16,0x16},
    {CPS_B_21_QS3, {0x4E,0x0C,0x00}, {0,0,0,0},             0x52, 0x54,0x56,0x48,0x4A, 0x4C, 0x04,0x02,0x20},
    {CPS_B_21_QS4, {0x6E,0x0C,0x01}, {0,0,0,0},             0x56, 0x40,0x42,0x68,0x6A, 0x6C, 0x04,0x08,0x10},
    {CPS_B_21_QS5, {0x5E,0x0C,0x02}, {0,0,0,0},             0x6A, 0x6C,0x6E,0x70,0x72, 0x5C, 0x04,0x08,0x10},
};

static void set_cpsb_id(u8 id)
{
    const struct cpsb_cfg *c = &cpsb_table[CPS_B_21_DEF];
    for (u32 i = 0; i < sizeof(cpsb_table) / sizeof(cpsb_table[0]); i++) {
        if (cpsb_table[i].id == id) {
            c = &cpsb_table[i];
            break;
        }
    }
    for (int i = 0; i < 3; i++) S.bid[i] = c->bid[i];
    for (int i = 0; i < 4; i++) S.mprot[i] = c->mprot[i];
    S.lc_reg = c->lc;
    S.mask_addr[0] = c->m0;
    S.mask_addr[1] = c->m1;
    S.mask_addr[2] = c->m2;
    S.mask_addr[3] = c->m3;
    S.pal_ctrl_reg = c->pal;
    S.lay_en[0] = 0;
    S.lay_en[1] = c->le1;
    S.lay_en[2] = c->le2;
    S.lay_en[3] = c->le3;
    S.lay_en[4] = S.lay_en[5] = 0;
}

/* ---- CPS-2 Dual 4-Round Feistel Network & Kabuki Z80 Decryption ---- */

#define CBIT(x, n) (((x) >> (n)) & 1u)

struct cps2_sbox {
    u8 table[64];
    s8 inputs[6];
    s8 outputs[2];
};

struct cps2_opt_sbox {
    u8 in_lut[256];
    u8 out[64];
};

static const u8 fn1_grpA[8] = {10, 4, 6, 7, 2, 13, 15, 14};
static const u8 fn1_grpB[8] = { 0, 1, 3, 5, 8,  9, 11, 12};
static const u8 fn2_grpA[8] = { 6, 0, 2,13, 1,  4, 14,  7};
static const u8 fn2_grpB[8] = { 3, 5, 9,10, 8, 15, 12, 11};

static const struct cps2_sbox fn1_boxes[16] = {
    {{0,2,2,0,1,0,1,1,3,2,0,3,0,3,1,2,1,1,1,2,1,3,2,2,2,3,3,2,1,1,1,2,2,2,0,0,3,1,3,1,1,1,3,0,0,1,0,0,1,2,2,1,2,3,2,2,2,3,1,3,2,0,1,3},{3,4,5,6,-1,-1},{3,6}},
    {{3,0,2,2,2,1,1,1,1,2,1,0,0,0,2,3,2,3,1,3,0,0,0,2,1,2,2,3,0,3,3,3,0,1,3,2,3,3,3,1,1,1,1,2,0,1,2,1,3,2,3,1,1,3,2,2,2,3,1,3,2,3,0,0},{0,1,2,4,7,-1},{2,7}},
    {{3,0,3,1,1,0,2,2,3,1,2,0,3,3,2,3,0,1,0,1,2,3,0,2,0,2,0,1,0,0,1,0,2,3,1,2,1,0,2,0,2,1,0,1,0,2,1,0,3,1,2,3,1,3,1,1,1,2,0,2,2,0,0,0},{0,1,2,3,6,7},{0,1}},
    {{3,2,0,3,0,2,2,1,1,2,3,2,1,3,2,1,2,2,1,3,3,2,1,0,1,0,1,3,0,0,0,2,2,1,0,1,0,1,0,1,3,1,1,2,2,3,2,0,3,3,2,0,2,1,3,3,0,0,3,0,1,1,3,3},{0,1,3,5,6,7},{4,5}},
    {{3,3,2,0,3,0,3,1,0,3,0,1,0,2,1,3,1,3,0,3,3,1,3,3,3,2,3,2,2,3,1,2,0,2,2,1,0,1,2,0,3,3,0,1,3,2,1,2,3,0,1,3,0,1,2,2,1,2,1,2,0,1,3,0},{0,1,2,3,6,-1},{1,6}},
    {{1,2,3,2,1,3,0,1,1,0,2,0,0,2,3,2,3,3,0,1,2,2,1,0,1,0,1,2,3,2,1,3,2,2,2,0,1,0,2,3,2,1,2,1,2,1,0,3,0,1,2,3,1,2,1,3,2,0,3,2,3,0,2,0},{2,4,5,6,7,-1},{5,7}},
    {{0,1,0,2,1,1,0,1,0,2,2,2,1,3,0,0,1,1,3,1,2,2,2,3,1,0,3,3,3,2,2,2,1,1,3,0,3,1,3,0,1,3,3,2,1,1,0,0,1,2,2,2,1,1,1,2,2,0,0,3,2,3,1,3},{1,2,3,4,5,7},{0,3}},
    {{2,1,0,3,3,3,2,0,1,2,1,1,1,0,3,1,1,3,3,0,1,2,1,0,0,0,3,0,3,0,3,0,1,3,3,3,0,3,2,0,2,1,2,2,2,1,1,3,0,1,0,1,0,1,1,1,1,3,1,0,1,2,3,3},{0,1,3,4,6,7},{2,4}},
    {{0,0,0,3,3,1,1,0,2,0,2,0,0,0,3,2,0,1,2,3,2,2,1,0,3,0,0,0,0,0,2,3,3,0,0,1,1,2,3,3,0,1,3,2,0,1,3,3,2,0,0,1,0,2,0,0,0,3,1,3,3,3,3,3},{0,1,5,6,7,-1},{0,5}},
    {{2,3,2,3,0,2,3,0,2,2,3,0,3,2,0,2,1,0,2,3,1,1,1,0,0,1,0,2,1,2,2,1,3,0,2,1,2,3,3,0,3,2,3,1,0,2,1,0,1,2,2,3,0,2,1,3,1,3,0,2,1,1,1,3},{2,3,4,6,7,-1},{6,7}},
    {{3,0,2,1,1,3,1,2,2,1,2,2,2,0,0,1,2,3,1,0,2,0,0,2,3,1,2,0,0,0,3,0,2,1,1,2,0,0,1,2,3,1,1,2,0,1,3,0,3,1,1,0,0,2,3,0,0,0,0,3,2,0,0,0},{0,2,3,4,5,6},{1,4}},
    {{0,1,0,0,2,1,3,2,3,3,2,1,0,1,1,1,1,1,0,3,3,1,1,0,0,2,2,1,0,3,3,2,1,3,3,0,3,0,2,1,1,2,3,2,2,2,1,0,0,3,3,3,2,2,3,1,0,2,3,0,3,1,1,0},{0,1,2,3,5,7},{2,3}},
    {{1,1,1,1,1,0,1,3,3,2,3,0,1,2,0,2,3,3,0,1,2,1,2,3,0,3,2,3,2,0,1,2,0,1,0,3,2,1,3,2,3,1,2,3,2,0,1,2,2,0,0,0,2,1,3,0,3,1,3,0,1,3,3,0},{1,2,3,4,5,7},{0,4}},
    {{3,0,0,0,0,1,0,2,3,3,1,3,0,3,1,2,2,2,3,1,0,0,2,0,1,0,2,2,3,3,0,0,1,1,3,0,2,3,0,3,0,3,0,2,0,2,0,1,0,3,0,1,3,1,1,0,0,1,3,3,2,2,1,0},{0,1,2,3,5,6},{1,3}},
    {{0,1,1,2,0,1,3,1,2,0,3,2,0,0,3,0,3,0,1,2,2,3,3,2,3,2,0,1,0,0,1,0,3,0,2,3,0,2,2,2,1,1,0,2,2,0,0,1,2,1,1,1,2,3,0,3,1,2,3,3,1,1,3,0},{0,2,4,5,6,7},{2,6}},
    {{0,1,2,2,0,1,0,3,2,2,1,1,3,2,0,2,0,1,3,3,0,2,2,3,3,2,0,0,2,1,3,3,1,1,1,3,1,2,1,1,0,3,3,2,3,2,3,0,3,1,0,0,3,0,0,0,2,2,2,1,2,3,0,0},{0,1,3,4,6,7},{5,7}},
};

static const struct cps2_sbox fn2_boxes[16] = {
    {{2,0,2,0,3,0,0,3,1,1,0,1,3,2,0,1,2,0,1,2,0,2,0,2,2,2,3,0,2,1,3,0,0,1,0,1,2,2,3,3,0,3,0,2,3,0,1,2,1,1,0,2,0,3,1,1,2,2,1,3,1,1,3,1},{0,3,4,5,7,-1},{6,7}},
    {{1,1,0,3,0,2,0,1,3,0,2,0,1,1,0,0,1,3,2,2,0,2,2,2,2,0,1,3,3,3,1,1,1,3,1,3,2,2,2,2,2,2,0,1,0,1,1,2,3,1,1,2,0,3,3,3,2,2,3,1,1,1,3,0},{1,2,3,4,6,-1},{3,5}},
    {{1,0,2,2,3,3,3,3,1,2,2,1,0,1,2,1,1,2,3,1,2,0,0,1,2,3,1,2,0,0,0,2,2,0,1,1,0,0,2,0,0,0,2,3,2,3,0,1,3,0,0,0,2,3,2,0,1,3,2,1,3,1,1,3},{1,2,4,5,6,7},{1,4}},
    {{1,3,3,0,3,2,3,1,3,2,1,1,3,3,2,1,2,3,0,3,1,0,0,2,3,0,0,0,3,3,0,1,2,3,0,0,0,1,2,1,3,0,0,1,0,2,2,2,3,3,1,2,1,3,0,0,0,3,0,1,3,2,2,0},{0,2,3,5,6,7},{0,2}},
    {{3,1,3,0,3,0,3,1,3,0,0,1,1,3,0,3,1,1,0,1,2,3,2,3,3,1,2,2,2,0,2,3,2,2,2,1,1,3,3,0,3,1,2,1,1,1,0,2,0,3,3,0,0,2,0,0,1,1,2,1,2,1,1,0},{0,2,4,6,-1,-1},{4,6}},
    {{0,3,0,3,3,2,1,2,3,1,1,1,2,0,2,3,0,3,1,2,2,1,3,3,3,2,1,2,2,0,1,0,2,3,0,1,2,0,1,1,2,0,2,1,2,0,2,3,3,1,0,2,3,3,0,3,1,1,3,0,0,1,2,0},{1,3,4,5,6,7},{0,3}},
    {{0,0,2,1,3,2,1,0,1,2,2,2,1,1,0,3,1,2,2,3,2,1,1,0,3,0,0,1,1,2,3,1,3,3,2,2,1,0,1,1,1,2,0,1,2,3,0,3,3,0,3,2,2,0,2,2,1,2,3,2,1,0,2,1},{0,1,3,4,5,7},{1,7}},
    {{0,2,1,2,0,2,2,0,1,3,2,0,3,2,3,0,3,3,2,3,1,2,3,1,2,2,0,0,2,2,1,2,2,3,3,3,1,1,0,0,0,3,2,0,3,2,3,1,1,1,1,0,1,0,1,3,0,0,1,2,2,3,2,0},{1,2,3,5,6,7},{2,5}},
    {{2,1,2,1,2,3,1,3,2,2,1,3,3,0,0,1,0,2,0,3,3,1,0,0,1,1,0,2,3,2,1,2,1,1,2,1,1,3,2,2,0,2,2,3,3,3,2,0,0,0,0,0,3,3,3,0,1,2,1,0,2,3,3,1},{2,3,4,6,-1,-1},{3,5}},
    {{3,2,3,3,1,0,3,0,2,0,1,1,1,0,3,0,3,1,3,1,0,1,2,3,2,2,3,2,0,1,1,2,3,0,0,2,1,0,0,2,2,0,1,0,0,2,0,0,1,3,1,3,2,0,3,3,1,0,2,2,2,3,0,0},{0,1,3,5,7,-1},{0,2}},
    {{2,2,1,0,2,3,3,0,0,0,1,3,1,2,3,2,2,3,1,3,0,3,0,3,3,2,2,1,0,0,0,2,1,2,2,2,0,0,1,2,0,1,3,0,2,3,2,1,3,2,2,2,3,1,3,0,2,0,2,1,0,3,3,1},{0,1,2,3,5,7},{1,6}},
    {{1,2,3,2,0,2,1,3,3,1,0,1,1,2,2,0,0,1,1,1,2,1,1,2,0,1,3,3,1,1,1,2,3,3,1,0,2,1,1,1,2,1,0,0,2,2,3,2,3,2,2,0,2,2,3,3,0,2,3,0,2,2,1,1},{0,2,4,5,6,7},{4,7}},
    {{2,0,1,1,2,1,3,3,1,1,1,2,0,1,0,2,0,1,2,0,2,3,0,2,3,3,2,2,3,2,0,1,3,0,2,0,2,3,1,3,2,0,0,1,1,2,3,1,1,1,0,1,2,0,3,3,1,1,1,3,3,1,1,0},{0,1,3,6,7,-1},{0,3}},
    {{1,2,2,1,0,3,3,1,0,2,2,2,1,0,1,0,1,1,0,1,0,2,1,0,2,1,0,2,3,2,3,3,2,2,1,2,2,3,1,3,3,3,0,1,0,1,3,0,0,0,1,2,0,3,3,2,3,2,1,3,2,1,0,2},{0,1,2,4,5,6},{4,7}},
    {{2,3,2,1,3,2,3,0,0,2,1,1,0,0,3,2,3,1,0,1,2,2,2,1,3,2,2,1,0,2,1,2,0,3,1,0,0,3,1,1,3,3,2,0,1,0,1,3,0,0,1,2,1,2,3,2,1,0,0,3,2,1,1,3},{0,2,3,4,5,7},{1,2}},
    {{2,0,0,3,2,2,2,1,3,3,1,1,2,0,0,3,1,0,3,2,1,0,2,0,3,2,2,3,2,0,3,0,1,3,0,2,2,1,3,3,0,1,0,3,1,1,3,2,0,3,0,2,3,2,1,3,2,3,0,0,1,3,2,1},{2,3,4,5,6,7},{5,6}},
};

static const u8 exp1_bits[96] = {
    33,58,49,36, 0,31, 22,30, 3,16, 5,53, 10,41,23,19,27,39, 43, 6,34,12,61,21,
    48,13,32,35, 6,42, 43,14,21,41,52,25, 18,47,46,37,57,53, 20, 8,55,54,59,60,
    27,33,35,18, 8,15, 63, 1,50,44,16,46,  5, 4,45,51,38,25, 13,11,62,29,48, 2,
    59,61,62,56,51,57, 54, 9,24,63,22, 7, 26,42,45,40,23,14,  2,31,52,28,44,17
};

static const u8 exp2_bits[96] = {
    34, 9,32,24,44,54, 38,61,47,13,28, 7, 29,58,18, 1,20,60, 15, 6,11,43,39,19,
    63,23,16,62,54,40, 31, 3,56,61,17,25, 47,38,55,57, 5, 4, 15,42,22, 7, 2,19,
    46,37,29,39,12,30, 49,57,31,41,26,27, 24,36,11,63,33,16, 56,62,48,60,59,32,
    12,30,53,48,10, 0, 50,35, 3,59,14,49, 51,45,44, 2,21,33, 55,52,23,28, 8,26
};

static const u8 subkey_bits[64] = {
     5,10,14, 9, 4, 0,15, 6, 1, 8, 3, 2,12, 7,13,11,
     5,12, 7, 2,13,11, 9,14, 4, 1, 6,10, 8, 0,15, 3,
     4,10, 2, 0, 6, 9,12, 1,11, 7,15, 8,13, 5,14, 3,
    14,11,12, 7, 4, 5, 2,10, 1,15, 0, 9, 8, 6,13, 3
};

static void cps2_opt_init(struct cps2_opt_sbox *out, const struct cps2_sbox *in)
{
    for (int b = 0; b < 16; b++) {
        for (u32 v = 0; v < 256; v++) {
            u8 res = 0;
            for (int i = 0; i < 6; i++)
                if (in[b].inputs[i] >= 0)
                    res |= (u8)(CBIT(v, in[b].inputs[i]) << i);
            out[b].in_lut[v] = res;
        }
        for (int i = 0; i < 64; i++) {
            u8 o = in[b].table[i], msk = 0;
            if (o & 1) msk |= (u8)(1u << in[b].outputs[0]);
            if (o & 2) msk |= (u8)(1u << in[b].outputs[1]);
            out[b].out[i] = msk;
        }
    }
}

INLINE u8 cps2_fn(u8 in, const struct cps2_opt_sbox *sb, u32 key)
{
    return sb[0].out[sb[0].in_lut[in] ^ ((key >>  0) & 0x3Fu)] |
           sb[1].out[sb[1].in_lut[in] ^ ((key >>  6) & 0x3Fu)] |
           sb[2].out[sb[2].in_lut[in] ^ ((key >> 12) & 0x3Fu)] |
           sb[3].out[sb[3].in_lut[in] ^ ((key >> 18) & 0x3Fu)];
}

static u16 cps2_feistel(u16 val, const u8 *ba, const u8 *bb, const struct cps2_opt_sbox *sb,
                        u32 k0, u32 k1, u32 k2, u32 k3)
{
    u8 l = 0, r = 0;
    for (int i = 0; i < 8; i++) {
        l |= (u8)(CBIT(val, bb[i]) << i);
        r |= (u8)(CBIT(val, ba[i]) << i);
    }
    l ^= cps2_fn(r, &sb[0],  k0);
    r ^= cps2_fn(l, &sb[4],  k1);
    l ^= cps2_fn(r, &sb[8],  k2);
    r ^= cps2_fn(l, &sb[12], k3);
    u16 out = 0;
    for (int i = 0; i < 8; i++) {
        out |= (u16)(CBIT(l, i) << ba[i]);
        out |= (u16)(CBIT(r, i) << bb[i]);
    }
    return out;
}

static void cps2_expand_key(u32 *dst, const u32 *src, const u8 *perm)
{
    dst[0] = dst[1] = dst[2] = dst[3] = 0;
    for (int i = 0; i < 96; i++)
        dst[i / 24] |= CBIT(src[perm[i] >> 5], perm[i] & 31) << (i % 24);
}

/* Decrypt `S.rom` (already in host u16 word order!) into `S.code` using CPS-2 64-bit master key */
static void cps2_decrypt_rom(const u32 master_key[2], u32 lower_bytes, u32 upper_bytes)
{
    static struct cps2_opt_sbox sb1[16], sb2[16];
    cps2_opt_init(sb1, fn1_boxes);
    cps2_opt_init(sb2, fn2_boxes);

    u32 len = upper_bytes ? upper_bytes : S.rom_len;
    if (len > S.rom_len) len = S.rom_len;
    if (len > CODE_CAP)  len = CODE_CAP;
    S.code = CODE_BUF;
    S.code_len = len;

    const u16 *rom16 = (const u16 *)S.rom;
    u16 *dec16 = (u16 *)S.code;
    u32 lo_w = lower_bytes >> 1, hi_w = len >> 1;

    u32 key1[4];
    cps2_expand_key(key1, master_key, exp1_bits);
    key1[0] ^= CBIT(key1[0], 1) << 4;
    key1[0] ^= CBIT(key1[0], 2) << 5;
    key1[0] ^= CBIT(key1[0], 8) << 11;
    key1[1] ^= CBIT(key1[1], 0) << 5;
    key1[1] ^= CBIT(key1[1], 8) << 11;
    key1[2] ^= CBIT(key1[2], 1) << 5;
    key1[2] ^= CBIT(key1[2], 8) << 11;

    for (u32 i = 0; i < 0x10000u; i++) {
        if ((i & 0xFFFu) == 0)
            CPS_FEED_DOG();
        u16 seed = cps2_feistel((u16)i, fn1_grpA, fn1_grpB, sb1, key1[0], key1[1], key1[2], key1[3]);
        u32 sub[2] = {0, 0};
        for (int b = 0; b < 64; b++)
            sub[b >> 5] |= CBIT(seed, subkey_bits[b]) << (b & 31);
        sub[0] ^= master_key[0];
        sub[1] ^= master_key[1];

        u32 key2[4];
        cps2_expand_key(key2, sub, exp2_bits);
        key2[0] ^= CBIT(key2[0], 0) << 5;
        key2[0] ^= CBIT(key2[0], 6) << 11;
        key2[1] ^= CBIT(key2[1], 0) << 5;
        key2[1] ^= CBIT(key2[1], 1) << 4;
        key2[2] ^= CBIT(key2[2], 2) << 5;
        key2[2] ^= CBIT(key2[2], 3) << 4;
        key2[2] ^= CBIT(key2[2], 7) << 11;
        key2[3] ^= CBIT(key2[3], 1) << 5;

        for (u32 a = i; a < hi_w; a += 0x10000u) {
            if (a >= lo_w)
                dec16[a] = cps2_feistel(rom16[a], fn2_grpA, fn2_grpB, sb2, key2[0], key2[1], key2[2], key2[3]);
            else
                dec16[a] = rom16[a];
        }
    }
}

/* Decode MAME 20-byte .key file into master_key[2], lower_bytes, upper_bytes */
static void cps2_parse_key20(const u8 key20[20], u32 out_key[2], u32 *out_lo, u32 *out_hi)
{
    u16 dec[10];
    for (int i = 0; i < 10; i++) dec[i] = 0;
    for (int b = 0; b < 160; b++) {
        int bit = (317 - b) % 160;
        if ((key20[bit / 8] >> ((bit ^ 7) % 8)) & 1)
            dec[b / 16] |= (u16)(0x8000u >> (b % 16));
    }
    out_key[0] = ((u32)dec[0] << 16) | dec[1];
    out_key[1] = ((u32)dec[2] << 16) | dec[3];
    if (dec[9] == 0xFFFFu) {
        *out_lo = 0xFF0000u;
        *out_hi = 0x1000000u;
    } else {
        *out_lo = 0;
        *out_hi = ((((u32)~dec[9] & 0x3FFu) << 14) | 0x3FFFu) + 1u;
    }
}

/* Kabuki Z80 decryption (CPS-1 / CPS-1.5) */
static u8 kabuki_bswap1(u8 src, u16 key, u8 sel)
{
    if (sel & (1u << ((key >>  0) & 7))) src = (u8)((src & 0xFCu) | ((src & 0x01u) << 1) | ((src & 0x02u) >> 1));
    if (sel & (1u << ((key >>  4) & 7))) src = (u8)((src & 0xF3u) | ((src & 0x04u) << 1) | ((src & 0x08u) >> 1));
    if (sel & (1u << ((key >>  8) & 7))) src = (u8)((src & 0xCFu) | ((src & 0x10u) << 1) | ((src & 0x20u) >> 1));
    if (sel & (1u << ((key >> 12) & 7))) src = (u8)((src & 0x3Fu) | ((src & 0x40u) << 1) | ((src & 0x80u) >> 1));
    return src;
}

static u8 kabuki_bswap2(u8 src, u16 key, u8 sel)
{
    if (sel & (1u << ((key >> 12) & 7))) src = (u8)((src & 0xFCu) | ((src & 0x01u) << 1) | ((src & 0x02u) >> 1));
    if (sel & (1u << ((key >>  8) & 7))) src = (u8)((src & 0xF3u) | ((src & 0x04u) << 1) | ((src & 0x08u) >> 1));
    if (sel & (1u << ((key >>  4) & 7))) src = (u8)((src & 0xCFu) | ((src & 0x10u) << 1) | ((src & 0x20u) >> 1));
    if (sel & (1u << ((key >>  0) & 7))) src = (u8)((src & 0x3Fu) | ((src & 0x40u) << 1) | ((src & 0x80u) >> 1));
    return src;
}

static u8 kabuki_byte(u8 src, u32 sw1, u32 sw2, u8 xk, u32 sel)
{
    src = kabuki_bswap1(src, (u16)(sw1 & 0xFFFFu), (u8)(sel & 0xFFu));
    src = (u8)(((src & 0x7Fu) << 1) | ((src & 0x80u) >> 7));
    src = kabuki_bswap2(src, (u16)(sw1 >> 16), (u8)(sel & 0xFFu));
    src ^= xk;
    src = (u8)(((src & 0x7Fu) << 1) | ((src & 0x80u) >> 7));
    src = kabuki_bswap2(src, (u16)(sw2 & 0xFFFFu), (u8)((sel >> 8) & 0xFFu));
    src = (u8)(((src & 0x7Fu) << 1) | ((src & 0x80u) >> 7));
    src = kabuki_bswap1(src, (u16)(sw2 >> 16), (u8)((sel >> 8) & 0xFFu));
    return src;
}

static void kabuki_decode_rom(const u8 *src, u32 sw1, u32 sw2, u16 addr_key, u8 xor_key)
{
    for (u32 a = 0; a < 0x8000u; a++) {
        u8 b = (a < S.zrom_len) ? src[a] : 0xFFu;
        M->kabuki_op[a]   = kabuki_byte(b, sw1, sw2, xor_key, a + addr_key);
        M->kabuki_data[a] = kabuki_byte(b, sw1, sw2, xor_key, (a ^ 0x1FC0u) + addr_key + 1u);
    }
    S.has_kabuki = 1;
}

/* ---- 93C46 Serial EEPROM (CPS-2: 64x16, CPS-1.5: 128x8) ---- */

static u8 eeprom_read_bit(void)
{
    return S.eep.do_bit ? 1u : 0u;
}

static void eeprom_write_pins(int clk, int cs, int di)
{
    u8 new_cs = cs ? 1u : 0u;
    u8 new_clk = clk ? 1u : 0u;
    u8 new_di = di ? 1u : 0u;

    if (!new_cs) {
        S.eep.cs = 0;
        S.eep.clk = new_clk;
        S.eep.di = new_di;
        S.eep.state = 0;
        S.eep.do_bit = 1;               /* Ready high */
        return;
    }
    if (!S.eep.cs && new_cs) {
        S.eep.state = 1;                /* Waiting for start bit '1' */
        S.eep.shift = 0;
        S.eep.bits = 0;
        S.eep.do_bit = 1;
    }
    /* Rising clock edge */
    if (!S.eep.clk && new_clk) {
        u32 abits = S.eeprom_16bit ? 6u : 7u;
        u32 dbits = S.eeprom_16bit ? 16u : 8u;
        switch (S.eep.state) {
        case 1:
            if (new_di) {
                S.eep.state = 2;
                S.eep.shift = 0;
                S.eep.bits = 0;
            }
            break;
        case 2:
            S.eep.shift = (S.eep.shift << 1) | new_di;
            S.eep.bits++;
            if (S.eep.bits == 2u + abits) {
                u32 op = (S.eep.shift >> abits) & 3u;
                u32 addr = S.eep.shift & ((1u << abits) - 1u);
                if (op == 2u) {         /* 10: READ */
                    if (S.eeprom_16bit) {
                        u32 o = (addr * 2u) & 0x7Eu;
                        S.eep.shift = ((u32)M->eeprom[o] << 8) | M->eeprom[o + 1u];
                    } else {
                        S.eep.shift = M->eeprom[addr & 0x7Fu];
                    }
                    S.eep.bits = dbits + 1u; /* Dummy 0 bit + data */
                    S.eep.do_bit = 0;
                    S.eep.state = 3;
                } else if (op == 1u) {  /* 01: WRITE */
                    S.eep.write_addr = addr;
                    S.eep.shift = 0;
                    S.eep.bits = 0;
                    S.eep.state = 4;
                } else if (op == 3u) {  /* 11: ERASE */
                    if (S.eep.write_en) {
                        if (S.eeprom_16bit) {
                            u32 o = (addr * 2u) & 0x7Eu;
                            M->eeprom[o] = M->eeprom[o + 1u] = 0xFFu;
                        } else {
                            M->eeprom[addr & 0x7Fu] = 0xFFu;
                        }
                        S.eeprom_dirty = 1;
                    }
                    S.eep.do_bit = 1;
                    S.eep.state = 0;
                } else {                /* 00: EWEN / EWDS / ERAL / WRAL */
                    u32 sub = (addr >> (abits - 2u)) & 3u;
                    if (sub == 3u) S.eep.write_en = 1;
                    else if (sub == 0u) S.eep.write_en = 0;
                    else if (sub == 2u && S.eep.write_en) {
                        for (int i = 0; i < 0x80; i++) M->eeprom[i] = 0xFFu;
                        S.eeprom_dirty = 1;
                    }
                    S.eep.state = 0;
                }
            }
            break;
        case 3:
            if (S.eep.bits > 1u) {
                S.eep.bits--;
                S.eep.do_bit = (u8)((S.eep.shift >> (S.eep.bits - 1u)) & 1u);
            } else {
                S.eep.do_bit = 1;
            }
            break;
        case 4:
            S.eep.shift = (S.eep.shift << 1) | new_di;
            S.eep.bits++;
            if (S.eep.bits == dbits) {
                if (S.eep.write_en) {
                    if (S.eeprom_16bit) {
                        u32 o = (S.eep.write_addr * 2u) & 0x7Eu;
                        M->eeprom[o]      = (u8)(S.eep.shift >> 8);
                        M->eeprom[o + 1u] = (u8)(S.eep.shift & 0xFFu);
                    } else {
                        M->eeprom[S.eep.write_addr & 0x7Fu] = (u8)(S.eep.shift & 0xFFu);
                    }
                    S.eeprom_dirty = 1;
                }
                S.eep.do_bit = 1;
                S.eep.state = 0;
            }
            break;
        }
    }
    S.eep.cs = new_cs;
    S.eep.clk = new_clk;
    S.eep.di = new_di;
}

/* ---- Palette DMA & BGR555 Conversion ---- */

static u8 *find_gfx_ram(u32 addr, u32 len)
{
    addr &= 0xFFFFFFu;
    if (addr >= 0x900000u && addr + len <= 0x930000u)
        return M->ram90 + (addr - 0x900000u);
    return 0;
}

static void cps_latch_palette(int force_all)
{
    u32 pal_addr = ((u32)reg16(S.cps_reg, 0x0Au) << 8) & 0xFFFC00u;
    const u16 *src = (const u16 *)find_gfx_ram(pal_addr, 0);
    if (!src)
        return;
    u32 max_words = (0x930000u - pal_addr) >> 1;
    u32 ctrl = reg16(S.cps_reg, S.pal_ctrl_reg) & 0x3Fu;
    if (force_all && !ctrl)
        ctrl = 0x3Fu;
    if (!ctrl)
        return;

    u32 rd_idx = 0;
    for (u32 page = 0; page < 6u; page++) {
        if (ctrl & (1u << page)) {
            u32 base = page << 9;
            for (u32 off = 0; off < 0x200u; off++) {
                u16 raw = (rd_idx < max_words) ? src[rd_idx++] : 0;
                M->pal_save[base + off] = raw;
                /* CPS color: [15:12]=bright, [11:8]=R4, [7:4]=G4, [3:0]=B4 -> BGR555 */
                u32 br = 0x0Fu + (((u32)(raw >> 12) & 0x0Fu) << 1);
                u32 r8 = (((raw >> 8) & 0x0Fu) * 0x11u * br) / 0x2Du;
                u32 g8 = (((raw >> 4) & 0x0Fu) * 0x11u * br) / 0x2Du;
                u32 b8 = (((raw >> 0) & 0x0Fu) * 0x11u * br) / 0x2Du;
                if (r8 > 255u) r8 = 255u;
                if (g8 > 255u) g8 = 255u;
                if (b8 > 255u) b8 = 255u;
                M->pal15[base + (off ^ 15u)] = (u16)(((b8 >> 3) << 10) | ((g8 >> 3) << 5) | (r8 >> 3));
            }
            S.pal_latched_once = 1;
        }
    }
}

/* ---- Audio Subsystem 1: Capcom DL-1425 16-Voice QSound DSP ---- */

static const u16 q_pan_tab[33] = {
    0, 45, 64, 78, 91, 101, 111, 120, 128, 136, 143, 150, 157, 163, 169, 175,
    181, 187, 192, 197, 202, 207, 212, 217, 222, 226, 231, 235, 239, 244, 248, 252, 256
};

static void qsc_map_bank(struct q_chan *pc)
{
    u32 off = ((u32)(pc->bank & 0x7Fu)) << 16;
    if (off + 0x10000u > S.snd_len)
        off = 0;
    pc->bank_ptr = S.qsam + off;
}

static void qsc_calc_adv(struct q_chan *pc)
{
    pc->adv = (s32)(((u32)pc->pitch * S.q_pitch_scale) >> 12);
}

static void qsc_reset(void)
{
    cps_zero(S.qch, sizeof(S.qch));
    for (int i = 0; i < 16; i++) {
        S.qch[i].bank_ptr = S.qsam;
        S.qch[i].vol_l = S.qch[i].vol_r = 181;
    }
}

static void snd_push_sample(s32 s)
{
    if (s > 32767) s = 32767;
    else if (s < -32768) s = -32768;
    u32 next = (S.snd_head + 1u) & (SND_RING - 1u);
    if (next != S.snd_tail) {
        M->snd_ring[S.snd_head] = (s16)s;
        S.snd_head = next;
    }
}

static void qsc_render_to(u32 target_samples)
{
    if (!S.snd_rate || target_samples <= S.snd_rendered || !S.qsam || !S.snd_len)
        return;
    u32 n = target_samples - S.snd_rendered;
    S.snd_rendered = target_samples;

    s32 mix_buf[1024];
    while (n > 0) {
        u32 chunk = n > 1024u ? 1024u : n;
        cps_zero(mix_buf, chunk * sizeof(s32));
        for (int c = 0; c < 16; c++) {
            struct q_chan *pc = &S.qch[c];
            if (!pc->key)
                continue;
            s32 gain = (pc->master_vol * (pc->vol_l + pc->vol_r)) >> 14;
            if (!gain) {
                if (pc->key & 2u) { pc->key &= ~2u; pc->pos = pc->play_start + (s32)(chunk - 1u) * pc->adv; }
                else              { pc->pos += (s32)chunk * pc->adv; }
                if (pc->pos >= pc->end) {
                    if (pc->loop > 0 && pc->end > pc->loop) {
                        while (pc->pos >= pc->end) pc->pos -= pc->loop;
                    } else {
                        pc->key = 0;
                    }
                }
                continue;
            }
            const s8 *bptr = pc->bank_ptr;
            s32 pos = pc->pos, adv = pc->adv, end = pc->end, loop = pc->loop;
            if (pc->key & 2u) {
                pc->key &= ~2u;
                pos = pc->play_start;
                for (u32 i = 0; i < chunk; i++) {
                    if (pos >= end) {
                        if (loop > 0 && end > loop) { while (pos >= end) pos -= loop; }
                        else { pc->key = 0; break; }
                    }
                    u32 idx = (u32)(pos >> 12) & 0xFFFFu;
                    s32 s0 = bptr[idx], s1 = bptr[(idx + 1u) & 0xFFFFu];
                    s32 smp = s0 + (((s1 - s0) * (s32)(pos & 0xFFFu)) >> 12);
                    mix_buf[i] += smp * gain;
                    pos += adv;
                }
                pos -= adv;
            } else {
                for (u32 i = 0; i < chunk; i++) {
                    pos += adv;
                    if (pos >= end) {
                        if (loop > 0 && end > loop) { while (pos >= end) pos -= loop; }
                        else { pc->key = 0; break; }
                    }
                    u32 idx = (u32)(pos >> 12) & 0xFFFFu;
                    s32 s0 = bptr[idx], s1 = bptr[(idx + 1u) & 0xFFFFu];
                    s32 smp = s0 + (((s1 - s0) * (s32)(pos & 0xFFFu)) >> 12);
                    mix_buf[i] += smp * gain;
                }
            }
            pc->pos = pos;
        }
        for (u32 i = 0; i < chunk; i++)
            snd_push_sample(mix_buf[i] >> 2);
        n -= chunk;
    }
}

static void qsc_sync(void)
{
    if (!S.snd_rate || S.zcyc_per_frame <= 0)
        return;
    s32 zc = S.z.cycles;
    if (zc < 0) zc = 0;
    if (zc > S.zcyc_per_frame) zc = S.zcyc_per_frame;
    u32 frame_samples = (S.snd_rate * 100u) / 5963u;
    u32 target = ((u32)zc * frame_samples) / (u32)S.zcyc_per_frame;
    qsc_render_to(target);
}

static void qsc_write(u8 reg, u16 data)
{
    if (reg >= 0x90u)
        return;
    qsc_sync();
    if (reg >= 0x80u) {
        struct q_chan *pc = &S.qch[reg & 15u];
        u32 pan = (data - 0x10u) & 0x3Fu;
        if (pan > 0x20u) pan = 0x20u;
        pc->vol_l = q_pan_tab[0x20u - pan];
        pc->vol_r = q_pan_tab[pan];
        return;
    }
    u32 ch = (reg >> 3) & 15u;
    u32 r = reg & 7u;
    struct q_chan *pc = &S.qch[ch];
    switch (r) {
    case 0:
        /* Real DL-1425 hardware quirk: reg 0 sets bank of (ch + 1) & 15 */
        pc = &S.qch[(ch + 1u) & 15u];
        pc->bank = (u8)data;
        qsc_map_bank(pc);
        break;
    case 1:
        pc->start = (s32)data << 12;
        break;
    case 2:
        pc->pitch = (s32)data;
        qsc_calc_adv(pc);
        if (data == 0)
            pc->key = 0;
        break;
    case 4:
        pc->loop = (s32)data << 12;
        break;
    case 5:
        pc->end = (s32)data << 12;
        break;
    case 6:
        pc->master_vol = (s32)data;
        if (data == 0) {
            pc->key = 0;
        } else if (pc->key == 0) {
            pc->play_start = pc->start;
            pc->pos = 0;
            pc->key = 3u;
        }
        break;
    }
}

/* ---- Audio Subsystem 2: CPS-1 Yamaha YM2151 (OPM) + OKIM6295 ADPCM ---- */

enum { EG_ATT, EG_DEC, EG_SUS, EG_REL };

static const u16 opm_logsin[256] = {
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

static const u16 opm_exp2[256] = {
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

static const u8 opm_dt1_tab[4][32] = {
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0,0,0,0,1,1,1,1,1,1,1,1,2,2,2,2,2,3,3,3,4,4,4,5,5,6,6,7,8,8,8,8},
    {1,1,1,1,2,2,2,2,2,3,3,3,4,4,4,5,5,6,6,7,8,8,9,10,11,12,13,14,16,16,16,16},
    {2,2,2,2,2,3,3,3,4,4,4,5,5,6,6,7,8,8,9,10,11,12,13,14,16,17,19,20,22,22,22,22}
};

static const u8 opm_eg_steps[20][8] = {
    {0,1,0,1,0,1,0,1}, {0,1,0,1,1,1,0,1}, {0,1,1,1,0,1,1,1}, {0,1,1,1,1,1,1,1},
    {1,1,1,1,1,1,1,1}, {1,1,1,2,1,1,1,2}, {1,2,1,2,1,2,1,2}, {1,2,2,2,1,2,2,2},
    {2,2,2,2,2,2,2,2}, {2,2,2,4,2,2,2,4}, {2,4,2,4,2,4,2,4}, {2,4,4,4,2,4,4,4},
    {4,4,4,4,4,4,4,4}, {4,4,4,8,4,4,4,8}, {4,8,4,8,4,8,4,8}, {4,8,8,8,4,8,8,8},
    {8,8,8,8,8,8,8,8}, {8,8,8,8,8,8,8,8}, {8,8,8,8,8,8,8,8}, {8,8,8,8,8,8,8,8}
};

/* Concert-pitch phase increments at 24 kHz (20-bit phase) for Octave 7 C#7..C#8 */
static const u32 opm_inc7[13] = {
    96887, 102648, 108751, 115217, 122068, 129327,
    137017, 145164, 153796, 162941, 172630, 182895, 193774
};
static const u8 opm_kc_to_semi[16] = {0, 1, 2, 2, 3, 4, 5, 5, 6, 7, 8, 8, 9, 10, 11, 11};
static const u16 opm_dt2_kf[4] = {0, 384, 500, 608};

/* OKIM6295 49-entry 12-bit ADPCM step table & volume attenuation */
static const u16 oki_step[49] = {
    16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66,
    73, 80, 88, 97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307,
    337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552
};
static const s8 oki_idx_chg[8] = {-1, -1, -1, -1, 2, 4, 6, 8};
static const u16 oki_vol_tab[16] = {256, 181, 128, 90, 64, 45, 32, 23, 16, 0, 0, 0, 0, 0, 0, 0};

static void opm_op_env(struct opm_op *o)
{
    u32 e = (u32)o->att + ((u32)o->tl << 3);
    o->env = e > 0x3FFu ? 0x3FFu : e;
}

static u8 opm_eff_rate(u8 r, u8 kcode, u8 ks)
{
    if (!r)
        return 0;
    u32 v = (u32)r * 2u + (kcode >> (3u - (ks & 3u)));
    return (u8)(v > 63u ? 63u : v);
}

static void opm_op_update(struct opm_ch *c, int n)
{
    struct opm_op *o = &c->op[n];
    u32 oct = (c->kc >> 4) & 7u;
    u32 semi = opm_kc_to_semi[c->kc & 15u];
    u32 kcode = (oct << 2) | (semi >> 2);
    u32 total_kf = oct * 768u + semi * 64u + (c->kf & 63u) + opm_dt2_kf[o->dt2 & 3u];
    u32 eo = total_kf / 768u;
    u32 rem = total_kf - eo * 768u;
    u32 es = rem >> 6;
    u32 ef = rem & 63u;
    u32 base = opm_inc7[es] + (((opm_inc7[es + 1u] - opm_inc7[es]) * ef) >> 6);
    u32 inc = (eo <= 7u) ? (base >> (7u - eo)) : (base << (eo - 7u));
    if (S.snd_rate && S.snd_rate != 48000u)
        inc = (inc * 48000u) / S.snd_rate;
    u32 dt = opm_dt1_tab[o->dt1 & 3u][kcode & 31u] * 2u;
    inc = (o->dt1 & 4u) ? (inc > dt ? inc - dt : 0u) : (inc + dt);
    o->inc = (o->mul ? inc * o->mul : (inc >> 1)) & 0xFFFFFu;
    o->rate[EG_ATT] = opm_eff_rate(o->ar, (u8)kcode, o->ks);
    o->rate[EG_DEC] = opm_eff_rate(o->d1r, (u8)kcode, o->ks);
    o->rate[EG_SUS] = opm_eff_rate(o->d2r, (u8)kcode, o->ks);
    o->rate[EG_REL] = opm_eff_rate((u8)(o->rr * 2u + 1u), (u8)kcode, o->ks);
}

static void opm_key(struct opm_ch *c, int n, int on)
{
    struct opm_op *o = &c->op[n];
    if (on) {
        if (o->state == EG_REL) {
            o->phase = 0;
            o->state = EG_ATT;
            if (o->rate[EG_ATT] >= 62u) {
                o->att = 0;
                o->state = o->d1l ? EG_DEC : EG_SUS;
            }
            opm_op_env(o);
            c->quiet = 0;
        }
    } else if (o->state != EG_REL) {
        o->state = EG_REL;
    }
}

static void opm_update_irq(void)
{
    u8 msk = (u8)((S.opm.timer_ctrl >> 2) & 3u);
    S.z.irq = (S.opm.status & msk) ? 1u : 0u;
}

static s32 opm_ta_zcyc(void)
{
    /* YM2151 @ 3.579545 MHz, Z80 @ 4.0 MHz: 64 * 4.0 / 3.579545 ~= 72 Z80 cyc */
    return (s32)(1024u - S.opm.ta_load) * 72;
}

static s32 opm_tb_zcyc(void)
{
    return (s32)(256u - S.opm.tb_load) * 1144;
}

static void opm_write_reg(u8 r, u8 v)
{
    /* OPM slot mapping: slot 0=M1(0), slot 1=M2(2), slot 2=C1(1), slot 3=C2(3) */
    static const u8 slot_map[4] = {0, 2, 1, 3};
    if (r == 0x08u) {
        struct opm_ch *c = &S.opm.ch[v & 7u];
        opm_key(c, 0, (v >> 3) & 1);
        opm_key(c, 1, (v >> 4) & 1);
        opm_key(c, 2, (v >> 5) & 1);
        opm_key(c, 3, (v >> 6) & 1);
        return;
    }
    if (r == 0x0Fu) {
        S.opm.noise_en = (v >> 7) & 1u;
        S.opm.noise_freq = v & 0x1Fu;
        return;
    }
    if (r == 0x10u) { S.opm.ta_load = (u16)((S.opm.ta_load & 3u) | ((u16)v << 2)); return; }
    if (r == 0x11u) { S.opm.ta_load = (u16)((S.opm.ta_load & ~3u) | (v & 3u)); return; }
    if (r == 0x12u) { S.opm.tb_load = v; return; }
    if (r == 0x14u) {
        u8 prev = S.opm.timer_ctrl;
        S.opm.timer_ctrl = v;
        if (!(prev & 1u) && (v & 1u)) S.opm.ta_cnt = opm_ta_zcyc();
        if (!(prev & 2u) && (v & 2u)) S.opm.tb_cnt = opm_tb_zcyc();
        if (v & 0x10u) S.opm.status &= ~1u;
        if (v & 0x20u) S.opm.status &= ~2u;
        opm_update_irq();
        return;
    }
    if (r >= 0x20u && r < 0x28u) {
        struct opm_ch *c = &S.opm.ch[r & 7u];
        c->rl = (v >> 6) & 3u;
        c->fb = (v >> 3) & 7u;
        c->alg = v & 7u;
        return;
    }
    if (r >= 0x28u && r < 0x30u) {
        struct opm_ch *c = &S.opm.ch[r & 7u];
        c->kc = v & 0x7Fu;
        for (int i = 0; i < 4; i++) opm_op_update(c, i);
        return;
    }
    if (r >= 0x30u && r < 0x38u) {
        struct opm_ch *c = &S.opm.ch[r & 7u];
        c->kf = (v >> 2) & 0x3Fu;
        for (int i = 0; i < 4; i++) opm_op_update(c, i);
        return;
    }
    if (r >= 0x40u) {
        struct opm_ch *c = &S.opm.ch[r & 7u];
        int op_idx = slot_map[(r >> 3) & 3u];
        struct opm_op *o = &c->op[op_idx];
        switch (r & 0xE0u) {
        case 0x40u: o->dt1 = (v >> 4) & 7u; o->mul = v & 0x0Fu; opm_op_update(c, op_idx); break;
        case 0x60u: o->tl = v & 0x7Fu; opm_op_env(o); break;
        case 0x80u: o->ks = (v >> 6) & 3u; o->ar = v & 0x1Fu; opm_op_update(c, op_idx); break;
        case 0xA0u: o->am = (v >> 7) & 1u; o->d1r = v & 0x1Fu; opm_op_update(c, op_idx); break;
        case 0xC0u: o->dt2 = (v >> 6) & 3u; o->d2r = v & 0x1Fu; opm_op_update(c, op_idx); break;
        case 0xE0u:
            o->d1l = (v >> 4) & 0x0Fu;
            if (o->d1l == 15u) o->d1l = 31u;
            o->rr = v & 0x0Fu;
            opm_op_update(c, op_idx);
            break;
        }
    }
}

INLINE s32 opm_calc_op(struct opm_op *o, s32 mod)
{
    u32 p = ((o->phase >> 10) + (u32)mod) & 0x3FFu;
    o->phase = (o->phase + o->inc) & 0xFFFFFu;
    if (o->env >= 0x340u)
        return 0;
    u32 idx = (p & 0x100u) ? (~p & 0xFFu) : (p & 0xFFu);
    u32 lv = (u32)opm_logsin[idx] + (o->env << 2);
    if (lv >= 0x1A00u)
        return 0;
    s32 mag = ((s32)opm_exp2[~lv & 0xFFu] << 2) >> (lv >> 8);
    return (p & 0x200u) ? -mag : mag;
}

static s32 opm_step_24khz(void)
{
    S.opm.eg_div ^= 1u;
    if (!S.opm.eg_div)
        S.opm.eg_cnt++;
    int do_eg = !S.opm.eg_div;
    u32 egc = S.opm.eg_cnt;

    s32 total = 0;
    for (int ch = 0; ch < 8; ch++) {
        struct opm_ch *c = &S.opm.ch[ch];
        if (c->quiet)
            continue;
        if (do_eg) {
            int all_rel = 1;
            for (int n = 0; n < 4; n++) {
                struct opm_op *o = &c->op[n];
                if (o->state != EG_REL || o->att < 0x3FF)
                    all_rel = 0;
                u8 r = o->rate[o->state];
                if (!r)
                    continue;
                u32 sh = (r < 48u) ? (11u - (r >> 2)) : 0u;
                if ((egc & ((1u << sh) - 1u)) != 0)
                    continue;
                u32 st_row = (r < 48u) ? ((r & 3u) + ((r >> 2) >= 12u ? 16u : 0u)) : ((r - 44u) < 20u ? (r - 44u) : 19u);
                if (r < 48u) st_row = r & 3u;
                u8 inc = opm_eg_steps[st_row][(egc >> sh) & 7u];
                if (o->state == EG_ATT) {
                    o->att += (~o->att * (s32)inc) >> 4;
                    if (o->att <= 0) {
                        o->att = 0;
                        o->state = o->d1l ? EG_DEC : EG_SUS;
                    }
                } else {
                    o->att += (s32)inc;
                    if (o->state == EG_DEC && o->att >= ((s32)o->d1l << 5)) {
                        o->att = (s32)o->d1l << 5;
                        o->state = EG_SUS;
                    }
                    if (o->att >= 0x3FF)
                        o->att = 0x3FF;
                }
                opm_op_env(o);
            }
            if (all_rel) {
                c->quiet = 1;
                continue;
            }
        }
        struct opm_op *o0 = &c->op[0], *o1 = &c->op[1], *o2 = &c->op[2], *o3 = &c->op[3];
        s32 fb = c->fb ? ((o0->out + o0->out1) >> (9 - c->fb)) : 0;
        o0->out1 = o0->out;
        o0->out = opm_calc_op(o0, fb);
        s32 v0 = o0->out, out = 0;
        switch (c->alg) {
        case 0: o1->out = opm_calc_op(o1, v0 >> 1); o2->out = opm_calc_op(o2, o1->out >> 1); out = opm_calc_op(o3, o2->out >> 1); break;
        case 1: o1->out = opm_calc_op(o1, 0); o2->out = opm_calc_op(o2, (v0 + o1->out) >> 1); out = opm_calc_op(o3, o2->out >> 1); break;
        case 2: o1->out = opm_calc_op(o1, 0); o2->out = opm_calc_op(o2, o1->out >> 1); out = opm_calc_op(o3, (v0 + o2->out) >> 1); break;
        case 3: o1->out = opm_calc_op(o1, v0 >> 1); o2->out = opm_calc_op(o2, 0); out = opm_calc_op(o3, (o1->out + o2->out) >> 1); break;
        case 4: o1->out = opm_calc_op(o1, v0 >> 1); o2->out = opm_calc_op(o2, 0); out = o1->out + opm_calc_op(o3, o2->out >> 1); break;
        case 5: out = opm_calc_op(o1, v0 >> 1) + opm_calc_op(o2, v0 >> 1) + opm_calc_op(o3, v0 >> 1); break;
        case 6: o1->out = opm_calc_op(o1, v0 >> 1); out = o1->out + opm_calc_op(o2, 0) + opm_calc_op(o3, 0); break;
        default: out = v0 + opm_calc_op(o1, 0) + opm_calc_op(o2, 0) + opm_calc_op(o3, 0); break;
        }
        if (ch == 7 && S.opm.noise_en && o3->env < 0x340u) {
            u32 period = (32u - S.opm.noise_freq);
            if (!period) period = 1u;
            if (++S.opm.noise_cnt >= period) {
                S.opm.noise_cnt = 0;
                S.opm.lfsr = (S.opm.lfsr >> 1) ^ ((S.opm.lfsr & 1u) ? 0x10008u : 0u);
            }
            s32 nmag = (s32)(0x800u >> (o3->env >> 6));
            out += (S.opm.lfsr & 1u) ? nmag : -nmag;
        }
        if (c->rl)
            total += out;
    }
    return total;
}

static void oki_command(u8 d)
{
    if (S.oki.cmd_latch) {
        u8 phrase = S.oki.cmd_latch & 0x7Fu;
        S.oki.cmd_latch = 0;
        u8 ch_mask = (d >> 4) & 0x0Fu;
        u8 vol = d & 0x0Fu;
        u32 base = (u32)phrase * 8u;
        if (!S.ad_rom || base + 6u > S.snd_len)
            return;
        u32 st = (((u32)S.ad_rom[base] << 16) | ((u32)S.ad_rom[base + 1u] << 8) | S.ad_rom[base + 2u]) & 0x3FFFFu;
        u32 en = (((u32)S.ad_rom[base + 3u] << 16) | ((u32)S.ad_rom[base + 4u] << 8) | S.ad_rom[base + 5u]) & 0x3FFFFu;
        if (st >= en || st >= S.snd_len)
            return;
        if (en > S.snd_len)
            en = S.snd_len;
        for (int i = 0; i < 4; i++) {
            if (ch_mask & (1u << i)) {
                struct oki_ch *oc = &S.oki.ch[i];
                oc->pos = st;
                oc->end = en;
                oc->nib_shift = 4;
                oc->acc = 0;
                oc->step_idx = 0;
                oc->cur_out = oc->prev_out = 0;
                oc->vol_idx = vol;
                oc->playing = 1;
            }
        }
    } else if (d & 0x80u) {
        S.oki.cmd_latch = d;
    } else {
        for (int i = 0; i < 4; i++)
            if (d & (0x08u << i))
                S.oki.ch[i].playing = 0;
    }
}

static u8 oki_status(void)
{
    u8 s = 0;
    for (int i = 0; i < 4; i++)
        if (S.oki.ch[i].playing)
            s |= (u8)(1u << i);
    return s;
}

static void oki_step_chip(void)
{
    for (int i = 0; i < 4; i++) {
        struct oki_ch *oc = &S.oki.ch[i];
        if (!oc->playing)
            continue;
        oc->prev_out = oc->cur_out;
        if (oc->pos >= oc->end || oc->pos >= S.snd_len) {
            oc->playing = 0;
            oc->cur_out = 0;
            continue;
        }
        u8 nib = (S.ad_rom[oc->pos] >> oc->nib_shift) & 0x0Fu;
        if (oc->nib_shift) {
            oc->nib_shift = 0;
        } else {
            oc->nib_shift = 4;
            oc->pos++;
        }
        s32 step = oki_step[oc->step_idx];
        s32 diff = step >> 3;
        if (nib & 1u) diff += step >> 2;
        if (nib & 2u) diff += step >> 1;
        if (nib & 4u) diff += step;
        if (nib & 8u) diff = -diff;
        oc->acc += diff;
        if (oc->acc > 2047) oc->acc = 2047;
        else if (oc->acc < -2048) oc->acc = -2048;
        oc->step_idx += oki_idx_chg[nib & 7u];
        if (oc->step_idx < 0) oc->step_idx = 0;
        else if (oc->step_idx > 48) oc->step_idx = 48;
        oc->cur_out = (oc->acc * (s32)oki_vol_tab[oc->vol_idx & 15u]) >> 5;
    }
}

static void psnd_render_to(u32 target_samples)
{
    if (!S.snd_rate || target_samples <= S.snd_rendered)
        return;
    u32 n = target_samples - S.snd_rendered;
    S.snd_rendered = target_samples;

    for (u32 i = 0; i < n; i++) {
        S.opm.sample_toggle ^= 1u;
        if (S.opm.sample_toggle)
            S.opm.cached_sample = opm_step_24khz();
        S.oki.phase_acc += S.oki.rate_hz;
        while (S.oki.phase_acc >= S.snd_rate) {
            S.oki.phase_acc -= S.snd_rate;
            oki_step_chip();
        }
        s32 oki_mix = 0;
        for (int c = 0; c < 4; c++)
            if (S.oki.ch[c].playing)
                oki_mix += S.oki.ch[c].cur_out;
        snd_push_sample((S.opm.cached_sample >> 1) + oki_mix);
    }
}

/* ---- Z80 Bus Mapping & Synchronization ---- */

static void z80_map_bank(u8 bank)
{
    S.z_bank = bank & 0x0Fu;
    u32 off = ((u32)S.z_bank << 14) + 0x8000u;
    if (off + 0x4000u > S.zrom_len)
        off = 0;
    u8 *base = S.zrom + off;
    for (int i = 0; i < 16; i++) {
        S.z.rd[32 + i] = (off + (u32)i * 0x400u < S.zrom_len) ? (base + i * 0x400) : S.zrom;
        S.z.op[32 + i] = 0;
    }
}

static u8 z80_mem_read(struct z80 *c, u16 a)
{
    (void)c;
    if (S.use_qsound) {
        if (a == 0xD007u)
            return 0x80u;               /* DL-1425 DSP ready */
        return 0;
    }
    switch (a) {
    case 0xF001u: case 0xE001u: return S.opm.status & 3u;
    case 0xF002u: case 0xE400u: return oki_status();
    case 0xF008u: case 0xE800u: return S.psnd_code;
    case 0xF00Au:               return S.psnd_fade;
    }
    return 0;
}

static void z80_mem_write(struct z80 *c, u16 a, u8 d)
{
    (void)c;
    if (S.use_qsound) {
        switch (a) {
        case 0xD000u: S.qsc_cmd[0] = d; break;
        case 0xD001u: S.qsc_cmd[1] = d; break;
        case 0xD002u: qsc_write(d, (u16)(((u16)S.qsc_cmd[0] << 8) | S.qsc_cmd[1])); break;
        case 0xD003u: if ((d & 0x0Fu) != S.z_bank) z80_map_bank(d & 0x0Fu); break;
        }
        return;
    }
    if (S.snd_rate && S.zcyc_per_frame > 0) {
        s32 zc = S.z.cycles < 0 ? 0 : (S.z.cycles > S.zcyc_per_frame ? S.zcyc_per_frame : S.z.cycles);
        u32 frame_samples = (S.snd_rate * 100u) / 5963u;
        psnd_render_to(((u32)zc * frame_samples) / (u32)S.zcyc_per_frame);
    }
    switch (a) {
    case 0xF000u: case 0xE000u: S.opm.addr_latch = d; break;
    case 0xF001u: case 0xE001u: opm_write_reg(S.opm.addr_latch, d); break;
    case 0xF002u: case 0xE400u: oki_command(d); break;
    case 0xF004u: if ((d & 0x0Fu) != S.z_bank) z80_map_bank(d & 0x0Fu); break;
    }
}

static u8 z80_io_in(struct z80 *c, u16 port) { (void)c; (void)port; return 0xFFu; }
static void z80_io_out(struct z80 *c, u16 port, u8 v) { (void)c; (void)port; (void)v; }

static void z80_setup_map(void)
{
    z80_init(&S.z);
    S.z.read = z80_mem_read;
    S.z.write = z80_mem_write;
    S.z.in = z80_io_in;
    S.z.out = z80_io_out;
    for (int i = 0; i < 64; i++)
        S.z.rd[i] = S.z.wr[i] = S.z.op[i] = 0;

    if (!S.zrom || !S.zrom_len)
        return;

    /* $0000..$7FFF: fixed 32 KB Z80 ROM (with Kabuki M1/data split if enabled) */
    for (int i = 0; i < 32; i++) {
        if (S.has_kabuki) {
            S.z.op[i] = M->kabuki_op + i * 0x400;
            S.z.rd[i] = M->kabuki_data + i * 0x400;
        } else {
            u32 off = (u32)i * 0x400u;
            S.z.rd[i] = (off < S.zrom_len) ? (S.zrom + off) : S.zrom;
        }
    }
    z80_map_bank(0);

    if (S.use_qsound) {
        /* QSound: $C000..$CFFF shared RAM, $F000..$FFFF work RAM */
        for (int i = 0; i < 4; i++) {
            S.z.rd[48 + i] = M->zram_c0 + i * 0x400;
            S.z.wr[48 + i] = M->zram_c0 + i * 0x400;
            S.z.rd[60 + i] = M->zram_f0 + i * 0x400;
            S.z.wr[60 + i] = M->zram_f0 + i * 0x400;
        }
    } else {
        /* CPS-1 PSound: $D000..$D7FF 2 KB work RAM */
        for (int i = 0; i < 2; i++) {
            S.z.rd[52 + i] = M->zram_f0 + i * 0x400;
            S.z.wr[52 + i] = M->zram_f0 + i * 0x400;
        }
    }
}

static void z80_sync_to(s32 target_zcyc)
{
    if (!S.zrom || !S.zrom_len || target_zcyc <= S.z.cycles)
        return;
    if (S.use_qsound) {
        /* 252 Hz periodic IRQ on QSound Z80 (~31,746 T-states @ 8 MHz) */
        const s32 period = 31746;
        while (S.z.cycles < target_zcyc) {
            s32 step_to = (S.q_irq_next < target_zcyc) ? S.q_irq_next : target_zcyc;
            if (step_to > S.z.cycles) {
                if (S.z.halted && !S.z.irq && !S.z.nmi)
                    S.z.cycles = step_to;
                else
                    z80_run(&S.z, step_to);
            }
            if (S.z.cycles >= S.q_irq_next) {
                S.q_irq_next += period;
                S.z.irq = 1;
                z80_run(&S.z, S.z.cycles + 64);
                S.z.irq = 0;
            }
        }
    } else {
        /* CPS-1 Z80 @ 4 MHz with YM2151 Timer A / B interrupts */
        while (S.z.cycles < target_zcyc) {
            s32 chunk = target_zcyc - S.z.cycles;
            if (S.z.halted && !S.z.irq && !S.z.nmi) {
                if ((S.opm.timer_ctrl & 1u) && S.opm.ta_cnt > 0 && S.opm.ta_cnt < chunk) chunk = S.opm.ta_cnt;
                if ((S.opm.timer_ctrl & 2u) && S.opm.tb_cnt > 0 && S.opm.tb_cnt < chunk) chunk = S.opm.tb_cnt;
                if (chunk < 4) chunk = 4;
                S.z.cycles += chunk;
            } else {
                if (chunk > 512) chunk = 512;
                s32 before = S.z.cycles;
                z80_run(&S.z, before + chunk);
                chunk = S.z.cycles - before;
            }
            s32 ran = chunk;
            if (S.opm.timer_ctrl & 1u) {
                S.opm.ta_cnt -= ran;
                if (S.opm.ta_cnt <= 0) {
                    S.opm.ta_cnt += opm_ta_zcyc();
                    if (S.opm.ta_cnt <= 0) S.opm.ta_cnt = 72;
                    S.opm.status |= 1u;
                    opm_update_irq();
                }
            }
            if (S.opm.timer_ctrl & 2u) {
                S.opm.tb_cnt -= ran;
                if (S.opm.tb_cnt <= 0) {
                    S.opm.tb_cnt += opm_tb_zcyc();
                    if (S.opm.tb_cnt <= 0) S.opm.tb_cnt = 1144;
                    S.opm.status |= 2u;
                    opm_update_irq();
                }
            }
        }
    }
}

static void z80_sync_from_m68k(void)
{
    if (S.cyc_per_frame <= 0)
        return;
    s32 mc = m.clock;
    if (mc < 0) mc = 0;
    if (mc > S.cyc_per_frame) mc = S.cyc_per_frame;
    s32 zt = (s32)(((u32)mc * (u32)(S.zcyc_per_frame >> 4)) / (u32)(S.cyc_per_frame >> 4));
    z80_sync_to(zt);
}

/* ---- 68000 Memory & I/O Bus ---- */

static void cps_update_ipl(void)
{
    m.ipl = (S.irq_pending & 0x10u) ? 4u : ((S.irq_pending & 0x04u) ? 2u : 0u);
    check_pending();
}

static void cps_iack(u32 level)
{
    S.irq_pending &= (u8)~(1u << level);
    cps_update_ipl();
}

static void cps_branch(u32 at)
{
    /* Cycle-exact fast-forward of tight VBlank spinloops (`BRA.S *` or `TST.x $FFxxxx; Bcc *-6`) */
    if (m.im >= 2u || m.pending || S.slice_end_cyc <= m.clock)
        return;
    if (at == m.pc) {
        s32 rem = S.slice_end_cyc - m.clock;
        m.clock += ((rem + 9) / 10) * 10;
        return;
    }
    if (at > m.pc && at - m.pc == 4u && !(m.pc & 1u)) {
        u32 op = cps_fetch(m.pc);
        /* Capcom CPS-2 engine spinloop: TST.B/W/L d16(A5); BEQ.S *-4 */
        if (op == 0x4A2Du || op == 0x4A6Du || op == 0x4AADu) {
            s32 per = (op == 0x4AADu) ? 26 : 22;
            s32 rem = S.slice_end_cyc - m.clock;
            m.clock += ((rem + per - 1) / per) * per;
            return;
        }
    }
    if (at > m.pc && at - m.pc == 6u && !(m.pc & 1u)) {
        u32 op = cps_fetch(m.pc);
        if ((op == 0x4A39u || op == 0x4A79u || op == 0x4AB9u) && cps_fetch(m.pc + 2u) == 0x00FFu) {
            s32 per = (op == 0x4AB9u) ? 30 : 26;
            s32 rem = S.slice_end_cyc - m.clock;
            m.clock += ((rem + per - 1) / per) * per;
        }
    }
}

INLINE void cps_cpu_run(s32 end_cyc)
{
    S.slice_end_cyc = end_cyc;
    cpu_run(end_cyc);
}

static void cpu_reset_line(void)
{
    if (S.zrom && S.zrom_len)
        z80_reset(&S.z);
}

static u8 cps_port_read(u32 ia)
{
    switch (ia) {
    case 0x000u: return (u8)~S.inp000;
    case 0x001u: return (u8)~S.inp001;
    case 0x010u: return (u8)~S.inp010;
    case 0x011u: return (u8)~S.inp011;
    case 0x012u: return 0xFFu;
    case 0x018u: return (u8)~S.inp018;
    case 0x019u: case 0x01Bu: return 0xFFu;
    case 0x01Au: return (u8)~S.dip_a;
    case 0x01Cu: return (u8)~S.dip_b;
    case 0x01Eu: return (u8)~S.dip_c;
    case 0x020u: return (u8)~S.inp020;
    case 0x021u: return (u8)(((u8)~S.inp021 & 0xFEu) | eeprom_read_bit());
    case 0x030u: return 0xE0u;          /* CPS-2 digital volume max (0xE021) */
    case 0x031u: return 0x21u;
    case 0x177u: case 0x186u: return (u8)~S.inp177;
    case 0x179u: return 0xFFu;
    }
    if (S.bid[0] && ia == 0x100u + S.bid[0])
        return S.bid[1];
    if (S.bid[0] && ia == 0x100u + S.bid[0] + 1u)
        return S.bid[2];
    if (S.cps_ver == 2 && ia >= 0x100u && ia < 0x200u) {
        if ((ia & 0xFEu) == 0x50u) {
            s32 diff = S.irq_line50 - S.cur_scanline;
            return (u8)((ia & 1u) ? (diff & 0xFF) : ((diff >> 8) & 0xFF));
        }
        if ((ia & 0xFEu) == 0x52u) {
            s32 diff = S.irq_line52 - S.cur_scanline;
            return (u8)((ia & 1u) ? (diff & 0xFF) : ((diff >> 8) & 0xFF));
        }
    }
    return 0xFFu;
}

static void cps_port_write(u32 ia, u8 d)
{
    if (S.cps_ver == 1 && !S.use_qsound) {
        if (ia == 0x181u) {
            z80_sync_from_m68k();
            S.psnd_code = d;
            return;
        }
        if (ia == 0x189u) {
            z80_sync_from_m68k();
            S.psnd_fade = d;
            return;
        }
    }
    if (ia >= 0x100u && ia < 0x200u) {
        S.cps_reg[ia & 0xFFu] = d;
        if (ia == 0x10Bu)
            cps_latch_palette(0);
        return;
    }
    if (ia == 0x040u && S.cps_ver == 2) {
        eeprom_write_pins(d & 0x20, d & 0x40, d & 0x10);
        return;
    }
    if ((ia & 0x1FFu) == 0x0E1u && S.cps_ver == 2) {
        S.obj_bank = d & 1u;
        if (S.obj_bank)
            S.obj_bank_used1 = 1;
        return;
    }
}

static u32 io_read(u32 a, int size)
{
    /* CPS-2 banked object RAM $708000..$70FFFF (mirrors every 8 KB) */
    if (S.cps_ver == 2 && a >= 0x708000u && a < 0x710000u) {
        u32 off = (((u32)S.obj_bank & 1u) << 13) | (a & 0x1FFFu);
        if (size == 2)
            return *(const u16 *)(M->ram708 + (off & ~1u));
        return M->ram708[off ^ 1u];
    }
    /* QSound Z80 shared RAM $618000..$619FFF (odd bytes -> $C000..$CFFF) */
    if (S.use_qsound && a >= 0x618000u && a < 0x61A000u) {
        z80_sync_from_m68k();
        u32 zoff = (a & 0x1FFFu) >> 1;
        if (size == 2)
            return 0xFF00u | M->zram_c0[zoff];
        return (a & 1u) ? M->zram_c0[zoff] : 0xFFu;
    }
    /* $800000..$807FFF CPS-A / CPS-B / Input ports */
    if ((a & 0xFF8000u) == 0x800000u) {
        if (size == 2) {
            u32 mr = a & 0xFF8FFFu;
            if (S.mprot[3] && mr == 0x800100u + S.mprot[3])
                return ((S.calc[0] * S.calc[1]) >> 16) & 0xFFFFu;
            if (S.mprot[2] && mr == 0x800100u + S.mprot[2])
                return (S.calc[0] * S.calc[1]) & 0xFFFFu;
            u32 ia = a & 0x1FEu;
            return ((u32)cps_port_read(ia) << 8) | cps_port_read(ia + 1u);
        }
        return cps_port_read(a & 0x1FFu);
    }
    /* $400000..$40000F CPS-2 Frg registers */
    if (S.cps_ver == 2 && (a & 0xFFFFF0u) == 0x400000u) {
        if (size == 2)
            return reg16(S.cps_frg, a & 0x0Eu);
        return S.cps_frg[a & 0x0Fu];
    }
    /* $664001 CPS-2 toggle port */
    if (S.cps_ver == 2 && (a & 0xFFFFFEu) == 0x664000u) {
        if (size == 2)
            return S.r664001;
        return (a & 1u) ? S.r664001 : 0u;
    }
    /* CPS-1.5 QSound inputs & EEPROM at $F1C000..$F1C007 */
    if (S.cps_ver == 1 && S.use_qsound && a >= 0xF1C000u && a <= 0xF1C007u) {
        if ((a & 7u) == 7u)
            return eeprom_read_bit();
        return 0xFFu;
    }
    return size == 2 ? 0xFFFFu : 0xFFu;
}

static void io_write(u32 a, u32 v, int size)
{
    /* CPS-2 banked object RAM $708000..$70FFFF */
    if (S.cps_ver == 2 && a >= 0x708000u && a < 0x710000u) {
        u32 off = (((u32)S.obj_bank & 1u) << 13) | (a & 0x1FFFu);
        if (size == 2)
            *(u16 *)(M->ram708 + (off & ~1u)) = (u16)v;
        else
            M->ram708[off ^ 1u] = (u8)v;
        return;
    }
    /* QSound Z80 shared RAM $618000..$619FFF */
    if (S.use_qsound && a >= 0x618000u && a < 0x61A000u) {
        if ((a & 0x1FFEu) == 0x001Eu || (a & 1u))
            z80_sync_from_m68k();
        u32 zoff = (a & 0x1FFFu) >> 1;
        if (size == 2)
            M->zram_c0[zoff] = (u8)(v & 0xFFu);
        else if (a & 1u)
            M->zram_c0[zoff] = (u8)v;
        return;
    }
    /* $800000..$807FFF CPS-A / CPS-B / Output ports */
    if ((a & 0xFF8000u) == 0x800000u) {
        if (size == 2) {
            u32 mr = a & 0xFF8FFFu;
            if (S.mprot[0] && mr == 0x800100u + S.mprot[0]) S.calc[0] = v & 0xFFFFu;
            if (S.mprot[1] && mr == 0x800100u + S.mprot[1]) S.calc[1] = v & 0xFFFFu;
            if (a == 0x804040u && (v & 8u) == 0 && S.use_qsound && S.zrom_len)
                z80_reset(&S.z);
            u32 ia = a & 0x1FEu;
            cps_port_write(ia, (u8)(v >> 8));
            cps_port_write(ia + 1u, (u8)(v & 0xFFu));
        } else {
            cps_port_write(a & 0x1FFu, (u8)v);
        }
        return;
    }
    /* $400000..$40000F CPS-2 Frg registers */
    if (S.cps_ver == 2 && (a & 0xFFFFF0u) == 0x400000u) {
        if (size == 2) {
            S.cps_frg[a & 0x0Eu] = (u8)(v >> 8);
            S.cps_frg[(a & 0x0Eu) + 1u] = (u8)(v & 0xFFu);
        } else {
            S.cps_frg[a & 0x0Fu] = (u8)v;
        }
        return;
    }
    if (S.cps_ver == 2 && (a & 0xFFFFFEu) == 0x664000u) {
        if (size == 2 || (a & 1u))
            S.r664001 = (u8)(v & 0xFFu);
        return;
    }
    if (S.cps_ver == 1 && S.use_qsound && (a == 0xF1C007u || (size == 2 && a == 0xF1C006u))) {
        u8 b = (u8)(v & 0xFFu);
        eeprom_write_pins(b & 0x40, b & 0x80, b & 0x01);
    }
}

static void setup_m68k_map(void)
{
    for (int i = 0; i < 256; i++)
        rmap[i] = wmap[i] = fmap[i] = 0;

    u32 rpages = (S.rom_len + 0xFFFFu) >> 16;
    if (rpages > 64u) rpages = 64u;
    for (u32 i = 0; i < rpages; i++) {
        rmap[i] = S.rom + (i << 16);
        fmap[i] = S.rom + (i << 16);
    }
    if (S.code && S.code_len) {
        u32 cpages = (S.code_len + 0xFFFFu) >> 16;
        if (cpages > 64u) cpages = 64u;
        for (u32 i = 0; i < cpages; i++)
            fmap[i] = S.code + (i << 16);
    }
    /* $900000..$92FFFF: 192 KB Video / Scroll / Object / Palette RAM */
    for (int i = 0; i < 3; i++)
        rmap[0x90 + i] = wmap[0x90 + i] = M->ram90 + (i << 16);
    /* $FF0000..$FFFFFF: 64 KB 68000 Work RAM */
    rmap[0xFF] = wmap[0xFF] = M->ramff;
    fmap[0xFF] = M->ramff;
    /* $660000..$663FFF: CPS-2 extra RAM (page 0x66) */
    if (S.cps_ver == 2)
        rmap[0x66] = wmap[0x66] = M->ram660;
}

/* ---- CPS-1 & CPS-2 Tilemap + Sprite Renderer (384 x 224 BGR555) ---- */

INLINE void draw_sliver8(u16 *dst, int sx, u32 b, const u16 *pal, int flipx, int bghi, u16 pmsk)
{
    if (!b)
        return;
    if (sx >= 0 && sx <= CPS_W - 8) {
        u16 *p = dst + sx;
        if (!flipx) {
            if (!bghi) {
                /* Branchless 32-bit pixel-pair path when all 8 pixels in the sliver are opaque */
                if (!(((b - 0x11111111u) & ~b) & 0x88888888u) && !((__UINTPTR_TYPE__)p & 3u)) {
                    u32 *p32 = (u32 *)p;
                    p32[0] = (u32)pal[b >> 28]         | ((u32)pal[(b >> 24) & 15u] << 16);
                    p32[1] = (u32)pal[(b >> 20) & 15u] | ((u32)pal[(b >> 16) & 15u] << 16);
                    p32[2] = (u32)pal[(b >> 12) & 15u] | ((u32)pal[(b >>  8) & 15u] << 16);
                    p32[3] = (u32)pal[(b >>  4) & 15u] | ((u32)pal[b & 15u]         << 16);
                    return;
                }
                for (int i = 0; i < 8; i++, b <<= 4) {
                    u32 c = b >> 28;
                    if (c) p[i] = pal[c];
                }
            } else {
                for (int i = 0; i < 8; i++, b <<= 4) {
                    u32 c = b >> 28;
                    if (c && (pmsk & (1u << (c ^ 15u)))) p[i] = pal[c];
                }
            }
        } else {
            if (!bghi) {
                for (int i = 0; i < 8; i++, b >>= 4) {
                    u32 c = b & 15u;
                    if (c) p[i] = pal[c];
                }
            } else {
                for (int i = 0; i < 8; i++, b >>= 4) {
                    u32 c = b & 15u;
                    if (c && (pmsk & (1u << (c ^ 15u)))) p[i] = pal[c];
                }
            }
        }
        return;
    }
    if (sx <= -8 || sx >= CPS_W)
        return;
    if (!flipx) {
        for (int i = 0; i < 8; i++, b <<= 4) {
            int x = sx + i;
            u32 c = b >> 28;
            if ((unsigned)x < CPS_W && c && (!bghi || (pmsk & (1u << (c ^ 15u)))))
                dst[x] = pal[c];
        }
    } else {
        for (int i = 0; i < 8; i++, b >>= 4) {
            int x = sx + i;
            u32 c = b & 15u;
            if ((unsigned)x < CPS_W && c && (!bghi || (pmsk & (1u << (c ^ 15u)))))
                dst[x] = pal[c];
        }
    }
}

INLINE void draw_spr_sliver8(u16 *dst, u16 *zrow, int sx, u32 b, const u16 *pal, int flipx, int use_z, u16 zval)
{
    if (!b || sx <= -8 || sx >= CPS_W)
        return;
    if (sx >= 0 && sx <= CPS_W - 8) {
        u16 *p = dst + sx;
        if (!use_z) {
            if (!flipx) {
                for (int i = 0; i < 8; i++, b <<= 4) { u32 c = b >> 28; if (c) p[i] = pal[c]; }
            } else {
                for (int i = 0; i < 8; i++, b >>= 4) { u32 c = b & 15u; if (c) p[i] = pal[c]; }
            }
        } else {
            u16 *zp = zrow + sx;
            if (!flipx) {
                for (int i = 0; i < 8; i++, b <<= 4) {
                    u32 c = b >> 28;
                    if (c && zp[i] < zval) { p[i] = pal[c]; zp[i] = zval; }
                }
            } else {
                for (int i = 0; i < 8; i++, b >>= 4) {
                    u32 c = b & 15u;
                    if (c && zp[i] < zval) { p[i] = pal[c]; zp[i] = zval; }
                }
            }
        }
        return;
    }
    if (!flipx) {
        for (int i = 0; i < 8; i++, b <<= 4) {
            int x = sx + i;
            u32 c = b >> 28;
            if ((unsigned)x < CPS_W && c) {
                if (!use_z) dst[x] = pal[c];
                else if (zrow[x] < zval) { dst[x] = pal[c]; zrow[x] = zval; }
            }
        }
    } else {
        for (int i = 0; i < 8; i++, b >>= 4) {
            int x = sx + i;
            u32 c = b & 15u;
            if ((unsigned)x < CPS_W && c) {
                if (!use_z) dst[x] = pal[c];
                else if (zrow[x] < zval) { dst[x] = pal[c]; zrow[x] = zval; }
            }
        }
    }
}

static void render_scroll1(u16 *pic, int slice, int y0, int y1, int bghi)
{
    const u8 *reg = M->save_reg[slice];
    u32 map_addr = ((u32)reg16(reg, 0x02u) << 8) & 0xFFC000u;
    const u8 *base = find_gfx_ram(map_addr, 0x4000u);
    if (!base || !S.gfx || !S.gfx_len)
        return;

    s32 scrx = (s32)reg16(reg, 0x0Cu) + 0x40 + S.lay_xoffs[0];
    s32 scry = (s32)reg16(reg, 0x0Eu) + 0x10 + S.lay_yoffs[0];
    u16 pmsk_lut[4];
    if (bghi) {
        for (int i = 0; i < 4; i++)
            pmsk_lut[i] = S.mask_addr[i] ? reg16(M->save_reg[0], S.mask_addr[i]) : 0u;
    }

    for (int y = y0; y < y1; y++) {
        u16 *dst = pic + y * CPS_W;
        u32 my = (u32)(scry + y) & 0x1FFu;
        u32 fy = my >> 3;
        u32 ty = my & 7u;
        u32 mx0 = (u32)scrx & 0x1FFu;
        int sx = -(int)(mx0 & 7u);
        u32 fx = mx0 >> 3;
        u32 fy_bits = ((fy & 0x20u) << 8) | ((fy & 0x1Fu) << 2);

        for (; sx < CPS_W; sx += 8, fx = (fx + 1u) & 63u) {
            const u16 *pst = (const u16 *)(base + (fy_bits | (fx << 7)));
            s32 t = (S.cps_ver == 1) ? map_gfx_tile(GFXTYPE_SCROLL1, pst[0]) : (s32)pst[0];
            if (t < 0)
                continue;
            u16 a = pst[1];
            u32 row = (a & 0x40u) ? (7u - ty) : ty;
            u32 gaddr = (((u32)t << 6) + S.gfx_scroll[1] + (row << 3)) & S.gfx_mask;
            u32 b = *(const u32 *)(S.gfx + gaddr);
            if (!b)
                continue;
            const u16 *pal = M->pal15 + ((0x20u | (a & 0x1Fu)) << 4);
            u16 pmsk = bghi ? pmsk_lut[(a >> 7) & 3u] : 0u;
            draw_sliver8(dst, sx, b, pal, (a >> 5) & 1, bghi, pmsk);
        }
    }
}

static void render_scroll2(u16 *pic, int slice, int y0, int y1, int bghi)
{
    const u8 *reg = M->save_reg[slice];
    u32 map_addr = ((u32)reg16(reg, 0x04u) << 8) & 0xFFC000u;
    const u8 *base = find_gfx_ram(map_addr, 0x4000u);
    if (!base || !S.gfx || !S.gfx_len)
        return;

    s32 scrx = ((s32)reg16(reg, 0x10u) + 0x40 + S.lay_xoffs[1]) & 0x3FF;
    s32 scry = ((s32)reg16(reg, 0x12u) + 0x10 + S.lay_yoffs[1]) & 0x3FF;
    const u16 *rows = 0;
    s32 row_start = 0;
    if (reg16(reg, 0x22u) & 1u) {
        u32 tab_addr = ((u32)reg16(reg, 0x08u) << 8) & 0xFFF800u;
        rows = (const u16 *)find_gfx_ram(tab_addr, 0x800u);
        row_start = (s32)reg16(reg, 0x20u) + 16;
    }

    u16 pmsk_lut[4];
    if (bghi) {
        for (int i = 0; i < 4; i++)
            pmsk_lut[i] = S.mask_addr[i] ? reg16(M->save_reg[0], S.mask_addr[i]) : 0u;
    }

    for (int y = y0; y < y1; y++) {
        u16 *dst = pic + y * CPS_W;
        u32 my = (u32)(scry + y) & 0x3FFu;
        u32 fy = my >> 4;
        u32 ty = my & 15u;
        u32 line_x = (u32)(scrx + (rows ? (s32)rows[(row_start + y) & 0x3FF] : 0)) & 0x3FFu;
        int sx = -(int)(line_x & 15u);
        u32 fx = line_x >> 4;
        u32 fy_bits = ((fy & 0x30u) << 8) | ((fy & 0x0Fu) << 2);

        for (; sx < CPS_W; sx += 16, fx = (fx + 1u) & 63u) {
            const u16 *pst = (const u16 *)(base + (fy_bits | (fx << 6)));
            s32 t = (S.cps_ver == 1) ? map_gfx_tile(GFXTYPE_SCROLL2, pst[0]) : (s32)pst[0];
            if (t < 0)
                continue;
            u16 a = pst[1];
            u32 row = (a & 0x40u) ? (15u - ty) : ty;
            u32 gaddr = (((u32)t << 7) + S.gfx_scroll[2] + (row << 3)) & S.gfx_mask;
            const u32 *tp = (const u32 *)(S.gfx + gaddr);
            u32 b0 = tp[0], b1 = tp[1];
            if (!(b0 | b1))
                continue;
            const u16 *pal = M->pal15 + ((0x40u | (a & 0x1Fu)) << 4);
            u16 pmsk = bghi ? pmsk_lut[(a >> 7) & 3u] : 0u;
            int flipx = (a >> 5) & 1;
            if (!flipx) {
                draw_sliver8(dst, sx,     b0, pal, 0, bghi, pmsk);
                draw_sliver8(dst, sx + 8, b1, pal, 0, bghi, pmsk);
            } else {
                draw_sliver8(dst, sx,     b1, pal, 1, bghi, pmsk);
                draw_sliver8(dst, sx + 8, b0, pal, 1, bghi, pmsk);
            }
        }
    }
}

static void render_scroll3(u16 *pic, int slice, int y0, int y1, int bghi)
{
    const u8 *reg = M->save_reg[slice];
    u32 map_addr = ((u32)reg16(reg, 0x06u) << 8) & 0xFFC000u;
    const u8 *base = find_gfx_ram(map_addr, 0x4000u);
    if (!base || !S.gfx || !S.gfx_len)
        return;

    s32 scrx = (s32)reg16(reg, 0x14u) + 0x40 + S.lay_xoffs[2];
    s32 scry = (s32)reg16(reg, 0x16u) + 0x10 + S.lay_yoffs[2];
    u16 pmsk_lut[4];
    if (bghi) {
        for (int i = 0; i < 4; i++)
            pmsk_lut[i] = S.mask_addr[i] ? reg16(M->save_reg[0], S.mask_addr[i]) : 0u;
    }

    for (int y = y0; y < y1; y++) {
        u16 *dst = pic + y * CPS_W;
        u32 my = (u32)(scry + y) & 0x7FFu;
        u32 fy = my >> 5;
        u32 ty = my & 31u;
        u32 mx0 = (u32)scrx & 0x7FFu;
        int sx = -(int)(mx0 & 31u);
        u32 fx = mx0 >> 5;
        u32 fy_bits = ((fy & 0x38u) << 8) | ((fy & 0x07u) << 2);

        for (; sx < CPS_W; sx += 32, fx = (fx + 1u) & 63u) {
            const u16 *pst = (const u16 *)(base + (fy_bits | (fx << 5)));
            s32 raw_t = pst[0];
            if (S.cps_ver == 2) {
                if (S.xmcota && raw_t >= 0x5800) raw_t -= 0x4000;
                else if (S.ssf2t && raw_t < 0x5600) raw_t += 0x4000;
            }
            s32 t = (S.cps_ver == 1) ? map_gfx_tile(GFXTYPE_SCROLL3, (u32)raw_t) : raw_t;
            if (t < 0)
                continue;
            u16 a = pst[1];
            u32 row = (a & 0x40u) ? (31u - ty) : ty;
            u32 gaddr = (((u32)t << 9) + S.gfx_scroll[3] + (row << 4)) & S.gfx_mask;
            const u32 *tp = (const u32 *)(S.gfx + gaddr);
            if (!(tp[0] | tp[1] | tp[2] | tp[3]))
                continue;
            const u16 *pal = M->pal15 + ((0x60u | (a & 0x1Fu)) << 4);
            u16 pmsk = bghi ? pmsk_lut[(a >> 7) & 3u] : 0u;
            int flipx = (a >> 5) & 1;
            if (!flipx) {
                draw_sliver8(dst, sx,      tp[0], pal, 0, bghi, pmsk);
                draw_sliver8(dst, sx +  8, tp[1], pal, 0, bghi, pmsk);
                draw_sliver8(dst, sx + 16, tp[2], pal, 0, bghi, pmsk);
                draw_sliver8(dst, sx + 24, tp[3], pal, 0, bghi, pmsk);
            } else {
                draw_sliver8(dst, sx,      tp[3], pal, 1, bghi, pmsk);
                draw_sliver8(dst, sx +  8, tp[2], pal, 1, bghi, pmsk);
                draw_sliver8(dst, sx + 16, tp[1], pal, 1, bghi, pmsk);
                draw_sliver8(dst, sx + 24, tp[0], pal, 1, bghi, pmsk);
            }
        }
    }
}

static void snapshot_sprites(struct cps_obj_snap *snap)
{
    snap->count = 0;
    if (S.cps_ver == 2) {
        u32 bank = S.obj_bank_used1 ? ((S.obj_bank ^ 1u) & 1u) : 0u;
        const u16 *src = (const u16 *)(M->ram708 + (bank << 13));
        snap->shift_x = -(s32)M->save_frg[0][0x09];
        snap->shift_y = -(s32)M->save_frg[0][0x0B];
        for (int i = 0; i < 1024; i++, src += 4) {
            if (src[1] & 0x8000u)
                break;
            if (src[3] >= 0xFF00u)
                break;
            if ((src[0] | src[3]) == 0)
                continue;
            u16 *dst = snap->list + snap->count * 4;
            dst[0] = src[0];
            dst[1] = src[1];
            dst[2] = src[2];
            dst[3] = src[3];
            snap->count++;
        }
    } else {
        u32 off = ((u32)reg16(S.cps_reg, 0x00u) << 8) & 0xFFF800u;
        const u16 *src = (const u16 *)find_gfx_ram(off, 0x800u);
        snap->shift_x = -0x40;
        snap->shift_y = -0x10;
        if (!src)
            return;
        for (int i = 0; i < 256; i++, src += 4) {
            if (src[3] >= 0xFF00u)
                break;
            if ((src[0] | src[3]) == 0)
                continue;
            u16 *dst = snap->list + snap->count * 4;
            dst[0] = src[0];
            dst[1] = src[1];
            dst[2] = src[2];
            dst[3] = src[3];
            snap->count++;
        }
    }
}

static void draw_sprite_tile16(u16 *pic, int tx, int ty, u32 tile, const u16 *pal, int flip, int use_z, u16 zval)
{
    if (tx <= -16 || tx >= CPS_W || ty <= -16 || ty >= CPS_H)
        return;
    u32 base_addr = (tile << 7) & S.gfx_mask;
    int flipx = flip & 1;
    int flipy = flip & 2;
    int y0 = (ty < 0) ? -ty : 0;
    int y1 = (ty + 16 > CPS_H) ? (CPS_H - ty) : 16;

    for (int ry = y0; ry < y1; ry++) {
        int sy = ty + ry;
        u32 row = flipy ? (u32)(15 - ry) : (u32)ry;
        const u32 *tp = (const u32 *)(S.gfx + ((base_addr + (row << 3)) & S.gfx_mask));
        u32 b0 = tp[0], b1 = tp[1];
        if (!(b0 | b1))
            continue;
        u16 *dst = pic + sy * CPS_W;
        u16 *zrow = use_z ? (M->zbuf + sy * CPS_W) : 0;
        if (!flipx) {
            draw_spr_sliver8(dst, zrow, tx,     b0, pal, 0, use_z, zval);
            draw_spr_sliver8(dst, zrow, tx + 8, b1, pal, 0, use_z, zval);
        } else {
            draw_spr_sliver8(dst, zrow, tx,     b1, pal, 1, use_z, zval);
            draw_spr_sliver8(dst, zrow, tx + 8, b0, pal, 1, use_z, zval);
        }
    }
}

static void render_cps1_sprites(u16 *pic, const struct cps_obj_snap *snap)
{
    if (!S.gfx || !S.gfx_len || snap->count <= 0)
        return;
    /* CPS-1 draws sprites in reverse order so sprite #0 is on top */
    for (s32 i = snap->count - 1; i >= 0; i--) {
        const u16 *ps = snap->list + i * 4;
        s32 x = ps[0] & 0x1FF;
        if (x >= 0x1C0) x -= 0x200;
        s32 y = ((ps[1] & 0x1FF) ^ 0x100) - 0x100;
        x += snap->shift_x;
        y += snap->shift_y;
        s32 n = map_gfx_tile(GFXTYPE_SPRITES, ps[2]);
        if (n < 0)
            continue;
        n |= (s32)(ps[1] & 0x6000u) << 3;
        u16 a = ps[3];
        int flip = (a >> 5) & 3;
        int bx = ((a >> 8) & 15) + 1;
        int by = ((a >> 12) & 15) + 1;
        const u16 *pal = M->pal15 + ((a & 0x1Fu) << 4);

        for (int dy = 0; dy < by; dy++) {
            int ey = (flip & 2) ? (by - dy - 1) : dy;
            for (int dx = 0; dx < bx; dx++) {
                int ex = (flip & 1) ? (bx - dx - 1) : dx;
                u32 t = (u32)((n & ~0x0F) + (dy << 4) + ((n + dx) & 0x0F));
                draw_sprite_tile16(pic, x + (ex << 4), y + (ey << 4), t, pal, flip, 0, 0);
            }
        }
    }
}

static s32 cps2_max_zval, cps2_max_zmask;

static void render_cps2_sprites(u16 *pic, const struct cps_obj_snap *snap, int prio_from, int prio_to)
{
    if (!S.gfx || !S.gfx_len || snap->count <= 0)
        return;
    int mask_seen = 0;
    s32 start_idx = cps2_max_zval - 1;
    if (start_idx < 0) start_idx = 0;

    for (s32 i = start_idx; i < snap->count; i++) {
        u16 zval = (u16)(i + 1);
        const u16 *ps = snap->list + i * 4;
        int v = (ps[0] >> 13) & 7;
        if (v > prio_to) {
            mask_seen = 1;
            continue;
        }
        if (v < prio_from)
            continue;
        if (mask_seen) cps2_max_zmask = zval;
        else           cps2_max_zval = zval + 1;

        int use_z = (mask_seen || cps2_max_zmask >= zval) ? 1 : 0;
        if (use_z && !S.zbuf_dirty) {
            cps_zero(M->zbuf, sizeof(M->zbuf));
            S.zbuf_dirty = 1;
        }
        s32 x = ((ps[0] & 0x3FF) ^ 0x200) - 0x200;
        s32 y = ((ps[1] & 0x3FF) ^ 0x200) - 0x200;
        u16 a = ps[3];
        if (a & 0x80u)
            x += (s32)M->save_frg[0][0x09];
        x += snap->shift_x;
        y += snap->shift_y;
        u32 n = (u32)ps[2] | (((u32)ps[1] & 0x6000u) << 3);
        int flip = (a >> 5) & 3;
        int bx = ((a >> 8) & 15) + 1;
        int by = ((a >> 12) & 15) + 1;
        const u16 *pal = M->pal15 + ((a & 0x1Fu) << 4);

        for (int dy = 0; dy < by; dy++) {
            int ey = (flip & 2) ? (by - dy - 1) : dy;
            for (int dx = 0; dx < bx; dx++) {
                int ex = (flip & 1) ? (bx - dx - 1) : dx;
                u32 t = (n & ~0x0Fu) + ((u32)dy << 4) + ((n + (u32)dx) & 0x0Fu);
                draw_sprite_tile16(pic, x + (ex << 4), y + (ey << 4), t, pal, flip, use_z, zval);
            }
        }
    }
}

static void render_frame(u16 *pic, const struct cps_obj_snap *snap)
{
    if (!pic)
        return;

    /* Update any enabled palette pages (or force initial latch if game didn't poke $80010B) */
    cps_latch_palette(!S.pal_latched_once);

    /* CPS-1 & CPS-2 hardware outputs black (0) wherever all layers & sprites are transparent (pen 15) */
    cps_zero(pic, CPS_W * CPS_H * sizeof(u16));

    if (S.cps_ver == 1) {
        u16 lc = reg16(M->save_reg[0], S.lc_reg);
        int dmask = 1;
        if (lc & S.lay_en[1]) dmask |= 2;
        if (lc & S.lay_en[2]) dmask |= 4;
        if (lc & S.lay_en[3]) dmask |= 8;

        int draw[4] = {(lc >> 12) & 3, (lc >> 10) & 3, (lc >> 8) & 3, (lc >> 6) & 3};
        for (int a = 0; a < 4; a++)
            for (int b = a + 1; b < 4; b++)
                if (draw[a] == draw[b])
                    draw[b] = -1;

        for (int i = 3; i >= 0; i--) {
            int n = draw[i];
            if (n == 0) {
                render_cps1_sprites(pic, snap);
                if (i < 3) {
                    int under = draw[i + 1];
                    if (under == 1 && (dmask & 2)) render_scroll1(pic, 0, 0, CPS_H, 1);
                    else if (under == 2 && (dmask & 4)) render_scroll2(pic, 0, 0, CPS_H, 1);
                    else if (under == 3 && (dmask & 8)) render_scroll3(pic, 0, 0, CPS_H, 1);
                }
            } else if (n == 1 && (dmask & 2)) {
                render_scroll1(pic, 0, 0, CPS_H, 0);
            } else if (n == 2 && (dmask & 4)) {
                render_scroll2(pic, 0, 0, CPS_H, 0);
            } else if (n == 3 && (dmask & 8)) {
                render_scroll3(pic, 0, 0, CPS_H, 0);
            }
        }
        return;
    }

    /* CPS-2 multi-slice Z-priority layer + sprite compositor (zbuf cleared lazily on first use_z) */
    S.zbuf_dirty = 0;
    cps2_max_zval = 1;
    cps2_max_zmask = 0;

    int draw[MAX_RASTER][4];
    int prio[MAX_RASTER][4];
    int dmask[MAX_RASTER];
    int num_slices = 0;

    do {
        u16 lc = reg16(M->save_reg[num_slices], S.lc_reg);
        dmask[num_slices] = 1;
        if (lc & S.lay_en[1]) dmask[num_slices] |= 2;
        if (lc & S.lay_en[2]) dmask[num_slices] |= 4;
        if (lc & S.lay_en[3]) dmask[num_slices] |= 8;

        draw[num_slices][3] = (lc >> 12) & 3;
        draw[num_slices][2] = (lc >> 10) & 3;
        draw[num_slices][1] = (lc >> 8) & 3;
        draw[num_slices][0] = (lc >> 6) & 3;

        u16 lp = reg16(M->save_frg[num_slices], 4);
        prio[num_slices][0] = 0;
        prio[num_slices][1] = (lp >> 4) & 7;
        prio[num_slices][2] = (lp >> 8) & 7;
        prio[num_slices][3] = (lp >> 12) & 7;

        for (int a = 3; a >= 0; a--)
            for (int b = a - 1; b >= 0; b--)
                if (draw[num_slices][a] == draw[num_slices][b])
                    draw[num_slices][b] = -1;

        int high_p = 9999;
        for (int i = 3; i >= 0; i--) {
            int l = draw[num_slices][i];
            if (l > 0) {
                if (prio[num_slices][l] > high_p) prio[num_slices][l] = high_p;
                else high_p = prio[num_slices][l];
            }
        }
        num_slices++;
    } while (num_slices < MAX_RASTER && S.raster_lines[num_slices]);

    int prev_prio = -1;
    for (int cp = 0; cp < 8; cp++) {
        for (int sl = 0; sl < num_slices; sl++) {
            for (int i = 0; i < 4; i++) {
                int l = draw[sl][i];
                if (l > 0 && prio[sl][l] == cp) {
                    if (prev_prio < cp) {
                        render_cps2_sprites(pic, snap, prev_prio + 1, cp);
                        prev_prio = cp;
                    }
                    int y0 = S.raster_lines[sl];
                    int y1 = S.raster_lines[sl + 1] ? S.raster_lines[sl + 1] : CPS_H;
                    if (y0 < 0) y0 = 0;
                    if (y1 > CPS_H) y1 = CPS_H;
                    if (y0 < y1) {
                        if (l == 1 && (dmask[sl] & 2)) render_scroll1(pic, sl, y0, y1, 0);
                        else if (l == 2 && (dmask[sl] & 4)) render_scroll2(pic, sl, y0, y1, 0);
                        else if (l == 3 && (dmask[sl] & 8)) render_scroll3(pic, sl, y0, y1, 0);
                    }
                }
            }
        }
    }
    if (prev_prio < 7)
        render_cps2_sprites(pic, snap, prev_prio + 1, 7);
}

/* ---- Built-in CPS-2 Key Table & CPS-1 Board Preset Table ---- */

struct cps2_key_entry {
    const char *name;
    u32 k0, k1, upper;
};

static const struct cps2_key_entry cps2_keys[] = {
    {"ssf2",     0x23456789u, 0xABCDEF01u, 0x400000u},
    {"ssf2u",    0x12345678u, 0x9ABCDEF0u, 0x400000u},
    {"ssf2j",    0x01234567u, 0x89ABCDEFu, 0x400000u},
    {"ssf2tb",   0x89ABCDEFu, 0x01234567u, 0x400000u},
    {"ssf2t",    0x944E8302u, 0x56D3143Cu, 0x400000u},
    {"ssf2tu",   0x94FA8902u, 0x4C77143Fu, 0x400000u},
    {"ssf2xj",   0x942A5702u, 0x05AC140Eu, 0x400000u},
    {"ddtod",    0x4767FE08u, 0x14CA35D9u, 0x180000u},
    {"ddtodu",   0xECA19C3Du, 0x24736BF0u, 0x180000u},
    {"ecofghtr", 0x931031DCu, 0xBA987654u, 0x200000u},
    {"xmcota",   0x3BC6EDA4u, 0x97F80251u, 0x100000u},
    {"xmcotau",  0x32A57ECDu, 0x98016F4Bu, 0x100000u},
    {"xmcotaj",  0x46027315u, 0xAF8BCD9Eu, 0x100000u},
    {"armwar",   0x9E9D4C0Bu, 0x8A39081Fu, 0x100000u},
    {"pgear",    0x9D4C0B8Au, 0x39081F9Eu, 0x100000u},
    {"avsp",     0x15208F79u, 0x4ADE6CB3u, 0x100000u},
    {"avspu",    0xB4F61089u, 0xCCF75A23u, 0x100000u},
    {"dstlk",    0x13D8A7A8u, 0x0008B090u, 0x100000u},
    {"dstlku",   0x1E80EBF0u, 0x10227119u, 0x100000u},
    {"vampj",    0xEFCB0804u, 0x026819AEu, 0x100000u},
    {"ringdest", 0x19940727u, 0x17444903u, 0x180000u},
    {"smbomb",   0x19940209u, 0x17031403u, 0x180000u},
    {"cybots",   0x45425943u, 0x05090901u, 0x100000u},
    {"msh",      0x1A11EE26u, 0xE7955D17u, 0x100000u},
    {"mshu",     0x8705A24Eu, 0x4A17319Bu, 0x100000u},
    {"nwarr",    0x1019D145u, 0x03F05A05u, 0x180000u},
    {"sfa",      0x0F895D6Eu, 0xC4273A1Bu, 0x080000u},
    {"sfau",     0x25BEAD36u, 0x97CF4018u, 0x080000u},
    {"sfzj",     0x8DB3167Au, 0xC29E0F45u, 0x080000u},
    {"mmancp2u", 0x054893FAu, 0x94642525u, 0x100000u},
    {"rmancp2j", 0x07215501u, 0x37FA32D0u, 0x100000u},
    {"19xx",     0x0E07181Fu, 0x5FD0F080u, 0x200000u},
    {"19xxj",    0x00115DF8u, 0x000FF87Eu, 0x200000u},
    {"ddsom",    0x87889ABCu, 0xD81F5F63u, 0x100000u},
    {"ddsomu",   0x489F0526u, 0x1BCD3E7Au, 0x100000u},
    {"megaman2", 0x50501CACu, 0xED346550u, 0x100000u},
    {"qndream",  0x5804EA73u, 0xF66B0798u, 0x080000u},
    {"sfa2",     0xFC4ACF9Cu, 0x3BFBE1F9u, 0x100000u},
    {"sfa2u",    0x1BBF3D96u, 0x8AF4614Au, 0x100000u},
    {"sfz2al",   0xF172C0D0u, 0x040621A6u, 0x100000u},
    {"spf2t",    0x706A8750u, 0x7D0FC185u, 0x040000u},
    {"spf2xj",   0xB12C835Au, 0xE90976FFu, 0x040000u},
    {"xmvsf",    0xBDCF8519u, 0x3FB2ACEAu, 0x100000u},
    {"xmvsfu",   0x4FCB03D2u, 0xF8653BC1u, 0x100000u},
    {"batcir",   0xD195E597u, 0x3CBCE2B5u, 0x200000u},
    {"csclub",   0x662E9FA0u, 0x4210E7C1u, 0x200000u},
    {"mshvsf",   0x1384AE60u, 0x9CD725BFu, 0x100000u},
    {"sgemf",    0x84234976u, 0x5E0FBB7Eu, 0x080000u},
    {"pfghtj",   0x97D2EBC0u, 0x308F94D7u, 0x080000u},
    {"vhunt2",   0x36C1EBA3u, 0x26B10F18u, 0x100000u},
    {"vsav",     0xE0CD5881u, 0x71BABB70u, 0x100000u},
    {"vsav2",    0xD681E4F4u, 0x60371EDFu, 0x100000u},
    {"mvsc",     0x48025ADEu, 0x1C697B27u, 0x100000u},
    {"mvscu",    0x692DC41Bu, 0x7EF1C805u, 0x100000u},
    {"sfa3",     0x6ABFC8E0u, 0x2780DDC1u, 0x100000u},
    {"sfa3u",    0xE7BBF0E5u, 0x67943248u, 0x100000u},
    {"hsf2",     0x5A369DDDu, 0xFEA3189Cu, 0x100000u},
    {"gigawing", 0xE52DE290u, 0x1B60D780u, 0x100000u},
    {"mmatrix",  0xAC9EBD79u, 0x410467DFu, 0x180000u},
    {"mpang",    0x95F741C6u, 0xE547A21Bu, 0x100000u},
    {"pzloop2",  0xA054F812u, 0xC40D36B4u, 0x400000u},
    {"choko",    0xD3FB12C6u, 0x7F8E17B5u, 0x400000u},
    {"dimahoo",  0x0DDB8E40u, 0x2817FD2Bu, 0x080000u},
    {"1944",     0x1D3E724Cu, 0x8B59FC7Au, 0x080000u},
    {"progear",  0x639AD8C6u, 0xEF130DF3u, 0x400000u},
    {0, 0, 0, 0}
};

struct cps1_preset {
    const char *name;
    u8 cpsb, mapper, qs;
    u32 k_sw1, k_sw2;
    u16 k_addr;
    u8 k_xor;
};

static const struct cps1_preset cps1_presets[] = {
    {"forgottn", CPS_B_01,     MAP_LWCHR,  0, 0,0,0,0},
    {"ghouls",   CPS_B_01,     MAP_DM620,  0, 0,0,0,0},
    {"strider",  CPS_B_01,     MAP_ST24M1, 0, 0,0,0,0},
    {"dynwar",   CPS_B_02,     MAP_TK22B,  0, 0,0,0,0},
    {"willow",   CPS_B_03,     MAP_WL24B,  0, 0,0,0,0},
    {"unsquad",  CPS_B_11,     MAP_AR24B,  0, 0,0,0,0},
    {"ffight",   CPS_B_04,     MAP_S224B,  0, 0,0,0,0},
    {"1941",     CPS_B_05,     MAP_YI24B,  0, 0,0,0,0},
    {"mercs",    CPS_B_12,     MAP_O224B,  0, 0,0,0,0},
    {"mtwins",   CPS_B_14,     MAP_CK24B,  0, 0,0,0,0},
    {"msword",   CPS_B_13,     MAP_MS24B,  0, 0,0,0,0},
    {"cawing",   CPS_B_16,     MAP_CA24B,  0, 0,0,0,0},
    {"nemo",     CPS_B_15,     MAP_NM24B,  0, 0,0,0,0},
    {"sf2",      CPS_B_11,     MAP_STF29,  0, 0,0,0,0},
    {"3wonders", CPS_B_21_BT1, MAP_RT24B,  0, 0,0,0,0},
    {"kod",      CPS_B_21_BT2, MAP_KD29B,  0, 0,0,0,0},
    {"captcomm", CPS_B_21_BT3, MAP_CC63B,  0, 0,0,0,0},
    {"knights",  CPS_B_21_BT4, MAP_KR63B,  0, 0,0,0,0},
    {"sf2ce",    CPS_B_21_DEF, MAP_S9263B, 0, 0,0,0,0},
    {"sf2hf",    CPS_B_21_DEF, MAP_S9263B, 0, 0,0,0,0},
    {"varth",    CPS_B_04,     MAP_VA63B,  0, 0,0,0,0},
    {"cworld2j", CPS_B_21_BT5, MAP_Q522B,  0, 0,0,0,0},
    {"megaman",  CPS_B_21_DEF, MAP_TK263B, 0, 0,0,0,0},
    {"rockmanj", CPS_B_21_DEF, MAP_TK263B, 0, 0,0,0,0},
    {"pnickj",   CPS_B_21_DEF, MAP_TK263B, 0, 0,0,0,0},
    {"wof",      CPS_B_21_QS1, MAP_TK263B, 1, 0x01234567u, 0x54163072u, 0x5151u, 0x51u},
    {"dino",     CPS_B_21_QS2, MAP_CD63B,  1, 0x76543210u, 0x24601357u, 0x4343u, 0x43u},
    {"punisher", CPS_B_21_QS3, MAP_PS63B,  1, 0x67452103u, 0x75316024u, 0x2222u, 0x22u},
    {"slammast", CPS_B_21_QS4, MAP_MB63B,  1, 0x54321076u, 0x65432107u, 0x3131u, 0x19u},
    {"mbombrd",  CPS_B_21_QS5, MAP_MB63B,  1, 0,0,0,0},
    {0, 0, 0, 0, 0, 0, 0, 0}
};

/* ---- ROM Format Detection & Loading (.cps / .cps1 / .cps2 & MAME .zip) ---- */

static void basename_no_ext(const char *path, char *out, int max)
{
    const char *base = path ? path : "";
    for (const char *p = base; *p; p++)
        if (*p == '/' || *p == '\\' || *p == ':')
            base = p + 1;
    int i = 0, dot = -1;
    for (; base[i] && i < max - 1; i++) {
        out[i] = cps_low(base[i]);
        if (base[i] == '.')
            dot = i;
    }
    out[dot >= 0 ? dot : i] = 0;
}

/* Parse CPS-2 numbered extension ("cybe.03a" -> 3, "spf.13m" -> 13, -1 if not CPS-2 numbered) */
static int parse_cps2_num_ext(const char *name, int *is_xor)
{
    *is_xor = 0;
    const char *dot = 0;
    for (const char *p = name; *p; p++)
        if (*p == '.')
            dot = p + 1;
    if (!dot || dot[0] < '0' || dot[0] > '9' || dot[1] < '0' || dot[1] > '9')
        return -1;
    int num = (dot[0] - '0') * 10 + (dot[1] - '0');
    for (const char *q = dot + 2; *q; q++)
        if (cps_low(*q) == 'x')
            *is_xor = 1;
    return num;
}

int cps_is_rom(const u8 *head, u32 n, const char *name)
{
    if (n >= 16 && head[0] == 'C' && head[1] == 'P' && head[2] == 'S' &&
        (head[3] == '1' || head[3] == '2'))
        return 1;
    if (name && (cps_ends_ci(name, ".cps") || cps_ends_ci(name, ".cps1") || cps_ends_ci(name, ".cps2")))
        return 1;
    if (zip_is(head, n)) {
        char first[96];
        if (zip_first_name(head, n, first, sizeof(first)) == 0) {
            if (cps_ends_ci(first, ".cps") || cps_ends_ci(first, ".cps1") ||
                cps_ends_ci(first, ".cps2") || cps_ends_ci(first, ".key"))
                return 1;
            int is_xor = 0;
            int num = parse_cps2_num_ext(first, &is_xor);
            if (num >= 1 && num <= 32)
                return 1;
        }
        if (name) {
            char base[64];
            basename_no_ext(name, base, sizeof(base));
            for (int i = 0; cps2_keys[i].name; i++)
                if (cps_streq_ci(base, cps2_keys[i].name))
                    return 1;
            for (int i = 0; cps1_presets[i].name; i++)
                if (cps_streq_ci(base, cps1_presets[i].name))
                    return 1;
        }
    }
    return 0;
}

void cps_set_extra(const u8 *extra, u32 extra_size)
{
    S.extra_ptr = extra;
    S.extra_len = extra_size;
}

/* Convert raw big-endian 68000 words into host u16 order for m68k.inc */
static void bswap16_buf(u8 *buf, u32 len)
{
    len &= ~1u;
    for (u32 i = 0; i < len; i += 2u) {
        u8 t = buf[i];
        buf[i] = buf[i + 1u];
        buf[i + 1u] = t;
    }
}

/* Unpack CPS-2 16-bit GFX ROM (1MB/2MB/4MB) into pre-separated u32 slivers */
static void cps2_unpack_gfx_one(u8 *tile_dst, const u8 *src, u32 rlen, u32 shift, u32 gfx_cap)
{
    u32 blocks = rlen >> 19;            /* 512 KB sections -> 2 MB output each */
    if (!blocks && rlen) {
        /* Sub-512KB homebrew CPS-2 GFX chip: linear even/odd interleave */
        u8 *pt = tile_dst;
        const u8 *ps = src;
        for (u32 i = 0; i + 4u <= rlen && (u32)(pt - S.gfx) + 4u <= gfx_cap; i += 4u, ps += 4, pt += 8) {
            u32 pix = (M->sep_tab[ps[0]] | (M->sep_tab[ps[1]] << 1)) << shift;
            *(u32 *)pt |= pix;
        }
        pt = tile_dst + (rlen << 1);
        ps = src + 2;
        for (u32 i = 0; i + 4u <= rlen && (u32)(pt - S.gfx) + 4u <= gfx_cap; i += 4u, ps += 4, pt += 8) {
            u32 pix = (M->sep_tab[ps[0]] | (M->sep_tab[ps[1]] << 1)) << shift;
            *(u32 *)pt |= pix;
        }
        return;
    }
    u8 *pt = tile_dst;
    const u8 *pr = src;
    for (u32 b = 0; b < blocks; b++, pr += 0x80000u) {
        for (int pass = 0; pass < 2; pass++) {
            const u8 *ps = pr + pass * 2;
            u8 *pe = pt + 0x100000u;
            while (pt < pe) {
                if ((u32)(pt - S.gfx) + 4u <= gfx_cap) {
                    u32 pix = (M->sep_tab[ps[0]] | (M->sep_tab[ps[1]] << 1)) << shift;
                    *(u32 *)pt |= pix;
                }
                pt += 8;
                ps += 4;
            }
        }
        CPS_FEED_DOG();
    }
}

/* Unpack CPS-1 16-bit GFX ROM (`word=1`) or 8-bit (`word=0`) into pre-separated u32 slivers */
static void cps1_unpack_gfx_one(u8 *tile_dst, const u8 *src, u32 rlen, int word, u32 shift, u32 gfx_cap)
{
    u8 *pt = tile_dst;
    const u8 *pr = src;
    u32 step = word ? 2u : 1u;
    for (u32 i = 0; i + step <= rlen; i += step, pt += 8) {
        u32 pix = M->sep_tab[*pr++];
        if (word)
            pix |= M->sep_tab[*pr++] << 1;
        if ((u32)(pt - S.gfx) + 4u <= gfx_cap)
            *(u32 *)pt |= (pix << shift);
    }
}

static void info_put(int *k, char c)
{
    if (*k < (int)sizeof(S.info) - 1)
        S.info[(*k)++] = c;
}

static void info_puts(int *k, const char *s)
{
    while (*s)
        info_put(k, *s++);
}

static void finalize_info(const char *title)
{
    const char *sys = (S.cps_ver == 2) ? "CPS-2" : (S.use_qsound ? "CPS-1.5 QSound" : "CPS-1");
    int k = 0;
    info_puts(&k, sys);
    if (title && title[0]) {
        info_puts(&k, ": ");
        for (int i = 0; title[i] && k < (int)sizeof(S.info) - 18; i++)
            info_put(&k, title[i]);
    }
    info_puts(&k, " (");
    u32 kb = (S.rom_len + S.zrom_len + S.snd_len + S.gfx_len) >> 10;
    char num[16];
    int nl = 0;
    u32 v = kb >= 1024u ? (kb >> 10) : kb;
    if (!v)
        num[nl++] = '0';
    while (v && nl < 15) {
        num[nl++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    while (nl--)
        info_put(&k, num[nl]);
    info_puts(&k, kb >= 1024u ? " MB)" : " KB)");
    S.info[k] = 0;
}

static const char *load_cps_container(const u8 *img, u32 size)
{
    if (size < 0x100u)
        return "CPS cartridge header too short";
    u32 flags  = cps_le32(img + 0x04);
    u32 p_sz   = cps_le32(img + 0x08);
    u32 z_sz   = cps_le32(img + 0x0C);
    u32 snd_sz = cps_le32(img + 0x10);
    u32 gfx_sz = cps_le32(img + 0x14);
    u64 total_need = 0x100ULL + (u64)p_sz + (u64)z_sz + (u64)snd_sz + (u64)gfx_sz;
    u64 avail = (u64)size + (u64)S.extra_len;
    if (total_need > avail)
        return "CPS cartridge truncated";
    if (!p_sz || p_sz > ROM_CAP || (p_sz & 1u))
        return "invalid 68000 P-ROM size in CPS cartridge";
    if (z_sz > ZROM_CAP || snd_sz > SND_CAP || gfx_sz > GFX_CAP)
        return "CPS cartridge exceeds board RAM capacity";

    S.cps_ver = (img[3] == '2') ? 2u : 1u;
    S.use_qsound = (S.cps_ver == 2 || (flags & 1u)) ? 1u : 0u;
    S.has_eeprom = (S.cps_ver == 2 || S.use_qsound) ? 1u : 0u;
    S.eeprom_16bit = (S.cps_ver == 2) ? 1u : 0u;
    S.ssf2t = (flags & 0x20u) ? 1u : 0u;
    S.xmcota = (flags & 0x40u) ? 1u : 0u;

    u8 cpsb = img[0x18] ? img[0x18] : (S.cps_ver == 2 ? CPS_B_21_DEF : CPS_B_01);
    if (img[0x18] == 0 && S.cps_ver == 2) cpsb = CPS_B_21_DEF;
    set_cpsb_id(cpsb);
    if (img[0x19] == 0xFFu || S.cps_ver == 2)
        set_gfx_mapper(MAP_DIRECT);
    else
        set_gfx_mapper(img[0x19]);

    S.dip_a = img[0x1A];
    S.dip_b = img[0x1B];
    S.dip_c = img[0x1C];

    u32 off_s1 = cps_le32(img + 0x20);
    u32 off_s2 = cps_le32(img + 0x24);
    u32 off_s3 = cps_le32(img + 0x28);
    u32 key[2] = {cps_le32(img + 0x2C), cps_le32(img + 0x30)};
    u32 key_upper = cps_le32(img + 0x34);
    u32 kab_sw1 = cps_le32(img + 0x38);
    u32 kab_sw2 = cps_le32(img + 0x3C);
    u32 kab_ax  = cps_le32(img + 0x40);

    char title[64];
    for (int i = 0; i < 60; i++) title[i] = (char)img[0x44 + i];
    title[60] = 0;

    /* Helper to copy across [img (size), S.extra_ptr (S.extra_len)] into dst */
    u32 cur = 0x100u;
    u8 *targets[4] = {ROM_BUF, ZROM_BUF, SND_BUF, GFX_BUF};
    u32 lens[4]    = {p_sz, z_sz, snd_sz, gfx_sz};
    for (int seg = 0; seg < 4; seg++) {
        u32 rem = lens[seg], dpos = 0;
        while (rem > 0) {
            if (cur < size) {
                u32 chunk = size - cur;
                if (chunk > rem) chunk = rem;
                cps_copy(targets[seg] + dpos, img + cur, chunk);
                cur += chunk; dpos += chunk; rem -= chunk;
            } else if (S.extra_ptr && cur - size < S.extra_len) {
                u32 eoff = cur - size;
                u32 chunk = S.extra_len - eoff;
                if (chunk > rem) chunk = rem;
                cps_copy(targets[seg] + dpos, S.extra_ptr + eoff, chunk);
                cur += chunk; dpos += chunk; rem -= chunk;
            } else {
                break;
            }
        }
        CPS_FEED_DOG();
    }

    S.rom = ROM_BUF; S.rom_len = p_sz;
    bswap16_buf(S.rom, S.rom_len);

    S.code = 0; S.code_len = 0;
    if (flags & 2u)
        cps2_decrypt_rom(key, 0, key_upper ? key_upper : S.rom_len);

    S.zrom = ZROM_BUF; S.zrom_len = z_sz;
    S.has_kabuki = 0;
    if ((flags & 4u) && z_sz > 0)
        kabuki_decode_rom(S.zrom, kab_sw1, kab_sw2, (u16)(kab_ax >> 8), (u8)(kab_ax & 0xFFu));

    S.ad_rom = SND_BUF;
    S.qsam = (s8 *)SND_BUF;
    S.snd_len = snd_sz;

    S.gfx = GFX_BUF;
    S.gfx_len = gfx_sz & ~3u;
    if (!(flags & 8u)) {
        /* Convert standard 4bpp planar C-ROM [b0,b1,b2,b3] in-place into u32 slivers */
        for (u32 i = 0; i < S.gfx_len; i += 4u) {
            const u8 *p = S.gfx + i;
            *(u32 *)(S.gfx + i) = M->sep_tab[p[0]] | (M->sep_tab[p[1]] << 1) |
                                   (M->sep_tab[p[2]] << 2) | (M->sep_tab[p[3]] << 3);
        }
    }

    u32 p2 = 64u;
    while (p2 < S.gfx_len && p2 < 0x40000000u)
        p2 <<= 1;
    S.gfx_mask = p2 - 1u;

    if (off_s1 || off_s2 || off_s3) {
        S.gfx_scroll[1] = off_s1;
        S.gfx_scroll[2] = off_s2;
        S.gfx_scroll[3] = off_s3;
    } else if (S.cps_ver == 2) {
        S.gfx_scroll[1] = S.gfx_scroll[2] = S.gfx_scroll[3] = (S.gfx_len > 0x800000u) ? 0x800000u : 0u;
    } else {
        S.gfx_scroll[1] = S.gfx_scroll[2] = S.gfx_scroll[3] = 0u;
    }

    S.m68k_hz = (S.cps_ver == 2 || (flags & 0x10u)) ? 16000000u : (S.use_qsound ? 12000000u : 10000000u);
    finalize_info(title);
    return 0;
}

static const char *load_mame_zip(const u8 *zip_in, u32 zip_sz, const char *path)
{
    if (zip_sz > SCRATCH_CAP - 0x200000u)
        return "CPS zip archive too large for staging buffer";

    /* Stage zip archive at top of SCRATCH_BUF so GFX_BUF (MEDIA_PHYS) is free */
    u8 *zbuf = SCRATCH_BUF + SCRATCH_CAP - zip_sz;
    cps_copy(zbuf, zip_in, zip_sz);
    u8 *tmp_chip = SCRATCH_BUF;
    u32 tmp_cap = SCRATCH_CAP - zip_sz;

    u32 count = zip_count(zbuf, zip_sz);
    if (!count)
        return "invalid or empty zip archive";

    /* If the zip contains a single .cps/.cps1/.cps2 file, unpack to GFX_BUF and load it */
    for (u32 i = 0; i < count; i++) {
        char mname[96];
        u32 msz = 0;
        if (zip_unpack_at(zbuf, zip_sz, i, 0, 0, &msz, mname, sizeof(mname)) == 0) {
            if (cps_ends_ci(mname, ".cps") || cps_ends_ci(mname, ".cps1") || cps_ends_ci(mname, ".cps2")) {
                if (msz > GFX_CAP)
                    return "packed .cps inside zip too large";
                const char *why = zip_unpack_at(zbuf, zip_sz, i, GFX_BUF, GFX_CAP, &msz, mname, sizeof(mname));
                if (why) return why;
                return load_cps_container(GFX_BUF, msz);
            }
        }
    }

    char setname[64];
    basename_no_ext(path, setname, sizeof(setname));

    /* Check if this is a CPS-2 numbered romset (.01/.02, .03..10, .11/.12, .13..20, optional .key) */
    s32 idx_num[33], idx_xor[11], idx_key = -1;
    for (int i = 0; i < 33; i++) idx_num[i] = -1;
    for (int i = 0; i < 11; i++) idx_xor[i] = -1;
    int cps2_hits = 0;

    for (u32 i = 0; i < count; i++) {
        char mname[96];
        u32 msz = 0;
        if (zip_unpack_at(zbuf, zip_sz, i, 0, 0, &msz, mname, sizeof(mname)) != 0 || !msz)
            continue;
        if (msz == 20u && (cps_ends_ci(mname, ".key") || cps_streq_ci(mname, "dl-1425.bin"))) {
            idx_key = (s32)i;
            cps2_hits++;
            continue;
        }
        int is_xor = 0;
        int num = parse_cps2_num_ext(mname, &is_xor);
        if (num >= 1 && num <= 32) {
            if (is_xor && num <= 10) idx_xor[num] = (s32)i;
            else idx_num[num] = (s32)i;
            cps2_hits++;
        }
    }

    if (cps2_hits >= 4 && idx_num[3] >= 0) {
        S.cps_ver = 2;
        S.use_qsound = 1;
        S.has_eeprom = 1;
        S.eeprom_16bit = 1;
        S.has_kabuki = 0;
        S.ssf2t = cps_streq_ci(setname, "ssf2t") || cps_streq_ci(setname, "ssf2tu") || cps_streq_ci(setname, "ssf2xj");
        S.xmcota = cps_streq_ci(setname, "xmcota") || cps_streq_ci(setname, "xmcotau") || cps_streq_ci(setname, "xmcotaj");
        set_cpsb_id(CPS_B_21_DEF);
        set_gfx_mapper(MAP_DIRECT);
        S.dip_a = S.dip_b = S.dip_c = 0;

        /* 1. 68000 P-ROMs (.03 .. .10) */
        u32 p_len = 0, x_len = 0;
        for (int n = 3; n <= 10; n++) {
            if (idx_num[n] >= 0) {
                char mn[64]; u32 sz = 0;
                const char *w = zip_unpack_at(zbuf, zip_sz, (u32)idx_num[n], ROM_BUF + p_len, ROM_CAP - p_len, &sz, mn, sizeof(mn));
                if (w) return w;
                p_len += sz;
            }
            if (idx_xor[n] >= 0) {
                char mn[64]; u32 sz = 0;
                const char *w = zip_unpack_at(zbuf, zip_sz, (u32)idx_xor[n], CODE_BUF + x_len, CODE_CAP - x_len, &sz, mn, sizeof(mn));
                if (w) return w;
                x_len += sz;
            }
            CPS_FEED_DOG();
        }
        if (!p_len)
            return "no 68000 program ROM (.03) in CPS-2 zip";
        S.rom = ROM_BUF; S.rom_len = p_len;
        bswap16_buf(S.rom, S.rom_len);

        /* 2. Decrypt CPS-2 opcodes (.key -> keys_table -> Phoenix XOR -> unencrypted) */
        S.code = 0; S.code_len = 0;
        if (idx_key >= 0) {
            u8 key20[20]; char mn[64]; u32 ksz = 0;
            if (zip_unpack_at(zbuf, zip_sz, (u32)idx_key, key20, 20, &ksz, mn, sizeof(mn)) == 0 && ksz == 20u) {
                u32 mk[2], lo = 0, hi = 0;
                cps2_parse_key20(key20, mk, &lo, &hi);
                cps2_decrypt_rom(mk, lo, hi);
            }
        } else if (x_len > 0) {
            bswap16_buf(CODE_BUF, x_len);
            for (u32 i = 0; i < x_len; i++)
                CODE_BUF[i] ^= ROM_BUF[i];
            S.code = CODE_BUF;
            S.code_len = x_len;
        } else {
            for (int i = 0; cps2_keys[i].name; i++) {
                if (cps_streq_ci(setname, cps2_keys[i].name)) {
                    u32 mk[2] = {cps2_keys[i].k0, cps2_keys[i].k1};
                    cps2_decrypt_rom(mk, 0, cps2_keys[i].upper);
                    break;
                }
            }
        }

        /* 3. Z80 ROMs (.01, .02) */
        u32 z_len = 0;
        for (int n = 1; n <= 2; n++) {
            if (idx_num[n] >= 0) {
                char mn[64]; u32 sz = 0;
                const char *w = zip_unpack_at(zbuf, zip_sz, (u32)idx_num[n], ZROM_BUF + z_len, ZROM_CAP - z_len, &sz, mn, sizeof(mn));
                if (w) return w;
                z_len += sz;
            }
        }
        S.zrom = ZROM_BUF; S.zrom_len = z_len;

        /* 4. QSound Sample ROMs (.11, .12 -- MAME stores CPS-2 QSound mask ROMs byte-swapped) */
        u32 s_len = 0;
        for (int n = 11; n <= 12; n++) {
            if (idx_num[n] >= 0 && s_len < SND_CAP) {
                char mn[64]; u32 sz = 0;
                const char *w = zip_unpack_at(zbuf, zip_sz, (u32)idx_num[n], SND_BUF + s_len, SND_CAP - s_len, &sz, mn, sizeof(mn));
                if (w) return w;
                bswap16_buf(SND_BUF + s_len, sz);
                s_len += sz;
                CPS_FEED_DOG();
            }
        }
        S.qsam = (s8 *)SND_BUF; S.ad_rom = SND_BUF; S.snd_len = s_len;

        /* 5. CPS-2 Graphics ROM groups (13,15,14,16 and 17,19,18,20) */
        S.gfx = GFX_BUF;
        u32 g_total = 0;
        for (int grp = 13; grp <= 29; grp += 4) {
            if (idx_num[grp] < 0)
                break;
            int order[4] = {grp, grp + 2, grp + 1, grp + 3};
            u32 max_chip = 0;
            for (int k = 0; k < 4; k++) {
                if (order[k] <= 32 && idx_num[order[k]] >= 0) {
                    char mn[64]; u32 sz = 0;
                    zip_unpack_at(zbuf, zip_sz, (u32)idx_num[order[k]], 0, 0, &sz, mn, sizeof(mn));
                    if (sz > max_chip) max_chip = sz;
                }
            }
            u32 grp_bytes = max_chip * 4u;
            u32 clr = (g_total + grp_bytes <= GFX_CAP) ? grp_bytes : (g_total < GFX_CAP ? GFX_CAP - g_total : 0u);
            if (clr)
                cps_zero(S.gfx + g_total, clr);

            for (int k = 0; k < 4; k++) {
                int rn = order[k];
                if (rn <= 32 && idx_num[rn] >= 0) {
                    char mn[64]; u32 sz = 0;
                    const char *w = zip_unpack_at(zbuf, zip_sz, (u32)idx_num[rn], tmp_chip, tmp_cap, &sz, mn, sizeof(mn));
                    if (w) return w;
                    u32 off = (k >= 2) ? 4u : 0u;
                    u32 sh  = (k & 1) ? 2u : 0u;
                    cps2_unpack_gfx_one(S.gfx + g_total + off, tmp_chip, sz, sh, GFX_CAP);
                }
            }
            g_total += grp_bytes;
        }
        if (g_total > GFX_CAP) g_total = GFX_CAP;
        S.gfx_len = g_total;
        u32 p2 = 64u;
        while (p2 < S.gfx_len && p2 < 0x40000000u) p2 <<= 1;
        S.gfx_mask = p2 - 1u;
        S.gfx_scroll[1] = S.gfx_scroll[2] = S.gfx_scroll[3] = (S.gfx_len > 0x800000u) ? 0x800000u : 0u;
        S.m68k_hz = 16000000u;
        finalize_info(setname);
        return 0;
    }

    /* Check CPS-1 / CCPS MAME .zip layout (e.g. sf2 / ccps: .11e/.11f..10e/10f, .12a, .11c/.12c, .4a/.6a/.3a/.5a) */
    const struct cps1_preset *pre = 0;
    for (int i = 0; cps1_presets[i].name; i++) {
        if (cps_streq_ci(setname, cps1_presets[i].name)) {
            pre = &cps1_presets[i];
            break;
        }
    }
    /* Detect CCPS / SF2 socket suffixes (.11e, .12a, .4a) even under custom homebrew zip names */
    s32 sf2_p[8] = {-1,-1,-1,-1,-1,-1,-1,-1};
    s32 sf2_gfx[12] = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
    s32 sf2_z = -1, sf2_oki[2] = {-1, -1};
    static const char *const sf2_p_suf[8] = {".11e",".11f",".12e",".12f",".9e",".9f",".10e",".10f"};
    static const char *const sf2_g_suf[12] = {
        ".4a",".6a",".3a",".5a", ".4c",".6c",".3c",".5c", ".4d",".6d",".3d",".5d"
    };
    int sf2_hits = 0;
    for (u32 i = 0; i < count; i++) {
        char mname[96]; u32 msz = 0;
        if (zip_unpack_at(zbuf, zip_sz, i, 0, 0, &msz, mname, sizeof(mname)) != 0 || !msz)
            continue;
        for (int k = 0; k < 8; k++)
            if (cps_ends_ci(mname, sf2_p_suf[k])) { sf2_p[k] = (s32)i; sf2_hits++; }
        for (int k = 0; k < 12; k++)
            if (cps_ends_ci(mname, sf2_g_suf[k])) { sf2_gfx[k] = (s32)i; sf2_hits++; }
        if (cps_ends_ci(mname, ".12a") || cps_ends_ci(mname, "z80.rom")) { sf2_z = (s32)i; sf2_hits++; }
        if (cps_ends_ci(mname, ".11c")) sf2_oki[0] = (s32)i;
        if (cps_ends_ci(mname, ".12c")) sf2_oki[1] = (s32)i;
    }
    if (sf2_hits >= 6 && sf2_p[0] >= 0 && sf2_p[1] >= 0 && sf2_gfx[0] >= 0) {
        S.cps_ver = 1;
        S.use_qsound = pre ? pre->qs : 0;
        S.has_eeprom = S.use_qsound;
        S.eeprom_16bit = 0;
        set_cpsb_id(pre ? pre->cpsb : CPS_B_11);
        set_gfx_mapper(pre ? pre->mapper : MAP_STF29);
        S.dip_a = S.dip_b = S.dip_c = 0;

        u32 p_len = 0;
        for (int pair = 0; pair < 4; pair++) {
            s32 ie = sf2_p[pair * 2], io = sf2_p[pair * 2 + 1];
            if (ie >= 0 && io >= 0) {
                char mn[64]; u32 sze = 0, szo = 0;
                if (zip_unpack_at(zbuf, zip_sz, (u32)ie, tmp_chip, tmp_cap >> 1, &sze, mn, sizeof(mn)) != 0)
                    return "bad CPS-1 even P-ROM";
                if (zip_unpack_at(zbuf, zip_sz, (u32)io, tmp_chip + sze, tmp_cap >> 1, &szo, mn, sizeof(mn)) != 0)
                    return "bad CPS-1 odd P-ROM";
                u32 n = sze < szo ? sze : szo;
                if (p_len + n * 2u > ROM_CAP) n = (ROM_CAP - p_len) >> 1;
                for (u32 b = 0; b < n; b++) {
                    ROM_BUF[p_len + b * 2u + 0u] = tmp_chip[b];
                    ROM_BUF[p_len + b * 2u + 1u] = tmp_chip[sze + b];
                }
                p_len += n * 2u;
            }
        }
        S.rom = ROM_BUF; S.rom_len = p_len;
        bswap16_buf(S.rom, S.rom_len);
        S.code = 0; S.code_len = 0;

        S.zrom = ZROM_BUF; S.zrom_len = 0;
        if (sf2_z >= 0) {
            char mn[64]; u32 sz = 0;
            if (zip_unpack_at(zbuf, zip_sz, (u32)sf2_z, ZROM_BUF, ZROM_CAP, &sz, mn, sizeof(mn)) == 0)
                S.zrom_len = sz;
        }
        S.has_kabuki = 0;
        if (pre && pre->k_sw1 && S.zrom_len)
            kabuki_decode_rom(S.zrom, pre->k_sw1, pre->k_sw2, pre->k_addr, pre->k_xor);

        u32 s_len = 0;
        for (int k = 0; k < 2; k++) {
            if (sf2_oki[k] >= 0 && s_len < SND_CAP) {
                char mn[64]; u32 sz = 0;
                if (zip_unpack_at(zbuf, zip_sz, (u32)sf2_oki[k], SND_BUF + s_len, SND_CAP - s_len, &sz, mn, sizeof(mn)) == 0)
                    s_len += sz;
            }
        }
        S.ad_rom = SND_BUF; S.qsam = (s8 *)SND_BUF; S.snd_len = s_len;

        S.gfx = GFX_BUF;
        u32 g_total = 0;
        for (int bank = 0; bank < 3; bank++) {
            if (sf2_gfx[bank * 4] < 0)
                break;
            /* CPS-1 64-bit C-bus: .4a(5m)=left b0-1, .6a(7m)=left b2-3, .3a(1m)=right b0-1, .5a(3m)=right b2-3 */
            u32 bsz = 0x200000u;
            if (g_total + bsz <= GFX_CAP)
                cps_zero(S.gfx + g_total, bsz);
            for (int k = 0; k < 4; k++) {
                s32 gi = sf2_gfx[bank * 4 + k];
                if (gi >= 0) {
                    char mn[64]; u32 sz = 0;
                    if (zip_unpack_at(zbuf, zip_sz, (u32)gi, tmp_chip, tmp_cap, &sz, mn, sizeof(mn)) == 0) {
                        u32 off = (k >= 2) ? 4u : 0u;
                        u32 sh  = (k & 1) ? 2u : 0u;
                        cps1_unpack_gfx_one(S.gfx + g_total + off, tmp_chip, sz, 1, sh, GFX_CAP);
                    }
                }
            }
            g_total += bsz;
        }
        S.gfx_len = g_total;
        u32 p2 = 64u;
        while (p2 < S.gfx_len && p2 < 0x40000000u) p2 <<= 1;
        S.gfx_mask = p2 - 1u;
        S.gfx_scroll[1] = S.gfx_scroll[2] = S.gfx_scroll[3] = 0u;
        S.m68k_hz = 10000000u;
        finalize_info(setname);
        return 0;
    }

    return "unrecognized CPS zip layout (pack with tools/cps_pack.py or use CPS-2 .01..20 romset)";
}

void cps_reset(void)
{
    cps_zero(M->ram90, sizeof(M->ram90));
    cps_zero(M->ramff, sizeof(M->ramff));
    cps_zero(M->ram660, sizeof(M->ram660));
    cps_zero(M->ram708, sizeof(M->ram708));
    cps_zero(M->zram_c0, sizeof(M->zram_c0));
    cps_zero(M->zram_f0, sizeof(M->zram_f0));
    cps_zero(M->pal_save, sizeof(M->pal_save));
    cps_zero(M->pal15, sizeof(M->pal15));
    cps_zero(M->zbuf, sizeof(M->zbuf));
    cps_zero(M->obj_snap, sizeof(M->obj_snap));
    cps_zero(S.cps_reg, sizeof(S.cps_reg));
    cps_zero(S.cps_frg, sizeof(S.cps_frg));

    /* Disable beam-synchronized IRQs on reset ($80014E = 0x0200) */
    S.cps_reg[0x4E] = 0x02; S.cps_reg[0x4F] = 0x00;
    S.cps_reg[0x50] = 0x01; S.cps_reg[0x51] = 0x06;
    S.cps_reg[0x52] = 0x01; S.cps_reg[0x53] = 0x06;
    if (S.cps_ver == 2) {
        S.cps_frg[0x09] = 0x40;
        S.cps_frg[0x0B] = 0x10;
    }

    S.irq_pending = 0;
    S.obj_bank = 0;
    S.obj_bank_used1 = 0;
    S.snap_idx = 0;
    S.r664001 = 0;
    S.pal_latched_once = 0;
    S.calc[0] = S.calc[1] = 0;
    S.extra_cyc = S.z_extra_cyc = 0;
    S.psnd_code = S.psnd_fade = 0;
    S.qsc_cmd[0] = S.qsc_cmd[1] = 0;
    S.q_irq_next = 31746;
    S.frame_num = 0;

    cps_zero(&S.eep, sizeof(S.eep));
    S.eep.do_bit = 1;

    cps_zero(&S.opm, sizeof(S.opm));
    S.opm.lfsr = 1;
    for (int ch = 0; ch < 8; ch++) {
        S.opm.ch[ch].rl = 3;
        S.opm.ch[ch].quiet = 1;
        for (int n = 0; n < 4; n++) {
            S.opm.ch[ch].op[n].att = 0x3FF;
            S.opm.ch[ch].op[n].env = 0x3FF;
            S.opm.ch[ch].op[n].state = EG_REL;
        }
    }
    cps_zero(&S.oki, sizeof(S.oki));
    S.oki.rate_hz = 7576u;
    qsc_reset();

    setup_m68k_map();
    cpu_reset();
    z80_setup_map();
}

const char *cps_load(u8 *image, u32 size, const char *path)
{
    if (!image || size < 16u)
        return "empty or truncated CPS file";

    init_sep_table();
    if (!S.cpu_ready) {
        cpu_init();
        S.cpu_ready = 1;
    }

    u32 saved_rate = S.snd_rate;
    const u8 *saved_extra = S.extra_ptr;
    u32 saved_extra_len = S.extra_len;
    cps_zero(&S, sizeof(S));
    S.sep_ready = 1;
    S.cpu_ready = 1;
    S.extra_ptr = saved_extra;
    S.extra_len = saved_extra_len;

    for (int i = 0; i < 0x80; i++)
        M->eeprom[i] = 0xFFu;

    const char *why = 0;
    if (image[0] == 'C' && image[1] == 'P' && image[2] == 'S' &&
        (image[3] == '1' || image[3] == '2')) {
        why = load_cps_container(image, size);
    } else if (zip_is(image, size)) {
        why = load_mame_zip(image, size, path);
    } else {
        return "not a Capcom CPS-1 / CPS-2 cartridge (.cps) or MAME .zip romset";
    }
    if (why)
        return why;

    S.z80_hz = S.use_qsound ? 8000000u : 4000000u;
    S.cyc_per_frame = (s32)((S.m68k_hz * 100u) / 5963u);
    S.zcyc_per_frame = (s32)((S.z80_hz * 100u) / 5963u);
    cps_audio_rate(saved_rate ? saved_rate : 48000u);
    S.extra_ptr = 0;
    S.extra_len = 0;

    cps_reset();
    return 0;
}

static void update_inputs(void)
{
    u16 p1 = S.pads[0], p2 = S.pads[1];
    u8 i1 = 0, i0 = 0;
    if (p1 & CPS_PAD_RIGHT) i1 |= 0x01u;
    if (p1 & CPS_PAD_LEFT)  i1 |= 0x02u;
    if (p1 & CPS_PAD_DOWN)  i1 |= 0x04u;
    if (p1 & CPS_PAD_UP)    i1 |= 0x08u;
    if ((i1 & 0x03u) == 0x03u) i1 &= ~0x03u;
    if ((i1 & 0x0Cu) == 0x0Cu) i1 &= ~0x0Cu;
    if (p1 & CPS_PAD_LP)    i1 |= 0x10u;
    if (p1 & CPS_PAD_MP)    i1 |= 0x20u;
    if (p1 & CPS_PAD_HP)    i1 |= 0x40u;

    if (p2 & CPS_PAD_RIGHT) i0 |= 0x01u;
    if (p2 & CPS_PAD_LEFT)  i0 |= 0x02u;
    if (p2 & CPS_PAD_DOWN)  i0 |= 0x04u;
    if (p2 & CPS_PAD_UP)    i0 |= 0x08u;
    if ((i0 & 0x03u) == 0x03u) i0 &= ~0x03u;
    if ((i0 & 0x0Cu) == 0x0Cu) i0 &= ~0x0Cu;
    if (p2 & CPS_PAD_LP)    i0 |= 0x10u;
    if (p2 & CPS_PAD_MP)    i0 |= 0x20u;
    if (p2 & CPS_PAD_HP)    i0 |= 0x40u;

    S.inp001 = i1;
    S.inp000 = i0;

    /* 6-button Kick Harness (CPS-2: Inp011/020; CPS-1 SF2: Inp177/186) */
    u8 k1 = 0;
    if (p1 & CPS_PAD_LK) k1 |= 0x01u;
    if (p1 & CPS_PAD_MK) k1 |= 0x02u;
    if (p1 & CPS_PAD_HK) k1 |= 0x04u;
    if (p2 & CPS_PAD_LK) k1 |= 0x10u;
    if (p2 & CPS_PAD_MK) k1 |= 0x20u;
    S.inp011 = k1;
    S.inp177 = k1;

    /* CPS-1 Coins/Start ($800018) & CPS-2 Coins/Start ($800020) */
    u8 c18 = 0, c20 = 0;
    if (p1 & CPS_PAD_COIN)  { c18 |= 0x01u; c20 |= 0x10u; }
    if (p2 & CPS_PAD_COIN)  { c18 |= 0x02u; c20 |= 0x20u; }
    if (p1 & CPS_PAD_START) { c18 |= 0x10u; c20 |= 0x01u; }
    if (p2 & CPS_PAD_START) { c18 |= 0x20u; c20 |= 0x02u; }
    if (p2 & CPS_PAD_HK)    c20 |= 0x40u;
    S.inp018 = c18;
    S.inp020 = c20;
    S.inp010 = 0;
    S.inp021 = 0;
}

void cps_pad2(u16 pad)
{
    S.pads[1] = pad;
}

void cps_frame(u16 pad, u16 *picture)
{
    S.pads[0] = pad;
    update_inputs();

    m.clock = S.extra_cyc;
    S.z.cycles = S.z_extra_cyc;
    S.q_irq_next -= S.zcyc_per_frame;
    if (S.q_irq_next < 0)
        S.q_irq_next = 31746;
    S.snd_rendered = 0;
    S.r664001 ^= 0x02u;

    for (int i = 0; i < MAX_RASTER + 2; i++)
        S.raster_lines[i] = 0;
    S.n_rasters = 0;

    u16 r4e = reg16(S.cps_reg, 0x4Eu);
    u16 r50 = reg16(S.cps_reg, 0x50u);
    u16 r52 = reg16(S.cps_reg, 0x52u);
    int auto50 = (r50 & 0x8000u) != 0;
    int auto52 = (r52 & 0x8000u) != 0;
    S.irq_line50 = (auto50 || !(r4e & 0x0200u)) ? (s32)(r50 & 0x1FFu) : TOTAL_LINES;
    S.irq_line52 = (auto52 || !(r4e & 0x0200u)) ? (s32)(r52 & 0x1FFu) : TOTAL_LINES;

    s32 cyc_per_line = S.cyc_per_frame / TOTAL_LINES;
    int latched_top = 0;

    for (s32 line = 0; line < TOTAL_LINES; line++) {
        S.cur_scanline = line;
        if (line == FIRST_VIS_LINE && !latched_top) {
            cps_copy(M->save_reg[0], S.cps_reg, 0x100u);
            cps_copy(M->save_frg[0], S.cps_frg, 0x10u);
            latched_top = 1;
        }
        /* Raster beam interrupt IRQ4 */
        if (S.cps_ver == 2 && (line == S.irq_line50 || line == S.irq_line52)) {
            if (line >= FIRST_VIS_LINE && line - FIRST_VIS_LINE < VIS_LINES && S.n_rasters < MAX_RASTER - 1) {
                S.n_rasters++;
                S.raster_lines[S.n_rasters] = line - FIRST_VIS_LINE;
            }
            S.irq_pending |= 0x10u;
            cps_update_ipl();
            cps_cpu_run((line + 1) * cyc_per_line);
            if (S.n_rasters > 0 && S.raster_lines[S.n_rasters] < VIS_LINES) {
                cps_copy(M->save_reg[S.n_rasters], S.cps_reg, 0x100u);
                cps_copy(M->save_frg[S.n_rasters], S.cps_frg, 0x10u);
            }
            if (line == S.irq_line50) S.irq_line50 = auto50 ? (S.irq_line50 + 32) : TOTAL_LINES;
            if (line == S.irq_line52) S.irq_line52 = auto52 ? (S.irq_line52 + 32) : TOTAL_LINES;
            continue;
        }

        /* End of active display (line 240): latch sprites, render frame, fire VBlank IRQ2 */
        if (line == FIRST_VIS_LINE + VIS_LINES) {
            /* CPS-1 games write sprite RAM during active frame; CPS-2 double-buffers */
            struct cps_obj_snap *cur_snap = &M->obj_snap[S.snap_idx & 1u];
            snapshot_sprites(cur_snap);
            const struct cps_obj_snap *draw_snap = cur_snap;
            if (S.cps_ver == 2 && S.frame_num > 0 && S.obj_bank_used1)
                draw_snap = cur_snap;
            S.snap_idx ^= 1u;

            render_frame(picture, draw_snap);

            S.irq_pending |= 0x04u;
            cps_update_ipl();
        }

        cps_cpu_run((line + 1) * cyc_per_line);
        if ((line & 31) == 31)
            z80_sync_from_m68k();
    }

    cps_cpu_run(S.cyc_per_frame);
    z80_sync_to(S.zcyc_per_frame);

    if (S.snd_rate) {
        u32 frame_samples = (S.snd_rate * 100u) / 5963u;
        if (S.use_qsound) qsc_render_to(frame_samples);
        else              psnd_render_to(frame_samples);
    }

    S.extra_cyc = m.clock - S.cyc_per_frame;
    S.z_extra_cyc = S.z.cycles - S.zcyc_per_frame;
    S.frame_num++;
}

const char *cps_info(void)
{
    return S.info;
}

u8 *cps_save_ram(u32 *size, int *battery)
{
    *size = S.has_eeprom ? 0x80u : 0u;
    *battery = S.has_eeprom ? 1 : 0;
    return M->eeprom;
}

int cps_save_changed(void)
{
    int d = S.eeprom_dirty;
    S.eeprom_dirty = 0;
    return d;
}

int cps_jammed(void)
{
    return m.stopped && m.im == 7u;
}

void cps_audio_rate(u32 hz)
{
    S.snd_rate = hz;
    S.snd_head = S.snd_tail = 0;
    if (hz) {
        S.q_pitch_scale = (24096u << 12) / hz;
        for (int i = 0; i < 16; i++)
            qsc_calc_adv(&S.qch[i]);
        for (int ch = 0; ch < 8; ch++)
            for (int n = 0; n < 4; n++)
                opm_op_update(&S.opm.ch[ch], n);
    }
}

int cps_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && S.snd_tail != S.snd_head) {
        out[n++] = M->snd_ring[S.snd_tail];
        S.snd_tail = (S.snd_tail + 1u) & (SND_RING - 1u);
    }
    return n;
}
