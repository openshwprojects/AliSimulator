/* Sega CD / Mega-CD ('segacd') expansion unit for md.c: see segacd.h. */
#pragma GCC optimize("O2")
#include "segacd.h"
#ifndef SEGACD_HOST
#include "hw.h"
#endif

typedef signed char s8;

#define INLINE static inline __attribute__((always_inline))

/* Sub-68000 runs at 12.5 MHz; Main-68000 runs at 7.670454 MHz (ratio ~ 1669/1024) */
#define SCD_STOPWATCH_DIV  384
#define SCD_CDD_DIV        166667       /* 12,500,000 / 75 Hz = 166,666.67 Sub-CPU cycles */
#define SCD_PCM_HZ         32552u       /* 12,500,000 / 384 = 32,552.08 Hz */

/* CDD status nibbles */
enum {
    CDD_STOP  = 0x00,
    CDD_PLAY  = 0x01,
    CDD_SEEK  = 0x02,
    CDD_SCAN  = 0x03,
    CDD_PAUSE = 0x04,
    CDD_OPEN  = 0x05,
    CDD_TOC   = 0x09,
    CDD_NOCD  = 0x0B,
    CDD_END   = 0x0C
};

/* CDC IFSTAT / IFCTRL / CTRL bits */
#define CDC_BIT_DTEI   0x40u
#define CDC_BIT_DECI   0x20u
#define CDC_BIT_DTBSY  0x08u
#define CDC_BIT_DTEN   0x02u
#define CDC_BIT_DTEIEN 0x40u
#define CDC_BIT_DECIEN 0x20u
#define CDC_BIT_DOUTEN 0x02u
#define CDC_BIT_DECEN  0x80u
#define CDC_BIT_AUTORQ 0x10u
#define CDC_BIT_WRRQ   0x04u
#define CDC_BIT_MODRQ  0x08u
#define CDC_BIT_FORMRQ 0x04u
#define CDC_BIT_SHDREN 0x01u

struct scd_pcm_ch {
    u32 addr;                           /* 16.11 fixed-point Wave RAM index */
    u32 st;                             /* Start address (data << 19) */
    u16 fd;                             /* 5.11 step increment */
    u16 ls;                             /* 16-bit loop address */
    u8  env;                            /* Envelope volume (0..255) */
    u8  pan;                            /* L: low nibble, R: high nibble */
};

struct segacd_state {
    const struct cdrom_toc *cd;
    u8  ext_bios;
    u8  pal_mode, overseas_mode;
    u8  bram_dirty;
    u8  optab_ready;

    /* Gate Array 256 x 16-bit register file ($FF8000..$FF81FF) */
    u16 regs[256];
    u8  sres;                           /* $A12001 bit 0: 1 = Sub-CPU running, 0 = held in reset */
    u8  sbrq;                           /* $A12001 bit 1: 1 = Main-CPU bus request (Sub-CPU halted) */
    u8  dmna_latch;
    u8  pending;                        /* Pending Sub-CPU IRQ bitmask (bits 1..6) */
    u8  ien;                            /* $FF8033 interrupt enable mask (bits 1..6) */

    /* Sub-68000 timing, Stopwatch & IRQ3 Timer */
    s32 sub_run_until;
    s32 stopwatch_base;
    s32 timer_cnt;
    s32 cdd_cnt;

    /* CDD (75 Hz drive controller & Redbook CD-DA player) */
    u8  cdd_status;
    u8  cdd_pending;
    s32 cdd_latency;
    s32 cdd_lba;
    s32 cdd_end_lba;
    u8  cdd_loop;
    u8  cdd_track_idx;                  /* 1..last_track */
    s32 cdd_scan_step;
    u16 cdda_fader_cur, cdda_fader_dst; /* 0..1024 (LC7883KM) */
    u32 cdda_lba;
    u32 cdda_pos;                       /* 0..588 stereo frames in cdda_sec */
    u32 cdda_phase;
    s16 cdda_l, cdda_r;
    u8  cdda_playing;

    /* Sanyo LC89510 CDC */
    u8  cdc_ar;
    u8  cdc_ifstat, cdc_ifctrl;
    u8  cdc_ctrl0, cdc_ctrl1;
    u8  cdc_stat0, cdc_stat2, cdc_stat3;
    u8  cdc_head[2][4];
    u8  cdc_irq;
    u8  cdc_dma_mode;                   /* 0=none, 4=PCM, 5=PRG, 7=Word2M, 8=Word1M0, 9=Word1M1 */
    u16 cdc_dbc, cdc_dac, cdc_pt, cdc_wa;
    s32 cdc_dma_cyc, cdc_dec_end;

    /* Clean-room _CDBIOS sector read queue state */
    u8  hle_reading;
    u8  hle_sec_ready;
    u32 hle_cur_lba, hle_rem_sec;
    u8  hle_head[4];

    /* Word-RAM Stamp ASIC ($FF8058..$FF8067) */
    u32 gfx_dot_mask;
    u8  gfx_stamp_shift, gfx_map_shift;
    u32 gfx_map_off;                    /* byte offset in word_ram_2m */
    u32 gfx_trace_off;                  /* byte offset in word_ram_2m */
    u32 gfx_buf_off;                    /* column stride in dots */
    u32 gfx_buf_start;                  /* dot index in word_ram_2m */
    s32 gfx_cyc_per_line;
    s32 gfx_last_cyc;

    /* Ricoh RF5C164 8-channel PCM */
    struct scd_pcm_ch pcm_ch[8];
    u8  pcm_en;
    u8  pcm_on_mask;                    /* bit j = 1 when channel j is active */
    u8  pcm_sel;                        /* selected channel 0..7 */
    u8  pcm_bank;                       /* selected 4 KB Wave RAM bank 0..15 */
    u32 pcm_phase;
    s16 pcm_l, pcm_r;

    u32 sub_poll_pc;
    u8  sub_poll_cnt;

    char title_buf[96];
};

static void s68k_iack(u32 level);
static void scd_gfx_update(s32 cur_cyc);

static void s68k_idle_branch(u32 at);
#define M68K_IACK(level)   s68k_iack(level)
#define M68K_BRANCH(at)    s68k_idle_branch(at)
#define M68K_EXTERNAL_STATE                                                     \
    struct segacd_mem {                                                         \
        struct segacd_state st;                                                 \
        struct m68k s68k;                                                       \
        u8 *s68k_rmap[256];                                                     \
        u8 *s68k_wmap[256];                                                     \
        u8  s68k_optab[65536];                                                  \
        u8  bios_rom[0x20000];      /* 128 KB Main-CPU Mega-CD BIOS */          \
        u8  prg_ram[0x80000];       /* 512 KB Sub-CPU PRG-RAM */                \
        u8  word_ram_2m[0x40000];   /* 256 KB Word-RAM (2M view) */             \
        u8  word_ram_1m[2][0x20000];/* 2 x 128 KB Word-RAM (1M banks) */        \
        u8  cdc_ram[0x4400];        /* 16 KB + wrap LC89510 CDC buffer */       \
        u8  pcm_ram[0x10000];       /* 64 KB RF5C164 PCM Wave RAM */            \
        u8  bram[0x2000];           /* 8 KB internal Backup RAM */              \
        u8  cdda_sec[2352];         /* Current Redbook CD-DA sector */          \
        u8  hle_sec[2048];          /* Clean-room _CDBIOS sector buffer */      \
        u16 lut_offset[0x8000];     /* 1M Cell-RAM rearrangement LUT */         \
        u8  lut_cell[256];          /* Stamp ASIC cell flip/rot LUT */          \
        u8  lut_pixel[512];         /* Stamp ASIC pixel flip/rot LUT */         \
    };                                                                          \
    SEGACD_MEM_BIND                                                             \
    /* Bind m68k.inc globals into EMU_RAM_PHYS */

#ifdef SEGACD_HOST
#define SEGACD_MEM_BIND static struct segacd_mem segacd_mem_buf;
#define M (&segacd_mem_buf)
#else
#define SEGACD_MEM_BIND
#define M ((struct segacd_mem *)KSEG0(EMU_RAM_PHYS))
#endif

#define S     (M->st)
#define m     (M->s68k)
#define rmap  (M->s68k_rmap)
#define wmap  (M->s68k_wmap)
#define optab (M->s68k_optab)

#include "m68k.inc"

#ifndef SEGACD_HOST
_Static_assert(sizeof(struct segacd_mem) <= EMU_RAM_SIZE, "segacd_mem exceeds EMU_RAM_SIZE");
#endif

/* Helper macros for m68k.inc native word-swapped memory (p[addr ^ 1] = byte) */
#define WSW_RB(base, addr)      ((base)[(addr) ^ 1u])
#define WSW_WB(base, addr, val) ((base)[(addr) ^ 1u] = (u8)(val))
#define WSW_RW(base, even_addr) (*(const u16 *)((base) + ((even_addr) & ~1u)))
#define WSW_WW(base, even_addr, val) (*(u16 *)((base) + ((even_addr) & ~1u)) = (u16)(val))

static inline u8 to_bcd8(u32 v)
{
    v %= 100u;
    return (u8)(((v / 10u) << 4) | (v % 10u));
}

static inline u16 to_bcd16(u32 v)
{
    v %= 100u;
    return (u16)(((v / 10u) << 8) | (v % 10u));
}

static inline u32 rd_be32(const u8 *p)
{
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

/* Pixel priority mixer for 1M Dot-RAM & 2M Stamp ASIC (PM0..1 = bits 4..3 of $FF8003) */
static inline u8 prio_mix_byte(u32 pm, u8 old_b, u8 new_b)
{
    switch (pm & 3u) {
    case 0: /* Normal */
        return new_b;
    case 1: /* Underwrite (keep existing non-zero nibbles) */
        return (u8)(((old_b & 0xF0u) ? (old_b & 0xF0u) : (new_b & 0xF0u)) |
                    ((old_b & 0x0Fu) ? (old_b & 0x0Fu) : (new_b & 0x0Fu)));
    case 2: /* Overwrite (write only non-zero new nibbles) */
        return (u8)(((new_b & 0xF0u) ? (new_b & 0xF0u) : (old_b & 0xF0u)) |
                    ((new_b & 0x0Fu) ? (new_b & 0x0Fu) : (old_b & 0x0Fu)));
    default:
        return old_b;
    }
}

/* ========================================================================
 * Sub-68000 Interrupts, Idle-Loop Detector & Memory Map
 * ======================================================================== */

static void s68k_update_irq(void)
{
    u8 mask = S.pending & S.ien;
    u32 lvl = 0;
    for (int i = 6; i >= 1; i--) {
        if (mask & (1u << i)) {
            lvl = (u32)i;
            break;
        }
    }
    m.ipl = lvl;
    check_pending();
}

static void s68k_trigger_irq(u32 level)
{
    if (S.ien & (1u << level)) {
        S.pending |= (u8)(1u << level);
        s68k_update_irq();
    }
}

static void s68k_iack(u32 level)
{
    S.pending &= (u8)~(1u << level);
    if (level == 2u)
        S.regs[0] &= (u16)~0x0100u;     /* Clear IFL2 */
    s68k_update_irq();
}

static void scd_gfx_update(s32 cur_cyc);

static void s68k_idle_branch(u32 at)
{
    u32 t = m.pc;
    if (t >= at || at - t > 10u || (t & 1u))
        return;
    const u8 *p = rmap[(t >> 16) & 0xFFu];
    if (!p || ((t + 10u) >> 16) != (t >> 16))
        return;
    u32 op = *(const u16 *)(p + (t & 0xFFFFu)), len, a;
    if ((op & 0xFF00u) == 0x4A00u && (op & 0xC0u) != 0xC0u)
        len = 2u;
    else if ((op & 0xFF00u) == 0x0C00u && (op & 0xC0u) != 0xC0u)
        len = (op & 0xC0u) == 0x80u ? 6u : 4u;
    else if ((op & 0xFFC0u) == 0x0800u)
        len = 4u;
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
    if (t + len != at)
        return;
    u32 a24 = a & 0xFFFFFFu;
    if ((a24 & 0xFFFE00u) == 0xFF8000u) {
        u32 gr = a24 & 0x1FEu;
        if (gr == 0x06u || gr == 0x08u || gr == 0x0Cu)
            return;
        if (gr == 0x58u) {
            if (m.clock < S.sub_run_until)
                m.clock = S.sub_run_until;
            scd_gfx_update(m.clock);
            return;
        }
    } else if ((a24 & 0x0F0000u) >= 0x080000u) {
        return;
    }
    if (m.clock < S.sub_run_until)
        m.clock = S.sub_run_until;
}

static void s68k_rebuild_map(void)
{
    u8 mem_mode = (u8)(S.regs[1] & 0xFFu);
    int is_1m = (mem_mode & 0x04u) != 0;
    int ret   = (mem_mode & 0x01u) != 0;
    u8  wp    = (u8)(S.regs[1] >> 8);

    for (u32 i = 0; i < 256u; i++) {
        u32 slot = i & 0x0Fu;
        rmap[i] = 0;
        wmap[i] = 0;
        if (slot < 8u) {
            /* $000000..$07FFFF: 512 KB PRG-RAM (mirrored every 1 MB) */
            u8 *pg = M->prg_ram + (slot << 16);
            rmap[i] = pg;
            /* First 128 KB ($000000..$01FFFF) has WP0..7 write-protect (in 512 B blocks) */
            if (slot >= 2u || wp == 0u)
                wmap[i] = pg;
        } else if (slot < 12u) {
            /* $080000..$0BFFFF: 256 KB Word-RAM (2M) or 256 KB Dot-RAM (1M -> via io_read/write) */
            if (!is_1m && !ret) {
                u8 *pg = M->word_ram_2m + ((slot & 3u) << 16);
                rmap[i] = pg;
                wmap[i] = pg;
            }
        } else if (slot < 14u) {
            /* $0C0000..$0DFFFF: 128 KB Word-RAM bank in 1M mode */
            if (is_1m) {
                int sub_bank = ret ? 0 : 1;
                u8 *pg = M->word_ram_1m[sub_bank] + ((slot & 1u) << 16);
                rmap[i] = pg;
                wmap[i] = pg;
            }
        }
        /* slot 14 ($FE0000: 8 KB BRAM) & slot 15 ($FF0000: PCM + Gate Array) go via io_read/io_write */
    }
}

static void scd_word_ram_switch(int to_1m)
{
    u16 *p2m = (u16 *)M->word_ram_2m;
    u16 *p0  = (u16 *)M->word_ram_1m[0];
    u16 *p1  = (u16 *)M->word_ram_1m[1];
    if (to_1m) {
        for (u32 i = 0; i < 0x10000u; i++) {
            *p0++ = *p2m++;
            *p1++ = *p2m++;
        }
    } else {
        for (u32 i = 0; i < 0x10000u; i++) {
            *p2m++ = *p0++;
            *p2m++ = *p1++;
        }
    }
}

/* ========================================================================
 * Word-RAM Stamp ASIC ($FF8058..$FF8067) & 1M Cell/Dot LUTs
 * ======================================================================== */

static void scd_init_gfx_luts(void)
{
    for (u32 i = 0; i < 0x4000u; i++)
        M->lut_offset[i] = (u16)(((i & 7u) << 8) | (((i >> 8) & 0x3Fu) << 2) | (((i >> 3) & 0x1Fu) << 11));
    for (u32 i = 0x4000u; i < 0x6000u; i++)
        M->lut_offset[i] = (u16)(((i & 7u) << 8) | (((i >> 7) & 0x3Fu) << 2) | (((i >> 3) & 0x0Fu) << 11));
    for (u32 i = 0x6000u; i < 0x7000u; i++)
        M->lut_offset[i] = (u16)(((i & 7u) << 8) | (((i >> 6) & 0x3Fu) << 2) | (((i >> 3) & 0x07u) << 11) | 0x8000u);
    for (u32 i = 0x7000u; i < 0x7800u; i++)
        M->lut_offset[i] = (u16)(((i & 7u) << 8) | (((i >> 5) & 0x3Fu) << 2) | (((i >> 3) & 0x03u) << 11) | 0xC000u);
    for (u32 i = 0x7800u; i < 0x8000u; i++)
        M->lut_offset[i] = (u16)(((i & 7u) << 8) | (((i >> 5) & 0x3Fu) << 2) | (((i >> 3) & 0x03u) << 11) | 0xE000u);

    for (u32 i = 0; i < 256u; i++) {
        u8 mask = (i & 8u) ? 3u : 1u;
        u8 row  = (u8)((i >> 6) & mask);
        u8 col  = (u8)((i >> 4) & mask);
        if (i & 4u) col ^= mask;
        if (i & 2u) { col ^= mask; row ^= mask; }
        if (i & 1u) { u8 t = col; col = row ^ mask; row = t; }
        M->lut_cell[i] = (u8)(row + col * (mask + 1u));
    }

    for (u32 i = 0; i < 512u; i++) {
        u8 row = (u8)((i >> 6) & 7u);
        u8 col = (u8)((i >> 3) & 7u);
        if (i & 4u) col ^= 7u;
        if (i & 2u) { col ^= 7u; row ^= 7u; }
        if (i & 1u) { u8 t = col; col = row ^ 7u; row = t; }
        M->lut_pixel[i] = (u8)(col + row * 8u);
    }
}

static void scd_gfx_render_line(u32 buf_idx, u32 width)
{
    u8  cfg = (u8)(S.regs[0x58 >> 1] & 0xFFu);
    u32 pm  = (S.regs[1] >> 3) & 3u;
    u32 stamp_mask = (cfg & 2u) ? 0x7FCu : 0x7FFu;

    u32 xpos = (u32)WSW_RW(M->word_ram_2m, S.gfx_trace_off + 0u) << 8;
    u32 ypos = (u32)WSW_RW(M->word_ram_2m, S.gfx_trace_off + 2u) << 8;
    u32 xstep = (u32)(s32)(s16)WSW_RW(M->word_ram_2m, S.gfx_trace_off + 4u);
    u32 ystep = (u32)(s32)(s16)WSW_RW(M->word_ram_2m, S.gfx_trace_off + 6u);
    S.gfx_trace_off = (S.gfx_trace_off + 8u) & 0x3FFF8u;

    while (width--) {
        u8 pix_out = 0;
        if (cfg & 1u) {
            xpos &= S.gfx_dot_mask;
            ypos &= S.gfx_dot_mask;
        } else {
            xpos &= 0xFFFFFFu;
            ypos &= 0xFFFFFFu;
        }

        if (!((xpos | ypos) & ~S.gfx_dot_mask)) {
            u32 map_idx = (xpos >> S.gfx_stamp_shift) | ((ypos >> S.gfx_stamp_shift) << S.gfx_map_shift);
            u16 sdata = WSW_RW(M->word_ram_2m, (S.gfx_map_off + (map_idx << 1)) & 0x3FFFEu);
            u32 sidx  = (u32)(sdata & stamp_mask) << 8;
            if (sidx) {
                u32 hrr = (sdata >> 13) & 7u;
                sidx |= (u32)M->lut_cell[hrr | ((u32)(cfg & 2u) << 2) | ((ypos >> 8) & 0xC0u) | ((xpos >> 10) & 0x30u)] << 6;
                sidx |= (u32)M->lut_pixel[hrr | ((xpos >> 8) & 0x38u) | ((ypos >> 5) & 0x1C0u)];
                u8 pair = WSW_RB(M->word_ram_2m, (sidx >> 1) & 0x3FFFFu);
                pix_out = (sidx & 1u) ? (pair & 0x0Fu) : (pair >> 4);
            }
        }

        u32 byte_idx = (buf_idx >> 1) & 0x3FFFFu;
        u8  pix_in   = WSW_RB(M->word_ram_2m, byte_idx);
        u8  merged   = (buf_idx & 1u) ? (u8)((pix_in & 0xF0u) | pix_out)
                                      : (u8)((pix_out << 4) | (pix_in & 0x0Fu));
        WSW_WB(M->word_ram_2m, byte_idx, prio_mix_byte(pm, pix_in, merged));

        if ((buf_idx & 7u) != 7u)
            buf_idx++;
        else
            buf_idx += S.gfx_buf_off;

        xpos += xstep;
        ypos += ystep;
    }
}

static void scd_gfx_start(u16 trace_base)
{
    u8 cfg = (u8)(S.regs[0x58 >> 1] & 0xFFu);
    u32 mask;
    switch ((cfg >> 1) & 3u) {
    case 0:  S.gfx_dot_mask = 0x07FFFFu; S.gfx_stamp_shift = 15; S.gfx_map_shift = 4; mask = 0x3FE00u; break;
    case 1:  S.gfx_dot_mask = 0x07FFFFu; S.gfx_stamp_shift = 16; S.gfx_map_shift = 3; mask = 0x3FF80u; break;
    case 2:  S.gfx_dot_mask = 0x7FFFFFu; S.gfx_stamp_shift = 15; S.gfx_map_shift = 8; mask = 0x20000u; break;
    default: S.gfx_dot_mask = 0x7FFFFFu; S.gfx_stamp_shift = 16; S.gfx_map_shift = 7; mask = 0x38000u; break;
    }
    S.gfx_trace_off = ((u32)trace_base << 2) & 0x3FFF8u;
    S.gfx_map_off   = ((u32)S.regs[0x5A >> 1] << 2) & mask;
    S.gfx_buf_off   = ((((u32)S.regs[0x5C >> 1] & 0x1Fu) + 1u) << 6) - 7u;
    S.gfx_buf_start = (((u32)S.regs[0x5E >> 1] << 3) & 0x7FFC0u) + ((u32)S.regs[0x60 >> 1] & 0x3Fu);

    u32 hdot = S.regs[0x62 >> 1] & 0x1FFu;
    s32 cpl = (s32)(3u * (4u + 2u * hdot + ((hdot + 3u) >> 2)));
    if (cpl < 64) cpl = 64;
    S.gfx_cyc_per_line = cpl;
    S.gfx_last_cyc = m.clock;
    S.regs[0x58 >> 1] |= 0x8000u;       /* Set GRON */

    if ((S.regs[0x64 >> 1] & 0xFFu) == 0u) {
        S.regs[0x58 >> 1] &= (u16)~0x8000u;
        s68k_trigger_irq(1u);
    }
}

static void scd_gfx_update(s32 cur_cyc)
{
    if (!(S.regs[0x58 >> 1] & 0x8000u))
        return;
    /* Stamp ASIC operates when Word-RAM is in 2M mode owned by Sub-CPU */
    if ((S.regs[1] & 0x05u) == 0x01u) {
        S.gfx_last_cyc = cur_cyc;
        return;
    }
    s32 elapsed = cur_cyc - S.gfx_last_cyc;
    if (elapsed < S.gfx_cyc_per_line)
        return;

    u32 lines = (u32)(elapsed / S.gfx_cyc_per_line);
    u32 rem   = S.regs[0x64 >> 1] & 0xFFu;
    int done  = 0;
    if (lines >= rem) {
        lines = rem;
        done = 1;
    }
    S.gfx_last_cyc += (s32)lines * S.gfx_cyc_per_line;
    S.regs[0x64 >> 1] = (u16)((S.regs[0x64 >> 1] & 0xFF00u) | ((rem - lines) & 0xFFu));

    u32 hdot = S.regs[0x62 >> 1] & 0x1FFu;
    while (lines--) {
        scd_gfx_render_line(S.gfx_buf_start, hdot);
        S.gfx_buf_start += 8u;
    }

    if (done) {
        S.regs[0x58 >> 1] &= (u16)~0x8000u;
        s68k_trigger_irq(1u);
    }
}

/* ========================================================================
 * Ricoh RF5C164 8-Channel PCM & 44.1 kHz Redbook CD-DA @ Host Audio Rate
 * ======================================================================== */

static u8 scd_pcm_read(u32 a)
{
    if (a >= 0x1000u)
        return M->pcm_ram[((u32)S.pcm_bank << 12) | (a & 0xFFFu)];
    if (a >= 0x10u && a < 0x20u) {
        u32 ch = (a - 0x10u) >> 1;
        u32 pos = (S.pcm_ch[ch].addr >> 11) & 0xFFFFu;
        return (a & 1u) ? (u8)(pos >> 8) : (u8)pos;
    }
    return 0xFFu;
}

static void scd_pcm_write(u32 a, u8 v)
{
    if (a >= 0x1000u) {
        M->pcm_ram[((u32)S.pcm_bank << 12) | (a & 0xFFFu)] = v;
        return;
    }
    struct scd_pcm_ch *c = &S.pcm_ch[S.pcm_sel & 7u];
    switch (a & 0x1FFFu) {
    case 0x00: c->env = v; break;
    case 0x01: c->pan = v; break;
    case 0x02: c->fd  = (u16)((c->fd & 0xFF00u) | v); break;
    case 0x03: c->fd  = (u16)((c->fd & 0x00FFu) | ((u16)v << 8)); break;
    case 0x04: c->ls  = (u16)((c->ls & 0xFF00u) | v); break;
    case 0x05: c->ls  = (u16)((c->ls & 0x00FFu) | ((u16)v << 8)); break;
    case 0x06:
        c->st = (u32)v << 19;
        if (!(S.pcm_on_mask & (1u << (S.pcm_sel & 7u))))
            c->addr = c->st;
        break;
    case 0x07:
        if (v & 0x40u)
            S.pcm_sel = v & 0x07u;
        else
            S.pcm_bank = v & 0x0Fu;
        S.pcm_en = (v & 0x80u) != 0;
        break;
    case 0x08:
        S.pcm_on_mask = (u8)~v;
        for (int i = 0; i < 8; i++)
            if (v & (1u << i))
                S.pcm_ch[i].addr = S.pcm_ch[i].st;
        break;
    }
}

static void scd_step_pcm_one(void)
{
    if (!S.pcm_en || !S.pcm_on_mask) {
        S.pcm_l = S.pcm_r = 0;
        return;
    }
    s32 l = 0, r = 0;
    for (int j = 0; j < 8; j++) {
        if (!(S.pcm_on_mask & (1u << j)))
            continue;
        struct scd_pcm_ch *c = &S.pcm_ch[j];
        u8 d = M->pcm_ram[(c->addr >> 11) & 0xFFFFu];
        if (d == 0xFFu) {
            c->addr = (u32)c->ls << 11;
            d = M->pcm_ram[c->ls];
            if (d == 0xFFu)
                continue;
        }
        c->addr += c->fd;
        s32 s = (d & 0x80u) ? (s32)(d & 0x7Fu) : -(s32)(d & 0x7Fu);
        l += (s * (s32)c->env * (s32)(c->pan & 0x0Fu)) >> 5;
        r += (s * (s32)c->env * (s32)(c->pan >> 4)) >> 5;
    }
    if (l > 32767) l = 32767; else if (l < -32768) l = -32768;
    if (r > 32767) r = 32767; else if (r < -32768) r = -32768;
    S.pcm_l = (s16)l;
    S.pcm_r = (s16)r;
}

static void scd_mix_audio(s16 *samples, int count, u32 rate)
{
    if (!rate || count <= 0)
        return;

    for (int i = 0; i < count; i++) {
        /* 1. Step Ricoh RF5C164 (32552 Hz -> host rate) */
        S.pcm_phase += SCD_PCM_HZ;
        while (S.pcm_phase >= rate) {
            S.pcm_phase -= rate;
            scd_step_pcm_one();
        }
        s32 add = ((s32)S.pcm_l + (s32)S.pcm_r) >> 1;

        /* 2. Step Redbook CD-DA (44100 Hz -> host rate) */
        if (S.cdda_playing && S.cd && S.cd->read_2352) {
            S.cdda_phase += 44100u;
            while (S.cdda_phase >= rate) {
                S.cdda_phase -= rate;
                if (S.cdda_fader_cur < S.cdda_fader_dst) S.cdda_fader_cur++;
                else if (S.cdda_fader_cur > S.cdda_fader_dst) S.cdda_fader_cur--;

                if (S.cdda_pos >= 588u) {
                    if ((s32)S.cdda_lba >= S.cdd_end_lba || S.cdda_lba >= S.cd->total_lba) {
                        if (S.cdd_loop) {
                            S.cdda_lba = (u32)S.cdd_lba;
                        } else {
                            S.cdda_playing = 0;
                            S.cdd_status = CDD_PAUSE;
                            S.regs[0x36 >> 1] |= 0x0100u;
                            S.cdda_l = S.cdda_r = 0;
                            break;
                        }
                    }
                    if (S.cd->read_2352(S.cdda_lba, M->cdda_sec) < 0) {
                        S.cdda_playing = 0;
                        S.cdda_l = S.cdda_r = 0;
                        break;
                    }
                    S.cdda_lba++;
                    S.cdda_pos = 0;
                }
                const u8 *sp = &M->cdda_sec[S.cdda_pos * 4u];
                s16 sl = (s16)((u16)sp[0] | ((u16)sp[1] << 8));
                s16 sr = (s16)((u16)sp[2] | ((u16)sp[3] << 8));
                s32 mul = S.cdda_fader_cur;
                S.cdda_l = (s16)(((s32)sl * mul) >> 10);
                S.cdda_r = (s16)(((s32)sr * mul) >> 10);
                S.cdda_pos++;
            }
            add += ((s32)S.cdda_l + (s32)S.cdda_r) >> 2;
        }

        s32 tot = (s32)samples[i] + add;
        if (tot > 32767) tot = 32767;
        else if (tot < -32768) tot = -32768;
        samples[i] = (s16)tot;
    }
}

/* ========================================================================
 * Sanyo LC89510 CDC & 75 Hz CDD Hardware
 * ======================================================================== */

static inline u16 cdc_ram_rw_be(u32 idx)
{
    idx &= 0x3FFEu;
    return (u16)(((u16)M->cdc_ram[idx] << 8) | M->cdc_ram[idx + 1u]);
}

static void cdc_reset(void)
{
    S.cdc_ar = 0;
    S.cdc_ifstat = 0xFFu;
    S.cdc_ifctrl = 0x00u;
    S.cdc_ctrl0 = S.cdc_ctrl1 = 0;
    S.cdc_stat0 = S.cdc_stat2 = 0;
    S.cdc_stat3 = 0x80u;
    S.cdc_head[0][0] = S.cdc_head[0][1] = S.cdc_head[0][2] = 0;
    S.cdc_head[0][3] = 0x01u;
    S.cdc_irq = 0;
    S.cdc_dma_mode = 0;
    S.cdc_dbc = S.cdc_dac = S.cdc_pt = S.cdc_wa = 0;
    S.pending &= (u8)~(1u << 5);
    s68k_update_irq();
}

static void cdc_finish_xfer(void)
{
    S.cdc_dbc = 0xFFFFu;
    S.cdc_ifstat |= (CDC_BIT_DTBSY | CDC_BIT_DTEN);
    S.cdc_ifstat &= (u8)~CDC_BIT_DTEI;
    if (S.cdc_ifctrl & CDC_BIT_DTEIEN) {
        if (!S.cdc_irq)
            s68k_trigger_irq(5u);
        S.cdc_irq |= CDC_BIT_DTEI;
    }
    S.regs[0x04 >> 1] = (u16)((S.regs[0x04 >> 1] & 0x07FFu) | 0x8000u); /* EDT=1, DSR=0 */
    S.cdc_dma_mode = 0;
}

static void cdc_dma_transfer_bytes(u32 nbytes)
{
    u32 words = nbytes >> 1;
    u16 src = S.cdc_dac & 0x3FFEu;

    if (S.cdc_dma_mode == 4u) {
        /* PCM Wave RAM DMA (byte-granular into current 64 KB Wave RAM) */
        u32 dst = ((u32)S.regs[0x0A >> 1] << 2) & 0xFFFFu;
        S.regs[0x0A >> 1] = (u16)(S.regs[0x0A >> 1] + (words >> 1));
        S.cdc_dac = (u16)(S.cdc_dac + (words << 1));
        for (u32 i = 0; i < words * 2u; i++)
            M->pcm_ram[(dst + i) & 0xFFFFu] = M->cdc_ram[(src + i) & 0x3FFFu];
        return;
    }

    u8 *dst_ram = M->prg_ram;
    u32 dst_mask = 0x7FFFEu;
    if (S.cdc_dma_mode == 7u) {
        dst_ram = M->word_ram_2m;
        dst_mask = 0x3FFFEu;
    } else if (S.cdc_dma_mode == 8u) {
        dst_ram = M->word_ram_1m[0];
        dst_mask = 0x1FFFEu;
    } else if (S.cdc_dma_mode == 9u) {
        dst_ram = M->word_ram_1m[1];
        dst_mask = 0x1FFFEu;
    }

    u32 dst = ((u32)S.regs[0x0A >> 1] << 3) & dst_mask;
    S.regs[0x0A >> 1] = (u16)(S.regs[0x0A >> 1] + (words >> 2));
    S.cdc_dac = (u16)(S.cdc_dac + (words << 1));
    while (words--) {
        WSW_WW(dst_ram, dst, cdc_ram_rw_be(src));
        src = (src + 2u) & 0x3FFEu;
        dst = (dst + 2u) & dst_mask;
    }
}

static void cdc_dma_init(void)
{
    if (S.cdc_ifstat & CDC_BIT_DTEN)
        return;
    S.cdc_dma_mode = 0;
    u8 dd = (u8)((S.regs[0x04 >> 1] >> 8) & 7u);
    switch (dd) {
    case 2: /* Main-CPU Host Read */
    case 3: /* Sub-CPU Host Read */
        S.regs[0x08 >> 1] = cdc_ram_rw_be(S.cdc_dac);
        S.regs[0x04 >> 1] |= 0x4000u;   /* Set DSR */
        S.cdc_dac = (u16)(S.cdc_dac + 2u);
        S.cdc_dbc = (u16)(S.cdc_dbc - 2u);
        if ((s16)S.cdc_dbc < 0) {
            cdc_finish_xfer();
            S.regs[0x04 >> 1] |= 0x4000u; /* Keep DSR on last word until read! */
        }
        break;
    case 4: S.cdc_dma_mode = 4u; break;
    case 5: S.cdc_dma_mode = 5u; break;
    case 7:
        if (S.regs[1] & 4u)
            S.cdc_dma_mode = (S.regs[1] & 1u) ? 8u : 9u;
        else
            S.cdc_dma_mode = 7u;
        break;
    }
}

static void cdc_dma_update(s32 cur_cyc)
{
    if (!S.cdc_dma_mode)
        return;
    s32 avail = (cur_cyc - S.cdc_dma_cyc) >> 2; /* 4 Sub-CPU cycles per byte */
    avail &= ~7;
    if (avail <= 0)
        return;
    u32 rem = (u32)S.cdc_dbc + 1u;
    if (rem <= (u32)avail) {
        cdc_dma_transfer_bytes(rem);
        S.cdc_dma_cyc += (s32)(rem << 2);
        cdc_finish_xfer();
    } else {
        cdc_dma_transfer_bytes((u32)avail);
        S.cdc_dbc = (u16)(S.cdc_dbc - avail);
        S.cdc_dma_cyc += avail << 2;
    }
}

static u16 cdc_host_read(u8 expect_dd)
{
    u16 data = S.regs[0x08 >> 1];
    u8 hi = (u8)(S.regs[0x04 >> 1] >> 8);
    if ((hi & 0x47u) == (0x40u | expect_dd)) {
        if (hi & 0x80u) {
            S.regs[0x04 >> 1] &= (u16)~0x4000u; /* Clear DSR after final word */
        } else {
            S.regs[0x08 >> 1] = cdc_ram_rw_be(S.cdc_dac);
            S.cdc_dac = (u16)(S.cdc_dac + 2u);
            S.cdc_dbc = (u16)(S.cdc_dbc - 2u);
            if ((s16)S.cdc_dbc < 0) {
                cdc_finish_xfer();
                S.regs[0x04 >> 1] |= 0x4000u;
            }
        }
    }
    return data;
}

static u8 cdc_reg_read(void)
{
    u8 r = S.cdc_ar & 0x0Fu, v = 0xFFu;
    switch (r) {
    case 0x01:
        if (m.clock > S.cdc_dec_end) {
            S.cdc_ifstat |= CDC_BIT_DECI;
            S.cdc_irq &= (u8)~CDC_BIT_DECI;
        }
        v = S.cdc_ifstat;
        break;
    case 0x02: v = (u8)S.cdc_dbc; break;
    case 0x03: v = (u8)(S.cdc_dbc >> 8); break;
    case 0x04: case 0x05: case 0x06: case 0x07:
        v = S.cdc_head[S.cdc_ctrl1 & CDC_BIT_SHDREN][r - 4u];
        break;
    case 0x08: v = (u8)S.cdc_pt; break;
    case 0x09: v = (u8)(S.cdc_pt >> 8); break;
    case 0x0A: v = (u8)S.cdc_wa; break;
    case 0x0B: v = (u8)(S.cdc_wa >> 8); break;
    case 0x0C: v = S.cdc_stat0; break;
    case 0x0D: v = 0x00u; break;
    case 0x0E: v = S.cdc_stat2; break;
    case 0x0F:
        v = S.cdc_stat3;
        S.cdc_stat3 = 0x80u;
        S.cdc_ifstat |= CDC_BIT_DECI;
        S.cdc_irq &= (u8)~CDC_BIT_DECI;
        break;
    }
    if (S.cdc_ar)
        S.cdc_ar = (S.cdc_ar + 1u) & 0x0Fu;
    S.regs[0x04 >> 1] = (u16)((S.regs[0x04 >> 1] & 0xFF00u) | S.cdc_ar);
    return v;
}

static void cdc_reg_write(u8 v)
{
    u8 r = S.cdc_ar & 0x0Fu;
    switch (r) {
    case 0x01: {
        u8 prev = S.cdc_irq;
        if (m.clock > S.cdc_dec_end) {
            S.cdc_ifstat |= CDC_BIT_DECI;
            prev &= (u8)~CDC_BIT_DECI;
        }
        S.cdc_irq = (u8)(~S.cdc_ifstat & v & (CDC_BIT_DTEIEN | CDC_BIT_DECIEN));
        if (S.cdc_irq && !prev)
            s68k_trigger_irq(5u);
        if (!(v & CDC_BIT_DOUTEN)) {
            S.cdc_ifstat |= (CDC_BIT_DTBSY | CDC_BIT_DTEN);
            S.cdc_dma_mode = 0;
        }
        S.cdc_ifctrl = v;
        break;
    }
    case 0x02: S.cdc_dbc = (u16)((S.cdc_dbc & 0xFF00u) | v); break;
    case 0x03: S.cdc_dbc = (u16)((S.cdc_dbc & 0x00FFu) | (((u16)v & 0x0Fu) << 8)); break;
    case 0x04: S.cdc_dac = (u16)((S.cdc_dac & 0xFF00u) | v); break;
    case 0x05: S.cdc_dac = (u16)((S.cdc_dac & 0x00FFu) | ((u16)v << 8)); break;
    case 0x06:
        if (S.cdc_ifctrl & CDC_BIT_DOUTEN) {
            S.cdc_ifstat &= (u8)~(CDC_BIT_DTBSY | CDC_BIT_DTEN);
            S.regs[0x04 >> 1] &= 0x07FFu;
            S.cdc_dma_cyc = m.clock;
            cdc_dma_init();
        }
        break;
    case 0x07:
        S.cdc_ifstat |= CDC_BIT_DTEI;
        S.cdc_irq &= (u8)~CDC_BIT_DTEI;
        break;
    case 0x08: S.cdc_wa = (u16)((S.cdc_wa & 0xFF00u) | v); break;
    case 0x09: S.cdc_wa = (u16)((S.cdc_wa & 0x00FFu) | ((u16)v << 8)); break;
    case 0x0A:
        S.cdc_stat0 = v & CDC_BIT_DECEN;
        if (!(v & CDC_BIT_DECEN)) {
            S.cdc_ifstat |= CDC_BIT_DECI;
            S.cdc_irq &= (u8)~CDC_BIT_DECI;
        }
        S.cdc_ctrl0 = v;
        break;
    case 0x0B:
        S.cdc_ctrl1 = v;
        S.cdc_stat2 = v & (CDC_BIT_MODRQ | CDC_BIT_FORMRQ);
        break;
    case 0x0C: S.cdc_pt = (u16)((S.cdc_pt & 0xFF00u) | v); break;
    case 0x0D: S.cdc_pt = (u16)((S.cdc_pt & 0x00FFu) | ((u16)v << 8)); break;
    case 0x0F: cdc_reset(); return;
    }
    if (S.cdc_ar)
        S.cdc_ar = (S.cdc_ar + 1u) & 0x0Fu;
    S.regs[0x04 >> 1] = (u16)((S.regs[0x04 >> 1] & 0xFF00u) | S.cdc_ar);
}

static void cdc_decode_sector(u32 lba, int has_data)
{
    if (!(S.cdc_ctrl0 & CDC_BIT_DECEN))
        return;

    u32 msf = lba + 150u;
    u8 h0 = has_data ? to_bcd8(msf / 4500u) : 0;
    u8 h1 = has_data ? to_bcd8((msf / 75u) % 60u) : 0;
    u8 h2 = has_data ? to_bcd8(msf % 75u) : 0;
    u8 h3 = has_data ? 0x01u : 0x00u;

    S.cdc_head[0][0] = h0; S.cdc_head[0][1] = h1;
    S.cdc_head[0][2] = h2; S.cdc_head[0][3] = h3;
    S.cdc_stat3 = 0x00u;
    S.cdc_ifstat &= (u8)~CDC_BIT_DECI;
    S.cdc_dec_end = m.clock + 110000;

    if (S.cdc_ifctrl & CDC_BIT_DECIEN) {
        if (!(S.cdc_irq & CDC_BIT_DTEI))
            s68k_trigger_irq(5u);
        S.cdc_irq |= CDC_BIT_DECI;
    }

    if ((S.cdc_ctrl0 & CDC_BIT_WRRQ) && has_data && S.cd && S.cd->read_2048) {
        S.cdc_pt = (u16)(S.cdc_pt + 2352u);
        S.cdc_wa = (u16)(S.cdc_wa + 2352u);
        u32 off = S.cdc_pt & 0x3FFFu;
        M->cdc_ram[off + 0u] = h0;
        M->cdc_ram[off + 1u] = h1;
        M->cdc_ram[off + 2u] = h2;
        M->cdc_ram[off + 3u] = h3;
        (void)S.cd->read_2048(lba, M->cdc_ram + off + 4u);
        if (off + 2052u > 0x4000u) {
            u32 over = (off + 2052u) - 0x4000u;
            for (u32 i = 0; i < over; i++)
                M->cdc_ram[i] = M->cdc_ram[0x4000u + i];
        }
    }
}

static u8 cdd_find_track(s32 lba)
{
    if (!S.cd || lba < 0)
        return 1;
    u8 trk = 1;
    for (u8 t = 1; t <= S.cd->last_track; t++) {
        if ((u32)lba >= S.cd->tracks[t].lba)
            trk = t;
    }
    return trk;
}

static void cdd_update_checksum(void)
{
    u32 sum = ((S.regs[0x38 >> 1] >> 8) & 0xFu) + (S.regs[0x38 >> 1] & 0xFu) +
              ((S.regs[0x3A >> 1] >> 8) & 0xFu) + (S.regs[0x3A >> 1] & 0xFu) +
              ((S.regs[0x3C >> 1] >> 8) & 0xFu) + (S.regs[0x3C >> 1] & 0xFu) +
              ((S.regs[0x3E >> 1] >> 8) & 0xFu) + (S.regs[0x3E >> 1] & 0xFu) +
              ((S.regs[0x40 >> 1] >> 8) & 0xFu);
    S.regs[0x40 >> 1] = (u16)((S.regs[0x40 >> 1] & 0xFF00u) | (~sum & 0x0Fu));
}

static void cdd_process_cmd(void)
{
    u8 cmd = (u8)((S.regs[0x42 >> 1] >> 8) & 0x0Fu);
    u8 sub = (u8)(S.regs[0x44 >> 1] & 0x0Fu);

    switch (cmd) {
    case 0x00: /* Get Status */
        if (S.cdd_latency <= 1) {
            S.regs[0x38 >> 1] = (u16)((S.regs[0x38 >> 1] & 0x00FFu) | ((u16)S.cdd_status << 8));
            u8 rs1 = (u8)(S.regs[0x38 >> 1] & 0x0Fu);
            if (S.cdd_status != CDD_STOP && S.cdd_status <= CDD_PAUSE) {
                if (rs1 == 0x0Fu || rs1 == 0x00u) {
                    u32 msf = (u32)(S.cdd_lba >= 0 ? S.cdd_lba + 150 : 150);
                    S.regs[0x38 >> 1] = (u16)((u16)S.cdd_status << 8);
                    S.regs[0x3A >> 1] = to_bcd16(msf / 4500u);
                    S.regs[0x3C >> 1] = to_bcd16((msf / 75u) % 60u);
                    S.regs[0x3E >> 1] = to_bcd16(msf % 75u);
                    u8 is_data = (S.cd && !S.cd->tracks[S.cdd_track_idx].is_audio) ? 0x04u : 0x00u;
                    S.regs[0x40 >> 1] = (u16)((u16)is_data << 8);
                } else if (rs1 == 0x01u && S.cd) {
                    s32 rel = S.cdd_lba - (s32)S.cd->tracks[S.cdd_track_idx].lba;
                    if (rel < 0) rel = -rel;
                    S.regs[0x3A >> 1] = to_bcd16((u32)rel / 4500u);
                    S.regs[0x3C >> 1] = to_bcd16(((u32)rel / 75u) % 60u);
                    S.regs[0x3E >> 1] = to_bcd16((u32)rel % 75u);
                } else if (rs1 == 0x02u) {
                    S.regs[0x3A >> 1] = to_bcd16(S.cdd_track_idx);
                }
            }
        }
        break;

    case 0x01: /* Stop */
        S.cdd_status = S.cd ? CDD_TOC : CDD_NOCD;
        S.cdda_playing = 0;
        S.regs[0x36 >> 1] |= 0x0100u;
        S.regs[0x38 >> 1] = (CDD_STOP << 8) | 0x0Fu;
        S.regs[0x3A >> 1] = S.regs[0x3C >> 1] = S.regs[0x3E >> 1] = 0;
        S.regs[0x40 >> 1] = 0;
        S.cdd_lba = 0;
        S.cdd_track_idx = 1;
        cdd_update_checksum();
        return;

    case 0x02: /* Report TOC */
        switch (sub) {
        case 0x00: {
            u32 msf = (u32)(S.cdd_lba + 150);
            S.regs[0x38 >> 1] = (u16)((u16)S.cdd_status << 8);
            S.regs[0x3A >> 1] = to_bcd16(msf / 4500u);
            S.regs[0x3C >> 1] = to_bcd16((msf / 75u) % 60u);
            S.regs[0x3E >> 1] = to_bcd16(msf % 75u);
            u8 is_data = (S.cd && !S.cd->tracks[S.cdd_track_idx].is_audio) ? 0x04u : 0x00u;
            S.regs[0x40 >> 1] = (u16)((u16)is_data << 8);
            break;
        }
        case 0x01: {
            s32 rel = S.cd ? (S.cdd_lba - (s32)S.cd->tracks[S.cdd_track_idx].lba) : 0;
            if (rel < 0) rel = 0;
            S.regs[0x38 >> 1] = (u16)(((u16)S.cdd_status << 8) | 0x01u);
            S.regs[0x3A >> 1] = to_bcd16((u32)rel / 4500u);
            S.regs[0x3C >> 1] = to_bcd16(((u32)rel / 75u) % 60u);
            S.regs[0x3E >> 1] = to_bcd16((u32)rel % 75u);
            u8 is_data = (S.cd && !S.cd->tracks[S.cdd_track_idx].is_audio) ? 0x04u : 0x00u;
            S.regs[0x40 >> 1] = (u16)((u16)is_data << 8);
            break;
        }
        case 0x02:
            S.regs[0x38 >> 1] = (u16)(((u16)S.cdd_status << 8) | 0x02u);
            S.regs[0x3A >> 1] = to_bcd16(S.cdd_track_idx);
            S.regs[0x3C >> 1] = S.regs[0x3E >> 1] = S.regs[0x40 >> 1] = 0;
            break;
        case 0x03: {
            u32 tot = (S.cd ? S.cd->total_lba : 0u) + 150u;
            S.regs[0x38 >> 1] = (u16)(((u16)S.cdd_status << 8) | 0x03u);
            S.regs[0x3A >> 1] = to_bcd16(tot / 4500u);
            S.regs[0x3C >> 1] = to_bcd16((tot / 75u) % 60u);
            S.regs[0x3E >> 1] = to_bcd16(tot % 75u);
            S.regs[0x40 >> 1] = 0;
            break;
        }
        case 0x04:
            S.regs[0x38 >> 1] = (u16)(((u16)S.cdd_status << 8) | 0x04u);
            S.regs[0x3A >> 1] = 0x0001u;
            S.regs[0x3C >> 1] = to_bcd16(S.cd ? S.cd->last_track : 1u);
            S.regs[0x3E >> 1] = S.regs[0x40 >> 1] = 0;
            break;
        case 0x05: {
            u32 trk = (((S.regs[0x46 >> 1] >> 8) & 0xFu) * 10u) + (S.regs[0x46 >> 1] & 0xFu);
            if (S.cd && trk >= 1u && trk <= S.cd->last_track) {
                u32 lba = S.cd->tracks[trk].lba + 150u;
                S.regs[0x38 >> 1] = (u16)(((u16)S.cdd_status << 8) | 0x05u);
                S.regs[0x3A >> 1] = to_bcd16(lba / 4500u);
                S.regs[0x3C >> 1] = to_bcd16((lba / 75u) % 60u);
                u16 ff = to_bcd16(lba % 75u);
                if (!S.cd->tracks[trk].is_audio)
                    ff |= 0x0800u;
                S.regs[0x3E >> 1] = ff;
                S.regs[0x40 >> 1] = (u16)((trk % 10u) << 8);
            } else {
                S.regs[0x38 >> 1] = (u16)(((u16)S.cdd_status << 8) | 0x0Fu);
                S.regs[0x3A >> 1] = S.regs[0x3C >> 1] = S.regs[0x3E >> 1] = S.regs[0x40 >> 1] = 0;
            }
            break;
        }
        default:
            S.regs[0x38 >> 1] = (u16)(((u16)S.cdd_status << 8) | 0x06u);
            S.regs[0x3A >> 1] = S.regs[0x3C >> 1] = S.regs[0x3E >> 1] = S.regs[0x40 >> 1] = 0;
            break;
        }
        break;

    case 0x03: /* Play */
    case 0x04: /* Seek */
        S.regs[0x38 >> 1] = (CDD_SEEK << 8) | 0x0Fu;
        S.regs[0x3A >> 1] = S.regs[0x3C >> 1] = S.regs[0x3E >> 1] = 0;
        S.regs[0x40 >> 1] = 0;
        S.cdd_pending = (cmd == 0x03u) ? CDD_PLAY : CDD_PAUSE;
        cdd_update_checksum();
        return;

    case 0x06: /* Pause */
        S.cdda_playing = 0;
        S.regs[0x36 >> 1] |= 0x0100u;
        S.cdd_status = CDD_PAUSE;
        S.regs[0x38 >> 1] = (u16)((S.regs[0x38 >> 1] & 0x00FFu) | (CDD_PAUSE << 8));
        break;

    case 0x07: /* Resume */
        S.cdd_status = CDD_PLAY;
        S.regs[0x38 >> 1] = (u16)((S.regs[0x38 >> 1] & 0x00FFu) | (CDD_PLAY << 8));
        break;

    case 0x0A: /* Track Jump */
        S.cdda_playing = 0;
        S.regs[0x36 >> 1] |= 0x0100u;
        S.cdd_status = CDD_PAUSE;
        S.regs[0x38 >> 1] = (u16)((S.regs[0x38 >> 1] & 0x00FFu) | (CDD_PAUSE << 8));
        break;

    case 0x0C: /* Close Tray */
        S.cdda_playing = 0;
        S.cdd_status = S.cd ? CDD_TOC : CDD_NOCD;
        S.regs[0x38 >> 1] = (CDD_STOP << 8) | 0x0Fu;
        break;

    case 0x0D: /* Open Tray */
        S.cdda_playing = 0;
        S.cdd_status = CDD_OPEN;
        S.regs[0x38 >> 1] = (CDD_OPEN << 8) | 0x0Fu;
        break;
    }
    cdd_update_checksum();
}

static void cdd_tick_75hz(void)
{
    /* Clean-room _CDBIOS streaming sector pump */
    if (!S.ext_bios && S.hle_reading && !S.hle_sec_ready && S.cd && S.cd->read_2048) {
        if (S.hle_rem_sec > 0 && S.hle_cur_lba < S.cd->total_lba) {
            if (S.cd->read_2048(S.hle_cur_lba, M->hle_sec) == 0) {
                u32 msf = S.hle_cur_lba + 150u;
                S.hle_head[0] = to_bcd8(msf / 4500u);
                S.hle_head[1] = to_bcd8((msf / 75u) % 60u);
                S.hle_head[2] = to_bcd8(msf % 75u);
                S.hle_head[3] = 0x01u;
                /* Also populate CDC RAM buffer so direct CDC DMA / host read works! */
                M->cdc_ram[0] = S.hle_head[0];
                M->cdc_ram[1] = S.hle_head[1];
                M->cdc_ram[2] = S.hle_head[2];
                M->cdc_ram[3] = S.hle_head[3];
                for (u32 i = 0; i < 2048u; i++)
                    M->cdc_ram[4u + i] = M->hle_sec[i];
                S.cdc_pt = 0;
                S.cdc_wa = 2352u;
                S.hle_sec_ready = 1;
                S.hle_cur_lba++;
                S.hle_rem_sec--;
                if (!S.hle_rem_sec)
                    S.hle_reading = 0;
            }
        } else {
            S.hle_reading = 0;
        }
    }

    if (S.cdd_latency > 0) {
        S.cdd_latency--;
        cdc_decode_sector(0, 0);
    } else if (S.cdd_status == CDD_PLAY && S.cd) {
        if (S.cdd_lba >= (s32)S.cd->total_lba) {
            S.cdd_status = CDD_END;
            S.cdda_playing = 0;
            return;
        }
        u8 trk = cdd_find_track(S.cdd_lba);
        S.cdd_track_idx = trk;
        if (!S.cd->tracks[trk].is_audio) {
            S.cdda_playing = 0;
            S.regs[0x36 >> 1] |= 0x0100u;
            cdc_decode_sector((u32)S.cdd_lba, 1);
            S.cdd_lba++;
        } else {
            if (!S.cdda_playing) {
                S.cdda_lba = (u32)S.cdd_lba;
                S.cdd_end_lba = (trk < S.cd->last_track) ? (s32)S.cd->tracks[trk + 1u].lba : (s32)S.cd->total_lba;
                S.cdd_loop = 0;
                S.cdda_pos = 588u;
                S.cdda_playing = 1;
            }
            S.regs[0x36 >> 1] &= (u16)~0x0100u;
            cdc_decode_sector(0, 0);
            S.cdd_lba = (s32)S.cdda_lba;
        }
    } else {
        cdc_decode_sector(0, 0);
    }

    if (S.cdd_pending) {
        u32 mm = (((S.regs[0x44 >> 1] >> 8) & 0xFu) * 10u) + (S.regs[0x44 >> 1] & 0xFu);
        u32 ss = (((S.regs[0x46 >> 1] >> 8) & 0xFu) * 10u) + (S.regs[0x46 >> 1] & 0xFu);
        u32 ff = (((S.regs[0x48 >> 1] >> 8) & 0xFu) * 10u) + (S.regs[0x48 >> 1] & 0xFu);
        s32 lba = (s32)((mm * 60u + ss) * 75u + ff) - 150;
        if (lba < 0) lba = 0;
        if (S.cd && (u32)lba > S.cd->total_lba)
            lba = (s32)S.cd->total_lba;
        S.cdd_lba = lba;
        S.cdd_track_idx = cdd_find_track(lba);
        S.cdd_latency = 2;
        S.cdda_playing = 0;
        S.regs[0x36 >> 1] |= 0x0100u;
        S.cdd_status = S.cdd_pending;
        S.cdd_pending = 0;
    }

    /* Trigger Sub-CPU Level 4 CDD interrupt if HOCK ($FF8037 bit 2) is set */
    if (S.regs[0x36 >> 1] & 0x0004u)
        s68k_trigger_irq(4u);
}

/* ========================================================================
 * Clean-Room Sub-CPU _CDBIOS ($5F22) & _BURAM ($5F16) HLE Dispatcher
 * ======================================================================== */

static void scd_hle_cdbios(u16 fn)
{
    u32 a0 = m.r[8] & 0xFFFFFFu;
    u32 a1 = m.r[9] & 0xFFFFFFu;

    switch (fn) {
    case 0x0002: /* MSCSTOP */
        S.cdda_playing = 0;
        S.hle_reading = 0;
        S.cdd_status = CDD_STOP;
        S.regs[0x36 >> 1] |= 0x0100u;
        m.c = 0;
        break;

    case 0x0003: /* MSCPAUSEON */
        S.cdda_playing = 0;
        S.cdd_status = CDD_PAUSE;
        S.regs[0x36 >> 1] |= 0x0100u;
        m.c = 0;
        break;

    case 0x0004: /* MSCPAUSEOFF */
        if (S.cd && S.cd->tracks[S.cdd_track_idx].is_audio) {
            S.cdda_playing = 1;
            S.cdd_status = CDD_PLAY;
            S.regs[0x36 >> 1] &= (u16)~0x0100u;
        }
        m.c = 0;
        break;

    case 0x0011: /* MSCPLAY  (track -> end of disc) */
    case 0x0012: /* MSCPLAY1 (single track once) */
    case 0x0013: /* MSCPLAYR (single track repeat!) */ {
        u16 trk = (u16)rw(a0);
        if (S.cd && trk >= 1u && trk <= S.cd->last_track) {
            S.hle_reading = 0;
            S.cdd_track_idx = (u8)trk;
            S.cdd_lba = (s32)S.cd->tracks[trk].lba;
            S.cdda_lba = S.cd->tracks[trk].lba;
            S.cdd_end_lba = (fn == 0x0011u)
                ? (s32)S.cd->total_lba
                : ((trk < S.cd->last_track) ? (s32)S.cd->tracks[trk + 1u].lba : (s32)S.cd->total_lba);
            S.cdd_loop = (fn == 0x0013u) ? 1u : 0u;
            S.cdda_pos = 588u;
            S.cdda_playing = S.cd->tracks[trk].is_audio ? 1u : 0u;
            S.cdd_status = CDD_PLAY;
            S.regs[0x36 >> 1] &= (u16)~0x0100u;
        }
        m.c = 0;
        break;
    }

    case 0x0017: /* ROMREAD (continuous from *(u32 *)A0) */
        S.cdda_playing = 0;
        S.hle_cur_lba = rl(a0);
        S.hle_rem_sec = S.cd ? S.cd->total_lba : 0u;
        S.hle_sec_ready = 0;
        S.hle_reading = 1;
        m.c = 0;
        break;

    case 0x0018: /* ROMSEEK */
        S.cdda_playing = 0;
        S.cdd_lba = (s32)rl(a0);
        S.cdd_status = CDD_PAUSE;
        m.c = 0;
        break;

    case 0x0020: /* ROMREADN (start LBA at A0, count at A0+4) */
        S.cdda_playing = 0;
        S.hle_cur_lba = rl(a0);
        S.hle_rem_sec = rl(a0 + 4u);
        S.hle_sec_ready = 0;
        S.hle_reading = (S.hle_rem_sec > 0);
        m.c = 0;
        break;

    case 0x0021: /* ROMREADE (start LBA at A0, end LBA at A0+4) */ {
        u32 st = rl(a0), en = rl(a0 + 4u);
        S.cdda_playing = 0;
        S.hle_cur_lba = st;
        S.hle_rem_sec = (en >= st) ? (en - st + 1u) : 1u;
        S.hle_sec_ready = 0;
        S.hle_reading = 1;
        m.c = 0;
        break;
    }

    case 0x0080: /* CDBCHK (C=0 done, C=1 busy) */
        m.c = 0;
        break;

    case 0x0081: /* CDBSTAT -> A0 points to status table */
        m.r[8] = 0x00005E00u;
        WSW_WW(M->prg_ram, 0x5E00u, S.cdda_playing ? 0x0100u : 0x0000u);
        WSW_WW(M->prg_ram, 0x5E02u, S.cdd_track_idx);
        m.c = 0;
        break;

    case 0x0083: /* CDBTOCREAD (D1.w = track number -> D0 = MM:SS:FF:type, D1 = track type) */ {
        u16 trk = (u16)m.r[1];
        if (S.cd && trk >= 1u && trk <= S.cd->last_track) {
            u32 msf = S.cd->tracks[trk].lba + 150u;
            u8 tbyte = S.cd->tracks[trk].is_audio ? 0x00u : 0xFFu;
            m.r[0] = ((u32)to_bcd8(msf / 4500u) << 24) |
                     ((u32)to_bcd8((msf / 75u) % 60u) << 16) |
                     ((u32)to_bcd8(msf % 75u) << 8) | trk;
            m.r[1] = (m.r[1] & 0xFFFFFF00u) | tbyte;
            m.c = 0;
        } else {
            m.c = 0x100u;
        }
        break;
    }

    case 0x0085: /* FDRSET (D1.w: bit 15 = master, else target fader 0..0x400) */
        S.cdda_fader_dst = (u16)(m.r[1] & 0x7FFu);
        if (S.cdda_fader_dst > 0x400u) S.cdda_fader_dst = 0x400u;
        S.cdda_fader_cur = S.cdda_fader_dst;
        m.c = 0;
        break;

    case 0x0086: /* FDRCHG */
        S.cdda_fader_dst = (u16)((m.r[1] >> 16) & 0x7FFu);
        if (S.cdda_fader_dst > 0x400u) S.cdda_fader_dst = 0x400u;
        m.c = 0;
        break;

    case 0x0087: /* CDCSTART */
        m.c = 0;
        break;

    case 0x0089: /* CDCSTOP */
        S.hle_reading = 0;
        S.hle_sec_ready = 0;
        m.c = 0;
        break;

    case 0x008A: /* CDCSTAT (C=0 if sector ready, C=1 if not ready) */
        m.c = S.hle_sec_ready ? 0u : 0x100u;
        m.z = S.hle_sec_ready ? 1u : 0u;
        break;

    case 0x008B: /* CDCREAD (prepares transfer; returns header in D0, C=0 if ready) */
        if (!S.hle_sec_ready) {
            m.c = 0x100u;
            break;
        }
        m.r[0] = ((u32)S.hle_head[0] << 24) | ((u32)S.hle_head[1] << 16) |
                 ((u32)S.hle_head[2] << 8)  | S.hle_head[3];
        S.cdc_dac = 4u;
        S.cdc_dbc = 2047u;
        S.cdc_ifctrl |= CDC_BIT_DOUTEN;
        S.cdc_ifstat &= (u8)~(CDC_BIT_DTBSY | CDC_BIT_DTEN);
        S.regs[0x04 >> 1] &= 0x07FFu;
        S.cdc_dma_cyc = m.clock;
        cdc_dma_init();
        m.c = 0;
        break;

    case 0x008C: /* CDCTRN (A0 = 2048B dst, A1 = 4B header dst) */
        if (!S.hle_sec_ready) {
            m.c = 0x100u;
            break;
        }
        for (u32 i = 0; i < 2048u; i += 2u)
            ww(a0 + i, ((u32)M->hle_sec[i] << 8) | M->hle_sec[i + 1u]);
        for (u32 i = 0; i < 4u; i++)
            wb(a1 + i, S.hle_head[i]);
        m.r[8] = a0 + 2048u;
        m.r[9] = a1 + 4u;
        S.regs[0x04 >> 1] = (u16)((S.regs[0x04 >> 1] & 0x07FFu) | 0x8000u);
        m.c = 0;
        break;

    case 0x008D: /* CDCACK */
        S.hle_sec_ready = 0;
        m.c = 0;
        break;

    default:
        m.c = 0;
        break;
    }
}

static void scd_hle_buram(u16 fn)
{
    /* Minimal _BURAM ($5F16) handler: BRAMINIT/BRAMSTAT/BRAMSERCH/BRAMREAD/BRAMWRITE */
    switch (fn) {
    case 0x0000: /* BRAMINIT */
    case 0x0001: /* BRAMSTAT -> D0 = free blocks, D1 = dir free */
        m.r[0] = 0x7Fu;
        m.r[1] = 0x20u;
        m.c = 0;
        break;
    default:
        m.c = 0;
        break;
    }
}

/* ========================================================================
 * Sub-68000 Bus I/O ($000000 WP, $080000 Dot-RAM, $FE0000 BRAM, $FF0000 GA/PCM)
 * ======================================================================== */

static u16 scd_font_expand(u32 reg_off)
{
    u8 bits = (u8)((S.regs[0x4E >> 1] >> (((reg_off & 6u) ^ 6u) << 1)) << 2);
    u8 code = (u8)(S.regs[0x4C >> 1] & 0xFFu);
    u16 data = (code >> (bits & 4u)) & 0x0Fu;
    bits >>= 1;
    data |= (u16)(((code >> (bits & 4u)) << 4) & 0xF0u);
    bits >>= 1;
    data |= (u16)(((code >> (bits & 4u)) << 8) & 0xF00u);
    bits >>= 1;
    data |= (u16)(((code >> (bits & 4u)) << 12) & 0xF000u);
    return data;
}

static void scd_set_sub_memmode(u8 data)
{
    u8 cur = (u8)(S.regs[1] & 0xFFu);
    u8 pm_bits = data & 0x18u;
    if ((data ^ cur) & 0x05u) {
        if (data & 0x04u) {
            /* Switching to or swapping in 1M/1M mode */
            if (!(cur & 0x04u))
                scd_word_ram_switch(1);
            if (data & 0x01u)
                S.dmna_latch = 0;
            S.regs[1] = (u16)((S.regs[1] & 0xFFC0u) | (data & 0x1Du)); /* DMNA cleared */
        } else {
            /* 2M mode */
            if (cur & 0x04u) {
                scd_word_ram_switch(0);
                data |= (u8)(~S.dmna_latch & 1u);
                if (!(data & 1u)) {
                    data |= 0x02u; /* DMNA set */
                    S.regs[1] = (u16)((S.regs[1] & 0xFFC0u) | (data & 0x1Fu));
                    s68k_rebuild_map();
                    md_remap();
                    return;
                }
            }
            if (data & 0x01u) {
                /* Sub-CPU sets RET=1 -> returns 2M Word-RAM to Main-CPU! */
                scd_gfx_update(m.clock);
                S.dmna_latch = 0;
                S.regs[1] = (u16)((S.regs[1] & 0xFFC0u) | (data & 0x1Du));
            } else {
                S.regs[1] = (u16)((S.regs[1] & 0xFFE3u) | pm_bits);
            }
        }
        s68k_rebuild_map();
        md_remap();
        return;
    }
    S.regs[1] = (u16)((S.regs[1] & 0xFFE3u) | pm_bits);
}

static u32 io_read(u32 a, int size)
{
    u32 slot = (a >> 16) & 0x0Fu;

    /* 1. PRG-RAM (when wmap==0 due to WP, reads still hit rmap, so only unmapped if strange) */
    if (slot < 8u) {
        u32 off = a & 0x7FFFFu;
        return (size == 1) ? WSW_RB(M->prg_ram, off) : WSW_RW(M->prg_ram, off);
    }

    /* 2. $080000..$0BFFFF: 1M Dot-RAM view (1 nibble per byte / 2 nibbles per word) */
    if (slot >= 8u && slot < 12u) {
        if (S.regs[1] & 0x04u) {
            int sub_bank = (S.regs[1] & 1u) ? 0 : 1;
            u8 b = WSW_RB(M->word_ram_1m[sub_bank], (a >> 1) & 0x1FFFFu);
            if (size == 1)
                return (a & 1u) ? (b & 0x0Fu) : (b >> 4);
            return ((u32)(b & 0x0Fu) | (((u32)b << 4) & 0x0F00u));
        }
        return (size == 1) ? 0xFFu : 0xFFFFu;
    }

    /* 3. $FE0000..$FEFFFF: 8 KB Backup RAM (odd bytes) */
    if (slot == 14u) {
        u8 b = M->bram[(a >> 1) & 0x1FFFu];
        if (size == 1)
            return (a & 1u) ? b : 0xFFu;
        return 0xFF00u | b;
    }

    /* 4. $FF0000..$FFFFFF: Ricoh RF5C164 PCM ($FF0000..$FF7FFF) & Gate Array ($FF8000..$FFFFFF) */
    if (slot == 15u) {
        if (!(a & 0x8000u)) {
            if (size == 1)
                return (a & 1u) ? scd_pcm_read((a >> 1) & 0x1FFFu) : 0xFFu;
            return scd_pcm_read((a >> 1) & 0x1FFFu);
        }

        u32 r = a & 0x1FFu;
        if (r == 0x0Eu || r == 0x03u || r == 0x02u || (r >= 0x10u && r < 0x20u)) {
            if (S.sub_poll_pc == m.pc) {
                if (++S.sub_poll_cnt >= 3 && m.clock < S.sub_run_until)
                    m.clock = S.sub_run_until;
            } else {
                S.sub_poll_pc = m.pc;
                S.sub_poll_cnt = 1;
            }
        }
        if (size == 1) {
            if (r == 0x00u) return S.regs[0x06 >> 1] >> 8;
            if (r == 0x01u) return 0x01u;
            if (r == 0x03u) return S.regs[1] & 0x1Fu;
            if (r == 0x07u) return cdc_reg_read();
            if (r == 0x58u) {
                scd_gfx_update(m.clock);
                if ((S.regs[0x58 >> 1] & 0x8000u) && m.clock < S.sub_run_until) {
                    m.clock = S.sub_run_until;
                    scd_gfx_update(m.clock);
                }
                return S.regs[0x58 >> 1] >> 8;
            }
            if (r >= 0x50u && r <= 0x57u) {
                u16 fd = scd_font_expand(r);
                return (r & 1u) ? (fd & 0xFFu) : (fd >> 8);
            }
            u16 w = S.regs[(r & 0x1FEu) >> 1];
            return (r & 1u) ? (w & 0xFFu) : (w >> 8);
        } else {
            r &= 0x1FEu;
            if (r == 0x00u) return (S.regs[0x06 >> 1] & 0xFF00u) | 0x01u;
            if (r == 0x02u) return S.regs[1] & 0xFF1Fu;
            if (r == 0x06u) return cdc_reg_read();
            if (r == 0x08u) return cdc_host_read(3u);
            if (r == 0x0Cu) {
                s32 ticks = (m.clock - S.stopwatch_base) / SCD_STOPWATCH_DIV;
                return (S.regs[0x0C >> 1] + (u32)ticks) & 0x0FFFu;
            }
            if (r >= 0x50u && r <= 0x56u) return scd_font_expand(r);
            if (r == 0x58u) {
                scd_gfx_update(m.clock);
                if ((S.regs[0x58 >> 1] & 0x8000u) && m.clock < S.sub_run_until) {
                    m.clock = S.sub_run_until;
                    scd_gfx_update(m.clock);
                }
            }
            return S.regs[r >> 1];
        }
    }

    return (size == 1) ? 0xFFu : 0xFFFFu;
}

static void io_write(u32 a, u32 v, int size)
{
    S.sub_poll_cnt = 0;
    u32 slot = (a >> 16) & 0x0Fu;

    /* 1. Write-protected PRG-RAM ($000000..$01FFFF) */
    if (slot < 2u) {
        u32 off = a & 0x7FFFFu;
        u32 wp_limit = ((u32)(S.regs[1] >> 8)) << 9;
        if (off >= wp_limit) {
            if (size == 1) WSW_WB(M->prg_ram, off, v);
            else           WSW_WW(M->prg_ram, off, v);
        }
        return;
    }

    /* 2. $080000..$0BFFFF: 1M Dot-RAM write (with PM0..1 priority!) */
    if (slot >= 8u && slot < 12u) {
        if (S.regs[1] & 0x04u) {
            int sub_bank = (S.regs[1] & 1u) ? 0 : 1;
            u32 pm = (S.regs[1] >> 3) & 3u;
            u32 byte_idx = (a >> 1) & 0x1FFFFu;
            u8 prev = WSW_RB(M->word_ram_1m[sub_bank], byte_idx);
            u8 next;
            if (size == 1)
                next = (a & 1u) ? (u8)((prev & 0xF0u) | (v & 0x0Fu))
                                : (u8)((prev & 0x0Fu) | ((v & 0x0Fu) << 4));
            else
                next = (u8)((v & 0x0Fu) | ((v >> 4) & 0xF0u));
            WSW_WB(M->word_ram_1m[sub_bank], byte_idx, prio_mix_byte(pm, prev, next));
        }
        return;
    }

    /* 3. $FE0000..$FEFFFF: 8 KB Backup RAM */
    if (slot == 14u) {
        if (size == 2 || (a & 1u)) {
            u32 idx = (a >> 1) & 0x1FFFu;
            u8 b = (u8)v;
            if (M->bram[idx] != b) {
                M->bram[idx] = b;
                S.bram_dirty = 1;
            }
        }
        return;
    }

    /* 4. $FF0000..$FFFFFF: PCM & Gate Array */
    if (slot == 15u) {
        if (!(a & 0x8000u)) {
            if (size == 2 || (a & 1u))
                scd_pcm_write((a >> 1) & 0x1FFFu, (u8)v);
            return;
        }

        u32 r = a & 0x1FFu;
        /* Clean-room Sub-CPU BIOS HLE trap ports at $FF81FC (_CDBIOS) & $FF81FE (_BURAM) */
        if (!S.ext_bios && size == 2) {
            if (r == 0x1FCu) { scd_hle_cdbios((u16)v); return; }
            if (r == 0x1FEu) { scd_hle_buram((u16)v); return; }
        }

        if (size == 1) {
            switch (r) {
            case 0x00: S.regs[0x06 >> 1] = (u16)((S.regs[0x06 >> 1] & 0x00FFu) | ((v & 0xFFu) << 8)); return;
            case 0x01: return;
            case 0x02: case 0x03: scd_set_sub_memmode((u8)v); return;
            case 0x04:
                cdc_dma_update(m.clock);
                S.regs[0x04 >> 1] = (u16)((S.regs[0x04 >> 1] & 0x00FFu) | (((u16)v & 7u) << 8));
                S.regs[0x0A >> 1] = 0;
                cdc_dma_init();
                return;
            case 0x05:
                S.cdc_ar = v & 0x0Fu;
                S.regs[0x04 >> 1] = (u16)((S.regs[0x04 >> 1] & 0xFF00u) | S.cdc_ar);
                return;
            case 0x07: cdc_reg_write((u8)v); return;
            case 0x0E: case 0x0F:
                S.regs[0x0E >> 1] = (u16)((S.regs[0x0E >> 1] & 0xFF00u) | (v & 0xFFu));
                return;
            case 0x30: case 0x31:
                S.regs[0x30 >> 1] = (u16)(v & 0xFFu);
                S.timer_cnt = (v & 0xFFu) ? (s32)(((v & 0xFFu) + 1u) * SCD_STOPWATCH_DIV) : 0;
                return;
            case 0x33:
                S.ien = (u8)(v & 0x7Eu);
                S.regs[0x32 >> 1] = (u16)((S.regs[0x32 >> 1] & 0xFF00u) | (v & 0xFFu));
                S.regs[0] = (u16)((S.regs[0] & 0x7FFFu) | (((u16)v & 0x04u) << 13));
                if (!(v & 0x02u))
                    S.pending &= (u8)~0x02u;
                s68k_update_irq();
                return;
            case 0x4C: case 0x4D:
                S.regs[0x4C >> 1] = (u16)(v & 0xFFu);
                return;
            default:
                if (r >= 0x10u && r < 0x20u) return; /* COMCMD read-only on Sub-CPU */
                if ((r >= 0x08u && r <= 0x0Du) || (r >= 0x34u && r <= 0x35u) || (r >= 0x5Au && r <= 0x67u)) {
                    io_write(a & ~1u, (v << 8) | (v & 0xFFu), 2);
                    return;
                }
                if (r & 1u)
                    S.regs[r >> 1] = (u16)((S.regs[r >> 1] & 0xFF00u) | (v & 0xFFu));
                else
                    S.regs[r >> 1] = (u16)((S.regs[r >> 1] & 0x00FFu) | ((v & 0xFFu) << 8));
                return;
            }
        } else {
            r &= 0x1FEu;
            switch (r) {
            case 0x00:
                S.regs[0x06 >> 1] = (u16)((S.regs[0x06 >> 1] & 0x00FFu) | (v & 0xFF00u));
                return;
            case 0x02: scd_set_sub_memmode((u8)v); return;
            case 0x04:
                cdc_dma_update(m.clock);
                S.cdc_ar = v & 0x0Fu;
                S.regs[0x04 >> 1] = (u16)((v & 0x0700u) | S.cdc_ar);
                S.regs[0x0A >> 1] = 0;
                cdc_dma_init();
                return;
            case 0x06: cdc_reg_write((u8)v); return;
            case 0x08: (void)cdc_host_read(3u); return;
            case 0x0C:
                S.stopwatch_base = m.clock;
                S.regs[0x0C >> 1] = 0;
                return;
            case 0x0E:
                S.regs[0x0E >> 1] = (u16)((S.regs[0x0E >> 1] & 0xFF00u) | (v & 0xFFu));
                return;
            case 0x30:
                S.regs[0x30 >> 1] = (u16)(v & 0xFFu);
                S.timer_cnt = (v & 0xFFu) ? (s32)(((v & 0xFFu) + 1u) * SCD_STOPWATCH_DIV) : 0;
                return;
            case 0x32:
                S.ien = (u8)(v & 0x7Eu);
                S.regs[0x32 >> 1] = (u16)(v & 0xFFu);
                S.regs[0] = (u16)((S.regs[0] & 0x7FFFu) | (((u16)v & 0x04u) << 13));
                if (!(v & 0x02u))
                    S.pending &= (u8)~0x02u;
                s68k_update_irq();
                return;
            case 0x34:
                S.cdda_fader_dst = (u16)((v >> 4) & 0x7FFu);
                if (S.cdda_fader_dst > 0x400u) S.cdda_fader_dst = 0x400u;
                return;
            case 0x36:
                S.regs[0x36 >> 1] = (u16)((S.regs[0x36 >> 1] & 0xFF00u) | (v & 0x04u));
                return;
            case 0x4A:
                S.regs[0x4A >> 1] = 0;
                cdd_process_cmd();
                return;
            case 0x66:
                S.regs[0x66 >> 1] = (u16)v;
                scd_gfx_start((u16)v);
                return;
            default:
                if (r >= 0x10u && r < 0x20u) return;
                S.regs[r >> 1] = (u16)v;
                return;
            }
        }
    }
}

static void cpu_reset_line(void)
{
}

/* ========================================================================
 * Main-68000 Expansion Interface ($000000..$3FFFFF & $A12000..$A1202F)
 * ======================================================================== */

static void scd_step_sub_to(s32 target_sub_cyc)
{
    if (target_sub_cyc <= m.clock)
        return;

    while (m.clock < target_sub_cyc) {
        s32 step = target_sub_cyc - m.clock;
        if (S.timer_cnt > 0 && S.timer_cnt < step)
            step = S.timer_cnt;
        if (S.cdd_cnt > 0 && S.cdd_cnt < step)
            step = S.cdd_cnt;
        if (step <= 0)
            step = 1;

        s32 next_cyc = m.clock + step;
        S.sub_run_until = next_cyc;

        if (S.sres && !S.sbrq)
            cpu_run(next_cyc);
        else
            m.clock = next_cyc;

        s32 ran = m.clock - (next_cyc - step);
        if (ran < 0) ran = 0;

        if (S.timer_cnt > 0) {
            S.timer_cnt -= ran;
            if (S.timer_cnt <= 0) {
                u32 reload = S.regs[0x30 >> 1] & 0xFFu;
                S.timer_cnt += (s32)((reload + 1u) * SCD_STOPWATCH_DIV);
                s68k_trigger_irq(3u);
            }
        }

        S.cdd_cnt -= ran;
        while (S.cdd_cnt <= 0) {
            S.cdd_cnt += SCD_CDD_DIV;
            cdd_tick_75hz();
        }

        if (S.cdc_dma_mode)
            cdc_dma_update(m.clock);
        if (S.regs[0x58 >> 1] & 0x8000u)
            scd_gfx_update(m.clock);
    }
}

static void scd_addon_run_line(s32 main_cyc)
{
    /* main_cyc <= ~160,000 per frame -> main_cyc * 1669 <= 267,040,000 (fits in signed 32-bit!) */
    s32 sub_target = (main_cyc > 0) ? ((main_cyc * 1669) >> 10) : 0;
    scd_step_sub_to(sub_target);
}

static void scd_addon_end_frame(s32 main_frame_cyc)
{
    s32 sub_frame = (main_frame_cyc * 1669) >> 10;
    scd_step_sub_to(sub_frame);

    s32 ticks = (sub_frame - S.stopwatch_base) / SCD_STOPWATCH_DIV;
    S.regs[0x0C >> 1] = (u16)((S.regs[0x0C >> 1] + (u32)ticks) & 0x0FFFu);
    S.stopwatch_base += ticks * SCD_STOPWATCH_DIV - sub_frame;

    m.clock       -= sub_frame;
    S.gfx_last_cyc -= sub_frame;
    S.cdc_dma_cyc  -= sub_frame;
    S.cdc_dec_end  -= sub_frame;
}

static void scd_addon_map(u8 *m_rmap[256], u8 *m_wmap[256])
{
    u8  mem_mode = (u8)(S.regs[1] & 0xFFu);
    u32 prg_bank = ((u32)mem_mode >> 6) & 3u;
    int sub_halted = (!S.sres || S.sbrq);
    int is_1m = (mem_mode & 0x04u) != 0;
    int ret   = (mem_mode & 0x01u) != 0;

    /* $000000..$1FFFFF: 128 KB Mega-CD BIOS + 128 KB banked PRG-RAM window (mirrored every 256 KB) */
    for (u32 i = 0x00u; i < 0x20u; i++) {
        if ((i & 2u) == 0u) {
            m_rmap[i] = M->bios_rom + ((i & 1u) << 16);
            m_wmap[i] = 0;
        } else if (sub_halted) {
            u8 *pg = M->prg_ram + (prg_bank << 17) + ((i & 1u) << 16);
            m_rmap[i] = pg;
            m_wmap[i] = pg;
        }
    }

    /* $200000..$3FFFFF: Word-RAM (mirrored every 256 KB) */
    for (u32 i = 0x20u; i < 0x40u; i++) {
        if (!is_1m) {
            if (ret) {
                u8 *pg = M->word_ram_2m + ((i & 3u) << 16);
                m_rmap[i] = pg;
                m_wmap[i] = pg;
            }
        } else {
            if ((i & 3u) < 2u) {
                u8 *pg = M->word_ram_1m[ret] + ((i & 1u) << 16);
                m_rmap[i] = pg;
                m_wmap[i] = pg;
            }
            /* (i & 3) >= 2 ($220000..$23FFFF): 1M VDP Cell-arranged view via scd_addon_io_read/write */
        }
    }
}

static u32 scd_addon_io_read(u32 a, int size, s32 main_cyc)
{
    u32 page = (a >> 16) & 0xFFu;

    /* 1. $220000..$3FFFFF (odd pairs): 1M VDP Cell-arranged Word-RAM */
    if (page >= 0x20u && page < 0x40u && (S.regs[1] & 0x04u) && ((page & 3u) >= 2u)) {
        int main_bank = S.regs[1] & 1u;
        u32 cell_off = (u32)M->lut_offset[(a >> 2) & 0x7FFFu] | (a & 0x10003u);
        if (size == 1)
            return WSW_RB(M->word_ram_1m[main_bank], cell_off);
        return WSW_RW(M->word_ram_1m[main_bank], cell_off);
    }

    /* 2. $400000..$7FFFFF: RAM Cartridge ID ($400000 = 0xFF none, or 0x04 64KB) */
    if (page >= 0x40u && page < 0x80u)
        return (size == 1) ? 0xFFu : 0xFFFFu;

    /* 3. $A12000..$A1202F: Main-CPU Gate Array registers */
    if (page == 0xA1u && (a & 0xFF00u) == 0x2000u) {
        if (main_cyc > 0)
            scd_step_sub_to((main_cyc * 1669) >> 10);

        u32 r = a & 0x3Fu;
        u16 w;
        switch (r & 0x3Eu) {
        case 0x00: {
            u8 hi = (u8)((S.regs[0] >> 8) & 0x81u); /* IEN2 (bit 7) | IFL2 (bit 0) */
            u8 lo = (u8)(((!S.sres || S.sbrq) ? 0x02u : 0x00u) | (S.sres ? 0x01u : 0x00u));
            w = (u16)(((u16)hi << 8) | lo);
            break;
        }
        case 0x02:
            w = S.regs[1];
            break;
        case 0x04:
            w = (u16)(S.regs[0x04 >> 1] & 0xC700u);
            break;
        case 0x06:
            w = WSW_RW(M->bios_rom, 0x72u);
            break;
        case 0x08:
            w = cdc_host_read(2u);
            break;
        case 0x0C: {
            s32 ticks = (m.clock - S.stopwatch_base) / SCD_STOPWATCH_DIV;
            w = (u16)((S.regs[0x0C >> 1] + (u32)ticks) & 0x0FFFu);
            break;
        }
        default:
            if ((r & 0x3Eu) < 0x30u)
                w = S.regs[(r & 0x3Eu) >> 1];
            else
                w = 0xFFFFu;
            break;
        }
        return (size == 1) ? ((r & 1u) ? (w & 0xFFu) : (w >> 8)) : w;
    }

    return (size == 1) ? 0xFFu : 0xFFFFu;
}

static void scd_main_ctrl_write_lo(u8 v)
{
    u8 new_sres = v & 1u;
    u8 new_sbrq = (v >> 1) & 1u;
    int map_chg = ((new_sres != S.sres) || (new_sbrq != S.sbrq));

    if (new_sres && !S.sres) {
        /* Rising edge of /SRES -> reset Sub-68000 from PRG-RAM $000000 vectors! */
        s68k_rebuild_map();
        cpu_reset();
    }
    S.sres = new_sres;
    S.sbrq = new_sbrq;
    S.regs[0] = (u16)((S.regs[0] & 0xFF00u) | (v & 3u));
    if (map_chg) {
        s68k_rebuild_map();
        md_remap();
    }
}

static void scd_main_memmode_write_lo(u8 v)
{
    u8 cur = (u8)(S.regs[1] & 0xFFu);
    u8 bk  = v & 0xC0u;
    int map_chg = ((cur & 0xC0u) != bk);

    if (cur & 0x04u) {
        /* 1M mode: Main-CPU writing DMNA=1 requests bank swap (sets DMNA=1) */
        if (v & 0x02u) {
            S.dmna_latch = 1;
            cur |= 0x02u;
        }
    } else {
        /* 2M mode: Main-CPU writing DMNA=1 hands Word-RAM over to Sub-CPU (RET=0, DMNA=1) */
        if (v & 0x02u) {
            S.dmna_latch = 1;
            cur = (u8)((cur & ~0x01u) | 0x02u);
            map_chg = 1;
        }
    }
    S.regs[1] = (u16)((S.regs[1] & 0xFF00u) | bk | (cur & 0x3Fu));
    if (map_chg) {
        s68k_rebuild_map();
        md_remap();
    }
}

static void scd_addon_io_write(u32 a, u32 v, int size, s32 main_cyc)
{
    u32 page = (a >> 16) & 0xFFu;

    /* 1. $220000..$3FFFFF: 1M VDP Cell-arranged Word-RAM write */
    if (page >= 0x20u && page < 0x40u && (S.regs[1] & 0x04u) && ((page & 3u) >= 2u)) {
        int main_bank = S.regs[1] & 1u;
        u32 cell_off = (u32)M->lut_offset[(a >> 2) & 0x7FFFu] | (a & 0x10003u);
        if (size == 1)
            WSW_WB(M->word_ram_1m[main_bank], cell_off, v);
        else
            WSW_WW(M->word_ram_1m[main_bank], cell_off, v);
        return;
    }

    /* 2. $A12000..$A1202F: Main-CPU Gate Array write */
    if (page == 0xA1u && (a & 0xFF00u) == 0x2000u) {
        if (main_cyc > 0)
            scd_step_sub_to((main_cyc * 1669) >> 10);

        u32 r = a & 0x3Fu;
        if (size == 1) {
            switch (r) {
            case 0x00:
                if (v & 1u) {
                    S.regs[0] |= 0x0100u;   /* Set IFL2 */
                    s68k_trigger_irq(2u);
                }
                return;
            case 0x01:
                scd_main_ctrl_write_lo((u8)v);
                return;
            case 0x02:
                S.regs[1] = (u16)((S.regs[1] & 0x00FFu) | ((v & 0xFFu) << 8));
                s68k_rebuild_map();
                return;
            case 0x03:
                scd_main_memmode_write_lo((u8)v);
                return;
            case 0x06:
                WSW_WB(M->bios_rom, 0x72u, v);
                return;
            case 0x07:
                WSW_WB(M->bios_rom, 0x73u, v);
                return;
            case 0x0E:
            case 0x0F: /* Main-CPU byte write to either $A1200E or $A1200F updates CFM ($0E)! */
                S.regs[0x0E >> 1] = (u16)((S.regs[0x0E >> 1] & 0x00FFu) | ((v & 0xFFu) << 8));
                return;
            default:
                if (r >= 0x10u && r < 0x20u) {
                    if (r & 1u)
                        S.regs[r >> 1] = (u16)((S.regs[r >> 1] & 0xFF00u) | (v & 0xFFu));
                    else
                        S.regs[r >> 1] = (u16)((S.regs[r >> 1] & 0x00FFu) | ((v & 0xFFu) << 8));
                }
                return;
            }
        } else {
            r &= 0x3Eu;
            switch (r) {
            case 0x00:
                scd_main_ctrl_write_lo((u8)v);
                if (v & 0x0100u) {
                    S.regs[0] |= 0x0100u;
                    s68k_trigger_irq(2u);
                }
                return;
            case 0x02:
                S.regs[1] = (u16)((S.regs[1] & 0x00FFu) | (v & 0xFF00u));
                scd_main_memmode_write_lo((u8)v);
                s68k_rebuild_map();
                return;
            case 0x06:
                WSW_WW(M->bios_rom, 0x72u, v);
                return;
            case 0x0E:
                S.regs[0x0E >> 1] = (u16)((S.regs[0x0E >> 1] & 0x00FFu) | (v & 0xFF00u));
                return;
            default:
                if (r >= 0x10u && r < 0x20u)
                    S.regs[r >> 1] = (u16)v;
                return;
            }
        }
    }
}

/* ========================================================================
 * Clean-Room Mega-CD BIOS Builder (Main-CPU ROM & Sub-CPU PRG-RAM Kernel)
 * ======================================================================== */

static void scd_read_disc_bytes(u32 byte_off, u32 len, u8 *dst_wsw, u32 dst_off, u32 dst_max)
{
    if (!S.cd || !S.cd->read_2048 || !len)
        return;
    u8 sec[2048];
    u32 cur_sec = 0xFFFFFFFFu;
    for (u32 i = 0; i < len && (dst_off + i) < dst_max; i++) {
        u32 pos = byte_off + i;
        u32 lba = pos >> 11;
        u32 in_sec = pos & 0x7FFu;
        if (lba != cur_sec) {
            if (S.cd->read_2048(lba, sec) < 0)
                return;
            cur_sec = lba;
        }
        WSW_WB(dst_wsw, dst_off + i, sec[in_sec]);
    }
}

static void wsw_put32(u8 *base, u32 off, u32 val)
{
    WSW_WW(base, off + 0u, (u16)(val >> 16));
    WSW_WW(base, off + 2u, (u16)val);
}

static void wsw_copy_words(u8 *base, u32 off, const u16 *words, u32 count)
{
    for (u32 i = 0; i < count; i++)
        WSW_WW(base, off + i * 2u, words[i]);
}

static void scd_build_cleanroom_bios(u16 *main_ram32kw)
{
    /* 1. Clear Main-CPU 128 KB BIOS ROM and install vectors */
    for (u32 i = 0; i < sizeof(M->bios_rom); i++)
        M->bios_rom[i] = 0;

    wsw_put32(M->bios_rom, 0x00u, 0x00FFFE00u);     /* Initial SSP */
    wsw_put32(M->bios_rom, 0x04u, 0x00000200u);     /* Initial PC -> Clean-Room Main Boot */
    for (u32 v = 2u; v < 64u; v++)
        wsw_put32(M->bios_rom, v * 4u, 0x000002F0u);/* Default RTE */
    wsw_put32(M->bios_rom, 0x70u, 0x00FFFD0Cu);     /* Level 4 H-INT -> $FFFD0C (low word at $72 = $A12006!) */
    wsw_put32(M->bios_rom, 0x78u, 0x00FFFD06u);     /* Level 6 V-INT -> $FFFD06 */

    /* Default Main-CPU V-INT handler at $0002E0: triggers Sub-CPU IFL2 ($A12000 = 0x01) + RTE! */
    static const u16 main_vint_code[] = {
        0x13FC, 0x0001, 0x00A1, 0x2000,             /* MOVE.B #$01, $00A12000.l (assert Sub-CPU IFL2) */
        0x4E73                                      /* RTE */
    };
    wsw_copy_words(M->bios_rom, 0x02E0u, main_vint_code, sizeof(main_vint_code) / 2u);
    WSW_WW(M->bios_rom, 0x02F0u, 0x4E73u);          /* RTE */

    /* Read Sector 0 to locate Main-CPU IP and Sub-CPU SP */
    u8 sec0[2048];
    for (u32 i = 0; i < 2048u; i++) sec0[i] = 0;
    if (S.cd && S.cd->read_2048)
        (void)S.cd->read_2048(0u, sec0);

    u32 ip_off   = rd_be32(sec0 + 0x30u);
    u32 ip_size  = rd_be32(sec0 + 0x34u);
    u32 ip_entry = rd_be32(sec0 + 0x38u);
    u32 sp_off   = rd_be32(sec0 + 0x40u);
    u32 sp_size  = rd_be32(sec0 + 0x44u);

    if (!ip_off) ip_off = 0x200u;
    if (!ip_size || ip_size > 0xEA00u) ip_size = 0x800u;
    if (!sp_off) sp_off = 0x1000u;
    if (!sp_size || sp_size > 0x78000u) sp_size = 0x8000u;

    /* Load Main-CPU IP into Mega Drive Work RAM ($FF0000 = main_ram32kw) */
    u8 *mram = (u8 *)main_ram32kw;
    u32 main_jump = 0x00FF0000u + ip_entry;
    if (ip_off >= 0x800u) {
        /* Copy Sector 0 $200..$7FF to $FF0000, and Sector >=1 IP payload to $FF0600 (or $FF0000 if $200 is empty) */
        int has_sec_stub = (sec0[0x200] != 0 || sec0[0x201] != 0);
        /* Detect retail Sega copyrighted region-security preamble (4BFA ... "SEGA"): skip straight to IP at $FF0600! */
        int retail_sec = (sec0[0x200] == 0x4Bu && sec0[0x201] == 0xFAu);
        if (has_sec_stub && !retail_sec) {
            scd_read_disc_bytes(0x200u, 0x600u, mram, 0u, 0xFD00u);
            scd_read_disc_bytes(ip_off, ip_size, mram, 0x600u, 0xFD00u);
        } else if (retail_sec) {
            scd_read_disc_bytes(0x200u, 0x600u, mram, 0u, 0xFD00u);
            scd_read_disc_bytes(ip_off, ip_size, mram, 0x600u, 0xFD00u);
            if (!ip_entry) main_jump = 0x00FF0600u;
        } else {
            scd_read_disc_bytes(ip_off, ip_size, mram, 0u, 0xFD00u);
        }
    } else {
        scd_read_disc_bytes(ip_off, ip_size, mram, 0u, 0xFD00u);
    }

    /* Populate Main-CPU Work RAM jump vectors at $FFFD00..$FFFD17 */
    WSW_WW(mram, 0xFD00u, 0x4EF9u); wsw_put32(mram, 0xFD02u, 0x00000200u); /* RESET */
    WSW_WW(mram, 0xFD06u, 0x4EF9u); wsw_put32(mram, 0xFD08u, 0x000002E0u); /* V-INT ($FFFD06) */
    WSW_WW(mram, 0xFD0Cu, 0x4EF9u); wsw_put32(mram, 0xFD0Eu, 0x000002F0u); /* H-INT ($FFFD0C) */
    WSW_WW(mram, 0xFD12u, 0x4EF9u); wsw_put32(mram, 0xFD14u, 0x000002F0u); /* EXT-INT */

    /* Main-CPU Boot Stub at $000200:
       1. Release Z80 reset ($A11200 = $0100)
       2. Start Sub-CPU ($A12001 = $01 -> SRES=1, SBRQ=0)
       3. Unmask VDP V-INT (SR = $2000) and JMP main_jump ($FF0000)! */
    u16 main_boot[] = {
        0x33FC, 0x0100, 0x00A1, 0x1200,             /* MOVE.W #$0100, $00A11200.l */
        0x13FC, 0x0001, 0x00A1, 0x2001,             /* MOVE.B #$01,   $00A12001.l (start Sub-CPU!) */
        0x46FC, 0x2000,                             /* MOVE.W #$2000, SR */
        0x4EF9, (u16)(main_jump >> 16), (u16)main_jump /* JMP main_jump */
    };
    wsw_copy_words(M->bios_rom, 0x0200u, main_boot, sizeof(main_boot) / 2u);

    /* 2. Build Clean-Room Sub-CPU Kernel in PRG-RAM ($000000..$005FFF) + Load SP at $006000! */
    for (u32 i = 0; i < 0x6000u; i++)
        M->prg_ram[i] = 0;
    scd_read_disc_bytes(sp_off, sp_size, M->prg_ram, 0x6000u, sizeof(M->prg_ram));

    /* Sub-CPU vectors at $000000..$0000FF */
    wsw_put32(M->prg_ram, 0x00u, 0x00005DC0u);      /* Sub SSP */
    wsw_put32(M->prg_ram, 0x04u, 0x00000400u);      /* Sub Reset PC */
    for (u32 v = 2u; v < 64u; v++)
        wsw_put32(M->prg_ram, v * 4u, 0x000004F0u); /* Default RTE */
    /* Autovectors Level 1..6 -> standard Sub-CPU RAM jump table $5F76..$5F94 */
    for (u32 lvl = 1u; lvl <= 6u; lvl++) {
        u32 jtab = 0x5F76u + (lvl - 1u) * 6u;
        wsw_put32(M->prg_ram, (24u + lvl) * 4u, jtab);
        WSW_WW(M->prg_ram, jtab, 0x4EF9u);
        wsw_put32(M->prg_ram, jtab + 2u, 0x000004F0u); /* Default RTE */
    }
    WSW_WW(M->prg_ram, 0x04F0u, 0x4E73u);           /* RTE */
    WSW_WW(M->prg_ram, 0x04F2u, 0x4E75u);           /* RTS */

    /* _BURAM ($5F16) & _CDBIOS ($5F22) stubs */
    static const u16 buram_stub[] = {
        0x33C0, 0x00FF, 0x81FE,                     /* MOVE.W D0, $00FF81FE.l */
        0x4E75                                      /* RTS */
    };
    static const u16 cdbios_stub[] = {
        0x33C0, 0x00FF, 0x81FC,                     /* MOVE.W D0, $00FF81FC.l */
        0x4E75                                      /* RTS */
    };
    WSW_WW(M->prg_ram, 0x5F16u, 0x4EF9u); wsw_put32(M->prg_ram, 0x5F18u, 0x00000510u);
    WSW_WW(M->prg_ram, 0x5F22u, 0x4EF9u); wsw_put32(M->prg_ram, 0x5F24u, 0x00000520u);
    wsw_copy_words(M->prg_ram, 0x0510u, buram_stub, sizeof(buram_stub) / 2u);
    wsw_copy_words(M->prg_ram, 0x0520u, cdbios_stub, sizeof(cdbios_stub) / 2u);

    /* Inspect $006000 for standard "MAIN-SUBCPU" module header */
    int is_sp_hdr = (WSW_RB(M->prg_ram, 0x6000u) == 'M' &&
                     WSW_RB(M->prg_ram, 0x6001u) == 'A' &&
                     WSW_RB(M->prg_ram, 0x6002u) == 'I' &&
                     WSW_RB(M->prg_ram, 0x6003u) == 'N' &&
                     WSW_RB(M->prg_ram, 0x6004u) == '-');
    u32 sp_init = 0x000004F2u;                      /* RTS */
    u32 sp_main = 0x00006000u;
    u32 sp_int2 = 0;

    if (is_sp_hdr) {
        u32 tbl_rel = ((u32)WSW_RW(M->prg_ram, 0x6018u) << 16) | WSW_RW(M->prg_ram, 0x601Au);
        u32 tbl = 0x6000u + tbl_rel;
        if (tbl >= 0x6000u && tbl + 6u < sizeof(M->prg_ram)) {
            u16 o_init = WSW_RW(M->prg_ram, tbl + 0u);
            u16 o_main = WSW_RW(M->prg_ram, tbl + 2u);
            u16 o_int2 = WSW_RW(M->prg_ram, tbl + 4u);
            if (o_init) sp_init = tbl + (u32)(s32)(s16)o_init;
            if (o_main) sp_main = tbl + (u32)(s32)(s16)o_main;
            if (o_int2) sp_int2 = tbl + (u32)(s32)(s16)o_int2;
        }
    }

    if (sp_int2) {
        /* Level 2 IRQ wrapper at $000480: MOVEM.L D0-D7/A0-A6,-(SP); JSR sp_int2; MOVEM.L (SP)+,D0-D7/A0-A6; RTE */
        u16 int2_wrap[] = {
            0x48E7, 0xFFFE,                         /* MOVEM.L D0-D7/A0-A6, -(A7) */
            0x4EB9, (u16)(sp_int2 >> 16), (u16)sp_int2,
            0x4CDF, 0x7FFF,                         /* MOVEM.L (A7)+, D0-D7/A0-A6 */
            0x4E73                                  /* RTE */
        };
        wsw_copy_words(M->prg_ram, 0x0480u, int2_wrap, sizeof(int2_wrap) / 2u);
        wsw_put32(M->prg_ram, 0x5F7Cu + 2u, 0x00000480u); /* Patch $5F7C Level 2 jump! */
    }

    /* Sub-CPU Kernel Startup at $000400:
       1. Enable HOCK ($FF8036 = $0004) & IEN1..IEN5 ($FF8033 = $3E)
       2. Call SPInit (with interrupts masked), then unmask SR = $2000 and loop calling SPMain! */
    u16 sub_boot[] = {
        0x33FC, 0x0004, 0x00FF, 0x8036,             /* MOVE.W #$0004, $00FF8036.l (HOCK) */
        0x13FC, 0x003E, 0x00FF, 0x8033,             /* MOVE.B #$3E,   $00FF8033.l (IEN1..5) */
        0x4EB9, (u16)(sp_init >> 16), (u16)sp_init, /* JSR sp_init */
        0x46FC, 0x2000,                             /* MOVE.W #$2000, SR */
        /* .loop ($041A): */
        0x4EB9, (u16)(sp_main >> 16), (u16)sp_main, /* JSR sp_main */
        0x60F8                                      /* BRA.S .loop */
    };
    wsw_copy_words(M->prg_ram, 0x0400u, sub_boot, sizeof(sub_boot) / 2u);
}

/* ========================================================================
 * Addon Reset & Public Load / Save API
 * ======================================================================== */

static void scd_addon_reset(u16 *main_ram32kw)
{
    for (u32 i = 0; i < 256u; i++)
        S.regs[i] = 0;
    for (u32 i = 0; i < sizeof(M->prg_ram); i++)
        M->prg_ram[i] = 0;
    for (u32 i = 0; i < sizeof(M->word_ram_2m); i++)
        M->word_ram_2m[i] = 0;
    for (u32 i = 0; i < sizeof(M->word_ram_1m); i++)
        ((u8 *)M->word_ram_1m)[i] = 0;
    for (u32 i = 0; i < sizeof(M->pcm_ram); i++)
        M->pcm_ram[i] = 0;

    S.sres = 0;
    S.sbrq = 1;
    S.dmna_latch = 0;
    S.pending = 0;
    S.ien = 0;
    S.regs[0] = 0x0002u;                            /* SBRQ=1, SRES=0 */
    S.regs[1] = 0x0001u;                            /* 2M mode, RET=1 (Main-CPU owns Word-RAM) */
    S.regs[0x08 >> 1] = 0xFFFFu;
    S.regs[0x0A >> 1] = 0xFFFFu;
    S.regs[0x36 >> 1] = 0x0100u;                    /* Data/mute bit */
    S.regs[0x40 >> 1] = 0x000Fu;

    S.stopwatch_base = 0;
    S.timer_cnt = 0;
    S.cdd_cnt = SCD_CDD_DIV;
    S.cdd_status = S.cd ? CDD_TOC : CDD_NOCD;
    S.cdd_pending = 0;
    S.cdd_latency = 0;
    S.cdd_lba = 0;
    S.cdd_end_lba = 0;
    S.cdd_loop = 0;
    S.cdd_track_idx = 1;
    S.cdda_fader_cur = S.cdda_fader_dst = 0x400u;
    S.cdda_playing = 0;
    S.cdda_pos = 588u;
    S.cdda_l = S.cdda_r = 0;

    S.hle_reading = 0;
    S.hle_sec_ready = 0;

    S.pcm_en = 0;
    S.pcm_on_mask = 0;
    S.pcm_sel = S.pcm_bank = 0;
    for (int i = 0; i < 8; i++) {
        S.pcm_ch[i].addr = S.pcm_ch[i].st = 0;
        S.pcm_ch[i].fd = S.pcm_ch[i].ls = 0;
        S.pcm_ch[i].env = 0;
        S.pcm_ch[i].pan = 0xFFu;
    }
    S.pcm_l = S.pcm_r = 0;

    cdc_reset();
    S.gfx_last_cyc = 0;

    if (S.ext_bios) {
        WSW_WW(M->bios_rom, 0x70u, 0xFFFFu);
        WSW_WW(M->bios_rom, 0x72u, 0xFFFFu);
    } else {
        scd_build_cleanroom_bios(main_ram32kw);
    }

    m.clock = 0;
    s68k_rebuild_map();
    cpu_reset();
}

static const struct md_addon segacd_addon = {
    scd_addon_reset,
    scd_addon_map,
    scd_addon_io_read,
    scd_addon_io_write,
    scd_addon_run_line,
    scd_addon_end_frame,
    scd_mix_audio,
    0,
    0
};

static char *scd_put(char *p, char *end, const char *s)
{
    while (*s && p < end) *p++ = *s++;
    *p = 0;
    return p;
}

static char *scd_put_u32(char *p, char *end, u32 v)
{
    char tmp[12];
    int n = 0;
    do { tmp[n++] = (char)('0' + v % 10u); v /= 10u; } while (v);
    while (n-- && p < end) *p++ = tmp[n];
    *p = 0;
    return p;
}

const char *segacd_load(const u8 *bios, u32 bios_size, const struct cdrom_toc *cd, int region)
{
    if (!cd || !cd->total_lba || !cd->read_2048)
        return "not a valid Sega CD / Mega-CD disc image";

    /* Initialize Sub-68000 opcode table & GFX LUTs inside EMU_RAM_PHYS */
    cpu_init();
    scd_init_gfx_luts();

    S.cd = cd;
    S.bram_dirty = 0;

    /* Initialize formatted 8 KB Backup RAM signature at end of BRAM */
    for (u32 i = 0; i < sizeof(M->bram); i++)
        M->bram[i] = 0;
    static const u8 bram_footer[16] = {
        0x5F,0x5F,0x5F,0x5F,0x5F,0x5F,0x5F,0x5F,0x5F,0x5F,0x5F,
        0x00, 0x00,0x7F, 0x00,0x7F
    };
    for (u32 i = 0; i < 16u; i++)
        M->bram[0x1FF0u + i] = bram_footer[i];

    /* Read Sector 0 to extract game title and region */
    u8 sec0[2048];
    for (u32 i = 0; i < 2048u; i++) sec0[i] = 0;
    (void)cd->read_2048(0u, sec0);

    int reg_c = region;
    if (!reg_c) {
        int j = 0, u = 0, e = 0;
        for (int i = 0x1F0; i < 0x1F3; i++) {
            u8 c = sec0[i];
            if (c == 'J') j = 1;
            if (c == 'U') u = 1;
            if (c == 'E') e = 1;
        }
        reg_c = u ? 'U' : j ? 'J' : e ? 'E' : 'U';
    }
    S.pal_mode = (reg_c == 'E');
    S.overseas_mode = (reg_c != 'J');

    if (bios && bios_size >= 0x20000u) {
        /* Byte-swap 128 KB big-endian 68000 BIOS into m68k.inc word order */
        for (u32 i = 0; i < 0x20000u; i += 2u) {
            M->bios_rom[i]      = bios[i + 1u];
            M->bios_rom[i + 1u] = bios[i];
        }
        S.ext_bios = 1;
    } else {
        S.ext_bios = 0;
    }

    /* Format disc info string */
    char name[49];
    int n = 0;
    for (int pass = 0; pass < 2 && !n; pass++) {
        const u8 *s = sec0 + (pass ? 0x120 : 0x150);
        for (int i = 0; i < 48; i++) {
            char c = (char)s[i];
            if (c < 32 || c > 126) c = ' ';
            if (c == ' ' && (!n || name[n - 1] == ' ')) continue;
            name[n++] = c;
        }
        while (n && name[n - 1] == ' ') n--;
    }
    name[n] = 0;

    char *end = S.title_buf + sizeof(S.title_buf) - 1;
    char *p = scd_put(S.title_buf, end, n ? name : "SEGA CD DISC");
    p = scd_put(p, end, S.ext_bios ? " (Mega-CD BIOS, " : " (Built-in CDBIOS, ");
    p = scd_put_u32(p, end, cd->last_track);
    p = scd_put(p, end, " trk, ");
    p = scd_put(p, end, S.pal_mode ? "PAL)" : S.overseas_mode ? "NTSC-U)" : "NTSC-J)");

    md_attach_addon(&segacd_addon, S.pal_mode, S.overseas_mode, S.title_buf);
    return 0;
}

u8 *segacd_save_ram(u32 *size, int *battery)
{
    *size = sizeof(M->bram);
    *battery = 1;
    return M->bram;
}

int segacd_save_changed(void)
{
    int d = S.bram_dirty;
    S.bram_dirty = 0;
    return d;
}
