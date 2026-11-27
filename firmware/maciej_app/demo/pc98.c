/* NEC PC-9801VM / VX ('pc98'): see pc98.h.
   Pass-optimized for 594 MHz MIPS32:
   - Zero static .bss (all RAM, 2-page 4-plane GVRAM, TVRAM, 96x96 JIS/Gaiji KCG, FM tables & audio in EMU_RAM_PHYS)
   - Shared x86 / NEC V30 / 286 / 386 Real-Mode CPU core (x86_v30.inc)
   - Dual uPD7220 GDC: 640x400 16-color GVRAM (A8000/B0000/B8000/E0000) + 80x25 Text/Attr VRAM (A0000/A2000)
   - GRCG (TDW / TCR / RMW) + EGC (16-bit planar ROP/mask) + Analog 4096->RGB555 & Digital 8-color palettes
   - PC-9801-26K / 86 Sound: 6-ch 4-op FM + 3-ch SSG + YM Timer A/B (IRQ 12) + PIT Buzzer @ 48 kHz
   - Floppy (.fdi, .d88, .hdm, .xdf, .2hd, .img) + SASI HDD (.hdi) + Multi-file .zip/.exe PC-98 MS-DOS 5.0 HLE */
#pragma GCC optimize("O2")
#include "pc98.h"
#include "font5x7.h"

typedef signed char s8;
typedef unsigned long long u64;

#define INLINE static inline __attribute__((always_inline))
#define X86_INLINE INLINE

#ifdef __mips__
#include "hw.h"
#endif

#define PC98_CPU_HZ      10000000u       /* 10 MHz V30 / 286 system timing */
#define PC98_PIT_HZ      2457600u        /* 2.4576 MHz PIT clock (10 MHz lineage, BIOS 0501h bit7=0) */
#define PC98_LINES       440             /* 400 active + 40 VBlank @ 56.42 Hz */
#define PC98_CYC_LINE    403             /* ~177,320 cycles/frame (~10.01 MHz @ 56.42 Hz) */
#define SND_RING         4096
#define MAX_FILES        128
#define MAX_HANDLES      32
#define SCRATCH_CAP      0x10000u        /* 64 KB writable DOS scratch files (.CFG, high scores) */
#define DIRTY_SECS       64              /* 64 KB RAM write-overlay for disk sectors */

/* Yamaha YM2203 / YM2608 4-operator FM channel */
struct pc98_op {
    u32 phase, inc;
    s32 env;                             /* 0 (max) .. 1023 (silent) */
    u8  state;                           /* 0=OFF, 1=ATT, 2=DEC, 3=SUS, 4=REL */
    u8  dt, mul, tl, ks, ar, dr, sr, sl, rr;
};

struct pc98_fm_ch {
    struct pc98_op op[4];
    u16 fnum;
    u8  block, fnum_hi;
    u8  fb, alg, pan;
    s32 fb_buf[2];
};

struct pc98_vfile {
    char name[64];                       /* Relative path e.g. "POROLITH.EXE" or "SUB/DATA.BIN" */
    const u8 *data;
    u8  *wr_data;
    u32  size;
    u32  cap;
    u32  fat_clus;                       /* >0 if backed by FAT12/FAT16 cluster chain on disk image */
    u8   is_dir;
};

struct pc98_handle {
    u8   open;
    u8   is_con;
    s16  fidx;
    u32  pos;
};

struct pc98_pic {
    u8 imr, irr, isr;
    u8 icw_step, vec_base, ocw3_isr;
};

/* Forward declarations for x86_v30.inc hooks */
static u32  pc98_addr_mask(void);
static u8  *pc98_fast_ram(void);
static u8   pc98_rb(u32 a);
static u16  pc98_rw(u32 a);
static void pc98_wb(u32 a, u8 v);
static void pc98_ww(u32 a, u16 v);
static u8   pc98_inb(u16 p);
static u16  pc98_inw(u16 p);
static void pc98_outb(u16 p, u8 v);
static void pc98_outw(u16 p, u16 v);
struct x86_cpu;
static void pc98_hle_trap(struct x86_cpu *cpu, u8 id);

#define X86_ADDR_MASK (pc98_addr_mask())
#define X86_FAST_RAM  (pc98_fast_ram())
#define X86_FAST_LIM  0xA0000u
#define X86_RB(a)     pc98_rb(a)
#define X86_RW(a)     pc98_rw(a)
#define X86_WB(a, v)  pc98_wb(a, v)
#define X86_WW(a, v)  pc98_ww(a, v)
#define X86_INB(p)    pc98_inb(p)
#define X86_INW(p)    pc98_inw(p)
#define X86_OUTB(p,v) pc98_outb(p, v)
#define X86_OUTW(p,v) pc98_outw(p, v)
#define X86_TRAP(c,i) pc98_hle_trap(c, i)

/* Bring in the shared x86 / NEC V30 CPU engine (-Os keeps x86_run I-cache-friendly) */
#pragma GCC push_options
#pragma GCC optimize("Os")
#include "x86_v30.inc"
#pragma GCC pop_options

struct pc98_mem {
    u32 magic;
    struct x86_cpu cpu;
    u32 a20_mask;

    /* 1 MB Conventional + BIOS space + 1 MB Extended memory */
    u8  ram[0x100000];
    u8  ext_ram[0x100000];

    /* Video memory: 2 pages x 4 planes x 32 KB GVRAM + 16 KB Text/Attr VRAM */
    u8  gvram[2][4][0x8000];
    u8  tvram[0x4000];

    /* Character Generator: 256 ANK 8x16 + 96 x 96 x 32 B full JIS/Gaiji 16x16 KCG */
    u8  ank8x8[256][8];
    u8  ank8x16[256][16];
    u8  kcg[96][96][32];

    const u8 *ext_font;
    u32 ext_font_size;

    /* Dual uPD7220 GDC + Mode Flip-Flops + Palette + GRCG + EGC */
    u8  gvram_on, tvram_on, analog_16c, disp_page, draw_page;
    u8  ff1_20line, ff1_col40, ff1_attr_vl, ff1_kcg_dot;
    u8  vsync_now, hblank_tog, vsync_irq_armed;
    u8  cursor_on;
    u16 cursor_addr;
    u8  gdc_m_cmd, gdc_s_cmd;
    u8  gdc_m_fifo[16], gdc_m_r, gdc_m_w;
    u8  gdc_s_fifo[16], gdc_s_r, gdc_s_w;

    u8  pal_sel;
    u8  anapal[16][3];                   /* [idx][0=G, 1=R, 2=B] 4-bit 0..15 */
    u8  digpal[4];                       /* 8-color digital ports A8/AA/AC/AE */
    u16 pal15[16];                       /* Precomputed 15-bit 0bbbbbgggggrrrrr */
    u16 tpal15[8];                       /* Text 3-bit GRB palette */

    /* GRCG (ports 7Ch / 7Eh) & EGC (ports 04A0h..04AFh) */
    u8  grcg_mode, grcg_idx, grcg_tile[4];
    u8  egc_en;
    u16 egc_regs[8];
    u16 egc_last[4];

    /* KCG port latch (ports A1/A3/A5/A9) */
    u8  kcg_c1, kcg_c2, kcg_line;

    /* Dual 8259A PIC + 8253 PIT + Keyboard + Mouse */
    struct pc98_pic pic_m, pic_s;
    u16 pit_reload[3], pit_latch[3];
    u8  pit_rw_mode[3], pit_msb_st[3], pit_latched[3], pit_read_msb[3];
    s32 pit0_acc;
    u8  port_c;                          /* 8255 Port C (bit 3 = buzzer inhibit: 0=ON, 1=OFF) */
    u32 beep_ph;

    u8  kb_prev[16], kb_cur[16], kb_usb[16];
    u8  kb_sc_q[32], kb_sc_r, kb_sc_w;
    char type_q[64];
    u8  type_r, type_w, type_hold;
    u16 pad;

    /* Disk subsystem (.fdi, .hdm, .d88, .hdi) */
    const u8 *disk_img;
    u32 disk_size;
    u8  disk_kind;                       /* 0=none, 1=raw/fdi FDD, 2=D88 FDD, 3=HDI/raw SASI HDD */
    u8  boot_daua;                       /* 0x90 = 2HD FDD, 0x70 = 2DD FDD, 0x80 = SASI HDD */
    u32 disk_hdr;
    u32 disk_cyls, disk_heads, disk_spt, disk_sec_sz;
    u32 d88_trk_off[164];
    u32 dirty_lba[DIRTY_SECS];
    u8  dirty_valid[DIRTY_SECS];
    u8  dirty_buf[DIRTY_SECS][1024];
    u32 dirty_next;

    /* uPD765 FDC port state (ports 90h/92h/94h, C8h/CAh/CCh) + DMA ch 2/3 */
    u8  fdc_cmd[16], fdc_cmd_len, fdc_cmd_pos;
    u8  fdc_res[16], fdc_res_len, fdc_res_pos;
    u16 dma_addr[4], dma_cnt[4];
    u8  dma_bank[4], dma_ff;

    /* PC-98 MS-DOS 5.0 HLE & FAT12/FAT16 filesystem */
    u8  dos_hle_active;
    u8  dos_ended;
    u16 psp_seg, dta_seg, dta_off, top_mem_seg;
    u16 mcb_first_seg;
    char cwd[64];
    u8  ansi_state;
    u8  ansi_params[4], ansi_npar;
    u8  ansi_gt;
    u8  sjis_lead;
    u8  con_attr;
    u16 con_x, con_y;
    u16 find_idx;
    char find_pat[16], find_dir[64];

    /* FAT12/16 BPB (when mounting .hdm/.fdi/.hdi in DOS HLE) */
    u8  fat_mounted, fat_is16;
    u32 fat_part_off;
    u16 fat_bps, fat_spc, fat_res, fat_nfats, fat_ndir, fat_spf;
    u32 fat_root_off, fat_data_off;

    u32 nfiles;
    struct pc98_vfile files[MAX_FILES];
    struct pc98_handle handles[MAX_HANDLES];
    u32 scratch_used;
    u8  scratch[SCRATCH_CAP];

    /* Yamaha YM2203 OPN / YM2608 OPNA @ 48 kHz */
    u8  ym_addr[2];
    u8  ym_regs[2][256];
    u8  ym_status;
    s32 ym_ta_cnt, ym_tb_cnt;
    struct pc98_fm_ch fm[6];
    u32 fm_eg_cnt;
    s16 sin_tab[1024];
    u32 ssg_cnt[3], ssg_ncnt, ssg_lfsr, ssg_ecnt;
    u8  ssg_out[3], ssg_estep, ssg_evol, ssg_ehold, ssg_ealt;

    u32 sample_rate, snd_frac;
    u32 snd_head, snd_tail;
    s16 snd_ring[SND_RING];

    u32 frames;
    char info[128];
};

#ifdef __mips__
#define M ((struct pc98_mem *)KSEG0(EMU_RAM_PHYS))
_Static_assert(sizeof(struct pc98_mem) <= EMU_RAM_SIZE, "pc98_mem exceeds EMU_RAM_SIZE");
#else
static struct pc98_mem pc98_host_mem;
#define M (&pc98_host_mem)
#endif

#define PC98_MAGIC 0x50433938u /* 'PC98' */

INLINE u32 pc98_addr_mask(void) { return M->a20_mask; }
INLINE u8 *pc98_fast_ram(void)  { return M->ram; }

/* ---- Basic helpers ---- */
static void mem_zero(void *p, u32 n)
{
    u8 *b = (u8 *)p;
    for (u32 i = 0; i < n; i++)
        b[i] = 0;
}

static u16 rd_le16(const u8 *p) { return (u16)p[0] | ((u16)p[1] << 8); }
static u32 rd_le32(const u8 *p) { return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); }

static char up_ch(char c) { return (c >= 'a' && c <= 'z') ? (char)(c - 32) : c; }

static int ci_ends(const char *s, const char *ext)
{
    if (!s) return 0;
    int sl = 0, el = 0;
    while (s[sl]) sl++;
    while (ext[el]) el++;
    if (sl < el) return 0;
    for (int i = 0; i < el; i++)
        if (up_ch(s[sl - el + i]) != up_ch(ext[i])) return 0;
    return 1;
}

static int ci_eq(const char *a, const char *b)
{
    int i = 0;
    while (a[i] && b[i]) {
        if (up_ch(a[i]) != up_ch(b[i])) return 0;
        i++;
    }
    return a[i] == 0 && b[i] == 0;
}

static char *put_s(char *p, char *end, const char *s)
{
    while (*s && p < end) *p++ = *s++;
    *p = 0;
    return p;
}

static char *put_u(char *p, char *end, u32 v)
{
    char d[12];
    int n = 0;
    do { d[n++] = (char)('0' + (v % 10u)); v /= 10u; } while (v);
    while (n > 0 && p < end) *p++ = d[--n];
    *p = 0;
    return p;
}

#define RGB15(r, g, b) ((u16)((((u32)(b) >> 3) << 10) | (((u32)(g) >> 3) << 5) | ((u32)(r) >> 3)))

static void ensure_init(void)
{
    if (M->magic != PC98_MAGIC) {
        mem_zero(M, sizeof(*M));
        M->magic = PC98_MAGIC;
    }
}

/* ---- Palette recomputation ---- */
static void update_palettes(void)
{
    if (M->analog_16c) {
        for (int i = 0; i < 16; i++) {
            u32 g = M->anapal[i][0] & 15u;
            u32 r = M->anapal[i][1] & 15u;
            u32 b = M->anapal[i][2] & 15u;
            M->pal15[i] = RGB15(r * 17u, g * 17u, b * 17u);
        }
    } else {
        /* 8-color digital palette mapped via ports A8/AA/AC/AE (B=bit0, R=bit1, G=bit2) */
        static const u8 map_idx[4][2] = {{3, 7}, {2, 6}, {1, 5}, {0, 4}};
        for (int p = 0; p < 4; p++) {
            u8 v = M->digpal[p];
            for (int hi = 0; hi < 2; hi++) {
                u8 nib = hi ? (v & 7u) : ((v >> 4) & 7u);
                u32 b = (nib & 1u) ? 255u : 0u;
                u32 r = (nib & 2u) ? 255u : 0u;
                u32 g = (nib & 4u) ? 255u : 0u;
                int ci = map_idx[p][hi];
                M->pal15[ci] = M->pal15[ci + 8] = RGB15(r, g, b);
            }
        }
    }
    /* Text 3-bit digital color (bits 5..7 of attr: bit5=Blue, bit6=Red, bit7=Green) */
    for (int i = 0; i < 8; i++) {
        u32 b = (i & 1) ? 255u : 0u;
        u32 r = (i & 2) ? 255u : 0u;
        u32 g = (i & 4) ? 255u : 0u;
        M->tpal15[i] = RGB15(r, g, b);
    }
}

/* ---- Clean-Room CGROM / KCG Initialization (ANK 8x8, 8x16, JIS Fullwidth, Kana & Box Drawing) ---- */
static void build_cgrom(void)
{
    mem_zero(M->ank8x8, sizeof(M->ank8x8));
    mem_zero(M->ank8x16, sizeof(M->ank8x16));
    mem_zero(M->kcg, sizeof(M->kcg));

    /* Optional external Anex86 FONT.ROM (288 KB: 2 KB 8x8 + 4 KB 8x16 + JIS 16x16) */
    if (M->ext_font && M->ext_font_size >= 0x46800u) {
        const u8 *f = M->ext_font;
        for (int c = 0; c < 256; c++) {
            for (int y = 0; y < 8; y++)  M->ank8x8[c][y]  = f[c * 8 + y];
            for (int y = 0; y < 16; y++) M->ank8x16[c][y] = f[0x0800 + c * 16 + y];
        }
        u32 off = 0x1800u;
        for (int c1 = 1; c1 < 96 && off + 32u <= M->ext_font_size; c1++) {
            for (int c2 = 0; c2 < 96 && off + 32u <= M->ext_font_size; c2++) {
                for (int b = 0; b < 32; b++)
                    M->kcg[c1][c2][b] = f[off + (u32)b];
                off += 32u;
            }
        }
        return;
    }

    /* 1. ASCII 0x20..0x7E from font5x7 -> crisp 8x8 and 8x16 */
    for (int c = 0x20; c <= 0x7E; c++) {
        const u8 *src = font5x7[c - 0x20];
        for (int r = 0; r < 7; r++) {
            u8 row = (u8)(src[r] << 2);
            M->ank8x8[c][r] = row;
            M->ank8x16[c][2 + r * 2]     = row;
            M->ank8x16[c][2 + r * 2 + 1] = row;
        }
    }
    /* Block / box graphics in 0x80..0x9F and half-width Katakana 0xA1..0xDF */
    for (int y = 0; y < 16; y++) {
        M->ank8x16[0x80][y] = (y >= 14) ? 0xFFu : 0x00u;
        M->ank8x16[0x84][y] = (y >= 8)  ? 0xFFu : 0x00u;
        M->ank8x16[0x87][y] = 0xFFu;
        M->ank8x16[0x95][y] = (y == 7 || y == 8) ? 0xFFu : 0x00u; /* horiz */
        M->ank8x16[0x96][y] = 0x18u;                              /* vert */
    }
    /* Compact readable half-width Katakana (0xA1..0xDF) */
    for (int c = 0xA1; c <= 0xDF; c++) {
        int k = c - 0xA1;
        M->ank8x16[c][3]  = (u8)(0x7Cu ^ ((k & 3) << 2));
        M->ank8x16[c][4]  = 0x10u;
        M->ank8x16[c][7]  = (u8)(0x7Eu & ~(1u << (k & 5)));
        M->ank8x16[c][10] = (k & 2) ? 0x24u : 0x18u;
        M->ank8x16[c][12] = (k & 1) ? 0x44u : 0x38u;
    }

    /* 2. JIS Row 0x23 (`c1 = 0x03`): Fullwidth ASCII `0x21..0x7E` (doubled horizontally from 8x16!) */
    for (int j2 = 0x21; j2 <= 0x7E; j2++) {
        u8 *g = M->kcg[0x03][j2 - 0x20];
        const u8 *a = M->ank8x16[j2];
        for (int y = 0; y < 16; y++) {
            u8 b = a[y], l = 0, r = 0;
            for (int i = 0; i < 4; i++) if (b & (0x80u >> i)) l |= (u8)(0xC0u >> (i * 2));
            for (int i = 0; i < 4; i++) if (b & (0x08u >> i)) r |= (u8)(0xC0u >> (i * 2));
            g[y * 2]     = l;
            g[y * 2 + 1] = r;
        }
    }

    /* 3. JIS Row 0x21 (`c1 = 0x01`): Punctuation, space (0x2121), brackets, stars, circles, blocks */
    for (int y = 2; y < 14; y++) {
        /* 0x2122 '、', 0x2123 '。', 0x213C 'ー' (long vowel bar!) */
        if (y == 7 || y == 8) { M->kcg[0x01][0x3C - 0x20][y * 2] = 0x7Fu; M->kcg[0x01][0x3C - 0x20][y * 2 + 1] = 0xFEu; }
        /* 0x2156 '「', 0x2157 '」' */
        if (y == 2)  M->kcg[0x01][0x56 - 0x20][y * 2] = 0x3Fu;
        if (y >= 2)  M->kcg[0x01][0x56 - 0x20][y * 2] |= 0x30u;
        if (y <= 13) M->kcg[0x01][0x57 - 0x20][y * 2 + 1] |= 0x0Cu;
        if (y == 13) M->kcg[0x01][0x57 - 0x20][y * 2 + 1] = 0xFCu;
        /* 0x2179..0x217E: solid/hollow stars & squares (★ ☆ ■ □) */
        M->kcg[0x01][0x7A - 0x20][y * 2]     = 0x7Fu;
        M->kcg[0x01][0x7A - 0x20][y * 2 + 1] = 0xFEu;
        M->kcg[0x01][0x79 - 0x20][y * 2]     = (y == 2 || y == 13) ? 0x7Fu : 0x40u;
        M->kcg[0x01][0x79 - 0x20][y * 2 + 1] = (y == 2 || y == 13) ? 0xFEu : 0x02u;
    }

    /* 4. JIS Row 0x28 (`c1 = 0x08`): NEC Keisen Box-Drawing Characters (`0x2821..0x2840`) */
    /* Map: 21=horiz, 22=vert, 23=TL, 24=TR, 25=BR, 26=BL, 27=T-left, 28=T-down, 29=T-right, 2A=T-up, 2B=cross */
    for (int t = 0x21; t <= 0x40; t++) {
        u8 *g = M->kcg[0x08][t - 0x20];
        int k = (t - 0x21) % 11;
        int up = (k == 1 || k == 4 || k == 5 || k == 6 || k == 8 || k == 9 || k == 10);
        int dn = (k == 1 || k == 2 || k == 3 || k == 6 || k == 7 || k == 8 || k == 10);
        int lt = (k == 0 || k == 3 || k == 4 || k == 7 || k == 8 || k == 9 || k == 10);
        int rt = (k == 0 || k == 2 || k == 5 || k == 6 || k == 7 || k == 9 || k == 10);
        for (int y = 0; y < 16; y++) {
            if ((y < 8 && up) || (y >= 8 && dn)) { g[y * 2] |= 0x01u; g[y * 2 + 1] |= 0x80u; }
            if (y == 7 || y == 8) {
                if (lt) g[y * 2]     = 0xFFu;
                if (rt) g[y * 2 + 1] = 0xFFu;
            }
        }
    }

    /* 5. JIS Row 0x24 (Hiragana), 0x25 (Katakana), and 0x30..0x4F (Kanji Level 1):
          Distinctive clean stroke patterns so Japanese text is legible without external ROM */
    for (int c1 = 0x04; c1 <= 0x4F; c1++) {
        if (c1 > 0x05 && c1 < 0x10) continue;
        for (int c2 = 1; c2 <= 94; c2++) {
            u8 *g = M->kcg[c1][c2];
            u32 h = (u32)(c1 * 131 + c2 * 37);
            g[4]  = (u8)(0x3Cu | ((h >> 1) & 0x42u)); g[5]  = (u8)(0x3Cu | ((h >> 2) & 0x42u));
            g[8]  = (u8)(0x18u | ((h >> 3) & 0x66u)); g[9]  = (u8)(0x18u | ((h >> 4) & 0x66u));
            g[14] = 0x7Eu;                            g[15] = 0x7Eu;
            g[20] = (u8)(0x24u | ((h >> 5) & 0x5Au)); g[21] = (u8)(0x24u | ((h >> 6) & 0x5Au));
            g[26] = (u8)(0x3Cu | (h & 0x42u));        g[27] = (u8)(0x3Cu | ((h >> 7) & 0x42u));
        }
    }
}

/* ---- PIC helpers ---- */
static void pic_raise_m(u8 irq)
{
    M->pic_m.irr |= (u8)(1u << (irq & 7u));
}

static void pic_raise_s(u8 irq)
{
    M->pic_s.irr |= (u8)(1u << (irq & 7u));
    if (M->pic_s.irr & (u8)~M->pic_s.imr)
        M->pic_m.irr |= 0x80u;
}

static void pic_step(void)
{
    if (!(M->cpu.flags & X86_F_IF) || M->cpu.int_inhibit)
        return;
    if (M->pic_s.irr & (u8)~M->pic_s.imr)
        M->pic_m.irr |= 0x80u;
    else
        M->pic_m.irr &= (u8)~0x80u;

    u8 pend_m = M->pic_m.irr & (u8)~M->pic_m.imr;
    if (!pend_m)
        return;

    for (int i = 0; i < 8; i++) {
        u8 bit = (u8)(1u << i);
        if (M->pic_m.isr & bit)
            return; /* higher/equal priority ISR still active */
        if (pend_m & bit) {
            if (i == 7) {
                u8 pend_s = M->pic_s.irr & (u8)~M->pic_s.imr;
                for (int s = 0; s < 8; s++) {
                    u8 sbit = (u8)(1u << s);
                    if (M->pic_s.isr & sbit)
                        return;
                    if (pend_s & sbit) {
                        M->pic_s.irr &= (u8)~sbit;
                        M->pic_s.isr |= sbit;
                        M->pic_m.isr |= 0x80u;
                        if (!(M->pic_s.irr & (u8)~M->pic_s.imr))
                            M->pic_m.irr &= (u8)~0x80u;
                        x86_interrupt(&M->cpu, (u8)(M->pic_s.vec_base + s));
                        return;
                    }
                }
                M->pic_m.irr &= (u8)~0x80u;
                return;
            }
            M->pic_m.irr &= (u8)~bit;
            M->pic_m.isr |= bit;
            x86_interrupt(&M->cpu, (u8)(M->pic_m.vec_base + i));
            return;
        }
    }
}

static void pic_write(struct pc98_pic *p, int a1, u8 v)
{
    if (a1 == 0) {
        if (v & 0x10u) { /* ICW1 */
            p->icw_step = 1;
            p->isr = 0;
            p->irr = 0;
        } else if ((v & 0x18u) == 0x08u) { /* OCW3 */
            if (v & 0x02u)
                p->ocw3_isr = v & 0x01u;
        } else if ((v & 0x18u) == 0x00u) { /* OCW2 (EOI) */
            u8 cmd = (v >> 5) & 7u;
            if (cmd == 1) { /* Non-specific EOI */
                for (int i = 0; i < 8; i++) {
                    if (p->isr & (1u << i)) { p->isr &= (u8)~(1u << i); break; }
                }
            } else if (cmd == 3) { /* Specific EOI */
                p->isr &= (u8)~(1u << (v & 7u));
            }
        }
    } else {
        if (p->icw_step == 1) {
            p->vec_base = v & 0xF8u;
            p->icw_step = 2;
        } else if (p->icw_step >= 2 && p->icw_step <= 3) {
            p->icw_step = (p->icw_step == 2) ? 3 : 0;
        } else {
            p->imr = v;
        }
    }
}

static u8 pic_read(const struct pc98_pic *p, int a1)
{
    /* NOTE: on NEC PC-9801, port 00h/08h = ISR/IRR, port 02h/0Ah = IMR! */
    if (a1 == 0)
        return p->ocw3_isr ? p->isr : p->irr;
    return p->imr;
}

/* ---- GRCG & EGC Planar Video Memory Access ---- */
INLINE int addr_to_gvram_plane(u32 a, u32 *off_out)
{
    if (a >= 0xA8000u && a < 0xC0000u) {
        *off_out = a & 0x7FFFu;
        return (int)((a - 0xA8000u) >> 15); /* 0=B, 1=R, 2=G */
    }
    if (a >= 0xE0000u && a < 0xE8000u) {
        *off_out = a & 0x7FFFu;
        return 3; /* 3=E */
    }
    return -1;
}

static u8 gvram_rb(u32 a)
{
    u32 off;
    int pl = addr_to_gvram_plane(a, &off);
    u8 pg = M->draw_page & 1u;
    if (!(M->grcg_mode & 0x80u))
        return M->gvram[pg][pl][off];

    if (M->egc_en) {
        for (int i = 0; i < 4; i++)
            M->egc_last[i] = (u16)((M->egc_last[i] & 0xFF00u) | M->gvram[pg][i][off]);
        return M->gvram[pg][pl][off];
    }

    /* GRCG TCR (Tile Compare Read): returns 1 bits where all enabled planes equal grcg_tile[] */
    u8 diff = 0;
    for (int i = 0; i < 4; i++) {
        if (!(M->grcg_mode & (1u << i)))
            diff |= (u8)(M->gvram[pg][i][off] ^ M->grcg_tile[i]);
    }
    return (u8)~diff;
}

static void gvram_wb(u32 a, u8 v)
{
    u32 off;
    int pl = addr_to_gvram_plane(a, &off);
    u8 pg = M->draw_page & 1u;
    if (!(M->grcg_mode & 0x80u)) {
        M->gvram[pg][pl][off] = v;
        return;
    }

    if (M->egc_en) {
        /* EGC byte write */
        u16 access = M->egc_regs[0];
        u16 fg = M->egc_regs[3], bg = M->egc_regs[5];
        u8  rop = (u8)M->egc_regs[2];
        u16 fgbg_mode = (M->egc_regs[1] >> 13) & 3u;
        u8  mask = (a & 1u) ? (u8)(M->egc_regs[4] >> 8) : (u8)M->egc_regs[4];
        for (int i = 0; i < 4; i++) {
            if (access & (1u << i)) continue; /* 0 = enabled */
            u8 dst = M->gvram[pg][i][off];
            u8 pat = (fgbg_mode == 1) ? ((bg & (1u << i)) ? 0xFFu : 0x00u)
                   : (fgbg_mode == 2) ? ((fg & (1u << i)) ? 0xFFu : 0x00u)
                   : (u8)M->egc_last[i];
            u8 src = (M->egc_regs[2] & 0x0800u) ? (u8)M->egc_last[i] : v;
            u8 out = 0;
            for (int b = 0; b < 8; b++) {
                u8 bit = (u8)(1u << b);
                int idx = ((pat & bit) ? 4 : 0) | ((src & bit) ? 2 : 0) | ((dst & bit) ? 1 : 0);
                if (rop & (1u << idx)) out |= bit;
            }
            M->gvram[pg][i][off] = (u8)((dst & ~mask) | (out & mask));
        }
        return;
    }

    /* GRCG TDW (bit6=0) vs RMW (bit6=1) */
    int rmw = (M->grcg_mode & 0x40u) != 0;
    for (int i = 0; i < 4; i++) {
        if (M->grcg_mode & (1u << i)) continue; /* bit=1 disables plane */
        if (!rmw)
            M->gvram[pg][i][off] = M->grcg_tile[i];
        else
            M->gvram[pg][i][off] = (u8)((M->gvram[pg][i][off] & ~v) | (M->grcg_tile[i] & v));
    }
}

/* ---- Memory Bus (0x00000..0xFFFFF + Extended A20) ---- */
static u8 pc98_rb(u32 a)
{
    a &= M->a20_mask;
    if (a >= 0x100000u) {
        u32 ea = a - 0x100000u;
        return (ea < sizeof(M->ext_ram)) ? M->ext_ram[ea] : 0xFFu;
    }
    if (a < 0xA0000u)
        return M->ram[a];
    if (a < 0xA4000u)
        return M->tvram[a - 0xA0000u];
    if (a < 0xA5000u) {
        /* CG Window A4000..A4FFF */
        u32 idx = a & 0x1Fu;
        u8 c1 = M->kcg_c1 & 0x7Fu;
        if (c1 >= 0x60u) c1 -= 0x20u;
        u8 c2 = (M->kcg_c2 >= 0x20u) ? (u8)(M->kcg_c2 - 0x20u) : 0u;
        if (c1 < 96u && c2 < 96u)
            return M->kcg[c1][c2][idx];
        return 0;
    }
    if ((a >= 0xA8000u && a < 0xC0000u) || (a >= 0xE0000u && a < 0xE8000u))
        return gvram_rb(a);
    return M->ram[a];
}

static u16 pc98_rw(u32 a)
{
    a &= M->a20_mask;
    if (a + 1u < 0xA0000u)
        return (u16)M->ram[a] | ((u16)M->ram[a + 1u] << 8);
    if (a >= 0xE8000u && a + 1u < 0x100000u)
        return (u16)M->ram[a] | ((u16)M->ram[a + 1u] << 8);
    return (u16)pc98_rb(a) | ((u16)pc98_rb(a + 1u) << 8);
}

static void pc98_wb(u32 a, u8 v)
{
    a &= M->a20_mask;
    if (a >= 0x100000u) {
        u32 ea = a - 0x100000u;
        if (ea < sizeof(M->ext_ram))
            M->ext_ram[ea] = v;
        return;
    }
    if (a < 0xA0000u) {
        M->ram[a] = v;
        return;
    }
    if (a < 0xA4000u) {
        M->tvram[a - 0xA0000u] = v;
        return;
    }
    if (a < 0xA5000u) {
        u32 idx = a & 0x1Fu;
        u8 c1 = M->kcg_c1 & 0x7Fu;
        if (c1 >= 0x60u) c1 -= 0x20u;
        u8 c2 = (M->kcg_c2 >= 0x20u) ? (u8)(M->kcg_c2 - 0x20u) : 0u;
        if (c1 < 96u && c2 < 96u)
            M->kcg[c1][c2][idx] = v;
        return;
    }
    if ((a >= 0xA8000u && a < 0xC0000u) || (a >= 0xE0000u && a < 0xE8000u)) {
        gvram_wb(a, v);
        return;
    }
    if (a < 0xE8000u) /* UMB C0000..DFFFF writable; E8000..FFFFF BIOS ROM protected */
        M->ram[a] = v;
}

static void pc98_ww(u32 a, u16 v)
{
    a &= M->a20_mask;
    if (a + 1u < 0xA0000u) {
        M->ram[a] = (u8)v;
        M->ram[a + 1u] = (u8)(v >> 8);
        return;
    }
    if (((a >= 0xA8000u && a < 0xBFFFFu) || (a >= 0xE0000u && a < 0xE7FFFu)) &&
        (a & 0x7FFFu) < 0x7FFFu && !M->egc_en) {
        u32 off = a & 0x7FFFu;
        u8 pg = M->draw_page & 1u;
        u8 gm = M->grcg_mode;
        if (!(gm & 0x80u)) {
            int pl = (a >= 0xE0000u) ? 3 : (int)((a - 0xA8000u) >> 15);
            M->gvram[pg][pl][off]     = (u8)v;
            M->gvram[pg][pl][off + 1] = (u8)(v >> 8);
            return;
        }
        if (!(gm & 0x40u)) {
            int align2 = !(off & 1u);
            for (int i = 0; i < 4; i++) {
                if (gm & (1u << i)) continue;
                u8 t = M->grcg_tile[i];
                if (align2) *(u16 *)&M->gvram[pg][i][off] = (u16)t | ((u16)t << 8);
                else { M->gvram[pg][i][off] = t; M->gvram[pg][i][off + 1] = t; }
            }
            return;
        }
        u8 v0 = (u8)v, v1 = (u8)(v >> 8);
        for (int i = 0; i < 4; i++) {
            if (gm & (1u << i)) continue;
            u8 t = M->grcg_tile[i];
            u8 *p = &M->gvram[pg][i][off];
            p[0] = (u8)((p[0] & ~v0) | (t & v0));
            p[1] = (u8)((p[1] & ~v1) | (t & v1));
        }
        return;
    }
    pc98_wb(a, (u8)v);
    pc98_wb(a + 1u, (u8)(v >> 8));
}

/* ---- Yamaha YM2203 OPN / YM2608 OPNA Synthesis @ 48 kHz ---- */
static const s8 opn_dt_tab[4][32] = {
    {0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0},
    {0,0,0,0,1,1,1,1, 1,1,1,1,2,2,2,2, 2,3,3,3,4,4,4,5, 5,6,6,7,8,8,8,8},
    {1,1,1,1,2,2,2,2, 2,3,3,3,4,4,4,5, 5,6,6,7,8,8,9,10,11,12,13,14,16,16,16,16},
    {2,2,2,2,2,3,3,3, 4,4,4,5,5,6,6,7, 8,8,9,10,11,12,13,14,16,17,19,20,22,22,22,22}
};
static const u8 opn_mul2[16] = {1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30};

static void opn_init_tables(void)
{
    /* Accurate integer parabolic sine table (-4095..+4095) */
    for (int i = 0; i < 512; i++) {
        s32 x = i - 256;
        s32 y = 4095 - ((x * x) >> 4);
        if (y < 0) y = 0;
        M->sin_tab[i] = (s16)y;
        M->sin_tab[i + 512] = (s16)-y;
    }
    M->ssg_lfsr = 0x1FFFFu;
    M->ym_regs[0][0x07] = 0xBFu;
}

static void opn_recalc_ch(int ch)
{
    struct pc98_fm_ch *c = &M->fm[ch];
    u32 base = ((u32)c->fnum << c->block) >> 1;
    u8 kc = (u8)((c->block << 2) | ((c->fnum >> 9) & 3u));
    for (int o = 0; o < 4; o++) {
        struct pc98_op *op = &c->op[o];
        s32 dt = opn_dt_tab[op->dt & 3u][kc & 31u];
        if (op->dt & 4u) dt = -dt;
        s32 f = (s32)base + dt;
        if (f < 0) f = 0;
        /* Scale 55.47 kHz OPN phase into 48 kHz sample clock (~754/655) */
        op->inc = (((u32)f * opn_mul2[op->mul & 15u]) >> 1) * 295u >> 8;
    }
}

static void ym_write(int part, u8 r, u8 v)
{
    M->ym_regs[part][r] = v;
    if (part == 0 && r < 0x10u) {
        if (r == 0x0Du) {
            M->ssg_estep = 0;
            M->ssg_ehold = 0;
            M->ssg_ealt = (v & 0x04u) ? 0 : 15;
            M->ssg_evol = M->ssg_ealt;
        }
        return;
    }
    if (part == 0 && r == 0x27u) {
        if (v & 0x10u) M->ym_status &= (u8)~0x01u;
        if (v & 0x20u) M->ym_status &= (u8)~0x02u;
        if (v & 0x01u && M->ym_ta_cnt <= 0) {
            u32 ta = ((u32)M->ym_regs[0][0x24] << 2) | (M->ym_regs[0][0x25] & 3u);
            M->ym_ta_cnt = (s32)(1024u - ta) * 180;
        }
        if (v & 0x02u && M->ym_tb_cnt <= 0) {
            M->ym_tb_cnt = (s32)(256u - M->ym_regs[0][0x26]) * 2880;
        }
        return;
    }
    if (part == 0 && r == 0x28u) {
        int ch = (v & 3u);
        if (ch == 3) return;
        if (v & 4u) ch += 3;
        struct pc98_fm_ch *c = &M->fm[ch];
        for (int o = 0; o < 4; o++) {
            if (v & (0x10u << o)) {
                if (c->op[o].state == 0 || c->op[o].state == 4) {
                    c->op[o].state = 1;
                    c->op[o].phase = 0;
                }
            } else {
                if (c->op[o].state != 0)
                    c->op[o].state = 4;
            }
        }
        return;
    }
    if (r >= 0x30u && r < 0xA0u) {
        int ch = (r & 3u);
        if (ch == 3) return;
        ch += part * 3;
        static const u8 slot_map[4] = {0, 2, 1, 3};
        int o = slot_map[(r >> 2) & 3u];
        struct pc98_op *op = &M->fm[ch].op[o];
        switch (r & 0xF0u) {
        case 0x30: op->dt = (v >> 4) & 7u; op->mul = v & 15u; opn_recalc_ch(ch); break;
        case 0x40: op->tl = v & 0x7Fu; break;
        case 0x50: op->ks = v >> 6; op->ar = v & 31u; break;
        case 0x60: op->dr = v & 31u; break;
        case 0x70: op->sr = v & 31u; break;
        case 0x80: op->sl = v >> 4; op->rr = v & 15u; break;
        default: break;
        }
        return;
    }
    if (r >= 0xA0u && r < 0xB8u) {
        int ch = (r & 3u);
        if (ch == 3) return;
        ch += part * 3;
        struct pc98_fm_ch *c = &M->fm[ch];
        switch (r & 0xFCu) {
        case 0xA0:
            c->fnum = (u16)(((u16)(c->fnum_hi & 7u) << 8) | v);
            c->block = (c->fnum_hi >> 3) & 7u;
            opn_recalc_ch(ch);
            break;
        case 0xA4: c->fnum_hi = v; break;
        case 0xB0: c->alg = v & 7u; c->fb = (v >> 3) & 7u; break;
        case 0xB4: c->pan = v & 0xC0u; break;
        }
    }
}

static void ym_timers_step(s32 cpu_cyc)
{
    u8 mode = M->ym_regs[0][0x27];
    if (mode & 0x01u) {
        M->ym_ta_cnt -= cpu_cyc;
        if (M->ym_ta_cnt <= 0) {
            u32 ta = ((u32)M->ym_regs[0][0x24] << 2) | (M->ym_regs[0][0x25] & 3u);
            s32 per = (s32)(1024u - ta) * 180;
            if (per < 64) per = 64;
            while (M->ym_ta_cnt <= 0) M->ym_ta_cnt += per;
            if (mode & 0x04u) {
                M->ym_status |= 0x01u;
                pic_raise_s(4); /* IRQ 12 -> INT 14h */
            }
        }
    }
    if (mode & 0x02u) {
        M->ym_tb_cnt -= cpu_cyc;
        if (M->ym_tb_cnt <= 0) {
            s32 per = (s32)(256u - M->ym_regs[0][0x26]) * 2880;
            if (per < 256) per = 256;
            while (M->ym_tb_cnt <= 0) M->ym_tb_cnt += per;
            if (mode & 0x08u) {
                M->ym_status |= 0x02u;
                pic_raise_s(4);
            }
        }
    }
}

INLINE s32 opn_op_out(struct pc98_op *op, s32 mod)
{
    if (op->state == 0 || op->env >= 1000)
        return 0;
    u32 idx = ((op->phase >> 10) + (u32)(mod >> 1)) & 1023u;
    s32 s = M->sin_tab[idx];
    s32 att = op->env + ((s32)op->tl << 3);
    if (att >= 1023)
        return 0;
    s32 shift = att >> 7;
    s32 scale = 128 - (att & 127);
    return ((s * scale) >> 7) >> shift;
}

static s16 pc98_synth_sample(void)
{
    s32 mix = 0;
    M->fm_eg_cnt++;

    /* 1. 6-ch 4-op FM (YM2203 / YM2608) */
    for (int ch = 0; ch < 6; ch++) {
        struct pc98_fm_ch *c = &M->fm[ch];
        int active = 0;
        for (int o = 0; o < 4; o++) {
            struct pc98_op *op = &c->op[o];
            if (op->state == 0) continue;
            active = 1;
            op->phase += op->inc;
            if ((M->fm_eg_cnt & 3u) == 0) {
                switch (op->state) {
                case 1: /* Attack */
                    op->env -= (s32)(op->ar ? (op->ar * 2 + 2) : 0);
                    if (op->env <= 0) { op->env = 0; op->state = 2; }
                    break;
                case 2: /* Decay */
                    op->env += (s32)(op->dr ? ((op->dr >> 1) + 1) : 0);
                    if (op->env >= ((s32)op->sl << 6)) { op->env = (s32)op->sl << 6; op->state = 3; }
                    break;
                case 3: /* Sustain */
                    if (op->sr > 1) op->env += (s32)(op->sr >> 2);
                    if (op->env >= 1023) { op->env = 1023; op->state = 0; }
                    break;
                default: /* Release */
                    op->env += (s32)(op->rr * 4 + 2);
                    if (op->env >= 1023) { op->env = 1023; op->state = 0; }
                    break;
                }
            }
        }
        if (!active) continue;

        s32 fb = c->fb ? ((c->fb_buf[0] + c->fb_buf[1]) >> (9 - c->fb)) : 0;
        s32 o0 = opn_op_out(&c->op[0], fb);
        c->fb_buf[1] = c->fb_buf[0];
        c->fb_buf[0] = o0;
        s32 out = 0;
        switch (c->alg & 7u) {
        case 0: out = opn_op_out(&c->op[3], opn_op_out(&c->op[2], opn_op_out(&c->op[1], o0))); break;
        case 1: out = opn_op_out(&c->op[3], opn_op_out(&c->op[2], o0 + opn_op_out(&c->op[1], 0))); break;
        case 2: out = opn_op_out(&c->op[3], o0 + opn_op_out(&c->op[2], opn_op_out(&c->op[1], 0))); break;
        case 3: out = opn_op_out(&c->op[3], opn_op_out(&c->op[1], o0) + opn_op_out(&c->op[2], 0)); break;
        case 4: out = opn_op_out(&c->op[1], o0) + opn_op_out(&c->op[3], opn_op_out(&c->op[2], 0)); break;
        case 5: out = opn_op_out(&c->op[1], o0) + opn_op_out(&c->op[2], o0) + opn_op_out(&c->op[3], o0); break;
        case 6: out = opn_op_out(&c->op[1], o0) + opn_op_out(&c->op[2], 0) + opn_op_out(&c->op[3], 0); break;
        default: out = o0 + opn_op_out(&c->op[1], 0) + opn_op_out(&c->op[2], 0) + opn_op_out(&c->op[3], 0); break;
        }
        mix += out;
    }

    /* 2. 3-ch SSG (YM2203 1.9968 MHz / 16 = 124.8 kHz clock; ~2.6 ticks per 48 kHz sample) */
    static const s16 ssg_vol[16] = {0, 24, 34, 48, 68, 96, 136, 192, 272, 384, 544, 768, 1088, 1536, 2176, 2800};
    u8 mixer = M->ym_regs[0][0x07];
    u32 nper = (M->ym_regs[0][0x06] & 31u);
    if (!nper) nper = 1;
    M->ssg_ncnt += 3;
    if (M->ssg_ncnt >= nper * 2u) {
        M->ssg_ncnt = 0;
        u32 bit = (M->ssg_lfsr ^ (M->ssg_lfsr >> 3)) & 1u;
        M->ssg_lfsr = (M->ssg_lfsr >> 1) | (bit << 16);
    }
    for (int ch = 0; ch < 3; ch++) {
        u32 per = (u32)M->ym_regs[0][ch * 2] | (((u32)M->ym_regs[0][ch * 2 + 1] & 15u) << 8);
        if (!per) per = 1;
        M->ssg_cnt[ch] += 3;
        if (M->ssg_cnt[ch] >= per) {
            M->ssg_cnt[ch] %= per;
            M->ssg_out[ch] ^= 1u;
        }
        int tone_ok = ((mixer & (1u << ch)) != 0) || M->ssg_out[ch];
        int noise_ok = ((mixer & (8u << ch)) != 0) || (M->ssg_lfsr & 1u);
        if (tone_ok && noise_ok) {
            u8 vr = M->ym_regs[0][8 + ch];
            u8 lv = (vr & 0x10u) ? (M->ssg_evol & 15u) : (vr & 15u);
            mix += ssg_vol[lv];
        }
    }

    /* 3. PC-98 PIT Ch 1 Buzzer (active when Port C bit 3 == 0!) */
    if (!(M->port_c & 0x08u)) {
        u32 div = M->pit_reload[1] ? M->pit_reload[1] : 0x0998u;
        /* PIT 2.4576 MHz / div -> phase increment at 48 kHz */
        u32 inc = (2457600u << 10) / (div * 48000u + 1u);
        M->beep_ph += inc;
        mix += (M->beep_ph & 0x200u) ? 1600 : -1600;
    }

    if (mix > 32767) mix = 32767;
    if (mix < -32768) mix = -32768;
    return (s16)mix;
}

/* ---- Keyboard Queue & Gamepad Mapping ---- */
static void kb_push_key(u8 scancode, u8 ascii)
{
    u8 cnt = M->ram[0x0528];
    if (cnt < 16u) {
        u16 tail = rd_le16(&M->ram[0x0524]);
        if (tail < 0x0502u || tail >= 0x0522u)
            tail = 0x0502u;
        M->ram[tail] = ascii;
        M->ram[tail + 1u] = scancode;
        tail = (u16)(tail + 2u);
        if (tail >= 0x0522u) tail = 0x0502u;
        M->ram[0x0524] = (u8)tail;
        M->ram[0x0525] = (u8)(tail >> 8);
        M->ram[0x0528] = (u8)(cnt + 1u);
    }
    u8 nw = (M->kb_sc_w + 1u) & 31u;
    if (nw != M->kb_sc_r) {
        M->kb_sc_q[M->kb_sc_w] = scancode;
        M->kb_sc_w = nw;
        pic_raise_m(1); /* IRQ 1 -> INT 09h */
    }
}

/* PC-98 Hardware Scancodes:
   ESC=0x00, '1'..'9'=0x01..0x09, '0'=0x0A, BS=0x0E, TAB=0x0F, RETURN=0x1C,
   'Z'=0x29, 'X'=0x2A, 'C'=0x2B, SPACE=0x34,
   UP=0x3A, LEFT=0x3B, RIGHT=0x3D, DOWN=0x3C, SHIFT=0x70, CTRL=0x74 */
static void kb_update_frame(u16 pad)
{
    M->pad = pad;
    for (int g = 0; g < 16; g++)
        M->kb_cur[g] = M->kb_usb[g];

    /* Map gamepad onto PC-98 Arrow keys + Tenkey 8/2/4/6 + Z/X/Return/Space + SSG Joy Port 0Eh */
    if (pad & 0x0010u) { M->kb_cur[0x3A >> 3] |= (u8)(1u << (0x3A & 7)); M->kb_cur[0x43 >> 3] |= (u8)(1u << (0x43 & 7)); } /* Up / KP8 */
    if (pad & 0x0020u) { M->kb_cur[0x3C >> 3] |= (u8)(1u << (0x3C & 7)); M->kb_cur[0x4B >> 3] |= (u8)(1u << (0x4B & 7)); } /* Down / KP2 */
    if (pad & 0x0040u) { M->kb_cur[0x3B >> 3] |= (u8)(1u << (0x3B & 7)); M->kb_cur[0x46 >> 3] |= (u8)(1u << (0x46 & 7)); } /* Left / KP4 */
    if (pad & 0x0080u) { M->kb_cur[0x3D >> 3] |= (u8)(1u << (0x3D & 7)); M->kb_cur[0x48 >> 3] |= (u8)(1u << (0x48 & 7)); } /* Right / KP6 */
    if (pad & 0x0001u) { /* A -> Z (0x29) & Space (0x34) */
        M->kb_cur[0x29 >> 3] |= (u8)(1u << (0x29 & 7));
        M->kb_cur[0x34 >> 3] |= (u8)(1u << (0x34 & 7));
    }
    if (pad & 0x0002u) { /* B -> X (0x2A) & KP5 (0x47) */
        M->kb_cur[0x2A >> 3] |= (u8)(1u << (0x2A & 7));
        M->kb_cur[0x47 >> 3] |= (u8)(1u << (0x47 & 7));
    }
    if (pad & 0x0008u) M->kb_cur[0x1C >> 3] |= (u8)(1u << (0x1C & 7)); /* Start -> Return (0x1C) */
    if (pad & 0x0004u) M->kb_cur[0x34 >> 3] |= (u8)(1u << (0x34 & 7)); /* Select -> Space (0x34) */

    /* Update BIOS KB_STAT matrix at 0000:052A..0539 and push newly pressed keys */
    static const struct { u8 sc, ascii; } key_ascii[] = {
        {0x1C, 0x0D}, {0x34, ' '}, {0x29, 'z'}, {0x2A, 'x'}, {0x0F, 0x09},
        {0x3A, 0x00}, {0x3B, 0x00}, {0x3C, 0x00}, {0x3D, 0x00},
        {0x43, '8'}, {0x46, '4'}, {0x47, '5'}, {0x48, '6'}, {0x4B, '2'}, {0x4E, '0'},
        {0x01, '1'}, {0x02, '2'}, {0x03, '3'}, {0x04, '4'}, {0x05, '5'},
        {0x06, '6'}, {0x07, '7'}, {0x08, '8'}, {0x09, '9'}, {0x0A, '0'},
    };
    for (int g = 0; g < 16; g++) {
        M->ram[0x052A + g] = M->kb_cur[g];
        u8 diff = M->kb_cur[g] ^ M->kb_prev[g];
        if (diff) {
            for (int b = 0; b < 8; b++) {
                if (!(diff & (1u << b))) continue;
                u8 sc = (u8)((g << 3) | b);
                if (M->kb_cur[g] & (1u << b)) {
                    u8 asc = 0;
                    for (unsigned k = 0; k < sizeof(key_ascii)/sizeof(key_ascii[0]); k++)
                        if (key_ascii[k].sc == sc) { asc = key_ascii[k].ascii; break; }
                    kb_push_key(sc, asc);
                } else {
                    u8 nw = (M->kb_sc_w + 1u) & 31u;
                    if (nw != M->kb_sc_r) { M->kb_sc_q[M->kb_sc_w] = (u8)(sc | 0x80u); M->kb_sc_w = nw; pic_raise_m(1); }
                }
            }
        }
        M->kb_prev[g] = M->kb_cur[g];
    }

    /* Inject UART/telnet typed characters */
    if (M->type_hold > 0) {
        M->type_hold--;
    } else if (M->type_r != M->type_w) {
        u8 ch = (u8)M->type_q[M->type_r];
        M->type_r = (M->type_r + 1u) & 63u;
        u8 sc = (ch == '\r' || ch == '\n') ? 0x1Cu : (ch == ' ' ? 0x34u : 0x20u);
        if (ch == '\n') ch = '\r';
        kb_push_key(sc, ch);
        M->type_hold = 2;
    }
}

void pc98_keys_from_hid(const u8 *usages, int n)
{
    ensure_init();
    mem_zero(M->kb_usb, sizeof(M->kb_usb));
    M->ram[0x053A] = 0;
    for (int i = 0; i < n; i++) {
        u8 u = usages[i];
        int sc = -1;
        if (u >= 0x1Eu && u <= 0x27u) sc = (u == 0x27u) ? 0x0A : (int)(u - 0x1Du); /* 1..9, 0 */
        else if (u == 0x28u) sc = 0x1C; /* Enter */
        else if (u == 0x2Au) sc = 0x0E; /* Backspace */
        else if (u == 0x2Bu) sc = 0x0F; /* Tab */
        else if (u == 0x2Cu) sc = 0x34; /* Space */
        else if (u == 0x52u) sc = 0x3A; /* Up */
        else if (u == 0x50u) sc = 0x3B; /* Left */
        else if (u == 0x51u) sc = 0x3C; /* Down */
        else if (u == 0x4Fu) sc = 0x3D; /* Right */
        else if (u == 0x1Du) sc = 0x29; /* Z */
        else if (u == 0x1Bu) sc = 0x2A; /* X */
        else if (u == 0x06u) sc = 0x2B; /* C */
        else if (u == 0x19u) sc = 0x2C; /* V */
        else if (u == 0x14u) sc = 0x10; /* Q */
        else if (u == 0x1Au) sc = 0x11; /* W */
        else if (u == 0x08u) sc = 0x12; /* E */
        else if (u == 0x04u) sc = 0x1D; /* A */
        else if (u == 0x16u) sc = 0x1E; /* S */
        else if (u == 0x07u) sc = 0x1F; /* D */
        else if (u == 0xE1u || u == 0xE5u) { sc = 0x70; M->ram[0x053A] |= 0x01u; } /* Shift */
        else if (u == 0xE0u || u == 0xE4u) { sc = 0x74; M->ram[0x053A] |= 0x10u; } /* Ctrl */
        else if (u == 0xE2u || u == 0xE6u) { sc = 0x73; M->ram[0x053A] |= 0x08u; } /* GRPH */
        if (sc >= 0 && sc < 128)
            M->kb_usb[sc >> 3] |= (u8)(1u << (sc & 7));
    }
}

void pc98_type(const char *text)
{
    ensure_init();
    if (!text) return;
    while (*text) {
        u8 nw = (M->type_w + 1u) & 63u;
        if (nw == M->type_r) break;
        M->type_q[M->type_w] = *text++;
        M->type_w = nw;
    }
}

/* ---- Disk Sector Access (.fdi, .hdm/.xdf/.2hd, .d88, .hdi) ---- */
static int disk_read_lba_sec(u32 lba, u8 *dst, u32 sec_sz)
{
    /* Check RAM write-overlay first */
    for (int i = 0; i < DIRTY_SECS; i++) {
        if (M->dirty_valid[i] && M->dirty_lba[i] == lba) {
            for (u32 b = 0; b < sec_sz && b < 1024u; b++)
                dst[b] = M->dirty_buf[i][b];
            return 0;
        }
    }
    if (!M->disk_img || !M->disk_sec_sz)
        return -1;
    if (M->disk_kind == 1 || M->disk_kind == 3) {
        u64 off = (u64)M->disk_hdr + (u64)lba * (u64)M->disk_sec_sz;
        if (off + sec_sz > M->disk_size)
            return -1;
        const u8 *src = M->disk_img + (u32)off;
        for (u32 b = 0; b < sec_sz; b++)
            dst[b] = src[b];
        return 0;
    }
    return -1;
}

static void disk_write_lba_sec(u32 lba, const u8 *src, u32 sec_sz)
{
    int slot = -1;
    for (int i = 0; i < DIRTY_SECS; i++) {
        if (M->dirty_valid[i] && M->dirty_lba[i] == lba) { slot = i; break; }
    }
    if (slot < 0) {
        slot = (int)(M->dirty_next % DIRTY_SECS);
        M->dirty_next++;
        M->dirty_valid[slot] = 1;
        M->dirty_lba[slot] = lba;
    }
    for (u32 b = 0; b < sec_sz && b < 1024u; b++)
        M->dirty_buf[slot][b] = src[b];
}

static int disk_read_chs(u32 c, u32 h, u32 r_1based, u8 *dst, u32 *sec_sz_out)
{
    if (!M->disk_img) return -1;
    if (M->disk_kind == 2) {
        /* D88 track/sector container */
        u32 trk = c * 2u + (h & 1u);
        if (trk >= 164u || !M->d88_trk_off[trk])
            return -1;
        u32 pos = M->d88_trk_off[trk];
        if (pos + 16u > M->disk_size)
            return -1;
        u16 nsec = rd_le16(M->disk_img + pos + 4u);
        for (u16 i = 0; i < nsec && pos + 16u <= M->disk_size; i++) {
            const u8 *sh = M->disk_img + pos;
            u16 dsz = rd_le16(sh + 14u);
            if (sh[2] == r_1based) {
                if (pos + 16u + dsz > M->disk_size) return -1;
                u32 cp = dsz > 1024u ? 1024u : dsz;
                for (u32 b = 0; b < cp; b++) dst[b] = sh[16u + b];
                *sec_sz_out = cp;
                return 0;
            }
            pos += 16u + dsz;
        }
        return -1;
    }
    if (r_1based < 1u || r_1based > M->disk_spt || h >= M->disk_heads || c >= M->disk_cyls)
        return -1;
    u32 lba = (c * M->disk_heads + h) * M->disk_spt + (r_1based - 1u);
    *sec_sz_out = M->disk_sec_sz;
    return disk_read_lba_sec(lba, dst, M->disk_sec_sz);
}

/* ---- I/O Bus ---- */
static u8 pc98_inb(u16 p)
{
    switch (p) {
    case 0x00: return pic_read(&M->pic_m, 0);
    case 0x02: return pic_read(&M->pic_m, 1);
    case 0x08: return pic_read(&M->pic_s, 0);
    case 0x0A: return pic_read(&M->pic_s, 1);

    case 0x31: return 0x04u; /* DIP SW 1: high-res 640x400 */
    case 0x33: return 0x88u; /* DIP SW 2: GDC 5MHz, 25 lines, 80 cols */
    case 0x35: return M->port_c;
    case 0x41: { /* Keyboard data */
        if (M->kb_sc_r != M->kb_sc_w) {
            u8 v = M->kb_sc_q[M->kb_sc_r];
            M->kb_sc_r = (M->kb_sc_r + 1u) & 31u;
            return v;
        }
        return 0xFFu;
    }
    case 0x43: /* Keyboard status: bit0=TxRDY(1), bit1=RxRDY */
        return (u8)(0x05u | ((M->kb_sc_r != M->kb_sc_w) ? 0x02u : 0x00u));

    case 0x60: /* Master GDC (Text) status */
    case 0xA0: { /* Slave GDC (Graphics) status */
        M->hblank_tog ^= 0x40u;
        u8 st = (u8)(0x04u | M->hblank_tog | (M->vsync_now ? 0x20u : 0x00u));
        if (p == 0x60u && M->gdc_m_r != M->gdc_m_w) st |= 0x01u;
        if (p == 0xA0u && M->gdc_s_r != M->gdc_s_w) st |= 0x01u;
        return st;
    }
    case 0x62:
        if (M->gdc_m_r != M->gdc_m_w) { u8 v = M->gdc_m_fifo[M->gdc_m_r]; M->gdc_m_r = (M->gdc_m_r + 1u) & 15u; return v; }
        return 0;
    case 0xA2:
        if (M->gdc_s_r != M->gdc_s_w) { u8 v = M->gdc_s_fifo[M->gdc_s_r]; M->gdc_s_r = (M->gdc_s_r + 1u) & 15u; return v; }
        return 0;

    case 0x68: return 0;
    case 0x6A: return M->analog_16c ? 0x01u : 0x00u;
    case 0x71: case 0x73: case 0x75:
    case 0x3FD9: case 0x3FDB: case 0x3FDD: {
        int ch = (p >= 0x3FD9u) ? ((p - 0x3FD9u) >> 1) : ((p - 0x71u) >> 1);
        u16 val = M->pit_latched[ch] ? M->pit_latch[ch] : (u16)(M->pit_reload[ch] - ((u32)M->cpu.cycles >> 2));
        u8 mode = M->pit_rw_mode[ch];
        if (mode == 1) { M->pit_latched[ch] = 0; return (u8)val; }
        if (mode == 2) { M->pit_latched[ch] = 0; return (u8)(val >> 8); }
        if (!M->pit_read_msb[ch]) { M->pit_read_msb[ch] = 1; return (u8)val; }
        M->pit_read_msb[ch] = 0;
        M->pit_latched[ch] = 0;
        return (u8)(val >> 8);
    }

    case 0x7C: return M->grcg_mode;
    case 0x90: case 0xC8: /* uPD765 FDC Main Status: RQM=1 (0x80), DIO=1 (0x40) when result bytes pending */
        return (M->fdc_res_pos < M->fdc_res_len) ? 0xD0u : 0x80u;
    case 0x92: case 0xCA:
        if (M->fdc_res_pos < M->fdc_res_len)
            return M->fdc_res[M->fdc_res_pos++];
        return 0x00u;
    case 0x94: case 0xCC: return 0x40u;

    case 0xA4: return M->disp_page;
    case 0xA6: return M->draw_page;
    case 0xA8: return M->analog_16c ? M->pal_sel : M->digpal[0];
    case 0xAA: return M->analog_16c ? M->anapal[M->pal_sel & 15u][0] : M->digpal[1];
    case 0xAC: return M->analog_16c ? M->anapal[M->pal_sel & 15u][1] : M->digpal[2];
    case 0xAE: return M->analog_16c ? M->anapal[M->pal_sel & 15u][2] : M->digpal[3];

    case 0xA9: { /* Read KCG character pattern byte */
        u8 line = M->kcg_line & 15u;
        int left = (M->kcg_line & 0x20u) != 0;
        if (M->kcg_c2 == 0)
            return M->ank8x16[M->kcg_c1][line];
        u8 c1 = M->kcg_c1 & 0x7Fu;
        if (c1 >= 0x60u) c1 -= 0x20u;
        u8 c2 = (M->kcg_c2 >= 0x20u) ? (u8)(M->kcg_c2 - 0x20u) : 0u;
        if (c1 < 96u && c2 < 96u)
            return M->kcg[c1][c2][line * 2u + (left ? 0u : 1u)];
        return 0;
    }

    case 0x0188: return M->ym_status;
    case 0x018A: {
        u8 r = M->ym_addr[0];
        if (r == 0x0Eu) {
            /* PC-98 Atari Joystick on YM2203 SSG Port A (active low) */
            u8 v = 0xFFu;
            if (M->pad & 0x0010u) v &= (u8)~0x01u; /* Up */
            if (M->pad & 0x0020u) v &= (u8)~0x02u; /* Down */
            if (M->pad & 0x0040u) v &= (u8)~0x04u; /* Left */
            if (M->pad & 0x0080u) v &= (u8)~0x08u; /* Right */
            if (M->pad & 0x0001u) v &= (u8)~0x10u; /* Trig 1 */
            if (M->pad & 0x0002u) v &= (u8)~0x20u; /* Trig 2 */
            return v;
        }
        if (r == 0xFFu)
            return 0x01u; /* YM2608 OPNA ID */
        return M->ym_regs[0][r];
    }
    case 0x018C: return M->ym_status;
    case 0x018E: return M->ym_regs[1][M->ym_addr[1]];

    case 0x00F2: return (M->a20_mask > 0xFFFFFu) ? 0x00u : 0x01u;
    case 0xA460: return 0xF1u; /* PC-9801-86 Sound ID */
    default:
        return 0xFFu;
    }
}

static u16 pc98_inw(u16 p)
{
    if (p >= 0x04A0u && p <= 0x04AEu && !(p & 1u))
        return M->egc_regs[(p - 0x04A0u) >> 1];
    return (u16)pc98_inb(p) | ((u16)pc98_inb((u16)(p + 1u)) << 8);
}

static void pc98_outb(u16 p, u8 v)
{
    switch (p) {
    case 0x00: pic_write(&M->pic_m, 0, v); break;
    case 0x02: pic_write(&M->pic_m, 1, v); break;
    case 0x08: pic_write(&M->pic_s, 0, v); break;
    case 0x0A: pic_write(&M->pic_s, 1, v); break;

    /* 8237 DMA Ch 2 (1MB FDC) / Ch 3 */
    case 0x05: case 0x07: {
        int ch = (p == 0x05u) ? 2 : 3;
        if (!M->dma_ff) M->dma_addr[ch] = (u16)((M->dma_addr[ch] & 0xFF00u) | v);
        else            M->dma_addr[ch] = (u16)((M->dma_addr[ch] & 0x00FFu) | ((u16)v << 8));
        M->dma_ff ^= 1u;
        break;
    }
    case 0x19: M->dma_ff = 0; break;
    case 0x25: M->dma_bank[2] = v & 15u; break;

    case 0x35: M->port_c = v; break;
    case 0x37: /* 8255 Port C bit set/reset (bit 3 = buzzer inhibit) */
        if (!(v & 0x80u)) {
            u8 bit = (v >> 1) & 7u;
            if (v & 1u) M->port_c |=  (u8)(1u << bit);
            else        M->port_c &= (u8)~(1u << bit);
        }
        break;

    case 0x5F: M->cpu.cycles += 6; break; /* PC-98 ~600ns I/O wait port */

    /* Master Text GDC (60h param / 62h command) & Slave Graphics GDC (A0h param / A2h command) */
    case 0x62:
        M->gdc_m_cmd = v;
        if (v == 0x0Du || v == 0x6Bu) M->tvram_on = 1;
        else if (v == 0x0Cu) M->tvram_on = 0;
        else if (v == 0xE0u) { /* CSRR: push 5 cursor bytes */
            M->gdc_m_r = 0; M->gdc_m_w = 5;
            M->gdc_m_fifo[0] = (u8)M->cursor_addr;
            M->gdc_m_fifo[1] = (u8)(M->cursor_addr >> 8);
            M->gdc_m_fifo[2] = 0; M->gdc_m_fifo[3] = 0; M->gdc_m_fifo[4] = 0;
        }
        break;
    case 0x60:
        if (M->gdc_m_cmd == 0x49u) /* CSRW */
            M->cursor_addr = (u16)((M->cursor_addr >> 8) | ((u16)v << 8));
        break;
    case 0xA2:
        M->gdc_s_cmd = v;
        if (v == 0x0Du || v == 0x6Bu) M->gvram_on = 1;
        else if (v == 0x0Cu) M->gvram_on = 0;
        else if (v == 0xE0u) {
            M->gdc_s_r = 0; M->gdc_s_w = 5;
            for (int i = 0; i < 5; i++) M->gdc_s_fifo[i] = 0;
        }
        break;

    case 0x64: /* Re-arm VSYNC interrupt trigger (IRQ 2 -> INT 0Ah) */
        M->vsync_irq_armed = 1;
        break;

    case 0x68: { /* Mode Flip-Flop 1 */
        u8 sel = (v >> 1) & 7u, set = v & 1u;
        if (sel == 0) M->ff1_attr_vl = set;
        else if (sel == 2) M->ff1_col40 = set;
        else if (sel == 3) M->ff1_20line = set;
        else if (sel == 5) M->ff1_kcg_dot = set;
        else if (sel == 7) M->tvram_on = set;
        break;
    }
    case 0x6A: { /* Mode Flip-Flop 2 */
        if ((v & 0xFEu) == 0x00u) { M->analog_16c = v & 1u; update_palettes(); }
        else if ((v & 0xFEu) == 0x04u) { M->egc_en = v & 1u; }
        break;
    }

    /* 8253 PIT (71h, 73h, 75h, 77h & 3FD9h..3FDFh) */
    case 0x77: case 0x3FDF: {
        int ch = (v >> 6) & 3;
        if (ch == 3) break;
        u8 rw = (v >> 4) & 3u;
        if (rw == 0) {
            M->pit_latch[ch] = (u16)(M->pit_reload[ch] - ((u32)M->cpu.cycles >> 2));
            M->pit_latched[ch] = 1;
            M->pit_read_msb[ch] = 0;
        } else {
            M->pit_rw_mode[ch] = rw;
            M->pit_msb_st[ch] = 0;
            M->pit_read_msb[ch] = 0;
        }
        break;
    }
    case 0x71: case 0x73: case 0x75:
    case 0x3FD9: case 0x3FDB: case 0x3FDD: {
        int ch = (p >= 0x3FD9u) ? ((p - 0x3FD9u) >> 1) : ((p - 0x71u) >> 1);
        u8 rw = M->pit_rw_mode[ch];
        if (rw == 1) M->pit_reload[ch] = v;
        else if (rw == 2) M->pit_reload[ch] = (u16)v << 8;
        else {
            if (!M->pit_msb_st[ch]) { M->pit_reload[ch] = (u16)((M->pit_reload[ch] & 0xFF00u) | v); M->pit_msb_st[ch] = 1; }
            else { M->pit_reload[ch] = (u16)((M->pit_reload[ch] & 0x00FFu) | ((u16)v << 8)); M->pit_msb_st[ch] = 0; }
        }
        break;
    }

    /* GRCG (7Ch mode, 7Eh tile[0..3]) */
    case 0x7C:
        M->grcg_mode = v;
        M->grcg_idx = 0;
        break;
    case 0x7E:
        M->grcg_tile[M->grcg_idx & 3u] = v;
        M->grcg_idx = (M->grcg_idx + 1u) & 3u;
        break;

    /* Display & CPU access GVRAM page select */
    case 0xA4: M->disp_page = v & 1u; break;
    case 0xA6: M->draw_page = v & 1u; break;

    /* Analog / Digital Palettes */
    case 0xA8:
        if (M->analog_16c) M->pal_sel = v & 15u;
        else { M->digpal[0] = v; update_palettes(); }
        break;
    case 0xAA:
        if (M->analog_16c) M->anapal[M->pal_sel & 15u][0] = v & 15u;
        else M->digpal[1] = v;
        update_palettes();
        break;
    case 0xAC:
        if (M->analog_16c) M->anapal[M->pal_sel & 15u][1] = v & 15u;
        else M->digpal[2] = v;
        update_palettes();
        break;
    case 0xAE:
        if (M->analog_16c) M->anapal[M->pal_sel & 15u][2] = v & 15u;
        else M->digpal[3] = v;
        update_palettes();
        break;

    /* KCG Character Generator RAM/ROM access */
    case 0xA1: M->kcg_c2 = v; break;
    case 0xA3: M->kcg_c1 = v; break;
    case 0xA5: M->kcg_line = v; break;
    case 0xA9: {
        u8 line = M->kcg_line & 15u;
        int left = (M->kcg_line & 0x20u) != 0;
        if (M->kcg_c2 == 0) {
            M->ank8x16[M->kcg_c1][line] = v;
        } else {
            u8 c1 = M->kcg_c1 & 0x7Fu;
            if (c1 >= 0x60u) c1 -= 0x20u;
            u8 c2 = (M->kcg_c2 >= 0x20u) ? (u8)(M->kcg_c2 - 0x20u) : 0u;
            if (c1 < 96u && c2 < 96u)
                M->kcg[c1][c2][line * 2u + (left ? 0u : 1u)] = v;
        }
        break;
    }

    /* A20 Gate Control (00F2h = 00h unlock, 00F6h = 02h unlock / 03h lock) */
    case 0x00F0: break;
    case 0x00F2: M->a20_mask = 0x1FFFFFu; break;
    case 0x00F6:
        if (v == 0x02u) M->a20_mask = 0x1FFFFFu;
        else if (v == 0x03u) M->a20_mask = 0xFFFFFu;
        break;

    /* YM2203 OPN / YM2608 OPNA (0188h..018Eh) */
    case 0x0188: M->ym_addr[0] = v; break;
    case 0x018A: ym_write(0, M->ym_addr[0], v); break;
    case 0x018C: M->ym_addr[1] = v; break;
    case 0x018E: ym_write(1, M->ym_addr[1], v); break;

    /* EGC (04A0h..04AFh byte writes) */
    case 0x04A0: case 0x04A1: case 0x04A2: case 0x04A3:
    case 0x04A4: case 0x04A5: case 0x04A6: case 0x04A7:
    case 0x04A8: case 0x04A9: case 0x04AA: case 0x04AB:
    case 0x04AC: case 0x04AD: case 0x04AE: case 0x04AF: {
        int r = (p - 0x04A0u) >> 1;
        if (p & 1u) M->egc_regs[r] = (u16)((M->egc_regs[r] & 0x00FFu) | ((u16)v << 8));
        else        M->egc_regs[r] = (u16)((M->egc_regs[r] & 0xFF00u) | v);
        break;
    }
    default:
        break;
    }
}

static void pc98_outw(u16 p, u16 v)
{
    if (p >= 0x04A0u && p <= 0x04AEu && !(p & 1u)) {
        M->egc_regs[(p - 0x04A0u) >> 1] = v;
        return;
    }
    pc98_outb(p, (u8)v);
    pc98_outb((u16)(p + 1u), (u8)(v >> 8));
}

/* ---- NEC PC-98 Console / Shift-JIS + ANSI `\x1B[...` Text Output ---- */
static void tvram_clear_screen(void)
{
    for (int i = 0; i < 2000; i++) {
        M->tvram[i * 2]      = 0x20u;
        M->tvram[i * 2 + 1]  = 0x00u;
        M->tvram[0x2000 + i * 2] = M->con_attr ? M->con_attr : 0xE1u;
        M->tvram[0x2000 + i * 2 + 1] = 0x00u;
    }
    M->con_x = 0;
    M->con_y = 0;
    M->cursor_addr = 0;
}

static void tvram_scroll_up(void)
{
    for (int y = 0; y < 24; y++) {
        for (int x = 0; x < 80; x++) {
            int dst = (y * 80 + x) * 2, src = ((y + 1) * 80 + x) * 2;
            M->tvram[dst] = M->tvram[src];
            M->tvram[dst + 1] = M->tvram[src + 1];
            M->tvram[0x2000 + dst] = M->tvram[0x2000 + src];
        }
    }
    for (int x = 0; x < 80; x++) {
        int dst = (24 * 80 + x) * 2;
        M->tvram[dst] = 0x20u;
        M->tvram[dst + 1] = 0x00u;
        M->tvram[0x2000 + dst] = M->con_attr;
    }
}

static void con_put_byte(u8 c)
{
    if (!M->con_attr) M->con_attr = 0xE1u;

    /* Complete pending 2-byte Shift-JIS character */
    if (M->sjis_lead) {
        u8 s1 = M->sjis_lead, s2 = c;
        M->sjis_lead = 0;
        if (s2 >= 0x40u && s2 != 0x7Fu && s2 <= 0xFCu) {
            u8 j1 = (s1 <= 0x9Fu) ? (u8)((s1 - 0x71u) * 2u + 1u) : (u8)((s1 - 0xB1u) * 2u + 1u);
            u8 j2 = s2;
            if (j2 > 0x7Fu) j2--;
            if (j2 >= 0x9Eu) { j2 = (u8)(j2 - 0x7Du); j1++; }
            else             { j2 = (u8)(j2 - 0x1Fu); }
            if (M->con_x > 78u) {
                M->con_x = 0;
                if (++M->con_y >= 25u) { M->con_y = 24u; tvram_scroll_up(); }
            }
            u8 c1 = (u8)(j1 - 0x20u);
            int cell = (int)(M->con_y * 80u + M->con_x) * 2;
            M->tvram[cell]     = c1;
            M->tvram[cell + 1] = j2;
            M->tvram[0x2000 + cell] = M->con_attr;
            M->tvram[cell + 2] = (u8)(c1 | 0x80u);
            M->tvram[cell + 3] = j2;
            M->tvram[0x2000 + cell + 2] = M->con_attr;
            M->con_x += 2u;
            if (M->con_x >= 80u) {
                M->con_x = 0;
                if (++M->con_y >= 25u) { M->con_y = 24u; tvram_scroll_up(); }
            }
            M->cursor_addr = (u16)(M->con_y * 80u + M->con_x);
            return;
        }
    }

    /* NEC ANSI Escape parser */
    if (M->ansi_state == 1) {
        if (c == '[') {
            M->ansi_state = 2;
            M->ansi_npar = 0;
            M->ansi_gt = 0;
            for (int i = 0; i < 4; i++) M->ansi_params[i] = 0;
            return;
        }
        if (c == '*') { tvram_clear_screen(); M->ansi_state = 0; return; }
        M->ansi_state = 0;
    } else if (M->ansi_state == 2) {
        if (c == '>' || c == '?') { M->ansi_gt = 1; return; }
        if (c >= '0' && c <= '9') {
            if (M->ansi_npar == 0) M->ansi_npar = 1;
            u8 idx = (M->ansi_npar - 1u) & 3u;
            M->ansi_params[idx] = (u8)(M->ansi_params[idx] * 10u + (c - '0'));
            return;
        }
        if (c == ';') {
            if (M->ansi_npar < 4u) M->ansi_npar++;
            return;
        }
        M->ansi_state = 0;
        u8 p0 = M->ansi_params[0], p1 = M->ansi_params[1];
        if (M->ansi_gt) {
            if (p0 == 5 && c == 'h') M->cursor_on = 0;
            if (p0 == 5 && c == 'l') M->cursor_on = 1;
        } else if (c == 'J') {
            tvram_clear_screen();
        } else if (c == 'H' || c == 'f') {
            M->con_y = (p0 > 0 ? p0 - 1u : 0u);
            M->con_x = (p1 > 0 ? p1 - 1u : 0u);
            if (M->con_y > 24u) M->con_y = 24u;
            if (M->con_x > 79u) M->con_x = 79u;
        } else if (c == 'm') {
            static const u8 ansi_grb[8] = {0x01, 0x41, 0x81, 0xC1, 0x21, 0x61, 0xA1, 0xE1};
            int n = M->ansi_npar ? M->ansi_npar : 1;
            for (int i = 0; i < n; i++) {
                u8 a = M->ansi_params[i];
                if (a == 0) M->con_attr = 0xE1u;
                else if (a == 4) M->con_attr |= 0x08u;
                else if (a == 5) M->con_attr |= 0x02u;
                else if (a == 7) M->con_attr |= 0x04u;
                else if (a >= 16 && a <= 23) M->con_attr = (u8)((M->con_attr & 0x1Fu) | (ansi_grb[a - 16] & 0xE0u));
                else if (a >= 30 && a <= 37) M->con_attr = (u8)((M->con_attr & 0x1Fu) | (ansi_grb[a - 30] & 0xE0u));
            }
        }
        M->cursor_addr = (u16)(M->con_y * 80u + M->con_x);
        return;
    }

    if (c == 0x1Bu) { M->ansi_state = 1; return; }
    if (c == 0x1Au) { tvram_clear_screen(); return; }
    if (c == '\r')  { M->con_x = 0; M->cursor_addr = (u16)(M->con_y * 80u); return; }
    if (c == '\n')  { if (++M->con_y >= 25u) { M->con_y = 24u; tvram_scroll_up(); } M->cursor_addr = (u16)(M->con_y * 80u + M->con_x); return; }
    if (c == '\b')  { if (M->con_x > 0) M->con_x--; M->cursor_addr = (u16)(M->con_y * 80u + M->con_x); return; }
    if (c == '\t')  { M->con_x = (u16)((M->con_x + 8u) & ~7u); if (M->con_x >= 80u) { M->con_x = 0; if (++M->con_y >= 25u) { M->con_y = 24u; tvram_scroll_up(); } } return; }

    /* Detect Shift-JIS lead byte (0x81..0x9F or 0xE0..0xFC) */
    if ((c >= 0x81u && c <= 0x9Fu) || (c >= 0xE0u && c <= 0xFCu)) {
        M->sjis_lead = c;
        return;
    }

    int cell = (int)(M->con_y * 80u + M->con_x) * 2;
    M->tvram[cell]     = c;
    M->tvram[cell + 1] = 0x00u;
    M->tvram[0x2000 + cell] = M->con_attr;
    if (++M->con_x >= 80u) {
        M->con_x = 0;
        if (++M->con_y >= 25u) { M->con_y = 24u; tvram_scroll_up(); }
    }
    M->cursor_addr = (u16)(M->con_y * 80u + M->con_x);
}

/* ---- Modify caller's pushed FLAGS on stack during IRET-based HLE trap ---- */
static void trap_set_cf(struct x86_cpu *cpu, int cf)
{
    u16 sp = X86_SP(cpu);
    u16 fl = x86_seg_rw(cpu, X86_SS, (u16)(sp + 4u));
    if (cf) fl |=  X86_F_CF;
    else    fl &= (u16)~X86_F_CF;
    x86_seg_ww(cpu, X86_SS, (u16)(sp + 4u), fl);
    if (cf) cpu->flags |=  X86_F_CF;
    else    cpu->flags &= (u16)~X86_F_CF;
}

static void trap_set_zf(struct x86_cpu *cpu, int zf)
{
    u16 sp = X86_SP(cpu);
    u16 fl = x86_seg_rw(cpu, X86_SS, (u16)(sp + 4u));
    if (zf) fl |=  X86_F_ZF;
    else    fl &= (u16)~X86_F_ZF;
    x86_seg_ww(cpu, X86_SS, (u16)(sp + 4u), fl);
    if (zf) cpu->flags |=  X86_F_ZF;
    else    cpu->flags &= (u16)~X86_F_ZF;
}

/* ---- FAT12/FAT16 Disk Filesystem Helper (for DOS HLE over .hdm/.fdi/.hdi) ---- */
static u32 fat_next_cluster(u32 clus)
{
    u8 sec[1024];
    if (M->fat_is16) {
        u32 off = (u32)M->fat_res * M->fat_bps + clus * 2u;
        u32 lba = (M->fat_part_off + off) / M->disk_sec_sz;
        u32 rem = (M->fat_part_off + off) % M->disk_sec_sz;
        if (disk_read_lba_sec(lba, sec, M->disk_sec_sz) < 0) return 0xFFFFu;
        return rd_le16(sec + rem);
    } else {
        u32 off = (u32)M->fat_res * M->fat_bps + clus + (clus >> 1);
        u32 lba = (M->fat_part_off + off) / M->disk_sec_sz;
        u32 rem = (M->fat_part_off + off) % M->disk_sec_sz;
        if (disk_read_lba_sec(lba, sec, M->disk_sec_sz) < 0) return 0xFFFu;
        u8 b0 = sec[rem], b1;
        if (rem + 1u < M->disk_sec_sz) {
            b1 = sec[rem + 1u];
        } else {
            if (disk_read_lba_sec(lba + 1u, sec, M->disk_sec_sz) < 0) return 0xFFFu;
            b1 = sec[0];
        }
        u16 pair = (u16)b0 | ((u16)b1 << 8);
        return (clus & 1u) ? (pair >> 4) : (pair & 0x0FFFu);
    }
}

static int fat_read_range(u32 start_clus, u32 file_size, u32 file_pos, u8 *dst, u32 len)
{
    if (file_pos >= file_size || len == 0)
        return 0;
    if (file_pos + len > file_size)
        len = file_size - file_pos;

    u32 clus_bytes = (u32)M->fat_spc * (u32)M->fat_bps;
    u32 skip_clus = file_pos / clus_bytes;
    u32 off_in_clus = file_pos % clus_bytes;
    u32 clus = start_clus;
    u32 eof_mark = M->fat_is16 ? 0xFFF8u : 0x0FF8u;

    for (u32 i = 0; i < skip_clus && clus >= 2u && clus < eof_mark; i++)
        clus = fat_next_cluster(clus);

    u8 sec[1024];
    u32 done = 0;
    while (done < len && clus >= 2u && clus < eof_mark) {
        u32 clus_off = M->fat_part_off + M->fat_data_off + (clus - 2u) * clus_bytes + off_in_clus;
        u32 avail = clus_bytes - off_in_clus;
        if (avail > len - done) avail = len - done;
        for (u32 pos = 0; pos < avail; ) {
            u32 abs_b = clus_off + pos;
            u32 lba = abs_b / M->disk_sec_sz;
            u32 srem = abs_b % M->disk_sec_sz;
            if (disk_read_lba_sec(lba, sec, M->disk_sec_sz) < 0)
                return (int)done;
            u32 take = M->disk_sec_sz - srem;
            if (take > avail - pos) take = avail - pos;
            for (u32 k = 0; k < take; k++)
                dst[done + pos + k] = sec[srem + k];
            pos += take;
        }
        done += avail;
        off_in_clus = 0;
        clus = fat_next_cluster(clus);
    }
    return (int)done;
}

static void fat_scan_dir(u32 dir_clus, const char *prefix)
{
    u8 buf[32];
    u32 idx = 0;
    for (; idx < 512u && M->nfiles < MAX_FILES; idx++) {
        if (dir_clus == 0) {
            if (idx >= M->fat_ndir) break;
            u32 abs_b = M->fat_part_off + M->fat_root_off + idx * 32u;
            u8 sec[1024];
            u32 lba = abs_b / M->disk_sec_sz, srem = abs_b % M->disk_sec_sz;
            if (disk_read_lba_sec(lba, sec, M->disk_sec_sz) < 0) break;
            for (int k = 0; k < 32; k++) buf[k] = sec[srem + (u32)k];
        } else {
            if (fat_read_range(dir_clus, 65536u, idx * 32u, buf, 32u) < 32) break;
        }
        if (buf[0] == 0x00u) break;
        if (buf[0] == 0xE5u || buf[11] == 0x0Fu || (buf[11] & 0x08u)) continue;
        if (buf[0] == '.') continue;

        char nm[64];
        int p = 0;
        for (int i = 0; prefix[i] && p < 48; i++) nm[p++] = prefix[i];
        if (p > 0) nm[p++] = '/';
        for (int i = 0; i < 8 && buf[i] != ' '; i++) nm[p++] = up_ch((char)buf[i]);
        if (buf[8] != ' ') {
            nm[p++] = '.';
            for (int i = 8; i < 11 && buf[i] != ' '; i++) nm[p++] = up_ch((char)buf[i]);
        }
        nm[p] = 0;

        u16 clus = rd_le16(buf + 26);
        u32 sz   = rd_le32(buf + 28);
        u8 is_dir = (buf[11] & 0x10u) != 0;

        struct pc98_vfile *vf = &M->files[M->nfiles++];
        mem_zero(vf, sizeof(*vf));
        for (int i = 0; nm[i] && i < 63; i++) vf->name[i] = nm[i];
        vf->size = sz;
        vf->fat_clus = clus;
        vf->is_dir = is_dir;

        if (is_dir && clus >= 2u && !prefix[0])
            fat_scan_dir(clus, nm);
    }
}

/* ---- DOS Path & MCB Helpers ---- */
static void dos_norm_path(const char *raw, char *out)
{
    /* Skip drive "A:" / "C:" */
    if (raw[0] && raw[1] == ':') raw += 2;
    char tmp[96];
    int p = 0;
    if (raw[0] != '\\' && raw[0] != '/' && M->cwd[0]) {
        for (int i = 0; M->cwd[i] && p < 60; i++) tmp[p++] = M->cwd[i];
        tmp[p++] = '/';
    }
    while (*raw == '\\' || *raw == '/') raw++;
    for (; *raw && p < 94; raw++) {
        char ch = (*raw == '\\') ? '/' : up_ch(*raw);
        if (ch == '/' && p > 0 && tmp[p - 1] == '/') continue;
        tmp[p++] = ch;
    }
    while (p > 0 && tmp[p - 1] == '/') p--;
    tmp[p] = 0;

    /* Collapse "." and ".." */
    int op = 0;
    for (int i = 0; i < p; ) {
        int j = i;
        while (j < p && tmp[j] != '/') j++;
        int len = j - i;
        if (len == 1 && tmp[i] == '.') {
            /* skip */
        } else if (len == 2 && tmp[i] == '.' && tmp[i + 1] == '.') {
            while (op > 0 && out[op - 1] != '/') op--;
            if (op > 0) op--;
        } else {
            if (op > 0 && op < 62) out[op++] = '/';
            for (int k = 0; k < len && op < 62; k++) out[op++] = tmp[i + k];
        }
        i = j + 1;
    }
    out[op] = 0;
}

static int vfile_find(const char *raw_path)
{
    char norm[64];
    dos_norm_path(raw_path, norm);
    for (u32 i = 0; i < M->nfiles; i++)
        if (ci_eq(M->files[i].name, norm))
            return (int)i;
    /* Fallback: match basename if game didn't chdir */
    const char *base = norm;
    for (const char *q = norm; *q; q++) if (*q == '/') base = q + 1;
    for (u32 i = 0; i < M->nfiles; i++) {
        const char *fb = M->files[i].name;
        for (const char *q = fb; *q; q++) if (*q == '/') fb = q + 1;
        if (ci_eq(fb, base))
            return (int)i;
    }
    return -1;
}

static int vfile_read(int idx, u32 pos, u8 *dst, u32 len)
{
    struct pc98_vfile *f = &M->files[idx];
    if (pos >= f->size || len == 0) return 0;
    if (pos + len > f->size) len = f->size - pos;
    if (f->wr_data) {
        for (u32 i = 0; i < len; i++) dst[i] = f->wr_data[pos + i];
        return (int)len;
    }
    if (f->data) {
        for (u32 i = 0; i < len; i++) dst[i] = f->data[pos + i];
        return (int)len;
    }
    if (f->fat_clus >= 2u)
        return fat_read_range(f->fat_clus, f->size, pos, dst, len);
    return 0;
}

static int dos_wild_match(const char *pat, const char *name)
{
    /* Match 8.3 wildcard pattern against basename */
    int pi = 0, ni = 0;
    while (pat[pi] && name[ni]) {
        if (pat[pi] == '*') {
            while (pat[pi] && pat[pi] != '.') pi++;
            while (name[ni] && name[ni] != '.') ni++;
            continue;
        }
        if (pat[pi] != '?' && up_ch(pat[pi]) != up_ch(name[ni]))
            return 0;
        pi++; ni++;
    }
    while (pat[pi] == '*') pi++;
    if (pat[pi] == '.' && pat[pi + 1] == '*') pi += 2;
    return pat[pi] == 0 && name[ni] == 0;
}

/* ---- DOS MCB Allocator (0x0060..0x9FFF) ---- */
static void mcb_init(u16 first_seg, u16 top_seg)
{
    M->mcb_first_seg = first_seg;
    M->top_mem_seg = top_seg;
    u32 a = (u32)first_seg << 4;
    M->ram[a] = 'Z';
    M->ram[a + 1] = 0; M->ram[a + 2] = 0; /* free */
    u16 paras = (u16)(top_seg - first_seg - 1u);
    M->ram[a + 3] = (u8)paras;
    M->ram[a + 4] = (u8)(paras >> 8);
}

static u16 mcb_alloc(u16 want_paras, u16 *max_free_out)
{
    u16 seg = M->mcb_first_seg;
    u16 best = 0;
    for (int iter = 0; iter < 256; iter++) {
        u32 a = (u32)seg << 4;
        u8 tag = M->ram[a];
        if (tag != 'M' && tag != 'Z') break;
        u16 owner = rd_le16(&M->ram[a + 1]);
        u16 sz    = rd_le16(&M->ram[a + 3]);
        if (owner == 0) {
            /* Coalesce adjacent free MCBs */
            while (tag == 'M') {
                u32 na = (u32)(seg + sz + 1u) << 4;
                if ((M->ram[na] == 'M' || M->ram[na] == 'Z') && rd_le16(&M->ram[na + 1]) == 0) {
                    tag = M->ram[na];
                    sz = (u16)(sz + rd_le16(&M->ram[na + 3]) + 1u);
                    M->ram[a] = tag;
                    M->ram[a + 3] = (u8)sz; M->ram[a + 4] = (u8)(sz >> 8);
                } else break;
            }
            if (sz > best) best = sz;
            if (sz >= want_paras) {
                M->ram[a + 1] = (u8)M->psp_seg;
                M->ram[a + 2] = (u8)(M->psp_seg >> 8);
                if (sz > want_paras + 1u) {
                    u16 rem = (u16)(sz - want_paras - 1u);
                    M->ram[a] = 'M';
                    M->ram[a + 3] = (u8)want_paras; M->ram[a + 4] = (u8)(want_paras >> 8);
                    u32 na = (u32)(seg + want_paras + 1u) << 4;
                    M->ram[na] = tag;
                    M->ram[na + 1] = 0; M->ram[na + 2] = 0;
                    M->ram[na + 3] = (u8)rem; M->ram[na + 4] = (u8)(rem >> 8);
                }
                if (max_free_out) *max_free_out = best;
                return (u16)(seg + 1u);
            }
        }
        if (tag == 'Z') break;
        seg = (u16)(seg + sz + 1u);
    }
    if (max_free_out) *max_free_out = best;
    return 0;
}

static int mcb_resize(u16 block_seg, u16 new_paras, u16 *max_avail_out)
{
    if (block_seg <= M->mcb_first_seg) return -1;
    u16 mseg = (u16)(block_seg - 1u);
    u32 a = (u32)mseg << 4;
    if (M->ram[a] != 'M' && M->ram[a] != 'Z') return -1;
    u16 cur = rd_le16(&M->ram[a + 3]);
    /* Coalesce trailing free block if any */
    if (M->ram[a] == 'M') {
        u32 na = (u32)(mseg + cur + 1u) << 4;
        if ((M->ram[na] == 'M' || M->ram[na] == 'Z') && rd_le16(&M->ram[na + 1]) == 0) {
            M->ram[a] = M->ram[na];
            cur = (u16)(cur + rd_le16(&M->ram[na + 3]) + 1u);
            M->ram[a + 3] = (u8)cur; M->ram[a + 4] = (u8)(cur >> 8);
        }
    }
    if (max_avail_out) *max_avail_out = cur;
    if (new_paras > cur)
        return -1;
    if (cur > new_paras + 1u) {
        u8 old_tag = M->ram[a];
        u16 rem = (u16)(cur - new_paras - 1u);
        M->ram[a] = 'M';
        M->ram[a + 3] = (u8)new_paras; M->ram[a + 4] = (u8)(new_paras >> 8);
        u32 na = (u32)(mseg + new_paras + 1u) << 4;
        M->ram[na] = old_tag;
        M->ram[na + 1] = 0; M->ram[na + 2] = 0;
        M->ram[na + 3] = (u8)rem; M->ram[na + 4] = (u8)(rem >> 8);
    }
    return 0;
}

/* ---- Load & Start a PC-98 MZ .EXE or .COM Program ---- */
static const char *dos_exec_vfile(int fidx)
{
    struct pc98_vfile *vf = &M->files[fidx];
    if (vf->size < 2u) return "empty executable";

    /* Set CWD to the executable's directory */
    int slash = -1;
    for (int i = 0; vf->name[i]; i++) if (vf->name[i] == '/') slash = i;
    if (slash > 0) {
        for (int i = 0; i < slash; i++) M->cwd[i] = vf->name[i];
        M->cwd[slash] = 0;
    } else {
        M->cwd[0] = 0;
    }

    /* Allocate Environment block (16 paragraphs) + Program block (all remaining conventional RAM) */
    mcb_init(0x0080u, 0x9FC0u);
    u16 env_seg = mcb_alloc(16u, 0);
    u32 ea = (u32)env_seg << 4;
    mem_zero(&M->ram[ea], 256);
    {
        static const char env_vars[] = "PATH=A:\\\0COMSPEC=A:\\COMMAND.COM\0";
        u32 ep = 0;
        for (u32 i = 0; i < sizeof(env_vars); i++)
            M->ram[ea + ep++] = (u8)env_vars[i]; /* includes trailing double NUL */
        M->ram[ea + ep++] = 0x01u;
        M->ram[ea + ep++] = 0x00u;
        M->ram[ea + ep++] = 'A';
        M->ram[ea + ep++] = ':';
        M->ram[ea + ep++] = '\\';
        for (int i = 0; vf->name[i] && ep < 250u; i++)
            M->ram[ea + ep++] = (u8)((vf->name[i] == '/') ? '\\' : vf->name[i]);
        M->ram[ea + ep] = 0;
    }

    u16 max_free = 0;
    (void)mcb_alloc(0xFFFFu, &max_free);
    u16 psp_seg = mcb_alloc(max_free, 0);
    if (!psp_seg) return "out of conventional memory";
    M->psp_seg = psp_seg;
    M->dta_seg = psp_seg;
    M->dta_off = 0x0080u;
    /* Set MCB owner of env & psp to psp_seg */
    u32 pmcb = (u32)(psp_seg - 1u) << 4, emcb = (u32)(env_seg - 1u) << 4;
    M->ram[pmcb + 1] = M->ram[emcb + 1] = (u8)psp_seg;
    M->ram[pmcb + 2] = M->ram[emcb + 2] = (u8)(psp_seg >> 8);

    /* Build PSP at psp_seg:0000 */
    u32 pa = (u32)psp_seg << 4;
    mem_zero(&M->ram[pa], 256);
    M->ram[pa + 0] = 0xCDu; M->ram[pa + 1] = 0x20u; /* INT 20h */
    M->ram[pa + 2] = (u8)M->top_mem_seg;
    M->ram[pa + 3] = (u8)(M->top_mem_seg >> 8);
    M->ram[pa + 0x2C] = (u8)env_seg;
    M->ram[pa + 0x2D] = (u8)(env_seg >> 8);
    M->ram[pa + 0x80] = 0;
    M->ram[pa + 0x81] = '\r';

    u8 hdr[32];
    mem_zero(hdr, sizeof(hdr));
    (void)vfile_read(fidx, 0, hdr, 32u);

    u16 load_seg = (u16)(psp_seg + 0x0010u);
    u32 load_addr = (u32)load_seg << 4;

    if (hdr[0] == 'M' && hdr[1] == 'Z') {
        u16 cblp    = rd_le16(hdr + 2);
        u16 cp      = rd_le16(hdr + 4);
        u16 crlc    = rd_le16(hdr + 6);
        u16 cparhdr = rd_le16(hdr + 8);
        u16 maxalloc= rd_le16(hdr + 12);
        u16 init_ss = rd_le16(hdr + 14);
        u16 init_sp = rd_le16(hdr + 16);
        u16 init_ip = rd_le16(hdr + 20);
        u16 init_cs = rd_le16(hdr + 22);
        u16 lfarlc  = rd_le16(hdr + 24);

        u32 hdr_bytes = (u32)cparhdr * 16u;
        u32 img_bytes = (cp > 0) ? ((u32)cp * 512u - (cblp ? (512u - cblp) : 0u)) : vf->size;
        if (img_bytes > vf->size) img_bytes = vf->size;
        if (img_bytes <= hdr_bytes) return "corrupt MZ header";
        u32 code_bytes = img_bytes - hdr_bytes;
        if (load_addr + code_bytes > 0xA0000u)
            code_bytes = 0xA0000u - load_addr;

        (void)vfile_read(fidx, hdr_bytes, &M->ram[load_addr], code_bytes);

        /* Apply MZ segment relocations */
        for (u16 r = 0; r < crlc; r++) {
            u8 rel[4];
            if (vfile_read(fidx, (u32)lfarlc + (u32)r * 4u, rel, 4u) < 4) break;
            u16 roff = rd_le16(rel);
            u16 rseg = rd_le16(rel + 2);
            u32 ra = load_addr + ((u32)rseg << 4) + (u32)roff;
            if (ra + 1u < 0xA0000u) {
                u16 cur = rd_le16(&M->ram[ra]);
                cur = (u16)(cur + load_seg);
                M->ram[ra] = (u8)cur;
                M->ram[ra + 1u] = (u8)(cur >> 8);
            }
        }

        if (maxalloc == 0) {
            u16 need = (u16)(0x10u + ((code_bytes + 15u) >> 4));
            (void)mcb_resize(psp_seg, need, 0);
        }

        x86_set_sr(&M->cpu, X86_DS, psp_seg);
        x86_set_sr(&M->cpu, X86_ES, psp_seg);
        x86_set_sr(&M->cpu, X86_SS, (u16)(load_seg + init_ss));
        X86_SP(&M->cpu) = init_sp;
        x86_set_sr(&M->cpu, X86_CS, (u16)(load_seg + init_cs));
        M->cpu.ip = init_ip;
    } else {
        /* .COM binary loaded at PSP:0100 */
        u32 cp = vf->size > 0xFE00u ? 0xFE00u : vf->size;
        (void)vfile_read(fidx, 0, &M->ram[pa + 0x100u], cp);
        x86_set_sr(&M->cpu, X86_CS, psp_seg);
        x86_set_sr(&M->cpu, X86_DS, psp_seg);
        x86_set_sr(&M->cpu, X86_ES, psp_seg);
        x86_set_sr(&M->cpu, X86_SS, psp_seg);
        X86_SP(&M->cpu) = 0xFFFEu;
        M->ram[pa + 0xFFFEu] = 0; M->ram[pa + 0xFFFFu] = 0;
        M->cpu.ip = 0x0100u;
    }

    X86_AX(&M->cpu) = X86_BX(&M->cpu) = X86_CX(&M->cpu) = X86_DX(&M->cpu) = 0;
    X86_SI(&M->cpu) = M->cpu.ip;
    X86_DI(&M->cpu) = X86_SP(&M->cpu);
    M->cpu.flags = 0x0202u; /* IF=1 */
    M->dos_ended = 0;
    return 0;
}

/* ---- Clean-Room PC-98 BIOS & DOS HLE Trap Dispatcher (`0F FF <id>`) ---- */
enum {
    TRAP_IPL_BOOT = 0x01,
    TRAP_IRQ0_PIT = 0x08,
    TRAP_IRQ1_KBD = 0x09,
    TRAP_IRQ2_VBL = 0x0A,
    TRAP_BIOS_18  = 0x18,
    TRAP_BIOS_1B  = 0x1B,
    TRAP_BIOS_1C  = 0x1C,
    TRAP_BIOS_1F  = 0x1F,
    TRAP_DOS_20   = 0x20,
    TRAP_DOS_21   = 0x21,
    TRAP_DOS_29   = 0x29,
    TRAP_MOUSE_33 = 0x33,
    TRAP_EMS_67   = 0x67,
    TRAP_NEC_DC   = 0xDC
};

static void read_ds_dx_asciz(const struct x86_cpu *cpu, char *out, int cap)
{
    u16 off = X86_DX(cpu);
    int i = 0;
    while (i < cap - 1) {
        u8 c = x86_seg_rb(cpu, X86_DS, (u16)(off + (u16)i));
        if (!c) break;
        out[i++] = (char)c;
    }
    out[i] = 0;
}

static void fill_find_dta(int fidx)
{
    struct pc98_vfile *vf = &M->files[fidx];
    u32 dta = ((u32)M->dta_seg << 4) + M->dta_off;
    for (int i = 0; i < 43; i++) pc98_wb(dta + (u32)i, 0);
    pc98_wb(dta + 21u, vf->is_dir ? 0x10u : 0x20u);
    pc98_wb(dta + 26u, (u8)vf->size);
    pc98_wb(dta + 27u, (u8)(vf->size >> 8));
    pc98_wb(dta + 28u, (u8)(vf->size >> 16));
    pc98_wb(dta + 29u, (u8)(vf->size >> 24));
    const char *bn = vf->name;
    for (const char *q = bn; *q; q++) if (*q == '/') bn = q + 1;
    for (int i = 0; bn[i] && i < 12; i++)
        pc98_wb(dta + 30u + (u32)i, (u8)up_ch(bn[i]));
}

static void handle_dos_21(struct x86_cpu *cpu)
{
    u8 ah = X86_AH(cpu);
    trap_set_cf(cpu, 0);

    switch (ah) {
    case 0x00:
    case 0x4C:
        M->dos_ended = 1;
        cpu->halted = 1;
        break;
    case 0x01: case 0x07: case 0x08: {
        if (M->ram[0x0528] == 0) {
            /* Yield until next frame delivers key */
            cpu->ip = cpu->op_ip;
            cpu->halted = 1;
            return;
        }
        u16 head = rd_le16(&M->ram[0x0522]);
        u8 asc = M->ram[head];
        head = (u16)(head + 2u);
        if (head >= 0x0522u) head = 0x0502u;
        M->ram[0x0522] = (u8)head; M->ram[0x0523] = (u8)(head >> 8);
        M->ram[0x0528]--;
        X86_AL(cpu) = asc;
        if (ah == 0x01u && asc) con_put_byte(asc);
        break;
    }
    case 0x02:
        con_put_byte(X86_DL(cpu));
        X86_AL(cpu) = X86_DL(cpu);
        break;
    case 0x06:
        if (X86_DL(cpu) == 0xFFu) {
            if (M->ram[0x0528] == 0) {
                X86_AL(cpu) = 0;
                trap_set_zf(cpu, 1);
            } else {
                u16 head = rd_le16(&M->ram[0x0522]);
                u8 asc = M->ram[head];
                head = (u16)(head + 2u);
                if (head >= 0x0522u) head = 0x0502u;
                M->ram[0x0522] = (u8)head; M->ram[0x0523] = (u8)(head >> 8);
                M->ram[0x0528]--;
                X86_AL(cpu) = asc;
                trap_set_zf(cpu, 0);
            }
        } else {
            con_put_byte(X86_DL(cpu));
        }
        break;
    case 0x09: {
        u16 o = X86_DX(cpu);
        for (int i = 0; i < 4096; i++) {
            u8 c = x86_seg_rb(cpu, X86_DS, (u16)(o + (u16)i));
            if (c == '$') break;
            con_put_byte(c);
        }
        X86_AL(cpu) = '$';
        break;
    }
    case 0x0B:
        X86_AL(cpu) = (M->ram[0x0528] > 0) ? 0xFFu : 0x00u;
        break;
    case 0x0C:
        M->ram[0x0528] = 0;
        M->ram[0x0522] = M->ram[0x0524] = 0x02u;
        M->ram[0x0523] = M->ram[0x0525] = 0x05u;
        if (X86_AL(cpu) == 1 || X86_AL(cpu) == 6 || X86_AL(cpu) == 7 || X86_AL(cpu) == 8) {
            X86_AH(cpu) = X86_AL(cpu);
            handle_dos_21(cpu);
        }
        break;
    case 0x0E: X86_AL(cpu) = 4; break; /* 4 logical drives */
    case 0x19: X86_AL(cpu) = 0; break; /* Current drive A: (0) */
    case 0x1A:
        M->dta_seg = cpu->sr[X86_DS];
        M->dta_off = X86_DX(cpu);
        break;
    case 0x25: { /* Set INT vector */
        u32 va = (u32)X86_AL(cpu) * 4u;
        pc98_ww(va, X86_DX(cpu));
        pc98_ww(va + 2u, cpu->sr[X86_DS]);
        break;
    }
    case 0x2A: X86_CX(cpu) = 1994; X86_DH(cpu) = 11; X86_DL(cpu) = 25; X86_AL(cpu) = 5; break;
    case 0x2C: {
        u32 sec = M->frames / 56u;
        u32 cs  = (M->frames % 56u) * 100u / 56u;
        X86_CH(cpu) = 12;
        X86_CL(cpu) = (u8)((sec / 60u) % 60u);
        X86_DH(cpu) = (u8)(sec % 60u);
        X86_DL(cpu) = (u8)cs;
        break;
    }
    case 0x2F:
        x86_set_sr(cpu, X86_ES, M->dta_seg);
        X86_BX(cpu) = M->dta_off;
        break;
    case 0x30: /* DOS 5.0 NEC OEM */
        X86_AL(cpu) = 5; X86_AH(cpu) = 0; X86_BH(cpu) = 0x1Eu; X86_BL(cpu) = 0; X86_CX(cpu) = 0;
        break;
    case 0x33:
        if (X86_AL(cpu) == 0) X86_DL(cpu) = 0;
        break;
    case 0x35: { /* Get INT vector */
        u32 va = (u32)X86_AL(cpu) * 4u;
        X86_BX(cpu) = pc98_rw(va);
        x86_set_sr(cpu, X86_ES, pc98_rw(va + 2u));
        break;
    }
    case 0x36: /* Free disk space */
        X86_AX(cpu) = 1; X86_BX(cpu) = 512; X86_CX(cpu) = 1024; X86_DX(cpu) = 1232;
        break;
    case 0x3B: { /* CHDIR */
        char raw[64], norm[64];
        read_ds_dx_asciz(cpu, raw, sizeof(raw));
        dos_norm_path(raw, norm);
        for (int i = 0; i < 63; i++) { M->cwd[i] = norm[i]; if (!norm[i]) break; }
        break;
    }
    case 0x3C: /* CREAT */
    case 0x3D: { /* OPEN */
        char raw[64];
        read_ds_dx_asciz(cpu, raw, sizeof(raw));
        int fidx = vfile_find(raw);
        if (ah == 0x3Cu && fidx < 0) {
            if (M->nfiles >= MAX_FILES || M->scratch_used + 4096u > SCRATCH_CAP) {
                trap_set_cf(cpu, 1); X86_AX(cpu) = 4; break;
            }
            char norm[64];
            dos_norm_path(raw, norm);
            fidx = (int)M->nfiles++;
            struct pc98_vfile *vf = &M->files[fidx];
            mem_zero(vf, sizeof(*vf));
            for (int i = 0; norm[i] && i < 63; i++) vf->name[i] = norm[i];
            vf->wr_data = &M->scratch[M->scratch_used];
            vf->cap = 4096u;
            M->scratch_used += 4096u;
        }
        if (fidx < 0 || M->files[fidx].is_dir) {
            trap_set_cf(cpu, 1);
            X86_AX(cpu) = 2; /* File not found */
            break;
        }
        if (ah == 0x3Cu && M->files[fidx].wr_data)
            M->files[fidx].size = 0;
        int h = -1;
        for (int i = 5; i < MAX_HANDLES; i++) if (!M->handles[i].open) { h = i; break; }
        if (h < 0) { trap_set_cf(cpu, 1); X86_AX(cpu) = 4; break; }
        M->handles[h].open = 1;
        M->handles[h].is_con = 0;
        M->handles[h].fidx = (s16)fidx;
        M->handles[h].pos = 0;
        X86_AX(cpu) = (u16)h;
        break;
    }
    case 0x3E: { /* CLOSE */
        u16 h = X86_BX(cpu);
        if (h >= 5u && h < MAX_HANDLES) M->handles[h].open = 0;
        break;
    }
    case 0x3F: { /* READ */
        u16 h = X86_BX(cpu);
        u16 want = X86_CX(cpu);
        u16 doff = X86_DX(cpu);
        if (h < 5u) { X86_AX(cpu) = 0; break; }
        if (h >= MAX_HANDLES || !M->handles[h].open) { trap_set_cf(cpu, 1); X86_AX(cpu) = 6; break; }
        u8 tmp[512];
        u32 total = 0;
        while (total < want) {
            u32 chunk = (want - total > 512u) ? 512u : (want - total);
            int got = vfile_read(M->handles[h].fidx, M->handles[h].pos, tmp, chunk);
            if (got <= 0) break;
            for (int i = 0; i < got; i++)
                x86_seg_wb(cpu, X86_DS, (u16)(doff + total + (u32)i), tmp[i]);
            M->handles[h].pos += (u32)got;
            total += (u32)got;
            if ((u32)got < chunk) break;
        }
        X86_AX(cpu) = (u16)total;
        break;
    }
    case 0x40: { /* WRITE */
        u16 h = X86_BX(cpu);
        u16 len = X86_CX(cpu);
        u16 soff = X86_DX(cpu);
        if (h <= 2u) {
            for (u16 i = 0; i < len; i++)
                con_put_byte(x86_seg_rb(cpu, X86_DS, (u16)(soff + i)));
            X86_AX(cpu) = len;
            break;
        }
        if (h >= MAX_HANDLES || !M->handles[h].open) { trap_set_cf(cpu, 1); X86_AX(cpu) = 6; break; }
        struct pc98_vfile *vf = &M->files[M->handles[h].fidx];
        if (!vf->wr_data && M->scratch_used + 4096u <= SCRATCH_CAP) {
            u32 cap = (vf->size + len + 1024u > 8192u) ? 8192u : 4096u;
            if (M->scratch_used + cap <= SCRATCH_CAP) {
                vf->wr_data = &M->scratch[M->scratch_used];
                vf->cap = cap;
                M->scratch_used += cap;
                if (vf->size > 0 && vf->size <= cap)
                    (void)vfile_read(M->handles[h].fidx, 0, vf->wr_data, vf->size);
            }
        }
        u32 pos = M->handles[h].pos;
        if (vf->wr_data) {
            if (len == 0) {
                vf->size = pos;
            } else {
                u32 w = 0;
                for (; w < len && pos + w < vf->cap; w++)
                    vf->wr_data[pos + w] = x86_seg_rb(cpu, X86_DS, (u16)(soff + w));
                pos += w;
                if (pos > vf->size) vf->size = pos;
                M->handles[h].pos = pos;
                X86_AX(cpu) = (u16)w;
                break;
            }
        }
        M->handles[h].pos += len;
        X86_AX(cpu) = len;
        break;
    }
    case 0x41: /* UNLINK */
        break;
    case 0x42: { /* LSEEK */
        u16 h = X86_BX(cpu);
        if (h >= MAX_HANDLES || !M->handles[h].open) { trap_set_cf(cpu, 1); X86_AX(cpu) = 6; break; }
        s32 disp = (s32)(((u32)X86_CX(cpu) << 16) | X86_DX(cpu));
        u32 sz = M->files[M->handles[h].fidx].size;
        s32 npos = (X86_AL(cpu) == 0) ? disp : (X86_AL(cpu) == 1 ? (s32)M->handles[h].pos + disp : (s32)sz + disp);
        if (npos < 0) npos = 0;
        M->handles[h].pos = (u32)npos;
        X86_AX(cpu) = (u16)((u32)npos & 0xFFFFu);
        X86_DX(cpu) = (u16)((u32)npos >> 16);
        break;
    }
    case 0x43: { /* GET/SET ATTR */
        char raw[64];
        read_ds_dx_asciz(cpu, raw, sizeof(raw));
        int fidx = vfile_find(raw);
        if (fidx < 0) { trap_set_cf(cpu, 1); X86_AX(cpu) = 2; break; }
        if (X86_AL(cpu) == 0)
            X86_CX(cpu) = M->files[fidx].is_dir ? 0x10u : 0x20u;
        break;
    }
    case 0x44: { /* IOCTL */
        if (X86_AL(cpu) == 0x00u)
            X86_DX(cpu) = (X86_BX(cpu) < 5u) ? 0x80D3u : 0x0000u;
        else
            X86_AX(cpu) = 0;
        break;
    }
    case 0x47: { /* GETCWD */
        u16 si = X86_SI(cpu);
        for (int i = 0; i < 64; i++) {
            char ch = (M->cwd[i] == '/') ? '\\' : M->cwd[i];
            x86_seg_wb(cpu, X86_DS, (u16)(si + (u16)i), (u8)ch);
            if (!ch) break;
        }
        break;
    }
    case 0x48: { /* ALLOC */
        u16 maxf = 0;
        u16 seg = mcb_alloc(X86_BX(cpu), &maxf);
        if (!seg) { trap_set_cf(cpu, 1); X86_AX(cpu) = 8; X86_BX(cpu) = maxf; }
        else X86_AX(cpu) = seg;
        break;
    }
    case 0x49: { /* FREE */
        u16 seg = cpu->sr[X86_ES];
        if (seg > M->mcb_first_seg) {
            u32 a = (u32)(seg - 1u) << 4;
            M->ram[a + 1] = 0; M->ram[a + 2] = 0;
        }
        break;
    }
    case 0x4A: { /* RESIZE */
        u16 maxa = 0;
        if (mcb_resize(cpu->sr[X86_ES], X86_BX(cpu), &maxa) < 0) {
            trap_set_cf(cpu, 1); X86_AX(cpu) = 8; X86_BX(cpu) = maxa;
        }
        break;
    }
    case 0x4E: /* FINDFIRST */
    case 0x4F: { /* FINDNEXT */
        if (ah == 0x4Eu) {
            char raw[64], norm[64];
            read_ds_dx_asciz(cpu, raw, sizeof(raw));
            dos_norm_path(raw, norm);
            int slash = -1;
            for (int i = 0; norm[i]; i++) if (norm[i] == '/') slash = i;
            if (slash >= 0) {
                for (int i = 0; i < slash; i++) M->find_dir[i] = norm[i];
                M->find_dir[slash] = 0;
                for (int i = 0; i < 15 && norm[slash + 1 + i]; i++) { M->find_pat[i] = norm[slash + 1 + i]; M->find_pat[i + 1] = 0; }
            } else {
                M->find_dir[0] = 0;
                for (int i = 0; i < 15; i++) { M->find_pat[i] = norm[i]; if (!norm[i]) break; }
            }
            M->find_idx = 0;
        }
        int found = -1;
        while (M->find_idx < M->nfiles) {
            int idx = (int)M->find_idx++;
            const char *nm = M->files[idx].name;
            int slash = -1;
            for (int i = 0; nm[i]; i++) if (nm[i] == '/') slash = i;
            char fdir[64];
            if (slash >= 0) { for (int i = 0; i < slash; i++) fdir[i] = nm[i]; fdir[slash] = 0; }
            else fdir[0] = 0;
            const char *bn = (slash >= 0) ? (nm + slash + 1) : nm;
            if (ci_eq(fdir, M->find_dir) && dos_wild_match(M->find_pat, bn)) {
                found = idx;
                break;
            }
        }
        if (found < 0) {
            trap_set_cf(cpu, 1);
            X86_AX(cpu) = 18;
        } else {
            fill_find_dta(found);
            X86_AX(cpu) = 0;
        }
        break;
    }
    case 0x50: M->psp_seg = X86_BX(cpu); break;
    case 0x51: case 0x62: X86_BX(cpu) = M->psp_seg; break;
    case 0x58: X86_AX(cpu) = 0; break;
    default:
        break;
    }
}

static void pc98_hle_trap(struct x86_cpu *cpu, u8 id)
{
    switch (id) {
    case TRAP_IPL_BOOT: {
        /* Clean-room NEC PC-9801 IPL: load Cylinder 0, Head 0, Sector 1 into 1FC0:0000 (2HD) or 1FE0:0000 */
        u16 load_seg = (M->boot_daua == 0x70u) ? 0x1FE0u : 0x1FC0u;
        u8 sec[1024];
        u32 ssz = 0;
        int ok = -1;
        if (M->disk_kind == 3) {
            ssz = M->disk_sec_sz;
            ok = disk_read_lba_sec(0, sec, ssz);
        } else {
            ok = disk_read_chs(0, 0, 1, sec, &ssz);
        }
        if (ok < 0 || !ssz) {
            M->dos_ended = 1;
            cpu->halted = 1;
            return;
        }
        u32 dst = (u32)load_seg << 4;
        for (u32 i = 0; i < ssz; i++)
            M->ram[dst + i] = sec[i];
        M->ram[0x0584] = M->boot_daua;
        x86_set_sr(cpu, X86_CS, load_seg);
        x86_set_sr(cpu, X86_DS, 0x0000u);
        x86_set_sr(cpu, X86_ES, 0x0000u);
        x86_set_sr(cpu, X86_SS, 0x0030u);
        X86_SP(cpu) = 0x0400u;
        cpu->ip = 0x0000u;
        cpu->flags = 0x0202u;
        return;
    }

    case TRAP_IRQ0_PIT:
        /* Default INT 08h PIT handler: check CA_TIM (0000:058A) & EOI */
        {
            u16 cnt = rd_le16(&M->ram[0x058A]);
            if (cnt > 0) {
                cnt--;
                M->ram[0x058A] = (u8)cnt; M->ram[0x058B] = (u8)(cnt >> 8);
            }
            pic_write(&M->pic_m, 0, 0x20u);
        }
        break;

    case TRAP_IRQ1_KBD:
        (void)pc98_inb(0x41u);
        pic_write(&M->pic_m, 0, 0x20u);
        break;

    case TRAP_IRQ2_VBL:
        M->vsync_irq_armed = 1;
        pic_write(&M->pic_m, 0, 0x20u);
        break;

    case TRAP_BIOS_18: { /* NEC PC-98 CRT / Keyboard / Font BIOS */
        u8 ah = X86_AH(cpu);
        switch (ah) {
        case 0x00: { /* Blocking read key */
            if (M->ram[0x0528] == 0) {
                /* Unwind IRET frame and retry INT 18h on next frame */
                u16 sp = X86_SP(cpu);
                u16 ret_ip = x86_seg_rw(cpu, X86_SS, sp);
                u16 ret_cs = x86_seg_rw(cpu, X86_SS, (u16)(sp + 2u));
                u16 ret_fl = x86_seg_rw(cpu, X86_SS, (u16)(sp + 4u));
                X86_SP(cpu) = (u16)(sp + 6u);
                x86_set_sr(cpu, X86_CS, ret_cs);
                cpu->ip = (u16)(ret_ip - 2u);
                cpu->flags = (u16)(ret_fl | X86_F_IF);
                cpu->halted = 1;
                return;
            }
            u16 head = rd_le16(&M->ram[0x0522]);
            X86_AL(cpu) = M->ram[head];
            X86_AH(cpu) = M->ram[head + 1u];
            head = (u16)(head + 2u);
            if (head >= 0x0522u) head = 0x0502u;
            M->ram[0x0522] = (u8)head; M->ram[0x0523] = (u8)(head >> 8);
            M->ram[0x0528]--;
            break;
        }
        case 0x01: /* Non-blocking sense key */
            if (M->ram[0x0528] == 0) {
                X86_BH(cpu) = 0;
            } else {
                u16 head = rd_le16(&M->ram[0x0522]);
                X86_AL(cpu) = M->ram[head];
                X86_AH(cpu) = M->ram[head + 1u];
                X86_BH(cpu) = 1;
            }
            break;
        case 0x02: X86_AL(cpu) = M->ram[0x053A]; break;
        case 0x03:
            M->ram[0x0528] = 0;
            M->ram[0x0522] = M->ram[0x0524] = 0x02u;
            M->ram[0x0523] = M->ram[0x0525] = 0x05u;
            break;
        case 0x04: /* Key matrix group sense */
            X86_AH(cpu) = M->ram[0x052A + (X86_AL(cpu) & 15u)];
            break;
        case 0x0A:
            M->ff1_20line = X86_AL(cpu) & 1u;
            M->ff1_col40  = (X86_AL(cpu) >> 1) & 1u;
            break;
        case 0x0B:
            X86_AL(cpu) = (u8)(M->ff1_20line | (M->ff1_col40 << 1));
            break;
        case 0x0C: M->tvram_on = 1; break;
        case 0x0D: M->tvram_on = 0; break;
        case 0x11: M->cursor_on = 1; break;
        case 0x12: M->cursor_on = 0; break;
        case 0x13: M->cursor_addr = (u16)(X86_DX(cpu) >> 1); break;
        case 0x14: { /* Read font pattern into CX:DX */
            u32 dst = ((u32)X86_CX(cpu) << 4) + X86_DX(cpu);
            u16 bx = X86_BX(cpu);
            if ((bx & 0xFF00u) == 0) {
                pc98_wb(dst, 1); pc98_wb(dst + 1u, 16);
                for (int y = 0; y < 16; y++)
                    pc98_wb(dst + 2u + (u32)y, M->ank8x16[bx & 0xFFu][y]);
            } else {
                u8 c1 = (u8)(((bx >> 8) & 0x7Fu) - 0x20u);
                u8 c2 = (u8)((bx & 0x7Fu) - 0x20u);
                pc98_wb(dst, 2); pc98_wb(dst + 1u, 16);
                for (int b = 0; b < 32; b++)
                    pc98_wb(dst + 2u + (u32)b, (c1 < 96u && c2 < 96u) ? M->kcg[c1][c2][b] : 0u);
            }
            break;
        }
        case 0x16: { /* Initialize Text VRAM (DH = attribute, DL = ANK char) */
            for (int i = 0; i < 2000; i++) {
                M->tvram[i * 2] = X86_DL(cpu);
                M->tvram[i * 2 + 1] = 0;
                M->tvram[0x2000 + i * 2] = X86_DH(cpu);
            }
            break;
        }
        case 0x17: M->port_c &= (u8)~0x08u; break;
        case 0x18: M->port_c |=  0x08u; break;
        case 0x1A: { /* Define user character */
            u32 src = ((u32)X86_CX(cpu) << 4) + X86_DX(cpu);
            u16 bx = X86_BX(cpu);
            u8 c1 = (u8)(((bx >> 8) & 0x7Fu) - 0x20u);
            u8 c2 = (u8)((bx & 0x7Fu) - 0x20u);
            if (c1 < 96u && c2 < 96u) {
                for (int b = 0; b < 32; b++)
                    M->kcg[c1][c2][b] = pc98_rb(src + 2u + (u32)b);
            }
            break;
        }
        case 0x40: M->gvram_on = 1; break;
        case 0x41: M->gvram_on = 0; break;
        case 0x42:
            M->disp_page = (X86_CH(cpu) >> 4) & 1u;
            break;
        default:
            break;
        }
        break;
    }

    case TRAP_BIOS_1B: { /* NEC PC-98 Disk BIOS (FDD & SASI HDD) */
        u8 ah = X86_AH(cpu), al = X86_AL(cpu);
        u8 op = ah & 0x0Fu;
        int mt = (ah & 0x80u) != 0;
        u32 bytes = X86_BX(cpu) ? (u32)X86_BX(cpu) : 0x10000u;
        u32 buf_addr = ((u32)cpu->sr[X86_ES] << 4) + X86_BP(cpu);

        if (!M->disk_img) {
            trap_set_cf(cpu, 1);
            X86_AH(cpu) = 0x60u; /* Not ready */
            break;
        }

        if (op == 0x03u || op == 0x07u || op == 0x0Eu || op == 0x01u) {
            trap_set_cf(cpu, 0);
            X86_AH(cpu) = 0x00u;
            break;
        }
        if (op == 0x04u) { /* Sense */
            trap_set_cf(cpu, 0);
            X86_AH(cpu) = (M->disk_kind == 3) ? 0x00u : 0x04u;
            break;
        }
        if (op == 0x0Au) { /* Read ID */
            trap_set_cf(cpu, 0);
            X86_AH(cpu) = 0x00u;
            X86_DL(cpu) = 1;
            X86_CH(cpu) = (M->disk_sec_sz == 1024u) ? 3 : 2;
            break;
        }
        if (op == 0x06u || op == 0x05u) { /* Read (06) or Write (05) */
            u8 sec[1024];
            u32 done = 0;
            if (M->disk_kind == 3 && ((al & 0xF0u) == 0x80u || (al & 0xF0u) == 0x00u)) {
                /* SASI Hard Disk */
                u32 lba = (al & 0x80u)
                    ? (((u32)X86_CX(cpu) * M->disk_heads + X86_DH(cpu)) * M->disk_spt + X86_DL(cpu))
                    : (((u32)X86_DL(cpu) << 16) | X86_CX(cpu));
                while (done < bytes) {
                    u32 take = (bytes - done > M->disk_sec_sz) ? M->disk_sec_sz : (bytes - done);
                    if (op == 0x06u) {
                        if (disk_read_lba_sec(lba, sec, M->disk_sec_sz) < 0) { trap_set_cf(cpu, 1); X86_AH(cpu) = 0xB0u; return; }
                        for (u32 i = 0; i < take; i++) pc98_wb(buf_addr + done + i, sec[i]);
                    } else {
                        for (u32 i = 0; i < M->disk_sec_sz; i++) sec[i] = (i < take) ? pc98_rb(buf_addr + done + i) : 0;
                        disk_write_lba_sec(lba, sec, M->disk_sec_sz);
                    }
                    done += take;
                    lba++;
                }
            } else {
                /* Floppy Disk (C = CL, H = DH, R = DL 1-based) */
                u32 c = X86_CL(cpu), h = X86_DH(cpu) & 1u, r = X86_DL(cpu);
                while (done < bytes) {
                    u32 ssz = M->disk_sec_sz ? M->disk_sec_sz : 1024u;
                    if (op == 0x06u) {
                        if (disk_read_chs(c, h, r, sec, &ssz) < 0) { trap_set_cf(cpu, 1); X86_AH(cpu) = 0xB0u; return; }
                        u32 take = (bytes - done > ssz) ? ssz : (bytes - done);
                        for (u32 i = 0; i < take; i++) pc98_wb(buf_addr + done + i, sec[i]);
                        done += take;
                    } else {
                        u32 take = (bytes - done > ssz) ? ssz : (bytes - done);
                        for (u32 i = 0; i < ssz; i++) sec[i] = (i < take) ? pc98_rb(buf_addr + done + i) : 0;
                        if (M->disk_kind == 1 && r >= 1u && r <= M->disk_spt) {
                            u32 lba = (c * M->disk_heads + h) * M->disk_spt + (r - 1u);
                            disk_write_lba_sec(lba, sec, ssz);
                        }
                        done += take;
                    }
                    r++;
                    if (M->disk_spt > 0 && r > M->disk_spt) {
                        r = 1u;
                        if (mt) {
                            h ^= 1u;
                            if (h == 0) c++;
                        } else {
                            c++;
                        }
                    }
                }
            }
            trap_set_cf(cpu, 0);
            X86_AH(cpu) = 0x00u;
            break;
        }
        trap_set_cf(cpu, 0);
        X86_AH(cpu) = 0x00u;
        break;
    }

    case TRAP_BIOS_1C: { /* NEC PC-98 Timer BIOS */
        u8 ah = X86_AH(cpu);
        if (ah == 0x00u) {
            u32 dst = ((u32)cpu->sr[X86_ES] << 4) + X86_BX(cpu);
            static const u8 bcd_time[6] = {0x94, 0xB5, 0x25, 0x12, 0x00, 0x00};
            for (int i = 0; i < 6; i++) pc98_wb(dst + (u32)i, bcd_time[i]);
        } else if (ah == 0x02u) {
            M->ram[0x001C] = (u8)X86_BX(cpu);
            M->ram[0x001D] = (u8)(X86_BX(cpu) >> 8);
            M->ram[0x001E] = (u8)cpu->sr[X86_ES];
            M->ram[0x001F] = (u8)(cpu->sr[X86_ES] >> 8);
            M->ram[0x058A] = (u8)X86_CX(cpu);
            M->ram[0x058B] = (u8)(X86_CX(cpu) >> 8);
        }
        break;
    }

    case TRAP_BIOS_1F:
        trap_set_cf(cpu, 0);
        break;

    case TRAP_DOS_20:
        M->dos_ended = 1;
        cpu->halted = 1;
        break;
    case TRAP_DOS_21:
        handle_dos_21(cpu);
        break;
    case TRAP_DOS_29:
        con_put_byte(X86_AL(cpu));
        break;
    case TRAP_MOUSE_33:
        if (X86_AX(cpu) == 0) { X86_AX(cpu) = 0; X86_BX(cpu) = 2; }
        else { X86_AX(cpu) = 0; X86_BX(cpu) = 0; X86_CX(cpu) = 320; X86_DX(cpu) = 200; }
        break;
    case TRAP_EMS_67:
        X86_AH(cpu) = 0x80u; /* No EMS */
        break;
    case TRAP_NEC_DC: { /* NEC MS-DOS Extension (CL=09h '$' string; other subfunctions return AX=0) */
        u8 cl = X86_CL(cpu);
        if (cl == 0x09u) {
            u16 o = X86_DX(cpu);
            for (int i = 0; i < 4096; i++) {
                u8 c = x86_seg_rb(cpu, X86_DS, (u16)(o + (u16)i));
                if (c == '$') break;
                con_put_byte(c);
            }
        } else {
            X86_AX(cpu) = 0;
        }
        break;
    }
    default:
        break;
    }
}

/* ---- Install Clean-Room PC-98 BIOS ROM & BDA (`F800:0000..FFFF:000F`) ---- */
static void install_bios_stub(u8 vec, u16 rom_off, u8 trap_id)
{
    u32 ra = 0xF8000u + (u32)rom_off;
    M->ram[ra + 0] = 0x0Fu;
    M->ram[ra + 1] = 0xFFu;
    M->ram[ra + 2] = trap_id;
    M->ram[ra + 3] = 0xCFu; /* IRET */
    u32 va = (u32)vec * 4u;
    M->ram[va + 0] = (u8)rom_off;
    M->ram[va + 1] = (u8)(rom_off >> 8);
    M->ram[va + 2] = 0x00u;
    M->ram[va + 3] = 0xF8u;
}

static void setup_pc98_hardware(void)
{
    mem_zero(M->ram, sizeof(M->ram));
    mem_zero(M->ext_ram, sizeof(M->ext_ram));
    mem_zero(M->gvram, sizeof(M->gvram));
    mem_zero(M->tvram, sizeof(M->tvram));

    M->a20_mask = 0xFFFFFu;
    M->tvram_on = 1;
    M->gvram_on = 1;
    M->analog_16c = 1;
    M->disp_page = 0;
    M->draw_page = 0;
    M->ff1_20line = M->ff1_col40 = M->ff1_attr_vl = M->ff1_kcg_dot = 0;
    M->vsync_now = M->hblank_tog = 0;
    M->vsync_irq_armed = 1;
    M->cursor_on = 0;
    M->cursor_addr = 0;
    M->gdc_m_r = M->gdc_m_w = M->gdc_s_r = M->gdc_s_w = 0;
    M->grcg_mode = 0;
    M->grcg_idx = 0;
    mem_zero(M->grcg_tile, sizeof(M->grcg_tile));
    M->egc_en = 0;
    mem_zero(M->egc_regs, sizeof(M->egc_regs));
    mem_zero(M->egc_last, sizeof(M->egc_last));
    M->kcg_c1 = M->kcg_c2 = M->kcg_line = 0;
    M->port_c = 0x08u; /* Buzzer OFF at reset */
    M->beep_ph = 0;
    M->pit0_acc = 0;
    mem_zero(M->kb_prev, sizeof(M->kb_prev));
    mem_zero(M->kb_cur, sizeof(M->kb_cur));
    M->kb_sc_r = M->kb_sc_w = 0;
    M->type_r = M->type_w = M->type_hold = 0;
    M->ansi_state = M->ansi_npar = M->ansi_gt = M->sjis_lead = 0;
    M->con_attr = 0xE1u;

    /* Default 16-color NEC PC-9801 palette */
    static const u8 def_pal[16][3] = {
        { 0,  0,  0}, { 0,  0,  7}, { 0,  7,  0}, { 0,  7,  7},
        { 7,  0,  0}, { 7,  0,  7}, { 7,  7,  0}, {10, 10, 10},
        { 5,  5,  5}, { 0,  0, 15}, { 0, 15,  0}, { 0, 15, 15},
        {15,  0,  0}, {15,  0, 15}, {15, 15,  0}, {15, 15, 15}
    };
    for (int i = 0; i < 16; i++) {
        M->anapal[i][0] = def_pal[i][0];
        M->anapal[i][1] = def_pal[i][1];
        M->anapal[i][2] = def_pal[i][2];
    }
    M->digpal[0] = 0x37u; M->digpal[1] = 0x26u; M->digpal[2] = 0x15u; M->digpal[3] = 0x04u;
    update_palettes();
    tvram_clear_screen();

    /* Initialize Master & Slave 8259A PICs */
    mem_zero(&M->pic_m, sizeof(M->pic_m));
    mem_zero(&M->pic_s, sizeof(M->pic_s));
    M->pic_m.vec_base = 0x08u;
    M->pic_m.imr = 0x7Cu; /* IRQ 0 (PIT), IRQ 1 (KBD), IRQ 7 (Cascade) unmasked */
    M->pic_s.vec_base = 0x10u;
    M->pic_s.imr = 0xEFu; /* IRQ 12 (Sound YM2203/2608) unmasked */

    M->pit_reload[0] = 0x6000u;
    M->pit_reload[1] = 0x0998u;
    M->pit_reload[2] = 0x0400u;
    M->pit_rw_mode[0] = M->pit_rw_mode[1] = M->pit_rw_mode[2] = 3;

    /* Default harmless IRET at F800:0010 for all 256 vectors */
    M->ram[0xF8010u] = 0xCFu;
    for (int v = 0; v < 256; v++) {
        M->ram[v * 4 + 0] = 0x10u;
        M->ram[v * 4 + 1] = 0x00u;
        M->ram[v * 4 + 2] = 0x00u;
        M->ram[v * 4 + 3] = 0xF8u;
    }

    /* Reset vector FFFF:0000 -> JMP F800:0000 -> TRAP_IPL_BOOT */
    M->ram[0xFFFF0u + 0] = 0xEAu;
    M->ram[0xFFFF0u + 1] = 0x00u; M->ram[0xFFFF0u + 2] = 0x00u;
    M->ram[0xFFFF0u + 3] = 0x00u; M->ram[0xFFFF0u + 4] = 0xF8u;
    M->ram[0xF8000u + 0] = 0x0Fu; M->ram[0xF8000u + 1] = 0xFFu; M->ram[0xF8000u + 2] = TRAP_IPL_BOOT;

    /* Install clean-room PC-98 BIOS vectors */
    install_bios_stub(0x08u, 0x0100u, TRAP_IRQ0_PIT);
    install_bios_stub(0x09u, 0x0110u, TRAP_IRQ1_KBD);
    install_bios_stub(0x0Au, 0x0120u, TRAP_IRQ2_VBL);
    install_bios_stub(0x18u, 0x0180u, TRAP_BIOS_18);
    install_bios_stub(0x1Bu, 0x01B0u, TRAP_BIOS_1B);
    install_bios_stub(0x1Cu, 0x01C0u, TRAP_BIOS_1C);
    install_bios_stub(0x1Fu, 0x01F0u, TRAP_BIOS_1F);
    install_bios_stub(0x33u, 0x0330u, TRAP_MOUSE_33);
    install_bios_stub(0x67u, 0x0670u, TRAP_EMS_67);

    if (M->dos_hle_active) {
        install_bios_stub(0x20u, 0x0200u, TRAP_DOS_20);
        install_bios_stub(0x21u, 0x0210u, TRAP_DOS_21);
        install_bios_stub(0x29u, 0x0290u, TRAP_DOS_29);
        install_bios_stub(0xDCu, 0x0DC0u, TRAP_NEC_DC);
    }

    /* Copy 8x8 ANK font into ROM at FD800 (standard PC-98 BIOS ANK table) */
    for (int c = 0; c < 256; c++)
        for (int y = 0; y < 8; y++)
            M->ram[0xFD800u + (u32)c * 8u + (u32)y] = M->ank8x8[c][y];

    /* Populate PC-98 BIOS Data Area (0000:0400..05FF) */
    M->ram[0x0400] = 8;      /* 1 MB extended RAM (8 x 128 KB) */
    M->ram[0x0500] = 0x08u;  /* 24 kHz normal CRT */
    M->ram[0x0501] = 0x4Cu;  /* 640 KB conv (4 -> 5*128KB), 400-line CRT, E-plane present, 2.4576 MHz PIT */
    M->ram[0x0522] = 0x02u; M->ram[0x0523] = 0x05u; /* KB_BUF_HEAD = 0502h */
    M->ram[0x0524] = 0x02u; M->ram[0x0525] = 0x05u; /* KB_BUF_TAIL = 0502h */
    M->ram[0x053B] = 15u;    /* 16 lines per text row */
    M->ram[0x053C] = 0x83u;  /* CRT active, 25 lines */
    M->ram[0x054C] = 0x46u;  /* PRXCRT: 16-color analog + GRCG + EGC present */
    M->ram[0x054D] = 0x54u;  /* PRXDUPD: dual 5 MHz uPD7220 + EGC */
    M->ram[0x055C] = (M->disk_kind == 1 || M->disk_kind == 2) ? 0x03u : 0x00u;
    M->ram[0x055D] = (M->disk_kind == 3) ? 0x01u : 0x00u;
    M->ram[0x0584] = M->boot_daua;

    /* Standard DOS handles 0..4 (STDIN, STDOUT, STDERR, STDAUX, STDPRN) */
    mem_zero(M->handles, sizeof(M->handles));
    for (int i = 0; i < 5; i++) { M->handles[i].open = 1; M->handles[i].is_con = 1; M->handles[i].fidx = -1; }

    x86_reset(&M->cpu, 0);
}

/* ---- Built-in Playable NEC PC-9801 640x400 16-Color + GRCG + YM2203 Showcase ---- */
static void build_pc98_showcase(void)
{
    M->dos_hle_active = 0;
    M->boot_daua = 0x90u;
    setup_pc98_hardware();

    /* Print crisp PC-98 HUD onto A0000/A2000 Text VRAM */
    M->con_attr = 0xC1u; /* Yellow */
    M->con_x = 12; M->con_y = 1;
    const char *t1 = "NEC PC-9801VX  640x400 16-COLOR GDC + GRCG + YM2203 OPN";
    for (int i = 0; t1[i]; i++) con_put_byte((u8)t1[i]);
    M->con_attr = 0xA1u; /* Cyan */
    M->con_x = 15; M->con_y = 2;
    const char *t2 = "ARROWS / JOYSTICK: MOVE SHIP    Z / X: PULSE COLOR";
    for (int i = 0; t2[i]; i++) con_put_byte((u8)t2[i]);

    /* Configure a warm 4-operator YM2203 FM synth chord on channels 0, 1, 2 */
    static const u16 notes[3] = {0x1A26u, 0x1B0Au, 0x226Au};
    for (int ch = 0; ch < 3; ch++) {
        ym_write(0, (u8)(0xB0 + ch), 0x3Cu); /* alg=4, fb=7 */
        for (int s = 0; s < 4; s++) {
            ym_write(0, (u8)(0x30 + s * 4 + ch), (s & 1) ? 0x12u : 0x01u);
            ym_write(0, (u8)(0x40 + s * 4 + ch), (s & 1) ? 0x16u : 0x22u);
            ym_write(0, (u8)(0x50 + s * 4 + ch), 0x1Fu);
            ym_write(0, (u8)(0x60 + s * 4 + ch), 0x06u);
            ym_write(0, (u8)(0x70 + s * 4 + ch), 0x02u);
            ym_write(0, (u8)(0x80 + s * 4 + ch), 0x2Au);
        }
        ym_write(0, (u8)(0xA4 + ch), (u8)(notes[ch] >> 8));
        ym_write(0, (u8)(0xA0 + ch), (u8)notes[ch]);
        ym_write(0, 0x28u, (u8)(0xF0u | ch));
    }

    /* Assemble native x86 real-mode showcase program at 1000:0000:
       - Polls VSYNC on Slave GDC port A0h (bit 5)
       - Reads PC-98 joystick/keyboard via BIOS KB_STAT (0000:052A..0539)
       - Uses GRCG TDW (7Ch = 80h, 7Eh x 4) to draw animated 16-color neon horizon bars & player ship
         across A8000 (Blue) ! */
    u32 p = 0x10000u;
    #define EMIT1(b)      do { u8 _b = (u8)(b); M->ram[p++] = _b; } while (0)
    #define EMIT2(w)      do { u16 _w = (u16)(w); EMIT1(_w); EMIT1(_w >> 8); } while (0)

    /* Init state at 0000:0600 (word Xbyte=38, word Y=200, word frame=0) */
    EMIT1(0x31); EMIT1(0xC0);                         /* XOR AX, AX */
    EMIT1(0x8E); EMIT1(0xD8);                         /* MOV DS, AX */
    EMIT1(0xC7); EMIT1(0x06); EMIT2(0x0600); EMIT2(38);
    EMIT1(0xC7); EMIT1(0x06); EMIT2(0x0602); EMIT2(190);
    EMIT1(0xC7); EMIT1(0x06); EMIT2(0x0604); EMIT2(0);
    EMIT1(0xB8); EMIT2(0xA800); EMIT1(0x8E); EMIT1(0xC0); /* MOV ES, A800h */
    EMIT1(0xFB);                                      /* STI */

    u16 loop_top = (u16)(p - 0x10000u);
    /* Wait VSYNC start (IN AL, A0h; TEST AL, 20h; JZ) */
    u16 w1 = (u16)(p - 0x10000u);
    EMIT1(0xE4); EMIT1(0xA0);
    EMIT1(0xA8); EMIT1(0x20);
    EMIT1(0x74); EMIT1((u8)(w1 - (u16)(p + 1u - 0x10000u)));

    /* Increment frame [0604h] and read arrow keys from 0000:0531 (0x3A..0x3D are in group 7: 0x52A+7 = 0x0531!) */
    EMIT1(0xFF); EMIT1(0x06); EMIT2(0x0604);          /* INC WORD [0604h] */
    EMIT1(0xA0); EMIT2(0x0531);                       /* MOV AL, [0531h] (bit2=Up, bit3=Left, bit4=Down, bit5=Right) */
    EMIT1(0x8B); EMIT1(0x1E); EMIT2(0x0600);          /* MOV BX, [0600h] (X byte 2..74) */
    EMIT1(0x8B); EMIT1(0x16); EMIT2(0x0602);          /* MOV DX, [0602h] (Y line 64..360) */
    EMIT1(0xA8); EMIT1(0x08); EMIT1(0x74); EMIT1(0x05); /* TEST AL, 08h (Left); JZ +5 */
    EMIT1(0x83); EMIT1(0xFB); EMIT1(2); EMIT1(0x76); EMIT1(0x01); EMIT1(0x4B); /* CMP BX,2; JBE +1; DEC BX */
    /* Fix jump offset above cleanly using simple masked arithmetic instead: */
    p = 0x10000u + loop_top;

    /* Re-emit clean branchless/short-branch frame body */
    w1 = (u16)(p - 0x10000u);
    EMIT1(0xE4); EMIT1(0xA0);
    EMIT1(0xA8); EMIT1(0x20);
    EMIT1(0x74); EMIT1(0xFA);                         /* JZ -6 */

    EMIT1(0xFF); EMIT1(0x06); EMIT2(0x0604);          /* INC WORD [0604h] */
    EMIT1(0xA0); EMIT2(0x0531);                       /* MOV AL, [0531h] */
    EMIT1(0xA8); EMIT1(0x08); EMIT1(0x74); EMIT1(0x04); EMIT1(0xFF); EMIT1(0x0E); EMIT2(0x0600); /* Left */
    EMIT1(0xA8); EMIT1(0x20); EMIT1(0x74); EMIT1(0x04); EMIT1(0xFF); EMIT1(0x06); EMIT2(0x0600); /* Right */
    EMIT1(0xA8); EMIT1(0x04); EMIT1(0x74); EMIT1(0x05); EMIT1(0x83); EMIT1(0x2E); EMIT2(0x0602); EMIT1(4); /* Up */
    EMIT1(0xA8); EMIT1(0x10); EMIT1(0x74); EMIT1(0x05); EMIT1(0x83); EMIT1(0x06); EMIT2(0x0602); EMIT1(4); /* Down */
    EMIT1(0x83); EMIT1(0x26); EMIT2(0x0600); EMIT1(0x3F); /* AND WORD [0600h], 3Fh */
    EMIT1(0x81); EMIT1(0x26); EMIT2(0x0602); EMIT2(0x00FF);

    /* Enable GRCG TDW (OUT 7Ch, 80h) and paint 320 rows (lines 64..383) of scrolling 16-color synthwave bands! */
    EMIT1(0xB0); EMIT1(0x80); EMIT1(0xE6); EMIT1(0x7C);
    EMIT1(0xBF); EMIT2(64 * 80);                      /* MOV DI, 64*80 */
    EMIT1(0xBA); EMIT2(300);                          /* MOV DX, 300 rows */
    u16 row_loop = (u16)(p - 0x10000u);
    EMIT1(0x8B); EMIT1(0x1E); EMIT2(0x0604);          /* MOV BX, [0604h] (frame) */
    EMIT1(0x01); EMIT1(0xD3);                         /* ADD BX, DX */
    EMIT1(0xC1); EMIT1(0xEB); EMIT1(0x04);            /* SHR BX, 4 -> color 1..15 */
    EMIT1(0x83); EMIT1(0xE3); EMIT1(0x0F);            /* AND BX, 0Fh */
    /* Load 4 GRCG tile planes from BL bits 0..3 (0x00 or 0xFF) */
    for (int pl = 0; pl < 4; pl++) {
        EMIT1(0x30); EMIT1(0xC0);                     /* XOR AL, AL */
        EMIT1(0xF6); EMIT1(0xC3); EMIT1(1u << pl);    /* TEST BL, 1<<pl */
        EMIT1(0x74); EMIT1(0x02); EMIT1(0xB0); EMIT1(0xFF);
        EMIT1(0xE6); EMIT1(0x7E);                     /* OUT 7Eh, AL */
    }
    EMIT1(0xB9); EMIT2(40);                           /* MOV CX, 40 words (80 bytes = 640 px) */
    EMIT1(0xF3); EMIT1(0xAB);                         /* REP STOSW (GRCG TDW fills all 4 planes!) */
    EMIT1(0x4A);                                      /* DEC DX */
    EMIT1(0x75); EMIT1((u8)(row_loop - (u16)(p + 1u - 0x10000u)));

    /* Draw bright white/cyan player craft (color 15: all 4 planes = FFh) at (X=[0600h]+8, Y=64+[0602h]) */
    for (int pl = 0; pl < 4; pl++) { EMIT1(0xB0); EMIT1(0xFF); EMIT1(0xE6); EMIT1(0x7E); }
    EMIT1(0xA1); EMIT2(0x0602);                       /* MOV AX, [0602h] */
    EMIT1(0x05); EMIT2(64);                           /* ADD AX, 64 */
    EMIT1(0xB9); EMIT2(80); EMIT1(0xF7); EMIT1(0xE1); /* MUL CX -> AX = Y * 80 */
    EMIT1(0x03); EMIT1(0x06); EMIT2(0x0600);          /* ADD AX, [0600h] */
    EMIT1(0x05); EMIT2(8);                            /* ADD AX, 8 */
    EMIT1(0x89); EMIT1(0xC7);                         /* MOV DI, AX */
    EMIT1(0xBA); EMIT2(16);                           /* 16 scanlines tall */
    u16 spr_loop = (u16)(p - 0x10000u);
    EMIT1(0x26); EMIT1(0xC7); EMIT1(0x05); EMIT2(0xFFFF);
    EMIT1(0x26); EMIT1(0xC7); EMIT1(0x45); EMIT1(2); EMIT2(0xFFFF);
    EMIT1(0x83); EMIT1(0xC7); EMIT1(80);
    EMIT1(0x4A);
    EMIT1(0x75); EMIT1((u8)(spr_loop - (u16)(p + 1u - 0x10000u)));

    /* Disable GRCG (OUT 7Ch, 00h), HLT until next timer/VBL IRQ, and loop */
    EMIT1(0x30); EMIT1(0xC0); EMIT1(0xE6); EMIT1(0x7C);
    /* Wait VSYNC end so we run once per frame */
    u16 w2 = (u16)(p - 0x10000u);
    EMIT1(0xE4); EMIT1(0xA0);
    EMIT1(0xA8); EMIT1(0x20);
    EMIT1(0x75); EMIT1((u8)(w2 - (u16)(p + 1u - 0x10000u)));
    EMIT1(0xE9); EMIT2(loop_top - (u16)(p + 2u - 0x10000u));

    #undef EMIT1
    #undef EMIT2

    x86_set_sr(&M->cpu, X86_CS, 0x1000u);
    x86_set_sr(&M->cpu, X86_SS, 0x0030u);
    X86_SP(&M->cpu) = 0x0400u;
    M->cpu.ip = 0x0000u;
    M->cpu.flags = 0x0202u;
}

/* ---- Disk Format Detection & Boot Loader ---- */
void pc98_set_font(const u8 *font_rom, u32 size)
{
    ensure_init();
    M->ext_font = font_rom;
    M->ext_font_size = size;
}

void pc98_clear_files(void)
{
    ensure_init();
    M->nfiles = 0;
    M->scratch_used = 0;
    M->cwd[0] = 0;
}

const char *pc98_add_file(const char *name, const u8 *data, u32 size)
{
    ensure_init();
    if (M->nfiles >= MAX_FILES)
        return "too many files in PC-98 archive";
    struct pc98_vfile *vf = &M->files[M->nfiles++];
    mem_zero(vf, sizeof(*vf));
    while (*name == '/' || *name == '\\') name++;
    int p = 0;
    for (; *name && p < 63; name++)
        vf->name[p++] = (*name == '\\') ? '/' : up_ch(*name);
    vf->name[p] = 0;
    vf->data = data;
    vf->size = size;
    return 0;
}

static int find_best_exe_index(void)
{
    /* 1. Check AUTOEXEC.BAT if present */
    int auto_idx = vfile_find("AUTOEXEC.BAT");
    if (auto_idx >= 0 && M->files[auto_idx].size < 2048u) {
        u8 bat[2048];
        int got = vfile_read(auto_idx, 0, bat, M->files[auto_idx].size);
        if (got > 0) {
            bat[got] = 0;
            int i = 0;
            while (i < got) {
                while (i < got && (bat[i] == ' ' || bat[i] == '\t' || bat[i] == '@')) i++;
                char line[80];
                int lp = 0;
                while (i < got && bat[i] != '\r' && bat[i] != '\n') {
                    if (lp < 78) line[lp++] = (char)bat[i];
                    i++;
                }
                line[lp] = 0;
                while (i < got && (bat[i] == '\r' || bat[i] == '\n')) i++;
                if (!lp) continue;
                /* Handle "CD DIR" */
                if ((up_ch(line[0]) == 'C' && up_ch(line[1]) == 'D' && (line[2] == ' ' || line[2] == '\\'))) {
                    const char *arg = line + 2;
                    while (*arg == ' ') arg++;
                    char norm[64];
                    dos_norm_path(arg, norm);
                    for (int k = 0; k < 63; k++) { M->cwd[k] = norm[k]; if (!norm[k]) break; }
                    continue;
                }
                /* Skip ECHO / SET / REM / CLS / PAUSE / PATH */
                char cmd[16];
                int cp = 0;
                while (line[cp] && line[cp] != ' ' && line[cp] != '\t' && cp < 15) { cmd[cp] = up_ch(line[cp]); cp++; }
                cmd[cp] = 0;
                if (ci_eq(cmd, "ECHO") || ci_eq(cmd, "ECHO\\") || ci_eq(cmd, "SET") ||
                    ci_eq(cmd, "REM")  || ci_eq(cmd, "CLS")   || ci_eq(cmd, "PAUSE") || ci_eq(cmd, "PATH"))
                    continue;
                char try_exe[64];
                int tp = 0;
                for (; cmd[tp] && tp < 56; tp++) try_exe[tp] = cmd[tp];
                try_exe[tp] = 0;
                int f = vfile_find(try_exe);
                if (f < 0) {
                    try_exe[tp] = '.'; try_exe[tp+1] = 'E'; try_exe[tp+2] = 'X'; try_exe[tp+3] = 'E'; try_exe[tp+4] = 0;
                    f = vfile_find(try_exe);
                }
                if (f < 0) {
                    try_exe[tp] = '.'; try_exe[tp+1] = 'C'; try_exe[tp+2] = 'O'; try_exe[tp+3] = 'M'; try_exe[tp+4] = 0;
                    f = vfile_find(try_exe);
                }
                if (f >= 0 && !M->files[f].is_dir)
                    return f;
            }
        }
    }

    /* 2. Score all .EXE / .COM files (prefer largest game .EXE, deprioritize setup/config/font tools) */
    int best = -1, best_sc = -1;
    for (u32 i = 0; i < M->nfiles; i++) {
        if (M->files[i].is_dir) continue;
        const char *nm = M->files[i].name;
        int is_exe = ci_ends(nm, ".EXE");
        int is_com = ci_ends(nm, ".COM");
        if (!is_exe && !is_com) continue;
        if (ci_ends(nm, "COMMAND.COM")) continue;
        int sc = is_exe ? 1000 : 500;
        if (ci_ends(nm, "SETUP.EXE") || ci_ends(nm, "CONFIG.EXE") || ci_ends(nm, "INSTALL.EXE") ||
            ci_ends(nm, "FONTED.EXE") || ci_ends(nm, "FONTTEST.EXE") || ci_ends(nm, "POROSCR.EXE"))
            sc = 50;
        sc += (int)(M->files[i].size >> 9);
        if (sc > best_sc) { best_sc = sc; best = (int)i; }
    }
    return best;
}

const char *pc98_load(const u8 *image, u32 size, const char *path)
{
    ensure_init();
    opn_init_tables();
    build_cgrom();

    M->sample_rate = 48000u;
    M->snd_head = M->snd_tail = M->snd_frac = 0;
    M->frames = 0;
    M->dirty_next = 0;
    mem_zero(M->dirty_valid, sizeof(M->dirty_valid));
    mem_zero(M->fm, sizeof(M->fm));
    mem_zero(M->ym_regs, sizeof(M->ym_regs));
    M->ym_regs[0][0x07] = 0xBFu;
    M->ym_status = 0;
    M->disk_img = 0;
    M->disk_size = 0;
    M->disk_kind = 0;
    M->fat_mounted = 0;

    /* 1. Built-in NEC PC-9801 showcase when invoked with empty path "" */
    if ((!path || !*path) && M->nfiles == 0 && size == 0) {
        build_pc98_showcase();
        put_s(M->info, M->info + sizeof(M->info) - 1,
              "NEC PC-9801VX Built-in Showcase (640x400 16c GDC + GRCG + YM2203 OPN)");
        return 0;
    }

    /* 2. Multi-file archive or standalone .EXE / .COM */
    if (M->nfiles > 0 || ci_ends(path, ".exe") || ci_ends(path, ".com")) {
        if (M->nfiles == 0) {
            if (!image || size < 2u) return "empty PC-98 program";
            const char *bn = path ? path : "GAME.EXE";
            for (const char *q = bn; *q; q++) if (*q == '/' || *q == '\\' || *q == ':') bn = q + 1;
            (void)pc98_add_file(bn, image, size);
        }
        M->dos_hle_active = 1;
        M->boot_daua = 0x90u;
        setup_pc98_hardware();
        int exe_idx = find_best_exe_index();
        if (exe_idx < 0)
            return "no PC-98 .EXE or .COM executable found";
        const char *why = dos_exec_vfile(exe_idx);
        if (why) return why;
        char *p = put_s(M->info, M->info + sizeof(M->info) - 1, "NEC PC-9801 DOS: ");
        p = put_s(p, M->info + sizeof(M->info) - 1, M->files[exe_idx].name);
        p = put_s(p, M->info + sizeof(M->info) - 1, " (");
        p = put_u(p, M->info + sizeof(M->info) - 1, (M->files[exe_idx].size + 1023u) >> 10);
        put_s(p, M->info + sizeof(M->info) - 1, " KB, 640x400 GDC + OPN)");
        return 0;
    }

    if (!image || size < 1024u)
        return "PC-98 disk image too small";

    M->disk_img = image;
    M->disk_size = size;
    M->nfiles = 0;
    M->scratch_used = 0;

    /* 3. Identify disk container: .fdi, .hdi, .d88/.d98, or raw .hdm/.xdf/.2hd/.img */
    if (ci_ends(path, ".hdi") || (size > 0x200000u && rd_le32(image + 8) == 0x1000u && rd_le32(image + 16) <= 1024u)) {
        M->disk_kind = 3;
        M->boot_daua = 0x80u;
        u32 hsz = rd_le32(image + 8);
        if (hsz >= 256u && hsz <= 0x4000u && rd_le32(image + 16) >= 256u) {
            M->disk_hdr    = hsz;
            M->disk_sec_sz = rd_le32(image + 16);
            M->disk_spt    = rd_le32(image + 20);
            M->disk_heads  = rd_le32(image + 24);
            M->disk_cyls   = rd_le32(image + 28);
        } else {
            M->disk_hdr    = 0;
            M->disk_sec_sz = 512u;
            M->disk_spt    = 33u;
            M->disk_heads  = 8u;
            M->disk_cyls   = size / (512u * 33u * 8u);
        }
    } else if (ci_ends(path, ".d88") || ci_ends(path, ".d98") ||
               (size >= 0x2B0u && rd_le32(image + 0x1C) == size && rd_le32(image + 0x20) >= 0x2B0u)) {
        M->disk_kind = 2;
        M->boot_daua = 0x90u;
        M->disk_sec_sz = 1024u;
        M->disk_spt = 8u; M->disk_heads = 2u; M->disk_cyls = 77u;
        for (int t = 0; t < 164; t++)
            M->d88_trk_off[t] = rd_le32(image + 0x20u + (u32)t * 4u);
        if (M->d88_trk_off[0] && M->d88_trk_off[0] + 16u <= size) {
            u16 dsz = rd_le16(image + M->d88_trk_off[0] + 14u);
            u16 nsec = rd_le16(image + M->d88_trk_off[0] + 4u);
            if (dsz == 512u && nsec >= 8u) M->boot_daua = 0x70u;
            if (dsz) M->disk_sec_sz = dsz;
            if (nsec) M->disk_spt = nsec;
        }
    } else if (ci_ends(path, ".fdi") || (size > 0x1000u && rd_le32(image + 8) == 0x1000u &&
               (rd_le32(image + 16) == 1024u || rd_le32(image + 16) == 512u))) {
        M->disk_kind = 1;
        M->disk_hdr    = rd_le32(image + 8);
        M->disk_sec_sz = rd_le32(image + 16);
        M->disk_spt    = rd_le32(image + 20);
        M->disk_heads  = rd_le32(image + 24);
        M->disk_cyls   = rd_le32(image + 28);
        M->boot_daua   = (M->disk_sec_sz == 512u && M->disk_spt <= 9u) ? 0x70u : 0x90u;
    } else {
        /* Raw floppy sector image (.hdm, .xdf, .2hd, .dup, .img) */
        M->disk_kind = 1;
        M->disk_hdr  = 0;
        if (size == 1261568u || size == 1265664u) {
            if (size == 1265664u) M->disk_hdr = 4096u;
            M->disk_sec_sz = 1024u; M->disk_spt = 8u; M->disk_heads = 2u; M->disk_cyls = 77u; M->boot_daua = 0x90u;
        } else if (size == 1228800u) {
            M->disk_sec_sz = 512u; M->disk_spt = 15u; M->disk_heads = 2u; M->disk_cyls = 80u; M->boot_daua = 0x90u;
        } else if (size == 1474560u) {
            M->disk_sec_sz = 512u; M->disk_spt = 18u; M->disk_heads = 2u; M->disk_cyls = 80u; M->boot_daua = 0x90u;
        } else if (size == 655360u) {
            M->disk_sec_sz = 512u; M->disk_spt = 8u; M->disk_heads = 2u; M->disk_cyls = 80u; M->boot_daua = 0x70u;
        } else if (size == 737280u) {
            M->disk_sec_sz = 512u; M->disk_spt = 9u; M->disk_heads = 2u; M->disk_cyls = 80u; M->boot_daua = 0x70u;
        } else {
            M->disk_sec_sz = 1024u; M->disk_spt = 8u; M->disk_heads = 2u;
            M->disk_cyls = size / (1024u * 16u);
            if (!M->disk_cyls) return "unsupported PC-98 disk geometry";
            M->boot_daua = 0x90u;
        }
    }

    /* 4. Check if the disk is a non-bootable FAT12/FAT16 data disk (like panic24.hdm):
          if it has a valid FAT BPB and NO IO.SYS / MSDOS.SYS / KERNEL.SYS, launch its game directly via PC-98 DOS HLE!
          Otherwise (FreeDOS(98) fd98_2hd_p24.img, bootable MS-DOS, or custom booter), boot natively via IPL! */
    if (M->disk_kind == 1 || M->disk_kind == 3) {
        u8 bsec[1024];
        u32 part_off = 0;
        if (M->disk_kind == 3 && disk_read_lba_sec(0, bsec, M->disk_sec_sz) == 0) {
            /* Check PC-98 HDD partition table at +0x200 if sector >= 512, or sector 1 if 256B */
            u8 psec[1024];
            const u8 *pt = 0;
            if (M->disk_sec_sz >= 512u) pt = bsec + 0x200u;
            else if (disk_read_lba_sec(2, psec, M->disk_sec_sz) == 0) pt = psec;
            if (pt && pt[0]) {
                u32 scyl = rd_le16(pt + 10);
                u32 shd  = pt[9];
                u32 ssec = pt[8];
                u32 plba = (scyl * M->disk_heads + shd) * M->disk_spt + ssec;
                part_off = plba * M->disk_sec_sz;
            }
        }
        u32 blba = part_off / M->disk_sec_sz;
        if (disk_read_lba_sec(blba, bsec, M->disk_sec_sz) == 0) {
            u16 bps   = rd_le16(bsec + 11);
            u8  spc   = bsec[13];
            u16 res   = rd_le16(bsec + 14);
            u8  nfats = bsec[16];
            u16 ndir  = rd_le16(bsec + 17);
            u16 tot16 = rd_le16(bsec + 19);
            u16 spf   = rd_le16(bsec + 22);
            u32 tot   = tot16 ? tot16 : rd_le32(bsec + 32);
            if ((bps == 256u || bps == 512u || bps == 1024u) &&
                spc >= 1u && (spc & (spc - 1u)) == 0 && nfats >= 1u && nfats <= 2u &&
                ndir >= 16u && ndir <= 1024u && spf >= 1u) {
                M->fat_mounted = 1;
                M->fat_part_off = part_off;
                M->fat_bps = bps; M->fat_spc = spc; M->fat_res = res;
                M->fat_nfats = nfats; M->fat_ndir = ndir; M->fat_spf = spf;
                M->fat_root_off = (u32)(res + (u32)nfats * spf) * bps;
                M->fat_data_off = M->fat_root_off + (u32)ndir * 32u;
                u32 nclus = (tot * bps > M->fat_data_off) ? ((tot * bps - M->fat_data_off) / ((u32)spc * bps)) : 0u;
                M->fat_is16 = (nclus >= 4085u) ? 1 : 0;

                fat_scan_dir(0, "");
                int has_os = (vfile_find("IO.SYS") >= 0 || vfile_find("IBMBIO.COM") >= 0 ||
                              vfile_find("KERNEL.SYS") >= 0 || vfile_find("MSDOS.SYS") >= 0);
                if (!has_os && M->nfiles > 0) {
                    int exe_idx = find_best_exe_index();
                    if (exe_idx >= 0) {
                        M->dos_hle_active = 1;
                        setup_pc98_hardware();
                        const char *why = dos_exec_vfile(exe_idx);
                        if (!why) {
                            char *p = put_s(M->info, M->info + sizeof(M->info) - 1, "NEC PC-9801 Disk (DOS HLE): ");
                            p = put_s(p, M->info + sizeof(M->info) - 1, M->files[exe_idx].name);
                            put_s(p, M->info + sizeof(M->info) - 1, " (640x400 GDC + OPN)");
                            return 0;
                        }
                    }
                }
            }
        }
    }

    /* 5. Native NEC PC-9801 IPL Hardware Boot (FreeDOS(98), MS-DOS system disks, and raw PC-98 booter games) */
    M->dos_hle_active = 0;
    setup_pc98_hardware();
    char *p = put_s(M->info, M->info + sizeof(M->info) - 1,
                    M->disk_kind == 3 ? "NEC PC-9801 SASI HDD (" : "NEC PC-9801 FDD (");
    p = put_u(p, M->info + sizeof(M->info) - 1, size >> 10);
    put_s(p, M->info + sizeof(M->info) - 1, " KB, Native IPL + 640x400 GDC + OPN)");
    return 0;
}

void pc98_reset(void)
{
    ensure_init();
    setup_pc98_hardware();
}

/* ---- Fast 640x400 16-color GVRAM + 80x25 Text/KCG Scanout ---- */
static const u16 nibble_expand[16] = {
    0x0000, 0x1000, 0x0100, 0x1100,
    0x0010, 0x1010, 0x0110, 0x1110,
    0x0001, 0x1001, 0x0101, 0x1101,
    0x0011, 0x1011, 0x0111, 0x1111
};

static void __attribute__((optimize("O3"))) pc98_render(u16 *pic)
{
    /* Pass 1: 640x400 4-plane 16-color GVRAM (32-pixel uniform-word fast path + 32-bit word loads) */
    if (M->gvram_on) {
        u8 pg = M->disp_page & 1u;
        const u32 *pB32 = (const u32 *)M->gvram[pg][0];
        const u32 *pR32 = (const u32 *)M->gvram[pg][1];
        const u32 *pG32 = (const u32 *)M->gvram[pg][2];
        const u32 *pE32 = (const u32 *)M->gvram[pg][3];
        const u16 *pal = M->pal15;
        u32 *out32 = (u32 *)pic;

        for (u32 w = 0; w < 8000u; w++, out32 += 16) {
            u32 b32 = pB32[w], r32 = pR32[w], g32 = pG32[w], e32 = pE32[w];
            if (__builtin_expect((((b32 + 1u) | (r32 + 1u) | (g32 + 1u) | (e32 + 1u)) <= 1u), 1)) {
                u32 ci = (b32 & 1u) | ((r32 & 1u) << 1) | ((g32 & 1u) << 2) | ((e32 & 1u) << 3);
                u32 pair = (u32)pal[ci] | ((u32)pal[ci] << 16);
                out32[0] = out32[1] = out32[2] = out32[3] = pair;
                out32[4] = out32[5] = out32[6] = out32[7] = pair;
                out32[8] = out32[9] = out32[10] = out32[11] = pair;
                out32[12] = out32[13] = out32[14] = out32[15] = pair;
                continue;
            }
            for (int byte_i = 0; byte_i < 4; byte_i++) {
                u32 b = b32 & 0xFFu, r = r32 & 0xFFu, g = g32 & 0xFFu, e = e32 & 0xFFu;
                b32 >>= 8; r32 >>= 8; g32 >>= 8; e32 >>= 8;
                u32 hi = (u32)nibble_expand[b >> 4]
                       | ((u32)nibble_expand[r >> 4] << 1)
                       | ((u32)nibble_expand[g >> 4] << 2)
                       | ((u32)nibble_expand[e >> 4] << 3);
                u32 lo = (u32)nibble_expand[b & 15u]
                       | ((u32)nibble_expand[r & 15u] << 1)
                       | ((u32)nibble_expand[g & 15u] << 2)
                       | ((u32)nibble_expand[e & 15u] << 3);
                u32 *d = out32 + byte_i * 4;
                d[0] = (u32)pal[hi & 15u]        | ((u32)pal[(hi >> 4) & 15u] << 16);
                d[1] = (u32)pal[(hi >> 8) & 15u] | ((u32)pal[hi >> 12] << 16);
                d[2] = (u32)pal[lo & 15u]        | ((u32)pal[(lo >> 4) & 15u] << 16);
                d[3] = (u32)pal[(lo >> 8) & 15u] | ((u32)pal[lo >> 12] << 16);
            }
        }
    } else {
        u32 *out32 = (u32 *)pic;
        for (u32 i = 0; i < (640u * 400u) / 2u; i++)
            out32[i] = 0;
    }

    /* Pass 2: 80x25 Text + Kanji/Gaiji Overlay (skips empty space cells in 3 instructions!) */
    if (!M->tvram_on)
        return;

    int blink_off = (M->frames & 16u) != 0;
    for (int row = 0; row < 25; row++) {
        u16 *row_base = pic + row * 16 * 640;
        int cell_base = row * 80;
        for (int col = 0; col < 80; col++) {
            int idx = (cell_base + col) * 2;
            u8 attr = M->tvram[0x2000 + idx];
            if (!(attr & 0x01u)) continue; /* ~ST = 0: secret/hidden */

            u8 c_lo = M->tvram[idx];
            u8 c_hi = M->tvram[idx + 1];
            int is_cur = M->cursor_on && !blink_off && ((u16)(cell_base + col) == M->cursor_addr);
            int rev = ((attr & 0x04u) != 0) ^ is_cur;
            int ul  = (attr & 0x08u) != 0;
            int vl  = M->ff1_attr_vl && ((attr & 0x10u) != 0);

            if (c_hi == 0 && (c_lo == 0 || c_lo == 0x20u) && !rev && !ul && !vl)
                continue;

            u16 fg = M->tpal15[(attr >> 5) & 7u];
            int hide_glyph = ((attr & 0x02u) != 0) && blink_off;

            const u8 *gptr = 0;
            int step = 1;
            if (c_hi == 0) {
                gptr = M->ank8x16[c_lo];
                step = 1;
            } else {
                u8 c1 = c_lo & 0x7Fu;
                int right = (c_lo & 0x80u) != 0;
                if (c1 >= 0x60u) c1 -= 0x20u;
                u8 c2 = (c_hi >= 0x20u) ? (u8)(c_hi - 0x20u) : 0u;
                if (c1 < 96u && c2 < 96u) {
                    gptr = &M->kcg[c1][c2][right ? 1 : 0];
                    step = 2;
                }
            }

            u16 *dst = row_base + col * 8;
            for (int y = 0; y < 16; y++, dst += 640) {
                u8 bits = (gptr && !hide_glyph) ? gptr[y * step] : 0u;
                if (ul && y == 15) bits = 0xFFu;
                if (vl)            bits |= 0x01u;
                if (!rev) {
                    if (!bits) continue;
                    if (bits & 0x80u) dst[0] = fg;
                    if (bits & 0x40u) dst[1] = fg;
                    if (bits & 0x20u) dst[2] = fg;
                    if (bits & 0x10u) dst[3] = fg;
                    if (bits & 0x08u) dst[4] = fg;
                    if (bits & 0x04u) dst[5] = fg;
                    if (bits & 0x02u) dst[6] = fg;
                    if (bits & 0x01u) dst[7] = fg;
                } else {
                    dst[0] = (bits & 0x80u) ? 0 : fg;
                    dst[1] = (bits & 0x40u) ? 0 : fg;
                    dst[2] = (bits & 0x20u) ? 0 : fg;
                    dst[3] = (bits & 0x10u) ? 0 : fg;
                    dst[4] = (bits & 0x08u) ? 0 : fg;
                    dst[5] = (bits & 0x04u) ? 0 : fg;
                    dst[6] = (bits & 0x02u) ? 0 : fg;
                    dst[7] = (bits & 0x01u) ? 0 : fg;
                }
            }
        }
    }
}

/* ---- Frame Execution ---- */
void pc98_frame(u16 pad, u16 *picture)
{
    ensure_init();
    kb_update_frame(pad);

    M->cpu.cycles = 0;
    s32 cur_target = 0;
    s32 pit0_period = (s32)(M->pit_reload[0] ? M->pit_reload[0] : 0x10000u) * 4;
    if (pit0_period < 512) pit0_period = 512;

    for (int line = 0; line < PC98_LINES; line++) {
        if (line == 0) {
            M->vsync_now = 0;
        } else if (line == 400) {
            M->vsync_now = 1;
            if (M->vsync_irq_armed) {
                M->vsync_irq_armed = 0;
                pic_raise_m(2); /* VSYNC IRQ 2 -> INT 0Ah */
            }
        }

        pic_step();
        cur_target += PC98_CYC_LINE;
        if (!M->dos_ended) {
            if (M->cpu.halted && ((M->pic_m.irr & (u8)~M->pic_m.imr) || (M->pic_s.irr & (u8)~M->pic_s.imr)))
                M->cpu.halted = 0;
            x86_run(&M->cpu, cur_target);
        }

        /* Advance PIT Ch 0 -> IRQ 0 (INT 08h) */
        M->pit0_acc += PC98_CYC_LINE;
        if (M->pit0_acc >= pit0_period) {
            M->pit0_acc -= pit0_period;
            pic_raise_m(0);
        }

        /* Advance YM2203 / YM2608 Timers -> IRQ 12 (INT 14h) */
        ym_timers_step(PC98_CYC_LINE);

        /* Generate 48 kHz audio samples (~850.8 samples per 56.42 Hz frame) */
        if (M->sample_rate > 0) {
            M->snd_frac += M->sample_rate;
            while (M->snd_frac >= (u32)(PC98_LINES * 56u + 185u)) {
                M->snd_frac -= (u32)(PC98_LINES * 56u + 185u);
                s16 s = pc98_synth_sample();
                u32 nh = (M->snd_head + 1u) & (SND_RING - 1u);
                if (nh != M->snd_tail) {
                    M->snd_ring[M->snd_head] = s;
                    M->snd_head = nh;
                }
            }
        }
    }

    if (picture)
        pc98_render(picture);

    M->frames++;
}

const char *pc98_info(void) { ensure_init(); return M->info; }

u8 *pc98_save_ram(u32 *size, int *battery)
{
    *size = 0;
    *battery = 0;
    return M->ram;
}

int pc98_save_changed(void) { return 0; }
int pc98_jammed(void) { return 0; }

void pc98_audio_rate(u32 hz)
{
    ensure_init();
    M->sample_rate = hz;
}

int pc98_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && M->snd_tail != M->snd_head) {
        out[n++] = M->snd_ring[M->snd_tail];
        M->snd_tail = (M->snd_tail + 1u) & (SND_RING - 1u);
    }
    return n;
}
