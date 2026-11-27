/* Atari Jaguar 64-Bit Interactive Multimedia System Emulator: see jaguar.h.
   Zero static .bss (68000 + optab, Tom GPU RISC, Jerry DSP RISC, Blitter,
   Object Processor, 65,536-entry CRY->RGB555 LUT & 48 kHz audio ring live in
   EMU_RAM_PHYS; 2 MB 64-bit DRAM lives at 0x03580000; 6 MB Cart ROM at 0x05800000). */
#include "jaguar.h"
#include "font5x7.h"

#ifndef JAGUAR_HOST
#include "hw.h"
#endif

typedef signed char s8;
#ifdef JAGUAR_HOST
typedef unsigned long long u64;
#endif
#define INLINE static inline __attribute__((always_inline))

#define JAG_SND_RING    8192
#define JAG_DRAM_SIZE   0x00200000u     /* 2 MB 64-bit Jaguar DRAM */
#define JAG_ROM_CAP     0x00600000u     /* 6 MB Jaguar Cartridge Space ($800000..$DFFFFF) */

/* Jaguar 32-bit RISC Processor (shared by Tom GPU @ $F02100 & Jerry DSP @ $F1A100) */
struct jag_risc {
    u32 r[64];              /* Two banks of 32 x 32-bit registers (bank 0: 0..31, bank 1: 32..63) */
    u32 pc;
    u32 flags;              /* b0=Z, b1=C, b2=N, b14=REGPAGE */
    u32 ctrl;               /* b0=GO */
    u32 mtxc, mtxa;
    u32 hidata, remain;
    s32 acc_lo, acc_hi;     /* 64-bit MAC accumulator (pure 32-bit split) */
    u8  is_dsp;
};

/* Jaguar Jerry 4-Voice Wavetable / PCM Synth Assist (alongside Jerry I2S LTXD/RTXD) */
struct jag_voice {
    u32 phase, inc;
    u32 addr, end;
    u8  vol, wave, active;
};

struct jaguar_state {
    u8  jammed, eeprom_dirty;
    int scr_w, scr_h;
    u16 pad1, pad2;
    u32 rom_size, boot_entry;
    u32 frame_no;

    /* Tom Video & Interrupt Registers ($F00000..$F002FF) */
    u16 memcon1, memcon2, hc, vc;
    u16 vmode;              /* b0=vid_en, b1..2=mode (0=16b CRY, 1=24b, 2=16b direct, 3=16b RGB) */
    u16 bord1, bord2;
    u32 olp;                /* Object List Pointer (24-bit DRAM byte address) */
    u16 int1, int2;         /* $F000E0: b0=VBlank, b1=GPU, b2=OP_Y, b3=Timer */
    u16 pit0, pit1;
    s32 pit_cnt;
    u16 joy_latch;          /* $F14000 column strobe */

    /* Tom 64-bit Hardware Blitter Registers ($F02200..$F0229B) */
    u32 a1_base, a1_flags, a1_clip, a1_pixel, a1_step, a1_fstep, a1_fpixel, a1_inc, a1_finc;
    u32 a2_base, a2_flags, a2_mask, a2_pixel, a2_step;
    u32 b_cmd, b_count;
    u32 b_srcd[2], b_dstd[2], b_dstz[2], b_srcz1[2], b_srcz2[2], b_patd[2];
    u32 b_iinc, b_zinc, b_stop;
    u32 b_i[4], b_z[4];

    /* Jerry Timers & I2S DAC ($F10000..$F1A1FF) */
    u16 jpit[4];
    s16 dac_l, dac_r;
    struct jag_voice voices[4];
    u32 sample_rate;
    u32 snd_head, snd_tail;

    char info[96];
};

static void jag_iack(u32 level);
#define M68K_IACK(level) jag_iack(level)

#define M68K_EXTERNAL_STATE                                                     \
    struct jaguar_mem {                                                         \
        struct jaguar_state st;                                                 \
        struct m68k m_cpu;                                                      \
        u8 *m_rmap[256];                                                        \
        u8 *m_wmap[256];                                                        \
        u8  m_optab[65536];                                                     \
        struct jag_risc gpu;                                                    \
        struct jag_risc dsp;                                                    \
        u8  gpu_ram[0x1000] __attribute__((aligned(4))); /* 4 KB $F03000 */     \
        u8  dsp_ram[0x2000] __attribute__((aligned(4))); /* 8 KB $F1B000 */     \
        u8  boot_rom[0x2000] __attribute__((aligned(4)));/* 8 KB $E00000 */     \
        u16 clut[256];                                  /* $F00400 CLUT */      \
        u16 cry_lut[65536];                             /* 16b CRY->RGB555 */   \
        u8  eeprom[128];                                /* 93C46 .sav */        \
        s16 snd_ring[JAG_SND_RING];                                             \
    };                                                                          \
    JAG_MEM_BIND

#ifdef JAGUAR_HOST
#define JAG_MEM_BIND static struct jaguar_mem jag_host_mem;
static u8 jag_host_dram[JAG_DRAM_SIZE] __attribute__((aligned(4)));
static u8 jag_host_rom[JAG_ROM_CAP] __attribute__((aligned(4)));
#define M           (&jag_host_mem)
#define DRAM_BUF    jag_host_dram
#define ROM_BUF     jag_host_rom
#else
#define JAG_MEM_BIND
/* Physical layout during jaguar_play:
   0x03400000..0x0357FFFF (1.5 MB) : struct jaguar_mem M (~245 KB, 0 B static .bss!)
   0x03580000..0x0377FFFF (2.0 MB) : DRAM_BUF (2 MB 64-bit Jaguar DRAM)
   0x05800000..0x05DFFFFF (6.0 MB) : ROM_BUF  (6 MB Jaguar Cartridge Space) */
#define M           ((struct jaguar_mem *)KSEG0(EMU_RAM_PHYS))
#define DRAM_BUF    ((u8 *)KSEG0(0x03580000u))
#define ROM_BUF     ((u8 *)KSEG0(0x05800000u))
#endif

#define S     (M->st)
#define m     (M->m_cpu)
#define rmap  (M->m_rmap)
#define wmap  (M->m_wmap)
#define optab (M->m_optab)

#pragma GCC optimize("O2")
#include "m68k.inc"

#ifndef JAGUAR_HOST
_Static_assert(sizeof(struct jaguar_mem) <= 0x00180000u, "jaguar_mem exceeds 1.5 MB slot");
#endif

static void jag_zero(void *p, u32 n)
{
    u8 *b = (u8 *)p;
    for (u32 i = 0; i < n; i++) b[i] = 0;
}

/* ---- Atari Official 16x16 CRY Chroma Matrix -> 0BBBBBGGGGGRRRRR LUT ---- */
static void jag_init_cry_lut(void)
{
    static const u8 red_c[16][16] = {
        {  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0},
        { 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 19,  0},
        { 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 64, 43, 21,  0},
        {102,102,102,102,102,102,102,102,102,102,102, 95, 71, 47, 23,  0},
        {135,135,135,135,135,135,135,135,135,135,130,104, 78, 52, 26,  0},
        {169,169,169,169,169,169,169,169,169,170,141,113, 85, 56, 28,  0},
        {203,203,203,203,203,203,203,203,203,183,153,122, 91, 61, 30,  0},
        {237,237,237,237,237,237,237,237,230,197,164,131, 98, 65, 32,  0},
        {255,255,255,255,255,255,255,255,247,214,181,148,115, 82, 49, 17},
        {255,255,255,255,255,255,255,255,255,235,204,173,143,112, 81, 51},
        {255,255,255,255,255,255,255,255,255,255,227,198,170,141,113, 85},
        {255,255,255,255,255,255,255,255,255,255,249,223,197,171,145,119},
        {255,255,255,255,255,255,255,255,255,255,255,248,224,200,177,153},
        {255,255,255,255,255,255,255,255,255,255,255,255,252,230,208,187},
        {255,255,255,255,255,255,255,255,255,255,255,255,255,255,240,221},
        {255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255}
    };
    static const u8 grn_c[16][16] = {
        {  0, 17, 34, 51, 68, 85,102,119,136,153,170,187,204,221,238,255},
        {  0, 19, 38, 57, 77, 96,115,134,154,173,192,211,231,250,255,255},
        {  0, 21, 43, 64, 86,107,129,150,172,193,215,236,255,255,255,255},
        {  0, 23, 47, 71, 95,119,142,166,190,214,238,255,255,255,255,255},
        {  0, 26, 52, 78,104,130,156,182,208,234,255,255,255,255,255,255},
        {  0, 28, 56, 85,113,141,170,198,226,255,255,255,255,255,255,255},
        {  0, 30, 61, 91,122,153,183,214,244,255,255,255,255,255,255,255},
        {  0, 32, 65, 98,131,164,197,230,255,255,255,255,255,255,255,255},
        {  0, 32, 65, 98,131,164,197,230,255,255,255,255,255,255,255,255},
        {  0, 30, 61, 91,122,153,183,214,244,255,255,255,255,255,255,255},
        {  0, 28, 56, 85,113,141,170,198,226,255,255,255,255,255,255,255},
        {  0, 26, 52, 78,104,130,156,182,208,234,255,255,255,255,255,255},
        {  0, 23, 47, 71, 95,119,142,166,190,214,238,255,255,255,255,255},
        {  0, 21, 43, 64, 86,107,129,150,172,193,215,236,255,255,255,255},
        {  0, 19, 38, 57, 77, 96,115,134,154,173,192,211,231,250,255,255},
        {  0, 17, 34, 51, 68, 85,102,119,136,153,170,187,204,221,238,255}
    };
    static const u8 blu_c[16][16] = {
        {255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255},
        {255,255,255,255,255,255,255,255,255,255,255,255,255,255,240,221},
        {255,255,255,255,255,255,255,255,255,255,255,255,252,230,208,187},
        {255,255,255,255,255,255,255,255,255,255,255,248,224,200,177,153},
        {255,255,255,255,255,255,255,255,255,255,249,223,197,171,145,119},
        {255,255,255,255,255,255,255,255,255,255,227,198,170,141,113, 85},
        {255,255,255,255,255,255,255,255,255,235,204,173,143,112, 81, 51},
        {255,255,255,255,255,255,255,255,247,214,181,148,115, 82, 49, 17},
        {237,237,237,237,237,237,237,237,230,197,164,131, 98, 65, 32,  0},
        {203,203,203,203,203,203,203,203,203,183,153,122, 91, 61, 30,  0},
        {169,169,169,169,169,169,169,169,169,170,141,113, 85, 56, 28,  0},
        {135,135,135,135,135,135,135,135,135,135,130,104, 78, 52, 26,  0},
        {102,102,102,102,102,102,102,102,102,102,102, 95, 71, 47, 23,  0},
        { 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 64, 43, 21,  0},
        { 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 34, 19,  0},
        {  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0}
    };

    for (u32 cry = 0; cry < 65536u; cry++) {
        u32 c = (cry >> 12) & 15u;
        u32 r = (cry >> 8)  & 15u;
        u32 y = cry & 0xFFu;
        u32 rr = ((u32)red_c[c][r] * y) >> 11;
        u32 gg = ((u32)grn_c[c][r] * y) >> 11;
        u32 bb = ((u32)blu_c[c][r] * y) >> 11;
        M->cry_lut[cry] = (u16)((bb << 10) | (gg << 5) | rr);
    }
}

/* Convert Jaguar 16-bit RGB (RRRRR BBBBB GGGGG x) -> 0BBBBBGGGGGRRRRR */
INLINE u16 jag_rgb16_to_15(u16 w)
{
    u32 r = (w >> 11) & 31u;
    u32 b = (w >> 6)  & 31u;
    u32 g = (w >> 1)  & 31u;
    return (u16)((b << 10) | (g << 5) | r);
}

/* ---- Unified Big-Endian Memory Helpers (compatible with m68k.inc word-order!) ---- */
INLINE u8 jag_dram_rb(u32 a)
{
    return DRAM_BUF[(a & 0x1FFFFFu) ^ 1u];
}
INLINE void jag_dram_wb(u32 a, u8 v)
{
    DRAM_BUF[(a & 0x1FFFFFu) ^ 1u] = v;
}
INLINE u16 jag_dram_rw(u32 a)
{
    return *(const u16 *)&DRAM_BUF[a & 0x1FFFFEu];
}
INLINE void jag_dram_ww(u32 a, u16 v)
{
    *(u16 *)&DRAM_BUF[a & 0x1FFFFEu] = v;
}
INLINE u32 jag_dram_rl(u32 a)
{
    return ((u32)jag_dram_rw(a) << 16) | jag_dram_rw(a + 2u);
}
INLINE void jag_dram_wl(u32 a, u32 v)
{
    jag_dram_ww(a, (u16)(v >> 16));
    jag_dram_ww(a + 2u, (u16)v);
}

static u32 io_read(u32 a, int size);
static void io_write(u32 a, u32 v, int size);

static inline u8 jag_bus_rb(u32 a)
{
    a &= 0xFFFFFFu;
    if (a < 0x200000u) return jag_dram_rb(a);
    if (a >= 0x800000u && a < 0xE00000u) return ROM_BUF[(a - 0x800000u) ^ 1u];
    if (a >= 0xF03000u && a < 0xF04000u) return M->gpu_ram[(a - 0xF03000u) ^ 1u];
    if (a >= 0xF1B000u && a < 0xF1D000u) return M->dsp_ram[(a - 0xF1B000u) ^ 1u];
    return (u8)io_read(a, 1);
}

static inline u16 jag_bus_rw(u32 a)
{
    a &= 0xFFFFFEu;
    if (a < 0x200000u) return jag_dram_rw(a);
    if (a >= 0xF03000u && a < 0xF04000u) return *(const u16 *)&M->gpu_ram[a - 0xF03000u];
    if (a >= 0xF1B000u && a < 0xF1D000u) return *(const u16 *)&M->dsp_ram[a - 0xF1B000u];
    if (a >= 0x800000u && a < 0xE00000u) return *(const u16 *)&ROM_BUF[a - 0x800000u];
    return (u16)io_read(a, 2);
}

static inline u32 jag_bus_rl(u32 a)
{
    return ((u32)jag_bus_rw(a) << 16) | jag_bus_rw(a + 2u);
}

static inline void jag_bus_wb(u32 a, u8 v)
{
    a &= 0xFFFFFFu;
    if (a < 0x200000u) { jag_dram_wb(a, v); return; }
    if (a >= 0xF03000u && a < 0xF04000u) { M->gpu_ram[(a - 0xF03000u) ^ 1u] = v; return; }
    if (a >= 0xF1B000u && a < 0xF1D000u) { M->dsp_ram[(a - 0xF1B000u) ^ 1u] = v; return; }
    io_write(a, v, 1);
}

static inline void jag_bus_ww(u32 a, u16 v)
{
    a &= 0xFFFFFEu;
    if (a < 0x200000u) { jag_dram_ww(a, v); return; }
    if (a >= 0xF03000u && a < 0xF04000u) { *(u16 *)&M->gpu_ram[a - 0xF03000u] = v; return; }
    if (a >= 0xF1B000u && a < 0xF1D000u) { *(u16 *)&M->dsp_ram[a - 0xF1B000u] = v; return; }
    io_write(a, v, 2);
}

static inline void jag_bus_wl(u32 a, u32 v)
{
    jag_bus_ww(a, (u16)(v >> 16));
    jag_bus_ww(a + 2u, (u16)v);
}

/* ============================================================================
   Tom 64-Bit Hardware Blitter ($F02200..$F0229B)
   ============================================================================ */

static void jag_blitter_exec(u32 cmd)
{
    S.b_cmd = cmd;
    u32 outer = (S.b_count >> 16) & 0xFFFFu;
    u32 inner = S.b_count & 0xFFFFu;
    if (!inner) return;
    if (!outer) outer = 1u;

    u32 a1_base = S.a1_base & 0xFFFFF8u;
    u32 a2_base = S.a2_base & 0xFFFFF8u;
    u32 pitch_flags = (S.a1_flags >> 3) & 7u;   /* PIXEL size: 0=1b,1=2b,2=4b,3=8b,4=16b,5=32b */
    u32 wid_code    = (S.a1_flags >> 9) & 63u;
    /* Decode Jaguar floating-point width code ((4 | mant2) << exp4) */
    u32 dst_stride_px = ((4u | (wid_code & 3u)) << ((wid_code >> 2) & 15u)) >> 2;
    if (!dst_stride_px) dst_stride_px = 320u;

    u32 a2_wid_code = (S.a2_flags >> 9) & 63u;
    u32 src_stride_px = ((4u | (a2_wid_code & 3u)) << ((a2_wid_code >> 2) & 15u)) >> 2;
    if (!src_stride_px) src_stride_px = 320u;

    int x1 = (s16)(S.a1_pixel & 0xFFFFu);
    int y1 = (s16)(S.a1_pixel >> 16);
    int x2 = (s16)(S.a2_pixel & 0xFFFFu);
    int y2 = (s16)(S.a2_pixel >> 16);

    int step1_x = (s16)(S.a1_step & 0xFFFFu);
    int step1_y = (s16)(S.a1_step >> 16);
    int step2_x = (s16)(S.a2_step & 0xFFFFu);
    int step2_y = (s16)(S.a2_step >> 16);

    int inc_x = (S.a1_flags & 0x00030000u) ? (s16)(S.a1_inc & 0xFFFFu) : 1;
    int inc_y = (S.a1_flags & 0x00030000u) ? (s16)(S.a1_inc >> 16) : 0;

    int srcen  = (cmd & 0x00000001u) != 0;
    int patdsel= (cmd & 0x00010000u) != 0;
    int gourz  = (cmd & 0x00001000u) != 0;
    int bkgw   = (cmd & 0x04000000u) != 0;  /* DCOMPEN / transparent 0 skip */
    u32 lfu    = (cmd >> 21) & 15u;

    u16 pat16  = (u16)(patdsel ? (S.b_patd[0] >> 16) : (S.b_dstd[0] >> 16));
    s32 cur_i  = (s32)S.b_i[0];             /* 8.16 intensity for CRY Gouraud! */
    s32 iinc   = (s32)S.b_iinc;
    if (iinc & 0x00800000) iinc |= (s32)0xFF000000u; /* sign-extend 24-bit B_IINC! */

    /* Fast path: 16-bit DRAM horizontal solid / CRY-Gouraud span fill (30x faster on MIPS 24KEf) */
    if (pitch_flags == 4u && a1_base < 0x180000u && inc_x == 1 && inc_y == 0 && !srcen && !bkgw && lfu != 6u) {
        u16 fill16 = (lfu == 0u) ? 0u : ((lfu == 15u) ? 0xFFFFu : pat16);
        u32 fill32 = (u32)fill16 | ((u32)fill16 << 16);
        u16 chr = pat16 & 0xFF00u;
        for (u32 oy = 0; oy < outer; oy++) {
            u32 row_off = (a1_base + ((u32)(y1 * (int)dst_stride_px + x1) * 2u)) & 0x1FFFFEu;
            if (row_off + inner * 2u <= JAG_DRAM_SIZE) {
                u16 *row = (u16 *)&DRAM_BUF[row_off];
                if (!gourz) {
                    u32 ix = 0;
                    if ((row_off & 2u) && ix < inner)
                        row[ix++] = fill16;
                    u32 *r32 = (u32 *)&row[ix];
                    u32 pairs = (inner - ix) >> 1;
                    for (u32 k = 0; k < pairs; k++)
                        r32[k] = fill32;
                    ix += pairs << 1;
                    if (ix < inner)
                        row[ix] = fill16;
                } else if (lfu == 0u || lfu == 15u) {
                    for (u32 ix = 0; ix < inner; ix++) {
                        row[ix] = fill16;
                        cur_i += iinc;
                    }
                } else {
                    for (u32 ix = 0; ix < inner; ix++) {
                        s32 iy = cur_i >> 16;
                        if (iy < 0) iy = 0;
                        else if (iy > 255) iy = 255;
                        row[ix] = (u16)(chr | (u32)iy);
                        cur_i += iinc;
                    }
                }
                x1 += (int)inner;
                x2 += (int)inner;
                if (S.a1_flags & 0x00080000u) { x1 += step1_x; y1 += step1_y; }
                if (S.a2_flags & 0x00080000u) { x2 += step2_x; y2 += step2_y; }
                continue;
            }
            for (u32 ix = 0; ix < inner; ix++) {
                u32 da = a1_base + ((u32)(y1 * (int)dst_stride_px + x1) * 2u);
                u16 sval = pat16;
                if (gourz) {
                    s32 iy = cur_i >> 16;
                    if (iy < 0) iy = 0;
                    else if (iy > 255) iy = 255;
                    sval = (u16)(chr | (u32)iy);
                    cur_i += iinc;
                }
                jag_bus_ww(da, (lfu == 0u) ? 0u : ((lfu == 15u) ? 0xFFFFu : sval));
                x1 += 1; x2 += 1;
            }
            if (S.a1_flags & 0x00080000u) { x1 += step1_x; y1 += step1_y; }
            if (S.a2_flags & 0x00080000u) { x2 += step2_x; y2 += step2_y; }
        }
        S.a1_pixel = ((u32)(u16)y1 << 16) | (u16)x1;
        S.a2_pixel = ((u32)(u16)y2 << 16) | (u16)x2;
        return;
    }

    for (u32 oy = 0; oy < outer; oy++) {
        for (u32 ix = 0; ix < inner; ix++) {
            if (pitch_flags == 4u) {        /* 16-bit CRY / RGB pixels (99% of Jaguar games!) */
                u32 da = a1_base + ((u32)(y1 * (int)dst_stride_px + x1) * 2u);
                u16 sval = pat16;
                if (srcen) {
                    u32 sa = a2_base + ((u32)(y2 * (int)src_stride_px + x2) * 2u);
                    sval = jag_bus_rw(sa);
                }
                if (gourz) {
                    s32 iy = cur_i >> 16;
                    if (iy < 0) iy = 0;
                    else if (iy > 255) iy = 255;
                    sval = (u16)((sval & 0xFF00u) | (u32)iy);
                    cur_i += iinc;
                }
                if (!(bkgw && sval == 0)) {
                    u16 out = sval;
                    if (lfu == 0u) out = 0;
                    else if (lfu == 15u) out = 0xFFFFu;
                    else if (lfu == 6u) out = sval ^ jag_bus_rw(da); /* S ^ D */
                    jag_bus_ww(da, out);
                }
            } else {                        /* 8-bit / Phrase fill */
                u32 da = a1_base + (u32)(y1 * (int)dst_stride_px + x1);
                u8 sv = srcen ? jag_bus_rb(a2_base + (u32)(y2 * (int)src_stride_px + x2)) : (u8)pat16;
                if (!(bkgw && sv == 0))
                    jag_bus_wb(da, (lfu == 0u) ? 0u : sv);
            }
            x1 += inc_x; y1 += inc_y;
            x2 += 1;
        }
        if (S.a1_flags & 0x00080000u) { x1 += step1_x; y1 += step1_y; }
        if (S.a2_flags & 0x00080000u) { x2 += step2_x; y2 += step2_y; }
    }
    S.a1_pixel = ((u32)(u16)y1 << 16) | (u16)x1;
    S.a2_pixel = ((u32)(u16)y2 << 16) | (u16)x2;
}

/* ============================================================================
   Tom GPU & Jerry DSP 32-Bit Jaguar RISC Engine (64-Opcode ISA!)
   ============================================================================ */

static inline void risc_zn(struct jag_risc *c, u32 r)
{
    c->flags = (c->flags & ~5u) | (r == 0 ? 1u : 0u) | ((r >> 31) ? 4u : 0u);
}

static void jag_risc_run(struct jag_risc *c, int budget)
{
    if (!(c->ctrl & 1u)) return;
    while (budget-- > 0 && (c->ctrl & 1u)) {
        u16 ins = jag_bus_rw(c->pc);
        c->pc += 2u;
        u32 op  = (ins >> 10) & 63u;
        u32 im  = (ins >> 5)  & 31u;
        u32 dn  = ins & 31u;
        u32 bk  = (c->flags & 0x4000u) ? 32u : 0u;
        u32 *rs = &c->r[bk + im];
        u32 *rd = &c->r[bk + dn];
        u32 q32 = im ? im : 32u;

        switch (op) {
        case  0: { u32 a = *rd, b = *rs, r = a + b; c->flags = (c->flags & ~2u) | (r < a ? 2u : 0u); *rd = r; risc_zn(c, r); break; } /* ADD */
        case  1: { u32 cy = (c->flags >> 1) & 1u, a = *rd, b = *rs, r = a + b + cy; c->flags = (c->flags & ~2u) | ((cy ? (r <= a) : (r < a)) ? 2u : 0u); *rd = r; risc_zn(c, r); break; } /* ADDC */
        case  2: { u32 a = *rd, r = a + q32; c->flags = (c->flags & ~2u) | (r < a ? 2u : 0u); *rd = r; risc_zn(c, r); break; } /* ADDQ */
        case  3: *rd += q32; break;                                     /* ADDQT */
        case  4: { u32 b = *rs, a = *rd; c->flags = (c->flags & ~2u) | (b > a ? 2u : 0u); *rd = a - b; risc_zn(c, *rd); break; } /* SUB */
        case  5: { u32 b = *rs + ((c->flags >> 1) & 1u), a = *rd; c->flags = (c->flags & ~2u) | (b > a ? 2u : 0u); *rd = a - b; risc_zn(c, *rd); break; } /* SUBC */
        case  6: { u32 a = *rd; c->flags = (c->flags & ~2u) | (q32 > a ? 2u : 0u); *rd = a - q32; risc_zn(c, *rd); break; } /* SUBQ */
        case  7: *rd -= q32; break;                                     /* SUBQT */
        case  8: *rd = 0u - *rd; risc_zn(c, *rd); break;                /* NEG */
        case  9: *rd &= *rs; risc_zn(c, *rd); break;                    /* AND */
        case 10: *rd |= *rs; risc_zn(c, *rd); break;                    /* OR */
        case 11: *rd ^= *rs; risc_zn(c, *rd); break;                    /* XOR */
        case 12: *rd = ~(*rd); risc_zn(c, *rd); break;                  /* NOT */
        case 13: c->flags = (c->flags & ~1u) | (((*rd >> im) & 1u) ? 0u : 1u); break; /* BTST */
        case 14: *rd |= (1u << im); risc_zn(c, *rd); break;             /* BSET */
        case 15: *rd &= ~(1u << im); risc_zn(c, *rd); break;            /* BCLR */
        case 16: *rd = (*rd & 0xFFFFu) * (*rs & 0xFFFFu); risc_zn(c, *rd); break; /* MULT */
        case 17: *rd = (u32)((s32)(s16)*rd * (s32)(s16)*rs); risc_zn(c, *rd); break; /* IMULT */
        case 18: c->acc_lo = (s32)(s16)*rd * (s32)(s16)*rs; break;      /* IMULTN */
        case 19: *rd = (u32)c->acc_lo; break;                           /* RESMAC */
        case 20: c->acc_lo += (s32)(s16)*rd * (s32)(s16)*rs; break;     /* IMACN */
        case 21: { u32 dv = *rs; if (dv) { c->remain = *rd % dv; *rd /= dv; } else *rd = 0xFFFFFFFFu; break; } /* DIV */
        case 22: if ((s32)*rd < 0) *rd = 0u - *rd; risc_zn(c, *rd); break; /* ABS */
        case 23: { s32 sh = (s32)*rs; *rd = (sh < 0) ? (*rd << ((-sh) & 31)) : (*rd >> (sh & 31)); risc_zn(c, *rd); break; } /* SH */
        case 24: *rd <<= (32u - q32); risc_zn(c, *rd); break;           /* SHLQ */
        case 25: *rd >>= q32; risc_zn(c, *rd); break;                   /* SHRQ */
        case 26: { s32 sh = (s32)*rs; *rd = (sh < 0) ? (*rd << ((-sh) & 31)) : (u32)((s32)*rd >> (sh & 31)); risc_zn(c, *rd); break; } /* SHA */
        case 27: *rd = (u32)((s32)*rd >> q32); risc_zn(c, *rd); break;  /* SHARQ */
        case 28: { u32 r = *rs & 31u; *rd = r ? ((*rd >> r) | (*rd << (32u - r))) : *rd; risc_zn(c, *rd); break; } /* ROR */
        case 29: *rd = (*rd >> q32) | (*rd << (32u - q32)); risc_zn(c, *rd); break; /* RORQ */
        case 30: { u32 a = *rd, b = *rs, d = a - b; c->flags = (c->flags & ~7u) | (d == 0 ? 1u : 0u) | (b > a ? 2u : 0u) | ((d >> 31) ? 4u : 0u); break; } /* CMP */
        case 31: { s32 q = (im & 16u) ? (s32)(im | ~31u) : (s32)im; u32 a = *rd, b = (u32)q, d = a - b; c->flags = (c->flags & ~7u) | (d == 0 ? 1u : 0u) | (b > a ? 2u : 0u) | ((d >> 31) ? 4u : 0u); break; } /* CMPQ */
        case 32: { s32 v = (s32)*rd; *rd = (u32)(v < 0 ? 0 : (v > 255 ? 255 : v)); risc_zn(c, *rd); break; } /* SAT8 */
        case 33: { s32 v = (s32)*rd; *rd = (u32)(v < 0 ? 0 : (v > 65535 ? 65535 : v)); risc_zn(c, *rd); break; } /* SAT16 */
        case 34: *rd = *rs; break;                                      /* MOVE */
        case 35: *rd = im; break;                                       /* MOVEQ */
        case 36: *rd = c->r[(bk ^ 32u) + im]; break;                    /* MOVEFA */
        case 37: c->r[(bk ^ 32u) + dn] = *rs; break;                    /* MOVETA */
        case 38: { u16 lo = jag_bus_rw(c->pc), hi = jag_bus_rw(c->pc + 2u); c->pc += 4u; *rd = ((u32)hi << 16) | lo; break; } /* MOVEI */
        case 39: *rd = jag_bus_rb(*rs); break;                          /* LOADB */
        case 40: *rd = jag_bus_rw(*rs); break;                          /* LOADW */
        case 41: *rd = jag_bus_rl(*rs); break;                          /* LOAD */
        case 42: c->hidata = jag_bus_rl(*rs); *rd = jag_bus_rl(*rs + 4u); break; /* LOADP */
        case 43: *rd = jag_bus_rl(c->r[bk + 14] + q32 * 4u); break;     /* LOAD (R14+n) */
        case 44: *rd = jag_bus_rl(c->r[bk + 15] + q32 * 4u); break;     /* LOAD (R15+n) */
        case 45: jag_bus_wb(*rs, (u8)*rd); break;                       /* STOREB */
        case 46: jag_bus_ww(*rs, (u16)*rd); break;                      /* STOREW */
        case 47: jag_bus_wl(*rs, *rd); break;                           /* STORE */
        case 48: jag_bus_wl(*rs, c->hidata); jag_bus_wl(*rs + 4u, *rd); break; /* STOREP */
        case 49: jag_bus_wl(c->r[bk + 14] + q32 * 4u, *rd); break;      /* STORE (R14+n) */
        case 50: jag_bus_wl(c->r[bk + 15] + q32 * 4u, *rd); break;      /* STORE (R15+n) */
        case 51: *rd = c->pc; break;                                    /* MOVE PC, Rn */
        case 52:                                                        /* JUMP cc, (Rs) */
        case 53: {                                                      /* JR cc, rel5 */
            u32 cc = dn;
            u32 z = c->flags & 1u, cy = (c->flags >> 1) & 1u, n = (c->flags >> 2) & 1u;
            int take = 0;
            switch (cc) {
            case  0: take = 1; break;               /* T */
            case  1: take = !z; break;              /* NZ */
            case  2: take = (int)z; break;          /* Z */
            case  4: take = !cy; break;             /* NC */
            case  5: take = !cy && !z; break;       /* NC NZ */
            case  6: take = !cy && z; break;        /* NC Z */
            case  8: take = (int)cy; break;         /* C */
            case  9: take = cy && !z; break;        /* C NZ */
            case 10: take = cy || z; break;         /* C|Z */
            case 20: take = !n; break;              /* PL / NN */
            case 21: take = !n && !z; break;        /* NN NZ */
            case 24: take = (int)n; break;          /* MI / N */
            case 25: take = n && !z; break;         /* N NZ */
            default: take = 0; break;
            }
            if (take) {
                u32 target = (op == 52u) ? *rs : (u32)((s32)c->pc + (((im & 16u) ? (s32)(im | ~31u) : (s32)im) * 2));
                /* Jaguar RISC has a 1-slot branch delay! Execute delay slot before branching! */
                if (budget > 0)
                    jag_risc_run(c, 1);
                c->pc = target;
            }
            break;
        }
        default: break; /* NOP / PACK / UNPACK */
        }
    }
}

/* ============================================================================
   Tom 64-Bit Object Processor (Scanline Linked-List Compositor)
   ============================================================================ */

static inline u16 jag_map_pixel16(u16 raw)
{
    u32 mode = (S.vmode >> 1) & 3u;
    if (mode == 0u) return M->cry_lut[raw];
    return jag_rgb16_to_15(raw);
}

static void jag_op_render_line(int y, u16 *dst)
{
    int w = S.scr_w;
    u16 bg = (S.vmode & 6u) ? jag_rgb16_to_15(S.bord1) : M->cry_lut[S.bord1];
    u32 bg32 = (u32)bg | ((u32)bg << 16);
    u32 *d32 = (u32 *)dst;
    int bg_done = 0;

    if (!(S.vmode & 1u) || !(S.olp & 0x1FFFF8u)) {
        for (int i = 0; i < (w >> 1); i++) d32[i] = bg32;
        return;
    }

    u32 addr = S.olp & 0x1FFFF8u;
    u16 vc = (u16)(y * 2 + 36);     /* Jaguar half-line VC counter */

    for (int guard = 0; guard < 128 && addr < 0x1FFFF0u; guard++) {
        u32 p0_hi = jag_dram_rl(addr);
        u32 p0_lo = jag_dram_rl(addr + 4u);
        u32 type  = p0_lo & 7u;

        if (type == 4u) break;      /* STOP object! */

        /* LINK field: bits 42..24 of phrase 0 -> phrase address (byte addr = link << 3) */
        u32 link = (((p0_hi & 0x7FFu) << 8) | ((p0_lo >> 24) & 0xFFu)) << 3;

        if (type == 3u) {           /* BRANCH object */
            u32 ypos = (p0_lo >> 3) & 0x7FFu;
            u32 cc   = (p0_lo >> 14) & 7u;
            int take = 0;
            if (cc == 0u) take = (vc == ypos) || (ypos == 0x7FFu);
            else if (cc == 1u) take = (vc < ypos);
            else if (cc == 2u) take = (vc > ypos);
            addr = take ? link : (addr + 8u);
            continue;
        }
        if (type == 2u) {           /* GPU IRQ object */
            S.int1 |= 0x0400u;
            addr = link;
            continue;
        }

        /* TYPE 0 (BITMAP) or TYPE 1 (SCALED BITMAP) */
        u32 p1_hi = jag_dram_rl(addr + 8u);
        u32 p1_lo = jag_dram_rl(addr + 12u);

        int ypos   = (int)((p0_lo >> 3) & 0x7FFu);
        int height = (int)((p0_lo >> 14) & 0x3FFu);
        u32 data_a = ((p0_hi >> 11) & 0x1FFFFFu) << 3;

        /* Support both half-line VC coords (ypos >= 32 && height*2) and direct pixel Y coords! */
        int sy_top = (ypos >= 36 && ypos > 240) ? ((ypos - 36) >> 1) : ypos;
        int vscale = 32;            /* 3.5 fixed-point (32 = 1.0x) */
        int hscale = 32;
        if (type == 1u) {
            u32 p2_lo = jag_dram_rl(addr + 20u);
            hscale = (int)(p2_lo & 0xFFu);
            vscale = (int)((p2_lo >> 8) & 0xFFu);
            if (hscale < 1) hscale = 32;
            if (vscale < 1) vscale = 32;
        }

        int out_h = (height * vscale) >> 5;
        if (y >= sy_top && y < sy_top + out_h && height > 0) {
            int src_row = ((y - sy_top) << 5) / vscale;
            int xpos = (int)(p1_lo & 0xFFFu);
            if (xpos & 0x800) xpos -= 0x1000;   /* signed 12-bit XPOS */
            u32 depth  = (p1_lo >> 12) & 7u;    /* 0=1b, 1=2b, 2=4b, 3=8b, 4=16b */
            u32 dwidth = ((p1_lo >> 18) & 0x3FFu);  /* phrases (8 bytes) per source row */
            u32 iwidth = ((p1_hi << 4) | (p1_lo >> 28)) & 0x3FFu; /* phrases drawn */
            u32 idx_hi = (p1_hi >> 6) & 0x7Fu;
            int refl   = (p1_hi >> 13) & 1;
            int trans  = (p1_hi >> 15) & 1;
            if (!iwidth) iwidth = dwidth;

            u32 row_a = data_a + (u32)src_row * dwidth * 8u;
            int src_px = 0;
            if (depth == 4u)      src_px = (int)iwidth * 4;
            else if (depth == 3u) src_px = (int)iwidth * 8;
            else if (depth == 2u) src_px = (int)iwidth * 16;

            int out_w = (src_px * hscale) >> 5;
            if (!bg_done) {
                if (type == 0u && !refl && !trans && (depth == 4u || depth == 3u) &&
                    xpos <= 0 && xpos + src_px >= w && (row_a + (u32)src_px * 2u <= JAG_DRAM_SIZE)) {
                    bg_done = 1;
                } else {
                    for (int i = 0; i < (w >> 1); i++) d32[i] = bg32;
                    bg_done = 1;
                }
            }
            /* Fast unscaled scanline compositor (TYPE 0, !refl: zero 32-bit divides per pixel!) */
            if (type == 0u && !refl && (depth == 4u || depth == 3u) && (row_a + (u32)src_px * 2u <= JAG_DRAM_SIZE)) {
                int x0 = xpos < 0 ? -xpos : 0;
                int x1_end = (xpos + src_px > w) ? (w - xpos) : src_px;
                u32 mode = (S.vmode >> 1) & 3u;
                const u16 *lut = M->cry_lut;
                if (depth == 4u) {
                    const u16 *src16 = (const u16 *)&DRAM_BUF[row_a & 0x1FFFFEu];
                    if (mode == 0u) {
                        if (!trans) {
                            int ix = x0;
                            if (ix < x1_end && (((xpos + ix) | (int)((row_a >> 1) + (u32)ix)) & 1)) {
                                dst[xpos + ix] = lut[src16[ix]];
                                ix++;
                            }
                            if (ix + 1 < x1_end && !(((xpos + ix) | (int)((row_a >> 1) + (u32)ix)) & 1)) {
                                u32 last_w = 0u;
                                u32 last_out = (u32)lut[0] | ((u32)lut[0] << 16);
                                for (; ix + 1 < x1_end; ix += 2) {
                                    u32 w2 = *(const u32 *)&src16[ix];
                                    if (w2 != last_w) {
                                        last_w = w2;
                                        last_out = (u32)lut[w2 & 0xFFFFu] | ((u32)lut[w2 >> 16] << 16);
                                    }
                                    *(u32 *)&dst[xpos + ix] = last_out;
                                }
                            }
                            for (; ix < x1_end; ix++)
                                dst[xpos + ix] = lut[src16[ix]];
                        } else {
                            for (int ix = x0; ix < x1_end; ix++) {
                                u16 raw = src16[ix];
                                if (raw) dst[xpos + ix] = lut[raw];
                            }
                        }
                    } else {
                        for (int ix = x0; ix < x1_end; ix++) {
                            u16 raw = src16[ix];
                            if (!trans || raw) dst[xpos + ix] = jag_rgb16_to_15(raw);
                        }
                    }
                } else {
                    const u16 *clut = M->clut;
                    for (int ix = x0; ix < x1_end; ix++) {
                        u8 pen = DRAM_BUF[(row_a + (u32)ix) ^ 1u];
                        if (!trans || pen) {
                            u16 raw = clut[pen];
                            dst[xpos + ix] = (mode == 0u) ? lut[raw] : jag_rgb16_to_15(raw);
                        }
                    }
                }
                addr = link;
                continue;
            }
            for (int ox = 0; ox < out_w; ox++) {
                int dx = xpos + ox;
                if ((unsigned)dx >= (unsigned)w) continue;
                int ix = ((ox << 5) / hscale);
                if (refl) ix = src_px - 1 - ix;
                if (ix < 0 || ix >= src_px) continue;

                if (depth == 4u) {
                    u16 raw = jag_dram_rw(row_a + (u32)ix * 2u);
                    if (trans && raw == 0) continue;
                    dst[dx] = jag_map_pixel16(raw);
                } else if (depth == 3u) {
                    u8 pen = jag_dram_rb(row_a + (u32)ix);
                    if (trans && pen == 0) continue;
                    dst[dx] = jag_map_pixel16(M->clut[pen]);
                } else if (depth == 2u) {
                    u8 b = jag_dram_rb(row_a + (u32)(ix >> 1));
                    u8 pen = (ix & 1) ? (b & 15u) : (b >> 4);
                    if (trans && pen == 0) continue;
                    dst[dx] = jag_map_pixel16(M->clut[((idx_hi << 1) & 0xF0u) | pen]);
                }
            }
        }
        addr = link;
    }
    if (!bg_done) {
        for (int i = 0; i < (w >> 1); i++) d32[i] = bg32;
    }
}

/* ============================================================================
   68000 Hardware I/O Bus ($F00000 Tom & $F10000 Jerry)
   ============================================================================ */

static void jag_iack(u32 level)
{
    (void)level;
    m.ipl = 0;
    check_pending();
}

static void cpu_reset_line(void) {}

static u16 jag_read_joy(void)
{
    /* Atari Jaguar Controller Port 1 ($F14000 active-LOW):
       b8=Up, b9=Down, b10=Left, b11=Right, b1=B/C/Option */
    u16 v = 0xFFFFu;
    u16 p = S.pad1;
    if (p & 0x0010u) v &= (u16)~0x0100u;    /* Up */
    if (p & 0x0020u) v &= (u16)~0x0200u;    /* Down */
    if (p & 0x0040u) v &= (u16)~0x0400u;    /* Left */
    if (p & 0x0080u) v &= (u16)~0x0800u;    /* Right */
    return v;
}

static u16 jag_read_joybuts(void)
{
    /* $F14002 active-LOW: b0=Pause, b1=A(Fire/B_C) */
    u16 v = 0xFFFFu;
    if (S.pad1 & 0x0008u) v &= (u16)~0x0001u;   /* Start -> Pause */
    if (S.pad1 & 0x0001u) v &= (u16)~0x0002u;   /* A -> Button A */
    if (S.pad1 & 0x0002u) v &= (u16)~0x0004u;   /* B -> Button B */
    if (S.pad1 & 0x0400u) v &= (u16)~0x0008u;   /* X -> Button C */
    return v;
}

static u32 io_read(u32 a, int size)
{
    a &= 0xFFFFFFu;
    if (a >= 0xF00400u && a < 0xF00800u)
        return M->clut[(a - 0xF00400u) >> 1];
    if (a >= 0xF03000u && a < 0xF04000u)
        return (size == 2) ? *(u16 *)&M->gpu_ram[a - 0xF03000u] : M->gpu_ram[(a - 0xF03000u) ^ 1u];
    if (a >= 0xF1B000u && a < 0xF1D000u)
        return (size == 2) ? *(u16 *)&M->dsp_ram[a - 0xF1B000u] : M->dsp_ram[(a - 0xF1B000u) ^ 1u];

    switch (a & 0xFFFFFEu) {
    case 0xF00000: return S.memcon1;
    case 0xF00006: return S.vc;
    case 0xF00028: return S.vmode;
    case 0xF000E0: return S.int1;
    case 0xF02114: return (u16)(M->gpu.ctrl >> 16);
    case 0xF02116: return (u16)M->gpu.ctrl;
    case 0xF02238: return 0x0001u;              /* Blitter IDLE bit = 1 (instant completion!) */
    case 0xF0223A: return 0x0001u;
    case 0xF14000: return jag_read_joy();
    case 0xF14002: return jag_read_joybuts();
    case 0xF1A114: return (u16)(M->dsp.ctrl >> 16);
    case 0xF1A116: return (u16)M->dsp.ctrl;
    }
    return 0;
}

static void jag_write_u32_part(u32 *reg, u32 a, u32 v, int size)
{
    if (size == 2) {
        if ((a & 2u) == 0) *reg = (*reg & 0x0000FFFFu) | ((v & 0xFFFFu) << 16);
        else               *reg = (*reg & 0xFFFF0000u) | (v & 0xFFFFu);
    } else {
        int sh = (3 - (int)(a & 3u)) * 8;
        *reg = (*reg & ~(0xFFu << sh)) | ((v & 0xFFu) << sh);
    }
}

static void io_write(u32 a, u32 v, int size)
{
    a &= 0xFFFFFFu;
    if (a >= 0xF00400u && a < 0xF00800u) {
        M->clut[(a - 0xF00400u) >> 1] = (u16)v;
        return;
    }
    if (a >= 0xF03000u && a < 0xF04000u) {
        if (size == 2) *(u16 *)&M->gpu_ram[a - 0xF03000u] = (u16)v;
        else           M->gpu_ram[(a - 0xF03000u) ^ 1u] = (u8)v;
        return;
    }
    if (a >= 0xF1B000u && a < 0xF1D000u) {
        if (size == 2) *(u16 *)&M->dsp_ram[a - 0xF1B000u] = (u16)v;
        else           M->dsp_ram[(a - 0xF1B000u) ^ 1u] = (u8)v;
        return;
    }

    /* Tom Blitter Registers ($F02200..$F0229B) */
    if (a >= 0xF02200u && a < 0xF022A0u) {
        u32 r = a & 0xFFFFFCu;
        switch (r) {
        case 0xF02200: jag_write_u32_part(&S.a1_base,  a, v, size); break;
        case 0xF02204: jag_write_u32_part(&S.a1_flags, a, v, size); break;
        case 0xF02208: jag_write_u32_part(&S.a1_clip,  a, v, size); break;
        case 0xF0220C: jag_write_u32_part(&S.a1_pixel, a, v, size); break;
        case 0xF02210: jag_write_u32_part(&S.a1_step,  a, v, size); break;
        case 0xF0221C: jag_write_u32_part(&S.a1_inc,   a, v, size); break;
        case 0xF02224: jag_write_u32_part(&S.a2_base,  a, v, size); break;
        case 0xF02228: jag_write_u32_part(&S.a2_flags, a, v, size); break;
        case 0xF02230: jag_write_u32_part(&S.a2_pixel, a, v, size); break;
        case 0xF02234: jag_write_u32_part(&S.a2_step,  a, v, size); break;
        case 0xF02238:
            jag_write_u32_part(&S.b_cmd, a, v, size);
            if ((a & 2u) != 0) jag_blitter_exec(S.b_cmd);
            break;
        case 0xF0223C: jag_write_u32_part(&S.b_count,  a, v, size); break;
        case 0xF02240: jag_write_u32_part(&S.b_srcd[0],a, v, size); break;
        case 0xF02244: jag_write_u32_part(&S.b_srcd[1],a, v, size); break;
        case 0xF02248: jag_write_u32_part(&S.b_dstd[0],a, v, size); break;
        case 0xF0224C: jag_write_u32_part(&S.b_dstd[1],a, v, size); break;
        case 0xF02268: jag_write_u32_part(&S.b_patd[0],a, v, size); break;
        case 0xF0226C: jag_write_u32_part(&S.b_patd[1],a, v, size); break;
        case 0xF02270: jag_write_u32_part(&S.b_iinc,   a, v, size); break;
        case 0xF0227C: jag_write_u32_part(&S.b_i[0],   a, v, size); break;
        }
        return;
    }

    switch (a & 0xFFFFFEu) {
    case 0xF00000:
        S.memcon1 = (u16)v;
        if (v & 1u) rmap[0] = DRAM_BUF; /* Unmap boot ROM from $000000 -> DRAM! */
        break;
    case 0xF00020: S.olp = (S.olp & 0xFFFF0000u) | (v & 0xFFFFu); break;    /* Jaguar word-swapped OLP! */
    case 0xF00022: S.olp = (S.olp & 0x0000FFFFu) | ((v & 0xFFFFu) << 16); break;
    case 0xF00028: S.vmode = (u16)v; break;
    case 0xF0002A: S.bord1 = (u16)v; break;
    case 0xF0002C: S.bord2 = (u16)v; break;
    case 0xF000E0:
        /* INT1: high byte clears pending bits, low byte enables */
        S.int1 = (u16)((S.int1 & ~((v >> 8) & 0x1Fu)) | (v & 0x1Fu));
        break;
    case 0xF000E2: S.int2 = (u16)v; break;

    /* Tom GPU Control ($F02100..$F0211F) */
    case 0xF02100: case 0xF02102: jag_write_u32_part(&M->gpu.flags, a, v, size); break;
    case 0xF02110: case 0xF02112: jag_write_u32_part(&M->gpu.pc,    a, v, size); break;
    case 0xF02114: case 0xF02116: jag_write_u32_part(&M->gpu.ctrl,  a, v, size); break;

    /* Jerry DSP & Audio ($F10000..$F1A1FF) */
    case 0xF14000: S.joy_latch = (u16)v; break;
    case 0xF1A100: case 0xF1A102: jag_write_u32_part(&M->dsp.flags, a, v, size); break;
    case 0xF1A110: case 0xF1A112: jag_write_u32_part(&M->dsp.pc,    a, v, size); break;
    case 0xF1A114: case 0xF1A116: jag_write_u32_part(&M->dsp.ctrl,  a, v, size); break;
    case 0xF1A148: case 0xF1A14A: S.dac_l = (s16)v; break;
    case 0xF1A14C: case 0xF1A14E: S.dac_r = (s16)v; break;

    /* Jerry Synth Voice Assist ($F1A200..$F1A21F: pitch16, vol/wave16 per voice!) */
    default:
        if (a >= 0xF1A200u && a < 0xF1A220u) {
            u32 ch = ((a - 0xF1A200u) >> 2) & 3u;
            if ((a & 2u) == 0) {
                u32 hz = v & 0xFFFFu;
                S.voices[ch].inc = (hz << 12) / ((S.sample_rate ? S.sample_rate : 48000u) >> 4);
            } else {
                S.voices[ch].vol    = (u8)(v & 0xFFu);
                S.voices[ch].wave   = (u8)((v >> 8) & 3u);
                S.voices[ch].active = (S.voices[ch].vol > 0) ? 1u : 0u;
            }
        }
        break;
    }
}

/* ============================================================================
   Built-in Playable 64-Bit Jaguar Game (""): "TEMPEST JAGUAR 64"
   Executes native 68000 + Tom GPU 32-bit RISC + 64-bit Blitter CRY Gouraud +
   64-bit Object Processor + Jerry 4-voice techno synth!
   ============================================================================ */

static void j68_w16(u8 *b, u32 *p, u16 w) { b[*p] = (u8)w; b[*p + 1] = (u8)(w >> 8); *p += 2u; }
static void j68_w32(u8 *b, u32 *p, u32 d) { j68_w16(b, p, (u16)(d >> 16)); j68_w16(b, p, (u16)d); }
static u32  j68_bcc(u8 *b, u32 *p, u16 op){ j68_w16(b, p, op); u32 at = *p; j68_w16(b, p, 0); return at; }
static void j68_fix(u8 *b, u32 at, u32 to){ u32 t = at; j68_w16(b, &t, (u16)(s16)((s32)to - (s32)at)); }

static void build_builtin_jaguar_rom(void)
{
    jag_zero(ROM_BUF, 0x20000u);

    /* 1. Pre-build HUD Banner Sprite (160x12 16-bit CRY) at Cart ROM $804000 (copied to DRAM $050000)
          and Golden Claw Ship Sprite (16x16 16-bit CRY) at $806000 (copied to DRAM $054000)
          and Neon Flipper Enemy Sprite (16x16 16-bit CRY) at $806400 (copied to DRAM $054400)! */
    static const char banner[] = "TEMPEST JAGUAR 64  CRY-3D";
    for (int i = 0; banner[i]; i++) {
        const u8 *g = font5x7[banner[i] - 32];
        for (int gy = 0; gy < 7; gy++) {
            for (int gx = 0; gx < 5; gx++) {
                if ((g[gy] >> (4 - gx)) & 1u) {
                    int px = 4 + i * 6 + gx, py = 2 + gy;
                    u16 cry = (u16)(((gy < 3 ? 0xFE00u : 0xF700u)) | (255u - (u32)gy * 12u));
                    u32 off = 0x4000u + (u32)(py * 160 + px) * 2u;
                    *(u16 *)&ROM_BUF[off] = cry;
                }
            }
        }
    }

    /* Golden Claw Player Sprite (16x16 CRY, $8Fxx golden yellow!) */
    static const char *const claw[16] = {
        "##............##",
        ".###........###.",
        "..####....####..",
        "...####..####...",
        "....########....",
        "...###.##.###...",
        "..###......###..",
        ".###........###.",
        ".##..........##.",
        "................",
        "................",
        "................",
        "................",
        "................",
        "................",
        "................"
    };
    for (int y = 0; y < 16; y++)
        for (int x = 0; x < 16; x++)
            if (claw[y][x] == '#')
                *(u16 *)&ROM_BUF[0x6000u + (u32)(y * 16 + x) * 2u] = (u16)(0xFEFCu - (u32)y * 6u);

    /* Magenta/Red Flipper Enemy Sprite (16x16 CRY, $C2FF neon crimson-magenta!) */
    for (int y = 0; y < 16; y++) {
        for (int x = 0; x < 16; x++) {
            int dx = x - 7, dy = y - 7;
            if ((dx == dy || dx == -dy || (y == 7 && x >= 2 && x <= 13)))
                *(u16 *)&ROM_BUF[0x6400u + (u32)(y * 16 + x) * 2u] = 0xC2FFu;
        }
    }

    /* 12-lane rim & center coordinate table at $803000 (12 x 4 words: rim_x, rim_y, in_x, in_y) */
    static const s16 rim_xy[12][4] = {
        {160,  28, 160,  96}, {226,  42, 178, 100}, {272,  76, 190, 108},
        {288, 120, 194, 118}, {272, 164, 190, 128}, {226, 198, 178, 136},
        {160, 210, 160, 140}, { 94, 198, 142, 136}, { 48, 164, 130, 128},
        { 32, 120, 126, 118}, { 48,  76, 130, 108}, { 94,  42, 142, 100}
    };
    u32 tp = 0x3000u;
    for (int i = 0; i < 12; i++)
        for (int k = 0; k < 4; k++)
            j68_w16(ROM_BUF, &tp, (u16)rim_xy[i][k]);

    /* Tom GPU 32-bit RISC Microprogram at $803400 (copied to $F03000 GPU RAM & run every VBlank!):
       Draws a 16-dot emerald-cyan CRY vortex core at row 118 of DRAM `$010000` ($022720)
       using MOVEI, MOVEQ, STOREW, ADDQT, SUBQ, JR NZ (with delay slot) & halts via G_CTRL! */
    u32 gp = 0x3400u;
    j68_w16(ROM_BUF, &gp, (u16)((38u << 10) | 1u));             /* MOVEI #$00022720, R1 (center pit) */
    j68_w16(ROM_BUF, &gp, 0x2720u); j68_w16(ROM_BUF, &gp, 0x0002u);
    j68_w16(ROM_BUF, &gp, (u16)((38u << 10) | 3u));             /* MOVEI #$00003FC8, R3 (CRY emerald) */
    j68_w16(ROM_BUF, &gp, 0x3FC8u); j68_w16(ROM_BUF, &gp, 0x0000u);
    j68_w16(ROM_BUF, &gp, (u16)((35u << 10) | (16u << 5) | 4u));/* MOVEQ #16, R4 */
    /* gp loop (8 bytes back from after JR): */
    j68_w16(ROM_BUF, &gp, (u16)((46u << 10) | (1u << 5) | 3u)); /* STOREW R3, (R1) */
    j68_w16(ROM_BUF, &gp, (u16)(( 3u << 10) | (2u << 5) | 1u)); /* ADDQT #2, R1 */
    j68_w16(ROM_BUF, &gp, (u16)(( 6u << 10) | (1u << 5) | 4u)); /* SUBQ #1, R4 */
    j68_w16(ROM_BUF, &gp, (u16)((53u << 10) | (28u << 5) | 1u));/* JR NZ, -4 (-8 bytes) */
    j68_w16(ROM_BUF, &gp, 0xE400u);                             /* NOP (branch delay slot) */
    j68_w16(ROM_BUF, &gp, (u16)((38u << 10) | 2u));             /* MOVEI #$00F02114, R2 (G_CTRL) */
    j68_w16(ROM_BUF, &gp, 0x2114u); j68_w16(ROM_BUF, &gp, 0x00F0u);
    j68_w16(ROM_BUF, &gp, (u16)((35u << 10) | (0u << 5) | 0u)); /* MOVEQ #0, R0 */
    j68_w16(ROM_BUF, &gp, (u16)((47u << 10) | (2u << 5) | 0u)); /* STORE R0, (R2) -> stop GPU */
    j68_w16(ROM_BUF, &gp, 0xE400u);                             /* NOP */
    j68_w16(ROM_BUF, &gp, 0xE400u);

    /* ---- 68000 Vectors & Boot Code at $802000 (standard Jaguar cartridge start!) ---- */
    u32 p = 0x2000u;
    /* Set VMODE=$0001 (16-bit CRY enabled!), BORD1=$0010 (deep space indigo) */
    j68_w16(ROM_BUF, &p, 0x33FCu); j68_w16(ROM_BUF, &p, 0x0001u); j68_w32(ROM_BUF, &p, 0x00F00028u);
    j68_w16(ROM_BUF, &p, 0x33FCu); j68_w16(ROM_BUF, &p, 0x0014u); j68_w32(ROM_BUF, &p, 0x00F0002Au);
    /* Unmap boot ROM from $000000 via MEMCON1 ($F00000 = 1) & install VBlank Level 2 vector ($68) = $802400 */
    j68_w16(ROM_BUF, &p, 0x33FCu); j68_w16(ROM_BUF, &p, 0x0001u); j68_w32(ROM_BUF, &p, 0x00F00000u);
    j68_w16(ROM_BUF, &p, 0x23FCu); j68_w32(ROM_BUF, &p, 0x00802400u); j68_w32(ROM_BUF, &p, 0x00000068u);

    /* Copy Banner ($804000 -> $050000, 1920 words), Claw & Flipper ($806000 -> $054000, 512 words),
       and GPU RISC code ($803400 -> $F03000, 16 words)! */
    j68_w16(ROM_BUF, &p, 0x41F9u); j68_w32(ROM_BUF, &p, 0x00804000u);
    j68_w16(ROM_BUF, &p, 0x43F9u); j68_w32(ROM_BUF, &p, 0x00050000u);
    j68_w16(ROM_BUF, &p, 0x303Cu); j68_w16(ROM_BUF, &p, 1919);
    u32 lb1 = p; j68_w16(ROM_BUF, &p, 0x32D8u); j68_w16(ROM_BUF, &p, 0x51C8u); j68_w16(ROM_BUF, &p, (u16)(s16)((s32)lb1 - (s32)p));

    j68_w16(ROM_BUF, &p, 0x41F9u); j68_w32(ROM_BUF, &p, 0x00806000u);
    j68_w16(ROM_BUF, &p, 0x43F9u); j68_w32(ROM_BUF, &p, 0x00054000u);
    j68_w16(ROM_BUF, &p, 0x303Cu); j68_w16(ROM_BUF, &p, 767);
    u32 lb2 = p; j68_w16(ROM_BUF, &p, 0x32D8u); j68_w16(ROM_BUF, &p, 0x51C8u); j68_w16(ROM_BUF, &p, (u16)(s16)((s32)lb2 - (s32)p));

    j68_w16(ROM_BUF, &p, 0x41F9u); j68_w32(ROM_BUF, &p, 0x00803400u);
    j68_w16(ROM_BUF, &p, 0x43F9u); j68_w32(ROM_BUF, &p, 0x00F03000u);
    j68_w16(ROM_BUF, &p, 0x7013u);
    u32 lb3 = p; j68_w16(ROM_BUF, &p, 0x32D8u); j68_w16(ROM_BUF, &p, 0x51C8u); j68_w16(ROM_BUF, &p, (u16)(s16)((s32)lb3 - (s32)p));

    /* Initialize Jerry 4-Voice Techno Synth ($F1A200..$F1A20F) */
    j68_w16(ROM_BUF, &p, 0x33FCu); j68_w16(ROM_BUF, &p, 110);    j68_w32(ROM_BUF, &p, 0x00F1A200u);
    j68_w16(ROM_BUF, &p, 0x33FCu); j68_w16(ROM_BUF, &p, 0x0138u);j68_w32(ROM_BUF, &p, 0x00F1A202u);
    j68_w16(ROM_BUF, &p, 0x33FCu); j68_w16(ROM_BUF, &p, 220);    j68_w32(ROM_BUF, &p, 0x00F1A204u);
    j68_w16(ROM_BUF, &p, 0x33FCu); j68_w16(ROM_BUF, &p, 0x0228u);j68_w32(ROM_BUF, &p, 0x00F1A206u);

    /* Initialize Game State at $002000: [0]=frame, [2]=lane(0..11), [4]=cool(0), [6]=en_z(0..63), [8]=shot_z($FFFF) */
    j68_w16(ROM_BUF, &p, 0x4BF9u); j68_w32(ROM_BUF, &p, 0x00002000u);
    j68_w16(ROM_BUF, &p, 0x426Du); j68_w16(ROM_BUF, &p, 0);
    j68_w16(ROM_BUF, &p, 0x426Du); j68_w16(ROM_BUF, &p, 2);
    j68_w16(ROM_BUF, &p, 0x426Du); j68_w16(ROM_BUF, &p, 4);
    j68_w16(ROM_BUF, &p, 0x426Du); j68_w16(ROM_BUF, &p, 6);
    j68_w16(ROM_BUF, &p, 0x3B7Cu); j68_w16(ROM_BUF, &p, 0xFFFFu); j68_w16(ROM_BUF, &p, 8);

    /* Enable VBlank INT1 ($F000E0 = $0001) & wait for VBlank via 68000 STOP #$2000! */
    j68_w16(ROM_BUF, &p, 0x33FCu); j68_w16(ROM_BUF, &p, 0x0001u); j68_w32(ROM_BUF, &p, 0x00F000E0u);
    j68_w16(ROM_BUF, &p, 0x4E72u); j68_w16(ROM_BUF, &p, 0x2000u);
    j68_w16(ROM_BUF, &p, 0x60FAu);

    /* ---- Level 2 VBlank ISR at $802400 ---- */
    p = 0x2400u;
    j68_w16(ROM_BUF, &p, 0x48E7u); j68_w16(ROM_BUF, &p, 0xFFFEu);
    j68_w16(ROM_BUF, &p, 0x4BF9u); j68_w32(ROM_BUF, &p, 0x00002000u);   /* A5 = $2000 */
    j68_w16(ROM_BUF, &p, 0x526Du); j68_w16(ROM_BUF, &p, 0);             /* frame++ */

    /* 1. Clear 320x224 16-bit CRY canvas at DRAM $010000 via Tom 64-bit Hardware Blitter!
          A1_BASE=$010000, A1_FLAGS=$00003820 (16bpp, width=320), A1_PIXEL=0, B_PATD=$00120012,
          B_COUNT=(1<<16)|71680? Use (224<<16)|320 + A1_FLAGS XADDPIX + step=(-320, +1):
          Simpler: outer=1, inner=65535 (or 224x320 linear: outer=224, inner=320, A1_STEP=(1<<16)|(-320 & 0xFFFF), A1_FLAGS|=$00080000)! */
    j68_w16(ROM_BUF, &p, 0x23FCu); j68_w32(ROM_BUF, &p, 0x00010000u); j68_w32(ROM_BUF, &p, 0x00F02200u); /* A1_BASE */
    j68_w16(ROM_BUF, &p, 0x23FCu); j68_w32(ROM_BUF, &p, 0x00084220u); j68_w32(ROM_BUF, &p, 0x00F02204u); /* A1_FLAGS (16b, wid=0x21->320, ADD_STEP) */
    j68_w16(ROM_BUF, &p, 0x23FCu); j68_w32(ROM_BUF, &p, 0x00000000u); j68_w32(ROM_BUF, &p, 0x00F0220Cu); /* A1_PIXEL */
    j68_w16(ROM_BUF, &p, 0x23FCu); j68_w32(ROM_BUF, &p, 0x0001FEC0u); j68_w32(ROM_BUF, &p, 0x00F02210u); /* A1_STEP (+1,-320) */
    j68_w16(ROM_BUF, &p, 0x23FCu); j68_w32(ROM_BUF, &p, 0x00120012u); j68_w32(ROM_BUF, &p, 0x00F02268u); /* B_PATD */
    j68_w16(ROM_BUF, &p, 0x23FCu); j68_w32(ROM_BUF, &p, (224u << 16) | 320u); j68_w32(ROM_BUF, &p, 0x00F0223Cu);
    j68_w16(ROM_BUF, &p, 0x23FCu); j68_w32(ROM_BUF, &p, 0x01810000u); j68_w32(ROM_BUF, &p, 0x00F02238u); /* PATDSEL + LFU=S */

    /* Kick Tom GPU 32-bit RISC @ $F03000! */
    j68_w16(ROM_BUF, &p, 0x23FCu); j68_w32(ROM_BUF, &p, 0x00F03000u); j68_w32(ROM_BUF, &p, 0x00F02110u);
    j68_w16(ROM_BUF, &p, 0x23FCu); j68_w32(ROM_BUF, &p, 0x00000001u); j68_w32(ROM_BUF, &p, 0x00F02114u);

    /* 2. Update Jerry Techno Arpeggio Note from frame counter! */
    j68_w16(ROM_BUF, &p, 0x302Du); j68_w16(ROM_BUF, &p, 0);
    j68_w16(ROM_BUF, &p, 0xE648u);                                      /* LSR.W #3, D0 */
    j68_w16(ROM_BUF, &p, 0x0240u); j68_w16(ROM_BUF, &p, 7u);
    j68_w16(ROM_BUF, &p, 0xE948u);                                      /* LSL.W #4, D0 */
    j68_w16(ROM_BUF, &p, 0x0640u); j68_w16(ROM_BUF, &p, 220u);
    j68_w16(ROM_BUF, &p, 0x33C0u); j68_w32(ROM_BUF, &p, 0x00F1A204u);   /* Voice 1 arpeggio Hz! */

    /* 3. Read Jaguar Controller ($F14000 / $F14002) or Attract AI spin around the 12-lane web! */
    j68_w16(ROM_BUF, &p, 0x3439u); j68_w32(ROM_BUF, &p, 0x00F14000u);   /* D2 = ~JOYSTICK */
    j68_w16(ROM_BUF, &p, 0x4642u);
    j68_w16(ROM_BUF, &p, 0x4A6Du); j68_w16(ROM_BUF, &p, 4);             /* cooldown > 0? */
    u32 b_cd = j68_bcc(ROM_BUF, &p, 0x6700u);
    j68_w16(ROM_BUF, &p, 0x536Du); j68_w16(ROM_BUF, &p, 4);
    u32 b_mv_dn = j68_bcc(ROM_BUF, &p, 0x6000u);
    j68_fix(ROM_BUF, b_cd, p);

    j68_w16(ROM_BUF, &p, 0x302Du); j68_w16(ROM_BUF, &p, 2);             /* D0 = lane (0..11) */
    j68_w16(ROM_BUF, &p, 0x0242u); j68_w16(ROM_BUF, &p, 0x0C00u);       /* Left or Right held? */
    u32 b_has = j68_bcc(ROM_BUF, &p, 0x6600u);
    /* Attract AI: rotate 1 lane every 12 frames */
    j68_w16(ROM_BUF, &p, 0x322Du); j68_w16(ROM_BUF, &p, 0);
    j68_w16(ROM_BUF, &p, 0x0241u); j68_w16(ROM_BUF, &p, 15u);
    u32 b_nai = j68_bcc(ROM_BUF, &p, 0x6600u);
    j68_w16(ROM_BUF, &p, 0x343Cu); j68_w16(ROM_BUF, &p, 0x0800u);
    j68_fix(ROM_BUF, b_has, p);
    j68_w16(ROM_BUF, &p, 0x0802u); j68_w16(ROM_BUF, &p, 11u);           /* Right -> lane+1 */
    u32 b_nrt = j68_bcc(ROM_BUF, &p, 0x6700u);
    j68_w16(ROM_BUF, &p, 0x5240u);
    j68_w16(ROM_BUF, &p, 0x0C40u); j68_w16(ROM_BUF, &p, 12);
    u32 b_lw = j68_bcc(ROM_BUF, &p, 0x6D00u);
    j68_w16(ROM_BUF, &p, 0x7000u);
    j68_fix(ROM_BUF, b_lw, p);
    j68_fix(ROM_BUF, b_nrt, p);
    j68_w16(ROM_BUF, &p, 0x0802u); j68_w16(ROM_BUF, &p, 10u);           /* Left -> lane-1 */
    u32 b_nlf = j68_bcc(ROM_BUF, &p, 0x6700u);
    j68_w16(ROM_BUF, &p, 0x5340u);
    u32 b_lp = j68_bcc(ROM_BUF, &p, 0x6A00u);
    j68_w16(ROM_BUF, &p, 0x700Bu);
    j68_fix(ROM_BUF, b_lp, p);
    j68_fix(ROM_BUF, b_nlf, p);
    j68_w16(ROM_BUF, &p, 0x3B40u); j68_w16(ROM_BUF, &p, 2);
    j68_w16(ROM_BUF, &p, 0x3B7Cu); j68_w16(ROM_BUF, &p, 5); j68_w16(ROM_BUF, &p, 4);
    j68_fix(ROM_BUF, b_nai, p);
    j68_fix(ROM_BUF, b_mv_dn, p);

    /* 4. Draw 12-Segment 3D Tempest Web into $010000 CRY Framebuffer!
          Each lane i=0..11 connects rim_xy[i] -> rim_xy[(i+1)%12] AND spoke rim_xy[i] -> in_xy[i] -> in_xy[(i+1)%12]!
          Active player lane [2] glows electric gold ($8FFF), other lanes electric cyan-blue ($2DF0)! */
    j68_w16(ROM_BUF, &p, 0x41F9u); j68_w32(ROM_BUF, &p, 0x00803000u);   /* A0 = rim_xy table */
    j68_w16(ROM_BUF, &p, 0x43F9u); j68_w32(ROM_BUF, &p, 0x00010000u);   /* A1 = CRY canvas */
    j68_w16(ROM_BUF, &p, 0x7E00u);                                      /* D7 = lane 0..11 */
    u32 l_web = p;
    /* Color D6 = (D7 == 2(A5)) ? $FEFF (electric yellow-gold) : $07F0 (electric cobalt-cyan) */
    j68_w16(ROM_BUF, &p, 0x3C3Cu); j68_w16(ROM_BUF, &p, 0x07F0u);
    j68_w16(ROM_BUF, &p, 0xBE6Du); j68_w16(ROM_BUF, &p, 2);
    u32 b_nact = j68_bcc(ROM_BUF, &p, 0x6600u);
    j68_w16(ROM_BUF, &p, 0x3C3Cu); j68_w16(ROM_BUF, &p, 0xFEFFu);
    j68_fix(ROM_BUF, b_nact, p);

    /* Interpolate 9 points along spoke (x0,y0) -> (x1,y1) in 12.3 fixed-point (fits 100% in VBlank!) */
    j68_w16(ROM_BUF, &p, 0x3010u);                                      /* D0 = rim_x */
    j68_w16(ROM_BUF, &p, 0x3228u); j68_w16(ROM_BUF, &p, 2);             /* D1 = rim_y */
    j68_w16(ROM_BUF, &p, 0x3428u); j68_w16(ROM_BUF, &p, 4);             /* D2 = in_x */
    j68_w16(ROM_BUF, &p, 0x3628u); j68_w16(ROM_BUF, &p, 6);             /* D3 = in_y */
    j68_w16(ROM_BUF, &p, 0x9440u);                                      /* D2 = in_x - rim_x */
    j68_w16(ROM_BUF, &p, 0x9641u);                                      /* D3 = in_y - rim_y */
    j68_w16(ROM_BUF, &p, 0xE740u);                                      /* D0 = rim_x << 3 */
    j68_w16(ROM_BUF, &p, 0xE741u);                                      /* D1 = rim_y << 3 */
    j68_w16(ROM_BUF, &p, 0x7808u);                                      /* D4 = 8..0 */
    u32 l_d2 = p;
    j68_w16(ROM_BUF, &p, 0x3A01u); j68_w16(ROM_BUF, &p, 0xE645u);       /* D5 = py (>> 3) */
    j68_w16(ROM_BUF, &p, 0xCAFCu); j68_w16(ROM_BUF, &p, 320u);          /* D5 = py * 320 */
    j68_w16(ROM_BUF, &p, 0x2F00u);                                      /* MOVE.L D0, -(SP) */
    j68_w16(ROM_BUF, &p, 0xE640u);                                      /* D0 = px (>> 3) */
    j68_w16(ROM_BUF, &p, 0x48C0u);                                      /* EXT.L D0 */
    j68_w16(ROM_BUF, &p, 0xDA80u);                                      /* D5 += px */
    j68_w16(ROM_BUF, &p, 0xDA85u);                                      /* D5 *= 2 */
    /* Depth-shaded CRY Gouraud intensity along spoke: (D6 & $FF00) | (112 + D4 * 16) */
    j68_w16(ROM_BUF, &p, 0x3004u); j68_w16(ROM_BUF, &p, 0xE940u);       /* D0 = D4 << 4 */
    j68_w16(ROM_BUF, &p, 0x0640u); j68_w16(ROM_BUF, &p, 112u);
    j68_w16(ROM_BUF, &p, 0x0246u); j68_w16(ROM_BUF, &p, 0xFF00u);
    j68_w16(ROM_BUF, &p, 0x8046u);                                      /* OR.W D6, D0 */
    j68_w16(ROM_BUF, &p, 0x3380u); j68_w16(ROM_BUF, &p, 0x5800u);       /* MOVE.W D0, 0(A1, D5.L) */
    j68_w16(ROM_BUF, &p, 0x3380u); j68_w16(ROM_BUF, &p, 0x5802u);       /* MOVE.W D0, 2(A1, D5.L) */
    j68_w16(ROM_BUF, &p, 0x201Fu);                                      /* MOVE.L (SP)+, D0 */
    j68_w16(ROM_BUF, &p, 0xD042u);                                      /* x_fp += dx */
    j68_w16(ROM_BUF, &p, 0xD243u);                                      /* y_fp += dy */
    j68_w16(ROM_BUF, &p, 0x51CCu); j68_w16(ROM_BUF, &p, (u16)(s16)((s32)l_d2 - (s32)p));

    /* Restore full bright rim intensity in D6 ($FF) and draw outer rim segment rim_xy[i] -> rim_xy[(i+1)%12] */
    j68_w16(ROM_BUF, &p, 0x0046u); j68_w16(ROM_BUF, &p, 0x00F8u);
    j68_w16(ROM_BUF, &p, 0x3010u); j68_w16(ROM_BUF, &p, 0x3228u); j68_w16(ROM_BUF, &p, 2);
    j68_w16(ROM_BUF, &p, 0x45E8u); j68_w16(ROM_BUF, &p, 8);             /* LEA 8(A0), A2 */
    j68_w16(ROM_BUF, &p, 0x0C47u); j68_w16(ROM_BUF, &p, 11);
    u32 b_nw2 = j68_bcc(ROM_BUF, &p, 0x6600u);
    j68_w16(ROM_BUF, &p, 0x45F9u); j68_w32(ROM_BUF, &p, 0x00803000u);
    j68_fix(ROM_BUF, b_nw2, p);
    j68_w16(ROM_BUF, &p, 0x3412u); j68_w16(ROM_BUF, &p, 0x362Au); j68_w16(ROM_BUF, &p, 2);
    j68_w16(ROM_BUF, &p, 0x9440u); j68_w16(ROM_BUF, &p, 0x9641u);
    j68_w16(ROM_BUF, &p, 0xE740u); j68_w16(ROM_BUF, &p, 0xE741u);
    j68_w16(ROM_BUF, &p, 0x7808u);
    u32 l_rim = p;
    j68_w16(ROM_BUF, &p, 0x3A01u); j68_w16(ROM_BUF, &p, 0xE645u);
    j68_w16(ROM_BUF, &p, 0xCAFCu); j68_w16(ROM_BUF, &p, 320u);
    j68_w16(ROM_BUF, &p, 0x2F00u);
    j68_w16(ROM_BUF, &p, 0xE640u); j68_w16(ROM_BUF, &p, 0x48C0u);
    j68_w16(ROM_BUF, &p, 0xDA80u); j68_w16(ROM_BUF, &p, 0xDA85u);
    j68_w16(ROM_BUF, &p, 0x3386u); j68_w16(ROM_BUF, &p, 0x5800u);
    j68_w16(ROM_BUF, &p, 0x3386u); j68_w16(ROM_BUF, &p, 0x5802u);
    j68_w16(ROM_BUF, &p, 0x201Fu);
    j68_w16(ROM_BUF, &p, 0xD042u); j68_w16(ROM_BUF, &p, 0xD243u);
    j68_w16(ROM_BUF, &p, 0x51CCu); j68_w16(ROM_BUF, &p, (u16)(s16)((s32)l_rim - (s32)p));

    /* Draw inner pit polygon segment in_xy[i] -> in_xy[(i+1)%12] */
    j68_w16(ROM_BUF, &p, 0x3028u); j68_w16(ROM_BUF, &p, 4);
    j68_w16(ROM_BUF, &p, 0x3228u); j68_w16(ROM_BUF, &p, 6);
    j68_w16(ROM_BUF, &p, 0x342Au); j68_w16(ROM_BUF, &p, 4);
    j68_w16(ROM_BUF, &p, 0x362Au); j68_w16(ROM_BUF, &p, 6);
    j68_w16(ROM_BUF, &p, 0x9440u); j68_w16(ROM_BUF, &p, 0x9641u);
    j68_w16(ROM_BUF, &p, 0xE740u); j68_w16(ROM_BUF, &p, 0xE741u);
    j68_w16(ROM_BUF, &p, 0x3C3Cu); j68_w16(ROM_BUF, &p, 0x05D8u);
    j68_w16(ROM_BUF, &p, 0x7808u);
    u32 l_pit = p;
    j68_w16(ROM_BUF, &p, 0x3A01u); j68_w16(ROM_BUF, &p, 0xE645u);
    j68_w16(ROM_BUF, &p, 0xCAFCu); j68_w16(ROM_BUF, &p, 320u);
    j68_w16(ROM_BUF, &p, 0x2F00u);
    j68_w16(ROM_BUF, &p, 0xE640u); j68_w16(ROM_BUF, &p, 0x48C0u);
    j68_w16(ROM_BUF, &p, 0xDA80u); j68_w16(ROM_BUF, &p, 0xDA85u);
    j68_w16(ROM_BUF, &p, 0x3386u); j68_w16(ROM_BUF, &p, 0x5800u);
    j68_w16(ROM_BUF, &p, 0x201Fu);
    j68_w16(ROM_BUF, &p, 0xD042u); j68_w16(ROM_BUF, &p, 0xD243u);
    j68_w16(ROM_BUF, &p, 0x51CCu); j68_w16(ROM_BUF, &p, (u16)(s16)((s32)l_pit - (s32)p));

    j68_w16(ROM_BUF, &p, 0x5088u);                                      /* ADDQ.L #8, A0 */
    j68_w16(ROM_BUF, &p, 0x5247u);                                      /* ADDQ.W #1, D7 */
    j68_w16(ROM_BUF, &p, 0x0C47u); j68_w16(ROM_BUF, &p, 12);
    u32 b_wlp = j68_bcc(ROM_BUF, &p, 0x6D00u);
    j68_fix(ROM_BUF, b_wlp, l_web);

    /* Player Plasma Bolt ($F14002 Button A/B/C fires down active lane!) */
    j68_w16(ROM_BUF, &p, 0x3039u); j68_w32(ROM_BUF, &p, 0x00F14002u);
    j68_w16(ROM_BUF, &p, 0x4640u);
    j68_w16(ROM_BUF, &p, 0x0240u); j68_w16(ROM_BUF, &p, 0x000Eu);
    u32 b_nf = j68_bcc(ROM_BUF, &p, 0x6700u);
    j68_w16(ROM_BUF, &p, 0x4A6Du); j68_w16(ROM_BUF, &p, 8);
    u32 b_af = j68_bcc(ROM_BUF, &p, 0x6A00u);
    j68_w16(ROM_BUF, &p, 0x426Du); j68_w16(ROM_BUF, &p, 8);
    j68_w16(ROM_BUF, &p, 0x3B6Du); j68_w16(ROM_BUF, &p, 2); j68_w16(ROM_BUF, &p, 10);
    j68_w16(ROM_BUF, &p, 0x33FCu); j68_w16(ROM_BUF, &p, 760u);   j68_w32(ROM_BUF, &p, 0x00F1A208u);
    j68_w16(ROM_BUF, &p, 0x33FCu); j68_w16(ROM_BUF, &p, 0x0238u);j68_w32(ROM_BUF, &p, 0x00F1A20Au);
    j68_fix(ROM_BUF, b_af, p);
    j68_fix(ROM_BUF, b_nf, p);

    j68_w16(ROM_BUF, &p, 0x4A6Du); j68_w16(ROM_BUF, &p, 8);
    u32 b_nb = j68_bcc(ROM_BUF, &p, 0x6B00u);
    j68_w16(ROM_BUF, &p, 0x302Du); j68_w16(ROM_BUF, &p, 10);
    j68_w16(ROM_BUF, &p, 0xE740u);
    j68_w16(ROM_BUF, &p, 0x41F9u); j68_w32(ROM_BUF, &p, 0x00803000u);
    j68_w16(ROM_BUF, &p, 0x3230u); j68_w16(ROM_BUF, &p, 0x0000u);
    j68_w16(ROM_BUF, &p, 0x3430u); j68_w16(ROM_BUF, &p, 0x0002u);
    j68_w16(ROM_BUF, &p, 0x3630u); j68_w16(ROM_BUF, &p, 0x0004u);
    j68_w16(ROM_BUF, &p, 0x3830u); j68_w16(ROM_BUF, &p, 0x0006u);
    j68_w16(ROM_BUF, &p, 0x9641u); j68_w16(ROM_BUF, &p, 0x9842u);
    j68_w16(ROM_BUF, &p, 0x3A2Du); j68_w16(ROM_BUF, &p, 8);
    j68_w16(ROM_BUF, &p, 0xC7C5u); j68_w16(ROM_BUF, &p, 0xE843u); j68_w16(ROM_BUF, &p, 0xD243u);
    j68_w16(ROM_BUF, &p, 0xC9C5u); j68_w16(ROM_BUF, &p, 0xE844u); j68_w16(ROM_BUF, &p, 0xD444u);
    j68_w16(ROM_BUF, &p, 0xC4FCu); j68_w16(ROM_BUF, &p, 320u);
    j68_w16(ROM_BUF, &p, 0x48C1u); j68_w16(ROM_BUF, &p, 0xD481u); j68_w16(ROM_BUF, &p, 0xD482u);
    j68_w16(ROM_BUF, &p, 0x33BCu); j68_w16(ROM_BUF, &p, 0x8FFFu); j68_w16(ROM_BUF, &p, 0x2800u);
    j68_w16(ROM_BUF, &p, 0x33BCu); j68_w16(ROM_BUF, &p, 0x8FFFu); j68_w16(ROM_BUF, &p, 0x2802u);
    j68_w16(ROM_BUF, &p, 0x0682u); j68_w32(ROM_BUF, &p, 640u);
    j68_w16(ROM_BUF, &p, 0x33BCu); j68_w16(ROM_BUF, &p, 0x08FFu); j68_w16(ROM_BUF, &p, 0x2800u);
    j68_w16(ROM_BUF, &p, 0x33BCu); j68_w16(ROM_BUF, &p, 0x08FFu); j68_w16(ROM_BUF, &p, 0x2802u);
    j68_w16(ROM_BUF, &p, 0x526Du); j68_w16(ROM_BUF, &p, 8);
    j68_w16(ROM_BUF, &p, 0x0C6Du); j68_w16(ROM_BUF, &p, 16u); j68_w16(ROM_BUF, &p, 8);
    u32 b_kbolt = j68_bcc(ROM_BUF, &p, 0x6D00u);
    j68_w16(ROM_BUF, &p, 0x3B7Cu); j68_w16(ROM_BUF, &p, 0xFFFFu); j68_w16(ROM_BUF, &p, 8);
    j68_w16(ROM_BUF, &p, 0x4279u); j68_w32(ROM_BUF, &p, 0x00F1A20Au);
    j68_fix(ROM_BUF, b_kbolt, p);
    j68_fix(ROM_BUF, b_nb, p);

    /* 5. Build 64-Bit Jaguar Object Processor List at DRAM $004000 (16-byte/24-byte aligned!):
       - Obj 0 ($004000, TYPE 0 BITMAP): 320x224 16-bit CRY Canvas ($010000), LINK -> $004020
       - Obj 1 ($004020, TYPE 0 BITMAP, TRANS): 160x12 CRY HUD Banner ($050000) at (80, 4), LINK -> $004040
       - Obj 2 ($004040, TYPE 0 BITMAP, TRANS): 16x16 Golden Claw Ship ($054000) on active rim lane, LINK -> $004060
       - Obj 3 ($004060, TYPE 1 SCALED BITMAP, TRANS): 16x16 Flipper Enemy ($054400) zooming up the tube, LINK -> $004080
       - Obj 4 ($004080, TYPE 4 STOP): End of Object List! */
    j68_w16(ROM_BUF, &p, 0x43F9u); j68_w32(ROM_BUF, &p, 0x00004000u);

    /* Obj 0: Canvas $010000 (data_phrase=$02000), link_phrase=$00804 ($004020>>3), height=224, ypos=0, depth=4, dwidth=80, iwidth=80 */
    j68_w16(ROM_BUF, &p, 0x22BCu); j68_w32(ROM_BUF, &p, (0x02000u << 11) | (0x804u >> 8));
    j68_w16(ROM_BUF, &p, 0x237Cu); j68_w32(ROM_BUF, &p, ((0x804u & 0xFFu) << 24) | (224u << 14) | 0u); j68_w16(ROM_BUF, &p, 4);
    j68_w16(ROM_BUF, &p, 0x237Cu); j68_w32(ROM_BUF, &p, (80u >> 4)); j68_w16(ROM_BUF, &p, 8);
    j68_w16(ROM_BUF, &p, 0x237Cu); j68_w32(ROM_BUF, &p, ((80u & 15u) << 28) | (80u << 18) | (4u << 12) | 0u); j68_w16(ROM_BUF, &p, 12);

    /* Obj 1 ($004020): Banner $050000 (phrase=$0A000), link=$00808 ($004040>>3), h=12, y=4, TRANS, w=40 phrases, x=80 */
    j68_w16(ROM_BUF, &p, 0x237Cu); j68_w32(ROM_BUF, &p, (0x0A000u << 11) | (0x808u >> 8)); j68_w16(ROM_BUF, &p, 0x20);
    j68_w16(ROM_BUF, &p, 0x237Cu); j68_w32(ROM_BUF, &p, ((0x808u & 0xFFu) << 24) | (12u << 14) | (4u << 3)); j68_w16(ROM_BUF, &p, 0x24);
    j68_w16(ROM_BUF, &p, 0x237Cu); j68_w32(ROM_BUF, &p, 0x00008000u | (40u >> 4)); j68_w16(ROM_BUF, &p, 0x28);
    j68_w16(ROM_BUF, &p, 0x237Cu); j68_w32(ROM_BUF, &p, ((40u & 15u) << 28) | (40u << 18) | (4u << 12) | 80u); j68_w16(ROM_BUF, &p, 0x2C);

    /* Obj 2 ($004040): Golden Claw at rim_xy[lane] - 8 ($054000 -> phrase=$0A800, link=$0080C -> $004060) */
    j68_w16(ROM_BUF, &p, 0x302Du); j68_w16(ROM_BUF, &p, 2);
    j68_w16(ROM_BUF, &p, 0xE740u);                                      /* lane * 8 */
    j68_w16(ROM_BUF, &p, 0x41F9u); j68_w32(ROM_BUF, &p, 0x00803000u);
    j68_w16(ROM_BUF, &p, 0x3230u); j68_w16(ROM_BUF, &p, 0x0000u);       /* D1 = rim_x */
    j68_w16(ROM_BUF, &p, 0x3430u); j68_w16(ROM_BUF, &p, 0x0002u);       /* D2 = rim_y */
    j68_w16(ROM_BUF, &p, 0x5141u); j68_w16(ROM_BUF, &p, 0x5142u);       /* -8, -8 */
    j68_w16(ROM_BUF, &p, 0x237Cu); j68_w32(ROM_BUF, &p, (0x0A800u << 11) | (0x80Cu >> 8)); j68_w16(ROM_BUF, &p, 0x40);
    j68_w16(ROM_BUF, &p, 0xE742u);                                      /* D2 = y << 3 */
    j68_w16(ROM_BUF, &p, 0x48C2u);
    j68_w16(ROM_BUF, &p, 0x0082u); j68_w32(ROM_BUF, &p, ((0x80Cu & 0xFFu) << 24) | (16u << 14));
    j68_w16(ROM_BUF, &p, 0x2342u); j68_w16(ROM_BUF, &p, 0x44);
    j68_w16(ROM_BUF, &p, 0x237Cu); j68_w32(ROM_BUF, &p, 0x00008000u); j68_w16(ROM_BUF, &p, 0x48);
    j68_w16(ROM_BUF, &p, 0x0241u); j68_w16(ROM_BUF, &p, 0x0FFFu);
    j68_w16(ROM_BUF, &p, 0x48C1u);
    j68_w16(ROM_BUF, &p, 0x0081u); j68_w32(ROM_BUF, &p, (4u << 28) | (4u << 18) | (4u << 12));
    j68_w16(ROM_BUF, &p, 0x2341u); j68_w16(ROM_BUF, &p, 0x4C);

    /* Obj 3 ($004060, TYPE 1 SCALED BITMAP): Flipper zooming from center (scale 12 -> 40!) toward rim! */
    j68_w16(ROM_BUF, &p, 0x302Du); j68_w16(ROM_BUF, &p, 0);             /* frame */
    j68_w16(ROM_BUF, &p, 0x0240u); j68_w16(ROM_BUF, &p, 63u);           /* z = 0..63 */
    j68_w16(ROM_BUF, &p, 0xE240u);                                      /* scale = 12 + (z >> 1) (12..43 in 3.5 fixed!) */
    j68_w16(ROM_BUF, &p, 0x0640u); j68_w16(ROM_BUF, &p, 12u);
    j68_w16(ROM_BUF, &p, 0x3200u); j68_w16(ROM_BUF, &p, 0xE141u); j68_w16(ROM_BUF, &p, 0x8041u); /* (vscale<<8)|hscale */
    j68_w16(ROM_BUF, &p, 0x237Cu); j68_w32(ROM_BUF, &p, (0x0A880u << 11) | (0x810u >> 8)); j68_w16(ROM_BUF, &p, 0x60);
    j68_w16(ROM_BUF, &p, 0x237Cu); j68_w32(ROM_BUF, &p, ((0x810u & 0xFFu) << 24) | (16u << 14) | (106u << 3) | 1u); j68_w16(ROM_BUF, &p, 0x64);
    j68_w16(ROM_BUF, &p, 0x237Cu); j68_w32(ROM_BUF, &p, 0x00008000u); j68_w16(ROM_BUF, &p, 0x68);
    j68_w16(ROM_BUF, &p, 0x237Cu); j68_w32(ROM_BUF, &p, (4u << 28) | (4u << 18) | (4u << 12) | 152u); j68_w16(ROM_BUF, &p, 0x6C);
    j68_w16(ROM_BUF, &p, 0x42A9u); j68_w16(ROM_BUF, &p, 0x70);
    j68_w16(ROM_BUF, &p, 0x48C0u);
    j68_w16(ROM_BUF, &p, 0x2340u); j68_w16(ROM_BUF, &p, 0x74);          /* Phrase 2 low = (vscale<<8)|hscale! */

    /* Obj 4 ($004080, TYPE 4 STOP) */
    j68_w16(ROM_BUF, &p, 0x42A9u); j68_w16(ROM_BUF, &p, 0x80);
    j68_w16(ROM_BUF, &p, 0x237Cu); j68_w32(ROM_BUF, &p, 4u); j68_w16(ROM_BUF, &p, 0x84);

    /* Point Jaguar OLP ($F00020/$F00022) to $00004000 & clear INT1 ($F000E0 = $0101) */
    j68_w16(ROM_BUF, &p, 0x33FCu); j68_w16(ROM_BUF, &p, 0x4000u); j68_w32(ROM_BUF, &p, 0x00F00020u);
    j68_w16(ROM_BUF, &p, 0x33FCu); j68_w16(ROM_BUF, &p, 0x0000u); j68_w32(ROM_BUF, &p, 0x00F00022u);
    j68_w16(ROM_BUF, &p, 0x33FCu); j68_w16(ROM_BUF, &p, 0x0101u); j68_w32(ROM_BUF, &p, 0x00F000E0u);

    j68_w16(ROM_BUF, &p, 0x4CDFu); j68_w16(ROM_BUF, &p, 0x7FFFu);
    j68_w16(ROM_BUF, &p, 0x4E73u);

    S.rom_size   = 0x20000u;
    S.boot_entry = 0x00802000u;
}

/* ============================================================================
   Cartridge Loader (.j64, .jag, .rom, .abs, .cof) & 60 Hz Frame Execution
   ============================================================================ */

static void jag_build_boot_rom(u32 entry_pc)
{
    jag_zero(M->boot_rom, sizeof(M->boot_rom));
    u32 p = 0;
    j68_w32(M->boot_rom, &p, 0x001FFFF0u);      /* Initial SSP at top of 2 MB DRAM */
    j68_w32(M->boot_rom, &p, entry_pc);         /* Initial PC */
    for (int v = 2; v < 64; v++)
        j68_w32(M->boot_rom, &p, 0x00E00100u);
    u32 rp = 0x0100u;
    j68_w16(M->boot_rom, &rp, 0x4E73u);         /* Default RTE */
}

static void jag_setup_68k_map(void)
{
    for (int i = 0; i < 256; i++)
        rmap[i] = wmap[i] = 0;
    /* $000000..$1FFFFF: 2 MB Jaguar DRAM */
    for (int i = 0; i < 32; i++)
        rmap[i] = wmap[i] = DRAM_BUF + ((u32)i << 16);
    /* $800000..$DFFFFF: 6 MB Cartridge ROM */
    for (int i = 0; i < 96; i++)
        rmap[0x80 + i] = ROM_BUF + ((u32)i << 16);
    /* $E00000: Clean-room Boot ROM */
    rmap[0xE0] = M->boot_rom;
}

void jaguar_reset(void)
{
    jag_zero(&M->gpu, sizeof(M->gpu));
    jag_zero(&M->dsp, sizeof(M->dsp));
    M->dsp.is_dsp = 1u;
    jag_zero(M->gpu_ram, sizeof(M->gpu_ram));
    jag_zero(M->dsp_ram, sizeof(M->dsp_ram));
    jag_zero(M->clut,    sizeof(M->clut));

    S.memcon1 = 1u;
    S.vmode   = 1u;
    S.bord1   = 0;
    S.olp     = 0;
    S.int1    = 0;
    S.dac_l   = S.dac_r = 0;
    jag_zero(S.voices, sizeof(S.voices));
    S.snd_head = S.snd_tail = 0;
    S.jammed   = 0;
    S.frame_no = 0;

    jag_build_boot_rom(S.boot_entry ? S.boot_entry : 0x00802000u);
    cpu_init();
    jag_setup_68k_map();
    /* Copy initial SSP & PC vectors into DRAM[0..7] if booting directly into DRAM or Cart! */
    for (int i = 0; i < 256; i++)
        DRAM_BUF[i] = M->boot_rom[i];

    /* If a .jag / .abs / BJL homebrew was loaded into DRAM ($4000), preserve its code above $2000! */
    cpu_reset();
}

const char *jaguar_load(const u8 *image, u32 size, const char *path)
{
    u32 keep_rate = S.sample_rate;
    if (keep_rate != 48000u && keep_rate != 44100u && keep_rate != 32000u && keep_rate != 22050u)
        keep_rate = 48000u;
    jag_zero(&S, sizeof(S));
    jag_zero(M->eeprom, sizeof(M->eeprom));
    jag_zero(DRAM_BUF, JAG_DRAM_SIZE);
    S.sample_rate = keep_rate;
    S.scr_w = 320;
    S.scr_h = 224;

    jag_init_cry_lut();

    if (!path || !*path || !image || size == 0) {
        build_builtin_jaguar_rom();
        static const char bi[] = "Tempest Jaguar 64 (Built-in Atari Jaguar 68000 + Tom GPU/OP/Blitter CRY-3D)";
        for (u32 i = 0; i < sizeof(bi); i++) S.info[i] = bi[i];
        jaguar_reset();
        return 0;
    }

    if (size < 64u)
        return "Jaguar image too small";

    jag_zero(ROM_BUF, 0x200000u);

    /* Detect format:
       1. JagServer 'JAGR' header (offset 0..3 == "JAGR" or offset $1C == "JAGR") -> load into DRAM!
       2. DRI / BJL .abs header ($601B) -> load into DRAM at header base ($4000)!
       3. Standard .j64 / .rom cartridge ($800000, universal header @ $400 -> entry @ $802000 or vector @ $04)! */
    if (size >= 32u && image[0] == 'J' && image[1] == 'A' && image[2] == 'G' && image[3] == 'R') {
        u32 load_a = ((u32)image[6] << 24) | ((u32)image[7] << 16) | ((u32)image[8] << 8) | image[9];
        u32 hdr_sz = (image[5] == 3) ? 18u : 14u;
        u32 run_a  = (image[5] == 3) ? (((u32)image[14]<<24)|((u32)image[15]<<16)|((u32)image[16]<<8)|image[17]) : load_a;
        load_a &= 0x1FFFFEu;
        for (u32 i = hdr_sz; i + 1u < size && load_a + (i - hdr_sz) + 1u < JAG_DRAM_SIZE; i += 2u) {
            u32 d = load_a + (i - hdr_sz);
            DRAM_BUF[d]     = image[i + 1u];
            DRAM_BUF[d + 1] = image[i];
        }
        S.boot_entry = run_a ? run_a : 0x00004000u;
        static const char tg[] = "Atari Jaguar .jag Homebrew (68000 + Tom GPU/OP/Blitter + Jerry DSP)";
        for (u32 i = 0; i < sizeof(tg); i++) S.info[i] = tg[i];
    } else {
        u32 cap = size < JAG_ROM_CAP ? size : JAG_ROM_CAP;
        for (u32 i = 0; i + 1u < cap; i += 2u) {
            ROM_BUF[i]     = image[i + 1u];
            ROM_BUF[i + 1] = image[i];
        }
        S.rom_size = cap;
        /* Check if cart has valid 68000 reset PC at offset $04 ($80xxxx), else standard $802000 */
        u32 vec_pc = ((u32)image[4] << 24) | ((u32)image[5] << 16) | ((u32)image[6] << 8) | image[7];
        if (vec_pc >= 0x00800000u && vec_pc < 0x00E00000u)
            S.boot_entry = vec_pc;
        else if (cap > 0x2004u)
            S.boot_entry = 0x00802000u;
        else
            S.boot_entry = 0x00800000u;
        static const char tg[] = "Atari Jaguar 64-Bit Cartridge (68000 + Tom GPU/OP/Blitter CRY + Jerry DSP)";
        for (u32 i = 0; i < sizeof(tg); i++) S.info[i] = tg[i];
    }

    jaguar_reset();
    return 0;
}

void jaguar_pad2(u16 pad) { S.pad2 = pad; }

static s16 jag_synth_sample(void)
{
    s32 mix = ((s32)S.dac_l + (s32)S.dac_r) >> 1;
    for (int i = 0; i < 4; i++) {
        struct jag_voice *v = &S.voices[i];
        if (!v->active || !v->vol) continue;
        v->phase = (v->phase + v->inc) & 0xFFFFFu;
        u32 ph = v->phase >> 10;
        s32 w = 0;
        if (v->wave == 0)      w = (ph < 512u) ? ((s32)ph * 4 - 1024) : (3072 - (s32)ph * 4);
        else if (v->wave == 1) w = (s32)ph * 2 - 1024;
        else                   w = (ph < 512u) ? 900 : -900;
        mix += (w * (s32)v->vol) >> 2;
    }
    if (mix > 32767) mix = 32767;
    else if (mix < -32768) mix = -32768;
    return (s16)mix;
}

void jaguar_frame(u16 pad, u16 *picture)
{
    S.pad1 = pad;
    const int total_lines = 262;
    const int vis_h = S.scr_h;
    u32 target_samples = (S.sample_rate ? S.sample_rate : 48000u) / 60u;
    u32 samp_acc = 0;

    m.clock = 0;

    for (int line = 0; line < total_lines; line++) {
        S.vc = (u16)(line * 2 + 36);
        /* 13.295 MHz 68000 (~845 cycles/scanline) + Tom GPU & Jerry DSP slices */
        cpu_run((line + 1) * 845);
        if (M->gpu.ctrl & 1u) jag_risc_run(&M->gpu, 512);
        if (M->dsp.ctrl & 1u) jag_risc_run(&M->dsp, 256);

        if (line < vis_h && picture)
            jag_op_render_line(line, picture + (u32)line * (u32)S.scr_w);

        if (line == vis_h) {
            S.int1 |= 0x0100u;      /* VBlank pending */
            if (S.int1 & 0x0001u) {
                m.ipl = 2u;         /* Jaguar Tom INT -> 68000 Level 2 ($68)! */
                check_pending();
            }
        }

        samp_acc += target_samples;
        while (samp_acc >= (u32)total_lines) {
            samp_acc -= (u32)total_lines;
            s16 s = jag_synth_sample();
            if (S.snd_head - S.snd_tail < JAG_SND_RING)
                M->snd_ring[S.snd_head++ & (JAG_SND_RING - 1u)] = s;
        }
    }

    S.frame_no++;
}

int jaguar_width(void)  { return S.scr_w ? S.scr_w : 320; }
int jaguar_height(void) { return S.scr_h ? S.scr_h : 224; }
const char *jaguar_info(void) { return S.info; }

u8 *jaguar_save_ram(u32 *size, int *battery)
{
    if (size) *size = sizeof(M->eeprom);
    if (battery) *battery = 1;
    return M->eeprom;
}

int jaguar_save_changed(void)
{
    int d = S.eeprom_dirty;
    S.eeprom_dirty = 0;
    return d;
}

int jaguar_jammed(void) { return S.jammed; }

void jaguar_audio_rate(u32 hz)
{
    S.sample_rate = hz ? hz : 48000u;
}

int jaguar_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && S.snd_tail != S.snd_head)
        out[n++] = M->snd_ring[S.snd_tail++ & (JAG_SND_RING - 1u)];
    return n;
}

int jaguar_is_rom(const u8 *head, u32 len, u32 size)
{
    if (!head || len < 32u || size < 64u)
        return 0;
    if (head[0] == 'J' && head[1] == 'A' && head[2] == 'G' && head[3] == 'R')
        return 1;
    if (len >= 0x410u && head[0x404] == 'T' && head[0x405] == 'A' && head[0x406] == 'R' && head[0x407] == 'I')
        return 1;
    return 0;
}

#ifdef JAGUAR_HOST
void jaguar_host_poison_mem(void)
{
    u8 *b = (u8 *)&jag_host_mem;
    for (u32 i = 0; i < sizeof(jag_host_mem); i++)
        b[i] = (u8)(0xA5u ^ (i & 0xFFu));
}
#endif
