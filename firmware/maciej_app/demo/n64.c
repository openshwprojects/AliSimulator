/* Nintendo 64 (NUS, 1996) 64-Bit 3D Console Emulator: see n64.h.
   Zero static .bss: 93.75 MHz VR4300 (MIPS III 64-bit integer + 32-entry TLB +
   pure-integer bit-exact COP1 IEEE-754 single/double FPU), 8 MB RDRAM, RCP
   (SP/DPC/MI/VI/AI/PI/RI/SI), PIF HLE IPL3 + Joybus, HLE Fast3D/F3DEX/F3DEX2,
   and 16-bit Z-buffered Gouraud/TMEM RDP rasterizer live in EMU_RAM_PHYS. */
#include "n64.h"
#include "font5x7.h"

#ifndef N64_HOST
#include "hw.h"
#else
typedef unsigned long long u64;
#endif
typedef signed long long s64;

#define INLINE static inline __attribute__((always_inline))

#define N64_RDRAM_SIZE   0x00800000u    /* 8 MB RDRAM (4 MB base + 4 MB Expansion Pak!) */
#define N64_ROM_CAP      0x01000000u    /* Up to 16 MB Cartridge ROM */
#define N64_SAVE_SIZE    0x00008000u    /* 32 KB SRAM / Controller Pak / EEPROM (.sav) */
#define N64_SND_RING     8192

/* RCP MI_INTR bits */
#define MI_INTR_SP  0x01u
#define MI_INTR_SI  0x02u
#define MI_INTR_AI  0x04u
#define MI_INTR_VI  0x08u
#define MI_INTR_PI  0x10u
#define MI_INTR_DP  0x20u

/* COP0 Register Indices */
#define C0_INDEX     0
#define C0_RANDOM    1
#define C0_ENTRYLO0  2
#define C0_ENTRYLO1  3
#define C0_CONTEXT   4
#define C0_PAGEMASK  5
#define C0_WIRED     6
#define C0_BADVADDR  8
#define C0_COUNT     9
#define C0_ENTRYHI  10
#define C0_COMPARE  11
#define C0_STATUS   12
#define C0_CAUSE    13
#define C0_EPC      14
#define C0_PRID     15
#define C0_CONFIG   16
#define C0_TAGLO    28
#define C0_ERROREPC 30

struct n64_tlb {
    u32 page_mask, entry_hi, entry_lo0, entry_lo1;
    u8  valid0, valid1;
};

struct n64_vtx {
    s32 sx, sy, sz, w_clip;             /* Screen X/Y (16.4), Z (0..0x7FFF), clip W */
    s32 s, t;                           /* Texture coords S10.5 */
    u8  r, g, b, a;
    u8  clip_flags;
};

struct n64_tile {
    u32 fmt, siz, line, tmem;
    u32 palette, cms, cmt, masks, maskt, shifts, shiftt;
    u16 uls, ult, lrs, lrt;             /* 10.2 texels */
};

struct n64_state {
    u8  jammed, save_dirty, is_pal;
    int scr_w, scr_h;
    u16 pad1;
    u32 rom_size, boot_pc;
    u8  cic_seed, cic_type;
    u32 frame_no;

    /* 93.75 MHz VR4300 CPU */
    u64 gpr[32];
    u64 hi, lo;
    u32 pc, next_pc;
    u8  in_delay, ll_bit;
    u64 cp0[32];
    u64 fpr[32];                        /* 32 x 64-bit IEEE-754 FPRs */
    u32 fcr31;                          /* b23 = FP condition bit */
    s32 cycles;
    u32 count_sub;

    /* RCP Registers */
    u32 sp_mem_addr, sp_dram_addr, sp_status, sp_pc, sp_semaphore;
    u32 dpc_start, dpc_end, dpc_current, dpc_status;
    u32 mi_mode, mi_intr, mi_mask;
    u32 vi_status, vi_origin, vi_width, vi_intr, vi_current;
    u32 vi_burst, vi_v_sync, vi_h_sync, vi_leap, vi_h_start, vi_v_start, vi_v_burst, vi_x_scale, vi_y_scale;
    u32 ai_dram_addr, ai_len, ai_control, ai_status, ai_dacrate, ai_bitrate;
    u32 ai_fifo_len[2], ai_fifo_addr[2];
    u8  ai_fifo_cnt;
    s32 ai_cycles_left;
    u32 pi_dram_addr, pi_cart_addr, pi_status;
    u32 pi_io_latch;
    s32 pi_io_busy_until;
    u32 ri_mode, ri_config, ri_select, ri_refresh;
    u32 si_dram_addr, si_status;

    /* HLE Fast3D / F3DEX / F3DEX2 + RDP Rasterizer State */
    u8  ucode_kind;                     /* 0=Fast3D, 1=F3DEX, 2=F3DEX2 */
    u32 segments[16];
    s32 mv_stack[10][16];               /* S15.16 4x4 ModelView stack */
    int mv_sp;
    s32 proj_mtx[16];                   /* S15.16 4x4 Projection */
    s32 mvp_mtx[16];                    /* Combined ModelView * Projection */
    int mvp_dirty;
    s16 vp_scale[4], vp_trans[4];       /* 2.0x screen coords (e.g. 640, 480, 511, 0) */
    u32 geom_mode;
    u16 tex_scale_s, tex_scale_t;
    u8  num_lights;
    u8  light_col[8][3];
    s8  light_dir[8][3];
    u32 rdp_other_hi, rdp_other_lo;
    u32 rdp_combine_hi, rdp_combine_lo;
    u32 color_img_addr, color_img_width, color_img_siz;
    u32 z_img_addr;
    u32 tex_img_addr, tex_img_width, tex_img_siz, tex_img_fmt;
    u32 fill_color, env_color, prim_color, blend_color, fog_color;
    u16 scis_ulx, scis_uly, scis_lrx, scis_lry;
    struct n64_tile tiles[8];

    u32 sample_rate;
    u32 snd_head, snd_tail;
    char info[96];
};

struct n64_mem {
    struct n64_state st;
    struct n64_tlb   tlb[32];
    struct n64_vtx   vtx_buf[64];
    u8  sp_dmem[4096] __attribute__((aligned(4)));
    u8  sp_imem[4096] __attribute__((aligned(4)));
    u8  tmem[4096]    __attribute__((aligned(4)));
    u8  pif_ram[64]   __attribute__((aligned(4)));
    u8  save_ram[N64_SAVE_SIZE] __attribute__((aligned(4)));
    s16 snd_ring[N64_SND_RING];
};

#ifdef N64_HOST
static struct n64_mem n64_host_mem;
static u8 n64_host_rdram[N64_RDRAM_SIZE] __attribute__((aligned(8)));
static u8 n64_host_rom[N64_ROM_CAP]      __attribute__((aligned(8)));
#define M           (&n64_host_mem)
#define RDRAM_BUF   n64_host_rdram
#define ROM_BUF     n64_host_rom
#else
/* Physical layout on S3811:
   0x03400000..0x0357FFFF (1.5 MB) : struct n64_mem M (~64 KB, 0 B static .bss!)
   0x03580000..0x03D7FFFF (8.0 MB) : RDRAM_BUF (Full 8 MB N64 RDRAM w/ Expansion Pak!)
   0x06900000..0x078FFFFF (16.0 MB): ROM_BUF   (Word-normalized Cartridge ROM in IMAGE_WORK_PHYS!) */
#define M           ((struct n64_mem *)KSEG0(EMU_RAM_PHYS))
#define RDRAM_BUF   ((u8 *)KSEG0(0x03580000u))
#define ROM_BUF     ((u8 *)KSEG0(IMAGE_WORK_PHYS))
_Static_assert(sizeof(struct n64_mem) <= 0x00180000u, "n64_mem exceeds 1.5 MB slot");
#endif

#define S (M->st)
#pragma GCC optimize("O2")

static void n64_zero(void *p, u32 n)
{
    u8 *b = (u8 *)p;
    for (u32 i = 0; i < n; i++) b[i] = 0;
}

/* ============================================================================
   Pure 32-Bit 64-Bit Shifts, Multiply & Divide (Zero libgcc __*di3 helpers!)
   ============================================================================ */

INLINE u64 n64_shl64(u64 v, u32 sh)
{
    sh &= 63u;
    if (sh == 0u) return v;
    u32 lo = (u32)v, hi = (u32)(v >> 32);
    if (sh >= 32u) return (u64)(lo << (sh - 32u)) << 32;
    return ((u64)((hi << sh) | (lo >> (32u - sh))) << 32) | (lo << sh);
}

INLINE u64 n64_shr64(u64 v, u32 sh)
{
    sh &= 63u;
    if (sh == 0u) return v;
    u32 lo = (u32)v, hi = (u32)(v >> 32);
    if (sh >= 32u) return hi >> (sh - 32u);
    return ((u64)(hi >> sh) << 32) | ((lo >> sh) | (hi << (32u - sh)));
}

INLINE s64 n64_sar64(s64 v, u32 sh)
{
    sh &= 63u;
    if (sh == 0u) return v;
    u32 lo = (u32)(u64)v;
    s32 hi = (s32)((u64)v >> 32);
    if (sh >= 32u) {
        s32 rlo = hi >> (sh - 32u);
        s32 rhi = hi >> 31;
        return (s64)(((u64)(u32)rhi << 32) | (u32)rlo);
    }
    s32 rhi = hi >> sh;
    u32 rlo = (lo >> sh) | ((u32)hi << (32u - sh));
    return (s64)(((u64)(u32)rhi << 32) | rlo);
}

INLINE void n64_mulu32(u32 a, u32 b, u32 *hi, u32 *lo)
{
    u32 al = a & 0xFFFFu, ah = a >> 16;
    u32 bl = b & 0xFFFFu, bh = b >> 16;
    u32 p0 = al * bl, p1 = al * bh, p2 = ah * bl, p3 = ah * bh;
    u32 cy = ((p0 >> 16) + (p1 & 0xFFFFu) + (p2 & 0xFFFFu)) >> 16;
    *lo = p0 + (p1 << 16) + (p2 << 16);
    *hi = p3 + (p1 >> 16) + (p2 >> 16) + cy;
}

static void n64_divu64(u64 num, u64 den, u64 *quot, u64 *rem)
{
    if (den == 0) { *quot = ~0ULL; *rem = num; return; }
    if ((num >> 32) == 0 && (den >> 32) == 0) {
        u32 n32 = (u32)num, d32 = (u32)den;
        *quot = n32 / d32;
        *rem  = n32 % d32;
        return;
    }
    u64 q = 0, r = 0;
    for (int i = 63; i >= 0; i--) {
        r = (r << 1) | ((num >> i) & 1ULL);
        if (r >= den) {
            r -= den;
            q |= (1ULL << i);
        }
    }
    *quot = q;
    *rem  = r;
}

static void n64_divs64(s64 num, s64 den, u64 *quot, u64 *rem)
{
    if (den == 0) { *quot = (num < 0) ? 1ULL : ~0ULL; *rem = (u64)num; return; }
    int nq = (num < 0) ^ (den < 0), nr = (num < 0);
    u64 un = (num < 0) ? (0ULL - (u64)num) : (u64)num;
    u64 ud = (den < 0) ? (0ULL - (u64)den) : (u64)den;
    u64 q, r;
    n64_divu64(un, ud, &q, &r);
    *quot = nq ? (0ULL - q) : q;
    *rem  = nr ? (0ULL - r) : r;
}

static void n64_dmultu(u64 a, u64 b, u64 *hi_out, u64 *lo_out)
{
    u32 a0 = (u32)a, a1 = (u32)(a >> 32);
    u32 b0 = (u32)b, b1 = (u32)(b >> 32);
    u32 h00, l00, h01, l01, h10, l10, h11, l11;
    n64_mulu32(a0, b0, &h00, &l00);
    n64_mulu32(a0, b1, &h01, &l01);
    n64_mulu32(a1, b0, &h10, &l10);
    n64_mulu32(a1, b1, &h11, &l11);
    u64 mid = (u64)h00 + (u64)l01 + (u64)l10;
    *lo_out = ((mid & 0xFFFFFFFFULL) << 32) | l00;
    *hi_out = ((u64)h11 << 32) + l11 + h01 + h10 + (mid >> 32);
}

/* ============================================================================
   Word-Ordered Big-Endian Buffer Accessors (1-instruction 32-bit R/W!)
   ============================================================================ */

INLINE u8  be_r8(const u8 *b, u32 a)          { return b[a ^ 3u]; }
INLINE void be_w8(u8 *b, u32 a, u8 v)         { b[a ^ 3u] = v; }
INLINE u16 be_r16(const u8 *b, u32 a)         { return *(const u16 *)&b[(a & ~1u) ^ 2u]; }
INLINE void be_w16(u8 *b, u32 a, u16 v)       { *(u16 *)&b[(a & ~1u) ^ 2u] = v; }
INLINE u32 be_r32(const u8 *b, u32 a)         { return *(const u32 *)&b[a & ~3u]; }
INLINE void be_w32(u8 *b, u32 a, u32 v)       { *(u32 *)&b[a & ~3u] = v; }

static void be_copy_bytes(u8 *dst_buf, u32 dst_a, const u8 *src_buf, u32 src_a, u32 len, u32 dst_mask, u32 src_mask)
{
    if (((dst_a | src_a | len) & 3u) == 0u) {
        for (u32 i = 0; i < len; i += 4u)
            be_w32(dst_buf, (dst_a + i) & dst_mask, be_r32(src_buf, (src_a + i) & src_mask));
    } else {
        for (u32 i = 0; i < len; i++)
            be_w8(dst_buf, (dst_a + i) & dst_mask, be_r8(src_buf, (src_a + i) & src_mask));
    }
}

/* ============================================================================
   RCP Interrupts & PIF Joybus Controller / EEPROM / MemPak
   ============================================================================ */

static void n64_update_irq_line(void)
{
    if (S.mi_intr & S.mi_mask)
        S.cp0[C0_CAUSE] |= 0x0400ULL;   /* Cause.IP2 */
    else
        S.cp0[C0_CAUSE] &= ~0x0400ULL;
}

static void n64_raise_mi(u32 bit)
{
    S.mi_intr |= bit;
    n64_update_irq_line();
}

static void n64_clear_mi(u32 bit)
{
    S.mi_intr &= ~bit;
    n64_update_irq_line();
}

static u8 n64_mempak_data_crc(const u8 *data32)
{
    u8 crc = 0;
    for (int i = 0; i <= 32; i++) {
        u8 b = (i < 32) ? data32[i] : 0u;
        for (int bit = 7; bit >= 0; bit--) {
            u8 xor_v = (crc & 0x80u) ? 0x85u : 0x00u;
            crc = (u8)(((crc << 1) | ((b >> bit) & 1u)) ^ xor_v);
        }
    }
    return crc;
}

static void n64_encode_joypad(u16 p, u8 out[4])
{
    /* N64 Joybus 4-byte report:
       out[0]: b7=A, b6=B, b5=Z, b4=Start, b3=DUp, b2=DDown, b1=DLeft, b0=DRight
       out[1]: b5=L, b4=R, b3=CUp, b2=CDown, b1=CLeft, b0=CRight
       out[2]: Stick X (-80..+80 signed)
       out[3]: Stick Y (-80..+80 signed; +80 = Up, -80 = Down!) */
    u8 b0 = 0, b1 = 0;
    s8 sx = 0, sy = 0;
    if (p & 0x0001u) b0 |= 0x80u;       /* X -> A */
    if (p & 0x0002u) b0 |= 0x40u;       /* Z -> B */
    if (p & 0x0400u) b0 |= 0x20u;       /* C -> Z-Trigger! */
    if (p & 0x0004u) b0 |= 0x20u;       /* Select/Tab -> Z-Trigger */
    if (p & 0x0008u) b0 |= 0x10u;       /* Enter -> Start */
    if (p & 0x0100u) b1 |= 0x20u;       /* Q -> L */
    if (p & 0x0200u) b1 |= 0x10u;       /* E -> R */
    if (p & 0x0800u) b1 |= 0x04u;       /* V -> C-Down */
    /* Map arrows to BOTH Analog Stick (+/-80) AND D-Pad so 3D analog & 2D menus both work! */
    if (p & 0x0010u) { sy =  80; b0 |= 0x08u; }
    if (p & 0x0020u) { sy = -80; b0 |= 0x04u; }
    if (p & 0x0040u) { sx = -80; b0 |= 0x02u; }
    if (p & 0x0080u) { sx =  80; b0 |= 0x01u; }
    out[0] = b0;
    out[1] = b1;
    out[2] = (u8)sx;
    out[3] = (u8)sy;
}

static void n64_pif_process(void)
{
    u8 pif[64];
    for (int i = 0; i < 64; i++) pif[i] = be_r8(M->pif_ram, (u32)i);

    /* CIC-6105 anti-tamper challenge-response at PIF[0x30..0x3E] */
    if (pif[63] & 0x02u) {
        static const u8 lut0[16] = { 4,0,7,10,1,12,5,14,8,13,2,11,3,6,15,9 };
        static const u8 lut1[16] = { 7,2,10,1,14,9,12,5,8,13,6,11,3,4,0,15 };
        u8 key = 0x0Bu, sel = 0u;
        for (int n = 0; n < 30; n++) {
            u8 ch_nib = (n & 1) ? (pif[48 + (n >> 1)] & 15u) : (pif[48 + (n >> 1)] >> 4);
            u8 r_nib  = (key + 5u * ch_nib) & 15u;
            if (n & 1) pif[48 + (n >> 1)] = (u8)((pif[48 + (n >> 1)] & 0xF0u) | r_nib);
            else       pif[48 + (n >> 1)] = (u8)((pif[48 + (n >> 1)] & 0x0Fu) | (r_nib << 4));
            key = sel ? lut1[r_nib] : lut0[r_nib];
            sel = (r_nib >> 3) & 1u;
        }
        pif[63] &= (u8)~0x02u;
    }

    int ch = 0, i = 0;
    while (i < 63 && ch < 6) {
        u8 tx = pif[i];
        if (tx == 0xFEu) break;         /* End of Joybus frame */
        if (tx == 0xFDu || tx == 0x00u) {
            if (tx == 0x00u) ch++;
            i++;
            continue;
        }
        if (tx == 0xFFu) { i++; continue; } /* Padding NOP byte */
        if (i + 1 >= 63) break;
        u8 rx = pif[i + 1] & 0x3Fu;
        int cmd_off = i + 2;
        int res_off = cmd_off + (tx & 0x3Fu);
        if (res_off + rx > 63) break;

        u8 cmd = pif[cmd_off];
        if (ch == 0) {                  /* Port 1: Standard N64 Controller + 32 KB MemPak */
            if ((cmd == 0x00u || cmd == 0xFFu) && rx >= 3) {
                pif[res_off + 0] = 0x05u;
                pif[res_off + 1] = 0x00u;
                pif[res_off + 2] = 0x01u; /* Controller Pak present */
            } else if (cmd == 0x01u && rx >= 4) {
                n64_encode_joypad(S.pad1, &pif[res_off]);
            } else if (cmd == 0x02u && (tx & 0x3Fu) >= 3 && rx >= 33) {
                u32 addr = (((u32)pif[cmd_off + 1] << 8) | (pif[cmd_off + 2] & 0xE0u)) & (N64_SAVE_SIZE - 32u);
                for (int k = 0; k < 32; k++) pif[res_off + k] = M->save_ram[addr + (u32)k];
                pif[res_off + 32] = n64_mempak_data_crc(&pif[res_off]);
            } else if (cmd == 0x03u && (tx & 0x3Fu) >= 35 && rx >= 1) {
                u32 addr = (((u32)pif[cmd_off + 1] << 8) | (pif[cmd_off + 2] & 0xE0u)) & (N64_SAVE_SIZE - 32u);
                for (int k = 0; k < 32; k++) M->save_ram[addr + (u32)k] = pif[cmd_off + 3 + k];
                S.save_dirty = 1u;
                pif[res_off] = n64_mempak_data_crc(&pif[cmd_off + 3]);
            }
        } else if (ch == 4) {           /* Cart Channel 4: 4K EEPROM (stored at save_ram + 0x7800) */
            u8 *eep = &M->save_ram[0x7800];
            if ((cmd == 0x00u || cmd == 0xFFu) && rx >= 3) {
                pif[res_off + 0] = 0x00u;
                pif[res_off + 1] = 0x80u;
                pif[res_off + 2] = 0x00u;
            } else if (cmd == 0x04u && (tx & 0x3Fu) >= 2 && rx >= 8) {
                u32 blk = (pif[cmd_off + 1] & 0x7Fu) * 8u;
                for (int k = 0; k < 8; k++) pif[res_off + k] = eep[blk + (u32)k];
            } else if (cmd == 0x05u && (tx & 0x3Fu) >= 10 && rx >= 1) {
                u32 blk = (pif[cmd_off + 1] & 0x7Fu) * 8u;
                for (int k = 0; k < 8; k++) eep[blk + (u32)k] = pif[cmd_off + 2 + k];
                S.save_dirty = 1u;
                pif[res_off] = 0x00u;
            }
        } else {                        /* Ports 2..4: No controller connected (bit 7 = 0x80 in RX len) */
            pif[i + 1] |= 0x80u;
        }

        i = res_off + rx;
        ch++;
    }
    pif[63] = 0;
    for (int k = 0; k < 64; k++) be_w8(M->pif_ram, (u32)k, pif[k]);
}

#pragma GCC optimize("O2")

/* ============================================================================
   HLE Fast3D / F3DEX / F3DEX2 + 16-Bit Z-Buffered RDP Triangle/TexRect Engine
   ============================================================================ */

INLINE u16 n64_rgba32_to_5551(u8 r, u8 g, u8 b, u8 a)
{
    return (u16)(((u32)(r >> 3) << 11) | ((u32)(g >> 3) << 6) | ((u32)(b >> 3) << 1) | (a ? 1u : 0u));
}

INLINE u32 n64_seg_addr(u32 seg_ptr)
{
    u32 seg = (seg_ptr >> 24) & 15u;
    return (S.segments[seg] + (seg_ptr & 0x00FFFFFFu)) & (N64_RDRAM_SIZE - 1u);
}

static void rdp_fill_rect(int ulx, int uly, int lrx, int lry)
{
    u32 cyc_type = (S.rdp_other_hi >> 20) & 3u;     /* 3 = FILL, 2 = COPY */
    if (cyc_type == 3u) { lrx += 1; lry += 1; }
    if (ulx < (int)(S.scis_ulx >> 2)) ulx = (int)(S.scis_ulx >> 2);
    if (uly < (int)(S.scis_uly >> 2)) uly = (int)(S.scis_uly >> 2);
    if (lrx > (int)(S.scis_lrx >> 2)) lrx = (int)(S.scis_lrx >> 2);
    if (lry > (int)(S.scis_lry >> 2)) lry = (int)(S.scis_lry >> 2);
    int w = (int)S.color_img_width;
    if (w <= 0) w = 320;
    if (lrx > w) lrx = w;
    if (lry > 240) lry = 240;
    if (ulx >= lrx || uly >= lry) return;

    u32 base = S.color_img_addr & (N64_RDRAM_SIZE - 4u);
    if (S.color_img_siz == 3u) {        /* 32-bit RGBA8888 target */
        u32 c32 = (cyc_type == 3u) ? S.fill_color : S.prim_color;
        for (int y = uly; y < lry; y++) {
            u32 row = base + (u32)(y * w) * 4u;
            for (int x = ulx; x < lrx; x++)
                be_w32(RDRAM_BUF, (row + (u32)x * 4u) & (N64_RDRAM_SIZE - 4u), c32);
        }
        return;
    }

    /* 16-bit RGBA5551 or Z-buffer clear! */
    u16 c0, c1;
    if (cyc_type == 3u) {
        c0 = (u16)(S.fill_color >> 16);
        c1 = (u16)S.fill_color;
    } else {
        c0 = c1 = n64_rgba32_to_5551((u8)(S.prim_color >> 24), (u8)(S.prim_color >> 16),
                                     (u8)(S.prim_color >> 8),  (u8)S.prim_color);
    }
    u32 pair_be = ((u32)c0 << 16) | c1;
    for (int y = uly; y < lry; y++) {
        u32 row = base + (u32)(y * w) * 2u;
        int x = ulx;
        if ((row & 3u) == 0u) {
            if ((x & 1) && x < lrx) {
                be_w16(RDRAM_BUF, (row + (u32)x * 2u) & (N64_RDRAM_SIZE - 2u), c1);
                x++;
            }
            for (; x + 1 < lrx; x += 2)
                be_w32(RDRAM_BUF, (row + (u32)x * 2u) & (N64_RDRAM_SIZE - 4u), pair_be);
        }
        for (; x < lrx; x++)
            be_w16(RDRAM_BUF, (row + (u32)x * 2u) & (N64_RDRAM_SIZE - 2u), (x & 1) ? c1 : c0);
    }
}

struct rdp_tex_setup {
    int tw, th, uls_px, ult_px;
    u32 tbase, row_bytes;
    u8  shifts, shiftt, clamp_s, clamp_t, siz, fmt, pal_hi;
};

INLINE void rdp_prepare_tile(int tile_id, struct rdp_tex_setup *ts)
{
    const struct n64_tile *tl = &S.tiles[tile_id & 7];
    int tw = ((tl->lrs - tl->uls) >> 2) + 1;
    int th = ((tl->lrt - tl->ult) >> 2) + 1;
    if (tl->masks) tw = 1 << tl->masks;
    if (tl->maskt) th = 1 << tl->maskt;
    if (tw < 1) tw = 32;
    if (th < 1) th = 32;
    ts->tw = tw;
    ts->th = th;
    ts->uls_px = (int)(tl->uls >> 2);
    ts->ult_px = (int)(tl->ult >> 2);
    ts->tbase = (tl->tmem * 8u) & 0xFFFu;
    ts->row_bytes = tl->line ? (tl->line * 8u) : ((tl->siz == 2u) ? (u32)tw * 2u : (u32)tw);
    ts->shifts = tl->shifts;
    ts->shiftt = tl->shiftt;
    ts->clamp_s = ((tl->cms & 2u) || !tl->masks) ? 1u : 0u;
    ts->clamp_t = ((tl->cmt & 2u) || !tl->maskt) ? 1u : 0u;
    ts->siz = tl->siz;
    ts->fmt = tl->fmt;
    ts->pal_hi = (u8)(tl->palette << 4);
}

/* Returns packed (r << 24) | (g << 16) | (b << 8) | a in a single register! */
INLINE u32 rdp_sample_fast(const struct rdp_tex_setup *ts, int s_sub, int t_sub)
{
    if (ts->shifts)
        s_sub = (ts->shifts >= 11u) ? (s_sub << (16u - ts->shifts)) : (s_sub >> ts->shifts);
    if (ts->shiftt)
        t_sub = (ts->shiftt >= 11u) ? (t_sub << (16u - ts->shiftt)) : (t_sub >> ts->shiftt);
    int u = (s_sub >> 5) - ts->uls_px;
    int v = (t_sub >> 5) - ts->ult_px;
    if (ts->clamp_s) { u = u < 0 ? 0 : (u >= ts->tw ? ts->tw - 1 : u); } else u &= (ts->tw - 1);
    if (ts->clamp_t) { v = v < 0 ? 0 : (v >= ts->th ? ts->th - 1 : v); } else v &= (ts->th - 1);

    u32 row_a = (ts->tbase + (u32)v * ts->row_bytes) & 0xFFFu;
    if (ts->siz == 2u && ts->fmt == 0u) {   /* 16-bit RGBA5551 */
        u16 tx = be_r16(M->tmem, (row_a + (u32)u * 2u) & 0xFFEu);
        if (!(tx & 1u)) return 0u;
        u32 r = ((tx >> 11) & 31u) << 3;
        u32 g = ((tx >>  6) & 31u) << 3;
        u32 b = ((tx >>  1) & 31u) << 3;
        return (r << 24) | (g << 16) | (b << 8) | 255u;
    }
    if (ts->fmt == 2u) {                    /* CI8 / CI4 Color-Indexed via TLUT @ TMEM $800 */
        u8 idx;
        if (ts->siz == 1u) {
            idx = be_r8(M->tmem, (row_a + (u32)u) & 0xFFFu);
        } else {
            u8 b8 = be_r8(M->tmem, (row_a + (u32)(u >> 1)) & 0xFFFu);
            idx = (u8)((((u & 1) ? b8 : (b8 >> 4)) & 15u) | ts->pal_hi);
        }
        u16 tx = be_r16(M->tmem, 0x800u + ((u32)idx * 2u & 0x7FEu));
        if (!(tx & 1u)) return 0u;
        u32 r = ((tx >> 11) & 31u) << 3;
        u32 g = ((tx >>  6) & 31u) << 3;
        u32 b = ((tx >>  1) & 31u) << 3;
        return (r << 24) | (g << 16) | (b << 8) | 255u;
    }
    /* I8 / IA8 / I4 Intensity */
    u32 iv;
    if (ts->siz >= 1u) {
        iv = be_r8(M->tmem, (row_a + (u32)u) & 0xFFFu);
    } else {
        u8 b8 = be_r8(M->tmem, (row_a + (u32)(u >> 1)) & 0xFFFu);
        iv = (((u & 1) ? b8 : (b8 >> 4)) & 15u) * 17u;
    }
    if (ts->fmt == 3u && ts->siz == 1u) {   /* IA8: 4b I + 4b A */
        u32 ii = (iv >> 4) * 17u;
        u32 aa = (iv & 15u) * 17u;
        return (ii << 24) | (ii << 16) | (ii << 8) | aa;
    }
    if (!iv) return 0u;
    return (iv << 24) | (iv << 16) | (iv << 8) | 255u;
}

static void rdp_tex_rect(int ulx, int uly, int lrx, int lry, int tile_id, int s0, int t0, int dsdx, int dtdy)
{
    u32 cyc_type = (S.rdp_other_hi >> 20) & 3u;
    if (cyc_type == 2u) dsdx >>= 2;     /* COPY mode steps 4 texels -> 1x! */
    int w = (int)S.color_img_width;
    if (w <= 0) w = 320;
    if (ulx < 0) ulx = 0;
    if (uly < 0) uly = 0;
    if (lrx > w) lrx = w;
    if (lry > 240) lry = 240;
    if (ulx >= lrx || uly >= lry) return;

    struct rdp_tex_setup ts;
    rdp_prepare_tile(tile_id, &ts);
    u32 cbase = S.color_img_addr & (N64_RDRAM_SIZE - 4u);
    int cur_t = t0;
    for (int y = uly; y < lry; y++, cur_t += dtdy) {
        int cur_s = s0;
        u32 row = cbase + (u32)(y * w) * 2u;
        for (int x = ulx; x < lrx; x++, cur_s += dsdx) {
            u32 rgba = rdp_sample_fast(&ts, cur_s >> 5, cur_t >> 5);
            if (!(rgba & 0xFFu)) continue;
            u16 out = n64_rgba32_to_5551((u8)(rgba >> 24), (u8)(rgba >> 16), (u8)(rgba >> 8), 1u);
            be_w16(RDRAM_BUF, (row + (u32)x * 2u) & (N64_RDRAM_SIZE - 2u), out);
        }
    }
}

static void rdp_draw_tri(const struct n64_vtx *v0, const struct n64_vtx *v1, const struct n64_vtx *v2, int textured, int tile_id)
{
    /* Reject clipped behind-camera vertices */
    if (v0->w_clip <= 64 || v1->w_clip <= 64 || v2->w_clip <= 64)
        return;

    s32 x0 = v0->sx >> 4, y0 = v0->sy >> 4;
    s32 x1 = v1->sx >> 4, y1 = v1->sy >> 4;
    s32 x2 = v2->sx >> 4, y2 = v2->sy >> 4;

    /* Signed 2x area for backface culling & barycentric interpolation */
    s32 area = (x1 - x0) * (y2 - y0) - (y1 - y0) * (x2 - x0);
    if (area == 0) return;
    if ((S.geom_mode & 0x00002000u) && area > 0 && S.ucode_kind != 2u) return; /* G_CULL_BACK (F3D/F3DEX) */
    if ((S.geom_mode & 0x00000400u) && area > 0 && S.ucode_kind == 2u) return; /* G_CULL_BACK (F3DEX2) */

    int min_x = x0 < x1 ? (x0 < x2 ? x0 : x2) : (x1 < x2 ? x1 : x2);
    int max_x = x0 > x1 ? (x0 > x2 ? x0 : x2) : (x1 > x2 ? x1 : x2);
    int min_y = y0 < y1 ? (y0 < y2 ? y0 : y2) : (y1 < y2 ? y1 : y2);
    int max_y = y0 > y1 ? (y0 > y2 ? y0 : y2) : (y1 > y2 ? y1 : y2);

    int w = (int)S.color_img_width;
    if (w <= 0) w = 320;
    int sx0 = (int)(S.scis_ulx >> 2), sy0 = (int)(S.scis_uly >> 2);
    int sx1 = (int)(S.scis_lrx >> 2), sy1 = (int)(S.scis_lry >> 2);
    if (sx1 <= 0 || sx1 > w) sx1 = w;
    if (sy1 <= 0 || sy1 > 240) sy1 = 240;

    if (min_x < sx0) min_x = sx0;
    if (min_y < sy0) min_y = sy0;
    if (max_x >= sx1) max_x = sx1 - 1;
    if (max_y >= sy1) max_y = sy1 - 1;
    if (min_x > max_x || min_y > max_y) return;

    /* Ensure positive area by swapping v1 <-> v2 if needed */
    if (area < 0) {
        const struct n64_vtx *vt = v1; v1 = v2; v2 = vt;
        s32 xt = x1; x1 = x2; x2 = xt;
        s32 yt = y1; y1 = y2; y2 = yt;
        area = -area;
    }

    /* 16-bit reciprocal (1 << 20) / area using 32-bit hardware division ONCE per triangle! */
    s32 inv_area = (area > 0) ? ((1 << 20) / area) : 0;
    if (!inv_area) return;

    int z_cmp = (S.rdp_other_lo & 0x10u) != 0 || (S.geom_mode & 0x00000001u) != 0;
    int z_upd = (S.rdp_other_lo & 0x20u) != 0 || (S.geom_mode & 0x00000001u) != 0;
    u32 cbase = S.color_img_addr & (N64_RDRAM_SIZE - 4u);
    u32 zbase = S.z_img_addr     & (N64_RDRAM_SIZE - 4u);
    if (!zbase) z_cmp = z_upd = 0;

    s32 A01 = y0 - y1, B01 = x1 - x0;
    s32 A12 = y1 - y2, B12 = x2 - x1;
    s32 A20 = y2 - y0, B20 = x0 - x2;

    s32 w0_row = (x2 - x1) * (min_y - y1) - (y2 - y1) * (min_x - x1);
    s32 w1_row = (x0 - x2) * (min_y - y2) - (y0 - y2) * (min_x - x2);
    s32 w2_row = (x1 - x0) * (min_y - y0) - (y1 - y0) * (min_x - x0);

    s32 z0 = v0->sz, z1 = v1->sz, z2 = v2->sz;
    s32 r0 = v0->r,  r1 = v1->r,  r2 = v2->r;
    s32 g0 = v0->g,  g1 = v1->g,  g2 = v2->g;
    s32 b0 = v0->b,  b1 = v1->b,  b2 = v2->b;
    s32 s0 = v0->s,  s1 = v1->s,  s2 = v2->s;
    s32 t0 = v0->t,  t1 = v1->t,  t2 = v2->t;
    u32 csiz = S.color_img_siz;
    struct rdp_tex_setup ts;
    if (textured) rdp_prepare_tile(tile_id, &ts);

    for (int y = min_y; y <= max_y; y++) {
        s32 e0 = w0_row, e1 = w1_row, e2 = w2_row;
        u32 crow = cbase + (u32)(y * w) * 2u;
        u32 zrow = zbase + (u32)(y * w) * 2u;
        int entered = 0;
        if (!textured && csiz != 3u &&
            crow + (u32)(max_x + 1) * 2u <= N64_RDRAM_SIZE &&
            (!zbase || zrow + (u32)(max_x + 1) * 2u <= N64_RDRAM_SIZE)) {
            u16 *cp16 = (u16 *)(void *)(RDRAM_BUF + crow);
            u16 *zp16 = (u16 *)(void *)(RDRAM_BUF + zrow);
            for (int x = min_x; x <= max_x; x++) {
                if ((e0 | e1 | e2) >= 0) {
                    entered = 1;
                    s32 b0w = (e0 * inv_area) >> 10;
                    s32 b1w = (e1 * inv_area) >> 10;
                    s32 b2w = 1024 - b0w - b1w;
                    if (b2w < 0) b2w = 0;
                    u16 pz = (u16)(((z0 * b0w + z1 * b1w + z2 * b2w) >> 10) & 0x7FFFu);
                    int xi = x ^ 1;
                    if (!z_cmp || pz <= (zp16[xi] >> 1)) {
                        s32 cr = (r0 * b0w + r1 * b1w + r2 * b2w) >> 10;
                        s32 cg = (g0 * b0w + g1 * b1w + g2 * b2w) >> 10;
                        s32 cb = (b0 * b0w + b1 * b1w + b2 * b2w) >> 10;
                        if (cr < 0) cr = 0; else if (cr > 255) cr = 255;
                        if (cg < 0) cg = 0; else if (cg > 255) cg = 255;
                        if (cb < 0) cb = 0; else if (cb > 255) cb = 255;
                        if (z_upd) zp16[xi] = (u16)(pz << 1);
                        cp16[xi] = n64_rgba32_to_5551((u8)cr, (u8)cg, (u8)cb, 1u);
                    }
                } else if (entered) {
                    break;
                }
                e0 += A12; e1 += A20; e2 += A01;
            }
        } else {
            for (int x = min_x; x <= max_x; x++) {
                if ((e0 | e1 | e2) >= 0) {
                    entered = 1;
                    /* Barycentric weights in 0..1024 (>> 10) */
                    s32 b0w = (e0 * inv_area) >> 10;
                    s32 b1w = (e1 * inv_area) >> 10;
                    s32 b2w = 1024 - b0w - b1w;
                    if (b2w < 0) b2w = 0;

                    u16 pz = (u16)(((z0 * b0w + z1 * b1w + z2 * b2w) >> 10) & 0x7FFFu);
                    u32 za = (zrow + (u32)x * 2u) & (N64_RDRAM_SIZE - 2u);
                    if (!z_cmp || pz <= (be_r16(RDRAM_BUF, za) >> 1)) {
                        s32 cr = (r0 * b0w + r1 * b1w + r2 * b2w) >> 10;
                        s32 cg = (g0 * b0w + g1 * b1w + g2 * b2w) >> 10;
                        s32 cb = (b0 * b0w + b1 * b1w + b2 * b2w) >> 10;
                        if (textured) {
                            s32 u_s = ((s0 * b0w + s1 * b1w + s2 * b2w) >> 10);
                            s32 v_t = ((t0 * b0w + t1 * b1w + t2 * b2w) >> 10);
                            u32 rgba = rdp_sample_fast(&ts, u_s, v_t);
                            if (!(rgba & 0xFFu)) {
                                e0 += A12; e1 += A20; e2 += A01;
                                continue;
                            }
                            cr = (cr * (s32)(rgba >> 24)) >> 8;
                            cg = (cg * (s32)((rgba >> 16) & 0xFFu)) >> 8;
                            cb = (cb * (s32)((rgba >> 8)  & 0xFFu)) >> 8;
                        }
                        if (cr < 0) cr = 0; else if (cr > 255) cr = 255;
                        if (cg < 0) cg = 0; else if (cg > 255) cg = 255;
                        if (cb < 0) cb = 0; else if (cb > 255) cb = 255;

                        if (z_upd)
                            be_w16(RDRAM_BUF, za, (u16)(pz << 1));
                        if (csiz == 3u) {
                            u32 ca32 = (cbase + (u32)(y * w + x) * 4u) & (N64_RDRAM_SIZE - 4u);
                            be_w32(RDRAM_BUF, ca32, ((u32)cr << 24) | ((u32)cg << 16) | ((u32)cb << 8) | 0xFFu);
                        } else {
                            u32 ca16 = (crow + (u32)x * 2u) & (N64_RDRAM_SIZE - 2u);
                            be_w16(RDRAM_BUF, ca16, n64_rgba32_to_5551((u8)cr, (u8)cg, (u8)cb, 1u));
                        }
                    }
                } else if (entered) {
                    break;
                }
                e0 += A12; e1 += A20; e2 += A01;
            }
        }
        w0_row += B12; w1_row += B20; w2_row += B01;
    }
}

/* ---- N64 Fixed-Point S15.16 4x4 Matrix Loader & Multiplier ---- */
static void hle_read_mtx(u32 addr, s32 out[16])
{
    /* N64 Mtx layout: 32 bytes signed integer part + 32 bytes unsigned fraction part! */
    for (int i = 0; i < 16; i += 2) {
        u32 iw = be_r32(RDRAM_BUF, (addr + (u32)i * 2u) & (N64_RDRAM_SIZE - 4u));
        u32 fw = be_r32(RDRAM_BUF, (addr + 32u + (u32)i * 2u) & (N64_RDRAM_SIZE - 4u));
        out[i]     = (s32)(((u32)(iw & 0xFFFF0000u)) | (fw >> 16));
        out[i + 1] = (s32)(((iw & 0xFFFFu) << 16)    | (fw & 0xFFFFu));
    }
}

static void hle_mtx_mul(const s32 a[16], const s32 b[16], s32 out[16])
{
    s32 tmp[16];
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            s64 sum = 0;
            for (int k = 0; k < 4; k++)
                sum += (s64)a[r * 4 + k] * (s64)b[k * 4 + c];
            tmp[r * 4 + c] = (s32)(sum >> 16);
        }
    }
    for (int i = 0; i < 16; i++) out[i] = tmp[i];
}

static void hle_load_vertices(u32 addr, u32 v0_idx, u32 count)
{
    if (S.mvp_dirty) {
        hle_mtx_mul(S.mv_stack[S.mv_sp], S.proj_mtx, S.mvp_mtx);
        S.mvp_dirty = 0;
    }
    int lit = (S.ucode_kind == 2u) ? ((S.geom_mode & 0x00020000u) != 0) : ((S.geom_mode & 0x00020000u) != 0);
    s32 vps_x = S.vp_scale[0] ? S.vp_scale[0] : 640;    /* 320 * 4 = 1280? N64 Vp is S13.2: 320*2*4 = 640! */
    s32 vps_y = S.vp_scale[1] ? S.vp_scale[1] : 480;
    s32 vpt_x = S.vp_trans[0] ? S.vp_trans[0] : 640;
    s32 vpt_y = S.vp_trans[1] ? S.vp_trans[1] : 480;

    for (u32 i = 0; i < count && (v0_idx + i) < 64u; i++) {
        u32 va = (addr + i * 16u) & (N64_RDRAM_SIZE - 16u);
        s32 vx = (s16)be_r16(RDRAM_BUF, va + 0u);
        s32 vy = (s16)be_r16(RDRAM_BUF, va + 2u);
        s32 vz = (s16)be_r16(RDRAM_BUF, va + 4u);
        s32 tc_s = (s16)be_r16(RDRAM_BUF, va + 8u);
        s32 tc_t = (s16)be_r16(RDRAM_BUF, va + 10u);

        s64 cx64 = (s64)vx * S.mvp_mtx[0] + (s64)vy * S.mvp_mtx[4] + (s64)vz * S.mvp_mtx[ 8] + S.mvp_mtx[12];
        s64 cy64 = (s64)vx * S.mvp_mtx[1] + (s64)vy * S.mvp_mtx[5] + (s64)vz * S.mvp_mtx[ 9] + S.mvp_mtx[13];
        s64 cz64 = (s64)vx * S.mvp_mtx[2] + (s64)vy * S.mvp_mtx[6] + (s64)vz * S.mvp_mtx[10] + S.mvp_mtx[14];
        s64 cw64 = (s64)vx * S.mvp_mtx[3] + (s64)vy * S.mvp_mtx[7] + (s64)vz * S.mvp_mtx[11] + S.mvp_mtx[15];

        struct n64_vtx *dv = &M->vtx_buf[v0_idx + i];
        s32 cw = (s32)n64_sar64(cw64, 8u);
        dv->w_clip = cw;
        if (cw > 16) {
            /* Scale 64-bit clip coords into safe 32-bit range so perspective divide uses
               pure 32-bit hardware division (zero libgcc __divdi3/__ashrdi3 on MIPS32!) */
            u32 sh = 8u;
            while (sh < 28u &&
                   (n64_sar64(cw64, sh) > 0x7FFF ||
                    n64_sar64(cx64, sh) > 0x3FFFF || n64_sar64(cx64, sh) < -0x3FFFF ||
                    n64_sar64(cy64, sh) > 0x3FFFF || n64_sar64(cy64, sh) < -0x3FFFF ||
                    n64_sar64(cz64, sh) > 0x7FFF  || n64_sar64(cz64, sh) < -0x7FFF)) {
                sh++;
            }
            s32 d32 = (s32)n64_sar64(cw64, sh);
            if (d32 < 1) d32 = 1;
            s32 ndc_x = ((s32)n64_sar64(cx64, sh) * 1024)  / d32;  /* -1024..+1024 */
            s32 ndc_y = ((s32)n64_sar64(cy64, sh) * 1024)  / d32;
            s32 ndc_z = ((s32)n64_sar64(cz64, sh) * 16383) / d32;
            /* Screen X/Y in 16.4 subpixels: vpt/4 + (ndc * vps/4) / 1024 */
            dv->sx = (vpt_x << 2) + ((ndc_x * vps_x) >> 8);
            dv->sy = (vpt_y << 2) - ((ndc_y * vps_y) >> 8);
            s32 zz = 16384 + ndc_z;
            if (zz < 0) zz = 0; else if (zz > 0x7FFF) zz = 0x7FFF;
            dv->sz = zz;
        } else {
            dv->sx = dv->sy = dv->sz = 0;
        }
        u32 sc_s = (S.tex_scale_s == 0xFFFFu || S.tex_scale_s == 0u) ? 0x10000u : (u32)S.tex_scale_s;
        u32 sc_t = (S.tex_scale_t == 0xFFFFu || S.tex_scale_t == 0u) ? 0x10000u : (u32)S.tex_scale_t;
        dv->s = (s32)n64_sar64((s64)tc_s * (s64)sc_s, 16u);
        dv->t = (s32)n64_sar64((s64)tc_t * (s64)sc_t, 16u);

        if (lit && S.num_lights > 0) {
            s32 nx = (s8)be_r8(RDRAM_BUF, va + 12u);
            s32 ny = (s8)be_r8(RDRAM_BUF, va + 13u);
            s32 nz = (s8)be_r8(RDRAM_BUF, va + 14u);
            /* Ambient is light[num_lights], directional is light[0..num_lights-1] */
            s32 lr = S.light_col[S.num_lights][0];
            s32 lg = S.light_col[S.num_lights][1];
            s32 lb = S.light_col[S.num_lights][2];
            for (u32 l = 0; l < S.num_lights && l < 7u; l++) {
                s32 dot = nx * S.light_dir[l][0] + ny * S.light_dir[l][1] + nz * S.light_dir[l][2];
                if (dot > 0) {
                    s32 inten = dot >> 7;
                    lr += (S.light_col[l][0] * inten) >> 7;
                    lg += (S.light_col[l][1] * inten) >> 7;
                    lb += (S.light_col[l][2] * inten) >> 7;
                }
            }
            dv->r = (u8)(lr > 255 ? 255 : lr);
            dv->g = (u8)(lg > 255 ? 255 : lg);
            dv->b = (u8)(lb > 255 ? 255 : lb);
            dv->a = be_r8(RDRAM_BUF, va + 15u);
        } else {
            dv->r = be_r8(RDRAM_BUF, va + 12u);
            dv->g = be_r8(RDRAM_BUF, va + 13u);
            dv->b = be_r8(RDRAM_BUF, va + 14u);
            dv->a = be_r8(RDRAM_BUF, va + 15u);
        }
    }
}

static void hle_run_dl(u32 dl_addr, int depth)
{
    if (depth > 18) return;
    u32 pc = dl_addr & (N64_RDRAM_SIZE - 8u);
    int tex_on = 0, active_tile = 0;

    for (int guard = 0; guard < 16384; guard++) {
        u32 w0 = be_r32(RDRAM_BUF, pc);
        u32 w1 = be_r32(RDRAM_BUF, pc + 4u);
        pc = (pc + 8u) & (N64_RDRAM_SIZE - 8u);
        u32 op = w0 >> 24;

        switch (op) {
        case 0x00: break;                               /* G_SPNOOP / G_NOOP */

        /* ---- Fast3D / F3DEX Matrix, Movemem, Vertex & Display-List Call ---- */
        case 0x01:                                      /* F3D/F3DEX G_MTX OR F3DEX2 G_VTX! */
            if (S.ucode_kind == 2u) {
                u32 n  = (w0 >> 12) & 0xFFu;
                u32 v0 = ((w0 & 0xFFFu) >> 1) - n;
                hle_load_vertices(n64_seg_addr(w1), v0 & 63u, n);
            } else {
                u32 flags = (w0 >> 16) & 0xFFu;         /* b0=PROJECTION, b1=LOAD, b2=PUSH */
                s32 m[16];
                hle_read_mtx(n64_seg_addr(w1), m);
                if (flags & 1u) {
                    if (flags & 2u) for (int i = 0; i < 16; i++) S.proj_mtx[i] = m[i];
                    else            hle_mtx_mul(m, S.proj_mtx, S.proj_mtx);
                } else {
                    if ((flags & 4u) && S.mv_sp < 9) {
                        for (int i = 0; i < 16; i++) S.mv_stack[S.mv_sp + 1][i] = S.mv_stack[S.mv_sp][i];
                        S.mv_sp++;
                    }
                    if (flags & 2u) for (int i = 0; i < 16; i++) S.mv_stack[S.mv_sp][i] = m[i];
                    else            hle_mtx_mul(m, S.mv_stack[S.mv_sp], S.mv_stack[S.mv_sp]);
                }
                S.mvp_dirty = 1;
            }
            break;

        case 0xDA: {                                    /* F3DEX2 G_MTX */
            u32 flags = (w0 & 0xFFu) ^ 1u;              /* F3DEX2 inverts PUSH bit */
            s32 m[16];
            hle_read_mtx(n64_seg_addr(w1), m);
            if (flags & 4u) {
                if (flags & 2u) for (int i = 0; i < 16; i++) S.proj_mtx[i] = m[i];
                else            hle_mtx_mul(m, S.proj_mtx, S.proj_mtx);
            } else {
                if ((flags & 1u) && S.mv_sp < 9) {
                    for (int i = 0; i < 16; i++) S.mv_stack[S.mv_sp + 1][i] = S.mv_stack[S.mv_sp][i];
                    S.mv_sp++;
                }
                if (flags & 2u) for (int i = 0; i < 16; i++) S.mv_stack[S.mv_sp][i] = m[i];
                else            hle_mtx_mul(m, S.mv_stack[S.mv_sp], S.mv_stack[S.mv_sp]);
            }
            S.mvp_dirty = 1;
            break;
        }

        case 0xBD:                                      /* F3D/F3DEX G_POPMTX */
        case 0xD8:                                      /* F3DEX2 G_POPMTX */
            if (S.mv_sp > 0) { S.mv_sp--; S.mvp_dirty = 1; }
            break;

        case 0x03:                                      /* F3D/F3DEX G_MOVEMEM */
        case 0xDC: {                                    /* F3DEX2 G_MOVEMEM */
            u32 ma = n64_seg_addr(w1);
            u32 idx = (op == 0x03u) ? ((w0 >> 16) & 0xFFu) : (w0 & 0xFFu);
            if (idx == 0x80u || idx == 0x08u) {         /* G_MV_VIEWPORT */
                for (int k = 0; k < 4; k++) S.vp_scale[k] = (s16)be_r16(RDRAM_BUF, ma + (u32)k * 2u);
                for (int k = 0; k < 4; k++) S.vp_trans[k] = (s16)be_r16(RDRAM_BUF, ma + 8u + (u32)k * 2u);
            } else if (idx >= 0x86u && idx <= 0x94u) {  /* G_MV_L0..L7 */
                u32 li = (idx - 0x86u) >> 1;
                if (li < 8u) {
                    S.light_col[li][0] = be_r8(RDRAM_BUF, ma + 0u);
                    S.light_col[li][1] = be_r8(RDRAM_BUF, ma + 1u);
                    S.light_col[li][2] = be_r8(RDRAM_BUF, ma + 2u);
                    S.light_dir[li][0] = (s8)be_r8(RDRAM_BUF, ma + 8u);
                    S.light_dir[li][1] = (s8)be_r8(RDRAM_BUF, ma + 9u);
                    S.light_dir[li][2] = (s8)be_r8(RDRAM_BUF, ma + 10u);
                }
            }
            break;
        }

        case 0x04: {                                    /* F3D / F3DEX G_VTX */
            u32 v0, n;
            if (S.ucode_kind == 1u) {                   /* F3DEX 1.x (Toy Story 2!) */
                v0 = (w0 >> 17) & 0x7Fu;
                n  = (w0 >> 10) & 0x3Fu;
            } else {                                    /* Fast3D (Super Mario 64) */
                n  = ((w0 >> 20) & 0x0Fu) + 1u;
                v0 = (w0 >> 16) & 0x0Fu;
            }
            hle_load_vertices(n64_seg_addr(w1), v0 & 63u, n);
            break;
        }

        case 0x06:                                      /* F3D/F3DEX G_DL OR F3DEX2 G_TRI2! */
            if (S.ucode_kind == 2u) {
                u32 a0 = (w0 >> 17) & 0x3Fu, a1 = (w0 >> 9) & 0x3Fu, a2 = (w0 >> 1) & 0x3Fu;
                u32 b0 = (w1 >> 17) & 0x3Fu, b1 = (w1 >> 9) & 0x3Fu, b2 = (w1 >> 1) & 0x3Fu;
                rdp_draw_tri(&M->vtx_buf[a0], &M->vtx_buf[a1], &M->vtx_buf[a2], tex_on, active_tile);
                rdp_draw_tri(&M->vtx_buf[b0], &M->vtx_buf[b1], &M->vtx_buf[b2], tex_on, active_tile);
                break;
            }
            __attribute__((fallthrough));
        case 0xDE: {                                    /* F3DEX2 G_DL */
            u32 target = n64_seg_addr(w1);
            if ((w0 >> 16) & 0xFFu) {                   /* Branch (no push) */
                pc = target & (N64_RDRAM_SIZE - 8u);
            } else {
                hle_run_dl(target, depth + 1);
            }
            break;
        }

        case 0xB8:                                      /* F3D/F3DEX G_ENDDL */
        case 0xDF:                                      /* F3DEX2 G_ENDDL */
            return;

        case 0xBC:                                      /* F3D/F3DEX G_MOVEWORD */
        case 0xDB: {                                    /* F3DEX2 G_MOVEWORD */
            u32 mw_idx = (op == 0xBCu) ? (w0 & 0xFFu) : ((w0 >> 16) & 0xFFu);
            u32 mw_ofs = (op == 0xBCu) ? ((w0 >> 8) & 0xFFFFu) : (w0 & 0xFFFFu);
            if (mw_idx == 0x06u) {                      /* G_MW_SEGMENT */
                S.segments[(mw_ofs >> 2) & 15u] = w1 & 0x00FFFFFFu;
            } else if (mw_idx == 0x02u) {               /* G_MW_NUMLIGHT */
                S.num_lights = (u8)((op == 0xBCu) ? (((w1 - 0x80000000u) >> 5) - 1u) : (w1 / 24u));
                if (S.num_lights > 7u) S.num_lights = 1u;
            }
            break;
        }

        case 0xB7: S.geom_mode |= w1; break;            /* G_SETGEOMETRYMODE */
        case 0xB6: S.geom_mode &= ~w1; break;           /* G_CLEARGEOMETRYMODE */
        case 0xD9: S.geom_mode = (S.geom_mode & (w0 & 0x00FFFFFFu)) | w1; break; /* F3DEX2 G_GEOMETRYMODE */

        case 0xBB:                                      /* F3D/F3DEX G_TEXTURE */
        case 0xD7:                                      /* F3DEX2 G_TEXTURE */
            tex_on = (op == 0xBBu) ? (w0 & 1u) : ((w0 & 2u) != 0);
            active_tile   = (int)((w0 >> 8) & 7u);
            S.tex_scale_s = (u16)(w1 >> 16);
            S.tex_scale_t = (u16)w1;
            break;

        case 0xB9: S.rdp_other_lo = (S.rdp_other_lo & ~(((1u << (w0 & 31u)) - 1u) << ((w0 >> 8) & 31u))) | w1; break;
        case 0xBA: S.rdp_other_hi = (S.rdp_other_hi & ~(((1u << (w0 & 31u)) - 1u) << ((w0 >> 8) & 31u))) | w1; break;
        case 0xE2: S.rdp_other_lo = (S.rdp_other_lo & ~(((1u << ((w0 & 31u) + 1u)) - 1u) << (32u - ((w0 >> 8) & 31u) - ((w0 & 31u) + 1u)))) | w1; break;
        case 0xE3: S.rdp_other_hi = (S.rdp_other_hi & ~(((1u << ((w0 & 31u) + 1u)) - 1u) << (32u - ((w0 >> 8) & 31u) - ((w0 & 31u) + 1u)))) | w1; break;

        /* ---- Triangles (`G_TRI1`, `G_TRI2`) ---- */
        case 0xBF: {                                    /* F3D / F3DEX G_TRI1 */
            u32 i0, i1, i2;
            if (S.ucode_kind == 1u) {
                i0 = ((w1 >> 17) & 0x3Fu);
                i1 = ((w1 >>  9) & 0x3Fu);
                i2 = ((w1 >>  1) & 0x3Fu);
            } else {
                i0 = ((w1 >> 16) & 0xFFu) / 10u;
                i1 = ((w1 >>  8) & 0xFFu) / 10u;
                i2 = (w1 & 0xFFu) / 10u;
            }
            rdp_draw_tri(&M->vtx_buf[i0 & 63u], &M->vtx_buf[i1 & 63u], &M->vtx_buf[i2 & 63u], tex_on, active_tile);
            break;
        }
        case 0x02:                                      /* F3DEX2 G_MODIFYVTX */
        case 0xB2: {                                    /* F3DEX  G_MODIFYVTX (used heavily by Toy Story 2!) */
            u32 where = (w0 >> 16) & 0xFFu;
            u32 vidx  = ((w0 & 0xFFFFu) >> 1) & 63u;
            struct n64_vtx *dv = &M->vtx_buf[vidx];
            if (where == 0x10u) {                       /* G_MWO_POINT_RGBA */
                dv->r = (u8)(w1 >> 24);
                dv->g = (u8)(w1 >> 16);
                dv->b = (u8)(w1 >>  8);
                dv->a = (u8)w1;
            } else if (where == 0x14u) {                /* G_MWO_POINT_ST */
                dv->s = (s16)(w1 >> 16);
                dv->t = (s16)w1;
            } else if (where == 0x18u) {                /* G_MWO_POINT_XYSCREEN (S13.2 -> 16.4 subpixels!) */
                dv->sx = ((s32)(s16)(w1 >> 16)) << 2;
                dv->sy = ((s32)(s16)w1)         << 2;
                if (dv->w_clip <= 64) dv->w_clip = 1024;
            } else if (where == 0x1Cu) {                /* G_MWO_POINT_ZSCREEN */
                s32 zs = (s32)(w1 >> 16) & 0x7FFFu;
                dv->sz = zs;
                if (dv->w_clip <= 64) dv->w_clip = 1024;
            }
            break;
        }

        case 0x05: {                                    /* F3DEX2 G_TRI1 */
            u32 i0 = (w0 >> 17) & 0x3Fu, i1 = (w0 >> 9) & 0x3Fu, i2 = (w0 >> 1) & 0x3Fu;
            rdp_draw_tri(&M->vtx_buf[i0], &M->vtx_buf[i1], &M->vtx_buf[i2], tex_on, active_tile);
            break;
        }
        case 0x07:                                      /* F3DEX2 G_QUAD */
        case 0xB1:                                      /* F3DEX G_TRI2 */
        case 0xB5: {                                    /* F3DEX G_QUAD */
            u32 a0 = (w0 >> 17) & 0x3Fu, a1 = (w0 >> 9) & 0x3Fu, a2 = (w0 >> 1) & 0x3Fu;
            u32 b0 = (w1 >> 17) & 0x3Fu, b1 = (w1 >> 9) & 0x3Fu, b2 = (w1 >> 1) & 0x3Fu;
            if (op == 0xB5u && S.ucode_kind == 0u) {    /* Fast3D G_QUAD (/10 indices) */
                a0 = ((w1 >> 24) & 0xFFu) / 10u; a1 = ((w1 >> 16) & 0xFFu) / 10u; a2 = ((w1 >> 8) & 0xFFu) / 10u;
                b0 = a0; b1 = a2; b2 = (w1 & 0xFFu) / 10u;
            }
            rdp_draw_tri(&M->vtx_buf[a0 & 63u], &M->vtx_buf[a1 & 63u], &M->vtx_buf[a2 & 63u], tex_on, active_tile);
            rdp_draw_tri(&M->vtx_buf[b0 & 63u], &M->vtx_buf[b1 & 63u], &M->vtx_buf[b2 & 63u], tex_on, active_tile);
            break;
        }

        /* ---- Direct RDP Rasterizer & TMEM Commands (`0xE4..0xFF`) ---- */
        case 0xE4: {                                    /* G_TEXRECT (128-bit / 2-word + RDPHALF_1/2!) */
            int lrx = (int)((w0 >> 14) & 0x3FFu);
            int lry = (int)((w0 >>  2) & 0x3FFu);
            int tid = (int)((w1 >> 24) & 7u);
            int ulx = (int)((w1 >> 14) & 0x3FFu);
            int uly = (int)((w1 >>  2) & 0x3FFu);
            u32 h0 = be_r32(RDRAM_BUF, pc);
            u32 h1 = be_r32(RDRAM_BUF, pc + 4u);
            u32 h2 = be_r32(RDRAM_BUF, pc + 8u);
            u32 h3 = be_r32(RDRAM_BUF, pc + 12u);
            int s0, t0, dsdx, dtdy;
            if ((h0 >> 24) == 0xB3u || (h0 >> 24) == 0xB4u || (h0 >> 24) == 0xE1u) {
                pc = (pc + 16u) & (N64_RDRAM_SIZE - 8u);
                s0   = ((s16)(h1 >> 16)) << 5;
                t0   = ((s16)h1)         << 5;
                dsdx = (s16)(h3 >> 16);
                dtdy = (s16)h3;
            } else {
                pc = (pc + 8u) & (N64_RDRAM_SIZE - 8u);
                s0   = ((s16)(h0 >> 16)) << 5;
                t0   = ((s16)h0)         << 5;
                dsdx = (s16)(h1 >> 16);
                dtdy = (s16)h1;
            }
            (void)h2;
            rdp_tex_rect(ulx, uly, lrx, lry, tid, s0, t0, dsdx, dtdy);
            break;
        }

        case 0xE9:                                      /* G_RDPFULLSYNC */
            n64_raise_mi(MI_INTR_DP);
            break;

        case 0xED:                                      /* G_SETSCISSOR */
            S.scis_ulx = (u16)((w0 >> 12) & 0xFFFu);
            S.scis_uly = (u16)(w0 & 0xFFFu);
            S.scis_lrx = (u16)((w1 >> 12) & 0xFFFu);
            S.scis_lry = (u16)(w1 & 0xFFFu);
            break;

        case 0xEF:                                      /* G_SETOTHERMODE */
            S.rdp_other_hi = w0 & 0x00FFFFFFu;
            S.rdp_other_lo = w1;
            break;

        case 0xF0: {                                    /* G_LOADTLUT */
            u32 tid = (w1 >> 24) & 7u;
            u32 count = (((w1 >> 12) & 0xFFFu) >> 2) + 1u;
            u32 dst = 0x800u + ((S.tiles[tid].tmem * 8u) & 0x7FEu);
            u32 src = S.tex_img_addr & (N64_RDRAM_SIZE - 2u);
            for (u32 i = 0; i < count && dst + i * 2u < 4096u; i++)
                be_w16(M->tmem, dst + i * 2u, be_r16(RDRAM_BUF, (src + i * 2u) & (N64_RDRAM_SIZE - 2u)));
            break;
        }

        case 0xF2: {                                    /* G_SETTILESIZE */
            u32 tid = (w1 >> 24) & 7u;
            S.tiles[tid].uls = (u16)((w0 >> 12) & 0xFFFu);
            S.tiles[tid].ult = (u16)(w0 & 0xFFFu);
            S.tiles[tid].lrs = (u16)((w1 >> 12) & 0xFFFu);
            S.tiles[tid].lrt = (u16)(w1 & 0xFFFu);
            break;
        }

        case 0xF3: {                                    /* G_LOADBLOCK */
            u32 tid = (w1 >> 24) & 7u;
            u32 texels = ((w1 >> 12) & 0xFFFu) + 1u;
            u32 nbytes = (S.tex_img_siz == 2u) ? (texels * 2u) : (S.tex_img_siz == 3u ? texels * 4u : texels);
            if (nbytes > 4096u) nbytes = 4096u;
            u32 dst = (S.tiles[tid].tmem * 8u) & 0xFFFu;
            u32 src = S.tex_img_addr & (N64_RDRAM_SIZE - 4u);
            for (u32 i = 0; i < nbytes; i++)
                be_w8(M->tmem, (dst + i) & 0xFFFu, be_r8(RDRAM_BUF, (src + i) & (N64_RDRAM_SIZE - 1u)));
            break;
        }

        case 0xF4: {                                    /* G_LOADTILE */
            u32 tid = (w1 >> 24) & 7u;
            S.tiles[tid].uls = (u16)((w0 >> 12) & 0xFFFu);
            S.tiles[tid].ult = (u16)(w0 & 0xFFFu);
            S.tiles[tid].lrs = (u16)((w1 >> 12) & 0xFFFu);
            S.tiles[tid].lrt = (u16)(w1 & 0xFFFu);
            u32 uls = S.tiles[tid].uls >> 2, ult = S.tiles[tid].ult >> 2;
            u32 lrs = S.tiles[tid].lrs >> 2, lrt = S.tiles[tid].lrt >> 2;
            u32 bpp_sh = S.tex_img_siz;                 /* 1=8b, 2=16b */
            u32 dst_base = (S.tiles[tid].tmem * 8u) & 0xFFFu;
            u32 dst_stride = S.tiles[tid].line ? (S.tiles[tid].line * 8u) : (((lrs - uls + 1u) << bpp_sh) >> 1);
            u32 src_stride = ((S.tex_img_width << bpp_sh) >> 1);
            for (u32 y = ult; y <= lrt; y++) {
                u32 row_len = ((lrs - uls + 1u) << bpp_sh) >> 1;
                u32 sa = S.tex_img_addr + y * src_stride + ((uls << bpp_sh) >> 1);
                u32 da = dst_base + (y - ult) * dst_stride;
                for (u32 b = 0; b < row_len; b++)
                    be_w8(M->tmem, (da + b) & 0xFFFu, be_r8(RDRAM_BUF, (sa + b) & (N64_RDRAM_SIZE - 1u)));
            }
            break;
        }

        case 0xF5: {                                    /* G_SETTILE */
            u32 tid = (w1 >> 24) & 7u;
            struct n64_tile *tl = &S.tiles[tid];
            tl->fmt     = (w0 >> 21) & 7u;
            tl->siz     = (w0 >> 19) & 3u;
            tl->line    = (w0 >>  9) & 0x1FFu;
            tl->tmem    = w0 & 0x1FFu;
            tl->palette = (w1 >> 20) & 15u;
            tl->cmt     = (w1 >> 18) & 3u;
            tl->maskt   = (w1 >> 14) & 15u;
            tl->shiftt  = (w1 >> 10) & 15u;
            tl->cms     = (w1 >>  8) & 3u;
            tl->masks   = (w1 >>  4) & 15u;
            tl->shifts  = w1 & 15u;
            break;
        }

        case 0xF6: {                                    /* G_FILLRECT */
            int lrx = (int)((w0 >> 14) & 0x3FFu);
            int lry = (int)((w0 >>  2) & 0x3FFu);
            int ulx = (int)((w1 >> 14) & 0x3FFu);
            int uly = (int)((w1 >>  2) & 0x3FFu);
            rdp_fill_rect(ulx, uly, lrx, lry);
            break;
        }

        case 0xF7: S.fill_color  = w1; break;
        case 0xF8: S.fog_color   = w1; break;
        case 0xF9: S.blend_color = w1; break;
        case 0xFA: S.prim_color  = w1; break;
        case 0xFB: S.env_color   = w1; break;
        case 0xFC: S.rdp_combine_hi = w0 & 0x00FFFFFFu; S.rdp_combine_lo = w1; break;

        case 0xFD:                                      /* G_SETTIMG */
            S.tex_img_fmt   = (w0 >> 21) & 7u;
            S.tex_img_siz   = (w0 >> 19) & 3u;
            S.tex_img_width = (w0 & 0xFFFu) + 1u;
            S.tex_img_addr  = n64_seg_addr(w1);
            break;

        case 0xFE:                                      /* G_SETZIMG */
            S.z_img_addr = n64_seg_addr(w1);
            break;

        case 0xFF:                                      /* G_SETCIMG */
            S.color_img_siz   = (w0 >> 19) & 3u;
            S.color_img_width = (w0 & 0xFFFu) + 1u;
            S.color_img_addr  = n64_seg_addr(w1);
            break;
        }
    }
}

static void n64_rsp_launch_task(void)
{
    /* Inspect libultra OSTask header at SP_DMEM[0xFC0..0xFFF] */
    u32 task_type = be_r32(M->sp_dmem, 0xFC0u);
    u32 ucode_data= be_r32(M->sp_dmem, 0xFD8u) & (N64_RDRAM_SIZE - 1u);
    u32 ucode_dsz = be_r32(M->sp_dmem, 0xFDCu);
    u32 data_ptr  = be_r32(M->sp_dmem, 0xFF0u) & (N64_RDRAM_SIZE - 1u);

    if (task_type == 1u && data_ptr != 0u) {            /* M_GFXTASK! */
        /* Detect microcode variant from ucode_data string ("F3DEX", "F3DZEX", "RSP SW") */
        S.ucode_kind = 1u;                              /* Default F3DEX 1.x */
        u32 scan_len = (ucode_dsz > 0 && ucode_dsz <= 4096u) ? ucode_dsz : 2048u;
        for (u32 i = 0; i + 8u < scan_len && ucode_data + i + 8u < N64_RDRAM_SIZE; i++) {
            u8 c0 = be_r8(RDRAM_BUF, ucode_data + i);
            if (c0 == 'F' && be_r8(RDRAM_BUF, ucode_data + i + 1u) == '3' && be_r8(RDRAM_BUF, ucode_data + i + 2u) == 'D') {
                u8 c5 = be_r8(RDRAM_BUF, ucode_data + i + 5u);
                u8 c6 = be_r8(RDRAM_BUF, ucode_data + i + 6u);
                if (c5 == '2' || c6 == '2' || be_r8(RDRAM_BUF, ucode_data + i + 3u) == 'Z')
                    S.ucode_kind = 2u;                  /* F3DEX2 / F3DZEX */
                else
                    S.ucode_kind = 1u;                  /* F3DEX 1.x */
                break;
            }
            if (c0 == 'R' && be_r8(RDRAM_BUF, ucode_data + i + 4u) == 'S' && be_r8(RDRAM_BUF, ucode_data + i + 5u) == 'W') {
                S.ucode_kind = 0u;                      /* Fast3D 1.0/2.0 */
                break;
            }
        }
        S.mv_sp = 0;
        hle_run_dl(data_ptr, 0);
        S.sp_status |= 0x0203u;                         /* HALT | BROKE | TASKDONE(SIG2) */
        if (S.sp_status & 0x0040u)                      /* INTR_BREAK */
            n64_raise_mi(MI_INTR_SP);
        n64_raise_mi(MI_INTR_DP);
        return;
    }

    if (task_type == 2u) {                              /* M_AUDTASK (ABI1/ABI2 HLE completion) */
        S.sp_status |= 0x0203u;
        if (S.sp_status & 0x0040u)
            n64_raise_mi(MI_INTR_SP);
        return;
    }

    /* Custom RSP task: mark halted + broke + raise SP interrupt if enabled */
    S.sp_status |= 0x0203u;
    if (S.sp_status & 0x0040u)
        n64_raise_mi(MI_INTR_SP);
}

#pragma GCC reset_options

/* ============================================================================
   RCP Physical Memory Bus ($00000000..$1FFFFFFF) & TLB Translation
   ============================================================================ */

static u32 n64_io_r32(u32 pa)
{
    u32 grp = (pa >> 16) & 0xFFFFu;
    if (pa >= 0x04000000u && pa < 0x04001000u) return be_r32(M->sp_dmem, pa & 0xFFCu);
    if (pa >= 0x04001000u && pa < 0x04002000u) return be_r32(M->sp_imem, pa & 0xFFCu);
    if (pa >= 0x10000000u && pa < 0x1FC00000u) {
        if (S.cycles < S.pi_io_busy_until)
            return S.pi_io_latch;
        u32 off = pa - 0x10000000u;
        return (off < S.rom_size) ? be_r32(ROM_BUF, off) : 0u;
    }
    if (pa >= 0x1FC007C0u && pa < 0x1FC00800u) return be_r32(M->pif_ram, pa - 0x1FC007C0u);

    switch (grp) {
    case 0x0404:                                        /* SP Registers */
        switch (pa & 0x1Fu) {
        case 0x00: return S.sp_mem_addr;
        case 0x04: return S.sp_dram_addr;
        case 0x10: return S.sp_status;
        case 0x14: return 0u;                           /* SP_DMA_FULL = 0 */
        case 0x18: return 0u;                           /* SP_DMA_BUSY = 0 */
        case 0x1C: { u32 s = S.sp_semaphore; S.sp_semaphore = 1u; return s; }
        }
        return 0;
    case 0x0408: return S.sp_pc;
    case 0x0410:                                        /* DPC Registers */
        switch (pa & 0x1Fu) {
        case 0x00: return S.dpc_start;
        case 0x04: return S.dpc_end;
        case 0x08: return S.dpc_current;
        case 0x0C: return (S.dpc_status & 7u) | 0x80u;  /* CBUF_READY = 1, busy = 0 */
        }
        return 0;
    case 0x0430:                                        /* MI Registers */
        switch (pa & 0x0Fu) {
        case 0x00: return S.mi_mode;
        case 0x04: return 0x02020102u;                  /* MI_VERSION */
        case 0x08: return S.mi_intr;
        case 0x0C: return S.mi_mask;
        }
        return 0;
    case 0x0440:                                        /* VI Registers */
        switch (pa & 0x3Fu) {
        case 0x00: return S.vi_status;
        case 0x04: return S.vi_origin;
        case 0x08: return S.vi_width;
        case 0x0C: return S.vi_intr;
        case 0x10: return S.vi_current;
        case 0x24: return S.vi_h_start;
        case 0x28: return S.vi_v_start;
        case 0x30: return S.vi_x_scale;
        case 0x34: return S.vi_y_scale;
        }
        return 0;
    case 0x0450:                                        /* AI Registers */
        if ((pa & 0x1Fu) == 0x04u) return S.ai_fifo_cnt ? S.ai_fifo_len[0] : 0u;
        if ((pa & 0x1Fu) == 0x0Cu)
            return (S.ai_fifo_cnt >= 2 ? 0x80000001u : 0u) | (S.ai_fifo_cnt >= 1 ? 0x40000000u : 0u);
        return 0;
    case 0x0460:                                        /* PI Registers */
        switch (pa & 0x1Fu) {
        case 0x00: return S.pi_dram_addr;
        case 0x04: return S.pi_cart_addr;
        case 0x10: return 0u;                           /* PI_STATUS: DMA idle */
        }
        return 0;
    case 0x0470:                                        /* RI Registers */
        if ((pa & 0x1Fu) == 0x0Cu) return S.ri_select ? S.ri_select : 0x14u;
        return 0;
    case 0x0480:                                        /* SI Registers */
        if ((pa & 0x1Fu) == 0x00u) return S.si_dram_addr;
        if ((pa & 0x1Fu) == 0x18u) return (S.mi_intr & MI_INTR_SI) ? 0x1000u : 0u;
        return 0;
    }
    return 0;
}

static void n64_ai_push_dma(u32 dram_a, u32 len_bytes)
{
    len_bytes &= ~7u;
    if (!len_bytes) return;

    u32 dac_hz = 48681812u / ((S.ai_dacrate ? S.ai_dacrate : 1099u) + 1u);
    if (dac_hz < 8000u || dac_hz > 96000u) dac_hz = 44100u;
    u32 out_hz = S.sample_rate ? S.sample_rate : 48000u;

    /* Resample signed 16-bit BE stereo frames from RDRAM -> 48 kHz mono ring! */
    u32 frames = len_bytes >> 2;
    u32 phase = 0;
    u32 step  = (dac_hz << 12) / out_hz;
    if (!step) step = 4096u;
    while ((phase >> 12) < frames) {
        u32 idx = phase >> 12;
        u32 fa = (dram_a + idx * 4u) & (N64_RDRAM_SIZE - 4u);
        u32 lr = be_r32(RDRAM_BUF, fa);
        s32 l = (s16)(lr >> 16), r = (s16)lr;
        s32 mono = (l + r) >> 1;
        if (S.snd_head - S.snd_tail < N64_SND_RING)
            M->snd_ring[S.snd_head++ & (N64_SND_RING - 1u)] = (s16)mono;
        phase += step;
    }

    if (S.ai_fifo_cnt < 2) {
        S.ai_fifo_len[S.ai_fifo_cnt] = len_bytes;
        S.ai_fifo_cnt++;
        if (S.ai_fifo_cnt == 1)
            S.ai_cycles_left = (s32)((frames * (93750000u / 1000u)) / (dac_hz / 1000u ? dac_hz / 1000u : 44u));
    }
}

static void n64_io_w32(u32 pa, u32 v)
{
    u32 grp = (pa >> 16) & 0xFFFFu;
    if (pa >= 0x04000000u && pa < 0x04001000u) { be_w32(M->sp_dmem, pa & 0xFFCu, v); return; }
    if (pa >= 0x04001000u && pa < 0x04002000u) { be_w32(M->sp_imem, pa & 0xFFCu, v); return; }
    if (pa >= 0x10000000u && pa < 0x1FC00000u) {
        /* Real N64 PI Domain-1 CPU write latch: sets IO_BUSY for ~160 CPU cycles! */
        S.pi_io_latch = v;
        S.pi_io_busy_until = S.cycles + 160;
        return;
    }
    if (pa >= 0x1FC007C0u && pa < 0x1FC00800u) {
        be_w32(M->pif_ram, pa - 0x1FC007C0u, v);
        if ((pa & 0xFFFu) == 0x7FCu) n64_pif_process();
        return;
    }

    switch (grp) {
    case 0x0404:                                        /* SP Registers */
        switch (pa & 0x1Fu) {
        case 0x00: S.sp_mem_addr  = v & 0x1FFFu; break;
        case 0x04: S.sp_dram_addr = v & 0x00FFFFFFu; break;
        case 0x08: {                                    /* SP_RD_LEN: RDRAM -> SP DMEM/IMEM */
            u32 len  = (v & 0xFFFu) + 1u;
            u32 cnt  = ((v >> 12) & 0xFFu) + 1u;
            u32 skip = (v >> 20) & 0xFFFu;
            u8 *sp_b = (S.sp_mem_addr & 0x1000u) ? M->sp_imem : M->sp_dmem;
            u32 ma = S.sp_mem_addr & 0xFFFu, da = S.sp_dram_addr;
            for (u32 c = 0; c < cnt; c++) {
                be_copy_bytes(sp_b, ma, RDRAM_BUF, da, len, 0xFFFu, N64_RDRAM_SIZE - 1u);
                ma = (ma + len) & 0xFFFu;
                da += len + skip;
            }
            break;
        }
        case 0x0C: {                                    /* SP_WR_LEN: SP DMEM/IMEM -> RDRAM */
            u32 len  = (v & 0xFFFu) + 1u;
            u32 cnt  = ((v >> 12) & 0xFFu) + 1u;
            u32 skip = (v >> 20) & 0xFFFu;
            const u8 *sp_b = (S.sp_mem_addr & 0x1000u) ? M->sp_imem : M->sp_dmem;
            u32 ma = S.sp_mem_addr & 0xFFFu, da = S.sp_dram_addr;
            for (u32 c = 0; c < cnt; c++) {
                be_copy_bytes(RDRAM_BUF, da, sp_b, ma, len, N64_RDRAM_SIZE - 1u, 0xFFFu);
                ma = (ma + len) & 0xFFFu;
                da += len + skip;
            }
            break;
        }
        case 0x10: {                                    /* SP_STATUS */
            int was_halted = (S.sp_status & 1u) != 0;
            if (v & 0x00000001u) S.sp_status &= ~0x0001u; /* CLR_HALT */
            if (v & 0x00000002u) S.sp_status |=  0x0001u; /* SET_HALT */
            if (v & 0x00000004u) S.sp_status &= ~0x0002u; /* CLR_BROKE */
            if (v & 0x00000008u) n64_clear_mi(MI_INTR_SP);/* CLR_INTR */
            if (v & 0x00000010u) n64_raise_mi(MI_INTR_SP);/* SET_INTR */
            if (v & 0x00000080u) S.sp_status &= ~0x0040u; /* CLR_INTR_BREAK */
            if (v & 0x00000100u) S.sp_status |=  0x0040u; /* SET_INTR_BREAK */
            for (int sig = 0; sig < 8; sig++) {
                if (v & (1u << (9 + sig * 2)))      S.sp_status &= ~(1u << (7 + sig));
                if (v & (1u << (9 + sig * 2 + 1)))  S.sp_status |=  (1u << (7 + sig));
            }
            if (was_halted && !(S.sp_status & 1u))
                n64_rsp_launch_task();
            break;
        }
        case 0x1C: S.sp_semaphore = 0u; break;
        }
        return;

    case 0x0408: S.sp_pc = v & 0xFFCu; return;

    case 0x0410:                                        /* DPC Registers */
        switch (pa & 0x1Fu) {
        case 0x00: S.dpc_start = S.dpc_current = v & 0x00FFFFF8u; break;
        case 0x04:
            S.dpc_end = v & 0x00FFFFF8u;
            S.dpc_current = S.dpc_end;
            n64_raise_mi(MI_INTR_DP);
            break;
        case 0x0C:
            if (v & 0x0001u) S.dpc_status &= ~0x0001u;
            if (v & 0x0002u) S.dpc_status |=  0x0001u;
            if (v & 0x0004u) S.dpc_status &= ~0x0002u;
            if (v & 0x0008u) S.dpc_status |=  0x0002u;
            break;
        }
        return;

    case 0x0430:                                        /* MI Registers */
        if ((pa & 0x0Fu) == 0x00u) {
            S.mi_mode = (S.mi_mode & ~0x7Fu) | (v & 0x7Fu);
            if (v & 0x0800u) n64_clear_mi(MI_INTR_DP);  /* MI_CLR_DP_INTR */
        } else if ((pa & 0x0Fu) == 0x0Cu) {
            for (int b = 0; b < 6; b++) {
                if (v & (1u << (b * 2)))     S.mi_mask &= ~(1u << b);
                if (v & (1u << (b * 2 + 1))) S.mi_mask |=  (1u << b);
            }
            n64_update_irq_line();
        }
        return;

    case 0x0440:                                        /* VI Registers */
        switch (pa & 0x3Fu) {
        case 0x00: S.vi_status  = v; break;
        case 0x04: S.vi_origin  = v & 0x00FFFFFFu; break;
        case 0x08: S.vi_width   = v & 0xFFFu; break;
        case 0x0C: S.vi_intr    = v & 0x3FFu; break;
        case 0x10: n64_clear_mi(MI_INTR_VI); break;     /* Writing VI_CURRENT clears VI IRQ! */
        case 0x24: S.vi_h_start = v; break;
        case 0x28: S.vi_v_start = v; break;
        case 0x30: S.vi_x_scale = v; break;
        case 0x34: S.vi_y_scale = v; break;
        }
        return;

    case 0x0450:                                        /* AI Registers */
        switch (pa & 0x1Fu) {
        case 0x00: S.ai_dram_addr = v & 0x00FFFFF8u; break;
        case 0x04: n64_ai_push_dma(S.ai_dram_addr, v & 0x3FFFFu); break;
        case 0x08: S.ai_control = v & 1u; break;
        case 0x0C: n64_clear_mi(MI_INTR_AI); break;
        case 0x10: S.ai_dacrate = v & 0x3FFFu; break;
        case 0x14: S.ai_bitrate = v & 0x0Fu; break;
        }
        return;

    case 0x0460:                                        /* PI Registers */
        switch (pa & 0x1Fu) {
        case 0x00: S.pi_dram_addr = v & 0x00FFFFFEu; break;
        case 0x04: S.pi_cart_addr = v & 0x1FFFFFFEu; break;
        case 0x08: {                                    /* PI_RD_LEN: RDRAM -> Cart SRAM */
            u32 len = (v & 0x00FFFFFFu) + 1u;
            if ((S.pi_cart_addr >> 24) == 0x08u) {
                u32 sa = S.pi_cart_addr & (N64_SAVE_SIZE - 1u);
                for (u32 i = 0; i < len && sa + i < N64_SAVE_SIZE; i++)
                    M->save_ram[sa + i] = be_r8(RDRAM_BUF, (S.pi_dram_addr + i) & (N64_RDRAM_SIZE - 1u));
                S.save_dirty = 1u;
            }
            n64_raise_mi(MI_INTR_PI);
            break;
        }
        case 0x0C: {                                    /* PI_WR_LEN: Cart ROM/SRAM -> RDRAM */
            u32 len = (v & 0x00FFFFFFu) + 1u;
            if (S.pi_cart_addr >= 0x10000000u && S.pi_cart_addr < 0x1FC00000u) {
                u32 ca = S.pi_cart_addr - 0x10000000u;
                u32 da = S.pi_dram_addr;
                if (((ca | da | len) & 3u) == 0u && ca + len <= S.rom_size && da + len <= N64_RDRAM_SIZE) {
                    for (u32 i = 0; i < len; i += 4u)
                        be_w32(RDRAM_BUF, da + i, be_r32(ROM_BUF, ca + i));
                } else {
                    for (u32 i = 0; i < len && da + i < N64_RDRAM_SIZE; i++) {
                        u8 b = (ca + i < S.rom_size) ? be_r8(ROM_BUF, ca + i) : 0u;
                        be_w8(RDRAM_BUF, da + i, b);
                    }
                }
            } else if ((S.pi_cart_addr >> 24) == 0x08u) {
                u32 sa = S.pi_cart_addr & (N64_SAVE_SIZE - 1u);
                for (u32 i = 0; i < len && sa + i < N64_SAVE_SIZE; i++)
                    be_w8(RDRAM_BUF, (S.pi_dram_addr + i) & (N64_RDRAM_SIZE - 1u), M->save_ram[sa + i]);
            }
            n64_raise_mi(MI_INTR_PI);
            break;
        }
        case 0x10:
            if (v & 0x02u) n64_clear_mi(MI_INTR_PI);
            break;
        }
        return;

    case 0x0470:
        if ((pa & 0x1Fu) == 0x0Cu) S.ri_select = v;
        return;

    case 0x0480:                                        /* SI Registers (PIF 64B DMA!) */
        switch (pa & 0x1Fu) {
        case 0x00: S.si_dram_addr = v & 0x00FFFFFCu; break;
        case 0x04:                                      /* SI_PIF_ADDR_RD64B: PIF -> RDRAM */
            n64_pif_process();
            be_copy_bytes(RDRAM_BUF, S.si_dram_addr, M->pif_ram, 0, 64u, N64_RDRAM_SIZE - 1u, 63u);
            n64_raise_mi(MI_INTR_SI);
            break;
        case 0x10:                                      /* SI_PIF_ADDR_WR64B: RDRAM -> PIF */
            be_copy_bytes(M->pif_ram, 0, RDRAM_BUF, S.si_dram_addr, 64u, 63u, N64_RDRAM_SIZE - 1u);
            n64_pif_process();
            n64_raise_mi(MI_INTR_SI);
            break;
        case 0x18:
            n64_clear_mi(MI_INTR_SI);
            break;
        }
        return;
    }
}

/* ---- Virtual-to-Physical Translation (KSEG0/KSEG1 Fast Path + 32-Entry TLB) ---- */
INLINE u32 n64_v2p(u32 va)
{
    u32 seg = va >> 29;
    if (seg == 4u || seg == 5u)         /* KSEG0 (0x80000000) & KSEG1 (0xA0000000) */
        return va & 0x1FFFFFFFu;

    for (int i = 0; i < 32; i++) {
        const struct n64_tlb *t = &M->tlb[i];
        u32 mask = t->page_mask | 0x1FFFu;
        u32 vpn2 = ~mask;
        if (((va ^ t->entry_hi) & vpn2 & ~0x1FFFu) == 0u) {
            u32 odd = va & ((mask + 1u) >> 1);
            if (odd ? t->valid1 : t->valid0) {
                u32 lo = odd ? t->entry_lo1 : t->entry_lo0;
                u32 pfn = (lo >> 6) << 12;
                return (pfn & ~(mask >> 1)) | (va & (mask >> 1));
            }
        }
    }
    return va & 0x1FFFFFFFu;
}

INLINE u8  n64_r8(u32 va)  { u32 pa = n64_v2p(va); if (pa < N64_RDRAM_SIZE) return be_r8(RDRAM_BUF, pa);  u32 w = n64_io_r32(pa & ~3u); return (u8)(w >> ((3u - (pa & 3u)) * 8u)); }
INLINE u16 n64_r16(u32 va) { u32 pa = n64_v2p(va); if (pa < N64_RDRAM_SIZE) return be_r16(RDRAM_BUF, pa); u32 w = n64_io_r32(pa & ~3u); return (u16)(w >> ((2u - (pa & 2u)) * 8u)); }
INLINE u32 n64_r32(u32 va) { u32 pa = n64_v2p(va); return (pa < N64_RDRAM_SIZE) ? be_r32(RDRAM_BUF, pa) : n64_io_r32(pa); }
INLINE u64 n64_r64(u32 va) { u32 pa = n64_v2p(va); if (pa < N64_RDRAM_SIZE) return ((u64)be_r32(RDRAM_BUF, pa) << 32) | be_r32(RDRAM_BUF, pa + 4u); return ((u64)n64_io_r32(pa) << 32) | n64_io_r32(pa + 4u); }

INLINE void n64_w8(u32 va, u8 v)   { u32 pa = n64_v2p(va); if (pa < N64_RDRAM_SIZE) be_w8(RDRAM_BUF, pa, v); }
INLINE void n64_w16(u32 va, u16 v) { u32 pa = n64_v2p(va); if (pa < N64_RDRAM_SIZE) be_w16(RDRAM_BUF, pa, v); }
INLINE void n64_w32(u32 va, u32 v) { u32 pa = n64_v2p(va); if (pa < N64_RDRAM_SIZE) be_w32(RDRAM_BUF, pa, v); else n64_io_w32(pa, v); }
INLINE void n64_w64(u32 va, u64 v) { u32 pa = n64_v2p(va); if (pa < N64_RDRAM_SIZE) { be_w32(RDRAM_BUF, pa, (u32)(v >> 32)); be_w32(RDRAM_BUF, pa + 4u, (u32)v); } else { n64_io_w32(pa, (u32)(v >> 32)); n64_io_w32(pa + 4u, (u32)v); } }

/* ============================================================================
   Pure-Integer Bit-Exact COP1 IEEE-754 Single & Double Precision FPU
   (Zero C float/double, zero libgcc __divdf3/__udivdi3 — 100% identical PC == MIPS!)
   ============================================================================ */

static u32 fpu_d_to_s(u64 d)
{
    u32 sign = (u32)(d >> 63) << 31;
    int exp  = (int)((d >> 52) & 0x7FFULL);
    u64 frac = d & 0x000FFFFFFFFFFFFFULL;
    if (exp == 0x7FF) return sign | 0x7F800000u | (frac ? 0x00400000u : 0u);
    if (exp == 0) return sign;
    int se = exp - 1023 + 127;
    if (se <= 0) return sign;
    if (se >= 255) return sign | 0x7F800000u;
    return sign | ((u32)se << 23) | (u32)(frac >> 29);
}

static u64 fpu_s_to_d(u32 s)
{
    u64 sign = (u64)(s >> 31) << 63;
    int exp  = (int)((s >> 23) & 0xFFu);
    u64 frac = s & 0x7FFFFFu;
    if (exp == 0xFF) return sign | 0x7FF0000000000000ULL | (frac ? 0x0008000000000000ULL : 0ULL);
    if (exp == 0) return sign;
    u64 de = (u64)(exp - 127 + 1023);
    return sign | (de << 52) | (frac << 29);
}

static u32 fpu_i32_to_s(s32 x)
{
    if (x == 0) return 0u;
    u32 sign = (x < 0) ? 0x80000000u : 0u;
    u32 mag  = (x < 0) ? (0u - (u32)x) : (u32)x;
    int exp  = 158;
    while (mag >= 0x01000000u) { mag = (mag + 1u) >> 1; exp++; }
    while (mag <  0x00800000u) { mag <<= 1; exp--; }
    return sign | ((u32)exp << 23) | (mag & 0x7FFFFFu);
}

static s32 fpu_s_to_i32(u32 s)
{
    int exp = (int)((s >> 23) & 0xFFu) - 127;
    if (exp < 0) return 0;
    if (exp >= 31) return (s & 0x80000000u) ? (s32)0x80000000u : 0x7FFFFFFF;
    u32 m = (s & 0x7FFFFFu) | 0x800000u;
    u32 mag = (exp >= 23) ? (m << (exp - 23)) : (m >> (23 - exp));
    return (s & 0x80000000u) ? -(s32)mag : (s32)mag;
}

static u32 fpu_add_s(u32 a, u32 b)
{
    if ((a & 0x7FFFFFFFu) == 0u) return b;
    if ((b & 0x7FFFFFFFu) == 0u) return a;
    u32 sa = a >> 31, sb = b >> 31;
    int ea = (int)((a >> 23) & 0xFFu), eb = (int)((b >> 23) & 0xFFu);
    if (ea == 0xFF) return a;
    if (eb == 0xFF) return b;
    u32 ma = ((a & 0x7FFFFFu) | 0x800000u) << 6;
    u32 mb = ((b & 0x7FFFFFu) | 0x800000u) << 6;
    if (ea < eb || (ea == eb && ma < mb)) {
        u32 ts = sa; sa = sb; sb = ts;
        int te = ea; ea = eb; eb = te;
        u32 tm = ma; ma = mb; mb = tm;
    }
    int diff = ea - eb;
    mb = (diff >= 31) ? 0u : (mb >> diff);
    u32 mr = (sa == sb) ? (ma + mb) : (ma - mb);
    if (mr == 0u) return 0u;
    while (mr >= 0x40000000u) { mr >>= 1; ea++; }
    while (mr <  0x20000000u && ea > 0) { mr <<= 1; ea--; }
    if (ea <= 0) return 0u;
    if (ea >= 255) return (sa << 31) | 0x7F800000u;
    return (sa << 31) | ((u32)ea << 23) | (((mr + 0x20u) >> 6) & 0x7FFFFFu);
}

static u32 fpu_mul_s(u32 a, u32 b)
{
    u32 s = (a ^ b) & 0x80000000u;
    int ea = (int)((a >> 23) & 0xFFu), eb = (int)((b >> 23) & 0xFFu);
    if (ea == 0 || eb == 0) return s;
    if (ea == 0xFF || eb == 0xFF) return s | 0x7F800000u;
    u32 ma = (a & 0x7FFFFFu) | 0x800000u;
    u32 mb = (b & 0x7FFFFFu) | 0x800000u;
    u32 hi, lo;
    n64_mulu32(ma, mb, &hi, &lo);
    u32 m = (hi << 9) | (lo >> 23);
    int er = ea + eb - 127;
    if (m >= 0x01000000u) { m = (m + 1u) >> 1; er++; }
    if (er <= 0) return s;
    if (er >= 255) return s | 0x7F800000u;
    return s | ((u32)er << 23) | (m & 0x7FFFFFu);
}

static u32 fpu_div_s(u32 a, u32 b)
{
    u32 s = (a ^ b) & 0x80000000u;
    int ea = (int)((a >> 23) & 0xFFu), eb = (int)((b >> 23) & 0xFFu);
    if (eb == 0) return s | 0x7F800000u;
    if (ea == 0) return s;
    u32 num = (a & 0x7FFFFFu) | 0x800000u;
    u32 den = (b & 0x7FFFFFu) | 0x800000u;
    int er = ea - eb + 127;
    if (num < den) { num <<= 1; er--; }
    u32 q = 0u;
    for (int i = 23; i >= 0; i--) {
        if (num >= den) { num -= den; q |= (1u << i); }
        num <<= 1;
    }
    if (er <= 0) return s;
    if (er >= 255) return s | 0x7F800000u;
    return s | ((u32)er << 23) | (q & 0x7FFFFFu);
}

static u32 fpu_sqrt_s(u32 a)
{
    if ((a & 0x7FFFFFFFu) == 0u) return a;
    if (a & 0x80000000u) return 0x7FC00000u;
    int e = (int)((a >> 23) & 0xFFu) - 127;
    u64 m = (u64)((a & 0x7FFFFFu) | 0x800000u) << 23;
    if (e & 1) { m <<= 1; e--; }
    int re = (e >> 1) + 127;
    /* Integer bit-by-bit square root for 24-bit mantissa */
    u64 res = 0, bit = 1ULL << 46;
    while (bit > m) bit >>= 2;
    while (bit != 0) {
        if (m >= res + bit) { m -= res + bit; res = (res >> 1) + bit; }
        else                { res >>= 1; }
        bit >>= 2;
    }
    return ((u32)re << 23) | ((u32)res & 0x7FFFFFu);
}

INLINE u32 fpu_get_s(u32 reg)
{
    if (S.cp0[C0_STATUS] & 0x04000000ULL)   /* Status.FR == 1 */
        return (u32)S.fpr[reg];
    return (reg & 1u) ? (u32)(S.fpr[reg & ~1u] >> 32) : (u32)S.fpr[reg & ~1u];
}

INLINE void fpu_set_s(u32 reg, u32 v)
{
    if (S.cp0[C0_STATUS] & 0x04000000ULL) {
        S.fpr[reg] = (S.fpr[reg] & 0xFFFFFFFF00000000ULL) | v;
    } else if (reg & 1u) {
        S.fpr[reg & ~1u] = (S.fpr[reg & ~1u] & 0x00000000FFFFFFFFULL) | ((u64)v << 32);
    } else {
        S.fpr[reg & ~1u] = (S.fpr[reg & ~1u] & 0xFFFFFFFF00000000ULL) | v;
    }
}

INLINE u64 fpu_get_d(u32 reg)
{
    return (S.cp0[C0_STATUS] & 0x04000000ULL) ? S.fpr[reg] : S.fpr[reg & ~1u];
}

INLINE void fpu_set_d(u32 reg, u64 v)
{
    if (S.cp0[C0_STATUS] & 0x04000000ULL) S.fpr[reg] = v;
    else                                  S.fpr[reg & ~1u] = v;
}

static void fpu_exec_cop1(u32 ins, int *branch_to, u32 *btarget, int *nullify)
{
    u32 rs = (ins >> 21) & 31u;
    u32 ft = (ins >> 16) & 31u;
    u32 fs = (ins >> 11) & 31u;
    u32 fd = (ins >>  6) & 31u;
    u32 fn = ins & 63u;

    switch (rs) {
    case 0x00: if (ft) S.gpr[ft] = (u64)(s64)(s32)fpu_get_s(fs); return;       /* MFC1 */
    case 0x01: if (ft) S.gpr[ft] = fpu_get_d(fs); return;                       /* DMFC1 */
    case 0x02: if (ft) S.gpr[ft] = (u64)(s64)(s32)(fs == 31u ? S.fcr31 : 0x00000A00u); return; /* CFC1 */
    case 0x04: fpu_set_s(fs, (u32)S.gpr[ft]); return;                           /* MTC1 */
    case 0x05: fpu_set_d(fs, S.gpr[ft]); return;                                /* DMTC1 */
    case 0x06: if (fs == 31u) S.fcr31 = (u32)S.gpr[ft]; return;                 /* CTC1 */
    case 0x08: {                                                                /* BC1F / BC1T / BC1FL / BC1TL */
        int cc = (S.fcr31 & 0x00800000u) != 0;
        int want = (ft & 1u) != 0;
        int likely = (ft & 2u) != 0;
        if (cc == want) {
            *branch_to = 1;
            *btarget = S.pc + 4u + ((u32)(s32)(s16)ins << 2);
        } else if (likely) {
            *nullify = 1;
        }
        return;
    }
    case 0x10:                                                                  /* fmt = S (16) */
    case 0x11: {                                                                /* fmt = D (17) */
        u32 a = (rs == 0x10u) ? fpu_get_s(fs) : fpu_d_to_s(fpu_get_d(fs));
        u32 b = (rs == 0x10u) ? fpu_get_s(ft) : fpu_d_to_s(fpu_get_d(ft));
        u32 r = 0;
        if (fn >= 0x30u) {                                                      /* C.cond.S / C.cond.D */
            int eq = (a == b) || (((a | b) & 0x7FFFFFFFu) == 0u);
            int lt = 0;
            if (!eq) {
                int sa = (a >> 31) != 0, sb = (b >> 31) != 0;
                lt = (sa != sb) ? sa : (sa ? (a > b) : (a < b));
            }
            int cond = ((fn & 4u) && lt) || ((fn & 2u) && eq);
            if (cond) S.fcr31 |= 0x00800000u;
            else      S.fcr31 &= ~0x00800000u;
            return;
        }
        switch (fn) {
        case 0x00: r = fpu_add_s(a, b); break;                                  /* ADD */
        case 0x01: r = fpu_add_s(a, b ^ 0x80000000u); break;                    /* SUB */
        case 0x02: r = fpu_mul_s(a, b); break;                                  /* MUL */
        case 0x03: r = fpu_div_s(a, b); break;                                  /* DIV */
        case 0x04: r = fpu_sqrt_s(a); break;                                    /* SQRT */
        case 0x05: r = a & 0x7FFFFFFFu; break;                                  /* ABS */
        case 0x06: if (rs == 0x11u) { fpu_set_d(fd, fpu_get_d(fs)); return; } r = a; break; /* MOV */
        case 0x07: if (rs == 0x11u) { fpu_set_d(fd, fpu_get_d(fs) ^ (1ULL << 63)); return; } r = a ^ 0x80000000u; break; /* NEG */
        case 0x08: case 0x09: case 0x0A: case 0x0B:
            fpu_set_d(fd, (u64)(s64)fpu_s_to_i32(a)); return;                   /* ROUND/TRUNC.L */
        case 0x0C: case 0x0D: case 0x0E: case 0x0F:
        case 0x24:
            fpu_set_s(fd, (u32)fpu_s_to_i32(a)); return;                        /* CVT/TRUNC.W */
        case 0x20: fpu_set_s(fd, a); return;                                    /* CVT.S.D */
        case 0x21: fpu_set_d(fd, fpu_s_to_d(a)); return;                        /* CVT.D.S */
        case 0x25: fpu_set_d(fd, (u64)(s64)fpu_s_to_i32(a)); return;            /* CVT.L */
        default: return;
        }
        if (rs == 0x10u) fpu_set_s(fd, r);
        else             fpu_set_d(fd, fpu_s_to_d(r));
        return;
    }
    case 0x14: {                                                                /* fmt = W (20) */
        s32 iv = (s32)fpu_get_s(fs);
        u32 fs32 = fpu_i32_to_s(iv);
        if (fn == 0x20u) fpu_set_s(fd, fs32);                                   /* CVT.S.W */
        else if (fn == 0x21u) fpu_set_d(fd, fpu_s_to_d(fs32));                  /* CVT.D.W */
        return;
    }
    case 0x15: {                                                                /* fmt = L (21) */
        s32 iv = (s32)(s64)fpu_get_d(fs);
        u32 fs32 = fpu_i32_to_s(iv);
        if (fn == 0x20u) fpu_set_s(fd, fs32);                                   /* CVT.S.L */
        else if (fn == 0x21u) fpu_set_d(fd, fpu_s_to_d(fs32));                  /* CVT.D.L */
        return;
    }
    }
}

/* ============================================================================
   93.75 MHz NEC VR4300 (MIPS III) CPU Execution Engine
   ============================================================================ */

#pragma GCC optimize("O2")

static void n64_take_exception(u32 exc_code, u32 pc_cur, int in_bd)
{
    if (!(S.cp0[C0_STATUS] & 0x02ULL)) {                /* Status.EXL == 0 */
        if (in_bd) {
            S.cp0[C0_EPC]   = (u64)(s64)(s32)(pc_cur - 4u);
            S.cp0[C0_CAUSE] |= 0x80000000ULL;           /* Cause.BD */
        } else {
            S.cp0[C0_EPC]   = (u64)(s64)(s32)pc_cur;
            S.cp0[C0_CAUSE] &= ~0x80000000ULL;
        }
        S.cp0[C0_STATUS] |= 0x02ULL;                    /* Set EXL */
    }
    S.cp0[C0_CAUSE] = (S.cp0[C0_CAUSE] & ~0x7CULL) | ((u64)exc_code << 2);
    S.pc      = (S.cp0[C0_STATUS] & 0x00400000ULL) ? 0xBFC00380u : 0x80000180u;
    S.next_pc = S.pc + 4u;
    S.in_delay = 0;
}

static void n64_cpu_run(s32 target_cycles)
{
    while (S.cycles < target_cycles) {
        /* Advance COP0 Count (46.875 MHz = 1 tick per 2 CPU cycles) & check Compare IP7! */
        u32 old_cnt = (u32)S.cp0[C0_COUNT];
        u32 new_cnt = old_cnt + 2u;
        S.cp0[C0_COUNT] = new_cnt;
        u32 cmp = (u32)S.cp0[C0_COMPARE];
        if ((u32)(cmp - old_cnt - 1u) < 2u)
            S.cp0[C0_CAUSE] |= 0x8000ULL;               /* Cause.IP7 */

        /* Check Hardware Interrupts (IE=1, EXL=0, ERL=0) */
        u32 st = (u32)S.cp0[C0_STATUS];
        if ((st & 0x07u) == 0x01u && ((u32)S.cp0[C0_CAUSE] & st & 0xFF00u) != 0u) {
            n64_take_exception(0u, S.pc, S.in_delay);
        }

        u32 cur_pc = S.pc;
        u32 k0_off = cur_pc - 0x80000000u;
        u32 ins    = (k0_off < N64_RDRAM_SIZE) ? be_r32(RDRAM_BUF, k0_off) : n64_r32(cur_pc);

        /* Fast Idle-Loop Skip (`b . ; nop` = 0x1000FFFF, 0x00000000) */
        if (!S.in_delay && (ins == 0x1000FFFFu || ins == (0x08000000u | ((cur_pc >> 2) & 0x03FFFFFFu))) &&
            n64_r32(cur_pc + 4u) == 0x00000000u) {
            s32 rem = target_cycles - S.cycles;
            if (rem > 4) {
                u32 add_cnt = (u32)rem >> 1;
                u32 c0 = (u32)S.cp0[C0_COUNT];
                if ((u32)(cmp - c0 - 1u) < add_cnt)
                    S.cp0[C0_CAUSE] |= 0x8000ULL;
                S.cp0[C0_COUNT] = c0 + add_cnt;
                S.cycles = target_cycles;
                break;
            }
        }

        /* Cycle-Exact Hardware-Poll Fast-Forward (`lw rt, imm(rs) ; andi rt, rt, m ; beq rt, r0, -3 ; nop`) */
        if (!S.in_delay && (ins >> 26) == 0x23u && (target_cycles - S.cycles) >= 8) {
            u32 p_rt = (ins >> 16) & 31u;
            u32 p_rs = (ins >> 21) & 31u;
            u32 i1 = (k0_off + 12u < N64_RDRAM_SIZE) ? be_r32(RDRAM_BUF, k0_off + 4u)  : n64_r32(cur_pc + 4u);
            u32 i2 = (k0_off + 12u < N64_RDRAM_SIZE) ? be_r32(RDRAM_BUF, k0_off + 8u)  : n64_r32(cur_pc + 8u);
            u32 i3 = (k0_off + 12u < N64_RDRAM_SIZE) ? be_r32(RDRAM_BUF, k0_off + 12u) : n64_r32(cur_pc + 12u);
            if (p_rt != 0u && p_rt != p_rs &&
                (i1 & 0xFFFF0000u) == ((0x0Cu << 26) | (p_rt << 21) | (p_rt << 16)) &&
                i2 == ((0x04u << 26) | (p_rt << 21) | 0xFFFDu) &&
                i3 == 0x00000000u) {
                u32 poll_va = (u32)(S.gpr[p_rs] + (u64)(s64)(s16)ins);
                u32 poll_pa = poll_va & 0x1FFFFFFFu;
                if (poll_pa >= 0x04040000u && poll_pa < 0x04900000u && poll_pa != 0x0404001Cu) {
                    u32 val = n64_io_r32(poll_pa & ~3u);
                    if ((val & (i1 & 0xFFFFu)) == 0u) {
                        u32 iters = (u32)(target_cycles - S.cycles) >> 3;
                        u32 add_cnt = iters << 2;
                        S.gpr[p_rt] = 0;
                        if ((u32)(cmp - new_cnt - 1u) < add_cnt)
                            S.cp0[C0_CAUSE] |= 0x8000ULL;
                        S.cp0[C0_COUNT] = new_cnt + add_cnt - 2u;
                        S.cycles += (s32)(iters << 3);
                        continue;
                    }
                }
            }
        }

        u32 seq_pc   = S.next_pc;
        int was_bd   = S.in_delay;
        S.pc         = seq_pc;
        S.next_pc    = seq_pc + 4u;
        S.in_delay   = 0;
        S.cycles    += 2;
        S.gpr[0]     = 0;

        u32 op = ins >> 26;
        u32 rs = (ins >> 21) & 31u;
        u32 rt = (ins >> 16) & 31u;
        u32 rd = (ins >> 11) & 31u;
        u32 sa = (ins >>  6) & 31u;
        u32 fn = ins & 63u;
        u32 uimm = ins & 0xFFFFu;
        s64 simm = (s64)(s16)uimm;

        int do_branch = 0, nullify = 0;
        u32 btarget = 0;

        switch (op) {
        case 0x00:                                      /* SPECIAL */
            switch (fn) {
            case 0x00: if (rd) S.gpr[rd] = (u64)(s64)(s32)((u32)S.gpr[rt] << sa); break;               /* SLL */
            case 0x02: if (rd) S.gpr[rd] = (u64)(s64)(s32)((u32)S.gpr[rt] >> sa); break;               /* SRL */
            case 0x03: if (rd) S.gpr[rd] = (u64)(s64)((s32)S.gpr[rt] >> sa); break;                    /* SRA */
            case 0x04: if (rd) S.gpr[rd] = (u64)(s64)(s32)((u32)S.gpr[rt] << (S.gpr[rs] & 31u)); break;/* SLLV */
            case 0x06: if (rd) S.gpr[rd] = (u64)(s64)(s32)((u32)S.gpr[rt] >> (S.gpr[rs] & 31u)); break;/* SRLV */
            case 0x07: if (rd) S.gpr[rd] = (u64)(s64)((s32)S.gpr[rt] >> (S.gpr[rs] & 31u)); break;     /* SRAV */
            case 0x08: do_branch = 1; btarget = (u32)S.gpr[rs]; break;                                 /* JR */
            case 0x09: btarget = (u32)S.gpr[rs]; if (rd) S.gpr[rd] = (u64)(s64)(s32)(cur_pc + 8u); do_branch = 1; break; /* JALR */
            case 0x0C: n64_take_exception(8u, cur_pc, was_bd); continue;                               /* SYSCALL */
            case 0x0D: n64_take_exception(9u, cur_pc, was_bd); continue;                               /* BREAK */
            case 0x0F: break;                                                                          /* SYNC */
            case 0x10: if (rd) S.gpr[rd] = S.hi; break;                                                /* MFHI */
            case 0x11: S.hi = S.gpr[rs]; break;                                                        /* MTHI */
            case 0x12: if (rd) S.gpr[rd] = S.lo; break;                                                /* MFLO */
            case 0x13: S.lo = S.gpr[rs]; break;                                                        /* MTLO */
            case 0x14: if (rd) S.gpr[rd] = n64_shl64(S.gpr[rt], (u32)S.gpr[rs]); break;                 /* DSLLV */
            case 0x16: if (rd) S.gpr[rd] = n64_shr64(S.gpr[rt], (u32)S.gpr[rs]); break;                 /* DSRLV */
            case 0x17: if (rd) S.gpr[rd] = (u64)n64_sar64((s64)S.gpr[rt], (u32)S.gpr[rs]); break;       /* DSRAV */
            case 0x18: { s64 p = (s64)(s32)S.gpr[rs] * (s64)(s32)S.gpr[rt]; S.lo = (u64)(s64)(s32)p; S.hi = (u64)(s64)(s32)(p >> 32); break; } /* MULT */
            case 0x19: { u64 p = (u64)(u32)S.gpr[rs] * (u64)(u32)S.gpr[rt]; S.lo = (u64)(s64)(s32)p; S.hi = (u64)(s64)(s32)(p >> 32); break; } /* MULTU */
            case 0x1A: { s32 a = (s32)S.gpr[rs], b = (s32)S.gpr[rt]; if (b) { if (a == (s32)0x80000000u && b == -1) { S.lo = (u64)(s64)a; S.hi = 0; } else { S.lo = (u64)(s64)(a / b); S.hi = (u64)(s64)(a % b); } } break; } /* DIV */
            case 0x1B: { u32 a = (u32)S.gpr[rs], b = (u32)S.gpr[rt]; if (b) { S.lo = (u64)(s64)(s32)(a / b); S.hi = (u64)(s64)(s32)(a % b); } break; } /* DIVU */
            case 0x1C: { int neg = ((s64)S.gpr[rs] < 0) ^ ((s64)S.gpr[rt] < 0); u64 ua = (s64)S.gpr[rs] < 0 ? (0ULL - S.gpr[rs]) : S.gpr[rs]; u64 ub = (s64)S.gpr[rt] < 0 ? (0ULL - S.gpr[rt]) : S.gpr[rt]; n64_dmultu(ua, ub, &S.hi, &S.lo); if (neg) { S.lo = ~S.lo + 1ULL; S.hi = ~S.hi + (S.lo == 0ULL ? 1ULL : 0ULL); } break; } /* DMULT */
            case 0x1D: n64_dmultu(S.gpr[rs], S.gpr[rt], &S.hi, &S.lo); break;                          /* DMULTU */
            case 0x1E: n64_divs64((s64)S.gpr[rs], (s64)S.gpr[rt], &S.lo, &S.hi); break;                /* DDIV */
            case 0x1F: n64_divu64(S.gpr[rs], S.gpr[rt], &S.lo, &S.hi); break;                          /* DDIVU */
            case 0x20: case 0x21: if (rd) S.gpr[rd] = (u64)(s64)(s32)((u32)S.gpr[rs] + (u32)S.gpr[rt]); break; /* ADD / ADDU */
            case 0x22: case 0x23: if (rd) S.gpr[rd] = (u64)(s64)(s32)((u32)S.gpr[rs] - (u32)S.gpr[rt]); break; /* SUB / SUBU */
            case 0x24: if (rd) S.gpr[rd] = S.gpr[rs] & S.gpr[rt]; break;                               /* AND */
            case 0x25: if (rd) S.gpr[rd] = S.gpr[rs] | S.gpr[rt]; break;                               /* OR */
            case 0x26: if (rd) S.gpr[rd] = S.gpr[rs] ^ S.gpr[rt]; break;                               /* XOR */
            case 0x27: if (rd) S.gpr[rd] = ~(S.gpr[rs] | S.gpr[rt]); break;                            /* NOR */
            case 0x2A: if (rd) S.gpr[rd] = ((s64)S.gpr[rs] < (s64)S.gpr[rt]) ? 1ULL : 0ULL; break;     /* SLT */
            case 0x2B: if (rd) S.gpr[rd] = (S.gpr[rs] < S.gpr[rt]) ? 1ULL : 0ULL; break;               /* SLTU */
            case 0x2C: case 0x2D: if (rd) S.gpr[rd] = S.gpr[rs] + S.gpr[rt]; break;                    /* DADD / DADDU */
            case 0x2E: case 0x2F: if (rd) S.gpr[rd] = S.gpr[rs] - S.gpr[rt]; break;                    /* DSUB / DSUBU */
            case 0x38: if (rd) S.gpr[rd] = n64_shl64(S.gpr[rt], sa); break;                             /* DSLL */
            case 0x3A: if (rd) S.gpr[rd] = n64_shr64(S.gpr[rt], sa); break;                             /* DSRL */
            case 0x3B: if (rd) S.gpr[rd] = (u64)n64_sar64((s64)S.gpr[rt], sa); break;                   /* DSRA */
            case 0x3C: if (rd) S.gpr[rd] = n64_shl64(S.gpr[rt], sa + 32u); break;                       /* DSLL32 */
            case 0x3E: if (rd) S.gpr[rd] = n64_shr64(S.gpr[rt], sa + 32u); break;                       /* DSRL32 */
            case 0x3F: if (rd) S.gpr[rd] = (u64)n64_sar64((s64)S.gpr[rt], sa + 32u); break;             /* DSRA32 */
            }
            break;

        case 0x01: {                                    /* REGIMM */
            int ge = (rt & 1u) != 0;
            int likely = (rt & 2u) != 0;
            int link = (rt & 0x10u) != 0;
            int take = ge ? ((s64)S.gpr[rs] >= 0) : ((s64)S.gpr[rs] < 0);
            if (link) S.gpr[31] = (u64)(s64)(s32)(cur_pc + 8u);
            if (take) { do_branch = 1; btarget = cur_pc + 4u + ((u32)(s32)(s16)uimm << 2); }
            else if (likely) nullify = 1;
            break;
        }

        case 0x02: do_branch = 1; btarget = ((cur_pc + 4u) & 0xF0000000u) | ((ins & 0x03FFFFFFu) << 2); break; /* J */
        case 0x03: S.gpr[31] = (u64)(s64)(s32)(cur_pc + 8u); do_branch = 1; btarget = ((cur_pc + 4u) & 0xF0000000u) | ((ins & 0x03FFFFFFu) << 2); break; /* JAL */
        case 0x04: if (S.gpr[rs] == S.gpr[rt]) { do_branch = 1; btarget = cur_pc + 4u + ((u32)(s32)(s16)uimm << 2); } break; /* BEQ */
        case 0x05: if (S.gpr[rs] != S.gpr[rt]) { do_branch = 1; btarget = cur_pc + 4u + ((u32)(s32)(s16)uimm << 2); } break; /* BNE */
        case 0x06: if ((s64)S.gpr[rs] <= 0)    { do_branch = 1; btarget = cur_pc + 4u + ((u32)(s32)(s16)uimm << 2); } break; /* BLEZ */
        case 0x07: if ((s64)S.gpr[rs] >  0)    { do_branch = 1; btarget = cur_pc + 4u + ((u32)(s32)(s16)uimm << 2); } break; /* BGTZ */

        case 0x08: case 0x09: if (rt) S.gpr[rt] = (u64)(s64)(s32)((u32)S.gpr[rs] + (u32)simm); break;  /* ADDI / ADDIU */
        case 0x0A: if (rt) S.gpr[rt] = ((s64)S.gpr[rs] < simm) ? 1ULL : 0ULL; break;                   /* SLTI */
        case 0x0B: if (rt) S.gpr[rt] = (S.gpr[rs] < (u64)simm) ? 1ULL : 0ULL; break;                   /* SLTIU */
        case 0x0C: if (rt) S.gpr[rt] = S.gpr[rs] & uimm; break;                                        /* ANDI */
        case 0x0D: if (rt) S.gpr[rt] = S.gpr[rs] | uimm; break;                                        /* ORI */
        case 0x0E: if (rt) S.gpr[rt] = S.gpr[rs] ^ uimm; break;                                        /* XORI */
        case 0x0F: if (rt) S.gpr[rt] = (u64)(s64)(s32)(uimm << 16); break;                             /* LUI */

        case 0x10:                                      /* COP0 */
            switch (rs) {
            case 0x00: if (rt) S.gpr[rt] = (u64)(s64)(s32)S.cp0[rd]; break;                            /* MFC0 */
            case 0x01: if (rt) S.gpr[rt] = S.cp0[rd]; break;                                           /* DMFC0 */
            case 0x04:
            case 0x05: {                                                                               /* MTC0 / DMTC0 */
                u64 v = (rs == 0x04u) ? (u64)(u32)S.gpr[rt] : S.gpr[rt];
                if (rd == C0_COMPARE) {
                    S.cp0[C0_COMPARE] = (u32)v;
                    S.cp0[C0_CAUSE] &= ~0x8000ULL;      /* Clear IP7! */
                } else if (rd == C0_CAUSE) {
                    S.cp0[C0_CAUSE] = (S.cp0[C0_CAUSE] & ~0x0300ULL) | (v & 0x0300ULL);
                } else if (rd != C0_RANDOM && rd != C0_PRID) {
                    S.cp0[rd] = v;
                }
                break;
            }
            case 0x10:                                  /* TLB / ERET */
                if (fn == 0x18u) {                      /* ERET */
                    if (S.cp0[C0_STATUS] & 0x04ULL) {
                        S.pc = (u32)S.cp0[C0_ERROREPC];
                        S.cp0[C0_STATUS] &= ~0x04ULL;
                    } else {
                        S.pc = (u32)S.cp0[C0_EPC];
                        S.cp0[C0_STATUS] &= ~0x02ULL;
                    }
                    S.next_pc = S.pc + 4u;
                    S.ll_bit = 0;
                    continue;
                } else if (fn == 0x02u || fn == 0x06u) { /* TLBWI / TLBWR */
                    u32 idx = (fn == 0x02u) ? ((u32)S.cp0[C0_INDEX] & 31u) : (((u32)S.cp0[C0_COUNT] >> 2) & 31u);
                    struct n64_tlb *t = &M->tlb[idx];
                    t->page_mask = (u32)S.cp0[C0_PAGEMASK];
                    t->entry_hi  = (u32)S.cp0[C0_ENTRYHI];
                    t->entry_lo0 = (u32)S.cp0[C0_ENTRYLO0];
                    t->entry_lo1 = (u32)S.cp0[C0_ENTRYLO1];
                    t->valid0    = (u8)((t->entry_lo0 >> 1) & 1u);
                    t->valid1    = (u8)((t->entry_lo1 >> 1) & 1u);
                } else if (fn == 0x01u) {               /* TLBR */
                    const struct n64_tlb *t = &M->tlb[(u32)S.cp0[C0_INDEX] & 31u];
                    S.cp0[C0_PAGEMASK] = t->page_mask;
                    S.cp0[C0_ENTRYHI]  = t->entry_hi;
                    S.cp0[C0_ENTRYLO0] = t->entry_lo0;
                    S.cp0[C0_ENTRYLO1] = t->entry_lo1;
                } else if (fn == 0x08u) {               /* TLBP */
                    S.cp0[C0_INDEX] = 0x80000000ULL;
                    u32 hi = (u32)S.cp0[C0_ENTRYHI];
                    for (u32 i = 0; i < 32u; i++) {
                        u32 mask = M->tlb[i].page_mask | 0x1FFFu;
                        if (((hi ^ M->tlb[i].entry_hi) & ~mask) == 0u) {
                            S.cp0[C0_INDEX] = i;
                            break;
                        }
                    }
                }
                break;
            }
            break;

        case 0x11:                                      /* COP1 FPU */
            fpu_exec_cop1(ins, &do_branch, &btarget, &nullify);
            break;

        case 0x14: if (S.gpr[rs] == S.gpr[rt]) { do_branch = 1; btarget = cur_pc + 4u + ((u32)(s32)(s16)uimm << 2); } else nullify = 1; break; /* BEQL */
        case 0x15: if (S.gpr[rs] != S.gpr[rt]) { do_branch = 1; btarget = cur_pc + 4u + ((u32)(s32)(s16)uimm << 2); } else nullify = 1; break; /* BNEL */
        case 0x16: if ((s64)S.gpr[rs] <= 0)    { do_branch = 1; btarget = cur_pc + 4u + ((u32)(s32)(s16)uimm << 2); } else nullify = 1; break; /* BLEZL */
        case 0x17: if ((s64)S.gpr[rs] >  0)    { do_branch = 1; btarget = cur_pc + 4u + ((u32)(s32)(s16)uimm << 2); } else nullify = 1; break; /* BGTZL */

        case 0x18: case 0x19: if (rt) S.gpr[rt] = S.gpr[rs] + (u64)simm; break;                        /* DADDI / DADDIU */

        case 0x1A: {                                    /* LDL */
            u32 a = (u32)(S.gpr[rs] + (u64)simm);
            int sh = (int)(a & 7u) * 8;
            u64 dw = n64_r64(a & ~7u);
            u64 msk = (sh == 0) ? 0ULL : ((1ULL << sh) - 1ULL);
            if (rt) S.gpr[rt] = (S.gpr[rt] & msk) | (dw << sh);
            break;
        }
        case 0x1B: {                                    /* LDR */
            u32 a = (u32)(S.gpr[rs] + (u64)simm);
            int sh = (7 - (int)(a & 7u)) * 8;
            u64 dw = n64_r64(a & ~7u);
            u64 msk = (sh == 0) ? ~0ULL : ((1ULL << (64 - sh)) - 1ULL);
            if (rt) S.gpr[rt] = (S.gpr[rt] & ~msk) | (dw >> sh);
            break;
        }

        case 0x20: if (rt) S.gpr[rt] = (u64)(s64)(s8)n64_r8((u32)(S.gpr[rs] + (u64)simm)); break;      /* LB */
        case 0x21: if (rt) S.gpr[rt] = (u64)(s64)(s16)n64_r16((u32)(S.gpr[rs] + (u64)simm)); break;    /* LH */
        case 0x22: {                                    /* LWL */
            u32 a = (u32)(S.gpr[rs] + (u64)simm);
            int sh = (int)(a & 3u) * 8;
            u32 w = n64_r32(a & ~3u);
            u32 msk = (sh == 0) ? 0u : ((1u << sh) - 1u);
            if (rt) S.gpr[rt] = (u64)(s64)(s32)(((u32)S.gpr[rt] & msk) | (w << sh));
            break;
        }
        case 0x23: if (rt) S.gpr[rt] = (u64)(s64)(s32)n64_r32((u32)(S.gpr[rs] + (u64)simm)); break;    /* LW */
        case 0x24: if (rt) S.gpr[rt] = n64_r8((u32)(S.gpr[rs] + (u64)simm)); break;                    /* LBU */
        case 0x25: if (rt) S.gpr[rt] = n64_r16((u32)(S.gpr[rs] + (u64)simm)); break;                   /* LHU */
        case 0x26: {                                    /* LWR */
            u32 a = (u32)(S.gpr[rs] + (u64)simm);
            int sh = (3 - (int)(a & 3u)) * 8;
            u32 w = n64_r32(a & ~3u);
            u32 msk = (sh == 0) ? ~0u : ((1u << (32 - sh)) - 1u);
            if (rt) S.gpr[rt] = (u64)(s64)(s32)(((u32)S.gpr[rt] & ~msk) | (w >> sh));
            break;
        }
        case 0x27: if (rt) S.gpr[rt] = n64_r32((u32)(S.gpr[rs] + (u64)simm)); break;                   /* LWU */

        case 0x28: n64_w8((u32)(S.gpr[rs] + (u64)simm), (u8)S.gpr[rt]); break;                         /* SB */
        case 0x29: n64_w16((u32)(S.gpr[rs] + (u64)simm), (u16)S.gpr[rt]); break;                       /* SH */
        case 0x2A: {                                    /* SWL */
            u32 a = (u32)(S.gpr[rs] + (u64)simm);
            int sh = (int)(a & 3u) * 8;
            u32 old = n64_r32(a & ~3u);
            u32 msk = (sh == 0) ? ~0u : ((1u << (32 - sh)) - 1u);
            n64_w32(a & ~3u, (old & ~msk) | ((u32)S.gpr[rt] >> sh));
            break;
        }
        case 0x2B: n64_w32((u32)(S.gpr[rs] + (u64)simm), (u32)S.gpr[rt]); break;                       /* SW */
        case 0x2C: {                                    /* SDL */
            u32 a = (u32)(S.gpr[rs] + (u64)simm);
            int sh = (int)(a & 7u) * 8;
            u64 old = n64_r64(a & ~7u);
            u64 msk = (sh == 0) ? ~0ULL : ((1ULL << (64 - sh)) - 1ULL);
            n64_w64(a & ~7u, (old & ~msk) | (S.gpr[rt] >> sh));
            break;
        }
        case 0x2D: {                                    /* SDR */
            u32 a = (u32)(S.gpr[rs] + (u64)simm);
            int sh = (7 - (int)(a & 7u)) * 8;
            u64 old = n64_r64(a & ~7u);
            u64 msk = (sh == 0) ? 0ULL : ((1ULL << sh) - 1ULL);
            n64_w64(a & ~7u, (old & msk) | (S.gpr[rt] << sh));
            break;
        }
        case 0x2E: {                                    /* SWR */
            u32 a = (u32)(S.gpr[rs] + (u64)simm);
            int sh = (3 - (int)(a & 3u)) * 8;
            u32 old = n64_r32(a & ~3u);
            u32 msk = (sh == 0) ? 0u : ((1u << sh) - 1u);
            n64_w32(a & ~3u, (old & msk) | ((u32)S.gpr[rt] << sh));
            break;
        }
        case 0x2F: break;                               /* CACHE */
        case 0x30: S.ll_bit = 1u; if (rt) S.gpr[rt] = (u64)(s64)(s32)n64_r32((u32)(S.gpr[rs] + (u64)simm)); break; /* LL */
        case 0x31: fpu_set_s(rt, n64_r32((u32)(S.gpr[rs] + (u64)simm))); break;                        /* LWC1 */
        case 0x35: fpu_set_d(rt, n64_r64((u32)(S.gpr[rs] + (u64)simm))); break;                        /* LDC1 */
        case 0x37: if (rt) S.gpr[rt] = n64_r64((u32)(S.gpr[rs] + (u64)simm)); break;                   /* LD */
        case 0x38: if (S.ll_bit) n64_w32((u32)(S.gpr[rs] + (u64)simm), (u32)S.gpr[rt]); if (rt) S.gpr[rt] = S.ll_bit; S.ll_bit = 0; break; /* SC */
        case 0x39: n64_w32((u32)(S.gpr[rs] + (u64)simm), fpu_get_s(rt)); break;                        /* SWC1 */
        case 0x3D: n64_w64((u32)(S.gpr[rs] + (u64)simm), fpu_get_d(rt)); break;                        /* SDC1 */
        case 0x3F: n64_w64((u32)(S.gpr[rs] + (u64)simm), S.gpr[rt]); break;                            /* SD */
        }

        if (do_branch) {
            S.next_pc  = btarget;
            S.in_delay = 1u;
        } else if (nullify) {
            S.pc       = seq_pc + 4u;
            S.next_pc  = seq_pc + 8u;
            S.in_delay = 0;
        }
    }
}

#pragma GCC reset_options

/* ============================================================================
   Built-in Playable 64-Bit 3D N64 Game (""): "STAR WING 64"
   Executes native R4300i MIPS III + COP1 FPU + PIF Joybus + F3DEX + Z-Buffered RDP!
   ============================================================================ */

static void mips_emit(u8 *b, u32 *p, u32 ins) { be_w32(b, *p, ins); *p += 4u; }
static void mips_li(u8 *b, u32 *p, u32 rt, u32 v)
{
    mips_emit(b, p, (0x0Fu << 26) | (rt << 16) | (v >> 16));
    if (v & 0xFFFFu)
        mips_emit(b, p, (0x0Du << 26) | (rt << 21) | (rt << 16) | (v & 0xFFFFu));
}

static void put_vtx(u8 *b, u32 off, s16 x, s16 y, s16 z, s16 s, s16 t, u8 r, u8 g, u8 bl, u8 a)
{
    be_w16(b, off + 0u, (u16)x);
    be_w16(b, off + 2u, (u16)y);
    be_w16(b, off + 4u, (u16)z);
    be_w16(b, off + 6u, 0);
    be_w16(b, off + 8u, (u16)s);
    be_w16(b, off + 10u,(u16)t);
    be_w8(b,  off + 12u, r);
    be_w8(b,  off + 13u, g);
    be_w8(b,  off + 14u, bl);
    be_w8(b,  off + 15u, a);
}

static void put_mtx_ident(u8 *b, u32 off)
{
    for (u32 i = 0; i < 64u; i += 4u) be_w32(b, off + i, 0);
    be_w16(b, off +  0u, 1);
    be_w16(b, off + 10u, 1);
    be_w16(b, off + 20u, 1);
    be_w16(b, off + 30u, 1);
}

static void build_builtin_n64_rom(void)
{
    n64_zero(ROM_BUF, 0x40000u);
    be_w32(ROM_BUF, 0x00u, 0x80371240u);
    be_w32(ROM_BUF, 0x08u, 0x80001000u);
    static const char title[] = "STAR WING 64        ";
    for (int i = 0; i < 20; i++) be_w8(ROM_BUF, 0x20u + (u32)i, (u8)title[i]);
    be_w8(ROM_BUF, 0x3Eu, 'E');

    /* ROM offset $01000 -> loaded at RDRAM $00001000 (`0x80001000`):
         $001000..$001FFF : Native R4300i 64-bit game loop!
         $002000..$00203F : F3DEX signature string ("F3DEX 1.23")
         $002100..$00210F : Viewport Vp (320x240)
         $002200..$00223F : Perspective Projection Mtx
         $002240..$00227F : Arwing ModelView Mtx (updated every frame by R4300i!)
         $002280..$0022BF : Ground/Ring ModelView Mtx (scrolling every frame!)
         $002400..$0025FF : 3D Vertex Bank (Arwing Starfighter + 3D Ground Grid + Gold Ring)
         $002800..$003FFF : 16x16 RGBA16 Ground Checker Texture + 128x12 HUD Texture
         $004000..$004FFF : Master F3DEX Display List
         $005000..$005FFF : 800-frame Stereo 16-bit 48 kHz AI DMA Synth Buffer! */
    u32 R = 0x0000u;                                /* Offset inside 0x1000 payload -> RDRAM $001000 + off */
    #define B(a) (0x1000u + ((a) - 0x1000u))

    static const char sig[] = "RSP Gfx ucode F3DEX 1.23";
    for (u32 i = 0; i < sizeof(sig); i++) be_w8(ROM_BUF, B(0x2000u) + i, (u8)sig[i]);

    /* Viewport (320x240 -> vscale=(640,480,511,0), vtrans=(640,480,511,0)) */
    be_w16(ROM_BUF, B(0x2100u), 640); be_w16(ROM_BUF, B(0x2102u), 480);
    be_w16(ROM_BUF, B(0x2104u), 511); be_w16(ROM_BUF, B(0x2106u), 0);
    be_w16(ROM_BUF, B(0x2108u), 640); be_w16(ROM_BUF, B(0x210Au), 480);
    be_w16(ROM_BUF, B(0x210Cu), 511); be_w16(ROM_BUF, B(0x210Eu), 0);

    /* Perspective Projection Matrix (FOV ~60 deg: m00=1.25, m11=1.66, m22=-1, m23=-1, m32=-40) */
    put_mtx_ident(ROM_BUF, B(0x2200u));
    be_w16(ROM_BUF, B(0x2200u) +  0u, 1);     be_w16(ROM_BUF, B(0x2200u) + 32u +  0u, 0x4000u); /* 1.25 */
    be_w16(ROM_BUF, B(0x2200u) + 10u, 1);     be_w16(ROM_BUF, B(0x2200u) + 32u + 10u, 0xAA00u); /* 1.66 */
    be_w16(ROM_BUF, B(0x2200u) + 20u, (u16)-1);
    be_w16(ROM_BUF, B(0x2200u) + 22u, (u16)-1);                                                 /* w = -z */
    be_w16(ROM_BUF, B(0x2200u) + 28u, (u16)-32);
    be_w16(ROM_BUF, B(0x2200u) + 30u, 0);

    /* Default Arwing & Ground ModelView Matrices (z = -180 in front of camera!) */
    put_mtx_ident(ROM_BUF, B(0x2240u));
    be_w16(ROM_BUF, B(0x2240u) + 28u, (u16)-180);
    put_mtx_ident(ROM_BUF, B(0x2280u));
    be_w16(ROM_BUF, B(0x2280u) + 26u, (u16)-48);
    be_w16(ROM_BUF, B(0x2280u) + 28u, (u16)-220);

    /* 256-entry Signed Sine Table (S8.8) at $002300..$0024FF -> move vertices to $002600! */
    static const s16 qsin[65] = {
          0,   6,  13,  19,  25,  31,  38,  44,  50,  56,  62,  68,  74,  80,  86,  92,
         98, 104, 109, 115, 121, 126, 132, 137, 142, 147, 152, 157, 162, 167, 172, 177,
        181, 185, 190, 194, 198, 202, 206, 209, 213, 216, 220, 223, 226, 229, 231, 234,
        237, 239, 241, 243, 245, 247, 248, 250, 251, 252, 253, 254, 255, 255, 256, 256, 256
    };
    for (int i = 0; i < 256; i++) {
        int q = (i >> 6) & 3, idx = i & 63;
        s16 v = (q == 0) ? qsin[idx] : (q == 1) ? qsin[64 - idx] : (q == 2) ? -qsin[idx] : -qsin[64 - idx];
        be_w16(ROM_BUF, B(0x2300u) + (u32)i * 2u, (u16)v);
    }

    /* 3D Arwing Starfighter Vertices at $002600 (12 vertices):
         v0: Nose cone (0, 2, -52) bright white-silver
         v1: Top dorsal ridge (0, 16, 20) royal cobalt blue
         v2: Belly keel (0, -10, 20) slate silver
         v3: Left wingtip (-68, -6, 28) cobalt-white
         v4: Right wingtip (+68, -6, 28) cobalt-white
         v5: Left G-Diffuser fin (-28, 18, 26) electric blue
         v6: Right G-Diffuser fin (+28, 18, 26) electric blue
         v7..v9: Blazing orange-gold plasma engine core at rear z=+22! */
    u32 vb = B(0x2600u);
    put_vtx(ROM_BUF, vb +  0*16u,   0,   2, -56, 0, 0, 250, 252, 255, 255);
    put_vtx(ROM_BUF, vb +  1*16u,   0,  16,  22, 0, 0,  60, 140, 255, 255);
    put_vtx(ROM_BUF, vb +  2*16u,   0, -10,  22, 0, 0, 160, 180, 210, 255);
    put_vtx(ROM_BUF, vb +  3*16u, -70,  -6,  30, 0, 0, 220, 235, 255, 255);
    put_vtx(ROM_BUF, vb +  4*16u,  70,  -6,  30, 0, 0, 220, 235, 255, 255);
    put_vtx(ROM_BUF, vb +  5*16u, -28,  20,  26, 0, 0,  30,  90, 245, 255);
    put_vtx(ROM_BUF, vb +  6*16u,  28,  20,  26, 0, 0,  30,  90, 245, 255);
    put_vtx(ROM_BUF, vb +  7*16u,   0,   9,  23, 0, 0, 255, 245,  90, 255);
    put_vtx(ROM_BUF, vb +  8*16u, -11,  -6,  23, 0, 0, 255,  70,  30, 255);
    put_vtx(ROM_BUF, vb +  9*16u,  11,  -6,  23, 0, 0, 255,  70,  30, 255);

    /* 3D Perspective Textured Ground Plane ($002600 + 12*16) + Floating Gold Gate ($002600 + 16*16) */
    put_vtx(ROM_BUF, vb + 12*16u, -220, -18, -190,    0,    0,  90, 220, 140, 255);
    put_vtx(ROM_BUF, vb + 13*16u,  220, -18, -190, 2048,    0,  90, 220, 140, 255);
    put_vtx(ROM_BUF, vb + 14*16u,  220, -18,  140, 2048, 2048, 170, 255, 190, 255);
    put_vtx(ROM_BUF, vb + 15*16u, -220, -18,  140,    0, 2048, 170, 255, 190, 255);

    put_vtx(ROM_BUF, vb + 16*16u, -50,  58, -80, 0, 0, 255, 220,  50, 255);
    put_vtx(ROM_BUF, vb + 17*16u,  50,  58, -80, 0, 0, 255, 220,  50, 255);
    put_vtx(ROM_BUF, vb + 18*16u,  38,  48, -80, 0, 0, 255, 140,  20, 255);
    put_vtx(ROM_BUF, vb + 19*16u, -38,  48, -80, 0, 0, 255, 140,  20, 255);

    /* 16x16 RGBA16 Corneria Meadow Checker Texture at $002800 (512 bytes) */
    for (int y = 0; y < 16; y++) {
        for (int x = 0; x < 16; x++) {
            int chk = ((x >> 2) ^ (y >> 2)) & 1;
            u16 c = chk ? n64_rgba32_to_5551(40, 195, 95, 1) : n64_rgba32_to_5551(24, 125, 68, 1);
            if (x == 0 || y == 0) c = n64_rgba32_to_5551(80, 240, 170, 1);
            be_w16(ROM_BUF, B(0x2800u) + (u32)(y * 16 + x) * 2u, c);
        }
    }

    /* 160x12 RGBA16 HUD Banner ("STAR WING 64  R4300I+RDP") at $002C00 (3840 bytes) */
    static const char hud[] = "STAR WING 64  R4300I+RDP";
    for (int i = 0; hud[i]; i++) {
        const u8 *g = font5x7[hud[i] - 32];
        for (int gy = 0; gy < 7; gy++) {
            for (int gx = 0; gx < 5; gx++) {
                if ((g[gy] >> (4 - gx)) & 1u) {
                    u16 col = (gy < 3) ? n64_rgba32_to_5551(255, 245, 90, 1) : n64_rgba32_to_5551(90, 210, 255, 1);
                    be_w16(ROM_BUF, B(0x2C00u) + (u32)((2 + gy) * 160 + (4 + i * 6 + gx)) * 2u, col);
                }
            }
        }
    }

    /* Master F3DEX Display List at $004000!
       Color FB = $00100000 (320x240 RGBA16), Z-Buffer = $00140000 (320x240 Z16)! */
    u32 dl = B(0x4000u);
    #define DL(hi, lo) do { be_w32(ROM_BUF, dl, (hi)); be_w32(ROM_BUF, dl + 4u, (lo)); dl += 8u; } while (0)
    DL(0xED000000u, (320u << 14) | (240u << 2));                /* G_SETSCISSOR 0,0..320,240 */
    DL(0xFE000000u, 0x00140000u);                               /* G_SETZIMG $00140000 */
    /* 1. Clear Z-buffer via G_SETCIMG $00140000 + FILL mode + G_FILLRECT 0xFFFCFFFC! */
    DL(0xFF100000u | 319u, 0x00140000u);
    DL(0xEF300000u, 0x00000000u);                               /* G_SETOTHERMODE FILL */
    DL(0xF7000000u, 0xFFFCFFFCu);
    DL(0xF6000000u | (319u << 14) | (239u << 2), 0u);
    /* 2. Clear Color sky gradient (top horizon indigo -> cobalt horizon) into $00100000! */
    DL(0xFF100000u | 319u, 0x00100000u);
    for (u32 band = 0; band < 6u; band++) {
        u16 sky = n64_rgba32_to_5551((u8)(12 + band * 12), (u8)(22 + band * 22), (u8)(75 + band * 28), 1);
        DL(0xF7000000u, ((u32)sky << 16) | sky);
        u32 y0 = band * 24u, y1 = y0 + 23u;
        DL(0xF6000000u | (319u << 14) | (y1 << 2), y0 << 2);
    }
    u16 ground_hz = n64_rgba32_to_5551(16, 65, 52, 1);
    DL(0xF7000000u, ((u32)ground_hz << 16) | ground_hz);
    DL(0xF6000000u | (319u << 14) | (239u << 2), 144u << 2);

    /* 3. Enable Z-buffer 1-cycle rendering, load Viewport ($002100) & Projection Mtx ($002200) */
    DL(0xEF000000u, 0x00000030u);                               /* Z_CMP | Z_UPD */
    DL(0xB7000000u, 0x00000001u);                               /* G_ZBUFFER */
    DL(0x03800010u, 0x00002100u);                               /* G_MOVEMEM Vp */
    DL(0x01030040u, 0x00002200u);                               /* G_MTX Projection LOAD */

    /* 4. Load 16x16 RGBA16 Meadow Checker into TMEM & draw 3D Textured Ground + Gold Gate ($002280)! */
    DL(0x01020040u, 0x00002280u);                               /* G_MTX Ground MV LOAD */
    DL(0xFD10000Fu, 0x00002800u);                               /* G_SETTIMG RGBA16 w=16 $002800 */
    DL(0xF5100000u, 0x07000000u);                               /* G_SETTILE tile 7 */
    DL(0xF3000000u, (7u << 24) | (255u << 12));                 /* G_LOADBLOCK 256 texels */
    DL(0xF5100400u, (0u << 24) | (4u << 14) | (4u << 4));       /* G_SETTILE tile 0 mask=4 (16x16 wrap!) */
    DL(0xF2000000u, (15u << 14) | (15u << 2));
    DL(0xBB000001u, 0xFFFFFFFFu);                               /* G_TEXTURE ON */
    DL(0x04000000u | (0u << 17) | (8u << 10), 0x00002600u + 12*16u); /* G_VTX v12..v19 -> slot 0..7 */
    DL(0xB1000000u | (0u << 17) | (1u << 9) | (2u << 1), (0u << 17) | (2u << 9) | (3u << 1)); /* Ground 2 tris */
    DL(0xBB000000u, 0u);                                        /* G_TEXTURE OFF */
    DL(0xB1000000u | (4u << 17) | (5u << 9) | (6u << 1), (4u << 17) | (6u << 9) | (7u << 1)); /* Gold Gate! */

    /* 5. Load Arwing Dynamic ModelView ($002240) & draw 3D Z-Buffered Arwing Starfighter! */
    DL(0x01020040u, 0x00002240u);
    DL(0x04000000u | (0u << 17) | (10u << 10), 0x00002600u);    /* G_VTX v0..v9 */
    DL(0xB1000000u | (0u << 17) | (1u << 9) | (3u << 1), (0u << 17) | (4u << 9) | (1u << 1)); /* Left/Right top wings */
    DL(0xB1000000u | (0u << 17) | (3u << 9) | (2u << 1), (0u << 17) | (2u << 9) | (4u << 1)); /* Belly wings */
    DL(0xB1000000u | (0u << 17) | (5u << 9) | (3u << 1), (0u << 17) | (4u << 9) | (6u << 1)); /* G-Diffuser fins */
    DL(0xBF000000u, (7u << 17) | (8u << 9) | (9u << 1));        /* Glowing rear plasma core! */

    /* 6. Draw 160x12 RGBA16 HUD Banner at (80, 6) via TMEM LoadTile + G_TEXRECT! */
    DL(0xFD100000u | 159u, 0x00002C00u);
    DL(0xF5100000u | (40u << 9), 0u);                           /* line = 40 (320 bytes = 160 RGBA16 px) */
    DL(0xF4000000u, (159u << 14) | (11u << 2));                 /* G_LOADTILE 160x12 */
    DL(0xE4000000u | (240u << 14) | (18u << 2), (80u << 14) | (6u << 2));
    DL(0x00000000u, (1024u << 16) | 1024u);
    DL(0xE9000000u, 0u);                                        /* G_RDPFULLSYNC */
    DL(0xB8000000u, 0u);                                        /* G_ENDDL */
    #undef DL

    /* Pre-synthesize 800 stereo frames (3200 bytes) of heroic Star Wing chord at $005000! */
    for (u32 s = 0; s < 800u; s++) {
        s32 v1 = ((s * 6u) & 255u) < 128u ? 3600 : -3600;
        s32 v2 = ((s * 9u) & 255u) < 128u ? 2800 : -2800;
        s32 v3 = (s32)(((s * 12u) & 255u) * 24u) - 3072;
        s16 l = (s16)(v1 + v3), r = (s16)(v2 + v3);
        be_w32(ROM_BUF, B(0x5000u) + s * 4u, ((u32)(u16)l << 16) | (u16)r);
    }

    /* ---- Emit Native 64-Bit R4300i Game Loop at $001000 (`0x80001000`)! ---- */
    R = B(0x1000u);
    /* Configure VI ($A4400000): RGBA16 (0x0002), origin=$00100000, width=320, v_intr=2 */
    mips_li(ROM_BUF, &R, 8, 0xA4400000u);
    mips_li(ROM_BUF, &R, 9, 0x00003202u); mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x00u);
    mips_li(ROM_BUF, &R, 9, 0x00100000u); mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x04u);
    mips_li(ROM_BUF, &R, 9, 320u);        mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x08u);
    mips_li(ROM_BUF, &R, 9, 2u);          mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x0Cu);

    /* Configure AI ($A4500000): dacrate = 1013 (~48 kHz), control = 1 */
    mips_li(ROM_BUF, &R, 8, 0xA4500000u);
    mips_li(ROM_BUF, &R, 9, 1013u); mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x10u);
    mips_li(ROM_BUF, &R, 9, 1u);    mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x08u);

    /* Prepare Joybus Read Command Block at RDRAM $001F00 (tx=1, rx=4, cmd=0x01, end=0xFE, pif[63]=1) */
    mips_li(ROM_BUF, &R, 8, 0x80001F00u);
    mips_li(ROM_BUF, &R, 9, 0x01040100u); mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x00u);
    mips_li(ROM_BUF, &R, 9, 0xFE000000u); mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x08u);
    mips_li(ROM_BUF, &R, 9, 0x00000001u); mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x3Cu);

    /* s0 ($16) = frame (0), s1 ($17) = ship_x (0), s2 ($18) = ship_y (0) */
    mips_emit(ROM_BUF, &R, 0x00008021u);                        /* daddu/addu s0, zero, zero */
    mips_emit(ROM_BUF, &R, 0x00008821u);                        /* s1 = 0 */
    mips_emit(ROM_BUF, &R, 0x00009021u);                        /* s2 = 0 */

    /* ---- Main Frame Loop ---- */
    u32 loop_top = R;
    mips_emit(ROM_BUF, &R, (0x09u << 26) | (16u << 21) | (16u << 16) | 1u); /* addiu s0, s0, 1 */

    /* 1. SI DMA Joybus Read ($A4800000: DRAM=$001F00 -> WR64B -> RD64B -> read stick_x/y at $001F04/$001F05!) */
    mips_li(ROM_BUF, &R, 8, 0xA4800000u);
    mips_li(ROM_BUF, &R, 9, 0x00001F00u);
    mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x00u);
    mips_li(ROM_BUF, &R, 9, 0x1FC007C0u);
    mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x10u); /* WR64B */
    mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x00u);
    mips_li(ROM_BUF, &R, 9, 0x00001F40u);
    mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x00u);
    mips_li(ROM_BUF, &R, 9, 0x1FC007C0u);
    mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x04u); /* RD64B -> $001F40! */

    /* Read signed analog stick X ($80001F45) & Y ($80001F46): ship_x += sx>>5, ship_y += sy>>5 */
    mips_li(ROM_BUF, &R, 8, 0x80001F40u);
    mips_emit(ROM_BUF, &R, (0x20u << 26) | (8u << 21) | (10u << 16) | 5u);   /* LB t2, 5(t0) = stick_x */
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (10u << 16) | (10u << 11) | (5u << 6) | 0x03u); /* SRA t2, 5 */
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (17u << 21) | (10u << 16) | (17u << 11) | 0x21u); /* s1 += t2 */
    mips_emit(ROM_BUF, &R, (0x20u << 26) | (8u << 21) | (11u << 16) | 6u);   /* LB t3, 6(t0) = stick_y */
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (11u << 16) | (11u << 11) | (5u << 6) | 0x03u); /* SRA t3, 5 */
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (18u << 21) | (11u << 16) | (18u << 11) | 0x21u); /* s2 += t3 */

    /* 2. Build 3D Roll/Yaw Rotation + Translation in Arwing Mtx ($80002240) using sin/cos table ($80002300)! */
    mips_li(ROM_BUF, &R, 8, 0x80002300u);
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (16u << 16) | (12u << 11) | (2u << 6) | 0x00u); /* t4 = frame * 4 */
    mips_emit(ROM_BUF, &R, (0x0Cu << 26) | (12u << 21) | (12u << 16) | 0xFFu);             /* ang = (frame*4)&255 */
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (12u << 16) | (13u << 11) | (1u << 6) | 0x00u); /* ang*2 */
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (8u << 21)  | (13u << 16) | (13u << 11) | 0x21u);
    mips_emit(ROM_BUF, &R, (0x21u << 26) | (13u << 21) | (14u << 16) | 0u);                /* t6 = sin (-256..256) */
    mips_emit(ROM_BUF, &R, (0x09u << 26) | (12u << 21) | (12u << 16) | 64u);
    mips_emit(ROM_BUF, &R, (0x0Cu << 26) | (12u << 21) | (12u << 16) | 0xFFu);
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (12u << 16) | (13u << 11) | (1u << 6) | 0x00u);
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (8u << 21)  | (13u << 16) | (13u << 11) | 0x21u);
    mips_emit(ROM_BUF, &R, (0x21u << 26) | (13u << 21) | (15u << 16) | 0u);                /* t7 = cos (-256..256) */

    /* Convert sin/cos (S8.8) -> S15.16 (<< 8) and write 3D Roll+Yaw Mtx into $80002240!
       Gentle barrel-roll bank: bank_ang = sin >> 2 (so cos_b ~= 0x0000F000, sin_b = sin << 6!) */
    mips_li(ROM_BUF, &R, 9, 0x80002240u);
    /* tx = ship_x + (sin >> 3): store at Mtx[3][0] integer part (+24) */
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (14u << 16) | (24u << 11) | (3u << 6) | 0x03u); /* t8 = sin >> 3 */
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (24u << 21) | (17u << 16) | (24u << 11) | 0x21u); /* t8 += ship_x */
    mips_emit(ROM_BUF, &R, (0x29u << 26) | (9u << 21)  | (24u << 16) | 24u);               /* SH tx -> Mtx int[12] */
    /* ty = ship_y + (cos >> 4): store at Mtx[3][1] integer part (+26) */
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (15u << 16) | (25u << 11) | (4u << 6) | 0x03u); /* t9 = cos >> 4 */
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (25u << 21) | (18u << 16) | (25u << 11) | 0x21u);
    mips_emit(ROM_BUF, &R, (0x29u << 26) | (9u << 21)  | (25u << 16) | 26u);
    /* Roll matrix elements M[0][1] = sin<<6, M[1][0] = -(sin<<6) in S15.16! */
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (14u << 16) | (24u << 11) | (6u << 6) | 0x00u); /* s16_val = sin << 6 */
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (24u << 16) | (25u << 11) | (16u << 6) | 0x03u);/* int part */
    mips_emit(ROM_BUF, &R, (0x29u << 26) | (9u << 21)  | (25u << 16) | 2u);
    mips_emit(ROM_BUF, &R, (0x29u << 26) | (9u << 21)  | (24u << 16) | 34u);
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (0u << 21)  | (24u << 16) | (24u << 11) | 0x23u);/* neg */
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (24u << 16) | (25u << 11) | (16u << 6) | 0x03u);
    mips_emit(ROM_BUF, &R, (0x29u << 26) | (9u << 21)  | (25u << 16) | 8u);
    mips_emit(ROM_BUF, &R, (0x29u << 26) | (9u << 21)  | (24u << 16) | 40u);

    /* Scroll Ground/Gate Z ($80002280 + 28) toward camera: z = -260 + ((frame * 3) & 127) */
    mips_li(ROM_BUF, &R, 9, 0x80002280u);
    mips_emit(ROM_BUF, &R, (0x00u << 26) | (16u << 16) | (24u << 11) | (2u << 6) | 0x00u);
    mips_emit(ROM_BUF, &R, (0x0Cu << 26) | (24u << 21) | (24u << 16) | 127u);
    mips_emit(ROM_BUF, &R, (0x09u << 26) | (24u << 21) | (24u << 16) | (0xFFFFu & (u32)-260));
    mips_emit(ROM_BUF, &R, (0x29u << 26) | (9u << 21)  | (24u << 16) | 28u);

    /* 3. Submit OSTask (M_GFXTASK=1, ucode_data=$002000, data_ptr=$004000) to SP_DMEM[$FC0] & start RSP! */
    mips_li(ROM_BUF, &R, 8, 0xA4000FC0u);
    mips_li(ROM_BUF, &R, 9, 1u);          mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x00u);
    mips_li(ROM_BUF, &R, 9, 0x00002000u); mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x18u);
    mips_li(ROM_BUF, &R, 9, 64u);         mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x1Cu);
    mips_li(ROM_BUF, &R, 9, 0x00004000u); mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x30u);
    mips_li(ROM_BUF, &R, 8, 0xA4040000u);
    mips_li(ROM_BUF, &R, 9, 0x00000005u); mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x10u); /* CLR_HALT|CLR_BROKE */

    /* 4. Push 800 stereo frames (3200 B) from $005000 to AI DMA! */
    mips_li(ROM_BUF, &R, 8, 0xA4500000u);
    mips_li(ROM_BUF, &R, 9, 0x00005000u); mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x00u);
    mips_li(ROM_BUF, &R, 9, 3200u);       mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (9u << 16) | 0x04u);

    /* 5. Wait for next VBlank (`MI_INTR & MI_INTR_VI` == 0x08), clear `VI_CURRENT`, and loop! */
    mips_li(ROM_BUF, &R, 8, 0xA4300000u);
    u32 wait_vi = R;
    mips_emit(ROM_BUF, &R, (0x23u << 26) | (8u << 21) | (9u << 16) | 0x08u);                /* LW t1, MI_INTR */
    mips_emit(ROM_BUF, &R, (0x0Cu << 26) | (9u << 21) | (9u << 16) | MI_INTR_VI);
    u32 b_off = ((wait_vi - (R + 4u)) >> 2) & 0xFFFFu;
    mips_emit(ROM_BUF, &R, (0x04u << 26) | (9u << 21) | (0u << 16) | b_off);                /* BEQ t1, zero, wait_vi */
    mips_emit(ROM_BUF, &R, 0x00000000u);
    mips_li(ROM_BUF, &R, 8, 0xA4400000u);
    mips_emit(ROM_BUF, &R, (0x2Bu << 26) | (8u << 21) | (0u << 16) | 0x10u);                /* SW zero, VI_CURRENT */

    u32 j_targ = (0x80001000u + (loop_top - B(0x1000u))) >> 2;
    mips_emit(ROM_BUF, &R, (0x02u << 26) | (j_targ & 0x03FFFFFFu));                         /* J loop_top */
    mips_emit(ROM_BUF, &R, 0x00000000u);
    #undef B

    S.rom_size = 0x40000u;
    S.boot_pc  = 0x80001000u;
    S.cic_seed = 0x3Fu;
    S.cic_type = 2u;
    S.is_pal   = 0;
}

/* ============================================================================
   Cartridge Loader (.z64 / .v64 / .n64), PIF IPL3 Boot & VI Scanout
   ============================================================================ */

static u32 n64_crc32_be_buf(const u8 *word_buf, u32 start_off, u32 len)
{
    u32 crc = 0xFFFFFFFFu;
    for (u32 i = 0; i < len; i++) {
        u8 b = be_r8(word_buf, start_off + i);
        crc ^= b;
        for (int k = 0; k < 8; k++)
            crc = (crc & 1u) ? (0xEDB88320u ^ (crc >> 1)) : (crc >> 1);
    }
    return ~crc;
}

void n64_reset(void)
{
    n64_zero(S.gpr, sizeof(S.gpr));
    n64_zero(S.cp0, sizeof(S.cp0));
    n64_zero(S.fpr, sizeof(S.fpr));
    n64_zero(M->tlb, sizeof(M->tlb));
    n64_zero(M->sp_dmem, sizeof(M->sp_dmem));
    n64_zero(M->sp_imem, sizeof(M->sp_imem));
    n64_zero(M->tmem, sizeof(M->tmem));
    n64_zero(M->pif_ram, sizeof(M->pif_ram));
    n64_zero(RDRAM_BUF, N64_RDRAM_SIZE);

    /* IPL3 Boot: copy up to 1 MB from Cart ROM[0x1000..] -> RDRAM[boot_pc & 0x3FFFFF] */
    u32 dst_off = S.boot_pc & 0x003FFFFFu;
    u32 copy_len = (S.rom_size > 0x1000u) ? (S.rom_size - 0x1000u) : 0u;
    if (copy_len > 0x100000u) copy_len = 0x100000u;
    if (dst_off + copy_len > N64_RDRAM_SIZE) copy_len = N64_RDRAM_SIZE - dst_off;
    be_copy_bytes(RDRAM_BUF, dst_off, ROM_BUF, 0x1000u, copy_len, N64_RDRAM_SIZE - 1u, N64_ROM_CAP - 1u);

    /* Copy ROM[0x000..0xFFF] into SP_DMEM (real PIF/IPL2 behavior expected by IPL3/libultra!) */
    u32 dmem_copy = S.rom_size < 0x1000u ? S.rom_size : 0x1000u;
    be_copy_bytes(M->sp_dmem, 0, ROM_BUF, 0, dmem_copy, 0xFFFu, N64_ROM_CAP - 1u);

    /* Write libultra OS Boot Globals in RDRAM ($000300..$0003F0) */
    be_w32(RDRAM_BUF, 0x000300u, S.is_pal ? 0u : 1u);           /* osTvType: 1=NTSC, 0=PAL */
    be_w32(RDRAM_BUF, 0x000304u, 0u);                           /* osRomType */
    be_w32(RDRAM_BUF, 0x000308u, 0xB0000000u);                  /* osRomBase */
    be_w32(RDRAM_BUF, 0x00030Cu, 0u);                           /* osResetType (cold boot) */
    be_w32(RDRAM_BUF, 0x000310u, 0u);                           /* osCicId */
    be_w32(RDRAM_BUF, 0x000314u, 0u);                           /* osVersion */
    be_w32(RDRAM_BUF, 0x000318u, N64_RDRAM_SIZE);               /* osMemSize (8 MB!) */
    be_w32(RDRAM_BUF, 0x0003F0u, N64_RDRAM_SIZE);               /* CIC-6105 osMemSize! */

    /* Post-IPL3 VR4300 CPU & COP0 Register State */
    S.gpr[11] = (u64)(s64)(s32)0xA4000040u;
    S.gpr[20] = S.is_pal ? 0ULL : 1ULL;
    S.gpr[22] = S.cic_seed;
    S.gpr[29] = (u64)(s64)(s32)0xA4001FF0u;
    S.gpr[31] = (u64)(s64)(s32)0xA4001550u;

    S.cp0[C0_RANDOM]  = 31u;
    S.cp0[C0_COUNT]   = 0x5000u;
    S.cp0[C0_STATUS]  = 0x34000000ULL;                          /* CU0 | CU1 | FR */
    S.cp0[C0_PRID]    = 0x00000B22ULL;
    S.cp0[C0_CONFIG]  = 0x7006E463ULL;

    S.pc        = S.boot_pc;
    S.next_pc   = S.pc + 4u;
    S.in_delay  = 0;
    S.ll_bit    = 0;
    S.sp_status = 0x0001u;                                      /* SP_STATUS_HALT */
    S.ri_select = 0x14u;
    S.mi_intr   = 0;
    S.mi_mask   = 0;
    S.ai_fifo_cnt = 0;
    S.snd_head = S.snd_tail = 0;

    S.scis_lrx = 320u << 2;
    S.scis_lry = 240u << 2;
}

static void n64_format_mempak(u8 *pak)
{
    n64_zero(pak, N64_SAVE_SIZE);
    /* Page 0 ($0000..$00FF): Standard libultra Controller Pak ID blocks at $20, $60, $80, $C0 */
    static const u8 id_blk[28] = {
        0x81,0x01,0x02,0x03, 0x04,0x05,0x06,0x07, 0x08,0x09,0x0A,0x0B, 0x0C,0x0D,0x0E,0x0F,
        0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF, 0x00,0x01,0x01,0x00
    };
    u16 sum = 0;
    for (int i = 0; i < 28; i += 2)
        sum = (u16)(sum + (((u16)id_blk[i] << 8) | id_blk[i + 1]));
    u16 isum = (u16)(0xFFF2u - sum);
    static const u32 id_offs[4] = { 0x0020u, 0x0060u, 0x0080u, 0x00C0u };
    for (int c = 0; c < 4; c++) {
        u32 o = id_offs[c];
        for (int i = 0; i < 28; i++) pak[o + (u32)i] = id_blk[i];
        pak[o + 28u] = (u8)(sum >> 8);  pak[o + 29u] = (u8)sum;
        pak[o + 30u] = (u8)(isum >> 8); pak[o + 31u] = (u8)isum;
    }
    /* Pages 1 & 2 ($0100..$02FF): Primary & Backup Inode/FAT tables (pages 5..127 = 0x0003 free!) */
    u8 fat_csum = 0;
    for (u32 p = 5u; p < 128u; p++) {
        pak[0x0100u + p * 2u] = 0x00u;
        pak[0x0101u + p * 2u] = 0x03u;
        fat_csum = (u8)(fat_csum + 0x03u);
    }
    pak[0x0101u] = fat_csum;
    for (u32 i = 0; i < 256u; i++)
        pak[0x0200u + i] = pak[0x0100u + i];
}

const char *n64_load(const u8 *image, u32 size, const char *path)
{
    u32 keep_rate = S.sample_rate;
    if (keep_rate != 48000u && keep_rate != 44100u && keep_rate != 32000u && keep_rate != 22050u)
        keep_rate = 48000u;
    n64_zero(&S, sizeof(S));
    n64_format_mempak(M->save_ram);
    S.sample_rate = keep_rate;
    S.scr_w = 320;
    S.scr_h = 240;

    if (!path || !*path || !image || size == 0) {
        build_builtin_n64_rom();
        static const char bi[] = "Star Wing 64 (Built-in N64 R4300i + FPU + F3DEX + Z-Buffered RDP 3D)";
        for (u32 i = 0; i < sizeof(bi); i++) S.info[i] = bi[i];
        n64_reset();
        return 0;
    }

    if (size < 0x1040u)
        return "N64 ROM image too small";

    u32 cap = (size < N64_ROM_CAP) ? (size & ~3u) : N64_ROM_CAP;
    /* Auto-detect endianness:
       0x80 0x37 0x12 0x40 = .z64 (Big-Endian)
       0x37 0x80 0x40 0x12 = .v64 (Doctor V64 16-bit byte-swapped)
       0x40 0x12 0x37 0x80 = .n64 (Little-Endian 32-bit word-swapped) */
    int fmt = 0;
    if (image[0] == 0x80u && image[1] == 0x37u)      fmt = 0;
    else if (image[0] == 0x37u && image[1] == 0x80u) fmt = 1;
    else if (image[0] == 0x40u && image[3] == 0x80u) fmt = 2;
    else return "Not a valid Nintendo 64 ROM (.z64/.v64/.n64)";

    for (u32 i = 0; i < cap; i += 4u) {
        u32 w;
        if (fmt == 0)      w = ((u32)image[i] << 24) | ((u32)image[i+1] << 16) | ((u32)image[i+2] << 8) | image[i+3];
        else if (fmt == 1) w = ((u32)image[i+1] << 24) | ((u32)image[i] << 16) | ((u32)image[i+3] << 8) | image[i+2];
        else               w = ((u32)image[i+3] << 24) | ((u32)image[i+2] << 16) | ((u32)image[i+1] << 8) | image[i];
        be_w32(ROM_BUF, i, w);
    }
    S.rom_size = cap;

    u32 entry = be_r32(ROM_BUF, 0x08u);
    u32 ipl_crc = n64_crc32_be_buf(ROM_BUF, 0x40u, 0xFC0u);
    S.cic_seed = 0x3Fu;
    S.cic_type = 2u;
    if (ipl_crc == 0x0B050EE0u)      { S.cic_seed = 0x78u; S.cic_type = 3u; entry -= 0x100000u; } /* CIC-6103 */
    else if (ipl_crc == 0x98BC2C86u) { S.cic_seed = 0x91u; S.cic_type = 5u; }                     /* CIC-6105 */
    else if (ipl_crc == 0xACC8580Au) { S.cic_seed = 0x85u; S.cic_type = 6u; entry -= 0x200000u; } /* CIC-6106 */

    S.boot_pc = entry;
    u8 cc = be_r8(ROM_BUF, 0x3Eu);
    S.is_pal = (cc == 'P' || cc == 'D' || cc == 'F' || cc == 'I' || cc == 'S' || cc == 'U') ? 1u : 0u;

    /* Extract 20-char ROM title from header 0x20..0x33 */
    char title[24];
    int tlen = 0;
    for (int i = 0; i < 20; i++) {
        u8 c = be_r8(ROM_BUF, 0x20u + (u32)i);
        title[i] = (c >= 32u && c < 127u) ? (char)c : ' ';
        if (title[i] != ' ') tlen = i + 1;
    }
    title[tlen] = 0;
    int pos = 0;
    static const char pfx[] = "N64: ";
    for (int i = 0; pfx[i]; i++) S.info[pos++] = pfx[i];
    for (int i = 0; title[i] && pos < 60; i++) S.info[pos++] = title[i];
    static const char sfx[] = " (VR4300 + FPU + RCP/RDP 3D)";
    for (int i = 0; sfx[i] && pos < 95; i++) S.info[pos++] = sfx[i];
    S.info[pos] = 0;

    n64_reset();
    return 0;
}

#pragma GCC optimize("O2")

static __attribute__((noinline)) void n64_vi_scanout(u16 *picture)
{
    if (!picture) return;
    u32 bpp_mode = S.vi_status & 3u;
    u32 origin   = S.vi_origin & (N64_RDRAM_SIZE - 4u);
    int stride   = (int)S.vi_width;
    if (stride <= 0 || stride > 640) stride = 320;

    if (bpp_mode < 2u || origin < 0x0400u || (S.vi_h_start == 0u && S.vi_v_start == 0u && origin < 0x1000u)) {
        for (int i = 0; i < 320 * 240; i++) picture[i] = 0;
        return;
    }

    int src_h = (stride >= 512) ? 480 : 240;
    for (int y = 0; y < 240; y++) {
        int sy = (src_h == 480) ? (y * 2) : y;
        u16 *dst = picture + y * 320;
        if (bpp_mode == 2u) {           /* 16-bit RGBA5551 (RRRRR GGGGG BBBBB A) -> 0BBBBBGGGGGRRRRR */
            u32 row = origin + (u32)(sy * stride) * 2u;
            if (stride == 320 && !(row & 3u) && row + 640u <= N64_RDRAM_SIZE && !(((__UINTPTR_TYPE__)dst) & 3u)) {
                const u32 *rsrc = (const u32 *)(const void *)(RDRAM_BUF + row);
                u32 *d32 = (u32 *)(void *)dst;
                for (int x = 0; x < 320; x += 2) {
                    u32 w2 = rsrc[x >> 1];
                    u32 p0 = w2 >> 16, p1 = w2 & 0xFFFFu;
                    u32 c0 = (((p0 >> 1) & 31u) << 10) | (((p0 >> 6) & 31u) << 5) | ((p0 >> 11) & 31u);
                    u32 c1 = (((p1 >> 1) & 31u) << 10) | (((p1 >> 6) & 31u) << 5) | ((p1 >> 11) & 31u);
                    d32[x >> 1] = c0 | (c1 << 16);
                }
            } else {
                for (int x = 0; x < 320; x++) {
                    int sx = (stride == 320) ? x : ((x * stride) / 320);
                    u16 p = be_r16(RDRAM_BUF, (row + (u32)sx * 2u) & (N64_RDRAM_SIZE - 2u));
                    u32 r = (p >> 11) & 31u;
                    u32 g = (p >>  6) & 31u;
                    u32 b = (p >>  1) & 31u;
                    dst[x] = (u16)((b << 10) | (g << 5) | r);
                }
            }
        } else {                        /* 32-bit RGBA8888 -> 0BBBBBGGGGGRRRRR */
            u32 row = origin + (u32)(sy * stride) * 4u;
            for (int x = 0; x < 320; x++) {
                int sx = (stride == 320) ? x : ((x * stride) / 320);
                u32 p = be_r32(RDRAM_BUF, (row + (u32)sx * 4u) & (N64_RDRAM_SIZE - 4u));
                u32 r = (p >> 27) & 31u;
                u32 g = (p >> 19) & 31u;
                u32 b = (p >> 11) & 31u;
                dst[x] = (u16)((b << 10) | (g << 5) | r);
            }
        }
    }
}

void n64_frame(u16 pad, u16 *picture)
{
    S.pad1 = pad;
    const int half_lines = S.is_pal ? 625 : 525;
    /* Effective CPI-adjusted VR4300 slice per half-line (~512 cycles * 525 = ~268K cycles/field;
       with HLE RSP/RDP + idle-loop skip, runs N64 games smoothly within S3811's budget!) */
    const s32 cyc_per_line = 512;

    S.cycles = 0;
    S.pi_io_busy_until = 0;
    for (int hl = 0; hl < half_lines; hl++) {
        S.vi_current = ((u32)hl & ~1u) | (S.frame_no & 1u);
        n64_cpu_run((hl + 1) * cyc_per_line);

        if ((u32)hl == S.vi_intr || (S.vi_intr == 0u && hl == 512))
            n64_raise_mi(MI_INTR_VI);

        if (S.ai_fifo_cnt > 0) {
            S.ai_cycles_left -= cyc_per_line * 6;
            if (S.ai_cycles_left <= 0) {
                S.ai_fifo_cnt--;
                S.ai_fifo_len[0] = S.ai_fifo_len[1];
                S.ai_cycles_left = 180000;
                n64_raise_mi(MI_INTR_AI);
            }
        }
    }

    n64_vi_scanout(picture);
    S.frame_no++;
}

int n64_width(void)  { return 320; }
int n64_height(void) { return 240; }
const char *n64_info(void) { return S.info; }

u8 *n64_save_ram(u32 *size, int *battery)
{
    if (size) *size = N64_SAVE_SIZE;
    if (battery) *battery = 1;
    return M->save_ram;
}

int n64_save_changed(void)
{
    int d = S.save_dirty;
    S.save_dirty = 0;
    return d;
}

int n64_jammed(void) { return S.jammed; }

void n64_audio_rate(u32 hz)
{
    S.sample_rate = hz ? hz : 48000u;
}

int n64_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && S.snd_tail != S.snd_head)
        out[n++] = M->snd_ring[S.snd_tail++ & (N64_SND_RING - 1u)];
    return n;
}

int n64_is_rom(const u8 *head, u32 len, u32 size)
{
    if (!head || len < 8u || size < 0x1040u)
        return 0;
    if (head[0] == 0x80u && head[1] == 0x37u && head[2] == 0x12u && head[3] == 0x40u) return 1;
    if (head[0] == 0x37u && head[1] == 0x80u && head[2] == 0x40u && head[3] == 0x12u) return 1;
    if (head[0] == 0x40u && head[1] == 0x12u && head[2] == 0x37u && head[3] == 0x80u) return 1;
    return 0;
}

#ifdef N64_HOST
void n64_host_poison_mem(void)
{
    u8 *b = (u8 *)&n64_host_mem;
    for (u32 i = 0; i < sizeof(n64_host_mem); i++)
        b[i] = (u8)(0xC3u ^ (i & 0xFFu));
    for (u32 i = 0; i < sizeof(n64_host_rdram); i += 4096u)
        n64_host_rdram[i] = 0x5Au;
    for (u32 i = 0; i < 0x80000u; i++)
        n64_host_rom[i] = (u8)(0xA5u ^ (i & 0xFFu));
}
#endif
