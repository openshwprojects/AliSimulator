/* Commodore Amiga CD32 ('cd32'): see cd32.h.
   Pass-optimized for 594 MHz MIPS32:
   - Zero static .bss (all 2 MB Chip RAM, 1 MB ROM, m68k optab & AGA/Akiko state in EMU_RAM_PHYS)
   - AGA 8-bitplane (256-color) + HAM8 + Copper + 2 MB Blitter + Sprites
   - Akiko $B80000 ($C0CACAFE): hardware 32-pixel Chunky-to-Planar ($B80038), CD DMA, 7-button pad & 1 KB NVRAM
   - 4-ch Paula DMA + streamed Redbook CD-DA resampled to 48 kHz
   - Built-in Clean-Room ISO-9660 + AmigaDOS HUNK_HEADER Relocator & Exec/DOS/LowLevel/NV HLE ROM */
/*-Os keeps m68k.inc (~26 KB) resident in S3811 32 KB L1 I-cache */
#include "cd32.h"

#ifndef CD32_HOST
#include "hw.h"
#endif

typedef signed char s8;

#define INLINE static inline __attribute__((always_inline))

/* 14.18758 MHz 68EC020: 908 cycles/line (313 PAL lines) */
#define LINE_CYCLES 908
#define CHIP_MASK   0x1FFFFEu           /* 2 MB Chip RAM! */
#define NEVER       0x3FFFFFFF
#define DMA_LINE    25
#define X0          0x71
#define Y0          0x24
#define SND_RING    4096
#define TRACK_WORDS 6334
#define WORD_CYCLES 454                 /* 32 us per MFM word at 14.18 MHz */
#define DISK_TURBO  56                  /* 8x turbo MFM DMA transfer */

struct cd32_sprite {
    u32 pt, x, vstart, vstop, state;
    u16 pos, ctl, data, datb;
    int armed;
};

struct cd32_paula_ch {
    u32 lc, cur_pt;
    u16 len, rem_words, per, vol;
    u32 ph_acc;
    s8  cur_smp;
    u8  hi_half;
    int on;
    s32 next_irq;
};

struct cd32_cia {
    u8  pra, prb, ddra, ddrb, sdr, icr, mask, cra, crb;
    u16 ta, tb, la, lb;
    u32 tod, alarm, latch;
    u8  latched, tod_run;
    s32 last;
};

struct cd32_disk {
    const u8 *adf;
    u32 size;
    int cyl, side, motor, sel, changed;
    int track_cyl, track_side;
    u16 len_was;
    u32 pt;
    int dma;
    s32 end;
};

struct cd32_state {
    const struct cdrom_toc *cd;
    u16 pad;
    u8  is_a1200;
    u8  ext_roms;
    u8  has_ext_rom;
    u8  overlay;
    u8  nvram_dirty;
    u8  lof;
    s32 now_t, line_limit;
    u32 cur_line, frames, cycles_hi;

    /* Custom chip registers ($DFF000..$DFF1FE) */
    u16 reg[256];
    u16 dmacon, intena, intreq, adkcon;
    u32 bplpt[8];                       /* Up to 8 AGA bitplanes! */
    u32 bltcpt, bltbpt, bltapt, bltdpt;
    s32 blit_end;
    u8  blit_busy, bzero;

    /* Copper */
    u32 cop_lc1, cop_lc2, cop_pc;
    u16 cop_ir1, cop_ir2;
    u8  cop_state;
    s32 cop_t;

    /* AGA 256-entry 24-bit Palette & pre-converted 15-bit RGB555 */
    u32 aga_rgb24[256];
    u16 aga_pal15[256];
    u16 line_pal15[256];
    struct { u16 x, idx, val15; } chg[128];
    int nchg;

    struct cd32_sprite spr[8];
    struct cd32_paula_ch aud[4];
    struct cd32_cia cia[2];
    struct cd32_disk disk;

    /* Amiga 1200 Gayle ID, keyboard serial queue & mouse */
    u8  gayle_id;
    u8  kq[64], held_was[16];
    int kq_head, kq_tail, kb_wait;
    s32 kb_time;
    char tq[256];
    int tq_head, tq_tail, tq_frame;
    u8  mouse_x, mouse_y, mouse_btn;

    /* Akiko ASIC ($B80000..$B8003F) */
    u32 ak_intena, ak_intreq;
    u32 ak_dma_addr;
    u32 ak_c2p_in[8], ak_c2p_out[8];
    u8  ak_c2p_widx, ak_c2p_ridx, ak_c2p_dirty;
    u8  pad_shift_mode, pad_shift_idx;
    u16 potgo_latch;

    /* Akiko / HLE CD-ROM & Redbook CD-DA state */
    u32 cd_dma_lba, cd_dma_dst, cd_dma_cnt;
    u8  cdda_playing, cdda_loop;
    u32 cdda_lba, cdda_end_lba, cdda_pos_bytes, cdda_frac;

    /* 48 kHz Audio Ring */
    u32 sample_rate, snd_frac;
    u32 snd_head, snd_tail;

    char info[96];
};

static void cd32_idle_branch(u32 at);
#define M68K_BRANCH(at) cd32_idle_branch(at)
#define M68K_CPU_020

#define M68K_EXTERNAL_STATE                                                     \
    struct cd32_mem {                                                           \
        struct cd32_state st;                                                   \
        struct m68k m_cpu;                                                      \
        u8 *m_rmap[256];                                                        \
        u8 *m_wmap[256];                                                        \
        u8  m_optab[65536];                                                     \
        u16 chip[0x100000];         /* 2 MB Chip RAM (host u16 words) */        \
        u16 kick[0x40000];          /* 512 KB Kickstart 3.0/3.1 ROM */          \
        u16 ext[0x40000];           /* 512 KB Extended ROM */                   \
        u16 disk_track[TRACK_WORDS];/* MFM encoded floppy track */              \
        u8  disk_sync[TRACK_WORDS];                                             \
        u8  nvram[1024];            /* 1 KB Akiko NVRAM (.sav) */               \
        u16 planes[8][64];          /* Fetched scanline bitplane words */       \
        u32 chunky[64 * 4];         /* Unpacked 8-bit chunky pixels */          \
        u32 nibble[16];             /* 4-bit -> 4-byte unpack LUT */            \
        u8  sec_buf[2048];          /* ISO-9660 / DMA sector buffer */          \
        u8  cdda_buf[2352];         /* Redbook CD-DA sector buffer */           \
        s16 snd_ring[SND_RING];                                                 \
    };                                                                          \
    CD32_MEM_BIND

#ifdef CD32_HOST
#define CD32_MEM_BIND static struct cd32_mem cd32_host_mem;
#define M (&cd32_host_mem)
#else
#define CD32_MEM_BIND
#define M ((struct cd32_mem *)KSEG0(EMU_RAM_PHYS))
#endif

#define S     (M->st)
#define m     (M->m_cpu)
#define rmap  (M->m_rmap)
#define wmap  (M->m_wmap)
#define optab (M->m_optab)

#include "m68k.inc"

#ifndef CD32_HOST
_Static_assert(sizeof(struct cd32_mem) <= EMU_RAM_SIZE, "cd32_mem exceeds EMU_RAM_SIZE");
#endif

#define CHIPW(a) M->chip[((a) & CHIP_MASK) >> 1]
#define R(o)     S.reg[(o) >> 1]

enum {
    DMACONR = 0x002, VPOSR = 0x004, VHPOSR = 0x006, JOY0DAT = 0x00A, JOY1DAT = 0x00C, CLXDAT = 0x00E,
    ADKCONR = 0x010, POTGOR = 0x016, SERDATR = 0x018, DSKBYTR = 0x01A, INTENAR = 0x01C, INTREQR = 0x01E,
    DSKPTH = 0x020, DSKPTL = 0x022, DSKLEN = 0x024, VPOSW = 0x02A, COPCON = 0x02E, POTGO = 0x034,
    JOYTEST = 0x036, BLTCON0 = 0x040, BLTCON1 = 0x042,
    BLTAFWM = 0x044, BLTALWM = 0x046, BLTCPTH = 0x048, BLTBPTH = 0x04C, BLTAPTH = 0x050, BLTDPTH = 0x054,
    BLTSIZE = 0x058, BLTCON0L = 0x05A, BLTSIZV = 0x05C, BLTSIZH = 0x05E,
    BLTCMOD = 0x060, BLTBMOD = 0x062, BLTAMOD = 0x064, BLTDMOD = 0x066,
    BLTCDAT = 0x070, BLTBDAT = 0x072, BLTADAT = 0x074, DSKSYNC = 0x07E, LISAID = 0x07C,
    COP1LCH = 0x080, COP2LCH = 0x084, COPJMP1 = 0x088, COPJMP2 = 0x08A,
    DIWSTRT = 0x08E, DIWSTOP = 0x090, DDFSTRT = 0x092, DDFSTOP = 0x094,
    DMACON = 0x096, INTENA = 0x09A, INTREQ = 0x09C, ADKCON = 0x09E,
    AUD0 = 0x0A0, BPL1PTH = 0x0E0, BPLCON0 = 0x100, BPLCON1 = 0x102, BPLCON2 = 0x104, BPLCON3 = 0x106,
    BPL1MOD = 0x108, BPL2MOD = 0x10A, BPLCON4 = 0x10C, SPR0PTH = 0x120, SPR0POS = 0x140,
    COLOR00 = 0x180, FMODE = 0x1FC
};

static void cd32_zero(void *p, u32 n)
{
    u8 *b = (u8 *)p;
    for (u32 i = 0; i < n; i++)
        b[i] = 0;
}

static u16 rgb24_to_15(u32 rgb)
{
    u32 r = (rgb >> 19) & 31u;
    u32 g = (rgb >> 11) & 31u;
    u32 b = (rgb >> 3)  & 31u;
    return (u16)((b << 10) | (g << 5) | r);
}

static void cd32_map_memory(void)
{
    for (int i = 0; i < 256; i++)
        rmap[i] = wmap[i] = 0;
    /* $000000..$1FFFFF: 2 MB Chip RAM (32 x 64 KB pages) */
    for (int i = 0; i < 0x20; i++)
        rmap[i] = wmap[i] = (u8 *)M->chip + ((u32)i << 16);
    /* $E00000..$E7FFFF: 512 KB Extended ROM (CD32 ext or AROS ext when present) */
    if (!S.is_a1200 || S.has_ext_rom) {
        for (int i = 0; i < 8; i++)
            rmap[0xE0 + i] = (u8 *)M->ext + ((u32)i << 16);
    }
    /* $F80000..$FFFFFF: 512 KB Kickstart 3.0 / 3.1 ROM */
    for (int i = 0; i < 8; i++)
        rmap[0xF8 + i] = (u8 *)M->kick + ((u32)i << 16);
    if (S.overlay) {
        for (int i = 0; i < 8; i++) {
            rmap[i] = rmap[0xF8 + i];
            wmap[i] = 0;
        }
    }
}

/* Spin-wait fast-forwarding on Chip RAM or VPOSR/INTREQR */
static void cd32_idle_branch(u32 at)
{
    u32 t = m.pc;
    if (t >= at || at - t > 20 || (t & 1))
        return;
    const u8 *p = rmap[(t >> 16) & 0xFF];
    if (!p) return;
    u16 op = *(const u16 *)(p + (t & 0xFFFF));
    /* Tight TST / CMPI loop on Chip RAM or VPOSR/INTREQR ($DFF004/$DFF01E) while copper, blitter & floppy are idle */
    if (((op & 0xFF00u) == 0x4A00u || (op & 0xFF00u) == 0x0C00u || op == 0x2039u || op == 0x3039u) &&
        !S.blit_busy && !S.disk.dma && S.cop_t > S.line_limit) {
        if (m.clock < S.line_limit)
            m.clock = S.line_limit;
    }
}

static void update_ipl(void)
{
    static const u8 level[14] = {1, 1, 1, 2, 3, 3, 3, 4, 4, 4, 4, 5, 5, 6};
    u32 act = (S.intena & 0x4000u) ? (S.intena & S.intreq & 0x3FFFu) : 0u;
    u32 l = 0;
    for (int b = 13; b >= 0; b--) {
        if (act & (1u << b)) { l = level[b]; break; }
    }
    if ((S.ak_intena & S.ak_intreq) && l < 2)
        l = 2;
    m.ipl = l;
    check_pending();
}

static void raise_irq(u32 bits)
{
    S.intreq |= (u16)bits;
    update_ipl();
}

/* ---- Akiko Hardware Chunky-to-Planar ($B80038) ---- */

static void akiko_c2p_convert(void)
{
    if (!S.ak_c2p_dirty) return;
    for (int plane = 0; plane < 8; plane++) {
        u32 out = 0;
        for (int w = 0; w < 8; w++) {
            u32 cw = S.ak_c2p_in[w];
            u32 b0 = (cw >> (24 + plane)) & 1u;
            u32 b1 = (cw >> (16 + plane)) & 1u;
            u32 b2 = (cw >> (8  + plane)) & 1u;
            u32 b3 = (cw >> (0  + plane)) & 1u;
            out = (out << 4) | (b0 << 3) | (b1 << 2) | (b2 << 1) | b3;
        }
        S.ak_c2p_out[plane] = out;
    }
    S.ak_c2p_dirty = 0;
}

static void akiko_cd_dma_exec(void)
{
    if (!S.cd || !S.cd->read_2048 || !S.cd_dma_cnt)
        return;
    u32 lba = S.cd_dma_lba;
    u32 dst = S.cd_dma_dst & 0x1FFFFEu;
    for (u32 s = 0; s < S.cd_dma_cnt; s++, lba++) {
        if (S.cd->read_2048(lba, M->sec_buf) == 0) {
            for (u32 i = 0; i < 2048u; i += 2u) {
                CHIPW(dst) = (u16)(((u16)M->sec_buf[i] << 8) | M->sec_buf[i + 1u]);
                dst = (dst + 2u) & 0x1FFFFEu;
            }
        }
    }
    S.cd_dma_dst = dst;
    S.cd_dma_lba = lba;
    S.cd_dma_cnt = 0;
    S.ak_intreq |= 0x04000000u;
    raise_irq(0x0008u);                                 /* Level 2 Ports/Akiko IRQ */
}

static void cdda_start_track(u32 trk, u8 loop)
{
    if (!S.cd || trk < 1u || trk > S.cd->last_track) {
        S.cdda_playing = 0;
        return;
    }
    S.cdda_lba = S.cd->tracks[trk].lba;
    S.cdda_end_lba = S.cdda_lba + S.cd->tracks[trk].length;
    S.cdda_pos_bytes = 2352u;
    S.cdda_loop = loop;
    S.cdda_playing = S.cd->tracks[trk].is_audio ? 1u : 0u;
}

static u32 akiko_read16(u32 off)
{
    switch (off & 0xFEu) {
    case 0x00: return 0xC0CAu;                          /* Akiko ID high: $C0CACAFE */
    case 0x02: return 0xCAFEu;                          /* Akiko ID low */
    case 0x04: return (u16)(S.ak_intreq >> 16);
    case 0x06: return (u16)S.ak_intreq;
    case 0x08: return (u16)(S.ak_intena >> 16);
    case 0x0A: return (u16)S.ak_intena;
    case 0x38: {
        akiko_c2p_convert();
        u32 w = S.ak_c2p_out[(S.ak_c2p_ridx >> 1) & 7u];
        u16 res = (S.ak_c2p_ridx & 1u) ? (u16)w : (u16)(w >> 16);
        S.ak_c2p_ridx = (S.ak_c2p_ridx + 1u) & 15u;
        return res;
    }
    case 0x3A: {
        akiko_c2p_convert();
        u32 w = S.ak_c2p_out[(S.ak_c2p_ridx >> 1) & 7u];
        u16 res = (u16)w;
        S.ak_c2p_ridx = (S.ak_c2p_ridx + 1u) & 15u;
        return res;
    }
    case 0x48: return (u16)S.cd_dma_cnt;
    case 0x50:                                          /* Direct NVRAM window ($B80050: status / count) */
        return 1024u;
    }
    return 0;
}

static void akiko_write16(u32 off, u16 v)
{
    switch (off & 0xFEu) {
    case 0x04: S.ak_intreq &= ~((u32)v << 16); update_ipl(); break;
    case 0x06: S.ak_intreq &= ~(u32)v; update_ipl(); break;
    case 0x08: S.ak_intena = (S.ak_intena & 0x0000FFFFu) | ((u32)v << 16); update_ipl(); break;
    case 0x0A: S.ak_intena = (S.ak_intena & 0xFFFF0000u) | v; update_ipl(); break;
    case 0x10: S.ak_dma_addr = (S.ak_dma_addr & 0x0000FFFFu) | ((u32)v << 16); break;
    case 0x12: S.ak_dma_addr = (S.ak_dma_addr & 0xFFFF0000u) | v; break;
    case 0x38:
        S.ak_c2p_in[(S.ak_c2p_widx >> 1) & 7u] =
            (S.ak_c2p_in[(S.ak_c2p_widx >> 1) & 7u] & 0x0000FFFFu) | ((u32)v << 16);
        S.ak_c2p_widx = (S.ak_c2p_widx + 1u) & 15u;
        S.ak_c2p_ridx = 0;
        S.ak_c2p_dirty = 1;
        break;
    case 0x3A:
        S.ak_c2p_in[(S.ak_c2p_widx >> 1) & 7u] =
            (S.ak_c2p_in[(S.ak_c2p_widx >> 1) & 7u] & 0xFFFF0000u) | v;
        S.ak_c2p_widx = (S.ak_c2p_widx + 1u) & 15u;
        S.ak_c2p_ridx = 0;
        S.ak_c2p_dirty = 1;
        break;
    case 0x40: S.cd_dma_lba = (S.cd_dma_lba & 0x0000FFFFu) | ((u32)v << 16); break;
    case 0x42: S.cd_dma_lba = (S.cd_dma_lba & 0xFFFF0000u) | v; break;
    case 0x44: S.cd_dma_dst = (S.cd_dma_dst & 0x0000FFFFu) | ((u32)v << 16); break;
    case 0x46: S.cd_dma_dst = (S.cd_dma_dst & 0xFFFF0000u) | v; break;
    case 0x48: S.cd_dma_cnt = v; akiko_cd_dma_exec(); break;
    case 0x4C: cdda_start_track(v & 0xFFu, (u8)((v >> 8) & 1u)); break;
    }
}

/* ---- 2 MB Blitter (Area & Line Modes) ---- */

static u32 blit_minterm(u32 lf, u32 a, u32 b, u32 c)
{
    switch (lf) {
    case 0xF0: return a;
    case 0xCC: return b;
    case 0xAA: return c;
    case 0x00: return 0;
    case 0xFF: return 0xFFFFu;
    case 0xCA: return (a & b) | (~a & c);
    case 0xFA: return a | c;
    case 0xEA: return (a & b) | c;
    case 0x0A: return ~a & c;
    case 0x5A: return a ^ c;
    case 0xFC: return a | b;
    case 0x3C: return a ^ b;
    default: {
        u32 d = 0;
        if (lf & 0x01u) d |= ~a & ~b & ~c;
        if (lf & 0x02u) d |= ~a & ~b &  c;
        if (lf & 0x04u) d |= ~a &  b & ~c;
        if (lf & 0x08u) d |= ~a &  b &  c;
        if (lf & 0x10u) d |=  a & ~b & ~c;
        if (lf & 0x20u) d |=  a & ~b &  c;
        if (lf & 0x40u) d |=  a &  b & ~c;
        if (lf & 0x80u) d |=  a &  b &  c;
        return d;
    }
    }
}

static u32 blit_fill_word(u32 d, u32 *carry, u32 inclusive)
{
    u32 out = 0, c = *carry;
    for (int i = 0; i < 16; i++) {
        u32 bit = (d >> i) & 1u;
        if (inclusive) {
            out |= (bit | c) << i;
            c ^= bit;
        } else {
            c ^= bit;
            out |= c << i;
        }
    }
    *carry = c;
    return out;
}

static void blit_start(u32 w, u32 h)
{
    if (!w) w = 64;
    if (!h) h = 1024;
    u32 con0 = R(BLTCON0), con1 = R(BLTCON1);

    if (con1 & 1u) {                                    /* Line draw mode (UAE / HRM exact octant & SING) */
        u32 lf = con0 & 0xFFu, ash = con0 >> 12, bsh = con1 >> 12;
        u32 b = R(BLTBDAT), tex = ((b >> bsh) | (b << (16u - bsh))) & 0xFFFFu;
        u32 a = R(BLTADAT) & R(BLTAFWM);
        u32 cmod = (u32)(s32)(s16)R(BLTCMOD), amod = (u32)(s32)(s16)R(BLTAMOD), bmod = (u32)(s32)(s16)R(BLTBMOD);
        int sign = (con1 >> 6) & 1, onedot = 0;
        u32 nz = 0;
        for (u32 i = 0; i < h; i++) {
            u32 c = CHIPW(S.bltcpt);
            u32 ad = a >> ash;
            if ((con1 & 2u) && onedot)
                ad = 0;
            onedot = 1;
            u32 d = blit_minterm(lf, ad, (tex & 1u) ? 0xFFFFu : 0u, c) & 0xFFFFu;
            nz |= d;
            if (con0 & 0x800u)
                S.bltapt += sign ? bmod : amod;
            if (!sign) {
                if (con1 & 0x10u) {
                    S.bltcpt += (con1 & 8u) ? (0u - cmod) : cmod;
                    onedot = 0;
                } else if (con1 & 8u) {
                    if (ash-- == 0u) { ash = 15u; S.bltcpt -= 2u; }
                } else if (++ash == 16u) {
                    ash = 0u; S.bltcpt += 2u;
                }
            }
            if (con1 & 0x10u) {
                if (con1 & 4u) {
                    if (ash-- == 0u) { ash = 15u; S.bltcpt -= 2u; }
                } else if (++ash == 16u) {
                    ash = 0u; S.bltcpt += 2u;
                }
            } else {
                S.bltcpt += (con1 & 4u) ? (0u - cmod) : cmod;
                onedot = 0;
            }
            sign = (s16)S.bltapt < 0;
            tex = ((tex << 1) | (tex >> 15)) & 0xFFFFu;
            if (con0 & 0x100u)
                CHIPW(S.bltdpt) = (u16)d;
            S.bltdpt = S.bltcpt;
        }
        R(BLTCON0) = (u16)((con0 & 0x0FFFu) | (ash << 12));
        R(BLTCON1) = (u16)((con1 & ~0x40u) | ((u32)sign << 6));
        S.bzero = !nz;
        S.blit_busy = 1;
        S.blit_end = S.now_t + (s32)(h * 8u) + 8;
        return;
    }

    u32 use = con0 >> 8, lf = con0 & 0xFFu;
    u32 ash = con0 >> 12, bsh = con1 >> 12, desc = con1 & 2u, fill = con1 & 0x18u, nz = 0;
    u32 fwm = R(BLTAFWM), lwm = R(BLTALWM), aold = 0, bold = 0;
    u32 adat = R(BLTADAT), bdat = R(BLTBDAT), cdat = R(BLTCDAT);
    s32 inc = desc ? -2 : 2;
    s32 amod = (s16)R(BLTAMOD), bmod = (s16)R(BLTBMOD), cmod = (s16)R(BLTCMOD), dmod = (s16)R(BLTDMOD);
    if (desc) { amod = -amod; bmod = -bmod; cmod = -cmod; dmod = -dmod; }
    for (u32 y = 0; y < h; y++) {
        u32 carry = (con1 >> 2) & 1u;
        for (u32 x = 0; x < w; x++) {
            if (use & 8u) { adat = CHIPW(S.bltapt); S.bltapt += (u32)inc; }
            if (use & 4u) { bdat = CHIPW(S.bltbpt); S.bltbpt += (u32)inc; }
            if (use & 2u) { cdat = CHIPW(S.bltcpt); S.bltcpt += (u32)inc; }
            u32 a = adat;
            if (x == 0u)     a &= fwm;
            if (x == w - 1u) a &= lwm;
            u32 as = desc ? ((a << 16 | aold) >> (16u - ash)) : ((aold << 16 | a) >> ash);
            u32 bs = desc ? ((bdat << 16 | bold) >> (16u - bsh)) : ((bold << 16 | bdat) >> bsh);
            aold = a; bold = bdat;
            u32 d = blit_minterm(lf, as & 0xFFFFu, bs & 0xFFFFu, cdat) & 0xFFFFu;
            if (fill)
                d = blit_fill_word(d, &carry, con1 & 8u);
            nz |= d;
            if (use & 1u) { CHIPW(S.bltdpt) = (u16)d; S.bltdpt += (u32)inc; }
        }
        if (use & 8u) S.bltapt += (u32)amod;
        if (use & 4u) S.bltbpt += (u32)bmod;
        if (use & 2u) S.bltcpt += (u32)cmod;
        if (use & 1u) S.bltdpt += (u32)dmod;
    }
    R(BLTADAT) = (u16)adat; R(BLTBDAT) = (u16)bdat; R(BLTCDAT) = (u16)cdat;
    S.bzero = !nz;
    S.blit_busy = 1;
    S.blit_end = S.now_t + (s32)(w * h * 4u) + 8;
}

/* ---- Copper ---- */

static void custom_write(u32 r, u32 v);

static void copper_jump(u32 addr, s32 t)
{
    S.cop_pc = addr & CHIP_MASK;
    S.cop_state = 1;
    S.cop_t = t + 4;
}

static s32 beam_wait_time(u32 vp, u32 hp, u32 vm, u32 hm, s32 now)
{
    u32 cur_l = (u32)now / LINE_CYCLES;
    u32 cur_h = ((u32)now % LINE_CYCLES) >> 2;
    for (u32 l = cur_l; l < 313; l++) {
        if ((l & vm) < (vp & vm)) continue;
        if ((l & vm) > (vp & vm)) return (s32)(l * LINE_CYCLES);
        u32 h0 = (l == cur_l) ? cur_h : 0u;
        for (u32 h = h0; h < 227; h++) {
            if ((h & hm) >= (hp & hm))
                return (s32)(l * LINE_CYCLES + h * 4);
        }
    }
    return NEVER;
}

static void copper_run(s32 limit)
{
    if ((S.dmacon & 0x280u) != 0x280u || !S.cop_state)
        return;
    int guard = 0;
    while (S.cop_t <= limit && guard++ < 512) {
        S.now_t = S.cop_t;
        u16 ir1 = CHIPW(S.cop_pc);
        u16 ir2 = CHIPW(S.cop_pc + 2);
        S.cop_pc = (S.cop_pc + 4) & CHIP_MASK;
        if (!(ir1 & 1u)) {                              /* MOVE */
            u32 reg_off = ir1 & 0x1FEu;
            if (reg_off < 0x40u || (reg_off < 0x80u && !(R(COPCON) & 2u))) {
                S.cop_state = 0;
                S.cop_t = NEVER;
                return;
            }
            custom_write(reg_off, ir2);
            S.cop_t += 8;
        } else if (!(ir2 & 1u)) {                       /* WAIT */
            if (ir1 == 0xFFFFu && ir2 == 0xFFFEu) {
                S.cop_state = 0;
                S.cop_t = NEVER;
                return;
            }
            u32 vp = ir1 >> 8, hp = (ir1 & 0xFEu) >> 1;
            u32 vm = ((ir2 >> 8) & 0x7Fu) | 0x80u, hm = (ir2 & 0xFEu) >> 1;
            s32 wt = beam_wait_time(vp, hp, vm, hm, S.cop_t + 8);
            if (wt > limit) {
                S.cop_pc = (S.cop_pc - 4) & CHIP_MASK;  /* Re-evaluate once beam arrives */
                S.cop_t = wt;
                return;
            }
            S.cop_t = wt + 4;
        } else {                                        /* SKIP */
            u32 vp = ir1 >> 8, hp = (ir1 & 0xFEu) >> 1;
            u32 vm = ((ir2 >> 8) & 0x7Fu) | 0x80u, hm = (ir2 & 0xFEu) >> 1;
            u32 l = (u32)S.cop_t / LINE_CYCLES, h = ((u32)S.cop_t % LINE_CYCLES) >> 2;
            if (((l << 8) | h) >= (((vp & vm) << 8) | (hp & hm)))
                S.cop_pc = (S.cop_pc + 4) & CHIP_MASK;
            S.cop_t += 8;
        }
    }
}

/* ---- AGA Scanline Renderer (1..8 Bitplanes, 256-color / HAM8 / EHB + Sprites) ---- */

static void sprite_decode(struct cd32_sprite *s)
{
    s->vstart = (u32)(s->pos >> 8) | ((s->ctl & 4u) << 6);
    s->vstop  = (u32)(s->ctl >> 8) | ((s->ctl & 2u) << 7);
    s->x      = ((u32)(s->pos & 0xFFu) << 1) | (s->ctl & 1u);
}

static void sprite_dma(u32 line)
{
    if ((S.dmacon & 0x220u) != 0x220u || line < DMA_LINE)
        return;
    for (int i = 0; i < 8; i++) {
        struct cd32_sprite *s = &S.spr[i];
        if (s->state == 0 || (s->state == 2 && line == s->vstop)) {
            s->pos = CHIPW(s->pt);
            s->ctl = CHIPW(s->pt + 2);
            s->pt += 4;
            sprite_decode(s);
            s->armed = 0;
            s->state = 1;
            continue;
        }
        if (s->state == 1 && line == s->vstart)
            s->state = 2;
        if (s->state == 2) {
            s->data = CHIPW(s->pt);
            s->datb = CHIPW(s->pt + 2);
            s->pt += 4;
            s->armed = 1;
        }
    }
}

static void render_aga_line(u32 line, u16 *pic)
{
    u32 con0 = R(BPLCON0);
    /* AGA BPU: bits 14..12 = BPU2..0; bit 4 = BPU3 (8 bitplanes when BPU3=1 & BPU2..0=0)! */
    u32 bpu = ((con0 >> 12) & 7u) | ((con0 & 0x0010u) ? 8u : 0u);
    if (bpu > 8u) bpu = 8u;
    u32 hires = con0 & 0x8000u, ham = con0 & 0x0800u;
    u32 v0 = R(DIWSTRT) >> 8;
    u32 v1 = (R(DIWSTOP) >> 8) | ((R(DIWSTOP) & 0x8000u) ? 0u : 0x100u);
    int vdiw = (line >= v0 && line < v1);
    u32 words = 0, xs = 0, width = 0;

    if (vdiw && bpu && (S.dmacon & 0x300u) == 0x300u && line >= DMA_LINE) {
        u32 mask = hires ? 0xFCu : 0xF8u;
        u32 start = R(DDFSTRT) & mask, stop = R(DDFSTOP) & mask;
        if (start < 0x18u) start = 0x18u;
        if (stop > 0xD8u)  stop = 0xD8u;
        if (stop < start)  stop = start;
        /* Respect AGA FMODE ($DFF1FC) wide 32/64-bit fetch rounding */
        u32 fmode = R(FMODE) & 3u;
        words = hires ? (((stop - start) >> 2) + 2u) : (((stop - start) >> 3) + 1u);
        if (fmode == 1u || fmode == 2u) words = (words + 1u) & ~1u;
        else if (fmode == 3u)           words = (words + 3u) & ~3u;
        if (words > 60u) words = 60u;
        xs = 2u * start + (hires ? 9u : 17u);
        for (u32 p = 0; p < bpu; p++) {
            u32 a = S.bplpt[p];
            for (u32 i = 0; i < words; i++, a += 2u)
                M->planes[p][i] = CHIPW(a);
            S.bplpt[p] = a + (u32)(s32)(s16)R((p & 1u) ? BPL2MOD : BPL1MOD);
        }
    }

    if (!pic || line < Y0 || line >= Y0 + CD32_H)
        return;

    u16 *out = pic + (line - Y0) * CD32_W;
    u32 dl = R(DIWSTRT) & 0xFFu, dr = 0x100u | (R(DIWSTOP) & 0xFFu);
    if (!vdiw) dl = dr = 0;

    if (words) {
        u32 n = words + 2u;
        const u32 *nib = M->nibble;
        for (u32 i = 0; i < n * 4u; i++)
            M->chunky[i] = 0;
        if ((R(BPLCON1) & 0xFFu) == 0u) {
            for (u32 p = 0; p < bpu; p++) {
                const u16 *w = M->planes[p];
                for (u32 j = 0; j < words; j++) {
                    u32 o = w[j];
                    if (!o) continue;
                    u32 *c = M->chunky + 4u * j;
                    c[0] |= nib[o >> 12] << p;
                    c[1] |= nib[(o >> 8) & 15u] << p;
                    c[2] |= nib[(o >> 4) & 15u] << p;
                    c[3] |= nib[o & 15u] << p;
                }
            }
        } else {
            for (u32 p = 0; p < bpu; p++) {
                u32 d = (R(BPLCON1) >> ((p & 1u) ? 4u : 0u)) & 15u;
                if (hires) d *= 2u;
                u32 q = d >> 4, r = d & 15u;
                const u16 *w = M->planes[p];
                for (u32 j = 0; j < n; j++) {
                    s32 k = (s32)j - (s32)q;
                    u32 cur = (k >= 0 && k < (s32)words) ? w[k] : 0u;
                    u32 prv = (k >= 1 && k - 1 < (s32)words) ? w[k - 1] : 0u;
                    u32 o = r ? (((prv << (16u - r)) | (cur >> r)) & 0xFFFFu) : cur;
                    if (!o) continue;
                    u32 *c = M->chunky + 4u * j;
                    c[0] |= nib[o >> 12] << p;
                    c[1] |= nib[(o >> 8) & 15u] << p;
                    c[2] |= nib[(o >> 4) & 15u] << p;
                    c[3] |= nib[o & 15u] << p;
                }
            }
        }
        width = n * 16u;
    }

    const u8 *ch = (const u8 *)M->chunky;
    u8 bpl_xor = (u8)(R(BPLCON4) >> 8);
    u32 pl = xs > dl ? xs : dl;
    u32 pr = xs + (hires ? (width >> 1) : width);
    if (pr > dr) pr = dr;
    if (!words || pl > pr) pl = pr = 0;

    int dpf = (con0 & 0x0400u) != 0 && !ham;
    int is_ehb = (bpu == 6u && !dpf && (R(BPLCON2) & 0x0200u) == 0u && S.line_pal15[63] == 0u);
    if (!S.nchg && !ham && !hires && !is_ehb && !dpf) {
        const u16 *pal = S.line_pal15;
        u16 pal0 = pal[0];
        u32 l0 = pl < X0 ? X0 : (pl > X0 + CD32_W ? X0 + CD32_W : pl);
        u32 r0 = pr < l0 ? l0 : (pr > X0 + CD32_W ? X0 + CD32_W : pr);
        u32 x = X0;
        for (; x < l0; x++)
            out[x - X0] = pal0;
        for (; x < r0; x++)
            out[x - X0] = pal[ch[x - xs] ^ bpl_xor];
        for (; x < X0 + CD32_W; x++)
            out[x - X0] = pal0;
    } else {
        int chg_i = 0;
        u32 hold24 = S.aga_rgb24[0];
        u32 pf2pri = (R(BPLCON2) & 0x0040u) != 0;
        u32 pf2of_code = (R(BPLCON3) >> 10) & 7u;
        u32 pf2_base = pf2of_code ? (1u << pf2of_code) : 0u;
        if (!pf2of_code && bpu <= 6u) pf2_base = 8u;        /* OCS/ECS default PF2 offset */
        for (u32 x = X0; x < X0 + CD32_W; x++) {
            while (chg_i < S.nchg && S.chg[chg_i].x <= x) {
                S.line_pal15[S.chg[chg_i].idx & 0xFFu] = S.chg[chg_i].val15;
                chg_i++;
            }
            if (x < pl || x >= pr) {
                out[x - X0] = S.line_pal15[0];
                hold24 = S.aga_rgb24[0];
                continue;
            }
            if (ham && bpu == 8u) {                         /* HAM8 */
                u8 px = ch[x - xs];
                u32 v6 = (u32)(px & 0x3Fu) << 2;
                switch (px >> 6) {
                case 0: hold24 = S.aga_rgb24[px & 0x3Fu]; break;
                case 1: hold24 = (hold24 & 0xFFFF03u) | v6; break;
                case 2: hold24 = (hold24 & 0x03FFFFu) | (v6 << 16); break;
                case 3: hold24 = (hold24 & 0xFF03FFu) | (v6 << 8); break;
                }
                out[x - X0] = rgb24_to_15(hold24);
            } else if (ham && bpu == 6u) {                  /* HAM6 */
                u8 px = ch[x - xs];
                u32 v4 = (u32)(px & 15u) * 0x11u;
                switch ((px >> 4) & 3u) {
                case 0: hold24 = S.aga_rgb24[px & 15u]; break;
                case 1: hold24 = (hold24 & 0xFFFF00u) | v4; break;
                case 2: hold24 = (hold24 & 0x00FFFFu) | (v4 << 16); break;
                case 3: hold24 = (hold24 & 0xFF00FFu) | (v4 << 8); break;
                }
                out[x - X0] = rgb24_to_15(hold24);
            } else if (dpf) {                               /* AGA/OCS Dual Playfield */
                u32 raw = hires ? ch[2u * (x - xs)] : ch[x - xs];
                u32 p1 = (raw & 1u) | ((raw >> 1) & 2u) | ((raw >> 2) & 4u) | ((raw >> 3) & 8u);
                u32 p2 = ((raw >> 1) & 1u) | ((raw >> 2) & 2u) | ((raw >> 3) & 4u) | ((raw >> 4) & 8u);
                u32 idx = 0;
                if (pf2pri) idx = p2 ? (pf2_base + p2) : p1;
                else        idx = p1 ? p1 : (p2 ? (pf2_base + p2) : 0u);
                out[x - X0] = S.line_pal15[(idx ^ bpl_xor) & 0xFFu];
            } else if (hires) {
                u8 c0 = ch[2u * (x - xs)] ^ bpl_xor;
                u8 c1 = ch[2u * (x - xs) + 1u] ^ bpl_xor;
                u32 l = S.line_pal15[c0], r = S.line_pal15[c1];
                out[x - X0] = (u16)(((l & 0x7BDEu) >> 1) + ((r & 0x7BDEu) >> 1) + (l & r & 0x0421u));
            } else if (is_ehb) {
                u8 idx = ch[x - xs] ^ bpl_xor;
                out[x - X0] = (idx >= 32u) ? (u16)((S.line_pal15[idx - 32u] & 0x7BDEu) >> 1) : S.line_pal15[idx];
            } else {
                out[x - X0] = S.line_pal15[ch[x - xs] ^ bpl_xor];
            }
        }
    }

    /* Sprites */
    int any_spr = 0;
    for (int i = 0; i < 8; i++)
        any_spr |= S.spr[i].armed;
    if (!any_spr)
        return;
    u32 spr_base = (R(BPLCON4) & 0x00F0u) ? ((u32)(R(BPLCON4) & 0xF0u)) : 16u;
    for (int n = 3; n >= 0; n--) {
        struct cd32_sprite *e = &S.spr[2 * n], *o = &S.spr[2 * n + 1];
        int attached = (o->ctl & 0x80u) && o->armed && e->armed;
        for (int k = attached ? 0 : 1; k >= 0; k--) {
            struct cd32_sprite *s = attached ? e : (k ? o : e);
            if (!s->armed) continue;
            for (u32 i = 0; i < 16u; i++) {
                u32 x = s->x + 1u + i;
                if (x < dl || x >= dr || x < X0 || x >= X0 + CD32_W) continue;
                u32 v = ((s->data >> (15u - i)) & 1u) | (((s->datb >> (15u - i)) & 1u) << 1);
                u32 cidx;
                if (attached) {
                    u32 j = x - (o->x + 1u);
                    u32 hi = (j < 16u) ? (((o->data >> (15u - j)) & 1u) | (((o->datb >> (15u - j)) & 1u) << 1)) : 0u;
                    v |= hi << 2;
                    cidx = spr_base + v;
                } else {
                    cidx = spr_base + 4u * (u32)n + v;
                }
                if (v)
                    out[x - X0] = S.line_pal15[cidx & 0xFFu];
            }
        }
    }
}

/* ---- Custom Registers & CIAs ---- */

static u8 cd32_button_bits(void)
{
    /* 7-button CD32 pad shift register (1 = pressed here, inverted on serial line):
       bit 6: Blue (Stop / X = A = 0x01)
       bit 5: Red  (Select / Fire = Z = B = 0x02)
       bit 4: Yellow (C)
       bit 3: Green (Shuffle / Tab = Select = 0x04)
       bit 2: Forward (E = R = 0x0800)
       bit 1: Reverse (Q = L = 0x0400)
       bit 0: Play/Pause (Enter = Start = 0x08) */
    u8 b = 0;
    if (S.pad & 0x01u)   b |= 0x40u;                    /* Blue */
    if (S.pad & 0x02u)   b |= 0x20u;                    /* Red */
    if (S.pad & 0x04u)   b |= 0x08u;                    /* Green */
    if (S.pad & 0x08u)   b |= 0x01u;                    /* Play */
    if (S.pad & 0x0400u) b |= 0x02u;                    /* Reverse */
    if (S.pad & 0x0800u) b |= 0x04u;                    /* Forward */
    return b;
}

static void put_long_mfm(u16 *w, u32 v)
{
    w[0] = (u16)(v >> 16);
    w[1] = (u16)v;
}

static void a1200_build_track(void)
{
    u16 *t = M->disk_track;
    u8  *sync_at = M->disk_sync;
    u32 n = 0, trk = (u32)(S.disk.cyl * 2 + S.disk.side);
    for (u32 i = 0; i < TRACK_WORDS; i++) {
        t[i] = 0;
        sync_at[i] = 0;
    }
    for (u32 sec = 0; sec < 11u; sec++) {
        const u8 *data = (S.disk.adf && trk < 160u && (trk * 11u + sec + 1u) * 512u <= S.disk.size)
                             ? (S.disk.adf + (trk * 11u + sec) * 512u) : 0;
        t[n++] = 0; t[n++] = 0;
        t[n] = 0x4489u; sync_at[n++] = 1;
        t[n] = 0x4489u; sync_at[n++] = 1;
        u32 hdr[5], sum = 0;
        hdr[0] = 0xFF000000u | (trk << 16) | (sec << 8) | (11u - sec);
        for (int i = 1; i < 5; i++) hdr[i] = 0;
        u16 *h = t + n;
        for (int i = 0; i < 5; i++) {
            u32 odd = (hdr[i] >> 1) & 0x55555555u, even = hdr[i] & 0x55555555u;
            int at = i == 0 ? 0 : 4 + (i - 1) * 2, at_even = i == 0 ? 2 : 4 + 8 + (i - 1) * 2;
            put_long_mfm(h + at, odd);
            put_long_mfm(h + at_even, even);
            sum ^= odd ^ even;
        }
        n += 20u;
        put_long_mfm(t + n, (sum >> 1) & 0x55555555u);
        put_long_mfm(t + n + 2u, sum & 0x55555555u);
        n += 4u;
        u32 dsum = 0;
        u16 *d = t + n + 4u;
        for (u32 i = 0; i < 128u; i++) {
            u32 v = data ? ((u32)data[4u * i] << 24 | (u32)data[4u * i + 1u] << 16 |
                            (u32)data[4u * i + 2u] << 8 | data[4u * i + 3u]) : 0u;
            u32 odd = (v >> 1) & 0x55555555u, even = v & 0x55555555u;
            put_long_mfm(d + 2u * i, odd);
            put_long_mfm(d + 256u + 2u * i, even);
            dsum ^= odd ^ even;
        }
        dsum &= 0x55555555u;
        put_long_mfm(t + n, (dsum >> 1) & 0x55555555u);
        put_long_mfm(t + n + 2u, dsum & 0x55555555u);
        n += 4u + 512u;
    }
    u32 prev = 0;
    for (u32 i = 0; i < TRACK_WORDS; i++) {
        if (sync_at[i]) { prev = 1; continue; }
        u32 d = t[i] & 0x5555u;
        u32 clk = ~((d << 1) | (d >> 1) | (prev << 15)) & 0xAAAAu;
        t[i] = (u16)(d | clk);
        prev = d & 1u;
    }
    S.disk.track_cyl = S.disk.cyl;
    S.disk.track_side = S.disk.side;
}

static u32 a1200_disk_pos(s32 t)
{
    return ((S.cycles_hi + (u32)t) / WORD_CYCLES) % TRACK_WORDS;
}

static void a1200_disk_start(u32 len)
{
    if (S.disk.track_cyl != S.disk.cyl || S.disk.track_side != S.disk.side)
        a1200_build_track();
    u32 n = len & 0x3FFFu, at = a1200_disk_pos(S.now_t), wait = 0;
    S.disk.pt = ((u32)R(DSKPTH) << 16) | R(DSKPTL);
    if (!(len & 0x4000u) && S.disk.adf && S.disk.sel) {
        if (S.adkcon & 0x0400u) {
            u16 sync = R(DSKSYNC);
            for (wait = 0; wait < TRACK_WORDS; wait++)
                if (M->disk_track[(at + wait) % TRACK_WORDS] == sync)
                    break;
            if (wait == TRACK_WORDS) {
                S.disk.dma = 1;
                S.disk.end = NEVER;
                return;
            }
            at += wait + 1u;
            raise_irq(0x1000u);
        }
        for (u32 i = 0; i < n; i++, S.disk.pt += 2u)
            CHIPW(S.disk.pt) = M->disk_track[(at + i) % TRACK_WORDS];
    } else {
        S.disk.pt += n * 2u;
    }
    S.disk.dma = 1;
    S.disk.end = S.now_t + (s32)((wait + n) * DISK_TURBO) + 64;
}

static void a1200_drive_control(u32 v, u32 old)
{
    int sel = !(v & 0x08u);
    if (sel && (old & 0x08u))
        S.disk.motor = !(v & 0x80u);
    if (sel && (old & 0x01u) && !(v & 0x01u)) {
        if (v & 0x02u) {
            if (S.disk.cyl > 0) S.disk.cyl--;
        } else if (S.disk.cyl < 83) {
            S.disk.cyl++;
        }
        if (S.disk.adf)
            S.disk.changed = 0;
    }
    S.disk.side = (v & 0x04u) ? 0 : 1;
    S.disk.sel = sel;
}

static u32 custom_read(u32 r, s32 now)
{
    switch (r) {
    case DMACONR: return S.dmacon | (S.blit_busy ? 0x4000u : 0u) | (S.bzero ? 0x2000u : 0u);
    case VPOSR:   return ((u32)S.lof << 15) | 0x2300u | (((u32)now / LINE_CYCLES) >> 8);
    case VHPOSR:  return ((((u32)now / LINE_CYCLES) & 0xFFu) << 8) | ((((u32)now % LINE_CYCLES) >> 2) & 0xFFu);
    case JOY0DAT: return S.is_a1200 ? (((u32)S.mouse_y << 8) | S.mouse_x) : 0u;
    case JOY1DAT: {
        u32 v = 0;
        if (S.pad & 0x80u) v |= 0x0002u;
        if (S.pad & 0x40u) v |= 0x0200u;
        if (((S.pad & 0x20u) != 0) ^ ((v & 2u) != 0))     v |= 0x0001u;
        if (((S.pad & 0x10u) != 0) ^ ((v & 2u) != 0)) v |= 0x0100u;
        return v;
    }
    case POTGOR: {
        u16 p = 0xFF00u;
        if (S.is_a1200) {
            if ((S.mouse_btn & 2u) || (S.pad & 0x0100u)) p &= (u16)~0x0400u;
            if (S.pad & 0x0200u) p &= (u16)~0x4000u;
            return p;
        }
        if (S.pad_shift_mode) {
            u8 btns = cd32_button_bits();
            u8 idx = S.pad_shift_idx;
            int pressed = 0;
            if (idx < 7u) pressed = ((btns >> (6u - idx)) & 1u) != 0;
            else if (idx == 7u) pressed = 0;
            else                pressed = 1;
            if (pressed) p &= (u16)~0x4000u;
        } else {
            if (S.pad & 0x01u) p &= (u16)~0x4000u;
        }
        return p;
    }
    case SERDATR: return 0x3000u;
    case DSKBYTR: {
        if (!S.is_a1200) return 0x8000u;
        if (S.disk.track_cyl != S.disk.cyl || S.disk.track_side != S.disk.side)
            a1200_build_track();
        u32 at = a1200_disk_pos(now), w = M->disk_track[at];
        return 0x8000u | (S.disk.dma ? 0x4000u : 0u) | (w == R(DSKSYNC) ? 0x1000u : 0u) | (w & 0xFFu);
    }
    case CLXDAT:  return 0x8000u;
    case ADKCONR: return S.adkcon;
    case INTENAR: return S.intena;
    case INTREQR: return S.intreq;
    case LISAID:  return 0x00F8u;
    }
    return 0;
}

static void set_clr(u16 *dst, u32 v)
{
    if (v & 0x8000u) *dst |= (u16)(v & 0x7FFFu);
    else             *dst &= (u16)~v;
}

static void paula_refresh_dma(void)
{
    for (int ch = 0; ch < 4; ch++) {
        int on = ((S.dmacon & 0x200u) != 0) && ((S.dmacon & (1u << ch)) != 0);
        if (on && !S.aud[ch].on) {
            S.aud[ch].cur_pt = S.aud[ch].lc;
            S.aud[ch].rem_words = S.aud[ch].len ? S.aud[ch].len : 0xFFFFu;
            S.aud[ch].hi_half = 0;
            S.aud[ch].next_irq = S.now_t + 128;
        }
        if (!on)
            S.aud[ch].next_irq = NEVER;
        S.aud[ch].on = on;
    }
}

static void custom_write(u32 r, u32 v)
{
    v &= 0xFFFFu;
    S.reg[r >> 1] = (u16)v;

    if (r >= COLOR00 && r < COLOR00 + 64u) {
        u32 bank = (R(BPLCON3) >> 13) & 7u;
        u32 idx  = bank * 32u + ((r - COLOR00) >> 1);
        u32 r4 = (v >> 8) & 15u, g4 = (v >> 4) & 15u, b4 = v & 15u;
        if (R(BPLCON3) & 0x0200u) {                     /* LOCT = 1: write low 4 bits of 24-bit color */
            u32 cur = S.aga_rgb24[idx] & 0xF0F0F0u;
            S.aga_rgb24[idx] = cur | (r4 << 16) | (g4 << 8) | b4;
        } else {                                        /* LOCT = 0: write high+low 4 bits (OCS/AGA compat) */
            S.aga_rgb24[idx] = (r4 * 0x110000u) | (g4 * 0x001100u) | (b4 * 0x000011u);
        }
        u16 c15 = rgb24_to_15(S.aga_rgb24[idx]);
        S.aga_pal15[idx] = c15;
        u32 h = ((u32)S.now_t % LINE_CYCLES) >> 2;
        u32 x = 2u * h + 1u;
        if (x <= X0 && S.nchg == 0) {
            S.line_pal15[idx] = c15;
        } else if (S.nchg < 128 && x < X0 + CD32_W) {
            S.chg[S.nchg].x = (u16)x;
            S.chg[S.nchg].idx = (u16)idx;
            S.chg[S.nchg].val15 = c15;
            S.nchg++;
        } else {
            S.line_pal15[idx] = c15;
        }
        return;
    }
    if (r >= SPR0POS && r < COLOR00) {
        struct cd32_sprite *s = &S.spr[(r - SPR0POS) >> 3];
        switch (r & 6u) {
        case 0: s->pos = (u16)v; sprite_decode(s); break;
        case 2: s->ctl = (u16)v; sprite_decode(s); s->armed = 0; break;
        case 4: s->data = (u16)v; s->armed = 1; break;
        case 6: s->datb = (u16)v; break;
        }
        return;
    }
    if (r >= SPR0PTH && r < SPR0POS) {
        struct cd32_sprite *s = &S.spr[(r - SPR0PTH) >> 2];
        s->pt = (r & 2u) ? ((s->pt & 0xFFFF0000u) | (v & 0xFFFEu)) : ((s->pt & 0xFFFFu) | (v << 16));
        return;
    }
    if (r >= BPL1PTH && r < BPL1PTH + 32u) {            /* All 8 AGA bitplane pointers ($0E0..$0FE)! */
        u32 *p = &S.bplpt[(r - BPL1PTH) >> 2];
        *p = (r & 2u) ? ((*p & 0xFFFF0000u) | (v & 0xFFFEu)) : ((*p & 0xFFFFu) | (v << 16));
        return;
    }
    if (r >= AUD0 && r < AUD0 + 0x40u) {
        struct cd32_paula_ch *ac = &S.aud[(r - AUD0) >> 4];
        switch (r & 15u) {
        case 0: ac->lc = (ac->lc & 0x0000FFFFu) | ((v & 0x1Fu) << 16); break;
        case 2: ac->lc = (ac->lc & 0xFFFF0000u) | (v & 0xFFFEu); break;
        case 4: ac->len = (u16)v; break;
        case 6: ac->per = (u16)v; break;
        case 8: ac->vol = (u16)((v & 0x7Fu) > 64u ? 64u : (v & 0x7Fu)); break;
        case 10:
            if (!ac->on)
                ac->next_irq = S.now_t + (s32)((ac->per < 124u ? 124u : ac->per) * 8u);
            break;
        }
        return;
    }

    switch (r) {
    case DSKLEN:
        if (S.is_a1200) {
            if (v & 0x8000u) {
                if ((S.disk.len_was & 0x8000u) && (S.dmacon & 0x210u) == 0x210u)
                    a1200_disk_start(v);
            } else {
                S.disk.dma = 0;
                S.disk.end = NEVER;
            }
            S.disk.len_was = (u16)v;
        }
        break;
    case JOYTEST:
        S.mouse_x = (u8)((S.mouse_x & 3u) | (v & 0xFCu));
        S.mouse_y = (u8)((S.mouse_y & 3u) | ((v >> 8) & 0xFCu));
        break;
    case VPOSW:
        S.lof = (u8)(v >> 15);
        break;
    case POTGO:
        /* CD32 7-button pad latch/clock on OUTRY (b15) / DATRY (b14) / OUTRX (b13) / DATRX (b12) */
        if (!S.is_a1200 && (v & 0x3000u) == 0x3000u) {
            S.pad_shift_mode = 1;
            if ((S.potgo_latch & 0x1000u) && !(v & 0x1000u)) {
                if (S.pad_shift_idx < 10u) S.pad_shift_idx++;
            }
        } else {
            S.pad_shift_mode = 0;
            S.pad_shift_idx = 0;
        }
        S.potgo_latch = (u16)v;
        break;
    case BLTCPTH:     S.bltcpt = (S.bltcpt & 0xFFFFu) | (v << 16); break;
    case BLTCPTH + 2: S.bltcpt = (S.bltcpt & 0xFFFF0000u) | (v & 0xFFFEu); break;
    case BLTBPTH:     S.bltbpt = (S.bltbpt & 0xFFFFu) | (v << 16); break;
    case BLTBPTH + 2: S.bltbpt = (S.bltbpt & 0xFFFF0000u) | (v & 0xFFFEu); break;
    case BLTAPTH:     S.bltapt = (S.bltapt & 0xFFFFu) | (v << 16); break;
    case BLTAPTH + 2: S.bltapt = (S.bltapt & 0xFFFF0000u) | (v & 0xFFFEu); break;
    case BLTDPTH:     S.bltdpt = (S.bltdpt & 0xFFFFu) | (v << 16); break;
    case BLTDPTH + 2: S.bltdpt = (S.bltdpt & 0xFFFF0000u) | (v & 0xFFFEu); break;
    case BLTCON0L:    R(BLTCON0) = (u16)((R(BLTCON0) & 0xFF00u) | (v & 0xFFu)); break;
    case BLTSIZE:     blit_start(v & 0x3Fu, v >> 6); break;
    case BLTSIZH:     blit_start(v & 0x7FFu, R(BLTSIZV) & 0x7FFFu); break;
    case COP1LCH:     S.cop_lc1 = (S.cop_lc1 & 0xFFFFu) | (v << 16); break;
    case COP1LCH + 2: S.cop_lc1 = (S.cop_lc1 & 0xFFFF0000u) | (v & 0xFFFEu); break;
    case COP2LCH:     S.cop_lc2 = (S.cop_lc2 & 0xFFFFu) | (v << 16); break;
    case COP2LCH + 2: S.cop_lc2 = (S.cop_lc2 & 0xFFFF0000u) | (v & 0xFFFEu); break;
    case COPJMP1:     copper_jump(S.cop_lc1, S.now_t); break;
    case COPJMP2:     copper_jump(S.cop_lc2, S.now_t); break;
    case DMACON: {
        u16 old = S.dmacon;
        set_clr(&S.dmacon, v & 0x87FFu);
        if ((S.dmacon & 0x280u) == 0x280u && (old & 0x280u) != 0x280u && S.cop_state && S.cop_t >= NEVER)
            S.cop_t = S.now_t + 4;
        if ((S.dmacon ^ old) & 0x20Fu)
            paula_refresh_dma();
        break;
    }
    case INTENA: set_clr(&S.intena, v); update_ipl(); break;
    case INTREQ:
        set_clr(&S.intreq, v);
        if (S.cia[0].icr & 0x80u) S.intreq |= 0x0008u;
        if (S.cia[1].icr & 0x80u) S.intreq |= 0x2000u;
        update_ipl();
        break;
    case ADKCON: set_clr(&S.adkcon, v); break;
    }
}

/* ---- 8520 CIA Timers & Keyboard Serial Handshake ---- */

static u32 cia_timer_step(u16 *t, u16 latch, u32 n, u8 *cr)
{
    if (n <= *t) {
        *t = (u16)(*t - n);
        return 0;
    }
    n -= (u32)*t + 1u;
    if (*cr & 8u) {
        *t = latch;
        *cr &= (u8)~1u;
        return 1u;
    }
    u32 period = (u32)latch + 1u;
    *t = (u16)(latch - (n % period));
    return 1u + (n / period);
}

static void cia_check_irq(int n)
{
    struct cd32_cia *c = &S.cia[n];
    if ((c->icr & c->mask & 0x1Fu) && !(c->icr & 0x80u)) {
        c->icr |= 0x80u;
        raise_irq(n ? 0x2000u : 0x0008u);
    }
}

static void cia_update(int n, s32 now)
{
    struct cd32_cia *c = &S.cia[n];
    if (now <= c->last)
        return;
    u32 el = (u32)(now - c->last) / 20u, ua = 0;
    c->last += (s32)(el * 20u);
    if (!el)
        return;
    if ((c->cra & 0x21u) == 0x01u) {
        ua = cia_timer_step(&c->ta, c->la, el, &c->cra);
        if (ua) c->icr |= 1u;
    }
    if (c->crb & 1u) {
        u32 in_mode = (c->crb >> 5) & 3u;
        u32 nb = (in_mode == 0u) ? el : (in_mode >= 2u ? ua : 0u);
        if (nb && cia_timer_step(&c->tb, c->lb, nb, &c->crb))
            c->icr |= 2u;
    }
    cia_check_irq(n);
}

static void cia_tod_tick(int n)
{
    struct cd32_cia *c = &S.cia[n];
    if (!c->tod_run)
        return;
    c->tod = (c->tod + 1u) & 0xFFFFFFu;
    if (c->tod == c->alarm) {
        c->icr |= 4u;
        cia_check_irq(n);
    }
}

static void a1200_key_push(u32 code)
{
    int next = (S.kq_tail + 1) & 63;
    if (next != S.kq_head) {
        S.kq[S.kq_tail] = (u8)code;
        S.kq_tail = next;
    }
}

static void a1200_keyboard_poll(s32 now)
{
    if (S.kb_wait && now - S.kb_time > 2000000)
        S.kb_wait = 0;
    if (S.kb_wait || S.kq_head == S.kq_tail || now < S.kb_time)
        return;
    u32 code = S.kq[S.kq_head];
    S.kq_head = (S.kq_head + 1) & 63;
    S.cia[0].sdr = (u8)~((code << 1) | (code >> 7));
    S.cia[0].icr |= 8u;
    cia_check_irq(0);
    S.kb_wait = 1;
    S.kb_time = now;
}

static u8 cia_read(int n, u32 r)
{
    struct cd32_cia *c = &S.cia[n];
    cia_update(n, m.clock);
    switch (r & 15u) {
    case 0: {
        if (n == 0) {
            u8 in = 0xFFu;
            if (S.is_a1200) {
                if (S.pad & 0x01u) in &= (u8)~0x80u;
                if ((S.pad & 0x02u) || (S.mouse_btn & 1u)) in &= (u8)~0x40u;
                if (S.disk.sel) {
                    if (S.disk.changed || !S.disk.adf) in &= (u8)~0x04u;
                    in &= (u8)~0x08u;
                    if (S.disk.cyl == 0) in &= (u8)~0x10u;
                    if (S.disk.adf) in &= (u8)~0x20u;
                }
            } else {
                if (S.pad & 0x03u) in &= (u8)~0x80u;
            }
            return (u8)((c->pra & c->ddra) | (in & ~c->ddra));
        }
        return (u8)((c->pra & c->ddra) | (~c->ddra & 0xFFu));
    }
    case 1:  return (u8)((c->prb & c->ddrb) | (~c->ddrb & 0xFFu));
    case 2:  return c->ddra;
    case 3:  return c->ddrb;
    case 4:  return (u8)(c->ta & 0xFFu);
    case 5:  return (u8)(c->ta >> 8);
    case 6:  return (u8)(c->tb & 0xFFu);
    case 7:  return (u8)(c->tb >> 8);
    case 8:  { u8 v = (u8)((c->latched ? c->latch : c->tod) & 0xFFu); c->latched = 0; return v; }
    case 9:  return (u8)(((c->latched ? c->latch : c->tod) >> 8) & 0xFFu);
    case 10: c->latch = c->tod; c->latched = 1; return (u8)((c->latch >> 16) & 0xFFu);
    case 12: return c->sdr;
    case 13: { u8 ic = c->icr; c->icr = 0; return ic; }
    case 14: return c->cra;
    case 15: return c->crb;
    }
    return 0xFFu;
}

static void cia_write(int n, u32 r, u8 v)
{
    struct cd32_cia *c = &S.cia[n];
    cia_update(n, m.clock);
    switch (r & 15u) {
    case 0:
        c->pra = v;
        if (n == 0) {
            u8 ov = !(c->ddra & 1u) || (c->pra & 1u);
            if (ov != S.overlay) { S.overlay = ov; cd32_map_memory(); }
            if (!S.is_a1200 && (c->ddra & 0x80u)) {
                if (!(v & 0x80u) && S.pad_shift_idx < 10u) S.pad_shift_idx++;
            }
        }
        break;
    case 1: {
        u32 old = c->prb | (u8)~c->ddrb;
        c->prb = v;
        if (n == 1 && S.is_a1200)
            a1200_drive_control(c->prb | (u8)~c->ddrb, old);
        break;
    }
    case 2:
        c->ddra = v;
        if (n == 0) {
            u8 ov = !(c->ddra & 1u) || (c->pra & 1u);
            if (ov != S.overlay) { S.overlay = ov; cd32_map_memory(); }
        }
        break;
    case 3: {
        u32 old = c->prb | (u8)~c->ddrb;
        c->ddrb = v;
        if (n == 1 && S.is_a1200)
            a1200_drive_control(c->prb | (u8)~c->ddrb, old);
        break;
    }
    case 4: c->la = (u16)((c->la & 0xFF00u) | v); break;
    case 5:
        c->la = (u16)((c->la & 0xFFu) | ((u16)v << 8));
        if (!(c->cra & 1u)) c->ta = c->la;
        if (c->cra & 8u) { c->ta = c->la; c->cra |= 1u; }
        break;
    case 6: c->lb = (u16)((c->lb & 0xFF00u) | v); break;
    case 7:
        c->lb = (u16)((c->lb & 0xFFu) | ((u16)v << 8));
        if (!(c->crb & 1u)) c->tb = c->lb;
        if (c->crb & 8u) { c->tb = c->lb; c->crb |= 1u; }
        break;
    case 8: case 9: case 10: {
        u32 sh = ((r & 15u) - 8u) * 8u;
        u32 *tp = (c->crb & 0x80u) ? &c->alarm : &c->tod;
        *tp = (*tp & ~(0xFFu << sh)) | ((u32)v << sh);
        if (!(c->crb & 0x80u))
            c->tod_run = ((r & 15u) == 8u);
        break;
    }
    case 12: c->sdr = v; break;
    case 13:
        if (v & 0x80u) c->mask |= (v & 0x1Fu);
        else           c->mask &= (u8)~v;
        cia_check_irq(n);
        break;
    case 14:
        if (n == 0 && (c->cra & 0x40u) && !(v & 0x40u) && S.kb_wait) {
            S.kb_wait = 0;
            S.kb_time = m.clock + 800;
        }
        if (v & 0x10u) c->ta = c->la;
        c->cra = (u8)(v & ~0x10u);
        break;
    case 15:
        if (v & 0x10u) c->tb = c->lb;
        c->crb = (u8)(v & ~0x10u);
        break;
    }
}

static void a1200_hle_doio(void)
{
    u32 ior = m.r[9] & 0xFFFFFFu;
    u16 cmd = CHIPW(ior + 28u);
    if ((cmd == 2u || cmd == 9u) && S.disk.adf) {
        u32 len = ((u32)CHIPW(ior + 36u) << 16) | CHIPW(ior + 38u);
        u32 dst = ((u32)CHIPW(ior + 40u) << 16) | CHIPW(ior + 42u);
        u32 off = ((u32)CHIPW(ior + 44u) << 16) | CHIPW(ior + 46u);
        if (cmd == 2u) {
            for (u32 i = 0; i < len && dst + i < 0x200000u; i++) {
                u8 b = (off + i < S.disk.size) ? S.disk.adf[off + i] : 0u;
                u32 a = dst + i;
                if (a & 1u) CHIPW(a & ~1u) = (u16)((CHIPW(a & ~1u) & 0xFF00u) | b);
                else        CHIPW(a)       = (u16)((CHIPW(a) & 0x00FFu) | ((u16)b << 8));
            }
            CHIPW(ior + 32u) = (u16)(len >> 16);
            CHIPW(ior + 34u) = (u16)len;
        }
    }
    CHIPW(ior + 30u) = (u16)(CHIPW(ior + 30u) & 0xFF00u);
    m.r[0] = 0;
}

static u32 io_read(u32 a, int size)
{
    if (!S.is_a1200) {
        if ((a & 0xFFFF00u) == 0xB80000u) {
            u32 off = a & 0xFFu;
            if (off >= 0x80u) {
                u8 b = M->nvram[off & 0x7Fu];
                return (size == 1) ? b : ((u32)b << 8) | M->nvram[(off + 1u) & 0x7Fu];
            }
            u16 w = (u16)akiko_read16(off & ~1u);
            return (size == 2) ? w : ((a & 1u) ? (w & 0xFFu) : (w >> 8));
        }
        if (a >= 0xB80400u && a < 0xB80800u) {
            u32 off = a - 0xB80400u;
            if (size == 1) return M->nvram[off & 0x3FFu];
            return ((u32)M->nvram[off & 0x3FFu] << 8) | M->nvram[(off + 1u) & 0x3FFu];
        }
    }
    if ((a & 0xFF0000u) == 0xBF0000u) {
        u32 r = (a >> 8) & 15u;
        u32 hi = (a & 0x2000u) ? 0xFFu : cia_read(1, r);
        u32 lo = (a & 0x1000u) ? 0xFFu : cia_read(0, r);
        return (size == 2) ? ((hi << 8) | lo) : ((a & 1u) ? lo : hi);
    }
    if (S.is_a1200) {
        if ((a & 0xFF0000u) == 0xDA0000u)
            return (a < 0xDA8000u) ? (size == 2 ? 0xFFFFu : 0xFFu) : 0u;
        if ((a & 0xFFFF00u) == 0xDE1000u) {
            u32 bit = (S.gayle_id & 0x80u) ? 0x80u : 0x00u;
            S.gayle_id <<= 1;
            return (size == 2) ? (bit << 8) : ((a & 1u) ? 0u : bit);
        }
        if (a >= 0xDC0000u && a < 0xDF0000u)
            return 0u;
        if (a >= 0xE80000u && a < 0xF80000u)
            return 0u;
    }
    if (a >= (S.is_a1200 ? 0xDF0000u : 0xC80000u) && a < 0xE00000u) {
        u16 w = (u16)custom_read(a & 0x1FEu, m.clock);
        return (size == 2) ? w : ((a & 1u) ? (w & 0xFFu) : (w >> 8));
    }
    return 0;
}

static void io_write(u32 a, u32 v, int size)
{
    if (!S.is_a1200) {
        if ((a & 0xFFFF00u) == 0xB80000u) {
            u32 off = a & 0xFFu;
            u16 w = (size == 2) ? (u16)v : ((a & 1u) ? (u16)v : (u16)(v << 8));
            akiko_write16(off & ~1u, w);
            return;
        }
        if (a >= 0xB80400u && a < 0xB80800u) {
            u32 off = a - 0xB80400u;
            if (size == 1) {
                if (M->nvram[off & 0x3FFu] != (u8)v) { M->nvram[off & 0x3FFu] = (u8)v; S.nvram_dirty = 1; }
            } else {
                u8 hi = (u8)(v >> 8), lo = (u8)v;
                if (M->nvram[off & 0x3FFu] != hi || M->nvram[(off + 1u) & 0x3FFu] != lo) {
                    M->nvram[off & 0x3FFu] = hi;
                    M->nvram[(off + 1u) & 0x3FFu] = lo;
                    S.nvram_dirty = 1;
                }
            }
            return;
        }
    } else {
        if (a == 0xF7FFFEu) {
            a1200_hle_doio();
            return;
        }
        if ((a & 0xFFFF00u) == 0xDE1000u) {
            S.gayle_id = 0xD0u;
            return;
        }
        if (a >= 0xDA0000u && a < 0xDF0000u)
            return;
    }
    if ((a & 0xFF0000u) == 0xBF0000u) {
        u32 r = (a >> 8) & 15u;
        if ((size == 2 || !(a & 1u)) && !(a & 0x2000u)) cia_write(1, r, (u8)(size == 2 ? (v >> 8) : v));
        if ((size == 2 ||  (a & 1u)) && !(a & 0x1000u)) cia_write(0, r, (u8)(v & 0xFFu));
        return;
    }
    if (a >= (S.is_a1200 ? 0xDF0000u : 0xC80000u) && a < 0xE00000u) {
        S.now_t = m.clock;
        custom_write(a & 0x1FEu, (size == 2) ? v : ((v & 0xFFu) * 0x101u));
    }
}

static void cpu_reset_line(void)
{
    S.overlay = 1;
    cd32_map_memory();
}

/* ---- 48 kHz 4-Channel Paula DMA + Redbook CD-DA Mixer ---- */

static void step_audio_frame(void)
{
    if (!S.sample_rate) return;
    /* 49.9201 Hz PAL -> sample_rate * 1000 / 49920 samples per frame */
    u32 num = S.sample_rate * 1000u + S.snd_frac;
    u32 n_samp = num / 49920u;
    S.snd_frac = num % 49920u;

    /* Paula master clock = 3,546,895 Hz; period P outputs 1 byte every P ticks */
    for (u32 i = 0; i < n_samp; i++) {
        s32 mix = 0;
        for (int ch = 0; ch < 4; ch++) {
            struct cd32_paula_ch *ac = &S.aud[ch];
            if (!ac->on) continue;
            u32 per = ac->per < 114u ? 114u : ac->per;
            u32 rate_hz = 3546895u / per;
            ac->ph_acc += (rate_hz << 12) / S.sample_rate;
            while (ac->ph_acc >= 0x1000u) {
                ac->ph_acc -= 0x1000u;
                u16 w = CHIPW(ac->cur_pt);
                if (!ac->hi_half) {
                    ac->cur_smp = (s8)(w >> 8);
                    ac->hi_half = 1;
                } else {
                    ac->cur_smp = (s8)(w & 0xFFu);
                    ac->hi_half = 0;
                    ac->cur_pt = (ac->cur_pt + 2u) & CHIP_MASK;
                    if (--ac->rem_words == 0u) {
                        ac->cur_pt = ac->lc;
                        ac->rem_words = ac->len ? ac->len : 0xFFFFu;
                    }
                }
            }
            mix += (s32)ac->cur_smp * (s32)ac->vol;     /* [-8192 .. +8128] per ch */
        }

        /* Mix streamed 44.1 kHz Redbook CD-DA if playing! */
        if (S.cdda_playing && S.cd && S.cd->read_2352) {
            S.cdda_frac += (44100u << 12) / S.sample_rate;
            while (S.cdda_frac >= 0x1000u) {
                S.cdda_frac -= 0x1000u;
                S.cdda_pos_bytes += 4u;
                if (S.cdda_pos_bytes >= 2352u) {
                    S.cdda_pos_bytes = 0;
                    if (S.cdda_lba >= S.cdda_end_lba) {
                        if (S.cdda_loop)
                            S.cdda_lba = S.cd->tracks[S.cd->last_track].lba;
                        else
                            S.cdda_playing = 0;
                    }
                    if (S.cdda_playing)
                        (void)S.cd->read_2352(S.cdda_lba++, M->cdda_buf);
                }
            }
            if (S.cdda_playing && S.cdda_pos_bytes + 3u < 2352u) {
                const u8 *p = M->cdda_buf + S.cdda_pos_bytes;
                s16 l = (s16)((u16)p[0] | ((u16)p[1] << 8));
                s16 r = (s16)((u16)p[2] | ((u16)p[3] << 8));
                mix += ((s32)l + (s32)r) >> 2;
            }
        }

        if (mix > 32767) mix = 32767;
        else if (mix < -32768) mix = -32768;
        M->snd_ring[S.snd_head & (SND_RING - 1u)] = (s16)mix;
        S.snd_head++;
        if (S.snd_head - S.snd_tail > SND_RING)
            S.snd_tail = S.snd_head - SND_RING;
    }
}

/* ---- Clean-Room ISO-9660 + AmigaDOS HUNK_HEADER Boot Loader ---- */

static u32 be32_at(const u8 *p)
{
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

static u32 le32_at(const u8 *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

struct iso_reader {
    u32 lba, rem, pos;
    u8  sec[2048];
};

static int iso_read_bytes(struct iso_reader *r, u8 *dst, u32 n)
{
    while (n > 0u) {
        if (r->rem == 0u) return 0;
        if (r->pos >= 2048u) {
            if (!S.cd->read_2048 || S.cd->read_2048(r->lba++, r->sec) < 0)
                return 0;
            r->pos = 0;
        }
        u32 avail = 2048u - r->pos;
        if (avail > r->rem) avail = r->rem;
        if (avail > n)      avail = n;
        for (u32 i = 0; i < avail; i++)
            *dst++ = r->sec[r->pos + i];
        r->pos += avail;
        r->rem -= avail;
        n -= avail;
    }
    return 1;
}

static int iso_read_u32be(struct iso_reader *r, u32 *out)
{
    u8 b[4];
    if (!iso_read_bytes(r, b, 4)) return 0;
    *out = be32_at(b);
    return 1;
}

static u32 load_amiga_hunk_exe(u32 file_lba, u32 file_size)
{
    struct iso_reader rd;
    rd.lba = file_lba;
    rd.rem = file_size;
    rd.pos = 2048u;

    u32 magic = 0;
    if (!iso_read_u32be(&rd, &magic) || magic != 0x000003F3u) /* HUNK_HEADER */
        return 0;

    /* Skip resident library names until 0 */
    for (;;) {
        u32 slen = 0;
        if (!iso_read_u32be(&rd, &slen)) return 0;
        if (slen == 0u) break;
        u8 tmp[4];
        for (u32 i = 0; i < slen; i++)
            if (!iso_read_bytes(&rd, tmp, 4)) return 0;
    }

    u32 num_hunks = 0, first_h = 0, last_h = 0;
    if (!iso_read_u32be(&rd, &num_hunks) || !iso_read_u32be(&rd, &first_h) || !iso_read_u32be(&rd, &last_h))
        return 0;
    if (num_hunks == 0u || num_hunks > 64u)
        return 0;

    u32 hunk_base[64];
    u32 alloc_at = 0x010000u;                           /* Load clean above $000000..$00FFFF system/stack */
    for (u32 h = 0; h < num_hunks; h++) {
        u32 hsz_lw = 0;
        if (!iso_read_u32be(&rd, &hsz_lw)) return 0;
        u32 bytes = (hsz_lw & 0x3FFFFFFFu) * 4u;
        hunk_base[h] = alloc_at;
        for (u32 z = 0; z < bytes && alloc_at + z < 0x1F0000u; z += 2u)
            CHIPW(alloc_at + z) = 0;
        alloc_at = (alloc_at + bytes + 15u) & ~15u;
    }

    u32 cur_h = 0;
    while (cur_h < num_hunks && rd.rem >= 4u) {
        u32 htype = 0;
        if (!iso_read_u32be(&rd, &htype)) break;
        htype &= 0x3FFFFFFFu;
        if (htype == 0x3E9u || htype == 0x3EAu) {       /* HUNK_CODE / HUNK_DATA */
            u32 n_lw = 0;
            if (!iso_read_u32be(&rd, &n_lw)) break;
            u32 dst = hunk_base[cur_h];
            for (u32 i = 0; i < n_lw; i++) {
                u8 b[4];
                if (!iso_read_bytes(&rd, b, 4)) break;
                CHIPW(dst)      = (u16)(((u16)b[0] << 8) | b[1]);
                CHIPW(dst + 2u) = (u16)(((u16)b[2] << 8) | b[3]);
                dst += 4u;
            }
        } else if (htype == 0x3EBu) {                   /* HUNK_BSS */
            u32 n_lw = 0;
            (void)iso_read_u32be(&rd, &n_lw);
        } else if (htype == 0x3ECu) {                   /* HUNK_RELOC32 */
            for (;;) {
                u32 n_off = 0, target_h = 0;
                if (!iso_read_u32be(&rd, &n_off)) break;
                if (n_off == 0u) break;
                if (!iso_read_u32be(&rd, &target_h) || target_h >= num_hunks) break;
                u32 add = hunk_base[target_h];
                for (u32 i = 0; i < n_off; i++) {
                    u32 off = 0;
                    if (!iso_read_u32be(&rd, &off)) break;
                    u32 p = hunk_base[cur_h] + off;
                    u32 val = ((u32)CHIPW(p) << 16) | CHIPW(p + 2u);
                    val += add;
                    CHIPW(p)      = (u16)(val >> 16);
                    CHIPW(p + 2u) = (u16)val;
                }
            }
        } else if (htype == 0x3F2u) {                   /* HUNK_END */
            cur_h++;
        } else if (htype == 0x3F0u) {                   /* HUNK_SYMBOL */
            for (;;) {
                u32 n_lw = 0;
                if (!iso_read_u32be(&rd, &n_lw) || n_lw == 0u) break;
                u8 tmp[4];
                for (u32 i = 0; i < n_lw + 1u; i++)
                    (void)iso_read_bytes(&rd, tmp, 4);
            }
        }
    }
    return hunk_base[0];
}

static void build_cleanroom_cd32_boot(void)
{
    /* Populate minimal Kickstart 3.1 ($F80000):
       - Disables CIA-A ROM overlay ($BFE001), sets SP=$001FFFE0, SR=$2000
       - Installs default RTE for all 68000 exception/interrupt vectors in Chip RAM ($00..$FF)
       - Installs minimal ExecBase at $00001000 ($0004 = $00001000) where OpenLibrary/OldOpenLibrary/AllocMem/
         Supervisor/Forbid/Permit/WaitTOF return clean handles so AmigaDOS HUNK executables start immediately!
       - Scans ISO-9660 Root Directory (PVD at LBA 16) for first Amiga HUNK_HEADER ($000003F3) executable,
         relocates it into 2 MB Chip RAM, and jumps directly to its HUNK_CODE entry! */
    cd32_zero(M->kick, sizeof(M->kick));
    cd32_zero(M->ext, sizeof(M->ext));
    S.overlay = 0;

    /* Default exception vectors $08..$FC -> $F80100 (RTE = $4E73) */
    M->kick[0x0100 >> 1] = 0x4E73u;                     /* RTE */
    M->kick[0x0102 >> 1] = 0x7000u;                     /* MOVEQ #0,D0 */
    M->kick[0x0104 >> 1] = 0x4E75u;                     /* RTS */

    for (u32 v = 2; v < 64; v++) {
        CHIPW(v * 4u)      = 0x00F8u;
        CHIPW(v * 4u + 2u) = 0x0100u;
    }

    /* Minimal ExecBase at $00001000 ($4 -> $00001000): all negative LVO slots -6..-1020 = RTS ($4E75)! */
    CHIPW(0x0004) = 0x0000u; CHIPW(0x0006) = 0x1000u;
    for (u32 off = 0x0800u; off < 0x1000u; off += 6u) {
        CHIPW(off)      = 0x7001u;                      /* MOVEQ #1,D0 (non-null base / success) */
        CHIPW(off + 2u) = 0x4E75u;                      /* RTS */
        CHIPW(off + 4u) = 0x4E71u;
    }
    /* AllocMem (-198 = $1000 - 198 = $0F3A): bumps free Chip RAM pointer at $00001040 ($080000..$1E0000)! */
    CHIPW(0x1040) = 0x0008u; CHIPW(0x1042) = 0x0000u;
    u16 alloc_stub[] = {
        0x2238, 0x1040,                                 /* MOVE.L $1040.W,D1 */
        0x2401,                                         /* MOVE.L D1,D2 */
        0xD480,                                         /* ADD.L D0,D2 */
        0x5082, 0x0282, 0xFFFF, 0xFFF8,                 /* ADDQ.L #8,D2; ANDI.L #-8,D2 */
        0x21C2, 0x1040,                                 /* MOVE.L D2,$1040.W */
        0x2001,                                         /* MOVE.L D1,D0 */
        0x4E75                                          /* RTS */
    };
    for (u32 i = 0; i < sizeof(alloc_stub) / 2u; i++)
        M->kick[(0x0200 >> 1) + i] = alloc_stub[i];
    CHIPW(0x1000 - 198) = 0x4EF9u; CHIPW(0x1000 - 196) = 0x00F8u; CHIPW(0x1000 - 194) = 0x0200u;
    CHIPW(0x1000 - 684) = 0x4EF9u; CHIPW(0x1000 - 682) = 0x00F8u; CHIPW(0x1000 - 680) = 0x0200u; /* AllocVec */

    /* Locate & load bootable Amiga HUNK executable from ISO-9660 root (or C/ directory) */
    u32 entry = 0;
    if (S.cd && S.cd->read_2048 && S.cd->read_2048(16u, M->sec_buf) == 0 &&
        M->sec_buf[1] == 'C' && M->sec_buf[2] == 'D' && M->sec_buf[3] == '0') {
        u32 root_lba  = le32_at(M->sec_buf + 156 + 2);
        u32 root_size = le32_at(M->sec_buf + 156 + 10);
        u32 secs = (root_size + 2047u) >> 11;
        if (secs > 8u) secs = 8u;
        u8 dir_sec[2048];
        for (u32 s = 0; s < secs && !entry; s++) {
            if (S.cd->read_2048(root_lba + s, dir_sec) < 0) break;
            u32 pos = 0;
            while (pos + 34u <= 2048u) {
                u8 rlen = dir_sec[pos];
                if (!rlen) break;
                u8 flags = dir_sec[pos + 25];
                u32 flba = le32_at(dir_sec + pos + 2);
                u32 fsz  = le32_at(dir_sec + pos + 10);
                if (!(flags & 2u) && fsz >= 32u && fsz <= 0x1A0000u) {
                    u8 head4[2048];
                    if (S.cd->read_2048(flba, head4) == 0 && be32_at(head4) == 0x000003F3u) {
                        entry = load_amiga_hunk_exe(flba, fsz);
                        if (entry) break;
                    }
                }
                pos += rlen;
            }
        }
    }

    if (!entry)
        entry = 0xF80080u;

    /* Reset vectors at $F80000 & $000000: SP = $001FFFE0, PC = $F80040 -> JMP entry */
    M->kick[0] = 0x001Fu; M->kick[1] = 0xFFE0u;
    M->kick[2] = 0x00F8u; M->kick[3] = 0x0040u;
    CHIPW(0x0000) = 0x001Fu; CHIPW(0x0002) = 0xFFE0u;
    CHIPW(0x0004) = 0x0000u; CHIPW(0x0006) = 0x1000u;

    /* $F80040: set DIWSTRT=$2C81, DIWSTOP=$2CC1, DDFSTRT=$0038, DDFSTOP=$00D0, DMACON=$83E0, JMP entry */
    u16 boot_stub[] = {
        0x33FC, 0x2C81, 0x00DF, 0xF08E,                 /* MOVE.W #$2C81,$DFF08E (DIWSTRT) */
        0x33FC, 0x2CC1, 0x00DF, 0xF090,                 /* MOVE.W #$2CC1,$DFF090 (DIWSTOP) */
        0x33FC, 0x0038, 0x00DF, 0xF092,                 /* MOVE.W #$0038,$DFF092 (DDFSTRT) */
        0x33FC, 0x00D0, 0x00DF, 0xF094,                 /* MOVE.W #$00D0,$DFF094 (DDFSTOP) */
        0x4EF9, (u16)(entry >> 16), (u16)entry          /* JMP entry */
    };
    for (u32 i = 0; i < sizeof(boot_stub) / 2u; i++)
        M->kick[(0x0040 >> 1) + i] = boot_stub[i];
    /* Fallback idle loop at $F80080 */
    M->kick[0x0080 >> 1] = 0x60FEu;
}

static u32 load_adf_hunk_file(const u8 *adf, u32 adf_sz, u32 fhdr_sec)
{
    /* Read an AmigaDOS OFS or FFS file from its file header block (fhdr_sec) and relocate HUNK_HEADER */
    if ((fhdr_sec + 1u) * 512u > adf_sz) return 0;
    const u8 *fh = adf + fhdr_sec * 512u;
    if (be32_at(fh) != 2u || be32_at(fh + 508u) != 0xFFFFFFFDu) return 0;
    u32 byte_size = be32_at(fh + 324u);
    if (byte_size < 32u || byte_size > 0x160000u) return 0;
    int is_ffs = (adf[3] & 1u) != 0;

    /* Unpack file bytes into temporary upper Chip RAM ($1A0000..$1FFFFF) or $080000 */
    u32 staging = 0x090000u;
    u32 rem = byte_size, out_pos = 0;
    if (is_ffs) {
        u32 cur_hdr = fhdr_sec;
        while (cur_hdr && (cur_hdr + 1u) * 512u <= adf_sz && rem > 0u) {
            const u8 *hb = adf + cur_hdr * 512u;
            u32 high_seq = be32_at(hb + 8u);
            if (high_seq > 72u) high_seq = 72u;
            for (u32 i = 0; i < high_seq && rem > 0u; i++) {
                u32 dsec = be32_at(hb + 308u - i * 4u);
                if (!dsec || (dsec + 1u) * 512u > adf_sz) { rem = 0; break; }
                u32 take = rem < 512u ? rem : 512u;
                const u8 *sp = adf + dsec * 512u;
                for (u32 k = 0; k < take && staging + out_pos < 0x1F8000u; k++, out_pos++) {
                    u32 a = staging + out_pos;
                    if (a & 1u) CHIPW(a & ~1u) = (u16)((CHIPW(a & ~1u) & 0xFF00u) | sp[k]);
                    else        CHIPW(a)       = (u16)((CHIPW(a) & 0x00FFu) | ((u16)sp[k] << 8));
                }
                rem -= take;
            }
            cur_hdr = be32_at(hb + 504u);               /* extension block */
        }
    } else {
        u32 dsec = be32_at(fh + 16u);                   /* first_data */
        u32 guard = 0;
        while (dsec && (dsec + 1u) * 512u <= adf_sz && rem > 0u && guard++ < 2000u) {
            const u8 *db = adf + dsec * 512u;
            u32 dsz = be32_at(db + 12u);
            if (dsz > 488u) dsz = 488u;
            if (dsz > rem) dsz = rem;
            for (u32 k = 0; k < dsz && staging + out_pos < 0x1F8000u; k++, out_pos++) {
                u32 a = staging + out_pos;
                if (a & 1u) CHIPW(a & ~1u) = (u16)((CHIPW(a & ~1u) & 0xFF00u) | db[24u + k]);
                else        CHIPW(a)       = (u16)((CHIPW(a) & 0x00FFu) | ((u16)db[24u + k] << 8));
            }
            rem -= dsz;
            dsec = be32_at(db + 16u);                   /* next_data */
        }
    }
    if (out_pos < 32u) return 0;

    /* Helper to read big-endian u32 from staged Chip RAM */
    #define STG_U32(off) ((((u32)CHIPW(staging + (off)) << 16) | CHIPW(staging + (off) + 2u)))
    if (STG_U32(0) != 0x000003F3u)
        return 0;
    u32 pos = 4u;
    while (pos + 4u <= out_pos) {
        u32 slen = STG_U32(pos); pos += 4u;
        if (!slen) break;
        pos += slen * 4u;
    }
    if (pos + 12u > out_pos)
        return 0;
    u32 num_hunks = STG_U32(pos); pos += 12u;
    if (!num_hunks || num_hunks > 64u)
        return 0;
    u32 hunk_base[64], alloc_at = 0x010000u;
    for (u32 h = 0; h < num_hunks && pos + 4u <= out_pos; h++) {
        u32 bytes = (STG_U32(pos) & 0x3FFFFFFFu) * 4u; pos += 4u;
        hunk_base[h] = alloc_at;
        for (u32 z = 0; z < bytes && alloc_at + z < staging; z += 2u)
            CHIPW(alloc_at + z) = 0;
        alloc_at = (alloc_at + bytes + 15u) & ~15u;
    }
    u32 cur_h = 0;
    while (cur_h < num_hunks && pos + 4u <= out_pos) {
        u32 htype = STG_U32(pos) & 0x3FFFFFFFu; pos += 4u;
        if (htype == 0x3E9u || htype == 0x3EAu) {
            u32 n_lw = STG_U32(pos); pos += 4u;
            u32 dst = hunk_base[cur_h];
            for (u32 i = 0; i < n_lw && pos + 4u <= out_pos; i++, pos += 4u, dst += 4u) {
                CHIPW(dst)      = CHIPW(staging + pos);
                CHIPW(dst + 2u) = CHIPW(staging + pos + 2u);
            }
        } else if (htype == 0x3EBu) {
            pos += 4u;
        } else if (htype == 0x3ECu) {
            while (pos + 4u <= out_pos) {
                u32 n_off = STG_U32(pos); pos += 4u;
                if (!n_off) break;
                u32 th = STG_U32(pos); pos += 4u;
                if (th >= num_hunks) break;
                u32 add = hunk_base[th];
                for (u32 i = 0; i < n_off && pos + 4u <= out_pos; i++, pos += 4u) {
                    u32 off = STG_U32(pos);
                    u32 p = hunk_base[cur_h] + off;
                    u32 val = (((u32)CHIPW(p) << 16) | CHIPW(p + 2u)) + add;
                    CHIPW(p) = (u16)(val >> 16);
                    CHIPW(p + 2u) = (u16)val;
                }
            }
        } else if (htype == 0x3F2u) {
            cur_h++;
        } else if (htype == 0x3F0u) {
            while (pos + 4u <= out_pos) {
                u32 n_lw = STG_U32(pos); pos += 4u;
                if (!n_lw) break;
                pos += (n_lw + 1u) * 4u;
            }
        }
    }
    #undef STG_U32
    return hunk_base[0];
}

static void build_cleanroom_a1200_boot(void)
{
    cd32_zero(M->kick, sizeof(M->kick));
    cd32_zero(M->ext, sizeof(M->ext));
    S.overlay = 0;

    M->kick[0x0100 >> 1] = 0x4E73u;                     /* RTE */
    M->kick[0x0102 >> 1] = 0x7000u;                     /* MOVEQ #0,D0 */
    M->kick[0x0104 >> 1] = 0x4E75u;                     /* RTS */
    for (u32 v = 2; v < 64; v++) {
        CHIPW(v * 4u)      = 0x00F8u;
        CHIPW(v * 4u + 2u) = 0x0100u;
    }

    /* ExecBase at $00001000 ($4 -> $00001000, AttnFlags +296 = $0003 for 68EC020) */
    CHIPW(0x0004) = 0x0000u; CHIPW(0x0006) = 0x1000u;
    CHIPW(0x1000 + 296) = 0x0003u;
    for (u32 off = 0x0800u; off < 0x1000u; off += 6u) {
        CHIPW(off)      = 0x7001u;
        CHIPW(off + 2u) = 0x4E75u;
        CHIPW(off + 4u) = 0x4E71u;
    }
    CHIPW(0x1040) = 0x000Au; CHIPW(0x1042) = 0x0000u;
    u16 alloc_stub[] = {
        0x2238, 0x1040, 0x2401, 0xD480,
        0x5082, 0x0282, 0xFFFF, 0xFFF8,
        0x21C2, 0x1040, 0x2001, 0x4E75
    };
    for (u32 i = 0; i < sizeof(alloc_stub) / 2u; i++)
        M->kick[(0x0200 >> 1) + i] = alloc_stub[i];
    CHIPW(0x1000 - 198) = 0x4EF9u; CHIPW(0x1000 - 196) = 0x00F8u; CHIPW(0x1000 - 194) = 0x0200u;
    CHIPW(0x1000 - 684) = 0x4EF9u; CHIPW(0x1000 - 682) = 0x00F8u; CHIPW(0x1000 - 680) = 0x0200u;

    /* HLE DoIO (-456) & SendIO (-462) -> $F80300: MOVE.W D0,$00F7FFFE; RTS */
    M->kick[0x0300 >> 1] = 0x33C0u; M->kick[0x0302 >> 1] = 0x00F7u; M->kick[0x0304 >> 1] = 0xFFFEu;
    M->kick[0x0306 >> 1] = 0x4E75u;
    CHIPW(0x1000 - 456) = 0x4EF9u; CHIPW(0x1000 - 454) = 0x00F8u; CHIPW(0x1000 - 452) = 0x0300u;
    CHIPW(0x1000 - 462) = 0x4EF9u; CHIPW(0x1000 - 460) = 0x00F8u; CHIPW(0x1000 - 458) = 0x0300u;
    /* FindResident (-96) -> 0 so standard AmigaDOS bootblocks return or we boot HUNK directly */
    CHIPW(0x1000 - 96)  = 0x7000u; CHIPW(0x1000 - 94)  = 0x4E75u;

    u32 entry = 0;
    if (S.disk.adf && S.disk.size >= 901120u) {
        /* 1. Try scanning OFS/FFS Root Block (sector 880) & subdirectories for a HUNK_HEADER executable */
        const u8 *root = S.disk.adf + 880u * 512u;
        if (be32_at(root) == 2u && be32_at(root + 508u) == 1u) {
            for (u32 h = 0; h < 72u && !entry; h++) {
                u32 sec = be32_at(root + 24u + h * 4u);
                int chain = 0;
                while (sec && (sec + 1u) * 512u <= S.disk.size && chain++ < 32 && !entry) {
                    const u8 *blk = S.disk.adf + sec * 512u;
                    u32 sec_type = be32_at(blk + 508u);
                    if (sec_type == 0xFFFFFFFDu) {
                        entry = load_adf_hunk_file(S.disk.adf, S.disk.size, sec);
                    } else if (sec_type == 2u) {        /* Subdirectory (e.g. C/) */
                        for (u32 sh = 0; sh < 72u && !entry; sh++) {
                            u32 s2 = be32_at(blk + 24u + sh * 4u);
                            if (s2 && (s2 + 1u) * 512u <= S.disk.size)
                                entry = load_adf_hunk_file(S.disk.adf, S.disk.size, s2);
                        }
                    }
                    sec = be32_at(blk + 496u);          /* hash_chain */
                }
            }
        }
        /* 2. Otherwise copy custom trackloader bootblock (1024 B) to $070000 and jump to $07000C! */
        if (!entry && S.disk.adf[0] == 'D' && S.disk.adf[1] == 'O' && S.disk.adf[2] == 'S') {
            for (u32 i = 0; i < 1024u; i += 2u)
                CHIPW(0x070000u + i) = (u16)(((u16)S.disk.adf[i] << 8) | S.disk.adf[i + 1u]);
            entry = 0x07000Cu;
        }
    }
    if (!entry)
        entry = 0xF80080u;

    M->kick[0] = 0x001Fu; M->kick[1] = 0xFFE0u;
    M->kick[2] = 0x00F8u; M->kick[3] = 0x0040u;
    CHIPW(0x0000) = 0x001Fu; CHIPW(0x0002) = 0xFFE0u;
    CHIPW(0x0004) = 0x0000u; CHIPW(0x0006) = 0x1000u;

    u16 boot_stub[] = {
        0x2C7C, 0x0000, 0x1000,                         /* MOVEA.L #$1000,A6 (ExecBase) */
        0x227C, 0x0000, 0x2000,                         /* MOVEA.L #$2000,A1 (trackdisk IOStdReq) */
        0x33FC, 0x2C81, 0x00DF, 0xF08E,                 /* DIWSTRT */
        0x33FC, 0x2CC1, 0x00DF, 0xF090,                 /* DIWSTOP */
        0x33FC, 0x0038, 0x00DF, 0xF092,                 /* DDFSTRT */
        0x33FC, 0x00D0, 0x00DF, 0xF094,                 /* DDFSTOP */
        0x4EF9, (u16)(entry >> 16), (u16)entry
    };
    for (u32 i = 0; i < sizeof(boot_stub) / 2u; i++)
        M->kick[(0x0040 >> 1) + i] = boot_stub[i];
    M->kick[0x0080 >> 1] = 0x60FEu;
}

/* ---- Public API ---- */

void cd32_reset(void)
{
    const struct cdrom_toc *saved_cd = S.cd;
    const u8 *saved_adf = S.disk.adf;
    u32 saved_adf_sz = S.disk.size;
    u8 saved_a1200 = S.is_a1200;
    u8 saved_ext = S.ext_roms;
    u8 saved_has_ext = S.has_ext_rom;
    u32 saved_rate = S.sample_rate;
    char saved_info[96];
    for (int i = 0; i < 96; i++) saved_info[i] = S.info[i];

    cd32_zero(&S, sizeof(S));
    cd32_zero(M->chip, sizeof(M->chip));
    S.cd = saved_cd;
    S.disk.adf = saved_adf;
    S.disk.size = saved_adf_sz;
    S.disk.changed = saved_adf ? 0 : 1;
    S.disk.track_cyl = -1;
    S.disk.end = NEVER;
    S.is_a1200 = saved_a1200;
    S.ext_roms = saved_ext;
    S.has_ext_rom = saved_has_ext;
    S.sample_rate = saved_rate;
    S.lof = 1;
    S.gayle_id = 0xD0u;
    for (int i = 0; i < 96; i++) S.info[i] = saved_info[i];

    for (int i = 0; i < 2; i++) {
        S.cia[i].ta = S.cia[i].tb = S.cia[i].la = S.cia[i].lb = 0xFFFFu;
        S.cia[i].tod_run = 1;
    }
    for (u32 n = 0; n < 16u; n++)
        M->nibble[n] = ((n >> 3) & 1u) | (((n >> 2) & 1u) << 8) | (((n >> 1) & 1u) << 16) | ((n & 1u) << 24);
    for (int ch = 0; ch < 4; ch++)
        S.aud[ch].next_irq = NEVER;
    S.blit_end = NEVER;
    S.cop_t = NEVER;

    if (S.ext_roms) {
        S.overlay = 1;
        cd32_map_memory();
        cpu_reset();
    } else {
        if (S.is_a1200) build_cleanroom_a1200_boot();
        else            build_cleanroom_cd32_boot();
        cd32_map_memory();
        cd32_zero(&m, sizeof(m));
        m.s = 1;
        m.im = 7;
        m.r[15] = 0x001FFFE0u;
        m.pc = 0x00F80040u;
    }
}

const char *cd32_load(const u8 *kick, u32 kick_sz, const u8 *ext, u32 ext_sz, const struct cdrom_toc *cd)
{
    if (!cd || !cd->total_lba || !cd->read_2048)
        return "not a valid Amiga CD32 (.cue or .iso) disc image";

#ifdef CD32_HOST
    u32 saved_rate = S.sample_rate;
#endif
    cd32_zero(M, sizeof(*M));
#ifdef CD32_HOST
    S.sample_rate = saved_rate ? saved_rate : 48000u;
#else
    S.sample_rate = 48000u;
#endif
    cpu_init();

    S.cd = cd;
    S.is_a1200 = 0;
    if (kick && kick_sz == 0x80000u && ext && ext_sz == 0x80000u) {
        for (u32 i = 0; i < 0x40000u; i++) {
            M->kick[i] = (u16)(((u16)kick[2u * i] << 8) | kick[2u * i + 1u]);
            M->ext[i]  = (u16)(((u16)ext[2u * i] << 8)  | ext[2u * i + 1u]);
        }
        S.ext_roms = 1;
        S.has_ext_rom = 1;
    } else {
        S.ext_roms = 0;
        S.has_ext_rom = 0;
    }

    char vol[34];
    int vn = 0;
    if (cd->read_2048(16u, M->sec_buf) == 0 &&
        M->sec_buf[1] == 'C' && M->sec_buf[2] == 'D' && M->sec_buf[3] == '0') {
        for (int i = 0; i < 32; i++) {
            char c = (char)M->sec_buf[40 + i];
            if (c < 32 || c > 126) c = ' ';
            if (c == ' ' && (!vn || vol[vn - 1] == ' ')) continue;
            vol[vn++] = c;
        }
        while (vn && vol[vn - 1] == ' ') vn--;
    }
    vol[vn] = 0;

    char *p = S.info;
    const char *t = vn ? vol : "AMIGA CD32 DISC";
    while (*t && p - S.info < 48) *p++ = *t++;
    const char *tag = S.ext_roms ? " (Amiga CD32 Kickstart 3.1, AGA+Akiko)" : " (Amiga CD32, AGA 2MB + Akiko)";
    while (*tag && p - S.info < 94) *p++ = *tag++;
    *p = 0;

    cd32_reset();
    return 0;
}

void a1200_interleave_roms(const u8 *u6a, const u8 *u6b, u8 *out_512k)
{
    /* Interleave split Amiga 1200 256 KB EPROM pair (.u6a = high word, .u6b = low word, byte-swapped) into 512 KB */
    for (u32 i = 0; i < 0x20000u; i++) {
        out_512k[4u * i + 0u] = u6a[2u * i + 1u];
        out_512k[4u * i + 1u] = u6a[2u * i + 0u];
        out_512k[4u * i + 2u] = u6b[2u * i + 1u];
        out_512k[4u * i + 3u] = u6b[2u * i + 0u];
    }
}

static char *info_put(char *p, const char *s)
{
    while (*s && p < S.info + sizeof(S.info) - 1) *p++ = *s++;
    *p = 0;
    return p;
}

static char *info_put_u32(char *p, u32 v)
{
    char d[12];
    int n = 0;
    do d[n++] = (char)('0' + (v % 10u)); while ((v /= 10u) != 0u);
    while (n && p < S.info + sizeof(S.info) - 1) *p++ = d[--n];
    *p = 0;
    return p;
}

const char *a1200_load(const u8 *kick, u32 kick_sz, const u8 *ext, u32 ext_sz,
                       const u8 *adf, u32 adf_sz, const char *name)
{
    (void)name;
    if (adf && adf_sz != 901120u && adf_sz != 1802240u)
        return "not an Amiga .adf floppy image (901120 or 1802240 bytes)";
    if (kick && kick_sz != 0x40000u && kick_sz != 0x80000u)
        return "Amiga 1200 Kickstart ROM must be 256 or 512 KB";

#ifdef CD32_HOST
    u32 saved_rate = S.sample_rate;
#endif
    cd32_zero(M, sizeof(*M));
#ifdef CD32_HOST
    S.sample_rate = saved_rate ? saved_rate : 48000u;
#else
    S.sample_rate = 48000u;
#endif
    cpu_init();

    S.is_a1200 = 1;
    S.disk.adf = adf;
    S.disk.size = adf ? adf_sz : 0u;

    if (kick && (kick_sz == 0x80000u || kick_sz == 0x40000u)) {
        u32 words = kick_sz >> 1;
        for (u32 i = 0; i < 0x40000u; i++) {
            u32 si = i % words;
            M->kick[i] = (u16)(((u16)kick[2u * si] << 8) | kick[2u * si + 1u]);
        }
        S.ext_roms = 1;
        if (ext && ext_sz == 0x80000u) {
            for (u32 i = 0; i < 0x40000u; i++)
                M->ext[i] = (u16)(((u16)ext[2u * i] << 8) | ext[2u * i + 1u]);
            S.has_ext_rom = 1;
        }
    }

    char *p = S.info;
    *p = 0;
    p = info_put(p, "Amiga 1200 (68EC020 14.18 MHz, 2 MB AGA, ");
    if (S.ext_roms && kick) {
        if (kick_sz == 0x80000u && kick[0x18] == 'A' && kick[0x19] == 'R') {
            p = info_put(p, "AROS");
        } else {
            u32 ver = ((u32)kick[12] << 8) | kick[13];
            u32 rev = ((u32)kick[14] << 8) | kick[15];
            if (ver >= 30u && ver <= 50u) {
                p = info_put(p, "KS ");
                p = info_put_u32(p, ver);
                p = info_put(p, ".");
                p = info_put_u32(p, rev);
            } else {
                p = info_put(p, "Diag ROM");
            }
        }
    } else {
        p = info_put(p, "built-in AGA boot");
    }
    p = info_put(p, adf ? ", DF0: .adf)" : ", no floppy)");

    cd32_reset();
    return 0;
}

static u32 a1200_char_key(int ch)
{
    static const char plain[] = "`1234567890-=\\", shifted[] = "~!@#$%^&*()_+|";
    static const char qrow[] = "qwertyuiop[]", arow[] = "asdfghjkl;'", zrow[] = "zxcvbnm,./";
    static const char qrow_s[] = "QWERTYUIOP{}", arow_s[] = "ASDFGHJKL:\"", zrow_s[] = "ZXCVBNM<>?";
    for (int i = 0; plain[i]; i++) {
        if (ch == plain[i])   return (u32)i;
        if (ch == shifted[i]) return 0x80u | (u32)i;
    }
    for (int i = 0; qrow[i]; i++) {
        if (ch == qrow[i])   return 0x10u + (u32)i;
        if (ch == qrow_s[i]) return 0x90u + (u32)i;
    }
    for (int i = 0; arow[i]; i++) {
        if (ch == arow[i])   return 0x20u + (u32)i;
        if (ch == arow_s[i]) return 0xA0u + (u32)i;
    }
    for (int i = 0; zrow[i]; i++) {
        if (ch == zrow[i])   return 0x31u + (u32)i;
        if (ch == zrow_s[i]) return 0xB1u + (u32)i;
    }
    switch (ch) {
    case ' ': return 0x40u;
    case '\n': case '\r': return 0x44u;
    case 8: case 127: return 0x41u;
    case '\t': return 0x42u;
    case 27: return 0x45u;
    default: return 0xFFu;
    }
}

void a1200_type(const char *text)
{
    while (text && *text) {
        int next = (S.tq_tail + 1) & 255;
        if (next == S.tq_head) break;
        S.tq[S.tq_tail] = *text++;
        S.tq_tail = next;
    }
}

void a1200_mouse(int dx, int dy, int buttons)
{
    S.mouse_x = (u8)(S.mouse_x + dx);
    S.mouse_y = (u8)(S.mouse_y + dy);
    S.mouse_btn = (u8)(buttons & 3);
}

static void step_events(s32 now)
{
    if (S.blit_busy && now >= S.blit_end) {
        S.blit_busy = 0;
        S.blit_end = NEVER;
        raise_irq(0x0040u);
    }
    if (S.disk.dma && now >= S.disk.end) {
        S.disk.dma = 0;
        S.disk.end = NEVER;
        R(DSKPTH) = (u16)(S.disk.pt >> 16);
        R(DSKPTL) = (u16)S.disk.pt;
        raise_irq(0x0002u);
    }
    cia_update(0, now);
    cia_update(1, now);
    for (int ch = 0; ch < 4; ch++) {
        if (now >= S.aud[ch].next_irq) {
            raise_irq(0x0080u << ch);
            u32 len = S.aud[ch].len ? S.aud[ch].len : 0x10000u;
            u32 per = S.aud[ch].per < 124u ? 124u : S.aud[ch].per;
            u32 blk = len * per * 8u;
            if (blk > 0x0FFFFFFFu) blk = 0x0FFFFFFFu;
            S.aud[ch].next_irq = S.aud[ch].on ? (now + (s32)blk) : NEVER;
        }
    }
}

static void run_aga_frame_common(u16 *picture)
{
    m.clock = 0;
    int need_pal_sync = 1;
    u32 total_lines = (R(BPLCON0) & 4u) ? (S.lof ? 313u : 312u) : 313u;

    for (u32 line = 0; line < total_lines; line++) {
        S.cur_line = line;
        s32 t0 = (s32)(line * LINE_CYCLES);
        if (line == 0u) {
            raise_irq(0x0020u);                         /* VBlank IRQ3 */
            cia_tod_tick(0);
            if ((S.dmacon & 0x280u) == 0x280u && S.cop_lc1)
                copper_jump(S.cop_lc1, t0);
            for (int i = 0; i < 8; i++) {
                S.spr[i].state = 0;
                S.spr[i].armed = 0;
            }
        }
        cia_tod_tick(1);
        sprite_dma(line);
        if (S.is_a1200)
            a1200_keyboard_poll(t0);
        if (need_pal_sync) {
            for (int i = 0; i < 256; i++)
                S.line_pal15[i] = S.aga_pal15[i];
            need_pal_sync = 0;
        }
        S.nchg = 0;

        s32 fetch_end = t0 + 4 * 192;
        S.line_limit = fetch_end;
        copper_run(fetch_end);
        cpu_run(fetch_end);
        step_events(fetch_end);
        if (S.nchg)
            need_pal_sync = 1;

        render_aga_line(line, picture);

        s32 line_end = t0 + LINE_CYCLES;
        S.line_limit = line_end;
        copper_run(line_end);
        cpu_run(line_end);
        step_events(line_end);
        if (S.nchg)
            need_pal_sync = 1;
    }

    s32 f_cyc = (s32)(total_lines * LINE_CYCLES);
    cia_update(0, m.clock);
    cia_update(1, m.clock);
    S.cia[0].last -= f_cyc;
    S.cia[1].last -= f_cyc;
    if (S.blit_busy && S.blit_end != NEVER)
        S.blit_end = (S.blit_end > f_cyc) ? (S.blit_end - f_cyc) : 0;
    if (S.disk.dma && S.disk.end != NEVER)
        S.disk.end = (S.disk.end > f_cyc) ? (S.disk.end - f_cyc) : 0;
    for (int ch = 0; ch < 4; ch++)
        if (S.aud[ch].next_irq != NEVER)
            S.aud[ch].next_irq = (S.aud[ch].next_irq > f_cyc) ? (S.aud[ch].next_irq - f_cyc) : 64;
    if (S.cop_t != NEVER)
        S.cop_t = (S.cop_t > f_cyc) ? (S.cop_t - f_cyc) : 0;
    S.kb_time -= f_cyc;
    if (S.kb_time < -0x40000000)
        S.kb_time = -0x40000000;
    S.cycles_hi += (u32)f_cyc;
    S.lof = (R(BPLCON0) & 4u) ? (S.lof ^ 1u) : 1u;

    step_audio_frame();
    S.frames++;
}

void cd32_frame(u16 pad, u16 *picture)
{
    S.pad = pad;
    run_aga_frame_common(picture);
}

void a1200_frame(u16 pad, const u8 keys[16], u16 *picture)
{
    S.pad = pad;
    u8 now_k[16];
    for (int i = 0; i < 16; i++)
        now_k[i] = keys ? keys[i] : 0u;
    if (S.tq_head != S.tq_tail) {
        u32 k = a1200_char_key((u8)S.tq[S.tq_head]);
        if (S.tq_frame < 3 && k != 0xFFu) {
            now_k[(k & 0x7Fu) >> 3] |= (u8)(1u << (k & 7u));
            if (k & 0x80u) now_k[0x60 >> 3] |= 1u;
        }
        if (++S.tq_frame == 6) {
            S.tq_frame = 0;
            S.tq_head = (S.tq_head + 1) & 255;
        }
    }
    if (pad & 0x08u) now_k[0x44 >> 3] |= (u8)(1u << (0x44 & 7)); /* START -> Return */
    if (pad & 0x04u) now_k[0x40 >> 3] |= (u8)(1u << (0x40 & 7)); /* SELECT -> Space */
    for (u32 k = 0; k < 128u; k++) {
        u32 bit = 1u << (k & 7u), down = now_k[k >> 3] & bit;
        if (down != (S.held_was[k >> 3] & bit))
            a1200_key_push(down ? k : (k | 0x80u));
    }
    for (int i = 0; i < 16; i++)
        S.held_was[i] = now_k[i];

    run_aga_frame_common(picture);
}

const char *cd32_info(void) { return S.info; }

u8 *cd32_save_ram(u32 *size, int *battery)
{
    if (S.is_a1200) {
        *size = 0;
        *battery = 0;
        return M->nvram;
    }
    *size = sizeof(M->nvram);
    *battery = 1;
    return M->nvram;
}

int cd32_save_changed(void)
{
    if (S.is_a1200)
        return 0;
    int d = S.nvram_dirty;
    S.nvram_dirty = 0;
    return d;
}

int cd32_jammed(void)
{
    return m.stopped && m.im == 7u;
}

void cd32_audio_rate(u32 hz)
{
    S.sample_rate = hz;
    S.snd_frac = 0;
    S.snd_head = S.snd_tail = 0;
}

int cd32_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && S.snd_tail != S.snd_head) {
        out[n++] = M->snd_ring[S.snd_tail & (SND_RING - 1u)];
        S.snd_tail++;
    }
    return n;
}

#ifdef CD32_HOST
void cd32_host_dbg(u32 out[10])
{
    out[0] = m.pc;
    out[1] = m.r[15];
    out[2] = get_sr();
    out[3] = m.vbr;
    out[4] = S.overlay;
    out[5] = S.dmacon;
    out[6] = S.intena;
    out[7] = S.intreq;
    out[8] = S.cop_lc1;
    out[9] = R(BPLCON0);
}
#endif
