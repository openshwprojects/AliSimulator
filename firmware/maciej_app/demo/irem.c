/* Irem M72 & M92 Classic Arcade Multi-Board Emulator: see irem.h.
   Zero static .bss (NEC V30/V33 1 MB bus, Z80, YM2151, GA20 PCM, tilemaps,
   sprites, palettes & audio ring live in EMU_RAM_PHYS; decoded 8x8 tiles,
   16x16 sprites, PCM samples & .zip staging live in upper physical RAM). */
#include "irem.h"
#include "z80.h"
#include "zip.h"
#include "font5x7.h"

#ifndef IREM_HOST
#include "hw.h"
#endif

#define INLINE static inline __attribute__((always_inline))
#define X86_INLINE INLINE

enum {
    IREM_BOARD_M72 = 0,     /* NEC V30 + Z80 + dual 64x64 tilemaps + 256 multi-cell sprites + YM2151 + DAC */
    IREM_BOARD_M92 = 1      /* NEC V33 + Sound + 3 rowscroll playfields PF1..3 + sprites + YM2151 + GA20 PCM */
};

#define IREM_SND_RING   8192
#define IREM_MAX_TILES  65536u          /* 65,536 8x8 4bpp tiles (2 MB pre-decoded u32x8) */
#define IREM_MAX_SPR16  65536u          /* 65,536 16x16 4bpp sprite cells (8 MB nibble-packed 128 B/cell) */
#define IREM_ZROM_CAP   0x00040000u     /* 256 KB Sound Z80 ROM */
#define IREM_PCM_CAP    0x00400000u     /* 4 MB Irem GA20 / M72 Sample ROM */
#define IREM_STAGE_CAP  0x00500000u     /* 5 MB .zip unpack scratch */

#pragma GCC push_options
#pragma GCC optimize("O2")
#include "ym2151.inc"
#pragma GCC pop_options

/* Irem GA20 4-Channel 8-bit Linear PCM Voice */
struct irem_ga20_ch {
    u32 start, end, pos_frac;
    u32 step_48k;
    u8  rate_reg, vol, playing;
};

struct irem_state {
    u8  board;
    u8  jammed;
    int scr_w, scr_h;
    u16 pad1, pad2;
    u8  coin_prev, coin_pulse;
    u32 rom_size, zrom_size, pcm_size, pcm_mask;
    u32 tile_count, spr16_count;
    u32 tile_mask, spr16_mask;
    u32 frame_no;
    int cur_scanline;

    /* Interrupts & Scroll / Video Control */
    u8  vblank_vec, raster_vec;
    u16 raster_irq_line;
    u8  raster_irq_en;
    u8  video_ctrl;             /* bit 0=BG on, bit 1=FG on, bit 2=Spr on */
    u16 scroll_x[3];            /* PF0(FG), PF1(BG), PF2(M92 3rd layer) */
    u16 scroll_y[3];
    u8  m92_pf_ctrl[3];         /* rowscroll enable & VRAM base per M92 playfield */
    u8  act_spr[256];
    int n_act_spr;

    /* Sound Z80 + YM2151 + M72 DAC + Irem GA20 4-ch PCM */
    u32 sample_rate;
    u8  snd_latch, snd_latch_pending;
    s16 m72_dac;
    u32 m72_samp_pos, m72_samp_end;
    u8  ga20_regs[32];
    struct irem_ga20_ch ga20[4];
    u32 snd_head, snd_tail;

    char info[96];
};

/* Forward declarations for x86_v30.inc bus hooks */
#pragma GCC optimize("O2")

INLINE u8 irem_rb(u32 a);
INLINE u16 irem_rw(u32 a);
static void irem_wb(u32 a, u8 v);
static void irem_ww(u32 a, u16 v);
static u8 irem_inb(u16 port);
static u16 irem_inw(u16 port);
static void irem_outb(u16 port, u8 v);
static void irem_outw(u16 port, u16 v);

#define X86_ADDR_MASK   0xFFFFFu
#define X86_RB(a)       irem_rb(a)
#define X86_RW(a)       irem_rw(a)
#define X86_WB(a, v)    irem_wb(a, v)
#define X86_WW(a, v)    irem_ww(a, v)
#define X86_INB(p)      irem_inb(p)
#define X86_INW(p)      irem_inw(p)
#define X86_OUTB(p, v)  irem_outb(p, v)
#define X86_OUTW(p, v)  irem_outw(p, v)

struct irem_mem {
    struct irem_state st;
    u8  mem[0x100000];              /* Unified 1 MB NEC V30 / V33 20-bit address space! */
    u16 spr_dma[0x0400];            /* Latched Sprite DMA buffer (256 sprites x 4 words = 2 KB) */
    u16 pal15[2048];                /* Preconverted 0BBBBBGGGGGRRRRR palette */
    u8  zram[0x4000];               /* 16 KB Sound Z80 RAM */
    u8  tile_nz[IREM_MAX_TILES];    /* 1 if 8x8 tile has non-zero pen */
    u8  spr_nz[IREM_MAX_SPR16];     /* 1 if 16x16 sprite cell has non-zero pen */
    u8  line_pri[IREM_W_MAX] __attribute__((aligned(4)));
    s16 snd_ring[IREM_SND_RING];
    /* Placed after mem[] so irem_rb/rw can inline straight against M->mem! */
    struct z80 zcpu;
    struct ym2151 opm;
};

#ifdef IREM_HOST
static struct irem_mem irem_host_mem;
static u32 irem_host_tiles[IREM_MAX_TILES * 8u];
static u8  irem_host_spr[IREM_MAX_SPR16 * 128u];
static u8  irem_host_zrom[IREM_ZROM_CAP];
static u8  irem_host_pcm[IREM_PCM_CAP];
static u8  irem_host_stage[IREM_STAGE_CAP];
#define M           (&irem_host_mem)
#define TILE_BUF    irem_host_tiles
#define SPR_BUF     irem_host_spr
#define ZROM_BUF    irem_host_zrom
#define PCM_BUF     irem_host_pcm
#define ZIP_STAGE   irem_host_stage
#define IREM_POLL() ((void)0)
#else
/* Physical layout during irem_play:
   0x03400000..0x0357FFFF (1.5 MB) : struct irem_mem M (~1.21 MB, 0 B static .bss!)
   0x03580000..0x0377FFFF (2.0 MB) : TILE_BUF (65,536 x 32 B pre-decoded 8x8 tiles)
   0x05800000..0x0583FFFF (256 KB) : ZROM_BUF (Sound Z80 ROM)
   0x06900000..0x06CFFFFF (4.0 MB) : PCM_BUF  (Irem GA20 / M72 Sample ROM)
   0x06D00000..0x074FFFFF (8.0 MB) : SPR_BUF  (65,536 x 128 B pre-decoded 16x16 sprites)
   0x07500000..0x079FFFFF (5.0 MB) : ZIP_STAGE (.zip unpack scratch) */
#define M           ((struct irem_mem *)KSEG0(EMU_RAM_PHYS))
#define TILE_BUF    ((u32 *)KSEG0(0x03580000u))
#define ZROM_BUF    ((u8 *)KSEG0(0x05800000u))
#define PCM_BUF     ((u8 *)KSEG0(0x06900000u))
#define SPR_BUF     ((u8 *)KSEG0(0x06D00000u))
#define ZIP_STAGE   ((u8 *)KSEG0(0x07500000u))
#define IREM_POLL() ((void)now_ms())
_Static_assert(sizeof(struct irem_mem) <= 0x00180000u, "irem_mem exceeds 1.5 MB slot");
#endif

#define S (M->st)

#pragma GCC optimize("O2")

INLINE u8 irem_rb(u32 a)
{
    return M->mem[a & 0xFFFFFu];
}

INLINE u16 irem_rw(u32 a)
{
    a &= 0xFFFFFu;
    return (u16)M->mem[a] | ((u16)M->mem[(a + 1u) & 0xFFFFFu] << 8);
}

#pragma GCC push_options
#pragma GCC optimize("Os")
#include "x86_v30.inc"
#pragma GCC pop_options
#pragma GCC optimize("O2")

struct irem_cpu_holder {
    struct x86_cpu vcpu;
};
#ifdef IREM_HOST
static struct irem_cpu_holder irem_host_vcpu;
#define VCPU (irem_host_vcpu.vcpu)
#else
/* Place VCPU at 0x03780000 right above TILE_BUF in EMU_RAM_PHYS (zero static .bss!) */
#define VCPU (((struct irem_cpu_holder *)KSEG0(0x03780000u))->vcpu)
#endif

static void irem_zero(void *p, u32 n)
{
    u8 *b = (u8 *)p;
    for (u32 i = 0; i < n; i++)
        b[i] = 0;
}

static int irem_ci_has(const char *s, const char *sub)
{
    if (!s) return 0;
    for (; *s; s++) {
        const char *p = s, *q = sub;
        while (*p && *q && ((*p | 32) == (*q | 32))) {
            p++;
            q++;
        }
        if (!*q) return 1;
    }
    return 0;
}

static int irem_ci_ends(const char *s, const char *ext)
{
    int ls = 0, le = 0;
    while (s[ls]) ls++;
    while (ext[le]) le++;
    if (ls < le) return 0;
    for (int i = 0; i < le; i++)
        if ((s[ls - le + i] | 32) != (ext[i] | 32))
            return 0;
    return 1;
}

/* ---- Irem GA20 4-Channel 8-bit Linear PCM Engine ---- */
static void ga20_write(u32 off, u8 v)
{
    off &= 0x1Fu;
    S.ga20_regs[off] = v;
    int ch = (int)(off >> 3);
    struct irem_ga20_ch *c = &S.ga20[ch];
    switch (off & 7u) {
    case 0:
    case 1:
        c->start = (((u32)S.ga20_regs[ch * 8 + 1] << 12) | ((u32)S.ga20_regs[ch * 8 + 0] << 4));
        break;
    case 2:
    case 3:
        c->end = (((u32)S.ga20_regs[ch * 8 + 3] << 12) | ((u32)S.ga20_regs[ch * 8 + 2] << 4));
        break;
    case 4: {
        /* GA20 pitch: rate = 3579545 / (4 * (256 - reg)) */
        c->rate_reg = v;
        u32 div = 256u - (u32)v;
        if (div < 2u) div = 2u;
        u32 hz = 894886u / div;
        c->step_48k = (hz << 12) / (S.sample_rate ? S.sample_rate : 48000u);
        break;
    }
    case 5:
        c->vol = v;     /* 0..255 linear volume */
        break;
    case 6:
        if (v & 2u) {
            c->pos_frac = 0;
            c->playing  = (S.pcm_size > 0 && c->end > c->start) ? 1u : 0u;
        } else {
            c->playing = 0;
        }
        break;
    }
}

static s32 ga20_step_48k(void)
{
    if (!S.pcm_size) return 0;
    s32 sum = 0;
    for (int ch = 0; ch < 4; ch++) {
        struct irem_ga20_ch *c = &S.ga20[ch];
        if (!c->playing || !c->vol) continue;
        u32 cur = c->start + (c->pos_frac >> 12);
        if (cur >= c->end) {
            c->playing = 0;
            continue;
        }
        u8 raw = PCM_BUF[cur & S.pcm_mask];
        if (raw == 0x00u) {             /* GA20 hardware 0x00 end-of-sample marker! */
            c->playing = 0;
            continue;
        }
        s32 s = ((s32)raw - 128) * (s32)c->vol;
        sum += s >> 1;
        c->pos_frac += c->step_48k ? c->step_48k : 1024u;
    }
    return sum;
}

/* ---- NEC V30 / V33 Memory Write & I/O Port Bus ---- */
static void irem_wb(u32 a, u8 v)
{
    a &= 0xFFFFFu;
    /* IVT & Work RAM: $00000..$00FFF (V30/V33 IVT), $40000..$47FFF (early R-Type) & $A0000..$BFFFF */
    if (a < 0x01000u || (a >= 0x40000u && a < 0x48000u) || (a >= 0xA0000u && a < 0xC0000u)) {
        M->mem[a] = v;
        return;
    }
    /* Sprite RAM ($C0000..$C07FF on M72, $F8000..$F87FF on M92) */
    if ((a >= 0xC0000u && a < 0xC0800u) || (S.board == IREM_BOARD_M92 && a >= 0xF8000u && a < 0xF8800u)) {
        M->mem[a] = v;
        return;
    }
    /* Palette RAM ($C8000..$CBFFF: 15-bit xBBBBBGGGGGRRRRR LE words!) */
    if (a >= 0xC8000u && a < 0xCC000u) {
        M->mem[a] = v;
        u32 idx = ((a - 0xC8000u) >> 1) & 2047u;
        u32 base = 0xC8000u + idx * 2u;
        u16 w = (u16)M->mem[base] | ((u16)M->mem[base + 1u] << 8);
        M->pal15[idx] = w & 0x7FFFu;    /* Matches play.c 0BBBBBGGGGGRRRRR directly! */
        return;
    }
    /* Tilemap & Rowscroll VRAM ($D0000..$DFFFF) */
    if (a >= 0xD0000u && a < 0xE0000u) {
        M->mem[a] = v;
        return;
    }
}

static void irem_ww(u32 a, u16 v)
{
    irem_wb(a, (u8)v);
    irem_wb(a + 1u, (u8)(v >> 8));
}

static u8 irem_in_p1(void)
{
    /* Irem JAMMA P1 active-LOW:
       b0=Right, b1=Left, b2=Down, b3=Up, b6=Button2(Force/Jump), b7=Button1(Beam/Attack) */
    u8 v = 0xFFu;
    u16 p = S.pad1;
    if (p & 0x0080u) v &= (u8)~0x01u;   /* Right */
    if (p & 0x0040u) v &= (u8)~0x02u;   /* Left */
    if (p & 0x0020u) v &= (u8)~0x04u;   /* Down */
    if (p & 0x0010u) v &= (u8)~0x08u;   /* Up */
    if (p & 0x0002u) v &= (u8)~0x40u;   /* B -> Button 2 (Force Pod / Jump) */
    if (p & 0x0001u) v &= (u8)~0x80u;   /* A -> Button 1 (Fire / Beam) */
    return v;
}

static u8 irem_in_sys(void)
{
    /* Active-LOW system byte: b0=Start1, b1=Start2, b2=Coin1 */
    u8 v = 0xFFu;
    if (S.pad1 & 0x0008u) v &= (u8)~0x01u;
    if (S.pad1 & 0x0800u) v &= (u8)~0x02u;
    if (S.coin_pulse > 0) v &= (u8)~0x04u;
    return v;
}

static void irem_trigger_spr_dma(void)
{
    u32 src = (S.board == IREM_BOARD_M92) ? 0xF8000u : 0xC0000u;
    for (u32 i = 0; i < 0x0400u; i++)
        M->spr_dma[i] = (u16)M->mem[src + i * 2u] | ((u16)M->mem[src + i * 2u + 1u] << 8);
}

static u8 irem_inb(u16 port)
{
    switch (port & 0xFFu) {
    case 0x00: return irem_in_p1();
    case 0x01: return 0xFFu;
    case 0x02: return irem_in_sys();
    case 0x03: return 0xFFu;
    case 0x04: return 0xFFu;    /* DIP 1 (standard difficulty, 3 lives) */
    case 0x05: return 0xFFu;    /* DIP 2 */
    default:   return 0xFFu;
    }
}

static u16 irem_inw(u16 port)
{
    return (u16)irem_inb(port) | ((u16)irem_inb((u16)(port + 1u)) << 8);
}

static void irem_outb(u16 port, u8 v)
{
    u32 p = port & 0xFFu;
    switch (p) {
    case 0x00:  /* Sound command latch -> Sound Z80 NMI/IRQ */
        S.snd_latch = v;
        S.snd_latch_pending = 1u;
        M->zcpu.nmi = 1;
        break;
    case 0x04:  /* Sprite DMA ($C0000 / $F8000 -> spr_dma) */
        irem_trigger_spr_dma();
        break;
    case 0x06:
        S.raster_irq_line = (S.raster_irq_line & 0xFF00u) | v;
        S.raster_irq_en = 1u;
        break;
    case 0x07:
        S.raster_irq_line = (S.raster_irq_line & 0x00FFu) | ((u16)(v & 1u) << 8);
        break;
    /* Scroll registers ($80..$8B):
       $80..$81: PF0 (FG) Scroll X     $82..$83: PF0 (FG) Scroll Y
       $84..$85: PF1 (BG) Scroll X     $86..$87: PF1 (BG) Scroll Y
       $88..$89: PF2 (M92) Scroll X    $8A..$8B: PF2 (M92) Scroll Y
       $8C:      Video Control         $8D..$8F: M92 PF0..PF2 rowscroll control */
    case 0x80: S.scroll_x[0] = (S.scroll_x[0] & 0xFF00u) | v; break;
    case 0x81: S.scroll_x[0] = (S.scroll_x[0] & 0x00FFu) | ((u16)v << 8); break;
    case 0x82: S.scroll_y[0] = (S.scroll_y[0] & 0xFF00u) | v; break;
    case 0x83: S.scroll_y[0] = (S.scroll_y[0] & 0x00FFu) | ((u16)v << 8); break;
    case 0x84: S.scroll_x[1] = (S.scroll_x[1] & 0xFF00u) | v; break;
    case 0x85: S.scroll_x[1] = (S.scroll_x[1] & 0x00FFu) | ((u16)v << 8); break;
    case 0x86: S.scroll_y[1] = (S.scroll_y[1] & 0xFF00u) | v; break;
    case 0x87: S.scroll_y[1] = (S.scroll_y[1] & 0x00FFu) | ((u16)v << 8); break;
    case 0x88: S.scroll_x[2] = (S.scroll_x[2] & 0xFF00u) | v; break;
    case 0x89: S.scroll_x[2] = (S.scroll_x[2] & 0x00FFu) | ((u16)v << 8); break;
    case 0x8A: S.scroll_y[2] = (S.scroll_y[2] & 0xFF00u) | v; break;
    case 0x8B: S.scroll_y[2] = (S.scroll_y[2] & 0x00FFu) | ((u16)v << 8); break;
    case 0x8C: S.video_ctrl = v; break;
    case 0x8D: S.m92_pf_ctrl[0] = v; break;
    case 0x8E: S.m92_pf_ctrl[1] = v; break;
    case 0x8F: S.m92_pf_ctrl[2] = v; break;
    default:
        if (p >= 0xA0u && p < 0xC0u)
            ga20_write(p - 0xA0u, v);
        break;
    }
}

static void irem_outw(u16 port, u16 v)
{
    irem_outb(port, (u8)v);
    irem_outb((u16)(port + 1u), (u8)(v >> 8));
}

/* ---- Sound Z80 Bus (YM2151 + M72 DAC + Irem GA20 4-ch PCM) ---- */
static void irem_setup_z80_map(void)
{
    for (int i = 0; i < 64; i++) {
        M->zcpu.rd[i] = 0;
        M->zcpu.wr[i] = 0;
        M->zcpu.op[i] = 0;
    }
    /* $0000..$BFFF: Z80 Sound ROM; $C000..$FFFF: 16 KB Z80 Sound RAM */
    u32 rom_pages = (S.zrom_size + 1023u) >> 10;
    if (rom_pages > 48u) rom_pages = 48u;
    for (u32 i = 0; i < rom_pages; i++)
        M->zcpu.rd[i] = &ZROM_BUF[i << 10];
    for (int i = 48; i < 64; i++) {
        u8 *p = &M->zram[(i - 48) << 10];
        M->zcpu.rd[i] = p;
        M->zcpu.wr[i] = p;
    }
}

static u8 irem_z80_read(struct z80 *z, u16 a)
{
    (void)z;
    if (a < 0xC000u)
        return (a < S.zrom_size) ? ZROM_BUF[a] : 0u;
    return M->zram[a & 0x3FFFu];
}

static void irem_z80_write(struct z80 *z, u16 a, u8 v)
{
    (void)z;
    if (a >= 0xC000u)
        M->zram[a & 0x3FFFu] = v;
}

static u8 irem_z80_in(struct z80 *z, u16 port)
{
    (void)z;
    u8 p = (u8)port;
    if (p == 0x00u || p == 0x80u) {
        S.snd_latch_pending = 0;
        return S.snd_latch;
    }
    if (p == 0x01u || p == 0x02u)
        return M->opm.status;
    if (p >= 0x20u && p < 0x40u) {
        u32 ch = (p - 0x20u) >> 3;
        if (((p - 0x20u) & 7u) == 7u)
            return S.ga20[ch & 3u].playing;
        return S.ga20_regs[(p - 0x20u) & 31u];
    }
    return 0xFFu;
}

static void irem_z80_out(struct z80 *z, u16 port, u8 v)
{
    (void)z;
    u8 p = (u8)port;
    if (p == 0x00u) {
        M->opm.addr_latch = v;
    } else if (p == 0x01u) {
        ym2151_write_reg(&M->opm, M->opm.addr_latch, v, 3579545u);
    } else if (p == 0x02u) {
        /* M72 signed 8-bit sample DAC */
        S.m72_dac = (s16)((s8)v * 160);
    } else if (p == 0x06u) {
        M->zcpu.irq = 0;
    } else if (p >= 0x20u && p < 0x40u) {
        ga20_write(p - 0x20u, v);
    }
}

/* ============================================================================
   Scanline Tilemap & Multi-Cell Sprite Renderer (M72 & M92)
   ============================================================================ */

static void irem_draw_tilemap_line(int pf, int y, u8 pri_lo, u8 pri_hi, u16 *dst)
{
    if (!S.tile_count) return;
    int w = S.scr_w;
    /* Playfield VRAM bases in M->mem:
       PF0 (FG): $D0000 (64x64 x 4 bytes = 16 KB)
       PF1 (BG): $D8000 on M72, $D4000 on M92
       PF2 (M92 back): $D8000, Rowscroll table at $DC000 */
    u32 vbase = (pf == 0) ? 0xD0000u :
                (pf == 1) ? ((S.board == IREM_BOARD_M92) ? 0xD4000u : 0xD8000u) : 0xD8000u;

    int xscr = (s16)S.scroll_x[pf];
    int yscr = (s16)S.scroll_y[pf];
    if (S.board == IREM_BOARD_M92 && (S.m92_pf_ctrl[pf] & 0x01u)) {
        /* M92 Per-Scanline Rowscroll (e.g. In the Hunt underwater waves!) */
        u32 rtab = 0xDC000u + (u32)pf * 0x0400u + (u32)(y & 255) * 2u;
        s16 delta = (s16)((u16)M->mem[rtab] | ((u16)M->mem[rtab + 1u] << 8));
        xscr += delta;
    }

    int sy = (y + yscr) & 511;
    u32 row_base = vbase + (u32)(sy >> 3) * 256u;   /* 64 cols x 4 bytes/cell */

    for (int x = 0; x < w;) {
        int sx = (x + xscr) & 511;
        int tx0 = sx & 7;
        int span = 8 - tx0;
        if (x + span > w) span = w - x;

        u32 cell_a = row_base + (u32)(sx >> 3) * 4u;
        u16 code = (u16)M->mem[cell_a] | ((u16)M->mem[cell_a + 1u] << 8);
        u16 attr = (u16)M->mem[cell_a + 2u] | ((u16)M->mem[cell_a + 3u] << 8);
        u32 t = code & S.tile_mask;
        if (!M->tile_nz[t]) {
            x += span;
            continue;
        }

        int fx = (attr & 0x0100u) != 0;
        int fy = (attr & 0x0200u) != 0;
        u8  hi = (attr & 0x0080u) ? pri_hi : pri_lo;
        int ty = fy ? (7 - (sy & 7)) : (sy & 7);
        u32 row32 = TILE_BUF[t * 8u + (u32)ty];
        if (!row32) {
            x += span;
            continue;
        }

        const u16 *pal_row = &M->pal15[((u32)(attr & 0x3Fu) << 4) & 0x7F0u];
        if (!fx) {
            u32 r_sh = row32 >> (tx0 * 4);
            for (int k = 0; k < span; k++, r_sh >>= 4) {
                u32 pen = r_sh & 0x0Fu;
                if (pen && hi >= M->line_pri[x + k]) {
                    dst[x + k] = pal_row[pen];
                    M->line_pri[x + k] = hi;
                }
            }
        } else {
            for (int k = 0; k < span; k++) {
                int px = 7 - (tx0 + k);
                u32 pen = (row32 >> (px * 4)) & 0x0Fu;
                if (pen && hi >= M->line_pri[x + k]) {
                    dst[x + k] = pal_row[pen];
                    M->line_pri[x + k] = hi;
                }
            }
        }
        x += span;
    }
}

static void irem_draw_sprites_line(int y, u16 *dst)
{
    if (!S.spr16_count || !S.n_act_spr) return;
    int w = S.scr_w;

    for (int ai = 0; ai < S.n_act_spr; ai++) {
        int s = S.act_spr[ai];
        const u16 *sp = &M->spr_dma[s * 4];
        /* M72 / M92 4-word sprite entry:
           sp[0]: low 9 bits = Y (active when non-zero; screen_y = sp[0] & 0x1FF, or 256-y when bit 15=0?
                  Support direct screen Y in 0..255 via sp[0] & 0x1FF with 16..271 offset if >= 256!)
           sp[1]: base 16x16 cell code
           sp[2]: low byte = color(0..63), bit 8=FlipX, bit 9=FlipY, bits 10..11=H_exp(0..3 -> 1,2,4,8),
                  bits 12..13=W_exp(0..3 -> 1,2,4,8), bits 14..15=Priority
           sp[3]: X coordinate (signed 10-bit: 0..511, >= 448 wraps negative) */
        int sy = sp[0] & 0x1FFu;
        if (sy >= 448) sy -= 512;
        u32 code = sp[1];
        u16 attr = sp[2];
        int sx = sp[3] & 0x1FFu;
        if (sx >= 448) sx -= 512;

        int ch = 1 << ((attr >> 10) & 3u);
        int cw = 1 << ((attr >> 12) & 3u);
        int pix_h = ch * 16, pix_w = cw * 16;
        if (y < sy || y >= sy + pix_h) continue;
        if (sx >= w || sx + pix_w <= 0) continue;

        int fx = (attr & 0x0100u) != 0;
        int fy = (attr & 0x0200u) != 0;
        u8  pri = (attr & 0x8000u) ? 0x18u : 0x28u;
        const u16 *pal_row = &M->pal15[(0x200u + ((u32)(attr & 0x3Fu) << 4)) & 0x7F0u];

        int rel_y = fy ? (pix_h - 1 - (y - sy)) : (y - sy);
        int cy = rel_y >> 4, in_y = rel_y & 15;

        int x0 = sx < 0 ? 0 : sx;
        int x1 = (sx + pix_w > w) ? w : (sx + pix_w);
        for (int x = x0; x < x1; x++) {
            int rel_x = fx ? (pix_w - 1 - (x - sx)) : (x - sx);
            int cx = rel_x >> 4, in_x = rel_x & 15;
            u32 cell = (code + (u32)(cy * cw + cx)) & S.spr16_mask;
            if (!M->spr_nz[cell]) continue;
            u8 pk = SPR_BUF[cell * 128u + (u32)in_y * 8u + (u32)(in_x >> 1)];
            u8 pen = (in_x & 1) ? (pk >> 4) : (pk & 0x0Fu);
            if (pen && pri >= M->line_pri[x]) {
                dst[x] = pal_row[pen];
                M->line_pri[x] = pri;
            }
        }
    }
}

static void irem_render_line(int y, u16 *dst)
{
    int w = S.scr_w;
    u16 bg = M->pal15[0];
    u32 bg32 = (u32)bg | ((u32)bg << 16);
    u32 *d32 = (u32 *)dst;
    for (int i = 0; i < (w >> 1); i++)
        d32[i] = bg32;
    u32 *p32 = (u32 *)M->line_pri;
    for (int i = 0; i < (w + 3) >> 2; i++)
        p32[i] = 0;

    if (S.board == IREM_BOARD_M92) {
        if (S.video_ctrl & 0x04u) irem_draw_tilemap_line(2, y, 0x08u, 0x22u, dst);  /* PF2 back */
        if (S.video_ctrl & 0x01u) irem_draw_tilemap_line(1, y, 0x10u, 0x24u, dst);  /* PF1 mid */
        if (S.video_ctrl & 0x08u) irem_draw_sprites_line(y, dst);
        if (S.video_ctrl & 0x02u) irem_draw_tilemap_line(0, y, 0x30u, 0x38u, dst);  /* PF0 HUD/front */
    } else {
        if (S.video_ctrl & 0x01u) irem_draw_tilemap_line(1, y, 0x10u, 0x24u, dst);  /* M72 BG */
        if (S.video_ctrl & 0x04u) irem_draw_sprites_line(y, dst);
        if (S.video_ctrl & 0x02u) irem_draw_tilemap_line(0, y, 0x20u, 0x34u, dst);  /* M72 FG */
    }
}

/* ============================================================================
   Built-in Playable Irem NEC V30 Arcade Game ("") : "R-FORCE: BYDO ASSAULT"
   Executes genuine NEC V30 x86 machine code ($F000:0000) + Sound Z80 driver
   with dual M72 parallax tilemaps, R-9 Arrowhead + Force Pod + Wave Cannon +
   2x2 Bydo Guardian Core, YM2151 FM soundtrack, and Irem GA20 4-ch PCM SFX!
   ============================================================================ */

static void irem_put_tile_px(u32 t, int x, int y, u8 pen)
{
    u32 *r = &TILE_BUF[t * 8u + (u32)y];
    u32 sh = (u32)x * 4u;
    *r = (*r & ~(0x0Fu << sh)) | ((u32)(pen & 0x0Fu) << sh);
    if (pen) M->tile_nz[t] = 1u;
}

static void irem_put_spr_px(u32 cell, int x, int y, u8 pen)
{
    u32 off = cell * 128u + (u32)y * 8u + (u32)(x >> 1);
    if (x & 1) SPR_BUF[off] = (SPR_BUF[off] & 0x0Fu) | ((u8)(pen & 0x0Fu) << 4);
    else       SPR_BUF[off] = (SPR_BUF[off] & 0xF0u) | (pen & 0x0Fu);
    if (pen) M->spr_nz[cell] = 1u;
}

static void build_builtin_irem_assets(void)
{
    irem_zero(TILE_BUF, 512u * 32u);
    irem_zero(SPR_BUF,  64u * 128u);
    irem_zero(M->tile_nz, 512u);
    irem_zero(M->spr_nz, 64u);
    irem_zero(PCM_BUF, 0x4000u);

    /* BG Tile 1..4: Biomechanical Bydo star/conduit tiles */
    irem_put_tile_px(1u, 3, 3, 2u);
    irem_put_tile_px(2u, 5, 2, 3u); irem_put_tile_px(2u, 5, 3, 1u);
    for (int y = 0; y < 8; y++) {
        for (int x = 0; x < 8; x++) {
            /* Tile 3: Metallic Bydo rib girder */
            u8 p = ((x == 0 || x == 7) ? 5u : (y == 3 || y == 4) ? 6u : 4u);
            irem_put_tile_px(3u, x, y, p);
            /* Tile 4: Glowing organic bio-vein */
            u8 bp = (((x + y) & 3) == 0) ? 8u : 7u;
            irem_put_tile_px(4u, x, y, bp);
            /* Tile 5: Upper/Lower steel ceiling plate */
            irem_put_tile_px(5u, x, y, (y == 0 || y == 7) ? 3u : ((x & 3) == 0 ? 5u : 4u));
        }
    }

    /* ASCII 32..95 HUD Font in Tiles 32..95 */
    for (int ch = 32; ch < 96; ch++) {
        const u8 *gl = font5x7[ch - 32];
        for (int r = 0; r < 7; r++) {
            u8 bits = gl[r];
            for (int c = 0; c < 5; c++) {
                if (bits & (0x10u >> c))
                    irem_put_tile_px((u32)ch, c + 1, r, (r < 3) ? 1u : 9u);
            }
        }
    }

    /* Sprite 0..1 (32x16, cw=2, ch=1): R-9 Arrowhead Fighter! */
    for (int y = 0; y < 16; y++) {
        for (int x = 0; x < 32; x++) {
            u32 cell = (x >= 16) ? 1u : 0u;
            int lx = x & 15;
            int dy = y - 8;
            int ady = dy < 0 ? -dy : dy;
            if (x >= 2 && x <= 29 && ady * 3 <= (30 - x)) {
                u8 pen = 1u;                                        /* Crisp white hull */
                if (x >= 14 && x <= 23 && ady <= 2) pen = 3u;       /* R-9 blue canopy! */
                else if (ady >= 3)                  pen = 2u;       /* Red/blue wing trim */
                else if (x < 6 && ady <= 2)         pen = 6u;       /* Thruster glow */
                irem_put_spr_px(cell, lx, y, pen);
            }
        }
    }

    /* Sprite 2 (16x16): Glowing Orange/Gold Force Pod! */
    for (int y = 0; y < 16; y++) {
        for (int x = 0; x < 16; x++) {
            int dx = x - 7, dy = y - 7, r2 = dx * dx + dy * dy;
            if (r2 <= 36)
                irem_put_spr_px(2u, x, y, (r2 <= 6) ? 1u : (r2 <= 18) ? 6u : 5u);
        }
    }

    /* Sprite 3 (16x16): Charged Wave-Cannon Plasma Surge! */
    for (int y = 3; y <= 12; y++) {
        for (int x = 0; x < 16; x++) {
            int dy = y - 7;
            if (dy < 0) dy = -dy;
            if (dy <= 4)
                irem_put_spr_px(3u, x, y, (dy <= 1) ? 1u : (dy <= 2) ? 3u : 4u);
        }
    }

    /* Sprite 4..7 (32x32, cw=2, ch=2): Bydo Bio-Mechanical Guardian Core! */
    for (int cy = 0; cy < 2; cy++) {
        for (int cx = 0; cx < 2; cx++) {
            u32 cell = 4u + (u32)(cy * 2 + cx);
            for (int y = 0; y < 16; y++) {
                for (int x = 0; x < 16; x++) {
                    int gx = cx * 16 + x - 16;
                    int gy = cy * 16 + y - 16;
                    int r2 = gx * gx + gy * gy;
                    if (r2 <= 235) {
                        u8 pen = 8u;
                        if (r2 <= 26) pen = 6u;
                        else if (r2 <= 60) pen = 5u;
                        else if (((gx ^ gy) & 4) != 0) pen = 7u;
                        irem_put_spr_px(cell, x, y, pen);
                    }
                }
            }
        }
    }

    /* Sprite 8 (16x16): Bio-Explosion Ring */
    for (int y = 0; y < 16; y++)
        for (int x = 0; x < 16; x++) {
            int dx = x - 7, dy = y - 7, r2 = dx * dx + dy * dy;
            if (r2 >= 12 && r2 <= 52)
                irem_put_spr_px(8u, x, y, (r2 < 30) ? 1u : 6u);
        }

    S.tile_count  = 512u;
    S.spr16_count = 64u;
    S.tile_mask   = 511u;
    S.spr16_mask  = 63u;

    /* Synthesize Irem GA20 8-bit unsigned PCM Wave-Cannon & Explosion samples in PCM_BUF (0x00 = end marker!):
       Sample 0 ($0100..$08FF): Wave-Cannon Surge
       Sample 1 ($0900..$14FF): Bydo Core Explosion */
    u32 lfsr = 0xBEE5u;
    for (u32 i = 0; i < 0x07FEu; i++) {
        u32 ph = (i * (220u - (i >> 4))) >> 3;
        int v = 128 + (((ph & 16u) ? 56 : -56) * (int)(0x800u - i) >> 11);
        if (v < 1) v = 1;
        PCM_BUF[0x0100u + i] = (u8)v;
    }
    PCM_BUF[0x08FEu] = 0x00u;

    for (u32 i = 0; i < 0x0BFEu; i++) {
        if ((i & 3u) == 0) lfsr = (lfsr >> 1) ^ ((lfsr & 1u) ? 0xB400u : 0u);
        int v = 128 + (((lfsr & 1u) ? 72 : -72) * (int)(0xC00u - i) >> 12);
        if (v < 1) v = 1;
        PCM_BUF[0x0900u + i] = (u8)v;
    }
    PCM_BUF[0x14FEu] = 0x00u;
    S.pcm_size = 0x2000u;
    S.pcm_mask = 0x1FFFu;
}

static void build_builtin_irem_z80(void)
{
    /* Sound Z80 ROM: drives YM2151 R-Type FM bass/lead + triggers GA20 PCM on NMI latch! */
    irem_zero(ZROM_BUF, 0x2000u);
    static const u8 zp[] = {
        0xF3, 0x31, 0xF0, 0xFF,     /* DI; LD SP, $FFF0 */
        /* Load YM2151 instrument table from $0100 */
        0x21, 0x00, 0x01,
        0x7E, 0xFE, 0xFF, 0x28, 0x09,
        0xD3, 0x00, 0x23, 0x7E, 0xD3, 0x01, 0x23, 0x18, 0xF2,
        /* 16-step R-Type driving FM bass ($0140) & lead ($0150) loop */
        0x0E, 0x00,
        /* step_loop ($0017): */
        0x3E, 0x08, 0xD3, 0x00, 0x3E, 0x00, 0xD3, 0x01,
        0x3E, 0x08, 0xD3, 0x00, 0x3E, 0x01, 0xD3, 0x01,
        0x26, 0x01, 0x79, 0xC6, 0x40, 0x6F,
        0x3E, 0x28, 0xD3, 0x00, 0x7E, 0xD3, 0x01,
        0x79, 0xC6, 0x50, 0x6F,
        0x3E, 0x29, 0xD3, 0x00, 0x7E, 0xD3, 0x01,
        0x3E, 0x08, 0xD3, 0x00, 0x3E, 0x78, 0xD3, 0x01,
        0x3E, 0x08, 0xD3, 0x00, 0x3E, 0x79, 0xD3, 0x01,
        0x11, 0x00, 0x18,
        0x1B, 0x7A, 0xB3, 0x20, 0xFB,
        0x0C, 0x79, 0xE6, 0x0F, 0x4F,
        0xC3, 0x17, 0x00
    };
    for (u32 i = 0; i < sizeof(zp); i++)
        ZROM_BUF[i] = zp[i];

    /* Z80 NMI handler at $0066: reads sound latch IN A,($00) & triggers GA20 Ch 0! */
    static const u8 znmi[] = {
        0xF5,                           /* PUSH AF */
        0xDB, 0x00,                     /* IN A, ($00) */
        0x3E, 0x10, 0xD3, 0x20,         /* GA20 Ch0 start=$0100 (reg0=$10, reg1=$00) */
        0x3E, 0x00, 0xD3, 0x21,
        0x3E, 0x8F, 0xD3, 0x22,         /* GA20 Ch0 end=$08F0 */
        0x3E, 0x00, 0xD3, 0x23,
        0x3E, 0xDC, 0xD3, 0x24,         /* rate */
        0x3E, 0x90, 0xD3, 0x25,         /* vol */
        0x3E, 0x02, 0xD3, 0x26,         /* keyon! */
        0xF1,                           /* POP AF */
        0xED, 0x45                      /* RETN */
    };
    for (u32 i = 0; i < sizeof(znmi); i++)
        ZROM_BUF[0x0066u + i] = znmi[i];

    static const u8 ymp[] = {
        0x20, 0xEA,  0x21, 0xDC,
        0x40, 0x01,  0x48, 0x02,  0x50, 0x01,  0x58, 0x01,
        0x60, 0x16,  0x68, 0x12,  0x70, 0x14,  0x78, 0x08,
        0x80, 0x1F,  0x88, 0x1F,  0x90, 0x1F,  0x98, 0x1F,
        0xA0, 0x0B,  0xA8, 0x0A,  0xB0, 0x0A,  0xB8, 0x08,
        0xE0, 0x2A,  0xE8, 0x2A,  0xF0, 0x2A,  0xF8, 0x1A,
        0x41, 0x12,  0x49, 0x01,  0x51, 0x22,  0x59, 0x01,
        0x61, 0x14,  0x69, 0x0A,  0x71, 0x12,  0x79, 0x0A,
        0x81, 0x1E,  0x89, 0x1E,  0x91, 0x1E,  0x99, 0x1E,
        0xA1, 0x08,  0xA9, 0x06,  0xB1, 0x08,  0xB9, 0x06,
        0xE1, 0x28,  0xE9, 0x18,  0xF1, 0x28,  0xF9, 0x18,
        0xFF
    };
    for (u32 i = 0; i < sizeof(ymp); i++)
        ZROM_BUF[0x0100u + i] = ymp[i];

    static const u8 b_kc[16] = {0x18,0x18,0x28,0x18, 0x1B,0x1B,0x2B,0x1B, 0x1E,0x1E,0x2E,0x1E, 0x20,0x1E,0x1B,0x16};
    static const u8 l_kc[16] = {0x48,0x4B,0x4E,0x54, 0x52,0x4E,0x4B,0x4E, 0x54,0x56,0x58,0x56, 0x54,0x52,0x4E,0x48};
    for (int i = 0; i < 16; i++) {
        ZROM_BUF[0x0140u + i] = b_kc[i];
        ZROM_BUF[0x0150u + i] = l_kc[i];
    }
    S.zrom_size = 0x2000u;
}

static void emit86_b(u8 *m, u32 *p, u8 v)  { m[(*p)++] = v; }
static void emit86_w(u8 *m, u32 *p, u16 v) { m[(*p)++] = (u8)v; m[(*p)++] = (u8)(v >> 8); }
static u32 emit86_jcc(u8 *m, u32 *p, u8 op) { m[(*p)++] = op; u32 at = (*p)++; m[at] = 0; return at; }
static void patch86_jcc(u8 *m, u32 at, u32 dst) { m[at] = (u8)(dst - (at + 1u)); }

static void build_builtin_irem_v30(void)
{
    /* Genuine NEC V30 16-bit Real-Mode Game Program in M->mem[$F0000..$FFFFF]:
       - Reset vector at $FFFF:0000 ($FFFF0) jumps to $F000:0100 ($F0100)
       - Installs VBlank ISR (vector 0x20 -> $0080..$0083 = $F000:0400)
       - Loads 15-bit xBBBBBGGGGGRRRRR palette into $C800:0000 (BG/FG + Sprite palettes!)
       - Builds Bydo biomechanical cavern in BG ($D800:0000) & hangar ceiling/floor + HUD in FG ($D000:0000)
       - VBlank ISR ($F000:0400) updates parallax scroll, reads JAMMA IN AL,00h, moves R-9 + Force Pod,
         fires Wave-Cannon surges (triggering OUT 00h, AL Sound Z80 GA20 SFX!), patrols 2x2 Bydo Core,
         checks hits/explosions, writes $C000:0000 Sprite RAM, and executes OUT 04h, AL Sprite DMA! */
    irem_zero(M->mem, 0x100000u);

    /* Palette data at $F0800 (48 x 16-bit 0BBBBBGGGGGRRRRR words -> 0..15 BG/FG, 32..47 Sprites) */
    static const u16 pal_bg[16] = {
        0x0821, 0x7FFF, 0x5AD6, 0x7E80, 0x2108, 0x39CE, 0x02BF, 0x1C43,
        0x2D87, 0x03FF, 0x7C1F, 0x03E0, 0x001F, 0x7FE0, 0x4E73, 0x7FFF
    };
    /* Sprite palette 0 (offset 0x200 in pal15 = byte 0x400 in $C8000): */
    static const u16 pal_sp[16] = {
        0x0000, 0x7FFF, 0x7C08, 0x7EC0, 0x7FE0, 0x019F, 0x03FF, 0x2D88,
        0x1486, 0x001F, 0x7C1F, 0x03E0, 0x5EF7, 0x39CE, 0x6739, 0x7FFF
    };
    for (int i = 0; i < 16; i++) {
        u32 o0 = 0xF0800u + (u32)i * 2u;
        M->mem[o0] = (u8)pal_bg[i]; M->mem[o0 + 1] = (u8)(pal_bg[i] >> 8);
        u32 o1 = 0xF0820u + (u32)i * 2u;
        M->mem[o1] = (u8)pal_sp[i]; M->mem[o1 + 1] = (u8)(pal_sp[i] >> 8);
    }

    static const char hud[] = "R-FORCE M72     FORCE [ON]     BYDO CORE";
    for (u32 i = 0; i < sizeof(hud); i++)
        M->mem[0xF0860u + i] = (u8)hud[i];

    /* ---- $FFFF0: Hardware Reset Entry -> JMP FAR $F000:$0100 ---- */
    u32 p = 0xFFFF0u;
    emit86_b(M->mem, &p, 0xEA); emit86_w(M->mem, &p, 0x0100); emit86_w(M->mem, &p, 0xF000);

    /* ---- $F0100: Main Initialization ---- */
    p = 0xF0100u;
    emit86_b(M->mem, &p, 0xFA);                                     /* CLI */
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 0xA000);       /* MOV AX, $A000 */
    emit86_b(M->mem, &p, 0x8E); emit86_b(M->mem, &p, 0xD8);         /* MOV DS, AX */
    emit86_b(M->mem, &p, 0x8E); emit86_b(M->mem, &p, 0xD0);         /* MOV SS, AX */
    emit86_b(M->mem, &p, 0xBC); emit86_w(M->mem, &p, 0x3FF0);       /* MOV SP, $3FF0 */

    /* Install IVT Vector 0x20 ($0000:$0080) = $F000:$0400 */
    emit86_b(M->mem, &p, 0x31); emit86_b(M->mem, &p, 0xC0);         /* XOR AX, AX */
    emit86_b(M->mem, &p, 0x8E); emit86_b(M->mem, &p, 0xC0);         /* MOV ES, AX */
    emit86_b(M->mem, &p, 0x26); emit86_b(M->mem, &p, 0xC7); emit86_b(M->mem, &p, 0x06);
    emit86_w(M->mem, &p, 0x0080); emit86_w(M->mem, &p, 0x0400);     /* MOV WORD ES:[$0080], $0400 */
    emit86_b(M->mem, &p, 0x26); emit86_b(M->mem, &p, 0xC7); emit86_b(M->mem, &p, 0x06);
    emit86_w(M->mem, &p, 0x0082); emit86_w(M->mem, &p, 0xF000);     /* MOV WORD ES:[$0082], $F000 */

    /* Copy BG/FG palette ($F000:$0800 -> $C800:$0000) & Sprite palette ($F000:$0820 -> $C800:$0400) */
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 0xF000);
    emit86_b(M->mem, &p, 0x8E); emit86_b(M->mem, &p, 0xD8);         /* DS = $F000 */
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 0xC800);
    emit86_b(M->mem, &p, 0x8E); emit86_b(M->mem, &p, 0xC0);         /* ES = $C800 */
    emit86_b(M->mem, &p, 0xFC);                                     /* CLD */
    emit86_b(M->mem, &p, 0xBE); emit86_w(M->mem, &p, 0x0800);       /* SI = $0800 */
    emit86_b(M->mem, &p, 0x31); emit86_b(M->mem, &p, 0xFF);         /* DI = 0 */
    emit86_b(M->mem, &p, 0xB9); emit86_w(M->mem, &p, 16);           /* CX = 16 */
    emit86_b(M->mem, &p, 0xF3); emit86_b(M->mem, &p, 0xA5);         /* REP MOVSW */
    emit86_b(M->mem, &p, 0xBF); emit86_w(M->mem, &p, 0x0400);       /* DI = $0400 */
    emit86_b(M->mem, &p, 0xB9); emit86_w(M->mem, &p, 16);
    emit86_b(M->mem, &p, 0xF3); emit86_b(M->mem, &p, 0xA5);

    /* Populate BG Tilemap ($D800:0000, 64x32 cells x 4 bytes): stars + bio-veins + tech ribs! */
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 0xD800);
    emit86_b(M->mem, &p, 0x8E); emit86_b(M->mem, &p, 0xC0);         /* ES = $D800 */
    emit86_b(M->mem, &p, 0x31); emit86_b(M->mem, &p, 0xFF);         /* DI = 0 */
    emit86_b(M->mem, &p, 0xB9); emit86_w(M->mem, &p, 2048);         /* CX = 2048 cells */
    u32 l_bg = p;
    /* Row = DI >> 8 (0..31): rows 3..4 & 25..26 = girder (3), rows 27..29 = bio-vein (4), else sparse star */
    emit86_b(M->mem, &p, 0x89); emit86_b(M->mem, &p, 0xFA);         /* MOV DX, DI */
    emit86_b(M->mem, &p, 0x31); emit86_b(M->mem, &p, 0xC0);         /* AX = 0 */
    emit86_b(M->mem, &p, 0x80); emit86_b(M->mem, &p, 0xFE); emit86_b(M->mem, &p, 4); /* CMP DH, 4 */
    u32 b_g1 = emit86_jcc(M->mem, &p, 0x77);
    emit86_b(M->mem, &p, 0x80); emit86_b(M->mem, &p, 0xFE); emit86_b(M->mem, &p, 3);
    u32 b_g2 = emit86_jcc(M->mem, &p, 0x72);
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 3);            /* Tile 3 */
    u32 b_put = emit86_jcc(M->mem, &p, 0xEB);
    patch86_jcc(M->mem, b_g1, p);
    patch86_jcc(M->mem, b_g2, p);
    emit86_b(M->mem, &p, 0x80); emit86_b(M->mem, &p, 0xFE); emit86_b(M->mem, &p, 25);
    u32 b_v1 = emit86_jcc(M->mem, &p, 0x72);
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 4);            /* Tile 4 bio-vein */
    u32 b_put2 = emit86_jcc(M->mem, &p, 0xEB);
    patch86_jcc(M->mem, b_v1, p);
    emit86_b(M->mem, &p, 0xF6); emit86_b(M->mem, &p, 0xC2); emit86_b(M->mem, &p, 0x1C);
    u32 b_nost = emit86_jcc(M->mem, &p, 0x75);
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 1);            /* Tile 1 star */
    patch86_jcc(M->mem, b_nost, p);
    patch86_jcc(M->mem, b_put, p);
    patch86_jcc(M->mem, b_put2, p);
    emit86_b(M->mem, &p, 0xAB);                                     /* STOSW (code) */
    emit86_b(M->mem, &p, 0x31); emit86_b(M->mem, &p, 0xC0);
    emit86_b(M->mem, &p, 0xAB);                                     /* STOSW (attr = pal 0) */
    emit86_b(M->mem, &p, 0xE2); emit86_b(M->mem, &p, (u8)(l_bg - (p + 1u))); /* LOOP l_bg */

    /* Populate FG Tilemap ($D000:0000): HUD banner on row 1 (offset 256 + 4*4 = $0110) */
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 0xD000);
    emit86_b(M->mem, &p, 0x8E); emit86_b(M->mem, &p, 0xC0);         /* ES = $D000 */
    emit86_b(M->mem, &p, 0xBE); emit86_w(M->mem, &p, 0x0860);       /* DS:SI = $F000:$0860 */
    emit86_b(M->mem, &p, 0xBF); emit86_w(M->mem, &p, 0x0110);       /* ES:DI = row 1, col 4 */
    u32 l_hud = p;
    emit86_b(M->mem, &p, 0xAC);                                     /* LODSB */
    emit86_b(M->mem, &p, 0x84); emit86_b(M->mem, &p, 0xC0);         /* TEST AL, AL */
    u32 b_hdone = emit86_jcc(M->mem, &p, 0x74);
    emit86_b(M->mem, &p, 0xB4); emit86_b(M->mem, &p, 0x00);
    emit86_b(M->mem, &p, 0xAB);                                     /* STOSW code */
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 0x0080);       /* high priority HUD */
    emit86_b(M->mem, &p, 0xAB);                                     /* STOSW attr */
    emit86_b(M->mem, &p, 0xEB); emit86_b(M->mem, &p, (u8)(l_hud - (p + 1u)));
    patch86_jcc(M->mem, b_hdone, p);

    /* Restore DS = $A000 & initialize game state in $A000:0000..0020 */
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 0xA000);
    emit86_b(M->mem, &p, 0x8E); emit86_b(M->mem, &p, 0xD8);
    /* [0]=frame, [2]=r9_x(48), [4]=r9_y(112), [6]=beam_x(0xFFFF), [8]=beam_y, [10]=boss_y(88), [12]=boss_dy(1), [14]=expl(0) */
    emit86_b(M->mem, &p, 0xC7); emit86_b(M->mem, &p, 0x06); emit86_w(M->mem, &p, 0x0002); emit86_w(M->mem, &p, 48);
    emit86_b(M->mem, &p, 0xC7); emit86_b(M->mem, &p, 0x06); emit86_w(M->mem, &p, 0x0004); emit86_w(M->mem, &p, 112);
    emit86_b(M->mem, &p, 0xC7); emit86_b(M->mem, &p, 0x06); emit86_w(M->mem, &p, 0x0006); emit86_w(M->mem, &p, 0xFFFF);
    emit86_b(M->mem, &p, 0xC7); emit86_b(M->mem, &p, 0x06); emit86_w(M->mem, &p, 0x000A); emit86_w(M->mem, &p, 88);
    emit86_b(M->mem, &p, 0xC7); emit86_b(M->mem, &p, 0x06); emit86_w(M->mem, &p, 0x000C); emit86_w(M->mem, &p, 1);

    /* Enable BG + FG + Sprites ($8C = 0x07) & STI + HLT idle loop! */
    emit86_b(M->mem, &p, 0xB0); emit86_b(M->mem, &p, 0x07);
    emit86_b(M->mem, &p, 0xE6); emit86_b(M->mem, &p, 0x8C);         /* OUT $8C, AL */
    emit86_b(M->mem, &p, 0xFB);                                     /* STI */
    u32 l_hlt = p;
    emit86_b(M->mem, &p, 0xF4);                                     /* HLT */
    emit86_b(M->mem, &p, 0xEB); emit86_b(M->mem, &p, (u8)(l_hlt - (p + 1u)));

    /* ---- $F0400: VBlank Interrupt Service Routine (55 Hz Game Update!) ---- */
    p = 0xF0400u;
    emit86_b(M->mem, &p, 0x60);                                     /* PUSHA (V30!) */
    emit86_b(M->mem, &p, 0x1E);                                     /* PUSH DS */
    emit86_b(M->mem, &p, 0x06);                                     /* PUSH ES */
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 0xA000);
    emit86_b(M->mem, &p, 0x8E); emit86_b(M->mem, &p, 0xD8);         /* DS = $A000 */

    /* 1. Advance frame & BG Scroll X ($84/$85) */
    emit86_b(M->mem, &p, 0xFF); emit86_b(M->mem, &p, 0x06); emit86_w(M->mem, &p, 0x0000); /* INC WORD [0] */
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x0000);       /* MOV AX, [0] */
    emit86_b(M->mem, &p, 0xD1); emit86_b(M->mem, &p, 0xE0);         /* SHL AX, 1 */
    emit86_b(M->mem, &p, 0xE7); emit86_b(M->mem, &p, 0x84);         /* OUT $84, AX (BG Scroll X!) */

    /* 2. Read JAMMA P1 input IN AL, 00h (active LOW) -> invert into BL */
    emit86_b(M->mem, &p, 0xE4); emit86_b(M->mem, &p, 0x00);         /* IN AL, $00 */
    emit86_b(M->mem, &p, 0xF6); emit86_b(M->mem, &p, 0xD0);         /* NOT AL */
    emit86_b(M->mem, &p, 0x88); emit86_b(M->mem, &p, 0xC3);         /* MOV BL, AL */
    emit86_b(M->mem, &p, 0x84); emit86_b(M->mem, &p, 0xDB);         /* TEST BL, BL */
    u32 b_man = emit86_jcc(M->mem, &p, 0x75);
    /* Attract AI weave & Wave-Cannon fire */
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x0000);
    emit86_b(M->mem, &p, 0xA8); emit86_b(M->mem, &p, 0x40);
    u32 b_adn = emit86_jcc(M->mem, &p, 0x74);
    emit86_b(M->mem, &p, 0xB3); emit86_b(M->mem, &p, 0x88);         /* Up + Fire */
    u32 b_aend = emit86_jcc(M->mem, &p, 0xEB);
    patch86_jcc(M->mem, b_adn, p);
    emit86_b(M->mem, &p, 0xB3); emit86_b(M->mem, &p, 0x84);         /* Down + Fire */
    patch86_jcc(M->mem, b_aend, p);
    patch86_jcc(M->mem, b_man, p);

    /* Move R-9 Fighter ([2]=x, [4]=y) */
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x0002);       /* AX = r9_x */
    emit86_b(M->mem, &p, 0xF6); emit86_b(M->mem, &p, 0xC3); emit86_b(M->mem, &p, 0x01); /* Right? */
    u32 b_nr = emit86_jcc(M->mem, &p, 0x74);
    emit86_b(M->mem, &p, 0x05); emit86_w(M->mem, &p, 2);
    emit86_b(M->mem, &p, 0x3D); emit86_w(M->mem, &p, 220);
    u32 b_rok = emit86_jcc(M->mem, &p, 0x7E);
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 220);
    patch86_jcc(M->mem, b_rok, p);
    patch86_jcc(M->mem, b_nr, p);

    emit86_b(M->mem, &p, 0xF6); emit86_b(M->mem, &p, 0xC3); emit86_b(M->mem, &p, 0x02); /* Left? */
    u32 b_nl = emit86_jcc(M->mem, &p, 0x74);
    emit86_b(M->mem, &p, 0x2D); emit86_w(M->mem, &p, 2);
    emit86_b(M->mem, &p, 0x3D); emit86_w(M->mem, &p, 16);
    u32 b_lok = emit86_jcc(M->mem, &p, 0x7D);
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 16);
    patch86_jcc(M->mem, b_lok, p);
    patch86_jcc(M->mem, b_nl, p);
    emit86_b(M->mem, &p, 0xA3); emit86_w(M->mem, &p, 0x0002);

    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x0004);       /* AX = r9_y */
    emit86_b(M->mem, &p, 0xF6); emit86_b(M->mem, &p, 0xC3); emit86_b(M->mem, &p, 0x08); /* Up? */
    u32 b_nu = emit86_jcc(M->mem, &p, 0x74);
    emit86_b(M->mem, &p, 0x2D); emit86_w(M->mem, &p, 1);
    emit86_b(M->mem, &p, 0x3D); emit86_w(M->mem, &p, 44);
    u32 b_uok = emit86_jcc(M->mem, &p, 0x7D);
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 44);
    patch86_jcc(M->mem, b_uok, p);
    patch86_jcc(M->mem, b_nu, p);

    emit86_b(M->mem, &p, 0xF6); emit86_b(M->mem, &p, 0xC3); emit86_b(M->mem, &p, 0x04); /* Down? */
    u32 b_nd = emit86_jcc(M->mem, &p, 0x74);
    emit86_b(M->mem, &p, 0x05); emit86_w(M->mem, &p, 1);
    emit86_b(M->mem, &p, 0x3D); emit86_w(M->mem, &p, 176);
    u32 b_dok = emit86_jcc(M->mem, &p, 0x7E);
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 176);
    patch86_jcc(M->mem, b_dok, p);
    patch86_jcc(M->mem, b_nd, p);
    emit86_b(M->mem, &p, 0xA3); emit86_w(M->mem, &p, 0x0004);

    /* 3. Wave-Cannon Beam ([6]=beam_x, [8]=beam_y) */
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x0006);
    emit86_b(M->mem, &p, 0x3D); emit86_w(M->mem, &p, 0xFFFF);
    u32 b_spawn_b = emit86_jcc(M->mem, &p, 0x74);
    emit86_b(M->mem, &p, 0x05); emit86_w(M->mem, &p, 8);            /* beam_x += 8 */
    emit86_b(M->mem, &p, 0x3D); emit86_w(M->mem, &p, 384);
    u32 b_bin = emit86_jcc(M->mem, &p, 0x7C);
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 0xFFFF);
    patch86_jcc(M->mem, b_bin, p);
    emit86_b(M->mem, &p, 0xA3); emit86_w(M->mem, &p, 0x0006);
    u32 b_bdone = emit86_jcc(M->mem, &p, 0xEB);

    patch86_jcc(M->mem, b_spawn_b, p);
    emit86_b(M->mem, &p, 0xF6); emit86_b(M->mem, &p, 0xC3); emit86_b(M->mem, &p, 0x80);
    u32 b_nofire = emit86_jcc(M->mem, &p, 0x74);
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x0002);
    emit86_b(M->mem, &p, 0x05); emit86_w(M->mem, &p, 48);
    emit86_b(M->mem, &p, 0xA3); emit86_w(M->mem, &p, 0x0006);
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x0004);
    emit86_b(M->mem, &p, 0xA3); emit86_w(M->mem, &p, 0x0008);
    /* Trigger Sound Z80 GA20 Wave-Cannon PCM via OUT 00h, AL! */
    emit86_b(M->mem, &p, 0xB0); emit86_b(M->mem, &p, 0x01);
    emit86_b(M->mem, &p, 0xE6); emit86_b(M->mem, &p, 0x00);
    patch86_jcc(M->mem, b_nofire, p);
    patch86_jcc(M->mem, b_bdone, p);

    /* 4. Bydo Guardian Core patrol ([10]=boss_y, [12]=boss_dy) + hit check */
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x000A);
    emit86_b(M->mem, &p, 0x03); emit86_b(M->mem, &p, 0x06); emit86_w(M->mem, &p, 0x000C);
    emit86_b(M->mem, &p, 0x3D); emit86_w(M->mem, &p, 48);
    u32 b_bmin = emit86_jcc(M->mem, &p, 0x7D);
    emit86_b(M->mem, &p, 0xC7); emit86_b(M->mem, &p, 0x06); emit86_w(M->mem, &p, 0x000C); emit86_w(M->mem, &p, 1);
    patch86_jcc(M->mem, b_bmin, p);
    emit86_b(M->mem, &p, 0x3D); emit86_w(M->mem, &p, 152);
    u32 b_bmax = emit86_jcc(M->mem, &p, 0x7E);
    emit86_b(M->mem, &p, 0xC7); emit86_b(M->mem, &p, 0x06); emit86_w(M->mem, &p, 0x000C); emit86_w(M->mem, &p, 0xFFFF);
    patch86_jcc(M->mem, b_bmax, p);
    emit86_b(M->mem, &p, 0xA3); emit86_w(M->mem, &p, 0x000A);

    /* Check Wave-Cannon hit against Bydo Core at X=300 */
    emit86_b(M->mem, &p, 0x81); emit86_b(M->mem, &p, 0x3E); emit86_w(M->mem, &p, 0x0006); emit86_w(M->mem, &p, 290);
    u32 b_nh1 = emit86_jcc(M->mem, &p, 0x7C);
    emit86_b(M->mem, &p, 0x81); emit86_b(M->mem, &p, 0x3E); emit86_w(M->mem, &p, 0x0006); emit86_w(M->mem, &p, 336);
    u32 b_nh2 = emit86_jcc(M->mem, &p, 0x7F);
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x0008);
    emit86_b(M->mem, &p, 0x2B); emit86_b(M->mem, &p, 0x06); emit86_w(M->mem, &p, 0x000A);
    emit86_b(M->mem, &p, 0x05); emit86_w(M->mem, &p, 8);
    emit86_b(M->mem, &p, 0x3D); emit86_w(M->mem, &p, 36);
    u32 b_nh3 = emit86_jcc(M->mem, &p, 0x77);
    emit86_b(M->mem, &p, 0xC7); emit86_b(M->mem, &p, 0x06); emit86_w(M->mem, &p, 0x0006); emit86_w(M->mem, &p, 0xFFFF);
    emit86_b(M->mem, &p, 0xC7); emit86_b(M->mem, &p, 0x06); emit86_w(M->mem, &p, 0x000E); emit86_w(M->mem, &p, 14);
    patch86_jcc(M->mem, b_nh1, p);
    patch86_jcc(M->mem, b_nh2, p);
    patch86_jcc(M->mem, b_nh3, p);

    /* 5. Write Sprite RAM ($C000:0000) & Trigger OUT 04h Sprite DMA! */
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 0xC000);
    emit86_b(M->mem, &p, 0x8E); emit86_b(M->mem, &p, 0xC0);         /* ES = $C000 */
    emit86_b(M->mem, &p, 0x31); emit86_b(M->mem, &p, 0xFF);         /* DI = 0 */

    /* Sprite 0: R-9 Fighter (2x1 = cw=2 -> attr=$1000, code=0) */
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x0004); emit86_b(M->mem, &p, 0xAB); /* y */
    emit86_b(M->mem, &p, 0x31); emit86_b(M->mem, &p, 0xC0);   emit86_b(M->mem, &p, 0xAB); /* code=0 */
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 0x1000); emit86_b(M->mem, &p, 0xAB); /* cw=2 */
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x0002); emit86_b(M->mem, &p, 0xAB); /* x */

    /* Sprite 1: Force Pod attached +34 px ahead of R-9 nose (code=2) */
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x0004); emit86_b(M->mem, &p, 0xAB);
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 2);      emit86_b(M->mem, &p, 0xAB);
    emit86_b(M->mem, &p, 0x31); emit86_b(M->mem, &p, 0xC0);   emit86_b(M->mem, &p, 0xAB);
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x0002);
    emit86_b(M->mem, &p, 0x05); emit86_w(M->mem, &p, 34);     emit86_b(M->mem, &p, 0xAB);

    /* Sprite 2: Bydo Guardian Core (2x2 -> cw=2, ch=2 -> attr=$1400, code=4, X=300) */
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x000A); emit86_b(M->mem, &p, 0xAB);
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 4);      emit86_b(M->mem, &p, 0xAB);
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 0x1400); emit86_b(M->mem, &p, 0xAB);
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 300);    emit86_b(M->mem, &p, 0xAB);

    /* Sprite 3: Wave-Cannon Plasma Surge (code=3, 1x1 -> attr=$0000) */
    emit86_b(M->mem, &p, 0x83); emit86_b(M->mem, &p, 0x3E); emit86_w(M->mem, &p, 0x0006); emit86_b(M->mem, &p, 0xFF);
    u32 b_nbspr = emit86_jcc(M->mem, &p, 0x74);
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x0008); emit86_b(M->mem, &p, 0xAB);
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 3);      emit86_b(M->mem, &p, 0xAB);
    emit86_b(M->mem, &p, 0x31); emit86_b(M->mem, &p, 0xC0);   emit86_b(M->mem, &p, 0xAB);
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x0006); emit86_b(M->mem, &p, 0xAB);
    u32 b_bspr_dn = emit86_jcc(M->mem, &p, 0xEB);
    patch86_jcc(M->mem, b_nbspr, p);
    emit86_b(M->mem, &p, 0x31); emit86_b(M->mem, &p, 0xC0);
    emit86_b(M->mem, &p, 0xAB); emit86_b(M->mem, &p, 0xAB); emit86_b(M->mem, &p, 0xAB); emit86_b(M->mem, &p, 0xAB);
    patch86_jcc(M->mem, b_bspr_dn, p);

    /* Sprite 4: Explosion Ring on Bydo Core when [14] > 0 */
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x000E);
    emit86_b(M->mem, &p, 0x85); emit86_b(M->mem, &p, 0xC0);
    u32 b_noex = emit86_jcc(M->mem, &p, 0x74);
    emit86_b(M->mem, &p, 0xFF); emit86_b(M->mem, &p, 0x0E); emit86_w(M->mem, &p, 0x000E);
    emit86_b(M->mem, &p, 0xA1); emit86_w(M->mem, &p, 0x000A);
    emit86_b(M->mem, &p, 0x05); emit86_w(M->mem, &p, 8);      emit86_b(M->mem, &p, 0xAB);
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 8);      emit86_b(M->mem, &p, 0xAB);
    emit86_b(M->mem, &p, 0x31); emit86_b(M->mem, &p, 0xC0);   emit86_b(M->mem, &p, 0xAB);
    emit86_b(M->mem, &p, 0xB8); emit86_w(M->mem, &p, 296);    emit86_b(M->mem, &p, 0xAB);
    u32 b_exdn = emit86_jcc(M->mem, &p, 0xEB);
    patch86_jcc(M->mem, b_noex, p);
    emit86_b(M->mem, &p, 0x31); emit86_b(M->mem, &p, 0xC0);
    emit86_b(M->mem, &p, 0xAB); emit86_b(M->mem, &p, 0xAB); emit86_b(M->mem, &p, 0xAB); emit86_b(M->mem, &p, 0xAB);
    patch86_jcc(M->mem, b_exdn, p);

    /* Trigger Sprite DMA (OUT 04h, AL) & return from interrupt! */
    emit86_b(M->mem, &p, 0xE6); emit86_b(M->mem, &p, 0x04);         /* OUT $04, AL */
    emit86_b(M->mem, &p, 0x07);                                     /* POP ES */
    emit86_b(M->mem, &p, 0x1F);                                     /* POP DS */
    emit86_b(M->mem, &p, 0x61);                                     /* POPA (V30!) */
    emit86_b(M->mem, &p, 0xCF);                                     /* IRET */
}

/* ============================================================================
   MAME .zip Romset Detection & Loader (Irem M72 & M92)
   ============================================================================ */

int irem_is_zip(const u8 *zip, u32 size, const char *name)
{
    if (!zip_is(zip, size))
        return 0;
    static const char *const irem_sets[] = {
        "rtype", "nspirit", "imgfight", "mrheli", "loht", "dbreed", "hharry", "gallop",
        "inthunt", "uccops", "gunforce", "bmaster", "mysticri", "hook", "nbbatman", "lethalth", 0
    };
    for (int i = 0; irem_sets[i]; i++)
        if (irem_ci_has(name, irem_sets[i]))
            return 1;

    u32 cnt = zip_count(zip, size);
    char mname[96];
    u32 msz = 0;
    for (u32 i = 0; i < cnt; i++) {
        if (zip_unpack_at(zip, size, i, 0, 0, &msz, mname, sizeof(mname)) != 0)
            continue;
        if (irem_ci_has(mname, "board_m72") || irem_ci_has(mname, "board_m92") ||
            irem_ci_has(mname, "rt-c0") || irem_ci_has(mname, "m72_") || irem_ci_has(mname, "m92_"))
            return 1;
    }
    return 0;
}

static u32 irem_pow2_mask(u32 sz)
{
    if (!sz) return 0;
    u32 p2 = 1u;
    while (p2 < sz && p2 < 0x40000000u)
        p2 <<= 1;
    return p2 - 1u;
}

static void irem_decode_packed_tiles(const u8 *src, u32 sz)
{
    u32 n = sz / 32u;
    if (n > IREM_MAX_TILES) n = IREM_MAX_TILES;
    for (u32 t = 0; t < n; t++) {
        const u8 *p = src + t * 32u;
        u8 nz = 0;
        for (int y = 0; y < 8; y++) {
            u32 r32 = 0;
            for (int x = 0; x < 8; x += 2) {
                u8 b = p[y * 4 + (x >> 1)];
                u8 p0 = b >> 4, p1 = b & 0x0Fu;
                nz |= p0 | p1;
                r32 |= ((u32)p0 << (x * 4)) | ((u32)p1 << ((x + 1) * 4));
            }
            TILE_BUF[t * 8u + (u32)y] = r32;
        }
        M->tile_nz[t] = nz ? 1u : 0u;
    }
    S.tile_count = n;
    S.tile_mask  = irem_pow2_mask(n);
}

static void irem_decode_packed_sprites(const u8 *src, u32 sz)
{
    u32 n = sz / 128u;
    if (n > IREM_MAX_SPR16) n = IREM_MAX_SPR16;
    for (u32 c = 0; c < n; c++) {
        const u8 *p = src + c * 128u;
        u8 *d = SPR_BUF + c * 128u;
        u8 nz = 0;
        for (int i = 0; i < 128; i++) {
            u8 b = p[i];
            u8 sw = (u8)((b >> 4) | (b << 4));
            nz |= sw;
            d[i] = sw;
        }
        M->spr_nz[c] = nz ? 1u : 0u;
    }
    S.spr16_count = n;
    S.spr16_mask  = irem_pow2_mask(n);
}

static const char *irem_load_zip(const u8 *zip, u32 size, const char *path)
{
    u32 cnt = zip_count(zip, size);
    if (!cnt)
        return "corrupt Irem M72/M92 .zip archive";

    irem_zero(M->mem, sizeof(M->mem));
    irem_zero(ZROM_BUF, IREM_ZROM_CAP);
    irem_zero(PCM_BUF,  0x80000u);
    irem_zero(M->tile_nz, sizeof(M->tile_nz));
    irem_zero(M->spr_nz,  sizeof(M->spr_nz));

    S.board = IREM_BOARD_M72;
    S.scr_w = 384;
    S.scr_h = 240;
    if (irem_ci_has(path, "inthunt") || irem_ci_has(path, "uccops") ||
        irem_ci_has(path, "gunforce") || irem_ci_has(path, "m92") ||
        irem_ci_has(path, "bmaster")  || irem_ci_has(path, "nbbatman")) {
        S.board = IREM_BOARD_M92;
        S.scr_w = 320;
        S.scr_h = 240;
    }

    u8 *split_lo = ZIP_STAGE + 0x200000u;
    u8 *split_hi = ZIP_STAGE + 0x300000u;
    u32 got_lo = 0, got_hi = 0;
    char mname[96];
    u32 msz = 0;

    for (u32 i = 0; i < cnt; i++) {
        IREM_POLL();
        if (zip_unpack_at(zip, size, i, 0, 0, &msz, mname, sizeof(mname)) != 0 || !msz)
            continue;
        if (irem_ci_has(mname, "board_m92")) {
            S.board = IREM_BOARD_M92; S.scr_w = 320; S.scr_h = 240;
            continue;
        }
        if (irem_ci_has(mname, "board_m72")) {
            S.board = IREM_BOARD_M72; S.scr_w = 384; S.scr_h = 240;
            continue;
        }
        if (msz > 0x200000u)
            continue;
        if (zip_unpack_at(zip, size, i, ZIP_STAGE, 0x200000u, &msz, mname, sizeof(mname)) != 0)
            continue;

        if (irem_ci_ends(mname, "v30.rom") || irem_ci_ends(mname, "v33.rom") || irem_ci_ends(mname, "main.rom")) {
            u32 cap = msz < 0x100000u ? msz : 0x100000u;
            u32 dst0 = (cap <= 0x20000u) ? (0x100000u - cap) : 0u;
            for (u32 k = 0; k < cap; k++)
                M->mem[dst0 + k] = ZIP_STAGE[k];
            S.rom_size = 0x100000u;
        } else if (irem_ci_ends(mname, "z80.rom") || irem_ci_ends(mname, "sound.rom") || irem_ci_has(mname, "_sp")) {
            u32 cap = msz < IREM_ZROM_CAP ? msz : IREM_ZROM_CAP;
            for (u32 k = 0; k < cap; k++)
                ZROM_BUF[k] = ZIP_STAGE[k];
            S.zrom_size = cap;
        } else if (irem_ci_ends(mname, "tiles.rom")) {
            irem_decode_packed_tiles(ZIP_STAGE, msz);
        } else if (irem_ci_ends(mname, "sprites.rom")) {
            irem_decode_packed_sprites(ZIP_STAGE, msz);
        } else if (irem_ci_ends(mname, "ga20.rom") || irem_ci_ends(mname, "pcm.rom") || irem_ci_has(mname, "vo")) {
            u32 cap = msz < IREM_PCM_CAP ? msz : IREM_PCM_CAP;
            for (u32 k = 0; k < cap; k++)
                PCM_BUF[k] = ZIP_STAGE[k];
            S.pcm_size = cap;
        } else if (!got_lo && (irem_ci_has(mname, "l0") || irem_ci_has(mname, "_l."))) {
            u32 cap = msz < 0x80000u ? msz : 0x80000u;
            for (u32 k = 0; k < cap; k++) split_lo[k] = ZIP_STAGE[k];
            got_lo = cap;
        } else if (!got_hi && (irem_ci_has(mname, "h0") || irem_ci_has(mname, "_h."))) {
            u32 cap = msz < 0x80000u ? msz : 0x80000u;
            for (u32 k = 0; k < cap; k++) split_hi[k] = ZIP_STAGE[k];
            got_hi = cap;
        }
    }

    if (!S.rom_size && got_lo && got_hi) {
        /* Interleave MAME split 16-bit NEC V30/V33 ROM pair (even=l0, odd=h0) */
        u32 pairs = got_lo < got_hi ? got_lo : got_hi;
        u32 total = pairs * 2u;
        u32 dst0 = (total <= 0x80000u) ? (0x100000u - total) : 0u;
        for (u32 k = 0; k < pairs && dst0 + k * 2u + 1u < 0x100000u; k++) {
            M->mem[dst0 + k * 2u]     = split_lo[k];
            M->mem[dst0 + k * 2u + 1] = split_hi[k];
        }
        if (dst0 > 0) {
            for (u32 k = 0x01000u; k < total && k < 0x40000u; k++)
                M->mem[k] = M->mem[dst0 + k];
        }
        S.rom_size = 0x100000u;
    }

    if (!S.rom_size)
        return "no recognizable Irem M72/M92 NEC V30/V33 ROMs found in .zip";

    S.pcm_mask = irem_pow2_mask(S.pcm_size);
    const char *tag = (S.board == IREM_BOARD_M92)
        ? "Irem M92 (NEC V33 + 3x Rowscroll PF + YM2151 + GA20 PCM)"
        : "Irem M72 (NEC V30 + Z80 + Dual Tilemaps + YM2151)";
    int n = 0;
    for (; tag[n] && n < (int)sizeof(S.info) - 1; n++)
        S.info[n] = tag[n];
    S.info[n] = 0;
    return 0;
}

/* ============================================================================
   Lifecycle & 55 Hz Frame Execution
   ============================================================================ */

void irem_reset(void)
{
    irem_zero(&M->mem[0x00000], 0x01000u);
    irem_zero(&M->mem[0x40000], 0x08000u);
    irem_zero(&M->mem[0xA0000], 0x40000u);
    irem_zero(M->spr_dma, sizeof(M->spr_dma));
    irem_zero(M->pal15,   sizeof(M->pal15));
    irem_zero(M->zram,    sizeof(M->zram));
    irem_zero(S.scroll_x, sizeof(S.scroll_x));
    irem_zero(S.scroll_y, sizeof(S.scroll_y));
    irem_zero(S.m92_pf_ctrl, sizeof(S.m92_pf_ctrl));
    irem_zero(S.ga20_regs, sizeof(S.ga20_regs));
    irem_zero(S.ga20, sizeof(S.ga20));

    S.vblank_vec = 0x20u;
    S.raster_vec = 0x22u;
    S.raster_irq_line = 0;
    S.raster_irq_en = 0;
    S.video_ctrl = 0x0Fu;
    S.m72_dac = 0;
    S.snd_head = S.snd_tail = 0;
    S.jammed = 0;
    S.frame_no = 0;

    x86_reset(&VCPU, 1);    /* NEC V30 / V33 mode */

    irem_zero(&M->zcpu, sizeof(M->zcpu));
    z80_init(&M->zcpu);
    M->zcpu.read  = irem_z80_read;
    M->zcpu.write = irem_z80_write;
    M->zcpu.in    = irem_z80_in;
    M->zcpu.out   = irem_z80_out;
    M->zcpu.trap  = -1;
    irem_setup_z80_map();
    z80_reset(&M->zcpu);

    ym2151_init(&M->opm, 3579545u, S.sample_rate ? S.sample_rate : 48000u);
}

const char *irem_load(const u8 *image, u32 size, const char *path)
{
    u32 keep_rate = S.sample_rate;
    if (keep_rate != 48000u && keep_rate != 44100u && keep_rate != 32000u && keep_rate != 22050u)
        keep_rate = 48000u;
    irem_zero(&S, sizeof(S));
    S.sample_rate = keep_rate;

    if (!path || !*path || !image || size == 0) {
        S.board = IREM_BOARD_M72;
        S.scr_w = 384;
        S.scr_h = 240;
        build_builtin_irem_assets();
        build_builtin_irem_z80();
        build_builtin_irem_v30();
        S.rom_size = 0x100000u;
        static const char bi[] = "R-Force: Bydo Assault (Built-in Irem M72 NEC V30 + Z80 + YM2151 + GA20)";
        for (u32 i = 0; i < sizeof(bi); i++)
            S.info[i] = bi[i];
        irem_reset();
        return 0;
    }

    if (zip_is(image, size)) {
        const char *err = irem_load_zip(image, size, path);
        if (err) return err;
        irem_reset();
        return 0;
    }

    return "expected an Irem M72 or M92 arcade .zip romset";
}

void irem_pad2(u16 pad)
{
    S.pad2 = pad;
}

void irem_frame(u16 pad, u16 *picture)
{
    S.pad1 = pad;
    u8 coin_now = (pad & 0x0004u) ? 1u : 0u;
    if (coin_now && !S.coin_prev)
        S.coin_pulse = 5u;
    S.coin_prev = coin_now;

    /* 284 scanlines @ 55.00 Hz (240 visible + 44 VBlank):
       - NEC V30/V33 @ ~8.5 MHz (~540 cycles/scanline)
       - Sound Z80 @ 3.58 MHz (~229 cycles/scanline) */
    const int total_lines = 284;
    const int vis_h = S.scr_h;
    u32 target_samples = (S.sample_rate ? S.sample_rate : 48000u) / 55u;
    u32 samp_acc = 0;

    VCPU.cycles = 0;
    M->zcpu.cycles = 0;

    /* Collect active sprites once per frame (reverse painter order so sprite 0 has highest priority) */
    S.n_act_spr = 0;
    if (picture) {
        for (int s = 255; s >= 0; s--) {
            if (M->spr_dma[s * 4] != 0)
                S.act_spr[S.n_act_spr++] = (u8)s;
        }
    }

    for (int line = 0; line < total_lines; line++) {
        S.cur_scanline = line;
        x86_run(&VCPU, (line + 1) * 540);

        if (S.zrom_size > 0) {
            z80_run(&M->zcpu, (line + 1) * 229);
            if (ym2151_tick_timers(&M->opm, 229, 3579545u))
                M->zcpu.irq = 1;
        }

        if (S.raster_irq_en && (u16)line == S.raster_irq_line)
            (void)x86_irq(&VCPU, S.raster_vec);

        if (line < vis_h && picture)
            irem_render_line(line, picture + (u32)line * (u32)S.scr_w);

        if (line == vis_h)
            (void)x86_irq(&VCPU, S.vblank_vec);

        samp_acc += target_samples;
        while (samp_acc >= (u32)total_lines) {
            samp_acc -= (u32)total_lines;
            s32 fm_l = 0, fm_r = 0;
            ym2151_sample_48khz(&M->opm, &fm_l, &fm_r);
            s32 mix = ((fm_l + fm_r) >> 1) + ga20_step_48k() + S.m72_dac;
            if (mix > 32767) mix = 32767;
            else if (mix < -32768) mix = -32768;
            if (S.snd_head - S.snd_tail < IREM_SND_RING)
                M->snd_ring[S.snd_head++ & (IREM_SND_RING - 1u)] = (s16)mix;
        }
    }

    if (S.coin_pulse > 0)
        S.coin_pulse--;
    S.frame_no++;
}

int irem_width(void)  { return S.scr_w ? S.scr_w : 384; }
int irem_height(void) { return S.scr_h ? S.scr_h : 240; }
const char *irem_info(void) { return S.info; }

u8 *irem_save_ram(u32 *size, int *battery)
{
    if (size) *size = 0;
    if (battery) *battery = 0;
    return 0;
}

int irem_save_changed(void) { return 0; }
int irem_jammed(void)       { return S.jammed; }

void irem_audio_rate(u32 hz)
{
    S.sample_rate = hz ? hz : 48000u;
    M->opm.sample_rate = S.sample_rate;
}

int irem_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && S.snd_tail != S.snd_head)
        out[n++] = M->snd_ring[S.snd_tail++ & (IREM_SND_RING - 1u)];
    return n;
}
