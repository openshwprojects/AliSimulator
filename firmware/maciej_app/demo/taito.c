/* Taito Classic & F2 / B-System Multi-Board Arcade Emulator: see taito.h.
   Zero static .bss (68000 + optab, Main Z80, Sound Z80, YM2151, YM2203/YM2610
   FM/SSG/ADPCM, TC0100SCN/TC0200OBJ/PC080SN/PC090OJ/Bubble-Bobble VRAM & audio
   ring live in EMU_RAM_PHYS; decoded tiles, sprites, ROMs & PCM samples live in
   upper physical RAM). */
#include "taito.h"
#include "z80.h"
#include "zip.h"
#include "font5x7.h"

#ifndef TAITO_HOST
#include "hw.h"
#endif

typedef signed char s8;
#define INLINE static inline __attribute__((always_inline))

enum {
    TAITO_BOARD_F2     = 0, /* 68000 + Z80 + TC0100SCN + TC0200OBJ + YM2151/YM2610 ADPCM (Puzzle Bobble, Liquid Kids, Final Blow) */
    TAITO_BOARD_RASTAN = 1, /* 68000 + Z80 + PC080SN + PC090OJ + YM2151 + ADPCM (Rastan, Rainbow Islands, Operation Wolf) */
    TAITO_BOARD_Z80    = 2  /* Dual Z80 + Bubble Bobble / SETA X1-001 video + MCU HLE + YM2203 (Bubble Bobble, The NewZealand Story) */
};

#define TAITO_SND_RING   8192
#define TAITO_MAX_TILES  65536u         /* 65,536 8x8 4bpp tiles (2 MB pre-decoded u32x8) */
#define TAITO_MAX_SPR16  65536u         /* 65,536 16x16 4bpp sprite cells (8 MB nibble-packed 128 B/cell) */
#define TAITO_ROM_CAP    0x00400000u    /* 4 MB 68000 / Main Z80 Program ROM */
#define TAITO_ZROM_CAP   0x00040000u    /* 256 KB Sound Z80 ROM */
#define TAITO_PCM_CAP    0x00400000u    /* 4 MB YM2610 / ADPCM Sample ROM */
#define TAITO_STAGE_CAP  0x00500000u    /* 5 MB MAME .zip unpack staging */

#pragma GCC push_options
#pragma GCC optimize("O2")
#include "ym2151.inc"
#pragma GCC pop_options

/* 6-Channel YM2610 / OKI / Taito ADPCM-A & PCM Voice */
struct taito_pcm_ch {
    u32 start, end, pos_frac;
    u32 step_48k;
    u8  vol, playing, adpcm4;
    s16 adpcm_acc;
    s8  adpcm_step;
};

/* 3-Channel SSG (AY-3-8910 / YM2203 / YM2610 SSG section) */
struct taito_ssg {
    u8  sel, regs[16], out[3];
    u32 cnt[3], ncnt, lfsr;
};

struct taito_state {
    u8  board;
    u8  jammed;
    int scr_w, scr_h;
    u16 pad1, pad2;
    u8  coin_prev, coin_pulse;
    u32 rom_size, zrom_size, pcm_size, pcm_mask;
    u32 tile_count, spr16_count;
    u32 tile_mask, spr16_mask;
    u32 frame_no;

    /* TC0100SCN & PC080SN Registers */
    u16 scn_ctrl[8];            /* [0]=BG0_X, [1]=FG0_X, [2]=BG0_Y, [3]=FG0_Y, [4]=TX_X, [5]=TX_Y, [6..7]=Ctrl */
    u16 pc080_scrollx[2];
    u16 pc080_scrolly[2];
    u16 pc080_ctrl;

    /* TC0140SYT / PC060HA Master <-> Sound Z80 Nibble Communication */
    u8  syt_mode;
    u8  syt_main2sub[4];
    u8  syt_sub2main[4];
    u8  syt_status;             /* bit 0 = main->sub ready, bit 2 = sub->main ready */

    /* Z80 Board Banking (Bubble Bobble / TNZS) */
    u8  z80_rombank;
    u8  z80_vidctrl;

    /* Active Sprite Pre-Filter */
    u16 act_spr[512];
    int n_act_spr;

    /* Audio (Sound Z80 + YM2151 / YM2203 / YM2610 + 6-ch ADPCM + SSG) */
    u32 sample_rate;
    u8  ym_port_sel;
    u8  adpcm_tl;               /* YM2610 ADPCM-A master total level */
    u8  adpcm_regs[32];
    struct taito_pcm_ch pcm[6];
    struct taito_ssg ssg;
    u32 snd_head, snd_tail;

    char info[96];
};

static void taito_iack(u32 level);
#define M68K_IACK(level) taito_iack(level)

#define M68K_EXTERNAL_STATE                                                     \
    struct taito_mem {                                                          \
        struct taito_state st;                                                  \
        struct m68k m_cpu;                                                      \
        u8 *m_rmap[256];                                                        \
        u8 *m_wmap[256];                                                        \
        u8  m_optab[65536];                                                     \
        struct z80 zmain;               /* Bubble Bobble / TNZS Main Z80 */     \
        struct z80 zsnd;                /* Sound Z80 */                         \
        struct ym2151 opm;                                                      \
        u8  wram[0x20000];              /* 128 KB 68000 / Main Z80 Work RAM */  \
        u8  scn_ram[0x10000];           /* 64 KB TC0100SCN / PC080SN VRAM */    \
        u32 tx_gfx[256 * 8];            /* Live-decoded TC0100SCN 2bpp TX RAM */\
        u8  tx_nz[256];                                                         \
        u8  obj_ram[0x4000];            /* 16 KB TC0200OBJ / PC090OJ / BB Obj */\
        u8  pal_ram[0x2000];            /* 8 KB TC0110PCR / Palette RAM */      \
        u16 pal15[4096];                /* Preconverted 0BBBBBGGGGGRRRRR */     \
        u8  zram[0x4000];               /* 16 KB Sound Z80 RAM */               \
        u8  mcu_ram[0x1000];            /* 4 KB Bubble Bobble / TNZS MCU RAM */ \
        u8  tile_nz[TAITO_MAX_TILES];                                           \
        u8  spr_nz[TAITO_MAX_SPR16];                                            \
        u8  line_pri[TAITO_W_MAX] __attribute__((aligned(4)));                  \
        s16 snd_ring[TAITO_SND_RING];                                           \
    };                                                                          \
    TAITO_MEM_BIND

#ifdef TAITO_HOST
#define TAITO_MEM_BIND static struct taito_mem taito_host_mem;
static u32 taito_host_tiles[TAITO_MAX_TILES * 8u];
static u8  taito_host_spr[TAITO_MAX_SPR16 * 128u];
static u8  taito_host_rom[TAITO_ROM_CAP];
static u8  taito_host_zrom[TAITO_ZROM_CAP];
static u8  taito_host_pcm[TAITO_PCM_CAP];
static u8  taito_host_stage[TAITO_STAGE_CAP];
#define M           (&taito_host_mem)
#define TILE_BUF    taito_host_tiles
#define SPR_BUF     taito_host_spr
#define ROM_BUF     taito_host_rom
#define ZROM_BUF    taito_host_zrom
#define PCM_BUF     taito_host_pcm
#define ZIP_STAGE   taito_host_stage
#define TAITO_POLL() ((void)0)
#else
#define TAITO_MEM_BIND
/* Physical layout during taito_play:
   0x03400000..0x0357FFFF (1.5 MB) : struct taito_mem M (~470 KB, 0 B static .bss!)
   0x03580000..0x0377FFFF (2.0 MB) : TILE_BUF  (65,536 x 32 B pre-decoded 8x8 tiles)
   0x05800000..0x05BFFFFF (4.0 MB) : ROM_BUF   (68000 / Main Z80 program ROM)
   0x06900000..0x0693FFFF (256 KB) : ZROM_BUF  (Sound Z80 ROM)
   0x06980000..0x06D7FFFF (4.0 MB) : PCM_BUF   (YM2610 / ADPCM samples)
   0x06D80000..0x0757FFFF (8.0 MB) : SPR_BUF   (65,536 x 128 B pre-decoded 16x16 sprites)
   0x07580000..0x07A7FFFF (5.0 MB) : ZIP_STAGE (MAME .zip unpack scratch) */
#define M           ((struct taito_mem *)KSEG0(EMU_RAM_PHYS))
#define TILE_BUF    ((u32 *)KSEG0(0x03580000u))
#define ROM_BUF     ((u8 *)KSEG0(0x05800000u))
#define ZROM_BUF    ((u8 *)KSEG0(0x06900000u))
#define PCM_BUF     ((u8 *)KSEG0(0x06980000u))
#define SPR_BUF     ((u8 *)KSEG0(0x06D80000u))
#define ZIP_STAGE   ((u8 *)KSEG0(0x07580000u))
#define TAITO_POLL() ((void)now_ms())
#endif

#define S     (M->st)
#define m     (M->m_cpu)
#define rmap  (M->m_rmap)
#define wmap  (M->m_wmap)
#define optab (M->m_optab)

#pragma GCC optimize("O2")
#include "m68k.inc"

#ifndef TAITO_HOST
_Static_assert(sizeof(struct taito_mem) <= 0x00180000u, "taito_mem exceeds 1.5 MB slot");
#endif

static void taito_zero(void *p, u32 n)
{
    u8 *b = (u8 *)p;
    for (u32 i = 0; i < n; i++)
        b[i] = 0;
}

static int taito_ci_has(const char *s, const char *sub)
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

static int taito_ci_ends(const char *s, const char *ext)
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

static u32 taito_pow2_mask(u32 sz)
{
    if (sz <= 1u) return 0u;
    u32 p2 = 1u;
    while (p2 < sz && p2 < 0x40000000u)
        p2 <<= 1;
    return p2 - 1u;
}

/* ---- TC0110PCR / Rastan / Bubble Bobble Palette Conversion -> 0BBBBBGGGGGRRRRR ---- */
INLINE void taito_update_pal15(u32 idx)
{
    idx &= 0xFFFu;
    u16 raw = ((u16)M->pal_ram[idx * 2u] << 8) | M->pal_ram[idx * 2u + 1u];
    /* Taito F2 TC0110PCR / Rastan 15-bit format:
       bit 14..10 = G (or B), bit 9..5 = R (or G), bit 4..0 = B (or R).
       Standard Taito xBBBBBGGGGGRRRRR (0..0x7FFF) matches play.c 0BBBBBGGGGGRRRRR directly! */
    M->pal15[idx] = raw & 0x7FFFu;
}

/* Live-decode TC0100SCN 2bpp TX0 Character Generator RAM ($80A000..$80BFFF, 256 chars x 16 B) */
static void taito_decode_tx_row(u32 ch_idx, u32 row)
{
    ch_idx &= 255u;
    row &= 7u;
    const u8 *p = &M->scn_ram[0xA000u + ch_idx * 16u + row * 2u];
    u8 b0 = p[0], b1 = p[1];
    u32 r32 = 0;
    for (int x = 0; x < 8; x++) {
        u32 pen = (((b0 >> (7 - x)) & 1u) << 1) | ((b1 >> (7 - x)) & 1u);
        r32 |= pen << (x * 4);
    }
    M->tx_gfx[ch_idx * 8u + row] = r32;
    u8 any = 0;
    for (int y = 0; y < 8; y++)
        if (M->tx_gfx[ch_idx * 8u + (u32)y]) any = 1u;
    M->tx_nz[ch_idx] = any;
}

/* ============================================================================
   Audio Synthesizers: YM2610 ADPCM-A / PCM + SSG (48 kHz)
   ============================================================================ */

static void taito_ssg_write(u8 reg, u8 v)
{
    reg &= 15u;
    S.ssg.regs[reg] = v;
}

static s32 taito_ssg_step_48k(void)
{
    static const s16 vol_tab[16] = {
        0, 48, 68, 96, 136, 192, 272, 384, 544, 768, 1088, 1536, 2176, 3072, 4352, 6144
    };
    struct taito_ssg *g = &S.ssg;
    if (!g->lfsr) g->lfsr = 1u;
    u8 mix_en = g->regs[7];
    s32 sum = 0;

    u32 nper = (u32)(g->regs[6] & 0x1Fu);
    if (!nper) nper = 1u;
    if (++g->ncnt >= nper * 2u) {
        g->ncnt = 0;
        u32 bit = ((g->lfsr ^ (g->lfsr >> 3)) & 1u);
        g->lfsr = (g->lfsr >> 1) | (bit << 16);
    }

    for (int c = 0; c < 3; c++) {
        u8 v = g->regs[8 + c] & 0x0Fu;
        if (!v) continue;
        u32 tp = (u32)g->regs[c * 2] | (((u32)g->regs[c * 2 + 1] & 0x0Fu) << 8);
        if (tp < 2u) tp = 2u;
        /* 2 MHz SSG / (16 * tp) = 125000 / tp Hz -> step 3 ticks per 48 kHz sample */
        g->cnt[c] += 3u;
        if (g->cnt[c] >= tp) {
            g->cnt[c] -= tp;
            g->out[c] ^= 1u;
        }
        int t_ok = ((mix_en >> c) & 1u) ? 1 : g->out[c];
        int n_ok = ((mix_en >> (c + 3)) & 1u) ? 1 : (int)(g->lfsr & 1u);
        if (t_ok && n_ok)
            sum += vol_tab[v];
    }
    return sum >> 1;
}

static void taito_adpcm_write(u8 r, u8 v)
{
    /* YM2610 Port B ($00..$2F) ADPCM-A 6-channel sample controller:
       $00: Key-On/Key-Off (bit 7 = 0->KeyOn, 1->KeyOff; bits 0..5 = ch mask)
       $01: Master Total Level (bits 0..5)
       $08..$0D: Ch 0..5 pan (bits 6..7) + level (bits 0..4, 31=max)
       $10..$15: Ch 0..5 Start LSB (* 256 bytes)
       $18..$1D: Ch 0..5 Start MSB
       $20..$25: Ch 0..5 End LSB   (* 256 bytes)
       $28..$2D: Ch 0..5 End MSB */
    if (r < 0x30u)
        S.adpcm_regs[r & 31u] = v;
    if (r == 0x00u) {
        int off = (v & 0x80u) != 0;
        for (int c = 0; c < 6; c++) {
            if (!(v & (1u << c))) continue;
            struct taito_pcm_ch *ch = &S.pcm[c];
            if (off) {
                ch->playing = 0;
            } else {
                ch->pos_frac   = 0;
                ch->adpcm_acc  = 0;
                ch->adpcm_step = 0;
                ch->step_48k   = (18500u << 12) / (S.sample_rate ? S.sample_rate : 48000u);
                ch->playing    = (S.pcm_size > 0 && ch->end > ch->start) ? 1u : 0u;
            }
        }
    } else if (r == 0x01u) {
        S.adpcm_tl = v & 0x3Fu;
    } else if (r >= 0x08u && r <= 0x0Du) {
        S.pcm[r - 0x08u].vol = v & 0x1Fu;
    } else if (r >= 0x10u && r <= 0x15u) {
        int c = r - 0x10u;
        S.pcm[c].start = (S.pcm[c].start & 0xFF0000u) | ((u32)v << 8);
    } else if (r >= 0x18u && r <= 0x1Du) {
        int c = r - 0x18u;
        S.pcm[c].start = (S.pcm[c].start & 0x00FF00u) | ((u32)v << 16);
    } else if (r >= 0x20u && r <= 0x25u) {
        int c = r - 0x20u;
        S.pcm[c].end = (S.pcm[c].end & 0xFF0000u) | (((u32)v << 8) | 0xFFu);
    } else if (r >= 0x28u && r <= 0x2Du) {
        int c = r - 0x28u;
        S.pcm[c].end = (S.pcm[c].end & 0x00FFFFu) | ((u32)v << 16);
    }
}

static s32 taito_pcm_step_48k(void)
{
    if (!S.pcm_size) return 0;
    s32 sum = 0;
    for (int i = 0; i < 6; i++) {
        struct taito_pcm_ch *c = &S.pcm[i];
        if (!c->playing || !c->vol) continue;
        u32 cur = c->start + (c->pos_frac >> 12);
        if (cur >= c->end) {
            c->playing = 0;
            continue;
        }
        s8 raw = (s8)PCM_BUF[cur & S.pcm_mask];
        sum += ((s32)raw * (s32)c->vol) * 3;
        c->pos_frac += c->step_48k ? c->step_48k : 1578u;
    }
    return sum;
}

/* ============================================================================
   JAMMA Input & TC0140SYT / PC060HA Sound Nibble Handshake
   ============================================================================ */

static u8 taito_in_p1(void)
{
    /* Active-LOW Taito JAMMA P1:
       b0=Up, b1=Down, b2=Left, b3=Right, b4=Btn1(Fire/Bubble), b5=Btn2(Jump), b6=Btn3 */
    u8 v = 0xFFu;
    u16 p = S.pad1;
    if (p & 0x0010u) v &= (u8)~0x01u;   /* Up */
    if (p & 0x0020u) v &= (u8)~0x02u;   /* Down */
    if (p & 0x0040u) v &= (u8)~0x04u;   /* Left */
    if (p & 0x0080u) v &= (u8)~0x08u;   /* Right */
    if (p & 0x0001u) v &= (u8)~0x10u;   /* A -> Button 1 (Bubble / Sword / Launch) */
    if (p & 0x0002u) v &= (u8)~0x20u;   /* B -> Button 2 (Jump) */
    if (p & 0x0400u) v &= (u8)~0x40u;   /* X -> Button 3 */
    return v;
}

static u8 taito_in_sys(void)
{
    /* Active-LOW Taito System/Coin: b0=Coin1, b2=Start1, b3=Start2 */
    u8 v = 0xFFu;
    if (S.coin_pulse > 0) v &= (u8)~0x01u;
    if (S.pad1 & 0x0008u) v &= (u8)~0x04u;
    if (S.pad1 & 0x0800u) v &= (u8)~0x08u;
    return v;
}

static void syt_master_write(u32 off, u8 v)
{
    if ((off & 1u) == 0) {
        S.syt_mode = v & 7u;
    } else {
        u8 m_idx = S.syt_mode & 3u;
        if (S.syt_mode < 4u) {
            S.syt_main2sub[m_idx] = v & 0x0Fu;
            S.syt_status |= 0x01u;
            M->zsnd.nmi = 1;
            S.syt_mode = (S.syt_mode + 1u) & 7u;
        }
    }
}

static u8 syt_master_read(u32 off)
{
    if ((off & 1u) == 0)
        return S.syt_status;
    u8 m_idx = S.syt_mode & 3u;
    if (S.syt_mode < 4u) {
        S.syt_status &= (u8)~0x04u;
        u8 r = S.syt_sub2main[m_idx];
        S.syt_mode = (S.syt_mode + 1u) & 7u;
        return r;
    }
    return S.syt_status;
}

/* ============================================================================
   Motorola 68000 Bus (Taito F2 / B-System & Rastan / Rainbow Islands)
   ============================================================================ */

static void taito_iack(u32 level)
{
    (void)level;
    m.ipl = 0;
    check_pending();
}

static void cpu_reset_line(void) {}

static u32 io_read(u32 a, int size)
{
    a &= 0xFFFFFFu;

    /* Taito F2: TC0100SCN VRAM ($800000..$80FFFF) & Ctrl ($820000..$82000F) */
    if (a >= 0x800000u && a < 0x810000u) {
        u32 o = a & 0xFFFFu;
        if (size == 2) return ((u32)M->scn_ram[o] << 8) | M->scn_ram[o + 1u];
        return M->scn_ram[o];
    }
    if (a >= 0x820000u && a < 0x820010u) {
        u16 w = S.scn_ctrl[(a >> 1) & 7u];
        return (size == 2) ? w : ((a & 1u) ? (w & 0xFFu) : (w >> 8));
    }

    /* Taito F2: TC0200OBJ ($900000..$903FFF) & Rastan PC090OJ ($D00000..$D03FFF) */
    if ((a >= 0x900000u && a < 0x904000u) || (a >= 0xD00000u && a < 0xD04000u)) {
        u32 o = a & 0x3FFFu;
        if (size == 2) return ((u32)M->obj_ram[o] << 8) | M->obj_ram[o + 1u];
        return M->obj_ram[o];
    }

    /* Rastan / Rainbow Islands: PC080SN ($C00000..$C0FFFF) */
    if (a >= 0xC00000u && a < 0xC10000u) {
        u32 o = a & 0xFFFFu;
        if (size == 2) return ((u32)M->scn_ram[o] << 8) | M->scn_ram[o + 1u];
        return M->scn_ram[o];
    }

    /* Palette RAM ($A00000..$A01FFF on F2, $200000..$201FFF on Rastan, $500000..$501FFF on B-System) */
    if ((a >= 0xA00000u && a < 0xA02000u) || (a >= 0x200000u && a < 0x202000u) || (a >= 0x500000u && a < 0x502000u)) {
        u32 o = a & 0x1FFFu;
        if (size == 2) return ((u32)M->pal_ram[o] << 8) | M->pal_ram[o + 1u];
        return M->pal_ram[o];
    }

    /* TC0220IOC / TC0510NIO Input ($B00000..$B0001F on F2, $300000..$38000F on Rastan) */
    if ((a >= 0xB00000u && a < 0xB00020u) || (a >= 0x300000u && a < 0x390000u)) {
        u32 r = (a >> 1) & 7u;
        u8 lo = 0xFFu;
        if (r == 0 || r == 2) lo = taito_in_p1();
        else if (r == 4 || r == 5) lo = taito_in_sys();
        if (size == 2) return 0xFF00u | lo;
        return (a & 1u) ? lo : 0xFFu;
    }

    /* TC0140SYT / PC060HA Sound Comm ($B80000 on F2, $390000/$3E0000 on Rastan) */
    if ((a >= 0xB80000u && a < 0xB80010u) || (a >= 0x390000u && a < 0x3F0010u)) {
        u8 v = syt_master_read((a >> 1) & 1u);
        return (size == 2) ? v : v;
    }

    return (size == 2) ? 0xFFFFu : 0xFFu;
}

static void io_write(u32 a, u32 v, int size)
{
    a &= 0xFFFFFFu;

    /* Taito F2: TC0100SCN VRAM ($800000..$80FFFF) */
    if (a >= 0x800000u && a < 0x810000u) {
        u32 o = a & 0xFFFFu;
        if (size == 2) {
            M->scn_ram[o]     = (u8)(v >> 8);
            M->scn_ram[o + 1] = (u8)v;
        } else {
            M->scn_ram[o] = (u8)v;
        }
        if (o >= 0xA000u && o < 0xC000u)
            taito_decode_tx_row((o - 0xA000u) >> 4, ((o - 0xA000u) >> 1) & 7u);
        return;
    }
    if (a >= 0x820000u && a < 0x820010u) {
        u32 idx = (a >> 1) & 7u;
        if (size == 2) S.scn_ctrl[idx] = (u16)v;
        else if (a & 1u) S.scn_ctrl[idx] = (S.scn_ctrl[idx] & 0xFF00u) | (v & 0xFFu);
        else             S.scn_ctrl[idx] = (S.scn_ctrl[idx] & 0x00FFu) | ((u16)(v & 0xFFu) << 8);
        return;
    }

    /* TC0200OBJ ($900000..$903FFF) & PC090OJ ($D00000..$D03FFF) */
    if ((a >= 0x900000u && a < 0x904000u) || (a >= 0xD00000u && a < 0xD04000u)) {
        u32 o = a & 0x3FFFu;
        if (size == 2) {
            M->obj_ram[o]     = (u8)(v >> 8);
            M->obj_ram[o + 1] = (u8)v;
        } else {
            M->obj_ram[o] = (u8)v;
        }
        return;
    }

    /* Rastan / Rainbow Islands: PC080SN ($C00000..$C4000F) */
    if (a >= 0xC00000u && a < 0xC10000u) {
        u32 o = a & 0xFFFFu;
        if (size == 2) {
            M->scn_ram[o]     = (u8)(v >> 8);
            M->scn_ram[o + 1] = (u8)v;
        } else {
            M->scn_ram[o] = (u8)v;
        }
        return;
    }
    if (a >= 0xC20000u && a < 0xC40010u) {
        u16 w = (u16)v;
        if (a == 0xC20000u) S.pc080_scrolly[0] = w;
        else if (a == 0xC20002u) S.pc080_scrolly[1] = w;
        else if (a == 0xC40000u) S.pc080_scrollx[0] = w;
        else if (a == 0xC40002u) S.pc080_scrollx[1] = w;
        else if (a == 0xC40004u) S.pc080_ctrl = w;
        return;
    }

    /* Palette RAM ($A00000 / $200000 / $500000) */
    if ((a >= 0xA00000u && a < 0xA02000u) || (a >= 0x200000u && a < 0x202000u) || (a >= 0x500000u && a < 0x502000u)) {
        u32 o = a & 0x1FFFu;
        if (size == 2) {
            M->pal_ram[o]     = (u8)(v >> 8);
            M->pal_ram[o + 1] = (u8)v;
        } else {
            M->pal_ram[o] = (u8)v;
        }
        taito_update_pal15(o >> 1);
        return;
    }

    /* TC0140SYT / PC060HA Sound Comm ($B80000 / $390000 / $3E0000) */
    if ((a >= 0xB80000u && a < 0xB80010u) || (a >= 0x390000u && a < 0x3F0010u)) {
        syt_master_write((a >> 1) & 1u, (u8)v);
        return;
    }
}

/* ============================================================================
   Bubble Bobble / TNZS Main Z80 & Sound Z80 Buses
   ============================================================================ */

static u8 taito_zmain_read(struct z80 *z, u16 a)
{
    (void)z;
    if (a < 0x8000u)
        return ROM_BUF[a & (TAITO_ROM_CAP - 1u)];
    if (a < 0xC000u) {
        u32 off = 0x8000u + (u32)S.z80_rombank * 0x4000u + (a & 0x3FFFu);
        if (S.rom_size) off %= S.rom_size;
        return ROM_BUF[off & (TAITO_ROM_CAP - 1u)];
    }
    if (a < 0xDD00u)
        return M->obj_ram[a - 0xC000u];
    if (a < 0xE000u) {
        /* Bubble Bobble 68705 MCU shared RAM ($DC00..$DFFF) clean-room HLE! */
        u32 mo = a & 0x0FFFu;
        if (mo == 0xC00u || mo == 0xD00u) return taito_in_sys();
        if (mo == 0xC01u || mo == 0xD01u) return taito_in_p1();
        if (mo == 0xC02u || mo == 0xD02u) return 0xFFu;
        return M->mcu_ram[mo];
    }
    if (a < 0xF800u)
        return M->wram[a - 0xE000u];
    if (a >= 0xFC00u && a < 0xFC10u) {
        if ((a & 3u) == 0) return taito_in_sys();
        if ((a & 3u) == 1) return taito_in_p1();
        return 0xFFu;
    }
    if (a >= 0xFE00u)
        return M->pal_ram[a - 0xFE00u];
    return M->wram[a & 0x1FFFu];
}

static void taito_zmain_write(struct z80 *z, u16 a, u8 v)
{
    (void)z;
    if (a >= 0xC000u && a < 0xDD00u) {
        M->obj_ram[a - 0xC000u] = v;
        return;
    }
    if (a >= 0xDD00u && a < 0xE000u) {
        M->mcu_ram[a & 0x0FFFu] = v;
        return;
    }
    if (a >= 0xE000u && a < 0xF800u) {
        M->wram[a - 0xE000u] = v;
        return;
    }
    if (a >= 0xFA00u && a < 0xFC00u) {
        if ((a & 0xFFu) == 0x00u) {
            S.syt_main2sub[0] = v;
            S.syt_status |= 1u;
            M->zsnd.nmi = 1;
        }
        return;
    }
    if (a >= 0xFC00u && a < 0xFE00u) {
        S.z80_rombank = v & 7u;
        S.z80_vidctrl = v;
        return;
    }
    if (a >= 0xFE00u) {
        u32 o = a - 0xFE00u;
        M->pal_ram[o] = v;
        /* Bubble Bobble 16-bit RGB444 / RGB555 palette entry */
        u32 idx = o >> 1;
        u8 hi = M->pal_ram[idx * 2u], lo = M->pal_ram[idx * 2u + 1u];
        u32 r4 = (hi >> 4) & 15u, g4 = hi & 15u, b4 = (lo >> 4) & 15u;
        M->pal15[idx] = (u16)(((b4 * 2u + (b4 >> 3)) << 10) | ((g4 * 2u + (g4 >> 3)) << 5) | (r4 * 2u + (r4 >> 3)));
    }
}

static u8 taito_zmain_in(struct z80 *z, u16 port)  { (void)z; (void)port; return 0xFFu; }
static void taito_zmain_out(struct z80 *z, u16 port, u8 v) { (void)z; (void)port; (void)v; }

/* Sound Z80 ($0000..$BFFF ROM, $C000..$DFFF RAM, $E000..$E003 YM2151/YM2610, $E200..$E201 TC0140SYT) */
static u8 taito_zsnd_read(struct z80 *z, u16 a)
{
    (void)z;
    if (a < 0xC000u)
        return (a < S.zrom_size) ? ZROM_BUF[a] : 0u;
    if (a < 0xE000u)
        return M->zram[a & 0x1FFFu];
    if (a >= 0xE000u && a < 0xE010u)
        return M->opm.status;
    if (a >= 0xE200u && a < 0xE210u) {
        if ((a & 1u) == 0) return S.syt_status;
        S.syt_status &= (u8)~0x01u;
        return S.syt_main2sub[S.syt_mode & 3u];
    }
    return M->zram[a & 0x3FFFu];
}

static void taito_zsnd_write(struct z80 *z, u16 a, u8 v)
{
    (void)z;
    if (a >= 0xC000u && a < 0xE000u) {
        M->zram[a & 0x1FFFu] = v;
        return;
    }
    if (a >= 0xE000u && a < 0xE004u) {
        switch (a & 3u) {
        case 0: S.ym_port_sel = 0; M->opm.addr_latch = v; S.ssg.sel = v & 15u; break;
        case 1:
            if (M->opm.addr_latch < 0x10u)
                taito_ssg_write(M->opm.addr_latch, v);
            else
                ym2151_write_reg(&M->opm, M->opm.addr_latch, v, 4000000u);
            break;
        case 2: S.ym_port_sel = 1u; M->opm.addr_latch = v; break;
        case 3: taito_adpcm_write(M->opm.addr_latch, v); break;
        }
        return;
    }
    if (a >= 0xE200u && a < 0xE210u) {
        if ((a & 1u) == 0) S.syt_mode = v & 7u;
        else { S.syt_sub2main[S.syt_mode & 3u] = v & 0x0Fu; S.syt_status |= 0x04u; }
        return;
    }
    if (a >= 0xF200u)
        M->zsnd.irq = 0;
}

static u8 taito_zsnd_in(struct z80 *z, u16 port)
{
    (void)z;
    u8 p = (u8)port;
    if (p == 0x00u) return M->opm.status;
    if (p == 0x04u) { S.syt_status &= (u8)~1u; return S.syt_main2sub[0]; }
    return 0xFFu;
}

static void taito_zsnd_out(struct z80 *z, u16 port, u8 v)
{
    (void)z;
    u8 p = (u8)port;
    if (p == 0x00u) { M->opm.addr_latch = v; S.ssg.sel = v & 15u; }
    else if (p == 0x01u) {
        if (M->opm.addr_latch < 0x10u) taito_ssg_write(M->opm.addr_latch, v);
        else ym2151_write_reg(&M->opm, M->opm.addr_latch, v, 4000000u);
    } else if (p == 0x02u) { M->opm.addr_latch = v; }
    else if (p == 0x03u) { taito_adpcm_write(M->opm.addr_latch, v); }
}

/* ============================================================================
   Scanline Renderers: TC0100SCN, TC0200OBJ, PC080SN, PC090OJ & Bubble Bobble
   ============================================================================ */

static void taito_draw_tc0100scn_bg_line(int layer, int y, u8 pri_val, u16 *dst)
{
    if (!S.tile_count) return;
    int w = S.scr_w;
    /* TC0100SCN BG0 = $0000 (rowscroll $C000), FG0 = $4000 (rowscroll $C400)
       PC080SN   BG0 = $0000 (rowscroll $4000), FG0 = $8000 */
    u32 vbase = (layer == 0) ? 0x0000u : ((S.board == TAITO_BOARD_RASTAN) ? 0x8000u : 0x4000u);
    int xscr, yscr;
    if (S.board == TAITO_BOARD_RASTAN) {
        xscr = -(s16)S.pc080_scrollx[layer];
        yscr = -(s16)S.pc080_scrolly[layer];
    } else {
        xscr = -(s16)S.scn_ctrl[layer ? 1 : 0];
        yscr = -(s16)S.scn_ctrl[layer ? 3 : 2];
        u32 rscr_off = (layer == 0 ? 0xC000u : 0xC400u) + (u32)(y & 255) * 2u;
        s16 rdx = (s16)(((u16)M->scn_ram[rscr_off] << 8) | M->scn_ram[rscr_off + 1u]);
        xscr -= rdx;
    }

    int sy = (y + yscr) & 511;
    u32 row_base = vbase + (u32)(sy >> 3) * 256u;   /* 64 cols x 4 bytes/cell (attr16, code16) */

    for (int x = 0; x < w;) {
        int sx = (x + xscr) & 511;
        int tx0 = sx & 7;
        int span = 8 - tx0;
        if (x + span > w) span = w - x;

        u32 ca = row_base + (u32)(sx >> 3) * 4u;
        u16 attr = ((u16)M->scn_ram[ca] << 8) | M->scn_ram[ca + 1u];
        u16 code = ((u16)M->scn_ram[ca + 2u] << 8) | M->scn_ram[ca + 3u];
        u32 t = code & S.tile_mask;
        if (!M->tile_nz[t]) {
            x += span;
            continue;
        }

        int fx = (attr & 0x4000u) != 0;
        int fy = (attr & 0x8000u) != 0;
        int ty = fy ? (7 - (sy & 7)) : (sy & 7);
        u32 row32 = TILE_BUF[t * 8u + (u32)ty];
        if (!row32) {
            x += span;
            continue;
        }

        const u16 *pal_row = &M->pal15[((u32)(attr & 0xFFu) << 4) & 0xFF0u];
        if (!fx) {
            u32 r_sh = row32 >> (tx0 * 4);
            for (int k = 0; k < span; k++, r_sh >>= 4) {
                u32 pen = r_sh & 0x0Fu;
                if (pen && pri_val >= M->line_pri[x + k]) {
                    dst[x + k] = pal_row[pen];
                    M->line_pri[x + k] = pri_val;
                }
            }
        } else {
            for (int k = 0; k < span; k++) {
                int px = 7 - (tx0 + k);
                u32 pen = (row32 >> (px * 4)) & 0x0Fu;
                if (pen && pri_val >= M->line_pri[x + k]) {
                    dst[x + k] = pal_row[pen];
                    M->line_pri[x + k] = pri_val;
                }
            }
        }
        x += span;
    }
}

static void taito_draw_tc0100scn_tx_line(int y, u8 pri_val, u16 *dst)
{
    int w = S.scr_w;
    int xscr = -(s16)S.scn_ctrl[4];
    int yscr = -(s16)S.scn_ctrl[5];
    int sy = (y + yscr) & 511;
    u32 row_base = 0x8000u + (u32)(sy >> 3) * 128u; /* 64 cols x 2 bytes/cell */

    for (int x = 0; x < w;) {
        int sx = (x + xscr) & 511;
        int tx0 = sx & 7;
        int span = 8 - tx0;
        if (x + span > w) span = w - x;

        u32 ca = row_base + (u32)(sx >> 3) * 2u;
        u16 word = ((u16)M->scn_ram[ca] << 8) | M->scn_ram[ca + 1u];
        u32 ch = word & 0xFFu;
        if (!M->tx_nz[ch]) {
            x += span;
            continue;
        }
        u32 row32 = M->tx_gfx[ch * 8u + (u32)(sy & 7)];
        if (!row32) {
            x += span;
            continue;
        }
        u32 col_bank = (word >> 8) & 0x3Fu;
        const u16 *pal_row = &M->pal15[(0x400u + (col_bank << 2)) & 0xFFCu];
        u32 r_sh = row32 >> (tx0 * 4);
        for (int k = 0; k < span; k++, r_sh >>= 4) {
            u32 pen = r_sh & 3u;
            if (pen && pri_val >= M->line_pri[x + k]) {
                dst[x + k] = pal_row[pen];
                M->line_pri[x + k] = pri_val;
            }
        }
        x += span;
    }
}

static void taito_prepare_sprites(void)
{
    S.n_act_spr = 0;
    if (!S.spr16_count) return;

    if (S.board == TAITO_BOARD_F2) {
        /* TC0200OBJ: 1024 entries x 16 bytes (8 words):
           w0 = code, w1 = x (signed 12b), w2 = y (signed 12b),
           w3 = (zoomy<<8)|zoomx (0=16px, 0x7F=8px), w4 = attr/color */
        for (int s = 0; s < 512; s++) {
            const u8 *p = &M->obj_ram[s * 16];
            u16 code = ((u16)p[0] << 8) | p[1];
            u16 w4   = ((u16)p[8] << 8) | p[9];
            if (!code && !w4) continue;
            u32 cell = code & S.spr16_mask;
            if (!M->spr_nz[cell]) continue;
            S.act_spr[S.n_act_spr++] = (u16)s;
        }
    } else if (S.board == TAITO_BOARD_RASTAN) {
        /* PC090OJ: 256 entries x 8 bytes (4 words): w0=attr, w1=code, w2=y, w3=x */
        for (int s = 255; s >= 0; s--) {
            const u8 *p = &M->obj_ram[s * 8];
            u16 code = (((u16)p[2] << 8) | p[3]) & 0x3FFFu;
            if (!code) continue;
            if (!M->spr_nz[code & S.spr16_mask]) continue;
            S.act_spr[S.n_act_spr++] = (u16)s;
        }
    }
}

static void taito_draw_sprites_line(int y, u16 *dst)
{
    if (!S.n_act_spr || !S.spr16_count) return;
    int w = S.scr_w;

    if (S.board == TAITO_BOARD_F2) {
        for (int ai = 0; ai < S.n_act_spr; ai++) {
            const u8 *p = &M->obj_ram[(u32)S.act_spr[ai] * 16u];
            u32 code = (((u16)p[0] << 8) | p[1]) & S.spr16_mask;
            int sx   = ((u16)p[2] << 8 | p[3]) & 0x0FFFu;
            int sy   = ((u16)p[4] << 8 | p[5]) & 0x0FFFu;
            if (sx >= 2048) sx -= 4096;
            if (sy >= 2048) sy -= 4096;
            u8 zx    = p[7], zy = p[6];
            u16 attr = ((u16)p[8] << 8) | p[9];

            /* TC0200OBJ zoom: 0x00 -> 16 px, >0 shrinks: size = 16 - (zoom >> 4) (clamped 1..16) */
            int out_w = 16 - (zx >> 4);
            int out_h = 16 - (zy >> 4);
            if (out_w < 1) out_w = 1;
            if (out_h < 1) out_h = 1;

            if (y < sy || y >= sy + out_h) continue;
            if (sx >= w || sx + out_w <= 0) continue;

            int fx = (attr & 0x0100u) != 0;
            int fy = (attr & 0x0200u) != 0;
            u8 pri = (attr & 0x0800u) ? 0x18u : 0x28u;
            const u16 *pal_row = &M->pal15[(0x200u + ((u32)(attr & 0x7Fu) << 4)) & 0xFF0u];

            int in_y = ((y - sy) * 16) / out_h;
            if (fy) in_y = 15 - in_y;
            const u8 *cell_p = &SPR_BUF[code * 128u + (u32)(in_y & 15) * 8u];

            int x0 = sx < 0 ? 0 : sx;
            int x1 = (sx + out_w > w) ? w : (sx + out_w);
            u32 step_x = (16u << 8) / (u32)out_w;
            u32 cur_x  = (u32)(x0 - sx) * step_x;
            for (int x = x0; x < x1; x++, cur_x += step_x) {
                int in_x = (int)(cur_x >> 8) & 15;
                if (fx) in_x = 15 - in_x;
                u8 pk = cell_p[in_x >> 1];
                u8 pen = (in_x & 1) ? (pk >> 4) : (pk & 0x0Fu);
                if (pen && pri >= M->line_pri[x]) {
                    dst[x] = pal_row[pen];
                    M->line_pri[x] = pri;
                }
            }
        }
    } else if (S.board == TAITO_BOARD_RASTAN) {
        for (int ai = 0; ai < S.n_act_spr; ai++) {
            const u8 *p = &M->obj_ram[(u32)S.act_spr[ai] * 8u];
            u16 attr = ((u16)p[0] << 8) | p[1];
            u32 code = (((u16)p[2] << 8) | p[3]) & S.spr16_mask;
            int sy   = (((u16)p[4] << 8) | p[5]) & 0x01FFu;
            int sx   = (((u16)p[6] << 8) | p[7]) & 0x01FFu;
            if (sy >= 448) sy -= 512;
            if (sx >= 448) sx -= 512;
            if (y < sy || y >= sy + 16 || sx >= w || sx + 16 <= 0) continue;

            int fx = (attr & 0x4000u) != 0;
            int fy = (attr & 0x8000u) != 0;
            int in_y = fy ? (15 - (y - sy)) : (y - sy);
            const u8 *cell_p = &SPR_BUF[code * 128u + (u32)in_y * 8u];
            const u16 *pal_row = &M->pal15[(0x200u + ((u32)(attr & 0x0Fu) << 4)) & 0xFF0u];

            int x0 = sx < 0 ? 0 : sx;
            int x1 = (sx + 16 > w) ? w : (sx + 16);
            for (int x = x0; x < x1; x++) {
                int in_x = fx ? (15 - (x - sx)) : (x - sx);
                u8 pk = cell_p[in_x >> 1];
                u8 pen = (in_x & 1) ? (pk >> 4) : (pk & 0x0Fu);
                if (pen && 0x28u >= M->line_pri[x]) {
                    dst[x] = pal_row[pen];
                    M->line_pri[x] = 0x28u;
                }
            }
        }
    }
}

static void taito_render_z80_frame(u16 *picture)
{
    /* Bubble Bobble / TNZS Z80 Object-Column Video ($C000..$DCFF):
       - $C000..$DFFF: 32x28 8x8 tilemap ($C000, 2 bytes/cell: code_lo, (pal<<4)|code_hi)
       - $D800..$D9FF: 64 16x16 sprites (4 bytes/entry: y, code, attr, x) */
    int w = S.scr_w, h = S.scr_h;
    u16 bg = M->pal15[0];
    for (int i = 0; i < w * h; i++)
        picture[i] = bg;

    if (S.tile_count) {
        for (int ty = 0; ty < (h >> 3); ty++) {
            for (int tx = 0; tx < (w >> 3); tx++) {
                u32 off = (u32)(ty * 32 + tx) * 2u;
                u8 lo = M->obj_ram[off], hi = M->obj_ram[off + 1u];
                u32 code = ((u32)(hi & 0x0Fu) << 8) | lo;
                u32 t = code & S.tile_mask;
                if (!M->tile_nz[t]) continue;
                const u16 *pal_row = &M->pal15[((u32)(hi >> 4) << 4) & 0xFFu];
                for (int py = 0; py < 8; py++) {
                    u32 r32 = TILE_BUF[t * 8u + (u32)py];
                    if (!r32) continue;
                    u16 *dst = picture + (ty * 8 + py) * w + tx * 8;
                    for (int px = 0; px < 8; px++, r32 >>= 4) {
                        u32 pen = r32 & 0x0Fu;
                        if (pen) dst[px] = pal_row[pen];
                    }
                }
            }
        }
    }

    if (S.spr16_count) {
        for (int s = 0; s < 64; s++) {
            const u8 *sp = &M->obj_ram[0x1800u + s * 4];
            int sy = sp[0];
            if (!sy || sy >= 240) continue;
            u32 code = ((u32)(sp[2] & 0x07u) << 8) | sp[1];
            u32 cell = code & S.spr16_mask;
            if (!M->spr_nz[cell]) continue;
            int sx = sp[3];
            int fx = (sp[2] & 0x40u) != 0;
            int fy = (sp[2] & 0x80u) != 0;
            const u16 *pal_row = &M->pal15[(0x80u + (((u32)(sp[2] >> 3) & 7u) << 4)) & 0xFFu];
            for (int py = 0; py < 16; py++) {
                int dy = sy + py;
                if (dy < 0 || dy >= h) continue;
                int iy = fy ? (15 - py) : py;
                const u8 *cp = &SPR_BUF[cell * 128u + (u32)iy * 8u];
                for (int px = 0; px < 16; px++) {
                    int dx = sx + px;
                    if (dx < 0 || dx >= w) continue;
                    int ix = fx ? (15 - px) : px;
                    u8 pk = cp[ix >> 1];
                    u8 pen = (ix & 1) ? (pk >> 4) : (pk & 0x0Fu);
                    if (pen) picture[dy * w + dx] = pal_row[pen];
                }
            }
        }
    }
}

static void taito_render_68k_line(int y, u16 *dst)
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

    taito_draw_tc0100scn_bg_line(0, y, 0x10u, dst);     /* BG0 */
    taito_draw_tc0100scn_bg_line(1, y, 0x20u, dst);     /* FG0 */
    taito_draw_sprites_line(y, dst);                    /* TC0200OBJ / PC090OJ */
    if (S.board == TAITO_BOARD_F2)
        taito_draw_tc0100scn_tx_line(y, 0x38u, dst);    /* TC0100SCN TX0 HUD */
}

/* ============================================================================
   Built-in Playable Taito F2 68000 + Z80 Game (""): "BUBBLE DRAGONS F2"
   Runs native 68000 machine code + Sound Z80 + TC0100SCN + TC0200OBJ zoom +
   YM2151 FM bouncy lead + YM2610 ADPCM bubble/pop SFX!
   ============================================================================ */

static void taito_put_tile_px(u32 t, int x, int y, u8 pen)
{
    u32 *r = &TILE_BUF[t * 8u + (u32)y];
    u32 sh = (u32)x * 4u;
    *r = (*r & ~(0x0Fu << sh)) | ((u32)(pen & 0x0Fu) << sh);
    if (pen) M->tile_nz[t] = 1u;
}

static void taito_put_spr_px(u32 cell, int x, int y, u8 pen)
{
    u32 off = cell * 128u + (u32)y * 8u + (u32)(x >> 1);
    if (x & 1) SPR_BUF[off] = (SPR_BUF[off] & 0x0Fu) | ((u8)(pen & 0x0Fu) << 4);
    else       SPR_BUF[off] = (SPR_BUF[off] & 0xF0u) | (pen & 0x0Fu);
    if (pen) M->spr_nz[cell] = 1u;
}

static void build_builtin_taito_assets(void)
{
    taito_zero(TILE_BUF, 256u * 32u);
    taito_zero(SPR_BUF,  32u * 128u);
    taito_zero(M->tile_nz, 256u);
    taito_zero(M->spr_nz,  32u);
    taito_zero(PCM_BUF,  0x4000u);

    /* Tile 1: Twinkling starfield dot; Tile 2: Neon candy-striped Bubble Bobble platform brick! */
    taito_put_tile_px(1u, 3, 3, 2u);
    for (int y = 0; y < 8; y++) {
        for (int x = 0; x < 8; x++) {
            u8 pen = 4u;
            if (y == 0 || x == 0) pen = 3u;
            else if (y == 7 || x == 7) pen = 5u;
            else if (((x + y) & 3) == 0) pen = 6u;
            taito_put_tile_px(2u, x, y, pen);
        }
    }
    /* Tile 3: Cavern side wall block */
    for (int y = 0; y < 8; y++)
        for (int x = 0; x < 8; x++)
            taito_put_tile_px(3u, x, y, ((x ^ y) & 2) ? 7u : 5u);

    /* Sprite 1 (16x16): Bubby the Green Bubble Dragon (back spikes, snout, big eye, orange feet)! */
    static const char *const drag[16] = {
        "....22....22....",
        "...2662..2662...",
        "..2633333332....",
        "..23331113333...",
        ".2633318133333..",
        ".26333111333333.",
        "..2333333333133.",
        "...23333333333..",
        "..26333444332...",
        ".263334444432...",
        "..23334444432...",
        "..23333444332...",
        "...233333332....",
        "...2332..2332...",
        "..55552..55552..",
        "..5555...5555..."
    };
    for (int y = 0; y < 16; y++)
        for (int x = 0; x < 16; x++) {
            char c = drag[y][x];
            if (c >= '1' && c <= '9')
                taito_put_spr_px(1u, x, y, (u8)(c - '0'));
        }

    /* Sprite 2 (16x16): Shimmering Rainbow Bubble! */
    for (int y = 0; y < 16; y++) {
        for (int x = 0; x < 16; x++) {
            int dx = x - 7, dy = y - 7;
            int r2 = dx * dx + dy * dy;
            if (r2 >= 34 && r2 <= 54)
                taito_put_spr_px(2u, x, y, ((x + y) & 2) ? 9u : 10u);
            else if (x >= 4 && x <= 5 && y >= 4 && y <= 5)
                taito_put_spr_px(2u, x, y, 1u);     /* Specular highlight */
            else if (r2 < 34 && ((x ^ y) & 3) == 0)
                taito_put_spr_px(2u, x, y, 11u);
        }
    }

    /* Sprite 3 (16x16): Wind-Up Monsta / Zen-Chan Enemy! */
    for (int y = 1; y < 15; y++) {
        for (int x = 1; x < 15; x++) {
            int dx = x - 7, dy = y - 7;
            if (dx * dx + dy * dy <= 44) {
                u8 pen = 12u;
                if ((x == 5 || x == 10) && (y >= 5 && y <= 8)) pen = 1u;
                else if (y == 10 && x >= 5 && x <= 10) pen = 6u;
                taito_put_spr_px(3u, x, y, pen);
            }
        }
    }

    /* Sprite 4 (16x16): Trapped Monsta inside Rainbow Bubble! */
    for (int y = 0; y < 16; y++) {
        for (int x = 0; x < 16; x++) {
            int dx = x - 7, dy = y - 7;
            int r2 = dx * dx + dy * dy;
            if (r2 >= 36 && r2 <= 54) taito_put_spr_px(4u, x, y, 9u);
            else if (r2 <= 20)        taito_put_spr_px(4u, x, y, (y == 7 && (x == 6 || x == 9)) ? 1u : 12u);
        }
    }

    /* Sprite 5 (16x16): Popped Bonus Melon / Star! */
    for (int y = 2; y < 14; y++)
        for (int x = 2; x < 14; x++)
            if ((x - 7) * (x - 7) + (y - 7) * (y - 7) <= 28)
                taito_put_spr_px(5u, x, y, ((x + y) & 2) ? 6u : 3u);

    S.tile_count  = 256u;
    S.spr16_count = 32u;
    S.tile_mask   = 255u;
    S.spr16_mask  = 31u;

    /* Synthesize Bubble Pop / Bloop signed 8-bit PCM sample at $0100..$08FF in PCM_BUF */
    for (u32 i = 0; i < 0x0800u; i++) {
        u32 freq = 16u + (i >> 5);  /* Rising pitch bubble bloop! */
        int s = (((i * freq) & 64u) ? 70 : -70) * (int)(0x800u - i) >> 11;
        PCM_BUF[0x0100u + i] = (u8)(s8)s;
    }
    S.pcm_size = 0x2000u;
    S.pcm_mask = 0x1FFFu;
}

static void build_builtin_taito_z80(void)
{
    /* Cheerful Bubble-Bobble-inspired YM2151 FM melody + NMI ADPCM Bubble-Bloop trigger! */
    taito_zero(ZROM_BUF, 0x2000u);
    static const u8 zp[] = {
        0xF3, 0x31, 0xF0, 0xDF,             /* DI; LD SP, $DFF0 */
        0x21, 0x00, 0x01,                   /* LD HL, $0100 */
        0x7E, 0xFE, 0xFF, 0x28, 0x0B,       /* LD A,(HL); CP $FF; JR Z,+11 ($0017) */
        0x32, 0x00, 0xE0, 0x23,             /* LD ($E000),A; INC HL */
        0x7E, 0x32, 0x01, 0xE0, 0x23,       /* LD A,(HL); LD ($E001),A; INC HL */
        0x18, 0xF0,                         /* JR -16 ($0007) */
        0x0E, 0x00,                         /* LD C, 0 */
        /* loop ($0019): */
        0x3E, 0x08, 0x32, 0x00, 0xE0, 0x3E, 0x00, 0x32, 0x01, 0xE0,
        0x3E, 0x08, 0x32, 0x00, 0xE0, 0x3E, 0x01, 0x32, 0x01, 0xE0,
        0x26, 0x01, 0x79, 0xC6, 0x40, 0x6F,
        0x3E, 0x28, 0x32, 0x00, 0xE0, 0x7E, 0x32, 0x01, 0xE0,
        0x79, 0xC6, 0x50, 0x6F,
        0x3E, 0x29, 0x32, 0x00, 0xE0, 0x7E, 0x32, 0x01, 0xE0,
        0x3E, 0x08, 0x32, 0x00, 0xE0, 0x3E, 0x78, 0x32, 0x01, 0xE0,
        0x3E, 0x08, 0x32, 0x00, 0xE0, 0x3E, 0x79, 0x32, 0x01, 0xE0,
        0x11, 0x00, 0x16,
        0x1B, 0x7A, 0xB3, 0x20, 0xFB,
        0x0C, 0x79, 0xE6, 0x0F, 0x4F,
        0xC3, 0x19, 0x00
    };
    for (u32 i = 0; i < sizeof(zp); i++)
        ZROM_BUF[i] = zp[i];

    /* NMI at $0066: reads TC0140SYT ($E201) & triggers YM2610 ADPCM Ch 0 Bubble Bloop! */
    static const u8 znmi[] = {
        0xF5,
        0x3A, 0x01, 0xE2,
        0x3E, 0x08, 0x32, 0x02, 0xE0, 0x3E, 0xDF, 0x32, 0x03, 0xE0, /* Ch0 vol=31 */
        0x3E, 0x10, 0x32, 0x02, 0xE0, 0x3E, 0x01, 0x32, 0x03, 0xE0, /* start=$0100 */
        0x3E, 0x20, 0x32, 0x02, 0xE0, 0x3E, 0x08, 0x32, 0x03, 0xE0, /* end=$08FF */
        0x3E, 0x00, 0x32, 0x02, 0xE0, 0x3E, 0x01, 0x32, 0x03, 0xE0, /* KeyOn Ch0 */
        0xF1,
        0xED, 0x45
    };
    for (u32 i = 0; i < sizeof(znmi); i++)
        ZROM_BUF[0x0066u + i] = znmi[i];

    static const u8 ymp[] = {
        0x20, 0xC4,  0x21, 0xDC,
        0x40, 0x02,  0x48, 0x01,  0x50, 0x02,  0x58, 0x01,
        0x60, 0x18,  0x68, 0x0C,  0x70, 0x16,  0x78, 0x0A,
        0x80, 0x1F,  0x88, 0x1F,  0x90, 0x1F,  0x98, 0x1F,
        0xA0, 0x0A,  0xA8, 0x08,  0xB0, 0x0A,  0xB8, 0x08,
        0xE0, 0x2A,  0xE8, 0x1A,  0xF0, 0x2A,  0xF8, 0x1A,
        0x41, 0x01,  0x49, 0x02,  0x51, 0x01,  0x59, 0x01,
        0x61, 0x16,  0x69, 0x12,  0x71, 0x14,  0x79, 0x0C,
        0x81, 0x1F,  0x89, 0x1F,  0x91, 0x1F,  0x99, 0x1F,
        0xA1, 0x0C,  0xA9, 0x0A,  0xB1, 0x0C,  0xB9, 0x0A,
        0xE1, 0x2A,  0xE9, 0x2A,  0xF1, 0x2A,  0xF9, 0x1A,
        0xFF
    };
    for (u32 i = 0; i < sizeof(ymp); i++)
        ZROM_BUF[0x0100u + i] = ymp[i];

    /* Bouncy major-scale Bubble Bobble inspired melody & bass */
    static const u8 lead_kc[16] = {0x4A,0x4E,0x51,0x56, 0x55,0x51,0x4E,0x4A, 0x4D,0x51,0x54,0x58, 0x56,0x54,0x51,0x4E};
    static const u8 bass_kc[16] = {0x2A,0x36,0x2A,0x36, 0x28,0x34,0x28,0x34, 0x2D,0x39,0x2D,0x39, 0x2E,0x3A,0x2E,0x31};
    for (int i = 0; i < 16; i++) {
        ZROM_BUF[0x0140u + i] = lead_kc[i];
        ZROM_BUF[0x0150u + i] = bass_kc[i];
    }
    S.zrom_size = 0x2000u;
}

/* Native 68000 machine-code emitters (m68k.inc keeps each 16-bit word in host u16!) */
static void m68_w16(u8 *rom, u32 *p, u16 w)
{
    rom[*p]     = (u8)w;
    rom[*p + 1] = (u8)(w >> 8);
    *p += 2u;
}

static void m68_w32(u8 *rom, u32 *p, u32 d)
{
    m68_w16(rom, p, (u16)(d >> 16));
    m68_w16(rom, p, (u16)d);
}

static u32 m68_bcc16(u8 *rom, u32 *p, u16 op)
{
    m68_w16(rom, p, op);
    u32 at = *p;
    m68_w16(rom, p, 0);
    return at;
}

static void m68_patch16(u8 *rom, u32 at, u32 dst)
{
    u32 t = at;
    m68_w16(rom, &t, (u16)(s16)((s32)dst - (s32)at));
}

static void build_builtin_taito_68k(void)
{
    taito_zero(ROM_BUF, 0x10000u);

    /* 68000 Vectors: SSP=$40FFF0, PC=$000400, Level 4/6 VBlank=$000800 */
    u32 vp = 0;
    m68_w32(ROM_BUF, &vp, 0x0040FFF0u);
    m68_w32(ROM_BUF, &vp, 0x00000400u);
    for (int v = 2; v < 64; v++)
        m68_w32(ROM_BUF, &vp, (v == 28 || v == 30) ? 0x00000800u : 0x000003F0u);
    u32 rte_p = 0x03F0u;
    m68_w16(ROM_BUF, &rte_p, 0x4E73u);      /* RTE */

    /* ROM Data at $001000:
       +$000: 16 BG colors ($A00000), +$020: 16 Sprite colors ($A00400), +$040: 4 TX colors ($A00800)
       +$080: 2bpp 8x8 ASCII font for TC0100SCN TX0 ($80A000)
       +$480: HUD string "  BUBBLE DRAGONS F2     ROUND 01      " */
    static const u16 pal_bg[16] = {
        0x1421, 0x7FFF, 0x7FE0, 0x7FF0, 0x6419, 0x380E, 0x03FF, 0x294A,
        0x03E0, 0x7C1F, 0x7FE0, 0x001F, 0x02BF, 0x5AD6, 0x4210, 0x7FFF
    };
    static const u16 pal_sp[16] = {
        0x0000, 0x7FFF, 0x01C0, 0x03E4, 0x5BF8, 0x01DF, 0x03FF, 0x001F,
        0x0000, 0x7E1F, 0x7FE8, 0x7F10, 0x20BF, 0x03E0, 0x7C00, 0x7FFF
    };
    static const u16 pal_tx[4] = { 0x0000, 0x1084, 0x03FF, 0x7FFF };

    u32 dp = 0x1000u;
    for (int i = 0; i < 16; i++) m68_w16(ROM_BUF, &dp, pal_bg[i]);
    for (int i = 0; i < 16; i++) m68_w16(ROM_BUF, &dp, pal_sp[i]);
    for (int i = 0; i < 4; i++)  m68_w16(ROM_BUF, &dp, pal_tx[i]);

    /* Build 64 ASCII glyphs (' '..'_', codes 32..95) in 2bpp TC0100SCN TX format at $001080 (64 x 16 B = 1024 B) */
    for (int ch = 32; ch < 96; ch++) {
        u32 gp = 0x1080u + (u32)(ch - 32) * 16u;
        const u8 *g = font5x7[ch - 32];
        for (int y = 0; y < 8; y++) {
            u8 b0 = 0, b1 = 0;
            if (y < 7) {
                for (int x = 0; x < 5; x++) {
                    if ((g[y] >> (4 - x)) & 1u) {
                        u8 bit = (u8)(1u << (6 - x));
                        b0 |= bit;
                        if (y < 3) b1 |= bit;   /* Two-tone gold/white gradient text! */
                    }
                }
            }
            m68_w16(ROM_BUF, &gp, ((u16)b0 << 8) | b1);
        }
    }

    static const char hud_str[] = "  BUBBLE DRAGONS F2     ROUND 01      ";
    u32 hp = 0x1500u;
    for (u32 i = 0; i < 38u; i++)
        m68_w16(ROM_BUF, &hp, (u16)(hud_str[i] ? (hud_str[i] - 32) : 0));

    /* ---- Main 68000 Entry at $000400 ---- */
    u32 p = 0x0400u;
    /* 1. Upload BG, Sprite & TX palettes into TC0110PCR ($A00000, $A00400, $A00800) */
    m68_w16(ROM_BUF, &p, 0x41F9u); m68_w32(ROM_BUF, &p, 0x00001000u);   /* LEA $1000.L, A0 */
    m68_w16(ROM_BUF, &p, 0x43F9u); m68_w32(ROM_BUF, &p, 0x00A00000u);   /* LEA $A00000.L, A1 */
    m68_w16(ROM_BUF, &p, 0x700Fu);                                      /* MOVEQ #15, D0 */
    u32 lp_p1 = p;
    m68_w16(ROM_BUF, &p, 0x32D8u);                                      /* MOVE.W (A0)+, (A1)+ */
    m68_w16(ROM_BUF, &p, 0x51C8u); m68_w16(ROM_BUF, &p, (u16)(s16)((s32)lp_p1 - (s32)p));

    m68_w16(ROM_BUF, &p, 0x43F9u); m68_w32(ROM_BUF, &p, 0x00A00400u);   /* Sprite pal $A00400 */
    m68_w16(ROM_BUF, &p, 0x700Fu);
    u32 lp_p2 = p;
    m68_w16(ROM_BUF, &p, 0x32D8u);
    m68_w16(ROM_BUF, &p, 0x51C8u); m68_w16(ROM_BUF, &p, (u16)(s16)((s32)lp_p2 - (s32)p));

    m68_w16(ROM_BUF, &p, 0x43F9u); m68_w32(ROM_BUF, &p, 0x00A00800u);   /* TX pal $A00800 */
    m68_w16(ROM_BUF, &p, 0x7003u);
    u32 lp_p3 = p;
    m68_w16(ROM_BUF, &p, 0x32D8u);
    m68_w16(ROM_BUF, &p, 0x51C8u); m68_w16(ROM_BUF, &p, (u16)(s16)((s32)lp_p3 - (s32)p));

    /* 2. Upload 64 2bpp glyphs from $1080 into TC0100SCN TX GFX RAM ($80A000, 512 words) */
    m68_w16(ROM_BUF, &p, 0x41F9u); m68_w32(ROM_BUF, &p, 0x00001080u);
    m68_w16(ROM_BUF, &p, 0x43F9u); m68_w32(ROM_BUF, &p, 0x0080A000u);
    m68_w16(ROM_BUF, &p, 0x303Cu); m68_w16(ROM_BUF, &p, 511);
    u32 lp_txg = p;
    m68_w16(ROM_BUF, &p, 0x32D8u);
    m68_w16(ROM_BUF, &p, 0x51C8u); m68_w16(ROM_BUF, &p, (u16)(s16)((s32)lp_txg - (s32)p));

    /* 3. Write HUD row 1 into TC0100SCN TX0 ($808084 = row 1, col 2) */
    m68_w16(ROM_BUF, &p, 0x41F9u); m68_w32(ROM_BUF, &p, 0x00001500u);
    m68_w16(ROM_BUF, &p, 0x43F9u); m68_w32(ROM_BUF, &p, 0x00808084u);
    m68_w16(ROM_BUF, &p, 0x7025u);                                      /* MOVEQ #37, D0 */
    u32 lp_hud = p;
    m68_w16(ROM_BUF, &p, 0x32D8u);
    m68_w16(ROM_BUF, &p, 0x51C8u); m68_w16(ROM_BUF, &p, (u16)(s16)((s32)lp_hud - (s32)p));

    /* 4. Build Bubble Bobble Cavern Platforms in TC0100SCN FG0 ($804000) & Starfield in BG0 ($800000):
       - BG0 ($800000): sparse stars (tile 1)
       - FG0 ($804000): left/right walls (col 0..1 & 38..39), floor (row 26..27),
                        3 Bubble-Bobble floating platforms on rows 10, 16, 21 (cols 8..31)! */
    m68_w16(ROM_BUF, &p, 0x43F9u); m68_w32(ROM_BUF, &p, 0x00800000u);
    m68_w16(ROM_BUF, &p, 0x303Cu); m68_w16(ROM_BUF, &p, 1791);          /* 28 rows x 64 cols = 1792 cells */
    u32 lp_bg = p;
    m68_w16(ROM_BUF, &p, 0x4259u);                                      /* CLR.W (A1)+ (attr=0) */
    m68_w16(ROM_BUF, &p, 0x3200u);                                      /* MOVE.W D0, D1 */
    m68_w16(ROM_BUF, &p, 0x0241u); m68_w16(ROM_BUF, &p, 0x0013u);       /* ANDI.W #$0013, D1 */
    u32 b_nst = m68_bcc16(ROM_BUF, &p, 0x6600u);                        /* BNE no_star */
    m68_w16(ROM_BUF, &p, 0x32FCu); m68_w16(ROM_BUF, &p, 1u);            /* MOVE.W #1, (A1)+ */
    u32 b_stdn = m68_bcc16(ROM_BUF, &p, 0x6000u);
    m68_patch16(ROM_BUF, b_nst, p);
    m68_w16(ROM_BUF, &p, 0x4259u);                                      /* CLR.W (A1)+ */
    m68_patch16(ROM_BUF, b_stdn, p);
    m68_w16(ROM_BUF, &p, 0x51C8u); m68_w16(ROM_BUF, &p, (u16)(s16)((s32)lp_bg - (s32)p));

    /* Helper macro-free loops to stamp FG0 ($804000 + (row*64 + col)*4):
       Floor row 26 & 27 (cols 0..39): $804000 + 26*256 = $805A00 & $805B00
       Platform 1 row 21 (cols 8..31): $804000 + 21*256 + 32 = $805520 (24 bricks)
       Platform 2 row 15 (cols 8..31): $804000 + 15*256 + 32 = $804F20 (24 bricks)
       Platform 3 row  9 (cols 8..31): $804000 +  9*256 + 32 = $804920 (24 bricks) */
    static const struct { u32 addr; u16 count, tile; } spans[] = {
        {0x00805A00u, 39, 2}, {0x00805B00u, 39, 2},
        {0x00805520u, 23, 2}, {0x00804F20u, 23, 2}, {0x00804920u, 23, 2},
        {0x00804300u,  0, 3}
    };
    for (int s = 0; spans[s].tile != 3; s++) {
        m68_w16(ROM_BUF, &p, 0x43F9u); m68_w32(ROM_BUF, &p, spans[s].addr);
        m68_w16(ROM_BUF, &p, 0x303Cu); m68_w16(ROM_BUF, &p, spans[s].count);
        u32 ls = p;
        m68_w16(ROM_BUF, &p, 0x4259u);
        m68_w16(ROM_BUF, &p, 0x32FCu); m68_w16(ROM_BUF, &p, spans[s].tile);
        m68_w16(ROM_BUF, &p, 0x51C8u); m68_w16(ROM_BUF, &p, (u16)(s16)((s32)ls - (s32)p));
    }
    /* Side walls on rows 3..25 (col 0,1 and col 38,39) */
    m68_w16(ROM_BUF, &p, 0x43F9u); m68_w32(ROM_BUF, &p, 0x00804300u);
    m68_w16(ROM_BUF, &p, 0x7016u);                                      /* 23 rows (3..25) */
    u32 lw = p;
    m68_w16(ROM_BUF, &p, 0x4269u); m68_w16(ROM_BUF, &p, 0);
    m68_w16(ROM_BUF, &p, 0x337Cu); m68_w16(ROM_BUF, &p, 3); m68_w16(ROM_BUF, &p, 2);
    m68_w16(ROM_BUF, &p, 0x4269u); m68_w16(ROM_BUF, &p, 4);
    m68_w16(ROM_BUF, &p, 0x337Cu); m68_w16(ROM_BUF, &p, 3); m68_w16(ROM_BUF, &p, 6);
    m68_w16(ROM_BUF, &p, 0x4269u); m68_w16(ROM_BUF, &p, 152);
    m68_w16(ROM_BUF, &p, 0x337Cu); m68_w16(ROM_BUF, &p, 3); m68_w16(ROM_BUF, &p, 154);
    m68_w16(ROM_BUF, &p, 0x4269u); m68_w16(ROM_BUF, &p, 156);
    m68_w16(ROM_BUF, &p, 0x337Cu); m68_w16(ROM_BUF, &p, 3); m68_w16(ROM_BUF, &p, 158);
    m68_w16(ROM_BUF, &p, 0xD3FCu); m68_w32(ROM_BUF, &p, 256u);          /* ADDA.L #256, A1 */
    m68_w16(ROM_BUF, &p, 0x51C8u); m68_w16(ROM_BUF, &p, (u16)(s16)((s32)lw - (s32)p));

    /* 5. Initialize Game State in Work RAM $400000 (A5):
       +$00: frame      +$02: drag_x(64)   +$04: drag_y(192)  +$06: drag_vy(0)
       +$08: drag_dir(0)+$0A: bub_x($FFFF) +$0C: bub_y(0)     +$0E: bub_age(0)
       +$10: mon_x(216) +$12: mon_y(152)   +$14: mon_dx($FFFE)+$16: mon_state(0=walk, >0=trapped/popped) */
    m68_w16(ROM_BUF, &p, 0x4BF9u); m68_w32(ROM_BUF, &p, 0x00400000u);   /* LEA $400000.L, A5 */
    m68_w16(ROM_BUF, &p, 0x426Du); m68_w16(ROM_BUF, &p, 0x0000u);
    m68_w16(ROM_BUF, &p, 0x3B7Cu); m68_w16(ROM_BUF, &p, 64);     m68_w16(ROM_BUF, &p, 0x0002u);
    m68_w16(ROM_BUF, &p, 0x3B7Cu); m68_w16(ROM_BUF, &p, 192);    m68_w16(ROM_BUF, &p, 0x0004u);
    m68_w16(ROM_BUF, &p, 0x426Du); m68_w16(ROM_BUF, &p, 0x0006u);
    m68_w16(ROM_BUF, &p, 0x426Du); m68_w16(ROM_BUF, &p, 0x0008u);
    m68_w16(ROM_BUF, &p, 0x3B7Cu); m68_w16(ROM_BUF, &p, 0xFFFFu); m68_w16(ROM_BUF, &p, 0x000Au);
    m68_w16(ROM_BUF, &p, 0x3B7Cu); m68_w16(ROM_BUF, &p, 216);    m68_w16(ROM_BUF, &p, 0x0010u);
    m68_w16(ROM_BUF, &p, 0x3B7Cu); m68_w16(ROM_BUF, &p, 152);    m68_w16(ROM_BUF, &p, 0x0012u);
    m68_w16(ROM_BUF, &p, 0x3B7Cu); m68_w16(ROM_BUF, &p, 0xFFFEu); m68_w16(ROM_BUF, &p, 0x0014u);
    m68_w16(ROM_BUF, &p, 0x426Du); m68_w16(ROM_BUF, &p, 0x0016u);

    /* Unmask interrupts (MOVE #$2000, SR) & idle BRA.S *-2 */
    m68_w16(ROM_BUF, &p, 0x46FCu); m68_w16(ROM_BUF, &p, 0x2000u);
    m68_w16(ROM_BUF, &p, 0x60FEu);

    /* ---- Level 4 VBlank ISR at $000800 (60 Hz Gameplay + TC0200OBJ Zoom!) ---- */
    p = 0x0800u;
    m68_w16(ROM_BUF, &p, 0x48E7u); m68_w16(ROM_BUF, &p, 0xFFFEu);       /* MOVEM.L D0-D7/A0-A6, -(SP) */
    m68_w16(ROM_BUF, &p, 0x4BF9u); m68_w32(ROM_BUF, &p, 0x00400000u);   /* LEA $400000.L, A5 */

    /* 1. Increment frame & gently drift BG0 starfield scroll Y ($820004) */
    m68_w16(ROM_BUF, &p, 0x526Du); m68_w16(ROM_BUF, &p, 0x0000u);       /* ADDQ.W #1, 0(A5) */
    m68_w16(ROM_BUF, &p, 0x302Du); m68_w16(ROM_BUF, &p, 0x0000u);       /* MOVE.W 0(A5), D0 */
    m68_w16(ROM_BUF, &p, 0xE248u);                                      /* LSR.W #1, D0 */
    m68_w16(ROM_BUF, &p, 0x33C0u); m68_w32(ROM_BUF, &p, 0x00820004u);   /* MOVE.W D0, $820004 (BG0 Y!) */

    /* 2. Read JAMMA P1 from TC0220IOC ($B00001) -> invert into D2 */
    m68_w16(ROM_BUF, &p, 0x7400u);
    m68_w16(ROM_BUF, &p, 0x1439u); m68_w32(ROM_BUF, &p, 0x00B00001u);   /* MOVE.B $B00001.L, D2 */
    m68_w16(ROM_BUF, &p, 0x4602u);                                      /* NOT.B D2 */
    m68_w16(ROM_BUF, &p, 0x4A02u);                                      /* TST.B D2 */
    u32 b_man = m68_bcc16(ROM_BUF, &p, 0x6600u);
    /* Attract AI: walk back & forth, hop onto platforms, blow bubbles! */
    m68_w16(ROM_BUF, &p, 0x302Du); m68_w16(ROM_BUF, &p, 0x0000u);
    m68_w16(ROM_BUF, &p, 0x0800u); m68_w16(ROM_BUF, &p, 6u);            /* BTST #6, D0 */
    u32 b_al = m68_bcc16(ROM_BUF, &p, 0x6700u);
    m68_w16(ROM_BUF, &p, 0x7418u);                                      /* Right + Bubble */
    u32 b_ae = m68_bcc16(ROM_BUF, &p, 0x6000u);
    m68_patch16(ROM_BUF, b_al, p);
    m68_w16(ROM_BUF, &p, 0x7414u);                                      /* Left + Bubble */
    m68_patch16(ROM_BUF, b_ae, p);
    m68_w16(ROM_BUF, &p, 0x0240u); m68_w16(ROM_BUF, &p, 0x003Fu);
    u32 b_nj = m68_bcc16(ROM_BUF, &p, 0x6600u);
    m68_w16(ROM_BUF, &p, 0x0002u); m68_w16(ROM_BUF, &p, 0x0020u);       /* Jump every 64 frames! */
    m68_patch16(ROM_BUF, b_nj, p);
    m68_patch16(ROM_BUF, b_man, p);

    /* 3. Move Dragon X (2(A5)) & Facing (8(A5)) */
    m68_w16(ROM_BUF, &p, 0x302Du); m68_w16(ROM_BUF, &p, 0x0002u);
    m68_w16(ROM_BUF, &p, 0x0802u); m68_w16(ROM_BUF, &p, 3u);            /* Right? */
    u32 b_nr = m68_bcc16(ROM_BUF, &p, 0x6700u);
    m68_w16(ROM_BUF, &p, 0x5440u);                                      /* ADDQ.W #2, D0 */
    m68_w16(ROM_BUF, &p, 0x426Du); m68_w16(ROM_BUF, &p, 0x0008u);       /* face right (0) */
    m68_w16(ROM_BUF, &p, 0x0C40u); m68_w16(ROM_BUF, &p, 280);
    u32 b_rok = m68_bcc16(ROM_BUF, &p, 0x6F00u);
    m68_w16(ROM_BUF, &p, 0x303Cu); m68_w16(ROM_BUF, &p, 280);
    m68_patch16(ROM_BUF, b_rok, p);
    m68_patch16(ROM_BUF, b_nr, p);

    m68_w16(ROM_BUF, &p, 0x0802u); m68_w16(ROM_BUF, &p, 2u);            /* Left? */
    u32 b_nl = m68_bcc16(ROM_BUF, &p, 0x6700u);
    m68_w16(ROM_BUF, &p, 0x5540u);                                      /* SUBQ.W #2, D0 */
    m68_w16(ROM_BUF, &p, 0x3B7Cu); m68_w16(ROM_BUF, &p, 0x0100u); m68_w16(ROM_BUF, &p, 0x0008u); /* FlipX */
    m68_w16(ROM_BUF, &p, 0x0C40u); m68_w16(ROM_BUF, &p, 24);
    u32 b_lok = m68_bcc16(ROM_BUF, &p, 0x6C00u);
    m68_w16(ROM_BUF, &p, 0x303Cu); m68_w16(ROM_BUF, &p, 24);
    m68_patch16(ROM_BUF, b_lok, p);
    m68_patch16(ROM_BUF, b_nl, p);
    m68_w16(ROM_BUF, &p, 0x3B40u); m68_w16(ROM_BUF, &p, 0x0002u);

    /* Jump & Gravity on Dragon Y (4(A5), vy=6(A5)) */
    m68_w16(ROM_BUF, &p, 0x302Du); m68_w16(ROM_BUF, &p, 0x0004u);       /* D0 = drag_y */
    m68_w16(ROM_BUF, &p, 0x322Du); m68_w16(ROM_BUF, &p, 0x0006u);       /* D1 = drag_vy */
    m68_w16(ROM_BUF, &p, 0x4A41u);                                      /* on ground (vy==0)? */
    u32 b_air = m68_bcc16(ROM_BUF, &p, 0x6600u);
    m68_w16(ROM_BUF, &p, 0x0202u); m68_w16(ROM_BUF, &p, 0x0021u);       /* Jump (Btn2 or Up)? */
    u32 b_nojp = m68_bcc16(ROM_BUF, &p, 0x6700u);
    m68_w16(ROM_BUF, &p, 0x323Cu); m68_w16(ROM_BUF, &p, (u16)-7);       /* vy = -7 */
    m68_patch16(ROM_BUF, b_nojp, p);
    m68_patch16(ROM_BUF, b_air, p);
    m68_w16(ROM_BUF, &p, 0xD041u);                                      /* drag_y += vy */
    m68_w16(ROM_BUF, &p, 0x5241u);                                      /* vy += 1 */
    m68_w16(ROM_BUF, &p, 0x0C40u); m68_w16(ROM_BUF, &p, 192);           /* Floor at Y=192 */
    u32 b_nfl = m68_bcc16(ROM_BUF, &p, 0x6D00u);
    m68_w16(ROM_BUF, &p, 0x303Cu); m68_w16(ROM_BUF, &p, 192);
    m68_w16(ROM_BUF, &p, 0x7200u);
    m68_patch16(ROM_BUF, b_nfl, p);
    m68_w16(ROM_BUF, &p, 0x3B40u); m68_w16(ROM_BUF, &p, 0x0004u);
    m68_w16(ROM_BUF, &p, 0x3B41u); m68_w16(ROM_BUF, &p, 0x0006u);

    /* 4. Rainbow Bubble Shoot & Float ($0A=bub_x, $0C=bub_y, $0E=bub_age) */
    m68_w16(ROM_BUF, &p, 0x302Du); m68_w16(ROM_BUF, &p, 0x000Au);
    m68_w16(ROM_BUF, &p, 0x0C40u); m68_w16(ROM_BUF, &p, 0xFFFFu);
    u32 b_spb = m68_bcc16(ROM_BUF, &p, 0x6700u);
    m68_w16(ROM_BUF, &p, 0x526Du); m68_w16(ROM_BUF, &p, 0x000Eu);       /* bub_age++ */
    m68_w16(ROM_BUF, &p, 0x322Du); m68_w16(ROM_BUF, &p, 0x000Eu);
    m68_w16(ROM_BUF, &p, 0x0C41u); m68_w16(ROM_BUF, &p, 20);            /* Shoot horizontally first 20f, then float up! */
    u32 b_flt = m68_bcc16(ROM_BUF, &p, 0x6E00u);
    m68_w16(ROM_BUF, &p, 0x5840u);                                      /* bub_x += 4 */
    u32 b_bmv = m68_bcc16(ROM_BUF, &p, 0x6000u);
    m68_patch16(ROM_BUF, b_flt, p);
    m68_w16(ROM_BUF, &p, 0x536Du); m68_w16(ROM_BUF, &p, 0x000Cu);       /* bub_y -= 1 */
    m68_patch16(ROM_BUF, b_bmv, p);
    m68_w16(ROM_BUF, &p, 0x0C6Du); m68_w16(ROM_BUF, &p, 28); m68_w16(ROM_BUF, &p, 0x000Cu);
    u32 b_bok = m68_bcc16(ROM_BUF, &p, 0x6E00u);
    m68_w16(ROM_BUF, &p, 0x303Cu); m68_w16(ROM_BUF, &p, 0xFFFFu);       /* Pop at ceiling! */
    m68_patch16(ROM_BUF, b_bok, p);
    m68_w16(ROM_BUF, &p, 0x3B40u); m68_w16(ROM_BUF, &p, 0x000Au);
    u32 b_bdn = m68_bcc16(ROM_BUF, &p, 0x6000u);

    m68_patch16(ROM_BUF, b_spb, p);
    m68_w16(ROM_BUF, &p, 0x0802u); m68_w16(ROM_BUF, &p, 4u);            /* Btn1? */
    u32 b_nb = m68_bcc16(ROM_BUF, &p, 0x6700u);
    m68_w16(ROM_BUF, &p, 0x302Du); m68_w16(ROM_BUF, &p, 0x0002u);
    m68_w16(ROM_BUF, &p, 0x0640u); m68_w16(ROM_BUF, &p, 16);
    m68_w16(ROM_BUF, &p, 0x3B40u); m68_w16(ROM_BUF, &p, 0x000Au);
    m68_w16(ROM_BUF, &p, 0x3B6Du); m68_w16(ROM_BUF, &p, 0x0004u); m68_w16(ROM_BUF, &p, 0x000Cu);
    m68_w16(ROM_BUF, &p, 0x426Du); m68_w16(ROM_BUF, &p, 0x000Eu);
    /* Notify Sound Z80 via TC0140SYT ($B80001/$B80003) -> Bubble Bloop ADPCM! */
    m68_w16(ROM_BUF, &p, 0x13FCu); m68_w16(ROM_BUF, &p, 0x0000u); m68_w32(ROM_BUF, &p, 0x00B80001u);
    m68_w16(ROM_BUF, &p, 0x13FCu); m68_w16(ROM_BUF, &p, 0x0001u); m68_w32(ROM_BUF, &p, 0x00B80003u);
    m68_patch16(ROM_BUF, b_nb, p);
    m68_patch16(ROM_BUF, b_bdn, p);

    /* 5. Patrol Wind-Up Monsta ($10=mon_x, $12=mon_y, $14=mon_dx, $16=mon_state) */
    m68_w16(ROM_BUF, &p, 0x302Du); m68_w16(ROM_BUF, &p, 0x0010u);
    m68_w16(ROM_BUF, &p, 0xD06Du); m68_w16(ROM_BUF, &p, 0x0014u);
    m68_w16(ROM_BUF, &p, 0x0C40u); m68_w16(ROM_BUF, &p, 64);
    u32 b_m1 = m68_bcc16(ROM_BUF, &p, 0x6C00u);
    m68_w16(ROM_BUF, &p, 0x3B7Cu); m68_w16(ROM_BUF, &p, 2); m68_w16(ROM_BUF, &p, 0x0014u);
    m68_patch16(ROM_BUF, b_m1, p);
    m68_w16(ROM_BUF, &p, 0x0C40u); m68_w16(ROM_BUF, &p, 240);
    u32 b_m2 = m68_bcc16(ROM_BUF, &p, 0x6F00u);
    m68_w16(ROM_BUF, &p, 0x3B7Cu); m68_w16(ROM_BUF, &p, 0xFFFEu); m68_w16(ROM_BUF, &p, 0x0014u);
    m68_patch16(ROM_BUF, b_m2, p);
    m68_w16(ROM_BUF, &p, 0x3B40u); m68_w16(ROM_BUF, &p, 0x0010u);

    /* 6. Write TC0200OBJ Sprite Table ($900000: 8 words/sprite: code, x, y, zoom, attr, 0,0,0) */
    m68_w16(ROM_BUF, &p, 0x43F9u); m68_w32(ROM_BUF, &p, 0x00900000u);
    /* Obj 0: Bubby the Green Dragon */
    m68_w16(ROM_BUF, &p, 0x32FCu); m68_w16(ROM_BUF, &p, 1u);            /* code=1 */
    m68_w16(ROM_BUF, &p, 0x32EDu); m68_w16(ROM_BUF, &p, 0x0002u);       /* x */
    m68_w16(ROM_BUF, &p, 0x32EDu); m68_w16(ROM_BUF, &p, 0x0004u);       /* y */
    m68_w16(ROM_BUF, &p, 0x4259u);                                      /* zoom=$0000 (16x16) */
    m68_w16(ROM_BUF, &p, 0x32EDu); m68_w16(ROM_BUF, &p, 0x0008u);       /* attr (FlipX/pal0) */
    m68_w16(ROM_BUF, &p, 0x4259u); m68_w16(ROM_BUF, &p, 0x4259u); m68_w16(ROM_BUF, &p, 0x4259u);

    /* Obj 1: Patrol Wind-Up Monsta */
    m68_w16(ROM_BUF, &p, 0x32FCu); m68_w16(ROM_BUF, &p, 3u);            /* code=3 */
    m68_w16(ROM_BUF, &p, 0x32EDu); m68_w16(ROM_BUF, &p, 0x0010u);       /* x */
    m68_w16(ROM_BUF, &p, 0x32EDu); m68_w16(ROM_BUF, &p, 0x0012u);       /* y */
    m68_w16(ROM_BUF, &p, 0x4259u);
    m68_w16(ROM_BUF, &p, 0x4259u);
    m68_w16(ROM_BUF, &p, 0x4259u); m68_w16(ROM_BUF, &p, 0x4259u); m68_w16(ROM_BUF, &p, 0x4259u);

    /* Obj 2: Ambient Trapped-Monsta Bubble gently pulsing with TC0200OBJ Hardware Zoom! */
    m68_w16(ROM_BUF, &p, 0x32FCu); m68_w16(ROM_BUF, &p, 4u);            /* code=4 (trapped Monsta!) */
    m68_w16(ROM_BUF, &p, 0x32FCu); m68_w16(ROM_BUF, &p, 152u);          /* x=152 */
    m68_w16(ROM_BUF, &p, 0x302Du); m68_w16(ROM_BUF, &p, 0x0000u);
    m68_w16(ROM_BUF, &p, 0x0240u); m68_w16(ROM_BUF, &p, 0x001Fu);
    m68_w16(ROM_BUF, &p, 0x0640u); m68_w16(ROM_BUF, &p, 84u);
    m68_w16(ROM_BUF, &p, 0x32C0u);                                      /* y=84..115 bobbing */
    m68_w16(ROM_BUF, &p, 0x302Du); m68_w16(ROM_BUF, &p, 0x0000u);
    m68_w16(ROM_BUF, &p, 0x0240u); m68_w16(ROM_BUF, &p, 0x0020u);       /* TC0200OBJ zoom pulse $0000 <-> $2020 (16x16 <-> 14x14)! */
    m68_w16(ROM_BUF, &p, 0x3200u);
    m68_w16(ROM_BUF, &p, 0xE148u);                                      /* LSL.W #8, D0 */
    m68_w16(ROM_BUF, &p, 0x8041u);                                      /* OR.W D1, D0 */
    m68_w16(ROM_BUF, &p, 0x32C0u);                                      /* zoom word */
    m68_w16(ROM_BUF, &p, 0x4259u);
    m68_w16(ROM_BUF, &p, 0x4259u); m68_w16(ROM_BUF, &p, 0x4259u); m68_w16(ROM_BUF, &p, 0x4259u);

    /* Obj 3: Player-shot Rainbow Bubble (active when $0A != $FFFF) */
    m68_w16(ROM_BUF, &p, 0x0C6Du); m68_w16(ROM_BUF, &p, 0xFFFFu); m68_w16(ROM_BUF, &p, 0x000Au);
    u32 b_nobj3 = m68_bcc16(ROM_BUF, &p, 0x6700u);
    m68_w16(ROM_BUF, &p, 0x32FCu); m68_w16(ROM_BUF, &p, 2u);            /* code=2 */
    m68_w16(ROM_BUF, &p, 0x32EDu); m68_w16(ROM_BUF, &p, 0x000Au);
    m68_w16(ROM_BUF, &p, 0x32EDu); m68_w16(ROM_BUF, &p, 0x000Cu);
    m68_w16(ROM_BUF, &p, 0x4259u);
    m68_w16(ROM_BUF, &p, 0x4259u);
    u32 b_o3d = m68_bcc16(ROM_BUF, &p, 0x6000u);
    m68_patch16(ROM_BUF, b_nobj3, p);
    m68_w16(ROM_BUF, &p, 0x4259u); m68_w16(ROM_BUF, &p, 0x4259u); m68_w16(ROM_BUF, &p, 0x4259u);
    m68_w16(ROM_BUF, &p, 0x4259u); m68_w16(ROM_BUF, &p, 0x4259u);
    m68_patch16(ROM_BUF, b_o3d, p);
    m68_w16(ROM_BUF, &p, 0x4259u); m68_w16(ROM_BUF, &p, 0x4259u); m68_w16(ROM_BUF, &p, 0x4259u);

    m68_w16(ROM_BUF, &p, 0x4CDFu); m68_w16(ROM_BUF, &p, 0x7FFFu);       /* MOVEM.L (SP)+, D0-D7/A0-A6 */
    m68_w16(ROM_BUF, &p, 0x4E73u);                                      /* RTE */
    S.rom_size = 0x10000u;
}

/* ============================================================================
   MAME .zip Romset Detection & Multi-Board Loader
   ============================================================================ */

int taito_is_zip(const u8 *zip, u32 size, const char *name)
{
    if (!zip_is(zip, size))
        return 0;
    static const char *const sets[] = {
        "bublbobl", "tokio", "tnzs", "plumpop", "arknoid2", "rastan", "rastsaga",
        "rainbow", "rbisland", "opwolf", "volfied", "cadash", "pbobble", "bustamov",
        "liquidk", "mizubaku", "finalb", "dondokod", "growl", "runark", "gunfront",
        "metalb", "dinorex", "deadconx", "driftout", "pulirula", 0
    };
    for (int i = 0; sets[i]; i++)
        if (taito_ci_has(name, sets[i]))
            return 1;

    u32 cnt = zip_count(zip, size);
    char mname[96];
    u32 msz = 0;
    for (u32 i = 0; i < cnt; i++) {
        if (zip_unpack_at(zip, size, i, 0, 0, &msz, mname, sizeof(mname)) != 0)
            continue;
        if (taito_ci_has(mname, "board_taito") || taito_ci_has(mname, "tc0100") ||
            taito_ci_has(mname, "b78-") || taito_ci_has(mname, "b04-") ||
            taito_ci_has(mname, "b22-") || taito_ci_has(mname, "c49-"))
            return 1;
    }
    return 0;
}

static void taito_decode_packed_tiles(const u8 *src, u32 sz)
{
    u32 n = sz / 32u;
    if (n > TAITO_MAX_TILES) n = TAITO_MAX_TILES;
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
    S.tile_mask  = taito_pow2_mask(n);
}

static void taito_decode_packed_sprites(const u8 *src, u32 sz)
{
    u32 n = sz / 128u;
    if (n > TAITO_MAX_SPR16) n = TAITO_MAX_SPR16;
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
    S.spr16_mask  = taito_pow2_mask(n);
}

static const char *taito_load_zip(const u8 *zip, u32 size, const char *path)
{
    u32 cnt = zip_count(zip, size);
    if (!cnt)
        return "corrupt Taito arcade .zip archive";

    taito_zero(ROM_BUF,  0x200000u);
    taito_zero(ZROM_BUF, TAITO_ZROM_CAP);
    taito_zero(PCM_BUF,  0x80000u);
    taito_zero(M->tile_nz, sizeof(M->tile_nz));
    taito_zero(M->spr_nz,  sizeof(M->spr_nz));

    S.board = TAITO_BOARD_F2;
    S.scr_w = 320;
    S.scr_h = 224;
    if (taito_ci_has(path, "rastan") || taito_ci_has(path, "rainbow") ||
        taito_ci_has(path, "rbisland") || taito_ci_has(path, "opwolf") ||
        taito_ci_has(path, "volfied") || taito_ci_has(path, "cadash")) {
        S.board = TAITO_BOARD_RASTAN;
        S.scr_w = 320;
        S.scr_h = 240;
    } else if (taito_ci_has(path, "bublbobl") || taito_ci_has(path, "tokio") ||
               taito_ci_has(path, "tnzs") || taito_ci_has(path, "plumpop")) {
        S.board = TAITO_BOARD_Z80;
        S.scr_w = 256;
        S.scr_h = 224;
    }

    u8 *split_hi = ZIP_STAGE + 0x200000u;
    u8 *split_lo = ZIP_STAGE + 0x300000u;
    u32 got_hi = 0, got_lo = 0;
    char mname[96];
    u32 msz = 0;

    for (u32 i = 0; i < cnt; i++) {
        TAITO_POLL();
        if (zip_unpack_at(zip, size, i, 0, 0, &msz, mname, sizeof(mname)) != 0 || !msz)
            continue;
        if (taito_ci_has(mname, "board_taito_f2"))     { S.board = TAITO_BOARD_F2;     S.scr_w = 320; S.scr_h = 224; continue; }
        if (taito_ci_has(mname, "board_taito_rastan")) { S.board = TAITO_BOARD_RASTAN; S.scr_w = 320; S.scr_h = 240; continue; }
        if (taito_ci_has(mname, "board_taito_z80"))    { S.board = TAITO_BOARD_Z80;    S.scr_w = 256; S.scr_h = 224; continue; }
        if (msz > 0x200000u)
            continue;
        if (zip_unpack_at(zip, size, i, ZIP_STAGE, 0x200000u, &msz, mname, sizeof(mname)) != 0)
            continue;

        if (taito_ci_ends(mname, "68k.rom") || taito_ci_ends(mname, "main.rom")) {
            u32 cap = msz < TAITO_ROM_CAP ? msz : TAITO_ROM_CAP;
            if (S.board == TAITO_BOARD_Z80) {
                for (u32 k = 0; k < cap; k++) ROM_BUF[k] = ZIP_STAGE[k];
            } else {
                /* Swap big-endian 68000 words into host u16 words for m68k.inc! */
                for (u32 k = 0; k + 1u < cap; k += 2u) {
                    ROM_BUF[k]     = ZIP_STAGE[k + 1u];
                    ROM_BUF[k + 1] = ZIP_STAGE[k];
                }
            }
            S.rom_size = cap;
        } else if (taito_ci_ends(mname, "z80.rom") || taito_ci_ends(mname, "sound.rom")) {
            u32 cap = msz < TAITO_ZROM_CAP ? msz : TAITO_ZROM_CAP;
            for (u32 k = 0; k < cap; k++) ZROM_BUF[k] = ZIP_STAGE[k];
            S.zrom_size = cap;
        } else if (taito_ci_ends(mname, "tiles.rom")) {
            taito_decode_packed_tiles(ZIP_STAGE, msz);
        } else if (taito_ci_ends(mname, "sprites.rom")) {
            taito_decode_packed_sprites(ZIP_STAGE, msz);
        } else if (taito_ci_ends(mname, "pcm.rom") || taito_ci_ends(mname, "adpcm.rom")) {
            u32 cap = msz < TAITO_PCM_CAP ? msz : TAITO_PCM_CAP;
            for (u32 k = 0; k < cap; k++) PCM_BUF[k] = ZIP_STAGE[k];
            S.pcm_size = cap;
        } else if (!got_hi && (taito_ci_has(mname, "_h.") || taito_ci_has(mname, "even"))) {
            u32 cap = msz < 0x100000u ? msz : 0x100000u;
            for (u32 k = 0; k < cap; k++) split_hi[k] = ZIP_STAGE[k];
            got_hi = cap;
        } else if (!got_lo && (taito_ci_has(mname, "_l.") || taito_ci_has(mname, "odd"))) {
            u32 cap = msz < 0x100000u ? msz : 0x100000u;
            for (u32 k = 0; k < cap; k++) split_lo[k] = ZIP_STAGE[k];
            got_lo = cap;
        }
    }

    if (!S.rom_size && got_hi && got_lo) {
        u32 pairs = got_hi < got_lo ? got_hi : got_lo;
        for (u32 k = 0; k < pairs && k * 2u + 1u < TAITO_ROM_CAP; k++) {
            ROM_BUF[k * 2u]     = split_lo[k];
            ROM_BUF[k * 2u + 1] = split_hi[k];
        }
        S.rom_size = pairs * 2u;
    }

    if (!S.rom_size)
        return "no recognizable Taito 68000 / Z80 program ROM found in .zip";

    S.pcm_mask = taito_pow2_mask(S.pcm_size);
    const char *tag = (S.board == TAITO_BOARD_Z80)
        ? "Taito Classic Dual-Z80 (Bubble Bobble / TNZS + YM2203 FM/SSG)"
        : (S.board == TAITO_BOARD_RASTAN)
            ? "Taito Rastan / Rainbow Islands (68000 + PC080SN + PC090OJ + YM2151)"
            : "Taito F2 / B-System (68000 + TC0100SCN + TC0200OBJ + YM2151/YM2610)";
    int n = 0;
    for (; tag[n] && n < (int)sizeof(S.info) - 1; n++)
        S.info[n] = tag[n];
    S.info[n] = 0;
    return 0;
}

/* ============================================================================
   Reset & 60 Hz Frame Execution
   ============================================================================ */

static void taito_setup_68k_map(void)
{
    for (int i = 0; i < 256; i++)
        rmap[i] = wmap[i] = 0;

    u32 rom_pages = (S.rom_size + 0xFFFFu) >> 16;
    if (rom_pages > 32u) rom_pages = 32u;
    for (u32 i = 0; i < rom_pages; i++)
        rmap[i] = ROM_BUF + (i << 16);

    /* Work RAM at $100000..$10FFFF (Rastan/Rainbow Islands) and $400000..$41FFFF (Taito F2/B-System) */
    rmap[0x10] = wmap[0x10] = M->wram;
    rmap[0x40] = wmap[0x40] = M->wram;
    rmap[0x41] = wmap[0x41] = M->wram + 0x10000u;
}

static void taito_setup_z80_maps(void)
{
    /* Sound Z80: $0000..$BFFF ROM, $C000..$DFFF RAM */
    for (int i = 0; i < 64; i++)
        M->zsnd.rd[i] = M->zsnd.wr[i] = M->zsnd.op[i] = 0;
    u32 zp = (S.zrom_size + 1023u) >> 10;
    if (zp > 48u) zp = 48u;
    for (u32 i = 0; i < zp; i++)
        M->zsnd.rd[i] = &ZROM_BUF[i << 10];
    for (int i = 48; i < 56; i++) {
        u8 *p = &M->zram[(i - 48) << 10];
        M->zsnd.rd[i] = M->zsnd.wr[i] = p;
    }

    /* Main Z80 (Bubble Bobble / TNZS): $0000..$7FFF fixed ROM, rest via callbacks */
    for (int i = 0; i < 64; i++)
        M->zmain.rd[i] = M->zmain.wr[i] = M->zmain.op[i] = 0;
    if (S.board == TAITO_BOARD_Z80) {
        for (int i = 0; i < 32; i++)
            M->zmain.rd[i] = &ROM_BUF[i << 10];
    }
}

void taito_reset(void)
{
    taito_zero(M->wram,    sizeof(M->wram));
    taito_zero(M->scn_ram, sizeof(M->scn_ram));
    taito_zero(M->tx_gfx,  sizeof(M->tx_gfx));
    taito_zero(M->tx_nz,   sizeof(M->tx_nz));
    taito_zero(M->obj_ram, sizeof(M->obj_ram));
    taito_zero(M->pal_ram, sizeof(M->pal_ram));
    taito_zero(M->pal15,   sizeof(M->pal15));
    taito_zero(M->zram,    sizeof(M->zram));
    taito_zero(M->mcu_ram, sizeof(M->mcu_ram));

    taito_zero(S.scn_ctrl, sizeof(S.scn_ctrl));
    taito_zero(S.pc080_scrollx, sizeof(S.pc080_scrollx));
    taito_zero(S.pc080_scrolly, sizeof(S.pc080_scrolly));
    S.pc080_ctrl = 0;
    S.syt_mode = S.syt_status = 0;
    taito_zero(S.syt_main2sub, sizeof(S.syt_main2sub));
    taito_zero(S.syt_sub2main, sizeof(S.syt_sub2main));
    S.z80_rombank = 0;
    S.z80_vidctrl = 0;
    taito_zero(S.pcm, sizeof(S.pcm));
    taito_zero(&S.ssg, sizeof(S.ssg));
    S.ssg.regs[7] = 0x3Fu;
    S.snd_head = S.snd_tail = 0;
    S.jammed = 0;
    S.frame_no = 0;

    taito_zero(&M->zsnd, sizeof(M->zsnd));
    z80_init(&M->zsnd);
    M->zsnd.read  = taito_zsnd_read;
    M->zsnd.write = taito_zsnd_write;
    M->zsnd.in    = taito_zsnd_in;
    M->zsnd.out   = taito_zsnd_out;
    M->zsnd.trap  = -1;

    taito_zero(&M->zmain, sizeof(M->zmain));
    z80_init(&M->zmain);
    M->zmain.read  = taito_zmain_read;
    M->zmain.write = taito_zmain_write;
    M->zmain.in    = taito_zmain_in;
    M->zmain.out   = taito_zmain_out;
    M->zmain.trap  = -1;

    taito_setup_z80_maps();
    z80_reset(&M->zsnd);
    z80_reset(&M->zmain);

    ym2151_init(&M->opm, 4000000u, S.sample_rate ? S.sample_rate : 48000u);

    if (S.board != TAITO_BOARD_Z80) {
        cpu_init();
        taito_setup_68k_map();
        cpu_reset();
    }
}

const char *taito_load(const u8 *image, u32 size, const char *path)
{
    u32 keep_rate = S.sample_rate;
    if (keep_rate != 48000u && keep_rate != 44100u && keep_rate != 32000u && keep_rate != 22050u)
        keep_rate = 48000u;
    taito_zero(&S, sizeof(S));
    S.sample_rate = keep_rate;

    if (!path || !*path || !image || size == 0) {
        S.board = TAITO_BOARD_F2;
        S.scr_w = 320;
        S.scr_h = 224;
        build_builtin_taito_assets();
        build_builtin_taito_z80();
        build_builtin_taito_68k();
        static const char bi[] = "Bubble Dragons F2 (Built-in Taito F2 68000 + TC0100SCN + TC0200OBJ + YM2151)";
        for (u32 i = 0; i < sizeof(bi); i++)
            S.info[i] = bi[i];
        taito_reset();
        return 0;
    }

    if (zip_is(image, size)) {
        const char *err = taito_load_zip(image, size, path);
        if (err) return err;
        taito_reset();
        return 0;
    }

    return "expected a Taito Classic / F2 arcade .zip romset";
}

void taito_pad2(u16 pad)
{
    S.pad2 = pad;
}

void taito_frame(u16 pad, u16 *picture)
{
    S.pad1 = pad;
    u8 coin_now = (pad & 0x0004u) ? 1u : 0u;
    if (coin_now && !S.coin_prev)
        S.coin_pulse = 5u;
    S.coin_prev = coin_now;

    const int total_lines = 262;
    const int vis_h = S.scr_h;
    u32 target_samples = (S.sample_rate ? S.sample_rate : 48000u) / 60u;
    u32 samp_acc = 0;

    M->zsnd.cycles = 0;
    if (S.board == TAITO_BOARD_Z80) {
        M->zmain.cycles = 0;
    } else {
        m.clock = 0;
        if (picture)
            taito_prepare_sprites();
    }

    for (int line = 0; line < total_lines; line++) {
        if (S.board == TAITO_BOARD_Z80) {
            /* 6.0 MHz Main Z80 (~381 cycles/line) */
            z80_run(&M->zmain, (line + 1) * 381);
            if (line == vis_h)
                M->zmain.irq = 1;
            else if (line == vis_h + 4)
                M->zmain.irq = 0;
        } else {
            /* 12.0 MHz 68000 (~763 cycles/line) */
            cpu_run((line + 1) * 763);
            if (line < vis_h && picture)
                taito_render_68k_line(line, picture + (u32)line * (u32)S.scr_w);
            if (line == vis_h) {
                /* Level 4 VBlank Autovector on F2, Level 6 on Rastan (both vectored in built-in!) */
                m.ipl = (S.board == TAITO_BOARD_RASTAN) ? 6u : 4u;
                check_pending();
            }
        }

        if (S.zrom_size > 0) {
            z80_run(&M->zsnd, (line + 1) * 254);
            if (ym2151_tick_timers(&M->opm, 254, 4000000u))
                M->zsnd.irq = 1;
        }

        samp_acc += target_samples;
        while (samp_acc >= (u32)total_lines) {
            samp_acc -= (u32)total_lines;
            s32 fm_l = 0, fm_r = 0;
            ym2151_sample_48khz(&M->opm, &fm_l, &fm_r);
            s32 mix = ((fm_l + fm_r) >> 1) + taito_pcm_step_48k() + taito_ssg_step_48k();
            if (mix > 32767) mix = 32767;
            else if (mix < -32768) mix = -32768;
            if (S.snd_head - S.snd_tail < TAITO_SND_RING)
                M->snd_ring[S.snd_head++ & (TAITO_SND_RING - 1u)] = (s16)mix;
        }
    }

    if (S.board == TAITO_BOARD_Z80 && picture)
        taito_render_z80_frame(picture);

    if (S.coin_pulse > 0)
        S.coin_pulse--;
    S.frame_no++;
}

int taito_width(void)  { return S.scr_w ? S.scr_w : 320; }
int taito_height(void) { return S.scr_h ? S.scr_h : 224; }
const char *taito_info(void) { return S.info; }

u8 *taito_save_ram(u32 *size, int *battery)
{
    if (size) *size = 0;
    if (battery) *battery = 0;
    return 0;
}

int taito_save_changed(void) { return 0; }
int taito_jammed(void)       { return S.jammed; }

void taito_audio_rate(u32 hz)
{
    S.sample_rate = hz ? hz : 48000u;
    M->opm.sample_rate = S.sample_rate;
}

int taito_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && S.snd_tail != S.snd_head)
        out[n++] = M->snd_ring[S.snd_tail++ & (TAITO_SND_RING - 1u)];
    return n;
}
