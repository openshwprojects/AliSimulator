/* Atari 800XL / 130XE (128 KB) & Atari 5200 SuperSystem: see a8.h. */
#pragma GCC optimize("O2")
#include "a8.h"

#ifdef A8_HOST
typedef unsigned long long u64;
#else
#include "hw.h"
#endif

#include "a8_roms.inc"

#define INLINE static inline __attribute__((always_inline))

#define LINE_CYC          114
#define PRE_WSYNC_CYC     105
#define POST_WSYNC_CYC    9
#define NTSC_LINES        262
#define PAL_LINES         312
#define VIS_START         8
#define VIS_END           248       /* 240 visible scanlines: 8..247 */

#define SND_RING          8192
#define TYPE_Q_MAX        512
#define CART_MAX          0x100000u /* Up to 1 MB banked cartridge */
#define ATR_MAX           0x100000u /* Up to 1 MB .atr disk or .xex binary */

/* 6502 status flags */
#define FN 0x80u
#define FV 0x40u
#define FU 0x20u
#define FB 0x10u
#define FD 0x08u
#define FI 0x04u
#define FZ 0x02u
#define FC 0x01u

/* Encoded ANTIC -> GTIA playfield pixel codes */
enum {
    PF_BK  = 0,
    PF_0   = 1,
    PF_1   = 2,
    PF_2   = 3,
    PF_3   = 4,
    PF_HI0 = 5,   /* Hires 0-bit: displays COLPF2, no PF collision */
    PF_HI1 = 6    /* Hires 1-bit: hue from PF2/PM, lum from PF1, PF2 collision */
};

/* Media & cartridge mapper kinds */
enum {
    MEDIA_NONE = 0,
    MEDIA_CART,
    MEDIA_ATR,
    MEDIA_XEX
};

enum {
    CART_NONE = 0,
    /* XL/XE mappers */
    CART_STD_8K,          /* $A000..$BFFF */
    CART_STD_16K,         /* $8000..$BFFF */
    CART_RIGHT_8K,        /* $8000..$9FFF */
    CART_OSS_034M,        /* 16K OSS two-chip ($A000/$B000) */
    CART_OSS_M091,        /* 16K OSS one-chip ($A000/$B000) */
    CART_DB_32K,          /* 32K DB ($8000 banked, $A000 fixed last 8K) */
    CART_XEGS,            /* 32K..1MB XEGS ($8000 banked, $A000 fixed last 8K) */
    CART_SW_XEGS,         /* 32K..1MB Switchable XEGS (bit 7 disables) */
    CART_MEGACART,        /* 16K..1MB MegaCart ($8000..$BFFF 16K banks, bit 7 disables) */
    CART_ATARIMAX_128K,   /* 128K Atarimax Flash ($A000 8K, $D500..$D50F, $D510..$D51F off) */
    CART_ATARIMAX_1MB,    /* 1MB Atarimax Flash ($A000 8K, $D500..$D57F, $D580..$D5FF off) */
    CART_WILLIAMS,        /* 32K/64K Williams ($A000 8K, $D500..$D507, $D508..$D50F off) */
    CART_EXPRESS_64K,     /* 64K Express / Diamond / SDX ($A000 8K) */
    CART_PHOENIX_8K,      /* 8K ($A000, any $D5xx disables) */
    CART_BLIZZARD_16K,    /* 16K ($8000..$BFFF, any $D5xx disables) */
    CART_SIC,             /* 128K..512K SIC! ($8000/$A000) */
    CART_BOUNTY_XL,       /* 40K Bounty Bob XL ($8000/$9000 4K banks + $A000 fixed 8K) */
    /* 5200 mappers */
    CART_5200_32K,        /* $4000..$BFFF linear 32K */
    CART_5200_16K_ONE,    /* 16K One-Chip ($8000..$BFFF mirrored at $4000..$7FFF) */
    CART_5200_16K_TWO,    /* 16K Two-Chip (first 8K at $4000/$6000, second 8K at $8000/$A000) */
    CART_5200_8K,         /* 8K mirrored 4x across $4000..$BFFF */
    CART_5200_4K,         /* 4K mirrored 8x across $4000..$BFFF */
    CART_5200_BOUNTY      /* 40K Bounty Bob ($4000 4x4K, $5000 4x4K, $8000 fixed 8K mirrored) */
};

struct a8_mem {
    u8 ram[0x20000];           /* 128 KB RAM (64 KB base + 64 KB 130XE extended banks) */
    u8 os_rom[0x4000];         /* 16 KB XL/XE OS ROM ($C000..$FFFF, Self-Test at +0x1000) */
    u8 bas_rom[0x2000];        /* 8 KB XL/XE BASIC ROM ($A000..$BFFF) */
    u8 bios52[0x800];          /* 2 KB Atari 5200 BIOS ($F800..$FFFF) */
    u8 ff_page[0x800];         /* 2 KB open-bus 0xFF page */
    u8 zero_page[0x800];       /* 2 KB dummy ANTIC I/O page */
    u8 cart_rom[CART_MAX];     /* Up to 1 MB cartridge image */
    u8 atr_buf[ATR_MAX];       /* Up to 1 MB .atr disk image or .xex binary */
    u16 pal_ntsc[256];         /* 256-color NTSC GTIA palette (0bbbbbgggggrrrrr) */
    u16 pal_pal[256];          /* 256-color PAL  GTIA palette (0bbbbbgggggrrrrr) */
    u8 pf_buf[384];            /* Scanline playfield pixel buffer */
    u8 pm_mask[A8_W];          /* Per-pixel Player/Missile bitmask (P0..3=0..3, M0..3=4..7) */
    u8 sio_rx_buf[300];        /* Serial SIO frame reply buffer */
    s16 snd_ring[SND_RING];    /* 48 kHz mono audio output ring */
    u8 type_q[TYPE_Q_MAX];     /* Queued POKEY KBCODEs from a8_type() */
};

#ifdef A8_HOST
static struct a8_mem a8_host_mem;
#define M (&a8_host_mem)
#else
#define M ((struct a8_mem *)KSEG0(EMU_RAM_PHYS))
#endif

static struct {
    u8 is_5200;
    u8 is_pal;
    u8 media_kind;
    u8 cart_kind;
    u32 cart_size;
    u32 atr_size;

    /* 32 x 2 KB fast memory page tables */
    const u8 *rd_page[32];
    u8 *wr_page[32];
    const u8 *antic_page[32];
    const u8 *code_page;
    u16 code_tag;

    /* SALLY 6502C CPU */
    u16 pc;
    u8 a, x, y, sp, p;
    s32 cyc;
    u8 nmi_pend, irq_pend, jammed;
    u8 wsync, wsync_next;

    /* Cartridge state */
    u8 cart_enabled;
    u8 cart_left_on;           /* External cart active at $A000..$BFFF (drives TRIG3 RD5) */
    u8 cart_bank;
    u8 cart_bank2;
    u8 sic_reg;
    u8 express_mask;

    /* 6520 PIA ($D300..$D303) */
    u8 porta_out, ddra, pactl;
    u8 portb_out, ddrb, pbctl;
    u8 eff_portb;

    /* ANTIC ($D400..$D40F) */
    u8 dmactl, chactl, hscrol, vscrol, pmbase, chbase;
    u8 nmien, nmist;
    u16 dlist, msc;
    u16 cur_scanline;
    u8 dl_ir;
    u8 dl_vrow, dl_vrow_end;
    u8 dl_in_vscrol;
    u8 dl_active_row;
    u8 dl_wait_vb;
    u8 dl_dli_today;
    u8 line_chars[48];
    u16 row_msc_base;
    int row_fetch_bytes;

    /* GTIA ($D000..$D01F / $C000..$C01F) */
    u8 hposp[4], hposm[4];
    u8 sizep[4], sizem;
    u8 grafp[4], grafm;
    u8 colpm[4], colpf[4], colbk;
    u8 prior, vdelay, gractl, consol_wr;
    u8 m2pf[4], p2pf[4], m2pl[4], p2pl[4];
    u8 trig_live[4], trig_latch[4];

    /* POKEY ($D200..$D20F / $E800..$E80F) */
    u8 audf[4], audc[4], audctl;
    u8 irqen, irqst, skctl, skstat;
    u8 kbcode;
    u8 pot_target[8], pot_scan, allpot;
    u32 lfsr17, lfsr9, lfsr5, lfsr4;
    s32 tmr_cnt[4], tmr_period[4];

    /* POKEY 48 kHz audio state */
    s32 snd_div[4], snd_period[4];
    u8 snd_out[4], snd_hpf[2];
    u32 snd_poly17, snd_poly9, snd_poly5, snd_poly4;
    u32 snd_rate, snd_phase;
    u32 snd_rd, snd_wr;
    s32 dc_est;

    /* .atr floppy & serial SIO state */
    u16 atr_sec_size;
    u32 atr_sectors;
    u8 atr_dd_short_boot;
    u8 sio_cmd_buf[6];
    u8 sio_cmd_len;
    u16 sio_rx_pos, sio_rx_len;
    s32 sio_rx_delay;
    u8 sio_serin_byte;
    u8 auto_option_frames;

    /* .xex multi-segment loader state */
    u8 xex_loading;
    u32 xex_pos, xex_size;
    u16 xex_first_addr;

    /* Input & typing queue */
    u16 pad;
    u8 hid_kbcode;
    u8 hid_key_down;
    u8 hid_shift;
    u8 prev_kbcode;
    u8 consol_keys;            /* bits 0..2: 1 = held (START=1, SELECT=2, OPTION=4) */
    u16 type_rd, type_wr;
    u8 type_timer;
    u8 type_holding;

    int save_dirty;
    char info[128];
} S;

static void mem_zero(void *dst, u32 n)
{
    u8 *p = (u8 *)dst;
    for (u32 i = 0; i < n; i++)
        p[i] = 0;
}

static void mem_copy(void *dst, const void *src, u32 n)
{
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    for (u32 i = 0; i < n; i++)
        d[i] = s[i];
}

static int ci_contains(const char *s, const char *sub)
{
    if (!s || !sub || !*sub)
        return 0;
    for (int i = 0; s[i]; i++) {
        int k = 0;
        while (sub[k]) {
            char a = s[i + k], b = sub[k];
            if (!a)
                return 0;
            if (a >= 'A' && a <= 'Z')
                a = (char)(a + 32);
            if (b >= 'A' && b <= 'Z')
                b = (char)(b + 32);
            if (a != b)
                break;
            k++;
        }
        if (!sub[k])
            return 1;
    }
    return 0;
}

/* ---- Authentic GTIA 256-color NTSC & PAL palette generation (0bbbbbgggggrrrrr) ----
   (built at every load: the tables are in the players' shared memory, which the next machine played writes
   over -- built once, behind a flag kept here, they were that machine's bytes after it) */
static void init_palettes(void)
{

    /* Chroma (R-Y, G-Y, B-Y) vectors in Q8 calibrated to Altirra / Laoo GTIA colors:
       Hue 0 = greyscale; Hue 1 = gold; Hue 3..4 = red-orange/red; Hue 6..7 = violet;
       Hue 8..9 = Atari GRAPHICS 0 blue ($94 -> rich cerulean blue); Hue 11..13 = cyan/green. */
    static const s16 ntsc_dr[16] = {
          0,  148,  196,  214,  192,  136,   54,  -38,
       -120, -178, -202, -184, -130,  -48,   44,  118
    };
    static const s16 ntsc_dg[16] = {
          0,   24,  -38,  -94, -124, -120,  -84,  -26,
         38,   94,  124,  120,   84,   28,  -28,   -4
    };
    static const s16 ntsc_db[16] = {
          0, -210, -172,  -94,   12,  116,  194,  232,
        220,  166,   76,  -30, -130, -198, -222, -226
    };

    static const s16 pal_dr[16] = {
          0,  140,  190,  212,  198,  146,   64,  -30,
       -114, -174, -200, -186, -136,  -56,   38,  114
    };
    static const s16 pal_dg[16] = {
          0,   30,  -32,  -88, -122, -122,  -88,  -32,
         32,   88,  122,  122,   88,   32,  -24,    2
    };
    static const s16 pal_db[16] = {
          0, -206, -176, -102,    4,  108,  190,  230,
        224,  172,   84,  -22, -124, -194, -220, -222
    };

    for (int mode = 0; mode < 2; mode++) {
        u16 *out = mode ? M->pal_pal : M->pal_ntsc;
        const s16 *dr = mode ? pal_dr : ntsc_dr;
        const s16 *dg = mode ? pal_dg : ntsc_dg;
        const s16 *db = mode ? pal_db : ntsc_db;
        for (int c = 0; c < 256; c++) {
            int hue = (c >> 4) & 15;
            int lum = c & 15;
            /* Luminance ramp: pure black at (0,0), smooth 16-step GTIA DAC */
            int y = (c == 0) ? 0 : (16 + lum * 15);
            int r = y + ((dr[hue] * 11) >> 4);
            int g = y + ((dg[hue] * 11) >> 4);
            int b = y + ((db[hue] * 11) >> 4);
            if (r < 0) r = 0; else if (r > 255) r = 255;
            if (g < 0) g = 0; else if (g > 255) g = 255;
            if (b < 0) b = 0; else if (b > 255) b = 255;
            out[c] = (u16)(((b >> 3) << 10) | ((g >> 3) << 5) | (r >> 3));
        }
    }
    for (int i = 0; i < 0x800; i++) {
        M->ff_page[i] = 0xFFu;
        M->zero_page[i] = 0x00u;
    }
}

/* ---- 32 x 2 KB MMU / Cartridge page table builder ---- */
static void rebuild_pages(void)
{
    S.code_tag = 0xFFFFu;
    S.code_page = 0;
    if (S.is_5200) {
        /* Atari 5200 memory map:
           $0000..$3FFF (pages 0..7):  16 KB RAM
           $4000..$BFFF (pages 8..23): 32 KB Cartridge slot
           $C000..$CFFF (pages 24..25): GTIA
           $D000..$D7FF (page 26):     ANTIC ($D400..$D4FF)
           $D800..$E7FF (pages 27..28): unmapped
           $E800..$EFFF (page 29):     POKEY
           $F000..$F7FF (page 30):     unmapped
           $F800..$FFFF (page 31):     2 KB 5200 OS BIOS */
        for (int p = 0; p < 8; p++) {
            u8 *ram = M->ram + ((u32)p << 11);
            S.rd_page[p] = ram;
            S.wr_page[p] = ram;
            S.antic_page[p] = ram;
        }
        for (int p = 8; p < 32; p++) {
            S.rd_page[p] = M->ff_page;
            S.wr_page[p] = 0;
            S.antic_page[p] = M->ff_page;
        }
        /* I/O pages trap to io_rd / io_wr via NULL */
        S.rd_page[24] = 0; S.rd_page[25] = 0; /* GTIA $C000..$CFFF */
        S.rd_page[26] = 0;                    /* ANTIC $D400..$D4FF */
        S.rd_page[29] = 0;                    /* POKEY $E800..$EFFF */
        /* 5200 2 KB BIOS at $F800..$FFFF */
        S.rd_page[31] = M->bios52;
        S.antic_page[31] = M->bios52;

        if (S.cart_enabled && S.cart_size > 0) {
            switch (S.cart_kind) {
            case CART_5200_32K:
                for (int p = 0; p < 16; p++) {
                    const u8 *rom = M->cart_rom + (((u32)p << 11) % S.cart_size);
                    S.rd_page[8 + p] = rom;
                    S.antic_page[8 + p] = rom;
                }
                break;
            case CART_5200_16K_ONE:
                /* 16 KB linear at $8000..$BFFF, mirrored at $4000..$7FFF */
                for (int p = 0; p < 16; p++) {
                    const u8 *rom = M->cart_rom + (((u32)(p & 7) << 11) % S.cart_size);
                    S.rd_page[8 + p] = rom;
                    S.antic_page[8 + p] = rom;
                }
                break;
            case CART_5200_16K_TWO:
                /* First 8K mirrored at $4000 & $6000; second 8K mirrored at $8000 & $A000 */
                for (int p = 0; p < 8; p++) {
                    const u8 *lo8 = M->cart_rom + ((u32)(p & 3) << 11);
                    const u8 *hi8 = M->cart_rom + 0x2000u + ((u32)(p & 3) << 11);
                    S.rd_page[8 + p] = lo8;
                    S.antic_page[8 + p] = lo8;
                    S.rd_page[16 + p] = hi8;
                    S.antic_page[16 + p] = hi8;
                }
                break;
            case CART_5200_8K:
                for (int p = 0; p < 16; p++) {
                    const u8 *rom = M->cart_rom + ((u32)(p & 3) << 11);
                    S.rd_page[8 + p] = rom;
                    S.antic_page[8 + p] = rom;
                }
                break;
            case CART_5200_4K:
                for (int p = 0; p < 16; p++) {
                    const u8 *rom = M->cart_rom + ((u32)(p & 1) << 11);
                    S.rd_page[8 + p] = rom;
                    S.antic_page[8 + p] = rom;
                }
                break;
            case CART_5200_BOUNTY: {
                /* $4000..$4FFF: 4x4K bank 1 (hotspots $4FF6..$4FF9 in page 9 -> trap rd/wr)
                   $5000..$5FFF: 4x4K bank 2 (hotspots $5FF6..$5FF9 in page 11 -> trap rd/wr)
                   $8000..$BFFF: fixed 8K (offset 0x8000) mirrored */
                const u8 *b0 = M->cart_rom + ((u32)(S.cart_bank & 3u) << 12);
                const u8 *b1 = M->cart_rom + 0x4000u + ((u32)(S.cart_bank2 & 3u) << 12);
                S.rd_page[8] = b0;
                S.rd_page[9] = 0; /* $4800..$4FFF trapped for $4FF6..$4FF9 read/write hotspots */
                S.antic_page[8] = b0;
                S.antic_page[9] = b0 + 0x800u;
                S.rd_page[10] = b1;
                S.rd_page[11] = 0; /* $5800..$5FFF trapped for $5FF6..$5FF9 read/write hotspots */
                S.antic_page[10] = b1;
                S.antic_page[11] = b1 + 0x800u;
                for (int p = 0; p < 8; p++) {
                    const u8 *fix = M->cart_rom + 0x8000u + ((u32)(p & 3) << 11);
                    S.rd_page[16 + p] = fix;
                    S.antic_page[16 + p] = fix;
                }
                break;
            }
            default:
                break;
            }
        }
        return;
    }

    /* ---- Atari 800XL / 130XE (128 KB) memory map ---- */
    u8 pb = (u8)((S.portb_out & S.ddrb) | ~S.ddrb);
    S.eff_portb = pb;

    /* Base 64 KB RAM across all 32 pages first */
    for (int p = 0; p < 32; p++) {
        u8 *ram = M->ram + ((u32)p << 11);
        S.rd_page[p] = ram;
        S.wr_page[p] = ram;
        S.antic_page[p] = ram;
    }

    /* 130XE Extended 64 KB RAM at $4000..$7FFF (pages 8..15):
       PORTB bits 2..3 select one of four 16 KB banks in ram[0x10000..0x1FFFF];
       bit 4 == 0 maps extended bank for CPU; bit 5 == 0 maps extended bank for ANTIC! */
    u32 ext_off = 0x10000u + (((u32)(pb >> 2) & 3u) << 14);
    if ((pb & 0x10u) == 0) {
        for (int p = 0; p < 8; p++) {
            u8 *eram = M->ram + ext_off + ((u32)p << 11);
            S.rd_page[8 + p] = eram;
            S.wr_page[8 + p] = eram;
        }
    }
    if ((pb & 0x20u) == 0) {
        for (int p = 0; p < 8; p++)
            S.antic_page[8 + p] = M->ram + ext_off + ((u32)p << 11);
    }

    /* OS ROM at $C000..$CFFF (pages 24..25) and $D800..$FFFF (pages 27..31) when PORTB bit 0 == 1 */
    if (pb & 0x01u) {
        for (int p = 24; p <= 25; p++) {
            const u8 *rom = M->os_rom + ((u32)(p - 24) << 11);
            S.rd_page[p] = rom;
            S.wr_page[p] = 0;
            S.antic_page[p] = rom;
        }
        for (int p = 27; p <= 31; p++) {
            const u8 *rom = M->os_rom + ((u32)(p - 24) << 11);
            S.rd_page[p] = rom;
            S.wr_page[p] = 0;
            S.antic_page[p] = rom;
        }
        /* Self-Test 2 KB ROM at $5000..$57FF (page 10) when PORTB bit 7 == 0 and CPU not in 130XE bank */
        if ((pb & 0x80u) == 0 && (pb & 0x10u) != 0) {
            const u8 *st = M->os_rom + 0x1000u;
            S.rd_page[10] = st;
            S.wr_page[10] = 0;
            if ((pb & 0x20u) != 0)
                S.antic_page[10] = st;
        }
    }

    /* External Cartridge ($8000..$9FFF = pages 16..19, $A000..$BFFF = pages 20..23) */
    S.cart_left_on = 0;
    if (S.cart_enabled && S.cart_size > 0) {
        u32 nb8 = S.cart_size >> 13;
        if (!nb8)
            nb8 = 1;
        switch (S.cart_kind) {
        case CART_STD_8K:
        case CART_PHOENIX_8K:
            for (int p = 0; p < 4; p++) {
                const u8 *rom = M->cart_rom + (((u32)p << 11) % S.cart_size);
                S.rd_page[20 + p] = rom;
                S.wr_page[20 + p] = 0;
                S.antic_page[20 + p] = rom;
            }
            S.cart_left_on = 1;
            break;
        case CART_RIGHT_8K:
            for (int p = 0; p < 4; p++) {
                const u8 *rom = M->cart_rom + (((u32)p << 11) % S.cart_size);
                S.rd_page[16 + p] = rom;
                S.wr_page[16 + p] = 0;
                S.antic_page[16 + p] = rom;
            }
            break;
        case CART_STD_16K:
        case CART_BLIZZARD_16K:
            for (int p = 0; p < 8; p++) {
                const u8 *rom = M->cart_rom + (((u32)p << 11) % S.cart_size);
                S.rd_page[16 + p] = rom;
                S.wr_page[16 + p] = 0;
                S.antic_page[16 + p] = rom;
            }
            S.cart_left_on = 1;
            break;
        case CART_XEGS:
        case CART_SW_XEGS:
        case CART_DB_32K: {
            u32 b = (u32)S.cart_bank % nb8;
            u32 last = nb8 - 1u;
            for (int p = 0; p < 4; p++) {
                const u8 *lo = M->cart_rom + (b << 13) + ((u32)p << 11);
                const u8 *hi = M->cart_rom + (last << 13) + ((u32)p << 11);
                S.rd_page[16 + p] = lo;
                S.wr_page[16 + p] = 0;
                S.antic_page[16 + p] = lo;
                S.rd_page[20 + p] = hi;
                S.wr_page[20 + p] = 0;
                S.antic_page[20 + p] = hi;
            }
            S.cart_left_on = 1;
            break;
        }
        case CART_MEGACART: {
            u32 nb16 = S.cart_size >> 14;
            if (!nb16)
                nb16 = 1;
            u32 b = (u32)S.cart_bank % nb16;
            for (int p = 0; p < 8; p++) {
                const u8 *rom = M->cart_rom + (b << 14) + ((u32)p << 11);
                S.rd_page[16 + p] = rom;
                S.wr_page[16 + p] = 0;
                S.antic_page[16 + p] = rom;
            }
            S.cart_left_on = 1;
            break;
        }
        case CART_ATARIMAX_128K:
        case CART_ATARIMAX_1MB:
        case CART_WILLIAMS:
        case CART_EXPRESS_64K: {
            u32 b = (u32)S.cart_bank % nb8;
            for (int p = 0; p < 4; p++) {
                const u8 *rom = M->cart_rom + (b << 13) + ((u32)p << 11);
                S.rd_page[20 + p] = rom;
                S.wr_page[20 + p] = 0;
                S.antic_page[20 + p] = rom;
            }
            S.cart_left_on = 1;
            break;
        }
        case CART_OSS_034M:
        case CART_OSS_M091: {
            /* 4x4K ROM: $A000..$AFFF = cart_bank (0..3), $B000..$BFFF = fixed bank (3 for 034M, 0 for M091) */
            u32 fix4 = (S.cart_kind == CART_OSS_M091) ? 0u : 3u;
            u32 b4 = (u32)S.cart_bank & 3u;
            for (int p = 0; p < 2; p++) {
                const u8 *lo = M->cart_rom + ((b4 << 12) % S.cart_size) + ((u32)p << 11);
                const u8 *hi = M->cart_rom + ((fix4 << 12) % S.cart_size) + ((u32)p << 11);
                S.rd_page[20 + p] = lo;
                S.wr_page[20 + p] = 0;
                S.antic_page[20 + p] = lo;
                S.rd_page[22 + p] = hi;
                S.wr_page[22 + p] = 0;
                S.antic_page[22 + p] = hi;
            }
            S.cart_left_on = 1;
            break;
        }
        case CART_SIC: {
            u32 nb16 = S.cart_size >> 14;
            if (!nb16)
                nb16 = 1;
            u32 b = (u32)(S.sic_reg & 0x1Fu) % nb16;
            const u8 *base = M->cart_rom + (b << 14);
            if (S.sic_reg & 0x20u) { /* $8000..$9FFF enabled */
                for (int p = 0; p < 4; p++) {
                    S.rd_page[16 + p] = base + ((u32)p << 11);
                    S.wr_page[16 + p] = 0;
                    S.antic_page[16 + p] = base + ((u32)p << 11);
                }
            }
            if ((S.sic_reg & 0x40u) == 0) { /* $A000..$BFFF enabled when bit 6 == 0 */
                for (int p = 0; p < 4; p++) {
                    S.rd_page[20 + p] = base + 0x2000u + ((u32)p << 11);
                    S.wr_page[20 + p] = 0;
                    S.antic_page[20 + p] = base + 0x2000u + ((u32)p << 11);
                }
                S.cart_left_on = 1;
            }
            break;
        }
        case CART_BOUNTY_XL: {
            const u8 *b0 = M->cart_rom + ((u32)(S.cart_bank & 3u) << 12);
            const u8 *b1 = M->cart_rom + 0x4000u + ((u32)(S.cart_bank2 & 3u) << 12);
            S.rd_page[16] = b0;
            S.rd_page[17] = 0; /* $8800..$8FFF trapped for $8FF6..$8FF9 */
            S.wr_page[16] = 0; S.wr_page[17] = 0;
            S.antic_page[16] = b0; S.antic_page[17] = b0 + 0x800u;
            S.rd_page[18] = b1;
            S.rd_page[19] = 0; /* $9800..$9FFF trapped for $9FF6..$9FF9 */
            S.wr_page[18] = 0; S.wr_page[19] = 0;
            S.antic_page[18] = b1; S.antic_page[19] = b1 + 0x800u;
            for (int p = 0; p < 4; p++) {
                const u8 *fix = M->cart_rom + 0x8000u + ((u32)p << 11);
                S.rd_page[20 + p] = fix;
                S.wr_page[20 + p] = 0;
                S.antic_page[20 + p] = fix;
            }
            S.cart_left_on = 1;
            break;
        }
        default:
            break;
        }
    }

    /* Internal 8 KB BASIC at $A000..$BFFF (pages 20..23) when PORTB bit 1 == 0 and no external left cart */
    if (!S.cart_left_on && (pb & 0x02u) == 0) {
        for (int p = 0; p < 4; p++) {
            const u8 *bas = M->bas_rom + ((u32)p << 11);
            S.rd_page[20 + p] = bas;
            S.wr_page[20 + p] = 0;
            S.antic_page[20 + p] = bas;
        }
    }

    /* Hardware I/O window at $D000..$D7FF (page 26): always trapped on CPU */
    S.rd_page[26] = 0;
    S.wr_page[26] = 0;
    S.antic_page[26] = M->ff_page;
}

/* ---- Cartridge $D500..$D5FF CCTL & Bounty Bob hotspot switching ---- */
static void cctl_access(u16 addr, u8 val, int is_write)
{
    u8 lo = (u8)(addr & 0xFFu);
    switch (S.cart_kind) {
    case CART_OSS_034M: {
        static const u8 map034[16] = { 0, 255, 255, 0, 1, 255, 255, 2, 255, 3, 255, 255, 255, 255, 255, 255 };
        u8 b = map034[lo & 15u];
        if (lo & 0x08u) {
            if (b == 255) {
                S.cart_enabled = 0;
            } else {
                S.cart_enabled = 1;
                S.cart_bank = b;
            }
        } else {
            S.cart_enabled = 1;
            S.cart_bank = (b == 255) ? 0 : b;
        }
        rebuild_pages();
        break;
    }
    case CART_OSS_M091: {
        u8 k = (u8)((lo & 1u) | ((lo & 8u) >> 2));
        if (k == 2u) {
            S.cart_enabled = 0;
        } else {
            S.cart_enabled = 1;
            S.cart_bank = (k == 0u) ? 1u : (k == 1u) ? 3u : 2u;
        }
        rebuild_pages();
        break;
    }
    case CART_DB_32K:
        S.cart_bank = (u8)(lo & 3u);
        rebuild_pages();
        break;
    case CART_XEGS:
        if (is_write) {
            S.cart_bank = (u8)(val & 0x7Fu);
            rebuild_pages();
        }
        break;
    case CART_SW_XEGS:
        if (is_write) {
            S.cart_enabled = (val & 0x80u) ? 0 : 1;
            S.cart_bank = (u8)(val & 0x7Fu);
            rebuild_pages();
        }
        break;
    case CART_MEGACART:
        if (is_write) {
            S.cart_enabled = (val & 0x80u) ? 0 : 1;
            S.cart_bank = (u8)(val & 0x7Fu);
            rebuild_pages();
        }
        break;
    case CART_ATARIMAX_128K:
        if (lo < 0x10u) {
            S.cart_enabled = 1;
            S.cart_bank = (u8)(lo & 0x0Fu);
            rebuild_pages();
        } else if (lo < 0x20u) {
            S.cart_enabled = 0;
            rebuild_pages();
        }
        break;
    case CART_ATARIMAX_1MB:
        if (lo < 0x80u) {
            S.cart_enabled = 1;
            S.cart_bank = (u8)(lo & 0x7Fu);
            rebuild_pages();
        } else {
            S.cart_enabled = 0;
            rebuild_pages();
        }
        break;
    case CART_WILLIAMS:
        if (lo < 0x08u) {
            S.cart_enabled = 1;
            S.cart_bank = (u8)(lo & 0x07u);
            rebuild_pages();
        } else if (lo < 0x10u) {
            S.cart_enabled = 0;
            rebuild_pages();
        }
        break;
    case CART_EXPRESS_64K:
        if ((lo & 0xF0u) == S.express_mask) {
            if (lo & 0x08u) {
                S.cart_enabled = 0;
            } else {
                S.cart_enabled = 1;
                S.cart_bank = (u8)((~lo) & 0x07u);
            }
            rebuild_pages();
        }
        break;
    case CART_PHOENIX_8K:
    case CART_BLIZZARD_16K:
        if (is_write) {
            S.cart_enabled = 0;
            rebuild_pages();
        }
        break;
    case CART_SIC:
        if (lo < 0x20u && is_write) {
            S.sic_reg = val;
            S.cart_enabled = ((val & 0x60u) == 0x40u) ? 0 : 1;
            rebuild_pages();
        }
        break;
    default:
        break;
    }
}

/* ---- POKEY IRQ line updater ---- */
INLINE void update_irq(void)
{
    u8 pokey_act = (u8)((~S.irqst) & S.irqen);
    u8 pia_act = 0;
    if (!S.is_5200) {
        if ((S.pactl & 0x81u) == 0x81u || (S.pbctl & 0x81u) == 0x81u)
            pia_act = 1;
    }
    S.irq_pend = (pokey_act || pia_act) ? 1 : 0;
}

/* ---- POKEY timer period helper (in 1.79 MHz CPU cycles) ---- */
static void pokey_recalc_periods(void)
{
    int base_mult = (S.audctl & 0x01u) ? 114 : 28;
    int c1_fast = (S.audctl & 0x40u) != 0;
    int c3_fast = (S.audctl & 0x20u) != 0;

    /* Channel 1 */
    S.snd_period[0] = c1_fast ? ((s32)S.audf[0] + 4) : (((s32)S.audf[0] + 1) * base_mult);
    /* Channel 2 (optionally 16-bit linked to channel 1) */
    if (S.audctl & 0x10u) {
        s32 f16 = (s32)S.audf[0] | ((s32)S.audf[1] << 8);
        S.snd_period[1] = c1_fast ? (f16 + 7) : ((f16 + 1) * base_mult);
    } else {
        S.snd_period[1] = ((s32)S.audf[1] + 1) * base_mult;
    }
    /* Channel 3 */
    S.snd_period[2] = c3_fast ? ((s32)S.audf[2] + 4) : (((s32)S.audf[2] + 1) * base_mult);
    /* Channel 4 (optionally 16-bit linked to channel 3) */
    if (S.audctl & 0x08u) {
        s32 f16 = (s32)S.audf[2] | ((s32)S.audf[3] << 8);
        S.snd_period[3] = c3_fast ? (f16 + 7) : ((f16 + 1) * base_mult);
    } else {
        S.snd_period[3] = ((s32)S.audf[3] + 1) * base_mult;
    }

    for (int i = 0; i < 4; i++) {
        if (S.snd_period[i] < 4)
            S.snd_period[i] = 4;
        S.tmr_period[i] = S.snd_period[i];
    }
}

/* ---- .atr sector offset & SIO operations ---- */
static int atr_sector_info(u32 sec, u32 *file_off, u32 *xfer_len)
{
    if (S.media_kind != MEDIA_ATR || sec == 0 || sec > S.atr_sectors)
        return 0;
    u32 ss = S.atr_sec_size;
    u32 len = (sec <= 3u && ss == 256u) ? 128u : ss;
    u32 off;
    if (ss == 256u && S.atr_dd_short_boot) {
        if (sec <= 3u)
            off = 16u + (sec - 1u) * 128u;
        else
            off = 16u + 384u + (sec - 4u) * 256u;
    } else {
        off = 16u + (sec - 1u) * ss;
    }
    if (off + len > S.atr_size)
        return 0;
    *file_off = off;
    *xfer_len = len;
    return 1;
}

static u8 sio_checksum(const u8 *buf, u32 len)
{
    u32 sum = 0;
    for (u32 i = 0; i < len; i++) {
        sum += buf[i];
        sum = (sum & 0xFFu) + (sum >> 8);
    }
    return (u8)sum;
}

/* Handle raw POKEY serial SIO 5-byte command frame (for custom non-OS loaders) */
static void sio_process_serial_cmd(void)
{
    const u8 *c = S.sio_cmd_buf;
    if (sio_checksum(c, 4) != c[4])
        return;
    u8 dev = c[0], cmd = c[1];
    u16 aux = (u16)c[2] | ((u16)c[3] << 8);
    if (dev != 0x31u || S.media_kind != MEDIA_ATR)
        return;

    u8 *rx = M->sio_rx_buf;
    u32 n = 0;
    if (cmd == 'S') {
        rx[n++] = 'A';
        rx[n++] = 'C';
        u8 st0 = 0x10u;
        if (S.atr_sec_size == 256u)
            st0 |= 0x20u;
        else if (S.atr_sectors >= 1000u)
            st0 |= 0x80u;
        rx[n++] = st0;
        rx[n++] = 0xFFu;
        rx[n++] = 0xE0u;
        rx[n++] = 0x00u;
        rx[n] = sio_checksum(rx + 2, 4);
        n++;
    } else if (cmd == 'R') {
        u32 off = 0, len = 0;
        rx[n++] = 'A';
        if (atr_sector_info(aux, &off, &len) && len <= 256u) {
            rx[n++] = 'C';
            for (u32 i = 0; i < len; i++)
                rx[n++] = M->atr_buf[off + i];
            rx[n] = sio_checksum(rx + 2, len);
            n++;
        } else {
            rx[n++] = 'E';
        }
    } else if (cmd == '?') {
        rx[n++] = 'A';
        rx[n++] = 'C';
        rx[n++] = 0x08u;
        rx[n++] = 0x08u;
    }
    if (n > 0) {
        S.sio_rx_pos = 0;
        S.sio_rx_len = (u16)n;
        S.sio_rx_delay = 160;
    }
}

/* ---- Hardware I/O Read & Write ---- */
static u8 gtia_rd(u16 addr)
{
    u8 r = (u8)(addr & 0x1Fu);
    if (r < 0x04u) return (u8)(S.m2pf[r] & 0x0Fu);
    if (r < 0x08u) return (u8)(S.p2pf[r - 4u] & 0x0Fu);
    if (r < 0x0Cu) return (u8)(S.m2pl[r - 8u] & 0x0Fu);
    if (r < 0x10u) return (u8)(S.p2pl[r - 12u] & 0x0Fu);
    if (r < 0x14u) {
        u8 t = (u8)(r - 0x10u);
        if (!S.is_5200 && t == 3u)
            return S.cart_left_on ? 1u : 0u;
        return (S.gractl & 0x04u) ? S.trig_latch[t] : S.trig_live[t];
    }
    if (r == 0x14u)
        return (S.is_pal && !S.is_5200) ? 0x01u : 0x0Fu;
    if (r == 0x1Fu) {
        if (S.is_5200)
            return 0x0Fu;
        u8 held = S.consol_keys;
        if (S.auto_option_frames > 0 && !(held & 0x02u))
            held |= 0x04u; /* Hold OPTION during .atr / .xex cold boot to disable BASIC */
        return (u8)((~held) & 0x07u & (~S.consol_wr | 0x07u));
    }
    return 0x0Fu;
}

static void gtia_wr(u16 addr, u8 val)
{
    u8 r = (u8)(addr & 0x1Fu);
    switch (r) {
    case 0x00: case 0x01: case 0x02: case 0x03:
        S.hposp[r] = val; break;
    case 0x04: case 0x05: case 0x06: case 0x07:
        S.hposm[r - 4u] = val; break;
    case 0x08: case 0x09: case 0x0A: case 0x0B:
        S.sizep[r - 8u] = (u8)(val & 3u); break;
    case 0x0C:
        S.sizem = val; break;
    case 0x0D: case 0x0E: case 0x0F: case 0x10:
        S.grafp[r - 0x0Du] = val; break;
    case 0x11:
        S.grafm = val; break;
    case 0x12: case 0x13: case 0x14: case 0x15:
        S.colpm[r - 0x12u] = (u8)(val & 0xFEu); break;
    case 0x16: case 0x17: case 0x18: case 0x19:
        S.colpf[r - 0x16u] = (u8)(val & 0xFEu); break;
    case 0x1A:
        S.colbk = (u8)(val & 0xFEu); break;
    case 0x1B:
        S.prior = val; break;
    case 0x1C:
        S.vdelay = val; break;
    case 0x1D:
        if (!(val & 0x04u)) {
            for (int i = 0; i < 4; i++)
                S.trig_latch[i] = 1u;
        } else {
            for (int i = 0; i < 4; i++)
                S.trig_latch[i] &= S.trig_live[i];
        }
        S.gractl = val;
        break;
    case 0x1E: /* HITCLR */
        for (int i = 0; i < 4; i++) {
            S.m2pf[i] = 0; S.p2pf[i] = 0;
            S.m2pl[i] = 0; S.p2pl[i] = 0;
        }
        break;
    case 0x1F:
        S.consol_wr = val;
        break;
    default:
        break;
    }
}

static u8 pokey_rd(u16 addr)
{
    u8 r = (u8)(addr & 0x0Fu);
    if (r < 0x08u) {
        u8 t = S.pot_target[r];
        return (S.pot_scan < t) ? S.pot_scan : t;
    }
    switch (r) {
    case 0x08:
        return S.allpot;
    case 0x09:
        return S.kbcode;
    case 0x0A:
        if ((S.skctl & 0x03u) == 0)
            return 0xFFu;
        /* Advance LFSR on read so tight RANDOM loops get distinct bytes */
        {
            u32 bit = ((S.lfsr17 >> 0) ^ (S.lfsr17 >> 5)) & 1u;
            S.lfsr17 = (S.lfsr17 >> 1) | (bit << 16);
            return (u8)((S.lfsr17 ^ (u32)S.cyc) & 0xFFu);
        }
    case 0x0D:
        return S.sio_serin_byte;
    case 0x0E:
        return S.irqst;
    case 0x0F:
        return S.skstat;
    default:
        return 0xFFu;
    }
}

static void pokey_wr(u16 addr, u8 val)
{
    u8 r = (u8)(addr & 0x0Fu);
    switch (r) {
    case 0x00: S.audf[0] = val; pokey_recalc_periods(); break;
    case 0x01: S.audc[0] = val; break;
    case 0x02: S.audf[1] = val; pokey_recalc_periods(); break;
    case 0x03: S.audc[1] = val; break;
    case 0x04: S.audf[2] = val; pokey_recalc_periods(); break;
    case 0x05: S.audc[2] = val; break;
    case 0x06: S.audf[3] = val; pokey_recalc_periods(); break;
    case 0x07: S.audc[3] = val; break;
    case 0x08: S.audctl = val; pokey_recalc_periods(); break;
    case 0x09: /* STIMER */
        for (int i = 0; i < 4; i++) {
            S.tmr_cnt[i] = S.tmr_period[i];
            S.snd_div[i] = S.snd_period[i];
            S.snd_out[i] = 1u;
        }
        break;
    case 0x0A: /* SKRES */
        S.skstat |= 0xE0u;
        break;
    case 0x0B: /* POTGO */
        S.pot_scan = 0;
        S.allpot = 0xFFu;
        break;
    case 0x0D: /* SEROUT */
        if (!S.is_5200 && (S.pbctl & 0x08u) == 0) {
            if (S.sio_cmd_len < 5u)
                S.sio_cmd_buf[S.sio_cmd_len++] = val;
        }
        if (S.irqen & 0x10u)
            S.irqst &= (u8)~0x10u;
        if (S.irqen & 0x08u)
            S.irqst &= (u8)~0x08u;
        update_irq();
        break;
    case 0x0E: /* IRQEN */
        S.irqen = val;
        S.irqst |= (u8)(~val | 0x08u);
        if (val & 0x08u)
            S.irqst &= (u8)~0x08u; /* Serial TX complete stays asserted when idle */
        update_irq();
        break;
    case 0x0F: /* SKCTL */
        S.skctl = val;
        if ((val & 0x03u) == 0) {
            S.sio_rx_len = 0;
            S.sio_cmd_len = 0;
        }
        break;
    default:
        break;
    }
}

static u8 pia_rd(u16 addr)
{
    switch (addr & 3u) {
    case 0: /* PORTA / DDRA */
        if ((S.pactl & 0x04u) == 0)
            return S.ddra;
        {
            u8 joy = 0xFFu;
            if (S.pad & A8_UP)    joy &= (u8)~0x01u;
            if (S.pad & A8_DOWN)  joy &= (u8)~0x02u;
            if (S.pad & A8_LEFT)  joy &= (u8)~0x04u;
            if (S.pad & A8_RIGHT) joy &= (u8)~0x08u;
            S.pactl &= (u8)~0xC0u;
            update_irq();
            return (u8)((S.porta_out & S.ddra) | (joy & ~S.ddra));
        }
    case 1: /* PORTB / DDRB */
        if ((S.pbctl & 0x04u) == 0)
            return S.ddrb;
        S.pbctl &= (u8)~0xC0u;
        update_irq();
        return (u8)((S.portb_out & S.ddrb) | ~S.ddrb);
    case 2:
        return (u8)(S.pactl & 0xBFu);
    case 3:
        return (u8)(S.pbctl & 0xBFu);
    }
    return 0xFFu;
}

static void pia_wr(u16 addr, u8 val)
{
    switch (addr & 3u) {
    case 0:
        if ((S.pactl & 0x04u) == 0)
            S.ddra = val;
        else
            S.porta_out = val;
        break;
    case 1:
        if ((S.pbctl & 0x04u) == 0)
            S.ddrb = val;
        else
            S.portb_out = val;
        rebuild_pages();
        break;
    case 2:
        S.pactl = (u8)((S.pactl & 0xC0u) | (val & 0x3Fu));
        update_irq();
        break;
    case 3: {
        u8 prev = S.pbctl;
        S.pbctl = (u8)((S.pbctl & 0xC0u) | (val & 0x3Fu));
        /* /COMMAND line (CB2, bit 3 when bit 5 == 1): falling clears buffer, rising executes cmd */
        if ((prev & 0x08u) && !(val & 0x08u)) {
            S.sio_cmd_len = 0;
            S.sio_rx_len = 0;
        } else if (!(prev & 0x08u) && (val & 0x08u)) {
            if (S.sio_cmd_len == 5u)
                sio_process_serial_cmd();
            S.sio_cmd_len = 0;
        }
        update_irq();
        break;
    }
    }
}

static u8 antic_io_rd(u16 addr)
{
    switch (addr & 0x0Fu) {
    case 0x0B: /* VCOUNT */
        return (u8)(S.cur_scanline >> 1);
    case 0x0C: /* PENH */
        return 0x80u;
    case 0x0D: /* PENV */
        return 0x40u;
    case 0x0F: /* NMIST */
        return S.nmist;
    default:
        return 0xFFu;
    }
}

static void antic_io_wr(u16 addr, u8 val)
{
    switch (addr & 0x0Fu) {
    case 0x00: S.dmactl = val; break;
    case 0x01: S.chactl = val; break;
    case 0x02: S.dlist = (u16)((S.dlist & 0xFF00u) | val); break;
    case 0x03: S.dlist = (u16)((S.dlist & 0x00FFu) | ((u16)val << 8)); break;
    case 0x04: S.hscrol = (u8)(val & 0x0Fu); break;
    case 0x05: S.vscrol = (u8)(val & 0x0Fu); break;
    case 0x07: S.pmbase = val; break;
    case 0x09: S.chbase = val; break;
    case 0x0A: /* WSYNC */
        if (S.wsync == 0) {
            S.wsync = 1;
            if (S.cyc > 0)
                S.cyc = 0;
        } else {
            S.wsync_next = 1;
        }
        break;
    case 0x0E: /* NMIEN */
        S.nmien = (u8)(val & 0xE0u);
        break;
    case 0x0F: /* NMIRES */
        S.nmist = 0x1Fu;
        break;
    default:
        break;
    }
}

static u8 io_rd(u16 addr)
{
    if (S.is_5200) {
        if (addr >= 0xC000u && addr < 0xD000u)
            return gtia_rd(addr);
        if (addr >= 0xD400u && addr < 0xD800u)
            return antic_io_rd(addr);
        if (addr >= 0xE800u && addr < 0xF000u)
            return pokey_rd(addr);
        if (S.cart_kind == CART_5200_BOUNTY) {
            if (addr >= 0x4800u && addr < 0x5000u) {
                if (addr >= 0x4FF6u && addr <= 0x4FF9u) {
                    S.cart_bank = (u8)(addr - 0x4FF6u);
                    rebuild_pages();
                }
                return M->cart_rom[((u32)(S.cart_bank & 3u) << 12) + (addr - 0x4000u)];
            }
            if (addr >= 0x5800u && addr < 0x6000u) {
                if (addr >= 0x5FF6u && addr <= 0x5FF9u) {
                    S.cart_bank2 = (u8)(addr - 0x5FF6u);
                    rebuild_pages();
                }
                return M->cart_rom[0x4000u + ((u32)(S.cart_bank2 & 3u) << 12) + (addr - 0x5000u)];
            }
        }
        return 0xFFu;
    }

    /* XL/XE Bounty Bob hotspots ($8FF6..$8FF9, $9FF6..$9FF9) */
    if (S.cart_kind == CART_BOUNTY_XL) {
        if (addr >= 0x8800u && addr < 0x9000u) {
            if (addr >= 0x8FF6u && addr <= 0x8FF9u) {
                S.cart_bank = (u8)(addr - 0x8FF6u);
                rebuild_pages();
            }
            return M->cart_rom[((u32)(S.cart_bank & 3u) << 12) + (addr - 0x8000u)];
        }
        if (addr >= 0x9800u && addr < 0xA000u) {
            if (addr >= 0x9FF6u && addr <= 0x9FF9u) {
                S.cart_bank2 = (u8)(addr - 0x9FF6u);
                rebuild_pages();
            }
            return M->cart_rom[0x4000u + ((u32)(S.cart_bank2 & 3u) << 12) + (addr - 0x9000u)];
        }
    }

    switch ((addr >> 8) & 0xFFu) {
    case 0xD0: return gtia_rd(addr);
    case 0xD1: return 0xFFu; /* PBI */
    case 0xD2: return pokey_rd(addr);
    case 0xD3: return pia_rd(addr);
    case 0xD4: return antic_io_rd(addr);
    case 0xD5:
        cctl_access(addr, 0, 0);
        if (S.cart_kind == CART_SIC && (addr & 0xFFu) < 0x20u)
            return S.sic_reg;
        return 0xFFu;
    case 0xD6:
    case 0xD7:
        return 0xFFu;
    default:
        return 0xFFu;
    }
}

static void io_wr(u16 addr, u8 val)
{
    if (S.is_5200) {
        if (addr >= 0xC000u && addr < 0xD000u) {
            gtia_wr(addr, val);
            return;
        }
        if (addr >= 0xD400u && addr < 0xD800u) {
            /* Note: WSYNC is $D40A on both XL/XE and 5200 */
            antic_io_wr(addr, val);
            return;
        }
        if (addr >= 0xE800u && addr < 0xF000u) {
            pokey_wr(addr, val);
            return;
        }
        if (S.cart_kind == CART_5200_BOUNTY) {
            if (addr >= 0x4FF6u && addr <= 0x4FF9u) {
                S.cart_bank = (u8)(addr - 0x4FF6u);
                rebuild_pages();
            } else if (addr >= 0x5FF6u && addr <= 0x5FF9u) {
                S.cart_bank2 = (u8)(addr - 0x5FF6u);
                rebuild_pages();
            }
        }
        return;
    }

    if (S.cart_kind == CART_BOUNTY_XL) {
        if (addr >= 0x8FF6u && addr <= 0x8FF9u) {
            S.cart_bank = (u8)(addr - 0x8FF6u);
            rebuild_pages();
            return;
        }
        if (addr >= 0x9FF6u && addr <= 0x9FF9u) {
            S.cart_bank2 = (u8)(addr - 0x9FF6u);
            rebuild_pages();
            return;
        }
    }

    if (addr < 0xD000u || addr >= 0xD800u)
        return; /* Ignore ROM writes */

    switch ((addr >> 8) & 0xFFu) {
    case 0xD0: gtia_wr(addr, val); break;
    case 0xD2: pokey_wr(addr, val); break;
    case 0xD3: pia_wr(addr, val); break;
    case 0xD4: antic_io_wr(addr, val); break;
    case 0xD5: cctl_access(addr, val, 1); break;
    default: break;
    }
}

INLINE u8 cpu_rd(u16 addr)
{
    const u8 *p = S.rd_page[addr >> 11];
    if (__builtin_expect(p != 0, 1))
        return p[addr & 0x7FFu];
    return io_rd(addr);
}

INLINE void cpu_wr(u16 addr, u8 val)
{
    u8 *p = S.wr_page[addr >> 11];
    if (__builtin_expect(p != 0, 1)) {
        p[addr & 0x7FFu] = val;
        return;
    }
    io_wr(addr, val);
}

INLINE u8 antic_rd(u16 addr)
{
    return S.antic_page[addr >> 11][addr & 0x7FFu];
}

INLINE u16 cpu_rd16(u16 addr)
{
    const u8 *p = S.rd_page[addr >> 11];
    u32 off = addr & 0x7FFu;
    if (__builtin_expect(p != 0 && off < 0x7FFu, 1))
        return (u16)p[off] | ((u16)p[off + 1u] << 8);
    return (u16)cpu_rd(addr) | ((u16)cpu_rd((u16)(addr + 1u)) << 8);
}

INLINE void push8(u8 v)
{
    M->ram[0x100u + S.sp] = v;
    S.sp--;
}

INLINE u8 pop8(void)
{
    S.sp++;
    return M->ram[0x100u + S.sp];
}

/* ---- High-level SIOV ($E459) & Multi-segment .xex Loader ($D1FF) ---- */
static int handle_siov_hook(void)
{
    u8 ddev = M->ram[0x0300];
    u8 dunit = M->ram[0x0301];
    u8 dcmd = M->ram[0x0302];
    u16 dbuf = (u16)M->ram[0x0304] | ((u16)M->ram[0x0305] << 8);
    u16 dbyt = (u16)M->ram[0x0308] | ((u16)M->ram[0x0309] << 8);
    u16 daux = (u16)M->ram[0x030A] | ((u16)M->ram[0x030B] << 8);
    u8 wire_dev = (u8)(ddev + (dunit ? (u8)(dunit - 1u) : 0u));
    u8 status = 0x8Au; /* 138 = Device Timeout */

    if (wire_dev == 0x31u) {
        if (S.media_kind == MEDIA_XEX) {
            if (dcmd == 'S') {
                static const u8 st[4] = { 0x10u, 0xFFu, 0xE0u, 0x00u };
                u16 n = dbyt < 4u ? dbyt : 4u;
                for (u16 i = 0; i < n; i++)
                    cpu_wr((u16)(dbuf + i), st[i]);
                status = 0x01u;
            } else if (dcmd == 'R' && daux == 1u) {
                /* Synthesize a clean 1-sector boot record at $0700 so XL OS completes cold start
                   and jumps through DOSVEC ($000A) to our $D1FF segment-loader trap! */
                static const u8 boot_sec[20] = {
                    0x00, 0x01, 0x00, 0x07, 0x06, 0x07,
                    /* $0706 (BOOT INIT): set DOSVEC ($000A) = $D1FF, CLC, RTS */
                    0xA9, 0xFF, 0x85, 0x0A,
                    0xA9, 0xD1, 0x85, 0x0B,
                    0x18, 0x60
                };
                u16 n = dbyt < 128u ? dbyt : 128u;
                for (u16 i = 0; i < n; i++)
                    cpu_wr((u16)(dbuf + i), (i < sizeof(boot_sec)) ? boot_sec[i] : 0u);
                S.xex_loading = 1;
                S.xex_pos = 0;
                S.xex_first_addr = 0xFFFFu;
                M->ram[0x02E0] = 0xFFu; M->ram[0x02E1] = 0xFFu;
                M->ram[0x02E2] = 0xFFu; M->ram[0x02E3] = 0xFFu;
                status = 0x01u;
            }
        } else if (S.media_kind == MEDIA_ATR) {
            if (dcmd == 'S') {
                u8 st[4] = { 0x10u, 0xFFu, 0xE0u, 0x00u };
                if (S.atr_sec_size == 256u)
                    st[0] |= 0x20u;
                else if (S.atr_sectors >= 1000u)
                    st[0] |= 0x80u;
                u16 n = dbyt < 4u ? dbyt : 4u;
                for (u16 i = 0; i < n; i++)
                    cpu_wr((u16)(dbuf + i), st[i]);
                status = 0x01u;
            } else if (dcmd == 'R') {
                u32 off = 0, len = 0;
                if (atr_sector_info(daux, &off, &len)) {
                    u16 n = dbyt < len ? dbyt : (u16)len;
                    for (u16 i = 0; i < n; i++)
                        cpu_wr((u16)(dbuf + i), M->atr_buf[off + i]);
                    status = 0x01u;
                } else {
                    status = 0x8Fu; /* 143 = Checksum/sector error */
                }
            } else if (dcmd == 'W' || dcmd == 'P') {
                u32 off = 0, len = 0;
                if (atr_sector_info(daux, &off, &len)) {
                    u16 n = dbyt < len ? dbyt : (u16)len;
                    for (u16 i = 0; i < n; i++)
                        M->atr_buf[off + i] = cpu_rd((u16)(dbuf + i));
                    S.save_dirty = 1;
                    status = 0x01u;
                } else {
                    status = 0x8Fu;
                }
            } else if (dcmd == 'N') { /* Read 12-byte PERCOM block */
                u16 spt = (S.atr_sectors == 1040u) ? 26u : 18u;
                u8 sides = (S.atr_sectors > 1440u) ? 1u : 0u;
                u8 tracks = (u8)((S.atr_sectors / (spt * (sides + 1u))) ? (S.atr_sectors / (spt * (sides + 1u))) : 40u);
                u8 percom[12] = {
                    tracks, 0x01u, (u8)(spt >> 8), (u8)(spt & 0xFFu),
                    sides, (S.atr_sec_size == 256u || spt == 26u) ? 0x04u : 0x00u,
                    (u8)(S.atr_sec_size >> 8), (u8)(S.atr_sec_size & 0xFFu),
                    0xFFu, 0x00u, 0x00u, 0x00u
                };
                u16 n = dbyt < 12u ? dbyt : 12u;
                for (u16 i = 0; i < n; i++)
                    cpu_wr((u16)(dbuf + i), percom[i]);
                status = 0x01u;
            } else if (dcmd == '?') {
                if (dbyt >= 1u)
                    cpu_wr(dbuf, 0x08u);
                status = 0x01u;
            }
        }
    }

    /* Complete SIOV immediately with RTS */
    M->ram[0x0303] = status;
    M->ram[0x0042] = 0; /* CRITIC = 0 */
    S.y = status;
    S.p = (u8)((S.p & ~(FN | FZ)) | ((status & 0x80u) ? FN : 0u));
    u16 ret = (u16)pop8();
    ret |= (u16)pop8() << 8;
    S.pc = (u16)(ret + 1u);
    S.cyc -= 40;
    return 1;
}

static void handle_xex_step(void)
{
    const u8 *b = M->atr_buf;
    u32 sz = S.xex_size;

    while (S.xex_pos + 4u <= sz) {
        u16 start = (u16)b[S.xex_pos] | ((u16)b[S.xex_pos + 1u] << 8);
        S.xex_pos += 2u;
        if (start == 0xFFFFu)
            continue; /* Skip $FFFF binary header(s) */
        if (S.xex_pos + 2u > sz)
            break;
        u16 end = (u16)b[S.xex_pos] | ((u16)b[S.xex_pos + 1u] << 8);
        S.xex_pos += 2u;
        if (end < start)
            break;
        if (S.xex_first_addr == 0xFFFFu && start != 0x02E0u && start != 0x02E2u)
            S.xex_first_addr = start;

        M->ram[0x02E2] = 0xFFu;
        M->ram[0x02E3] = 0xFFu;

        u32 len = (u32)end - (u32)start + 1u;
        for (u32 i = 0; i < len && S.xex_pos < sz; i++)
            cpu_wr((u16)(start + i), b[S.xex_pos++]);

        /* Did this segment write INITAD ($02E2..$02E3)? Execute it live on the 6502! */
        u16 init = (u16)M->ram[0x02E2] | ((u16)M->ram[0x02E3] << 8);
        if (init != 0xFFFFu) {
            M->ram[0x02E2] = 0xFFu;
            M->ram[0x02E3] = 0xFFu;
            /* Push $D1FE so the INITAD routine's RTS lands right back at $D1FF */
            push8(0xD1u);
            push8(0xFEu);
            S.pc = init;
            return;
        }
    }

    /* All segments loaded: launch RUNAD ($02E0..$02E1) */
    S.xex_loading = 0;
    S.auto_option_frames = 0;
    u16 run = (u16)M->ram[0x02E0] | ((u16)M->ram[0x02E1] << 8);
    if (run == 0xFFFFu)
        run = (S.xex_first_addr != 0xFFFFu) ? S.xex_first_addr : 0xE474u;
    push8(0xE4u);
    push8(0x73u); /* WARMSV - 1 */
    S.pc = run;
}

/* ---- SALLY 6502C CPU Core ---- */
INLINE void set_nz(u8 v)
{
    S.p = (u8)((S.p & ~(FN | FZ)) | (v & FN) | (v == 0 ? FZ : 0));
}

INLINE void do_adc(u8 v)
{
    u32 c = S.p & FC;
    if (__builtin_expect((S.p & FD) != 0, 0)) {
        u32 al = (S.a & 0x0Fu) + (v & 0x0Fu) + c;
        if (al > 9u)
            al += 6u;
        u32 ah = (S.a >> 4) + (v >> 4) + (al > 15u ? 1u : 0u);
        u8 z = (u8)(S.a + v + c);
        u8 n = (u8)((ah << 4) | (al & 0x0Fu));
        u8 ov = (u8)((~(S.a ^ v) & (S.a ^ n)) & 0x80u);
        if (ah > 9u)
            ah += 6u;
        S.a = (u8)((ah << 4) | (al & 0x0Fu));
        S.p = (u8)((S.p & ~(FN | FV | FZ | FC)) |
                   (n & FN) | (ov ? FV : 0u) | (z == 0 ? FZ : 0u) | (ah > 15u ? FC : 0u));
    } else {
        u32 sum = (u32)S.a + (u32)v + c;
        u8 res = (u8)sum;
        u8 ov = (u8)((~(S.a ^ v) & (S.a ^ res)) & 0x80u);
        S.a = res;
        S.p = (u8)((S.p & ~(FN | FV | FZ | FC)) |
                   (res & FN) | (ov ? FV : 0u) | (res == 0 ? FZ : 0u) | (sum > 0xFFu ? FC : 0u));
    }
}

INLINE void do_sbc(u8 v)
{
    u32 borrow = (S.p & FC) ? 0u : 1u;
    u32 diff = (u32)S.a - (u32)v - borrow;
    u8 bin = (u8)diff;
    u8 ov = (u8)(((S.a ^ v) & (S.a ^ bin)) & 0x80u);
    if (__builtin_expect((S.p & FD) != 0, 0)) {
        s32 al = (s32)(S.a & 0x0Fu) - (s32)(v & 0x0Fu) - (s32)borrow;
        if (al < 0)
            al = ((al - 6) & 0x0F) - 0x10;
        s32 ah = (s32)(S.a & 0xF0u) - (s32)(v & 0xF0u) + al;
        if (ah < 0)
            ah -= 0x60;
        S.a = (u8)ah;
    } else {
        S.a = bin;
    }
    S.p = (u8)((S.p & ~(FN | FV | FZ | FC)) |
               (bin & FN) | (ov ? FV : 0u) | (bin == 0 ? FZ : 0u) | (diff < 0x100u ? FC : 0u));
}

INLINE void do_cmp(u8 reg, u8 v)
{
    u32 d = (u32)reg - (u32)v;
    u8 r = (u8)d;
    S.p = (u8)((S.p & ~(FN | FZ | FC)) | (r & FN) | (r == 0 ? FZ : 0u) | (d < 0x100u ? FC : 0u));
}

INLINE u8 do_asl(u8 v)
{
    S.p = (u8)((S.p & ~FC) | (v >> 7));
    v <<= 1;
    set_nz(v);
    return v;
}

INLINE u8 do_lsr(u8 v)
{
    S.p = (u8)((S.p & ~FC) | (v & 1u));
    v >>= 1;
    set_nz(v);
    return v;
}

INLINE u8 do_rol(u8 v)
{
    u8 c = (u8)(S.p & FC);
    S.p = (u8)((S.p & ~FC) | (v >> 7));
    v = (u8)((v << 1) | c);
    set_nz(v);
    return v;
}

INLINE u8 do_ror(u8 v)
{
    u8 c = (u8)((S.p & FC) << 7);
    S.p = (u8)((S.p & ~FC) | (v & 1u));
    v = (u8)((v >> 1) | c);
    set_nz(v);
    return v;
}

INLINE u8 pc_rd8(void)
{
    u16 pc = S.pc++;
    if (__builtin_expect((pc & 0xF800u) == S.code_tag, 1))
        return S.code_page[pc & 0x7FFu];
    const u8 *p = S.rd_page[pc >> 11];
    if (__builtin_expect(p != 0, 1)) {
        S.code_page = p;
        S.code_tag = (u16)(pc & 0xF800u);
        return p[pc & 0x7FFu];
    }
    return io_rd(pc);
}

INLINE u16 pc_rd16(void)
{
    u16 pc = S.pc;
    S.pc = (u16)(pc + 2u);
    u32 off = pc & 0x7FFu;
    if (__builtin_expect((pc & 0xF800u) == S.code_tag && off < 0x7FFu, 1))
        return (u16)S.code_page[off] | ((u16)S.code_page[off + 1u] << 8);
    return cpu_rd16(pc);
}

/* Addressing modes */
#define RD_IMM()   (pc_rd8())
#define AD_ZP()    ((u16)pc_rd8())
#define AD_ZPX()   ((u16)((u8)(pc_rd8() + S.x)))
#define AD_ZPY()   ((u16)((u8)(pc_rd8() + S.y)))
#define AD_ABS()   (pc_rd16())
#define AD_ABX_R() ({ u16 _b = pc_rd16(); u16 _a = (u16)(_b + S.x); if ((_a ^ _b) & 0xFF00u) S.cyc--; _a; })
#define AD_ABY_R() ({ u16 _b = pc_rd16(); u16 _a = (u16)(_b + S.y); if ((_a ^ _b) & 0xFF00u) S.cyc--; _a; })
#define AD_ABX_W() ({ u16 _b = pc_rd16(); (u16)(_b + S.x); })
#define AD_ABY_W() ({ u16 _b = pc_rd16(); (u16)(_b + S.y); })
#define AD_INX()   ({ u8 _zp = (u8)(pc_rd8() + S.x); (u16)M->ram[_zp] | ((u16)M->ram[(u8)(_zp + 1u)] << 8); })
#define AD_INY_R() ({ u8 _zp = pc_rd8(); u16 _b = (u16)M->ram[_zp] | ((u16)M->ram[(u8)(_zp + 1u)] << 8); u16 _a = (u16)(_b + S.y); if ((_a ^ _b) & 0xFF00u) S.cyc--; _a; })
#define AD_INY_W() ({ u8 _zp = pc_rd8(); u16 _b = (u16)M->ram[_zp] | ((u16)M->ram[(u8)(_zp + 1u)] << 8); (u16)(_b + S.y); })

#define BRANCH(cond) do { \
    s8 _rel = (s8)pc_rd8(); \
    if (cond) { \
        u16 _old = S.pc; \
        S.pc = (u16)(S.pc + _rel); \
        S.cyc -= ((_old ^ S.pc) & 0xFF00u) ? 2 : 1; \
    } \
} while (0)

static void cpu_run(s32 budget)
{
    S.cyc += budget;
    if (S.wsync) {
        if (S.cyc > 0)
            S.cyc = 0;
        return;
    }

    while (S.cyc > 0 && !S.jammed) {
        if (__builtin_expect(S.nmi_pend != 0, 0)) {
            S.nmi_pend = 0;
            push8((u8)(S.pc >> 8));
            push8((u8)S.pc);
            push8((u8)((S.p & ~FB) | FU));
            S.p |= FI;
            S.pc = cpu_rd16(0xFFFAu);
            S.cyc -= 7;
            if (S.cyc <= 0)
                break;
        } else if (__builtin_expect(S.irq_pend && !(S.p & FI), 0)) {
            push8((u8)(S.pc >> 8));
            push8((u8)S.pc);
            push8((u8)((S.p & ~FB) | FU));
            S.p |= FI;
            S.pc = cpu_rd16(0xFFFEu);
            S.cyc -= 7;
            if (S.cyc <= 0)
                break;
        }

        /* High-speed OS SIOV ($E459) & .xex binary segment loader ($D1FF) hooks */
        if (__builtin_expect(!S.is_5200 && (S.pc == 0xE459u || S.pc == 0xD1FFu), 0)) {
            if (S.pc == 0xD1FFu && S.xex_loading) {
                handle_xex_step();
                continue;
            }
            if (S.pc == 0xE459u && (S.eff_portb & 0x01u) && S.sio_rx_len == 0) {
                if (handle_siov_hook())
                    continue;
            }
        }

        u8 op = pc_rd8();
        u16 ad;
        u8 v;

        switch (op) {
        /* LDA */
        case 0xA9: S.a = RD_IMM(); set_nz(S.a); S.cyc -= 2; break;
        case 0xA5: S.a = M->ram[AD_ZP()]; set_nz(S.a); S.cyc -= 3; break;
        case 0xB5: S.a = M->ram[AD_ZPX()]; set_nz(S.a); S.cyc -= 4; break;
        case 0xAD: S.a = cpu_rd(AD_ABS()); set_nz(S.a); S.cyc -= 4; break;
        case 0xBD: S.a = cpu_rd(AD_ABX_R()); set_nz(S.a); S.cyc -= 4; break;
        case 0xB9: S.a = cpu_rd(AD_ABY_R()); set_nz(S.a); S.cyc -= 4; break;
        case 0xA1: S.a = cpu_rd(AD_INX()); set_nz(S.a); S.cyc -= 6; break;
        case 0xB1: S.a = cpu_rd(AD_INY_R()); set_nz(S.a); S.cyc -= 5; break;

        /* LDX */
        case 0xA2: S.x = RD_IMM(); set_nz(S.x); S.cyc -= 2; break;
        case 0xA6: S.x = M->ram[AD_ZP()]; set_nz(S.x); S.cyc -= 3; break;
        case 0xB6: S.x = M->ram[AD_ZPY()]; set_nz(S.x); S.cyc -= 4; break;
        case 0xAE: S.x = cpu_rd(AD_ABS()); set_nz(S.x); S.cyc -= 4; break;
        case 0xBE: S.x = cpu_rd(AD_ABY_R()); set_nz(S.x); S.cyc -= 4; break;

        /* LDY */
        case 0xA0: S.y = RD_IMM(); set_nz(S.y); S.cyc -= 2; break;
        case 0xA4: S.y = M->ram[AD_ZP()]; set_nz(S.y); S.cyc -= 3; break;
        case 0xB4: S.y = M->ram[AD_ZPX()]; set_nz(S.y); S.cyc -= 4; break;
        case 0xAC: S.y = cpu_rd(AD_ABS()); set_nz(S.y); S.cyc -= 4; break;
        case 0xBC: S.y = cpu_rd(AD_ABX_R()); set_nz(S.y); S.cyc -= 4; break;

        /* STA */
        case 0x85: M->ram[AD_ZP()] = S.a; S.cyc -= 3; break;
        case 0x95: M->ram[AD_ZPX()] = S.a; S.cyc -= 4; break;
        case 0x8D: cpu_wr(AD_ABS(), S.a); S.cyc -= 4; break;
        case 0x9D: cpu_wr(AD_ABX_W(), S.a); S.cyc -= 5; break;
        case 0x99: cpu_wr(AD_ABY_W(), S.a); S.cyc -= 5; break;
        case 0x81: cpu_wr(AD_INX(), S.a); S.cyc -= 6; break;
        case 0x91: cpu_wr(AD_INY_W(), S.a); S.cyc -= 6; break;

        /* STX */
        case 0x86: M->ram[AD_ZP()] = S.x; S.cyc -= 3; break;
        case 0x96: M->ram[AD_ZPY()] = S.x; S.cyc -= 4; break;
        case 0x8E: cpu_wr(AD_ABS(), S.x); S.cyc -= 4; break;

        /* STY */
        case 0x84: M->ram[AD_ZP()] = S.y; S.cyc -= 3; break;
        case 0x94: M->ram[AD_ZPX()] = S.y; S.cyc -= 4; break;
        case 0x8C: cpu_wr(AD_ABS(), S.y); S.cyc -= 4; break;

        /* Transfers */
        case 0xAA: S.x = S.a; set_nz(S.x); S.cyc -= 2; break;
        case 0xA8: S.y = S.a; set_nz(S.y); S.cyc -= 2; break;
        case 0x8A: S.a = S.x; set_nz(S.a); S.cyc -= 2; break;
        case 0x98: S.a = S.y; set_nz(S.a); S.cyc -= 2; break;
        case 0xBA: S.x = S.sp; set_nz(S.x); S.cyc -= 2; break;
        case 0x9A: S.sp = S.x; S.cyc -= 2; break;

        /* Stack */
        case 0x48: push8(S.a); S.cyc -= 3; break;
        case 0x68: S.a = pop8(); set_nz(S.a); S.cyc -= 4; break;
        case 0x08: push8((u8)(S.p | FB | FU)); S.cyc -= 3; break;
        case 0x28: S.p = (u8)((pop8() & ~FB) | FU); S.cyc -= 4; break;

        /* Logical */
        case 0x29: S.a &= RD_IMM(); set_nz(S.a); S.cyc -= 2; break;
        case 0x25: S.a &= M->ram[AD_ZP()]; set_nz(S.a); S.cyc -= 3; break;
        case 0x35: S.a &= M->ram[AD_ZPX()]; set_nz(S.a); S.cyc -= 4; break;
        case 0x2D: S.a &= cpu_rd(AD_ABS()); set_nz(S.a); S.cyc -= 4; break;
        case 0x3D: S.a &= cpu_rd(AD_ABX_R()); set_nz(S.a); S.cyc -= 4; break;
        case 0x39: S.a &= cpu_rd(AD_ABY_R()); set_nz(S.a); S.cyc -= 4; break;
        case 0x21: S.a &= cpu_rd(AD_INX()); set_nz(S.a); S.cyc -= 6; break;
        case 0x31: S.a &= cpu_rd(AD_INY_R()); set_nz(S.a); S.cyc -= 5; break;

        case 0x09: S.a |= RD_IMM(); set_nz(S.a); S.cyc -= 2; break;
        case 0x05: S.a |= M->ram[AD_ZP()]; set_nz(S.a); S.cyc -= 3; break;
        case 0x15: S.a |= M->ram[AD_ZPX()]; set_nz(S.a); S.cyc -= 4; break;
        case 0x0D: S.a |= cpu_rd(AD_ABS()); set_nz(S.a); S.cyc -= 4; break;
        case 0x1D: S.a |= cpu_rd(AD_ABX_R()); set_nz(S.a); S.cyc -= 4; break;
        case 0x19: S.a |= cpu_rd(AD_ABY_R()); set_nz(S.a); S.cyc -= 4; break;
        case 0x01: S.a |= cpu_rd(AD_INX()); set_nz(S.a); S.cyc -= 6; break;
        case 0x11: S.a |= cpu_rd(AD_INY_R()); set_nz(S.a); S.cyc -= 5; break;

        case 0x49: S.a ^= RD_IMM(); set_nz(S.a); S.cyc -= 2; break;
        case 0x45: S.a ^= M->ram[AD_ZP()]; set_nz(S.a); S.cyc -= 3; break;
        case 0x55: S.a ^= M->ram[AD_ZPX()]; set_nz(S.a); S.cyc -= 4; break;
        case 0x4D: S.a ^= cpu_rd(AD_ABS()); set_nz(S.a); S.cyc -= 4; break;
        case 0x5D: S.a ^= cpu_rd(AD_ABX_R()); set_nz(S.a); S.cyc -= 4; break;
        case 0x59: S.a ^= cpu_rd(AD_ABY_R()); set_nz(S.a); S.cyc -= 4; break;
        case 0x41: S.a ^= cpu_rd(AD_INX()); set_nz(S.a); S.cyc -= 6; break;
        case 0x51: S.a ^= cpu_rd(AD_INY_R()); set_nz(S.a); S.cyc -= 5; break;

        case 0x24: v = M->ram[AD_ZP()]; S.p = (u8)((S.p & ~(FN | FV | FZ)) | (v & (FN | FV)) | ((S.a & v) ? 0 : FZ)); S.cyc -= 3; break;
        case 0x2C: v = cpu_rd(AD_ABS()); S.p = (u8)((S.p & ~(FN | FV | FZ)) | (v & (FN | FV)) | ((S.a & v) ? 0 : FZ)); S.cyc -= 4; break;

        /* ADC / SBC */
        case 0x69: do_adc(RD_IMM()); S.cyc -= 2; break;
        case 0x65: do_adc(M->ram[AD_ZP()]); S.cyc -= 3; break;
        case 0x75: do_adc(M->ram[AD_ZPX()]); S.cyc -= 4; break;
        case 0x6D: do_adc(cpu_rd(AD_ABS())); S.cyc -= 4; break;
        case 0x7D: do_adc(cpu_rd(AD_ABX_R())); S.cyc -= 4; break;
        case 0x79: do_adc(cpu_rd(AD_ABY_R())); S.cyc -= 4; break;
        case 0x61: do_adc(cpu_rd(AD_INX())); S.cyc -= 6; break;
        case 0x71: do_adc(cpu_rd(AD_INY_R())); S.cyc -= 5; break;

        case 0xE9: case 0xEB: do_sbc(RD_IMM()); S.cyc -= 2; break;
        case 0xE5: do_sbc(M->ram[AD_ZP()]); S.cyc -= 3; break;
        case 0xF5: do_sbc(M->ram[AD_ZPX()]); S.cyc -= 4; break;
        case 0xED: do_sbc(cpu_rd(AD_ABS())); S.cyc -= 4; break;
        case 0xFD: do_sbc(cpu_rd(AD_ABX_R())); S.cyc -= 4; break;
        case 0xF9: do_sbc(cpu_rd(AD_ABY_R())); S.cyc -= 4; break;
        case 0xE1: do_sbc(cpu_rd(AD_INX())); S.cyc -= 6; break;
        case 0xF1: do_sbc(cpu_rd(AD_INY_R())); S.cyc -= 5; break;

        /* CMP / CPX / CPY */
        case 0xC9: do_cmp(S.a, RD_IMM()); S.cyc -= 2; break;
        case 0xC5: do_cmp(S.a, M->ram[AD_ZP()]); S.cyc -= 3; break;
        case 0xD5: do_cmp(S.a, M->ram[AD_ZPX()]); S.cyc -= 4; break;
        case 0xCD: do_cmp(S.a, cpu_rd(AD_ABS())); S.cyc -= 4; break;
        case 0xDD: do_cmp(S.a, cpu_rd(AD_ABX_R())); S.cyc -= 4; break;
        case 0xD9: do_cmp(S.a, cpu_rd(AD_ABY_R())); S.cyc -= 4; break;
        case 0xC1: do_cmp(S.a, cpu_rd(AD_INX())); S.cyc -= 6; break;
        case 0xD1: do_cmp(S.a, cpu_rd(AD_INY_R())); S.cyc -= 5; break;

        case 0xE0: do_cmp(S.x, RD_IMM()); S.cyc -= 2; break;
        case 0xE4: do_cmp(S.x, M->ram[AD_ZP()]); S.cyc -= 3; break;
        case 0xEC: do_cmp(S.x, cpu_rd(AD_ABS())); S.cyc -= 4; break;

        case 0xC0: do_cmp(S.y, RD_IMM()); S.cyc -= 2; break;
        case 0xC4: do_cmp(S.y, M->ram[AD_ZP()]); S.cyc -= 3; break;
        case 0xCC: do_cmp(S.y, cpu_rd(AD_ABS())); S.cyc -= 4; break;

        /* INC / DEC / INX / DEX / INY / DEY */
        case 0xE6: ad = AD_ZP(); v = (u8)(M->ram[ad] + 1u); M->ram[ad] = v; set_nz(v); S.cyc -= 5; break;
        case 0xF6: ad = AD_ZPX(); v = (u8)(M->ram[ad] + 1u); M->ram[ad] = v; set_nz(v); S.cyc -= 6; break;
        case 0xEE: ad = AD_ABS(); v = (u8)(cpu_rd(ad) + 1u); cpu_wr(ad, v); set_nz(v); S.cyc -= 6; break;
        case 0xFE: ad = AD_ABX_W(); v = (u8)(cpu_rd(ad) + 1u); cpu_wr(ad, v); set_nz(v); S.cyc -= 7; break;

        case 0xC6: ad = AD_ZP(); v = (u8)(M->ram[ad] - 1u); M->ram[ad] = v; set_nz(v); S.cyc -= 5; break;
        case 0xD6: ad = AD_ZPX(); v = (u8)(M->ram[ad] - 1u); M->ram[ad] = v; set_nz(v); S.cyc -= 6; break;
        case 0xCE: ad = AD_ABS(); v = (u8)(cpu_rd(ad) - 1u); cpu_wr(ad, v); set_nz(v); S.cyc -= 6; break;
        case 0xDE: ad = AD_ABX_W(); v = (u8)(cpu_rd(ad) - 1u); cpu_wr(ad, v); set_nz(v); S.cyc -= 7; break;

        case 0xE8: S.x++; set_nz(S.x); S.cyc -= 2; break;
        case 0xCA: S.x--; set_nz(S.x); S.cyc -= 2; break;
        case 0xC8: S.y++; set_nz(S.y); S.cyc -= 2; break;
        case 0x88: S.y--; set_nz(S.y); S.cyc -= 2; break;

        /* Shifts & Rotates */
        case 0x0A: S.a = do_asl(S.a); S.cyc -= 2; break;
        case 0x06: ad = AD_ZP(); M->ram[ad] = do_asl(M->ram[ad]); S.cyc -= 5; break;
        case 0x16: ad = AD_ZPX(); M->ram[ad] = do_asl(M->ram[ad]); S.cyc -= 6; break;
        case 0x0E: ad = AD_ABS(); cpu_wr(ad, do_asl(cpu_rd(ad))); S.cyc -= 6; break;
        case 0x1E: ad = AD_ABX_W(); cpu_wr(ad, do_asl(cpu_rd(ad))); S.cyc -= 7; break;

        case 0x4A: S.a = do_lsr(S.a); S.cyc -= 2; break;
        case 0x46: ad = AD_ZP(); M->ram[ad] = do_lsr(M->ram[ad]); S.cyc -= 5; break;
        case 0x56: ad = AD_ZPX(); M->ram[ad] = do_lsr(M->ram[ad]); S.cyc -= 6; break;
        case 0x4E: ad = AD_ABS(); cpu_wr(ad, do_lsr(cpu_rd(ad))); S.cyc -= 6; break;
        case 0x5E: ad = AD_ABX_W(); cpu_wr(ad, do_lsr(cpu_rd(ad))); S.cyc -= 7; break;

        case 0x2A: S.a = do_rol(S.a); S.cyc -= 2; break;
        case 0x26: ad = AD_ZP(); M->ram[ad] = do_rol(M->ram[ad]); S.cyc -= 5; break;
        case 0x36: ad = AD_ZPX(); M->ram[ad] = do_rol(M->ram[ad]); S.cyc -= 6; break;
        case 0x2E: ad = AD_ABS(); cpu_wr(ad, do_rol(cpu_rd(ad))); S.cyc -= 6; break;
        case 0x3E: ad = AD_ABX_W(); cpu_wr(ad, do_rol(cpu_rd(ad))); S.cyc -= 7; break;

        case 0x6A: S.a = do_ror(S.a); S.cyc -= 2; break;
        case 0x66: ad = AD_ZP(); M->ram[ad] = do_ror(M->ram[ad]); S.cyc -= 5; break;
        case 0x76: ad = AD_ZPX(); M->ram[ad] = do_ror(M->ram[ad]); S.cyc -= 6; break;
        case 0x6E: ad = AD_ABS(); cpu_wr(ad, do_ror(cpu_rd(ad))); S.cyc -= 6; break;
        case 0x7E: ad = AD_ABX_W(); cpu_wr(ad, do_ror(cpu_rd(ad))); S.cyc -= 7; break;

        /* Branches */
        case 0x10: BRANCH(!(S.p & FN)); S.cyc -= 2; break;
        case 0x30: BRANCH( (S.p & FN)); S.cyc -= 2; break;
        case 0x50: BRANCH(!(S.p & FV)); S.cyc -= 2; break;
        case 0x70: BRANCH( (S.p & FV)); S.cyc -= 2; break;
        case 0x90: BRANCH(!(S.p & FC)); S.cyc -= 2; break;
        case 0xB0: BRANCH( (S.p & FC)); S.cyc -= 2; break;
        case 0xD0: BRANCH(!(S.p & FZ)); S.cyc -= 2; break;
        case 0xF0: BRANCH( (S.p & FZ)); S.cyc -= 2; break;

        /* Jumps & Calls */
        case 0x4C: S.pc = cpu_rd16(S.pc); S.cyc -= 3; break;
        case 0x6C: {
            u16 ptr = cpu_rd16(S.pc);
            u16 hi = (u16)((ptr & 0xFF00u) | ((ptr + 1u) & 0x00FFu)); /* NMOS page-wrap bug */
            S.pc = (u16)cpu_rd(ptr) | ((u16)cpu_rd(hi) << 8);
            S.cyc -= 5;
            break;
        }
        case 0x20: {
            u16 dst = cpu_rd16(S.pc);
            u16 ret = (u16)(S.pc + 1u);
            push8((u8)(ret >> 8));
            push8((u8)ret);
            S.pc = dst;
            S.cyc -= 6;
            break;
        }
        case 0x60: {
            u16 ret = (u16)pop8();
            ret |= (u16)pop8() << 8;
            S.pc = (u16)(ret + 1u);
            S.cyc -= 6;
            break;
        }
        case 0x40: {
            S.p = (u8)((pop8() & ~FB) | FU);
            u16 ret = (u16)pop8();
            ret |= (u16)pop8() << 8;
            S.pc = ret;
            S.cyc -= 6;
            break;
        }
        case 0x00: { /* BRK */
            S.pc++;
            push8((u8)(S.pc >> 8));
            push8((u8)S.pc);
            push8((u8)(S.p | FB | FU));
            S.p |= FI;
            S.pc = cpu_rd16(0xFFFEu);
            S.cyc -= 7;
            break;
        }

        /* Flag ops */
        case 0x18: S.p &= (u8)~FC; S.cyc -= 2; break;
        case 0x38: S.p |= FC;      S.cyc -= 2; break;
        case 0x58: S.p &= (u8)~FI; S.cyc -= 2; break;
        case 0x78: S.p |= FI;      S.cyc -= 2; break;
        case 0xB8: S.p &= (u8)~FV; S.cyc -= 2; break;
        case 0xD8: S.p &= (u8)~FD; S.cyc -= 2; break;
        case 0xF8: S.p |= FD;      S.cyc -= 2; break;

        /* Common Atari SALLY undocumented opcodes */
        /* LAX */
        case 0xA7: S.a = S.x = M->ram[AD_ZP()]; set_nz(S.a); S.cyc -= 3; break;
        case 0xB7: S.a = S.x = M->ram[AD_ZPY()]; set_nz(S.a); S.cyc -= 4; break;
        case 0xAF: S.a = S.x = cpu_rd(AD_ABS()); set_nz(S.a); S.cyc -= 4; break;
        case 0xBF: S.a = S.x = cpu_rd(AD_ABY_R()); set_nz(S.a); S.cyc -= 4; break;
        case 0xA3: S.a = S.x = cpu_rd(AD_INX()); set_nz(S.a); S.cyc -= 6; break;
        case 0xB3: S.a = S.x = cpu_rd(AD_INY_R()); set_nz(S.a); S.cyc -= 5; break;
        case 0xAB: S.a = S.x = (u8)((S.a | 0xEEu) & RD_IMM()); set_nz(S.a); S.cyc -= 2; break;

        /* SAX */
        case 0x87: M->ram[AD_ZP()] = (u8)(S.a & S.x); S.cyc -= 3; break;
        case 0x97: M->ram[AD_ZPY()] = (u8)(S.a & S.x); S.cyc -= 4; break;
        case 0x8F: cpu_wr(AD_ABS(), (u8)(S.a & S.x)); S.cyc -= 4; break;
        case 0x83: cpu_wr(AD_INX(), (u8)(S.a & S.x)); S.cyc -= 6; break;

        /* DCP (DEC + CMP) */
        case 0xC7: ad = AD_ZP(); v = (u8)(M->ram[ad] - 1u); M->ram[ad] = v; do_cmp(S.a, v); S.cyc -= 5; break;
        case 0xD7: ad = AD_ZPX(); v = (u8)(M->ram[ad] - 1u); M->ram[ad] = v; do_cmp(S.a, v); S.cyc -= 6; break;
        case 0xCF: ad = AD_ABS(); v = (u8)(cpu_rd(ad) - 1u); cpu_wr(ad, v); do_cmp(S.a, v); S.cyc -= 6; break;
        case 0xDF: ad = AD_ABX_W(); v = (u8)(cpu_rd(ad) - 1u); cpu_wr(ad, v); do_cmp(S.a, v); S.cyc -= 7; break;
        case 0xDB: ad = AD_ABY_W(); v = (u8)(cpu_rd(ad) - 1u); cpu_wr(ad, v); do_cmp(S.a, v); S.cyc -= 7; break;
        case 0xC3: ad = AD_INX(); v = (u8)(cpu_rd(ad) - 1u); cpu_wr(ad, v); do_cmp(S.a, v); S.cyc -= 8; break;
        case 0xD3: ad = AD_INY_W(); v = (u8)(cpu_rd(ad) - 1u); cpu_wr(ad, v); do_cmp(S.a, v); S.cyc -= 8; break;

        /* ISC / ISB (INC + SBC) */
        case 0xE7: ad = AD_ZP(); v = (u8)(M->ram[ad] + 1u); M->ram[ad] = v; do_sbc(v); S.cyc -= 5; break;
        case 0xF7: ad = AD_ZPX(); v = (u8)(M->ram[ad] + 1u); M->ram[ad] = v; do_sbc(v); S.cyc -= 6; break;
        case 0xEF: ad = AD_ABS(); v = (u8)(cpu_rd(ad) + 1u); cpu_wr(ad, v); do_sbc(v); S.cyc -= 6; break;
        case 0xFF: ad = AD_ABX_W(); v = (u8)(cpu_rd(ad) + 1u); cpu_wr(ad, v); do_sbc(v); S.cyc -= 7; break;
        case 0xFB: ad = AD_ABY_W(); v = (u8)(cpu_rd(ad) + 1u); cpu_wr(ad, v); do_sbc(v); S.cyc -= 7; break;
        case 0xE3: ad = AD_INX(); v = (u8)(cpu_rd(ad) + 1u); cpu_wr(ad, v); do_sbc(v); S.cyc -= 8; break;
        case 0xF3: ad = AD_INY_W(); v = (u8)(cpu_rd(ad) + 1u); cpu_wr(ad, v); do_sbc(v); S.cyc -= 8; break;

        /* SLO (ASL + ORA) */
        case 0x07: ad = AD_ZP(); v = do_asl(M->ram[ad]); M->ram[ad] = v; S.a |= v; set_nz(S.a); S.cyc -= 5; break;
        case 0x17: ad = AD_ZPX(); v = do_asl(M->ram[ad]); M->ram[ad] = v; S.a |= v; set_nz(S.a); S.cyc -= 6; break;
        case 0x0F: ad = AD_ABS(); v = do_asl(cpu_rd(ad)); cpu_wr(ad, v); S.a |= v; set_nz(S.a); S.cyc -= 6; break;
        case 0x1F: ad = AD_ABX_W(); v = do_asl(cpu_rd(ad)); cpu_wr(ad, v); S.a |= v; set_nz(S.a); S.cyc -= 7; break;
        case 0x1B: ad = AD_ABY_W(); v = do_asl(cpu_rd(ad)); cpu_wr(ad, v); S.a |= v; set_nz(S.a); S.cyc -= 7; break;
        case 0x03: ad = AD_INX(); v = do_asl(cpu_rd(ad)); cpu_wr(ad, v); S.a |= v; set_nz(S.a); S.cyc -= 8; break;
        case 0x13: ad = AD_INY_W(); v = do_asl(cpu_rd(ad)); cpu_wr(ad, v); S.a |= v; set_nz(S.a); S.cyc -= 8; break;

        /* RLA (ROL + AND) */
        case 0x27: ad = AD_ZP(); v = do_rol(M->ram[ad]); M->ram[ad] = v; S.a &= v; set_nz(S.a); S.cyc -= 5; break;
        case 0x37: ad = AD_ZPX(); v = do_rol(M->ram[ad]); M->ram[ad] = v; S.a &= v; set_nz(S.a); S.cyc -= 6; break;
        case 0x2F: ad = AD_ABS(); v = do_rol(cpu_rd(ad)); cpu_wr(ad, v); S.a &= v; set_nz(S.a); S.cyc -= 6; break;
        case 0x3F: ad = AD_ABX_W(); v = do_rol(cpu_rd(ad)); cpu_wr(ad, v); S.a &= v; set_nz(S.a); S.cyc -= 7; break;
        case 0x3B: ad = AD_ABY_W(); v = do_rol(cpu_rd(ad)); cpu_wr(ad, v); S.a &= v; set_nz(S.a); S.cyc -= 7; break;
        case 0x23: ad = AD_INX(); v = do_rol(cpu_rd(ad)); cpu_wr(ad, v); S.a &= v; set_nz(S.a); S.cyc -= 8; break;
        case 0x33: ad = AD_INY_W(); v = do_rol(cpu_rd(ad)); cpu_wr(ad, v); S.a &= v; set_nz(S.a); S.cyc -= 8; break;

        /* SRE (LSR + EOR) */
        case 0x47: ad = AD_ZP(); v = do_lsr(M->ram[ad]); M->ram[ad] = v; S.a ^= v; set_nz(S.a); S.cyc -= 5; break;
        case 0x57: ad = AD_ZPX(); v = do_lsr(M->ram[ad]); M->ram[ad] = v; S.a ^= v; set_nz(S.a); S.cyc -= 6; break;
        case 0x4F: ad = AD_ABS(); v = do_lsr(cpu_rd(ad)); cpu_wr(ad, v); S.a ^= v; set_nz(S.a); S.cyc -= 6; break;
        case 0x5F: ad = AD_ABX_W(); v = do_lsr(cpu_rd(ad)); cpu_wr(ad, v); S.a ^= v; set_nz(S.a); S.cyc -= 7; break;
        case 0x5B: ad = AD_ABY_W(); v = do_lsr(cpu_rd(ad)); cpu_wr(ad, v); S.a ^= v; set_nz(S.a); S.cyc -= 7; break;
        case 0x43: ad = AD_INX(); v = do_lsr(cpu_rd(ad)); cpu_wr(ad, v); S.a ^= v; set_nz(S.a); S.cyc -= 8; break;
        case 0x53: ad = AD_INY_W(); v = do_lsr(cpu_rd(ad)); cpu_wr(ad, v); S.a ^= v; set_nz(S.a); S.cyc -= 8; break;

        /* RRA (ROR + ADC) */
        case 0x67: ad = AD_ZP(); v = do_ror(M->ram[ad]); M->ram[ad] = v; do_adc(v); S.cyc -= 5; break;
        case 0x77: ad = AD_ZPX(); v = do_ror(M->ram[ad]); M->ram[ad] = v; do_adc(v); S.cyc -= 6; break;
        case 0x6F: ad = AD_ABS(); v = do_ror(cpu_rd(ad)); cpu_wr(ad, v); do_adc(v); S.cyc -= 6; break;
        case 0x7F: ad = AD_ABX_W(); v = do_ror(cpu_rd(ad)); cpu_wr(ad, v); do_adc(v); S.cyc -= 7; break;
        case 0x7B: ad = AD_ABY_W(); v = do_ror(cpu_rd(ad)); cpu_wr(ad, v); do_adc(v); S.cyc -= 7; break;
        case 0x63: ad = AD_INX(); v = do_ror(cpu_rd(ad)); cpu_wr(ad, v); do_adc(v); S.cyc -= 8; break;
        case 0x73: ad = AD_INY_W(); v = do_ror(cpu_rd(ad)); cpu_wr(ad, v); do_adc(v); S.cyc -= 8; break;

        /* ANC / ALR / ARR / AXS(SBX) / LAS */
        case 0x0B: case 0x2B:
            S.a &= RD_IMM();
            set_nz(S.a);
            S.p = (u8)((S.p & ~FC) | (S.a >> 7));
            S.cyc -= 2;
            break;
        case 0x4B:
            S.a &= RD_IMM();
            S.a = do_lsr(S.a);
            S.cyc -= 2;
            break;
        case 0x6B:
            S.a &= RD_IMM();
            S.a = do_ror(S.a);
            S.p = (u8)((S.p & ~(FC | FV)) | ((S.a >> 6) & FC) | ((((S.a >> 6) ^ (S.a >> 5)) & 1u) ? FV : 0u));
            S.cyc -= 2;
            break;
        case 0xCB: {
            u8 imm = RD_IMM();
            u32 d = (u32)(S.a & S.x) - (u32)imm;
            S.x = (u8)d;
            S.p = (u8)((S.p & ~(FN | FZ | FC)) | (S.x & FN) | (S.x == 0 ? FZ : 0u) | (d < 0x100u ? FC : 0u));
            S.cyc -= 2;
            break;
        }
        case 0xBB:
            v = (u8)(cpu_rd(AD_ABY_R()) & S.sp);
            S.a = S.x = S.sp = v;
            set_nz(v);
            S.cyc -= 4;
            break;
        case 0x8B:
            S.a = (u8)((S.a | 0xEEu) & S.x & RD_IMM());
            set_nz(S.a);
            S.cyc -= 2;
            break;
        case 0x9C: /* SHY abs,X */
            ad = AD_ABX_W();
            cpu_wr(ad, (u8)(S.y & ((ad >> 8) + 1u)));
            S.cyc -= 5;
            break;
        case 0x9E: /* SHX abs,Y */
            ad = AD_ABY_W();
            cpu_wr(ad, (u8)(S.x & ((ad >> 8) + 1u)));
            S.cyc -= 5;
            break;
        case 0x9F: /* SHA abs,Y */
            ad = AD_ABY_W();
            cpu_wr(ad, (u8)(S.a & S.x & ((ad >> 8) + 1u)));
            S.cyc -= 5;
            break;
        case 0x93: /* SHA (zp),Y */
            ad = AD_INY_W();
            cpu_wr(ad, (u8)(S.a & S.x & ((ad >> 8) + 1u)));
            S.cyc -= 6;
            break;
        case 0x9B: /* TAS abs,Y */
            ad = AD_ABY_W();
            S.sp = (u8)(S.a & S.x);
            cpu_wr(ad, (u8)(S.sp & ((ad >> 8) + 1u)));
            S.cyc -= 5;
            break;

        /* Standard & undocumented NOPs */
        case 0xEA: case 0x1A: case 0x3A: case 0x5A: case 0x7A: case 0xDA: case 0xFA:
            S.cyc -= 2; break;
        case 0x80: case 0x82: case 0x89: case 0xC2: case 0xE2:
            S.pc++; S.cyc -= 2; break;
        case 0x04: case 0x44: case 0x64:
            S.pc++; S.cyc -= 3; break;
        case 0x14: case 0x34: case 0x54: case 0x74: case 0xD4: case 0xF4:
            S.pc++; S.cyc -= 4; break;
        case 0x0C:
            S.pc += 2u; S.cyc -= 4; break;
        case 0x1C: case 0x3C: case 0x5C: case 0x7C: case 0xDC: case 0xFC:
            (void)AD_ABX_R(); S.cyc -= 4; break;

        /* KIL / JAM */
        default:
            S.pc--;
            S.jammed = 1;
            S.cyc = 0;
            break;
        }

        if (S.wsync)
            break;
    }
}

/* ---- ANTIC Display List & Scanline Renderer ---- */
static const u8 mode_heights[16] = {
    1, 1, 8, 10, 8, 16, 8, 16, 8, 4, 4, 2, 1, 2, 1, 1
};
/* Bytes per row for [width_mode 0..3][mode 0..15] */
static const u8 mode_bytes[4][16] = {
    { 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0 },
    { 0, 0, 32, 32, 32, 32, 16, 16,  8,  8, 16, 16, 16, 32, 32, 32 },
    { 0, 0, 40, 40, 40, 40, 20, 20, 10, 10, 20, 20, 20, 40, 40, 40 },
    { 0, 0, 48, 48, 48, 48, 24, 24, 12, 12, 24, 24, 24, 48, 48, 48 }
};

INLINE u16 dl_fetch8_inc(void)
{
    u8 b = antic_rd(S.dlist);
    S.dlist = (u16)((S.dlist & 0xFC00u) | ((S.dlist + 1u) & 0x03FFu));
    return b;
}

static int antic_begin_line(int y)
{
    S.dl_dli_today = 0;
    int dma = 9; /* DRAM refresh cycles */

    /* Player / Missile DMA ($D400 bits 2..3) */
    if ((S.dmactl & 0x0Cu) && y >= VIS_START && y < VIS_END) {
        int single = (S.dmactl & 0x10u) != 0;
        u16 base = single ? (u16)((S.pmbase & 0xF8u) << 8) : (u16)((S.pmbase & 0xFCu) << 8);
        u16 idx = single ? (u16)(y & 0xFFu) : (u16)((y >> 1) & 0x7Fu);
        if ((S.dmactl & 0x04u) && (S.gractl & 0x01u)) {
            u8 m = antic_rd((u16)(base + (single ? 0x300u : 0x180u) + idx));
            if (single || !(y & 1)) {
                S.grafm = m;
            } else {
                /* VDELAY bits 0..3 hold odd scanline reload of M0..M3 */
                u8 keep = 0;
                if (S.vdelay & 0x01u) keep |= 0x03u;
                if (S.vdelay & 0x02u) keep |= 0x0Cu;
                if (S.vdelay & 0x04u) keep |= 0x30u;
                if (S.vdelay & 0x08u) keep |= 0xC0u;
                S.grafm = (u8)((S.grafm & keep) | (m & ~keep));
            }
            dma += 1;
        }
        if ((S.dmactl & 0x08u) && (S.gractl & 0x02u)) {
            for (int p = 0; p < 4; p++) {
                u8 g = antic_rd((u16)(base + (single ? (0x400u + (u16)p * 0x100u) : (0x200u + (u16)p * 0x80u)) + idx));
                if (single || !(y & 1) || !(S.vdelay & (0x10u << p)))
                    S.grafp[p] = g;
            }
            dma += 4;
        }
    }

    if (y < VIS_START || y >= VIS_END) {
        if (y == 0) {
            S.dl_wait_vb = 0;
            S.dl_active_row = 0;
            S.dl_in_vscrol = 0;
        }
        if (y == VIS_END) {
            /* Vertical Blank NMI on scanline 248 (sets bit 6, clears bit 7 on real ANTIC) */
            S.nmist = (u8)((S.nmist & 0x1Fu) | 0x40u);
            if (S.nmien & 0x40u)
                S.nmi_pend = 1;
        }
        return dma;
    }

    if (!(S.dmactl & 0x20u) || S.dl_wait_vb) {
        S.dl_active_row = 0;
        return dma;
    }

    /* Advance or fetch Display List instruction */
    int first_row_line = 0;
    if (!S.dl_active_row) {
        first_row_line = 1;
        for (int jmp_guard = 0; jmp_guard < 4; jmp_guard++) {
            u8 ir = (u8)dl_fetch8_inc();
            dma += 1;
            u8 mode = (u8)(ir & 0x0Fu);
            if (mode == 0x01u) {
                u16 lo = dl_fetch8_inc();
                u16 hi = dl_fetch8_inc();
                dma += 2;
                S.dlist = (u16)(lo | (hi << 8));
                if (ir & 0x40u) { /* JVB */
                    S.dl_ir = ir;
                    S.dl_wait_vb = 1;
                    S.dl_active_row = 0;
                    if (ir & 0x80u)
                        S.dl_dli_today = 1;
                    break;
                }
                continue;
            }
            S.dl_ir = ir;
            S.dl_active_row = 1;
            if (mode == 0x00u) {
                /* Blank lines 1..8 */
                S.dl_vrow = 0;
                S.dl_vrow_end = (u8)((ir >> 4) & 0x07u);
                S.dl_in_vscrol = 0;
                S.row_fetch_bytes = 0;
            } else {
                if (ir & 0x40u) { /* LMS */
                    u16 lo = dl_fetch8_inc();
                    u16 hi = dl_fetch8_inc();
                    dma += 2;
                    S.msc = (u16)(lo | (hi << 8));
                }
                u8 h = mode_heights[mode];
                u8 vs_on = (ir & 0x20u) ? 1u : 0u;
                if (vs_on && !S.dl_in_vscrol) {
                    S.dl_vrow = S.vscrol;
                    S.dl_vrow_end = (u8)(h - 1u);
                    S.dl_in_vscrol = 1;
                } else if (vs_on && S.dl_in_vscrol) {
                    S.dl_vrow = 0;
                    S.dl_vrow_end = (u8)(h - 1u);
                } else if (!vs_on && S.dl_in_vscrol) {
                    S.dl_vrow = 0;
                    S.dl_vrow_end = S.vscrol;
                    S.dl_in_vscrol = 0;
                } else {
                    S.dl_vrow = 0;
                    S.dl_vrow_end = (u8)(h - 1u);
                }
            }
            break;
        }
    }

    if (S.dl_active_row) {
        u8 ir = S.dl_ir;
        u8 mode = (u8)(ir & 0x0Fu);
        if (mode >= 0x02u) {
            u8 wmode = (u8)(S.dmactl & 0x03u);
            u8 fmode = wmode;
            if ((ir & 0x10u) && (fmode == 1u || fmode == 2u))
                fmode++;
            int nbytes = mode_bytes[fmode][mode];
            S.row_fetch_bytes = nbytes;
            if (first_row_line) {
                S.row_msc_base = S.msc;
                for (int i = 0; i < nbytes; i++) {
                    S.line_chars[i] = antic_rd(S.msc);
                    S.msc = (u16)((S.msc & 0xF000u) | ((S.msc + 1u) & 0x0FFFu));
                }
                dma += nbytes;
            }
            if (mode <= 0x07u)
                dma += nbytes; /* Character font glyph fetch on every line of char row */
            else if (!first_row_line)
                dma += 0; /* Multi-line bitmap modes reuse ANTIC's 48-byte line buffer! */
        }

        if (S.dl_vrow == S.dl_vrow_end && (ir & 0x80u))
            S.dl_dli_today = 1;
    }

    if (S.dl_dli_today) {
        /* DLI sets bit 7 and clears bit 6 on real ANTIC */
        S.nmist = (u8)((S.nmist & 0x1Fu) | 0x80u);
        if (S.nmien & 0x80u)
            S.nmi_pend = 1;
    }

    return dma;
}

static void antic_end_line(void)
{
    if (!S.dl_active_row)
        return;
    if (S.dl_vrow == S.dl_vrow_end) {
        S.dl_active_row = 0;
    } else {
        S.dl_vrow = (u8)((S.dl_vrow + 1u) & 0x0Fu);
        if (S.dl_vrow == 0) /* Safety wrap if VSCROL started past mode height */
            S.dl_active_row = 0;
    }
}

/* Render one visible scanline (py = 0..239 -> picture + py * A8_W) */
static void render_scanline(u16 *out)
{
    const u16 *pal = S.is_pal ? M->pal_pal : M->pal_ntsc;
    u8 *pf = M->pf_buf;

    /* 1. Default whole 336-pixel line to PF_BK (0) using 32-bit word stores */
    u32 *pf32 = (u32 *)pf;
    for (int i = 0; i < A8_W / 4; i++)
        pf32[i] = 0;

    u8 ir = S.dl_ir;
    u8 mode = S.dl_active_row ? (u8)(ir & 0x0Fu) : 0u;
    u8 wmode = (u8)(S.dmactl & 0x03u);
    u8 gtia_mode = (u8)(S.prior & 0xC0u);

    /* 2. Decode ANTIC playfield mode into pf[0..335] */
    if (mode >= 0x02u && wmode != 0u && S.row_fetch_bytes > 0) {
        int clip_l = (wmode == 1u) ? 40 : (wmode == 2u) ? 8 : 0;
        int clip_r = (wmode == 1u) ? 296 : (wmode == 2u) ? 328 : 336;
        int x0;
        if (ir & 0x10u) {
            int hs = (int)(S.hscrol & 0x0Fu) * 2;
            x0 = (wmode == 1u) ? (8 + hs) : (-24 + hs);
        } else {
            x0 = (wmode == 1u) ? 40 : (wmode == 2u) ? 8 : -24;
        }

        int nbytes = S.row_fetch_bytes;
        u8 vrow = S.dl_vrow;

        switch (mode) {
        case 0x02:
        case 0x03: {
            u16 fbase = (u16)((S.chbase & 0xFCu) << 8);
            u8 chactl = S.chactl;
            for (int i = 0; i < nbytes; i++) {
                int bx = x0 + i * 8;
                if (bx + 8 <= clip_l || bx >= clip_r)
                    continue;
                u8 ch = S.line_chars[i];
                u8 code = (u8)(ch & 0x7Fu);
                u8 g = 0;
                if (mode == 0x02u) {
                    if (vrow < 8u) {
                        u8 r = (chactl & 0x04u) ? (u8)(7u - vrow) : vrow;
                        g = antic_rd((u16)(fbase + ((u16)code << 3) + r));
                    }
                } else {
                    if (code < 0x60u) {
                        if (vrow < 8u) {
                            u8 r = (chactl & 0x04u) ? (u8)(7u - vrow) : vrow;
                            g = antic_rd((u16)(fbase + ((u16)code << 3) + r));
                        }
                    } else {
                        if (vrow >= 2u && vrow < 8u) {
                            u8 r = (chactl & 0x04u) ? (u8)(7u - vrow) : vrow;
                            g = antic_rd((u16)(fbase + ((u16)code << 3) + r));
                        } else if (vrow >= 8u && vrow < 10u) {
                            u8 r = (u8)(vrow - 8u);
                            if (chactl & 0x04u) r = (u8)(7u - r);
                            g = antic_rd((u16)(fbase + ((u16)code << 3) + r));
                        }
                    }
                }
                if (ch & 0x80u) {
                    if (chactl & 0x01u)
                        g = 0;
                    else if (chactl & 0x02u)
                        g ^= 0xFFu;
                }
                if (bx >= clip_l && bx + 8 <= clip_r) {
                    u8 *d = pf + bx;
                    d[0] = (g & 0x80u) ? PF_HI1 : PF_HI0;
                    d[1] = (g & 0x40u) ? PF_HI1 : PF_HI0;
                    d[2] = (g & 0x20u) ? PF_HI1 : PF_HI0;
                    d[3] = (g & 0x10u) ? PF_HI1 : PF_HI0;
                    d[4] = (g & 0x08u) ? PF_HI1 : PF_HI0;
                    d[5] = (g & 0x04u) ? PF_HI1 : PF_HI0;
                    d[6] = (g & 0x02u) ? PF_HI1 : PF_HI0;
                    d[7] = (g & 0x01u) ? PF_HI1 : PF_HI0;
                } else {
                    for (int b = 0; b < 8; b++) {
                        int px = bx + b;
                        if (px >= clip_l && px < clip_r)
                            pf[px] = (g & (0x80u >> b)) ? PF_HI1 : PF_HI0;
                    }
                }
            }
            break;
        }
        case 0x04:
        case 0x05: {
            u16 fbase = (u16)((S.chbase & 0xFCu) << 8);
            u8 crow = (mode == 0x05u) ? (u8)(vrow >> 1) : vrow;
            for (int i = 0; i < nbytes; i++) {
                int bx = x0 + i * 8;
                if (bx + 8 <= clip_l || bx >= clip_r)
                    continue;
                u8 ch = S.line_chars[i];
                u8 g = 0;
                if (crow < 8u) {
                    u8 r = (S.chactl & 0x04u) ? (u8)(7u - crow) : crow;
                    g = antic_rd((u16)(fbase + ((u16)(ch & 0x7Fu) << 3) + r));
                }
                u8 c3 = (ch & 0x80u) ? PF_3 : PF_2;
                if (bx >= clip_l && bx + 8 <= clip_r) {
                    u8 *d = pf + bx;
                    u8 p0 = (u8)((g >> 6) & 3u), p1 = (u8)((g >> 4) & 3u);
                    u8 p2 = (u8)((g >> 2) & 3u), p3 = (u8)(g & 3u);
                    d[0] = d[1] = (p0 == 0u) ? PF_BK : (p0 == 1u) ? PF_0 : (p0 == 2u) ? PF_1 : c3;
                    d[2] = d[3] = (p1 == 0u) ? PF_BK : (p1 == 1u) ? PF_0 : (p1 == 2u) ? PF_1 : c3;
                    d[4] = d[5] = (p2 == 0u) ? PF_BK : (p2 == 1u) ? PF_0 : (p2 == 2u) ? PF_1 : c3;
                    d[6] = d[7] = (p3 == 0u) ? PF_BK : (p3 == 1u) ? PF_0 : (p3 == 2u) ? PF_1 : c3;
                } else {
                    for (int p = 0; p < 4; p++) {
                        u8 pair = (u8)((g >> (6 - p * 2)) & 3u);
                        u8 col = (pair == 0u) ? PF_BK : (pair == 1u) ? PF_0 : (pair == 2u) ? PF_1 : c3;
                        int px = bx + p * 2;
                        if (px >= clip_l && px < clip_r) pf[px] = col;
                        if (px + 1 >= clip_l && px + 1 < clip_r) pf[px + 1] = col;
                    }
                }
            }
            break;
        }
        case 0x06:
        case 0x07: {
            u16 fbase = (u16)((S.chbase & 0xFEu) << 8);
            u8 crow = (mode == 0x07u) ? (u8)(vrow >> 1) : vrow;
            for (int i = 0; i < nbytes; i++) {
                int bx = x0 + i * 16;
                if (bx + 16 <= clip_l || bx >= clip_r)
                    continue;
                u8 ch = S.line_chars[i];
                u8 g = 0;
                if (crow < 8u) {
                    u8 r = (S.chactl & 0x04u) ? (u8)(7u - crow) : crow;
                    g = antic_rd((u16)(fbase + ((u16)(ch & 0x3Fu) << 3) + r));
                }
                u8 fg = (u8)(PF_0 + ((ch >> 6) & 3u));
                for (int b = 0; b < 8; b++) {
                    u8 col = (g & (0x80u >> b)) ? fg : PF_BK;
                    int px = bx + b * 2;
                    if (px >= clip_l && px < clip_r) pf[px] = col;
                    if (px + 1 >= clip_l && px + 1 < clip_r) pf[px + 1] = col;
                }
            }
            break;
        }
        case 0x08:
            for (int i = 0; i < nbytes; i++) {
                int bx = x0 + i * 32;
                if (bx + 32 <= clip_l || bx >= clip_r)
                    continue;
                u8 g = S.line_chars[i];
                for (int p = 0; p < 4; p++) {
                    u8 pair = (u8)((g >> (6 - p * 2)) & 3u);
                    u8 col = pair ? (u8)(PF_0 + pair - 1u) : PF_BK;
                    int px = bx + p * 8;
                    for (int k = 0; k < 8; k++)
                        if (px + k >= clip_l && px + k < clip_r)
                            pf[px + k] = col;
                }
            }
            break;
        case 0x09:
            for (int i = 0; i < nbytes; i++) {
                int bx = x0 + i * 32;
                if (bx + 32 <= clip_l || bx >= clip_r)
                    continue;
                u8 g = S.line_chars[i];
                for (int b = 0; b < 8; b++) {
                    u8 col = (g & (0x80u >> b)) ? PF_0 : PF_BK;
                    int px = bx + b * 4;
                    for (int k = 0; k < 4; k++)
                        if (px + k >= clip_l && px + k < clip_r)
                            pf[px + k] = col;
                }
            }
            break;
        case 0x0A:
            for (int i = 0; i < nbytes; i++) {
                int bx = x0 + i * 16;
                if (bx + 16 <= clip_l || bx >= clip_r)
                    continue;
                u8 g = S.line_chars[i];
                for (int p = 0; p < 4; p++) {
                    u8 pair = (u8)((g >> (6 - p * 2)) & 3u);
                    u8 col = pair ? (u8)(PF_0 + pair - 1u) : PF_BK;
                    int px = bx + p * 4;
                    for (int k = 0; k < 4; k++)
                        if (px + k >= clip_l && px + k < clip_r)
                            pf[px + k] = col;
                }
            }
            break;
        case 0x0B:
        case 0x0C:
            for (int i = 0; i < nbytes; i++) {
                int bx = x0 + i * 16;
                if (bx + 16 <= clip_l || bx >= clip_r)
                    continue;
                u8 g = S.line_chars[i];
                for (int b = 0; b < 8; b++) {
                    u8 col = (g & (0x80u >> b)) ? PF_0 : PF_BK;
                    int px = bx + b * 2;
                    if (px >= clip_l && px < clip_r) pf[px] = col;
                    if (px + 1 >= clip_l && px + 1 < clip_r) pf[px + 1] = col;
                }
            }
            break;
        case 0x0D:
        case 0x0E:
            for (int i = 0; i < nbytes; i++) {
                int bx = x0 + i * 8;
                if (bx + 8 <= clip_l || bx >= clip_r)
                    continue;
                u8 g = S.line_chars[i];
                if (bx >= clip_l && bx + 8 <= clip_r) {
                    u8 *d = pf + bx;
                    u8 p0 = (u8)((g >> 6) & 3u), p1 = (u8)((g >> 4) & 3u);
                    u8 p2 = (u8)((g >> 2) & 3u), p3 = (u8)(g & 3u);
                    d[0] = d[1] = p0 ? (u8)(PF_0 + p0 - 1u) : PF_BK;
                    d[2] = d[3] = p1 ? (u8)(PF_0 + p1 - 1u) : PF_BK;
                    d[4] = d[5] = p2 ? (u8)(PF_0 + p2 - 1u) : PF_BK;
                    d[6] = d[7] = p3 ? (u8)(PF_0 + p3 - 1u) : PF_BK;
                } else {
                    for (int p = 0; p < 4; p++) {
                        u8 pair = (u8)((g >> (6 - p * 2)) & 3u);
                        u8 col = pair ? (u8)(PF_0 + pair - 1u) : PF_BK;
                        int px = bx + p * 2;
                        if (px >= clip_l && px + 1 < clip_r) {
                            pf[px] = col; pf[px + 1] = col;
                        } else {
                            if (px >= clip_l && px < clip_r) pf[px] = col;
                            if (px + 1 >= clip_l && px + 1 < clip_r) pf[px + 1] = col;
                        }
                    }
                }
            }
            break;
        case 0x0F:
            if (gtia_mode == 0u) {
                for (int i = 0; i < nbytes; i++) {
                    int bx = x0 + i * 8;
                    if (bx + 8 <= clip_l || bx >= clip_r)
                        continue;
                    u8 g = S.line_chars[i];
                    if (bx >= clip_l && bx + 8 <= clip_r) {
                        u8 *d = pf + bx;
                        d[0] = (g & 0x80u) ? PF_HI1 : PF_HI0;
                        d[1] = (g & 0x40u) ? PF_HI1 : PF_HI0;
                        d[2] = (g & 0x20u) ? PF_HI1 : PF_HI0;
                        d[3] = (g & 0x10u) ? PF_HI1 : PF_HI0;
                        d[4] = (g & 0x08u) ? PF_HI1 : PF_HI0;
                        d[5] = (g & 0x04u) ? PF_HI1 : PF_HI0;
                        d[6] = (g & 0x02u) ? PF_HI1 : PF_HI0;
                        d[7] = (g & 0x01u) ? PF_HI1 : PF_HI0;
                    } else {
                        for (int b = 0; b < 8; b++) {
                            int px = bx + b;
                            if (px >= clip_l && px < clip_r)
                                pf[px] = (g & (0x80u >> b)) ? PF_HI1 : PF_HI0;
                        }
                    }
                }
            } else {
                for (int i = 0; i < nbytes; i++) {
                    int bx = x0 + i * 8;
                    if (bx + 8 <= clip_l || bx >= clip_r)
                        continue;
                    u8 g = S.line_chars[i];
                    u8 hi_n = (u8)(0x80u | (g >> 4));
                    u8 lo_n = (u8)(0x80u | (g & 0x0Fu));
                    for (int k = 0; k < 4; k++) {
                        if (bx + k >= clip_l && bx + k < clip_r) pf[bx + k] = hi_n;
                        if (bx + 4 + k >= clip_l && bx + 4 + k < clip_r) pf[bx + 4 + k] = lo_n;
                    }
                }
            }
            break;
        default:
            break;
        }
    }

    /* 3. Fast 32-bit playfield pass for ALL modes (both standard GTIA and Modes 9/10/11!) */
    u8 any_pm = (u8)(S.grafp[0] | S.grafp[1] | S.grafp[2] | S.grafp[3] | S.grafm);
    {
        u16 lut[7];
        lut[PF_BK]  = pal[S.colbk];
        lut[PF_0]   = pal[S.colpf[0]];
        lut[PF_1]   = pal[S.colpf[1]];
        lut[PF_2]   = pal[S.colpf[2]];
        lut[PF_3]   = pal[S.colpf[3]];
        lut[PF_HI0] = pal[S.colpf[2]];
        lut[PF_HI1] = pal[(S.colpf[2] & 0xF0u) | (S.colpf[1] & 0x0Fu)];

        u32 *out32 = (u32 *)out;
        if (!gtia_mode) {
            for (int x = 0; x < A8_W; x += 2) {
                u32 p0 = lut[pf[x]];
                u32 p1 = lut[pf[x + 1]];
                out32[x >> 1] = p0 | (p1 << 16);
            }
        } else {
            u16 glut[16];
            if (gtia_mode == 0x40u) {
                u8 hb = (u8)(S.colbk & 0xF0u);
                for (int n = 0; n < 16; n++)
                    glut[n] = pal[hb | (u8)n];
            } else if (gtia_mode == 0xC0u) {
                u8 lb = (u8)(S.colbk & 0x0Fu);
                glut[0] = pal[S.colbk & 0xF0u];
                for (int n = 1; n < 16; n++)
                    glut[n] = pal[((u8)n << 4) | lb];
            } else {
                glut[0] = pal[S.colpm[0]]; glut[1] = pal[S.colpm[1]];
                glut[2] = pal[S.colpm[2]]; glut[3] = pal[S.colpm[3]];
                glut[4] = glut[12] = pal[S.colpf[0]];
                glut[5] = glut[13] = pal[S.colpf[1]];
                glut[6] = glut[14] = pal[S.colpf[2]];
                glut[7] = glut[15] = pal[S.colpf[3]];
                glut[8] = glut[9] = glut[10] = glut[11] = pal[S.colbk];
            }
            for (int x = 0; x < A8_W; x += 2) {
                u8 v0 = pf[x], v1 = pf[x + 1];
                u32 p0 = (v0 & 0x80u) ? glut[v0 & 15u] : lut[v0];
                u32 p1 = (v1 & 0x80u) ? glut[v1 & 15u] : lut[v1];
                out32[x >> 1] = p0 | (p1 << 16);
            }
        }
        if (!any_pm)
            return;
    }

    /* 4. Splat Players (bits 0..3) and Missiles (bits 4..7) into pm_mask[pm_min..pm_max) */
    u8 *pm = M->pm_mask;
    int pm_min = A8_W, pm_max = 0;
    {
        static const u8 size_step[4] = { 2, 4, 2, 8 };
        for (int p = 0; p < 4; p++) {
            if (S.grafp[p] && S.hposp[p]) {
                int step = size_step[S.sizep[p] & 3u];
                int bx = ((int)S.hposp[p] - 44) * 2;
                int ex = bx + 8 * step;
                if (ex > 0 && bx < A8_W) {
                    if (bx < 0) bx = 0;
                    if (ex > A8_W) ex = A8_W;
                    if (bx < pm_min) pm_min = bx;
                    if (ex > pm_max) pm_max = ex;
                }
            }
            if (((S.grafm >> (p * 2)) & 3u) && S.hposm[p]) {
                int step = size_step[(S.sizem >> (p * 2)) & 3u];
                int bx = ((int)S.hposm[p] - 44) * 2;
                int ex = bx + 2 * step;
                if (ex > 0 && bx < A8_W) {
                    if (bx < 0) bx = 0;
                    if (ex > A8_W) ex = A8_W;
                    if (bx < pm_min) pm_min = bx;
                    if (ex > pm_max) pm_max = ex;
                }
            }
        }
        if (pm_min >= pm_max)
            return; /* All active sprites are offscreen! */

        pm_min &= ~3;
        pm_max = (pm_max + 3) & ~3;
        if (pm_max > A8_W)
            pm_max = A8_W;
        u32 *pm32 = (u32 *)pm;
        for (int i = pm_min >> 2; i < (pm_max >> 2); i++)
            pm32[i] = 0;

        for (int p = 0; p < 4; p++) {
            u8 g = S.grafp[p];
            if (g && S.hposp[p]) {
                int step = size_step[S.sizep[p] & 3u];
                int bx = ((int)S.hposp[p] - 44) * 2;
                u8 bit = (u8)(1u << p);
                if (bx >= 0 && bx + 8 * step <= A8_W) {
                    u16 m16 = (u16)bit | ((u16)bit << 8);
                    for (int b = 0; b < 8; b++) {
                        if (g & (0x80u >> b)) {
                            u16 *d = (u16 *)(pm + bx + b * step);
                            if (step == 2) {
                                d[0] |= m16;
                            } else if (step == 4) {
                                d[0] |= m16; d[1] |= m16;
                            } else {
                                d[0] |= m16; d[1] |= m16; d[2] |= m16; d[3] |= m16;
                            }
                        }
                    }
                } else if (bx + 8 * step > 0 && bx < A8_W) {
                    for (int b = 0; b < 8; b++) {
                        if (g & (0x80u >> b)) {
                            int sx = bx + b * step;
                            for (int k = 0; k < step; k++) {
                                int px = sx + k;
                                if ((unsigned)px < (unsigned)A8_W)
                                    pm[px] |= bit;
                            }
                        }
                    }
                }
            }
            u8 mg = (u8)((S.grafm >> (p * 2)) & 3u);
            if (mg && S.hposm[p]) {
                int step = size_step[(S.sizem >> (p * 2)) & 3u];
                int bx = ((int)S.hposm[p] - 44) * 2;
                u8 bit = (u8)(0x10u << p);
                if (bx >= 0 && bx + 2 * step <= A8_W) {
                    u16 m16 = (u16)bit | ((u16)bit << 8);
                    for (int b = 0; b < 2; b++) {
                        if (mg & (0x02u >> b)) {
                            u16 *d = (u16 *)(pm + bx + b * step);
                            if (step == 2) {
                                d[0] |= m16;
                            } else if (step == 4) {
                                d[0] |= m16; d[1] |= m16;
                            } else {
                                d[0] |= m16; d[1] |= m16; d[2] |= m16; d[3] |= m16;
                            }
                        }
                    }
                } else if (bx + 2 * step > 0 && bx < A8_W) {
                    for (int b = 0; b < 2; b++) {
                        if (mg & (0x02u >> b)) {
                            int sx = bx + b * step;
                            for (int k = 0; k < step; k++) {
                                int px = sx + k;
                                if ((unsigned)px < (unsigned)A8_W)
                                    pm[px] |= bit;
                            }
                        }
                    }
                }
            }
        }
    }

    /* 5. Compose GTIA priorities + hardware collisions ONLY across [pm_min..pm_max) where pm[x] != 0 */
    static const u8 pf_coll_bit[7] = { 0x00u, 0x01u, 0x02u, 0x04u, 0x08u, 0x00u, 0x04u };
    u8 fifth = (S.prior & 0x10u) != 0;
    u8 multi = (S.prior & 0x20u) != 0;
    u8 prio = (u8)(S.prior & 0x0Fu);
    if (!prio)
        prio = 0x01u;

    for (int x = pm_min; x < pm_max; ) {
        u8 m_orig = pm[x];
        if (!m_orig) {
            x++;
            continue;
        }
        u8 pfv_orig = pf[x];
        int run_end = x + 1;
        while (run_end < pm_max && pm[run_end] == m_orig && pf[run_end] == pfv_orig)
            run_end++;

        u8 m = m_orig;
        u8 pfv = pfv_orig;
        u8 pf_cb = 0;
        u8 col = S.colbk;

        if (pfv & 0x80u) {
            /* GTIA Modes 9 / 10 / 11 */
            u8 nib = (u8)(pfv & 0x0Fu);
            if (gtia_mode == 0x40u) {
                u8 pmc = (m & 1u) ? S.colpm[0] : (m & 2u) ? S.colpm[1] : (m & 4u) ? S.colpm[2] :
                         (m & 8u) ? S.colpm[3] : fifth ? S.colpf[3] :
                         (m & 0x10u) ? S.colpm[0] : (m & 0x20u) ? S.colpm[1] :
                         (m & 0x40u) ? S.colpm[2] : S.colpm[3];
                u16 pc = pal[pmc | nib];
                for (; x < run_end; x++)
                    out[x] = pc;
                continue;
            } else if (gtia_mode == 0xC0u) {
                col = (nib == 0u) ? (u8)(S.colbk & 0xF0u) : (u8)((nib << 4) | (S.colbk & 0x0Fu));
                u16 pc = pal[col];
                for (; x < run_end; x++)
                    out[x] = pc;
                continue;
            } else {
                static const u8 m10_pf[16] = {
                    PF_BK, PF_BK, PF_BK, PF_BK, PF_0, PF_1, PF_2, PF_3,
                    PF_BK, PF_BK, PF_BK, PF_BK, PF_0, PF_1, PF_2, PF_3
                };
                if (nib < 4u) {
                    m |= (u8)(1u << nib);
                    pfv = PF_BK;
                } else {
                    pfv = m10_pf[nib];
                }
            }
        }

        pf_cb = pf_coll_bit[pfv];

        /* Hardware collision latches if this span overlaps playfield window [8, 328) */
        if (m && run_end > 8 && x < 328) {
            u8 pl = (u8)(m & 0x0Fu);
            if (pl & 1u) { S.p2pf[0] |= pf_cb; S.p2pl[0] |= (u8)(pl & ~1u); }
            if (pl & 2u) { S.p2pf[1] |= pf_cb; S.p2pl[1] |= (u8)(pl & ~2u); }
            if (pl & 4u) { S.p2pf[2] |= pf_cb; S.p2pl[2] |= (u8)(pl & ~4u); }
            if (pl & 8u) { S.p2pf[3] |= pf_cb; S.p2pl[3] |= (u8)(pl & ~8u); }
            if (m & 0x10u) { S.m2pf[0] |= pf_cb; S.m2pl[0] |= pl; }
            if (m & 0x20u) { S.m2pf[1] |= pf_cb; S.m2pl[1] |= pl; }
            if (m & 0x40u) { S.m2pf[2] |= pf_cb; S.m2pl[2] |= pl; }
            if (m & 0x80u) { S.m2pf[3] |= pf_cb; S.m2pl[3] |= pl; }
        }

        /* Group presence & colors */
        u8 m_pm = fifth ? (u8)(m & 0x0Fu) : m;
        u8 g0 = (u8)((m_pm & 0x01u) | ((m_pm >> 4) & 0x01u));
        u8 g1 = (u8)(((m_pm >> 1) & 0x01u) | ((m_pm >> 5) & 0x01u));
        u8 g2 = (u8)(((m_pm >> 2) & 0x01u) | ((m_pm >> 6) & 0x01u));
        u8 g3 = (u8)(((m_pm >> 3) & 0x01u) | ((m_pm >> 7) & 0x01u));

        u8 has_pm01 = (u8)(g0 | g1);
        u8 has_pm23 = (u8)(g2 | g3);
        u8 c_pm01 = multi ? (u8)((g0 ? S.colpm[0] : 0u) | (g1 ? S.colpm[1] : 0u))
                          : (g0 ? S.colpm[0] : S.colpm[1]);
        u8 c_pm23 = multi ? (u8)((g2 ? S.colpm[2] : 0u) | (g3 ? S.colpm[3] : 0u))
                          : (g2 ? S.colpm[2] : S.colpm[3]);

        u8 has_pf01 = (pfv == PF_0 || pfv == PF_1) ? 1u : 0u;
        u8 c_pf01 = (pfv == PF_0) ? S.colpf[0] : S.colpf[1];

        u8 has_fifth = (fifth && (m & 0xF0u)) ? 1u : 0u;
        u8 has_pf23 = (has_fifth || pfv == PF_2 || pfv == PF_3 || pfv == PF_HI0 || pfv == PF_HI1) ? 1u : 0u;
        u8 c_pf23 = (has_fifth || pfv == PF_3) ? S.colpf[3] : S.colpf[2];

        if (prio & 0x01u) {
            if (has_pm01)      col = c_pm01;
            else if (has_pm23) col = c_pm23;
            else if (has_pf01) col = c_pf01;
            else if (has_pf23) col = c_pf23;
        } else if (prio & 0x02u) {
            if (has_pm01)      col = c_pm01;
            else if (has_pf01) col = c_pf01;
            else if (has_pf23) col = c_pf23;
            else if (has_pm23) col = c_pm23;
        } else if (prio & 0x04u) {
            if (has_pf01)      col = c_pf01;
            else if (has_pf23) col = c_pf23;
            else if (has_pm01) col = c_pm01;
            else if (has_pm23) col = c_pm23;
        } else {
            if (has_pf01)      col = c_pf01;
            else if (has_pm01) col = c_pm01;
            else if (has_pm23) col = c_pm23;
            else if (has_pf23) col = c_pf23;
        }

        /* Hires 1-bit always supplies luminance (COLPF1 & 0x0F) over COLPF2 or underlying PM! */
        if (pfv == PF_HI1)
            col = (u8)((col & 0xF0u) | (S.colpf[1] & 0x0Fu));

        u16 pc = pal[col];
        for (; x < run_end; x++)
            out[x] = pc;
    }
}

/* ---- POKEY Scanline Timers, Potentiometers, Serial & 48 kHz Audio ---- */
static void pokey_scanline_step(void)
{
    /* Potentiometer ramp (228 scanlines normal, immediate in fast pot mode SKCTL & 4) */
    int step = (S.skctl & 0x04u) ? 16 : 1;
    if (S.pot_scan < 228u) {
        int next = (int)S.pot_scan + step;
        S.pot_scan = (u8)(next > 228 ? 228 : next);
        for (int i = 0; i < 8; i++) {
            if (S.pot_scan >= S.pot_target[i])
                S.allpot &= (u8)~(1u << i);
        }
    }

    /* POKEY Timers 1 (bit 0), 2 (bit 1), 4 (bit 2) */
    if (S.irqen & 0x07u) {
        static const u8 tchan[3] = { 0, 1, 3 };
        static const u8 tbit[3]  = { 0x01u, 0x02u, 0x04u };
        for (int t = 0; t < 3; t++) {
            if (S.irqen & tbit[t]) {
                int ch = tchan[t];
                S.tmr_cnt[ch] -= LINE_CYC;
                while (S.tmr_cnt[ch] <= 0) {
                    S.tmr_cnt[ch] += S.tmr_period[ch];
                    S.irqst &= (u8)~tbit[t];
                }
            }
        }
        update_irq();
    }

    /* POKEY Serial SIO byte delivery */
    if (S.sio_rx_pos < S.sio_rx_len) {
        S.sio_rx_delay -= LINE_CYC;
        if (S.sio_rx_delay <= 0) {
            S.sio_serin_byte = M->sio_rx_buf[S.sio_rx_pos++];
            S.sio_rx_delay = 160;
            if (S.sio_rx_pos >= S.sio_rx_len)
                S.sio_rx_len = 0;
            if (S.irqen & 0x20u) {
                S.irqst &= (u8)~0x20u;
                update_irq();
            }
        }
    }

    /* Synthesize 48 kHz audio samples for this scanline (114 CPU cycles) */
    if (!S.snd_rate)
        return;

    u32 cpu_hz = S.is_pal ? 1773447u : 1789772u;
    S.snd_phase += S.snd_rate * (u32)LINE_CYC;
    while (S.snd_phase >= cpu_hz) {
        S.snd_phase -= cpu_hz;
        /* Advance POKEY polynomials & 4 channel dividers by ~37 CPU cycles/sample */
        u32 step_cyc = 37u;
        {
            u32 b17 = ((S.snd_poly17 >> 0) ^ (S.snd_poly17 >> 5)) & 1u;
            S.snd_poly17 = (S.snd_poly17 >> 1) | (b17 << 16);
            u32 b9 = ((S.snd_poly9 >> 0) ^ (S.snd_poly9 >> 5)) & 1u;
            S.snd_poly9 = (S.snd_poly9 >> 1) | (b9 << 8);
            u32 b5 = ((S.snd_poly5 >> 0) ^ (S.snd_poly5 >> 2)) & 1u;
            S.snd_poly5 = (S.snd_poly5 >> 1) | (b5 << 4);
            u32 b4 = ((S.snd_poly4 >> 0) ^ (S.snd_poly4 >> 1)) & 1u;
            S.snd_poly4 = (S.snd_poly4 >> 1) | (b4 << 3);
        }

        u32 p17 = (S.audctl & 0x80u) ? (S.snd_poly9 & 1u) : (S.snd_poly17 & 1u);
        u32 p5  = S.snd_poly5 & 1u;
        u32 p4  = S.snd_poly4 & 1u;

        for (int ch = 0; ch < 4; ch++) {
            u8 ac = S.audc[ch];
            if ((ac & 0x1Fu) == 0u || (ac & 0x10u))
                continue;
            S.snd_div[ch] -= (s32)step_cyc;
            if (S.snd_div[ch] <= 0) {
                s32 per = S.snd_period[ch];
                if (S.snd_div[ch] + per <= 0)
                    S.snd_div[ch] = per;
                else
                    S.snd_div[ch] += per;

                /* High-pass filter latch: ch 2 clocks ch 0, ch 3 clocks ch 1 */
                if (ch == 2 && (S.audctl & 0x04u))
                    S.snd_hpf[0] = S.snd_out[0];
                if (ch == 3 && (S.audctl & 0x02u))
                    S.snd_hpf[1] = S.snd_out[1];

                u8 dist = (u8)((ac >> 5) & 7u);
                if (dist == 5u || dist == 7u) {
                    /* Pure square wave (suppress ultrasonic < 10-cycle ticks into silence) */
                    S.snd_out[ch] = (per < 10) ? 1u : (u8)(S.snd_out[ch] ^ 1u);
                } else if (dist == 4u) {
                    S.snd_out[ch] = (u8)p17;
                } else if (dist == 6u) {
                    S.snd_out[ch] = (u8)p4;
                } else if (dist == 2u) {
                    if (p5) S.snd_out[ch] = (u8)p4;
                } else if (dist == 0u) {
                    if (p5) S.snd_out[ch] = (u8)p17;
                } else {
                    if (p5) S.snd_out[ch] ^= 1u;
                }

                /* Advance LFSR one extra step per divider reload to avoid harmonic lock */
                u32 b17 = ((S.snd_poly17 >> 0) ^ (S.snd_poly17 >> 5)) & 1u;
                S.snd_poly17 = (S.snd_poly17 >> 1) | (b17 << 16);
                u32 b5 = ((S.snd_poly5 >> 0) ^ (S.snd_poly5 >> 2)) & 1u;
                S.snd_poly5 = (S.snd_poly5 >> 1) | (b5 << 4);
                u32 b4 = ((S.snd_poly4 >> 0) ^ (S.snd_poly4 >> 1)) & 1u;
                S.snd_poly4 = (S.snd_poly4 >> 1) | (b4 << 3);
            }
        }

        s32 mix = 0;
        for (int ch = 0; ch < 4; ch++) {
            u8 ac = S.audc[ch];
            s32 vol = (s32)(ac & 0x0Fu);
            if (!vol)
                continue;
            if (ac & 0x10u) {
                /* Volume-only 4-bit DAC digisound */
                mix += vol;
            } else {
                u8 out = S.snd_out[ch];
                if (ch == 0 && (S.audctl & 0x04u)) out ^= S.snd_hpf[0];
                if (ch == 1 && (S.audctl & 0x02u)) out ^= S.snd_hpf[1];
                if (out)
                    mix += vol;
            }
        }

        /* Gentle high-pass DC blocker -> signed 16-bit PCM */
        s32 raw = mix * 380;
        S.dc_est += (raw - (S.dc_est >> 9));
        s32 pcm = raw - (S.dc_est >> 9);
        if (pcm > 32767) pcm = 32767;
        else if (pcm < -32768) pcm = -32768;

        if ((S.snd_wr - S.snd_rd) < SND_RING)
            M->snd_ring[S.snd_wr++ & (SND_RING - 1u)] = (s16)pcm;
    }
}

/* ---- USB HID & ASCII Typing -> POKEY KBCODE ---- */
static const u8 akey_letters[26] = {
    0x3Fu, 0x15u, 0x12u, 0x3Au, 0x2Au, 0x38u, 0x3Du, 0x39u, 0x0Du, /* a..i */
    0x01u, 0x05u, 0x00u, 0x25u, 0x23u, 0x08u, 0x0Au, 0x2Fu, 0x28u, /* j..r */
    0x3Eu, 0x2Du, 0x0Bu, 0x10u, 0x2Eu, 0x16u, 0x2Bu, 0x17u         /* s..z */
};
static const u8 akey_digits[10] = {
    0x32u, 0x1Fu, 0x1Eu, 0x1Au, 0x18u, 0x1Du, 0x1Bu, 0x33u, 0x35u, 0x30u
};
static const u8 a52_digits[10] = {
    0x25u, 0x3Fu, 0x3Du, 0x3Bu, 0x37u, 0x35u, 0x33u, 0x2Fu, 0x2Du, 0x2Bu
};

static int ascii_to_kbcode(char c)
{
    if (c >= 'a' && c <= 'z')
        return akey_letters[c - 'a'];
    if (c >= 'A' && c <= 'Z')
        return akey_letters[c - 'A'] | 0x40u;
    if (c >= '0' && c <= '9')
        return akey_digits[c - '0'];
    switch (c) {
    case '\r': case '\n': return 0x0Cu; /* RETURN */
    case ' ':  return 0x21u;
    case '\b': case 0x7F: return 0x34u; /* BACKSPACE */
    case '\t': return 0x2Cu;
    case '!':  return 0x5Fu;
    case '"':  return 0x5Eu;
    case '#':  return 0x5Au;
    case '$':  return 0x58u;
    case '%':  return 0x5Du;
    case '&':  return 0x5Bu;
    case '\'': return 0x73u;
    case '@':  return 0x75u;
    case '(':  return 0x70u;
    case ')':  return 0x72u;
    case '<':  return 0x36u;
    case '>':  return 0x37u;
    case '=':  return 0x0Fu;
    case '?':  return 0x66u;
    case '-':  return 0x0Eu;
    case '+':  return 0x06u;
    case '*':  return 0x07u;
    case '/':  return 0x26u;
    case ':':  return 0x42u;
    case ';':  return 0x02u;
    case ',':  return 0x20u;
    case '.':  return 0x22u;
    case '_':  return 0x4Eu;
    case '[':  return 0x60u;
    case ']':  return 0x62u;
    case '^':  return 0x47u;
    case '\\': return 0x46u;
    case '|':  return 0x4Fu;
    default:   return -1;
    }
}

void a8_type(char c)
{
    if (S.is_5200)
        return;
    int code = ascii_to_kbcode(c);
    if (code >= 0 && (u16)(S.type_wr - S.type_rd) < TYPE_Q_MAX)
        M->type_q[S.type_wr++ & (TYPE_Q_MAX - 1u)] = (u8)code;
}

static void update_inputs(u16 pad, const u8 *hid, int hid_n)
{
    S.pad = pad;

    if (S.is_5200) {
        /* Atari 5200 analog stick + dual fire + 12-key pad + Start/Pause/Reset */
        S.pot_target[0] = (pad & A8_LEFT) ? 6u : (pad & A8_RIGHT) ? 220u : 114u;
        S.pot_target[1] = (pad & A8_UP)   ? 6u : (pad & A8_DOWN)  ? 220u : 114u;

        S.trig_live[0] = (pad & A8_A) ? 0u : 1u; /* Bottom Fire = TRIG0 */
        S.trig_live[1] = 1u;
        S.trig_live[2] = 1u;
        S.trig_live[3] = 1u;
        if (S.gractl & 0x04u)
            S.trig_latch[0] &= S.trig_live[0];

        int key = -1;
        if (pad & A8_START)  key = 0x39; /* START */
        else if (pad & A8_X) key = 0x31; /* PAUSE */
        else if (pad & A8_SELECT) key = 0x29; /* RESET */
        else if (pad & A8_Y) key = 0x27; /* * */

        for (int i = 0; i < hid_n && key < 0; i++) {
            u8 u = hid[i];
            if (u == 0x27u) key = a52_digits[0];
            else if (u >= 0x1Eu && u <= 0x26u) key = a52_digits[u - 0x1Du];
            else if (u == 0x2Du) key = 0x27; /* - -> * */
            else if (u == 0x2Eu) key = 0x23; /* = -> # */
            else if (u == 0x3Au || u == 0x3Bu) key = 0x39; /* F1/F2 -> START */
            else if (u == 0x3Cu) key = 0x31; /* F3 -> PAUSE */
            else if (u == 0x3Du) key = 0x29; /* F4 -> RESET */
        }

        /* Top Fire button = SKSTAT bit 3 (0 when held) */
        u8 sk = 0xFFu;
        if (pad & A8_B)
            sk &= (u8)~0x08u;
        if (key >= 0 && (S.skctl & 0x02u) && (S.consol_wr & 0x03u) == 0) {
            sk &= (u8)~0x04u;
            S.kbcode = (u8)key;
            if (S.irqen & 0x40u) {
                S.irqst &= (u8)~0x40u;
                update_irq();
            }
        }
        S.skstat = sk;
        return;
    }

    /* ---- Atari 800XL / 130XE inputs ---- */
    u8 consol = 0;
    if (pad & A8_START)  consol |= 0x01u; /* START */
    if (pad & A8_SELECT) consol |= 0x02u; /* SELECT */
    if (pad & (A8_X | 0x0400u)) consol |= 0x04u; /* OPTION (C / PAGE-) */

    u8 shift = 0, ctrl = 0;
    int key = -1;
    int fire = (pad & A8_A) != 0;

    for (int i = 0; i < hid_n; i++) {
        u8 u = hid[i];
        if (u == 0xE1u || u == 0xE5u) shift = 1;
        else if (u == 0xE0u) ctrl = 1;
        else if (u == 0xE4u || u == 0xE2u || u == 0xE6u) fire = 1; /* Right Ctrl / Alt = Joystick Fire */
        else if (u == 0x3Au || u == 0x3Bu) consol |= 0x01u; /* F1 / F2 = START */
        else if (u == 0x3Cu) consol |= 0x02u; /* F3 = SELECT */
        else if (u == 0x3Du) consol |= 0x04u; /* F4 = OPTION */
    }
    S.consol_keys = consol;

    S.trig_live[0] = fire ? 0u : 1u;
    S.trig_live[1] = 1u;
    S.trig_live[2] = 1u;
    S.trig_live[3] = S.cart_left_on ? 1u : 0u;
    if (S.gractl & 0x04u)
        S.trig_latch[0] &= S.trig_live[0];

    /* Map first non-modifier USB HID key to POKEY KBCODE */
    for (int i = 0; i < hid_n && key < 0; i++) {
        u8 u = hid[i];
        if (u >= 0x04u && u <= 0x1Du) {
            key = akey_letters[u - 0x04u];
        } else if (u == 0x27u) {
            key = shift ? 0x72 : akey_digits[0]; shift = 0;
        } else if (u >= 0x1Eu && u <= 0x26u) {
            int d = (int)(u - 0x1Du);
            if (shift) {
                static const u8 sh_d[10] = { 0x72u,0x5Fu,0x75u,0x5Au,0x58u,0x5Du,0x47u,0x5Bu,0x07u,0x70u };
                key = sh_d[d]; shift = 0;
            } else {
                key = akey_digits[d];
            }
        } else {
            switch (u) {
            case 0x28: key = 0x0Cu; break; /* Enter -> RETURN */
            case 0x2A: key = 0x34u; break; /* Backspace */
            case 0x2B: key = 0x2Cu; break; /* Tab */
            case 0x2C: key = 0x21u; break; /* Space */
            case 0x2D: key = shift ? 0x4Eu : 0x0Eu; shift = 0; break; /* - / _ */
            case 0x2E: key = shift ? 0x06u : 0x0Fu; shift = 0; break; /* = / + */
            case 0x2F: key = 0x60u; shift = 0; break; /* [ */
            case 0x30: key = 0x62u; shift = 0; break; /* ] */
            case 0x31: key = shift ? 0x4Fu : 0x46u; shift = 0; break; /* \ / | */
            case 0x33: key = shift ? 0x42u : 0x02u; shift = 0; break; /* ; / : */
            case 0x34: key = shift ? 0x5Eu : 0x73u; shift = 0; break; /* ' / " */
            case 0x35: key = 0x27u; break; /* ` -> ATARI Inverse key */
            case 0x36: key = shift ? 0x36u : 0x20u; shift = 0; break; /* , / < */
            case 0x37: key = shift ? 0x37u : 0x22u; shift = 0; break; /* . / > */
            case 0x38: key = shift ? 0x66u : 0x26u; shift = 0; break; /* / / ? */
            case 0x39: key = 0x3Cu; break; /* Caps Lock */
            case 0x3Eu: /* F5 = Warm Reset (RNMI) */
                S.nmist = (u8)((S.nmist & 0x1Fu) | 0x20u);
                S.nmi_pend = 1;
                break;
            case 0x3Fu: key = 0x11u; break; /* F6 = HELP */
            case 0x40u: /* F7 = BREAK IRQ */
                if (S.irqen & 0x80u) { S.irqst &= (u8)~0x80u; update_irq(); }
                break;
            default: break;
            }
        }
    }

    if (key >= 0) {
        if (shift) key |= 0x40;
        if (ctrl)  key |= 0x80;
    } else if (pad & (A8_B | 0x0800u)) {
        key = 0x21; /* Pad B / Remote PAGE+ -> Space */
    } else if (pad & A8_Y) {
        key = 0x11; /* Pad Y -> HELP */
    }

    /* Drain synthetic typing queue from a8_type() when no physical key is held */
    if (key < 0) {
        if (S.type_timer > 0) {
            S.type_timer--;
            if (S.type_holding) {
                key = S.kbcode;
                if (S.type_timer == 0) {
                    S.type_holding = 0;
                    S.type_timer = 1; /* 1 frame key-up gap */
                }
            }
        } else if (S.type_rd != S.type_wr && !S.xex_loading && S.auto_option_frames == 0 &&
                   (!(S.eff_portb & 0x01u) || M->ram[0x02FC] == 0xFFu)) {
            key = M->type_q[S.type_rd++ & (TYPE_Q_MAX - 1u)];
            S.type_holding = 1;
            S.type_timer = 1;
            /* Clear XL OS KEYDEL ($02F1) repeat lock so consecutive identical chars never drop */
            if ((S.eff_portb & 0x01u) && M->ram[0x02F1] <= 3u)
                M->ram[0x02F1] = 0;
        }
    }

    u8 sk = 0xFFu;
    if (shift || (key >= 0 && (key & 0x40)))
        sk &= (u8)~0x08u;
    if (key >= 0 && (S.skctl & 0x02u)) {
        sk &= (u8)~0x04u;
        if ((u8)key != S.prev_kbcode) {
            S.kbcode = (u8)key;
            S.prev_kbcode = (u8)key;
            if (S.irqen & 0x40u) {
                S.irqst &= (u8)~0x40u;
                update_irq();
            }
        }
    } else {
        S.prev_kbcode = 0xFFu;
    }
    S.skstat = sk;
}

/* ---- Reset & Frame Execution ---- */
void a8_reset(void)
{
    mem_zero(M->ram, sizeof(M->ram));

    S.cyc = 0;
    S.nmi_pend = 0;
    S.irq_pend = 0;
    S.jammed = 0;
    S.wsync = 0;
    S.wsync_next = 0;

    S.porta_out = 0xFFu; S.ddra = 0x00u; S.pactl = 0x3Cu;
    S.portb_out = 0xFFu; S.ddrb = 0x00u; S.pbctl = 0x3Cu;
    S.eff_portb = 0xFFu;

    S.dmactl = 0; S.chactl = 0; S.hscrol = 0; S.vscrol = 0;
    S.pmbase = 0; S.chbase = 0; S.nmien = 0; S.nmist = 0x1Fu;
    S.dlist = 0; S.msc = 0;
    S.dl_active_row = 0; S.dl_wait_vb = 0; S.dl_in_vscrol = 0;

    mem_zero(S.hposp, 4); mem_zero(S.hposm, 4);
    mem_zero(S.sizep, 4); S.sizem = 0;
    mem_zero(S.grafp, 4); S.grafm = 0;
    mem_zero(S.colpm, 4); mem_zero(S.colpf, 4); S.colbk = 0;
    S.prior = 0; S.vdelay = 0; S.gractl = 0; S.consol_wr = 0x0Fu;
    for (int i = 0; i < 4; i++) {
        S.m2pf[i] = 0; S.p2pf[i] = 0; S.m2pl[i] = 0; S.p2pl[i] = 0;
        S.trig_live[i] = 1u; S.trig_latch[i] = 1u;
    }

    for (int i = 0; i < 4; i++) {
        S.audf[i] = 0; S.audc[i] = 0;
        S.tmr_cnt[i] = 28; S.snd_div[i] = 28; S.snd_out[i] = 1u;
    }
    S.audctl = 0;
    S.irqen = 0; S.irqst = 0xFFu; S.skctl = 0; S.skstat = 0xFFu;
    S.kbcode = 0xFFu; S.prev_kbcode = 0xFFu;
    for (int i = 0; i < 8; i++)
        S.pot_target[i] = S.is_5200 ? 114u : 228u;
    S.pot_scan = 0; S.allpot = 0xFFu;
    S.lfsr17 = 0x1FFFFu; S.lfsr9 = 0x1FFu; S.lfsr5 = 0x1Fu; S.lfsr4 = 0x0Fu;
    S.snd_poly17 = 0x1FFFFu; S.snd_poly9 = 0x1FFu; S.snd_poly5 = 0x1Fu; S.snd_poly4 = 0x0Fu;
    pokey_recalc_periods();

    S.sio_cmd_len = 0; S.sio_rx_pos = 0; S.sio_rx_len = 0;
    S.xex_loading = 0; S.xex_pos = 0;
    S.type_rd = 0; S.type_wr = 0; S.type_timer = 0; S.type_holding = 0;

    /* Reset cartridge initial bank */
    S.cart_enabled = (S.media_kind == MEDIA_CART) ? 1u : 0u;
    S.cart_bank = (S.cart_kind == CART_ATARIMAX_1MB) ? 0x7Fu : 0u;
    S.cart_bank2 = 0u;
    S.sic_reg = 0u;

    /* Hold OPTION during boot for .atr / .xex so XL/XE OS disables Internal BASIC cleanly */
    S.auto_option_frames = (!S.is_5200 && (S.media_kind == MEDIA_ATR || S.media_kind == MEDIA_XEX)) ? 75u : 0u;

    rebuild_pages();

    S.a = 0; S.x = 0; S.y = 0; S.sp = 0xFDu;
    S.p = (u8)(FI | FU);
    S.pc = cpu_rd16(0xFFFCu);
}

void a8_frame(u16 pad, const u8 *hid, int hid_n, u16 *picture)
{
    update_inputs(pad, hid, hid_n);
    if (S.auto_option_frames > 0)
        S.auto_option_frames--;

    int total_lines = S.is_pal ? PAL_LINES : NTSC_LINES;
    for (int y = 0; y < total_lines; y++) {
        S.cur_scanline = (u16)y;
        int dma = antic_begin_line(y);

        int pre = PRE_WSYNC_CYC - dma;
        if (pre < 4)
            pre = 4;
        cpu_run(pre);

        if (picture && y >= VIS_START && y < VIS_END)
            render_scanline(picture + (y - VIS_START) * A8_W);

        S.wsync = S.wsync_next;
        S.wsync_next = 0;
        cpu_run(POST_WSYNC_CYC);

        antic_end_line();
        pokey_scanline_step();
    }
}

/* ---- Format Probing & Loading ---- */
int a8_is_xex(const u8 *buf, u32 len)
{
    if (!buf || len < 7u || buf[0] != 0xFFu || buf[1] != 0xFFu)
        return 0;
    u32 p = 2u;
    int segs = 0;
    while (p + 4u <= len) {
        u16 s = (u16)buf[p] | ((u16)buf[p + 1u] << 8);
        p += 2u;
        if (s == 0xFFFFu)
            continue;
        if (p + 2u > len)
            return 0;
        u16 e = (u16)buf[p] | ((u16)buf[p + 1u] << 8);
        p += 2u;
        if (e < s)
            return 0;
        u32 slen = (u32)e - (u32)s + 1u;
        if (segs == 0 && (s < 0x0200u || p + slen > len))
            return 0;
        if (p + slen > len)
            break;
        p += slen;
        segs++;
    }
    return segs > 0;
}

int a8_is_car(const u8 *buf, u32 len, int *is_5200)
{
    if (!buf || len < 16u || buf[0] != 'C' || buf[1] != 'A' || buf[2] != 'R' || buf[3] != 'T')
        return 0;
    u32 t = ((u32)buf[4] << 24) | ((u32)buf[5] << 16) | ((u32)buf[6] << 8) | (u32)buf[7];
    if (t == 0 || t > 110u)
        return 0;
    if (is_5200)
        *is_5200 = (t == 4u || t == 6u || t == 7u || t == 16u || t == 19u || t == 20u) ? 1 : 0;
    return 1;
}

static void build_info(const char *sys, const char *detail)
{
    int n = 0;
    for (int i = 0; sys[i] && n < 120; i++)
        S.info[n++] = sys[i];
    if (detail && *detail) {
        const char *sep = " -- ";
        for (int i = 0; sep[i] && n < 120; i++)
            S.info[n++] = sep[i];
        for (int i = 0; detail[i] && n < 126; i++)
            S.info[n++] = detail[i];
    }
    S.info[n] = 0;
}

/* Auto-detect 16 KB Atari 5200 One-Chip ($8000..$BFFF) vs Two-Chip ($4000/$6000 + $8000/$A000) */
static u8 detect_5200_16k(const u8 *rom)
{
    /* If first 8K == second 8K, both mappings are identical */
    int same = 1;
    for (u32 i = 0; i < 0x2000u; i++) {
        if (rom[i] != rom[0x2000u + i]) { same = 0; break; }
    }
    if (same)
        return CART_5200_16K_ONE;

    u16 start = (u16)rom[0x3FFE] | ((u16)rom[0x3FFF] << 8);
    if (start >= 0x4000u && start < 0x8000u)
        return CART_5200_16K_TWO;

    /* Count JMP ($4C) / JSR ($20) targets in upper 8K ($A000..$BFFF = rom[0x2000..0x3FFF]) */
    int hits_4000 = 0, hits_8000 = 0;
    for (u32 i = 0x2000u; i + 2u < 0x3FF8u; i++) {
        if (rom[i] == 0x20u || rom[i] == 0x4Cu) {
            u16 t = (u16)rom[i + 1u] | ((u16)rom[i + 2u] << 8);
            if (t >= 0x4000u && t < 0x6000u) hits_4000++;
            else if (t >= 0x8000u && t < 0xA000u) hits_8000++;
        }
    }
    return (hits_4000 > hits_8000) ? CART_5200_16K_TWO : CART_5200_16K_ONE;
}

const char *a8_load(const u8 *os16k, const u8 *bas8k, u8 *media, u32 size, const char *path)
{
    init_palettes();
    S.is_5200 = 0;
    S.is_pal = (ci_contains(path, "ntsc") || ci_contains(path, "(usa)") || ci_contains(path, "(us)")) ? 0u : 1u;
    S.save_dirty = 0;

    mem_copy(M->os_rom, os16k ? os16k : altirra_os_xl, 0x4000u);
    mem_copy(M->bas_rom, bas8k ? bas8k : altirra_basic, 0x2000u);

    const char *sys = S.is_pal ? "Atari 130XE (PAL, 128 KB)" : "Atari 130XE (NTSC, 128 KB)";

    /* No media (""): boot straight into 8K BASIC Ready prompt */
    if (!media || size == 0) {
        S.media_kind = MEDIA_NONE;
        S.cart_kind = CART_NONE;
        S.cart_size = 0;
        S.atr_size = 0;
        build_info(sys, bas8k ? "8K BASIC" : "Altirra 8K BASIC 1.59");
        a8_reset();
        return 0;
    }

    /* 1. .atr floppy disk image ($0296 magic) */
    if (size >= 16u && media[0] == 0x96u && media[1] == 0x02u) {
        if (size > ATR_MAX)
            return "the .atr disk image is larger than 1 MB";
        u16 ss = (u16)media[4] | ((u16)media[5] << 8);
        if (ss != 128u && ss != 256u && ss != 512u)
            return "unsupported .atr sector size";
        mem_copy(M->atr_buf, media, size);
        S.media_kind = MEDIA_ATR;
        S.cart_kind = CART_NONE;
        S.cart_size = 0;
        S.atr_size = size;
        S.atr_sec_size = ss;
        u32 body = size - 16u;
        if (ss == 256u && (body & 255u) == 128u) {
            S.atr_dd_short_boot = 1u;
            S.atr_sectors = (body >= 384u) ? (3u + (body - 384u) / 256u) : (body / 128u);
        } else {
            S.atr_dd_short_boot = 0u;
            S.atr_sectors = body / ss;
        }
        build_info(sys, (ss == 256u) ? "DD .atr floppy disk" :
                        (S.atr_sectors >= 1000u) ? "ED .atr floppy disk" : "SD .atr floppy disk");
        a8_reset();
        return 0;
    }

    /* 2. .car headered cartridge ("CART") */
    int car_5200 = 0;
    if (a8_is_car(media, size, &car_5200)) {
        if (car_5200)
            return a52_load(0, media, size, path);
        u32 ctype = ((u32)media[4] << 24) | ((u32)media[5] << 16) | ((u32)media[6] << 8) | (u32)media[7];
        u32 rsz = size - 16u;
        if (rsz == 0 || rsz > CART_MAX)
            return "unsupported .car ROM size";
        mem_copy(M->cart_rom, media + 16u, rsz);
        S.media_kind = MEDIA_CART;
        S.cart_size = rsz;
        S.atr_size = 0;
        S.express_mask = 0x70u;

        switch (ctype) {
        case 1:  S.cart_kind = CART_STD_8K; break;
        case 2:  S.cart_kind = CART_STD_16K; break;
        case 3:  S.cart_kind = CART_OSS_034M; break;
        case 5:  S.cart_kind = CART_DB_32K; break;
        case 8: case 22: S.cart_kind = CART_WILLIAMS; break;
        case 9:  S.cart_kind = CART_EXPRESS_64K; S.express_mask = 0x70u; break;
        case 10: S.cart_kind = CART_EXPRESS_64K; S.express_mask = 0xD0u; break;
        case 11: S.cart_kind = CART_EXPRESS_64K; S.express_mask = 0xE0u; break;
        case 12: case 13: case 14: case 23: case 24: case 25: S.cart_kind = CART_XEGS; break;
        case 15: S.cart_kind = CART_OSS_M091; break;
        case 18: S.cart_kind = CART_BOUNTY_XL; break;
        case 21: S.cart_kind = CART_RIGHT_8K; break;
        case 26: case 27: case 28: case 29: case 30: case 31: case 32: S.cart_kind = CART_MEGACART; break;
        case 33: case 34: case 35: case 36: case 37: case 38: S.cart_kind = CART_SW_XEGS; break;
        case 39: S.cart_kind = CART_PHOENIX_8K; break;
        case 40: S.cart_kind = CART_BLIZZARD_16K; break;
        case 41: S.cart_kind = CART_ATARIMAX_128K; break;
        case 42: case 75: S.cart_kind = CART_ATARIMAX_1MB; break;
        case 58: case 59: case 60: S.cart_kind = CART_SIC; break;
        default:
            S.cart_kind = (rsz <= 0x2000u) ? CART_STD_8K : (rsz <= 0x4000u) ? CART_STD_16K : CART_XEGS;
            break;
        }
        build_info(sys, "CART ROM");
        a8_reset();
        if (ctype == 75u) { S.cart_bank = 0u; rebuild_pages(); }
        return 0;
    }

    /* 3. .xex / .obx / .com ($FFFF multi-segment binary executable) */
    if (a8_is_xex(media, size)) {
        if (size > ATR_MAX)
            return "the .xex executable is larger than 1 MB";
        mem_copy(M->atr_buf, media, size);
        S.media_kind = MEDIA_XEX;
        S.cart_kind = CART_NONE;
        S.cart_size = 0;
        S.xex_size = size;
        S.atr_size = 0;
        build_info(sys, "binary executable (.xex)");
        a8_reset();
        return 0;
    }

    /* 4. Headerless XL/XE ROM cartridge (2K / 4K / 8K / 16K / 32K..1MB) */
    if (size <= CART_MAX && (size == 0x800u || size == 0x1000u || size == 0x2000u || size == 0x4000u ||
        size == 0x8000u || size == 0xA000u || size == 0x10000u || size == 0x20000u ||
        size == 0x40000u || size == 0x80000u || size == 0x100000u)) {
        S.media_kind = MEDIA_CART;
        S.atr_size = 0;
        if (size < 0x2000u) {
            /* Mirror 2K/4K across $A000..$BFFF */
            for (u32 off = 0; off < 0x2000u; off += size)
                mem_copy(M->cart_rom + off, media, size);
            S.cart_size = 0x2000u;
            S.cart_kind = CART_STD_8K;
        } else {
            mem_copy(M->cart_rom, media, size);
            S.cart_size = size;
            if (size == 0x2000u) {
                S.cart_kind = CART_STD_8K;
            } else if (size == 0x4000u) {
                S.cart_kind = CART_STD_16K;
            } else if (size == 0xA000u) {
                S.cart_kind = CART_BOUNTY_XL;
            } else {
                /* Distinguish Atarimax (bank 0 has $BFFC == 0x00 and last bank doesn't) vs XEGS */
                int last_ok = (media[size - 4u] == 0x00u);
                int first_ok = (media[0x1FFCu] == 0x00u);
                if (!last_ok && first_ok && size == 0x20000u)
                    S.cart_kind = CART_ATARIMAX_128K;
                else
                    S.cart_kind = CART_XEGS;
            }
        }
        build_info(sys, "cartridge ROM");
        a8_reset();
        return 0;
    }

    return "not a supported Atari 800XL / 130XE .atr, .xex, .car or .rom file";
}

const char *a52_load(const u8 *bios2k, u8 *media, u32 size, const char *path)
{
    init_palettes();
    if (!media || size < 1024u)
        return "Atari 5200 requires a cartridge (.a52, .car, .bin)";

    S.is_5200 = 1;
    S.is_pal = ci_contains(path, "(pal)") ? 1u : 0u;
    S.save_dirty = 0;
    S.atr_size = 0;
    mem_copy(M->bios52, bios2k ? bios2k : altirra_os_5200, 0x800u);

    const u8 *rom = media;
    u32 rsz = size;
    u32 ctype = 0;
    int car_5200 = 0;
    if (a8_is_car(media, size, &car_5200)) {
        if (!car_5200)
            return "this .car file is for the Atari 800XL/130XE (use 'atari8')";
        ctype = ((u32)media[4] << 24) | ((u32)media[5] << 16) | ((u32)media[6] << 8) | (u32)media[7];
        rom = media + 16u;
        rsz = size - 16u;
    }

    if (rsz == 0 || rsz > CART_MAX)
        return "unsupported Atari 5200 cartridge size";

    S.media_kind = MEDIA_CART;
    if (rsz < 0x1000u) {
        for (u32 off = 0; off < 0x1000u; off += rsz)
            mem_copy(M->cart_rom + off, rom, rsz);
        rsz = 0x1000u;
    } else {
        mem_copy(M->cart_rom, rom, rsz);
    }
    S.cart_size = rsz;

    const char *detail = "32 KB cartridge";
    if (ctype == 4u || rsz == 0x8000u) {
        S.cart_kind = CART_5200_32K;
        detail = "32 KB cartridge";
    } else if (ctype == 6u) {
        S.cart_kind = CART_5200_16K_TWO;
        detail = "16 KB Two-Chip cartridge";
    } else if (ctype == 16u) {
        S.cart_kind = CART_5200_16K_ONE;
        detail = "16 KB One-Chip cartridge";
    } else if (ctype == 7u || rsz == 0xA000u) {
        S.cart_kind = CART_5200_BOUNTY;
        detail = "40 KB Bounty Bob cartridge";
    } else if (ctype == 19u || rsz == 0x2000u) {
        S.cart_kind = CART_5200_8K;
        detail = "8 KB cartridge";
    } else if (ctype == 20u || rsz == 0x1000u) {
        S.cart_kind = CART_5200_4K;
        detail = "4 KB cartridge";
    } else if (rsz == 0x4000u) {
        S.cart_kind = detect_5200_16k(M->cart_rom);
        detail = (S.cart_kind == CART_5200_16K_TWO) ? "16 KB Two-Chip cartridge" : "16 KB One-Chip cartridge";
    } else if (rsz == 0x6000u) {
        /* 24 KB dump: pad first 8K + 16K into 32 KB ($4000..$BFFF) */
        for (u32 i = 0x6000u; i-- > 0;)
            M->cart_rom[0x2000u + i] = M->cart_rom[i];
        mem_copy(M->cart_rom, M->cart_rom + 0x2000u, 0x2000u);
        S.cart_size = 0x8000u;
        S.cart_kind = CART_5200_32K;
        detail = "24 KB cartridge";
    } else {
        return "unsupported Atari 5200 ROM size (expected 4K, 8K, 16K, 24K, 32K or 40K)";
    }

    build_info("Atari 5200 SuperSystem", detail);
    a8_reset();
    return 0;
}

int a8_pal(void)
{
    return S.is_pal;
}

const char *a8_info(void)
{
    return S.info;
}

u8 *a8_save_ram(u32 *size, int *battery)
{
    if (!S.is_5200 && S.media_kind == MEDIA_ATR && S.atr_size > 0) {
        *size = S.atr_size;
        *battery = 1;
        return M->atr_buf;
    }
    *size = 0;
    *battery = 0;
    return 0;
}

int a8_save_changed(void)
{
    int d = S.save_dirty;
    S.save_dirty = 0;
    return d;
}

int a8_jammed(void)
{
    return S.jammed;
}

void a8_audio_rate(u32 hz)
{
    S.snd_rate = hz;
    S.snd_phase = 0;
    S.snd_rd = 0;
    S.snd_wr = 0;
}

int a8_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && S.snd_rd != S.snd_wr)
        out[n++] = M->snd_ring[S.snd_rd++ & (SND_RING - 1u)];
    return n;
}
