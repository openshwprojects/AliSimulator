/* MSX1 & MSX2 home computers (TMS9918A / Yamaha V9938, 256 KB Mapper, SCC, YM2413, .dsk): see msx.h. */
#pragma GCC optimize("O2")
#include "msx.h"
#include "z80.h"
#ifndef MSX_HOST
#include "hw.h"
#endif

#define LINE_T   228
#define LINES    262
#define FRAME_T  (LINE_T * LINES)
#define DSK_MAX  0xB4000u               /* 720 KB (80 tracks x 2 sides x 9 sectors x 512 B) */

enum {
    MAP_PLAIN = 0,
    MAP_KONAMI4,
    MAP_KONAMI_SCC,
    MAP_ASCII8,
    MAP_ASCII16,
    MAP_GENERIC8,
    MAP_GENERIC16
};

struct msx_mem {
    u8 bios[0x8000];                    /* 32 KB Slot 0-0 Main BIOS ($0000..$7FFF) */
    u8 subrom[0x4000];                  /* 16 KB Slot 3-1 MSX2 Sub-ROM ($0000..$3FFF) */
    u8 diskrom[0x4000];                 /* 16 KB Slot 3-2 Disk ROM ($4000..$7FFF) */
    u8 fmrom[0x4000];                   /* 16 KB Slot 2 MSX-MUSIC OPLL ROM ($4000..$7FFF) */
    u8 ram[0x40000];                    /* 256 KB Slot 3-0 Memory Mapper RAM (16 x 16 KB) */
    u8 vram[0x20000];                   /* 128 KB Yamaha V9938 VRAM */
    u8 exp_vram[0x10000];               /* 64 KB V9938 Expansion VRAM (MXD/MXS) */
    u8 dsk[DSK_MAX];                    /* Mounted .dsk floppy image (up to 720 KB) */
    u8 open_bus[0x400];
    u8 sav_dummy[256];
    s16 audio_ring[4096];
};

#ifdef MSX_HOST
static struct msx_mem msx_mem_buf;
#define M (&msx_mem_buf)
#else
#define M ((struct msx_mem *)KSEG0(EMU_RAM_PHYS))
#endif

struct msx_ay {
    u8 reg_sel;
    u8 reg[16];
    u32 phase[3], noise_phase, env_phase;
    u8 out_bit[3];
    u32 lfsr;
    u8 env_step, env_vol, env_hold, env_att;
};

struct msx_scc {
    s8 wave[5][32];
    u16 period[5];
    u8 vol[5];
    u8 enable;
    u32 phase[5], pos[5];
};

struct msx_opll {
    u8 addr;
    u8 reg[64];
    u32 mod_phase[9], car_phase[9];
    s16 env_lvl[9];                     /* 0 (loudest) .. 511 (silent) */
    u8 eg_state[9];                     /* 0=off, 1=att, 2=dec, 3=sus, 4=rel */
    u8 key_was[9];
    s16 prev_mod[9];
    u32 lfsr;
};

struct vdp_cmd_state {
    u8 active;
    u8 op;                              /* high nibble of R#46 */
    u8 lop;                             /* low nibble of R#46 */
    u16 sx, sy, dx, dy, nx, ny;
    u16 cx, cy;
    s32 err;
    u16 step_cnt;
};

static struct {
    struct z80 cpu;
    u8 *rom;
    u32 rom_size, banks8k, banks16k;
    u8 is_msx2;
    u8 has_cart, has_dsk, dsk_dirty;
    u32 dsk_size;
    u8 mapper, ext_bios, ext_subrom;
    u16 cart_base;
    u16 cart_init;
    u8 bank[4];
    u8 scc_mapped;

    /* Slots & Memory Mapper */
    u8 ppi_a;                           /* Port 0xA8 primary slot select */
    u8 ppi_c;                           /* Port 0xAA keyboard row select */
    u8 slot3_sub;                       /* $FFFF secondary slot select for expanded Slot 3 */
    u8 mapper_page[4];                  /* Ports 0xFC..0xFF 16 KB RAM mapper banks */

    /* TMS9918A / Yamaha V9938 VDP */
    u8 vdp_reg[64];
    u8 vdp_stat[16];
    u32 vdp_addr;
    u8 vdp_first, vdp_latch, vdp_buf;
    u8 pal_first, pal_latch;
    u8 pal_rgb333[16][3];
    u16 pal[16];
    u16 pal256[256];                    /* Precomputed GGGRRRBB -> 0bbbbbgggggrrrrr for SCREEN 8 */
    u16 spr8_pal[16];                   /* Fixed V9938 8-bit mode sprite palette */
    int cur_w, cur_h;
    u32 frame_no;
    struct vdp_cmd_state cmd;

    /* Ricoh RP5C01 RTC */
    u8 rtc_addr;
    u8 rtc_bank[4][16];

    /* Input */
    u16 pad_state;
    u8 kbd_hid[11];
    u8 kbd_row[11];
    char typed_ch;
    u8 typed_frames;

    /* Audio */
    struct msx_ay ay;
    struct msx_scc scc;
    struct msx_opll opll;
    u32 sample_rate, audio_frac;
    s32 audio_last_cyc;
    int audio_count;
} S;

static char info_buf[96];

static const s16 ay_vol_tab[16] = {
       0,   163,   205,   258,   325,   410,   516,   649,
     817,  1029,  1295,  1631,  2053,  2584,  3254,  4096
};

/* Quarter-wave sine table (64 entries -> 256-entry full wave, range -2048..+2048) for YM2413 OPLL */
static const s16 opll_sin64[64] = {
       0,   50,  100,  151,  201,  251,  301,  350,  400,  449,  498,  546,  595,  642,  690,  737,
     784,  830,  876,  921,  965, 1009, 1053, 1096, 1138, 1179, 1220, 1260, 1299, 1338, 1375, 1412,
    1448, 1483, 1517, 1551, 1583, 1615, 1645, 1675, 1703, 1730, 1757, 1782, 1806, 1829, 1851, 1872,
    1892, 1911, 1928, 1945, 1960, 1974, 1987, 1998, 2009, 2018, 2026, 2033, 2038, 2042, 2045, 2047
};

/* YM2413 16 instruments (0 = user, 1..15 = ROM patches): {mod_mult, mod_tl, fb, car_mult, ar, dr, sl, rr} */
static const u8 opll_patches[16][8] = {
    {1, 16, 0, 1, 12, 4, 2, 5},         /* 0: User default */
    {1, 18, 5, 1, 15, 3, 2, 5},         /* 1: Violin */
    {1, 22, 4, 1, 15, 5, 3, 6},         /* 2: Guitar */
    {1, 16, 3, 1, 15, 4, 4, 5},         /* 3: Piano */
    {1, 24, 2, 1, 11, 2, 1, 5},         /* 4: Flute */
    {1, 20, 3, 2, 12, 3, 2, 5},         /* 5: Clarinet */
    {1, 20, 2, 1, 12, 2, 2, 5},         /* 6: Oboe */
    {1, 16, 5, 1, 13, 3, 2, 5},         /* 7: Trumpet */
    {1, 20, 1, 1, 14, 1, 1, 5},         /* 8: Organ */
    {1, 18, 4, 1, 11, 3, 2, 4},         /* 9: Horn */
    {1, 22, 2, 1, 10, 2, 1, 4},         /* 10: Synthesizer */
    {3, 14, 4, 1, 15, 6, 4, 7},         /* 11: Harpsichord */
    {2, 20, 1, 1, 15, 5, 3, 6},         /* 12: Vibraphone */
    {1, 14, 6, 1, 14, 4, 2, 5},         /* 13: Synth Bass */
    {1, 18, 3, 1, 15, 5, 3, 6},         /* 14: Acoustic Bass */
    {1, 14, 6, 1, 15, 3, 2, 5}          /* 15: Electric Guitar */
};

/* Compact 8x8 ASCII font (0x20..0x7F) placed at $1BBF + 0x100 ($1CBF) for CGTABL = $1BBF */
static const u8 msx_font96[96][8] = {
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, {0x10,0x10,0x10,0x10,0x10,0x00,0x10,0x00},
    {0x28,0x28,0x28,0x00,0x00,0x00,0x00,0x00}, {0x28,0x28,0x7C,0x28,0x7C,0x28,0x28,0x00},
    {0x10,0x3C,0x50,0x38,0x14,0x78,0x10,0x00}, {0x60,0x64,0x08,0x10,0x20,0x4C,0x0C,0x00},
    {0x30,0x48,0x50,0x20,0x54,0x48,0x34,0x00}, {0x10,0x10,0x20,0x00,0x00,0x00,0x00,0x00},
    {0x08,0x10,0x20,0x20,0x20,0x10,0x08,0x00}, {0x20,0x10,0x08,0x08,0x08,0x10,0x20,0x00},
    {0x00,0x10,0x54,0x38,0x54,0x10,0x00,0x00}, {0x00,0x10,0x10,0x7C,0x10,0x10,0x00,0x00},
    {0x00,0x00,0x00,0x00,0x00,0x10,0x10,0x20}, {0x00,0x00,0x00,0x7C,0x00,0x00,0x00,0x00},
    {0x00,0x00,0x00,0x00,0x00,0x10,0x10,0x00}, {0x00,0x04,0x08,0x10,0x20,0x40,0x00,0x00},
    {0x38,0x44,0x4C,0x54,0x64,0x44,0x38,0x00}, {0x10,0x30,0x10,0x10,0x10,0x10,0x38,0x00},
    {0x38,0x44,0x04,0x18,0x20,0x40,0x7C,0x00}, {0x7C,0x08,0x10,0x18,0x04,0x44,0x38,0x00},
    {0x08,0x18,0x28,0x48,0x7C,0x08,0x08,0x00}, {0x7C,0x40,0x78,0x04,0x04,0x44,0x38,0x00},
    {0x18,0x20,0x40,0x78,0x44,0x44,0x38,0x00}, {0x7C,0x04,0x08,0x10,0x20,0x20,0x20,0x00},
    {0x38,0x44,0x44,0x38,0x44,0x44,0x38,0x00}, {0x38,0x44,0x44,0x3C,0x04,0x08,0x30,0x00},
    {0x00,0x10,0x10,0x00,0x10,0x10,0x00,0x00}, {0x00,0x10,0x10,0x00,0x10,0x10,0x20,0x00},
    {0x08,0x10,0x20,0x40,0x20,0x10,0x08,0x00}, {0x00,0x00,0x7C,0x00,0x7C,0x00,0x00,0x00},
    {0x20,0x10,0x08,0x04,0x08,0x10,0x20,0x00}, {0x38,0x44,0x04,0x18,0x10,0x00,0x10,0x00},
    {0x38,0x44,0x5C,0x54,0x5C,0x40,0x38,0x00}, {0x38,0x44,0x44,0x7C,0x44,0x44,0x44,0x00},
    {0x78,0x44,0x44,0x78,0x44,0x44,0x78,0x00}, {0x38,0x44,0x40,0x40,0x40,0x44,0x38,0x00},
    {0x70,0x48,0x44,0x44,0x44,0x48,0x70,0x00}, {0x7C,0x40,0x40,0x78,0x40,0x40,0x7C,0x00},
    {0x7C,0x40,0x40,0x78,0x40,0x40,0x40,0x00}, {0x38,0x44,0x40,0x5C,0x44,0x44,0x38,0x00},
    {0x44,0x44,0x44,0x7C,0x44,0x44,0x44,0x00}, {0x38,0x10,0x10,0x10,0x10,0x10,0x38,0x00},
    {0x1C,0x08,0x08,0x08,0x08,0x48,0x30,0x00}, {0x44,0x48,0x50,0x60,0x50,0x48,0x44,0x00},
    {0x40,0x40,0x40,0x40,0x40,0x40,0x7C,0x00}, {0x44,0x6C,0x54,0x54,0x44,0x44,0x44,0x00},
    {0x44,0x64,0x54,0x4C,0x44,0x44,0x44,0x00}, {0x38,0x44,0x44,0x44,0x44,0x44,0x38,0x00},
    {0x78,0x44,0x44,0x78,0x40,0x40,0x40,0x00}, {0x38,0x44,0x44,0x44,0x54,0x48,0x34,0x00},
    {0x78,0x44,0x44,0x78,0x50,0x48,0x44,0x00}, {0x38,0x44,0x40,0x38,0x04,0x44,0x38,0x00},
    {0x7C,0x10,0x10,0x10,0x10,0x10,0x10,0x00}, {0x44,0x44,0x44,0x44,0x44,0x44,0x38,0x00},
    {0x44,0x44,0x44,0x44,0x44,0x28,0x10,0x00}, {0x44,0x44,0x44,0x54,0x54,0x54,0x28,0x00},
    {0x44,0x44,0x28,0x10,0x28,0x44,0x44,0x00}, {0x44,0x44,0x28,0x10,0x10,0x10,0x10,0x00},
    {0x7C,0x04,0x08,0x10,0x20,0x40,0x7C,0x00}, {0x38,0x20,0x20,0x20,0x20,0x20,0x38,0x00},
    {0x00,0x40,0x20,0x10,0x08,0x04,0x00,0x00}, {0x38,0x08,0x08,0x08,0x08,0x08,0x38,0x00},
    {0x10,0x28,0x44,0x00,0x00,0x00,0x00,0x00}, {0x00,0x00,0x00,0x00,0x00,0x00,0x7C,0x00},
    {0x20,0x10,0x08,0x00,0x00,0x00,0x00,0x00}, {0x00,0x00,0x38,0x04,0x3C,0x44,0x3C,0x00},
    {0x40,0x40,0x58,0x64,0x44,0x44,0x78,0x00}, {0x00,0x00,0x38,0x40,0x40,0x44,0x38,0x00},
    {0x04,0x04,0x34,0x4C,0x44,0x44,0x3C,0x00}, {0x00,0x00,0x38,0x44,0x7C,0x40,0x38,0x00},
    {0x18,0x24,0x20,0x70,0x20,0x20,0x20,0x00}, {0x00,0x00,0x3C,0x44,0x44,0x3C,0x04,0x38},
    {0x40,0x40,0x58,0x64,0x44,0x44,0x44,0x00}, {0x10,0x00,0x30,0x10,0x10,0x10,0x38,0x00},
    {0x08,0x00,0x18,0x08,0x08,0x08,0x48,0x30}, {0x40,0x40,0x48,0x50,0x60,0x50,0x48,0x00},
    {0x30,0x10,0x10,0x10,0x10,0x10,0x38,0x00}, {0x00,0x00,0x68,0x54,0x54,0x44,0x44,0x00},
    {0x00,0x00,0x58,0x64,0x44,0x44,0x44,0x00}, {0x00,0x00,0x38,0x44,0x44,0x44,0x38,0x00},
    {0x00,0x00,0x78,0x44,0x44,0x78,0x40,0x40}, {0x00,0x00,0x3C,0x44,0x44,0x3C,0x04,0x04},
    {0x00,0x00,0x58,0x64,0x40,0x40,0x40,0x00}, {0x00,0x00,0x3C,0x40,0x38,0x04,0x78,0x00},
    {0x20,0x20,0x70,0x20,0x20,0x24,0x18,0x00}, {0x00,0x00,0x44,0x44,0x44,0x4C,0x34,0x00},
    {0x00,0x00,0x44,0x44,0x44,0x28,0x10,0x00}, {0x00,0x00,0x44,0x44,0x54,0x54,0x28,0x00},
    {0x00,0x00,0x44,0x28,0x10,0x28,0x44,0x00}, {0x00,0x00,0x44,0x44,0x44,0x3C,0x04,0x38},
    {0x00,0x00,0x7C,0x08,0x10,0x20,0x7C,0x00}, {0x08,0x10,0x10,0x20,0x10,0x10,0x08,0x00},
    {0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x00}, {0x20,0x10,0x10,0x08,0x10,0x10,0x20,0x00},
    {0x00,0x20,0x54,0x08,0x00,0x00,0x00,0x00}, {0x38,0x44,0x5C,0x50,0x5C,0x44,0x38,0x00}
};

/* ---- Helper: 15-bit 0bbbbbgggggrrrrr from 3-bit RGB333 ---- */
static inline u16 pack_rgb333(u8 r3, u8 g3, u8 b3)
{
    u32 r5 = ((u32)(r3 & 7u) * 31u + 3u) / 7u;
    u32 g5 = ((u32)(g3 & 7u) * 31u + 3u) / 7u;
    u32 b5 = ((u32)(b3 & 7u) * 31u + 3u) / 7u;
    return (u16)(r5 | (g5 << 5) | (b5 << 10));
}

/* ---- Audio synthesis (AY-3-8910 + Konami SCC + Yamaha YM2413 OPLL) ---- */
static inline s16 opll_sin(u32 idx)
{
    idx &= 255u;
    u32 q = idx & 63u;
    s16 v = opll_sin64[(idx & 64u) ? (63u - q) : q];
    return (idx & 128u) ? (s16)-v : v;
}

static void audio_step(u32 tstates)
{
    if (!S.sample_rate || !tstates)
        return;
    u32 count = 0;
    while (tstates) {
        u32 chunk = tstates > 16000u ? 16000u : tstates;
        tstates -= chunk;
        u32 num = chunk * S.sample_rate + S.audio_frac;
        count += num / 3579545u;
        S.audio_frac = num % 3579545u;
    }
    if (!count)
        return;

    u32 ay_step = 57272720u / S.sample_rate;
    u32 scc_step = 916363520u / S.sample_rate;
    /* YM2413 master = 3.579545 MHz / 72 = 49715.9 Hz */
    u32 opll_base = (49716u << 10) / S.sample_rate;

    while (count--) {
        s32 mix = 0;

        /* 1. AY-3-8910 */
        u32 ep = (u32)S.ay.reg[11] | ((u32)S.ay.reg[12] << 8);
        if (!ep) ep = 1u;
        u32 ep8 = ep << 9;
        S.ay.env_phase += ay_step;
        while (S.ay.env_phase >= ep8) {
            S.ay.env_phase -= ep8;
            if (!S.ay.env_hold) {
                S.ay.env_step++;
                if (S.ay.env_step >= 16) {
                    S.ay.env_step = 0;
                    u8 sh = S.ay.reg[13] & 0x0Fu;
                    if (!(sh & 0x08u)) {
                        S.ay.env_att = 0;
                        S.ay.env_hold = 1;
                    } else {
                        if (sh & 0x02u) S.ay.env_att ^= 0x0Fu;
                        if (sh & 0x01u) { S.ay.env_hold = 1; S.ay.env_step = 15; }
                    }
                }
            }
            S.ay.env_vol = (S.ay.env_step ^ S.ay.env_att) & 15u;
        }
        u32 np = S.ay.reg[6] & 0x1Fu;
        if (!np) np = 1u;
        u32 np8 = np << 9;
        S.ay.noise_phase += ay_step;
        while (S.ay.noise_phase >= np8) {
            S.ay.noise_phase -= np8;
            u32 fb = ((S.ay.lfsr >> 0) ^ (S.ay.lfsr >> 3)) & 1u;
            S.ay.lfsr = (S.ay.lfsr >> 1) | (fb << 16);
        }
        u8 mixer = S.ay.reg[7];
        for (int ch = 0; ch < 3; ch++) {
            u32 tp = (u32)S.ay.reg[ch * 2] | (((u32)S.ay.reg[ch * 2 + 1] & 0x0Fu) << 8);
            if (!tp) tp = 1u;
            u32 tp8 = tp << 8;
            S.ay.phase[ch] += ay_step;
            while (S.ay.phase[ch] >= tp8) {
                S.ay.phase[ch] -= tp8;
                S.ay.out_bit[ch] ^= 1u;
            }
            int t_ok = (mixer & (1u << ch)) || S.ay.out_bit[ch];
            int n_ok = (mixer & (8u << ch)) || (S.ay.lfsr & 1u);
            u8 vr = S.ay.reg[8 + ch];
            u8 vol = (vr & 0x10u) ? S.ay.env_vol : (vr & 0x0Fu);
            s16 amp = ay_vol_tab[vol & 15u];
            mix += (t_ok && n_ok) ? amp : -amp;
        }

        /* 2. Konami SCC 5-channel wavetable */
        if (S.mapper == MAP_KONAMI_SCC && S.scc.enable) {
            for (int ch = 0; ch < 5; ch++) {
                if (!(S.scc.enable & (1u << ch)) || !S.scc.vol[ch])
                    continue;
                u32 per = (u32)(S.scc.period[ch] & 0xFFFu) + 1u;
                if (per <= 9u)
                    continue;
                u32 p8 = per << 8;
                S.scc.phase[ch] += scc_step;
                while (S.scc.phase[ch] >= p8) {
                    S.scc.phase[ch] -= p8;
                    S.scc.pos[ch] = (S.scc.pos[ch] + 1u) & 31u;
                }
                const s8 *wv = S.scc.wave[ch < 4 ? ch : 3];
                mix += ((s32)wv[S.scc.pos[ch]] * (s32)(S.scc.vol[ch] & 15u)) * 3;
            }
        }

        /* 3. Yamaha YM2413 OPLL (MSX-MUSIC) */
        if (S.is_msx2) {
            static const u8 mult_tab[16] = {1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 20, 24, 24, 30, 30};
            S.opll.lfsr = (S.opll.lfsr >> 1) ^ ((S.opll.lfsr & 1u) ? 0x400181u : 0u);
            int rhythm = (S.opll.reg[0x0E] & 0x20u) != 0;
            int melody_ch = rhythm ? 6 : 9;
            for (int ch = 0; ch < melody_ch; ch++) {
                if (!S.opll.eg_state[ch])
                    continue;
                u8 r20 = S.opll.reg[0x20 + ch];
                u8 r30 = S.opll.reg[0x30 + ch];
                u32 fnum = (u32)S.opll.reg[0x10 + ch] | (((u32)r20 & 1u) << 8);
                u32 blk  = (r20 >> 1) & 7u;
                u8 inst  = (r30 >> 4) & 15u;
                u8 vol4  = r30 & 15u;

                u8 mm, mtl, fb, cm, ar, dr, sl, rr;
                if (inst == 0) {
                    mm  = S.opll.reg[0x00] & 15u;
                    cm  = S.opll.reg[0x01] & 15u;
                    mtl = S.opll.reg[0x02] & 63u;
                    fb  = S.opll.reg[0x03] & 7u;
                    ar  = (S.opll.reg[0x05] >> 4) & 15u;
                    dr  = S.opll.reg[0x05] & 15u;
                    sl  = (S.opll.reg[0x07] >> 4) & 15u;
                    rr  = S.opll.reg[0x07] & 15u;
                } else {
                    const u8 *p = opll_patches[inst];
                    mm = p[0]; mtl = p[1]; fb = p[2]; cm = p[3];
                    ar = p[4]; dr = p[5]; sl = p[6]; rr = p[7];
                }

                /* Envelope step */
                s16 lvl = S.opll.env_lvl[ch];
                u8 st = S.opll.eg_state[ch];
                if (st == 1) {          /* Attack */
                    lvl -= (s16)((ar + 2) * 2);
                    if (lvl <= 0) { lvl = 0; st = 2; }
                } else if (st == 2) {   /* Decay */
                    s16 sus_lvl = (s16)(sl * 32);
                    if (lvl < sus_lvl) lvl += (s16)((dr ? dr : 1));
                    if (lvl >= sus_lvl) { lvl = sus_lvl; st = 3; }
                } else if (st == 4) {   /* Release */
                    u8 rrate = (r20 & 0x20u) ? 3 : (rr ? rr : 2);
                    lvl += (s16)rrate;
                    if (lvl >= 511) { lvl = 511; st = 0; }
                }
                S.opll.env_lvl[ch] = lvl;
                S.opll.eg_state[ch] = st;

                u32 base_inc = (((fnum << blk) >> 1) * opll_base) >> 10;
                S.opll.mod_phase[ch] += (base_inc * mult_tab[mm]) >> 1;
                S.opll.car_phase[ch] += (base_inc * mult_tab[cm]) >> 1;

                s32 fb_off = fb ? ((s32)S.opll.prev_mod[ch] >> (9 - fb)) : 0;
                s16 mod_raw = opll_sin((S.opll.mod_phase[ch] >> 10) + (u32)fb_off);
                s32 mod_atten = (s32)mod_raw * (64 - (s32)mtl) >> 6;
                S.opll.prev_mod[ch] = (s16)mod_atten;

                s16 car_raw = opll_sin((S.opll.car_phase[ch] >> 10) + (u32)(mod_atten >> 5));
                s32 tot_att = (s32)lvl + (s32)vol4 * 28;
                if (tot_att < 512) {
                    s32 gain = 512 - tot_att;
                    mix += ((s32)car_raw * gain) >> 9;
                }
            }
            if (rhythm && (S.opll.reg[0x0E] & 0x1Fu)) {
                u8 rk = S.opll.reg[0x0E];
                if (rk & 0x10u) {       /* Bass drum */
                    S.opll.car_phase[6] += opll_base * 3u;
                    mix += (opll_sin(S.opll.car_phase[6] >> 10) * (15 - (S.opll.reg[0x36] & 15u))) >> 5;
                }
                if (rk & 0x0Du) {       /* Snare / Hi-Hat / Cymbal */
                    s32 n = (S.opll.lfsr & 1u) ? 900 : -900;
                    mix += (n * (15 - (S.opll.reg[0x37] & 15u))) >> 4;
                }
            }
        }

        if (mix > 32767) mix = 32767;
        if (mix < -32768) mix = -32768;
        if (S.audio_count < 4096)
            M->audio_ring[S.audio_count++] = (s16)mix;
    }
}

static void audio_catch_up(void)
{
    if (!S.sample_rate)
        return;
    s32 now = S.cpu.cycles;
    if (now > S.audio_last_cyc) {
        audio_step((u32)(now - S.audio_last_cyc));
        S.audio_last_cyc = now;
    }
}

static void opll_write_reg(u8 r, u8 v)
{
    if (r >= 64)
        return;
    audio_catch_up();
    S.opll.reg[r] = v;
    if (r >= 0x20u && r < 0x29u) {
        int ch = r - 0x20;
        u8 kon = (v & 0x10u) ? 1 : 0;
        if (kon && !S.opll.key_was[ch]) {
            S.opll.eg_state[ch] = 1;
            S.opll.env_lvl[ch] = 480;
            S.opll.mod_phase[ch] = 0;
            S.opll.car_phase[ch] = 0;
        } else if (!kon && S.opll.key_was[ch]) {
            if (S.opll.eg_state[ch])
                S.opll.eg_state[ch] = 4;
        }
        S.opll.key_was[ch] = kon;
    }
}

static void ay_write_reg(u8 r, u8 v)
{
    if (r >= 16)
        return;
    audio_catch_up();
    S.ay.reg[r] = v;
    if (r == 13) {
        S.ay.env_phase = 0;
        S.ay.env_step = 0;
        S.ay.env_hold = 0;
        S.ay.env_att = (v & 0x04u) ? 0x0Fu : 0x00u;
        S.ay.env_vol = S.ay.env_att ^ 0x0Fu;
    }
}

static u8 ay_read_reg(u8 r)
{
    if (r >= 16)
        return 0xFFu;
    if (r == 14) {                      /* Joystick Port A */
        if (S.ay.reg[15] & 0x40u)       /* Port 2 */
            return 0xFFu;
        u8 v = 0xFFu;
        if (S.pad_state & MSX_UP)    v &= (u8)~0x01u;
        if (S.pad_state & MSX_DOWN)  v &= (u8)~0x02u;
        if (S.pad_state & MSX_LEFT)  v &= (u8)~0x04u;
        if (S.pad_state & MSX_RIGHT) v &= (u8)~0x08u;
        if (S.pad_state & MSX_A)     v &= (u8)~0x10u;
        if (S.pad_state & MSX_B)     v &= (u8)~0x20u;
        return v;
    }
    return S.ay.reg[r];
}

/* ---- Yamaha V9938 & TMS9918A VDP ---- */
static inline int vdp_mode5(void)
{
    u8 r0 = S.vdp_reg[0], r1 = S.vdp_reg[1];
    int m1 = (r1 >> 4) & 1;
    int m2 = (r1 >> 3) & 1;
    int m3 = (r0 >> 1) & 1;
    int m4 = S.is_msx2 ? ((r0 >> 2) & 1) : 0;
    int m5 = S.is_msx2 ? ((r0 >> 3) & 1) : 0;
    return (m5 << 4) | (m4 << 3) | (m3 << 2) | (m2 << 1) | m1;
}

static inline int vdp_bpp(void)
{
    int m = vdp_mode5();
    if (m == 0x10) return 2;            /* G5 / SCREEN 6: 512px 2bpp */
    if (m == 0x1C) return 8;            /* G7 / SCREEN 8: 256px 8bpp */
    return 4;                           /* G4 / SCREEN 5 (256px) & G6 / SCREEN 7 (512px): 4bpp */
}

static inline int vdp_cmd_width(void)
{
    int m = vdp_mode5();
    return (m == 0x10 || m == 0x14) ? 512 : 256;
}

static u8 vdp_point_raw(int x, int y, int use_exp)
{
    u8 *mem = use_exp ? M->exp_vram : M->vram;
    u32 mask = use_exp ? 0xFFFFu : 0x1FFFFu;
    int m = vdp_mode5();
    y &= 0x3FF;
    if (m == 0x10) {                    /* SCREEN 6: 512 px, 2bpp, 128 B/line */
        x &= 511;
        u32 off = ((u32)y * 128u + (u32)(x >> 2)) & mask;
        int sh = (3 - (x & 3)) * 2;
        return (mem[off] >> sh) & 3u;
    }
    if (m == 0x14) {                    /* SCREEN 7: 512 px, 4bpp, 256 B/line */
        x &= 511;
        u32 off = ((u32)y * 256u + (u32)(x >> 1)) & mask;
        return (x & 1) ? (mem[off] & 15u) : (mem[off] >> 4);
    }
    if (m == 0x1C) {                    /* SCREEN 8: 256 px, 8bpp, 256 B/line */
        x &= 255;
        u32 off = ((u32)y * 256u + (u32)x) & mask;
        return mem[off];
    }
    /* Default SCREEN 5 (G4): 256 px, 4bpp, 128 B/line */
    x &= 255;
    u32 off = ((u32)y * 128u + (u32)(x >> 1)) & mask;
    return (x & 1) ? (mem[off] & 15u) : (mem[off] >> 4);
}

static void vdp_pset_raw(int x, int y, u8 src, u8 lop, int use_exp)
{
    int bpp = vdp_bpp();
    u8 pmask = (bpp == 2) ? 3u : (bpp == 8) ? 0xFFu : 15u;
    src &= pmask;
    if ((lop & 8u) && src == 0)         /* Transparent logical ops TIMP/TAND/TOR/TEOR/TNOT */
        return;

    u8 dst = vdp_point_raw(x, y, use_exp);
    u8 out = src;
    switch (lop & 7u) {
    case 0: out = src; break;                           /* IMP */
    case 1: out = dst & src; break;                     /* AND */
    case 2: out = dst | src; break;                     /* OR */
    case 3: out = dst ^ src; break;                     /* EOR */
    case 4: out = (u8)((~src) & pmask); break;          /* NOT */
    default: out = src; break;
    }

    u8 *mem = use_exp ? M->exp_vram : M->vram;
    u32 mask = use_exp ? 0xFFFFu : 0x1FFFFu;
    int m = vdp_mode5();
    y &= 0x3FF;
    if (m == 0x10) {
        x &= 511;
        u32 off = ((u32)y * 128u + (u32)(x >> 2)) & mask;
        int sh = (3 - (x & 3)) * 2;
        mem[off] = (u8)((mem[off] & ~(3u << sh)) | ((out & 3u) << sh));
    } else if (m == 0x14) {
        x &= 511;
        u32 off = ((u32)y * 256u + (u32)(x >> 1)) & mask;
        if (x & 1) mem[off] = (u8)((mem[off] & 0xF0u) | (out & 15u));
        else       mem[off] = (u8)((mem[off] & 0x0Fu) | ((out & 15u) << 4));
    } else if (m == 0x1C) {
        x &= 255;
        u32 off = ((u32)y * 256u + (u32)x) & mask;
        mem[off] = out;
    } else {
        x &= 255;
        u32 off = ((u32)y * 128u + (u32)(x >> 1)) & mask;
        if (x & 1) mem[off] = (u8)((mem[off] & 0xF0u) | (out & 15u));
        else       mem[off] = (u8)((mem[off] & 0x0Fu) | ((out & 15u) << 4));
    }
}

static u8 *vdp_byte_ptr(int x, int y, int use_exp)
{
    u8 *mem = use_exp ? M->exp_vram : M->vram;
    u32 mask = use_exp ? 0xFFFFu : 0x1FFFFu;
    int m = vdp_mode5();
    y &= 0x3FF;
    if (m == 0x10) return mem + (((u32)y * 128u + (u32)((x & 511) >> 2)) & mask);
    if (m == 0x14) return mem + (((u32)y * 256u + (u32)((x & 511) >> 1)) & mask);
    if (m == 0x1C) return mem + (((u32)y * 256u + (u32)(x & 255)) & mask);
    return mem + (((u32)y * 128u + (u32)((x & 255) >> 1)) & mask);
}

static void vdp_cmd_feed_cpu(u8 clr)
{
    if (!S.cmd.active)
        return;
    u8 arg = S.vdp_reg[45];
    int dix = (arg & 0x04u) ? -1 : 1;
    int diy = (arg & 0x08u) ? -1 : 1;
    int mxd = (arg & 0x20u) != 0;
    int wmax = vdp_cmd_width();

    if (S.cmd.op == 0x0Fu) {            /* HMMC: byte-packed write */
        int ppb = (vdp_bpp() == 2) ? 4 : (vdp_bpp() == 8) ? 1 : 2;
        int x = ((int)S.cmd.dx + (int)S.cmd.cx * dix) & (wmax - 1);
        int y = ((int)S.cmd.dy + (int)S.cmd.cy * diy) & 0x3FF;
        *vdp_byte_ptr(x, y, mxd) = clr;
        S.cmd.cx = (u16)(S.cmd.cx + ppb);
        if (S.cmd.cx >= S.cmd.nx) {
            S.cmd.cx = 0;
            S.cmd.cy++;
            if (S.cmd.cy >= S.cmd.ny) {
                S.cmd.active = 0;
                S.vdp_stat[2] &= (u8)~0x81u;    /* clear TR & CE */
                return;
            }
        }
        S.vdp_stat[2] |= 0x81u;                 /* TR | CE */
    } else if (S.cmd.op == 0x0Bu) {     /* LMMC: 1 pixel per R#44 write */
        int x = ((int)S.cmd.dx + (int)S.cmd.cx * dix) & (wmax - 1);
        int y = ((int)S.cmd.dy + (int)S.cmd.cy * diy) & 0x3FF;
        vdp_pset_raw(x, y, clr, S.cmd.lop, mxd);
        S.cmd.cx++;
        if (S.cmd.cx >= S.cmd.nx) {
            S.cmd.cx = 0;
            S.cmd.cy++;
            if (S.cmd.cy >= S.cmd.ny) {
                S.cmd.active = 0;
                S.vdp_stat[2] &= (u8)~0x81u;
                return;
            }
        }
        S.vdp_stat[2] |= 0x81u;
    }
}

static void vdp_cmd_exec(u8 cmr)
{
    u8 op = cmr >> 4;
    u8 lop = cmr & 0x0Fu;
    u8 arg = S.vdp_reg[45];
    int dix = (arg & 0x04u) ? -1 : 1;
    int diy = (arg & 0x08u) ? -1 : 1;
    int mxs = (arg & 0x10u) != 0;
    int mxd = (arg & 0x20u) != 0;
    int wmax = vdp_cmd_width();
    int ppb = (vdp_bpp() == 2) ? 4 : (vdp_bpp() == 8) ? 1 : 2;

    u16 sx = (u16)(S.vdp_reg[32] | (((u16)S.vdp_reg[33] & 1u) << 8));
    u16 sy = (u16)(S.vdp_reg[34] | (((u16)S.vdp_reg[35] & 3u) << 8));
    u16 dx = (u16)(S.vdp_reg[36] | (((u16)S.vdp_reg[37] & 1u) << 8));
    u16 dy = (u16)(S.vdp_reg[38] | (((u16)S.vdp_reg[39] & 3u) << 8));
    u16 nx = (u16)(S.vdp_reg[40] | (((u16)S.vdp_reg[41] & 1u) << 8));
    u16 ny = (u16)(S.vdp_reg[42] | (((u16)S.vdp_reg[43] & 3u) << 8));
    u8 clr = S.vdp_reg[44];

    S.cmd.active = 0;
    S.vdp_stat[2] &= (u8)~0x91u;        /* clear TR, BD, CE */

    if (op == 0x00u)                    /* STOP */
        return;

    u16 w_nx = nx ? nx : (u16)wmax;
    u16 w_ny = ny ? ny : 1024u;

    switch (op) {
    case 0x04:                          /* POINT */
        S.vdp_stat[7] = vdp_point_raw(sx, sy, mxs);
        S.vdp_reg[44] = S.vdp_stat[7];
        break;
    case 0x05:                          /* PSET */
        vdp_pset_raw(dx, dy, clr, lop, mxd);
        break;
    case 0x06: {                        /* SRCH */
        int eq = (arg & 0x02u) != 0;    /* 0: find == CLR; 1: find != CLR */
        int pmask = (vdp_bpp() == 2) ? 3 : (vdp_bpp() == 8) ? 255 : 15;
        u8 target = clr & (u8)pmask;
        int x = sx & (wmax - 1);
        while (x >= 0 && x < wmax) {
            u8 p = vdp_point_raw(x, sy, mxs);
            if (eq ? (p != target) : (p == target)) {
                S.vdp_stat[2] |= 0x10u; /* BD = found */
                S.vdp_stat[3] = (u8)x;
                S.vdp_stat[4] = (u8)(0xFEu | ((x >> 8) & 1u));
                break;
            }
            x += dix;
        }
        break;
    }
    case 0x07: {                        /* LINE (Maj = nx, Min = ny, MAJ bit 0 of R#45) */
        int maj = nx;
        int min = ny;
        int maj_y = (arg & 0x01u) != 0;
        int x = dx, y = dy;
        int e = 2 * min - maj;
        for (int i = 0; i <= maj; i++) {
            vdp_pset_raw(x & (wmax - 1), y & 0x3FF, clr, lop, mxd);
            if (e >= 0) {
                if (maj_y) x += dix;
                else       y += diy;
                e -= 2 * maj;
            }
            if (maj_y) y += diy;
            else       x += dix;
            e += 2 * min;
        }
        break;
    }
    case 0x08:                          /* LMMV */
        for (u32 ry = 0; ry < w_ny; ry++) {
            int y = ((int)dy + (int)ry * diy) & 0x3FF;
            for (u32 rx = 0; rx < w_nx; rx++) {
                int x = ((int)dx + (int)rx * dix) & (wmax - 1);
                vdp_pset_raw(x, y, clr, lop, mxd);
            }
        }
        break;
    case 0x09:                          /* LMMM */
        for (u32 ry = 0; ry < w_ny; ry++) {
            int y_s = ((int)sy + (int)ry * diy) & 0x3FF;
            int y_d = ((int)dy + (int)ry * diy) & 0x3FF;
            for (u32 rx = 0; rx < w_nx; rx++) {
                int x_s = ((int)sx + (int)rx * dix) & (wmax - 1);
                int x_d = ((int)dx + (int)rx * dix) & (wmax - 1);
                u8 c = vdp_point_raw(x_s, y_s, mxs);
                vdp_pset_raw(x_d, y_d, c, lop, mxd);
            }
        }
        break;
    case 0x0A:                          /* LMCM (VRAM -> CPU via S#7) */
        S.cmd.active = 1;
        S.cmd.op = op;
        S.cmd.lop = lop;
        S.cmd.sx = sx; S.cmd.sy = sy;
        S.cmd.nx = w_nx; S.cmd.ny = w_ny;
        S.cmd.cx = 0; S.cmd.cy = 0;
        S.vdp_stat[7] = vdp_point_raw(sx, sy, mxs);
        S.vdp_stat[2] |= 0x81u;         /* TR | CE */
        break;
    case 0x0B:                          /* LMMC (CPU -> VRAM via R#44, first pixel in R#44!) */
        S.cmd.active = 1;
        S.cmd.op = op;
        S.cmd.lop = lop;
        S.cmd.dx = dx; S.cmd.dy = dy;
        S.cmd.nx = w_nx; S.cmd.ny = w_ny;
        S.cmd.cx = 0; S.cmd.cy = 0;
        vdp_cmd_feed_cpu(clr);
        break;
    case 0x0C:                          /* HMMV */
        for (u32 ry = 0; ry < w_ny; ry++) {
            int y = ((int)dy + (int)ry * diy) & 0x3FF;
            for (u32 rx = 0; rx < w_nx; rx += (u32)ppb) {
                int x = ((int)dx + (int)rx * dix) & (wmax - 1);
                *vdp_byte_ptr(x, y, mxd) = clr;
            }
        }
        break;
    case 0x0D:                          /* HMMM */
        for (u32 ry = 0; ry < w_ny; ry++) {
            int y_s = ((int)sy + (int)ry * diy) & 0x3FF;
            int y_d = ((int)dy + (int)ry * diy) & 0x3FF;
            for (u32 rx = 0; rx < w_nx; rx += (u32)ppb) {
                int x_s = ((int)sx + (int)rx * dix) & (wmax - 1);
                int x_d = ((int)dx + (int)rx * dix) & (wmax - 1);
                *vdp_byte_ptr(x_d, y_d, mxd) = *vdp_byte_ptr(x_s, y_s, mxs);
            }
        }
        break;
    case 0x0E: {                        /* YMMM (from DX to right/left edge) */
        int span = (dix > 0) ? (wmax - (dx & (wmax - 1))) : ((dx & (wmax - 1)) + ppb);
        for (u32 ry = 0; ry < w_ny; ry++) {
            int y_s = ((int)sy + (int)ry * diy) & 0x3FF;
            int y_d = ((int)dy + (int)ry * diy) & 0x3FF;
            for (int rx = 0; rx < span; rx += ppb) {
                int x = ((int)dx + rx * dix) & (wmax - 1);
                *vdp_byte_ptr(x, y_d, mxd) = *vdp_byte_ptr(x, y_s, mxd);
            }
        }
        break;
    }
    case 0x0F:                          /* HMMC (CPU -> VRAM, first byte in R#44!) */
        S.cmd.active = 1;
        S.cmd.op = op;
        S.cmd.lop = lop;
        S.cmd.dx = dx; S.cmd.dy = dy;
        S.cmd.nx = w_nx; S.cmd.ny = w_ny;
        S.cmd.cx = 0; S.cmd.cy = 0;
        vdp_cmd_feed_cpu(clr);
        break;
    }
}

static void vdp_update_irq(void)
{
    int vb_irq = (S.vdp_stat[0] & 0x80u) && (S.vdp_reg[1] & 0x20u);
    int hb_irq = S.is_msx2 && (S.vdp_stat[1] & 0x01u) && (S.vdp_reg[0] & 0x10u);
    S.cpu.irq = (u8)((vb_irq || hb_irq) ? 1 : 0);
}

static u32 vdp_vram_mask(void)
{
    return S.is_msx2 ? 0x1FFFFu : 0x3FFFu;
}

static void vdp_write_reg(u8 r, u8 v)
{
    r &= S.is_msx2 ? 0x3Fu : 0x07u;
    S.vdp_reg[r] = v;
    if (r == 14 && S.is_msx2)
        S.vdp_addr = (S.vdp_addr & 0x3FFFu) | (((u32)(v & 7u)) << 14);
    else if (r == 16 && S.is_msx2)
        S.pal_first = 0;
    else if (r == 44 && S.is_msx2 && S.cmd.active)
        vdp_cmd_feed_cpu(v);
    else if (r == 46 && S.is_msx2)
        vdp_cmd_exec(v);
    if (r == 0 || r == 1)
        vdp_update_irq();
}

static void vdp_data_write(u8 v)
{
    u32 mask = vdp_vram_mask();
    S.vdp_first = 0;
    if (S.is_msx2 && (S.vdp_reg[45] & 0x40u))
        M->exp_vram[S.vdp_addr & 0xFFFFu] = v;
    else
        M->vram[S.vdp_addr & mask] = v;
    S.vdp_buf = v;
    S.vdp_addr = (S.vdp_addr + 1u) & mask;
    if (S.is_msx2)
        S.vdp_reg[14] = (u8)((S.vdp_addr >> 14) & 7u);
}

static u8 vdp_data_read(void)
{
    u32 mask = vdp_vram_mask();
    u8 v = S.vdp_buf;
    S.vdp_first = 0;
    if (S.is_msx2 && (S.vdp_reg[45] & 0x40u))
        S.vdp_buf = M->exp_vram[S.vdp_addr & 0xFFFFu];
    else
        S.vdp_buf = M->vram[S.vdp_addr & mask];
    S.vdp_addr = (S.vdp_addr + 1u) & mask;
    if (S.is_msx2)
        S.vdp_reg[14] = (u8)((S.vdp_addr >> 14) & 7u);
    return v;
}

static void vdp_ctrl_write(u8 v)
{
    if (!S.vdp_first) {
        S.vdp_first = 1;
        S.vdp_latch = v;
        return;
    }
    S.vdp_first = 0;
    if (v & 0x80u) {
        vdp_write_reg(v & 0x3Fu, S.vdp_latch);
    } else {
        u32 hi = S.is_msx2 ? (((u32)(S.vdp_reg[14] & 7u)) << 14) : 0u;
        S.vdp_addr = hi | (((u32)(v & 0x3Fu)) << 8) | S.vdp_latch;
        if (!(v & 0x40u))
            (void)vdp_data_read();
    }
}

static u8 vdp_status_read(void)
{
    S.vdp_first = 0;
    u8 sr = S.is_msx2 ? (S.vdp_reg[15] & 0x0Fu) : 0u;
    u8 v = S.vdp_stat[sr];
    if (sr == 0) {
        S.vdp_stat[0] &= 0x1Fu;
        vdp_update_irq();
    } else if (sr == 1) {
        S.vdp_stat[1] &= (u8)~0x01u;
        vdp_update_irq();
    } else if (sr == 2) {
        S.vdp_stat[2] ^= 0x20u;         /* Toggle HR so tight HBlank poll loops never stall */
    } else if (sr == 7 && S.cmd.active && S.cmd.op == 0x0Au) {
        u8 arg = S.vdp_reg[45];
        int dix = (arg & 0x04u) ? -1 : 1;
        int diy = (arg & 0x08u) ? -1 : 1;
        int mxs = (arg & 0x10u) != 0;
        int wmax = vdp_cmd_width();
        S.cmd.cx++;
        if (S.cmd.cx >= S.cmd.nx) {
            S.cmd.cx = 0;
            S.cmd.cy++;
            if (S.cmd.cy >= S.cmd.ny) {
                S.cmd.active = 0;
                S.vdp_stat[2] &= (u8)~0x81u;
                return v;
            }
        }
        int x = ((int)S.cmd.sx + (int)S.cmd.cx * dix) & (wmax - 1);
        int y = ((int)S.cmd.sy + (int)S.cmd.cy * diy) & 0x3FF;
        S.vdp_stat[7] = vdp_point_raw(x, y, mxs);
    }
    return v;
}

static void vdp_pal_write(u8 v)
{
    if (!S.is_msx2)
        return;
    if (!S.pal_first) {
        S.pal_first = 1;
        S.pal_latch = v;
        return;
    }
    S.pal_first = 0;
    u8 idx = S.vdp_reg[16] & 15u;
    u8 r3 = (S.pal_latch >> 4) & 7u;
    u8 b3 = S.pal_latch & 7u;
    u8 g3 = v & 7u;
    S.pal_rgb333[idx][0] = r3;
    S.pal_rgb333[idx][1] = g3;
    S.pal_rgb333[idx][2] = b3;
    S.pal[idx] = pack_rgb333(r3, g3, b3);
    S.vdp_reg[16] = (u8)((idx + 1u) & 15u);
}

static void vdp_ind_write(u8 v)
{
    if (!S.is_msx2)
        return;
    u8 r = S.vdp_reg[17] & 0x3Fu;
    if (r != 17u)
        vdp_write_reg(r, v);
    if (!(S.vdp_reg[17] & 0x80u))
        S.vdp_reg[17] = (u8)((r + 1u) & 0x3Fu);
}

/* ---- RAM Mapper & Expanded Slot Memory Mapping ---- */
static inline u8 *mapper_bank_ptr(int cpu_page)
{
    u32 pg = S.is_msx2 ? (S.mapper_page[cpu_page & 3] & 15u) : (u32)(cpu_page & 3);
    return M->ram + pg * 0x4000u;
}

static inline u8 sys_rd8(u16 a)
{
    return mapper_bank_ptr(a >> 14)[a & 0x3FFFu];
}

static inline void sys_wr8(u16 a, u8 v)
{
    mapper_bank_ptr(a >> 14)[a & 0x3FFFu] = v;
}

static u8 *slot1_1k_ptr(int page1k)
{
    u32 a = (u32)page1k << 10;
    if (!S.has_cart || !S.rom || !S.rom_size)
        return M->open_bus;
    if (S.mapper == MAP_PLAIN) {
        if (S.rom_size <= 0x4000u) {
            if (a >= 0x4000u && a < 0xC000u)
                return S.rom + ((a - 0x4000u) % S.rom_size);
            return M->open_bus;
        }
        if (a >= S.cart_base && a - S.cart_base < S.rom_size)
            return S.rom + (a - S.cart_base);
        return M->open_bus;
    }
    if (a < 0x4000u || a >= 0xC000u)
        return M->open_bus;
    if (S.mapper == MAP_ASCII16 || S.mapper == MAP_GENERIC16) {
        int win = (a >= 0x8000u) ? 1 : 0;
        u32 b = S.bank[win] % S.banks16k;
        return S.rom + b * 0x4000u + (a & 0x3FFFu);
    }
    int win = (int)((a - 0x4000u) >> 13);
    if (win == 2 && S.mapper == MAP_KONAMI_SCC && S.scc_mapped && a >= 0x9800u && a < 0xA000u)
        return 0;
    u32 b = S.bank[win] % S.banks8k;
    return S.rom + b * 0x2000u + (a & 0x1FFFu);
}

static void rebuild_map(void)
{
    for (int i = 0; i < 64; i++) {
        int pg = i >> 4;
        int slot = (S.ppi_a >> (pg * 2)) & 3;
        S.cpu.rd[i] = M->open_bus;
        S.cpu.wr[i] = 0;
        S.cpu.op[i] = 0;
        if (slot == 0) {                /* Main BIOS ($0000..$7FFF) */
            if (i < 32)
                S.cpu.rd[i] = M->bios + i * 0x400;
        } else if (slot == 1) {         /* Cartridge */
            S.cpu.rd[i] = slot1_1k_ptr(i);
        } else if (slot == 2) {         /* MSX-MUSIC (YM2413 ROM in $4000..$7FFF on MSX2) */
            if (S.is_msx2 && i >= 16 && i < 32)
                S.cpu.rd[i] = M->fmrom + (i - 16) * 0x400;
        } else if (slot == 3) {
            if (!S.is_msx2) {
                S.cpu.rd[i] = M->ram + i * 0x400;
                S.cpu.wr[i] = M->ram + i * 0x400;
            } else {
                int sub = (S.slot3_sub >> (pg * 2)) & 3;
                if (sub == 0) {         /* 3-0: 256 KB Memory Mapper RAM */
                    u8 *base = mapper_bank_ptr(pg) + (i & 15) * 0x400;
                    S.cpu.rd[i] = base;
                    S.cpu.wr[i] = base;
                } else if (sub == 1) {  /* 3-1: MSX2 Sub-ROM ($0000..$3FFF) */
                    if (i < 16)
                        S.cpu.rd[i] = M->subrom + i * 0x400;
                } else if (sub == 2) {  /* 3-2: Disk ROM ($4000..$7FFF) */
                    if (S.has_dsk && i >= 16 && i < 32)
                        S.cpu.rd[i] = M->diskrom + (i - 16) * 0x400;
                }
                /* Intercept $FC00..$FFFF so $FFFF reads/writes secondary slot register! */
                if (i == 63) {
                    S.cpu.rd[63] = 0;
                    S.cpu.wr[63] = 0;
                }
            }
        }
    }
}

/* Slot ID format: bit 7 = expanded; bits 1..0 = primary; bits 3..2 = secondary */
static u8 slot_read_byte(u8 slot_id, u16 a)
{
    int pri = slot_id & 3;
    int pg = a >> 14;
    if (pri == 0) return a < 0x8000u ? M->bios[a] : 0xFFu;
    if (pri == 1) {
        u8 *p = slot1_1k_ptr(a >> 10);
        return p ? p[a & 0x3FFu] : 0xFFu;
    }
    if (pri == 2) {
        if (S.is_msx2 && a >= 0x4000u && a < 0x8000u)
            return M->fmrom[a - 0x4000u];
        return 0xFFu;
    }
    if (!S.is_msx2)
        return M->ram[a];
    if (a == 0xFFFFu)
        return (u8)~S.slot3_sub;
    int sub = (slot_id & 0x80u) ? ((slot_id >> 2) & 3) : ((S.slot3_sub >> (pg * 2)) & 3);
    if (sub == 0) return mapper_bank_ptr(pg)[a & 0x3FFFu];
    if (sub == 1) return a < 0x4000u ? M->subrom[a] : 0xFFu;
    if (sub == 2) return (S.has_dsk && a >= 0x4000u && a < 0x8000u) ? M->diskrom[a - 0x4000u] : 0xFFu;
    return 0xFFu;
}

static u8 scc_read(u16 a)
{
    u16 off = a & 0xFFu;
    if (off < 0x80u) {
        int ch = off >> 5;
        return (u8)S.scc.wave[ch][off & 31u];
    }
    if (off >= 0xA0u && off < 0xC0u)
        return (u8)S.scc.wave[3][off & 31u];
    return 0xFFu;
}

static void scc_write(u16 a, u8 v)
{
    audio_catch_up();
    u16 off = a & 0xFFu;
    if (off < 0x80u) {
        int ch = off >> 5;
        S.scc.wave[ch][off & 31u] = (s8)v;
        if (ch == 3)
            S.scc.wave[4][off & 31u] = (s8)v;
    } else if (off >= 0x80u && off < 0x8Au) {
        int ch = (off - 0x80u) >> 1;
        if (off & 1u)
            S.scc.period[ch] = (u16)((S.scc.period[ch] & 0x0FFu) | (((u16)v & 0x0Fu) << 8));
        else
            S.scc.period[ch] = (u16)((S.scc.period[ch] & 0xF00u) | v);
    } else if (off >= 0x8Au && off < 0x8Fu) {
        S.scc.vol[off - 0x8Au] = v & 0x0Fu;
    } else if (off == 0x8Fu) {
        S.scc.enable = v & 0x1Fu;
    }
}

static void slot_write_byte(u8 slot_id, u16 a, u8 v)
{
    int pri = slot_id & 3;
    int pg = a >> 14;
    if (pri == 3) {
        if (!S.is_msx2) {
            M->ram[a] = v;
            return;
        }
        if (a == 0xFFFFu) {
            S.slot3_sub = v;
            rebuild_map();
            return;
        }
        int sub = (slot_id & 0x80u) ? ((slot_id >> 2) & 3) : ((S.slot3_sub >> (pg * 2)) & 3);
        if (sub == 0)
            mapper_bank_ptr(pg)[a & 0x3FFFu] = v;
        return;
    }
    if (pri != 1 || !S.has_cart || S.mapper == MAP_PLAIN)
        return;

    switch (S.mapper) {
    case MAP_KONAMI4:
        if (a >= 0x6000u && a < 0x8000u)      { S.bank[1] = v; rebuild_map(); }
        else if (a >= 0x8000u && a < 0xA000u) { S.bank[2] = v; rebuild_map(); }
        else if (a >= 0xA000u && a < 0xC000u) { S.bank[3] = v; rebuild_map(); }
        break;
    case MAP_GENERIC8:
        if (a >= 0x4000u && a < 0xC000u) {
            S.bank[(a - 0x4000u) >> 13] = v;
            rebuild_map();
        }
        break;
    case MAP_KONAMI_SCC:
        if (a >= 0x5000u && a < 0x5800u)      { S.bank[0] = v; rebuild_map(); }
        else if (a >= 0x7000u && a < 0x7800u) { S.bank[1] = v; rebuild_map(); }
        else if (a >= 0x9000u && a < 0x9800u) {
            S.bank[2] = v;
            S.scc_mapped = (u8)(((v & 0x3Fu) == 0x3Fu) ? 1 : 0);
            rebuild_map();
        } else if (S.scc_mapped && a >= 0x9800u && a < 0xA000u) {
            scc_write(a, v);
        } else if (a >= 0xB000u && a < 0xB800u) {
            S.bank[3] = v;
            rebuild_map();
        }
        break;
    case MAP_ASCII8:
        if (a >= 0x6000u && a < 0x8000u) {
            S.bank[(a - 0x6000u) >> 11] = v;
            rebuild_map();
        }
        break;
    case MAP_ASCII16:
        if (a >= 0x6000u && a < 0x6800u)      { S.bank[0] = v; rebuild_map(); }
        else if (a >= 0x7000u && a < 0x7800u) { S.bank[1] = v; rebuild_map(); }
        break;
    case MAP_GENERIC16:
        if (a >= 0x4000u && a < 0x8000u)      { S.bank[0] = v; rebuild_map(); }
        else if (a >= 0x8000u && a < 0xC000u) { S.bank[1] = v; rebuild_map(); }
        break;
    }
}

static inline u8 mem_rd8(u16 a)
{
    u8 *p = S.cpu.rd[a >> 10];
    if (p)
        return p[a & 0x3FFu];
    int slot = (S.ppi_a >> ((a >> 14) * 2)) & 3;
    if (slot == 1 && S.mapper == MAP_KONAMI_SCC && S.scc_mapped && a >= 0x9800u && a < 0xA000u)
        return scc_read(a);
    if (slot == 3 && S.is_msx2) {
        if (a == 0xFFFFu)
            return (u8)~S.slot3_sub;
        int sub = (S.slot3_sub >> 6) & 3;
        if (sub == 0)
            return mapper_bank_ptr(3)[a & 0x3FFFu];
    }
    return 0xFFu;
}

static inline void mem_wr8(u16 a, u8 v)
{
    u8 *p = S.cpu.wr[a >> 10];
    if (p) {
        p[a & 0x3FFu] = v;
        return;
    }
    int slot = (S.ppi_a >> ((a >> 14) * 2)) & 3;
    slot_write_byte((u8)slot, a, v);
}

static u8 cpu_read(struct z80 *c, u16 a)
{
    (void)c;
    return mem_rd8(a);
}

static void cpu_write(struct z80 *c, u16 a, u8 v)
{
    (void)c;
    mem_wr8(a, v);
}

/* ---- MSX 11-row keyboard matrix ---- */
static void kbd_press_rc(u8 rows[11], int r, int bit)
{
    if ((unsigned)r < 11u)
        rows[r] &= (u8)~(1u << bit);
}

static void kbd_press_ascii(u8 rows[11], char ch)
{
    if (ch >= '0' && ch <= '7') { kbd_press_rc(rows, 0, ch - '0'); return; }
    if (ch == '8' || ch == '9') { kbd_press_rc(rows, 1, ch - '8'); return; }
    if (ch >= 'a' && ch <= 'z') ch = (char)(ch - 32);
    if (ch >= 'A' && ch <= 'Z') {
        int idx = ch - 'A';
        if (idx < 2)       kbd_press_rc(rows, 2, 6 + idx);
        else if (idx < 10) kbd_press_rc(rows, 3, idx - 2);
        else if (idx < 18) kbd_press_rc(rows, 4, idx - 10);
        else               kbd_press_rc(rows, 5, idx - 18);
        return;
    }
    if (ch == ' ')  kbd_press_rc(rows, 8, 0);
    if (ch == '\r' || ch == '\n') kbd_press_rc(rows, 7, 7);
    if (ch == '\b') kbd_press_rc(rows, 7, 5);
    if (ch == '\t') kbd_press_rc(rows, 7, 3);
}

void msx_keys_from_hid(const u8 *usages, int n)
{
    for (int i = 0; i < 11; i++)
        S.kbd_hid[i] = 0xFFu;
    for (int i = 0; i < n; i++) {
        u8 u = usages[i];
        if (u >= 0x04 && u <= 0x1D)       kbd_press_ascii(S.kbd_hid, (char)('A' + (u - 0x04)));
        else if (u >= 0x1E && u <= 0x26)  kbd_press_ascii(S.kbd_hid, (char)('1' + (u - 0x1E)));
        else if (u == 0x27)               kbd_press_ascii(S.kbd_hid, '0');
        else if (u == 0x28) kbd_press_rc(S.kbd_hid, 7, 7);
        else if (u == 0x2A) kbd_press_rc(S.kbd_hid, 7, 5);
        else if (u == 0x2B) kbd_press_rc(S.kbd_hid, 7, 3);
        else if (u == 0x2C) kbd_press_rc(S.kbd_hid, 8, 0);
        else if (u == 0x3A) kbd_press_rc(S.kbd_hid, 6, 5);
        else if (u == 0x3B) kbd_press_rc(S.kbd_hid, 6, 6);
        else if (u == 0x3C) kbd_press_rc(S.kbd_hid, 6, 7);
        else if (u == 0x3D) kbd_press_rc(S.kbd_hid, 7, 0);
        else if (u == 0x3E) kbd_press_rc(S.kbd_hid, 7, 1);
        else if (u == 0x4F) kbd_press_rc(S.kbd_hid, 8, 7);
        else if (u == 0x50) kbd_press_rc(S.kbd_hid, 8, 4);
        else if (u == 0x51) kbd_press_rc(S.kbd_hid, 8, 6);
        else if (u == 0x52) kbd_press_rc(S.kbd_hid, 8, 5);
        else if (u == 0xE1 || u == 0xE5) kbd_press_rc(S.kbd_hid, 6, 0);
        else if (u == 0xE0 || u == 0xE4) kbd_press_rc(S.kbd_hid, 6, 1);
        else if (u == 0xE2 || u == 0xE6) kbd_press_rc(S.kbd_hid, 6, 2);
    }
}

void msx_type(char c)
{
    S.typed_ch = c;
    S.typed_frames = 6;
}

static void update_kbd_rows(void)
{
    for (int i = 0; i < 11; i++)
        S.kbd_row[i] = S.kbd_hid[i];
    if (S.pad_state & MSX_A)      kbd_press_rc(S.kbd_row, 8, 0);
    if (S.pad_state & MSX_B)      kbd_press_ascii(S.kbd_row, 'M');
    if (S.pad_state & MSX_START)  { kbd_press_rc(S.kbd_row, 7, 7); kbd_press_rc(S.kbd_row, 6, 5); }
    if (S.pad_state & MSX_SELECT) { kbd_press_rc(S.kbd_row, 7, 6); kbd_press_rc(S.kbd_row, 6, 6); }
    if (S.pad_state & MSX_LEFT)   kbd_press_rc(S.kbd_row, 8, 4);
    if (S.pad_state & MSX_UP)     kbd_press_rc(S.kbd_row, 8, 5);
    if (S.pad_state & MSX_DOWN)   kbd_press_rc(S.kbd_row, 8, 6);
    if (S.pad_state & MSX_RIGHT)  kbd_press_rc(S.kbd_row, 8, 7);
    if (S.typed_frames) {
        kbd_press_ascii(S.kbd_row, S.typed_ch);
        S.typed_frames--;
    }
}

/* ---- Palette Init (TMS9918A & V9938) ---- */
static void vdp_init_palettes(void)
{
    static const u8 tms_rgb[16][3] = {
        {0x00, 0x00, 0x00}, {0x00, 0x00, 0x00}, {0x21, 0xC8, 0x42}, {0x5E, 0xDC, 0x78},
        {0x54, 0x55, 0xED}, {0x7D, 0x76, 0xFC}, {0xD4, 0x52, 0x4D}, {0x42, 0xEB, 0xF5},
        {0xFC, 0x55, 0x54}, {0xFF, 0x79, 0x78}, {0xD4, 0xC1, 0x54}, {0xE6, 0xCE, 0x80},
        {0x21, 0xB0, 0x3B}, {0xC9, 0x5B, 0xBA}, {0xCC, 0xCC, 0xCC}, {0xFF, 0xFF, 0xFF}
    };
    static const u8 v9938_def[16][3] = {    /* R, G, B in 3-bit 0..7 */
        {0,0,0}, {0,0,0}, {1,6,1}, {3,7,3}, {1,1,7}, {2,3,7}, {5,1,1}, {2,6,7},
        {7,1,1}, {7,3,3}, {6,6,1}, {6,6,4}, {1,4,1}, {6,2,5}, {5,5,5}, {7,7,7}
    };
    static const u8 spr8_def[16][3] = {     /* Fixed V9938 SCREEN 8 sprite RGB333 */
        {0,0,0}, {0,0,2}, {3,0,0}, {3,0,2}, {0,3,0}, {0,3,2}, {3,3,0}, {3,3,2},
        {7,4,2}, {0,0,7}, {7,0,0}, {7,0,7}, {0,7,0}, {0,7,7}, {7,7,0}, {7,7,7}
    };
    for (int i = 0; i < 16; i++) {
        if (S.is_msx2) {
            S.pal_rgb333[i][0] = v9938_def[i][0];
            S.pal_rgb333[i][1] = v9938_def[i][1];
            S.pal_rgb333[i][2] = v9938_def[i][2];
            S.pal[i] = pack_rgb333(v9938_def[i][0], v9938_def[i][1], v9938_def[i][2]);
        } else {
            S.pal[i] = (u16)((tms_rgb[i][0] >> 3) | ((tms_rgb[i][1] >> 3) << 5) | ((tms_rgb[i][2] >> 3) << 10));
        }
        S.spr8_pal[i] = pack_rgb333(spr8_def[i][0], spr8_def[i][1], spr8_def[i][2]);
    }
    for (int c = 0; c < 256; c++) {
        /* SCREEN 8: GGGRRRBB */
        u32 g5 = (((u32)((c >> 5) & 7)) * 31u + 3u) / 7u;
        u32 r5 = (((u32)((c >> 2) & 7)) * 31u + 3u) / 7u;
        u32 b5 = (((u32)(c & 3)) * 31u + 1u) / 3u;
        S.pal256[c] = (u16)(r5 | (g5 << 5) | (b5 << 10));
    }
}

/* ---- Clean-room HLE MSX1 / MSX2 Main BIOS + Sub-ROM + Disk ROM ---- */
static void hle_vdp_reg(u8 r, u8 val)
{
    if (r < 8u)
        sys_wr8((u16)(0xF3DFu + r), val);
    else if (r < 24u)
        sys_wr8((u16)(0xFFE7u + (r - 8u)), val);
    else if (r >= 25u && r < 28u)
        sys_wr8((u16)(0xFFFAu + (r - 25u)), val);
    vdp_write_reg(r, val);
}

static void hle_set_u16(u16 addr, u16 val)
{
    sys_wr8(addr, (u8)val);
    sys_wr8((u16)(addr + 1u), (u8)(val >> 8));
}

static void hle_load_font(u32 pat_base)
{
    u32 mask = vdp_vram_mask();
    for (u32 i = 0; i < 2048u; i++)
        M->vram[(pat_base + i) & mask] = 0;
    for (u32 ch = 0; ch < 96u; ch++)
        for (u32 r = 0; r < 8u; r++)
            M->vram[(pat_base + 0x100u + ch * 8u + r) & mask] = M->bios[0x1CBFu + ch * 8u + r];
}

static void hle_chgclr(void)
{
    u8 fg = sys_rd8(0xF3E9u) & 15u;
    u8 bg = sys_rd8(0xF3EAu) & 15u;
    u8 bd = sys_rd8(0xF3EBu) & 15u;
    u8 mode = sys_rd8(0xFCAFu);
    if (mode == 0) {
        hle_vdp_reg(7, (u8)((fg << 4) | bg));
    } else {
        hle_vdp_reg(7, (u8)((fg << 4) | bd));
        if (mode == 1) {
            u16 col_base = (u16)(sys_rd8(0xF3F6u) | ((u16)sys_rd8(0xF3F7u) << 8));
            for (int i = 0; i < 32; i++)
                M->vram[(col_base + i) & 0x3FFFu] = (u8)((fg << 4) | bg);
        }
    }
}

static void hle_setmod_regs(u8 mode)
{
    sys_wr8(0xFCAFu, mode);
    if (S.is_msx2) {
        hle_vdp_reg(8, 0x08u);          /* VR=1 (64Kbit chips), sprites on */
        hle_vdp_reg(9, (u8)(S.vdp_reg[9] & 0x80u));
        hle_vdp_reg(10, 0x00u);
        hle_vdp_reg(11, 0x00u);
    }
    if (mode == 0) {
        u8 wid = sys_rd8(0xF3AEu);      /* LINL40 */
        if (S.is_msx2 && wid > 40) {    /* Text 2 (80 cols) */
            sys_wr8(0xF3B0u, 80);
            hle_vdp_reg(0, 0x04u);      /* M4=1 */
            hle_vdp_reg(1, 0xF0u);      /* M1=1 */
            hle_vdp_reg(2, 0x03u);      /* Name at $0000 */
            hle_vdp_reg(3, 0x27u);      /* Blink at $0800 */
            hle_vdp_reg(4, 0x02u);      /* Pattern at $1000 */
        } else {
            sys_wr8(0xF3B0u, 40);
            hle_vdp_reg(0, 0x00u);
            hle_vdp_reg(1, 0xF0u);
            hle_vdp_reg(2, 0x00u);
            hle_vdp_reg(4, 0x01u);
        }
    } else if (mode == 1) {
        sys_wr8(0xF3B0u, 32);
        hle_vdp_reg(0, 0x00u); hle_vdp_reg(1, 0xE2u); hle_vdp_reg(2, 0x06u);
        hle_vdp_reg(3, 0x80u); hle_vdp_reg(4, 0x00u); hle_vdp_reg(5, 0x36u); hle_vdp_reg(6, 0x07u);
    } else if (mode == 2) {
        hle_vdp_reg(0, 0x02u); hle_vdp_reg(1, 0xE2u); hle_vdp_reg(2, 0x06u);
        hle_vdp_reg(3, 0xFFu); hle_vdp_reg(4, 0x03u); hle_vdp_reg(5, 0x36u); hle_vdp_reg(6, 0x07u);
    } else if (mode == 3) {
        hle_vdp_reg(0, 0x00u); hle_vdp_reg(1, 0xEAu); hle_vdp_reg(2, 0x02u);
        hle_vdp_reg(4, 0x00u); hle_vdp_reg(5, 0x36u); hle_vdp_reg(6, 0x07u);
    } else if (S.is_msx2 && mode == 4) {    /* Graphic 3 */
        hle_vdp_reg(0, 0x04u); hle_vdp_reg(1, 0xE2u); hle_vdp_reg(2, 0x06u);
        hle_vdp_reg(3, 0xFFu); hle_vdp_reg(4, 0x03u); hle_vdp_reg(5, 0x3Cu);
        hle_vdp_reg(6, 0x07u); hle_vdp_reg(11, 0x00u);
    } else if (S.is_msx2 && mode == 5) {    /* Graphic 4 (256x212 4bpp) */
        hle_vdp_reg(0, 0x06u); hle_vdp_reg(1, 0xE2u); hle_vdp_reg(2, 0x1Fu);
        hle_vdp_reg(5, 0xEFu); hle_vdp_reg(6, 0x0Fu); hle_vdp_reg(9, 0x80u); hle_vdp_reg(11, 0x00u);
    } else if (S.is_msx2 && mode == 6) {    /* Graphic 5 (512x212 2bpp) */
        hle_vdp_reg(0, 0x08u); hle_vdp_reg(1, 0xE2u); hle_vdp_reg(2, 0x1Fu);
        hle_vdp_reg(5, 0xEFu); hle_vdp_reg(6, 0x0Fu); hle_vdp_reg(9, 0x80u); hle_vdp_reg(11, 0x00u);
    } else if (S.is_msx2 && mode == 7) {    /* Graphic 6 (512x212 4bpp) */
        hle_vdp_reg(0, 0x0Au); hle_vdp_reg(1, 0xE2u); hle_vdp_reg(2, 0x1Fu);
        hle_vdp_reg(5, 0xF7u); hle_vdp_reg(6, 0x1Eu); hle_vdp_reg(9, 0x80u); hle_vdp_reg(11, 0x01u);
    } else if (S.is_msx2 && mode == 8) {    /* Graphic 7 (256x212 8bpp) */
        hle_vdp_reg(0, 0x0Eu); hle_vdp_reg(1, 0xE2u); hle_vdp_reg(2, 0x1Fu);
        hle_vdp_reg(5, 0xF7u); hle_vdp_reg(6, 0x1Eu); hle_vdp_reg(9, 0x80u); hle_vdp_reg(11, 0x01u);
    }
    hle_chgclr();
}

static void hle_chgmod(u8 mode)
{
    sys_wr8(0xFCAFu, mode);
    sys_wr8(0xF3DCu, 1);
    sys_wr8(0xF3DDu, 1);
    hle_setmod_regs(mode);
    if (mode == 0) {
        u8 wid = sys_rd8(0xF3B0u);
        u32 pat = (wid > 40) ? 0x1000u : 0x0800u;
        hle_set_u16(0xF3B3u, 0x0000u);
        hle_set_u16(0xF3B7u, (u16)pat);
        for (u32 i = 0; i < (u32)wid * 24u; i++)
            M->vram[i] = 0x20u;
        hle_load_font(pat);
    } else if (mode == 1) {
        hle_set_u16(0xF3B3u, 0x1800u);
        hle_set_u16(0xF3F6u, 0x2000u);
        hle_set_u16(0xF3F8u, 0x0000u);
        hle_set_u16(0xF3FAu, 0x1B00u);
        hle_set_u16(0xF3FCu, 0x3800u);
        for (u32 i = 0; i < 768u; i++)
            M->vram[0x1800u + i] = 0x20u;
        for (u32 i = 0; i < 128u; i += 4u)
            M->vram[0x1B00u + i] = 0xD0u;
        hle_load_font(0x0000u);
        hle_chgclr();
    } else if (mode == 2 || mode == 4) {
        for (u32 i = 0; i < 768u; i++)
            M->vram[0x1800u + i] = (u8)(i & 0xFFu);
        u8 col = (u8)(((sys_rd8(0xF3E9u) & 15u) << 4) | (sys_rd8(0xF3EAu) & 15u));
        for (u32 i = 0; i < 0x1800u; i++) {
            M->vram[i] = 0;
            M->vram[0x2000u + i] = col;
        }
        u32 sat = (mode == 4) ? 0x1E00u : 0x1B00u;
        u8 term = (mode == 4) ? 0xD8u : 0xD0u;
        for (u32 i = 0; i < 128u; i += 4u)
            M->vram[sat + i] = term;
    } else if (S.is_msx2 && mode >= 5 && mode <= 8) {
        u32 bytes = (mode >= 7) ? 0xD400u : 0x6A00u;
        for (u32 i = 0; i < bytes; i++)
            M->vram[i] = 0;
        u32 sat = (((u32)(S.vdp_reg[11] & 3u) << 15) | ((u32)(S.vdp_reg[5] & 0xFCu) << 7)) & 0x1FFFFu;
        for (u32 i = 0; i < 128u; i += 4u)
            M->vram[(sat + i) & 0x1FFFFu] = 0xD8u;
    }
}

static void hle_chput(u8 ch)
{
    u8 mode = sys_rd8(0xFCAFu);
    int cols = (mode == 0) ? (sys_rd8(0xF3B0u) > 40 ? 80 : 40) : 32;
    u16 nam = (mode == 0) ? 0x0000u : 0x1800u;
    int y = sys_rd8(0xF3DCu) ? (sys_rd8(0xF3DCu) - 1) : 0;
    int x = sys_rd8(0xF3DDu) ? (sys_rd8(0xF3DDu) - 1) : 0;
    if (y >= 24) y = 23;
    if (x >= cols) x = cols - 1;

    if (ch == 0x0Cu) {
        for (int i = 0; i < cols * 24; i++)
            M->vram[(nam + i) & 0x3FFFu] = 0x20u;
        x = 0; y = 0;
    } else if (ch == '\r') {
        x = 0;
    } else if (ch == '\n') {
        y++;
    } else if (ch == '\b') {
        if (x > 0) x--;
    } else if (ch >= 0x20u) {
        M->vram[(nam + y * cols + x) & 0x3FFFu] = ch;
        x++;
        if (x >= cols) { x = 0; y++; }
    }
    if (y >= 24) {
        for (int r = 0; r < 23 * cols; r++)
            M->vram[(nam + r) & 0x3FFFu] = M->vram[(nam + cols + r) & 0x3FFFu];
        for (int c = 0; c < cols; c++)
            M->vram[(nam + 23 * cols + c) & 0x3FFFu] = 0x20u;
        y = 23;
    }
    sys_wr8(0xF3DCu, (u8)(y + 1));
    sys_wr8(0xF3DDu, (u8)(x + 1));
}

/* ---- Disk (.dsk) PHYDIO + Automatic FAT12 .BIN/.COM Booter ---- */
static void dsk_phydio(void)
{
    struct z80 *c = &S.cpu;
    if (!S.has_dsk) {
        c->af.b.h = 0x02u;              /* Not ready */
        c->af.b.l |= Z80_FC;
        return;
    }
    int write = (c->af.b.l & Z80_FC) != 0;
    u32 count = c->bc.b.h;
    u32 sec = c->de.w;
    u16 addr = c->hl.w;
    for (u32 s = 0; s < count; s++) {
        u32 off = (sec + s) * 512u;
        for (u32 i = 0; i < 512u; i++) {
            u16 dst = (u16)(addr + s * 512u + i);
            if (!write) {
                u8 b = (off + i < S.dsk_size) ? M->dsk[off + i] : 0;
                /* Write to RAM (even if Disk ROM is currently paged in $4000..$7FFF!) */
                int slot = (S.ppi_a >> ((dst >> 14) * 2)) & 3;
                if (slot == 3 && S.is_msx2 && ((S.slot3_sub >> ((dst >> 14) * 2)) & 3) != 0)
                    sys_wr8(dst, b);
                else
                    mem_wr8(dst, b);
            } else if (off + i < DSK_MAX) {
                M->dsk[off + i] = mem_rd8(dst);
                S.dsk_dirty = 1;
            }
        }
    }
    c->bc.b.h = 0;
    c->af.b.l &= (u8)~Z80_FC;
}

/* Minimal MSX-DOS 1 BDOS ($0005 / $F37D) so .COM programs on FAT12 .dsk images can open & read files! */
static u32 fat12_next(const u8 *fat, u32 cl)
{
    u32 off = cl + (cl >> 1);
    u16 v = (u16)(fat[off] | ((u16)fat[off + 1] << 8));
    return (cl & 1u) ? (v >> 4) : (v & 0xFFFu);
}

static u16 bdos_dma = 0x0080u;

static void dsk_bdos(void)
{
    struct z80 *c = &S.cpu;
    u8 fn = c->bc.b.l;
    switch (fn) {
    case 0x02: hle_chput(c->de.b.l); break;                 /* Console output */
    case 0x06:                                              /* Direct console I/O */
        if (c->de.b.l != 0xFFu) hle_chput(c->de.b.l);
        else c->af.b.h = 0;
        break;
    case 0x09: {                                            /* Print '$'-terminated string */
        for (u16 p = c->de.w; ; p++) {
            u8 ch = mem_rd8(p);
            if (ch == '$') break;
            hle_chput(ch);
        }
        break;
    }
    case 0x0B: c->af.b.h = c->hl.b.l = 0; break;
    case 0x0C: c->bc.w = c->hl.w = 0x0022u; break;          /* CPM 2.2 */
    case 0x19: c->af.b.h = c->hl.b.l = 0; break;            /* Current drive A: */
    case 0x1A: bdos_dma = c->de.w; break;                   /* Set DMA address */
    case 0x0F: {                                            /* FCB Open */
        u16 fcb = c->de.w;
        u16 bps = (u16)(M->dsk[11] | (M->dsk[12] << 8));
        if (!bps) bps = 512;
        u16 rsvd = (u16)(M->dsk[14] | (M->dsk[15] << 8));
        u8 nfats = M->dsk[16] ? M->dsk[16] : 2;
        u16 nroot = (u16)(M->dsk[17] | (M->dsk[18] << 8));
        u16 spf = (u16)(M->dsk[22] | (M->dsk[23] << 8));
        u32 root_off = (u32)(rsvd + nfats * spf) * bps;
        int found = -1;
        for (u32 e = 0; e < nroot && root_off + e * 32u + 32u <= S.dsk_size; e++) {
            const u8 *de = M->dsk + root_off + e * 32u;
            if (de[0] == 0x00u) break;
            if (de[0] == 0xE5u || (de[11] & 0x18u)) continue;
            int ok = 1;
            for (int k = 0; k < 11; k++) {
                u8 w = mem_rd8((u16)(fcb + 1u + k));
                if (w >= 'a' && w <= 'z') w -= 32u;
                if (w != '?' && w != de[k]) { ok = 0; break; }
            }
            if (ok) { found = (int)e; break; }
        }
        if (found < 0) {
            c->af.b.h = c->hl.b.l = 0xFFu;
        } else {
            const u8 *de = M->dsk + root_off + (u32)found * 32u;
            mem_wr8((u16)(fcb + 14u), 0x80u); mem_wr8((u16)(fcb + 15u), 0x00u); /* rec size = 128 */
            for (int k = 0; k < 4; k++)
                mem_wr8((u16)(fcb + 16u + k), de[28 + k]);                      /* file size */
            mem_wr8((u16)(fcb + 26u), de[26]); mem_wr8((u16)(fcb + 27u), de[27]); /* start cluster */
            for (int k = 0; k < 4; k++)
                mem_wr8((u16)(fcb + 33u + k), 0);                               /* random record = 0 */
            c->af.b.h = c->hl.b.l = 0;
        }
        break;
    }
    case 0x14:                                              /* Sequential Read (128B) */
    case 0x27: {                                            /* Random Block Read (HL records of rec_size) */
        u16 fcb = c->de.w;
        u16 rec_sz = (u16)(mem_rd8((u16)(fcb + 14u)) | ((u16)mem_rd8((u16)(fcb + 15u)) << 8));
        if (!rec_sz) rec_sz = 128;
        u32 nrec = (fn == 0x27u) ? c->hl.w : 1u;
        u32 fsize = (u32)mem_rd8((u16)(fcb + 16u)) | ((u32)mem_rd8((u16)(fcb + 17u)) << 8) |
                    ((u32)mem_rd8((u16)(fcb + 18u)) << 16) | ((u32)mem_rd8((u16)(fcb + 19u)) << 24);
        u32 cur_rec = (u32)mem_rd8((u16)(fcb + 33u)) | ((u32)mem_rd8((u16)(fcb + 34u)) << 8) |
                      ((u32)mem_rd8((u16)(fcb + 35u)) << 16);
        u32 byte_pos = cur_rec * rec_sz;
        u16 cl0 = (u16)(mem_rd8((u16)(fcb + 26u)) | ((u16)mem_rd8((u16)(fcb + 27u)) << 8));
        u16 bps = (u16)(M->dsk[11] | (M->dsk[12] << 8)); if (!bps) bps = 512;
        u8 spc = M->dsk[13] ? M->dsk[13] : 2;
        u16 rsvd = (u16)(M->dsk[14] | (M->dsk[15] << 8));
        u8 nfats = M->dsk[16] ? M->dsk[16] : 2;
        u16 nroot = (u16)(M->dsk[17] | (M->dsk[18] << 8));
        u16 spf = (u16)(M->dsk[22] | (M->dsk[23] << 8));
        const u8 *fat = M->dsk + (u32)rsvd * bps;
        u32 data_off = (u32)(rsvd + nfats * spf + ((nroot * 32u + bps - 1u) / bps)) * bps;
        u32 cl_bytes = (u32)spc * bps;

        u32 to_read = nrec * rec_sz;
        u32 got = 0;
        while (got < to_read && byte_pos < fsize) {
            u32 cl_idx = byte_pos / cl_bytes;
            u32 in_cl = byte_pos % cl_bytes;
            u32 cl = cl0;
            for (u32 step = 0; step < cl_idx && cl >= 2u && cl < 0xFF8u; step++)
                cl = fat12_next(fat, cl);
            if (cl < 2u || cl >= 0xFF8u) break;
            u32 off = data_off + (cl - 2u) * cl_bytes + in_cl;
            u8 val = (off < S.dsk_size) ? M->dsk[off] : 0;
            mem_wr8((u16)(bdos_dma + got), val);
            got++;
            byte_pos++;
        }
        u32 recs_done = (got + rec_sz - 1u) / rec_sz;
        cur_rec += recs_done;
        mem_wr8((u16)(fcb + 33u), (u8)cur_rec);
        mem_wr8((u16)(fcb + 34u), (u8)(cur_rec >> 8));
        mem_wr8((u16)(fcb + 35u), (u8)(cur_rec >> 16));
        if (fn == 0x27u) c->hl.w = (u16)recs_done;
        c->af.b.h = (got == 0) ? 1 : 0;
        break;
    }
    case 0x2F: {                                            /* Read absolute logical sectors (DE=start, H=cnt) */
        u32 cnt = c->hl.b.h;
        u32 sec = c->de.w;
        for (u32 i = 0; i < cnt * 512u; i++) {
            u32 off = sec * 512u + i;
            mem_wr8((u16)(bdos_dma + i), off < S.dsk_size ? M->dsk[off] : 0);
        }
        c->af.b.h = 0;
        break;
    }
    default:
        c->af.b.h = 0;
        break;
    }
}

/* Boot .dsk image: try FAT12 .BIN (0xFE BLOAD) or .COM executable first if boot sector needs MSXDOS.SYS,
   otherwise execute boot sector at $C01E! */
static u16 hle_boot_dsk(void)
{
    /* Set up MSX Disk-BASIC / MSX-DOS RAM slot variables ($F341..$F344 = 0x83 = Slot 3-0 RAM) */
    u8 ram_slt = S.is_msx2 ? 0x83u : 0x03u;
    for (int i = 0; i < 4; i++)
        sys_wr8((u16)(0xF341u + i), ram_slt);
    sys_wr8(0xFB21u, 1);                /* 1 disk drive */
    sys_wr8(0xFB22u, 0x8Bu);            /* Disk ROM in Slot 3-2 */
    sys_wr8(0xF348u, 0x8Bu);

    /* Install BDOS jump at $0005 and $F37D when all-RAM is paged in */
    /* Place BDOS stub at $F360 in RAM: OUT (0x4D), A; RET */
    sys_wr8(0xF360u, 0xD3u); sys_wr8(0xF361u, 0x4Du); sys_wr8(0xF362u, 0xC9u);
    sys_wr8(0xF37Du, 0xC3u); sys_wr8(0xF37Eu, 0x60u); sys_wr8(0xF37Fu, 0xF3u);

    /* Inspect FAT12 root directory for BLOAD .BIN (0xFE header) or standalone .COM (when no MSXDOS.SYS) */
    u16 bps = (u16)(M->dsk[11] | (M->dsk[12] << 8));
    u8 spc = M->dsk[13];
    u16 rsvd = (u16)(M->dsk[14] | (M->dsk[15] << 8));
    u8 nfats = M->dsk[16];
    u16 nroot = (u16)(M->dsk[17] | (M->dsk[18] << 8));
    u16 spf = (u16)(M->dsk[22] | (M->dsk[23] << 8));
    int has_msxdos_sys = 0;
    int first_bin = -1, first_com = -1;

    if (bps == 512 && spc >= 1 && spc <= 8 && nfats >= 1 && nfats <= 2 && nroot > 0 && nroot <= 512 && spf > 0) {
        u32 root_off = (u32)(rsvd + nfats * spf) * 512u;
        for (u32 e = 0; e < nroot && root_off + e * 32u + 32u <= S.dsk_size; e++) {
            const u8 *de = M->dsk + root_off + e * 32u;
            if (de[0] == 0x00u) break;
            if (de[0] == 0xE5u || (de[11] & 0x18u)) continue;
            if (de[0]=='M' && de[1]=='S' && de[2]=='X' && de[3]=='D' && de[4]=='O' && de[5]=='S' &&
                de[8]=='S' && de[9]=='Y' && de[10]=='S')
                has_msxdos_sys = 1;
            if (first_bin < 0 && de[8] == 'B' && de[9] == 'I' && de[10] == 'N')
                first_bin = (int)e;
            if (first_com < 0 && de[8] == 'C' && de[9] == 'O' && de[10] == 'M' &&
                !(de[0]=='C' && de[1]=='O' && de[2]=='M' && de[3]=='M' && de[4]=='A' && de[5]=='N'))
                first_com = (int)e;
        }

        /* Check if boot sector is a standard DOS boot sector that merely looks for MSXDOS.SYS */
        int boot_wants_dos = 0;
        for (u32 i = 0x1Eu; i < 500u; i++) {
            if (M->dsk[i]=='M' && M->dsk[i+1]=='S' && M->dsk[i+2]=='X' && M->dsk[i+3]=='D' && M->dsk[i+4]=='O') {
                boot_wants_dos = 1;
                break;
            }
        }
        int boot_valid = (M->dsk[0] == 0xEBu || M->dsk[0] == 0xE9u) && M->dsk[0x1E] != 0x00u && M->dsk[0x1E] != 0xC9u && M->dsk[0x1E] != 0xD0u;

        if ((!boot_valid || (boot_wants_dos && !has_msxdos_sys)) && (first_bin >= 0 || first_com >= 0)) {
            int pick = (first_com >= 0) ? first_com : first_bin;
            const u8 *de = M->dsk + root_off + (u32)pick * 32u;
            u16 cl = (u16)(de[26] | (de[27] << 8));
            u32 fsz = (u32)de[28] | ((u32)de[29] << 8) | ((u32)de[30] << 16);
            const u8 *fat = M->dsk + (u32)rsvd * 512u;
            u32 data_off = (u32)(rsvd + nfats * spf + ((nroot * 32u + 511u) / 512u)) * 512u;
            u32 cl_bytes = (u32)spc * 512u;

            if (pick == first_com) {
                /* Map all 4 pages to Slot 3-0 RAM for MSX-DOS .COM ($0100) */
                S.ppi_a = 0xFFu;
                S.slot3_sub = 0x00u;
                rebuild_map();
                sys_wr8(0x0000u, 0xC9u);
                sys_wr8(0x0005u, 0xC3u); sys_wr8(0x0006u, 0x60u); sys_wr8(0x0007u, 0xF3u);
                sys_wr8(0x0006u, 0x60u);
                u32 got = 0;
                while (got < fsz && cl >= 2u && cl < 0xFF8u) {
                    u32 off = data_off + (cl - 2u) * cl_bytes;
                    for (u32 b = 0; b < cl_bytes && got < fsz; b++, got++)
                        if (0x0100u + got < 0xF300u && off + b < S.dsk_size)
                            sys_wr8((u16)(0x0100u + got), M->dsk[off + b]);
                    cl = fat12_next(fat, cl);
                }
                return 0x0100u;
            } else {
                /* BLOAD .BIN: byte 0 = 0xFE, 1..2 = start, 3..4 = end, 5..6 = exec */
                u8 hdr[7] = {0};
                u32 got = 0;
                u16 start = 0x8000u, exec = 0x8000u;
                while (got < fsz && cl >= 2u && cl < 0xFF8u) {
                    u32 off = data_off + (cl - 2u) * cl_bytes;
                    for (u32 b = 0; b < cl_bytes && got < fsz; b++, got++) {
                        u8 v = (off + b < S.dsk_size) ? M->dsk[off + b] : 0;
                        if (got < 7u) {
                            hdr[got] = v;
                            if (got == 6u && hdr[0] == 0xFEu) {
                                start = (u16)(hdr[1] | (hdr[2] << 8));
                                exec  = (u16)(hdr[5] | (hdr[6] << 8));
                                if (!exec) exec = start;
                                if (start >= 0x8000u) S.ppi_a = (u8)((S.ppi_a & 0x0Fu) | 0xF0u);
                                else if (start >= 0x4000u) S.ppi_a = (u8)((S.ppi_a & 0x03u) | 0xFCu);
                                rebuild_map();
                            }
                        } else if (hdr[0] == 0xFEu) {
                            sys_wr8((u16)(start + (got - 7u)), v);
                        }
                    }
                    cl = fat12_next(fat, cl);
                }
                if (hdr[0] == 0xFEu)
                    return exec;
            }
        }
    }

    /* Standard MSX Disk ROM boot: load sector 0 into $C000, map Slot 0-0 / Slot 3-2 / Slot 3-0 / Slot 3-0,
       Carry = 0, jump to $C01E! */
    for (u32 i = 0; i < 512u; i++)
        sys_wr8((u16)(0xC000u + i), i < S.dsk_size ? M->dsk[i] : 0);
    S.ppi_a = 0xFCu;                    /* P0=Slot0, P1=Slot3, P2=Slot3, P3=Slot3 */
    S.slot3_sub = 0x08u;                /* P1=Subslot 2 (Disk ROM at $4000), P2=0 (RAM), P3=0 (RAM) */
    rebuild_map();
    S.cpu.af.b.l &= (u8)~Z80_FC;
    return 0xC01Eu;
}

static void hle_subrom_dispatch(u16 entry)
{
    struct z80 *c = &S.cpu;
    switch (entry) {
    case 0x005F: case 0x01B5:           /* CHGMOD / CHGMDP */
        hle_chgmod(c->af.b.h);
        break;
    case 0x0062: hle_chgclr(); break;
    case 0x0069: {                      /* CLRSPR (Mode 1 or Mode 2) */
        int m = vdp_mode5();
        if (m >= 0x08) {
            u32 sat = (((u32)(S.vdp_reg[11] & 3u) << 15) | ((u32)(S.vdp_reg[5] & 0xFCu) << 7)) & 0x1FFFFu;
            for (u32 i = 0; i < 128u; i += 4u)
                M->vram[(sat + i) & 0x1FFFFu] = 0xD8u;
        } else {
            u16 sat = (u16)((S.vdp_reg[5] & 0x7Fu) << 7);
            for (u32 i = 0; i < 128u; i += 4u)
                M->vram[(sat + i) & 0x3FFFu] = 0xD0u;
        }
        break;
    }
    case 0x0141: case 0x0145:           /* INIPLT / RSTPLT */
        vdp_init_palettes();
        break;
    case 0x0149: {                      /* GETPLT: A = pal# -> B = R*16+B, C = G */
        u8 idx = c->af.b.h & 15u;
        c->bc.b.h = (u8)((S.pal_rgb333[idx][0] << 4) | S.pal_rgb333[idx][2]);
        c->bc.b.l = S.pal_rgb333[idx][1];
        break;
    }
    case 0x014D: {                      /* SETPLT: D = pal#, A = R*16+B, E = G */
        u8 idx = c->de.b.h & 15u;
        u8 r3 = (c->af.b.h >> 4) & 7u;
        u8 b3 = c->af.b.h & 7u;
        u8 g3 = c->de.b.l & 7u;
        S.pal_rgb333[idx][0] = r3;
        S.pal_rgb333[idx][1] = g3;
        S.pal_rgb333[idx][2] = b3;
        S.pal[idx] = pack_rgb333(r3, g3, b3);
        break;
    }
    case 0x0180:                        /* WRTVDP: B = data, C = reg */
        hle_vdp_reg(c->bc.b.l, c->bc.b.h);
        break;
    case 0x01AD: {                      /* REDCLK: C = (bank<<4)|addr -> A = 4-bit value */
        u8 b = (c->bc.b.l >> 4) & 3u;
        u8 a = c->bc.b.l & 15u;
        c->af.b.h = S.rtc_bank[b][a] & 15u;
        break;
    }
    case 0x01B1: {                      /* WRTCLK: C = (bank<<4)|addr, A = value */
        u8 b = (c->bc.b.l >> 4) & 3u;
        u8 a = c->bc.b.l & 15u;
        S.rtc_bank[b][a] = c->af.b.h & 15u;
        break;
    }
    default:
        break;
    }
}

static void hle_bios_dispatch(u16 entry)
{
    struct z80 *c = &S.cpu;
    switch (entry) {
    case 0x0000: {
        for (u32 i = 0xF380u; i < 0xFFFFu; i++)
            sys_wr8((u16)i, 0);
        for (u32 i = 0xFD9Au; i <= 0xFFCAu; i++)
            sys_wr8((u16)i, 0xC9u);
        hle_set_u16(0xFC48u, 0xC000u);  /* BOTTOM */
        hle_set_u16(0xFC4Au, 0xF300u);  /* HIMEM (below $F340..$F37F Disk/BDOS workspace) */
        sys_wr8(0xF3AEu, 40);           /* LINL40 */
        sys_wr8(0xF3AFu, 29);           /* LINL32 */
        sys_wr8(0xF3E9u, 15);           /* FORCLR */
        sys_wr8(0xF3EAu, 4);            /* BAKCLR */
        sys_wr8(0xF3EBu, 4);            /* BDRCLR */
        if (S.is_msx2) {
            sys_wr8(0xFAF8u, 0x87u);    /* EXBRSA = Slot 3-1 (Sub-ROM) */
            sys_wr8(0xFCC1u, 0x00u);    /* EXPTBL[0] = unexpanded */
            sys_wr8(0xFCC2u, 0x00u);
            sys_wr8(0xFCC3u, 0x00u);
            sys_wr8(0xFCC4u, 0x80u);    /* EXPTBL[3] = expanded! */
        }
        S.ay.reg[7] = 0xBFu;
        S.ay.reg[15] = 0x0Fu;
        hle_chgmod(1);

        if (!S.has_cart && S.has_dsk) {
            c->hl.w = hle_boot_dsk();
            break;
        }
        if (S.cart_base == 0x0000u && S.rom_size >= 0x8000u)
            S.ppi_a = 0xC5u;
        else
            S.ppi_a = 0xD4u;
        S.slot3_sub = 0x00u;
        rebuild_map();
        c->hl.w = S.cart_init ? S.cart_init : 0x4010u;
        break;
    }
    case 0x000C:
        c->af.b.h = slot_read_byte(c->af.b.h, c->hl.w);
        c->iff1 = c->iff2 = 0;
        break;
    case 0x0014:
        slot_write_byte(c->af.b.h, c->hl.w, c->de.b.l);
        c->iff1 = c->iff2 = 0;
        break;
    case 0x0020: {
        u32 d = (u32)c->hl.w - (u32)c->de.w;
        c->af.b.l = (u8)((c->af.b.l & ~(Z80_FZ | Z80_FC | Z80_FN)) | Z80_FN |
                         ((d & 0xFFFFu) == 0 ? Z80_FZ : 0) | (d >= 0x10000u ? Z80_FC : 0));
        break;
    }
    case 0x0024: {                      /* ENASLT: A = slot_id, H = page (bits 7..6) */
        int pg = (c->hl.b.h >> 6) & 3;
        int sl = c->af.b.h & 3;
        S.ppi_a = (u8)((S.ppi_a & ~(3u << (pg * 2))) | ((u32)sl << (pg * 2)));
        if (S.is_msx2 && sl == 3 && (c->af.b.h & 0x80u)) {
            int sub = (c->af.b.h >> 2) & 3;
            S.slot3_sub = (u8)((S.slot3_sub & ~(3u << (pg * 2))) | ((u32)sub << (pg * 2)));
        }
        rebuild_map();
        c->iff1 = c->iff2 = 0;
        break;
    }
    case 0x003B: {                      /* KEYINT helper */
        u8 old_r15 = S.vdp_reg[15];
        if (S.is_msx2 && (S.vdp_stat[1] & 0x01u) && (S.vdp_reg[0] & 0x10u)) {
            /* Horizontal line IRQ (IE1): clear S#1 FH and let H.KEYI handle it without advancing JIFFY */
            S.vdp_stat[1] &= (u8)~0x01u;
            vdp_update_irq();
            c->af.b.l |= Z80_FZ;
            break;
        }
        S.vdp_reg[15] = 0;
        u8 st = vdp_status_read();
        S.vdp_reg[15] = old_r15;
        sys_wr8(0xF3E7u, st);
        if (st & 0x80u) {
            u16 jif = (u16)(sys_rd8(0xFC9Eu) | ((u16)sys_rd8(0xFC9Fu) << 8)) + 1u;
            sys_wr8(0xFC9Eu, (u8)jif);
            sys_wr8(0xFC9Fu, (u8)(jif >> 8));
            for (int r = 0; r < 11; r++)
                sys_wr8((u16)(0xFBE5u + r), S.kbd_row[r]);
            c->af.b.l &= (u8)~Z80_FZ;
        } else {
            c->af.b.l |= Z80_FZ;
        }
        break;
    }
    case 0x0041: hle_vdp_reg(1, (u8)(sys_rd8(0xF3E0u) & ~0x40u)); break;
    case 0x0044: hle_vdp_reg(1, (u8)(sys_rd8(0xF3E0u) | 0x40u));  break;
    case 0x0047: hle_vdp_reg(c->bc.b.l, c->bc.b.h);               break;
    case 0x004A: {                      /* RDVRM (14-bit on MSX1, 16-bit on MSX2) */
        u32 mask = S.is_msx2 ? 0xFFFFu : 0x3FFFu;
        u32 a = c->hl.w & mask;
        S.vdp_first = 0;
        S.vdp_addr = (a + 1u) & vdp_vram_mask();
        c->af.b.h = M->vram[a];
        S.vdp_buf = M->vram[S.vdp_addr];
        break;
    }
    case 0x004D: {                      /* WRTVRM */
        u32 mask = S.is_msx2 ? 0xFFFFu : 0x3FFFu;
        u32 a = c->hl.w & mask;
        S.vdp_first = 0;
        M->vram[a] = c->af.b.h;
        S.vdp_addr = (a + 1u) & vdp_vram_mask();
        break;
    }
    case 0x0050: {                      /* SETRD */
        u32 mask = S.is_msx2 ? 0xFFFFu : 0x3FFFu;
        S.vdp_first = 0;
        S.vdp_buf = M->vram[c->hl.w & mask];
        S.vdp_addr = ((c->hl.w & mask) + 1u) & vdp_vram_mask();
        break;
    }
    case 0x0053: {                      /* SETWRT */
        u32 mask = S.is_msx2 ? 0xFFFFu : 0x3FFFu;
        S.vdp_first = 0;
        S.vdp_addr = c->hl.w & mask;
        break;
    }
    case 0x0056: {                      /* FILVRM */
        u32 cnt = c->bc.w ? c->bc.w : 0x10000u;
        u32 mask = S.is_msx2 ? 0xFFFFu : 0x3FFFu;
        S.vdp_first = 0;
        for (u32 i = 0; i < cnt; i++)
            M->vram[(c->hl.w + i) & mask] = c->af.b.h;
        S.vdp_addr = ((c->hl.w + cnt) & mask);
        c->cycles += (s32)(cnt * 20u);
        break;
    }
    case 0x0059: {                      /* LDIRMV */
        u32 cnt = c->bc.w ? c->bc.w : 0x10000u;
        u32 hi = S.is_msx2 ? (((u32)(S.vdp_reg[14] & 7u) & 4u) << 14) : 0u;
        u32 mask = vdp_vram_mask();
        S.vdp_first = 0;
        for (u32 i = 0; i < cnt; i++)
            mem_wr8((u16)(c->de.w + i), M->vram[(hi + c->hl.w + i) & mask]);
        c->cycles += (s32)(cnt * 22u);
        break;
    }
    case 0x005C: {                      /* LDIRVM */
        u32 cnt = c->bc.w ? c->bc.w : 0x10000u;
        u32 hi = S.is_msx2 ? (((u32)(S.vdp_reg[14] & 7u) & 4u) << 14) : 0u;
        u32 mask = vdp_vram_mask();
        S.vdp_first = 0;
        for (u32 i = 0; i < cnt; i++)
            M->vram[(hi + c->de.w + i) & mask] = mem_rd8((u16)(c->hl.w + i));
        c->cycles += (s32)(cnt * 22u);
        break;
    }
    case 0x005F: hle_chgmod(c->af.b.h); break;
    case 0x0062: hle_chgclr();          break;
    case 0x0069: hle_subrom_dispatch(0x0069); break;
    case 0x006C: hle_chgmod(0); break;
    case 0x006F: hle_chgmod(1); break;
    case 0x0072: hle_chgmod(2); break;
    case 0x0075: hle_chgmod(3); break;
    case 0x0078: hle_setmod_regs(0); break;
    case 0x007B: hle_setmod_regs(1); break;
    case 0x007E: hle_setmod_regs(2); break;
    case 0x0081: hle_setmod_regs(3); break;
    case 0x0084: {
        u32 sz = (S.vdp_reg[1] & 2u) ? 32u : 8u;
        c->hl.w = (u16)(((u32)(S.vdp_reg[6] & 7u) << 11) + c->af.b.h * sz);
        break;
    }
    case 0x0087:
        c->hl.w = (u16)(((u32)(S.vdp_reg[5] & 0x7Fu) << 7) + (c->af.b.h & 31u) * 4u);
        break;
    case 0x008A:
        c->af.b.h = (S.vdp_reg[1] & 2u) ? 32 : 8;
        break;
    case 0x0090:
        for (u8 r = 0; r < 14; r++)
            ay_write_reg(r, r == 7 ? 0xBFu : 0);
        break;
    case 0x0093: ay_write_reg(c->af.b.h, c->de.b.l); break;
    case 0x0096: c->af.b.h = ay_read_reg(c->af.b.h); break;
    case 0x009C: c->af.b.h = 0; c->af.b.l |= Z80_FZ; break;
    case 0x00A2: hle_chput(c->af.b.h); break;
    case 0x00C3: hle_chput(0x0Cu); break;
    case 0x00C6: sys_wr8(0xF3DDu, c->hl.b.h); sys_wr8(0xF3DCu, c->hl.b.l); break;
    case 0x00D5: {
        int u = 0, d = 0, l = 0, r = 0;
        if (c->af.b.h == 0) {
            u = !(S.kbd_row[8] & 0x20u); d = !(S.kbd_row[8] & 0x40u);
            l = !(S.kbd_row[8] & 0x10u); r = !(S.kbd_row[8] & 0x80u);
        } else if (c->af.b.h == 1) {
            u = (S.pad_state & MSX_UP) != 0;   d = (S.pad_state & MSX_DOWN) != 0;
            l = (S.pad_state & MSX_LEFT) != 0; r = (S.pad_state & MSX_RIGHT) != 0;
        }
        u8 dir = 0;
        if (u && r) dir = 2;
        else if (d && r) dir = 4;
        else if (d && l) dir = 6;
        else if (u && l) dir = 8;
        else if (u) dir = 1;
        else if (r) dir = 3;
        else if (d) dir = 5;
        else if (l) dir = 7;
        c->af.b.h = dir;
        c->af.b.l = (u8)((c->af.b.l & ~Z80_FZ) | (dir ? 0 : Z80_FZ));
        break;
    }
    case 0x00D8: {
        int on = 0;
        if (c->af.b.h == 0)      on = !(S.kbd_row[8] & 0x01u);
        else if (c->af.b.h == 1) on = (S.pad_state & MSX_A) != 0;
        else if (c->af.b.h == 3) on = (S.pad_state & MSX_B) != 0;
        c->af.b.h = on ? 0xFFu : 0x00u;
        c->af.b.l = (u8)((c->af.b.l & ~Z80_FZ) | (on ? 0 : Z80_FZ));
        break;
    }
    case 0x00DB: case 0x00DE: c->af.b.h = 0; break;
    case 0x0138: c->af.b.h = S.ppi_a; break;
    case 0x013B: S.ppi_a = c->af.b.h; rebuild_map(); break;
    case 0x0141: {
        u8 row = c->af.b.h;
        c->af.b.h = row < 11 ? S.kbd_row[row] : 0xFFu;
        break;
    }
    case 0x015C: case 0x015F:           /* SUBROM / EXTROM (MSX2: call Sub-ROM at IX) */
        if (S.is_msx2)
            hle_subrom_dispatch(c->ix.w);
        break;
    case 0x016B: {                      /* BIGFIL (MSX2: 16-bit VRAM fill HL, BC, A) */
        u32 cnt = c->bc.w ? c->bc.w : 0x10000u;
        u32 hi = ((u32)(S.vdp_reg[14] & 7u) & 4u) << 14;
        for (u32 i = 0; i < cnt; i++)
            M->vram[(hi + ((c->hl.w + i) & 0xFFFFu)) & 0x1FFFFu] = c->af.b.h;
        break;
    }
    case 0x0171: {                      /* NRDVRM (MSX2: 16-bit VRAM read HL -> A) */
        u32 hi = ((u32)(S.vdp_reg[14] & 7u) & 4u) << 14;
        c->af.b.h = M->vram[(hi + c->hl.w) & 0x1FFFFu];
        break;
    }
    case 0x0177: {                      /* NWRVRM (MSX2: 16-bit VRAM write HL, A) */
        u32 hi = ((u32)(S.vdp_reg[14] & 7u) & 4u) << 14;
        M->vram[(hi + c->hl.w) & 0x1FFFFu] = c->af.b.h;
        break;
    }
    default:
        break;
    }
}

static const u16 bios_entries[] = {
    0x0000, 0x000C, 0x0014, 0x0020, 0x0024, 0x003B,
    0x0041, 0x0044, 0x0047, 0x004A, 0x004D, 0x0050, 0x0053, 0x0056, 0x0059, 0x005C,
    0x005F, 0x0062, 0x0069, 0x006C, 0x006F, 0x0072, 0x0075, 0x0078, 0x007B, 0x007E,
    0x0081, 0x0084, 0x0087, 0x008A,
    0x0090, 0x0093, 0x0096, 0x009C, 0x00A2, 0x00C3, 0x00C6, 0x00D5, 0x00D8, 0x00DB,
    0x00DE, 0x0138, 0x013B, 0x0141, 0x015C, 0x015F, 0x016B, 0x0171, 0x0177
};

static const u16 subrom_entries[] = {
    0x005F, 0x0062, 0x0069, 0x0141, 0x0145, 0x0149, 0x014D, 0x0180, 0x01AD, 0x01B1, 0x01B5
};

static void build_clean_sub_and_ext_roms(void)
{
    /* 1. Built-in MSX2 Sub-ROM (Slot 3-1, $0000..$3FFF) */
    if (!S.ext_subrom) {
        for (u32 i = 0; i < sizeof(M->subrom); i++)
            M->subrom[i] = 0xC9u;
        M->subrom[0x0000] = 'C';
        M->subrom[0x0001] = 'D';
        int ns = (int)(sizeof(subrom_entries) / sizeof(subrom_entries[0]));
        for (int i = 0; i < ns; i++) {
            u16 stub = (u16)(0x3E00u + i * 4);
            M->subrom[stub + 0] = 0xD3u;    /* OUT (0x4E), A */
            M->subrom[stub + 1] = 0x4Eu;
            M->subrom[stub + 2] = 0xC9u;
            u16 e = subrom_entries[i];
            M->subrom[e + 0] = 0xC3u;
            M->subrom[e + 1] = (u8)stub;
            M->subrom[e + 2] = (u8)(stub >> 8);
        }
    }

    /* 2. Built-in Disk ROM (Slot 3-2, $4000..$7FFF) */
    for (u32 i = 0; i < sizeof(M->diskrom); i++)
        M->diskrom[i] = 0xC9u;
    /* When external C-BIOS scans Slot 3-2 with a .dsk mounted, AB header at $4000 boots the disk! */
    if (S.has_dsk && !S.has_cart) {
        M->diskrom[0x0000] = 'A';
        M->diskrom[0x0001] = 'B';
        /*STATEMENT/DEVICE=0, TEXT=0, INIT=$4020 */
        M->diskrom[0x0002] = 0x20u; M->diskrom[0x0003] = 0x40u;
        for (int i = 4; i < 16; i++) M->diskrom[i] = 0;
        /* $4020: OUT (0x4C), A (triggers hle_boot_dsk -> HL = entry); JP (HL) */
        M->diskrom[0x0020] = 0xD3u; M->diskrom[0x0021] = 0x4Cu; M->diskrom[0x0022] = 0xE9u;
    }
    /* $4010 PHYDIO -> OUT (0x4B), A; RET */
    M->diskrom[0x0010] = 0xD3u; M->diskrom[0x0011] = 0x4Bu; M->diskrom[0x0012] = 0xC9u;
    /* $4013 DSKCHG -> LD B,1; OR A; RET */
    M->diskrom[0x0013] = 0x06u; M->diskrom[0x0014] = 0x01u; M->diskrom[0x0015] = 0xB7u; M->diskrom[0x0016] = 0xC9u;

    /* 3. Built-in MSX-MUSIC YM2413 ROM stub (Slot 2, $4000..$7FFF) */
    for (u32 i = 0; i < sizeof(M->fmrom); i++)
        M->fmrom[i] = 0xC9u;
    static const char sig[8] = {'A','P','R','L','O','P','L','L'};
    for (int i = 0; i < 8; i++)
        M->fmrom[0x0018 + i] = (u8)sig[i];
    /* $4110 WRTOPL (A=reg, E=data): OUT ($7C),A; LD A,E; OUT ($7D),A; RET */
    static const u8 wrtopl[] = { 0xD3, 0x7C, 0x7B, 0xD3, 0x7D, 0xC9 };
    for (u32 i = 0; i < sizeof(wrtopl); i++)
        M->fmrom[0x0110 + i] = wrtopl[i];
}

static void build_msx_bios(void)
{
    for (u32 i = 0; i < sizeof(M->bios); i++)
        M->bios[i] = 0xC9u;

    int n_ent = (int)(sizeof(bios_entries) / sizeof(bios_entries[0]));
    for (int i = 0; i < n_ent; i++) {
        u16 stub = (u16)(0x3E00u + i * 4);
        M->bios[stub + 0] = 0xD3u;
        M->bios[stub + 1] = 0x4Fu;
        M->bios[stub + 2] = 0xC9u;
        M->bios[stub + 3] = 0x00u;
        u16 e = bios_entries[i];
        if (e != 0x0000u && e != 0x003Bu) {
            M->bios[e + 0] = 0xC3u;
            M->bios[e + 1] = (u8)stub;
            M->bios[e + 2] = (u8)(stub >> 8);
        }
    }

    M->bios[0x0000] = 0xF3u;
    M->bios[0x0001] = 0xC3u;
    M->bios[0x0002] = 0x00u;
    M->bios[0x0003] = 0x3Du;
    static const u8 boot_seq[] = {
        0x3E, 0xC0, 0xD3, 0xA8,         /* Map Slot 3 RAM into Page 3 ($C000..$FFFF) before using stack */
        0x31, 0x00, 0xF3,
        0xED, 0x56,
        0xCD, 0x00, 0x3E,
        0xFB,
        0xE9
    };
    for (u32 i = 0; i < sizeof(boot_seq); i++)
        M->bios[0x3D00u + i] = boot_seq[i];

    M->bios[0x0004] = 0xBFu;
    M->bios[0x0005] = 0x1Bu;
    M->bios[0x0006] = 0x98u;
    M->bios[0x0007] = 0x98u;
    M->bios[0x002B] = 0x11u;
    M->bios[0x002C] = 0x00u;
    M->bios[0x002D] = S.is_msx2 ? 0x01u : 0x00u;    /* MSXVER: 0 = MSX1, 1 = MSX2! */

    M->bios[0x001C] = 0xDDu; M->bios[0x001D] = 0xE9u;
    M->bios[0x0038] = 0xC3u; M->bios[0x0039] = 0x20u; M->bios[0x003A] = 0x3Du;
    static const u8 isr_seq[] = {
        0xF5, 0xC5, 0xD5, 0xE5, 0xDD, 0xE5, 0xFD, 0xE5,
        0x08, 0xF5, 0xD9, 0xC5, 0xD5, 0xE5,
        0xCD, 0x9A, 0xFD,
        0xCD, 0x14, 0x3E,
        0xCA, 0x3A, 0x3D,
        0xCD, 0x9F, 0xFD,
        0xE1, 0xD1, 0xC1, 0xD9, 0xF1, 0x08,
        0xFD, 0xE1, 0xDD, 0xE1, 0xE1, 0xD1, 0xC1, 0xF1,
        0xFB, 0xC9
    };
    for (u32 i = 0; i < sizeof(isr_seq); i++)
        M->bios[0x3D20u + i] = isr_seq[i];

    for (u32 i = 0; i < 2048u; i++)
        M->bios[0x1BBFu + i] = 0;
    for (u32 ch = 0; ch < 96u; ch++)
        for (u32 r = 0; r < 8u; r++)
            M->bios[0x1CBFu + ch * 8u + r] = msx_font96[ch][r];
}

/* ---- Z80 I/O ports ---- */
static u8 msx_in(struct z80 *c, u16 port)
{
    (void)c;
    u8 p = (u8)port;
    switch (p) {
    case 0x98: return vdp_data_read();
    case 0x99: return vdp_status_read();
    case 0xA2: return ay_read_reg(S.ay.reg_sel);
    case 0xA8: return S.ppi_a;
    case 0xA9: {
        u8 row = S.ppi_c & 0x0Fu;
        return row < 11 ? S.kbd_row[row] : 0xFFu;
    }
    case 0xAA: return S.ppi_c;
    case 0xB5:
        if (S.is_msx2) {
            u8 a = S.rtc_addr & 15u;
            if (a >= 13u)
                return 0xF0u | (S.rtc_bank[0][a] & 15u);
            u8 bank = S.rtc_bank[0][13] & 3u;
            return 0xF0u | (S.rtc_bank[bank][a] & 15u);
        }
        break;
    case 0xFC: case 0xFD: case 0xFE: case 0xFF:
        if (S.is_msx2)
            return (u8)(0xF0u | (S.mapper_page[p - 0xFCu] & 15u));
        break;
    }
    return 0xFFu;
}

static void msx_out(struct z80 *c, u16 port, u8 v)
{
    u8 p = (u8)port;
    if (!S.ext_bios && p == 0x4Fu && (S.ppi_a & 3u) == 0 && c->pc.w >= 0x3E02u && c->pc.w < 0x3F00u) {
        u32 idx = (c->pc.w - 0x3E02u) >> 2;
        if (idx < sizeof(bios_entries) / sizeof(bios_entries[0]))
            hle_bios_dispatch(bios_entries[idx]);
        return;
    }
    if (S.is_msx2 && !S.ext_subrom && p == 0x4Eu && c->pc.w >= 0x3E02u && c->pc.w < 0x3F00u) {
        u32 idx = (c->pc.w - 0x3E02u) >> 2;
        if (idx < sizeof(subrom_entries) / sizeof(subrom_entries[0]))
            hle_subrom_dispatch(subrom_entries[idx]);
        return;
    }
    if (S.has_dsk) {
        if (p == 0x4Bu && c->pc.w >= 0x4010u && c->pc.w < 0x4020u) {
            dsk_phydio();
            return;
        }
        if (p == 0x4Cu && c->pc.w >= 0x4020u && c->pc.w < 0x4030u) {
            c->hl.w = hle_boot_dsk();
            return;
        }
        if (p == 0x4Du && c->pc.w >= 0xF360u && c->pc.w < 0xF370u) {
            dsk_bdos();
            return;
        }
    }
    switch (p) {
    case 0x7C:
        if (S.is_msx2) S.opll.addr = v & 0x3Fu;
        break;
    case 0x7D:
        if (S.is_msx2) opll_write_reg(S.opll.addr, v);
        break;
    case 0x98: vdp_data_write(v); break;
    case 0x99: vdp_ctrl_write(v); break;
    case 0x9A: vdp_pal_write(v);  break;
    case 0x9B: vdp_ind_write(v);  break;
    case 0xA0: S.ay.reg_sel = v & 0x0Fu; break;
    case 0xA1: ay_write_reg(S.ay.reg_sel, v); break;
    case 0xA8:
        if (S.ppi_a != v) {
            S.ppi_a = v;
            rebuild_map();
        }
        break;
    case 0xAA: S.ppi_c = v; break;
    case 0xAB:
        if (!(v & 0x80u)) {
            u8 bit = (u8)(1u << ((v >> 1) & 7u));
            if (v & 1u) S.ppi_c |= bit;
            else        S.ppi_c &= (u8)~bit;
        }
        break;
    case 0xB4:
        if (S.is_msx2) S.rtc_addr = v & 15u;
        break;
    case 0xB5:
        if (S.is_msx2) {
            u8 a = S.rtc_addr & 15u;
            if (a >= 13u) {
                S.rtc_bank[0][a] = v & 15u;
            } else {
                u8 bank = S.rtc_bank[0][13] & 3u;
                S.rtc_bank[bank][a] = v & 15u;
            }
        }
        break;
    case 0xFC: case 0xFD: case 0xFE: case 0xFF:
        if (S.is_msx2) {
            u8 idx = p - 0xFCu;
            u8 pg = v & 15u;
            if (S.mapper_page[idx] != pg) {
                S.mapper_page[idx] = pg;
                rebuild_map();
            }
        }
        break;
    }
}

/* ---- Scanline Renderer: TMS9918A & Yamaha V9938 (SCREEN 0..8, Sprite Mode 1 & 2) ---- */
static void render_sprites_mode1(int y, u8 *row)
{
    int size = (S.vdp_reg[1] & 2u) ? 16 : 8;
    int mag = S.vdp_reg[1] & 1u;
    int h = size << mag;
    const u8 *sat = M->vram + ((S.vdp_reg[5] & 0x7Fu) << 7);
    u32 patterns = (u32)(S.vdp_reg[6] & 7u) << 11;
    u8 taken[256];
    int n = 0, i;
    for (i = 0; i < 32; i++, sat += 4) {
        if (sat[0] == 0xD0u)
            break;
        int r = (u8)(y - sat[0] - 1);
        if (r >= h)
            continue;
        if (n == 4) {
            if (!(S.vdp_stat[0] & 0x40u))
                S.vdp_stat[0] = (u8)((S.vdp_stat[0] & 0xA0u) | 0x40u | i);
            break;
        }
        if (!n++)
            for (int x = 0; x < 256; x++)
                taken[x] = 0;
        r >>= mag;
        u32 a = patterns | ((u32)(size == 16 ? (sat[2] & 0xFCu) : sat[2]) << 3) | (u32)r;
        u32 bits = ((u32)M->vram[a & 0x3FFFu] << 8) | (size == 16 ? M->vram[(a + 16u) & 0x3FFFu] : 0);
        int x0 = sat[1] - ((sat[3] & 0x80u) ? 32 : 0);
        u8 c = sat[3] & 15u;
        for (int k = 0; k < h; k++) {
            if (!(bits & (0x8000u >> (k >> mag))))
                continue;
            int x = x0 + k;
            if ((unsigned)x >= 256u)
                continue;
            if (taken[x] & 1u)
                S.vdp_stat[0] |= 0x20u;
            taken[x] |= 1u;
            if (c && !(taken[x] & 2u)) {
                taken[x] |= 2u;
                row[x] = c;
            }
        }
    }
    if (!(S.vdp_stat[0] & 0x40u))
        S.vdp_stat[0] = (u8)((S.vdp_stat[0] & 0xE0u) | (i < 32 ? i : 31));
}

/* Sprite Mode 2 (V9938: 8 sprites/line, per-line color table at SAT-0x200, CC OR-blending!) */
static void render_sprites_mode2(int vy, u16 *out, int out_w, int is_scr8)
{
    if (S.vdp_reg[8] & 0x02u)           /* SPD: sprites disabled */
        return;
    int size = (S.vdp_reg[1] & 2u) ? 16 : 8;
    int mag = S.vdp_reg[1] & 1u;
    int h = size << mag;
    int tp = (S.vdp_reg[8] & 0x20u) != 0;   /* TP=1: color 0 is solid, not transparent */

    u32 sat_base = (((u32)(S.vdp_reg[11] & 3u) << 15) | ((u32)(S.vdp_reg[5] & 0xFCu) << 7)) & 0x1FFFFu;
    u32 col_base = (((u32)(S.vdp_reg[11] & 3u) << 15) | ((u32)(S.vdp_reg[5] & 0xF8u) << 7)) & 0x1FFFFu;
    u32 pat_base = ((u32)(S.vdp_reg[6] & 0x3Fu) << 11) & 0x1FFFFu;

    u8 spr_col[256];
    u8 spr_owner[256];
    int active_any = 0;
    int n = 0, i;

    for (i = 0; i < 32; i++) {
        const u8 *sat = M->vram + ((sat_base + (u32)i * 4u) & 0x1FFFFu);
        if (sat[0] == 0xD8u)
            break;
        int r = (u8)(vy - sat[0] - 1);
        if (r >= h)
            continue;
        if (n == 8) {
            if (!(S.vdp_stat[0] & 0x40u))
                S.vdp_stat[0] = (u8)((S.vdp_stat[0] & 0xA0u) | 0x40u | i);
            break;
        }
        if (!n++) {
            active_any = 1;
            for (int x = 0; x < 256; x++) {
                spr_col[x] = 0xFFu;
                spr_owner[x] = 0xFFu;
            }
        }
        int row_in_spr = r >> mag;
        u8 attr = M->vram[(col_base + (u32)i * 16u + (u32)row_in_spr) & 0x1FFFFu];
        u8 c = attr & 15u;
        int ec = (attr & 0x80u) != 0;
        int cc = (attr & 0x40u) != 0;
        int ic = (attr & 0x20u) != 0;

        u32 pa = (pat_base + ((u32)(size == 16 ? (sat[2] & 0xFCu) : sat[2]) << 3) + (u32)row_in_spr) & 0x1FFFFu;
        u32 bits = ((u32)M->vram[pa] << 8) | (size == 16 ? M->vram[(pa + 16u) & 0x1FFFFu] : 0);
        int x0 = sat[1] - (ec ? 32 : 0);

        /* Find parent non-CC sprite index for OR-blending */
        u8 group = (u8)i;
        if (cc) {
            for (int p = i - 1; p >= 0; p--) {
                u8 pa_attr = M->vram[(col_base + (u32)p * 16u) & 0x1FFFFu];
                if (!(pa_attr & 0x40u)) { group = (u8)p; break; }
            }
        }

        for (int k = 0; k < h; k++) {
            if (!(bits & (0x8000u >> (k >> mag))))
                continue;
            int x = x0 + k;
            if ((unsigned)x >= 256u)
                continue;
            if (spr_owner[x] == 0xFFu) {
                if (!cc) {
                    spr_owner[x] = group;
                    if (c || tp)
                        spr_col[x] = c;
                } else {
                    /* CC=1 sprite can also draw standalone when preceding non-CC sprite had 0 bit here! */
                    spr_owner[x] = group;
                    if (c || tp)
                        spr_col[x] = c;
                }
            } else if (cc && spr_owner[x] == group) {
                if (c || tp)
                    spr_col[x] = (spr_col[x] == 0xFFu) ? c : (u8)(spr_col[x] | c);
            } else if (!cc && !ic) {
                S.vdp_stat[0] |= 0x20u;
            }
        }
    }
    if (!(S.vdp_stat[0] & 0x40u))
        S.vdp_stat[0] = (u8)((S.vdp_stat[0] & 0xE0u) | (i < 32 ? i : 31));

    if (!active_any || !out)
        return;

    const u16 *sp_pal = is_scr8 ? S.spr8_pal : S.pal;
    if (out_w == 512) {
        for (int x = 0; x < 256; x++) {
            if (spr_col[x] != 0xFFu) {
                u16 px = sp_pal[spr_col[x] & 15u];
                out[x * 2] = px;
                out[x * 2 + 1] = px;
            }
        }
    } else {
        for (int x = 0; x < 256; x++)
            if (spr_col[x] != 0xFFu)
                out[x] = sp_pal[spr_col[x] & 15u];
    }
}

static void render_line(int y, u16 *out)
{
    int out_w = S.cur_w;
    u8 bd_idx = S.vdp_reg[7] & 15u;
    int m = vdp_mode5();
    u16 back = (m == 0x1C) ? S.pal256[S.vdp_reg[7]] : S.pal[bd_idx];

    if (!out)
        return;

    if (!(S.vdp_reg[1] & 0x40u)) {
        for (int x = 0; x < out_w; x++)
            out[x] = back;
        return;
    }

    int vy = S.is_msx2 ? ((y + S.vdp_reg[23]) & 0xFF) : y;

    /* 1. Text 2: 80 columns in 512 px */
    if (m == 0x09) {
        u32 nam_base = ((u32)(S.vdp_reg[2] & 0x7Cu) << 10) & 0x1FFFFu;
        u32 pat_base = ((u32)(S.vdp_reg[4] & 0x3Fu) << 11) & 0x1FFFFu;
        u32 blk_base = (((u32)(S.vdp_reg[10] & 7u) << 14) | ((u32)(S.vdp_reg[3] & 0xF8u) << 6)) & 0x1FFFFu;
        u16 fg = S.pal[(S.vdp_reg[7] >> 4) & 15u];
        u16 bg = S.pal[S.vdp_reg[7] & 15u];
        u16 bfg = S.pal[(S.vdp_reg[12] >> 4) & 15u];
        u16 bbg = S.pal[S.vdp_reg[12] & 15u];
        int blink_on = ((S.frame_no >> 4) & 1u) != 0 && (S.vdp_reg[13] & 0xF0u);

        for (int x = 0; x < 16; x++)
            out[x] = out[496 + x] = bg;
        int row_ch = vy >> 3;
        int line_in_ch = vy & 7;
        for (int k = 0; k < 80; k++) {
            u8 ch = M->vram[(nam_base + (u32)row_ch * 80u + (u32)k) & 0x1FFFFu];
            u8 bits = M->vram[(pat_base + (u32)ch * 8u + (u32)line_in_ch) & 0x1FFFFu];
            u8 bl = M->vram[(blk_base + (u32)row_ch * 10u + (u32)(k >> 3)) & 0x1FFFFu];
            int is_bl = blink_on && ((bl & (0x80u >> (k & 7))) != 0);
            u16 c1 = is_bl ? bfg : fg;
            u16 c0 = is_bl ? bbg : bg;
            for (int i = 0; i < 6; i++)
                out[16 + k * 6 + i] = (bits & (0x80u >> i)) ? c1 : c0;
        }
        return;
    }

    /* 2. Graphic 4 (SCREEN 5): 256 px, 4bpp packed bitmap */
    if (m == 0x0C) {
        u32 page = (S.vdp_reg[2] >> 5) & 3u;
        const u8 *src = M->vram + ((page * 0x8000u + (u32)vy * 128u) & 0x1FFFFu);
        int tp = (S.vdp_reg[8] & 0x20u) != 0;
        for (int x = 0; x < 128; x++) {
            u8 b = src[x];
            u8 hi = b >> 4, lo = b & 15u;
            out[x * 2]     = (hi || tp) ? S.pal[hi] : back;
            out[x * 2 + 1] = (lo || tp) ? S.pal[lo] : back;
        }
        render_sprites_mode2(vy, out, 256, 0);
        return;
    }

    /* 3. Graphic 5 (SCREEN 6): 512 px, 2bpp packed bitmap */
    if (m == 0x10) {
        u32 page = (S.vdp_reg[2] >> 5) & 3u;
        const u8 *src = M->vram + ((page * 0x8000u + (u32)vy * 128u) & 0x1FFFFu);
        int tp = (S.vdp_reg[8] & 0x20u) != 0;
        for (int x = 0; x < 128; x++) {
            u8 b = src[x];
            for (int p = 0; p < 4; p++) {
                u8 c = (b >> ((3 - p) * 2)) & 3u;
                out[x * 4 + p] = (c || tp) ? S.pal[c] : back;
            }
        }
        render_sprites_mode2(vy, out, 512, 0);
        return;
    }

    /* 4. Graphic 6 (SCREEN 7): 512 px, 4bpp packed bitmap */
    if (m == 0x14) {
        u32 page = (S.vdp_reg[2] >> 5) & 1u;
        const u8 *src = M->vram + ((page * 0x10000u + (u32)vy * 256u) & 0x1FFFFu);
        int tp = (S.vdp_reg[8] & 0x20u) != 0;
        for (int x = 0; x < 256; x++) {
            u8 b = src[x];
            u8 hi = b >> 4, lo = b & 15u;
            out[x * 2]     = (hi || tp) ? S.pal[hi] : back;
            out[x * 2 + 1] = (lo || tp) ? S.pal[lo] : back;
        }
        render_sprites_mode2(vy, out, 512, 0);
        return;
    }

    /* 5. Graphic 7 (SCREEN 8): 256 px, 8bpp GGGRRRBB direct RGB */
    if (m == 0x1C) {
        u32 page = (S.vdp_reg[2] >> 5) & 1u;
        const u8 *src = M->vram + ((page * 0x10000u + (u32)vy * 256u) & 0x1FFFFu);
        for (int x = 0; x < 256; x++)
            out[x] = S.pal256[src[x]];
        render_sprites_mode2(vy, out, 256, 1);
        return;
    }

    /* 6. Tile modes: Text 1 (SCREEN 0 40c), Multicolor (SCREEN 3), Graphic 1/2/3 (SCREEN 1/2/4) */
    u8 row[256];
    u32 vmask = vdp_vram_mask();
    u32 nam_off = ((u32)(S.vdp_reg[2] & (S.is_msx2 ? 0x7Fu : 0x0Fu)) << 10) & vmask;
    const u8 *names = M->vram + nam_off;

    if (m == 0x01) {                    /* Text 1 (40 cols) */
        const u8 *p = M->vram + ((((u32)(S.vdp_reg[4] & (S.is_msx2 ? 0x3Fu : 7u)) << 11) + (vy & 7)) & vmask);
        const u8 *n = names + ((vy >> 3) & 31) * 40;
        u8 fg = S.vdp_reg[7] >> 4, bg = S.vdp_reg[7] & 15u;
        for (int x = 0; x < 8; x++)
            row[x] = row[248 + x] = 0;
        for (int k = 0; k < 40; k++) {
            u8 bits = p[n[k] * 8];
            for (int i = 0; i < 6; i++)
                row[8 + k * 6 + i] = (bits & (0x80u >> i)) ? fg : bg;
        }
        for (int x = 0; x < 256; x++)
            out[x] = row[x] ? S.pal[row[x]] : back;
        return;
    }

    if (m == 0x02) {                    /* Multicolor (SCREEN 3) */
        const u8 *p = M->vram + ((((u32)(S.vdp_reg[4] & 7u) << 11) + ((vy >> 3) & 3) * 2 + ((vy >> 2) & 1)) & vmask);
        const u8 *n = names + ((vy >> 3) & 31) * 32;
        for (int k = 0; k < 32; k++) {
            u8 v = p[n[k] * 8];
            for (int i = 0; i < 4; i++) {
                row[k * 8 + i] = v >> 4;
                row[k * 8 + 4 + i] = v & 15u;
            }
        }
    } else {                            /* Graphic 1 (0x00), Graphic 2 (0x04), Graphic 3 (0x08) */
        const u8 *n = names + ((vy >> 3) & 31) * 32;
        int is_g23 = (m == 0x04 || m == 0x08);
        for (int k = 0; k < 32; k++) {
            u8 bits, c;
            if (is_g23) {
                u32 idx = (u32)((((vy >> 6) & 3) << 11) | (n[k] << 3) | (vy & 7));
                u32 pb = S.is_msx2 ? ((u32)(S.vdp_reg[4] & 0x3Cu) << 11) : ((u32)(S.vdp_reg[4] & 4u) << 11);
                u32 cb = S.is_msx2 ? (((u32)(S.vdp_reg[10] & 7u) << 14) | ((u32)(S.vdp_reg[3] & 0x80u) << 6))
                                   : ((u32)(S.vdp_reg[3] & 0x80u) << 6);
                bits = M->vram[(pb | (idx & (((u32)(S.vdp_reg[4] & 3u) << 11) | 0x7FFu))) & vmask];
                c    = M->vram[(cb | (idx & (((u32)(S.vdp_reg[3] & 0x7Fu) << 6) | 0x3Fu))) & vmask];
            } else {
                u32 pb = (u32)(S.vdp_reg[4] & (S.is_msx2 ? 0x3Fu : 7u)) << 11;
                u32 cb = S.is_msx2 ? (((u32)(S.vdp_reg[10] & 7u) << 14) | ((u32)S.vdp_reg[3] << 6))
                                   : ((u32)S.vdp_reg[3] << 6);
                bits = M->vram[(pb + n[k] * 8 + (vy & 7)) & vmask];
                c    = M->vram[(cb + (n[k] >> 3)) & vmask];
            }
            u8 fg = c >> 4, bg = c & 15u;
            for (int i = 0; i < 8; i++)
                row[k * 8 + i] = (bits & (0x80u >> i)) ? fg : bg;
        }
    }

    if (m == 0x08) {                    /* Graphic 3 (SCREEN 4): Sprite Mode 2 */
        for (int x = 0; x < 256; x++)
            out[x] = row[x] ? S.pal[row[x]] : back;
        render_sprites_mode2(vy, out, 256, 0);
    } else {                            /* Sprite Mode 1 */
        render_sprites_mode1(y, row);
        for (int x = 0; x < 256; x++)
            out[x] = row[x] ? S.pal[row[x]] : back;
    }
}

/* ---- Mapper detection & Public API ---- */
int msx_is_cart(const u8 *head, u32 got, u32 total_size)
{
    if (got < 16 || total_size < 0x2000u || total_size > 0x400000u)
        return 0;
    if (head[0] == 'A' && head[1] == 'B') {
        u16 init = (u16)(head[2] | ((u16)head[3] << 8));
        if (init >= 0x4000u || head[4] || head[5] || head[6] || head[7])
            return 1;
    }
    return 0;
}

static u8 detect_mapper(const u8 *rom, u32 size)
{
    if (size <= 0x8000u)
        return MAP_PLAIN;
    if (size <= 0x10000u) {
        int st = 0;
        for (u32 i = 0; i + 2 < size; i++) {
            if (rom[i] == 0x32u) {
                u16 a = (u16)(rom[i + 1] | ((u16)rom[i + 2] << 8));
                if (a >= 0x5000u && a < 0xC000u)
                    st++;
            }
        }
        if (st < 2)
            return MAP_PLAIN;
    }

    u32 c4000 = 0, c5000 = 0, c6000 = 0, c6800 = 0, c7000 = 0, c7800 = 0, c8000 = 0, c9000 = 0, cA000 = 0, cB000 = 0;
    for (u32 i = 0; i + 2 < size; i++) {
        if (rom[i] != 0x32u)
            continue;
        u16 a = (u16)(rom[i + 1] | ((u16)rom[i + 2] << 8));
        if (a >= 0x5000u && a < 0x5800u)      c5000++;
        else if (a >= 0x4000u && a < 0x6000u) c4000++;
        else if (a >= 0x6000u && a < 0x6800u) c6000++;
        else if (a >= 0x6800u && a < 0x7000u) c6800++;
        else if (a >= 0x7000u && a < 0x7800u) c7000++;
        else if (a >= 0x7800u && a < 0x8000u) c7800++;
        else if (a >= 0x9000u && a < 0x9800u) c9000++;
        else if (a >= 0x8000u && a < 0xA000u) c8000++;
        else if (a >= 0xB000u && a < 0xB800u) cB000++;
        else if (a >= 0xA000u && a < 0xC000u) cA000++;
    }

    if (c6800 || c7800)
        return MAP_ASCII8;
    if (c5000 || c9000 || cB000)
        return MAP_KONAMI_SCC;
    if (c8000 || cA000) {
        if (!c6000 && !cA000 && size >= 0x4000u) {
            int nz2000 = 0;
            for (u32 i = 0x2000u; i < 0x4000u; i++)
                if (rom[i]) { nz2000 = 1; break; }
            if (!nz2000)
                return MAP_GENERIC16;
        }
        return c4000 ? MAP_GENERIC8 : MAP_KONAMI4;
    }
    if (c7000 && !c6000 && size >= 0x4000u) {
        int nz2000 = 0;
        for (u32 i = 0x2000u; i < 0x4000u; i++)
            if (rom[i]) { nz2000 = 1; break; }
        if (nz2000) {
            for (u32 i = 0; i + 6 < size && i < 0x4000u; i++) {
                if (rom[i] == 0x32u && rom[i + 1] == 0x00u && rom[i + 2] == 0x70u && rom[i + 3] == 0x21u) {
                    if (rom[i + 5] >= 0x60u && rom[i + 5] < 0x80u)
                        return MAP_KONAMI_SCC;
                    if (rom[i + 5] >= 0x80u && rom[i + 5] < 0xC0u)
                        return MAP_ASCII16;
                }
            }
        }
        return MAP_ASCII16;
    }
    if (c6000 && !c7000)
        return MAP_GENERIC8;
    return MAP_ASCII16;
}

static int ends_with_ci(const char *name, const char *ext)
{
    if (!name) return 0;
    int n = 0, e = 0;
    while (name[n]) n++;
    while (ext[e]) e++;
    if (n < e) return 0;
    for (int i = 0; i < e; i++) {
        char c = name[n - e + i];
        if (c >= 'A' && c <= 'Z') c = (char)(c + 32);
        if (c != ext[i]) return 0;
    }
    return 1;
}

static void fmt_info(void)
{
    static const char *const mnames[] = {
        "ROM", "Konami MegaROM", "Konami SCC MegaROM",
        "ASCII8 MegaROM", "ASCII16 MegaROM", "Generic 8K MegaROM", "Generic 16K MegaROM"
    };
    char *p = info_buf;
    const char *h;
    if (S.is_msx2)
        h = S.ext_bios ? "MSX2 (V9938), " : "MSX2 (V9938, built-in BIOS), ";
    else
        h = S.ext_bios ? "MSX1, " : "MSX1 (built-in BIOS), ";
    while (*h) *p++ = *h++;
    const char *mn = (!S.has_cart && S.has_dsk) ? "Floppy Disk" : mnames[S.mapper];
    while (*mn) *p++ = *mn++;
    *p++ = ' ';
    u32 sz = (!S.has_cart && S.has_dsk) ? S.dsk_size : S.rom_size;
    u32 kb = (sz + 1023u) >> 10;
    char tmp[16];
    int n = 0;
    do { tmp[n++] = (char)('0' + kb % 10); kb /= 10; } while (kb);
    while (n--) *p++ = tmp[n];
    const char *suf = " KB";
    while (*suf) *p++ = *suf++;
    *p = 0;
}

static const char *msx_load_common(int msx2, const u8 *bios32k, const u8 *subrom16k, u8 *media, u32 media_size, const char *name)
{
    if (!media || media_size < 0x2000u)
        return msx2 ? "too small for an MSX2 cartridge or disk (at least 8 KB)"
                    : "too small for an MSX1 cartridge (at least 8 KB)";
    if (media_size > 0x400000u)
        return "too large for an MSX image (over 4 MB)";

    for (u32 i = 0; i < sizeof(*M); i++)
        ((u8 *)M)[i] = 0;
    for (u32 i = 0; i < sizeof(M->open_bus); i++)
        M->open_bus[i] = 0xFFu;
    for (u32 i = 0; i < sizeof(S); i++)
        ((u8 *)&S)[i] = 0;

    S.is_msx2 = (u8)(msx2 ? 1 : 0);

    int is_dsk = msx2 && (ends_with_ci(name, ".dsk") ||
                          ((media_size == 368640u || media_size == 737280u) &&
                           !(media[0] == 'A' && media[1] == 'B') &&
                           !(media_size >= 0x4002u && media[0x4000] == 'A' && media[0x4001] == 'B')));

    if (is_dsk) {
        if (media_size > DSK_MAX)
            return "MSX2 .dsk image exceeds 720 KB";
        for (u32 i = 0; i < media_size; i++)
            M->dsk[i] = media[i];
        S.has_dsk = 1;
        S.dsk_size = media_size;
    } else {
        int ab0 = media[0] == 'A' && media[1] == 'B';
        int ab4 = media_size >= 0x4010u && media[0x4000] == 'A' && media[0x4001] == 'B';
        int ab8 = media_size >= 0x8010u && media[0x8000] == 'A' && media[0x8001] == 'B';
        if (!ab0 && !ab4 && !ab8)
            return msx2 ? "not an MSX2 ROM cartridge ('AB' header) or .dsk floppy image"
                        : "not an MSX1 ROM cartridge (missing 'AB' header)";

        S.has_cart = 1;
        S.rom = media;
        S.rom_size = media_size;
        S.banks8k = (media_size + 0x1FFFu) >> 13;
        S.banks16k = (media_size + 0x3FFFu) >> 14;
        if (!S.banks8k) S.banks8k = 1;
        if (!S.banks16k) S.banks16k = 1;

        u32 ab_off = ab0 ? 0u : ab4 ? 0x4000u : 0x8000u;
        S.cart_init = (u16)(media[ab_off + 2] | ((u16)media[ab_off + 3] << 8));
        S.mapper = detect_mapper(media, media_size);

        if (S.mapper == MAP_PLAIN) {
            if (ab0) {
                if (S.cart_init < 0x4000u && media_size >= 0x8000u)
                    S.cart_base = 0x0000u;
                else if (S.cart_init >= 0x8000u && media_size <= 0x4000u)
                    S.cart_base = 0x8000u;
                else
                    S.cart_base = 0x4000u;
            } else if (ab4) {
                S.cart_base = (S.cart_init >= 0x8000u) ? 0x4000u : 0x0000u;
            } else {
                S.cart_base = 0x0000u;
            }
        } else {
            S.cart_base = 0x4000u;
        }
    }

    if (subrom16k && msx2) {
        for (u32 i = 0; i < 0x4000u; i++)
            M->subrom[i] = subrom16k[i];
        S.ext_subrom = 1;
    } else {
        S.ext_subrom = 0;
    }

    if (bios32k) {
        for (u32 i = 0; i < 0x8000u; i++)
            M->bios[i] = bios32k[i];
        S.ext_bios = 1;
    } else {
        build_msx_bios();
        S.ext_bios = 0;
    }
    build_clean_sub_and_ext_roms();

    msx_reset();
    fmt_info();
    return 0;
}

const char *msx_load(const u8 *bios32k, u8 *cart, u32 cart_size)
{
    return msx_load_common(0, bios32k, 0, cart, cart_size, 0);
}

const char *msx2_load(const u8 *bios32k, const u8 *subrom16k, u8 *media, u32 media_size, const char *name)
{
    return msx_load_common(1, bios32k, subrom16k, media, media_size, name);
}

void msx_reset(void)
{
    z80_init(&S.cpu);
    S.cpu.read = cpu_read;
    S.cpu.write = cpu_write;
    S.cpu.in = msx_in;
    S.cpu.out = msx_out;
    S.cpu.trap = -1;

    for (u32 i = 0; i < sizeof(M->ram); i++)
        M->ram[i] = 0;
    for (u32 i = 0; i < sizeof(M->vram); i++)
        M->vram[i] = 0;
    for (u32 i = 0; i < sizeof(M->exp_vram); i++)
        M->exp_vram[i] = 0;
    for (int i = 0; i < 11; i++)
        S.kbd_hid[i] = S.kbd_row[i] = 0xFFu;

    S.ppi_a = 0x00u;
    S.ppi_c = 0x00u;
    S.slot3_sub = 0x00u;
    S.mapper_page[0] = 3;
    S.mapper_page[1] = 2;
    S.mapper_page[2] = 1;
    S.mapper_page[3] = 0;

    S.vdp_addr = 0;
    S.vdp_first = S.vdp_latch = S.vdp_buf = 0;
    S.pal_first = S.pal_latch = 0;
    for (int i = 0; i < 64; i++)
        S.vdp_reg[i] = 0;
    for (int i = 0; i < 16; i++)
        S.vdp_stat[i] = 0;
    S.cur_w = MSX_W;
    S.cur_h = MSX_H;
    S.frame_no = 0;
    for (u32 i = 0; i < sizeof(S.cmd); i++)
        ((u8 *)&S.cmd)[i] = 0;

    /* RP5C01 RTC valid BCD time (2026-11-20 12:00:00) + MSX2 CMOS defaults */
    for (u32 i = 0; i < sizeof(S.rtc_bank); i++)
        ((u8 *)S.rtc_bank)[i] = 0;
    S.rtc_bank[0][5] = 2; S.rtc_bank[0][7] = 0; S.rtc_bank[0][8] = 2;   /* 12h, day 20 */
    S.rtc_bank[0][9] = 1; S.rtc_bank[0][10] = 1;                        /* Nov */
    S.rtc_bank[0][11] = 6; S.rtc_bank[0][12] = 4;                       /* 1980+46 = 2026 */
    S.rtc_bank[0][13] = 0x08u;                                          /* Timer enable */
    S.rtc_bank[2][0] = 0x0Au;                                           /* MSX2 valid CMOS ID */

    if (S.mapper == MAP_ASCII16 || S.mapper == MAP_GENERIC16) {
        S.bank[0] = 0; S.bank[1] = 0;
    } else if (S.mapper == MAP_ASCII8) {
        S.bank[0] = S.bank[1] = S.bank[2] = S.bank[3] = 0;
    } else {
        S.bank[0] = 0; S.bank[1] = 1; S.bank[2] = 2; S.bank[3] = 3;
    }
    S.scc_mapped = 0;
    for (u32 i = 0; i < sizeof(S.scc); i++)
        ((u8 *)&S.scc)[i] = 0;
    for (u32 i = 0; i < sizeof(S.ay); i++)
        ((u8 *)&S.ay)[i] = 0;
    S.ay.reg[7] = 0xBFu;
    S.ay.reg[15] = 0x0Fu;
    S.ay.lfsr = 1u;

    for (u32 i = 0; i < sizeof(S.opll); i++)
        ((u8 *)&S.opll)[i] = 0;
    S.opll.lfsr = 1u;

    vdp_init_palettes();
    rebuild_map();
    z80_reset(&S.cpu);
}

void msx_frame(u16 pad, u16 *picture)
{
    S.pad_state = pad;
    update_kbd_rows();
    S.audio_count = 0;
    S.audio_last_cyc = S.cpu.cycles;

    /* Determine frame resolution from current VDP mode */
    int m = vdp_mode5();
    S.cur_w = (m == 0x09 || m == 0x10 || m == 0x14) ? 512 : 256;
    S.cur_h = (S.is_msx2 && (S.vdp_reg[9] & 0x80u)) ? 212 : 192;

    S.vdp_stat[2] &= (u8)~0x40u;        /* VR = 0 during active display */

    for (int line = 0; line < LINES; line++) {
        if (line < S.cur_h)
            render_line(line, picture ? picture + line * S.cur_w : 0);

        /* V9938 Horizontal Line Interrupt (R#19 compared against scrolled VRAM line) */
        if (S.is_msx2 && ((line + S.vdp_reg[23]) & 0xFF) == S.vdp_reg[19]) {
            S.vdp_stat[1] |= 0x01u;
            vdp_update_irq();
        }

        z80_run(&S.cpu, line * LINE_T + 2);
        if (line == S.cur_h) {
            S.vdp_stat[0] |= 0x80u;     /* F = 1 (VBlank) */
            S.vdp_stat[2] |= 0x40u;     /* VR = 1 (VBlank) */
            vdp_update_irq();
        }
        z80_run(&S.cpu, (line + 1) * LINE_T);
    }
    audio_catch_up();
    S.cpu.cycles -= FRAME_T;
    S.frame_no++;
}

int msx_width(void)  { return S.cur_w ? S.cur_w : MSX_W; }
int msx_height(void) { return S.cur_h ? S.cur_h : MSX_H; }

const char *msx_info(void) { return info_buf; }

u8 *msx_save_ram(u32 *size, int *battery)
{
    *size = sizeof(M->sav_dummy);
    *battery = 0;
    return M->sav_dummy;
}

int msx_save_changed(void) { return 0; }

int msx_jammed(void)
{
    return S.cpu.halted && !S.cpu.iff1;
}

void msx_audio_rate(u32 hz)
{
    S.sample_rate = hz;
    S.audio_frac = 0;
    S.audio_count = 0;
    S.audio_last_cyc = S.cpu.cycles;
}

int msx_audio(s16 *out, int max)
{
    int n = S.audio_count < max ? S.audio_count : max;
    for (int i = 0; i < n; i++)
        out[i] = M->audio_ring[i];
    S.audio_count = 0;
    return n;
}
