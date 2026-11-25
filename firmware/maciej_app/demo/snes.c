/* A Super Nintendo / Super Famicom (65C816 + S-PPU + SPC700 + S-DSP): see snes.h. */
#pragma GCC optimize("O2")
#include "snes.h"
#ifndef SNES_HOST
#include "hw.h"
#endif

/* 65C816 Processor Status (P) bits */
#define FN 0x80u
#define FV 0x40u
#define FM 0x20u
#define FX 0x10u
#define FD 0x08u
#define FI 0x04u
#define FZ 0x02u
#define FC 0x01u

/* SPC700 PSW bits */
#define SP_N 0x80u
#define SP_V 0x40u
#define SP_P 0x20u
#define SP_B 0x10u
#define SP_H 0x08u
#define SP_I 0x04u
#define SP_Z 0x02u
#define SP_C 0x01u

enum { MAP_LOROM = 0, MAP_HIROM = 1, MAP_EXHIROM = 2 };

struct snes_dma_ch {
    u8 dmap;            /* $43x0 */
    u8 bbad;            /* $43x1 */
    u16 a1t;            /* $43x2..$43x3 */
    u8 a1b;             /* $43x4 */
    u16 das;            /* $43x5..$43x6 (byte count / indirect HDMA addr) */
    u8 dasb;            /* $43x7 (indirect HDMA bank) */
    u16 a2a;            /* $43x8..$43x9 (HDMA table current address) */
    u8 nltr;            /* $43xA (HDMA line counter & repeat) */
    u8 unused;          /* $43xB */
    u8 hdma_do_xfer;
    u8 hdma_terminated;
};

struct snes_voice {
    s16 brr_buf[16];    /* current decoded 16-sample BRR ring */
    s16 prev1, prev2;
    u16 brr_addr;
    u8 brr_hdr;
    u8 buf_pos;         /* 0..15 */
    u16 interp_pos;     /* 16-bit fractional position (step 0x1000 = 1.0) */
    s16 env;            /* 0..0x7FF */
    u8 env_mode;        /* 0=release, 1=attack, 2=decay, 3=sustain */
    u8 key_latch;
    s16 last_out;
};

/* All large state lives in EMU_RAM_PHYS (0x03400000, 9.5 MB cached KSEG0) */
struct snes_mem {
    u8 wram[0x20000];           /* 128 KB Work RAM */
    u8 vram[0x10000];           /* 64 KB Video RAM */
    u16 cgram[256];             /* 256 x 15-bit BGR555 palette RAM */
    u8 oam[544];                /* 512 B low + 32 B high OAM */
    u8 apuram[0x10000];         /* 64 KB SPC700 RAM */
    u8 sram[0x20000];           /* up to 128 KB battery SRAM (.sav) */

    /* 2048 x 8 KB fast page pointers covering the 16 MB 65C816 address space */
    const u8 *page_r[2048];
    u8 *page_w[2048];

    /* Decoded planar -> nibble/byte tile caches (updated lazily via dirty flags) */
    u32 bp_lut[256];
    u32 bp_lut_flip[256];
    u8 vram_dirty2[4096];
    u8 vram_dirty4[2048];
    u8 vram_dirty8[1024];
    u32 tile2_cache[4096][8];   /* 128 KB */
    u32 tile4_cache[2048][8];   /* 64 KB */
    u8 tile8_cache[1024][64];   /* 64 KB */
    u8 bright_lut[16][32];      /* Master brightness 0..15 * 5-bit channel */

    s16 audio_ring[4096];

    u8 spr_yh[128][2];          /* each sprite's first line and height (0: off the left edge), for the line
                                   scan; from OAM and OBSEL when S.oam_dirty */
    u8 spr_line_n[240];         /* each line's sprites, at most 32 in the order of the scan: how many ... */
    u8 spr_line[240][32];       /* ... and which -- made with spr_yh, and again when the scan's first sprite
                                   (S.spr_first) changes */
};

#ifdef SNES_HOST
static struct snes_mem snes_mem_buf;
#define M (&snes_mem_buf)
#else
#define M ((struct snes_mem *)KSEG0(EMU_RAM_PHYS))
#endif

static struct {
    /* Cartridge */
    u8 *rom;
    u32 rom_size, sram_size, sram_mask;
    u8 mapper, is_pal, fastrom, sram_dirty;

    /* 65C816 CPU */
    u16 c, x, y, s, d, pc;
    u8 pbr, dbr, p, e;
    u8 stopped, waiting, irq_line, nmi_pending;
    s32 master_cyc, line_end_mc;

    /* S-CPU I/O ($4016..$421F) */
    u8 nmitimen;                /* $4200 */
    u8 wrio;                    /* $4201 */
    u8 wrdivb, wrmpya, wrmpyb;
    u16 wrdiva, rddiv, rdmpy;
    u16 htime, vtime;
    u8 memsel;                  /* $420D */
    u8 mdr;                     /* 5A22 S-CPU Memory Data Register (open bus) */
    u8 rdnmi, timeup, hvbjoy;
    u8 irq_fired_this_line;
    u16 joy1_hw, joy1_shift;
    u8 joy_strobe;
    u32 wmadd;                  /* $2181..$2183 (17-bit WRAM port) */
    struct snes_dma_ch dma[8];

    /* S-PPU ($2100..$213F) */
    u8 inidisp;                 /* $2100 */
    u8 obsel;                   /* $2101 */
    u16 oamadd_reload, oam_addr;/* $2102..$2103 */
    u8 oam_latch, oam_prio;
    u8 bgmode;                  /* $2105 */
    u8 mosaic;                  /* $2106 */
    u8 bg_sc[4];                /* $2107..$210A */
    u8 bg12nba, bg34nba;        /* $210B..$210C */
    u16 bg_hofs[4], bg_vofs[4]; /* $210D..$2114 */
    u8 bg_old_latch, bghofs_latch;
    u8 vmain;                   /* $2115 */
    u16 vmadd, vram_prefetch;   /* $2116..$2117 */
    u8 m7sel, m7_latch;         /* $211A */
    s16 m7a, m7b, m7c, m7d, m7x, m7y, m7hofs, m7vofs;
    s32 mpy_res;                /* $2134..$2136 (24-bit M7A * (s8)(M7B>>8)) */
    u16 cgadd;                  /* $2121 (byte index 0..511) */
    u8 cg_latch;
    u8 w12sel, w34sel, wobjsel; /* $2123..$2125 */
    u8 wh0, wh1, wh2, wh3;      /* $2126..$2129 */
    u8 wbglog, wobjlog;         /* $212A..$212B */
    u8 tm, ts, tmw, tsw;        /* $212C..$212F */
    u8 cgwsel, cgadsub;         /* $2130..$2131 */
    u16 fixed_col;              /* $2132 15-bit BGR555 */
    u8 setini;                  /* $2133 */
    u16 h_latch, v_latch;
    u8 hv_flip_h, hv_flip_v, stat78;
    int cur_line, out_h;

    /* SPC700 + S-DSP */
    u16 spc_pc;
    u8 spc_a, spc_x, spc_y, spc_sp, spc_psw;
    u8 spc_stopped;
    u8 cpu_to_apu[4];           /* written by 65C816 ($2140..$2143), read by SPC700 ($F4..$F7) */
    u8 apu_to_cpu[4];           /* written by SPC700 ($F4..$F7), read by 65C816 ($2140..$2143) */
    u8 spc_ctrl;                /* $F1 */
    u8 spc_dsp_addr;            /* $F2 */
    u8 spc_t_div[3];            /* $FA..$FC */
    u8 spc_t_out[3];            /* $FD..$FF (4-bit) */
    u16 spc_t_stage1[3];
    u8 spc_t_stage2[3];
    s32 apu_last_mc;
    s32 spc_cyc_avail;          /* accumulated SPC700 cycle budget (preserves fractional debt across $214x polls) */
    u32 apu_mc_rem;             /* master_cyc * 64 -> 1.024 MHz SPC700 cycles */
    u32 dsp_spc_acc;            /* 32 SPC700 cycles per 32 kHz S-DSP sample */

    u8 dsp[128];
    struct snes_voice voice[8];
    u32 dsp_counter;            /* 0..30719 envelope rate counter */
    s16 noise_val;
    u16 echo_off, echo_len;
    s16 fir_buf_l[8], fir_buf_r[8];
    u8 fir_idx;

    /* 32 kHz -> 48 kHz output resampler */
    u32 sample_rate, resamp_acc;
    s16 prev_mono;
    int audio_count;

    /* DSP-1 (cartridge types 03h..05h: Super Mario Kart, Pilotwings ...) */
    struct {
        u8 map;                 /* 0: none; its registers' place: 1 HiROM, 2 LoROM up to 1 MB, 3 LoROM 2 MB */
        u8 state, cmd;          /* 0 waits for a command, 1 takes its parameters, 2 gives its results */
        u16 sr, dr;             /* status (RQM 8000h, DRS 1000h, DRC 0400h) and data registers */
        u16 pos;                /* the word under way */
        s16 in[8], out[4];
        /* the projection that command 02h sets up for 06h, 0Ah and 0Eh */
        s16 centre_x, centre_y, v_offset, vplane_c, vplane_e;
        s16 sin_aas, cos_aas, sin_azs, cos_azs, sin_azs_cl, cos_azs_cl;
        s16 sec1_c, sec1_e, sec2_c, sec2_e;
        s16 nx, ny, nz, gx, gy, gz, les_c, les_e, les;
        s16 mat[3][3][3];       /* the attitude matrices A, B, C */
    } d1;

    u8 oam_dirty;               /* OAM or OBSEL written since M->spr_yh was worked out */
    u8 spr_first;               /* the sprite the scan started from when M->spr_line was made */
} S;

static char info_buf[96];

/* Clean-room 64-byte SPC700 IPL boot loader ($FFC0..$FFFF):
   Zeroes $00..$EF, sets SP=$EF, writes $AA/$BB to ports 0/1, waits for $CC on
   port 0, copies blocks into APURAM, and jumps to entry when count bit0 != 0 after 0. */
static const u8 spc_ipl_rom[64] = {
    0xCD, 0xEF, 0xBD, 0xE8, 0x00, 0xC6, 0x1D, 0xD0,
    0xFC, 0x8F, 0xAA, 0xF4, 0x8F, 0xBB, 0xF5, 0x78,
    0xCC, 0xF4, 0xD0, 0xFB, 0x2F, 0x19, 0xEB, 0xF4,
    0xD0, 0xFC, 0x7E, 0xF4, 0xD0, 0x0B, 0xE4, 0xF5,
    0xCB, 0xF4, 0xD7, 0x00, 0xFC, 0xD0, 0xF3, 0xAB,
    0x01, 0x10, 0xEF, 0x7E, 0xF4, 0x10, 0xEB, 0xBA,
    0xF6, 0xDA, 0x00, 0xBA, 0xF4, 0xC4, 0xF4, 0xDD,
    0x5D, 0xD0, 0xDB, 0x1F, 0x00, 0x00, 0xC0, 0xFF
};

/* =====================================================================
 * Sony S-DSP (8-voice BRR ADPCM, Gaussian interp, ADSR/GAIN, Echo FIR)
 * ===================================================================== */
static const s16 s_gauss[512] = {
       0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
       1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    2,    2,    2,    2,    2,
       2,    2,    3,    3,    3,    3,    3,    4,    4,    4,    4,    4,    5,    5,    5,    5,
       6,    6,    6,    6,    7,    7,    7,    8,    8,    8,    9,    9,    9,   10,   10,   10,
      11,   11,   11,   12,   12,   13,   13,   14,   14,   15,   15,   15,   16,   16,   17,   17,
      18,   19,   19,   20,   20,   21,   21,   22,   23,   23,   24,   24,   25,   26,   27,   27,
      28,   29,   29,   30,   31,   32,   32,   33,   34,   35,   36,   36,   37,   38,   39,   40,
      41,   42,   43,   44,   45,   46,   47,   48,   49,   50,   51,   52,   53,   54,   55,   56,
      58,   59,   60,   61,   62,   64,   65,   66,   67,   69,   70,   71,   73,   74,   76,   77,
      78,   80,   81,   83,   84,   86,   87,   89,   90,   92,   94,   95,   97,   99,  100,  102,
     104,  106,  107,  109,  111,  113,  115,  117,  118,  120,  122,  124,  126,  128,  130,  132,
     134,  137,  139,  141,  143,  145,  147,  150,  152,  154,  156,  159,  161,  163,  166,  168,
     171,  173,  175,  178,  180,  183,  186,  188,  191,  193,  196,  199,  201,  204,  207,  210,
     212,  215,  218,  221,  224,  227,  230,  233,  236,  239,  242,  245,  248,  251,  254,  257,
     260,  263,  267,  270,  273,  276,  280,  283,  286,  290,  293,  297,  300,  304,  307,  311,
     314,  318,  321,  325,  328,  332,  336,  339,  343,  347,  351,  354,  358,  362,  366,  370,
     374,  378,  381,  385,  389,  393,  397,  401,  405,  410,  414,  418,  422,  426,  430,  434,
     439,  443,  447,  451,  456,  460,  464,  469,  473,  477,  482,  486,  491,  495,  499,  504,
     508,  513,  517,  522,  527,  531,  536,  540,  545,  550,  554,  559,  563,  568,  573,  577,
     582,  587,  592,  596,  601,  606,  611,  615,  620,  625,  630,  635,  640,  644,  649,  654,
     659,  664,  669,  674,  678,  683,  688,  693,  698,  703,  708,  713,  718,  723,  728,  732,
     737,  742,  747,  752,  757,  762,  767,  772,  777,  782,  787,  792,  797,  802,  806,  811,
     816,  821,  826,  831,  836,  841,  846,  851,  855,  860,  865,  870,  875,  880,  884,  889,
     894,  899,  904,  908,  913,  918,  923,  927,  932,  937,  941,  946,  951,  955,  960,  965,
     969,  974,  978,  983,  988,  992,  997, 1001, 1005, 1010, 1014, 1019, 1023, 1027, 1032, 1036,
    1040, 1045, 1049, 1053, 1057, 1061, 1066, 1070, 1074, 1078, 1082, 1086, 1090, 1094, 1098, 1102,
    1106, 1109, 1113, 1117, 1121, 1125, 1128, 1132, 1136, 1139, 1143, 1146, 1150, 1153, 1157, 1160,
    1164, 1167, 1170, 1174, 1177, 1180, 1183, 1186, 1190, 1193, 1196, 1199, 1202, 1205, 1207, 1210,
    1213, 1216, 1219, 1221, 1224, 1227, 1229, 1232, 1234, 1237, 1239, 1241, 1244, 1246, 1248, 1251,
    1253, 1255, 1257, 1259, 1261, 1263, 1265, 1267, 1269, 1270, 1272, 1274, 1275, 1277, 1279, 1280,
    1282, 1283, 1284, 1286, 1287, 1288, 1290, 1291, 1292, 1293, 1294, 1295, 1296, 1297, 1297, 1298,
    1299, 1300, 1300, 1301, 1302, 1302, 1303, 1303, 1303, 1304, 1304, 1304, 1304, 1304, 1305, 1305
};

static const u16 dsp_rate_period[32] = {
    0, 2048, 1536, 1280, 1024, 768, 640, 512,
    384, 320, 256, 192, 160, 128, 96, 80,
    64, 48, 40, 32, 24, 20, 16, 12,
    10, 8, 6, 5, 4, 3, 2, 1
};

static const u16 dsp_rate_offset[32] = {
    0, 0, 1040, 536, 0, 1040, 536, 0,
    1040, 536, 0, 1040, 536, 0, 1040, 536,
    0, 1040, 536, 0, 1040, 536, 0, 1040,
    536, 0, 1040, 536, 0, 1040, 0, 0
};

static inline s16 clamp16(s32 x)
{
    return (s16)(x > 32767 ? 32767 : x < -32768 ? -32768 : x);
}

static inline int dsp_rate_hit(int r)
{
    if (r <= 0)
        return 0;
    return ((S.dsp_counter + dsp_rate_offset[r & 31]) % dsp_rate_period[r & 31]) == 0;
}

static void brr_decode_block(struct snes_voice *v, int ch)
{
    u8 hdr = M->apuram[v->brr_addr];
    v->brr_hdr = hdr;
    int shift = hdr >> 4;
    int filter = (hdr >> 2) & 3;
    for (int i = 0; i < 8; i++) {
        u8 b = M->apuram[(u16)(v->brr_addr + 1u + i)];
        for (int n = 0; n < 2; n++) {
            s32 s = (n == 0) ? (s32)(s8)(b & 0xF0u) >> 4 : (s32)(s8)((b << 4) & 0xF0u) >> 4;
            if (shift <= 12)
                s = (s << shift) >> 1;
            else
                s = (s < 0) ? -2048 : 0;
            s32 p1 = v->prev1, p2 = v->prev2;
            switch (filter) {
            case 1: s += p1 + ((-p1) >> 4); break;
            case 2: s += (p1 << 1) + ((-p1 * 3) >> 5) - p2 + (p2 >> 4); break;
            case 3: s += (p1 << 1) + ((-p1 * 13) >> 6) - p2 + ((p2 * 3) >> 4); break;
            }
            if (s > 32767) s = 32767;
            else if (s < -32768) s = -32768;
            s = (s16)((u16)s << 1) >> 1;    /* 15-bit sign-wrap as real S-DSP */
            v->prev2 = v->prev1;
            v->prev1 = (s16)s;
            v->brr_buf[i * 2 + n] = (s16)s;
        }
    }
    if (hdr & 1u) {                         /* END bit */
        S.dsp[0x7C] |= (u8)(1u << ch);
        if (hdr & 2u) {                     /* LOOP bit */
            u16 dir = (u16)((u16)S.dsp[0x5D] << 8) + (u16)S.dsp[(ch << 4) | 4] * 4u;
            v->brr_addr = (u16)(M->apuram[(u16)(dir + 2u)] | ((u16)M->apuram[(u16)(dir + 3u)] << 8));
        } else {
            v->env_mode = 0;
            v->env = 0;
        }
    } else {
        v->brr_addr = (u16)(v->brr_addr + 9u);
    }
}

static void dsp_key_on(int ch)
{
    struct snes_voice *v = &S.voice[ch];
    u16 dir = (u16)((u16)S.dsp[0x5D] << 8) + (u16)S.dsp[(ch << 4) | 4] * 4u;
    v->brr_addr = (u16)(M->apuram[dir] | ((u16)M->apuram[(u16)(dir + 1u)] << 8));
    v->prev1 = v->prev2 = 0;
    v->buf_pos = 0;
    v->interp_pos = 0;
    v->env = 0;
    v->env_mode = 1;                        /* Attack */
    S.dsp[0x7C] &= (u8)~(1u << ch);
    brr_decode_block(v, ch);
}

static void dsp_step_env(struct snes_voice *v, int ch)
{
    if (v->env_mode == 0) {
        v->env -= 8;
        if (v->env < 0) v->env = 0;
        return;
    }
    u8 adsr1 = S.dsp[(ch << 4) | 5];
    if (adsr1 & 0x80u) {                    /* ADSR */
        u8 adsr2 = S.dsp[(ch << 4) | 6];
        int rate, step = 0;
        if (v->env_mode == 1) {             /* Attack */
            rate = ((adsr1 & 0x0Fu) << 1) + 1;
            step = (rate == 31) ? 1024 : 32;
            if (dsp_rate_hit(rate)) {
                v->env += (s16)step;
                if (v->env >= 0x7E0) {
                    if (v->env > 0x7FF) v->env = 0x7FF;
                    v->env_mode = 2;
                }
            }
        } else if (v->env_mode == 2) {      /* Decay */
            rate = (((adsr1 >> 4) & 7u) << 1) + 16;
            if (dsp_rate_hit(rate)) {
                v->env -= (s16)(((v->env - 1) >> 8) + 1);
                if (v->env < 0) v->env = 0;
            }
            s16 sl = (s16)(((adsr2 >> 5) + 1) << 8);
            if (v->env <= sl)
                v->env_mode = 3;
        } else {                            /* Sustain */
            rate = adsr2 & 0x1Fu;
            if (dsp_rate_hit(rate)) {
                v->env -= (s16)(((v->env - 1) >> 8) + 1);
                if (v->env < 0) v->env = 0;
            }
        }
    } else {                                /* GAIN */
        u8 gain = S.dsp[(ch << 4) | 7];
        if (!(gain & 0x80u)) {
            v->env = (s16)((gain & 0x7Fu) << 4);
        } else {
            int rate = gain & 0x1Fu;
            if (dsp_rate_hit(rate)) {
                switch ((gain >> 5) & 3u) {
                case 0: v->env -= 32; break;
                case 1: v->env -= (s16)(((v->env - 1) >> 8) + 1); break;
                case 2: v->env += 32; break;
                case 3: v->env += (v->env < 0x600) ? 32 : 8; break;
                }
                if (v->env < 0) v->env = 0;
                if (v->env > 0x7FF) v->env = 0x7FF;
            }
        }
    }
}

static void dsp_sample_32k(void)
{
    S.dsp_counter = (S.dsp_counter == 0) ? 30719u : (S.dsp_counter - 1u);

    u8 flg = S.dsp[0x6C];
    if (flg & 0x80u) {                      /* Soft reset */
        for (int ch = 0; ch < 8; ch++) {
            S.voice[ch].env = 0;
            S.voice[ch].env_mode = 0;
        }
    }

    /* Update 15-bit noise LFSR */
    if (dsp_rate_hit(flg & 0x1Fu)) {
        u16 fb = (u16)((S.noise_val ^ (S.noise_val >> 1)) & 1u);
        S.noise_val = (s16)(((u16)(S.noise_val >> 1) & 0x3FFFu) | (fb << 14));
        if (S.noise_val & 0x4000)
            S.noise_val |= (s16)0x8000u;
    }

    u8 kon = S.dsp[0x4C];
    u8 kof = S.dsp[0x5C];
    S.dsp[0x4C] = 0;

    s32 main_l = 0, main_r = 0, echo_in_l = 0, echo_in_r = 0;
    u8 pmon = S.dsp[0x2D] & 0xFEu;
    u8 non  = S.dsp[0x3D];
    u8 eon  = S.dsp[0x4D];

    for (int ch = 0; ch < 8; ch++) {
        struct snes_voice *v = &S.voice[ch];
        if (kof & (1u << ch))
            v->env_mode = 0;
        if (kon & (1u << ch))
            dsp_key_on(ch);

        if (v->env == 0 && v->env_mode == 0 && (v->brr_hdr & 3u) == 1u) {
            S.dsp[(ch << 4) | 8] = 0;
            S.dsp[(ch << 4) | 9] = 0;
            v->last_out = 0;
            continue;
        }

        dsp_step_env(v, ch);
        S.dsp[(ch << 4) | 8] = (u8)(v->env >> 4);

        s32 s;
        if (non & (1u << ch)) {
            s = S.noise_val;
        } else {
            u32 idx = (v->interp_pos >> 4) & 0xFFu;
            u32 p0 = v->buf_pos;
            s32 out = ((s32)s_gauss[255u - idx] * v->brr_buf[p0]) >> 11;
            out += ((s32)s_gauss[511u - idx] * v->brr_buf[(p0 + 1u) & 15u]) >> 11;
            out += ((s32)s_gauss[256u + idx] * v->brr_buf[(p0 + 2u) & 15u]) >> 11;
            out = (s16)out;
            out += ((s32)s_gauss[idx] * v->brr_buf[(p0 + 3u) & 15u]) >> 11;
            s = clamp16(out) & ~1;
        }

        s = (s * v->env) >> 11;
        v->last_out = (s16)s;
        S.dsp[(ch << 4) | 9] = (u8)(s >> 8);

        /* Advance pitch (with optional pitch modulation from ch-1) */
        s32 pitch = (S.dsp[(ch << 4) | 2] | ((S.dsp[(ch << 4) | 3] & 0x3Fu) << 8));
        if ((pmon & (1u << ch)) && ch > 0)
            pitch += ((S.voice[ch - 1].last_out >> 5) * pitch) >> 10;
        if (pitch < 0) pitch = 0;
        if (pitch > 0x3FFF) pitch = 0x3FFF;

        u32 next_pos = (u32)v->interp_pos + (u32)pitch;
        u32 adv = next_pos >> 12;
        v->interp_pos = (u16)(next_pos & 0x0FFFu);
        while (adv--) {
            v->buf_pos = (v->buf_pos + 1u) & 15u;
            if (v->buf_pos == 0)
                brr_decode_block(v, ch);
        }

        s32 vl = (s8)S.dsp[(ch << 4) | 0];
        s32 vr = (s8)S.dsp[(ch << 4) | 1];
        s32 cl = (s * vl) >> 7;
        s32 cr = (s * vr) >> 7;
        main_l = clamp16(main_l + cl);
        main_r = clamp16(main_r + cr);
        if (eon & (1u << ch)) {
            echo_in_l = clamp16(echo_in_l + cl);
            echo_in_r = clamp16(echo_in_r + cr);
        }
    }

    /* Echo buffer + 8-tap FIR filter */
    s32 fl = 0, fr = 0;
    if (!(flg & 0x20u) || S.dsp[0x2C] || S.dsp[0x3C]) {
        u16 echo_base = (u16)((u16)S.dsp[0x6D] << 8);
        u16 ea = (u16)(echo_base + S.echo_off);
        s16 el = (s16)((M->apuram[ea] | ((u16)M->apuram[(u16)(ea + 1u)] << 8)) & 0xFFFEu);
        s16 er = (s16)((M->apuram[(u16)(ea + 2u)] | ((u16)M->apuram[(u16)(ea + 3u)] << 8)) & 0xFFFEu);
        S.fir_idx = (S.fir_idx + 1u) & 7u;
        S.fir_buf_l[S.fir_idx] = el >> 1;
        S.fir_buf_r[S.fir_idx] = er >> 1;

        for (int i = 0; i < 7; i++) {
            u8 idx = (S.fir_idx + 1u + i) & 7u;
            s8 coef = (s8)S.dsp[(i << 4) | 0x0F];
            fl += (S.fir_buf_l[idx] * coef) >> 6;
            fr += (S.fir_buf_r[idx] * coef) >> 6;
        }
        fl = (s16)fl + ((S.fir_buf_l[S.fir_idx] * (s8)S.dsp[0x7F]) >> 6);
        fr = (s16)fr + ((S.fir_buf_r[S.fir_idx] * (s8)S.dsp[0x7F]) >> 6);
        fl = clamp16(fl) & ~1;
        fr = clamp16(fr) & ~1;

        if (!(flg & 0x20u)) {               /* ECEN == 0: write echo RAM */
            s8 efb = (s8)S.dsp[0x0D];
            s16 wl = clamp16(echo_in_l + ((fl * efb) >> 7)) & ~1;
            s16 wr = clamp16(echo_in_r + ((fr * efb) >> 7)) & ~1;
            M->apuram[ea] = (u8)wl;
            M->apuram[(u16)(ea + 1u)] = (u8)((u16)wl >> 8);
            M->apuram[(u16)(ea + 2u)] = (u8)wr;
            M->apuram[(u16)(ea + 3u)] = (u8)((u16)wr >> 8);
        }
    }
    if (S.echo_off == 0)
        S.echo_len = (u16)((S.dsp[0x7D] & 0x0Fu) * 2048u);
    S.echo_off += 4u;
    if (S.echo_off >= (S.echo_len ? S.echo_len : 4u))
        S.echo_off = 0;

    s32 out_l = clamp16(((main_l * (s8)S.dsp[0x0C]) >> 7) + ((fl * (s8)S.dsp[0x2C]) >> 7));
    s32 out_r = clamp16(((main_r * (s8)S.dsp[0x1C]) >> 7) + ((fr * (s8)S.dsp[0x3C]) >> 7));
    if (flg & 0x40u)                        /* MUTE */
        out_l = out_r = 0;
    s16 mono = (s16)((out_l + out_r) >> 1);

    /* Resample 32000 Hz -> S.sample_rate (48000 Hz: 1.5 output samples per 32k sample) */
    if (S.sample_rate) {
        S.resamp_acc += S.sample_rate;
        while (S.resamp_acc >= 32000u) {
            S.resamp_acc -= 32000u;
            /* Linear interpolation between prev_mono and mono */
            s32 frac = (s32)((32000u - (S.resamp_acc < 32000u ? S.resamp_acc : 0u)) * 256u / 32000u);
            s32 interp = S.prev_mono + (((mono - S.prev_mono) * frac) >> 8);
            if (S.audio_count < 4096)
                M->audio_ring[S.audio_count++] = clamp16(interp);
        }
    }
    S.prev_mono = mono;
}

/* =====================================================================
 * Sony SPC700 CPU (1.024 MHz, all 256 opcodes)
 * ===================================================================== */
static u8 spc_rd(u16 a)
{
    if ((a & 0xFFF0u) == 0x00F0u) {
        switch (a & 0x0Fu) {
        case 0x2: return S.spc_dsp_addr;
        case 0x3: return S.dsp[S.spc_dsp_addr & 0x7Fu];
        case 0x4: case 0x5: case 0x6: case 0x7:
            return S.cpu_to_apu[a - 0xF4u];
        case 0xD: case 0xE: case 0xF: {
            u8 v = S.spc_t_out[a - 0xFDu];
            S.spc_t_out[a - 0xFDu] = 0;
            return v;
        }
        default: return M->apuram[a];
        }
    }
    if (a >= 0xFFC0u && (S.spc_ctrl & 0x80u))
        return spc_ipl_rom[a - 0xFFC0u];
    return M->apuram[a];
}

static void spc_wr(u16 a, u8 v)
{
    M->apuram[a] = v;
    if ((a & 0xFFF0u) == 0x00F0u) {
        switch (a & 0x0Fu) {
        case 0x1:
            if ((v & 1u) && !(S.spc_ctrl & 1u)) { S.spc_t_stage1[0] = S.spc_t_stage2[0] = S.spc_t_out[0] = 0; }
            if ((v & 2u) && !(S.spc_ctrl & 2u)) { S.spc_t_stage1[1] = S.spc_t_stage2[1] = S.spc_t_out[1] = 0; }
            if ((v & 4u) && !(S.spc_ctrl & 4u)) { S.spc_t_stage1[2] = S.spc_t_stage2[2] = S.spc_t_out[2] = 0; }
            if (v & 0x10u) { S.cpu_to_apu[0] = S.cpu_to_apu[1] = 0; }
            if (v & 0x20u) { S.cpu_to_apu[2] = S.cpu_to_apu[3] = 0; }
            S.spc_ctrl = v;
            break;
        case 0x2:
            S.spc_dsp_addr = v;
            break;
        case 0x3:
            if (S.spc_dsp_addr < 0x80u) {
                if (S.spc_dsp_addr == 0x7Cu)
                    S.dsp[0x7C] = 0;
                else if (S.spc_dsp_addr == 0x4Cu)
                    S.dsp[0x4C] |= v;
                else
                    S.dsp[S.spc_dsp_addr] = v;
            }
            break;
        case 0x4: case 0x5: case 0x6: case 0x7:
            S.apu_to_cpu[a - 0xF4u] = v;
            break;
        case 0xA: case 0xB: case 0xC:
            S.spc_t_div[a - 0xFAu] = v;
            break;
        }
    }
}

static inline u16 spc_dp(u8 off)
{
    return (u16)(((S.spc_psw & SP_P) ? 0x0100u : 0x0000u) | off);
}

static inline u8 spc_fetch8(void)
{
    return spc_rd(S.spc_pc++);
}

static inline u16 spc_fetch16(void)
{
    u8 lo = spc_fetch8();
    u8 hi = spc_fetch8();
    return (u16)(lo | ((u16)hi << 8));
}

static inline void spc_push8(u8 v)
{
    M->apuram[0x0100u | S.spc_sp--] = v;
}

static inline u8 spc_pop8(void)
{
    return M->apuram[0x0100u | ++S.spc_sp];
}

static inline void spc_nz(u8 v)
{
    S.spc_psw = (u8)((S.spc_psw & ~(SP_N | SP_Z)) | (v & SP_N) | (v == 0 ? SP_Z : 0));
}

static u8 spc_adc(u8 a, u8 b)
{
    u32 cin = S.spc_psw & SP_C;
    u32 r = (u32)a + b + cin;
    S.spc_psw &= (u8)~(SP_N | SP_V | SP_H | SP_Z | SP_C);
    if (r > 0xFFu) S.spc_psw |= SP_C;
    if (((a & 0x0Fu) + (b & 0x0Fu) + cin) > 0x0Fu) S.spc_psw |= SP_H;
    if ((~(a ^ b) & (a ^ r)) & 0x80u) S.spc_psw |= SP_V;
    spc_nz((u8)r);
    return (u8)r;
}

static inline u8 spc_sbc(u8 a, u8 b)
{
    return spc_adc(a, (u8)(b ^ 0xFFu));
}

static void spc_cmp(u8 a, u8 b)
{
    u32 r = (u32)a - b;
    S.spc_psw = (u8)((S.spc_psw & ~(SP_N | SP_Z | SP_C)) | (a >= b ? SP_C : 0));
    spc_nz((u8)r);
}

static u8 spc_asl(u8 v) { S.spc_psw = (u8)((S.spc_psw & ~SP_C) | (v >> 7)); v <<= 1; spc_nz(v); return v; }
static u8 spc_lsr(u8 v) { S.spc_psw = (u8)((S.spc_psw & ~SP_C) | (v & 1u)); v >>= 1; spc_nz(v); return v; }
static u8 spc_rol(u8 v) { u8 c = S.spc_psw & 1u; S.spc_psw = (u8)((S.spc_psw & ~SP_C) | (v >> 7)); v = (u8)((v << 1) | c); spc_nz(v); return v; }
static u8 spc_ror(u8 v) { u8 c = (u8)((S.spc_psw & 1u) << 7); S.spc_psw = (u8)((S.spc_psw & ~SP_C) | (v & 1u)); v = (u8)((v >> 1) | c); spc_nz(v); return v; }

static u16 spc_addr_abs_idx(u8 idx) { return (u16)(spc_fetch16() + idx); }
static u16 spc_addr_ind_x(void) { u16 d = spc_dp((u8)(spc_fetch8() + S.spc_x)); return (u16)(spc_rd(d) | ((u16)spc_rd((u16)((d & 0xFF00u) | ((d + 1u) & 0xFFu))) << 8)); }
static u16 spc_addr_ind_y(void) { u16 d = spc_dp(spc_fetch8()); u16 base = (u16)(spc_rd(d) | ((u16)spc_rd((u16)((d & 0xFF00u) | ((d + 1u) & 0xFFu))) << 8)); return (u16)(base + S.spc_y); }

static u32 spc_step_one(void)
{
    if (S.spc_stopped)
        return 2;
    u8 op = spc_fetch8();

    /* High nibble families: TCALL (x1), SET1/CLR1 (x2), BBS/BBC (x3) */
    if ((op & 0x0Fu) == 0x01u) {            /* TCALL 0..15 */
        u16 vec = (u16)(0xFFDEu - ((op >> 4) * 2u));
        spc_push8((u8)(S.spc_pc >> 8));
        spc_push8((u8)S.spc_pc);
        S.spc_pc = (u16)(spc_rd(vec) | ((u16)spc_rd((u16)(vec + 1u)) << 8));
        return 8;
    }
    if ((op & 0x0Fu) == 0x02u) {            /* SET1 / CLR1 dp.bit */
        u16 a = spc_dp(spc_fetch8());
        u8 bit = (u8)(1u << (op >> 5));
        u8 v = spc_rd(a);
        spc_wr(a, (op & 0x10u) ? (u8)(v & ~bit) : (u8)(v | bit));
        return 4;
    }
    if ((op & 0x0Fu) == 0x03u) {            /* BBS / BBC dp.bit, rel */
        u16 a = spc_dp(spc_fetch8());
        s8 rel = (s8)spc_fetch8();
        int set = (spc_rd(a) >> (op >> 5)) & 1;
        if ((op & 0x10u) ? !set : set) {
            S.spc_pc = (u16)(S.spc_pc + rel);
            return 7;
        }
        return 5;
    }

    /* Standard ALU group: OR(0x), AND(2x), EOR(4x), CMP(6x), ADC(8x), SBC(Ax) */
    u8 low = op & 0x1Fu;
    int alu_grp = op >> 5;
    if (alu_grp <= 5 && ((low >= 0x04u && low <= 0x09u) || (low >= 0x14u && low <= 0x19u))) {
        u8 lhs, rhs;
        u16 dst_a = 0;
        int to_acc = 1;
        u32 cyc = 3;
        switch (low) {
        case 0x04: lhs = S.spc_a; rhs = spc_rd(spc_dp(spc_fetch8())); break;
        case 0x05: lhs = S.spc_a; rhs = spc_rd(spc_fetch16()); cyc = 4; break;
        case 0x06: lhs = S.spc_a; rhs = spc_rd(spc_dp(S.spc_x)); break;
        case 0x07: lhs = S.spc_a; rhs = spc_rd(spc_addr_ind_x()); cyc = 6; break;
        case 0x08: lhs = S.spc_a; rhs = spc_fetch8(); cyc = 2; break;
        case 0x09: {                        /* dp(d), dp(s) — note source byte comes FIRST in SPC700! */
            u16 sa = spc_dp(spc_fetch8());
            dst_a = spc_dp(spc_fetch8());
            rhs = spc_rd(sa);
            lhs = spc_rd(dst_a);
            to_acc = 0; cyc = 6;
            break;
        }
        case 0x14: lhs = S.spc_a; rhs = spc_rd(spc_dp((u8)(spc_fetch8() + S.spc_x))); cyc = 4; break;
        case 0x15: lhs = S.spc_a; rhs = spc_rd(spc_addr_abs_idx(S.spc_x)); cyc = 5; break;
        case 0x16: lhs = S.spc_a; rhs = spc_rd(spc_addr_abs_idx(S.spc_y)); cyc = 5; break;
        case 0x17: lhs = S.spc_a; rhs = spc_rd(spc_addr_ind_y()); cyc = 6; break;
        case 0x18: {                        /* dp, #imm — imm byte comes FIRST! */
            rhs = spc_fetch8();
            dst_a = spc_dp(spc_fetch8());
            lhs = spc_rd(dst_a);
            to_acc = 0; cyc = 5;
            break;
        }
        default:                            /* 0x19: (X), (Y) */
            dst_a = spc_dp(S.spc_x);
            rhs = spc_rd(spc_dp(S.spc_y));
            lhs = spc_rd(dst_a);
            to_acc = 0; cyc = 5;
            break;
        }
        u8 res = lhs;
        switch (alu_grp) {
        case 0: res = lhs | rhs; spc_nz(res); break;
        case 1: res = lhs & rhs; spc_nz(res); break;
        case 2: res = lhs ^ rhs; spc_nz(res); break;
        case 3: spc_cmp(lhs, rhs); return cyc;
        case 4: res = spc_adc(lhs, rhs); break;
        case 5: res = spc_sbc(lhs, rhs); break;
        }
        if (to_acc) S.spc_a = res;
        else        spc_wr(dst_a, res);
        return cyc;
    }

    switch (op) {
    case 0x00: return 2;                    /* NOP */
    case 0xEF: case 0xFF: S.spc_stopped = 1; return 3;  /* SLEEP / STOP */
    case 0x20: S.spc_psw &= (u8)~SP_P; return 2;        /* CLRP */
    case 0x40: S.spc_psw |= SP_P; return 2;             /* SETP */
    case 0x60: S.spc_psw &= (u8)~SP_C; return 2;        /* CLRC */
    case 0x80: S.spc_psw |= SP_C; return 2;             /* SETC */
    case 0xED: S.spc_psw ^= SP_C; return 3;             /* NOTC */
    case 0xE0: S.spc_psw &= (u8)~(SP_V | SP_H); return 2; /* CLRV */
    case 0xA0: S.spc_psw |= SP_I; return 3;             /* EI */
    case 0xC0: S.spc_psw &= (u8)~SP_I; return 3;        /* DI */

    /* Branches */
    case 0x10: { s8 r = (s8)spc_fetch8(); if (!(S.spc_psw & SP_N)) { S.spc_pc = (u16)(S.spc_pc + r); return 4; } return 2; }
    case 0x30: { s8 r = (s8)spc_fetch8(); if (S.spc_psw & SP_N)    { S.spc_pc = (u16)(S.spc_pc + r); return 4; } return 2; }
    case 0x50: { s8 r = (s8)spc_fetch8(); if (!(S.spc_psw & SP_V)) { S.spc_pc = (u16)(S.spc_pc + r); return 4; } return 2; }
    case 0x70: { s8 r = (s8)spc_fetch8(); if (S.spc_psw & SP_V)    { S.spc_pc = (u16)(S.spc_pc + r); return 4; } return 2; }
    case 0x90: { s8 r = (s8)spc_fetch8(); if (!(S.spc_psw & SP_C)) { S.spc_pc = (u16)(S.spc_pc + r); return 4; } return 2; }
    case 0xB0: { s8 r = (s8)spc_fetch8(); if (S.spc_psw & SP_C)    { S.spc_pc = (u16)(S.spc_pc + r); return 4; } return 2; }
    case 0xD0: { s8 r = (s8)spc_fetch8(); if (!(S.spc_psw & SP_Z)) { S.spc_pc = (u16)(S.spc_pc + r); return 4; } return 2; }
    case 0xF0: { s8 r = (s8)spc_fetch8(); if (S.spc_psw & SP_Z)    { S.spc_pc = (u16)(S.spc_pc + r); return 4; } return 2; }
    case 0x2F: { s8 r = (s8)spc_fetch8(); S.spc_pc = (u16)(S.spc_pc + r); return 4; }
    case 0x2E: { u8 v = spc_rd(spc_dp(spc_fetch8())); s8 r = (s8)spc_fetch8(); if (S.spc_a != v) { S.spc_pc = (u16)(S.spc_pc + r); return 7; } return 5; }
    case 0xDE: { u8 v = spc_rd(spc_dp((u8)(spc_fetch8() + S.spc_x))); s8 r = (s8)spc_fetch8(); if (S.spc_a != v) { S.spc_pc = (u16)(S.spc_pc + r); return 8; } return 6; }
    case 0x6E: { u16 a = spc_dp(spc_fetch8()); s8 r = (s8)spc_fetch8(); u8 v = (u8)(spc_rd(a) - 1u); spc_wr(a, v); if (v) { S.spc_pc = (u16)(S.spc_pc + r); return 7; } return 5; }
    case 0xFE: { s8 r = (s8)spc_fetch8(); if (--S.spc_y) { S.spc_pc = (u16)(S.spc_pc + r); return 6; } return 4; }

    /* Jumps / Calls / Stack */
    case 0x5F: S.spc_pc = spc_fetch16(); return 3;
    case 0x1F: { u16 a = (u16)(spc_fetch16() + S.spc_x); S.spc_pc = (u16)(spc_rd(a) | ((u16)spc_rd((u16)(a + 1u)) << 8)); return 6; }
    case 0x3F: { u16 dst = spc_fetch16(); spc_push8((u8)(S.spc_pc >> 8)); spc_push8((u8)S.spc_pc); S.spc_pc = dst; return 8; }
    case 0x4F: { u8 u = spc_fetch8(); spc_push8((u8)(S.spc_pc >> 8)); spc_push8((u8)S.spc_pc); S.spc_pc = (u16)(0xFF00u | u); return 6; }
    case 0x6F: { u8 lo = spc_pop8(); S.spc_pc = (u16)(lo | ((u16)spc_pop8() << 8)); return 5; }
    case 0x7F: { S.spc_psw = spc_pop8(); u8 lo = spc_pop8(); S.spc_pc = (u16)(lo | ((u16)spc_pop8() << 8)); return 6; }
    case 0x0F: {                            /* BRK */
        spc_push8((u8)(S.spc_pc >> 8));
        spc_push8((u8)S.spc_pc);
        spc_push8(S.spc_psw);
        S.spc_psw = (u8)((S.spc_psw | SP_B) & ~SP_I);
        S.spc_pc = (u16)(spc_rd(0xFFDEu) | ((u16)spc_rd(0xFFDFu) << 8));
        return 8;
    }
    case 0x2D: spc_push8(S.spc_a); return 4;
    case 0x4D: spc_push8(S.spc_x); return 4;
    case 0x6D: spc_push8(S.spc_y); return 4;
    case 0x0D: spc_push8(S.spc_psw); return 4;
    case 0xAE: S.spc_a = spc_pop8(); return 4;
    case 0xCE: S.spc_x = spc_pop8(); return 4;
    case 0xEE: S.spc_y = spc_pop8(); return 4;
    case 0x8E: S.spc_psw = spc_pop8(); return 4;

    /* Shifts / Rotates / INC / DEC */
    case 0x1C: S.spc_a = spc_asl(S.spc_a); return 2;
    case 0x0B: { u16 a = spc_dp(spc_fetch8()); spc_wr(a, spc_asl(spc_rd(a))); return 4; }
    case 0x1B: { u16 a = spc_dp((u8)(spc_fetch8() + S.spc_x)); spc_wr(a, spc_asl(spc_rd(a))); return 5; }
    case 0x0C: { u16 a = spc_fetch16(); spc_wr(a, spc_asl(spc_rd(a))); return 5; }
    case 0x5C: S.spc_a = spc_lsr(S.spc_a); return 2;
    case 0x4B: { u16 a = spc_dp(spc_fetch8()); spc_wr(a, spc_lsr(spc_rd(a))); return 4; }
    case 0x5B: { u16 a = spc_dp((u8)(spc_fetch8() + S.spc_x)); spc_wr(a, spc_lsr(spc_rd(a))); return 5; }
    case 0x4C: { u16 a = spc_fetch16(); spc_wr(a, spc_lsr(spc_rd(a))); return 5; }
    case 0x3C: S.spc_a = spc_rol(S.spc_a); return 2;
    case 0x2B: { u16 a = spc_dp(spc_fetch8()); spc_wr(a, spc_rol(spc_rd(a))); return 4; }
    case 0x3B: { u16 a = spc_dp((u8)(spc_fetch8() + S.spc_x)); spc_wr(a, spc_rol(spc_rd(a))); return 5; }
    case 0x2C: { u16 a = spc_fetch16(); spc_wr(a, spc_rol(spc_rd(a))); return 5; }
    case 0x7C: S.spc_a = spc_ror(S.spc_a); return 2;
    case 0x6B: { u16 a = spc_dp(spc_fetch8()); spc_wr(a, spc_ror(spc_rd(a))); return 4; }
    case 0x7B: { u16 a = spc_dp((u8)(spc_fetch8() + S.spc_x)); spc_wr(a, spc_ror(spc_rd(a))); return 5; }
    case 0x6C: { u16 a = spc_fetch16(); spc_wr(a, spc_ror(spc_rd(a))); return 5; }
    case 0x9F: S.spc_a = (u8)((S.spc_a >> 4) | (S.spc_a << 4)); spc_nz(S.spc_a); return 5;

    case 0xBC: spc_nz(++S.spc_a); return 2;
    case 0x3D: spc_nz(++S.spc_x); return 2;
    case 0xFC: spc_nz(++S.spc_y); return 2;
    case 0xAB: { u16 a = spc_dp(spc_fetch8()); u8 v = (u8)(spc_rd(a) + 1u); spc_wr(a, v); spc_nz(v); return 4; }
    case 0xBB: { u16 a = spc_dp((u8)(spc_fetch8() + S.spc_x)); u8 v = (u8)(spc_rd(a) + 1u); spc_wr(a, v); spc_nz(v); return 5; }
    case 0xAC: { u16 a = spc_fetch16(); u8 v = (u8)(spc_rd(a) + 1u); spc_wr(a, v); spc_nz(v); return 5; }
    case 0x9C: spc_nz(--S.spc_a); return 2;
    case 0x1D: spc_nz(--S.spc_x); return 2;
    case 0xDC: spc_nz(--S.spc_y); return 2;
    case 0x8B: { u16 a = spc_dp(spc_fetch8()); u8 v = (u8)(spc_rd(a) - 1u); spc_wr(a, v); spc_nz(v); return 4; }
    case 0x9B: { u16 a = spc_dp((u8)(spc_fetch8() + S.spc_x)); u8 v = (u8)(spc_rd(a) - 1u); spc_wr(a, v); spc_nz(v); return 5; }
    case 0x8C: { u16 a = spc_fetch16(); u8 v = (u8)(spc_rd(a) - 1u); spc_wr(a, v); spc_nz(v); return 5; }

    /* CMP X / CMP Y */
    case 0xC8: spc_cmp(S.spc_x, spc_fetch8()); return 2;
    case 0x3E: spc_cmp(S.spc_x, spc_rd(spc_dp(spc_fetch8()))); return 3;
    case 0x1E: spc_cmp(S.spc_x, spc_rd(spc_fetch16())); return 4;
    case 0xAD: spc_cmp(S.spc_y, spc_fetch8()); return 2;
    case 0x7E: spc_cmp(S.spc_y, spc_rd(spc_dp(spc_fetch8()))); return 3;
    case 0x5E: spc_cmp(S.spc_y, spc_rd(spc_fetch16())); return 4;

    /* MOV loads / stores / transfers */
    case 0xE8: S.spc_a = spc_fetch8(); spc_nz(S.spc_a); return 2;
    case 0xE6: S.spc_a = spc_rd(spc_dp(S.spc_x)); spc_nz(S.spc_a); return 3;
    case 0xBF: S.spc_a = spc_rd(spc_dp(S.spc_x++)); spc_nz(S.spc_a); return 4;
    case 0xE4: S.spc_a = spc_rd(spc_dp(spc_fetch8())); spc_nz(S.spc_a); return 3;
    case 0xF4: S.spc_a = spc_rd(spc_dp((u8)(spc_fetch8() + S.spc_x))); spc_nz(S.spc_a); return 4;
    case 0xE5: S.spc_a = spc_rd(spc_fetch16()); spc_nz(S.spc_a); return 4;
    case 0xF5: S.spc_a = spc_rd(spc_addr_abs_idx(S.spc_x)); spc_nz(S.spc_a); return 5;
    case 0xF6: S.spc_a = spc_rd(spc_addr_abs_idx(S.spc_y)); spc_nz(S.spc_a); return 5;
    case 0xE7: S.spc_a = spc_rd(spc_addr_ind_x()); spc_nz(S.spc_a); return 6;
    case 0xF7: S.spc_a = spc_rd(spc_addr_ind_y()); spc_nz(S.spc_a); return 6;

    case 0xCD: S.spc_x = spc_fetch8(); spc_nz(S.spc_x); return 2;
    case 0xF8: S.spc_x = spc_rd(spc_dp(spc_fetch8())); spc_nz(S.spc_x); return 3;
    case 0xF9: S.spc_x = spc_rd(spc_dp((u8)(spc_fetch8() + S.spc_y))); spc_nz(S.spc_x); return 4;
    case 0xE9: S.spc_x = spc_rd(spc_fetch16()); spc_nz(S.spc_x); return 4;

    case 0x8D: S.spc_y = spc_fetch8(); spc_nz(S.spc_y); return 2;
    case 0xEB: S.spc_y = spc_rd(spc_dp(spc_fetch8())); spc_nz(S.spc_y); return 3;
    case 0xFB: S.spc_y = spc_rd(spc_dp((u8)(spc_fetch8() + S.spc_x))); spc_nz(S.spc_y); return 4;
    case 0xEC: S.spc_y = spc_rd(spc_fetch16()); spc_nz(S.spc_y); return 4;

    case 0xC6: spc_wr(spc_dp(S.spc_x), S.spc_a); return 4;
    case 0xAF: spc_wr(spc_dp(S.spc_x++), S.spc_a); return 4;
    case 0xC4: spc_wr(spc_dp(spc_fetch8()), S.spc_a); return 4;
    case 0xD4: spc_wr(spc_dp((u8)(spc_fetch8() + S.spc_x)), S.spc_a); return 5;
    case 0xC5: spc_wr(spc_fetch16(), S.spc_a); return 5;
    case 0xD5: spc_wr(spc_addr_abs_idx(S.spc_x), S.spc_a); return 6;
    case 0xD6: spc_wr(spc_addr_abs_idx(S.spc_y), S.spc_a); return 6;
    case 0xC7: spc_wr(spc_addr_ind_x(), S.spc_a); return 7;
    case 0xD7: spc_wr(spc_addr_ind_y(), S.spc_a); return 7;

    case 0xD8: spc_wr(spc_dp(spc_fetch8()), S.spc_x); return 4;
    case 0xD9: spc_wr(spc_dp((u8)(spc_fetch8() + S.spc_y)), S.spc_x); return 5;
    case 0xC9: spc_wr(spc_fetch16(), S.spc_x); return 5;

    case 0xCB: spc_wr(spc_dp(spc_fetch8()), S.spc_y); return 4;
    case 0xDB: spc_wr(spc_dp((u8)(spc_fetch8() + S.spc_x)), S.spc_y); return 5;
    case 0xCC: spc_wr(spc_fetch16(), S.spc_y); return 5;

    case 0x7D: S.spc_a = S.spc_x; spc_nz(S.spc_a); return 2;
    case 0xDD: S.spc_a = S.spc_y; spc_nz(S.spc_a); return 2;
    case 0x5D: S.spc_x = S.spc_a; spc_nz(S.spc_x); return 2;
    case 0xFD: S.spc_y = S.spc_a; spc_nz(S.spc_y); return 2;
    case 0x9D: S.spc_x = S.spc_sp; spc_nz(S.spc_x); return 2;
    case 0xBD: S.spc_sp = S.spc_x; return 2;
    case 0xFA: { u8 v = spc_rd(spc_dp(spc_fetch8())); spc_wr(spc_dp(spc_fetch8()), v); return 5; }
    case 0x8F: { u8 v = spc_fetch8(); spc_wr(spc_dp(spc_fetch8()), v); return 5; }

    /* 16-bit word operations */
    case 0xBA: {                        /* MOVW YA, dp */
        u8 d = spc_fetch8();
        S.spc_a = spc_rd(spc_dp(d));
        S.spc_y = spc_rd(spc_dp((u8)(d + 1u)));
        S.spc_psw = (u8)((S.spc_psw & ~(SP_N | SP_Z)) | (S.spc_y & SP_N) | ((S.spc_a | S.spc_y) == 0 ? SP_Z : 0));
        return 5;
    }
    case 0xDA: {                        /* MOVW dp, YA */
        u8 d = spc_fetch8();
        spc_wr(spc_dp(d), S.spc_a);
        spc_wr(spc_dp((u8)(d + 1u)), S.spc_y);
        return 5;
    }
    case 0x3A: {                        /* INCW dp */
        u8 d = spc_fetch8();
        u16 w = (u16)((spc_rd(spc_dp(d)) | ((u16)spc_rd(spc_dp((u8)(d + 1u))) << 8)) + 1u);
        spc_wr(spc_dp(d), (u8)w);
        spc_wr(spc_dp((u8)(d + 1u)), (u8)(w >> 8));
        S.spc_psw = (u8)((S.spc_psw & ~(SP_N | SP_Z)) | ((w >> 8) & SP_N) | (w == 0 ? SP_Z : 0));
        return 6;
    }
    case 0x1A: {                        /* DECW dp */
        u8 d = spc_fetch8();
        u16 w = (u16)((spc_rd(spc_dp(d)) | ((u16)spc_rd(spc_dp((u8)(d + 1u))) << 8)) - 1u);
        spc_wr(spc_dp(d), (u8)w);
        spc_wr(spc_dp((u8)(d + 1u)), (u8)(w >> 8));
        S.spc_psw = (u8)((S.spc_psw & ~(SP_N | SP_Z)) | ((w >> 8) & SP_N) | (w == 0 ? SP_Z : 0));
        return 6;
    }
    case 0x7A: {                        /* ADDW YA, dp */
        u8 d = spc_fetch8();
        u8 blo = spc_rd(spc_dp(d)), bhi = spc_rd(spc_dp((u8)(d + 1u)));
        S.spc_psw &= (u8)~SP_C;
        u8 rlo = spc_adc(S.spc_a, blo);
        u8 rhi = spc_adc(S.spc_y, bhi);
        S.spc_a = rlo; S.spc_y = rhi;
        S.spc_psw = (u8)((S.spc_psw & ~SP_Z) | ((rlo | rhi) == 0 ? SP_Z : 0));
        return 5;
    }
    case 0x9A: {                        /* SUBW YA, dp */
        u8 d = spc_fetch8();
        u8 blo = spc_rd(spc_dp(d)), bhi = spc_rd(spc_dp((u8)(d + 1u)));
        S.spc_psw |= SP_C;
        u8 rlo = spc_sbc(S.spc_a, blo);
        u8 rhi = spc_sbc(S.spc_y, bhi);
        S.spc_a = rlo; S.spc_y = rhi;
        S.spc_psw = (u8)((S.spc_psw & ~SP_Z) | ((rlo | rhi) == 0 ? SP_Z : 0));
        return 5;
    }
    case 0x5A: {                        /* CMPW YA, dp */
        u8 d = spc_fetch8();
        u16 ya = (u16)(S.spc_a | ((u16)S.spc_y << 8));
        u16 bw = (u16)(spc_rd(spc_dp(d)) | ((u16)spc_rd(spc_dp((u8)(d + 1u))) << 8));
        u16 r = (u16)(ya - bw);
        S.spc_psw = (u8)((S.spc_psw & ~(SP_N | SP_Z | SP_C)) |
                         (ya >= bw ? SP_C : 0) | ((r >> 8) & SP_N) | (r == 0 ? SP_Z : 0));
        return 4;
    }
    case 0xCF: {                        /* MUL YA */
        u16 r = (u16)S.spc_y * (u16)S.spc_a;
        S.spc_a = (u8)r;
        S.spc_y = (u8)(r >> 8);
        spc_nz(S.spc_y);
        return 9;
    }
    case 0x9E: {                        /* DIV YA, X */
        S.spc_psw &= (u8)~(SP_N | SP_V | SP_H | SP_Z);
        if ((S.spc_y & 0x0Fu) >= (S.spc_x & 0x0Fu))
            S.spc_psw |= SP_H;
        if (S.spc_y >= S.spc_x)
            S.spc_psw |= SP_V;
        u32 yva = ((u32)S.spc_y << 8) | S.spc_a;
        u32 x = S.spc_x;
        if (S.spc_y < (x << 1)) {
            S.spc_a = (u8)(yva / x);
            S.spc_y = (u8)(yva % x);
        } else {
            S.spc_a = (u8)(255u - (yva - (x << 9)) / (256u - x));
            S.spc_y = (u8)(x + (yva - (x << 9)) % (256u - x));
        }
        spc_nz(S.spc_a);
        return 12;
    }
    case 0xDF: {                        /* DAA */
        if ((S.spc_psw & SP_C) || S.spc_a > 0x99u) {
            S.spc_a = (u8)(S.spc_a + 0x60u);
            S.spc_psw |= SP_C;
        }
        if ((S.spc_psw & SP_H) || (S.spc_a & 0x0Fu) > 9u)
            S.spc_a = (u8)(S.spc_a + 0x06u);
        spc_nz(S.spc_a);
        return 3;
    }
    case 0xBE: {                        /* DAS */
        if (!(S.spc_psw & SP_C) || S.spc_a > 0x99u) {
            S.spc_a = (u8)(S.spc_a - 0x60u);
            S.spc_psw &= (u8)~SP_C;
        } else {
            S.spc_psw |= SP_C;
        }
        if (!(S.spc_psw & SP_H) || (S.spc_a & 0x0Fu) > 9u)
            S.spc_a = (u8)(S.spc_a - 0x06u);
        spc_nz(S.spc_a);
        return 3;
    }

    /* TSET1 / TCLR1 & 1-bit C operations */
    case 0x0E: { u16 a = spc_fetch16(); u8 v = spc_rd(a); spc_nz((u8)(S.spc_a - v)); spc_wr(a, v | S.spc_a); return 6; }
    case 0x4E: { u16 a = spc_fetch16(); u8 v = spc_rd(a); spc_nz((u8)(S.spc_a - v)); spc_wr(a, (u8)(v & ~S.spc_a)); return 6; }
    case 0x0A: case 0x2A: case 0x4A: case 0x6A: case 0x8A: case 0xAA: case 0xCA: case 0xEA: {
        u16 m = spc_fetch16();
        u16 a = m & 0x1FFFu;
        u8 sh = (u8)(m >> 13);
        u8 bit = (u8)((spc_rd(a) >> sh) & 1u);
        switch (op) {
        case 0x0A: S.spc_psw |= bit; break;
        case 0x2A: S.spc_psw |= (u8)(bit ^ 1u); break;
        case 0x4A: if (!bit) S.spc_psw &= (u8)~SP_C; break;
        case 0x6A: if (bit)  S.spc_psw &= (u8)~SP_C; break;
        case 0x8A: S.spc_psw ^= bit; break;
        case 0xAA: S.spc_psw = (u8)((S.spc_psw & ~SP_C) | bit); break;
        case 0xCA: {
            u8 v = spc_rd(a);
            v = (S.spc_psw & SP_C) ? (u8)(v | (1u << sh)) : (u8)(v & ~(1u << sh));
            spc_wr(a, v);
            return 6;
        }
        case 0xEA: spc_wr(a, (u8)(spc_rd(a) ^ (1u << sh))); return 5;
        }
        return 4;
    }
    }
    return 2;
}

static void apu_catch_up(void)
{
    s32 now = S.master_cyc;
    if (now <= S.apu_last_mc)
        return;
    u32 dmc = (u32)(now - S.apu_last_mc);
    S.apu_last_mc = now;

    /* 21.477 MHz master -> 1.024 MHz SPC700 (~20.974 master cycles per SPC cycle -> * 64 / 1342) */
    S.apu_mc_rem += dmc * 64u;
    S.spc_cyc_avail += (s32)(S.apu_mc_rem / 1342u);
    S.apu_mc_rem %= 1342u;

    while (S.spc_cyc_avail > 0) {
        u32 cyc;
        if (S.spc_pc == 0xFFCFu && (S.spc_ctrl & 0x87u) == 0x80u && S.cpu_to_apu[0] != 0xCCu && S.spc_cyc_avail > 9) {
            u32 iters = (u32)((S.spc_cyc_avail + 8) / 9);
            cyc = iters * 9u;
            spc_cmp(S.cpu_to_apu[0], 0xCCu);
            S.spc_cyc_avail -= (s32)cyc;
        } else {
            cyc = spc_step_one();
            S.spc_cyc_avail -= (s32)cyc;
        }

        /* Advance 8 kHz (128 cyc) & 64 kHz (16 cyc) SPC700 timers */
        for (int t = 0; t < 3; t++) {
            if (!(S.spc_ctrl & (1u << t)))
                continue;
            u16 step_div = (t == 2) ? 16u : 128u;
            S.spc_t_stage1[t] = (u16)(S.spc_t_stage1[t] + cyc);
            while (S.spc_t_stage1[t] >= step_div) {
                S.spc_t_stage1[t] = (u16)(S.spc_t_stage1[t] - step_div);
                S.spc_t_stage2[t]++;
                u8 target = S.spc_t_div[t];
                if (S.spc_t_stage2[t] == target) {
                    S.spc_t_stage2[t] = 0;
                    S.spc_t_out[t] = (S.spc_t_out[t] + 1u) & 0x0Fu;
                }
            }
        }

        /* Step 32 kHz S-DSP every 32 SPC700 cycles */
        S.dsp_spc_acc += cyc;
        while (S.dsp_spc_acc >= 32u) {
            S.dsp_spc_acc -= 32u;
            dsp_sample_32k();
        }
    }
}

/* =====================================================================
 * S-PPU / B-Bus ($2100..$21FF), GPDMA / HDMA, and 24-Bit System Bus
 * ===================================================================== */
static inline u16 vram_trans(u16 a)
{
    a &= 0x7FFFu;
    switch ((S.vmain >> 2) & 3u) {
    case 1: return (u16)((a & 0xFF00u) | ((a & 0x001Fu) << 3) | ((a >> 5) & 7u));
    case 2: return (u16)((a & 0xFE00u) | ((a & 0x003Fu) << 3) | ((a >> 6) & 7u));
    case 3: return (u16)((a & 0xFC00u) | ((a & 0x007Fu) << 3) | ((a >> 7) & 7u));
    default: return a;
    }
}

static inline u16 vram_step(void)
{
    static const u16 st[4] = {1, 32, 128, 128};
    return st[S.vmain & 3u];
}

static inline void mark_vram_dirty(u16 waddr)
{
    waddr &= 0x7FFFu;
    M->vram_dirty2[waddr >> 3] = 1;
    M->vram_dirty4[waddr >> 4] = 1;
    M->vram_dirty8[waddr >> 5] = 1;
}

static inline s16 sext13(u16 v)
{
    return (v & 0x1000u) ? (s16)(v | 0xE000u) : (s16)(v & 0x0FFFu);
}

static u8 bbus_rd(u8 reg)
{
    if (reg >= 0x40u && reg <= 0x7Fu) {
        apu_catch_up();
        return S.apu_to_cpu[reg & 3u];
    }
    switch (reg) {
    case 0x34: return (u8)S.mpy_res;
    case 0x35: return (u8)(S.mpy_res >> 8);
    case 0x36: return (u8)(S.mpy_res >> 16);
    case 0x37: {
        u32 hc = (u32)((S.master_cyc % 1364) >> 2);
        S.h_latch = (u16)hc;
        S.v_latch = (u16)S.cur_line;
        S.stat78 |= 0x40u;
        return 0;
    }
    case 0x38: {
        u16 a = S.oam_addr & 0x3FFu;
        u8 v = (a < 512u) ? M->oam[a] : M->oam[512u + (a & 31u)];
        S.oam_addr = (u16)((a + 1u) & 0x3FFu);
        return v;
    }
    case 0x39: {
        u8 v = (u8)S.vram_prefetch;
        if (!(S.vmain & 0x80u)) {
            u16 ta = vram_trans(S.vmadd);
            S.vram_prefetch = (u16)(M->vram[ta * 2u] | ((u16)M->vram[ta * 2u + 1u] << 8));
            S.vmadd = (u16)((S.vmadd + vram_step()) & 0x7FFFu);
        }
        return v;
    }
    case 0x3A: {
        u8 v = (u8)(S.vram_prefetch >> 8);
        if (S.vmain & 0x80u) {
            u16 ta = vram_trans(S.vmadd);
            S.vram_prefetch = (u16)(M->vram[ta * 2u] | ((u16)M->vram[ta * 2u + 1u] << 8));
            S.vmadd = (u16)((S.vmadd + vram_step()) & 0x7FFFu);
        }
        return v;
    }
    case 0x3B: {
        u16 c = M->cgram[(S.cgadd >> 1) & 0xFFu];
        u8 v = (S.cgadd & 1u) ? (u8)((c >> 8) & 0x7Fu) : (u8)c;
        S.cgadd = (u16)((S.cgadd + 1u) & 0x1FFu);
        return v;
    }
    case 0x3C: {
        u8 v = S.hv_flip_h ? (u8)((S.h_latch >> 8) & 1u) : (u8)S.h_latch;
        S.hv_flip_h ^= 1u;
        return v;
    }
    case 0x3D: {
        u8 v = S.hv_flip_v ? (u8)((S.v_latch >> 8) & 1u) : (u8)S.v_latch;
        S.hv_flip_v ^= 1u;
        return v;
    }
    case 0x3E: return 0x01u;            /* PPU1 5C77 v1 */
    case 0x3F: {
        u8 v = (u8)(0x03u | (S.is_pal ? 0x10u : 0x00u) | S.stat78);
        S.stat78 &= (u8)~0x40u;
        S.hv_flip_h = S.hv_flip_v = 0;
        return v;
    }
    case 0x80: {
        u8 v = M->wram[S.wmadd & 0x1FFFFu];
        S.wmadd = (S.wmadd + 1u) & 0x1FFFFu;
        return v;
    }
    }
    return S.mdr;
}

static void bbus_wr(u8 reg, u8 v)
{
    if (reg >= 0x40u && reg <= 0x7Fu) {
        apu_catch_up();
        S.cpu_to_apu[reg & 3u] = v;
        return;
    }
    switch (reg) {
    case 0x00: S.inidisp = v; break;
    case 0x01: S.obsel = v; S.oam_dirty = 1; break;
    case 0x02:
        S.oamadd_reload = (u16)((S.oamadd_reload & 0x0100u) | v);
        S.oam_addr = (u16)((S.oamadd_reload << 1) & 0x3FFu);
        break;
    case 0x03:
        S.oamadd_reload = (u16)((S.oamadd_reload & 0x00FFu) | ((u16)(v & 1u) << 8));
        S.oam_prio = (v & 0x80u) != 0;
        S.oam_addr = (u16)((S.oamadd_reload << 1) & 0x3FFu);
        break;
    case 0x04: {
        u16 a = S.oam_addr & 0x3FFu;
        if (a < 512u) {
            if (!(a & 1u)) {
                S.oam_latch = v;
            } else {
                M->oam[a - 1u] = S.oam_latch;
                M->oam[a] = v;
            }
        } else {
            M->oam[512u + (a & 31u)] = v;
        }
        S.oam_dirty = 1;
        S.oam_addr = (u16)((a + 1u) & 0x3FFu);
        break;
    }
    case 0x05: S.bgmode = v; break;
    case 0x06: S.mosaic = v; break;
    case 0x07: case 0x08: case 0x09: case 0x0A:
        S.bg_sc[reg - 0x07u] = v;
        break;
    case 0x0B: S.bg12nba = v; break;
    case 0x0C: S.bg34nba = v; break;
    case 0x0D:
        S.m7hofs = sext13((u16)(((u16)v << 8) | S.m7_latch));
        S.m7_latch = v;
        /* fall through */
    case 0x0F: case 0x11: case 0x13: {
        int bg = (reg - 0x0Du) >> 1;
        S.bg_hofs[bg] = (u16)((((u16)v << 8) | (S.bg_old_latch & ~7u) | (S.bghofs_latch & 7u)) & 0x03FFu);
        S.bg_old_latch = v;
        S.bghofs_latch = v;
        break;
    }
    case 0x0E:
        S.m7vofs = sext13((u16)(((u16)v << 8) | S.m7_latch));
        S.m7_latch = v;
        /* fall through */
    case 0x10: case 0x12: case 0x14: {
        int bg = (reg - 0x0Eu) >> 1;
        S.bg_vofs[bg] = (u16)((((u16)v << 8) | S.bg_old_latch) & 0x03FFu);
        S.bg_old_latch = v;
        break;
    }
    case 0x15: S.vmain = v; break;
    case 0x16: S.vmadd = (u16)((S.vmadd & 0x7F00u) | v); break;
    case 0x17: S.vmadd = (u16)((S.vmadd & 0x00FFu) | ((u16)(v & 0x7Fu) << 8)); break;
    case 0x18: {
        u16 ta = vram_trans(S.vmadd);
        M->vram[ta * 2u] = v;
        mark_vram_dirty(ta);
        if (!(S.vmain & 0x80u))
            S.vmadd = (u16)((S.vmadd + vram_step()) & 0x7FFFu);
        break;
    }
    case 0x19: {
        u16 ta = vram_trans(S.vmadd);
        M->vram[ta * 2u + 1u] = v;
        mark_vram_dirty(ta);
        if (S.vmain & 0x80u)
            S.vmadd = (u16)((S.vmadd + vram_step()) & 0x7FFFu);
        break;
    }
    case 0x1A: S.m7sel = v; break;
    case 0x1B:
        S.m7a = (s16)(((u16)v << 8) | S.m7_latch);
        S.m7_latch = v;
        S.mpy_res = (s32)S.m7a * (s32)(s8)((u16)S.m7b >> 8);
        break;
    case 0x1C:
        S.m7b = (s16)(((u16)v << 8) | S.m7_latch);
        S.m7_latch = v;
        S.mpy_res = (s32)S.m7a * (s32)(s8)v;
        break;
    case 0x1D: S.m7c = (s16)(((u16)v << 8) | S.m7_latch); S.m7_latch = v; break;
    case 0x1E: S.m7d = (s16)(((u16)v << 8) | S.m7_latch); S.m7_latch = v; break;
    case 0x1F: S.m7x = sext13((u16)(((u16)v << 8) | S.m7_latch)); S.m7_latch = v; break;
    case 0x20: S.m7y = sext13((u16)(((u16)v << 8) | S.m7_latch)); S.m7_latch = v; break;
    case 0x21: S.cgadd = (u16)((u16)v << 1); break;
    case 0x22:
        if (!(S.cgadd & 1u)) {
            S.cg_latch = v;
        } else {
            M->cgram[(S.cgadd >> 1) & 0xFFu] = (u16)(((u16)(v & 0x7Fu) << 8) | S.cg_latch);
        }
        S.cgadd = (u16)((S.cgadd + 1u) & 0x1FFu);
        break;
    case 0x23: S.w12sel = v; break;
    case 0x24: S.w34sel = v; break;
    case 0x25: S.wobjsel = v; break;
    case 0x26: S.wh0 = v; break;
    case 0x27: S.wh1 = v; break;
    case 0x28: S.wh2 = v; break;
    case 0x29: S.wh3 = v; break;
    case 0x2A: S.wbglog = v; break;
    case 0x2B: S.wobjlog = v; break;
    case 0x2C: S.tm = v; break;
    case 0x2D: S.ts = v; break;
    case 0x2E: S.tmw = v; break;
    case 0x2F: S.tsw = v; break;
    case 0x30: S.cgwsel = v; break;
    case 0x31: S.cgadsub = v; break;
    case 0x32: {
        u16 val5 = v & 0x1Fu;
        if (v & 0x20u) S.fixed_col = (u16)((S.fixed_col & ~0x001Fu) | val5);
        if (v & 0x40u) S.fixed_col = (u16)((S.fixed_col & ~0x03E0u) | (val5 << 5));
        if (v & 0x80u) S.fixed_col = (u16)((S.fixed_col & ~0x7C00u) | (val5 << 10));
        break;
    }
    case 0x33:
        S.setini = v;
        S.out_h = (v & 0x04u) ? SNES_H_MAX : SNES_H_DEF;
        break;
    case 0x80:
        M->wram[S.wmadd & 0x1FFFFu] = v;
        S.wmadd = (S.wmadd + 1u) & 0x1FFFFu;
        break;
    case 0x81: S.wmadd = (S.wmadd & 0x1FF00u) | v; break;
    case 0x82: S.wmadd = (S.wmadd & 0x100FFu) | ((u32)v << 8); break;
    case 0x83: S.wmadd = (S.wmadd & 0x0FFFFu) | ((u32)(v & 1u) << 16); break;
    }
}

static u8 mem_rd8(u32 addr);
static void mem_wr8(u32 addr, u8 v);

/* DMA byte pattern offsets for modes 0..7 */
static const u8 dma_b_off[8][4] = {
    {0, 0, 0, 0}, {0, 1, 0, 1}, {0, 0, 0, 0}, {0, 0, 1, 1},
    {0, 1, 2, 3}, {0, 1, 0, 1}, {0, 0, 0, 0}, {0, 0, 1, 1}
};
static const u8 dma_unit_len[8] = {1, 2, 2, 4, 4, 4, 2, 4};

static void dma_xfer_byte(u32 a_addr, u8 b_reg, int to_cpu)
{
    /* Avoid A-bus <-> B-bus conflict when A-bus points to $21xx in system banks */
    u8 bank = (u8)(a_addr >> 16);
    u16 off = (u16)a_addr;
    int a_is_bbus = ((bank & 0x7Fu) < 0x40u) && (off >= 0x2100u && off <= 0x21FFu);
    if (to_cpu) {
        u8 v = bbus_rd(b_reg);
        if (!a_is_bbus)
            mem_wr8(a_addr, v);
    } else {
        u8 v = a_is_bbus ? 0 : mem_rd8(a_addr);
        bbus_wr(b_reg, v);
    }
}

static void run_gpdma(u8 mask)
{
    for (int ch = 0; ch < 8; ch++) {
        if (!(mask & (1u << ch)))
            continue;
        struct snes_dma_ch *d = &S.dma[ch];
        int to_cpu = (d->dmap & 0x80u) != 0;
        int step_mode = (d->dmap >> 3) & 3u;
        int mode = d->dmap & 7u;
        u32 count = d->das ? d->das : 0x10000u;
        u32 idx = 0;
        while (count--) {
            u8 b_reg = (u8)(d->bbad + dma_b_off[mode][idx & 3u]);
            dma_xfer_byte(((u32)d->a1b << 16) | d->a1t, b_reg, to_cpu);
            if (step_mode == 0)      d->a1t++;
            else if (step_mode == 2) d->a1t--;
            idx++;
            S.master_cyc += 8;
        }
        d->das = 0;
    }
}

static void hdma_load_entry(struct snes_dma_ch *d)
{
    u8 hdr = mem_rd8(((u32)d->a1b << 16) | d->a2a++);
    d->nltr = hdr;
    if (hdr == 0) {
        d->hdma_terminated = 1;
        d->hdma_do_xfer = 0;
        return;
    }
    if (d->dmap & 0x40u) {                  /* Indirect HDMA */
        u8 lo = mem_rd8(((u32)d->a1b << 16) | d->a2a++);
        u8 hi = mem_rd8(((u32)d->a1b << 16) | d->a2a++);
        d->das = (u16)(lo | ((u16)hi << 8));
    }
    d->hdma_do_xfer = 1;
}

static u8 s_hdmaen;

static void run_hdma_init(void)
{
    for (int ch = 0; ch < 8; ch++) {
        struct snes_dma_ch *d = &S.dma[ch];
        d->hdma_terminated = 0;
        d->hdma_do_xfer = 0;
        if (!(s_hdmaen & (1u << ch)))
            continue;
        d->a2a = d->a1t;
        hdma_load_entry(d);
        S.master_cyc += 18;
    }
}

static void run_hdma_scanline(void)
{
    for (int ch = 0; ch < 8; ch++) {
        if (!(s_hdmaen & (1u << ch)))
            continue;
        struct snes_dma_ch *d = &S.dma[ch];
        if (d->hdma_terminated)
            continue;
        if (d->hdma_do_xfer) {
            int to_cpu = (d->dmap & 0x80u) != 0;
            int indirect = (d->dmap & 0x40u) != 0;
            int mode = d->dmap & 7u;
            int len = dma_unit_len[mode];
            for (int i = 0; i < len; i++) {
                u8 b_reg = (u8)(d->bbad + dma_b_off[mode][i]);
                u32 a_addr = indirect ? (((u32)d->dasb << 16) | d->das++)
                                      : (((u32)d->a1b << 16) | d->a2a++);
                dma_xfer_byte(a_addr, b_reg, to_cpu);
                S.master_cyc += 8;
            }
        }
        d->nltr--;
        d->hdma_do_xfer = (d->nltr & 0x80u) != 0;
        if ((d->nltr & 0x7Fu) == 0)
            hdma_load_entry(d);
    }
}

static u8 scpu_io_rd(u16 off)
{
    if (off >= 0x2100u && off <= 0x21FFu)
        return bbus_rd((u8)off);
    if (off == 0x4016u) {
        u8 bit = (u8)((S.joy1_shift >> 15) & 1u);
        if (!S.joy_strobe)
            S.joy1_shift = (u16)((S.joy1_shift << 1) | 1u);
        return (u8)((S.mdr & 0xFCu) | bit);
    }
    if (off == 0x4017u)
        return (u8)((S.mdr & 0xE0u) | 0x1Cu);
    if (off >= 0x4300u && off <= 0x437Fu) {
        struct snes_dma_ch *d = &S.dma[(off >> 4) & 7u];
        switch (off & 0x0Fu) {
        case 0x0: return d->dmap;
        case 0x1: return d->bbad;
        case 0x2: return (u8)d->a1t;
        case 0x3: return (u8)(d->a1t >> 8);
        case 0x4: return d->a1b;
        case 0x5: return (u8)d->das;
        case 0x6: return (u8)(d->das >> 8);
        case 0x7: return d->dasb;
        case 0x8: return (u8)d->a2a;
        case 0x9: return (u8)(d->a2a >> 8);
        case 0xA: return d->nltr;
        default:  return d->unused;
        }
    }
    switch (off) {
    case 0x4210: { u8 v = (u8)((S.mdr & 0x70u) | 0x02u | S.rdnmi); S.rdnmi = 0; return v; }
    case 0x4211: { u8 v = (u8)((S.mdr & 0x7Fu) | S.timeup); S.timeup = 0; S.irq_line = 0; return v; }
    case 0x4212: {
        u32 hc = (u32)(S.master_cyc % 1364);
        u8 hb = (hc >= 1096u) ? 0x40u : 0x00u;
        u8 vb = (S.cur_line >= S.out_h + 1) ? 0x80u : 0x00u;
        return (u8)((S.mdr & 0x3Eu) | vb | hb);
    }
    case 0x4213: return S.wrio;
    case 0x4214: return (u8)S.rddiv;
    case 0x4215: return (u8)(S.rddiv >> 8);
    case 0x4216: return (u8)S.rdmpy;
    case 0x4217: return (u8)(S.rdmpy >> 8);
    case 0x4218: return (u8)S.joy1_hw;
    case 0x4219: return (u8)(S.joy1_hw >> 8);
    case 0x421A: case 0x421B: case 0x421C: case 0x421D: case 0x421E: case 0x421F:
        return 0;
    }
    return S.mdr;
}

static void scpu_io_wr(u16 off, u8 v)
{
    if (off >= 0x2100u && off <= 0x21FFu) {
        bbus_wr((u8)off, v);
        return;
    }
    if (off == 0x4016u) {
        S.joy_strobe = v & 1u;
        if (S.joy_strobe)
            S.joy1_shift = S.joy1_hw;
        return;
    }
    if (off >= 0x4300u && off <= 0x437Fu) {
        struct snes_dma_ch *d = &S.dma[(off >> 4) & 7u];
        switch (off & 0x0Fu) {
        case 0x0: d->dmap = v; break;
        case 0x1: d->bbad = v; break;
        case 0x2: d->a1t = (u16)((d->a1t & 0xFF00u) | v); break;
        case 0x3: d->a1t = (u16)((d->a1t & 0x00FFu) | ((u16)v << 8)); break;
        case 0x4: d->a1b = v; break;
        case 0x5: d->das = (u16)((d->das & 0xFF00u) | v); break;
        case 0x6: d->das = (u16)((d->das & 0x00FFu) | ((u16)v << 8)); break;
        case 0x7: d->dasb = v; break;
        case 0x8: d->a2a = (u16)((d->a2a & 0xFF00u) | v); break;
        case 0x9: d->a2a = (u16)((d->a2a & 0x00FFu) | ((u16)v << 8)); break;
        case 0xA: d->nltr = v; break;
        default:  d->unused = v; break;
        }
        return;
    }
    switch (off) {
    case 0x4200: {
        u8 old = S.nmitimen;
        S.nmitimen = v;
        if ((v & 0x80u) && !(old & 0x80u) && (S.rdnmi & 0x80u))
            S.nmi_pending = 1;
        if (!(v & 0x30u)) {
            S.timeup = 0;
            S.irq_line = 0;
        }
        break;
    }
    case 0x4201: S.wrio = v; break;
    case 0x4202: S.wrmpya = v; break;
    case 0x4203:
        S.wrmpyb = v;
        S.rdmpy = (u16)S.wrmpya * (u16)v;
        break;
    case 0x4204: S.wrdiva = (u16)((S.wrdiva & 0xFF00u) | v); break;
    case 0x4205: S.wrdiva = (u16)((S.wrdiva & 0x00FFu) | ((u16)v << 8)); break;
    case 0x4206:
        S.wrdivb = v;
        if (v == 0) {
            S.rddiv = 0xFFFFu;
            S.rdmpy = S.wrdiva;
        } else {
            S.rddiv = (u16)(S.wrdiva / v);
            S.rdmpy = (u16)(S.wrdiva % v);
        }
        break;
    case 0x4207: S.htime = (u16)((S.htime & 0x0100u) | v); break;
    case 0x4208: S.htime = (u16)((S.htime & 0x00FFu) | ((u16)(v & 1u) << 8)); break;
    case 0x4209: S.vtime = (u16)((S.vtime & 0x0100u) | v); break;
    case 0x420A: S.vtime = (u16)((S.vtime & 0x00FFu) | ((u16)(v & 1u) << 8)); break;
    case 0x420B: if (v) run_gpdma(v); break;
    case 0x420C: s_hdmaen = v; break;
    case 0x420D: S.memsel = v & 1u; break;
    }
}

static u32 mirror_rom_off(u32 off, u32 size)
{
    if (!size)
        return 0;
    /* Standard SNES two-chip power-of-two mirroring (e.g. 768 KB = 512 KB + 256 KB) */
    u32 p2 = 1u;
    while ((p2 << 1) <= size)
        p2 <<= 1;
    if (p2 == size)
        return off & (size - 1u);
    u32 rem = size - p2;
    u32 r2 = 1u;
    while (r2 < rem)
        r2 <<= 1;
    off &= (p2 << 1) - 1u;
    if (off >= p2)
        off = p2 + ((off - p2) & (r2 - 1u));
    if (off >= size)
        off %= size;
    return off;
}

/* =====================================================================
 * DSP-1: the maths coprocessor in the cartridges of Super Mario Kart, Pilotwings and a dozen others (a NEC
 * uPD77C25 running Nintendo's program).  The game writes a command byte and its 16-bit parameters to the
 * chip's data register and reads 16-bit results back; the status register's top bit says the chip is ready.
 * The program is not run here: each command's result is worked out directly, in the program's own fixed-point
 * steps (normalising to mantissa and exponent, the inverse by Newton's iteration from a table of seeds, sines
 * from a table with a linear step, square roots between table nodes) as those who took the chip apart
 * described them (Overload, Andreas Naive, neviksti and The Dumper; the Snes9x and bsnes documentation of the
 * DSP-1), written anew.  The tables are computed from what they hold (sine, 1 / x, square root; pi * i comes
 * from a multiplication).  Not compared with a real chip.
 * ===================================================================== */
#define D1 S.d1
#define D1_RQM 0x8000u          /* status: ready for the next byte */
#define D1_DRS 0x1000u          /* ... the second byte of a word is next */
#define D1_DRC 0x0400u          /* ... the data register takes bytes (a command), not words */

static const s16 d1_sin_half[128] = {       /* 32767 * sin(2 pi i / 256), the first half turn */
    0x0000, 0x0324, 0x0648, 0x096A, 0x0C8C, 0x0FAB, 0x12C8, 0x15E2, 0x18F9, 0x1C0B, 0x1F1A, 0x2223,
    0x2528, 0x2826, 0x2B1F, 0x2E11, 0x30FB, 0x33DF, 0x36BA, 0x398C, 0x3C56, 0x3F17, 0x41CE, 0x447A,
    0x471C, 0x49B4, 0x4C3F, 0x4EBF, 0x5133, 0x539B, 0x55F5, 0x5842, 0x5A82, 0x5CB3, 0x5ED7, 0x60EB,
    0x62F1, 0x64E8, 0x66CF, 0x68A6, 0x6A6D, 0x6C23, 0x6DC9, 0x6F5E, 0x70E2, 0x7254, 0x73B5, 0x7504,
    0x7641, 0x776B, 0x7884, 0x7989, 0x7A7C, 0x7B5C, 0x7C29, 0x7CE3, 0x7D89, 0x7E1D, 0x7E9C, 0x7F09,
    0x7F61, 0x7FA6, 0x7FD8, 0x7FF5, 0x7FFF, 0x7FF5, 0x7FD8, 0x7FA6, 0x7F61, 0x7F09, 0x7E9C, 0x7E1D,
    0x7D89, 0x7CE3, 0x7C29, 0x7B5C, 0x7A7C, 0x7989, 0x7884, 0x776B, 0x7641, 0x7504, 0x73B5, 0x7254,
    0x70E2, 0x6F5E, 0x6DC9, 0x6C23, 0x6A6D, 0x68A6, 0x66CF, 0x64E8, 0x62F1, 0x60EB, 0x5ED7, 0x5CB3,
    0x5A82, 0x5842, 0x55F5, 0x539B, 0x5133, 0x4EBF, 0x4C3F, 0x49B4, 0x471C, 0x447A, 0x41CE, 0x3F17,
    0x3C56, 0x398C, 0x36BA, 0x33DF, 0x30FB, 0x2E11, 0x2B1F, 0x2826, 0x2528, 0x2223, 0x1F1A, 0x1C0B,
    0x18F9, 0x15E2, 0x12C8, 0x0FAB, 0x0C8C, 0x096A, 0x0648, 0x0324,
};
static const s16 d1_inv_seed[128] = {       /* 2^29 / (4000h + 80h * i): where the inverse's iteration starts */
    0x7FFF, 0x7F02, 0x7E08, 0x7D12, 0x7C1F, 0x7B30, 0x7A45, 0x795D, 0x7878, 0x7797, 0x76BA, 0x75DF,
    0x7507, 0x7433, 0x7361, 0x7293, 0x71C7, 0x70FE, 0x7038, 0x6F75, 0x6EB4, 0x6DF6, 0x6D3A, 0x6C81,
    0x6BCA, 0x6B16, 0x6A64, 0x69B4, 0x6907, 0x685B, 0x67B2, 0x670B, 0x6666, 0x65C4, 0x6523, 0x6484,
    0x63E7, 0x634C, 0x62B3, 0x621C, 0x6186, 0x60F2, 0x6060, 0x5FD0, 0x5F41, 0x5EB5, 0x5E29, 0x5D9F,
    0x5D17, 0x5C91, 0x5C0C, 0x5B88, 0x5B06, 0x5A85, 0x5A06, 0x5988, 0x590B, 0x5890, 0x5816, 0x579D,
    0x5726, 0x56B0, 0x563B, 0x55C8, 0x5555, 0x54E4, 0x5474, 0x5405, 0x5398, 0x532B, 0x52BF, 0x5255,
    0x51EC, 0x5183, 0x511C, 0x50B6, 0x5050, 0x4FEC, 0x4F89, 0x4F26, 0x4EC5, 0x4E64, 0x4E05, 0x4DA6,
    0x4D48, 0x4CEC, 0x4C90, 0x4C34, 0x4BDA, 0x4B81, 0x4B28, 0x4AD0, 0x4A79, 0x4A23, 0x49CD, 0x4979,
    0x4925, 0x48D1, 0x487F, 0x482D, 0x47DC, 0x478C, 0x473C, 0x46ED, 0x469F, 0x4651, 0x4604, 0x45B8,
    0x456C, 0x4521, 0x44D7, 0x448D, 0x4444, 0x43FC, 0x43B4, 0x436D, 0x4326, 0x42E0, 0x429A, 0x4255,
    0x4211, 0x41CD, 0x4189, 0x4146, 0x4104, 0x40C2, 0x4081, 0x4040,
};
static const s16 d1_sqrt_tab[65] = {        /* 32768 * sqrt(i / 64) */
    0x0000, 0x1000, 0x16A0, 0x1BB6, 0x2000, 0x23C6, 0x2731, 0x2A54, 0x2D41, 0x3000, 0x3298, 0x3510,
    0x376C, 0x39B0, 0x3BDD, 0x3DF7, 0x4000, 0x41F8, 0x43E1, 0x45BE, 0x478D, 0x4952, 0x4B0B, 0x4CBB,
    0x4E62, 0x5000, 0x5195, 0x5323, 0x54A9, 0x5629, 0x57A2, 0x5915, 0x5A82, 0x5BE9, 0x5D4B, 0x5EA8,
    0x6000, 0x6152, 0x62A1, 0x63EB, 0x6531, 0x6673, 0x67B1, 0x68EB, 0x6A21, 0x6B54, 0x6C84, 0x6DB0,
    0x6ED9, 0x7000, 0x7123, 0x7243, 0x7360, 0x747B, 0x7593, 0x76A8, 0x77BB, 0x78CC, 0x79DA, 0x7AE5,
    0x7BEF, 0x7CF6, 0x7DFB, 0x7EFE, 0x7FFF,
};
/* the steepest view (zenith angle) that command 02h takes, by the exponent of the view centre's height */
static const s16 d1_max_azs[16] = {
    0x38B4, 0x38B7, 0x38BA, 0x38BE, 0x38C0, 0x38C4, 0x38C7, 0x38CA,
    0x38CE, 0x38D0, 0x38D4, 0x38D7, 0x38DA, 0x38DD, 0x38E0, 0x38E4,
};
/* a command's words: parameters in the high nibble, results in the low one (Fh: the 1024 words of the chip's
   data ROM; 00h: the three commands that stop the chip) */
static const u8 d1_words[64] = {
    0x21, 0x40, 0x74, 0x33, 0x22, 0x40, 0x33, 0x11, 0x32, 0x33, 0x14, 0x31, 0x32, 0x33, 0x22, 0x11,
    0x22, 0x40, 0x74, 0x33, 0x63, 0x40, 0x33, 0x1F, 0x41, 0x33, 0x00, 0x31, 0x63, 0x33, 0x22, 0x1F,
    0x21, 0x40, 0x74, 0x33, 0x22, 0x40, 0x33, 0x11, 0x31, 0x33, 0x00, 0x31, 0x32, 0x33, 0x22, 0x11,
    0x22, 0x40, 0x74, 0x33, 0x63, 0x40, 0x33, 0x1F, 0x41, 0x33, 0x00, 0x31, 0x63, 0x33, 0x22, 0x1F,
};

static s32 d1_sin_at(int i)                 /* (i up to BFh) */
{
    return i < 128 ? d1_sin_half[i] : -(s32)d1_sin_half[i - 128];
}

static s16 d1_sin(s16 a)
{
    if (a < 0) {
        if (a == -32768)
            return 0;
        return (s16)-d1_sin((s16)-a);
    }
    s32 step = ((a & 0xFF) * 205887) >> 16;                     /* pi * the angle's low byte */
    s32 s = d1_sin_at(a >> 8) + ((step * d1_sin_at(0x40 + (a >> 8))) >> 15);
    return (s16)(s > 32767 ? 32767 : s);
}

static s16 d1_cos(s16 a)
{
    if (a < 0) {
        if (a == -32768)
            return -32768;
        a = (s16)-a;
    }
    s32 step = ((a & 0xFF) * 205887) >> 16;
    s32 s = d1_sin_at(0x40 + (a >> 8)) - ((step * d1_sin_at(a >> 8)) >> 15);
    return (s16)(s < -32768 ? -32767 : s);
}

/* how many bits the 15-bit m can be shifted up before its top bit differs from the sign (15: m is 0 or -1) */
static int d1_headroom(s16 m)
{
    int n = 0;
    s16 bit = 0x4000;
    if (m < 0)
        while ((m & bit) && bit) { bit >>= 1; n++; }
    else
        while (!(m & bit) && bit) { bit >>= 1; n++; }
    return n;
}

static s16 d1_shl(s16 m, int n) { return (s16)(u16)((u32)(u16)m << n); }

/* m as a mantissa with the exponent lowered by the shifts made */
static void d1_norm(s16 m, s16 *c, s16 *e)
{
    int n = d1_headroom(m);
    *c = d1_shl(m, n);
    *e = (s16)(*e - n);
}

/* a 31-bit product as a mantissa; the exponent is the number of shifts.  With 4 shifts the chip loses the low
   half's part (its data ROM has 0001h where the power of two 0010h belongs): kept */
static void d1_norm32(s32 p, s16 *c, s16 *e)
{
    s16 lo = (s16)(p & 0x7FFF);
    s16 hi = (s16)(p >> 15);
    int n = d1_headroom(hi);
    if (n == 0) {
        *c = hi;
    } else {
        *c = d1_shl(hi, n);
        if (n < 15) {
            if (n != 4)
                *c = (s16)(*c + (lo >> (15 - n)));
        } else {
            s16 bit = 0x4000;
            if (hi < 0)
                while ((lo & bit) && bit) { bit >>= 1; n++; }
            else
                while (!(lo & bit) && bit) { bit >>= 1; n++; }
            if (n > 15)
                *c = d1_shl(lo, n - 15);
            else
                *c = (s16)(*c + lo);
        }
    }
    *e = (s16)n;
}

/* mantissa and exponent back to a number: too large clips, small ones lose their low bits */
static s16 d1_denorm(s16 c, s16 e)
{
    if (e > 0)
        return (s16)(c > 0 ? 32767 : c < 0 ? -32767 : 0);
    if (e < 0)
        return (s16)(e > -16 ? c >> -e : 0);
    return c;
}

/* the projection's alignment shift, by a multiplication with the data ROM's powers of two as the chip does it:
   7FFFh for no shift, and the wrong entry again (11 places shift as 15) */
static s16 d1_align(s16 c, int e)
{
    if (e == 0)
        return (s16)((c * 0x7FFF) >> 15);
    if (e > 15)
        return 0;
    return (s16)(c >> (e == 11 ? 15 : e));
}

/* 1 / (c * 2^e) as a mantissa and an exponent: the seed for the normalised c, two Newton steps */
static void d1_inverse(s16 c, s16 e, s16 *ic, s16 *ie)
{
    if (c == 0) {
        *ic = 0x7FFF;
        *ie = 0x002F;
        return;
    }
    int neg = 0;
    if (c < 0) {
        if (c < -32767)
            c = -32767;
        c = (s16)-c;
        neg = 1;
    }
    while (c < 0x4000) {
        c = (s16)(c << 1);
        e--;
    }
    if (c == 0x4000) {
        if (!neg) {
            *ic = 0x7FFF;
        } else {
            *ic = -0x4000;
            e--;
        }
    } else {
        s32 i = d1_inv_seed[(c - 0x4000) >> 7];
        i = (s16)((i + ((-i * ((c * i) >> 15)) >> 15)) << 1);
        i = (s16)((i + ((-i * ((c * i) >> 15)) >> 15)) << 1);
        *ic = (s16)(neg ? -i : i);
    }
    *ie = (s16)(1 - e);
}

/* command 02h: the view (focus point, distances eye - focus and eye - screen, azimuth and zenith angles) */
static void d1_parameter(const s16 *in, s16 *out)
{
    s16 fx = in[0], fy = in[1], fz = in[2], lfe = in[3], les = in[4], aas = in[5], azs = in[6];
    s16 c, e, csec, max_azs, aux;
    s16 azs_cl = azs;

    D1.sin_aas = d1_sin(aas);
    D1.cos_aas = d1_cos(aas);
    D1.sin_azs = d1_sin(azs);
    D1.cos_azs = d1_cos(azs);

    D1.nx = (s16)((D1.sin_azs * -D1.sin_aas) >> 15);
    D1.ny = (s16)((D1.sin_azs * D1.cos_aas) >> 15);
    D1.nz = (s16)((D1.cos_azs * 0x7FFF) >> 15);

    /* the centre of the projection */
    D1.centre_x = (s16)(fx + ((lfe * D1.nx) >> 15));
    D1.centre_y = (s16)(fy + ((lfe * D1.ny) >> 15));
    s16 centre_z = (s16)(fz + ((lfe * D1.nz) >> 15));

    D1.gx = (s16)(D1.centre_x - ((les * D1.nx) >> 15));
    D1.gy = (s16)(D1.centre_y - ((les * D1.ny) >> 15));
    D1.gz = (s16)(centre_z - ((les * D1.nz) >> 15));

    D1.les_e = 0;
    d1_norm(les, &D1.les_c, &D1.les_e);
    D1.les = les;

    e = 0;
    d1_norm(centre_z, &c, &e);
    D1.vplane_c = c;
    D1.vplane_e = e;

    /* the zenith angle is clipped to what the height allows */
    max_azs = d1_max_azs[-e & 15];
    if (azs_cl < 0) {
        max_azs = (s16)-max_azs;
        if (azs_cl < max_azs + 1)
            azs_cl = (s16)(max_azs + 1);
    } else if (azs_cl > max_azs) {
        azs_cl = max_azs;
    }
    D1.sin_azs_cl = d1_sin(azs_cl);
    D1.cos_azs_cl = d1_cos(azs_cl);

    d1_inverse(D1.cos_azs_cl, 0, &D1.sec1_c, &D1.sec1_e);
    d1_norm((s16)((c * D1.sec1_c) >> 15), &c, &e);
    e = (s16)(e + D1.sec1_e);
    c = (s16)((d1_denorm(c, e) * D1.sin_azs_cl) >> 15);

    D1.centre_x = (s16)(D1.centre_x + ((c * D1.sin_aas) >> 15));
    D1.centre_y = (s16)(D1.centre_y - ((c * D1.cos_aas) >> 15));
    out[2] = D1.centre_x;
    out[3] = D1.centre_y;

    /* the raster line of the horizon; past the clip the tangent and the secant go on as short series */
    s16 vof = 0;
    if (azs != azs_cl || azs == max_azs) {
        if (azs == -32768)
            azs = -32767;
        c = (s16)(azs - max_azs);
        if (c >= 0)
            c--;
        aux = (s16)~(c << 2);
        c = (s16)((aux * 0x14AC) >> 15);
        c = (s16)(((c * aux) >> 15) + 0x6488);
        vof = (s16)(vof - ((((c * aux) >> 15) * les) >> 15));
        c = (s16)((aux * aux) >> 15);
        aux = (s16)(((c * 0x0A26) >> 15) + 0x277A);
        D1.cos_azs_cl = (s16)(D1.cos_azs_cl + ((((c * aux) >> 15) * D1.cos_azs_cl) >> 15));
    }
    out[0] = vof;

    D1.v_offset = (s16)((les * D1.cos_azs_cl) >> 15);

    d1_inverse(D1.sin_azs_cl, 0, &csec, &e);
    d1_norm(D1.v_offset, &c, &e);
    d1_norm((s16)((c * csec) >> 15), &c, &e);
    if (c == -32768) {
        c >>= 1;
        e++;
    }
    out[1] = d1_denorm((s16)-c, e);

    d1_inverse(D1.cos_azs_cl, 0, &D1.sec2_c, &D1.sec2_e);
}

/* command 0Ah: the Mode 7 matrix (A, B, C, D) of raster line vs */
static void d1_raster(s16 vs, s16 *out)
{
    s16 c, e, c1, e1;

    d1_inverse((s16)(((vs * D1.sin_azs) >> 15) + D1.v_offset), 7, &c, &e);
    e = (s16)(e + D1.vplane_e);
    c1 = (s16)((c * D1.vplane_c) >> 15);
    e1 = (s16)(e + D1.sec2_e);

    d1_norm(c1, &c, &e);
    c = d1_denorm(c, e);
    out[0] = (s16)((c * D1.cos_aas) >> 15);
    out[2] = (s16)((c * D1.sin_aas) >> 15);

    d1_norm((s16)((c1 * D1.sec2_c) >> 15), &c, &e1);
    c = d1_denorm(c, e1);
    out[1] = (s16)((c * -D1.sin_aas) >> 15);
    out[3] = (s16)((c * D1.cos_aas) >> 15);
}

/* command 06h: a point of the world on the screen (H, V) and the size (M) of what stands there */
static void d1_project(const s16 *in, s16 *out)
{
    s16 px, py, pz, ex, ey, ez, ref;
    s16 c2, c4, c6, c10, c19, c25, e2, e4, e6, e7;

    d1_norm32((s32)in[0] - D1.gx, &px, &ex);
    d1_norm32((s32)in[1] - D1.gy, &py, &ey);
    d1_norm32((s32)in[2] - D1.gz, &pz, &ez);
    px >>= 1; ex--;                         /* (room for the scalar products) */
    py >>= 1; ey--;
    pz >>= 1; ez--;

    ref = ey < ez ? ey : ez;
    if (ex < ref)
        ref = ex;
    px = d1_align(px, ex - ref);            /* all three to one exponent */
    py = d1_align(py, ey - ref);
    pz = d1_align(pz, ez - ref);

    /* the eye's distance from the point along the line of sight: the screen's distance less the point's part
       along the screen's normal */
    s32 along = -((px * D1.nx) >> 15) - ((py * D1.ny) >> 15) - ((pz * D1.nz) >> 15);
    ref = (s16)(16 - ref);
    if (ref >= 0)
        along = (s32)((u32)along << ref);
    else
        along >>= -ref;
    if (along == -1)
        along = 0;
    along >>= 1;
    d1_norm32((s32)(u16)D1.les + along, &c10, &e2);
    e2 = (s16)(15 - e2);

    d1_inverse(c10, 0, &c4, &e4);
    c2 = (s16)((c4 * D1.les_c) >> 15);      /* the scale */

    /* H: the point's part along the screen's horizontal, scaled */
    e7 = 0;
    s16 h = (s16)(((px * ((D1.cos_aas * 0x7FFF) >> 15)) >> 15) + ((py * ((D1.sin_aas * 0x7FFF) >> 15)) >> 15));
    d1_norm((s16)((h * c2) >> 15), &c19, &e7);
    out[0] = d1_denorm(c19, (s16)(D1.les_e - e2 + ref + e7));

    /* V: ... along the screen's vertical */
    e6 = 0;
    s16 v = (s16)(((px * ((D1.cos_azs * -D1.sin_aas) >> 15)) >> 15) +
                  ((py * ((D1.cos_azs * D1.cos_aas) >> 15)) >> 15) +
                  ((pz * ((-D1.sin_azs * 0x7FFF) >> 15)) >> 15));
    d1_norm((s16)((v * c2) >> 15), &c25, &e6);
    out[1] = d1_denorm(c25, (s16)(D1.les_e - e2 + ref + e6));

    /* M: the scale / 128 */
    d1_norm(c2, &c6, &e4);
    out[2] = d1_denorm(c6, (s16)(e4 + D1.les_e - e2 - 7));
}

/* command 0Eh: the point of the ground that screen position (H, V) shows */
static void d1_target(s16 h, s16 v, s16 *out)
{
    s16 c, e, c1, e1;

    d1_inverse((s16)(((v * D1.sin_azs) >> 15) + D1.v_offset), 8, &c, &e);
    e = (s16)(e + D1.vplane_e);
    c1 = (s16)((c * D1.vplane_c) >> 15);
    e1 = (s16)(e + D1.sec1_e);

    h = d1_shl(h, 8);
    d1_norm(c1, &c, &e);
    c = (s16)((d1_denorm(c, e) * h) >> 15);
    s16 x = (s16)(D1.centre_x + ((c * D1.cos_aas) >> 15));       /* (H along the screen's horizontal: the raster */
    s16 y = (s16)(D1.centre_y + ((c * D1.sin_aas) >> 15));       /*  matrix's A and C) */

    v = d1_shl(v, 8);
    d1_norm((s16)((c1 * D1.sec1_c) >> 15), &c, &e1);
    c = (s16)((d1_denorm(c, e1) * v) >> 15);
    out[0] = (s16)(x + ((c * -D1.sin_aas) >> 15));
    out[1] = (s16)(y + ((c * D1.cos_aas) >> 15));
}

/* commands 01h / 11h / 21h: an attitude matrix from a scale and three angles (z, y, x) */
static void d1_attitude(s16 (*m)[3], const s16 *in)
{
    s16 s = (s16)(in[0] >> 1);
    s16 sz = d1_sin(in[1]), cz = d1_cos(in[1]);
    s16 sy = d1_sin(in[2]), cy = d1_cos(in[2]);
    s16 sx = d1_sin(in[3]), cx = d1_cos(in[3]);
    s32 scz = (s * cz) >> 15, ssz = (s * sz) >> 15;

    m[0][0] = (s16)((scz * cy) >> 15);
    m[0][1] = (s16)-((ssz * cy) >> 15);
    m[0][2] = (s16)((s * sy) >> 15);
    m[1][0] = (s16)(((ssz * cx) >> 15) + ((((scz * sx) >> 15) * sy) >> 15));
    m[1][1] = (s16)(((scz * cx) >> 15) - ((((ssz * sx) >> 15) * sy) >> 15));
    m[1][2] = (s16)-((((s * sx) >> 15) * cy) >> 15);
    m[2][0] = (s16)(((ssz * sx) >> 15) - ((((scz * cx) >> 15) * sy) >> 15));
    m[2][1] = (s16)(((scz * sx) >> 15) + ((((ssz * cx) >> 15) * sy) >> 15));
    m[2][2] = (s16)((((s * cx) >> 15) * cy) >> 15);
}

/* command 14h: the new attitude angles after turning by (U, F, L) about the object's own axes */
static void d1_gyrate(const s16 *in, s16 *out)
{
    s16 az = in[0], ax = in[1], ay = in[2], u = in[3], f = in[4], l = in[5];
    s16 csec, esec, csin, ctan, c, e;
    s16 say = d1_sin(ay), cay = d1_cos(ay);

    d1_inverse(d1_cos(ax), 0, &csec, &esec);

    d1_norm32(u * cay - f * say, &c, &e);
    e = (s16)(esec - e);
    d1_norm((s16)((c * csec) >> 15), &c, &e);
    out[0] = (s16)(az + d1_denorm(c, e));

    out[1] = (s16)(ax + ((u * say) >> 15) + ((f * cay) >> 15));

    d1_norm32(u * cay + f * say, &c, &e);
    e = (s16)(esec - e);
    d1_norm(d1_sin(ax), &csin, &e);
    ctan = (s16)((csec * csin) >> 15);
    d1_norm((s16)-((c * ctan) >> 15), &c, &e);
    out[2] = (s16)(ay + d1_denorm(c, e) + l);
}

static void __attribute__((noinline)) d1_exec(void)
{
    const s16 *in = D1.in;
    s16 *out = D1.out;
    u8 cmd = D1.cmd;
    s16 (*m)[3] = D1.mat[(cmd >> 4) == 1 ? 1 : (cmd >> 4) == 2 ? 2 : 0];

    switch (cmd & 0x0Fu) {
    case 0x00:                              /* 00h, 20h multiply; 10h, 30h inverse */
        if (cmd & 0x10u)
            d1_inverse(in[0], in[1], &out[0], &out[1]);
        else
            out[0] = (s16)(((in[0] * in[1]) >> 15) + ((cmd & 0x20u) ? 1 : 0));
        break;
    case 0x01: case 0x05:                   /* attitude matrix A (01h, 31h), B (11h), C (21h) */
        d1_attitude(m, in);
        break;
    case 0x02:                              /* the projection's parameters */
        d1_parameter(in, out);
        break;
    case 0x03:                              /* subjective: (F, L, U) of the object's axes into the world's */
        for (int k = 0; k < 3; k++)
            out[k] = (s16)(((in[0] * m[0][k]) >> 15) + ((in[1] * m[1][k]) >> 15) + ((in[2] * m[2][k]) >> 15));
        break;
    case 0x04:                              /* 04h, 24h triangle: radius * sine and cosine */
        if (cmd & 0x10u) {
            d1_gyrate(in, out);             /* 14h, 34h */
        } else {
            out[0] = (s16)((d1_sin(in[0]) * in[1]) >> 15);
            out[1] = (s16)((d1_cos(in[0]) * in[1]) >> 15);
        }
        break;
    case 0x06:
        d1_project(in, out);
        break;
    case 0x07: case 0x0F:                   /* memory test (0), memory size (27h, 2Fh), data ROM (17h..3Fh) */
        out[0] = (s16)((cmd & 0x30u) == 0x20u ? 0x0100 : 0x0000);
        break;
    case 0x08: {                            /* 08h radius; 18h, 38h range; 28h distance */
        s32 sq = in[0] * in[0] + in[1] * in[1] + in[2] * in[2];
        if ((cmd & 0x30u) == 0x00u) {
            sq = (s32)((u32)sq << 1);
            out[0] = (s16)sq;
            out[1] = (s16)(sq >> 16);
        } else if ((cmd & 0x30u) == 0x20u) {
            s16 r = 0;
            if (sq) {
                s16 c, e;
                d1_norm32(sq, &c, &e);
                if (e & 1)
                    c = (s16)((c * 0x4000) >> 15);
                int node = (c * 0x0040) >> 15;
                s32 lo = d1_sqrt_tab[node & 63], hi = d1_sqrt_tab[(node & 63) + 1];
                r = (s16)((((hi - lo) * (c & 0x1FF)) >> 9) + lo);
                r = (s16)(r >> (e >> 1));
            }
            out[0] = r;
        } else {
            out[0] = (s16)(((sq - in[3] * in[3]) >> 15) + ((cmd & 0x20u) ? 1 : 0));
        }
        break;
    }
    case 0x09: case 0x0D:                   /* objective: a world vector along the object's axes */
        for (int k = 0; k < 3; k++)
            out[k] = (s16)(((in[0] * m[k][0]) >> 15) + ((in[1] * m[k][1]) >> 15) + ((in[2] * m[k][2]) >> 15));
        break;
    case 0x0A:
        d1_raster(in[0], out);
        break;
    case 0x0B:                              /* scalar: the vector's part along the object's forward axis */
        out[0] = (s16)((in[0] * m[0][0] + in[1] * m[0][1] + in[2] * m[0][2]) >> 15);
        break;
    case 0x0C:
        if (cmd & 0x10u) {                  /* 1Ch, 3Ch polar: a vector turned about z, y, x in turn */
            s16 x = in[3], y = in[4], z = in[5], t;
            s16 s = d1_sin(in[0]), c = d1_cos(in[0]);
            t = (s16)(((y * s) >> 15) + ((x * c) >> 15));
            y = (s16)(((y * c) >> 15) - ((x * s) >> 15));
            x = t;
            s = d1_sin(in[1]); c = d1_cos(in[1]);
            t = (s16)(((x * s) >> 15) + ((z * c) >> 15));
            x = (s16)(((x * c) >> 15) - ((z * s) >> 15));
            z = t;
            out[0] = x;
            s = d1_sin(in[2]); c = d1_cos(in[2]);
            out[1] = (s16)(((z * s) >> 15) + ((y * c) >> 15));
            out[2] = (s16)(((z * c) >> 15) - ((y * s) >> 15));
        } else {                            /* 0Ch, 2Ch rotate in the plane */
            s16 s = d1_sin(in[0]), c = d1_cos(in[0]);
            out[0] = (s16)(((in[2] * s) >> 15) + ((in[1] * c) >> 15));
            out[1] = (s16)(((in[2] * c) >> 15) - ((in[1] * s) >> 15));
        }
        break;
    case 0x0E:
        d1_target(in[0], in[1], out);
        break;
    }
}

static void d1_reset(void)
{
    D1.sr = (u16)(D1_RQM | D1_DRC);
    D1.dr = 0x0080u;
    D1.state = 0;
    D1.pos = 0;
}

/* a byte to or from the data register: the port's steps */
static void __attribute__((noinline)) d1_port_step(int rd, u8 *data)
{
    if (!(D1.sr & D1_RQM))
        return;                             /* (stopped by command 1Ah, 2Ah or 3Ah) */
    if (rd)
        *data = (D1.sr & D1_DRS) ? (u8)(D1.dr >> 8) : (u8)D1.dr;
    else if (D1.sr & D1_DRS)
        D1.dr = (u16)((D1.dr & 0x00FFu) | ((u16)*data << 8));
    else
        D1.dr = (u16)((D1.dr & 0xFF00u) | *data);

    u32 n_out = d1_words[D1.cmd & 63u] & 15u;
    if (n_out == 15u)
        n_out = 1024u;
    switch (D1.state) {
    case 0:                                 /* a command byte */
        D1.cmd = (u8)D1.dr;
        if (!(D1.cmd & 0xC0u)) {
            if (d1_words[D1.cmd] == 0u) {
                D1.sr &= (u16)~D1_RQM;
            } else {
                D1.pos = 0;
                D1.state = 1;
                D1.sr &= (u16)~D1_DRC;
            }
        }
        break;
    case 1:                                 /* its parameters, low byte first */
        D1.sr ^= D1_DRS;
        if (!(D1.sr & D1_DRS)) {
            D1.in[D1.pos++ & 7u] = (s16)D1.dr;
            if (D1.pos >= (u32)(d1_words[D1.cmd] >> 4)) {
                d1_exec();
                D1.pos = 0;
                D1.dr = (u16)D1.out[0];
                D1.state = 2;
                if (n_out == 0u) {
                    D1.dr = 0x0080u;
                    D1.state = 0;
                    D1.sr |= D1_DRC;
                }
            }
        }
        break;
    case 2:                                 /* its results */
        D1.sr ^= D1_DRS;
        if (!(D1.sr & D1_DRS)) {
            D1.pos++;
            if (D1.pos >= n_out) {
                if (D1.cmd == 0x0Au && D1.dr != 0x8000u) {
                    D1.in[0]++;             /* the raster command goes on with the next line until 8000h */
                    d1_exec();              /* is written instead of the last result being read */
                    D1.pos = 0;
                    D1.dr = (u16)D1.out[0];
                } else {
                    D1.dr = 0x0080u;
                    D1.state = 0;
                    D1.sr |= D1_DRC;
                }
            } else {
                D1.dr = (u16)(n_out == 1024u ? 0 : D1.out[D1.pos & 3u]);
            }
        }
        break;
    }
}

/* is addr one of the chip's registers?  0 no, 1 data, 2 status */
static int d1_port(u32 addr)
{
    u32 bank = (addr >> 16) & 0x7Fu, off = addr & 0xFFFFu;
    if (D1.map == 1u)
        return (bank < 0x20u && off >= 0x6000u && off < 0x8000u) ? (off < 0x7000u ? 1 : 2) : 0;
    if (D1.map == 2u)
        return (bank >= 0x20u && bank < 0x40u && off >= 0x8000u) ? (off < 0xC000u ? 1 : 2) : 0;
    if (D1.map == 3u)
        return (bank >= 0x60u && bank < 0x70u && off < 0x8000u) ? (off < 0x4000u ? 1 : 2) : 0;
    return 0;
}

static int addr_is_sram(u32 addr)
{
    if (!S.sram_size)
        return 0;
    u8 bank = (u8)(addr >> 16);
    u16 off = (u16)addr;
    if (S.mapper == MAP_LOROM) {
        if ((bank >= 0x70u && bank <= 0x7Du) || (bank >= 0xF0u)) {
            if (off < 0x8000u || S.rom_size <= 0x200000u)
                return 1;
        }
    } else {
        if (((bank >= 0x20u && bank <= 0x3Fu) || (bank >= 0xA0u && bank <= 0xBFu)) &&
            off >= 0x6000u && off < 0x8000u)
            return 1;
    }
    return 0;
}

static void build_page_tables(void)
{
    for (u32 page = 0; page < 2048u; page++) {
        u32 addr = page << 13;
        u8 bank = (u8)(addr >> 16);
        u16 off = (u16)addr;
        M->page_r[page] = 0;
        M->page_w[page] = 0;

        if (bank == 0x7Eu || bank == 0x7Fu) {
            u8 *w = M->wram + (addr & 0x1FFFFu);
            M->page_r[page] = w;
            M->page_w[page] = w;
            continue;
        }
        if ((bank & 0x7Fu) < 0x40u && off < 0x2000u) {
            M->page_r[page] = M->wram;
            M->page_w[page] = M->wram;
            continue;
        }
        if (addr_is_sram(addr))
            continue;                       /* handled in slow path so sram_mask & sram_dirty apply */
        if (D1.map && d1_port(addr))
            continue;                       /* the DSP-1's registers (in ROM's place in LoROM cartridges) */
        if ((bank & 0x7Fu) < 0x40u && off < 0x8000u)
            continue;                       /* I/O ($2000..$7FFF) */

        u32 rom_off;
        if (S.mapper == MAP_LOROM) {
            rom_off = ((u32)(bank & 0x7Fu) << 15) | (off & 0x7FFFu);
        } else if (S.mapper == MAP_EXHIROM && bank < 0x80u) {
            rom_off = 0x400000u + (((u32)(bank & 0x3Fu) << 16) | off);
        } else {
            rom_off = ((u32)(bank & 0x3Fu) << 16) | off;
        }
        rom_off = mirror_rom_off(rom_off, S.rom_size);
        if (rom_off + 0x2000u <= S.rom_size)
            M->page_r[page] = S.rom + rom_off;
    }
}

static inline u8 mem_rd8(u32 addr)
{
    addr &= 0xFFFFFFu;
    const u8 *p = M->page_r[addr >> 13];
    if (p)
        return (S.mdr = p[addr & 0x1FFFu]);
    if (addr_is_sram(addr))
        return (S.mdr = M->sram[addr & S.sram_mask]);
    if (D1.map) {
        int reg = d1_port(addr);
        if (reg == 1) {
            u8 v = 0x80u;
            d1_port_step(1, &v);
            return (S.mdr = v);
        }
        if (reg == 2)
            return (S.mdr = (u8)(D1.sr >> 8));
    }
    u8 bank = (u8)(addr >> 16);
    u16 off = (u16)addr;
    if ((bank & 0x7Fu) < 0x40u && off < 0x8000u)
        return (S.mdr = scpu_io_rd(off));
    u32 rom_off = (S.mapper == MAP_LOROM)
                  ? (((u32)(bank & 0x7Fu) << 15) | (off & 0x7FFFu))
                  : (((u32)(bank & 0x3Fu) << 16) | off);
    return (S.mdr = S.rom[mirror_rom_off(rom_off, S.rom_size)]);
}

static inline void mem_wr8(u32 addr, u8 v)
{
    S.mdr = v;
    addr &= 0xFFFFFFu;
    u8 *p = M->page_w[addr >> 13];
    if (p) {
        p[addr & 0x1FFFu] = v;
        return;
    }
    if (addr_is_sram(addr)) {
        u32 sa = addr & S.sram_mask;
        if (M->sram[sa] != v) {
            M->sram[sa] = v;
            S.sram_dirty = 1;
        }
        return;
    }
    if (D1.map) {
        int reg = d1_port(addr);
        if (reg) {
            if (reg == 1)
                d1_port_step(0, &v);
            return;
        }
    }
    u8 bank = (u8)(addr >> 16);
    u16 off = (u16)addr;
    if ((bank & 0x7Fu) < 0x40u && off < 0x8000u)
        scpu_io_wr(off, v);
}

/* =====================================================================
 * WDC 65C816 CPU Core (Emulation + Native 8/16-bit M & X)
 * ===================================================================== */
static inline u16 cpu_rd16(u32 a)
{
    u8 lo = mem_rd8(a);
    u8 hi = mem_rd8((a + 1u) & 0xFFFFFFu);
    return (u16)(lo | ((u16)hi << 8));
}

static inline u16 cpu_rd16_bank(u8 bank, u16 off)
{
    u8 lo = mem_rd8(((u32)bank << 16) | off);
    u8 hi = mem_rd8(((u32)bank << 16) | (u16)(off + 1u));
    return (u16)(lo | ((u16)hi << 8));
}

static inline u32 cpu_rd24_bank0(u16 off)
{
    u8 b0 = mem_rd8(off);
    u8 b1 = mem_rd8((u16)(off + 1u));
    u8 b2 = mem_rd8((u16)(off + 2u));
    return (u32)b0 | ((u32)b1 << 8) | ((u32)b2 << 16);
}

static inline u8 c_fetch8(void)
{
    u8 v = mem_rd8(((u32)S.pbr << 16) | S.pc);
    S.pc++;
    return v;
}

static inline u16 c_fetch16(void)
{
    u8 lo = c_fetch8();
    u8 hi = c_fetch8();
    return (u16)(lo | ((u16)hi << 8));
}

static inline void fix_mx(void)
{
    if (S.e) {
        S.p |= (u8)(FM | FX);
        S.s = (u16)(0x0100u | (S.s & 0xFFu));
    }
    if (S.p & FX) {
        S.x &= 0x00FFu;
        S.y &= 0x00FFu;
    }
}

/* Stack helpers: legacy=1 wraps within $0100..$01FF in E=1; legacy=0 wraps S only at end */
static inline void push8_e(u8 v, int legacy)
{
    mem_wr8(S.s, v);
    if (S.e && legacy) S.s = (u16)(0x0100u | ((S.s - 1u) & 0xFFu));
    else               S.s--;
}

static inline u8 pop8_e(int legacy)
{
    if (S.e && legacy) S.s = (u16)(0x0100u | ((S.s + 1u) & 0xFFu));
    else               S.s++;
    return mem_rd8(S.s);
}

static inline void push16_e(u16 v, int legacy)
{
    push8_e((u8)(v >> 8), legacy);
    push8_e((u8)v, legacy);
    if (S.e && !legacy)
        S.s = (u16)(0x0100u | (S.s & 0xFFu));
}

static inline u16 pop16_e(int legacy)
{
    u8 lo = pop8_e(legacy);
    u8 hi = pop8_e(legacy);
    if (S.e && !legacy)
        S.s = (u16)(0x0100u | (S.s & 0xFFu));
    return (u16)(lo | ((u16)hi << 8));
}

static inline void set_nz8(u8 v)
{
    S.p = (u8)((S.p & ~(FN | FZ)) | (v & FN) | (v == 0 ? FZ : 0));
}

static inline void set_nz16(u16 v)
{
    S.p = (u8)((S.p & ~(FN | FZ)) | ((v >> 8) & FN) | (v == 0 ? FZ : 0));
}

/* Effective address helpers (24-bit) */
static inline u32 ea_dp(void)
{
    u8 o = c_fetch8();
    return (u16)(S.d + o);
}

static inline u32 ea_dp_idx(u16 idx)
{
    u8 o = c_fetch8();
    if (S.e && (S.d & 0xFFu) == 0)
        return (u16)((S.d & 0xFF00u) | ((o + idx) & 0xFFu));
    return (u16)(S.d + o + idx);
}

static inline u32 ea_abs(void)
{
    return ((u32)S.dbr << 16) | c_fetch16();
}

static inline u32 ea_abs_idx(u16 idx)
{
    return (((u32)S.dbr << 16) + c_fetch16() + idx) & 0xFFFFFFu;
}

static inline u32 ea_long(void)
{
    u16 lo = c_fetch16();
    u8 b = c_fetch8();
    return ((u32)b << 16) | lo;
}

static inline u32 ea_long_x(void)
{
    return (ea_long() + S.x) & 0xFFFFFFu;
}

static inline u32 ea_dp_ind(void)
{
    u8 o = c_fetch8();
    u16 a0 = (u16)(S.d + o);
    u16 a1 = (S.e && (S.d & 0xFFu) == 0) ? (u16)((S.d & 0xFF00u) | ((o + 1u) & 0xFFu)) : (u16)(a0 + 1u);
    u16 ptr = (u16)(mem_rd8(a0) | ((u16)mem_rd8(a1) << 8));
    return ((u32)S.dbr << 16) | ptr;
}

static inline u32 ea_dp_indx(void)
{
    u8 o = c_fetch8();
    u16 a0, a1;
    if (S.e && (S.d & 0xFFu) == 0) {
        u8 low = (u8)(o + S.x);
        a0 = (u16)((S.d & 0xFF00u) | low);
        a1 = (u16)((S.d & 0xFF00u) | (u8)(low + 1u));
    } else {
        a0 = (u16)(S.d + o + S.x);
        a1 = (u16)(a0 + 1u);
    }
    u16 ptr = (u16)(mem_rd8(a0) | ((u16)mem_rd8(a1) << 8));
    return ((u32)S.dbr << 16) | ptr;
}

static inline u32 ea_dp_indy(void)
{
    u8 o = c_fetch8();
    u16 a0 = (u16)(S.d + o);
    u16 a1 = (S.e && (S.d & 0xFFu) == 0) ? (u16)((S.d & 0xFF00u) | ((o + 1u) & 0xFFu)) : (u16)(a0 + 1u);
    u16 ptr = (u16)(mem_rd8(a0) | ((u16)mem_rd8(a1) << 8));
    return (((u32)S.dbr << 16) + ptr + S.y) & 0xFFFFFFu;
}

static inline u32 ea_dp_long(void)
{
    u16 a0 = (u16)(S.d + c_fetch8());
    return cpu_rd24_bank0(a0);
}

static inline u32 ea_dp_long_y(void)
{
    return (ea_dp_long() + S.y) & 0xFFFFFFu;
}

static inline u32 ea_sr(void)
{
    return (u16)(S.s + c_fetch8());
}

static inline u32 ea_sr_indy(void)
{
    u16 a0 = (u16)(S.s + c_fetch8());
    u16 ptr = cpu_rd16_bank(0, a0);
    return (((u32)S.dbr << 16) + ptr + S.y) & 0xFFFFFFu;
}

/* 8/16-bit binary + BCD ADC & SBC */
static void do_adc8(u8 b)
{
    u8 a = (u8)S.c;
    u32 cin = S.p & FC;
    u32 r;
    if (!(S.p & FD)) {
        r = (u32)a + b + cin;
        S.p = (u8)((S.p & ~(FC | FV)) | (r > 0xFFu ? FC : 0) |
                   (((~(a ^ b) & (a ^ r)) & 0x80u) ? FV : 0));
    } else {
        u32 lo = (a & 0x0Fu) + (b & 0x0Fu) + cin;
        if (lo > 9u) lo = ((lo + 6u) & 0x0Fu) + 0x10u;
        u32 hi = (a & 0xF0u) + (b & 0xF0u) + lo;
        S.p = (u8)((S.p & ~(FC | FV)) | (((~(a ^ b) & (a ^ hi)) & 0x80u) ? FV : 0));
        if (hi > 0x9Fu) hi += 0x60u;
        if (hi > 0xFFu) S.p |= FC;
        r = hi & 0xFFu;
    }
    S.c = (u16)((S.c & 0xFF00u) | (u8)r);
    set_nz8((u8)r);
}

static void do_adc16(u16 b)
{
    u16 a = S.c;
    u32 cin = S.p & FC;
    u32 r;
    if (!(S.p & FD)) {
        r = (u32)a + b + cin;
        S.p = (u8)((S.p & ~(FC | FV)) | (r > 0xFFFFu ? FC : 0) |
                   (((~(a ^ b) & (a ^ r)) & 0x8000u) ? FV : 0));
    } else {
        u32 n0 = (a & 0x000Fu) + (b & 0x000Fu) + cin;
        if (n0 > 9u) n0 = ((n0 + 6u) & 0x000Fu) + 0x0010u;
        u32 n1 = (a & 0x00F0u) + (b & 0x00F0u) + n0;
        if (n1 > 0x9Fu) n1 = ((n1 + 0x60u) & 0x00FFu) + 0x0100u;
        u32 n2 = (a & 0x0F00u) + (b & 0x0F00u) + n1;
        if (n2 > 0x9FFu) n2 = ((n2 + 0x600u) & 0x0FFFu) + 0x1000u;
        u32 n3 = (a & 0xF000u) + (b & 0xF000u) + n2;
        S.p = (u8)((S.p & ~(FC | FV)) | (((~(a ^ b) & (a ^ n3)) & 0x8000u) ? FV : 0));
        if (n3 > 0x9FFFu) n3 += 0x6000u;
        if (n3 > 0xFFFFu) S.p |= FC;
        r = n3 & 0xFFFFu;
    }
    S.c = (u16)r;
    set_nz16((u16)r);
}

static void do_sbc8(u8 b)
{
    u8 a = (u8)S.c;
    u8 bi = (u8)(b ^ 0xFFu);
    u32 cin = S.p & FC;
    u32 bin = (u32)a + bi + cin;
    S.p = (u8)((S.p & ~(FC | FV)) | (bin > 0xFFu ? FC : 0) |
               (((~(a ^ bi) & (a ^ bin)) & 0x80u) ? FV : 0));
    u32 r = bin;
    if (S.p & FD) {
        s32 lo = (s32)(a & 0x0Fu) + (s32)(bi & 0x0Fu) + (s32)cin;
        if (lo <= 0x0F) lo = ((lo - 6) & 0x0F);
        else            lo = ((lo - 0x10) & 0x0F) + 0x10;
        s32 hi = (s32)(a & 0xF0u) + (s32)(bi & 0xF0u) + lo;
        if (hi <= 0xFF) hi -= 0x60;
        r = (u32)hi & 0xFFu;
    }
    S.c = (u16)((S.c & 0xFF00u) | (u8)r);
    set_nz8((u8)r);
}

static void do_sbc16(u16 b)
{
    u16 a = S.c;
    u16 bi = (u16)(b ^ 0xFFFFu);
    u32 cin = S.p & FC;
    u32 bin = (u32)a + bi + cin;
    S.p = (u8)((S.p & ~(FC | FV)) | (bin > 0xFFFFu ? FC : 0) |
               (((~(a ^ bi) & (a ^ bin)) & 0x8000u) ? FV : 0));
    u32 r = bin;
    if (S.p & FD) {
        s32 n0 = (s32)(a & 0x000Fu) + (s32)(bi & 0x000Fu) + (s32)cin;
        if (n0 <= 0x0F) n0 = (n0 - 6) & 0x0F;
        else            n0 = ((n0 - 0x10) & 0x0F) + 0x10;
        s32 n1 = (s32)(a & 0x00F0u) + (s32)(bi & 0x00F0u) + n0;
        if (n1 <= 0xFF) n1 = (n1 - 0x60) & 0xFF;
        else            n1 = ((n1 - 0x100) & 0xFF) + 0x100;
        s32 n2 = (s32)(a & 0x0F00u) + (s32)(bi & 0x0F00u) + n1;
        if (n2 <= 0xFFF) n2 = (n2 - 0x600) & 0xFFF;
        else             n2 = ((n2 - 0x1000) & 0xFFF) + 0x1000;
        s32 n3 = (s32)(a & 0xF000u) + (s32)(bi & 0xF000u) + n2;
        if (n3 <= 0xFFFF) n3 -= 0x6000;
        r = (u32)n3 & 0xFFFFu;
    }
    S.c = (u16)r;
    set_nz16((u16)r);
}

static inline void do_cmp8(u8 a, u8 b)
{
    S.p = (u8)((S.p & ~FC) | (a >= b ? FC : 0));
    set_nz8((u8)(a - b));
}

static inline void do_cmp16(u16 a, u16 b)
{
    S.p = (u8)((S.p & ~FC) | (a >= b ? FC : 0));
    set_nz16((u16)(a - b));
}

static void cpu_interrupt(u16 vec_native, u16 vec_emu, int is_brk, int legacy_wrap)
{
    S.waiting = 0;
    if (!S.e) {
        push8_e(S.pbr, 0);
        push16_e(S.pc, 0);
        push8_e(S.p, 0);
        S.p = (u8)((S.p | FI) & ~FD);
        S.pbr = 0;
        S.pc = cpu_rd16_bank(0, vec_native);
    } else {
        push16_e(S.pc, legacy_wrap);
        push8_e((u8)(is_brk ? (S.p | 0x10u) : (S.p & ~0x10u)), legacy_wrap);
        if (!legacy_wrap)
            S.s = (u16)(0x0100u | (S.s & 0xFFu));
        S.p = (u8)((S.p | FI) & ~FD);
        S.pbr = 0;
        S.pc = cpu_rd16_bank(0, vec_emu);
    }
    S.master_cyc += 48;
}

#define M8  ((S.p & FM) != 0)
#define X8  ((S.p & FX) != 0)
#define RD_M(ea)     (M8 ? (u16)mem_rd8(ea) : cpu_rd16(ea))
#define RD_IMM_M()   (M8 ? (u16)c_fetch8() : c_fetch16())
#define RD_IMM_X()   (X8 ? (u16)c_fetch8() : c_fetch16())

static inline void wr_m(u32 ea, u16 v)
{
    if (M8) {
        mem_wr8(ea, (u8)v);
    } else {
        mem_wr8(ea, (u8)v);
        mem_wr8((ea + 1u) & 0xFFFFFFu, (u8)(v >> 8));
    }
}

static inline void wr_x(u32 ea, u16 v)
{
    if (X8) {
        mem_wr8(ea, (u8)v);
    } else {
        mem_wr8(ea, (u8)v);
        mem_wr8((ea + 1u) & 0xFFFFFFu, (u8)(v >> 8));
    }
}

static inline void op_ora(u16 v) { if (M8) { u8 r = (u8)(S.c | v); S.c = (u16)((S.c & 0xFF00u) | r); set_nz8(r); } else { S.c |= v; set_nz16(S.c); } }
static inline void op_and(u16 v) { if (M8) { u8 r = (u8)(S.c & v); S.c = (u16)((S.c & 0xFF00u) | r); set_nz8(r); } else { S.c &= v; set_nz16(S.c); } }
static inline void op_eor(u16 v) { if (M8) { u8 r = (u8)(S.c ^ v); S.c = (u16)((S.c & 0xFF00u) | r); set_nz8(r); } else { S.c ^= v; set_nz16(S.c); } }
static inline void op_lda(u16 v) { if (M8) { S.c = (u16)((S.c & 0xFF00u) | (u8)v); set_nz8((u8)v); } else { S.c = v; set_nz16(v); } }
static inline void op_adc(u16 v) { if (M8) do_adc8((u8)v); else do_adc16(v); }
static inline void op_sbc(u16 v) { if (M8) do_sbc8((u8)v); else do_sbc16(v); }
static inline void op_cmp(u16 v) { if (M8) do_cmp8((u8)S.c, (u8)v); else do_cmp16(S.c, v); }
static inline void op_cpx(u16 v) { if (X8) do_cmp8((u8)S.x, (u8)v); else do_cmp16(S.x, v); }
static inline void op_cpy(u16 v) { if (X8) do_cmp8((u8)S.y, (u8)v); else do_cmp16(S.y, v); }
static inline void op_ldx(u16 v) { if (X8) { S.x = (u8)v; set_nz8((u8)v); } else { S.x = v; set_nz16(v); } }
static inline void op_ldy(u16 v) { if (X8) { S.y = (u8)v; set_nz8((u8)v); } else { S.y = v; set_nz16(v); } }

static inline void op_bit(u16 v)
{
    if (M8) {
        S.p = (u8)((S.p & ~(FN | FV | FZ)) | (v & (FN | FV)) | (((S.c & v) & 0xFFu) == 0 ? FZ : 0));
    } else {
        S.p = (u8)((S.p & ~(FN | FV | FZ)) | ((v >> 8) & (FN | FV)) | ((S.c & v) == 0 ? FZ : 0));
    }
}

static inline void rmw_asl(u32 ea) { if (M8) { u8 v = mem_rd8(ea); S.p = (u8)((S.p & ~FC) | (v >> 7)); v <<= 1; mem_wr8(ea, v); set_nz8(v); } else { u16 v = cpu_rd16(ea); S.p = (u8)((S.p & ~FC) | (v >> 15)); v <<= 1; wr_m(ea, v); set_nz16(v); } }
static inline void rmw_lsr(u32 ea) { if (M8) { u8 v = mem_rd8(ea); S.p = (u8)((S.p & ~FC) | (v & 1u)); v >>= 1; mem_wr8(ea, v); set_nz8(v); } else { u16 v = cpu_rd16(ea); S.p = (u8)((S.p & ~FC) | (v & 1u)); v >>= 1; wr_m(ea, v); set_nz16(v); } }
static inline void rmw_rol(u32 ea) { u8 c = S.p & 1u; if (M8) { u8 v = mem_rd8(ea); S.p = (u8)((S.p & ~FC) | (v >> 7)); v = (u8)((v << 1) | c); mem_wr8(ea, v); set_nz8(v); } else { u16 v = cpu_rd16(ea); S.p = (u8)((S.p & ~FC) | (v >> 15)); v = (u16)((v << 1) | c); wr_m(ea, v); set_nz16(v); } }
static inline void rmw_ror(u32 ea) { u16 c = S.p & 1u; if (M8) { u8 v = mem_rd8(ea); S.p = (u8)((S.p & ~FC) | (v & 1u)); v = (u8)((v >> 1) | (c << 7)); mem_wr8(ea, v); set_nz8(v); } else { u16 v = cpu_rd16(ea); S.p = (u8)((S.p & ~FC) | (v & 1u)); v = (u16)((v >> 1) | (c << 15)); wr_m(ea, v); set_nz16(v); } }
static inline void rmw_inc(u32 ea) { if (M8) { u8 v = (u8)(mem_rd8(ea) + 1u); mem_wr8(ea, v); set_nz8(v); } else { u16 v = (u16)(cpu_rd16(ea) + 1u); wr_m(ea, v); set_nz16(v); } }
static inline void rmw_dec(u32 ea) { if (M8) { u8 v = (u8)(mem_rd8(ea) - 1u); mem_wr8(ea, v); set_nz8(v); } else { u16 v = (u16)(cpu_rd16(ea) - 1u); wr_m(ea, v); set_nz16(v); } }
static inline void rmw_tsb(u32 ea) { if (M8) { u8 v = mem_rd8(ea); S.p = (u8)((S.p & ~FZ) | (((v & S.c) & 0xFFu) == 0 ? FZ : 0)); mem_wr8(ea, (u8)(v | S.c)); } else { u16 v = cpu_rd16(ea); S.p = (u8)((S.p & ~FZ) | ((v & S.c) == 0 ? FZ : 0)); wr_m(ea, v | S.c); } }
static inline void rmw_trb(u32 ea) { if (M8) { u8 v = mem_rd8(ea); S.p = (u8)((S.p & ~FZ) | (((v & S.c) & 0xFFu) == 0 ? FZ : 0)); mem_wr8(ea, (u8)(v & ~S.c)); } else { u16 v = cpu_rd16(ea); S.p = (u8)((S.p & ~FZ) | ((v & S.c) == 0 ? FZ : 0)); wr_m(ea, (u16)(v & ~S.c)); } }

static inline void do_branch(int cond, s32 clk, u32 br_cyc)
{
    s8 rel = (s8)c_fetch8();
    if (!cond)
        return;
    S.pc = (u16)(S.pc + rel);
    S.master_cyc += 6;
    if (rel >= -6 && rel <= -2 && !S.nmi_pending && !(S.irq_line && !(S.p & FI))) {
        s32 cur_after = S.master_cyc + (s32)br_cyc * clk;
        if (cur_after < S.line_end_mc) {
            s32 loop_mc = 0;
            u32 pc24 = ((u32)S.pbr << 16) | S.pc;
            const u8 *cp = M->page_r[pc24 >> 13];
            if (rel == -2) {
                loop_mc = 6 + (s32)br_cyc * clk;
            } else if (cp && (S.pc & 0x1FFFu) <= 0x1FF8u) {
                const u8 *ip = cp + (S.pc & 0x1FFFu);
                u8 op0 = ip[0];
                if (rel == -4 && (op0 == 0xA5u || op0 == 0x24u || op0 == 0xC5u ||
                                  op0 == 0xA6u || op0 == 0xA4u || op0 == 0xE4u || op0 == 0xC4u)) {
                    u16 dp_a = (u16)(S.d + ip[1]);
                    if (dp_a < 0x1FFFu) {
                        int is16 = (op0 == 0xA5u || op0 == 0x24u || op0 == 0xC5u) ? !M8 : !X8;
                        loop_mc = (3 + is16) * clk + 6 + (s32)br_cyc * clk;
                    }
                } else if (rel == -5 && (op0 == 0x2Cu || op0 == 0xADu || op0 == 0xCDu ||
                                         op0 == 0xAEu || op0 == 0xACu || op0 == 0xECu || op0 == 0xCCu)) {
                    u16 abs_a = (u16)(ip[1] | ((u16)ip[2] << 8));
                    if (op0 == 0x2Cu && M8 && (S.dbr & 0x7Fu) < 0x40u && abs_a == 0x4210u && S.rdnmi == 0) {
                        loop_mc = 4 * clk + 6 + (s32)br_cyc * clk;
                    } else if (((S.dbr & 0x7Fu) < 0x40u && abs_a < 0x1FFFu) || S.dbr == 0x7Eu || S.dbr == 0x7Fu) {
                        int is16 = (op0 == 0x2Cu || op0 == 0xADu || op0 == 0xCDu) ? !M8 : !X8;
                        loop_mc = (4 + is16) * clk + 6 + (s32)br_cyc * clk;
                    }
                } else if (rel == -6 && (op0 == 0xAFu || op0 == 0xCFu) && (ip[3] == 0x7Eu || ip[3] == 0x7Fu)) {
                    loop_mc = (5 + !M8) * clk + 6 + (s32)br_cyc * clk;
                }
            }
            if (loop_mc > 0) {
                s32 rem = S.line_end_mc - cur_after;
                S.master_cyc += ((rem + loop_mc - 1) / loop_mc) * loop_mc;
            }
        }
    }
}

static void cpu_step(void)
{
    if (S.nmi_pending) {
        S.nmi_pending = 0;
        cpu_interrupt(0xFFEAu, 0xFFFAu, 0, 1);
        return;
    }
    if (S.irq_line) {
        S.waiting = 0;
        if (!(S.p & FI)) {
            cpu_interrupt(0xFFEEu, 0xFFFEu, 0, 1);
            return;
        }
    }
    if (S.waiting || S.stopped) {
        S.master_cyc = S.line_end_mc;
        return;
    }

    s32 clk = (S.memsel && (S.pbr & 0x80u)) ? 6 : 8;
    u8 op = c_fetch8();
    u32 cyc = 2;

    switch (op) {
    /* Interrupts / Misc Control */
    case 0x00: (void)c_fetch8(); cpu_interrupt(0xFFE6u, 0xFFFEu, 1, 1); return;     /* BRK */
    case 0x02: (void)c_fetch8(); cpu_interrupt(0xFFE4u, 0xFFF4u, 0, 0); return;     /* COP */
    case 0x40:                          /* RTI */
        if (S.e) {
            S.p = (u8)((pop8_e(1) & ~0x10u) | FM | FX);
            S.pc = pop16_e(1);
        } else {
            S.p = pop8_e(0);
            S.pc = pop16_e(0);
            S.pbr = pop8_e(0);
            fix_mx();
        }
        cyc = 7; break;
    case 0x60: S.pc = (u16)(pop16_e(1) + 1u); cyc = 6; break;                       /* RTS */
    case 0x6B: S.pc = (u16)(pop16_e(0) + 1u); S.pbr = pop8_e(0); if (S.e) S.s = (u16)(0x0100u | (S.s & 0xFFu)); cyc = 6; break; /* RTL */
    case 0x42: (void)c_fetch8(); cyc = 2; break;                                    /* WDM */
    case 0xEA: cyc = 2; break;                                                      /* NOP */
    case 0xCB: S.waiting = 1; cyc = 3; break;                                       /* WAI */
    case 0xDB: S.stopped = 1; cyc = 3; break;                                       /* STP */

    /* Flag & Mode Instructions */
    case 0x18: S.p &= (u8)~FC; break;
    case 0x38: S.p |= FC; break;
    case 0x58: S.p &= (u8)~FI; break;
    case 0x78: S.p |= FI; break;
    case 0xB8: S.p &= (u8)~FV; break;
    case 0xD8: S.p &= (u8)~FD; break;
    case 0xF8: S.p |= FD; break;
    case 0xC2: S.p &= (u8)~c_fetch8(); fix_mx(); cyc = 3; break;                    /* REP */
    case 0xE2: S.p |= c_fetch8(); fix_mx(); cyc = 3; break;                         /* SEP */
    case 0xFB: {                                                                    /* XCE */
        u8 old_c = S.p & FC;
        S.p = (u8)((S.p & ~FC) | (S.e ? FC : 0));
        S.e = old_c;
        fix_mx();
        break;
    }
    case 0xEB: {                                                                    /* XBA */
        S.c = (u16)((S.c << 8) | (S.c >> 8));
        set_nz8((u8)S.c);
        cyc = 3; break;
    }

    /* Branches */
    case 0x10: do_branch(!(S.p & FN), clk, 2); break;
    case 0x30: do_branch((S.p & FN) != 0, clk, 2); break;
    case 0x50: do_branch(!(S.p & FV), clk, 2); break;
    case 0x70: do_branch((S.p & FV) != 0, clk, 2); break;
    case 0x90: do_branch(!(S.p & FC), clk, 2); break;
    case 0xB0: do_branch((S.p & FC) != 0, clk, 2); break;
    case 0xD0: do_branch(!(S.p & FZ), clk, 2); break;
    case 0xF0: do_branch((S.p & FZ) != 0, clk, 2); break;
    case 0x80: cyc = 3; do_branch(1, clk, 3); break;
    case 0x82: { s16 r = (s16)c_fetch16(); S.pc = (u16)(S.pc + r); cyc = 4; break; } /* BRL */

    /* Jumps & Calls */
    case 0x4C: {                        /* JMP abs */
        u16 dst = c_fetch16();
        if (dst == (u16)(S.pc - 3u) && !S.nmi_pending && !(S.irq_line && !(S.p & FI)) && S.master_cyc < S.line_end_mc)
            S.master_cyc = S.line_end_mc;
        S.pc = dst;
        cyc = 3; break;
    }
    case 0x5C: { u16 dst = c_fetch16(); S.pbr = c_fetch8(); S.pc = dst; cyc = 4; break; }               /* JML */
    case 0x6C: { u16 a = c_fetch16(); S.pc = cpu_rd16_bank(0, a); cyc = 5; break; }                     /* JMP (abs) */
    case 0x7C: { u16 a = (u16)(c_fetch16() + S.x); S.pc = cpu_rd16_bank(S.pbr, a); cyc = 6; break; }    /* JMP (abs,X) */
    case 0xDC: { u16 a = c_fetch16(); u32 t = cpu_rd24_bank0(a); S.pc = (u16)t; S.pbr = (u8)(t >> 16); cyc = 6; break; } /* JML [abs] */
    case 0x20: { u16 dst = c_fetch16(); push16_e((u16)(S.pc - 1u), 1); S.pc = dst; cyc = 6; break; }    /* JSR abs */
    case 0x22: {                                                                                        /* JSL long */
        u16 dst = c_fetch16();
        u8 nb = c_fetch8();
        push8_e(S.pbr, 0);
        push16_e((u16)(S.pc - 1u), 0);
        S.pbr = nb;
        S.pc = dst;
        cyc = 8; break;
    }
    case 0xFC: {                                                                                        /* JSR (abs,X) */
        u16 a = (u16)(c_fetch16() + S.x);
        push16_e((u16)(S.pc - 1u), 0);
        S.pc = cpu_rd16_bank(S.pbr, a);
        cyc = 8; break;
    }

    /* Stack Push / Pull */
    case 0x48: if (M8) { push8_e((u8)S.c, 1); cyc = 3; } else { push16_e(S.c, 1); cyc = 4; } break;     /* PHA */
    case 0xDA: if (X8) { push8_e((u8)S.x, 1); cyc = 3; } else { push16_e(S.x, 1); cyc = 4; } break;     /* PHX */
    case 0x5A: if (X8) { push8_e((u8)S.y, 1); cyc = 3; } else { push16_e(S.y, 1); cyc = 4; } break;     /* PHY */
    case 0x08: push8_e(S.p, 1); cyc = 3; break;                                                         /* PHP */
    case 0x8B: push8_e(S.dbr, 0); if (S.e) S.s = (u16)(0x0100u | (S.s & 0xFFu)); cyc = 3; break;        /* PHB */
    case 0x4B: push8_e(S.pbr, 0); if (S.e) S.s = (u16)(0x0100u | (S.s & 0xFFu)); cyc = 3; break;        /* PHK */
    case 0x0B: push16_e(S.d, 0); cyc = 4; break;                                                        /* PHD */
    case 0xF4: push16_e(c_fetch16(), 0); cyc = 5; break;                                                /* PEA */
    case 0xD4: { u16 a = (u16)(S.d + c_fetch8()); push16_e(cpu_rd16_bank(0, a), 0); cyc = 6; break; }   /* PEI */
    case 0x62: { s16 r = (s16)c_fetch16(); push16_e((u16)(S.pc + r), 0); cyc = 6; break; }              /* PER */

    case 0x68: if (M8) { u8 v = pop8_e(1); S.c = (u16)((S.c & 0xFF00u) | v); set_nz8(v); cyc = 4; } else { S.c = pop16_e(1); set_nz16(S.c); cyc = 5; } break; /* PLA */
    case 0xFA: if (X8) { S.x = pop8_e(1); set_nz8((u8)S.x); cyc = 4; } else { S.x = pop16_e(1); set_nz16(S.x); cyc = 5; } break; /* PLX */
    case 0x7A: if (X8) { S.y = pop8_e(1); set_nz8((u8)S.y); cyc = 4; } else { S.y = pop16_e(1); set_nz16(S.y); cyc = 5; } break; /* PLY */
    case 0x28: S.p = pop8_e(1); fix_mx(); cyc = 4; break;                                               /* PLP */
    case 0xAB: S.dbr = pop8_e(0); if (S.e) S.s = (u16)(0x0100u | (S.s & 0xFFu)); set_nz8(S.dbr); cyc = 4; break; /* PLB */
    case 0x2B: S.d = pop16_e(0); set_nz16(S.d); cyc = 5; break;                                         /* PLD */

    /* Register Transfers */
    case 0xAA: if (X8) { S.x = (u8)S.c; set_nz8((u8)S.x); } else { S.x = S.c; set_nz16(S.x); } break;   /* TAX */
    case 0xA8: if (X8) { S.y = (u8)S.c; set_nz8((u8)S.y); } else { S.y = S.c; set_nz16(S.y); } break;   /* TAY */
    case 0x8A: if (M8) { S.c = (u16)((S.c & 0xFF00u) | (u8)S.x); set_nz8((u8)S.x); } else { S.c = S.x; set_nz16(S.c); } break; /* TXA */
    case 0x98: if (M8) { S.c = (u16)((S.c & 0xFF00u) | (u8)S.y); set_nz8((u8)S.y); } else { S.c = S.y; set_nz16(S.c); } break; /* TYA */
    case 0xBA: if (X8) { S.x = (u8)S.s; set_nz8((u8)S.x); } else { S.x = S.s; set_nz16(S.x); } break;   /* TSX */
    case 0x9A: S.s = S.e ? (u16)(0x0100u | (S.x & 0xFFu)) : S.x; break;                                 /* TXS */
    case 0x9B: if (X8) { S.y = (u8)S.x; set_nz8((u8)S.y); } else { S.y = S.x; set_nz16(S.y); } break;   /* TXY */
    case 0xBB: if (X8) { S.x = (u8)S.y; set_nz8((u8)S.x); } else { S.x = S.y; set_nz16(S.x); } break;   /* TYX */
    case 0x5B: S.d = S.c; set_nz16(S.d); break;                                                         /* TCD */
    case 0x7B: S.c = S.d; set_nz16(S.c); break;                                                         /* TDC */
    case 0x1B: S.s = S.e ? (u16)(0x0100u | (S.c & 0xFFu)) : S.c; break;                                 /* TCS */
    case 0x3B: S.c = S.s; set_nz16(S.c); break;                                                         /* TSC */

    /* Block Moves: MVN ($54), MVP ($44) */
    case 0x54: case 0x44: {
        u8 dst_b = c_fetch8();
        u8 src_b = c_fetch8();
        S.dbr = dst_b;
        u8 v = mem_rd8(((u32)src_b << 16) | S.x);
        mem_wr8(((u32)dst_b << 16) | S.y, v);
        if (op == 0x54u) { S.x++; S.y++; }
        else             { S.x--; S.y--; }
        if (X8) { S.x &= 0xFFu; S.y &= 0xFFu; }
        S.c--;
        if (S.c != 0xFFFFu)
            S.pc = (u16)(S.pc - 3u);
        cyc = 7; break;
    }

    /* Accumulator / Index single-byte RMW */
    case 0x0A: if (M8) { u8 v = (u8)S.c; S.p = (u8)((S.p & ~FC) | (v >> 7)); v <<= 1; S.c = (u16)((S.c & 0xFF00u) | v); set_nz8(v); } else { S.p = (u8)((S.p & ~FC) | (S.c >> 15)); S.c <<= 1; set_nz16(S.c); } break;
    case 0x4A: if (M8) { u8 v = (u8)S.c; S.p = (u8)((S.p & ~FC) | (v & 1u)); v >>= 1; S.c = (u16)((S.c & 0xFF00u) | v); set_nz8(v); } else { S.p = (u8)((S.p & ~FC) | (S.c & 1u)); S.c >>= 1; set_nz16(S.c); } break;
    case 0x2A: { u16 c = S.p & 1u; if (M8) { u8 v = (u8)S.c; S.p = (u8)((S.p & ~FC) | (v >> 7)); v = (u8)((v << 1) | c); S.c = (u16)((S.c & 0xFF00u) | v); set_nz8(v); } else { S.p = (u8)((S.p & ~FC) | (S.c >> 15)); S.c = (u16)((S.c << 1) | c); set_nz16(S.c); } break; }
    case 0x6A: { u16 c = S.p & 1u; if (M8) { u8 v = (u8)S.c; S.p = (u8)((S.p & ~FC) | (v & 1u)); v = (u8)((v >> 1) | (c << 7)); S.c = (u16)((S.c & 0xFF00u) | v); set_nz8(v); } else { S.p = (u8)((S.p & ~FC) | (S.c & 1u)); S.c = (u16)((S.c >> 1) | (c << 15)); set_nz16(S.c); } break; }
    case 0x1A: if (M8) { u8 v = (u8)(S.c + 1u); S.c = (u16)((S.c & 0xFF00u) | v); set_nz8(v); } else { S.c++; set_nz16(S.c); } break;
    case 0x3A: if (M8) { u8 v = (u8)(S.c - 1u); S.c = (u16)((S.c & 0xFF00u) | v); set_nz8(v); } else { S.c--; set_nz16(S.c); } break;
    case 0xE8: if (X8) { S.x = (u8)(S.x + 1u); set_nz8((u8)S.x); } else { S.x++; set_nz16(S.x); } break;
    case 0xCA: if (X8) { S.x = (u8)(S.x - 1u); set_nz8((u8)S.x); } else { S.x--; set_nz16(S.x); } break;
    case 0xC8: if (X8) { S.y = (u8)(S.y + 1u); set_nz8((u8)S.y); } else { S.y++; set_nz16(S.y); } break;
    case 0x88: if (X8) { S.y = (u8)(S.y - 1u); set_nz8((u8)S.y); } else { S.y--; set_nz16(S.y); } break;

    /* ORA */
    case 0x09: op_ora(RD_IMM_M()); cyc = 2 + !M8; break;
    case 0x05: op_ora(RD_M(ea_dp())); cyc = 3 + !M8; break;
    case 0x15: op_ora(RD_M(ea_dp_idx(S.x))); cyc = 4 + !M8; break;
    case 0x0D: op_ora(RD_M(ea_abs())); cyc = 4 + !M8; break;
    case 0x1D: op_ora(RD_M(ea_abs_idx(S.x))); cyc = 4 + !M8; break;
    case 0x19: op_ora(RD_M(ea_abs_idx(S.y))); cyc = 4 + !M8; break;
    case 0x0F: op_ora(RD_M(ea_long())); cyc = 5 + !M8; break;
    case 0x1F: op_ora(RD_M(ea_long_x())); cyc = 5 + !M8; break;
    case 0x12: op_ora(RD_M(ea_dp_ind())); cyc = 5 + !M8; break;
    case 0x01: op_ora(RD_M(ea_dp_indx())); cyc = 6 + !M8; break;
    case 0x11: op_ora(RD_M(ea_dp_indy())); cyc = 5 + !M8; break;
    case 0x07: op_ora(RD_M(ea_dp_long())); cyc = 6 + !M8; break;
    case 0x17: op_ora(RD_M(ea_dp_long_y())); cyc = 6 + !M8; break;
    case 0x03: op_ora(RD_M(ea_sr())); cyc = 4 + !M8; break;
    case 0x13: op_ora(RD_M(ea_sr_indy())); cyc = 7 + !M8; break;

    /* AND */
    case 0x29: op_and(RD_IMM_M()); cyc = 2 + !M8; break;
    case 0x25: op_and(RD_M(ea_dp())); cyc = 3 + !M8; break;
    case 0x35: op_and(RD_M(ea_dp_idx(S.x))); cyc = 4 + !M8; break;
    case 0x2D: op_and(RD_M(ea_abs())); cyc = 4 + !M8; break;
    case 0x3D: op_and(RD_M(ea_abs_idx(S.x))); cyc = 4 + !M8; break;
    case 0x39: op_and(RD_M(ea_abs_idx(S.y))); cyc = 4 + !M8; break;
    case 0x2F: op_and(RD_M(ea_long())); cyc = 5 + !M8; break;
    case 0x3F: op_and(RD_M(ea_long_x())); cyc = 5 + !M8; break;
    case 0x32: op_and(RD_M(ea_dp_ind())); cyc = 5 + !M8; break;
    case 0x21: op_and(RD_M(ea_dp_indx())); cyc = 6 + !M8; break;
    case 0x31: op_and(RD_M(ea_dp_indy())); cyc = 5 + !M8; break;
    case 0x27: op_and(RD_M(ea_dp_long())); cyc = 6 + !M8; break;
    case 0x37: op_and(RD_M(ea_dp_long_y())); cyc = 6 + !M8; break;
    case 0x23: op_and(RD_M(ea_sr())); cyc = 4 + !M8; break;
    case 0x33: op_and(RD_M(ea_sr_indy())); cyc = 7 + !M8; break;

    /* EOR */
    case 0x49: op_eor(RD_IMM_M()); cyc = 2 + !M8; break;
    case 0x45: op_eor(RD_M(ea_dp())); cyc = 3 + !M8; break;
    case 0x55: op_eor(RD_M(ea_dp_idx(S.x))); cyc = 4 + !M8; break;
    case 0x4D: op_eor(RD_M(ea_abs())); cyc = 4 + !M8; break;
    case 0x5D: op_eor(RD_M(ea_abs_idx(S.x))); cyc = 4 + !M8; break;
    case 0x59: op_eor(RD_M(ea_abs_idx(S.y))); cyc = 4 + !M8; break;
    case 0x4F: op_eor(RD_M(ea_long())); cyc = 5 + !M8; break;
    case 0x5F: op_eor(RD_M(ea_long_x())); cyc = 5 + !M8; break;
    case 0x52: op_eor(RD_M(ea_dp_ind())); cyc = 5 + !M8; break;
    case 0x41: op_eor(RD_M(ea_dp_indx())); cyc = 6 + !M8; break;
    case 0x51: op_eor(RD_M(ea_dp_indy())); cyc = 5 + !M8; break;
    case 0x47: op_eor(RD_M(ea_dp_long())); cyc = 6 + !M8; break;
    case 0x57: op_eor(RD_M(ea_dp_long_y())); cyc = 6 + !M8; break;
    case 0x43: op_eor(RD_M(ea_sr())); cyc = 4 + !M8; break;
    case 0x53: op_eor(RD_M(ea_sr_indy())); cyc = 7 + !M8; break;

    /* ADC */
    case 0x69: op_adc(RD_IMM_M()); cyc = 2 + !M8; break;
    case 0x65: op_adc(RD_M(ea_dp())); cyc = 3 + !M8; break;
    case 0x75: op_adc(RD_M(ea_dp_idx(S.x))); cyc = 4 + !M8; break;
    case 0x6D: op_adc(RD_M(ea_abs())); cyc = 4 + !M8; break;
    case 0x7D: op_adc(RD_M(ea_abs_idx(S.x))); cyc = 4 + !M8; break;
    case 0x79: op_adc(RD_M(ea_abs_idx(S.y))); cyc = 4 + !M8; break;
    case 0x6F: op_adc(RD_M(ea_long())); cyc = 5 + !M8; break;
    case 0x7F: op_adc(RD_M(ea_long_x())); cyc = 5 + !M8; break;
    case 0x72: op_adc(RD_M(ea_dp_ind())); cyc = 5 + !M8; break;
    case 0x61: op_adc(RD_M(ea_dp_indx())); cyc = 6 + !M8; break;
    case 0x71: op_adc(RD_M(ea_dp_indy())); cyc = 5 + !M8; break;
    case 0x67: op_adc(RD_M(ea_dp_long())); cyc = 6 + !M8; break;
    case 0x77: op_adc(RD_M(ea_dp_long_y())); cyc = 6 + !M8; break;
    case 0x63: op_adc(RD_M(ea_sr())); cyc = 4 + !M8; break;
    case 0x73: op_adc(RD_M(ea_sr_indy())); cyc = 7 + !M8; break;

    /* STA */
    case 0x85: wr_m(ea_dp(), S.c); cyc = 3 + !M8; break;
    case 0x95: wr_m(ea_dp_idx(S.x), S.c); cyc = 4 + !M8; break;
    case 0x8D: wr_m(ea_abs(), S.c); cyc = 4 + !M8; break;
    case 0x9D: wr_m(ea_abs_idx(S.x), S.c); cyc = 5 + !M8; break;
    case 0x99: wr_m(ea_abs_idx(S.y), S.c); cyc = 5 + !M8; break;
    case 0x8F: wr_m(ea_long(), S.c); cyc = 5 + !M8; break;
    case 0x9F: wr_m(ea_long_x(), S.c); cyc = 5 + !M8; break;
    case 0x92: wr_m(ea_dp_ind(), S.c); cyc = 5 + !M8; break;
    case 0x81: wr_m(ea_dp_indx(), S.c); cyc = 6 + !M8; break;
    case 0x91: wr_m(ea_dp_indy(), S.c); cyc = 6 + !M8; break;
    case 0x87: wr_m(ea_dp_long(), S.c); cyc = 6 + !M8; break;
    case 0x97: wr_m(ea_dp_long_y(), S.c); cyc = 6 + !M8; break;
    case 0x83: wr_m(ea_sr(), S.c); cyc = 4 + !M8; break;
    case 0x93: wr_m(ea_sr_indy(), S.c); cyc = 7 + !M8; break;

    /* LDA */
    case 0xA9: op_lda(RD_IMM_M()); cyc = 2 + !M8; break;
    case 0xA5: op_lda(RD_M(ea_dp())); cyc = 3 + !M8; break;
    case 0xB5: op_lda(RD_M(ea_dp_idx(S.x))); cyc = 4 + !M8; break;
    case 0xAD: op_lda(RD_M(ea_abs())); cyc = 4 + !M8; break;
    case 0xBD: op_lda(RD_M(ea_abs_idx(S.x))); cyc = 4 + !M8; break;
    case 0xB9: op_lda(RD_M(ea_abs_idx(S.y))); cyc = 4 + !M8; break;
    case 0xAF: op_lda(RD_M(ea_long())); cyc = 5 + !M8; break;
    case 0xBF: op_lda(RD_M(ea_long_x())); cyc = 5 + !M8; break;
    case 0xB2: op_lda(RD_M(ea_dp_ind())); cyc = 5 + !M8; break;
    case 0xA1: op_lda(RD_M(ea_dp_indx())); cyc = 6 + !M8; break;
    case 0xB1: op_lda(RD_M(ea_dp_indy())); cyc = 5 + !M8; break;
    case 0xA7: op_lda(RD_M(ea_dp_long())); cyc = 6 + !M8; break;
    case 0xB7: op_lda(RD_M(ea_dp_long_y())); cyc = 6 + !M8; break;
    case 0xA3: op_lda(RD_M(ea_sr())); cyc = 4 + !M8; break;
    case 0xB3: op_lda(RD_M(ea_sr_indy())); cyc = 7 + !M8; break;

    /* CMP */
    case 0xC9: op_cmp(RD_IMM_M()); cyc = 2 + !M8; break;
    case 0xC5: op_cmp(RD_M(ea_dp())); cyc = 3 + !M8; break;
    case 0xD5: op_cmp(RD_M(ea_dp_idx(S.x))); cyc = 4 + !M8; break;
    case 0xCD: op_cmp(RD_M(ea_abs())); cyc = 4 + !M8; break;
    case 0xDD: op_cmp(RD_M(ea_abs_idx(S.x))); cyc = 4 + !M8; break;
    case 0xD9: op_cmp(RD_M(ea_abs_idx(S.y))); cyc = 4 + !M8; break;
    case 0xCF: op_cmp(RD_M(ea_long())); cyc = 5 + !M8; break;
    case 0xDF: op_cmp(RD_M(ea_long_x())); cyc = 5 + !M8; break;
    case 0xD2: op_cmp(RD_M(ea_dp_ind())); cyc = 5 + !M8; break;
    case 0xC1: op_cmp(RD_M(ea_dp_indx())); cyc = 6 + !M8; break;
    case 0xD1: op_cmp(RD_M(ea_dp_indy())); cyc = 5 + !M8; break;
    case 0xC7: op_cmp(RD_M(ea_dp_long())); cyc = 6 + !M8; break;
    case 0xD7: op_cmp(RD_M(ea_dp_long_y())); cyc = 6 + !M8; break;
    case 0xC3: op_cmp(RD_M(ea_sr())); cyc = 4 + !M8; break;
    case 0xD3: op_cmp(RD_M(ea_sr_indy())); cyc = 7 + !M8; break;

    /* SBC */
    case 0xE9: op_sbc(RD_IMM_M()); cyc = 2 + !M8; break;
    case 0xE5: op_sbc(RD_M(ea_dp())); cyc = 3 + !M8; break;
    case 0xF5: op_sbc(RD_M(ea_dp_idx(S.x))); cyc = 4 + !M8; break;
    case 0xED: op_sbc(RD_M(ea_abs())); cyc = 4 + !M8; break;
    case 0xFD: op_sbc(RD_M(ea_abs_idx(S.x))); cyc = 4 + !M8; break;
    case 0xF9: op_sbc(RD_M(ea_abs_idx(S.y))); cyc = 4 + !M8; break;
    case 0xEF: op_sbc(RD_M(ea_long())); cyc = 5 + !M8; break;
    case 0xFF: op_sbc(RD_M(ea_long_x())); cyc = 5 + !M8; break;
    case 0xF2: op_sbc(RD_M(ea_dp_ind())); cyc = 5 + !M8; break;
    case 0xE1: op_sbc(RD_M(ea_dp_indx())); cyc = 6 + !M8; break;
    case 0xF1: op_sbc(RD_M(ea_dp_indy())); cyc = 5 + !M8; break;
    case 0xE7: op_sbc(RD_M(ea_dp_long())); cyc = 6 + !M8; break;
    case 0xF7: op_sbc(RD_M(ea_dp_long_y())); cyc = 6 + !M8; break;
    case 0xE3: op_sbc(RD_M(ea_sr())); cyc = 4 + !M8; break;
    case 0xF3: op_sbc(RD_M(ea_sr_indy())); cyc = 7 + !M8; break;

    /* LDX / LDY / STX / STY / STZ / CPX / CPY / BIT */
    case 0xA2: op_ldx(RD_IMM_X()); cyc = 2 + !X8; break;
    case 0xA6: op_ldx(X8 ? mem_rd8(ea_dp()) : cpu_rd16(ea_dp())); cyc = 3 + !X8; break;
    case 0xB6: op_ldx(X8 ? mem_rd8(ea_dp_idx(S.y)) : cpu_rd16(ea_dp_idx(S.y))); cyc = 4 + !X8; break;
    case 0xAE: op_ldx(X8 ? mem_rd8(ea_abs()) : cpu_rd16(ea_abs())); cyc = 4 + !X8; break;
    case 0xBE: op_ldx(X8 ? mem_rd8(ea_abs_idx(S.y)) : cpu_rd16(ea_abs_idx(S.y))); cyc = 4 + !X8; break;

    case 0xA0: op_ldy(RD_IMM_X()); cyc = 2 + !X8; break;
    case 0xA4: op_ldy(X8 ? mem_rd8(ea_dp()) : cpu_rd16(ea_dp())); cyc = 3 + !X8; break;
    case 0xB4: op_ldy(X8 ? mem_rd8(ea_dp_idx(S.x)) : cpu_rd16(ea_dp_idx(S.x))); cyc = 4 + !X8; break;
    case 0xAC: op_ldy(X8 ? mem_rd8(ea_abs()) : cpu_rd16(ea_abs())); cyc = 4 + !X8; break;
    case 0xBC: op_ldy(X8 ? mem_rd8(ea_abs_idx(S.x)) : cpu_rd16(ea_abs_idx(S.x))); cyc = 4 + !X8; break;

    case 0x86: wr_x(ea_dp(), S.x); cyc = 3 + !X8; break;
    case 0x96: wr_x(ea_dp_idx(S.y), S.x); cyc = 4 + !X8; break;
    case 0x8E: wr_x(ea_abs(), S.x); cyc = 4 + !X8; break;
    case 0x84: wr_x(ea_dp(), S.y); cyc = 3 + !X8; break;
    case 0x94: wr_x(ea_dp_idx(S.x), S.y); cyc = 4 + !X8; break;
    case 0x8C: wr_x(ea_abs(), S.y); cyc = 4 + !X8; break;

    case 0x64: wr_m(ea_dp(), 0); cyc = 3 + !M8; break;
    case 0x74: wr_m(ea_dp_idx(S.x), 0); cyc = 4 + !M8; break;
    case 0x9C: wr_m(ea_abs(), 0); cyc = 4 + !M8; break;
    case 0x9E: wr_m(ea_abs_idx(S.x), 0); cyc = 5 + !M8; break;

    case 0xE0: op_cpx(RD_IMM_X()); cyc = 2 + !X8; break;
    case 0xE4: op_cpx(X8 ? mem_rd8(ea_dp()) : cpu_rd16(ea_dp())); cyc = 3 + !X8; break;
    case 0xEC: op_cpx(X8 ? mem_rd8(ea_abs()) : cpu_rd16(ea_abs())); cyc = 4 + !X8; break;
    case 0xC0: op_cpy(RD_IMM_X()); cyc = 2 + !X8; break;
    case 0xC4: op_cpy(X8 ? mem_rd8(ea_dp()) : cpu_rd16(ea_dp())); cyc = 3 + !X8; break;
    case 0xCC: op_cpy(X8 ? mem_rd8(ea_abs()) : cpu_rd16(ea_abs())); cyc = 4 + !X8; break;

    case 0x89: {                        /* BIT #imm: ONLY affects Z! */
        u16 v = RD_IMM_M();
        u16 m = M8 ? ((S.c & v) & 0xFFu) : (S.c & v);
        S.p = (u8)((S.p & ~FZ) | (m == 0 ? FZ : 0));
        cyc = 2 + !M8; break;
    }
    case 0x24: op_bit(RD_M(ea_dp())); cyc = 3 + !M8; break;
    case 0x34: op_bit(RD_M(ea_dp_idx(S.x))); cyc = 4 + !M8; break;
    case 0x2C: op_bit(RD_M(ea_abs())); cyc = 4 + !M8; break;
    case 0x3C: op_bit(RD_M(ea_abs_idx(S.x))); cyc = 4 + !M8; break;

    /* Memory RMW: ASL, LSR, ROL, ROR, INC, DEC, TSB, TRB */
    case 0x06: rmw_asl(ea_dp()); cyc = 5 + 2 * !M8; break;
    case 0x16: rmw_asl(ea_dp_idx(S.x)); cyc = 6 + 2 * !M8; break;
    case 0x0E: rmw_asl(ea_abs()); cyc = 6 + 2 * !M8; break;
    case 0x1E: rmw_asl(ea_abs_idx(S.x)); cyc = 7 + 2 * !M8; break;

    case 0x46: rmw_lsr(ea_dp()); cyc = 5 + 2 * !M8; break;
    case 0x56: rmw_lsr(ea_dp_idx(S.x)); cyc = 6 + 2 * !M8; break;
    case 0x4E: rmw_lsr(ea_abs()); cyc = 6 + 2 * !M8; break;
    case 0x5E: rmw_lsr(ea_abs_idx(S.x)); cyc = 7 + 2 * !M8; break;

    case 0x26: rmw_rol(ea_dp()); cyc = 5 + 2 * !M8; break;
    case 0x36: rmw_rol(ea_dp_idx(S.x)); cyc = 6 + 2 * !M8; break;
    case 0x2E: rmw_rol(ea_abs()); cyc = 6 + 2 * !M8; break;
    case 0x3E: rmw_rol(ea_abs_idx(S.x)); cyc = 7 + 2 * !M8; break;

    case 0x66: rmw_ror(ea_dp()); cyc = 5 + 2 * !M8; break;
    case 0x76: rmw_ror(ea_dp_idx(S.x)); cyc = 6 + 2 * !M8; break;
    case 0x6E: rmw_ror(ea_abs()); cyc = 6 + 2 * !M8; break;
    case 0x7E: rmw_ror(ea_abs_idx(S.x)); cyc = 7 + 2 * !M8; break;

    case 0xE6: rmw_inc(ea_dp()); cyc = 5 + 2 * !M8; break;
    case 0xF6: rmw_inc(ea_dp_idx(S.x)); cyc = 6 + 2 * !M8; break;
    case 0xEE: rmw_inc(ea_abs()); cyc = 6 + 2 * !M8; break;
    case 0xFE: rmw_inc(ea_abs_idx(S.x)); cyc = 7 + 2 * !M8; break;

    case 0xC6: rmw_dec(ea_dp()); cyc = 5 + 2 * !M8; break;
    case 0xD6: rmw_dec(ea_dp_idx(S.x)); cyc = 6 + 2 * !M8; break;
    case 0xCE: rmw_dec(ea_abs()); cyc = 6 + 2 * !M8; break;
    case 0xDE: rmw_dec(ea_abs_idx(S.x)); cyc = 7 + 2 * !M8; break;

    case 0x04: rmw_tsb(ea_dp()); cyc = 5 + 2 * !M8; break;
    case 0x0C: rmw_tsb(ea_abs()); cyc = 6 + 2 * !M8; break;
    case 0x14: rmw_trb(ea_dp()); cyc = 5 + 2 * !M8; break;
    case 0x1C: rmw_trb(ea_abs()); cyc = 6 + 2 * !M8; break;
    }

    S.master_cyc += (s32)cyc * clk;
}

/* =====================================================================
 * S-PPU Scanline Renderer (Modes 0..7, Cached Tiles, Sprites, Windows, Math)
 * ===================================================================== */
static inline const u32 *get_tile2(u16 tile_idx)
{
    tile_idx &= 0x0FFFu;
    if (M->vram_dirty2[tile_idx]) {
        M->vram_dirty2[tile_idx] = 0;
        const u8 *p = M->vram + ((u32)tile_idx << 4);
        u32 *dst = M->tile2_cache[tile_idx];
        for (int y = 0; y < 8; y++)
            dst[y] = M->bp_lut[p[y * 2]] | (M->bp_lut[p[y * 2 + 1]] << 1);
    }
    return M->tile2_cache[tile_idx];
}

static inline const u32 *get_tile4(u16 tile_idx)
{
    tile_idx &= 0x07FFu;
    if (M->vram_dirty4[tile_idx]) {
        M->vram_dirty4[tile_idx] = 0;
        const u8 *p = M->vram + ((u32)tile_idx << 5);
        u32 *dst = M->tile4_cache[tile_idx];
        for (int y = 0; y < 8; y++)
            dst[y] = M->bp_lut[p[y * 2]] | (M->bp_lut[p[y * 2 + 1]] << 1) |
                     (M->bp_lut[p[16 + y * 2]] << 2) | (M->bp_lut[p[16 + y * 2 + 1]] << 3);
    }
    return M->tile4_cache[tile_idx];
}

static inline const u8 *get_tile8(u16 tile_idx)
{
    tile_idx &= 0x03FFu;
    if (M->vram_dirty8[tile_idx]) {
        M->vram_dirty8[tile_idx] = 0;
        const u8 *p = M->vram + ((u32)tile_idx << 6);
        u8 *dst = M->tile8_cache[tile_idx];
        for (int y = 0; y < 8; y++) {
            u32 lo = M->bp_lut[p[y * 2]] | (M->bp_lut[p[y * 2 + 1]] << 1) |
                     (M->bp_lut[p[16 + y * 2]] << 2) | (M->bp_lut[p[16 + y * 2 + 1]] << 3);
            u32 hi = M->bp_lut[p[32 + y * 2]] | (M->bp_lut[p[32 + y * 2 + 1]] << 1) |
                     (M->bp_lut[p[48 + y * 2]] << 2) | (M->bp_lut[p[48 + y * 2 + 1]] << 3);
            for (int x = 0; x < 8; x++, lo >>= 4, hi >>= 4)
                dst[y * 8 + x] = (u8)((lo & 0x0Fu) | ((hi & 0x0Fu) << 4));
        }
    }
    return M->tile8_cache[tile_idx];
}

static inline u32 flip_nibbles32(u32 v)
{
    v = ((v >> 4) & 0x0F0F0F0Fu) | ((v & 0x0F0F0F0Fu) << 4);
    v = ((v >> 8) & 0x00FF00FFu) | ((v & 0x00FF00FFu) << 8);
    return (v >> 16) | (v << 16);
}

/* Compute window clip mask (1 = masked/disabled inside window) for layer (0..3=BG1..4, 4=OBJ, 5=COL) */
/* A layer's window mask of the line (layers 0..3: BG1..BG4, 4: OBJ, 5: the colour window): 1 where the windows
   cover the layer.  The two windows' edges cut the line into at most five runs, each of one value: returns 0
   when no pixel is covered and 1 when all are (out_mask is not written then: most lines of most games), 2 with
   out_mask filled.  (It was worked out pixel by pixel, up to three times a line: a tenth of Super Mario Kart's
   frame for windows that were empty.) */
static int build_window_mask(int layer, u8 *out_mask)
{
    u8 sel, log_op;
    if (layer < 2)      { sel = (u8)(S.w12sel >> (layer * 4)); log_op = (u8)((S.wbglog >> (layer * 2)) & 3u); }
    else if (layer < 4) { sel = (u8)(S.w34sel >> ((layer - 2) * 4)); log_op = (u8)((S.wbglog >> (layer * 2)) & 3u); }
    else if (layer == 4){ sel = (u8)(S.wobjsel & 0x0Fu); log_op = (u8)(S.wobjlog & 3u); }
    else                { sel = (u8)(S.wobjsel >> 4); log_op = (u8)((S.wobjlog >> 2) & 3u); }

    int w1_en = (sel & 0x02u) != 0, w1_inv = (sel & 0x01u) != 0;
    int w2_en = (sel & 0x08u) != 0, w2_inv = (sel & 0x04u) != 0;
    if (!w1_en && !w2_en)
        return 0;

    int wh0 = S.wh0, wh1 = S.wh1, wh2 = S.wh2, wh3 = S.wh3;
    int edge[6] = { 0, wh0, wh1 + 1, wh2, wh3 + 1, SNES_W };
    for (int i = 2; i <= 4; i++) {                  /* (the four inner edges in order) */
        int v = edge[i], j = i - 1;
        while (j >= 1 && edge[j] > v) {
            edge[j + 1] = edge[j];
            j--;
        }
        edge[j + 1] = v;
    }
    u8 val[5];
    int any = 0, all = 1;
    for (int i = 0; i < 5; i++) {
        int x = edge[i];
        if (x >= edge[i + 1]) {
            val[i] = 2u;                            /* (an empty run) */
            continue;
        }
        int m1 = 0, m2 = 0, m;
        if (w1_en) { m1 = (x >= wh0 && x <= wh1); if (w1_inv) m1 = !m1; }
        if (w2_en) { m2 = (x >= wh2 && x <= wh3); if (w2_inv) m2 = !m2; }
        if (w1_en && !w2_en)      m = m1;
        else if (!w1_en && w2_en) m = m2;
        else {
            switch (log_op) {
            case 0: m = m1 | m2; break;     /* OR */
            case 1: m = m1 & m2; break;     /* AND */
            case 2: m = m1 ^ m2; break;     /* XOR */
            default: m = !(m1 ^ m2); break; /* XNOR */
            }
        }
        val[i] = (u8)m;
        any |= m;
        all &= m;
    }
    if (!any)
        return 0;
    if (all)
        return 1;
    for (int i = 0; i < 5; i++)
        if (val[i] != 2u)
            for (int x = edge[i]; x < edge[i + 1]; x++)
                out_mask[x] = val[i];
    return 2;
}

static inline u16 fetch_bg_map_entry(u8 sc_reg, int tx, int ty)
{
    u32 base_w = (u32)(sc_reg & 0xFCu) << 8;
    u32 sx_scr = (tx >> 5) & 1;
    u32 sy_scr = (ty >> 5) & 1;
    u32 screen = 0;
    switch (sc_reg & 3u) {
    case 1: screen = sx_scr; break;
    case 2: screen = sy_scr; break;
    case 3: screen = sx_scr | (sy_scr << 1); break;
    }
    u32 waddr = (base_w + (screen << 10) + (u32)((ty & 31) << 5) + (u32)(tx & 31)) & 0x7FFFu;
    return (u16)(M->vram[waddr * 2u] | ((u16)M->vram[waddr * 2u + 1u] << 8));
}

static inline u16 direct_color_15(u8 px, u8 pal3)
{
    u16 r = (u16)(((px & 0x07u) << 2) | ((pal3 & 1u) << 1));
    u16 g = (u16)((((px >> 3) & 0x07u) << 2) | (pal3 & 2u));
    u16 b = (u16)((((px >> 6) & 0x03u) << 3) | (pal3 & 4u));
    return (u16)(r | (g << 5) | (b << 10));
}

struct line_compositor {
    u16 *main_col;                      /* the main screen's colours: main_buf, or the picture's line itself when
                                           the line has no colour maths, clipping or dimming to go through */
    int use_sub;                        /* the sub screen is looked at (colour maths with it): else not drawn */
    int need_src;                       /* main_src is looked at (colour maths somewhere on the line) */
    u16 main_buf[SNES_W], sub_col[SNES_W];
    u8 main_z[SNES_W], sub_z[SNES_W];
    u8 main_src[SNES_W];                /* bitmask: 0x01..0x08=BG1..4, 0x10=OBJ(pal4..7), 0x20=Backdrop, 0x00=OBJ(pal0..3) */
} __attribute__((aligned(4)));          /* (render_snes_line fills its arrays a 32-bit word at a time) */
typedef u32 __attribute__((may_alias)) u32_alias;

/* where on the line a colour-window rule (CGWSEL's "clip to black" or "prevent the maths": 0 never, 1 outside the
   window, 2 inside, 3 always) holds, given build_window_mask's answer for the colour window: 0 nowhere,
   1 everywhere, 2 where the mask is 0, 3 where it is 1 */
static inline int cw_region(int mode, int kind)
{
    if (mode == 0)
        return 0;
    if (mode == 3)
        return 1;
    if (mode == 1)
        return kind == 0 ? 1 : kind == 1 ? 0 : 2;
    return kind == 0 ? 0 : kind == 1 ? 1 : 3;
}

static void render_bg_layer(struct line_compositor *lc, int bg, int bpp, int line_y,
                            u8 z_lo, u8 z_hi, int opt_mode)
{
    u8 bit = (u8)(1u << bg);
    int on_main = (S.tm & bit) != 0;
    int on_sub  = (S.ts & bit) != 0 && lc->use_sub;
    if (!on_main && !on_sub)
        return;

    u8 wmask[SNES_W];
    u8 m_win_on = (on_main && (S.tmw & bit)) ? 1 : 0;
    u8 s_win_on = (on_sub  && (S.tsw & bit)) ? 1 : 0;
    if (m_win_on || s_win_on) {
        int kind = build_window_mask(bg, wmask);
        if (kind == 1) {                            /* all covered: the layer is off where its window counts */
            if (m_win_on) on_main = 0;
            if (s_win_on) on_sub = 0;
            if (!on_main && !on_sub)
                return;
        }
        if (kind != 2)
            m_win_on = s_win_on = 0;
    }

    int mos_sz = (S.mosaic & bit) ? ((S.mosaic >> 4) + 1) : 1;
    int eff_y = (mos_sz > 1) ? (line_y - (line_y % mos_sz)) : line_y;

    int mode = S.bgmode & 7u;
    int hires_m56 = (mode == 5 || mode == 6);
    int tile_w16 = hires_m56 ? 1 : ((S.bgmode & (0x10u << bg)) != 0);
    int ilace_m56 = hires_m56 && (S.setini & 1u);
    int tile_h16 = ilace_m56 ? 1 : ((S.bgmode & (0x10u << bg)) != 0);

    u16 chr_base_w = (bg < 2) ? (u16)(((bg == 0 ? (S.bg12nba & 0x0Fu) : (S.bg12nba >> 4)) << 12))
                              : (u16)(((bg == 2 ? (S.bg34nba & 0x0Fu) : (S.bg34nba >> 4)) << 12));
    u8 sc_reg = S.bg_sc[bg];
    u16 hofs = S.bg_hofs[bg];
    u16 vofs = S.bg_vofs[bg];
    u8 mode0_pal_off = (mode == 0) ? (u8)(bg * 32) : 0;
    int direct_col = (bpp == 8) && (S.cgwsel & 1u);

    /* Fast 8-pixel tile-sliver path for standard 8x8 2bpp/4bpp BGs (Modes 0, 1, 3) */
    if (!opt_mode && mos_sz == 1 && !hires_m56 && !tile_w16 && !tile_h16 && (bpp == 2 || bpp == 4)) {
        int sy = eff_y + vofs;
        int ty = sy >> 3;
        int fy = sy & 7;
        int sx = hofs;
        int x = 0;
        u16 chr_shift = (bpp == 2) ? (chr_base_w >> 3) : (chr_base_w >> 4);
        /* where the line's row of the tile map lies in VRAM, for the left and the right screen (the entry of a
           column is then one addition away: fetch_bg_map_entry's sum, split) */
        u32 map_row[2];
        {
            u32 base_w = (u32)(sc_reg & 0xFCu) << 8, sy_scr = ((u32)ty >> 5) & 1u;
            for (u32 sx_scr = 0; sx_scr < 2u; sx_scr++) {
                u32 screen = 0;
                switch (sc_reg & 3u) {
                case 1: screen = sx_scr; break;
                case 2: screen = sy_scr; break;
                case 3: screen = sx_scr | (sy_scr << 1); break;
                }
                map_row[sx_scr] = base_w + (screen << 10) + (u32)((ty & 31) << 5);
            }
        }
        const u8 *vram = M->vram;
        const u16 *cg = M->cgram;
        u8 *mz = lc->main_z, *ms = lc->main_src, *sz = lc->sub_z;
        u16 *mc = lc->main_col, *sc = lc->sub_col;
        int plain = on_main && !on_sub && !m_win_on;    /* the usual layer: the main screen alone, no window */
        while (x < SNES_W) {
            int tx0 = sx & 7;
            int n = 8 - tx0;
            if (x + n > SNES_W)
                n = SNES_W - x;
            u32 tx = (u32)(sx >> 3);
            u32 waddr = (map_row[(tx >> 5) & 1u] + (tx & 31u)) & 0x7FFFu;
            u32 ent = vram[waddr * 2u] | ((u32)vram[waddr * 2u + 1u] << 8);
            int py = (ent & 0x8000u) ? (7 - fy) : fy;
            u16 tid = (u16)(chr_shift + (ent & 0x03FFu));
            u32 row32 = (bpp == 2) ? get_tile2(tid)[py] : get_tile4(tid)[py];
            if (row32) {
                if (ent & 0x4000u)
                    row32 = flip_nibbles32(row32);
                row32 >>= (tx0 << 2);
                u32 pal = (ent >> 10) & 7u;
                const u16 *pal_p = (bpp == 2) ? &cg[(mode0_pal_off + pal * 4u) & 0xFFu]
                                              : &cg[(pal * 16u) & 0xFFu];
                u8 z = (ent & 0x2000u) ? z_hi : z_lo;
                if (plain) {
                    for (int dx = x; row32 && dx < x + n; dx++, row32 >>= 4) {
                        u32 px = row32 & 0x0Fu;
                        if (px && z > mz[dx]) {
                            mz[dx] = z;
                            mc[dx] = pal_p[px];
                            ms[dx] = bit;
                        }
                    }
                } else {
                    for (int i = 0; i < n; i++, row32 >>= 4) {
                        u32 px = row32 & 0x0Fu;
                        if (!px)
                            continue;
                        int dx = x + i;
                        u16 col = pal_p[px];
                        if (on_main && (!m_win_on || !wmask[dx]) && z > mz[dx]) {
                            mz[dx] = z;
                            mc[dx] = col;
                            ms[dx] = bit;
                        }
                        if (on_sub && (!s_win_on || !wmask[dx]) && z > sz[dx]) {
                            sz[dx] = z;
                            sc[dx] = col;
                        }
                    }
                }
            }
            x += n;
            sx += n;
        }
        return;
    }

    if (!opt_mode && mos_sz == 1 && !hires_m56 && !tile_w16 && !tile_h16 && bpp == 8) {
        int sy = eff_y + vofs;
        int ty = sy >> 3;
        int fy = sy & 7;
        int sx = hofs;
        int x = 0;
        u16 chr_shift = chr_base_w >> 5;
        u32 map_row[2];                             /* (as the 2- / 4-bit loop above has it) */
        {
            u32 base_w = (u32)(sc_reg & 0xFCu) << 8, sy_scr = ((u32)ty >> 5) & 1u;
            for (u32 sx_scr = 0; sx_scr < 2u; sx_scr++) {
                u32 screen = 0;
                switch (sc_reg & 3u) {
                case 1: screen = sx_scr; break;
                case 2: screen = sy_scr; break;
                case 3: screen = sx_scr | (sy_scr << 1); break;
                }
                map_row[sx_scr] = base_w + (screen << 10) + (u32)((ty & 31) << 5);
            }
        }
        const u8 *vram = M->vram;
        const u16 *cg = M->cgram;
        /* the usual layer: one screen alone, no window, colours from the palette -- its z, colour (and for the
           main screen what it came from) straight through one pointer each */
        int one_m = on_main && !on_sub && !m_win_on && !direct_col;
        int one_s = on_sub && !on_main && !s_win_on && !direct_col;
        u8 *one_z = one_m ? lc->main_z : lc->sub_z;
        u16 *one_c = one_m ? lc->main_col : lc->sub_col;
        while (x < SNES_W) {
            int tx0 = sx & 7;
            int n = 8 - tx0;
            if (x + n > SNES_W)
                n = SNES_W - x;
            u32 tx = (u32)(sx >> 3);
            u32 waddr = (map_row[(tx >> 5) & 1u] + (tx & 31u)) & 0x7FFFu;
            u32 ent = vram[waddr * 2u] | ((u32)vram[waddr * 2u + 1u] << 8);
            int py = (ent & 0x8000u) ? (7 - fy) : fy;
            const u8 *tr = get_tile8((u16)(chr_shift + (ent & 0x03FFu))) + py * 8;
            int hf = (ent & 0x4000u) != 0;
            u8 pal = (u8)((ent >> 10) & 7u);
            u8 z = (ent & 0x2000u) ? z_hi : z_lo;
            if (one_m || one_s) {
                const u8 *t = tr + (hf ? 7 - tx0 : tx0);
                int step = hf ? -1 : 1;
                for (int dx = x; dx < x + n; dx++, t += step) {
                    u32 px = *t;
                    if (px && z > one_z[dx]) {
                        one_z[dx] = z;
                        one_c[dx] = cg[px];
                        if (one_m)
                            lc->main_src[dx] = bit;
                    }
                }
                x += n;
                sx += n;
                continue;
            }
            for (int i = 0; i < n; i++) {
                u8 px = tr[hf ? (7 - (tx0 + i)) : (tx0 + i)];
                if (!px)
                    continue;
                int dx = x + i;
                u16 col = direct_col ? direct_color_15(px, pal) : M->cgram[px];
                if (on_main && (!m_win_on || !wmask[dx]) && z > lc->main_z[dx]) {
                    lc->main_z[dx] = z;
                    lc->main_col[dx] = col;
                    lc->main_src[dx] = bit;
                }
                if (on_sub && (!s_win_on || !wmask[dx]) && z > lc->sub_z[dx]) {
                    lc->sub_z[dx] = z;
                    lc->sub_col[dx] = col;
                }
            }
            x += n;
            sx += n;
        }
        return;
    }

    /* Fast 8-pixel sub-tile sliver paths for 16x16-pixel BGs (2bpp / 4bpp and 8bpp) */
    if (!opt_mode && mos_sz == 1 && !hires_m56 && tile_w16 && tile_h16 && (bpp == 2 || bpp == 4)) {
        int sy = eff_y + vofs;
        int ty = sy >> 4;
        int fy = sy & 15;
        int sx = hofs;
        int x = 0;
        u16 chr_shift = (bpp == 2) ? (chr_base_w >> 3) : (chr_base_w >> 4);
        u32 map_row[2];
        {
            u32 base_w = (u32)(sc_reg & 0xFCu) << 8, sy_scr = ((u32)ty >> 5) & 1u;
            for (u32 sx_scr = 0; sx_scr < 2u; sx_scr++) {
                u32 screen = 0;
                switch (sc_reg & 3u) {
                case 1: screen = sx_scr; break;
                case 2: screen = sy_scr; break;
                case 3: screen = sx_scr | (sy_scr << 1); break;
                }
                map_row[sx_scr] = base_w + (screen << 10) + (u32)((ty & 31) << 5);
            }
        }
        const u8 *vram = M->vram;
        const u16 *cg = M->cgram;
        u8 *mz = lc->main_z, *ms = lc->main_src, *sz = lc->sub_z;
        u16 *mc = lc->main_col, *sc = lc->sub_col;
        int main_only = on_main && !on_sub && !m_win_on;
        while (x < SNES_W) {
            int tx0 = sx & 7;
            int n = 8 - tx0;
            if (x + n > SNES_W)
                n = SNES_W - x;
            u32 tx = (u32)(sx >> 4);
            u32 waddr = (map_row[(tx >> 5) & 1u] + (tx & 31u)) & 0x7FFFu;
            u32 ent = vram[waddr * 2u] | ((u32)vram[waddr * 2u + 1u] << 8);
            int py16 = (ent & 0x8000u) ? (15 - fy) : fy;
            u32 sub_x = ((u32)(sx >> 3) ^ (ent >> 14)) & 1u;
            u16 tid = (u16)(chr_shift + (ent & 0x03FFu) + sub_x + ((u32)(py16 & 8) << 1));
            u32 row32 = (bpp == 2) ? get_tile2(tid)[py16 & 7] : get_tile4(tid)[py16 & 7];
            if (row32) {
                if (ent & 0x4000u)
                    row32 = flip_nibbles32(row32);
                row32 >>= (tx0 << 2);
                u32 pal = (ent >> 10) & 7u;
                const u16 *pal_p = (bpp == 2) ? &cg[(mode0_pal_off + pal * 4u) & 0xFFu]
                                              : &cg[(pal * 16u) & 0xFFu];
                u8 z = (ent & 0x2000u) ? z_hi : z_lo;
                if (main_only) {
                    for (int dx = x; row32 && dx < x + n; dx++, row32 >>= 4) {
                        u32 px = row32 & 0x0Fu;
                        if (px && z > mz[dx]) {
                            mz[dx] = z;
                            mc[dx] = pal_p[px];
                            ms[dx] = bit;
                        }
                    }
                } else {
                    for (int i = 0; i < n; i++, row32 >>= 4) {
                        u32 px = row32 & 0x0Fu;
                        if (!px)
                            continue;
                        int dx = x + i;
                        u16 col = pal_p[px];
                        if (on_main && (!m_win_on || !wmask[dx]) && z > mz[dx]) {
                            mz[dx] = z;
                            mc[dx] = col;
                            ms[dx] = bit;
                        }
                        if (on_sub && (!s_win_on || !wmask[dx]) && z > sz[dx]) {
                            sz[dx] = z;
                            sc[dx] = col;
                        }
                    }
                }
            }
            x += n;
            sx += n;
        }
        return;
    }

    if (!opt_mode && mos_sz == 1 && !hires_m56 && tile_w16 && tile_h16 && bpp == 8) {
        int sy = eff_y + vofs;
        int ty = sy >> 4;
        int fy = sy & 15;
        int sx = hofs;
        int x = 0;
        u16 chr_shift = chr_base_w >> 5;
        u32 map_row[2];
        {
            u32 base_w = (u32)(sc_reg & 0xFCu) << 8, sy_scr = ((u32)ty >> 5) & 1u;
            for (u32 sx_scr = 0; sx_scr < 2u; sx_scr++) {
                u32 screen = 0;
                switch (sc_reg & 3u) {
                case 1: screen = sx_scr; break;
                case 2: screen = sy_scr; break;
                case 3: screen = sx_scr | (sy_scr << 1); break;
                }
                map_row[sx_scr] = base_w + (screen << 10) + (u32)((ty & 31) << 5);
            }
        }
        const u8 *vram = M->vram;
        const u16 *cg = M->cgram;
        int single_m = on_main && !on_sub && !m_win_on && !direct_col;
        int single_s = on_sub && !on_main && !s_win_on && !direct_col;
        u8 *dst_z = single_m ? lc->main_z : lc->sub_z;
        u16 *dst_c = single_m ? lc->main_col : lc->sub_col;
        while (x < SNES_W) {
            int tx0 = sx & 7;
            int n = 8 - tx0;
            if (x + n > SNES_W)
                n = SNES_W - x;
            u32 tx = (u32)(sx >> 4);
            u32 waddr = (map_row[(tx >> 5) & 1u] + (tx & 31u)) & 0x7FFFu;
            u32 ent = vram[waddr * 2u] | ((u32)vram[waddr * 2u + 1u] << 8);
            int py16 = (ent & 0x8000u) ? (15 - fy) : fy;
            int hf = (ent & 0x4000u) != 0;
            u32 sub_x = (((u32)(sx >> 3) & 1u) ^ (u32)hf);
            const u8 *tr = get_tile8((u16)(chr_shift + (ent & 0x03FFu) + sub_x + ((u32)(py16 & 8) << 1))) + (py16 & 7) * 8;
            u8 pal = (u8)((ent >> 10) & 7u);
            u8 z = (ent & 0x2000u) ? z_hi : z_lo;
            if (single_m || single_s) {
                const u8 *t = tr + (hf ? 7 - tx0 : tx0);
                int step = hf ? -1 : 1;
                for (int dx = x; dx < x + n; dx++, t += step) {
                    u32 px = *t;
                    if (px && z > dst_z[dx]) {
                        dst_z[dx] = z;
                        dst_c[dx] = cg[px];
                        if (single_m)
                            lc->main_src[dx] = bit;
                    }
                }
                x += n;
                sx += n;
                continue;
            }
            for (int i = 0; i < n; i++) {
                u8 px = tr[hf ? (7 - (tx0 + i)) : (tx0 + i)];
                if (!px)
                    continue;
                int dx = x + i;
                u16 col = direct_col ? direct_color_15(px, pal) : M->cgram[px];
                if (on_main && (!m_win_on || !wmask[dx]) && z > lc->main_z[dx]) {
                    lc->main_z[dx] = z;
                    lc->main_col[dx] = col;
                    lc->main_src[dx] = bit;
                }
                if (on_sub && (!s_win_on || !wmask[dx]) && z > lc->sub_z[dx]) {
                    lc->sub_z[dx] = z;
                    lc->sub_col[dx] = col;
                }
            }
            x += n;
            sx += n;
        }
        return;
    }

    /* Fast 4-pixel sub-tile sliver path for hi-res Modes 5 & 6 (including Mode 6 offset-per-tile and interlace) */
    if (mos_sz == 1 && hires_m56 && (bpp == 2 || bpp == 4)) {
        int base_sy = (eff_y + vofs) << (ilace_m56 ? 1 : 0);
        u16 chr_shift = (bpp == 2) ? (chr_base_w >> 3) : (chr_base_w >> 4);
        u32 map_row[2] = { 0, 0 };
        if (!opt_mode) {
            int ty = base_sy >> (tile_h16 ? 4 : 3);
            u32 base_w = (u32)(sc_reg & 0xFCu) << 8, sy_scr = ((u32)ty >> 5) & 1u;
            for (u32 sx_scr = 0; sx_scr < 2u; sx_scr++) {
                u32 screen = 0;
                switch (sc_reg & 3u) {
                case 1: screen = sx_scr; break;
                case 2: screen = sy_scr; break;
                case 3: screen = sx_scr | (sy_scr << 1); break;
                }
                map_row[sx_scr] = base_w + (screen << 10) + (u32)((ty & 31) << 5);
            }
        }
        const u8 *vram = M->vram;
        const u16 *cg = M->cgram;
        u8 *mz = lc->main_z, *ms = lc->main_src, *sz = lc->sub_z;
        u16 *mc = lc->main_col, *sc = lc->sub_col;
        int main_only = on_main && !on_sub && !m_win_on;
        u8 bg_enable = (bg == 0) ? 0x20u : 0x40u;
        int x = 0;
        while (x < SNES_W) {
            int u0 = (x + hofs) & 3;
            int n = 4 - u0;
            if (x + n > SNES_W)
                n = SNES_W - x;
            if (opt_mode && x < 8 && x + n > 8)
                n = 8 - x;

            int xh = x + hofs;
            int sy = base_sy;
            if (opt_mode && (x >= 8 || (hofs & ~7u) != 0)) {
                int col_idx = ((x + (hofs & 7)) >> 3) - 1;
                if (col_idx >= 0) {
                    int opt_tx = (col_idx + (S.bg_hofs[2] >> 3)) & 63;
                    int opt_ty = S.bg_vofs[2] >> 3;
                    u16 hv = fetch_bg_map_entry(S.bg_sc[2], opt_tx, opt_ty);
                    u16 vv = fetch_bg_map_entry(S.bg_sc[2], opt_tx, opt_ty + 1);
                    if ((hv >> 8) & bg_enable)
                        xh = x + (hv & 0x03F8u) + (hofs & 7);
                    if ((vv >> 8) & bg_enable)
                        sy = (eff_y + (vv & 0x03FFu)) << (ilace_m56 ? 1 : 0);
                }
            }

            u32 tx = (u32)(xh >> 3);
            u32 ent;
            if (!opt_mode) {
                u32 waddr = (map_row[(tx >> 5) & 1u] + (tx & 31u)) & 0x7FFFu;
                ent = vram[waddr * 2u] | ((u32)vram[waddr * 2u + 1u] << 8);
            } else {
                ent = fetch_bg_map_entry(sc_reg, (int)tx, sy >> (tile_h16 ? 4 : 3));
            }

            int hflip = (ent >> 14) & 1;
            u32 h_add = (u32)(((xh >> 2) & 1) ^ hflip);
            int fy = sy & (tile_h16 ? 15 : 7);
            int py_full = (ent & 0x8000u) ? ((tile_h16 ? 15 : 7) - fy) : fy;
            u32 v_add = (tile_h16 && py_full >= 8) ? 16u : 0u;
            u16 tid = (u16)(chr_shift + (ent & 0x03FFu) + h_add + v_add);
            u32 row32 = (bpp == 2) ? get_tile2(tid)[py_full & 7] : get_tile4(tid)[py_full & 7];
            if (row32) {
                if (hflip)
                    row32 = flip_nibbles32(row32);
                row32 >>= (u0 << 3);
                u32 pal = (ent >> 10) & 7u;
                const u16 *pal_p = (bpp == 2) ? &cg[(pal * 4u) & 0xFFu] : &cg[(pal * 16u) & 0xFFu];
                u8 z = (ent & 0x2000u) ? z_hi : z_lo;
                if (main_only) {
                    for (int dx = x; row32 && dx < x + n; dx++, row32 >>= 8) {
                        u32 px = row32 & 0x0Fu;
                        if (px && z > mz[dx]) {
                            mz[dx] = z;
                            mc[dx] = pal_p[px];
                            ms[dx] = bit;
                        }
                    }
                } else {
                    for (int i = 0; i < n; i++, row32 >>= 8) {
                        u32 px = row32 & 0x0Fu;
                        if (!px)
                            continue;
                        int dx = x + i;
                        u16 col = pal_p[px];
                        if (on_main && (!m_win_on || !wmask[dx]) && z > mz[dx]) {
                            mz[dx] = z;
                            mc[dx] = col;
                            ms[dx] = bit;
                        }
                        if (on_sub && (!s_win_on || !wmask[dx]) && z > sz[dx]) {
                            sz[dx] = z;
                            sc[dx] = col;
                        }
                    }
                }
            }
            x += n;
        }
        return;
    }

    for (int x = 0; x < SNES_W; x++) {
        int eff_x = (mos_sz > 1) ? (x - (x % mos_sz)) : x;
        int sx = eff_x + hofs;
        int sy = eff_y + vofs;
        if (hires_m56) sx <<= 1;
        if (ilace_m56) sy <<= 1;

        /* Offset-per-tile in Modes 2, 4, 6 (for BG1 & BG2, starting from column 1) */
        if (opt_mode && (eff_x >= 8 || (hofs & ~7u) != 0)) {
            int col_idx = ((eff_x + (hofs & 7)) >> 3) - 1;
            if (col_idx >= 0) {
                int opt_tx = (col_idx + (S.bg_hofs[2] >> 3)) & 63;
                int opt_ty = S.bg_vofs[2] >> 3;
                u16 hv = fetch_bg_map_entry(S.bg_sc[2], opt_tx, opt_ty);
                u8 bg_enable = (bg == 0) ? 0x20u : 0x40u;
                if (mode == 4) {
                    if ((hv >> 8) & bg_enable) {
                        if (hv & 0x8000u) sy = eff_y + (hv & 0x03FFu);
                        else              sx = eff_x + (hv & 0x03F8u) + (hofs & 7);
                    }
                } else {
                    u16 vv = fetch_bg_map_entry(S.bg_sc[2], opt_tx, opt_ty + 1);
                    if ((hv >> 8) & bg_enable)
                        sx = ((eff_x + (hv & 0x03F8u) + (hofs & 7)) << (hires_m56 ? 1 : 0));
                    if ((vv >> 8) & bg_enable)
                        sy = ((eff_y + (vv & 0x03FFu)) << (ilace_m56 ? 1 : 0));
                }
            }
        }

        int tx = sx >> (tile_w16 ? 4 : 3);
        int ty = sy >> (tile_h16 ? 4 : 3);
        u16 ent = fetch_bg_map_entry(sc_reg, tx, ty);
        u16 base_tile = ent & 0x03FFu;
        int hflip = (ent & 0x4000u) != 0;
        int vflip = (ent & 0x8000u) != 0;
        int px_x = sx & (tile_w16 ? 15 : 7);
        int px_y = sy & (tile_h16 ? 15 : 7);
        if (hflip) px_x = (tile_w16 ? 15 : 7) - px_x;
        if (vflip) px_y = (tile_h16 ? 15 : 7) - px_y;
        if (tile_w16 && (px_x >= 8)) { base_tile = (u16)(base_tile + 1u); px_x &= 7; }
        if (tile_h16 && (px_y >= 8)) { base_tile = (u16)(base_tile + 16u); px_y &= 7; }

        u8 px = 0;
        if (bpp == 2) {
            const u32 *t = get_tile2((u16)((chr_base_w >> 3) + base_tile));
            px = (u8)((t[px_y] >> (px_x * 4)) & 0x03u);
        } else if (bpp == 4) {
            const u32 *t = get_tile4((u16)((chr_base_w >> 4) + base_tile));
            px = (u8)((t[px_y] >> (px_x * 4)) & 0x0Fu);
        } else {
            const u8 *t = get_tile8((u16)((chr_base_w >> 5) + base_tile));
            px = t[px_y * 8 + px_x];
        }
        if (!px)
            continue;

        u8 pal = (u8)((ent >> 10) & 7u);
        u16 col;
        if (bpp == 2)      col = M->cgram[(mode0_pal_off + pal * 4u + px) & 0xFFu];
        else if (bpp == 4) col = M->cgram[(pal * 16u + px) & 0xFFu];
        else               col = direct_col ? direct_color_15(px, pal) : M->cgram[px];

        u8 z = (ent & 0x2000u) ? z_hi : z_lo;
        int m_ok = on_main && (!m_win_on || !wmask[x]);
        int s_ok = on_sub  && (!s_win_on || !wmask[x]);
        if (m_ok && z > lc->main_z[x]) {
            lc->main_z[x] = z;
            lc->main_col[x] = col;
            lc->main_src[x] = bit;
        }
        if (s_ok && z > lc->sub_z[x]) {
            lc->sub_z[x] = z;
            lc->sub_col[x] = col;
        }
    }
}

static void render_mode7_line(struct line_compositor *lc, int line_y)
{
    int extbg = (S.setini & 0x40u) != 0;
    int m1 = (S.tm & 1u) != 0, s1 = (S.ts & 1u) != 0 && lc->use_sub;
    int m2 = extbg && (S.tm & 2u), s2 = extbg && (S.ts & 2u) && lc->use_sub;
    if (!m1 && !s1 && !m2 && !s2)
        return;

    /* each layer's window, where it counts: mw / sw say that wmask is to be looked at for the main / sub screen */
    u8 wmask1[SNES_W], wmask2[SNES_W];
    int mw1 = m1 && (S.tmw & 1u), sw1 = s1 && (S.tsw & 1u);
    int mw2 = m2 && (S.tmw & 2u), sw2 = s2 && (S.tsw & 2u);
    if (mw1 || sw1) {
        int kind = build_window_mask(0, wmask1);
        if (kind == 1) {
            if (mw1) m1 = 0;
            if (sw1) s1 = 0;
        }
        if (kind != 2)
            mw1 = sw1 = 0;
    }
    if (mw2 || sw2) {
        int kind = build_window_mask(1, wmask2);
        if (kind == 1) {
            if (mw2) m2 = 0;
            if (sw2) s2 = 0;
        }
        if (kind != 2)
            mw2 = sw2 = 0;
    }
    if (!m1 && !s1 && !m2 && !s2)
        return;

    int mos_sz = (S.mosaic & 1u) ? ((S.mosaic >> 4) + 1) : 1;
    int sy = (mos_sz > 1) ? (line_y - (line_y % mos_sz)) : line_y;
    if (S.m7sel & 2u)
        sy = 255 - sy;

    /* 11-bit signed clip as real PPU1 */
    #define CLIP10(v) (((v) & 0x2000) ? ((v) | ~0x03FF) : ((v) & 0x03FF))
    s32 hofs = CLIP10((s32)S.m7hofs - S.m7x);
    s32 vofs = CLIP10((s32)S.m7vofs - S.m7y);
    s32 base_x = ((S.m7a * hofs) & ~63) + ((S.m7b * vofs) & ~63) + ((S.m7b * sy) & ~63) + ((s32)S.m7x << 8);
    s32 base_y = ((S.m7c * hofs) & ~63) + ((S.m7d * vofs) & ~63) + ((S.m7d * sy) & ~63) + ((s32)S.m7y << 8);
    #undef CLIP10

    int direct_col = (S.cgwsel & 1u) != 0;

    /* The plain case -- BG1 alone, no mosaic, palette colours: the map position steps by (A, C) a pixel, no
       multiplication, and what the loop needs stays in registers.  This layer is the first drawn into the line,
       so its priority 5 beats what is there (the backdrop's 0) without a look. */
    if (mos_sz == 1 && !m2 && !s2 && !direct_col) {
        s32 fx = base_x, fy = base_y, da = S.m7a, dc = S.m7c;
        if (S.m7sel & 1u) {                         /* flipped left to right */
            fx += da * 255;
            fy += dc * 255;
            da = -da;
            dc = -dc;
        }
        int over = (S.m7sel & 0x80u) != 0, fill0 = (S.m7sel & 0x40u) != 0;
        const u8 *vram = M->vram;
        const u16 *cg = M->cgram;
        u8 *mz = lc->main_z, *ms = lc->main_src, *sz = lc->sub_z;
        u16 *mc = lc->main_col, *sc = lc->sub_col;
        if (m1 && !mw1 && !s1) {
            /* ... on the main screen alone, no window (a racing game's ground): no branch on the pixel -- a
               transparent one (0) writes the backdrop's colour again, which is CGRAM's entry 0, with priority 0
               (and source 20h, the backdrop's, when the line's colour maths will look at sources) */
            int need_src = lc->need_src;
            for (int x = 0; x < SNES_W; x++, fx += da, fy += dc) {
                s32 rx = fx >> 8, ry = fy >> 8;
                u32 px;
                if (over && ((rx | ry) & ~1023)) {
                    px = fill0 ? vram[(u32)(((ry & 7) << 3) | (rx & 7)) * 2u + 1u] : 0u;
                } else {
                    u32 tile = vram[((((u32)ry >> 3) & 127u) << 8) | ((((u32)rx >> 3) & 127u) << 1)];
                    px = vram[((tile << 6) | (u32)((ry & 7) << 3) | (u32)(rx & 7)) * 2u + 1u];
                }
                u32 any = (0u - px) >> 26;              /* 3Fh for a pixel, 0 for none */
                mc[x] = cg[px];
                mz[x] = (u8)(any & 5u);
                if (need_src)
                    ms[x] = (u8)(0x20u ^ (any & 0x21u));
            }
            return;
        }
        for (int x = 0; x < SNES_W; x++, fx += da, fy += dc) {
            s32 rx = fx >> 8, ry = fy >> 8;
            u32 px;
            if (over && ((rx | ry) & ~1023)) {      /* outside the 1024 x 1024 map */
                if (!fill0)
                    continue;
                px = vram[(u32)(((ry & 7) << 3) | (rx & 7)) * 2u + 1u];
            } else {
                u32 tile = vram[((((u32)ry >> 3) & 127u) << 8) | ((((u32)rx >> 3) & 127u) << 1)];
                px = vram[((tile << 6) | (u32)((ry & 7) << 3) | (u32)(rx & 7)) * 2u + 1u];
            }
            if (!px)
                continue;
            u16 col = cg[px];
            if (m1 && !(mw1 && wmask1[x])) {
                mz[x] = 5;
                mc[x] = col;
                ms[x] = 0x01u;
            }
            if (s1 && !(sw1 && wmask1[x])) {
                sz[x] = 5;
                sc[x] = col;
            }
        }
        return;
    }

    for (int x = 0; x < SNES_W; x++) {
        int sx = (mos_sz > 1) ? (x - (x % mos_sz)) : x;
        if (S.m7sel & 1u)
            sx = 255 - sx;
        s32 rx = (base_x + S.m7a * sx) >> 8;
        s32 ry = (base_y + S.m7c * sx) >> 8;

        u8 px = 0;
        if ((S.m7sel & 0x80u) && (rx < 0 || rx >= 1024 || ry < 0 || ry >= 1024)) {
            if (S.m7sel & 0x40u) {
                u32 ca = (u32)(((ry & 7) << 3) | (rx & 7)) * 2u + 1u;
                px = M->vram[ca];
            }
        } else {
            u32 tx = (u32)(rx >> 3) & 127u;
            u32 ty = (u32)(ry >> 3) & 127u;
            u8 tile = M->vram[((ty << 7) | tx) * 2u];
            u32 ca = (((u32)tile << 6) | (u32)((ry & 7) << 3) | (u32)(rx & 7)) * 2u + 1u;
            px = M->vram[ca];
        }

        if (px) {
            u16 col = direct_col ? direct_color_15(px, 0) : M->cgram[px];
            if (m1 && (!mw1 || !wmask1[x]) && 5 > lc->main_z[x]) {
                lc->main_z[x] = 5; lc->main_col[x] = col; lc->main_src[x] = 0x01u;
            }
            if (s1 && (!sw1 || !wmask1[x]) && 5 > lc->sub_z[x]) {
                lc->sub_z[x] = 5; lc->sub_col[x] = col;
            }
        }
        if (extbg && (px & 0x7Fu)) {
            u8 p7 = px & 0x7Fu;
            u8 z2 = (px & 0x80u) ? 7 : 2;
            u16 col2 = M->cgram[p7];
            if (m2 && (!mw2 || !wmask2[x]) && z2 > lc->main_z[x]) {
                lc->main_z[x] = z2; lc->main_col[x] = col2; lc->main_src[x] = 0x02u;
            }
            if (s2 && (!sw2 || !wmask2[x]) && z2 > lc->sub_z[x]) {
                lc->sub_z[x] = z2; lc->sub_col[x] = col2;
            }
        }
    }
}

static void render_sprites_line(struct line_compositor *lc, int line_y, const u8 obj_z[4])
{
    int on_main = (S.tm & 0x10u) != 0;
    int on_sub  = (S.ts & 0x10u) != 0 && lc->use_sub;
    if (!on_main && !on_sub)
        return;

    static const u8 spr_w_tab[8][2] = {
        {8, 16}, {8, 32}, {8, 64}, {16, 32}, {16, 64}, {32, 64}, {16, 32}, {16, 32}
    };
    static const u8 spr_h_tab[8][2] = {
        {8, 16}, {8, 32}, {8, 64}, {16, 32}, {16, 64}, {32, 64}, {32, 64}, {32, 32}
    };

    u8 sz_mode = (u8)((S.obsel >> 5) & 7u);
    u16 base_w = (u16)((S.obsel & 7u) << 13);
    u16 gap_w  = (u16)(((S.obsel >> 3) & 3u) << 12);
    int first = S.oam_prio ? ((S.oam_addr >> 2) & 0x7F) : 0;

    /* each sprite's first line and height (0 when it is off the left edge: on no line), kept until OAM or
       OBSEL is written: the scan of all 128 for every line then looks at two bytes a sprite */
    if (S.oam_dirty) {
        for (int idx = 0; idx < 128; idx++) {
            u8 hi_bits = (u8)((M->oam[512 + (idx >> 2)] >> ((idx & 3) * 2)) & 3u);
            int sx = M->oam[idx * 4 + 0] | ((hi_bits & 1u) ? -256 : 0);
            int big = (hi_bits >> 1) & 1;
            int w = spr_w_tab[sz_mode][big];
            M->spr_yh[idx][0] = (u8)((M->oam[idx * 4 + 1] + 1) & 0xFF);
            M->spr_yh[idx][1] = (sx <= -w && sx != -256) ? 0u : spr_h_tab[sz_mode][big];
        }
        S.oam_dirty = 0;
        S.spr_first = 0xFFu;                    /* (the lines' lists are to be made again) */
    }
    /* the sprites of each line -- the first 32, in the scan's order from `first`, whose lines (wrapping at 256)
       reach it: listed once here, where the scan of all 128 was done for every line (a game writes OAM once a
       frame; 3% of a frame of Super Mario Kart went into the scan) */
    if (S.spr_first != (u8)first) {
        const u8 (*yh)[2] = M->spr_yh;
        for (int l = 0; l < 240; l++)
            M->spr_line_n[l] = 0;
        for (int i = 0; i < 128; i++) {
            int idx = (first + i) & 0x7F;
            u32 y0 = yh[idx][0], h = yh[idx][1];
            for (u32 dy = 0; dy < h; dy++) {
                u32 l = (y0 + dy) & 0xFFu;
                if (l < 240u && M->spr_line_n[l] < 32u)
                    M->spr_line[l][M->spr_line_n[l]++] = (u8)idx;
            }
        }
        S.spr_first = (u8)first;
    }
    if ((u32)line_y >= 240u)
        return;
    const u8 *sel = M->spr_line[line_y];
    int n_sel = M->spr_line_n[line_y];
    if (!n_sel)
        return;

    u8 wmask[SNES_W];
    int mw = on_main && (S.tmw & 0x10u), sw = on_sub && (S.tsw & 0x10u);    /* the window counts, by wmask */
    if (mw || sw) {
        int kind = build_window_mask(4, wmask);
        if (kind == 1) {
            if (mw) on_main = 0;
            if (sw) on_sub = 0;
            if (!on_main && !on_sub)
                return;
        }
        if (kind != 2)
            mw = sw = 0;
    }

    u8 line_px[SNES_W] __attribute__((aligned(4))), line_pal[SNES_W], line_pri[SNES_W];
    for (int x = 0; x < SNES_W / 4; x++)
        ((u32_alias *)line_px)[x] = 0u;
    int lo = SNES_W, hi = 0;                    /* the columns the sprites' pixels reach */

    /* Draw selected sprites back-to-front so earlier OAM wins every non-zero pixel (including priority!) */
    for (int s = n_sel - 1; s >= 0; s--) {
        int idx = sel[s];
        u8 hi_bits = (u8)((M->oam[512 + (idx >> 2)] >> ((idx & 3) * 2)) & 3u);
        int sx = M->oam[idx * 4 + 0] | ((hi_bits & 1u) ? -256 : 0);
        if (sx == -256)
            continue;
        int sy = (M->oam[idx * 4 + 1] + 1) & 0xFF;
        u8 tile0 = M->oam[idx * 4 + 2];
        u8 attr  = M->oam[idx * 4 + 3];
        int big = (hi_bits >> 1) & 1;
        int w = spr_w_tab[sz_mode][big];
        int h = spr_h_tab[sz_mode][big];
        int dy = (line_y - sy) & 0xFF;
        if (attr & 0x80u) dy = h - 1 - dy;
        int ty = dy >> 3, fy = dy & 7;
        int hflip = (attr & 0x40u) != 0;
        u8 pal = (u8)((attr >> 1) & 7u);
        u8 pri = (u8)((attr >> 4) & 3u);
        u16 name_w = (u16)(base_w + ((attr & 1u) ? (0x1000u + gap_w) : 0));

        int tiles_w = w >> 3;
        for (int tx = 0; tx < tiles_w; tx++) {
            int screen_x0 = sx + (hflip ? (tiles_w - 1 - tx) : tx) * 8;
            if (screen_x0 >= SNES_W || screen_x0 + 8 <= 0)
                continue;
            u8 c_row = (u8)(((tile0 >> 4) + ty) & 0x0Fu);
            u8 c_col = (u8)((tile0 + tx) & 0x0Fu);
            u16 tid = (u16)((name_w >> 4) + ((c_row << 4) | c_col));
            u32 row32 = get_tile4(tid)[fy];
            if (!row32)
                continue;
            if (hflip)
                row32 = flip_nibbles32(row32);
            if (screen_x0 < lo)
                lo = screen_x0;
            if (screen_x0 + 8 > hi)
                hi = screen_x0 + 8;
            for (int k = 0; k < 8; k++, row32 >>= 4) {
                int dx = screen_x0 + k;
                if ((unsigned)dx >= SNES_W)
                    continue;
                u8 px = (u8)(row32 & 0x0Fu);
                if (px) {
                    line_px[dx] = px;
                    line_pal[dx] = pal;
                    line_pri[dx] = pri;
                }
            }
        }
    }
    if (lo < 0)
        lo = 0;
    if (hi > SNES_W)
        hi = SNES_W;

    const u16 *cg = M->cgram + 128;
    u8 *mz = lc->main_z, *ms = lc->main_src, *sz = lc->sub_z;
    u16 *mc = lc->main_col, *sc = lc->sub_col;
    for (int x = lo; x < hi; x++) {
        u32 px = line_px[x];
        if (!px)
            continue;
        u32 pal = line_pal[x];
        u16 col = cg[pal * 16u + px];
        u8 z = obj_z[line_pri[x]];
        if (on_main && !(mw && wmask[x]) && z > mz[x]) {
            mz[x] = z;
            mc[x] = col;
            ms[x] = (pal >= 4u) ? 0x10u : 0x00u;    /* (only OBJ palettes 4..7 take part in colour maths) */
        }
        if (on_sub && !(sw && wmask[x]) && z > sz[x]) {
            sz[x] = z;
            sc[x] = col;
        }
    }
}

/* The colour maths on whole 15-bit colours, a channel's five bits each with room above them (green moved up 16):
   render_snes_line's sums channel by channel, their results exactly.  add / sub clamp at 31 / 0 (a bit above
   each channel tells: it carries out of an addition, and stays set through a subtraction that does not borrow);
   the halved ones cannot leave 0..31 -- (a + b) / 2 is (a & b) + (a ^ b) / 2 a channel, and a difference below
   0 halves to below 0, clamped to 0 as before the halving. */
static inline __attribute__((always_inline)) u32 cm_add(u32 a, u32 b)
{
    u32 A = (a & 0x7C1Fu) | ((a & 0x03E0u) << 16), B = (b & 0x7C1Fu) | ((b & 0x03E0u) << 16);
    u32 S2 = A + B, O = S2 & 0x04008020u;
    S2 |= O - (O >> 5);
    return (S2 & 0x7C1Fu) | ((S2 >> 16) & 0x03E0u);
}

static inline __attribute__((always_inline)) u32 cm_sub(u32 a, u32 b)
{
    u32 A = (a & 0x7C1Fu) | ((a & 0x03E0u) << 16), B = (b & 0x7C1Fu) | ((b & 0x03E0u) << 16);
    u32 D = (A | 0x04008020u) - B, K = D & 0x04008020u;
    D &= K - (K >> 5);
    return (D & 0x7C1Fu) | ((D >> 16) & 0x03E0u);
}

static inline __attribute__((always_inline)) u32 cm_add_half(u32 a, u32 b)
{
    a &= 0x7FFFu;
    b &= 0x7FFFu;
    return (a & b) + (((a ^ b) & 0x7BDEu) >> 1);
}

static inline __attribute__((always_inline)) u32 cm_sub_half(u32 a, u32 b)
{
    return (cm_sub(a, b) & 0x7BDEu) >> 1;
}

/* The colour maths of the pixels x0 .. x1 - 1 of a line, where the colour window neither clips the main screen
   nor prevents the maths (most lines that have maths at all, whole): each pixel a layer of CGADSUB's came from
   gets the sub screen's pixel -- the fixed colour where it has none, then not halved -- or the fixed colour
   added to / subtracted from it.  SUB: subtract; HALF: CGADSUB's halving; SCR: the sub screen is the other
   operand */
static inline __attribute__((always_inline)) void cm_line(const struct line_compositor *lc, u16 *dst, int x0, int x1,
                                                          u32 math_en, u32 fixed_col, int SUB, int HALF, int SCR)
{
    const u16 *mc = lc->main_col, *sc = lc->sub_col;
    const u8 *src = lc->main_src, *sz = lc->sub_z;
    for (int x = x0; x < x1; x++) {
        u32 c = mc[x];
        if (src[x] & math_en) {
            u32 o = fixed_col;
            int half = HALF;
            if (SCR) {
                if (sz[x])
                    o = sc[x];
                else
                    half = 0;
            }
            if (SUB)
                c = half ? cm_sub_half(c, o) : cm_sub(c, o);
            else
                c = half ? cm_add_half(c, o) : cm_add(c, o);
        }
        dst[x] = (u16)c;
    }
}

static void __attribute__((noinline)) cm_line_any(const struct line_compositor *lc, u16 *dst, int x0, int x1,
                                                  u32 math_en, u32 fixed_col, int subtract, int half, int scr)
{
    switch ((subtract ? 4 : 0) | (half ? 2 : 0) | (scr ? 1 : 0)) {
    case 0: cm_line(lc, dst, x0, x1, math_en, fixed_col, 0, 0, 0); break;
    case 1: cm_line(lc, dst, x0, x1, math_en, fixed_col, 0, 0, 1); break;
    case 2: cm_line(lc, dst, x0, x1, math_en, fixed_col, 0, 1, 0); break;
    case 3: cm_line(lc, dst, x0, x1, math_en, fixed_col, 0, 1, 1); break;
    case 4: cm_line(lc, dst, x0, x1, math_en, fixed_col, 1, 0, 0); break;
    case 5: cm_line(lc, dst, x0, x1, math_en, fixed_col, 1, 0, 1); break;
    case 6: cm_line(lc, dst, x0, x1, math_en, fixed_col, 1, 1, 0); break;
    default: cm_line(lc, dst, x0, x1, math_en, fixed_col, 1, 1, 1); break;
    }
}

/* The same where the colour window clips the main screen to black: the maths' pixels are then 0 plus the other
   operand, never halved -- the operand itself when adding, 0 when subtracting -- and the others black */
static void __attribute__((noinline)) cm_line_clipped(const struct line_compositor *lc, u16 *dst, int x0, int x1,
                                                      u32 math_en, u32 fixed_col, int subtract, int scr)
{
    for (int x = x0; x < x1; x++) {
        u32 c = 0u;
        if (!subtract && (lc->main_src[x] & math_en))
            c = ((scr && lc->sub_z[x]) ? lc->sub_col[x] : fixed_col) & 0x7FFFu;
        dst[x] = (u16)c;
    }
}

static void render_snes_line(int y, u16 *dst)
{
    if (S.inidisp & 0x80u) {            /* Forced blank */
        for (int x = 0; x < SNES_W; x++)
            dst[x] = 0;
        return;
    }

    /* What the line's last stage will do, from the registers alone: the main screen is clipped to black, and
       the colour maths is prevented, nowhere (0), everywhere (1), where the colour window's mask is 0 (2) or
       where it is 1 (3).  With no clipping, no maths and full brightness the layers draw straight into the
       picture's line; with no maths the sub screen is not drawn at all. */
    u8 cw_mask[SNES_W];
    int clip_mode = (S.cgwsel >> 6) & 3u;
    int prev_mode = (S.cgwsel >> 4) & 3u;
    u8 math_en     = S.cgadsub & 0x3Fu;
    int cw_kind = 0;
    if (clip_mode == 1 || clip_mode == 2 || (math_en && (prev_mode == 1 || prev_mode == 2)))
        cw_kind = build_window_mask(5, cw_mask);
    int clip_r = cw_region(clip_mode, cw_kind);
    int prev_r = math_en ? cw_region(prev_mode, cw_kind) : 1;
    int sub_scr_en = (S.cgwsel & 0x02u) != 0;
    u8 bright      = S.inidisp & 0x0Fu;
    int direct = clip_r == 0 && prev_r == 1 && bright == 15u;

    struct line_compositor lc;
    lc.main_col = direct ? dst : lc.main_buf;
    lc.use_sub = sub_scr_en && prev_r != 1;
    lc.need_src = prev_r != 1;
    {                                   /* the backdrop everywhere (main_src 20h), a word at a time */
        u32 back2 = (u32)M->cgram[0] * 0x10001u;
        u32_alias *mz = (u32_alias *)lc.main_z, *ms = (u32_alias *)lc.main_src;
        if (((unsigned long)lc.main_col & 3ul) == 0ul) {
            u32_alias *mc = (u32_alias *)lc.main_col;
            for (int i = 0; i < SNES_W / 2; i++)
                mc[i] = back2;
        } else {
            for (int i = 0; i < SNES_W; i++)
                lc.main_col[i] = (u16)back2;
        }
        for (int i = 0; i < SNES_W / 4; i++)
            mz[i] = 0u;
        if (prev_r != 1)                /* (what a pixel came from is looked at by the colour maths only) */
            for (int i = 0; i < SNES_W / 4; i++)
                ms[i] = 0x20202020u;
        if (lc.use_sub) {
            u32 fix2 = (u32)S.fixed_col * 0x10001u;
            u32_alias *sc = (u32_alias *)lc.sub_col, *sz = (u32_alias *)lc.sub_z;
            for (int i = 0; i < SNES_W / 2; i++)
                sc[i] = fix2;
            for (int i = 0; i < SNES_W / 4; i++)
                sz[i] = 0u;
        }
    }

    int mode = S.bgmode & 7u;
    switch (mode) {
    case 0: {
        static const u8 oz[4] = {3, 6, 9, 12};
        render_bg_layer(&lc, 3, 2, y, 1, 4, 0);
        render_bg_layer(&lc, 2, 2, y, 2, 5, 0);
        render_bg_layer(&lc, 1, 2, y, 7, 10, 0);
        render_bg_layer(&lc, 0, 2, y, 8, 11, 0);
        render_sprites_line(&lc, y, oz);
        break;
    }
    case 1: {
        static const u8 oz[4] = {2, 4, 7, 10};
        int bg3_top = (S.bgmode & 0x08u) != 0;
        render_bg_layer(&lc, 2, 2, y, 1, bg3_top ? 11 : 3, 0);
        render_bg_layer(&lc, 1, 4, y, 5, 8, 0);
        render_bg_layer(&lc, 0, 4, y, 6, 9, 0);
        render_sprites_line(&lc, y, oz);
        break;
    }
    case 2: {
        static const u8 oz[4] = {2, 4, 6, 8};
        render_bg_layer(&lc, 1, 4, y, 1, 5, 1);
        render_bg_layer(&lc, 0, 4, y, 3, 7, 1);
        render_sprites_line(&lc, y, oz);
        break;
    }
    case 3: {
        static const u8 oz[4] = {2, 4, 6, 8};
        render_bg_layer(&lc, 1, 4, y, 1, 5, 0);
        render_bg_layer(&lc, 0, 8, y, 3, 7, 0);
        render_sprites_line(&lc, y, oz);
        break;
    }
    case 4: {
        static const u8 oz[4] = {2, 4, 6, 8};
        render_bg_layer(&lc, 1, 2, y, 1, 5, 1);
        render_bg_layer(&lc, 0, 8, y, 3, 7, 1);
        render_sprites_line(&lc, y, oz);
        break;
    }
    case 5: {
        static const u8 oz[4] = {2, 4, 6, 8};
        render_bg_layer(&lc, 1, 2, y, 1, 5, 0);
        render_bg_layer(&lc, 0, 4, y, 3, 7, 0);
        render_sprites_line(&lc, y, oz);
        break;
    }
    case 6: {
        static const u8 oz[4] = {2, 4, 6, 8};
        render_bg_layer(&lc, 0, 4, y, 3, 7, 1);
        render_sprites_line(&lc, y, oz);
        break;
    }
    default: {                          /* Mode 7 */
        static const u8 oz[4] = {3, 6, 8, 9};
        render_mode7_line(&lc, y);
        render_sprites_line(&lc, y, oz);
        break;
    }
    }

    /* Colour window + add / subtract / half colour maths + master brightness */
    if (direct)                         /* the main screen as it is, drawn into the picture: most lines of most games */
        return;
    int subtract   = (S.cgadsub & 0x80u) != 0;
    int half_math  = (S.cgadsub & 0x40u) != 0;
    u16 fixed_col  = S.fixed_col;
    const u8 *blut = M->bright_lut[bright];

    if (clip_r == 0 && prev_r == 1) {   /* ... dimmed */
        for (int x = 0; x < SNES_W; x++) {
            u16 mc = lc.main_col[x];
            dst[x] = (u16)(blut[mc & 31u] | ((u16)blut[(mc >> 5) & 31u] << 5) | ((u16)blut[(mc >> 10) & 31u] << 10));
        }
        return;
    }

    /* The line by the runs of the colour window's mask -- at most five, the whole line when the mask is not
       looked at -- each with the main screen clipped to black or not and the maths prevented or not: black, the
       main screen as it is, or the maths on whole colours (cm_line).  (It was decided, and summed channel by
       channel with their clamps, at every pixel: half of the frame of a game with maths on every line.) */
    int masked = clip_r >= 2 || prev_r >= 2;        /* (cw_region gives 2 / 3 only with a mask made) */
    for (int x0 = 0; x0 < SNES_W;) {
        int m = masked ? cw_mask[x0] : 0, x1 = SNES_W;
        if (masked)
            for (x1 = x0 + 1; x1 < SNES_W && cw_mask[x1] == m; x1++)
                ;
        int clip_blk = clip_r == 1 || (clip_r == 2 && !m) || (clip_r == 3 && m);
        int prevent  = prev_r == 1 || (prev_r == 2 && !m) || (prev_r == 3 && m);
        if (prevent) {
            if (clip_blk)
                for (int x = x0; x < x1; x++)
                    dst[x] = 0;
            else
                for (int x = x0; x < x1; x++)
                    dst[x] = lc.main_col[x];
        } else if (clip_blk) {
            cm_line_clipped(&lc, dst, x0, x1, math_en, fixed_col, subtract, sub_scr_en);
        } else {
            cm_line_any(&lc, dst, x0, x1, math_en, fixed_col, subtract, half_math, sub_scr_en);
        }
        x0 = x1;
    }
    if (bright < 15u)
        for (int x = 0; x < SNES_W; x++) {
            u16 mc = dst[x];
            dst[x] = (u16)(blut[mc & 31u] | ((u16)blut[(mc >> 5) & 31u] << 5) | ((u16)blut[(mc >> 10) & 31u] << 10));
        }
}

/* =====================================================================
 * Frame Execution, Cartridge Loader & Public API
 * ===================================================================== */
static u16 map_snes_pad(u16 pad)
{
    u16 hw = 0;
    if (pad & SNES_PAD_B)      hw |= 0x8000u;
    if (pad & SNES_PAD_Y)      hw |= 0x4000u;
    if (pad & SNES_PAD_SELECT) hw |= 0x2000u;
    if (pad & SNES_PAD_START)  hw |= 0x1000u;
    if (pad & SNES_PAD_UP)     hw |= 0x0800u;
    if (pad & SNES_PAD_DOWN)   hw |= 0x0400u;
    if (pad & SNES_PAD_LEFT)   hw |= 0x0200u;
    if (pad & SNES_PAD_RIGHT)  hw |= 0x0100u;
    if (pad & SNES_PAD_A)      hw |= 0x0080u;
    if (pad & SNES_PAD_X)      hw |= 0x0040u;
    if (pad & SNES_PAD_L)      hw |= 0x0020u;
    if (pad & SNES_PAD_R)      hw |= 0x0010u;
    return hw;
}

void snes_frame(u16 pad, u16 *picture)
{
    S.joy1_hw = map_snes_pad(pad);
    if (S.joy_strobe)
        S.joy1_shift = S.joy1_hw;

    S.audio_count = 0;
    int total_lines = S.is_pal ? 312 : 262;
    int vblank_line = S.out_h + 1;          /* 225 (or 240 in overscan) */

    for (int line = 0; line < total_lines; line++) {
        S.cur_line = line;
        s32 line_start = line * 1364;
        s32 render_mc  = line_start + 1096;
        s32 line_end   = line_start + 1364;

        if (line == 0) {
            S.rdnmi = 0;
            run_hdma_init();
        } else if (line == vblank_line) {
            S.rdnmi = 0x80u;
            if (!(S.inidisp & 0x80u))
                S.oam_addr = (u16)((S.oamadd_reload << 1) & 0x3FFu);
            if (S.nmitimen & 0x80u)
                S.nmi_pending = 1;
            if (S.nmitimen & 0x01u)
                S.joy1_shift = S.joy1_hw;
        }

        /* Check H/V timer IRQ position on this scanline */
        int irq_mode = (S.nmitimen >> 4) & 3u;
        s32 irq_mc = -1;
        if (irq_mode == 1) {                /* H-IRQ every line at HTIME */
            if (S.htime < 341u)
                irq_mc = line_start + (s32)S.htime * 4;
        } else if (irq_mode == 2) {         /* V-IRQ at VTIME, H=0 */
            if (line == (int)S.vtime)
                irq_mc = line_start;
        } else if (irq_mode == 3) {         /* HV-IRQ at VTIME, HTIME */
            if (line == (int)S.vtime && S.htime < 341u)
                irq_mc = line_start + (s32)S.htime * 4;
        }

        if (irq_mc >= 0 && irq_mc < render_mc) {
            S.line_end_mc = irq_mc;
            while (S.master_cyc < irq_mc)
                cpu_step();
            S.timeup = 0x80u;
            S.irq_line = 1;
            irq_mc = -1;
        }

        S.line_end_mc = render_mc;
        while (S.master_cyc < render_mc)
            cpu_step();

        /* Render visible scanlines 1..out_h (SNES line 0 is pre-render!) */
        if (picture && line >= 1 && line <= S.out_h)
            render_snes_line(line - 1, picture + (line - 1) * SNES_W);

        if (line < vblank_line)
            run_hdma_scanline();

        if (irq_mc >= render_mc && irq_mc < line_end) {
            S.line_end_mc = irq_mc;
            while (S.master_cyc < irq_mc)
                cpu_step();
            S.timeup = 0x80u;
            S.irq_line = 1;
        }

        S.line_end_mc = line_end;
        while (S.master_cyc < line_end)
            cpu_step();
    }

    apu_catch_up();
    s32 frame_mc = total_lines * 1364;
    S.master_cyc -= frame_mc;
    S.apu_last_mc -= frame_mc;
}

static int score_snes_hdr(const u8 *rom, u32 size, u32 off, int want_map)
{
    if (off + 64u > size)
        return -100;
    const u8 *h = rom + off;
    u16 comp = (u16)(h[0x1C] | ((u16)h[0x1D] << 8));
    u16 csum = (u16)(h[0x1E] | ((u16)h[0x1F] << 8));
    u16 rst  = (u16)(h[0x3C] | ((u16)h[0x3D] << 8));
    if (rst < 0x8000u)
        return -50;
    int score = 0;
    if ((comp ^ csum) == 0xFFFFu && (comp != 0 || csum != 0))
        score += 6;
    u8 mode = h[0x15] & 0x0Fu;
    if (want_map == MAP_LOROM && (mode == 0 || mode == 2 || mode == 3)) score += 4;
    if (want_map == MAP_HIROM && (mode == 1 || mode == 0x0A))           score += 4;
    if (want_map == MAP_EXHIROM && mode == 5)                           score += 6;
    if (h[0x17] >= 0x07u && h[0x17] <= 0x0Du)
        score += 2;
    int ascii_ok = 0;
    for (int i = 0; i < 21; i++)
        if (h[i] >= 0x20u && h[i] <= 0x7Eu)
            ascii_ok++;
    if (ascii_ok >= 14)
        score += 2;
    u32 rst_off = (want_map == MAP_LOROM) ? (off - 0x7FC0u + (rst & 0x7FFFu))
                                          : (off - 0xFFC0u + rst);
    if (rst_off < size) {
        u8 op = rom[rst_off];
        if (op == 0x78u || op == 0x18u || op == 0x4Cu || op == 0x5Cu ||
            op == 0x80u || op == 0x9Cu || op == 0xA9u || op == 0xA2u || op == 0xEAu)
            score += 4;
    }
    return score;
}

static void fmt_snes_info(const u8 *hdr)
{
    char *p = info_buf;
    const char *mname = (S.mapper == MAP_EXHIROM) ? "ExHiROM" : (S.mapper == MAP_HIROM) ? "HiROM" : "LoROM";
    while (*mname) *p++ = *mname++;
    const char *reg = S.is_pal ? " PAL, \"" : " NTSC, \"";
    while (*reg) *p++ = *reg++;
    int end = 21;
    while (end > 0 && (hdr[end - 1] <= 0x20u || hdr[end - 1] >= 0x7Fu))
        end--;
    for (int i = 0; i < end; i++) {
        u8 ch = hdr[i];
        *p++ = (ch >= 0x20u && ch < 0x7Fu) ? (char)ch : ' ';
    }
    *p++ = '"';
    const char *sep = ", ";
    while (*sep) *p++ = *sep++;
    u32 kb = S.rom_size >> 10;
    char tmp[16]; int n = 0;
    do { tmp[n++] = (char)('0' + kb % 10); kb /= 10; } while (kb);
    while (n--) *p++ = tmp[n];
    const char *suf = " KB";
    while (*suf) *p++ = *suf++;
    *p = 0;
}

const char *snes_load(u8 *image, u32 size)
{
    if (!image || size < 0x8000u)
        return "too small for a Super Nintendo cartridge (at least 32 KB)";
    if (size >= 0x8200u && (size & 0x3FFu) == 0x200u) {
        image += 512;
        size -= 512u;
    }
    if (size > 0x800000u)
        return "too large for a Super Nintendo cartridge (over 8 MB)";

    int s_lo = score_snes_hdr(image, size, 0x007FC0u, MAP_LOROM);
    int s_hi = score_snes_hdr(image, size, 0x00FFC0u, MAP_HIROM);
    int s_ex = score_snes_hdr(image, size, 0x40FFC0u, MAP_EXHIROM);

    u32 hdr_off = 0x007FC0u;
    u8 mapper = MAP_LOROM;
    int best = s_lo;
    if (s_hi > best) { best = s_hi; hdr_off = 0x00FFC0u; mapper = MAP_HIROM; }
    if (s_ex > best) { best = s_ex; hdr_off = 0x40FFC0u; mapper = MAP_EXHIROM; }
    if (best < 0)
        return "not a valid Super Nintendo ROM (bad reset vector / header)";

    for (u32 i = 0; i < sizeof(*M); i++)
        ((u8 *)M)[i] = 0;
    for (u32 v = 0; v < 256u; v++) {
        u32 fw = 0, rv = 0;
        for (int k = 0; k < 8; k++) {
            if (v & (1u << (7 - k))) fw |= (1u << (k * 4));
            if (v & (1u << k))       rv |= (1u << (k * 4));
        }
        M->bp_lut[v] = fw;
        M->bp_lut_flip[v] = rv;
    }
    for (u32 b = 0; b < 16u; b++)
        for (u32 c = 0; c < 32u; c++)
            M->bright_lut[b][c] = (u8)((c * b + 7u) / 15u);

    for (u32 i = 0; i < sizeof(S); i++)
        ((u8 *)&S)[i] = 0;
    s_hdmaen = 0;

    const u8 *hdr = image + hdr_off;
    S.rom = image;
    S.rom_size = size;
    S.mapper = mapper;
    S.fastrom = (hdr[0x15] & 0x10u) != 0;
    u8 country = hdr[0x19];
    S.is_pal = (country >= 0x02u && country <= 0x0Cu) || country == 0x11u;

    u8 ram_code = hdr[0x18];
    if (ram_code >= 1u && ram_code <= 12u) {
        u32 sz = 1024u << (ram_code > 7u ? 7u : ram_code);
        S.sram_size = sz;
        S.sram_mask = sz - 1u;
    }

    /* cartridge types 03h..05h have a DSP: the DSP-1, but for the three games with a DSP-2, -3 or -4 (not
       emulated: their registers stay open bus, as every DSP's did before) */
    if (hdr[0x16] >= 0x03u && hdr[0x16] <= 0x05u && (hdr[0x15] & 0x0Eu) == 0u) {
        static const char *const other[] = { "DUNGEON MASTER", "SD GUNDAM GX", "TOP GEAR 3000", "PLANETS CHAMP TG3000" };
        int is_other = 0;
        for (u32 k = 0; k < sizeof(other) / sizeof(other[0]); k++) {
            const char *t = other[k];
            u32 i = 0;
            while (t[i] && hdr[i] == (u8)t[i])
                i++;
            if (!t[i])
                is_other = 1;
        }
        if (!is_other) {
            D1.map = (u8)(mapper == MAP_HIROM ? 1u : size > 0x100000u ? 3u : 2u);
            d1_reset();
        }
    }

    build_page_tables();
    snes_reset();
    fmt_snes_info(hdr);
    return 0;
}

void snes_reset(void)
{
    for (u32 i = 0; i < sizeof(M->wram); i++) M->wram[i] = 0x55u;
    for (u32 i = 0; i < sizeof(M->vram); i++) M->vram[i] = 0;
    for (u32 i = 0; i < 256u; i++) M->cgram[i] = 0;
    for (u32 i = 0; i < sizeof(M->oam); i++) M->oam[i] = 0;
    S.oam_dirty = 1;
    for (u32 i = 0; i < sizeof(M->apuram); i++) M->apuram[i] = 0;
    for (u32 i = 0; i < 4096u; i++) M->vram_dirty2[i] = 1;
    for (u32 i = 0; i < 2048u; i++) M->vram_dirty4[i] = 1;
    for (u32 i = 0; i < 1024u; i++) M->vram_dirty8[i] = 1;

    S.c = S.x = S.y = S.d = 0;
    S.s = 0x01FFu;
    S.pbr = S.dbr = 0;
    S.e = 1;
    S.p = (u8)(FM | FX | FI);
    S.pc = cpu_rd16_bank(0, 0xFFFCu);
    S.stopped = S.waiting = S.irq_line = S.nmi_pending = 0;
    S.master_cyc = 0;
    S.inidisp = 0x80u;
    S.wrio = 0xFFu;
    S.htime = 0x01FFu;
    S.vtime = 0x01FFu;
    S.out_h = SNES_H_DEF;
    s_hdmaen = 0;

    /* Reset SPC700 into IPL ROM at $FFC0 */
    S.spc_pc = 0xFFC0u;
    S.spc_a = S.spc_x = S.spc_y = 0;
    S.spc_sp = 0xEFu;
    S.spc_psw = SP_Z;
    S.spc_ctrl = 0x80u;
    S.spc_stopped = 0;
    for (int i = 0; i < 4; i++)
        S.cpu_to_apu[i] = S.apu_to_cpu[i] = 0;
    for (int i = 0; i < 128; i++)
        S.dsp[i] = 0;
    S.dsp[0x6C] = 0xE0u;
    S.noise_val = -0x4000;
    S.apu_last_mc = 0;
    S.spc_cyc_avail = 0;
    S.apu_mc_rem = 0;
    S.dsp_spc_acc = 0;
}

int snes_width(void)   { return SNES_W; }
int snes_height(void)  { return S.out_h; }
int snes_pal(void)     { return S.is_pal; }
const char *snes_info(void) { return info_buf; }

u8 *snes_save_ram(u32 *size, int *battery)
{
    *size = S.sram_size ? S.sram_size : 2048u;
    *battery = S.sram_size != 0;
    return M->sram;
}

int snes_save_changed(void)
{
    int d = S.sram_dirty;
    S.sram_dirty = 0;
    return d;
}

int snes_jammed(void)
{
    return S.stopped;
}

void snes_audio_rate(u32 hz)
{
    S.sample_rate = hz;
    S.resamp_acc = 0;
    S.audio_count = 0;
}

int snes_audio(s16 *out, int max)
{
    int n = S.audio_count < max ? S.audio_count : max;
    for (int i = 0; i < n; i++)
        out[i] = M->audio_ring[i];
    S.audio_count = 0;
    return n;
}
