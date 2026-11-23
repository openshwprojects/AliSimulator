/* NEC PC Engine / TurboGrafx-16 ('pce'), SuperGrafx ('sgx'), and
   PC Engine CD-ROM2 / Super CD-ROM2 / Arcade Card ('pcecd'): see pce.h. */
#pragma GCC optimize("O2")
#include "pce.h"
#ifndef PCE_HOST
#include "hw.h"
#endif

typedef signed char s8;

#define FC 0x01
#define FZ 0x02
#define FI 0x04
#define FD 0x08
#define FB 0x10
#define FT 0x20
#define FV 0x40
#define FN 0x80

#define LINE_CYC   455u                 /* 1365 master clocks / 3 = 455 CPU clocks at 7.15909 MHz */
#define LINES_DEF  263u                 /* 263 lines (262 when VCE bit 2 is clear) */

/* SuperGrafx VPC pixel flags in 16-bit intermediate linebuffers */
#define SGX_PIX_MASK   0x01FFu
#define SGX_TRANSP     0x0200u
#define SGX_SPRITE     0x0800u

/* SCSI CD-ROM phases */
enum {
    SCSI_BUS_FREE = 0,
    SCSI_COMMAND  = 1,
    SCSI_DATA_IN  = 2,
    SCSI_STATUS   = 3,
    SCSI_MSG_IN   = 4
};

#define SCSI_SIG_IO   0x08u
#define SCSI_SIG_CD   0x10u
#define SCSI_SIG_MSG  0x20u
#define SCSI_SIG_REQ  0x40u
#define SCSI_SIG_BSY  0x80u

/* $1803 CD/ADPCM interrupt status bits (masked by $1802 -> IRQ2) */
#define CDIRQ_ADPCM_HALF 0x04u
#define CDIRQ_ADPCM_END  0x08u
#define CDIRQ_SUBQ       0x10u
#define CDIRQ_DONE       0x20u
#define CDIRQ_DRQ        0x40u

enum {
    CDDA_PAUSED  = -1,
    CDDA_STOPPED = 0,
    CDDA_PLAYING = 1
};

enum {
    PLAYMODE_SILENT = 0,
    PLAYMODE_LOOP   = 1,
    PLAYMODE_IRQ    = 2,
    PLAYMODE_NORMAL = 3
};

struct pce_psg_ch {
    u16 freq;
    u8 ctrl, balance, wave[32], wave_idx, dda;
    u8 noise_ctrl;
    u32 phase, noise_phase, lfsr;
    s32 noise_out;
};

struct pce_vdc {
    u8  reg, status, latch_lo;
    u8  byr_latched, satb_dirty, burst_mode, sat_dma_slcounter;
    u16 regs[20], vram_rbuf, bg_y;
    u16 display_counter, rcr_count;
};

struct pce_ac_port {
    u32 base;
    u16 offset;
    u16 increment;
    u8  control;
};

struct pce_state {
    u8 a, x, y, s, p;
    u16 pc;
    u8 mpr[8], mpr_latch;
    u8 speed;                           /* 1 = 7.16 MHz (CSH), 4 = 1.79 MHz (CSL; reset state) */
    u8 irq_mask, irq_lines;             /* bit 0: IRQ2 (CD), bit 1: IRQ1 (VDC), bit 2: TIQ (timer) */
    u8 jammed, io_buf;
    u8 sgx_mode, cd_mode, ext_bios;
    u32 cycles;
    s32 cyc_debt;

    /* Timer: 7-bit counter clocked every 1024 7.16 MHz cycles */
    u8 tmr_reload, tmr_cnt, tmr_on;
    s32 tmr_prescale;

    /* Dual HuC6270 VDCs + HuC6202 VPC + HuC6260 VCE */
    struct pce_vdc vdc[2];
    u16 frame_counter;
    u16 lat_vds, lat_vsw, lat_vdw, lat_vcr, vblank_fl;
    u8  vpc_prio[2];
    u16 vpc_win[2];
    u8  vpc_st_mode;
    u8  vce_ctrl;
    u16 vce_addr;

    /* Joypad & BRAM */
    u16 pad_state;
    u8 joy_sel, joy_clr, joy_six_toggle;
    u8 bram_unlocked, bram_dirty;

    /* Cartridge / Memory map */
    u8 *rom;
    u32 rom_size, rom_pages, rom_p2;
    u8 sf2_bank, sf2_mapper, populous_ram, us_region;
    const u8 *page_r[256];
    u8 *page_w[256];
    const u8 *mpr_r[8];                 /* direct fast-path pointers for MPR0..7 (0 = I/O, BRAM, or AC port) */
    u8 *mpr_w[8];

    /* Frame geometry */
    int out_w, out_h;

    /* PSG */
    u8 psg_sel, psg_vol, lfo_freq, lfo_ctrl;
    struct pce_psg_ch psg[6];
    u32 sample_rate, audio_cyc_last, audio_frac;
    int audio_count;

    /* PC Engine CD-ROM2 & SCSI state */
    const struct cdrom_toc *cd;
    u32 cd_data_base;
    u8  cd_port[16];
    u8  scsi_phase;
    u8  scsi_signals;
    u8  scsi_db;
    u8  scsi_ack, scsi_rst;
    u8  scsi_cmd[16];
    u8  scsi_cmd_pos;
    u8  scsi_msg_pending, scsi_status_sent, scsi_msg_sent, scsi_xfer_done;
    u8  sense_key, sense_asc, sense_ascq;
    u32 scsi_lba, scsi_sec_left;
    s32 scsi_read_timer;
    u32 din_r, din_count;
    u8  subq_last[12];
    u8  subq_fifo[16];
    u8  subq_r, subq_count;

    /* Redbook CD-DA playback */
    s8  cdda_status;
    u8  cdda_mode;
    u32 cdda_start_lba, cdda_lba, cdda_end_lba;
    u32 cdda_pos;                       /* 0..588 stereo frames in cdda_sec */
    u32 cdda_phase;                     /* 44100 -> sample_rate resampler */
    s16 cdda_last_l, cdda_last_r;

    /* OKI MSM5205 12-bit ADPCM + Fader */
    u16 adpcm_addr, adpcm_raddr, adpcm_waddr, adpcm_len;
    u8  adpcm_half, adpcm_end, adpcm_playing;
    u8  adpcm_cmd, adpcm_freq, adpcm_pbuf, adpcm_rbuf, adpcm_nibble;
    s32 adpcm_sample, adpcm_ssi, adpcm_cur_pcm;
    u32 adpcm_phase;                    /* adpcm_fs -> sample_rate resampler */
    u8  fader_cmd, fader_clocked;
    s32 fader_vol, fader_cnt, fader_reload;
    s32 adpcm_fade_vol, cdda_fade_vol;

    /* Arcade Card Pro / Duo */
    struct pce_ac_port ac_ports[4];
    u32 ac_shift_latch;
    u8  ac_shift_bits, ac_rotate_bits;

    char info_buf[96];
};

struct pce_mem {
    struct pce_state st;
    u8  wram[0x8000];                   /* 8 KB on PCE/PCE-CD ($F8), 32 KB on SuperGrafx ($F8..$FB) */
    u8  bram[0x800];                    /* 2 KB backup RAM at $F7 (unlocked by $1807 = 0x80) */
    u8  pad_ram[0x2000];                /* scratch page for unmapped writes */
    u8  ff_page[0x2000];                /* 0xFF open-bus page */
    u16 vram[2][0x8000];                /* 2 x 32K words (64 KB on PCE, 128 KB on SuperGrafx) */
    u16 satb[2][256];                   /* 2 x 64 sprites x 4 words */
    u16 sgx_lb[2][PCE_W_MAX];           /* SuperGrafx per-VDC scanline buffers */
    u16 vce_raw[512];                   /* 9-bit GRB */
    u16 vce_pal[512];                   /* 15-bit 0bbbbbgggggrrrrr */
    u32 spread8[256], spread8_rev[256]; /* bitplane byte -> 8 x 4-bit nibbles (normal and X-flipped) */
    s16 audio_ring[4096];
    u8  din_buf[4096];                  /* SCSI Data-In sector FIFO */
    u8  cdda_sec[2352];                 /* Current Redbook CD-DA sector */
    u8  adpcm_ram[0x10000];             /* 64 KB OKI MSM5205 ADPCM RAM */
    u8  cd_bios[0x40000];               /* 256 KB System Card 3.0 BIOS ($00..$1F) */
    u8  cd_ram[0x40000];                /* 256 KB Super System Card + CD-ROM2 RAM ($68..$87) */
    u8  ac_ram[0x200000];               /* 2 MB Arcade Card RAM ($40..$43 / $1A00..$1A7F) */
};

#ifdef PCE_HOST
static struct pce_mem pce_mem_buf;
#define M (&pce_mem_buf)
#ifdef PCE_CPU_TEST
u8 pce_sst_ram[0x200000];
#endif
#else
#define M ((struct pce_mem *)KSEG0(EMU_RAM_PHYS))
_Static_assert(sizeof(struct pce_mem) <= EMU_RAM_SIZE, "pce_mem exceeds EMU_RAM_SIZE");
#endif

#define S (M->st)

/* 30-step 1.5 dB attenuation LUT for PSG (0 = silence, 31 = max) */
static const u16 psg_vol_tab[32] = {
    0,   18,   21,   25,   30,   35,   42,   50,
   59,   70,   83,   99,  118,  140,  166,  198,
  235,  279,  332,  395,  469,  558,  663,  789,
  937, 1115, 1325, 1575, 1873, 2227, 2648, 3150
};

/* OKI MSM5205 ADPCM step sizes & index deltas */
static const u16 oki_steps[49] = {
    16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50,
    55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143, 157,
    173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449,
    494, 544, 598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552
};

static const s8 oki_idx_delta[16] = {
    -1, -1, -1, -1, 2, 4, 6, 8,
    -1, -1, -1, -1, 2, 4, 6, 8
};

#ifndef PCE_CPU_TEST
/* Clean-room 8x8 ASCII font (32..95) for System Card ex_getfnt ($E060) */
static const u8 pce_bios_font64[64 * 8] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x18,0x18,0x18,0x18,0x18,0x00,0x18,0x00,
    0x6C,0x6C,0x24,0x00,0x00,0x00,0x00,0x00, 0x6C,0xFE,0x6C,0x6C,0xFE,0x6C,0x00,0x00,
    0x18,0x3E,0x60,0x3C,0x06,0x7C,0x18,0x00, 0x62,0x66,0x0C,0x18,0x30,0x66,0x46,0x00,
    0x38,0x6C,0x38,0x76,0xDC,0xCC,0x76,0x00, 0x18,0x18,0x30,0x00,0x00,0x00,0x00,0x00,
    0x0C,0x18,0x30,0x30,0x30,0x18,0x0C,0x00, 0x30,0x18,0x0C,0x0C,0x0C,0x18,0x30,0x00,
    0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00, 0x00,0x18,0x18,0x7E,0x18,0x18,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x30, 0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00, 0x06,0x0C,0x18,0x30,0x60,0xC0,0x80,0x00,
    0x3C,0x66,0x6E,0x76,0x66,0x66,0x3C,0x00, 0x18,0x38,0x18,0x18,0x18,0x18,0x7E,0x00,
    0x3C,0x66,0x06,0x1C,0x30,0x66,0x7E,0x00, 0x3C,0x66,0x06,0x1C,0x06,0x66,0x3C,0x00,
    0x0C,0x1C,0x3C,0x6C,0x7E,0x0C,0x0C,0x00, 0x7E,0x60,0x7C,0x06,0x06,0x66,0x3C,0x00,
    0x3C,0x60,0x7C,0x66,0x66,0x66,0x3C,0x00, 0x7E,0x66,0x06,0x0C,0x18,0x18,0x18,0x00,
    0x3C,0x66,0x66,0x3C,0x66,0x66,0x3C,0x00, 0x3C,0x66,0x66,0x3E,0x06,0x0C,0x38,0x00,
    0x00,0x18,0x18,0x00,0x18,0x18,0x00,0x00, 0x00,0x18,0x18,0x00,0x18,0x18,0x30,0x00,
    0x0C,0x18,0x30,0x60,0x30,0x18,0x0C,0x00, 0x00,0x00,0x7E,0x00,0x7E,0x00,0x00,0x00,
    0x30,0x18,0x0C,0x06,0x0C,0x18,0x30,0x00, 0x3C,0x66,0x06,0x0C,0x18,0x00,0x18,0x00,
    0x3C,0x66,0x6E,0x6E,0x60,0x62,0x3C,0x00, 0x18,0x3C,0x66,0x66,0x7E,0x66,0x66,0x00,
    0x7C,0x66,0x66,0x7C,0x66,0x66,0x7C,0x00, 0x3C,0x66,0x60,0x60,0x60,0x66,0x3C,0x00,
    0x78,0x6C,0x66,0x66,0x66,0x6C,0x78,0x00, 0x7E,0x60,0x60,0x78,0x60,0x60,0x7E,0x00,
    0x7E,0x60,0x60,0x78,0x60,0x60,0x60,0x00, 0x3C,0x66,0x60,0x6E,0x66,0x66,0x3E,0x00,
    0x66,0x66,0x66,0x7E,0x66,0x66,0x66,0x00, 0x3C,0x18,0x18,0x18,0x18,0x18,0x3C,0x00,
    0x1E,0x0C,0x0C,0x0C,0x6C,0x6C,0x38,0x00, 0x66,0x6C,0x78,0x70,0x78,0x6C,0x66,0x00,
    0x60,0x60,0x60,0x60,0x60,0x60,0x7E,0x00, 0x63,0x77,0x7F,0x6B,0x63,0x63,0x63,0x00,
    0x66,0x76,0x7E,0x7E,0x6E,0x66,0x66,0x00, 0x3C,0x66,0x66,0x66,0x66,0x66,0x3C,0x00,
    0x7C,0x66,0x66,0x7C,0x60,0x60,0x60,0x00, 0x3C,0x66,0x66,0x66,0x6A,0x6C,0x36,0x00,
    0x7C,0x66,0x66,0x7C,0x6C,0x66,0x66,0x00, 0x3C,0x66,0x60,0x3C,0x06,0x66,0x3C,0x00,
    0x7E,0x18,0x18,0x18,0x18,0x18,0x18,0x00, 0x66,0x66,0x66,0x66,0x66,0x66,0x3C,0x00,
    0x66,0x66,0x66,0x66,0x66,0x3C,0x18,0x00, 0x63,0x63,0x63,0x6B,0x7F,0x77,0x63,0x00,
    0x66,0x66,0x3C,0x18,0x3C,0x66,0x66,0x00, 0x66,0x66,0x66,0x3C,0x18,0x18,0x18,0x00,
    0x7E,0x06,0x0C,0x18,0x30,0x60,0x7E,0x00, 0x3C,0x30,0x30,0x30,0x30,0x30,0x3C,0x00,
    0xC0,0x60,0x30,0x18,0x0C,0x06,0x02,0x00, 0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0x00,
    0x18,0x3C,0x66,0x00,0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00
};
#endif

static u16 grb9_to_bgr15(u16 c)
{
    u32 b = c & 7u, r = (c >> 3) & 7u, g = (c >> 6) & 7u;
    u32 r5 = (r << 2) | (r >> 1);
    u32 g5 = (g << 2) | (g >> 1);
    u32 b5 = (b << 2) | (b >> 1);
    return (u16)((b5 << 10) | (g5 << 5) | r5);
}

static inline u8 u8_to_bcd(u32 v)
{
    v %= 100u;
    return (u8)(((v / 10u) << 4) | (v % 10u));
}

static inline u32 bcd_to_u8(u8 b)
{
    return (u32)((b >> 4) * 10u + (b & 0x0Fu));
}

static inline void lba_to_amsf(u32 lba, u8 *m, u8 *s, u8 *f)
{
    u32 tot = lba + 150u;
    *m = (u8)(tot / 4500u);
    *s = (u8)((tot / 75u) % 60u);
    *f = (u8)(tot % 75u);
}

static inline u32 amsf_to_lba(u32 m, u32 s, u32 f)
{
    u32 tot = (m * 60u + s) * 75u + f;
    return tot >= 150u ? (tot - 150u) : 0u;
}

static void sync_mpr(int i)
{
    u8 p = S.mpr[i];
    if (p == 0xFF || p == 0xF7 || (S.cd_mode && p >= 0x40 && p <= 0x43)) {
        S.mpr_r[i] = 0;
        S.mpr_w[i] = 0;
    } else {
        S.mpr_r[i] = S.page_r[p];
        S.mpr_w[i] = S.page_w[p];
    }
}

static void rebuild_pages(void)
{
    for (int p = 0; p < 256; p++) {
        S.page_r[p] = M->ff_page;
        S.page_w[p] = 0;
    }

    if (S.cd_mode) {
        /* $00..$1F (256 KB): System Card 3.0 BIOS ROM */
        for (u32 p = 0; p < 0x20u; p++)
            S.page_r[p] = M->cd_bios + p * 0x2000u;
        /* $68..$87 (256 KB): Super System Card RAM ($68..$7F) + CD-ROM2 RAM ($80..$87) */
        for (u32 p = 0x68u; p <= 0x87u; p++) {
            u8 *ram = M->cd_ram + (p - 0x68u) * 0x2000u;
            S.page_r[p] = ram;
            S.page_w[p] = ram;
        }
    } else if (S.rom && S.rom_pages) {
        for (u32 p = 0; p < 0x80u; p++) {
            u32 idx;
            if (S.sf2_mapper) {
                if (p < 0x40u)
                    idx = p % S.rom_pages;
                else
                    idx = (0x40u + (u32)S.sf2_bank * 0x40u + (p - 0x40u)) % S.rom_pages;
            } else if (S.populous_ram && p >= 0x40u && p < 0x44u) {
                S.page_r[p] = M->wram + 0x2000u + (p - 0x40u) * 0x2000u;
                S.page_w[p] = M->wram + 0x2000u + (p - 0x40u) * 0x2000u;
                continue;
            } else if (S.rom_pages <= 0x40u) {
                if (p < 0x40u || S.rom_pages == S.rom_p2)
                    idx = p % S.rom_p2;
                else
                    idx = S.rom_p2 + ((p - 0x40u) % (S.rom_pages - S.rom_p2));
            } else {
                if (p < 0x40u)
                    idx = p;
                else
                    idx = 0x40u + ((p - 0x40u) % (S.rom_pages - 0x40u));
            }
            S.page_r[p] = S.rom + idx * 0x2000u;
        }
    }

    if (S.sgx_mode) {
        /* SuperGrafx: 32 KB WRAM across $F8..$FB */
        for (u32 i = 0; i < 4u; i++) {
            S.page_r[0xF8u + i] = M->wram + i * 0x2000u;
            S.page_w[0xF8u + i] = M->wram + i * 0x2000u;
        }
    } else {
        S.page_r[0xF8] = M->wram;
        S.page_w[0xF8] = M->wram;
    }

    for (int i = 0; i < 8; i++)
        sync_mpr(i);
}

/* ========================================================================
 * OKI MSM5205 ADPCM + Redbook CD-DA + 6-Channel PSG Audio @ 48 kHz
 * ======================================================================== */

static s32 oki_decode_nibble(u8 nib)
{
    u32 step = oki_steps[S.adpcm_ssi];
    u32 mag = ((step >> 3) +
               ((nib & 1u) ? (step >> 2) : 0u) +
               ((nib & 2u) ? (step >> 1) : 0u) +
               ((nib & 4u) ? step : 0u));
    s32 delta = (nib & 8u) ? -(s32)mag : (s32)mag;
    S.adpcm_sample += delta;
    if (S.adpcm_sample > 2047)  S.adpcm_sample = 2047;
    if (S.adpcm_sample < -2048) S.adpcm_sample = -2048;

    S.adpcm_ssi += oki_idx_delta[nib & 0x0Fu];
    if (S.adpcm_ssi < 0)  S.adpcm_ssi = 0;
    if (S.adpcm_ssi > 48) S.adpcm_ssi = 48;
    return S.adpcm_sample;
}

static void pcecd_update_irq(void)
{
    S.cd_port[3] &= (u8)~(CDIRQ_ADPCM_HALF | CDIRQ_ADPCM_END);
    if (S.adpcm_half) S.cd_port[3] |= CDIRQ_ADPCM_HALF;
    if (S.adpcm_end)  S.cd_port[3] |= CDIRQ_ADPCM_END;

    u8 irq = S.cd_port[2] & S.cd_port[3] & 0x7Cu;
    if (irq)
        S.irq_lines |= 0x01u;           /* IRQ2 */
    else
        S.irq_lines &= (u8)~0x01u;
}

static void pcecd_sync_fader(void)
{
    if (S.fader_cmd & 2u) {
        S.adpcm_fade_vol = S.fader_vol >> 6;    /* 0..1024 */
        S.cdda_fade_vol  = 1024;
    } else {
        S.cdda_fade_vol  = S.fader_vol >> 6;    /* 0..1024 */
        S.adpcm_fade_vol = 1024;
    }
}

static void pcecd_update_subq(u32 lba)
{
    if (!S.cd)
        return;
    int trk = 1;
    for (int t = 1; t <= (int)S.cd->last_track; t++) {
        if (lba >= S.cd->tracks[t].lba)
            trk = t;
    }
    u32 rel_lba = lba >= S.cd->tracks[trk].lba ? (lba - S.cd->tracks[trk].lba) : 0u;
    u8 rm, rs, rf, am, as, af;
    lba_to_amsf(rel_lba >= 150u ? rel_lba - 150u : 0u, &rm, &rs, &rf);
    if (rel_lba < 150u) {
        rm = 0;
        rs = (u8)(rel_lba / 75u);
        rf = (u8)(rel_lba % 75u);
    }
    lba_to_amsf(lba, &am, &as, &af);
    S.subq_last[0] = S.cd->tracks[trk].control;
    S.subq_last[1] = u8_to_bcd((u32)trk);
    S.subq_last[2] = 0x01;
    S.subq_last[3] = u8_to_bcd(rm);
    S.subq_last[4] = u8_to_bcd(rs);
    S.subq_last[5] = u8_to_bcd(rf);
    S.subq_last[7] = u8_to_bcd(am);
    S.subq_last[8] = u8_to_bcd(as);
    S.subq_last[9] = u8_to_bcd(af);
}

static s32 pcecd_step_audio_sample(u32 sr)
{
    s32 mix = 0;

    /* 1. OKI MSM5205 ADPCM: fs = 32088 / (16 - freq) Hz */
    if (S.adpcm_playing) {
        u32 div = 16u - (S.adpcm_freq & 0x0Fu);
        u32 ad_fs = 32088u / div;
        S.adpcm_phase += ad_fs;
        while (S.adpcm_phase >= sr) {
            S.adpcm_phase -= sr;
            if (!S.adpcm_nibble) {
                S.adpcm_half = (S.adpcm_len < 32768u);
                if (!S.adpcm_len && !(S.adpcm_cmd & 0x10u)) {
                    if (S.adpcm_end)
                        S.adpcm_half = 0;
                    S.adpcm_end = 1;
                    if (S.adpcm_cmd & 0x40u)
                        S.adpcm_playing = 0;
                    pcecd_update_irq();
                }
                S.adpcm_pbuf = M->adpcm_ram[S.adpcm_raddr];
                S.adpcm_raddr = (u16)(S.adpcm_raddr + 1u);
                if (S.adpcm_len && !(S.adpcm_cmd & 0x10u))
                    S.adpcm_len--;
            }
            if (S.adpcm_playing) {
                u8 nib = (S.adpcm_pbuf >> (S.adpcm_nibble ^ 4u)) & 0x0Fu;
                S.adpcm_nibble ^= 4u;
                S.adpcm_cur_pcm = (oki_decode_nibble(nib) * S.adpcm_fade_vol) >> 7;
            }
        }
        mix += S.adpcm_cur_pcm;
    }

    /* 2. Redbook CD-DA: 44100 Hz 16-bit LE stereo */
    if (S.cdda_status == CDDA_PLAYING && S.cd && S.cd->read_2352) {
        S.cdda_phase += 44100u;
        while (S.cdda_phase >= sr) {
            S.cdda_phase -= sr;
            if (S.cdda_pos >= 588u) {
                if (S.cdda_lba >= S.cdda_end_lba || S.cdda_lba >= S.cd->total_lba) {
                    if (S.cdda_mode == PLAYMODE_LOOP) {
                        S.cdda_lba = S.cdda_start_lba;
                    } else {
                        S.cdda_status = CDDA_STOPPED;
                        if (S.cdda_mode == PLAYMODE_IRQ) {
                            S.cd_port[3] |= CDIRQ_DONE;
                            pcecd_update_irq();
                        }
                        S.cdda_last_l = S.cdda_last_r = 0;
                        break;
                    }
                }
                if (S.cd->read_2352(S.cdda_lba, M->cdda_sec) < 0) {
                    S.cdda_status = CDDA_STOPPED;
                    break;
                }
                pcecd_update_subq(S.cdda_lba);
                S.cdda_lba++;
                S.cdda_pos = 0;
            }
            if (!(S.subq_last[0] & 0x04u) && S.cdda_mode != PLAYMODE_SILENT) {
                const u8 *sp = &M->cdda_sec[S.cdda_pos * 4u];
                s16 sl = (s16)((u16)sp[0] | ((u16)sp[1] << 8));
                s16 sr_ch = (s16)((u16)sp[2] | ((u16)sp[3] << 8));
                S.cdda_last_l = (s16)(((s32)sl * S.cdda_fade_vol) >> 10);
                S.cdda_last_r = (s16)(((s32)sr_ch * S.cdda_fade_vol) >> 10);
            } else {
                S.cdda_last_l = S.cdda_last_r = 0;
            }
            S.cdda_pos++;
        }
        mix += ((s32)S.cdda_last_l + (s32)S.cdda_last_r) >> 2;
    }

    return mix;
}

static void psg_step_samples(u32 cyc_7m)
{
    if (!S.sample_rate || !cyc_7m)
        return;
    u32 count = 0;
    while (cyc_7m) {
        u32 chunk = cyc_7m > 8000u ? 8000u : cyc_7m;
        cyc_7m -= chunk;
        u32 num = chunk * S.sample_rate + S.audio_frac;
        count += num / 7159090u;
        S.audio_frac = num % 7159090u;
    }
    if (!count)
        return;

    u32 psg_step = 916363520u / S.sample_rate;
    int lm = (S.psg_vol >> 4) & 0x0F, rm = S.psg_vol & 0x0F;

    while (count--) {
        s32 mix_l = 0, mix_r = 0;
        for (int ch = 0; ch < 6; ch++) {
            struct pce_psg_ch *c = &S.psg[ch];
            if (!(c->ctrl & 0x80))
                continue;
            if (ch == 1 && (S.lfo_ctrl & 0x80))
                continue;
            int sample5;
            if ((c->ctrl & 0xC0) == 0xC0) {
                sample5 = c->dda & 0x1F;
            } else if (ch >= 4 && (c->noise_ctrl & 0x80)) {
                u32 nf = (c->noise_ctrl & 0x1F) ^ 0x1F;
                u32 nperiod = (nf ? nf * 64u : 32u) << 8;
                c->noise_phase += psg_step;
                while (c->noise_phase >= nperiod) {
                    c->noise_phase -= nperiod;
                    u32 bit = ((c->lfsr >> 0) ^ (c->lfsr >> 1) ^ (c->lfsr >> 11) ^ (c->lfsr >> 12) ^ (c->lfsr >> 17)) & 1u;
                    c->lfsr = (c->lfsr >> 1) | (bit << 17);
                    c->noise_out = (c->lfsr & 1u) ? 31 : 0;
                }
                sample5 = c->noise_out;
            } else {
                u32 period = c->freq ? c->freq : 4096u;
                if (ch == 0 && (S.lfo_ctrl & 0x03) && !(S.lfo_ctrl & 0x80)) {
                    struct pce_psg_ch *m = &S.psg[1];
                    u32 mp = (m->freq ? m->freq : 4096u) * (S.lfo_freq ? S.lfo_freq : 256u);
                    if (mp) {
                        m->phase += psg_step;
                        u32 mp8 = mp << 8;
                        while (m->phase >= mp8) {
                            m->phase -= mp8;
                            m->wave_idx = (m->wave_idx + 1) & 31;
                        }
                        s32 mod = (s32)(m->wave[m->wave_idx] & 0x1F) - 16;
                        int shift = ((S.lfo_ctrl & 3) - 1) * 2;
                        s32 adj = (s32)period + (mod << shift);
                        period = adj < 1 ? 1u : adj > 4095 ? 4095u : (u32)adj;
                    }
                }
                u32 p8 = period << 8;
                c->phase += psg_step;
                while (c->phase >= p8) {
                    c->phase -= p8;
                    c->wave_idx = (c->wave_idx + 1) & 31;
                }
                sample5 = c->wave[c->wave_idx] & 0x1F;
            }
            int cv = c->ctrl & 0x1F;
            int lv = cv + ((c->balance >> 4) & 0x0F) + lm - 30;
            int rv = cv + (c->balance & 0x0F) + rm - 30;
            s32 centered = sample5 - 15;
            if (lv > 0)
                mix_l += centered * (s32)psg_vol_tab[lv > 31 ? 31 : lv];
            if (rv > 0)
                mix_r += centered * (s32)psg_vol_tab[rv > 31 ? 31 : rv];
        }
        s32 mono = (mix_l + mix_r) >> 4;
        if (S.cd_mode)
            mono += pcecd_step_audio_sample(S.sample_rate);
        if (mono > 32767) mono = 32767;
        if (mono < -32768) mono = -32768;
        if (S.audio_count < 4096)
            M->audio_ring[S.audio_count++] = (s16)mono;
    }
}

static void psg_catch_up(void)
{
    if (!S.sample_rate)
        return;
    u32 delta = S.cycles - S.audio_cyc_last;
    S.audio_cyc_last = S.cycles;
    if (delta)
        psg_step_samples(delta);
}

/* ========================================================================
 * NEC SCSI CD-ROM2 Drive & Arcade Card Hardware ($1800..$1AFF)
 * ======================================================================== */

static const u8 scsi_cdb_len[16] = {
    6, 6, 10, 10, 10, 10, 10, 10, 10, 10, 12, 12, 10, 10, 10, 10
};

static void scsi_set_phase(u8 ph)
{
    S.scsi_phase = ph;
    switch (ph) {
    case SCSI_BUS_FREE:
        S.scsi_signals = 0;
        S.cd_port[3] &= (u8)~CDIRQ_DONE;
        pcecd_update_irq();
        break;
    case SCSI_COMMAND:
        S.scsi_signals = SCSI_SIG_BSY | SCSI_SIG_CD | SCSI_SIG_REQ;
        break;
    case SCSI_DATA_IN:
        S.scsi_signals = SCSI_SIG_BSY | SCSI_SIG_IO;
        break;
    case SCSI_STATUS:
        S.scsi_signals = SCSI_SIG_BSY | SCSI_SIG_CD | SCSI_SIG_IO | SCSI_SIG_REQ;
        break;
    case SCSI_MSG_IN:
        S.scsi_signals = SCSI_SIG_BSY | SCSI_SIG_MSG | SCSI_SIG_CD | SCSI_SIG_IO | SCSI_SIG_REQ;
        break;
    }
}

static void scsi_send_status(u8 st, u8 msg)
{
    S.din_r = S.din_count = 0;
    S.scsi_msg_pending = msg;
    S.scsi_status_sent = 0;
    S.scsi_msg_sent = 0;
    S.scsi_db = st ? 0x01u : 0x00u;
    scsi_set_phase(SCSI_STATUS);
}

static void scsi_send_data(const u8 *buf, u32 len)
{
    if (len > sizeof(M->din_buf))
        len = sizeof(M->din_buf);
    for (u32 i = 0; i < len; i++)
        M->din_buf[i] = buf[i];
    S.din_r = 0;
    S.din_count = len;
    S.scsi_xfer_done = 1;
    scsi_set_phase(SCSI_DATA_IN);
    if (len > 0) {
        S.scsi_db = M->din_buf[S.din_r++];
        S.din_count--;
        S.scsi_signals |= SCSI_SIG_REQ;
    }
}

static u32 scsi_parse_pos(const u8 *cdb, int is_end)
{
    u32 mode = cdb[9] & 0xC0u;
    if (mode == 0x40u)
        return amsf_to_lba(bcd_to_u8(cdb[2]), bcd_to_u8(cdb[3]), bcd_to_u8(cdb[4]));
    if (mode == 0x80u && S.cd) {
        u32 trk = bcd_to_u8(cdb[2]);
        if (!trk) trk = 1;
        if (trk > S.cd->last_track)
            return S.cd->total_lba;
        return S.cd->tracks[trk].lba;
    }
    u32 v = ((u32)cdb[3] << 16) | ((u32)cdb[4] << 8) | cdb[5];
    if (is_end && !v && S.cd)
        return S.cd->total_lba;
    return v;
}

static void scsi_exec_cmd(void)
{
    const u8 *cdb = S.scsi_cmd;
    u8 buf[32];
    for (int i = 0; i < 32; i++) buf[i] = 0;

    switch (cdb[0]) {
    case 0x00: /* TEST UNIT READY */
        scsi_send_status(0, 0);
        break;

    case 0x03: /* REQUEST SENSE */
        buf[0] = 0x70;
        buf[2] = S.sense_key;
        buf[7] = 0x0A;
        buf[12] = S.sense_asc;
        buf[13] = S.sense_ascq;
        S.sense_key = S.sense_asc = S.sense_ascq = 0;
        scsi_send_data(buf, 18);
        break;

    case 0x08: { /* READ(6) */
        u32 lba = ((u32)(cdb[1] & 0x1Fu) << 16) | ((u32)cdb[2] << 8) | cdb[3];
        u32 cnt = cdb[4] ? cdb[4] : 256u;
        S.cdda_status = CDDA_STOPPED;
        if (!S.cd || lba >= S.cd->total_lba) {
            S.sense_key = 0x05; S.sense_asc = 0x25;
            scsi_send_status(1, 0);
            break;
        }
        S.scsi_lba = lba;
        S.scsi_sec_left = cnt;
        S.scsi_read_timer = 1200;       /* ~0.16 ms first-sector latency */
        scsi_set_phase(SCSI_DATA_IN);
        break;
    }

    case 0xD8: { /* NEC SAPSP (Set Audio Playback Start Position) */
        u32 start = scsi_parse_pos(cdb, 0);
        S.cdda_start_lba = S.cdda_lba = start;
        S.cdda_end_lba = S.cd ? S.cd->total_lba : start;
        S.cdda_pos = 588u;
        pcecd_update_subq(start);
        if (cdb[1]) {
            S.cdda_mode = PLAYMODE_NORMAL;
            S.cdda_status = CDDA_PLAYING;
        } else {
            S.cdda_mode = PLAYMODE_SILENT;
            S.cdda_status = CDDA_PAUSED;
        }
        scsi_send_status(0, 0);
        S.cd_port[3] |= CDIRQ_DONE;
        pcecd_update_irq();
        break;
    }

    case 0xD9: { /* NEC SAPEP (Set Audio Playback End Position) */
        S.cdda_end_lba = scsi_parse_pos(cdb, 1);
        switch (cdb[1]) {
        case 0x00: S.cdda_mode = PLAYMODE_SILENT; S.cdda_status = CDDA_STOPPED; break;
        case 0x01: S.cdda_mode = PLAYMODE_LOOP;   S.cdda_status = CDDA_PLAYING; break;
        case 0x02: S.cdda_mode = PLAYMODE_IRQ;    S.cdda_status = CDDA_PLAYING; break;
        default:   S.cdda_mode = PLAYMODE_NORMAL; S.cdda_status = CDDA_PLAYING; break;
        }
        scsi_send_status(0, 0);
        break;
    }

    case 0xDA: /* NEC PAUSE */
        if (S.cdda_status != CDDA_STOPPED) {
            S.cdda_status = CDDA_PAUSED;
            scsi_send_status(0, 0);
        } else {
            S.sense_key = 0x05; S.sense_asc = 0x2C;
            scsi_send_status(1, 0);
        }
        break;

    case 0xDD: /* NEC READ SUBCHANNEL Q */
        buf[0] = (S.cdda_status == CDDA_PAUSED) ? 2 : (S.cdda_status == CDDA_PLAYING) ? 0 : 3;
        buf[2] = S.subq_last[1];
        buf[3] = S.subq_last[2];
        buf[4] = S.subq_last[3];
        buf[5] = S.subq_last[4];
        buf[6] = S.subq_last[5];
        buf[7] = S.subq_last[7];
        buf[8] = S.subq_last[8];
        buf[9] = S.subq_last[9];
        scsi_send_data(buf, 10);
        break;

    case 0xDE: /* NEC GET DIRECTORY INFO */
        if (!S.cd) {
            scsi_send_status(1, 0);
            break;
        }
        if (cdb[1] == 0x00) {
            buf[0] = u8_to_bcd(S.cd->first_track);
            buf[1] = u8_to_bcd(S.cd->last_track);
            scsi_send_data(buf, 2);
        } else if (cdb[1] == 0x01) {
            u8 m, s, f;
            lba_to_amsf(S.cd->total_lba, &m, &s, &f);
            buf[0] = u8_to_bcd(m);
            buf[1] = u8_to_bcd(s);
            buf[2] = u8_to_bcd(f);
            scsi_send_data(buf, 3);
        } else {
            u32 trk = (cdb[2] == 0xAAu) ? 100u : bcd_to_u8(cdb[2]);
            if (!trk) trk = 1;
            if (trk != 100u && trk > S.cd->last_track) trk = 100u;
            u32 lba = (trk == 100u) ? S.cd->total_lba : S.cd->tracks[trk].lba;
            u8 m, s, f;
            lba_to_amsf(lba, &m, &s, &f);
            buf[0] = u8_to_bcd(m);
            buf[1] = u8_to_bcd(s);
            buf[2] = u8_to_bcd(f);
            buf[3] = (trk == 100u) ? 0x04u : S.cd->tracks[trk].control;
            scsi_send_data(buf, 4);
        }
        break;

    default:
        S.sense_key = 0x05; S.sense_asc = 0x20;
        scsi_send_status(1, 0);
        break;
    }
}

static void scsi_step(void)
{
    switch (S.scsi_phase) {
    case SCSI_COMMAND:
        if ((S.scsi_signals & SCSI_SIG_REQ) && S.scsi_ack) {
            if (S.scsi_cmd_pos < sizeof(S.scsi_cmd))
                S.scsi_cmd[S.scsi_cmd_pos++] = S.scsi_db;
            S.scsi_signals &= (u8)~SCSI_SIG_REQ;
        }
        if (!(S.scsi_signals & SCSI_SIG_REQ) && !S.scsi_ack && S.scsi_cmd_pos) {
            if (S.scsi_cmd_pos >= scsi_cdb_len[S.scsi_cmd[0] >> 4]) {
                S.scsi_cmd_pos = 0;
                scsi_exec_cmd();
            } else {
                S.scsi_signals |= SCSI_SIG_REQ;
            }
        }
        break;

    case SCSI_DATA_IN:
        if ((S.scsi_signals & SCSI_SIG_REQ) && S.scsi_ack)
            S.scsi_signals &= (u8)~SCSI_SIG_REQ;
        if (!(S.scsi_signals & SCSI_SIG_REQ) && !S.scsi_ack) {
            if (S.din_count > 0) {
                S.scsi_db = M->din_buf[S.din_r++];
                S.din_count--;
                S.scsi_signals |= SCSI_SIG_REQ;
            } else if (S.scsi_xfer_done) {
                S.cd_port[3] &= (u8)~CDIRQ_DRQ;
                S.scsi_xfer_done = 0;
                scsi_send_status(0, 0);
                S.cd_port[3] |= CDIRQ_DONE;
                pcecd_update_irq();
            }
        }
        break;

    case SCSI_STATUS:
        if ((S.scsi_signals & SCSI_SIG_REQ) && S.scsi_ack) {
            S.scsi_signals &= (u8)~SCSI_SIG_REQ;
            S.scsi_status_sent = 1;
        }
        if (!(S.scsi_signals & SCSI_SIG_REQ) && !S.scsi_ack && S.scsi_status_sent) {
            S.scsi_status_sent = 0;
            S.scsi_db = S.scsi_msg_pending;
            scsi_set_phase(SCSI_MSG_IN);
        }
        break;

    case SCSI_MSG_IN:
        if ((S.scsi_signals & SCSI_SIG_REQ) && S.scsi_ack) {
            S.scsi_signals &= (u8)~SCSI_SIG_REQ;
            S.scsi_msg_sent = 1;
        }
        if (!(S.scsi_signals & SCSI_SIG_REQ) && !S.scsi_ack && S.scsi_msg_sent) {
            S.scsi_msg_sent = 0;
            scsi_set_phase(SCSI_BUS_FREE);
        }
        break;
    }
}

static u8 pcecd_read_1808(void)
{
    u8 ret = S.scsi_db;
    if ((S.scsi_signals & (SCSI_SIG_REQ | SCSI_SIG_IO)) == (SCSI_SIG_REQ | SCSI_SIG_IO) &&
        !(S.scsi_signals & SCSI_SIG_CD) && !S.scsi_ack) {
        S.scsi_ack = 1;
        scsi_step();
        S.scsi_ack = 0;
        scsi_step();
    }
    return ret;
}

static void pcecd_step_line(u32 cyc_7m)
{
    if (!S.cd_mode)
        return;

    /* Fader countdown */
    if (S.fader_clocked && S.fader_reload > 0) {
        S.fader_cnt -= (s32)cyc_7m;
        while (S.fader_cnt <= 0) {
            if (S.fader_vol > 0)
                S.fader_vol--;
            pcecd_sync_fader();
            S.fader_cnt += S.fader_reload;
        }
    }

    /* Sector Read timer */
    if (S.scsi_read_timer > 0) {
        S.scsi_read_timer -= (s32)cyc_7m;
        if (S.scsi_read_timer <= 0 && S.din_count == 0 && S.scsi_sec_left > 0) {
            if (S.cd && S.cd->read_2048 && S.cd->read_2048(S.scsi_lba, M->din_buf) == 0) {
                pcecd_update_subq(S.scsi_lba);
                S.din_r = 0;
                S.din_count = 2048u;
                S.scsi_lba++;
                S.scsi_sec_left--;
                S.cd_port[3] |= CDIRQ_DRQ;
                pcecd_update_irq();
                if (S.scsi_sec_left > 0) {
                    S.scsi_xfer_done = 0;
                    S.scsi_read_timer = 1600;
                } else {
                    S.scsi_xfer_done = 1;
                }
                scsi_step();
            } else {
                S.scsi_sec_left = 0;
                S.sense_key = 0x03; S.sense_asc = 0x11;
                scsi_send_status(1, 0);
            }
        }
    }

    /* Hardware CD -> ADPCM DMA ($180B bit 0/1) */
    if (S.cd_port[0x0B] & 3u) {
        while ((S.scsi_signals & (SCSI_SIG_REQ | SCSI_SIG_IO)) == (SCSI_SIG_REQ | SCSI_SIG_IO) &&
               !(S.scsi_signals & SCSI_SIG_CD)) {
            u8 b = pcecd_read_1808();
            M->adpcm_ram[S.adpcm_waddr++] = b;
            if (!(S.adpcm_cmd & 0x10u) && S.adpcm_len < 0xFFFFu)
                S.adpcm_len++;
            S.adpcm_half = (S.adpcm_len < 32768u);
        }
        pcecd_update_irq();
    }
}

/* Arcade Card 2 MB RAM & Shift/Rotate Hardware ($1A00..$1AFF & pages $40..$43) */
static inline void ac_auto_inc(struct pce_ac_port *pt)
{
    if (pt->control & 0x01u) {
        if (pt->control & 0x10u)
            pt->base = (pt->base + pt->increment) & 0xFFFFFFu;
        else
            pt->offset = (u16)(pt->offset + pt->increment);
    }
}

static inline u32 ac_eff_addr(const struct pce_ac_port *pt)
{
    u32 a = pt->base;
    if (pt->control & 0x02u) {
        a += pt->offset;
        if (pt->control & 0x08u)
            a += 0xFF0000u;
    }
    return a & 0x1FFFFFu;
}

static u8 ac_read(u16 off)
{
    if ((off & 0x1F00u) != 0x1A00u)
        return 0xFF;
    if (off < 0x1A80u) {
        struct pce_ac_port *pt = &S.ac_ports[(off >> 4) & 3u];
        switch (off & 0x0Fu) {
        case 0x00:
        case 0x01: {
            u8 ret = M->ac_ram[ac_eff_addr(pt)];
            ac_auto_inc(pt);
            return ret;
        }
        case 0x02: return (u8)(pt->base);
        case 0x03: return (u8)(pt->base >> 8);
        case 0x04: return (u8)(pt->base >> 16);
        case 0x05: return (u8)(pt->offset);
        case 0x06: return (u8)(pt->offset >> 8);
        case 0x07: return (u8)(pt->increment);
        case 0x08: return (u8)(pt->increment >> 8);
        case 0x09: return pt->control;
        }
    } else if (off >= 0x1AE0u) {
        switch (off & 0x1Fu) {
        case 0x00: case 0x01: case 0x02: case 0x03:
            return (u8)(S.ac_shift_latch >> ((off & 3u) * 8u));
        case 0x04: return S.ac_shift_bits;
        case 0x05: return S.ac_rotate_bits;
        case 0x1C: case 0x1D: return 0x00;
        case 0x1E: return 0x10;
        case 0x1F: return 0x51;         /* Arcade Card hardware ID */
        }
    }
    return 0xFF;
}

static void ac_write(u16 off, u8 v)
{
    if ((off & 0x1F00u) != 0x1A00u)
        return;
    if (off < 0x1A80u) {
        struct pce_ac_port *pt = &S.ac_ports[(off >> 4) & 3u];
        switch (off & 0x0Fu) {
        case 0x00:
        case 0x01:
            M->ac_ram[ac_eff_addr(pt)] = v;
            ac_auto_inc(pt);
            break;
        case 0x02: pt->base = (pt->base & 0xFFFF00u) | v; break;
        case 0x03: pt->base = (pt->base & 0xFF00FFu) | ((u32)v << 8); break;
        case 0x04: pt->base = (pt->base & 0x00FFFFu) | ((u32)v << 16); break;
        case 0x05:
            pt->offset = (u16)((pt->offset & 0xFF00u) | v);
            if ((pt->control & 0x60u) == 0x20u) {
                if (pt->control & 0x08u) pt->base += 0xFF0000u;
                pt->base = (pt->base + pt->offset) & 0xFFFFFFu;
            }
            break;
        case 0x06:
            pt->offset = (u16)((pt->offset & 0x00FFu) | ((u16)v << 8));
            if ((pt->control & 0x60u) == 0x40u) {
                if (pt->control & 0x08u) pt->base += 0xFF0000u;
                pt->base = (pt->base + pt->offset) & 0xFFFFFFu;
            }
            break;
        case 0x07: pt->increment = (u16)((pt->increment & 0xFF00u) | v); break;
        case 0x08: pt->increment = (u16)((pt->increment & 0x00FFu) | ((u16)v << 8)); break;
        case 0x09: pt->control = v & 0x7Fu; break;
        case 0x0A:
            if ((pt->control & 0x60u) == 0x60u) {
                if (pt->control & 0x08u) pt->base += 0xFF0000u;
                pt->base = (pt->base + pt->offset) & 0xFFFFFFu;
            }
            break;
        }
    } else if (off >= 0x1AE0u) {
        switch (off & 0x1Fu) {
        case 0x00: case 0x01: case 0x02: case 0x03: {
            u32 sh = (off & 3u) * 8u;
            S.ac_shift_latch = (S.ac_shift_latch & ~(0xFFu << sh)) | ((u32)v << sh);
            break;
        }
        case 0x04:
            S.ac_shift_bits = v & 0x0Fu;
            if (S.ac_shift_bits) {
                if (S.ac_shift_bits & 8u)
                    S.ac_shift_latch >>= (16u - S.ac_shift_bits);
                else
                    S.ac_shift_latch <<= S.ac_shift_bits;
            }
            break;
        case 0x05:
            S.ac_rotate_bits = v & 0x0Fu;
            if (S.ac_rotate_bits) {
                if (S.ac_rotate_bits & 8u) {
                    u32 sa = 16u - S.ac_rotate_bits;
                    S.ac_shift_latch = (S.ac_shift_latch >> sa) | (S.ac_shift_latch << (32u - sa));
                } else {
                    u32 sa = S.ac_rotate_bits;
                    S.ac_shift_latch = (S.ac_shift_latch << sa) | (S.ac_shift_latch >> (32u - sa));
                }
            }
            break;
        }
    }
}

static u8 pcecd_reg_read(u16 off)
{
    if ((off & 0x1F00u) == 0x1A00u)
        return ac_read(off);

    if ((off & 0x18C0u) == 0x18C0u) {
        switch (off & 0x18CFu) {
        case 0x18C1: return 0xAA;
        case 0x18C2: return 0x55;
        case 0x18C3: return 0x00;
        case 0x18C5: return 0xAA;
        case 0x18C6: return 0x55;
        case 0x18C7: return 0x03;       /* Super System Card 3.0 RAM signature */
        }
        return 0xFF;
    }

    psg_catch_up();
    switch (off & 0x0Fu) {
    case 0x0: return S.scsi_signals;
    case 0x1: return S.scsi_db;
    case 0x2: return S.cd_port[2];
    case 0x3: {
        S.bram_unlocked = 0;
        u8 ret = S.cd_port[3];
        S.cd_port[3] ^= 2u;
        return ret;
    }
    case 0x4: return S.cd_port[4];
    case 0x5: {
        s16 ch = (S.cd_port[3] & 2u) ? S.cdda_last_r : S.cdda_last_l;
        u16 mag = ch < 0 ? (u16)(-ch) : (u16)ch;
        return (u8)mag;
    }
    case 0x6: {
        s16 ch = (S.cd_port[3] & 2u) ? S.cdda_last_r : S.cdda_last_l;
        u16 mag = ch < 0 ? (u16)(-ch) : (u16)ch;
        return (u8)(mag >> 8);
    }
    case 0x7: {
        u8 ret = 0;
        if (S.subq_count > 0) {
            ret = S.subq_fifo[S.subq_r & 15u];
            S.subq_r++;
            S.subq_count--;
        }
        if (S.subq_count == 0) {
            S.cd_port[3] &= (u8)~CDIRQ_SUBQ;
            pcecd_update_irq();
        }
        return ret;
    }
    case 0x8: return pcecd_read_1808();
    case 0xA: {
        u8 ret = S.adpcm_rbuf;
        S.adpcm_rbuf = M->adpcm_ram[S.adpcm_raddr++];
        if (S.adpcm_len && !(S.adpcm_cmd & 0x10u)) {
            S.adpcm_len--;
            if (!S.adpcm_len)
                S.adpcm_end = 1;
        }
        S.adpcm_half = (S.adpcm_len < 32768u);
        pcecd_update_irq();
        return ret;
    }
    case 0xB: return S.cd_port[0x0B];
    case 0xC:
        return (u8)((S.adpcm_end ? 0x01u : 0u) | (S.adpcm_playing ? 0x08u : 0u));
    case 0xD: return S.adpcm_cmd;
    }
    return 0;
}

static void pcecd_reg_write(u16 off, u8 v)
{
    if ((off & 0x1F00u) == 0x1A00u) {
        ac_write(off, v);
        return;
    }
    if ((off & 0x18C0u) == 0x18C0u)
        return;

    psg_catch_up();
    switch (off & 0x0Fu) {
    case 0x0:
        if (S.scsi_phase == SCSI_BUS_FREE) {
            S.scsi_cmd_pos = 0;
            scsi_set_phase(SCSI_COMMAND);
        }
        S.cd_port[3] &= (u8)~(CDIRQ_DONE | CDIRQ_DRQ);
        pcecd_update_irq();
        break;
    case 0x1:
        S.cd_port[1] = v;
        S.scsi_db = v;
        scsi_step();
        break;
    case 0x2:
        S.cd_port[2] = v;
        S.scsi_ack = (v & 0x80u) != 0;
        scsi_step();
        pcecd_update_irq();
        break;
    case 0x4:
        S.cd_port[4] = v;
        if (v & 2u) {
            S.scsi_sec_left = 0;
            S.scsi_read_timer = 0;
            S.din_r = S.din_count = 0;
            S.cdda_status = CDDA_STOPPED;
            scsi_set_phase(SCSI_BUS_FREE);
            S.cd_port[3] &= (u8)~0x70u;
            pcecd_update_irq();
        }
        break;
    case 0x7:
        if (v & 0x80u)
            S.bram_unlocked = 1;
        break;
    case 0x8:
        if (!(S.adpcm_cmd & 0x80u)) {
            S.adpcm_addr = (u16)((S.adpcm_addr & 0xFF00u) | v);
            if (S.adpcm_cmd & 0x10u)
                S.adpcm_len = S.adpcm_addr;
        }
        break;
    case 0x9:
        if (!(S.adpcm_cmd & 0x80u)) {
            S.adpcm_addr = (u16)((S.adpcm_addr & 0x00FFu) | ((u16)v << 8));
            if (S.adpcm_cmd & 0x10u)
                S.adpcm_len = S.adpcm_addr;
        }
        break;
    case 0xA:
        M->adpcm_ram[S.adpcm_waddr++] = v;
        if (!(S.adpcm_cmd & 0x10u) && S.adpcm_len < 0xFFFFu)
            S.adpcm_len++;
        S.adpcm_half = (S.adpcm_len < 32768u);
        pcecd_update_irq();
        break;
    case 0xB:
        S.cd_port[0x0B] = v;
        pcecd_step_line(0);
        break;
    case 0xD:
        if (v & 0x80u) {
            S.adpcm_addr = S.adpcm_raddr = S.adpcm_waddr = S.adpcm_len = 0;
            S.adpcm_cmd = 0;
            S.adpcm_playing = S.adpcm_half = S.adpcm_end = S.adpcm_nibble = 0;
            S.adpcm_sample = 0;
            S.adpcm_ssi = 0;
            pcecd_update_irq();
            break;
        }
        if (S.adpcm_playing && !(v & 0x20u))
            S.adpcm_playing = 0;
        if (!S.adpcm_playing && (v & 0x20u)) {
            S.adpcm_playing = 1;
            S.adpcm_half = 0;
            S.adpcm_nibble = 0;
            S.adpcm_phase = 0;
            S.adpcm_sample = 0;
            S.adpcm_ssi = 0;
        }
        if (v & 0x10u) {
            S.adpcm_len = S.adpcm_addr;
            S.adpcm_end = 0;
        }
        if (!(S.adpcm_cmd & 0x08u) && (v & 0x08u)) {
            S.adpcm_raddr = (v & 0x04u) ? S.adpcm_addr : (u16)(S.adpcm_addr - 1u);
            S.adpcm_rbuf = M->adpcm_ram[S.adpcm_raddr];
        }
        if (!(S.adpcm_cmd & 0x02u) && (v & 0x02u))
            S.adpcm_waddr = (v & 0x01u) ? S.adpcm_addr : (u16)(S.adpcm_addr - 1u);
        S.adpcm_cmd = v;
        pcecd_update_irq();
        break;
    case 0xE:
        S.adpcm_freq = v & 0x0Fu;
        break;
    case 0xF:
        S.fader_cmd = v;
        if (!(v & 8u)) {
            S.fader_vol = 65536;
            S.fader_cnt = 0;
            S.fader_reload = 0;
            S.fader_clocked = 0;
        } else {
            S.fader_reload = (v & 4u) ? 273 : 655;
            if (!S.fader_clocked)
                S.fader_cnt = S.fader_reload;
            S.fader_clocked = 1;
        }
        pcecd_sync_fader();
        break;
    }
}

/* ========================================================================
 * Dual HuC6270 VDC + HuC6202 VPC + HuC6260 VCE Helpers
 * ======================================================================== */

static inline u16 vdc_inc(int chip)
{
    static const u16 incs[4] = {1, 32, 64, 128};
    return incs[(S.vdc[chip].regs[5] >> 11) & 3];
}

static void vdc_update_irq(void)
{
    u8 st = S.vdc[0].status;
    if (S.sgx_mode)
        st |= S.vdc[1].status;
    if (st & 0x3Fu)
        S.irq_lines |= 0x02u;
    else
        S.irq_lines &= (u8)~0x02u;
}

static void vdc_satb_dma(int chip)
{
    u16 src = S.vdc[chip].regs[19];
    for (int i = 0; i < 256; i++) {
        u16 a = (u16)(src + i);
        M->satb[chip][i] = M->vram[chip][a & 0x7FFFu];
    }
    S.vdc[chip].satb_dirty = 0;
    S.vdc[chip].sat_dma_slcounter = 2;
}

static void vdc_vram_dma(int chip)
{
    struct pce_vdc *v = &S.vdc[chip];
    u16 src = v->regs[16], dst = v->regs[17], len = v->regs[18];
    s32 ds = (v->regs[15] & 0x04) ? -1 : 1;
    s32 dd = (v->regs[15] & 0x08) ? -1 : 1;
    u32 count = (u32)len + 1u;
    while (count--) {
        u16 val = src < 0x8000u ? M->vram[chip][src] : 0;
        if (dst < 0x8000u)
            M->vram[chip][dst] = val;
        src = (u16)(src + ds);
        dst = (u16)(dst + dd);
    }
    v->regs[16] = src;
    v->regs[17] = dst;
    v->regs[18] = 0xFFFF;
    if (v->regs[15] & 0x02) {
        v->status |= 0x10;              /* DV */
        vdc_update_irq();
    }
}

static u8 vdc_read_chip(int chip, u8 port)
{
    struct pce_vdc *v = &S.vdc[chip];
    switch (port & 3) {
    case 0: {
        u8 st = v->status;
        v->status &= (u8)~0x3Fu;
        vdc_update_irq();
        return st;
    }
    case 1:
        return 0;
    case 2:
        return (u8)(v->vram_rbuf & 0xFFu);
    case 3: {
        u8 hi = (u8)(v->vram_rbuf >> 8);
        if (v->reg == 2) {
            v->regs[1] = (u16)(v->regs[1] + vdc_inc(chip));
            v->vram_rbuf = v->regs[1] < 0x8000u ? M->vram[chip][v->regs[1]] : 0;
        }
        return hi;
    }
    }
    return 0;
}

static void vdc_write_chip(int chip, u8 port, u8 val)
{
    struct pce_vdc *v = &S.vdc[chip];
    switch (port & 3) {
    case 0:
        v->reg = val & 0x1Fu;
        break;
    case 2:
        if (v->reg == 2) {
            v->latch_lo = val;
        } else if (v->reg < 20) {
            v->regs[v->reg] = (v->regs[v->reg] & 0xFF00u) | val;
            if (v->reg == 8) {
                v->bg_y = v->regs[8] & 0x1FFu;
                v->byr_latched = 1;
            } else if (v->reg == 19) {
                v->satb_dirty = 1;
            }
        }
        break;
    case 3:
        if (v->reg == 2) {
            u16 a = v->regs[0];
            if (a < 0x8000u)
                M->vram[chip][a] = (u16)(((u16)val << 8) | v->latch_lo);
            v->regs[0] = (u16)(a + vdc_inc(chip));
        } else if (v->reg < 20) {
            v->regs[v->reg] = (v->regs[v->reg] & 0x00FFu) | ((u16)val << 8);
            if (v->reg == 1) {
                v->vram_rbuf = v->regs[1] < 0x8000u ? M->vram[chip][v->regs[1]] : 0;
            } else if (v->reg == 8) {
                v->bg_y = v->regs[8] & 0x1FFu;
                v->byr_latched = 1;
            } else if (v->reg == 18) {
                vdc_vram_dma(chip);
            } else if (v->reg == 19) {
                v->satb_dirty = 1;
            }
        }
        break;
    }
}

static u8 joypad_read_nibble(void)
{
    u8 lo = 0x0F;
    if (!S.joy_clr) {
        int six = (S.pad_state & 0x0F00) != 0;
        if (six && S.joy_six_toggle) {
            if (!S.joy_sel) {
                lo = 0;
            } else {
                if (S.pad_state & PCE_III) lo &= (u8)~0x01;
                if (S.pad_state & PCE_IV)  lo &= (u8)~0x02;
                if (S.pad_state & PCE_V)   lo &= (u8)~0x04;
                if (S.pad_state & PCE_VI)  lo &= (u8)~0x08;
            }
        } else if (S.joy_sel) {
            if (S.pad_state & PCE_UP)    lo &= (u8)~0x01;
            if (S.pad_state & PCE_RIGHT) lo &= (u8)~0x02;
            if (S.pad_state & PCE_DOWN)  lo &= (u8)~0x04;
            if (S.pad_state & PCE_LEFT)  lo &= (u8)~0x08;
        } else {
            if (S.pad_state & PCE_I)      lo &= (u8)~0x01;
            if (S.pad_state & PCE_II)     lo &= (u8)~0x02;
            if (S.pad_state & PCE_SELECT) lo &= (u8)~0x04;
            if (S.pad_state & PCE_RUN)    lo &= (u8)~0x08;
        }
    }
    /* Bit 5 ($20) = 0 when CD-ROM2 unit is attached, 1 on standalone HuCard PCE! */
    u8 cd_bit = S.cd_mode ? 0x00u : 0x20u;
    S.io_buf = (u8)(0x80u | (S.us_region ? 0x00u : 0x40u) | cd_bit | 0x10u | lo);
    return S.io_buf;
}

/* ---- Hardware I/O page ($FF: $1FE000..$1FFFFF) ---- */
static __attribute__((unused)) u8 io_read(u16 off)
{
    switch (off & 0x1C00u) {
    case 0x0000:                        /* HuC6270 VDC(s) & SuperGrafx HuC6202 VPC */
        if (S.sgx_mode) {
            u16 a = off & 0x1Fu;
            if (a & 8u) {
                switch (a) {
                case 0x08: return S.vpc_prio[0];
                case 0x09: return S.vpc_prio[1];
                case 0x0A: return (u8)(S.vpc_win[0] & 0xFFu);
                case 0x0B: return (u8)(S.vpc_win[0] >> 8);
                case 0x0C: return (u8)(S.vpc_win[1] & 0xFFu);
                case 0x0D: return (u8)(S.vpc_win[1] >> 8);
                case 0x0E: return S.vpc_st_mode;
                default:   return 0;
                }
            }
            return vdc_read_chip((a >> 4) & 1, (u8)(a & 3u));
        }
        return vdc_read_chip(0, (u8)(off & 3u));

    case 0x0400:                        /* HuC6260 VCE */
        switch (off & 7u) {
        case 4:
            return (u8)(M->vce_raw[S.vce_addr & 0x1FFu] & 0xFFu);
        case 5: {
            u8 hi = (u8)((M->vce_raw[S.vce_addr & 0x1FFu] >> 8) | 0xFEu);
            S.vce_addr = (S.vce_addr + 1u) & 0x1FFu;
            return hi;
        }
        default:
            return 0xFF;
        }

    case 0x0800:                        /* PSG */
        return S.io_buf;

    case 0x0C00:                        /* Timer */
        S.io_buf = (S.io_buf & 0x80u) | (S.tmr_cnt & 0x7Fu);
        return S.io_buf;

    case 0x1000:                        /* Joypad */
        return joypad_read_nibble();

    case 0x1400:                        /* Interrupt controller */
        if ((off & 3u) == 2u) {
            S.io_buf = (S.io_buf & 0xF8u) | (S.irq_mask & 0x07u);
            return S.io_buf;
        }
        if ((off & 3u) == 3u) {
            S.io_buf = (S.io_buf & 0xF8u) | (S.irq_lines & 0x07u);
            return S.io_buf;
        }
        return S.io_buf;

    case 0x1800:                        /* CD-ROM2 / Arcade Card / BRAM */
        if (S.cd_mode)
            return pcecd_reg_read(off);
        if ((off & 0x0Fu) == 3u)
            S.bram_unlocked = 0;
        return 0xFF;
    }
    return 0xFF;
}

static __attribute__((unused)) void io_write(u16 off, u8 v)
{
    S.io_buf = v;
    switch (off & 0x1C00u) {
    case 0x0000:
        if (S.sgx_mode) {
            u16 a = off & 0x1Fu;
            if (a & 8u) {
                switch (a) {
                case 0x08: S.vpc_prio[0] = v; break;
                case 0x09: S.vpc_prio[1] = v; break;
                case 0x0A: S.vpc_win[0] = (S.vpc_win[0] & 0x300u) | v; break;
                case 0x0B: S.vpc_win[0] = (S.vpc_win[0] & 0x0FFu) | (((u16)v & 3u) << 8); break;
                case 0x0C: S.vpc_win[1] = (S.vpc_win[1] & 0x300u) | v; break;
                case 0x0D: S.vpc_win[1] = (S.vpc_win[1] & 0x0FFu) | (((u16)v & 3u) << 8); break;
                case 0x0E: S.vpc_st_mode = v & 1u; break;
                }
                return;
            }
            vdc_write_chip((a >> 4) & 1, (u8)(a & 3u), v);
        } else {
            vdc_write_chip(0, (u8)(off & 3u), v);
        }
        break;

    case 0x0400:
        switch (off & 7u) {
        case 0: S.vce_ctrl = v; break;
        case 2: S.vce_addr = (S.vce_addr & 0x100u) | v; break;
        case 3: S.vce_addr = (S.vce_addr & 0x0FFu) | (((u16)v & 1u) << 8); break;
        case 4: {
            u16 idx = S.vce_addr & 0x1FFu;
            M->vce_raw[idx] = (M->vce_raw[idx] & 0x100u) | v;
            M->vce_pal[idx] = grb9_to_bgr15(M->vce_raw[idx]);
            break;
        }
        case 5: {
            u16 idx = S.vce_addr & 0x1FFu;
            M->vce_raw[idx] = (M->vce_raw[idx] & 0x0FFu) | (((u16)v & 1u) << 8);
            M->vce_pal[idx] = grb9_to_bgr15(M->vce_raw[idx]);
            S.vce_addr = (S.vce_addr + 1u) & 0x1FFu;
            break;
        }
        }
        break;

    case 0x0800: {                      /* PSG */
        psg_catch_up();
        struct pce_psg_ch *c = &S.psg[S.psg_sel];
        switch (off & 0x0Fu) {
        case 0: S.psg_sel = (v & 7) < 6 ? (v & 7) : 5; break;
        case 1: S.psg_vol = v; break;
        case 2: c->freq = (c->freq & 0x0F00u) | v; break;
        case 3: c->freq = (c->freq & 0x00FFu) | (((u16)v & 0x0Fu) << 8); break;
        case 4:
            if ((v & 0xC0) == 0x40)
                c->wave_idx = 0;
            c->ctrl = v;
            break;
        case 5: c->balance = v; break;
        case 6:
            if ((c->ctrl & 0xC0) == 0xC0) {
                c->dda = v & 0x1F;
            } else if (!(c->ctrl & 0x80)) {
                c->wave[c->wave_idx & 31] = v & 0x1F;
                c->wave_idx = (c->wave_idx + 1) & 31;
            }
            break;
        case 7:
            if (S.psg_sel >= 4)
                c->noise_ctrl = v;
            break;
        case 8: S.lfo_freq = v; break;
        case 9:
            S.lfo_ctrl = v;
            if (v & 0x80)
                S.psg[1].wave_idx = 0;
            break;
        }
        break;
    }

    case 0x0C00:                        /* Timer */
        if (!(off & 1u)) {
            S.tmr_reload = v & 0x7F;
        } else {
            u8 on = v & 1;
            if (!S.tmr_on && on) {
                S.tmr_cnt = S.tmr_reload;
                S.tmr_prescale = 1024;
            }
            S.tmr_on = on;
        }
        break;

    case 0x1000: {                      /* Joypad */
        u8 new_clr = (v >> 1) & 1;
        if (!S.joy_clr && new_clr)
            S.joy_six_toggle ^= 1;
        S.joy_sel = v & 1;
        S.joy_clr = new_clr;
        break;
    }

    case 0x1400:                        /* Interrupt controller */
        if ((off & 3u) == 2u)
            S.irq_mask = v & 0x07u;
        else if ((off & 3u) == 3u)
            S.irq_lines &= (u8)~0x04u;
        break;

    case 0x1800:                        /* CD-ROM2 / Arcade Card / BRAM */
        if (S.cd_mode) {
            pcecd_reg_write(off, v);
        } else if ((off & 0x0Fu) == 7u && (v & 0x80u)) {
            S.bram_unlocked = 1;
        }
        break;
    }
}

/* ---- Bus read / write ---- */
static inline u8 bus_read(u16 a)
{
#ifdef PCE_CPU_TEST
    u32 phys = ((u32)S.mpr[a >> 13] << 13) | (a & 0x1FFFu);
    return pce_sst_ram[phys & 0x1FFFFFu];
#else
    const u8 *r = S.mpr_r[a >> 13];
    if (r)
        return r[a & 0x1FFFu];
    u8 page = S.mpr[a >> 13];
    u16 off = a & 0x1FFFu;
    if (page == 0xFF)
        return io_read(off);
    if (page == 0xF7)
        return (S.bram_unlocked && off < 0x800u) ? M->bram[off] : 0xFF;
    if (S.cd_mode && page >= 0x40 && page <= 0x43)
        return ac_read((u16)(0x1A00u + (u16)(page - 0x40u) * 0x10u));
    return 0xFF;
#endif
}

static inline void bus_write(u16 a, u8 v)
{
#ifdef PCE_CPU_TEST
    u32 phys = ((u32)S.mpr[a >> 13] << 13) | (a & 0x1FFFu);
    pce_sst_ram[phys & 0x1FFFFFu] = v;
#else
    u8 *w = S.mpr_w[a >> 13];
    if (w) {
        w[a & 0x1FFFu] = v;
        return;
    }
    u8 page = S.mpr[a >> 13];
    u16 off = a & 0x1FFFu;
    if (page == 0xFF) {
        io_write(off, v);
        return;
    }
    if (page == 0xF7) {
        if (S.bram_unlocked && off < 0x800u && M->bram[off] != v) {
            M->bram[off] = v;
            S.bram_dirty = 1;
        }
        return;
    }
    if (S.cd_mode && page >= 0x40 && page <= 0x43) {
        ac_write((u16)(0x1A00u + (u16)(page - 0x40u) * 0x10u), v);
        return;
    }
    if (S.sf2_mapper && (a & 0xFFF0u) == 0x1FF0u) {
        S.sf2_bank = (u8)(a & 3u);
        rebuild_pages();
    }
#endif
}

static inline u8 zp_read(u8 zp)          { return bus_read((u16)(0x2000u | zp)); }
static inline void zp_write(u8 zp, u8 v) { bus_write((u16)(0x2000u | zp), v); }
static inline void push8(u8 v)           { bus_write((u16)(0x2100u | S.s), v); S.s--; }
static inline u8 pull8(void)             { S.s++; return bus_read((u16)(0x2100u | S.s)); }
static inline void push16(u16 v)         { push8((u8)(v >> 8)); push8((u8)v); }
static inline u16 pull16(void)           { u16 lo = pull8(); return lo | ((u16)pull8() << 8); }
static inline u8 fetch8(void)            { return bus_read(S.pc++); }
static inline u16 fetch16(void)          { u16 lo = fetch8(); return lo | ((u16)fetch8() << 8); }

static inline void set_nz(u8 v)
{
    S.p = (S.p & (u8)~(FN | FZ)) | (v & FN) | (v ? 0 : FZ);
}

static inline u16 zp_ind(u8 zp)
{
    u16 lo = zp_read(zp);
    return lo | ((u16)zp_read((u8)(zp + 1)) << 8);
}

/* ========================================================================
 * Clean-Room System Card 3.0 BIOS ($E000..$E0E4 Jump Table & IRQ Vectors)
 * ======================================================================== */

#ifndef PCE_CPU_TEST
static void bios_load_sectors_to_mem(u32 start_lba, u32 nsec, u8 dh, u16 bx, u16 ax_bytes)
{
    if (!S.cd || !S.cd->read_2048)
        return;
    u8 sec[2048];
    if (dh == 0xFEu) {
        /* VRAM byte-count mode: ax_bytes bytes to MAWR = bx */
        u16 mawr = bx;
        u32 rem = ax_bytes;
        u32 lba = start_lba;
        while (rem > 0) {
            if (S.cd->read_2048(lba++, sec) < 0)
                break;
            u32 take = rem > 2048u ? 2048u : rem;
            for (u32 i = 0; i + 1u < take; i += 2u) {
                M->vram[0][mawr & 0x7FFFu] = (u16)(sec[i] | ((u16)sec[i + 1u] << 8));
                mawr++;
            }
            rem -= take;
        }
        S.vdc[0].regs[0] = mawr;
        return;
    }
    if (dh == 0x01u || dh == 0xFFu) {
        /* VRAM sector-count mode */
        u16 mawr = bx;
        for (u32 s = 0; s < nsec; s++) {
            if (S.cd->read_2048(start_lba + s, sec) < 0)
                break;
            for (u32 i = 0; i < 2048u; i += 2u) {
                M->vram[0][mawr & 0x7FFFu] = (u16)(sec[i] | ((u16)sec[i + 1u] << 8));
                mawr++;
            }
        }
        S.vdc[0].regs[0] = mawr;
        return;
    }
    if (dh >= 2u && dh <= 6u) {
        /* MPR slot #dh auto-bank mode */
        u16 base_va = (u16)(dh << 13);
        u16 off = 0;
        for (u32 s = 0; s < nsec; s++) {
            if (S.cd->read_2048(start_lba + s, sec) < 0)
                break;
            for (u32 i = 0; i < 2048u; i++) {
                bus_write((u16)(base_va + off), sec[i]);
                off++;
                if (off == 0x2000u) {
                    off = 0;
                    S.mpr[dh]++;
                    sync_mpr(dh);
                }
            }
        }
        return;
    }

    /* dh == 0: Local CPU virtual address bx (auto-advancing MPR if >= $4000) */
    u32 va = bx;
    for (u32 s = 0; s < nsec; s++) {
        if (S.cd->read_2048(start_lba + s, sec) < 0)
            break;
        for (u32 i = 0; i < 2048u; i++) {
            bus_write((u16)va, sec[i]);
            u32 prev_slot = (va >> 13) & 7u;
            va = (va + 1u) & 0xFFFFu;
            u32 next_slot = (va >> 13) & 7u;
            if (next_slot != prev_slot && prev_slot >= 2u && prev_slot <= 6u && next_slot == 7u) {
                /* Wrapped past $DFFF -> advance MPR6 and stay at $C000 */
                S.mpr[6]++;
                sync_mpr(6);
                va = 0xC000u;
            }
        }
    }
}

static void bios_poll_joypad(void)
{
    u8 cur = 0;
    if (S.pad_state & PCE_I)      cur |= 0x01u;
    if (S.pad_state & PCE_II)     cur |= 0x02u;
    if (S.pad_state & PCE_SELECT) cur |= 0x04u;
    if (S.pad_state & PCE_RUN)    cur |= 0x08u;
    if (S.pad_state & PCE_UP)     cur |= 0x10u;
    if (S.pad_state & PCE_RIGHT)  cur |= 0x20u;
    if (S.pad_state & PCE_DOWN)   cur |= 0x40u;
    if (S.pad_state & PCE_LEFT)   cur |= 0x80u;
    u8 old = M->wram[0x0228];
    M->wram[0x0232] = old;                      /* joyold ($2232) */
    M->wram[0x0228] = cur;                      /* joy ($2228) */
    M->wram[0x022D] = (u8)(cur & ~old);         /* joytrg ($222D) */
}

static void bios_cd_boot(void)
{
    if (!S.cd || !S.cd->read_2048) {
        S.jammed = 1;
        return;
    }

    /* Locate first Data track (Track 1 on ISO/homebrew, Track 2 on standard NEC CDs) */
    u32 data_lba = 0;
    for (int t = 1; t <= (int)S.cd->last_track; t++) {
        if (!S.cd->tracks[t].is_audio) {
            data_lba = S.cd->tracks[t].lba;
            break;
        }
    }
    S.cd_data_base = data_lba;

    /* Default System Card 3.0 environment */
    S.mpr[0] = 0xFF;
    S.mpr[1] = 0xF8;
    S.mpr[2] = 0x80;
    S.mpr[3] = 0x81;
    S.mpr[4] = 0x82;
    S.mpr[5] = 0x83;
    S.mpr[6] = 0x84;
    S.mpr[7] = 0x00;
    for (int i = 0; i < 8; i++)
        sync_mpr(i);

    S.speed = 1;                                /* CSH 7.16 MHz */
    S.psg_vol = 0xFF;
    S.fader_vol = 65536;
    pcecd_sync_fader();
    M->wram[0x0227] = 0x01;                     /* joyena = port 1 */
    M->wram[0x00F3] = 0xCC;                     /* vdc_crl: BG + SPR + RCR + VBL */
    S.vdc[0].regs[5] = 0x00CC;
    S.vdc[0].regs[9] = 0x0010;                  /* 64x32 BAT */
    S.irq_mask = 0;

    u8 ipl[2048];
    if (S.cd->read_2048(data_lba + 1u, ipl) < 0) {
        S.jammed = 1;
        return;
    }

    u32 blk = ((u32)ipl[0] << 16) | ((u32)ipl[1] << 8) | ipl[2];
    u32 cnt = ipl[3] ? ipl[3] : 1u;
    u16 sta = (u16)(ipl[4] | ((u16)ipl[5] << 8));
    u16 jmp = (u16)(ipl[6] | ((u16)ipl[7] << 8));

    if (ipl[8] | ipl[9] | ipl[10] | ipl[11] | ipl[12]) {
        for (int m = 2; m <= 6; m++) {
            S.mpr[m] = ipl[6 + m];
            sync_mpr(m);
        }
    }
    if (sta < 0x2000u) sta = 0x4000u;
    if (jmp < 0x2000u) jmp = sta;

    bios_load_sectors_to_mem(data_lba + blk, cnt, 0, sta, 0);
    S.s = 0xFF;
    S.p &= (u8)~FI;                             /* CLI */
    S.pc = jmp;
}

static void bios_hle_call(u8 fn)
{
    u8  al = zp_read(0xF8), ah = zp_read(0xF9);
    u8  bl = zp_read(0xFA), bh = zp_read(0xFB);
    u8  cl = zp_read(0xFC), ch = zp_read(0xFD);
    u8  dl = zp_read(0xFE), dh = zp_read(0xFF);
    u16 ax = (u16)(al | ((u16)ah << 8));
    u16 bx = (u16)(bl | ((u16)bh << 8));
    u16 cx = (u16)(cl | ((u16)ch << 8));

    switch (fn) {
    case 0: /* cd_boot ($E000) */
        bios_cd_boot();
        return;

    case 1: /* cd_reset ($E003) */
        S.cdda_status = CDDA_STOPPED;
        scsi_set_phase(SCSI_BUS_FREE);
        S.a = 0; set_nz(0);
        break;

    case 2: /* cd_base ($E006) */
        if (S.cd) {
            if ((al & 3u) == 0) {
                u32 trk = bcd_to_u8(cl);
                if (!trk) trk = 1;
                if (trk <= S.cd->last_track)
                    S.cd_data_base = S.cd->tracks[trk].lba;
            } else if ((al & 3u) == 1u) {
                S.cd_data_base = amsf_to_lba(bcd_to_u8(cl), bcd_to_u8(ch), bcd_to_u8(dl));
            } else {
                S.cd_data_base = ((u32)cl << 16) | ((u32)ch << 8) | dl;
            }
        }
        S.a = 0; set_nz(0);
        break;

    case 3: { /* cd_read ($E009) */
        u32 rel = ((u32)cl << 16) | ((u32)ch << 8) | dl;
        u32 cnt = al ? al : 256u;
        S.cdda_status = CDDA_STOPPED;
        bios_load_sectors_to_mem(S.cd_data_base + rel, cnt, dh, bx, ax);
        S.a = 0; set_nz(0);
        break;
    }

    case 4: /* cd_seek ($E00C) */
        S.cdda_status = CDDA_STOPPED;
        pcecd_update_subq(S.cd_data_base + (((u32)cl << 16) | ((u32)ch << 8) | dl));
        S.a = 0; set_nz(0);
        break;

    case 5: { /* cd_exec ($E00F) */
        u32 rel = ((u32)cl << 16) | ((u32)ch << 8) | dl;
        u32 cnt = al ? al : 1u;
        bios_load_sectors_to_mem(S.cd_data_base + rel, cnt, dh, bx, ax);
        S.pc = bx;
        return;
    }

    case 6: { /* cd_play ($E012) */
        psg_catch_up();
        if (S.cd) {
            u32 st_lba = S.cdda_lba, en_lba = S.cd->total_lba;
            u8 smode = bh & 0xC0u;
            if (smode == 0x00u) {
                st_lba = ((u32)al << 16) | ((u32)ah << 8) | bl;
            } else if (smode == 0x40u) {
                st_lba = amsf_to_lba(bcd_to_u8(al), bcd_to_u8(ah), bcd_to_u8(bl));
            } else if (smode == 0x80u) {
                u32 trk = bcd_to_u8(al);
                if (!trk) trk = 1;
                if (trk <= S.cd->last_track) {
                    st_lba = S.cd->tracks[trk].lba;
                    en_lba = (trk < S.cd->last_track) ? S.cd->tracks[trk + 1u].lba : S.cd->total_lba;
                }
            }
            u8 emode = dh & 0xC0u;
            if (emode == 0x00u && (cl | ch | dl)) {
                en_lba = ((u32)cl << 16) | ((u32)ch << 8) | dl;
            } else if (emode == 0x40u) {
                en_lba = amsf_to_lba(bcd_to_u8(cl), bcd_to_u8(ch), bcd_to_u8(dl));
            } else if (emode == 0x80u && cl) {
                u32 etrk = bcd_to_u8(cl);
                en_lba = (etrk <= S.cd->last_track) ? S.cd->tracks[etrk].lba : S.cd->total_lba;
            }
            S.cdda_start_lba = S.cdda_lba = st_lba;
            S.cdda_end_lba = en_lba;
            S.cdda_pos = 588u;
            u8 pm = dh & 0x3Fu;
            S.cdda_mode = (pm == 1u) ? PLAYMODE_LOOP : (pm == 0u) ? PLAYMODE_SILENT : PLAYMODE_NORMAL;
            S.cdda_status = (pm == 0u) ? CDDA_PAUSED : CDDA_PLAYING;
            pcecd_update_subq(st_lba);
        }
        S.a = 0; set_nz(0);
        break;
    }

    case 7: /* cd_search ($E015) */
        S.cdda_status = CDDA_PAUSED;
        S.a = 0; set_nz(0);
        break;

    case 8: /* cd_pause ($E018) */
        psg_catch_up();
        S.cdda_status = CDDA_PAUSED;
        S.a = 0; set_nz(0);
        break;

    case 9: /* cd_stat ($E01B) */
        if (S.a == 0)
            S.a = 0x00;
        else
            S.a = (S.cdda_status == CDDA_PLAYING) ? 0x80u : 0x00u;
        set_nz(S.a);
        break;

    case 10: /* cd_subq ($E01E) */
        bus_write(bx + 0, (S.cdda_status == CDDA_PAUSED) ? 2 : (S.cdda_status == CDDA_PLAYING) ? 0 : 3);
        bus_write(bx + 1, 0);
        bus_write(bx + 2, S.subq_last[1]);
        bus_write(bx + 3, S.subq_last[2]);
        bus_write(bx + 4, S.subq_last[3]);
        bus_write(bx + 5, S.subq_last[4]);
        bus_write(bx + 6, S.subq_last[5]);
        bus_write(bx + 7, S.subq_last[7]);
        bus_write(bx + 8, S.subq_last[8]);
        bus_write(bx + 9, S.subq_last[9]);
        S.a = 0; set_nz(0);
        break;

    case 11: /* cd_dinfo ($E021) */
        if (S.cd) {
            if (al == 0) {
                bus_write(bx + 0, u8_to_bcd(S.cd->first_track));
                bus_write(bx + 1, u8_to_bcd(S.cd->last_track));
            } else if (al == 1) {
                u8 m, s, f;
                lba_to_amsf(S.cd->total_lba, &m, &s, &f);
                bus_write(bx + 0, u8_to_bcd(m));
                bus_write(bx + 1, u8_to_bcd(s));
                bus_write(bx + 2, u8_to_bcd(f));
            } else {
                u32 trk = bcd_to_u8(ah);
                if (!trk) trk = 1;
                u32 lba = (trk <= S.cd->last_track) ? S.cd->tracks[trk].lba : S.cd->total_lba;
                u8 m, s, f;
                lba_to_amsf(lba, &m, &s, &f);
                bus_write(bx + 0, u8_to_bcd(m));
                bus_write(bx + 1, u8_to_bcd(s));
                bus_write(bx + 2, u8_to_bcd(f));
                bus_write(bx + 3, (trk <= S.cd->last_track) ? S.cd->tracks[trk].control : 4u);
            }
        }
        S.a = 0; set_nz(0);
        break;

    case 15: /* cd_fade ($E02D) */
        pcecd_reg_write(0x180F, S.a);
        S.a = 0; set_nz(0);
        break;

    case 16: /* ad_reset ($E030) */
        pcecd_reg_write(0x180D, 0x80);
        S.a = 0; set_nz(0);
        break;

    case 17: { /* ad_trans ($E033): CD sectors -> ADPCM RAM */
        psg_catch_up();
        if (dh == 0)
            S.adpcm_waddr = bx;
        u32 rel = ((u32)cl << 16) | ((u32)ch << 8) | dl;
        u32 cnt = al ? al : 256u;
        u8 sec[2048];
        for (u32 s = 0; s < cnt && S.cd && S.cd->read_2048; s++) {
            if (S.cd->read_2048(S.cd_data_base + rel + s, sec) < 0)
                break;
            for (u32 i = 0; i < 2048u; i++)
                M->adpcm_ram[S.adpcm_waddr++] = sec[i];
        }
        S.a = 0; set_nz(0);
        break;
    }

    case 18: { /* ad_read ($E036): ADPCM RAM cx -> CPU/VRAM bx */
        u16 rptr = cx;
        if (dh == 0xFFu || dh == 0x01u) {
            u16 mawr = bx;
            for (u32 i = 0; i < ax; i += 2u) {
                u8 lo = M->adpcm_ram[rptr++];
                u8 hi = M->adpcm_ram[rptr++];
                M->vram[0][mawr++ & 0x7FFFu] = (u16)(lo | ((u16)hi << 8));
            }
        } else {
            for (u32 i = 0; i < ax; i++)
                bus_write((u16)(bx + i), M->adpcm_ram[rptr++]);
        }
        S.a = 0; set_nz(0);
        break;
    }

    case 19: { /* ad_write ($E039): CPU/VRAM bx -> ADPCM RAM cx */
        psg_catch_up();
        u16 wptr = cx;
        for (u32 i = 0; i < ax; i++)
            M->adpcm_ram[wptr++] = bus_read((u16)(bx + i));
        S.a = 0; set_nz(0);
        break;
    }

    case 20: /* ad_play ($E03C) */
    case 21: /* ad_cplay ($E03F) */
        psg_catch_up();
        S.adpcm_raddr = bx;
        S.adpcm_len = ax;
        S.adpcm_freq = dh & 0x0Fu;
        S.adpcm_cmd = (dl & 1u) ? 0x00u : 0x40u;   /* bit 0 of dl = 0: auto-stop on end */
        S.adpcm_playing = 1;
        S.adpcm_end = S.adpcm_half = S.adpcm_nibble = 0;
        S.adpcm_phase = 0;
        S.adpcm_sample = 0;
        S.adpcm_ssi = 0;
        S.a = 0; set_nz(0);
        break;

    case 22: /* ad_stop ($E042) */
        psg_catch_up();
        S.adpcm_playing = 0;
        S.a = 0; set_nz(0);
        break;

    case 23: /* ad_stat ($E045) */
        S.a = S.adpcm_playing ? 0x04u : 0x00u;
        S.x = S.adpcm_end ? 0x00u : 0x01u;
        set_nz(S.a);
        break;

    case 24: /* bm_format ($E048) */
        M->bram[0] = 'H'; M->bram[1] = 'U'; M->bram[2] = 'B'; M->bram[3] = 'M';
        M->bram[4] = 0x00; M->bram[5] = 0x88; M->bram[6] = 0x10; M->bram[7] = 0x80;
        S.a = 0; set_nz(0);
        break;

    case 25: /* bm_free ($E04B) */
        zp_write(0xFC, 0xF0);
        zp_write(0xFD, 0x07);
        S.a = 0; set_nz(0);
        break;

    case 30: /* ex_getver ($E05A): System Card v3.00 */
        S.x = 0x03;
        S.y = 0x00;
        S.a = 0x00;
        set_nz(0);
        break;

    case 31: /* ex_setvec ($E05D): vector A (0..5) = X | (Y << 8) */
        if (S.a < 6u) {
            M->wram[0x0200u + S.a * 2u] = S.x;
            M->wram[0x0201u + S.a * 2u] = S.y;
        }
        break;

    case 32: { /* ex_getfnt ($E060): 8x8 / 16x16 font glyph for _ax -> _bx */
        u8 ascii = (ah == 0) ? al : ' ';
        if (ascii < 32u || ascii >= 96u) ascii = ' ';
        const u8 *g = &pce_bios_font64[(ascii - 32u) * 8u];
        u8 mode = dh & 3u;
        if (mode == 2u) {
            /* 8x8 1bpp (8 bytes) */
            for (int r = 0; r < 8; r++)
                bus_write((u16)(bx + r), g[r]);
        } else {
            /* 16x16 1bpp (32 bytes, 2x scaled) */
            for (int r = 0; r < 8; r++) {
                u8 b = g[r];
                u16 wide = 0;
                for (int k = 0; k < 8; k++)
                    if (b & (0x80u >> k))
                        wide |= (u16)(3u << (14 - k * 2));
                for (int dup = 0; dup < 2; dup++) {
                    u32 off = (u32)(r * 2 + dup) * 2u;
                    bus_write((u16)(bx + off + 0u), (u8)(wide >> 8));
                    bus_write((u16)(bx + off + 1u), (u8)wide);
                }
            }
        }
        S.a = 0; set_nz(0);
        break;
    }

    case 33: /* ex_joysns ($E063) */
    case 34: /* ex_joyrep ($E066) */
        bios_poll_joypad();
        S.a = 0; set_nz(0);
        break;

    case 40: S.vdc[0].regs[5] |= 0x04u; M->wram[0x00F3] |= 0x04u; break;   /* ex_rcron */
    case 41: S.vdc[0].regs[5] &= ~0x04u; M->wram[0x00F3] &= ~0x04u; break; /* ex_rcroff */
    case 42: S.irq_mask &= ~0x02u; break;                                   /* ex_irqon */
    case 43: S.irq_mask |= 0x02u; break;                                    /* ex_irqoff */
    case 44: S.vdc[0].regs[5] |= 0x80u; M->wram[0x00F3] |= 0x80u; break;   /* ex_bgon */
    case 45: S.vdc[0].regs[5] &= ~0x80u; M->wram[0x00F3] &= ~0x80u; break; /* ex_bgoff */
    case 46: S.vdc[0].regs[5] |= 0x40u; M->wram[0x00F3] |= 0x40u; break;   /* ex_spron */
    case 47: S.vdc[0].regs[5] &= ~0x40u; M->wram[0x00F3] &= ~0x40u; break; /* ex_sproff */
    case 48: S.vdc[0].regs[5] |= 0xC0u; M->wram[0x00F3] |= 0xC0u; break;   /* ex_dspon */
    case 49: S.vdc[0].regs[5] &= ~0xC0u; M->wram[0x00F3] &= ~0xC0u; break; /* ex_dspoff */
    case 51: vdc_satb_dma(0); break;                                        /* ex_sprdma */

    case 57: S.a = u8_to_bcd(S.a); set_nz(S.a); break;                      /* ex_binbcd */
    case 58: S.a = (u8)bcd_to_u8(S.a); set_nz(S.a); break;                  /* ex_bcdbin */
    case 59: { /* ex_rnd ($E0BA) */
        u32 r = (u32)(M->wram[0x0249] | ((u32)M->wram[0x024A] << 8)) * 1103515245u + 12345u;
        M->wram[0x0249] = (u8)(r >> 8);
        M->wram[0x024A] = (u8)(r >> 16);
        S.a = (u8)(r >> 16);
        set_nz(S.a);
        break;
    }

    case 60: { /* ma_mul8u ($E0BD): _al * _bl -> _cx */
        u16 p = (u16)al * (u16)bl;
        zp_write(0xFC, (u8)p);
        zp_write(0xFD, (u8)(p >> 8));
        break;
    }
    case 61: { /* ma_mul8s ($E0C0) */
        s16 p = (s16)(s8)al * (s16)(s8)bl;
        zp_write(0xFC, (u8)p);
        zp_write(0xFD, (u8)((u16)p >> 8));
        break;
    }
    case 62: { /* ma_mul16u ($E0C3): _ax * _bx -> _cx:_dx */
        u32 p = (u32)ax * (u32)bx;
        zp_write(0xFC, (u8)p);
        zp_write(0xFD, (u8)(p >> 8));
        zp_write(0xFE, (u8)(p >> 16));
        zp_write(0xFF, (u8)(p >> 24));
        break;
    }
    case 63: { /* ma_div16s ($E0C6): _ax / _bx -> _cx, rem _dx */
        s16 q = bx ? (s16)((s16)ax / (s16)bx) : 0;
        s16 r = bx ? (s16)((s16)ax % (s16)bx) : 0;
        zp_write(0xFC, (u8)q); zp_write(0xFD, (u8)((u16)q >> 8));
        zp_write(0xFE, (u8)r); zp_write(0xFF, (u8)((u16)r >> 8));
        break;
    }
    case 64: { /* ma_div16u ($E0C9): _ax / _bx -> _cx, rem _dx */
        u16 q = bx ? (ax / bx) : 0xFFFFu;
        u16 r = bx ? (ax % bx) : 0u;
        zp_write(0xFC, (u8)q); zp_write(0xFD, (u8)(q >> 8));
        zp_write(0xFE, (u8)r); zp_write(0xFF, (u8)(r >> 8));
        break;
    }
    case 74: /* ex_memopen ($E0DE): A=0 indicates Super System Card + Arcade Card present */
        S.a = 0x00;
        S.p &= (u8)~FC;
        set_nz(0);
        break;

    default:
        S.a = 0; set_nz(0);
        break;
    }
}

static void build_cleanroom_syscard_bios(void)
{
    for (u32 i = 0; i < sizeof(M->cd_bios); i++)
        M->cd_bios[i] = 0x60u;                      /* RTS fill */

    u8 *b0 = M->cd_bios;                            /* Page $00 mapped at $E000..$FFFF */

    /* 1. $E000..$E0E6 Jump Table: 77 entries x 3 bytes (JMP $EE00 + fn*2) */
    for (u32 fn = 0; fn < 78u; fn++) {
        u16 target = (u16)(0xEE00u + fn * 2u);
        if (fn == 39u)                              /* ex_vsync ($E07B): real HuC6280 VBlank wait! */
            target = 0xEF40u;
        b0[fn * 3u + 0u] = 0x4Cu;                   /* JMP abs */
        b0[fn * 3u + 1u] = (u8)target;
        b0[fn * 3u + 2u] = (u8)(target >> 8);
        /* At $EE00 + fn*2: NOP; RTS (intercepted at $EE00..$EE9B in cpu_step) */
        u16 stub = (u16)(0x0E00u + fn * 2u);
        b0[stub + 0u] = 0xEAu;
        b0[stub + 1u] = 0x60u;
    }

    /* 2. ex_vsync ($EF40): PHA; LDA $2241; .loop: CMP $2241; BEQ .loop; PLA; RTS */
    static const u8 vsync_code[] = {
        0x48,               /* PHA */
        0x58,               /* CLI (ensure VBlank IRQ1 can fire) */
        0xAD, 0x41, 0x22,   /* LDA $2241 */
        0xCD, 0x41, 0x22,   /* CMP $2241 */
        0xF0, 0xFB,         /* BEQ -5 */
        0x68,               /* PLA */
        0x60                /* RTS */
    };
    for (u32 i = 0; i < sizeof(vsync_code); i++)
        b0[0x0F40u + i] = vsync_code[i];

    /* 3. System Card IRQ1 handler at $EF60:
          - If bit 1 of $20F5 (irq_m) is set, JMP ($2202) to game's custom IRQ1!
          - Else save A/X/Y, read $0000 -> $20F6 (vdc_sr), on VD ($20) increment $2241,
            latch $220C/$2210 -> BXR/BYR, poll joypad if $2227 != 0, RTI. */
    static const u8 irq1_code[] = {
        0x48,               /* PHA */
        0xA5, 0xF5,         /* LDA <$F5 (irq_m) */
        0x29, 0x02,         /* AND #$02 */
        0xF0, 0x04,         /* BEQ .std_irq1 */
        0x68,               /* PLA */
        0x6C, 0x02, 0x22,   /* JMP ($2202) */
        /* .std_irq1 ($EF6B): */
        0xDA, 0x5A,         /* PHX; PHY */
        0xAD, 0x00, 0x00,   /* LDA $0000 (VDC status) */
        0x85, 0xF6,         /* STA <$F6 (vdc_sr) */
        0x29, 0x20,         /* AND #$20 (VBlank?) */
        0xF0, 0x1E,         /* BEQ .done */
        0xEE, 0x41, 0x22,   /* INC $2241 (irq_cnt) */
        /* Update BXR (reg 7) from $220C/$220D & BYR (reg 8) from $2210/$2211 */
        0x03, 0x07,         /* ST0 #$07 */
        0xAD, 0x0C, 0x22, 0x8D, 0x02, 0x00,
        0xAD, 0x0D, 0x22, 0x8D, 0x03, 0x00,
        0x03, 0x08,         /* ST0 #$08 */
        0xAD, 0x10, 0x22, 0x8D, 0x02, 0x00,
        0xAD, 0x11, 0x22, 0x8D, 0x03, 0x00,
        0x20, 0x63, 0xE0,   /* JSR ex_joysns ($E063) */
        /* .done: */
        0xA5, 0xF7,         /* LDA <$F7 (restore vdc_reg) */
        0x8D, 0x00, 0x00,   /* STA $0000 */
        0x7A, 0xFA, 0x68,   /* PLY; PLX; PLA */
        0x40                /* RTI */
    };
    for (u32 i = 0; i < sizeof(irq1_code); i++)
        b0[0x0F60u + i] = irq1_code[i];

    /* 4. IRQ2 handler ($EFB0) & TIQ handler ($EFCE) */
    static const u8 irq2_code[] = {
        0x48,
        0xA5, 0xF5, 0x29, 0x01, 0xF0, 0x04,
        0x68, 0x6C, 0x00, 0x22, /* JMP ($2200) */
        0xAD, 0x03, 0x18,       /* Read $1803 */
        0x68, 0x40              /* PLA; RTI */
    };
    for (u32 i = 0; i < sizeof(irq2_code); i++)
        b0[0x0FB0u + i] = irq2_code[i];

    static const u8 tiq_code[] = {
        0x8D, 0x03, 0x14,       /* STA $1403 (ack TIQ) */
        0x48,
        0xA5, 0xF5, 0x29, 0x04, 0xF0, 0x04,
        0x68, 0x6C, 0x04, 0x22, /* JMP ($2204) */
        0x68, 0x40              /* PLA; RTI */
    };
    for (u32 i = 0; i < sizeof(tiq_code); i++)
        b0[0x0FD0u + i] = tiq_code[i];

    static const u8 nmi_code[] = { 0x40 };          /* RTI */
    b0[0x0FF0u] = nmi_code[0];

    /* 5. Hardware vectors at $FFF6..$FFFF */
    b0[0x1FF6] = 0xB0; b0[0x1FF7] = 0xEF;           /* IRQ2  -> $EFB0 */
    b0[0x1FF8] = 0x60; b0[0x1FF9] = 0xEF;           /* IRQ1  -> $EF60 */
    b0[0x1FFA] = 0xD0; b0[0x1FFB] = 0xEF;           /* TIQ   -> $EFD0 */
    b0[0x1FFC] = 0xF0; b0[0x1FFD] = 0xEF;           /* NMI   -> $EFF0 */
    b0[0x1FFE] = 0x00; b0[0x1FFF] = 0xE0;           /* RESET -> $E000 (cd_boot) */
}
#endif

/* ========================================================================
 * HuC6280 CPU Execution
 * ======================================================================== */

static u8 do_adc(u8 lhs, u8 rhs, u32 *extra_cyc)
{
    u32 c = S.p & FC;
    if (S.p & FD) {
        *extra_cyc += 1;
        u32 lo = (lhs & 0x0Fu) + (rhs & 0x0Fu) + c;
        u32 hi = (lhs >> 4) + (rhs >> 4);
        if (lo > 9) { lo += 6; hi += 1; }
        if (hi > 9) hi += 6;
        u8 res = (u8)((hi << 4) | (lo & 0x0Fu));
        S.p = (S.p & (u8)~(FC | FN | FZ)) | (hi > 15 ? FC : 0) | (res & FN) | (res ? 0 : FZ);
        return res;
    } else {
        u32 sum = (u32)lhs + (u32)rhs + c;
        u8 res = (u8)sum;
        u8 ov = (u8)((~(lhs ^ rhs) & (lhs ^ res) & 0x80u) ? FV : 0);
        S.p = (S.p & (u8)~(FC | FV | FN | FZ)) | (sum > 0xFF ? FC : 0) | ov | (res & FN) | (res ? 0 : FZ);
        return res;
    }
}

static u8 do_sbc(u8 lhs, u8 rhs, u32 *extra_cyc)
{
    u32 c = (S.p & FC) ^ 1u;
    u32 diff = (u32)lhs - (u32)rhs - c;
    if (S.p & FD) {
        *extra_cyc += 1;
        s32 lo = (s32)(lhs & 0x0Fu) - (s32)(rhs & 0x0Fu) - (s32)c;
        s32 hi = (s32)(lhs >> 4) - (s32)(rhs >> 4);
        if (lo < 0) { lo -= 6; hi -= 1; }
        if (hi < 0) hi -= 6;
        u8 res = (u8)(((u32)hi << 4) | ((u32)lo & 0x0Fu));
        S.p = (S.p & (u8)~(FC | FN | FZ)) | (diff < 0x100 ? FC : 0) | (res & FN) | (res ? 0 : FZ);
        return res;
    } else {
        u8 res = (u8)diff;
        u8 ov = (u8)(((lhs ^ rhs) & (lhs ^ diff) & 0x80u) ? FV : 0);
        S.p = (S.p & (u8)~(FC | FV | FN | FZ)) | (diff < 0x100 ? FC : 0) | ov | (res & FN) | (res ? 0 : FZ);
        return res;
    }
}

static void do_cmp(u8 reg, u8 v)
{
    u32 d = (u32)reg - (u32)v;
    u8 r = (u8)d;
    S.p = (S.p & (u8)~(FC | FN | FZ)) | (d < 0x100 ? FC : 0) | (r & FN) | (r ? 0 : FZ);
}

static u32 do_branch(int cond)
{
    s32 rel = (signed char)fetch8();
    if (!cond)
        return 2;
    S.pc = (u16)(S.pc + rel);
    return 4;
}

static u32 do_block(int mode)
{
    u16 src = fetch16();
    u16 dst = fetch16();
    u16 len = fetch16();
    u32 count = len ? (u32)len : 0x10000u;
    push8(S.y);
    push8(S.a);
    push8(S.x);
    u16 alt = 0;
    for (u32 i = 0; i < count; i++) {
        u16 rs = (mode == 4) ? (u16)(src + alt) : src;
        u16 wd = (mode == 3) ? (u16)(dst + alt) : dst;
        u8 v = bus_read(rs);
        bus_write(wd, v);
        alt ^= 1u;
        if (mode == 0)      { src++; dst++; }
        else if (mode == 1) { src--; dst--; }
        else if (mode == 2) { src++; }
        else if (mode == 3) { src++; }
        else                { dst++; }
    }
    S.x = pull8();
    S.a = pull8();
    S.y = pull8();
    return 17u + count * 6u;
}

static u32 cpu_step(void)
{
#ifndef PCE_CPU_TEST
    /* Intercept clean-room System Card 3.0 BIOS stubs at $EE00..$EE9B (MPR7 == $00) */
    if (S.cd_mode && !S.ext_bios && S.mpr[7] == 0x00 &&
        S.pc >= 0xEE00u && S.pc < 0xEE9Cu && ((S.pc & 1u) == 0u)) {
        u8 fn = (u8)((S.pc - 0xEE00u) >> 1);
        S.pc++;                                     /* advance to RTS ($EE01 + fn*2) */
        bios_hle_call(fn);
        return 12;
    }
#endif

    u8 op = fetch8();
    u8 tflag = S.p & FT;
    S.p &= (u8)~FT;
    u32 cyc = 2, extra = 0;
    u16 ea;
    u8 v, zp;

    if ((op & 0x0F) == 0x07) {
        u8 bit = (u8)(1u << ((op >> 4) & 7));
        zp = fetch8();
        v = zp_read(zp);
        if (op & 0x80) zp_write(zp, (u8)(v | bit));
        else           zp_write(zp, (u8)(v & ~bit));
        return 7;
    }
    if ((op & 0x0F) == 0x0F) {
        u8 bit = (u8)(1u << ((op >> 4) & 7));
        zp = fetch8();
        v = zp_read(zp);
        s32 rel = (signed char)fetch8();
        int hit = (op & 0x80) ? ((v & bit) != 0) : ((v & bit) == 0);
        if (hit) {
            S.pc = (u16)(S.pc + rel);
            return 8;
        }
        return 6;
    }

    switch (op) {
    case 0x00:
        S.pc++;
        push16(S.pc);
        push8((u8)(S.p | FB));
        S.p = (S.p & (u8)~FD) | FI;
        S.pc = bus_read(0xFFF6) | ((u16)bus_read(0xFFF7) << 8);
        return 8;
    case 0x40:
        S.p = (u8)(pull8() & ~FB);
        S.pc = pull16();
        return 7;
    case 0x60:
        S.pc = (u16)(pull16() + 1u);
        return 7;
    case 0x20:
        ea = fetch16();
        push16((u16)(S.pc - 1u));
        S.pc = ea;
        return 7;
    case 0x44: {
        s32 rel = (signed char)fetch8();
        push16((u16)(S.pc - 1u));
        S.pc = (u16)(S.pc + rel);
        return 8;
    }
    case 0x4C:
        S.pc = fetch16();
        return 4;
    case 0x6C:
        ea = fetch16();
        S.pc = bus_read(ea) | ((u16)bus_read((u16)(ea + 1)) << 8);
        return 7;
    case 0x7C:
        ea = (u16)(fetch16() + S.x);
        S.pc = bus_read(ea) | ((u16)bus_read((u16)(ea + 1)) << 8);
        return 7;

    case 0x02: v = S.x; S.x = S.y; S.y = v; return 3;
    case 0x22: v = S.a; S.a = S.x; S.x = v; return 3;
    case 0x42: v = S.a; S.a = S.y; S.y = v; return 3;
    case 0x62: S.a = 0; return 2;
    case 0x82: S.x = 0; return 2;
    case 0xC2: S.y = 0; return 2;
    case 0x54: S.speed = 4; return 3;
    case 0xD4: S.speed = 1; return 3;
    case 0xF4: S.p |= FT; return 2;

    case 0x03:
        v = fetch8();
#ifdef PCE_CPU_TEST
        pce_sst_ram[0x1FE000] = v;
        return 4;
#else
        vdc_write_chip(S.sgx_mode ? S.vpc_st_mode : 0, 0, v);
        return 5;
#endif
    case 0x13:
        v = fetch8();
#ifdef PCE_CPU_TEST
        pce_sst_ram[0x1FE002] = v;
        return 4;
#else
        vdc_write_chip(S.sgx_mode ? S.vpc_st_mode : 0, 2, v);
        return 5;
#endif
    case 0x23:
        v = fetch8();
#ifdef PCE_CPU_TEST
        pce_sst_ram[0x1FE003] = v;
        return 4;
#else
        vdc_write_chip(S.sgx_mode ? S.vpc_st_mode : 0, 3, v);
        return 5;
#endif

    case 0x43:
        v = fetch8();
        if (v) {
            u8 ored = 0;
            for (int i = 0; i < 8; i++)
                if (v & (1u << i))
                    ored |= S.mpr[i];
            S.mpr_latch = ored;
        }
        S.a = S.mpr_latch;
        return 4;
    case 0x53:
        v = fetch8();
        if (v) {
            S.mpr_latch = S.a;
            for (int i = 0; i < 8; i++) {
                if (v & (1u << i)) {
                    S.mpr[i] = S.a;
#ifndef PCE_CPU_TEST
                    sync_mpr(i);
#endif
                }
            }
        }
        return 5;

    case 0x73: return do_block(0);
    case 0xC3: return do_block(1);
    case 0xD3: return do_block(2);
    case 0xE3: return do_block(3);
    case 0xF3: return do_block(4);

    case 0x83: v = fetch8(); zp = fetch8(); ea = zp_read(zp); goto do_tst7;
    case 0xA3: v = fetch8(); zp = (u8)(fetch8() + S.x); ea = zp_read(zp); goto do_tst7;
    case 0x93: v = fetch8(); ea = bus_read(fetch16()); cyc = 8; goto do_tst;
    case 0xB3: v = fetch8(); ea = bus_read((u16)(fetch16() + S.x)); cyc = 8; goto do_tst;
    do_tst7:
        cyc = 7;
    do_tst:
        S.p = (S.p & (u8)~(FN | FV | FZ)) | ((u8)ea & (FN | FV)) | ((v & (u8)ea) ? 0 : FZ);
        return cyc;

    case 0x80: return do_branch(1);
    case 0x10: return do_branch(!(S.p & FN));
    case 0x30: return do_branch((S.p & FN) != 0);
    case 0x50: return do_branch(!(S.p & FV));
    case 0x70: return do_branch((S.p & FV) != 0);
    case 0x90: return do_branch(!(S.p & FC));
    case 0xB0: return do_branch((S.p & FC) != 0);
    case 0xD0: return do_branch(!(S.p & FZ));
    case 0xF0: return do_branch((S.p & FZ) != 0);

    case 0x18: S.p &= (u8)~FC; return 2;
    case 0x38: S.p |= FC; return 2;
    case 0x58: S.p &= (u8)~FI; return 2;
    case 0x78: S.p |= FI; return 2;
    case 0xB8: S.p &= (u8)~FV; return 2;
    case 0xD8: S.p &= (u8)~FD; return 2;
    case 0xF8: S.p |= FD; return 2;

    case 0x48: push8(S.a); return 3;
    case 0x68: S.a = pull8(); set_nz(S.a); return 4;
    case 0xDA: push8(S.x); return 3;
    case 0xFA: S.x = pull8(); set_nz(S.x); return 4;
    case 0x5A: push8(S.y); return 3;
    case 0x7A: S.y = pull8(); set_nz(S.y); return 4;
    case 0x08: push8((u8)(S.p | FB)); return 3;
    case 0x28: S.p = (u8)(pull8() & ~FB); return 4;

    case 0xAA: S.x = S.a; set_nz(S.x); return 2;
    case 0x8A: S.a = S.x; set_nz(S.a); return 2;
    case 0xA8: S.y = S.a; set_nz(S.y); return 2;
    case 0x98: S.a = S.y; set_nz(S.a); return 2;
    case 0xBA: S.x = S.s; set_nz(S.x); return 2;
    case 0x9A: S.s = S.x; return 2;
    case 0xEA: return 2;
    case 0xE8: S.x++; set_nz(S.x); return 2;
    case 0xCA: S.x--; set_nz(S.x); return 2;
    case 0xC8: S.y++; set_nz(S.y); return 2;
    case 0x88: S.y--; set_nz(S.y); return 2;
    case 0x1A: S.a++; set_nz(S.a); return 2;
    case 0x3A: S.a--; set_nz(S.a); return 2;

    case 0x09: v = fetch8(); cyc = 2; goto op_ora;
    case 0x05: v = zp_read(fetch8()); cyc = 4; goto op_ora;
    case 0x15: v = zp_read((u8)(fetch8() + S.x)); cyc = 4; goto op_ora;
    case 0x0D: v = bus_read(fetch16()); cyc = 5; goto op_ora;
    case 0x1D: v = bus_read((u16)(fetch16() + S.x)); cyc = 5; goto op_ora;
    case 0x19: v = bus_read((u16)(fetch16() + S.y)); cyc = 5; goto op_ora;
    case 0x01: v = bus_read(zp_ind((u8)(fetch8() + S.x))); cyc = 7; goto op_ora;
    case 0x11: v = bus_read((u16)(zp_ind(fetch8()) + S.y)); cyc = 7; goto op_ora;
    case 0x12: v = bus_read(zp_ind(fetch8())); cyc = 7; goto op_ora;
    op_ora:
        if (tflag) { u8 m = (u8)(zp_read(S.x) | v); zp_write(S.x, m); set_nz(m); return cyc + 3; }
        S.a |= v; set_nz(S.a); return cyc;

    case 0x29: v = fetch8(); cyc = 2; goto op_and;
    case 0x25: v = zp_read(fetch8()); cyc = 4; goto op_and;
    case 0x35: v = zp_read((u8)(fetch8() + S.x)); cyc = 4; goto op_and;
    case 0x2D: v = bus_read(fetch16()); cyc = 5; goto op_and;
    case 0x3D: v = bus_read((u16)(fetch16() + S.x)); cyc = 5; goto op_and;
    case 0x39: v = bus_read((u16)(fetch16() + S.y)); cyc = 5; goto op_and;
    case 0x21: v = bus_read(zp_ind((u8)(fetch8() + S.x))); cyc = 7; goto op_and;
    case 0x31: v = bus_read((u16)(zp_ind(fetch8()) + S.y)); cyc = 7; goto op_and;
    case 0x32: v = bus_read(zp_ind(fetch8())); cyc = 7; goto op_and;
    op_and:
        if (tflag) { u8 m = (u8)(zp_read(S.x) & v); zp_write(S.x, m); set_nz(m); return cyc + 3; }
        S.a &= v; set_nz(S.a); return cyc;

    case 0x49: v = fetch8(); cyc = 2; goto op_eor;
    case 0x45: v = zp_read(fetch8()); cyc = 4; goto op_eor;
    case 0x55: v = zp_read((u8)(fetch8() + S.x)); cyc = 4; goto op_eor;
    case 0x4D: v = bus_read(fetch16()); cyc = 5; goto op_eor;
    case 0x5D: v = bus_read((u16)(fetch16() + S.x)); cyc = 5; goto op_eor;
    case 0x59: v = bus_read((u16)(fetch16() + S.y)); cyc = 5; goto op_eor;
    case 0x41: v = bus_read(zp_ind((u8)(fetch8() + S.x))); cyc = 7; goto op_eor;
    case 0x51: v = bus_read((u16)(zp_ind(fetch8()) + S.y)); cyc = 7; goto op_eor;
    case 0x52: v = bus_read(zp_ind(fetch8())); cyc = 7; goto op_eor;
    op_eor:
        if (tflag) { u8 m = (u8)(zp_read(S.x) ^ v); zp_write(S.x, m); set_nz(m); return cyc + 3; }
        S.a ^= v; set_nz(S.a); return cyc;

    case 0x69: v = fetch8(); cyc = 2; goto op_adc;
    case 0x65: v = zp_read(fetch8()); cyc = 4; goto op_adc;
    case 0x75: v = zp_read((u8)(fetch8() + S.x)); cyc = 4; goto op_adc;
    case 0x6D: v = bus_read(fetch16()); cyc = 5; goto op_adc;
    case 0x7D: v = bus_read((u16)(fetch16() + S.x)); cyc = 5; goto op_adc;
    case 0x79: v = bus_read((u16)(fetch16() + S.y)); cyc = 5; goto op_adc;
    case 0x61: v = bus_read(zp_ind((u8)(fetch8() + S.x))); cyc = 7; goto op_adc;
    case 0x71: v = bus_read((u16)(zp_ind(fetch8()) + S.y)); cyc = 7; goto op_adc;
    case 0x72: v = bus_read(zp_ind(fetch8())); cyc = 7; goto op_adc;
    op_adc:
        if (tflag) { u8 m = do_adc(zp_read(S.x), v, &extra); zp_write(S.x, m); return cyc + 3 + extra; }
        S.a = do_adc(S.a, v, &extra); return cyc + extra;

    case 0xE9: v = fetch8(); cyc = 2; goto op_sbc;
    case 0xE5: v = zp_read(fetch8()); cyc = 4; goto op_sbc;
    case 0xF5: v = zp_read((u8)(fetch8() + S.x)); cyc = 4; goto op_sbc;
    case 0xED: v = bus_read(fetch16()); cyc = 5; goto op_sbc;
    case 0xFD: v = bus_read((u16)(fetch16() + S.x)); cyc = 5; goto op_sbc;
    case 0xF9: v = bus_read((u16)(fetch16() + S.y)); cyc = 5; goto op_sbc;
    case 0xE1: v = bus_read(zp_ind((u8)(fetch8() + S.x))); cyc = 7; goto op_sbc;
    case 0xF1: v = bus_read((u16)(zp_ind(fetch8()) + S.y)); cyc = 7; goto op_sbc;
    case 0xF2: v = bus_read(zp_ind(fetch8())); cyc = 7; goto op_sbc;
    op_sbc:
        S.a = do_sbc(S.a, v, &extra); return cyc + extra;

    case 0xC9: do_cmp(S.a, fetch8()); return 2;
    case 0xC5: do_cmp(S.a, zp_read(fetch8())); return 4;
    case 0xD5: do_cmp(S.a, zp_read((u8)(fetch8() + S.x))); return 4;
    case 0xCD: do_cmp(S.a, bus_read(fetch16())); return 5;
    case 0xDD: do_cmp(S.a, bus_read((u16)(fetch16() + S.x))); return 5;
    case 0xD9: do_cmp(S.a, bus_read((u16)(fetch16() + S.y))); return 5;
    case 0xC1: do_cmp(S.a, bus_read(zp_ind((u8)(fetch8() + S.x)))); return 7;
    case 0xD1: do_cmp(S.a, bus_read((u16)(zp_ind(fetch8()) + S.y))); return 7;
    case 0xD2: do_cmp(S.a, bus_read(zp_ind(fetch8()))); return 7;

    case 0xE0: do_cmp(S.x, fetch8()); return 2;
    case 0xE4: do_cmp(S.x, zp_read(fetch8())); return 4;
    case 0xEC: do_cmp(S.x, bus_read(fetch16())); return 5;
    case 0xC0: do_cmp(S.y, fetch8()); return 2;
    case 0xC4: do_cmp(S.y, zp_read(fetch8())); return 4;
    case 0xCC: do_cmp(S.y, bus_read(fetch16())); return 5;

    case 0x89: v = fetch8(); cyc = 2; goto op_bit;
    case 0x24: v = zp_read(fetch8()); cyc = 4; goto op_bit;
    case 0x34: v = zp_read((u8)(fetch8() + S.x)); cyc = 4; goto op_bit;
    case 0x2C: v = bus_read(fetch16()); cyc = 5; goto op_bit;
    case 0x3C: v = bus_read((u16)(fetch16() + S.x)); cyc = 5; goto op_bit;
    op_bit:
        S.p = (S.p & (u8)~(FN | FV | FZ)) | (v & (FN | FV)) | ((S.a & v) ? 0 : FZ);
        return cyc;

    case 0xA9: S.a = fetch8(); set_nz(S.a); return 2;
    case 0xA5: S.a = zp_read(fetch8()); set_nz(S.a); return 4;
    case 0xB5: S.a = zp_read((u8)(fetch8() + S.x)); set_nz(S.a); return 4;
    case 0xAD: S.a = bus_read(fetch16()); set_nz(S.a); return 5;
    case 0xBD: S.a = bus_read((u16)(fetch16() + S.x)); set_nz(S.a); return 5;
    case 0xB9: S.a = bus_read((u16)(fetch16() + S.y)); set_nz(S.a); return 5;
    case 0xA1: S.a = bus_read(zp_ind((u8)(fetch8() + S.x))); set_nz(S.a); return 7;
    case 0xB1: S.a = bus_read((u16)(zp_ind(fetch8()) + S.y)); set_nz(S.a); return 7;
    case 0xB2: S.a = bus_read(zp_ind(fetch8())); set_nz(S.a); return 7;

    case 0xA2: S.x = fetch8(); set_nz(S.x); return 2;
    case 0xA6: S.x = zp_read(fetch8()); set_nz(S.x); return 4;
    case 0xB6: S.x = zp_read((u8)(fetch8() + S.y)); set_nz(S.x); return 4;
    case 0xAE: S.x = bus_read(fetch16()); set_nz(S.x); return 5;
    case 0xBE: S.x = bus_read((u16)(fetch16() + S.y)); set_nz(S.x); return 5;

    case 0xA0: S.y = fetch8(); set_nz(S.y); return 2;
    case 0xA4: S.y = zp_read(fetch8()); set_nz(S.y); return 4;
    case 0xB4: S.y = zp_read((u8)(fetch8() + S.x)); set_nz(S.y); return 4;
    case 0xAC: S.y = bus_read(fetch16()); set_nz(S.y); return 5;
    case 0xBC: S.y = bus_read((u16)(fetch16() + S.x)); set_nz(S.y); return 5;

    case 0x85: zp_write(fetch8(), S.a); return 4;
    case 0x95: zp_write((u8)(fetch8() + S.x), S.a); return 4;
    case 0x8D: bus_write(fetch16(), S.a); return 5;
    case 0x9D: bus_write((u16)(fetch16() + S.x), S.a); return 5;
    case 0x99: bus_write((u16)(fetch16() + S.y), S.a); return 5;
    case 0x81: bus_write(zp_ind((u8)(fetch8() + S.x)), S.a); return 7;
    case 0x91: bus_write((u16)(zp_ind(fetch8()) + S.y), S.a); return 7;
    case 0x92: bus_write(zp_ind(fetch8()), S.a); return 7;

    case 0x86: zp_write(fetch8(), S.x); return 4;
    case 0x96: zp_write((u8)(fetch8() + S.y), S.x); return 4;
    case 0x8E: bus_write(fetch16(), S.x); return 5;

    case 0x84: zp_write(fetch8(), S.y); return 4;
    case 0x94: zp_write((u8)(fetch8() + S.x), S.y); return 4;
    case 0x8C: bus_write(fetch16(), S.y); return 5;

    case 0x64: zp_write(fetch8(), 0); return 4;
    case 0x74: zp_write((u8)(fetch8() + S.x), 0); return 4;
    case 0x9C: bus_write(fetch16(), 0); return 5;
    case 0x9E: bus_write((u16)(fetch16() + S.x), 0); return 5;

    case 0x0A: S.p = (S.p & (u8)~FC) | (S.a >> 7); S.a <<= 1; set_nz(S.a); return 2;
    case 0x4A: S.p = (S.p & (u8)~FC) | (S.a & 1u); S.a >>= 1; set_nz(S.a); return 2;
    case 0x2A: v = S.p & FC; S.p = (S.p & (u8)~FC) | (S.a >> 7); S.a = (u8)((S.a << 1) | v); set_nz(S.a); return 2;
    case 0x6A: v = (u8)((S.p & FC) << 7); S.p = (S.p & (u8)~FC) | (S.a & 1u); S.a = (u8)((S.a >> 1) | v); set_nz(S.a); return 2;

    case 0x06: zp = fetch8(); v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v >> 7); v <<= 1; zp_write(zp, v); set_nz(v); return 6;
    case 0x16: zp = (u8)(fetch8() + S.x); v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v >> 7); v <<= 1; zp_write(zp, v); set_nz(v); return 6;
    case 0x0E: ea = fetch16(); v = bus_read(ea); S.p = (S.p & (u8)~FC) | (v >> 7); v <<= 1; bus_write(ea, v); set_nz(v); return 7;
    case 0x1E: ea = (u16)(fetch16() + S.x); v = bus_read(ea); S.p = (S.p & (u8)~FC) | (v >> 7); v <<= 1; bus_write(ea, v); set_nz(v); return 7;

    case 0x46: zp = fetch8(); v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v & 1u); v >>= 1; zp_write(zp, v); set_nz(v); return 6;
    case 0x56: zp = (u8)(fetch8() + S.x); v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v & 1u); v >>= 1; zp_write(zp, v); set_nz(v); return 6;
    case 0x4E: ea = fetch16(); v = bus_read(ea); S.p = (S.p & (u8)~FC) | (v & 1u); v >>= 1; bus_write(ea, v); set_nz(v); return 7;
    case 0x5E: ea = (u16)(fetch16() + S.x); v = bus_read(ea); S.p = (S.p & (u8)~FC) | (v & 1u); v >>= 1; bus_write(ea, v); set_nz(v); return 7;

    case 0x26: zp = fetch8(); ea = S.p & FC; v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v >> 7); v = (u8)((v << 1) | ea); zp_write(zp, v); set_nz(v); return 6;
    case 0x36: zp = (u8)(fetch8() + S.x); ea = S.p & FC; v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v >> 7); v = (u8)((v << 1) | ea); zp_write(zp, v); set_nz(v); return 6;
    case 0x2E: ea = fetch16(); v = bus_read(ea); cyc = S.p & FC; S.p = (S.p & (u8)~FC) | (v >> 7); v = (u8)((v << 1) | cyc); bus_write(ea, v); set_nz(v); return 7;
    case 0x3E: ea = (u16)(fetch16() + S.x); v = bus_read(ea); cyc = S.p & FC; S.p = (S.p & (u8)~FC) | (v >> 7); v = (u8)((v << 1) | cyc); bus_write(ea, v); set_nz(v); return 7;

    case 0x66: zp = fetch8(); ea = (u16)((S.p & FC) << 7); v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v & 1u); v = (u8)((v >> 1) | ea); zp_write(zp, v); set_nz(v); return 6;
    case 0x76: zp = (u8)(fetch8() + S.x); ea = (u16)((S.p & FC) << 7); v = zp_read(zp); S.p = (S.p & (u8)~FC) | (v & 1u); v = (u8)((v >> 1) | ea); zp_write(zp, v); set_nz(v); return 6;
    case 0x6E: ea = fetch16(); v = bus_read(ea); cyc = (u32)((S.p & FC) << 7); S.p = (S.p & (u8)~FC) | (v & 1u); v = (u8)((v >> 1) | cyc); bus_write(ea, v); set_nz(v); return 7;
    case 0x7E: ea = (u16)(fetch16() + S.x); v = bus_read(ea); cyc = (u32)((S.p & FC) << 7); S.p = (S.p & (u8)~FC) | (v & 1u); v = (u8)((v >> 1) | cyc); bus_write(ea, v); set_nz(v); return 7;

    case 0xE6: zp = fetch8(); v = (u8)(zp_read(zp) + 1u); zp_write(zp, v); set_nz(v); return 6;
    case 0xF6: zp = (u8)(fetch8() + S.x); v = (u8)(zp_read(zp) + 1u); zp_write(zp, v); set_nz(v); return 6;
    case 0xEE: ea = fetch16(); v = (u8)(bus_read(ea) + 1u); bus_write(ea, v); set_nz(v); return 7;
    case 0xFE: ea = (u16)(fetch16() + S.x); v = (u8)(bus_read(ea) + 1u); bus_write(ea, v); set_nz(v); return 7;

    case 0xC6: zp = fetch8(); v = (u8)(zp_read(zp) - 1u); zp_write(zp, v); set_nz(v); return 6;
    case 0xD6: zp = (u8)(fetch8() + S.x); v = (u8)(zp_read(zp) - 1u); zp_write(zp, v); set_nz(v); return 6;
    case 0xCE: ea = fetch16(); v = (u8)(bus_read(ea) - 1u); bus_write(ea, v); set_nz(v); return 7;
    case 0xDE: ea = (u16)(fetch16() + S.x); v = (u8)(bus_read(ea) - 1u); bus_write(ea, v); set_nz(v); return 7;

    case 0x04:
        zp = fetch8(); v = zp_read(zp);
        S.p = (S.p & (u8)~(FN | FV | FZ)) | (v & (FN | FV)) | ((S.a & v) ? 0 : FZ);
        zp_write(zp, (u8)(v | S.a));
        return 6;
    case 0x0C:
        ea = fetch16(); v = bus_read(ea);
        S.p = (S.p & (u8)~(FN | FV | FZ)) | (v & (FN | FV)) | ((S.a & v) ? 0 : FZ);
        bus_write(ea, (u8)(v | S.a));
        return 7;
    case 0x14:
        zp = fetch8(); v = zp_read(zp);
        S.p = (S.p & (u8)~(FN | FV | FZ)) | (v & (FN | FV)) | ((S.a & v) ? 0 : FZ);
        zp_write(zp, (u8)(v & (u8)~S.a));
        return 6;
    case 0x1C:
        ea = fetch16(); v = bus_read(ea);
        S.p = (S.p & (u8)~(FN | FV | FZ)) | (v & (FN | FV)) | ((S.a & v) ? 0 : FZ);
        bus_write(ea, (u8)(v & (u8)~S.a));
        return 7;

    default:
        return 2;
    }
}

static void check_interrupts(void)
{
    if (S.p & FI)
        return;
    u8 active = S.irq_lines & (u8)~S.irq_mask;
    if (!active)
        return;
    u16 vec = (active & 0x04) ? 0xFFFA : (active & 0x02) ? 0xFFF8 : 0xFFF6;
    push16(S.pc);
    push8((u8)(S.p & ~FB));
    S.p = (S.p & (u8)~(FD | FT)) | FI;
    S.pc = bus_read(vec) | ((u16)bus_read((u16)(vec + 1)) << 8);
    S.cycles += 8u * S.speed;
}

static void run_cycles_7m(u32 budget)
{
    S.cyc_debt += (s32)budget;
    while (S.cyc_debt > 0) {
        u32 before = S.cycles;
        check_interrupts();
        S.cyc_debt -= (s32)(S.cycles - before);
        if (S.cyc_debt <= 0)
            break;
#ifndef PCE_CPU_TEST
        if (!(S.p & FT) && S.cyc_debt > 0) {
            const u8 *code_page = S.mpr_r[S.pc >> 13];
            u16 off = S.pc & 0x1FFFu;
            if (code_page && off <= 0x1FFAu && !(S.cd_mode && !S.ext_bios && S.mpr[7] == 0 && S.pc >= 0xEE00u && S.pc < 0xEE9Cu)) {
                const u8 *code = code_page + off;
                u32 loop_cpu = 0;
                int set_a = -1;
                if (code[0] == 0x80 && code[1] == 0xFE) {
                    loop_cpu = 4;
                } else if (code[0] == 0x4C && (u16)(code[1] | ((u16)code[2] << 8)) == S.pc) {
                    loop_cpu = 4;
                } else if ((code[0] & 0x0F) == 0x0F && code[2] == 0xFD && S.mpr_r[1] == M->wram) {
                    u8 bit = (u8)(1u << ((code[0] >> 4) & 7));
                    u8 zv = M->wram[code[1]];
                    if ((code[0] & 0x80) ? ((zv & bit) != 0) : ((zv & bit) == 0))
                        loop_cpu = 8;
                } else if (code[0] == 0xA5 && (code[2] == 0xD0 || code[2] == 0xF0) &&
                           code[3] == 0xFC && S.mpr_r[1] == M->wram) {
                    u8 zv = M->wram[code[1]];
                    if ((code[2] == 0xD0) ? (zv != 0) : (zv == 0)) {
                        loop_cpu = 8;
                        set_a = zv;
                    }
                } else if (code[0] == 0xAD && (code[3] == 0xD0 || code[3] == 0xF0) && code[4] == 0xFB) {
                    u16 ea = (u16)(code[1] | ((u16)code[2] << 8));
                    const u8 *rp = S.mpr_r[ea >> 13];
                    if (rp) {
                        u8 mv = rp[ea & 0x1FFFu];
                        if ((code[3] == 0xD0) ? (mv != 0) : (mv == 0)) {
                            loop_cpu = 9;
                            set_a = mv;
                        }
                    }
                }
                if (loop_cpu) {
                    u32 loop_cyc = loop_cpu * S.speed;
                    u32 rem = (u32)S.cyc_debt;
                    if (rem > loop_cyc) {
                        u32 iters = (rem - 1u) / loop_cyc;
                        if (S.tmr_on) {
                            u32 t_iters = S.tmr_prescale > (s32)loop_cyc
                                        ? (u32)(S.tmr_prescale - 1) / loop_cyc : 0;
                            if (iters > t_iters)
                                iters = t_iters;
                        }
                        if (iters > 0) {
                            if (set_a >= 0) {
                                S.a = (u8)set_a;
                                set_nz(S.a);
                            }
                            u32 adv = iters * loop_cyc;
                            S.cycles += adv;
                            S.cyc_debt -= (s32)adv;
                            if (S.tmr_on)
                                S.tmr_prescale -= (s32)adv;
                        }
                    }
                }
            }
        }
#endif
        u32 c = cpu_step() * S.speed;
        S.cycles += c;
        S.cyc_debt -= (s32)c;
        if (S.tmr_on) {
            S.tmr_prescale -= (s32)c;
            while (S.tmr_prescale <= 0) {
                S.tmr_prescale += 1024;
                if (S.tmr_cnt == 0) {
                    S.tmr_cnt = S.tmr_reload;
                    S.irq_lines |= 0x04;
                } else {
                    S.tmr_cnt--;
                }
            }
        }
    }
}

/* ========================================================================
 * Scanline Renderer (Single VDC + SuperGrafx Dual-VDC VPC Mixer)
 * ======================================================================== */

static int calc_width(void)
{
    int hdw = ((S.vdc[0].regs[11] & 0x7Fu) + 1) * 8;
    int dot = S.vce_ctrl & 3;
    int def_w = dot == 0 ? 256 : dot == 1 ? 320 : 512;
    if (hdw >= 128 && hdw <= PCE_W_MAX)
        return hdw;
    return def_w;
}

static void render_vdc_scanline(int chip, int y, u16 *dst, int w, int sgx_raw)
{
    struct pce_vdc *vdc = &S.vdc[chip];
    const u16 *vram = M->vram[chip];
    const u16 *satb = M->satb[chip];
    u16 cr = vdc->regs[5];
    u16 bg0 = sgx_raw ? SGX_TRANSP : M->vce_pal[0];
    u16 overscan = sgx_raw ? SGX_TRANSP : M->vce_pal[0x100];
    u8 bg_opaque[PCE_W_MAX];

    if (cr & 0x80) {
        static const int bat_w_tab[8] = {32, 64, 128, 128, 32, 64, 128, 128};
        int mwr = (vdc->regs[9] >> 4) & 7;
        int bw_mask = bat_w_tab[mwr] - 1;
        int bh_mask = (mwr & 4) ? 63 : 31;
        int bat_stride = bat_w_tab[mwr];

        u32 sy = vdc->bg_y & (u32)((bh_mask << 3) | 7);
        u32 row_bat = (sy >> 3) * (u32)bat_stride;
        u32 ty = sy & 7u;
        u32 bxr = vdc->regs[7] & 0x3FFu;

        int tx = (int)(bxr >> 3);
        int fine_x = (int)(bxr & 7u);
        int x = -fine_x;
        while (x < w) {
            u16 entry = vram[(row_bat + (u32)(tx & bw_mask)) & 0x7FFFu];
            u32 tile_base = ((u32)(entry & 0x0FFFu) << 4);
            u16 pal_base = (u16)((entry >> 12) << 4);
            const u16 *pal = &M->vce_pal[pal_base];
            u16 w01 = (tile_base + ty) < 0x8000u ? vram[tile_base + ty] : 0;
            u16 w23 = (tile_base + 8u + ty) < 0x8000u ? vram[tile_base + 8u + ty] : 0;
            u32 pix8 = M->spread8[w01 & 0xFFu] | (M->spread8[w01 >> 8] << 1) |
                       (M->spread8[w23 & 0xFFu] << 2) | (M->spread8[w23 >> 8] << 3);
            if (x >= 0 && x + 8 <= w) {
                if (!pix8) {
                    for (int b = 0; b < 8; b++) {
                        bg_opaque[x + b] = 0;
                        dst[x + b] = bg0;
                    }
                } else {
                    for (int b = 0; b < 8; b++) {
                        u8 px = (u8)(pix8 & 0x0Fu);
                        pix8 >>= 4;
                        bg_opaque[x + b] = px;
                        dst[x + b] = px ? (sgx_raw ? (u16)(pal_base + px) : pal[px]) : bg0;
                    }
                }
            } else {
                int b_start = x < 0 ? -x : 0;
                int b_end = (x + 8 > w) ? (w - x) : 8;
                for (int b = b_start; b < b_end; b++) {
                    u8 px = (u8)((pix8 >> (b * 4)) & 0x0Fu);
                    int dx = x + b;
                    bg_opaque[dx] = px;
                    dst[dx] = px ? (sgx_raw ? (u16)(pal_base + px) : pal[px]) : bg0;
                }
            }
            x += 8;
            tx++;
        }
    } else {
        for (int x = 0; x < w; x++) {
            bg_opaque[x] = 0;
            dst[x] = overscan;
        }
    }

    if (!(cr & 0x40))
        return;

    u8 spr_drawn[PCE_W_MAX];
    u8 spr0_mask[PCE_W_MAX];
    for (int x = 0; x < w; x++) {
        spr_drawn[x] = 0;
        spr0_mask[x] = 0;
    }

    int cells = 0, hit0 = 0;
    for (int i = 0; i < 64; i++) {
        const u16 *s = &satb[i * 4];
        int sy = (int)(s[0] & 0x3FFu) - 64;
        int cgy = (s[3] >> 12) & 3;
        int sh = cgy == 0 ? 16 : cgy == 1 ? 32 : 64;
        if (y < sy || y >= sy + sh)
            continue;
        int cgx = (s[3] >> 8) & 1;
        int orig_cells = cgx ? 2 : 1;
        int sw_cells = orig_cells;
        if (cells + sw_cells > 16) {
            if (cells >= 16) {
                if (cr & 0x02) {
                    vdc->status |= 0x02;
                    vdc_update_irq();
                }
                break;
            }
            sw_cells = 1;
            if (cr & 0x02) {
                vdc->status |= 0x02;
                vdc_update_irq();
            }
        }
        cells += sw_cells;

        int sx = (int)(s[1] & 0x3FFu) - 32;
        u32 pat = (s[2] >> 1) & 0x3FFu;
        if (cgx) pat &= ~1u;
        if (cgy == 1) pat &= ~2u;
        else if (cgy >= 2) pat &= ~6u;

        int row = y - sy;
        if (s[3] & 0x8000u)
            row = (sh - 1) - row;
        u32 pat_y = pat + (u32)((row >> 4) * 2);
        u32 line_in_cell = (u32)(row & 15);
        int xflip = (s[3] & 0x0800u) != 0;
        int fg = (s[3] & 0x0080u) != 0;
        u16 pal_base = (u16)(0x100u + ((s[3] & 0x0Fu) << 4));
        const u16 *pal = &M->vce_pal[pal_base];

        for (int c = 0; c < sw_cells; c++) {
            int cx = sx + c * 16;
            if (cx + 16 <= 0 || cx >= w)
                continue;
            u32 cell_pat = pat_y + (u32)(xflip ? (orig_cells - 1 - c) : c);
            u32 base = (cell_pat << 6) + line_in_cell;
            if (base + 48u >= 0x8000u)
                continue;
            u16 p0 = vram[base];
            u16 p1 = vram[base + 16u];
            u16 p2 = vram[base + 32u];
            u16 p3 = vram[base + 48u];
            if (!(p0 | p1 | p2 | p3))
                continue;
            u32 left8, right8;
            if (!xflip) {
                left8  = M->spread8[p0 >> 8]   | (M->spread8[p1 >> 8] << 1) |
                         (M->spread8[p2 >> 8] << 2)   | (M->spread8[p3 >> 8] << 3);
                right8 = M->spread8[p0 & 0xFF] | (M->spread8[p1 & 0xFF] << 1) |
                         (M->spread8[p2 & 0xFF] << 2) | (M->spread8[p3 & 0xFF] << 3);
            } else {
                left8  = M->spread8_rev[p0 & 0xFF] | (M->spread8_rev[p1 & 0xFF] << 1) |
                         (M->spread8_rev[p2 & 0xFF] << 2) | (M->spread8_rev[p3 & 0xFF] << 3);
                right8 = M->spread8_rev[p0 >> 8]   | (M->spread8_rev[p1 >> 8] << 1) |
                         (M->spread8_rev[p2 >> 8] << 2)   | (M->spread8_rev[p3 >> 8] << 3);
            }
            for (int half = 0; half < 2; half++) {
                u32 pack = half ? right8 : left8;
                if (!pack)
                    continue;
                int bx = cx + half * 8;
                for (int b = 0; b < 8; b++) {
                    u8 px = (u8)(pack & 0x0Fu);
                    pack >>= 4;
                    if (!px)
                        continue;
                    int dx = bx + b;
                    if ((unsigned)dx >= (unsigned)w)
                        continue;
                    if (i == 0)
                        spr0_mask[dx] = 1;
                    else if (spr0_mask[dx])
                        hit0 = 1;
                    if (!spr_drawn[dx]) {
                        spr_drawn[dx] = 1;
                        if (fg || !bg_opaque[dx])
                            dst[dx] = sgx_raw ? (u16)(SGX_SPRITE | pal_base | px) : pal[px];
                    }
                }
            }
        }
    }

    if (hit0 && (cr & 0x01)) {
        vdc->status |= 0x01;
        vdc_update_irq();
    }
}

static void mix_sgx_vpc(const u16 *lb0, const u16 *lb1, u16 *dst, int w)
{
    static const u8 prio_sel[4] = { 1, 1, 0, 0 };
    static const u8 prio_sh[4]  = { 4, 0, 4, 0 };
    int w0 = (int)S.vpc_win[0] - 0x40;
    int w1 = (int)S.vpc_win[1] - 0x40;
    u16 bg0 = M->vce_pal[0];

    for (int x = 0; x < w; x++) {
        int in_win = (x < w0 ? 1 : 0) | (x < w1 ? 2 : 0);
        u8 pb = (S.vpc_prio[prio_sel[in_win]] >> prio_sh[in_win]) & 0x0Fu;

        u16 p1 = (pb & 1u) ? lb0[x] : SGX_TRANSP;
        u16 p2 = (pb & 2u) ? lb1[x] : SGX_TRANSP;

        switch (pb >> 2) {
        case 1: /* VDC0 Sprites > VDC1 Sprites > VDC0 BG > VDC1 BG */
            if ((p2 & SGX_SPRITE) && !(p1 & SGX_SPRITE))
                p1 |= SGX_TRANSP;
            break;
        case 2: /* VDC0 BG > VDC1 Sprites > VDC1 BG > VDC0 Sprites */
            if ((p1 & SGX_SPRITE) && !(p2 & SGX_SPRITE) && !(p2 & SGX_TRANSP))
                p1 |= SGX_TRANSP;
            break;
        }

        u16 pick = (p1 & SGX_TRANSP) ? p2 : p1;
        dst[x] = (pick & SGX_TRANSP) ? bg0 : M->vce_pal[pick & SGX_PIX_MASK];
    }
}

/* ========================================================================
 * Public Lifecycle, Frame Loop, Audio & Save API
 * ======================================================================== */

static u8 bitrev8(u8 b)
{
    b = (u8)(((b & 0xF0u) >> 4) | ((b & 0x0Fu) << 4));
    b = (u8)(((b & 0xCCu) >> 2) | ((b & 0x33u) << 2));
    return (u8)(((b & 0xAAu) >> 1) | ((b & 0x55u) << 1));
}

static void append_str(char **p, const char *s)
{
    while (*s) *(*p)++ = *s++;
}

static void append_u32(char **p, u32 v)
{
    char tmp[16];
    int n = 0;
    do { tmp[n++] = (char)('0' + v % 10u); v /= 10u; } while (v);
    while (n--) *(*p)++ = tmp[n];
}

static void fmt_info(void)
{
    char *p = S.info_buf;
    if (S.cd_mode) {
        append_str(&p, S.ext_bios ? "PC Engine CD-ROM2 (System Card 3.0, "
                                  : "PC Engine CD-ROM2 (Built-in SysCard 3.0 + Arcade Card, ");
        append_u32(&p, S.cd ? S.cd->last_track : 1u);
        append_str(&p, " trk)");
    } else if (S.sgx_mode) {
        append_str(&p, "NEC SuperGrafx (Dual VDC + VPC, ROM ");
        append_u32(&p, S.rom_size >> 10);
        append_str(&p, " KB)");
    } else {
        append_str(&p, S.sf2_mapper ? "HuCard (SF2 mapper)" :
                       S.us_region ? "TurboGrafx-16 HuCard" : "PC Engine HuCard");
        append_str(&p, ", ROM ");
        append_u32(&p, S.rom_size >> 10);
        append_str(&p, " KB");
    }
    *p = 0;
}

static void init_common_tables(void)
{
    u32 keep_rate = S.sample_rate;
    /* Clear core state & small RAMs without redundantly wiping 2 MB ac_ram twice */
    for (u32 i = 0; i < (u32)((u8 *)M->cd_bios - (u8 *)M); i++)
        ((u8 *)M)[i] = 0;
    S.sample_rate = keep_rate;

    for (u32 i = 0; i < sizeof(M->ff_page); i++)
        M->ff_page[i] = 0xFFu;
    for (u32 b = 0; b < 256u; b++) {
        u32 n = 0, r = 0;
        for (int k = 0; k < 8; k++) {
            n |= ((b >> (7 - k)) & 1u) << (k * 4);
            r |= ((b >> k) & 1u) << (k * 4);
        }
        M->spread8[b] = n;
        M->spread8_rev[b] = r;
    }
    M->bram[0] = 'H'; M->bram[1] = 'U'; M->bram[2] = 'B'; M->bram[3] = 'M';
    M->bram[4] = 0x00; M->bram[5] = 0x88; M->bram[6] = 0x10; M->bram[7] = 0x80;
}

static const char *load_hucard_common(u8 *image, u32 size, int sgx)
{
    if (!image || size < 8192u)
        return sgx ? "too small for a SuperGrafx HuCard (at least 8 KB)"
                   : "too small for a PC Engine HuCard (at least 8 KB)";
    if (size > 512u && (size & 0x1FFFu) == 512u) {
        image += 512;
        size -= 512;
    }
    if (size < 8192u)
        return "too small for a HuCard";

    init_common_tables();
    S.sgx_mode = (u8)sgx;
    S.cd_mode = 0;
    S.rom = image;
    S.rom_size = size;
    S.rom_pages = (size + 0x1FFFu) >> 13;
    S.rom_p2 = 1;
    while (S.rom_p2 * 2u <= S.rom_pages && S.rom_p2 < 0x40u)
        S.rom_p2 *= 2u;
    S.sf2_mapper = S.rom_pages > 128u;

    u8 rst_hi = S.rom[0x1FFF];
    if (rst_hi < 0xC0u && bitrev8(rst_hi) >= 0xE0u) {
        for (u32 i = 0; i < size; i++)
            S.rom[i] = bitrev8(S.rom[i]);
        S.us_region = 1;
    }
    for (u32 i = 0x1F00u; i + 8u < size && i < 0x2000u; i++)
        if (S.rom[i] == 'P' && S.rom[i + 1] == 'O' && S.rom[i + 2] == 'P' && S.rom[i + 3] == 'U')
            S.populous_ram = 1;

    pce_reset();
    fmt_info();
    return 0;
}

const char *pce_load(u8 *image, u32 size)
{
    return load_hucard_common(image, size, 0);
}

const char *sgx_load(u8 *image, u32 size)
{
    return load_hucard_common(image, size, 1);
}

const char *pcecd_load(const u8 *bios, u32 bios_size, const struct cdrom_toc *cd)
{
    if (!cd || !cd->total_lba || !cd->read_2048)
        return "not a valid PC Engine CD-ROM image";

    init_common_tables();
    for (u32 i = 0; i < sizeof(M->cd_ram); i++)
        M->cd_ram[i] = 0;
    for (u32 i = 0; i < 0x10000u; i++)
        M->ac_ram[i] = 0;

    S.cd_mode = 1;
    S.sgx_mode = 0;
    S.cd = cd;

    if (bios && bios_size >= 0x8000u) {
        if (bios_size > 512u && (bios_size & 0x1FFFu) == 512u) {
            bios += 512;
            bios_size -= 512;
        }
        for (u32 off = 0; off < sizeof(M->cd_bios); off += bios_size) {
            u32 take = sizeof(M->cd_bios) - off;
            if (take > bios_size) take = bios_size;
            for (u32 i = 0; i < take; i++)
                M->cd_bios[off + i] = bios[i];
        }
        /* Bit-reversed US System Card check */
        if (M->cd_bios[0x1FFF] < 0xC0u && bitrev8(M->cd_bios[0x1FFF]) >= 0xE0u) {
            for (u32 i = 0; i < sizeof(M->cd_bios); i++)
                M->cd_bios[i] = bitrev8(M->cd_bios[i]);
        }
        S.ext_bios = 1;
    } else {
#ifndef PCE_CPU_TEST
        build_cleanroom_syscard_bios();
#endif
        S.ext_bios = 0;
    }

    pce_reset();
    fmt_info();
    return 0;
}

void pce_reset(void)
{
    S.a = S.x = S.y = 0;
    S.s = 0xFF;
    S.p = FI;
    for (int i = 0; i < 8; i++)
        S.mpr[i] = 0;
    S.mpr_latch = 0;
    S.speed = 4;
    S.irq_mask = 0;
    S.irq_lines = 0;
    S.cyc_debt = 0;
    S.jammed = 0;
    S.tmr_on = 0;
    S.tmr_cnt = S.tmr_reload = 0;
    S.tmr_prescale = 1024;
    S.sf2_bank = 0;
    S.out_w = PCE_W_DEF;
    S.out_h = PCE_H_DEF;

    for (int c = 0; c < 2; c++) {
        struct pce_vdc *v = &S.vdc[c];
        for (u32 i = 0; i < sizeof(*v); i++)
            ((u8 *)v)[i] = 0;
        v->vram_rbuf = 0xFFFFu;
        v->regs[10] = 0x0202;
        v->regs[11] = 0x041F;
        v->regs[12] = 0x0F02;
        v->regs[13] = 239;
        v->regs[14] = 0x000C;
        v->burst_mode = 1;
    }
    S.vpc_prio[0] = S.vpc_prio[1] = 0x11u;
    S.vpc_win[0] = S.vpc_win[1] = 0;
    S.vpc_st_mode = 0;

    S.frame_counter = 0;
    S.lat_vds = 0x0F;
    S.lat_vsw = 0x02;
    S.lat_vdw = 239;
    S.lat_vcr = 0x0C;
    S.vblank_fl = 0x0F + 0x02 + 239 + 1;
    for (int i = 0; i < 6; i++)
        S.psg[i].lfsr = 1u;

    if (S.cd_mode) {
        S.fader_vol = 65536;
        S.fader_clocked = 0;
        pcecd_sync_fader();
        S.cdda_status = CDDA_STOPPED;
        S.cdda_pos = 588u;
        S.adpcm_playing = 0;
        scsi_set_phase(SCSI_BUS_FREE);
        pcecd_update_subq(0);
    }

    rebuild_pages();
    S.pc = bus_read(0xFFFE) | ((u16)bus_read(0xFFFF) << 8);
}

static u32 calc_line_leadin(void)
{
    int hds = (S.vdc[0].regs[10] >> 8) & 0x7F;
    int hdw = S.vdc[0].regs[11] & 0x7F;
    int hde = (S.vdc[0].regs[11] >> 8) & 0x7F;
    int magical = ((hds + hdw + 1 + hde + 2) & ~1) - (hdw + 1);
    int cyc = magical * 8 - 2;
    int dc = S.vce_ctrl & 1;
    if (S.vce_ctrl & 2)
        dc = 2;
    if (dc == 0)
        cyc = (cyc * 4) / 3;
    else if (dc == 2)
        cyc = (cyc * 2) / 3;
    if (cyc < 16)
        cyc = 16;
    if (cyc > 380)
        cyc = 380;
    return (u32)cyc;
}

void pce_frame(u16 pad, u16 *picture)
{
    S.pad_state = pad;
    S.audio_count = 0;
    S.audio_cyc_last = S.cycles;

    int chips = S.sgx_mode ? 2 : 1;
    int w = calc_width();
    int h_latched = 0;
    int h = S.out_h;
    int safety = 0;

    do {
        if (S.frame_counter == 0) {
            S.lat_vsw = S.vdc[0].regs[12] & 0x1Fu;
            S.lat_vds = (S.vdc[0].regs[12] >> 8) & 0xFFu;
            S.lat_vdw = S.vdc[0].regs[13] & 0x1FFu;
            S.lat_vcr = S.vdc[0].regs[14] & 0xFFu;
            S.vblank_fl = S.lat_vds + S.lat_vsw + S.lat_vdw + 1u;
            if (S.vblank_fl > 261u)
                S.vblank_fl = 261u;
            for (int c = 0; c < chips; c++) {
                S.vdc[c].display_counter = 0;
                S.vdc[c].burst_mode = !(S.vdc[c].regs[5] & 0xC0u);
            }
        }

        u16 active_dc = S.lat_vds + S.lat_vsw;
        int need_vbi[2] = {0, 0};

        for (int c = 0; c < chips; c++) {
            struct pce_vdc *v = &S.vdc[c];
            if (v->display_counter == active_dc) {
                v->burst_mode = !(v->regs[5] & 0xC0u);
                v->rcr_count = 0;
                if (c == 0) {
                    w = calc_width();
                    int vdw = (int)S.lat_vdw + 1;
                    h = vdw < 160 ? PCE_H_DEF : vdw > PCE_H_MAX ? PCE_H_MAX : vdw;
                    S.out_w = w;
                    S.out_h = h;
                    h_latched = 1;
                }
            }
            if (v->display_counter == S.vblank_fl) {
                need_vbi[c] = 1;
                if (v->satb_dirty || (v->regs[15] & 0x10u))
                    vdc_satb_dma(c);
            }
            if ((int)v->rcr_count == ((int)(v->regs[6] & 0x3FFu) - 0x40) && (v->regs[5] & 0x04u)) {
                v->status |= 0x04u;
                vdc_update_irq();
            }
        }

        u32 leadin = calc_line_leadin();
        run_cycles_7m(leadin);

        int ay = (int)S.vdc[0].display_counter - (int)active_dc;
        int draw_row = picture && ay >= 0 && ay < h &&
                       S.vdc[0].display_counter >= active_dc &&
                       S.vdc[0].display_counter < active_dc + S.lat_vdw + 1u;

        for (int c = 0; c < chips; c++) {
            struct pce_vdc *v = &S.vdc[c];
            u16 *target = S.sgx_mode ? M->sgx_lb[c] : (picture + ay * w);
            if (!v->burst_mode && v->display_counter >= active_dc &&
                v->display_counter < active_dc + S.lat_vdw + 1u) {
                if (v->display_counter == active_dc)
                    v->bg_y = v->regs[8] & 0x1FFu;
                else
                    v->bg_y = (v->bg_y + 1u) & 0x1FFu;
                if (draw_row)
                    render_vdc_scanline(c, ay, target, w, S.sgx_mode);
            } else if (draw_row) {
                u16 os = S.sgx_mode ? SGX_TRANSP : M->vce_pal[0x100];
                for (int x = 0; x < w; x++)
                    target[x] = os;
            }
        }

        if (S.sgx_mode && draw_row)
            mix_sgx_vpc(M->sgx_lb[0], M->sgx_lb[1], picture + ay * w, w);

        for (int c = 0; c < chips; c++) {
            if (need_vbi[c] && (S.vdc[c].regs[5] & 0x08u))
                S.vdc[c].status |= 0x20u;
        }

        run_cycles_7m(2);

        if ((S.vdc[0].status | (S.sgx_mode ? S.vdc[1].status : 0)) & 0x20u)
            vdc_update_irq();

        run_cycles_7m(LINE_CYC - leadin - 2u);
        pcecd_step_line(LINE_CYC);

        for (int c = 0; c < chips; c++) {
            struct pce_vdc *v = &S.vdc[c];
            v->rcr_count++;
            v->display_counter++;
            if (v->sat_dma_slcounter) {
                v->sat_dma_slcounter--;
                if (!v->sat_dma_slcounter && (v->regs[15] & 0x01u)) {
                    v->status |= 0x08u;
                    vdc_update_irq();
                }
            }
            if (v->display_counter == active_dc + S.lat_vdw + S.lat_vcr + 3u)
                v->display_counter = 0;
        }

        u16 total_lines = (S.vce_ctrl & 0x04u) ? 263u : 262u;
        S.frame_counter = (u16)((S.frame_counter + 1u) % total_lines);
    } while (S.frame_counter != S.vblank_fl && ++safety < 300);

    if (!h_latched) {
        S.out_w = w;
        S.out_h = h;
    }
    psg_catch_up();
}

int pce_width(void)   { return S.out_w; }
int pce_height(void)  { return S.out_h; }
const char *pce_info(void) { return S.info_buf; }

u8 *pce_save_ram(u32 *size, int *battery)
{
    *size = sizeof(M->bram);
    *battery = 1;
    return M->bram;
}

int pce_save_changed(void)
{
    int d = S.bram_dirty;
    S.bram_dirty = 0;
    return d;
}

u32 pce_cpu_cycles(void) { return S.cycles; }
int pce_jammed(void)     { return S.jammed; }

void pce_audio_rate(u32 hz)
{
    S.sample_rate = hz;
    S.audio_frac = 0;
    S.audio_count = 0;
    S.audio_cyc_last = S.cycles;
}

int pce_audio(s16 *out, int max)
{
    int n = S.audio_count < max ? S.audio_count : max;
    for (int i = 0; i < n; i++)
        out[i] = M->audio_ring[i];
    S.audio_count = 0;
    return n;
}

#ifdef PCE_CPU_TEST
void pce_sst_set(u8 a, u8 x, u8 y, u8 s, u8 p, u16 pc, const u8 mpr[8])
{
    S.a = a; S.x = x; S.y = y; S.s = s; S.p = p; S.pc = pc;
    for (int i = 0; i < 8; i++)
        S.mpr[i] = mpr[i];
    S.speed = 1;
}

void pce_sst_get(u8 *a, u8 *x, u8 *y, u8 *s, u8 *p, u16 *pc, u8 mpr[8])
{
    *a = S.a; *x = S.x; *y = S.y; *s = S.s; *p = S.p; *pc = S.pc;
    for (int i = 0; i < 8; i++)
        mpr[i] = S.mpr[i];
}

u32 pce_sst_step(void)
{
    return cpu_step();
}
#endif
