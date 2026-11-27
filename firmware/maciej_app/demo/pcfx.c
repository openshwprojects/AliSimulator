/* NEC PC-FX 32-Bit Multimedia CD-ROM Console Emulator: see pcfx.h.
   Zero static .bss: V810 32-bit RISC + FPU, HuC6261 VCE (512-col YUV->RGB555),
   dual HuC6270 VDC-A & VDC-B (2 x 64 KB VRAM), HuC6272 KING (BG0..BG3 + affine +
   SCSI CD-ROM + 2-ch ADPCM), HuC6273 RAINBOW, HuC6230 6-ch PSG + CD-DA, 2 MB
   Main RAM, 1 MB KRAM, and 1 MB BIOS reside entirely in EMU_RAM_PHYS. */
#include "pcfx.h"
#include "font5x7.h"

#ifndef PCFX_HOST
#include "hw.h"
#else
typedef unsigned long long u64;
#endif

#define INLINE static inline __attribute__((always_inline))
#pragma GCC optimize("O2")

#define PCFX_RAM_SIZE    0x00200000u    /* 2 MB Main RAM */
#define PCFX_KRAM_SIZE   0x00100000u    /* 1 MB HuC6272 KING KRAM */
#define PCFX_BIOS_SIZE   0x00100000u    /* 1 MB System BIOS ($FFF00000..$FFFFFFFF) */
#define PCFX_SRAM_SIZE   0x00008000u    /* 32 KB Backup SRAM (.sav) */
#define PCFX_SND_RING    8192

/* NEC V810 System Registers & PSW Flags */
#define SR_EIPC   0
#define SR_EIPSW  1
#define SR_FEPC   2
#define SR_FEPSW  3
#define SR_ECR    4
#define SR_PSW    5
#define SR_PIR    6
#define SR_TKCW   7
#define SR_CHCW   24

#define PSW_IA    0x000F0000u
#define PSW_NP    0x00008000u
#define PSW_EP    0x00004000u
#define PSW_AE    0x00002000u
#define PSW_ID    0x00001000u
#define PSW_CY    0x00000008u
#define PSW_OV    0x00000004u
#define PSW_S     0x00000002u
#define PSW_Z     0x00000001u

/* Dual HuC6270 Video Display Controller (VDC-A @ $400, VDC-B @ $500) */
struct pcfx_vdc {
    u16 vram[32768];                    /* 64 KB (32K words) per VDC */
    u16 satb[256];                      /* 64-sprite Attribute Table cache */
    u16 regs[32];                       /* R00 MAWR, R01 MARR, R02 VWR, R05 CR, R06 RCR, R07 BXR, R08 BYR, R09 MWR, R19 DVSSR */
    u16 read_buf;
    u8  ar;
    u8  status;                         /* b5=VD(VBlank), b2=RR(RCR), b0=CR */
    u8  satb_dirty;
};

/* HuC6230 6-Channel Wavetable / Noise PSG */
struct pcfx_psg_ch {
    u16 freq;
    u8  ctrl;                           /* b7=enable, b6=DDA, b4..0=vol */
    u8  bal;                            /* b7..4=L, b3..0=R */
    u8  wave[32];
    u8  widx, rpos;
    u8  noise;                          /* b7=noise_en, b4..0=nfreq */
    u32 phase;
    u16 lfsr;
};

/* HuC6272 KING ADPCM Channel (2 channels) */
struct pcfx_adpcm_ch {
    u32 start_a, end_a, loop_a, cur_a;
    u32 phase;
    s32 sample, step_idx;
    u8  active, loop, nibble_hi;
    u8  vol_l, vol_r, rate_code;
};

struct pcfx_state {
    const struct cdrom_toc *cd;
    u8  jammed, sram_dirty, ext_bios;
    int scr_w, scr_h;
    u16 pad1;
    u32 frame_no;

    /* NEC V810 32-bit RISC CPU */
    u32 r[32];
    u32 sr[32];
    u32 pc;
    u8  halted;
    s32 cycles;

    /* Interrupt Controller ($E00..$EFF) & 16-bit Timer ($0C0..$0CF) */
    u16 irq_pend;                       /* Bitmask for IRQ 8..15 (bit k = IRQ (15 - k) or direct bit) */
    u16 irq_mask;                       /* 0 = enabled, 1 = masked (default 0x7F = all masked) */
    u16 irq_prio[2];
    u16 timer_ctrl, timer_period;
    s32 timer_cnt;

    /* Gamepad Latch ($000..$08F) */
    u16 pad_ctrl[2];
    u32 pad_data[2];

    /* HuC6261 VCE ($300..$3FF) */
    u16 vce_ctrl;                       /* b0=320px mode */
    u16 vce_addr;
    u16 vce_pal[512];                   /* 16-bit Y8U4V4 palette */
    u16 vce_rgb[512];                   /* Cached RGB555 equivalents! */
    u16 vce_prio[2];
    u16 vce_pal_ofs[4];                 /* Palette base offsets for VDC-A, VDC-B, KING */

    /* HuC6272 KING ($600..$6FF) */
    u8  king_ar;
    u8  king_kram_page;
    u32 king_ra, king_wa;               /* KRAM read/write word addresses + bit 18..27 signed step */
    u16 king_regs[96];                  /* BG0..BG3 mode/scroll/affine/DMA/ADPCM */

    /* Built-in KING SCSI CD-ROM State Machine */
    u8  scsi_phase;                     /* 0=BUS_FREE, 1=CMD, 2=DATA_IN, 3=STATUS, 4=MSG_IN */
    u8  scsi_cmd[12];
    u8  scsi_cmd_len, scsi_cmd_pos;
    u8  scsi_status_byte, scsi_sense_key;
    u32 scsi_buf_len, scsi_buf_pos;
    u32 scsi_next_lba, scsi_rem_sectors;

    /* Redbook CD-DA Playback */
    u8  cdda_playing, cdda_loop;
    u32 cdda_lba, cdda_end_lba;
    u32 cdda_pos, cdda_frac;
    u32 psg_key[6], psg_inc[6], ns_key[2], ns_inc[2], cached_sr, adpcm_inc, cdda_inc;

    /* HuC6273 RAINBOW ($200..$2FF) */
    u16 rbw_ctrl;
    u32 rbw_kram_src;
    u16 rbw_blocks;
    u8  rbw_ready_line;

    /* HuC6230 SoundBox ($100..$1FF) */
    u8  psg_ch_sel, psg_main_bal;
    u8  cdda_vol_l, cdda_vol_r;
    struct pcfx_psg_ch psg[6];
    struct pcfx_adpcm_ch adpcm[2];

    u32 sample_rate;
    u32 snd_head, snd_tail;
    char info[96];
};

struct pcfx_mem {
    struct pcfx_state st;
    struct pcfx_vdc vdc[2];             /* [0] = VDC-A, [1] = VDC-B (128 KB total) */
    u16 yuv_lut[65536];                 /* 16-bit Y8U4V4 -> 0BBBBBGGGGGRRRRR (128 KB) */
    u16 rbw_fb[16 * 256];               /* 16-line RAINBOW decoded YUV block strip */
    u8  scsi_buf[2352];
    u8  cdda_sec[2352];
    u8  sram[PCFX_SRAM_SIZE];           /* 32 KB .sav */
    s16 snd_ring[PCFX_SND_RING];
    u32 bios_magic;
};

#ifdef PCFX_HOST
static struct pcfx_mem pcfx_host_mem;
static u8 pcfx_host_ram[PCFX_RAM_SIZE] __attribute__((aligned(4)));
static u8 pcfx_host_kram[PCFX_KRAM_SIZE] __attribute__((aligned(4)));
static u8 pcfx_host_bios[PCFX_BIOS_SIZE] __attribute__((aligned(4)));
#define M           (&pcfx_host_mem)
#define RAM_BUF     pcfx_host_ram
#define KRAM_BUF    pcfx_host_kram
#define BIOS_BUF    pcfx_host_bios
#else
/* Physical layout inside 9.5 MB EMU_RAM_PHYS (0x03400000..0x03D7FFFF):
   0x03400000..0x0357FFFF (1.5 MB) : struct pcfx_mem M (~330 KB, 0 B static .bss!)
   0x03580000..0x0377FFFF (2.0 MB) : RAM_BUF  (2 MB PC-FX Main RAM)
   0x03780000..0x0387FFFF (1.0 MB) : KRAM_BUF (1 MB HuC6272 KING KRAM)
   0x03880000..0x0397FFFF (1.0 MB) : BIOS_BUF (1 MB PC-FX BIOS ROM) */
#define M           ((struct pcfx_mem *)KSEG0(EMU_RAM_PHYS))
#define RAM_BUF     ((u8 *)KSEG0(0x03580000u))
#define KRAM_BUF    ((u8 *)KSEG0(0x03780000u))
#define BIOS_BUF    ((u8 *)KSEG0(0x03880000u))
_Static_assert(sizeof(struct pcfx_mem) <= 0x00180000u, "pcfx_mem exceeds 1.5 MB slot");
#endif

#define S (M->st)

static void fx_zero(void *p, u32 n)
{
    u8 *b = (u8 *)p;
    for (u32 i = 0; i < n; i++) b[i] = 0;
}

/* ---- Pure 32-Bit 32x32->64 Multiply Helpers (Zero libgcc Calls!) ---- */
INLINE void fx_mulu64(u32 a, u32 b, u32 *hi, u32 *lo)
{
    u32 al = a & 0xFFFFu, ah = a >> 16;
    u32 bl = b & 0xFFFFu, bh = b >> 16;
    u32 p0 = al * bl, p1 = al * bh, p2 = ah * bl, p3 = ah * bh;
    u32 cy = ((p0 >> 16) + (p1 & 0xFFFFu) + (p2 & 0xFFFFu)) >> 16;
    *lo = p0 + (p1 << 16) + (p2 << 16);
    *hi = p3 + (p1 >> 16) + (p2 >> 16) + cy;
}

INLINE void fx_muls64(s32 a, s32 b, u32 *hi, u32 *lo)
{
    int neg = (a < 0) ^ (b < 0);
    u32 ua = (a < 0) ? (0u - (u32)a) : (u32)a;
    u32 ub = (b < 0) ? (0u - (u32)b) : (u32)b;
    u32 h, l;
    fx_mulu64(ua, ub, &h, &l);
    if (neg) {
        l = ~l + 1u;
        h = ~h + (l == 0u ? 1u : 0u);
    }
    *hi = h;
    *lo = l;
}

/* ---- HuC6261 VCE Y8U4V4 -> RGB555 (0BBBBBGGGGGRRRRR) Lookup Table ---- */
static void fx_init_yuv_lut(void)
{
    for (u32 yuv = 0; yuv < 65536u; yuv++) {
        s32 y = (s32)((yuv >> 8) & 0xFFu);
        s32 u = ((s32)((yuv >> 4) & 0x0Fu) - 8) * 16;
        s32 v = ((s32)(yuv & 0x0Fu) - 8) * 16;
        s32 r = y + ((359 * v) >> 8);
        s32 g = y - ((88 * u + 183 * v) >> 8);
        s32 b = y + ((454 * u) >> 8);
        if (r < 0) r = 0; else if (r > 255) r = 255;
        if (g < 0) g = 0; else if (g > 255) g = 255;
        if (b < 0) b = 0; else if (b > 255) b = 255;
        M->yuv_lut[yuv] = (u16)(((u32)(b >> 3) << 10) | ((u32)(g >> 3) << 5) | (u32)(r >> 3));
    }
}

/* ============================================================================
   Interrupt Controller ($E00..$EFF) & V810 IRQ Priority Arbiter
   PC-FX IRQs: bit 0=IRQ15, bit 1=IRQ14, bit 2=IRQ13, bit 3=IRQ12(VDC-B),
               bit 4=IRQ11(VDC-A), bit 5=IRQ10(KING), bit 6=IRQ9(Timer), bit 7=IRQ8(Pad)
   ============================================================================ */

static void fx_raise_irq(int irq_level)     /* irq_level = 8..15 */
{
    if (irq_level >= 8 && irq_level <= 15)
        S.irq_pend |= (u16)(1u << (15 - irq_level));
}

static void fx_clear_irq(int irq_level)
{
    if (irq_level >= 8 && irq_level <= 15)
        S.irq_pend &= (u16)~(1u << (15 - irq_level));
}

static int fx_top_irq(void)
{
    u16 active = S.irq_pend & (u16)~S.irq_mask;
    if (!active) return -1;
    if (S.sr[SR_PSW] & (PSW_NP | PSW_EP | PSW_ID)) return -1;
    u32 min_lvl = (S.sr[SR_PSW] & PSW_IA) >> 16;
    for (int bit = 0; bit < 8; bit++) {
        if (active & (1u << bit)) {
            int lvl = 15 - bit;
            if ((u32)lvl >= min_lvl)
                return lvl;
        }
    }
    return -1;
}

/* ============================================================================
   Built-in HuC6272 KING SCSI CD-ROM Controller (over struct cdrom_toc *cd)
   ============================================================================ */

static u32 fx_cd_data_base(void)
{
    if (!S.cd) return 0;
    for (u32 t = S.cd->first_track; t <= S.cd->last_track; t++)
        if (!S.cd->tracks[t].is_audio)
            return S.cd->tracks[t].lba;
    return 0;
}

static void fx_scsi_load_next_sector(void)
{
    fx_zero(M->scsi_buf, 2048);
    if (S.cd && S.cd->read_2048)
        (void)S.cd->read_2048(S.scsi_next_lba, M->scsi_buf);
    S.scsi_next_lba++;
    S.scsi_buf_pos = 0;
    S.scsi_buf_len = 2048u;
}

static u8 fx_to_bcd(u32 v) { return (u8)(((v / 10u) % 10u) * 16u + (v % 10u)); }

static void fx_lba_to_msf(u32 lba, u8 *m, u8 *s, u8 *f)
{
    u32 a = lba + 150u;
    *f = fx_to_bcd(a % 75u);
    *s = fx_to_bcd((a / 75u) % 60u);
    *m = fx_to_bcd(a / (75u * 60u));
}

static void fx_scsi_exec_cmd(void)
{
    u8 op = S.scsi_cmd[0];
    S.scsi_status_byte = 0x00u;         /* GOOD */
    S.scsi_buf_pos = S.scsi_buf_len = 0;
    S.scsi_rem_sectors = 0;

    switch (op) {
    case 0x00: /* TEST UNIT READY */
    case 0x01: /* REZERO */
        S.scsi_phase = 3u;
        break;

    case 0x03: /* REQUEST SENSE */
        fx_zero(M->scsi_buf, 18);
        M->scsi_buf[0] = 0x70u;
        M->scsi_buf[2] = S.scsi_sense_key;
        M->scsi_buf[7] = 10u;
        S.scsi_buf_len = (S.scsi_cmd[4] > 0 && S.scsi_cmd[4] <= 18u) ? S.scsi_cmd[4] : 18u;
        S.scsi_phase = 2u;
        break;

    case 0x08: { /* READ(6) */
        u32 lba = (((u32)S.scsi_cmd[1] & 0x1Fu) << 16) | ((u32)S.scsi_cmd[2] << 8) | S.scsi_cmd[3];
        u32 cnt = S.scsi_cmd[4] ? S.scsi_cmd[4] : 256u;
        S.scsi_next_lba = lba;
        S.scsi_rem_sectors = cnt - 1u;
        S.cdda_playing = 0;
        fx_scsi_load_next_sector();
        S.scsi_phase = 2u;
        break;
    }

    case 0x28: { /* READ(10) */
        u32 lba = ((u32)S.scsi_cmd[2] << 24) | ((u32)S.scsi_cmd[3] << 16) |
                  ((u32)S.scsi_cmd[4] << 8)  | S.scsi_cmd[5];
        u32 cnt = ((u32)S.scsi_cmd[7] << 8) | S.scsi_cmd[8];
        if (!cnt) { S.scsi_phase = 3u; break; }
        S.scsi_next_lba = lba;
        S.scsi_rem_sectors = cnt - 1u;
        S.cdda_playing = 0;
        fx_scsi_load_next_sector();
        S.scsi_phase = 2u;
        break;
    }

    case 0xD8: /* NEC AUDIO TRACK SEARCH / PLAY START */
    case 0xD9: {
        u32 mode = S.scsi_cmd[9] & 0xC0u;
        u32 lba = 0;
        if (mode == 0x00u) {
            lba = ((u32)S.scsi_cmd[2] << 24) | ((u32)S.scsi_cmd[3] << 16) |
                  ((u32)S.scsi_cmd[4] << 8) | S.scsi_cmd[5];
        } else if (mode == 0x40u) {
            u32 m = (S.scsi_cmd[2] >> 4) * 10u + (S.scsi_cmd[2] & 15u);
            u32 s = (S.scsi_cmd[3] >> 4) * 10u + (S.scsi_cmd[3] & 15u);
            u32 f = (S.scsi_cmd[4] >> 4) * 10u + (S.scsi_cmd[4] & 15u);
            u32 tot = (m * 60u + s) * 75u + f;
            lba = (tot >= 150u) ? (tot - 150u) : 0u;
        } else {
            u32 trk = (S.scsi_cmd[2] >> 4) * 10u + (S.scsi_cmd[2] & 15u);
            if (S.cd && trk >= S.cd->first_track && trk <= S.cd->last_track) {
                lba = S.cd->tracks[trk].lba;
                S.cdda_end_lba = lba + S.cd->tracks[trk].length;
            }
        }
        if (!S.cdda_end_lba && S.cd) S.cdda_end_lba = S.cd->total_lba;
        S.cdda_lba = lba;
        S.cdda_pos = 2352u;
        S.cdda_playing = (op == 0xD9u || (S.scsi_cmd[1] & 1u)) ? 1u : 0u;
        S.cdda_loop = (op == 0xD9u && (S.scsi_cmd[1] & 3u) == 1u) ? 1u : 0u;
        S.scsi_phase = 3u;
        break;
    }

    case 0xDA: /* PAUSE */
        S.cdda_playing = 0;
        S.scsi_phase = 3u;
        break;

    case 0xDD: { /* NEC READ SUBCHANNEL Q */
        fx_zero(M->scsi_buf, 10);
        M->scsi_buf[0] = S.cdda_playing ? 0x00u : 0x03u;
        M->scsi_buf[1] = S.cdda_playing ? 0x00u : 0x04u;
        M->scsi_buf[2] = 0x01u;
        M->scsi_buf[3] = 0x01u;
        fx_lba_to_msf(S.cdda_lba, &M->scsi_buf[7], &M->scsi_buf[8], &M->scsi_buf[9]);
        S.scsi_buf_len = 10u;
        S.scsi_phase = 2u;
        break;
    }

    case 0xDE: { /* NEC GET DIR INFO (READ TOC) */
        fx_zero(M->scsi_buf, 4);
        u8 mode = S.scsi_cmd[1] & 3u;
        if (mode == 0u && S.cd) {
            M->scsi_buf[0] = fx_to_bcd(S.cd->first_track);
            M->scsi_buf[1] = fx_to_bcd(S.cd->last_track);
        } else if (mode == 1u && S.cd) {
            fx_lba_to_msf(S.cd->total_lba, &M->scsi_buf[0], &M->scsi_buf[1], &M->scsi_buf[2]);
        } else if (mode == 2u && S.cd) {
            u32 trk = (S.scsi_cmd[2] >> 4) * 10u + (S.scsi_cmd[2] & 15u);
            if (trk < 1u) trk = 1u;
            if (trk > S.cd->last_track) trk = S.cd->last_track;
            fx_lba_to_msf(S.cd->tracks[trk].lba, &M->scsi_buf[0], &M->scsi_buf[1], &M->scsi_buf[2]);
            M->scsi_buf[3] = S.cd->tracks[trk].control;
        }
        S.scsi_buf_len = 4u;
        S.scsi_phase = 2u;
        break;
    }

    default:
        S.scsi_phase = 3u;
        break;
    }
}

static u8 fx_scsi_read_data(void)
{
    if (S.scsi_phase == 2u) {
        u8 b = M->scsi_buf[S.scsi_buf_pos++];
        if (S.scsi_buf_pos >= S.scsi_buf_len) {
            if (S.scsi_rem_sectors > 0) {
                S.scsi_rem_sectors--;
                fx_scsi_load_next_sector();
            } else {
                S.scsi_phase = 3u;
            }
        }
        return b;
    }
    if (S.scsi_phase == 3u) {
        S.scsi_phase = 4u;
        return S.scsi_status_byte;
    }
    if (S.scsi_phase == 4u) {
        S.scsi_phase = 0u;
        return 0x00u;                   /* Command Complete message */
    }
    return 0;
}

/* ============================================================================
   HuC6273 RAINBOW Motion RLE / YUV 16-Line Block Decoder
   Packet format in KRAM:
     Header word 0: 0xFFFE = 16x16 direct YUV844 block (256 words)
                    0xFFFD = 16-line RLE YUV844 block ((count8, yuv16) pairs)
   ============================================================================ */

static void fx_rainbow_decode_strip(void)
{
    if (!(S.rbw_ctrl & 1u)) return;
    u32 ka = S.rbw_kram_src & (PCFX_KRAM_SIZE - 2u);
    u16 tag = *(const u16 *)&KRAM_BUF[ka];
    ka = (ka + 2u) & (PCFX_KRAM_SIZE - 2u);

    if (tag == 0xFFFEu) {               /* Uncompressed 256x16 YUV strip */
        for (int i = 0; i < 256 * 16; i++) {
            M->rbw_fb[i] = *(const u16 *)&KRAM_BUF[ka];
            ka = (ka + 2u) & (PCFX_KRAM_SIZE - 2u);
        }
    } else if (tag == 0xFFFDu) {        /* RLE compressed 256x16 YUV strip */
        int pos = 0;
        int guard = 8192;
        while (pos < 256 * 16 && guard-- > 0) {
            u16 cnt = *(const u16 *)&KRAM_BUF[ka];
            ka = (ka + 2u) & (PCFX_KRAM_SIZE - 2u);
            u16 yuv = *(const u16 *)&KRAM_BUF[ka];
            ka = (ka + 2u) & (PCFX_KRAM_SIZE - 2u);
            if (!cnt) break;
            for (u16 k = 0; k < cnt && pos < 256 * 16; k++)
                M->rbw_fb[pos++] = yuv;
        }
    }
    S.rbw_kram_src = ka;
    S.rbw_ready_line = 1u;
}

/* ============================================================================
   PC-FX Hardware I/O Port Bus ($000..$FFF & $80000000 Mirror)
   ============================================================================ */

static u32 fx_encode_pad(u16 p)
{
    /* PC-FX Standard 6-Button Pad (FX-PAD ID = 0x20000000 -> upper 4 bits = 2? In Mednafen:
       bit 28..31 = 0xF (standard pad = 0xF0000000 / active-HIGH buttons in b0..b13!):
       b0=I, b1=II, b2=III, b3=IV, b4=V, b5=VI, b6=Select, b7=Run(Start),
       b8=Up, b9=Right, b10=Down, b11=Left */
    u32 v = 0xF0000000u;
    if (p & 0x0001u) v |= 0x0001u;      /* A (X) -> Button I */
    if (p & 0x0002u) v |= 0x0002u;      /* B (Z) -> Button II */
    if (p & 0x0400u) v |= 0x0004u;      /* X (C) -> Button III */
    if (p & 0x0800u) v |= 0x0008u;      /* Y (V) -> Button IV */
    if (p & 0x0100u) v |= 0x0010u;      /* L (Q) -> Button V */
    if (p & 0x0200u) v |= 0x0020u;      /* R (E) -> Button VI */
    if (p & 0x0004u) v |= 0x0040u;      /* Select */
    if (p & 0x0008u) v |= 0x0080u;      /* Start -> Run */
    if (p & 0x0010u) v |= 0x0100u;      /* Up */
    if (p & 0x0080u) v |= 0x0200u;      /* Right */
    if (p & 0x0020u) v |= 0x0400u;      /* Down */
    if (p & 0x0040u) v |= 0x0800u;      /* Left */
    return v;
}

static u16 fx_vdc_read(int chip, u32 off)
{
    struct pcfx_vdc *v = &M->vdc[chip];
    if ((off & 4u) == 0) {
        u8 st = v->status;
        v->status = 0;
        fx_clear_irq(chip == 0 ? 11 : 12);
        return st;
    }
    u16 ret = v->read_buf;
    if (v->ar == 2u) {
        static const u8 inc_tab[4] = { 1, 32, 64, 128 };
        v->regs[1] = (u16)((v->regs[1] + inc_tab[(v->regs[5] >> 11) & 3u]) & 0x7FFFu);
        v->read_buf = v->vram[v->regs[1]];
    }
    return ret;
}

static void fx_vdc_write(int chip, u32 off, u16 val, int is_byte)
{
    struct pcfx_vdc *v = &M->vdc[chip];
    if ((off & 4u) == 0) {
        v->ar = (u8)(val & 31u);
        return;
    }
    u8 r = v->ar;
    if (is_byte) {
        if (off & 1u) v->regs[r] = (u16)((v->regs[r] & 0x00FFu) | ((val & 0xFFu) << 8));
        else          v->regs[r] = (u16)((v->regs[r] & 0xFF00u) | (val & 0xFFu));
        if (!(off & 1u)) return;        /* Commit on MSB byte write! */
    } else {
        v->regs[r] = val;
    }

    if (r == 1u) {                      /* MARR */
        v->read_buf = v->vram[v->regs[1] & 0x7FFFu];
    } else if (r == 2u) {               /* VWR */
        static const u8 inc_tab[4] = { 1, 32, 64, 128 };
        v->vram[v->regs[0] & 0x7FFFu] = v->regs[2];
        v->regs[0] = (u16)((v->regs[0] + inc_tab[(v->regs[5] >> 11) & 3u]) & 0x7FFFu);
    } else if (r == 19u) {              /* DVSSR -> instant SATB copy */
        u32 sa = v->regs[19] & 0x7FFFu;
        for (u32 i = 0; i < 256u; i++)
            v->satb[i] = v->vram[(sa + i) & 0x7FFFu];
    }
}

static s32 fx_king_step(u32 addr_reg)
{
    s32 step = (s32)((addr_reg >> 18) & 0x3FFu);
    if (step & 0x200) step |= ~0x3FF;
    return step ? step : 1;
}

static u32 fx_io_read16(u32 port)
{
    port &= 0xFFEu;

    /* Gamepad KP0 ($000..$07E) & KP1 ($080..$0BE) */
    if (port < 0x0C0u) {
        int ch = (port >= 0x080u) ? 1 : 0;
        u32 sub = port & 0x7Eu;
        if (sub == 0x00u) return S.pad_ctrl[ch] | 0x08u;
        if (sub == 0x40u || sub == 0x04u) return (u16)S.pad_data[ch];
        if (sub == 0x42u || sub == 0x06u) return (u16)(S.pad_data[ch] >> 16);
        return 0;
    }

    /* Hardware Timer ($0C0..$0FE) */
    if (port < 0x100u) {
        if ((port & 0x3Eu) == 0x00u) return S.timer_ctrl;
        if ((port & 0x3Eu) == 0x08u) return S.timer_period;
        return 0;
    }

    /* HuC6273 RAINBOW ($200..$2FE) */
    if (port >= 0x200u && port < 0x300u) {
        if (port == 0x200u) return S.rbw_ctrl;
        return 0;
    }

    /* HuC6261 VCE ($300..$3FE) */
    if (port >= 0x300u && port < 0x400u) {
        switch (port & 0x1Eu) {
        case 0x00: return S.vce_ctrl;
        case 0x02: return S.vce_addr;
        case 0x04: {
            u16 v = S.vce_pal[S.vce_addr & 511u];
            S.vce_addr = (u16)((S.vce_addr + 1u) & 511u);
            return v;
        }
        }
        return 0;
    }

    /* Dual HuC6270 VDC-A ($400) & VDC-B ($500) */
    if (port >= 0x400u && port < 0x600u)
        return fx_vdc_read((port >= 0x500u) ? 1 : 0, port & 7u);

    /* HuC6272 KING ($600..$6FE) */
    if (port >= 0x600u && port < 0x700u) {
        if ((port & 7u) == 0u) return S.king_ar;
        u8 r = S.king_ar;
        if (r == 0x00u) return fx_scsi_read_data();
        if (r == 0x05u) {
            /* SCSI Bus Status: b6=BSY, b5=REQ, b4=MSG, b3=CD, b2=IO */
            if (S.scsi_phase == 0u) return 0x00u;
            if (S.scsi_phase == 1u) return 0x68u;       /* BSY | REQ | CD */
            if (S.scsi_phase == 2u) return 0x64u;       /* BSY | REQ | IO (DATA IN) */
            if (S.scsi_phase == 3u) return 0x6Cu;       /* BSY | REQ | CD | IO (STATUS) */
            if (S.scsi_phase == 4u) return 0x7Cu;       /* BSY | REQ | MSG | CD | IO */
            return 0;
        }
        if (r == 0x10u) {
            u32 wa = ((u32)(S.king_kram_page & 1u) << 18) | (S.king_ra & 0x3FFFFu);
            u16 v = *(const u16 *)&KRAM_BUF[(wa * 2u) & (PCFX_KRAM_SIZE - 2u)];
            s32 stp = fx_king_step(S.king_ra);
            if ((port & 2u) || 1)
                S.king_ra = (S.king_ra & 0xFFFC0000u) | ((S.king_ra + (u32)stp) & 0x3FFFFu);
            return v;
        }
        if (r < 96u) return S.king_regs[r];
        return 0;
    }

    /* Interrupt Controller ($E00..$EFE) */
    if (port >= 0xE00u && port < 0xF00u) {
        u32 sub = port & 0xFCu;
        if (sub == 0x00u) return S.irq_pend;
        if (sub == 0x40u) return S.irq_mask;
        if (sub == 0x80u) return S.irq_prio[0];
        if (sub == 0xC0u) return S.irq_prio[1];
    }

    return 0;
}

static void fx_io_write16(u32 port, u16 val, int is_byte)
{
    u32 raw_port = port & 0xFFFu;
    port &= 0xFFEu;

    /* Gamepad ($000..$0BE) */
    if (port < 0x0C0u) {
        int ch = (port >= 0x080u) ? 1 : 0;
        if ((port & 0x7Eu) == 0x00u) {
            S.pad_ctrl[ch] = val;
            if (val & 1u)
                S.pad_data[ch] = fx_encode_pad(ch == 0 ? S.pad1 : 0u);
        }
        return;
    }

    /* Timer ($0C0..$0FE) */
    if (port < 0x100u) {
        if ((port & 0x3Eu) == 0x00u) {
            S.timer_ctrl = val;
            fx_clear_irq(9);
        } else if ((port & 0x3Eu) == 0x08u) {
            S.timer_period = val;
            S.timer_cnt = (val ? (s32)val : 65536) * 15;
        }
        return;
    }

    /* HuC6230 SoundBox ($100..$1FE) */
    if (port >= 0x100u && port < 0x200u) {
        u8 v8 = (u8)(val & 0xFFu);
        struct pcfx_psg_ch *ch = &S.psg[S.psg_ch_sel < 6u ? S.psg_ch_sel : 0u];
        switch (port & 0x3Eu) {
        case 0x00: S.psg_ch_sel = v8 & 7u; break;
        case 0x02: S.psg_main_bal = v8; break;
        case 0x04: ch->freq = (u16)((ch->freq & 0x0F00u) | v8); break;
        case 0x06: ch->freq = (u16)((ch->freq & 0x00FFu) | ((u16)(v8 & 0x0Fu) << 8)); break;
        case 0x08:
            if ((v8 & 0xC0u) == 0u) ch->widx = 0;
            ch->ctrl = v8;
            break;
        case 0x0A: ch->bal = v8; break;
        case 0x0C:
            ch->wave[ch->widx & 31u] = v8 & 0x1Fu;
            if (!(ch->ctrl & 0x80u)) ch->widx = (ch->widx + 1u) & 31u;
            break;
        case 0x0E: ch->noise = v8; break;
        case 0x28: S.cdda_vol_l = v8 & 63u; break;
        case 0x2A: S.cdda_vol_r = v8 & 63u; break;
        }
        return;
    }

    /* HuC6273 RAINBOW ($200..$2FE) */
    if (port >= 0x200u && port < 0x300u) {
        switch (port & 0x1Eu) {
        case 0x00: S.rbw_ctrl = val; break;
        case 0x04: S.rbw_kram_src = (S.rbw_kram_src & 0xFFFF0000u) | val; break;
        case 0x06: S.rbw_kram_src = (S.rbw_kram_src & 0x0000FFFFu) | ((u32)val << 16); break;
        case 0x08:
            S.rbw_blocks = val;
            if (val > 0) fx_rainbow_decode_strip();
            break;
        }
        return;
    }

    /* HuC6261 VCE ($300..$3FE) */
    if (port >= 0x300u && port < 0x400u) {
        switch (port & 0x1Eu) {
        case 0x00: S.vce_ctrl = val; break;
        case 0x02: S.vce_addr = val & 511u; break;
        case 0x04: {
            u32 idx = S.vce_addr & 511u;
            S.vce_pal[idx] = val;
            S.vce_rgb[idx] = M->yuv_lut[val];
            S.vce_addr = (u16)((idx + 1u) & 511u);
            break;
        }
        case 0x08: S.vce_pal_ofs[0] = val; break;
        case 0x0A: S.vce_pal_ofs[1] = val; break;
        case 0x0C: S.vce_pal_ofs[2] = val; break;
        case 0x0E: S.vce_pal_ofs[3] = val; break;
        case 0x10: S.vce_prio[0] = val; break;
        case 0x12: S.vce_prio[1] = val; break;
        }
        return;
    }

    /* Dual HuC6270 VDC-A ($400) & VDC-B ($500) */
    if (port >= 0x400u && port < 0x600u) {
        fx_vdc_write((port >= 0x500u) ? 1 : 0, raw_port & 7u, val, is_byte);
        return;
    }

    /* HuC6272 KING ($600..$6FE) */
    if (port >= 0x600u && port < 0x700u) {
        if ((raw_port & 7u) == 0u) {
            S.king_ar = (u8)(val & 0x7Fu);
            return;
        }
        u8 r = S.king_ar;
        if (r < 96u) S.king_regs[r] = val;

        if (r == 0x00u && S.scsi_phase == 1u) {
            static const u8 cdb_len[8] = { 6, 10, 10, 6, 12, 12, 10, 10 };
            if (S.scsi_cmd_pos == 0)
                S.scsi_cmd_len = cdb_len[(val >> 5) & 7u];
            S.scsi_cmd[S.scsi_cmd_pos++] = (u8)val;
            if (S.scsi_cmd_pos >= S.scsi_cmd_len)
                fx_scsi_exec_cmd();
            return;
        }
        if (r == 0x01u && (val & 0x04u)) {              /* SCSI SEL -> enter COMMAND phase */
            S.scsi_phase = 1u;
            S.scsi_cmd_pos = 0;
            return;
        }
        if (r == 0x0Bu && (val & 1u) && S.scsi_phase == 2u) {
            /* KING SCSI -> KRAM Hardware DMA! */
            u32 ka = (((u32)S.king_regs[0x09] | ((u32)(S.king_regs[0x0A] & 3u) << 16)) * 2u) & (PCFX_KRAM_SIZE - 2u);
            u32 nbytes = (u32)S.king_regs[0x08] * 2u;
            if (!nbytes) nbytes = 2048u;
            for (u32 i = 0; i < nbytes && S.scsi_phase == 2u; i++)
                KRAM_BUF[(ka + i) & (PCFX_KRAM_SIZE - 1u)] = fx_scsi_read_data();
            return;
        }
        if (r == 0x0Cu) {
            if (raw_port & 2u) S.king_ra = (S.king_ra & 0x0000FFFFu) | ((u32)val << 16);
            else               S.king_ra = (S.king_ra & 0xFFFF0000u) | val;
            return;
        }
        if (r == 0x0Du) {
            if (raw_port & 2u) S.king_wa = (S.king_wa & 0x0000FFFFu) | ((u32)val << 16);
            else               S.king_wa = (S.king_wa & 0xFFFF0000u) | val;
            return;
        }
        if (r == 0x0Eu) { S.king_kram_page = (u8)(val & 3u); return; }
        if (r == 0x10u) {
            u32 wa = ((u32)(S.king_kram_page & 1u) << 18) | (S.king_wa & 0x3FFFFu);
            *(u16 *)&KRAM_BUF[(wa * 2u) & (PCFX_KRAM_SIZE - 2u)] = val;
            s32 stp = fx_king_step(S.king_wa);
            S.king_wa = (S.king_wa & 0xFFFC0000u) | ((S.king_wa + (u32)stp) & 0x3FFFFu);
            return;
        }
        if (r == 0x14u && val > 0) {
            /* Main RAM -> KRAM DMA (0x12 = KRAM word addr, 0x13 = RAM word addr, 0x14 = word count) */
            u32 kd = ((u32)S.king_regs[0x12] * 2u) & (PCFX_KRAM_SIZE - 2u);
            u32 rs = ((u32)S.king_regs[0x13] * 2u) & (PCFX_RAM_SIZE - 2u);
            for (u32 i = 0; i < val; i++) {
                *(u16 *)&KRAM_BUF[(kd + i * 2u) & (PCFX_KRAM_SIZE - 2u)] =
                    *(const u16 *)&RAM_BUF[(rs + i * 2u) & (PCFX_RAM_SIZE - 2u)];
            }
            return;
        }
        if (r == 0x50u) {
            /* KING 2-Ch ADPCM Control: b0=ch0 on, b1=ch1 on, b2=ch0 loop, b3=ch1 loop */
            for (int c = 0; c < 2; c++) {
                if ((val & (1u << c)) && !S.adpcm[c].active) {
                    S.adpcm[c].start_a = ((u32)S.king_regs[0x58 + c * 3] << 8) & (PCFX_KRAM_SIZE - 1u);
                    S.adpcm[c].end_a   = ((u32)S.king_regs[0x59 + c * 3] << 8) & (PCFX_KRAM_SIZE - 1u);
                    S.adpcm[c].loop_a  = ((u32)S.king_regs[0x5A + c * 3] << 8) & (PCFX_KRAM_SIZE - 1u);
                    S.adpcm[c].cur_a   = S.adpcm[c].start_a;
                    S.adpcm[c].sample  = 0;
                    S.adpcm[c].step_idx= 0;
                    S.adpcm[c].nibble_hi = 0;
                    S.adpcm[c].vol_l   = (u8)(S.king_regs[0x51 + c] & 63u);
                    S.adpcm[c].vol_r   = (u8)((S.king_regs[0x51 + c] >> 8) & 63u);
                }
                S.adpcm[c].active = (val >> c) & 1u;
                S.adpcm[c].loop   = (val >> (c + 2)) & 1u;
            }
            return;
        }
        return;
    }

    /* Interrupt Controller ($E00..$EFE) */
    if (port >= 0xE00u && port < 0xF00u) {
        u32 sub = port & 0xFCu;
        if (sub == 0x00u) S.irq_pend &= val;
        else if (sub == 0x40u) S.irq_mask = val & 0xFFu;
        else if (sub == 0x80u) S.irq_prio[0] = val;
        else if (sub == 0xC0u) S.irq_prio[1] = val;
    }
}

static u32 fx_io_read32(u32 port)
{
    return fx_io_read16(port) | (fx_io_read16(port + 2u) << 16);
}

static void fx_io_write32(u32 port, u32 val)
{
    fx_io_write16(port, (u16)val, 0);
    fx_io_write16(port + 2u, (u16)(val >> 16), 0);
}

/* ============================================================================
   NEC V810 Memory Map ($00000000 RAM, $80000000 I/O, $E0000000 SRAM, $FFF00000 BIOS)
   ============================================================================ */

INLINE u8 fx_mem_r8(u32 a)
{
    if (a < PCFX_RAM_SIZE) return RAM_BUF[a];
    if (a >= 0xFFF00000u)  return BIOS_BUF[a & 0xFFFFFu];
    if ((a >> 24) == 0x80u) {
        u16 w = (u16)fx_io_read16(a & 0xFFEu);
        return (a & 1u) ? (u8)(w >> 8) : (u8)w;
    }
    if ((a >> 24) == 0xE0u) return M->sram[(a >> 1) & (PCFX_SRAM_SIZE - 1u)];
    return 0;
}

INLINE u16 fx_mem_r16(u32 a)
{
    a &= ~1u;
    if (a < PCFX_RAM_SIZE) return *(const u16 *)&RAM_BUF[a];
    if (a >= 0xFFF00000u)  return *(const u16 *)&BIOS_BUF[a & 0xFFFFEu];
    if ((a >> 24) == 0x80u) return (u16)fx_io_read16(a & 0xFFEu);
    if ((a >> 24) == 0xE0u) return M->sram[(a >> 1) & (PCFX_SRAM_SIZE - 1u)];
    return 0;
}

INLINE u32 fx_mem_r32(u32 a)
{
    a &= ~3u;
    if (a < PCFX_RAM_SIZE) return *(const u32 *)&RAM_BUF[a];
    if (a >= 0xFFF00000u)  return *(const u32 *)&BIOS_BUF[a & 0xFFFFCu];
    if ((a >> 24) == 0x80u) return fx_io_read32(a & 0xFFCu);
    return (u32)fx_mem_r16(a) | ((u32)fx_mem_r16(a + 2u) << 16);
}

INLINE void fx_mem_w8(u32 a, u8 v)
{
    if (a < PCFX_RAM_SIZE) { RAM_BUF[a] = v; return; }
    if ((a >> 24) == 0x80u) { fx_io_write16(a & 0xFFFu, v, 1); return; }
    if ((a >> 24) == 0xE0u) {
        u32 idx = (a >> 1) & (PCFX_SRAM_SIZE - 1u);
        if (M->sram[idx] != v) { M->sram[idx] = v; S.sram_dirty = 1u; }
    }
}

INLINE void fx_mem_w16(u32 a, u16 v)
{
    a &= ~1u;
    if (a < PCFX_RAM_SIZE) { *(u16 *)&RAM_BUF[a] = v; return; }
    if ((a >> 24) == 0x80u) { fx_io_write16(a & 0xFFEu, v, 0); return; }
    if ((a >> 24) == 0xE0u) {
        u32 idx = (a >> 1) & (PCFX_SRAM_SIZE - 1u);
        u8 b = (u8)v;
        if (M->sram[idx] != b) { M->sram[idx] = b; S.sram_dirty = 1u; }
    }
}

INLINE void fx_mem_w32(u32 a, u32 v)
{
    a &= ~3u;
    if (a < PCFX_RAM_SIZE) { *(u32 *)&RAM_BUF[a] = v; return; }
    if ((a >> 24) == 0x80u) { fx_io_write32(a & 0xFFCu, v); return; }
    fx_mem_w16(a, (u16)v);
    fx_mem_w16(a + 2u, (u16)(v >> 16));
}

/* ============================================================================
   NEC V810 32-Bit RISC + Pure-Integer IEEE-754 Single-Precision FPU
   ============================================================================ */

INLINE s32 fx_sext(u32 v, int bits)
{
    u32 m = 1u << (bits - 1);
    return (s32)((v ^ m) - m);
}

INLINE void fx_set_sz(u32 res)
{
    S.sr[SR_PSW] = (S.sr[SR_PSW] & ~(PSW_S | PSW_Z)) |
                   ((res == 0u) ? PSW_Z : 0u) |
                   ((res & 0x80000000u) ? PSW_S : 0u);
}

INLINE void fx_set_flag(u32 mask, int on)
{
    if (on) S.sr[SR_PSW] |= mask;
    else    S.sr[SR_PSW] &= ~mask;
}

static int fx_cond(u32 cond)
{
    u32 psw = S.sr[SR_PSW];
    int z = (psw & PSW_Z) != 0, s = (psw & PSW_S) != 0;
    int ov = (psw & PSW_OV) != 0, cy = (psw & PSW_CY) != 0;
    switch (cond & 15u) {
    case  0: return ov;
    case  1: return cy;
    case  2: return z;
    case  3: return z || cy;
    case  4: return s;
    case  5: return 1;
    case  6: return s ^ ov;
    case  7: return (s ^ ov) || z;
    case  8: return !ov;
    case  9: return !cy;
    case 10: return !z;
    case 11: return !(z || cy);
    case 12: return !s;
    case 13: return 0;
    case 14: return !(s ^ ov);
    default: return !((s ^ ov) || z);
    }
}

/* Pure 32-bit IEEE-754 single-precision helpers for V810 0x3E FPU opcodes */
static u32 fx_i32_to_f32(s32 x)
{
    if (x == 0) return 0u;
    u32 sign = (x < 0) ? 0x80000000u : 0u;
    u32 mag  = (x < 0) ? (0u - (u32)x) : (u32)x;
    int exp  = 158;
    while (mag >= 0x01000000u) { mag >>= 1; exp++; }
    while (mag <  0x00800000u) { mag <<= 1; exp--; }
    return sign | ((u32)exp << 23) | (mag & 0x7FFFFFu);
}

static s32 fx_f32_to_i32(u32 f)
{
    int exp = (int)((f >> 23) & 0xFFu) - 127;
    if (exp < 0) return 0;
    if (exp >= 31) return (f & 0x80000000u) ? (s32)0x80000000u : 0x7FFFFFFF;
    u32 m = (f & 0x7FFFFFu) | 0x800000u;
    u32 mag = (exp >= 23) ? (m << (exp - 23)) : (m >> (23 - exp));
    return (f & 0x80000000u) ? -(s32)mag : (s32)mag;
}

static u32 fx_f32_add(u32 a, u32 b)
{
    if ((a & 0x7FFFFFFFu) == 0u) return b;
    if ((b & 0x7FFFFFFFu) == 0u) return a;
    u32 sa = a >> 31, sb = b >> 31;
    int ea = (int)((a >> 23) & 0xFFu), eb = (int)((b >> 23) & 0xFFu);
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
    return (sa << 31) | ((u32)ea << 23) | ((mr >> 6) & 0x7FFFFFu);
}

static u32 fx_f32_mul(u32 a, u32 b)
{
    u32 s = (a ^ b) & 0x80000000u;
    int ea = (int)((a >> 23) & 0xFFu), eb = (int)((b >> 23) & 0xFFu);
    if (ea == 0 || eb == 0) return 0u;
    u32 ma = (a & 0x7FFFFFu) | 0x800000u;
    u32 mb = (b & 0x7FFFFFu) | 0x800000u;
    u32 hi, lo;
    fx_mulu64(ma, mb, &hi, &lo);
    u32 m = (hi << 9) | (lo >> 23);
    int er = ea + eb - 127;
    if (m >= 0x01000000u) { m >>= 1; er++; }
    if (er <= 0) return 0u;
    if (er >= 255) return s | 0x7F800000u;
    return s | ((u32)er << 23) | (m & 0x7FFFFFu);
}

static u32 fx_f32_div(u32 a, u32 b)
{
    u32 s = (a ^ b) & 0x80000000u;
    int ea = (int)((a >> 23) & 0xFFu), eb = (int)((b >> 23) & 0xFFu);
    if (eb == 0) return s | 0x7F800000u;
    if (ea == 0) return 0u;
    u32 num = (a & 0x7FFFFFu) | 0x800000u;
    u32 den = (b & 0x7FFFFFu) | 0x800000u;
    int er = ea - eb + 127;
    if (num < den) { num <<= 1; er--; }
    /* Pure 32-bit binary restoring mantissa division (24 quotient bits, zero 64-bit div!) */
    u32 q = 0u;
    for (int i = 23; i >= 0; i--) {
        if (num >= den) {
            num -= den;
            q |= (1u << i);
        }
        num <<= 1;
    }
    if (er <= 0) return 0u;
    if (er >= 255) return s | 0x7F800000u;
    return s | ((u32)er << 23) | (q & 0x7FFFFFu);
}

static void fx_v810_bstr(u32 subop)
{
    u32 len  = S.r[28];
    u32 dbo  = S.r[26] & 31u;
    u32 sbo  = S.r[27] & 31u;
    u32 dst  = S.r[29] & ~3u;
    u32 src  = S.r[30] & ~3u;
    while (len > 0) {
        u32 sb = (fx_mem_r32(src) >> sbo) & 1u;
        u32 dw = fx_mem_r32(dst);
        u32 db = (dw >> dbo) & 1u;
        u32 nb = db;
        switch (subop & 15u) {
        case  8: nb = db | sb; break;           /* ORBSU */
        case  9: nb = db & sb; break;           /* ANDBSU */
        case 10: nb = db ^ sb; break;           /* XORBSU */
        case 11: nb = sb; break;                /* MOVBSU */
        case 12: nb = db | (sb ^ 1u); break;    /* ORNBSU */
        case 13: nb = db & (sb ^ 1u); break;    /* ANDNBSU */
        case 14: nb = db ^ (sb ^ 1u); break;    /* XORNBSU */
        case 15: nb = sb ^ 1u; break;           /* NOTBSU */
        default: S.r[28] = 0; return;
        }
        dw = (dw & ~(1u << dbo)) | (nb << dbo);
        fx_mem_w32(dst, dw);
        sbo++; if (sbo >= 32u) { sbo = 0; src += 4u; }
        dbo++; if (dbo >= 32u) { dbo = 0; dst += 4u; }
        len--;
        S.cycles += 2;
    }
    S.r[26] = dbo; S.r[27] = sbo; S.r[28] = 0; S.r[29] = dst; S.r[30] = src;
}

static void fx_v810_run(s32 target_cycles)
{
    while (S.cycles < target_cycles) {
        int irq = fx_top_irq();
        if (irq >= 0) {
            S.sr[SR_EIPC]  = S.pc;
            S.sr[SR_EIPSW] = S.sr[SR_PSW];
            S.sr[SR_ECR]   = 0xFE00u | ((u32)irq << 4);
            u32 nia = (u32)(irq + 1);
            if (nia > 15u) nia = 15u;
            S.sr[SR_PSW] = (S.sr[SR_PSW] & ~PSW_IA) | (nia << 16) | PSW_EP | PSW_ID;
            S.pc = 0xFFFFFE00u | ((u32)irq << 4);
            S.halted = 0;
            S.cycles += 12;
        }

        if (S.halted) {
            S.cycles = target_cycles;
            break;
        }

        S.r[0] = 0;
        u16 op = fx_mem_r16(S.pc);
        u32 op6 = (u32)(op >> 10);

        if ((op6 & 0x38u) == 0x20u) {   /* Bcond / BR / NOP */
            u32 cond = (op >> 9) & 15u;
            if (cond != 13u && fx_cond(cond)) {
                S.pc += (u32)fx_sext(op & 0x1FEu, 9) & ~1u;
                S.cycles += 3;
            } else {
                S.pc += 2u;
                S.cycles += 1;
            }
            continue;
        }

        u32 r1 = op & 31u;
        u32 r2 = (op >> 5) & 31u;

        switch (op6) {
        case 0x00: S.pc += 2u; S.cycles += 1; if (r2) S.r[r2] = S.r[r1]; break; /* MOV */
        case 0x01: { /* ADD */
            S.pc += 2u; S.cycles += 1;
            u32 a = S.r[r2], b = S.r[r1], res = a + b;
            fx_set_flag(PSW_OV, (((a ^ ~b) & (a ^ res)) & 0x80000000u) != 0);
            fx_set_flag(PSW_CY, res < a);
            if (r2) S.r[r2] = res;
            fx_set_sz(r2 ? res : 0u);
            break;
        }
        case 0x02: { /* SUB */
            S.pc += 2u; S.cycles += 1;
            u32 a = S.r[r2], b = S.r[r1], res = a - b;
            fx_set_flag(PSW_OV, (((a ^ b) & (a ^ res)) & 0x80000000u) != 0);
            fx_set_flag(PSW_CY, res > a);
            if (r2) S.r[r2] = res;
            fx_set_sz(r2 ? res : 0u);
            break;
        }
        case 0x03: { /* CMP */
            S.pc += 2u; S.cycles += 1;
            u32 a = S.r[r2], b = S.r[r1], res = a - b;
            fx_set_sz(res);
            fx_set_flag(PSW_OV, (((a ^ b) & (a ^ res)) & 0x80000000u) != 0);
            fx_set_flag(PSW_CY, res > a);
            break;
        }
        case 0x04: { /* SHL */
            S.pc += 2u; S.cycles += 1;
            u32 sh = S.r[r1] & 31u, v = S.r[r2], res = v << sh;
            fx_set_flag(PSW_CY, sh && ((v >> (32u - sh)) & 1u));
            fx_set_flag(PSW_OV, 0);
            if (r2) S.r[r2] = res;
            fx_set_sz(r2 ? res : 0u);
            break;
        }
        case 0x05: { /* SHR */
            S.pc += 2u; S.cycles += 1;
            u32 sh = S.r[r1] & 31u, v = S.r[r2], res = v >> sh;
            fx_set_flag(PSW_CY, sh && ((v >> (sh - 1u)) & 1u));
            fx_set_flag(PSW_OV, 0);
            if (r2) S.r[r2] = res;
            fx_set_sz(r2 ? res : 0u);
            break;
        }
        case 0x06: S.pc = S.r[r1] & ~1u; S.cycles += 3; break; /* JMP [r1] */
        case 0x07: { /* SAR */
            S.pc += 2u; S.cycles += 1;
            u32 sh = S.r[r1] & 31u, v = S.r[r2], res = (u32)((s32)v >> sh);
            fx_set_flag(PSW_CY, sh && ((v >> (sh - 1u)) & 1u));
            fx_set_flag(PSW_OV, 0);
            if (r2) S.r[r2] = res;
            fx_set_sz(r2 ? res : 0u);
            break;
        }
        case 0x08: { /* MUL */
            S.pc += 2u; S.cycles += 13;
            u32 hi, lo;
            fx_muls64((s32)S.r[r1], (s32)S.r[r2], &hi, &lo);
            S.r[30] = hi;
            if (r2) S.r[r2] = lo;
            fx_set_sz(r2 ? lo : 0u);
            fx_set_flag(PSW_OV, hi != ((lo & 0x80000000u) ? 0xFFFFFFFFu : 0u));
            break;
        }
        case 0x09: { /* DIV */
            S.pc += 2u; S.cycles += 38;
            u32 d = S.r[r1];
            if (d == 0u) break;
            if (S.r[r2] == 0x80000000u && d == 0xFFFFFFFFu) {
                S.r[30] = 0u; if (r2) S.r[r2] = 0x80000000u; fx_set_flag(PSW_OV, 1); fx_set_sz(r2 ? 0x80000000u : 0u);
            } else {
                u32 q = (u32)((s32)S.r[r2] / (s32)d), rem = (u32)((s32)S.r[r2] % (s32)d);
                S.r[30] = rem; if (r2) S.r[r2] = q; fx_set_flag(PSW_OV, 0); fx_set_sz(r2 ? q : 0u);
            }
            break;
        }
        case 0x0A: { /* MULU */
            S.pc += 2u; S.cycles += 13;
            u32 hi, lo;
            fx_mulu64(S.r[r1], S.r[r2], &hi, &lo);
            S.r[30] = hi;
            if (r2) S.r[r2] = lo;
            fx_set_sz(r2 ? lo : 0u);
            fx_set_flag(PSW_OV, hi != 0u);
            break;
        }
        case 0x0B: { /* DIVU */
            S.pc += 2u; S.cycles += 36;
            u32 d = S.r[r1];
            if (d != 0u) {
                u32 q = S.r[r2] / d, rem = S.r[r2] % d;
                S.r[30] = rem; if (r2) S.r[r2] = q; fx_set_flag(PSW_OV, 0); fx_set_sz(r2 ? q : 0u);
            }
            break;
        }
        case 0x0C: { S.pc += 2u; S.cycles += 1; u32 res = S.r[r1] | S.r[r2]; if (r2) S.r[r2] = res; fx_set_flag(PSW_OV, 0); fx_set_sz(r2 ? res : 0u); break; }
        case 0x0D: { S.pc += 2u; S.cycles += 1; u32 res = S.r[r1] & S.r[r2]; if (r2) S.r[r2] = res; fx_set_flag(PSW_OV, 0); fx_set_sz(r2 ? res : 0u); break; }
        case 0x0E: { S.pc += 2u; S.cycles += 1; u32 res = S.r[r1] ^ S.r[r2]; if (r2) S.r[r2] = res; fx_set_flag(PSW_OV, 0); fx_set_sz(r2 ? res : 0u); break; }
        case 0x0F: { S.pc += 2u; S.cycles += 1; u32 res = ~S.r[r1];          if (r2) S.r[r2] = res; fx_set_flag(PSW_OV, 0); fx_set_sz(r2 ? res : 0u); break; }
        case 0x10: S.pc += 2u; S.cycles += 1; if (r2) S.r[r2] = (u32)fx_sext(r1, 5); break; /* MOV imm5 */
        case 0x11: { /* ADD imm5 */
            S.pc += 2u; S.cycles += 1;
            u32 a = S.r[r2], b = (u32)fx_sext(r1, 5), res = a + b;
            fx_set_flag(PSW_OV, (((a ^ ~b) & (a ^ res)) & 0x80000000u) != 0);
            fx_set_flag(PSW_CY, res < a);
            if (r2) S.r[r2] = res;
            fx_set_sz(r2 ? res : 0u);
            break;
        }
        case 0x12: S.pc += 2u; S.cycles += 1; if (r2) S.r[r2] = (u32)fx_cond(r1); break; /* SETF */
        case 0x13: { /* CMP imm5 */
            S.pc += 2u; S.cycles += 1;
            u32 a = S.r[r2], b = (u32)fx_sext(r1, 5), res = a - b;
            fx_set_sz(res);
            fx_set_flag(PSW_OV, (((a ^ b) & (a ^ res)) & 0x80000000u) != 0);
            fx_set_flag(PSW_CY, res > a);
            break;
        }
        case 0x14: { S.pc += 2u; S.cycles += 1; u32 v = S.r[r2], res = v << r1; fx_set_flag(PSW_CY, r1 && ((v >> (32u - r1)) & 1u)); fx_set_flag(PSW_OV, 0); if (r2) S.r[r2] = res; fx_set_sz(r2 ? res : 0u); break; }
        case 0x15: { S.pc += 2u; S.cycles += 1; u32 v = S.r[r2], res = v >> r1; fx_set_flag(PSW_CY, r1 && ((v >> (r1 - 1u)) & 1u));   fx_set_flag(PSW_OV, 0); if (r2) S.r[r2] = res; fx_set_sz(r2 ? res : 0u); break; }
        case 0x16: S.pc += 2u; S.cycles += 1; S.sr[SR_PSW] &= ~PSW_ID; break; /* EI */
        case 0x17: { S.pc += 2u; S.cycles += 1; u32 v = S.r[r2], res = (u32)((s32)v >> r1); fx_set_flag(PSW_CY, r1 && ((v >> (r1 - 1u)) & 1u)); fx_set_flag(PSW_OV, 0); if (r2) S.r[r2] = res; fx_set_sz(r2 ? res : 0u); break; }
        case 0x18: { /* TRAP */
            S.sr[SR_EIPC] = S.pc + 2u; S.sr[SR_EIPSW] = S.sr[SR_PSW];
            S.sr[SR_ECR] = 0xFFA0u + r1; S.sr[SR_PSW] |= PSW_EP | PSW_ID;
            S.pc = 0xFFFFFFA0u + (r1 & 0x10u); S.cycles += 12;
            break;
        }
        case 0x19: /* RETI */
            S.cycles += 8;
            if (S.sr[SR_PSW] & PSW_NP) { S.pc = S.sr[SR_FEPC] & ~1u; S.sr[SR_PSW] = S.sr[SR_FEPSW]; }
            else                       { S.pc = S.sr[SR_EIPC] & ~1u; S.sr[SR_PSW] = S.sr[SR_EIPSW]; }
            break;
        case 0x1A: S.pc += 2u; S.halted = 1u; break;                    /* HALT */
        case 0x1C: S.pc += 2u; S.cycles += 1; S.sr[r1] = S.r[r2]; break;/* LDSR */
        case 0x1D: S.pc += 2u; S.cycles += 1; if (r2) S.r[r2] = S.sr[r1]; break; /* STSR */
        case 0x1E: S.pc += 2u; S.cycles += 1; S.sr[SR_PSW] |= PSW_ID; break; /* DI */
        case 0x1F: S.pc += 2u; S.cycles += 2; fx_v810_bstr(r1); break;  /* BSTR */

        case 0x28: { u16 im = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 1; if (r2) S.r[r2] = S.r[r1] + (u32)(s32)(s16)im; break; } /* MOVEA */
        case 0x29: { /* ADDI */
            u16 im = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 1;
            u32 a = S.r[r1], b = (u32)(s32)(s16)im, res = a + b;
            fx_set_flag(PSW_OV, (((a ^ ~b) & (a ^ res)) & 0x80000000u) != 0);
            fx_set_flag(PSW_CY, res < a);
            if (r2) S.r[r2] = res;
            fx_set_sz(r2 ? res : 0u);
            break;
        }
        case 0x2A: { u32 lo = fx_mem_r16(S.pc + 2u); u32 d = ((op & 0x3FFu) << 16) | lo; S.pc += (u32)fx_sext(d, 26) & ~1u; S.cycles += 3; break; } /* JR */
        case 0x2B: { u32 lo = fx_mem_r16(S.pc + 2u); u32 d = ((op & 0x3FFu) << 16) | lo; S.r[31] = S.pc + 4u; S.pc += (u32)fx_sext(d, 26) & ~1u; S.cycles += 3; break; } /* JAL */
        case 0x2C: { u16 im = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 1; u32 res = S.r[r1] | im; if (r2) S.r[r2] = res; fx_set_flag(PSW_OV, 0); fx_set_sz(r2 ? res : 0u); break; } /* ORI */
        case 0x2D: { u16 im = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 1; u32 res = S.r[r1] & im; if (r2) S.r[r2] = res; fx_set_flag(PSW_OV, 0); fx_set_sz(r2 ? res : 0u); break; } /* ANDI */
        case 0x2E: { u16 im = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 1; u32 res = S.r[r1] ^ im; if (r2) S.r[r2] = res; fx_set_flag(PSW_OV, 0); fx_set_sz(r2 ? res : 0u); break; } /* XORI */
        case 0x2F: { u32 im = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 1; if (r2) S.r[r2] = S.r[r1] + (im << 16); break; } /* MOVHI */

        case 0x30: { u16 d = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 3; if (r2) S.r[r2] = (u32)(s32)(s8)fx_mem_r8(S.r[r1] + (u32)(s32)(s16)d); break; }  /* LD.B */
        case 0x31: { u16 d = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 3; if (r2) S.r[r2] = (u32)(s32)(s16)fx_mem_r16(S.r[r1] + (u32)(s32)(s16)d); break; } /* LD.H */
        case 0x33: { u16 d = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 4; if (r2) S.r[r2] = fx_mem_r32(S.r[r1] + (u32)(s32)(s16)d); break; }               /* LD.W */
        case 0x34: { u16 d = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 2; fx_mem_w8(S.r[r1] + (u32)(s32)(s16)d, (u8)S.r[r2]); break; }                     /* ST.B */
        case 0x35: { u16 d = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 2; fx_mem_w16(S.r[r1] + (u32)(s32)(s16)d, (u16)S.r[r2]); break; }                   /* ST.H */
        case 0x37: { u16 d = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 3; fx_mem_w32(S.r[r1] + (u32)(s32)(s16)d, S.r[r2]); break; }                        /* ST.W */

        /* PC-FX Dedicated Hardware I/O Port Instructions (IN.B / IN.H / IN.W / OUT.B / OUT.H / OUT.W)! */
        case 0x38: { u16 d = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 3; u32 p = S.r[r1] + (u32)(s32)(s16)d; u16 w = (u16)fx_io_read16(p & 0xFFEu); if (r2) S.r[r2] = (p & 1u) ? (w >> 8) : (w & 0xFFu); break; }
        case 0x39: { u16 d = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 3; if (r2) S.r[r2] = fx_io_read16(S.r[r1] + (u32)(s32)(s16)d); break; }
        case 0x3B: { u16 d = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 5; if (r2) S.r[r2] = fx_io_read32(S.r[r1] + (u32)(s32)(s16)d); break; }
        case 0x3C: { u16 d = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 2; fx_io_write16(S.r[r1] + (u32)(s32)(s16)d, (u8)S.r[r2], 1); break; }
        case 0x3D: { u16 d = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 2; fx_io_write16(S.r[r1] + (u32)(s32)(s16)d, (u16)S.r[r2], 0); break; }
        case 0x3F: { u16 d = fx_mem_r16(S.pc + 2u); S.pc += 4u; S.cycles += 4; fx_io_write32(S.r[r1] + (u32)(s32)(s16)d, S.r[r2]); break; }

        case 0x3E: { /* V810 IEEE-754 FPU & Extended Instructions */
            u16 w2 = fx_mem_r16(S.pc + 2u);
            S.pc += 4u; S.cycles += 6;
            u32 sub = w2 >> 10;
            u32 a = S.r[r2], b = S.r[r1], res = 0;
            switch (sub) {
            case 0x00: { /* CMPF.S */
                u32 diff = fx_f32_add(a, b ^ 0x80000000u);
                fx_set_sz(diff & 0x7FFFFFFFu ? diff : 0u);
                fx_set_flag(PSW_OV, 0);
                fx_set_flag(PSW_CY, (diff & 0x80000000u) != 0 && (diff & 0x7FFFFFFFu) != 0);
                break;
            }
            case 0x02: res = (u32)fx_f32_to_i32(b); if (r2) S.r[r2] = res; fx_set_sz(res); break; /* CVT.WS */
            case 0x03: res = fx_i32_to_f32((s32)b); if (r2) S.r[r2] = res; fx_set_sz(res); break; /* CVT.SW */
            case 0x04: res = fx_f32_add(a, b);      if (r2) S.r[r2] = res; fx_set_sz(res); break; /* ADDF.S */
            case 0x05: res = fx_f32_add(a, b ^ 0x80000000u); if (r2) S.r[r2] = res; fx_set_sz(res); break; /* SUBF.S */
            case 0x06: res = fx_f32_mul(a, b);      if (r2) S.r[r2] = res; fx_set_sz(res); break; /* MULF.S */
            case 0x07: res = fx_f32_div(a, b);      if (r2) S.r[r2] = res; fx_set_sz(res); break; /* DIVF.S */
            case 0x08: { u32 x = b, rev = 0; for (int i = 0; i < 32; i++) rev = (rev << 1) | ((x >> i) & 1u); if (r2) S.r[r2] = rev; break; }
            case 0x0B: res = (u32)fx_f32_to_i32(b); if (r2) S.r[r2] = res; fx_set_sz(res); break; /* TRNC.SW */
            }
            break;
        }
        default:
            S.pc += 2u; S.cycles += 1;
            break;
        }
    }
}

#pragma GCC optimize("O2")

/* ============================================================================
   PC-FX Multi-Chip Video Compositor (HuC6272 KING + Dual HuC6270 + RAINBOW + VCE)
   ============================================================================ */

static void fx_render_vdc_bg(int chip, int line, u16 *dst, u16 pal_base)
{
    const struct pcfx_vdc *v = &M->vdc[chip];
    if (!(v->regs[5] & 0x0080u)) return;    /* BG enable bit in CR */
    static const int mw_tab[4] = { 32, 64, 128, 128 };
    int mw = mw_tab[(v->regs[9] >> 4) & 3u];
    int mh = (v->regs[9] & 0x40u) ? 64 : 32;
    int sy = (line + (int)v->regs[8]) & (mh * 8 - 1);
    int ty = sy >> 3, fy = sy & 7;
    int bxr = (int)v->regs[7];
    int w = S.scr_w;
    int mw_px_mask = mw * 8 - 1;
    int row_base = ty * mw;

    for (int x = 0; x < w;) {
        int sx = (x + bxr) & mw_px_mask;
        int sx_in = sx & 7;
        int span = 8 - sx_in;
        if (x + span > w) span = w - x;
        int tx = sx >> 3;
        u16 bat = v->vram[(row_base + tx) & 0x7FFFu];
        u32 cg  = ((u32)(bat & 0x0FFFu) << 4) & 0x7FFFu;
        u16 p01 = v->vram[(cg + (u32)fy) & 0x7FFFu];
        u16 p23 = v->vram[(cg + 8u + (u32)fy) & 0x7FFFu];
        if (!(p01 | p23)) {
            x += span;
            continue;
        }
        u32 pal = (pal_base + (((bat >> 12) & 15u) << 4)) & 511u;
        const u16 *rgb = S.vce_rgb;
        int fx = 7 - sx_in;
        for (int k = 0; k < span; k++, fx--) {
            u32 pen = (((p01 >> fx) & 1u) << 0) | (((p01 >> (fx + 8)) & 1u) << 1) |
                      (((p23 >> fx) & 1u) << 2) | (((p23 >> (fx + 8)) & 1u) << 3);
            if (pen)
                dst[x + k] = rgb[(pal + pen) & 511u];
        }
        x += span;
    }
}

static void fx_render_vdc_obj(int chip, int line, u16 *dst, u16 pal_base)
{
    const struct pcfx_vdc *v = &M->vdc[chip];
    if (!(v->regs[5] & 0x0040u)) return;    /* Sprite enable bit in CR */
    int w = S.scr_w;
    static const int h_tab[4] = { 16, 32, 64, 64 };

    for (int i = 63; i >= 0; i--) {
        const u16 *sp = &v->satb[i * 4];
        int sy = (int)(sp[0] & 0x3FFu) - 64;
        int sx = (int)(sp[1] & 0x3FFu) - 32;
        u16 pat = (sp[2] >> 1) & 0x3FFu;
        u16 atr = sp[3];
        int sw = (atr & 0x0100u) ? 32 : 16;
        int sh = h_tab[(atr >> 12) & 3u];
        if (line < sy || line >= sy + sh) continue;

        int ry = (atr & 0x8000u) ? (sh - 1 - (line - sy)) : (line - sy);
        int hflip = (atr & 0x0800u) != 0;
        u32 pal = 256u + ((atr & 15u) << 4);
        int cy_cell = ry >> 4, iy = ry & 15;
        if (sw == 32) pat &= ~1u;
        if (sh == 32) pat &= ~2u;
        else if (sh == 64) pat &= ~6u;

        for (int cx = 0; cx < (sw >> 4); cx++) {
            int cell_x = hflip ? ((sw >> 4) - 1 - cx) : cx;
            u32 cg = (((u32)pat + (u32)(cy_cell * 2 + cell_x)) << 6) & 0x7FFFu;
            u16 pl0 = v->vram[(cg + (u32)iy) & 0x7FFFu];
            u16 pl1 = v->vram[(cg + 16u + (u32)iy) & 0x7FFFu];
            u16 pl2 = v->vram[(cg + 32u + (u32)iy) & 0x7FFFu];
            u16 pl3 = v->vram[(cg + 48u + (u32)iy) & 0x7FFFu];
            for (int px = 0; px < 16; px++) {
                int dx = sx + cx * 16 + px;
                if ((unsigned)dx >= (unsigned)w) continue;
                int bit = hflip ? px : (15 - px);
                u32 pen = (((pl0 >> bit) & 1u) << 0) | (((pl1 >> bit) & 1u) << 1) |
                          (((pl2 >> bit) & 1u) << 2) | (((pl3 >> bit) & 1u) << 3);
                if (pen)
                    dst[dx] = S.vce_rgb[(pal_base + pal + pen) & 511u];
            }
        }
    }
}

static void fx_render_king_bg(int bg_idx, int line, u16 *dst)
{
    u16 mode_reg = S.king_regs[0x20];
    u16 en_reg   = S.king_regs[0x21];
    if (!(en_reg & (1u << bg_idx))) return;

    u32 bpp_mode = (mode_reg >> (bg_idx * 3)) & 7u; /* 1=4bpp, 2=8bpp, 3=16bpp YUV */
    if (!bpp_mode) return;

    u32 base_b = ((u32)S.king_regs[0x22 + bg_idx * 2] << 10) & (PCFX_KRAM_SIZE - 1u);
    u32 size_c = S.king_regs[0x23 + bg_idx * 2];
    int bw = (size_c & 1u) ? 512 : 256;
    int bh = (size_c & 2u) ? 512 : 256;
    int scx = (s16)S.king_regs[0x2A + bg_idx * 2];
    int scy = (s16)S.king_regs[0x2B + bg_idx * 2];
    u16 pal_ofs = (S.vce_pal_ofs[2] & 0x1FFu);
    int w = S.scr_w;

    /* KING BG0 Hardware Affine Rotation & Zoom! */
    if (bg_idx == 0 && (mode_reg & 0x1000u) && bpp_mode == 2u) {
        s32 ma = (s16)S.king_regs[0x32];
        s32 mb = (s16)S.king_regs[0x33];
        s32 mc = (s16)S.king_regs[0x34];
        s32 md = (s16)S.king_regs[0x35];
        s32 cx = (s16)S.king_regs[0x36];
        s32 cy = (s16)S.king_regs[0x37];
        s32 dy = line - 120;
        s32 u = (cx << 8) + mb * dy + (-128) * ma;
        s32 v = (cy << 8) + md * dy + (-128) * mc;
        u32 xmask = (u32)(bw - 1), ymask = (u32)(bh - 1);
        for (int x = 0; x < w; x++) {
            u32 tx = ((u32)(u >> 8)) & xmask;
            u32 ty = ((u32)(v >> 8)) & ymask;
            u8 pen = KRAM_BUF[(base_b + ty * (u32)bw + tx) & (PCFX_KRAM_SIZE - 1u)];
            if (pen)
                dst[x] = S.vce_rgb[(pal_ofs + pen) & 511u];
            u += ma;
            v += mc;
        }
        return;
    }

    u32 sy = (u32)(line + scy) & (u32)(bh - 1);
    u32 xm = (u32)(bw - 1);
    if (bpp_mode == 3u) {               /* 16-bpp direct Y8U4V4 bitmap in KRAM! */
        u32 row = base_b + sy * (u32)bw * 2u;
        const u16 *lut = M->yuv_lut;
        for (int x = 0; x < w; x++) {
            u32 sx = (u32)(x + scx) & xm;
            u16 yuv = *(const u16 *)&KRAM_BUF[(row + sx * 2u) & (PCFX_KRAM_SIZE - 2u)];
            if (yuv)
                dst[x] = lut[yuv];
        }
    } else if (bpp_mode == 2u) {        /* 8-bpp 256-color bitmap in KRAM */
        u32 row = base_b + sy * (u32)bw;
        for (int x = 0; x < w; x++) {
            u32 sx = (u32)(x + scx) & xm;
            u8 pen = KRAM_BUF[(row + sx) & (PCFX_KRAM_SIZE - 1u)];
            if (pen)
                dst[x] = S.vce_rgb[(pal_ofs + pen) & 511u];
        }
    } else if (bpp_mode == 1u) {        /* 4-bpp 16-color bitmap in KRAM */
        u32 row = base_b + sy * ((u32)bw >> 1);
        for (int x = 0; x < w; x++) {
            u32 sx = (u32)(x + scx) & xm;
            u8 b = KRAM_BUF[(row + (sx >> 1)) & (PCFX_KRAM_SIZE - 1u)];
            u8 pen = (sx & 1u) ? (b & 15u) : (b >> 4);
            if (pen)
                dst[x] = S.vce_rgb[(pal_ofs + pen) & 511u];
        }
    }
}

static void fx_render_scanline(int line, u16 *dst)
{
    int w = S.scr_w;
    u16 backdrop = S.vce_rgb[0];
    for (int x = 0; x < w; x++)
        dst[x] = backdrop;

    /* Back-to-front PC-FX hardware compositor:
       1. RAINBOW motion YUV background (if active)
       2. KING BG3 -> BG2 -> BG1 -> BG0 (including BG0 affine!)
       3. HuC6270 VDC-B BG + 64 Sprites
       4. HuC6270 VDC-A BG + 64 Sprites */
    if ((S.rbw_ctrl & 1u) && S.rbw_ready_line) {
        const u16 *rrow = &M->rbw_fb[(line & 15) * 256];
        const u16 *lut = M->yuv_lut;
        for (int x = 0; x < w && x < 256; x++)
            if (rrow[x]) dst[x] = lut[rrow[x]];
    }

    for (int bg = 3; bg >= 0; bg--)
        fx_render_king_bg(bg, line, dst);

    u16 pb_b = S.vce_pal_ofs[1] & 0x1FFu;
    u16 pb_a = S.vce_pal_ofs[0] & 0x1FFu;
    fx_render_vdc_bg(1, line, dst, pb_b);
    fx_render_vdc_obj(1, line, dst, pb_b);
    fx_render_vdc_bg(0, line, dst, pb_a);
    fx_render_vdc_obj(0, line, dst, pb_a);
}

/* ============================================================================
   HuC6230 6-Ch PSG + 2-Ch KING ADPCM + Redbook CD-DA Audio @ 48 kHz
   ============================================================================ */

static s16 fx_audio_sample(void)
{
    static const int step_tab[49] = {
         16,  17,  19,  21,  23,  25,  28,  31,  34,  37,  41,  45,  50,  55,  60,  66,
         73,  80,  88,  97, 107, 118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307,
        337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963,1060,1166,1282,1411,1552
    };
    static const int idx_adj[8] = { -1, -1, -1, -1, 2, 4, 6, 8 };

    u32 sr = S.sample_rate ? S.sample_rate : 48000u;
    if (__builtin_expect(sr != S.cached_sr, 0)) {
        S.cached_sr = sr;
        S.adpcm_inc = (16000u << 8) / sr;
        S.cdda_inc  = (44100u << 8) / sr;
    }
    s32 mix = 0;

    /* 1. HuC6230 6-Channel 32-Step Wavetable / Noise PSG (3.58 MHz clock) */
    for (int i = 0; i < 6; i++) {
        struct pcfx_psg_ch *ch = &S.psg[i];
        if (!(ch->ctrl & 0x80u)) continue;
        s32 vol = (s32)(ch->ctrl & 0x1Fu);
        if (!vol) continue;
        s32 s5 = 0;
        if (ch->ctrl & 0x40u) {
            s5 = (s32)ch->wave[0] - 16;
        } else if (i >= 4 && (ch->noise & 0x80u)) {
            u32 nf = 32u - (ch->noise & 0x1Fu);
            u32 nk = (nf << 20) ^ sr;
            if (nk != S.ns_key[i - 4]) { S.ns_key[i - 4] = nk; S.ns_inc[i - 4] = (111860u << 8) / (nf * sr); }
            ch->phase += S.ns_inc[i - 4];
            while (ch->phase >= 256u) {
                ch->phase -= 256u;
                u16 b = (u16)(((ch->lfsr >> 0) ^ (ch->lfsr >> 1) ^ (ch->lfsr >> 11) ^ (ch->lfsr >> 12) ^ (ch->lfsr >> 17)) & 1u);
                ch->lfsr = (u16)((ch->lfsr >> 1) | (b << 14));
            }
            s5 = (ch->lfsr & 1u) ? 14 : -14;
        } else {
            u32 period = ch->freq ? ch->freq : 1u;
            u32 pk = (period << 18) ^ sr;
            if (pk != S.psg_key[i]) { S.psg_key[i] = pk; S.psg_inc[i] = (3579545u << 5) / (period * sr); }
            u32 inc = S.psg_inc[i];
            ch->phase += inc;
            ch->rpos = (u8)((ch->rpos + (ch->phase >> 5)) & 31u);
            ch->phase &= 31u;
            s5 = (s32)ch->wave[ch->rpos] - 16;
        }
        s32 lr = ((ch->bal >> 4) & 15u) + (ch->bal & 15u);
        if (!lr) lr = 24;
        mix += (s5 * vol * lr) >> 2;
    }

    /* 2. KING 2-Channel ADPCM (~16 kHz / rate_code) */
    for (int c = 0; c < 2; c++) {
        struct pcfx_adpcm_ch *ad = &S.adpcm[c];
        if (!ad->active) continue;
        ad->phase += S.adpcm_inc;
        while (ad->phase >= 256u) {
            ad->phase -= 256u;
            u8 byte = KRAM_BUF[ad->cur_a & (PCFX_KRAM_SIZE - 1u)];
            u8 nib = ad->nibble_hi ? (byte >> 4) : (byte & 15u);
            ad->nibble_hi ^= 1u;
            if (!ad->nibble_hi) {
                ad->cur_a++;
                if (ad->cur_a >= ad->end_a) {
                    if (ad->loop) ad->cur_a = ad->loop_a;
                    else { ad->active = 0; break; }
                }
            }
            int stp = step_tab[ad->step_idx];
            int diff = stp >> 3;
            if (nib & 1u) diff += stp >> 2;
            if (nib & 2u) diff += stp >> 1;
            if (nib & 4u) diff += stp;
            if (nib & 8u) ad->sample -= diff; else ad->sample += diff;
            if (ad->sample > 2047) ad->sample = 2047;
            else if (ad->sample < -2048) ad->sample = -2048;
            ad->step_idx += idx_adj[nib & 7u];
            if (ad->step_idx < 0) ad->step_idx = 0;
            else if (ad->step_idx > 48) ad->step_idx = 48;
        }
        s32 vsum = (s32)ad->vol_l + (s32)ad->vol_r;
        if (!vsum) vsum = 48;
        mix += (ad->sample * vsum) >> 4;
    }

    /* 3. Redbook CD-DA Stereo-to-Mono Resampler (44.1 kHz -> 48 kHz) */
    if (S.cdda_playing && S.cd && S.cd->read_2352) {
        S.cdda_frac += S.cdda_inc;
        while (S.cdda_frac >= 256u) {
            S.cdda_frac -= 256u;
            if (S.cdda_pos >= 2352u) {
                if (S.cdda_lba >= S.cdda_end_lba) {
                    if (S.cdda_loop) S.cdda_lba = S.cd->tracks[S.cd->last_track].lba;
                    else { S.cdda_playing = 0; break; }
                }
                if (S.cd->read_2352(S.cdda_lba, M->cdda_sec) != 0) {
                    S.cdda_playing = 0;
                    break;
                }
                S.cdda_lba++;
                S.cdda_pos = 0;
            }
            s16 l = *(const s16 *)&M->cdda_sec[S.cdda_pos];
            s16 r = *(const s16 *)&M->cdda_sec[S.cdda_pos + 2u];
            S.cdda_pos += 4u;
            mix += ((s32)l + (s32)r) >> 2;
        }
    }

    if (mix > 32767) mix = 32767;
    else if (mix < -32768) mix = -32768;
    return (s16)mix;
}

/* ============================================================================
   V810 Code Emitter & Clean-Room IPL + Built-in Playable 32-Bit PC-FX Game:
   "STAR SOLDIER FX-32" (V810 RISC + KING Affine BG0 + KING 16b YUV + Dual VDC + PSG)
   ============================================================================ */

static void v8_w16(u8 *b, u32 *p, u16 w) { *(u16 *)&b[*p] = w; *p += 2u; }
static void v8_movhi(u8 *b, u32 *p, u32 r1, u32 r2, u16 hi) { v8_w16(b, p, (u16)((0x2Fu << 10) | (r2 << 5) | r1)); v8_w16(b, p, hi); }
static void v8_movea(u8 *b, u32 *p, u32 r1, u32 r2, u16 lo) { v8_w16(b, p, (u16)((0x28u << 10) | (r2 << 5) | r1)); v8_w16(b, p, lo); }
static void v8_li32(u8 *b, u32 *p, u32 rd, u32 v)
{
    u16 lo = (u16)(v & 0xFFFFu);
    u16 hi = (u16)((v >> 16) + ((lo & 0x8000u) ? 1u : 0u));
    v8_movhi(b, p, 0, rd, hi);
    v8_movea(b, p, rd, rd, lo);
}
static void v8_outh(u8 *b, u32 *p, u32 rs_val, u16 port) { v8_w16(b, p, (u16)((0x3Du << 10) | (rs_val << 5) | 0u)); v8_w16(b, p, port); }
static void v8_inh(u8 *b, u32 *p, u32 rd_val, u16 port)  { v8_w16(b, p, (u16)((0x39u << 10) | (rd_val << 5) | 0u)); v8_w16(b, p, port); }

static void fx_build_cleanroom_bios(u32 boot_entry)
{
    fx_zero(BIOS_BUF, PCFX_BIOS_SIZE);

    /* Install V810 Hardware Interrupt Dispatchers at $FFFFFE80..$FFFFFEF0 (IRQ 8..15):
       Each vector checks if RAM[$00007F00 + irq*4] is non-zero; if so jumps via R29, else RETI! */
    for (int irq = 8; irq <= 15; irq++) {
        u32 vp = 0xFFE00u | ((u32)irq << 4);
        /* LD.W $7F00+irq*4[R0], R29 ; CMP 0, R29 ; BE +4 ; JMP [R29] ; RETI */
        v8_w16(BIOS_BUF, &vp, (u16)((0x33u << 10) | (29u << 5) | 0u));
        v8_w16(BIOS_BUF, &vp, (u16)(0x7F00u + irq * 4));
        v8_w16(BIOS_BUF, &vp, (u16)((0x13u << 10) | (29u << 5) | 0u));
        v8_w16(BIOS_BUF, &vp, (u16)((0x20u << 10) | (2u << 9) | 4u)); /* BE +4 */
        v8_w16(BIOS_BUF, &vp, (u16)((0x06u << 10) | 29u));            /* JMP [R29] */
        v8_w16(BIOS_BUF, &vp, (u16)(0x19u << 10));                    /* RETI */
    }

    /* Reset vector at $FFFFFFF0 -> JR $FFF00100 -> set SP=$001FFFC0, jump to boot_entry! */
    u32 rp = 0xFFFF0u;
    u32 disp = (0xFFF00100u - 0xFFFFFFF0u) & 0x03FFFFFFu;
    v8_w16(BIOS_BUF, &rp, (u16)((0x2Au << 10) | ((disp >> 16) & 0x3FFu)));
    v8_w16(BIOS_BUF, &rp, (u16)(disp & 0xFFFFu));

    u32 ip = 0x00100u;
    v8_li32(BIOS_BUF, &ip, 8u, PSW_ID);             /* Clear PSW_NP (leave PSW_ID until game runs EI!) */
    v8_w16(BIOS_BUF, &ip, (u16)((0x1Cu << 10) | (8u << 5) | SR_PSW));
    v8_li32(BIOS_BUF, &ip, 3u, 0x001FFFC0u);        /* R3 (SP) = top of 2 MB RAM */
    v8_li32(BIOS_BUF, &ip, 10u, boot_entry);
    v8_w16(BIOS_BUF, &ip, (u16)((0x06u << 10) | 10u)); /* JMP [R10] */
}

static u16 fx_rgb_to_yuv(u8 r, u8 g, u8 b)
{
    s32 y = ( 77 * (s32)r + 150 * (s32)g +  29 * (s32)b) >> 8;
    s32 u = ((-43 * (s32)r -  85 * (s32)g + 128 * (s32)b) >> 12) + 8;
    s32 v = ((128 * (s32)r - 107 * (s32)g -  21 * (s32)b) >> 12) + 8;
    if (y < 0) y = 0; else if (y > 255) y = 255;
    if (u < 0) u = 0; else if (u > 15) u = 15;
    if (v < 0) v = 0; else if (v > 15) v = 15;
    return (u16)(((u32)y << 8) | ((u32)u << 4) | (u32)v);
}

static void build_builtin_pcfx_game(void)
{
    fx_zero(RAM_BUF, PCFX_RAM_SIZE);
    fx_zero(KRAM_BUF, PCFX_KRAM_SIZE);

    /* 1. Pre-populate KRAM:
          - $00000..$0FFFF (64 KB): KING BG0 256x256 8-bpp Affine Rotating Cyber-Grid!
          - $20000..$3FFFF (128 KB): KING BG1 256x256 16-bpp Direct-YUV Deep-Space Nebula! */
    for (int y = 0; y < 256; y++) {
        for (int x = 0; x < 256; x++) {
            u8 pen = 0;
            if ((x & 31) == 0 || (y & 31) == 0)
                pen = (u8)(16 + (((x >> 5) ^ (y >> 5)) & 7));
            else if (((x & 31) == 16 && (y & 7) < 4) || ((y & 31) == 16 && (x & 7) < 4))
                pen = 24;
            KRAM_BUF[y * 256 + x] = pen;

            /* 16-bit Direct YUV Horizon Nebula in BG1 ($20000) */
            u8 r = (u8)(6 + (y >> 3));
            u8 g = (u8)(10 + ((x ^ y) >> 4));
            u8 b = (u8)(36 + ((255 - y) >> 2));
            u16 yuv = fx_rgb_to_yuv(r, g, b);
            if (((x * 73 + y * 197) & 511) == 0)
                yuv = fx_rgb_to_yuv(245, 250, 255);
            *(u16 *)&KRAM_BUF[0x20000u + (u32)(y * 256 + x) * 2u] = yuv;
        }
    }

    /* 2. Build VCE 512-entry YUV Palette Table at RAM $010000 (copied by V810 to $304):
          - 0..31: KING BG0 neon grid colors
          - 256..287: VDC-A Star Soldier ship (256+1..15) & Boss/Lasers (272+1..15)
          - 384..399: VDC-B HUD font palette */
    u16 *pal = (u16 *)&RAM_BUF[0x10000u];
    pal[0] = fx_rgb_to_yuv(4, 6, 24);
    for (int i = 0; i < 8; i++)
        pal[16 + i] = fx_rgb_to_yuv((u8)(30 + i * 26), (u8)(200 - i * 14), 255);
    pal[24] = fx_rgb_to_yuv(255, 190, 40);
    /* Ship palette (256..271) */
    pal[257] = fx_rgb_to_yuv(245, 250, 255);        /* White fuselage */
    pal[258] = fx_rgb_to_yuv(50, 150, 255);         /* Cobalt wing */
    pal[259] = fx_rgb_to_yuv(255, 60, 50);          /* Red core */
    pal[260] = fx_rgb_to_yuv(255, 230, 60);         /* Thruster / twin laser gold */
    /* Boss palette (272..287) */
    pal[273] = fx_rgb_to_yuv(255, 50, 190);
    pal[274] = fx_rgb_to_yuv(120, 255, 120);
    pal[275] = fx_rgb_to_yuv(255, 240, 120);
    /* VDC-B HUD Banner palette (16..31 of bank 384 -> VCEofs1 = 384, BG pal 0 = 384+1..3!) */
    pal[385] = fx_rgb_to_yuv(255, 240, 90);
    pal[386] = fx_rgb_to_yuv(90, 230, 255);

    /* 3. Build VDC-A Sprite CG at RAM $012000 (copied to VDC-A VRAM $1000: pat $40=Ship, $41=Laser, $42=CoreBoss) */
    static const char *const ship16[16] = {
        ".......11.......",
        "......1111......",
        "......1221......",
        ".....112211.....",
        "....11133111....",
        "...2211331122...",
        "..222111111222..",
        ".22221111112222.",
        "222..112211..222",
        "22...11..11...22",
        ".....44..44.....",
        ".....44..44.....",
        "......4..4......",
        "................",
        "................",
        "................"
    };
    u16 *vdc_cg = (u16 *)&RAM_BUF[0x12000u];
    for (int y = 0; y < 16; y++) {
        u16 p0 = 0, p1 = 0;
        for (int x = 0; x < 16; x++) {
            char c = ship16[y][x];
            u32 pen = (c >= '1' && c <= '4') ? (u32)(c - '0') : 0u;
            if (pen & 1u) p0 |= (u16)(1u << (15 - x));
            if (pen & 2u) p1 |= (u16)(1u << (15 - x));
            if (pen & 4u) vdc_cg[32 + y] |= (u16)(1u << (15 - x));
        }
        vdc_cg[y] = p0;
        vdc_cg[16 + y] = p1;
    }
    /* Pat $41 (offset 64 words): Twin Laser Bolt */
    for (int y = 2; y < 14; y++) {
        vdc_cg[64 + 32 + y] = 0x1818u;              /* pen 4 = gold twin bolt! */
    }
    /* Pat $42 (offset 128 words): Star-Core Boss */
    for (int y = 0; y < 16; y++) {
        for (int x = 0; x < 16; x++) {
            int dx = x - 7, dy = y - 7, d2 = dx * dx + dy * dy;
            u32 pen = (d2 <= 12) ? 3u : ((d2 <= 45) ? 1u : 0u);
            if (pen & 1u) vdc_cg[128 + y]      |= (u16)(1u << (15 - x));
            if (pen & 2u) vdc_cg[128 + 16 + y] |= (u16)(1u << (15 - x));
        }
    }

    /* 4. Build VDC-B HUD Font Tiles & BAT at RAM $014000 ("STAR SOLDIER FX-32  V810+KING") */
    u16 *vb_bat = (u16 *)&RAM_BUF[0x14000u];
    u16 *vb_chr = (u16 *)&RAM_BUF[0x15000u];
    static const char hud[] = "STAR SOLDIER FX-32  V810+KING";
    for (int c = 0; c < 64; c++) {
        const u8 *g = font5x7[c];
        for (int y = 0; y < 7; y++) {
            u8 row = 0;
            for (int x = 0; x < 5; x++)
                if ((g[y] >> (4 - x)) & 1u) row |= (u8)(1u << (6 - x));
            vb_chr[c * 16 + y] = (u16)((y < 3) ? row : 0u) | ((u16)((y >= 3) ? row : 0u) << 8);
        }
    }
    for (int i = 0; hud[i]; i++)
        vb_bat[32 + 1 + i] = (u16)(0x0100u + (u32)(hud[i] - 32));

    /* 5. Build 256-entry Signed Sine Table (8.8 fixed-point: round(sin*256)) at RAM $018000 for KING Affine BG0! */
    static const s16 qsin[65] = {
          0,   6,  13,  19,  25,  31,  38,  44,  50,  56,  62,  68,  74,  80,  86,  92,
         98, 104, 109, 115, 121, 126, 132, 137, 142, 147, 152, 157, 162, 167, 172, 177,
        181, 185, 190, 194, 198, 202, 206, 209, 213, 216, 220, 223, 226, 229, 231, 234,
        237, 239, 241, 243, 245, 247, 248, 250, 251, 252, 253, 254, 255, 255, 256, 256, 256
    };
    s16 *sintab = (s16 *)&RAM_BUF[0x18000u];
    for (int i = 0; i < 256; i++) {
        int q = (i >> 6) & 3, idx = i & 63;
        s16 v = (q == 0) ? qsin[idx] : (q == 1) ? qsin[64 - idx] : (q == 2) ? -qsin[idx] : -qsin[64 - idx];
        sintab[i] = v;
    }

    /* 6. Emit Native NEC V810 32-Bit RISC Program at RAM $008000! */
    u32 p = 0x008000u;

    /* Upload 512 VCE YUV colors: VCE_ADDR ($302) = 0, loop 512 words from $010000 -> OUT.H $304 */
    v8_outh(RAM_BUF, &p, 0, 0x0300u);               /* VCE 256px mode */
    v8_outh(RAM_BUF, &p, 0, 0x0302u);               /* VCE addr = 0 */
    v8_li32(RAM_BUF, &p, 10u, 0x0380u >> 4 ? 384u : 384u);
    v8_outh(RAM_BUF, &p, 10u, 0x030Au);             /* VDC-B palette offset = 384! */
    v8_li32(RAM_BUF, &p, 6u, 0x00010000u);
    v8_li32(RAM_BUF, &p, 7u, 512u);
    u32 l_pal = p;
    v8_w16(RAM_BUF, &p, (u16)((0x31u << 10) | (8u << 5) | 6u)); v8_w16(RAM_BUF, &p, 0); /* LD.H 0[R6], R8 */
    v8_outh(RAM_BUF, &p, 8u, 0x0304u);
    v8_w16(RAM_BUF, &p, (u16)((0x11u << 10) | (6u << 5) | 2u));                         /* ADD +2, R6 */
    v8_w16(RAM_BUF, &p, (u16)((0x11u << 10) | (7u << 5) | 0x1Fu));                      /* ADD -1, R7 */
    v8_w16(RAM_BUF, &p, (u16)((0x20u << 10) | (10u << 9) | (((s32)l_pal - (s32)p) & 0x1FEu))); /* BNE l_pal */

    /* Upload VDC-A Sprite CG ($012000 -> VRAM $1000, 192 words) & enable VDC-A OBJ + VBlank IRQ! */
    v8_outh(RAM_BUF, &p, 0u, 0x0400u);              /* AR = 0 (MAWR) */
    v8_li32(RAM_BUF, &p, 8u, 0x1000u);
    v8_outh(RAM_BUF, &p, 8u, 0x0404u);
    v8_li32(RAM_BUF, &p, 8u, 2u);
    v8_outh(RAM_BUF, &p, 8u, 0x0400u);              /* AR = 2 (VWR) */
    v8_li32(RAM_BUF, &p, 6u, 0x00012000u);
    v8_li32(RAM_BUF, &p, 7u, 192u);
    u32 l_va = p;
    v8_w16(RAM_BUF, &p, (u16)((0x31u << 10) | (8u << 5) | 6u)); v8_w16(RAM_BUF, &p, 0);
    v8_outh(RAM_BUF, &p, 8u, 0x0404u);
    v8_w16(RAM_BUF, &p, (u16)((0x11u << 10) | (6u << 5) | 2u));
    v8_w16(RAM_BUF, &p, (u16)((0x11u << 10) | (7u << 5) | 0x1Fu));
    v8_w16(RAM_BUF, &p, (u16)((0x20u << 10) | (10u << 9) | (((s32)l_va - (s32)p) & 0x1FEu)));
    v8_li32(RAM_BUF, &p, 8u, 5u);  v8_outh(RAM_BUF, &p, 8u, 0x0400u);
    v8_li32(RAM_BUF, &p, 8u, 0x0048u); v8_outh(RAM_BUF, &p, 8u, 0x0404u); /* VDC-A CR: Sprites + VBlank IRQ! */

    /* Upload VDC-B HUD BAT ($014000 -> VRAM $0000, 96 words) & Font ($015000 -> VRAM $1000, 1024 words) */
    v8_outh(RAM_BUF, &p, 0u, 0x0500u);
    v8_outh(RAM_BUF, &p, 0u, 0x0504u);
    v8_li32(RAM_BUF, &p, 8u, 2u); v8_outh(RAM_BUF, &p, 8u, 0x0500u);
    v8_li32(RAM_BUF, &p, 6u, 0x00014000u);
    v8_li32(RAM_BUF, &p, 7u, 96u);
    u32 l_vb1 = p;
    v8_w16(RAM_BUF, &p, (u16)((0x31u << 10) | (8u << 5) | 6u)); v8_w16(RAM_BUF, &p, 0);
    v8_outh(RAM_BUF, &p, 8u, 0x0504u);
    v8_w16(RAM_BUF, &p, (u16)((0x11u << 10) | (6u << 5) | 2u));
    v8_w16(RAM_BUF, &p, (u16)((0x11u << 10) | (7u << 5) | 0x1Fu));
    v8_w16(RAM_BUF, &p, (u16)((0x20u << 10) | (10u << 9) | (((s32)l_vb1 - (s32)p) & 0x1FEu)));

    v8_outh(RAM_BUF, &p, 0u, 0x0500u);
    v8_li32(RAM_BUF, &p, 8u, 0x1000u); v8_outh(RAM_BUF, &p, 8u, 0x0504u);
    v8_li32(RAM_BUF, &p, 8u, 2u); v8_outh(RAM_BUF, &p, 8u, 0x0500u);
    v8_li32(RAM_BUF, &p, 6u, 0x00015000u);
    v8_li32(RAM_BUF, &p, 7u, 1024u);
    u32 l_vb2 = p;
    v8_w16(RAM_BUF, &p, (u16)((0x31u << 10) | (8u << 5) | 6u)); v8_w16(RAM_BUF, &p, 0);
    v8_outh(RAM_BUF, &p, 8u, 0x0504u);
    v8_w16(RAM_BUF, &p, (u16)((0x11u << 10) | (6u << 5) | 2u));
    v8_w16(RAM_BUF, &p, (u16)((0x11u << 10) | (7u << 5) | 0x1Fu));
    v8_w16(RAM_BUF, &p, (u16)((0x20u << 10) | (10u << 9) | (((s32)l_vb2 - (s32)p) & 0x1FEu)));
    v8_li32(RAM_BUF, &p, 8u, 5u); v8_outh(RAM_BUF, &p, 8u, 0x0500u);
    v8_li32(RAM_BUF, &p, 8u, 0x0080u); v8_outh(RAM_BUF, &p, 8u, 0x0504u); /* VDC-B CR: BG on! */

    /* Configure HuC6272 KING: BG0 = 8bpp Affine ($00000), BG1 = 16bpp Direct YUV ($20000)! */
    v8_li32(RAM_BUF, &p, 8u, 0x20u); v8_outh(RAM_BUF, &p, 8u, 0x0600u);
    v8_li32(RAM_BUF, &p, 8u, 0x1000u | (3u << 3) | 2u); v8_outh(RAM_BUF, &p, 8u, 0x0604u);
    v8_li32(RAM_BUF, &p, 8u, 0x21u); v8_outh(RAM_BUF, &p, 8u, 0x0600u);
    v8_li32(RAM_BUF, &p, 8u, 0x0003u); v8_outh(RAM_BUF, &p, 8u, 0x0604u); /* Enable BG0 + BG1 */
    v8_li32(RAM_BUF, &p, 8u, 0x24u); v8_outh(RAM_BUF, &p, 8u, 0x0600u);
    v8_li32(RAM_BUF, &p, 8u, 0x20000u >> 10); v8_outh(RAM_BUF, &p, 8u, 0x0604u); /* BG1 KRAM base */

    /* Initialize HuC6230 6-Ch Wavetable Synth (Ch 0 lead + Ch 1 bass sawtooth)! */
    for (int ch = 0; ch < 2; ch++) {
        v8_li32(RAM_BUF, &p, 8u, (u32)ch); v8_outh(RAM_BUF, &p, 8u, 0x0100u);
        v8_outh(RAM_BUF, &p, 0u, 0x0108u);
        for (int s = 0; s < 32; s++) {
            u32 wv = (ch == 0) ? ((s < 16) ? 28u : 4u) : (u32)s;
            v8_li32(RAM_BUF, &p, 8u, wv); v8_outh(RAM_BUF, &p, 8u, 0x010Cu);
        }
        v8_li32(RAM_BUF, &p, 8u, 0xFFu); v8_outh(RAM_BUF, &p, 8u, 0x010Au);
        v8_li32(RAM_BUF, &p, 8u, (ch == 0) ? 254u : 508u); v8_outh(RAM_BUF, &p, 8u, 0x0104u);
        v8_li32(RAM_BUF, &p, 8u, ((ch == 0) ? 254u : 508u) >> 8); v8_outh(RAM_BUF, &p, 8u, 0x0106u);
        v8_li32(RAM_BUF, &p, 8u, (ch == 0) ? 0x9Bu : 0x99u); v8_outh(RAM_BUF, &p, 8u, 0x0108u);
    }

    /* Game state at RAM $002000: [0]=frame, [4]=sx(120), [8]=sy(192), [12]=laser_y(200) */
    v8_li32(RAM_BUF, &p, 12u, 0x00002000u);
    v8_li32(RAM_BUF, &p, 8u, 120u); v8_w16(RAM_BUF, &p, (u16)((0x37u << 10) | (8u << 5) | 12u)); v8_w16(RAM_BUF, &p, 4);
    v8_li32(RAM_BUF, &p, 8u, 192u); v8_w16(RAM_BUF, &p, (u16)((0x37u << 10) | (8u << 5) | 12u)); v8_w16(RAM_BUF, &p, 8);
    v8_li32(RAM_BUF, &p, 8u, 180u); v8_w16(RAM_BUF, &p, (u16)((0x37u << 10) | (8u << 5) | 12u)); v8_w16(RAM_BUF, &p, 12);

    /* Install IRQ 11 (VDC-A VBlank) handler at RAM[$7F00 + 11*4] = $008800, unmask IRQ 11 (~0x10 = 0xEF), EI + HALT loop! */
    v8_li32(RAM_BUF, &p, 8u, 0x00008800u);
    v8_w16(RAM_BUF, &p, (u16)((0x37u << 10) | (8u << 5) | 0u)); v8_w16(RAM_BUF, &p, (u16)(0x7F00u + 11 * 4));
    v8_li32(RAM_BUF, &p, 8u, 0x00EFu);
    v8_outh(RAM_BUF, &p, 8u, 0x0E40u);              /* Unmask IRQ 11 */
    v8_w16(RAM_BUF, &p, (u16)(0x16u << 10));        /* EI */
    u32 l_halt = p;
    v8_w16(RAM_BUF, &p, (u16)(0x1Au << 10));        /* HALT */
    v8_w16(RAM_BUF, &p, (u16)((0x20u << 10) | (5u << 9) | (((s32)l_halt - (s32)p) & 0x1FEu))); /* BR l_halt */

    /* ---- IRQ 11 VBlank Handler at RAM $008800 ---- */
    p = 0x008800u;
    v8_inh(RAM_BUF, &p, 8u, 0x0400u);               /* Clear VDC-A status & IRQ 11! */
    v8_li32(RAM_BUF, &p, 12u, 0x00002000u);
    v8_w16(RAM_BUF, &p, (u16)((0x33u << 10) | (13u << 5) | 12u)); v8_w16(RAM_BUF, &p, 0); /* R13 = frame */
    v8_w16(RAM_BUF, &p, (u16)((0x11u << 10) | (13u << 5) | 1u));                          /* frame++ */
    v8_w16(RAM_BUF, &p, (u16)((0x37u << 10) | (13u << 5) | 12u)); v8_w16(RAM_BUF, &p, 0);

    /* Strobe KP0 Gamepad ($000 = 1 -> IN.H $004 -> R14)! */
    v8_li32(RAM_BUF, &p, 8u, 1u); v8_outh(RAM_BUF, &p, 8u, 0x0000u);
    v8_inh(RAM_BUF, &p, 14u, 0x0004u);
    v8_w16(RAM_BUF, &p, (u16)((0x33u << 10) | (15u << 5) | 12u)); v8_w16(RAM_BUF, &p, 4); /* R15 = sx */
    /* Right (b9 = 0x0200): sx += 3; Left (b11 = 0x0800): sx -= 3 */
    v8_w16(RAM_BUF, &p, (u16)((0x2Du << 10) | (8u << 5) | 14u)); v8_w16(RAM_BUF, &p, 0x0200u);
    v8_w16(RAM_BUF, &p, (u16)((0x20u << 10) | (2u << 9) | 4u));
    v8_w16(RAM_BUF, &p, (u16)((0x11u << 10) | (15u << 5) | 3u));
    v8_w16(RAM_BUF, &p, (u16)((0x2Du << 10) | (8u << 5) | 14u)); v8_w16(RAM_BUF, &p, 0x0800u);
    v8_w16(RAM_BUF, &p, (u16)((0x20u << 10) | (2u << 9) | 4u));
    v8_w16(RAM_BUF, &p, (u16)((0x11u << 10) | (15u << 5) | 0x1Du));
    v8_w16(RAM_BUF, &p, (u16)((0x37u << 10) | (15u << 5) | 12u)); v8_w16(RAM_BUF, &p, 4);

    /* Update KING Affine Matrix (A=cos, B=-sin, C=sin, D=cos) + BG1 scroll + center scroll! */
    v8_li32(RAM_BUF, &p, 16u, 0x00018000u);         /* sintab */
    v8_w16(RAM_BUF, &p, (u16)((0x2Du << 10) | (8u << 5) | 13u)); v8_w16(RAM_BUF, &p, 0xFFu); /* ang = frame & 255 */
    v8_w16(RAM_BUF, &p, (u16)((0x14u << 10) | (8u << 5) | 1u));
    v8_w16(RAM_BUF, &p, (u16)((0x01u << 10) | (8u << 5) | 16u));
    v8_w16(RAM_BUF, &p, (u16)((0x31u << 10) | (17u << 5) | 8u)); v8_w16(RAM_BUF, &p, 0);  /* R17 = sin */
    v8_w16(RAM_BUF, &p, (u16)((0x29u << 10) | (8u << 5) | 13u)); v8_w16(RAM_BUF, &p, 64u);
    v8_w16(RAM_BUF, &p, (u16)((0x2Du << 10) | (8u << 5) | 8u));  v8_w16(RAM_BUF, &p, 0xFFu);
    v8_w16(RAM_BUF, &p, (u16)((0x14u << 10) | (8u << 5) | 1u));
    v8_w16(RAM_BUF, &p, (u16)((0x01u << 10) | (8u << 5) | 16u));
    v8_w16(RAM_BUF, &p, (u16)((0x31u << 10) | (18u << 5) | 8u)); v8_w16(RAM_BUF, &p, 0);  /* R18 = cos */
    v8_w16(RAM_BUF, &p, (u16)((0x00u << 10) | (19u << 5) | 0u));
    v8_w16(RAM_BUF, &p, (u16)((0x02u << 10) | (19u << 5) | 17u));                         /* R19 = -sin */

    v8_li32(RAM_BUF, &p, 8u, 0x32u); v8_outh(RAM_BUF, &p, 8u, 0x0600u); v8_outh(RAM_BUF, &p, 18u, 0x0604u);
    v8_li32(RAM_BUF, &p, 8u, 0x33u); v8_outh(RAM_BUF, &p, 8u, 0x0600u); v8_outh(RAM_BUF, &p, 19u, 0x0604u);
    v8_li32(RAM_BUF, &p, 8u, 0x34u); v8_outh(RAM_BUF, &p, 8u, 0x0600u); v8_outh(RAM_BUF, &p, 17u, 0x0604u);
    v8_li32(RAM_BUF, &p, 8u, 0x35u); v8_outh(RAM_BUF, &p, 8u, 0x0600u); v8_outh(RAM_BUF, &p, 18u, 0x0604u);
    v8_li32(RAM_BUF, &p, 8u, 0x36u); v8_outh(RAM_BUF, &p, 8u, 0x0600u); v8_outh(RAM_BUF, &p, 13u, 0x0604u);
    v8_li32(RAM_BUF, &p, 8u, 0x37u); v8_outh(RAM_BUF, &p, 8u, 0x0600u); v8_outh(RAM_BUF, &p, 13u, 0x0604u);
    /* Scroll BG1 Nebula vertically (-frame) */
    v8_li32(RAM_BUF, &p, 8u, 0x2Du); v8_outh(RAM_BUF, &p, 8u, 0x0600u); v8_outh(RAM_BUF, &p, 13u, 0x0604u);

    /* Arpeggiate HuC6230 Ch 0 melody note from frame! */
    v8_outh(RAM_BUF, &p, 0u, 0x0100u);
    v8_w16(RAM_BUF, &p, (u16)((0x15u << 10) | (8u << 5) | 0u));
    v8_w16(RAM_BUF, &p, (u16)((0x00u << 10) | (8u << 5) | 13u));
    v8_w16(RAM_BUF, &p, (u16)((0x15u << 10) | (8u << 5) | 3u));
    v8_w16(RAM_BUF, &p, (u16)((0x2Du << 10) | (8u << 5) | 8u)); v8_w16(RAM_BUF, &p, 7u);
    v8_w16(RAM_BUF, &p, (u16)((0x14u << 10) | (8u << 5) | 4u));
    v8_w16(RAM_BUF, &p, (u16)((0x29u << 10) | (8u << 5) | 8u)); v8_w16(RAM_BUF, &p, 160u);
    v8_outh(RAM_BUF, &p, 8u, 0x0104u);

    /* Write 3 Sprites to VDC-A VRAM $7F00 & trigger DVSSR ($13 = $7F00)!
       Spr 0: Ship at (sx, 192), pat=$40 ($80), pal=0
       Spr 1: Twin Laser zooming up, pat=$41 ($82), pal=0
       Spr 2: Core Boss swaying at (120 + (sin>>3), 48), pat=$42 ($84), pal=1 */
    v8_outh(RAM_BUF, &p, 0u, 0x0400u);
    v8_li32(RAM_BUF, &p, 8u, 0x7F00u); v8_outh(RAM_BUF, &p, 8u, 0x0404u);
    v8_li32(RAM_BUF, &p, 8u, 2u); v8_outh(RAM_BUF, &p, 8u, 0x0400u);

    /* Spr 0: Ship */
    v8_li32(RAM_BUF, &p, 8u, 192u + 64u); v8_outh(RAM_BUF, &p, 8u, 0x0404u);
    v8_w16(RAM_BUF, &p, (u16)((0x29u << 10) | (8u << 5) | 15u)); v8_w16(RAM_BUF, &p, 32u);
    v8_outh(RAM_BUF, &p, 8u, 0x0404u);
    v8_li32(RAM_BUF, &p, 8u, 0x0080u); v8_outh(RAM_BUF, &p, 8u, 0x0404u);
    v8_li32(RAM_BUF, &p, 8u, 0x0080u); v8_outh(RAM_BUF, &p, 8u, 0x0404u);

    /* Spr 1: Twin Laser (y = 188 - ((frame * 6) & 127)) */
    v8_w16(RAM_BUF, &p, (u16)((0x14u << 10) | (8u << 5) | 0u));
    v8_w16(RAM_BUF, &p, (u16)((0x00u << 10) | (8u << 5) | 13u));
    v8_w16(RAM_BUF, &p, (u16)((0x14u << 10) | (8u << 5) | 2u));
    v8_w16(RAM_BUF, &p, (u16)((0x2Du << 10) | (8u << 5) | 8u)); v8_w16(RAM_BUF, &p, 127u);
    v8_li32(RAM_BUF, &p, 9u, 188u + 64u);
    v8_w16(RAM_BUF, &p, (u16)((0x02u << 10) | (9u << 5) | 8u));
    v8_outh(RAM_BUF, &p, 9u, 0x0404u);
    v8_w16(RAM_BUF, &p, (u16)((0x29u << 10) | (8u << 5) | 15u)); v8_w16(RAM_BUF, &p, 32u);
    v8_outh(RAM_BUF, &p, 8u, 0x0404u);
    v8_li32(RAM_BUF, &p, 8u, 0x0082u); v8_outh(RAM_BUF, &p, 8u, 0x0404u);
    v8_li32(RAM_BUF, &p, 8u, 0x0080u); v8_outh(RAM_BUF, &p, 8u, 0x0404u);

    /* Spr 2: Swaying Core Boss */
    v8_li32(RAM_BUF, &p, 8u, 48u + 64u); v8_outh(RAM_BUF, &p, 8u, 0x0404u);
    v8_w16(RAM_BUF, &p, (u16)((0x00u << 10) | (8u << 5) | 17u));
    v8_w16(RAM_BUF, &p, (u16)((0x17u << 10) | (8u << 5) | 2u));
    v8_w16(RAM_BUF, &p, (u16)((0x29u << 10) | (8u << 5) | 8u)); v8_w16(RAM_BUF, &p, 120u + 32u);
    v8_outh(RAM_BUF, &p, 8u, 0x0404u);
    v8_li32(RAM_BUF, &p, 8u, 0x0084u); v8_outh(RAM_BUF, &p, 8u, 0x0404u);
    v8_li32(RAM_BUF, &p, 8u, 0x0081u); v8_outh(RAM_BUF, &p, 8u, 0x0404u);

    /* Trigger DVSSR ($13 = $7F00) & RETI! */
    v8_li32(RAM_BUF, &p, 8u, 19u); v8_outh(RAM_BUF, &p, 8u, 0x0400u);
    v8_li32(RAM_BUF, &p, 8u, 0x7F00u); v8_outh(RAM_BUF, &p, 8u, 0x0404u);
    v8_w16(RAM_BUF, &p, (u16)(0x19u << 10));

    fx_build_cleanroom_bios(0x00008000u);
}

/* ============================================================================
   Public API: pcfx_set_bios, pcfx_load, pcfx_reset, pcfx_frame, Audio & Save
   ============================================================================ */

void pcfx_set_bios(const u8 *rom, u32 size)
{
    if (rom && size >= 0x40000u) {
        fx_zero(BIOS_BUF, PCFX_BIOS_SIZE);
        u32 cap = size < PCFX_BIOS_SIZE ? size : PCFX_BIOS_SIZE;
        for (u32 i = 0; i < cap; i++) BIOS_BUF[i] = rom[i];
        M->bios_magic = 0x50434658u;
    } else {
        M->bios_magic = 0;
    }
}

void pcfx_reset(void)
{
    fx_zero(S.r, sizeof(S.r));
    fx_zero(S.sr, sizeof(S.sr));
    S.sr[SR_PSW] = PSW_NP | PSW_ID;
    S.sr[SR_PIR] = 0x00005100u;
    S.pc         = 0xFFFFFFF0u;
    S.halted     = 0;
    S.cycles     = 0;

    S.irq_pend   = 0;
    S.irq_mask   = 0x7Fu;
    S.timer_ctrl = 0;
    S.scsi_phase = 0;
    S.cdda_playing = 0;
    S.snd_head = S.snd_tail = 0;
}

const char *pcfx_load(const struct cdrom_toc *cd, const char *path)
{
    u32 keep_rate = S.sample_rate;
    if (keep_rate != 48000u && keep_rate != 44100u && keep_rate != 32000u && keep_rate != 22050u)
        keep_rate = 48000u;
    u8 use_ext_bios = (path && *path && M->bios_magic == 0x50434658u) ? 1u : 0u;
    M->bios_magic = 0;

    fx_zero(&S, sizeof(S));
    fx_zero(M->vdc, sizeof(M->vdc));
    fx_zero(M->rbw_fb, sizeof(M->rbw_fb));
    fx_zero(M->sram, sizeof(M->sram));
    S.sample_rate = keep_rate;
    S.cd          = cd;
    S.ext_bios    = use_ext_bios;
    S.scr_w       = 256;
    S.scr_h       = 240;

    /* Always rebuild YUV->RGB555 table unconditionally (EMU_RAM_PHYS safe!) */
    fx_init_yuv_lut();

    if (!path || !*path || !cd) {
        build_builtin_pcfx_game();
        static const char bi[] = "Star Soldier FX-32 (Built-in PC-FX V810 + KING Affine/YUV + Dual VDC)";
        for (u32 i = 0; i < sizeof(bi); i++) S.info[i] = bi[i];
        pcfx_reset();
        return 0;
    }

    fx_zero(RAM_BUF, PCFX_RAM_SIZE);
    fx_zero(KRAM_BUF, PCFX_KRAM_SIZE);

    /* Boot PC-FX CD-ROM ("PC-FX:Hu_CD-ROM" IPL boot header at data track LBA + 0..1)! */
    u32 base_lba = fx_cd_data_base();
    u8 sec0[2048], sec1[2048];
    fx_zero(sec0, sizeof(sec0));
    fx_zero(sec1, sizeof(sec1));
    if (!cd->read_2048 || cd->read_2048(base_lba, sec0) != 0)
        return "Cannot read PC-FX boot sector";
    (void)cd->read_2048(base_lba + 1u, sec1);

    u32 entry_pc = 0x00008000u;
    /* Check both sector 1 (standard PC-FX boot record) and sector 0 + 0x20 */
    const u8 *bh = (sec0[0] == 'P' && sec0[1] == 'C' && sec0[2] == '-' && sec0[3] == 'F') ? sec1 : sec0;
    u32 prog_lba  = *(const u32 *)&bh[0x020];
    u32 prog_secs = *(const u32 *)&bh[0x024];
    u32 load_addr = *(const u32 *)&bh[0x028];
    u32 boot_pc   = *(const u32 *)&bh[0x02C];

    if (!S.ext_bios) {
        if (prog_secs > 0 && prog_secs <= 1024u && load_addr < PCFX_RAM_SIZE) {
            for (u32 s = 0; s < prog_secs; s++) {
                u32 dst = load_addr + s * 2048u;
                if (dst + 2048u > PCFX_RAM_SIZE) break;
                if (cd->read_2048(prog_lba + s, &RAM_BUF[dst]) != 0) break;
            }
            if (boot_pc < PCFX_RAM_SIZE)
                entry_pc = boot_pc;
            else
                entry_pc = load_addr;
        }
        fx_build_cleanroom_bios(entry_pc);
    }

    static const char dinfo[] = "NEC PC-FX CD-ROM (21.5 MHz V810 + KING + Dual VDC + RAINBOW + HuC6230)";
    for (u32 i = 0; i < sizeof(dinfo); i++) S.info[i] = dinfo[i];
    pcfx_reset();
    return 0;
}

void pcfx_frame(u16 pad, u16 *picture)
{
    S.pad1 = pad;
    S.scr_w = (S.vce_ctrl & 1u) ? 320 : 256;

    const int total_lines = 263;
    const int vis_h = 240;
    const s32 cyc_per_line = 1365;      /* 21.47727 MHz / 59.94 Hz / 263 lines */
    u32 target_samples = (S.sample_rate ? S.sample_rate : 48000u) / 60u;
    u32 samp_acc = 0;

    S.cycles = 0;

    for (int line = 0; line < total_lines; line++) {
        fx_v810_run((line + 1) * cyc_per_line);

        /* Hardware 16-bit Timer ($0C0) */
        if (S.timer_ctrl & 0x04u) {
            S.timer_cnt -= cyc_per_line;
            if (S.timer_cnt <= 0) {
                S.timer_cnt += (S.timer_period ? (s32)S.timer_period : 65536) * 15;
                if (S.timer_ctrl & 0x02u)
                    fx_raise_irq(9);
            }
        }

        /* VDC-A & VDC-B RCR Raster Compare */
        for (int c = 0; c < 2; c++) {
            struct pcfx_vdc *v = &M->vdc[c];
            if ((int)v->regs[6] - 64 == line && (v->regs[5] & 0x0004u)) {
                v->status |= 0x04u;
                fx_raise_irq(c == 0 ? 11 : 12);
            }
        }

        if (line < vis_h && picture)
            fx_render_scanline(line, picture + (u32)line * (u32)S.scr_w);

        if (line == vis_h) {
            for (int c = 0; c < 2; c++) {
                struct pcfx_vdc *v = &M->vdc[c];
                v->status |= 0x20u;
                /* Auto-SATB repeat if DCR bit 4 set */
                if (v->regs[15] & 0x0010u) {
                    u32 sa = v->regs[19] & 0x7FFFu;
                    for (u32 i = 0; i < 256u; i++)
                        v->satb[i] = v->vram[(sa + i) & 0x7FFFu];
                }
                if (v->regs[5] & 0x0008u)
                    fx_raise_irq(c == 0 ? 11 : 12);
            }
        }

        samp_acc += target_samples;
        while (samp_acc >= (u32)total_lines) {
            samp_acc -= (u32)total_lines;
            s16 s = fx_audio_sample();
            if (S.snd_head - S.snd_tail < PCFX_SND_RING)
                M->snd_ring[S.snd_head++ & (PCFX_SND_RING - 1u)] = s;
        }
    }

    S.frame_no++;
}

int pcfx_width(void)  { return S.scr_w ? S.scr_w : 256; }
int pcfx_height(void) { return S.scr_h ? S.scr_h : 240; }
const char *pcfx_info(void) { return S.info; }

u8 *pcfx_save_ram(u32 *size, int *battery)
{
    if (size) *size = PCFX_SRAM_SIZE;
    if (battery) *battery = 1;
    return M->sram;
}

int pcfx_save_changed(void)
{
    int d = S.sram_dirty;
    S.sram_dirty = 0;
    return d;
}

int pcfx_jammed(void) { return S.jammed; }

void pcfx_audio_rate(u32 hz)
{
    S.sample_rate = hz ? hz : 48000u;
}

int pcfx_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && S.snd_tail != S.snd_head)
        out[n++] = M->snd_ring[S.snd_tail++ & (PCFX_SND_RING - 1u)];
    return n;
}

#ifdef PCFX_HOST
void pcfx_host_poison_mem(void)
{
    u8 *b = (u8 *)&pcfx_host_mem;
    for (u32 i = 0; i < sizeof(pcfx_host_mem); i++)
        b[i] = (u8)(0x5Au ^ (i & 0xFFu));
}
#endif
