/* Mattel Intellivision (.int / .rom) emulator:
   - GI CP1610 16-bit microprocessor (894.886 kHz NTSC, 14,934 cycles/frame, SDBD, interruptible rules)
   - AY-3-8900-1 STIC (176 x 208 BGR555 with 8px TV border: Color Stack, F/B, Colored Squares, 8 MOBs, GRAM, GROM,
     fine H/V delay scroll, border masking, hardware MOB/BG/border collisions, VBlank register/GRAM windows & BUSRQ)
   - AY-3-8914 3-channel PSG + 17-bit LFSR noise + 4-scale envelope synthesized at 48 kHz mono
   - Hand controllers ($01FE/$01FF): 16-direction disc, 3 side action buttons, 12-key keypad
   - Supports Intellicart .rom (segmented + CRC-16 + RAM attributes) and raw big-endian .int/.bin images
   - Clean-room built-in mini-EXEC ($1000..$1FFF) & 256-card GROM ($3000..$37FF) + optional external exec.bin/grom.bin */
#pragma GCC optimize("O2")

#ifdef __mips__
#include "hw.h"
#endif
#include "intv.h"

#define PAD_A      0x0001u
#define PAD_B      0x0002u
#define PAD_SELECT 0x0004u
#define PAD_START  0x0008u
#define PAD_UP     0x0010u
#define PAD_DOWN   0x0020u
#define PAD_LEFT   0x0040u
#define PAD_RIGHT  0x0080u
#define PAD_X      0x0100u
#define PAD_Y      0x0200u
#define PAD_L      0x0400u
#define PAD_R      0x0800u

#define INTV_AUD_MAX    2048
#define FRAME_CYCLES    14934
#define LINE_CYCLES     57
#define FIRST_HOLD      68
#define FETCH_HOLD      108
#define EXTRA_HOLD      38
#define FIRST_GAP       120
#define FETCH_TIME      (FIRST_GAP + 12 * LINE_CYCLES * 16 + LINE_CYCLES + 17)
#define GFX_WINDOW      (FRAME_CYCLES - FETCH_TIME)   /* 3796 */
#define REG_WINDOW      (GFX_WINDOW - 896)            /* 2900 */

#define ATTR_READ       0x01u
#define ATTR_WRITE16    0x02u
#define ATTR_WRITE8     0x04u

#define ALLOW_IRQ       1u
#define ALLOW_BUSRQ     2u

struct intv_work {
    u16 cart_mem[65536];
    u8 cart_attr[256];       /* per 256-word page */
    u16 exec[4096];          /* $1000..$1FFF */
    u16 ext_exec[4096];
    u16 exec_aux[256];       /* $0400..$04FF (Intellivision II) */
    u8 grom[2048];           /* $3000..$37FF */
    u8 ext_grom[2048];
    u8 gram[512];            /* $3800..$39FF */
    u8 scratch_ram[240];     /* $0100..$01EF */
    u16 sys_ram[352];        /* $0200..$035F */
    u16 stic_regs[64];
    u16 stic_cards[240];

    /* Renderer scratch */
    u8 bg_col[160 * 96];
    u8 bg_on[160 * 96];
    u8 last_bg[12];
    u8 mob_col[176 * 224];
    u8 mob_on[176 * 224];
    u8 mob_behind[176 * 224];
    u16 mob_rows[8][16];
    u8 mob_active[8];
    u8 img[176 * 224];

    s16 aud_buf[INTV_AUD_MAX];
};

#ifdef __mips__
#define W (*((struct intv_work *)KSEG0(EMU_RAM_PHYS)))
#else
static struct intv_work intv_host_work;
#define W intv_host_work
#endif

static struct {
    u8 has_ext_exec;
    u8 has_ext_aux;
    u8 has_ext_grom;
    u8 is_rom_fmt;
    u8 jammed;

    /* CP1610 state */
    u16 r[8];
    u8 s, z, o, c;
    u8 ie, d, intr, halted;

    /* STIC timing & mode */
    u8 color_stack_mode;
    u8 enable_req;
    u8 display_enabled;
    int now_cyc;
    int access_from;
    int regs_until;
    int gfx_until;

    /* AY-3-8914 PSG */
    u8 psg_reg[16];
    int tone_cnt[3];
    u8 tone_out[3];
    int noise_cnt;
    u32 noise_lfsr;
    int env_cnt;
    int env_step;
    u8 env_lvl;
    int psg_cyc_rem;

    /* Audio output */
    u32 sample_rate;
    u32 aud_count;
    u32 aud_frac;
    int dc_acc;

    /* Input & HLE EXEC boot state */
    u16 pad;
    u8 ext_key;
    u8 boot_stage;           /* 0=reset, 1=title wait, 2=running game */
    u8 title_wait;
    u16 start_addr;
    u16 lfsr_rnd;

    char info_str[96];
} S;

#define BGR555(r, g, b) ((u16)((((u32)(b) & 0xF8u) << 7) | (((u32)(g) & 0xF8u) << 2) | (((u32)(r) & 0xF8u) >> 3)))

/* Authentic 16-color AY-3-8900-1 STIC palette in BGR555 */
static const u16 stic_pal[16] = {
    BGR555(  0,   0,   0), /*  0 Black */
    BGR555(  0,  45, 255), /*  1 Blue */
    BGR555(255,  61,  16), /*  2 Red */
    BGR555(201, 207, 171), /*  3 Tan */
    BGR555( 56, 107,  63), /*  4 Dark Green */
    BGR555(  0, 167,  86), /*  5 Green */
    BGR555(250, 234,  80), /*  6 Yellow */
    BGR555(255, 252, 255), /*  7 White */
    BGR555(189, 172, 200), /*  8 Grey */
    BGR555( 36, 184, 255), /*  9 Cyan */
    BGR555(255, 180,  31), /* 10 Orange */
    BGR555( 84, 110,   0), /* 11 Brown */
    BGR555(255,  78,  87), /* 12 Pink */
    BGR555(164, 150, 255), /* 13 Light Blue */
    BGR555(117, 204, 128), /* 14 Yellow-Green */
    BGR555(181,  26,  88)  /* 15 Purple */
};

static const s16 ay_vol[16] = {
    0, 72, 102, 144, 204, 288, 408, 577, 816, 1154, 1632, 2308, 3264, 4616, 6528, 9232
};

/* Clean-room 96-character 8x8 ASCII font (0x20..0x7F -> GROM cards 0..95) */
static const u8 grom_ascii96[96][8] = {
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, {0x18,0x18,0x18,0x18,0x18,0x00,0x18,0x00},
    {0x6C,0x6C,0x24,0x00,0x00,0x00,0x00,0x00}, {0x6C,0xFE,0x6C,0x6C,0xFE,0x6C,0x00,0x00},
    {0x18,0x7E,0xD8,0x7C,0x1B,0x7E,0x18,0x00}, {0xC6,0xCC,0x18,0x30,0x66,0xC6,0x00,0x00},
    {0x38,0x6C,0x38,0x76,0xDC,0xCC,0x76,0x00}, {0x18,0x18,0x30,0x00,0x00,0x00,0x00,0x00},
    {0x0C,0x18,0x30,0x30,0x30,0x18,0x0C,0x00}, {0x30,0x18,0x0C,0x0C,0x0C,0x18,0x30,0x00},
    {0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00}, {0x00,0x18,0x18,0x7E,0x18,0x18,0x00,0x00},
    {0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x30}, {0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0x00},
    {0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00}, {0x06,0x0C,0x18,0x30,0x60,0xC0,0x00,0x00},
    {0x7C,0xC6,0xCE,0xD6,0xE6,0xC6,0x7C,0x00}, {0x18,0x38,0x18,0x18,0x18,0x18,0x7E,0x00},
    {0x7C,0xC6,0x06,0x3C,0x60,0xC0,0xFE,0x00}, {0x7C,0xC6,0x06,0x3C,0x06,0xC6,0x7C,0x00},
    {0x1C,0x3C,0x6C,0xCC,0xFE,0x0C,0x0C,0x00}, {0xFE,0xC0,0xFC,0x06,0x06,0xC6,0x7C,0x00},
    {0x7C,0xC0,0xFC,0xC6,0xC6,0xC6,0x7C,0x00}, {0xFE,0x06,0x0C,0x18,0x30,0x30,0x30,0x00},
    {0x7C,0xC6,0xC6,0x7C,0xC6,0xC6,0x7C,0x00}, {0x7C,0xC6,0xC6,0x7E,0x06,0xC6,0x7C,0x00},
    {0x00,0x18,0x18,0x00,0x18,0x18,0x00,0x00}, {0x00,0x18,0x18,0x00,0x18,0x18,0x30,0x00},
    {0x0C,0x18,0x30,0x60,0x30,0x18,0x0C,0x00}, {0x00,0x00,0x7E,0x00,0x7E,0x00,0x00,0x00},
    {0x30,0x18,0x0C,0x06,0x0C,0x18,0x30,0x00}, {0x7C,0xC6,0x0C,0x18,0x18,0x00,0x18,0x00},
    {0x7C,0xC6,0xDE,0xDE,0xDC,0xC0,0x7C,0x00}, {0x38,0x6C,0xC6,0xC6,0xFE,0xC6,0xC6,0x00},
    {0xFC,0xC6,0xC6,0xFC,0xC6,0xC6,0xFC,0x00}, {0x7C,0xC6,0xC0,0xC0,0xC0,0xC6,0x7C,0x00},
    {0xF8,0xCC,0xC6,0xC6,0xC6,0xCC,0xF8,0x00}, {0xFE,0xC0,0xC0,0xFC,0xC0,0xC0,0xFE,0x00},
    {0xFE,0xC0,0xC0,0xFC,0xC0,0xC0,0xC0,0x00}, {0x7C,0xC6,0xC0,0xCE,0xC6,0xC6,0x7E,0x00},
    {0xC6,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0x00}, {0x7E,0x18,0x18,0x18,0x18,0x18,0x7E,0x00},
    {0x1E,0x06,0x06,0x06,0xC6,0xC6,0x7C,0x00}, {0xC6,0xCC,0xD8,0xF0,0xD8,0xCC,0xC6,0x00},
    {0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xFE,0x00}, {0xC6,0xEE,0xFE,0xD6,0xC6,0xC6,0xC6,0x00},
    {0xC6,0xE6,0xF6,0xDE,0xCE,0xC6,0xC6,0x00}, {0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00},
    {0xFC,0xC6,0xC6,0xFC,0xC0,0xC0,0xC0,0x00}, {0x7C,0xC6,0xC6,0xC6,0xD6,0xDE,0x7C,0x06},
    {0xFC,0xC6,0xC6,0xFC,0xD8,0xCC,0xC6,0x00}, {0x7C,0xC6,0xC0,0x7C,0x06,0xC6,0x7C,0x00},
    {0xFE,0x18,0x18,0x18,0x18,0x18,0x18,0x00}, {0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00},
    {0xC6,0xC6,0xC6,0xC6,0x6C,0x38,0x10,0x00}, {0xC6,0xC6,0xC6,0xD6,0xFE,0xEE,0xC6,0x00},
    {0xC6,0xC6,0x6C,0x38,0x6C,0xC6,0xC6,0x00}, {0xC6,0xC6,0x6C,0x38,0x18,0x18,0x18,0x00},
    {0xFE,0x06,0x0C,0x18,0x30,0x60,0xFE,0x00}, {0x3C,0x30,0x30,0x30,0x30,0x30,0x3C,0x00},
    {0xC0,0x60,0x30,0x18,0x0C,0x06,0x00,0x00}, {0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0x00},
    {0x10,0x38,0x6C,0xC6,0x00,0x00,0x00,0x00}, {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF},
    {0x30,0x18,0x0C,0x00,0x00,0x00,0x00,0x00}, {0x00,0x00,0x78,0x0C,0x7C,0xCC,0x76,0x00},
    {0xC0,0xC0,0xDC,0xE6,0xC6,0xC6,0xDC,0x00}, {0x00,0x00,0x7C,0xC6,0xC0,0xC6,0x7C,0x00},
    {0x06,0x06,0x76,0xCE,0xC6,0xC6,0x76,0x00}, {0x00,0x00,0x7C,0xC6,0xFE,0xC0,0x7C,0x00},
    {0x1C,0x36,0x30,0x78,0x30,0x30,0x30,0x00}, {0x00,0x00,0x76,0xC6,0xC6,0x7E,0x06,0x7C},
    {0xC0,0xC0,0xDC,0xE6,0xC6,0xC6,0xC6,0x00}, {0x18,0x00,0x38,0x18,0x18,0x18,0x3C,0x00},
    {0x06,0x00,0x06,0x06,0x06,0x06,0xC6,0x7C}, {0xC0,0xC0,0xCC,0xD8,0xF0,0xD8,0xCC,0x00},
    {0x38,0x18,0x18,0x18,0x18,0x18,0x3C,0x00}, {0x00,0x00,0xEC,0xFE,0xD6,0xC6,0xC6,0x00},
    {0x00,0x00,0xDC,0xE6,0xC6,0xC6,0xC6,0x00}, {0x00,0x00,0x7C,0xC6,0xC6,0xC6,0x7C,0x00},
    {0x00,0x00,0xDC,0xC6,0xC6,0xDC,0xC0,0xC0}, {0x00,0x00,0x76,0xC6,0xC6,0x76,0x06,0x06},
    {0x00,0x00,0xDC,0xE6,0xC0,0xC0,0xC0,0x00}, {0x00,0x00,0x7C,0xC0,0x7C,0x06,0xFC,0x00},
    {0x30,0x30,0x7C,0x30,0x30,0x36,0x1C,0x00}, {0x00,0x00,0xC6,0xC6,0xC6,0xCE,0x76,0x00},
    {0x00,0x00,0xC6,0xC6,0xC6,0x6C,0x38,0x00}, {0x00,0x00,0xC6,0xC6,0xD6,0xFE,0x6C,0x00},
    {0x00,0x00,0xC6,0x6C,0x38,0x6C,0xC6,0x00}, {0x00,0x00,0xC6,0xC6,0xC6,0x7E,0x06,0x7C},
    {0x00,0x00,0xFE,0x0C,0x38,0x60,0xFE,0x00}, {0x0E,0x18,0x18,0x70,0x18,0x18,0x0E,0x00},
    {0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00}, {0x70,0x18,0x18,0x0E,0x18,0x18,0x70,0x00},
    {0x76,0xDC,0x00,0x00,0x00,0x00,0x00,0x00}, {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}
};

static void build_clean_roms(void)
{
    /* 1. GROM ($3000..$37FF): cards 0..95 = ASCII, cards 96..255 = geometric blocks/lines/slopes */
    if (S.has_ext_grom) {
        for (int i = 0; i < 2048; i++)
            W.grom[i] = W.ext_grom[i];
    } else {
        for (int c = 0; c < 96; c++)
            for (int r = 0; r < 8; r++)
                W.grom[c * 8 + r] = grom_ascii96[c][r];
        for (int c = 96; c < 256; c++) {
            int k = c - 96;
            for (int r = 0; r < 8; r++) {
                u8 v = 0;
                if (k < 16) {
                    /* 2x2 quadrant block combinations (cards 96..111) */
                    int q = (r >= 4 ? 2 : 0);
                    if (k & (1 << q)) v |= 0xF0u;
                    if (k & (1 << (q + 1))) v |= 0x0Fu;
                } else if (k < 32) {
                    /* Horizontal / vertical / frame bars */
                    int m = k - 16;
                    if ((m & 1) && r < 2) v |= 0xFFu;
                    if ((m & 2) && r >= 6) v |= 0xFFu;
                    if (m & 4) v |= 0xC0u;
                    if (m & 8) v |= 0x03u;
                } else if (k < 48) {
                    /* Diagonals and triangles */
                    int m = k - 32;
                    v = (m & 1) ? (u8)(0xFFu << (7 - r)) : (u8)(0xFFu >> r);
                    if (m & 2) v = (u8)~v;
                } else {
                    /* Checkerboards / solid / stripes */
                    v = (k & 1) ? ((r & 1) ? 0xAAu : 0x55u) : 0xFFu;
                }
                W.grom[c * 8 + r] = v;
            }
        }
    }

    /* 2. EXEC ($1000..$1FFF) */
    if (S.has_ext_exec) {
        for (int i = 0; i < 4096; i++)
            W.exec[i] = W.ext_exec[i];
        return;
    }

    for (int i = 0; i < 4096; i++)
        W.exec[i] = 0x00AFu; /* JR R5 (`MOVR R5, R7` = (2<<6)|(5<<3)|7 = 0x0AF) safe fallback */

    /* $1000: Reset entry (HLE hooked) */
    W.exec[0x000] = 0x0004u; W.exec[0x001] = 0x0310u; W.exec[0x002] = 0x0041u; /* J $1041 */

    /* $1004: Hardware VBlank IRQ vector -> J $1030 */
    W.exec[0x004] = 0x0004u; W.exec[0x005] = 0x0310u; W.exec[0x006] = 0x0030u;

    /* $1014: Standard EXEC ISR epilogue (reached via JR R5, PULR R7, or J $1014!) */
    W.exec[0x014] = 0x02B4u; /* PULR R4 */
    W.exec[0x015] = 0x02B3u; /* PULR R3 */
    W.exec[0x016] = 0x02B2u; /* PULR R2 */
    W.exec[0x017] = 0x02B1u; /* PULR R1 */
    W.exec[0x018] = 0x02B0u; /* PULR R0 */
    W.exec[0x019] = 0x0038u; /* RSWD R0 */
    W.exec[0x01A] = 0x02B0u; /* PULR R0 */
    W.exec[0x01B] = 0x02B5u; /* PULR R5 */
    W.exec[0x01C] = 0x0002u; /* EIS */
    W.exec[0x01D] = 0x02B7u; /* PULR R7 */

    /* $1020: Default EXEC ISR (placed in $0100:$0101 until game installs its own ISRVEC) */
    W.exec[0x020] = 0x0240u; W.exec[0x021] = 0x0020u; /* MVO R0, $0020 (enable STIC display) */
    W.exec[0x022] = 0x00AFu;                          /* JR R5 (-> $1014) */

    /* $1030: Genuine CP1610 ISR prologue pushing R5, R0, GSWD, R1..R4 and dispatching ($0101:$0100) */
    W.exec[0x030] = 0x0275u;                          /* PSHR R5 */
    W.exec[0x031] = 0x0270u;                          /* PSHR R0 */
    W.exec[0x032] = 0x0030u;                          /* GSWD R0 */
    W.exec[0x033] = 0x0270u;                          /* PSHR R0 */
    W.exec[0x034] = 0x0271u;                          /* PSHR R1 */
    W.exec[0x035] = 0x0272u;                          /* PSHR R2 */
    W.exec[0x036] = 0x0273u;                          /* PSHR R3 */
    W.exec[0x037] = 0x0274u;                          /* PSHR R4 */
    W.exec[0x038] = 0x0280u; W.exec[0x039] = 0x0101u; /* MVI $0101, R0 */
    W.exec[0x03A] = 0x0040u;                          /* SWAP R0 */
    W.exec[0x03B] = 0x03C0u; W.exec[0x03C] = 0x0100u; /* XOR $0100, R0 */
    W.exec[0x03D] = 0x0001u;                          /* SDBD */
    W.exec[0x03E] = 0x02BDu; W.exec[0x03F] = 0x0014u; W.exec[0x040] = 0x0010u; /* MVII #$1014, R5 */
    /* $1041 is boot resume, so jump over $1041 to $1045 for MOVR R0, R7! */
    /* Wait: replace $103D..$1040 jump cleanly: put MOVR R0, R7 at $1046 and branch over $1041..$1045! */
    W.exec[0x03D] = 0x0200u; W.exec[0x03E] = 0x0006u; /* B $1045 */

    /* $1041: Boot resume target (HLE hooked; ECS $4800 stubs branch here!) */
    W.exec[0x041] = 0x0002u;                          /* EIS */
    W.exec[0x042] = 0x0220u; W.exec[0x043] = 0x0001u; /* B $1042 (title wait loop) */

    /* $1045: Finish ISR dispatch: R5 = $1014, PC = R0 */
    W.exec[0x045] = 0x0001u;                          /* SDBD */
    W.exec[0x046] = 0x02BDu; W.exec[0x047] = 0x0014u; W.exec[0x048] = 0x0010u; /* MVII #$1014, R5 */
    W.exec[0x049] = 0x0087u;                          /* MOVR R0, R7 */

    /* $1050..$105F: Safe EXEC idle spin loop (EIS; B $1059) for R5 return from after_title */
    for (int i = 0x04A; i < 0x058; i++)
        W.exec[i] = 0x0034u;                           /* NOP */
    W.exec[0x058] = 0x0002u;                           /* EIS */
    W.exec[0x059] = 0x0220u; W.exec[0x05A] = 0x0001u;  /* B $1059 */
}

/* ---- Hand Controllers ($01FE = Right / P2, $01FF = Left / P1) ---- */
static const u8 disc_codes[16] = {
    0x04u, 0x14u, 0x16u, 0x06u, 0x02u, 0x12u, 0x13u, 0x03u,
    0x01u, 0x11u, 0x19u, 0x09u, 0x08u, 0x18u, 0x1Cu, 0x0Cu
};

static const u8 key_codes[12] = {
    0x48u, /* 0 */
    0x81u, 0x41u, 0x21u, /* 1 2 3 */
    0x82u, 0x42u, 0x22u, /* 4 5 6 */
    0x84u, 0x44u, 0x24u, /* 7 8 9 */
    0x88u, /* 10 = Clear */
    0x28u  /* 11 = Enter */
};

static u8 controller_read(int port)
{
    /* Many Intellivision games read $01FF (Left), some read $01FE (Right), or OR both for 1P!
       Drive Player 1 on $01FF; leave $01FE idle (0xFF) so 2-player games don't mirror P2. */
    if (port == 0)
        return 0xFFu;

    u8 code = 0;
    int dx = ((S.pad & PAD_RIGHT) ? 1 : 0) - ((S.pad & PAD_LEFT) ? 1 : 0);
    int dy = ((S.pad & PAD_UP) ? 1 : 0) - ((S.pad & PAD_DOWN) ? 1 : 0);
    if (dx != 0 || dy != 0) {
        int dir = 0;
        if      (dx ==  0 && dy ==  1) dir = 0;
        else if (dx ==  1 && dy ==  1) dir = 2;
        else if (dx ==  1 && dy ==  0) dir = 4;
        else if (dx ==  1 && dy == -1) dir = 6;
        else if (dx ==  0 && dy == -1) dir = 8;
        else if (dx == -1 && dy == -1) dir = 10;
        else if (dx == -1 && dy ==  0) dir = 12;
        else                           dir = 14;
        code |= disc_codes[dir];
    }

    if (S.pad & PAD_A) code |= 0xA0u; /* Top side action buttons */
    if (S.pad & PAD_B) code |= 0x60u; /* Bottom-left action button */
    if (S.pad & PAD_X) code |= 0xC0u; /* Bottom-right action button */

    if (S.ext_key < 12u)
        code |= key_codes[S.ext_key];
    else if (S.pad & PAD_START)  code |= key_codes[11]; /* Enter */
    else if (S.pad & PAD_SELECT) code |= key_codes[10]; /* Clear */
    else if (S.pad & PAD_Y)      code |= key_codes[1];  /* Keypad 1 */
    else if (S.pad & PAD_L)      code |= key_codes[2];  /* Keypad 2 */
    else if (S.pad & PAD_R)      code |= key_codes[3];  /* Keypad 3 */

    return (u8)(~code & 0xFFu);
}

/* ---- STIC Registers & Renderer ---- */
static void stic_reg_masks(u32 reg, u16 *impl, u16 *ones)
{
    if (reg < 0x08u)      { *impl = 0x07FFu; *ones = 0x3800u; }
    else if (reg < 0x10u) { *impl = 0x0FFFu; *ones = 0x3000u; }
    else if (reg < 0x18u) { *impl = 0x3FFFu; *ones = 0x0000u; }
    else if (reg < 0x20u) { *impl = (u16)(0x03FFu & ~(1u << (reg - 0x18u))); *ones = 0x3C00u; }
    else if (reg >= 0x28u && reg <= 0x2Cu) { *impl = 0x000Fu; *ones = 0x3FF0u; }
    else if (reg == 0x30u || reg == 0x31u) { *impl = 0x0007u; *ones = 0x3FF8u; }
    else if (reg == 0x32u) { *impl = 0x0003u; *ones = 0x3FFCu; }
    else { *impl = 0x0000u; *ones = 0x3FFFu; }
}

static void stic_store(u32 reg, u16 val)
{
    if (reg == 0x20u) S.enable_req = 1;
    if (reg == 0x21u) S.color_stack_mode = 0;
    u16 impl, ones;
    stic_reg_masks(reg, &impl, &ones);
    W.stic_regs[reg] = (val & impl) | ones;
}

static void stic_reset(void)
{
    for (u32 r = 0; r < 0x40u; r++) {
        W.stic_regs[r] = 0;
        if (r != 0x20u) stic_store(r, 0xFFFFu);
    }
    /* Clear collisions on reset */
    for (u32 r = 0x18u; r < 0x20u; r++)
        stic_store(r, 0u);
    S.color_stack_mode = 1;
    S.enable_req = 0;
    S.display_enabled = 0;
    S.access_from = 0;
    S.regs_until = FRAME_CYCLES;
    S.gfx_until = FRAME_CYCLES;
    for (int i = 0; i < 240; i++)
        W.stic_cards[i] = 0;
}

static u16 double_byte_bits(u8 b)
{
    u16 w = 0;
    for (int i = 0; i < 8; i++)
        if (b & (1u << i))
            w |= (u16)(3u << (i * 2));
    return w;
}

static u16 rev16(u16 w)
{
    u16 out = 0;
    for (int i = 0; i < 16; i++)
        if (w & (1u << i))
            out |= (u16)(0x8000u >> i);
    return out;
}

static __attribute__((noinline)) void stic_render_frame(u16 *picture)
{
    if (!S.display_enabled) {
        u16 blk = stic_pal[0];
        for (int i = 0; i < INTV_W * INTV_H; i++)
            picture[i] = blk;
        return;
    }

    /* 1. Draw 20 x 12 BACKTAB cards into 160 x 96 half-line background */
    u8 stack[4];
    for (int i = 0; i < 4; i++)
        stack[i] = (u8)(W.stic_regs[0x28 + i] & 0x0Fu);
    int sp = 0;
    u8 bg = stack[0];

    for (int row = 0; row < 12; row++) {
        for (int col = 0; col < 20; col++) {
            u16 card = W.stic_cards[row * 20 + col];
            int orig = row * 8 * 160 + col * 8;
            if (S.color_stack_mode && (card & 0x1800u) == 0x1000u) {
                /* Colored Squares mode */
                u8 sq[4] = {
                    (u8)(card & 7u),
                    (u8)((card >> 3) & 7u),
                    (u8)((card >> 6) & 7u),
                    (u8)(((card >> 9) & 3u) | ((card >> 11) & 4u))
                };
                for (int y = 0; y < 8; y++) {
                    for (int x = 0; x < 8; x++) {
                        u8 c = sq[(y >> 2) * 2 + (x >> 2)];
                        int at = orig + y * 160 + x;
                        W.bg_col[at] = (c == 7u) ? bg : c;
                        W.bg_on[at] = (c == 7u) ? 0u : 1u;
                    }
                }
                continue;
            }
            u8 fg;
            u16 idx;
            if (S.color_stack_mode) {
                if (card & 0x2000u) {
                    sp = (sp + 1) & 3;
                    bg = stack[sp];
                }
                fg = (u8)(((card >> 9) & 8u) | (card & 7u));
                idx = (card & 0x800u) ? (card & 0x9F8u) : (card & 0x7F8u);
            } else {
                fg = (u8)(card & 7u);
                bg = (u8)(((card >> 9) & 0x0Bu) | ((card >> 11) & 0x04u));
                idx = card & 0x9F8u;
            }
            const u8 *glyph = (idx & 0x800u) ? (W.gram + (idx & 0x1F8u)) : (W.grom + (idx & 0x7F8u));
            for (int y = 0; y < 8; y++) {
                u8 bits = glyph[y];
                int at = orig + y * 160;
                for (int x = 7; x >= 0; x--, at++) {
                    u8 on = (bits >> x) & 1u;
                    W.bg_col[at] = on ? fg : bg;
                    W.bg_on[at] = on;
                }
            }
        }
        W.last_bg[row] = bg;
    }

    /* 2. Draw 8 MOBs (7 down to 0 so MOB 0 has top priority) */
    for (int i = 0; i < 176 * 224; i++)
        W.mob_on[i] = 0;

    for (int m = 7; m >= 0; m--) {
        u16 xr = W.stic_regs[m];
        u16 yr = W.stic_regs[0x08 + m];
        u16 ar = W.stic_regs[0x10 + m];
        for (int i = 0; i < 16; i++)
            W.mob_rows[m][i] = 0;
        int x = xr & 0xFFu;
        int y = (int)(yr & 0x7Fu) * 2;
        W.mob_active[m] = 0;
        if (x == 0 || x >= 167 || (xr & 0x300u) == 0 || y >= 208)
            continue;
        W.mob_active[m] = 1;

        int tall = (yr & 0x80u) != 0;
        int h = tall ? 16 : 8;
        u16 idx = ar & 0xFF8u;
        if (!S.color_stack_mode || (idx & 0x800u))
            idx &= 0x9F8u;
        if (tall)
            idx &= 0xFF0u;
        int wide = (xr & 0x400u) != 0;
        int fx = (yr & 0x400u) != 0;
        int fy = (yr & 0x800u) != 0;
        for (int r = 0; r < h; r++) {
            u8 b = (idx & 0x800u) ? W.gram[((idx & 0x1FFu) + (u32)r) & 0x1FFu]
                                  : W.grom[(idx + (u32)r) & 0x7FFu];
            u16 bits = wide ? double_byte_bits(b) : (u16)((u16)b << 8);
            if (fx)
                bits = wide ? rev16(bits) : (u16)(rev16(bits) << 8);
            W.mob_rows[m][fy ? (h - 1 - r) : r] = bits;
        }
        if (!(xr & 0x200u))
            continue;
        u8 col = (u8)(((ar >> 9) & 8u) | (ar & 7u));
        u8 behind = (u8)((ar >> 13) & 1u);
        int shift = (yr >> 8) & 3;
        int shown = h;
        if (y + (h << shift) > 208)
            shown = (207 - y + (1 << shift)) >> shift;
        for (int r = 0; r < shown; r++) {
            u16 bits = W.mob_rows[m][r];
            if (!bits)
                continue;
            for (int rep = 0; rep < (1 << shift); rep++) {
                int line = y + (r << shift) + rep;
                if (line >= 224)
                    break;
                for (int k = 0; k < 16; k++) {
                    if (!(bits & (0x8000u >> k)))
                        continue;
                    int px = x + k;
                    if (px >= 176)
                        break;
                    int at = line * 176 + px;
                    W.mob_col[at] = col;
                    W.mob_on[at] = 1;
                    W.mob_behind[at] = behind;
                }
            }
        }
    }

    /* 3. Compose background, MOBs, H/V fine delay, and border */
    int hd = W.stic_regs[0x30] & 7;
    int vd = (int)(W.stic_regs[0x31] & 7) * 2;
    for (int line = 0; line < 224; line++)
        for (int px = 167 - hd; px < 176; px++)
            if (px >= 0) W.mob_on[line * 176 + px] = 0;

    for (int line = 0; line < 208 - vd; line++) {
        int row = (line >> 1) - 8;
        int in_pic = (row >= 0 && row < 96);
        int crow = (line - 16) >> 4;
        u8 fill = !in_pic ? W.last_bg[11]
                          : ((line & 15) == 0 ? W.last_bg[(crow + 11) % 12] : W.last_bg[crow]);
        int out = (line + vd) * 176;
        for (int x = 0; x < hd; x++)
            W.img[out + x] = 0;
        for (int x = 0; x + hd < 176; x++) {
            u8 c = fill, on = 0;
            if (in_pic && x >= 8 && x < 168) {
                int at = row * 160 + (x - 8);
                c = W.bg_col[at];
                on = W.bg_on[at];
            }
            int mi = line * 176 + x;
            if (W.mob_on[mi] && !(W.mob_behind[mi] && on))
                c = W.mob_col[mi];
            W.img[out + x + hd] = c;
        }
    }

    u8 border = (u8)(W.stic_regs[0x2C] & 0x0Fu);
    u16 edges = W.stic_regs[0x32];
    int top_b = (edges & 2u) ? 32 : 16;
    int left_b = (edges & 1u) ? 16 : 8;
    for (int i = 0; i < top_b * 176; i++)
        W.img[i] = border;
    for (int i = 208 * 176; i < 224 * 176; i++)
        W.img[i] = border;
    for (int line = top_b; line < 208; line++) {
        int at = line * 176;
        for (int x = 0; x < left_b; x++) W.img[at + x] = border;
        for (int x = 167; x < 176; x++) W.img[at + x] = border;
    }

    /* 4. Hardware MOB-MOB, MOB-BG, and MOB-Border collisions */
    static const int mob_h_tab[8] = {8, 16, 16, 32, 32, 64, 64, 128};
    u16 trim[8][16];
    for (int m = 0; m < 8; m++) {
        int sx = (int)(W.stic_regs[m] & 0xFFu) + hd;
        u16 mask = 0xFFFFu;
        for (int k = 0; k < 16; k++)
            if (sx + k <= 6 || sx + k >= 168)
                mask &= (u16)~(0x8000u >> k);
        for (int r = 0; r < 16; r++)
            trim[m][r] = W.mob_rows[m][r] & mask;
    }

    for (int a = 0; a < 8; a++) {
        u16 xra = W.stic_regs[a], yra = W.stic_regs[0x08 + a];
        int ax = xra & 0x1FFu, ay = (int)(yra & 0x7Fu) << 1;
        int aw = (xra & 0x400u) ? 16 : 8, ah = mob_h_tab[(yra >> 7) & 7], ash = (yra >> 8) & 3;
        if (!(W.mob_active[a] && ax > 0x100 && ax < 0x1A8 - hd && ay <= 0xD8 - vd))
            continue;

        for (int b = a + 1; b < 8; b++) {
            u16 xrb = W.stic_regs[b], yrb = W.stic_regs[0x08 + b];
            int bx = xrb & 0x1FFu, by = (int)(yrb & 0x7Fu) << 1;
            int bw = (xrb & 0x400u) ? 16 : 8, bh = mob_h_tab[(yrb >> 7) & 7], bsh = (yrb >> 8) & 3;
            if (!(W.mob_active[b] && bx > 0x100 && bx < 0x1A7 - hd && by <= 0xD8 - vd))
                continue;
            if ((ax < bx || ax >= bx + bw) && (bx < ax || bx >= ax + aw))
                continue;
            if ((ay < by || ay >= by + bh) && (by < ay || by >= ay + ah))
                continue;
            int sa = (ax < bx) ? (bx - ax) : 0;
            int sb = (bx < ax) ? (ax - bx) : 0;
            int lo = (ay > by) ? ay : by;
            int hi = (ay + ah - 1 < by + bh - 1) ? (ay + ah - 1) : (by + bh - 1);
            if (lo < 15 - vd) lo = 15 - vd;
            if (hi > 208 - vd) hi = 208 - vd;
            for (int line = lo; line <= hi; line++) {
                u16 ba = (u16)(trim[a][(line - ay) >> ash] << sa);
                u16 bb = (u16)(trim[b][(line - by) >> bsh] << sb);
                if (ba & bb) {
                    W.stic_regs[0x18 + a] |= (u16)(1u << b);
                    W.stic_regs[0x18 + b] |= (u16)(1u << a);
                    break;
                }
            }
        }

        int x = ax & 0xFF;
        if (!(W.stic_regs[0x18 + a] & 0x100u)) {
            int last = ay + ah - 1;
            if (last > 206 - vd) last = 206 - vd;
            for (int line = ay; line <= last; line++) {
                u16 bits = trim[a][(line - ay) >> ash];
                int row = (line >> 1) - 8;
                if (!bits || row < 0 || row >= 96) continue;
                int hit = 0;
                for (int k = 0; k < 16; k++) {
                    int px = x + k - 8;
                    if ((bits & (0x8000u >> k)) && px >= 0 && px < 160 && W.bg_on[row * 160 + px]) {
                        W.stic_regs[0x18 + a] |= 0x100u;
                        hit = 1;
                        break;
                    }
                }
                if (hit) break;
            }
        }

        if (!(W.stic_regs[0x18 + a] & 0x200u)) {
            int sx = x + hd, sy = ay + vd, hit = 0;
            for (int r = 0; r < (ah >> ash) && !hit; r++) {
                u16 bits = W.mob_rows[a][r];
                if (!bits) continue;
                for (int rep = 0; rep < (1 << ash) && !hit; rep++) {
                    int line = sy + (r << ash) + rep;
                    if (line < 15 || line > 208) continue;
                    for (int k = 0; k < 16; k++) {
                        if (!(bits & (0x8000u >> k))) continue;
                        int px = sx + k;
                        if (px < 7 || px > 167) continue;
                        if (px == 7 || px == 167 || ((edges & 1u) && px <= 15) || line < top_b || line == 208) {
                            W.stic_regs[0x18 + a] |= 0x200u;
                            hit = 1;
                            break;
                        }
                    }
                }
            }
        }
    }

    /* 5. Output 176 x 208 BGR555 (lines 8..215 of 224) */
    for (int y = 0; y < INTV_H; y++) {
        const u8 *src = W.img + (y + 8) * 176;
        u16 *dst = picture + y * INTV_W;
        for (int x = 0; x < INTV_W; x++)
            dst[x] = stic_pal[src[x] & 0x0Fu];
    }
}

/* ---- AY-3-8914 PSG Audio (48 kHz mono) ---- */
static const u8 psg_masks[14] = {
    0xFFu,0xFFu,0xFFu,0xFFu, 0x0Fu,0x0Fu,0x0Fu,0xFFu, 0xFFu,0x1Fu,0x0Fu, 0x3Fu,0x3Fu,0x3Fu
};

static void psg_write(u32 reg, u8 val)
{
    if (reg >= 14u) return;
    S.psg_reg[reg] = val & psg_masks[reg];
    if (reg == 10u) {
        S.env_step = 0;
        S.env_cnt = 0;
        S.env_lvl = (S.psg_reg[10] & 0x04u) ? 0u : 15u;
    }
}

static s16 psg_tick_one(void)
{
    for (int ch = 0; ch < 3; ch++) {
        int per = (int)S.psg_reg[ch] | ((int)S.psg_reg[ch + 4] << 8);
        if (!per) per = 0x1000;
        if (++S.tone_cnt[ch] >= per) {
            S.tone_cnt[ch] = 0;
            S.tone_out[ch] ^= 1u;
        }
    }
    int nper = (S.psg_reg[9] ? (int)S.psg_reg[9] : 32) * 2;
    if (++S.noise_cnt >= nper) {
        S.noise_cnt = 0;
        u32 s = S.noise_lfsr;
        S.noise_lfsr = (s >> 1) ^ ((s & 1u) ? 0x10004u : 0u);
    }
    int eper = ((int)S.psg_reg[3] | ((int)S.psg_reg[7] << 8));
    if (!eper) eper = 0x10000;
    eper *= 2;
    if (++S.env_cnt >= eper) {
        S.env_cnt = 0;
        if (S.env_step >= 0) {
            u8 sh = S.psg_reg[10];
            int hold = sh & 1, alt = (sh >> 1) & 1, atk = (sh >> 2) & 1, rep = (sh >> 3) & 1;
            int st = (S.env_step + 1) & 31;
            if (st < 16) {
                S.env_lvl = (u8)(atk ? st : (15 - st));
                S.env_step = st;
            } else if (st == 16 && (!rep || hold)) {
                S.env_lvl = (u8)((rep && (atk != alt)) ? 15 : 0);
                S.env_step = -1;
            } else if (st == 16 && !alt) {
                S.env_lvl = (u8)(atk ? 0 : 15);
                S.env_step = 0;
            } else {
                S.env_lvl = (u8)(atk ? (31 - st) : (st - 16));
                S.env_step = st;
            }
        }
    }

    u8 en = S.psg_reg[8];
    u8 nz = (u8)(S.noise_lfsr & 1u);
    int mix = 0;
    static const u8 eshift[4] = {0, 2, 1, 0};
    for (int ch = 0; ch < 3; ch++) {
        u8 t = S.tone_out[ch] | ((en >> ch) & 1u);
        u8 n = nz | ((en >> (ch + 3)) & 1u);
        if (!(t & n)) continue;
        u8 v = S.psg_reg[11 + ch];
        u8 mode = v >> 4;
        mix += mode ? (ay_vol[S.env_lvl] >> eshift[mode]) : ay_vol[v & 0x0Fu];
    }
    return (s16)(mix >> 1);
}

static void audio_step_cycles(int cyc)
{
    if (!S.sample_rate || cyc <= 0)
        return;
    /* AY-3-8914 ticks every 4 CP1610 cycles (~223.72 kHz) */
    S.psg_cyc_rem += cyc;
    while (S.psg_cyc_rem >= 4) {
        S.psg_cyc_rem -= 4;
        int raw = psg_tick_one();
        S.aud_frac += S.sample_rate;
        if (S.aud_frac >= 224010u) { /* 14,934 * 60 / 4 = 224,010 ticks/s */
            S.aud_frac -= 224010u;
            S.dc_acc += (raw * 256 - S.dc_acc) >> 9;
            int centered = raw - (S.dc_acc >> 8);
            if (centered > 32767) centered = 32767;
            if (centered < -32768) centered = -32768;
            if (S.aud_count < INTV_AUD_MAX)
                W.aud_buf[S.aud_count++] = (s16)centered;
        }
    }
}

/* ---- Memory Bus ---- */
static u16 bus_read(u16 addr)
{
    if (addr < 0x1000u) {
        if (addr < 0x0080u) {
            if (S.now_cyc < S.access_from || S.now_cyc > S.regs_until)
                return addr & 0x0Eu;
            if ((addr & 0x7Fu) == 0x21u)
                S.color_stack_mode = 1;
            if (addr >= 0x0040u)
                return W.gram[addr];
            return W.stic_regs[addr];
        }
        if (addr == 0x0080u || addr == 0x0081u)
            return 0x8000u; /* Intellivoice ready/absent idle */
        if (addr >= 0x0100u && addr < 0x01F0u)
            return W.scratch_ram[addr - 0x0100u];
        if (addr >= 0x01F0u && addr < 0x0200u) {
            if (addr >= 0x01FEu)
                return controller_read(addr & 1u);
            return S.psg_reg[addr - 0x01F0u];
        }
        if (addr >= 0x0200u && addr < 0x0360u)
            return W.sys_ram[addr - 0x0200u];
        if (addr >= 0x0400u && addr < 0x0500u && S.has_ext_aux)
            return W.exec_aux[addr - 0x0400u];
        return (W.cart_attr[addr >> 8] & ATTR_READ) ? W.cart_mem[addr] : 0xFFFFu;
    }
    if (addr < 0x2000u)
        return W.exec[addr - 0x1000u];
    if (addr >= 0x3000u && addr < 0x4000u) {
        if (S.now_cyc < S.access_from || S.now_cyc > S.gfx_until)
            return addr & 0x3FFFu;
        return (addr & 0x0800u) ? W.gram[addr & 0x1FFu] : W.grom[addr & 0x7FFu];
    }
    u16 v = (W.cart_attr[addr >> 8] & ATTR_READ) ? W.cart_mem[addr] : 0xFFFFu;
    if ((addr & 0x3FFFu) < 0x0040u) {
        if (S.now_cyc >= S.access_from && S.now_cyc <= S.regs_until && (addr & 0x7Fu) == 0x21u)
            S.color_stack_mode = 1;
    }
    return v;
}

static void bus_write(u16 addr, u16 val)
{
    if (addr < 0x1000u) {
        if (addr < 0x0080u) {
            u32 reg = addr & 0x7Fu;
            if (reg < 0x40u && S.now_cyc >= S.access_from && S.now_cyc <= S.regs_until)
                stic_store(reg, val);
            return;
        }
        if (addr >= 0x0100u && addr < 0x01F0u) {
            W.scratch_ram[addr - 0x0100u] = (u8)(val & 0xFFu);
            return;
        }
        if (addr >= 0x01F0u && addr < 0x01FEu) {
            psg_write(addr - 0x01F0u, (u8)(val & 0xFFu));
            return;
        }
        if (addr >= 0x0200u && addr < 0x0360u) {
            W.sys_ram[addr - 0x0200u] = val;
            return;
        }
    } else if (addr < 0x2000u) {
        return;
    } else if (addr >= 0x3000u && addr < 0x4000u) {
        if (S.now_cyc >= S.access_from && S.now_cyc <= S.gfx_until && (addr & 0x0800u))
            W.gram[addr & 0x1FFu] = (u8)(val & 0xFFu);
        return;
    } else if ((addr & 0x3FFFu) < 0x0040u) {
        u32 reg = addr & 0x3Fu;
        if (S.now_cyc >= S.access_from && S.now_cyc <= S.regs_until)
            stic_store(reg, val);
    }

    u8 attr = W.cart_attr[addr >> 8];
    if (attr & ATTR_WRITE16)
        W.cart_mem[addr] = val;
    else if (attr & ATTR_WRITE8)
        W.cart_mem[addr] = val & 0xFFu;
}

/* ---- Clean-room Built-in Mini-EXEC HLE Hooks (only when !S.has_ext_exec) ---- */
static void draw_builtin_title(u16 title_ptr)
{
    /* Green background Color Stack, tan border, white text */
    for (int i = 0; i < 4; i++)
        stic_store(0x28u + (u32)i, 5u);
    stic_store(0x2Cu, 5u);
    S.color_stack_mode = 1;
    for (int i = 0; i < 240; i++)
        W.sys_ram[i] = 0;

    /* Top/bottom decorative bars */
    for (int x = 1; x < 19; x++) {
        W.sys_ram[1 * 20 + x] = (u16)((95u << 3) | 6u); /* yellow bar */
        W.sys_ram[10 * 20 + x] = (u16)((95u << 3) | 6u);
    }

    /* Title string from cartridge header */
    u16 year = 1900u + (bus_read(title_ptr) & 0xFFu);
    u16 p = (u16)(title_ptr + 1u);
    char tbuf[20];
    int tn = 0;
    while (tn < 18) {
        u16 ch = bus_read(p++) & 0xFFu;
        if (!ch) break;
        if (ch >= 0x20u && ch < 0x7Fu)
            tbuf[tn++] = (char)ch;
    }
    int tx = (20 - tn) / 2;
    if (tx < 0) tx = 0;
    for (int i = 0; i < tn && tx + i < 20; i++)
        W.sys_ram[4 * 20 + tx + i] = (u16)(((u16)(tbuf[i] - 0x20) << 3) | 7u);

    /* Year line */
    char ybuf[4] = {
        (char)('0' + (year / 1000u) % 10u),
        (char)('0' + (year / 100u) % 10u),
        (char)('0' + (year / 10u) % 10u),
        (char)('0' + year % 10u)
    };
    for (int i = 0; i < 4; i++)
        W.sys_ram[7 * 20 + 8 + i] = (u16)(((u16)(ybuf[i] - 0x20) << 3) | 7u);
}

static __attribute__((noinline)) int intv_hle_exec(u16 pc)
{
    switch (pc) {
    case 0x1000u: {
        S.r[6] = 0x02F0u;
        W.scratch_ram[0] = 0x20u; /* default ISRVEC = $1020 */
        W.scratch_ram[1] = 0x10u;
        S.boot_stage = 0;
        /* If cartridge maps $4800 (ECS bank disable stub), run it first -- it branches to $1041 */
        if ((W.cart_attr[0x48] & ATTR_READ) && W.cart_mem[0x4800] != 0xFFFFu && W.cart_mem[0x4800] != 0x0000u) {
            S.r[7] = 0x4800u;
            return 8;
        }
        S.r[7] = 0x1041u;
        return 8;
    }

    case 0x1041u: {
        /* Boot stage 0: parse $5000 cartridge header */
        if (S.boot_stage == 0) {
            S.r[6] = 0x02F0u;
            W.scratch_ram[0] = 0x20u;
            W.scratch_ram[1] = 0x10u;
            u16 start_lo = bus_read(0x5004u) & 0xFFu;
            u16 start_hi = bus_read(0x5005u) & 0xFFu;
            u16 title_lo = bus_read(0x500Au) & 0xFFu;
            u16 title_hi = bus_read(0x500Bu) & 0xFFu;
            u16 flags = bus_read(0x500Cu);
            S.start_addr = (u16)((start_hi << 8) | start_lo);
            u16 title_ptr = (u16)((title_hi << 8) | title_lo);

            /* Walk past year byte + null-terminated title string to find after_title code */
            u16 after = (u16)(title_ptr + 1u);
            for (int guard = 0; guard < 64; guard++) {
                if ((bus_read(after++) & 0xFFu) == 0u)
                    break;
            }

            if (flags & 0x0040u) {
                /* Bit 6: jump directly to code after title string (IntyBASIC, 4-TRIS, Song Player, etc.) */
                S.boot_stage = 2;
                S.r[5] = 0x1058u;
                S.r[7] = after;
                return 12;
            }

            draw_builtin_title(title_ptr);
            S.title_wait = 10u;
            S.boot_stage = 1;
            S.ie = 1;
            if (flags & 0x0080u) {
                /* Bit 7: call custom title hook as subroutine JSR R5, after (if start_addr == after, it IS main!) */
                if (S.start_addr == after) {
                    S.boot_stage = 2;
                    S.r[5] = 0x1058u;
                } else {
                    S.r[5] = 0x1042u;
                }
                S.r[7] = after;
                return 12;
            }
            S.r[7] = 0x1042u;
            return 10;
        }
        return 0;
    }

    case 0x1042u: {
        /* Title wait loop: brief title screen, then launch START ($5004:$5005) */
        if (S.boot_stage == 1) {
            S.ie = 1;
            S.intr = ALLOW_BUSRQ | ALLOW_IRQ;
            if (controller_read(1) != 0xFFu || S.title_wait == 0) {
                S.boot_stage = 2;
                for (int i = 0; i < 240; i++)
                    W.sys_ram[i] = 0;
                S.r[6] = 0x02F0u;
                S.r[7] = S.start_addr ? S.start_addr : 0x5010u;
                return 12;
            }
        }
        return 0; /* execute genuine B $1042 so VBlank IRQ fires naturally */
    }

    case 0x1668u: /* Sign-extend low byte of R0 */
        S.r[0] = (u16)(s16)(signed char)(S.r[0] & 0xFFu);
        S.s = (S.r[0] >> 15) & 1u;
        S.z = (S.r[0] == 0u) ? 1u : 0u;
        S.r[7] = S.r[5];
        return 10;

    case 0x167Du:
    case 0x169Eu: { /* RAND: R0 = bit count -> N-bit random in R0 */
        u32 bits = S.r[0] & 0x0Fu;
        u32 steps = bits ? bits : 16u;
        for (u32 i = 0; i < steps; i++) {
            u16 b = (u16)(((S.lfsr_rnd >> 0) ^ (S.lfsr_rnd >> 2) ^ (S.lfsr_rnd >> 3) ^ (S.lfsr_rnd >> 5)) & 1u);
            S.lfsr_rnd = (u16)((S.lfsr_rnd >> 1) | (b << 15));
        }
        if (!S.lfsr_rnd) S.lfsr_rnd = 0xACE1u;
        S.r[0] = bits ? (u16)(S.lfsr_rnd & ((1u << bits) - 1u)) : S.lfsr_rnd;
        S.s = (S.r[0] >> 15) & 1u;
        S.z = (S.r[0] == 0u) ? 1u : 0u;
        S.r[7] = S.r[5];
        return 18;
    }

    case 0x1730u:
    case 0x1738u: { /* CLRMEM: zero R0 words starting at R4 */
        u16 cnt = S.r[0];
        while (cnt--)
            bus_write(S.r[4]++, 0u);
        S.r[0] = 0u;
        S.z = 1; S.s = 0;
        S.r[7] = S.r[5];
        return 24;
    }

    case 0x1741u: { /* FILLMEM: fill R0 words with R1 starting at R4 */
        u16 cnt = S.r[0], val = S.r[1];
        while (cnt--)
            bus_write(S.r[4]++, val);
        S.r[0] = 0u;
        S.z = 1; S.s = 0;
        S.r[7] = S.r[5];
        return 24;
    }

    case 0x1867u: { /* PRINT from @R1++ to @R4++ with attr R3 */
        for (int guard = 0; guard < 240; guard++) {
            u16 ch = bus_read(S.r[1]++) & 0xFFu;
            if (!ch) break;
            u16 card = (ch >= 0x20u) ? (u16)(((ch - 0x20u) << 3) | (S.r[3] & 0x3FFFu)) : (S.r[3] & 0x3FFFu);
            bus_write(S.r[4]++, card);
        }
        S.r[7] = S.r[5];
        return 30;
    }

    case 0x187Bu: { /* PRINT inline string from @R5++ to @R4++ with attr R3 */
        for (int guard = 0; guard < 240; guard++) {
            u16 ch = bus_read(S.r[5]++) & 0xFFu;
            if (!ch) break;
            u16 card = (ch >= 0x20u) ? (u16)(((ch - 0x20u) << 3) | (S.r[3] & 0x3FFFu)) : (S.r[3] & 0x3FFFu);
            bus_write(S.r[4]++, card);
        }
        S.r[7] = S.r[5];
        return 30;
    }

    default:
        return 0;
    }
}

/* ---- GI CP1610 16-bit CPU Core ---- */
static inline u16 set_sz(u16 v)
{
    S.s = (u8)((v >> 15) & 1u);
    S.z = (v == 0u) ? 1u : 0u;
    return v;
}

static inline u16 cp_add(u16 a, u16 b, u16 cin)
{
    u32 sum = (u32)a + (u32)b + (u32)cin;
    u16 res = (u16)sum;
    S.c = (u8)((sum >> 16) & 1u);
    S.o = (u8)(((~(a ^ b) & (a ^ res)) >> 15) & 1u);
    return set_sz(res);
}

static inline u16 cp_sub(u16 a, u16 b)
{
    /* b - a = b + ~a + 1 (C=1 means no borrow) */
    u32 sum = (u32)b + (u32)(a ^ 0xFFFFu) + 1u;
    u16 res = (u16)sum;
    S.c = (u8)((sum >> 16) & 1u);
    S.o = (u8)((((a ^ b) & (b ^ res)) >> 15) & 1u);
    return set_sz(res);
}

static inline void cp_operate(u32 kind, u16 opnd, u32 reg)
{
    switch (kind) {
    case 2u: S.r[reg] = opnd; break;
    case 3u: S.r[reg] = cp_add(opnd, S.r[reg], 0); break;
    case 4u: S.r[reg] = cp_sub(opnd, S.r[reg]); break;
    case 5u: (void)cp_sub(opnd, S.r[reg]); break;
    case 6u: S.r[reg] = set_sz(opnd & S.r[reg]); break;
    default: S.r[reg] = set_sz(opnd ^ S.r[reg]); break;
    }
}

static int cp1610_step(void)
{
    if (S.halted)
        return 4;

    u16 pc = S.r[7];
    if (!S.has_ext_exec && pc >= 0x1000u && pc < 0x2000u) {
        int h = intv_hle_exec(pc);
        if (h) {
            S.intr = ALLOW_BUSRQ | S.ie;
            return h;
        }
    }

    u16 op = bus_read(pc) & 0x3FFu;
    S.intr = ALLOW_BUSRQ | S.ie;
    int cyc = 6;

    if (op >= 0x240u) {
        u32 kind = (op >> 6) & 7u;
        u32 mode = (op >> 3) & 7u;
        u32 reg = op & 7u;
        int dbd = (S.d != 0);

        if (mode == 0u) {
            u16 addr = bus_read((u16)(pc + 1u));
            S.r[7] = (u16)(pc + 2u);
            if (kind == 1u) {
                bus_write(addr, S.r[reg]);
                S.intr = 0;
                cyc = 11;
            } else {
                cp_operate(kind, bus_read(addr), reg);
                cyc = (reg >= 6u) ? 11 : 10;
            }
        } else if (mode == 7u) {
            if (kind == 1u) {
                S.r[7] = (u16)(pc + 2u + (dbd ? 1u : 0u));
                bus_write((u16)(pc + 1u), S.r[reg]);
                S.intr = 0;
                cyc = 9;
            } else {
                u16 opnd;
                if (dbd) {
                    opnd = (bus_read((u16)(pc + 1u)) & 0xFFu) | ((bus_read((u16)(pc + 2u)) & 0xFFu) << 8);
                    S.r[7] = (u16)(pc + 3u);
                } else {
                    opnd = bus_read((u16)(pc + 1u));
                    S.r[7] = (u16)(pc + 2u);
                }
                cp_operate(kind, opnd, reg);
                cyc = (dbd ? 10 : 8) + (reg >= 6u ? 1 : 0);
            }
        } else if (kind == 1u) {
            u16 data = S.r[reg];
            u16 addr = S.r[mode];
            S.r[7] = (u16)(pc + 1u);
            bus_write(addr, data);
            if (mode >= 4u) S.r[mode] = (u16)(addr + 1u);
            S.intr = 0;
            cyc = 9;
        } else if (mode == 6u) {
            u16 addr = (u16)(S.r[6] - 1u);
            S.r[7] = (u16)(pc + 1u);
            u16 opnd = bus_read(addr);
            S.r[6] = addr;
            cp_operate(kind, opnd, reg);
            cyc = 12;
        } else {
            u16 addr = S.r[mode];
            S.r[7] = (u16)(pc + 1u);
            u16 opnd = bus_read(addr);
            u16 next = (u16)(addr + 1u);
            if (dbd) {
                u16 hi = bus_read((mode >= 4u) ? next : addr);
                opnd = (opnd & 0xFFu) | ((hi & 0xFFu) << 8);
                next++;
            }
            if (mode >= 4u) S.r[mode] = next;
            cp_operate(kind, opnd, reg);
            cyc = dbd ? 10 : 8;
        }
    } else if (op >= 0x200u) {
        u16 disp = bus_read((u16)(pc + 1u));
        u16 tgt = (u16)(((op & 0x20u) ? (disp ^ 0xFFFFu) : disp) + pc + 2u);
        S.r[7] = (u16)(pc + 2u);
        int taken = 0;
        if (op & 0x10u) {
            taken = ((op & 0x0Fu) == 0u);
        } else {
            switch (op & 7u) {
            case 0u: taken = 1; break;
            case 1u: taken = (S.c == 1u); break;
            case 2u: taken = (S.o == 1u); break;
            case 3u: taken = (S.s == 0u); break;
            case 4u: taken = (S.z == 1u); break;
            case 5u: taken = ((S.s ^ S.o) == 1u); break;
            case 6u: taken = ((S.z | (S.s ^ S.o)) == 1u); break;
            default: taken = ((S.c ^ S.s) == 1u); break;
            }
            if (op & 8u) taken = !taken;
        }
        if (taken) {
            S.r[7] = tgt;
            cyc = 9;
        } else {
            cyc = 7;
        }
    } else if (op >= 0x080u) {
        u32 kind = op >> 6;
        u32 src = (op >> 3) & 7u;
        u32 dst = op & 7u;
        S.r[7] = (u16)(pc + 1u);
        u16 sv = S.r[src];
        if (kind == 2u) S.r[dst] = set_sz(sv);
        else cp_operate(kind, sv, dst);
        cyc = (dst == 7u && src != 7u) ? 7 : (dst >= 6u ? 7 : 6);
    } else if (op >= 0x040u) {
        u32 reg = op & 3u;
        u32 two = (op >> 2) & 1u;
        u16 v = S.r[reg], res = 0;
        S.r[7] = (u16)(pc + 1u);
        S.intr = 0;
        switch ((op >> 3) & 7u) {
        case 0u: /* SWAP */
            if (two) { res = (u16)((v & 0xFFu) * 0x101u); S.s = (u8)((v >> 7) & 1u); }
            else     { res = (u16)((v >> 8) | (v << 8));  S.s = (u8)((v >> 15) & 1u); }
            break;
        case 1u: /* SLL */
            res = (u16)(v << (1u + two));
            S.s = (u8)((res >> 15) & 1u);
            break;
        case 2u: /* RLC */
            if (two) { res = (u16)((v << 2) | (S.c << 1) | S.o); S.o = (u8)((v >> 14) & 1u); }
            else     { res = (u16)((v << 1) | S.c); }
            S.c = (u8)((v >> 15) & 1u);
            S.s = (u8)((res >> 15) & 1u);
            break;
        case 3u: /* SLLC */
            res = (u16)(v << (1u + two));
            if (two) S.o = (u8)((v >> 14) & 1u);
            S.c = (u8)((v >> 15) & 1u);
            S.s = (u8)((res >> 15) & 1u);
            break;
        case 4u: /* SLR */
            res = (u16)(v >> (1u + two));
            S.s = (u8)((res >> 7) & 1u);
            break;
        case 5u: /* SAR */
            res = (u16)(((int)(s16)v) >> (1u + two));
            S.s = (u8)((res >> 7) & 1u);
            break;
        case 6u: /* RRC */
            if (two) { res = (u16)((v >> 2) | ((u16)S.c << 14) | ((u16)S.o << 15)); S.o = (u8)((v >> 1) & 1u); }
            else     { res = (u16)((v >> 1) | ((u16)S.c << 15)); }
            S.c = (u8)(v & 1u);
            S.s = (u8)((res >> 7) & 1u);
            break;
        default: /* SARC */
            res = (u16)(((int)(s16)v) >> (1u + two));
            if (two) S.o = (u8)((v >> 1) & 1u);
            S.c = (u8)(v & 1u);
            S.s = (u8)((res >> 7) & 1u);
            break;
        }
        S.z = (res == 0u) ? 1u : 0u;
        S.r[reg] = res;
        cyc = two ? 8 : 6;
    } else if (op >= 0x008u) {
        u32 reg = op & 7u;
        S.r[7] = (u16)(pc + 1u);
        u16 v = S.r[reg];
        cyc = (reg >= 6u) ? 7 : 6;
        switch (op >> 3) {
        case 1u: S.r[reg] = set_sz((u16)(v + 1u)); break;
        case 2u: S.r[reg] = set_sz((u16)(v - 1u)); break;
        case 3u: S.r[reg] = set_sz((u16)(v ^ 0xFFFFu)); break;
        case 4u: S.r[reg] = cp_sub(v, 0u); break;
        case 5u: S.r[reg] = cp_add(v, S.c, 0u); break;
        case 6u:
            if (reg < 4u) {
                u16 st = (u16)((S.s << 7) | (S.z << 6) | (S.o << 5) | (S.c << 4));
                S.r[reg] = (u16)(st | (st << 8));
                S.intr = 0;
            }
            cyc = 6;
            break;
        default:
            S.s = (u8)((v >> 7) & 1u);
            S.z = (u8)((v >> 6) & 1u);
            S.o = (u8)((v >> 5) & 1u);
            S.c = (u8)((v >> 4) & 1u);
            S.intr = 0;
            cyc = 6;
            break;
        }
    } else {
        if (op == 0x004u) {
            u16 w1 = bus_read((u16)(pc + 1u));
            u16 w2 = bus_read((u16)(pc + 2u));
            u16 tgt = (u16)((((w1 >> 2) & 0x3Fu) << 10) | (w2 & 0x3FFu));
            u32 sav = (w1 >> 8) & 3u;
            u32 im = w1 & 3u;
            if (im) S.intr = S.ie = (u8)(im & 1u);
            if (sav != 3u) S.r[4u + sav] = (u16)(pc + 3u);
            S.r[7] = tgt;
            cyc = 13;
        } else {
            S.r[7] = (u16)(pc + 1u);
            S.intr = 0;
            switch (op) {
            case 0x000u: S.halted = 1; break;
            case 0x001u: S.d = 2; break;
            case 0x002u: S.ie = 1; break;
            case 0x003u: S.ie = 0; break;
            case 0x006u: S.c = 0; break;
            case 0x007u: S.c = 1; break;
            default: break;
            }
            cyc = 4;
        }
    }

    S.d >>= 1;
    return cyc;
}

/* ---- Cartridge Loaders (.rom Intellicart & .int / .bin) ---- */
static u16 icart_crc16(const u8 *b, u32 start, u32 end)
{
    u16 crc = 0xFFFFu;
    for (u32 i = start; i < end; i++) {
        crc ^= (u16)((u16)b[i] << 8);
        for (int bit = 0; bit < 8; bit++)
            crc = (crc & 0x8000u) ? (u16)((crc << 1) ^ 0x1021u) : (u16)(crc << 1);
    }
    return crc;
}

int intv_is_rom(const u8 *head, u32 got, u32 total_size)
{
    if (!head || got < 6u || total_size < 53u)
        return 0;
    /* Exclude MSX "AB" (0x41, 0x42) */
    if (head[0] == 0x41u && head[1] == 0x42u)
        return 0;
    return (head[0] == 0xA8u || (head[0] & ~0x20u) == 0x41u) && ((head[1] ^ head[2]) == 0xFFu) && head[1] > 0u;
}

void intv_set_bios(const u8 *exec_data, u32 exec_size, const u8 *grom_data, u32 grom_size)
{
    if (exec_data && (exec_size == 8192u || exec_size == 8704u)) {
        u32 base = (exec_size == 8704u) ? 512u : 0u;
        if (exec_size == 8704u) {
            for (u32 i = 0; i < 256u; i++)
                W.exec_aux[i] = (u16)((((u16)exec_data[i * 2] << 8) | exec_data[i * 2 + 1]) & 0x3FFu);
            S.has_ext_aux = 1;
        } else {
            S.has_ext_aux = 0;
        }
        for (u32 i = 0; i < 4096u; i++)
            W.exec[i] = W.ext_exec[i] = (u16)((((u16)exec_data[base + i * 2] << 8) | exec_data[base + i * 2 + 1]) & 0x3FFu);
        S.has_ext_exec = 1;
    } else {
        S.has_ext_exec = 0;
        S.has_ext_aux = 0;
    }

    if (grom_data && grom_size == 2048u) {
        for (u32 i = 0; i < 2048u; i++)
            W.ext_grom[i] = grom_data[i];
        S.has_ext_grom = 1;
    } else {
        S.has_ext_grom = 0;
    }
}

const char *intv_load(const u8 *data, u32 size)
{
    if (!data || size < 64u)
        return "not an Intellivision cartridge (too small)";

    u8 keep_exec = S.has_ext_exec, keep_aux = S.has_ext_aux, keep_grom = S.has_ext_grom;
    u32 keep_rate = S.sample_rate;
    for (u32 i = 0; i < sizeof(S); i++)
        ((u8 *)&S)[i] = 0;
    S.has_ext_exec = keep_exec;
    S.has_ext_aux = keep_aux;
    S.has_ext_grom = keep_grom;
    S.sample_rate = keep_rate;
    S.ext_key = 0xFFu;
    S.noise_lfsr = 1u;
    S.lfsr_rnd = 0xACE1u;

    for (u32 i = 0; i < 65536u; i++) W.cart_mem[i] = 0xFFFFu;
    for (u32 i = 0; i < 256u; i++)   W.cart_attr[i] = 0u;
    for (u32 i = 0; i < 240u; i++)   W.scratch_ram[i] = 0u;
    for (u32 i = 0; i < 352u; i++)   W.sys_ram[i] = 0u;
    for (u32 i = 0; i < 512u; i++)   W.gram[i] = 0u;

    u32 total_words = 0;
    if (intv_is_rom(data, size, size)) {
        /* Intellicart .rom segmented format */
        u32 segs = data[1];
        u32 off = 3u;
        for (u32 s = 0; s < segs; s++) {
            u32 start = off;
            if (off + 2u > size)
                return "truncated Intellicart .rom segment header";
            u32 lo = (u32)data[off++] << 8;
            u32 hi = ((u32)data[off++] << 8) + 0x100u;
            if (hi <= lo || hi > 0x10000u)
                return "invalid Intellicart .rom segment range";
            u32 len = hi - lo;
            if (off + len * 2u + 2u > size)
                return "truncated Intellicart .rom segment data";
            for (u32 w = 0; w < len; w++, off += 2u)
                W.cart_mem[lo + w] = (u16)(((u16)data[off] << 8) | data[off + 1]);
            for (u32 pg = lo >> 8; pg < (hi >> 8); pg++)
                W.cart_attr[pg] |= ATTR_READ;
            u16 exp_crc = (u16)(((u16)data[off] << 8) | data[off + 1]);
            if (icart_crc16(data, start, off) != exp_crc)
                return "corrupt Intellicart .rom (CRC-16 mismatch)";
            off += 2u;
            total_words += len;
        }
        if (off + 50u > size)
            return "truncated Intellicart .rom attribute table";
        for (u32 page = 0; page < 32u; page++) {
            u8 attr = (u8)((data[off + (page >> 1)] >> ((page & 1u) * 4u)) & 0x0Fu);
            u8 rng = data[off + 16u + ((page >> 1) | ((page & 1u) << 4))];
            u32 first = (rng >> 4) & 7u, last = rng & 7u;
            if ((attr & 0x03u) == 0x03u) {
                for (u32 sub = first; sub <= last; sub++) {
                    u32 pg = (page << 3) | sub;
                    W.cart_attr[pg] |= ATTR_READ | ((attr & 0x04u) ? ATTR_WRITE8 : ATTR_WRITE16);
                    for (u32 w = 0; w < 256u; w++)
                        if (W.cart_mem[(pg << 8) + w] == 0xFFFFu)
                            W.cart_mem[(pg << 8) + w] = 0u;
                }
            }
        }
        S.is_rom_fmt = 1;
    } else {
        /* Raw big-endian .int / .bin image */
        if ((size & 1u) || size > 65536u)
            return "not an Intellivision .int/.bin image (invalid byte size)";
        u32 n_words = size >> 1;
        total_words = n_words;

        /* Validate $5000 cartridge header: start ($5004:$5005) and title ($500A:$500B) high bytes should be >= $48 */
        if (n_words < 16u)
            return "Intellivision image too short";
        u16 w4 = ((u16)data[8] << 8) | data[9];
        u16 w5 = ((u16)data[10] << 8) | data[11];
        u16 w10 = ((u16)data[20] << 8) | data[21];
        u16 w11 = ((u16)data[22] << 8) | data[23];
        if ((w5 > 0xFFu && w11 > 0xFFu) || ((w5 & 0xFFu) < 0x40u && (w11 & 0xFFu) < 0x40u) || (w4 > 0x3FFu && w10 > 0x3FFu))
            return "invalid Intellivision $5000 cartridge header";

        /* Non-4K-multiple >8K-word homebrew .bin (e.g. SDK-1600 Song Player): linear from $5000;
           4K-multiple commercial .bin: USUAL_MAP ($5000-$6FFF, $D000-$DFFF, $F000-$FFFF, $9000-$BFFF) */
        if (n_words > 0x2000u && (n_words & 0x3FFu) != 0u) {
            for (u32 w = 0; w < n_words && 0x5000u + w < 0x10000u; w++) {
                u32 a = 0x5000u + w;
                W.cart_mem[a] = (u16)(((u16)data[w * 2] << 8) | data[w * 2 + 1]);
                W.cart_attr[a >> 8] |= ATTR_READ;
            }
        } else {
            static const u16 map_seg[4][2] = {
                {0x5000u, 0x2000u}, {0xD000u, 0x1000u}, {0xF000u, 0x1000u}, {0x9000u, 0x3000u}
            };
            u32 at = 0;
            for (int s = 0; s < 4 && at < n_words; s++) {
                u32 base = map_seg[s][0], cap = map_seg[s][1];
                for (u32 w = 0; w < cap && at < n_words; w++, at++) {
                    W.cart_mem[base + w] = (u16)(((u16)data[at * 2] << 8) | data[at * 2 + 1]);
                    W.cart_attr[(base + w) >> 8] |= ATTR_READ;
                }
            }
        }
        /* Provide JLP 16-bit scratch RAM at $8040..$9F7F if unmapped */
        for (u32 pg = 0x81u; pg <= 0x8Fu; pg++) {
            if (!W.cart_attr[pg]) {
                W.cart_attr[pg] = ATTR_READ | ATTR_WRITE16;
                for (u32 w = 0; w < 256u; w++) W.cart_mem[(pg << 8) + w] = 0u;
            }
        }
        S.is_rom_fmt = 0;
    }

    build_clean_roms();
    stic_reset();
    S.r[7] = 0x1000u;

    /* Format info string */
    char *p = S.info_str;
    const char *pre = S.is_rom_fmt ? "Intellivision (.rom), " : "Intellivision, ";
    while (*pre) *p++ = *pre++;
    u32 kw = (total_words + 511u) >> 10;
    if (kw >= 10u) *p++ = (char)('0' + kw / 10u);
    *p++ = (char)('0' + kw % 10u);
    const char *mid = "K decles (";
    while (*mid) *p++ = *mid++;
    const char *btag = (S.has_ext_exec && S.has_ext_grom) ? "external EXEC+GROM" : "built-in EXEC+GROM";
    while (*btag) *p++ = *btag++;
    *p++ = ')';
    *p = 0;
    return 0;
}

const char *intv_info(void) { return S.info_str; }
void intv_set_key(u8 key) { S.ext_key = key; }
int intv_jammed(void) { return S.jammed || S.halted; }
u8 *intv_save_ram(u32 *size, int *battery) { *size = 0; *battery = 0; return 0; }
int intv_save_changed(void) { return 0; }
void intv_audio_rate(u32 hz) { S.sample_rate = hz; S.aud_frac = 0; S.psg_cyc_rem = 0; }

int intv_audio(s16 *out, int max)
{
    int n = (int)S.aud_count < max ? (int)S.aud_count : max;
    for (int i = 0; i < n; i++)
        out[i] = W.aud_buf[i];
    S.aud_count = 0;
    return n;
}

static void run_cpu_segment(int until, int *irq_pend, int irq_until, int *busrq_pend, int busrq_until, int *fetched_rows)
{
    while (S.now_cyc < until) {
        if (*irq_pend && (S.intr & ALLOW_IRQ)) {
            *irq_pend = 0;
            if (S.now_cyc <= irq_until) {
                bus_write(S.r[6], S.r[7]);
                S.r[6]++;
                S.r[7] = 0x1004u;
                S.now_cyc += 12;
                S.access_from = S.now_cyc;
                if (S.title_wait > 0) S.title_wait--;
                continue;
            }
        } else if (*busrq_pend && (S.intr & ALLOW_BUSRQ)) {
            *busrq_pend = 0;
            if (S.now_cyc <= busrq_until) {
                int row = (*fetched_rows)++;
                if (row < 12) {
                    for (int i = row * 20; i < row * 20 + 20; i++)
                        W.stic_cards[i] = W.sys_ram[i] & 0x3FFFu;
                }
                S.now_cyc = busrq_until;
                continue;
            }
        }
        S.now_cyc += cp1610_step();
    }
}

void intv_frame(u16 pad, u16 *picture)
{
    S.pad = pad;
    S.aud_count = 0;
    S.now_cyc = 0;

    int irq_pend = 1;
    int irq_until = REG_WINDOW + 7;
    int busrq_pend = 0, busrq_until = 0, fetched_rows = 0;

    S.access_from = S.display_enabled ? 1000000 : 0;
    S.enable_req = 0;
    S.regs_until = REG_WINDOW;
    S.gfx_until = GFX_WINDOW;

    /* Phase 1: VBlank Register Window (0 .. 2900) */
    run_cpu_segment(REG_WINDOW, &irq_pend, irq_until, &busrq_pend, busrq_until, &fetched_rows);

    /* Phase 2: Registers close; check if display enabled for this frame */
    S.display_enabled = S.enable_req;
    if (!S.display_enabled) {
        S.access_from = 0;
        S.regs_until = FRAME_CYCLES;
        S.gfx_until = FRAME_CYCLES;
        run_cpu_segment(FRAME_CYCLES, &irq_pend, irq_until, &busrq_pend, busrq_until, &fetched_rows);
    } else {
        /* GRAM open until GFX_WINDOW (3796) */
        run_cpu_segment(GFX_WINDOW, &irq_pend, irq_until, &busrq_pend, busrq_until, &fetched_rows);

        int vd = W.stic_regs[0x31] & 7;
        int delay = 2 * LINE_CYCLES * vd + (int)(W.stic_regs[0x30] & 7);

        /* First BUSRQ fetch */
        int at = GFX_WINDOW;
        busrq_pend = 1;
        busrq_until = at + FIRST_HOLD;
        at += FIRST_GAP + delay;
        run_cpu_segment(at, &irq_pend, irq_until, &busrq_pend, busrq_until, &fetched_rows);

        /* 11 middle row fetches */
        for (int f = 0; f < 11; f++) {
            busrq_pend = 1;
            busrq_until = at + FETCH_HOLD;
            at += 16 * LINE_CYCLES;
            run_cpu_segment(at, &irq_pend, irq_until, &busrq_pend, busrq_until, &fetched_rows);
        }

        /* Last row fetch */
        busrq_pend = 1;
        busrq_until = at + FETCH_HOLD;
        at += 16 * LINE_CYCLES - delay;
        run_cpu_segment(at, &irq_pend, irq_until, &busrq_pend, busrq_until, &fetched_rows);

        /* Extra fetch when vDelay == 0 */
        if (vd == 0) {
            busrq_pend = 1;
            busrq_until = at + EXTRA_HOLD;
        }
        run_cpu_segment(FRAME_CYCLES, &irq_pend, irq_until, &busrq_pend, busrq_until, &fetched_rows);
    }

    stic_render_frame(picture);
    audio_step_cycles(S.now_cyc);
}
