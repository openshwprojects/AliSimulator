#pragma GCC optimize("O2")
#include "scv.h"

#ifndef SCV_HOST
#include "hw.h"
#endif

/* ========================================================================
 * WORKSPACE IN CACHED DDR (0 B static .bss on MIPS!)
 * ======================================================================== */

#define SCV_AUDIO_MAX  2048

/* uPD7801 PSW flags */
#define F_CY   0x01u
#define F_L0   0x04u
#define F_L1   0x08u
#define F_HC   0x10u
#define F_SK   0x20u
#define F_Z    0x40u

/* uPD7801 IRR interrupt request flags */
#define IRR_F0   0x01u
#define IRR_FT0  0x02u
#define IRR_F1   0x04u
#define IRR_F2   0x08u
#define IRR_FST  0x10u

struct upd7801_cpu {
    u16 pc, sp;
    u8  psw, iff, iff_pend, halt;
    u8  v, a, b, c, d, e, h, l;
    u8  v2, a2, b2, c2, d2, e2, h2, l2;
    u8  pa_out, pb_out, pc_out;
    u8  mb, mc, mkl, tm0, tm1, s_reg;
    u8  irr, int1_line, int2_line, to_ff;
    s32 ovc0;
};

struct scv_ws {
    struct upd7801_cpu cpu;

    u8  bios[0x1000];      /* $0000..$0FFF: 4 KB internal uPD7801G ROM */
    u8  charrom[0x0400];   /* 128 x 8x8 ASCII/symbol character generator */
    u8  vram[0x1404];      /* $2000..$3403: 4 KB pattern + 512 B text + 512 B OAM + 4 regs */
    u8  iram[0x0080];      /* $FF80..$FFFF: 128 B internal CPU RAM */
    u8  sram[0x2000];      /* Optional 8 KB / 4 KB cartridge SRAM ($E000..$FF7F) */
    u8  rom[128 * 1024];   /* Up to 128 KB cartridge ROM */
    u32 rom_size;
    u8  has_sram, sram_dirty, ext_bios;

    u8  porta, portc;
    u16 pad;
    u16 key_mask;          /* bits 0..9 = '0'..'9', 10 = Cl, 11 = En, 12 = Pause */
    u8  key_ttl;

    /* Epoch TV-1 256x256 internal color-index canvas + 16-color BGR555 palette */
    u8  canvas[256][256];
    u16 pal[16];

    /* NEC uPD1771C-017 sound synthesizer */
    u8  snd_buf[8];
    u8  snd_len;
    u8  snd_mode;          /* 0=off, 1=noise/sfx, 2=tone */
    u8  snd_wave;
    u8  snd_period;
    u8  snd_vol;
    s32 snd_ack_cyc;
    u32 snd_phase;
    u32 snd_step;
    u32 snd_lfsr;
    u32 snd_nphase;
    u32 sample_rate;
    u32 snd_frac;
    s16 audio_ring[SCV_AUDIO_MAX];
    int audio_count;

    char info[96];
};

#define PAD_A       0x0001u
#define PAD_B       0x0002u
#define PAD_SELECT  0x0004u
#define PAD_START   0x0008u
#define PAD_UP      0x0010u
#define PAD_DOWN    0x0020u
#define PAD_LEFT    0x0040u
#define PAD_RIGHT   0x0080u

#ifdef SCV_HOST
static struct scv_ws scv_host_ws;
#define WS (&scv_host_ws)
#else
#define WS ((struct scv_ws *)KSEG0(EMU_RAM_PHYS))
#endif

static inline u16 bgr555(int r, int g, int b)
{
    return (u16)(((b >> 3) << 10) | ((g >> 3) << 5) | (r >> 3));
}

/* ========================================================================
 * BUILT-IN 128-CHAR 8x8 FONT (0x00..0x7F ASCII + SCV SYMBOLS)
 * ======================================================================== */

static const u8 scv_ascii_8x8[96][8] = {
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, /* 20 ' ' */
    {0x18,0x18,0x18,0x18,0x18,0x00,0x18,0x00}, /* 21 '!' */
    {0x6C,0x6C,0x24,0x00,0x00,0x00,0x00,0x00}, /* 22 '"' */
    {0x6C,0xFE,0x6C,0x6C,0xFE,0x6C,0x00,0x00}, /* 23 '#' */
    {0x18,0x7E,0x60,0x7C,0x06,0xFC,0x18,0x00}, /* 24 '$' */
    {0xC6,0xCC,0x18,0x30,0x66,0xC6,0x00,0x00}, /* 25 '%' */
    {0x38,0x6C,0x38,0x76,0xDC,0xCC,0x76,0x00}, /* 26 '&' */
    {0x18,0x18,0x30,0x00,0x00,0x00,0x00,0x00}, /* 27 ''' */
    {0x0C,0x18,0x30,0x30,0x30,0x18,0x0C,0x00}, /* 28 '(' */
    {0x30,0x18,0x0C,0x0C,0x0C,0x18,0x30,0x00}, /* 29 ')' */
    {0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00}, /* 2A '*' */
    {0x00,0x18,0x18,0x7E,0x18,0x18,0x00,0x00}, /* 2B '+' */
    {0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x30}, /* 2C ',' */
    {0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0x00}, /* 2D '-' */
    {0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00}, /* 2E '.' */
    {0x06,0x0C,0x18,0x30,0x60,0xC0,0x00,0x00}, /* 2F '/' */
    {0x7C,0xC6,0xCE,0xD6,0xE6,0xC6,0x7C,0x00}, /* 30 '0' */
    {0x18,0x38,0x18,0x18,0x18,0x18,0x7E,0x00}, /* 31 '1' */
    {0x7C,0xC6,0x06,0x3C,0x60,0xC0,0xFE,0x00}, /* 32 '2' */
    {0x7C,0xC6,0x06,0x3C,0x06,0xC6,0x7C,0x00}, /* 33 '3' */
    {0x1C,0x3C,0x6C,0xCC,0xFE,0x0C,0x1E,0x00}, /* 34 '4' */
    {0xFE,0xC0,0xFC,0x06,0x06,0xC6,0x7C,0x00}, /* 35 '5' */
    {0x38,0x60,0xC0,0xFC,0xC6,0xC6,0x7C,0x00}, /* 36 '6' */
    {0xFE,0xC6,0x0C,0x18,0x30,0x30,0x30,0x00}, /* 37 '7' */
    {0x7C,0xC6,0xC6,0x7C,0xC6,0xC6,0x7C,0x00}, /* 38 '8' */
    {0x7C,0xC6,0xC6,0x7E,0x06,0x0C,0x78,0x00}, /* 39 '9' */
    {0x00,0x18,0x18,0x00,0x18,0x18,0x00,0x00}, /* 3A ':' */
    {0x00,0x18,0x18,0x00,0x18,0x18,0x30,0x00}, /* 3B ';' */
    {0x0C,0x18,0x30,0x60,0x30,0x18,0x0C,0x00}, /* 3C '<' */
    {0x00,0x00,0x7E,0x00,0x7E,0x00,0x00,0x00}, /* 3D '=' */
    {0x60,0x30,0x18,0x0C,0x18,0x30,0x60,0x00}, /* 3E '>' */
    {0x7C,0xC6,0x0C,0x18,0x18,0x00,0x18,0x00}, /* 3F '?' */
    {0x7C,0xC6,0xDE,0xDE,0xDE,0xC0,0x7C,0x00}, /* 40 '@' */
    {0x38,0x6C,0xC6,0xC6,0xFE,0xC6,0xC6,0x00}, /* 41 'A' */
    {0xFC,0xC6,0xC6,0xFC,0xC6,0xC6,0xFC,0x00}, /* 42 'B' */
    {0x3C,0x66,0xC0,0xC0,0xC0,0x66,0x3C,0x00}, /* 43 'C' */
    {0xF8,0xCC,0xC6,0xC6,0xC6,0xCC,0xF8,0x00}, /* 44 'D' */
    {0xFE,0xC0,0xC0,0xF8,0xC0,0xC0,0xFE,0x00}, /* 45 'E' */
    {0xFE,0xC0,0xC0,0xF8,0xC0,0xC0,0xC0,0x00}, /* 46 'F' */
    {0x3C,0x66,0xC0,0xCE,0xC6,0x66,0x3E,0x00}, /* 47 'G' */
    {0xC6,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0x00}, /* 48 'H' */
    {0x7E,0x18,0x18,0x18,0x18,0x18,0x7E,0x00}, /* 49 'I' */
    {0x1E,0x06,0x06,0x06,0xC6,0xC6,0x7C,0x00}, /* 4A 'J' */
    {0xC6,0xCC,0xD8,0xF0,0xD8,0xCC,0xC6,0x00}, /* 4B 'K' */
    {0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xFE,0x00}, /* 4C 'L' */
    {0xC6,0xEE,0xFE,0xD6,0xC6,0xC6,0xC6,0x00}, /* 4D 'M' */
    {0xC6,0xE6,0xF6,0xDE,0xCE,0xC6,0xC6,0x00}, /* 4E 'N' */
    {0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00}, /* 4F 'O' */
    {0xFC,0xC6,0xC6,0xFC,0xC0,0xC0,0xC0,0x00}, /* 50 'P' */
    {0x7C,0xC6,0xC6,0xC6,0xD6,0xDE,0x7C,0x06}, /* 51 'Q' */
    {0xFC,0xC6,0xC6,0xFC,0xD8,0xCC,0xC6,0x00}, /* 52 'R' */
    {0x7C,0xC6,0xC0,0x7C,0x06,0xC6,0x7C,0x00}, /* 53 'S' */
    {0xFE,0x18,0x18,0x18,0x18,0x18,0x18,0x00}, /* 54 'T' */
    {0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00}, /* 55 'U' */
    {0xC6,0xC6,0xC6,0xC6,0x6C,0x38,0x10,0x00}, /* 56 'V' */
    {0xC6,0xC6,0xC6,0xD6,0xFE,0xEE,0xC6,0x00}, /* 57 'W' */
    {0xC6,0xC6,0x6C,0x38,0x6C,0xC6,0xC6,0x00}, /* 58 'X' */
    {0xC6,0xC6,0x6C,0x38,0x18,0x18,0x18,0x00}, /* 59 'Y' */
    {0xFE,0x06,0x0C,0x18,0x30,0x60,0xFE,0x00}, /* 5A 'Z' */
    {0x3C,0x30,0x30,0x30,0x30,0x30,0x3C,0x00}, /* 5B '[' */
    {0xC0,0x60,0x30,0x18,0x0C,0x06,0x00,0x00}, /* 5C '\' */
    {0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0x00}, /* 5D ']' */
    {0x10,0x38,0x6C,0xC6,0x00,0x00,0x00,0x00}, /* 5E '^' */
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF}, /* 5F '_' */
    {0x30,0x18,0x0C,0x00,0x00,0x00,0x00,0x00}, /* 60 '`' */
    {0x00,0x00,0x78,0x0C,0x7C,0xCC,0x76,0x00}, /* 61 'a' */
    {0xC0,0xC0,0xFC,0xC6,0xC6,0xC6,0xFC,0x00}, /* 62 'b' */
    {0x00,0x00,0x7C,0xC6,0xC0,0xC6,0x7C,0x00}, /* 63 'c' */
    {0x0C,0x0C,0x7C,0xCC,0xCC,0xCC,0x76,0x00}, /* 64 'd' */
    {0x00,0x00,0x7C,0xC6,0xFE,0xC0,0x7C,0x00}, /* 65 'e' */
    {0x38,0x6C,0x60,0xF0,0x60,0x60,0xF0,0x00}, /* 66 'f' */
    {0x00,0x00,0x76,0xCC,0xCC,0x7C,0x0C,0xF8}, /* 67 'g' */
    {0xC0,0xC0,0xFC,0xC6,0xC6,0xC6,0xC6,0x00}, /* 68 'h' */
    {0x18,0x00,0x38,0x18,0x18,0x18,0x3C,0x00}, /* 69 'i' */
    {0x06,0x00,0x06,0x06,0x06,0xC6,0xC6,0x7C}, /* 6A 'j' */
    {0xC0,0xC0,0xCC,0xD8,0xF0,0xD8,0xCC,0x00}, /* 6B 'k' */
    {0x38,0x18,0x18,0x18,0x18,0x18,0x3C,0x00}, /* 6C 'l' */
    {0x00,0x00,0xEC,0xFE,0xD6,0xC6,0xC6,0x00}, /* 6D 'm' */
    {0x00,0x00,0xDC,0x66,0x66,0x66,0x66,0x00}, /* 6E 'n' */
    {0x00,0x00,0x7C,0xC6,0xC6,0xC6,0x7C,0x00}, /* 6F 'o' */
    {0x00,0x00,0xFC,0xC6,0xC6,0xFC,0xC0,0xC0}, /* 70 'p' */
    {0x00,0x00,0x76,0xCC,0xCC,0x7C,0x0C,0x1E}, /* 71 'q' */
    {0x00,0x00,0xDC,0x76,0x60,0x60,0xF0,0x00}, /* 72 'r' */
    {0x00,0x00,0x7C,0xC0,0x7C,0x06,0xFC,0x00}, /* 73 's' */
    {0x30,0x30,0xFC,0x30,0x30,0x36,0x1C,0x00}, /* 74 't' */
    {0x00,0x00,0xCC,0xCC,0xCC,0xCC,0x76,0x00}, /* 75 'u' */
    {0x00,0x00,0xC6,0xC6,0xC6,0x6C,0x38,0x00}, /* 76 'v' */
    {0x00,0x00,0xC6,0xC6,0xD6,0xFE,0x6C,0x00}, /* 77 'w' */
    {0x00,0x00,0xC6,0x6C,0x38,0x6C,0xC6,0x00}, /* 78 'x' */
    {0x00,0x00,0xC6,0xC6,0xCE,0x76,0x06,0x7C}, /* 79 'y' */
    {0x00,0x00,0xFE,0x0C,0x38,0x60,0xFE,0x00}, /* 7A 'z' */
    {0x0E,0x18,0x18,0x70,0x18,0x18,0x0E,0x00}, /* 7B '{' */
    {0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00}, /* 7C '|' */
    {0x70,0x18,0x18,0x0E,0x18,0x18,0x70,0x00}, /* 7D '}' */
    {0x76,0xDC,0x00,0x00,0x00,0x00,0x00,0x00}, /* 7E '~' */
    {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}  /* 7F solid */
};

static void scv_init_charrom(void)
{
    for (int i = 0; i < 1024; i++)
        WS->charrom[i] = 0;
    for (int c = 0; c < 96; c++)
        for (int r = 0; r < 8; r++)
            WS->charrom[(0x20 + c) * 8 + r] = scv_ascii_8x8[c][r];
    /* Control/symbol characters 0x01..0x1F (0x00 stays blank space!) */
    static const u8 sym_box[8] = {0xFF,0x81,0x81,0x81,0x81,0x81,0x81,0xFF};
    for (int c = 1; c < 32; c++)
        for (int r = 0; r < 8; r++)
            WS->charrom[c * 8 + r] = (c == 0x1F) ? 0xFFu : sym_box[r];
}

/* ========================================================================
 * CLEAN-ROOM 4 KB INTERNAL uPD7801G BIOS ($0000..$0FFF)
 * ======================================================================== */

static void scv_build_bios(void)
{
    for (int i = 0; i < 0x1000; i++)
        WS->bios[i] = 0x00u;

    /* Vectors:
       $0000: JMP $0100 (Reset)
       $0004: RETI      (INT0)
       $0008: RETI      (INTT0)
       $0010: RETI      (INT1 - uPD1771C ACK)
       $0020: XRI MKL,$20; JMP $FFFA (INT2 - VBlank rising/falling edge!)
       $0040: RETI      (INTS)
       $0060: RETI      (SOFTI) */
    WS->bios[0x0000] = 0x54u; WS->bios[0x0001] = 0x00u; WS->bios[0x0002] = 0x01u;
    WS->bios[0x0004] = 0x62u;
    WS->bios[0x0008] = 0x62u;
    WS->bios[0x0010] = 0x62u;
    /* $0020: toggle ES (MKL bit 5) so INT2 fires on both vpos 240 (rising -> MKL&$20 becomes 0
       during VBlank, matching Inufuto/Epoch `offi mk,$20`!) and vpos 0 (falling -> MKL&$20=1),
       then jump through RAM hook at $FFFA! */
    WS->bios[0x0020] = 0x64u; WS->bios[0x0021] = 0x93u; WS->bios[0x0022] = 0x20u;
    WS->bios[0x0023] = 0x54u; WS->bios[0x0024] = 0xFAu; WS->bios[0x0025] = 0xFFu;
    WS->bios[0x0040] = 0x62u;
    WS->bios[0x0060] = 0x62u;

    /* Default all 64 CALT entries ($0080..$00FF) to safe RET stub at $01F0 */
    WS->bios[0x01F0] = 0x08u; /* RET */
    for (int t = 0; t < 64; t++) {
        WS->bios[0x0080 + t * 2 + 0] = 0xF0u;
        WS->bios[0x0080 + t * 2 + 1] = 0x01u;
    }

    /* Populate SCV BIOS CALT vectors:
       $008C (CALT $8C, op $86) -> $0200: Clear Text/Block VRAM ($3000..$31FF)
       $008E (CALT $8E, op $87) -> $0230: Clear Sprite OAM ($3200..$33FF)
       $0090 (CALT $90, op $88) -> $0260: Hardware / Working RAM / Hook Init
       $0092 (CALT $92, op $89) -> $02B0: Clear Sprite Pattern RAM ($2000..$2FFF, stack-safe!) */
    WS->bios[0x008C] = 0x00u; WS->bios[0x008D] = 0x02u;
    WS->bios[0x008E] = 0x30u; WS->bios[0x008F] = 0x02u;
    WS->bios[0x0090] = 0x60u; WS->bios[0x0091] = 0x02u;
    WS->bios[0x0092] = 0xB0u; WS->bios[0x0093] = 0x02u;

    /* $0951: Standard SCV IRQ epilogue jumped to by cartridge VBlank handlers (`jmp $0951`):
       EI (48 20), RETI (62) */
    WS->bios[0x0951] = 0x48u; WS->bios[0x0952] = 0x20u; WS->bios[0x0953] = 0x62u;

    /* $0200: Clear $3000..$31FF (preserves VA, HL, BC) */
    {
        static const u8 fn8c[] = {
            0x48, 0x0E,             /* PUSH VA */
            0x48, 0x3E,             /* PUSH HL */
            0x48, 0x1E,             /* PUSH BC */
            0x34, 0x00, 0x30,       /* LXI H, $3000 */
            0x6A, 0x02,             /* MVI B, 2 */
            0x69, 0x00,             /* MVI A, 0 */
            /* pg_lp ($020D): */
            0x6B, 0xFF,             /* MVI C, $FF (256 iterations: FF..00, then 00->FF skips JR!) */
            /* byte_lp ($020F): */
            0x3D,                   /* STAX H+ */
            0x53,                   /* DCR C (skips on borrow!) */
            0xFD,                   /* JR -3 ($020F) */
            0x52,                   /* DCR B (skips on borrow? wait: DCR B skips when B: 0->FF! For 2 pages, B=1 -> 1->0 no skip, 0->FF skip!) */
            0xF8,                   /* JR -8 ($020D) */
            0x48, 0x1F,             /* POP BC */
            0x48, 0x3F,             /* POP HL */
            0x48, 0x0F,             /* POP VA */
            0x08                    /* RET */
        };
        for (u32 i = 0; i < sizeof(fn8c); i++)
            WS->bios[0x0200 + i] = fn8c[i];
        WS->bios[0x020A] = 0x01u;   /* B = 1 -> 2 iterations (1->0, 0->FF skips JR!) */
    }

    /* $0230: Clear $3200..$33FF (preserves VA, HL, BC) */
    for (u32 i = 0; i < 27; i++)
        WS->bios[0x0230 + i] = WS->bios[0x0200 + i];
    WS->bios[0x0238] = 0x32u;       /* LXI H, $3200 */

    /* $0260: CALT $90 — Hardware, port, interrupt-hook, and working-RAM init
       Note: Caller invoked `CALT $90`, so return address is already at [SP..SP+1]! */
    {
        u16 p = 0x0260;
        #define B(x) (WS->bios[p++] = (u8)(x))
        B(0x48); B(0x24);                   /* DI */
        B(0x68); B(0xFF);                   /* MVI V, $FF */
        B(0x69); B(0xFF); B(0x4D); B(0xC4); /* MVI A, $FF; MOV MB, A */
        B(0x69); B(0x07); B(0x4D); B(0xC5); /* MVI A, $07; MOV MC, A */
        B(0x69); B(0xFF); B(0x4D); B(0xC0); /* MVI A, $FF; MOV PA, A */
        B(0x69); B(0x28); B(0x4D); B(0xC2); /* MVI A, $28; MOV PC, A (PC3=1 un-resets uPD1771C, PC5=1!) */
        /* Set $FFFA..$FFFC = `54 51 09` (`JMP $0951`) */
        B(0x71); B(0xFA); B(0x54);          /* MVIW $FA, $54 */
        B(0x71); B(0xFB); B(0x51);          /* MVIW $FB, $51 */
        B(0x71); B(0xFC); B(0x09);          /* MVIW $FC, $09 */
        /* Clear working RAM $FF80..$FFF5 (leaving stack at $FFF6..$FFF9 untouched!) */
        B(0x34); B(0x80); B(0xFF);          /* LXI H, $FF80 */
        B(0x6B); B(0x75);                   /* MVI C, $75 (118 bytes: $FF80..$FFF5; DCR C skips on 0->FF!) */
        B(0x69); B(0x00);                   /* MVI A, 0 */
        B(0x3D);                            /* clr_w: STAX H+ */
        B(0x53);                            /* DCR C */
        B(0xFD);                            /* JR -3 */
        /* Enable INT2 rising-edge VBlank (`MKL = $27`: ES=1, MK2=0, others masked) */
        B(0x69); B(0x27); B(0x4D); B(0xC3); /* MVI A, $27; MOV MKL, A */
        B(0x08);                            /* RET */
        #undef B
    }

    /* $02B0: CALT $92 — Clear Sprite Pattern RAM ($2000..$2FFF, or $2000..$2DFF if SP is in $2000..$2FFF!) */
    {
        u16 p = 0x02B0;
        #define B(x) (WS->bios[p++] = (u8)(x))
        B(0x48); B(0x0E);                   /* PUSH VA */
        B(0x48); B(0x3E);                   /* PUSH HL */
        B(0x48); B(0x1E);                   /* PUSH BC */
        /* Store SP to $FFF4..$FFF5 via SSPD ($70 $0E lo hi) to check SPH! */
        B(0x70); B(0x0E); B(0xF4); B(0xFF); /* SSPD $FFF4 */
        B(0x28); B(0xF5);                   /* LDAW $F5 (A = SPH) */
        B(0x6A); B(0x0F);                   /* MVI B, 15 (16 pages = $2000..$2FFF) */
        B(0x37); B(0x30);                   /* LTI A, $30 (if SPH < $30, skip JR!) */
        B(0xC3);                            /* JR +3 (keep B = 15) */
        B(0x66); B(0x21); B(0x1A);          /* SUI A, $21; MOV B, A (clears $2000..(SPH-1)FF, never touching stack!) */
        B(0x34); B(0x00); B(0x20);          /* LXI H, $2000 */
        B(0x69); B(0x00);                   /* MVI A, 0 */
        /* pg_lp: */
        u16 pg_lp = p;
        B(0x6B); B(0xFF);                   /* MVI C, $FF (256 bytes per page!) */
        B(0x3D);                            /* STAX H+ */
        B(0x53);                            /* DCR C */
        B(0xFD);                            /* JR -3 */
        B(0x52);                            /* DCR B */
        { u8 rel = (u8)((pg_lp - (p + 1u)) & 0x3Fu); B(0xC0u | rel); }
        B(0x48); B(0x1F);                   /* POP BC */
        B(0x48); B(0x3F);                   /* POP HL */
        B(0x48); B(0x0F);                   /* POP VA */
        B(0x08);                            /* RET */
        #undef B
    }

    /* $0100: Reset Boot Routine -> sets SP=$FFFA, calls CALT $90, $92, $8C, $8E, sets TV-1 defaults,
       and jumps to cartridge ($8001 if [$8000]=='H', else $8000)! */
    {
        u16 p = 0x0100;
        #define B(x) (WS->bios[p++] = (u8)(x))
        B(0x04); B(0xFA); B(0xFF);          /* LXI SP, $FFFA */
        B(0x88);                            /* CALT $90 */
        B(0x89);                            /* CALT $92 */
        B(0x86);                            /* CALT $8C */
        B(0x87);                            /* CALT $8E */
        /* Default Epoch TV-1 registers $3400..$3403 = $10, $01, $00, $F0 */
        B(0x34); B(0x00); B(0x34);          /* LXI H, $3400 */
        B(0x4B); B(0x10); B(0x32);          /* MVIX HL, $10; INX HL */
        B(0x4B); B(0x01); B(0x32);          /* MVIX HL, $01; INX HL */
        B(0x4B); B(0x00); B(0x32);          /* MVIX HL, $00; INX HL */
        B(0x4B); B(0xF0);                   /* MVIX HL, $F0 */
        /* Check cartridge header at $8000: if 'H' ($48), jump to $8001, else $8000 */
        B(0x70); B(0x69); B(0x00); B(0x80); /* MOV A, ($8000) */
        B(0x77); B(0x48);                   /* EQI A, 'H' ($48) -> skips next JMP if equal! */
        B(0x54); B(0x00); B(0x80);          /* JMP $8000 */
        B(0x54); B(0x01); B(0x80);          /* JMP $8001 */
        #undef B
    }
}

/* ========================================================================
 * NEC uPD1771C-017 SOUND SYNTHESIZER ($3600 + INTF1 ACK)
 * ======================================================================== */

static const s8 scv_waves[4][16] = {
    {  96,  96,  96,  96,  96,  96,  96,  96, -96, -96, -96, -96, -96, -96, -96, -96 },
    { 110, 110, 110, 110, -70, -70, -70, -70, -70, -70, -70, -70, 110, 110, -70, -70 },
    { 112,  84,  56,  28,   0, -28, -56, -84,-112, -84, -56, -28,   0,  28,  56,  84 },
    { 108, 108,  64, -64,-108,-108,  64, 108,  64, -64,-108, -64,  64, 108, -64, -96 }
};

static void scv_snd_recalc(void)
{
    if (!WS->sample_rate || WS->snd_mode == 0 || WS->snd_vol == 0 || WS->snd_period == 0) {
        WS->snd_step = 0;
        return;
    }
    /* Real uPD1771C @ 6 MHz: 16-step cycle frequency = 46,875 Hz / period -> step = (16 * 46875 << 16) / (period * rate)
       Avoid 64-bit division: 46875 * 65536 = 3,072,000,000 (fits in u32!), or (750000 << 12) / rate * 16 / period! */
    u32 base = (750000u << 11) / WS->sample_rate; /* (750000 / rate) in 21.11, * 32 = 16.16! */
    WS->snd_step = (base << 5) / (u32)WS->snd_period;
}

static void scv_snd_write(u8 d)
{
    if (!(WS->portc & 0x08u))
        return;

    /* Pulse INTF1 ready/ACK 24 CPU cycles after each byte written to $3600 */
    WS->cpu.int1_line = 0;
    WS->snd_ack_cyc = 24;

    if (WS->snd_len == 0) {
        if (d == 0x00u) {
            WS->snd_mode = 0;
            WS->snd_vol = 0;
            WS->snd_step = 0;
            return;
        }
        WS->snd_buf[0] = d;
        WS->snd_len = 1;
        return;
    }

    if (WS->snd_len < sizeof(WS->snd_buf))
        WS->snd_buf[WS->snd_len++] = d;

    u8 cmd = WS->snd_buf[0];
    if (cmd == 0x02u) {
        /* 4-byte Tone command: $02, timbre, period, volume ($00..$1F) */
        if (WS->snd_len >= 4) {
            WS->snd_mode = 2;
            WS->snd_wave = (WS->snd_buf[1] >> 5) & 3u;
            WS->snd_period = WS->snd_buf[2] ? WS->snd_buf[2] : 1u;
            WS->snd_vol = WS->snd_buf[3] & 0x1Fu;
            WS->snd_len = 0;
            scv_snd_recalc();
        }
    } else if (cmd == 0x01u) {
        /* 3- or 4-byte Noise/SFX command */
        if (WS->snd_len >= 3) {
            WS->snd_mode = 1;
            WS->snd_period = WS->snd_buf[1] ? WS->snd_buf[1] : 32u;
            WS->snd_vol = WS->snd_buf[2] & 0x1Fu;
            if (WS->snd_len >= 4 || (WS->snd_buf[2] & 0x1Fu) != 0)
                WS->snd_len = 0;
            scv_snd_recalc();
        }
    } else {
        /* Fallback short SFX / PCM command */
        if (d == 0x00u) {
            WS->snd_mode = 0;
            WS->snd_vol = 0;
            WS->snd_len = 0;
            WS->snd_step = 0;
        } else if (WS->snd_len >= 3) {
            WS->snd_mode = 1;
            WS->snd_period = (u8)(40u + (WS->snd_buf[1] & 0x7Fu));
            WS->snd_vol = (WS->snd_buf[2] & 0x1Fu) ? (WS->snd_buf[2] & 0x1Fu) : 16u;
            WS->snd_len = 0;
            scv_snd_recalc();
        }
    }
}

static void scv_snd_line(void)
{
    if (!WS->sample_rate)
        return;

    u32 num = WS->sample_rate + WS->snd_frac;
    u32 ns = num / 15720u;
    WS->snd_frac = num % 15720u;

    while (ns--) {
        s32 s = 0;
        if ((WS->portc & 0x08u) && WS->snd_mode != 0 && WS->snd_vol != 0 && WS->snd_step != 0) {
            WS->snd_phase += WS->snd_step;
            if (WS->snd_mode == 2) {
                int idx = (WS->snd_phase >> 16) & 15;
                s = (s32)scv_waves[WS->snd_wave & 3u][idx] * (s32)WS->snd_vol * 4;
            } else {
                u32 prev = WS->snd_nphase;
                WS->snd_nphase += WS->snd_step;
                if ((prev ^ WS->snd_nphase) & 0x8000u) {
                    u32 bit = ((WS->snd_lfsr >> 6) ^ (WS->snd_lfsr >> 5)) & 1u;
                    WS->snd_lfsr = ((WS->snd_lfsr << 1) | bit) & 0x7Fu;
                    if (!WS->snd_lfsr) WS->snd_lfsr = 0x55u;
                }
                s = ((WS->snd_lfsr & 1u) ? 90 : -90) * (s32)WS->snd_vol * 4;
            }
        }
        if (WS->audio_count < SCV_AUDIO_MAX)
            WS->audio_ring[WS->audio_count++] = (s16)s;
    }
}

/* ========================================================================
 * MEMORY & CONTROLLER BUS
 * ======================================================================== */

static u8 scv_read_pb(void)
{
    u8 data = 0xFFu;
    u8 pa = WS->porta;

    /* Row 0: P1 Left(0), Up(1), Btn1(2) */
    if (!(pa & 0x01u)) {
        if (WS->pad & PAD_LEFT)  data &= (u8)~0x01u;
        if (WS->pad & PAD_UP)    data &= (u8)~0x02u;
        if (WS->pad & PAD_A)     data &= (u8)~0x04u;
    }
    /* Row 1: P1 Down(0), Right(1), Btn2(2) */
    if (!(pa & 0x02u)) {
        if (WS->pad & PAD_DOWN)  data &= (u8)~0x01u;
        if (WS->pad & PAD_RIGHT) data &= (u8)~0x02u;
        if (WS->pad & PAD_B)     data &= (u8)~0x04u;
    }
    /* Rows 2..7: console numeric keypad 0..9, Cl (Select), En (Start) on PB6 / PB7 */
    u16 km = WS->key_mask;
    if (WS->pad & PAD_SELECT) km |= (1u << 10); /* Cl */
    if (WS->pad & PAD_START)  km |= (1u << 11); /* En */

    for (int r = 0; r < 6; r++) {
        if (!(pa & (u8)(0x04u << r))) {
            if (km & (1u << (r * 2 + 0))) data &= (u8)~0x40u;
            if (km & (1u << (r * 2 + 1))) data &= (u8)~0x80u;
        }
    }
    return data;
}

static u8 scv_rd(u16 a)
{
    if (a < 0x1000u)
        return WS->bios[a];
    if (a >= 0x2000u && a <= 0x3403u)
        return WS->vram[a - 0x2000u];
    if (a >= 0xFF80u)
        return WS->iram[a - 0xFF80u];
    if (a >= 0x8000u && WS->rom_size > 0) {
        u32 off = (u32)(a - 0x8000u);
        if (WS->rom_size <= 0x8000u) {
            if (a >= 0xE000u && WS->has_sram && (WS->portc & 0x20u))
                return WS->sram[a - 0xE000u];
            return WS->rom[off % WS->rom_size];
        } else if (WS->rom_size <= 0x10000u) {
            u32 bank = (WS->portc >> 5) & 1u;
            return WS->rom[(bank * 0x8000u + off) % WS->rom_size];
        } else {
            if (a >= 0xF000u && WS->has_sram && (WS->portc & 0x40u))
                return WS->sram[a - 0xF000u];
            u32 bank = (WS->portc >> 5) & 3u;
            return WS->rom[(bank * 0x8000u + off) % WS->rom_size];
        }
    }
    return 0xFFu;
}

static void scv_wr(u16 a, u8 v)
{
    if (a >= 0x2000u && a <= 0x3403u) {
        WS->vram[a - 0x2000u] = v;
        return;
    }
    if (a == 0x3600u) {
        scv_snd_write(v);
        return;
    }
    if (a >= 0xFF80u) {
        WS->iram[a - 0xFF80u] = v;
        return;
    }
    if (a >= 0xE000u && a < 0xFF80u) {
        if (WS->rom_size <= 0x8000u && (WS->portc & 0x20u)) {
            WS->has_sram = 1;
            if (WS->sram[a - 0xE000u] != v) {
                WS->sram[a - 0xE000u] = v;
                WS->sram_dirty = 1;
            }
        } else if (WS->rom_size > 0x10000u && a >= 0xF000u && (WS->portc & 0x40u)) {
            WS->has_sram = 1;
            if (WS->sram[a - 0xF000u] != v) {
                WS->sram[a - 0xF000u] = v;
                WS->sram_dirty = 1;
            }
        }
    }
}

/* ========================================================================
 * NEC uPD7801G CPU CORE (FULL INSTRUCTION SET + SKIP/OVERLAY ENGINE)
 * ======================================================================== */

static u8 u78_rp(int port)
{
    struct upd7801_cpu *c = &WS->cpu;
    if (port == 0) /* PA (output on 7801) */
        return c->pa_out;
    if (port == 1) /* PB */
        return (u8)((scv_read_pb() & c->mb) | (c->pb_out & (u8)~c->mb));
    /* PC: bit 0 = Pause active-low, bit 2 = -SCS high, others per MC */
    u8 inputs = (u8)(0x84u | (c->mc & 0x03u));
    u8 pcin = (WS->key_mask & (1u << 12)) ? 0x04u : 0x05u;
    u8 d = (u8)((pcin & inputs) | (c->pc_out & (u8)~inputs));
    if (!(c->mc & 0x10u))
        d = (u8)((d & ~0x10u) | (c->to_ff ? 0x10u : 0u));
    return d;
}

static void u78_wp(int port, u8 v)
{
    struct upd7801_cpu *c = &WS->cpu;
    if (port == 0) {
        c->pa_out = v;
        WS->porta = v;
    } else if (port == 1) {
        c->pb_out = v;
    } else {
        c->pc_out = v;
        u8 inputs = (u8)(0x84u | (c->mc & 0x03u));
        u8 out = (u8)((v & (u8)~inputs) | inputs);
        if (!(WS->portc & 0x08u) && (out & 0x08u)) {
            /* uPD1771C released from reset */
            WS->snd_len = 0;
            WS->snd_mode = 0;
            WS->snd_vol = 0;
        } else if (!(out & 0x08u)) {
            WS->snd_mode = 0;
            WS->snd_vol = 0;
            WS->snd_len = 0;
        }
        WS->portc = out;
    }
}

static inline void u78_zhc_add(struct upd7801_cpu *c, u8 after, u8 before, u8 carry)
{
    if (after == 0) c->psw |= F_Z; else c->psw &= (u8)~F_Z;
    if (after == before) c->psw = (u8)((c->psw & ~F_CY) | (carry & F_CY));
    else if (after < before) c->psw |= F_CY;
    else c->psw &= (u8)~F_CY;
    if ((after & 15u) < (before & 15u)) c->psw |= F_HC;
    else c->psw &= (u8)~F_HC;
}

static inline void u78_zhc_sub(struct upd7801_cpu *c, u8 after, u8 before, u8 borrow)
{
    if (after == 0) c->psw |= F_Z; else c->psw &= (u8)~F_Z;
    if (before == after) c->psw = (u8)((c->psw & ~F_CY) | (borrow & F_CY));
    else if (after > before) c->psw |= F_CY;
    else c->psw &= (u8)~F_CY;
    if ((after & 15u) > (before & 15u)) c->psw |= F_HC;
    else c->psw &= (u8)~F_HC;
}

static inline u8 *u78_reg8(struct upd7801_cpu *c, int idx)
{
    switch (idx & 7) {
    case 0: return &c->v;
    case 1: return &c->a;
    case 2: return &c->b;
    case 3: return &c->c;
    case 4: return &c->d;
    case 5: return &c->e;
    case 6: return &c->h;
    default: return &c->l;
    }
}

static void u78_set_int2(int state)
{
    struct upd7801_cpu *c = &WS->cpu;
    if (c->mkl & 0x20u) {
        if (!c->int2_line && state)
            c->irr |= IRR_F2;
    } else {
        if (c->int2_line && !state)
            c->irr |= IRR_F2;
    }
    c->int2_line = (u8)state;
}

static void u78_timers(int cyc)
{
    struct upd7801_cpu *c = &WS->cpu;
    if (c->ovc0 > 0) {
        c->ovc0 -= cyc;
        if (c->ovc0 <= 0) {
            c->irr |= IRR_FT0;
            c->to_ff = 0;
            s32 reload = 8 * ((s32)c->tm0 + (((s32)(c->tm1 & 0x0Fu)) << 8));
            c->ovc0 = (reload > 0) ? reload : 0;
        }
    }
    if (WS->snd_ack_cyc > 0) {
        WS->snd_ack_cyc -= cyc;
        if (WS->snd_ack_cyc <= 0) {
            WS->snd_ack_cyc = 0;
            if (!c->int1_line) {
                c->int1_line = 1;
                c->irr |= IRR_F1;
            }
        }
    }
}

static void u78_check_irq(void)
{
    struct upd7801_cpu *c = &WS->cpu;
    u16 vec = 0;
    u8 mask = 0;

    if ((c->irr & IRR_F0) && !(c->mkl & 0x01u))      { vec = 0x0004u; mask = 0; }
    else if ((c->irr & IRR_FT0) && !(c->mkl & 0x02u)){ vec = 0x0008u; mask = IRR_FT0; }
    else if ((c->irr & IRR_F1) && !(c->mkl & 0x04u)) { vec = 0x0010u; mask = IRR_F1; }
    else if ((c->irr & IRR_F2) && !(c->mkl & 0x08u)) { vec = 0x0020u; mask = IRR_F2; }
    else if ((c->irr & IRR_FST) && !(c->mkl & 0x10u)){ vec = 0x0040u; mask = IRR_FST; }

    if (vec) {
        c->halt = 0;
        if (!c->iff)
            return;
        scv_wr(--c->sp, c->psw);
        scv_wr(--c->sp, (u8)(c->pc >> 8));
        scv_wr(--c->sp, (u8)c->pc);
        c->iff = c->iff_pend = 0;
        c->irr &= (u8)~mask;
        c->psw &= (u8)~(F_SK | F_L0 | F_L1);
        c->pc = vec;
    }
}

/* Exact uPD7801 opcode length tables (with 0x63 CALB = 1 byte fixed!) */
static int u78_oplen_main(u8 op)
{
    static const u8 len[256] = {
        /* 00 */ 1,1,1,1,3,3,1,2, 1,1,1,1,1,1,1,1,
        /* 10 */ 1,1,1,1,3,3,2,2, 1,1,1,1,1,1,1,1,
        /* 20 */ 2,1,1,1,3,3,2,2, 2,1,1,1,1,1,1,1,
        /* 30 */ 2,1,1,1,3,3,2,2, 2,1,1,1,1,1,1,1,
        /* 40 */ 1,1,1,1,3,3,2,2, 0,2,2,2,0,0,2,2,
        /* 50 */ 1,1,1,1,3,3,2,2, 2,2,2,2,2,2,2,2,
        /* 60 */ 0,1,1,1,0,3,2,2, 2,2,2,2,2,2,2,2,
        /* 70 */ 0,3,1,1,0,3,2,2, 2,2,2,2,2,2,2,2,
        /* 80..BF CALT = 1 byte */
        1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
        /* C0..FF JR = 1 byte */
        1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1,
        1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1, 1,1,1,1,1,1,1,1
    };
    return len[op];
}

static int u78_oplen_pre(u8 pre, u8 op2)
{
    if (pre == 0x64u)
        return (op2 >= 0x08u) ? 3 : 2;
    if (pre == 0x70u) {
        if ((op2 & 0xCFu) == 0x0Eu || (op2 & 0xEFu) == 0x68u || (op2 & 0xF8u) == 0x68u || (op2 & 0xF8u) == 0x78u)
            return 4;
        return 2;
    }
    if (pre == 0x74u)
        return (op2 >= 0x80u && (op2 & 7u) == 0u) ? 3 : 2;
    return 2; /* 48, 4C, 4D, 60 */
}

static void u78_alu_op(struct upd7801_cpu *c, u8 kind, u8 *dst, u8 rhs)
{
    u8 lhs = *dst, res;
    switch (kind & 0x0Fu) {
    case 0x01: /* ANA */ res = lhs & rhs; *dst = res; if (res) c->psw &= (u8)~F_Z; else c->psw |= F_Z; break;
    case 0x02: /* XRA */ res = lhs ^ rhs; *dst = res; if (res) c->psw &= (u8)~F_Z; else c->psw |= F_Z; break;
    case 0x03: /* ORA */ res = lhs | rhs; *dst = res; if (res) c->psw &= (u8)~F_Z; else c->psw |= F_Z; break;
    case 0x04: /* ADDNC */ res = (u8)(lhs + rhs); u78_zhc_add(c, res, lhs, 0); *dst = res; if (!(c->psw & F_CY)) c->psw |= F_SK; break;
    case 0x05: /* GTA */ res = (u8)(lhs - rhs - 1u); u78_zhc_sub(c, res, lhs, 0); if (!(c->psw & F_CY)) c->psw |= F_SK; break;
    case 0x06: /* SUBNB */ res = (u8)(lhs - rhs); u78_zhc_sub(c, res, lhs, 0); *dst = res; if (!(c->psw & F_CY)) c->psw |= F_SK; break;
    case 0x07: /* LTA */ res = (u8)(lhs - rhs); u78_zhc_sub(c, res, lhs, 0); if (c->psw & F_CY) c->psw |= F_SK; break;
    case 0x08: /* ADD */ res = (u8)(lhs + rhs); u78_zhc_add(c, res, lhs, 0); *dst = res; break;
    case 0x09: /* ONA */ if (lhs & rhs) { c->psw &= (u8)~F_Z; c->psw |= F_SK; } else { c->psw |= F_Z; } break;
    case 0x0A: /* ADC */ { u8 cy = c->psw & F_CY; res = (u8)(lhs + rhs + cy); u78_zhc_add(c, res, lhs, cy); *dst = res; break; }
    case 0x0B: /* OFFA */ if (lhs & rhs) { c->psw &= (u8)~F_Z; } else { c->psw |= (u8)(F_Z | F_SK); } break;
    case 0x0C: /* SUB */ res = (u8)(lhs - rhs); u78_zhc_sub(c, res, lhs, 0); *dst = res; break;
    case 0x0D: /* NEA */ res = (u8)(lhs - rhs); u78_zhc_sub(c, res, lhs, 0); if (!(c->psw & F_Z)) c->psw |= F_SK; break;
    case 0x0E: /* SBB */ { u8 cy = c->psw & F_CY; res = (u8)(lhs - rhs - cy); u78_zhc_sub(c, res, lhs, cy); *dst = res; break; }
    case 0x0F: /* EQA */ res = (u8)(lhs - rhs); u78_zhc_sub(c, res, lhs, 0); if (c->psw & F_Z) c->psw |= F_SK; break;
    default: break;
    }
}

static int u78_step(void)
{
    struct upd7801_cpu *c = &WS->cpu;
    if (c->halt) {
        u78_timers(4);
        u78_check_irq();
        return 4;
    }

    u8 op = scv_rd(c->pc++);

    /* Clear L0 / L1 overlay flags except on LXI H (0x34), MVI A (0x69), MVI L (0x6F) */
    if (op == 0x34u || op == 0x6Fu) c->psw &= (u8)~F_L1;
    else if (op == 0x69u)           c->psw &= (u8)~F_L0;
    else                            c->psw &= (u8)~(F_L0 | F_L1);

    /* Handle SK (skip next instruction, except SOFTI 0x72) */
    if ((c->psw & F_SK) && op != 0x72u) {
        int len = u78_oplen_main(op);
        int cyc = 8;
        if (len > 0) {
            c->pc = (u16)(c->pc + (len - 1));
            cyc = (len == 1) ? 4 : 8;
        } else {
            u8 op2 = scv_rd(c->pc++);
            int plen = u78_oplen_pre(op, op2);
            c->pc = (u16)(c->pc + (plen - 2));
            cyc = 8;
        }
        c->psw &= (u8)~F_SK;
        u78_timers(cyc);
        u78_check_irq();
        c->iff = c->iff_pend;
        return cyc;
    }

    int cyc = 4;
    #define BC16 ((u16)(((u16)c->b << 8) | c->c))
    #define DE16 ((u16)(((u16)c->d << 8) | c->e))
    #define HL16 ((u16)(((u16)c->h << 8) | c->l))
    #define SET_BC(v) do { u16 _v=(v); c->b=(u8)(_v>>8); c->c=(u8)_v; } while(0)
    #define SET_DE(v) do { u16 _v=(v); c->d=(u8)(_v>>8); c->e=(u8)_v; } while(0)
    #define SET_HL(v) do { u16 _v=(v); c->h=(u8)(_v>>8); c->l=(u8)_v; } while(0)
    #define WA16(off) ((u16)(((u16)c->v << 8) | (off)))

    switch (op) {
    case 0x00: break; /* NOP */
    case 0x01: c->halt = 1; cyc = 6; break; /* HLT */
    case 0x02: c->sp++; cyc = 7; break;
    case 0x03: c->sp--; cyc = 7; break;
    case 0x04: { u8 lo = scv_rd(c->pc++), hi = scv_rd(c->pc++); c->sp = (u16)(((u16)hi << 8) | lo); cyc = 10; break; }
    case 0x05: { u16 wa = WA16(scv_rd(c->pc++)); u8 imm = scv_rd(c->pc++); u8 m = scv_rd(wa) & imm; scv_wr(wa, m); if (m) c->psw &= (u8)~F_Z; else c->psw |= F_Z; cyc = 16; break; }
    case 0x07: u78_alu_op(c, 0x01, &c->a, scv_rd(c->pc++)); cyc = 7; break;
    case 0x08: { u8 lo = scv_rd(c->sp++); u8 hi = scv_rd(c->sp++); c->pc = (u16)(((u16)hi << 8) | lo); cyc = 11; break; } /* RET */
    case 0x09: break; /* SIO */
    case 0x0A: c->a = c->b; break;
    case 0x0B: c->a = c->c; break;
    case 0x0C: c->a = c->d; break;
    case 0x0D: c->a = c->e; break;
    case 0x0E: c->a = c->h; break;
    case 0x0F: c->a = c->l; break;

    case 0x10: { u8 tv = c->v, ta = c->a; c->v = c->v2; c->a = c->a2; c->v2 = tv; c->a2 = ta; break; } /* EXA */
    case 0x11: { /* EXX */
        u8 t;
        t = c->b; c->b = c->b2; c->b2 = t; t = c->c; c->c = c->c2; c->c2 = t;
        t = c->d; c->d = c->d2; c->d2 = t; t = c->e; c->e = c->e2; c->e2 = t;
        t = c->h; c->h = c->h2; c->h2 = t; t = c->l; c->l = c->l2; c->l2 = t;
        break;
    }
    case 0x12: SET_BC(BC16 + 1u); cyc = 7; break;
    case 0x13: SET_BC(BC16 - 1u); cyc = 7; break;
    case 0x14: c->c = scv_rd(c->pc++); c->b = scv_rd(c->pc++); cyc = 10; break;
    case 0x15: { u16 wa = WA16(scv_rd(c->pc++)); u8 imm = scv_rd(c->pc++); u8 m = scv_rd(wa) | imm; scv_wr(wa, m); if (m) c->psw &= (u8)~F_Z; else c->psw |= F_Z; cyc = 16; break; }
    case 0x16: u78_alu_op(c, 0x02, &c->a, scv_rd(c->pc++)); cyc = 7; break;
    case 0x17: u78_alu_op(c, 0x03, &c->a, scv_rd(c->pc++)); cyc = 7; break;
    case 0x18: { u8 lo = scv_rd(c->sp++); u8 hi = scv_rd(c->sp++); c->pc = (u16)(((u16)hi << 8) | lo); c->psw |= F_SK; cyc = 11; break; } /* RETS */
    case 0x19: c->to_ff = 1; c->ovc0 = 8 * ((s32)c->tm0 + (((s32)(c->tm1 & 0x0Fu)) << 8)); break; /* STM */
    case 0x1A: c->b = c->a; break;
    case 0x1B: c->c = c->a; break;
    case 0x1C: c->d = c->a; break;
    case 0x1D: c->e = c->a; break;
    case 0x1E: c->h = c->a; break;
    case 0x1F: c->l = c->a; break;

    case 0x20: { /* INRW wa */
        u16 wa = WA16(scv_rd(c->pc++));
        u8 m = scv_rd(wa), tmp = (u8)(m + 1u), ocy = c->psw & F_CY;
        u78_zhc_add(c, tmp, m, 0);
        scv_wr(wa, tmp);
        if (c->psw & F_CY) c->psw |= F_SK;
        c->psw = (u8)((c->psw & ~F_CY) | ocy);
        cyc = 13; break;
    }
    case 0x21: { /* TABLE (7801 opcode 0x21!) */
        u16 ea = (u16)(c->pc + c->a + 1u);
        c->c = scv_rd(ea);
        c->b = scv_rd((u16)(ea + 1u));
        cyc = 19; break;
    }
    case 0x22: SET_DE(DE16 + 1u); cyc = 7; break;
    case 0x23: SET_DE(DE16 - 1u); cyc = 7; break;
    case 0x24: c->e = scv_rd(c->pc++); c->d = scv_rd(c->pc++); cyc = 10; break;
    case 0x25: { u16 wa = WA16(scv_rd(c->pc++)); u8 imm = scv_rd(c->pc++), m = scv_rd(wa); u78_alu_op(c, 0x05, &m, imm); cyc = 13; break; }
    case 0x26: u78_alu_op(c, 0x04, &c->a, scv_rd(c->pc++)); cyc = 7; break;
    case 0x27: u78_alu_op(c, 0x05, &c->a, scv_rd(c->pc++)); cyc = 7; break;
    case 0x28: c->a = scv_rd(WA16(scv_rd(c->pc++))); cyc = 10; break;
    case 0x29: c->a = scv_rd(BC16); cyc = 7; break;
    case 0x2A: c->a = scv_rd(DE16); cyc = 7; break;
    case 0x2B: c->a = scv_rd(HL16); cyc = 7; break;
    case 0x2C: { u16 de = DE16; c->a = scv_rd(de); SET_DE(de + 1u); cyc = 7; break; }
    case 0x2D: { u16 hl = HL16; c->a = scv_rd(hl); SET_HL(hl + 1u); cyc = 7; break; }
    case 0x2E: { u16 de = DE16; c->a = scv_rd(de); SET_DE(de - 1u); cyc = 7; break; }
    case 0x2F: { u16 hl = HL16; c->a = scv_rd(hl); SET_HL(hl - 1u); cyc = 7; break; }

    case 0x30: { /* DCRW wa */
        u16 wa = WA16(scv_rd(c->pc++));
        u8 m = scv_rd(wa), tmp = (u8)(m - 1u), ocy = c->psw & F_CY;
        u78_zhc_sub(c, tmp, m, 0);
        scv_wr(wa, tmp);
        if (c->psw & F_CY) c->psw |= F_SK;
        c->psw = (u8)((c->psw & ~F_CY) | ocy);
        cyc = 13; break;
    }
    case 0x31: { /* BLOCK */
        u16 de = DE16, hl = HL16;
        scv_wr(de, scv_rd(hl));
        SET_DE(de + 1u);
        SET_HL(hl + 1u);
        c->c--;
        if (c->c == 0xFFu) c->psw |= F_CY;
        else { c->psw &= (u8)~F_CY; c->pc--; }
        cyc = 13; break;
    }
    case 0x32: SET_HL(HL16 + 1u); cyc = 7; break;
    case 0x33: SET_HL(HL16 - 1u); cyc = 7; break;
    case 0x34: { /* LXI H, w (with L0 overlay) */
        if (c->psw & F_L0) { c->pc += 2; }
        else { c->l = scv_rd(c->pc++); c->h = scv_rd(c->pc++); c->psw |= F_L0; }
        cyc = 10; break;
    }
    case 0x35: { u16 wa = WA16(scv_rd(c->pc++)); u8 imm = scv_rd(c->pc++), m = scv_rd(wa); u78_alu_op(c, 0x07, &m, imm); cyc = 13; break; }
    case 0x36: u78_alu_op(c, 0x06, &c->a, scv_rd(c->pc++)); cyc = 7; break;
    case 0x37: u78_alu_op(c, 0x07, &c->a, scv_rd(c->pc++)); cyc = 7; break;
    case 0x38: scv_wr(WA16(scv_rd(c->pc++)), c->a); cyc = 10; break;
    case 0x39: scv_wr(BC16, c->a); cyc = 7; break;
    case 0x3A: scv_wr(DE16, c->a); cyc = 7; break;
    case 0x3B: scv_wr(HL16, c->a); cyc = 7; break;
    case 0x3C: { u16 de = DE16; scv_wr(de, c->a); SET_DE(de + 1u); cyc = 7; break; }
    case 0x3D: { u16 hl = HL16; scv_wr(hl, c->a); SET_HL(hl + 1u); cyc = 7; break; }
    case 0x3E: { u16 de = DE16; scv_wr(de, c->a); SET_DE(de - 1u); cyc = 7; break; }
    case 0x3F: { u16 hl = HL16; scv_wr(hl, c->a); SET_HL(hl - 1u); cyc = 7; break; }

    case 0x41: case 0x42: case 0x43: { /* INR A/B/C */
        u8 *r = (op == 0x41u) ? &c->a : (op == 0x42u) ? &c->b : &c->c;
        u8 ocy = c->psw & F_CY, tmp = (u8)(*r + 1u);
        u78_zhc_add(c, tmp, *r, 0); *r = tmp;
        if (c->psw & F_CY) c->psw |= F_SK;
        c->psw = (u8)((c->psw & ~F_CY) | ocy);
        break;
    }
    case 0x44: { /* CALL w */
        u8 lo = scv_rd(c->pc++), hi = scv_rd(c->pc++);
        scv_wr(--c->sp, (u8)(c->pc >> 8));
        scv_wr(--c->sp, (u8)c->pc);
        c->pc = (u16)(((u16)hi << 8) | lo);
        cyc = 16; break;
    }
    case 0x45: { u16 wa = WA16(scv_rd(c->pc++)); u8 imm = scv_rd(c->pc++), m = scv_rd(wa); u78_alu_op(c, 0x09, &m, imm); cyc = 13; break; }
    case 0x46: u78_alu_op(c, 0x08, &c->a, scv_rd(c->pc++)); cyc = 7; break;
    case 0x47: u78_alu_op(c, 0x09, &c->a, scv_rd(c->pc++)); cyc = 7; break;
    case 0x48: { /* PRE_48 (uPD7801 layout!) */
        u8 op2 = scv_rd(c->pc++);
        cyc = 8;
        switch (op2) {
        case 0x00: if (c->irr & IRR_F0) c->psw |= F_SK; break;
        case 0x01: if (c->irr & IRR_FT0) c->psw |= F_SK; c->irr &= (u8)~IRR_FT0; break;
        case 0x02: if (c->irr & IRR_F1) c->psw |= F_SK; c->irr &= (u8)~IRR_F1; break;
        case 0x03: if (c->irr & IRR_F2) c->psw |= F_SK; c->irr &= (u8)~IRR_F2; break;
        case 0x04: if (c->irr & IRR_FST) c->psw |= F_SK; c->irr &= (u8)~IRR_FST; break;
        case 0x0A: if (c->psw & F_CY) c->psw |= F_SK; break;
        case 0x0C: if (c->psw & F_Z)  c->psw |= F_SK; break;
        case 0x0E: scv_wr(--c->sp, c->v); scv_wr(--c->sp, c->a); cyc = 17; break;
        case 0x0F: c->a = scv_rd(c->sp++); c->v = scv_rd(c->sp++); cyc = 15; break;
        case 0x10: if (!(c->irr & IRR_F0)) c->psw |= F_SK; break;
        case 0x11: if (!(c->irr & IRR_FT0)) c->psw |= F_SK; c->irr &= (u8)~IRR_FT0; break;
        case 0x12: if (!(c->irr & IRR_F1)) c->psw |= F_SK; c->irr &= (u8)~IRR_F1; break;
        case 0x13: if (!(c->irr & IRR_F2)) c->psw |= F_SK; c->irr &= (u8)~IRR_F2; break;
        case 0x14: if (!(c->irr & IRR_FST)) c->psw |= F_SK; c->irr &= (u8)~IRR_FST; break;
        case 0x1A: if (!(c->psw & F_CY)) c->psw |= F_SK; break;
        case 0x1C: if (!(c->psw & F_Z))  c->psw |= F_SK; break;
        case 0x1E: scv_wr(--c->sp, c->b); scv_wr(--c->sp, c->c); cyc = 17; break;
        case 0x1F: c->c = scv_rd(c->sp++); c->b = scv_rd(c->sp++); cyc = 15; break;
        case 0x20: c->iff_pend = 1; break; /* EI */
        case 0x24: c->iff = c->iff_pend = 0; break; /* DI */
        case 0x2A: c->psw &= (u8)~F_CY; break; /* CLC */
        case 0x2B: c->psw |= F_CY; break;      /* STC */
        case 0x2E: scv_wr(--c->sp, c->d); scv_wr(--c->sp, c->e); cyc = 17; break;
        case 0x2F: c->e = scv_rd(c->sp++); c->d = scv_rd(c->sp++); cyc = 15; break;
        case 0x30: { u8 cy = c->psw & F_CY; c->psw = (u8)((c->psw & ~F_CY) | ((c->a >> 7) & 1u)); c->a = (u8)((c->a << 1) | cy); break; } /* RLL A */
        case 0x31: { u8 cy = (u8)((c->psw & F_CY) << 7); c->psw = (u8)((c->psw & ~F_CY) | (c->a & 1u)); c->a = (u8)((c->a >> 1) | cy); break; } /* RLR A */
        case 0x32: { u8 cy = c->psw & F_CY; c->psw = (u8)((c->psw & ~F_CY) | ((c->c >> 7) & 1u)); c->c = (u8)((c->c << 1) | cy); break; } /* RLL C */
        case 0x33: { u8 cy = (u8)((c->psw & F_CY) << 7); c->psw = (u8)((c->psw & ~F_CY) | (c->c & 1u)); c->c = (u8)((c->c >> 1) | cy); break; } /* RLR C */
        case 0x34: c->psw = (u8)((c->psw & ~F_CY) | ((c->a >> 7) & 1u)); c->a <<= 1; break; /* SLL A */
        case 0x35: c->psw = (u8)((c->psw & ~F_CY) | (c->a & 1u)); c->a >>= 1; break;        /* SLR A */
        case 0x36: c->psw = (u8)((c->psw & ~F_CY) | ((c->c >> 7) & 1u)); c->c <<= 1; break; /* SLL C */
        case 0x37: c->psw = (u8)((c->psw & ~F_CY) | (c->c & 1u)); c->c >>= 1; break;        /* SLR C */
        case 0x38: { u8 m = scv_rd(HL16); scv_wr(HL16, (u8)((m << 4) | (c->a & 0x0Fu))); c->a = (u8)((c->a & 0xF0u) | (m >> 4)); cyc = 17; break; } /* RLD */
        case 0x39: { u8 m = scv_rd(HL16); scv_wr(HL16, (u8)((c->a << 4) | (m >> 4))); c->a = (u8)((c->a & 0xF0u) | (m & 0x0Fu)); cyc = 17; break; } /* RRD */
        case 0x3E: scv_wr(--c->sp, c->h); scv_wr(--c->sp, c->l); cyc = 17; break;
        case 0x3F: c->l = scv_rd(c->sp++); c->h = scv_rd(c->sp++); cyc = 15; break;
        default: break;
        }
        break;
    }
    case 0x49: scv_wr(BC16, scv_rd(c->pc++)); cyc = 10; break;
    case 0x4A: scv_wr(DE16, scv_rd(c->pc++)); cyc = 10; break;
    case 0x4B: scv_wr(HL16, scv_rd(c->pc++)); cyc = 10; break;
    case 0x4C: { /* PRE_4C */
        u8 op2 = scv_rd(c->pc++);
        cyc = 10;
        if (op2 < 0xC0u) c->a = 0xFFu;
        else if (op2 == 0xC0u) c->a = u78_rp(0);
        else if (op2 == 0xC1u) c->a = u78_rp(1);
        else if (op2 == 0xC2u) c->a = u78_rp(2);
        else if (op2 == 0xC3u) c->a = c->mkl;
        else if (op2 == 0xC8u) c->a = c->s_reg;
        break;
    }
    case 0x4D: { /* PRE_4D */
        u8 op2 = scv_rd(c->pc++);
        cyc = 10;
        if (op2 == 0xC0u) u78_wp(0, c->a);
        else if (op2 == 0xC1u) u78_wp(1, c->a);
        else if (op2 == 0xC2u) u78_wp(2, c->a);
        else if (op2 == 0xC3u) c->mkl = c->a;
        else if (op2 == 0xC4u) c->mb = c->a;
        else if (op2 == 0xC5u) { c->mc = c->a; u78_wp(2, c->pc_out); }
        else if (op2 == 0xC6u) c->tm0 = c->a;
        else if (op2 == 0xC7u) c->tm1 = c->a;
        else if (op2 == 0xC8u) c->s_reg = c->a;
        break;
    }
    case 0x4E: case 0x4F: { /* JRE */
        u8 offs = scv_rd(c->pc++);
        if (op & 1u) c->pc = (u16)(c->pc - (256u - offs));
        else         c->pc = (u16)(c->pc + offs);
        cyc = 17; break;
    }

    case 0x51: case 0x52: case 0x53: { /* DCR A/B/C */
        u8 *r = (op == 0x51u) ? &c->a : (op == 0x52u) ? &c->b : &c->c;
        u8 ocy = c->psw & F_CY, tmp = (u8)(*r - 1u);
        u78_zhc_sub(c, tmp, *r, 0); *r = tmp;
        if (c->psw & F_CY) c->psw |= F_SK;
        c->psw = (u8)((c->psw & ~F_CY) | ocy);
        break;
    }
    case 0x54: { u8 lo = scv_rd(c->pc++), hi = scv_rd(c->pc++); c->pc = (u16)(((u16)hi << 8) | lo); cyc = 10; break; } /* JMP w */
    case 0x55: { u16 wa = WA16(scv_rd(c->pc++)); u8 imm = scv_rd(c->pc++), m = scv_rd(wa); u78_alu_op(c, 0x0B, &m, imm); cyc = 13; break; }
    case 0x56: u78_alu_op(c, 0x0A, &c->a, scv_rd(c->pc++)); cyc = 7; break;
    case 0x57: u78_alu_op(c, 0x0B, &c->a, scv_rd(c->pc++)); cyc = 7; break;
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F: { /* BIT b, wa */
        u16 wa = WA16(scv_rd(c->pc++));
        if (scv_rd(wa) & (1u << (op & 7u))) c->psw |= F_SK;
        cyc = 10; break;
    }

    case 0x60: { /* PRE_60: reg-reg ALU */
        u8 op2 = scv_rd(c->pc++);
        cyc = 8;
        u8 kind = (u8)((op2 >> 3) & 0x0Fu);
        if (op2 < 0x80u)
            u78_alu_op(c, kind, u78_reg8(c, op2 & 7u), c->a);
        else
            u78_alu_op(c, kind, &c->a, *u78_reg8(c, op2 & 7u));
        break;
    }
    case 0x61: { /* DAA */
        u8 l = c->a & 0x0Fu, h = c->a >> 4, adj = 0, ocy = c->psw & F_CY;
        if (!(c->psw & F_HC)) {
            if (l < 10u) { if (!(h < 10u && !ocy)) adj = 0x60u; }
            else         { adj = (h < 9u && !ocy) ? 0x06u : 0x66u; }
        } else if (l < 3u) {
            adj = (h < 10u && !ocy) ? 0x06u : 0x66u;
        }
        u8 tmp = (u8)(c->a + adj);
        u78_zhc_add(c, tmp, c->a, ocy);
        c->psw |= ocy;
        c->a = tmp;
        break;
    }
    case 0x62: { /* RETI */
        u8 lo = scv_rd(c->sp++), hi = scv_rd(c->sp++);
        c->psw = scv_rd(c->sp++);
        c->pc = (u16)(((u16)hi << 8) | lo);
        cyc = 15; break;
    }
    case 0x63: { /* CALB (1 byte!) */
        scv_wr(--c->sp, (u8)(c->pc >> 8));
        scv_wr(--c->sp, (u8)c->pc);
        c->pc = BC16;
        cyc = 13; break;
    }
    case 0x64: { /* PRE_64: reg/port immediate ALU */
        u8 op2 = scv_rd(c->pc++);
        u8 kind = (u8)((op2 >> 3) & 0x0Fu);
        if (op2 < 0x80u) {
            u8 imm = scv_rd(c->pc++);
            u78_alu_op(c, kind, u78_reg8(c, op2 & 7u), imm);
            cyc = 11;
        } else if ((op2 & 4u) == 0u && kind != 0u) {
            u8 imm = scv_rd(c->pc++);
            int psel = op2 & 3;
            u8 val = (psel < 3) ? u78_rp(psel) : c->mkl;
            u8 before = val;
            u78_alu_op(c, kind, &val, imm);
            /* Write back only for modifying ops (ANA,XRA,ORA,ADDNC,SUBNB,ADD,ADC,SUB,SBB) */
            if (kind != 0x05u && kind != 0x07u && kind != 0x09u && kind != 0x0Bu && kind != 0x0Du && kind != 0x0Fu) {
                if (psel < 3) u78_wp(psel, val);
                else c->mkl = val;
            } else {
                (void)before;
            }
            cyc = 17;
        } else {
            cyc = 8;
        }
        break;
    }
    case 0x65: { u16 wa = WA16(scv_rd(c->pc++)); u8 imm = scv_rd(c->pc++), m = scv_rd(wa); u78_alu_op(c, 0x0D, &m, imm); cyc = 13; break; }
    case 0x66: u78_alu_op(c, 0x0C, &c->a, scv_rd(c->pc++)); cyc = 7; break;
    case 0x67: u78_alu_op(c, 0x0D, &c->a, scv_rd(c->pc++)); cyc = 7; break;
    case 0x68: c->v = scv_rd(c->pc++); cyc = 7; break;
    case 0x69: if (c->psw & F_L1) c->pc++; else { c->a = scv_rd(c->pc++); c->psw |= F_L1; } cyc = 7; break;
    case 0x6A: c->b = scv_rd(c->pc++); cyc = 7; break;
    case 0x6B: c->c = scv_rd(c->pc++); cyc = 7; break;
    case 0x6C: c->d = scv_rd(c->pc++); cyc = 7; break;
    case 0x6D: c->e = scv_rd(c->pc++); cyc = 7; break;
    case 0x6E: c->h = scv_rd(c->pc++); cyc = 7; break;
    case 0x6F: if (c->psw & F_L0) c->pc++; else { c->l = scv_rd(c->pc++); c->psw |= F_L0; } cyc = 7; break;

    case 0x70: { /* PRE_70: 16-bit mem & indirect-X ALU */
        u8 op2 = scv_rd(c->pc++);
        if (op2 < 0x80u) {
            if ((op2 & 0xCFu) == 0x0Eu) {
                u8 lo = scv_rd(c->pc++), hi = scv_rd(c->pc++);
                u16 addr = (u16)(((u16)hi << 8) | lo);
                u16 val = (op2 == 0x0Eu) ? c->sp : (op2 == 0x1Eu) ? BC16 : (op2 == 0x2Eu) ? DE16 : HL16;
                scv_wr(addr, (u8)val);
                scv_wr((u16)(addr + 1u), (u8)(val >> 8));
                cyc = 20;
            } else if ((op2 & 0xCFu) == 0x0Fu) {
                u8 lo = scv_rd(c->pc++), hi = scv_rd(c->pc++);
                u16 addr = (u16)(((u16)hi << 8) | lo);
                u16 val = (u16)(scv_rd(addr) | ((u16)scv_rd((u16)(addr + 1u)) << 8));
                if (op2 == 0x0Fu) c->sp = val;
                else if (op2 == 0x1Fu) SET_BC(val);
                else if (op2 == 0x2Fu) SET_DE(val);
                else SET_HL(val);
                cyc = 20;
            } else if ((op2 & 0xF8u) == 0x68u) {
                u8 lo = scv_rd(c->pc++), hi = scv_rd(c->pc++);
                *u78_reg8(c, op2 & 7u) = scv_rd((u16)(((u16)hi << 8) | lo));
                cyc = 17;
            } else if ((op2 & 0xF8u) == 0x78u) {
                u8 lo = scv_rd(c->pc++), hi = scv_rd(c->pc++);
                scv_wr((u16)(((u16)hi << 8) | lo), *u78_reg8(c, op2 & 7u));
                cyc = 17;
            } else {
                cyc = 8;
            }
        } else {
            u8 mode = op2 & 7u;
            u8 kind = (u8)((op2 >> 3) & 0x0Fu);
            if (mode != 0u && kind != 0u) {
                u16 ea = 0;
                switch (mode) {
                case 1: ea = BC16; break;
                case 2: ea = DE16; break;
                case 3: ea = HL16; break;
                case 4: ea = DE16; SET_DE(ea + 1u); break;
                case 5: ea = HL16; SET_HL(ea + 1u); break;
                case 6: ea = DE16; SET_DE(ea - 1u); break;
                case 7: ea = HL16; SET_HL(ea - 1u); break;
                }
                u78_alu_op(c, kind, &c->a, scv_rd(ea));
                cyc = 11;
            } else {
                cyc = 8;
            }
        }
        break;
    }
    case 0x71: { u16 wa = WA16(scv_rd(c->pc++)); scv_wr(wa, scv_rd(c->pc++)); cyc = 13; break; }
    case 0x72: { /* SOFTI */
        scv_wr(--c->sp, c->psw);
        scv_wr(--c->sp, (u8)(c->pc >> 8));
        scv_wr(--c->sp, (u8)c->pc);
        c->pc = 0x0060u;
        cyc = 19; break;
    }
    case 0x73: c->pc = BC16; break; /* JB */
    case 0x74: { /* PRE_74: working-reg ALU */
        u8 op2 = scv_rd(c->pc++);
        u8 kind = (u8)((op2 >> 3) & 0x0Fu);
        if (op2 >= 0x80u && (op2 & 7u) == 0u && kind != 0u) {
            u16 wa = WA16(scv_rd(c->pc++));
            u78_alu_op(c, kind, &c->a, scv_rd(wa));
            cyc = 14;
        } else {
            cyc = 8;
        }
        break;
    }
    case 0x75: { u16 wa = WA16(scv_rd(c->pc++)); u8 imm = scv_rd(c->pc++), m = scv_rd(wa); u78_alu_op(c, 0x0F, &m, imm); cyc = 13; break; }
    case 0x76: u78_alu_op(c, 0x0E, &c->a, scv_rd(c->pc++)); cyc = 7; break;
    case 0x77: u78_alu_op(c, 0x0F, &c->a, scv_rd(c->pc++)); cyc = 7; break;
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F: { /* CALF */
        u8 lo = scv_rd(c->pc++);
        u16 dst = (u16)(((u16)(0x08u + (op & 7u)) << 8) | lo);
        scv_wr(--c->sp, (u8)(c->pc >> 8));
        scv_wr(--c->sp, (u8)c->pc);
        c->pc = dst;
        cyc = 16; break;
    }

    default:
        if (op >= 0x80u && op < 0xC0u) { /* CALT $80..$FE (7801 64-entry table!) */
            u16 vec = (u16)(0x0080u + 2u * (op & 0x3Fu));
            scv_wr(--c->sp, (u8)(c->pc >> 8));
            scv_wr(--c->sp, (u8)c->pc);
            u8 lo = scv_rd(vec), hi = scv_rd((u16)(vec + 1u));
            c->pc = (u16)(((u16)hi << 8) | lo);
            cyc = 19;
        } else if (op >= 0xC0u) { /* JR -32..+31 */
            s8 rel = (s8)(op << 2) >> 2;
            c->pc = (u16)((s32)c->pc + rel);
            cyc = 13;
        }
        break;
    }

    #undef BC16
    #undef DE16
    #undef HL16
    #undef SET_BC
    #undef SET_DE
    #undef SET_HL
    #undef WA16

    u78_timers(cyc);
    u78_check_irq();
    c->iff = c->iff_pend;
    return cyc;
}

/* ========================================================================
 * EPOCH TV-1 VIDEO PROCESSOR (TEXT / SEMIGRAPHICS / BLOCK + 128 SPRITES)
 * ======================================================================== */

static const u8 scv_spr_lut0[16] = {0, 15, 12, 13, 10, 11,  8, 9, 6, 7,  4,  5, 2, 3,  1,  1};
static const u8 scv_spr_lut1[16] = {0,  1,  8, 11,  2,  3, 10, 9, 4, 5, 12, 13, 6, 7, 14, 15};

static inline void scv_plot(int x, int y, u8 col)
{
    if ((unsigned)x < 256u && (unsigned)y < 256u)
        WS->canvas[y][x] = col;
}

static void scv_draw_spr_part(u8 x, u8 y, u8 pat, u8 col)
{
    if (x >= 4u) {
        int px = (int)x - 4;
        int py = (int)y + 2;
        if ((unsigned)py < 256u) {
            if (pat & 8u) scv_plot(px, py, col);
            if ((pat & 4u) && px < 255) scv_plot(px + 1, py, col);
            if ((pat & 2u) && px < 254) scv_plot(px + 2, py, col);
            if ((pat & 1u) && px < 253) scv_plot(px + 3, py, col);
        }
    }
}

static void scv_draw_sprite_16(u8 x, u8 y, u8 tile_idx, u8 col, int left, int right, int top, int bottom, u8 clip_y)
{
    y = (u8)(y + clip_y * 2u);
    for (int j = (int)clip_y * 4; j < 32; j += 4, y = (u8)(y + 2u)) {
        if ((top && j < 16) || (bottom && j >= 16)) {
            u32 base = (u32)(tile_idx & 0x7Fu) * 32u + (u32)j;
            if (left) {
                u8 p0 = WS->vram[base + 0];
                u8 p1 = WS->vram[base + 1];
                scv_draw_spr_part(x,            y,            p0 >> 4,   col);
                scv_draw_spr_part((u8)(x + 4u), y,            p1 >> 4,   col);
                scv_draw_spr_part(x,            (u8)(y + 1u), p0 & 0x0Fu, col);
                scv_draw_spr_part((u8)(x + 4u), (u8)(y + 1u), p1 & 0x0Fu, col);
            }
            if (right) {
                u8 p2 = WS->vram[base + 2];
                u8 p3 = WS->vram[base + 3];
                scv_draw_spr_part((u8)(x +  8u), y,            p2 >> 4,   col);
                scv_draw_spr_part((u8)(x + 12u), y,            p3 >> 4,   col);
                scv_draw_spr_part((u8)(x +  8u), (u8)(y + 1u), p2 & 0x0Fu, col);
                scv_draw_spr_part((u8)(x + 12u), (u8)(y + 1u), p3 & 0x0Fu, col);
            }
        }
    }
}

static void scv_render_screen(u16 *pic)
{
    if (!pic)
        return;

    u8 r0 = WS->vram[0x1400];
    u8 r1 = WS->vram[0x1401];
    u8 r2 = WS->vram[0x1402];
    u8 r3 = WS->vram[0x1403];

    u8 fg    = r3 >> 4;
    u8 bg    = r3 & 0x0Fu;
    u8 gr_fg = r1 >> 4;
    u8 gr_bg = r1 & 0x0Fu;
    int clip_x = (r2 & 0x0Fu) * 2;
    int clip_y = r2 >> 4;

    for (int y = 0; y < 256; y++)
        for (int x = 0; x < 256; x++)
            WS->canvas[y][x] = gr_bg;

    for (int y = 0; y < 16; y++) {
        int text_y = (y < clip_y) ? !(r0 & 0x80u) : !!(r0 & 0x80u);
        for (int x = 0; x < 32; x++) {
            int text_x = (x < clip_x) ? !(r0 & 0x40u) : !!(r0 & 0x40u);
            u8 d = WS->vram[0x1000 + y * 32 + x];
            int bx = x * 8, by = y * 16;

            if (text_x && text_y) {
                const u8 *ch = &WS->charrom[(d & 0x7Fu) * 8];
                for (int i = 0; i < 8; i++) {
                    u8 row = ch[i];
                    for (int j = 0; j < 8; j++)
                        WS->canvas[by + i][bx + j] = (row & (0x80u >> j)) ? fg : bg;
                }
                for (int i = 8; i < 16; i++)
                    for (int j = 0; j < 8; j++)
                        WS->canvas[by + i][bx + j] = bg;
            } else {
                u8 gmode = r0 & 0x03u;
                if (gmode == 0x01u) {
                    /* Semi-graphics 2x4 blocks (4x4 px each) */
                    for (int sub = 0; sub < 8; sub++) {
                        if (d & (0x80u >> sub)) {
                            int sx = bx + (sub & 1) * 4;
                            int sy = by + (sub >> 1) * 4;
                            for (int i = 0; i < 4; i++)
                                for (int j = 0; j < 4; j++)
                                    WS->canvas[sy + i][sx + j] = gr_fg;
                        }
                    }
                } else if (gmode == 0x03u) {
                    /* Block graphics 1x2 blocks (8x8 px each) */
                    u8 c_top = d >> 4, c_bot = d & 0x0Fu;
                    if (c_top) {
                        for (int i = 0; i < 8; i++)
                            for (int j = 0; j < 8; j++)
                                WS->canvas[by + i][bx + j] = c_top;
                    }
                    if (c_bot) {
                        for (int i = 8; i < 16; i++)
                            for (int j = 0; j < 8; j++)
                                WS->canvas[by + i][bx + j] = c_bot;
                    }
                }
            }
        }
    }

    /* Sprites (128 or 64) */
    if (r0 & 0x10u) {
        int nspr = (r0 & 0x04u) ? 64 : 128;
        for (int i = 0; i < nspr; i++) {
            const u8 *oam = &WS->vram[0x1200 + i * 4];
            u8 spr_y = oam[0] & 0xFEu;
            u8 y_32  = oam[0] & 1u;
            u8 clip  = oam[1] >> 4;
            u8 col   = oam[1] & 0x0Fu;
            u8 spr_x = oam[2] & 0xFEu;
            u8 x_32  = oam[2] & 1u;
            u8 tidx  = oam[3] & 0x7Fu;
            int half = (oam[3] >> 7) & 1;

            if (!col || !spr_y)
                continue;

            int left = 1, right = 1, top = 1, bottom = 1;
            if (half) {
                if (tidx & 0x40u) {
                    if (y_32) { spr_y = (u8)(spr_y - 8u); top = 0; y_32 = 0; }
                    else      { bottom = 0; }
                }
                if (x_32) { spr_x = (u8)(spr_x - 8u); left = 0; x_32 = 0; }
                else      { right = 0; }
            }

            if ((r0 & 0x20u) && (i & 0x20)) {
                scv_draw_sprite_16(spr_x, spr_y, tidx, col, left, right, top, bottom, clip);
                if (x_32 || y_32) {
                    u8 col2 = (i & 0x10) ? scv_spr_lut1[col] : scv_spr_lut0[col];
                    u8 tidx2 = (u8)(tidx ^ (8u * x_32 + y_32));
                    scv_draw_sprite_16(spr_x, spr_y, tidx2, col2, left, right, top, bottom, clip);
                }
            } else {
                scv_draw_sprite_16(spr_x, spr_y, tidx, col, left, right, top, bottom, clip);
                if (x_32)
                    scv_draw_sprite_16((u8)(spr_x + 16u), spr_y, (u8)(tidx | 8u), col, 1, 1, top, bottom, clip);
                if (y_32) {
                    u8 clip2 = (clip & 8u) ? (clip & 7u) : 0u;
                    scv_draw_sprite_16(spr_x, (u8)(spr_y + 16u), (u8)(tidx | 1u), col, left, right, 1, 1, clip2);
                    if (x_32)
                        scv_draw_sprite_16((u8)(spr_x + 16u), (u8)(spr_y + 16u), (u8)(tidx | 9u), col, 1, 1, 1, 1, clip2);
                }
            }
        }
    }

    /* Output 192x222 active TV-1 viewport (x = 24..215, y = 23..244) */
    for (int y = 0; y < SCV_H; y++) {
        u16 *dst = pic + y * SCV_W;
        const u8 *src = &WS->canvas[23 + y][24];
        for (int x = 0; x < SCV_W; x++)
            dst[x] = WS->pal[src[x] & 15u];
    }
}

/* ========================================================================
 * PUBLIC LIFECYCLE & FRAME EXECUTION
 * ======================================================================== */

static void scv_init_palette(void)
{
    static const u8 rgb[16][3] = {
        {   0,   0, 155 }, /*  0 Medium Blue */
        {   0,   0,   0 }, /*  1 Black       */
        {   0,   0, 255 }, /*  2 Blue        */
        { 161,   0, 255 }, /*  3 Purple      */
        {   0, 255,   0 }, /*  4 Green       */
        { 160, 255, 157 }, /*  5 Light Green */
        {   0, 255, 255 }, /*  6 Cyan        */
        {   0, 161,   0 }, /*  7 Dark Green  */
        { 255,   0,   0 }, /*  8 Red         */
        { 255, 161,   0 }, /*  9 Orange      */
        { 255,   0, 255 }, /* 10 Magenta     */
        { 255, 160, 159 }, /* 11 Pink        */
        { 255, 255,   0 }, /* 12 Yellow      */
        { 163, 160,   0 }, /* 13 Olive       */
        { 161, 160, 157 }, /* 14 Grey        */
        { 255, 255, 255 }  /* 15 White       */
    };
    for (int i = 0; i < 16; i++)
        WS->pal[i] = bgr555(rgb[i][0], rgb[i][1], rgb[i][2]);
}

const char *scv_load(const u8 *bios, u32 bios_size, const u8 *rom, u32 rom_size)
{
    if (!rom || rom_size < 512u)
        return "too small for an Epoch Super Cassette Vision cartridge";

    /* Strip optional 32-byte EmuSCV ".cart" header if present */
    if (rom_size > 544u && rom[0] == 'E' && rom[1] == 'm' && rom[2] == 'u' &&
        rom[3] == 'S' && rom[4] == 'C' && rom[5] == 'V') {
        rom += 32;
        rom_size -= 32u;
    }
    if (rom_size > sizeof(WS->rom))
        rom_size = sizeof(WS->rom);

    u32 keep_rate = WS->sample_rate;
    for (u32 i = 0; i < sizeof(*WS); i++)
        ((u8 *)WS)[i] = 0;
    WS->sample_rate = keep_rate;

    scv_init_palette();
    scv_init_charrom();

    if (bios && bios_size >= 0x1000u) {
        for (int i = 0; i < 0x1000; i++)
            WS->bios[i] = bios[i];
        if (bios_size >= 0x1400u) {
            for (int i = 0; i < 0x0400; i++)
                WS->charrom[i] = bios[0x1000 + i];
        }
        WS->ext_bios = 1;
    } else {
        scv_build_bios();
        WS->ext_bios = 0;
    }

    WS->rom_size = rom_size;
    for (u32 i = 0; i < rom_size; i++)
        WS->rom[i] = rom[i];

    scv_reset();

    char *p = WS->info;
    const char *tag = WS->ext_bios ? "Epoch SCV (Ext BIOS), ROM " : "Epoch SCV, ROM ";
    while (*tag) *p++ = *tag++;
    u32 kb = (rom_size + 1023u) >> 10;
    char d[12]; int n = 0;
    do { d[n++] = (char)('0' + (kb % 10u)); kb /= 10u; } while (kb);
    while (n--) *p++ = d[n];
    *p++ = ' '; *p++ = 'K'; *p++ = 'B'; *p = 0;
    return 0;
}

void scv_reset(void)
{
    for (u32 i = 0; i < sizeof(WS->cpu); i++)
        ((u8 *)&WS->cpu)[i] = 0;
    for (u32 i = 0; i < sizeof(WS->vram); i++)
        WS->vram[i] = 0;
    for (u32 i = 0; i < sizeof(WS->iram); i++)
        WS->iram[i] = 0;

    WS->cpu.mb = 0xFFu;
    WS->cpu.mc = 0xFFu;
    WS->cpu.mkl = 0xFFu;
    WS->porta = 0xFFu;
    WS->portc = 0x00u;
    WS->snd_lfsr = 0x55u;
    WS->snd_len = 0;
    WS->snd_mode = 0;
    WS->snd_vol = 0;
}

void scv_frame(u16 pad, u16 *picture)
{
    WS->pad = pad;
    WS->audio_count = 0;
    if (WS->key_ttl) {
        if (!--WS->key_ttl)
            WS->key_mask = 0;
    }

    /* 4.000 MHz XTAL / 59.92 Hz = 66,755 cycles per frame across 262 scanlines (~255 cyc/line) */
    int cyc_debt = 0;
    for (int sl = 0; sl < 262; sl++) {
        if (sl == 0)
            u78_set_int2(0);
        else if (sl == 240)
            u78_set_int2(1);

        int budget = (sl & 1) ? 255 : 254;
        while (cyc_debt < budget)
            cyc_debt += u78_step();
        cyc_debt -= budget;

        scv_snd_line();
    }

    scv_render_screen(picture);
}

const char *scv_info(void) { return WS->info; }

int scv_jammed(void)
{
    return WS->cpu.halt && !WS->cpu.iff && (WS->cpu.mkl & 0x1Fu) == 0x1Fu;
}

void scv_keyboard(const u8 *usages, int n)
{
    if (!WS->key_ttl)
        WS->key_mask = 0;
    for (int i = 0; i < n; i++) {
        u8 u = usages[i];
        if (u == 0x27u) WS->key_mask |= (1u << 0);
        else if (u >= 0x1Eu && u <= 0x26u) WS->key_mask |= (u16)(1u << (u - 0x1Du));
        else if (u == 0x2Au || u == 0x06u) WS->key_mask |= (1u << 10); /* Backspace/C -> Cl */
        else if (u == 0x28u)               WS->key_mask |= (1u << 11); /* Enter -> En */
        else if (u == 0x13u)               WS->key_mask |= (1u << 12); /* P -> Pause */
    }
}

void scv_typed(char c)
{
    if (c >= '0' && c <= '9') { WS->key_mask |= (u16)(1u << (c - '0')); WS->key_ttl = 6; }
    else if (c == 'c' || c == 'C') { WS->key_mask |= (1u << 10); WS->key_ttl = 6; }
    else if (c == '\r' || c == '\n') { WS->key_mask |= (1u << 11); WS->key_ttl = 6; }
    else if (c == 'p' || c == 'P') { WS->key_mask |= (1u << 12); WS->key_ttl = 6; }
}

void scv_audio_rate(u32 hz)
{
    WS->sample_rate = hz;
    WS->snd_frac = 0;
    WS->audio_count = 0;
    scv_snd_recalc();
}

int scv_audio(s16 *out, int max)
{
    int n = WS->audio_count < max ? WS->audio_count : max;
    for (int i = 0; i < n; i++)
        out[i] = WS->audio_ring[i];
    WS->audio_count = 0;
    return n;
}

u32 scv_save_sram(u8 *dst, u32 max)
{
    if (!WS->has_sram || !dst)
        return 0;
    u32 sz = (WS->rom_size > 0x10000u) ? 0x0F80u : 0x1F80u;
    if (sz > max) sz = max;
    for (u32 i = 0; i < sz; i++)
        dst[i] = WS->sram[i];
    return sz;
}

void scv_load_sram(const u8 *src, u32 len)
{
    if (!src || !len)
        return;
    if (len > sizeof(WS->sram))
        len = sizeof(WS->sram);
    for (u32 i = 0; i < len; i++)
        WS->sram[i] = src[i];
    WS->has_sram = 1;
}

u8 *scv_save_ram(u32 *size, int *battery)
{
    *size = (WS->rom_size > 0x10000u) ? 0x1000u : 0x2000u;
    *battery = 1;
    return WS->sram;
}

int scv_save_changed(void)
{
    int was = WS->sram_dirty;
    WS->sram_dirty = 0;
    return was;
}
