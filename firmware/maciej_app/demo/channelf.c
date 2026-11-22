/* Fairchild Channel F / Video Entertainment System (1976) emulator for ALi M3801/S3811.
 *
 * Hardware modelled:
 *   - Fairchild F8 CPU (3850 ALU/64B scratchpad + 3851 PSUs + 3853 SMI, 1.7897725 MHz / 2 -> 14,914 ticks/frame)
 *   - MK4027 128x64 2-bpp dynamic VRAM (visible 102x58 at X=4..105, Y=4..61) with per-row col 125/126 4-palette select
 *   - Port 0/1/4/5 quasi-bidirectional I/O + Front Panel (TIME/MODE/HOLD/START) + Right/Left 8-way push/pull/twist sticks
 *   - F2102 1024x1-bit cartridge SRAM (ports $20/$21/$24/$25) + 2114 Schach/homebrew RAM ($2000..$FFFF) + 256 KB multicart
 *   - Clean-room HLE PSU ($0000 init, $008F delay, $00D0 clrscrn, $0107 pushk, $011E popk, $0679/$067C 5x8 drawchar)
 *     or optional external sl31253.bin ($0000..$03FF) + sl31254.bin ($0400..$07FF)
 *   - 48 kHz mono 16-bit 3-tone (1000 Hz, 500 Hz, 120+240 Hz) RC-decay + PWM audio synthesis
 *
 * All large buffers reside in KSEG0(EMU_RAM_PHYS) -> zero .bss footprint.
 */
#pragma GCC optimize("O2")

#include "channelf.h"

#ifndef CHF_HOST
#include "hw.h"
#endif

typedef signed char s8;

#define TICKS_PER_FRAME 14914
#define CHF_RING_MASK   4095u           /* 4096 mono 16-bit samples */

/* Controller button bits passed in `pad` (matching nes.h / play.c) */
#define BTN_A      0x01u
#define BTN_B      0x02u
#define BTN_SELECT 0x04u
#define BTN_START  0x08u
#define BTN_UP     0x10u
#define BTN_DOWN   0x20u
#define BTN_LEFT   0x40u
#define BTN_RIGHT  0x80u
#define BTN_L      0x100u
#define BTN_R      0x200u

/* F8 W status flags */
#define W_SIGN  0x01u                   /* 1 = positive/zero (bit7 == 0), 0 = negative (bit7 == 1) */
#define W_CARRY 0x02u
#define W_ZERO  0x04u
#define W_OVF   0x08u
#define W_INT   0x10u

struct chf_ws {
    u8 mem[0x10000];                    /* 64 KB address space (PSU1/PSU2 + RAM $2000..$FFFF) */
    u8 vram[128 * 64];                  /* 2-bit pixels (0..3) per cell */
    u8 f2102[1024];                     /* 1024 x 1-bit Maze SRAM */
    s16 snd_ring[CHF_RING_MASK + 1u];
    u8 cart[262144];                    /* up to 256 KB Sean Riddle multicart */
};

#ifdef CHF_HOST
static struct chf_ws chf_host_ws;
#define WS (&chf_host_ws)
#else
#define WS ((struct chf_ws *)KSEG0(EMU_RAM_PHYS))
#endif

static u32 cart_size;
static u16 ram_start;
static u8 is_multicart;
static u8 mc_bank;
static u8 psu1_hle, psu2_hle;

/* F8 CPU state */
static u8 R[64];
static u8 A, ISAR, W;
static u16 PC0, PC1, DC0, DC1;
static s32 tick_debt;

/* HLE state */
static u16 hle_delay;

/* I/O, video & F2102 state */
static u8 ports[64];
static u8 p0_prev;
static u8 vx, vy, vcolor;
static u8 ctrl_enabled;
static u8 joy_panel, joy_right, joy_left;
static u8 f5_prev;
static u16 f2102_state, f2102_addr;

/* Audio state */
static u32 snd_hz;
static u32 snd_tick_acc;
static u32 snd_rd, snd_wr;
static u8 snd_tone;
static u32 snd_phase1, snd_phase2;
static s32 snd_amp;

static char info_str[96];

static void bzero_u8(void *dst, u32 n)
{
    u8 *p = (u8 *)dst;
    for (u32 i = 0; i < n; i++)
        p[i] = 0;
}

static void bcopy_u8(void *dst, const void *src, u32 n)
{
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    for (u32 i = 0; i < n; i++)
        d[i] = s[i];
}

static void put_s(char **p, const char *end, const char *s)
{
    while (*s && *p < end)
        *(*p)++ = *s++;
    **p = 0;
}

static void put_u(char **p, const char *end, u32 v)
{
    char d[12];
    int n = 0;
    do d[n++] = (char)('0' + (v % 10u)); while (v /= 10u);
    while (n && *p < end)
        *(*p)++ = d[--n];
    **p = 0;
}

/* play.c 15-bit colour format: 0bbbbbgggggrrrrr */
#define RGB15(r, g, b) ((u16)((((r) >> 3) & 31) | ((((g) >> 3) & 31) << 5) | ((((b) >> 3) & 31) << 10)))

/* Channel F 8 hardware colours (matched to MAME channelf_v.cpp & FreeChaF) */
enum {
    COL_BLACK   = 0,
    COL_WHITE   = 1,
    COL_BLUE    = 2,
    COL_GREEN   = 3,
    COL_RED     = 4,
    COL_LTGRAY  = 5,
    COL_LTGREEN = 6,
    COL_LTBLUE  = 7
};

static const u16 hw_colors[8] = {
    RGB15(0x10, 0x10, 0x10),            /* 0: BLACK */
    RGB15(0xFD, 0xFD, 0xFD),            /* 1: WHITE */
    RGB15(0x53, 0x31, 0xFF),            /* 2: BLUE */
    RGB15(0x5D, 0xCC, 0x02),            /* 3: GREEN */
    RGB15(0xF3, 0x3F, 0x4B),            /* 4: RED */
    RGB15(0xE0, 0xE0, 0xE0),            /* 5: LTGRAY */
    RGB15(0xA6, 0xFF, 0x91),            /* 6: LTGREEN */
    RGB15(0xD0, 0xCE, 0xFF)             /* 7: LTBLUE */
};

/* Per-row palette table [pal 0..3][pixel 0..3] */
static const u8 row_pal[4][4] = {
    { COL_BLACK,   COL_WHITE, COL_WHITE, COL_WHITE },
    { COL_LTBLUE,  COL_BLUE,  COL_RED,   COL_GREEN },
    { COL_LTGRAY,  COL_BLUE,  COL_RED,   COL_GREEN },
    { COL_LTGREEN, COL_BLUE,  COL_RED,   COL_GREEN }
};

/* Clean-room 5x7/5x8 system glyph table (bits 7..3 = 5 horizontal pixels) for HLE $0679 drawchar_sys */
static const u8 hle_font[32][8] = {
    {0x70,0x88,0x98,0xA8,0xC8,0x88,0x70,0x00}, /* 00 '0' */
    {0x20,0x60,0x20,0x20,0x20,0x20,0x70,0x00}, /* 01 '1' */
    {0x70,0x88,0x08,0x30,0x40,0x80,0xF8,0x00}, /* 02 '2' */
    {0x70,0x88,0x08,0x30,0x08,0x88,0x70,0x00}, /* 03 '3' */
    {0x10,0x30,0x50,0x90,0xF8,0x10,0x10,0x00}, /* 04 '4' */
    {0xF8,0x80,0xF0,0x08,0x08,0x88,0x70,0x00}, /* 05 '5' / 'S' */
    {0x30,0x40,0x80,0xF0,0x88,0x88,0x70,0x00}, /* 06 '6' */
    {0xF8,0x08,0x10,0x20,0x40,0x40,0x40,0x00}, /* 07 '7' */
    {0x70,0x88,0x88,0x70,0x88,0x88,0x70,0x00}, /* 08 '8' */
    {0x70,0x88,0x88,0x78,0x08,0x10,0x60,0x00}, /* 09 '9' */
    {0x00,0x20,0x00,0x00,0x00,0x20,0x00,0x00}, /* 0A ':' */
    {0x70,0x88,0x08,0x30,0x20,0x00,0x20,0x00}, /* 0B '?' */
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, /* 0C ' ' */
    {0x70,0x88,0x80,0xB8,0x88,0x88,0x70,0x00}, /* 0D 'G' */
    {0x88,0xD8,0xA8,0xA8,0x88,0x88,0x88,0x00}, /* 0E 'M' */
    {0xF8,0x20,0x20,0x20,0x20,0x20,0x20,0x00}, /* 0F 'T' */
    {0x70,0x88,0x80,0x70,0x08,0x88,0x70,0x00}, /* 10 'S' */
    {0x70,0x88,0x88,0xF8,0x88,0x88,0x88,0x00}, /* 11 'A' */
    {0xF0,0x88,0x88,0xF0,0x88,0x88,0xF0,0x00}, /* 12 'B' */
    {0x70,0x88,0x80,0x80,0x80,0x88,0x70,0x00}, /* 13 'C' */
    {0xF0,0x88,0x88,0x88,0x88,0x88,0xF0,0x00}, /* 14 'D' */
    {0xF8,0x80,0x80,0xF0,0x80,0x80,0xF8,0x00}, /* 15 'E' */
    {0xF8,0x80,0x80,0xF0,0x80,0x80,0x80,0x00}, /* 16 'F' */
    {0x88,0x88,0x88,0xF8,0x88,0x88,0x88,0x00}, /* 17 'H' */
    {0x70,0x20,0x20,0x20,0x20,0x20,0x70,0x00}, /* 18 'I' */
    {0x80,0x80,0x80,0x80,0x80,0x80,0xF8,0x00}, /* 19 'L' */
    {0x88,0xC8,0xA8,0x98,0x88,0x88,0x88,0x00}, /* 1A 'N' */
    {0xF0,0x88,0x88,0xF0,0x80,0x80,0x80,0x00}, /* 1B 'P' */
    {0xF0,0x88,0x88,0xF0,0xA0,0x90,0x88,0x00}, /* 1C 'R' */
    {0x88,0x88,0x88,0x88,0x88,0x88,0x70,0x00}, /* 1D 'U' */
    {0x88,0x88,0x88,0x88,0x50,0x50,0x20,0x00}, /* 1E 'V' */
    {0x88,0x88,0x50,0x20,0x50,0x88,0x88,0x00}, /* 1F 'X' */
};

static inline u8 mem_rd8(u16 addr)
{
    if (addr >= 0x0800u) {
        if (is_multicart && addr < 0x2000u) {
            u32 mapped = (u32)(addr - 0x0800u) | (((u32)mc_bank & 0x1Fu) << 13) | (((u32)mc_bank & 0x20u) << 7);
            if (mapped < cart_size)
                return WS->cart[mapped];
        } else if ((u32)(addr - 0x0800u) < cart_size) {
            return WS->cart[addr - 0x0800u];
        }
    }
    return WS->mem[addr];
}

static inline u16 mem_rd16(u16 addr)
{
    return ((u16)mem_rd8(addr) << 8) | (u16)mem_rd8((u16)(addr + 1u));
}

static inline void mem_wr8(u16 addr, u8 val)
{
    if (is_multicart && addr == 0x3000u) {
        mc_bank = val;
        return;
    }
    if (addr < ram_start)
        return;
    WS->mem[addr] = val;
}

static void f2102_out(u8 port, u8 val)
{
    if (port == 0x20u || port == 0x24u) {
        f2102_state = (f2102_state & 0x00FFu) | ((u16)val << 8);
        f2102_addr = (f2102_addr & 0x3F3u) | (u16)(val & 0x04u) | (u16)((val & 0x02u) << 2);
        if ((val & 1u) == 0u)
            f2102_state = (f2102_state & 0x7FFFu) | ((u16)(WS->f2102[f2102_addr & 0x3FFu] & 1u) << 15);
        else
            WS->f2102[f2102_addr & 0x3FFu] = (val >> 3) & 1u;
    } else if (port == 0x21u || port == 0x25u) {
        f2102_state = (f2102_state & 0xFF00u) | (u16)val;
        f2102_addr = (f2102_addr & 0x00Cu)
                   | (u16)((val & 0xE0u) << 2)
                   | (u16)((val & 0x0Eu) << 3)
                   | (u16)((val & 0x10u) >> 3)
                   | (u16)(val & 0x01u);
    }
    ports[0x24] = (u8)(f2102_state >> 8);
    ports[0x25] = (u8)(f2102_state & 0xFFu);
}

static u8 port_in(u8 port)
{
    port &= 0x3Fu;
    u8 ext = 0;
    if (port == 0u)
        ext = (joy_panel ^ 0x0Fu) & 0x0Fu;
    else if (ctrl_enabled && port == 1u)
        ext = joy_right ^ 0xFFu;
    else if (ctrl_enabled && port == 4u)
        ext = joy_left ^ 0xFFu;
    return ports[port] | ext;
}

static void port_out(u8 port, u8 val)
{
    port &= 0x3Fu;
    ports[port] = val;

    switch (port) {
    case 0:
        if (!(p0_prev & 0x20u) && (val & 0x20u))
            WS->vram[((u32)vy << 7) | vx] = vcolor;
        p0_prev = val;
        ctrl_enabled = (val & 0x40u) == 0u;
        break;
    case 1:
        vcolor = ((val ^ 0xFFu) >> 6) & 3u;
        break;
    case 4:
        vx = (val ^ 0xFFu) & 0x7Fu;
        break;
    case 5: {
        vy = (val ^ 0xFFu) & 0x3Fu;
        u8 t = (val >> 6) & 3u;
        if (t != snd_tone) {
            snd_tone = t;
            snd_amp = 9000;
            if (t == 0u) {
                snd_phase1 = 0;
                snd_phase2 = 0;
            }
        }
        break;
    }
    case 0x20:
    case 0x21:
    case 0x24:
    case 0x25:
        f2102_out(port, val);
        break;
    }
}

/* F8 ALU helpers */
static inline void set_0z0s(u8 v)
{
    W &= W_INT;
    if (v == 0u)
        W |= W_ZERO;
    if (!(v & 0x80u))
        W |= W_SIGN;
}

static inline u8 add8_cin(u8 a, u8 b, u8 cin)
{
    u16 res = (u16)a + (u16)b + (u16)cin;
    u8 r8 = (u8)res;
    W &= W_INT;
    if (!(r8 & 0x80u))
        W |= W_SIGN;
    if (r8 == 0u)
        W |= W_ZERO;
    if (res >= 0x100u)
        W |= W_CARRY;
    if (((a ^ b) & 0x80u) == 0u && ((a ^ r8) & 0x80u) != 0u)
        W |= W_OVF;
    return r8;
}

static inline u8 add_bcd(u8 a, u8 b)
{
    u16 sum = (u16)a + (u16)b;
    int ci = ((a & 0x0Fu) + (b & 0x0Fu)) > 0x0Fu;
    int cu = sum >= 0x100u;
    (void)add8_cin(a, b, 0);
    if (!ci)
        sum = (sum & 0xF0u) | ((sum + 0x0Au) & 0x0Fu);
    if (!cu)
        sum = sum + 0xA0u;
    return (u8)sum;
}

static inline u8 *isar_ptr(u8 low4)
{
    if (low4 < 12u)
        return &R[low4];
    if (low4 == 15u)
        return 0;
    u8 *p = &R[ISAR & 0x3Fu];
    if (low4 == 13u)
        ISAR = (ISAR & 0x38u) | ((ISAR + 1u) & 0x07u);
    else if (low4 == 14u)
        ISAR = (ISAR & 0x38u) | ((ISAR - 1u) & 0x07u);
    return p;
}

static inline s32 branch_disp(u8 n)
{
    return (n & 0x80u) ? -(s32)(((n - 1u) ^ 0xFFu) + 1u) : (s32)n - 1;
}

/* Clean-room HLE PSU subroutines ($0000..$07FF when external PSU ROMs are absent) */
static void hle_clrscrn(u8 r3)
{
    u8 c125 = 0, c126 = 0;
    if (r3 & 0x80u) {
        u8 c = (r3 >> 6) & 3u;
        u8 pat = r3 & 7u;
        if (pat == 3u) {
            c125 = c;
            c126 = 0;
        } else if (pat == 6u) {
            c125 = 0;
            c126 = c;
        } else {
            c125 = c;
            c126 = c;
        }
    }
    for (int row = 0; row < 64; row++) {
        u8 *line = &WS->vram[row << 7];
        bzero_u8(line, 125u);
        line[125] = c125;
        line[126] = c126;
        line[127] = 0;
    }
}

static void hle_drawchar_glyph(const u8 *glyph, u8 color, u8 x0, u8 y0)
{
    for (int r = 0; r < 8; r++) {
        u8 bits = glyph[r];
        u8 y = (y0 + (u8)r) & 0x3Fu;
        for (int c = 0; c < 5; c++) {
            u8 x = (x0 + (u8)c) & 0x7Fu;
            WS->vram[((u32)y << 7) | x] = (bits & (0x80u >> c)) ? color : 0u;
        }
    }
}

static int f8_hle_step(void)
{
    if (hle_delay) {
        hle_delay--;
        return 2563;
    }
    switch (PC0) {
    case 0x0000:                        /* Power-on reset -> jump into cartridge at $0802 */
        bzero_u8(R, sizeof(R));
        A = 0x55u;
        DC0 = 0x0801u;
        PC0 = 0x0802u;
        R[0x3B] = 0x28u;
        ISAR = 0x3Bu;
        return 1459;

    case 0x008F: {                      /* BIOS_DELAY: R5 = frame/tick delay count */
        u8 d = R[5];
        R[5] = 0;
        R[6] = 0;
        A = 0xFFu;
        PC0 = PC1;
        hle_delay = d;
        return 16;
    }

    case 0x00D0:                        /* BIOS_CLEAR_SCREEN: R3 = palette/colour descriptor */
        hle_clrscrn(R[3]);
        PC0 = PC1;
        return TICKS_PER_FRAME;

    case 0x0107: {                      /* BIOS_PUSH_K: push K (R12,R13) to stack at R[59] */
        u8 sp = R[0x3B] & 0x3Fu;
        R[sp] = R[12];
        R[(sp + 1u) & 0x3Fu] = R[13];
        R[0x3B] = (sp + 2u) & 0x3Fu;
        A = ISAR;
        R[7] = ISAR;
        PC0 = PC1;
        return 48;
    }

    case 0x011E: {                      /* BIOS_POP_K: pop stack at R[59] into K (R12,R13) */
        u8 sp = R[0x3B] & 0x3Fu;
        R[13] = R[(sp - 1u) & 0x3Fu];
        R[12] = R[(sp - 2u) & 0x3Fu];
        R[0x3B] = (sp - 2u) & 0x3Fu;
        A = ISAR;
        R[7] = ISAR;
        PC0 = PC1;
        return 50;
    }

    case 0x0679: {                      /* BIOS_DRAW_CHARACTER (internal font): R0=col|ch, R1=x, R2=y */
        u8 ch = R[0] & 0x1Fu;
        u8 col = (R[0] >> 6) & 3u;
        hle_drawchar_glyph(hle_font[ch], col, R[1], R[2]);
        R[1] = (u8)(R[1] + 6u);
        PC0 = PC1;
        return 900;
    }

    case 0x067C: {                      /* drawchar from DC0 + (R0 & $3F) * 5 */
        u8 glyph[8];
        u16 base = (u16)(DC0 + (u16)(R[0] & 0x3Fu) * 5u);
        u32 bitpos = 0;
        for (int r = 0; r < 8; r++) {
            u8 rowb = 0;
            for (int c = 0; c < 5; c++, bitpos++) {
                u8 b = mem_rd8((u16)(base + (bitpos >> 3)));
                if (b & (0x80u >> (bitpos & 7u)))
                    rowb |= (u8)(0x80u >> c);
            }
            glyph[r] = rowb;
        }
        hle_drawchar_glyph(glyph, (R[0] >> 6) & 3u, R[1], R[2]);
        R[1] = (u8)(R[1] + 6u);
        PC0 = PC1;
        return 900;
    }

    default:
        PC0 = PC1;
        return 32;
    }
}

static int f8_step(void)
{
    if (hle_delay || (PC0 < 0x0400u && psu1_hle) || (PC0 >= 0x0400u && PC0 < 0x0800u && psu2_hle))
        return f8_hle_step();

    u8 op = mem_rd8(PC0++);

    switch (op) {
    case 0x00: case 0x01: case 0x02: case 0x03:
        A = R[12u + op];
        return 2;
    case 0x04: case 0x05: case 0x06: case 0x07:
        R[8u + op] = A;
        return 2;
    case 0x08:                          /* LR K, P */
        R[12] = (u8)(PC1 >> 8);
        R[13] = (u8)PC1;
        return 8;
    case 0x09:                          /* LR P, K */
        PC1 = ((u16)R[12] << 8) | R[13];
        return 8;
    case 0x0A:                          /* LR A, IS */
        A = ISAR;
        return 2;
    case 0x0B:                          /* LR IS, A */
        ISAR = A & 0x3Fu;
        return 2;
    case 0x0C:                          /* PK */
        PC1 = PC0;
        PC0 = ((u16)R[12] << 8) | R[13];
        return 5;
    case 0x0D:                          /* LR P0, Q */
        PC0 = ((u16)R[14] << 8) | R[15];
        return 8;
    case 0x0E:                          /* LR Q, DC */
        R[14] = (u8)(DC0 >> 8);
        R[15] = (u8)DC0;
        return 8;
    case 0x0F:                          /* LR DC, Q */
        DC0 = ((u16)R[14] << 8) | R[15];
        return 8;
    case 0x10:                          /* LR DC, H */
        DC0 = ((u16)R[10] << 8) | R[11];
        return 8;
    case 0x11:                          /* LR H, DC */
        R[10] = (u8)(DC0 >> 8);
        R[11] = (u8)DC0;
        return 8;
    case 0x12:                          /* SR 1 */
        A >>= 1;
        set_0z0s(A);
        return 2;
    case 0x13:                          /* SL 1 */
        A = (u8)(A << 1);
        set_0z0s(A);
        return 2;
    case 0x14:                          /* SR 4 */
        A >>= 4;
        set_0z0s(A);
        return 2;
    case 0x15:                          /* SL 4 */
        A = (u8)(A << 4);
        set_0z0s(A);
        return 2;
    case 0x16:                          /* LM */
        A = mem_rd8(DC0++);
        return 5;
    case 0x17:                          /* ST */
        mem_wr8(DC0++, A);
        return 5;
    case 0x18:                          /* COM */
        A ^= 0xFFu;
        set_0z0s(A);
        return 2;
    case 0x19:                          /* LNK */
        A = add8_cin(A, 0, (W & W_CARRY) ? 1u : 0u);
        return 2;
    case 0x1A:                          /* DI */
        W &= (u8)~W_INT;
        return 2;
    case 0x1B:                          /* EI */
        W |= W_INT;
        return 2;
    case 0x1C:                          /* POP */
        PC0 = PC1;
        return 4;
    case 0x1D:                          /* LR W, J */
        W = R[9] & 0x1Fu;
        return 2;
    case 0x1E:                          /* LR J, W */
        R[9] = W & 0x1Fu;
        return 4;
    case 0x1F:                          /* INC */
        A = add8_cin(A, 1u, 0);
        return 2;
    case 0x20:                          /* LI n */
        A = mem_rd8(PC0++);
        return 5;
    case 0x21:                          /* NI n */
        A &= mem_rd8(PC0++);
        set_0z0s(A);
        return 5;
    case 0x22:                          /* OI n */
        A |= mem_rd8(PC0++);
        set_0z0s(A);
        return 5;
    case 0x23:                          /* XI n */
        A ^= mem_rd8(PC0++);
        set_0z0s(A);
        return 5;
    case 0x24:                          /* AI n */
        A = add8_cin(A, mem_rd8(PC0++), 0);
        return 5;
    case 0x25: {                        /* CI n: flags of n - A */
        u8 n = mem_rd8(PC0++);
        (void)add8_cin(n, A ^ 0xFFu, 1u);
        return 5;
    }
    case 0x26:                          /* IN n */
        A = port_in(mem_rd8(PC0++));
        set_0z0s(A);
        return 8;
    case 0x27:                          /* OUT n */
        port_out(mem_rd8(PC0++), A);
        return 8;
    case 0x28: {                        /* PI mn */
        A = mem_rd8(PC0++);
        PC1 = (u16)(PC0 + 1u);
        u8 lo = mem_rd8(PC0);
        PC0 = ((u16)A << 8) | lo;
        return 13;
    }
    case 0x29: {                        /* JMP mn */
        A = mem_rd8(PC0++);
        u8 lo = mem_rd8(PC0);
        PC0 = ((u16)A << 8) | lo;
        return 11;
    }
    case 0x2A:                          /* DCI mn */
        DC0 = mem_rd16(PC0);
        PC0 = (u16)(PC0 + 2u);
        return 12;
    case 0x2B: case 0x2D: case 0x2E: case 0x2F:
        return 2;
    case 0x2C: {                        /* XDC */
        u16 t = DC0;
        DC0 = DC1;
        DC1 = t;
        return 4;
    }

    case 0x30: case 0x31: case 0x32: case 0x33:
    case 0x34: case 0x35: case 0x36: case 0x37:
    case 0x38: case 0x39: case 0x3A: case 0x3B:
    case 0x3C: case 0x3D: case 0x3E: case 0x3F: {
        u8 *p = isar_ptr(op & 0x0Fu);
        if (p)
            *p = add8_cin(*p, 0xFFu, 0);
        return 3;
    }

    case 0x40: case 0x41: case 0x42: case 0x43:
    case 0x44: case 0x45: case 0x46: case 0x47:
    case 0x48: case 0x49: case 0x4A: case 0x4B:
    case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
        u8 *p = isar_ptr(op & 0x0Fu);
        if (p)
            A = *p;
        return 2;
    }

    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57:
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
        u8 *p = isar_ptr(op & 0x0Fu);
        if (p)
            *p = A;
        return 2;
    }

    case 0x60: case 0x61: case 0x62: case 0x63:
    case 0x64: case 0x65: case 0x66: case 0x67:
        ISAR = (ISAR & 0x07u) | (u8)((op & 0x07u) << 3);
        return 2;

    case 0x68: case 0x69: case 0x6A: case 0x6B:
    case 0x6C: case 0x6D: case 0x6E: case 0x6F:
        ISAR = (ISAR & 0x38u) | (op & 0x07u);
        return 2;

    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        A = op & 0x0Fu;
        return 2;

    case 0x80: case 0x81: case 0x82: case 0x83:
    case 0x84: case 0x85: case 0x86: case 0x87: {
        u8 n = mem_rd8(PC0++);
        if ((W & (op & 0x07u)) != 0u) {
            PC0 = (u16)((s32)PC0 + branch_disp(n));
            return 7;
        }
        return 6;
    }

    case 0x88:                          /* AM */
        A = add8_cin(A, mem_rd8(DC0++), 0);
        return 5;
    case 0x89:                          /* AMD */
        A = add_bcd(A, mem_rd8(DC0++));
        return 5;
    case 0x8A:                          /* NM */
        A &= mem_rd8(DC0++);
        set_0z0s(A);
        return 5;
    case 0x8B:                          /* OM */
        A |= mem_rd8(DC0++);
        set_0z0s(A);
        return 5;
    case 0x8C:                          /* XM */
        A ^= mem_rd8(DC0++);
        set_0z0s(A);
        return 5;
    case 0x8D:                          /* CM */
        (void)add8_cin(mem_rd8(DC0++), A ^ 0xFFu, 1u);
        return 5;
    case 0x8E:                          /* ADC */
        DC0 = (u16)((s32)DC0 + (s32)(s8)A);
        return 5;
    case 0x8F: {                        /* BR7 n */
        u8 n = mem_rd8(PC0++);
        if ((ISAR & 0x07u) != 7u) {
            PC0 = (u16)((s32)PC0 + branch_disp(n));
            return 7;
        }
        return 6;
    }

    case 0x90: case 0x91: case 0x92: case 0x93:
    case 0x94: case 0x95: case 0x96: case 0x97:
    case 0x98: case 0x99: case 0x9A: case 0x9B:
    case 0x9C: case 0x9D: case 0x9E: case 0x9F: {
        u8 n = mem_rd8(PC0++);
        if ((W & (op & 0x0Fu)) == 0u) {
            PC0 = (u16)((s32)PC0 + branch_disp(n));
            return 7;
        }
        return 6;
    }

    case 0xA0: case 0xA1: case 0xA2: case 0xA3:
    case 0xA4: case 0xA5: case 0xA6: case 0xA7:
    case 0xA8: case 0xA9: case 0xAA: case 0xAB:
    case 0xAC: case 0xAD: case 0xAE: case 0xAF:
        A = port_in(op & 0x0Fu);
        set_0z0s(A);
        return (op & 0x0Fu) > 1u ? 8 : 4;

    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        port_out(op & 0x0Fu, A);
        return (op & 0x0Fu) > 1u ? 8 : 4;

    case 0xC0: case 0xC1: case 0xC2: case 0xC3:
    case 0xC4: case 0xC5: case 0xC6: case 0xC7:
    case 0xC8: case 0xC9: case 0xCA: case 0xCB:
    case 0xCC: case 0xCD: case 0xCE: case 0xCF: {
        u8 *p = isar_ptr(op & 0x0Fu);
        if (p)
            A = add8_cin(A, *p, 0);
        return 2;
    }

    case 0xD0: case 0xD1: case 0xD2: case 0xD3:
    case 0xD4: case 0xD5: case 0xD6: case 0xD7:
    case 0xD8: case 0xD9: case 0xDA: case 0xDB:
    case 0xDC: case 0xDD: case 0xDE: case 0xDF: {
        u8 *p = isar_ptr(op & 0x0Fu);
        if (p)
            A = add_bcd(A, *p);
        return 4;
    }

    case 0xE0: case 0xE1: case 0xE2: case 0xE3:
    case 0xE4: case 0xE5: case 0xE6: case 0xE7:
    case 0xE8: case 0xE9: case 0xEA: case 0xEB:
    case 0xEC: case 0xED: case 0xEE: case 0xEF: {
        u8 *p = isar_ptr(op & 0x0Fu);
        if (p) {
            A ^= *p;
            set_0z0s(A);
        }
        return 2;
    }

    default: {                          /* 0xF0..0xFF: NS r */
        u8 *p = isar_ptr(op & 0x0Fu);
        if (p) {
            A &= *p;
            set_0z0s(A);
        }
        return 2;
    }
    }
}

/* Step 48 kHz mono 3-tone audio by `dt` F8 ticks (894,886 ticks/sec = 14914 * 60) */
static void audio_step(int dt)
{
    if (!snd_hz || dt <= 0)
        return;

    const u32 cpu_rate = (u32)TICKS_PER_FRAME * 60u;
    snd_tick_acc += (u32)dt * snd_hz;

    while (snd_tick_acc >= cpu_rate) {
        snd_tick_acc -= cpu_rate;
        s32 s = 0;

        if (snd_tone != 0u && snd_amp > 0) {
            u32 f1 = (snd_tone == 1u) ? 1000u : (snd_tone == 2u) ? 500u : 120u;
            snd_phase1 += (f1 << 16) / snd_hz;
            s = (snd_phase1 & 0x8000u) ? snd_amp : -snd_amp;
            if (snd_tone == 3u) {
                snd_phase2 += (240u << 16) / snd_hz;
                s = (s + ((snd_phase2 & 0x8000u) ? snd_amp : -snd_amp)) >> 1;
            }
            snd_amp = (snd_amp * 32702) >> 15;
        }

        if ((snd_wr - snd_rd) <= CHF_RING_MASK)
            WS->snd_ring[snd_wr++ & CHF_RING_MASK] = (s16)s;
    }
}

static void map_inputs(u16 pad, const u8 *hid, int hid_n)
{
    u8 p = 0, r = 0, l = 0;

    if (pad & BTN_RIGHT)  r |= 0x01u;
    if (pad & BTN_LEFT)   r |= 0x02u;
    if (pad & BTN_DOWN)   r |= 0x04u;
    if (pad & BTN_UP)     r |= 0x08u;
    if (pad & BTN_L)      r |= 0x10u;   /* CCW */
    if (pad & BTN_R)      r |= 0x20u;   /* CW */
    if (pad & BTN_B)      r |= 0x40u;   /* Pull */
    if (pad & BTN_A)      r |= 0x80u;   /* Push / Fire */

    if (pad & BTN_SELECT) p |= 0x02u;   /* MODE */
    if (pad & BTN_START)  p |= 0x08u;   /* START */

    u8 f5_now = 0;
    for (int i = 0; i < hid_n; i++) {
        switch (hid[i]) {
        case 0x1E: case 0x3A: p |= 0x01u; break; /* 1 / F1 -> TIME */
        case 0x1F: case 0x3B: p |= 0x02u; break; /* 2 / F2 -> MODE */
        case 0x20: case 0x3C: p |= 0x04u; break; /* 3 / F3 -> HOLD */
        case 0x21: case 0x3D: case 0x28: p |= 0x08u; break; /* 4 / F4 / Enter -> START */
        case 0x3E: f5_now = 1; break;            /* F5 -> Console RESET */
        case 0x14: case 0x2F: r |= 0x10u; break; /* Q / [ -> Rotate CCW */
        case 0x08: case 0x30: r |= 0x20u; break; /* E / ] -> Rotate CW */
        case 0x06:            r |= 0x40u; break; /* C -> Pull */
        case 0x2C:            r |= 0x80u; break; /* Space -> Push / Fire */
        case 0x0F:            l |= 0x01u; break; /* L -> P2 Right */
        case 0x0D:            l |= 0x02u; break; /* J -> P2 Left */
        case 0x0E:            l |= 0x04u; break; /* K -> P2 Down */
        case 0x0C:            l |= 0x08u; break; /* I -> P2 Up */
        case 0x18:            l |= 0x40u; break; /* U -> P2 Pull */
        case 0x12:            l |= 0x80u; break; /* O -> P2 Push */
        }
    }
    if (f5_now && !f5_prev)
        channelf_reset();
    f5_prev = f5_now;

    joy_panel = p;
    joy_right = r;
    joy_left = l;
}

void channelf_reset(void)
{
    bzero_u8(WS->mem + ram_start, 0x10000u - ram_start);
    bzero_u8(WS->vram, sizeof(WS->vram));
    bzero_u8(WS->f2102, sizeof(WS->f2102));
    bzero_u8(R, sizeof(R));
    bzero_u8(ports, sizeof(ports));

    A = 0;
    ISAR = 0;
    W = 0;
    PC0 = 0;
    PC1 = 0;
    DC0 = 0;
    DC1 = 0;
    tick_debt = 0;
    hle_delay = 0;
    mc_bank = 0;

    p0_prev = 0;
    vx = 0;
    vy = 0;
    vcolor = 2;
    ctrl_enabled = 0;
    f2102_state = 0;
    f2102_addr = 0;

    snd_tone = 0;
    snd_phase1 = 0;
    snd_phase2 = 0;
    snd_amp = 9000;
    snd_tick_acc = 0;
    snd_rd = snd_wr = 0;
}

const char *channelf_load(const u8 *psu1, const u8 *psu2, u8 *image, u32 size)
{
    if (!image || size < 64u)
        return "Channel F cartridge image is too small";
    if (size > sizeof(WS->cart))
        return "Channel F cartridge image exceeds 256 KB";

    bzero_u8(WS, sizeof(*WS));

    if (psu1) {
        bcopy_u8(WS->mem + 0x0000u, psu1, 1024u);
        psu1_hle = 0;
    } else {
        psu1_hle = 1;
    }
    if (psu2) {
        bcopy_u8(WS->mem + 0x0400u, psu2, 1024u);
        psu2_hle = 0;
    } else {
        psu2_hle = 1;
    }

    bcopy_u8(WS->cart, image, size);
    cart_size = size;

    if (size == 262144u) {
        is_multicart = 1;
        ram_start = 0x2000u;
    } else {
        is_multicart = 0;
        u32 end = 0x0800u + size;
        if (end > 0xFFFFu)
            end = 0xFFFFu;
        ram_start = (u16)end;
    }

    if (psu1_hle && WS->cart[0] != 0x55u)
        return "not a valid Channel F cartridge ($55 header missing)";

    f5_prev = 0;
    snd_hz = 0;
    channelf_reset();

    char *p = info_str, *end = info_str + sizeof(info_str) - 1;
    put_s(&p, end, (psu1_hle || psu2_hle) ? "Fairchild Channel F (HLE PSU" : "Fairchild Channel F (SL31253+SL31254");
    if (is_multicart)
        put_s(&p, end, ", 256 KB multicart), ");
    else
        put_s(&p, end, "), ");
    put_u(&p, end, size);
    put_s(&p, end, " bytes");
    return 0;
}

void channelf_frame(u16 pad, const u8 *hid, int hid_n, u16 *picture)
{
    map_inputs(pad, hid, hid_n);

    s32 ticks = tick_debt;
    while (ticks < TICKS_PER_FRAME) {
        int dt = f8_step();
        ticks += dt;
        audio_step(dt);
    }
    tick_debt = ticks - TICKS_PER_FRAME;

    if (picture) {
        for (int y = 0; y < CHF_H; y++) {
            const u8 *line = &WS->vram[(y + 4) << 7];
            u8 pal = (u8)(((line[125] & 2u) >> 1) | (line[126] & 2u));
            const u8 *cmap = row_pal[pal];
            u16 *dst = &picture[y * CHF_W];
            for (int x = 0; x < CHF_W; x++)
                dst[x] = hw_colors[cmap[line[x + 4] & 3u]];
        }
    }
}

const char *channelf_info(void)
{
    return info_str;
}

u8 *channelf_save_ram(u32 *size, int *battery)
{
    (void)size;
    (void)battery;
    return 0;
}

int channelf_save_changed(void)
{
    return 0;
}

int channelf_jammed(void)
{
    return 0;
}

void channelf_audio_rate(u32 hz)
{
    snd_hz = (hz >= 8000u && hz <= 192000u) ? hz : 0;
    snd_tick_acc = 0;
    snd_rd = snd_wr = 0;
}

int channelf_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && snd_rd != snd_wr)
        out[n++] = WS->snd_ring[snd_rd++ & CHF_RING_MASK];
    return n;
}
