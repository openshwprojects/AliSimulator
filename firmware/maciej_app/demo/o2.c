/* Magnavox Odyssey2 / Philips Videopac G7000 (.o2) emulator:
   - Intel 8048 MCU (1.79 MHz / 357,954 machine cycles/s, 64 B internal RAM, 8-level stack, timer/counter, P1/P2)
   - Intel 8244 NTSC VDC (160 x 240 BGR555: 4 sprites, 12 single chars, 4 quad groups, 9x9 grid, hardware collisions)
   - 24-bit shift-register + LFSR noise audio synthesized at 48 kHz mono
   - Cartridge banking: 2 KB, 4 KB, 8 KB, 12 KB, and 16 KB ROMs (P10..P11)
   - Clean-room built-in 1 KB G7000/O2 BIOS ($000..$3FF) + optional external o2rom.bin (1024 B) */
#pragma GCC optimize("O2")

#ifdef __mips__
#include "hw.h"
#endif
#include "o2.h"

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

#define O2_MAX_ROM   16384u
#define O2_AUD_MAX   2048
#define O2_LINES     262
#define O2_CYC_LINE  23       /* ~22.75 machine cycles/line -> 6026 cycles/frame */
#define O2_HBL_START 18       /* active: 0..17, HBlank: 18..22 (T1=1) */
#define O2_VBL_LINE  242      /* VBlank: 242..261 (20 lines * 23 = 460 cyc -> NTSC R1 ~ 57) */

struct o2_work {
    u8 cart[O2_MAX_ROM];
    u8 bios[1024];
    u8 ext_bios[1024];
    u8 iram[64];
    u8 eram[128];
    u8 vdc[256];
    u8 layer[O2_W];
    s16 aud_buf[O2_AUD_MAX];
};

#ifdef __mips__
#define W (*((struct o2_work *)KSEG0(EMU_RAM_PHYS)))
#else
static struct o2_work o2_host_work;
#define W o2_host_work
#endif

static struct {
    u32 cart_size;
    u8 has_ext_bios;
    u8 jammed;

    /* Intel 8048 state */
    u16 pc;
    u16 stack[8];
    u8 a, psw, f1, dbf;
    u8 p1, p2, bus;
    u8 t, tf, t_mode;         /* t_mode: 0=stopped, 1=timer (/32), 2=counter (T1 falling) */
    u8 t_prescale;
    u8 ie, tcnti, in_irq;
    u8 ext_irq, tim_irq;
    u8 t1_prev;

    /* VDC state */
    u8 vdc_stat;
    u8 coll_mask;
    u8 coll_stat;
    int scan_y;
    int line_cyc;

    /* Input & BIOS selectgame state */
    u16 pad;
    u8 ext_key;               /* 0x00..0x2F or 0xFF */
    u8 boot_wait;             /* frames remaining on SELECT GAME if no key pressed */
    u8 lfsr_rnd;
    u8 clock_x;

    /* Audio state */
    u32 sample_rate;
    u32 aud_count;
    u32 aud_frac;
    u32 shift_reg;
    u32 shift_bits;
    u32 shift_frac;
    u16 noise_lfsr;

    char info_str[96];
} S;

/* BGR555 helper: bits 0..4=R, 5..9=G, 10..14=B */
#define BGR555(r, g, b) ((u16)((((u32)(b) & 0xF8u) << 7) | (((u32)(g) & 0xF8u) << 2) | (((u32)(r) & 0xF8u) >> 3)))

/* Grid/Background color order (bits 2..0 = R, G, B -> 0=blk,1=blu,2=grn,3=cyn,4=red,5=vio,6=yel,7=wht) */
static const u16 grid_pal[16] = {
    BGR555(  0,   0,   0), BGR555( 24,  48, 176), BGR555( 24, 152,  32), BGR555( 24, 160, 176),
    BGR555(176,  28,  28), BGR555(168,  32, 168), BGR555(176, 152,  24), BGR555(184, 184, 184),
    BGR555( 84,  84,  84), BGR555( 80, 128, 255), BGR555( 80, 236,  88), BGR555( 80, 240, 255),
    BGR555(255,  80,  80), BGR555(248,  88, 248), BGR555(255, 236,  72), BGR555(255, 255, 255)
};

/* Character/Sprite color order (bits 2..0 = B, G, R -> 0=blk,1=red,2=grn,3=yel,4=blu,5=vio,6=cyn,7=wht) */
static const u16 fore_pal[8] = {
    BGR555( 56,  56,  56), BGR555(255,  76,  76), BGR555( 76, 236,  84), BGR555(255, 236,  72),
    BGR555( 76, 124, 255), BGR555(248,  88, 248), BGR555( 76, 240, 255), BGR555(255, 255, 255)
};

/* Clean-room Intel 8244 64-character x 8-row internal ROM (row 7 is always 0x00 end-of-character marker;
   MSB = leftmost pixel, LSB = rightmost pixel). Indices 0x00..0x2F match the 48-key Odyssey2 matrix! */
static const u8 o2_charset[64][8] = {
    /* 0x00..0x07: 0 1 2 3 4 5 6 7 */
    {0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00}, {0x18,0x38,0x18,0x18,0x18,0x18,0x7E,0x00},
    {0x7C,0xC6,0x06,0x3C,0x60,0xC0,0xFE,0x00}, {0x7C,0xC6,0x06,0x3C,0x06,0xC6,0x7C,0x00},
    {0xCC,0xCC,0xCC,0xFE,0x0C,0x0C,0x0C,0x00}, {0xFE,0xC0,0xFC,0x06,0x06,0xC6,0x7C,0x00},
    {0x7C,0xC0,0xFC,0xC6,0xC6,0xC6,0x7C,0x00}, {0xFE,0x06,0x0C,0x18,0x30,0x30,0x30,0x00},
    /* 0x08..0x0F: 8 9 : $ (space) ? L P */
    {0x7C,0xC6,0xC6,0x7C,0xC6,0xC6,0x7C,0x00}, {0x7C,0xC6,0xC6,0x7E,0x06,0xC6,0x7C,0x00},
    {0x00,0x18,0x18,0x00,0x18,0x18,0x00,0x00}, {0x18,0x7E,0xD8,0x7C,0x1B,0x7E,0x18,0x00},
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, {0x7C,0xC6,0x0C,0x18,0x18,0x00,0x18,0x00},
    {0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xFE,0x00}, {0xFC,0xC6,0xC6,0xFC,0xC0,0xC0,0xC0,0x00},
    /* 0x10..0x17: + W E R T U I O */
    {0x00,0x18,0x18,0x7E,0x18,0x18,0x00,0x00}, {0xC6,0xC6,0xC6,0xD6,0xFE,0xEE,0xC6,0x00},
    {0xFE,0xC0,0xC0,0xFC,0xC0,0xC0,0xFE,0x00}, {0xFC,0xC6,0xC6,0xFC,0xD8,0xCC,0xC6,0x00},
    {0xFE,0x18,0x18,0x18,0x18,0x18,0x18,0x00}, {0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00},
    {0x7E,0x18,0x18,0x18,0x18,0x18,0x7E,0x00}, {0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00},
    /* 0x18..0x1F: Q S D F G H J K */
    {0x7C,0xC6,0xC6,0xC6,0xD6,0xDE,0x7C,0x00}, {0x7C,0xC6,0xC0,0x7C,0x06,0xC6,0x7C,0x00},
    {0xF8,0xCC,0xC6,0xC6,0xC6,0xCC,0xF8,0x00}, {0xFE,0xC0,0xC0,0xFC,0xC0,0xC0,0xC0,0x00},
    {0x7C,0xC6,0xC0,0xCE,0xC6,0xC6,0x7E,0x00}, {0xC6,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0x00},
    {0x06,0x06,0x06,0x06,0xC6,0xC6,0x7C,0x00}, {0xC6,0xCC,0xD8,0xF0,0xD8,0xCC,0xC6,0x00},
    /* 0x20..0x27: A Z X C V B M . */
    {0x38,0x6C,0xC6,0xFE,0xC6,0xC6,0xC6,0x00}, {0xFE,0x06,0x0C,0x18,0x30,0x60,0xFE,0x00},
    {0xC6,0xC6,0x6C,0x38,0x6C,0xC6,0xC6,0x00}, {0x7C,0xC6,0xC0,0xC0,0xC0,0xC6,0x7C,0x00},
    {0xC6,0xC6,0xC6,0xC6,0x6C,0x38,0x10,0x00}, {0xFC,0xC6,0xC6,0xFC,0xC6,0xC6,0xFC,0x00},
    {0xC6,0xEE,0xFE,0xD6,0xC6,0xC6,0xC6,0x00}, {0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00},
    /* 0x28..0x2F: - * div = Y N / block */
    {0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0x00}, {0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00},
    {0x00,0x18,0x00,0x7E,0x00,0x18,0x00,0x00}, {0x00,0x00,0x7E,0x00,0x7E,0x00,0x00,0x00},
    {0xC6,0xC6,0x6C,0x38,0x18,0x18,0x18,0x00}, {0xC6,0xE6,0xF6,0xDE,0xCE,0xC6,0xC6,0x00},
    {0x02,0x06,0x0C,0x18,0x30,0x60,0xC0,0x00}, {0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0xFE,0x00},
    /* 0x30..0x37: bar, ball, man-R, man-R-walk, man-L-walk, man-L, arrow-R, tree */
    {0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00}, {0x00,0x3C,0x7E,0x7E,0x7E,0x3C,0x00,0x00},
    {0x38,0x38,0x10,0x3C,0x10,0x28,0x28,0x00}, {0x38,0x38,0x12,0x3C,0x50,0x28,0x44,0x00},
    {0x1C,0x1C,0x48,0x3C,0x0A,0x14,0x22,0x00}, {0x1C,0x1C,0x08,0x3C,0x08,0x14,0x14,0x00},
    {0x00,0x08,0x0C,0xFE,0x0C,0x08,0x00,0x00}, {0x18,0x3C,0x7E,0xFF,0x18,0x18,0x3C,0x00},
    /* 0x38..0x3F: slope-L, slope-R, man-fwd, backslash, sub/ship1, plane, ship2, ship3 */
    {0x80,0xC0,0xE0,0xF0,0xF8,0xFC,0xFE,0x00}, {0x01,0x03,0x07,0x0F,0x1F,0x3F,0x7F,0x00},
    {0x3C,0x3C,0x18,0x7E,0x5A,0x24,0x66,0x00}, {0xC0,0x60,0x30,0x18,0x0C,0x06,0x02,0x00},
    {0x18,0x18,0x3C,0xFF,0xFF,0x7E,0x00,0x00}, {0x10,0x18,0xFC,0xFF,0xFC,0x18,0x10,0x00},
    {0x18,0x3C,0x7E,0xDB,0xFF,0x24,0x42,0x00}, {0x00,0x18,0x3C,0x7E,0xFF,0xBD,0x81,0x00}
};

/* Clean-room Page 3 ($300..$37E) sound tone & tune data (for MOVP3 and BIOS playsound) */
static const u8 bios_page3_snd[0x80] = {
    /* $300..$327: 10 4-byte tone entries ($A7, $A8, $A9, $AA) for N1..N10 */
    0xFF,0x00,0xFF,0xCA,  /* $00 N1 */
    0xF0,0xF0,0xF0,0xCA,  /* $04 N2 */
    0xCC,0xCC,0xCC,0xCA,  /* $08 N3 */
    0xAA,0xAA,0xAA,0xCA,  /* $0C N4 */
    0xFC,0x03,0xFC,0xEA,  /* $10 N5 */
    0xF0,0x0F,0xF0,0xEA,  /* $14 N6 */
    0xE3,0x38,0xE3,0xEA,  /* $18 N7 */
    0xCC,0xCC,0xCC,0xEA,  /* $1C N8 */
    0xB6,0xDB,0x6D,0xEA,  /* $20 N9 */
    0xAA,0xAA,0xAA,0xEA,  /* $24 N10 */
    /* $328: tune_beep_error */
    0x8C,0x00, 0x00,0x00,0x00,0x00,
    /* $32E: tune_explode */
    0x4F,0xFF, 0x4F,0xFA, 0x4F,0xF5, 0x48,0xF2, 0x00,0x00,0x00,0x00,0x00,0x00,
    /* $33C: tune_alarm */
    0x86,0x18, 0x86,0x10, 0x86,0x18, 0x86,0x10, 0x86,0x18, 0x86,0x10, 0x00,0x00,
    /* $34A: tune_select */
    0x84,0x10, 0x84,0x18, 0x86,0x24, 0x00,0x00,0x00,0x00,0x00,0x00,
    /* $356: tune_keyclick */
    0x82,0x20, 0x00,0x00,
    /* $35A: tune_buzz */
    0x90,0x04, 0x00,0x00,
    /* $35E: tune_select2 */
    0x83,0x14, 0x22, 0x83,0x1C, 0x22, 0x85,0x24, 0x00,
    /* $367..$369 pad */
    0x00,0x00,0x00,
    /* $36A: tune_shoot */
    0x82,0x24, 0x82,0x1C, 0x82,0x14, 0x46,0xFC, 0x00
};

static void build_clean_bios(void)
{
    for (int i = 0; i < 1024; i++)
        W.bios[i] = 0x83u; /* RET fallback */

    /* Hardware vectors: $000 -> $00E0 (CALL $00F1; JMP $0400) so $00F1 (init) is a true subroutine */
    W.bios[0x000] = 0x04u; W.bios[0x001] = 0xE0u; /* $000: JMP $00E0 */
    W.bios[0x003] = 0x84u; W.bios[0x004] = 0x02u; /* $003: JMP $0402 (cart ext IRQ) */
    W.bios[0x007] = 0x84u; W.bios[0x008] = 0x04u; /* $007: JMP $0404 (cart timer IRQ) */
    W.bios[0x0E0] = 0x14u; W.bios[0x0E1] = 0xF1u; /* $0E0: CALL $00F1 (init) */
    W.bios[0x0E2] = 0x84u; W.bios[0x0E3] = 0x00u; /* $0E2: JMP $0400 */

    /* $009: irq -> save A in RB1.R7, read VDC status, jump to cart $406 (vsyncirq) */
    W.bios[0x009] = 0xD5u;                         /* SEL RB1 */
    W.bios[0x00A] = 0xAFu;                         /* MOV R7, A */
    W.bios[0x00B] = 0x84u; W.bios[0x00C] = 0x06u;  /* JMP $0406 */

    /* $014: irqend -> restore A from RB1.R7, RETR */
    W.bios[0x014] = 0xD5u;                         /* SEL RB1 */
    W.bios[0x015] = 0xFFu;                         /* MOV A, R7 */
    W.bios[0x016] = 0x93u;                         /* RETR */

    /* $01A: vsyncirq (HLE trapped), ends with JMP $0014 */
    W.bios[0x01A] = 0x04u; W.bios[0x01B] = 0x14u;
    W.bios[0x030] = 0x04u; W.bios[0x031] = 0x14u;
    W.bios[0x044] = 0x04u; W.bios[0x045] = 0x14u;
    W.bios[0x04B] = 0x04u; W.bios[0x04C] = 0x14u;

    /* Page 3 ($300..$37E): sound data table */
    for (int i = 0; i < 0x7F; i++)
        W.bios[0x300 + i] = bios_page3_snd[i];

    /* Bank switch helpers ($37F..$38E) in genuine 8048 machine code */
    /* $37F bank02: ANL P1,#$FE; JMP $0400 */
    W.bios[0x37F] = 0x99u; W.bios[0x380] = 0xFEu; W.bios[0x381] = 0x84u; W.bios[0x382] = 0x00u;
    /* $383 bank01: ANL P1,#$FD; JMP $0400 */
    W.bios[0x383] = 0x99u; W.bios[0x384] = 0xFDu; W.bios[0x385] = 0x84u; W.bios[0x386] = 0x00u;
    /* $387 bank0:  ANL P1,#$FC; JMP $0400 */
    W.bios[0x387] = 0x99u; W.bios[0x388] = 0xFCu; W.bios[0x389] = 0x84u; W.bios[0x38A] = 0x00u;
    /* $38B bank3:  ORL P1,#$03; JMP $0400 */
    W.bios[0x38B] = 0x89u; W.bios[0x38C] = 0x03u; W.bios[0x38D] = 0x84u; W.bios[0x38E] = 0x00u;
}

static inline u8 *reg_bank(void)
{
    return W.iram + ((S.psw & 0x10u) ? 24 : 0);
}

static u8 rom_read(u16 addr)
{
    addr &= 0xFFFu;
    if (addr < 0x400u)
        return S.has_ext_bios ? W.ext_bios[addr] : W.bios[addr];

    u32 sz = S.cart_size;
    u32 bank = S.p1 & 3u;
    if (sz <= 2048u) {
        /* 2 KB: A11 drives Cart A10 ($400..$7FF -> 0..3FF, $800..$FFF -> 400..7FF) */
        u32 off = ((addr & 0x800u) ? 0x400u : 0u) | (addr & 0x3FFu);
        return (off < sz) ? W.cart[off] : 0xFFu;
    }
    if (sz == 3072u) {
        /* 3 KB linear unbanked ($400..$FFF -> 0..BFF) */
        return W.cart[addr - 0x400u];
    }
    if (sz == 4096u) {
        /* 4 KB: 2 banks of 2 KB selected by P10 */
        u32 b = bank & 1u;
        u32 off = b * 2048u + (((addr & 0x800u) ? 0x400u : 0u) | (addr & 0x3FFu));
        return W.cart[off];
    }
    if (sz == 8192u) {
        /* 8 KB: 4 banks of 2 KB selected by P11..P10 */
        u32 off = bank * 2048u + (((addr & 0x800u) ? 0x400u : 0u) | (addr & 0x3FFu));
        return W.cart[off];
    }
    if (sz == 12288u) {
        /* 12 KB: 4 banks of 3 KB ($400..$FFF linear) */
        return W.cart[bank * 3072u + (addr - 0x400u)];
    }
    /* 16 KB: 4 banks of 4 KB ($400..$FFF at +0x400..+0xFFF) */
    return W.cart[(bank * 4096u + addr) % sz];
}

/* Effective Odyssey2 key currently held (0x00..0x2F, or 0xFF = none) */
static u8 current_o2_key(void)
{
    if (S.ext_key < 0x30u)
        return S.ext_key;
    if (S.pad & PAD_START)  return 0x01u; /* '1' (Start 1P) */
    if (S.pad & PAD_SELECT) return 0x02u; /* '2' (Start 2P / Game 2) */
    if (S.pad & PAD_X)      return 0x03u; /* '3' */
    if (S.pad & PAD_Y)      return 0x04u; /* '4' */
    if (S.pad & PAD_B)      return 0x0Cu; /* Space */
    if (S.pad & PAD_L)      return 0x2Cu; /* 'Y' (Yes) */
    if (S.pad & PAD_R)      return 0x2Fu; /* Enter */
    return 0xFFu;
}

static u8 read_p2(void)
{
    u8 out = S.p2 | 0xF0u;
    if (!(S.p1 & 0x04u)) {
        /* P12 == 0: Keyboard scanner active; P20..P22 select row 0..5 */
        u8 row = S.p2 & 0x07u;
        u8 k = current_o2_key();
        if (k < 0x30u && (k >> 3) == row) {
            u8 col = (k & 0x07u) ^ 0x07u; /* active/encoded in P25..P27; wait: on O2 col is (k & 7) XORed or direct? */
            /* On Odyssey2 8048 BIOS readkey ($00B0): reads P2, checks JB4 (P24==0 means pressed),
               takes P25..P27 XOR 7 or direct: let's match standard O2 hardware: col bits P25..P27 = (k & 7) ^ 7?
               Wait: in O2 hardware 74LS148 priority encoder has active-low outputs A0..A2 = ~(col) & 7!
               Wait: let's check what O2 BIOS readkey ($00B0) decodes: CPL A -> SWAP A -> RR A -> ANL A,#07 -> ORL A,row*8!
               YES! 74LS148 outputs inverted column ~(k & 7) on P25..P27, and GS (active low = 0) on P24! */
            out = (u8)((S.p2 & 0x0Fu) | ((u32)col << 5)); /* P24 = 0 (pressed), P25..P27 = ~col */
        }
    }
    return out;
}

static u8 read_bus_joy(void)
{
    /* Active-low joystick on BUS when P12=1 (or P13=1,P14=1): P2 low 3 bits = 0 (Player 1) or 1 (Player 2).
       Note: some games wire main player to stick 0, others to stick 1 -- map single-player pad to stick 0 AND stick 1! */
    u8 v = 0xFFu;
    u8 sel = S.p2 & 0x07u;
    if (sel == 0u || sel == 1u) {
        if (S.pad & PAD_UP)    v &= (u8)~0x01u;
        if (S.pad & PAD_RIGHT) v &= (u8)~0x02u;
        if (S.pad & PAD_DOWN)  v &= (u8)~0x04u;
        if (S.pad & PAD_LEFT)  v &= (u8)~0x08u;
        if (S.pad & PAD_A)     v &= (u8)~0x10u;
    }
    return v;
}

static void vdc_write(u8 addr, u8 val)
{
    if (addr == 0xA0u) {
        /* Foreground / Grid registers $00..$7F can even be written anytime here (real chip ignores $00..$3F/$40..$7F
           when $A0.5 is 1 on some revs, except quad Y/ptr raster tricks turn $A0.5 off first) */
        W.vdc[0xA0] = val;
        if (!(val & 0x01u))
            S.ext_irq = 0;
        return;
    }
    if (addr == 0xA2u) {
        S.coll_mask = val;
        W.vdc[0xA2] = val;
        return;
    }
    if (addr >= 0xA7u && addr <= 0xA9u) {
        W.vdc[addr] = val;
        S.shift_reg = (u32)W.vdc[0xA7] | ((u32)W.vdc[0xA8] << 8) | ((u32)W.vdc[0xA9] << 16);
        S.shift_bits = 24u;
        return;
    }
    if (addr == 0xAAu) {
        W.vdc[0xAA] = val;
        if (!(val & 0x80u))
            S.shift_bits = 0;
        else if (S.shift_bits == 0)
            S.shift_bits = 24u;
        return;
    }
    W.vdc[addr] = val;
}

static u8 vdc_read(u8 addr)
{
    if (addr == 0xA1u) {
        u8 st = S.vdc_stat;
        if (S.scan_y >= O2_VBL_LINE)
            st |= 0x08u; /* vblank */
        if (S.line_cyc < O2_HBL_START)
            st |= 0x01u; /* !hblank / display */
        S.vdc_stat &= (u8)~(0x80u | 0x08u | 0x04u);
        S.ext_irq = 0;   /* reading $A1 acknowledges VDC VBlank interrupt */
        return st;
    }
    if (addr == 0xA2u) {
        u8 c = S.coll_stat;
        S.coll_stat = 0;
        return c;
    }
    if (addr == 0xA4u) {
        return (S.scan_y < 256) ? (u8)S.scan_y : 255u;
    }
    if (addr == 0xA5u) {
        return (u8)(S.line_cyc * 8);
    }
    return W.vdc[addr];
}

static u8 ext_read(u8 addr)
{
    /* Copy mode (P13=0, P14=0, P16=1): reads come from ERAM! */
    if (!(S.p1 & 0x10u) && ((S.p1 & 0x08u) || (S.p1 & 0x40u)))
        return W.eram[addr & 0x7Fu];
    if (!(S.p1 & 0x08u))
        return vdc_read(addr);
    if (!(S.p1 & 0x10u))
        return W.eram[addr & 0x7Fu];
    return read_bus_joy();
}

static void ext_write(u8 addr, u8 val)
{
    /* Copy mode (P13=0, P14=0, P16=1): writes go ONLY to VDC! */
    if (!(S.p1 & 0x08u) && !(S.p1 & 0x10u) && (S.p1 & 0x40u)) {
        vdc_write(addr, val);
        return;
    }
    if (!(S.p1 & 0x08u))
        vdc_write(addr, val);
    if (!(S.p1 & 0x10u))
        W.eram[addr & 0x7Fu] = val;
}

static inline void push_pc_psw(u16 ret_pc)
{
    u8 sp = S.psw & 0x07u;
    S.stack[sp] = (u16)((ret_pc & 0xFFFu) | ((u16)(S.psw & 0xF0u) << 8));
    S.psw = (u8)((S.psw & 0xF8u) | ((sp + 1u) & 0x07u));
}

static inline void pop_ret(int restore_psw)
{
    u8 sp = (S.psw - 1u) & 0x07u;
    u16 v = S.stack[sp];
    S.pc = v & 0xFFFu;
    if (restore_psw) {
        S.psw = (u8)((v >> 8 & 0xF0u) | 0x08u | sp);
        S.in_irq = 0;
    } else {
        S.psw = (u8)((S.psw & 0xF8u) | sp);
    }
}

/* ---- Clean-room HLE BIOS routines ($000..$3FF when no external o2rom.bin) ---- */
static void hle_calcchar(u8 *r, u8 ch, u8 y, u8 col)
{
    u16 ptr = (u16)(((u16)(ch & 0x3Fu) * 8u - (u16)(y >> 1)) & 0x1FFu);
    r[5] = (u8)(ptr & 0xFFu);
    u8 cbits = (col <= 7u) ? (u8)(col << 1) : (u8)(col & 0x0Eu);
    r[6] = (u8)(cbits | (u8)((ptr >> 8) & 1u));
}

static void hle_parsesnd(void)
{
    u8 *rb1 = W.iram + 24;
    u8 cmd = rb1[1];
    u8 param = rb1[2];
    if (cmd == 0u) {
        W.iram[0x3F] &= (u8)~0x40u;
        vdc_write(0xAAu, 0u);
        S.pc = 0x014u;
        return;
    }
    if ((cmd & 0xF0u) == 0x10u) {
        rb1[4] = param;
        S.pc = 0x40Au; /* re-dispatch custom/BIOS sound vector immediately */
        return;
    }
    if ((cmd & 0xE0u) == 0x20u) {
        rb1[5] = (u8)((cmd & 0x1Fu) + 1u);
        vdc_write(0xAAu, 0u);
        S.pc = 0x014u;
        return;
    }
    if ((cmd & 0xC0u) == 0x40u) {
        rb1[4]++;
        rb1[5] = (u8)((cmd & 0x1Fu) + 1u);
        vdc_write(0xA7u, 0xAAu);
        vdc_write(0xA8u, 0x55u);
        vdc_write(0xA9u, param ? param : 0xFFu);
        vdc_write(0xAAu, (u8)(0xD0u | (param & 0x0Fu ? (param & 0x0Fu) : 0x0Cu)));
        S.pc = 0x014u;
        return;
    }
    /* TONE (bit 7 = 1): param is offset in Page 3 ($300..$327) */
    rb1[4]++;
    rb1[5] = (u8)((cmd & 0x3Fu) + 1u);
    u8 off = (u8)(param & 0x3Cu);
    vdc_write(0xA7u, W.bios[0x300u + off + 0u]);
    vdc_write(0xA8u, W.bios[0x300u + off + 1u]);
    vdc_write(0xA9u, W.bios[0x300u + off + 2u]);
    vdc_write(0xAAu, (u8)(W.bios[0x300u + off + 3u] | 0x80u));
    S.pc = 0x014u;
}

static void hle_doclock_step(void)
{
    u8 clk = W.iram[0x3E];
    if (clk & 0x80u)
        return;
    clk = (u8)((clk & 0xC0u) | (((clk & 0x3Fu) + 1u) & 0x3Fu));
    if ((clk & 0x3Fu) >= 60u) {
        clk &= 0xC0u;
        u8 sec = W.eram[0x02], min = W.eram[0x01];
        if (clk & 0x40u) {
            /* forward BCD */
            sec = (u8)(((sec & 0x0Fu) >= 9u) ? (sec + 7u) : (sec + 1u));
            if (sec >= 0x60u) {
                sec = 0;
                min = (u8)(((min & 0x0Fu) >= 9u) ? (min + 7u) : (min + 1u));
                if (min >= 0x60u) min = 0;
            }
        } else if (sec || min) {
            /* countdown BCD */
            if (sec == 0u) {
                sec = 0x59u;
                min = (u8)(((min & 0x0Fu) == 0u) ? (min - 7u) : (min - 1u));
            } else {
                sec = (u8)(((sec & 0x0Fu) == 0u) ? (sec - 7u) : (sec - 1u));
            }
        }
        W.eram[0x02] = sec;
        W.eram[0x01] = min;
    }
    W.iram[0x3E] = clk;
}

static void draw_select_game_banner(void)
{
    /* "SELECT GAME" using single chars 0..10 in bright white on black */
    static const u8 msg[11] = {0x19,0x12,0x0E,0x12,0x23,0x14,0x0C,0x1C,0x20,0x26,0x12};
    for (int i = 0; i < 256; i++)
        W.vdc[i] = 0;
    for (int i = 0; i < 12; i++)
        W.vdc[0x10 + i * 4] = 0xF8u;
    for (int q = 0; q < 4; q++)
        W.vdc[0x40 + q * 16] = 0xF8u;
    for (int i = 0; i < 11; i++) {
        u8 y = 0x68u, x = (u8)(0x24u + i * 8);
        u16 ptr = (u16)(((u16)msg[i] * 8u - (u16)(y >> 1)) & 0x1FFu);
        W.vdc[0x10 + i * 4 + 0] = y;
        W.vdc[0x10 + i * 4 + 1] = x;
        W.vdc[0x10 + i * 4 + 2] = (u8)(ptr & 0xFFu);
        W.vdc[0x10 + i * 4 + 3] = (u8)(0x0Eu | ((ptr >> 8) & 1u));
    }
    W.vdc[0xA3] = 0x00u;
    W.vdc[0xA0] = 0x21u; /* foreground on + VBlank IRQ enable */
}

static __attribute__((noinline)) int o2_hle_bios(u16 pc)
{
    u8 *r = reg_bank();
    switch (pc) {
    case 0x0F1u: /* init (callable subroutine) */
        S.ie = 0;
        S.tcnti = 0;
        S.dbf = 0;
        S.f1 = 0;
        S.p1 = (u8)((S.p1 & 0x03u) | 0xBCu); /* VDC enabled (P13=0), ERAM disabled (P14=1), kbd off (P12=1) */
        for (int i = 0; i < 64; i++)
            W.iram[i] = 0;
        for (int i = 0; i < 12; i++)
            W.vdc[0x10 + i * 4] = 0xF8u;
        for (int q = 0; q < 4; q++)
            W.vdc[0x40 + q * 16] = 0xF8u;
        W.vdc[0xA0] = 0x01u;
        W.vdc[0xAA] = 0x00u;
        pop_ret(0);
        return 2;

    case 0x2C2u:
    case 0x2C3u: { /* selectgame */
        S.psw = 0x08u;
        S.dbf = 0;
        S.p1 = (u8)((S.p1 & 0x03u) | 0xA4u);
        S.ie = 1;
        u8 k = current_o2_key();
        if (k == 0xFFu && S.boot_wait > 0) {
            draw_select_game_banner();
            /* Yield until next VBlank while displaying SELECT GAME */
            if (!S.f1)
                return 2; /* stay at $02C3 until VBlank sets F1 */
            S.f1 = 0;
            S.boot_wait--;
            if (S.boot_wait > 0)
                return 2;
            k = 0x01u; /* auto-select Game 1 after brief banner if no key pressed */
        } else if (k == 0xFFu) {
            k = 0x01u;
        }
        /* Clear screen & enter cartridge after-selectgame vector ($0408) with key in A & R0 */
        for (int i = 0; i < 12; i++)
            W.vdc[0x10 + i * 4] = 0xF8u;
        for (int q = 0; q < 4; q++)
            W.vdc[0x40 + q * 16] = 0xF8u;
        W.vdc[0xA0] = 0x01u; /* gfxoff, VBlank IRQ enabled */
        S.a = k;
        W.iram[0] = k;
        S.f1 = 0;
        S.pc = 0x408u;
        return 2;
    }

    case 0x01Au: /* vsyncirq */
    case 0x030u: {
        (void)vdc_read(0xA1u);
        if (pc == 0x01Au) {
            S.f1 = 1;
            W.iram[0x3D] = vdc_read(0xA2u);
        }
        if (W.iram[0x3F] & 0x80u) {
            /* Copy VBlank table from ERAM[$7F] downward into VDC */
            u8 p = 0x7Fu;
            for (int guard = 0; guard < 64; guard++) {
                u8 cnt = W.eram[p & 0x7Fu];
                p--;
                if (!cnt)
                    break;
                u8 dst = W.eram[p & 0x7Fu];
                p--;
                while (cnt--) {
                    vdc_write(dst++, W.eram[p & 0x7Fu]);
                    p--;
                }
            }
            W.iram[0x3F] &= (u8)~0x80u;
            W.vdc[0xA0] |= 0x21u;
        }
        hle_doclock_step();
        if (W.iram[0x3F] & 0x40u) {
            u8 *rb1 = W.iram + 24;
            if (rb1[5] > 0)
                rb1[5]--;
            if (rb1[5] == 0) {
                S.psw = (u8)((S.psw & ~0x10u) | 0x10u); /* SEL RB1 */
                S.pc = 0x40Au; /* jump to cart soundirq vector */
                return 2;
            }
        }
        S.pc = 0x014u;
        return 2;
    }

    case 0x044u: { /* soundirq: read BIOS tune in Page 3 via RB1.R4 */
        u8 *rb1 = W.iram + 24;
        u8 idx = rb1[4];
        rb1[1] = W.bios[0x300u | idx];
        rb1[4] = (u8)(idx + 1u);
        rb1[2] = W.bios[0x300u | rb1[4]];
        hle_parsesnd();
        return 2;
    }

    case 0x04Bu: /* parsesnd */
        hle_parsesnd();
        return 2;

    case 0x089u: { /* copyregs: copy R2 bytes from @R0 (IRAM) to VDC[@R1] */
        u8 src = r[0] & 0x3Fu, dst = r[1], cnt = r[2];
        while (cnt--)
            vdc_write(dst++, W.iram[src++ & 0x3Fu]);
        r[0] = src; r[1] = dst; r[2] = 0;
        pop_ret(0);
        return 2;
    }

    case 0x0B0u:
    case 0x0BCu: { /* readkey: A = 0x00..0x2F (bit7=0, CY=1) when pressed, 0xFF (bit7=1, CY=0) when none */
        u8 k = current_o2_key();
        if (k < 0x30u) {
            S.a = k;
            S.psw |= 0x80u;  /* CY = 1: key pressed */
        } else {
            S.a = 0xFFu;
            S.psw &= (u8)~0x80u; /* CY = 0: no key */
        }
        pop_ret(0);
        return 2;
    }

    case 0x0E7u: /* vdcenable */
        S.p1 = (u8)((S.p1 | 0xBCu) & ~0x48u); /* P13=0, P14=1, P16=0 */
        pop_ret(0);
        return 2;

    case 0x0ECu: /* extramenable */
        S.p1 = (u8)((S.p1 | 0xACu) & ~0x50u); /* P13=1, P14=0, P16=0 */
        pop_ret(0);
        return 2;

    case 0x11Cu: /* gfxoff */
        W.vdc[0xA0] &= (u8)~0x28u;
        S.p1 = (u8)((S.p1 | 0xBCu) & ~0x48u);
        pop_ret(0);
        return 2;

    case 0x127u: /* gfxon */
        W.vdc[0xA0] |= 0x21u;
        S.ie = 1;
        pop_ret(0);
        return 2;

    case 0x132u: /* tableend */
        W.eram[r[0] & 0x7Fu] = 0u;
        W.iram[0x3F] |= 0x80u;
        S.ie = 1;
        W.vdc[0xA0] |= 0x01u;
        pop_ret(0);
        return 2;

    case 0x13Du: { /* waitforkey */
        S.ie = 1;
        W.vdc[0xA0] |= 0x01u;
        u8 k = current_o2_key();
        if (k < 0x30u) {
            S.a = k;
            S.psw &= (u8)~0x80u;
            pop_ret(0);
        }
        /* else stay at $013D so interrupts keep firing */
        return 2;
    }

    case 0x14Bu: /* calcchar23 */
        hle_calcchar(r, r[5], r[4], r[6]);
        pop_ret(0);
        return 2;

    case 0x16Bu: /* clearchar */
        for (int i = 0; i < 12; i++)
            W.vdc[0x10 + i * 4] = 0xF8u;
        for (int q = 0; q < 4; q++)
            W.vdc[0x40 + q * 16] = 0xF8u;
        pop_ret(0);
        return 2;

    case 0x176u: /* waitvsync */
        S.ie = 1;
        W.vdc[0xA0] |= 0x01u;
        if (S.f1) {
            S.f1 = 0;
            S.p1 = (u8)((S.p1 | 0xBCu) & ~0x48u);
            pop_ret(0);
        }
        return 2;

    case 0x17Cu: { /* tablebcdbyte: print 2 BCD nibbles of A into ERAM table @R0 */
        u8 val = S.a;
        hle_calcchar(r, (u8)((val >> 4) & 0x0Fu), r[4], r[6]);
        W.eram[r[0]-- & 0x7Fu] = r[4];
        W.eram[r[0]-- & 0x7Fu] = r[3];
        W.eram[r[0]-- & 0x7Fu] = r[5];
        W.eram[r[0]-- & 0x7Fu] = r[6];
        r[3] = (u8)(r[3] + 8u);
        hle_calcchar(r, (u8)(val & 0x0Fu), r[4], r[6]);
        W.eram[r[0]-- & 0x7Fu] = r[4];
        W.eram[r[0]-- & 0x7Fu] = r[3];
        W.eram[r[0]-- & 0x7Fu] = r[5];
        W.eram[r[0]-- & 0x7Fu] = r[6];
        r[3] = (u8)(r[3] + 8u);
        pop_ret(0);
        return 2;
    }

    case 0x229u: { /* tablebcdnibble */
        hle_calcchar(r, (u8)(S.a & 0x0Fu), r[4], r[6]);
        W.eram[r[0]-- & 0x7Fu] = r[4];
        W.eram[r[0]-- & 0x7Fu] = r[3];
        W.eram[r[0]-- & 0x7Fu] = r[5];
        W.eram[r[0]-- & 0x7Fu] = r[6];
        r[3] = (u8)(r[3] + 8u);
        pop_ret(0);
        return 2;
    }

    case 0x197u: /* tableprintchar */
        hle_calcchar(r, r[5], r[4], r[6]);
        W.eram[r[0]-- & 0x7Fu] = r[4];
        W.eram[r[0]-- & 0x7Fu] = r[3];
        W.eram[r[0]-- & 0x7Fu] = r[5];
        W.eram[r[0]-- & 0x7Fu] = r[6];
        r[3] = (u8)(r[3] + 8u);
        pop_ret(0);
        return 2;

    case 0x22Cu: /* tablechar23 */
        hle_calcchar(r, r[5], r[4], r[6]);
        W.eram[r[0]-- & 0x7Fu] = r[5];
        W.eram[r[0]-- & 0x7Fu] = r[6];
        pop_ret(0);
        return 2;

    case 0x235u: /* tableput2 */
        W.eram[r[0]-- & 0x7Fu] = r[5];
        W.eram[r[0]-- & 0x7Fu] = r[6];
        pop_ret(0);
        return 2;

    case 0x1A2u: { /* playsound: A = tune offset */
        u8 *rb1 = W.iram + 24;
        rb1[4] = S.a;
        rb1[5] = 1u;
        W.iram[0x3F] |= 0x40u;
        S.ie = 1;
        W.vdc[0xA0] |= 0x01u;
        pop_ret(0);
        return 2;
    }

    case 0x23Au: { /* initclock: draw initial MM:SS from ERAM[$01:$02] into VDC[$28..$3B] at (R3, R4), col R6 */
        S.clock_x = r[3] ? r[3] : 0x20u;
        u8 min = W.eram[0x01], sec = W.eram[0x02];
        u8 digits[5] = {(u8)(min >> 4), (u8)(min & 0x0Fu), 0x0Au, (u8)(sec >> 4), (u8)(sec & 0x0Fu)};
        u8 dst = 0x28u, x = S.clock_x;
        for (int i = 0; i < 5; i++) {
            hle_calcchar(r, digits[i], r[4], r[6]);
            vdc_write(dst++, r[4]);
            vdc_write(dst++, x);
            vdc_write(dst++, r[5]);
            vdc_write(dst++, r[6]);
            x = (u8)(x + 8u);
        }
        pop_ret(0);
        return 2;
    }

    case 0x1B0u: { /* doclock: stage MM:SS into ERAM[$7F] VBlank copy table for VDC[$28..$3B] */
        u8 min = W.eram[0x01], sec = W.eram[0x02];
        u8 digits[5] = {(u8)(min >> 4), (u8)(min & 0x0Fu), 0x0Au, (u8)(sec >> 4), (u8)(sec & 0x0Fu)};
        u8 p = 0x7Fu, x = S.clock_x ? S.clock_x : 0x20u;
        W.eram[p-- & 0x7Fu] = 20u;
        W.eram[p-- & 0x7Fu] = 0x28u;
        for (int i = 0; i < 5; i++) {
            hle_calcchar(r, digits[i], r[4], r[6]);
            W.eram[p-- & 0x7Fu] = r[4];
            W.eram[p-- & 0x7Fu] = x;
            W.eram[p-- & 0x7Fu] = r[5];
            W.eram[p-- & 0x7Fu] = r[6];
            x = (u8)(x + 8u);
        }
        W.eram[p & 0x7Fu] = 0u;
        W.iram[0x3F] |= 0x80u;
        S.ie = 1;
        W.vdc[0xA0] |= 0x01u;
        pop_ret(0);
        return 2;
    }

    case 0x261u: /* putchar23 */
        hle_calcchar(r, r[5], r[4], r[6]);
        vdc_write((u8)(r[0] + 2u), r[5]);
        vdc_write((u8)(r[0] + 3u), r[6]);
        r[0] = (u8)(r[0] + 4u);
        pop_ret(0);
        return 2;

    case 0x3EAu: /* printchar: R0=VDC char reg, R3=X, R4=Y, R5=char, R6=color */
        hle_calcchar(r, r[5], r[4], r[6]);
        vdc_write(r[0]++, r[4]);
        vdc_write(r[0]++, r[3]);
        vdc_write(r[0]++, r[5]);
        vdc_write(r[0]++, r[6]);
        r[3] = (u8)(r[3] + 8u);
        pop_ret(0);
        return 2;

    case 0x26Au:   /* bittest: R0=base in ERAM, A=bit index -> F0 & CY = bit */
    case 0x280u:   /* bitclear */
    case 0x28Au: { /* bitset */
        u8 idx = S.a;
        u8 addr = (u8)((r[0] + (idx >> 3)) & 0x7Fu);
        u8 mask = (u8)(0x80u >> (idx & 7u));
        if (pc == 0x26Au) {
            int set = (W.eram[addr] & mask) != 0;
            S.psw = set ? (u8)(S.psw | 0xA0u) : (u8)(S.psw & ~0xA0u);
        } else if (pc == 0x280u) {
            W.eram[addr] &= (u8)~mask;
        } else {
            W.eram[addr] |= mask;
        }
        pop_ret(0);
        return 2;
    }

    case 0x293u: /* random */
        S.lfsr_rnd = (u8)((S.lfsr_rnd << 1) ^ (((S.lfsr_rnd >> 7) ^ (S.lfsr_rnd >> 5) ^ (S.lfsr_rnd >> 4) ^ (S.lfsr_rnd >> 3)) & 1u));
        if (!S.lfsr_rnd) S.lfsr_rnd = 0x5Au;
        S.a = S.lfsr_rnd;
        pop_ret(0);
        return 2;

    case 0x2A4u: /* nibblemixer */
        S.a = (u8)(((S.a & 0x0Fu) << 4) | ((r[0] >> 4) & 0x0Fu));
        pop_ret(0);
        return 2;

    case 0x38Fu:
    case 0x395u: { /* getjoystick: R1=stick -> R2=dx, R3=dy, F0=fire */
        u8 dx = 0, dy = 0;
        if (S.pad & PAD_LEFT)  dx = 0xFFu;
        if (S.pad & PAD_RIGHT) dx = 0x01u;
        if (S.pad & PAD_UP)    dy = 0xFFu;
        if (S.pad & PAD_DOWN)  dy = 0x01u;
        r[2] = dx;
        r[3] = dy;
        if (S.pad & PAD_A)
            S.psw |= 0x20u;  /* F0 = 1 */
        else
            S.psw &= (u8)~0x20u;
        pop_ret(0);
        return 2;
    }

    case 0x3B1u: { /* decodejoystick: R2=dx, R3=dy -> R1 = 0..7 (0=U,1=UR,2=R,3=DR,4=D,5=DL,6=L,7=UL) */
        u8 dx = r[2], dy = r[3], dir = 0xFFu;
        if (dy == 0xFFu && dx == 0x00u) dir = 0u;
        else if (dy == 0xFFu && dx == 0x01u) dir = 1u;
        else if (dy == 0x00u && dx == 0x01u) dir = 2u;
        else if (dy == 0x01u && dx == 0x01u) dir = 3u;
        else if (dy == 0x01u && dx == 0x00u) dir = 4u;
        else if (dy == 0x01u && dx == 0xFFu) dir = 5u;
        else if (dy == 0x00u && dx == 0xFFu) dir = 6u;
        else if (dy == 0xFFu && dx == 0xFFu) dir = 7u;
        r[1] = dir;
        pop_ret(0);
        return 2;
    }

    case 0x3CFu: { /* multiply: A * R1 -> R2 (hi), R1 / A (lo) */
        u16 prod = (u16)S.a * (u16)r[1];
        r[2] = (u8)(prod >> 8);
        r[1] = (u8)(prod & 0xFFu);
        S.a = r[1];
        pop_ret(0);
        return 2;
    }

    case 0x3DDu: { /* divide: (R2:R1 or A) / R3 */
        u16 num = ((u16)r[2] << 8) | r[1];
        u8 den = r[3] ? r[3] : 1u;
        r[1] = (u8)(num / den);
        r[2] = (u8)(num % den);
        S.a = r[1];
        pop_ret(0);
        return 2;
    }

    default:
        return 0;
    }
}

static inline void alu_add(u8 b, u8 carry_in)
{
    u16 sum = (u16)S.a + (u16)b + (u16)carry_in;
    u8 ac = (((S.a & 0x0Fu) + (b & 0x0Fu) + carry_in) > 0x0Fu) ? 0x40u : 0u;
    u8 cy = (sum > 0xFFu) ? 0x80u : 0u;
    S.psw = (u8)((S.psw & 0x3Fu) | cy | ac);
    S.a = (u8)sum;
}

static int cpu_step(int t1_pin)
{
    /* Interrupt check (external IRQ has priority over timer IRQ) */
    if (!S.in_irq) {
        if (S.ie && S.ext_irq) {
            S.in_irq = 1;
            push_pc_psw(S.pc);
            S.pc = 0x003u;
            return 2;
        }
        if (S.tcnti && S.tim_irq) {
            S.tim_irq = 0;
            S.in_irq = 1;
            push_pc_psw(S.pc);
            S.pc = 0x007u;
            return 2;
        }
    }

    if (!S.has_ext_bios && S.pc < 0x400u) {
        int h = o2_hle_bios(S.pc);
        if (h)
            return h;
    }

    u16 pc_op = S.pc;
    u8 op = rom_read(pc_op);
    u16 pc1 = (pc_op + 1u) & 0xFFFu;
    S.pc = pc1;
    u8 *r = reg_bank();

    /* Fast dispatch for JMP / CALL / JBb */
    if ((op & 0x1Fu) == 0x04u) {
        u8 lo = rom_read(pc1);
        u16 mb = S.in_irq ? 0u : (u16)((u32)S.dbf << 11);
        S.pc = mb | ((u16)(op & 0xE0u) << 3) | lo;
        return 2;
    }
    if ((op & 0x1Fu) == 0x14u) {
        u8 lo = rom_read(pc1);
        u16 ret = (pc1 + 1u) & 0xFFFu;
        push_pc_psw(ret);
        u16 mb = S.in_irq ? 0u : (u16)((u32)S.dbf << 11);
        S.pc = mb | ((u16)(op & 0xE0u) << 3) | lo;
        return 2;
    }
    if ((op & 0x1Fu) == 0x12u) {
        u8 lo = rom_read(pc1);
        S.pc = (pc1 + 1u) & 0xFFFu;
        if ((S.a >> (op >> 5)) & 1u)
            S.pc = (pc1 & 0xF00u) | lo;
        return 2;
    }

    switch (op) {
    case 0x00u: case 0x01u: return 1;
    case 0x02u: S.bus = S.a; return 2;
    case 0x03u: alu_add(rom_read(pc1), 0); S.pc = (pc1 + 1u) & 0xFFFu; return 2;
    case 0x05u: S.ie = 1; return 1;
    case 0x07u: S.a--; return 1;
    case 0x08u: S.a = ext_read(0xFFu); return 2;
    case 0x09u: S.a = S.p1; return 2;
    case 0x0Au: S.a = read_p2(); return 2;
    case 0x0Cu: case 0x0Du: case 0x0Eu: case 0x0Fu: S.a = (u8)((S.a & 0xF0u) | 0x0Fu); return 2;
    case 0x10u: case 0x11u: W.iram[r[op & 1] & 0x3Fu]++; return 1;
    case 0x13u: alu_add(rom_read(pc1), (S.psw >> 7) & 1u); S.pc = (pc1 + 1u) & 0xFFFu; return 2;
    case 0x15u: S.ie = 0; return 1;
    case 0x16u: { u8 lo = rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; if (S.tf) S.pc = (pc1 & 0xF00u) | lo; S.tf = 0; return 2; }
    case 0x17u: S.a++; return 1;
    case 0x18u: case 0x19u: case 0x1Au: case 0x1Bu:
    case 0x1Cu: case 0x1Du: case 0x1Eu: case 0x1Fu: r[op & 7]++; return 1;
    case 0x20u: case 0x21u: { u8 *m = &W.iram[r[op & 1] & 0x3Fu]; u8 t = S.a; S.a = *m; *m = t; return 1; }
    case 0x23u: S.a = rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; return 2;
    case 0x25u: S.tcnti = 1; return 1;
    case 0x26u: { u8 lo = rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; /* T0=1 idle (voice off) */ (void)lo; return 2; }
    case 0x27u: S.a = 0; return 1;
    case 0x28u: case 0x29u: case 0x2Au: case 0x2Bu:
    case 0x2Cu: case 0x2Du: case 0x2Eu: case 0x2Fu: { u8 t = S.a; S.a = r[op & 7]; r[op & 7] = t; return 1; }
    case 0x30u: case 0x31u: { u8 *m = &W.iram[r[op & 1] & 0x3Fu]; u8 lo = *m & 0x0Fu; *m = (u8)((*m & 0xF0u) | (S.a & 0x0Fu)); S.a = (u8)((S.a & 0xF0u) | lo); return 1; }
    case 0x35u: S.tcnti = 0; S.tim_irq = 0; return 1;
    case 0x36u: { u8 lo = rom_read(pc1); S.pc = (pc1 & 0xF00u) | lo; return 2; } /* T0=1 */
    case 0x37u: S.a = (u8)~S.a; return 1;
    case 0x39u: S.p1 = S.a; return 2;
    case 0x3Au: S.p2 = S.a; return 2;
    case 0x3Cu: case 0x3Du: case 0x3Eu: case 0x3Fu: return 2;
    case 0x40u: case 0x41u: S.a |= W.iram[r[op & 1] & 0x3Fu]; return 1;
    case 0x42u: S.a = S.t; return 1;
    case 0x43u: S.a |= rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; return 2;
    case 0x45u: S.t_mode = 2; return 1;
    case 0x46u: { u8 lo = rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; if (!t1_pin) S.pc = (pc1 & 0xF00u) | lo; return 2; }
    case 0x47u: S.a = (u8)((S.a << 4) | (S.a >> 4)); return 1;
    case 0x48u: case 0x49u: case 0x4Au: case 0x4Bu:
    case 0x4Cu: case 0x4Du: case 0x4Eu: case 0x4Fu: S.a |= r[op & 7]; return 1;
    case 0x50u: case 0x51u: S.a &= W.iram[r[op & 1] & 0x3Fu]; return 1;
    case 0x53u: S.a &= rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; return 2;
    case 0x55u: S.t_mode = 1; S.t_prescale = 0; return 1;
    case 0x56u: { u8 lo = rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; if (t1_pin) S.pc = (pc1 & 0xF00u) | lo; return 2; }
    case 0x57u: {
        u16 v = S.a;
        if ((v & 0x0Fu) > 9u || (S.psw & 0x40u))
            v += 6u;
        if (v > 0xFFu)
            S.psw |= 0x80u;
        if (((v >> 4) & 0x0Fu) > 9u || (S.psw & 0x80u))
            v += 0x60u;
        if (v > 0xFFu)
            S.psw |= 0x80u;
        S.a = (u8)v;
        return 1;
    }
    case 0x58u: case 0x59u: case 0x5Au: case 0x5Bu:
    case 0x5Cu: case 0x5Du: case 0x5Eu: case 0x5Fu: S.a &= r[op & 7]; return 1;
    case 0x60u: case 0x61u: alu_add(W.iram[r[op & 1] & 0x3Fu], 0); return 1;
    case 0x62u: S.t = S.a; return 1;
    case 0x65u: S.t_mode = 0; return 1;
    case 0x67u: { u8 c = (S.psw >> 7) & 1u; S.psw = (u8)((S.psw & 0x7Fu) | ((S.a & 1u) << 7)); S.a = (u8)((S.a >> 1) | (c << 7)); return 1; }
    case 0x68u: case 0x69u: case 0x6Au: case 0x6Bu:
    case 0x6Cu: case 0x6Du: case 0x6Eu: case 0x6Fu: alu_add(r[op & 7], 0); return 1;
    case 0x70u: case 0x71u: alu_add(W.iram[r[op & 1] & 0x3Fu], (S.psw >> 7) & 1u); return 1;
    case 0x75u: return 1;
    case 0x76u: { u8 lo = rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; if (S.f1) S.pc = (pc1 & 0xF00u) | lo; return 2; }
    case 0x77u: S.a = (u8)((S.a >> 1) | (S.a << 7)); return 1;
    case 0x78u: case 0x79u: case 0x7Au: case 0x7Bu:
    case 0x7Cu: case 0x7Du: case 0x7Eu: case 0x7Fu: alu_add(r[op & 7], (S.psw >> 7) & 1u); return 1;
    case 0x80u: case 0x81u: S.a = ext_read(r[op & 1]); return 2;
    case 0x83u: pop_ret(0); return 2;
    case 0x85u: S.psw &= (u8)~0x20u; return 1;
    case 0x86u: { u8 lo = rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; if (S.ext_irq) S.pc = (pc1 & 0xF00u) | lo; return 2; }
    case 0x88u: S.bus |= rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; return 2;
    case 0x89u: S.p1 |= rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; return 2;
    case 0x8Au: S.p2 |= rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; return 2;
    case 0x8Cu: case 0x8Du: case 0x8Eu: case 0x8Fu: return 2;
    case 0x90u: case 0x91u: ext_write(r[op & 1], S.a); return 2;
    case 0x93u: pop_ret(1); return 2;
    case 0x95u: S.psw ^= 0x20u; return 1;
    case 0x96u: { u8 lo = rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; if (S.a != 0) S.pc = (pc1 & 0xF00u) | lo; return 2; }
    case 0x97u: S.psw &= (u8)~0x80u; return 1;
    case 0x98u: S.bus &= rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; return 2;
    case 0x99u: S.p1 &= rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; return 2;
    case 0x9Au: S.p2 &= rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; return 2;
    case 0x9Cu: case 0x9Du: case 0x9Eu: case 0x9Fu: return 2;
    case 0xA0u: case 0xA1u: W.iram[r[op & 1] & 0x3Fu] = S.a; return 1;
    case 0xA3u: S.a = rom_read((pc1 & 0xF00u) | S.a); return 2;
    case 0xA5u: S.f1 = 0; return 1;
    case 0xA7u: S.psw ^= 0x80u; return 1;
    case 0xA8u: case 0xA9u: case 0xAAu: case 0xABu:
    case 0xACu: case 0xADu: case 0xAEu: case 0xAFu: r[op & 7] = S.a; return 1;
    case 0xB0u: case 0xB1u: W.iram[r[op & 1] & 0x3Fu] = rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; return 2;
    case 0xB3u: S.pc = (pc1 & 0xF00u) | rom_read((pc1 & 0xF00u) | S.a); return 2;
    case 0xB5u: S.f1 ^= 1u; return 1;
    case 0xB6u: { u8 lo = rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; if (S.psw & 0x20u) S.pc = (pc1 & 0xF00u) | lo; return 2; }
    case 0xB8u: case 0xB9u: case 0xBAu: case 0xBBu:
    case 0xBCu: case 0xBDu: case 0xBEu: case 0xBFu: r[op & 7] = rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; return 2;
    case 0xC5u: S.psw &= (u8)~0x10u; return 1;
    case 0xC6u: { u8 lo = rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; if (S.a == 0) S.pc = (pc1 & 0xF00u) | lo; return 2; }
    case 0xC7u: S.a = S.psw | 0x08u; return 1;
    case 0xC8u: case 0xC9u: case 0xCAu: case 0xCBu:
    case 0xCCu: case 0xCDu: case 0xCEu: case 0xCFu: r[op & 7]--; return 1;
    case 0xD0u: case 0xD1u: S.a ^= W.iram[r[op & 1] & 0x3Fu]; return 1;
    case 0xD3u: S.a ^= rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; return 2;
    case 0xD5u: S.psw |= 0x10u; return 1;
    case 0xD7u: S.psw = (u8)(S.a | 0x08u); return 1;
    case 0xD8u: case 0xD9u: case 0xDAu: case 0xDBu:
    case 0xDCu: case 0xDDu: case 0xDEu: case 0xDFu: S.a ^= r[op & 7]; return 1;
    case 0xE3u: S.a = rom_read(0x300u | S.a); return 2;
    case 0xE5u: S.dbf = 0; return 1;
    case 0xE6u: { u8 lo = rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; if (!(S.psw & 0x80u)) S.pc = (pc1 & 0xF00u) | lo; return 2; }
    case 0xE7u: S.a = (u8)((S.a << 1) | (S.a >> 7)); return 1;
    case 0xE8u: case 0xE9u: case 0xEAu: case 0xEBu:
    case 0xECu: case 0xEDu: case 0xEEu: case 0xEFu: {
        u8 lo = rom_read(pc1);
        S.pc = (pc1 + 1u) & 0xFFFu;
        if (--r[op & 7] != 0)
            S.pc = (pc1 & 0xF00u) | lo;
        return 2;
    }
    case 0xF0u: case 0xF1u: S.a = W.iram[r[op & 1] & 0x3Fu]; return 1;
    case 0xF5u: S.dbf = 1; return 1;
    case 0xF6u: { u8 lo = rom_read(pc1); S.pc = (pc1 + 1u) & 0xFFFu; if (S.psw & 0x80u) S.pc = (pc1 & 0xF00u) | lo; return 2; }
    case 0xF7u: { u8 c = (S.psw >> 7) & 1u; S.psw = (u8)((S.psw & 0x7Fu) | (S.a & 0x80u)); S.a = (u8)((S.a << 1) | c); return 1; }
    case 0xF8u: case 0xF9u: case 0xFAu: case 0xFBu:
    case 0xFCu: case 0xFDu: case 0xFEu: case 0xFFu: S.a = r[op & 7]; return 1;
    default: return 1;
    }
}

/* ---- Scanline Renderer (160 x 240 BGR555 + Pixel-Exact Collisions) ---- */
static inline void plot_layer(u16 *line, int x, u16 col, u8 mask)
{
    if ((unsigned)x >= O2_W)
        return;
    u8 prev = W.layer[x];
    if ((prev & 0x80u) && (mask & 0x80u))
        S.vdc_stat |= 0x80u; /* character-to-character overlap */
    u8 both = prev | mask;
    if (prev && (both & S.coll_mask)) {
        for (u8 b = 1u; b; b = (u8)(b << 1))
            if ((both & b) && (S.coll_mask & b))
                S.coll_stat |= (u8)(both & ~b);
    }
    W.layer[x] = both;
    line[x] = col;
}

static void draw_char_slice(u16 *line, int y, u8 cy, int cx, u16 ptr, u8 attr)
{
    if (y < (int)cy)
        return;
    int r0 = (int)((ptr + (cy >> 1)) & 7u);
    int dy = (y >> 1) - ((int)cy >> 1);
    if (dy < 0 || r0 + dy >= 8)
        return;
    u16 rom_addr = (u16)((ptr + (u16)(y >> 1)) & 0x1FFu);
    u8 bits = o2_charset[(rom_addr >> 3) & 0x3Fu][rom_addr & 7u];
    if (!bits)
        return;
    u16 col = fore_pal[(attr >> 1) & 7u];
    for (int b = 0; b < 8; b++)
        if (bits & (0x80u >> b))
            plot_layer(line, cx + b, col, 0x80u);
}

static void render_scanline(int y, u16 *picture)
{
    u16 *line = picture + y * O2_W;
    u8 ctrl = W.vdc[0xA0];
    u8 col_reg = W.vdc[0xA3];
    u16 bg = grid_pal[(col_reg >> 3) & 7u];
    for (int x = 0; x < O2_W; x++) {
        line[x] = bg;
        W.layer[x] = 0;
    }

    /* 1. Background Grid (9x9 segments + dots) */
    if (ctrl & 0x48u) {
        u16 gcol = grid_pal[(col_reg & 7u) | ((col_reg & 0x40u) ? 8u : 0u)];
        if ((ctrl & 0x40u) && y >= 24 && y <= 218) {
            int ry = y - 24;
            if ((ry % 24) < 3) {
                for (int c = 0; c < 10; c++) {
                    int gx = 8 + c * 16;
                    plot_layer(line, gx, gcol, 0x20u);
                    plot_layer(line, gx + 1, gcol, 0x20u);
                }
            }
        }
        if ((ctrl & 0x08u) && y >= 24 && y <= 218) {
            int ry = y - 24;
            int row = ry / 24, rem = ry % 24;
            /* Vertical bars (first so horizontal intersections share cleanly) */
            if (row < 8) {
                int vw = (ctrl & 0x80u) ? 16 : 2;
                for (int c = 0; c < 10; c++) {
                    if (W.vdc[0xE0 + c] & (1u << row)) {
                        int gx = 8 + c * 16;
                        for (int k = 0; k < vw; k++)
                            plot_layer(line, gx + k, gcol, 0x10u);
                    }
                }
            }
            /* Horizontal bars (3 scanlines tall at rem == 0..2) */
            if (rem < 3 && row <= 8) {
                for (int c = 0; c < 9; c++) {
                    int on = (row < 8) ? ((W.vdc[0xC0 + c] >> row) & 1) : (W.vdc[0xD0 + c] & 1);
                    if (on) {
                        int gx = 8 + c * 16;
                        for (int k = 0; k < 18; k++)
                            plot_layer(line, gx + k, gcol, 0x20u);
                    }
                }
            }
        }
    }

    if (!(ctrl & 0x20u))
        return;

    /* 2. Quad characters ($40..$7F, 4 groups x 4 chars spaced 16 px apart with authentic X cutoff) */
    for (int q = 0; q < 4; q++) {
        int base = 0x40 + q * 16;
        u8 qy = W.vdc[base + 0];
        int qx = W.vdc[base + 1];
        for (int c = 0; c < 4; c++) {
            int cx = qx + c * 16;
            if (cx >= O2_W)
                break; /* authentic 8244 quad horizontal cutoff */
            u16 ptr = (u16)W.vdc[base + c * 4 + 2] | ((u16)(W.vdc[base + c * 4 + 3] & 1u) << 8);
            draw_char_slice(line, y, qy, cx, ptr, W.vdc[base + c * 4 + 3]);
        }
    }

    /* 3. Single foreground characters ($10..$3F, 12 chars) */
    for (int i = 0; i < 12; i++) {
        int base = 0x10 + i * 4;
        u16 ptr = (u16)W.vdc[base + 2] | ((u16)(W.vdc[base + 3] & 1u) << 8);
        draw_char_slice(line, y, W.vdc[base + 0], W.vdc[base + 1], ptr, W.vdc[base + 3]);
    }

    /* 4. Sprites 3..0 ($00..$0F ctrl, $80..$9F shape; LSB = leftmost pixel; Sprite 0 on top) */
    for (int s = 3; s >= 0; s--) {
        u8 sy = W.vdc[s * 4 + 0];
        u8 sx = W.vdc[s * 4 + 1];
        u8 sc = W.vdc[s * 4 + 2];
        int zoom = (sc & 0x04u) ? 2 : 1;
        int sh = 16 * zoom;
        int dy = y - (int)sy;
        if (dy < 0 || dy >= sh)
            continue;
        int row = dy / (2 * zoom);
        u8 bits = W.vdc[0x80 + s * 8 + row];
        if (!bits)
            continue;
        int shift = (sc & 0x01u) ? 1 : 0;
        if ((sc & 0x02u) && !(row & 1))
            shift++;
        u16 col = fore_pal[(sc >> 3) & 7u];
        u8 smask = (u8)(1u << s);
        for (int b = 0; b < 8; b++) {
            if (bits & (1u << b)) {
                int px = (int)sx + shift + b * zoom;
                plot_layer(line, px, col, smask);
                if (zoom == 2)
                    plot_layer(line, px + 1, col, smask);
            }
        }
    }
}

/* ---- 8244 24-bit Shift Register + LFSR Audio (48 kHz mono) ---- */
static void audio_step(u32 mcycles)
{
    if (!S.sample_rate || !mcycles)
        return;

    u8 sctrl = W.vdc[0xAA];
    u32 shift_hz = (sctrl & 0x20u) ? 3933u : 983u;

    u32 num = mcycles * S.sample_rate + S.aud_frac;
    u32 n_samp = num / 361560u; /* 262 * 23 * 60 Hz = 361,560 machine cycles/s */
    S.aud_frac = num % 361560u;

    for (u32 i = 0; i < n_samp; i++) {
        s16 out = 0;
        if ((sctrl & 0x80u) && (sctrl & 0x0Fu) && S.shift_bits > 0) {
            S.shift_frac += shift_hz;
            while (S.shift_frac >= S.sample_rate) {
                S.shift_frac -= S.sample_rate;
                u32 bit0 = S.shift_reg & 1u;
                if (sctrl & 0x40u) {
                    S.shift_reg = (S.shift_reg >> 1) | (bit0 << 23);
                } else {
                    S.shift_reg >>= 1;
                    if (S.shift_bits > 0 && --S.shift_bits == 0)
                        S.vdc_stat |= 0x04u; /* sound finished status */
                }
                if (sctrl & 0x10u) {
                    u16 fb = (u16)(((S.noise_lfsr >> 0) ^ (S.noise_lfsr >> 1) ^ (S.noise_lfsr >> 14)) & 1u);
                    S.noise_lfsr = (u16)((S.noise_lfsr >> 1) | (fb << 14));
                }
            }
            u32 sig = S.shift_reg & 1u;
            if (sctrl & 0x10u)
                sig ^= (S.noise_lfsr & 1u);
            s16 amp = (s16)((sctrl & 0x0Fu) * 380);
            out = sig ? amp : (s16)-amp;
        }
        if (S.aud_count < O2_AUD_MAX)
            W.aud_buf[S.aud_count++] = out;
    }
}

void o2_set_bios(const u8 *data, u32 size)
{
    if (data && size == 1024u) {
        for (u32 i = 0; i < 1024u; i++)
            W.ext_bios[i] = data[i];
        S.has_ext_bios = 1;
    } else {
        S.has_ext_bios = 0;
    }
}

const char *o2_load(const u8 *data, u32 size)
{
    if (!data || !size)
        return "empty Odyssey2 cartridge";
    if (size != 2048u && size != 3072u && size != 4096u && size != 8192u && size != 12288u && size != 16384u)
        return "not an Odyssey2 / Videopac ROM (expected 2, 3, 4, 8, 12, or 16 KB)";

    /* Validate reset/IRQ header in active reset bank (Bank 0 on 2K, Bank 1 on 4K, Bank 3 on 8K/12K/16K):
       offset +2 (ext IRQ) or +6 (VSync IRQ) in a real O2/VP cart is an 8048 JMP/CALL/RETR/SEL/NOP, not ASCII/zeros */
    u32 boot_off = (size == 4096u) ? 2048u : (size == 8192u) ? 6144u :
                   (size == 12288u) ? 9216u : (size == 16384u) ? 12288u + 1024u : 0u;
    const u8 *bh = data + boot_off;
    int all_same = 1;
    for (u32 i = 1; i < 16u; i++)
        if (bh[i] != bh[0]) all_same = 0;
    if (all_same)
        return "invalid Odyssey2 ROM header";
    /* At boot_off+0 (RESET vector) an 8048 cart must start with JMP ((op & 0x1F)==0x04), SEL MB, or DIS/ORL/ANL */
    u8 op0 = bh[0];
    if ((op0 & 0x1Fu) != 0x04u && op0 != 0xE5u && op0 != 0xF5u && op0 != 0x15u && op0 != 0x89u && op0 != 0x99u &&
        op0 != 0x00u && op0 != 0x23u && op0 != 0xB8u)
        return "invalid Odyssey2 entry instruction";

    u8 keep_ext = S.has_ext_bios;
    u32 keep_rate = S.sample_rate;
    for (u32 i = 0; i < sizeof(S); i++)
        ((u8 *)&S)[i] = 0;
    S.has_ext_bios = keep_ext;
    S.sample_rate = keep_rate;
    S.cart_size = size;
    for (u32 i = 0; i < size; i++)
        W.cart[i] = data[i];
    build_clean_bios();

    for (int i = 0; i < 64; i++) W.iram[i] = 0;
    for (int i = 0; i < 128; i++) W.eram[i] = 0;
    for (int i = 0; i < 256; i++) W.vdc[i] = 0;

    S.pc = 0x000u;
    S.psw = 0x08u;
    S.p1 = 0xFFu; /* RESET sets all P1/P2 latches HIGH (selects highest bank on 4K/8K carts!) */
    S.p2 = 0xFFu;
    S.bus = 0xFFu;
    S.ext_key = 0xFFu;
    S.boot_wait = 10u; /* brief SELECT GAME splash, then auto-enter Game 1 if no key held */
    S.lfsr_rnd = 0xA5u;
    S.noise_lfsr = 0x7FFFu;

    /* Format info string */
    const char *btag = S.has_ext_bios ? "external o2rom.bin" : "built-in BIOS";
    char *p = S.info_str;
    const char *pre = "Odyssey2 / Videopac G7000, ";
    while (*pre) *p++ = *pre++;
    u32 kb = size >> 10;
    if (kb >= 10u) *p++ = (char)('0' + kb / 10u);
    *p++ = (char)('0' + kb % 10u);
    const char *mid = " KB ROM (";
    while (*mid) *p++ = *mid++;
    while (*btag) *p++ = *btag++;
    *p++ = ')';
    *p = 0;
    return 0;
}

const char *o2_info(void) { return S.info_str; }
void o2_set_key(u8 key) { S.ext_key = key; }
int o2_jammed(void) { return S.jammed; }
u8 *o2_save_ram(u32 *size, int *battery) { *size = 0; *battery = 0; return 0; }
int o2_save_changed(void) { return 0; }
void o2_audio_rate(u32 hz) { S.sample_rate = hz; S.aud_frac = 0; S.shift_frac = 0; }

int o2_audio(s16 *out, int max)
{
    int n = (int)S.aud_count < max ? (int)S.aud_count : max;
    for (int i = 0; i < n; i++)
        out[i] = W.aud_buf[i];
    S.aud_count = 0;
    return n;
}

void o2_frame(u16 pad, u16 *picture)
{
    S.pad = pad;
    S.aud_count = 0;

    for (int y = 0; y < O2_LINES; y++) {
        S.scan_y = y;
        if (y == O2_VBL_LINE) {
            S.vdc_stat |= 0x08u;
            if (W.vdc[0xA0] & 0x01u)
                S.ext_irq = 1;
        } else if (y == 0) {
            S.vdc_stat &= (u8)~0x08u;
        }

        int cyc = 0;
        int rendered = (y >= O2_H);
        while (cyc < O2_CYC_LINE) {
            S.line_cyc = cyc;
            int t1 = (y >= O2_VBL_LINE || cyc >= O2_HBL_START) ? 1 : 0;
            if (!rendered && cyc >= O2_HBL_START) {
                render_scanline(y, picture);
                rendered = 1;
            }
            /* Counter mode clocks on T1 falling edge (1 -> 0) */
            if (S.t_mode == 2 && S.t1_prev && !t1) {
                if (++S.t == 0u) {
                    S.tf = 1;
                    if (S.tcnti) S.tim_irq = 1;
                }
            }
            S.t1_prev = (u8)t1;

            int step = cpu_step(t1);
            cyc += step;

            if (S.t_mode == 1) {
                S.t_prescale = (u8)(S.t_prescale + (u8)step);
                while (S.t_prescale >= 32u) {
                    S.t_prescale -= 32u;
                    if (++S.t == 0u) {
                        S.tf = 1;
                        if (S.tcnti) S.tim_irq = 1;
                    }
                }
            }
        }
        if (!rendered)
            render_scanline(y, picture);
        audio_step(O2_CYC_LINE);
    }
}
