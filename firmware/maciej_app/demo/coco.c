/* TRS-80 Color Computer 1/2 (NTSC) & Dragon 32/64 (PAL): see coco.h.
 * Zero static .bss footprint: all RAM, ROM, cartridge, staging and audio buffers live in KSEG0(EMU_RAM_PHYS).
 */
#pragma GCC optimize("O2")
#include "coco.h"

#ifndef COCO_HOST
#include "hw.h"
#endif

#define COCO_CYC_LINE       57u
#define COCO_LINES_NTSC     262u        /* 262 * 57 = 14,934 cycles @ 894,886 Hz = 59.92 Hz */
#define COCO_LINES_PAL      312u        /* 312 * 57 = 17,784 cycles @ 889,200 Hz = 50.00 Hz */
#define COCO_CLOCK_NTSC     894886u
#define COCO_CLOCK_PAL      889200u
#define COCO_RING_LEN       4096u
#define COCO_MAX_DAC_EV     8192u

struct coco_ws {
    u8 ram[0x10000];                    /* 64 KB DRAM */
    u8 rom_exec[0x4000];                /* $8000..$BFFF: Ext/Color BASIC, Dragon 32 ROM, or clean-room Exec */
    u8 rom_cart[0x4000];                /* $C000..$FEFF: Program Pak (.ccc / .rom) */
    u8 stage[0xF000];                   /* Staged .cas / .bin image for clean resets */
    u32 dac_cyc[COCO_MAX_DAC_EV];       /* Cycle timestamps of DAC / 1-bit sound writes */
    s16 dac_lvl[COCO_MAX_DAC_EV];       /* Signed/scaled output level at each write */
    s16 snd_ring[COCO_RING_LEN];
    u16 pal[16];
};

#ifdef COCO_HOST
static struct coco_ws coco_host_ws;
#define WS (&coco_host_ws)
#else
#define WS ((struct coco_ws *)KSEG0(EMU_RAM_PHYS))
#endif

#define RGB15_CC(r, g, b) ((u16)((((r) >> 3) & 31u) | ((((g) >> 3) & 31u) << 5) | ((((b) >> 3) & 31u) << 10)))

/* Palette indices:
 * 0..7:  MC6847 Graphics (Green, Yellow, Blue, Red, Buff, Cyan, Magenta, Orange)
 * 8..12: Alnum Green, Dark Green, Alnum Orange, Dark Orange, Black
 * 13..15: CoCo NTSC RG6 Artifact Blue, Artifact Orange, Artifact White
 */
static const u8 coco_pal_rgb[16][3] = {
    { 28, 220,  24}, /*  0: Green */
    {235, 228,  24}, /*  1: Yellow */
    { 24,  48, 235}, /*  2: Blue */
    {224,  36,  20}, /*  3: Red */
    {232, 238, 240}, /*  4: Buff (White) */
    { 24, 212, 224}, /*  5: Cyan */
    {216,  56, 228}, /*  6: Magenta */
    {238, 108,  20}, /*  7: Orange */
    { 32, 232,  28}, /*  8: Alnum Bright Green */
    {  0,  36,   0}, /*  9: Alnum Dark Green */
    {238, 108,  20}, /* 10: Alnum Bright Orange */
    { 36,  14,   0}, /* 11: Alnum Dark Orange */
    { 12,  12,  12}, /* 12: Black */
    { 20, 148, 255}, /* 13: NTSC Artifact Blue (01) */
    {255,  96,  20}, /* 14: NTSC Artifact Orange (10) */
    {255, 255, 255}, /* 15: NTSC Artifact White (11) */
};

/* Authentic MC6847 internal 64x12 character generator ROM */
static const u8 mc6847_font[64 * 12] = {
    0x00,0x00,0x00,0x1C,0x22,0x02,0x1A,0x2A,0x2A,0x1C,0x00,0x00, /* @ */
    0x00,0x00,0x00,0x08,0x14,0x22,0x22,0x3E,0x22,0x22,0x00,0x00, /* A */
    0x00,0x00,0x00,0x3C,0x12,0x12,0x1C,0x12,0x12,0x3C,0x00,0x00, /* B */
    0x00,0x00,0x00,0x1C,0x22,0x20,0x20,0x20,0x22,0x1C,0x00,0x00, /* C */
    0x00,0x00,0x00,0x3C,0x12,0x12,0x12,0x12,0x12,0x3C,0x00,0x00, /* D */
    0x00,0x00,0x00,0x3E,0x20,0x20,0x38,0x20,0x20,0x3E,0x00,0x00, /* E */
    0x00,0x00,0x00,0x3E,0x20,0x20,0x38,0x20,0x20,0x20,0x00,0x00, /* F */
    0x00,0x00,0x00,0x1E,0x20,0x20,0x26,0x22,0x22,0x1E,0x00,0x00, /* G */
    0x00,0x00,0x00,0x22,0x22,0x22,0x3E,0x22,0x22,0x22,0x00,0x00, /* H */
    0x00,0x00,0x00,0x1C,0x08,0x08,0x08,0x08,0x08,0x1C,0x00,0x00, /* I */
    0x00,0x00,0x00,0x02,0x02,0x02,0x02,0x22,0x22,0x1C,0x00,0x00, /* J */
    0x00,0x00,0x00,0x22,0x24,0x28,0x30,0x28,0x24,0x22,0x00,0x00, /* K */
    0x00,0x00,0x00,0x20,0x20,0x20,0x20,0x20,0x20,0x3E,0x00,0x00, /* L */
    0x00,0x00,0x00,0x22,0x36,0x2A,0x2A,0x22,0x22,0x22,0x00,0x00, /* M */
    0x00,0x00,0x00,0x22,0x32,0x2A,0x26,0x22,0x22,0x22,0x00,0x00, /* N */
    0x00,0x00,0x00,0x3E,0x22,0x22,0x22,0x22,0x22,0x3E,0x00,0x00, /* O */
    0x00,0x00,0x00,0x3C,0x22,0x22,0x3C,0x20,0x20,0x20,0x00,0x00, /* P */
    0x00,0x00,0x00,0x1C,0x22,0x22,0x22,0x2A,0x24,0x1A,0x00,0x00, /* Q */
    0x00,0x00,0x00,0x3C,0x22,0x22,0x3C,0x28,0x24,0x22,0x00,0x00, /* R */
    0x00,0x00,0x00,0x1C,0x22,0x10,0x08,0x04,0x22,0x1C,0x00,0x00, /* S */
    0x00,0x00,0x00,0x3E,0x08,0x08,0x08,0x08,0x08,0x08,0x00,0x00, /* T */
    0x00,0x00,0x00,0x22,0x22,0x22,0x22,0x22,0x22,0x1C,0x00,0x00, /* U */
    0x00,0x00,0x00,0x22,0x22,0x22,0x14,0x14,0x08,0x08,0x00,0x00, /* V */
    0x00,0x00,0x00,0x22,0x22,0x22,0x2A,0x2A,0x36,0x22,0x00,0x00, /* W */
    0x00,0x00,0x00,0x22,0x22,0x14,0x08,0x14,0x22,0x22,0x00,0x00, /* X */
    0x00,0x00,0x00,0x22,0x22,0x14,0x08,0x08,0x08,0x08,0x00,0x00, /* Y */
    0x00,0x00,0x00,0x3E,0x02,0x04,0x08,0x10,0x20,0x3E,0x00,0x00, /* Z */
    0x00,0x00,0x00,0x38,0x20,0x20,0x20,0x20,0x20,0x38,0x00,0x00, /* [ */
    0x00,0x00,0x00,0x20,0x20,0x10,0x08,0x04,0x02,0x02,0x00,0x00, /* \ */
    0x00,0x00,0x00,0x0E,0x02,0x02,0x02,0x02,0x02,0x0E,0x00,0x00, /* ] */
    0x00,0x00,0x00,0x08,0x1C,0x2A,0x08,0x08,0x08,0x08,0x00,0x00, /* ^ */
    0x00,0x00,0x00,0x00,0x08,0x10,0x3E,0x10,0x08,0x00,0x00,0x00, /* _ */
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, /*   */
    0x00,0x00,0x00,0x08,0x08,0x08,0x08,0x08,0x00,0x08,0x00,0x00, /* ! */
    0x00,0x00,0x00,0x14,0x14,0x14,0x00,0x00,0x00,0x00,0x00,0x00, /* " */
    0x00,0x00,0x00,0x14,0x14,0x36,0x00,0x36,0x14,0x14,0x00,0x00, /* # */
    0x00,0x00,0x00,0x08,0x1E,0x20,0x1C,0x02,0x3C,0x08,0x00,0x00, /* $ */
    0x00,0x00,0x00,0x32,0x32,0x04,0x08,0x10,0x26,0x26,0x00,0x00, /* % */
    0x00,0x00,0x00,0x10,0x28,0x28,0x10,0x2A,0x24,0x1A,0x00,0x00, /* & */
    0x00,0x00,0x00,0x18,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00, /* ' */
    0x00,0x00,0x00,0x08,0x10,0x20,0x20,0x20,0x10,0x08,0x00,0x00, /* ( */
    0x00,0x00,0x00,0x08,0x04,0x02,0x02,0x02,0x04,0x08,0x00,0x00, /* ) */
    0x00,0x00,0x00,0x00,0x08,0x1C,0x3E,0x1C,0x08,0x00,0x00,0x00, /* * */
    0x00,0x00,0x00,0x00,0x08,0x08,0x3E,0x08,0x08,0x00,0x00,0x00, /* + */
    0x00,0x00,0x00,0x00,0x00,0x00,0x30,0x30,0x10,0x20,0x00,0x00, /* , */
    0x00,0x00,0x00,0x00,0x00,0x00,0x3E,0x00,0x00,0x00,0x00,0x00, /* - */
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x30,0x30,0x00,0x00, /* . */
    0x00,0x00,0x00,0x02,0x02,0x04,0x08,0x10,0x20,0x20,0x00,0x00, /* / */
    0x00,0x00,0x00,0x18,0x24,0x24,0x24,0x24,0x24,0x18,0x00,0x00, /* 0 */
    0x00,0x00,0x00,0x08,0x18,0x08,0x08,0x08,0x08,0x1C,0x00,0x00, /* 1 */
    0x00,0x00,0x00,0x1C,0x22,0x02,0x1C,0x20,0x20,0x3E,0x00,0x00, /* 2 */
    0x00,0x00,0x00,0x1C,0x22,0x02,0x04,0x02,0x22,0x1C,0x00,0x00, /* 3 */
    0x00,0x00,0x00,0x04,0x0C,0x14,0x3E,0x04,0x04,0x04,0x00,0x00, /* 4 */
    0x00,0x00,0x00,0x3E,0x20,0x3C,0x02,0x02,0x22,0x1C,0x00,0x00, /* 5 */
    0x00,0x00,0x00,0x1C,0x20,0x20,0x3C,0x22,0x22,0x1C,0x00,0x00, /* 6 */
    0x00,0x00,0x00,0x3E,0x02,0x04,0x08,0x10,0x20,0x20,0x00,0x00, /* 7 */
    0x00,0x00,0x00,0x1C,0x22,0x22,0x1C,0x22,0x22,0x1C,0x00,0x00, /* 8 */
    0x00,0x00,0x00,0x1C,0x22,0x22,0x1E,0x02,0x02,0x1C,0x00,0x00, /* 9 */
    0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x18,0x18,0x00,0x00,0x00, /* : */
    0x00,0x00,0x00,0x18,0x18,0x00,0x18,0x18,0x08,0x10,0x00,0x00, /* ; */
    0x00,0x00,0x00,0x04,0x08,0x10,0x20,0x10,0x08,0x04,0x00,0x00, /* < */
    0x00,0x00,0x00,0x00,0x00,0x3E,0x00,0x3E,0x00,0x00,0x00,0x00, /* = */
    0x00,0x00,0x00,0x10,0x08,0x04,0x02,0x04,0x08,0x10,0x00,0x00, /* > */
    0x00,0x00,0x00,0x18,0x24,0x04,0x08,0x08,0x00,0x08,0x00,0x00, /* ? */
};

struct pia6821 {
    u8 ora, ddra, cra;
    u8 orb, ddrb, crb;
};

#define MEDIA_NONE  0
#define MEDIA_CART  1
#define MEDIA_BIN   2
#define MEDIA_CAS   3

static struct {
    /* Motorola MC6809 CPU */
    u8 a, b, dp, cc;
    u16 x, y, u, s, pc;
    u8 jam, cwai, sync_wait, nmi_armed, nmi_pend;
    u32 cyc, total_frames;

    /* Machine & Media */
    u8 is_dragon;
    u8 use_ext_rom;
    u8 media_kind;
    u32 stage_len;
    u16 auto_exec;

    /* SAM (MC6883) & PIAs (2 x MC6821) */
    u16 sam;
    struct pia6821 pia0, pia1;

    /* Keyboard (7 rows x 8 cols in CoCo layout; Dragon remaps rows) & Joysticks */
    u8 usb_kbd_row[7];
    u8 kbd_row[7];                      /* bit c = 1 when key (row, col c) is pressed */
    u8 joy_axis[4];                     /* 0..63: [0]=RX, [1]=RY, [2]=LX, [3]=LY */
    u8 joy_btn[2];                      /* Right Fire 1, Right Fire 2 */
    char type_q[512];
    u16 type_head, type_tail;
    u8 type_hold, type_ch;

    /* Built-in Clean-Room BASIC Line Buffer */
    char bas_line[128];
    u8 bas_len;
    u16 cur_pos;                        /* 0..511 offset in $0400 text screen */
    u8 prev_key_asc;
    u8 pmode, pcolor_css;

    /* Audio (cycle-exact 6-bit DAC + 1-bit sound) */
    s16 cur_dac_lvl, snd_held_lvl;
    u32 dac_nev;
    s32 snd_dc;
    u32 snd_hz, snd_rem, snd_head, snd_count;

    char info[96];
} S;

static void cc_zero(void *dst, u32 n)
{
    u8 *p = (u8 *)dst;
    for (u32 i = 0; i < n; i++) p[i] = 0;
}

static void cc_copy(void *dst, const void *src, u32 n)
{
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    for (u32 i = 0; i < n; i++) d[i] = s[i];
}

static void put_s(char **p, const char *end, const char *s)
{
    while (*s && *p < end) *(*p)++ = *s++;
    **p = 0;
}

static void put_u(char **p, const char *end, u32 v)
{
    char d[12]; int n = 0;
    do d[n++] = (char)('0' + (v % 10u)); while (v /= 10u);
    while (n && *p < end) *(*p)++ = d[--n];
    **p = 0;
}

/* ---- Built-In Clean-Room Executive & Interactive Color BASIC Helpers ---- */
static u8 ascii_to_vdg(u8 c)
{
    if (c >= 'a' && c <= 'z') c = (u8)(c - 32u);
    if (c >= 0x40u && c <= 0x5Fu) return c;         /* '@','A'..'Z','['..'_': D6=1 (normal green bg) */
    if (c >= 0x20u && c <= 0x3Fu) return (u8)(c + 0x40u); /* ' '..'?': $60..$7F (normal green bg) */
    return 0x60u;
}

static void vdg_cls(int color)
{
    u8 fill = 0x60u;
    if (color >= 0 && color <= 8)
        fill = (color == 0) ? 0x80u : (u8)(0x8Fu | (((color - 1) & 7) << 4));
    for (int i = 0; i < 512; i++)
        WS->ram[0x0400 + i] = fill;
    S.cur_pos = 0;
    WS->ram[0x0088] = 0x04; WS->ram[0x0089] = 0x00;
}

static void vdg_putc(u8 c)
{
    if (c == 0x08u) {
        if (S.cur_pos > 0) {
            WS->ram[0x0400 + S.cur_pos] = 0x60u;
            S.cur_pos--;
        }
    } else if (c == '\r' || c == '\n') {
        WS->ram[0x0400 + S.cur_pos] = 0x60u;
        S.cur_pos = (u16)(((S.cur_pos >> 5) + 1u) << 5);
    } else if (c >= 0x20u) {
        WS->ram[0x0400 + S.cur_pos++] = ascii_to_vdg(c);
    }
    while (S.cur_pos >= 512u) {
        for (int i = 0; i < 480; i++)
            WS->ram[0x0400 + i] = WS->ram[0x0400 + 32 + i];
        for (int i = 480; i < 512; i++)
            WS->ram[0x0400 + i] = 0x60u;
        S.cur_pos -= 32u;
    }
    WS->ram[0x0088] = (u8)((0x0400u + S.cur_pos) >> 8);
    WS->ram[0x0089] = (u8)((0x0400u + S.cur_pos) & 0xFFu);
}

static void vdg_puts(const char *s)
{
    while (*s) vdg_putc((u8)*s++);
}

static u8 poll_matrix_ascii(void)
{
    static const char map_noshift[7][8] = {
        {'@','A','B','C','D','E','F','G'},
        {'H','I','J','K','L','M','N','O'},
        {'P','Q','R','S','T','U','V','W'},
        {'X','Y','Z', 0 , 0 , 8 , 9 ,' '},
        {'0','1','2','3','4','5','6','7'},
        {'8','9',':',';',',','-','.','/'},
        {'\r',12, 3 , 0 , 0 , 0 , 0 , 0 },
    };
    static const char map_shift[7][8] = {
        {'@','A','B','C','D','E','F','G'},
        {'H','I','J','K','L','M','N','O'},
        {'P','Q','R','S','T','U','V','W'},
        {'X','Y','Z', 0 , 0 , 8 , 9 ,' '},
        {'0','!','"','#','$','%','&','\''},
        {'(',')','*','+','<','=','>','?'},
        {'\r',12, 3 , 0 , 0 , 0 , 0 , 0 },
    };
    int shift = (S.kbd_row[6] & 0x80u) != 0u;
    u8 found = 0;
    for (int r = 0; r < 7 && !found; r++) {
        u8 m = S.kbd_row[r];
        if (!m) continue;
        for (int c = 0; c < 8; c++) {
            if (r == 6 && c == 7) continue;
            if (m & (1u << c)) {
                found = (u8)(shift ? map_shift[r][c] : map_noshift[r][c]);
                if (found) break;
            }
        }
    }
    if (found && found != S.prev_key_asc) {
        S.prev_key_asc = found;
        return found;
    }
    if (!found) S.prev_key_asc = 0;
    return 0;
}

static const char *skip_sp(const char *s) { while (*s == ' ') s++; return s; }

static int parse_atom(const char **ps)
{
    const char *s = skip_sp(*ps);
    int neg = 0;
    if (*s == '-') { neg = 1; s++; }
    else if (*s == '+') { s++; }
    int v = 0;
    if (s[0] == '&' && (s[1] == 'H' || s[1] == 'h')) {
        s += 2;
        while (1) {
            char c = *s;
            if (c >= '0' && c <= '9') v = (v << 4) | (c - '0');
            else if (c >= 'A' && c <= 'F') v = (v << 4) | (c - 'A' + 10);
            else if (c >= 'a' && c <= 'f') v = (v << 4) | (c - 'a' + 10);
            else break;
            s++;
        }
    } else {
        while (*s >= '0' && *s <= '9')
            v = v * 10 + (*s++ - '0');
    }
    *ps = s;
    return neg ? -v : v;
}

static int parse_int_expr(const char **ps)
{
    int lhs = parse_atom(ps);
    while (1) {
        const char *s = skip_sp(*ps);
        char op = *s;
        if (op != '+' && op != '-' && op != '*' && op != '/') break;
        s++;
        *ps = s;
        int rhs = parse_atom(ps);
        if (op == '+') lhs += rhs;
        else if (op == '-') lhs -= rhs;
        else if (op == '*') lhs *= rhs;
        else if (rhs != 0) lhs /= rhs;
    }
    return lhs;
}

static int kw_match(const char **ps, const char *kw)
{
    const char *s = skip_sp(*ps);
    while (*kw) {
        char a = *s++;
        if (a >= 'a' && a <= 'z') a = (char)(a - 32);
        if (a != *kw++) return 0;
    }
    *ps = s;
    return 1;
}

static void record_dac_event(void);

static void exec_basic_stmt(const char *s, u16 *jump_exec)
{
    while (*s) {
        s = skip_sp(s);
        if (!*s) break;
        if (kw_match(&s, "CLS")) {
            s = skip_sp(s);
            int c = -1;
            if (*s >= '0' && *s <= '8') c = parse_int_expr(&s);
            S.pia1.orb &= (u8)~0xF8u;
            S.sam = (u16)((S.sam & ~0x03FFu) | (2u << 3)); /* F=2 ($0400), V=0 */
            vdg_cls(c);
        } else if (kw_match(&s, "PRINT") || kw_match(&s, "?")) {
            int nl = 1;
            while (*s && *s != ':') {
                s = skip_sp(s);
                if (*s == '"') {
                    s++;
                    while (*s && *s != '"') vdg_putc((u8)*s++);
                    if (*s == '"') s++;
                    nl = 1;
                } else if (*s == ';') {
                    s++; nl = 0;
                } else if (*s == ',') {
                    s++; vdg_putc(' '); vdg_putc(' '); nl = 0;
                } else if (*s && *s != ':') {
                    int v = parse_int_expr(&s);
                    char nb[16]; char *np = nb, *ne = nb + 15;
                    if (v < 0) { vdg_putc('-'); v = -v; }
                    put_u(&np, ne, (u32)v);
                    vdg_puts(nb);
                    nl = 1;
                }
            }
            if (nl) vdg_putc('\r');
        } else if (kw_match(&s, "POKE")) {
            int addr = parse_int_expr(&s) & 0xFFFF;
            s = skip_sp(s); if (*s == ',') s++;
            int val = parse_int_expr(&s) & 0xFF;
            if (addr < 0x8000 || (S.sam & 0x8000u)) WS->ram[addr] = (u8)val;
        } else if (kw_match(&s, "PMODE")) {
            int pm = parse_int_expr(&s) & 4;
            S.pmode = (u8)pm;
        } else if (kw_match(&s, "PCLS")) {
            s = skip_sp(s);
            int c = (*s >= '0' && *s <= '9') ? (parse_int_expr(&s) & 3) : 0;
            u8 b = (S.pmode == 4) ? (c ? 0xFFu : 0x00u) : (u8)(c * 0x55u);
            for (u32 i = 0; i < 0x1800u; i++) WS->ram[0x0E00u + i] = b;
        } else if (kw_match(&s, "SCREEN")) {
            int tp = parse_int_expr(&s);
            s = skip_sp(s); if (*s == ',') s++;
            int cs = parse_int_expr(&s) & 1;
            S.pcolor_css = (u8)cs;
            if (tp == 0) {
                S.pia1.orb = (u8)(cs ? 0x08u : 0x00u);
                S.sam = (u16)((S.sam & ~0x03FFu) | (2u << 3));
            } else {
                /* Graphics page at $0E00 (F = 7): PMODE 4 -> RG6 ($F0), else CG6 ($E0) */
                u8 vdg_b = (S.pmode == 4) ? 0xF0u : 0xE0u;
                if (cs) vdg_b |= 0x08u;
                S.pia1.orb = vdg_b;
                S.sam = (u16)((S.sam & ~0x03FFu) | 6u | (7u << 3));
            }
        } else if (kw_match(&s, "SOUND")) {
            int tone = parse_int_expr(&s) & 255;
            s = skip_sp(s); if (*s == ',') s++;
            int dur = parse_int_expr(&s);
            if (dur < 1) dur = 1;
            if (dur > 20) dur = 20;
            u32 half_per = (u32)(260 - tone) * 2u;
            if (half_per < 20u) half_per = 20u;
            S.pia1.crb |= 0x08u;
            for (u32 c = 0; c < (u32)dur * 700u && c + half_per < 14000u; c += half_per) {
                S.cyc = c;
                S.pia1.ora = (S.pia1.ora == 0xFCu) ? 0x00u : 0xFCu;
                record_dac_event();
            }
        } else if (kw_match(&s, "EXEC")) {
            s = skip_sp(s);
            u16 a = S.auto_exec ? S.auto_exec : 0x2000u;
            if (*s && *s != ':') a = (u16)(parse_int_expr(&s) & 0xFFFF);
            *jump_exec = a;
            return;
        } else {
            while (*s && *s != ':') s++;
        }
        if (*s == ':') s++;
    }
}

/* Load staged .bin or .cas into RAM and return entry point */
static u16 load_staged_program(int *is_ml_out)
{
    *is_ml_out = 0;
    if (S.media_kind == MEDIA_CART) {
        *is_ml_out = 1;
        return 0xC000u;
    }
    if (S.media_kind == MEDIA_BIN) {
        const u8 *p = WS->stage;
        u32 rem = S.stage_len;
        /* DragonDOS 9-byte binary header: 55 ftype load_hi load_lo len_hi len_lo exec_hi exec_lo AA */
        if (rem > 9u && p[0] == 0x55u && p[8] == 0xAAu) {
            u16 ld = ((u16)p[2] << 8) | p[3];
            u16 ln = ((u16)p[4] << 8) | p[5];
            u16 ex = ((u16)p[6] << 8) | p[7];
            if ((u32)ln + 9u <= rem) {
                for (u32 i = 0; i < ln; i++) WS->ram[(ld + i) & 0xFFFFu] = p[9u + i];
                *is_ml_out = 1;
                return ex;
            }
        }
        /* CoCo Disk BASIC segmented .BIN: [00 len_hi len_lo addr_hi addr_lo data...] ... [FF 00 00 exec_hi exec_lo] */
        u32 pos = 0;
        u16 exec_a = 0x2000u;
        int segs = 0;
        while (pos + 5u <= rem) {
            u8 tag = p[pos];
            u16 ln = ((u16)p[pos + 1u] << 8) | p[pos + 2u];
            u16 ad = ((u16)p[pos + 3u] << 8) | p[pos + 4u];
            pos += 5u;
            if (tag == 0x00u && pos + ln <= rem) {
                if (segs == 0) exec_a = ad;
                for (u16 i = 0; i < ln; i++) WS->ram[(ad + i) & 0xFFFFu] = p[pos + i];
                pos += ln;
                segs++;
            } else if (tag == 0xFFu) {
                exec_a = ad;
                segs++;
                break;
            } else {
                segs = 0;
                break;
            }
        }
        if (segs > 0) {
            *is_ml_out = 1;
            return exec_a;
        }
        /* Fallback raw binary at $2000 */
        u32 n = rem > 0x6000u ? 0x6000u : rem;
        for (u32 i = 0; i < n; i++) WS->ram[0x2000u + i] = p[i];
        *is_ml_out = 1;
        return 0x2000u;
    }
    if (S.media_kind == MEDIA_CAS) {
        const u8 *p = WS->stage;
        u32 len = S.stage_len, i = 0;
        u8 ftype = 2, gap = 0;
        u16 load_a = 0x2000u, exec_a = 0x2000u, cur_a = 0x2000u;
        int got_ml = 0;
        /* Scan all cassette blocks; if a BASIC loader precedes an ML file on the same tape, load the ML file! */
        while (i + 4u <= len) {
            if (p[i] != 0x3Cu || (i > 0 && p[i - 1u] != 0x55u)) {
                i++;
                continue;
            }
            u8 btype = p[i + 1u];
            u8 blen  = p[i + 2u];
            if (i + 4u + blen > len) break;
            const u8 *bd = p + i + 3u;
            if (btype == 0x00u && blen >= 15u) {
                ftype  = bd[8];
                gap    = bd[10];
                exec_a = ((u16)bd[11] << 8) | bd[12];
                load_a = ((u16)bd[13] << 8) | bd[14];
                cur_a  = (ftype == 0) ? 0x2601u : load_a;
            } else if (btype == 0x01u) {
                if (ftype == 2 && gap == 0xFFu) {
                    /* Segmented ML blocks inside cassette data */
                    u32 k = 0;
                    while (k + 5u <= blen) {
                        u8 tg = bd[k];
                        u16 sl = ((u16)bd[k + 1u] << 8) | bd[k + 2u];
                        u16 sa = ((u16)bd[k + 3u] << 8) | bd[k + 4u];
                        k += 5u;
                        if (tg == 0x00u && k + sl <= blen) {
                            for (u16 m = 0; m < sl; m++) WS->ram[(sa + m) & 0xFFFFu] = bd[k + m];
                            k += sl;
                            got_ml = 1;
                        } else if (tg == 0xFFu) {
                            exec_a = sa;
                            got_ml = 1;
                            break;
                        } else break;
                    }
                } else {
                    for (u8 m = 0; m < blen; m++)
                        WS->ram[(cur_a + m) & 0xFFFFu] = bd[m];
                    cur_a = (u16)(cur_a + blen);
                    if (ftype == 2) got_ml = 1;
                }
            } else if (btype == 0xFFu) {
                if (got_ml) break;
            }
            i += 4u + blen;
        }
        if (got_ml) {
            *is_ml_out = 1;
            return exec_a;
        }
    }
    return 0;
}

static void build_cleanroom_rom(void)
{
    for (u32 i = 0; i < sizeof(WS->rom_exec); i++)
        WS->rom_exec[i] = 0x12u;        /* 6809 NOP */

    /* CoCo Indirect ROM Jump Table at $A000..$A00B (offset 0x2000 in rom_exec):
     * [$A000] = POLCAT ($A140), [$A002] = CHROUT ($A150), [$A00A] = JOYIN ($A160)
     */
    WS->rom_exec[0x2000] = 0xA1; WS->rom_exec[0x2001] = 0x40;
    WS->rom_exec[0x2002] = 0xA1; WS->rom_exec[0x2003] = 0x50;
    WS->rom_exec[0x2004] = 0xA1; WS->rom_exec[0x2005] = 0x70;
    WS->rom_exec[0x2006] = 0xA1; WS->rom_exec[0x2007] = 0x70;
    WS->rom_exec[0x2008] = 0xA1; WS->rom_exec[0x2009] = 0x70;
    WS->rom_exec[0x200A] = 0xA1; WS->rom_exec[0x200B] = 0x60;

    /* $A100: Default PIA0 VSync IRQ service routine (jumped to via $010C: 7E A1 00!) */
    static const u8 irq_srv[] = {
        0xB6, 0xFF, 0x03,   /* LDA $FF03 */
        0x2A, 0x0C,         /* BPL +12 */
        0xB6, 0xFF, 0x02,   /* LDA $FF02 (acknowledge PIA0 CB1 VSync IRQ!) */
        0xFC, 0x01, 0x12,   /* LDD $0112 (CoCo 16-bit TIMER) */
        0xC3, 0x00, 0x01,   /* ADDD #$0001 */
        0xFD, 0x01, 0x12,   /* STD $0112 */
        0x3B                /* RTI */
    };
    cc_copy(WS->rom_exec + 0x2100, irq_srv, sizeof(irq_srv));

    /* $A120: Default FIRQ service routine (jumped to via $010F: 7E A1 20) */
    static const u8 firq_srv[] = { 0xB6, 0xFF, 0x22, 0x3B };
    cc_copy(WS->rom_exec + 0x2120, firq_srv, sizeof(firq_srv));

    /* $A140: POLCAT: LDA $FF58 ; TSTA ; RTS */
    static const u8 polcat_srv[] = { 0xB6, 0xFF, 0x58, 0x4D, 0x39 };
    cc_copy(WS->rom_exec + 0x2140, polcat_srv, sizeof(polcat_srv));

    /* $A150: CHROUT: STA $FF59 ; RTS */
    static const u8 chrout_srv[] = { 0xB7, 0xFF, 0x59, 0x39 };
    cc_copy(WS->rom_exec + 0x2150, chrout_srv, sizeof(chrout_srv));

    /* $A160: JOYIN: STA $FF5A ; RTS */
    static const u8 joyin_srv[] = { 0xB7, 0xFF, 0x5A, 0x39 };
    cc_copy(WS->rom_exec + 0x2160, joyin_srv, sizeof(joyin_srv));

    /* $A170: Generic RTS */
    WS->rom_exec[0x2170] = 0x39;

    /* $A200: Hardware RESET entry + Interactive Color BASIC Executive Loop */
    static const u8 reset_srv[] = {
        0x1A, 0x50,         /* ORCC #$50 (mask IRQ + FIRQ) */
        0x10, 0xCE, 0x7F, 0x00, /* LDS #$7F00 */
        0x4F, 0x1F, 0x8B,   /* CLRA ; TFR A,DP */
        /* Init PIA0 ($FF00..$FF03): PA=input, PB=output, CB1 VSync IRQ enabled ($35) */
        0x7F, 0xFF, 0x01,   /* CLR $FF01 */
        0x7F, 0xFF, 0x00,   /* CLR $FF00 */
        0x86, 0x34, 0xB7, 0xFF, 0x01, /* LDA #$34 ; STA $FF01 */
        0x7F, 0xFF, 0x03,   /* CLR $FF03 */
        0x86, 0xFF, 0xB7, 0xFF, 0x02, /* LDA #$FF ; STA $FF02 (DDRB) */
        0x86, 0x35, 0xB7, 0xFF, 0x03, /* LDA #$35 ; STA $FF03 (CB1 FSync IRQ on!) */
        0x86, 0xFF, 0xB7, 0xFF, 0x02, /* LDA #$FF ; STA $FF02 */
        /* Init PIA1 ($FF20..$FF23): PA7..2=DAC out ($FC), PB7..3,1=VDG/snd out ($FA), CB2 sound enable ($3C) */
        0x7F, 0xFF, 0x21,
        0x86, 0xFC, 0xB7, 0xFF, 0x20,
        0x86, 0x34, 0xB7, 0xFF, 0x21,
        0x7F, 0xFF, 0x23,
        0x86, 0xFA, 0xB7, 0xFF, 0x22,
        0x86, 0x3C, 0xB7, 0xFF, 0x23,
        0x7F, 0xFF, 0x22,   /* Text mode ($00) */
        /* Set RAM IRQ ($010C) -> JMP $A100, FIRQ ($010F) -> JMP $A120 */
        0x86, 0x7E, 0xB7, 0x01, 0x0C, 0xB7, 0x01, 0x0F,
        0x8E, 0xA1, 0x00, 0xBF, 0x01, 0x0D,
        0x8E, 0xA1, 0x20, 0xBF, 0x01, 0x10,
        /* Enable IRQ & FIRQ, then invoke boot/program dispatcher ($FF5B) */
        0x1C, 0xAF,         /* ANDCC #$AF */
        0xB7, 0xFF, 0x5B,   /* STA $FF5B (if ML/cart loaded, sets PC = entry; else prints BASIC banner) */
        /* Interactive Color BASIC idle/poll loop: poll $FF5C, wait for VSync IRQ */
        0xB7, 0xFF, 0x5C,   /* loop: STA $FF5C */
        0x3C, 0xEF,         /* CWAI #$EF */
        0x20, 0xF9          /* BRA loop (-7) */
    };
    cc_copy(WS->rom_exec + 0x2200, reset_srv, sizeof(reset_srv));

    /* 6809 Hardware Vectors at $BFF2..$BFFF (mirrored by SAM at $FFF2..$FFFF) */
    WS->rom_exec[0x3FF2] = 0x01; WS->rom_exec[0x3FF3] = 0x03; /* SWI3 -> $0103 */
    WS->rom_exec[0x3FF4] = 0x01; WS->rom_exec[0x3FF5] = 0x00; /* SWI2 -> $0100 */
    WS->rom_exec[0x3FF6] = 0x01; WS->rom_exec[0x3FF7] = 0x0F; /* FIRQ -> $010F */
    WS->rom_exec[0x3FF8] = 0x01; WS->rom_exec[0x3FF9] = 0x0C; /* IRQ  -> $010C */
    WS->rom_exec[0x3FFA] = 0x01; WS->rom_exec[0x3FFB] = 0x06; /* SWI  -> $0106 */
    WS->rom_exec[0x3FFC] = 0x01; WS->rom_exec[0x3FFD] = 0x09; /* NMI  -> $0109 */
    WS->rom_exec[0x3FFE] = 0xA2; WS->rom_exec[0x3FFF] = 0x00; /* RESET-> $A200 */
}

/* ---- Audio Event Capture & Synthesis ---- */
static void record_dac_event(void)
{
    /* Compute composite CoCo audio output from 6-bit DAC ($FF20 bits 7..2) + 1-bit sound ($FF22 bit 1) */
    u8 dac6 = (u8)(((S.pia1.ora & S.pia1.ddra) | (~S.pia1.ddra & 0xFCu)) >> 2);
    u8 sbit = (u8)(((S.pia1.orb & S.pia1.ddrb) >> 1) & 1u);
    int snd_en = (S.pia1.crb & 0x08u) != 0u; /* PIA1 CB2 sound mux enable */
    s16 lvl = (s16)((snd_en ? ((s32)dac6 * 280) : ((s32)dac6 * 90)) + ((s32)sbit * 6000));
    if (lvl == S.cur_dac_lvl) return;
    S.cur_dac_lvl = lvl;
    if (S.dac_nev < COCO_MAX_DAC_EV) {
        WS->dac_cyc[S.dac_nev] = S.cyc;
        WS->dac_lvl[S.dac_nev] = lvl;
        S.dac_nev++;
    }
}

/* ---- PIA & SAM Memory-Mapped I/O ($FF00..$FFFF) ---- */
static inline int pia_irq_active(const struct pia6821 *p)
{
    return (((p->cra & 0x80u) && (p->cra & 0x01u)) ||
            ((p->cra & 0x40u) && (p->cra & 0x08u)) ||
            ((p->crb & 0x80u) && (p->crb & 0x01u)) ||
            ((p->crb & 0x40u) && (p->crb & 0x08u)));
}

static u8 pia0_read_pa(void)
{
    static const u8 dragon_rmap[7] = {4, 5, 0, 1, 2, 3, 6};
    /* Active-low column strobe on PIA0 PB ($FF02) */
    u8 pb_out = (u8)((S.pia0.orb & S.pia0.ddrb) | (~S.pia0.ddrb & 0xFFu));
    u8 active_cols = (u8)(~pb_out);
    u8 pa_in = 0x7Fu;

    for (int r = 0; r < 7; r++) {
        u8 src_r = S.is_dragon ? dragon_rmap[r] : (u8)r;
        if (S.kbd_row[src_r] & active_cols)
            pa_in &= (u8)~(1u << r);
    }

    /* Joystick fire buttons pull PA0 / PA1 low when keyboard columns aren't strobed (or on Dragon/CoCo button test) */
    if (active_cols == 0u || active_cols == 0xFFu) {
        if (S.joy_btn[0]) pa_in &= (u8)~0x01u;
        if (S.joy_btn[1]) pa_in &= (u8)~0x02u;
    }

    /* Analog Joystick Comparator on PA7: CA2 selects X/Y, CB2 selects Right/Left */
    int ca2 = ((S.pia0.cra >> 3) & 1u) != 0u;
    int cb2 = ((S.pia0.crb >> 3) & 1u) != 0u;
    u8 joy_v = S.joy_axis[(cb2 ? 2 : 0) + (ca2 ? 1 : 0)];
    u8 dac_v = (u8)(((S.pia1.ora & S.pia1.ddra) >> 2) & 63u);
    if (joy_v >= dac_v)
        pa_in |= 0x80u;

    return (u8)((S.pia0.ora & S.pia0.ddra) | (pa_in & ~S.pia0.ddra));
}

static __attribute__((noinline)) u8 io_read(u16 addr)
{
    if (addr >= 0xFFF0u) {
        return (S.sam & 0x8000u) ? WS->ram[0xBFF0u + (addr & 15u)]
                                 : WS->rom_exec[0x3FF0u + (addr & 15u)];
    }
    if (addr < 0xFF20u) {               /* PIA0 ($FF00..$FF1F mirrored) */
        switch (addr & 3u) {
        case 0:
            if (S.pia0.cra & 0x04u) { S.pia0.cra &= 0x3Fu; return pia0_read_pa(); }
            return S.pia0.ddra;
        case 1: return S.pia0.cra;
        case 2:
            if (S.pia0.crb & 0x04u) {
                S.pia0.crb &= 0x3Fu;
                return (u8)((S.pia0.orb & S.pia0.ddrb) | (~S.pia0.ddrb & 0xFFu));
            }
            return S.pia0.ddrb;
        case 3: return S.pia0.crb;
        }
    }
    if (addr < 0xFF40u) {               /* PIA1 ($FF20..$FF3F mirrored) */
        switch (addr & 3u) {
        case 0:
            if (S.pia1.cra & 0x04u) {
                S.pia1.cra &= 0x3Fu;
                return (u8)((S.pia1.ora & S.pia1.ddra) | (0x02u & ~S.pia1.ddra));
            }
            return S.pia1.ddra;
        case 1: return S.pia1.cra;
        case 2:
            if (S.pia1.crb & 0x04u) {
                S.pia1.crb &= 0x3Fu;
                /* Bit 2 = 1 indicates 32K/64K RAM installed */
                return (u8)((S.pia1.orb & S.pia1.ddrb) | (0x04u & ~S.pia1.ddrb));
            }
            return S.pia1.ddrb;
        case 3: return S.pia1.crb;
        }
    }
    if (addr == 0xFF58u && !S.use_ext_rom) {
        return poll_matrix_ascii();
    }
    return 0xFFu;
}

static __attribute__((noinline)) void io_write(u16 addr, u8 val)
{
    if (addr < 0xFF20u) {               /* PIA0 */
        switch (addr & 3u) {
        case 0: if (S.pia0.cra & 0x04u) S.pia0.ora = val; else S.pia0.ddra = val; break;
        case 1: S.pia0.cra = (u8)((S.pia0.cra & 0xC0u) | (val & 0x3Fu)); break;
        case 2: if (S.pia0.crb & 0x04u) S.pia0.orb = val; else S.pia0.ddrb = val; break;
        case 3: S.pia0.crb = (u8)((S.pia0.crb & 0xC0u) | (val & 0x3Fu)); break;
        }
        return;
    }
    if (addr < 0xFF40u) {               /* PIA1 */
        switch (addr & 3u) {
        case 0:
            if (S.pia1.cra & 0x04u) { S.pia1.ora = val; record_dac_event(); }
            else S.pia1.ddra = val;
            break;
        case 1: S.pia1.cra = (u8)((S.pia1.cra & 0xC0u) | (val & 0x3Fu)); break;
        case 2:
            if (S.pia1.crb & 0x04u) { S.pia1.orb = val; record_dac_event(); }
            else S.pia1.ddrb = val;
            break;
        case 3:
            S.pia1.crb = (u8)((S.pia1.crb & 0xC0u) | (val & 0x3Fu));
            record_dac_event();
            break;
        }
        return;
    }
    if (addr >= 0xFF58u && addr <= 0xFF5Cu && !S.use_ext_rom) {
        if (addr == 0xFF59u) {
            vdg_putc(S.a);
        } else if (addr == 0xFF5Au) {
            WS->ram[0x015A] = S.joy_axis[0];
            WS->ram[0x015B] = S.joy_axis[1];
            WS->ram[0x015C] = S.joy_axis[2];
            WS->ram[0x015D] = S.joy_axis[3];
        } else if (addr == 0xFF5Bu) {
            vdg_cls(-1);
            int is_ml = 0;
            u16 entry = load_staged_program(&is_ml);
            if (is_ml) {
                S.auto_exec = entry;
                S.pc = entry;
            } else {
                vdg_puts(S.is_dragon ? "DRAGON 64K BASIC\r(C) CLEAN-ROOM EXEC\r\rOK\r"
                                     : "COLOR BASIC 64K\r(C) CLEAN-ROOM EXEC\r\rOK\r");
                WS->ram[0x0400 + S.cur_pos] = 0x20u; /* solid cursor */
            }
        } else if (addr == 0xFF5Cu) {
            u8 k = poll_matrix_ascii();
            if (k) {
                if (k == '\r') {
                    WS->ram[0x0400 + S.cur_pos] = 0x60u;
                    vdg_putc('\r');
                    S.bas_line[S.bas_len] = 0;
                    S.bas_len = 0;
                    u16 jmp = 0;
                    const char *ln = skip_sp(S.bas_line);
                    /* Strip optional line number for immediate execution */
                    while (*ln >= '0' && *ln <= '9') ln++;
                    exec_basic_stmt(ln, &jmp);
                    if (jmp) {
                        S.pc = jmp;
                        return;
                    }
                    if ((S.pia1.orb & 0x80u) == 0u) {
                        vdg_puts("OK\r");
                        WS->ram[0x0400 + S.cur_pos] = 0x20u;
                    }
                } else if (k == 0x08u) {
                    if (S.bas_len > 0) { S.bas_len--; vdg_putc(0x08u); WS->ram[0x0400 + S.cur_pos] = 0x20u; }
                } else if (k == 12u) {
                    S.bas_len = 0; vdg_cls(-1); vdg_puts("OK\r"); WS->ram[0x0400 + S.cur_pos] = 0x20u;
                } else if (k >= 0x20u && S.bas_len < sizeof(S.bas_line) - 1u) {
                    S.bas_line[S.bas_len++] = (char)k;
                    vdg_putc(k);
                    WS->ram[0x0400 + S.cur_pos] = 0x20u;
                }
            }
        }
        return;
    }
    if (addr >= 0xFFC0u && addr <= 0xFFDFu) {
        u16 bit = (u16)(1u << ((addr - 0xFFC0u) >> 1));
        if (addr & 1u) S.sam |= bit;
        else           S.sam &= (u16)~bit;
    }
}

static inline u8 cpu_rd(u16 addr)
{
    if (addr < 0x8000u) return WS->ram[addr];
    if (addr >= 0xFF00u) return io_read(addr);
    if (S.sam & 0x8000u) return WS->ram[addr];
    if (addr < 0xC000u) return WS->rom_exec[addr - 0x8000u];
    return (S.media_kind == MEDIA_CART) ? WS->rom_cart[addr - 0xC000u] : 0xFFu;
}

static inline void cpu_wr(u16 addr, u8 val)
{
    if (addr < 0x8000u) { WS->ram[addr] = val; return; }
    if (addr >= 0xFF00u) { io_write(addr, val); return; }
    if (S.sam & 0x8000u) WS->ram[addr] = val;
}

static inline u16 cpu_rd16(u16 addr)
{
    u8 hi = cpu_rd(addr);
    return (u16)(((u16)hi << 8) | cpu_rd((u16)(addr + 1u)));
}

static inline void cpu_wr16(u16 addr, u16 val)
{
    cpu_wr(addr, (u8)(val >> 8));
    cpu_wr((u16)(addr + 1u), (u8)val);
}

static inline u8 fetch8(void)  { return cpu_rd(S.pc++); }
static inline u16 fetch16(void){ u8 hi = fetch8(); return (u16)(((u16)hi << 8) | fetch8()); }

/* ---- Full Motorola MC6809 CPU Core ---- */
#define CC_C 0x01u
#define CC_V 0x02u
#define CC_Z 0x04u
#define CC_N 0x08u
#define CC_I 0x10u
#define CC_H 0x20u
#define CC_F 0x40u
#define CC_E 0x80u

static inline u16 get_d(void) { return (u16)(((u16)S.a << 8) | S.b); }
static inline void set_d(u16 v) { S.a = (u8)(v >> 8); S.b = (u8)v; }

static inline void nz8(u8 v)
{
    S.cc = (u8)((S.cc & ~(CC_N | CC_Z | CC_V)) | ((v & 0x80u) ? CC_N : 0u) | (v ? 0u : CC_Z));
}

static inline void nz16(u16 v)
{
    S.cc = (u8)((S.cc & ~(CC_N | CC_Z | CC_V)) | ((v & 0x8000u) ? CC_N : 0u) | (v ? 0u : CC_Z));
}

static u8 alu_add8(u8 r, u8 v, u8 c)
{
    u32 res = (u32)r + (u32)v + (u32)c;
    u8 r8 = (u8)res;
    S.cc &= (u8)~(CC_H | CC_N | CC_Z | CC_V | CC_C);
    if (((r & 15u) + (v & 15u) + c) & 16u) S.cc |= CC_H;
    if (r8 & 0x80u) S.cc |= CC_N;
    if (r8 == 0u)   S.cc |= CC_Z;
    if (~(r ^ v) & (r ^ r8) & 0x80u) S.cc |= CC_V;
    if (res > 0xFFu) S.cc |= CC_C;
    return r8;
}

static u8 alu_sub8(u8 r, u8 v, u8 b)
{
    u32 res = (u32)r - (u32)v - (u32)b;
    u8 r8 = (u8)res;
    S.cc &= (u8)~(CC_N | CC_Z | CC_V | CC_C);
    if (r8 & 0x80u) S.cc |= CC_N;
    if (r8 == 0u)   S.cc |= CC_Z;
    if ((r ^ v) & (r ^ r8) & 0x80u) S.cc |= CC_V;
    if (res > 0xFFu) S.cc |= CC_C;
    return r8;
}

static u16 alu_add16(u16 r, u16 v)
{
    u32 res = (u32)r + (u32)v;
    u16 r16 = (u16)res;
    S.cc &= (u8)~(CC_N | CC_Z | CC_V | CC_C);
    if (r16 & 0x8000u) S.cc |= CC_N;
    if (r16 == 0u)     S.cc |= CC_Z;
    if (~(r ^ v) & (r ^ r16) & 0x8000u) S.cc |= CC_V;
    if (res > 0xFFFFu) S.cc |= CC_C;
    return r16;
}

static u16 alu_sub16(u16 r, u16 v)
{
    u32 res = (u32)r - (u32)v;
    u16 r16 = (u16)res;
    S.cc &= (u8)~(CC_N | CC_Z | CC_V | CC_C);
    if (r16 & 0x8000u) S.cc |= CC_N;
    if (r16 == 0u)     S.cc |= CC_Z;
    if ((r ^ v) & (r ^ r16) & 0x8000u) S.cc |= CC_V;
    if (res > 0xFFFFu) S.cc |= CC_C;
    return r16;
}

static u8 rmw_op(u8 sub, u8 v)
{
    u8 r = v, c;
    switch (sub) {
    case 0x0: /* NEG */
        return alu_sub8(0, v, 0);
    case 0x3: /* COM */
        r = (u8)~v; nz8(r); S.cc |= CC_C; return r;
    case 0x4: /* LSR */
        S.cc = (u8)((S.cc & ~(CC_N | CC_Z | CC_C)) | (v & 1u ? CC_C : 0u));
        r = v >> 1; if (!r) S.cc |= CC_Z; return r;
    case 0x6: /* ROR */
        c = (S.cc & CC_C) ? 0x80u : 0u;
        S.cc = (u8)((S.cc & ~(CC_N | CC_Z | CC_C)) | (v & 1u ? CC_C : 0u));
        r = (u8)((v >> 1) | c);
        if (r & 0x80u) S.cc |= CC_N;
        if (!r) S.cc |= CC_Z;
        return r;
    case 0x7: /* ASR */
        S.cc = (u8)((S.cc & ~(CC_N | CC_Z | CC_C)) | (v & 1u ? CC_C : 0u));
        r = (u8)((v & 0x80u) | (v >> 1));
        if (r & 0x80u) S.cc |= CC_N;
        if (!r) S.cc |= CC_Z;
        return r;
    case 0x8: /* ASL */
        S.cc = (u8)((S.cc & ~(CC_N | CC_Z | CC_V | CC_C)) | ((v & 0x80u) ? CC_C : 0u));
        r = (u8)(v << 1);
        if (r & 0x80u) S.cc |= CC_N;
        if (!r) S.cc |= CC_Z;
        if ((v ^ r) & 0x80u) S.cc |= CC_V;
        return r;
    case 0x9: /* ROL */
        c = (S.cc & CC_C) ? 1u : 0u;
        S.cc = (u8)((S.cc & ~(CC_N | CC_Z | CC_V | CC_C)) | ((v & 0x80u) ? CC_C : 0u));
        r = (u8)((v << 1) | c);
        if (r & 0x80u) S.cc |= CC_N;
        if (!r) S.cc |= CC_Z;
        if ((v ^ r) & 0x80u) S.cc |= CC_V;
        return r;
    case 0xA: /* DEC */
        r = (u8)(v - 1u);
        S.cc = (u8)((S.cc & ~(CC_N | CC_Z | CC_V)) | ((r & 0x80u) ? CC_N : 0u) |
                    (r ? 0u : CC_Z) | (v == 0x80u ? CC_V : 0u));
        return r;
    case 0xC: /* INC */
        r = (u8)(v + 1u);
        S.cc = (u8)((S.cc & ~(CC_N | CC_Z | CC_V)) | ((r & 0x80u) ? CC_N : 0u) |
                    (r ? 0u : CC_Z) | (v == 0x7Fu ? CC_V : 0u));
        return r;
    case 0xD: /* TST */
        nz8(v); return v;
    case 0xF: /* CLR */
        S.cc = (u8)((S.cc & ~(CC_N | CC_V | CC_C)) | CC_Z);
        return 0;
    }
    return r;
}

static inline u16 *idx_reg_ptr(u8 rr)
{
    switch (rr & 3u) {
    case 0: return &S.x;
    case 1: return &S.y;
    case 2: return &S.u;
    default: return &S.s;
    }
}

static u16 ea_indexed(u32 *extra)
{
    u8 post = fetch8();
    u16 *rp = idx_reg_ptr(post >> 5);
    if (!(post & 0x80u)) {
        s32 off = (post & 0x10u) ? ((s32)(post & 0x1Fu) - 32) : (s32)(post & 0x1Fu);
        *extra += 1u;
        return (u16)(*rp + off);
    }
    u16 ea = 0;
    int ind = (post & 0x10u) != 0u;
    switch (post & 0x0Fu) {
    case 0x00: ea = *rp; (*rp)++; *extra += 2u; break;
    case 0x01: ea = *rp; (*rp) += 2u; *extra += 3u; break;
    case 0x02: (*rp)--; ea = *rp; *extra += 2u; break;
    case 0x03: (*rp) -= 2u; ea = *rp; *extra += 3u; break;
    case 0x04: ea = *rp; break;
    case 0x05: ea = (u16)(*rp + (signed char)S.b); *extra += 1u; break;
    case 0x06: ea = (u16)(*rp + (signed char)S.a); *extra += 1u; break;
    case 0x08: { s32 o = (signed char)fetch8(); ea = (u16)(*rp + o); *extra += 1u; break; }
    case 0x09: { u16 o = fetch16(); ea = (u16)(*rp + o); *extra += 4u; break; }
    case 0x0B: ea = (u16)(*rp + get_d()); *extra += 4u; break;
    case 0x0C: { s32 o = (signed char)fetch8(); ea = (u16)(S.pc + o); *extra += 1u; break; }
    case 0x0D: { u16 o = fetch16(); ea = (u16)(S.pc + o); *extra += 5u; break; }
    case 0x0F: ea = fetch16(); *extra += 2u; break;
    default:   ea = *rp; break;
    }
    if (ind) {
        ea = cpu_rd16(ea);
        *extra += 3u;
    }
    return ea;
}

static inline void push8_sp(u16 *sp, u8 v)  { cpu_wr(--(*sp), v); }
static inline void push16_sp(u16 *sp, u16 v){ cpu_wr(--(*sp), (u8)v); cpu_wr(--(*sp), (u8)(v >> 8)); }
static inline u8 pull8_sp(u16 *sp)          { return cpu_rd((*sp)++); }
static inline u16 pull16_sp(u16 *sp)        { u8 hi = cpu_rd((*sp)++); return (u16)(((u16)hi << 8) | cpu_rd((*sp)++)); }

static void push_entire_state(void)
{
    S.cc |= CC_E;
    push16_sp(&S.s, S.pc);
    push16_sp(&S.s, S.u);
    push16_sp(&S.s, S.y);
    push16_sp(&S.s, S.x);
    push8_sp(&S.s, S.dp);
    push8_sp(&S.s, S.b);
    push8_sp(&S.s, S.a);
    push8_sp(&S.s, S.cc);
}

static u16 get_tfr_reg(u8 id)
{
    switch (id & 15u) {
    case 0:  return get_d();
    case 1:  return S.x;
    case 2:  return S.y;
    case 3:  return S.u;
    case 4:  return S.s;
    case 5:  return S.pc;
    case 8:  return (u16)(0xFF00u | S.a);
    case 9:  return (u16)(0xFF00u | S.b);
    case 10: return (u16)((S.cc << 8) | S.cc);
    case 11: return (u16)((S.dp << 8) | S.dp);
    default: return 0xFFFFu;
    }
}

static void set_tfr_reg(u8 id, u16 val)
{
    switch (id & 15u) {
    case 0:  set_d(val); break;
    case 1:  S.x = val; break;
    case 2:  S.y = val; break;
    case 3:  S.u = val; break;
    case 4:  S.s = val; S.nmi_armed = 1; break;
    case 5:  S.pc = val; break;
    case 8:  S.a = (u8)val; break;
    case 9:  S.b = (u8)val; break;
    case 10: S.cc = (u8)val; break;
    case 11: S.dp = (u8)val; break;
    }
}

static int cond_true(u8 cond)
{
    int n = (S.cc & CC_N) != 0, v = (S.cc & CC_V) != 0, z = (S.cc & CC_Z) != 0, c = (S.cc & CC_C) != 0;
    switch (cond & 15u) {
    case 0x0: return 1;                 /* BRA */
    case 0x1: return 0;                 /* BRN */
    case 0x2: return !c && !z;          /* BHI */
    case 0x3: return c || z;            /* BLS */
    case 0x4: return !c;                /* BCC / BHS */
    case 0x5: return c;                 /* BCS / BLO */
    case 0x6: return !z;                /* BNE */
    case 0x7: return z;                 /* BEQ */
    case 0x8: return !v;                /* BVC */
    case 0x9: return v;                 /* BVS */
    case 0xA: return !n;                /* BPL */
    case 0xB: return n;                 /* BMI */
    case 0xC: return n == v;            /* BGE */
    case 0xD: return n != v;            /* BLT */
    case 0xE: return !z && (n == v);    /* BGT */
    case 0xF: return z || (n != v);     /* BLE */
    }
    return 0;
}

static u32 cpu_step(void)
{
    if (S.jam) return 4u;

    int irq_on  = pia_irq_active(&S.pia0);
    int firq_on = pia_irq_active(&S.pia1);

    if (S.sync_wait) {
        if (S.nmi_pend || firq_on || irq_on) S.sync_wait = 0;
        else return 2u;
    }

    if (S.nmi_pend && S.nmi_armed) {
        S.nmi_pend = 0;
        if (!S.cwai) push_entire_state();
        S.cwai = 0;
        S.cc |= (CC_I | CC_F);
        S.pc = cpu_rd16(0xFFFCu);
        return 19u;
    }
    if (firq_on && !(S.cc & CC_F)) {
        if (!S.cwai) {
            S.cc &= (u8)~CC_E;
            push16_sp(&S.s, S.pc);
            push8_sp(&S.s, S.cc);
        }
        S.cwai = 0;
        S.cc |= (CC_I | CC_F);
        S.pc = cpu_rd16(0xFFF6u);
        return 10u;
    }
    if (irq_on && !(S.cc & CC_I)) {
        if (!S.cwai) push_entire_state();
        S.cwai = 0;
        S.cc |= CC_I;
        S.pc = cpu_rd16(0xFFF8u);
        return 19u;
    }
    if (S.cwai) return 2u;

    u8 op = fetch8();
    u32 ex = 0;
    u16 ea = 0;

    /* Page 0 Direct / Inherent / Indexed / Extended RMW & JMP ($00..$0F, $40..$7F) */
    if (op < 0x10u || (op >= 0x40u && op < 0x80u)) {
        u8 sub = op & 15u;
        u8 mode = op >> 4;
        if (mode == 4u) {               /* Inherent A */
            if (sub != 0xDu) S.a = rmw_op(sub, S.a);
            else             (void)rmw_op(sub, S.a);
            return 2u;
        }
        if (mode == 5u) {               /* Inherent B */
            if (sub != 0xDu) S.b = rmw_op(sub, S.b);
            else             (void)rmw_op(sub, S.b);
            return 2u;
        }
        if (mode == 0u)      { ea = (u16)(((u16)S.dp << 8) | fetch8()); ex += 4u; }
        else if (mode == 6u) { ea = ea_indexed(&ex); ex += 4u; }
        else                 { ea = fetch16(); ex += 5u; }

        if (sub == 0xEu) {              /* JMP */
            S.pc = ea;
            return ex - 1u;
        }
        if (sub == 0xDu) {              /* TST */
            (void)rmw_op(sub, cpu_rd(ea));
            return ex + 2u;
        }
        if (sub == 0xFu) {              /* CLR */
            (void)cpu_rd(ea);
            cpu_wr(ea, rmw_op(sub, 0));
            return ex + 2u;
        }
        u8 v = rmw_op(sub, cpu_rd(ea));
        cpu_wr(ea, v);
        return ex + 2u;
    }

    /* Short branches ($20..$2F) */
    if (op >= 0x20u && op <= 0x2Fu) {
        s32 off = (signed char)fetch8();
        if (cond_true(op & 15u)) S.pc = (u16)(S.pc + off);
        return 3u;
    }

    /* Page 1 ($10 xx) */
    if (op == 0x10u) {
        u8 op2 = fetch8();
        if (op2 >= 0x21u && op2 <= 0x2Fu) {
            u16 off = fetch16();
            if (cond_true(op2 & 15u)) { S.pc = (u16)(S.pc + off); return 6u; }
            return 5u;
        }
        if (op2 == 0x3Fu) {             /* SWI2 */
            push_entire_state();
            S.pc = cpu_rd16(0xFFF4u);
            return 20u;
        }
        u8 md = op2 >> 4, lo = op2 & 15u;
        u16 val16 = 0;
        if (lo != 0xFu) {
            if (md == 8u || md == 0xCu) { val16 = fetch16(); ex += 5u; }
            else if (md == 9u || md == 0xDu) { ea = (u16)(((u16)S.dp << 8) | fetch8()); val16 = cpu_rd16(ea); ex += 7u; }
            else if (md == 0xAu || md == 0xEu) { ea = ea_indexed(&ex); val16 = cpu_rd16(ea); ex += 7u; }
            else { ea = fetch16(); val16 = cpu_rd16(ea); ex += 8u; }
        } else {
            if (md == 9u || md == 0xDu) { ea = (u16)(((u16)S.dp << 8) | fetch8()); ex += 7u; }
            else if (md == 0xAu || md == 0xEu) { ea = ea_indexed(&ex); ex += 7u; }
            else { ea = fetch16(); ex += 8u; }
        }
        switch (op2) {
        case 0x83: case 0x93: case 0xA3: case 0xB3: (void)alu_sub16(get_d(), val16); return ex;
        case 0x8C: case 0x9C: case 0xAC: case 0xBC: (void)alu_sub16(S.y, val16); return ex;
        case 0x8E: case 0x9E: case 0xAE: case 0xBE: S.y = val16; nz16(S.y); return ex - 1u;
        case 0x9F: case 0xAF: case 0xBF: cpu_wr16(ea, S.y); nz16(S.y); return ex - 1u;
        case 0xCE: case 0xDE: case 0xEE: case 0xFE: S.s = val16; S.nmi_armed = 1; nz16(S.s); return ex - 1u;
        case 0xDF: case 0xEF: case 0xFF: cpu_wr16(ea, S.s); nz16(S.s); return ex - 1u;
        }
        return 4u;
    }

    /* Page 2 ($11 xx) */
    if (op == 0x11u) {
        u8 op2 = fetch8();
        if (op2 == 0x3Fu) {             /* SWI3 */
            push_entire_state();
            S.pc = cpu_rd16(0xFFF2u);
            return 20u;
        }
        u8 md = op2 >> 4;
        u16 val16;
        if (md == 8u)      { val16 = fetch16(); ex += 5u; }
        else if (md == 9u) { ea = (u16)(((u16)S.dp << 8) | fetch8()); val16 = cpu_rd16(ea); ex += 7u; }
        else if (md == 0xAu){ ea = ea_indexed(&ex); val16 = cpu_rd16(ea); ex += 7u; }
        else               { ea = fetch16(); val16 = cpu_rd16(ea); ex += 8u; }
        if ((op2 & 15u) == 3u)      (void)alu_sub16(S.u, val16);
        else if ((op2 & 15u) == 0xCu)(void)alu_sub16(S.s, val16);
        return ex;
    }

    /* Misc Inherent / Stack / LEA ($12..$1F, $30..$3F) */
    switch (op) {
    case 0x12: return 2u;               /* NOP */
    case 0x13: S.sync_wait = 1; return 2u; /* SYNC */
    case 0x16: { u16 o = fetch16(); S.pc = (u16)(S.pc + o); return 5u; } /* LBRA */
    case 0x17: { u16 o = fetch16(); push16_sp(&S.s, S.pc); S.pc = (u16)(S.pc + o); return 9u; } /* LBSR */
    case 0x19: {                        /* DAA */
        u16 corr = 0;
        u8 lsn = S.a & 15u, msn = S.a >> 4;
        if ((S.cc & CC_H) || lsn > 9u) corr |= 0x06u;
        if ((S.cc & CC_C) || msn > 9u || (msn > 8u && lsn > 9u)) corr |= 0x60u;
        u16 sum = (u16)S.a + corr;
        if (sum & 0x100u) S.cc |= CC_C;
        S.a = (u8)sum;
        nz8(S.a);
        return 2u;
    }
    case 0x1A: S.cc |= fetch8(); return 3u;  /* ORCC */
    case 0x1C: S.cc &= fetch8(); return 3u;  /* ANDCC */
    case 0x1D: S.a = (S.b & 0x80u) ? 0xFFu : 0x00u; nz16(get_d()); return 2u; /* SEX */
    case 0x1E: {                        /* EXG */
        u8 pb = fetch8();
        u16 r1 = get_tfr_reg(pb >> 4), r2 = get_tfr_reg(pb & 15u);
        set_tfr_reg(pb >> 4, r2);
        set_tfr_reg(pb & 15u, r1);
        return 8u;
    }
    case 0x1F: {                        /* TFR */
        u8 pb = fetch8();
        set_tfr_reg(pb & 15u, get_tfr_reg(pb >> 4));
        return 6u;
    }
    case 0x30: S.x = ea_indexed(&ex); S.cc = (u8)((S.cc & ~CC_Z) | (S.x ? 0u : CC_Z)); return 4u + ex;
    case 0x31: S.y = ea_indexed(&ex); S.cc = (u8)((S.cc & ~CC_Z) | (S.y ? 0u : CC_Z)); return 4u + ex;
    case 0x32: S.s = ea_indexed(&ex); S.nmi_armed = 1; return 4u + ex;
    case 0x33: S.u = ea_indexed(&ex); return 4u + ex;
    case 0x34: case 0x36: {             /* PSHS / PSHU */
        u8 m = fetch8();
        u16 *sp = (op == 0x34u) ? &S.s : &S.u;
        u16 oth = (op == 0x34u) ? S.u  : S.s;
        u32 c = 5u;
        if (m & 0x80u) { push16_sp(sp, S.pc); c += 2u; }
        if (m & 0x40u) { push16_sp(sp, oth);  c += 2u; }
        if (m & 0x20u) { push16_sp(sp, S.y);  c += 2u; }
        if (m & 0x10u) { push16_sp(sp, S.x);  c += 2u; }
        if (m & 0x08u) { push8_sp(sp, S.dp);  c += 1u; }
        if (m & 0x04u) { push8_sp(sp, S.b);   c += 1u; }
        if (m & 0x02u) { push8_sp(sp, S.a);   c += 1u; }
        if (m & 0x01u) { push8_sp(sp, S.cc);  c += 1u; }
        return c;
    }
    case 0x35: case 0x37: {             /* PULS / PULU */
        u8 m = fetch8();
        u16 *sp  = (op == 0x35u) ? &S.s : &S.u;
        u16 *oth = (op == 0x35u) ? &S.u : &S.s;
        u32 c = 5u;
        if (m & 0x01u) { S.cc = pull8_sp(sp);  c += 1u; }
        if (m & 0x02u) { S.a  = pull8_sp(sp);  c += 1u; }
        if (m & 0x04u) { S.b  = pull8_sp(sp);  c += 1u; }
        if (m & 0x08u) { S.dp = pull8_sp(sp);  c += 1u; }
        if (m & 0x10u) { S.x  = pull16_sp(sp); c += 2u; }
        if (m & 0x20u) { S.y  = pull16_sp(sp); c += 2u; }
        if (m & 0x40u) { *oth = pull16_sp(sp); if (op == 0x37u) S.nmi_armed = 1; c += 2u; }
        if (m & 0x80u) { S.pc = pull16_sp(sp); c += 2u; }
        return c;
    }
    case 0x39: S.pc = pull16_sp(&S.s); return 5u; /* RTS */
    case 0x3A: S.x = (u16)(S.x + S.b); return 3u; /* ABX */
    case 0x3B: {                        /* RTI */
        S.cc = pull8_sp(&S.s);
        if (S.cc & CC_E) {
            S.a  = pull8_sp(&S.s);
            S.b  = pull8_sp(&S.s);
            S.dp = pull8_sp(&S.s);
            S.x  = pull16_sp(&S.s);
            S.y  = pull16_sp(&S.s);
            S.u  = pull16_sp(&S.s);
            S.pc = pull16_sp(&S.s);
            return 15u;
        }
        S.pc = pull16_sp(&S.s);
        return 6u;
    }
    case 0x3C:                          /* CWAI */
        S.cc &= fetch8();
        push_entire_state();
        S.cwai = 1;
        return 20u;
    case 0x3D: {                        /* MUL */
        u16 res = (u16)S.a * (u16)S.b;
        set_d(res);
        S.cc = (u8)((S.cc & ~(CC_Z | CC_C)) | (res ? 0u : CC_Z) | ((S.b & 0x80u) ? CC_C : 0u));
        return 11u;
    }
    case 0x3F:                          /* SWI */
        push_entire_state();
        S.cc |= (CC_I | CC_F);
        S.pc = cpu_rd16(0xFFFAu);
        return 19u;
    }

    /* Register A / B / D / X / U ALU & Load/Store ($80..$FF) */
    if (op == 0x8Du) {                  /* BSR */
        s32 off = (signed char)fetch8();
        push16_sp(&S.s, S.pc);
        S.pc = (u16)(S.pc + off);
        return 7u;
    }

    u8 hi = op >> 4;
    u8 sub = op & 15u;
    int is_b = (hi >= 0xCu);
    u8 md = hi & 3u;                    /* 0=Imm, 1=Direct, 2=Indexed, 3=Extended */

    if (sub == 0xDu && !is_b) {         /* JSR Direct / Indexed / Extended */
        if (md == 1u)      { ea = (u16)(((u16)S.dp << 8) | fetch8()); ex += 7u; }
        else if (md == 2u) { ea = ea_indexed(&ex); ex += 7u; }
        else               { ea = fetch16(); ex += 8u; }
        push16_sp(&S.s, S.pc);
        S.pc = ea;
        return ex;
    }

    /* 16-bit operations: x3 (SUBD/ADDD), xC (CMPX/LDD), xD (STD), xE (LDX/LDU), xF (STX/STU) */
    if (sub == 0x3u || sub == 0xCu || (sub == 0xDu && is_b) || sub == 0xEu || sub == 0xFu) {
        if (sub == 0xFu || (sub == 0xDu && is_b)) {
            if (md == 1u)      { ea = (u16)(((u16)S.dp << 8) | fetch8()); ex += 5u; }
            else if (md == 2u) { ea = ea_indexed(&ex); ex += 5u; }
            else               { ea = fetch16(); ex += 6u; }
            u16 rv = (sub == 0xDu) ? get_d() : (is_b ? S.u : S.x);
            cpu_wr16(ea, rv);
            nz16(rv);
            return ex;
        }
        u16 v16;
        if (md == 0u)      { v16 = fetch16(); ex += 3u; }
        else if (md == 1u) { ea = (u16)(((u16)S.dp << 8) | fetch8()); v16 = cpu_rd16(ea); ex += 5u; }
        else if (md == 2u) { ea = ea_indexed(&ex); v16 = cpu_rd16(ea); ex += 5u; }
        else               { ea = fetch16(); v16 = cpu_rd16(ea); ex += 6u; }

        if (sub == 0x3u) {
            set_d(is_b ? alu_add16(get_d(), v16) : alu_sub16(get_d(), v16));
            return ex + 1u;
        }
        if (sub == 0xCu) {
            if (is_b) { set_d(v16); nz16(v16); return ex; }
            (void)alu_sub16(S.x, v16);
            return ex + 1u;
        }
        if (is_b) { S.u = v16; nz16(S.u); }
        else      { S.x = v16; nz16(S.x); }
        return ex;
    }

    /* 8-bit operations on A or B */
    u8 *reg = is_b ? &S.b : &S.a;
    if (sub == 0x7u) {                  /* STA / STB */
        if (md == 1u)      { ea = (u16)(((u16)S.dp << 8) | fetch8()); ex += 4u; }
        else if (md == 2u) { ea = ea_indexed(&ex); ex += 4u; }
        else               { ea = fetch16(); ex += 5u; }
        cpu_wr(ea, *reg);
        nz8(*reg);
        return ex;
    }

    u8 v8;
    if (md == 0u)      { v8 = fetch8(); ex += 2u; }
    else if (md == 1u) { ea = (u16)(((u16)S.dp << 8) | fetch8()); v8 = cpu_rd(ea); ex += 4u; }
    else if (md == 2u) { ea = ea_indexed(&ex); v8 = cpu_rd(ea); ex += 4u; }
    else               { ea = fetch16(); v8 = cpu_rd(ea); ex += 5u; }

    switch (sub) {
    case 0x0: *reg = alu_sub8(*reg, v8, 0); break;
    case 0x1: (void)alu_sub8(*reg, v8, 0); break;
    case 0x2: *reg = alu_sub8(*reg, v8, (S.cc & CC_C) ? 1u : 0u); break;
    case 0x4: *reg &= v8; nz8(*reg); break;
    case 0x5: nz8((u8)(*reg & v8)); break;
    case 0x6: *reg = v8; nz8(*reg); break;
    case 0x8: *reg ^= v8; nz8(*reg); break;
    case 0x9: *reg = alu_add8(*reg, v8, (S.cc & CC_C) ? 1u : 0u); break;
    case 0xA: *reg |= v8; nz8(*reg); break;
    case 0xB: *reg = alu_add8(*reg, v8, 0); break;
    }
    return ex;
}

/* ---- MC6847 Scanline Video Renderer (320 x 240 with Border) ---- */
static void render_scanline(int line_y, u16 *picture)
{
    if (!picture || line_y < 0 || line_y >= COCO_H) return;
    u16 *dst = picture + line_y * COCO_W;

    u8 pb = (u8)((S.pia1.orb & S.pia1.ddrb) | (~S.pia1.ddrb & 0x00u));
    int ag  = (pb & 0x80u) != 0u;
    u8 gm   = (pb >> 4) & 7u;
    int css = (pb & 0x08u) != 0u;

    u16 border_c = ag ? WS->pal[css ? 4 : 0] : WS->pal[12];

    /* Top / bottom 24-line border */
    if (line_y < 24 || line_y >= 216) {
        for (int x = 0; x < COCO_W; x++) dst[x] = border_c;
        return;
    }

    int y = line_y - 24;                /* 0..191 active MC6847 scanline */
    u16 vram_base = (u16)(((S.sam >> 3) & 0x7Fu) << 9);

    for (int x = 0; x < 32; x++) *dst++ = border_c;

    if (ag) {
        u8 sub_m = (gm >> 1) & 3u;
        if (gm & 1u) {                  /* Resolution Graphics: RG1, RG2, RG3, RG6 */
            int bpr = (sub_m < 3u) ? 16 : 32;
            int rh  = (gm & 4u) ? 1 : (gm & 2u) ? 2 : 3;
            u16 row_off = (u16)((y / rh) * bpr);
            if (sub_m == 3u && css && !S.is_dragon) {
                /* CoCo NTSC RG6 (256x192, CSS=1) 4-Color Artifact Mode! */
                for (int bx = 0; bx < 32; bx++) {
                    u8 m = WS->ram[(vram_base + row_off + bx) & 0xFFFFu];
                    for (int p = 6; p >= 0; p -= 2) {
                        u8 pair = (m >> p) & 3u;
                        u16 c = (pair == 0u) ? WS->pal[12] : WS->pal[12 + pair];
                        *dst++ = c; *dst++ = c;
                    }
                }
            } else {
                int dpb = (sub_m < 3u) ? 2 : 1;
                u16 fg = WS->pal[css ? 4 : 0], bg = WS->pal[12];
                for (int bx = 0; bx < bpr; bx++) {
                    u8 m = WS->ram[(vram_base + row_off + bx) & 0xFFFFu];
                    for (int p = 7; p >= 0; p--) {
                        u16 c = ((m >> p) & 1u) ? fg : bg;
                        for (int d = 0; d < dpb; d++) *dst++ = c;
                    }
                }
            }
        } else {                        /* Color Graphics: CG1, CG2, CG3, CG6 */
            u8 coff = css ? 4u : 0u;
            int dpb = (sub_m == 0u) ? 4 : 2;
            int bpr = (sub_m == 0u) ? 16 : 32;
            int rh  = (gm & 4u) ? ((gm & 2u) ? 1 : 2) : 3;
            u16 row_off = (u16)((y / rh) * bpr);
            for (int bx = 0; bx < bpr; bx++) {
                u8 m = WS->ram[(vram_base + row_off + bx) & 0xFFFFu];
                for (int p = 6; p >= 0; p -= 2) {
                    u16 c = WS->pal[((m >> p) & 3u) + coff];
                    for (int d = 0; d < dpb; d++) *dst++ = c;
                }
            }
        }
    } else {                            /* Alphanumeric & Semigraphics (SG4 / SG6) */
        u16 row_off = (u16)((y / 12) * 32);
        int chr_y = y % 12;
        int sh2x2 = (1 - (chr_y / 6)) * 2;
        int sh2x3 = (2 - (chr_y / 4)) * 2;
        u16 afg = WS->pal[css ? 10 : 8];
        u16 abg = WS->pal[css ? 11 : 9];
        int intext = (gm & 1u) != 0u;

        for (int cx = 0; cx < 32; cx++) {
            u8 chr = WS->ram[(vram_base + row_off + cx) & 0xFFFFu];
            if (chr & 0x80u) {          /* D7=1 -> AS=1 (Semigraphics) */
                u8 m, cidx;
                if (intext) {           /* SG6 (2x3) */
                    m = (chr >> sh2x3) & 3u;
                    cidx = (u8)(((chr >> 6) & 3u) + (css ? 4u : 0u));
                } else {                /* SG4 (2x2) */
                    m = (chr >> sh2x2) & 3u;
                    cidx = (chr >> 4) & 7u;
                }
                for (int p = 1; p >= 0; p--) {
                    u16 c = (m & (1u << p)) ? WS->pal[cidx] : WS->pal[12];
                    *dst++ = c; *dst++ = c; *dst++ = c; *dst++ = c;
                }
            } else {                    /* D7=0 -> Alphanumeric (D6 = INV: 1=normal green bg, 0=inverted) */
                u8 m = mc6847_font[(chr & 0x3Fu) * 12u + chr_y];
                if (chr & 0x40u) m = (u8)~m;
                for (int p = 7; p >= 0; p--)
                    *dst++ = (m & (1u << p)) ? afg : abg;
            }
        }
    }

    for (int x = 0; x < 32; x++) *dst++ = border_c;
}

/* ---- Keyboard & Gamepad Mapping ---- */
static void kbd_set(int row, int col)
{
    S.kbd_row[row] |= (u8)(1u << col);
}

static void kbd_press_ascii(u8 c)
{
    if (c >= 'a' && c <= 'z') c = (u8)(c - 32u);
    if (c == '@') { kbd_set(0, 0); return; }
    if (c >= 'A' && c <= 'G') { kbd_set(0, c - 'A' + 1); return; }
    if (c >= 'H' && c <= 'O') { kbd_set(1, c - 'H'); return; }
    if (c >= 'P' && c <= 'W') { kbd_set(2, c - 'P'); return; }
    if (c >= 'X' && c <= 'Z') { kbd_set(3, c - 'X'); return; }
    if (c == ' ')  { kbd_set(3, 7); return; }
    if (c == '\r' || c == '\n') { kbd_set(6, 0); return; }
    if (c == 0x08u){ kbd_set(3, 5); return; }
    if (c >= '0' && c <= '7') { kbd_set(4, c - '0'); return; }
    if (c == '8' || c == '9') { kbd_set(5, c - '8'); return; }
    /* Shifted punctuation on CoCo/Dragon */
    static const struct { char ch; u8 r, c, sh; } punct[] = {
        {':',5,2,0}, {';',5,3,0}, {',',5,4,0}, {'-',5,5,0}, {'.',5,6,0}, {'/',5,7,0},
        {'!',4,1,1}, {'"',4,2,1}, {'#',4,3,1}, {'$',4,4,1}, {'%',4,5,1}, {'&',4,6,1}, {'\'',4,7,1},
        {'(',5,0,1}, {')',5,1,1}, {'*',5,2,1}, {'+',5,3,1}, {'<',5,4,1}, {'=',5,5,1}, {'>',5,6,1}, {'?',5,7,1},
    };
    for (u32 i = 0; i < sizeof(punct) / sizeof(punct[0]); i++) {
        if ((u8)punct[i].ch == c) {
            kbd_set(punct[i].r, punct[i].c);
            if (punct[i].sh) kbd_set(6, 7);
            return;
        }
    }
}

void coco_typed(char c)
{
    u8 ch = (u8)c;
    if (ch == '\n') ch = '\r';
    u16 next = (u16)((S.type_tail + 1u) % sizeof(S.type_q));
    if (next != S.type_head) {
        S.type_q[S.type_tail] = (char)ch;
        S.type_tail = next;
    }
}

void coco_keyboard(const u8 *usages, int n)
{
    cc_zero(S.kbd_row, sizeof(S.kbd_row));
    for (int i = 0; i < n; i++) {
        u8 u = usages[i];
        if (u == 0xE1 || u == 0xE5) kbd_set(6, 7);          /* Shift */
        else if (u >= 0x04 && u <= 0x1D) kbd_press_ascii((u8)('A' + (u - 0x04)));
        else if (u >= 0x1E && u <= 0x26) kbd_press_ascii((u8)('1' + (u - 0x1E)));
        else if (u == 0x27) kbd_press_ascii('0');
        else if (u == 0x28 || u == 0x58) kbd_set(6, 0);     /* Enter */
        else if (u == 0x29) kbd_set(6, 2);                  /* Esc -> Break */
        else if (u == 0x2A || u == 0x50) kbd_set(3, 5);     /* Backspace / Left */
        else if (u == 0x4F) kbd_set(3, 6);                  /* Right */
        else if (u == 0x52) kbd_set(3, 3);                  /* Up */
        else if (u == 0x51) kbd_set(3, 4);                  /* Down */
        else if (u == 0x2C) kbd_set(3, 7);                  /* Space */
        else if (u == 0x2D) kbd_set(5, 5);                  /* - */
        else if (u == 0x2E) { kbd_set(5, 5); kbd_set(6, 7); } /* = (Shift -) */
        else if (u == 0x33) kbd_set(5, 3);                  /* ; */
        else if (u == 0x34) { kbd_set(4, 7); kbd_set(6, 7); } /* ' */
        else if (u == 0x36) kbd_set(5, 4);                  /* , */
        else if (u == 0x37) kbd_set(5, 6);                  /* . */
        else if (u == 0x38) kbd_set(5, 7);                  /* / */
    }
    cc_copy(S.usb_kbd_row, S.kbd_row, sizeof(S.usb_kbd_row));
}

/* ---- Sub-Frame 48 kHz Audio Integration ---- */
static void render_audio_frame(u32 frame_cycles, u32 clock_hz)
{
    if (!S.snd_hz) {
        S.dac_nev = 0;
        return;
    }
    u32 num = frame_cycles * S.snd_hz + S.snd_rem;
    u32 nsamp = num / clock_hz;
    S.snd_rem = num % clock_hz;

    u32 ev_idx = 0;
    u32 cyc_fp = 0;
    u32 cyc_step_fp = (clock_hz << 7) / S.snd_hz; /* 7-bit fractional cycles/sample */

    for (u32 s = 0; s < nsamp; s++) {
        u32 c0 = cyc_fp >> 7;
        cyc_fp += cyc_step_fp;
        u32 c1 = cyc_fp >> 7;
        if (c1 <= c0) c1 = c0 + 1u;

        s32 acc = 0;
        u32 cur = c0;
        while (ev_idx < S.dac_nev && WS->dac_cyc[ev_idx] < c1) {
            u32 tc = WS->dac_cyc[ev_idx];
            if (tc > cur) {
                acc += (s32)S.snd_held_lvl * (s32)(tc - cur);
                cur = tc;
            }
            S.snd_held_lvl = WS->dac_lvl[ev_idx++];
        }
        if (c1 > cur)
            acc += (s32)S.snd_held_lvl * (s32)(c1 - cur);

        s32 raw = acc / (s32)(c1 - c0);
        S.snd_dc += (raw - S.snd_dc) >> 8;
        s32 out = raw - S.snd_dc;
        if (out > 32767) out = 32767;
        if (out < -32768) out = -32768;
        if (S.snd_count < COCO_RING_LEN) {
            WS->snd_ring[(S.snd_head + S.snd_count) % COCO_RING_LEN] = (s16)out;
            S.snd_count++;
        }
    }
    S.dac_nev = 0;
}

/* ---- Reset, Load & Frame Execution ---- */
void coco_reset(void)
{
    cc_zero(WS->ram, sizeof(WS->ram));
    cc_zero(&S.pia0, sizeof(S.pia0));
    cc_zero(&S.pia1, sizeof(S.pia1));
    S.sam = (u16)(2u << 3);             /* Default SAM F=2 ($0400 text screen) */

    S.a = S.b = S.dp = 0;
    S.x = S.y = S.u = S.s = 0;
    S.cc = CC_I | CC_F;
    S.jam = S.cwai = S.sync_wait = S.nmi_armed = S.nmi_pend = 0;
    S.joy_axis[0] = S.joy_axis[1] = S.joy_axis[2] = S.joy_axis[3] = 32u;
    S.joy_btn[0] = S.joy_btn[1] = 0;
    S.bas_len = 0;
    S.cur_pos = 0;
    S.dac_nev = 0;
    S.pc = cpu_rd16(0xFFFEu);
}

static int ext_is(const char *path, const char *ext)
{
    if (!path) return 0;
    const char *dot = 0;
    for (const char *p = path; *p; p++)
        if (*p == '.') dot = p + 1;
    if (!dot) return 0;
    while (*dot && *ext) {
        char a = *dot++, b = *ext++;
        if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
        if (a != b) return 0;
    }
    return *dot == 0 && *ext == 0;
}

static const char *common_load(int dragon, const u8 *rom_lo8k, const u8 *rom_hi8k,
                               const u8 *image, u32 size, const char *path)
{
    cc_zero(&S, sizeof(S));
    S.is_dragon = (u8)dragon;
    for (int i = 0; i < 16; i++)
        WS->pal[i] = RGB15_CC(coco_pal_rgb[i][0], coco_pal_rgb[i][1], coco_pal_rgb[i][2]);

    if (rom_hi8k) {
        S.use_ext_rom = 1;
        if (rom_lo8k) cc_copy(WS->rom_exec, rom_lo8k, 0x2000u);
        else          cc_copy(WS->rom_exec, rom_hi8k, 0x2000u);
        cc_copy(WS->rom_exec + 0x2000u, rom_hi8k, 0x2000u);
    } else {
        S.use_ext_rom = 0;
        build_cleanroom_rom();
    }

    char *p = S.info, *end = S.info + sizeof(S.info) - 1;
    put_s(&p, end, dragon ? "Dragon 32/64 PAL" : "TRS-80 CoCo 64K NTSC");

    if (image && size > 0) {
        if (size > sizeof(WS->stage))
            return "image too large for CoCo/Dragon 64K";

        int is_cas = ext_is(path, "cas") || (size >= 16u && image[0] == 0x55u && image[1] == 0x55u);
        int is_cart = ext_is(path, "ccc") || ext_is(path, "rom");
        if (!is_cas && !is_cart && ext_is(path, "bin")) {
            S.media_kind = MEDIA_BIN;
        } else if (is_cas) {
            S.media_kind = MEDIA_CAS;
        } else if (is_cart || (size <= 0x4000u && !(image[0] == 0x00u && size > 5u))) {
            S.media_kind = MEDIA_CART;
        } else {
            S.media_kind = MEDIA_BIN;
        }

        if (S.media_kind == MEDIA_CART) {
            if (size > 0x4000u) return "Program Pak > 16 KB";
            for (u32 off = 0; off < 0x4000u; off += size) {
                u32 chunk = (0x4000u - off < size) ? (0x4000u - off) : size;
                cc_copy(WS->rom_cart + off, image, chunk);
            }
            put_s(&p, end, " Pak, ");
        } else {
            cc_copy(WS->stage, image, size);
            S.stage_len = size;
            put_s(&p, end, (S.media_kind == MEDIA_CAS) ? " Cassette, " : " Binary, ");
        }
        put_u(&p, end, (size + 1023u) >> 10);
        put_s(&p, end, " KB");
    } else {
        put_s(&p, end, " (Color BASIC)");
    }

    coco_reset();
    return 0;
}

const char *coco_load(const u8 *bas_rom, const u8 *ext_rom,
                      const u8 *image, u32 size, const char *path)
{
    return common_load(0, ext_rom, bas_rom, image, size, path);
}

const char *dragon_load(const u8 *d32_rom,
                        const u8 *image, u32 size, const char *path)
{
    return common_load(1, d32_rom, d32_rom ? (d32_rom + 0x2000u) : 0, image, size, path);
}

void coco_frame(u16 pad, u16 *picture)
{
    /* Map gamepad to BOTH Analog Joystick + Buttons AND Arrow/Space/Shift keys! */
    S.joy_axis[0] = (pad & 0x40u) ? 4u : (pad & 0x80u) ? 60u : 32u;
    S.joy_axis[1] = (pad & 0x10u) ? 4u : (pad & 0x20u) ? 60u : 32u;
    S.joy_btn[0]  = (pad & 0x01u) ? 1u : 0u;
    S.joy_btn[1]  = (pad & 0x02u) ? 1u : 0u;

    /* Start from current USB keyboard state, then overlay typed chars + gamepad */
    cc_copy(S.kbd_row, S.usb_kbd_row, sizeof(S.kbd_row));
    if (S.type_hold > 0) {
        S.type_hold--;
        if (S.type_hold >= 1u)
            kbd_press_ascii(S.type_ch);
    } else if (S.type_head != S.type_tail) {
        S.type_ch = (u8)S.type_q[S.type_head];
        S.type_head = (u16)((S.type_head + 1u) % sizeof(S.type_q));
        S.type_hold = 2u;
        kbd_press_ascii(S.type_ch);
    }

    /* Overlay gamepad D-Pad + Buttons onto CoCo keyboard arrows + Space + Shift + Enter */
    if (pad) {
        if (pad & 0x10u) kbd_set(3, 3); /* Up */
        if (pad & 0x20u) kbd_set(3, 4); /* Down */
        if (pad & 0x40u) kbd_set(3, 5); /* Left */
        if (pad & 0x80u) kbd_set(3, 6); /* Right */
        if (pad & 0x01u) kbd_set(3, 7); /* A -> Space (Button 0) */
        if (pad & 0x02u) kbd_set(6, 7); /* B -> Shift (Button 1) */
        if (pad & 0x08u) kbd_set(6, 0); /* Start -> Enter */
    }

    /* If external ROM is used with a .bin / .cas ML image, inject cleanly after ROM reset finishes */
    if (S.use_ext_rom && S.total_frames == 45u && (S.media_kind == MEDIA_BIN || S.media_kind == MEDIA_CAS)) {
        int is_ml = 0;
        u16 entry = load_staged_program(&is_ml);
        if (is_ml) S.pc = entry;
    }

    u32 lines = S.is_dragon ? COCO_LINES_PAL : COCO_LINES_NTSC;
    u32 speed_mul = ((S.sam >> 11) & 3u) ? 2u : 1u;
    u32 cyc_per_line = COCO_CYC_LINE * speed_mul;
    u32 frame_cycles = lines * cyc_per_line;
    u32 clock_hz = (S.is_dragon ? COCO_CLOCK_PAL : COCO_CLOCK_NTSC) * speed_mul;

    S.cyc = 0;
    u32 target = 0;
    for (u32 line = 0; line < lines; line++) {
        if (line < COCO_H)
            render_scanline((int)line, picture);

        target += cyc_per_line;
        while (S.cyc < target)
            S.cyc += cpu_step();

        /* PIA0 CA1 = HSync pulse once per scanline */
        S.pia0.cra |= 0x80u;
        /* PIA0 CB1 = FSync/VSync falling edge at active display end (line 216 = 24 border + 192 active) */
        if (line == 216u)
            S.pia0.crb |= 0x80u;
        /* PIA1 CB1 = Cartridge auto-start FIRQ pulse */
        if (S.media_kind == MEDIA_CART && S.use_ext_rom && line == 100u && S.total_frames < 8u)
            S.pia1.crb |= 0x80u;
    }

    S.total_frames++;
    render_audio_frame(frame_cycles, clock_hz);
}

int coco_width(void)  { return COCO_W; }
int coco_height(void) { return COCO_H; }
const char *coco_info(void) { return S.info; }
int coco_jammed(void) { return S.jam; }

void coco_audio_rate(u32 hz)
{
    S.snd_hz = (hz >= 8000u && hz <= 192000u) ? hz : 0;
    S.snd_rem = 0;
    S.snd_head = S.snd_count = 0;
    S.dac_nev = 0;
}

int coco_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && S.snd_count) {
        out[n++] = WS->snd_ring[S.snd_head];
        S.snd_head = (S.snd_head + 1u) % COCO_RING_LEN;
        S.snd_count--;
    }
    return n;
}
