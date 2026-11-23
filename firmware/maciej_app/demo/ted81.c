/* Commodore Plus/4 & C16 ('plus4') + Sinclair ZX81 ('zx81'): see ted81.h.
   Pass-optimized for 594 MHz MIPS32:
   - Zero static .bss (all 64 KB Plus/4 RAM, ROMs, tape decode buffers, Z80 state & audio in EMU_RAM_PHYS)
   - Precomputed 128-entry MOS TED YUV->RGB555 121-color palette LUT
   - Fast 256-page 7501 MMU ($FF3E/$FF3F ROM/RAM banking) & 64-page Z80 pointer map
   - Exact Plus/4 CINV ($0314) X/Y-preserving IRQ wrapper + ZX81 FRAMES ($4034) 50 Hz counter */
#pragma GCC optimize("O2")
#include "ted81.h"
#include "z80.h"

#ifndef TED81_HOST
#include "hw.h"
#endif

#define FC 0x01u
#define FZ 0x02u
#define FI 0x04u
#define FD 0x08u
#define FB 0x10u
#define FU 0x20u
#define FV 0x40u
#define FN 0x80u

#define SND_RING 4096

struct ted81_ws {
    u8  is_zx81;                /* 0 = Commodore Plus/4 64K, 1 = Sinclair ZX81 16K */
    u8  basic_mode;
    u8  has_prog;
    u16 prog_entry, prog_start, prog_end;
    u32 frames;

    /* ---- Commodore Plus/4 (MOS 7501 + TED 7360/8360) ---- */
    u8  a, x, y, s, p;
    u16 pc;
    u8  jam;
    s32 cycles;
    u8 *rdp[256], *wrp[256];

    u8  ram[0x10000];           /* 64 KB Plus/4 RAM (or ZX81 $0000..$FFFF space) */
    u8  rom_lo[0x4000];         /* Plus/4 $8000..$BFFF BASIC ROM (or ZX81 8 KB ROM) */
    u8  rom_hi[0x4000];         /* Plus/4 $C000..$FFFF Kernal + Font ($D000) */
    u8  rom_enabled;            /* Controlled by $FF3E (ROM on) / $FF3F (RAM on) */

    u8  ted[0x20];              /* MOS TED registers $FF00..$FF1F */
    u16 t_cnt[3], t_reload1;    /* TED 16-bit Timers 1..3 */
    u8  t1_run;
    u16 cur_line;
    u8  fd30;                   /* Plus/4 keyboard matrix row latch ($FD30) */
    u8  ff08_latch;             /* TED keyboard/joystick latch ($FF08) */
    u8  p4_mat[8], p4_usb[8];   /* Active-HIGH internal pressed bits per row 0..7 */
    u16 ted_pal15[128];         /* Precomputed 121-color RGB555 LUT */

    /* TED 2-Voice Sound + White Noise */
    u32 ted_cnt[2];
    u8  ted_out[2];
    u16 ted_lfsr;

    /* ---- Sinclair ZX81 (Z80 + ULA) ---- */
    struct z80 zcpu;
    u8  zx_rows[8], zx_usb[8];  /* Active-LOW 5-bit rows ($FEFE..$7FFE) */
    u8  zx_nmi_en;
    u32 zx_beep_pulses;

    /* Shared input & interactive BASIC */
    u16 pad;
    char type_q[64];
    u8  type_r, type_w, type_hold;
    char type_ch;
    u8  bas_x, bas_y, bas_len;
    char bas_line[40];

    /* Scratch buffer for C16-TAPE-RAW pulse decoding / .prg reload */
    u32 img_len;
    u8  img_buf[0x10000];       /* Decoded payload backup for clean reset */

    /* 48 kHz Audio Ring */
    u32 sample_rate, snd_frac, chip_frac;
    u32 snd_head, snd_tail;
    s16 snd_ring[SND_RING];

    char title[32];
    char info[96];
};

#ifdef TED81_HOST
static struct ted81_ws ted81_host_ws;
#define WS (&ted81_host_ws)
#else
#define WS ((struct ted81_ws *)KSEG0(EMU_RAM_PHYS))
#ifndef TED81_NO_ASSERT
_Static_assert(sizeof(struct ted81_ws) <= EMU_RAM_SIZE, "ted81_ws exceeds EMU_RAM_SIZE");
#endif
#endif

#define INLINE static inline __attribute__((always_inline))

static void ws_zero(void *p, u32 n)
{
    u8 *b = (u8 *)p;
    for (u32 i = 0; i < n; i++)
        b[i] = 0;
}

static int ci_ends(const char *s, const char *ext)
{
    if (!s) return 0;
    int sl = 0, el = 0;
    while (s[sl]) sl++;
    while (ext[el]) el++;
    if (sl < el) return 0;
    for (int i = 0; i < el; i++)
        if ((s[sl - el + i] | 32) != (ext[i] | 32)) return 0;
    return 1;
}

#define RGB15(r, g, b) ((u16)((((b) >> 3) << 10) | (((g) >> 3) << 5) | ((r) >> 3)))

/* Compact 5x7 ASCII font (0x20..0x7F) used to build Plus/4 PETSCII & ZX81 charsets */
static const u8 font5x7[96][5] = {
    {0x00,0x00,0x00,0x00,0x00},{0x00,0x00,0x5F,0x00,0x00},{0x00,0x07,0x00,0x07,0x00},{0x14,0x7F,0x14,0x7F,0x14},
    {0x24,0x2A,0x7F,0x2A,0x12},{0x23,0x13,0x08,0x64,0x62},{0x36,0x49,0x55,0x22,0x50},{0x00,0x05,0x03,0x00,0x00},
    {0x00,0x1C,0x22,0x41,0x00},{0x00,0x41,0x22,0x1C,0x00},{0x14,0x08,0x3E,0x08,0x14},{0x08,0x08,0x3E,0x08,0x08},
    {0x00,0x50,0x30,0x00,0x00},{0x08,0x08,0x08,0x08,0x08},{0x00,0x60,0x60,0x00,0x00},{0x20,0x10,0x08,0x04,0x02},
    {0x3E,0x51,0x49,0x45,0x3E},{0x00,0x42,0x7F,0x40,0x00},{0x42,0x61,0x51,0x49,0x46},{0x21,0x41,0x45,0x4B,0x31},
    {0x18,0x14,0x12,0x7F,0x10},{0x27,0x45,0x45,0x45,0x39},{0x3C,0x4A,0x49,0x49,0x30},{0x01,0x71,0x09,0x05,0x03},
    {0x36,0x49,0x49,0x49,0x36},{0x06,0x49,0x49,0x29,0x1E},{0x00,0x36,0x36,0x00,0x00},{0x00,0x56,0x36,0x00,0x00},
    {0x08,0x14,0x22,0x41,0x00},{0x14,0x14,0x14,0x14,0x14},{0x00,0x41,0x22,0x14,0x08},{0x02,0x01,0x51,0x09,0x06},
    {0x32,0x49,0x79,0x41,0x3E},{0x7E,0x11,0x11,0x11,0x7E},{0x7F,0x49,0x49,0x49,0x36},{0x3E,0x41,0x41,0x41,0x22},
    {0x7F,0x41,0x41,0x22,0x1C},{0x7F,0x49,0x49,0x49,0x41},{0x7F,0x09,0x09,0x09,0x01},{0x3E,0x41,0x49,0x49,0x7A},
    {0x7F,0x08,0x08,0x08,0x7F},{0x00,0x41,0x7F,0x41,0x00},{0x20,0x40,0x41,0x3F,0x01},{0x7F,0x08,0x14,0x22,0x41},
    {0x7F,0x40,0x40,0x40,0x40},{0x7F,0x02,0x0C,0x02,0x7F},{0x7F,0x04,0x08,0x10,0x7F},{0x3E,0x41,0x41,0x41,0x3E},
    {0x7F,0x09,0x09,0x09,0x06},{0x3E,0x41,0x51,0x21,0x5E},{0x7F,0x09,0x19,0x29,0x46},{0x46,0x49,0x49,0x49,0x31},
    {0x01,0x01,0x7F,0x01,0x01},{0x3F,0x40,0x40,0x40,0x3F},{0x1F,0x20,0x40,0x20,0x1F},{0x3F,0x40,0x38,0x40,0x3F},
    {0x63,0x14,0x08,0x14,0x63},{0x07,0x08,0x70,0x08,0x07},{0x61,0x51,0x49,0x45,0x43},{0x00,0x7F,0x41,0x41,0x00},
    {0x02,0x04,0x08,0x10,0x20},{0x00,0x41,0x41,0x7F,0x00},{0x04,0x02,0x01,0x02,0x04},{0x40,0x40,0x40,0x40,0x40},
    {0x00,0x01,0x02,0x04,0x00},{0x20,0x54,0x54,0x54,0x78},{0x7F,0x48,0x44,0x44,0x38},{0x38,0x44,0x44,0x44,0x20},
    {0x38,0x44,0x44,0x48,0x7F},{0x38,0x54,0x54,0x54,0x18},{0x08,0x7E,0x09,0x01,0x02},{0x0C,0x52,0x52,0x52,0x3E},
    {0x7F,0x08,0x04,0x04,0x78},{0x00,0x44,0x7D,0x40,0x00},{0x20,0x40,0x44,0x3D,0x00},{0x7F,0x10,0x28,0x44,0x00},
    {0x00,0x41,0x7F,0x40,0x00},{0x7C,0x04,0x18,0x04,0x78},{0x7C,0x08,0x04,0x04,0x78},{0x38,0x44,0x44,0x44,0x38},
    {0x7C,0x14,0x14,0x14,0x08},{0x08,0x14,0x14,0x18,0x7C},{0x7C,0x08,0x04,0x04,0x08},{0x48,0x54,0x54,0x54,0x20},
    {0x04,0x3F,0x44,0x40,0x20},{0x3C,0x40,0x40,0x20,0x7C},{0x1C,0x20,0x40,0x20,0x1C},{0x3C,0x40,0x30,0x40,0x3C},
    {0x44,0x28,0x10,0x28,0x44},{0x0C,0x50,0x50,0x50,0x3C},{0x44,0x64,0x54,0x4C,0x44},{0x00,0x08,0x36,0x41,0x00},
    {0x00,0x00,0x7F,0x00,0x00},{0x00,0x41,0x36,0x08,0x00},{0x10,0x08,0x08,0x10,0x08},{0x7F,0x7F,0x7F,0x7F,0x7F}
};

enum {
    PAD_A      = 0x001,
    PAD_B      = 0x002,
    PAD_SELECT = 0x004,
    PAD_START  = 0x008,
    PAD_UP     = 0x010,
    PAD_DOWN   = 0x020,
    PAD_LEFT   = 0x040,
    PAD_RIGHT  = 0x080
};

/* ============================================================================
 * PART 1: COMMODORE PLUS/4 & C16 (MOS 7501 + MOS 7360/8360 TED)
 * ============================================================================ */

static void init_ted_palette(void)
{
    /* Authentic MOS TED 16 hues (base RGBchroma offsets) x 8 luminance levels (121 unique colors) */
    static const s16 hue_rgb[16][3] = {
        {  0,   0,   0}, /*  0: Black (always 0,0,0) */
        {  0,   0,   0}, /*  1: Gray / White (neutral) */
        { 92, -46, -46}, /*  2: Red */
        {-82,  42,  48}, /*  3: Cyan */
        { 68, -58,  68}, /*  4: Purple */
        {-64,  68, -64}, /*  5: Green */
        {-54, -44,  96}, /*  6: Blue */
        { 64,  62, -88}, /*  7: Yellow */
        { 84, -12, -68}, /*  8: Orange */
        { 58,  10, -68}, /*  9: Brown */
        { 72,  44, -84}, /* 10: Yellow-Green */
        { 88, -32,  24}, /* 11: Pink */
        {-74,  64,  18}, /* 12: Blue-Green */
        {-36,  14,  88}, /* 13: Light Blue */
        { 22, -52,  92}, /* 14: Dark Blue / Violet */
        {-36,  72, -72}  /* 15: Light Green */
    };
    static const s16 lum_y[8] = { 44, 72, 98, 126, 158, 190, 222, 255 };

    for (int idx = 0; idx < 128; idx++) {
        int hue = idx & 15;
        int lum = (idx >> 4) & 7;
        if (hue == 0) {
            WS->ted_pal15[idx] = 0x0000u;
            continue;
        }
        s32 y = lum_y[lum];
        s32 r = y + hue_rgb[hue][0];
        s32 g = y + hue_rgb[hue][1];
        s32 b = y + hue_rgb[hue][2];
        if (r < 0) r = 0; else if (r > 255) r = 255;
        if (g < 0) g = 0; else if (g > 255) g = 255;
        if (b < 0) b = 0; else if (b > 255) b = 255;
        WS->ted_pal15[idx] = RGB15((u32)r, (u32)g, (u32)b);
    }
}

static void ted_step_sample(void)
{
    /* TED sound clock: 111,861 Hz (PAL 1.78977 MHz / 16) */
    WS->chip_frac += 111861u;
    u32 sr = WS->sample_rate ? WS->sample_rate : 48000u;
    s32 acc = 0, ticks = 0;

    u8 ctrl = WS->ted[0x11];
    u32 vol = ctrl & 0x0Fu;
    if (vol > 8u) vol = 8u;
    s32 amp = (s32)(vol * 1150u);

    u32 f1 = (u32)WS->ted[0x0E] | (((u32)WS->ted[0x12] & 3u) << 8);
    u32 f2 = (u32)WS->ted[0x0F] | (((u32)WS->ted[0x10] & 3u) << 8);
    u32 p1 = (f1 >= 1023u) ? 1u : (1024u - f1);
    u32 p2 = (f2 >= 1023u) ? 1u : (1024u - f2);

    while (WS->chip_frac >= sr) {
        WS->chip_frac -= sr;
        ticks++;

        if (++WS->ted_cnt[0] >= p1) {
            WS->ted_cnt[0] = 0;
            if (f1 >= 1023u) WS->ted_out[0] = 1u;
            else             WS->ted_out[0] ^= 1u;
        }
        if (++WS->ted_cnt[1] >= p2) {
            WS->ted_cnt[1] = 0;
            if (f2 >= 1023u) WS->ted_out[1] = 1u;
            else             WS->ted_out[1] ^= 1u;
            u16 fb = (u16)(((WS->ted_lfsr >> 7) ^ (WS->ted_lfsr >> 5) ^ (WS->ted_lfsr >> 4) ^ (WS->ted_lfsr >> 1)) & 1u);
            WS->ted_lfsr = (u16)(((WS->ted_lfsr << 1) | (fb ^ 1u)) & 0xFFu);
            if (!WS->ted_lfsr) WS->ted_lfsr = 0x55u;
        }

        s32 s = 0;
        if (ctrl & 0x10u) s += WS->ted_out[0] ? amp : -amp;
        if (ctrl & 0x20u) s += WS->ted_out[1] ? amp : -amp;
        else if (ctrl & 0x40u) s += (WS->ted_lfsr & 1u) ? amp : -amp;
        acc += s;
    }

    s32 out = ticks ? (acc / ticks) : 0;
    if (out > 32767) out = 32767;
    if (out < -32768) out = -32768;
    u32 nxt = (WS->snd_head + 1u) & (SND_RING - 1u);
    if (nxt != WS->snd_tail) {
        WS->snd_ring[WS->snd_head] = (s16)out;
        WS->snd_head = nxt;
    }
}

static void p4_setup_mmu(void)
{
    for (int i = 0; i < 256; i++) {
        WS->wrp[i] = WS->ram + i * 256;
        WS->rdp[i] = WS->ram + i * 256;
    }
    /* $FD00..$FDFF ($FD30 keyboard PIO) and $FF00..$FFFF (TED + ROM/RAM select + vectors) */
    WS->rdp[0xFD] = WS->wrp[0xFD] = 0;
    WS->rdp[0xFF] = WS->wrp[0xFF] = 0;
    if (WS->rom_enabled) {
        for (int i = 0x80; i < 0xC0; i++) WS->rdp[i] = WS->rom_lo + (i - 0x80) * 256;
        for (int i = 0xC0; i < 0xFF; i++) {
            if (i == 0xFD) continue;
            WS->rdp[i] = WS->rom_hi + (i - 0xC0) * 256;
        }
    }
}

static void ted_recalc_irq(void)
{
    u8 mask = (u8)(WS->ted[0x0A] & 0x5Eu);
    if (WS->ted[0x09] & mask)
        WS->ted[0x09] |= 0x80u;
    else
        WS->ted[0x09] &= ~0x80u;
}

/* Plus/4 8x8 Keyboard Matrix:
   Row 0 (~$01): Del(b0), Ret(b1), Pound(b2), Help(b3), F1(b4), F2(b5), F3(b6), @(b7)
   Row 1 (~$02): 3(b0), W(b1), A(b2), 4(b3), Z(b4), S(b5), E(b6), Shift(b7)
   Row 2 (~$04): 5(b0), R(b1), D(b2), 6(b3), C(b4), F(b5), T(b6), X(b7)
   Row 3 (~$08): 7(b0), Y(b1), G(b2), 8(b3), B(b4), H(b5), U(b6), V(b7)
   Row 4 (~$10): 9(b0), I(b1), J(b2), 0(b3), M(b4), K(b5), O(b6), N(b7)
   Row 5 (~$20): Down(b0), P(b1), L(b2), Up(b3), .(b4), :(b5), -(b6), ,(b7)
   Row 6 (~$40): Left(b0), *(b1), ;(b2), Right(b3), Esc(b4), =(b5), +(b6), /(b7)
   Row 7 (~$80): 1(b0), Home(b1), Ctrl(b2), 2(b3), Space(b4), C=(b5), Q(b6), Stop(b7) */
static void p4_press_ascii(char ch, u8 mat[8])
{
    if (ch >= 'a' && ch <= 'z') ch = (char)(ch - 32);
    switch (ch) {
    case ' ': mat[7] |= 0x10u; break;
    case '\r': case '\n': mat[0] |= 0x02u; break;
    case 8: case 127: mat[0] |= 0x01u; break;
    case '1': mat[7] |= 0x01u; break;
    case '2': mat[7] |= 0x08u; break;
    case '3': mat[1] |= 0x01u; break;
    case '4': mat[1] |= 0x08u; break;
    case '5': mat[2] |= 0x01u; break;
    case '6': mat[2] |= 0x08u; break;
    case '7': mat[3] |= 0x01u; break;
    case '8': mat[3] |= 0x08u; break;
    case '9': mat[4] |= 0x01u; break;
    case '0': mat[4] |= 0x08u; break;
    case 'A': mat[1] |= 0x04u; break;
    case 'B': mat[3] |= 0x10u; break;
    case 'C': mat[2] |= 0x10u; break;
    case 'D': mat[2] |= 0x04u; break;
    case 'E': mat[1] |= 0x40u; break;
    case 'F': mat[2] |= 0x20u; break;
    case 'G': mat[3] |= 0x04u; break;
    case 'H': mat[3] |= 0x20u; break;
    case 'I': mat[4] |= 0x02u; break;
    case 'J': mat[4] |= 0x04u; break;
    case 'K': mat[4] |= 0x20u; break;
    case 'L': mat[5] |= 0x04u; break;
    case 'M': mat[4] |= 0x10u; break;
    case 'N': mat[4] |= 0x80u; break;
    case 'O': mat[4] |= 0x40u; break;
    case 'P': mat[5] |= 0x02u; break;
    case 'Q': mat[7] |= 0x40u; break;
    case 'R': mat[2] |= 0x02u; break;
    case 'S': mat[1] |= 0x20u; break;
    case 'T': mat[2] |= 0x40u; break;
    case 'U': mat[3] |= 0x40u; break;
    case 'V': mat[3] |= 0x80u; break;
    case 'W': mat[1] |= 0x02u; break;
    case 'X': mat[2] |= 0x80u; break;
    case 'Y': mat[3] |= 0x02u; break;
    case 'Z': mat[1] |= 0x10u; break;
    case '"': mat[7] |= 0x08u; mat[1] |= 0x80u; break;
    default: break;
    }
}

static void p4_update_inputs(u16 pad)
{
    WS->pad = pad;
    for (int r = 0; r < 8; r++)
        WS->p4_mat[r] = WS->p4_usb[r];

    /* Mirror pad onto Plus/4 cursor keys + Space + Shift + Return (plus Joy1/Joy2 in $FF08 latch) */
    if (pad & PAD_UP)     WS->p4_mat[5] |= 0x08u;
    if (pad & PAD_DOWN)   WS->p4_mat[5] |= 0x01u;
    if (pad & PAD_LEFT)   WS->p4_mat[6] |= 0x01u;
    if (pad & PAD_RIGHT)  WS->p4_mat[6] |= 0x08u;
    if (pad & (PAD_A | PAD_SELECT)) WS->p4_mat[7] |= 0x10u; /* Space */
    if (pad & PAD_B)      WS->p4_mat[1] |= 0x80u;           /* Shift */
    if (pad & PAD_START)  WS->p4_mat[0] |= 0x02u;           /* Return */

    if (WS->type_hold > 0) {
        WS->type_hold--;
        p4_press_ascii(WS->type_ch, WS->p4_mat);
    } else if (WS->type_r != WS->type_w && !WS->basic_mode) {
        WS->type_ch = WS->type_q[WS->type_r];
        WS->type_r = (WS->type_r + 1u) & 63u;
        WS->type_hold = 3;
        p4_press_ascii(WS->type_ch, WS->p4_mat);
    }
}

static u8 p4_io_read(u16 addr)
{
    if ((addr & 0xFFF0u) == 0xFD30u)
        return WS->fd30;
    if (addr >= 0xFD00u && addr < 0xFE00u)
        return 0xFFu;
    if (addr >= 0xFF00u && addr < 0xFF20u) {
        u8 r = (u8)(addr & 0x1Fu);
        switch (r) {
        case 0x00: return (u8)(WS->t_cnt[0] & 0xFFu);
        case 0x01: return (u8)(WS->t_cnt[0] >> 8);
        case 0x02: return (u8)(WS->t_cnt[1] & 0xFFu);
        case 0x03: return (u8)(WS->t_cnt[1] >> 8);
        case 0x04: return (u8)(WS->t_cnt[2] & 0xFFu);
        case 0x05: return (u8)(WS->t_cnt[2] >> 8);
        case 0x08: return WS->ff08_latch;
        case 0x09: return (u8)(WS->ted[0x09] | 0x25u);
        case 0x0A: return (u8)((WS->ted[0x0A] & 0x5Fu) | 0xA0u);
        case 0x1C: return (u8)(0xFEu | ((WS->cur_line >> 8) & 1u));
        case 0x1D: return (u8)(WS->cur_line & 0xFFu);
        default:   return WS->ted[r];
        }
    }
    if (addr >= 0xFF20u)
        return WS->rom_enabled ? WS->rom_hi[addr - 0xC000u] : WS->ram[addr];
    return WS->ram[addr];
}

static void p4_io_write(u16 addr, u8 v)
{
    if ((addr & 0xFFF0u) == 0xFD30u) {
        WS->fd30 = v;
        return;
    }
    if (addr >= 0xFD00u && addr < 0xFE00u)
        return;
    if (addr == 0xFF3Eu) {
        if (!WS->rom_enabled) { WS->rom_enabled = 1; p4_setup_mmu(); }
        return;
    }
    if (addr == 0xFF3Fu) {
        if (WS->rom_enabled) { WS->rom_enabled = 0; p4_setup_mmu(); }
        return;
    }
    if (addr >= 0xFF00u && addr < 0xFF20u) {
        u8 r = (u8)(addr & 0x1Fu);
        switch (r) {
        case 0x00:
            WS->t_reload1 = (u16)((WS->t_reload1 & 0xFF00u) | v);
            WS->t1_run = 0;
            break;
        case 0x01:
            WS->t_reload1 = (u16)(((u16)v << 8) | (WS->t_reload1 & 0xFFu));
            WS->t_cnt[0] = WS->t_reload1;
            WS->t1_run = 1;
            break;
        case 0x02: WS->t_cnt[1] = (u16)((WS->t_cnt[1] & 0xFF00u) | v); break;
        case 0x03: WS->t_cnt[1] = (u16)(((u16)v << 8) | (WS->t_cnt[1] & 0xFFu)); break;
        case 0x04: WS->t_cnt[2] = (u16)((WS->t_cnt[2] & 0xFF00u) | v); break;
        case 0x05: WS->t_cnt[2] = (u16)(((u16)v << 8) | (WS->t_cnt[2] & 0xFFu)); break;
        case 0x08: {
            /* Latch active-low keyboard rows (~$FD30 & ~v) + Joystick 1 (!(v & 4)) + Joystick 2 (!(v & 2)) */
            u8 out = 0xFFu;
            u8 sel = (u8)~WS->fd30;
            for (int row = 0; row < 8; row++) {
                if (sel & (1u << row))
                    out &= (u8)~WS->p4_mat[row];
            }
            if (!(v & 0x04u)) {
                if (WS->pad & PAD_UP)    out &= (u8)~0x01u;
                if (WS->pad & PAD_DOWN)  out &= (u8)~0x02u;
                if (WS->pad & PAD_LEFT)  out &= (u8)~0x04u;
                if (WS->pad & PAD_RIGHT) out &= (u8)~0x08u;
                if (WS->pad & PAD_A)     out &= (u8)~0x40u;
            }
            if (!(v & 0x02u)) {
                if (WS->pad & PAD_UP)    out &= (u8)~0x01u;
                if (WS->pad & PAD_DOWN)  out &= (u8)~0x02u;
                if (WS->pad & PAD_LEFT)  out &= (u8)~0x04u;
                if (WS->pad & PAD_RIGHT) out &= (u8)~0x08u;
                if (WS->pad & PAD_A)     out &= (u8)~0x80u;
            }
            WS->ff08_latch = out;
            break;
        }
        case 0x09:
            WS->ted[0x09] &= (u8)~(v & 0x7Fu);
            ted_recalc_irq();
            break;
        case 0x0A:
            WS->ted[0x0A] = v;
            ted_recalc_irq();
            break;
        default:
            WS->ted[r] = v;
            break;
        }
        return;
    }
    WS->ram[addr] = v;
}

INLINE u8 p4_rd(u16 a)
{
    const u8 *pg = WS->rdp[a >> 8];
    return pg ? pg[a & 0xFFu] : p4_io_read(a);
}

INLINE void p4_wr(u16 a, u8 v)
{
    if (a <= 1u) { WS->ram[a] = v; return; }
    u8 *pg = WS->wrp[a >> 8];
    if (pg) pg[a & 0xFFu] = v;
    else    p4_io_write(a, v);
}

INLINE u16 p4_rd16(u16 a)
{
    return (u16)(p4_rd(a) | ((u16)p4_rd((u16)(a + 1u)) << 8));
}

INLINE void p4_push(u8 v) { WS->ram[0x0100u + WS->s--] = v; }
INLINE u8   p4_pull(void) { return WS->ram[0x0100u + ++WS->s]; }
INLINE void p4_nz(u8 v)   { WS->p = (u8)((WS->p & ~(FN | FZ)) | (v & FN) | (v ? 0u : FZ)); }

static void p4_adc(u8 m)
{
    u32 c = WS->p & FC;
    if (WS->p & FD) {
        u32 lo = (WS->a & 0x0Fu) + (m & 0x0Fu) + c;
        u32 hi = (WS->a >> 4) + (m >> 4) + (lo > 9u ? 1u : 0u);
        if (lo > 9u) lo += 6u;
        u8 bin = (u8)(WS->a + m + c);
        WS->p &= ~(FC | FZ | FV | FN);
        if (!bin) WS->p |= FZ;
        if ((hi << 4) & 0x80u) WS->p |= FN;
        if ((~(WS->a ^ m) & (WS->a ^ (u8)((hi << 4) | (lo & 0x0Fu)))) & 0x80u) WS->p |= FV;
        if (hi > 9u) hi += 6u;
        if (hi > 15u) WS->p |= FC;
        WS->a = (u8)((hi << 4) | (lo & 0x0Fu));
    } else {
        u32 sum = (u32)WS->a + m + c;
        u8 r = (u8)sum;
        WS->p &= ~(FC | FZ | FV | FN);
        if (sum > 0xFFu) WS->p |= FC;
        if ((~(WS->a ^ m) & (WS->a ^ r)) & 0x80u) WS->p |= FV;
        WS->a = r;
        p4_nz(r);
    }
}

static void p4_sbc(u8 m)
{
    if (WS->p & FD) {
        u32 c = (WS->p & FC) ^ 1u;
        s32 lo = (s32)(WS->a & 0x0Fu) - (s32)(m & 0x0Fu) - (s32)c;
        s32 hi = (s32)(WS->a >> 4) - (s32)(m >> 4) - (lo < 0 ? 1 : 0);
        u32 diff = (u32)WS->a - m - c;
        u8 bin = (u8)diff;
        WS->p &= ~(FC | FZ | FV | FN);
        if (diff < 0x100u) WS->p |= FC;
        if (!bin) WS->p |= FZ;
        if (bin & 0x80u) WS->p |= FN;
        if (((WS->a ^ m) & (WS->a ^ bin)) & 0x80u) WS->p |= FV;
        if (lo < 0) lo -= 6;
        if (hi < 0) hi -= 6;
        WS->a = (u8)(((u32)hi << 4) | ((u32)lo & 0x0Fu));
    } else {
        p4_adc((u8)~m);
    }
}

INLINE void p4_cmp(u8 r, u8 m)
{
    u16 d = (u16)r - m;
    WS->p = (u8)((WS->p & ~(FC | FZ | FN)) | (r >= m ? FC : 0u) | ((u8)d ? 0u : FZ) | ((u8)d & FN));
}

INLINE void p4_br(int cond)
{
    s32 off = (signed char)p4_rd(WS->pc++);
    if (cond) {
        u16 np = (u16)(WS->pc + off);
        WS->cycles += ((np ^ WS->pc) & 0xFF00u) ? 2 : 1;
        WS->pc = np;
    }
}

static s32 p4_step(void)
{
    if ((WS->ted[0x09] & 0x80u) && !(WS->p & FI)) {
        p4_push((u8)(WS->pc >> 8));
        p4_push((u8)WS->pc);
        p4_push((u8)((WS->p | FU) & ~FB));
        WS->p |= FI;
        WS->pc = p4_rd16(0xFFFEu);
        WS->cycles += 7;
        return 7;
    }

    s32 c0 = WS->cycles;
    u8 op = p4_rd(WS->pc++);
    u16 ea = 0;
    u8 v = 0;

#define P_IMM()  (WS->pc++)
#define P_ZP()   ((u16)p4_rd(WS->pc++))
#define P_ZPX()  ((u16)((p4_rd(WS->pc++) + WS->x) & 0xFFu))
#define P_ZPY()  ((u16)((p4_rd(WS->pc++) + WS->y) & 0xFFu))
#define P_ABS()  (ea = p4_rd16(WS->pc), WS->pc += 2, ea)
#define P_ABX()  (ea = p4_rd16(WS->pc), WS->pc += 2, (u16)(ea + WS->x))
#define P_ABY()  (ea = p4_rd16(WS->pc), WS->pc += 2, (u16)(ea + WS->y))
#define P_INDX() (v = (u8)(p4_rd(WS->pc++) + WS->x), (u16)(WS->ram[v] | ((u16)WS->ram[(u8)(v + 1u)] << 8)))
#define P_INDY() (v = p4_rd(WS->pc++), (u16)((WS->ram[v] | ((u16)WS->ram[(u8)(v + 1u)] << 8)) + WS->y))

    switch (op) {
    case 0x00: WS->pc++; p4_push((u8)(WS->pc >> 8)); p4_push((u8)WS->pc); p4_push((u8)(WS->p | FU | FB));
               WS->p |= FI; WS->pc = p4_rd16(0xFFFEu); WS->cycles += 7; break;
    case 0x01: WS->a |= p4_rd(P_INDX()); p4_nz(WS->a); WS->cycles += 6; break;
    case 0x05: WS->a |= WS->ram[P_ZP()]; p4_nz(WS->a); WS->cycles += 3; break;
    case 0x06: ea = P_ZP(); v = WS->ram[ea]; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v <<= 1; WS->ram[ea] = v; p4_nz(v); WS->cycles += 5; break;
    case 0x08: p4_push((u8)(WS->p | FU | FB)); WS->cycles += 3; break;
    case 0x09: WS->a |= p4_rd(P_IMM()); p4_nz(WS->a); WS->cycles += 2; break;
    case 0x0A: WS->p = (u8)((WS->p & ~FC) | (WS->a >> 7)); WS->a <<= 1; p4_nz(WS->a); WS->cycles += 2; break;
    case 0x0D: WS->a |= p4_rd(P_ABS()); p4_nz(WS->a); WS->cycles += 4; break;
    case 0x0E: ea = P_ABS(); v = p4_rd(ea); WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v <<= 1; p4_wr(ea, v); p4_nz(v); WS->cycles += 6; break;
    case 0x10: p4_br(!(WS->p & FN)); WS->cycles += 2; break;
    case 0x11: WS->a |= p4_rd(P_INDY()); p4_nz(WS->a); WS->cycles += 5; break;
    case 0x15: WS->a |= WS->ram[P_ZPX()]; p4_nz(WS->a); WS->cycles += 4; break;
    case 0x16: ea = P_ZPX(); v = WS->ram[ea]; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v <<= 1; WS->ram[ea] = v; p4_nz(v); WS->cycles += 6; break;
    case 0x18: WS->p &= ~FC; WS->cycles += 2; break;
    case 0x19: WS->a |= p4_rd(P_ABY()); p4_nz(WS->a); WS->cycles += 4; break;
    case 0x1D: WS->a |= p4_rd(P_ABX()); p4_nz(WS->a); WS->cycles += 4; break;
    case 0x1E: ea = P_ABX(); v = p4_rd(ea); WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v <<= 1; p4_wr(ea, v); p4_nz(v); WS->cycles += 7; break;

    case 0x20: ea = P_ABS(); WS->pc--; p4_push((u8)(WS->pc >> 8)); p4_push((u8)WS->pc); WS->pc = ea; WS->cycles += 6; break;
    case 0x21: WS->a &= p4_rd(P_INDX()); p4_nz(WS->a); WS->cycles += 6; break;
    case 0x24: v = WS->ram[P_ZP()]; WS->p = (u8)((WS->p & ~(FZ | FV | FN)) | (v & (FV | FN)) | ((WS->a & v) ? 0u : FZ)); WS->cycles += 3; break;
    case 0x25: WS->a &= WS->ram[P_ZP()]; p4_nz(WS->a); WS->cycles += 3; break;
    case 0x26: ea = P_ZP(); v = WS->ram[ea]; { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v = (u8)((v << 1) | c); } WS->ram[ea] = v; p4_nz(v); WS->cycles += 5; break;
    case 0x28: WS->p = (u8)((p4_pull() & ~FB) | FU); WS->cycles += 4; break;
    case 0x29: WS->a &= p4_rd(P_IMM()); p4_nz(WS->a); WS->cycles += 2; break;
    case 0x2A: { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (WS->a >> 7)); WS->a = (u8)((WS->a << 1) | c); } p4_nz(WS->a); WS->cycles += 2; break;
    case 0x2C: v = p4_rd(P_ABS()); WS->p = (u8)((WS->p & ~(FZ | FV | FN)) | (v & (FV | FN)) | ((WS->a & v) ? 0u : FZ)); WS->cycles += 4; break;
    case 0x2D: WS->a &= p4_rd(P_ABS()); p4_nz(WS->a); WS->cycles += 4; break;
    case 0x2E: ea = P_ABS(); v = p4_rd(ea); { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v = (u8)((v << 1) | c); } p4_wr(ea, v); p4_nz(v); WS->cycles += 6; break;
    case 0x30: p4_br((WS->p & FN) != 0); WS->cycles += 2; break;
    case 0x31: WS->a &= p4_rd(P_INDY()); p4_nz(WS->a); WS->cycles += 5; break;
    case 0x35: WS->a &= WS->ram[P_ZPX()]; p4_nz(WS->a); WS->cycles += 4; break;
    case 0x36: ea = P_ZPX(); v = WS->ram[ea]; { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v = (u8)((v << 1) | c); } WS->ram[ea] = v; p4_nz(v); WS->cycles += 6; break;
    case 0x38: WS->p |= FC; WS->cycles += 2; break;
    case 0x39: WS->a &= p4_rd(P_ABY()); p4_nz(WS->a); WS->cycles += 4; break;
    case 0x3D: WS->a &= p4_rd(P_ABX()); p4_nz(WS->a); WS->cycles += 4; break;
    case 0x3E: ea = P_ABX(); v = p4_rd(ea); { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v >> 7)); v = (u8)((v << 1) | c); } p4_wr(ea, v); p4_nz(v); WS->cycles += 7; break;

    case 0x40: WS->p = (u8)((p4_pull() & ~FB) | FU); v = p4_pull(); WS->pc = (u16)(v | ((u16)p4_pull() << 8)); WS->cycles += 6; break;
    case 0x41: WS->a ^= p4_rd(P_INDX()); p4_nz(WS->a); WS->cycles += 6; break;
    case 0x45: WS->a ^= WS->ram[P_ZP()]; p4_nz(WS->a); WS->cycles += 3; break;
    case 0x46: ea = P_ZP(); v = WS->ram[ea]; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v >>= 1; WS->ram[ea] = v; p4_nz(v); WS->cycles += 5; break;
    case 0x48: p4_push(WS->a); WS->cycles += 3; break;
    case 0x49: WS->a ^= p4_rd(P_IMM()); p4_nz(WS->a); WS->cycles += 2; break;
    case 0x4A: WS->p = (u8)((WS->p & ~FC) | (WS->a & 1u)); WS->a >>= 1; p4_nz(WS->a); WS->cycles += 2; break;
    case 0x4C: WS->pc = P_ABS(); WS->cycles += 3; break;
    case 0x4D: WS->a ^= p4_rd(P_ABS()); p4_nz(WS->a); WS->cycles += 4; break;
    case 0x4E: ea = P_ABS(); v = p4_rd(ea); WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v >>= 1; p4_wr(ea, v); p4_nz(v); WS->cycles += 6; break;
    case 0x50: p4_br(!(WS->p & FV)); WS->cycles += 2; break;
    case 0x51: WS->a ^= p4_rd(P_INDY()); p4_nz(WS->a); WS->cycles += 5; break;
    case 0x55: WS->a ^= WS->ram[P_ZPX()]; p4_nz(WS->a); WS->cycles += 4; break;
    case 0x56: ea = P_ZPX(); v = WS->ram[ea]; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v >>= 1; WS->ram[ea] = v; p4_nz(v); WS->cycles += 6; break;
    case 0x58: WS->p &= ~FI; WS->cycles += 2; break;
    case 0x59: WS->a ^= p4_rd(P_ABY()); p4_nz(WS->a); WS->cycles += 4; break;
    case 0x5D: WS->a ^= p4_rd(P_ABX()); p4_nz(WS->a); WS->cycles += 4; break;
    case 0x5E: ea = P_ABX(); v = p4_rd(ea); WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v >>= 1; p4_wr(ea, v); p4_nz(v); WS->cycles += 7; break;

    case 0x60: v = p4_pull(); WS->pc = (u16)((v | ((u16)p4_pull() << 8)) + 1u); WS->cycles += 6; break;
    case 0x61: p4_adc(p4_rd(P_INDX())); WS->cycles += 6; break;
    case 0x65: p4_adc(WS->ram[P_ZP()]); WS->cycles += 3; break;
    case 0x66: ea = P_ZP(); v = WS->ram[ea]; { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v = (u8)((v >> 1) | (c << 7)); } WS->ram[ea] = v; p4_nz(v); WS->cycles += 5; break;
    case 0x68: WS->a = p4_pull(); p4_nz(WS->a); WS->cycles += 4; break;
    case 0x69: p4_adc(p4_rd(P_IMM())); WS->cycles += 2; break;
    case 0x6A: { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (WS->a & 1u)); WS->a = (u8)((WS->a >> 1) | (c << 7)); } p4_nz(WS->a); WS->cycles += 2; break;
    case 0x6C: ea = P_ABS(); WS->pc = (u16)(p4_rd(ea) | ((u16)p4_rd((u16)((ea & 0xFF00u) | ((ea + 1u) & 0xFFu))) << 8)); WS->cycles += 5; break;
    case 0x6D: p4_adc(p4_rd(P_ABS())); WS->cycles += 4; break;
    case 0x6E: ea = P_ABS(); v = p4_rd(ea); { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v = (u8)((v >> 1) | (c << 7)); } p4_wr(ea, v); p4_nz(v); WS->cycles += 6; break;
    case 0x70: p4_br((WS->p & FV) != 0); WS->cycles += 2; break;
    case 0x71: p4_adc(p4_rd(P_INDY())); WS->cycles += 5; break;
    case 0x75: p4_adc(WS->ram[P_ZPX()]); WS->cycles += 4; break;
    case 0x76: ea = P_ZPX(); v = WS->ram[ea]; { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v = (u8)((v >> 1) | (c << 7)); } WS->ram[ea] = v; p4_nz(v); WS->cycles += 6; break;
    case 0x78: WS->p |= FI; WS->cycles += 2; break;
    case 0x79: p4_adc(p4_rd(P_ABY())); WS->cycles += 4; break;
    case 0x7D: p4_adc(p4_rd(P_ABX())); WS->cycles += 4; break;
    case 0x7E: ea = P_ABX(); v = p4_rd(ea); { u8 c = WS->p & FC; WS->p = (u8)((WS->p & ~FC) | (v & 1u)); v = (u8)((v >> 1) | (c << 7)); } p4_wr(ea, v); p4_nz(v); WS->cycles += 7; break;

    case 0x81: p4_wr(P_INDX(), WS->a); WS->cycles += 6; break;
    case 0x84: WS->ram[P_ZP()] = WS->y; WS->cycles += 3; break;
    case 0x85: WS->ram[P_ZP()] = WS->a; WS->cycles += 3; break;
    case 0x86: WS->ram[P_ZP()] = WS->x; WS->cycles += 3; break;
    case 0x88: WS->y--; p4_nz(WS->y); WS->cycles += 2; break;
    case 0x8A: WS->a = WS->x; p4_nz(WS->a); WS->cycles += 2; break;
    case 0x8C: p4_wr(P_ABS(), WS->y); WS->cycles += 4; break;
    case 0x8D: p4_wr(P_ABS(), WS->a); WS->cycles += 4; break;
    case 0x8E: p4_wr(P_ABS(), WS->x); WS->cycles += 4; break;
    case 0x90: p4_br(!(WS->p & FC)); WS->cycles += 2; break;
    case 0x91: p4_wr(P_INDY(), WS->a); WS->cycles += 6; break;
    case 0x94: WS->ram[P_ZPX()] = WS->y; WS->cycles += 4; break;
    case 0x95: WS->ram[P_ZPX()] = WS->a; WS->cycles += 4; break;
    case 0x96: WS->ram[P_ZPY()] = WS->x; WS->cycles += 4; break;
    case 0x98: WS->a = WS->y; p4_nz(WS->a); WS->cycles += 2; break;
    case 0x99: p4_wr(P_ABY(), WS->a); WS->cycles += 5; break;
    case 0x9A: WS->s = WS->x; WS->cycles += 2; break;
    case 0x9D: p4_wr(P_ABX(), WS->a); WS->cycles += 5; break;

    case 0xA0: WS->y = p4_rd(P_IMM()); p4_nz(WS->y); WS->cycles += 2; break;
    case 0xA1: WS->a = p4_rd(P_INDX()); p4_nz(WS->a); WS->cycles += 6; break;
    case 0xA2: WS->x = p4_rd(P_IMM()); p4_nz(WS->x); WS->cycles += 2; break;
    case 0xA4: WS->y = WS->ram[P_ZP()]; p4_nz(WS->y); WS->cycles += 3; break;
    case 0xA5: WS->a = WS->ram[P_ZP()]; p4_nz(WS->a); WS->cycles += 3; break;
    case 0xA6: WS->x = WS->ram[P_ZP()]; p4_nz(WS->x); WS->cycles += 3; break;
    case 0xA8: WS->y = WS->a; p4_nz(WS->y); WS->cycles += 2; break;
    case 0xA9: WS->a = p4_rd(P_IMM()); p4_nz(WS->a); WS->cycles += 2; break;
    case 0xAA: WS->x = WS->a; p4_nz(WS->x); WS->cycles += 2; break;
    case 0xAC: WS->y = p4_rd(P_ABS()); p4_nz(WS->y); WS->cycles += 4; break;
    case 0xAD: WS->a = p4_rd(P_ABS()); p4_nz(WS->a); WS->cycles += 4; break;
    case 0xAE: WS->x = p4_rd(P_ABS()); p4_nz(WS->x); WS->cycles += 4; break;
    case 0xB0: p4_br((WS->p & FC) != 0); WS->cycles += 2; break;
    case 0xB1: WS->a = p4_rd(P_INDY()); p4_nz(WS->a); WS->cycles += 5; break;
    case 0xB4: WS->y = WS->ram[P_ZPX()]; p4_nz(WS->y); WS->cycles += 4; break;
    case 0xB5: WS->a = WS->ram[P_ZPX()]; p4_nz(WS->a); WS->cycles += 4; break;
    case 0xB6: WS->x = WS->ram[P_ZPY()]; p4_nz(WS->x); WS->cycles += 4; break;
    case 0xB8: WS->p &= ~FV; WS->cycles += 2; break;
    case 0xB9: WS->a = p4_rd(P_ABY()); p4_nz(WS->a); WS->cycles += 4; break;
    case 0xBA: WS->x = WS->s; p4_nz(WS->x); WS->cycles += 2; break;
    case 0xBC: WS->y = p4_rd(P_ABX()); p4_nz(WS->y); WS->cycles += 4; break;
    case 0xBD: WS->a = p4_rd(P_ABX()); p4_nz(WS->a); WS->cycles += 4; break;
    case 0xBE: WS->x = p4_rd(P_ABY()); p4_nz(WS->x); WS->cycles += 4; break;

    case 0xC0: p4_cmp(WS->y, p4_rd(P_IMM())); WS->cycles += 2; break;
    case 0xC1: p4_cmp(WS->a, p4_rd(P_INDX())); WS->cycles += 6; break;
    case 0xC4: p4_cmp(WS->y, WS->ram[P_ZP()]); WS->cycles += 3; break;
    case 0xC5: p4_cmp(WS->a, WS->ram[P_ZP()]); WS->cycles += 3; break;
    case 0xC6: ea = P_ZP(); v = (u8)(WS->ram[ea] - 1u); WS->ram[ea] = v; p4_nz(v); WS->cycles += 5; break;
    case 0xC8: WS->y++; p4_nz(WS->y); WS->cycles += 2; break;
    case 0xC9: p4_cmp(WS->a, p4_rd(P_IMM())); WS->cycles += 2; break;
    case 0xCA: WS->x--; p4_nz(WS->x); WS->cycles += 2; break;
    case 0xCC: p4_cmp(WS->y, p4_rd(P_ABS())); WS->cycles += 4; break;
    case 0xCD: p4_cmp(WS->a, p4_rd(P_ABS())); WS->cycles += 4; break;
    case 0xCE: ea = P_ABS(); v = (u8)(p4_rd(ea) - 1u); p4_wr(ea, v); p4_nz(v); WS->cycles += 6; break;
    case 0xD0: p4_br(!(WS->p & FZ)); WS->cycles += 2; break;
    case 0xD1: p4_cmp(WS->a, p4_rd(P_INDY())); WS->cycles += 5; break;
    case 0xD5: p4_cmp(WS->a, WS->ram[P_ZPX()]); WS->cycles += 4; break;
    case 0xD6: ea = P_ZPX(); v = (u8)(WS->ram[ea] - 1u); WS->ram[ea] = v; p4_nz(v); WS->cycles += 6; break;
    case 0xD8: WS->p &= ~FD; WS->cycles += 2; break;
    case 0xD9: p4_cmp(WS->a, p4_rd(P_ABY())); WS->cycles += 4; break;
    case 0xDD: p4_cmp(WS->a, p4_rd(P_ABX())); WS->cycles += 4; break;
    case 0xDE: ea = P_ABX(); v = (u8)(p4_rd(ea) - 1u); p4_wr(ea, v); p4_nz(v); WS->cycles += 7; break;

    case 0xE0: p4_cmp(WS->x, p4_rd(P_IMM())); WS->cycles += 2; break;
    case 0xE1: p4_sbc(p4_rd(P_INDX())); WS->cycles += 6; break;
    case 0xE4: p4_cmp(WS->x, WS->ram[P_ZP()]); WS->cycles += 3; break;
    case 0xE5: p4_sbc(WS->ram[P_ZP()]); WS->cycles += 3; break;
    case 0xE6: ea = P_ZP(); v = (u8)(WS->ram[ea] + 1u); WS->ram[ea] = v; p4_nz(v); WS->cycles += 5; break;
    case 0xE8: WS->x++; p4_nz(WS->x); WS->cycles += 2; break;
    case 0xE9: case 0xEB: p4_sbc(p4_rd(P_IMM())); WS->cycles += 2; break;
    case 0xEA: WS->cycles += 2; break;
    case 0xEC: p4_cmp(WS->x, p4_rd(P_ABS())); WS->cycles += 4; break;
    case 0xED: p4_sbc(p4_rd(P_ABS())); WS->cycles += 4; break;
    case 0xEE: ea = P_ABS(); v = (u8)(p4_rd(ea) + 1u); p4_wr(ea, v); p4_nz(v); WS->cycles += 6; break;
    case 0xF0: p4_br((WS->p & FZ) != 0); WS->cycles += 2; break;
    case 0xF1: p4_sbc(p4_rd(P_INDY())); WS->cycles += 5; break;
    case 0xF5: p4_sbc(WS->ram[P_ZPX()]); WS->cycles += 4; break;
    case 0xF6: ea = P_ZPX(); v = (u8)(WS->ram[ea] + 1u); WS->ram[ea] = v; p4_nz(v); WS->cycles += 6; break;
    case 0xF8: WS->p |= FD; WS->cycles += 2; break;
    case 0xF9: p4_sbc(p4_rd(P_ABY())); WS->cycles += 4; break;
    case 0xFD: p4_sbc(p4_rd(P_ABX())); WS->cycles += 4; break;
    case 0xFE: ea = P_ABX(); v = (u8)(p4_rd(ea) + 1u); p4_wr(ea, v); p4_nz(v); WS->cycles += 7; break;

    case 0xA7: WS->a = WS->x = WS->ram[P_ZP()]; p4_nz(WS->a); WS->cycles += 3; break;
    case 0xB7: WS->a = WS->x = WS->ram[P_ZPY()]; p4_nz(WS->a); WS->cycles += 4; break;
    case 0xAF: WS->a = WS->x = p4_rd(P_ABS()); p4_nz(WS->a); WS->cycles += 4; break;
    case 0xBF: WS->a = WS->x = p4_rd(P_ABY()); p4_nz(WS->a); WS->cycles += 4; break;
    case 0x87: WS->ram[P_ZP()] = (u8)(WS->a & WS->x); WS->cycles += 3; break;
    case 0x8F: p4_wr(P_ABS(), (u8)(WS->a & WS->x)); WS->cycles += 4; break;
    case 0x04: case 0x44: case 0x64: WS->pc++; WS->cycles += 3; break;
    case 0x0C: WS->pc += 2; WS->cycles += 4; break;
    case 0x14: case 0x34: case 0x54: case 0x74: case 0xD4: case 0xF4: WS->pc++; WS->cycles += 4; break;
    case 0x1C: case 0x3C: case 0x5C: case 0x7C: case 0xDC: case 0xFC: WS->pc += 2; WS->cycles += 4; break;
    case 0x02: case 0x12: case 0x22: case 0x32: case 0x42: case 0x52:
    case 0x62: case 0x72: case 0x92: case 0xB2: case 0xD2: case 0xF2:
        WS->jam = 1; WS->pc--; WS->cycles += 2; break;
    default:
        WS->cycles += 2; break;
    }

    s32 dt = WS->cycles - c0;
    if (WS->t1_run) {
        if ((s32)WS->t_cnt[0] <= dt) {
            WS->t_cnt[0] = WS->t_reload1;
            WS->ted[0x09] |= 0x08u;
            ted_recalc_irq();
        } else {
            WS->t_cnt[0] = (u16)(WS->t_cnt[0] - dt);
        }
    }
    if ((s32)WS->t_cnt[1] <= dt) {
        WS->t_cnt[1] = (u16)(WS->t_cnt[1] - dt);
        WS->ted[0x09] |= 0x10u;
        ted_recalc_irq();
    } else {
        WS->t_cnt[1] = (u16)(WS->t_cnt[1] - dt);
    }
    if ((s32)WS->t_cnt[2] <= dt) {
        WS->t_cnt[2] = (u16)(WS->t_cnt[2] - dt);
        WS->ted[0x09] |= 0x40u;
        ted_recalc_irq();
    } else {
        WS->t_cnt[2] = (u16)(WS->t_cnt[2] - dt);
    }
    return dt;
}

static void render_ted_line(int y, u16 *dst)
{
    u8 r6 = WS->ted[0x06];
    u8 r7 = WS->ted[0x07];
    u16 border = WS->ted_pal15[WS->ted[0x19] & 0x7Fu];
    if (!(r6 & 0x10u)) {
        for (int x = 0; x < PLUS4_W; x++) dst[x] = border;
        return;
    }

    int bmm = (r6 >> 5) & 1;
    int ecm = (r6 >> 6) & 1;
    int mcm = (r7 >> 4) & 1;
    int rev_off = (r7 >> 7) & 1;        /* 1 = full 256-char set (no hardware reverse) */
    int ch_rom  = (WS->ted[0x12] >> 2) & 1;

    u16 vm_base   = (u16)(((u16)(WS->ted[0x14] & 0xF8u) << 8) + 0x0400u);
    u16 col_base  = (u16)((u16)(WS->ted[0x14] & 0xF8u) << 8);
    u16 chr_base  = (u16)((u16)(WS->ted[0x13] & (rev_off ? 0xF8u : 0xFCu)) << 8);
    u16 bmp_base  = (u16)((u16)(WS->ted[0x12] & 0x38u) << 10);

    u16 bg0 = WS->ted_pal15[WS->ted[0x15] & 0x7Fu];
    u16 bg1 = WS->ted_pal15[WS->ted[0x16] & 0x7Fu];
    u16 bg2 = WS->ted_pal15[WS->ted[0x17] & 0x7Fu];
    u16 bg3 = WS->ted_pal15[WS->ted[0x18] & 0x7Fu];

    int row = y >> 3, py = y & 7;
    int blink_hide = (WS->frames & 16u) != 0;

    for (int col = 0; col < 40; col++) {
        u16 off = (u16)(row * 40 + col);
        u8 sc = WS->ram[(vm_base + off) & 0xFFFFu];
        u8 cb = WS->ram[(col_base + off) & 0xFFFFu];
        u16 *cell = dst + col * 8;

        if (bmm) {
            u8 bits = WS->ram[(bmp_base + (u16)row * 320u + (u16)col * 8u + py) & 0xFFFFu];
            if (mcm) {
                u16 c01 = WS->ted_pal15[((cb & 0x0Fu) << 4) | (sc >> 4)];
                u16 c10 = WS->ted_pal15[((cb & 0xF0u))      | (sc & 0x0Fu)];
                u16 mc[4] = { bg0, c01, c10, bg1 };
                for (int px = 0; px < 4; px++) {
                    u16 p = mc[(bits >> (6 - px * 2)) & 3u];
                    cell[px * 2] = cell[px * 2 + 1] = p;
                }
            } else {
                u16 c1 = WS->ted_pal15[((cb & 0x0Fu) << 4) | (sc >> 4)];
                u16 c0 = WS->ted_pal15[((cb & 0xF0u))      | (sc & 0x0Fu)];
                for (int px = 0; px < 8; px++)
                    cell[px] = (bits & (0x80u >> px)) ? c1 : c0;
            }
        } else {
            u8 ch_idx = (ecm ? (sc & 0x3Fu) : (rev_off ? sc : (sc & 0x7Fu)));
            u16 g_addr = (u16)(chr_base + (u16)ch_idx * 8u + py);
            u8 bits = ch_rom ? WS->rom_hi[0x1000u + (g_addr & 0x0FFFu)] : WS->ram[g_addr];
            if (!ecm && !mcm && !rev_off && (sc & 0x80u))
                bits ^= 0xFFu;
            if (!mcm && (cb & 0x80u) && !rev_off && blink_hide)
                bits = 0u;

            if (mcm && (cb & 0x80u)) {
                u16 mc[4] = { bg0, bg1, bg2, WS->ted_pal15[cb & 0x7Fu] };
                for (int px = 0; px < 4; px++) {
                    u16 p = mc[(bits >> (6 - px * 2)) & 3u];
                    cell[px * 2] = cell[px * 2 + 1] = p;
                }
            } else {
                u16 bg = ecm ? ((sc >> 6) == 0 ? bg0 : (sc >> 6) == 1 ? bg1 : (sc >> 6) == 2 ? bg2 : bg3) : bg0;
                u16 fg = WS->ted_pal15[cb & 0x7Fu];
                for (int px = 0; px < 8; px++)
                    cell[px] = (bits & (0x80u >> px)) ? fg : bg;
            }
        }
    }
}

static void build_plus4_roms(u16 boot_entry)
{
    ws_zero(WS->rom_lo, sizeof(WS->rom_lo));
    ws_zero(WS->rom_hi, sizeof(WS->rom_hi));

    /* Build Commodore screen-code font at $D000 (rom_hi + $1000):
       0x00='@', 0x01..0x1A='A'..'Z', 0x1B='[', 0x20..0x3F=' '..'?' */
    for (int sc = 0; sc < 64; sc++) {
        int asc = (sc == 0) ? '@' : (sc <= 26) ? ('A' + sc - 1) : (sc < 32) ? ('[' + sc - 27) : sc;
        const u8 *g = font5x7[(asc >= 32 && asc < 128) ? (asc - 32) : 0];
        for (int py = 0; py < 8; py++) {
            u8 row = 0;
            if (py < 7) {
                for (int px = 0; px < 5; px++)
                    if (g[px] & (1u << py)) row |= (u8)(0x40u >> px);
            }
            WS->rom_hi[0x1000u + sc * 8 + py] = row;
            WS->rom_hi[0x1000u + (sc + 64) * 8 + py] = row;
            WS->rom_hi[0x1000u + (sc + 128) * 8 + py] = (u8)~row;
            WS->rom_hi[0x1000u + (sc + 192) * 8 + py] = (u8)~row;
        }
    }

    /* Hardware IRQ Entry at $CE00 (rom_hi + $0E00) AND mirrored in RAM at $FE00 so IRQ works
       even if a game switches ROM out via $FF3F!
       $FE00: PHA; TXA; PHA; TYA; PHA; JMP ($0314)
       $FE10 (default CINV): LDA $FF09; STA $FF09; PLA; TAY; PLA; TAX; PLA; RTI */
    static const u8 irq_entry[] = { 0x48, 0x8A, 0x48, 0x98, 0x48, 0x6C, 0x14, 0x03 };
    static const u8 irq_exit[]  = { 0xAD, 0x09, 0xFF, 0x8D, 0x09, 0xFF, 0x68, 0xA8, 0x68, 0xAA, 0x68, 0x40 };
    for (u32 i = 0; i < sizeof(irq_entry); i++) {
        WS->rom_hi[0x3E00u + i] = WS->ram[0xFE00u + i] = irq_entry[i];
    }
    for (u32 i = 0; i < sizeof(irq_exit); i++) {
        WS->rom_hi[0x3E10u + i] = WS->ram[0xFE10u + i] = irq_exit[i];
    }

    /* Reset stub at $FE40:
       SEI; CLD; LDX #$FF; TXS
       Set CINV ($0314/$0315) = $FE10
       Clear A=0, X=0, Y=0 (critical for Inufuto InitVram!), CLI, JMP boot_entry */
    u32 r = 0x3E40u;
    #define EMIT(b) do { WS->rom_hi[r] = WS->ram[0xC000u + r] = (u8)(b); r++; } while (0)
    EMIT(0x78); EMIT(0xD8); EMIT(0xA2); EMIT(0xFF); EMIT(0x9A);
    EMIT(0xA9); EMIT(0x10); EMIT(0x8D); EMIT(0x14); EMIT(0x03);
    EMIT(0xA9); EMIT(0xFE); EMIT(0x8D); EMIT(0x15); EMIT(0x03);
    EMIT(0xA9); EMIT(0x00); EMIT(0xAA); EMIT(0xA8);
    EMIT(0x58);
    if (boot_entry) {
        EMIT(0x4C); EMIT(boot_entry & 0xFFu); EMIT(boot_entry >> 8);
    } else {
        EMIT(0x4C); EMIT((0xC000u + r) & 0xFFu); EMIT((0xC000u + r) >> 8);
    }
    #undef EMIT

    /* Kernal jump stubs ($FFD2 CHROUT -> RTS, $FFE4 GETIN -> LDA #0 : RTS) */
    WS->rom_hi[0x3FD2] = WS->ram[0xFFD2] = 0x60u;
    WS->rom_hi[0x3FE4] = WS->ram[0xFFE4] = 0xA9u;
    WS->rom_hi[0x3FE5] = WS->ram[0xFFE5] = 0x00u;
    WS->rom_hi[0x3FE6] = WS->ram[0xFFE6] = 0x60u;

    /* 6502 Vectors at $FFFA..$FFFF (placed in BOTH rom_hi and RAM!) */
    WS->rom_hi[0x3FFA] = WS->ram[0xFFFA] = 0x10u; WS->rom_hi[0x3FFB] = WS->ram[0xFFFB] = 0xFEu;
    WS->rom_hi[0x3FFC] = WS->ram[0xFFFC] = 0x40u; WS->rom_hi[0x3FFD] = WS->ram[0xFFFD] = 0xFEu;
    WS->rom_hi[0x3FFE] = WS->ram[0xFFFE] = 0x00u; WS->rom_hi[0x3FFF] = WS->ram[0xFFFF] = 0xFEu;
}

static u8 asc_to_p4sc(char c)
{
    if (c == '@') return 0;
    if (c >= 'A' && c <= 'Z') return (u8)(c - 'A' + 1);
    if (c >= 'a' && c <= 'z') return (u8)(c - 'a' + 1);
    if (c >= 32 && c < 64) return (u8)c;
    return 32;
}

static void p4_basic_puts(int x, int y, const char *s, u8 col)
{
    while (*s && y < 25) {
        if (*s == '\n') { x = 0; y++; s++; continue; }
        if (x >= 40) { x = 0; y++; if (y >= 25) break; }
        WS->ram[0x0C00u + y * 40 + x] = asc_to_p4sc(*s++);
        WS->ram[0x0800u + y * 40 + x] = col;
        x++;
    }
    WS->bas_x = (u8)x;
    WS->bas_y = (u8)y;
}

static void p4_basic_init(void)
{
    /* Classic Commodore Plus/4 White screen ($71) + Light Blue-Purple border ($6E) + Black text ($00) */
    WS->ted[0x06] = 0x1Bu;
    WS->ted[0x07] = 0x48u;              /* PAL 40-col */
    WS->ted[0x12] = 0x04u;              /* ROM charset */
    WS->ted[0x13] = 0xD0u;              /* $D000 */
    WS->ted[0x14] = 0x08u;              /* Screen $0C00, Color $0800 */
    WS->ted[0x15] = 0x71u;              /* White background */
    WS->ted[0x19] = 0x6Eu;              /* Plus/4 lavender-blue border */
    for (int i = 0; i < 1000; i++) {
        WS->ram[0x0C00u + i] = 32u;
        WS->ram[0x0800u + i] = 0x00u;
    }
    p4_basic_puts(1, 1, "COMMODORE BASIC V3.5 60671 BYTES FREE", 0x00u);
    p4_basic_puts(0, 3, "READY.", 0x00u);
    WS->bas_x = 0; WS->bas_y = 4; WS->bas_len = 0;
}

static void p4_basic_step(void)
{
    while (WS->type_r != WS->type_w) {
        char c = WS->type_q[WS->type_r];
        WS->type_r = (WS->type_r + 1u) & 63u;
        if (c == '\r' || c == '\n') {
            WS->ram[0x0C00u + WS->bas_y * 40 + WS->bas_x] = 32u;
            if (WS->bas_y < 23) WS->bas_y++;
            p4_basic_puts(0, WS->bas_y, "READY.", 0x00u);
            if (WS->bas_y < 23) WS->bas_y++;
            WS->bas_x = 0; WS->bas_len = 0;
        } else if ((c == 8 || c == 127) && WS->bas_len > 0) {
            WS->ram[0x0C00u + WS->bas_y * 40 + WS->bas_x] = 32u;
            WS->bas_len--;
            if (WS->bas_x > 0) WS->bas_x--;
        } else if (c >= 32 && c < 127 && WS->bas_x < 39) {
            WS->bas_line[WS->bas_len < 38 ? WS->bas_len++ : 38] = c;
            WS->ram[0x0C00u + WS->bas_y * 40 + WS->bas_x] = asc_to_p4sc(c);
            WS->ram[0x0800u + WS->bas_y * 40 + WS->bas_x] = 0x00u;
            WS->bas_x++;
        }
    }
    WS->ram[0x0C00u + WS->bas_y * 40 + WS->bas_x] = (WS->frames & 16u) ? (32u | 0x80u) : 32u;
}

static u16 find_p4_entry(u16 start, u16 end)
{
    /* 1. Standard CBM BASIC stub at $1001 with SYS token (0x9E) */
    if (start == 0x1001u && end > 0x1008u) {
        for (u16 a = 0x1005u; a < 0x1040u && a < end; a++) {
            if (WS->img_buf[a] == 0x9Eu) {
                a++;
                while (a < end && WS->img_buf[a] == ' ') a++;
                u32 sys_addr = 0;
                while (a < end && WS->img_buf[a] >= '0' && WS->img_buf[a] <= '9') {
                    sys_addr = sys_addr * 10u + (u32)(WS->img_buf[a] - '0');
                    a++;
                }
                if (sys_addr >= 0x1000u && sys_addr < 0xFD00u)
                    return (u16)sys_addr;
            }
        }
    }
    return start;
}

static int parse_c16_tape_raw(const u8 *data, u32 size)
{
    u8 ver = data[12];
    u32 pos = 20u;

    #define NEXT_CLS(sym_out) do { \
        if (pos >= size) { sym_out = 0; break; } \
        if (data[pos] == 0u) { pos += 4u; sym_out = 'P'; } \
        else { \
            u32 w = data[pos++]; \
            if (ver >= 2u && pos < size && data[pos] != 0u) w += data[pos++]; \
            sym_out = (w < 84u) ? 'S' : (w < 168u) ? 'M' : 'L'; \
        } \
    } while (0)

    u32 pilot_s = 0;
    int got_hdr = 0;
    u16 load_st = 0x1800u, load_en = 0;

    while (pos < size) {
        char s1 = 0;
        NEXT_CLS(s1);
        if (!s1) break;
        if (s1 == 'S') {
            pilot_s++;
            continue;
        }
        if (s1 == 'L' && pilot_s >= 32u) {
            char s2 = 0;
            NEXT_CLS(s2);
            pilot_s = 0;
            if (s2 != 'M') continue;

            /* First (L, M) is byte-start of countdown byte 0 (0x89 or 0x09)! */
            u32 b_idx = 0;
            u8 hdr[32];
            ws_zero(hdr, sizeof(hdr));
            int in_block = 1;
            while (in_block && pos < size) {
                if (b_idx > 0) {
                    char m1 = 0, m2 = 0;
                    NEXT_CLS(m1);
                    NEXT_CLS(m2);
                    if (m1 == 'L' && m2 == 'S') break;
                    if (!(m1 == 'L' && m2 == 'M')) break;
                }
                u8 byte_val = 0;
                for (int bit = 0; bit < 9; bit++) {
                    char a = 0, c = 0;
                    NEXT_CLS(a);
                    NEXT_CLS(c);
                    u8 bv = (a == 'M' && c == 'S') ? 1u : 0u;
                    if (bit < 8) byte_val |= (u8)(bv << bit);
                }
                if (!got_hdr) {
                    if (b_idx >= 9u && b_idx < 9u + 32u)
                        hdr[b_idx - 9u] = byte_val;
                } else if (b_idx >= 9u) {
                    u32 dst = (u32)load_st + (b_idx - 9u);
                    if (dst < (u32)load_en && dst < 0x10000u)
                        WS->img_buf[dst] = byte_val;
                }
                b_idx++;
            }

            if (!got_hdr && b_idx >= 26u) {
                load_st = (u16)(hdr[1] | ((u16)hdr[2] << 8));
                load_en = (u16)(hdr[3] | ((u16)hdr[4] << 8));
                int k = 0;
                for (int i = 0; i < 16 && k < 24; i++) {
                    u8 ch = hdr[5 + i];
                    if (ch >= 32u && ch < 127u) WS->title[k++] = (char)ch;
                }
                while (k > 0 && WS->title[k - 1] == ' ') k--;
                WS->title[k] = 0;
                got_hdr = 1;
            } else if (got_hdr && b_idx > 32u && (b_idx - 9u) >= (u32)(load_en - load_st) / 2u) {
                WS->prog_start = load_st;
                WS->prog_end   = load_en;
                WS->prog_entry = find_p4_entry(load_st, load_en);
                WS->has_prog   = 1;
                #undef NEXT_CLS
                return 1;
            }
        } else {
            pilot_s = 0;
        }
    }
    #undef NEXT_CLS
    return 0;
}

/* ============================================================================
 * PART 2: SINCLAIR ZX81 16K (Z80 + ULA Live D_FILE + FRAMES $4034)
 * ============================================================================ */

static void build_zx81_rom_and_font(void)
{
    ws_zero(WS->rom_lo, 0x2000u);
    /* ZX81 ROM character table lives at $1E00..$1FFF (64 characters x 8 bytes):
       $00: Space
       $01..$07: 2x2 block semigraphics (TL=b0?, exact ZX81 semigraphics:
         $01: TL, $02: TR, $03: Top half, $04: BL, $05: Left half, $06: BL+TR, $07: TL+TR+BL,
         $08: Grey dither, $09: Bottom grey, $0A: Top grey; inverted $81..$87 give remaining quadrants!)
       $0B..$1B: " £ $ : ? ( ) > < = + - * / ; , .
       $1C..$25: 0 .. 9
       $26..$3F: A .. Z */
    static const char zx_punct[] = "\"#$:?()><=+-*/;,.";

    for (int ch = 0; ch < 64; ch++) {
        u8 *g = WS->rom_lo + 0x1E00u + ch * 8;
        if (ch == 0) {
            for (int y = 0; y < 8; y++) g[y] = 0x00u;
        } else if (ch >= 1 && ch <= 7) {
            u8 top = ((ch & 1) ? 0xF0u : 0u) | ((ch & 2) ? 0x0Fu : 0u);
            u8 bot = ((ch & 4) ? 0xF0u : 0u);
            for (int y = 0; y < 4; y++) g[y] = top;
            for (int y = 4; y < 8; y++) g[y] = bot;
        } else if (ch == 8) {
            for (int y = 0; y < 8; y++) g[y] = (y & 1) ? 0x55u : 0xAAu;
        } else if (ch == 9) {
            for (int y = 0; y < 4; y++) g[y] = 0x00u;
            for (int y = 4; y < 8; y++) g[y] = (y & 1) ? 0x55u : 0xAAu;
        } else if (ch == 10) {
            for (int y = 0; y < 4; y++) g[y] = (y & 1) ? 0x55u : 0xAAu;
            for (int y = 4; y < 8; y++) g[y] = 0x00u;
        } else {
            char asc = ' ';
            if (ch >= 0x0B && ch <= 0x1B) asc = zx_punct[ch - 0x0B];
            else if (ch >= 0x1C && ch <= 0x25) asc = (char)('0' + (ch - 0x1C));
            else if (ch >= 0x26 && ch <= 0x3F) asc = (char)('A' + (ch - 0x26));
            const u8 *f = font5x7[asc - 32];
            g[0] = 0;
            for (int py = 0; py < 7; py++) {
                u8 row = 0;
                for (int px = 0; px < 5; px++)
                    if (f[px] & (1u << py)) row |= (u8)(0x40u >> px);
                g[1 + py] = row;
            }
        }
    }

    /* Minimal clean-room ZX81 ROM stubs:
       $0000: DI; LD SP, $7FFE; LD I, $1E; JP boot_entry
       $0038: EI; RET
       $0066: RET (NMI)
       $02BB (KSCAN) / $0F2B (SLOW) / $02E7 (FAST): RET */
    WS->rom_lo[0x0000] = 0xF3u;
    WS->rom_lo[0x0001] = 0x31u; WS->rom_lo[0x0002] = 0xFEu; WS->rom_lo[0x0003] = 0x7Fu;
    WS->rom_lo[0x0004] = 0x3Eu; WS->rom_lo[0x0005] = 0x1Eu; WS->rom_lo[0x0006] = 0xEDu; WS->rom_lo[0x0007] = 0x47u;
    u16 jp = WS->has_prog ? WS->prog_entry : 0x0010u;
    WS->rom_lo[0x0008] = 0xC3u; WS->rom_lo[0x0009] = (u8)(jp & 0xFFu); WS->rom_lo[0x000A] = (u8)(jp >> 8);
    WS->rom_lo[0x0010] = 0x18u; WS->rom_lo[0x0011] = 0xFEu; /* JR $ */
    WS->rom_lo[0x0038] = 0xFBu; WS->rom_lo[0x0039] = 0xC9u;
    WS->rom_lo[0x0066] = 0xC9u;
    WS->rom_lo[0x02BB] = 0xC9u;
    WS->rom_lo[0x02E7] = 0xC9u;
    WS->rom_lo[0x0F2B] = 0xC9u;
}

static u8 zx81_zread(struct z80 *c, u16 addr)
{
    (void)c;
    if (addr < 0x4000u) return WS->rom_lo[addr & 0x1FFFu];
    if (addr < 0x8000u) return WS->ram[addr];
    if (addr >= 0xC000u) return WS->ram[0x4000u + (addr & 0x3FFFu)];
    return 0xFFu;
}

static void zx81_zwrite(struct z80 *c, u16 addr, u8 val)
{
    (void)c;
    if (addr >= 0x4000u && addr < 0x8000u)
        WS->ram[addr] = val;
    else if (addr >= 0xC000u)
        WS->ram[0x4000u + (addr & 0x3FFFu)] = val;
}

static u8 zx81_zin(struct z80 *c, u16 port)
{
    (void)c;
    if (!(port & 1u)) {
        WS->zx_beep_pulses++;
        u8 hi = (u8)(port >> 8);
        u8 res = 0x1Fu;
        for (int r = 0; r < 8; r++) {
            if (!(hi & (1u << r)))
                res &= WS->zx_rows[r];
        }
        return (u8)(res | 0xA0u);
    }
    return 0xFFu;
}

static void zx81_zout(struct z80 *c, u16 port, u8 val)
{
    (void)c; (void)val;
    if ((port & 0xFFu) == 0xFDu) WS->zx_nmi_en = 0;
    if ((port & 0xFFu) == 0xFEu) WS->zx_nmi_en = 1;
    WS->zx_beep_pulses++;
}

/* ZX81 8x5 Half-Row Keyboard Matrix ($FEFE..$7FFE, active-LOW bits 0..4):
   r=0 ($FEFE): Shift(b0), Z(b1), X(b2), C(b3), V(b4)
   r=1 ($FDFE): A(b0), S(b1), D(b2), F(b3), G(b4)
   r=2 ($FBFE): Q(b0), W(b1), E(b2), R(b3), T(b4)
   r=3 ($F7FE): 1(b0), 2(b1), 3(b2), 4(b3), 5(b4)
   r=4 ($EFFE): 0(b0), 9(b1), 8(b2), 7(b3), 6(b4)
   r=5 ($DFFE): P(b0), O(b1), I(b2), U(b3), Y(b4)
   r=6 ($BFFE): Newline(b0), L(b1), K(b2), J(b3), H(b4)
   r=7 ($7FFE): Space(b0), .(b1), M(b2), N(b3), B(b4) */
static void zx81_press_ascii(char ch, u8 rows[8])
{
    if (ch >= 'a' && ch <= 'z') ch = (char)(ch - 32);
    switch (ch) {
    case ' ': rows[7] &= (u8)~0x01u; break;
    case '\r': case '\n': rows[6] &= (u8)~0x01u; break;
    case '0': rows[4] &= (u8)~0x01u; break;
    case '9': rows[4] &= (u8)~0x02u; break;
    case '8': rows[4] &= (u8)~0x04u; break;
    case '7': rows[4] &= (u8)~0x08u; break;
    case '6': rows[4] &= (u8)~0x10u; break;
    case '1': rows[3] &= (u8)~0x01u; break;
    case '2': rows[3] &= (u8)~0x02u; break;
    case '3': rows[3] &= (u8)~0x04u; break;
    case '4': rows[3] &= (u8)~0x08u; break;
    case '5': rows[3] &= (u8)~0x10u; break;
    case 'Q': rows[2] &= (u8)~0x01u; break;
    case 'W': rows[2] &= (u8)~0x02u; break;
    case 'E': rows[2] &= (u8)~0x04u; break;
    case 'R': rows[2] &= (u8)~0x08u; break;
    case 'T': rows[2] &= (u8)~0x10u; break;
    case 'Y': rows[5] &= (u8)~0x10u; break;
    case 'U': rows[5] &= (u8)~0x08u; break;
    case 'I': rows[5] &= (u8)~0x04u; break;
    case 'O': rows[5] &= (u8)~0x02u; break;
    case 'P': rows[5] &= (u8)~0x01u; break;
    case 'A': rows[1] &= (u8)~0x01u; break;
    case 'S': rows[1] &= (u8)~0x02u; break;
    case 'D': rows[1] &= (u8)~0x04u; break;
    case 'F': rows[1] &= (u8)~0x08u; break;
    case 'G': rows[1] &= (u8)~0x10u; break;
    case 'H': rows[6] &= (u8)~0x10u; break;
    case 'J': rows[6] &= (u8)~0x08u; break;
    case 'K': rows[6] &= (u8)~0x04u; break;
    case 'L': rows[6] &= (u8)~0x02u; break;
    case 'Z': rows[0] &= (u8)~0x02u; break;
    case 'X': rows[0] &= (u8)~0x04u; break;
    case 'C': rows[0] &= (u8)~0x08u; break;
    case 'V': rows[0] &= (u8)~0x10u; break;
    case 'B': rows[7] &= (u8)~0x10u; break;
    case 'N': rows[7] &= (u8)~0x08u; break;
    case 'M': rows[7] &= (u8)~0x04u; break;
    case '.': rows[7] &= (u8)~0x02u; break;
    default: break;
    }
}

static void zx81_update_inputs(u16 pad)
{
    WS->pad = pad;
    for (int r = 0; r < 8; r++)
        WS->zx_rows[r] = WS->zx_usb[r];

    /* Map pad to BOTH Cursor/5-6-7-8-0 AND Q/A/O/P/Space/Newline so 3D Monster Maze & Inufuto games work! */
    if (pad & PAD_LEFT)   { WS->zx_rows[5] &= (u8)~0x02u; WS->zx_rows[3] &= (u8)~0x10u; } /* O + 5 */
    if (pad & PAD_RIGHT)  { WS->zx_rows[5] &= (u8)~0x01u; WS->zx_rows[4] &= (u8)~0x04u; } /* P + 8 */
    if (pad & PAD_UP)     { WS->zx_rows[2] &= (u8)~0x01u; WS->zx_rows[4] &= (u8)~0x08u; } /* Q + 7 */
    if (pad & PAD_DOWN)   { WS->zx_rows[1] &= (u8)~0x01u; WS->zx_rows[4] &= (u8)~0x10u; } /* A + 6 */
    if (pad & (PAD_A | PAD_SELECT)) { WS->zx_rows[7] &= (u8)~0x01u; WS->zx_rows[4] &= (u8)~0x01u; } /* Space + 0 */
    if (pad & (PAD_B | PAD_START))  { WS->zx_rows[6] &= (u8)~0x01u; } /* Newline */

    if (WS->type_hold > 0) {
        WS->type_hold--;
        zx81_press_ascii(WS->type_ch, WS->zx_rows);
    } else if (WS->type_r != WS->type_w && !WS->basic_mode) {
        WS->type_ch = WS->type_q[WS->type_r];
        WS->type_r = (WS->type_r + 1u) & 63u;
        WS->type_hold = 3;
        zx81_press_ascii(WS->type_ch, WS->zx_rows);
    }
}

static void render_zx81_dfile(u16 *pic)
{
    /* Classic crisp ZX81 paper-white (RGB 240,240,236) and deep charcoal ink (RGB 16,16,20) */
    const u16 paper = RGB15(240, 240, 236);
    const u16 ink   = RGB15( 16,  16,  20);

    for (int i = 0; i < ZX81_W * ZX81_H; i++)
        pic[i] = paper;

    u16 dfile = (u16)(WS->ram[0x400Cu] | ((u16)WS->ram[0x400Du] << 8));
    if (dfile < 0x4000u || dfile >= 0x7FF0u)
        return;

    u16 p = (u16)(dfile + 1u);          /* First byte at D_FILE is $76 HALT/Newline */
    u16 font_base = (u16)(((u16)WS->zcpu.i & 0xFEu) << 8);
    int custom_font = (font_base >= 0x4000u && font_base < 0x7E00u);

    for (int row = 0; row < 24 && p < 0x8000u; row++) {
        for (int col = 0; col < 32 && p < 0x8000u; col++) {
            u8 ch = WS->ram[p];
            if ((ch & 0x7Fu) == 0x76u)  /* Collapsed D_FILE newline! */
                break;
            p++;
            int inv = (ch & 0x80u) != 0;
            u8 idx = ch & 0x3Fu;
            const u8 *glyph = custom_font
                ? (WS->ram + font_base + idx * 8)
                : (WS->rom_lo + 0x1E00u + idx * 8);

            for (int py = 0; py < 8; py++) {
                u8 bits = inv ? (u8)~glyph[py] : glyph[py];
                u16 *dst = pic + (row * 8 + py) * ZX81_W + col * 8;
                for (int px = 0; px < 8; px++)
                    dst[px] = (bits & (0x80u >> px)) ? ink : paper;
            }
        }
        /* Advance past $76 end-of-line marker if full 32-col line didn't hit it yet */
        while (p < 0x8000u && (WS->ram[p] & 0x7Fu) != 0x76u)
            p++;
        if (p < 0x8000u && (WS->ram[p] & 0x7Fu) == 0x76u)
            p++;
    }
}

static u8 asc_to_zx81(char c)
{
    if (c == ' ') return 0;
    if (c >= '0' && c <= '9') return (u8)(0x1Cu + (c - '0'));
    if (c >= 'A' && c <= 'Z') return (u8)(0x26u + (c - 'A'));
    if (c >= 'a' && c <= 'z') return (u8)(0x26u + (c - 'a'));
    if (c == '"') return 0x0Bu;
    if (c == '$') return 0x0Du;
    if (c == ':') return 0x0Eu;
    if (c == '?') return 0x0Fu;
    if (c == '(') return 0x10u;
    if (c == ')') return 0x11u;
    if (c == '>') return 0x12u;
    if (c == '<') return 0x13u;
    if (c == '=') return 0x14u;
    if (c == '+') return 0x15u;
    if (c == '-') return 0x16u;
    if (c == '*') return 0x17u;
    if (c == '/') return 0x18u;
    if (c == ',') return 0x1Au;
    if (c == '.') return 0x1Bu;
    return 0;
}

static void zx81_basic_init(void)
{
    u16 df = 0x4200u;
    WS->ram[0x400Cu] = 0x00u;
    WS->ram[0x400Du] = 0x42u;
    u16 p = df;
    WS->ram[p++] = 0x76u;
    for (int r = 0; r < 24; r++) {
        for (int c = 0; c < 32; c++) WS->ram[p++] = 0x00u;
        WS->ram[p++] = 0x76u;
    }
    const char *b1 = "SINCLAIR ZX81 16K RAM";
    for (int i = 0; b1[i]; i++) WS->ram[df + 1 + 1 * 33 + 5 + i] = (u8)(asc_to_zx81(b1[i]) | 0x80u);
    /* Inverse 'K' cursor on bottom input row (row 22) */
    WS->ram[df + 1 + 22 * 33 + 0] = (u8)(asc_to_zx81('K') | 0x80u);
    WS->bas_x = 0; WS->bas_y = 22; WS->bas_len = 0;
}

static void zx81_basic_step(void)
{
    u16 df = 0x4200u;
    while (WS->type_r != WS->type_w) {
        char c = WS->type_q[WS->type_r];
        WS->type_r = (WS->type_r + 1u) & 63u;
        if (c == '\r' || c == '\n') {
            for (int x = 0; x < 32; x++) {
                WS->ram[df + 1 + 4 * 33 + x] = WS->ram[df + 1 + 22 * 33 + x];
                WS->ram[df + 1 + 22 * 33 + x] = 0x00u;
            }
            WS->bas_x = 0; WS->bas_len = 0;
        } else if ((c == 8 || c == 127) && WS->bas_x > 0) {
            WS->ram[df + 1 + 22 * 33 + WS->bas_x] = 0x00u;
            WS->bas_x--;
        } else if (c >= 32 && c < 127 && WS->bas_x < 30) {
            WS->ram[df + 1 + 22 * 33 + WS->bas_x++] = asc_to_zx81(c);
        }
    }
    WS->ram[df + 1 + 22 * 33 + WS->bas_x] = (u8)(asc_to_zx81((WS->bas_x == 0) ? 'K' : 'L') | ((WS->frames & 16u) ? 0x80u : 0x00u));
}

static u16 find_zx81_entry(void)
{
    u16 dfile = (u16)(WS->img_buf[0x400Cu] | ((u16)WS->img_buf[0x400Du] << 8));
    if (dfile < 0x407Du || dfile > 0x7FFFu) dfile = 0x7FFFu;

    /* Walk ZX81 BASIC lines from $407D to D_FILE looking for USR ($D4) + digits ($1C..$25) or 5-byte FP ($7E) */
    u32 p = 0x407Du;
    while (p + 6u < dfile) {
        u16 llen = (u16)(WS->img_buf[p + 2] | ((u16)WS->img_buf[p + 3] << 8));
        if (llen == 0u || p + 4u + llen > 0x8000u) break;
        for (u32 k = p + 4u; k < p + 4u + llen; k++) {
            if (WS->img_buf[k] == 0xEAu) break; /* Skip REM machine-code bytes so we don't match fake $D4 inside code! */
            if (WS->img_buf[k] == 0xD4u) {
                u32 q = k + 1u;
                while (q < p + 4u + llen && WS->img_buf[q] == 0x10u) q++; /* '(' */
                u32 addr = 0;
                int digits = 0;
                while (q < p + 4u + llen && WS->img_buf[q] >= 0x1Cu && WS->img_buf[q] <= 0x25u) {
                    addr = addr * 10u + (u32)(WS->img_buf[q] - 0x1Cu);
                    q++;
                    digits++;
                }
                if (digits >= 4 && addr >= 0x4000u && addr < 0x8000u)
                    return (u16)addr;
            }
        }
        p += 4u + llen;
    }

    /* Fallback: Line 1 REM machine-code at $407E */
    if (WS->img_buf[0x407Du] == 0xEAu)
        return 0x407Eu;
    return 0x4082u;
}

/* ============================================================================
 * PUBLIC API (PLUS/4 & ZX81)
 * ============================================================================ */

static void fmt_info(void)
{
    char *o = WS->info;
    const char *p = WS->is_zx81
        ? "Sinclair ZX81 16K (Z80 + ULA D_FILE, "
        : "Commodore Plus/4 64K (7501 + MOS TED 121-col, ";
    while (*p) *o++ = *p++;
    const char *s = WS->basic_mode ? "BASIC)" : (WS->title[0] ? WS->title : "Program)");
    while (*s) *o++ = *s++;
    if (!WS->basic_mode && WS->title[0]) *o++ = ')';
    *o = 0;
}

const char *plus4_load(const u8 *image, u32 size, const char *path)
{
#ifdef TED81_HOST
    u32 sr = WS->sample_rate;
#endif
    ws_zero(WS, sizeof(*WS));
#ifdef TED81_HOST
    WS->sample_rate = sr ? sr : 48000u;
#else
    WS->sample_rate = 48000u;
#endif
    WS->is_zx81 = 0;
    init_ted_palette();

    if (!image || size == 0) {
        WS->basic_mode = 1;
        ted81_reset();
        fmt_info();
        return 0;
    }

    /* Format 1: C16-TAPE-RAW (.tap) */
    if (size > 32u && image[0] == 'C' && image[1] == '1' && image[2] == '6' && image[3] == '-') {
        if (!parse_c16_tape_raw(image, size))
            return "corrupt or unsupported C16-TAPE-RAW .tap image";
    }
    /* Format 2: T64 tape container ("C64 tape image..." or "C64S tape...") */
    else if (size >= 0x60u && image[0] == 'C' && image[1] == '6' && image[2] == '4') {
        u16 st  = (u16)(image[0x42] | ((u16)image[0x43] << 8));
        u16 en  = (u16)(image[0x44] | ((u16)image[0x45] << 8));
        u32 off = (u32)image[0x48] | ((u32)image[0x49] << 8) | ((u32)image[0x4A] << 16) | ((u32)image[0x4B] << 24);
        if (off >= size || st >= en)
            return "invalid T64 container header";
        int k = 0;
        for (int i = 0; i < 16 && k < 24; i++) {
            u8 ch = image[0x50 + i];
            if (ch >= 32u && ch < 127u) WS->title[k++] = (char)ch;
        }
        while (k > 0 && WS->title[k - 1] == ' ') k--;
        WS->title[k] = 0;
        u32 len = size - off;
        if ((u32)st + len > 0x10000u) len = 0x10000u - st;
        for (u32 i = 0; i < len; i++) WS->img_buf[st + i] = image[off + i];
        WS->prog_start = st;
        WS->prog_end   = (u16)(st + len);
        WS->prog_entry = find_p4_entry(st, WS->prog_end);
        WS->has_prog   = 1;
    }
    /* Format 3: Standard Commodore .prg (2-byte little-endian load address + payload) */
    else if (size >= 4u && (ci_ends(path, ".prg") || image[1] == 0x10u || image[1] == 0x18u || image[1] == 0x20u)) {
        u16 st = (u16)(image[0] | ((u16)image[1] << 8));
        u32 len = size - 2u;
        if ((u32)st + len > 0x10000u) len = 0x10000u - st;
        for (u32 i = 0; i < len; i++) WS->img_buf[st + i] = image[2u + i];
        WS->prog_start = st;
        WS->prog_end   = (u16)(st + len);
        WS->prog_entry = find_p4_entry(st, WS->prog_end);
        WS->has_prog   = 1;
    } else {
        return "not a valid Commodore Plus/4 .tap, T64, or .prg file";
    }

    ted81_reset();
    fmt_info();
    return 0;
}

const char *zx81_load(const u8 *image, u32 size, const char *path)
{
    (void)path;
#ifdef TED81_HOST
    u32 sr = WS->sample_rate;
#endif
    ws_zero(WS, sizeof(*WS));
#ifdef TED81_HOST
    WS->sample_rate = sr ? sr : 48000u;
#else
    WS->sample_rate = 48000u;
#endif
    WS->is_zx81 = 1;
    for (int r = 0; r < 8; r++)
        WS->zx_rows[r] = WS->zx_usb[r] = 0x1Fu;

    if (!image || size == 0) {
        WS->basic_mode = 1;
        ted81_reset();
        fmt_info();
        return 0;
    }
    if (size < 120u || size > 0x3FF7u)
        return "not a valid Sinclair ZX81 .p / .81 snapshot";

    for (u32 i = 0; i < size; i++)
        WS->img_buf[0x4009u + i] = image[i];
    WS->prog_start = 0x4009u;
    WS->prog_end   = (u16)(0x4009u + size);
    WS->prog_entry = find_zx81_entry();
    WS->has_prog   = 1;

    ted81_reset();
    fmt_info();
    return 0;
}

void ted81_reset(void)
{
    WS->frames = 0;
    WS->jam = 0;
    WS->cycles = 0;

    if (!WS->is_zx81) {
        ws_zero(WS->ram, sizeof(WS->ram));
        ws_zero(WS->ted, sizeof(WS->ted));
        WS->rom_enabled = 1;
        WS->fd30 = 0xFFu;
        WS->ff08_latch = 0xFFu;
        WS->ted_lfsr = 0x55u;
        WS->ted[0x06] = 0x1Bu;
        WS->ted[0x07] = 0x48u;          /* Bit 6 = 1 -> 50 Hz PAL */
        WS->ted[0x12] = 0x04u;
        WS->ted[0x13] = 0xD0u;
        WS->ted[0x14] = 0x08u;

        if (WS->has_prog) {
            for (u32 a = WS->prog_start; a < WS->prog_end; a++)
                WS->ram[a] = WS->img_buf[a];
        }
        build_plus4_roms(WS->has_prog ? WS->prog_entry : 0u);
        if (WS->basic_mode)
            p4_basic_init();

        p4_setup_mmu();
        WS->s = 0xFDu;
        WS->p = FI | FU;
        WS->a = WS->x = WS->y = 0;
        WS->pc = p4_rd16(0xFFFCu);
    } else {
        ws_zero(WS->ram, sizeof(WS->ram));
        build_zx81_rom_and_font();
        if (WS->has_prog) {
            for (u32 a = WS->prog_start; a < WS->prog_end; a++)
                WS->ram[a] = WS->img_buf[a];
            WS->ram[0x4034u] = 0xFFu;
            WS->ram[0x4035u] = 0xFFu;
        } else {
            zx81_basic_init();
        }

        z80_init(&WS->zcpu);
        z80_reset(&WS->zcpu);
        WS->zcpu.read  = zx81_zread;
        WS->zcpu.write = zx81_zwrite;
        WS->zcpu.in    = zx81_zin;
        WS->zcpu.out   = zx81_zout;
        WS->zcpu.trap  = -1;
        for (int i = 0; i < 64; i++) {
            WS->zcpu.rd[i] = 0;
            WS->zcpu.wr[i] = 0;
        }
        for (int i = 0; i < 16; i++)
            WS->zcpu.rd[i] = WS->rom_lo + (i & 7) * 0x400;
        for (int i = 16; i < 32; i++) {
            WS->zcpu.rd[i] = WS->ram + i * 0x400;
            WS->zcpu.wr[i] = WS->ram + i * 0x400;
        }
        WS->zcpu.sp.w = 0x7FFEu;
        WS->zcpu.i    = 0x1Eu;
    }
}

void ted81_frame(u16 pad, u16 *picture)
{
    u32 sr = WS->sample_rate ? WS->sample_rate : 48000u;

    if (!WS->is_zx81) {
        p4_update_inputs(pad);
        WS->cycles = 0;
        const s32 cyc_per_line = 114;   /* 114 * 312 = 35,568 cycles/frame @ 1.78 MHz PAL */

        for (int line = 0; line < 312; line++) {
            WS->cur_line = (u16)line;
            u16 irq_line = (u16)(((u16)(WS->ted[0x0A] & 1u) << 8) | WS->ted[0x0B]);
            if ((u16)line == irq_line) {
                WS->ted[0x09] |= 0x02u;
                ted_recalc_irq();
            }
            s32 target = (line + 1) * cyc_per_line;
            if (!WS->basic_mode) {
                while (WS->cycles < target && !WS->jam)
                    p4_step();
            }

            if (line < PLUS4_H)
                render_ted_line(line, picture + line * PLUS4_W);

            WS->snd_frac += sr;
            while (WS->snd_frac >= 15600u) { /* 312 * 50 Hz = 15,600 lines/sec */
                WS->snd_frac -= 15600u;
                ted_step_sample();
            }
        }
        if (WS->basic_mode)
            p4_basic_step();
    } else {
        zx81_update_inputs(pad);
        WS->zx_beep_pulses = 0;
        WS->zcpu.cycles = 0;

        /* Decrement 16-bit FRAMES ($4034/$4035) once per 50 Hz PAL VSync */
        u16 frm = (u16)(WS->ram[0x4034u] | ((u16)WS->ram[0x4035u] << 8));
        frm--;
        WS->ram[0x4034u] = (u8)(frm & 0xFFu);
        WS->ram[0x4035u] = (u8)(frm >> 8);

        /* 3.25 MHz Z80 @ 50 Hz (SLOW mode yields ~25% CPU to user ML; run 32,500 T-states for silky 50fps!) */
        if (!WS->basic_mode)
            z80_run(&WS->zcpu, 32500);
        else
            zx81_basic_step();

        render_zx81_dfile(picture);

        /* Generate subtle authentic ZX81 50 Hz VSync + key-click audio so snd DMA stays live */
        u32 samps = sr / 50u;
        int click = (pad != 0) || (WS->zx_beep_pulses > 8u);
        for (u32 i = 0; i < samps; i++) {
            s16 s = 0;
            if (i < 8u) s = 420;
            else if (click && i < 96u) s = (i & 8u) ? 1400 : -1400;
            u32 nxt = (WS->snd_head + 1u) & (SND_RING - 1u);
            if (nxt != WS->snd_tail) {
                WS->snd_ring[WS->snd_head] = s;
                WS->snd_head = nxt;
            }
        }
    }
    WS->frames++;
}

void ted81_keyboard(const u8 *usages, int n)
{
    if (!WS->is_zx81) {
        for (int r = 0; r < 8; r++) WS->p4_usb[r] = 0;
        for (int i = 0; i < n; i++) {
            u8 u = usages[i];
            if (u >= 0x04u && u <= 0x1Du) p4_press_ascii((char)('A' + (u - 0x04u)), WS->p4_usb);
            else if (u >= 0x1Eu && u <= 0x26u) p4_press_ascii((char)('1' + (u - 0x1Eu)), WS->p4_usb);
            else if (u == 0x27u) p4_press_ascii('0', WS->p4_usb);
            else if (u == 0x28u) WS->p4_usb[0] |= 0x02u;
            else if (u == 0x2Au) WS->p4_usb[0] |= 0x01u;
            else if (u == 0x2Cu) WS->p4_usb[7] |= 0x10u;
            else if (u == 0xE1u || u == 0xE5u) WS->p4_usb[1] |= 0x80u;
            else if (u == 0x52u) WS->p4_usb[5] |= 0x08u;
            else if (u == 0x51u) WS->p4_usb[5] |= 0x01u;
            else if (u == 0x50u) WS->p4_usb[6] |= 0x01u;
            else if (u == 0x4Fu) WS->p4_usb[6] |= 0x08u;
        }
    } else {
        for (int r = 0; r < 8; r++) WS->zx_usb[r] = 0x1Fu;
        for (int i = 0; i < n; i++) {
            u8 u = usages[i];
            if (u >= 0x04u && u <= 0x1Du) zx81_press_ascii((char)('A' + (u - 0x04u)), WS->zx_usb);
            else if (u >= 0x1Eu && u <= 0x26u) zx81_press_ascii((char)('1' + (u - 0x1Eu)), WS->zx_usb);
            else if (u == 0x27u) zx81_press_ascii('0', WS->zx_usb);
            else if (u == 0x28u) WS->zx_usb[6] &= (u8)~0x01u;
            else if (u == 0x2Cu) WS->zx_usb[7] &= (u8)~0x01u;
            else if (u == 0xE1u || u == 0xE5u) WS->zx_usb[0] &= (u8)~0x01u;
            else if (u == 0x50u) { WS->zx_usb[0] &= (u8)~0x01u; WS->zx_usb[3] &= (u8)~0x10u; }
            else if (u == 0x51u) { WS->zx_usb[0] &= (u8)~0x01u; WS->zx_usb[4] &= (u8)~0x10u; }
            else if (u == 0x52u) { WS->zx_usb[0] &= (u8)~0x01u; WS->zx_usb[4] &= (u8)~0x08u; }
            else if (u == 0x4Fu) { WS->zx_usb[0] &= (u8)~0x01u; WS->zx_usb[4] &= (u8)~0x04u; }
        }
    }
}

void ted81_typed(char c)
{
    u8 nxt = (WS->type_w + 1u) & 63u;
    if (nxt != WS->type_r) {
        WS->type_q[WS->type_w] = c;
        WS->type_w = nxt;
    }
}

const char *ted81_info(void)
{
    return WS->info;
}

int ted81_jammed(void)
{
    return WS->jam;
}

void ted81_audio_rate(u32 hz)
{
    WS->sample_rate = hz ? hz : 48000u;
    WS->snd_head = WS->snd_tail = 0;
}

int ted81_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && WS->snd_tail != WS->snd_head) {
        out[n++] = WS->snd_ring[WS->snd_tail];
        WS->snd_tail = (WS->snd_tail + 1u) & (SND_RING - 1u);
    }
    return n;
}
