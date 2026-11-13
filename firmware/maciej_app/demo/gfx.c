/* The picture: one 1280 x 720 ARGB1555 bitmap shown by GMA layer 0 of the
   display engine through a single region head, the way the original
   applications set up their OSD (head word 0 = 0xAA200B51: signature 0xAA,
   enable, pixel format 5 = ARGB1555; pitch 2560 bytes; global alpha 0x0F;
   on a revision-1 chip the RGB -> YCbCr matrix at +0x240 of the head).
   The CPU draws into the bitmap itself (no GE commands), through KSEG1 so the
   display engine reads what was written without cache maintenance. */
#include "hw.h"
#include "font5x7.h"

#define FB ((volatile u16 *)KSEG1(FB_PHYS))
#define HEAD ((volatile u32 *)KSEG1(HEAD_PHYS))
#define PITCH_PX SCREEN_W

/* The matrix both original applications put at +0x240 of every head on a
   revision-1 S3811 for an HD output: BT.709 video range, x512, the rows Y,
   Cb, Cr of (R, G, B, offset), then 45 (their 'sharpness' setting 50).  With
   the matrix all zero the real box showed every colour as black. */
static const u32 rgb_to_ycbcr[13] = {
    93, 314, 32, 0,
    (u32)-52, (u32)-173, 225, 0,
    225, (u32)-204, (u32)-21, 0,
    45,
};

static int enabled;
static u32 enable_at_start;
static int started;

void gfx_init(void)
{
    /* what the layer's enable register held before the demo first wrote it:
       after a reset, the chip's own value (the drivers of the original
       applications change single bits of it and keep the rest) */
    if (!started) {
        enable_at_start = REG32(GMA0_ENABLE);
        started = 1;
    }
    /* region head (gma_capture.parse_head; the stock head at 0x008133C0) */
    HEAD[0] = 0xAA200B51u;                         /* signature, b16-22 0x20, ARGB1555, enabled */
    HEAD[1] = 0;                                   /* no palette */
    HEAD[2] = (u32)(SCREEN_W - 1) << 16;           /* x 0 .. 1279 */
    HEAD[3] = (u32)(SCREEN_H - 1) << 16;           /* y 0 .. 719 */
    HEAD[4] = ((u32)SCREEN_H << 16) | SCREEN_W;    /* bitmap 1280 x 720 */
    HEAD[5] = ((u32)(SCREEN_W * 2) << 16) | 0x0F;  /* pitch in bytes, global alpha (4-bit, opaque) */
    HEAD[6] = 0;                                   /* the only region */
    HEAD[7] = FB_PHYS;
    /* the rest of the block: no scaling filter (zero, as the originals have
       it without scaling), then the matrix -- written on revision 0 too,
       where the originals leave it zero (no revision-0 chip was tried) */
    for (u32 i = 8; i < HEAD_SIZE / 4; i++)
        HEAD[i] = 0;
    for (u32 i = 0; i < sizeof(rgb_to_ycbcr) / sizeof(rgb_to_ycbcr[0]); i++)
        HEAD[HEAD_MATRIX / 4 + i] = rgb_to_ycbcr[i];
    gfx_enable(1);
}

void gfx_enable(int on)
{
    /* The second layer off, and 0xB8006308 = 0xFF: the layer's global alpha
       (the originals' gma_hal_GlobalAlpha: bits 0-7 the value, bit 16 its
       enable, set only for a value other than 0xFF -- so 0xFF means none).
       Both originals write 0xFF as their driver opens the layer on revision 1
       (on revision 0 they leave it; the Opticum later sets 0x000100E5, a
       translucent OSD).  The emulator's screen capture does not use it. */
    /* On a revision-1 chip both originals also set bit 18 of the enable
       register and clear bit 19 -- 0x00040001 on, 0x00040000 off (with bit
       19 set the chip would skip the head's matrix: GMA_YCBCR); on revision
       0 they write 1 / 0.  For a true-colour region their driver writes 1 to
       0xB80063B8 (0 for CLUT8).  On the real box neither bit 18 nor 0x63B8
       made a visible difference; the matrix did. */
    u32 rev_bits = chip_rev() ? 0x00040000u : 0u;
    REG32(GMA1_ENABLE) = 0;
    REG32(GMA0_ALPHA) = 0xFFu;
    REG32(GMA_TRUECOLOUR) = 1;
    REG32(GMA0_HEAD) = HEAD_PHYS;
    REG32(GMA0_ENABLE) = rev_bits | (on ? 1u : 0u);
    enabled = on;
}

u32 gfx_enable_at_start(void)
{
    return enable_at_start;
}

int gfx_enabled(void)
{
    return enabled;
}

u32 gfx_head_phys(void)
{
    return HEAD_PHYS;
}

u32 gfx_fb_phys(void)
{
    return FB_PHYS;
}

u16 rgb_from_hex(u32 rrggbb)
{
    return RGB((rrggbb >> 16) & 0xFF, (rrggbb >> 8) & 0xFF, rrggbb & 0xFF);
}

static int clip(int *x, int *y, int *w, int *h)
{
    if (*x < 0) { *w += *x; *x = 0; }
    if (*y < 0) { *h += *y; *y = 0; }
    if (*x + *w > SCREEN_W) *w = SCREEN_W - *x;
    if (*y + *h > SCREEN_H) *h = SCREEN_H - *y;
    return *w > 0 && *h > 0;
}

/* ---- the mouse pointer: an arrow over the picture ---- */
#define CUR_W 11
#define CUR_H 17
static const char *const arrow[CUR_H] = {
    "X..........", "XX.........", "XWX........", "XWWX.......", "XWWWX......", "XWWWWX.....",
    "XWWWWWX....", "XWWWWWWX...", "XWWWWWWWX..", "XWWWWWWWWX.", "XWWWWWXXXXX", "XWWXWWX....",
    "XWX.XWWX...", "XX..XWWX...", "X....XWWX..", ".....XWWX..", "......XX...",
};
static u16 under[CUR_W * CUR_H];        /* what the pointer covers */
static int cur_x, cur_y, cur_drawn, cur_wanted;

static void cursor_erase(void)
{
    if (!cur_drawn)
        return;
    for (int r = 0; r < CUR_H; r++)
        for (int c = 0; c < CUR_W; c++) {
            int px = cur_x + c, py = cur_y + r;
            if (arrow[r][c] != '.' && px < SCREEN_W && py < SCREEN_H)
                FB[py * PITCH_PX + px] = under[r * CUR_W + c];
        }
    cur_drawn = 0;
}

static void cursor_draw(void)
{
    for (int r = 0; r < CUR_H; r++)
        for (int c = 0; c < CUR_W; c++) {
            int px = cur_x + c, py = cur_y + r;
            if (arrow[r][c] == '.' || px >= SCREEN_W || py >= SCREEN_H)
                continue;
            under[r * CUR_W + c] = FB[py * PITCH_PX + px];
            FB[py * PITCH_PX + px] = arrow[r][c] == 'X' ? RGB(0, 0, 0) : RGB(255, 255, 255);
        }
    cur_drawn = 1;
}

/* the pointer at (x, y) -- its tip -- shown (on) or not */
void gfx_cursor(int x, int y, int on)
{
    cursor_erase();
    cur_x = x;
    cur_y = y;
    cur_wanted = on;
    if (on)
        cursor_draw();
}

/* the main loop: the pointer drawn again after drawing took it away */
void gfx_cursor_refresh(void)
{
    if (cur_wanted && !cur_drawn)
        cursor_draw();
}

void gfx_fill(int x, int y, int w, int h, u16 color)
{
    if (!clip(&x, &y, &w, &h))
        return;
    if (cur_drawn && x < cur_x + CUR_W && cur_x < x + w && y < cur_y + CUR_H && cur_y < y + h)
        cursor_erase();                 /* (drawn under the pointer: it comes back in the main loop) */
    u32 pair = ((u32)color << 16) | color;
    for (int row = 0; row < h; row++) {
        volatile u16 *p = FB + (y + row) * PITCH_PX + x;
        int n = w;
        if (((u32)p & 2) && n) {               /* to a word boundary */
            *p++ = color;
            n--;
        }
        volatile u32 *q = (volatile u32 *)p;
        for (; n >= 2; n -= 2)
            *q++ = pair;
        if (n)
            *(volatile u16 *)q = color;
    }
}

static u16 mix(u16 a, u16 b, int num, int den)
{
    int ar = (a >> 10) & 31, ag = (a >> 5) & 31, ab = a & 31;
    int br = (b >> 10) & 31, bg = (b >> 5) & 31, bb = b & 31;
    int r = ar + (br - ar) * num / den, g = ag + (bg - ag) * num / den, bl = ab + (bb - ab) * num / den;
    return (u16)(0x8000u | (r << 10) | (g << 5) | bl);
}

void gfx_gradient(int x, int y, int w, int h, u16 top, u16 bottom)
{
    for (int row = 0; row < h; row++)
        gfx_fill(x, y + row, w, 1, mix(top, bottom, row, h > 1 ? h - 1 : 1));
}

void gfx_frame(int x, int y, int w, int h, int t, u16 color)
{
    gfx_fill(x, y, w, t, color);
    gfx_fill(x, y + h - t, w, t, color);
    gfx_fill(x, y, t, h, color);
    gfx_fill(x + w - t, y, t, h, color);
}

u16 gfx_get(int x, int y)
{
    if (x < 0 || y < 0 || x >= SCREEN_W || y >= SCREEN_H)
        return 0;
    return FB[y * PITCH_PX + x];
}

/* text: the 5 x 7 font scaled by `scale`, one column of spacing */
static void glyph(int x, int y, char c, int scale, u16 fg, int fill_bg, u16 bg)
{
    if ((u8)c < FONT_FIRST || (u8)c > FONT_LAST)
        c = '?';
    const u8 *rows = font5x7[(u8)c - FONT_FIRST];
    if (fill_bg)
        gfx_fill(x, y, (FONT_W + 1) * scale, (FONT_H + 1) * scale, bg);
    for (int r = 0; r < FONT_H; r++)
        for (int col = 0; col < FONT_W; col++)
            if (rows[r] & (0x10 >> col))
                gfx_fill(x + col * scale, y + r * scale, scale, scale, fg);
}

int gfx_text_width(const char *s, int scale)
{
    int n = 0;
    while (s[n])
        n++;
    return n * (FONT_W + 1) * scale;
}

static int text(int x, int y, const char *s, int scale, u16 fg, int fill_bg, u16 bg)
{
    for (; *s; s++, x += (FONT_W + 1) * scale)
        glyph(x, y, *s, scale, fg, fill_bg, bg);
    return x;
}

int gfx_text(int x, int y, const char *s, int scale, u16 fg)
{
    return text(x, y, s, scale, fg, 0, 0);
}

int gfx_text_bg(int x, int y, const char *s, int scale, u16 fg, u16 bg)
{
    return text(x, y, s, scale, fg, 1, bg);
}
