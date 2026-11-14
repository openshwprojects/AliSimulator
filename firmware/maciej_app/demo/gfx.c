/* The picture: one 1280 x 720 ARGB1555 bitmap shown by GMA layer 0 of the
   display engine through a single region head, the way the original
   applications set up their OSD (head word 0 = 0xAA200B51: signature 0xAA,
   enable, pixel format 5 = ARGB1555; pitch 2560 bytes; global alpha 0x0F;
   on a revision-1 chip the RGB -> YCbCr matrix at +0x240 of the head).
   The CPU draws into the bitmap itself (no GE commands), through KSEG1 so the
   display engine reads what was written without cache maintenance.

   There are two pictures, each with a head of its own: the test screen (the
   demo's boxes, what 'screen' draws, at FB_PHYS) and the console (console.c,
   at CON_FB_PHYS).  The layer shows one of them -- gfx_view points its head
   register at that head -- while both stay drawn; gfx_* draw into the test
   screen unless gfx_target says the console. */
#include "hw.h"
#include "font5x7.h"

#define FB_TEST ((volatile u16 *)KSEG1(FB_PHYS))
#define FB_CON ((volatile u16 *)KSEG1(CON_FB_PHYS))
#define HEAD ((volatile u32 *)KSEG1(HEAD_PHYS))
#define CON_HEAD ((volatile u32 *)KSEG1(CON_HEAD_PHYS))
#define PITCH_PX SCREEN_W

static volatile u16 *fb = FB_TEST;      /* where gfx_* draw */
static int view = 1;                    /* what the layer shows: 1 the console, 0 the test screen */

static volatile u16 *shown(void)
{
    return view ? FB_CON : FB_TEST;
}

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

/* a region head (gma_capture.parse_head; the stock head at 0x008133C0) */
static void head_write(volatile u32 *head, u32 bitmap)
{
    head[0] = 0xAA200B51u;                         /* signature, b16-22 0x20, ARGB1555, enabled */
    head[1] = 0;                                   /* no palette */
    head[2] = (u32)(SCREEN_W - 1) << 16;           /* x 0 .. 1279 */
    head[3] = (u32)(SCREEN_H - 1) << 16;           /* y 0 .. 719 */
    head[4] = ((u32)SCREEN_H << 16) | SCREEN_W;    /* bitmap 1280 x 720 */
    head[5] = ((u32)(SCREEN_W * 2) << 16) | 0x0F;  /* pitch in bytes, global alpha (4-bit, opaque) */
    head[6] = 0;                                   /* the only region */
    head[7] = bitmap;
    /* the rest of the block: no scaling filter (zero, as the originals have
       it without scaling), then the matrix -- written on revision 0 too,
       where the originals leave it zero (no revision-0 chip was tried) */
    for (u32 i = 8; i < HEAD_SIZE / 4; i++)
        head[i] = 0;
    for (u32 i = 0; i < sizeof(rgb_to_ycbcr) / sizeof(rgb_to_ycbcr[0]); i++)
        head[HEAD_MATRIX / 4 + i] = rgb_to_ycbcr[i];
}

void gfx_init(void)
{
    /* what the layer's enable register held before the demo first wrote it:
       after a reset, the chip's own value (the drivers of the original
       applications change single bits of it and keep the rest) */
    if (!started) {
        enable_at_start = REG32(GMA0_ENABLE);
        started = 1;
    }
    head_write(HEAD, FB_PHYS);
    head_write(CON_HEAD, CON_FB_PHYS);
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
    REG32(GMA0_HEAD) = view ? CON_HEAD_PHYS : HEAD_PHYS;
    REG32(GMA0_ENABLE) = rev_bits | (on ? 1u : 0u);
    enabled = on;
}

static void cursor_erase(void);

/* the console (1) or the test screen (0) on the TV: the layer's head register
   pointed at that picture's head (written again, the display engine reads the
   head anew -- as on the box after the layer's format changed); the mouse
   pointer moves over */
void gfx_view(int console)
{
    console = console ? 1 : 0;
    if (console == view)
        return;
    cursor_erase();
    view = console;
    REG32(GMA0_HEAD) = view ? CON_HEAD_PHYS : HEAD_PHYS;
}

int gfx_view_console(void)
{
    return view;
}

void gfx_target(int console)
{
    fb = console ? FB_CON : FB_TEST;
}

u32 gfx_console_head_phys(void)
{
    return CON_HEAD_PHYS;
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
    volatile u16 *p = shown();
    for (int r = 0; r < CUR_H; r++)
        for (int c = 0; c < CUR_W; c++) {
            int px = cur_x + c, py = cur_y + r;
            if (arrow[r][c] != '.' && px < SCREEN_W && py < SCREEN_H)
                p[py * PITCH_PX + px] = under[r * CUR_W + c];
        }
    cur_drawn = 0;
}

static void cursor_draw(void)
{
    volatile u16 *p = shown();
    for (int r = 0; r < CUR_H; r++)
        for (int c = 0; c < CUR_W; c++) {
            int px = cur_x + c, py = cur_y + r;
            if (arrow[r][c] == '.' || px >= SCREEN_W || py >= SCREEN_H)
                continue;
            under[r * CUR_W + c] = p[py * PITCH_PX + px];
            p[py * PITCH_PX + px] = arrow[r][c] == 'X' ? RGB(0, 0, 0) : RGB(255, 255, 255);
        }
    cur_drawn = 1;
}

/* drawing at (x, y, w, h) into the target: the pointer taken away first when
   it is over that place of the picture on the TV (the main loop draws it again) */
static void cursor_clear_of(int x, int y, int w, int h)
{
    if (cur_drawn && fb == shown() && x < cur_x + CUR_W && cur_x < x + w && y < cur_y + CUR_H && cur_y < y + h)
        cursor_erase();
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
    cursor_clear_of(x, y, w, h);
    u32 pair = ((u32)color << 16) | color;
    for (int row = 0; row < h; row++) {
        uart_rx_poll();                         /* (the whole screen takes longer than the UART's FIFO lasts) */
        volatile u16 *p = fb + (y + row) * PITCH_PX + x;
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
    return fb[y * PITCH_PX + x];
}

/* a console character cell, 12 x 16 at (x, y) (x even): the 5 x 7 glyph at
   twice its size and a column and a row of spacing, `fg` on `bg` -- two
   pixels a 32-bit store */
void gfx_cell(int x, int y, char c, u16 fg, u16 bg)
{
    if ((u8)c < FONT_FIRST || (u8)c > FONT_LAST)
        c = ' ';
    cursor_clear_of(x, y, 12, 16);
    const u8 *rows = font5x7[(u8)c - FONT_FIRST];
    u32 f = ((u32)fg << 16) | fg, b = ((u32)bg << 16) | bg;
    volatile u32 *p = (volatile u32 *)(fb + y * PITCH_PX + x);
    for (int r = 0; r < FONT_H + 1; r++) {
        u8 bits = r < FONT_H ? rows[r] : 0;
        u32 w0 = (bits & 0x10) ? f : b, w1 = (bits & 0x08) ? f : b, w2 = (bits & 0x04) ? f : b;
        u32 w3 = (bits & 0x02) ? f : b, w4 = (bits & 0x01) ? f : b;
        for (int k = 0; k < 2; k++) {
            p[0] = w0;
            p[1] = w1;
            p[2] = w2;
            p[3] = w3;
            p[4] = w4;
            p[5] = b;
            p += PITCH_PX / 2;
        }
    }
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
