/* The console on the TV: what the UART shows -- the boot messages, the
   prompt and what is typed (on the UART or a USB keyboard), the commands'
   output, the events ('[usb] ...', '[panel] ...', '[ir] ...') -- as a text
   terminal like a Linux console: 105 columns x 42 rows of the demo's 5 x 7
   font at twice its size (12 x 16 cells) under a title bar, the lines
   scrolling up and the last LINES of them kept: PgUp / PgDn (a USB
   keyboard's keys, or ESC [ 5 ~ / ESC [ 6 ~ from a terminal on the UART)
   look back half a screen at a time, new output comes back to the end.

   uart.c hands every character it sends to console_putc, which keeps the
   text and the cursor -- carriage return, line feed, backspace, tab, and of
   the escape sequences the demo sends ESC [ K, ESC [ 2 J and ESC [ H -- so
   the TV shows what a terminal on the UART does.  The picture is a bitmap
   of its own (gfx_view switches the TV between it and the test screen);
   only the cells that changed are drawn, from the main loop and every
   200 ms while a long output runs.  A prompt is green, the line typed after
   it white, an event's '[tag]' cyan, the rest grey; the text cursor (a
   block) blinks. */
#include "hw.h"

#define COLS     105
#define ROWS     42
#define LINES    512                    /* lines kept, the screen's among them */
#define CELL_W   12
#define CELL_H   16
#define X0       ((SCREEN_W - COLS * CELL_W) / 2)
#define TITLE_H  26
#define Y0       (TITLE_H + 6)
#define DRAW_MS  30                     /* the main loop draws at most this often */
#define BUSY_MS  200                    /* and a long output every this often */

#define C_BG       RGB(0, 0, 0)
#define C_BAR      RGB(24, 48, 128)
#define C_BAR_TEXT RGB(255, 255, 255)
#define C_BAR_DIM  RGB(150, 190, 255)
#define C_BAR_BACK RGB(255, 230, 120)

/* a cell's colour: grey text, a green prompt, the white line typed after it,
   a cyan '[tag]'; CURSOR: the text cursor's block over it */
enum { A_TEXT, A_PROMPT, A_TYPED, A_TAG, A_CURSOR = 4 };
static const u16 colours[4] = {RGB(200, 200, 200), RGB(100, 230, 100), RGB(255, 255, 255), RGB(100, 200, 240)};

static char text[LINES][COLS];          /* line n at text[n % LINES]; 0: an empty cell */
static u32 base;                        /* the number of the screen's first line */
static int row, col;                    /* the cursor on the screen */
static int esc;                         /* 1: after ESC, 2: in ESC [ ... */
static char esc_arg;                    /* its first parameter's first digit */
static u32 back;                        /* lines looked back (PgUp) */

static char shown_ch[ROWS][COLS];       /* what the picture has */
static u8 shown_attr[ROWS][COLS];
static char title_ch[COLS];
static u8 title_attr[COLS];
static int shown_ok;                    /* 0: draw everything */
static int started, changed, blink, drawing;
static u64 last_draw, last_blink;

static char *line_at(u32 n)
{
    return text[n % LINES];
}

static void clear_line(u32 n)
{
    char *l = line_at(n);
    for (int i = 0; i < COLS; i++)
        l[i] = 0;
}

static void newline(void)
{
    if (row < ROWS - 1) {
        row++;
        return;
    }
    base++;                             /* the screen's top line goes into what PgUp shows */
    clear_line(base + ROWS - 1);
}

/* ESC [ 2 J: an empty screen, what was on it kept above (as a terminal's
   scrollback keeps it) */
static void clear_screen(void)
{
    base += (u32)row + 1;
    for (int r = 0; r < ROWS; r++)
        clear_line(base + (u32)r);
}

static void draw(void);

void console_putc(char c)
{
    changed = 1;
    back = 0;                           /* new output: the end shown again */
    if (esc == 1) {
        esc = c == '[' ? 2 : 0;
        esc_arg = 0;
        return;
    }
    if (esc == 2) {
        if (c >= '0' && c <= '9') {
            if (!esc_arg)
                esc_arg = c;
            return;
        }
        if (c == ';')
            return;
        esc = 0;
        if (c == 'K') {                 /* erase to the end of the line */
            char *l = line_at(base + (u32)row);
            for (int i = col; i < COLS; i++)
                l[i] = 0;
        } else if (c == 'J' && esc_arg == '2') {
            clear_screen();
        } else if (c == 'H') {
            row = 0;
            col = 0;
        }
        return;
    }
    switch ((u8)c) {
    case 0x1b:
        esc = 1;
        return;
    case '\r':
        col = 0;
        return;
    case '\n':
        newline();
        return;
    case '\b':
        if (col > 0)
            col--;
        return;
    case '\t':
        do
            console_putc(' ');
        while (col % 8 && col < COLS);
        return;
    }
    if ((u8)c < 32 || (u8)c > 126)
        return;
    if (col >= COLS) {                  /* a long line goes on in the next one */
        col = 0;
        newline();
    }
    line_at(base + (u32)row)[col++] = c;
    if (started && !drawing && now_ms() - last_draw >= BUSY_MS)
        draw();                         /* (a long output: the TV keeps up) */
}

/* the colours of a line's cells: a prompt ("m3801...> ") and the line typed
   after it, an event's "[tag]" */
static void line_colours(const char *l, u8 *attr)
{
    int prompt_end = 0, tag_end = 0;
    if (l[0] == 'm' && l[1] == '3' && l[2] == '8' && l[3] == '0' && l[4] == '1') {
        for (int i = 5; i + 1 < COLS && i < 64 && l[i]; i++)
            if (l[i] == '>' && l[i + 1] == ' ') {
                prompt_end = i + 2;
                break;
            }
    } else if (l[0] == '[') {
        for (int i = 1; i < 16 && l[i]; i++)
            if (l[i] == ']') {
                tag_end = i + 1;
                break;
            }
    }
    for (int i = 0; i < COLS; i++)
        attr[i] = (u8)(i < prompt_end ? A_PROMPT : prompt_end ? A_TYPED : i < tag_end ? A_TAG : A_TEXT);
}

static int put_text(char *to, int at, const char *s)
{
    while (*s && at < COLS)
        to[at++] = *s++;
    return at;
}

/* the title bar: what this is, how to look back, the uptime */
static void draw_title(void)
{
    char t[COLS];
    u8 a[COLS];
    char right[64];
    for (int i = 0; i < COLS; i++) {
        t[i] = ' ';
        a[i] = 0;
    }
    int n = put_text(t, 1, "M3801 console - demo " APP_VERSION);
    u32 s = uptime_s();
    if (back)
        usnprintf(right, sizeof(right), "%u lines back - PgDn returns", back);
    else
        usnprintf(right, sizeof(right), "PgUp/PgDn: earlier lines   testscreen   up %u:%02u:%02u", s / 3600,
                  (s / 60) % 60, s % 60);
    int len = 0;
    while (right[len])
        len++;
    int from = COLS - 1 - len;
    if (from < n + 2)
        from = n + 2;
    put_text(t, from, right);
    for (int i = from; i < COLS; i++)
        a[i] = back ? 2 : 1;
    for (int i = 0; i < COLS; i++)
        if (t[i] != title_ch[i] || a[i] != title_attr[i]) {
            gfx_cell(X0 + i * CELL_W, (TITLE_H - CELL_H) / 2, t[i],
                     a[i] == 2 ? C_BAR_BACK : a[i] ? C_BAR_DIM : C_BAR_TEXT, C_BAR);
            title_ch[i] = t[i];
            title_attr[i] = a[i];
        }
}

static void draw(void)
{
    if (!started || !gfx_view_console())
        return;
    drawing = 1;
    gfx_target(1);
    if (!shown_ok) {
        gfx_fill(0, 0, SCREEN_W, SCREEN_H, C_BG);
        gfx_fill(0, 0, SCREEN_W, TITLE_H, C_BAR);
        for (int r = 0; r < ROWS; r++)
            for (int c = 0; c < COLS; c++) {
                shown_ch[r][c] = ' ';
                shown_attr[r][c] = A_TEXT;  /* (a blank cell on black is what the fill left) */
            }
        for (int i = 0; i < COLS; i++) {
            title_ch[i] = ' ';
            title_attr[i] = 0;
        }
        shown_ok = 1;
    }
    draw_title();
    u8 attr[COLS];
    for (int r = 0; r < ROWS; r++) {
        uart_rx_poll();     /* a whole screen takes 17 ms on the box: the UART's 16-byte FIFO lasts 1.4 ms */
        const char *l = line_at(base - back + (u32)r);
        line_colours(l, attr);
        for (int c = 0; c < COLS; c++) {
            char ch = l[c] ? l[c] : ' ';
            u8 a = attr[c];
            if (!back && blink && r == row && c == col)
                a |= A_CURSOR;
            if (ch == shown_ch[r][c] && a == shown_attr[r][c])
                continue;
            u16 fg = colours[a & 3];
            if (a & A_CURSOR)
                gfx_cell(X0 + c * CELL_W, Y0 + r * CELL_H, ch, C_BG, fg);
            else
                gfx_cell(X0 + c * CELL_W, Y0 + r * CELL_H, ch, fg, C_BG);
            shown_ch[r][c] = ch;
            shown_attr[r][c] = a;
        }
    }
    gfx_target(0);
    changed = 0;
    drawing = 0;
    last_draw = now_ms();
}

void console_start(void)
{
    started = 1;
    shown_ok = 0;
    draw();
}

void console_redraw(void)
{
    shown_ok = 0;
    changed = 1;
    draw();
}

void console_service(void)
{
    if (!started)
        return;
    u64 now = now_ms();
    if (now - last_blink >= 500) {      /* the cursor blinks; the title's uptime */
        last_blink = now;
        blink ^= 1;
        changed = 1;
    }
    if (changed && now - last_draw >= DRAW_MS)
        draw();
}

void console_scroll(int pages)
{
    u32 most = base < LINES - ROWS ? base : LINES - ROWS;
    int b = (int)back + pages * (ROWS / 2);
    if (b < 0)
        b = 0;
    if ((u32)b > most)
        b = (int)most;
    back = (u32)b;
    changed = 1;
    draw();
}
