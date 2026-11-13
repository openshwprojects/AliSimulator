/* ELEKTRODA ALI M3801 TEST FOR MACIEJ -- demo v4.

   A freestanding RAM application started by the box's original bootloader
   (no vendor SDK, no RTOS, no interrupts).  It shows:
     - a command line on the UART (115200 8E1): whole lines with editing and
       history, 'help' lists the commands;
     - a picture on the TV: a 1280 x 720 ARGB1555 OSD layer the CPU draws;
     - the front panel: text on the four 7-segment digits, key presses --
       or, on a board without the TM1650 (the Comsat TE 1050 HD), its two
       buttons on GPIO 31 / 9;
     - the remote control: every received NEC frame, its code and button;
     - the USB host controller: the device on its port, enumerated; a USB
       keyboard types into the command line like the UART (kbd.c).
   The UART updater (tools/maciej_uart.py --capture-boot) still works while
   it runs: three 'c' in a row on an empty line restart the box through the
   original bootloader, whose boot window the updater then catches. */
#include "hw.h"
#include "video_init.h"

/* ------------------------------------------------------------------ */
/* small string helpers (no libc)                                      */
/* ------------------------------------------------------------------ */
static int str_eq(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static int str_len(const char *s)
{
    int n = 0;
    while (s[n])
        n++;
    return n;
}

static void str_copy(char *dst, const char *src, int size)
{
    int i = 0;
    for (; i < size - 1 && src[i]; i++)
        dst[i] = src[i];
    dst[i] = 0;
}

/* "0x1f" (hex), "31" (decimal); returns 0 for an invalid number */
static int parse_u32(const char *s, u32 *out)
{
    u32 v = 0;
    int base = 10, digits = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        s += 2;
    }
    for (; *s; s++, digits++) {
        int d;
        if (*s >= '0' && *s <= '9')
            d = *s - '0';
        else if (base == 16 && *s >= 'a' && *s <= 'f')
            d = *s - 'a' + 10;
        else if (base == 16 && *s >= 'A' && *s <= 'F')
            d = *s - 'A' + 10;
        else
            return 0;
        v = v * (u32)base + (u32)d;
    }
    *out = v;
    return digits > 0;
}

/* ------------------------------------------------------------------ */
/* the picture                                                         */
/* ------------------------------------------------------------------ */
#define C_BG_TOP   RGB(16, 28, 72)
#define C_BG_BOT   RGB(2, 4, 16)
#define C_HEADER   RGB(24, 48, 128)
#define C_BOX      RGB(10, 16, 40)
#define C_FRAME    RGB(90, 140, 230)
#define C_TITLE    RGB(255, 255, 255)
#define C_LABEL    RGB(150, 190, 255)
#define C_VALUE    RGB(255, 230, 120)
#define C_OK       RGB(120, 230, 140)
#define C_DIM      RGB(120, 120, 140)

struct box {
    int x, y, w, h;
    const char *title;
};

static const struct box BOX_SYSTEM = {40, 120, 580, 200, "SYSTEM"};
static const struct box BOX_REMOTE = {660, 120, 580, 200, "REMOTE CONTROL"};
static const struct box BOX_PANEL = {40, 340, 580, 160, "FRONT PANEL"};
static const struct box BOX_UART = {660, 340, 580, 160, "COMMAND LINE"};
static const struct box BOX_USB = {40, 520, 580, 100, "USB HOST"};
static const struct box BOX_BARS = {660, 520, 580, 100, "COLOUR BARS"};

static void draw_box(const struct box *b)
{
    gfx_fill(b->x, b->y, b->w, b->h, C_BOX);
    gfx_frame(b->x, b->y, b->w, b->h, 3, C_FRAME);
    gfx_fill(b->x + 3, b->y + 3, b->w - 6, 30, C_HEADER);
    gfx_text(b->x + 14, b->y + 10, b->title, 2, C_TITLE);
}

/* one line of a box: a label and a value, the value area cleared first */
static void box_line(const struct box *b, int row, const char *label, const char *value, int scale, u16 color)
{
    int y = b->y + 44 + row * 26;
    int x = b->x + 16;
    gfx_fill(x, y, b->w - 32, 8 * scale, C_BOX);
    if (label)
        x = gfx_text(x, y, label, 2, C_LABEL) + 8;
    gfx_text(x, y, value, scale, color);
}

/* the demo screen is up (its boxes are kept current); a 'screen' drawing
   command hands the picture over until 'screen demo' */
static int demo_shown;
static int line_dirty = 1;              /* the command line box's typed line needs drawing */

static char last_command[48] = "(none yet)";
static u32 commands_run;
static char ir_text[3][40] = {"(press a button)", "", ""};
static char panel_key_text[40] = "(press a key)";
static u32 panel_presses;

static void draw_bars(void)
{
    static const u32 colors[8] = {0xFFFFFF, 0xFFFF00, 0x00FFFF, 0x00FF00, 0xFF00FF, 0xFF0000, 0x0000FF, 0x000000};
    const struct box *b = &BOX_BARS;
    int w = (b->w - 32) / 8;
    for (int i = 0; i < 8; i++)
        gfx_fill(b->x + 16 + i * w, b->y + 44, w, b->h - 56, rgb_from_hex(colors[i]));
}

static void update_uptime(void)
{
    if (!demo_shown)
        return;
    char buf[40];
    u32 s = uptime_s();
    usnprintf(buf, sizeof(buf), "%u:%02u:%02u", s / 3600, (s / 60) % 60, s % 60);
    box_line(&BOX_SYSTEM, 3, "Uptime", buf, 2, C_VALUE);
}

static void update_remote(void)
{
    if (!demo_shown)
        return;
    box_line(&BOX_REMOTE, 0, 0, ir_text[0], 3, C_VALUE);
    box_line(&BOX_REMOTE, 2, 0, ir_text[1], 2, C_TITLE);
    box_line(&BOX_REMOTE, 3, 0, ir_text[2], 2, C_LABEL);
    char buf[40];
    usnprintf(buf, sizeof(buf), "%u", ir_frames());
    box_line(&BOX_REMOTE, 4, "Frames", buf, 2, C_VALUE);
}

static void update_panel_box(void)
{
    if (!demo_shown)
        return;
    if (panel_present())
        box_line(&BOX_PANEL, 0, "Display", panel_current(), 2, C_VALUE);
    else
        box_line(&BOX_PANEL, 0, "Buttons", "GPIO 31 / 9, no display", 2, C_DIM);
    box_line(&BOX_PANEL, 1, "Key", panel_key_text, 2, C_TITLE);
    char buf[16];
    usnprintf(buf, sizeof(buf), "%u", panel_presses);
    box_line(&BOX_PANEL, 2, "Presses", buf, 2, C_VALUE);
}

static void update_uart_box(void)
{
    if (!demo_shown)
        return;
    box_line(&BOX_UART, 0, "Last", last_command, 2, C_VALUE);
    char buf[16];
    usnprintf(buf, sizeof(buf), "%u", commands_run);
    box_line(&BOX_UART, 1, "Commands", buf, 2, C_VALUE);
    box_line(&BOX_UART, 3, 0, "UART 115200 8E1 or a USB keyboard", 2, C_DIM);
}

static int usb_shown = -1;

static void update_usb_box(void)
{
    int connected = usb_connected();
    usb_shown = connected;
    if (!demo_shown)
        return;
    box_line(&BOX_USB, 0, "Port", connected ? "device connected" : "no device", 2, connected ? C_OK : C_DIM);
    if (connected && usb_summary()[0])
        box_line(&BOX_USB, 1, kbd_active() ? "Keyboard" : "Device", usb_summary(), 2, C_VALUE);
    else
        box_line(&BOX_USB, 1, "Controller", "0xB8032000", 2, C_DIM);
}

static void draw_screen(void)
{
    char buf[48];
    demo_shown = 1;
    gfx_gradient(0, 0, SCREEN_W, SCREEN_H, C_BG_TOP, C_BG_BOT);
    gfx_fill(0, 0, SCREEN_W, 96, C_HEADER);
    gfx_fill(0, 96, SCREEN_W, 3, C_FRAME);
    int w = gfx_text_width(APP_BANNER, 4);
    gfx_text((SCREEN_W - w) / 2, 14, APP_BANNER, 4, C_TITLE);
    const char *sub = "Demo " APP_VERSION " - a RAM application started by the original bootloader";
    w = gfx_text_width(sub, 2);
    gfx_text((SCREEN_W - w) / 2, 62, sub, 2, C_LABEL);

    draw_box(&BOX_SYSTEM);
    u32 id = REG32(SYS_CHIP_ID);
    usnprintf(buf, sizeof(buf), "%04x (rev byte %02x)", id >> 16, id & 0xFF);
    box_line(&BOX_SYSTEM, 0, "Chip ID", buf, 2, C_VALUE);
    usnprintf(buf, sizeof(buf), "%u MHz", cpu_mhz());
    box_line(&BOX_SYSTEM, 1, "CPU", buf, 2, C_VALUE);
    box_line(&BOX_SYSTEM, 2, "Picture", "1280x720 ARGB1555", 2, C_VALUE);
    update_uptime();

    draw_box(&BOX_REMOTE);
    update_remote();
    draw_box(&BOX_PANEL);
    update_panel_box();
    draw_box(&BOX_UART);
    update_uart_box();
    line_dirty = 1;
    draw_box(&BOX_USB);
    update_usb_box();
    draw_box(&BOX_BARS);
    draw_bars();

    const char *foot = "AliSimulator demo - type 'help' on the UART or a USB keyboard";
    w = gfx_text_width(foot, 2);
    gfx_text((SCREEN_W - w) / 2, 668, foot, 2, C_DIM);
}

/* ------------------------------------------------------------------ */
/* events                                                              */
/* ------------------------------------------------------------------ */
static void on_ir(const struct ir_event *ev)
{
    if (!ev->valid) {
        uprintf("[ir] frame not decoded (%u runs)\n", ev->runs);
        usnprintf(ir_text[1], sizeof(ir_text[1]), "not NEC (%u runs)", ev->runs);
        update_remote();
        return;
    }
    const char *name = ir_key_name(ev->code);
    if (ev->repeat) {
        uprintf("[ir] repeat %08x%s%s\n", ev->code, name ? " " : "", name ? name : "");
        return;
    }
    uprintf("[ir] NEC %08x  address %02x %02x  command %02x %02x  %s\n", ev->code,
            ev->bytes[0], ev->bytes[1], ev->bytes[2], ev->bytes[3], name ? name : "(unknown button)");
    usnprintf(ir_text[0], sizeof(ir_text[0]), "%s", name ? name : "?");
    usnprintf(ir_text[1], sizeof(ir_text[1]), "code %08x", ev->code);
    usnprintf(ir_text[2], sizeof(ir_text[2]), "addr %02x %02x cmd %02x", ev->bytes[0], ev->bytes[1], ev->bytes[2]);
    update_remote();
    char four[5];
    if (name) {
        int i = 0;
        for (; i < 4 && name[i] && name[i] != '/'; i++)
            four[i] = name[i];
        four[i] = 0;
    } else {
        usnprintf(four, sizeof(four), "r %02x", ev->bytes[2]);
    }
    panel_text(four);
    update_panel_box();
}

static int last_key = -2;
static int buttons_held, buttons_seen;     /* without a TM1650: the reported and the last read state */

static const char *panel_key_name(int key)
{
    switch (key & 0x3F) {                 /* front_panel.py's dump_maciej labels */
    case 0x07: return "UP (KI1/DIG4)";
    case 0x0F: return "DOWN (KI2/DIG4)";
    }
    return 0;
}

static const char *button_name(int bit)
{
    return bit == PANEL_BUTTON_UP ? "UP (GPIO 31)" : "DOWN (GPIO 9)";
}

static void event_begin(void)
{
    uart_puts("\r\x1b[K");                 /* the event line replaces the prompt line */
}

/* The two buttons of a board without the TM1650: a change counts once two
   reads 100 ms apart agree (the original firmwares confirm a press the same
   way).  Returns 1 when it printed an event. */
static int poll_buttons(void)
{
    int now = panel_buttons();
    int same = now == buttons_seen;
    buttons_seen = now;
    if (!same || now == buttons_held)
        return 0;
    int changed = now ^ buttons_held;
    buttons_held = now;
    event_begin();
    for (int bit = PANEL_BUTTON_UP; bit <= PANEL_BUTTON_DOWN; bit <<= 1) {
        if (!(changed & bit))
            continue;
        int down = (now & bit) != 0;
        if (down)
            panel_presses++;
        uprintf("[panel] button %s %s\n", button_name(bit), down ? "pressed" : "released");
        usnprintf(panel_key_text, sizeof(panel_key_text), "%s %s", button_name(bit), down ? "pressed" : "released");
    }
    update_panel_box();
    return 1;
}

/* Returns 1 when it printed an event. */
static int poll_panel(void)
{
    if (!panel_present())
        return poll_buttons();
    int key = panel_read_key();
    if (key == last_key)
        return 0;
    int was = last_key;
    last_key = key;
    if (key < 0) {
        event_begin();
        uprintf("[panel] no answer from the front panel chip\n");
        return 1;
    }
    if (!(key & 0x40)) {
        if (was >= 0 && (was & 0x40)) {
            event_begin();
            uprintf("[panel] key released\n");
            return 1;
        }
        return 0;
    }
    event_begin();
    const char *name = panel_key_name(key);
    panel_presses++;
    uprintf("[panel] key %02x pressed: KI%d/DIG%d%s%s\n", key, ((key >> 3) & 7) + 1, (key & 3) + 1,
            name ? " " : "", name ? name : "");
    usnprintf(panel_key_text, sizeof(panel_key_text), "%02x %s", key, name ? name : "");
    char four[5];
    usnprintf(four, sizeof(four), "P %02x", key & 0x3F);
    panel_text(four);
    update_panel_box();
    return 1;
}

/* ------------------------------------------------------------------ */
/* the command line                                                    */
/* ------------------------------------------------------------------ */
#define LINE_MAX 96
#define HISTORY 8
#define ARGS_MAX 10

static char line[LINE_MAX];
static int line_len;
static char history[HISTORY][LINE_MAX];
static int history_count, history_pos;
static int esc_state;

static void prompt(void)
{
    uart_puts("m3801> ");
}

static void show_line(void)
{
    /* clear the terminal line and print the prompt and the buffer again */
    uart_puts("\r\x1b[K");
    prompt();
    for (int i = 0; i < line_len; i++)
        uart_putc(line[i]);
}

/* the line being typed, on the TV too (the command line box; the main loop
   redraws it at most 20 times a second) */
#define TV_LINE_CHARS 40

static void update_line_box(void)
{
    char text[TV_LINE_CHARS + 2];
    int start = line_len > TV_LINE_CHARS - 1 ? line_len - (TV_LINE_CHARS - 1) : 0, n = 0;
    line_dirty = 0;
    if (!demo_shown)
        return;
    for (int i = start; i < line_len; i++)
        text[n++] = line[i];
    text[n++] = '_';
    text[n] = 0;
    box_line(&BOX_UART, 2, ">", text, 2, C_TITLE);
}

struct command {
    const char *name, *args, *help;
    void (*run)(int argc, char **argv);
};

static void cmd_help(int argc, char **argv);
static void cmd_version(int argc, char **argv);
static void cmd_ping(int argc, char **argv);
static void cmd_info(int argc, char **argv);
static void cmd_uptime(int argc, char **argv);
static void cmd_echo(int argc, char **argv);
static void cmd_md(int argc, char **argv);
static void cmd_mr(int argc, char **argv);
static void cmd_mw(int argc, char **argv);
static void cmd_screen(int argc, char **argv);
static void cmd_panel(int argc, char **argv);
static void cmd_keys(int argc, char **argv);
static void cmd_ir(int argc, char **argv);
static void cmd_usb(int argc, char **argv);
static void cmd_lsusb(int argc, char **argv);
static void cmd_disks(int argc, char **argv);
static void cmd_ls(int argc, char **argv);
static void cmd_cat(int argc, char **argv);
static void cmd_sector(int argc, char **argv);
static void cmd_watchdog(int argc, char **argv);
static void cmd_clear(int argc, char **argv);
static void cmd_reboot(int argc, char **argv);
static void cmd_bootloader(int argc, char **argv);
static void cmd_video(int argc, char **argv);

static const struct command commands[] = {
    {"help", "[command]", "this list", cmd_help},
    {"version", "", "banner and version", cmd_version},
    {"ping", "", "answers pong", cmd_ping},
    {"info", "", "chip, clock, memory layout, uptime", cmd_info},
    {"uptime", "", "time since this application started", cmd_uptime},
    {"echo", "<words>", "prints its arguments", cmd_echo},
    {"md", "<addr> [len]", "dump memory (RAM, flash window, registers)", cmd_md},
    {"mr", "<addr>", "read a 32-bit word", cmd_mr},
    {"mw", "<addr> <value>", "write a 32-bit word (RAM, registers)", cmd_mw},
    {"screen", "[subcommand]", "TV picture: demo, bars, clear [rrggbb], text <x> <y> <words>, "
               "rect <x> <y> <w> <h> <rrggbb>, on, off", cmd_screen},
    {"panel", "[text|bright <n>]", "front panel digits", cmd_panel},
    {"keys", "", "front panel key state", cmd_keys},
    {"ir", "[raw on|off]", "remote control receiver", cmd_ir},
    {"usb", "[reset|init|kbd|mouse|reg|ctl]", "USB port and the descriptors of its device (through a hub: of "
     "every device behind it); reset: a bus reset, init: the controller set up again, kbd [report|interrupt|raw "
     "on|off]: the keyboard, mouse: the mouse and its pointer, reg <off> [byte]: a register, ctl <type> <req> "
     "<value> <index> <len> [device]: a control request", cmd_usb},
    {"lsusb", "", "the USB devices, one line each", cmd_lsusb},
    {"disks", "", "USB disks (sticks, card readers): their size, partitions and file systems", cmd_disks},
    {"ls", "[n:][/path]", "a directory on a USB disk's FAT volume (n: the disk's device number, as "
     "lsusb lists it; n.p: its partition p)", cmd_ls},
    {"cat", "[n:]/path", "a text file on a USB disk (Ctrl-C stops it)", cmd_cat},
    {"sector", "[n:]<number>", "one sector of a USB disk in hex", cmd_sector},
    {"watchdog", "[test|off|on]", "the chip's watchdog: a demo stopped for 8 s restarts the box; "
     "test: stop feeding it (the box restarts)", cmd_watchdog},
    {"clear", "", "clear the terminal", cmd_clear},
    {"video", "init [opticum|comsat] [rev0|rev1]", "experimental: the original firmware's display and HDMI set-up",
     cmd_video},
    {"reboot", "", "restart through the original bootloader", cmd_reboot},
    {"restart", "", "the same as reboot", cmd_reboot},
    {"bootloader", "", "restart into the original bootloader: hold 'c' (or run maciej_uart.py) to stay", cmd_bootloader},
    {0, 0, 0, 0},
};

static int mem_range_ok(u32 a, u32 len)
{
    u32 end = a + len - 1;
    if (len == 0 || end < a)
        return 0;
    if ((a >= 0x80000000u && end < 0x88000000u) || (a >= 0xA0000000u && end < 0xA8000000u))
        return 1;                                      /* 128 MB DDR, cached / uncached */
    if ((a >= 0xAFC00000u && end <= 0xAFFFFFFFu) || (a >= 0xBFC00000u && end <= 0xBFFFFFFFu))
        return 2;                                      /* the 4 MB flash window */
    if (a >= 0xB8000000u && end <= 0xB8FFFFFFu)
        return 3;                                      /* device registers */
    return 0;
}

static void cmd_help(int argc, char **argv)
{
    if (argc > 1) {
        const char *name = argv[1][0] == '/' ? argv[1] + 1 : argv[1];
        for (const struct command *c = commands; c->name; c++)
            if (str_eq(c->name, name)) {
                uprintf("%s %s\n  %s\n", c->name, c->args, c->help);
                return;
            }
        uprintf("no command '%s'\n", argv[1]);
        return;
    }
    uprintf("Commands (whole lines, '/' in front allowed; Up/Down recall earlier ones;\n"
            "'ccc' on an empty line restarts into the bootloader for the UART updater):\n");
    for (const struct command *c = commands; c->name; c++) {
        char head[56];
        usnprintf(head, sizeof(head), "%s %s", c->name, c->args);
        uprintf("  %s", head);
        for (int i = str_len(head); i < 44; i++)
            uart_putc(' ');
        uprintf("%s\n", c->help);
    }
}

static void cmd_version(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    uprintf("%s\nVersion: %s\n", APP_BANNER, APP_VERSION);
}

static void cmd_ping(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    uprintf("pong %s\n", APP_VERSION);
}

static void cmd_info(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    u32 id = REG32(SYS_CHIP_ID);
    extern char _start[], __bss_end[];
    uprintf("chip ID word 0x%08x: %04x%s, revision byte %02x\n", id, id >> 16,
            (id >> 16) == 0x3811 ? " (S3811, the M3801's silicon)" : "", id & 0xFF);
    uprintf("CPU %u MHz (strap 0x%08x), CP0 Count %u kHz\n", cpu_mhz(), REG32(SYS_STRAP), ticks_per_ms());
    uprintf("application 0x%08x..0x%08x (%u bytes), picture at 0x%08x, region head 0x%08x\n",
            (u32)_start, (u32)__bss_end, (u32)(__bss_end - _start), gfx_fb_phys(), gfx_head_phys());
    uprintf("board: %s\n", panel_present() ? "TM1650 front panel on GPIO 31 / 9 (Opticum HD N2 type)"
                                          : "no TM1650; two buttons on GPIO 31 / 9 (Comsat TE 1050 HD type)");
    uprintf("display layer register 0xb8006300: 0x%08x at the demo's start, 0x%08x now\n",
            gfx_enable_at_start(), REG32(GMA0_ENABLE));
    uprintf("uptime %u ms\n", (u32)now_ms());
}

static void cmd_uptime(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    u32 s = uptime_s();
    uprintf("up %u:%02u:%02u (%u s)\n", s / 3600, (s / 60) % 60, s % 60, s);
}

static void cmd_echo(int argc, char **argv)
{
    for (int i = 1; i < argc; i++)
        uprintf("%s%s", i > 1 ? " " : "", argv[i]);
    uprintf("\n");
}

static void cmd_md(int argc, char **argv)
{
    u32 a, len = 64;
    if (argc < 2 || !parse_u32(argv[1], &a) || (argc > 2 && !parse_u32(argv[2], &len))) {
        uprintf("usage: md <address> [length]\n");
        return;
    }
    if (len > 4096)
        len = 4096;
    if (!mem_range_ok(a, len)) {
        uprintf("refused: 0x%08x..+%u is not RAM, flash or the device window\n", a, len);
        return;
    }
    for (u32 off = 0; off < len; off += 16) {
        uprintf("%08x:", a + off);
        char ascii[17];
        u32 n = len - off < 16 ? len - off : 16;
        for (u32 i = 0; i < 16; i++) {
            if (i < n) {
                u8 b = REG8(a + off + i);
                uprintf(" %02x", b);
                ascii[i] = (b >= 32 && b < 127) ? (char)b : '.';
            } else {
                uprintf("   ");
                ascii[i] = ' ';
            }
        }
        ascii[16] = 0;
        uprintf("  %s\n", ascii);
    }
}

static void cmd_mr(int argc, char **argv)
{
    u32 a;
    if (argc < 2 || !parse_u32(argv[1], &a) || (a & 3)) {
        uprintf("usage: mr <word-aligned address>\n");
        return;
    }
    if (!mem_range_ok(a, 4)) {
        uprintf("refused: 0x%08x is not RAM, flash or the device window\n", a);
        return;
    }
    uprintf("%08x: %08x\n", a, REG32(a));
}

static void cmd_mw(int argc, char **argv)
{
    u32 a, v;
    if (argc < 3 || !parse_u32(argv[1], &a) || !parse_u32(argv[2], &v) || (a & 3)) {
        uprintf("usage: mw <word-aligned address> <value>\n");
        return;
    }
    int kind = mem_range_ok(a, 4);
    if (kind == 0 || kind == 2) {
        uprintf("refused: 0x%08x is not RAM or a device register\n", a);
        return;
    }
    REG32(a) = v;
    uprintf("%08x <- %08x (reads back %08x)\n", a, v, REG32(a));
}

static void cmd_panel(int argc, char **argv)
{
    if (!panel_present()) {
        uprintf("no front panel display on this board: no TM1650 answered at start, so GPIO 31 / 9\n"
                "are read as two buttons (UP / DOWN; see 'keys'); last: %s\n", panel_key_text);
        return;
    }
    if (argc == 1) {
        uprintf("front panel shows \"%s\"; last key: %s\n", panel_current(), panel_key_text);
        return;
    }
    if (str_eq(argv[1], "bright") && argc > 2) {
        u32 level;
        if (!parse_u32(argv[2], &level) || level > 7) {
            uprintf("usage: panel bright <0..7>\n");
            return;
        }
        panel_brightness((int)level);
        uprintf("brightness %u\n", level);
        return;
    }
    char four[5] = "    ";
    int n = 0;
    for (int i = 1; i < argc && n < 4; i++)
        for (const char *p = argv[i]; *p && n < 4; p++)
            four[n++] = *p;
    panel_text(four);
    update_panel_box();
    uprintf("front panel: \"%s\"\n", panel_current());
}

static void cmd_keys(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (!panel_present()) {
        int held = panel_buttons();
        uprintf("buttons: UP (GPIO 31) %s, DOWN (GPIO 9) %s; %u presses so far\n",
                (held & PANEL_BUTTON_UP) ? "pressed" : "released",
                (held & PANEL_BUTTON_DOWN) ? "pressed" : "released", panel_presses);
        return;
    }
    int key = panel_read_key();
    if (key < 0)
        uprintf("the front panel chip does not answer\n");
    else
        uprintf("key byte %02x: %s KI%d/DIG%d; %u presses so far\n", key, (key & 0x40) ? "pressed" : "released (last)",
                ((key >> 3) & 7) + 1, (key & 3) + 1, panel_presses);
}

static void cmd_ir(int argc, char **argv)
{
    if (argc > 2 && str_eq(argv[1], "raw")) {
        int on = str_eq(argv[2], "on");
        ir_set_raw(on);
        uprintf("raw IR timing %s\n", on ? "on" : "off");
        return;
    }
    uprintf("IR receiver at 0x%08x: %u frames; last: %s, %s, %s\n", IRC_BASE, ir_frames(), ir_text[0], ir_text[1], ir_text[2]);
}

static int parse_args_u32(int argc, char **argv, int first, int count, u32 *out);

static void cmd_usb(int argc, char **argv)
{
    if (argc > 1 && str_eq(argv[1], "reset")) {
        usb_bus_reset();
        update_usb_box();
        return;
    }
    if (argc > 1 && str_eq(argv[1], "mouse")) {
        mouse_show_status();
        return;
    }
    if (argc > 1 && str_eq(argv[1], "kbd")) {
        if (argc > 2 && (str_eq(argv[2], "report") || str_eq(argv[2], "interrupt"))) {
            if (!kbd_active()) {
                uprintf("no USB keyboard\n");
                return;
            }
            kbd_set_mode(str_eq(argv[2], "interrupt"));
        } else if (argc > 3 && str_eq(argv[2], "raw") && (str_eq(argv[3], "on") || str_eq(argv[3], "off"))) {
            kbd_set_raw(str_eq(argv[3], "on"));
        } else if (argc > 2) {
            uprintf("usage: usb kbd [report | interrupt | raw on|off]\n");
            return;
        }
        kbd_show_status();
        return;
    }
    if (argc > 1 && str_eq(argv[1], "reg")) {
        u32 off, value = 0;
        int write = argc > 3;
        if (argc < 3 || !parse_u32(argv[2], &off) || (write && (!parse_u32(argv[3], &value) || value > 0xFF))) {
            uprintf("usage: usb reg <offset 0..0xff> [byte]\n");
            return;
        }
        int v = usb_reg(off, write, (u8)value);
        if (v == -2)
            uprintf("refused: the PHY's registers (+0xf0..+0xf7) are set by 'usb init'\n");
        else if (v < 0)
            uprintf("usage: usb reg <offset 0..0xff> [byte]\n");
        else
            uprintf("0x%08x %s %02x\n", USB_BASE + off, write ? "<-" : "=", write ? value : (u32)v);
        if (write && v >= 0)
            uprintf("  reads back %02x\n", (u32)v);
        return;
    }
    if (argc > 1 && str_eq(argv[1], "ctl")) {          /* a raw control request (IN data or none) */
        u32 v[5], device = 1;
        if (!parse_args_u32(argc, argv, 2, 5, v) || v[0] > 0xFF || v[1] > 0xFF || v[2] > 0xFFFF || v[3] > 0xFFFF
            || v[4] > 255 || (argc > 7 && (!parse_u32(argv[7], &device) || device < 1 || device > 15))) {
            uprintf("usage: usb ctl <bmRequestType> <bRequest> <wValue> <wIndex> <wLength 0..255> [device 1..]\n"
                    "       (the device's address as lsusb lists it; 1: the one on the box's port)\n");
            return;
        }
        static u8 buf[256];
        int n = usb_request((u8)device, (u8)v[0], (u8)v[1], (u16)v[2], (u16)v[3], buf, (u16)v[4], 500);
        if (n < 0) {
            uprintf("failed: %s\n", usb_error_text());
            return;
        }
        uprintf("%d bytes:", n);
        for (int i = 0; i < n; i++)
            uprintf("%s%02x", i % 16 ? " " : "\n  ", buf[i]);
        uprintf("\n");
        return;
    }
    if (argc > 1 && str_eq(argv[1], "init"))
        usb_init();
    else if (argc > 1) {
        uprintf("usage: usb [reset | init | kbd [report|interrupt|raw on|off] | mouse | reg <offset> [byte] |\n"
                "            ctl <type> <request> <value> <index> <length> [device]]\n");
        return;
    }
    usb_status();
    if (usb_connected())
        usb_enumerate();
    update_usb_box();
}

static int parse_args_u32(int argc, char **argv, int first, int count, u32 *out)
{
    if (argc < first + count)
        return 0;
    for (int i = 0; i < count; i++)
        if (!parse_u32(argv[first + i], &out[i]))
            return 0;
    return 1;
}

static u32 parse_color(const char *s, int *ok)
{
    u32 v = 0;
    *ok = 0;
    if (*s == '#')
        s++;
    int n = 0;
    for (; *s; s++, n++) {
        int d;
        if (*s >= '0' && *s <= '9') d = *s - '0';
        else if (*s >= 'a' && *s <= 'f') d = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F') d = *s - 'A' + 10;
        else return 0;
        v = (v << 4) | (u32)d;
    }
    *ok = n == 6;
    return v;
}

static void cmd_screen(int argc, char **argv)
{
    int ok;
    u32 n[4];
    if (argc == 1) {
        uprintf("picture %s: GMA layer 0 (0xb8006300 = 0x%08x), region head 0x%08x, bitmap 0x%08x, "
                "1280x720 ARGB1555\n",
                gfx_enabled() ? "on" : "off", REG32(GMA0_ENABLE), gfx_head_phys(), gfx_fb_phys());
        return;
    }
    if (str_eq(argv[1], "demo")) {
        draw_screen();
    } else if (str_eq(argv[1], "on") || str_eq(argv[1], "off")) {
        gfx_enable(str_eq(argv[1], "on"));
    } else if (str_eq(argv[1], "clear")) {
        u32 c = argc > 2 ? parse_color(argv[2], &ok) : 0;
        if (argc > 2 && !ok) {
            uprintf("usage: screen clear [rrggbb]\n");
            return;
        }
        demo_shown = 0;
        gfx_fill(0, 0, SCREEN_W, SCREEN_H, rgb_from_hex(c));
    } else if (str_eq(argv[1], "bars")) {
        demo_shown = 0;
        static const u32 colors[8] = {0xFFFFFF, 0xFFFF00, 0x00FFFF, 0x00FF00, 0xFF00FF, 0xFF0000, 0x0000FF, 0x000000};
        for (int i = 0; i < 8; i++)
            gfx_fill(i * SCREEN_W / 8, 0, SCREEN_W / 8, SCREEN_H, rgb_from_hex(colors[i]));
    } else if (str_eq(argv[1], "text") && parse_args_u32(argc, argv, 2, 2, n) && argc > 4) {
        char text[LINE_MAX];
        int len = 0;
        for (int i = 4; i < argc; i++)
            for (const char *p = argv[i]; *p && len < LINE_MAX - 2; p++)
                text[len++] = *p == '_' ? ' ' : *p;
        text[len] = 0;
        demo_shown = 0;
        gfx_text((int)n[0], (int)n[1], text, 3, C_TITLE);
    } else if (str_eq(argv[1], "rect") && parse_args_u32(argc, argv, 2, 4, n) && argc > 6) {
        u32 c = parse_color(argv[6], &ok);
        if (!ok) {
            uprintf("usage: screen rect <x> <y> <w> <h> <rrggbb>\n");
            return;
        }
        demo_shown = 0;
        gfx_fill((int)n[0], (int)n[1], (int)n[2], (int)n[3], rgb_from_hex(c));
    } else {
        uprintf("usage: screen [demo|on|off|bars|clear [rrggbb]|text <x> <y> <words>|rect <x> <y> <w> <h> <rrggbb>]\n");
        return;
    }
    uprintf("ok\n");
}

static void cmd_clear(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    uart_puts("\x1b[2J\x1b[H");
}

static void restart(const char *why)
{
    uprintf("%s\n", why);
    panel_text("boot");
    uart_flush();                          /* the FIFO and the shift register */
    platform_restart();
}

/* The bootloader leaves the display engine off, so on the box the TV shows
   nothing until something programs it.  This replays the stores an original
   application makes to bring up its 720p picture (video_init.h, recorded in
   the emulator with a TV on the HDMI port: display engine, TV encoder, VCAP,
   clock and reset bits, and the HDMI transmitter up to its start -- out of
   soft reset, unmuted), then puts the demo's own OSD layer back.  There is
   a table per board, each from the board's own firmware; the board is told
   by the front panel (a TM1650 answers on the Opticum, not on the Comsat).
   The firmwares branch on the chip's revision (the TV encoder, when the
   output is switched on), so each board has a table per revision and the
   chip's own is used (chip_rev; a real box reads 1, the emulator 0).
   The drivers' status polls are not replayed, only their pauses, so this is
   a guess at what the hardware needs; the emulator shows the picture with
   or without it. */
struct video_board {
    const char *key, *name, *image;
    const struct video_write *table[2];     /* chip revision 0, 1 */
    u32 count[2];
};

static const struct video_board video_boards[] = {
    {"opticum", "Opticum HD N2", "dump_maciej.bin", {video_init_opticum_rev0, video_init_opticum_rev1},
     {VIDEO_INIT_OPTICUM_REV0_COUNT, VIDEO_INIT_OPTICUM_REV1_COUNT}},
    {"comsat", "Comsat TE 1050 HD", "dump.bin", {video_init_comsat_rev0, video_init_comsat_rev1},
     {VIDEO_INIT_COMSAT_REV0_COUNT, VIDEO_INIT_COMSAT_REV1_COUNT}},
};

#define HDMI_CTRL 0xB802A007u              /* bit 0: the transmitter's soft reset */

/* replay a board's display set-up (video_init.h) and switch the picture on */
static void video_setup(const struct video_board *board, int rev)
{
    const struct video_write *table = board->table[rev];
    u32 count = board->count[rev], stores = 0, waited = 0;
    for (u32 i = 0; i < count; i++)
        if (table[i].size)
            stores++;
        else
            waited += table[i].value;
    uprintf("replaying %u register stores of the %s's display set-up (%s, chip revision %d, with %u ms of\n"
            "its pauses)...\n", stores, board->name, board->image, rev, waited);
    uart_flush();
    for (u32 i = 0; i < count; i++) {
        const struct video_write *w = &table[i];
        u32 a = 0xB8000000u | w->offset;
        if (w->size == 0)
            delay_ms(w->value);
        else if (w->size == 1)
            REG8(a) = (u8)w->value;
        else if (w->size == 2)
            REG16(a) = (u16)w->value;
        else
            REG32(a) = w->value;
    }
    /* GPIO 17 low: both originals drive it low (the bootloaders leave it
       high) as their picture goes on -- the GPIO stores are not in the table */
    REG32(GPIO0_DO) = REG32(GPIO0_DO) & ~(1u << 17);
    gfx_enable(1);                           /* (also the layer register 0xB8006308) */
    draw_screen();
    u8 hdmi = REG8(HDMI_CTRL);
    uprintf("done: output timing 0x%08x (750 lines: 720p), HDMI transmitter %s (0x%08x = %02x), OSD layer 0 on\n",
            REG32(DE_BASE + 0x0C), (hdmi & 1) ? "still in reset" : "running", HDMI_CTRL, hdmi);
}

static void cmd_video(int argc, char **argv)
{
    const struct video_board *board = &video_boards[panel_present() ? 0 : 1];
    int rev = chip_rev(), bad = 0;
    for (int i = 2; i < argc; i++) {
        if (str_eq(argv[i], "rev0") || str_eq(argv[i], "rev1")) {
            rev = argv[i][3] - '0';
            continue;
        }
        const struct video_board *named = 0;
        for (u32 b = 0; b < sizeof(video_boards) / sizeof(video_boards[0]); b++)
            if (str_eq(argv[i], video_boards[b].key))
                named = &video_boards[b];
        if (named)
            board = named;
        else
            bad = 1;
    }
    if (argc < 2 || !str_eq(argv[1], "init") || bad) {
        uprintf("usage: video init [opticum|comsat] [rev0|rev1]   (replay the original firmware's display\n"
                "set-up with the HDMI transmitter's start, as the demo does when it starts; without a name:\n"
                "this board's, %s, for this chip's revision, rev%d)\n", panel_present() ? "opticum" : "comsat",
                chip_rev());
        return;
    }
    video_setup(board, rev);
    /* The set-up's system stores (resets, a clock change) knock a USB device
       out -- on the box the keyboard answered nothing afterwards until a bus
       reset; the originals start their USB only after their display.  So
       the device is set up again here (at start the demo sets USB up after
       its own video_setup). */
    if (usb_connected()) {
        int ok = usb_enumerate_quiet() == 0;
        uprintf("USB device set up again after the display set-up: %s\n", ok ? usb_summary() : usb_error_text());
        update_usb_box();
    }
}

static void cmd_reboot(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    restart("Restarting via original bootloader");
}

/* The original bootloader stays in its shell only when 'c' arrives while it
   starts (about a second; the UART updater sends 'c' twenty times a second).
   Holding the c key works too: once the demo is back, 'ccc' on its empty
   line restarts it again, and the next 'c' reaches the bootloader. */
static void cmd_bootloader(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    uprintf("Hold the c key now (or start maciej_uart.py) to stay in the original bootloader's shell;\n"
            "without 'c' it starts the demo again.\n");
    restart("Restarting into the original bootloader");
}

static void cmd_lsusb(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    usb_lsusb();
    update_usb_box();
}

static void cmd_disks(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    disk_list();
}

/* the arguments from argv[1] on as one string (a name with spaces in it) */
static const char *joined(int argc, char **argv)
{
    static char buf[LINE_MAX];
    int n = 0;
    for (int i = 1; i < argc; i++) {
        if (i > 1 && n < LINE_MAX - 1)
            buf[n++] = ' ';
        for (const char *p = argv[i]; *p && n < LINE_MAX - 1; p++)
            buf[n++] = *p;
    }
    buf[n] = 0;
    return buf;
}

static void cmd_ls(int argc, char **argv)
{
    disk_ls(joined(argc, argv));
}

static void cmd_cat(int argc, char **argv)
{
    if (argc < 2) {
        uprintf("usage: cat [device:]/path\n");
        return;
    }
    disk_cat(joined(argc, argv));
}

static void cmd_sector(int argc, char **argv)
{
    if (argc != 2) {
        uprintf("usage: sector [device:]<sector number>\n");
        return;
    }
    disk_sector(argv[1]);
}

static void cmd_watchdog(int argc, char **argv)
{
    if (argc > 1 && str_eq(argv[1], "test")) {
        if (!dog_running()) {
            uprintf("the watchdog is off ('watchdog on' first)\n");
            return;
        }
        uprintf("Not feeding the watchdog any more: the demo stops here and the box restarts within %u s.\n",
                DOG_SECONDS);
        uart_flush();
        dog_hold();
        for (;;) { }
    }
    if (argc > 1 && str_eq(argv[1], "off")) {
        dog_stop();
        uprintf("watchdog off\n");
        return;
    }
    if (argc > 1 && str_eq(argv[1], "on")) {
        if (!dog_start()) {
            uprintf("the watchdog's counter does not count here: left off\n");
            return;
        }
    } else if (argc > 1) {
        uprintf("usage: watchdog [test|off|on]\n");
        return;
    }
    uprintf("watchdog at 0x%08x: %s\n", DOG_BASE, dog_running() ? "on, reset mode (control 0x64)" : "off");
    uprintf("  counter: %u ticks/s (memory clock / 32, measured against CP0 Count)\n", dog_rate());
    if (dog_running())
        uprintf("  started at 0x%08x, %u s before it overflows; now 0x%08x; fed every 0.1 s\n",
                dog_start_value(), DOG_SECONDS, dog_count());
}


static void run_line(void)
{
    char copy[LINE_MAX];
    char *argv[ARGS_MAX];
    int argc = 0;
    str_copy(copy, line, sizeof(copy));
    for (char *p = copy; *p && argc < ARGS_MAX;) {
        while (*p == ' ' || *p == '\t')
            *p++ = 0;
        if (!*p)
            break;
        argv[argc++] = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
    }
    if (argc == 0)
        return;
    if (history_count == 0 || !str_eq(history[(history_count - 1) % HISTORY], line)) {
        str_copy(history[history_count % HISTORY], line, LINE_MAX);
        history_count++;
    }
    str_copy(last_command, line, sizeof(last_command));
    commands_run++;
    update_uart_box();
    if (argv[0][0] == '/' && argv[0][1])            /* "/restart" as "restart" */
        argv[0]++;
    for (const struct command *c = commands; c->name; c++)
        if (str_eq(c->name, argv[0])) {
            c->run(argc, argv);
            return;
        }
    uprintf("unknown command '%s' -- type 'help'\n", argv[0]);
}

static void recall(int step)
{
    int oldest = history_count > HISTORY ? history_count - HISTORY : 0;
    int pos = history_pos + step;
    if (pos < oldest || pos > history_count)
        return;
    history_pos = pos;
    if (pos == history_count)
        line_len = 0;
    else {
        str_copy(line, history[pos % HISTORY], LINE_MAX);
        line_len = str_len(line);
    }
    show_line();
}

static int typing_on_usb;               /* cli_input is fed by the USB keyboard */

static void cli_input(int c)
{
    line_dirty = 1;
    if (esc_state == 1) {
        esc_state = c == '[' ? 2 : 0;
        return;
    }
    if (esc_state == 2) {
        esc_state = 0;
        if (c == 'A')
            recall(-1);
        else if (c == 'B')
            recall(1);
        return;
    }
    switch (c) {
    case 0x1b:
        esc_state = 1;
        return;
    case '\r':
    case '\n':
        if (c == '\n' && line_len == 0)
            return;                         /* the LF of a CR LF */
        uart_puts("\r\n");
        line[line_len] = 0;
        run_line();
        line_len = 0;
        history_pos = history_count;
        prompt();
        return;
    case 0x08:
    case 0x7f:
        if (line_len) {
            line_len--;
            uart_puts("\b \b");
        }
        return;
    case 0x03:                              /* Ctrl-C */
    case 0x15:                              /* Ctrl-U */
        line_len = 0;
        uart_puts("^C\r\n");
        prompt();
        return;
    }
    if (c < 0x20 || c > 0x7e || line_len >= LINE_MAX - 1)
        return;
    line[line_len++] = (char)c;
    uart_putc((char)c);
    /* the UART updater's boot capture: 'c' sent again and again (on the UART) */
    if (!typing_on_usb && line_len == 3 && line[0] == 'c' && line[1] == 'c' && line[2] == 'c')
        restart("\r\nBootloader capture requested ('ccc'): restarting via original bootloader");
}

/* ------------------------------------------------------------------ */
static volatile u32 bss_probe;
static volatile u32 data_probe = 0x13579bdfu;

void app_main(void)
{
    time_init();
    uart_init();
    if (bss_probe != 0 || data_probe != 0x13579bdfu) {
        uart_puts(APP_BANNER ": runtime init failed\r\n");
        for (;;) { }
    }
    bss_probe = 1;
    uart_puts("\r\n" APP_BANNER "\r\nVersion: " APP_VERSION "\r\n");
    uart_puts("RAM app via original bootloader\r\n");
    if (dog_start())                            /* before anything that could hang */
        uprintf("Watchdog on: a demo stopped for %u s restarts the box\n", DOG_SECONDS);
    else
        uprintf("Watchdog left off: its counter does not count here\n");
    gfx_init();
    if (!panel_init())
        uart_puts("No TM1650 front panel: GPIO 31 / 9 are read as two buttons (Comsat TE 1050 HD type board)\r\n");
    ir_init();
    draw_screen();
    uprintf("Demo: command line, TV picture, front panel, remote control, USB port. Type 'help'.\n");
    /* the picture on the TV: the bootloader never switches the video output
       on, so this board's display set-up runs now -- before USB, as in the
       originals, whose set-up's system stores would knock a USB device out */
    video_setup(&video_boards[panel_present() ? 0 : 1], chip_rev());
    if (usb_connected()) {                      /* plugged in before the demo started (a keyboard) */
        uprintf("[usb] device connected\n");
        usb_enumerate();
        update_usb_box();
    }
    history_pos = 0;
    prompt();

    u64 last_poll = now_ms(), last_second = last_poll, last_line_drawn = 0;
    struct ir_event ev;
    for (;;) {
        int c = uart_getc();
        if (c >= 0)
            cli_input(c);
        usb_int_poll();                         /* the keyboard's interrupt endpoint (endpoint B) */
        const char *said = kbd_poll();          /* a USB keyboard's keys: as if typed on the UART */
        if (said) {
            event_begin();
            uprintf("[usb] %s\n", said);
            if (kbd_lost() && usb_connected()) {    /* it stopped answering: set it up again */
                int ok = usb_enumerate_quiet() == 0;
                uprintf("[usb] %s\n", ok ? (kbd_active() ? "keyboard set up again" : "set up again: no keyboard now")
                                         : usb_error_text());
                update_usb_box();
            }
            show_line();
        }
        typing_on_usb = 1;
        while ((c = kbd_getc()) >= 0)
            cli_input(c);
        typing_on_usb = 0;
        said = mouse_poll();                    /* a USB mouse: the pointer, its buttons */
        if (said) {
            event_begin();
            uprintf("[usb] %s\n", said);
            show_line();
        }
        if (ir_poll(&ev)) {
            event_begin();
            on_ir(&ev);
            show_line();
        }
        gfx_cursor_refresh();                   /* (drawing under the mouse pointer took it away) */
        u64 now = now_ms();
        if (line_dirty && now - last_line_drawn >= 50) {
            last_line_drawn = now;
            update_line_box();
        }
        if (now - last_poll >= 100) {
            last_poll = now;
            if (poll_panel())
                show_line();
            if (usb_connected() != usb_shown) {
                int connected = usb_connected();
                event_begin();
                uprintf("[usb] %s\n", connected ? "device connected" : "device removed");
                if (connected)
                    usb_enumerate();            /* its name on the screen; a keyboard starts typing */
                else
                    usb_removed();
                update_usb_box();
                show_line();
            } else if (usb_shown && usb_hub_poll(event_begin)) {    /* a hub's ports, one each time */
                update_usb_box();
                show_line();
            }
        }
        if (now - last_second >= 1000) {
            last_second = now;
            update_uptime();
        }
    }
}
