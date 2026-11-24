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
#include "rf.h"
#include "snd.h"
#include "av.h"

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
    if (ntp_clock_text(buf, sizeof(buf)))       /* (once NTP set the clock: net.c) */
        box_line(&BOX_SYSTEM, 4, "Time", buf, 2, C_VALUE);
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
/* a device on the port that does not answer (the main loop, usb_try_again): 0 nothing due, 1..USB_RETRIES
   the tries made, -1 given up ('usb' or the port's next change start again); when the next is due */
static int usb_retry;
static u64 usb_retry_next;

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
    explorer_hide();                    /* (the explorer drew on this picture) */
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
#define LINE_MAX 160                    /* (a test's button script for a game needs the room) */
#define HISTORY 64
#define ARGS_MAX 48                     /* (as many words as a line can hold) */

static char line[LINE_MAX];
static int line_len;
/* the line as typed -- quotes and backslashes kept -- up to a '>' that sends
   the output to a file, from its first word (raw_line), and where the text
   after the command word begins in it (raw_rest): a verbatim command ('at',
   see verbatim()) gets that as its one argument -- AT+CPIN="...",
   AT+CMGS="..." need their quotes */
static char raw_line[LINE_MAX];
static const char *raw_rest;
/* the history: the commands entered, oldest first (a command entered again moves to the end; one typed with a
   space in front is not kept), 'history' numbers them from 1.  history_pos: the one shown while Up / Down
   look through them (history_n: the line being typed, kept in pending -- its text is also what Up / Down
   look for: the commands that start with it) */
static char history[HISTORY][LINE_MAX];
static int history_n, history_pos;
static char pending[LINE_MAX];
static int line_cur;                    /* the cursor in the line (line_len: at its end) */
static char killed[LINE_MAX];           /* what Ctrl-K / Ctrl-U / Ctrl-W took out: Ctrl-Y puts it back */
static int esc_state, esc_num;
static int tabs;                        /* Tabs pressed in a row (the second lists what completes the word) */

/* "m3801> ", with the current directory once 'cd' chose one: "m3801 3:/docs> " */
static void prompt(void)
{
    const char *cwd = disk_cwd();
    if (!cwd[0]) {
        uart_puts("m3801> ");
        return;
    }
    uart_puts("m3801 ");
    uart_puts(cwd);
    uart_puts("> ");
}

static void show_line(void)
{
    /* clear the terminal line and print the prompt and the buffer again, the cursor back where it is */
    uart_puts("\r\x1b[K");
    prompt();
    for (int i = 0; i < line_len; i++)
        uart_putc(line[i]);
    if (line_cur < line_len)
        uprintf("\x1b[%dD", line_len - line_cur);
}

/* a command entered: to the history's end (the same command earlier taken out; the oldest dropped when it is
   full; one typed with a space first not kept) */
static void history_add(const char *l)
{
    if (!l[0] || l[0] == ' ')
        return;
    int out = 0;
    for (int i = 0; i < history_n; i++)
        if (!str_eq(history[i], l)) {
            if (out != i)
                str_copy(history[out], history[i], LINE_MAX);
            out++;
        }
    history_n = out;
    if (history_n == HISTORY) {
        for (int i = 1; i < HISTORY; i++)
            str_copy(history[i - 1], history[i], LINE_MAX);
        history_n--;
    }
    str_copy(history[history_n++], l, LINE_MAX);
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
static void cmd_sum(int argc, char **argv);
static void cmd_sector(int argc, char **argv);
static void cmd_watchdog(int argc, char **argv);
static void cmd_clear(int argc, char **argv);
static void cmd_reboot(int argc, char **argv);
static void cmd_bootloader(int argc, char **argv);
static void cmd_prof(int argc, char **argv);
static void cmd_video(int argc, char **argv);
static void cmd_testscreen(int argc, char **argv);
static void cmd_console(int argc, char **argv);
static void cmd_explorer(int argc, char **argv);
static void cmd_nes(int argc, char **argv);
static void cmd_gb(int argc, char **argv);
static void cmd_sms(int argc, char **argv);
static void cmd_gg(int argc, char **argv);
static void cmd_sg(int argc, char **argv);
static void cmd_zx(int argc, char **argv);
static void cmd_a26(int argc, char **argv);
static void cmd_c64(int argc, char **argv);
static void cmd_amiga(int argc, char **argv);
static void cmd_dos(int argc, char **argv);
static void cmd_megadrive(int argc, char **argv);
static void cmd_pce(int argc, char **argv);
static void cmd_coleco(int argc, char **argv);
static void cmd_msx(int argc, char **argv);
static void cmd_msx2(int argc, char **argv);
static void cmd_ws(int argc, char **argv);
static void cmd_snes(int argc, char **argv);
static void cmd_neogeo(int argc, char **argv);
static void cmd_gba(int argc, char **argv);
static void cmd_a78(int argc, char **argv);
static void cmd_lynx(int argc, char **argv);
static void cmd_vectrex(int argc, char **argv);
static void cmd_fds(int argc, char **argv);
static void cmd_ngp(int argc, char **argv);
static void cmd_odyssey2(int argc, char **argv);
static void cmd_intv(int argc, char **argv);
static void cmd_psx(int argc, char **argv);
static void cmd_cps(int argc, char **argv);
static void cmd_atarist(int argc, char **argv);
static void cmd_sys16(int argc, char **argv);
static void cmd_atari8(int argc, char **argv);
static void cmd_a5200(int argc, char **argv);
static void cmd_megaduck(int argc, char **argv);
static void cmd_sv(int argc, char **argv);
static void cmd_chip8(int argc, char **argv);
static void cmd_channelf(int argc, char **argv);
static void cmd_pokemini(int argc, char **argv);
static void cmd_cpc(int argc, char **argv);
static void cmd_vic20(int argc, char **argv);
static void cmd_apple2(int argc, char **argv);
static void cmd_coco(int argc, char **argv);
static void cmd_dragon(int argc, char **argv);
static void cmd_cv(int argc, char **argv);
static void cmd_m5(int argc, char **argv);
static void cmd_pv1000(int argc, char **argv);
static void cmd_astro(int argc, char **argv);
static void cmd_arcadia(int argc, char **argv);
static void cmd_vc4000(int argc, char **argv);
static void cmd_studio2(int argc, char **argv);
static void cmd_scv(int argc, char **argv);
static void cmd_vb(int argc, char **argv);
static void cmd_sgx(int argc, char **argv);
static void cmd_pcecd(int argc, char **argv);
static void cmd_segacd(int argc, char **argv);
static void cmd_bbc(int argc, char **argv);
static void cmd_ti99(int argc, char **argv);
static void cmd_oric(int argc, char **argv);
static void cmd_plus4(int argc, char **argv);
static void cmd_zx81(int argc, char **argv);
static void cmd_pc88(int argc, char **argv);
static void cmd_mz700(int argc, char **argv);
static void cmd_x1(int argc, char **argv);
static void cmd_s32x(int argc, char **argv);
static void cmd_cd32(int argc, char **argv);
static void cmd_cps2(int argc, char **argv);
static void cmd_arcade(int argc, char **argv);
static void cmd_view(int argc, char **argv);
static void cmd_rf(int argc, char **argv);
static void cmd_history(int argc, char **argv);
static void cmd_cd(int argc, char **argv);
static void cmd_pwd(int argc, char **argv);
static void cmd_mkdir(int argc, char **argv);
static void cmd_rmdir(int argc, char **argv);
static void cmd_rm(int argc, char **argv);
static void cmd_touch(int argc, char **argv);
static void cmd_head(int argc, char **argv);
static void cmd_tail(int argc, char **argv);
static void cmd_df(int argc, char **argv);
static void cmd_ntfs(int argc, char **argv);
static void cmd_cp(int argc, char **argv);
static void cmd_mv(int argc, char **argv);
static void cmd_tty(int argc, char **argv);
static void cmd_stty(int argc, char **argv);
static void cmd_ifconfig(int argc, char **argv);
static void cmd_dhcp(int argc, char **argv);
static void cmd_arp(int argc, char **argv);
static void cmd_cu(int argc, char **argv);
static void cmd_at(int argc, char **argv);

/* the main loop's passes since 'loop' last looked: how many, how many slow, and each part's slowest (a pass
   that takes long holds the mouse's and the keyboard's reports back) */
#define LOOP_PARTS 5
static const char *const loop_part_names[LOOP_PARTS] = {
    "UART + endpoint B + keyboard", "Ethernet", "mouse", "IR + TV console + pointer",
    "timed jobs (command line box, hubs, panel, uptime)"};
static u32 loop_passes, loop_slow[3], loop_max_us, loop_part_max_us[LOOP_PARTS];
static u64 loop_since;
static int loop_reset;                  /* 'loop' looked: counted afresh after this pass (its printing not counted) */

static u32 us_since(u64 *t)             /* microseconds since *t (14 s at most), *t moved on to now */
{
    u64 now = now_ticks();
    u32 us = (u32)(now - *t) / (ticks_per_ms() / 1000);
    *t = now;
    return us;
}

static void loop_part(int part, u64 *t)
{
    u32 us = us_since(t);
    if (us > loop_part_max_us[part])
        loop_part_max_us[part] = us;
}

static void loop_pass(u64 start)
{
    u32 us = us_since(&start);
    if (loop_reset) {
        loop_reset = 0;
        loop_passes = loop_max_us = 0;
        for (int i = 0; i < 3; i++)
            loop_slow[i] = 0;
        for (int i = 0; i < LOOP_PARTS; i++)
            loop_part_max_us[i] = 0;
        loop_since = now_ms();
        return;
    }
    loop_passes++;
    loop_slow[0] += us > 5000;
    loop_slow[1] += us > 20000;
    loop_slow[2] += us > 100000;
    if (us > loop_max_us)
        loop_max_us = us;
}

static void cmd_loop(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    u32 ms = (u32)(now_ms() - loop_since);
    uprintf("main loop: %u passes in %u.%u s (%u a second), the slowest %u.%u ms; %u over 5 ms, %u over 20 ms, %u "
            "over 100 ms\n", loop_passes, ms / 1000, ms % 1000 / 100, ms >= 1000 ? loop_passes / (ms / 1000) : 0,
            loop_max_us / 1000, loop_max_us % 1000 / 100, loop_slow[0], loop_slow[1], loop_slow[2]);
    for (int i = 0; i < LOOP_PARTS; i++)
        uprintf("  %s: the slowest %u.%u ms\n", loop_part_names[i], loop_part_max_us[i] / 1000,
                loop_part_max_us[i] % 1000 / 100);
    loop_reset = 1;
}

static const struct command commands[] = {
    {"help", "[command]", "this list", cmd_help},
    {"version", "", "banner and version", cmd_version},
    {"ping", "[-c n] [host]", "answers pong; with a host: ICMP echo over Ethernet until Ctrl-C (or n)", cmd_ping},
    {"info", "", "chip, clock, memory layout, uptime", cmd_info},
    {"uptime", "", "time since this application started", cmd_uptime},
    {"loop", "", "the main loop since the last look: its passes, the slowest, which part took the time", cmd_loop},
    {"echo", "<words>", "prints its arguments", cmd_echo},
    {"md", "<addr> [len]", "dump memory (RAM, flash window, registers)", cmd_md},
    {"mr", "<addr>", "read a 32-bit word", cmd_mr},
    {"mw", "<addr> <value>", "write a 32-bit word (RAM, registers)", cmd_mw},
    {"screen", "[subcommand]", "the test screen's picture: demo, bars, clear [rrggbb], text <x> <y> <words>, "
               "rect <x> <y> <w> <h> <rrggbb> (each shows it), on, off", cmd_screen},
    {"testscreen", "", "the demo's test screen on the TV (its boxes, the colour bars); a key on the USB "
                   "keyboard (it types too) or 'console' brings the console back", cmd_testscreen},
    {"console", "", "the console on the TV again", cmd_console},
    {"explorer", "[n:][path]", "a file explorer on the TV, in the current directory (cd follows it, it follows cd; "
     "with a path: cd there first): USB keyboard Up/Down/PgUp/PgDn/Home/End, Enter opens (a picture: the viewer, "
     "a game's file -- .nes, .gb, .gbc, .sms, .gg, .sg, .sc, .sna, .z80, .tap, .tzx, .trd, .scl, .a26, .prg, .t64, .d64, .crt, "
     ".adf, .st, .msa, .tos, .atr, .xex, .obx, .car, .a52, .exe, .com, .md, .gen, .smd, a Mega Drive .bin, .32x, .pce, .sgx, .col, .mx1, .mx2, .dsk, .do, .po, .nib, .ccc, .cas, .cv, .m5, .pv, .ast, .a2k, .vc4, .st2, .scv, .vb, .vboy, .ssd, .dsd, .uef, .rpk, .p, .81, .d88, .2d, .mzt, .mzf, .cpr, .a0, .20, .60, .ws, .wsc, .sfc, .smc, .neo, .gba, .a78, .lnx, .lyx, .vec, .fds, .ngp, .ngc, .o2, .int, .ch8, .sc8, .xo8, .chf, .min, .cue, .iso, .psx, .cps, .cps1, .cps2, .s16, any of them in a .zip or a .gz (.adz): the game), "
     "Backspace goes up, "
     "'/' or Tab types a path, Esc: the console again; the mouse clicks, double-clicks, scrolls; on FAT: F2 "
     "renames, F7 makes a directory, Delete / F8 deletes (y), F5 / F6 mark a file to copy / move and Insert "
     "pastes it here", cmd_explorer},
    {"panel", "[text|bright <n>]", "front panel digits", cmd_panel},
    {"keys", "", "front panel key state", cmd_keys},
    {"ir", "[raw on|off]", "remote control receiver", cmd_ir},
    {"usb", "[reset|init|kbd|mouse|reg|ctl]", "USB port and the descriptors of its device (through a hub: of "
     "every device behind it); reset: a bus reset, init: the controller set up again, kbd [report|interrupt|raw "
     "on|off]: the keyboard, mouse: the mouse and its pointer, reg <off> [byte]: a register, ctl <type> <req> "
     "<value> <index> <len> [device]: a control request", cmd_usb},
    {"lsusb", "", "the USB devices, one line each", cmd_lsusb},
    {"disks", "", "USB disks (sticks, card readers): their size, partitions and file systems", cmd_disks},
    {"ls", "[n:][path]", "a directory on a USB disk's FAT or NTFS volume (n: the disk's device number, as "
     "lsusb lists it; n.p: its partition p; a path without '/' starts in the current directory)", cmd_ls},
    {"dir", "[n:][path]", "the same as ls", cmd_ls},
    {"cd", "[n:][path]", "the current directory ('..' one up, '/' the volume's root; alone: back to none)",
     cmd_cd},
    {"pwd", "", "the current directory", cmd_pwd},
    {"cat", "[n:]path", "a text file on a USB disk (Ctrl-C stops it)", cmd_cat},
    {"nes", "[-f frames] [-k script] <file>", "play a NES / Famicom cartridge file (.nes: NROM..MMC5 plus Konami VRC6, "
     "VRC7 FM, Namco 163 wavetable & Sunsoft 5B expansion audio) on the TV: arrows or W A S D, "
     "X = A, Z = B, Enter = Start, Tab = Select; Ctrl-C or Esc ends (-f: that many frames as fast as they go, "
     "then the picture's CRC-32; -k: a test's buttons, frame:hex,... or @path: read from that file).  Every "
     "player also takes its game in a "
     ".zip (the largest file in it that is no text or picture) or a .gz", cmd_nes},
    {"gb", "[-f frames] [-k script] <file>", "play a Game Boy cartridge file (.gb, .gbc) on the TV -- a Game Boy "
     "Color game in its colours, an older one in four shades: the keys and the options of nes", cmd_gb},
    {"sms", "[-f frames] [-k script] <file>", "play a Sega Master System cartridge file (.sms) on the TV: X = "
     "button 2, Z = button 1, Enter = Pause; the other keys and the options of nes", cmd_sms},
    {"gg", "[-f frames] [-k script] <file>", "play a Sega Game Gear cartridge file (.gg) on the TV: X = button 2, "
     "Z = button 1, Enter = Start; the options of nes", cmd_gg},
    {"sg", "[-f frames] [-k script] <file>", "play a Sega SG-1000 / SC-3000 cartridge file (.sg, .sc) on the TV: "
     "X = button 2, Z = button 1, Enter = Pause; the other keys and the options of nes", cmd_sg},
    {"zx", "[-f frames] [-k script] [file]", "a ZX Spectrum 48K / 128K + BetaDisk 128 on the TV: a snapshot (.sna, "
     ".z80), a tape (.tap, .tzx) or a TR-DOS floppy (.trd, .scl) with 48 kHz beeper + AY-3-8912 sound; no file: BASIC. "
     "Optional 48.rom, 128.rom and trdos.rom in zx/ or beside the program (else built-in clean-room loader). The USB "
     "keyboard is the Spectrum's (Shift = CAPS SHIFT, Ctrl / Alt = SYMBOL SHIFT, Backspace = DELETE), the arrows also a "
     "Kempston joystick (fire: the remote's OK); typed on the UART / telnet, characters are typed on it; Esc ends", cmd_zx},
    {"a26", "[-f frames] [-k script] <file>", "play an Atari 2600 cartridge file (.a26, .bin: 2K, 4K, F8, F6, F4, "
     "their Superchip RAM, FE, E0, 3F, E7, FA) on the TV: arrows or W A S D, X or Z = fire, Enter = the "
     "console's Reset, Tab = Select; the options of nes", cmd_a26},
    {"c64", "[-f frames] [-k script] [file]", "a Commodore 64 (PAL) on the TV: a program (.prg, .t64) or a "
     "disk (.d64), loaded and RUN by itself (LOAD from the disk works later too), or a cartridge (.crt: normal, "
     "Ocean, Magic Desk, EasyFlash, System 3, Dinamic, Fun Play, Super Games, RGCD, Simons' BASIC, Final "
     "Cartridge III), started in it; no file: BASIC.  Its ROMs are "
     "kernal.rom, basic.rom and chargen.rom beside the program, in c64/ or at the top of its disk.  The USB "
     "keyboard is the C64's (Tab = RUN/STOP, PageUp = RESTORE, Alt = C=), its arrows joystick 2 (fire: right "
     "Ctrl or the remote's OK; F9 swaps the ports); typed on the UART / telnet, characters are typed on it; "
     "Esc ends", cmd_c64},
    {"amiga", "[-f frames] [-k script] [file.adf]", "an Amiga 500 (PAL) on the TV, a floppy image (.adf) in its "
     "drive (no file: none).  Its Kickstart is kick.rom (256 or 512 KB), or AROS's free aros-rom.bin with "
     "aros-ext.bin, beside the disk, in amiga/ or at the top of its disk.  The USB keyboard is the Amiga's, its "
     "arrows the joystick (fire: right Ctrl or the remote's OK), Page Up / Down or the remote's 0 the mouse "
     "button; typed on the UART / telnet, characters are typed on it; Esc ends", cmd_amiga},
    {"dos", "[-f frames] [-k script] <file.exe>", "a DOS PC (a 286 AT with a VGA) on the TV running a DOS "
     "program (.exe, .com): the BIOS and DOS built in, its own file readable, no sound.  The USB keyboard is "
     "the PC's (Esc ends the player); the remote: arrows, OK = Up, 0 = Space, MENU = Enter, INFO = Esc; typed "
     "on the UART / telnet, characters are typed on it", cmd_dos},
    {"megadrive", "[-r j|u|e] [-f frames] [-k script] <file>", "play a Sega Mega Drive / Genesis cartridge file (.md, "
     ".gen, .bin; .smd and copier headers taken apart) on the TV with its sound, at its console's rate (-r: a "
     "Japanese, American or European one; else the header's region): X = B, Z = A, Tab / Space = C, Enter = Start, "
     "the remote's OK / 0 / INFO / MENU too; cartridge RAM kept in a .sav file; the options of nes", cmd_megadrive},
    {"pce", "[-f frames] [-k script] <file>", "play a PC Engine / TurboGrafx-16 HuCard (.pce) on the TV with its "
     "6-channel PSG sound: arrows or W A S D, X = I, Z = II, Enter = Run, Tab = Select; 2 KB backup RAM kept in a "
     ".sav file; the options of nes", cmd_pce},
    {"coleco", "[-f frames] [-k script] <file>", "play a ColecoVision cartridge (.col, .rom; MegaCart and Super Game "
     "Module too) on the TV with its SN76489 sound (coleco.rom in col/ if present, else built-in BIOS): X = fire 1, "
     "Z = fire 2, Enter = keypad 1, Tab = *, C = #, 0..9 on USB keyboard; the options of nes", cmd_coleco},
    {"msx", "[-f frames] [-k script] <file>", "play an MSX1 ROM cartridge (.rom, .mx1: plain, Konami, Konami SCC, "
     "ASCII8, ASCII16) on the TV with AY-3-8910 + SCC sound (msx.rom or cbios_main_msx1.rom in msx/ if present, "
     "else built-in BIOS): arrows or USB keyboard, X = Space / trigger A, Z = trigger B; the options of nes", cmd_msx},
    {"msx2", "[-f frames] [-k script] <file>", "play an MSX2 cartridge or floppy disk (.mx2, .dsk, .rom: V9938 SCREEN "
     "0..8, 128 KB VRAM, hardware blitter, 256 KB Mapper, RP5C01 RTC) on the TV with AY-3-8910 + SCC + YM2413 FM sound "
     "(msx2.rom/cbios_main_msx2.rom and msx2ext.rom/cbios_sub.rom in msx2/ if present, else built-in MSX2 BIOS): "
     "arrows or USB keyboard, X = Space / trigger A, Z = trigger B; the options of nes", cmd_msx2},
    {"ws", "[-f frames] [-k script] <file>", "play a Bandai WonderSwan or WonderSwan Color cartridge (.ws, .wsc; "
     "horizontal and rotated vertical games) on the TV with its 4-channel sound: arrows or W A S D, X = A, Z = B, "
     "Enter = Start, C/V/Q/E = Y1..Y4; cartridge SRAM / EEPROM kept in a .sav file; the options of nes", cmd_ws},
    {"snes", "[-f frames] [-k script] <file>", "play a Super Nintendo / Super Famicom cartridge (.sfc, .smc: LoROM, "
     "HiROM, ExHiROM, Modes 0-7) on the TV with SPC700 BRR sound: arrows or W A S D, X = A, Z = B, C = X, V = Y, "
     "Q = L, E = R, Enter = Start, Tab = Select; SRAM kept in a .sav file; the options of nes", cmd_snes},
    {"neogeo", "[-f frames] [-k script] <file>", "play an SNK Neo Geo AES / MVS cartridge (.neo) on the TV with its "
     "Z80 + YM2610 FM/SSG/ADPCM sound (uni-bios.rom or neogeo.rom in neogeo/ if present, else built-in BIOS): "
     "arrows or W A S D, X = A, Z = B, C = C, V = D, Enter = Start, Tab = Select; backup RAM kept in a .sav file; "
     "the options of nes", cmd_neogeo},
    {"gba", "[-f frames] [-k script] <file>", "play a Game Boy Advance cartridge (.gba; inside a .zip or .gz too) on "
     "the TV with DirectSound + PSG sound (gba_bios.bin in gba/ if present, else built-in BIOS): arrows or W A S D, "
     "X = A, Z = B, Q = L, E = R, Enter = Start, Tab = Select; SRAM / Flash / EEPROM kept in a .sav file; the options "
     "of nes", cmd_gba},
    {"a78", "[-f frames] [-k script] <file>", "play an Atari 7800 ProSystem cartridge (.a78: Linear, SuperGame, "
     "Activision, Absolute) on the TV with TIA + POKEY sound: arrows or W A S D, X = fire 1, Z = fire 2, Enter = "
     "Pause, Tab = Select, C = Reset; High-Score SRAM kept in a .sav file; the options of nes", cmd_a78},
    {"lynx", "[-f frames] [-k script] <file>", "play an Atari Lynx cartridge (.lnx, .lyx, BLL .o; horizontal and "
     "rotated vertical games) on the TV with 4-channel Mikey sound (lynxboot.img in lynx/ if present, else built-in "
     "loader): arrows or W A S D, X = A, Z = B, Q = Option 1, Tab = Option 2, Enter = Pause; the options of nes",
     cmd_lynx},
    {"vectrex", "[-f frames] [-k script] [file]", "a GCE Vectrex vector console on the TV: a cartridge (.vec), or no "
     "file for built-in Mine Storm (with vectrex.rom in vec/) / Vector Storm (with the built-in BIOS), with AY-3-8912 "
     "sound: arrows or W A S D, X = button 4, Z = button 3, Tab = button 2, Enter = button 1; the options of nes",
     cmd_vectrex},
    {"fds", "[-f frames] [-k script] <file>", "play a Famicom Disk System disk image (.fds: 1-8 sides) on the TV with "
     "its RP2C33 wavetable + FM sound (disksys.rom in fds/ if present, else built-in BIOS): arrows or W A S D, X = A, "
     "Z = B, Enter = Start, Tab = Select, Q / F6 = flip disk side; disk writes kept in a .sav file; the options of nes",
     cmd_fds},
    {"ngp", "[-f frames] [-k script] <file>", "play a Neo Geo Pocket or Neo Geo Pocket Color cartridge (.ngp, .ngc) on "
     "the TV with its Z80 + T6W28 + DAC sound (ngp_bios.rom in ngp/ if present, else built-in BIOS): arrows or W A S D, "
     "X = A, Z = B, Enter or Tab = Option; Flash saves kept in a .sav file; the options of nes", cmd_ngp},
    {"odyssey2", "[-f frames] [-k script] <file>", "play a Magnavox Odyssey2 / Philips Videopac G7000 cartridge (.o2, "
     ".bin: 2-16 KB) on the TV with its Intel 8244 sound (o2rom.bin in o2/ if present, else built-in BIOS): arrows or "
     "W A S D, X = Action, Z = Space, Enter = 1, Tab = 2, 0..9 on USB keyboard; the options of nes", cmd_odyssey2},
    {"intv", "[-f frames] [-k script] <file>", "play a Mattel Intellivision cartridge (.int, Intellicart .rom, .bin) on "
     "the TV with its AY-3-8914 sound (exec.bin and grom.bin in intv/ if present, else built-in EXEC and GROM): arrows "
     "or W A S D, X/Z/C = side buttons, Enter = Enter / 1, Tab = Clear, 0..9 on USB keyboard; the options of nes",
     cmd_intv},
    {"psx", "[-r j|u|e] [-f frames] [-k script] <file>", "play a Sony PlayStation 1 program or disc (.exe, .cue, .iso, .bin) on the "
     "TV with its R3000A + GTE 3D geometry, MDEC video and 24-voice SPU XA-ADPCM sound (scph1001.bin in psx/ if present, "
     "else built-in BIOS; -r u/j forces 60 Hz NTSC, R toggles 50/60 Hz): arrows or W A S D, X = Circle, Z = Cross, C = Triangle, V = Square, Q = L1, E = R1, Enter = "
     "Start, Tab = Select; 128 KB Memory Card kept in a .sav file; the options of nes", cmd_psx},
    {"cps", "[-f frames] [-k script] <file>", "play a Capcom CPS-1 / CPS-1.5 / CPS-2 arcade game (.cps, .cps1, .cps2, or "
     "MAME .zip romset) on the TV with its 68000 + Z80 and YM2151 + OKIM6295 / 16-voice QSound DSP sound: arrows or "
     "W A S D, X/Z/C = LP/MP/HP, V/Q/E = LK/MK/HK, Enter = Start, Tab = Coin; 93C46 EEPROM kept in a .sav file; the "
     "options of nes", cmd_cps},
    {"atarist", "[-f frames] [-k script] [file]", "an Atari 520ST / 1040STFM on the TV: a floppy image (.st, .msa) or "
     "GEMDOS program (.prg, .tos), or no file for desktop, with 8 MHz 68000, Shifter + STE Blitter, MFP, IKBD, WD1772 "
     "FDC and YM2149F sound (tos.img / etos256uk.img / etos192uk.img in atarist/ if present, else built-in TOS): "
     "the USB keyboard is the Atari ST's, arrows = joystick 1 (fire: right Ctrl, remote OK); Esc ends", cmd_atarist},
    {"sys16", "[-f frames] [-k script] <file>", "play a Sega System 16A / 16B / OutRun-Road arcade game (.s16 or MAME "
     ".zip romset) on the TV with its 10/12.5 MHz 68000 + Z80, 315-5195 mapper, 315-5197 tilemaps + zoomed sprites + "
     "road generator, and YM2151 + uPD7759 + Sega 16-ch PCM sound: arrows or W A S D, X/Z/C = buttons 1..3, Enter = "
     "Start, Tab = Coin; 16 KB NVRAM kept in a .sav file; the options of nes", cmd_sys16},
    {"atari8", "[-f frames] [-k script] [file]", "an Atari 800XL / 130XE (128 KB) on the TV: a floppy image (.atr, "
     "writes kept in .sav), binary program (.xex, .obx, .com) or cartridge (.car, .rom), or no file for 8K BASIC, with "
     "ANTIC + GTIA + POKEY 48 kHz sound (built-in AltirraOS XL + BASIC, or atarixl.rom / ataribas.rom in atari8/): "
     "the USB keyboard is the Atari's (F1/F2 = START, F3 = SELECT, F4 = OPTION), arrows = joystick 1 (fire: right Ctrl, "
     "remote OK); Esc ends", cmd_atari8},
    {"a5200", "[-f frames] [-k script] <file>", "play an Atari 5200 SuperSystem cartridge (.a52, .car, .bin: 4K..40K) on "
     "the TV with its ANTIC + GTIA + POKEY 48 kHz sound (5200.rom in a5200/ if present, else built-in Altirra 5200 OS): "
     "arrows or W A S D (analog stick), X = Bottom Fire, Z = Top Fire, Enter = Start, C = Pause, Tab = Reset, 0..9 on "
     "USB keyboard; the options of nes", cmd_a5200},
    {"megaduck", "[-f frames] [-k script] <file>", "play a Mega Duck / Cougar Boy cartridge (.duck, .md1, .md2, .bin) on "
     "the TV (160 x 144 five times as large, 59.7 frames a second; flat and $0001 / $B000 banked cartridges) with 48 kHz "
     "4-channel sound and SRAM kept in a .sav file: the keys and the options of nes", cmd_megaduck},
    {"sv", "[-f frames] [-k script] <file>", "play a Watara Supervision cartridge (.sv: 16 KB..512 KB Magnum) on the TV "
     "(160 x 160 four times as large, 61 frames a second) with its 4 MHz 65SC02 and 4-channel 48 kHz sound (2 pulse + "
     "ADPCM DMA + LFSR noise): the keys and the options of nes", cmd_sv},
    {"chip8", "[-f frames] [-k script] <file>", "play a CHIP-8, SUPER-CHIP 1.1 or XO-CHIP program (.ch8, .sc8, .xo8) on "
     "the TV (128 x 64 ten times as large: 1280 x 640, 4-plane 16 colours, 60 frames a second) with 48 kHz buzzer & "
     "XO-CHIP 128-bit pattern sound and RPL flags in .sav: arrows/WASD/X/Z or 1234/QWER/ASDF/ZXCV hex pad", cmd_chip8},
    {"channelf", "[-f frames] [-k script] <file>", "play a Fairchild Channel F / VES cartridge (.chf, .bin, .rom) on the "
     "TV (102 x 58 ten times as large: 1020 x 580, 60 frames a second; Fairchild F8 CPU, F2102 + Schach SRAM, built-in HLE "
     "PSU or sl31253.bin + sl31254.bin in channelf/) with 3-tone 48 kHz sound: X = Push, Z = Pull, Q/E = Twist, 1..4 = "
     "TIME/MODE/HOLD/START", cmd_channelf},
    {"pokemini", "[-f frames] [-k script] <file>", "play a Nintendo Pokemon Mini cartridge (.min) on the TV (96 x 64 ten "
     "times as large: 960 x 640, 72 frames a second; 4 MHz Seiko S1C88, PRC tile/sprite engine, built-in FreeBIOS or "
     "bios.min in pokemini/) with 48 kHz piezo PWM sound and 8 KB EEPROM (.sav): X = A, Z = B, Enter/C = C, Q/Space = "
     "Shake, Tab/P = Power", cmd_pokemini},
    {"cpc", "[-f frames] [-k script] [file]", "an Amstrad CPC 464 / 6128 + GX4000 on the TV (384 x 240 x3 in Mode 0/1, "
     "640 x 200 in Mode 2, 50 frames a second; 4 MHz Z80, UM6845R CRTC, 40010 Gate Array, 128 KB RAM, uPD765 FDC with "
     ".sav writeback, AY-3-8912 48 kHz sound; built-in OS + Locomotive BASIC 1.1 + AMSDOS): .sna, .dsk, .cpr, .bin, or "
     "no file for BASIC; USB keyboard + joystick 0; Esc ends", cmd_cpc},
    {"vic20", "[-f frames] [-k script] [file]", "a Commodore VIC-20 (PAL) on the TV (224 x 240 three times as large, 50 "
     "frames a second; MOS 6502, MOS 6561 VIC-I video + 4-channel 48 kHz sound, dual 6522 VIAs, automatic unexpanded / "
     "+3K / +24K RAM expansion, built-in KERNAL + BASIC V2 + chargen or in vic20/): .prg, .crt, .a0, .20, .60, .d64, or "
     "no file for BASIC; USB keyboard + joystick; Esc ends", cmd_vic20},
    {"apple2", "[-f frames] [-k script] [file]", "an Apple IIe Enhanced (128 KB) on the TV (280 x 192 x3 or 560 x 192 "
     "80-col / Double Hi-Res, 59.92 frames a second; WDC 65C02, NTSC artifact Hi-Res, Disk II GCR .sav writeback, 48 kHz "
     "$C030 speaker + Mockingboard AY-3-8910, embedded Apple IIe + Disk II ROMs): .dsk, .do, .po, .nib, .bin, or no file "
     "for Applesoft BASIC; USB keyboard + joystick; Esc ends", cmd_apple2},
    {"coco", "[-f frames] [-k script] [file]", "a TRS-80 Color Computer 64K (NTSC 60 Hz) on the TV (320 x 240 x3 with "
     "border; Motorola MC6809, SAM MC6883, dual MC6821 PIAs, MC6847 VDG + NTSC RG6 artifact colours, 48 kHz 6-bit DAC + "
     "1-bit sound, built-in Color BASIC exec or bas13.rom/extbas11.rom in coco/): .ccc, .rom, .bin, .cas, or no file for "
     "BASIC; USB keyboard + joystick; Esc ends", cmd_coco},
    {"dragon", "[-f frames] [-k script] [file]", "a Dragon 32 / 64 (PAL 50 Hz) on the TV (320 x 240 x3 with border; "
     "Motorola MC6809, SAM, dual PIAs with Dragon keyboard matrix, MC6847 VDG, 48 kHz 6-bit DAC + 1-bit sound, built-in "
     "BASIC exec or d32.rom in dragon/): .ccc, .rom, .bin, .cas, or no file for BASIC; Esc ends", cmd_dragon},
    {"cv", "[-f frames] [-k script] <file>", "play a VTech CreatiVision / Dick Smith Wizzard cartridge (.cv, .rom, .bin: "
     "4K..32K) on the TV (256 x 192 three times as large, 50 Hz PAL; 2 MHz 6502, MC6821 PIA, TMS9929A VDP, SN76489A 48 kHz "
     "sound, built-in BIOS or bioscv.rom in cv/): USB keyboard or joystick; Esc ends", cmd_cv},
    {"m5", "[-f frames] [-k script] <file>", "play a Sord M5 / CGL M5 cartridge (.m5, .rom, .bin: 4K..20K) on the TV "
     "(256 x 192 three times as large, 60 Hz NTSC; 3.58 MHz Z80 + Z80 CTC IM2, 36 KB RAM, TMS9918A VDP, SN76489AN 48 kHz "
     "sound, built-in Monitor BIOS or m5.rom in m5/): USB keyboard or joystick; Esc ends", cmd_m5},
    {"pv1000", "[-f frames] [-k script] <file>", "play a Casio PV-1000 cartridge (.pv, .bin, .rom: 8K..32K) on the TV "
     "(256 x 192 three times as large, 59.92 Hz; 3.58 MHz Z80, NEC D65010G031 VDP, 3-channel square/XOR 48 kHz PSG): "
     "the keys and the options of nes", cmd_pv1000},
    {"astro", "[-f frames] [-k script] [file]", "play a Bally Astrocade cartridge (.ast, .bin, .rom) or no file for "
     "built-in Star Blaster on the TV (320 x 204 three times as large, 59.92 Hz; 1.79 MHz Z80, Data Chip Magic-RAM "
     "blitter + 256-colour split palette, 3-voice + vibrato + LFSR 48 kHz synth, built-in BIOS or astro.bin in astro/): "
     "X = Trigger, Z/C = Knob, 0..9 = keypad", cmd_astro},
    {"arcadia", "[-f frames] [-k script] <file>", "play an Emerson Arcadia 2001 cartridge (.a2k, .bin) on the TV (160 x "
     "208, 640 x 624, 59.92 Hz; Signetics 2650 CPU + 2637 UVI video & 48 kHz tone/noise sound): arrows/WASD, X/Z = fire, "
     "Enter = Start, Tab = Option, 0..9 = keypad", cmd_arcadia},
    {"vc4000", "[-f frames] [-k script] <file>", "play an Interton VC 4000 cartridge (.vc4, .bin) on the TV (192 x 224, "
     "768 x 672, 50 Hz PAL; Signetics 2650 CPU + 2636 PVI programmable grid/objects/score LEDs & 48 kHz tone sound): "
     "arrows/WASD, X/Z = fire, Enter = Start, Tab = Select, 0..9 = keypad", cmd_vc4000},
    {"studio2", "[-f frames] [-k script] [file]", "play an RCA Studio II cartridge (.st2, .bin) or no file for built-in "
     "COSMAC Interceptor on the TV (256 x 128, 1024 x 640, 60 Hz; COSMAC CDP1802 + CDP1861 Pixie DMA + CA555 48 kHz "
     "tone, built-in BIOS or studio2.bin in studio2/): arrows/WASD, X/Z = fire (5), 0..9 = keypad", cmd_studio2},
    {"scv", "[-f frames] [-k script] <file>", "play an Epoch Super Cassette Vision cartridge (.scv, .bin, .cart: 8K..128K) "
     "on the TV (192 x 222, 768 x 666, 59.92 Hz; 4 MHz NEC uPD7801G, Epoch TV-1 VDP, uPD1771C 48 kHz sound, .sav SRAM, "
     "built-in BIOS + font or upd7801g.s01 in scv/): X/Z = triggers, Enter = En, Tab = Cl, P = Pause, 0..9 = keypad",
     cmd_scv},
    {"vb", "[-m 0|1|2|3] [-f frames] [-k script] <file>", "play a Nintendo Virtual Boy cartridge (.vb, .vboy) on the TV "
     "(384 x 224 three times as large: 1152 x 672, 50.27 Hz; 20 MHz 32-bit NEC V810 RISC, VIP 32 Worlds/OBJ dual-eye "
     "display, 6-ch VSU 48 kHz sound, 64 KB .sav SRAM; -m 0 Red/Black, 1 Red/Cyan 3D Anaglyph, 2 White, 3 Amber, V/F2/M "
     "cycles live): WASD/arrows + IJKL/TFGH, X = A, Z = B, Q/E = L/R", cmd_vb},
    {"sgx", "[-f frames] [-k script] <file>", "play an NEC SuperGrafx HuCard (.sgx) on the TV (256/320/512 x 240; "
     "HuC6280, dual HuC6270 VDCs with 128 KB VRAM + HuC6202 VPC priority/window mixer, 32 KB WRAM, 6-ch 48 kHz PSG, "
     "2 KB .sav BRAM): the keys and the options of pce", cmd_sgx},
    {"pcecd", "[-f frames] [-k script] <file>", "play a PC Engine CD-ROM2 / Super CD-ROM2 / Arcade Card disc (.cue, .iso) "
     "on the TV (streamed CD-ROM + Redbook CD-DA + OKI MSM5205 ADPCM + 6-ch PSG @ 48 kHz, 256 KB Super System Card 3.0 + "
     "2 MB Arcade Card RAM, 2 KB .sav BRAM; built-in System Card 3.0 BIOS or syscard3.pce in pcecd/)", cmd_pcecd},
    {"segacd", "[-r j|u|e] [-f frames] [-k script] <file>", "play a Sega CD / Mega-CD disc (.cue, .iso) on the TV "
     "(7.67 MHz Main-68000 + 12.5 MHz Sub-68000 + Z80, 512 KB PRG-RAM, 256 KB Word-RAM, Stamp ASIC scaling/rotation, "
     "LC89510 CDC + CDD, YM2612 + PSG + Ricoh RF5C164 8-ch PCM + Redbook CD-DA @ 48 kHz, 8 KB .sav BRAM; built-in "
     "CDBIOS or bios_CD_{U,E,J}.bin in segacd/)", cmd_segacd},
    {"bbc", "[-f frames] [-k script] [file]", "a BBC Micro Model B / Acorn Electron on the TV: a disk (.ssd, .dsd) or "
     "tape (.uef, *_el.uef for Electron), or no file for Teletext Mode 7 BASIC (2 MHz 6502, 6845 CRTC + Video ULA "
     "Modes 0-6 + SAA5050 Teletext Mode 7 + Electron ULA, dual 6522 VIAs, SN76489 48 kHz sound; built-in OS/BASIC or "
     "os12.rom + basic2.rom in bbc/)", cmd_bbc},
    {"ti99", "[-f frames] [-k script] [file]", "a Texas Instruments TI-99/4A on the TV: a cartridge (.rpk, .bin, .zip "
     "with c/d/g or 378/379i banked ROMs), or no file for TI BASIC (3 MHz 16-bit TMS9900 CPU, GROM + CRU, 32 KB "
     "Expansion RAM, TMS9918A VDP, TMS9919 48 kHz sound)", cmd_ti99},
    {"oric", "[-f frames] [-k script] [file]", "a Tangerine Oric-1 / Oric Atmos 48K on the TV: a tape (.tap) or disk "
     "(.dsk), or no file for Atmos BASIC (1 MHz 6502, HCS10017 240 x 224 serial-attribute ULA Text & Hires, 6522 VIA, "
     "AY-3-8912 48 kHz sound; built-in Atmos ROM or basic11b.rom in oric/)", cmd_oric},
    {"plus4", "[-f frames] [-k script] [file]", "a Commodore Plus/4 or C16 on the TV: a program (.prg, .t64) or raw "
     "tape (.tap), or no file for BASIC V3.5 (1.77 MHz MOS 7501/8501, 64 KB RAM, MOS 7360/8360 TED 121-colour video & "
     "2-voice 48 kHz sound)", cmd_plus4},
    {"zx81", "[-f frames] [-k script] [file]", "a Sinclair ZX81 16K on the TV: a snapshot/tape (.p, .81), or no file "
     "for Sinclair 16K BASIC (3.25 MHz Z80, ULA live D_FILE 256 x 192 display, 50 Hz FRAMES VSync, 48 kHz pulse sound)",
     cmd_zx81},
    {"pc88", "[-f frames] [-k script] [file]", "an NEC PC-8801mkIISR on the TV: a floppy disk (.d88, .n88), or no file "
     "for N88-BASIC (4 MHz Z80, 64 KB RAM + 48 KB 3-plane 640 x 200 GVRAM + Text VRAM, Sub-CPU disk HLE, Yamaha YM2203 "
     "OPN FM/SSG + beeper @ 48 kHz)", cmd_pc88},
    {"mz700", "[-f frames] [-k script] [file]", "a Sharp MZ-700 on the TV: a tape (.mzt, .mzf), or no file for 1Z-009A "
     "Monitor (3.58 MHz Z80, 64 KB banked RAM, 320 x 200 GRB CGROM display, Intel 8253 PIT 48 kHz sound)", cmd_mz700},
    {"x1", "[-f frames] [-k script] [file]", "a Sharp X1 on the TV: a disk or tape (.d88, .2d, .tap), or no file for "
     "X1 IPL/BASIC (4 MHz Z80, 16-bit I/O 48 KB GVRAM + 256-char colour PCG, 2 MHz AY-3-8910 @ 48 kHz)", cmd_x1},
    {"s32x", "[-r j|u|e] [-f frames] [-k script] <file>", "play a Sega 32X cartridge (.32x, .bin) on the TV (7.67 MHz "
     "68000 + dual 23 MHz 32-bit Hitachi SH-2 RISC CPUs + Z80, 256 KB SDRAM, SuperVDP 256-colour/RLE/15-bit Direct "
     "framebuffers, stereo 12-bit PWM + YM2612 + PSG @ 48 kHz, .sav SRAM; built-in MARS BIOS or 32x_{g,m,s}_bios.bin)",
     cmd_s32x},
    {"cd32", "[-f frames] [-k script] <file>", "play a Commodore Amiga CD32 disc (.cue, .iso) on the TV (14.18 MHz "
     "68EC020-compatible CPU, 2 MB Chip RAM, AGA 8-bitplane 256-colour / HAM8 + 2 MB Blitter + Copper, Akiko $C0CACAFE "
     "hardware Chunky-to-Planar + CD DMA + 7-button pad, 4-ch Paula + Redbook CD-DA @ 48 kHz, 1 KB .sav NVRAM)",
     cmd_cd32},
    {"cps2", "[-f frames] [-k script] <file>", "play a Capcom CPS-2 QSound arcade game (.zip with .key or .03x XOR "
     "tables, or .cps2) on the TV (384 x 224, 1152 x 672, 59.63 Hz; 16 MHz 68000 + Z80, Z-priority multi-slice "
     "tilemaps/sprites, 16-channel DL-1425 QSound DSP @ 48 kHz, 128-byte 93C46 .sav EEPROM)", cmd_cps2},
    {"arcade", "[-f frames] [-k script] [file]", "play a Golden-Age Z80 arcade .zip romset (Namco Pac-Man / Ms. Pac-Man "
     "WSG, Namco Galaxian starfield, Konami Frogger / Scramble dual-Z80 + AY-3-8910, Nintendo Donkey Kong DMA + DAC) "
     "or no file for built-in Maze Chomp on the TV (224 x 288 / 256, 60.6 Hz, 48 kHz sound)", cmd_arcade},
    {"rf", "<init|tune|status|scan|services|ts|spectrum|live|...>", "the aerial input (DVB-T): init the MxL603 tuner and the "
     "chip's demodulator, tune <MHz|channel> [6|7|8], status (lock, level, quality), scan [vhf|all|<from> <to>], "
     "services (the multiplex's channel names), ts <s> [file] [-p pids] (the stream's PIDs, or recorded to a .ts "
     "file), spectrum [from to [kHz]] (the aerial's level across the band as a chart on the TV), live [from to] "
     "(that chart swept again and again: Left / Right a marker, Up / Down zoom, PgUp / PgDn move, + / - faster / "
     "slower, Space pause, P peak hold, Enter a DVB-T lock tried at the marker, Esc ends); 'rf' alone lists all",
     cmd_rf},
    {"snd", "<init|beep|status|stop|vol>", "sound output (a prototype of the original firmware's driver: 48 kHz "
     "on HDMI -- after 'video init' -- and the SCART's L/R): init, beep [Hz] [ms] (a sine tone, then what the "
     "DMA did), status (the engine's registers, its DMA position and speed), stop, vol [0..100]", snd_command},
    {"play", "[-n frames] [-x] [-k] [-v] [-1] <file>", "a video file (.ts, .mpg, .m2v, .264, .mp4, .mov: MPEG-2 / "
     "MPEG-1 or H.264 video, MPEG audio -- an .mp4's sound, AAC, is not played) on the TV, decoded by the chip's own "
     "MPEG-2 / H.264 decoders, its sound through 'snd': Esc, "
     "Ctrl-C, q or EXIT ends (-n: that many frames, -x: as fast as they decode, without sound, -k: the last picture "
     "stays on the TV, -v: every picture's (H.264: slice's) decoding said, -1: the picture's own size instead of the "
     "screen's height)", play_command},
    {"av", "<status|shot <file.bmp|.yuv>|show|off|reset>", "the video player's decoder and picture layer: their "
     "registers, the picture shown last saved to a file (RGB .bmp or raw I420 .yuv), shown again, taken away, the "
     "decoder reset", av_command},
    {"view", "[-1] [-s | -c] <file>", "a picture (JPEG, PNG, GIF, BMP) on the TV, fitted to it: Right / Space the "
     "next one in its directory, Left the one before, i its details, Esc or q ends (-1: shown, the command ends; a "
     "baseline JPEG is decoded by the video engine, -s: by the CPU; -c: both, compared, nothing shown)", cmd_view},
    {"sum", "[n:]path", "a file read to its end: its size, CRC-32 (as zlib's, 7-Zip's), first bytes, how fast "
     "(Ctrl-C stops it)", cmd_sum},
    {"mkdir", "<path>", "make a directory (this writes the disk)", cmd_mkdir},
    {"rmdir", "<path>", "remove an empty directory (writes the disk)", cmd_rmdir},
    {"rm", "[-r] <path>", "remove a file; -r: a directory and everything in it (writes the disk)", cmd_rm},
    {"touch", "<path>", "make an empty file (writes the disk)", cmd_touch},
    {"cp", "[-r] <from> <to>", "copy a file (to a directory: into it; another disk too, between FAT and NTFS "
     "too); -r: a directory with everything in it (writes the disk)", cmd_cp},
    {"head", "[-n N] <path>", "a text file's first N lines (10)", cmd_head},
    {"tail", "[-n N] <path>", "a text file's last N lines (10)", cmd_tail},
    {"df", "[n:]", "the disks' volumes: size, free and used space", cmd_df},
    {"ntfs", "[n: [reset-journal]]", "an NTFS volume: its version, cluster and record sizes, $MFT, free space, "
     "dirty flag and journal -- and whether the demo writes it (only when Windows left it clean: 'Safely "
     "remove' the disk there); reset-journal: its journal emptied, as ntfs-3g does (writes the disk)", cmd_ntfs},
    {"mv", "<from> <to>", "rename a file or directory, or move it into another directory of the same volume "
     "(writes the disk)", cmd_mv},
    {"sector", "[n:]<number>", "one sector of a USB disk in hex", cmd_sector},
    {"tty", "", "the USB serial ports (a GSM / LTE module's AT and diagnostic ports, CDC ACM)", cmd_tty},
    {"stty", "[n] [baud]", "a USB serial port's baud rate (CH340 / CH341, CP210x, FTDI, PL2303, CDC ACM; "
     "8N1): shown, or set ('stty 0 9600')", cmd_stty},
    {"cu", "[n]", "the terminal joined to serial port n, ttyUSB<n> / ttyACM<n> (without n: the AT port): what "
     "you type goes to it; \"~.\" at a line's start or Ctrl-] ends", cmd_cu},
    {"at", "[command]", "one AT command to the AT port and its answer ('at +csq', 'at i'; a line starting "
     "with AT goes there too)", cmd_at},
    {"ifconfig", "", "the Ethernet port (a USB adapter with CDC ECM, an RTL8153's): MAC, address, router",
     cmd_ifconfig},
    {"dhcp", "", "ask the network's DHCP server for an address again", cmd_dhcp},
    {"arp", "", "the ARP table: addresses and the MACs they answer at", cmd_arp},
    /* net.c: wget, NTP, the TCP state (the telnet console on port 23 and netload on 6464 need no command) */
    {"wget", "[-O n:path] [--no-check-certificate] <url>", "an http:// or https:// URL (TLS 1.2; the "
     "certificate checked against Mozilla's roots and the NTP clock; redirections followed): its status line and "
     "body on the console, or with -O saved to a file (Ctrl-C stops it)", cmd_wget},
    {"ntp", "[server]", "set the clock from an NTP server (pool.ntp.org; done once after DHCP too)", cmd_ntp},
    {"date", "", "the time of day: UTC and Polish (CET / CEST), once NTP set it", cmd_date},
    {"netstat", "", "TCP: the ports listened on, the connections; the telnet console's client, the FTP server's",
     cmd_netstat},
    {"watchdog", "[test|off|on]", "the chip's watchdog: a demo stopped for 8 s restarts the box; "
     "test: stop feeding it (the box restarts)", cmd_watchdog},
    {"clear", "", "clear the terminal", cmd_clear},
    {"history", "[n | -c]", "the commands typed before, numbered (the last n; -c: forget them).  Up / Down "
     "recall the ones that start with what is typed, Ctrl-R looks for one holding what is typed next, "
     "!! / !n / !-n / !text run one again", cmd_history},
    {"video", "init [opticum|comsat] [rev0|rev1]", "experimental: the original firmware's display and HDMI set-up",
     cmd_video},
    {"reboot", "", "restart through the original bootloader", cmd_reboot},
    {"restart", "", "the same as reboot", cmd_reboot},
    {"bootloader", "", "restart into the original bootloader: hold 'c' (or run maciej_uart.py) to stay", cmd_bootloader},
    {"prof", "[-f frame] [-c address length] [-e event0 event1] <command ...>", "run the command with the sampling "
     "profiler (the CPU timer, ~10,000 samples a second) and list the 64-byte pieces of code it was found in, most "
     "first (-f: a game's samples from that frame on; -c: samples inside that code counted for its caller, as $ra "
     "says; -e: the CPU's two performance counters count those events, from the -f frame for 100 frames: 0 cycles, "
     "1 instructions, 9 I-cache accesses / misses, 10 D-cache accesses / writebacks, 11 D-cache misses)", cmd_prof},
    {0, 0, 0, 0},
};

/* prof.c */
int prof_start(void);
void prof_stop(void);
void prof_report(void);
void prof_from(u32 frame);
void prof_caller(u32 lo, u32 len);
void prof_events(u32 e0, u32 e1);

static void cmd_prof(int argc, char **argv)
{
    u32 from = 0, lo = 0, len = 0, e0 = 0, e1 = 0;
    int events = 0;
    for (;;) {
        if (argc > 3 && str_eq(argv[1], "-f") && parse_u32(argv[2], &from)) {
            argc -= 2;
            argv += 2;
        } else if (argc > 4 && str_eq(argv[1], "-c") && parse_u32(argv[2], &lo) && parse_u32(argv[3], &len)) {
            argc -= 3;
            argv += 3;
        } else if (argc > 4 && str_eq(argv[1], "-e") && parse_u32(argv[2], &e0) && parse_u32(argv[3], &e1)) {
            events = 1;
            argc -= 3;
            argv += 3;
        } else {
            break;
        }
    }
    if (argc < 2) {
        uprintf("usage: prof [-f frame] [-c address length] [-e event0 event1] <command ...>\n");
        return;
    }
    if (events)
        prof_events(e0, e1);
    prof_from(from);
    prof_caller(lo, len);
    const struct command *c = commands;
    while (c->name && !str_eq(c->name, argv[1]))
        c++;
    if (!c->name || c->run == cmd_prof) {
        uprintf("prof: unknown command '%s'\n", argv[1]);
        return;
    }
    if (prof_start() < 0)
        return;
    c->run(argc - 1, argv + 1);
    prof_stop();
    prof_report();
}

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
    uprintf("Commands (whole lines, '/' in front allowed; Tab completes a command, its choices, a file's name\n"
            "(twice: lists them); Up/Down recall earlier ones starting with what is typed, Ctrl-R searches them;\n"
            "Left/Right, Home/End, Ctrl-arrows, Delete, Ctrl-W/U/K/Y edit the line, Ctrl-L clears the screen;\n"
            "'ccc' on an empty line restarts into the bootloader for the UART updater;\n"
            "\"...\" or '...' keep spaces in a word; 'command > [n:]path' puts what it prints into a file,\n"
            "'>>' adds it to the file's end):\n");
    for (const struct command *c = commands; c->name; c++) {
        char head[96];
        usnprintf(head, sizeof(head), "%s %s", c->name, c->args);
        uprintf("  %s", head);
        int n = str_len(head);
        if (n >= 44) {                  /* (longer than its column: what it does starts on the next line) */
            uprintf("\n");
            n = -2;
        }
        for (int i = n; i < 44; i++)
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

/* 'ping': pong; 'ping [-c count] <host>': ICMP echo over Ethernet like Linux's ping, until Ctrl-C (eth.c) */
static void cmd_ping(int argc, char **argv)
{
    const char *host = 0;
    u32 count = 0;
    if (argc < 2) {
        uprintf("pong %s\n", APP_VERSION);
        return;
    }
    int bad = 0;
    for (int i = 1; i < argc && !bad; i++) {
        if (str_eq(argv[i], "-c"))
            bad = !(i + 1 < argc && parse_u32(argv[++i], &count) && count);
        else if (argv[i][0] != '-' && !host)
            host = argv[i];
        else
            bad = 1;
    }
    if (bad || !host) {
        uprintf("usage: ping [-c count] <host>   (a.b.c.d or a name; Ctrl-C stops)\n");
        return;
    }
    eth_ping(host, (int)count);
}

static void cmd_ifconfig(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    eth_show();
}

static void cmd_dhcp(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    eth_dhcp();
}

static void cmd_arp(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    eth_arp_list();
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
    if (argc > 1 && str_eq(argv[1], "ctl")) {          /* a raw control request (data IN, or OUT: the bytes the
                                                           last 'usb ctl' read -- read a register, write it back) */
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
    usb_retry = 0;                              /* (not set up: the main loop tries again) */
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
    if (!str_eq(argv[1], "on") && !str_eq(argv[1], "off")) {
        explorer_hide();                /* (drawn over it) */
        gfx_view(0);                    /* (what was drawn is on the TV) */
    }
    uprintf("ok\n");
}

static void cmd_testscreen(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    if (!demo_shown)
        draw_screen();                  /* (after a 'screen' drawing: the boxes again) */
    gfx_view(0);
    uprintf("the test screen is on the TV: a key on the USB keyboard, or 'console', brings the console back\n");
}

static void show_console(void)
{
    gfx_view(1);
    console_redraw();
}

static void cmd_console(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    show_console();
}

/* 'history': every command kept, numbered ('!n' runs number n again); 'history <n>': the last n; 'history -c':
   none kept any more */
static void cmd_history(int argc, char **argv)
{
    int from = 0;
    u32 n;
    if (argc > 1 && str_eq(argv[1], "-c")) {
        history_n = history_pos = 0;
        uprintf("history cleared\n");
        return;
    }
    if (argc > 1) {
        if (!parse_u32(argv[1], &n)) {
            uprintf("usage: history [n | -c]\n");
            return;
        }
        if ((int)n < history_n)
            from = history_n - (int)n;
    }
    for (int i = from; i < history_n; i++)
        uprintf("%5d  %s\n", i + 1, history[i]);
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

static void cmd_sum(int argc, char **argv)
{
    if (argc < 2) {
        uprintf("usage: sum [device:]path\n");
        return;
    }
    disk_sum(joined(argc, argv));
}


static void cmd_sector(int argc, char **argv)
{
    if (argc != 2) {
        uprintf("usage: sector [device:]<sector number>\n");
        return;
    }
    disk_sector(argv[1]);
}

static void cmd_cd(int argc, char **argv)
{
    disk_cd(joined(argc, argv));
}

static void cmd_pwd(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    disk_pwd();
}

/* 'explorer [n:][path]': the file explorer on the TV (explorer.c), on the test screen's picture */
static void cmd_explorer(int argc, char **argv)
{
    if (argc > 1)
        disk_cd(joined(argc, argv));
    demo_shown = 0;                     /* (the picture is the explorer's: the demo's boxes stay away) */
    explorer_show();
    uprintf("the explorer is on the TV, in %s ('help explorer': its keys); Esc on the USB keyboard or 'console' "
            "brings the console back\n", disk_cwd()[0] ? disk_cwd() : "the list of disks");
}

/* the TV back to what it showed before a command took the test screen's picture for its own (a game) */
static void picture_back(int console, int explorer)
{
    if (explorer) {
        explorer_show();
    } else {
        draw_screen();
        if (console)
            show_console();
    }
}

static void cmd_game(int argc, char **argv, int (*play)(const char *, u32, const char *))
{
    u32 frames = 0;
    const char *script = "";
    int first = 1, stay = 0;
    while (argc > first && argv[first][0] == '-') {
        if (str_eq(argv[first], "-s")) {
            stay = 1;
            first++;
        } else if (argc > first + 1 && str_eq(argv[first], "-f") && parse_u32(argv[first + 1], &frames)) {
            first += 2;
        } else if (argc > first + 1 && str_eq(argv[first], "-k")) {
            script = argv[first + 1];
            first += 2;
            if (script[0] == '@') {             /* -k @file: the script read from a file (longer than a line) */
                static char from_file[8192];
                u32 size = 0;
                int got = disk_read_head(script + 1, (u8 *)from_file, sizeof(from_file) - 1, &size);
                if (got < 0) {
                    uprintf("-k: cannot read %s\n", script + 1);
                    return;
                }
                u32 n = (u32)got;
                while (n && (from_file[n - 1] == '\n' || from_file[n - 1] == '\r' || from_file[n - 1] == ' '))
                    n--;
                from_file[n] = 0;
                script = from_file;
            }
        } else {
            break;
        }
    }
    if (argc <= first) {
        uprintf("usage: %s [-f frames] [-k script] <file>\n", argv[0]);
        return;
    }
    int console = gfx_view_console(), explorer = explorer_shown();
    if (explorer)
        explorer_hide();
    demo_shown = 0;
    (void)play(joined(argc - first + 1, argv + first - 1), frames, script);
    if (!stay)
        picture_back(console, explorer);
}

static void cmd_nes(int argc, char **argv)
{
    cmd_game(argc, argv, nes_play);
}

static void cmd_gb(int argc, char **argv)
{
    cmd_game(argc, argv, gb_play);
}

static void cmd_sms(int argc, char **argv)
{
    cmd_game(argc, argv, sms_play);
}

static void cmd_gg(int argc, char **argv)
{
    cmd_game(argc, argv, gg_play);
}

static void cmd_sg(int argc, char **argv)
{
    cmd_game(argc, argv, sg_play);
}

static void cmd_zx(int argc, char **argv)
{
    if (argc == 1) {                    /* (no file: BASIC) */
        static char none[] = "", *with[3];
        with[0] = argv[0];
        with[1] = none;
        with[2] = 0;
        cmd_game(2, with, zx_play);
        return;
    }
    cmd_game(argc, argv, zx_play);
}

static void cmd_c64(int argc, char **argv)
{
    if (argc == 1) {                    /* (no file: BASIC) */
        static char none[] = "", *with[3];
        with[0] = argv[0];
        with[1] = none;
        with[2] = 0;
        cmd_game(2, with, c64_play);
        return;
    }
    cmd_game(argc, argv, c64_play);
}

static void cmd_dos(int argc, char **argv)
{
    cmd_game(argc, argv, dos_play);
}

static void cmd_amiga(int argc, char **argv)
{
    if (argc == 1) {                    /* (no file: no disk in the drive) */
        static char none[] = "", *with[3];
        with[0] = argv[0];
        with[1] = none;
        with[2] = 0;
        cmd_game(2, with, amiga_play);
        return;
    }
    cmd_game(argc, argv, amiga_play);
}

static void cmd_megadrive(int argc, char **argv)
{
    int region = 0;
    /* (-r j|u|e: the console -- anywhere among the options; taken out of the words for cmd_game) */
    for (int i = 1; i < argc && argv[i][0] == '-'; ) {
        if (str_eq(argv[i], "-s")) { i++; continue; }
        if (i + 1 >= argc) break;
        if (!str_eq(argv[i], "-r")) { i += 2; continue; }
        char c = (char)(argv[i + 1][0] & ~32);
        if (c != 'J' && c != 'U' && c != 'E') {
            uprintf("-r: j (Japan, NTSC), u (America, NTSC) or e (Europe, PAL)\n");
            return;
        }
        region = c;
        for (int k = i; k + 2 < argc; k++)
            argv[k] = argv[k + 2];
        argc -= 2;
        break;
    }
    md_play_region(region);
    cmd_game(argc, argv, md_play);
    md_play_region(0);
}

static void cmd_a26(int argc, char **argv)
{
    cmd_game(argc, argv, a26_play);
}

static void cmd_pce(int argc, char **argv)
{
    cmd_game(argc, argv, pce_play);
}

static void cmd_coleco(int argc, char **argv)
{
    cmd_game(argc, argv, col_play);
}

static void cmd_msx(int argc, char **argv)
{
    cmd_game(argc, argv, msx_play);
}

static void cmd_msx2(int argc, char **argv)
{
    cmd_game(argc, argv, msx2_play);
}

static void cmd_ws(int argc, char **argv)
{
    cmd_game(argc, argv, ws_play);
}

static void cmd_snes(int argc, char **argv)
{
    cmd_game(argc, argv, snes_play);
}

static void cmd_neogeo(int argc, char **argv)
{
    cmd_game(argc, argv, neo_play);
}

static void cmd_gba(int argc, char **argv)
{
    cmd_game(argc, argv, gba_play);
}

static void cmd_a78(int argc, char **argv)
{
    cmd_game(argc, argv, a78_play);
}

static void cmd_lynx(int argc, char **argv)
{
    cmd_game(argc, argv, lnx_play);
}

static void cmd_vectrex(int argc, char **argv)
{
    int i = 1;
    while (i + 1 < argc && (str_eq(argv[i], "-f") || str_eq(argv[i], "-k")))
        i += 2;
    if (i == argc) {                    /* (no file: built-in Mine Storm / Vector Storm) */
        static char none[] = "";
        char *with[8];
        int k = 0;
        for (; k < argc && k < 6; k++)
            with[k] = argv[k];
        with[k++] = none;
        with[k] = 0;
        cmd_game(k, with, vec_play);
        return;
    }
    cmd_game(argc, argv, vec_play);
}

static void cmd_fds(int argc, char **argv)
{
    cmd_game(argc, argv, fds_play);
}

static void cmd_ngp(int argc, char **argv)
{
    cmd_game(argc, argv, ngp_play);
}

static void cmd_odyssey2(int argc, char **argv)
{
    cmd_game(argc, argv, o2_play);
}

static void cmd_intv(int argc, char **argv)
{
    cmd_game(argc, argv, intv_play);
}

static void cmd_psx(int argc, char **argv)
{
    int region = 0;
    for (int i = 1; i < argc && argv[i][0] == '-'; ) {
        if (str_eq(argv[i], "-s")) { i++; continue; }
        if (i + 1 >= argc) break;
        if (!str_eq(argv[i], "-r")) { i += 2; continue; }
        char c = (char)(argv[i + 1][0] & ~32);
        if (c != 'J' && c != 'U' && c != 'E') {
            uprintf("-r: j (Japan, NTSC 60 Hz), u (America, NTSC 60 Hz) or e (Europe, PAL 50 Hz)\n");
            return;
        }
        region = c;
        for (int k = i; k + 2 < argc; k++)
            argv[k] = argv[k + 2];
        argc -= 2;
        break;
    }
    psx_play_region(region);
    cmd_game(argc, argv, psx_play);
    psx_play_region(0);
}

static void cmd_cps(int argc, char **argv)
{
    cmd_game(argc, argv, cps_play);
}

static void cmd_atarist(int argc, char **argv)
{
    int i = 1;
    while (i + 1 < argc && (str_eq(argv[i], "-f") || str_eq(argv[i], "-k")))
        i += 2;
    if (i == argc) {                    /* (no file: boot TOS / EmuTOS desktop) */
        static char none[] = "";
        char *with[8];
        int k = 0;
        for (; k < argc && k < 6; k++)
            with[k] = argv[k];
        with[k++] = none;
        with[k] = 0;
        cmd_game(k, with, st_play);
        return;
    }
    cmd_game(argc, argv, st_play);
}

static void cmd_sys16(int argc, char **argv)
{
    cmd_game(argc, argv, s16_play);
}

static void cmd_atari8(int argc, char **argv)
{
    int i = 1;
    while (i + 1 < argc && (str_eq(argv[i], "-f") || str_eq(argv[i], "-k")))
        i += 2;
    if (i == argc) {                    /* (no file: boot 8K BASIC Ready prompt) */
        static char none[] = "";
        char *with[8];
        int k = 0;
        for (; k < argc && k < 6; k++)
            with[k] = argv[k];
        with[k++] = none;
        with[k] = 0;
        cmd_game(k, with, a8_play);
        return;
    }
    cmd_game(argc, argv, a8_play);
}

static void cmd_a5200(int argc, char **argv)
{
    cmd_game(argc, argv, a52_play);
}

static void cmd_megaduck(int argc, char **argv)
{
    cmd_game(argc, argv, megaduck_play);
}

static void cmd_sv(int argc, char **argv)
{
    cmd_game(argc, argv, sv_play);
}

static void cmd_chip8(int argc, char **argv)
{
    cmd_game(argc, argv, chip8_play);
}

static void cmd_channelf(int argc, char **argv)
{
    cmd_game(argc, argv, channelf_play);
}

static void cmd_pokemini(int argc, char **argv)
{
    cmd_game(argc, argv, pokemini_play);
}

static void cmd_cpc(int argc, char **argv)
{
    int i = 1;
    while (i + 1 < argc && (str_eq(argv[i], "-f") || str_eq(argv[i], "-k")))
        i += 2;
    if (i == argc) {                    /* (no file: boot Locomotive BASIC 1.1) */
        static char none[] = "";
        char *with[8];
        int k = 0;
        for (; k < argc && k < 6; k++)
            with[k] = argv[k];
        with[k++] = none;
        with[k] = 0;
        cmd_game(k, with, cpc_play);
        return;
    }
    cmd_game(argc, argv, cpc_play);
}

static void cmd_vic20(int argc, char **argv)
{
    int i = 1;
    while (i + 1 < argc && (str_eq(argv[i], "-f") || str_eq(argv[i], "-k")))
        i += 2;
    if (i == argc) {                    /* (no file: boot +24K Commodore BASIC V2) */
        static char none[] = "";
        char *with[8];
        int k = 0;
        for (; k < argc && k < 6; k++)
            with[k] = argv[k];
        with[k++] = none;
        with[k] = 0;
        cmd_game(k, with, vic20_play);
        return;
    }
    cmd_game(argc, argv, vic20_play);
}

static void cmd_opt_basic(int argc, char **argv, int (*play)(const char *, u32, const char *))
{
    int i = 1;
    while (i < argc) {
        if (str_eq(argv[i], "-s")) i++;
        else if (i + 1 < argc && (str_eq(argv[i], "-f") || str_eq(argv[i], "-k"))) i += 2;
        else break;
    }
    if (i == argc) {
        static char none[] = "";
        char *with[8];
        int k = 0;
        for (; k < argc && k < 6; k++)
            with[k] = argv[k];
        with[k++] = none;
        with[k] = 0;
        cmd_game(k, with, play);
        return;
    }
    cmd_game(argc, argv, play);
}

static void cmd_apple2(int argc, char **argv) { cmd_opt_basic(argc, argv, apple2_play); }
static void cmd_coco(int argc, char **argv)   { cmd_opt_basic(argc, argv, coco_play); }
static void cmd_dragon(int argc, char **argv) { cmd_opt_basic(argc, argv, dragon_play); }
static void cmd_cv(int argc, char **argv)     { cmd_game(argc, argv, cv_play); }
static void cmd_m5(int argc, char **argv)     { cmd_game(argc, argv, m5_play); }
static void cmd_pv1000(int argc, char **argv)  { cmd_game(argc, argv, pv1000_play); }
static void cmd_astro(int argc, char **argv)   { cmd_opt_basic(argc, argv, astro_play); }
static void cmd_arcadia(int argc, char **argv) { cmd_game(argc, argv, arcadia_play); }
static void cmd_vc4000(int argc, char **argv)  { cmd_game(argc, argv, vc4000_play); }
static void cmd_studio2(int argc, char **argv) { cmd_opt_basic(argc, argv, studio2_play); }
static void cmd_scv(int argc, char **argv)     { cmd_game(argc, argv, scv_play); }
static void cmd_sgx(int argc, char **argv)     { cmd_game(argc, argv, sgx_play); }
static void cmd_pcecd(int argc, char **argv)   { cmd_game(argc, argv, pcecd_play); }

static void cmd_vb(int argc, char **argv)
{
    int mode = 0;
    for (int i = 1; i < argc && argv[i][0] == '-'; ) {
        if (str_eq(argv[i], "-s")) { i++; continue; }
        if (i + 1 >= argc) break;
        if (!str_eq(argv[i], "-m")) { i += 2; continue; }
        u32 v = 0;
        if (!parse_u32(argv[i + 1], &v) || v > 3) {
            uprintf("-m: 0 (Red/Black), 1 (Red/Cyan 3D Anaglyph), 2 (White) or 3 (Amber)\n");
            return;
        }
        mode = (int)v;
        for (int k = i; k + 2 < argc; k++)
            argv[k] = argv[k + 2];
        argc -= 2;
        break;
    }
    vb_play_mode(mode);
    cmd_game(argc, argv, vb_play);
    vb_play_mode(0);
}

static void cmd_segacd(int argc, char **argv)
{
    int region = 0;
    for (int i = 1; i < argc && argv[i][0] == '-'; ) {
        if (str_eq(argv[i], "-s")) { i++; continue; }
        if (i + 1 >= argc) break;
        if (!str_eq(argv[i], "-r")) { i += 2; continue; }
        char c = (char)(argv[i + 1][0] & ~32);
        if (c != 'J' && c != 'U' && c != 'E') {
            uprintf("-r: j (Japan, NTSC), u (America, NTSC) or e (Europe, PAL)\n");
            return;
        }
        region = c;
        for (int k = i; k + 2 < argc; k++)
            argv[k] = argv[k + 2];
        argc -= 2;
        break;
    }
    segacd_play_region(region);
    cmd_game(argc, argv, segacd_play);
    segacd_play_region(0);
}

static void cmd_bbc(int argc, char **argv)    { cmd_opt_basic(argc, argv, bbc_play); }
static void cmd_ti99(int argc, char **argv)   { cmd_opt_basic(argc, argv, ti99_play); }
static void cmd_oric(int argc, char **argv)   { cmd_opt_basic(argc, argv, oric_play); }
static void cmd_plus4(int argc, char **argv)  { cmd_opt_basic(argc, argv, plus4_play); }
static void cmd_zx81(int argc, char **argv)   { cmd_opt_basic(argc, argv, zx81_play); }
static void cmd_pc88(int argc, char **argv)   { cmd_opt_basic(argc, argv, pc88_play); }
static void cmd_mz700(int argc, char **argv)  { cmd_opt_basic(argc, argv, mz700_play); }
static void cmd_x1(int argc, char **argv)     { cmd_opt_basic(argc, argv, x1_play); }
static void cmd_cd32(int argc, char **argv)   { cmd_game(argc, argv, cd32_play); }
static void cmd_cps2(int argc, char **argv)   { cmd_game(argc, argv, cps2_play); }
static void cmd_arcade(int argc, char **argv) { cmd_opt_basic(argc, argv, arcade_play); }

static void cmd_s32x(int argc, char **argv)
{
    int region = 0;
    for (int i = 1; i < argc && argv[i][0] == '-'; ) {
        if (str_eq(argv[i], "-s")) { i++; continue; }
        if (i + 1 >= argc) break;
        if (!str_eq(argv[i], "-r")) { i += 2; continue; }
        char c = (char)(argv[i + 1][0] & ~32);
        if (c != 'J' && c != 'U' && c != 'E') {
            uprintf("-r: j (Japan, NTSC), u (America, NTSC) or e (Europe, PAL)\n");
            return;
        }
        region = c;
        for (int k = i; k + 2 < argc; k++)
            argv[k] = argv[k + 2];
        argc -= 2;
        break;
    }
    s32x_play_region(region);
    cmd_game(argc, argv, s32x_play);
    s32x_play_region(0);
}

static void cmd_rf(int argc, char **argv)
{
    if (argc > 1 && str_eq(argv[1], "live")) {         /* (its chart has the TV until Esc: then what was there) */
        int console = gfx_view_console(), explorer = explorer_shown();
        if (explorer)
            explorer_hide();
        demo_shown = 0;
        (void)rf_command(argc, argv);
        picture_back(console, explorer);
        return;
    }
    if (argc > 1 && str_eq(argv[1], "spectrum")) {     /* (its chart takes the test screen's picture) */
        if (explorer_shown())
            explorer_hide();
        demo_shown = 0;
    }
    (void)rf_command(argc, argv);
}

static void cmd_view(int argc, char **argv)
{
    int once = 0, mode = 0, first = 1;
    for (; first < argc && argv[first][0] == '-' && argv[first][1] && !argv[first][2]; first++) {
        if (argv[first][1] == '1')
            once = 1;
        else if (argv[first][1] == 's')
            mode = 1;
        else if (argv[first][1] == 'c')
            mode = 2;
        else
            break;
    }
    if (argc <= first) {
        uprintf("usage: view [-1] [-s | -c] <picture file>\n");
        return;
    }
    if (mode == 2) {                    /* (nothing shown: the console stays) */
        view_set_mode(2);
        view_file(joined(argc - first + 1, argv + first - 1), 1);
        view_set_mode(0);
        return;
    }
    int console = gfx_view_console(), explorer = explorer_shown();
    if (explorer)
        explorer_hide();
    demo_shown = 0;
    view_set_mode(mode);
    view_file(joined(argc - first + 1, argv + first - 1), once);
    view_set_mode(0);
    if (!once)
        picture_back(console, explorer);
}

static void cmd_stty(int argc, char **argv)
{
    u32 n = 0, baud = 0;
    if ((argc > 1 && !parse_u32(argv[1], &n)) || (argc > 2 && (!parse_u32(argv[2], &baud) || !baud)) || argc > 3) {
        uprintf("usage: stty [port] [baud]\n");
        return;
    }
    serial_stty(argc > 1 ? (int)n : -1, baud);
}

/* mkdir / rmdir / rm / touch: one path (spaces in it allowed) */
static int one_path(int argc, char **argv)
{
    if (argc < 2)
        uprintf("usage: %s <path>\n", argv[0]);
    return argc >= 2;
}

static void cmd_mkdir(int argc, char **argv)
{
    if (one_path(argc, argv))
        disk_mkdir(joined(argc, argv));
}

static void cmd_rmdir(int argc, char **argv)
{
    if (one_path(argc, argv))
        disk_rmdir(joined(argc, argv));
}

static void cmd_rm(int argc, char **argv)
{
    if (argc >= 3 && str_eq(argv[1], "-r"))
        disk_rm_r(joined(argc - 1, argv + 1));  /* (a directory and everything in it) */
    else if (one_path(argc, argv))
        disk_rm(joined(argc, argv));
}

/* 'head [-n N] path' / 'tail [-n N] path' (10 lines when no -n) */
static void head_tail(int argc, char **argv, void (*fn)(const char *, u32))
{
    u32 lines = 10;
    int first = 1;
    if (argc >= 3 && str_eq(argv[1], "-n")) {
        if (!parse_u32(argv[2], &lines) || !lines) {
            uprintf("usage: %s [-n lines] <path>\n", argv[0]);
            return;
        }
        first = 3;
    }
    if (argc <= first) {
        uprintf("usage: %s [-n lines] <path>\n", argv[0]);
        return;
    }
    fn(joined(argc - first + 1, argv + first - 1), lines);
}

static void cmd_head(int argc, char **argv)
{
    head_tail(argc, argv, disk_head);
}

static void cmd_tail(int argc, char **argv)
{
    head_tail(argc, argv, disk_tail);
}

static void cmd_df(int argc, char **argv)
{
    disk_df(joined(argc, argv));
}

static void cmd_ntfs(int argc, char **argv)
{
    if (argc > 3)
        uprintf("usage: ntfs [n: [reset-journal]]\n");
    else
        disk_ntfs(argc > 1 ? argv[1] : "", argc > 2 ? argv[2] : "");
}

static void cmd_touch(int argc, char **argv)
{
    if (one_path(argc, argv))
        disk_touch(joined(argc, argv));
}

/* cp / mv: two paths (a name with spaces in quotes) */
static int two_paths(int argc, char **argv)
{
    if (argc != 3)
        uprintf("usage: %s <from> <to> (a name with spaces in quotes: %s \"my file.txt\" 4:/docs)\n", argv[0],
                argv[0]);
    return argc == 3;
}

static void cmd_cp(int argc, char **argv)
{
    if (argc == 4 && str_eq(argv[1], "-r"))
        disk_cp_r(argv[2], argv[3]);            /* (a directory with everything in it) */
    else if (two_paths(argc, argv))
        disk_cp(argv[1], argv[2]);
}

static void cmd_mv(int argc, char **argv)
{
    if (two_paths(argc, argv))
        disk_mv(argv[1], argv[2]);
}

static void cmd_tty(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    serial_list();
}

/* 'cu 2', 'cu ttyUSB2', 'cu -l /dev/ttyUSB2' (as Linux's cu); without a port: the AT port */
static void cmd_cu(int argc, char **argv)
{
    int port = -1;
    if (argc > 1) {
        const char *s = argc > 2 && str_eq(argv[1], "-l") ? argv[2] : argv[1];
        static const char *const prefixes[] = {"/dev/", "ttyUSB", "ttyACM"};
        for (int i = 0; i < 3; i++) {
            int k = 0;
            while (prefixes[i][k] && s[k] == prefixes[i][k])
                k++;
            if (!prefixes[i][k])
                s += k;
        }
        u32 v;
        if (!parse_u32(s, &v) || v >= SERIAL_PORTS) {
            uprintf("usage: cu [n] -- n: the port's number as 'tty' lists it, ttyUSB<n> / ttyACM<n> (without it: "
                    "the AT port)\n");
            return;
        }
        port = (int)v;
    }
    serial_cu(port);
}

static void cmd_at(int argc, char **argv)       /* (verbatim: argv[1] is the rest of the line as typed) */
{
    serial_at(argc > 1 ? argv[1] : "");
}

/* the commands that get the rest of the line as typed (raw_rest) as their one argument */
static int verbatim(const struct command *c)
{
    return c->run == cmd_at;
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


/* a command's output going into a file ('command > path') waits here */
#define CAPTURE_MAX (64 * 1024)
static u8 capture[CAPTURE_MAX];


/* the line in words: spaces between them, "..." or '...' keeping spaces (and
   the other quote) in one, a backslash the character after it.  A '>' or
   '>>' outside quotes (with or without a space after it) names the file the
   command's output goes into: *redirect, *append */
static int split_line(char *words, char **argv, const char **redirect, int *append)
{
    const char *p = line, *first = 0, *second = 0, *to_redirect = 0;
    char *w = words;
    int argc = 0;
    *redirect = 0;
    *append = 0;
    for (;;) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        int to_file = 0;
        if (*p != '>' && !first)
            first = p;
        else if (*p != '>' && argc == 1 && !second)
            second = p;
        if (*p == '>') {
            if (!to_redirect)
                to_redirect = p;
            to_file = p[1] == '>' ? 2 : 1;
            p += to_file;
            while (*p == ' ' || *p == '\t')
                p++;
        }
        char *start = w;
        while (*p && *p != ' ' && *p != '\t' && !(*p == '>' && !to_file)) {
            if (*p == '"' || *p == '\'') {
                char q = *p++;
                while (*p && *p != q)
                    *w++ = *p++;
                if (*p)
                    p++;
            } else if (*p == '\\' && p[1]) {
                p++;
                *w++ = *p++;
            } else {
                *w++ = *p++;
            }
        }
        *w++ = 0;
        if (to_file) {
            *redirect = start;
            *append = to_file == 2;
        } else if (argc < ARGS_MAX) {
            argv[argc++] = start;
        }
    }
    /* raw_line: from the first word to a redirect (or the end), trailing spaces left out; raw_rest in it */
    const char *end = to_redirect && to_redirect > first ? to_redirect : p;
    while (first && end > first && (end[-1] == ' ' || end[-1] == '\t'))
        end--;
    int n = 0;
    for (const char *s = first; s && s < end && n < LINE_MAX - 1; s++)
        raw_line[n++] = *s;
    raw_line[n] = 0;
    raw_rest = second && second < end ? raw_line + (second - first) : raw_line + n;
    return argc;
}

static void run_line(void)
{
    char words[2 * LINE_MAX];
    char *argv[ARGS_MAX];
    const char *redirect;
    int append;
    int argc = split_line(words, argv, &redirect, &append);
    if (argc == 0)
        return;
    char kept[LINE_MAX];                                /* (without the space a Tab left at its end) */
    str_copy(kept, line, LINE_MAX);
    for (int n = str_len(kept); n > 0 && kept[n - 1] == ' '; n--)
        kept[n - 1] = 0;
    history_add(kept);
    str_copy(last_command, line, sizeof(last_command));
    commands_run++;
    update_uart_box();
    if (argv[0][0] == '/' && argv[0][1])            /* "/restart" as "restart" */
        argv[0]++;
    const struct command *c = commands;
    while (c->name && !str_eq(c->name, argv[0]))
        c++;
    void (*run)(int, char **) = c->run;
    char *as_typed[2] = {argv[0], (char *)raw_rest}, **av = argv;
    if (!c->name) {
        if (!serial_count() || !at_prefixed(argv[0])) {  /* ("AT..." typed: for the modem, when there is one) */
            uprintf("unknown command '%s' -- type 'help'\n", argv[0]);
            return;
        }
        run = cmd_at;                                   /* "AT+CSQ" as "at AT+CSQ" */
        as_typed[1] = raw_line + (raw_line[0] == '/');
    }
    if (!c->name || verbatim(c)) {
        argc = 2;
        av = as_typed;
    }
    if (!redirect) {
        run(argc, av);
        return;
    }
    if (!redirect[0]) {
        uprintf("a file name after '%s'\n", append ? ">>" : ">");
        return;
    }
    u32 over;
    uart_capture(capture, CAPTURE_MAX);
    run(argc, av);
    u32 n = uart_capture_end(&over);
    disk_write_file(redirect, capture, n, append);
    if (over)
        uprintf("the output was longer than %u bytes: the file has its first %u\n", CAPTURE_MAX, CAPTURE_MAX);
}

/* ---- the line editor ----
   Keys (a terminal's, the telnet client's and the USB keyboard's alike): Left / Right, Home / End (Ctrl-A /
   Ctrl-E), Ctrl-Left / Ctrl-Right (Alt-B / Alt-F) a word; Backspace, Delete (Ctrl-D) at the cursor, Ctrl-W the
   word before it, Ctrl-U all before it, Ctrl-K all after it, Ctrl-Y puts back what those took; Up / Down
   (Ctrl-P / Ctrl-N) the commands before that start with what is typed; Ctrl-R looks for one holding what is
   typed next; Tab completes a command's name, its first word's choices as its help names them
   ("rf <init|tune|...>"), a disk's file or directory -- a second Tab lists them; Ctrl-L clears the screen;
   Ctrl-C drops the line.  "!!", "!n", "!-n", "!text" at a line's start run a command of the history again. */
static int typing_on_usb;               /* cli_input is fed by the USB keyboard */
static int esc_mod;                     /* ESC [ n ; mod x: the modifier (5 Ctrl, 3 Alt) */

static void set_line(const char *s)
{
    str_copy(line, s, LINE_MAX);
    line_len = line_cur = str_len(line);
    show_line();
}

static void edited(void)                /* typed on: Up / Down start again from this line */
{
    history_pos = history_n;
    tabs = 0;
}

static int starts_with(const char *s, const char *p)
{
    while (*p)
        if (*s++ != *p++)
            return 0;
    return 1;
}

static int lower(int c)
{
    return c >= 'A' && c <= 'Z' ? c + 32 : c;
}

static int starts_nocase(const char *s, const char *p)
{
    while (*p)
        if (lower(*s++) != lower(*p++))
            return 0;
    return 1;
}

/* Up (-1) / Down (+1): the command before / after the one shown that starts with what was typed */
static void recall(int step)
{
    line[line_len] = 0;
    if (history_pos == history_n)
        str_copy(pending, line, LINE_MAX);
    for (int p = history_pos + step; p >= 0 && p <= history_n; p += step) {
        if (p == history_n) {
            history_pos = p;
            set_line(pending);
            return;
        }
        if (starts_with(history[p], pending) && !str_eq(history[p], line)) {
            history_pos = p;
            set_line(history[p]);
            return;
        }
    }
}

/* the cursor to p */
static void move_to(int p)
{
    if (p < 0)
        p = 0;
    if (p > line_len)
        p = line_len;
    if (p < line_cur)
        uprintf("\x1b[%dD", line_cur - p);
    else if (p > line_cur)
        uprintf("\x1b[%dC", p - line_cur);
    line_cur = p;
}

static int word_left(void)
{
    int p = line_cur;
    while (p > 0 && line[p - 1] == ' ')
        p--;
    while (p > 0 && line[p - 1] != ' ')
        p--;
    return p;
}

static int word_right(void)
{
    int p = line_cur;
    while (p < line_len && line[p] == ' ')
        p++;
    while (p < line_len && line[p] != ' ')
        p++;
    return p;
}

/* n characters at the cursor; the cursor after them */
static void insert_text(const char *s, int n)
{
    if (n > LINE_MAX - 1 - line_len)
        n = LINE_MAX - 1 - line_len;
    if (n <= 0)
        return;
    for (int i = line_len - 1; i >= line_cur; i--)
        line[i + n] = line[i];
    for (int i = 0; i < n; i++)
        line[line_cur + i] = s[i];
    line_len += n;
    line_cur += n;
    if (line_cur == line_len)                   /* (at the end: only the new characters printed) */
        for (int i = 0; i < n; i++)
            uart_putc(s[i]);
    else
        show_line();
}

/* n characters from `at` taken out (keep: into killed, for Ctrl-Y) */
static void delete_text(int at, int n, int keep)
{
    if (at < 0 || n <= 0 || at + n > line_len)
        return;
    int backspace_at_end = n == 1 && at + 1 == line_len && line_cur == line_len;
    if (keep) {
        for (int i = 0; i < n; i++)
            killed[i] = line[at + i];
        killed[n] = 0;
    }
    for (int i = at; i + n < line_len; i++)
        line[i] = line[i + n];
    line_len -= n;
    if (line_cur >= at + n)
        line_cur -= n;
    else if (line_cur > at)
        line_cur = at;
    if (backspace_at_end)
        uart_puts("\b \b");
    else
        show_line();
}

/* ---- Ctrl-R: the newest command holding what is typed; Ctrl-R again an older one ---- */
static int srch_on, srch_found;        /* the search is on; the history entry found (-1: none) */
static char srch_query[40], srch_before[LINE_MAX];
static int srch_len;

static int holds(const char *s, const char *q)
{
    if (!*q)
        return 1;
    for (; *s; s++)
        if (starts_with(s, q))
            return 1;
    return 0;
}

static void search_from(int p)
{
    srch_found = -1;
    for (; p >= 0; p--)
        if (holds(history[p], srch_query)) {
            srch_found = p;
            break;
        }
    uprintf("\r\x1b[K(history search)'%s': %s", srch_query, srch_found >= 0 ? history[srch_found] : "(none)");
}

/* a key while searching: 1 taken; 0 the search ended (the command found is the line now), the key then
   handled as usual */
static int search_key(int c)
{
    if (c == 0x12) {                                    /* Ctrl-R: an older one */
        search_from(srch_found > 0 ? srch_found - 1 : srch_found == 0 ? -1 : history_n - 1);
        return 1;
    }
    if (c == 0x08 || c == 0x7f) {
        if (srch_len)
            srch_query[--srch_len] = 0;
        search_from(history_n - 1);
        return 1;
    }
    if (c >= 0x20 && c <= 0x7e) {
        if (srch_len < (int)sizeof(srch_query) - 1) {
            srch_query[srch_len++] = (char)c;
            srch_query[srch_len] = 0;
        }
        search_from(srch_found >= 0 ? srch_found : history_n - 1);
        return 1;
    }
    srch_on = 0;
    edited();
    if (c == 0x03 || c == 0x07) {                       /* Ctrl-C, Ctrl-G: the line as it was */
        set_line(srch_before);
        return 1;
    }
    set_line(srch_found >= 0 ? history[srch_found] : srch_before);
    return 0;
}

/* ---- Tab ---- */
#define CANDIDATES 128
static struct disk_entry tab_entries[CANDIDATES];
static const char *tab_cand[CANDIDATES];
static u8 tab_dir[CANDIDATES];
static int tab_n;
static char dir_part[LINE_MAX];         /* a file's: the directory typed before its name ("4:/c64/") */
static char tab_choices[256];           /* a command's first word's choices, as its help names them */
static u8 tab_swallowed[512];           /* what reading a directory says (not printed in the middle of a line) */

static void add_cand(const char *s, int dir, const char *typed, int nocase)
{
    if (tab_n < CANDIDATES && (nocase ? starts_nocase(s, typed) : starts_with(s, typed))) {
        tab_cand[tab_n] = s;
        tab_dir[tab_n++] = (u8)dir;
    }
}

/* the word the cursor ends: where it starts in the line, its text without quotes and backslashes; which word
   of the line it is (0: the command) */
static int word_at(int *start, char *out, int size)
{
    int index = 0, at = line_cur, n = 0, in_word = 0;
    char q = 0;
    for (int i = 0; i < line_cur; i++) {
        char ch = line[i];
        if (!q && (ch == ' ' || ch == '\t')) {
            if (in_word)
                index++;
            in_word = 0;
            n = 0;
            continue;
        }
        if (!in_word) {
            in_word = 1;
            at = i;
        }
        if (q) {
            if (ch == q)
                q = 0;
            else if (n < size - 1)
                out[n++] = ch;
        } else if (ch == '"' || ch == '\'') {
            q = ch;
        } else if (ch == '\\' && i + 1 < line_cur) {
            if (n < size - 1)
                out[n++] = line[++i];
        } else if (ch == '>') {                         /* (a redirect's file: a word of its own) */
            index++;
            n = 0;
            at = i + 1;
        } else if (n < size - 1) {
            out[n++] = ch;
        }
    }
    out[n] = 0;
    if (!in_word)
        at = line_cur;
    *start = at;
    return index;
}

/* "<init|tune|status|...>" at the start of a command's arguments: its choices into tab_choices[] (words of
   lower-case letters, digits and '-' only -- "<MHz|channel>" names no words to type), how many */
static int command_choices(const char *args)
{
    int n = 0, count = 0;
    char close = args[0] == '<' ? '>' : args[0] == '[' ? ']' : 0;
    if (!close || args[1] == '-')       /* ("[-r j|u|e] ... <file>": an option and its values -- taken for
                                           choices, 'megadrive' completed "u" / "e" and no file's name) */
        return 0;
    const char *p = args + 1;
    for (;;) {
        const char *s = p;
        int good = 1;
        while (*p && *p != '|' && *p != close) {
            if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') || *p == '-'))
                good = 0;
            p++;
        }
        int k = (int)(p - s);
        if (good && k && n + k + 1 <= (int)sizeof(tab_choices)) {
            for (int i = 0; i < k; i++)
                tab_choices[n + i] = s[i];
            tab_choices[n + k] = 0;
            n += k + 1;
            count++;
        }
        if (*p != '|')
            break;
        p++;
    }
    return count >= 2 ? count : 0;                      /* (one word alone: "<file>"-like, not choices) */
}

/* a file or directory's name: the volumes (no directory typed, none current), else the directory's entries */
static void file_cands(const char *word, const char **typed)
{
    int slash = -1, colon = -1;
    for (int i = 0; word[i]; i++) {
        if (word[i] == '/')
            slash = i;
        if (word[i] == ':' && colon < 0)
            colon = i;
    }
    dir_part[0] = 0;
    *typed = word + slash + 1;
    char path[LINE_MAX];
    if (slash < 0 && colon >= 0 && !word[colon + 1]) {           /* "4:": its top */
        usnprintf(dir_part, sizeof(dir_part), "%s/", word);
        *typed = "";
    } else if (slash < 0 && colon < 0 && !disk_cwd()[0]) {         /* the volumes: "4" -> "4:/" */
        int n = disk_volumes(tab_entries, CANDIDATES);
        for (int i = 0; i < n; i++) {
            char *s = tab_entries[i].name;
            int k = 0;
            while (s[k] && s[k] != ':')
                k++;
            if (!s[k])
                continue;
            s[k + 1] = '/';
            s[k + 2] = 0;
            add_cand(s, 2, word, 1);
        }
        return;
    } else {
        for (int i = 0; i <= slash && i < LINE_MAX - 1; i++)
            dir_part[i] = word[i];
        dir_part[slash + 1 > 0 ? slash + 1 : 0] = 0;
    }
    /* the directory to read: as typed, without its last '/' (but for a volume's top, "4:/", or "/") */
    str_copy(path, dir_part[0] ? dir_part : disk_cwd(), sizeof(path));
    int n = str_len(path);
    if (n > 1 && path[n - 1] == '/' && path[n - 2] != ':')
        path[n - 1] = 0;
    u32 total, over;
    uart_capture(tab_swallowed, sizeof(tab_swallowed));
    n = disk_dir_read(path, tab_entries, CANDIDATES, &total);
    (void)uart_capture_end(&over);
    for (int i = 0; i < n; i++) {
        const char *s = tab_entries[i].name;
        if (tab_entries[i].kind == DISK_VOLUME || str_eq(s, ".") || str_eq(s, ".."))
            continue;
        add_cand(s, tab_entries[i].kind == DISK_DIR, *typed, 1);
    }
}

/* the word from `start` to the cursor replaced by a + b ("..." around it when it holds a space); finished: a
   space after it (a quote closed first) */
static void replace_word(int start, const char *a, const char *b, int finished)
{
    char t[LINE_MAX];
    int n = 0, quote = 0;
    for (const char *s = a; *s; s++)
        quote |= *s == ' ';
    for (const char *s = b; *s; s++)
        quote |= *s == ' ';
    if (quote)
        t[n++] = '"';
    for (const char *s = a; *s && n < LINE_MAX - 3; s++)
        t[n++] = *s;
    for (const char *s = b; *s && n < LINE_MAX - 3; s++)
        t[n++] = *s;
    if (quote && finished)
        t[n++] = '"';
    if (finished)
        t[n++] = ' ';
    int k = line_cur - start;
    for (int i = start; i + k < line_len; i++)
        line[i] = line[i + k];
    line_len -= k;
    line_cur = start;
    if (n > LINE_MAX - 1 - line_len)
        n = LINE_MAX - 1 - line_len;
    for (int i = line_len - 1; i >= line_cur; i--)
        line[i + n] = line[i];
    for (int i = 0; i < n; i++)
        line[line_cur + i] = t[i];
    line_len += n;
    line_cur += n;
    show_line();
}

static void list_cands(void)
{
    for (int i = 1; i < tab_n; i++)                     /* (in order: a few dozen at most) */
        for (int j = i; j > 0; j--) {
            const char *x = tab_cand[j - 1], *y = tab_cand[j];
            while (*x && lower(*x) == lower(*y))
                x++, y++;
            if (lower(*x) <= lower(*y))
                break;
            const char *t = tab_cand[j];
            u8 d = tab_dir[j];
            tab_cand[j] = tab_cand[j - 1], tab_dir[j] = tab_dir[j - 1];
            tab_cand[j - 1] = t, tab_dir[j - 1] = d;
        }
    int w = 0;
    for (int i = 0; i < tab_n; i++) {
        int n = str_len(tab_cand[i]) + (tab_dir[i] == 1);
        if (n > w)
            w = n;
    }
    w += 2;
    int per = w < 78 ? 78 / w : 1;
    uart_puts("\r\n");
    for (int i = 0; i < tab_n; i++) {
        int n = str_len(tab_cand[i]) + (tab_dir[i] == 1);
        uart_puts(tab_cand[i]);
        if (tab_dir[i] == 1)
            uart_putc('/');
        if ((i + 1) % per == 0 || i == tab_n - 1)
            uart_puts("\r\n");
        else
            for (; n < w; n++)
                uart_putc(' ');
    }
    if (tab_n == CANDIDATES)
        uprintf("(and more: type more of the name)\n");
    show_line();
}

static void complete(void)
{
    char word[LINE_MAX], first[LINE_MAX];
    const char *typed;
    int start, index = word_at(&start, word, sizeof(word)), files = 0, fixed = 0;
    tab_n = 0;
    dir_part[0] = 0;
    if (index == 0) {
        if (word[0] == '/') {                           /* ("/restart") */
            dir_part[0] = '/';
            dir_part[1] = 0;
        }
        typed = word + (word[0] == '/');
        for (const struct command *c = commands; c->name; c++)
            add_cand(c->name, 0, typed, 0);
    } else {
        int i = 0, k = 0;
        while (line[i] == ' ')
            i++;
        if (line[i] == '/')
            i++;
        while (line[i] && line[i] != ' ' && k < LINE_MAX - 1)
            first[k++] = line[i++];
        first[k] = 0;
        const struct command *c = commands;
        while (c->name && !str_eq(c->name, first))
            c++;
        typed = word;
        if (index == 1 && str_eq(first, "help")) {
            for (c = commands; c->name; c++)
                add_cand(c->name, 0, typed, 0);
            fixed = 1;
        } else if (index == 1 && c->name && (k = command_choices(c->args)) > 0) {
            const char *s = tab_choices;
            for (int j = 0; j < k; j++, s += str_len(s) + 1)
                add_cand(s, 0, typed, 0);
            fixed = 1;
        }
        if (!fixed) {
            file_cands(word, &typed);
            files = 1;
        }
    }
    if (!tab_n)
        return;
    /* what they all start with (a file's name: whatever its letters' case) */
    int common = str_len(tab_cand[0]);
    for (int i = 1; i < tab_n; i++) {
        int k = 0;
        const char *x = tab_cand[i], *y = tab_cand[0];
        while (k < common && x[k] && (files ? lower(x[k]) == lower(y[k]) : x[k] == y[k]))
            k++;
        common = k;
    }
    if (tab_n == 1) {
        char name[DISK_ENTRY_NAME + 2];
        usnprintf(name, sizeof(name), "%s%s", tab_cand[0], tab_dir[0] == 1 ? "/" : "");
        replace_word(start, dir_part, name, tab_dir[0] == 0);
        tabs = 0;
        return;
    }
    if (common > str_len(typed)) {
        char part[DISK_ENTRY_NAME + 1];
        int k = 0;
        for (; k < common && k < DISK_ENTRY_NAME; k++)
            part[k] = tab_cand[0][k];
        part[k] = 0;
        replace_word(start, dir_part, part, 0);
        tabs = 0;
        return;
    }
    tabs++;                                             /* a short list at once, a long one at the second Tab */
    if ((tabs == 1 && tab_n <= 32) || (tabs == 2 && tab_n > 32))
        list_cands();
}

/* "!!", "!n", "!-n", "!text" at the line's start: that command of the history in the line (what follows kept,
   the line printed as it now is) -- 1; 0 not one; -1 none such (said) */
static int expand_history(void)
{
    if (line[0] != '!' || !line[1] || line[1] == ' ')
        return 0;
    int p = 1, at = -1;
    if (line[1] == '!') {
        at = history_n - 1;
        p = 2;
    } else if ((line[1] >= '0' && line[1] <= '9') || (line[1] == '-' && line[2] >= '0' && line[2] <= '9')) {
        int neg = line[1] == '-', n = 0;
        p = 1 + neg;
        while (line[p] >= '0' && line[p] <= '9')
            n = n * 10 + (line[p++] - '0');
        at = neg ? history_n - n : n - 1;
    } else {
        char want[LINE_MAX];
        int k = 0;
        while (line[p] && line[p] != ' ' && k < LINE_MAX - 1)
            want[k++] = line[p++];
        want[k] = 0;
        for (int i = history_n - 1; i >= 0 && at < 0; i--)
            if (starts_with(history[i], want))
                at = i;
    }
    if (at < 0 || at >= history_n) {
        line[p] = 0;
        uprintf("%s: not in the history ('history' lists it)\n", line);
        return -1;
    }
    char t[LINE_MAX];
    usnprintf(t, sizeof(t), "%s%s", history[at], line + p);
    str_copy(line, t, LINE_MAX);
    line_len = line_cur = str_len(line);
    uprintf("%s\n", line);
    return 1;
}

/* an escape sequence's end: ESC [ c, ESC [ n c, ESC [ n ; mod c, ESC O c */
static void esc_key(int c, int num, int mod)
{
    int word = mod >= 2;                                /* (Ctrl- or Alt- with an arrow: a word) */
    switch (c) {
    case 'A': recall(-1); return;
    case 'B': recall(1); return;
    case 'C': move_to(word ? word_right() : line_cur + 1); return;
    case 'D': move_to(word ? word_left() : line_cur - 1); return;
    case 'H': move_to(0); return;
    case 'F': move_to(line_len); return;
    case '~':
        if (num == 5 || num == 6)
            console_scroll(num == 5 ? 1 : -1);          /* the TV's console looks back or forward */
        else if (num == 3) {
            edited();
            delete_text(line_cur, 1, 0);                /* Delete */
        } else if (num == 1 || num == 7)
            move_to(0);
        else if (num == 4 || num == 8)
            move_to(line_len);
        return;                                         /* (Insert, F-keys: the explorer's) */
    }
}

static void cli_input(int c)
{
    line_dirty = 1;
    if (srch_on && !esc_state && search_key(c))
        return;
    if (c != 0x09)
        tabs = 0;
    if (esc_state == 1) {
        esc_state = 0;
        if (c == '[' || c == 'O') {
            esc_state = c == '[' ? 2 : 4;
            esc_num = 0;
            return;
        }
        if (c == 'b' || c == 'f') {                     /* Alt-B, Alt-F: a word back / on */
            move_to(c == 'b' ? word_left() : word_right());
        } else if (c == 0x7f || c == 0x08) {            /* Alt-Backspace: the word before */
            edited();
            int p = word_left();
            delete_text(p, line_cur - p, 1);
        }
        return;
    }
    if (esc_state == 2 || esc_state == 3) {             /* ESC [ (n) ...  /  ESC [ n ; (mod) ... */
        if (c >= '0' && c <= '9') {
            if (esc_state == 2 && esc_num < 1000)
                esc_num = esc_num * 10 + (c - '0');
            else if (esc_state == 3 && esc_mod < 100)
                esc_mod = esc_mod * 10 + (c - '0');
            return;
        }
        if (c == ';') {
            esc_state = 3;
            esc_mod = 0;
            return;
        }
        int mod = esc_state == 3 ? esc_mod : 0;
        esc_state = 0;
        esc_key(c, esc_num, mod);
        return;
    }
    if (esc_state == 4) {                               /* ESC O x: Home / End / arrows of some terminals */
        esc_state = 0;
        esc_key(c, 0, 0);
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
        if (expand_history() >= 0) {
            net_command(1);                 /* (a telnet client's typing and output go on during it: net.c) */
            run_line();
            net_command(0);
        }
        line_len = line_cur = 0;
        edited();
        prompt();
        return;
    case 0x08:
    case 0x7f:
        edited();
        if (line_cur)
            delete_text(line_cur - 1, 1, 0);
        return;
    case 0x03:                              /* Ctrl-C: the line dropped */
        line_len = line_cur = 0;
        edited();
        uart_puts("^C\r\n");
        prompt();
        return;
    case 0x01: move_to(0); return;                      /* Ctrl-A */
    case 0x05: move_to(line_len); return;               /* Ctrl-E */
    case 0x02: move_to(line_cur - 1); return;           /* Ctrl-B */
    case 0x06: move_to(line_cur + 1); return;           /* Ctrl-F */
    case 0x10: recall(-1); return;                      /* Ctrl-P */
    case 0x0E: recall(1); return;                       /* Ctrl-N */
    case 0x04:                                          /* Ctrl-D: the character at the cursor */
        edited();
        delete_text(line_cur, 1, 0);
        return;
    case 0x0B:                                          /* Ctrl-K: all after the cursor */
        edited();
        delete_text(line_cur, line_len - line_cur, 1);
        return;
    case 0x15:                                          /* Ctrl-U: all before it */
        edited();
        delete_text(0, line_cur, 1);
        return;
    case 0x17: {                                        /* Ctrl-W: the word before it */
        edited();
        int p = word_left();
        delete_text(p, line_cur - p, 1);
        return;
    }
    case 0x19:                                          /* Ctrl-Y: what those took, back */
        edited();
        insert_text(killed, str_len(killed));
        return;
    case 0x0C:                                          /* Ctrl-L: the screen cleared */
        uart_puts("\x1b[2J\x1b[H");
        show_line();
        return;
    case 0x12:                                          /* Ctrl-R: look through the history */
        line[line_len] = 0;
        str_copy(srch_before, line, LINE_MAX);
        srch_on = 1;
        srch_len = 0;
        srch_query[0] = 0;
        search_from(history_n - 1);
        return;
    case 0x09:                                          /* Tab */
        complete();
        return;
    }
    if (c < 0x20 || c > 0x7e)
        return;
    char ch = (char)c;
    edited();
    insert_text(&ch, 1);
    /* the UART updater's boot capture: 'c' sent again and again (on the UART) */
    if (!typing_on_usb && line_len == 3 && line_cur == 3 && line[0] == 'c' && line[1] == 'c' && line[2] == 'c')
        restart("\r\nBootloader capture requested ('ccc'): restarting via original bootloader");
}

/* a device on the port that did not answer when it came: tried again every
   3 s, ten times.  An LTE module (the A7670E) starting is connected for
   seconds before it answers: its chip's boot port first, then its own. */
#define USB_RETRIES 10
#define USB_RETRY_MS 3000

static void usb_try_again(void)
{
    int ok = usb_enumerate_quiet() == 0;
    usb_retry_next = now_ms() + USB_RETRY_MS;           /* (after the try: one can take seconds) */
    if (!ok && usb_retry++ < USB_RETRIES)
        return;
    usb_retry = ok ? 0 : -1;
    event_begin();
    if (ok) {
        uprintf("[usb] the device answers now: %s\n", usb_summary());
        if (serial_count())
            serial_list();
    } else {
        uprintf("[usb] the device still does not answer (%s): 'usb' tries again\n", usb_error_text());
    }
    update_usb_box();
    show_line();
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
    console_start();                            /* the TV shows the console, from the boot messages on */
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
    loop_since = last_poll;
    for (;;) {
        u64 pass_start = now_ticks(), t = pass_start;
        int c = uart_getc();
        if (c >= 0 && !(c == 3 && av_dismiss()))    /* (Ctrl-C: a picture 'play -k' left on the TV goes) */
            cli_input(c);
        usb_int_poll();                         /* the keyboard's interrupt endpoint (endpoint B) */
        const char *said = kbd_poll();          /* a USB keyboard's keys: as if typed on the UART */
        if (said) {
            event_begin();
            uprintf("[usb] %s\n", said);
            if (kbd_lost() && usb_connected()) {    /* it stopped answering: set it up again -- behind a hub that
                                                       port alone (the network adapter, disks untouched) */
                int ok = usb_set_up_again(kbd_device()) == 0;
                uprintf("[usb] %s\n", ok ? (kbd_active() ? "keyboard set up again" : "set up again: no keyboard now")
                                         : usb_error_text());
                update_usb_box();
            }
            show_line();
        }
        typing_on_usb = 1;
        while ((c = kbd_getc()) >= 0) {
            if (c == 3 && av_dismiss())         /* a picture 'play -k' left on the TV: Esc (kbd.c gives it
                                                   as Ctrl-C) gives the OSD back */
                continue;
            if (explorer_shown()) {
                explorer_key(c);                /* the explorer on the TV: its keys (Esc: the console again) */
                continue;
            }
            if (!gfx_view_console())
                show_console();                 /* the test screen: any key brings the console back -- and
                                                   types, so a command typed at once loses nothing */
            cli_input(c);
        }
        typing_on_usb = 0;
        loop_part(0, &t);
        said = eth_poll();                      /* the Ethernet port's frames, DHCP */
        if (said) {
            event_begin();
            uprintf("[eth] %s\n", said);
            show_line();
        }
        loop_part(1, &t);
        said = mouse_poll();                    /* a USB mouse: the pointer, its buttons */
        if (said) {
            event_begin();
            uprintf("[usb] %s\n", said);
            show_line();
        }
        loop_part(2, &t);
        if (explorer_poll())                    /* the explorer: the shell's 'cd' followed, its own done */
            show_line();                        /* (it changed the current directory: the prompt shows it) */
        if (ir_poll(&ev)) {
            if (ev.valid && !ev.repeat) {       /* EXIT: a picture 'play -k' left on the TV goes */
                const char *key = ir_key_name(ev.code);
                if (key && key[0] == 'E' && key[1] == 'X')
                    (void)av_dismiss();
            }
            event_begin();
            on_ir(&ev);
            show_line();
        }
        console_service();                      /* the TV's console: what changed, the cursor's blink */
        gfx_cursor_refresh();                   /* (drawing under the mouse pointer took it away) */
        loop_part(3, &t);
        u64 now = now_ms();
        if (line_dirty && now - last_line_drawn >= 50) {
            last_line_drawn = now;
            update_line_box();
        }
        if (now - last_poll >= 100) {
            last_poll = now;
            if (poll_panel())
                show_line();
            int bounced = 0;
            if (usb_connected() != usb_shown || (bounced = usb_shown && usb_bounced())) {
                int connected = usb_connected();
                event_begin();
                uprintf("[usb] %s\n", bounced ? "the device went away and came back: setting it up again"
                                              : connected ? "device connected" : "device removed");
                usb_retry = 0;
                if (connected)
                    usb_enumerate();            /* its name on the screen; a keyboard starts typing */
                else
                    usb_removed();
                update_usb_box();
                show_line();
            } else if (usb_shown && usb_retry > 0 && now >= usb_retry_next) {
                usb_try_again();
            } else if (usb_shown && !usb_retry && !usb_present(1)) {
                usb_retry = 1;                  /* connected, nothing set up: it did not answer when it came, or a
                                                   set-up elsewhere failed ('at' / 'cu' after a module's
                                                   restart, a hub's recovery) -- tried again */
                usb_retry_next = now + USB_RETRY_MS;
            } else if (usb_shown && usb_hub_poll(event_begin)) {    /* a hub's ports, one each time */
                update_usb_box();
                show_line();
            }
        }
        if (now - last_second >= 1000) {
            last_second = now;
            update_uptime();
        }
        loop_part(4, &t);
        loop_pass(pass_start);
    }
}
