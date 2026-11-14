/* A USB keyboard typing into the command line.

   usb.c finds a keyboard while it enumerates the device (an interface of
   class 3 = HID, protocol 1 = keyboard) and starts it here: SET_PROTOCOL
   selects the boot protocol (the 8-byte report a PC BIOS reads: modifier
   bits, a reserved byte, up to six keys held), SET_IDLE(0) asks for a report
   only when something changes.  The reports are read in one of two ways:
     - from the keyboard's interrupt endpoint, as a PC does: an IN transfer
       that stays pending on the controller's endpoint B (usb_in_start) and
       is asked again every millisecond until a key goes down or up -- the
       way that works with every keyboard, and the one used first;
     - with GET_REPORT over endpoint 0 every 16 ms ('usb kbd report', or by
       itself when the interrupt endpoint stalls).  Not every keyboard
       answers it with its keys: the low-speed one this was tested with
       (1a2c:2d23) always answers eight zero bytes.
   A key going down becomes what the UART would deliver for it (US layout;
   Enter = CR, Backspace = BS, Escape = Ctrl-C, Up / Down = ESC [ A / B,
   PgUp / PgDn = ESC [ 5 ~ / ESC [ 6 ~ (the TV's console looks back),
   Ctrl with a letter = its control code); a held key repeats after 500 ms,
   25 times a second.  Caps Lock is kept here (the keyboard's LED stays as it
   is: the demo sends no output reports).  'usb kbd raw on' prints every
   report that differs from the one before, as it arrives. */
#include "hw.h"

#define MODE_INTERRUPT    0
#define MODE_REPORT       1
#define REPORT_PERIOD_MS  16
#define REPEAT_DELAY_MS   500
#define REPEAT_PERIOD_MS  40
#define QUEUE             64

static int active, mode;
static u8 device;                       /* the keyboard's address on the bus */
static u8 iface, ep, interval;
static u16 ep_size;
static u8 held[8];                      /* the last report: modifiers, 0, six keys */
static u64 next_poll;
static int fails, armed;
static int via_d;                       /* read through endpoint D, which polls by itself (else endpoint B) */
static int switched;                    /* the way of reading was changed by itself once already */
static u32 reports, keys, errors;
static u32 int_errors;                  /* the interrupt endpoint's, since it was chosen */
static u8 last_raw[8];                  /* the report raw mode printed last */
static int silent;                      /* reads in a row without an answer (not a stall) */
static int lost;                        /* it stopped answering: main.c sets the device up again */
static int set_ups;                     /* such set-ups since the last report */
#define SET_UPS_MAX 3
static u8 caps;
static u8 repeat_key;
static u64 repeat_at;
static char queue[QUEUE];
static int q_head, q_tail;
static char message[176];
static int raw;                         /* 'usb kbd raw on': every report that differs is printed */

/* US layout, usages 0x04 (a) .. 0x38 (/) */
static const char plain[] = "abcdefghijklmnopqrstuvwxyz1234567890\r\x03\x08\t -=[]\\#;'`,./";
static const char shifted[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()\r\x03\x08\t _+{}|~:\"~<>?";

int kbd_active(void)
{
    return active;
}

u8 kbd_device(void)
{
    return active ? device : 0;
}

static void push(char c)
{
    int next = (q_head + 1) % QUEUE;
    if (next != q_tail) {
        queue[q_head] = c;
        q_head = next;
    }
}

int kbd_getc(void)
{
    if (q_tail == q_head)
        return -1;
    char c = queue[q_tail];
    q_tail = (q_tail + 1) % QUEUE;
    return (u8)c;
}

/* the characters of key `k` going down with the modifiers `mods`; 1 when it
   repeats while held */
static int key_down(u8 k, u8 mods)
{
    int shift = (mods & 0x22) != 0, ctrl = (mods & 0x11) != 0;
    if (k >= 0x04 && k <= 0x38) {
        char c = (shift ? shifted : plain)[k - 0x04];
        if (k <= 0x1D) {                                  /* a letter */
            if (caps)
                c ^= 0x20;
            if (ctrl)
                c = (char)((c | 0x20) - 'a' + 1);         /* Ctrl-A .. Ctrl-Z */
        }
        push(c);
        return k != 0x28 && k != 0x29 && k != 0x2B;      /* not Enter, Escape, Tab */
    }
    if (k >= 0x59 && k <= 0x62) {                         /* keypad 1..9, 0 */
        push(k == 0x62 ? '0' : (char)('1' + k - 0x59));
        return 1;
    }
    switch (k) {
    case 0x39: caps ^= 1; return 0;                       /* Caps Lock */
    case 0x52: push(0x1b); push('['); push('A'); return 1;   /* Up: the line before */
    case 0x51: push(0x1b); push('['); push('B'); return 1;   /* Down */
    case 0x4B: push(0x1b); push('['); push('5'); push('~'); return 1;   /* PgUp: the console looks back */
    case 0x4E: push(0x1b); push('['); push('6'); push('~'); return 1;   /* PgDn */
    case 0x4C: push(0x08); return 1;                      /* Delete: as Backspace (no cursor) */
    case 0x54: push('/'); return 1;                       /* keypad / * - + Enter . */
    case 0x55: push('*'); return 1;
    case 0x56: push('-'); return 1;
    case 0x57: push('+'); return 1;
    case 0x58: push('\r'); return 0;
    case 0x63: push('.'); return 1;
    }
    return 0;
}

static int held_key(const u8 *report, u8 k)
{
    for (int i = 2; i < 8; i++)
        if (report[i] == k)
            return 1;
    return 0;
}

static void on_report(const u8 *r, int n)
{
    u8 now[8] = {0};
    for (int i = 0; i < n && i < 8; i++)
        now[i] = r[i];
    reports++;
    if (now[2] == 0x01)
        return;                                           /* ErrorRollOver: too many keys at once */
    for (int i = 2; i < 8; i++) {
        u8 k = now[i];
        if (k < 0x04 || held_key(held, k))
            continue;
        keys++;
        if (key_down(k, now[0])) {
            repeat_key = k;
            repeat_at = now_ms() + REPEAT_DELAY_MS;
        } else {
            repeat_key = 0;
        }
    }
    if (repeat_key && !held_key(now, repeat_key))
        repeat_key = 0;
    for (int i = 0; i < 8; i++)
        held[i] = now[i];
}

static void disarm(void)                /* (its interrupt endpoint no longer read) */
{
    if (via_d)
        usb_epd_close();
    else
        usb_int_close(0);
}

void kbd_stop(void)
{
    if (active && mode == MODE_INTERRUPT && armed)
        disarm();
    active = 0;
    armed = 0;
    repeat_key = 0;
    q_head = q_tail = 0;
}

/* after SET_CONFIGURATION: the keyboard's device (its address), interface and
   interrupt endpoint; a line saying how it is read */
const char *kbd_start(u8 address, u8 interface, u8 endpoint, u16 size, u8 every)
{
    device = address;
    iface = interface;
    ep = endpoint;
    ep_size = size ? size : 8;
    interval = every ? every : 10;
    for (int i = 0; i < 8; i++)
        held[i] = 0;
    caps = 0;
    repeat_key = 0;
    q_head = q_tail = 0;
    fails = 0;
    armed = 0;
    switched = 0;
    reports = keys = errors = int_errors = 0;
    for (int i = 0; i < 8; i++)
        last_raw[i] = 0;
    silent = 0;
    lost = 0;
    mode = MODE_INTERRUPT;
    int proto = usb_request(device, 0x21, 0x0B, 0, iface, 0, 0, 100);    /* SET_PROTOCOL: boot */
    int idle = usb_request(device, 0x21, 0x0A, 0, iface, 0, 0, 100);     /* SET_IDLE: only on a change */
    active = 1;
    next_poll = now_ms();
    usnprintf(message, sizeof(message), "keyboard on interface %u: boot protocol%s, SET_IDLE %s; "
              "reading its interrupt endpoint %02x -- type on it", iface, proto < 0 ? " NOT set" : "",
              idle < 0 ? "refused" : "set", ep);
    return message;
}

void kbd_set_mode(int interrupt)
{
    if (!active)
        return;
    if (mode == MODE_INTERRUPT && armed)
        disarm();
    armed = 0;
    fails = 0;
    silent = 0;
    int_errors = 0;
    switched = 0;
    mode = interrupt ? MODE_INTERRUPT : MODE_REPORT;
    next_poll = now_ms();
}

void kbd_set_raw(int on)
{
    raw = on;
}

/* 1 when the keyboard stopped answering and should be set up again (main.c
   enumerates the device; kbd_start clears it) */
int kbd_lost(void)
{
    return lost;
}

/* a read without an answer at all -- not a stall: after three in a row the
   device was most likely reset (a display set-up's system stores do that)
   or lost; it is set up again, three times at most before a report */
static const char *no_answer(void)
{
    if (!usb_present(device))
        return 0;                       /* unplugged: the main loop reports that and stops it */
    if (++silent < 3)
        return 0;
    silent = 0;
    if (++set_ups > SET_UPS_MAX) {
        usnprintf(message, sizeof(message), "keyboard: no answer (%s) after %u set-ups -- given up; "
                  "'usb' tries again", usb_error_text(), SET_UPS_MAX);
        kbd_stop();
        return message;
    }
    lost = 1;
    usnprintf(message, sizeof(message), "keyboard: no answer (%s) -- setting it up again", usb_error_text());
    return message;
}

/* a stall of the way the keyboard is read, three times in a row: the other
   way is taken -- once; when that stalls too the keyboard is given up */
static const char *stalled(void)
{
    if (!usb_present(device))
        return 0;                       /* unplugged from a hub: its translator answers with a stall */
    silent = 0;
    if (++fails < 3)
        return 0;
    if (switched) {
        usnprintf(message, sizeof(message), "keyboard: neither its interrupt endpoint %02x nor GET_REPORT "
                  "works (%s) -- given up; 'usb' tries again", ep, usb_error_text());
        kbd_stop();
        return message;
    }
    if (mode == MODE_INTERRUPT)
        usnprintf(message, sizeof(message), "keyboard: its interrupt endpoint %02x stalls (%s); reading it "
                  "with GET_REPORT instead", ep, usb_error_text());
    else
        usnprintf(message, sizeof(message), "keyboard: GET_REPORT failed (%s); reading its interrupt "
                  "endpoint %02x instead", usb_error_text(), ep);
    kbd_set_mode(mode != MODE_INTERRUPT);
    switched = 1;
    return message;
}

/* with raw on, a report that differs from the one printed last as a line to show */
static const char *raw_line(const u8 *r, int n)
{
    int same = 1;
    for (int i = 0; i < 8; i++)
        if ((i < n ? r[i] : 0) != last_raw[i])
            same = 0;
    if (!raw || same)
        return 0;
    for (int i = 0; i < 8; i++)
        last_raw[i] = i < n ? r[i] : 0;
    usnprintf(message, sizeof(message), "keyboard report (%s, %d bytes): %02x %02x %02x %02x %02x %02x %02x %02x",
              mode == MODE_REPORT ? "GET_REPORT" : "interrupt endpoint", n,
              n > 0 ? r[0] : 0, n > 1 ? r[1] : 0, n > 2 ? r[2] : 0, n > 3 ? r[3] : 0,
              n > 4 ? r[4] : 0, n > 5 ? r[5] : 0, n > 6 ? r[6] : 0, n > 7 ? r[7] : 0);
    return message;
}

void kbd_show_status(void)
{
    if (!active) {
        uprintf("no USB keyboard (plug one in; 'usb' enumerates the port again)\n");
        return;
    }
    uprintf("keyboard on interface %u, interrupt endpoint %02x (%u bytes, every %u ms) of device %u\n", iface, ep,
            ep_size, interval, device);
    if (mode == MODE_REPORT) {
        uprintf("  read with GET_REPORT over endpoint 0 every %u ms\n", REPORT_PERIOD_MS);
    } else if (via_d) {
        u32 every_us, got, drops;
        usb_epd_counts(&every_us, &got, &drops);
        uprintf("  read from its interrupt endpoint through the controller's endpoint D (it polls by itself, "
                "every %u us); %u reports dropped for their data toggle\n", every_us, drops);
    } else {
        uprintf("  read from its interrupt endpoint (an IN pending on the controller's endpoint B%s); %u reports the "
                "controller dropped for their data toggle\n", mouse_active() ? ", in turns with the mouse's" : "",
                usb_int_drops(0));
    }
    uprintf("  %u reports, %u keys, %u errors; Caps Lock %s; raw reports %s; keys held now:", reports, keys, errors,
            caps ? "on" : "off", raw ? "on" : "off");
    int any = 0;
    for (int i = 2; i < 8; i++)
        if (held[i]) {
            uprintf(" %02x", held[i]);
            any = 1;
        }
    uprintf("%s (modifiers %02x)\n", any ? "" : " none", held[0]);
}

/* every pass of the main loop: reads the keyboard when it is due, repeats a
   held key; a line to show (a change of the way it is read) or 0 */
const char *kbd_poll(void)
{
    if (!active)
        return 0;
    u64 now = now_ms();
    const char *say = 0;
    u8 r[16];
    if (mode == MODE_REPORT) {
        if (now >= next_poll) {
            next_poll = now + REPORT_PERIOD_MS;
            int n = usb_request(device, 0xA1, 0x01, 0x0100, iface, r, 8, 50);  /* GET_REPORT (input) */
            if (n < 0 && (usb_last_error() & 0x80)) {
                errors++;                       /* a stall: it does not do GET_REPORT */
                say = stalled();
            } else if (n < 0) {
                errors++;
                say = no_answer();
            } else {
                fails = 0;
                silent = 0;
                set_ups = 0;
                say = raw_line(r, n);
                if (n >= 3)
                    on_report(r, n);
            }
        }
    } else {
        int n = 0;
        if (!armed && now >= next_poll) {
            /* endpoint D first: it polls by itself and nothing else takes it.  Through endpoint B every
               disk or network transfer ended the keyboard's IN, and behind a hub's translator a report
               caught between its two halves was lost -- the keyboard's toggle a step ahead, the next one
               dropped too: on the box 26 of 150 reports with Ethernet read every 20 ms, keys stuck */
            if (usb_epd_device() && usb_epd_device() == mouse_device())
                mouse_yield_epd();
            via_d = usb_epd_open(device, ep, ep_size, interval) == 0;
            if (!via_d)
                usb_int_open(0, device, ep, ep_size, interval);     /* (usb.c reads it: endpoint B's turns) */
            armed = 1;
        }
        if (armed)                              /* > 0 a report, 0 nothing yet, -1 failed, -2 an empty one */
            n = via_d ? usb_epd_take(r, sizeof(r)) : usb_int_take(0, r, sizeof(r));
        if (n == -1) {
            armed = 0;                          /* (the slot is closed): opened again when next_poll comes */
            errors++;
            next_poll = now + 100;
            u8 e = usb_last_error();
            if (e & 0x80) {
                say = stalled();                /* the endpoint is halted */
            } else if (!e || (e & 0x20)) {
                say = no_answer();              /* nobody answered: unplugged, or reset behind the demo's back */
            } else if (++int_errors == 1 || int_errors % 100 == 0) {
                usnprintf(message, sizeof(message), "keyboard: interrupt endpoint %02x: %s (%u errors)",
                          ep, usb_error_text(), int_errors);
                say = message;
            }
        } else if (n != 0) {
            fails = 0;
            silent = 0;
            set_ups = 0;
            if (n > 0) {
                say = raw_line(r, n);
                if (n >= 3)
                    on_report(r, n);
            }
        }
    }
    if (repeat_key && now >= repeat_at) {
        key_down(repeat_key, held[0]);
        repeat_at = now + REPEAT_PERIOD_MS;
    }
    return say;
}
