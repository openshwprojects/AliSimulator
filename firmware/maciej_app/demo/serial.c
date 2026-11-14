/* USB serial ports -- what Linux makes /dev/ttyUSB<n> and ttyACM<n> of: a
   GSM / LTE module's vendor-class interfaces with a bulk IN and a bulk OUT
   endpoint (its AT, modem and diagnostic ports, as Linux's option driver
   takes them), or a CDC ACM data interface.  usb.c hands them over
   (serial_attach) as it sets a device up.

   'tty' lists them.  'cu [n]' joins the terminal -- the UART and the USB
   keyboard -- to port n (without n: the first one named "AT"): what is typed
   goes out to it, what comes in is shown, until "~." at a line's start or
   Ctrl-] (as Linux's cu and telnet).  'at <command>' sends one AT command to
   that port ("AT" put in front when it is not there: 'at +csq', 'at i') and
   shows the answer up to its final result (OK, ERROR, +CME / +CMS ERROR, NO
   CARRIER, or the "> " of AT+CMGS) and what follows it at once (AT+HTTPREAD's
   data); lines that came before the command (+HTTPACTION, RING) first.  A
   token spoilt on the bus is tried again (usb.c); 'cu' goes on through a
   failed transfer while the device is still set up.

   The answers come in packets shorter than asked for: usb_bulk_in_packet
   reads them (usb.c says how the controller is made to). */
#include "hw.h"

#define PORTS SERIAL_PORTS

struct port {
    u8 used, acm, device, iface, in_ep, out_ep;
    u16 maxp;
    char name[32];
};

static struct port ports[PORTS];
static char said[96];
static u8 in[512];                      /* what a port sent ('cu' and 'at' are never at the same time) */

static const char *tty(const struct port *p)
{
    return p->acm ? "ttyACM" : "ttyUSB";
}

const char *serial_attach(u8 device, u8 iface, u8 control, int acm, u8 in_ep, u8 out_ep, u16 maxp,
                          const char *name)
{
    for (int i = 0; i < PORTS; i++) {
        struct port *p = &ports[i];
        if (p->used)
            continue;
        p->used = 1;
        p->acm = (u8)acm;
        p->device = device;
        p->iface = iface;
        p->in_ep = in_ep;
        p->out_ep = out_ep;
        p->maxp = maxp;
        usnprintf(p->name, sizeof(p->name), "%s", name);
        /* DTR and RTS on (SET_CONTROL_LINE_STATE, to the interface with the modem control: CDC ACM's
           communications interface), as Linux does when it opens the port; one without may refuse it */
        (void)usb_request(device, 0x21, 0x22, 3, control, 0, 0, 100);
        usnprintf(said, sizeof(said), "%s%d: a serial port (interface %u%s%s): 'cu %d'", tty(p), i, iface,
                  p->name[0] ? ", " : "", p->name, i);
        return said;
    }
    usnprintf(said, sizeof(said), "a serial port, but %d are known already: left alone", PORTS);
    return said;
}

void serial_detach(u8 device)
{
    for (int i = 0; i < PORTS; i++)
        if (!device || ports[i].device == device)
            ports[i].used = 0;
}

int serial_count(void)
{
    int n = 0;
    for (int i = 0; i < PORTS; i++)
        n += ports[i].used;
    return n;
}

void serial_list(void)
{
    for (int i = 0; i < PORTS; i++) {
        const struct port *p = &ports[i];
        if (p->used)
            uprintf("%s%d  device %u interface %u: %s (bulk in %02x, out %02x, %u-byte packets)\n", tty(p), i,
                    p->device, p->iface, p->name[0] ? p->name : "a serial port", 0x80 | p->in_ep, p->out_ep,
                    p->maxp);
    }
    if (!serial_count())
        uprintf("no USB serial ports (a GSM / LTE module, a CDC ACM device: 'lsusb' shows what is there)\n");
}

/* the port 'at' and 'cu' without a number use: the first named "... AT ...", else the first */
static int at_port(void)
{
    int first = -1;
    for (int i = 0; i < PORTS; i++) {
        if (!ports[i].used)
            continue;
        if (first < 0)
            first = i;
        const char *s = ports[i].name;
        for (int k = 0; s[k] && s[k + 1]; k++)
            if (s[k] == 'A' && s[k + 1] == 'T' && (k == 0 || s[k - 1] == ' ') && (s[k + 2] == ' ' || !s[k + 2]))
                return i;
    }
    return first;
}

static int port_ok(int n)
{
    if (n >= 0 && n < PORTS && ports[n].used)
        return 1;
    if (!serial_count())
        uprintf("no USB serial port ('tty' lists them)\n");
    else
        uprintf("no serial port %d ('tty' lists them)\n", n);
    return 0;
}

/* a transfer on port n failed (usb.c tried a token spoilt on the bus again already).  0: its device is
   still set up: go on.  Else it lost its set-up -- an LTE module that restarted: the A7670E after AT+CRESET
   came back twice and the second time had lost its configuration without the port's connection changing --
   and it is set up again (usb_set_up_again: behind a hub that port alone): 1 when port n is back (the same
   interface), -1 it is not */
static int recover(int n)
{
    u8 iface = ports[n].iface;
    if (usb_still_set_up(ports[n].device))
        return 0;
    uprintf("(the device is not set up any more -- restarted? -- setting it up again)\n");
    if (usb_set_up_again(ports[n].device) < 0) {
        uprintf("(it does not answer: %s)\n", usb_error_text());
        return -1;
    }
    return ports[n].used && ports[n].iface == iface ? 1 : -1;
}

/* the next character typed (the UART, then the USB keyboard), -1 none */
static int typed(void)
{
    int c = uart_getc();
    if (c >= 0)
        return c;
    usb_int_poll();
    (void)kbd_poll();
    return kbd_getc();
}

void serial_cu(int n)
{
    if (n < 0)
        n = at_port();
    if (!port_ok(n))
        return;
    struct port *p = &ports[n];
    uprintf("Connected to %s%d (device %u interface %u%s%s). What you type goes to it; \"~.\" at a line's "
            "start or Ctrl-] ends.\n", tty(p), n, p->device, p->iface, p->name[0] ? ", " : "", p->name);
    u8 out[64];
    int no = 0;                                 /* typed, not sent yet (after a failed send: sent again) */
    int line_start = 1, tilde = 0, done = 0, after_cr = 0, recoveries = 0, errors = 0;
    while (!done) {
        int c;
        while (no < (int)sizeof(out) - 1 && (c = typed()) >= 0) {
            if (c == 0x1D) {                    /* Ctrl-] */
                done = 1;
                break;
            }
            /* Enter as CR, the end of an AT command, whatever the terminal sends for it (CR, LF, CR LF) */
            int was_cr = after_cr;
            after_cr = c == '\r';
            if (c == '\n') {
                if (was_cr)
                    continue;
                c = '\r';
            }
            if (tilde) {
                tilde = 0;
                if (c == '.') {
                    done = 1;
                    break;
                }
                out[no++] = '~';
            }
            if (line_start && c == '~') {
                tilde = 1;
                continue;
            }
            out[no++] = (u8)c;
            line_start = c == '\r';
        }
        /* a failed transfer: with the device still set up the session goes on -- what was typed goes out
           the next time round, 50 failures in a row end it --; a device that lost its set-up is set up again
           (three times at most); one that is gone ends it (unplugged, restarting: the main loop sets it up
           when it is back) */
        int failed = no && usb_bulk_out(p->device, p->out_ep, p->maxp, out, (u32)no, 1000) < 0;
        if (!failed) {
            no = 0;
            int k = usb_bulk_in_packet(p->device, p->in_ep, p->maxp, in, 20);
            for (int i = 0; i < k; i++)
                uart_putc((char)in[i]);
            failed = k == -1;
        }
        if (failed) {
            int r = recover(n);
            if (r < 0 || (r == 0 && ++errors == 50) || (r > 0 && ++recoveries > 3)) {
                uprintf("\n(the port failed: %s)", usb_error_text());
                break;
            }
            if (r == 0 && errors == 1)
                uprintf("\n(a USB transfer failed: %s -- going on)\n", usb_error_text());
            if (r > 0)
                uprintf("(%s%d is back: type on)\n", tty(p), n);
        } else {
            errors = 0;
        }
        console_service();
    }
    uprintf("\nDisconnected from %s%d.\n", tty(p), n);
}

/* a final result code: the answer to an AT command is complete */
static int final_line(const char *l)
{
    static const char *const finals[] = {"OK", "ERROR", "+CME ERROR", "+CMS ERROR", "NO CARRIER", "BUSY",
                                         "NO ANSWER", "NO DIALTONE", "CONNECT"};
    for (unsigned i = 0; i < sizeof(finals) / sizeof(finals[0]); i++) {
        const char *f = finals[i];
        int k = 0;
        while (f[k] && l[k] == f[k])
            k++;
        if (!f[k] && (!l[k] || l[k] == ':' || l[k] == ' '))
            return 1;
    }
    return 0;
}

/* the module's output a line at a time, as it comes (CRs dropped, other control bytes as '.'); a long line
   in pieces of 79 -- the page AT+HTTPREAD gives can be one line of hundreds */
struct lines {
    char l[80];
    int n, cont;                        /* its characters so far; a piece of it printed already */
};

/* one character; 1 when it ended a line that is a final result */
static int line_char(struct lines *s, char c)
{
    if (c == '\n') {
        s->l[s->n] = 0;
        uprintf("%s\n", s->l);
        int final = !s->cont && final_line(s->l);
        s->n = s->cont = 0;
        return final;
    }
    if (c == '\r')
        return 0;
    if (s->n == (int)sizeof(s->l) - 1) {
        s->l[s->n] = 0;
        uprintf("%s", s->l);
        s->n = 0;
        s->cont = 1;
    }
    s->l[s->n++] = c >= 32 && c < 127 ? c : '.';
    return 0;
}

/* a line without its end yet: printed and ended */
static void line_end(struct lines *s)
{
    if (s->n || s->cont)
        (void)line_char(s, '\n');
}

/* "AT..." in any case: an AT command ('at' puts "AT" in front of anything else) */
int at_prefixed(const char *s)
{
    return (s[0] == 'A' || s[0] == 'a') && (s[1] == 'T' || s[1] == 't');
}

/* After the final result the answer is read on for 250 ms of quiet: some come after their OK (AT+HTTPREAD's
   data).  Lines that came before the command -- unsolicited ones: +HTTPACTION, RING, +CMTI -- are shown
   first, as they are.  A command that did not go out is sent again when the device is still set up (or was
   set up again). */
#define AT_AFTER_MS 250

void serial_at(const char *command)
{
    int n = at_port();
    if (!port_ok(n))
        return;
    struct port *p = &ports[n];
    u8 cmd[100];
    int len = 0;
    if (!at_prefixed(command)) {
        cmd[len++] = 'A';
        cmd[len++] = 'T';
    }
    while (*command && len < (int)sizeof(cmd) - 1)
        cmd[len++] = (u8)*command++;
    cmd[len++] = '\r';
    static struct lines s;
    s.n = s.cont = 0;
    for (int attempt = 0;; attempt++) {
        int k;
        while ((k = usb_bulk_in_packet(p->device, p->in_ep, p->maxp, in, 1)) > 0)
            for (int i = 0; i < k; i++)
                (void)line_char(&s, (char)in[i]);       /* (what came before the command: shown) */
        line_end(&s);
        if (usb_bulk_out(p->device, p->out_ep, p->maxp, cmd, (u32)len, 1000) == 0)
            break;
        uprintf("not sent to %s%d: %s\n", tty(p), n, usb_error_text());
        int r = attempt < 2 ? recover(n) : -1;
        if (r < 0)
            return;
        uprintf("(%s%d %s: the command again)\n", tty(p), n, r ? "is back" : "still set up");
    }
    int got = 0, done = 0;
    u64 start = now_ms(), last = start;
    for (;;) {
        int k = usb_bulk_in_packet(p->device, p->in_ep, p->maxp, in, 50);
        u64 now = now_ms();
        if (k > 0) {
            last = now;
            got = 1;
        }
        for (int i = 0; i < k; i++)
            done |= line_char(&s, (char)in[i]);
        if (!done && s.n == 2 && !s.cont && s.l[0] == '>' && s.l[1] == ' ') {
            uprintf("> \n");                    /* AT+CMGS waits for the text (Ctrl-Z ends it: 'cu') */
            return;
        }
        if (k == -1) {                          /* (a token spoilt on the bus was tried again in usb.c) */
            line_end(&s);
            uprintf("%s%d: %s\n", tty(p), n, usb_error_text());
            return;
        }
        if (done && now - last >= AT_AFTER_MS)
            break;
        if (uart_getc() == 3) {
            line_end(&s);
            uprintf("^C\n");
            return;
        }
        if (now - start > 120000 || (!done && now - last > 10000)) {
            line_end(&s);
            if (!done)
                uprintf("%s\n", got ? "(no final result within 10 s)" : "(no answer within 10 s)");
            return;
        }
    }
    line_end(&s);
}
