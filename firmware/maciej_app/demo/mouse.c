/* A USB mouse: a pointer on the TV, and painting with it.

   usb.c finds a mouse while it enumerates (an interface of class 3 = HID,
   subclass 1 = boot, protocol 2 = mouse) and starts it here: SET_PROTOCOL
   selects the boot protocol -- reports of the buttons (bit 0 left, 1 right,
   2 middle) and the X and Y movement as signed bytes, a wheel byte after
   them on most mice -- and SET_IDLE(0) asks for a report only when something
   changes.  The controller's endpoint D polls its interrupt endpoint by
   itself (usb.c, usb_epd_*), so the keyboard keeps endpoint B and a stick's
   transfers disturb neither; only when endpoint D polls another device does
   the mouse take turns with the keyboard on endpoint B (usb_int_*: slot 1),
   which behind a hub loses reports.  Like the keyboard tried, the A4Tech
   mouse tried answers GET_REPORT with nonsense.

   The pointer is an arrow drawn over the picture (gfx.c keeps what it
   covers and takes it away before anything is drawn under it).  With the
   left button held it paints; the right button picks the next colour; the
   wheel is told.  Every button going down or up is told on the UART with the
   pointer's place: '[usb] mouse: left down at 640,360'. */
#include "hw.h"

#define SLOT 1                          /* (usb.c's slots for interrupt endpoints) */
#define BRUSH 5

static int active, armed;
static int via_d;                       /* read through endpoint D (else endpoint B's turns) */
static u8 device, iface, ep, every;     /* every: its endpoint's interval (bInterval) */
static u16 ep_size;
static int x, y;                        /* the pointer */
static u8 buttons;
static int paint_x, paint_y;            /* where the last paint was put */
static int colour;
static u32 reports, errors, clicks;
static int wheel;
static u64 retry_at;
static char message[96];

static const u16 colours[] = {
    RGB(255, 230, 120), RGB(255, 80, 80), RGB(90, 220, 90), RGB(90, 160, 255), RGB(255, 255, 255),
    RGB(255, 140, 0),
};
static const char *const colour_names[] = {"yellow", "red", "green", "blue", "white", "orange"};

int mouse_active(void)
{
    return active;
}

u8 mouse_device(void)
{
    return active ? device : 0;
}

static void disarm(void)
{
    if (armed) {
        if (via_d)
            usb_epd_close();
        else
            usb_int_close(SLOT);
    }
    armed = 0;
}

void mouse_stop(void)
{
    if (active)
        disarm();
    active = 0;
    gfx_cursor(0, 0, 0);
}

/* after SET_CONFIGURATION: the mouse's device, interface and interrupt
   endpoint (its packet size and interval); a line saying so */
const char *mouse_start(u8 address, u8 interface, u8 endpoint, u16 size, u8 interval)
{
    device = address;
    iface = interface;
    ep = endpoint;
    every = interval ? interval : 10;
    via_d = 1;
    ep_size = size ? size : 8;
    if (ep_size > USB_DMA_SIZE)
        ep_size = USB_DMA_SIZE;
    int proto = usb_request(device, 0x21, 0x0B, 0, iface, 0, 0, 100);    /* SET_PROTOCOL: boot */
    int idle = usb_request(device, 0x21, 0x0A, 0, iface, 0, 0, 100);     /* SET_IDLE: only on a change */
    x = SCREEN_W / 2;
    y = SCREEN_H / 2;
    buttons = 0;
    reports = errors = clicks = 0;
    wheel = 0;
    colour = 0;
    active = 1;
    armed = 0;
    retry_at = now_ms();
    gfx_cursor(x, y, 1);
    usnprintf(message, sizeof(message), "mouse on interface %u: boot protocol%s, SET_IDLE %s; the pointer is on "
              "the TV", iface, proto < 0 ? " NOT set" : "", idle < 0 ? "refused" : "set");
    return message;
}

static const char *button_name(u8 bit)
{
    return bit == 1 ? "left" : bit == 2 ? "right" : bit == 4 ? "middle" : "another";
}

/* paint along from the last place to this one (a 5-pixel brush every 2 pixels) */
static void paint_to(int to_x, int to_y)
{
    int dx = to_x - paint_x, dy = to_y - paint_y;
    int steps = (dx < 0 ? -dx : dx) > (dy < 0 ? -dy : dy) ? (dx < 0 ? -dx : dx) : (dy < 0 ? -dy : dy);
    steps = steps / 2 + 1;
    for (int i = 1; i <= steps; i++) {
        int px = paint_x + dx * i / steps, py = paint_y + dy * i / steps;
        gfx_fill(px - BRUSH / 2, py - BRUSH / 2, BRUSH, BRUSH, colours[colour]);
    }
    paint_x = to_x;
    paint_y = to_y;
}

static int clamp(int v, int lo, int hi)
{
    return v < lo ? lo : v > hi ? hi : v;
}

/* a report: the pointer moved, buttons; a line to show (a button) or 0 */
static const char *on_report(const u8 *r, int n)
{
    const char *say = 0;
    reports++;
    if (n < 3)
        return 0;
    int dx = (signed char)r[1], dy = (signed char)r[2];
    /* a little acceleration: fast movements count double */
    if (dx > 6 || dx < -6)
        dx *= 2;
    if (dy > 6 || dy < -6)
        dy *= 2;
    x = clamp(x + dx, 0, SCREEN_W - 1);
    y = clamp(y + dy, 0, SCREEN_H - 1);
    if (n >= 4 && r[3]) {
        wheel += (signed char)r[3];
        usnprintf(message, sizeof(message), "mouse: wheel %d (%d in all) at %d,%d", (signed char)r[3], wheel, x, y);
        say = message;
    }
    u8 changed = (u8)(r[0] ^ buttons);
    if ((buttons & 1) && (r[0] & 1))
        paint_to(x, y);
    for (u8 bit = 1; bit <= 4; bit <<= 1)
        if (changed & bit) {
            int down = (r[0] & bit) != 0;
            if (down)
                clicks++;
            if (bit == 1 && down) {         /* the left button: painting begins here */
                paint_x = x;
                paint_y = y;
                paint_to(x, y);
            }
            if (bit == 2 && down)
                colour = (colour + 1) % (int)(sizeof(colours) / sizeof(colours[0]));
            usnprintf(message, sizeof(message), "mouse: %s %s at %d,%d%s%s", button_name(bit), down ? "down" : "up",
                      x, y, bit == 2 && down ? "; paint colour " : "", bit == 2 && down ? colour_names[colour] : "");
            say = message;
        }
    buttons = r[0];
    gfx_cursor(x, y, 1);
    return say;
}

/* a token failed (or the set-up did): tried again in 200 ms -- unless it
   was unplugged; a line every so often */
static const char *failed(u64 now)
{
    char why[72];
    const char *text = usb_error_text();
    int i = 0;
    for (; text[i] && i < (int)sizeof(why) - 1; i++)
        why[i] = text[i];               /* (usb_present's own requests change the text) */
    why[i] = 0;
    disarm();
    errors++;
    retry_at = now + 200;
    if (!usb_present(device)) {
        mouse_stop();
        return 0;                       /* unplugged: usb.c tells */
    }
    if (errors == 1 || errors % 50 == 0) {
        usnprintf(message, sizeof(message), "mouse: %s (%u errors)", why, errors);
        return message;
    }
    return 0;
}

/* every pass of the main loop (after usb_int_poll): its reports; a line to
   show, or 0 */
const char *mouse_poll(void)
{
    if (!active)
        return 0;
    u64 now = now_ms();
    if (!armed) {
        if (now < retry_at)
            return 0;
        if (via_d) {
            int r = usb_epd_open(device, ep, ep_size, every);
            if (r == -2)
                via_d = 0;              /* endpoint D polls another device: endpoint B's turns */
            else if (r < 0)
                return failed(now);
        }
        if (!via_d)
            usb_int_open(SLOT, device, ep, ep_size);
        armed = 1;
    }
    u8 r[USB_DMA_SIZE];
    int n = via_d ? usb_epd_take(r, sizeof(r)) : usb_int_take(SLOT, r, sizeof(r));
    if (n > 0)
        return on_report(r, n);
    if (n == -1)                        /* (endpoint D stopped / the slot is closed) */
        return failed(now);
    return 0;
}

void mouse_show_status(void)
{
    if (!active) {
        uprintf("no USB mouse (plug one in; 'usb' enumerates the port again)\n");
        return;
    }
    uprintf("mouse: device %u, interface %u, interrupt endpoint %02x (%u bytes, every %u ms)\n", device, iface, ep,
            ep_size, every);
    if (via_d) {
        u32 us, got, drops;
        usb_epd_counts(&us, &got, &drops);
        uprintf("  read through endpoint D, polled every %u.%u ms; %u packets, %u dropped for their data toggle\n",
                us / 1000, us % 1000 / 100, got, drops);
    } else {
        uprintf("  read through endpoint B in turns with the keyboard (endpoint D polls device %u); %u reports "
                "dropped for their data toggle\n", usb_epd_device(), usb_int_drops(SLOT));
    }
    uprintf("  pointer at %d,%d, buttons %02x, wheel %d; paint colour %s\n", x, y, buttons, wheel,
            colour_names[colour]);
    uprintf("  %u reports, %u button presses, %u errors\n", reports, clicks, errors);
}
