/* The console UART (16550 at 0xB8018300) by polling, and a small printf:
   %s %c %d %u %x %X %p %%, with an optional '0' flag and width (%08x). */
#include <stdarg.h>
#include "hw.h"

#define UART ((volatile u8 *)UART_BASE)

void uart_init(void)
{
    /* Keep the bootloader's 115200 baud divisor; 8 data bits, even parity,
       1 stop bit (as the v1..v3 applications and the UART updater); no
       interrupts; FIFOs on and cleared. */
    UART[3] = 0x1bu;
    UART[1] = 0;
    UART[2] = 0x07u;
}

/* Received bytes wait here: the chip's FIFO holds 16 (1.5 ms at 115200
   baud) and a USB transfer or a long output takes longer than that, so the
   delays (time.c) and the transmitter's wait move them over. */
static u8 rx_buf[256];
static u8 rx_head, rx_tail;             /* (8-bit indices wrap with the buffer) */

static void rx_store(u8 c)
{
    if ((u8)(rx_head + 1) != rx_tail)
        rx_buf[rx_head++] = c;
}

void uart_rx_poll(void)
{
    while (UART[5] & 1u)
        rx_store(UART[0]);
}

/* a command's output going into a file ('command > path'): kept here
   instead, without the CRs (the file gets Linux line ends) */
static u8 *cap;
static u32 cap_len, cap_max, cap_over;

void uart_capture(u8 *buf, u32 max)
{
    cap_len = cap_over = 0;
    cap_max = max;
    cap = buf;
}

u32 uart_capture_end(u32 *over)
{
    cap = 0;
    *over = cap_over;
    return cap_len;
}

void uart_putc(char c)
{
    if (cap) {
        if (c != '\r') {
            if (cap_len < cap_max)
                cap[cap_len++] = (u8)c;
            else
                cap_over++;
        }
        return;
    }
    u8 lsr;
    while (!((lsr = UART[5]) & 0x20u))
        if (lsr & 1u)
            rx_store(UART[0]);
    UART[0] = (u8)c;
    console_putc(c);                    /* the TV's console shows the same */
}

void uart_puts(const char *s)
{
    while (*s)
        uart_putc(*s++);
}

int uart_getc(void)
{
    uart_rx_poll();
    if (rx_head == rx_tail)
        return -1;
    return rx_buf[rx_tail++];
}

void uart_flush(void)
{
    /* the FIFO and the shift register: TEMT */
    while (!(UART[5] & 0x40u)) { }
}

/* ---- formatting ---- */
struct sink {
    char *buf;      /* null: the UART */
    int size, len;
};

static void put(struct sink *s, char c)
{
    if (!s->buf) {
        if (c == '\n')
            uart_putc('\r');
        uart_putc(c);
        s->len++;
        return;
    }
    if (s->len + 1 < s->size)
        s->buf[s->len] = c;
    s->len++;
}

static void put_number(struct sink *s, u32 v, int base, int upper, int width, int zero, int negative)
{
    char tmp[12];
    int n = 0;
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    do {
        tmp[n++] = digits[v % (u32)base];
        v /= (u32)base;
    } while (v);
    if (negative)
        width--;
    if (negative && zero)
        put(s, '-');
    while (width-- > n)
        put(s, zero ? '0' : ' ');
    if (negative && !zero)
        put(s, '-');
    while (n)
        put(s, tmp[--n]);
}

static void format(struct sink *s, const char *fmt, va_list ap)
{
    for (; *fmt; fmt++) {
        if (*fmt != '%') {
            put(s, *fmt);
            continue;
        }
        fmt++;
        int zero = 0, width = 0;
        if (*fmt == '0') {
            zero = 1;
            fmt++;
        }
        while (*fmt >= '0' && *fmt <= '9')
            width = width * 10 + (*fmt++ - '0');
        switch (*fmt) {
        case 's': {
            const char *str = va_arg(ap, const char *);
            int len = 0;
            if (!str)
                str = "(null)";
            while (str[len])
                len++;
            while (width-- > len)
                put(s, ' ');
            while (*str)
                put(s, *str++);
            break;
        }
        case 'c':
            put(s, (char)va_arg(ap, int));
            break;
        case 'd': {
            s32 v = va_arg(ap, s32);
            put_number(s, v < 0 ? (u32)(-v) : (u32)v, 10, 0, width, zero, v < 0);
            break;
        }
        case 'u':
            put_number(s, va_arg(ap, u32), 10, 0, width, zero, 0);
            break;
        case 'x':
        case 'X':
            put_number(s, va_arg(ap, u32), 16, *fmt == 'X', width, zero, 0);
            break;
        case 'p':
            put(s, '0');
            put(s, 'x');
            put_number(s, (u32)va_arg(ap, void *), 16, 0, 8, 1, 0);
            break;
        case '%':
            put(s, '%');
            break;
        case 0:
            return;
        default:
            put(s, '%');
            put(s, *fmt);
        }
    }
}

void vuprintf(const char *fmt, va_list ap)
{
    struct sink s = {0, 0, 0};
    format(&s, fmt, ap);
}

void uprintf(const char *fmt, ...)
{
    struct sink s = {0, 0, 0};
    va_list ap;
    va_start(ap, fmt);
    format(&s, fmt, ap);
    va_end(ap);
}

int usnprintf(char *buf, int size, const char *fmt, ...)
{
    struct sink s = {buf, size, 0};
    va_list ap;
    va_start(ap, fmt);
    format(&s, fmt, ap);
    va_end(ap);
    if (size > 0)
        buf[s.len < size ? s.len : size - 1] = 0;
    return s.len;
}
