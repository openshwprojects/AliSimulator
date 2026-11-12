/* Small freestanding MIPS32 application; no vendor SDK or C runtime needed. */
#ifndef APP_VERSION
#define APP_VERSION "v1"
#endif
#define APP_BANNER "ELEKTRODA ALI M3801 TEST FOR MACIEJ"

typedef unsigned char u8;
typedef unsigned int u32;

#define UART ((volatile u8 *)0xb8018300u)

static volatile u32 bss_probe;
static volatile u32 data_probe = 0x13579bdfu;

void platform_restart(void) __attribute__((noreturn));

static void putc_uart(char ch)
{
    while (!(UART[5] & 0x20u)) { }
    UART[0] = (u8)ch;
}

static void puts_uart(const char *text)
{
    while (*text)
        putc_uart(*text++);
}

void app_main(void)
{
    /* Keep the bootloader's 115200 baud divisor, select 8E1, use polling. */
    UART[3] = 0x1bu;
    UART[1] = 0;
    UART[2] = 0x07u;

    if (bss_probe != 0 || data_probe != 0x13579bdfu) {
        puts_uart(APP_BANNER ": runtime init failed\r\n");
        for (;;) { }
    }
    bss_probe = 1;
    puts_uart("\r\n" APP_BANNER "\r\nVersion: " APP_VERSION "\r\n");
    puts_uart("RAM app via original bootloader\r\n");
    puts_uart("Commands: v=version p=ping r=restart c=bootloader capture\r\n");
    for (;;) {
        if (UART[5] & 1u) {
            u8 ch = UART[0];
            if (ch == 'p')
                puts_uart("pong " APP_VERSION "\r\n");
            else if (ch == 'v')
                puts_uart(APP_BANNER "\r\nVersion: " APP_VERSION "\r\n");
            else if (ch == 'r' || ch == 'c') {
                /* The updater already sends repeated 'c' while capturing the
                   original loader. Here its first 'c' starts a software reboot;
                   subsequent bytes interrupt the loader's normal startup. */
                puts_uart("Restarting via original bootloader\r\n");
                /* Wait for the FIFO AND shift register, not just THR empty. */
                while (!(UART[5] & 0x40u)) { }
                platform_restart();
            }
        }
    }
}
