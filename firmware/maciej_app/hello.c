/* The smallest test application for the bootloader flash survey
   (tools/bootloader_flash_survey.py): it prints the demo's banner and answers
   'p' with a pong, nothing else.  Unlike app.c it touches no register but the
   UART's data and line-status bytes -- it keeps the bootloader's baud rate and
   frame format and has no restart code -- so it can run on every ALi chip whose
   bootloader starts it.  UART_BASE (default 0xB8018300; the M3329's console
   UART is at 0xB8001300) and the link address come from build.py. */
#ifndef APP_VERSION
#define APP_VERSION "survey"
#endif
#ifndef UART_BASE
#define UART_BASE 0xb8018300u
#endif
#define APP_BANNER "ELEKTRODA ALI M3801 TEST FOR MACIEJ"

typedef unsigned char u8;
typedef unsigned int u32;

#define UART ((volatile u8 *)UART_BASE)

static volatile u32 bss_probe;
static volatile u32 data_probe = 0x2468ace0u;

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
    if (bss_probe != 0 || data_probe != 0x2468ace0u) {
        puts_uart(APP_BANNER ": runtime init failed\r\n");
        for (;;) { }
    }
    bss_probe = 1;
    puts_uart("\r\n" APP_BANNER "\r\nVersion: " APP_VERSION "\r\n");
    puts_uart("Flash survey test application\r\n");
    for (;;) {
        if (UART[5] & 1u) {
            u8 ch = UART[0];
            if (ch == 'p')
                puts_uart("pong " APP_VERSION "\r\n");
            else if (ch == 'v')
                puts_uart(APP_BANNER "\r\nVersion: " APP_VERSION "\r\n");
        }
    }
}

/* start.S also carries the M3801 restart routine for app.c; nothing here
   calls it. */
