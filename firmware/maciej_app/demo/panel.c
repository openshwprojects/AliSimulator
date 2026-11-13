/* The front panel: a TM1650 4-digit LED driver and key scanner on a
   two-wire bus bit-banged over GPIO bank 0 (SCL = GPIO 31, SDA = GPIO 9), as
   the bootloader drives it ("bl_panel_init").  The chip has no device
   address: the first byte of a transfer is the command -- 0x48 display
   control, 0x68/0x6A/0x6C/0x6E digits 1..4, 0x4F the key read (as this
   board's application uses; 0x49 on the original part).  A pin the CPU lets
   go is an input pulled high; the chip pulls SDA low for its acknowledge
   and for the 0 bits of a key byte.  Only bits 9 and 31 of the bank are
   changed (read-modify-write).

   Not every M3801 board has the chip: the Comsat TE 1050 HD (dump.bin) has
   no display, and its two front buttons sit straight on the same pins, each
   pulled up and shorted to ground when pressed.  panel_init() asks for the
   chip's acknowledge; when none comes it lets go of both pins for good (a
   pin driven high would be shorted by a pressed button) and the demo reads
   them as two buttons instead (panel_buttons). */
#include "hw.h"

#define SCL_BIT (1u << 31)
#define SDA_BIT (1u << 9)
#define HALF_US 5                   /* ~100 kHz */

static char shown[5] = "    ";
static int bright = 2;
static int present;                 /* 1: a TM1650 answered; 0: none -- the pins are inputs */

static void pin(u32 bit, int level)
{
    /* output and driven: low, or high (push-pull, as the bootloader) */
    u32 dout = REG32(GPIO0_DO);
    REG32(GPIO0_DO) = level ? (dout | bit) : (dout & ~bit);
    REG32(GPIO0_DIR) = REG32(GPIO0_DIR) | bit;
}

static void sda_release(void)
{
    REG32(GPIO0_DIR) = REG32(GPIO0_DIR) & ~SDA_BIT;   /* input: the pull-up, or the chip */
}

static int sda_read(void)
{
    return (REG32(GPIO0_DI) & SDA_BIT) ? 1 : 0;
}

static void start(void)
{
    pin(SDA_BIT, 1);
    pin(SCL_BIT, 1);
    delay_us(HALF_US);
    pin(SDA_BIT, 0);
    delay_us(HALF_US);
    pin(SCL_BIT, 0);
    delay_us(HALF_US);
}

static void stop(void)
{
    pin(SDA_BIT, 0);
    delay_us(HALF_US);
    pin(SCL_BIT, 1);
    delay_us(HALF_US);
    pin(SDA_BIT, 1);
    delay_us(HALF_US);
}

/* 8 bits MSB first, then the chip's acknowledge (1: acknowledged) */
static int write_byte(u8 b)
{
    for (int i = 7; i >= 0; i--) {
        pin(SDA_BIT, (b >> i) & 1);
        delay_us(HALF_US);
        pin(SCL_BIT, 1);
        delay_us(HALF_US);
        pin(SCL_BIT, 0);
    }
    sda_release();
    delay_us(HALF_US);
    pin(SCL_BIT, 1);
    delay_us(HALF_US);
    int ack = !sda_read();
    pin(SCL_BIT, 0);
    delay_us(HALF_US);
    return ack;
}

static u8 read_byte(void)
{
    u8 b = 0;
    sda_release();
    for (int i = 7; i >= 0; i--) {
        delay_us(HALF_US);
        pin(SCL_BIT, 1);
        delay_us(HALF_US);
        b |= (u8)(sda_read() << i);
        pin(SCL_BIT, 0);
    }
    /* no acknowledge from the master: SDA high on the 9th clock */
    pin(SDA_BIT, 1);
    delay_us(HALF_US);
    pin(SCL_BIT, 1);
    delay_us(HALF_US);
    pin(SCL_BIT, 0);
    return b;
}

static int command(u8 cmd, u8 data)
{
    start();
    int ok = write_byte(cmd);
    ok &= write_byte(data);
    stop();
    return ok;
}

/* 7-segment patterns, bit 0..6 = a..g (the board's digits and segments are in
   the standard order: front_panel.py's dump_maciej entry) */
static u8 segments(char c)
{
    static const u8 digit[10] = {0x3F, 0x06, 0x5B, 0x4F, 0x66, 0x6D, 0x7D, 0x07, 0x7F, 0x6F};
    static const u8 alpha[26] = {
        0x77, 0x7C, 0x39, 0x5E, 0x79, 0x71, 0x3D, 0x76, 0x30, 0x1E, 0x76, 0x38, 0x37,  /* A..M */
        0x54, 0x3F, 0x73, 0x67, 0x50, 0x6D, 0x78, 0x3E, 0x3E, 0x3E, 0x76, 0x6E, 0x5B,  /* N..Z */
    };
    if (c >= '0' && c <= '9')
        return digit[c - '0'];
    if (c >= 'a' && c <= 'z') {
        switch (c) {               /* the lower-case shapes that read better */
        case 'b': return 0x7C;
        case 'c': return 0x58;
        case 'd': return 0x5E;
        case 'h': return 0x74;
        case 'i': return 0x10;
        case 'n': return 0x54;
        case 'o': return 0x5C;
        case 'r': return 0x50;
        case 't': return 0x78;
        case 'u': return 0x1C;
        }
        c = (char)(c - 'a' + 'A');
    }
    if (c >= 'A' && c <= 'Z')
        return alpha[c - 'A'];
    switch (c) {
    case '-': return 0x40;
    case '_': return 0x08;
    case '=': return 0x48;
    case '.': return 0x80;
    }
    return 0x00;
}

/* display on, 8-segment mode off (7 segments + point), brightness 1..8 */
static int display_control(void)
{
    return command(0x48, (u8)(((bright & 7) << 4) | 0x01));
}

void panel_brightness(int level)
{
    bright = level & 7;
    if (present)
        display_control();
}

void panel_text(const char *four)
{
    int i;
    for (i = 0; i < 4 && four[i]; i++)
        shown[i] = four[i];
    for (; i < 4; i++)
        shown[i] = ' ';
    shown[4] = 0;
    for (i = 0; present && i < 4; i++)
        command((u8)(0x68 + 2 * i), segments(shown[i]));
}

const char *panel_current(void)
{
    return shown;
}

int panel_init(void)
{
    /* both lines outputs, high: the idle bus; then the display-control
       command, which a TM1650 acknowledges byte by byte (three tries) */
    pin(SDA_BIT, 1);
    pin(SCL_BIT, 1);
    delay_us(HALF_US * 4);
    for (int tries = 0; tries < 3 && !present; tries++) {
        present = display_control();
        if (!present)
            delay_us(1000);
    }
    if (!present) {
        /* no chip: both pins inputs from now on (released first, then the
           output latch cleared) -- never driven again */
        REG32(GPIO0_DIR) = REG32(GPIO0_DIR) & ~(SCL_BIT | SDA_BIT);
        REG32(GPIO0_DO) = REG32(GPIO0_DO) & ~(SCL_BIT | SDA_BIT);
        return 0;
    }
    panel_text(" v4 ");
    return 1;
}

int panel_present(void)
{
    return present;
}

int panel_buttons(void)
{
    if (present)
        return 0;
    u32 di = REG32(GPIO0_DI);
    return ((di & SCL_BIT) ? 0 : PANEL_BUTTON_UP) | ((di & SDA_BIT) ? 0 : PANEL_BUTTON_DOWN);
}

int panel_read_key(void)
{
    if (!present)
        return -1;
    start();
    if (!write_byte(0x4F)) {
        stop();
        return -1;
    }
    u8 key = read_byte();
    stop();
    return key;
}
