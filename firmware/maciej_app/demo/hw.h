/* Shared definitions of the v4 demo (firmware/maciej_app/demo): register
   access, the CP0 Count time base, and the board's fixed addresses.  The
   board is maciej_333's Opticum HD N2 (ALi M3801 label, S3811 silicon); it
   also runs on the Comsat TE 1050 HD (dump.bin's board: no panel chip, two
   buttons), which it tells apart by the TM1650's answer. */
#ifndef DEMO_HW_H
#define DEMO_HW_H

#include <stdarg.h>                     /* (a freestanding header: vuprintf's va_list) */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed int s32;

#define REG8(a)  (*(volatile u8 *)(a))
#define REG16(a) (*(volatile u16 *)(a))
#define REG32(a) (*(volatile u32 *)(a))

#ifndef APP_VERSION
#define APP_VERSION "v4"
#endif
#define APP_BANNER "ELEKTRODA ALI M3801 TEST FOR MACIEJ"

/* chip identification (sys_ic_get_chip_id: the halfword at 0xB8000002) */
#define SYS_CHIP_ID      0xB8000000u
#define SYS_STRAP        0xB8000070u      /* bits 7..8: CPU clock 675/594/396/297 MHz */

/* the chip revision as the firmwares' sys_ic_get_rev_id tells it for the
   S3811: the byte at 0xB8000000 (the chip ID word's low byte), 0 -> IC_REV_0,
   anything else -> IC_REV_1 (the Comsat box tested reads 1) */
static inline int chip_rev(void)
{
    return (*(volatile unsigned char *)SYS_CHIP_ID) ? 1 : 0;
}

/* UART 16550 (the console; 115200 baud set by the bootloader) */
#define UART_BASE        0xB8018300u

/* the watchdog (dog_m3327e: counter at +0, control byte at +4; dog.c) */
#define DOG_BASE         0xB8018500u
#define DOG_SECONDS      8u               /* a demo stopped this long resets the box */

/* M6303 IR receiver (irc_6303.c) */
#define IRC_BASE         0xB8018100u

/* GPIO bank 0 (the TM1650 front panel: SCL = GPIO 31, SDA = GPIO 9; on the
   Comsat TE 1050 HD two buttons on the same pins) */
#define GPIO0_DI         0xB8000050u
#define GPIO0_DO         0xB8000054u
#define GPIO0_DIR        0xB8000058u

/* display engine: GMA layer 0 (enable, first region head) */
#define DE_BASE          0xB8006000u
#define GMA0_ENABLE      0xB8006300u      /* b0 on; b18 as the originals set it on revision 1 */
#define GMA0_HEAD        0xB8006304u
#define GMA0_ALPHA       0xB8006308u      /* global alpha: b0-7 value, b16 on (0xFF = none) */
#define GMA1_ENABLE      0xB8006380u      /* the second layer (gma_capture.LAYER_REGS) */
#define GMA_TRUECOLOUR   0xB80063B8u      /* the originals' driver writes 1 for a true-colour
                                             region (format < 8: ARGB1555), 0 for CLUT8 */
#define GMA_YCBCR        0x00080000u      /* bit 19 of a layer's enable register (the
                                             originals clear it).  When it is SET, a
                                             revision-1 S3811 skips the head's matrix and
                                             takes the layer's colours as YCbCr (red, green,
                                             blue fields = Cr, Y, Cb) -- measured on a real
                                             box; the demo leaves it clear */
/* A region head on a revision-1 S3811 is a 0x280-byte block: the 40-byte head,
   a scaling filter table at +0x40 and, at +0x240, the matrix the layer's RGB
   colours are converted to YCbCr with (gma_m36f_sync_block_header in both
   original applications); on revision 0 they leave the matrix zero. */
#define HEAD_SIZE        0x280u
#define HEAD_MATRIX      0x240u

/* ALi USB 2.0 host controller (hc_s3602) on the S3811 */
#define USB_BASE         0xB8032000u

/* RAM the demo uses beside its image (physical addresses; the CPU writes them
   through KSEG1, uncached, so the display engine reads what was written) */
#define FB_PHYS          0x02000000u      /* 1280 x 720 ARGB1555 = 1.8 MB: clear of the video
                                              buffers the original firmwares point the display
                                              engine and VCAP at (0x0116xxxx, 0x0146xxxx), which
                                              'video init' sets up again */
#define HEAD_PHYS        0x00F00000u      /* the GMA region head (HEAD_SIZE bytes, 32-byte aligned) */
#define CON_FB_PHYS      0x02200000u      /* the console's 1280 x 720 picture (console.c), shown instead of
                                              the test screen's through a head of its own */
#define CON_HEAD_PHYS    0x00F00800u      /* its region head (HEAD_SIZE bytes) */
#define USB_DMA_PHYS     0x00F00400u      /* the packet the USB controller receives by DMA (the
                                              keyboard's report; 32-byte aligned, read through KSEG1) */
#define USB_DMA_SIZE     64
#define USB_BULK_PHYS    0x00F01000u      /* a disk's bulk transfers (USB_BULK_SIZE bytes, 32-byte aligned) */
#define USB_BULK_SIZE    4096
#define KSEG1(p)         (0xA0000000u | (p))

static inline u32 cp0_count(void)
{
    u32 v;
    __asm__ volatile("mfc0 %0, $9" : "=r"(v));
    return v;
}

/* time.c */
void time_init(void);
u32 cpu_mhz(void);
u64 now_ticks(void);            /* CP0 Count extended to 64 bits (call often) */
u32 ticks_per_ms(void);
u64 now_ms(void);
u32 uptime_s(void);
void delay_us(u32 us);
void delay_ms(u32 ms);

/* dog.c (time.c feeds it every 0.1 s) */
int dog_start(void);            /* 1: running in reset mode; 0: its counter does not count, left off */
void dog_feed(void);
void dog_stop(void);
void dog_hold(void);            /* no more feeding: the box resets DOG_SECONDS later */
int dog_running(void);
u32 dog_rate(void);             /* counter ticks per second, as measured */
u32 dog_start_value(void);
u32 dog_count(void);

/* uart.c */
void uart_init(void);
void uart_putc(char c);
void uart_puts(const char *s);
int uart_getc(void);            /* -1: nothing received */
void uart_rx_poll(void);        /* received bytes from the chip's FIFO into the buffer (time.c calls it) */
void uart_flush(void);          /* until the transmitter is empty */
void uart_capture(u8 *buf, u32 max);    /* what is printed goes into buf instead ('command > file'; LF line ends) */
u32 uart_capture_end(u32 *over);        /* the bytes captured; *over: the ones that did not fit */
void uprintf(const char *fmt, ...);
void vuprintf(const char *fmt, va_list ap);
int usnprintf(char *buf, int size, const char *fmt, ...);

/* gfx.c */
#define SCREEN_W 1280
#define SCREEN_H 720
#define RGB(r, g, b) ((u16)(0x8000u | (((r) >> 3) << 10) | (((g) >> 3) << 5) | ((b) >> 3)))
void gfx_init(void);
void gfx_enable(int on);
int gfx_enabled(void);
u32 gfx_enable_at_start(void);  /* 0xB8006300 as the demo found it, before it wrote it */
void gfx_fill(int x, int y, int w, int h, u16 color);
void gfx_gradient(int x, int y, int w, int h, u16 top, u16 bottom);
void gfx_frame(int x, int y, int w, int h, int t, u16 color);
int gfx_text(int x, int y, const char *s, int scale, u16 fg);
int gfx_text_bg(int x, int y, const char *s, int scale, u16 fg, u16 bg);
int gfx_text_width(const char *s, int scale);
u16 gfx_get(int x, int y);
u32 gfx_head_phys(void);
u32 gfx_fb_phys(void);
u16 rgb_from_hex(u32 rrggbb);
void gfx_cursor(int x, int y, int on);  /* the mouse pointer: its tip at (x, y), shown or not */
void gfx_cursor_refresh(void);          /* the main loop: drawn again after drawing took it away */
void gfx_view(int console);             /* what the TV shows: the console (1) or the test screen (0) */
int gfx_view_console(void);
void gfx_target(int console);           /* where gfx_* draw: the console's picture or the test screen's (0) */
void gfx_cell(int x, int y, char c, u16 fg, u16 bg);   /* a 12 x 16 character cell (x even) */
u32 gfx_console_head_phys(void);

/* console.c: the console on the TV (what the UART shows, scrolling) */
void console_putc(char c);              /* uart.c: every character sent */
void console_start(void);               /* the picture is set up: draw from now on */
void console_service(void);             /* every main loop pass: the screen kept current */
void console_redraw(void);              /* everything drawn again (after the view switched to it) */
void console_scroll(int pages);         /* PgUp (1) / PgDn (-1): half a screen back or forward */

/* panel.c (TM1650 over bit-banged I2C; or, on a board without it, two
   buttons on the same pins: GPIO 31 = UP, GPIO 9 = DOWN, low when pressed) */
#define PANEL_BUTTON_UP   1
#define PANEL_BUTTON_DOWN 2
int panel_init(void);           /* 1: a TM1650 answered; 0: none, the pins are inputs from now on */
int panel_present(void);
void panel_text(const char *four);
const char *panel_current(void);
int panel_read_key(void);       /* key byte (0x44..0x77, bit 6 = pressed), -1: no ACK / no chip */
int panel_buttons(void);        /* without a TM1650: PANEL_BUTTON_* bits of the buttons held now */
void panel_brightness(int level);

/* ir.c */
struct ir_event {
    u32 code;                   /* the 32 bits as the SDK's NEC decoder shifts them in (MSB first) */
    u8 bytes[4];                /* address, address 2, command, command 2, LSB first on the wire */
    u8 repeat;                  /* a repeat frame (no data) */
    u8 valid;                   /* a complete NEC frame */
    u16 runs;                   /* run-length entries in the frame */
};
void ir_init(void);
int ir_poll(struct ir_event *ev);      /* 1: a frame ended (ev filled) */
void ir_set_raw(int on);
u32 ir_frames(void);
const char *ir_key_name(u32 code);

/* usb.c */
void usb_status(void);
void usb_bus_reset(void);
void usb_init(void);            /* the controller set up again ('usb init') */
int usb_reg(u32 offset, int write, u8 value);  /* one register, byte-wide: its value, < 0 refused */
int usb_connected(void);
int usb_enumerate(void);        /* the bus set up: the device on the port and, through hubs, every device
                                   behind it (addresses from 1, descriptors listed); 0 when the first answered */
int usb_enumerate_quiet(void);  /* the same without the listing */
void usb_removed(void);         /* the port lost its device: nothing is on the bus any more */
int usb_bounced(void);          /* its device went and came back between two looks, and is not set up now */
int usb_still_set_up(u8 device);        /* it answers, in its configuration */
int usb_set_up_again(u8 device);        /* one that lost its set-up: 0 set up again (behind a hub: that port
                                           alone; on the controller's port: the bus), -1 not */
int usb_set_interface(u8 device, u8 iface, u8 alt);    /* SET_INTERFACE (its toggles: DATA0): 0, -1 */
int usb_in_pending(void);               /* an interrupt IN (mouse, keyboard) is under way on endpoint B */
int usb_hub_poll(void (*before)(void));  /* every 100 ms: one port of one hub looked at -- a device plugged
                                   in is set up, one unplugged forgotten; 1 when it said so (after before()) */
int usb_present(u8 device);     /* is the device still plugged in where it was found? */
u8 usb_last_error(void);        /* the token error register after the last failure (0x80 stall, 0x20 no answer) */
void usb_lsusb(void);           /* the controller and every device, one line each */
const char *usb_summary(void);  /* "vvvv:pppp product" of the keyboard in use or the device on the port, "" */
int usb_request(u8 device, u8 rtype, u8 request, u16 value, u16 index, u8 *data, u16 len, u32 timeout_ms);
                                /* a control transfer to the device with that address (IN data or none):
                                   bytes received, -1 */
const char *usb_error_text(void);       /* why the last transfer failed */
int usb_in_start(u8 device, u8 ep, u16 size);   /* an IN to the device's endpoint (the controller's endpoint
                                           B, DMA): asked again every ms until the device has a packet; -1 the
                                           device does not answer */
int usb_in_read(u8 *data, int max);     /* its packet: bytes, 0 nothing yet, -1 error, -2 empty, -3 there is no
                                           IN (a bulk transfer took endpoint B: start it again) */
void usb_in_stop(void);
void usb_int_open(int slot, u8 device, u8 ep, u16 size, u8 interval);  /* interrupt endpoints read in turns on
                                           endpoint B: slot 0 the keyboard's, 1 a mouse's (when endpoint D is
                                           taken); interval: the endpoint's bInterval (ms) */
void usb_int_close(int slot);
int usb_int_take(int slot, u8 *data, int max);  /* > 0 a report, 0 nothing yet, -1 failed (closed), -2 empty */
u32 usb_int_drops(int slot);            /* packets dropped for their data toggle */
void usb_int_poll(void);                /* every main loop pass, before kbd_poll / mouse_poll */
int usb_bulk_in(u8 device, u8 ep, u16 maxp, u8 *data, u32 len, u32 timeout_ms);  /* bytes, -1 */
int usb_bulk_in_packet(u8 device, u8 ep, u16 maxp, u8 *data, u32 timeout_ms);
                                        /* one packet of any size: bytes, 0 none in time, -1 failed, -2 a
                                           zero-length packet (a token spoilt on the bus: tried again) */
int usb_bulk_out(u8 device, u8 ep, u16 maxp, const u8 *data, u32 len, u32 timeout_ms);  /* 0, -1 */
int usb_clear_halt(u8 device, u8 ep);   /* CLEAR_FEATURE(ENDPOINT_HALT) (bit 7 of ep: IN): 0, -1 */
int usb_bulk_sync(u8 device, u8 out_ep, u8 in_ep);  /* before a bulk-only command: both toggles in step */
int usb_epd_open(u8 device, u8 ep, u16 size, u8 interval);  /* endpoint D polls the device's interrupt IN
                                           endpoint by itself: 0, -1 no answer, -2 it polls another device */
void usb_epd_close(void);
int usb_epd_take(u8 *data, int max);    /* > 0 a report (it polls on), 0 nothing yet, -1 failed (stopped), -2 empty */
u8 usb_epd_device(void);                /* the device endpoint D polls, 0: none */
void usb_epd_counts(u32 *every_us, u32 *reports, u32 *drops);

/* mouse.c: a USB mouse (HID boot protocol): a pointer on the TV, painting */
const char *mouse_start(u8 device, u8 iface, u8 ep, u16 size, u8 interval);  /* after SET_CONFIGURATION */
void mouse_stop(void);
int mouse_active(void);
u8 mouse_device(void);                  /* the address of the mouse in use, 0: none */
void mouse_yield_epd(void);             /* endpoint D to the keyboard: the mouse reads through endpoint B */
int mouse_moving_on_b(void);            /* moving, read through endpoint B: eth.c reads less often */
const char *mouse_poll(void);           /* every main loop pass; a line to show, or 0 */
void mouse_show_status(void);

/* disk.c: USB mass storage (bulk-only, SCSI) and FAT file systems */
const char *disk_attach(u8 device, u8 iface, u8 in_ep, u8 out_ep, u16 maxp);  /* a line about the disk */
void disk_detach(u8 device);
void disk_list(void);                   /* 'disks' */
void disk_ls(const char *path);         /* 'ls [n:][/path]' (relative to the current directory) */
void disk_cat(const char *path);        /* 'cat [n:]/path' */
void disk_sector(const char *where);    /* 'sector [n:]<lba>' */
int disk_count(void);
void disk_cd(const char *path);         /* 'cd [n:][path]' */
void disk_pwd(void);                    /* 'pwd' */
const char *disk_cwd(void);             /* "3:/docs" (the prompt shows it), "" before any 'cd' */
void disk_mkdir(const char *path);      /* 'mkdir', 'rmdir', 'rm', 'touch': the FAT volume written */
void disk_rmdir(const char *path);
void disk_rm(const char *path);
void disk_touch(const char *path);
void disk_write_file(const char *path, const u8 *data, u32 len, int append);  /* 'command > path' / '>>' */
void disk_cp(const char *from, const char *to);         /* 'cp': a file, onto any FAT volume */
void disk_mv(const char *from, const char *to);         /* 'mv': rename / move on the same volume */

/* serial.c: USB serial ports (a GSM / LTE module's AT, modem and diagnostic ports; CDC ACM) */
#define SERIAL_PORTS 8
const char *serial_attach(u8 device, u8 iface, u8 control, int acm, u8 in_ep, u8 out_ep, u16 maxp,
                          const char *name);   /* control: the interface with the modem control (ACM's
                                                  communications interface); a line about the port */
void serial_detach(u8 device);          /* 0: all */
int serial_count(void);
void serial_list(void);                 /* 'tty' */
void serial_cu(int port);               /* 'cu [n]': the terminal joined to port n (-1: the AT port) until
                                           "~." or Ctrl-] */
void serial_at(const char *command);    /* 'at <command>': one AT command to the AT port, its answer */
int at_prefixed(const char *s);         /* "AT..." in any case */

/* eth.c: wired Ethernet through a USB adapter's CDC ECM function (an RTL8153's), DHCP, ARP, ping */
const char *eth_attach(u8 device, u8 ctrl_if, u8 data_if, u8 data_alt, u8 in_ep, u8 out_ep, u16 maxp, u8 int_ep,
                       u8 mac_string);  /* a line about the port */
void eth_detach(u8 device);             /* 0: all */
const char *eth_poll(void);             /* every main loop pass: frames, DHCP; a line to show, or 0 */
void eth_show(void);                    /* 'ifconfig' */
void eth_dhcp(void);                    /* 'dhcp': ask for an address again */
void eth_arp_list(void);                /* 'arp' */
void eth_ping(const char *host, int count);     /* 'ping [-c count] <host>' (0: until Ctrl-C) */
int eth_parse_ip(const char *s, u8 ip[4]);

/* kbd.c: a USB keyboard (HID boot protocol) typing into the command line */
const char *kbd_start(u8 device, u8 iface, u8 ep, u16 size, u8 interval);   /* after SET_CONFIGURATION */
u8 kbd_device(void);            /* the address of the keyboard in use, 0: none */
void kbd_stop(void);
int kbd_active(void);
const char *kbd_poll(void);     /* every main loop pass; a line to show, or 0 */
int kbd_getc(void);             /* the next character typed, -1: none */
void kbd_set_mode(int interrupt);       /* 0: GET_REPORT over endpoint 0, 1: the interrupt endpoint */
void kbd_set_raw(int on);               /* print every report that differs from the one before */
int kbd_lost(void);                     /* it stopped answering: set the device up again */
void kbd_show_status(void);

/* start.S: back through the original bootloader */
void platform_restart(void) __attribute__((noreturn));

#endif
