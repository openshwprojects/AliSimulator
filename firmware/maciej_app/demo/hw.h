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
void uart_inject(u8 c);                 /* a character uart_getc returns as if received (the telnet console) */
int uart_inject_room(void);
#define INJECT_ROOM 255                 /* uart_inject_room() with nothing waiting */
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
const char *console_last_line(void);    /* the last complete line printed ("" none yet) */
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
                                /* a control transfer to the device with that address (data IN or OUT):
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
int usb_bulk_sync(u8 device, u8 out_ep, u8 in_ep, int data_in);   /* before a bulk-only command: both
                                           toggles in step (with data in: the IN's at DATA0) */
int usb_epd_open(u8 device, u8 ep, u16 size, u8 interval);  /* endpoint D polls the device's interrupt IN
                                           endpoint by itself: 0, -1 no answer, -2 it polls another device */
void usb_epd_close(void);
int usb_epd_take(u8 *data, int max);    /* > 0 a report (it polls on), 0 nothing yet, -1 failed (stopped), -2 empty */
u8 usb_epd_device(void);                /* the device endpoint D polls, 0: none */
void usb_epd_counts(u32 *every_us, u32 *reports, u32 *drops);
u32 usb_epd_checks(void);               /* GET_STATUS asked of the device after failed tokens */

/* mouse.c: a USB mouse (HID boot protocol): a pointer on the TV, painting */
const char *mouse_start(u8 device, u8 iface, u8 ep, u16 size, u8 interval);  /* after SET_CONFIGURATION */
void mouse_stop(void);
int mouse_active(void);
u8 mouse_device(void);                  /* the address of the mouse in use, 0: none */
void mouse_yield_epd(void);             /* endpoint D to the keyboard: the mouse reads through endpoint B */
void mouse_retake_epd(void);            /* the keyboard that had endpoint D stopped: the mouse through it again */
int mouse_moving_on_b(void);            /* moving, read through endpoint B: eth.c reads less often */
const char *mouse_poll(void);           /* every main loop pass; a line to show, or 0 */
void mouse_show_status(void);

/* disk.c: USB mass storage (bulk-only, SCSI), FAT file systems and NTFS (read and written) */
const char *disk_attach(u8 device, u8 iface, u8 in_ep, u8 out_ep, u16 maxp);  /* a line about the disk */
void disk_detach(u8 device);
void disk_list(void);                   /* 'disks' */
void disk_ls(const char *path);         /* 'ls [n:][/path]' (relative to the current directory) */
void disk_cat(const char *path);        /* 'cat [n:]/path' */
void disk_sum(const char *path);        /* 'sum [n:]path': a file's size and CRC-32, read to its end */
void disk_rm_r(const char *path);       /* 'rm -r': a directory and everything in it */
void disk_cp_r(const char *from, const char *to);       /* 'cp -r': a directory with all in it */
void disk_df(const char *path);         /* 'df [n:]': the volumes' size, free and used space */
void disk_head(const char *path, u32 lines);    /* 'head [-n N]': a file's first lines */
void disk_tail(const char *path, u32 lines);    /* 'tail [-n N]': its last lines (of its last 16 KB) */
void disk_sector(const char *where);    /* 'sector [n:]<lba>' */
int disk_count(void);
void disk_cd(const char *path);         /* 'cd [n:][path]' */
void disk_pwd(void);                    /* 'pwd' */
const char *disk_cwd(void);             /* "3:/docs" (the prompt shows it), "" before any 'cd' */
void disk_mkdir(const char *path);      /* 'mkdir', 'rmdir', 'rm', 'touch': the volume written (FAT; NTFS when
                                           its journal is clean: 'ntfs' tells) */
void disk_rmdir(const char *path);
void disk_rm(const char *path);
void disk_touch(const char *path);
void disk_write_file(const char *path, const u8 *data, u32 len, int append);  /* 'command > path' / '>>' */
void disk_cp(const char *from, const char *to);         /* 'cp': a file, onto any FAT or NTFS volume */
void disk_mv(const char *from, const char *to);         /* 'mv': rename / move on the same volume */
void disk_ntfs(const char *volume, const char *what);   /* 'ntfs [n:]': an NTFS volume's geometry, its journal's
                                                           state, whether the demo writes it; 'ntfs n: reset-journal' */
/* what the explorer reads (explorer.c); errors are said on the UART like the commands' */
#define DISK_ENTRY_NAME 128
#define DISK_FILE       0
#define DISK_DIR        1
#define DISK_VOLUME     2
struct disk_entry {
    char name[DISK_ENTRY_NAME];         /* the long name as 'ls' shows it; a volume: "4:  FAT32 'STICK', ..." */
    u32 size;                           /* bytes (a volume: MB) */
    u32 size_hi;                        /* the size's bits 32..63 (NTFS: a file of 4 GB or more) */
    u16 date, time;                     /* FAT's */
    u8 kind;                            /* DISK_FILE, DISK_DIR, DISK_VOLUME */
    u8 attr;                            /* FAT's attribute byte (0x02 hidden; a volume: 0x02 not readable) */
};
int disk_dir_read(const char *path, struct disk_entry *out, int max, u32 *total);  /* entries, -1 */
int disk_volumes(struct disk_entry *out, int max);      /* every disk's volumes, named as 'cd' takes them */
void disk_cwd_volume(char *out, int size);              /* "disk 4: FAT32 'STICK', 39 MB", "" */
int disk_read_head(const char *path, u8 *buf, u32 max, u32 *size);       /* a file's first bytes, -1 */
int disk_exists(const char *path);      /* is there a file at that path? (nothing said when there is none) */
u32 disk_changes(void);                 /* changes when a disk comes or goes or a sector is written */
/* disk.c for ftp.c: a reader and a writer of its own (they last across main loop passes), -1 said why */
int disk_stat(const char *path, struct disk_entry *o);  /* a file, a directory, a volume's root: 0, -1 */
struct disk_space {
    u64 total, avail;                   /* bytes */
    u32 cluster;                        /* an allocation unit's bytes */
    char fs[8];                         /* "FAT32", "NTFS" */
    char label[34];
    u32 serial;
};
int disk_space(const char *path, struct disk_space *o); /* the volume holding path (smb.c): 0, -1 (said why) */
int disk_stream_open(const char *path, u64 *size);      /* 0, -1 */
u64 disk_stream_seek(u64 pos);                          /* to the sector holding pos, forwards or back (FTP's
                                                           REST, an .mp4's index): where it is now */
int disk_stream_read(u8 *buf, u32 max);                 /* max: 512 x n, 4096 at most; bytes, 0 the end, -1 */
void disk_stream_close(void);
u32 disk_stream_opens(void);            /* how often the reader was opened (a user that kept it: still its?) */
int disk_upload_open(const char *path, int append);     /* made / emptied / added to: 0, -1 */
int disk_upload_put(const u8 *data, u32 n);             /* 0, -1 (its clusters freed again) */
int disk_upload_close(void);                            /* its entry set: 0, -1 */
/* ftp.c: an FTP server on port 21 (the disks' volumes at its root, all of them, no password) */
const char *ftp_poll(void);             /* net_poll (the main loop only): a line to show, or 0 */
void ftp_status(void);                  /* 'netstat' */
int ftp_disk_busy(void);                /* a file moves (disk.c's reader / writer are FTP's now) */
/* smb.c: an SMB2 file server on port 445 (Windows' \\box\share: the disks' volumes as shares, no password) */
#define SMB_RAM_PHYS     0x00900000u      /* its buffers: a listing's entries (1 MB), each client's message in and
                                             answer out (128 KB each), the pipes' (srvsvc) -- free RAM between the
                                             demo's stack (to 0x00800000) and the USB / GMA buffers at 0x00F00000 */
#define SMB_RAM_SIZE     0x00200000u
/* (amiga.h's AMIGA_RAM_PHYS, 0x00B00000: the Amiga's chip, slow, Kickstart and extension memory, 512 KB each,
   2 MB to 0x00D00000) */
const char *smb_poll(void);             /* net_poll (the main loop only): a line to show, or 0 */
void smb_status(void);                  /* 'netstat' */
int smb_disk_busy(void);                /* a file is being written (disk.c's writer is the SMB server's now; its
                                           reader, kept between reads, may be taken: smb.c notices) */
/* http.c: the web page on port 80 (files, the TV's picture, the command line; no password) */
const char *http_poll(int in_cmd);      /* net_poll (0), net_uart_poll while a command runs (1): a line, or 0 */
void http_putc(char c);                 /* uart_putc: every character printed (the page's console) */
int http_clients(void);                 /* connections open now */
int http_disk_busy(void);               /* a file moves (disk.c's reader / writer are the page's now) */
void http_status(void);                 /* 'netstat' */

/* explorer.c: a file explorer on the TV (the test screen's picture), synced to the current directory */
void explorer_show(void);               /* 'explorer': on the TV (the listing follows on the next poll) */
void explorer_hide(void);               /* the test screen's picture is drawn by something else now */
int explorer_shown(void);               /* on the TV now: the USB keyboard's keys and the mouse are its own */
void explorer_key(int c);               /* a character from the USB keyboard (escape sequences in pieces) */
void explorer_mouse(int x, int y, u8 buttons, int wheel);  /* every mouse report while shown */
int explorer_poll(void);                /* every main loop pass: 1 when it changed the current directory */

/* serial.c: USB serial ports (a GSM / LTE module's AT, modem and diagnostic ports; CDC ACM) */
#define SERIAL_PORTS 8
#define SERIAL_ACM    1                 /* serial_attach's kinds: CDC ACM, the USB-serial chips (0: a module's own) */
#define SERIAL_CH34X  2
#define SERIAL_CP210X 3
#define SERIAL_FTDI   4
#define SERIAL_FTDI_H 5                 /* FT2232H / FT4232H / FT232H: another clock */
#define SERIAL_PL2303 6
#define SERIAL_FTDI_X 7                 /* FT-X / FT2232C/D: 48 MHz, the divisor's high bits as the H chips' */
int serial_chip(u16 vid, u16 pid, u16 bcd);     /* the USB-serial chip it is: SERIAL_*, 0 (bcd: bcdDevice) */
const char *serial_attach(u8 device, u8 iface, u8 control, int kind, u8 in_ep, u8 out_ep, u16 maxp,
                          const char *name);   /* control: the interface with the modem control (ACM's
                                                  communications interface; an FTDI's port number, 0 for a
                                                  chip with one); a line about the port */
void serial_stty(int port, u32 baud);   /* 'stty [n] [baud]' (port -1: all, baud 0: show) */
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
const char *eth_attach_rndis(u8 device, u8 ctrl_if, u8 data_if, u8 in_ep, u8 out_ep, u16 maxp);
                                        /* an LTE module's RNDIS function: the link when there is no Ethernet */
void eth_detach(u8 device);             /* 0: all */
const char *eth_poll(void);             /* every main loop pass: frames, DHCP; a line to show, or 0 */
void eth_show(void);                    /* 'ifconfig' */
void eth_dhcp(void);                    /* 'dhcp': ask for an address again */
void eth_arp_list(void);                /* 'arp' */
void eth_ping(const char *host, int count);     /* 'ping [-c count] <host>' (0: until Ctrl-C) */
int eth_parse_ip(const char *s, u8 ip[4]);

/* ---- networking: eth.c's IPv4 for tcp.c / net.c, TCP, wget, telnet, netload, NTP ---- */
#define KSEG0(p)         (0x80000000u | (p))
/* RAM the networking (and disk.c's NTFS reading) uses (physical; written through KSEG0, cached; clear of the
   video buffers the original firmwares' display set-up points the display engine and VCAP at: 0x0116xxxx,
   0x0146xxxx) */
#define WGET_PHYS        0x05000000u      /* 'wget -O': the body, up to WGET_MAX */
#define WGET_MAX         0x00800000u
#define NETLOAD_PHYS     0x06000000u      /* netload: the image received, up to NETLOAD_MAX */
#define NETLOAD_MAX      0x00700000u      /* (it is copied to 0x80000200: below the stack's 64 KB at 0x807F0000) */
#define NETLOAD_STUB_PHYS 0x06800000u     /* the copy + cache stub, run uncached from here */
#define NTFS_RUNS_PHYS   0x04000000u      /* disk.c: the runs of the NTFS file being read (cp, cat, sum), */
#define NTFS_RUNS_SIZE   0x00100000u      /* 12 bytes each: 87381 pieces at most */
#define NTFS_RUNS2_PHYS  0x04100000u      /* the same for the file the FTP server sends (NTFS_RUNS_SIZE bytes) */
#define FTP_ENTRIES_PHYS 0x04200000u      /* ftp.c: a directory's entries for a listing (1 MB) */
#define FTP_TEXT_PHYS    0x04300000u      /* ftp.c: the listing's text (1 MB) */
#define HTTP_ENTRIES_PHYS 0x04900000u     /* http.c: a directory's entries for a listing */
#define HTTP_ENTRIES_SIZE 0x00100000u
#define HTTP_TEXT_PHYS   0x04A00000u      /* http.c: each of its six connections' response text (a listing's
                                             JSON, the console's output), up to WGET_PHYS */
#define HTTP_TEXT_SIZE   0x00100000u
#define NTFS_UPCASE_PHYS 0x04400000u      /* disk.c, writing NTFS: the volume's $UpCase table (128 KB) */
#define NTFS_WORK_PHYS   0x04420000u      /* a directory's index being rebuilt: where its entries are, the plan of
                                             its new blocks (0x20000 bytes) */
#define NTFS_INDEX_PHYS  0x04500000u      /* that directory's entries themselves, up to NTFS_INDEX_SIZE */
#define NTFS_INDEX_SIZE  0x00400000u      /* (4096 entries with the longest names: 2.4 MB) */
int eth_ready(void);                    /* an address from DHCP */
const u8 *eth_address(void);
u32 eth_bound_count(void);              /* DHCP acknowledgements so far */
int eth_inside(void);                   /* eth code is reading / handling frames now (no eth_service in it) */
void eth_service(void);                 /* the frames waiting and TCP's timers, now (a command's waits) */
int eth_route(const u8 *ip, u8 mac[6]); /* the next hop's MAC (ARP up to 1 s): 1, 0 */
int eth_send_ipv4(u8 *frame, const u8 *mac, const u8 *ip, u8 proto, int len);  /* payload at frame + 34 */
int eth_send_multicast(u8 *frame, const u8 *group, u8 proto, int len, u8 ttl);  /* the same, to a group */
const u8 *eth_mac(void);                /* the link's MAC */
int eth_lookup(const char *host, u8 ip[4], const char *who);   /* a.b.c.d or DNS: 1, 0 (said why) */
int eth_dns_start(const char *name);    /* a DNS question, not waited for: 0, -1 */
int eth_dns_result(u8 ip[4]);           /* its answer: 1, 0 none yet, -1 no such name */

/* tcp.c: a few TCP connections, active (tcp_connect) and passive (tcp_listen + tcp_accept) */
#define TCP_FAILED     -1               /* refused, reset, timed out, the network went (tcp_why) */
#define TCP_CONNECTING  0
#define TCP_OPEN        1
#define TCP_PEER_DONE   2               /* the peer closed its side: what it sent can still be read */
#define TCP_DONE        3               /* closed both ways */
void tcp_input(const u8 *src, const u8 *dst, const u8 *src_mac, const u8 *seg, int len);   /* eth.c */
void tcp_poll(void);                    /* timers, sending (eth_poll, eth_service) */
int tcp_busy(void);                     /* a connection moves data: eth_poll reads frames on every pass */
void tcp_drop_all(void);                /* the Ethernet port went or got a new address */
int tcp_listen(u16 port);               /* 0, -1 no room */
int tcp_accept(u16 port);               /* an established connection that came in on the port: its number, -1 */
int tcp_connect(const u8 ip[4], u16 port);      /* its number (SYN sent), -1 no route / no room */
int tcp_status(int c);                  /* TCP_* */
const char *tcp_why(int c);             /* why it is TCP_FAILED */
int tcp_send(int c, const void *data, int len);         /* bytes taken into its send buffer (sent by tcp_poll) */
u32 tcp_room(int c);                    /* free bytes in its send buffer */
void tcp_push(int c);                   /* send what the buffer and the peer's window allow, now */
int tcp_recv(int c, void *data, int max);       /* bytes received so far (0 none) */
u32 tcp_unread(int c);                  /* received bytes not read yet */
void tcp_shutdown(int c);               /* a FIN after the data; the connection stays the caller's */
void tcp_close(int c);                  /* the same, and the connection is given up (it ends by itself) */
void tcp_abort(int c);                  /* RST, given up */
void tcp_peer(int c, u8 ip[4], u16 *port);
void tcp_list(void);                    /* 'netstat' */

/* net.c: wget, the telnet console (port 23), network loading (port 6464), NTP time */
void net_udp_input(const u8 *src, u16 sport, u16 dport, const u8 *data, int len);   /* eth.c */
const char *net_poll(void);             /* eth_poll's servers and the clock's setting; a line to show, or 0 */
void net_command(int running);          /* main.c: a command runs (1) / ended (0) */
void net_uart_poll(void);               /* uart_getc: the telnet client's typing (in a command: the network too) */
void telnet_putc(char c);               /* uart_putc: every character printed, to the telnet client */
int ntp_clock_text(char *buf, int size);        /* "11:23:45 CET" once NTP set the clock: 1, else 0 */
u32 net_clock_utc(void);                /* seconds since 1970 (UTC) once NTP set the clock, else 0 */
void cmd_wget(int argc, char **argv);
void cmd_ntp(int argc, char **argv);
/* ssdp.c: SSDP (UPnP discovery, UDP 1900): the box in Windows' Network folder, its web page */
void ssdp_input(const u8 *src, const u8 *mac, u16 sport, const u8 *data, int len);     /* eth.c (mac: the sender's),
                                                                                           net.c (to us: mac 0) */
const char *ssdp_poll(void);            /* net_poll: announcements, answers */
int ssdp_description(char *buf, int size);      /* http.c: /ssdp/device.xml */
void ssdp_status(void);                 /* 'netstat' */
/* tls.c: TLS for wget's https:// (BearSSL 0.6, ../bearssl) over one tcp.c connection at a time */
void tls_stir(u32 v);                   /* eth.c: each frame as it arrives (randomness for TLS's keys) */
int tls_begin(int c, const char *host, int check);     /* the handshake (check: the certificate): 1, 0 (said why) */
int tls_write(const void *data, int n); /* all of it: n, -1 (said why) */
int tls_read(u8 *buf, int max);         /* bytes, 0 the end, -1 (tls_why) */
const char *tls_why(void);
const char *tls_info(void);             /* "TLS 1.2, ECDHE_RSA_WITH_AES_128_GCM_SHA256" */
void tls_end(void);                     /* close_notify sent (not waited for); the connection stays the caller's */
void cmd_date(int argc, char **argv);
void cmd_netstat(int argc, char **argv);

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
int kbd_held(u8 usage);                 /* is the key with that HID usage held now? (a game's buttons) */
int kbd_held_all(u8 *usages, int max);  /* every key held now as HID usages, modifiers as 0xE0..0xE7: how many */
void kbd_show_status(void);

/* play.c: the game players (only one runs at a time: EMU_RAM_PHYS..SND_I2S_PHYS is theirs) */
#define MEDIA_PHYS       0x02400000u      /* a cartridge file, a picture file: read whole into RAM (cached) */
#define MEDIA_MAX        0x01000000u      /* 16 MB */
#define EMU_RAM_PHYS     0x03400000u      /* a machine's own RAM / VRAM / tables (cached KSEG0, 9.5 MB) */
#define EMU_RAM_SIZE     0x00980000u
#define PICTURE_PHYS     0x03D80000u      /* play.c's picture and previous-frame buffers (1.5 MB, up to 0x03F00000) */
int nes_play(const char *path, u32 frames, const char *script);    /* 'nes': 0, -1 it could not start */
int gb_play(const char *path, u32 frames, const char *script);     /* 'gb': the same for a Game Boy game */
int sms_play(const char *path, u32 frames, const char *script);    /* 'sms': a Master System game */
int gg_play(const char *path, u32 frames, const char *script);     /* 'gg': a Game Gear game */
int sg_play(const char *path, u32 frames, const char *script);     /* 'sg': an SG-1000 / SC-3000 game */
int zx_play(const char *path, u32 frames, const char *script);     /* 'zx': a ZX Spectrum 48K/128K/TR-DOS program ("": BASIC) */
int a26_play(const char *path, u32 frames, const char *script);    /* 'a26': an Atari 2600 game */
int c64_play(const char *path, u32 frames, const char *script);    /* 'c64': a C64 program ("": BASIC) */
int amiga_play(const char *path, u32 frames, const char *script);  /* 'amiga': an .adf ("": no disk) */
int dos_play(const char *path, u32 frames, const char *script);    /* 'dos': a DOS program (.exe, .com) */
int md_play(const char *path, u32 frames, const char *script);     /* 'megadrive': a Mega Drive / Genesis game */
void md_play_region(int region);        /* the console its next game runs on: 'J', 'U', 'E', 0 the header's */
int pce_play(const char *path, u32 frames, const char *script);    /* 'pce': a PC Engine / TurboGrafx-16 HuCard */
int col_play(const char *path, u32 frames, const char *script);    /* 'coleco': a ColecoVision cartridge (.col) */
int msx_play(const char *path, u32 frames, const char *script);    /* 'msx': an MSX1 ROM cartridge (.rom, .mx1) */
int msx2_play(const char *path, u32 frames, const char *script);   /* 'msx2': an MSX2 cartridge or disk (.mx2, .dsk, .rom) */
int ws_play(const char *path, u32 frames, const char *script);     /* 'ws': a WonderSwan / Color game (.ws, .wsc) */
int snes_play(const char *path, u32 frames, const char *script);   /* 'snes': a Super NES game (.sfc, .smc) */
int neo_play(const char *path, u32 frames, const char *script);    /* 'neogeo': a Neo Geo game (.neo) */
int gba_play(const char *path, u32 frames, const char *script);    /* 'gba': a Game Boy Advance game (.gba) */
int a78_play(const char *path, u32 frames, const char *script);    /* 'a78': an Atari 7800 game (.a78) */
int lnx_play(const char *path, u32 frames, const char *script);    /* 'lynx': an Atari Lynx game (.lnx) */
int vec_play(const char *path, u32 frames, const char *script);    /* 'vectrex': a Vectrex game (.vec, "": Mine Storm) */
int fds_play(const char *path, u32 frames, const char *script);    /* 'fds': a Famicom Disk System disk (.fds) */
int ngp_play(const char *path, u32 frames, const char *script);    /* 'ngp': a Neo Geo Pocket Color game (.ngp, .ngc) */
int o2_play(const char *path, u32 frames, const char *script);     /* 'odyssey2': an Odyssey2 / Videopac game (.o2) */
int intv_play(const char *path, u32 frames, const char *script);   /* 'intv': an Intellivision game (.int) */
int psx_play(const char *path, u32 frames, const char *script);    /* 'psx': a PlayStation 1 program / disc (.exe, .cue) */
void psx_play_region(int region);       /* 'J', 'U' (60 Hz NTSC), 'E' (50 Hz PAL), 0 auto */
int cps_play(const char *path, u32 frames, const char *script);    /* 'cps': a Capcom CPS-1 / CPS-2 arcade game (.cps, .zip) */
int st_play(const char *path, u32 frames, const char *script);     /* 'atarist': an Atari ST disk or program (.st, .msa, .prg, .tos) */
int s16_play(const char *path, u32 frames, const char *script);    /* 'sys16': a Sega System 16A / 16B / OutRun arcade game (.s16, .zip) */
int a8_play(const char *path, u32 frames, const char *script);     /* 'atari8': an Atari 800XL / 130XE disk, .xex or cart ("": BASIC) */
int a52_play(const char *path, u32 frames, const char *script);    /* 'a5200': an Atari 5200 SuperSystem cartridge (.a52, .car) */
int megaduck_play(const char *path, u32 frames, const char *script); /* 'megaduck': a Mega Duck / Cougar Boy cartridge (.duck, .md1, .md2, .bin) */
int sv_play(const char *path, u32 frames, const char *script);     /* 'sv': a Watara Supervision cartridge (.sv) */
int chip8_play(const char *path, u32 frames, const char *script);  /* 'chip8': a CHIP-8 / SCHIP / XO-CHIP program (.ch8, .sc8, .xo8) */
int channelf_play(const char *path, u32 frames, const char *script); /* 'channelf': a Fairchild Channel F cartridge (.chf, .bin, .rom) */
int pokemini_play(const char *path, u32 frames, const char *script); /* 'pokemini': a Nintendo Pokemon Mini cartridge (.min) */

/* view.c: the picture viewer (image.c decodes JPEG, PNG, GIF, BMP) */
#define IMAGE_WORK_PHYS  0x06900000u      /* the picture as shown, and the decoder's memory (a progressive JPEG's */
#define IMAGE_WORK_SIZE  0x01600000u      /* coefficients: about 3 bytes a pixel) -- up to 0x07F00000 */
#define VIEW_LIST_PHYS   0x07F00000u      /* the picture's directory, for the next / the one before (1 MB) */
#define VIEW_LIST_SIZE   0x00100000u
/* av.c (the video player, av.h): its decoder's buffers in IMAGE_WORK (0x06900000..0x07F00000: the viewer's,
   never used at the same time), the streams read and an .mp4's index in 0x05800000..0x06000000 (between
   WGET_PHYS's 8 MB and NETLOAD_PHYS) */
void view_file(const char *path, int once);     /* 'view': the picture on the TV; once: shown, not waited on */
void view_set_mode(int mode);           /* 'view -s': 1, image.c's decoder only; 'view -c': 2, both compared */
/* jpeghw.c: baseline JPEG by the video engine's JPEG mode (view.c's first try; image.c's decoder otherwise) */
const char *jpeghw_plan(const u8 *data, u32 size, u32 data_phys, u32 min_w, u32 min_h, u32 *out_w, u32 *out_h);
                                        /* 0 (the size it makes: pre-scaled, at least min_w x min_h), or why not */
const char *jpeghw_detail(void);        /* "4:2:0, 1/2" */
const char *jpeghw_run(u32 work_phys, u32 work_size, void (*row)(void *ctx, u32 y, const u8 *rgb), void *ctx,
                       u32 *decode_ms);  /* its rows of RGB: 0, or why not (no row given then) */
int view_is_picture(const char *name);  /* .jpg .jpeg .png .gif .bmp */
const char *view_last(void);            /* the path of the picture it showed last (the explorer selects it) */
void tv_opening(const char *path, int bar);     /* "Opening NAME ..." on the TV at once (bar: a strip at the top,
                                                   over the picture shown now) */
void tv_failed(const char *path, int bar, int wait);    /* "Could not open NAME" and why (the last line printed);
                                                           wait: up to 4 s, a key ends it */

/* start.S: back through the original bootloader */
void platform_restart(void) __attribute__((noreturn));

#endif
