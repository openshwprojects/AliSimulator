/* USB: the S3811's USB 2.0 host controller (ALi's own, driven by the SDK's
   hc_s3602 / hcd_s3602 code; the original applications attach it at
   0xB8032000).  Register meanings from the SDK's accessor functions and
   interrupt handlers (refs/MainCode/ddk/libcore_v40b.a) and from the box's
   own firmware, whose driver was traced in the emulator (dump.bin and
   dump_maciej.bin; src/usb_host.py lists the registers).

   The demo polls (CPU interrupts stay off).  It sets the controller up the
   way the box's firmware does for the chip's revision -- the USB block's
   reset, the PHY's reset and its settings at +0xF0 / +0xF4, host mode, the
   endpoints -- resets the bus and enumerates the device with control
   transfers on endpoint 0 (its descriptors, its strings) and configures it.
   A hub's ports are powered and each device behind it is reset and
   enumerated the same way with the next address (a hub behind a hub too:
   fifteen devices in all, hubs among the first seven); one port is asked
   for its status every 100 ms, so
   plugging in and pulling out is noticed.  A device that is not high speed
   behind a high-speed hub is reached through the hub's transaction
   translator: the split flag in the endpoint's address register and the
   hub's address and port in the register after it.
   A keyboard (an interface of class HID, protocol keyboard) is handed to
   kbd.c, which reads its key reports from its interrupt endpoint -- an IN
   transfer on the controller's endpoint B, which receives into RAM by DMA
   (the SDK's bulk IN, hcd_s3602_bulkin_start) -- or with GET_REPORT over
   endpoint 0.  A mouse (HID, protocol mouse) goes to mouse.c, its endpoint
   polled by the controller's endpoint D on its own; a USB stick or card
   reader (mass storage, bulk-only) to disk.c, which sends its commands
   through endpoint A and receives through endpoint B.

   Measured on a real S3811 (revision 1) with a seven-port high-speed hub:
     - a low-speed keyboard behind it answers control transfers with +0x80 =
       address << 1 | 1 and +0x81 = 0x40 (low speed) | port << 3 | the hub's
       address, and endpoint B's IN with the same in +0x84 / +0x85; an
       endpoint it does not have comes back as a stall 0.24 ms later (the
       translator's answer), not as "no response";
     - with +0x90 (set_plug_status) at 2 or 3 the controller does not split.
   And before, with the low-speed keyboard on the box's own port:
     - endpoint C, the SDK's interrupt endpoint (hcd_s3602_IntInC_start: a
       token every +0xA2 ms while +0x2B bit 5 is set), sends nothing at all to
       a low-speed device: no data, and no error for an address nobody has;
     - endpoint B's IN does: the first token at once, then one per millisecond
       while the device answers NAK (+0xA8 = 1; 2..15 that many per
       millisecond, 0 one after the other, 0x10 and above never again), "no
       response" within 0.2 ms when nobody answers; a packet is in RAM about
       0.1 ms after its token;
     - its data toggle lasts from one transfer to the next and goes back to
       DATA0 when bit 0 of +0x17 is pulsed; a packet with the wrong toggle is
       acknowledged and dropped (token error 0x08), as the USB rules say;
     - only the FIFO reset (+0x17 bit 4) ends a pending IN: clearing the
       transfer's bits in +0x32 does not. */
#include "hw.h"

#define USB ((volatile u8 *)USB_BASE)
#define USB32(off) REG32(USB_BASE + (off))
#define SYS_RESET 0xB8000080u           /* bit 28: the USB block (the originals' pulse) */

/* registers (byte offsets) */
#define R_PORT         0x10  /* b0 over-current, b1 device connected, b2 see hc_init, b5 bus reset
                                (the controller ends it), b6 suspend, b7 resume */
#define R_EP0          0x11  /* endpoint 0: b0-1 token PID (0 SETUP, 1 OUT, 2 IN), b4 FIFO reset,
                                b5 send the token; read: b7 FIFO empty */
#define R_EP0_FIFO     0x12
#define R_EPA          0x13  /* endpoint A: b6-7 transfer type (0x80 bulk), b2-5 the device's endpoint */
#define R_EPA_STATUS   0x14  /* b4 FIFO reset, b0 pulsed: the data toggle back to DATA0; read: b2 all sent */
#define R_EPB          0x16  /* endpoint B: b6-7 transfer type (0x80 bulk), b2-5 the device's endpoint */
#define R_EPB_STATUS   0x17  /* b4 FIFO reset (it also ends a pending IN), b0 pulsed: the data toggle back to DATA0 */
#define R_EPC          0x19  /* endpoint C: b6-7 transfer type (0xC0 interrupt), b2-5 the device's endpoint */
#define R_EPC_STATUS   0x1A  /* b4 FIFO reset; read: b7 FIFO empty */
#define R_TOKEN_ERROR  0x1D  /* why the last token failed (hcd_s3602_upt_parse_error's codes) */
#define R_INT_EN1      0x1E
#define R_INT_EN2      0x1F
#define R_FLAGS1       0x20  /* read to clear: b0 connection changed, b1 bus reset done */
#define R_FLAGS2       0x21  /* read to clear: endpoint 0 b7 done / b3 error, A b6 / b2, B b5 / b1, C b4 / b0 */
#define R_EPB_LAST     0x2C  /* 16 bits: the size of endpoint B's last packet (get_epb_last_data_size) */
#define R_FLAGS3       0x2F
#define R_EPAB_SIZE    0x30  /* b4-6: endpoint B's packet size, 8 << n, with b7 (b0-2 and b3: endpoint A's) */
#define R_SPEED        0x32  /* b5-6: the device's speed, 0x00 high, 0x20 full, 0x40 low; b2 the controller
                                sends the IN tokens, b3 the DMA transfer runs (it clears both at the end) */
#define R_MODE         0x34  /* |= 0x90: host mode */
#define R_DMA_RX_COUNT 0x38  /* 24 bits: the bytes to receive */
#define R_RESET_CFG    0x3D  /* revision 0: |= 0x60 before a bus reset */
#define R_AUTO         0x3E  /* |= 0x08: en_epa_auto_force */
#define R_DMA_RX_BASE  0x40  /* 32 bits: the receive buffer's physical address (32-byte aligned) */
#define R_DMA_RX_INDEX 0x44  /* 32 bits */
#define R_DMA_RX_DONE  0x48  /* 24 bits: the bytes received */
#define R_DMA_TX_BASE  0x50  /* 32 bits: the transmit buffer's physical address (32-byte aligned) */
#define R_DMA_TX_INDEX 0x54
#define R_DMA_TX_COUNT 0x58  /* 24 bits: the bytes to send */
#define R_DMA_STATE    0x60  /* strobes: b5 / b4 the DMA receiver's state set up / its transfer started, b1 / b0
                                the same for the transmitter */
#define R_INTF_MASK    0x62
#define R_INTF_STATUS  0x63
#define R_DMA_AUTO     0x68  /* 0x80 | size code << 4: receive; 0x08 | size code: transmit */
#define R_EP0_ADDRESS  0x80  /* new mode: endpoint 0's device address << 1; bit 0: the device is reached
                                through a high-speed hub's transaction translator (split transfers) */
#define R_EP0_SPLIT    0x81  /* that hub and port (set_ssplit_ctrl_info): b0-2 the hub's address, b3-5 its
                                port, b6 the device is low speed */
#define R_EPA_ADDRESS  0x82  /* the same pair for endpoint A */
#define R_EPA_SPLIT    0x83
#define R_EPB_ADDRESS  0x84  /* and for endpoint B */
#define R_EPB_SPLIT    0x85
#define R_NEW_MODE     0x8F  /* 0x80: the per-endpoint device addresses (the originals set it) */
#define R_NAK_RETRY    0xA8  /* 1: an IN the device answered with NAK is sent again in the next frame (1 ms) */
#define R_PHY0         0xF0  /* 32-bit PHY settings */
#define R_PHY_RESET    0xF2  /* 7, 2 ms, 0 (byte writes, nothing else in between) */
#define R_PHY1         0xF4

static int initialized;
static int quiet;                       /* a quiet set-up (lsusb, a retry): without the details */

/* a detail of the set-up, unless quiet -- a function, so that its arguments always run (as a macro it
   skipped them: disk_attach and serial_attach written inside it never ran in a quiet set-up) */
static void SAY(const char *fmt, ...)
{
    if (quiet)
        return;
    va_list ap;
    va_start(ap, fmt);
    vuprintf(fmt, ap);
    va_end(ap);
}

/* The devices on the bus: devices[a - 1] has the address a.  The first is
   the one on the controller's own port; a hub's devices follow as its ports
   are looked at.  Fifteen: the endpoints' address registers hold four bits
   of it (set_ep_device_address masks 0xF).  A hub needs one of the first
   seven, and only its first seven ports are reached: the split registers
   hold three bits of a hub's address and of its port. */
#define DEVICES     15
#define HUB_MAX     7                   /* the highest address a hub can have */
#define HUB_PORTS   7
#define SPEED_LOW   1                   /* (hcd_ioctrl_get_speed's codes) */
#define SPEED_FULL  2
#define SPEED_HIGH  3
struct device {
    u8 used;
    u8 address;                         /* 0 until SET_ADDRESS, then its place's number */
    u8 speed;
    u8 hub, port;                       /* the hub (its address) and port it is plugged into; hub 0: the
                                           controller's own port */
    u8 ep0_max;
    u8 split, info;                     /* not high speed, behind a high-speed hub: R_EP0_ADDRESS bit 0 and
                                           R_EP0_SPLIT's value */
    u8 ports;                           /* a hub: the number of its ports (else 0) */
    u8 ignore;                          /* a hub: bit n -- port n's device did not answer; left alone until
                                           it is plugged in again */
    u8 kbd_ep, kbd_if, kbd_interval;    /* a keyboard: its interrupt endpoint (0: none), interface, interval */
    u8 mouse_ep, mouse_if, mouse_interval;  /* a mouse: its interrupt endpoint (0: none), interface, interval */
    u16 mouse_size;
    u8 in_ep, out_ep;                   /* the IN and OUT endpoint whose data toggle is kept (| 0x10; 0: none
                                           used since the configuration, all DATA0; 0xFF: not known) */
    u8 in_toggle, out_toggle;           /* theirs: 0 DATA0, 1 DATA1 */
    u8 msc_if, msc_in, msc_out;         /* a mass-storage interface (bulk-only): its number, its bulk
                                           endpoints (0: none) */
    u16 msc_max;                        /* their packet size */
    u16 kbd_size;
    u16 vid, pid;
    char mfr[24], product[28];
};
static struct device devices[DEVICES];
static char summary[48];                /* usb_summary's text */
static u8 ep0_max = 8;                  /* the packet size of the device endpoint 0 is aimed at */
static u8 flags1_seen;                  /* interrupt flags 1's bit 0 (connection changed) read, not handled yet */
static u8 flags2_seen;                  /* interrupt flags 2 read (reading clears them), not handled yet */
static u8 last_error;                   /* the token error register after the last failure; 0: time-out */
static const char *last_stage = "";    /* the stage a transfer is in (0: there is no such device) */
static const char *fail_stage = "";    /* the last failure, as usb_error_text tells it: its stage and token */
static u8 fail_error;                  /* error -- transfers that work after it (a recovery's) leave it */
static int in_pending;                  /* an IN is under way on endpoint B (usb_in_start) */
static u8 intf_seen;                    /* the interface status (+0x63) read (reading clears it) */
static u8 owner[2], owner_ep[2];        /* whom endpoint A (0) and B (1) served last: device, endpoint
                                           (| 0x10); 0: nobody known */
static u8 epd_device, epd_running;      /* the device endpoint D polls (0: none), and whether it polls now */
static u8 flags3_seen;                  /* interrupt flags 3 read (reading clears them), not handled yet */

int usb_connected(void)
{
    return (USB[R_PORT] >> 1) & 1;
}

/* what the screen shows for the port: the keyboard in use, else the device
   on the controller's port -- "vvvv:pppp product" -- and how many more
   devices a hub brought ("" when nothing is enumerated) */
const char *usb_summary(void)
{
    u8 a = kbd_device();
    const struct device *d = &devices[a ? a - 1 : 0];
    int others = -1;
    for (int i = 0; i < DEVICES; i++)
        if (devices[i].used && devices[i].address)
            others++;
    summary[0] = 0;
    if (d->used && d->address) {
        if (others > 0)
            usnprintf(summary, sizeof(summary), "%04x:%04x%s%s +%d", d->vid, d->pid, d->product[0] ? " " : "",
                      d->product, others);
        else
            usnprintf(summary, sizeof(summary), "%04x:%04x%s%s", d->vid, d->pid, d->product[0] ? " " : "", d->product);
    }
    return summary;
}

/* the speed of the device on the controller's own port (hcd_ioctrl_get_speed:
   +0x32 bits 5..6 are 0 high, 0x20 full, 0x40 low) */
static u8 root_speed(void)
{
    switch (USB[R_SPEED] & 0x60) {
    case 0x00: return SPEED_HIGH;
    case 0x20: return SPEED_FULL;
    case 0x40: return SPEED_LOW;
    }
    return 0;
}

static const char *speed_name(u8 speed)
{
    switch (speed) {
    case SPEED_HIGH: return "high speed (480 Mbit/s)";
    case SPEED_FULL: return "full speed (12 Mbit/s)";
    case SPEED_LOW: return "low speed (1.5 Mbit/s)";
    }
    return "unknown speed";
}

static u8 flags1(void)                  /* (bit 0, the connection changed, is kept for usb_bounced) */
{
    flags1_seen |= USB[R_FLAGS1];
    return flags1_seen;
}

static u8 flags2(void)
{
    flags2_seen |= USB[R_FLAGS2];
    return flags2_seen;
}

/* init_ep_fifo: bit 4 set, a wait, cleared.  The SDK waits OS_Delay(1).  The demo waited a millisecond, five
   times in every disk command (endpoint 0's control transfers too): a 512-byte read took 5.1 ms on the box,
   0.96 ms with 10 us (a card reader's FAT16 card: 666 -> 2000 KB/s in 4 KB reads, 0 commands lost; a FAT32
   stick 697 -> 2752 KB/s) */
static void fifo_reset(u8 reg)
{
    USB[reg] = 0x10;
    delay_us(10);
    USB[reg] = 0x00;
}

/* the DMA receiver's 24-bit count (set_dma_rx_cnt) */
static void dma_rx_count(u32 count)
{
    USB[R_DMA_RX_COUNT] = (u8)count;
    USB[R_DMA_RX_COUNT + 1] = (u8)(count >> 8);
    USB[R_DMA_RX_COUNT + 2] = (u8)(count >> 16);
}

/* revision 0 only: bit 2 of the port register cleared and set again (after
   the PHY set-up and before every bus reset; dump.bin's driver) */
static void port_bit2_toggle(void)
{
    USB[R_PORT] = (u8)(USB[R_PORT] & ~0x04);
    USB[R_PORT] = (u8)(USB[R_PORT] | 0x04);
}

/* the set-up of the box's own firmware (dump.bin's USB driver, traced in the
   emulator at both chip revisions): the USB block's reset pulse, the PHY's
   reset and settings, then hcd_s3602_hw_init -- host mode, endpoints A / B
   bulk and C / D interrupt, the FIFOs reset, the interrupt flags cleared */
static void hc_init(void)
{
    static const u8 types[][2] = {{0x13, 0x80}, {0x16, 0x80}, {R_EPC, 0xC0}, {0x22, 0xC0}};
    static const u8 fifos[] = {R_EP0, 0x14, 0x17, R_EPC_STATUS, 0x23};
    REG32(SYS_RESET) |= 0x10000000u;
    delay_ms(1);
    REG32(SYS_RESET) &= ~0x10000000u;
    delay_ms(1);
    USB[R_PHY_RESET] = 7;
    delay_ms(2);
    USB[R_PHY_RESET] = 0;
    if (chip_rev() == 0) {
        USB32(R_PHY0) &= 0xFFFF003Fu;
        USB32(R_PHY1) &= 0x07FFFFFFu;
        delay_ms(1);
        USB32(R_PHY0) |= 0x0000F500u;
        USB32(R_PHY1) &= 0xE6FFFFFFu;
        USB32(R_PHY1) |= 0x10000000u;
        USB32(R_PHY0) &= 0x9FFF1FFFu;
        USB32(R_PHY0) |= 0x60006000u;
        port_bit2_toggle();
    } else {
        USB32(R_PHY0) = 0x6800355Cu;
        USB32(R_PHY1) = 0x09000FF0u;
    }
    USB[R_AUTO] = (u8)(USB[R_AUTO] | 0x08);
    USB[R_MODE] = (u8)(USB[R_MODE] | 0x90);
    for (unsigned i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
        u8 r = types[i][0];
        USB[r] = (u8)((USB[r] & 0x3F) | types[i][1]);   /* set_ep_transfer_type */
        USB[r] = (u8)(USB[r] & 0xFC);                    /* set_fifo_type */
    }
    for (unsigned i = 0; i < sizeof(fifos); i++)
        fifo_reset(fifos[i]);
    (void)USB[R_FLAGS1];
    (void)USB[R_FLAGS2];
    (void)USB[R_FLAGS3];
    (void)USB[R_INTF_STATUS];
    flags1_seen = 0;
    flags2_seen = 0;
    USB[R_INT_EN1] = 0x0F;
    USB[R_INT_EN2] = 0xFF;
    USB[R_NAK_RETRY] = 1;
    USB[R_INTF_MASK] = 0;
    initialized = 1;
    in_pending = 0;                     /* (the FIFO resets ended it) */
    intf_seen = 0;
    owner[0] = owner[1] = 0;
    epd_device = epd_running = 0;       /* (the block's reset stopped endpoint D) */
    flags3_seen = 0;
    /* the PHY's reset drops the device for a moment */
    for (int i = 0; i < 500 && !usb_connected(); i++)
        delay_ms(1);
}

/* drive a bus reset (issue_reset_to_device: the port register written 0x20,
   which also clears bit 2); the flags register 1 bit 1 says the controller
   ended it (the flags clear when read, so what was read is kept): ms taken,
   -1 none */
static int bus_reset(u8 *flags_out)
{
    u8 flags = 0;
    (void)USB[R_FLAGS1];
    if (chip_rev() == 0) {
        USB[R_RESET_CFG] = (u8)(USB[R_RESET_CFG] | 0x60);
        port_bit2_toggle();
    }
    USB[R_PORT] = 0x20;
    u64 start = now_ms();
    while (now_ms() - start < 500) {
        flags |= USB[R_FLAGS1];
        if (flags & 0x02)
            break;
    }
    *flags_out = flags;
    if (!(flags & 0x02)) {
        USB[R_PORT] = 0;                /* end it */
        return -1;
    }
    return (int)(now_ms() - start);
}

/* ---- endpoint 0 ---- */
static void ep0_pid(u8 pid)              /* set_ep0_token_pid */
{
    USB[R_EP0] = (u8)((USB[R_EP0] & 0xFC) | pid);
}

/* ep_force_token_sending, then wait for endpoint 0's done or error flag:
   0 done, -1 error (last_error = the token error register), -2 time-out */
static int ep0_send(u32 timeout_ms)
{
    flags2();
    flags2_seen &= (u8)~0x88;
    USB[R_EP0] = (u8)(USB[R_EP0] | 0x20);
    u64 start = now_ms();
    for (;;) {
        u8 f = flags2();
        if (f & 0x08) {
            flags2_seen &= (u8)~0x88;
            last_error = USB[R_TOKEN_ERROR];
            return -1;
        }
        if (f & 0x80) {
            flags2_seen &= (u8)~0x88;
            return 0;
        }
        if (now_ms() - start >= timeout_ms) {
            last_error = 0;
            return -2;
        }
    }
}

/* one control transfer: the SETUP the way hcd_s3602_issue_setup sends it
   (the PID set to IN and back to SETUP, the FIFO reset, the 8 bytes), an IN
   data stage into `data` (len bytes at most), the status stage; the bytes
   received or -1 (last_stage, last_error say why) */
static int control_once(const u8 *setup, u8 *data, u16 len, u32 timeout_ms)
{
    last_stage = "SETUP";
    ep0_pid(2);
    ep0_pid(0);
    fifo_reset(R_EP0);
    for (int i = 0; i < 8; i++)
        USB[R_EP0_FIFO] = setup[i];
    if (ep0_send(timeout_ms))
        return -1;
    int got = 0;
    if (setup[0] & 0x80) {
        last_stage = "IN data";
        while (got < len) {
            fifo_reset(R_EP0);
            ep0_pid(2);
            if (ep0_send(timeout_ms))
                return -1;
            int n = 0;
            while (!(USB[R_EP0] & 0x80) && got < len) {
                data[got++] = USB[R_EP0_FIFO];
                n++;
            }
            if (n < ep0_max)
                break;                  /* a short packet ends the data */
        }
        last_stage = "status (OUT)";
        fifo_reset(R_EP0);
        ep0_pid(1);
    } else {
        last_stage = "status (IN)";
        fifo_reset(R_EP0);
        ep0_pid(2);
    }
    int r = ep0_send(timeout_ms);
    fifo_reset(R_EP0);
    return r ? -1 : got;
}

/* endpoint 0 aimed at a device: its address, how it is reached (straight, or
   through a hub's translator), its packet size */
static void aim(const struct device *d)
{
    USB[R_EP0_SPLIT] = d->info;
    USB[R_EP0_ADDRESS] = (u8)(((d->address & 0x0F) << 1) | d->split);
    ep0_max = d->ep0_max;
}

/* a transfer failed for good: its stage and token error kept for
   usb_error_text / usb_last_error (on the box a stick's bulk time-out was
   told with the stage name of the reset recovery's requests after it) */
static void note_failure(void)
{
    fail_stage = last_stage;
    fail_error = last_error;
}

/* a transfer asked of a device that is not there (or with sizes that make no sense): -1, as "no response" */
static int no_device(void)
{
    last_stage = 0;
    last_error = 0x20;
    note_failure();
    return -1;
}

/* a control transfer to a device (IN data, or none), tried three times
   unless the device stalls it: the bytes received, -1 (usb_error_text says
   why) */
static int request(const struct device *d, u8 rtype, u8 req, u16 value, u16 index, u8 *data, u16 len, u32 timeout_ms)
{
    u8 setup[8] = {rtype, req, (u8)value, (u8)(value >> 8), (u8)index, (u8)(index >> 8), (u8)len, (u8)(len >> 8)};
    aim(d);
    for (int attempt = 0; attempt < 3; attempt++) {
        int n = control_once(setup, data, len, timeout_ms);
        if (n >= 0)
            return n;
        if (last_error & 0x80)
            break;                      /* a stall is the device's answer */
        delay_ms(2);
    }
    note_failure();
    return -1;
}

static struct device *device_at(u8 address)
{
    if (address < 1 || address > DEVICES || !devices[address - 1].used || devices[address - 1].address != address)
        return 0;
    return &devices[address - 1];
}

/* the same for the device with that address: -1 also when there is none */
int usb_request(u8 device, u8 rtype, u8 req, u16 value, u16 index, u8 *data, u16 len, u32 timeout_ms)
{
    const struct device *d = device_at(device);
    if (!d)
        return no_device();
    return request(d, rtype, req, value, index, data, len, timeout_ms);
}

/* the last failure (note_failure): "bulk IN stage: time-out, ..." */
const char *usb_error_text(void)
{
    static char text[72];
    u8 e = fail_error;
    if (!fail_stage)
        return "there is no device with that address";
    const char *what = !e ? "time-out, neither done nor error"
                     : (e & 0x80) ? "stall" : (e & 0x20) ? "no response" : (e & 0x40) ? "PID error"
                     : (e & 0x02) ? "CRC error" : (e & 0x08) ? "data toggle error" : (e & 0x04) ? "UTMI error"
                     : (e & 0x10) ? "unexpected packet" : "error";
    usnprintf(text, sizeof(text), "%s stage: %s (token error 0x%02x)", fail_stage, what, e);
    return text;
}

/* ---- endpoints A and B: transfers to and from RAM by DMA ---- */
/* Endpoint A sends (OUT: the SDK's hcd_s3602_bulkout_start), endpoint B
   receives (IN: hcd_s3602_bulkin_start).  The keyboard's interrupt endpoint
   and a stick's bulk IN endpoint share endpoint B, every stick endpoint A.

   The controller keeps one data toggle per endpoint, each device endpoint
   its own.  So the demo keeps every device's (one IN and one OUT endpoint
   each), counts the packets of each transfer, and notes whom endpoints A
   and B served last; before they serve another device endpoint the
   controller's toggle goes back to DATA0 (bit 0 of the FIFO register
   pulsed) and, when the device's is DATA1, CLEAR_FEATURE(ENDPOINT_HALT)
   puts that back to DATA0 as well (a USB rule for every endpoint with a
   data toggle). */
static u8 size_code(u16 size)           /* usbd_maxpkt_bin2index: 8 << n */
{
    u8 n = 0;
    while (n < 7 && (8u << n) < size)
        n++;
    return n;
}


static u8 intf_status(void)
{
    intf_seen |= USB[R_INTF_STATUS];
    return intf_seen;
}

static void toggle_pulse(u8 reg)        /* set_ep_data_toggle (it waits 1 ms twice; 0.1 ms does too) */
{
    USB[reg] = (u8)(USB[reg] | 0x01);
    delay_us(100);
    USB[reg] = (u8)(USB[reg] & 0xFE);
    delay_us(100);
}

/* CLEAR_FEATURE(ENDPOINT_HALT) on a device's endpoint (bit 7: IN): it is no
   longer halted and its toggle is DATA0 */
int usb_clear_halt(u8 device, u8 ep)
{
    struct device *d = device_at(device);
    if (!d || request(d, 0x02, 0x01, 0, ep, 0, 0, 500) < 0)
        return -1;
    int out = !(ep & 0x80);
    if (out) {
        d->out_ep = (u8)((ep & 0x0F) | 0x10);
        d->out_toggle = 0;
    } else {
        d->in_ep = (u8)((ep & 0x0F) | 0x10);
        d->in_toggle = 0;
    }
    owner[!out] = 0;                    /* the controller's goes back to DATA0 before the next transfer */
    return 0;
}

/* endpoint A (out = 1) or B is about to serve the device's endpoint `ep`:
   both data toggles in step; -1 when the device does not answer */
static int toggle_sync(struct device *d, u8 ep, int out)
{
    u8 *dev_ep = out ? &d->out_ep : &d->in_ep, *toggle = out ? &d->out_toggle : &d->in_toggle;
    u8 tagged = (u8)((ep & 0x0F) | 0x10);   /* (0: no endpoint used since the configuration) */
    if (owner[!out] == d->address && owner_ep[!out] == tagged && *dev_ep == tagged)
        return 0;                       /* in step already */
    if (*dev_ep && (*dev_ep != tagged || *toggle)) {
        if (usb_clear_halt(d->address, out ? (ep & 0x0F) : (0x80 | ep)) < 0)
            return -1;
    }
    *dev_ep = tagged;
    *toggle = 0;
    toggle_pulse(out ? R_EPA_STATUS : R_EPB_STATUS);
    owner[!out] = d->address;
    owner_ep[!out] = tagged;
    return 0;
}

/* a transfer of `bytes` (`asked` were asked for) has moved this many packets:
   the toggles flip once per packet */
static void toggle_count(struct device *d, int out, u32 bytes, u32 asked, u16 maxp)
{
    u32 packets = bytes < asked ? bytes / maxp + 1 : (bytes + maxp - 1) / maxp;
    if (packets & 1) {
        if (out)
            d->out_toggle ^= 1;
        else
            d->in_toggle ^= 1;
    }
}

/* the IN's state lost (a failed transfer): the next one starts both again */
static void toggle_unknown(struct device *d, int out)
{
    if (out)
        d->out_ep = 0xFF;
    else
        d->in_ep = 0xFF;
    owner[!out] = 0;
}

/* endpoint B set up for an IN of `count` bytes in packets of `maxp` into the
   RAM at `phys`, and started (hcd_s3602_bulkin_start): the controller sends
   the token at once and, while the device answers NAK, again every
   millisecond */
static void epb_start(const struct device *d, u8 ep, u16 maxp, u32 phys, u32 count)
{
    u8 code = size_code(maxp);
    USB[R_EPB_SPLIT] = d->info;                                                /* set_ssplit_ctrl_info */
    USB[R_EPB_ADDRESS] = (u8)(((d->address & 0x0F) << 1) | d->split);          /* set_ep_device_address */
    USB[R_EPAB_SIZE] = (u8)((USB[R_EPAB_SIZE] & 0x8F) | (code << 4) | 0x80);   /* set_epb_packet_size */
    USB[R_EPB] = (u8)((USB[R_EPB] & 0x3F) | 0x80);                             /* set_ep_transfer_type: bulk */
    USB[R_EPB] = (u8)((USB[R_EPB] & 0xC3) | ((ep & 0x0F) << 2));               /* set_ep_logical_num */
    flags2();
    flags2_seen &= (u8)~0x22;
    intf_status();
    intf_seen &= (u8)~0x04;
    USB[R_INTF_MASK] = 0x10;                        /* enable_all_usb_intf_int, mask_usb_intf_int(0x10) */
    USB[R_DMA_AUTO] = 0;                            /* disable_dma_auto_option */
    USB32(R_DMA_RX_INDEX) = 0;                      /* clear_dma_rx_index */
    USB32(R_DMA_RX_BASE) = phys;                    /* set_dma_rx_base_addr */
    fifo_reset(R_EPB_STATUS);                       /* init_ep_fifo */
    USB[R_DMA_AUTO] = (u8)(0x80 | (code << 4));     /* enable_dma_auto_rx */
    dma_rx_count(count);
    USB[R_DMA_STATE] = (u8)(USB[R_DMA_STATE] | 0x20);       /* init_dma_rx_state */
    USB[R_DMA_STATE] = (u8)(USB[R_DMA_STATE] | 0x10);       /* start_dma_rx_transfer */
    USB[R_SPEED] = (u8)(USB[R_SPEED] | 0x04);       /* dma_host_in_token */
    USB[R_SPEED] = (u8)(USB[R_SPEED] | 0x08);       /* en_dma_transfer */
}

/* ends endpoint B's IN, done or not: the FIFO reset does (clearing the
   transfer's bits alone leaves the controller sending tokens) */
static void epb_end(void)
{
    USB[R_SPEED] = (u8)(USB[R_SPEED] & ~0x0C);
    USB[R_DMA_AUTO] = 0;
    fifo_reset(R_EPB_STATUS);
    flags2();
    flags2_seen &= (u8)~0x22;
}

/* endpoint B's IN: 1 done (the bytes received at *n: endpoint B's done flag
   and the DMA's -- the byte count is final only after the latter), -1 a
   token failed (last_error), 0 not yet */
static int epb_state(u32 *n)
{
    u8 f = flags2();
    if ((f & 0x20) && (intf_status() & 0x04)) {
        flags2_seen &= (u8)~0x22;
        intf_seen &= (u8)~0x04;
        *n = USB32(R_DMA_RX_DONE) & 0xFFFFFFu;
        return 1;
    }
    if (f & 0x02) {
        flags2_seen &= (u8)~0x22;
        last_error = USB[R_TOKEN_ERROR];
        return -1;
    }
    return 0;
}

/* the keyboard's IN (kbd.c): it stays pending on endpoint B, `size` bytes
   (one packet, USB_DMA_SIZE at most) into the RAM at USB_DMA_PHYS, until a
   report has come, a token has failed, usb_in_stop -- or another transfer
   needed endpoint B (usb_in_read then says so) */
static u8 in_device, in_ep_number;
static u16 in_size;

int usb_in_start(u8 device, u8 ep, u16 size)
{
    struct device *d = device_at(device);
    if (!d)
        return no_device();
    if (size > USB_DMA_SIZE)
        size = USB_DMA_SIZE;
    last_stage = "interrupt IN";
    if (toggle_sync(d, ep, 0) < 0)
        return -1;
    epb_start(d, ep, size, USB_DMA_PHYS, size);
    in_pending = 1;
    in_device = device;
    in_ep_number = ep;
    in_size = size;
    return 0;
}

/* an interrupt IN is under way on endpoint B (the mouse's, the keyboard's when endpoint D is not its) */
int usb_in_pending(void)
{
    return in_pending;
}

/* a report that had come when its IN was ended (for a disk's or a network port's transfer): kept for its
   slot (usb_int_poll), its toggle counted -- ended unread it was lost, and the device's toggle one ahead of
   ours lost the next report too (on the box: a keyboard's keys repeated) */
static u8 kept[USB_DMA_SIZE], kept_device, kept_ep;
static int kept_n;

void usb_in_stop(void)
{
    if (!in_pending)
        return;
    u32 n;
    if (epb_state(&n) > 0) {
        struct device *d = device_at(in_device);
        if (d)
            toggle_count(d, 0, n, in_size, in_size);
        const volatile u8 *buf = (const volatile u8 *)KSEG1(USB_DMA_PHYS);
        if (n > USB_DMA_SIZE)
            n = USB_DMA_SIZE;
        for (u32 i = 0; i < n; i++)
            kept[i] = buf[i];
        kept_n = n ? (int)n : -2;
        kept_device = in_device;
        kept_ep = in_ep_number;
    }
    epb_end();
    in_pending = 0;
}

/* the IN's outcome: a packet's bytes (the transfer is over: usb_in_start for
   the next), 0 nothing yet, -1 a token failed (usb_error_text says why; over
   too), -2 a packet without data, -3 there is no IN: another transfer took
   endpoint B, or usb_in_start could not reach the device */
int usb_in_read(u8 *data, int max)
{
    if (!in_pending)
        return -3;
    u32 n;
    int r = epb_state(&n);
    if (!r)
        return 0;
    struct device *d = device_at(in_device);
    if (r < 0) {
        last_stage = "interrupt IN";
        note_failure();
        usb_in_stop();
        if (d)
            toggle_unknown(d, 0);
        return -1;
    }
    in_pending = 0;
    if (d)
        toggle_count(d, 0, n, in_size, in_size);
    const volatile u8 *buf = (const volatile u8 *)KSEG1(USB_DMA_PHYS);
    if (n > USB_DMA_SIZE)
        n = USB_DMA_SIZE;
    if ((int)n > max)
        n = (u32)max;
    for (u32 i = 0; i < n; i++)
        data[i] = buf[i];
    return n ? (int)n : -2;
}

/* ---- interrupt endpoints read in turn ---- */
/* Interrupt endpoints that share endpoint B -- the keyboard's always, a
   mouse's only when endpoint D (below) polls another device -- one IN
   pending at a time: each slot's IN for INT_TURN_MS while the other waits
   (both devices report every 10 ms at most; a key held for less than a turn
   could be missed).  A device is switched to with its data toggle known
   (usb_in_start); when that is DATA1 it costs a CLEAR_FEATURE(ENDPOINT_HALT)
   -- so the keyboard's turn goes on while its toggle is DATA1, 300 ms at
   most: its reports come in pairs, a key down and up.  The mouse's does
   not: a mouse stopped at DATA1 would hold the keyboard off.  Behind a hub
   the turns lose reports: ending an IN (the FIFO reset) can drop a packet the
   hub's translator already acknowledged, and the toggles fall out of step --
   on the box a mouse and a keyboard in turns both stuttered; alone either was
   fine.  So a single user keeps endpoint B for as long as it likes. */
#define INT_SLOTS        2              /* 0: the keyboard (kbd.c), 1: the mouse (mouse.c) */
#define INT_TURN_MS      16
static const u16 turn_max_ms[INT_SLOTS] = {300, 16};

struct int_slot {
    u8 open, failed, device, ep;
    u8 every;                           /* ms from one IN's start to the next (the endpoint's interval) */
    u64 next_start;
    u16 size;
    int result;                         /* the outcome not taken yet: > 0 a report's bytes, -1, -2; 0 none */
    u8 data[USB_DMA_SIZE];
    u32 drops;                          /* packets the controller dropped for their data toggle */
    u32 turns;                          /* turns it was given */
};
static struct int_slot slots[INT_SLOTS];
static int turn = -1;                   /* the slot holding endpoint B */
static u64 turn_since;
static int drop_seen;                   /* the token error register showed a toggle error during the IN */

/* the slot's interrupt endpoint is read from now on: `size` bytes a report, an IN started every
   `interval` ms at most -- the largest power of two up to the endpoint's bInterval, 8 ms at most, as a USB
   2.0 host schedules it.  (Endpoint B asks again every millisecond while the device answers NAK; started
   again at once after each report it read a moving PixArt mouse 954 times a second: movements of a count
   or two that its pointer's acceleration never saw -- a slow, "laggy" pointer -- and 73 failed split
   transactions in 1929 reports) */
void usb_int_open(int slot, u8 device, u8 ep, u16 size, u8 interval)
{
    struct int_slot *s = &slots[slot];
    if (turn == slot) {
        usb_in_stop();
        turn = -1;
    }
    s->open = 1;
    s->failed = 0;
    s->device = device;
    s->ep = ep;
    s->size = size;
    s->result = 0;
    s->every = 1;
    while (s->every < 8 && s->every * 2 <= interval)
        s->every *= 2;
    s->next_start = 0;
}

void usb_int_close(int slot)
{
    if (turn == slot) {
        usb_in_stop();
        turn = -1;
    }
    slots[slot].open = 0;
    slots[slot].result = 0;
}

/* the slot's outcome since it was last asked: > 0 a report's bytes (into
   data), 0 nothing yet, -1 its IN failed (usb_error_text; the slot is closed:
   usb_int_open again), -2 a packet without data */
int usb_int_take(int slot, u8 *data, int max)
{
    struct int_slot *s = &slots[slot];
    int r = s->result;
    s->result = 0;
    for (int i = 0; i < r && i < max; i++)
        data[i] = s->data[i];
    if (r == -1)
        s->open = 0;
    return r > max ? max : r;
}

/* packets the controller dropped for the slot (a data toggle out of step) */
u32 usb_int_drops(int slot)
{
    return slots[slot].drops;
}

static int toggle_is_odd(int slot)
{
    const struct device *d = device_at(slots[slot].device);
    return d && d->in_toggle;
}

static int someone_waits(int slot)
{
    for (int i = 0; i < INT_SLOTS; i++)
        if (i != slot && slots[i].open && !slots[i].failed && !slots[i].result)
            return 1;
    return 0;
}

static void int_start(int slot)
{
    struct int_slot *s = &slots[slot];
    drop_seen = 0;
    s->next_start = now_ms() + s->every;
    if (usb_in_start(s->device, s->ep, s->size) < 0) {
        s->result = -1;                 /* (usb_error_text: its toggles' set-up got no answer) */
        s->failed = 1;
    }
}

/* every pass of the main loop, before kbd_poll / mouse_poll: the IN of the
   slot whose turn it is looked at, its outcome kept for the slot; the turn
   handed on when it is over */
void usb_int_poll(void)
{
    u64 now = now_ms();
    int keep = -1;
    if (kept_n) {                               /* (a report usb_in_stop kept: to its slot) */
        for (int i = 0; i < INT_SLOTS; i++) {
            struct int_slot *s = &slots[i];
            if (s->open && s->device == kept_device && s->ep == kept_ep && !s->result) {
                s->result = kept_n;
                for (int k = 0; k < kept_n; k++)
                    s->data[k] = kept[k];
            }
        }
        kept_n = 0;
    }
    if (turn >= 0) {
        struct int_slot *s = &slots[turn];
        if (in_pending) {
            u8 buf[USB_DMA_SIZE];
            if (USB[R_TOKEN_ERROR] & 0x08)
                drop_seen = 1;
            int n = usb_in_read(buf, sizeof(buf));
            if (n != 0 && n != -3) {
                s->result = n;
                for (int i = 0; i < n; i++)
                    s->data[i] = buf[i];
                if (n == -1)
                    s->failed = 1;
                else if (drop_seen)
                    s->drops++;
            }
        }
        if (s->open && !s->failed) {
            u64 held = now - turn_since;
            if (!someone_waits(turn) || held < INT_TURN_MS || (toggle_is_odd(turn) && held < turn_max_ms[turn]))
                keep = turn;
        }
        if (keep < 0)
            usb_in_stop();              /* its turn is over */
    }
    if (keep >= 0) {
        if (!in_pending && !slots[keep].result && now >= slots[keep].next_start)
            int_start(keep);            /* (after its report was taken, its interval after the last start) */
        return;
    }
    int from = turn < 0 ? 0 : turn + 1;
    turn = -1;
    for (int k = 0; k < INT_SLOTS; k++) {
        int i = (from + k) % INT_SLOTS;
        if (slots[i].open && !slots[i].failed && !slots[i].result) {
            turn = i;
            turn_since = now;
            slots[i].turns++;
            int_start(i);
            break;
        }
    }
}

/* ---- endpoint D: an interrupt endpoint the controller polls itself ---- */
/* Endpoint D (the SDK's hcd_s3602_IntInD_start and epD_finish_ok) sends an
   IN token to one device endpoint every 2^(+0xA3 - 1) microframes while
   +0x2B bit 3 is set, through a hub's translator too (+0x88 / +0x89 like
   endpoint B's pair; +0x89 bit 7 reads 1 while a split transaction is under
   way), and puts the packet into its own FIFO: +0x24, read byte by byte
   while +0x23 bit 7 says it is not empty.  Flags 3 (+0x2F, read to clear;
   +0x2E = 0x77 enables them) bit 4 says a packet came; bit 0 is the SDK's
   "failed", but on the box a failed token showed only in +0x1D and flags 1
   (bit 4 through a translator, 5 without) and the polling went on -- an
   unplugged device is noticed at its port.  The data toggle lasts from one
   packet to the next, through the polling's stops and starts; bit 0 of
   +0x23 pulsed puts it back to DATA0.
   No DMA, nothing shared with endpoints A and B: a stick's transfers and the
   keyboard's IN leave it alone, so the mouse is read here.  As the SDK does,
   the polling is stopped when a packet came, the FIFO emptied and the
   polling started again.  Measured on the box (revision 1): a hub's status
   endpoint answered every change, a low-speed keyboard behind a hub its key
   report; without the pulse, a CLEAR_FEATURE(ENDPOINT_HALT) on the device's
   endpoint cost the next packet (token error 0x08). */
#define R_EPD          0x22  /* endpoint D: b6-7 transfer type (0xC0 interrupt), b2-5 the device's endpoint */
#define R_EPD_STATUS   0x23  /* b4 FIFO reset, b0 pulsed: the data toggle back to DATA0; read: b7 FIFO empty */
#define R_EPD_FIFO     0x24
#define R_PERIODIC     0x2B  /* b3: endpoint D polls (b5: endpoint C) */
#define R_INT_EN3      0x2E  /* 0x77: flags 3 enabled (en_host_int_flag3_all) */
#define R_EPCD_SIZE    0x31  /* b4-6: endpoint D's packet size, 8 << n (b0-2: endpoint C's) */
#define R_EPD_ADDRESS  0x88  /* endpoint D's device address << 1 | split, as +0x84 */
#define R_EPD_SPLIT    0x89  /* its translator, as +0x85; read: b7 a split transaction under way */
#define R_EPD_INTERVAL 0xA3  /* 2^(n - 1) microframes between two tokens; 0 stops */

static u8 epd_ep, epd_code;
static u16 epd_size;
static u32 epd_reports, epd_drops;

static u8 flags3(void)
{
    flags3_seen |= USB[R_FLAGS3];
    return flags3_seen;
}

/* the device's bInterval as endpoint D's: a high-speed device gives the
   exponent itself; below high speed it is in frames (ms): the longest
   2^(n - 1) microframes that is not longer (10 ms: 8) */
static u8 epd_interval(u8 speed, u8 interval)
{
    if (speed == SPEED_HIGH)
        return interval < 1 ? 1 : interval > 16 ? 16 : interval;
    u8 n = 4;                           /* 8 microframes: 1 ms */
    while (n < 16 && (1u << n) <= 8u * interval)
        n++;
    return n;
}

static void epd_go(void)                /* hcd_s3602_IntInD_start */
{
    const struct device *d = device_at(epd_device);
    if (!d)
        return;
    USB[R_EPD_SPLIT] = d->info;                                                    /* set_ssplit_ctrl_info */
    USB[R_EPD_ADDRESS] = (u8)(((d->address & 0x0F) << 1) | d->split);              /* set_ep_device_address */
    USB[R_EPCD_SIZE] = (u8)((USB[R_EPCD_SIZE] & 0x8F) | (size_code(epd_size) << 4));   /* set_epd_packet_size */
    USB[R_EPD] = (u8)((USB[R_EPD] & 0x3F) | 0xC0);                                 /* set_ep_transfer_type */
    USB[R_EPD] = (u8)((USB[R_EPD] & 0xC3) | ((epd_ep & 0x0F) << 2));               /* set_ep_logical_num */
    flags3();
    flags3_seen &= (u8)~0x11;
    fifo_reset(R_EPD_STATUS);                                                      /* init_ep_fifo */
    USB[R_INT_EN3] = 0x77;                                                         /* en_host_int_flag3_all */
    USB[R_EPD_INTERVAL] = epd_code;                                                /* set_int_interval_value */
    USB[R_PERIODIC] = (u8)(USB[R_PERIODIC] | 0x08);                                /* en_int_interval_ctrl */
    epd_running = 1;
}

static void epd_halt(void)              /* epD_finish_ok's first two steps */
{
    USB[R_EPD_INTERVAL] = 0;
    USB[R_PERIODIC] = (u8)(USB[R_PERIODIC] & ~0x08);
    epd_running = 0;
}

/* endpoint D polls the device's interrupt IN endpoint `ep` (packets of
   `size`, the endpoint descriptor's interval) from now on, both data toggles
   DATA0 first: 0; -1 the device did not answer (usb_error_text); -2
   endpoint D polls another device */
int usb_epd_open(u8 device, u8 ep, u16 size, u8 interval)
{
    struct device *d = device_at(device);
    if (!d)
        return no_device();
    if (epd_device && epd_device != device)
        return -2;
    epd_halt();
    epd_device = 0;
    last_stage = "interrupt IN (endpoint D)";
    if (usb_clear_halt(device, (u8)(0x80 | ep)) < 0)
        return -1;
    d->in_ep = 0xFF;                    /* (endpoint D moves the device's toggle on: unknown to endpoint B) */
    toggle_pulse(R_EPD_STATUS);
    epd_device = device;
    epd_ep = ep & 0x0F;
    epd_size = size ? size : 8;
    if (epd_size > 64)
        epd_size = 64;
    epd_code = epd_interval(d->speed, interval);
    epd_go();
    return 0;
}

void usb_epd_close(void)
{
    if (!epd_device)
        return;
    epd_halt();
    struct device *d = device_at(epd_device);
    if (d)
        d->in_ep = 0xFF;
    epd_device = 0;
}

/* endpoint D's outcome: > 0 a packet's bytes (into data; the polling goes
   on), 0 nothing yet, -1 a token failed (usb_error_text; the polling has
   stopped: usb_epd_open again), -2 a packet without data */
int usb_epd_take(u8 *data, int max)
{
    if (!epd_device || !epd_running)
        return 0;
    u8 f = flags3();
    if (!(f & 0x11))
        return 0;
    flags3_seen &= (u8)~0x11;
    u8 e = USB[R_TOKEN_ERROR];
    if (e & 0x08)
        epd_drops++;                    /* (a packet before this one had the other toggle) */
    epd_halt();
    if (!(f & 0x10)) {
        last_stage = "interrupt IN (endpoint D)";
        last_error = e;
        note_failure();
        return -1;
    }
    u8 buf[64];
    int n = 0;
    while (!(USB[R_EPD_STATUS] & 0x80) && n < (int)sizeof(buf))
        buf[n++] = USB[R_EPD_FIFO];
    epd_go();
    epd_reports++;
    for (int i = 0; i < n && i < max; i++)
        data[i] = buf[i];
    if (!n)
        return -2;
    return n > max ? max : n;
}

/* the device endpoint D polls (0: none); how often (us), and what came:
   reports, packets dropped for their data toggle */
u8 usb_epd_device(void)
{
    return epd_device;
}

void usb_epd_counts(u32 *every_us, u32 *reports, u32 *drops)
{
    *every_us = epd_device ? (125u << (epd_code - 1)) : 0;
    *reports = epd_reports;
    *drops = epd_drops;
}

/* a bulk-only command is about to begin: both endpoints' toggles in step
   now -- a CLEAR_FEATURE(ENDPOINT_HALT) between its command block and its
   data ends the command on a real stick (it stalled the status; a card
   reader refused the request and timed out) */
int usb_bulk_sync(u8 device, u8 out_ep, u8 in_ep)
{
    struct device *d = device_at(device);
    if (!d)
        return no_device();
    usb_in_stop();                      /* (the keyboard's IN: kbd.c starts it again) */
    last_stage = "toggle set-up";
    if (toggle_sync(d, out_ep, 1) < 0 || toggle_sync(d, in_ep, 0) < 0)
        return -1;
    return 0;
}

/* endpoint B made ready for an IN from the device's endpoint `ep` and started, `count` bytes into the RAM
   at USB_BULK_PHYS: 0, -1 the data toggles could not be put in step */
static int bulk_in_begin(struct device *d, u8 ep, u16 maxp, u32 count)
{
    usb_in_stop();                      /* (the keyboard's IN, when it was pending: kbd.c starts it again) */
    if (toggle_sync(d, ep, 0) < 0)
        return -1;
    last_stage = "bulk IN";             /* (after toggle_sync: its CLEAR_FEATURE names its own stages) */
    epb_start(d, ep, maxp, USB_BULK_PHYS, count);
    return 0;
}

/* a bulk transfer from the device's IN endpoint `ep` (packets of `maxp`):
   up to `len` bytes (USB_BULK_SIZE at most) into `data`, received in the RAM
   at USB_BULK_PHYS; the bytes received, -1 (usb_error_text says why: a
   stall, the endpoint is halted; no response; a time-out) */
int usb_bulk_in(u8 device, u8 ep, u16 maxp, u8 *data, u32 len, u32 timeout_ms)
{
    struct device *d = device_at(device);
    if (!d || !maxp || len > USB_BULK_SIZE)
        return no_device();
    if (bulk_in_begin(d, ep, maxp, len) < 0)
        return -1;
    u64 start = now_ms();
    u32 n = 0;
    int r;
    while (!(r = epb_state(&n)) && now_ms() - start < timeout_ms)
        ;
    epb_end();
    if (r <= 0) {
        if (!r)
            last_error = 0;             /* the time-out */
        note_failure();
        toggle_unknown(d, 0);
        return -1;
    }
    if (n > len)
        n = len;
    toggle_count(d, 0, n, len, maxp);
    const volatile u8 *buf = (const volatile u8 *)KSEG1(USB_BULK_PHYS);
    for (u32 i = 0; i < n; i++)
        data[i] = buf[i];
    return (int)n;
}

/* one packet from the device's bulk IN endpoint `ep`, whatever its size -- a
   serial port's answer is often shorter than asked for, and for a short
   packet the controller raises endpoint B's done but never the DMA's: the
   bytes stay in endpoint B's FIFO (usb_bulk_in, which waits for both, times
   out).  As measured on the box with an LTE module's AT port: the DMA is
   asked for one byte, so the controller sends no IN token after the first
   packet (with more asked for it goes on, and the next packet lands on this
   one); the packet's size is then at +0x2C (as the SDK's epB_finish_ok reads
   it); the FIFO hands the DMA 16 bits at a time, so that one-byte run took
   the first two bytes, and a second run -- the DMA's count set to the rest
   and started again -- moves the rest to the buffer's start.  The bytes (up
   to maxp, 512 at most), 0 none within timeout_ms (the IN is ended, the
   data toggle kept), -1 failed (usb_error_text), -2 a zero-length packet --
   as usb_in_read */
static int bulk_in_packet_once(u8 device, u8 ep, u16 maxp, u8 *data, u32 timeout_ms)
{
    struct device *d = device_at(device);
    if (!d || !maxp || maxp > USB_BULK_SIZE)
        return no_device();
    if (bulk_in_begin(d, ep, maxp, 1) < 0)
        return -1;
    const volatile u8 *buf = (const volatile u8 *)KSEG1(USB_BULK_PHYS);
    u64 start = now_ms(), empty_at = 0;
    u32 moved;
    int n = 0, r;
    while (!(r = epb_state(&moved))) {
        if (flags2_seen & 0x20) {                       /* done, nothing for the DMA: a zero-length packet */
            if (!empty_at)
                empty_at = now_ticks();
            else if (now_ticks() - empty_at > ticks_per_ms() / 20) {
                n = -2;
                break;
            }
        }
        if (now_ms() - start >= timeout_ms)
            break;
    }
    if (r > 0) {                                        /* a packet, its first DMA run done */
        n = USB[R_EPB_LAST] | USB[R_EPB_LAST + 1] << 8;
        if (n > maxp)
            n = maxp;
        if (n > 0)
            data[0] = buf[0];                           /* (the first run took two bytes) */
        if (n > 1)
            data[1] = buf[1];
        if (n > 2) {                                    /* the rest from the FIFO, to the buffer's start */
            dma_rx_count((u32)(n - 2));
            intf_status();
            intf_seen &= (u8)~0x04;
            USB[R_DMA_STATE] = (u8)(USB[R_DMA_STATE] | 0x20);   /* init_dma_rx_state */
            USB[R_DMA_STATE] = (u8)(USB[R_DMA_STATE] | 0x10);   /* start_dma_rx_transfer */
            USB[R_SPEED] = (u8)(USB[R_SPEED] | 0x08);           /* en_dma_transfer */
            u64 t = now_ms();
            while (!(intf_status() & 0x04) && now_ms() - t < 5)
                ;
            if (intf_status() & 0x04) {
                for (int i = 2; i < n; i++)
                    data[i] = buf[i - 2];
            } else {
                last_stage = "bulk IN (the packet's rest)";
                last_error = 0;
                r = -1;
            }
        }
        if (!n)
            n = -2;                                     /* (a zero-length packet that took the DMA's done) */
    }
    epb_end();
    intf_seen &= (u8)~0x04;
    if (r < 0) {
        toggle_unknown(d, 0);
        note_failure();
        return -1;
    }
    if (n)
        toggle_count(d, 0, n > 0 ? (u32)n : 0, maxp, maxp);     /* (one packet) */
    return n;
}

/* (a token spoilt on the bus -- not a stall, not "no response": a UTMI, CRC or PID error, as the box got one
   while an LTE module sent over GSM -- is tried again, twice: an IN that failed was not acknowledged, the
   device still has its packet) */
int usb_bulk_in_packet(u8 device, u8 ep, u16 maxp, u8 *data, u32 timeout_ms)
{
    int n = bulk_in_packet_once(device, ep, maxp, data, timeout_ms);
    for (int tries = 0; n == -1 && tries < 2 && fail_error && !(fail_error & 0xA0); tries++)
        n = bulk_in_packet_once(device, ep, maxp, data, timeout_ms);
    return n;
}

/* a bulk transfer to the device's OUT endpoint `ep` through endpoint A
   (hcd_s3602_bulkout_start): `len` bytes (USB_BULK_SIZE at most) from
   `data`, sent from the RAM at USB_BULK_PHYS; 0 sent, -1 (usb_error_text).
   It is over at the DMA transmit's done (+0x63 bit 1, as the SDK's
   hcd_s3602_dma_tx_done): endpoint A's done (flags 2 bit 6) comes after
   every packet -- on the box a 4 KB WRITE(10) to a card reader raised it
   eight times, the DMA transmit's done only after the eighth; ended at the
   first, the card reader waited for the rest and answered nothing more */
int usb_bulk_out(u8 device, u8 ep, u16 maxp, const u8 *data, u32 len, u32 timeout_ms)
{
    struct device *d = device_at(device);
    if (!d || !maxp || !len || len > USB_BULK_SIZE)
        return no_device();
    usb_in_stop();                      /* one DMA engine: the keyboard's IN waits (kbd.c starts it again) */
    if (toggle_sync(d, ep, 1) < 0)
        return -1;
    last_stage = "bulk OUT";            /* (after toggle_sync: its CLEAR_FEATURE names its own stages) */
    volatile u8 *buf = (volatile u8 *)KSEG1(USB_BULK_PHYS);
    for (u32 i = 0; i < len; i++)
        buf[i] = data[i];
    u8 code = size_code(maxp);
    USB[R_EPA_SPLIT] = d->info;                                                /* set_ssplit_ctrl_info */
    USB[R_EPA_ADDRESS] = (u8)(((d->address & 0x0F) << 1) | d->split);          /* set_ep_device_address */
    USB[R_EPAB_SIZE] = (u8)((USB[R_EPAB_SIZE] & 0xF8) | code | 0x08);          /* set_epa_packet_size */
    USB[R_EPA] = (u8)((USB[R_EPA] & 0x3F) | 0x80);                             /* set_ep_transfer_type: bulk */
    USB[R_EPA] = (u8)((USB[R_EPA] & 0xC3) | ((ep & 0x0F) << 2));               /* set_ep_logical_num */
    flags2();
    flags2_seen &= (u8)~0x44;
    intf_status();
    intf_seen &= (u8)~0x02;
    USB[R_INTF_MASK] = 0x10;                        /* enable_all_usb_intf_int, mask_usb_intf_int(0x10) */
    dma_rx_count(0);
    USB[R_DMA_AUTO] = (u8)(code | 0x08);            /* enable_dma_auto_tx */
    fifo_reset(R_EPA_STATUS);                       /* init_ep_fifo */
    USB32(R_DMA_TX_BASE) = USB_BULK_PHYS;           /* set_dma_tx_base_addr */
    USB32(R_DMA_TX_INDEX) = 0;                      /* clear_dma_tx_index */
    USB32(R_DMA_TX_COUNT) = len;                    /* set_dma_tx_transfer_byte */
    USB[R_DMA_STATE] = (u8)(USB[R_DMA_STATE] | 0x01);       /* start_dma_tx_transfer */
    USB[R_SPEED] = (u8)(USB[R_SPEED] | 0x08);       /* en_dma_transfer */
    u64 start = now_ms();
    int r = 0;
    while (!r && now_ms() - start < timeout_ms) {
        u8 f = flags2();
        if (f & 0x04) {                             /* endpoint A failed */
            last_error = USB[R_TOKEN_ERROR];
            r = -1;
        } else if (intf_status() & 0x02) {
            r = 1;                                  /* the DMA transmit done: every packet sent */
        }
    }
    flags2_seen &= (u8)~0x44;
    intf_seen &= (u8)~0x02;
    USB[R_DMA_STATE] = (u8)(USB[R_DMA_STATE] | 0x02);       /* init_dma_tx_state (hcd_s3602_dma_tx_done) */
    USB[R_SPEED] = (u8)(USB[R_SPEED] & ~0x08);      /* en_dma_transfer(0) */
    USB[R_DMA_AUTO] = 0;
    if (r <= 0) {
        if (!r)
            last_error = 0;
        note_failure();
        fifo_reset(R_EPA_STATUS);                   /* (epa_error_handler) */
        toggle_unknown(d, 1);
        return -1;
    }
    toggle_count(d, 1, len, len, maxp);
    return 0;
}

/* ---- enumeration ---- */
static u8 address_of(const struct device *d)    /* its place's number: the address it gets */
{
    return (u8)(d - devices + 1);
}

static struct device *new_device(u8 hub, u8 port, u8 speed)
{
    for (int i = 0; i < DEVICES; i++)
        if (!devices[i].used) {
            struct device *d = &devices[i];
            for (unsigned k = 0; k < sizeof(*d); k++)
                ((u8 *)d)[k] = 0;
            d->used = 1;
            d->hub = hub;
            d->port = port;
            d->speed = speed;
            d->ep0_max = 8;
            /* a device that is not high speed is reached through the translator of
               the nearest high-speed hub above it: that hub's address, the port
               leading to the device, bit 6 for a low-speed device */
            const struct device *h = device_at(hub);
            if (h && speed != SPEED_HIGH) {
                if (h->speed == SPEED_HIGH) {
                    d->split = 1;
                    d->info = (u8)(((port & 7) << 3) | (h->address & 7));
                } else {
                    d->split = h->split;
                    d->info = (u8)(h->info & 0x3F);
                }
                if (d->split && speed == SPEED_LOW)
                    d->info |= 0x40;
            }
            return d;
        }
    return 0;
}

static struct device *device_on(u8 hub, u8 port)
{
    for (int i = 0; i < DEVICES; i++)
        if (devices[i].used && devices[i].hub == hub && devices[i].port == port)
            return &devices[i];
    return 0;
}

static int port_connect(struct device *h, u8 port);
static void forget(struct device *d);

/* a device that lost its set-up (an LTE module that restarted) set up again: behind a hub that port alone --
   forgotten, reset and set up as when it was plugged in, the other devices untouched -- on the controller's
   port the whole bus, quietly.  0 set up again, -1 not */
int usb_set_up_again(u8 device)
{
    struct device *d = device_at(device);
    if (!d)
        return -1;
    if (!d->hub)
        return usb_enumerate_quiet();
    struct device *h = device_at(d->hub);
    u8 port = d->port;
    forget(d);
    if (!h)
        return -1;
    int was = quiet;
    quiet = 1;
    int r = port_connect(h, port);
    quiet = was;
    return r;
}

/* a device that is gone, with everything that was plugged into it */
static void forget(struct device *d)
{
    u8 a = address_of(d);
    if (d->address)
        for (int i = 0; i < DEVICES; i++)
            if (devices[i].used && devices[i].hub == a && &devices[i] != d)
                forget(&devices[i]);
    if (kbd_device() == a)
        kbd_stop();
    if (mouse_device() == a)
        mouse_stop();
    if (epd_device == a)
        usb_epd_close();
    if (d->msc_in)
        disk_detach(a);
    serial_detach(a);
    eth_detach(a);
    for (int i = 0; i < 2; i++)
        if (owner[i] == a)
            owner[i] = 0;               /* (the address may come back with another device) */
    d->used = 0;
}

static void forget_all(void)
{
    kbd_stop();
    mouse_stop();
    usb_epd_close();
    serial_detach(0);
    eth_detach(0);
    for (int i = 0; i < DEVICES; i++) {
        if (devices[i].used && devices[i].msc_in)
            disk_detach((u8)(i + 1));
        devices[i].used = 0;
    }
    owner[0] = owner[1] = 0;
}

/* the first keyboard on the bus starts typing when none does (after the one
   in use was unplugged); its line, or 0 */
static const char *start_a_keyboard(void)
{
    if (kbd_active())
        return 0;
    for (int i = 0; i < DEVICES; i++) {
        const struct device *d = &devices[i];
        if (d->used && d->address && d->kbd_ep)
            return kbd_start(d->address, d->kbd_if, d->kbd_ep, d->kbd_size, d->kbd_interval);
    }
    return 0;
}

/* the first mouse on the bus is used when none is (after the one in use was
   unplugged); its line, or 0 */
static const char *start_a_mouse(void)
{
    if (mouse_active())
        return 0;
    for (int i = 0; i < DEVICES; i++) {
        const struct device *d = &devices[i];
        if (d->used && d->address && d->mouse_ep)
            return mouse_start(d->address, d->mouse_if, d->mouse_ep, d->mouse_size, d->mouse_interval);
    }
    return 0;
}

/* a string descriptor as ASCII into `text` ("" when the device has none) */
static void print_string(const struct device *d, const char *label, u8 index, char *text, int size)
{
    u8 buf[64];
    text[0] = 0;
    if (!index)
        return;
    int n = request(d, 0x80, 0x06, (u16)(0x0300 | index), 0x0409, buf, sizeof(buf), 500);
    if (n < 2)
        return;
    int k = 0;
    for (int i = 2; i + 1 < n && i < buf[0] && k < size - 1; i += 2)
        text[k++] = (buf[i] >= 32 && buf[i] < 127 && !buf[i + 1]) ? (char)buf[i] : '?';
    text[k] = 0;
    if (label)
        SAY("  %s: %s\n", label, text);
}

/* configuration `index`'s descriptor into cfg (size bytes at most): its length, < 9 not read */
static int read_config(const struct device *d, u8 index, u8 *cfg, int size)
{
    if (request(d, 0x80, 0x06, (u16)(0x0200 | index), 0, cfg, 9, 500) != 9)
        return -1;
    u16 total = (u16)(cfg[2] | cfg[3] << 8);
    return request(d, 0x80, 0x06, (u16)(0x0200 | index), 0, cfg, total < size ? total : (u16)size, 500);
}

/* a CDC Ethernet (ECM) communications interface in a configuration's descriptor */
static int has_ecm(const u8 *cfg, int n)
{
    for (int i = 0; i + 8 < n && cfg[i]; i += cfg[i])
        if (cfg[i + 1] == 0x04 && cfg[i + 5] == 0x02 && cfg[i + 6] == 0x06)
            return 1;
    return 0;
}

/* SET_INTERFACE: an interface's alternate setting; its endpoints' toggles start at DATA0.  0, -1 */
int usb_set_interface(u8 device, u8 iface, u8 alt)
{
    struct device *d = device_at(device);
    if (!d)
        return no_device();
    if (request(d, 0x01, 0x0B, alt, iface, 0, 0, 500) < 0)
        return -1;
    d->in_ep = d->out_ep = 0;           /* (none used since: DATA0) */
    return 0;
}

/* a bulk endpoint's descriptor into an interface's pair: its number as the IN or the OUT one, its packets */
static void bulk_ep(const u8 *ep, u16 size, u8 *in, u8 *out, u16 *maxp)
{
    if (ep[2] & 0x80)
        *in = ep[2] & 0x0F;
    else
        *out = ep[2] & 0x0F;
    *maxp = size;
}

static const char *class_name(u8 c)
{
    switch (c) {
    case 0x01: return "audio";
    case 0x02: return "communications";
    case 0x03: return "HID";
    case 0x07: return "printer";
    case 0x08: return "mass storage";
    case 0x09: return "hub";
    case 0x0E: return "video";
    case 0xE0: return "wireless";
    case 0xFF: return "vendor specific";
    }
    return "other";
}

/* the makers of GSM / LTE modules: their vendor-class interfaces are serial ports (AT, modem, diagnostics,
   GPS).  Other vendor-class interfaces -- a Wi-Fi stick's, a camera's -- are not, and neither is subclass
   0x42, a phone's debug interface */
static int modem_vendor(u16 vid)
{
    static const u16 vids[] = {
        0x1E0E,                         /* SIMCom (the A7670E: 1e0e:9011) */
        0x2C7C,                         /* Quectel */
        0x05C6,                         /* Qualcomm */
        0x12D1,                         /* Huawei */
        0x19D2,                         /* ZTE */
        0x1BC7,                         /* Telit */
        0x1199,                         /* Sierra Wireless */
        0x2CB7,                         /* Fibocom */
    };
    for (unsigned i = 0; i < sizeof(vids) / sizeof(vids[0]); i++)
        if (vids[i] == vid)
            return 1;
    return 0;
}

/* ---- hubs ---- */
#define PORT_ENABLE        1            /* the hub class's port features */
#define PORT_RESET         4
#define PORT_POWER         8
#define C_PORT_CONNECTION  16
#define C_PORT_ENABLE      17
#define C_PORT_OVER_CURRENT 19
#define C_PORT_RESET       20

static int set_up_device(struct device *d, const u8 *first);

/* GET_STATUS of a hub's port: its status (bit 0 a device is connected, 1 the
   port is enabled, 8 powered, 9 a low-speed device, 10 a high-speed one) and
   what changed (bit 0 the connection, 1 enabled, 3 over-current, 4 a reset
   ended); -1 when the hub does not answer */
static int port_status(const struct device *h, u8 port, u16 *status, u16 *change)
{
    u8 b[4];
    if (request(h, 0xA3, 0x00, 0, port, b, 4, 500) != 4)
        return -1;
    *status = (u16)(b[0] | b[1] << 8);
    *change = (u16)(b[2] | b[3] << 8);
    return 0;
}

static void port_feature(const struct device *h, u8 port, int set, u8 feature)
{
    request(h, 0x23, set ? 0x03 : 0x01, feature, port, 0, 0, 500);
}

/* a device on a hub's port: the port's reset (the hub ends it and tells the
   device's speed), then the device set up at the next free address; -1 when
   it does not answer (its port is switched off again: it would answer at
   address 0 together with the next one) */
static int port_connect(struct device *h, u8 port)
{
    u16 status = 0, change = 0;
    u8 first[8];
    port_feature(h, port, 1, PORT_RESET);
    for (int i = 0; i < 50; i++) {
        delay_ms(10);
        if (port_status(h, port, &status, &change) == 0 && (change & 0x10))
            break;
    }
    port_feature(h, port, 0, C_PORT_RESET);
    port_feature(h, port, 0, C_PORT_CONNECTION);
    if (port_status(h, port, &status, &change) || !(status & 0x0002)) {
        SAY("hub %u port %u: the port did not come out of its reset (status 0x%04x)\n", h->address, port, status);
        h->ignore |= (u8)(1u << port);
        return -1;
    }
    struct device *d = new_device(h->address, port, (status & 0x0200) ? SPEED_LOW : (status & 0x0400) ? SPEED_HIGH
                                                                                                    : SPEED_FULL);
    if (!d) {
        SAY("hub %u port %u: a device, but the demo keeps %u at most\n", h->address, port, DEVICES);
        port_feature(h, port, 0, PORT_ENABLE);
        h->ignore |= (u8)(1u << port);
        return -1;
    }
    delay_ms(20);                                       /* reset recovery */
    SAY("hub %u port %u:\n", h->address, port);
    if (request(d, 0x80, 0x06, 0x0100, 0, first, 8, 500) != 8) {
        SAY("  a device (%s) that does not answer: %s\n", speed_name(d->speed), usb_error_text());
        port_feature(h, port, 0, PORT_ENABLE);
        h->ignore |= (u8)(1u << port);
        d->used = 0;
        return -1;
    }
    if (first[4] == 0x09 && address_of(d) > HUB_MAX) {
        SAY("  a hub, but the first %u addresses are taken: a hub needs one of them (the split registers hold "
            "three bits of it)\n", HUB_MAX);
        port_feature(h, port, 0, PORT_ENABLE);
        h->ignore |= (u8)(1u << port);
        d->used = 0;
        return -1;
    }
    if (set_up_device(d, first) < 0) {
        port_feature(h, port, 0, PORT_ENABLE);
        h->ignore |= (u8)(1u << port);
        forget(d);
        return -1;
    }
    return 0;
}

/* a hub, configured: its descriptor, its ports powered, then every port with
   a device on it */
static void hub_start(struct device *h)
{
    u8 b[16];
    if (request(h, 0xA0, 0x06, 0x2900, 0, b, sizeof(b), 500) < 7) {
        SAY("  hub descriptor: %s\n", usb_error_text());
        return;
    }
    h->ports = b[2] > HUB_PORTS ? HUB_PORTS : b[2];
    SAY("  hub: %u ports%s\n", b[2], b[2] > HUB_PORTS ? " (the first 7 are used)" : "");
    for (u8 p = 1; p <= h->ports; p++)
        port_feature(h, p, 1, PORT_POWER);
    delay_ms(2u * b[5] + 100);                          /* bPwrOn2PwrGood (2 ms units), then the devices attach */
    for (u8 p = 1; p <= h->ports; p++) {
        u16 status, change;
        if (port_status(h, p, &status, &change))
            continue;
        if (change & 1)
            port_feature(h, p, 0, C_PORT_CONNECTION);
        if (status & 1)
            port_connect(h, p);
    }
}

/* ---- a device ---- */
/* the device that answers at address 0 (after its bus or port reset; `first`:
   the first 8 bytes of its device descriptor): its address, its descriptors
   listed, its configuration set; a hub's ports, a keyboard started.  -1 when
   it stops answering before it has its address and descriptor */
static int set_up_device(struct device *d, const u8 *first)
{
    u8 dev[18], cfg[256];
    u8 a = address_of(d);
    d->ep0_max = first[7] ? first[7] : 8;
    if (request(d, 0x00, 0x05, a, 0, 0, 0, 500) < 0) {             /* SET_ADDRESS */
        SAY("SET_ADDRESS failed: %s\n", usb_error_text());
        return -1;
    }
    delay_ms(10);
    d->address = a;
    if (request(d, 0x80, 0x06, 0x0100, 0, dev, 18, 500) < 18) {
        SAY("GET_DESCRIPTOR (device) failed: %s\n", usb_error_text());
        return -1;
    }
    d->vid = (u16)(dev[8] | dev[9] << 8);
    d->pid = (u16)(dev[10] | dev[11] << 8);
    SAY("USB device %04x:%04x, USB %x.%02x, endpoint 0: %u bytes, %s\n", d->vid, d->pid, dev[3], dev[2], dev[7],
        speed_name(d->speed));
    if (d->split)
        SAY("  address %u, reached through hub %u's transaction translator (its port %u)\n", a, d->info & 7,
            (d->info >> 3) & 7);
    else if (d->hub)
        SAY("  address %u\n", a);
    char serial[32];
    print_string(d, "manufacturer", dev[14], d->mfr, sizeof(d->mfr));
    print_string(d, "product", dev[15], d->product, sizeof(d->product));
    print_string(d, "serial", dev[16], serial, sizeof(serial));
    int is_hub = dev[4] == 0x09, kbd_if = -1, in_kbd = 0, in_msc = 0, in_mouse = 0;
    /* serial ports: a GSM / LTE module's vendor-class interfaces with a bulk IN and OUT (its AT, modem,
       diagnostic and GPS ports, as Linux's option driver takes them), or a CDC ACM data interface (class 0x0A
       after a class 2 / subclass 2 one; not RNDIS's, protocol 0xFF) */
    struct serial_ep {
        u8 iface, control, acm, in, out, name;      /* control: the interface with the modem control */
        u16 maxp;
    } ser[8], *cur = 0;
    int nser = 0, acm_control = -1, modem = modem_vendor(d->vid);   /* acm_control: the interface before */
    /* CDC Ethernet (ECM): its communications interface (02/06, an interrupt endpoint, the Ethernet
       descriptor's MAC string), its data interface's setting with a bulk IN and OUT */
    int ecm_ctrl = -1, in_ecm_ctrl = 0, in_ecm_data = 0;
    u8 ecm_data = 0, ecm_alt = 0, ecm_in = 0, ecm_out = 0, ecm_int = 0, ecm_mac = 0;
    u16 ecm_maxp = 0;
    int n = read_config(d, 0, cfg, sizeof(cfg));
    if (n < 9) {
        SAY("GET_DESCRIPTOR (configuration) failed: %s\n", usb_error_text());
        return 0;
    }
    /* a device with a CDC Ethernet configuration besides its first, which has none, is set up in that one
       -- an RTL8153's second; its first is Realtek's own */
    for (u8 k = 1; k < dev[17] && k < 4 && !has_ecm(cfg, n); k++) {
        int m = read_config(d, k, cfg, sizeof(cfg));
        if (m >= 9 && has_ecm(cfg, m)) {
            n = m;
            SAY("  configuration %u has CDC Ethernet (ECM): that one\n", cfg[5]);
        } else {
            n = read_config(d, 0, cfg, sizeof(cfg));
        }
    }
    for (int i = 0; i + 1 < n && cfg[i]; i += cfg[i]) {
        if (cfg[i + 1] == 0x04 && i + 8 < n) {
            in_ecm_ctrl = cfg[i + 5] == 0x02 && cfg[i + 6] == 0x06;
            if (in_ecm_ctrl)
                ecm_ctrl = cfg[i + 2];
            in_ecm_data = ecm_ctrl >= 0 && cfg[i + 5] == 0x0A && cfg[i + 4] >= 2 && !ecm_in;
            if (in_ecm_data) {
                ecm_data = cfg[i + 2];
                ecm_alt = cfg[i + 3];
            }
            SAY("  interface %u: class %02x (%s), subclass %02x, protocol %02x, %u endpoints\n",
                cfg[i + 2], cfg[i + 5], class_name(cfg[i + 5]), cfg[i + 6], cfg[i + 7], cfg[i + 4]);
            if (cfg[i + 5] == 0x09)
                is_hub = 1;
            in_kbd = kbd_if < 0 && cfg[i + 5] == 0x03 && cfg[i + 7] == 0x01;     /* HID, keyboard */
            if (in_kbd)
                kbd_if = cfg[i + 2];
            in_mouse = !d->mouse_ep && cfg[i + 5] == 0x03 && cfg[i + 6] == 0x01 && cfg[i + 7] == 0x02;  /* boot mouse */
            if (in_mouse)
                d->mouse_if = cfg[i + 2];
            /* mass storage, SCSI commands, bulk-only transport */
            in_msc = !d->msc_in && cfg[i + 5] == 0x08 && cfg[i + 6] == 0x06 && cfg[i + 7] == 0x50;
            if (in_msc)
                d->msc_if = cfg[i + 2];
            cur = 0;
            if (((cfg[i + 5] == 0xFF && modem && cfg[i + 6] != 0x42) || (cfg[i + 5] == 0x0A && acm_control >= 0))
                && !cfg[i + 3] && nser < 8) {
                cur = &ser[nser++];
                *cur = (struct serial_ep){.iface = cfg[i + 2], .acm = cfg[i + 5] == 0x0A, .name = cfg[i + 8]};
                cur->control = cur->acm ? (u8)acm_control : cur->iface;
            }
            acm_control = cfg[i + 5] == 0x02 && cfg[i + 6] == 0x02 && cfg[i + 7] != 0xFF ? cfg[i + 2] : -1;
        } else if (cfg[i + 1] == 0x05 && i + 6 < n) {
            u16 size = (u16)((cfg[i + 4] | cfg[i + 5] << 8) & 0x7FF);
            SAY("    endpoint %02x %s, %u bytes%s", cfg[i + 2],
                (cfg[i + 3] & 3) == 2 ? "bulk" : (cfg[i + 3] & 3) == 3 ? "interrupt" : "isochronous", size,
                (cfg[i + 3] & 3) == 3 ? "" : "\n");
            if ((cfg[i + 3] & 3) == 3)                  /* bInterval: frames (ms) below high speed */
                SAY(d->speed != SPEED_HIGH ? ", every %u ms\n" : ", interval %u\n", cfg[i + 6]);
            if (in_msc && (cfg[i + 3] & 3) == 2)          /* its bulk endpoints */
                bulk_ep(cfg + i, size, &d->msc_in, &d->msc_out, &d->msc_max);
            if (in_mouse && !d->mouse_ep && (cfg[i + 2] & 0x80) && (cfg[i + 3] & 3) == 3) {
                d->mouse_ep = cfg[i + 2];
                d->mouse_size = size;
                d->mouse_interval = cfg[i + 6];
            }
            if (in_kbd && !d->kbd_ep && (cfg[i + 2] & 0x80) && (cfg[i + 3] & 3) == 3) {
                d->kbd_ep = cfg[i + 2];
                d->kbd_if = (u8)kbd_if;
                d->kbd_size = size;
                d->kbd_interval = cfg[i + 6];
            }
            if (cur && (cfg[i + 3] & 3) == 2)
                bulk_ep(cfg + i, size, &cur->in, &cur->out, &cur->maxp);
            if (in_ecm_data && (cfg[i + 3] & 3) == 2)
                bulk_ep(cfg + i, size, &ecm_in, &ecm_out, &ecm_maxp);
            if (in_ecm_ctrl && (cfg[i + 3] & 3) == 3 && (cfg[i + 2] & 0x80))
                ecm_int = cfg[i + 2] & 0x0F;
        } else if (cfg[i + 1] == 0x24 && i + 3 < n && in_ecm_ctrl && cfg[i + 2] == 0x0F) {
            ecm_mac = cfg[i + 3];                       /* (the Ethernet descriptor: its MAC address string) */
        }
    }
    if (request(d, 0x00, 0x09, cfg[5], 0, 0, 0, 500) == 0)        /* SET_CONFIGURATION */
        SAY("  configuration %u set\n", cfg[5]);
    else
        SAY("  SET_CONFIGURATION failed: %s\n", usb_error_text());
    char names[8][32];                  /* (the ports' interface names: each string read once) */
    for (int k = 0; k < nser && !is_hub; k++) {
        const struct serial_ep *s = &ser[k];
        int j = 0;
        while (j < k && ser[j].name != s->name)
            j++;
        if (j < k)
            usnprintf(names[k], sizeof(names[k]), "%s", names[j]);
        else
            print_string(d, 0, s->name, names[k], sizeof(names[k]));
        if (s->in && s->out)
            SAY("  %s\n", serial_attach(a, s->iface, s->control, s->acm, s->in, s->out, s->maxp, names[k]));
    }
    if (ecm_in && ecm_out && !is_hub)
        SAY("  %s\n", eth_attach(a, (u8)ecm_ctrl, ecm_data, ecm_alt, ecm_in, ecm_out, ecm_maxp, ecm_int, ecm_mac));
    if (d->msc_in && !d->msc_out)
        d->msc_in = 0;                  /* (bulk-only needs both) */
    if (is_hub && a > HUB_MAX) {
        SAY("  a hub at address %u: a hub needs one of the first %u (the split registers hold three bits of "
            "it); its ports are left off\n", a, HUB_MAX);
    } else if (is_hub) {
        hub_start(d);
    } else if (d->msc_in) {
        SAY("  %s\n", disk_attach(a, d->msc_if, d->msc_in, d->msc_out, d->msc_max));
    } else {
        if (d->kbd_ep) {
            const char *text = start_a_keyboard();
            SAY("  %s\n", text ? text : "a second keyboard: the first one stays in use");
        }
        if (d->mouse_ep) {
            const char *text = start_a_mouse();
            SAY("  %s\n", text ? text : "a second mouse: the first one stays in use");
        }
    }
    return 0;
}

/* the device on the controller's port, and through a hub every device behind
   it: the bus reset, addresses, descriptors, configurations; 0 when the
   device on the port answered */
int usb_enumerate(void)
{
    u8 first[8];
    forget_all();
    if (!initialized)
        hc_init();
    if (!usb_connected()) {
        SAY("no USB device on the port\n");
        return -1;
    }
    struct device *d = 0;
    int ok = 0;
    for (int round = 0; round < 2 && !ok; round++) {
        if (round) {
            /* three bus resets and still no answer: the controller is set up
               again, its PHY's reset included (a real box's port was found
               stuck like this -- connected, but no token done or failed --
               and only that brought it back) */
            SAY("the device does not answer: setting the controller up again\n");
            hc_init();
            if (!usb_connected())
                break;
        }
        for (int attempt = 1; attempt <= 3 && !ok; attempt++) {
            u8 flags;
            if (bus_reset(&flags) < 0) {
                SAY("bus reset: no completion flag (flags 0x%02x)\n", flags);
                continue;
            }
            delay_ms(100);                              /* reset recovery (10 ms at least) */
            USB[R_EP0] = 0x10;                          /* init_ep0_fifo */
            delay_ms(1);
            USB[R_EP0] = (u8)(USB[R_EP0] | 0x04);
            USB[R_NEW_MODE] = 0x80;
            forget_all();
            d = new_device(0, 0, root_speed());
            if (request(d, 0x80, 0x06, 0x0100, 0, first, 8, 500) == 8)
                ok = 1;
            else
                SAY("GET_DESCRIPTOR (device, 8 bytes), attempt %d of 3: %s\n", attempt, usb_error_text());
        }
    }
    if (!ok || set_up_device(d, first) < 0) {
        forget_all();
        return -1;
    }
    return 0;
}

/* usb_enumerate without its listing (a keyboard's line included): 0 when the
   device on the port answered */
int usb_enumerate_quiet(void)
{
    quiet = 1;
    int r = usb_enumerate();
    quiet = 0;
    return device_at(1) ? r : -1;
}

/* the controller's port lost its device: nothing is on the bus any more */
void usb_removed(void)
{
    forget_all();
}

/* is the device on the controller's port still set up: answering at its address, in its configuration
   (GET_CONFIGURATION not 0)?  An LTE module restarting (the A7670E after AT+CRESET) went away and came
   back twice, and after the second time it answered at its address without its configuration: its
   endpoints stalled */
int usb_still_set_up(u8 device)
{
    struct device *d = device_at(device);
    u8 config = 0;
    return d && request(d, 0x80, 0x08, 0, 0, &config, 1, 100) == 1 && config;
}

/* the device on the controller's port went away and came back since the last look, too quickly for the
   main loop's look at the port every 100 ms (the controller keeps the change: flags 1 bit 0), and the one
   set up there is not set up any more: 1, set it up again.  (Setting the controller up again drops the
   device for a moment too: one still set up was not gone.) */
int usb_bounced(void)
{
    if (!(flags1() & 0x01))
        return 0;
    flags1_seen = 0;
    return device_at(1) && !usb_still_set_up(1);
}

/* is the device still where it was enumerated?  The controller's port for
   the first; a hub's port otherwise: connected, enabled, the connection not
   changed since (a device unplugged from a hub fails its transfers before
   the hub's turn comes in usb_hub_poll, which is told to look there next) */
static u8 poll_hub, poll_port;          /* usb_hub_poll's place: a hub's address, its port */

int usb_present(u8 device)
{
    const struct device *d = device_at(device);
    if (!d || !usb_connected())
        return 0;
    if (!d->hub)
        return 1;
    if (!usb_present(d->hub))
        return 0;                       /* its hub is gone: that one's port comes next */
    const struct device *h = device_at(d->hub);
    u16 status, change;
    if (h && port_status(h, d->port, &status, &change) == 0 && (status & 3) == 3 && !(change & 1))
        return 1;
    poll_hub = d->hub;
    poll_port = d->port;
    return 0;
}

/* every 100 ms: one port of one hub, each in its turn -- a device plugged in
   is set up, one unplugged forgotten (with what was behind it), both said
   after `before` was called; 1 when something was said */
int usb_hub_poll(void (*before)(void))
{
    static u8 silent;                   /* GET_STATUS failures in a row */
    struct device *h = 0;
    for (int tries = 0; tries <= DEVICES && !h; tries++) {     /* this hub's next port, else the next hub's first */
        h = device_at(poll_hub);
        if (h && h->ports && poll_port >= 1 && poll_port <= h->ports)
            break;
        h = 0;
        poll_hub = (u8)(poll_hub % DEVICES + 1);
        poll_port = 1;
    }
    if (!h)
        return 0;
    u8 port = poll_port++;
    u16 status, change;
    int said = 0;
    if (port_status(h, port, &status, &change)) {
        if (!usb_connected())
            return 0;
        if (h->hub) {                   /* a hub on a hub's port: unplugged?  That port is looked at next */
            poll_hub = h->hub;
            poll_port = h->port;
            return 0;
        }
        if (++silent < 3)
            return 0;
        silent = 0;                     /* the hub was reset behind the demo's back */
        before();
        uprintf("[usb] hub %u does not answer (%s): setting the bus up again\n", h->address, usb_error_text());
        usb_enumerate_quiet();
        return 1;
    }
    silent = 0;
    if (change & 0x02)
        port_feature(h, port, 0, C_PORT_ENABLE);
    if (change & 0x08)
        port_feature(h, port, 0, C_PORT_OVER_CURRENT);
    if (change & 0x10)
        port_feature(h, port, 0, C_PORT_RESET);
    if (change & 0x01) {
        port_feature(h, port, 0, C_PORT_CONNECTION);
        h->ignore &= (u8)~(1u << port);
    }
    struct device *d = device_on(h->address, port);
    if (d && (!(status & 1) || (change & 1))) {         /* unplugged (or unplugged and something plugged in) */
        before();
        uprintf("[usb] hub %u port %u: device removed (%04x:%04x%s%s)\n", h->address, port, d->vid, d->pid,
                d->product[0] ? " " : "", d->product);
        forget(d);
        d = 0;
        said = 1;
        const char *text = start_a_keyboard();
        if (text)
            uprintf("[usb] %s\n", text);
        text = start_a_mouse();
        if (text)
            uprintf("[usb] %s\n", text);
    }
    if ((status & 1) && !d && !(h->ignore & (1u << port))) {
        if (!said)
            before();
        uprintf("[usb] hub %u port %u: device connected\n", h->address, port);
        delay_ms(100);                                  /* its contacts settle */
        port_connect(h, port);
        said = 1;
    }
    return said;
}

/* the token error register's value after the last failed transfer (0: a time-out) */
u8 usb_last_error(void)
{
    return fail_error;
}

/* lsusb: the controller, then every device in one line (enumerated quietly
   when nothing has been yet) */
void usb_lsusb(void)
{
    int connected = usb_connected();
    uprintf("Bus 001: ALi USB 2.0 host controller at 0x%08x, port: %s\n", USB_BASE,
            connected ? "device connected" : "no device");
    if (!connected)
        return;
    if (!device_at(1))
        usb_enumerate_quiet();
    if (!device_at(1)) {
        uprintf("Bus 001 Device ---: a device is connected but does not answer (%s)\n", usb_error_text());
        return;
    }
    for (int i = 0; i < DEVICES; i++) {
        const struct device *d = &devices[i];
        if (!d->used || !d->address)
            continue;
        uprintf("Bus 001 Device %03u: ID %04x:%04x %s%s%s, %s", d->address, d->vid, d->pid, d->mfr,
                d->mfr[0] && d->product[0] ? " " : "", d->product, speed_name(d->speed));
        if (d->hub)
            uprintf(", hub %u port %u", d->hub, d->port);
        uprintf("\n");
    }
}

void usb_status(void)
{
    u8 port = USB[R_PORT];
    uprintf("USB host controller at 0x%08x (ALi hc_s3602 type)%s\n", USB_BASE,
            initialized ? "" : ", not set up yet");
    uprintf("  port status 0x%02x: %s%s\n", port,
            (port & 2) ? "device connected" : "no device",
            (port & 1) ? ", OVER-CURRENT" : "");
    if (port & 2)
        uprintf("  speed: %s\n", speed_name(root_speed()));
    uprintf("  PHY settings (+0xf0, +0xf4): 0x%08x 0x%08x\n", USB32(R_PHY0), USB32(R_PHY1));
}

void usb_bus_reset(void)
{
    u8 flags;
    if (!initialized)
        hc_init();
    forget_all();                       /* the device is back at address 0, unconfigured */
    int ms = bus_reset(&flags);
    if (ms >= 0)
        uprintf("bus reset: done after %u ms, flags 0x%02x; 'usb' enumerates the device again\n", (u32)ms, flags);
    else
        uprintf("bus reset: no completion flag, flags 0x%02x\n", flags);
}

/* 'usb init': the controller set up again (the PHY's reset included) */
void usb_init(void)
{
    forget_all();
    hc_init();
}

/* 'usb reg': one register, byte-wide (md / mw use words) */
int usb_reg(u32 offset, int write, u8 value)
{
    if (offset > 0xFF)
        return -1;
    if (write) {
        if (offset >= R_PHY0 && offset < R_PHY1 + 4)
            return -2;                  /* the PHY: 'usb init' (a reset of it by hand hung a box) */
        USB[offset] = value;
    }
    return USB[offset];
}
