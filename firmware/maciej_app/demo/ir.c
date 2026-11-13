/* The remote control: the chip's M6303 IR receiver (IRC, 0xB8018100) set up
   as the SDK's irc_m6303irc_init does, read by polling instead of its
   interrupt.  The controller measures the receiver's output and queues one
   byte per run in a FIFO: bit 7 the line level, bits 0..6 the length in
   8 us ticks (a longer run takes several bytes of the same level).  A frame
   ends when the line stays idle for the timeout (status bit 1); the FIFO
   threshold (bit 0) only says bytes are waiting.  Frames are decoded as NEC:
   9 ms mark + 4.5 ms space + 32 bits (560 us mark, 560 / 1690 us space) or
   the 9 ms + 2.25 ms repeat. */
#include "hw.h"
#include "ir_keys.h"

#define IRC ((volatile u8 *)IRC_BASE)
#define IRCCFG   0
#define FIFOCTRL 1
#define TIMETHR  2
#define NOISETHR 3
#define IER      6
#define ISR      7
#define RLCBYTE  8

#define TICK_US 8
#define MAX_RLC 256
#define MAX_RUNS 128

static u8 rlc[MAX_RLC];
static int n_rlc;
static int raw_mode;
static u32 frames;
static u32 last_code;
static int have_last;

void ir_init(void)
{
    IRC[IRCCFG] = 0;
    IRC[IRCCFG] = 0x80 | ((12 * TICK_US) >> 5);         /* on, 8 us work clock (12 MHz bus) */
    IRC[FIFOCTRL] = 0xA0;                               /* FIFO threshold: 32 bytes */
    IRC[TIMETHR] = 24000 / (TICK_US << 7) - 1;          /* idle timeout 24 ms */
    IRC[NOISETHR] = 80 / TICK_US;                       /* ignore pulses below 80 us */
    IRC[ISR] = 3;                                       /* nothing pending */
    IRC[IER] = 3;                                       /* as the SDK (CPU interrupts stay off) */
    n_rlc = 0;
}

void ir_set_raw(int on)
{
    raw_mode = on;
}

u32 ir_frames(void)
{
    return frames;
}

const char *ir_key_name(u32 code)
{
    u32 key = (((code >> 16) & 0xFF) << 8) | (code & 0xFF);
    for (unsigned i = 0; i < IR_KEY_COUNT; i++)
        if ((ir_key_map[i].key_info >> 16) == key)
            return ir_key_names[i];
    return 0;
}

static int near(u32 us, u32 want, u32 tolerance_pct)
{
    u32 d = want * tolerance_pct / 100;
    return us + d >= want && us <= want + d;
}

/* the queued bytes as runs (level, microseconds), consecutive levels joined */
static int to_runs(u8 *level, u32 *us)
{
    int n = 0;
    for (int i = 0; i < n_rlc; i++) {
        u8 l = rlc[i] >> 7;
        u32 t = (u32)(rlc[i] & 0x7F) * TICK_US;
        if (n && level[n - 1] == l)
            us[n - 1] += t;
        else if (n < MAX_RUNS) {
            level[n] = l;
            us[n] = t;
            n++;
        }
    }
    return n;
}

static void decode(struct ir_event *ev)
{
    u8 level[MAX_RUNS];
    u32 us[MAX_RUNS];
    int n = to_runs(level, us);
    int i = 0;

    ev->valid = 0;
    ev->repeat = 0;
    ev->code = 0;
    ev->runs = (u16)n;
    for (int k = 0; k < 4; k++)
        ev->bytes[k] = 0;
    if (raw_mode) {
        uprintf("[ir] %d runs:", n);
        for (int k = 0; k < n; k++)
            uprintf(" %c%u", level[k] ? '+' : '-', us[k]);
        uprintf("\n");
    }
    /* the leader: the first long run is the mark, whichever level it has */
    while (i < n && !near(us[i], 9000, 25))
        i++;
    if (i + 1 >= n)
        return;
    u8 mark = level[i];
    if (near(us[i + 1], 2250, 25) && level[i + 1] != mark) {
        ev->repeat = 1;
        ev->valid = have_last;
        ev->code = last_code;
        return;
    }
    if (!near(us[i + 1], 4500, 25) || level[i + 1] == mark)
        return;
    i += 2;
    u32 code = 0;
    for (int bit = 0; bit < 32; bit++, i += 2) {
        if (i + 1 >= n || level[i] != mark || !near(us[i], 560, 60))
            return;
        int one;
        if (near(us[i + 1], 1690, 30))
            one = 1;
        else if (near(us[i + 1], 560, 60))
            one = 0;
        else
            return;
        code = (code << 1) | (u32)one;                 /* as the SDK's decoder: first bit highest */
        if (one)
            ev->bytes[bit >> 3] |= (u8)(1 << (bit & 7));   /* on the wire: each byte LSB first */
    }
    ev->code = code;
    ev->valid = 1;
    last_code = code;
    have_last = 1;
}

int ir_poll(struct ir_event *ev)
{
    int ended = 0;
    u8 status;
    while ((status = IRC[ISR] & 3) != 0) {
        IRC[ISR] = status;                              /* write 1 to clear */
        u8 count;
        do {
            count = IRC[FIFOCTRL] & 0x7F;
            for (u8 k = 0; k < count; k++) {
                u8 b = IRC[RLCBYTE];
                if (n_rlc < MAX_RLC)
                    rlc[n_rlc++] = b;
            }
        } while (count);
        if (status & 2)
            ended = 1;
    }
    if (!ended)
        return 0;
    decode(ev);
    n_rlc = 0;
    frames++;
    return 1;
}
