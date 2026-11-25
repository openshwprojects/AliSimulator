/* A sampling profiler: `prof <command ...>` runs the command with the CPU's own timer (CP0 Count / Compare)
   interrupting it about 10,000 times a second; each interrupt adds one to the 64-byte piece of code it
   stopped in (EPC), in a histogram over KSEG0 0x80000000..0x83FFFFFF (the application and the players' RAM,
   where the PlayStation's recompiled code lives).  Afterwards the pieces hit are printed as
   "address count" in hex, most first; tools map them to functions with the build's app.map / app.elf.

   The demo runs with interrupts off: only for the command's time, the general exception vector
   (EBase + 0x180 = 0x80000180, below the application's start) holds the handler below, Cause.IV is off (an
   interrupt there, not at +0x200 = _start), Status.BEV off and only IM7 -- the timer -- on.  The handler uses
   $k0 / $k1 alone (GCC and the PlayStation recompiler never do) and costs ~25 cycles a sample. */
#include "hw.h"

#define PROF_PHYS     0x05000000u      /* the histogram: WGET_PHYS's 8 MB, unused while a command runs */
#define PROF_SHIFT    6                /* 64-byte pieces */
#define PROF_PIECES   0x00100000u      /* 64 MB of KSEG0 / 64 */
#define PROF_INTERVAL 29700u           /* Count ticks between samples (Count = CPU / 2: ~10 kHz at 594 MHz) */
#define PROF_TOP      400              /* pieces printed at most */

static volatile u32 *const hist = (volatile u32 *)(0x80000000u | PROF_PHYS);

/* a player may name its own pieces (the PlayStation's recompiled code by the R3000 code it came from):
   psx.c defines it; this one is used when nothing else does */
__attribute__((weak)) void prof_report_more(const volatile u32 *h, u32 pieces, u32 shift)
{
    (void)h;
    (void)pieces;
    (void)shift;
}
static u32 saved_status, saved_cause, running, from_frame;

static void clear(void)
{
    for (u32 i = 0; i < PROF_PIECES; i++)
        hist[i] = 0;
}

/* `prof -e EV0 EV1`: the 24K's two performance counters (CP0 25: PerfCtl0/PerfCnt0 at selects 0/1, PerfCtl1/PerfCnt1
   at 2/3; Config1.PC says they exist) count events EV0 and EV1 in kernel mode -- from the game's frame N for
   PC_FRAMES frames with -f (32-bit counters: a whole run of cycles would wrap), else the command's whole run.
   The 24K's numbers include 0 cycles, 1 instructions completed, 9 I-cache accesses / misses, 10 D-cache accesses
   / writebacks, 11 D-cache misses (counter 0 / counter 1) */
#define PC_FRAMES 100u
static u32 pc_on, pc_ev[2], pc_val[2], pc_done, pc_count0, pc_count;     /* (CP0 Count over the same time) */

void prof_events(u32 e0, u32 e1)
{
    pc_on = 1;
    pc_ev[0] = e0 & 127u;
    pc_ev[1] = e1 & 127u;
}

static void pc_start(void)
{
    u32 z = 0, c0 = (pc_ev[0] << 5) | 0x2u, c1 = (pc_ev[1] << 5) | 0x2u;  /* the event, K: kernel mode */
    __asm__ volatile("mtc0 %0, $25, 0\n\tmtc0 %0, $25, 2\n\tmtc0 %1, $25, 1\n\tmtc0 %1, $25, 3\n\t"
                     "mtc0 %2, $25, 0\n\tmtc0 %3, $25, 2\n\tsll $0, $0, 3" : : "r"(z), "r"(z), "r"(c0), "r"(c1));
    __asm__ volatile("mfc0 %0, $9" : "=r"(pc_count0));
}

static void pc_stop(void)
{
    u32 z = 0, v0, v1, c;
    __asm__ volatile("mtc0 %0, $25, 0\n\tmtc0 %0, $25, 2\n\tsll $0, $0, 3" : : "r"(z));
    __asm__ volatile("mfc0 %0, $9" : "=r"(c));
    __asm__ volatile("mfc0 %0, $25, 1" : "=r"(v0));
    __asm__ volatile("mfc0 %0, $25, 3" : "=r"(v1));
    pc_val[0] = v0;
    pc_val[1] = v1;
    pc_count = c - pc_count0;
    pc_done = 1;
}

/* play.c, every frame of a game: `prof -f N` counts only from the game's frame N on */
void prof_frame(u32 n)
{
    if (running && from_frame && n == from_frame) {
        clear();
        if (pc_on)
            pc_start();
    }
    if (running && pc_on && from_frame && n == from_frame + PC_FRAMES && !pc_done)
        pc_stop();
}

void prof_from(u32 frame)
{
    from_frame = frame;
}

/* `prof -c ADDR LEN`: samples inside ADDR..ADDR+LEN-1 (a leaf function such as memset, which keeps its caller's
   return address in $ra) are counted for the caller instead (the word at 0x800001F0 holds ADDR, 0 = off) */
#define CALLER_WORD   0x800001F0u
static u32 caller_lo, caller_len;

void prof_caller(u32 lo, u32 len)
{
    caller_lo = lo;
    caller_len = len > 0x7FFFu ? 0x7FFFu : len;
}

static const u32 handler[] = {
    0x401a4800u,                       /* mfc0  $k0, $9          Count */
    0x275a0000u | PROF_INTERVAL,       /* addiu $k0, $k0, INTERVAL */
    0x409a5800u,                       /* mtc0  $k0, $11         Compare: the next sample; this one acked */
    0x000000c0u,                       /* ehb */
    0x401a7000u,                       /* mfc0  $k0, $14         EPC */
    0x3c1b8000u,                       /* lui   $k1, 0x8000 */
    0x8f7b01f0u,                       /* lw    $k1, 0x1F0($k1)  CALLER_WORD */
    0x035bd823u,                       /* subu  $k1, $k0, $k1 */
    0x2f7b0000u,                       /* sltiu $k1, $k1, LEN    (LEN patched in) */
    0x03fbd00bu,                       /* movn  $k0, $ra, $k1    inside: the caller */
    0x3c1b8000u,                       /* lui   $k1, 0x8000 */
    0x035bd023u,                       /* subu  $k0, $k0, $k1 */
    0x001ad182u,                       /* srl   $k0, $k0, 6 */
    0x3c1b0010u,                       /* lui   $k1, 0x0010      PROF_PIECES */
    0x035bd82bu,                       /* sltu  $k1, $k0, $k1 */
    0x001bd00au,                       /* movz  $k0, $0, $k1     outside: piece 0 */
    0x001ad080u,                       /* sll   $k0, $k0, 2 */
    0x3c1b8500u,                       /* lui   $k1, 0x8500      the histogram (KSEG0 PROF_PHYS) */
    0x035bd021u,                       /* addu  $k0, $k0, $k1 */
    0x8f5b0000u,                       /* lw    $k1, 0($k0) */
    0x00000000u,                       /* nop */
    0x277b0001u,                       /* addiu $k1, $k1, 1 */
    0xaf5b0000u,                       /* sw    $k1, 0($k0) */
    0x42000018u,                       /* eret */
    0x00000000u,                       /* nop */
};

/* `prof -s EV`: the samples taken every PROF_EV_PERIOD events EV of performance counter 0 instead of the timer --
   where e.g. the I-cache miss stall cycles (37) go.  The counter's overflow (its bit 31 set) interrupts on the line
   IntCtl.IPPCI names (IP7 on the S3811, the timer's); the handler sets the counter back, pushes the timer's Compare
   far ahead (acking it, if it was the timer) and counts EPC as above (no -c) */
#define PROF_EV_PERIOD 10000u
static u32 ev_on, ev_num;

void prof_sample(u32 ev)
{
    ev_on = 1;
    ev_num = ev & 127u;
}

static const u32 handler_ev[] = {
    0x401a4800u,                       /* mfc0  $k0, $9          Count */
    0x3c1b4000u,                       /* lui   $k1, 0x4000 */
    0x035bd021u,                       /* addu  $k0, $k0, $k1 */
    0x409a5800u,                       /* mtc0  $k0, $11         Compare: far ahead (a timer interrupt acked) */
    0x3c1a8000u,                       /* lui   $k0, 0x8000 */
    0x275a0000u | ((0u - PROF_EV_PERIOD) & 0xFFFFu),   /* addiu $k0, $k0, -PERIOD */
    0x409ac801u,                       /* mtc0  $k0, $25, 1      PerfCnt0: PERIOD events to the next */
    0x000000c0u,                       /* ehb */
    0x401a7000u,                       /* mfc0  $k0, $14         EPC */
    0x3c1b8000u,                       /* lui   $k1, 0x8000 */
    0x035bd023u,                       /* subu  $k0, $k0, $k1 */
    0x001ad182u,                       /* srl   $k0, $k0, 6 */
    0x3c1b0010u,                       /* lui   $k1, 0x0010      PROF_PIECES */
    0x035bd82bu,                       /* sltu  $k1, $k0, $k1 */
    0x001bd00au,                       /* movz  $k0, $0, $k1     outside: piece 0 */
    0x001ad080u,                       /* sll   $k0, $k0, 2 */
    0x3c1b8500u,                       /* lui   $k1, 0x8500      the histogram (KSEG0 PROF_PHYS) */
    0x035bd021u,                       /* addu  $k0, $k0, $k1 */
    0x8f5b0000u,                       /* lw    $k1, 0($k0) */
    0x00000000u,                       /* nop */
    0x277b0001u,                       /* addiu $k1, $k1, 1 */
    0xaf5b0000u,                       /* sw    $k1, 0($k0) */
    0x42000018u,                       /* eret */
    0x00000000u,                       /* nop */
};
typedef char prof_handler_ev_fits[sizeof(handler_ev) <= 0x70u ? 1 : -1];   /* (below CALLER_WORD) */

static inline u32 cp0_status(void) { u32 v; __asm__ volatile("mfc0 %0, $12" : "=r"(v)); return v; }
static inline u32 cp0_cause(void) { u32 v; __asm__ volatile("mfc0 %0, $13" : "=r"(v)); return v; }
static inline u32 cp0_ebase(void) { u32 v; __asm__ volatile("mfc0 %0, $15, 1" : "=r"(v)); return v; }
/* (ehb spelt sll $0, $0, 3: the build is -march=mips32, whose assembler lacks the name) */
static inline void set_status(u32 v) { __asm__ volatile("mtc0 %0, $12\n\tsll $0, $0, 3" : : "r"(v) : "memory"); }
static inline void set_cause(u32 v) { __asm__ volatile("mtc0 %0, $13\n\tsll $0, $0, 3" : : "r"(v) : "memory"); }
static inline void set_compare(u32 v) { __asm__ volatile("mtc0 %0, $11\n\tsll $0, $0, 3" : : "r"(v) : "memory"); }

int prof_start(void)
{
    if (running)
        return 0;
    u32 eb = cp0_ebase() & 0x3FFFF000u;
    if (eb != 0x00000000u) {           /* (EBase's exception base, bits 29..12 above 0x80000000) */
        uprintf("prof: EBase is 0x%08x, not 0x80000000: not started\n", cp0_ebase());
        return -1;
    }
    u32 ippci = 7u;
    if (ev_on) {
        u32 intctl;
        __asm__ volatile("mfc0 %0, $12, 1" : "=r"(intctl));
        ippci = (intctl >> 26) & 7u;
        if (ippci < 2u) {
            uprintf("prof: IntCtl %08x names no line for the counters' interrupt: not started\n", intctl);
            ev_on = 0;
            return -1;
        }
    }
    clear();
    volatile u32 *vec = (volatile u32 *)0x80000180u;
    if (ev_on) {
        for (u32 i = 0; i < sizeof(handler_ev) / sizeof(handler_ev[0]); i++)
            vec[i] = handler_ev[i];
        *(volatile u32 *)CALLER_WORD = 0u;
    } else {
        for (u32 i = 0; i < sizeof(handler) / sizeof(handler[0]); i++)
            vec[i] = handler[i];
        vec[8] = handler[8] | caller_len;                   /* the sltiu's LEN */
        *(volatile u32 *)CALLER_WORD = caller_len ? caller_lo : 0u;
    }
    for (u32 a = 0x80000180u; a < 0x80000200u; a += 16)
        __asm__ volatile("cache 0x15, 0(%0)\n\tcache 0x10, 0(%0)" : : "r"(a) : "memory");
    __asm__ volatile("sync\n\tsll $0, $0, 3" : : : "memory");
    saved_status = cp0_status();
    saved_cause = cp0_cause();
    set_status(saved_status & ~1u);                         /* interrupts off while it is set up */
    set_cause(saved_cause & ~(1u << 23));                   /* Cause.IV off: the vector at +0x180 */
    if (ev_on) {                                            /* counter 0: EV, interrupting (IE), kernel mode */
        u32 z = 0, ctl = (ev_num << 5) | 0x10u | 0x2u, cnt = 0x80000000u - PROF_EV_PERIOD;
        __asm__ volatile("mtc0 %0, $25, 0\n\tsll $0, $0, 3\n\tmtc0 %1, $25, 1\n\tmtc0 %2, $25, 0\n\tsll $0, $0, 3"
                         : : "r"(z), "r"(cnt), "r"(ctl));
        set_compare(cp0_count() + 0x40000000u);
    } else {
        set_compare(cp0_count() + PROF_INTERVAL);
    }
    u32 st = saved_status & ~((1u << 22) | 0xFF00u | 0x1Fu);   /* BEV, IM7..0, KSU / ERL / EXL / IE off */
    set_status(st | (1u << 15) | (1u << (8u + ippci)) | 1u);   /* IM7 (the timer), the counters' line, IE */
    running = 1;
    pc_done = 0;
    if (pc_on && !from_frame)
        pc_start();
    return 0;
}

void prof_stop(void)
{
    if (!running)
        return;
    if (ev_on) {
        u32 z = 0;
        __asm__ volatile("mtc0 %0, $25, 0\n\tsll $0, $0, 3" : : "r"(z));
        ev_on = 0;
    }
    if (pc_on && !pc_done)
        pc_stop();
    set_status(cp0_status() & ~1u);
    set_status(saved_status & ~1u);
    set_cause(saved_cause);
    set_status(saved_status);
    running = 0;
}

void prof_report(void)
{
    u32 total = 0, pieces = 0;
    for (u32 i = 0; i < PROF_PIECES; i++)
        if (hist[i]) {
            total += hist[i];
            pieces++;
        }
    u32 c0, c1, c2, c3, prid;
    __asm__ volatile("mfc0 %0, $16, 0" : "=r"(c0));
    __asm__ volatile("mfc0 %0, $16, 1" : "=r"(c1));
    __asm__ volatile("mfc0 %0, $16, 2" : "=r"(c2));
    __asm__ volatile("mfc0 %0, $16, 3" : "=r"(c3));
    __asm__ volatile("mfc0 %0, $15, 0" : "=r"(prid));
    uprintf("prof: CPU PRId %08x Config %08x %08x %08x %08x\n", prid, c0, c1, c2, c3);
    if (pc_on && pc_done) {
        if (from_frame)
            uprintf("prof: frames %u..%u: ", from_frame, from_frame + PC_FRAMES - 1u);
        else
            uprintf("prof: the whole run (32-bit, may have wrapped): ");
        uprintf("event %u (counter 0) %u, event %u (counter 1) %u; CP0 Count %u\n", pc_ev[0], pc_val[0], pc_ev[1],
                pc_val[1], pc_count);
    }
    pc_on = 0;
    uprintf("prof: %u samples in %u pieces of 64 bytes (%u outside 0x80000000..0x83ffffff)\n", total, pieces,
            hist[0]);
    for (u32 r = 0; r < PROF_PIECES; r += 1024) {      /* 64 KB regions: "R address samples" */
        u32 sum = 0;
        for (u32 i = r; i < r + 1024; i++)
            sum += hist[i];
        if (sum)
            uprintf("R %08x %u\n", 0x80000000u + (r << PROF_SHIFT), sum);
    }
    /* the most hit first: a threshold halved until PROF_TOP pieces are reached (no sort of a million) */
    u32 most = 0;
    for (u32 i = 1; i < PROF_PIECES; i++)
        if (hist[i] > most)
            most = hist[i];
    prof_report_more(hist, PROF_PIECES, PROF_SHIFT);
    u32 printed = 0;
    for (u32 hi = most + 1; hi > 1 && printed < PROF_TOP; ) {
        u32 lo = hi / 2;
        for (u32 i = 1; i < PROF_PIECES && printed < PROF_TOP; i++) {
            u32 c = hist[i];
            if (c >= lo && c < hi) {
                uprintf("P %08x %u\n", 0x80000000u + (i << PROF_SHIFT), c);
                printed++;
            }
        }
        hi = lo;
    }
    uprintf("prof: end\n");
}
