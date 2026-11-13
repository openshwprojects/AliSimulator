/* The time base: CP0 Count runs at half the CPU clock, which the strap pins
   select (sys_ic_get_cpu_clock for the S3811: bits 7..8 of 0xB8000070 ->
   675 / 594 / 396 / 297 MHz).  Count is 32 bits (12.7 s at 337.5 MHz), so the
   totals here are advanced on every call; the main loop calls far more often
   than that.  Only 32-bit divisions (the CPU's divu): no libgcc.  Every time
   read and every delay also empties the UART's receiver into its buffer and
   feeds the watchdog, so neither starves while the demo waits. */
#include "hw.h"

static const u32 clock_mhz[4] = {675, 594, 396, 297};
static u32 mhz;
static u32 per_ms;
static u32 last_count;
static u64 ticks_total;
static u64 ms_total;
static u32 tick_rem;
static u32 seconds;
static u32 ms_rem;
static u32 last_rx;             /* Count when the UART's receiver was last emptied */
static u32 last_feed;           /* Count when the watchdog was last fed */

/* every 62.5 us at most: received bytes into uart.c's buffer (they would
   overflow the chip's FIFO in a long delay or wait); every 0.1 s: the
   watchdog fed (dog.c) */
static void rx_service(u32 c)
{
    if ((u32)(c - last_rx) >= per_ms / 16) {
        last_rx = c;
        uart_rx_poll();
        if ((u32)(c - last_feed) >= per_ms * 100) {
            last_feed = c;
            dog_feed();
        }
    }
}

void time_init(void)
{
    mhz = clock_mhz[(REG32(SYS_STRAP) >> 7) & 3];
    per_ms = mhz * 500;             /* Count = CPU / 2 */
    last_count = cp0_count();
    ticks_total = 0;
    ms_total = 0;
    tick_rem = 0;
    seconds = 0;
    ms_rem = 0;
}

static void advance(void)
{
    u32 c = cp0_count();
    u32 delta = c - last_count;     /* wraps correctly for gaps below 12.7 s */
    last_count = c;
    ticks_total += delta;
    u32 ms = delta / per_ms;
    tick_rem += delta % per_ms;
    if (tick_rem >= per_ms) {
        tick_rem -= per_ms;
        ms++;
    }
    ms_total += ms;
    ms_rem += ms;
    seconds += ms_rem / 1000;
    ms_rem %= 1000;
    rx_service(c);
}

u32 uptime_s(void)
{
    advance();
    return seconds;
}

u32 cpu_mhz(void)
{
    return mhz;
}

u32 ticks_per_ms(void)
{
    return per_ms;
}

u64 now_ticks(void)
{
    advance();
    return ticks_total;
}

u64 now_ms(void)
{
    advance();
    return ms_total;
}

void delay_us(u32 us)
{
    u32 start = cp0_count();
    u32 wait = us * mhz / 2;
    for (;;) {
        u32 c = cp0_count();
        if ((u32)(c - start) >= wait)
            break;
        rx_service(c);
    }
    advance();
}

void delay_ms(u32 ms)
{
    while (ms--)
        delay_us(1000);
}
