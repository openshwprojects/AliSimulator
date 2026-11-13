/* The chip's watchdog (the SDK's dog_m3327e at 0xB8018500), kept running the
   way the box's own firmware keeps it: in reset mode, fed several times a
   second.  A 32-bit counter at +0 counts up at the memory clock divided by
   2^(5+n); the control byte at +4 holds n (bits 0-1), bit 2 (the counter
   runs) and 0x60 (reset the chip when the counter overflows; 0x10 would
   raise an interrupt instead).  dump.bin and dump_maciej.bin write the
   counter's start value, then 0x64, as they start, and the start value
   again about three times a second.

   The demo measures the counter's rate against CP0 Count once, then starts
   it DOG_SECONDS before the overflow; time.c feeds it -- writes that start
   value again -- every 0.1 s of its clock, from the time reads of the main
   loop, of every delay and of every wait.  A demo that stops (a bus access
   that never ends, as one with the USB PHY held in reset did) or loops
   without reading the time resets the box within DOG_SECONDS: the original
   bootloader starts the demo again, and the UART updater can catch the
   bootloader there without a power cycle.  platform_restart (start.S) takes
   the watchdog over for its immediate reset. */
#include "hw.h"

#define DOG_COUNT   REG32(DOG_BASE)
#define DOG_CONTROL REG8(DOG_BASE + 4)
#define DOG_RUN     0x04
#define DOG_RESET   0x60
#define MEASURE_MS  20

static u32 start_value;                 /* the counter DOG_SECONDS before it overflows */
static u32 rate;                        /* counter ticks per second (prescaler 0: memory clock / 32) */
static int running, held;

/* measure the counter, then run it in reset mode: 1, or 0 when it does not
   count (the emulator without its watchdog model) and is left off */
int dog_start(void)
{
    running = 0;                          /* no feeding into the measurement ('watchdog on' while it runs) */
    DOG_CONTROL = 0;
    DOG_COUNT = 0;
    DOG_CONTROL = DOG_RUN;                /* counting, prescaler 0, neither reset nor interrupt */
    delay_ms(MEASURE_MS);
    u32 ticks = DOG_COUNT;
    DOG_CONTROL = 0;
    rate = ticks * (1000 / MEASURE_MS);
    if (rate < 1000 || rate > 0x0FFFFFFFu / DOG_SECONDS) {
        running = 0;
        return 0;
    }
    start_value = 0xFFFFFFFFu - rate * DOG_SECONDS;
    DOG_COUNT = start_value;
    DOG_CONTROL = DOG_RESET | DOG_RUN;    /* 0x64, as the originals */
    running = 1;
    held = 0;
    return 1;
}

void dog_feed(void)
{
    if (running && !held)
        DOG_COUNT = start_value;
}

void dog_stop(void)
{
    DOG_CONTROL = 0;
    running = 0;
}

/* stop feeding it (the 'watchdog test'): the box resets DOG_SECONDS later */
void dog_hold(void)
{
    held = 1;
}

int dog_running(void)
{
    return running;
}

u32 dog_rate(void)
{
    return rate;
}

u32 dog_start_value(void)
{
    return start_value;
}

u32 dog_count(void)
{
    return DOG_COUNT;
}
