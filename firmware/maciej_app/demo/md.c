/* A Sega Mega Drive / Genesis: see md.h.

   The 68000 is m68k.inc's (amiga.c's), with the VDP's interrupt acknowledge,
   TAS not writing to memory (the console's bus does not take that write)
   and its taken branches looked at for a loop waiting on RAM.  The Z80 is
   z80.c's.  Waiting is cut short where nothing it could see changes: a
   68000 loop on RAM, the 68000 polling the VDP's status, the Z80 polling the
   YM2612's -- each goes on at once to just before what it waits for can
   come (idle_branch, status_read, z_status).

   The frame: 262 lines (PAL 313) of 3420 master clocks: 488.57 cycles of
   the 68000 (MCLK / 7) and 228 of the Z80 (MCLK / 15) a line.  A line here
   starts where the VDP's V counter changes (its H counter near 0xA5 in
   H40): the horizontal interrupt counter counts there (lines 0 to 224,
   reloaded from register 10 below), the line is drawn there in one go from
   the registers and memories as they are then -- so a change made in a
   horizontal interrupt shows from the next line, a change in the middle of
   a line from the next one -- then the 68000 runs the line, then the Z80
   (which also catches up with the 68000 whenever the 68000 touches its bus,
   its reset or its bus request, or the YM2612).  At line 224 (240 in V30)
   the vertical blanking starts, and 112 cycles later the vertical interrupt
   (level 6) and the Z80's interrupt (held for 171 of its cycles).  The
   horizontal interrupt is level 4; the VDP drops each when the 68000
   acknowledges it.

   The VDP: VRAM (64 KB), CRAM (64 colours of 9 bits), VSRAM (40 words);
   its control port's two-word commands, register writes, the data port
   (written at once: no FIFO, no access slots), auto-increment; DMA from the
   68000's bus (ROM, RAM) to VRAM, CRAM, VSRAM -- done at once, the 68000
   held for about the time it takes in the vertical blanking --, VRAM fill
   and copy (done at once, the busy flag up for the time they take); the
   status register (FIFO empty, VINT pending, sprite overflow and collision,
   odd frame, VBLANK, HBLANK, DMA busy, PAL); the HV counter with its jumps
   (H40, H32; V28 / V30, NTSC / PAL).  The picture: planes A and B (32, 64,
   128 cells) with full / per-cell / per-line horizontal scroll and full /
   2-cell vertical scroll, the window (left / right, up / down), the
   priorities, 80 sprites (64 in H32) from the link list, 20 (16) and 320
   (256) pixels of them a line with the overflow flag, their collision flag,
   the masking sprite at X 0, the sprite table's cache (Y, size and link are
   read from where the table was written, as the chip keeps them); shadow /
   highlight; the background colour, the blanked left column, the picture
   switched off; H32 / H40; V28 / V30 (240 lines on PAL).  Interlace mode 2
   (Sonic 2's two players) is drawn as its first field alone (tiles 16 lines
   high, every other line: the picture squeezed to 224 lines).  Not there:
   anything that changes in the middle of a line, the FIFO's timing, DMA
   slowing down in the active picture, the 128 KB VRAM mode, mode 4 (the
   Master System's: drawn as mode 5), the external interrupt, the HV
   counter's latch (light guns).

   The Z80: its 8 KB of RAM (twice), the bank register (0x6000: 9 bits in
   series) opening 32 KB of the 68000's space at 0x8000, the YM2612 at 0x4000,
   the PSG at 0x7F11, the VDP's HV counter at 0x7F08; the 68000's bus request
   and reset (which resets the YM2612 too).

   The I/O: the version register (overseas / domestic, NTSC / PAL), two
   pads (3 buttons, or 6 with their TH counting and its 1.5 ms time-out; a
   TH never made an output -- the control register left 0 -- driven by the
   data register all the same, as some homebrew expects), TMSS (its register
   takes writes; the console is a model without it).  The cartridge: up to
   4 MB as one, more through Sega's mapper (0xA130F3-FF, 512 KB banks: Super
   Street Fighter II); its RAM at 0x200000 when its header says so (odd
   bytes, even bytes or words), switched by 0xA130F1 on a cartridge of more
   than 2 MB; Super Mario World (Taiwan)'s protection register (0xA13000
   reads 0x1C; the cartridge known by its "SEGASEGA..." header or its
   checksums).

   The sound: see the YM2612's and the PSG's parts below. */
#include "md.h"
#include "z80.h"

u8 g_m68k_shared_optab[65536];

typedef signed char s8;

#define INLINE static inline __attribute__((always_inline))

static void vdp_iack(u32 level);
static void idle_branch(u32 at);
#define M68K_IACK(level) vdp_iack(level)
#define M68K_TAS_READ_ONLY
#define M68K_BRANCH(at) idle_branch(at)
#include "m68k.inc"

#define LINE_MCLK  3420
#define Z80_LINE   228                  /* (3420 / 15) */
#define VINT_DELAY 112                  /* 68000 cycles from the line's start to the vertical interrupt */
#define Z80_INT_LENGTH 171              /* the Z80's interrupt held for this many of its cycles */
#define TH_TIMEOUT 11500                /* a 6-button pad goes back to its first state: 1.5 ms of the 68000 */

static struct z80 z;

/* ---- the console ---- */
static u16 ram[0x8000];                 /* 64 KB (as the 68000 sees it: a word in each u16) */
static u8 zram[0x2000];
static u8 *rom;                         /* the cartridge, its words as the 68000's */
static u32 rom_size, rom_pages;         /* bytes, 64 KB pages */
static u8 big;                          /* more than 4 MB: Sega's mapper */
static u8 banks[8];                     /* its 512 KB banks at 0x000000, 0x080000, ... */
static u8 sram[0x10000];
static u32 sram_lo, sram_hi;            /* its addresses (first, last) */
static u8 sram_kind;                    /* 0 none, 1 odd bytes, 2 even bytes, 3 words */
static u8 sram_on, sram_dirty, sram_battery;
static u8 protection;                   /* an unlicensed cartridge's: 1 Super Mario World (Taiwan) */
static u8 pal, overseas;
static const struct md_addon *addon;
static u32 lines = 262;
static u32 cycles_hi;                   /* 68000 cycles of the frames before this one */
static char info[96];

/* the Z80's side */
static u8 z_reset = 1, z_busreq;        /* its RESET line held (as at power-on), the 68000 asked for its bus */
static u32 z_bank;                      /* the 68000's address of its window (bank << 15) */

/* the pads */
static u16 pads[2];
static u8 io_data[3], io_ctrl[3];
static u8 six;
static u8 th_count[2];
static u32 th_time[2];

/* ---- the VDP ---- */
static u16 vram[0x8000];                /* VRAM's words (address a: vram[a >> 1]) */
static u32 pat[0x4000];                 /* each 4-byte row of the patterns: pixel i in bits 4i..4i+3 */
static u16 cram[64], vsram[64];
static u16 colour[3][64];               /* CRAM as pixels: normal, shadow, highlight */
static u8 reg[32];
static u16 vaddr;
static u8 vcode, vpending;              /* the command's code; the first of its two words came */
static u8 vint_pending, hint_pending, spr_overflow, spr_collision, odd_frame;
static u8 fill_pending;
static s32 dma_busy_until;              /* (68000 cycles of the frame) */
/* A fill and a VRAM copy cost the 68000 no time here, so a program could ask for any number of them in one
   frame (a damaged ROM writing the ports in a loop: thousands of 64 KB fills, a frame of many seconds and the
   watchdog's reset).  The real chip moves about 50 KB a frame at most: what goes beyond DMA_FRAME_MAX in one
   frame is not done */
#define DMA_FRAME_MAX 0x100000u
static u32 dma_frame_left;
static int hcounter;
static u32 line;                        /* the line the VDP is on (0: the picture's first) */
static s32 line_start;                  /* where it started (68000 cycles of the frame) */
static s32 run_until;                   /* where the 68000's run now ends (the next event) */
static u8 in_vblank;
static u16 sat_cache[80 * 2];           /* the sprite table's Y and size / link words, as the chip keeps them */
static u8 spr_lines[MD_H_MAX][21];      /* each line's sprites in the list's order ([0]: how many; one more than the
                                           line takes: the overflow) -- made again when the table or the mode changed */
static u8 spr_dirty = 1;
static u8 nib_swap[256];
static u8 dot_overflow_before;
static u16 *pic;
static int pic_w = 320, pic_h = 224;    /* the picture being drawn (as the frame started) */
static u16 scratch[MD_W_MAX];

static int h40(void)
{
    return (reg[12] & 0x81) != 0;
}

static int height(void)
{
    return (reg[1] & 0x08) ? 240 : 224;
}

static u32 sat_base(void)
{
    return h40() ? (u32)(reg[5] & 0x7E) << 9 : (u32)(reg[5] & 0x7F) << 9;
}

/* ---- interrupts ---- */
static void irq_update(void)
{
    u32 level = 0;
    if (vint_pending && (reg[1] & 0x20))
        level = 6;
    else if (hint_pending && (reg[0] & 0x10))
        level = 4;
    m.ipl = level;
    check_pending();
}

static void vdp_iack(u32 level)
{
    if (level == 6)
        vint_pending = 0;
    else if (level == 4)
        hint_pending = 0;
    irq_update();
}

/* A loop waiting on RAM -- a Bcc / BRA back to a TST, CMPI or BTST #n of a RAM address (absolute, (An) or
   d16(An)) right before it: nothing but an interrupt can change what it reads, and none comes before the run's
   end (they come between runs), so the 68000 goes on to there at once */
static void idle_branch(u32 at)
{
    u32 t = m.pc;
    if (t >= at || at - t > 10 || (t & 1))      /* (an odd target: the 68000's own address error at its next
                                                   fetch -- not a 16-bit load from an odd address here) */
        return;
    const u8 *p = rmap[(t >> 16) & 0xFF];
    if (!p || ((t + 10) >> 16) != (t >> 16))
        return;
    u32 op = *(const u16 *)(p + (t & 0xFFFF)), len, a;
    if ((op & 0xFF00) == 0x4A00 && (op & 0xC0) != 0xC0)
        len = 2;                                        /* TST */
    else if ((op & 0xFF00) == 0x0C00 && (op & 0xC0) != 0xC0)
        len = (op & 0xC0) == 0x80 ? 6 : 4;              /* CMPI */
    else if ((op & 0xFFC0) == 0x0800)
        len = 4;                                        /* BTST #n */
    else
        return;
    u32 mode = (op >> 3) & 7, r = op & 7;
    const u16 *w = (const u16 *)(p + ((t + len) & 0xFFFF));
    if (mode == 2) {
        a = m.r[8 + r];
    } else if (mode == 5) {
        a = m.r[8 + r] + (u32)(s32)(s16)w[0];
        len += 2;
    } else if (mode == 7 && r < 2) {
        a = r ? (u32)w[0] << 16 | w[1] : (u32)(s32)(s16)w[0];
        len += r ? 4 : 2;
    } else {
        return;
    }
    u32 a24 = a & 0xFFFFFF;
    if (t + len != at || (a24 < 0xE00000 && !(addon && ((a24 & 0xFFFFC0) == 0xA12000 || (a24 & 0xFFFFC0) == 0xA15100))))
        return;
    if (m.clock < run_until)
        m.clock = run_until;
}

/* ---- VRAM, CRAM, VSRAM ---- */
static void vram_w(u32 a, u16 v)        /* a word at an even address */
{
    a &= 0xFFFE;
    vram[a >> 1] = v;
    u32 p = nib_swap[v >> 8] | (u32)nib_swap[v & 0xFF] << 8, *row = &pat[a >> 2];
    *row = (a & 2) ? (*row & 0xFFFFu) | p << 16 : (*row & 0xFFFF0000u) | p;
    u32 off = a - sat_base();
    if (off < (h40() ? 640u : 512u) && !(off & 4)) {
        sat_cache[(off >> 3) * 2 + ((off >> 1) & 1)] = v;
        spr_dirty = 1;
    }
}

static u8 vram_rb(u32 a)
{
    u16 w = vram[(a & 0xFFFF) >> 1];
    return (u8)((a & 1) ? w : w >> 8);
}

static void vram_wb(u32 a, u8 v)
{
    u16 w = vram[(a & 0xFFFF) >> 1];
    vram_w(a, (a & 1) ? (u16)((w & 0xFF00) | v) : (u16)((w & 0x00FF) | v << 8));
}

static u16 level15(u32 r, u32 g, u32 b)  /* three levels of 0..14 */
{
    return (u16)((r * 31 + 7) / 14 | (g * 31 + 7) / 14 << 5 | (b * 31 + 7) / 14 << 10);
}

static void cram_w(u32 i, u16 v)
{
    i &= 63;
    v &= 0x0EEE;
    cram[i] = v;
    u32 r = (v >> 1) & 7, g = (v >> 5) & 7, b = (v >> 9) & 7;
    colour[0][i] = level15(2 * r, 2 * g, 2 * b);
    colour[1][i] = level15(r, g, b);
    colour[2][i] = level15(r + 7, g + 7, b + 7);
}

/* ---- the H and V counters ---- */
static u32 h_count(void)
{
    u32 pos = (u32)(m.clock - line_start) * 7;
    if (pos >= LINE_MCLK)
        pos = LINE_MCLK - 1;
    if (h40()) {
        u32 i = (165 + pos * 210 / LINE_MCLK) % 210;
        return i <= 0xB6 ? i : i + 0x2D;
    }
    u32 i = (133 + pos * 171 / LINE_MCLK) % 171;
    return i <= 0x93 ? i : i + 0x55;
}

static u32 v_count(void)
{
    u32 v = line;
    if (!pal)
        v = v <= 0xEA ? v : v - 6;
    else
        v = v <= (height() == 240 ? 0x10Au : 0x102u) ? v : v + 0xC7;
    if ((reg[12] & 0x06) == 0x06)       /* (interlace mode 2: the line's bit 8 in bit 0) */
        v = (v << 1) | ((v >> 8) & 1);
    else if (reg[12] & 0x02)
        v = (v & 0xFE) | ((v >> 8) & 1);
    return v & 0xFF;
}

static u16 hv_read(void)
{
    return (u16)(v_count() << 8 | h_count());
}

static u16 status_read(void)
{
    static u32 poll_pc;
    static s32 poll_at;
    s32 d = m.clock - line_start;       /* (HBLANK: H 0xB3..0x05 in H40, 0x93..0x04 in H32) */
    s32 hb0 = h40() ? 33 : 40, hb1 = h40() ? 119 : 123;
    u16 v = (u16)(0x3600 | vint_pending << 7 | spr_overflow << 6 | spr_collision << 5 | odd_frame << 4 |
                  ((in_vblank || !(reg[1] & 0x40)) ? 8 : 0) | (d >= hb0 && d < hb1 ? 4 : 0) |
                  (m.clock < dma_busy_until ? 2 : 0) | pal);
    vpending = 0;
    spr_overflow = spr_collision = 0;
    /* read again by a tight loop (the same instruction, a few cycles later): the 68000 on to just before the
       status can next change (HBLANK's start or end, the DMA's end, the run's end: the line's or the VINT's) --
       the loop sees what it would have seen, in fewer turns */
    s32 loop = m.clock - poll_at;
    if (m.pc == poll_pc && loop > 0 && loop <= 40) {
        s32 next = line_start + (d < hb0 ? hb0 : d < hb1 ? hb1 : 0x7FFFFFF);
        if (dma_busy_until > m.clock && dma_busy_until < next)
            next = dma_busy_until;
        if (next > run_until)
            next = run_until;
        if (next - loop > m.clock)
            m.clock = next - loop;
    }
    poll_pc = m.pc;
    poll_at = m.clock;
    return v;
}

/* ---- DMA ---- */
static u16 bus_word(u32 a)              /* the 68000's bus as DMA reads it (ROM and RAM) */
{
    const u8 *p = rmap[(a >> 16) & 0xFF];
    return p ? *(const u16 *)(p + (a & 0xFFFE)) : (addon ? (u16)addon->io_read(a & 0xFFFFFE, 2, m.clock) : 0);
}

static void data_store(u16 v)
{
    switch (vcode & 0x0F) {
    case 1:
        if (vaddr & 1)
            v = (u16)(v >> 8 | v << 8);
        vram_w(vaddr, v);
        break;
    case 3:
        cram_w(vaddr >> 1, v);
        break;
    case 5:
        if (((vaddr >> 1) & 63) < 40)
            vsram[(vaddr >> 1) & 63] = v & 0x7FF;
        break;
    }
    vaddr = (u16)(vaddr + reg[15]);
}

static s32 dma_time(u32 units)          /* 68000 cycles for `units` transfers at the vertical blanking's rate */
{
    u32 per_line = h40() ? 205 : 167;
    if (!in_vblank && (reg[1] & 0x40))
        per_line = h40() ? 18 : 16;
    return (s32)(units * 489 / per_line);
}

static void dma_start(void)
{
    u32 len = (u32)(reg[19] | reg[20] << 8);
    if (!len)
        len = 0x10000;
    switch (reg[23] >> 6) {
    case 0:
    case 1: {                           /* the 68000's bus to VRAM / CRAM / VSRAM */
        u32 src = (u32)(reg[23] & 0x7F) << 17 | (u32)reg[22] << 9 | (u32)reg[21] << 1;
        for (u32 i = 0; i < len; i++) {
            data_store(bus_word(src));
            src = (src & 0xFE0000u) | ((src + 2) & 0x1FFFFu);
        }
        reg[21] = (u8)(src >> 1);
        reg[22] = (u8)(src >> 9);
        reg[19] = reg[20] = 0;
        m.clock += dma_time(len);       /* (the 68000 waits) */
        break;
    }
    case 2:                             /* a fill: at the next data port write */
        fill_pending = 1;
        break;
    default: {                          /* a VRAM copy (bytes) */
        u32 src = (u32)(reg[21] | reg[22] << 8);
        if (len > dma_frame_left)
            len = dma_frame_left;
        dma_frame_left -= len;
        for (u32 i = 0; i < len; i++) {
            vram_wb(vaddr, vram_rb(src));
            src = (src + 1) & 0xFFFF;
            vaddr = (u16)(vaddr + reg[15]);
        }
        reg[21] = (u8)src;
        reg[22] = (u8)(src >> 8);
        reg[19] = reg[20] = 0;
        dma_busy_until = m.clock + 2 * dma_time(len);
        break;
    }
    }
}

static void fill(u16 v)
{
    u32 len = (u32)(reg[19] | reg[20] << 8);
    if (!len)
        len = 0x10000;
    fill_pending = 0;
    if (len > dma_frame_left)
        len = dma_frame_left;
    dma_frame_left -= len;
    for (u32 i = 0; i < len; i++) {
        if ((vcode & 0x0F) == 1)
            vram_wb(vaddr ^ 1, (u8)(v >> 8));
        else if ((vcode & 0x0F) == 3)
            cram_w(vaddr >> 1, v);
        else if ((vcode & 0x0F) == 5 && ((vaddr >> 1) & 63) < 40)
            vsram[(vaddr >> 1) & 63] = v & 0x7FF;
        vaddr = (u16)(vaddr + reg[15]);
    }
    reg[19] = reg[20] = 0;
    dma_busy_until = m.clock + dma_time(len);
}

/* ---- the ports ---- */
static void data_write(u16 v)
{
    vpending = 0;
    data_store(v);
    if (fill_pending)
        fill(v);
}

static u16 data_read(void)
{
    u16 v = 0;
    vpending = 0;
    switch (vcode & 0x0F) {
    case 0: v = vram[(vaddr & 0xFFFE) >> 1]; break;
    case 4: v = vsram[((vaddr >> 1) & 63) < 40 ? (vaddr >> 1) & 63 : 0]; break;
    case 8: v = cram[(vaddr >> 1) & 63]; break;
    case 12: v = vram_rb(vaddr ^ 1); break;
    }
    vaddr = (u16)(vaddr + reg[15]);
    return v;
}

static void reg_write(u32 r, u8 v)
{
    if (r >= 24)
        return;
    reg[r] = v;
    if (r <= 1)
        irq_update();
    if (r == 1 || r == 5 || r == 12)
        spr_dirty = 1;
}

static void control_write(u16 v)
{
    if (vpending) {
        vpending = 0;
        vcode = (u8)((vcode & 0x03) | ((v >> 2) & 0x3C));
        vaddr = (u16)((vaddr & 0x3FFF) | (v & 3) << 14);
        if ((vcode & 0x20) && (reg[1] & 0x10))
            dma_start();
        return;
    }
    if ((v & 0xC000) == 0x8000) {
        reg_write((v >> 8) & 0x1F, (u8)v);
        return;
    }
    vpending = 1;
    vcode = (u8)((vcode & 0x3C) | (v >> 14));
    vaddr = (u16)((vaddr & 0xC000) | (v & 0x3FFF));
}

/* ---- the YM2612 and the PSG (the sound: see their part below) ---- */
static void ym_write(u32 port, u8 v, u32 mclk);
static u8 ym_status(u32 mclk);
static u8 z_status(struct z80 *c);
static void ym_reset(void);
static void psg_write(u8 v, u32 mclk);
static void psg_reset(void);

/* ---- the Z80 ---- */
static int z_running(void)
{
    return !z_reset && !z_busreq;
}

/* the Z80 up to its time `to` (cycles of the frame); up to the 68000's time t */
static s32 z_until;

static void z_catch_up_z(s32 to)
{
    z_until = to;
    if (z_running())
        z80_run(&z, to);
    else if (z.cycles < to)
        z.cycles = to;
}

static void z_catch_up(s32 t)
{
    z_catch_up_z(t * 7 / 15);
}

static u8 bus_byte(u32 a)               /* the 68000's bus as the Z80's window reads it */
{
    a &= 0xFFFFFF;
    const u8 *p = rmap[a >> 16];
    if (p)
        return p[(a & 0xFFFF) ^ 1];
    if (addon && a < 0x800000)
        return (u8)addon->io_read(a, 1, m.clock);
    return 0xFF;
}

static u8 z_read(struct z80 *c, u16 a)
{
    if (a >= 0x8000)
        return bus_byte(z_bank | (a & 0x7FFF));
    if (a < 0x6000)
        return z_status(c);
    if ((a & 0xFFF0) == 0x7F00 && (a & 0x0C) == 0x08) {        /* the VDP's HV counter */
        u16 hv = hv_read();
        return (u8)((a & 1) ? hv : hv >> 8);
    }
    return 0xFF;
}

static void z_write(struct z80 *c, u16 a, u8 v)
{
    if (a >= 0x8000) {
        u32 at = z_bank | (a & 0x7FFF);
        u8 *p = wmap[(at >> 16) & 0xFF];
        if (p)
            p[(at & 0xFFFF) ^ 1] = v;
        return;
    }
    if (a < 0x6000) {
        ym_write(a & 3, v, (u32)c->cycles * 15);
        return;
    }
    if (a < 0x6100) {
        z_bank = ((z_bank >> 1) | (u32)(v & 1) << 23) & 0xFF8000u;
        return;
    }
    if ((a & 0xFFF8) == 0x7F10 && (a & 1))
        psg_write(v, (u32)c->cycles * 15);
}

static u8 z_in(struct z80 *c, u16 port)
{
    (void)c;
    (void)port;
    return 0xFF;
}

static void z_out(struct z80 *c, u16 port, u8 v)
{
    (void)c;
    (void)port;
    (void)v;
}

static void z_map(void)
{
    for (int i = 0; i < 64; i++)
        z.rd[i] = z.wr[i] = 0;
    for (int i = 0; i < 16; i++)
        z.rd[i] = z.wr[i] = zram + ((i & 7) << 10);
}

static void z_set_reset(int held)
{
    if (held && !z_reset) {
        z80_reset(&z);
        ym_reset();
    }
    z_reset = (u8)held;
}

/* ---- the pads ---- */
static u32 now68(void)
{
    return cycles_hi + (u32)m.clock;
}

static u8 pad_read(int port)
{
    u8 ctl = io_ctrl[port], dat = io_data[port];
    if (port == 2)
        return (u8)((dat & ctl) | (0x7F & ~ctl));
    u32 p = pads[port];
    int th = (ctl & 0x40) || !ctl ? (dat & 0x40) != 0 : 1;   /* (TH never made an output: as one anyway) */
    if (six && now68() - th_time[port] > TH_TIMEOUT)
        th_count[port] = 0;
    u32 n = six ? th_count[port] : 0, in;
    if (th) {
        in = 0x40 | ((p & MD_C) ? 0 : 0x20) | ((p & MD_B) ? 0 : 0x10);
        if (n == 6)
            in |= ((p & MD_MODE) ? 0 : 8) | ((p & MD_X) ? 0 : 4) | ((p & MD_Y) ? 0 : 2) | ((p & MD_Z) ? 0 : 1);
        else
            in |= ((p & MD_RIGHT) ? 0 : 8) | ((p & MD_LEFT) ? 0 : 4) | ((p & MD_DOWN) ? 0 : 2) |
                  ((p & MD_UP) ? 0 : 1);
    } else {
        in = ((p & MD_START) ? 0 : 0x20) | ((p & MD_A) ? 0 : 0x10);
        if (n == 7)
            in |= 0x0F;
        else if (n != 5)
            in |= ((p & MD_DOWN) ? 0 : 2) | ((p & MD_UP) ? 0 : 1);
    }
    return (u8)((dat & 0x80) | (((dat & ctl) | (in & ~ctl)) & 0x7F));
}

static void pad_write(int port, u8 v)
{
    if (port < 2) {
        u8 out = (io_ctrl[port] & 0x40) || !io_ctrl[port];
        u8 th_was = out ? io_data[port] & 0x40 : 0x40, th_now = out ? v & 0x40 : 0x40;
        if (th_was != th_now) {
            if (now68() - th_time[port] > TH_TIMEOUT)
                th_count[port] = 0;
            th_count[port] = (u8)((th_count[port] + 1) & 7);
            th_time[port] = now68();
        }
    }
    io_data[port] = v;
}

static void ctrl_write(int port, u8 v)
{
    io_ctrl[port] = v;
}

/* ---- the 68000's bus: what is not memory ---- */
static void map_memory(void);

static u32 io_read(u32 a, int size)
{
    u32 page = a >> 16;
    if (page >= 0xC0 && page < 0xE0) {
        if ((a & 0x0700E0) != 0)
            return 0;
        u32 r = a & 0x1F;
        u16 v = r < 4 ? data_read() : r < 8 ? status_read() : r < 0x10 ? hv_read() : 0xFFFF;
        return size == 1 ? ((a & 1) ? v & 0xFFu : (u32)v >> 8) : v;
    }
    if (page == 0xA0) {                 /* the Z80's space */
        u32 o = a & 0xFFFF, v = 0xFF;
        z_catch_up(m.clock);
        if (o < 0x4000)
            v = zram[o & 0x1FFF];
        else if (o < 0x6000)
            v = ym_status((u32)m.clock * 7);
        return size == 1 ? v : v << 8 | v;
    }
    if (page == 0xA1) {
        u32 o = a & 0xFFFF, v = 0;
        if (o < 0x20) {
            u32 r = (o >> 1) & 15;
            if (r == 0)
                v = (overseas ? 0x80 : 0) | (pal ? 0x40 : 0) | (addon ? 0 : 0x20);
            else if (r <= 3)
                v = pad_read((int)r - 1);
            else if (r <= 6)
                v = io_ctrl[r - 4];
            else
                v = r == 7 || r == 10 || r == 13 ? 0xFF : 0;
            return size == 1 ? v : v << 8 | v;
        }
        if ((o & 0xFF00) == 0x1100) {   /* the bus request: 0 granted */
            v = (m.op & 0xFEFE) | (z_busreq ? 0 : 0x0101);
            return size == 1 ? ((a & 1) ? v & 0xFF : v >> 8) : v;
        }
        if (addon && o >= 0x2000)
            return addon->io_read(a, size, m.clock);
        if (protection == 1 && o == 0x3000)    /* (its protection register) */
            return 0x1C;
        return size == 1 ? 0xFF : 0xFFFF;
    }
    if (addon && page < 0xA0)
        return addon->io_read(a, size, m.clock);
    if (sram_kind && sram_on && a >= (sram_lo & ~1u) && a <= (sram_hi | 1u)) {
        u32 v;
        if (sram_kind == 3)
            v = size == 1 ? sram[(a - sram_lo) & 0xFFFF] : (u32)sram[(a - sram_lo) & 0xFFFF] << 8 |
                                                               sram[(a - sram_lo + 1) & 0xFFFF];
        else {
            u32 b = sram[((a - (sram_lo & ~1u)) >> 1) & 0xFFFF];
            v = size == 1 ? (((a & 1) == (sram_kind == 1)) ? b : 0xFF) : sram_kind == 1 ? 0xFF00 | b : b << 8 | 0xFF;
        }
        return v;
    }
    return size == 1 ? 0xFF : 0xFFFF;
}

static void sram_write(u32 at, u8 v)
{
    at &= 0xFFFF;
    if (sram[at] != v) {
        sram[at] = v;
        sram_dirty = 1;
    }
}

static void io_write(u32 a, u32 v, int size)
{
    u32 page = a >> 16;
    if (page >= 0xC0 && page < 0xE0) {
        if ((a & 0x0700E0) != 0)
            return;
        u32 r = a & 0x1F;
        if (size == 1 && r < 8)
            v |= v << 8;
        if (r < 4)
            data_write((u16)v);
        else if (r < 8)
            control_write((u16)v);
        else if (r >= 0x10 && r < 0x18 && (size == 2 || (a & 1)))
            psg_write((u8)v, (u32)m.clock * 7);
        return;
    }
    if (page == 0xA0) {
        u32 o = a & 0xFFFF;
        u8 b = (u8)(size == 1 ? v : v >> 8);
        z_catch_up(m.clock);
        if (o < 0x4000)
            zram[o & 0x1FFF] = b;
        else if (o < 0x6000)
            ym_write(o & 3, b, (u32)m.clock * 7);
        else if (o < 0x6100)
            z_bank = ((z_bank >> 1) | (u32)(b & 1) << 23) & 0xFF8000u;
        else if ((o & 0xFFF8) == 0x7F10)
            psg_write((u8)v, (u32)m.clock * 7);
        return;
    }
    if (page == 0xA1) {
        u32 o = a & 0xFFFF;
        if (o < 0x20) {
            u32 r = (o >> 1) & 15;
            if (r >= 1 && r <= 3)
                pad_write((int)r - 1, (u8)v);
            else if (r >= 4 && r <= 6)
                ctrl_write((int)r - 4, (u8)v);
            return;
        }
        u32 bit = size == 1 ? ((a & 1) ? 0 : v & 1) : (v >> 8) & 1;
        if ((o & 0xFF00) == 0x1100) {
            z_catch_up(m.clock);
            z_busreq = (u8)bit;
        } else if ((o & 0xFF00) == 0x1200) {
            z_catch_up(m.clock);
            z_set_reset(!bit);
        } else if (addon && o >= 0x2000) {
            addon->io_write(a, v, size, m.clock);
        } else if (o == 0x30F1 || (o == 0x30F0 && size == 2)) {
            if (rom_size > 0x200000 && sram_kind) {
                sram_on = (u8)(v & 1);
                map_memory();
            }
        } else if (big && (o & 0xFFF1) == 0x30F1 && o > 0x30F1) {
            banks[(o - 0x30F1) >> 1] = (u8)v;
            map_memory();
        }
        return;
    }
    if (addon && page < 0xA0) {
        addon->io_write(a, v, size, m.clock);
        return;
    }
    if (sram_kind && sram_on && a >= (sram_lo & ~1u) && a <= (sram_hi | 1u)) {
        if (sram_kind == 3) {
            if (size == 1)
                sram_write(a - sram_lo, (u8)v);
            else {
                sram_write(a - sram_lo, (u8)(v >> 8));
                sram_write(a - sram_lo + 1, (u8)v);
            }
        } else if (size == 2 || (a & 1) == (sram_kind == 1)) {
            sram_write((a - (sram_lo & ~1u)) >> 1, (u8)(size == 2 && sram_kind == 2 ? v >> 8 : v));
        }
    }
}

static void cpu_reset_line(void)
{
}

/* the 68000's map: the cartridge (its banks, its RAM's pages left to io_read / io_write), the RAM */
static void map_memory(void)
{
    for (int i = 0; i < 256; i++)
        rmap[i] = wmap[i] = 0;
    if (addon) {
        addon->map(rmap, wmap);
        for (int i = 0xE0; i < 0x100; i++)
            rmap[i] = wmap[i] = (u8 *)ram;
        return;
    }
    for (u32 i = 0; i < 0x40; i++) {
        u32 p = big ? (u32)banks[i >> 3] * 8 + (i & 7) : i;
        if (p >= rom_pages) {           /* (a ROM of 2^n pages seen again; beyond the rest: nothing) */
            u32 n = 1;
            while (n < rom_pages)
                n <<= 1;
            p &= n - 1;
        }
        rmap[i] = p < rom_pages ? rom + (p << 16) : 0;
    }
    if (sram_kind && sram_on)
        for (u32 i = sram_lo >> 16; i <= sram_hi >> 16 && i < 0x40; i++)
            rmap[i] = 0;
    for (int i = 0xE0; i < 0x100; i++)
        rmap[i] = wmap[i] = (u8 *)ram;
}

/* ---- drawing ---- */
/* A line is drawn into a buffer of colour numbers (0-63), 0x40 marking a pixel of high priority: plane B first
   (its transparent pixels the background colour's number), then plane A or the window over it (an opaque pixel
   of theirs goes where it has high priority or what is there has not), then the sprites -- drawn into a buffer of
   their own, the first in the list in front, 0x80 marking a pixel taken -- over that by the same rule, then the
   colours.  In shadow / highlight mode each plane keeps a buffer of its own (a transparent pixel keeping its
   tile's priority bit, which decides the shadow) and they are put together pixel by pixel. */
#define MARGIN 32
static u8 line_a[MD_W_MAX + 2 * MARGIN], line_b[MD_W_MAX + 2 * MARGIN], line_s[MD_W_MAX + 2 * MARGIN];

enum { PUT, OVER, RAW };                /* plane B onto the line; A / the window over it; a plane as it is */

INLINE u32 mirrored(u32 px)             /* a pattern row's 8 pixels the other way round */
{
    px = (px >> 16) | (px << 16);
    px = ((px >> 8) & 0x00FF00FFu) | ((px & 0x00FF00FFu) << 8);
    return ((px >> 4) & 0x0F0F0F0Fu) | ((px & 0x0F0F0F0Fu) << 4);
}

INLINE void tile_row(u8 *to, u32 name, u32 px, int how, u8 bg)
{
    u8 base = (u8)((name >> 9) & 0x70), pri = base & 0x40;
    if (name & 0x800)
        px = mirrored(px);
    if (how == PUT) {
        for (int i = 0; i < 8; i++, px >>= 4) {
            u32 v = px & 15;
            to[i] = v ? (u8)(base | v) : bg;
        }
    } else if (how == OVER) {
        if (!px)
            return;
        if (pri) {
            for (int i = 0; i < 8; i++, px >>= 4)
                if (px & 15)
                    to[i] = (u8)(base | (px & 15));
        } else {
            for (int i = 0; i < 8; i++, px >>= 4)
                if ((px & 15) && !(to[i] & 0x40))
                    to[i] = (u8)(base | (px & 15));
        }
    } else {
        for (int i = 0; i < 8; i++, px >>= 4) {
            u32 v = px & 15;
            to[i] = v ? (u8)(base | v) : pri;
        }
    }
}

/* the row of a tile's pattern: (interlace mode 2: 16 rows a tile, y counted in its 448 lines) */
INLINE u32 pattern(u32 name, u32 y, int im2)
{
    if (im2) {
        u32 r = (name & 0x1000) ? 15 - (y & 15) : y & 15;
        return pat[(((name & 0x3FF) << 4) | r) & 0x3FFF];
    }
    u32 r = (name & 0x1000) ? 7 - (y & 7) : y & 7;
    return pat[((name & 0x7FF) << 3) | r];
}

/* a plane's line: name table nt, scrolled by hs (to the right) and by vs[] (each 16-pixel column's, or vs[0]
   for all) */
INLINE void plane(u8 *to, u32 nt, u32 hs, const u16 *vs, int per_column, int y, int width, int im2, int how)
{
    static const u8 cells[4] = {32, 64, 32, 128};
    u32 w = cells[reg[16] & 3], h = cells[(reg[16] >> 4) & 3];
    if (w * h > 4096)
        h = 4096 / w;
    u32 wmask = w * 8 - 1, hmask = (h * 8 << im2) - 1, shift = im2 ? 4 : 3;
    u32 x0 = (0u - hs) & wmask;         /* the plane's x at the line's left */
    int sx = -(int)(x0 & 15);
    u32 col = (x0 >> 3) & ~1u;
    u32 yy = im2 ? (u32)y * 2 : (u32)y;
    u8 bg = reg[7] & 63;
    u32 ty = (yy + vs[0]) & hmask, rowbase = nt + (ty >> shift) * w * 2;
    for (; sx < width; sx += 16) {
        if (per_column) {
            int k = (sx + 15) >> 4;
            ty = (yy + vs[2 * (k < 20 ? k : 19)]) & hmask;
            rowbase = nt + (ty >> shift) * w * 2;
        }
        for (int t = 0; t < 2; t++, col++) {
            u32 name = vram[((rowbase + (col & (w - 1)) * 2) & 0xFFFF) >> 1];
            tile_row(to + MARGIN + sx + 8 * t, name, pattern(name, ty, im2), how, bg);
        }
    }
}

/* (one of each: the pixels' loops made for each way) */
static void plane_put(u8 *to, u32 nt, u32 hs, const u16 *vs, int per_column, int y, int width, int im2)
{
    plane(to, nt, hs, vs, per_column, y, width, im2, PUT);
}

static void plane_over(u8 *to, u32 nt, u32 hs, const u16 *vs, int per_column, int y, int width, int im2)
{
    plane(to, nt, hs, vs, per_column, y, width, im2, OVER);
}

static void plane_raw(u8 *to, u32 nt, u32 hs, const u16 *vs, int per_column, int y, int width, int im2)
{
    plane(to, nt, hs, vs, per_column, y, width, im2, RAW);
}

/* the window's cells from x0 to x1 (multiples of 16) of line y */
static void window(u8 *to, int x0, int x1, int y, int im2, int how)
{
    u32 nt = h40() ? (u32)(reg[3] & 0x3C) << 10 : (u32)(reg[3] & 0x3E) << 10, w = h40() ? 64 : 32;
    u32 yy = im2 ? (u32)y * 2 : (u32)y, row = nt + (yy >> (im2 ? 4 : 3)) * w * 2;
    for (int x = x0; x < x1; x += 8) {
        u32 name = vram[((row + (u32)(x >> 3) * 2) & 0xFFFF) >> 1];
        tile_row(to + MARGIN + x, name, pattern(name, yy, im2), how, 0);
    }
}

/* every line's sprites from the link list (as the chip finds them line by line) */
static void sprite_lines(int im2)
{
    int max = h40() ? 80 : 64, per_line = h40() ? 20 : 16, h = height();
    for (int y = 0; y < h; y++)
        spr_lines[y][0] = 0;
    for (int i = 0, k = 0; k < max; k++) {
        u16 sy = sat_cache[i * 2], sl = sat_cache[i * 2 + 1];
        int top = im2 ? (int)(sy & 0x3FF) - 256 : (int)(sy & 0x1FF) - 128;
        int bottom = top + (((sl >> 8) & 3) + 1) * (im2 ? 16 : 8);
        if (im2)
            top = (top + 1) >> 1, bottom = (bottom + 1) >> 1;
        if (top < 0)
            top = 0;
        if (bottom > h)
            bottom = h;
        for (int y = top; y < bottom; y++) {
            u8 *l = spr_lines[y];
            if (l[0] < per_line)
                l[++l[0]] = (u8)i;
            else
                l[0] = (u8)(per_line + 1);
        }
        i = sl & 0x7F;
        if (!i || i >= max)
            break;
    }
    spr_dirty = 0;
}

/* the sprites of line y into their buffer (cleared first when there are any), the first in the list in front;
   the flags.  How many there are on the line (0: the buffer not touched) */
static int sprites(u8 *to, int y, int width, int im2)
{
    int per_line = h40() ? 20 : 16, dots = width;
    u32 base = sat_base();
    if (spr_dirty)
        sprite_lines(im2);
    const u8 *list = spr_lines[y] + 1;
    int n = spr_lines[y][0], yy = im2 ? y * 2 : y;
    if (n > per_line) {
        spr_overflow = 1;
        n = per_line;
    }
    if (!n) {
        dot_overflow_before = 0;
        return 0;
    }
    for (int x = 0; x < width; x++)
        to[MARGIN + x] = 0;
    int masked = 0, nonzero = 0, overflow = 0;
    for (int j = 0; j < n && dots > 0; j++) {
        int i = list[j];
        u16 sy = sat_cache[i * 2], sl = sat_cache[i * 2 + 1];
        u32 name = vram[((base + (u32)i * 8 + 4) & 0xFFFF) >> 1];
        u32 xr = vram[((base + (u32)i * 8 + 6) & 0xFFFF) >> 1] & 0x1FF;
        int hc = ((sl >> 10) & 3) + 1, vc = ((sl >> 8) & 3) + 1;
        int wpx = hc * 8;
        if (!xr && (nonzero || dot_overflow_before))
            masked = 1;
        if (xr)
            nonzero = 1;
        if (wpx > dots) {
            wpx = dots;
            overflow = 1;
        }
        dots -= wpx;
        if (masked)
            continue;
        int top = im2 ? (int)(sy & 0x3FF) - 256 : (int)(sy & 0x1FF) - 128;
        int r = yy - top, rows = vc * (im2 ? 16 : 8);
        if (name & 0x1000)
            r = rows - 1 - r;
        int x = (int)xr - 128;
        u8 base_px = (u8)(0x80 | ((name >> 9) & 0x70));
        for (int c = 0; c * 8 < wpx; c++) {
            int at = x + c * 8;
            if (at <= -8 || at >= width)
                continue;
            int cc = (name & 0x800) ? hc - 1 - c : c;
            u32 px;
            if (im2)
                px = pat[(((((name & 0x3FF) + (u32)(cc * vc + (r >> 4))) & 0x3FF) << 4) | (u32)(r & 15)) & 0x3FFF];
            else
                px = pat[((((name & 0x7FF) + (u32)(cc * vc + (r >> 3))) & 0x7FF) << 3) | (u32)(r & 7)];
            if (!px)
                continue;
            if (name & 0x800)
                px = mirrored(px);
            u8 *d = to + MARGIN + at;
            for (int p = 0; p < 8; p++, px >>= 4) {
                u32 v = px & 15;
                if (!v)
                    continue;
                if (d[p] & 0x80)
                    spr_collision = 1;
                else
                    d[p] = (u8)(base_px | v);
            }
        }
    }
    dot_overflow_before = (u8)overflow;
    return n;
}

static void draw_line(int y)
{
    int width = h40() ? 320 : 256, out_w = pic_w;
    u16 *out = pic ? pic + y * out_w : scratch;
    u16 back = colour[0][reg[7] & 63];
    if (width > out_w)
        width = out_w;
    if (!(reg[1] & 0x40)) {             /* the picture switched off: the background colour */
        for (int x = 0; x < out_w; x++)
            out[x] = back;
        if (addon && addon->draw_line)
            addon->draw_line(y, out, width, back);
        return;
    }
    int im2 = (reg[12] & 0x06) == 0x06, sh = (reg[12] & 0x08) != 0;
    /* the horizontal scroll */
    u32 hb = (u32)(reg[13] & 0x3F) << 10;
    switch (reg[11] & 3) {
    case 1: hb += (u32)(y & 7) * 4; break;
    case 2: hb += (u32)(y & ~7) * 4; break;
    case 3: hb += (u32)y * 4; break;
    }
    u32 hs_a = vram[(hb & 0xFFFF) >> 1] & 0x3FF, hs_b = vram[((hb + 2) & 0xFFFF) >> 1] & 0x3FF;
    u32 nt_a = (u32)(reg[2] & 0x38) << 10, nt_b = (u32)(reg[4] & 7) << 13;
    int per_column = (reg[11] & 4) != 0;
    /* where the window is on this line (wx0 .. wx1) */
    int wy = (reg[18] & 0x1F) * 8;
    int win_line = (reg[18] & 0x80) ? y >= wy : y < wy;
    int wx0 = 0, wx1 = 0;
    if (win_line) {
        wx1 = width;
    } else {
        int hp = (reg[17] & 0x1F) * 16;
        if (hp > width)
            hp = width;
        if (reg[17] & 0x80)
            wx0 = hp, wx1 = width;
        else
            wx1 = hp;
    }
    u8 *l = line_b + MARGIN, *a = line_a + MARGIN, *s = line_s + MARGIN;
    if (!sh) {
        plane_put(line_b, nt_b, hs_b, vsram + 1, per_column, y, width, im2);
        if (wx1 <= wx0) {
            plane_over(line_b, nt_a, hs_a, vsram, per_column, y, width, im2);
        } else if (wx0 == 0 && wx1 >= width) {
            window(line_b, 0, width, y, im2, OVER);
        } else {                        /* (A and the window side by side: A's line made first) */
            plane_raw(line_a, nt_a, hs_a, vsram, per_column, y, width, im2);
            window(line_a, wx0, wx1, y, im2, RAW);
            for (int x = 0; x < width; x++) {
                u8 p = a[x];
                if ((p & 15) && ((p & 0x40) || !(l[x] & 0x40)))
                    l[x] = p;
            }
        }
        if (sprites(line_s, y, width, im2))
            for (int x = 0; x < width; x++) {
                u8 p = s[x];
                if ((p & 15) && ((p & 0x40) || !(l[x] & 0x40)))
                    l[x] = p;
            }
        const u16 *c = colour[0];
        for (int x = 0; x < width; x++)
            out[x] = c[l[x] & 63];
    } else {                            /* shadow / highlight */
        u8 *b = l;
        plane_raw(line_b, nt_b, hs_b, vsram + 1, per_column, y, width, im2);
        if (wx0 > 0 || wx1 < width)
            plane_raw(line_a, nt_a, hs_a, vsram, per_column, y, width, im2);
        if (wx1 > wx0)
            window(line_a, wx0, wx1, y, im2, RAW);
        int any = sprites(line_s, y, width, im2);
        u8 bg = reg[7] & 63;
        for (int x = 0; x < width; x++) {
            u8 pa = a[x], pb = b[x], ps = any ? s[x] : 0, p;
            int shadow = !((pa | pb) & 0x40);
            if ((pa & 0x4F) > 0x40)
                p = pa;
            else if ((pb & 0x4F) > 0x40)
                p = pb;
            else if (pa & 15)
                p = pa;
            else if (pb & 15)
                p = pb;
            else
                p = bg;
            u16 v;
            if ((ps & 15) && ((ps & 0x40) || (p & 0x4F) <= 0x40)) {
                u32 si = ps & 63;
                if (si == 62)
                    v = colour[shadow ? 0 : 2][p & 63];
                else if (si == 63)
                    v = colour[1][p & 63];
                else if ((si & 15) == 14 || (ps & 0x40) || !shadow)
                    v = colour[0][si];
                else
                    v = colour[1][si];
            } else {
                v = colour[shadow][p & 63];
            }
            out[x] = v;
        }
    }
    if (reg[0] & 0x20)                  /* the left column blanked */
        for (int x = 0; x < 8; x++)
            out[x] = back;
    if (addon && addon->draw_line)
        addon->draw_line(y, out, width, back);
    for (int x = width; x < out_w; x++)
        out[x] = back;
}

/* ---- the frame ---- */
static s32 line_end(u32 l)              /* 68000 cycles of the frame at line l's end */
{
    return (s32)((l + 1) * LINE_MCLK / 7);
}

static void ym_run(u32 mclk);
static void ym_frame_end(u32 mclk);

static void run_line(u32 l, s32 to)
{
    run_until = to;
    cpu_run(to);
    if (addon)
        addon->run_line(m.clock);
    z_catch_up(to);
    (void)l;
}

void md_frame(u16 pad, u16 *picture)
{
    pads[0] = pad;
    pic = picture;
    pic_w = h40() ? 320 : 256;
    pic_h = height();
    dma_frame_left = DMA_FRAME_MAX;
    int h = pic_h;
    for (line = 0; line < lines; line++) {
        line_start = (s32)(line * LINE_MCLK / 7);
        if (line == 0) {
            in_vblank = 0;
            odd_frame = (reg[12] & 2) ? odd_frame ^ 1 : 0;
        }
        if (addon && addon->scanline)
            addon->scanline((int)line, h);
        if ((int)line <= h) {
            if (--hcounter < 0) {
                hcounter = reg[10];
                hint_pending = 1;
                irq_update();
            }
        } else {
            hcounter = reg[10];
        }
        if ((int)line < h && (int)line < pic_h)
            draw_line((int)line);
        if ((int)line == h) {
            in_vblank = 1;
            run_line(line, line_start + VINT_DELAY);
            vint_pending = 1;
            irq_update();
            z.irq = 1;
            run_until = line_end(line);
            cpu_run(run_until);
            if (addon)
                addon->run_line(m.clock);
            z_catch_up_z((line_start + VINT_DELAY) * 7 / 15 + Z80_INT_LENGTH);
            z.irq = 0;
        }
        run_line(line, line_end(line));
        ym_run(line * LINE_MCLK + LINE_MCLK);
    }
    s32 frame = line_end(lines - 1);
    if (addon)
        addon->end_frame(frame);
    m.clock -= frame;
    z.cycles -= (s32)(lines * Z80_LINE);
    dma_busy_until = dma_busy_until > frame ? dma_busy_until - frame : 0;
    cycles_hi += (u32)frame;
    ym_frame_end(lines * LINE_MCLK);
    line = 0;
}

/* ===================== the sound ===================== */
/* The YM2612: MCLK / 7, a sample every 144 of its clocks (1008 master clocks: 53267 a second on NTSC).  Its
   timers A (1024 - NA samples) and B (16 x (256 - NB)) count, set their flags and reload whether sound is made or
   not (sound drivers poll them); the busy flag is never set.

   The synthesis, when the host asks for sound (md_audio_rate), at the chip's own rate: six channels of four
   operators -- each a 20-bit phase counter ((F-number << block) / 2, detune, multiple), a quarter sine of
   log-attenuations and a table of powers of two (as the chip makes its 14-bit output), modulation by the
   operators before it in the channel's algorithm (8 of them) and operator 1's feedback; the envelope
   generator (attack, decay, sustain, release; rates with key scaling, stepped every 3 samples by the chip's
   increment patterns; total level, sustain level); the LFO's amplitude and (approximately) frequency
   modulation; channel 3's own frequencies per operator; the DAC in place of channel 6; the left / right
   switches (both off: the channel silent; the sound is mono).  Not there: SSG-EG, CSM (channel 3 keyed by
   timer A), the 9-bit DAC's distortion ("ladder effect").

   The PSG (SN76489, MCLK / 15 / 16): three square waves and the noise (white: bits 0 and 3 of a 16-bit LFSR;
   periodic), 2 dB volume steps.  Both are mixed at the YM2612's rate and taken to the host's rate by keeping
   the newest sample (the averaging of two when two fall in one), then a first-order low-pass at about 10 kHz
   and a high-pass at 45 Hz (the PSG's levels are all above 0). */
#define YM_SAMPLE 1008                  /* master clocks */
#ifndef YM_STEP
#define YM_STEP   2                     /* the FM operators worked out every 2nd sample (26.6 kHz, above the 10 kHz
                                           low-pass after them): on the box the chip's full rate took 6.4 ms of the
                                           16.7 ms frame (Super Mario World) -- too much; envelopes, the LFO, the
                                           timers, the DAC and the PSG keep the full rate.  (-DYM_STEP=1: exact) */
#endif
#define RING      4096u                 /* samples kept for the host */

static const u16 logsin[256] = {
    2137, 1731, 1543, 1419, 1326, 1252, 1190, 1137, 1091, 1050, 1013, 979, 949, 920, 894, 869, 846, 825, 804, 785,
    767, 749, 732, 717, 701, 687, 672, 659, 646, 633, 621, 609, 598, 587, 576, 566, 556, 546, 536, 527, 518, 509,
    501, 492, 484, 476, 468, 461, 453, 446, 439, 432, 425, 418, 411, 405, 399, 392, 386, 380, 375, 369, 363, 358,
    352, 347, 341, 336, 331, 326, 321, 316, 311, 307, 302, 297, 293, 289, 284, 280, 276, 271, 267, 263, 259, 255,
    251, 248, 244, 240, 236, 233, 229, 226, 222, 219, 215, 212, 209, 205, 202, 199, 196, 193, 190, 187, 184, 181,
    178, 175, 172, 169, 167, 164, 161, 159, 156, 153, 151, 148, 146, 143, 141, 138, 136, 134, 131, 129, 127, 125,
    122, 120, 118, 116, 114, 112, 110, 108, 106, 104, 102, 100, 98, 96, 94, 92, 91, 89, 87, 85, 83, 82, 80, 78, 77,
    75, 74, 72, 70, 69, 67, 66, 64, 63, 62, 60, 59, 57, 56, 55, 53, 52, 51, 49, 48, 47, 46, 45, 43, 42, 41, 40, 39,
    38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 23, 22, 21, 20, 20, 19, 18, 17, 17, 16, 15, 15,
    14, 13, 13, 12, 12, 11, 10, 10, 9, 9, 8, 8, 7, 7, 7, 6, 6, 5, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1, 1,
    1, 1, 0, 0, 0, 0, 0, 0, 0, 0,
};                                      /* -log2(sin((i + 0.5) pi / 512)) x 256 */
static const u16 exp2_table[256] = {
    2042, 2037, 2031, 2026, 2020, 2015, 2010, 2004, 1999, 1993, 1988, 1983, 1977, 1972, 1966, 1961, 1956, 1951,
    1945, 1940, 1935, 1930, 1924, 1919, 1914, 1909, 1904, 1898, 1893, 1888, 1883, 1878, 1873, 1868, 1863, 1858,
    1853, 1848, 1843, 1838, 1833, 1828, 1823, 1818, 1813, 1808, 1803, 1798, 1794, 1789, 1784, 1779, 1774, 1769,
    1765, 1760, 1755, 1750, 1746, 1741, 1736, 1732, 1727, 1722, 1717, 1713, 1708, 1704, 1699, 1694, 1690, 1685,
    1681, 1676, 1672, 1667, 1663, 1658, 1654, 1649, 1645, 1640, 1636, 1631, 1627, 1623, 1618, 1614, 1609, 1605,
    1601, 1596, 1592, 1588, 1584, 1579, 1575, 1571, 1566, 1562, 1558, 1554, 1550, 1545, 1541, 1537, 1533, 1529,
    1525, 1520, 1516, 1512, 1508, 1504, 1500, 1496, 1492, 1488, 1484, 1480, 1476, 1472, 1468, 1464, 1460, 1456,
    1452, 1448, 1444, 1440, 1436, 1433, 1429, 1425, 1421, 1417, 1413, 1409, 1406, 1402, 1398, 1394, 1391, 1387,
    1383, 1379, 1376, 1372, 1368, 1364, 1361, 1357, 1353, 1350, 1346, 1342, 1339, 1335, 1332, 1328, 1324, 1321,
    1317, 1314, 1310, 1307, 1303, 1300, 1296, 1292, 1289, 1286, 1282, 1279, 1275, 1272, 1268, 1265, 1261, 1258,
    1255, 1251, 1248, 1244, 1241, 1238, 1234, 1231, 1228, 1224, 1221, 1218, 1214, 1211, 1208, 1205, 1201, 1198,
    1195, 1192, 1188, 1185, 1182, 1179, 1176, 1172, 1169, 1166, 1163, 1160, 1157, 1154, 1150, 1147, 1144, 1141,
    1138, 1135, 1132, 1129, 1126, 1123, 1120, 1117, 1114, 1111, 1108, 1105, 1102, 1099, 1096, 1093, 1090, 1087,
    1084, 1081, 1078, 1075, 1072, 1069, 1066, 1064, 1061, 1058, 1055, 1052, 1049, 1046, 1044, 1041, 1038, 1035,
    1032, 1030, 1027, 1024,
};                                      /* 2^(-(i + 1) / 256) x 2048 */
/* the detune (the YM2612's table: by DT 1-3 and the key code), added to the phase increment */
static const u8 detune[3][32] = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 6, 6, 7},
    {1, 1, 1, 1, 2, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 6, 6, 7, 8, 8, 9, 10, 11, 12, 13, 14, 16, 16, 16, 16},
    {2, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 6, 6, 7, 8, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 20, 22, 22, 22, 22},
};
/* the envelope's steps: for rates 0-47 by rate & 3 (each 2^(11 - rate / 4) ticks), then rates 48-63 */
static const u8 eg_steps[4 + 16][8] = {
    {0, 1, 0, 1, 0, 1, 0, 1}, {0, 1, 0, 1, 1, 1, 0, 1}, {0, 1, 1, 1, 0, 1, 1, 1}, {0, 1, 1, 1, 1, 1, 1, 1},
    {1, 1, 1, 1, 1, 1, 1, 1}, {1, 1, 1, 2, 1, 1, 1, 2}, {1, 2, 1, 2, 1, 2, 1, 2}, {1, 2, 2, 2, 1, 2, 2, 2},
    {2, 2, 2, 2, 2, 2, 2, 2}, {2, 2, 2, 4, 2, 2, 2, 4}, {2, 4, 2, 4, 2, 4, 2, 4}, {2, 4, 4, 4, 2, 4, 4, 4},
    {4, 4, 4, 4, 4, 4, 4, 4}, {4, 4, 4, 8, 4, 4, 4, 8}, {4, 8, 4, 8, 4, 8, 4, 8}, {4, 8, 8, 8, 4, 8, 8, 8},
    {8, 8, 8, 8, 8, 8, 8, 8}, {8, 8, 8, 8, 8, 8, 8, 8}, {8, 8, 8, 8, 8, 8, 8, 8}, {8, 8, 8, 8, 8, 8, 8, 8},
};
static const u8 lfo_period[8] = {108, 77, 71, 67, 62, 44, 8, 5};        /* samples a step (128 steps a cycle) */
static const u8 ams_shift[4] = {8, 3, 1, 0};
static const u16 pm_depth[8] = {0, 18, 36, 54, 76, 109, 219, 443};      /* 2^(cents / 1200) - 1, x 65536 / 7 */
static const s8 pm_wave[32] = {0, 1, 2, 3, 4, 5, 6, 7, 7, 6, 5, 4, 3, 2, 1, 0,
                               0, -1, -2, -3, -4, -5, -6, -7, -7, -6, -5, -4, -3, -2, -1, 0};
static const u16 psg_volume[16] = {3400, 2701, 2145, 1704, 1354, 1075, 854, 678, 539, 428, 340, 270, 215, 170, 135, 0};

enum { ATTACK, DECAY, SUSTAIN, RELEASE };

struct op {
    u32 phase, inc;                     /* 20 bits; the increment a sample (without the LFO) */
    s32 att;                            /* the envelope: 0 (loudest) .. 1023 */
    u32 env;                            /* att + the total level (1023 at most) */
    u8 state, key;
    u8 dt, mul, tl, ks, ar, d1r, d2r, rr, sl, am;
    u8 rate[4];                         /* the rates of the states, key scaling added (0-63) */
    s32 out, out1;                      /* the output, the one before (operator 1's feedback) */
};

struct channel {
    struct op op[4];                    /* operators 1, 2, 3, 4 (the registers' order: 1, 3, 2, 4) */
    u16 fnum;
    u8 block, kc, alg, fb, ams, pms, on;
    u8 quiet;                           /* every operator released and silent */
    u16 fnum3[3];                       /* channel 3's own (operators 1, 2, 3) */
    u8 block3[3], kc3[3];
};

static struct {
    u8 regs[2][256];
    u8 addr[2];
    u8 status, mode;                    /* the flags; register 0x27 */
    s32 ta, tb;                         /* samples to the timers' overflows */
    u32 time;                           /* master clocks of the frame done */
    struct channel ch[6];
    u8 latch[2], latch3;                /* 0xA4-0xA6's, 0xAC-0xAE's high byte, waiting for the low one */
    u8 dac_on, lfo_on, lfo_freq, lfo_step;
    s32 dac;
    u32 lfo_count, eg_count, eg_div;
    u8 ch3;                             /* channel 3's mode (0x27's bits 6-7) as the synthesis has got to it */
    u32 step_count;                     /* samples since the FM channels were last worked out (YM_STEP) */
    s32 fm;                             /* their sum then */
} ym;

static struct {
    u16 period[4];
    u8 volume[4], latch;
    s32 count[4];                       /* master clocks to the next flip */
    u8 high[4];                         /* the output's level */
    u16 lfsr;
} psg;

static struct {
    u32 rate;                           /* the host's samples a second (0: none made) */
    u32 step, acc;                      /* the YM2612's rate and the host's, in a phase accumulator */
    s32 sum, n, lp, lp_was, hp;
    s16 ring[RING];
    u32 head, tail;
} snd;

/* ---- the timers ---- */
static void ym_timers(u32 n)
{
    if (ym.mode & 1) {
        ym.ta -= (s32)n;
        if (ym.ta <= 0) {
            s32 period = 1024 - (ym.regs[0][0x24] << 2 | (ym.regs[0][0x25] & 3));
            while (ym.ta <= 0)
                ym.ta += period;
            if (ym.mode & 4)
                ym.status |= 1;
        }
    }
    if (ym.mode & 2) {
        ym.tb -= (s32)n;
        if (ym.tb <= 0) {
            s32 period = 16 * (256 - ym.regs[0][0x26]);
            while (ym.tb <= 0)
                ym.tb += period;
            if (ym.mode & 8)
                ym.status |= 2;
        }
    }
}

/* ---- the operators ---- */
static void op_update(struct channel *c, int n)    /* an operator's increment and rates from its registers */
{
    struct op *o = &c->op[n];
    u32 fnum = c->fnum, block = c->block, kc = c->kc;
    if (c == &ym.ch[2] && ym.ch3 && n < 3) {
        static const u8 which[3] = {1, 2, 0};   /* operator 1: 0xA9, 2: 0xAA, 3: 0xA8 */
        fnum = c->fnum3[which[n]], block = c->block3[which[n]], kc = c->kc3[which[n]];
    }
    s32 inc = (s32)((fnum << block) >> 1);
    if (o->dt & 3) {
        s32 d = detune[(o->dt & 3) - 1][kc];
        inc += (o->dt & 4) ? -d : d;
    }
    inc &= 0x1FFFF;
    o->inc = (o->mul ? (u32)inc * o->mul : (u32)inc >> 1) & 0xFFFFF;
    u32 ksr = kc >> (3 - o->ks);
    u32 r[4] = {o->ar ? 2u * o->ar + ksr : 0, o->d1r ? 2u * o->d1r + ksr : 0, o->d2r ? 2u * o->d2r + ksr : 0,
                2u * o->rr + 1 + ksr};
    for (int i = 0; i < 4; i++)
        o->rate[i] = (u8)(r[i] > 63 ? 63 : r[i]);
}

static void op_env(struct op *o)
{
    u32 e = (u32)o->att + ((u32)o->tl << 3);
    o->env = e > 0x3FF ? 0x3FF : e;
}

static void key(struct channel *c, int n, int on)
{
    struct op *o = &c->op[n];
    if (on && !o->key) {
        o->phase = 0;
        o->state = ATTACK;
        if (o->rate[ATTACK] >= 62)
            o->att = 0, o->state = DECAY;
        op_env(o);
        c->quiet = 0;
    } else if (!on && o->key) {
        o->state = RELEASE;
    }
    o->key = (u8)on;
}

static u8 key_code(u32 fnum, u32 block)
{
    u32 f11 = (fnum >> 10) & 1, f10 = (fnum >> 9) & 1, f9 = (fnum >> 8) & 1, f8 = (fnum >> 7) & 1;
    return (u8)(block << 2 | f11 << 1 | ((f11 & (f10 | f9 | f8)) | ((f11 ^ 1) & f10 & f9 & f8)));
}

static void ym_reg(int part, u32 r, u8 v)
{
    if (r < 0x30) {
        if (part)
            return;
        switch (r) {
        case 0x22:
            ym.lfo_on = (v >> 3) & 1;
            ym.lfo_freq = v & 7;
            if (!ym.lfo_on)
                ym.lfo_step = 0, ym.lfo_count = 0;
            break;
        case 0x27:                      /* (channel 3's mode: its operators' frequencies) */
            ym.ch3 = v & 0xC0;
            for (int n = 0; n < 3; n++)
                op_update(&ym.ch[2], n);
            break;
        case 0x28: {
            int ch = v & 3;
            if (ch == 3)
                break;
            ch += (v & 4) ? 3 : 0;
            for (int n = 0; n < 4; n++)
                key(&ym.ch[ch], n, (v >> (4 + n)) & 1);
            break;
        }
        case 0x2A: ym.dac = ((s32)v - 128) << 6; break;
        case 0x2B: ym.dac_on = v >> 7; break;
        }
        return;
    }
    int ch = (int)(r & 3);
    if (ch == 3)
        return;
    struct channel *c = &ym.ch[ch + 3 * part];
    if (r < 0xA0) {
        static const u8 slot[4] = {0, 2, 1, 3};
        int n = slot[(r >> 2) & 3];
        struct op *o = &c->op[n];
        switch (r & 0xF0) {
        case 0x30: o->dt = (v >> 4) & 7; o->mul = v & 15; break;
        case 0x40: o->tl = v & 0x7F; op_env(o); break;
        case 0x50: o->ks = v >> 6; o->ar = v & 31; break;
        case 0x60: o->am = v >> 7; o->d1r = v & 31; break;
        case 0x70: o->d2r = v & 31; break;
        case 0x80: o->sl = v >> 4; o->rr = v & 15; break;
        }
        op_update(c, n);
        return;
    }
    switch (r & 0xFC) {
    case 0xA0:
        c->fnum = (u16)((ym.latch[part] & 7) << 8 | v);
        c->block = (ym.latch[part] >> 3) & 7;
        c->kc = key_code(c->fnum, c->block);
        for (int n = 0; n < 4; n++)
            op_update(c, n);
        break;
    case 0xA4: ym.latch[part] = v; break;
    case 0xA8:
        if (!part) {
            struct channel *c3 = &ym.ch[2];
            c3->fnum3[ch] = (u16)((ym.latch3 & 7) << 8 | v);
            c3->block3[ch] = (ym.latch3 >> 3) & 7;
            c3->kc3[ch] = key_code(c3->fnum3[ch], c3->block3[ch]);
            for (int n = 0; n < 3; n++)
                op_update(c3, n);
        }
        break;
    case 0xAC: if (!part) ym.latch3 = v; break;
    case 0xB0: c->alg = v & 7; c->fb = (v >> 3) & 7; break;
    case 0xB4: c->on = (v & 0xC0) != 0; c->ams = (v >> 4) & 3; c->pms = v & 7; break;
    }
}

/* the envelope generator's tick (every 3 samples) */
static void eg_tick(void)
{
    u32 t = ++ym.eg_count;
    for (int ch = 0; ch < 6; ch++) {
        struct channel *c = &ym.ch[ch];
        if (c->quiet)
            continue;
        int quiet = 1;
        for (int n = 0; n < 4; n++) {
            struct op *o = &c->op[n];
            if (o->state == RELEASE && o->att >= 0x3FF)
                continue;
            quiet = 0;
            u32 rate = o->rate[o->state];
            if (rate < 2)
                continue;
            u32 inc;
            if (rate < 48) {
                u32 shift = 11 - (rate >> 2);
                if (t & ((1u << shift) - 1))
                    continue;
                inc = eg_steps[rate & 3][(t >> shift) & 7];
            } else {
                inc = eg_steps[rate - 44][t & 7];
            }
            if (o->state == ATTACK) {
                if (rate < 62)
                    o->att += (~o->att * (s32)inc) >> 4;
                if (o->att <= 0 || rate >= 62) {
                    o->att = 0;
                    o->state = DECAY;
                }
            } else {
                o->att += (s32)inc;
                if (o->att > 0x3FF)
                    o->att = 0x3FF;
                if (o->state == DECAY && o->att >= (o->sl == 15 ? 0x3E0 : o->sl << 5))
                    o->state = SUSTAIN;
            }
            op_env(o);
        }
        c->quiet = (u8)quiet;
    }
}

/* an operator's output (14 bits, signed): its phase moved by `mod` (in 1/1024 of a turn) */
INLINE s32 op_out(struct op *o, s32 mod, u32 am)
{
    u32 env = o->env + (o->am ? am : 0);
    if (env >= 0x3FF)
        return 0;
    u32 p = ((o->phase >> 10) + (u32)mod) & 0x3FF;
    u32 i = (p & 0x100) ? ~p & 0xFF : p & 0xFF;
    u32 a = logsin[i] + (env << 2);
    s32 v = a >= 0x1A00 ? 0 : (s32)(((u32)exp2_table[a & 0xFF] << 2) >> (a >> 8));
    return (p & 0x200) ? -v : v;
}

/* the channel's output after `steps` samples of the chip (its operators' phases moved on that many increments;
   2: the operators worked out at half the chip's rate, the box's budget -- see YM_STEP) */
static s32 channel_out(struct channel *c, u32 am_lfo, s32 pm, u32 steps)
{
    struct op *o = c->op;
    if (c->quiet)
        return 0;
    u32 am = am_lfo >> ams_shift[c->ams];
    for (int n = 0; n < 4; n++) {
        u32 inc = o[n].inc;
        if (pm && c->pms)
            inc += (u32)(((s32)(inc >> 4) * pm * (s32)pm_depth[c->pms]) >> 12);
        o[n].phase = (o[n].phase + inc * steps) & 0xFFFFF;
    }
    s32 fb = c->fb ? (o[0].out + o[0].out1) >> (10 - c->fb) : 0;
    o[0].out1 = o[0].out;
    s32 s1 = o[0].out = op_out(&o[0], fb, am), s2, s3, out;
    switch (c->alg) {
    case 0:
        s2 = op_out(&o[1], s1 >> 1, am);
        s3 = op_out(&o[2], s2 >> 1, am);
        out = op_out(&o[3], s3 >> 1, am);
        break;
    case 1:
        s2 = op_out(&o[1], 0, am);
        s3 = op_out(&o[2], (s1 + s2) >> 1, am);
        out = op_out(&o[3], s3 >> 1, am);
        break;
    case 2:
        s2 = op_out(&o[1], 0, am);
        s3 = op_out(&o[2], s2 >> 1, am);
        out = op_out(&o[3], (s1 + s3) >> 1, am);
        break;
    case 3:
        s2 = op_out(&o[1], s1 >> 1, am);
        s3 = op_out(&o[2], 0, am);
        out = op_out(&o[3], (s2 + s3) >> 1, am);
        break;
    case 4:
        s3 = op_out(&o[2], 0, am);
        out = op_out(&o[1], s1 >> 1, am) + op_out(&o[3], s3 >> 1, am);
        break;
    case 5:
        out = op_out(&o[1], s1 >> 1, am) + op_out(&o[2], s1 >> 1, am) + op_out(&o[3], s1 >> 1, am);
        break;
    case 6:
        out = op_out(&o[1], s1 >> 1, am) + op_out(&o[2], 0, am) + op_out(&o[3], 0, am);
        break;
    default:
        out = s1 + op_out(&o[1], 0, am) + op_out(&o[2], 0, am) + op_out(&o[3], 0, am);
        break;
    }
    if (out > 8191)
        out = 8191;
    else if (out < -8192)
        out = -8192;
    return out >> 5;                    /* (9 bits, as the DAC takes it) */
}

/* the PSG over one of the YM2612's samples */
static s32 psg_sample(void)
{
    s32 out = 0;
    if ((psg.volume[0] & psg.volume[1] & psg.volume[2] & psg.volume[3]) == 15)
        return 0;                       /* (all four silent) */
    for (int i = 0; i < 4; i++) {
        u32 period;
        if (i < 3)
            period = psg.period[i];
        else
            period = (psg.latch & 3) == 3 ? psg.period[2] : 0x10u << (psg.latch & 3);
        if (i < 3 && period <= 1) {
            psg.high[i] = 1;            /* (a period of 0 or 1: held high -- samples played by volume) */
        } else {
            psg.count[i] -= YM_SAMPLE;
            while (psg.count[i] <= 0) {
                psg.count[i] += (s32)(period ? period : 0x400) * 240;
                if (i < 3) {
                    psg.high[i] ^= 1;
                } else {
                    psg.high[3] ^= 0x80;        /* (the LFSR shifts on every other flip) */
                    if (psg.high[3] & 0x80) {
                        u32 bit = (psg.latch & 4) ? (psg.lfsr ^ (psg.lfsr >> 3)) & 1 : psg.lfsr & 1;
                        psg.lfsr = (u16)(psg.lfsr >> 1 | bit << 15);
                        psg.high[3] = (u8)((psg.high[3] & 0x80) | (psg.lfsr & 1));
                    }
                }
            }
        }
        if (psg.high[i] & 1)
            out += psg_volume[psg.volume[i]];
    }
    return out;
}

static void ym_synth(u32 n)
{
    if (!snd.rate)
        return;
    while (n--) {
        /* the LFO */
        u32 am = 0;
        s32 pm = 0;
        if (ym.lfo_on) {
            if (++ym.lfo_count >= lfo_period[ym.lfo_freq]) {
                ym.lfo_count = 0;
                ym.lfo_step = (ym.lfo_step + 1) & 127;
            }
            am = ym.lfo_step < 64 ? (u32)ym.lfo_step * 2 : (u32)(127 - ym.lfo_step) * 2;
            pm = pm_wave[ym.lfo_step >> 2];
        }
        if (++ym.eg_div == 3) {
            ym.eg_div = 0;
            eg_tick();
        }
        /* the FM channels: worked out on every YM_STEP-th sample (their phases moved on by as many increments),
           kept in between; the DAC's sample is taken every sample */
        if (++ym.step_count >= YM_STEP) {
            ym.step_count = 0;
            s32 fm = 0;
            for (int ch = 0; ch < 6; ch++) {
                struct channel *c = &ym.ch[ch];
                if (c->on && !(ch == 5 && ym.dac_on))
                    fm += channel_out(c, am, pm, YM_STEP);
            }
            ym.fm = fm;
        }
        s32 fm = ym.fm;
        if (ym.dac_on && ym.ch[5].on)
            fm += ym.dac >> 5;
        s32 mix = fm * 32 + psg_sample();
        /* to the host's rate */
        snd.sum += mix;
        snd.n++;
        snd.acc += snd.rate;
        if (snd.acc >= snd.step) {
            snd.acc -= snd.step;
            s32 v = snd.n == 1 ? snd.sum : snd.n == 2 ? snd.sum >> 1 : snd.sum / snd.n;
            snd.sum = snd.n = 0;
            snd.lp += ((v << 8) - snd.lp) >> 1;         /* (about 10 kHz at 48 kHz) */
            snd.hp += snd.lp - snd.lp_was - (snd.hp >> 8) - (snd.hp >> 9);  /* (the PSG's offset away: 45 Hz) */
            snd.lp_was = snd.lp;
            v = snd.hp >> 8;
            if (v > 32767)
                v = 32767;
            else if (v < -32768)
                v = -32768;
            if (snd.head - snd.tail < RING)
                snd.ring[snd.head++ & (RING - 1)] = (s16)v;
        }
    }
}

static void ym_run(u32 mclk)
{
    if (mclk <= ym.time + YM_SAMPLE - 1)
        return;
    u32 n = (mclk - ym.time) / YM_SAMPLE;
    ym.time += n * YM_SAMPLE;
    ym_timers(n);
}

/* The sound itself is made apart from the timers: while it is made, the chips' writes are kept with their times
   and played back at the frame's end (or when the log is full) -- the synthesis up to each write's time, then the
   write -- in one go.  Made a few samples at a time after every line instead, between the 68000, the Z80 and the
   picture, its tables and state left the box's caches each time: 5.1 ms of the frame instead of 2.3 (Super Mario
   World).  A write is kept with the timers' time when it came (ym.time: where the sound made line by line would
   have got to -- the timers' clock is moved on by every status read too, and a Z80 write made after the 68000's
   line can carry an earlier time), and played back in the order made: the sound is the same, sample for sample,
   as made line by line.  Without sound (rate 0) a write is applied at once. */
#define WLOG 2048
static struct {
    u32 mclk;
    u8 part, reg, val;                  /* part 0 / 1: the YM2612's, 2: the PSG's (reg unused) */
} wlog[WLOG];
static u32 wlog_n, syn_time;            /* the writes kept; master clocks of the frame synthesized */

static void psg_apply(u8 v);

static void sound_apply(u32 part, u32 r, u8 v)
{
    if (part == 2)
        psg_apply(v);
    else
        ym_reg((int)part, r, v);
}

static void syn_to(u32 mclk)            /* the sound made up to mclk, the kept writes played back on the way */
{
    for (u32 i = 0; i <= wlog_n; i++) {
        u32 t = i < wlog_n ? wlog[i].mclk : mclk;
        if (t > syn_time + YM_SAMPLE - 1) {
            u32 n = (t - syn_time) / YM_SAMPLE;
            syn_time += n * YM_SAMPLE;
            ym_synth(n);
        }
        if (i < wlog_n)
            sound_apply(wlog[i].part, wlog[i].reg, wlog[i].val);
    }
    wlog_n = 0;
}

static void sound_write(u32 part, u32 r, u8 v, u32 mclk)
{
    if (!snd.rate) {
        sound_apply(part, r, v);
        return;
    }
    if (wlog_n == WLOG)
        syn_to(mclk);
    wlog[wlog_n].mclk = mclk;
    wlog[wlog_n].part = (u8)part;
    wlog[wlog_n].reg = (u8)r;
    wlog[wlog_n].val = v;
    wlog_n++;
}

static void ym_frame_end(u32 mclk)
{
    ym_run(mclk);
    if (snd.rate)
        syn_to(ym.time);                /* (ym.time: past mclk when the Z80 ran a little beyond the frame) */
    else
        syn_time = ym.time;
    ym.time = ym.time > mclk ? ym.time - mclk : 0;
    syn_time = syn_time > mclk ? syn_time - mclk : 0;
}

static u8 ym_status(u32 mclk)
{
    ym_run(mclk);
    return ym.status;
}

/* the YM2612's status read by the Z80.  Read again at the same place a little later, unchanged: a loop waiting
   for a timer (a sound driver's main loop) -- nothing else it can read changes during this run of the Z80 (the
   68000 touches its RAM between runs, its interrupt line holds still), so it goes on to just before a timer's
   flag comes up or the run ends; the loop sees what it would have seen, in fewer turns */
static u8 z_status(struct z80 *c)
{
    static u16 poll_pc;
    static s32 poll_at;
    static u8 poll_status;
    u8 st = ym_status((u32)c->cycles * 15);
    s32 loop = c->cycles - poll_at;
    if (c->pc.w == poll_pc && st == poll_status && loop > 0 && loop < 1200) {
        s32 next = z_until;
        if ((ym.mode & 5) == 5 && !(st & 1)) {
            s32 t = (s32)((ym.time + (u32)ym.ta * YM_SAMPLE) / 15) + 1;
            if (t < next)
                next = t;
        }
        if ((ym.mode & 10) == 10 && !(st & 2)) {
            s32 t = (s32)((ym.time + (u32)ym.tb * YM_SAMPLE) / 15) + 1;
            if (t < next)
                next = t;
        }
        if (next - loop > c->cycles)
            c->cycles = next - loop;
    }
    poll_pc = c->pc.w;
    poll_at = c->cycles;
    poll_status = st;
    return st;
}

static void ym_write(u32 port, u8 v, u32 mclk)
{
    ym_run(mclk);
    int part = (port >> 1) & 1;
    if (!(port & 1)) {
        ym.addr[part] = v;
        return;
    }
    u32 r = ym.addr[part];
    if (!part && r >= 0x24 && r <= 0x27) {
        ym.regs[0][r] = v;
        if (r == 0x27) {
            if ((v & 1) && !(ym.mode & 1))
                ym.ta = 1024 - (ym.regs[0][0x24] << 2 | (ym.regs[0][0x25] & 3));
            if ((v & 2) && !(ym.mode & 2))
                ym.tb = 16 * (256 - ym.regs[0][0x26]);
            ym.status &= (u8)~((v >> 4) & 3);
            ym.mode = v;
        }
    }
    ym.regs[part][r] = v;
    sound_write((u32)part, r, v, ym.time);
}

static void ym_reset(void)
{
    if (snd.rate)                       /* (the sound up to now made with the chip as it was, its writes played) */
        syn_to(ym.time);
    u32 time = ym.time;
    u8 *p = (u8 *)&ym;
    for (u32 i = 0; i < sizeof(ym); i++)
        p[i] = 0;
    ym.time = time;
    if (!snd.rate)
        syn_time = time;
    for (int ch = 0; ch < 6; ch++) {
        ym.ch[ch].on = 1;               /* (left and right on at the reset) */
        ym.ch[ch].quiet = 1;
        for (int n = 0; n < 4; n++) {
            ym.ch[ch].op[n].att = 0x3FF;
            ym.ch[ch].op[n].env = 0x3FF;
            ym.ch[ch].op[n].state = RELEASE;
            op_update(&ym.ch[ch], n);
        }
    }
}

static void psg_write(u8 v, u32 mclk)
{
    ym_run(mclk);
    sound_write(2, 0, v, ym.time);
}

static void psg_apply(u8 v)
{
    if (v & 0x80) {
        psg.latch = v;
        u32 i = (v >> 5) & 3;
        if (v & 0x10)
            psg.volume[i] = v & 15;
        else if (i < 3)
            psg.period[i] = (u16)((psg.period[i] & 0x3F0) | (v & 15));
        else
            psg.lfsr = 0x8000;
        return;
    }
    u32 i = (psg.latch >> 5) & 3;
    if (psg.latch & 0x10)
        psg.volume[i] = v & 15;
    else if (i < 3)
        psg.period[i] = (u16)((psg.period[i] & 15) | (v & 0x3F) << 4);
    else
        psg.lfsr = 0x8000;
}

static void psg_reset(void)
{
    for (int i = 0; i < 4; i++) {
        psg.period[i] = 0, psg.volume[i] = 15, psg.count[i] = 0, psg.high[i] = 0;
    }
    psg.latch = 0x60;
    psg.lfsr = 0x8000;
}

void md_audio_rate(u32 hz)
{
    if (hz && hz < 8000)
        hz = 8000;
    if (hz > 192000)
        hz = 192000;
    for (u32 i = 0; i < wlog_n; i++)            /* (writes kept for a sound no longer made: applied) */
        sound_apply(wlog[i].part, wlog[i].reg, wlog[i].val);
    wlog_n = 0;
    syn_time = ym.time;
    snd.rate = hz;
    snd.step = (pal ? 53203424u : 53693175u) / YM_SAMPLE;      /* the YM2612's samples a second */
    snd.acc = 0, snd.sum = 0, snd.n = 0, snd.lp = snd.lp_was = snd.hp = 0;
    snd.head = snd.tail = 0;
}

int md_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && snd.tail != snd.head)
        out[n++] = snd.ring[snd.tail++ & (RING - 1)];
    if (addon && n > 0)
        addon->mix_audio(out, n, snd.rate);
    return n;
}

/* ===================== the outside ===================== */
static char *put(char *p, const char *s)
{
    while (*s && p < info + sizeof(info) - 1)
        *p++ = *s++;
    *p = 0;
    return p;
}

static char *put_number(char *p, u32 v)
{
    char d[12];
    int n = 0;
    do
        d[n++] = (char)('0' + v % 10);
    while (v /= 10);
    while (n && p < info + sizeof(info) - 1)
        *p++ = d[--n];
    *p = 0;
    return p;
}

static u32 be32(const u8 *p)
{
    return (u32)p[0] << 24 | (u32)p[1] << 16 | (u32)p[2] << 8 | p[3];
}

void md_reset(void)
{
    for (u32 i = 0; i < 0x8000; i++)
        ram[i] = 0;
    for (u32 i = 0; i < sizeof(zram); i++)
        zram[i] = 0;
    for (u32 i = 0; i < 0x8000; i++)
        vram[i] = 0;
    for (u32 i = 0; i < 0x4000; i++)
        pat[i] = 0;
    for (u32 i = 0; i < 64; i++) {
        cram_w(i, 0);
        vsram[i] = 0;
    }
    for (u32 i = 0; i < 160; i++)
        sat_cache[i] = 0;
    spr_dirty = 1;
    for (u32 i = 0; i < 32; i++)
        reg[i] = 0;
    vaddr = 0, vcode = 0, vpending = 0;
    vint_pending = hint_pending = spr_overflow = spr_collision = odd_frame = 0;
    fill_pending = 0, dma_busy_until = 0, hcounter = 0, line = 0, line_start = 0, in_vblank = 0;
    dot_overflow_before = 0;
    for (int i = 0; i < 3; i++)
        io_data[i] = 0x7F, io_ctrl[i] = 0;
    th_count[0] = th_count[1] = 0;
    th_time[0] = th_time[1] = 0;
    for (int i = 0; i < 8; i++)
        banks[i] = (u8)i;
    sram_on = sram_kind != 0 && rom_size <= 0x200000;
    if (addon)
        addon->reset(ram);
    map_memory();
    z80_init(&z);
    z.read = z_read;
    z.write = z_write;
    z.in = z_in;
    z.out = z_out;
    z_map();
    z_reset = 1, z_busreq = 0, z_bank = 0;
    ym.time = 0;
    ym_reset();
    psg_reset();
    cycles_hi = 0;
    m.clock = 0;
    cpu_reset();
}

static int sega_at(const u8 *p, u32 n, u32 at)  /* "SEGA" at `at` or one byte later */
{
    for (u32 k = at; k <= at + 1; k++)
        if (k + 4 <= n && p[k] == 'S' && p[k + 1] == 'E' && p[k + 2] == 'G' && p[k + 3] == 'A')
            return 1;
    return 0;
}

static int interleaved_at(const u8 *p, u32 n, u32 at)  /* the odd bytes of "SEGA MEGA" / "SEGA GENESIS" */
{
    return at + 4 <= n && p[at] == 'E' && p[at + 1] == 'A' && ((p[at + 2] == 'M' && p[at + 3] == 'G') ||
                                                              (p[at + 2] == 'G' && p[at + 3] == 'N'));
}

int md_cartridge(const u8 *head, u32 n, u32 size)
{
    if (size < 0x200)
        return 0;
    if ((size & 0x3FFF) == 512) {       /* a copier's 512 bytes first */
        if (sega_at(head, n, 0x300))
            return 2;
        if (interleaved_at(head, n, 0x280) || (n > 10 && head[8] == 0xAA && head[9] == 0xBB))
            return 3;
    }
    if (sega_at(head, n, 0x100))
        return 1;
    if (!(size & 0x3FFF) && interleaved_at(head, n, 0x80))
        return 4;
    return 0;
}

static void md_once(void)
{
    static int ready;
    if (!ready) {
        cpu_init();
        for (int i = 0; i < 256; i++)
            nib_swap[i] = (u8)((i >> 4) | (i & 15) << 4);
        ready = 1;
    }
}

void md_remap(void)
{
    map_memory();
}

void md_attach_addon(const struct md_addon *ext, int pal_mode, int overseas_mode, const char *title)
{
    md_once();
    addon = ext;
    rom = 0;
    rom_size = rom_pages = 0;
    big = 0;
    sram_kind = sram_on = sram_battery = sram_dirty = 0;
    protection = 0;
    pal = (u8)(pal_mode != 0);
    overseas = (u8)(overseas_mode != 0);
    lines = pal ? 313 : 262;
    if (snd.rate)
        snd.step = (pal ? 53203424u : 53693175u) / YM_SAMPLE;
    put(info, title ? title : "Sega CD");
    md_reset();
}

const char *md_load(u8 *image, u32 size, int region)
{
    md_once();
    addon = 0;
    int kind = md_cartridge(image, size, size);
    u32 skip = kind == 2 || kind == 3 ? 512 : 0;
    if (kind == 3 || kind == 4) {       /* interleaved: 16 KB blocks, the odd bytes' 8 KB, then the even ones' */
        u8 *block = (u8 *)pat;          /* (16 KB to put a block back together in: the patterns', unused yet) */
        size = (size - skip) & ~0x3FFFu;
        for (u32 at = 0; at < size; at += 0x4000) {
            const u8 *from = image + skip + at;
            for (u32 i = 0; i < 0x2000; i++) {
                block[2 * i] = from[0x2000 + i];
                block[2 * i + 1] = from[i];
            }
            for (u32 i = 0; i < 0x4000; i++)
                image[at + i] = block[i];
        }
    } else if (kind == 2) {             /* a copier's header before a plain image */
        size -= 512;
        for (u32 i = 0; i < size; i++)
            image[i] = image[i + 512];
    }
    if (size < 0x200)
        return "not a Mega Drive cartridge file (shorter than its header)";
    if (size > 0xA00000)
        return "not a cartridge this player can hold (more than 10 MB)";
    const u8 *hd = image;
    /* the region: the header's letters (or a newer one's hex digit: bit 0 Japan, 2 America, 3 Europe) */
    int j = 0, u = 0, e = 0, junk = 0;
    for (int i = 0x1F0; i < 0x1F3; i++) {
        u8 c = hd[i];
        j |= c == 'J', u |= c == 'U', e |= c == 'E';
        junk |= c != 'J' && c != 'U' && c != 'E' && c != ' ' && c != 0 && (i > 0x1F0 || !((c >= '0' && c <= '9') ||
                                                                                       (c >= 'A' && c <= 'F')));
    }
    if (junk)                           /* (not a region's letters: an unlicensed cartridge's header) */
        j = u = e = 0;
    else if (!j && !u && !e) {
        u8 c = hd[0x1F0];
        u32 v = c >= '0' && c <= '9' ? (u32)(c - '0') : c >= 'A' && c <= 'F' ? (u32)(c - 'A' + 10) : 0;
        j = v & 1, u = (v >> 2) & 1, e = (v >> 3) & 1;
    }
    int r = region ? region : u ? 'U' : j ? 'J' : e ? 'E' : 'U';
    overseas = r != 'J';
    pal = r == 'E';
    lines = pal ? 313 : 262;
    /* the cartridge's RAM: "RA", its kind, its first and last addresses */
    sram_kind = 0;
    sram_battery = 0;
    if (hd[0x1B0] == 'R' && hd[0x1B1] == 'A') {
        u32 lo = be32(hd + 0x1B4), hi = be32(hd + 0x1B8);
        if (lo >= 0x200000 && lo < 0x400000 && hi >= lo && hi - lo < 0x20000) {
            sram_lo = lo, sram_hi = hi;
            u8 kind = (hd[0x1B2] >> 3) & 3;     /* 0 words, 2 even bytes, 3 odd bytes */
            sram_kind = kind == 2 ? 2 : kind == 3 ? 1 : (lo & 1) ? 1 : 3;
            if (sram_kind == 3 && hi - lo >= 0x10000)
                sram_hi = lo + 0xFFFF;
            sram_battery = (hd[0x1B2] & 0x40) != 0;
        }
    }
    for (u32 i = 0; i < sizeof(sram); i++)
        sram[i] = 0xFF;
    sram_dirty = 0;
    /* unlicensed cartridges' protection */
    protection = 0;
    if (size == 0x200000) {             /* Super Mario World (Taiwan): "SEGA" x 4 for a header, or its checksums */
        u32 sum = 0;
        if (hd[0x18E] == 0x20 && hd[0x18F] == 0x20)
            for (u32 i = 0x200; i < size; i += 2)
                sum += (u32)(hd[i] << 8 | hd[i + 1]);
        if ((be32(hd + 0x100) == 0x53454741 && be32(hd + 0x104) == 0x53454741 && be32(hd + 0x108) == 0x53454741 &&
             be32(hd + 0x10C) == 0x53454741) || (sum & 0xFFFF) == 0xB4EB)
            protection = 1;
    }
    /* the name: the overseas one (or the domestic one), its spaces squeezed */
    char name[49];
    int n = 0;
    for (int pass = 0; pass < 2 && !n; pass++) {
        const u8 *s = hd + (pass ? 0x120 : 0x150);
        for (int i = 0; i < 48; i++) {
            char c = (char)s[i];
            if (c < 32 || c > 126)
                c = ' ';
            if (c == ' ' && (!n || name[n - 1] == ' '))
                continue;
            name[n++] = c;
        }
        while (n && name[n - 1] == ' ')
            n--;
    }
    name[n] = 0;
    if (n >= 8 && name[0] == 'S' && name[1] == 'E' && name[2] == 'G' && name[3] == 'A' && name[4] == 'S')
        n = 0;                          /* ("SEGASEGA...": no name) */
    /* the ROM, its words as the 68000's (on this little-endian host: each pair of bytes swapped) */
    for (u32 i = 0; i + 1 < size; i += 2) {
        u8 t = image[i];
        image[i] = image[i + 1];
        image[i + 1] = t;
    }
    rom = image;
    rom_size = size;
    rom_pages = (size + 0xFFFF) >> 16;
    big = size > 0x400000;
    char *p = put(info, n ? name : protection ? "an unlicensed cartridge" : "(no name)");
    p = put(p, ", ROM ");
    p = put_number(p, size >> 10);
    p = put(p, " KB, ");
    p = put(p, pal ? "PAL (E)" : overseas ? "NTSC (U)" : "NTSC (J)");
    if (sram_kind) {
        p = put(p, ", RAM ");
        p = put_number(p, ((sram_kind == 3 ? sram_hi - sram_lo + 1 : (sram_hi - sram_lo) / 2 + 1) + 1023) >> 10);
        p = put(p, " KB");
    }
    if (big)
        p = put(p, ", Sega mapper");
    if (protection)
        p = put(p, ", protection");
    md_reset();
    return 0;
}

void md_pad2(u16 pad)
{
    pads[1] = pad;
}

void md_six_button(int on)
{
    six = (u8)(on != 0);
}

int md_width(void)
{
    return pic_w;
}

int md_height(void)
{
    return pic_h;
}

int md_pal(void)
{
    return pal;
}

const char *md_info(void)
{
    return info;
}

u8 *md_save_ram(u32 *size, int *battery)
{
    u32 n = 0;
    if (sram_kind)
        n = sram_kind == 3 ? sram_hi - sram_lo + 1 : (sram_hi - sram_lo) / 2 + 1;
    if (n > sizeof(sram))
        n = sizeof(sram);
    *size = n;
    *battery = n != 0 && sram_battery;
    return sram;
}

int md_save_changed(void)
{
    int was = sram_dirty;
    sram_dirty = 0;
    return was;
}

u32 md_cpu_cycles(void)
{
    return cycles_hi + (u32)m.clock;
}

int md_jammed(void)
{
    return m.stopped && m.im == 7;
}

u8 md_peek(u32 a)
{
    const u8 *p = rmap[(a >> 16) & 0xFF];
    return p ? p[(a & 0xFFFF) ^ 1] : 0;
}

u8 md_z80_peek(u16 a)
{
    return a < 0x4000 ? zram[a & 0x1FFF] : 0xFF;
}

u8 md_vdp_reg(int r)
{
    return reg[r & 31];
}

u16 md_vram(u32 a)
{
    return vram[(a & 0xFFFF) >> 1];
}

u16 md_cram(int i)
{
    return cram[i & 63];
}

u16 md_vsram(int i)
{
    return vsram[i & 63];
}

void md_registers(u32 r[18])
{
    for (int i = 0; i < 16; i++)
        r[i] = m.r[i];
    r[16] = m.pc;
    r[17] = get_sr();
}
