/* pce.c: a NEC PC Engine / TurboGrafx-16 -- its HuC6280 at 7.16 MHz (the 65C02
   with its memory mapping registers MPR0..MPR7, zero page at $2000 and stack
   at $2100, the T-flag memory operations, the block transfers TII / TDD / TIN
   / TIA / TAI, ST0 / ST1 / ST2, TST, BBR / BBS / RMB / SMB, the 7 kHz timer
   and interrupt mask), the HuC6270 VDC and HuC6260 VCE (64 KB VRAM, scrolled
   background, 64 sprites up to 32 x 64, raster counter interrupts, VRAM and
   SATB DMA, 256 / 320 / 512 widths, 512 9-bit colours), the 6-channel PSG
   (wavetable, noise, DDA samples and LFO), Street Fighter II' banking and
   2 KB backup RAM (.sav).  Nothing in it knows the box: a HuCard image in RAM
   goes in, pictures of 15-bit colours come out (play.c puts them on the TV
   and reads the buttons; a PC harness runs the same file). */
#ifndef DEMO_PCE_H
#define DEMO_PCE_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed short s16;
typedef signed int s32;

#define PCE_W_MAX    512
#define PCE_H_MAX    242
#define PCE_W_DEF    256
#define PCE_H_DEF    240
#define PCE_FRAME_US 16712              /* 263 lines of 1365 master clocks at 21.47727 MHz (59.84 frames a second) */

/* the pad's buttons (the low eight bits match nes.h's and play.c's):
   A (X on the keyboard, the remote's OK) is I, B (Z, the remote's 0) is II,
   SELECT is Select, START is Run */
#define PCE_I      0x0001
#define PCE_II     0x0002
#define PCE_SELECT 0x0004
#define PCE_RUN    0x0008
#define PCE_UP     0x0010
#define PCE_DOWN   0x0020
#define PCE_LEFT   0x0040
#define PCE_RIGHT  0x0080
#define PCE_III    0x0100
#define PCE_IV     0x0200
#define PCE_V      0x0400
#define PCE_VI     0x0800

const char *pce_load(u8 *image, u32 size);      /* a .pce HuCard image in RAM (a 512-byte header skipped; bit-reversed
                                                   US dumps unreversed in place): 0, or why it cannot run */
void pce_reset(void);
void pce_frame(u16 pad, u16 *picture);          /* one frame: pce_width() x pce_height() 15-bit colours
                                                   (0bbbbbgggggrrrrr; 0: no picture kept) */
int pce_width(void);
int pce_height(void);
const char *pce_info(void);
u8 *pce_save_ram(u32 *size, int *battery);      /* the 2 KB backup RAM ($F7), saved when unlocked and written */
int pce_save_changed(void);
u32 pce_cpu_cycles(void);
int pce_jammed(void);

void pce_audio_rate(u32 hz);
int pce_audio(s16 *out, int max);

#ifdef PCE_CPU_TEST
/* SingleStepTests/huc6280 flat 2 MB bus mode: pce.c built with -DPCE_HOST -DPCE_CPU_TEST */
extern u8 pce_sst_ram[0x200000];
void pce_sst_set(u8 a, u8 x, u8 y, u8 s, u8 p, u16 pc, const u8 mpr[8]);
void pce_sst_get(u8 *a, u8 *x, u8 *y, u8 *s, u8 *p, u16 *pc, u8 mpr[8]);
u32 pce_sst_step(void);
#endif

#endif
