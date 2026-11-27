/* williams.c: Williams & Midway Classic Arcade Multi-Board Emulator (.zip; "" = built-in game).

   Supported Williams / Midway Arcade Hardware Families:
   1. Early Williams First/Second-Gen Blitter Hardware:
      - Dual Motorola MC6809E CPUs (1.0 MHz Main + 0.895 MHz Sound via m6809.inc)
      - 304x240 visible (304x256 VRAM) 4bpp packed bitmap + 16-color BBGGGRRR palette
      - Williams Special Chip 1 / 2 Hardware Blitter ($CA00..$CA07: solid, foreground,
        4-bit pixel shift, linear & columnar VRAM strides, SC1 XOR-4 width/height quirk)
      - Dual/Triple MC6821 PIAs (joysticks, 240 Hz VA11 IRQ, 6-bit sound command + 8-bit DAC)
      - Banked ROM/VRAM ($C900 / Defender $D000) + 1 KB battery-backed CMOS NVRAM (.sav)
      - Covers: Defender, Stargate, Robotron: 2084, Joust, Bubbles, Splat!, Sinistar.
   2. Midway Y-Unit / T-Unit 32-bit GSP Hardware:
      - Texas Instruments TMS34010 32-bit Graphics System Processor (bit-addressed memory,
        A0..A14 & B0..B14 register files, PIXBLT / FILL XY / LINE / MMFM / MMTM, DPYINT)
      - Midway Custom DMA2 Hardware Sprite Blitter ($01A80000: 4/8-bpp clipped/flipped/paletted)
      - 400x254 15-bit / 8-bpp display + Sound 6809 + YM2151 + OKI MSM6295 4-ch ADPCM @ 48 kHz
      - Covers: Smash TV, Total Carnage, Mortal Kombat, Mortal Kombat II, NBA Jam. */
#ifndef DEMO_WILLIAMS_H
#define DEMO_WILLIAMS_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define WILLIAMS_W_MAX    400
#define WILLIAMS_H_MAX    254
#define WILLIAMS_FRAME_US 16667 /* 60.00 Hz */

int williams_is_zip(const u8 *zip, u32 size, const char *name);
const char *williams_load(const u8 *image, u32 size, const char *path);
void williams_reset(void);
void williams_frame(u16 pad, u16 *picture);
void williams_pad2(u16 pad);
int williams_width(void);
int williams_height(void);
const char *williams_info(void);
u8 *williams_save_ram(u32 *size, int *battery);
int williams_save_changed(void);
int williams_jammed(void);
void williams_audio_rate(u32 hz);
int williams_audio(s16 *out, int max);

#endif
