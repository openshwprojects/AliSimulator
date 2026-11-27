/* irem.c: Irem M72 & M92 Classic Arcade Multi-Board Emulator (.zip; "" = built-in game).

   Supported Irem Arcade Hardware Families:
   1. Irem M72 (8 MHz NEC V30 via x86_v30.inc + 3.58 MHz Sound Z80 + dual 64x64 4bpp
      scrolling tilemaps + 256 multi-cell 16x16 hardware DMA sprites + VBlank & raster
      split interrupts + YM2151 OPM FM + 8-bit sample DAC):
      Covers: R-Type, R-Type II, Ninja Spirit, Image Fight, Mr. HELI, Gallop, Hammerin' Harry.
   2. Irem M92 (9 MHz NEC V33 + Sound CPU + 3 hardware scrolling/rowscroll playfields
      PF1/PF2/PF3 + 256 multi-cell sprites + 2048 15-bit colors + YM2151 + Irem GA20 4-ch PCM):
      Covers: In the Hunt, Undercover Cops, GunForce II, Blade Master, Mystic Riders, Hook. */
#ifndef DEMO_IREM_H
#define DEMO_IREM_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define IREM_W_MAX    384
#define IREM_H_MAX    240
#define IREM_FRAME_US 18182     /* 55.00 Hz authentic Irem M72 / M92 arcade refresh! */

int irem_is_zip(const u8 *zip, u32 size, const char *name);
const char *irem_load(const u8 *image, u32 size, const char *path);
void irem_reset(void);
void irem_frame(u16 pad, u16 *picture);
void irem_pad2(u16 pad);
int irem_width(void);
int irem_height(void);
const char *irem_info(void);
u8 *irem_save_ram(u32 *size, int *battery);
int irem_save_changed(void);
int irem_jammed(void);
void irem_audio_rate(u32 hz);
int irem_audio(s16 *out, int max);

#endif
