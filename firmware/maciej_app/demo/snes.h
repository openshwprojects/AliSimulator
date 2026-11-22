/* snes.c: a Nintendo Super Famicom / Super Nintendo Entertainment System.

   Main CPU: WDC 65C816 (emulation & native 8/16-bit M/X modes, LoROM / HiROM /
   ExHiROM, 8-channel GPDMA + HDMA, H/V timers, auto-joypad).
   Picture: S-PPU scanline renderer (256 x 224 or 256 x 239, Modes 0..7 incl.
   Mode 7 affine matrix & EXTBG, 128 sprites, mosaic, dual windows, subscreen
   color math) in 15-bit BGR555.
   Sound: Sony SPC700 + S-DSP (8-channel BRR ADPCM, Gaussian interpolation,
   ADSR/GAIN envelopes, pitch modulation, noise, echo FIR) resampled to 48 kHz.
   Cartridge battery SRAM kept in .sav. */
#ifndef DEMO_SNES_H
#define DEMO_SNES_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define SNES_W            256
#define SNES_H_DEF        224
#define SNES_H_MAX        239
#define SNES_FRAME_US     16639         /* NTSC: 60.0988 Hz */
#define SNES_FRAME_US_PAL 19997         /* PAL:  50.0070 Hz */

/* Pad bits match play.c's 12-button PAD_* */
#define SNES_PAD_A      0x0001
#define SNES_PAD_B      0x0002
#define SNES_PAD_SELECT 0x0004
#define SNES_PAD_START  0x0008
#define SNES_PAD_UP     0x0010
#define SNES_PAD_DOWN   0x0020
#define SNES_PAD_LEFT   0x0040
#define SNES_PAD_RIGHT  0x0080
#define SNES_PAD_X      0x0100
#define SNES_PAD_Y      0x0200
#define SNES_PAD_L      0x0400
#define SNES_PAD_R      0x0800

const char *snes_load(u8 *image, u32 size);
void snes_reset(void);
void snes_frame(u16 pad, u16 *picture);
int snes_width(void);
int snes_height(void);
int snes_pal(void);
const char *snes_info(void);
u8 *snes_save_ram(u32 *size, int *battery);
int snes_save_changed(void);
int snes_jammed(void);

void snes_audio_rate(u32 hz);
int snes_audio(s16 *out, int max);

#endif
