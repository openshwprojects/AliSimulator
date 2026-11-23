/* arcade.c: Golden-Age Z80 Classic Arcade Multi-Board Emulator
   Supports MAME .zip romsets and built-in games across 4 classic arcade boards:
   1. Namco Pac-Man / Ms. Pac-Man (3.072 MHz Z80 + 28x36 tilemap + 8 sprites + 3-ch Namco WSG)
   2. Namco Galaxian (3.072 MHz Z80 + column scroll + 8 sprites + shells/missiles + 256-star LFSR + synth)
   3. Konami Frogger / Scramble (Dual Z80 3.072 + 1.79 MHz + 8255 PPIs + column scroll + AY-3-8910)
   4. Nintendo Donkey Kong (3.072 MHz Z80 + 32x28 tilemap + 96 DMA sprites + discrete/DAC sound) */
#ifndef DEMO_ARCADE_H
#define DEMO_ARCADE_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define ARCADE_W        224
#define ARCADE_H_MAX    288
#define ARCADE_FRAME_US 16500   /* 60.606 Hz (18.432 MHz / (384 * 264)) */

const char *arcade_load(const u8 *image, u32 size, const char *path);
void arcade_reset(void);
void arcade_frame(u16 pad, u16 *picture);
int arcade_width(void);
int arcade_height(void);
const char *arcade_info(void);
int arcade_jammed(void);
void arcade_audio_rate(u32 hz);
int arcade_audio(s16 *out, int max);

#endif
