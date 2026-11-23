/* ted81.c: Commodore Plus/4 & C16 (MOS 7360/8360 TED) + Sinclair ZX81 Emulator
   - 'plus4': 1.77 MHz MOS 7501/8501 + 64 KB RAM + Clean-Room Kernal/BASIC + MOS TED 121-color
     video (Hi-Res/Multicolor Text, Hi-Res/Multicolor Bitmap, Raster IRQ, Timers 1..3) +
     TED 2-voice square/white-noise 48 kHz audio + C16-TAPE-RAW (.tap), T64, .prg & BASIC ("")
   - 'zx81':  3.25 MHz Zilog Z80 + 16 KB RAM Pack ($4000..$7FFF) + ULA live D_FILE 32x24 renderer
     (authentic 64-char ZX81 charset + 2x2 block/dither semigraphics + inverse) + 50 Hz FRAMES
     ($4034) VSync + keyboard matrix + VSync/tape pulse audio + .p / .81 & Sinclair BASIC ("") */
#ifndef DEMO_TED81_H
#define DEMO_TED81_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define PLUS4_W        320
#define PLUS4_H        200
#define PLUS4_FRAME_US 20000    /* 50.00 Hz PAL */

#define ZX81_W         256
#define ZX81_H         192
#define ZX81_FRAME_US  20000    /* 50.00 Hz PAL */

const char *plus4_load(const u8 *image, u32 size, const char *path);
const char *zx81_load(const u8 *image, u32 size, const char *path);

void ted81_reset(void);
void ted81_frame(u16 pad, u16 *picture);
void ted81_keyboard(const u8 *usages, int n);
void ted81_typed(char c);
const char *ted81_info(void);
int ted81_jammed(void);
void ted81_audio_rate(u32 hz);
int ted81_audio(s16 *out, int max);

#endif
