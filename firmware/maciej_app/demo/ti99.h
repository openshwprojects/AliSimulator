/* ti99.c: Texas Instruments TI-99/4A Home Computer Emulator
   - 3.0 MHz 16-bit TMS9900 CPU (workspace-in-memory architecture, CRU I/O, hardware MPY/DIV)
   - 256 B Scratchpad RAM ($8300..$83FF) + 32 KB Expansion RAM ($2000..$3FFF, $A000..$FFFF)
   - 378 non-inverted & 379i inverted banked cartridge ROMs ($6000..$7FFF, up to 512 KB) + GROM ($9800/$9C02)
   - TI TMS9918A VDP (Graphics I, Graphics II / Bitmap, Multicolor, 40-col Text, 32 sprites)
   - TI TMS9919 / SN76489 4-channel PSG @ 48 kHz
   - Supports .bin, .rpk / .zip (multi-ROM c/d/g or banked *8.bin / *9.bin), and interactive TI BASIC ("") */
#ifndef DEMO_TI99_H
#define DEMO_TI99_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define TI99_W        256
#define TI99_H        192
#define TI99_FRAME_US 16683     /* 59.94 Hz NTSC */

const char *ti99_load(const u8 *image, u32 size, const char *path);
void ti99_reset(void);
void ti99_frame(u16 pad, u16 *picture);
void ti99_keyboard(const u8 *usages, int n);
void ti99_typed(char c);
const char *ti99_info(void);
int ti99_jammed(void);
void ti99_audio_rate(u32 hz);
int ti99_audio(s16 *out, int max);

#endif
