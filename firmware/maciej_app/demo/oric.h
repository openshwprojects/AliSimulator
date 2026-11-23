/* oric.c: Tangerine Oric-1 & Oric Atmos 48K Home Computer Emulator
   - 1.0 MHz MOS 6502 CPU + 48 KB RAM + 16 KB Clean-Room Atmos 1.1 Basic/OS ROM ($C000..$FFFF)
   - HCS10017 ULA 240 x 224 Serial-Attribute Video (40x28 Text + 240x200 Hires + 3 Text rows,
     inline ink/paper, std/alt charsets $B400/$B800 & $9800/$9C00, double-height, blink, inverse)
   - MOS 6522 VIA ($0300..$030F: 100 Hz Timer 1 IRQ, Timer 2, keyboard row select & AY bus)
   - 1.0 MHz General Instrument AY-3-8912 3-channel PSG @ 48 kHz + 8x8 Keyboard Matrix
   - Supports .tap (single & multi-part Atmos tapes), .dsk (MFM_DISK / ORICDISK), and BASIC ("") */
#ifndef DEMO_ORIC_H
#define DEMO_ORIC_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define ORIC_W        240
#define ORIC_H        224
#define ORIC_FRAME_US 20000     /* 50.00 Hz PAL */

const char *oric_load(const u8 *image, u32 size, const char *path,
                      const u8 *ext_rom, u32 ext_rom_sz);
void oric_reset(void);
void oric_frame(u16 pad, u16 *picture);
void oric_keyboard(const u8 *usages, int n);
void oric_typed(char c);
const char *oric_info(void);
int oric_jammed(void);
void oric_audio_rate(u32 hz);
int oric_audio(s16 *out, int max);

#endif
