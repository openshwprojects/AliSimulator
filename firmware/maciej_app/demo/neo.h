/* neo.c: SNK Neo Geo AES / MVS cartridge (.neo) and Neo Geo CD (.cue / .iso).

   Main CPU: Motorola 68000 (m68k.inc) at 12 MHz with 64 KB work RAM, fixed 1 MB
   P1 window ($000000..$0FFFFF), banked 1 MB P2 window ($200000..$2FFFFF), 64 KB
   MVS backup SRAM ($D00000..$D0FFFF, kept in .sav), 2 KB / 8 KB memory card
   ($800000), and a built-in clean-room system BIOS ($C00000) with optional
   external BIOS (neogeo.rom / uni-bios.rom; neocd.bin / top-sp1.bin) support.
   Neo Geo CD adds 2 MB 68k PRG DRAM ($000000..$1FFFFF), 4 MB SPR DRAM, 1 MB
   ADPCM-A DRAM, 128 KB FIX PSRAM, 64 KB Z80 RAM, ISO9660 IPL.TXT + BIOS file /
   DMA upload engine ($E00000 / $FF0000), swapped VBL/Timer IRQs, and 44.1 kHz
   Redbook CD-DA mixed at 48 kHz.
   Picture: LSPC2 scanline renderer (320 x 224, 68 KB VRAM, 381 vertical sprite
   strips in SCB1..SCB4 with sticky chaining, 16-bit H/V shrink LUTs, 4/8-frame
   auto-animation, raster timer IRQ, S1/SFIX 8x8 fix layer with per-line/tile
   banking, 2 x 4096 16-bit palette banks + dark/shadow resistor DAC -> BGR555).
   Sound: Zilog Z80 (z80.c) at 4 MHz + Yamaha YM2610 (4-channel 4-op FM, 3-ch
   SSG + noise/envelope, 6-channel ADPCM-A, 1-channel ADPCM-B Delta-T) + CD-DA. */
#ifndef DEMO_NEO_H
#define DEMO_NEO_H

#include "cdrom.h"

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define NEO_W        320
#define NEO_H        224
#define NEO_FRAME_US 16779              /* AES: 264 lines * 1536 / 24.167829 MHz = 59.5995 Hz */

/* Pad bits match play.c's 12-button PAD_* */
#define NEO_PAD_A      0x0001
#define NEO_PAD_B      0x0002
#define NEO_PAD_SELECT 0x0004
#define NEO_PAD_START  0x0008
#define NEO_PAD_UP     0x0010
#define NEO_PAD_DOWN   0x0020
#define NEO_PAD_LEFT   0x0040
#define NEO_PAD_RIGHT  0x0080
#define NEO_PAD_C      0x0100           /* PAD_X -> Neo Geo C */
#define NEO_PAD_D      0x0200           /* PAD_Y -> Neo Geo D */
#define NEO_PAD_COIN   0x0400           /* PAD_L -> Coin (MVS) */
#define NEO_PAD_TEST   0x0800           /* PAD_R -> Service/Test */

/* Optional external 128 KB 68000 system BIOS (neogeo.rom / uni-bios.rom / sp-s2.sp1).
   Pass 0, 0 to use the built-in clean-room system BIOS. */
void neo_set_bios(const u8 *rom, u32 size);

/* Optional external 512 KB Neo Geo CD system BIOS (neocd.bin / top-sp1.bin / front-sp1.bin).
   Pass 0, 0 to use the built-in clean-room Neo Geo CD system BIOS. */
void neocd_set_bios(const u8 *rom, u32 size);

const char *neo_load(u8 *image, u32 size);
const char *neocd_load(const struct cdrom_toc *cd, const char *path);
void neo_reset(void);
void neo_frame(u16 pad, u16 *picture);
void neo_pad2(u16 pad);
const char *neo_info(void);
u8 *neo_save_ram(u32 *size, int *battery);
int neo_save_changed(void);
int neo_jammed(void);

void neo_audio_rate(u32 hz);
int neo_audio(s16 *out, int max);

#endif
