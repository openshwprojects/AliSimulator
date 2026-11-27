/* threedo.c: 3DO Interactive Multiplayer ('3do': .iso, .cue; "": built-in 3D CEL showcase)
   - 12.5 MHz 32-bit Big-Endian ARM60 (ARMv3) CPU with banked USR/FIQ/IRQ/SVC/ABT/UND registers
   - 2 MB DRAM + 1 MB dual-bank VRAM + 32 KB battery-backed NVRAM (.sav) in EMU_RAM_PHYS
   - Madam (0x03300000) hardware CEL Quad Projector: 1/2/4/6/8/16-bpp Unpacked & RLE Packed CELs,
     32-entry PLUT, PIXC (PPMP) shading & translucency, perspective quad rasterizer, SPORT clear/copy
   - Clio (0x03400000) timers, VBlank/scanline counters, IRQs, PBUS pad & XBUS CR-563 CD-ROM
   - DSPP / Portfolio Audio + 44.1 kHz Redbook CD-DA resampled & mixed @ 48 kHz
   - Clean-room Opera FS + Portfolio OS 2.5 HLE (boots LaunchMe directly) + optional panafz10.bin */
#ifndef DEMO_THREEDO_H
#define DEMO_THREEDO_H

#include "cdrom.h"

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define THREEDO_W        320
#define THREEDO_H        240
#define THREEDO_FRAME_US 16683          /* 59.94 Hz NTSC */

void threedo_set_bios(const u8 *rom, u32 size);
const char *threedo_load(const struct cdrom_toc *cd, const char *name);
void threedo_reset(void);
void threedo_frame(u16 pad, u16 *picture);
const char *threedo_info(void);
u8 *threedo_save_ram(u32 *size, int *battery);
int threedo_save_changed(void);
int threedo_jammed(void);

void threedo_audio_rate(u32 hz);
int threedo_audio(s16 *out, int max);

#ifdef THREEDO_HOST
void threedo_host_dbg(u32 out[8]);
#endif

#endif
