/* NEC PC-FX 32-Bit Multimedia CD-ROM Console Emulator for Maciej v4 (ALi S3811)
   Supports .cue / .iso PC-FX CD-ROM discs ("PC-FX:Hu_CD-ROM") with optional
   pcfx.rom / pcfxbios.bin or clean-room IPL boot, plus built-in playable 32-bit
   game (""): "STAR SOLDIER FX-32"!
   Architecture (zero static .bss — all state in EMU_RAM_PHYS):
     - 21.47727 MHz NEC V810 32-bit RISC CPU (full integer + BSTR + IEEE-754 FPU + I/O ports)
     - 2 MB Main RAM + 32 KB Backup SRAM (.sav) + 1 MB BIOS space
     - HuC6261 VCE (512-entry 16-bit Y8U4V4 palette + priority mixer -> RGB555)
     - Dual HuC6270 VDC-A & VDC-B (2 x 64 KB VRAM, CG tilemaps + 2 x 64 multi-cell sprites)
     - HuC6272 KING (1 MB KRAM, BG0..BG3 4/8/16-bpp YUV + BG0 affine rotation/zoom,
       KRAM DMA, built-in SCSI CD-ROM controller over cdrom.h, 2-ch ADPCM)
     - HuC6273 RAINBOW (RLE & YUV chroma-subsampled motion block decoder)
     - HuC6230 SoundBox (6-ch 32-step wavetable/noise PSG + 2-ch ADPCM + Redbook CD-DA @ 48 kHz) */
#ifndef DEMO_PCFX_H
#define DEMO_PCFX_H

#include "cdrom.h"

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define PCFX_W        256
#define PCFX_H        240
#define PCFX_FRAME_US 16683u            /* 59.94 Hz NTSC */

void pcfx_set_bios(const u8 *rom, u32 size);
const char *pcfx_load(const struct cdrom_toc *cd, const char *path);
void pcfx_reset(void);
void pcfx_frame(u16 pad, u16 *picture);

int pcfx_width(void);
int pcfx_height(void);
const char *pcfx_info(void);

u8 *pcfx_save_ram(u32 *size, int *battery);
int pcfx_save_changed(void);
int pcfx_jammed(void);

void pcfx_audio_rate(u32 hz);
int pcfx_audio(s16 *out, int max);

#endif
