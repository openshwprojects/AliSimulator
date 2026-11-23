/* cd32.c: Commodore Amiga CD32 Console Emulator
   - 14.18 MHz 68EC020-compatible CPU + 2 MB Chip RAM + 1 KB NVRAM (.sav)
   - AGA Lisa/Alice Custom Chipset: up to 8 bitplanes (256 colors / HAM8), 24-bit palette, Copper & 2 MB Blitter
   - Akiko Custom ASIC ($B80000 = $C0CACAFE): Hardware Chunky-to-Planar ($B80038), CD-ROM DMA & 7-button pad
   - 4-channel Paula 8-bit DMA audio + 44.1 kHz Redbook CD-DA mixed @ 48 kHz
   - Built-in Clean-Room ISO-9660 + AmigaDOS HUNK_HEADER Relocator & Exec/DOS/LowLevel ROM
     (optional cd32_kick31.rom + cd32_ext.rom in cd32/) */
#ifndef DEMO_CD32_H
#define DEMO_CD32_H

#include "cdrom.h"

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define CD32_W        352
#define CD32_H        272
#define CD32_FRAME_US 20032     /* 49.92 Hz PAL (313 lines) */

const char *cd32_load(const u8 *kick, u32 kick_sz, const u8 *ext, u32 ext_sz, const struct cdrom_toc *cd);
void cd32_reset(void);
void cd32_frame(u16 pad, u16 *picture);
const char *cd32_info(void);
u8 *cd32_save_ram(u32 *size, int *battery);
int cd32_save_changed(void);
int cd32_jammed(void);
void cd32_audio_rate(u32 hz);
int cd32_audio(s16 *out, int max);

#endif
