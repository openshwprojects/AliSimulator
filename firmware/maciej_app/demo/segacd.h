/* segacd.h: Sega CD / Mega-CD ('segacd') expansion unit for md.c:
   - 12.5 MHz Sub-68000 (m68k.inc, 0 B static .bss via EMU_RAM_PHYS)
   - 512 KB PRG-RAM (with WP0..7 write-protect & Main-CPU 128 KB banking)
   - 256 KB Word-RAM (2M mode + 1M/1M double-buffered Dot-RAM & VDP Cell-RAM)
   - Sega Gate Array ($A12000..$A1202F Main / $FF8000..$FF81FF Sub: SRES/SBRQ,
     IFL2, Stopwatch, IRQ3 Timer, 1bpp->4bpp Font Expander, COMFLAGS/CMD/STAT)
   - Word-RAM Stamp ASIC ($FF8058..$FF8067: 16x16/32x32 affine scaling & rotation)
   - Sanyo LC89510 CDC (DMA to PRG-RAM, Word-RAM, PCM RAM & Host Read) + 75 Hz CDD
   - Ricoh RF5C164 8-channel PCM ($FF0001..$FF7FFF, 64 KB Wave RAM) + streamed
     44.1 kHz Redbook CD-DA mixed into md.c's 48 kHz output
   - 8 KB internal Backup RAM (.sav)
   - Clean-room Mega-CD BIOS (boots IP/SP from Sector 0/1 + _CDBIOS $5F22 & _BURAM
     $5F16), with optional external bios_CD_{U,E,J}.bin (128 KB) override. */
#ifndef DEMO_SEGACD_H
#define DEMO_SEGACD_H

#include "md.h"
#include "cdrom.h"

const char *segacd_load(const u8 *bios, u32 bios_size, const struct cdrom_toc *cd, int region);
u8 *segacd_save_ram(u32 *size, int *battery);
int segacd_save_changed(void);

#endif
