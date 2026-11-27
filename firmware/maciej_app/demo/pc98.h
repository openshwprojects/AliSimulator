/* pc98.c: NEC PC-9801VM / VX ('pc98')
   - x86 / NEC V30 / 80286 / 80386 CPU (shared x86_v30.inc) + 640 KB RAM + 2 MB Extended
   - Dual uPD7220 GDC: 640x400 4-plane 16-color GVRAM (A8000/B0000/B8000/E0000, 2 pages) +
     80x25 Text/Attr VRAM (A0000/A2000) + CGROM/KCG (ANK, Kana, Box-Drawing, User Gaiji)
   - GRCG (Graphic Charger TDW/TCR/RMW) + EGC (Enhanced Graphic Charger 16-bit planar ROP)
   - PC-9801-26K / 86 Sound: 6-ch 4-op FM + 3-ch SSG + YM Timer A/B (IRQ 12) + PIT Beep @ 48 kHz
   - Dual 8259A PIC, 8253 PIT, uPD765 FDC (.fdi, .d88, .hdm, .xdf, .2hd) + SASI HDD (.hdi)
   - Clean-room PC-98 System/Disk/CRT BIOS (INT 18h/1Bh/1Ch/1Fh) + PC-98 MS-DOS 5.0 HLE (.zip/.exe) */
#ifndef DEMO_PC98_H
#define DEMO_PC98_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define PC98_W        640
#define PC98_H        400
#define PC98_FRAME_US 17724     /* 56.42 Hz (24.83 kHz CRT) */

void pc98_set_font(const u8 *font_rom, u32 size);
void pc98_clear_files(void);
const char *pc98_add_file(const char *name, const u8 *data, u32 size);
const char *pc98_load(const u8 *image, u32 size, const char *path);
void pc98_reset(void);
void pc98_frame(u16 pad, u16 *picture);
void pc98_keys_from_hid(const u8 *usages, int n);
void pc98_type(const char *text);
const char *pc98_info(void);
u8 *pc98_save_ram(u32 *size, int *battery);
int pc98_save_changed(void);
int pc98_jammed(void);
void pc98_audio_rate(u32 hz);
int pc98_audio(s16 *out, int max);

#endif
