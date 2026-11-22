/* st.c: Atari 520ST / 1040STFM / STE-Blitter home computer.

   CPU: Motorola MC68000 (m68k.inc) at 8.021 MHz (512 cycles/line, 313 PAL
   lines at 50.05 Hz or 263 NTSC lines at 59.82 Hz), with hardware Bus Error
   (Vector 2) and MC68901 MFP vectored IPL 6 interrupts.
   Memory: 2 MB ST-RAM ($000000..$1FFFFF), 192 KB TOS ($FC0000) or 256 KB
   EmuTOS / TOS 2.06 ($E00000), plus a built-in clean-room TOS/GEMDOS/BIOS/
   XBIOS fallback ROM when no external tos.img / etos*.img is present.
   Video: Atari Shifter (320x200 16c, 640x200 4c, 640x400 mono, per-scanline
   raster palettes, live video address counter) + Atari STE Blitter ($FF8A00).
   Peripherals: MC68901 MFP (Timers A/B/C/D incl. HBL Event Count & 200 Hz
   system tick), dual MC6850 ACIA + HD6301 IKBD (keyboard, mouse, joystick),
   Atari DMA + Western Digital WD1772 FDC (.st, .msa RLE, and auto-boot
   FAT12 wrapper for bare .prg / .tos executables).
   Sound: Yamaha YM2149F 3-channel PSG + envelope at 48 kHz. */
#ifndef DEMO_ST_H
#define DEMO_ST_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define ST_W_LOW       320
#define ST_H_LOW       200
#define ST_W_MAX       640
#define ST_H_MAX       400
#define ST_FRAME_US    19979            /* 50.05 Hz PAL */
#define ST_FRAME_US_NT 16688            /* 59.92 Hz NTSC */

/* Pad bits match play.c PAD_* */
#define ST_A           0x0001           /* Joystick 1 Fire */
#define ST_B           0x0002           /* Space */
#define ST_SELECT      0x0004           /* F2 */
#define ST_START       0x0008           /* Return / F1 */
#define ST_UP          0x0010
#define ST_DOWN        0x0020
#define ST_LEFT        0x0040
#define ST_RIGHT       0x0080

/* Load optional TOS / EmuTOS ROM (192 KB or 256 KB; 0 = built-in clean-room ROM)
   and optional media (.st, .msa, .prg, .tos; 0 = boot to desktop). */
const char *st_load(const u8 *tos_rom, u32 tos_size, u8 *media, u32 media_size, const char *name);
void st_reset(void);
void st_frame(u16 pad, const u8 *hid_usages, int hid_n, u16 *picture);
void st_type(char c);
int st_width(void);
int st_height(void);
int st_pal(void);
const char *st_info(void);
u8 *st_save_ram(u32 *size, int *battery);
int st_save_changed(void);
int st_jammed(void);

void st_audio_rate(u32 hz);
int st_audio(s16 *out, int max);

#endif
