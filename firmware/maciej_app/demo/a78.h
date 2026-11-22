/* a78.c: an Atari 7800 ProSystem (.a78).

   CPU: 1.79 MHz Atari SALLY 6502C (halted during MARIA DMA; 1.19 MHz on TIA/RIOT accesses).
   Picture: MARIA GCC1702 line-buffer display processor (320 x 224 NTSC / 320 x 240 PAL in
   15-bit BGR555, Display List Lists & 4-byte / 5-byte Display List headers, indirect tile
   character modes, 160A, 160B, 320A, 320B, 320C, 320D, Kangaroo transparency control, DLI
   scanline NMI, 256-colour NTSC & PAL YIQ palettes).
   Sound: Atari TIA 2-channel polynomial audio + optional cartridge POKEY 4-channel audio
   ($4000 or $0450) mixed at 48 kHz.
   Cartridges: 128-byte .a78 v1..v4 header + headerless 16K/32K/48K dumps, SuperGame bank
   switching (up to 512 KB, optional 16 KB RAM at $4000, EXFIX), Activation / Absolute /
   Activision banking, High-Score SRAM (.sav). */
#ifndef DEMO_A78_H
#define DEMO_A78_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define A78_W            320
#define A78_H_NTSC       224
#define A78_H_PAL        240
#define A78_FRAME_US     16684          /* NTSC: 262 lines * 114 cyc / 1.7897725 MHz = 59.92 Hz */
#define A78_FRAME_US_PAL 20065          /* PAL:  312 lines * 114 cyc / 1.7734475 MHz = 49.86 Hz */

/* Pad bits match play.c's PAD_* */
#define A78_PAD_A      0x0001           /* Fire 1 (Right / Left button) */
#define A78_PAD_B      0x0002           /* Fire 2 */
#define A78_PAD_SELECT 0x0004           /* Console Select */
#define A78_PAD_START  0x0008           /* Console Pause */
#define A78_PAD_UP     0x0010
#define A78_PAD_DOWN   0x0020
#define A78_PAD_LEFT   0x0040
#define A78_PAD_RIGHT  0x0080
#define A78_PAD_RESET  0x0100           /* C = Console Reset */

const char *a78_load(u8 *image, u32 size);
void a78_reset(void);
void a78_frame(u16 pad, u16 *picture);
int a78_width(void);
int a78_height(void);
int a78_pal(void);
const char *a78_info(void);
u8 *a78_save_ram(u32 *size, int *battery);
int a78_save_changed(void);
int a78_jammed(void);

void a78_audio_rate(u32 hz);
int a78_audio(s16 *out, int max);

#endif
