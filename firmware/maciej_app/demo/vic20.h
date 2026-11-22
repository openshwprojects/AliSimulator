/* vic20.c: Commodore VIC-20 (PAL) home computer emulator with 1.1084 MHz MOS
   6502, MOS 6561 VIC-I video + 4-channel 48 kHz sound (3 voices + LFSR noise),
   dual MOS 6522 VIAs (8x8 keyboard matrix, digital joystick, NMI/IRQ timers),
   automatic RAM expansion detection (unexpanded 5 KB, +3 KB, +8/+16/+24/+32 KB),
   .prg / .crt / .a0 / .20 / .60 / .d64 / .t64 support with KERNAL fast-LOAD &
   serial traps, and embedded VIC-20 KERNAL + BASIC + Character ROMs. */
#ifndef DEMO_VIC20_H
#define DEMO_VIC20_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define VIC20_W        224              /* 56 PAL cycles * 4 px (176 std + border): x3 = 672, or x4 = 896 */
#define VIC20_H        240              /* PAL visible lines 36..275: x3 = 720 */
#define VIC20_FRAME_US 19989            /* 312 lines * 71 cycles / 1,108,405 Hz = 50.03 Hz PAL */

const char *vic20_load(const u8 *ext_kernal, const u8 *ext_basic, const u8 *ext_chargen,
                       const u8 *image, u32 size, const char *path);
void vic20_reset(void);
void vic20_frame(u16 pad, u16 *picture);
void vic20_keyboard(const u8 *usages, int n);
void vic20_typed(char c);
int vic20_width(void);
int vic20_height(void);
const char *vic20_info(void);
u8 *vic20_save_ram(u32 *size, int *battery);
int vic20_save_changed(void);
int vic20_jammed(void);

void vic20_audio_rate(u32 hz);
int vic20_audio(s16 *out, int max);

#endif
