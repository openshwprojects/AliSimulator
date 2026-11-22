/* apple2.c: Apple IIe Enhanced (128 KB) home computer emulator with 1.0205 MHz
   WDC 65C02, Main + Auxiliary 64 KB RAM + 16 KB Language Card, Text 40/80,
   Lo-Res / Double Lo-Res, NTSC Artifact Hi-Res (280x192) & Double Hi-Res
   (560x192), Disk II 16-sector GCR controller (.dsk, .do, .po, .nib with .sav
   writeback), cycle-exact 48 kHz $C030 speaker + Slot 4 Mockingboard AY-3-8910,
   joystick/paddles, and embedded Apple IIe Enhanced + Disk II ROMs. */
#ifndef DEMO_APPLE2_H
#define DEMO_APPLE2_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define A2_W_STD    280                 /* 40 cols * 7 px: x3 = 840 x 576 on 720p TV */
#define A2_W_HI     560                 /* 80-col / Double Hi-Res: x2 x3 = 1120 x 576 */
#define A2_H        192                 /* 24 text rows * 8 px: x3 = 576 */
#define A2_W_MAX    560
#define A2_FRAME_US 16688               /* 17,030 cycles / 1,020,484 Hz = 59.92 Hz NTSC */

const char *apple2_load(const u8 *ext_rom16k, const u8 *ext_char4k, const u8 *ext_disk256,
                        const u8 *image, u32 size, const char *path);
void apple2_reset(void);
void apple2_frame(u16 pad, u16 *picture);
void apple2_keyboard(const u8 *usages, int n);
void apple2_typed(char c);
int apple2_width(void);
int apple2_height(void);
const char *apple2_info(void);
u8 *apple2_save_ram(u32 *size, int *battery);
int apple2_save_changed(void);
int apple2_jammed(void);

void apple2_audio_rate(u32 hz);
int apple2_audio(s16 *out, int max);

#endif
