/* coco.c: TRS-80 Color Computer 1/2 (NTSC 60 Hz) & Dragon 32/64 (PAL 50 Hz)
   64 KB home computer emulator with Motorola MC6809 CPU, Motorola MC6883 SAM,
   dual MC6821 PIAs, Motorola MC6847 VDG (all text, semigraphics SG4/SG6, color
   CG1..CG6, resolution RG1..RG6 + CoCo NTSC RG6 blue/orange artifact colors),
   cycle-exact 48 kHz 6-bit DAC + 1-bit sound, analog comparator joysticks,
   built-in Color BASIC executive + optional external ROMs, and .ccc/.rom/.bin/.cas
   loaders. */
#ifndef DEMO_COCO_H
#define DEMO_COCO_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define COCO_W            320           /* 256 active + 32*2 border: x3 = 960 x 720 */
#define COCO_H            240           /* 192 active + 24*2 border: x3 = 960 x 720 */
#define COCO_FRAME_US     16688         /* 14,934 cyc / 894,886 Hz = 59.92 Hz NTSC */
#define DRAGON_FRAME_US   20000         /* 50.00 Hz PAL */

const char *coco_load(const u8 *bas_rom, const u8 *ext_rom,
                      const u8 *image, u32 size, const char *path);
const char *dragon_load(const u8 *d32_rom,
                        const u8 *image, u32 size, const char *path);
void coco_reset(void);
void coco_frame(u16 pad, u16 *picture);
void coco_keyboard(const u8 *usages, int n);
void coco_typed(char c);
int coco_width(void);
int coco_height(void);
const char *coco_info(void);
int coco_jammed(void);

void coco_audio_rate(u32 hz);
int coco_audio(s16 *out, int max);

#endif
