/* jp8bit.c: Japanese 8-Bit Home Computer Legends ('pc88', 'mz700', 'x1')
   - 'pc88' (NEC PC-8801mkIISR): 4.0 MHz Z80 + 64 KB RAM + 48 KB 3-plane GVRAM + Text VRAM +
     Clean-Room N88 Disk Sub-CPU HLE ($37CC/$37D2/$3847) + Yamaha YM2203 OPN (3-ch 4-op FM + 3-ch SSG)
     @ 48 kHz + Keyboard & Atari Joystick (.d88, .n88, "" N88-BASIC)
   - 'mz700' (Sharp MZ-700): 3.58 MHz Z80 + 64 KB banked RAM + 1Z-009A Monitor + 40x25 GRB Display/CGROM
     + Intel 8253 PIT 3-channel timer/audio @ 48 kHz + 8255 PPI keyboard (.mzt, .mzf, "" Monitor)
   - 'x1' (Sharp X1): 4.0 MHz Z80 + 64 KB RAM + 16-bit Z80 I/O space (48 KB GVRAM + 256-char color PCG
     + Text/Attr VRAM + CRTC + Sub-CPU 8049 key HLE) + 2 MHz AY-3-8910 PSG @ 48 kHz (.d88, .2d, .tap, "") */
#ifndef DEMO_JP8BIT_H
#define DEMO_JP8BIT_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define PC88_W         640
#define PC88_H         200
#define PC88_FRAME_US  16667    /* 60.00 Hz */

#define MZ700_W        320
#define MZ700_H        200
#define MZ700_FRAME_US 16667    /* 60.00 Hz */

#define X1_W           320
#define X1_H           200
#define X1_FRAME_US    16667    /* 60.00 Hz */

const char *pc88_load(const u8 *image, u32 size, const char *path);
const char *mz700_load(const u8 *image, u32 size, const char *path);
const char *x1_load(const u8 *image, u32 size, const char *path);

void jp8bit_reset(void);
void jp8bit_frame(u16 pad, u16 *picture);
void jp8bit_keyboard(const u8 *usages, int n);
void jp8bit_typed(char c);
const char *jp8bit_info(void);
int jp8bit_jammed(void);
void jp8bit_audio_rate(u32 hz);
int jp8bit_audio(s16 *out, int max);

#endif
