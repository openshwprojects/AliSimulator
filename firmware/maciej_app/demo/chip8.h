/* chip8.c: CHIP-8, SUPER-CHIP 1.1 and XO-CHIP virtual console (.ch8, .sc8, .xo8)
   with 64 KB RAM, 64x32 / 128x64 4-plane 16-colour display, 16-byte RPL save flags
   (.sav), 16-key COSMAC VIP hex keypad + gamepad mapping, and 48 kHz buzzer +
   XO-CHIP 128-bit pattern audio. */
#ifndef DEMO_CHIP8_H
#define DEMO_CHIP8_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define CHIP8_W        128
#define CHIP8_H        64
#define CHIP8_FRAME_US 16667            /* 60 Hz */

const char *chip8_load(u8 *image, u32 size, const char *path);
void chip8_reset(void);
void chip8_frame(u16 pad, const u8 *hid, int hid_n, u16 *picture);
const char *chip8_info(void);
u8 *chip8_save_ram(u32 *size, int *battery);
int chip8_save_changed(void);
int chip8_jammed(void);

void chip8_audio_rate(u32 hz);
int chip8_audio(s16 *out, int max);

#endif
