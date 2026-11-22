/* Magnavox Odyssey2 / Philips Videopac G7000 (.o2) emulator */
#ifndef DEMO_O2_H
#define DEMO_O2_H

#define O2_W        160
#define O2_H        240
#define O2_FRAME_US 16683u   /* 59.94 Hz NTSC (Intel 8244, 262 lines) */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;

void o2_set_bios(const u8 *data, u32 size);
const char *o2_load(const u8 *data, u32 size);
const char *o2_info(void);
void o2_set_key(u8 key);                    /* 0x00..0x2F Odyssey2 keycode, or 0xFF: none */
void o2_frame(u16 pad, u16 *picture);       /* 160 x 240 15-bit BGR555 */
int o2_jammed(void);
u8 *o2_save_ram(u32 *size, int *battery);
int o2_save_changed(void);
void o2_audio_rate(u32 hz);
int o2_audio(s16 *out, int max);

#endif
