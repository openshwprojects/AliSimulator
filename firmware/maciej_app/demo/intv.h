/* Mattel Intellivision (.int / .rom) emulator */
#ifndef DEMO_INTV_H
#define DEMO_INTV_H

#define INTV_W        176
#define INTV_H        208
#define INTV_FRAME_US 16683u   /* 59.94 Hz NTSC (14,934 CP1610 cycles/frame @ 894.886 kHz) */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;

void intv_set_bios(const u8 *exec_data, u32 exec_size, const u8 *grom_data, u32 grom_size);
int intv_is_rom(const u8 *head, u32 got, u32 total_size);
const char *intv_load(const u8 *data, u32 size);
const char *intv_info(void);
void intv_set_key(u8 key);                     /* 0..9, 10=Clear, 11=Enter, 0xFF=none */
void intv_frame(u16 pad, u16 *picture);        /* 176 x 208 15-bit BGR555 */
int intv_jammed(void);
u8 *intv_save_ram(u32 *size, int *battery);
int intv_save_changed(void);
void intv_audio_rate(u32 hz);
int intv_audio(s16 *out, int max);

#endif
