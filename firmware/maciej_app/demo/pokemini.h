/* pokemini.c: Nintendo Pokemon Mini (2001) handheld console emulator (.min)
   with 4 MHz Seiko S1C88 CPU, 96x64 5-shade analog LCD + PRC tile/sprite/copy
   engine, 3x 16-bit timers + 256 Hz / RTC counters, 8 KB I2C EEPROM (.sav),
   shock sensor + rumble offset, 48 kHz Direct-PWM piezo audio, and embedded
   4 KB FreeBIOS (plus optional external bios.min in pokemini/). */
#ifndef DEMO_POKEMINI_H
#define DEMO_POKEMINI_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define PM_W        96
#define PM_H        64
#define PM_FRAME_US 13889               /* 72 Hz native refresh */

const char *pokemini_load(const u8 *ext_bios, u8 *image, u32 size);
void pokemini_reset(void);
void pokemini_frame(u16 pad, const u8 *hid, int hid_n, u16 *picture);
const char *pokemini_info(void);
u8 *pokemini_save_ram(u32 *size, int *battery);
int pokemini_save_changed(void);
int pokemini_jammed(void);

void pokemini_audio_rate(u32 hz);
int pokemini_audio(s16 *out, int max);

#endif
