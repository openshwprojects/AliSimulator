/* konami.c: Konami Classic Arcade Multi-Board Emulator (.zip; "" = built-in game).

   Supported Konami Arcade Hardware Families:
   1. TMNT2 / Sunset Riders / X-Men (12/16 MHz 68000 + 3.58 MHz Z80 + K052109 3-layer
      tilemaps + K053245/K053244 hardware-zoomed sprites + K053251 PCU1 priority +
      YM2151 OPM FM + K053260 4-ch PCM/KADPCM).
   2. TMNT / MIA / Punk Shot (10 MHz 68000 + 3.58 MHz Z80 + K052109 + K051960/K051937
      hardware-zoomed sprites + YM2151 + K007232 dual-ch PCM).
   3. GX400 Nemesis / Gradius / TwinBee (10 MHz 68000 + 3.58 MHz Z80 + 64 KB dynamic
      character RAM + dual rowscroll playfields + zoomed sprites + dual AY-3-8910 + K005289).
   4. Contra / Gryzor (3 MHz Motorola MC6809E / Konami-1 via m6809.inc + 3.58 MHz Z80 +
      dual K007121 tilemap/sprite ASICs + YM2151 FM). */
#ifndef DEMO_KONAMI_H
#define DEMO_KONAMI_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define KONAMI_W_MAX    320
#define KONAMI_H_MAX    240
#define KONAMI_FRAME_US 16667   /* 60.00 Hz */

int konami_is_zip(const u8 *zip, u32 size, const char *name);
const char *konami_load(const u8 *image, u32 size, const char *path);
void konami_reset(void);
void konami_frame(u16 pad, u16 *picture);
void konami_pad2(u16 pad);
int konami_width(void);
int konami_height(void);
const char *konami_info(void);
u8 *konami_save_ram(u32 *size, int *battery);
int konami_save_changed(void);
int konami_jammed(void);
void konami_audio_rate(u32 hz);
int konami_audio(s16 *out, int max);

#endif
