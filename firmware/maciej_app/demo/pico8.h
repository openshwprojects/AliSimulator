/* PICO-8 Fantasy Console Emulator for Maciej v4 (ALi S3811)
   - 128x128 16-colour display (plus secret 128..143 extended palette -> 32 colours),
     32 KB PICO-8 memory map ($0000..$7FFF) & 256 B persistent cartdata (.sav)
   - Loads both .p8 text cartridges (__lua__, __gfx__, __gff__, __map__, __sfx__, __music__)
     and .p8.png 160x205 RGBA steganography cartridges (raw, :c:\0, and \0pxa compressed!)
   - 16.16 fixed-point PICO-8 Lua VM (+=, -=, *=, /=, !=, //, ?print, tables, add/del/all/foreach,
     closures/functions, full PICO-8 graphics/map/sprite/input/math/peek/poke API)
   - 4-channel 48 kHz PICO-8 waveform synthesizer + pattern music sequencer
   - Built-in playable cartridge (""): "CELESTEPEAK-8"! */
#ifndef DEMO_PICO8_H
#define DEMO_PICO8_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define PICO8_W         128
#define PICO8_H         128
#define PICO8_FRAME_US  16667u          /* 60.00 Hz (30 fps _update carts paced internally at 30 Hz) */

const char *pico8_load(const u8 *image, u32 size, const char *path);
void pico8_reset(void);
void pico8_frame(u16 pad, u16 *picture);
void pico8_pad2(u16 pad);

const char *pico8_info(void);

u8 *pico8_save_ram(u32 *size, int *battery);
int pico8_save_changed(void);
int pico8_jammed(void);

void pico8_audio_rate(u32 hz);
int pico8_audio(s16 *out, int max);

int pico8_is_p8_png_name(const char *name);

#endif
