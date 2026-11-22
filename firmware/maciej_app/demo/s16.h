/* s16.c: Sega System 16A, System 16B & OutRun-Road arcade hardware.

   Main CPU: Motorola MC68000 (m68k.inc) at 10.0 / 12.5 MHz, with fmap[]
   support for Hitachi FD1089A/B and FD1094 decrypted opcode tables.
   Sound CPU: Zilog Z80A (z80.c) at 4.0 / 5.0 MHz, with op[] support for
   NEC MC-8123 decrypted sound programs.
   Memory Mapper: Sega 315-5195 8-region programmable mapper (System 16B)
   plus System 16A fixed map and OutRun road-scaler extension.
   Video (320 x 224 at 60 Hz):
     - Sega 315-5197 Tilemap Generator: Text/Fix layer + Foreground &
       Background scrollable 4-page 64x32 planes with rowscroll & colscroll
       and switchable tile banks.
     - Sega 16-bit Hardware-Zoomed Sprite Generator (16A, 16B & OutRun modes)
       with 4-level tilemap priority, H/V flip, and Shadow / Highlight pens.
     - Optional pseudo-3D dual-stripe perspective Road Generator (S16R).
     - 2048-entry 15-bit RGB + Shadow/Highlight palette CRAM ($840000).
   Audio (48 kHz):
     - Yamaha YM2151 (OPM) 8-channel 4-operator FM synthesizer
     - NEC uPD7759 ADPCM voice/percussion decoder
     - Sega 315-5218 16-channel digital PCM sample player
   Supports pre-packed .s16 arcade cartridges (tools/s16_pack.py) and
   direct MAME System 16A / 16B .zip romsets. */
#ifndef DEMO_S16_H
#define DEMO_S16_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define S16_W        320
#define S16_H        224
#define S16_FRAME_US 16667

int s16_is_zip(const u8 *zip, u32 size);
const char *s16_load(u8 *rom, u32 size, const char *path);
void s16_reset(void);
void s16_frame(u16 pad, u16 *picture);
const char *s16_info(void);
u8 *s16_save_ram(u32 *size, int *battery);
int s16_save_changed(void);
int s16_jammed(void);

void s16_audio_rate(u32 hz);
int s16_audio(s16 *out, int max);

#endif
