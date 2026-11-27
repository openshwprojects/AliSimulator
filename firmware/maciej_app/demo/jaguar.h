/* Atari Jaguar 64-Bit Interactive Multimedia System Emulator for Maciej v4 (ALi S3811)
   Supports .j64, .jag, .rom, .abs, .cof cartridges & homebrew (plus .zip) and
   built-in playable 64-bit CRY 3D tube shooter (""): "TEMPEST JAGUAR 64"!
   Architecture:
     - 13.295 MHz Motorola MC68000 (m68k.inc, zero static .bss)
     - 26.59 MHz Tom 32-bit GPU RISC ($F02100 + 4 KB Local RAM $F03000)
     - 64-bit Object Processor (Bitmap, Scaled Bitmap, GPU-IRQ, Branch & Stop objects)
     - 64-bit Hardware Blitter (Phrase clear, SRCEN copy, CRY Gouraud & Z-buffered spans)
     - 16-bit Atari CRY (65,536-entry LUT -> 0BBBBBGGGGGRRRRR), 16-bit RGB & 256-col CLUT
     - 26.59 MHz Jerry 32-bit DSP RISC ($F1A100 + 8 KB Local RAM $F1B000) + I2S 48 kHz DAC
     - 128-byte 93C46 cartridge EEPROM (.sav) */
#ifndef DEMO_JAGUAR_H
#define DEMO_JAGUAR_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define JAGUAR_W_MAX    320
#define JAGUAR_H_MAX    240
#define JAGUAR_FRAME_US 16667u          /* 60.00 Hz NTSC */

const char *jaguar_load(const u8 *image, u32 size, const char *path);
void jaguar_reset(void);
void jaguar_frame(u16 pad, u16 *picture);
void jaguar_pad2(u16 pad);

int jaguar_width(void);
int jaguar_height(void);
const char *jaguar_info(void);

u8 *jaguar_save_ram(u32 *size, int *battery);
int jaguar_save_changed(void);
int jaguar_jammed(void);

void jaguar_audio_rate(u32 hz);
int jaguar_audio(s16 *out, int max);
int jaguar_is_rom(const u8 *head, u32 len, u32 size);

#endif
