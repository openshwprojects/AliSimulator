/* Nintendo 64 (NUS, 1996) 64-Bit 3D Console Emulator for Maciej v4 (ALi S3811)
   Supports .z64 (Big-Endian), .v64 (Doctor V64 byte-swapped), and .n64 (LE)
   cartridges (plus .zip), with built-in playable 3D Fast3D/F3DEX showcase (""):
   "STAR WING 64"!
   Architecture (zero static .bss — 8 MB Expansion-Pak RDRAM in EMU_RAM_PHYS):
     - 93.75 MHz NEC VR4300 (MIPS III 64-bit integer + 32-entry TLB + pure-integer
       bit-exact COP1 IEEE-754 single/double FPU, zero libgcc 64-bit division)
     - 8 MB RDRAM (0x03580000..0x03D7FFFF) + up to 16 MB Cart ROM (0x06900000)
     - PIF HLE IPL3 boot (CIC-6101/6102/6103/6105/6106) + Joybus N64 Pad + EEPROM/SRAM (.sav)
     - RCP: SP (DMEM/IMEM + scalar RSP + HLE Fast3D / F3DEX / F3DEX2 & ABI audio),
       DPC/RDP (16-bit Z-buffered Gouraud + TMEM textured triangles, TexRect & FillRect),
       MI, VI (16/32-bpp scanout), AI (DMA stereo PCM -> 48 kHz), PI (Cart DMA), RI, SI */
#ifndef DEMO_N64_H
#define DEMO_N64_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define N64_W_MAX    320
#define N64_H_MAX    240
#define N64_FRAME_US 16667u             /* 60.00 Hz VI field rate (3D games run 20-60 fps) */

const char *n64_load(const u8 *image, u32 size, const char *path);
void n64_reset(void);
void n64_frame(u16 pad, u16 *picture);

int n64_width(void);
int n64_height(void);
const char *n64_info(void);

u8 *n64_save_ram(u32 *size, int *battery);
int n64_save_changed(void);
int n64_jammed(void);

void n64_audio_rate(u32 hz);
int n64_audio(s16 *out, int max);
int n64_is_rom(const u8 *head, u32 len, u32 size);

#endif
