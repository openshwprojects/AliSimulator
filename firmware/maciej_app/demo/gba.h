/* gba.c: a Nintendo Game Boy Advance (.gba).

   CPU: 16.78 MHz ARM7TDMI (full 32-bit ARMv4T + 16-bit Thumb instruction sets,
   banked USR/FIQ/SVC/ABT/IRQ/UND registers, accurate barrel-shifter & rotated
   unaligned LDR/SWP, open-bus & BIOS read protection, built-in ARM/HLE BIOS
   covering SWIs 0x00..0x2A + IRQ trampoline, and optional external gba_bios.bin).
   Picture: GBA PPU scanline renderer (240 x 160 in 15-bit BGR555, Modes 0..5,
   text & affine BG2/BG3, 128 normal & affine/double-size OBJs, OBJ window +
   WIN0/WIN1, alpha blend & fade-to-white/black, mosaic).
   DMA & Timers: 4 DMA channels (immediate, VBlank, HBlank, DirectSound FIFO) +
   4 16-bit timers (prescalers & cascade).
   Sound: DirectSound FIFO A & B DMA + 4 Game Boy PSG channels mixed at 48 kHz.
   Save: Auto-detected SRAM (32 KB), Flash 64 KB / 128 KB, and EEPROM (512B/8KB)
   kept in .sav. */
#ifndef DEMO_GBA_H
#define DEMO_GBA_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define GBA_W        240
#define GBA_H        160
#define GBA_FRAME_US 16743              /* 280,896 cycles / 16,777,216 Hz = 59.7275 Hz */

/* Pad bits match play.c's 12-button PAD_* */
#define GBA_PAD_A      0x0001
#define GBA_PAD_B      0x0002
#define GBA_PAD_SELECT 0x0004
#define GBA_PAD_START  0x0008
#define GBA_PAD_UP     0x0010
#define GBA_PAD_DOWN   0x0020
#define GBA_PAD_LEFT   0x0040
#define GBA_PAD_RIGHT  0x0080
#define GBA_PAD_L      0x0400
#define GBA_PAD_R      0x0800

/* Optional external 16 KB GBA BIOS (gba_bios.bin). Pass 0, 0 for built-in BIOS. */
void gba_set_bios(const u8 *rom, u32 size);

const char *gba_load(u8 *image, u32 size);
void gba_reset(void);
void gba_frame(u16 pad, u16 *picture);
const char *gba_info(void);
u8 *gba_save_ram(u32 *size, int *battery);
int gba_save_changed(void);
int gba_jammed(void);

void gba_audio_rate(u32 hz);
int gba_audio(s16 *out, int max);

#endif
