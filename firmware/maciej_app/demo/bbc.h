/* bbc.c: BBC Micro Model B (32K + Sideways ROM/RAM) & Acorn Electron Emulator
   - 2 MHz MOS 6502 + Motorola MC6845 CRTC + Acorn Video ULA (Modes 0..6) + SAA5050 Teletext Mode 7
   - Acorn Electron ULA ($FE00..$FE09) video, 50 Hz RTC, keyboard ROM page 8 & ULA tone
   - Dual 6522 System/User VIAs + 4 MHz TI SN76489 4-ch PSG @ 48 kHz
   - Supports .uef (plain or .gz), .ssd / .dsd (Acorn DFS 80T disks), .rom, and interactive BASIC ("") */
#ifndef DEMO_BBC_H
#define DEMO_BBC_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define BBC_W        320
#define BBC_H        256
#define BBC_FRAME_US 20000      /* 50.00 Hz PAL */

const char *bbc_load(const u8 *image, u32 size, const char *path,
                     const u8 *os_rom, u32 os_sz, const u8 *bas_rom, u32 bas_sz);
void bbc_reset(void);
void bbc_frame(u16 pad, u16 *picture);
void bbc_keyboard(const u8 *usages, int n);
void bbc_typed(char c);
const char *bbc_info(void);
int bbc_jammed(void);
void bbc_audio_rate(u32 hz);
int bbc_audio(s16 *out, int max);

#endif
