/* channelf.c: Fairchild Channel F / VES (1976) console emulator (.chf, .bin, .rom)
   with Fairchild F8 CPU (3850 + 3853 SMI), 102x58 visible 8-colour MK4027 VRAM,
   F2102 1-Kbit + 2114 Schach SRAM, 48 kHz 3-tone RC-decay audio, and clean-room
   HLE PSU 3851 BIOS (plus optional external sl31253.bin / sl31254.bin). */
#ifndef DEMO_CHANNELF_H
#define DEMO_CHANNELF_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define CHF_W        102
#define CHF_H        58
#define CHF_FRAME_US 16667              /* 60 Hz NTSC */

const char *channelf_load(const u8 *psu1, const u8 *psu2, u8 *image, u32 size);
void channelf_reset(void);
void channelf_frame(u16 pad, const u8 *hid, int hid_n, u16 *picture);
const char *channelf_info(void);
u8 *channelf_save_ram(u32 *size, int *battery);
int channelf_save_changed(void);
int channelf_jammed(void);

void channelf_audio_rate(u32 hz);
int channelf_audio(s16 *out, int max);

#endif
