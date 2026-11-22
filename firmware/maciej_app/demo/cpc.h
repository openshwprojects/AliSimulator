/* cpc.c: Amstrad CPC 464 / 6128 + GX4000 (.sna, .dsk, .bin, .cpr) home computer
   and console emulator with 4 MHz Z80 (z80.c), UM6845R CRTC, Amstrad 40010 Gate
   Array (Modes 0/1/2, 128 KB RAM banking, 52-line HSync IRQ counter), Intel 8255
   PPI, 1 MHz AY-3-8912 3-channel 48 kHz PSG, NEC uPD765 FDC (.dsk standard &
   extended floppies with auto-boot), .sna v1-v3 snapshots, GX4000 .cpr RIFF
   cartridges, and embedded CPC 6128 OS + Locomotive BASIC 1.1 + AMSDOS ROMs. */
#ifndef DEMO_CPC_H
#define DEMO_CPC_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define CPC_W_STD    384                /* 48 CRTC chars * 8 px (320 active + border): x3 = 1152 x 720 */
#define CPC_W_HI     640                /* Mode 2 80-column hi-res: x2 x3 = 1280 x 600 */
#define CPC_H_STD    240                /* 200 active lines + 20 top / 20 bottom border: x3 = 720 */
#define CPC_H_HI     200
#define CPC_W_MAX    640
#define CPC_H_MAX    240
#define CPC_FRAME_US 19968              /* 312 lines * 64 us = 50.08 Hz PAL */

const char *cpc_load(const u8 *ext_os, const u8 *ext_basic, const u8 *ext_amsdos,
                     u8 *image, u32 size, const char *path);
void cpc_reset(void);
void cpc_frame(u16 pad, u16 *picture);
void cpc_keyboard(const u8 *usages, int n);
void cpc_typed(char c);
int cpc_width(void);
int cpc_height(void);
const char *cpc_info(void);
u8 *cpc_save_ram(u32 *size, int *battery);
int cpc_save_changed(void);
int cpc_jammed(void);

void cpc_audio_rate(u32 hz);
int cpc_audio(s16 *out, int max);

#endif
