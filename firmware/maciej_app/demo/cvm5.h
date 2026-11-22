/* cvm5.c: Dual TMS9918A/TMS9929A + SN76489A console/home-computer core:
   1. VTech CreatiVision / Dick Smith Wizzard / Hanimex Rameses (cv):
      2.0 MHz MOS 6502, MC6821 PIA keyboard/joysticks, TMS9929A PAL VDP,
      TI SN76489A PSG, 4K..32K cartridge mapper, and built-in 2 KB BIOS.
   2. Sord M5 / CGL M5 (m5):
      3.58 MHz Zilog Z80, Z80 CTC (IM2 VDP interrupt chaining), TMS9918A NTSC
      VDP, SN76489AN PSG, 36 KB RAM, 4K..20K cartridge ROM, and built-in 8 KB
      Monitor BIOS. */
#ifndef DEMO_CVM5_H
#define DEMO_CVM5_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define CVM5_W          256             /* x3 = 768 x 576 centered on 1280 x 720 */
#define CVM5_H          192
#define CV_FRAME_US     20000           /* 50.00 Hz PAL (TMS9929A) */
#define M5_FRAME_US     16688           /* 59.92 Hz NTSC (TMS9918A) */

const char *cv_load(const u8 *ext_bios2k, const u8 *cart, u32 cart_size);
const char *m5_load(const u8 *ext_bios8k, const u8 *cart, u32 cart_size);
void cvm5_reset(void);
void cvm5_frame(u16 pad, u16 *picture);
void cvm5_keyboard(const u8 *usages, int n);
void cvm5_typed(char c);
int cvm5_width(void);
int cvm5_height(void);
const char *cvm5_info(void);
int cvm5_jammed(void);

void cvm5_audio_rate(u32 hz);
int cvm5_audio(s16 *out, int max);

#endif
