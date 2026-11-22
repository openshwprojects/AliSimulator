/* sv.c: a Watara Supervision handheld console (.sv) -- 4 MHz WDC 65SC02 CPU,
   160 x 160 4-shade 2bpp LCD framebuffer with hardware scroll & CPU/VRAM DMA,
   programmable timer + VBlank NMI, 16 KB..512 KB (Magnum) bank switching, and
   4-channel 48 kHz audio (2 pulse + 4-bit ADPCM DMA + LFSR noise). */
#ifndef DEMO_SV_H
#define DEMO_SV_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define SV_W        160
#define SV_H        160
#define SV_FRAME_US 16384               /* 65536 cycles @ 4.000 MHz (~61.035 Hz) */

const char *sv_load(u8 *image, u32 size);
void sv_reset(void);
void sv_frame(u16 pad, u16 *picture);
const char *sv_info(void);
u8 *sv_save_ram(u32 *size, int *battery);
int sv_save_changed(void);
int sv_jammed(void);

void sv_audio_rate(u32 hz);
int sv_audio(s16 *out, int max);

#endif
