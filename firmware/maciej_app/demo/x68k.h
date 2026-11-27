/* Sharp X68000 (1987, 10 MHz MC68000 + Cynthia Sprite/BG + CRTC/VC + YM2151 OPM + MSM6258 ADPCM).
   Supports .dim, .xdf, .hdm, .2hd, .dup floppy images (and 2-disk sets via Disk 2), .hdf SASI HD images,
   and standalone Human68k .x executables; optional iplrom.dat (128 KB) & cgrom.dat (768 KB) in x68k/
   or built-in clean-room IPL/IOCS ROM + CGROM. */
#ifndef DEMO_X68K_H
#define DEMO_X68K_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;

#define X68K_W_MAX      768
#define X68K_H_MAX      512
#define X68K_FRAME_US   18034u          /* 55.45 Hz standard X68000 31 kHz mode (also supports 15 kHz ~60 Hz) */

#define X68K_PAD_A      0x0001u         /* Joypad Button 1 (Z / Space / remote OK) */
#define X68K_PAD_B      0x0002u         /* Joypad Button 2 (X / remote 0) */
#define X68K_PAD_SELECT 0x0004u         /* XF1 / Space (Tab / remote INFO) */
#define X68K_PAD_START  0x0008u         /* Return / CR (Enter / remote MENU) */
#define X68K_PAD_UP     0x0010u
#define X68K_PAD_DOWN   0x0020u
#define X68K_PAD_LEFT   0x0040u
#define X68K_PAD_RIGHT  0x0080u

int x68k_is_image(const u8 *head, u32 size, const char *name);
void x68k_set_roms(const u8 *ipl, u32 ipl_size, const u8 *cg, u32 cg_size);
void x68k_set_disk2(const u8 *disk2, u32 disk2_size);
const char *x68k_load(const u8 *image, u32 size, const char *name);
const char *x68k_info(void);
void x68k_frame(u16 pad, u16 *picture);
int x68k_width(void);
int x68k_height(void);
u8 *x68k_save_ram(u32 *size, int *battery);
int x68k_save_changed(void);
int x68k_jammed(void);
void x68k_keys_from_hid(const u8 *usages, int n);
void x68k_type(const char *s);
void x68k_mouse(int dx, int dy, int buttons);
void x68k_audio_rate(u32 hz);
int x68k_audio(s16 *out, int max_samples);

#endif
