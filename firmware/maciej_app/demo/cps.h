/* cps.c: Capcom CPS-1, CPS-1.5 (QSound Dash) & CPS-2 arcade boards (.cps, .zip).

   Main CPU: Motorola 68000 (m68k.inc) at 10 / 12 MHz (CPS-1) or 16 MHz (CPS-2)
   with separate encrypted/decrypted fetch vs data maps (CPS-2 dual 4-round
   Feistel network + 20-byte .key / built-in key table), 192 KB GFX/scroll/obj
   RAM ($900000..$92FFFF), 64 KB work RAM ($FF0000..$FFFFFF), 2 x 32 KB banked
   CPS-2 object RAM ($708000..$70FFFF), 16 KB extra RAM ($660000..$663FFF),
   CPS-A & CPS-B custom registers ($800100..$8001FF, hardware 16x16 multiply,
   board IDs, layer/palette/priority masks), and 128-byte 93C46 EEPROM (.sav).
   Picture: 384 x 224 15-bit BGR555 (6 x 512 12-bit RGB + 4-bit brightness
   colors = 3,072 active colors from 4,096), 3 hardware tilemap layers (SCROLL1
   8x8, SCROLL2 16x16 with per-scanline rowscroll, SCROLL3 32x32), CPS-1 BgHi
   pen masking, CPS-2 per-sprite 3-bit Z-priority + sprite occlusion Z-buffer,
   and beam-synchronized raster interrupts (IRQ4) + VBlank (IRQ2).
   Sound: Zilog Z80 (z80.c, with Kabuki M1 decryption for CPS-1.5) driving
   Yamaha YM2151 (8-channel 4-operator OPM FM) + OKIM6295 (4-channel ADPCM) on
   CPS-1, or 8 MHz Z80 + Capcom DL-1425 16-voice QSound DSP on CPS-1.5 / CPS-2,
   mixed at 48 kHz. */
#ifndef DEMO_CPS_H
#define DEMO_CPS_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;
typedef unsigned long long u64;

#define CPS_W        384
#define CPS_H        224
#define CPS_FRAME_US 16770              /* 59.6294 Hz (262/259 lines) */

/* Pad bits match play.c's 12-button PAD_* */
#define CPS_PAD_LP     0x0001           /* PAD_A (X): Weak Punch / Attack / Shot */
#define CPS_PAD_MP     0x0002           /* PAD_B (Z): Medium Punch / Jump / Bomb */
#define CPS_PAD_COIN   0x0004           /* PAD_SELECT (Tab/Space): Insert Coin */
#define CPS_PAD_START  0x0008           /* PAD_START (Enter): Start */
#define CPS_PAD_UP     0x0010
#define CPS_PAD_DOWN   0x0020
#define CPS_PAD_LEFT   0x0040
#define CPS_PAD_RIGHT  0x0080
#define CPS_PAD_HP     0x0100           /* PAD_X (C): Strong Punch / Button 3 */
#define CPS_PAD_LK     0x0200           /* PAD_Y (V): Weak Kick / Button 4 */
#define CPS_PAD_MK     0x0400           /* PAD_L (Q): Medium Kick / Button 5 */
#define CPS_PAD_HK     0x0800           /* PAD_R (E): Strong Kick / Button 6 */

/* 1 if head/name is a .cps/.cps1/.cps2 cartridge or a MAME CPS-1/CPS-2 .zip romset */
int cps_is_rom(const u8 *head, u32 n, const char *name);

/* Optional extra RAM region on the box for >16 MB .cps cartridges (0, 0 on host) */
void cps_set_extra(const u8 *extra, u32 extra_size);

const char *cps_load(u8 *image, u32 size, const char *path);
void cps_reset(void);
void cps_frame(u16 pad, u16 *picture);
void cps_pad2(u16 pad);
const char *cps_info(void);
u8 *cps_save_ram(u32 *size, int *battery);
int cps_save_changed(void);
int cps_jammed(void);

void cps_audio_rate(u32 hz);
int cps_audio(s16 *out, int max);

#endif
