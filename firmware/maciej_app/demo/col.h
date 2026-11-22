/* col.c: a ColecoVision (with MegaCart bank switching and Super Game Module
   32 KB RAM + AY-3-8910 support).

   CPU: Zilog Z80A (z80.c) at 3.579545 MHz (228 T-states/line, 262 lines,
   59.92 Hz).  Picture: Texas Instruments TMS9928A (256 x 192, 16 KB VRAM,
   15-bit RGB pixels, VBlank edge driving Z80 NMI -> $0066 -> $8021).
   Sound: TI SN76489A 3-tone + noise PSG (plus SGM AY-3-8910), 48 kHz mono.
   BIOS: uses coleco.rom (8 KB) when supplied, or a built-in clean-room OS-7
   compatible BIOS & 8x8 ASCII font ($15A3) so cartridges run standalone. */
#ifndef DEMO_COL_H
#define DEMO_COL_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define COL_W        256
#define COL_H        192
#define COL_FRAME_US 16688

/* Pad bits match play.c's PAD_* */
#define COL_FIRE1    0x0001     /* Left fire (X / OK) */
#define COL_FIRE2    0x0002     /* Right fire (Z / 0) */
#define COL_SELECT   0x0004     /* Keypad * (Tab / Space / INFO) */
#define COL_START    0x0008     /* Keypad 1 (Enter / MENU) */
#define COL_UP       0x0010
#define COL_DOWN     0x0020
#define COL_LEFT     0x0040
#define COL_RIGHT    0x0080
#define COL_SHARP    0x0100     /* Keypad # (C) */
#define COL_KEY2     0x0200     /* Keypad 2 (V) */
#define COL_KEY3     0x0400     /* Keypad 3 (Q) */
#define COL_KEY4     0x0800     /* Keypad 4 (E) */

/* Explicit keypad override: 0..9, 10 = *, 11 = #, 0xFF = none */
void col_set_key(u8 key);

const char *col_load(const u8 *bios8k, u8 *cart, u32 cart_size);
void col_reset(void);
void col_frame(u16 pad, u16 *picture);
const char *col_info(void);
u8 *col_save_ram(u32 *size, int *battery);
int col_save_changed(void);
int col_jammed(void);

void col_audio_rate(u32 hz);
int col_audio(s16 *out, int max);

#endif
