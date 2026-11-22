/* vec.c: a GCE / Milton Bradley Vectrex (.vec).

   CPU: 1.5 MHz Motorola MC6809 (full instruction set including all indexed modes,
   EXG/TFR, MUL, DAA, CWAI/SYNC, page $10 & $11 opcodes, FIRQ/IRQ/NMI).
   Hardware: MOS 6522 VIA ($D000..$D00F: T1 ~RAMP beam timer, T2 frame timer, shift
   register ~BLANK beam/raster modulator, CA2 ~ZERO integrator clamp, DAC + 4-ch
   CD4052 analog S/H MUX, successive-approximation joystick comparator).
   Picture: 270 x 360 portrait (3:4 CRT aspect, shown twice as large: 540 x 720) in
   15-bit BGR555 with anti-aliased phosphor vector lines, endpoint bloom, and subtle
   CRT persistence decay.
   Sound: General Instrument AY-3-8912 3-channel PSG + VIA MUX direct DAC audio mixed
   at 48 kHz.
   System ROM: Optional 8 KB vectrex.rom (or 4 KB fastboot/exec) in vec/; otherwise
   built-in clean-room Vectrex Executive BIOS ($F000..$FFFF) + built-in playable
   Vector Storm game when started with no cartridge file. */
#ifndef DEMO_VEC_H
#define DEMO_VEC_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define VEC_W        270
#define VEC_H        360
#define VEC_FRAME_US 20000              /* 30,000 cycles @ 1.5 MHz = 50.00 Hz nominal */

/* Pad bits match play.c's PAD_* (Vectrex has analog stick + Buttons 1..4):
   Button 1 = Q / C (PAD_L / PAD_X)
   Button 2 = V / Tab (PAD_Y / PAD_SELECT)
   Button 3 = Z (PAD_B)
   Button 4 = X (PAD_A, primary fire / thrust in most Vectrex games!) */
#define VEC_PAD_A      0x0001           /* X = Button 4 (primary fire) */
#define VEC_PAD_B      0x0002           /* Z = Button 3 */
#define VEC_PAD_SELECT 0x0004           /* Tab = Button 2 */
#define VEC_PAD_START  0x0008           /* Enter = Button 1 (start / select option) */
#define VEC_PAD_UP     0x0010
#define VEC_PAD_DOWN   0x0020
#define VEC_PAD_LEFT   0x0040
#define VEC_PAD_RIGHT  0x0080
#define VEC_PAD_X      0x0100           /* C = Button 1 */
#define VEC_PAD_Y      0x0200           /* V = Button 2 */
#define VEC_PAD_L      0x0400           /* Q = Button 1 */
#define VEC_PAD_R      0x0800           /* E = Button 4 */

void vec_set_bios(const u8 *rom, u32 size);

const char *vec_load(u8 *image, u32 size);
void vec_reset(void);
void vec_frame(u16 pad, u16 *picture);
const char *vec_info(void);
u8 *vec_save_ram(u32 *size, int *battery);
int vec_save_changed(void);
int vec_jammed(void);

void vec_audio_rate(u32 hz);
int vec_audio(s16 *out, int max);

#endif
