/* ws.c: a Bandai WonderSwan and WonderSwan Color (SPHINX SoC).

   CPU: NEC V30MZ (16-bit 80186-compatible core with V30MZ flag & opcode
   semantics) at 3.072 MHz (256 cycles/line, 159 lines/frame, 75.47 Hz).
   Picture: 224 x 144 (or 144 x 224 rotated for vertical games), 2bpp mono
   8-shade LUT and WSC 2bpp / 4bpp planar / 4bpp chunky 12-bit RGB modes,
   BG + FG + FG window + 128 sprites + sprite window, GDMA, HBlank/VBlank
   timers.  Sound: 4-channel wavetable / voice / sweep / LFSR noise + Sound
   DMA at 48 kHz (exact 64 CPU clocks per sample).  Cartridge SRAM / EEPROM
   kept in .sav. */
#ifndef DEMO_WS_H
#define DEMO_WS_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define WS_W        224
#define WS_H        144
#define WS_FRAME_US 13250               /* 40704 / 3.072 MHz = 13250 us (75.47 Hz) */

/* Pad bits match play.c's PAD_* */
#define WS_A        0x0001
#define WS_B        0x0002
#define WS_SELECT   0x0004              /* mapped to Start / Y-pad helper */
#define WS_START    0x0008
#define WS_UP       0x0010              /* X1 */
#define WS_DOWN     0x0020              /* X3 */
#define WS_LEFT     0x0040              /* X4 */
#define WS_RIGHT    0x0080              /* X2 */
#define WS_Y1       0x0100              /* C / I */
#define WS_Y2       0x0200              /* V / U */
#define WS_Y3       0x0400              /* Q / L */
#define WS_Y4       0x0800              /* E / O */

const char *ws_load(u8 *image, u32 size, int prefer_color);
void ws_reset(void);
void ws_frame(u16 pad, u16 *picture);
int ws_width(void);
int ws_height(void);
const char *ws_info(void);
u8 *ws_save_ram(u32 *size, int *battery);
int ws_save_changed(void);
int ws_jammed(void);

void ws_audio_rate(u32 hz);
int ws_audio(s16 *out, int max);

#endif
