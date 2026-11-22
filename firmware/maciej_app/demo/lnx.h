/* lnx.c: an Atari Lynx (.lnx / .lyx).

   CPU: WDC 65SC02 (4 MHz effective, CMOS 65C02 + Rockwell bit ops + WAI/STP).
   Mikey ($FD00..$FDFF): 8 cascadable hardware timers, 4-channel shift-register /
   polynomial / direct-DAC audio mixed at 48 kHz, 16-colour 12-bit GBR444 palette,
   cartridge shift-register + audin bank addressing, MAPCTL ($FFF9) memory overlay.
   Suzy ($FC00..$FCFF): 16x16->32 hardware multiply/accumulate & 32/16 divide math
   unit, chained SCB hardware sprite engine (literal & RLE 1..4 bpp, 4-quadrant,
   fixed-point H/V scaling, stretch & tilt, pen palette remap, collision buffer).
   Picture: 160 x 102 (or 102 x 160 when rotated left/right per .lnx header) in
   15-bit BGR555.
   Boot: Built-in Lynx cartridge directory / BLL / encrypted-header loader +
   optional 512-byte lynxboot.img in lynx/. */
#ifndef DEMO_LNX_H
#define DEMO_LNX_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define LNX_W        160
#define LNX_H        102
#define LNX_FRAME_US 16667              /* 60.00 Hz nominal LCD refresh */

/* Pad bits match play.c's PAD_* */
#define LNX_PAD_A      0x0001           /* Outer A button */
#define LNX_PAD_B      0x0002           /* Inner B button */
#define LNX_PAD_OPT2   0x0004           /* Tab / Select = Option 2 */
#define LNX_PAD_PAUSE  0x0008           /* Enter / Start = Pause */
#define LNX_PAD_UP     0x0010
#define LNX_PAD_DOWN   0x0020
#define LNX_PAD_LEFT   0x0040
#define LNX_PAD_RIGHT  0x0080
#define LNX_PAD_OPT1   0x0400           /* Q (or C) = Option 1 */

void lnx_set_bios(const u8 *rom, u32 size);

const char *lnx_load(u8 *image, u32 size);
void lnx_reset(void);
void lnx_frame(u16 pad, u16 *picture);
int lnx_width(void);
int lnx_height(void);
const char *lnx_info(void);
u8 *lnx_save_ram(u32 *size, int *battery);
int lnx_save_changed(void);
int lnx_jammed(void);

void lnx_audio_rate(u32 hz);
int lnx_audio(s16 *out, int max);

#endif
