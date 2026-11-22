/* arcadia.c: Signetics 2650 & RCA COSMAC CDP1802 classic consoles:
   - Emerson Arcadia 2001 ('arcadia', .a2k / .bin): Signetics 2650 CPU at
     895 kHz + Signetics 2637 UVI (128x208 tile/block/UDG display, 4 hardware
     sprites, hardware collision, 15.7 kHz tone + 9-bit TIA LFSR noise).
   - Interton VC 4000 ('vc4000', .vc4 / .bin): Signetics 2650 CPU at 887 kHz +
     Signetics 2636 PVI (programmable playfield grid, 4 hardware objects with
     retrigger/scaling, 4-digit 7-segment BCD score LEDs, tone audio).
   - RCA Studio II ('studio2', .st2 / .bin; "" runs built-in game): RCA COSMAC
     CDP1802 CPU at 1.76 MHz + CDP1861 Pixie DMA video (64x32 -> 256x128),
     CA555 Q-gated tone oscillator, dual 10-key keypads, and clean-room 2 KB
     built-in Studio II BIOS + game ROM (with optional studio2.bin override). */
#ifndef DEMO_ARCADIA_H
#define DEMO_ARCADIA_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define ARCADIA_W       160
#define ARCADIA_H       208
#define VC4000_W        192
#define VC4000_H        224
#define STUDIO2_W       256
#define STUDIO2_H       128

#define ARC_W_MAX       256
#define ARC_H_MAX       224
#define ARCADIA_FRAME_US 16688
#define VC4000_FRAME_US  20000
#define STUDIO2_FRAME_US 16667

const char *arcadia_load(const u8 *rom, u32 rom_size);
const char *vc4000_load(const u8 *rom, u32 rom_size);
const char *studio2_load(const u8 *bios, u32 bios_size, const u8 *rom, u32 rom_size);

void arc_reset(void);
void arc_frame(u16 pad, u16 *picture);
int  arc_width(void);
int  arc_height(void);
u32  arc_frame_us(void);
const char *arc_info(void);
int  arc_jammed(void);

void arc_keyboard(const u8 *usages, int n);
void arc_typed(char c);

void arc_audio_rate(u32 hz);
int  arc_audio(s16 *out, int max);

#endif
