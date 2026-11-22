/* z80con.c: Casio PV-1000 (1983) and Bally Astrocade (1978) consoles,
   sharing the Z80 core (z80.c) and EMU_RAM_PHYS workspace:
   - Casio PV-1000 ('pv1000'): 3.579545 MHz Z80, NEC D65010G031 VDP (256x192
     3-bit RGB tile + PCG graphics, 16-step VBlank matrix/prerender IRQs) and
     3-channel square/XOR resistor-weighted PSG at 48 kHz.
   - Bally Astrocade ('astro'): 1.7897725 MHz Z80, custom Data Chip (160x102 /
     320x204 2bpp screen RAM, Magic RAM expand/rotate/shift/flop/OR/XOR blitter
     with hardware collision intercept, per-line 256-colour YUV left/right split
     palette, IM 2 raster interrupts), 3-voice + vibrato + 15-bit LFSR noise
     synthesizer at 48 kHz, 4-port joystick/knob/24-key keypad, and clean-room
     built-in 8 KB EXEC BIOS (with optional external astro.bin override). */
#ifndef DEMO_Z80CON_H
#define DEMO_Z80CON_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define PV1000_W        256
#define PV1000_H        192
#define ASTRO_W         320
#define ASTRO_H         204
#define Z80CON_W_MAX    320
#define Z80CON_H_MAX    204
#define Z80CON_FRAME_US 16688

const char *pv1000_load(const u8 *rom, u32 rom_size);
const char *astro_load(const u8 *bios, u32 bios_size, const u8 *rom, u32 rom_size);

void z80con_reset(void);
void z80con_frame(u16 pad, u16 *picture);
int  z80con_width(void);
int  z80con_height(void);
const char *z80con_info(void);
int  z80con_jammed(void);

void z80con_keyboard(const u8 *usages, int n);
void z80con_typed(char c);

void z80con_audio_rate(u32 hz);
int  z80con_audio(s16 *out, int max);

#endif
