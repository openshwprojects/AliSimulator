/* vb.c: Nintendo Virtual Boy (1995) emulator:
   - 20 MHz 32-bit NEC V810 RISC CPU (P_REG[0..31], S_REG[0..31], 128-entry
     instruction cache, BSTR bitstring search/logic ops, Virtual Boy custom
     XB/XH/REV/MPYHW instructions, and pure-integer IEEE-754 single-precision
     FPU with V810 exponent wrap so -msoft-float -nostdlib needs zero libgcc)
   - Virtual Image Processor (VIP): 384 x 224 dual-eye display @ 50.27 Hz,
     32 Worlds (Normal, HBias per-scanline scroll, Affine 2D zoom/rotation,
     and 4 OBJ sprite groups up to 1024 sprites), column-table brightness
     modulation (BRTA/BRTB/BRTC/REST/Repeat), and 4 selectable display modes:
     0 = Classic Red/Black, 1 = Red/Cyan 3D Anaglyph, 2 = White, 3 = Amber
   - Virtual Sound Unit (VSU): 6 stereo channels (5 x 32-sample 6-bit wavetable
     channels with sweep/modulation on ch 5 + 15-bit programmable-tap LFSR noise
     on ch 6) synthesized at 48 kHz
   - Hardware 20 us / 100 us reload timer, serial dual-D-pad controller, and
     up to 64 KB battery-backed cartridge SRAM (.sav). */
#ifndef DEMO_VB_H
#define DEMO_VB_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;

#define VB_W        384
#define VB_H        224
#define VB_FRAME_US 19891

enum {
    VB_MODE_RED      = 0,
    VB_MODE_ANAGLYPH = 1,
    VB_MODE_WHITE    = 2,
    VB_MODE_AMBER    = 3
};

const char *vb_load(const u8 *rom, u32 rom_size);
void        vb_reset(void);
void        vb_frame(u16 pad, const u8 *hid, int hid_n, u16 *picture);
const char *vb_info(void);
int         vb_jammed(void);

void        vb_set_mode(int mode);
int         vb_get_mode(void);

u8         *vb_save_ram(u32 *size, int *battery);
int         vb_save_changed(void);

void        vb_audio_rate(u32 hz);
int         vb_audio(s16 *out, int max);

#endif
