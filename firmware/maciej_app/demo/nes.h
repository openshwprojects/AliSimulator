/* nes.c: a NES (Famicom) machine -- its 6502, its picture chip, the cartridge
   boards most games came on.  Nothing in it knows the box: a cartridge image
   in RAM goes in, pictures of 256 x 240 palette entries come out (play.c puts
   them on the TV and reads the buttons; a PC harness runs the same file). */
#ifndef DEMO_NES_H
#define DEMO_NES_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define NES_W 256
#define NES_H 240

/* a controller's buttons, as nes_frame takes them */
#define NES_A      0x01
#define NES_B      0x02
#define NES_SELECT 0x04
#define NES_START  0x08
#define NES_UP     0x10
#define NES_DOWN   0x20
#define NES_LEFT   0x40
#define NES_RIGHT  0x80

const char *nes_load(u8 *image, u32 size);      /* an iNES file in RAM (used where it is, and written when it has
                                                   no CHR ROM): 0, or why it cannot run */
void nes_reset(void);
void nes_frame(u8 pad1, u8 pad2, u8 *picture);  /* one frame: NES_W x NES_H entries of nes_rgb (0: no picture kept) */
const char *nes_info(void);                     /* "mapper 4 (MMC3), PRG 256 KB, CHR 128 KB, battery" */
u8 *nes_save_ram(u32 *size, int *battery);      /* the cartridge's 8 KB of RAM at $6000 */
int nes_save_changed(void);                     /* written since the last call */
u32 nes_cpu_cycles(void);
int nes_jammed(void);                           /* the program ran into an instruction that stops the 6502 */
extern const u8 nes_rgb[64][3];

/* the sound: mono, signed 16-bit, at the host's rate.  nes_audio_rate(0) (the start) makes none and costs nothing;
   with a rate (8000-192000) each frame makes about rate / 60.1 samples, kept (up to 4096, the oldest dropped) until
   nes_audio takes them -- call it once a frame.  Setting the rate starts the sound afresh (the samples kept go). */
void nes_audio_rate(u32 hz);
int nes_audio(s16 *out, int max);               /* the samples made since the last call (at most max): how many */

/* for tests: run the 6502 alone from an address (nestest's $C000), one instruction at a time */
void nes_test_pc(u16 pc);
void nes_test_step(u16 *pc, u8 *a, u8 *x, u8 *y, u8 *p, u8 *s, u32 *cycles);
u8 nes_test_peek(u16 address);

/* Famicom Disk System (.fds): shares the 6502, PPU and 48 kHz mixer with nes.c */
#define FDS_PAD_FLIP 0x0400                     /* PAD_L ('Q' / PAGE-): eject, flip to next disk side, re-insert */
void fds_set_bios(const u8 *rom, u32 size);     /* optional 8 KB disksys.rom (0: built-in clean-room BIOS) */
const char *fds_load(u8 *image, u32 size);      /* a .fds disk image (with or without 16-byte FDS header) */
void fds_frame(u16 pad, u8 *picture);           /* one 60.1 Hz frame; picture: NES_W x NES_H entries of nes_rgb */

#endif
