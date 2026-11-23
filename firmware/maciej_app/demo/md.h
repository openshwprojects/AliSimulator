/* md.c: a Sega Mega Drive / Genesis (NTSC, or PAL) -- its 68000 (m68k.inc,
   shared with amiga.c) at 7.67 MHz with 64 KB of RAM, the Z80 (z80.c) at
   3.58 MHz with its 8 KB and its window on the 68000's bus, the VDP (two
   scrolled planes, the window, 80 sprites, shadow / highlight, DMA, the
   interrupts, the HV counter), the YM2612 (FM, its timers, the DAC) and the
   SN76489 (PSG), the 3- and 6-button pads, cartridge RAM and Sega's mapper
   for games over 4 MB.  Nothing in it knows the box: a cartridge image in
   RAM goes in, pictures of 15-bit colours come out (play.c puts them on the
   TV and reads the keys; a PC harness runs the same file). */
#ifndef DEMO_MD_H
#define DEMO_MD_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed int s32;
typedef signed short s16;

/* the picture: 320 x 224 (H40) or 256 x 224 (H32), or 240 lines high in PAL's V30 mode -- md_width() x
   md_height() as the last frame was drawn.  On a 1280 x 720 screen: three times as large (960 x 672) */
#define MD_W_MAX 320
#define MD_H_MAX 240
#define MD_FRAME_US     16688           /* NTSC: 262 lines of 3420 clocks of 53.693175 MHz (59.92 frames a second) */
#define MD_FRAME_US_PAL 20119           /* PAL: 313 lines of 3420 clocks of 53.203424 MHz (49.70 frames a second) */

/* the pad's buttons: the low eight bits are nes.h's (A, B, SELECT, START, the directions) as play.c gives them --
   its A (X on the keyboard, the remote's OK) is the Mega Drive's B, its B (Z) is A, SELECT (Tab / Space) is C;
   X, Y, Z and MODE are a 6-button pad's (md_six_button) */
#define MD_B     0x01
#define MD_A     0x02
#define MD_C     0x04
#define MD_START 0x08
#define MD_UP    0x10
#define MD_DOWN  0x20
#define MD_LEFT  0x40
#define MD_RIGHT 0x80
#define MD_X     0x100
#define MD_Y     0x200
#define MD_Z     0x400
#define MD_MODE  0x800

/* a cartridge file in RAM, whatever its name: the ROM as it is (.md, .gen, .bin); with a copier's 512-byte header
   before it; or interleaved (.smd: 16 KB blocks of the odd bytes' 8 KB, then the even ones', with or without
   that header) -- used where it is, its bytes rearranged in place for the 68000.  region: 0 the header's (its
   letters J U E, or a newer header's hex digit: U if it has it, else J, else E -- a game for Europe alone runs on
   a PAL console, any other on an NTSC one; no region: U), or 'U', 'J', 'E' that console.  0, or why it cannot
   run */
const char *md_load(u8 *image, u32 size, int region);
/* is this a Mega Drive cartridge?  head: the file's first n bytes (0x400 are enough), size: the file's: 0 no,
   1 a plain ROM ("SEGA" at 0x100), 2 one after a copier's header, 3 an interleaved one after it (.smd), 4 an
   interleaved one without it */
int md_cartridge(const u8 *head, u32 n, u32 size);
void md_reset(void);                            /* the reset button */
void md_frame(u16 pad, u16 *picture);           /* one frame: md_width() x md_height() colours (0bbbbbgggggrrrrr;
                                                   0: no picture kept, the frame still run) */
void md_pad2(u16 pad);                          /* the second pad's buttons */
void md_six_button(int on);                     /* 6-button pads (1) or 3-button ones (0: the start) */
int md_width(void);                             /* 320 or 256 */
int md_height(void);                            /* 224 or 240 */
int md_pal(void);                               /* a PAL console (50 frames a second) */
const char *md_info(void);                      /* "SONIC THE HEDGEHOG, ROM 512 KB, NTSC (U)" */
u8 *md_save_ram(u32 *size, int *battery);       /* the cartridge's RAM (when its header says it has some) */
int md_save_changed(void);                      /* written since the last call */
u32 md_cpu_cycles(void);                        /* 68000 cycles since the reset */
int md_jammed(void);                            /* STOPped with every interrupt masked: nothing can wake it */

/* the sound: mono, signed 16-bit, at the host's rate (the YM2612 and the PSG mixed).  md_audio_rate(0) (the
   start) makes none and costs nothing but the YM2612's timers; md_audio takes what was made -- call it once a
   frame */
void md_audio_rate(u32 hz);
int md_audio(s16 *out, int max);

/* for tests: a byte of the 68000's memory, of the Z80's, a VDP register, VRAM / CRAM / VSRAM words, the
   68000's registers D0-D7, A0-A7, PC, SR */
u8 md_peek(u32 address);
u8 md_z80_peek(u16 address);
u8 md_vdp_reg(int r);
u16 md_vram(u32 address);
u16 md_cram(int i);
u16 md_vsram(int i);
void md_registers(u32 r[18]);

/* Sega CD / Mega-CD expansion unit attachment hooks (used by segacd.c) */
struct md_addon {
    void (*reset)(u16 *main_ram32kw);
    void (*map)(u8 *rmap[256], u8 *wmap[256]);
    u32  (*io_read)(u32 a, int size, s32 main_cyc);
    void (*io_write)(u32 a, u32 v, int size, s32 main_cyc);
    void (*run_line)(s32 main_cyc);
    void (*end_frame)(s32 main_frame_cyc);
    void (*mix_audio)(s16 *samples, int count, u32 rate);
    void (*draw_line)(int y, u16 *out, int width, u16 md_bg);
    void (*scanline)(int y, int active_h);
};
void md_attach_addon(const struct md_addon *ext, int pal_mode, int overseas_mode, const char *title);
void md_remap(void);

#endif
