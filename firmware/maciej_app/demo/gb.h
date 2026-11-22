/* gb.c: a Game Boy (the first one, DMG, and the Color, CGB) -- its CPU,
   its picture chip, its timer, the cartridge boards most games came on.
   Nothing in it knows the box: a cartridge image in RAM goes in, pictures
   of 160 x 144 colours come out (play.c puts them on the TV and reads the buttons; a PC harness runs
   the same file against the test cartridges). */
#ifndef DEMO_GB_H
#define DEMO_GB_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define GB_W 160
#define GB_H 144

/* the buttons, as gb_frame takes them (the same bits as nes.h's) */
#define GB_A      0x01
#define GB_B      0x02
#define GB_SELECT 0x04
#define GB_START  0x08
#define GB_UP     0x10
#define GB_DOWN   0x20
#define GB_LEFT   0x40
#define GB_RIGHT  0x80

const char *gb_load(u8 *image, u32 size);       /* a .gb file in RAM (used where it is): 0, or why it cannot run */
const char *megaduck_load(u8 *image, u32 size); /* a Mega Duck / Cougar Boy (.duck, .md1, .md2, .bin) cartridge */
void gb_reset(void);
void gb_frame(u8 pad, u16 *picture);            /* one frame (70224 clock ticks): GB_W x GB_H colours, the
                                                   Color's 15 bits (0bbbbbgggggrrrrr) -- a game for the first
                                                   Game Boy in gb_rgb's shades (0: no picture kept) */
const char *gb_info(void);                      /* "TETRIS: MBC1, ROM 32 KB, RAM 8 KB, battery" (", Game Boy
                                                   Color": run as on one) */
u8 *gb_save_ram(u32 *size, int *battery);       /* the cartridge's RAM (size 0: it has none) */
int gb_save_changed(void);                      /* written since the last call */
u32 gb_cpu_cycles(void);                        /* machine cycles (4 clock ticks each) since the reset */
int gb_jammed(void);                            /* the program ran into an instruction that stops the CPU */
extern const u8 gb_rgb[4][3];

void gb_audio_rate(u32 hz);
int gb_audio(s16 *out, int max);

/* for tests: a byte the program sent out of the link port (the test cartridges print through it); the CPU's
   registers B C D E H L, and whether the program has run LD B,B (the mooneye tests' "done") since the reset */
extern void (*gb_serial_out)(u8 byte);
int gb_test_done(u8 regs[6]);

#endif
