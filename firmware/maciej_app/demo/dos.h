/* dos.c: an IBM PC AT with MS-DOS, enough for a DOS game -- an 80286 in
   real mode (the 8086's instructions and the 186 / 286 ones real-mode
   programs use), 640 KB, the 8259 interrupt controller, the 8253 timer
   (channel 0's interrupt at whatever rate the program sets; the speaker's
   channel silent), the keyboard controller with its interrupt, the CMOS
   clock; a VGA (text modes, CGA's 320 x 200 four colours, EGA's 16-colour
   planar modes, the 256-colour mode 13h and its unchained "mode X" form).
   The BIOS and DOS are not real ROMs but C: each interrupt vector points
   at a stub in the BIOS's segment that calls into this file and returns,
   so a program that hooks a vector and calls the old one gets them.  DOS
   runs one program (an .exe or a .com) and reads the files given with it.
   Nothing in it knows the box: the program's file in RAM goes in, pictures
   of 15-bit colours come out (play.c puts them on the TV and reads the
   keys; a PC harness runs the same file). */
#ifndef DEMO_DOS_H
#define DEMO_DOS_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

/* the picture: the 320 x 200 of the graphics modes (an 80-column text screen in it with narrow characters, a
   40-column one with 8 x 8 ones).  On a 1280 x 720 screen: three times as large (960 x 600) */
#define DOS_W 320
#define DOS_H 200
#define DOS_FRAME_US 14268              /* the VGA's 70.09 frames a second: 449 lines of 31.47 kHz */

/* the pad's bits (nes.h's) as keys of the PC's keyboard: the arrows; A = Up too, B = Space, START = Enter,
   SELECT = Esc.  Magicland Dizzy: Left / Right (or Z / X) walk, Up (or K) jumps -- with Left or Right: to that
   side --, Space or Enter picks up, uses, drops (its menu), Down (or M) is not used much */
#define DOS_A      0x01
#define DOS_B      0x02
#define DOS_SELECT 0x04
#define DOS_START  0x08
#define DOS_UP     0x10
#define DOS_DOWN   0x20
#define DOS_LEFT   0x40
#define DOS_RIGHT  0x80

/* other files the program can open beside it (its data files), given before dos_load: the name it opens them
   by (8.3, any case, no directory) and where they are (used where they are, never written).  0, or why not */
const char *dos_add_file(const char *name, const u8 *data, u32 size);
void dos_clear_files(void);
/* the program: an .exe (MZ) or a .com file (used where it is, never written), started as C:\NAME.EXE with
   the command line `args` set by dos_args before (none by default); the program's own file can be opened too.
   0, or why it cannot run */
const char *dos_load(u8 *file, u32 size, const char *name);
void dos_args(const char *args);                /* the command line (" /e"), before dos_load */
void dos_reset(void);                           /* the machine as at power-on, the program started again */
/* one frame: DOS_W x DOS_H colours (0bbbbbgggggrrrrr; 0: no picture kept).  keys: the PC's scan codes held,
   bit k & 7 of byte k >> 3 -- k the scan code (set 1, 0x01..0x58), k | 0x80 for the keys that send 0xE0
   first (the arrows, Insert, Delete, Home, End, Page Up / Down, right Ctrl / Alt, the keypad's Enter and /);
   from dos_keys_from_hid; 0: none */
void dos_frame(u8 pad, const u8 keys[32], u16 *picture);
/* a USB keyboard's held keys (HID usages; the modifiers as 0xE0-0xE7) as the PC's scan codes: every key of a
   US 101-key keyboard but Print Screen and Pause */
void dos_keys_from_hid(const u8 *usages, int n, u8 keys[32]);
void dos_type(const char *text);                /* characters to type, each pressed for a few frames */
int dos_typing(void);                           /* characters still to type */
const char *dos_info(void);                     /* "MAGIC.EXE: an .exe of 152 KB, 1 more file" */
u8 *dos_save_ram(u32 *size, int *battery);      /* (nothing kept: size 0) */
int dos_save_changed(void);
u32 dos_cpu_cycles(void);                       /* the CPU's cycles since the reset */
int dos_jammed(void);                           /* the program ended, or halted with interrupts off */
int dos_mode(void);                             /* the video mode the BIOS was last asked for (0x13, 0x0D, 3...) */
int dos_pmode(void);                            /* 1 when running in 80386 protected mode */
int dos_picture_changed(void);                  /* 1 when the last dos_frame modified picture */
void dos_audio_rate(u32 hz);                    /* 48 kHz AdLib YM3812 (OPL2) + Sound Blaster 2.0 PCM + PC speaker */
int dos_audio(s16 *out, int max);

/* for tests: a byte of the PC's memory (its 1 MB); the registers AX CX DX BX SP BP SI DI ES CS SS DS IP FLAGS;
   what the BIOS and DOS were asked that they do not do, the program's own messages (0: not said) */
u8 dos_peek(u32 address);
void dos_registers(u16 r[14]);
u32 dos_idle_cycles(void);                      /* the cycles passed over in loops that wait for an interrupt */
extern void (*dos_log)(const char *line);

#endif
