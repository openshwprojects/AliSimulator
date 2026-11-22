/* zx.c: ZX Spectrum 48K / 128K + Pentagon BetaDisk 128 (TR-DOS) --
   Zilog Z80A (z80.c), ULA / ULA-128 (256 x 192 + border, shadow screen bank 7,
   contended memory, floating bus), port 0x7FFD 128K memory paging (8 x 16 KB
   RAM banks, dual ROMs), Kempston joystick, 1-bit ULA beeper + General
   Instrument AY-3-8912 3-channel PSG audio (ports 0xFFFD / 0xBFFD) mixed at
   48 kHz, snapshots (.sna 48K/128K, .z80 v1/v2/v3 48K/128K), tapes (.tap,
   .tzx), and BetaDisk WD1793 FDC floppy disks (.trd, .scl).
   Uses 48.rom / 128.rom / trdos.rom when supplied on disk, or a built-in
   clean-room loader ROM when no external ROM file is present. */
#ifndef DEMO_ZX_H
#define DEMO_ZX_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef signed short s16;
typedef unsigned int u32;
typedef signed int s32;

#define ZX_W 320                        /* 256 x 192 picture with 32 px border left/right, */
#define ZX_H 240                        /* 24 lines above and below */
#define ZX_FRAME_US 19968               /* ~50.08 Hz */

/* Pad bits (match play.c PAD_*): Kempston joystick (A or B = fire); START = ENTER, SELECT = SPACE */
#define ZX_A      0x01
#define ZX_B      0x02
#define ZX_SELECT 0x04
#define ZX_START  0x08
#define ZX_UP     0x10
#define ZX_DOWN   0x20
#define ZX_LEFT   0x40
#define ZX_RIGHT  0x80

/* Optional 128K (32 KB: ROM 0 editor + ROM 1 48K BASIC) and TR-DOS (16 KB) ROMs */
void zx_set_extra_roms(const u8 *rom128_32k, u32 rom128_size, const u8 *trdos_16k, u32 trdos_size);

/* Load 48K ROM (16 KB; or 0 to use 128.rom / built-in clean-room ROM) and optional media file
   (.sna, .z80, .tap, .tzx, .trd, .scl; 0: BASIC).  Returns 0 on success, or error reason. */
const char *zx_load(const u8 *rom16k, u8 *file, u32 size, const char *name);
void zx_reset(void);
void zx_frame(u8 pad, const u8 matrix[8], u16 *picture);
void zx_keys_from_hid(const u8 *usages, int n, u8 matrix[8]);
void zx_type(const char *text);
int zx_typing(void);
const char *zx_info(void);
u8 *zx_save_ram(u32 *size, int *battery);
int zx_save_changed(void);
u32 zx_cpu_cycles(void);
int zx_jammed(void);
extern const u8 zx_rgb[16][3];

void zx_audio_rate(u32 hz);
int zx_audio(s16 *out, int max);

/* Test / debugger inspection */
struct z80 *zx_cpu(void);
u8 zx_peek(u16 address);
u8 zx_port_7ffd(void);

#endif
