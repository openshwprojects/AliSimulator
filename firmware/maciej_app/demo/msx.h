/* msx.c: MSX1 & MSX2 home computers (with MegaROM mappers, Disk .dsk, SCC & MSX-MUSIC).

   CPU: Zilog Z80A (z80.c) at 3.579545 MHz (228 T-states/line, 262 lines, 59.92 Hz).
   Picture:
     - MSX1: Texas Instruments TMS9918A (256 x 192, 16 KB VRAM, SCREEN 0..3).
     - MSX2: Yamaha V9938 (256/512 x 192/212, 128 KB VRAM + 64 KB ExpVRAM,
       ports 0x98..0x9B, RGB333 palette, SCREEN 0..8 incl. 80-col Text 2,
       G4..G7 bitmaps, Sprite Mode 2 w/ OR-color blending, R#19 scanline IRQ,
       R#23 vertical scroll, and full VDP blitter HMMC/YMMM/HMMM/HMMV/LMMC/
       LMCM/LMMM/LMMV/LINE/SRCH/PSET/POINT).
   Memory & Peripherals:
     - Slot 0: Main BIOS (32 KB: msx.rom / cbios_main_msx1.rom / cbios_main_msx2.rom
       or built-in clean-room MSX1 / MSX2 BIOS).
     - Slot 1: Cartridge (.rom, .mx1, .mx2 -- Plain, Konami4, Konami SCC,
       ASCII8, ASCII16, Generic8, Generic16 up to 4 MB).
     - Slot 2: MSX-MUSIC YM2413 OPLL ROM header ("APRLOPLL") + ports 0x7C/0x7D.
     - Slot 3 (expanded on MSX2 via $FFFF):
         3-0: 256 KB Memory Mapper RAM (16 x 16 KB pages on ports 0xFC..0xFF)
         3-1: MSX2 Sub-ROM (16 KB: cbios_sub.rom / msx2ext.rom or built-in)
         3-2: Disk ROM + FAT12 .dsk floppy controller ($4010 PHYDIO & BDOS)
     - Ricoh RP5C01 RTC & CMOS NVRAM (ports 0xB4 / 0xB5).
   Sound: AY-3-8910 PSG + Konami SCC 5-ch wavetable + Yamaha YM2413 OPLL FM, 48 kHz. */
#ifndef DEMO_MSX_H
#define DEMO_MSX_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define MSX_W        256
#define MSX_H        192
#define MSX2_W_MAX   512
#define MSX2_H_MAX   212
#define MSX_FRAME_US 16688

/* Pad bits match play.c's PAD_* */
#define MSX_A        0x0001     /* Trigger A & Space */
#define MSX_B        0x0002     /* Trigger B & M */
#define MSX_SELECT   0x0004     /* Select / F2 */
#define MSX_START    0x0008     /* Return / F1 */
#define MSX_UP       0x0010
#define MSX_DOWN     0x0020
#define MSX_LEFT     0x0040
#define MSX_RIGHT    0x0080

int msx_is_cart(const u8 *head, u32 got, u32 total_size);
const char *msx_load(const u8 *bios32k, u8 *cart, u32 cart_size);
const char *msx2_load(const u8 *bios32k, const u8 *subrom16k, u8 *media, u32 media_size, const char *name);
void msx_reset(void);
void msx_keys_from_hid(const u8 *usages, int n);
void msx_type(char c);
void msx_frame(u16 pad, u16 *picture);
int msx_width(void);
int msx_height(void);
const char *msx_info(void);
u8 *msx_save_ram(u32 *size, int *battery);
int msx_save_changed(void);
int msx_jammed(void);

void msx_audio_rate(u32 hz);
int msx_audio(s16 *out, int max);

#endif
