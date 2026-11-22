/* Atari 800XL / 130XE home computer & Atari 5200 SuperSystem console:
   - 1.79 MHz / 1.77 MHz SALLY 6502C CPU (including undocumented opcodes)
   - ANTIC Display List co-processor (modes 2..F, DLI, WSYNC, LMS, HSCROL, VSCROL)
   - GTIA video & sprite composer (336 x 240, 256-color NTSC/PAL, 4 Players + 4 Missiles,
     hardware collisions, PRIOR priorities, and GTIA modes 9 / 10 / 11)
   - POKEY 4-channel polynomial/pure-tone/16-bit/digisound 48 kHz audio, timers,
     potentiometers, keyboard matrix, and high-speed + serial SIO floppy bus
   - 6520 PIA (joysticks & 130XE 128 KB PORTB bank switching for CPU and ANTIC)
   - Formats: .atr, .xex / .obx / .com, .car, .rom / .bin (XL/XE), and .a52 / .car (5200)
   - Built-in royalty-free AltirraOS XL/XE, Altirra 8K BASIC, and Altirra 5200 OS ROMs,
     plus optional external atarixl.rom / ataribas.rom / 5200.rom override. */
#ifndef DEMO_A8_H
#define DEMO_A8_H

typedef unsigned char u8;
typedef signed char s8;
typedef unsigned short u16;
typedef short s16;
typedef unsigned int u32;
typedef int s32;

#define A8_W              336
#define A8_H              240
#define A8_FRAME_US_PAL   20033u    /* 1,773,447 Hz / (312 * 114) = 49.86 Hz */
#define A8_FRAME_US_NTSC  16707u    /* 1,789,772 Hz / (262 * 114) = 59.92 Hz */

/* Pad button bits (matching play.c) */
#define A8_A              0x0001u   /* Joystick Fire / 5200 Bottom Fire */
#define A8_B              0x0002u   /* XL/XE Space / 5200 Top Fire */
#define A8_SELECT         0x0004u   /* XL/XE SELECT / 5200 RESET */
#define A8_START          0x0008u   /* XL/XE START  / 5200 START */
#define A8_UP             0x0010u
#define A8_DOWN           0x0020u
#define A8_LEFT           0x0040u
#define A8_RIGHT          0x0080u
#define A8_X              0x0100u   /* XL/XE OPTION / 5200 PAUSE */
#define A8_Y              0x0200u   /* XL/XE HELP   / 5200 '*' */

const char *a8_load(const u8 *os16k, const u8 *bas8k, u8 *media, u32 size, const char *path);
const char *a52_load(const u8 *bios2k, u8 *media, u32 size, const char *path);

int a8_is_xex(const u8 *buf, u32 len);
int a8_is_car(const u8 *buf, u32 len, int *is_5200);

void a8_reset(void);
void a8_frame(u16 pad, const u8 *hid, int hid_n, u16 *picture);
void a8_type(char c);

int a8_pal(void);
const char *a8_info(void);
u8 *a8_save_ram(u32 *size, int *battery);
int a8_save_changed(void);
int a8_jammed(void);

void a8_audio_rate(u32 hz);
int a8_audio(s16 *out, int max);

#endif
