/* Taito Classic & F2 / B-System Multi-Board Arcade Emulator for Maciej v4 (ALi S3811)
   Supports MAME .zip romsets across three iconic Taito arcade hardware generations:
     1. Taito F2 / B-System (68000 + Z80 + TC0100SCN triple tilemap + TC0200OBJ zoomed
        chained sprites + TC0110PCR palette + TC0220IOC/TC0140SYT + YM2151/YM2610 ADPCM):
        Puzzle Bobble / Bust-A-Move, Liquid Kids, Final Blow, Growl, Gun Frontier, Metal Black
     2. Taito Rastan / Rainbow Islands (68000 + Z80 + PC080SN dual tilemaps + PC090OJ
        sprites + PC060HA sound latch + YM2151 + ADPCM):
        Rastan, Rainbow Islands, Operation Wolf, Volfied, Cadash
     3. Taito Classic Dual-Z80 (Main Z80 + Sound Z80 + Bubble Bobble / SETA X1-001 video +
        clean-room MCU HLE + YM2203 FM/SSG):
        Bubble Bobble, The NewZealand Story
   Plus built-in playable Taito F2 game (""): "BUBBLE DRAGONS F2"! */
#ifndef DEMO_TAITO_H
#define DEMO_TAITO_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

#define TAITO_W_MAX     320
#define TAITO_H_MAX     240
#define TAITO_FRAME_US  16667u          /* 60.00 Hz arcade vertical blank */

const char *taito_load(const u8 *image, u32 size, const char *path);
void taito_reset(void);
void taito_frame(u16 pad, u16 *picture);
void taito_pad2(u16 pad);

int taito_width(void);
int taito_height(void);
const char *taito_info(void);

u8 *taito_save_ram(u32 *size, int *battery);
int taito_save_changed(void);
int taito_jammed(void);

void taito_audio_rate(u32 hz);
int taito_audio(s16 *out, int max);

int taito_is_zip(const u8 *zip, u32 size, const char *name);

#endif
