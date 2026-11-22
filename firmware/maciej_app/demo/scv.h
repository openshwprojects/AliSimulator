#ifndef SCV_H
#define SCV_H

#ifdef SCV_HOST
#include <stdint.h>
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
#else
#include "types.h"
#endif

/*
 * Epoch Super Cassette Vision (1984, Japan / Yeno SCV in Europe):
 *  - NEC uPD7801G 8-bit MCU @ 4.000 MHz (full uCOM-87 7801 instruction set,
 *    working-register page V, alternate register bank, CALT/CALF, INT0..INTS)
 *  - Clean-room 4 KB internal BIOS ROM ($0000..$0FFF) + 1 KB 128-glyph ASCII
 *    character ROM (optional external upd7801g.s01 override supported)
 *  - Epoch TV-1 VDP: 32x16 text/semigraphics/block background + 128 hardware
 *    sprites (8x8..32x32, top-clip, 2-color sprite LUTs), 16-color RGB palette,
 *    192x222 active viewport @ 59.92 Hz
 *  - NEC uPD1771C-017 sound processor @ 6 MHz (square/timbre tone, LFSR noise,
 *    and multi-byte command handshake on $3600 / INTF1)
 *  - 8K / 16K / 32K / 32K+8K RAM / 64K / 128K / 128K+4K RAM cartridge mappers
 */

#define SCV_W         192
#define SCV_H         222
#define SCV_FRAME_US  16688

const char *scv_load(const u8 *bios, u32 bios_size, const u8 *rom, u32 rom_size);
void        scv_reset(void);
void        scv_frame(u16 pad, u16 *picture);
const char *scv_info(void);
int         scv_jammed(void);

void scv_keyboard(const u8 *usages, int n);
void scv_typed(char c);

void scv_audio_rate(u32 hz);
int  scv_audio(s16 *out, int max);

u32  scv_save_sram(u8 *dst, u32 max);
void scv_load_sram(const u8 *src, u32 len);

#endif
