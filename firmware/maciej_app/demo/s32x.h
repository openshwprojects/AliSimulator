/* s32x.c: Sega 32X ("Project Mars") Add-On Emulator (extends md.c).
   - Dual 23.01 MHz 32-bit Hitachi SH-2 (SH7604) RISC CPUs (Master + Slave)
   - On-chip SH7604 32/64-bit Hardware Divider, 2-ch DMAC (w/ 68k DREQ FIFO), FRT, WDT & 4 KB Cache RAM
   - 256 KB SDRAM ($06000000) + 2 x 128 KB SuperVDP Framebuffers (Packed 256-col, RLE, Direct 15-bit)
   - Scanline-accurate SuperVDP + Mega Drive VDP priority genlock compositor
   - Stereo 12-bit PWM Sound Generator mixed with YM2612 + SN76489 @ 48 kHz
   - Built-in Clean-Room Master/Slave SH-2 & 68k Vector Boot ROMs (optional 32x_{g,m,s}_bios.bin) */
#ifndef DEMO_S32X_H
#define DEMO_S32X_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;
typedef signed int s32;

const char *s32x_load(u8 *rom, u32 rom_size,
                      const u8 *bios_g, u32 bios_g_sz,
                      const u8 *bios_m, u32 bios_m_sz,
                      const u8 *bios_s, u32 bios_s_sz,
                      int region);

#endif
