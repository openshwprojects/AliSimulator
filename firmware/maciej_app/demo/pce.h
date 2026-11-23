/* pce.c: NEC PC Engine / TurboGrafx-16 ('pce'), NEC SuperGrafx ('sgx'), and
   PC Engine CD-ROM2 / Super CD-ROM2 / Arcade Card ('pcecd'):
   - HuC6280 CPU at 7.16 / 1.79 MHz (MPR0..MPR7, $2000 ZP, $2100 stack, T-flag,
     TII/TDD/TIN/TIA/TAI, ST0/ST1/ST2, TST, BBR/BBS/RMB/SMB, 7 kHz timer)
   - Single HuC6270 VDC (64 KB VRAM) on PCE/PCE-CD, or Dual HuC6270 VDCs
     (128 KB VRAM) + HuC6202 VPC window/priority mixer + 32 KB WRAM on SuperGrafx
   - HuC6260 VCE (512 9-bit GRB colours, 256 / 320 / 512 widths)
   - 6-channel wavetable/noise/DDA/LFO PSG + OKI MSM5205 12-bit ADPCM (64 KB)
     + streamed 44.1 kHz Redbook CD-DA mixed at 48 kHz
   - NEC SCSI CD-ROM2 drive ($1800..$180F), 256 KB Super System Card 3.0 RAM
     ($68..$87), 2 MB Arcade Card Pro/Duo RAM ($40..$43 / $1A00..$1AFF),
     2 KB battery-backed BRAM (.sav), and clean-room System Card 3.0 BIOS
     (with optional external syscard3.pce override). */
#ifndef DEMO_PCE_H
#define DEMO_PCE_H

#include "cdrom.h"

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed short s16;
typedef signed int s32;

#define PCE_W_MAX    512
#define PCE_H_MAX    242
#define PCE_W_DEF    256
#define PCE_H_DEF    240
#define PCE_FRAME_US 16712              /* 263 lines of 1365 master clocks at 21.47727 MHz (59.84 frames a second) */

/* the pad's buttons (the low eight bits match nes.h's and play.c's):
   A (X on the keyboard, the remote's OK) is I, B (Z, the remote's 0) is II,
   SELECT is Select, START is Run */
#define PCE_I      0x0001
#define PCE_II     0x0002
#define PCE_SELECT 0x0004
#define PCE_RUN    0x0008
#define PCE_UP     0x0010
#define PCE_DOWN   0x0020
#define PCE_LEFT   0x0040
#define PCE_RIGHT  0x0080
#define PCE_III    0x0100
#define PCE_IV     0x0200
#define PCE_V      0x0400
#define PCE_VI     0x0800

const char *pce_load(u8 *image, u32 size);      /* a .pce HuCard image in RAM (a 512-byte header skipped; bit-reversed
                                                   US dumps unreversed in place): 0, or why it cannot run */
const char *sgx_load(u8 *image, u32 size);      /* a .sgx SuperGrafx HuCard image (dual VDC + VPC + 32 KB WRAM) */
const char *pcecd_load(const u8 *bios, u32 bios_size, const struct cdrom_toc *cd);
                                                /* PC Engine CD / TurboGrafx-CD + Super System Card 3.0 + Arcade Card */
void pce_reset(void);
void pce_frame(u16 pad, u16 *picture);          /* one frame: pce_width() x pce_height() 15-bit colours
                                                   (0bbbbbgggggrrrrr; 0: no picture kept) */
int pce_width(void);
int pce_height(void);
const char *pce_info(void);
u8 *pce_save_ram(u32 *size, int *battery);      /* the 2 KB backup RAM ($F7), saved when unlocked and written */
int pce_save_changed(void);
u32 pce_cpu_cycles(void);
int pce_jammed(void);

void pce_audio_rate(u32 hz);
int pce_audio(s16 *out, int max);

#ifdef PCE_CPU_TEST
/* SingleStepTests/huc6280 flat 2 MB bus mode: pce.c built with -DPCE_HOST -DPCE_CPU_TEST */
extern u8 pce_sst_ram[0x200000];
void pce_sst_set(u8 a, u8 x, u8 y, u8 s, u8 p, u16 pc, const u8 mpr[8]);
void pce_sst_get(u8 *a, u8 *x, u8 *y, u8 *s, u8 *p, u16 *pc, u8 mpr[8]);
u32 pce_sst_step(void);
#endif

#endif
