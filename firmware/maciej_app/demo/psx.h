/* Sony PlayStation 1 (.exe / .cue / .iso) emulator */
#ifndef DEMO_PSX_H
#define DEMO_PSX_H

#define PSX_W_DEF     320
#define PSX_H_DEF     240
#define PSX_W_MAX        640
#define PSX_H_MAX        480
#define PSX_FRAME_US     16683u   /* 59.94 Hz NTSC */
#define PSX_FRAME_US_PAL 20000u   /* 50.00 Hz PAL */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef signed short s16;

/* Optional streaming sector reader for large .cue/.bin or .iso discs on disk:
   reads 1 sector at 0-based LBA `lba` (after 2s lead-in); returns sector size (2048 or 2352), or <= 0 on error */
typedef int (*psx_sector_fn)(u32 lba, u8 *buf2352);

void psx_set_bios(const u8 *data, u32 size);
void psx_set_disc(psx_sector_fn fn, u32 total_sectors, u32 sector_size);
void psx_set_toc(int first_track, int last_track, const u32 *track_lba, const u8 *track_is_audio);
int psx_is_exe(const u8 *head, u32 got);
const char *psx_load(const u8 *data, u32 size, const char *path);
const char *psx_info(void);
int psx_width(void);
int psx_height(void);
int psx_pal(void);
void psx_set_region(int region);            /* 0 = auto, 'J'/'U' = 60 Hz NTSC, 'E' = 50 Hz PAL */
void psx_set_skip_render(int skip);
void psx_print_stats(void);                 /* the recompiler's counters since the last call (box only) */
const u16 *psx_vram_frame(int *stride, int *is_24bpp);
const u8 *psx_vram_line24(int y);           /* a 24-bit picture's line y (3 bytes a pixel), or 0 (psx_scanout) */
void psx_frame(u16 pad, u16 *picture);      /* up to 640 x 480 15-bit BGR555 (skip_render 0: every frame) */
void psx_scanout(u16 *picture);             /* live play (skip_render 1 / 2): the picture when it is shown */
int psx_display_changed(void);              /* what is shown changed since the last call */
int psx_display_stale(void);                /* what is shown is a skipped game frame: keep the old picture */
int psx_display_flipped(void);              /* the shown part moved since the last call (all lines changed) */
u32 psx_frames_skipped(void);               /* game frames whose drawing was skipped */
int psx_jammed(void);
u8 *psx_save_ram(u32 *size, int *battery);
int psx_save_changed(void);
void psx_audio_rate(u32 hz);
int psx_audio(s16 *out, int max);

#endif
