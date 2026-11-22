/* The game players on the box ('nes <file>', 'gb <file>'): a cartridge file
   from a disk into RAM, the machine (nes.c, gb.c) run one frame at its own
   rate (the NES's 60.1 a second, the Game Boy's 59.7), its picture enlarged
   to the screen's whole height -- the NES's 256 x 240 three times (768 x
   720), the Game Boy's 160 x 144 five times (800 x 720) -- in the middle of
   the test screen's picture.  The NES's picture comes as its 64 colours'
   numbers, the Game Boy's (the Color's too) as 15-bit colours.

   The buttons, the same eight on both: a USB keyboard's keys as long as
   they are held (arrows or W A S D, X or K = A, Z or J = B, Enter = Start,
   Tab or Space = Select); the UART and the telnet console, where a key is
   only known when it is typed, so each counts as a short press (the same
   keys; the terminal's auto-repeat keeps a direction going); the remote
   (arrows, OK = A, 0 = B, MENU = Start, INFO = Select, EXIT ends); on a
   board with two front buttons, UP = Start and DOWN = A.  Ctrl-C or Esc
   ends.

   A cartridge with a battery keeps its RAM in a file beside it, named
   after the whole file (game.nes -> game.nes.sav, so that game.gb beside
   it keeps its own), read at the start and written at the end when the
   game changed it.  A save made before that had the extension dropped
   (game.sav): it is still read when there is no new one and its size is
   this cartridge's RAM's, and never written again.  A machine that makes sound (the NES) plays it through snd.c
   (HDMI and SCART), 48 kHz. */
#include "hw.h"
#include "nes.h"
#include "gb.h"
#include "sms.h"
#include "zx.h"
#include "a26.h"
#include "c64.h"
#include "amiga.h"
#include "dos.h"
#include "md.h"
#include "pce.h"
#include "col.h"
#include "msx.h"
#include "ws.h"
#include "snes.h"
#include "neo.h"
#include "gba.h"
#include "a78.h"
#include "lnx.h"
#include "vec.h"
#include "o2.h"
#include "intv.h"
#include "ngp.h"
#include "psx.h"
#include "cps.h"
#include "st.h"
#include "s16.h"
#include "a8.h"
#include "snd.h"
#include "zip.h"
#include "image.h"

/* a machine, as the player sees it */
struct machine {
    int w, h, xs, ys;                   /* the picture's size; how many times wider and higher on the TV */
    u32 frame_us;                       /* a frame's time */
    const char *(*load)(u8 *image, u32 size, const char *path);
    const char *(*info)(void);
    void (*frame)(u16 pad, void *picture);
    u8 *(*save_ram)(u32 *size, int *battery);
    int (*save_changed)(void);
    int (*jammed)(void);
    const u8 (*rgb)[3];
    int colours;                        /* the picture: numbers of rgb's colours, a byte each; 0: 15-bit colours
                                           (0bbbbbgggggrrrrr), two bytes each */
    const char *cpu;
    /* a machine with a computer's keyboard (the Spectrum): every key held on the USB keyboard as HID usages
       (modifiers 0xE0..0xE7) before each frame, and a character typed on the UART / telnet console; its
       USB keys then make no buttons but the arrows, and only Esc ends (Ctrl is a key of the machine's) */
    void (*keyboard)(const u8 *usages, int n);
    void (*typed)(char c);
    const char *keys;                   /* the keys, said when it starts (0: the NES's) */
    void (*size)(int *w, int *h);       /* a picture whose size the game changes (the Master System's 192 or
                                           224 lines): asked after each frame */
    /* sound (0: none): the rate to make it at (0: none made), and after each frame the samples made since the
       last call (mono, 16-bit) -- they go to the TV's HDMI sound and the SCART's (snd.c) */
    void (*audio_rate)(u32 hz);
    int (*audio)(s16 *out, int max);
};
static const struct machine *m;

static const char *nes_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    return nes_load(image, size);
}

static const char *gb_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    return gb_load(image, size);
}

static void nes_one(u16 pad, void *picture)
{
    nes_frame((u8)pad, 0, (u8 *)picture);
}

static void gb_one(u16 pad, void *picture)
{
    gb_frame((u8)pad, (u16 *)picture);
}

static const struct machine nes_machine = {NES_W, NES_H, 3, 3, 16639, nes_open, nes_info, nes_one, nes_save_ram,
                                           nes_save_changed, nes_jammed, nes_rgb, 64, "the 6502", 0, 0, 0, 0,
                                           nes_audio_rate, nes_audio};
static const struct machine gb_machine = {GB_W, GB_H, 5, 5, 16743, gb_open, gb_info, gb_one, gb_save_ram,
                                          gb_save_changed, gb_jammed, 0, 0, "the Game Boy's CPU", 0, 0, 0, 0, 0, 0};

/* the Master System (256 x 192, three times: 768 x 576) and the Game Gear (its 160 x 144 screen five times) */
static const char *sms_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    return sms_load(image, size, 0);
}

static const char *gg_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    return sms_load(image, size, 1);
}

static void sms_one(u16 pad, void *picture)
{
    sms_frame((u8)pad, (u16 *)picture);
}

static void sms_size(int *w, int *h)
{
    *w = sms_width();
    *h = sms_height();
}

static const struct machine sms_machine = {SMS_W, 192, 3, 3, SMS_FRAME_US, sms_open, sms_info, sms_one,
                                           sms_save_ram, sms_save_changed, sms_jammed, 0, 0, "the Z80", 0, 0,
                                           "arrows or W A S D, X = button 2, Z = button 1, Enter = Pause; Ctrl-C or "
                                           "Esc ends", sms_size, 0, 0};
static const struct machine gg_machine = {GG_W, GG_H, 5, 5, SMS_FRAME_US, gg_open, sms_info, sms_one,
                                          sms_save_ram, sms_save_changed, sms_jammed, 0, 0, "the Z80", 0, 0,
                                          "arrows or W A S D, X = button 2, Z = button 1, Enter = Start; Ctrl-C or "
                                          "Esc ends", 0, 0, 0};

/* the SG-1000 / SC-3000 (256 x 192, three times): a .sc file gets the SC-3000's 2 KB of RAM */
static const char *sg_open(u8 *image, u32 size, const char *path)
{
    int n = 0;
    while (path && path[n])
        n++;
    int sc = n >= 3 && path[n - 3] == '.' && (path[n - 2] | 32) == 's' && (path[n - 1] | 32) == 'c';
    return sms_load(image, size, sc ? SMS_SC3000 : SMS_SG1000);
}

static const struct machine sg_machine = {SMS_W, 192, 3, 3, SMS_FRAME_US, sg_open, sms_info, sms_one,
                                          sms_save_ram, sms_save_changed, sms_jammed, 0, 0, "the Z80", 0, 0,
                                          "arrows or W A S D, X = button 2, Z = button 1, Enter = Pause; Ctrl-C or "
                                          "Esc ends", 0, 0, 0};

/* the ZX Spectrum 48K: 320 x 240 with its border, three times (960 x 720).  Its ROM is not in the demo: a
   file 48.rom (16 KB) in the program's directory, or zx/48.rom or 48.rom at its volume's top */
static u8 zx_rom[16384];
static u8 zx_matrix[8];

static void zx_join(char *out, int size, const char *dir, int n, const char *name)     /* dir's first n, name */
{
    int k = 0;
    for (int i = 0; i < n && k < size - 1; i++)
        out[k++] = dir[i];
    while (*name && k < size - 1)
        out[k++] = *name++;
    out[k] = 0;
}

/* a machine's ROM file `name` of `least`..`want` bytes into rom: beside the program, in <sub>/ or at the top of
   its volume, or (no volume in the path) in <sub>/ on any disk; its size, 0 when not found */
static u32 rom_find(const char *path, const char *sub, const char *name, u8 *rom, u32 least, u32 want)
{
    char dir[160], try[200], in_sub[40], top[40];
    usnprintf(in_sub, sizeof(in_sub), "/%s/%s", sub, name);
    usnprintf(top, sizeof(top), "/%s", name);
    int n = 0, cut = 0, colon = -1, named = 0;
    const char *cwd = disk_cwd();
    for (const char *q = path; *q; q++)
        named |= *q == ':';
    /* the program's directory: as its path names it; a path without a volume ("manic.tap" after 'cd', what the
       explorer opens; "/top.tap": the current volume's top) starts from the current directory; none: that
       directory itself */
    if (!named && *cwd) {
        for (; cwd[n] && n < (int)sizeof(dir) - 2; n++) {
            dir[n] = cwd[n];
            if (cwd[n] == ':' && colon < 0)
                colon = n;
        }
        if (*path == '/' || *path == '\\')
            n = colon + 1;              /* ("4:" of "4:/games") */
        else if (n && dir[n - 1] != '/')
            dir[n++] = '/';
        cut = n;
    }
    for (const char *q = path; *q && n < (int)sizeof(dir) - 1; q++, n++) {
        dir[n] = *q;
        if (*q == '/' || *q == '\\')
            cut = n + 1;
        if (*q == ':' && colon < 0)
            colon = n;
    }
    dir[n] = 0;
    for (int k = 0; k < 3 + 16; k++) {
        if (k == 0) {
            if (!cut)
                continue;
            zx_join(try, sizeof(try), dir, cut, name);
        } else if (k < 3) {
            if (colon < 0)
                continue;
            zx_join(try, sizeof(try), dir, colon + 1, k == 1 ? in_sub : top);
        } else {                        /* (no directory to start from: <sub>/<name> on any disk) */
            if (colon >= 0)
                break;
            usnprintf(try, sizeof(try), "%d:%s", k - 3, in_sub);
        }
        u32 size = 0;
        if (disk_exists(try) && disk_read_head(try, rom, want, &size) >= (int)least && size >= least &&
            size <= want) {
            uprintf("ROM: %s\n", try);
            return size;
        }
    }
    return 0;
}

static int rom_read(const char *path, const char *sub, const char *name, u8 *rom, u32 size)
{
    return rom_find(path, sub, name, rom, size, size) != 0;
}

static int zx_rom_read(const char *path)
{
    return rom_read(path, "zx", "48.rom", zx_rom, sizeof(zx_rom));
}

static const char *zx_open(u8 *image, u32 size, const char *path)
{
    u8 *extra = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 got128 = rom_find(path, "zx", "128.rom", extra, 0x8000u, 0x8000u);
    u32 gottrd = rom_find(path, "zx", "trdos.rom", extra + 0x8000u, 0x4000u, 0x4000u);
    zx_set_extra_roms(got128 == 0x8000u ? extra : 0, got128,
                      gottrd == 0x4000u ? extra + 0x8000u : 0, gottrd);
    int has48 = zx_rom_read(path);
    if (!has48 && !size && !got128)
        return "no 48.rom (the Spectrum 48K's ROM, 16 KB) or 128.rom beside it, in zx/ or at the top of its disk";
    for (int i = 0; i < 8; i++)
        zx_matrix[i] = 0;
    return zx_load(has48 ? zx_rom : 0, size ? image : 0, size, path);
}

static void zx_one(u16 pad, void *picture)
{
    zx_frame((u8)pad, zx_matrix, (u16 *)picture);
}

static void zx_keyboard(const u8 *usages, int n)
{
    zx_keys_from_hid(usages, n, zx_matrix);
}

static void zx_typed(char c)
{
    char s[2] = {c, 0};
    zx_type(s);
}

static const struct machine zx_machine = {ZX_W, ZX_H, 3, 3, ZX_FRAME_US, zx_open, zx_info, zx_one, zx_save_ram,
                                          zx_save_changed, zx_jammed, 0, 0, "the Z80", zx_keyboard, zx_typed,
                                          "the USB keyboard is the Spectrum's (Shift = CAPS SHIFT, Ctrl / Alt = "
                                          "SYMBOL SHIFT), its arrows a Kempston joystick too; what is typed on this "
                                          "console is typed on it; Esc ends", 0, zx_audio_rate, zx_audio};

#define PAD_A      0x0001               /* (nes.h's and gb.h's bits) */
#define PAD_B      0x0002
#define PAD_SELECT 0x0004
#define PAD_START  0x0008
#define PAD_UP     0x0010
#define PAD_DOWN   0x0020
#define PAD_LEFT   0x0040
#define PAD_RIGHT  0x0080
#define PAD_X      0x0100               /* extra face / shoulder buttons (SNES, Neo Geo, GBA, PS1, 6-button MD) */
#define PAD_Y      0x0200
#define PAD_L      0x0400
#define PAD_R      0x0800
#define TAP_BUTTONS 12
#define TAP_FRAMES 6                    /* a key typed on the UART: the button held this many frames */
#define IR_FRAMES  9                    /* a remote's key: until its repeat frame would have come (108 ms) */

#define PICTURE_MAX (640 * 480)          /* up to 640 x 480 (PS1 / hi-res PCE & SNES / Vectrex), in PICTURE_PHYS */
static u16 *const picture = (u16 *)KSEG0(PICTURE_PHYS);
static u16 *const before = (u16 *)KSEG0(PICTURE_PHYS + PICTURE_MAX * 2u);
static u16 colours[256];
static int pw, ph;                      /* the picture's size now (m->w, m->h, or what m->size says) */
static u8 taps[TAP_BUTTONS];            /* frames left of each button's short press */

static u32 crc32(const u8 *p, u32 n)
{
    u32 c = 0xFFFFFFFFu;
    while (n--) {
        c ^= *p++;
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1)));
    }
    return ~c;
}

static struct machine psx_machine;

/* Direct zero-copy PS1 VRAM -> KSEG1(FB_PHYS) scanout blit with dirty-line & 480i even/odd row reuse */
static int __attribute__((optimize("O3"))) show_psx_vram_direct(int all)
{
    int vstride = 0, is24 = 0;
    const u16 *vbase = psx_vram_frame(&vstride, &is24);
    if (!vbase || is24 || ((unsigned long)vbase & 3u) || pw <= 0 || ph <= 0)
        return 0;
    volatile u32 *fb = (volatile u32 *)KSEG1(FB_PHYS);
    static u32 pair_buf[SCREEN_W / 2];
    int xs = m->xs, ys = m->ys;
    while (xs > 1 && pw * xs > SCREEN_W) xs--;
    while (ys > 1 && ph * ys > SCREEN_H) ys--;
    int out_w = (pw * xs) & ~1, out_x = ((SCREEN_W - out_w) / 2) & ~1, out_y = (SCREEN_H - ph * ys) / 2;
    if (out_y < 0) out_y = 0;

    if (xs == 2 && !(pw & 1) && pw * 2 <= SCREEN_W) {
        int wn = pw >> 1;
        if (ph > 240 && ys == 1) {
            /* 480i single-field progressive scanout: diff & convert only the 240 even VRAM lines */
            for (int y = 0; y < ph && out_y + y < SCREEN_H; y += 2) {
                const u32 *s32 = (const u32 *)(vbase + y * vstride);
                u32 *o32 = (u32 *)(before + y * pw);
                if (!all) {
                    int diff = 0;
                    for (int w = 0; w < wn; w++) {
                        if ((s32[w] ^ o32[w]) & 0x7FFF7FFFu) { diff = 1; break; }
                    }
                    if (!diff)
                        continue;
                }
                for (int w = 0; w < wn; w++) {
                    u32 c01 = s32[w];
                    o32[w] = c01;
                    u32 c0 = c01 & 0x7FFFu, c1 = (c01 >> 16) & 0x7FFFu;
                    u32 p0 = 0x8000u | ((c0 & 0x1Fu) << 10) | (c0 & 0x3E0u) | ((c0 >> 10) & 0x1Fu);
                    u32 p1 = 0x8000u | ((c1 & 0x1Fu) << 10) | (c1 & 0x3E0u) | ((c1 >> 10) & 0x1Fu);
                    pair_buf[w * 2]     = p0 | (p0 << 16);
                    pair_buf[w * 2 + 1] = p1 | (p1 << 16);
                }
                for (int r = 0; r < 2 && out_y + y + r < SCREEN_H; r++) {
                    volatile u32 *to = fb + ((u32)(out_y + y + r) * SCREEN_W + (u32)out_x) / 2;
                    for (int w = 0, n2 = wn * 2; w < n2; w++)
                        to[w] = pair_buf[w];
                }
            }
            return 1;
        }
        for (int y = 0; y < ph && out_y + y * ys < SCREEN_H; y++) {
            const u32 *s32 = (const u32 *)(vbase + y * vstride);
            u32 *o32 = (u32 *)(before + y * pw);
            if (!all) {
                int diff = 0;
                for (int w = 0; w < wn; w++) {
                    if ((s32[w] ^ o32[w]) & 0x7FFF7FFFu) { diff = 1; break; }
                }
                if (!diff)
                    continue;
            }
            for (int w = 0; w < wn; w++) {
                u32 c01 = s32[w];
                o32[w] = c01;
                u32 c0 = c01 & 0x7FFFu, c1 = (c01 >> 16) & 0x7FFFu;
                u32 p0 = 0x8000u | ((c0 & 0x1Fu) << 10) | (c0 & 0x3E0u) | ((c0 >> 10) & 0x1Fu);
                u32 p1 = 0x8000u | ((c1 & 0x1Fu) << 10) | (c1 & 0x3E0u) | ((c1 >> 10) & 0x1Fu);
                pair_buf[w * 2]     = p0 | (p0 << 16);
                pair_buf[w * 2 + 1] = p1 | (p1 << 16);
            }
            for (int r = 0; r < ys && out_y + y * ys + r < SCREEN_H; r++) {
                volatile u32 *to = fb + ((u32)(out_y + y * ys + r) * SCREEN_W + (u32)out_x) / 2;
                for (int w = 0, n2 = wn * 2; w < n2; w++)
                    to[w] = pair_buf[w];
            }
        }
        return 1;
    }
    if (xs == 3 && !(pw & 1) && pw * 3 <= SCREEN_W) {
        int wn = pw >> 1;
        for (int y = 0; y < ph && out_y + y * ys < SCREEN_H; y++) {
            const u32 *s32 = (const u32 *)(vbase + y * vstride);
            u32 *o32 = (u32 *)(before + y * pw);
            if (!all) {
                int diff = 0;
                for (int w = 0; w < wn; w++) {
                    if ((s32[w] ^ o32[w]) & 0x7FFF7FFFu) { diff = 1; break; }
                }
                if (!diff)
                    continue;
            }
            for (int w = 0; w < wn; w++) {
                u32 c01 = s32[w];
                o32[w] = c01;
                u32 c0 = c01 & 0x7FFFu, c1 = (c01 >> 16) & 0x7FFFu;
                u32 p = 0x8000u | ((c0 & 0x1Fu) << 10) | (c0 & 0x3E0u) | ((c0 >> 10) & 0x1Fu);
                u32 q = 0x8000u | ((c1 & 0x1Fu) << 10) | (c1 & 0x3E0u) | ((c1 >> 10) & 0x1Fu);
                pair_buf[w * 3]     = p | (p << 16);
                pair_buf[w * 3 + 1] = p | (q << 16);
                pair_buf[w * 3 + 2] = q | (q << 16);
            }
            for (int r = 0; r < ys && out_y + y * ys + r < SCREEN_H; r++) {
                volatile u32 *to = fb + ((u32)(out_y + y * ys + r) * SCREEN_W + (u32)out_x) / 2;
                for (int w = 0, n3 = wn * 3; w < n3; w++)
                    to[w] = pair_buf[w];
            }
        }
        return 1;
    }
    return 0;
}

/* the lines of the picture that changed, xs times as wide and ys times as high, into the middle of the test
   screen's picture (`all`: every line) */
static void __attribute__((optimize("O3"))) show(int all)
{
    /* (uncached; through the cache with its lines written back after each line is no faster: the whole 800 x 720
       takes 9 to 10 ms either way) */
    volatile u32 *fb = (volatile u32 *)KSEG1(FB_PHYS);
    static union {
        u32 pair[SCREEN_W / 2];
        u16 pixel[SCREEN_W];
    } row;
    int xs = m->xs, ys = m->ys;
    while (xs > 1 && pw * xs > SCREEN_W)
        xs--;
    while (ys > 1 && ph * ys > SCREEN_H)
        ys--;
    int out_w = (pw * xs) & ~1, out_x = (SCREEN_W - out_w) / 2 & ~1, out_y = (SCREEN_H - ph * ys) / 2;
    if (out_y < 0)
        out_y = 0;
    for (int y = 0; y < ph && out_y + y * ys < SCREEN_H; y++) {
        if (!m->colours) {                              /* 15-bit colours (the Game Boy's, ...) */
            const u16 *line = picture + y * pw;
            u16 *old = before + y * pw;
            int same = !all;
            if (!(pw & 1)) {
                const u32 *l32 = (const u32 *)line;
                const u32 *o32 = (const u32 *)old;
                for (int w = 0, wn = pw >> 1; w < wn && same; w++)
                    same = l32[w] == o32[w];
            } else {
                for (int x = 0; x < pw && same; x++)
                    same = line[x] == old[x];
            }
            if (same)
                continue;
            if (xs == 2 && pw * 2 <= SCREEN_W) {
                for (int x = 0, w = 0; x < pw; x++) {
                    u32 c = old[x] = line[x];
                    u32 p = 0x8000u | (c & 0x1Fu) << 10 | (c & 0x3E0u) | ((c >> 10) & 0x1Fu);
                    row.pair[w++] = p | (p << 16);
                }
            } else if (xs == 3 && !(pw & 1) && pw * 3 <= SCREEN_W) {
                for (int x = 0, w = 0; x < pw; x += 2) {
                    u32 c0 = old[x] = line[x], c1 = old[x + 1] = line[x + 1];
                    u32 p = 0x8000u | (c0 & 0x1Fu) << 10 | (c0 & 0x3E0u) | ((c0 >> 10) & 0x1Fu);
                    u32 q = 0x8000u | (c1 & 0x1Fu) << 10 | (c1 & 0x3E0u) | ((c1 >> 10) & 0x1Fu);
                    row.pair[w++] = p | (p << 16);
                    row.pair[w++] = p | (q << 16);
                    row.pair[w++] = q | (q << 16);
                }
            } else if (xs == 4 && pw * 4 <= SCREEN_W) {
                for (int x = 0, w = 0; x < pw; x++) {
                    u32 c = old[x] = line[x];
                    u32 p = 0x8000u | (c & 0x1Fu) << 10 | (c & 0x3E0u) | ((c >> 10) & 0x1Fu);
                    u32 pp = p | (p << 16);
                    row.pair[w++] = pp;
                    row.pair[w++] = pp;
                }
            } else if (xs == 6 && pw * 6 <= SCREEN_W) {
                for (int x = 0, w = 0; x < pw; x++) {
                    u32 c = old[x] = line[x];
                    u32 p = 0x8000u | (c & 0x1Fu) << 10 | (c & 0x3E0u) | ((c >> 10) & 0x1Fu);
                    u32 pp = p | (p << 16);
                    row.pair[w++] = pp;
                    row.pair[w++] = pp;
                    row.pair[w++] = pp;
                }
            } else {
                for (int x = 0, k = 0; x < pw && k + xs <= SCREEN_W; x++) {
                    u16 c = old[x] = line[x];
                    u16 p = (u16)(0x8000u | (c & 0x1Fu) << 10 | (c & 0x3E0u) | (c >> 10 & 0x1Fu));
                    for (int i = 0; i < xs; i++)
                        row.pixel[k++] = p;
                }
            }
            goto out;
        }
        const u8 *line = (const u8 *)picture + y * pw;
        u8 *old = (u8 *)before + y * pw;
        int same = !all;
        for (int x = 0; x < pw && same; x++)
            same = line[x] == old[x];
        if (same)
            continue;
        if (xs == 3) {
            for (int x = 0, w = 0; x < pw; x += 2) {
                u32 p = colours[old[x] = line[x]], q = colours[old[x + 1] = line[x + 1]];
                row.pair[w++] = p | p << 16;
                row.pair[w++] = p | q << 16;
                row.pair[w++] = q | q << 16;
            }
        } else {
            for (int x = 0, k = 0; x < pw && k + xs <= SCREEN_W; x++) {
                u16 p = colours[old[x] = line[x]];
                for (int i = 0; i < xs; i++)
                    row.pixel[k++] = p;
            }
        }
    out:
        for (int r = 0; r < ys && out_y + y * ys + r < SCREEN_H; r++) {
            volatile u32 *to = fb + ((u32)(out_y + y * ys + r) * SCREEN_W + (u32)out_x) / 2;
            for (int w = 0; w < out_w / 2; w++)
                to[w] = row.pair[w];
        }
    }
}

static void tap(u16 button, int frames)
{
    for (int i = 0; i < TAP_BUTTONS; i++)
        if (button & (1u << i))
            taps[i] = (u8)frames;
}

/* the buttons held now; -1 when the player asked to end.  `start`: a game begins -- the USB keyboard's keys
   held now (the Enter that opened it in the explorer) count only once they were let go */
static int buttons(int start)
{
    static u8 esc;                      /* an escape sequence's bytes so far: 1 ESC, 2 ESC [ */
    static u64 esc_at;
    static u32 stale;                   /* keys[] held since the start, not let go yet */
    u16 pad = 0;
    if (start)
        esc = 0;
    int c;
    usb_int_poll();
    (void)kbd_poll();
    while ((c = kbd_getc()) >= 0)
        if (c == 3 && !m->keyboard)
            return -1;
    if (m->keyboard) {                  /* a computer's keyboard: every key to it, the arrows also as buttons */
        u8 usages[16];
        int n = kbd_held_all(usages, 16);
        for (int i = 0; i < n; i++)
            if (usages[i] == 0x29)      /* Esc ends */
                return -1;
        m->keyboard(usages, start ? 0 : n);
    }
    static const struct {
        u8 usage;
        u16 button;
    } keys[] = {{0x52, PAD_UP}, {0x1A, PAD_UP}, {0x51, PAD_DOWN}, {0x16, PAD_DOWN}, {0x50, PAD_LEFT},
                {0x04, PAD_LEFT}, {0x4F, PAD_RIGHT}, {0x07, PAD_RIGHT}, {0x1B, PAD_A}, {0x0E, PAD_A},
                {0x1D, PAD_B}, {0x0D, PAD_B}, {0x28, PAD_START}, {0x2B, PAD_SELECT}, {0x2C, PAD_SELECT},
                {0x06, PAD_X}, {0x0C, PAD_X}, {0x19, PAD_Y}, {0x18, PAD_Y},
                {0x14, PAD_L}, {0x0F, PAD_L}, {0x08, PAD_R}, {0x12, PAD_R}};
    for (unsigned i = 0; i < (m->keyboard ? 4u : sizeof(keys) / sizeof(keys[0])); i++) {
        unsigned k = m->keyboard ? 2 * i : i;           /* (a computer's keyboard: the arrows alone) */
        int down = kbd_held(keys[k].usage);
        if (start && down)
            stale |= (1u << i);
        else if (!down)
            stale &= ~(1u << i);
        else if (!(stale & (1u << i)))
            pad |= keys[k].button;
    }
    static int psx_r_was_down;
    if (start)
        psx_r_was_down = kbd_held(0x15);
    else if (m == &psx_machine) {
        int r_down = kbd_held(0x15);    /* R on USB keyboard toggles 50 Hz PAL <-> 60 Hz NTSC */
        if (r_down && !psx_r_was_down) {
            int to_ntsc = psx_pal();
            psx_set_region(to_ntsc ? 'U' : 'E');
            psx_machine.frame_us = to_ntsc ? PSX_FRAME_US : PSX_FRAME_US_PAL;
        }
        psx_r_was_down = r_down;
    }
    while ((c = uart_getc()) >= 0) {
        if (c == 3)
            return -1;
        if (esc == 2) {
            esc = 0;
            tap(c == 'A' ? PAD_UP : c == 'B' ? PAD_DOWN : c == 'C' ? PAD_RIGHT : c == 'D' ? PAD_LEFT : 0, TAP_FRAMES);
            continue;
        }
        if (esc == 1) {
            esc = c == '[' ? 2 : 0;
            continue;
        }
        if (m->typed && c != 27) {      /* a computer: the character typed on it */
            m->typed((char)c);
            continue;
        }
        switch (c) {
        case 27: esc = 1, esc_at = now_ms(); break;
        case 'w': tap(PAD_UP, TAP_FRAMES); break;
        case 's': tap(PAD_DOWN, TAP_FRAMES); break;
        case 'a': tap(PAD_LEFT, TAP_FRAMES); break;
        case 'd': tap(PAD_RIGHT, TAP_FRAMES); break;
        case 'x': case 'k': tap(PAD_A, TAP_FRAMES); break;
        case 'z': case 'j': tap(PAD_B, TAP_FRAMES); break;
        case 'c': case 'i': tap(PAD_X, TAP_FRAMES); break;
        case 'v': case 'u': tap(PAD_Y, TAP_FRAMES); break;
        case 'q': case 'l': tap(PAD_L, TAP_FRAMES); break;
        case 'e': case 'o': tap(PAD_R, TAP_FRAMES); break;
        case 'r':
            if (m == &psx_machine) {
                int to_ntsc = psx_pal();
                psx_set_region(to_ntsc ? 'U' : 'E');
                psx_machine.frame_us = to_ntsc ? PSX_FRAME_US : PSX_FRAME_US_PAL;
            }
            break;
        case '\r': case '\n': tap(PAD_START, TAP_FRAMES); break;
        case '\t': case ' ': tap(PAD_SELECT, TAP_FRAMES); break;
        }
    }
    if (esc == 1 && now_ms() - esc_at > 150)
        return -1;                      /* (ESC alone, nothing after it: the Esc key) */
    struct ir_event ev;
    static u16 ir_button;
    while (ir_poll(&ev)) {
        if (ev.valid && !ev.repeat) {
            const char *name = ir_key_name(ev.code);
            if (m->typed && name && name[0] >= '0' && name[0] <= '9' && !name[1]) {
                m->typed(name[0]);
                ir_button = 0;
                continue;
            }
            static const struct {
                const char *name;
                u16 button;
            } remote[] = {{"UP", PAD_UP}, {"DOWN", PAD_DOWN}, {"LEFT", PAD_LEFT}, {"RIGHT", PAD_RIGHT},
                          {"OK", PAD_A}, {"0", PAD_B}, {"MENU", PAD_START}, {"INFO", PAD_SELECT},
                          {"1", PAD_X}, {"2", PAD_Y}, {"PAGE-", PAD_L}, {"PAGE+", PAD_R}};
            ir_button = 0;
            for (unsigned i = 0; name && i < sizeof(remote) / sizeof(remote[0]); i++) {
                const char *a = name, *b = remote[i].name;
                while (*a && *a == *b)
                    a++, b++;
                if (!*a && !*b)
                    ir_button = remote[i].button;
            }
            if (name && name[0] == 'E' && name[1] == 'X')      /* EXIT */
                return -1;
        }
        if (ev.valid)
            tap(ir_button, IR_FRAMES);                          /* (a repeat frame: the same key still held) */
    }
    if (!panel_present()) {
        int held = panel_buttons();
        if (held & PANEL_BUTTON_UP)
            pad |= PAD_START;
        if (held & PANEL_BUTTON_DOWN)
            pad |= PAD_A;
    }
    for (int i = 0; i < TAP_BUTTONS; i++)
        if (taps[i]) {
            taps[i]--;
            pad |= (u16)(1u << i);
        }
    return pad;
}

/* "frame:buttons,frame:buttons,...": the hex buttons held from that frame on (a test's script) */
static u16 scripted(const char **script, u32 frame, u16 pad)
{
    const char *s = *script;
    while (*s) {
        u32 at = 0, v = 0;
        const char *p = s;
        while (*p >= '0' && *p <= '9')
            at = at * 10 + (u32)(*p++ - '0');
        if (*p != ':' || at > frame)
            break;
        for (p++; (*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'); p++)
            v = v * 16 + (u32)(*p <= '9' ? *p - '0' : *p - 'a' + 10);
        pad = (u16)v;
        s = *p == ',' ? p + 1 : p;
        if (*p != ',')
            break;
    }
    *script = s;
    return pad;
}

/* the save file of a cartridge: its whole file name and ".sav" ("4:/games/a.nes" -> "4:/games/a.nes.sav": a.gb
   beside it has a save of its own); old: the name used before, the ending replaced ("4:/games/a.sav"), which
   two machines' games of one name shared -- one overwrote the other's.  0: the name does not fit */
static int save_path(const char *path, char *out, int size, int old)
{
    int n = 0, dot = -1;
    for (; path[n]; n++)
        if (path[n] == '.')
            dot = n;
        else if (path[n] == '/' || path[n] == '\\')
            dot = -1;
    if (dot < 0 || !old)
        dot = n;
    if (dot + 5 > size)
        return 0;
    for (int i = 0; i < dot; i++)
        out[i] = path[i];
    out[dot] = '.';
    out[dot + 1] = 's';
    out[dot + 2] = 'a';
    out[dot + 3] = 'v';
    out[dot + 4] = 0;
    return 1;
}

/* while an archive is unpacked (image.c asks every 32 KB it makes and every 64 blocks): the clock read, which
   feeds the watchdog -- a large archive takes seconds --, and Ctrl-C ends it */
static int unpack_poll(void)
{
    (void)now_ms();
    return uart_getc() == 3;
}

/* a game in a .zip or a .gz (an Amiga's .adz is one), read whole at image: the archive moved to the top of the
   media area, the game unpacked to its start.  The game's size (the file's own when it is no archive), or -1;
   as: the path the machine is told -- the archive's directory and the game's own name (its folders dropped),
   since the Spectrum, the C64 and the SC-3000 know a file by its extension; a .gz without a name in it: the
   file's own name without .gz (.adz: .adf) */
static int unpack(const char *path, u8 *image, u32 got, char *as, int max)
{
    int n = 0;
    while (path[n] && n < max - 1) {
        as[n] = path[n];
        n++;
    }
    as[n] = 0;
    int zip = zip_is(image, got);
    if (!zip && !gz_is(image, got))
        return (int)got;
    u8 *top = image + MEDIA_MAX - got;
    for (u32 i = got; i-- > 0;)                 /* (moved up: overlapping, so from the end) */
        top[i] = image[i];
    char name[96];
    u32 size = 0;
    image_poll = unpack_poll;
    const char *why = zip ? zip_unpack(top, got, 0, image, MEDIA_MAX - got, &size, name, sizeof(name))
                          : gz_unpack(top, got, image, MEDIA_MAX - got, &size, name, sizeof(name));
    image_poll = 0;
    if (why) {
        uprintf("%s: %s\n", path, why);
        return -1;
    }
    int dir = 0, dot = -1;                      /* (the path's directory: up to its last / \ or :) */
    for (int i = 0; path[i]; i++)
        if (path[i] == '/' || path[i] == '\\' || path[i] == ':')
            dir = i + 1, dot = -1;
        else if (path[i] == '.')
            dot = i;
    const char *base = name;
    for (const char *q = name; *q; q++)
        if (*q == '/' || *q == '\\')
            base = q + 1;
    n = dir < max - 1 ? dir : max - 1;
    if (*base) {
        for (int i = 0; base[i] && n < max - 1; i++)
            as[n++] = base[i];
    } else {                                    /* (a .gz with no name: the file's) */
        int adz = dot > 0 && (path[dot + 1] | 32) == 'a' && (path[dot + 2] | 32) == 'd' &&
                  (path[dot + 3] | 32) == 'z' && !path[dot + 4];
        int end = dot > dir ? dot : n;
        for (int i = dir; i < end && n < max - 1; i++)
            as[n++] = path[i];
        for (const char *e = adz ? ".adf" : ""; *e && n < max - 1; e++)
            as[n++] = *e;
    }
    as[n] = 0;
    uprintf("%s: %s unpacked (%u bytes)\n", path, *base ? base : as + dir, size);
    return (int)size;
}

static u32 psx_open_fsize;
static const struct machine cps_machine;
static const struct machine s16_machine;

/* 'nes' / 'gb' [-f frames] [-k script] <file>: frames 0 = until the player ends it.  0, -1 it could not
   start */
static int play(const struct machine *machine, const char *path, u32 frames, const char *script)
{
    m = machine;
    u8 *image = (u8 *)KSEG0(MEDIA_PHYS);
    u32 size = 0;
    tv_opening(path, 0);                        /* (on the TV at once: reading a game takes a moment) */
    u32 head_lim = (m == &psx_machine) ? 4096u : MEDIA_MAX;
    int got = *path ? disk_read_head(path, image, head_lim, &size) : 0;      /* ("": no file -- BASIC) */
    if (m == &psx_machine) {
        psx_open_fsize = size;
        if (got > 0 && size > 4096u && size <= MEDIA_MAX &&
            !(got >= 512 && image[0] == 'P' && image[1] == 'S' && image[2] == 'X' && image[3] == 'S'))
            got = disk_read_head(path, image, MEDIA_MAX, &size);
    }
    const char *why = 0;
    if (got >= 0 && size > MEDIA_MAX && m != &psx_machine && !(m == &cps_machine && size <= MEDIA_MAX + 0x0097FE00u)) {
        uprintf("%s: %u bytes -- more than a cartridge file can be here (%u MB)\n", path, size, MEDIA_MAX >> 20);
        got = -1;
    }
    char as[160];                               /* (a game in an archive: its own name, beside the archive) */
    if (got > 0 && size <= MEDIA_MAX && !((m == &cps_machine || m == &s16_machine) && zip_is(image, (u32)got)))
        got = unpack(path, image, (u32)got, as, sizeof(as));
    else
        as[0] = 0;
    if (got >= 0 && (why = m->load(image, (u32)got, *as ? as : path)) != 0) {
        uprintf("%s: %s\n", path, why);
        got = -1;
    }
    if (got < 0) {
        tv_failed(path, 0, !frames);            /* (a test's run: no waiting) */
        return -1;
    }
    uprintf("%s: %s\n", path, m->info());
    char sav[128], old_sav[128];
    u32 ram_size;
    int battery, have_sav = save_path(path, sav, sizeof(sav), 0), foreign = 0;
    u8 *ram = m->save_ram(&ram_size, &battery);
    if (battery && have_sav) {
        const char *from = 0;
        static struct disk_entry e;
        if (disk_exists(sav)) {
            /* (a save of another size is not this cartridge's: the file run with another machine's player
               once -- a Game Boy game as a Master System's, which keeps 32 KB for any game.  It is neither
               read nor written over) */
            if (disk_stat(sav, &e) == 0 && e.kind == DISK_FILE && e.size == ram_size && !e.size_hi)
                from = sav;
            else
                foreign = 1;
        }
        if (!from && save_path(path, old_sav, sizeof(old_sav), 1) && disk_exists(old_sav) &&
            disk_stat(old_sav, &e) == 0 && e.kind == DISK_FILE && e.size == ram_size && !e.size_hi)
            from = old_sav;             /* (a save from before the names told the machines apart) */
        u32 n = 0;
        if (foreign)
            uprintf("%s is not this cartridge's save (its RAM is %u bytes): left alone, and nothing will be "
                    "saved while it is there\n", sav, ram_size);
        if (from && disk_read_head(from, ram, ram_size, &n) > 0)
            uprintf("its battery RAM read from %s\n", from);
        (void)m->save_changed();
    }
    for (int i = 0; i < m->colours; i++)
        colours[i] = RGB(m->rgb[i][0], m->rgb[i][1], m->rgb[i][2]);
    for (int i = 0; i < TAP_BUTTONS; i++)
        taps[i] = 0;
    pw = m->w;
    ph = m->h;
    gfx_target(0);
    gfx_fill(0, 0, SCREEN_W, SCREEN_H, RGB(0, 0, 0));
    gfx_view(0);
    uprintf("playing: %s\n", m->keys ? m->keys : "arrows or W A S D, X = A, Z = B, Enter = Start, Tab = Select; "
            "Ctrl-C or Esc ends");
    u32 cur_frame_us = m->frame_us;
    u32 frame_ticks = ticks_per_ms() * (cur_frame_us / 1000u) + ticks_per_ms() * (cur_frame_us % 1000u) / 1000u;
    u64 next = now_ticks();
    u32 n = 0, late = 0, emu = 0, draw = 0, per = ticks_per_ms() / 1000u;   /* (emu, draw: microseconds) */
    u32 slowest = 0, slowest_at = 0, slowest_draw = 0, over = 0;     /* (the longest frame's run and draw
                                                                       together; frames longer than their time) */
    u16 pad = 0;
    int first = 1, by_script = *script != 0;    /* (a test's buttons: the script's alone) */
    int psx_live = (m == &psx_machine && !frames), psx_skipped = 0;
    if (m == &psx_machine)
        psx_set_skip_render(psx_live ? 1 : 0);
    /* sound, played as it is made (a test's run of -f frames makes none); what does not fit in the sound's ring
       (a game ahead of it) is dropped */
    static s16 samples[4096];
    u32 dropped = 0, sound_us = 0;              /* (sound_us: the run's time in m->audio and snd_write) */
    int sound = !frames && m->audio && snd_init(0) == 0;
    if (sound)
        m->audio_rate(snd_rate());
    u64 started_ms = now_ms();
    for (;; n++) {
        if (frames && n == frames)
            break;
        int held = buttons(n == 0);
        if (held < 0)
            break;
        pad = by_script ? scripted(&script, n, pad) : (u16)held;
        int do_skip = (psx_live && n > 0 && !first && psx_skipped < 3 && now_ticks() > next);
        if (psx_live)
            psx_set_skip_render(do_skip ? 2 : 1);
        psx_skipped = do_skip ? (psx_skipped + 1) : 0;
        u64 t0 = now_ticks();
        m->frame(pad, picture);
        u64 ts = now_ticks();
        if (sound) {
            int k = m->audio(samples, (int)(sizeof(samples) / sizeof(samples[0]))), room = snd_room();
            if (k > room)
                dropped += (u32)(k - room), k = room;
            if (k > 0)
                snd_write(samples, k);
        }
        if (m->frame_us != cur_frame_us) {
            cur_frame_us = m->frame_us;
            frame_ticks = ticks_per_ms() * (cur_frame_us / 1000u) + ticks_per_ms() * (cur_frame_us % 1000u) / 1000u;
        }
        if (m->size) {                          /* (the game changed its picture's size: drawn again whole) */
            int w, h;
            m->size(&w, &h);
            if (w != pw || h != ph) {
                pw = w;
                ph = h;
                gfx_fill(0, 0, SCREEN_W, SCREEN_H, RGB(0, 0, 0));
                first = 1;
            }
        }
        u64 t1 = now_ticks();
        if (!do_skip) {
            if (!(psx_live && show_psx_vram_direct(first)))
                show(first);
            first = 0;
        }
        u64 t2 = now_ticks();
        emu += (u32)(t1 - t0) / per;
        draw += (u32)(t2 - t1) / per;
        sound_us += (u32)(t1 - ts) / per;
        u32 took = (u32)(t2 - t0) / per;
        if (took > slowest)
            slowest = took, slowest_at = n, slowest_draw = (u32)(t2 - t1) / per;
        if (took > m->frame_us)
            over++;
        if (m->jammed()) {
            uprintf("the game's program stopped %s (an instruction that halts it) at frame %u\n", m->cpu, n);
            break;
        }
        if (!frames) {                          /* (a test's frames run as fast as they go) */
            next += frame_ticks;
            if (now_ticks() > next + 4u * frame_ticks) {
                next = now_ticks() - (psx_live ? frame_ticks : 0u);     /* too far behind: no catching up */
                late++;
            }
            while (now_ticks() < next)
                console_service();
        }
    }
    u32 ms = (u32)(now_ms() - started_ms);
    uprintf("%u frames in %u.%u s; a frame took %u us to run and %u us to draw (the slowest %u us of %u, frame %u, "
            "%u of it drawing; %u longer)%s; picture CRC-32 %08x\n", n, ms / 1000, ms % 1000 / 100, n ? emu / n : 0,
            n ? draw / n : 0,
            slowest, m->frame_us, slowest_at, slowest_draw, over, late ? " (some frames came late)" : "",
            crc32((const u8 *)picture, (u32)(pw * ph * (m->colours ? 1 : 2))));
    if (sound) {
        uprintf("sound: %u us a frame of the run handing it over\n", n ? sound_us / n : 0);
        m->audio_rate(0);
        snd_stop();
        if (dropped)
            uprintf("sound: %u samples did not fit in the sound's ring\n", dropped);
    }
    if (battery && have_sav && !foreign && m->save_changed())
        disk_write_file(sav, ram, ram_size, 0);
    return 0;
}

int nes_play(const char *path, u32 frames, const char *script)
{
    return play(&nes_machine, path, frames, script);
}

int gb_play(const char *path, u32 frames, const char *script)
{
    return play(&gb_machine, path, frames, script);
}

int sms_play(const char *path, u32 frames, const char *script)
{
    return play(&sms_machine, path, frames, script);
}

int gg_play(const char *path, u32 frames, const char *script)
{
    return play(&gg_machine, path, frames, script);
}

int sg_play(const char *path, u32 frames, const char *script)
{
    return play(&sg_machine, path, frames, script);
}

/* the Atari 2600: 160 x 228 of its 128 colours' numbers, five times as wide and three times as high (800 x
   684: its pixels were wide on a TV) */
static const char *a26_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    return a26_load(image, size);
}

static void a26_one(u16 pad, void *picture)
{
    a26_frame((u8)pad, (u8 *)picture);
}

static const struct machine a26_machine = {A26_W, A26_H, 5, 3, A26_FRAME_US, a26_open, a26_info, a26_one,
                                           a26_save_ram, a26_save_changed, a26_jammed, a26_rgb, 128, "the 6507",
                                           0, 0, "arrows or W A S D, X or Z = fire, Enter = the console's Reset, "
                                           "Tab = Select; Ctrl-C or Esc ends", 0, 0, 0};

int a26_play(const char *path, u32 frames, const char *script)
{
    return play(&a26_machine, path, frames, script);
}

/* the Commodore 64 (PAL): 352 x 240 (the 320 x 200 screen with 16 pixels of border left and right, 20 lines
   above and below), three times (1056 x 720).  Its ROMs are not in the demo: kernal.rom (8 KB), basic.rom
   (8 KB) and chargen.rom (4 KB) beside the program, in c64/ or at the top of its disk (VICE's files work,
   renamed) */
static u8 c64_kernal[8192], c64_basic[8192], c64_chargen[4096];
static u8 c64_matrix[8];

static const char *c64_open(u8 *image, u32 size, const char *path)
{
    if (!rom_read(path, "c64", "kernal.rom", c64_kernal, sizeof(c64_kernal)) ||
        !rom_read(path, "c64", "basic.rom", c64_basic, sizeof(c64_basic)) ||
        !rom_read(path, "c64", "chargen.rom", c64_chargen, sizeof(c64_chargen)))
        return "no kernal.rom, basic.rom and chargen.rom (the C64's ROMs: 8, 8 and 4 KB) beside it, in c64/ or "
               "at the top of its disk";
    for (int i = 0; i < 8; i++)
        c64_matrix[i] = 0;
    return c64_load(c64_kernal, c64_basic, c64_chargen, size ? image : 0, size, path);
}

static void c64_one(u16 pad, void *picture)
{
    c64_frame((u8)pad, c64_matrix, (u16 *)picture);
}

static void c64_keyboard(const u8 *usages, int n)
{
    c64_keys_from_hid(usages, n, c64_matrix);
}

static void c64_typed(char c)
{
    char s[2] = {c, 0};
    c64_type(s);
}

static const struct machine c64_machine = {C64_W, C64_H, 3, 3, C64_FRAME_US, c64_open, c64_info, c64_one,
                                           c64_save_ram, c64_save_changed, c64_jammed, 0, 0, "the 6510",
                                           c64_keyboard, c64_typed,
                                           "the USB keyboard is the C64's (Tab = RUN/STOP, PageUp = RESTORE, Alt = "
                                           "C=), its arrows joystick 2 (fire: right Ctrl, the remote's OK; F9 "
                                           "swaps the ports); the remote's MENU = SPACE, INFO = F7; what is typed "
                                           "on this console is typed on it; Esc ends", 0, 0, 0};

int c64_play(const char *path, u32 frames, const char *script)
{
    return play(&c64_machine, path, frames, script);
}

/* the Amiga 500 (PAL): 352 x 272 (PAL's 320 x 256 screen with 16 pixels of border left and right, 8 lines
   above and below), twice as large (704 x 544).  Its Kickstart is not in the demo: kick.rom (256 or 512 KB, the
   user's own), or AROS's free replacement aros-rom.bin with aros-ext.bin, beside the floppy image, in amiga/ or
   at the top of its disk.  amiga_load copies them: read into the top of the media area, above the .adf */
#define AMIGA_ROM_AT  (MEDIA_PHYS + MEDIA_MAX - 0x00100000u)
static u8 amiga_keys[16];

static const char *amiga_open(u8 *image, u32 size, const char *path)
{
    u8 *kick = (u8 *)KSEG0(AMIGA_ROM_AT), *ext = kick + 0x80000;
    u32 kick_size, ext_size = 0;
    if (size > AMIGA_ROM_AT - MEDIA_PHYS)
        return "too large for a floppy image";
    kick_size = rom_find(path, "amiga", "kick.rom", kick, 0x40000, 0x80000);
    if (!kick_size) {
        kick_size = rom_find(path, "amiga", "aros-rom.bin", kick, 0x80000, 0x80000);
        if (kick_size)
            ext_size = rom_find(path, "amiga", "aros-ext.bin", ext, 0x80000, 0x80000);
        if (!kick_size || !ext_size)
            return "no kick.rom (a Kickstart, 256 or 512 KB) and no aros-rom.bin with aros-ext.bin (AROS's free "
                   "one) beside it, in amiga/ or at the top of its disk";
    }
    for (int i = 0; i < 16; i++)
        amiga_keys[i] = 0;
    return amiga_load(kick, kick_size, ext_size ? ext : 0, ext_size, size ? image : 0, size, path);
}

static void amiga_one(u16 pad, void *picture)
{
    amiga_frame((u8)pad, amiga_keys, (u16 *)picture);
}

static void amiga_keyboard(const u8 *usages, int n)
{
    amiga_keys_from_hid(usages, n, amiga_keys);
}

static void amiga_typed(char c)
{
    char s[2] = {c, 0};
    amiga_type(s);
}

static const struct machine amiga_machine = {AMIGA_W, AMIGA_H, 2, 2, AMIGA_FRAME_US, amiga_open, amiga_info,
                                             amiga_one, amiga_save_ram, amiga_save_changed, amiga_jammed, 0, 0,
                                             "the 68000", amiga_keyboard, amiga_typed,
                                             "the USB keyboard is the Amiga's, its arrows the joystick (fire: right "
                                             "Ctrl, the remote's OK); the mouse button: Page Up / Page Down, the "
                                             "remote's 0; the remote's MENU = Return, INFO = Space; what is typed "
                                             "on this console is typed on it; Esc ends", 0, 0, 0};

int amiga_play(const char *path, u32 frames, const char *script)
{
    return play(&amiga_machine, path, frames, script);
}

/* a DOS PC (an AT with a VGA): the 320 x 200 picture three times as large (960 x 600).  One program (.exe or
   .com) runs, with no data files beside it (Magicland Dizzy needs none) */
static u8 dos_keys[32];

static const char *dos_open(u8 *image, u32 size, const char *path)
{
    for (int i = 0; i < 32; i++)
        dos_keys[i] = 0;
    dos_clear_files();
    dos_args("");
    return dos_load(image, size, path);
}

static void dos_one(u16 pad, void *picture)
{
    dos_frame((u8)pad, dos_keys, (u16 *)picture);
}

static void dos_keyboard(const u8 *usages, int n)
{
    dos_keys_from_hid(usages, n, dos_keys);
}

static void dos_typed(char c)
{
    char s[2] = {c, 0};
    dos_type(s);
}

static const struct machine dos_machine = {DOS_W, DOS_H, 3, 3, DOS_FRAME_US, dos_open, dos_info, dos_one,
                                           dos_save_ram, dos_save_changed, dos_jammed, 0, 0, "the 286",
                                           dos_keyboard, dos_typed,
                                           "the USB keyboard is the PC's (but Esc, which ends); the remote: arrows, "
                                           "OK = Up, 0 = Space, MENU = Enter, INFO = Esc; what is typed on this "
                                           "console is typed on it", 0, 0, 0};

int dos_play(const char *path, u32 frames, const char *script)
{
    return play(&dos_machine, path, frames, script);
}

int zx_play(const char *path, u32 frames, const char *script)
{
    return play(&zx_machine, path, frames, script);
}

/* the Mega Drive / Genesis: 320 x 224 (256 wide in H32, 240 high in PAL's V30) three times as large (960 x 672 of
   1280 x 720), at the console's own rate (NTSC's 59.92 frames a second, PAL's 49.70: chosen from the cartridge's
   header when it is loaded, or by md_play_region), with its sound.  The pad: the player's A (X, the remote's OK)
   is its B, the player's B (Z, the remote's 0) its A, Select (Tab / Space, the remote's INFO) its C, Start its
   Start: a 3-button pad */
static struct machine md_machine;
static int md_region;

void md_play_region(int region)
{
    md_region = region;
}

static const char *md_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    const char *why = md_load(image, size, md_region);
    md_machine.frame_us = md_pal() ? MD_FRAME_US_PAL : MD_FRAME_US;
    return why;
}

static void md_one(u16 pad, void *picture)
{
    md_frame(pad, (u16 *)picture);
}

static void md_size(int *w, int *h)
{
    *w = md_width();
    *h = md_height();
}

static struct machine md_machine = {MD_W_MAX, 224, 3, 3, MD_FRAME_US, md_open, md_info, md_one, md_save_ram,
                                    md_save_changed, md_jammed, 0, 0, "the 68000", 0, 0,
                                    "arrows or W A S D, Z = A, X = B, Tab / Space = C, Enter = Start; Ctrl-C or "
                                    "Esc ends", md_size, md_audio_rate, md_audio};

int md_play(const char *path, u32 frames, const char *script)
{
    return play(&md_machine, path, frames, script);
}

/* the PC Engine / TurboGrafx-16: 256 x 240 (or 320 / 512 wide as the game sets the VDC) enlarged to the TV's
   height (three times at 256 / 320, twice at 512), with its 6-channel PSG sound and 2 KB backup RAM (.sav) */
static const char *pce_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    return pce_load(image, size);
}

static void pce_one(u16 pad, void *pic_out)
{
    pce_frame(pad, (u16 *)pic_out);
}

static void pce_size(int *w, int *h)
{
    *w = pce_width();
    *h = pce_height();
}

static const struct machine pce_machine = {
    PCE_W_DEF, PCE_H_DEF, 3, 3, PCE_FRAME_US, pce_open, pce_info, pce_one, pce_save_ram, pce_save_changed,
    pce_jammed, 0, 0, "the HuC6280", 0, 0,
    "arrows or W A S D, X = I, Z = II, Enter = Run, Tab = Select (C/V/Q/E = III..VI); Ctrl-C or Esc ends",
    pce_size, pce_audio_rate, pce_audio
};

int pce_play(const char *path, u32 frames, const char *script)
{
    return play(&pce_machine, path, frames, script);
}

/* the ColecoVision (256 x 192, three times: 768 x 576): optional coleco.rom (8 KB) beside the game or in col/,
   otherwise the built-in OS-7 compatible BIOS runs it; 0-9, - (*) and = (#) on the USB keyboard press its
   12-key pad alongside Enter = 1 and Tab = * */
#define COL_BIOS_AT (MEDIA_PHYS + MEDIA_MAX - 0x00010000u)

static const char *col_open(u8 *image, u32 size, const char *path)
{
    if (size > COL_BIOS_AT - MEDIA_PHYS)
        return "too large for a ColecoVision cartridge";
    u8 *bios = (u8 *)KSEG0(COL_BIOS_AT);
    u32 got_bios = rom_find(path, "col", "coleco.rom", bios, 0x2000u, 0x2000u);
    col_set_key(0xFFu);
    return col_load(got_bios == 0x2000u ? bios : 0, image, size);
}

static void col_one(u16 pad, void *pic_out)
{
    u8 key = 0xFFu;
    if (kbd_held(0x27)) key = 0;                        /* 0 */
    for (int d = 1; d <= 9; d++)
        if (kbd_held((u8)(0x1Du + d))) key = (u8)d;     /* 1..9 */
    if (kbd_held(0x2Du)) key = 10;                      /* - -> * */
    if (kbd_held(0x2Eu)) key = 11;                      /* = -> # */
    col_set_key(key);
    col_frame(pad, (u16 *)pic_out);
}

static const struct machine col_machine = {
    COL_W, COL_H, 3, 3, COL_FRAME_US, col_open, col_info, col_one, col_save_ram, col_save_changed,
    col_jammed, 0, 0, "the Z80", 0, 0,
    "arrows or W A S D, X = fire 1, Z = fire 2, Enter = keypad 1, Tab = *, C = # (0..9/- /= on USB keyboard); "
    "Ctrl-C or Esc ends", 0, col_audio_rate, col_audio
};

int col_play(const char *path, u32 frames, const char *script)
{
    return play(&col_machine, path, frames, script);
}

/* the MSX1 (256 x 192, three times: 768 x 576): optional msx.rom or cbios_main_msx1.rom (32 KB) beside the
   cartridge or in msx/, otherwise the built-in MSX1 BIOS starts the cartridge; AY-3-8910 + Konami SCC sound */
#define MSX_BIOS_AT (MEDIA_PHYS + MEDIA_MAX - 0x00020000u)

static const char *msx_open(u8 *image, u32 size, const char *path)
{
    if (size > MSX_BIOS_AT - MEDIA_PHYS)
        return "too large for an MSX1 cartridge";
    u8 *bios = (u8 *)KSEG0(MSX_BIOS_AT);
    u32 got_bios = rom_find(path, "msx", "msx.rom", bios, 0x8000u, 0x8000u);
    if (!got_bios)
        got_bios = rom_find(path, "msx", "cbios_main_msx1.rom", bios, 0x8000u, 0x8000u);
    return msx_load(got_bios == 0x8000u ? bios : 0, image, size);
}

static void msx_one(u16 pad, void *pic_out)
{
    u8 usages[16];
    int n = kbd_held_all(usages, 16);
    msx_keys_from_hid(usages, n);
    msx_frame(pad, (u16 *)pic_out);
}

static const struct machine msx_machine = {
    MSX_W, MSX_H, 3, 3, MSX_FRAME_US, msx_open, msx_info, msx_one, msx_save_ram, msx_save_changed,
    msx_jammed, 0, 0, "the Z80", 0, 0,
    "arrows or W A S D, X = trigger A / Space, Z = trigger B / M, Enter = Return / F1, Tab = Select / F2 (plus "
    "USB keyboard); Ctrl-C or Esc ends", 0, msx_audio_rate, msx_audio
};

int msx_play(const char *path, u32 frames, const char *script)
{
    return play(&msx_machine, path, frames, script);
}

/* the MSX2 (Yamaha V9938: 256/512 x 192/212, 128 KB VRAM, SCREEN 0..8, hardware blitter, 256 KB Memory Mapper,
   RP5C01 RTC, .mx2 / .rom cartridges and FAT12 .dsk floppy disks; optional msx2.rom / cbios_main_msx2.rom and
   msx2ext.rom / cbios_sub.rom in msx2/ or msx/, else built-in MSX2 BIOS + Sub-ROM; AY-3-8910 + SCC + YM2413 sound) */
static struct machine msx2_machine;

static const char *msx2_open(u8 *image, u32 size, const char *path)
{
    u8 *work = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u8 *b_main = work;
    u8 *b_sub  = work + 0x8000u;
    u32 got_m = rom_find(path, "msx2", "msx2.rom", b_main, 0x8000u, 0x8000u);
    if (!got_m)
        got_m = rom_find(path, "msx2", "cbios_main_msx2.rom", b_main, 0x8000u, 0x8000u);
    if (!got_m)
        got_m = rom_find(path, "msx", "msx2.rom", b_main, 0x8000u, 0x8000u);
    if (!got_m)
        got_m = rom_find(path, "msx", "cbios_main_msx2.rom", b_main, 0x8000u, 0x8000u);

    u32 got_s = rom_find(path, "msx2", "msx2ext.rom", b_sub, 0x4000u, 0x4000u);
    if (!got_s)
        got_s = rom_find(path, "msx2", "cbios_sub.rom", b_sub, 0x4000u, 0x4000u);
    if (!got_s)
        got_s = rom_find(path, "msx", "msx2ext.rom", b_sub, 0x4000u, 0x4000u);
    if (!got_s)
        got_s = rom_find(path, "msx", "cbios_sub.rom", b_sub, 0x4000u, 0x4000u);

    msx2_machine.xs = 3;
    msx2_machine.ys = 3;
    return msx2_load(got_m == 0x8000u ? b_main : 0, got_s == 0x4000u ? b_sub : 0, image, size, path);
}

static void msx2_size(int *w, int *h)
{
    *w = msx_width();
    *h = msx_height();
    msx2_machine.xs = (*w <= 256) ? 3 : 2;
    msx2_machine.ys = 3;
}

static struct machine msx2_machine = {
    MSX_W, MSX_H, 3, 3, MSX_FRAME_US, msx2_open, msx_info, msx_one, msx_save_ram, msx_save_changed,
    msx_jammed, 0, 0, "the Z80", 0, 0,
    "arrows or W A S D, X = trigger A / Space, Z = trigger B / M, Enter = Return / F1, Tab = Select / F2 (plus "
    "USB keyboard); Ctrl-C or Esc ends",
    msx2_size, msx_audio_rate, msx_audio
};

int msx2_play(const char *path, u32 frames, const char *script)
{
    return play(&msx2_machine, path, frames, script);
}

/* the Bandai WonderSwan and WonderSwan Color: 224 x 144 five times as large (1120 x 720), or 144 x 224 rotated
   three times as large (432 x 672) when a vertical game turns the LCD, at 75.47 frames a second with its
   4-channel wavetable / voice / sweep / noise sound and cartridge SRAM / EEPROM (.sav) */
static struct machine ws_machine;

static const char *ws_open(u8 *image, u32 size, const char *path)
{
    int n = 0;
    while (path[n])
        n++;
    int is_wsc = n > 4 && path[n - 4] == '.' && (path[n - 3] | 32) == 'w' &&
                 (path[n - 2] | 32) == 's' && (path[n - 1] | 32) == 'c';
    ws_machine.xs = ws_machine.ys = 5;
    return ws_load(image, size, is_wsc);
}

static void ws_one(u16 pad, void *pic_out)
{
    ws_frame(pad, (u16 *)pic_out);
}

static void ws_size(int *w, int *h)
{
    *w = ws_width();
    *h = ws_height();
    ws_machine.xs = ws_machine.ys = (*h > *w) ? 3 : 5;
}

static struct machine ws_machine = {
    WS_W, WS_H, 5, 5, WS_FRAME_US, ws_open, ws_info, ws_one, ws_save_ram, ws_save_changed,
    ws_jammed, 0, 0, "the V30MZ", 0, 0,
    "arrows or W A S D (X-pad, or Y-pad when rotated), X = A, Z = B, Enter or Tab = Start (C/V/Q/E = Y1..Y4); "
    "Ctrl-C or Esc ends", ws_size, ws_audio_rate, ws_audio
};

int ws_play(const char *path, u32 frames, const char *script)
{
    return play(&ws_machine, path, frames, script);
}

/* the Super Nintendo / Super Famicom: 256 x 224 (or 239 in overscan) three times as large (768 x 672), at the
   console's own rate (NTSC's 60.10 frames a second, PAL's 50.01: chosen from the cartridge's header), with its
   8-channel SPC700 / S-DSP BRR sound and cartridge SRAM (.sav) */
static struct machine snes_machine;

static const char *snes_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    const char *why = snes_load(image, size);
    snes_machine.frame_us = snes_pal() ? SNES_FRAME_US_PAL : SNES_FRAME_US;
    return why;
}

static void snes_one(u16 pad, void *pic_out)
{
    snes_frame(pad, (u16 *)pic_out);
}

static void snes_size(int *w, int *h)
{
    *w = snes_width();
    *h = snes_height();
}

static struct machine snes_machine = {
    SNES_W, SNES_H_DEF, 3, 3, SNES_FRAME_US, snes_open, snes_info, snes_one, snes_save_ram, snes_save_changed,
    snes_jammed, 0, 0, "the 65816", 0, 0,
    "arrows or W A S D, X = A, Z = B, C = X, V = Y, Q = L, E = R, Enter = Start, Tab = Select; Ctrl-C or Esc ends",
    snes_size, snes_audio_rate, snes_audio
};

int snes_play(const char *path, u32 frames, const char *script)
{
    return play(&snes_machine, path, frames, script);
}

/* the SNK Neo Geo AES / MVS (.neo): 320 x 224 three times as large (960 x 672) at 59.60 frames a second, with its
   Z80 + YM2610 (FM, SSG, ADPCM-A, ADPCM-B) sound, 64 KB backup RAM (.sav), and optional uni-bios.rom / neogeo.rom
   in neogeo/ (otherwise the built-in system BIOS runs the cartridge) */
static const char *neo_open(u8 *image, u32 size, const char *path)
{
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 got = rom_find(path, "neogeo", "uni-bios.rom", bios, 0x20000u, 0x20000u);
    if (!got)
        got = rom_find(path, "neogeo", "neogeo.rom", bios, 0x20000u, 0x20000u);
    if (!got)
        got = rom_find(path, "neogeo", "sp-s2.sp1", bios, 0x20000u, 0x20000u);
    neo_set_bios(got == 0x20000u ? bios : 0, got);
    return neo_load(image, size);
}

static void neo_one(u16 pad, void *pic_out)
{
    neo_frame(pad, (u16 *)pic_out);
}

static const struct machine neo_machine = {
    NEO_W, NEO_H, 3, 3, NEO_FRAME_US, neo_open, neo_info, neo_one, neo_save_ram, neo_save_changed,
    neo_jammed, 0, 0, "the 68000", 0, 0,
    "arrows or W A S D, X = A, Z = B, C = C, V = D, Enter = Start, Tab = Select, Q = Coin; Ctrl-C or Esc ends",
    0, neo_audio_rate, neo_audio
};

int neo_play(const char *path, u32 frames, const char *script)
{
    return play(&neo_machine, path, frames, script);
}

/* the Nintendo Game Boy Advance (.gba): 240 x 160 four times as large (960 x 640) at 59.73 frames a second, with
   DirectSound FIFO A/B + 4-channel PSG sound, SRAM / Flash 64K & 128K / EEPROM (.sav), and optional gba_bios.bin in
   gba/ (otherwise the built-in BIOS runs the cartridge) */
static const char *gba_open(u8 *image, u32 size, const char *path)
{
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 got = rom_find(path, "gba", "gba_bios.bin", bios, 0x4000u, 0x4000u);
    gba_set_bios(got == 0x4000u ? bios : 0, got);
    return gba_load(image, size);
}

static void gba_one(u16 pad, void *pic_out)
{
    gba_frame(pad, (u16 *)pic_out);
}

static const struct machine gba_machine = {
    GBA_W, GBA_H, 4, 4, GBA_FRAME_US, gba_open, gba_info, gba_one, gba_save_ram, gba_save_changed,
    gba_jammed, 0, 0, "the ARM7TDMI", 0, 0,
    "arrows or W A S D, X = A, Z = B, Q = L, E = R, Enter = Start, Tab = Select; Ctrl-C or Esc ends",
    0, gba_audio_rate, gba_audio
};

int gba_play(const char *path, u32 frames, const char *script)
{
    return play(&gba_machine, path, frames, script);
}

/* the Atari 7800 ProSystem (.a78): 320 x 224 (NTSC) or 320 x 240 (PAL) three times as large (960 x 672 / 960 x 720),
   with MARIA GCC1702 display lists, TIA + cartridge POKEY sound, and 2 KB High-Score SRAM (.sav) */
static struct machine a78_machine;

static const char *a78_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    const char *why = a78_load(image, size);
    a78_machine.frame_us = a78_pal() ? A78_FRAME_US_PAL : A78_FRAME_US;
    return why;
}

static void a78_one(u16 pad, void *pic_out)
{
    a78_frame(pad, (u16 *)pic_out);
}

static void a78_size(int *w, int *h)
{
    *w = a78_width();
    *h = a78_height();
}

static struct machine a78_machine = {
    A78_W, A78_H_NTSC, 3, 3, A78_FRAME_US, a78_open, a78_info, a78_one, a78_save_ram, a78_save_changed,
    a78_jammed, 0, 0, "the 6502C", 0, 0,
    "arrows or W A S D, X = fire 1, Z = fire 2, Enter = Pause, Tab = Select, C = Reset; Ctrl-C or Esc ends",
    a78_size, a78_audio_rate, a78_audio
};

int a78_play(const char *path, u32 frames, const char *script)
{
    return play(&a78_machine, path, frames, script);
}

/* the Atari Lynx (.lnx / .lyx): 160 x 102 six times as large (960 x 612), or 102 x 160 four times as large (408 x
   640) when rotated, with Suzy hardware sprite scaling / math, 4-channel Mikey sound, and optional lynxboot.img in
   lynx/ (otherwise the built-in cartridge loader boots it) */
static struct machine lnx_machine;

static const char *lnx_open(u8 *image, u32 size, const char *path)
{
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 got = rom_find(path, "lynx", "lynxboot.img", bios, 0x200u, 0x200u);
    lnx_set_bios(got == 0x200u ? bios : 0, got);
    return lnx_load(image, size);
}

static void lnx_one(u16 pad, void *pic_out)
{
    lnx_frame(pad, (u16 *)pic_out);
}

static void lnx_size(int *w, int *h)
{
    *w = lnx_width();
    *h = lnx_height();
    lnx_machine.xs = lnx_machine.ys = (*h > *w) ? 4 : 6;
}

static struct machine lnx_machine = {
    LNX_W, LNX_H, 6, 6, LNX_FRAME_US, lnx_open, lnx_info, lnx_one, lnx_save_ram, lnx_save_changed,
    lnx_jammed, 0, 0, "the 65SC02", 0, 0,
    "arrows or W A S D, X = A, Z = B, Q = Option 1, Tab = Option 2, Enter = Pause; Ctrl-C or Esc ends",
    lnx_size, lnx_audio_rate, lnx_audio
};

int lnx_play(const char *path, u32 frames, const char *script)
{
    return play(&lnx_machine, path, frames, script);
}

/* the GCE / Milton Bradley Vectrex (.vec): 270 x 360 portrait phosphor vector CRT twice as large (540 x 720) at 50
   frames a second, with AY-3-8912 + MUX DAC sound, optional vectrex.rom in vec/ (with built-in Mine Storm when started
   with no file), and a built-in Executive BIOS + playable Vector Storm game when no vectrex.rom is present */
static const char *vec_open(u8 *image, u32 size, const char *path)
{
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 got = 0;
    if (*path || *disk_cwd()) {
        got = rom_find(path, "vec", "vectrex.rom", bios, 0x1000u, 0x2000u);
        if (!got)
            got = rom_find(path, "vectrex", "vectrex.rom", bios, 0x1000u, 0x2000u);
    } else {
        static struct disk_entry vols[8];
        int nv = disk_volumes(vols, 8);
        for (int i = 0; i < nv && !got; i++) {
            char vroot[16];
            int k = 0;
            while (vols[i].name[k] && vols[i].name[k] != ':' && k < 12) {
                vroot[k] = vols[i].name[k];
                k++;
            }
            vroot[k++] = ':';
            vroot[k++] = '/';
            vroot[k] = 0;
            got = rom_find(vroot, "vec", "vectrex.rom", bios, 0x1000u, 0x2000u);
            if (!got)
                got = rom_find(vroot, "vectrex", "vectrex.rom", bios, 0x1000u, 0x2000u);
        }
    }
    vec_set_bios((got == 0x2000u || got == 0x1000u) ? bios : 0, got);
    return vec_load(size ? image : 0, size);
}

static void vec_one(u16 pad, void *pic_out)
{
    vec_frame(pad, (u16 *)pic_out);
}

static const struct machine vec_machine = {
    VEC_W, VEC_H, 2, 2, VEC_FRAME_US, vec_open, vec_info, vec_one, vec_save_ram, vec_save_changed,
    vec_jammed, 0, 0, "the 6809", 0, 0,
    "arrows or W A S D, X = button 4 (fire), Z = button 3, Tab / V = button 2, Enter / C / Q = button 1; "
    "Ctrl-C or Esc ends",
    0, vec_audio_rate, vec_audio
};

int vec_play(const char *path, u32 frames, const char *script)
{
    return play(&vec_machine, path, frames, script);
}

/* the Nintendo Famicom Disk System (.fds): 256 x 240 three times as large (768 x 720) at 60.10 frames a second,
   with its RP2C33 wavetable + FM modulation sound, Q / PAGE- to eject & flip disk sides, disk writes kept in a
   .sav file, and optional disksys.rom (8 KB) in fds/ or nes/ (otherwise the built-in BIOS boots the disk) */
static const char *fds_open(u8 *image, u32 size, const char *path)
{
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 got = rom_find(path, "fds", "disksys.rom", bios, 0x2000u, 0x2000u);
    if (!got)
        got = rom_find(path, "nes", "disksys.rom", bios, 0x2000u, 0x2000u);
    fds_set_bios(got == 0x2000u ? bios : 0, got);
    return fds_load(image, size);
}

static void fds_one(u16 pad, void *pic_out)
{
    fds_frame(pad, (u8 *)pic_out);
}

static const struct machine fds_machine = {
    NES_W, NES_H, 3, 3, 16639, fds_open, nes_info, fds_one, nes_save_ram, nes_save_changed,
    nes_jammed, nes_rgb, 64, "the 6502", 0, 0,
    "arrows or W A S D, X = A, Z = B, Enter = Start, Tab = Select, Q = flip disk side; Ctrl-C or Esc ends",
    0, nes_audio_rate, nes_audio
};

int fds_play(const char *path, u32 frames, const char *script)
{
    return play(&fds_machine, path, frames, script);
}

/* the Magnavox Odyssey2 / Philips Videopac G7000 (.o2): 160 x 240 four times as wide and three times as high (640 x
   720) at 59.94 frames a second, with its Intel 8244 shift-register + noise sound, 48-key matrix (0..9, - = Clear,
   = = Enter on the USB keyboard), and optional o2rom.bin (1 KB) in o2/ (otherwise the built-in BIOS runs the game) */
static const char *o2_open(u8 *image, u32 size, const char *path)
{
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 got = rom_find(path, "o2", "o2rom.bin", bios, 0x400u, 0x400u);
    if (!got)
        got = rom_find(path, "odyssey2", "o2rom.bin", bios, 0x400u, 0x400u);
    o2_set_bios(got == 0x400u ? bios : 0, got);
    o2_set_key(0xFFu);
    return o2_load(image, size);
}

static void o2_one(u16 pad, void *pic_out)
{
    u8 key = 0xFFu;
    if (kbd_held(0x27)) key = 0x00u;                        /* 0 */
    for (int d = 1; d <= 9; d++)
        if (kbd_held((u8)(0x1Du + d))) key = (u8)d;         /* 1..9 */
    if (kbd_held(0x2Du)) key = 0x2Eu;                       /* - -> Clear */
    if (kbd_held(0x2Eu)) key = 0x2Fu;                       /* = -> Enter */
    o2_set_key(key);
    o2_frame(pad, (u16 *)pic_out);
}

static const struct machine o2_machine = {
    O2_W, O2_H, 4, 3, O2_FRAME_US, o2_open, o2_info, o2_one, o2_save_ram, o2_save_changed,
    o2_jammed, 0, 0, "the 8048", 0, 0,
    "arrows or W A S D, X = Action, Z = Space, Enter = key 1, Tab = key 2, C/V = keys 3/4 (0..9/- /= on USB "
    "keyboard); Ctrl-C or Esc ends",
    0, o2_audio_rate, o2_audio
};

int o2_play(const char *path, u32 frames, const char *script)
{
    return play(&o2_machine, path, frames, script);
}

/* the Mattel Intellivision (.int / Intellicart .rom): 176 x 208 four times as wide and three times as high (704 x 624)
   at 59.94 frames a second, with its STIC cards / 8 MOBs, AY-3-8914 3-channel + envelope sound, 16-way disc + 12-key
   pad (0..9, - = Clear, = = Enter on the USB keyboard), and optional exec.bin (8 KB) + grom.bin (2 KB) in intv/
   (otherwise the built-in EXEC and GROM run the cartridge) */
static const char *intv_open(u8 *image, u32 size, const char *path)
{
    u8 *ebuf = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u8 *gbuf = ebuf + 0x4000u;
    u32 got_e = rom_find(path, "intv", "exec.bin", ebuf, 0x2000u, 0x2200u);
    u32 got_g = rom_find(path, "intv", "grom.bin", gbuf, 0x800u, 0x800u);
    intv_set_bios(got_e ? ebuf : 0, got_e, got_g == 0x800u ? gbuf : 0, got_g);
    intv_set_key(0xFFu);
    return intv_load(image, size);
}

static void intv_one(u16 pad, void *pic_out)
{
    u8 key = 0xFFu;
    if (kbd_held(0x27)) key = 0u;                           /* 0 */
    for (int d = 1; d <= 9; d++)
        if (kbd_held((u8)(0x1Du + d))) key = (u8)d;         /* 1..9 */
    if (kbd_held(0x2Du)) key = 10u;                         /* - -> Clear */
    if (kbd_held(0x2Eu)) key = 11u;                         /* = -> Enter */
    intv_set_key(key);
    intv_frame(pad, (u16 *)pic_out);
}

static const struct machine intv_machine = {
    INTV_W, INTV_H, 4, 3, INTV_FRAME_US, intv_open, intv_info, intv_one, intv_save_ram, intv_save_changed,
    intv_jammed, 0, 0, "the CP1610", 0, 0,
    "arrows or W A S D (disc), X = top side button, Z = left, C = right, Enter = Enter / 1, Tab = Clear (0..9/- /= "
    "on USB keyboard); Ctrl-C or Esc ends",
    0, intv_audio_rate, intv_audio
};

int intv_play(const char *path, u32 frames, const char *script)
{
    return play(&intv_machine, path, frames, script);
}

/* the SNK Neo Geo Pocket & Neo Geo Pocket Color (.ngp, .ngc): 160 x 152 four times as large (640 x 608) at 59.73
   frames a second, with its Z80 + T6W28 stereo PSG + dual DAC sound, 64 KB cartridge Flash save (.sav), and optional
   ngp_bios.rom (64 KB) in ngp/ (otherwise the built-in BIOS runs the cartridge) */
static const char *ngp_open(u8 *image, u32 size, const char *path)
{
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 got = rom_find(path, "ngp", "ngp_bios.rom", bios, 0x10000u, 0x10000u);
    if (!got)
        got = rom_find(path, "ngp", "ngpcbios.rom", bios, 0x10000u, 0x10000u);
    ngp_set_bios(got == 0x10000u ? bios : 0, got);
    return ngp_load(image, size);
}

static void ngp_one(u16 pad, void *pic_out)
{
    ngp_frame(pad, (u16 *)pic_out);
}

static const struct machine ngp_machine = {
    NGP_W, NGP_H, 4, 4, NGP_FRAME_US, ngp_open, ngp_info, ngp_one, ngp_save_ram, ngp_save_changed,
    ngp_jammed, 0, 0, "the TLCS-900/H", 0, 0,
    "arrows or W A S D, X = A, Z = B, Enter or Tab = Option; Ctrl-C or Esc ends",
    0, ngp_audio_rate, ngp_audio
};

int ngp_play(const char *path, u32 frames, const char *script)
{
    return play(&ngp_machine, path, frames, script);
}

/* the Sony PlayStation 1 (.exe, .cue, .iso): 320 x 240 (or 256 / 368 / 512 / 640 x 240 / 480 as the GPU's GP1(08)
   sets it) enlarged to the TV's height (three times at 256 / 320 x 240: 768 / 960 x 720, twice at 512 / 640 wide),
   with its MIPS R3000A + GTE 3D geometry, MDEC video, 24-voice SPU XA-ADPCM sound, 128 KB Memory Card (.sav),
   streaming .cue / .bin & .iso CD-ROM support, and optional scph1001.bin (512 KB) in psx/ (otherwise the built-in
   BIOS runs the program or disc) */
static char psx_stream_path[200];
static u32 psx_sec_size;
static u32 psx_base_lba;
static u32 psx_stream_gen;
static int psx_stream_active;

struct psx_extent {
    u32 start_lba;
    u32 count;
    u32 file_sec;
};
static struct psx_extent psx_extents[32];
static u32 psx_n_extents;
static u32 psx_sparse_total;

static u32 psx_rd32le(const u8 *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static u8 psx_bcd(u32 v)
{
    return (u8)(((v / 10u) << 4) | (v % 10u));
}

#define PSX_CACHE_SETS  128u
#define PSX_CACHE_WAYS  4u
#define PSX_CACHE_SLOTS (PSX_CACHE_SETS * PSX_CACHE_WAYS)
#define PSX_CACHE_SHIFT 14u
#define PSX_CACHE_BYTES (1u << PSX_CACHE_SHIFT) /* 16 KB per slot x 512 = 8 MB in unused MEDIA_PHYS */

static u64 psx_stream_fsize;
static u32 psx_cache_tag[PSX_CACHE_SLOTS];
static u32 psx_cache_len[PSX_CACHE_SLOTS];
static u32 psx_cache_lru[PSX_CACHE_SLOTS];
static u32 psx_cache_clock;

static void psx_cache_reset(void)
{
    for (u32 i = 0; i < PSX_CACHE_SLOTS; i++) {
        psx_cache_tag[i] = 0xFFFFFFFFu;
        psx_cache_len[i] = 0u;
        psx_cache_lru[i] = 0u;
    }
    psx_cache_clock = 1u;
}

static const u8 *psx_cache_get_chunk(u32 chunk_id, u32 *avail_out)
{
    u8 *base = (u8 *)KSEG0(MEDIA_PHYS);
    u32 set_base = (chunk_id & (PSX_CACHE_SETS - 1u)) * PSX_CACHE_WAYS;
    for (u32 w = 0; w < PSX_CACHE_WAYS; w++) {
        u32 i = set_base + w;
        if (psx_cache_tag[i] == chunk_id) {
            psx_cache_lru[i] = ++psx_cache_clock;
            *avail_out = psx_cache_len[i];
            return base + i * PSX_CACHE_BYTES;
        }
    }
    u64 file_off = (u64)chunk_id << PSX_CACHE_SHIFT;
    if (file_off >= psx_stream_fsize)
        return 0;
    u64 rem64 = psx_stream_fsize - file_off;
    u32 want = (rem64 >= PSX_CACHE_BYTES) ? PSX_CACHE_BYTES : (u32)rem64;
    u32 ask_total = (want + 511u) & ~511u;

    /* Pick oldest LRU way in this set */
    u32 victim = set_base, best_lru = 0xFFFFFFFFu;
    for (u32 w = 0; w < PSX_CACHE_WAYS; w++) {
        u32 i = set_base + w;
        if (psx_cache_tag[i] == 0xFFFFFFFFu) {
            victim = i;
            break;
        }
        if (psx_cache_lru[i] < best_lru) {
            best_lru = psx_cache_lru[i];
            victim = i;
        }
    }

    u8 *slot = base + victim * PSX_CACHE_BYTES;
    if (disk_stream_seek(file_off) != file_off)
        return 0;
    u32 got = 0u;
    while (got < ask_total) {
        u32 step = ask_total - got;
        if (step > 4096u) /* disk_stream_read / USB_BULK_SIZE contract: max 4096 bytes per SCSI READ */
            step = 4096u;
        int r = disk_stream_read(slot + got, step);
        if (r <= 0)
            break;
        got += (u32)r;
    }
    (void)now_ms(); /* keep watchdog & UART serviced on bulk USB fill */
    if (got < want)
        return 0;
    psx_cache_tag[victim] = chunk_id;
    psx_cache_len[victim] = want;
    psx_cache_lru[victim] = ++psx_cache_clock;
    *avail_out = want;
    return slot;
}

static int psx_stream_read_cached(u64 byte_pos, u8 *dst, u32 len)
{
    u32 done = 0u;
    while (done < len) {
        u64 cur = byte_pos + done;
        u32 chunk_id = (u32)(cur >> PSX_CACHE_SHIFT);
        u32 off = (u32)(cur & (PSX_CACHE_BYTES - 1u));
        u32 avail = 0u;
        const u8 *chunk = psx_cache_get_chunk(chunk_id, &avail);
        if (!chunk || off >= avail)
            return -1;
        u32 take = avail - off;
        if (take > len - done)
            take = len - done;
        if (((off | done | (u32)(unsigned long)dst) & 3u) == 0u) {
            u32 w = take >> 2;
            u32 *d32 = (u32 *)(dst + done);
            const u32 *s32 = (const u32 *)(chunk + off);
            for (u32 i = 0; i < w; i++)
                d32[i] = s32[i];
            for (u32 i = w << 2; i < take; i++)
                dst[done + i] = chunk[off + i];
        } else {
            for (u32 i = 0; i < take; i++)
                dst[done + i] = chunk[off + i];
        }
        done += take;
    }
    return 0;
}

static int psx_disk_sector(u32 lba, u8 *buf2352)
{
    if (!psx_stream_active || !psx_sec_size)
        return -1;
    if (disk_stream_opens() != psx_stream_gen) {
        u64 sz = 0;
        if (disk_stream_open(psx_stream_path, &sz) < 0) {
            psx_stream_active = 0;
            return -1;
        }
        psx_stream_fsize = sz;
        psx_stream_gen = disk_stream_opens();
    }
    u64 byte_pos = 0;
    if (psx_n_extents > 0) {
        if (lba >= psx_sparse_total)
            return -1;
        int hit = -1;
        for (u32 i = 0; i < psx_n_extents; i++) {
            if (lba >= psx_extents[i].start_lba && lba - psx_extents[i].start_lba < psx_extents[i].count) {
                hit = (int)i;
                break;
            }
        }
        if (hit < 0) {
            for (u32 i = 0; i < psx_sec_size; i++)
                buf2352[i] = 0;
            if (psx_sec_size == 2352u) {
                for (int i = 1; i <= 10; i++)
                    buf2352[i] = 0xFFu;
                u32 tot = lba + 150u;
                buf2352[12] = psx_bcd(tot / (60u * 75u));
                buf2352[13] = psx_bcd((tot / 75u) % 60u);
                buf2352[14] = psx_bcd(tot % 75u);
                buf2352[15] = 2u;
                u8 ch = (u8)(lba & 7u);
                buf2352[16] = 1u; buf2352[17] = ch; buf2352[18] = 0xE4u; buf2352[19] = 0x01u;
                buf2352[20] = 1u; buf2352[21] = ch; buf2352[22] = 0xE4u; buf2352[23] = 0x01u;
            }
            return (int)psx_sec_size;
        }
        u32 rel = lba - psx_extents[hit].start_lba;
        byte_pos = 512ULL + (u64)(psx_extents[hit].file_sec + rel) * (u64)psx_sec_size;
    } else {
        byte_pos = (u64)(lba + psx_base_lba) * (u64)psx_sec_size;
    }
    if (psx_stream_read_cached(byte_pos, buf2352, psx_sec_size) < 0)
        return -1;
    return (int)psx_sec_size;
}

static int psx_stream_disc(const char *track_path, u32 hint_sec_size, u32 base_lba)
{
    u64 fsize = 0;
    psx_n_extents = 0;
    psx_sparse_total = 0;
    psx_cache_reset();
    if (disk_stream_open(track_path, &fsize) < 0)
        return 0;
    if (fsize < 18u * 2048u) {
        disk_stream_close();
        return 0;
    }
    psx_stream_fsize = fsize;
    int k = 0;
    while (track_path[k] && k < (int)sizeof(psx_stream_path) - 1) {
        psx_stream_path[k] = track_path[k];
        k++;
    }
    psx_stream_path[k] = 0;
    psx_base_lba = base_lba;
    psx_stream_gen = disk_stream_opens();
    psx_stream_active = 1;

    u8 hdr512[512];
    if (disk_stream_seek(0) == 0 && disk_stream_read(hdr512, 512u) == 512 &&
        hdr512[0] == 'P' && hdr512[1] == 'S' && hdr512[2] == 'X' && hdr512[3] == 'S') {
        u32 tot = psx_rd32le(hdr512 + 4u);
        u32 ssz = psx_rd32le(hdr512 + 8u);
        u32 nex = psx_rd32le(hdr512 + 12u);
        if ((ssz == 2048u || ssz == 2352u) && nex >= 1u && nex <= 32u && tot > 16u) {
            psx_sparse_total = tot;
            psx_sec_size = ssz;
            psx_n_extents = nex;
            for (u32 i = 0; i < nex; i++) {
                psx_extents[i].start_lba = psx_rd32le(hdr512 + 16u + i * 12u);
                psx_extents[i].count     = psx_rd32le(hdr512 + 20u + i * 12u);
                psx_extents[i].file_sec  = psx_rd32le(hdr512 + 24u + i * 12u);
            }
            u8 probe[2352];
            if (psx_disk_sector(16u, probe) > 0) {
                u32 off = (ssz == 2352u) ? (probe[15] == 1u ? 16u : 24u) : 0u;
                if (probe[off + 1u] == 'C' && probe[off + 2u] == 'D' && probe[off + 3u] == '0') {
                    psx_set_disc(psx_disk_sector, tot, ssz);
                    return 1;
                }
            }
        }
        psx_n_extents = 0;
        psx_sparse_total = 0;
    }

    u8 probe[2352];
    u32 ssz = 0;
    if (hint_sec_size == 2048u || hint_sec_size == 2352u) {
        psx_sec_size = hint_sec_size;
        if (psx_disk_sector(16u, probe) > 0) {
            u32 off = (hint_sec_size == 2352u) ? (probe[15] == 1u ? 16u : 24u) : 0u;
            if (probe[off + 1u] == 'C' && probe[off + 2u] == 'D' && probe[off + 3u] == '0')
                ssz = hint_sec_size;
        }
    }
    if (!ssz) {
        psx_sec_size = 2352u;
        if (psx_disk_sector(16u, probe) > 0) {
            u32 off = probe[15] == 1u ? 16u : 24u;
            if (probe[off + 1u] == 'C' && probe[off + 2u] == 'D' && probe[off + 3u] == '0')
                ssz = 2352u;
        }
    }
    if (!ssz) {
        psx_sec_size = 2048u;
        if (psx_disk_sector(16u, probe) > 0 &&
            probe[1] == 'C' && probe[2] == 'D' && probe[3] == '0')
            ssz = 2048u;
    }
    if (!ssz) {
        disk_stream_close();
        psx_stream_active = 0;
        return 0;
    }
    psx_sec_size = ssz;
    u32 bytes32 = fsize > 0xFFFFFFFFULL ? 0xFFFFFFFFu : (u32)fsize;
    u32 total_sec = (ssz == 2048u) ? (u32)(fsize >> 11) : (bytes32 / 2352u);
    if (total_sec <= base_lba) {
        disk_stream_close();
        psx_stream_active = 0;
        return 0;
    }
    psx_set_disc(psx_disk_sector, total_sec - base_lba, ssz);
    return 1;
}

static int psx_ci_word(const u8 *p, u32 rem, const char *kw)
{
    u32 k = 0;
    while (kw[k]) {
        if (k >= rem)
            return 0;
        char c = (char)p[k];
        if (c >= 'a' && c <= 'z')
            c = (char)(c - 32);
        if (c != kw[k])
            return 0;
        k++;
    }
    return k == rem || p[k] == ' ' || p[k] == '\t' || p[k] == '\r' || p[k] == '\n';
}

static const char *psx_open(u8 *image, u32 size, const char *path)
{
    if (psx_stream_active) {
        disk_stream_close();
        psx_stream_active = 0;
    }
    psx_set_disc(0, 0, 0);

    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 got_b = rom_find(path, "psx", "scph1001.bin", bios, 0x80000u, 0x80000u);
    if (!got_b)
        got_b = rom_find(path, "psx", "psx_bios.bin", bios, 0x80000u, 0x80000u);
    psx_set_bios(got_b == 0x80000u ? bios : 0, got_b);

    psx_machine.xs = 3;
    psx_machine.ys = 3;

    if (size >= 0x800u && psx_is_exe(image, size))
        return psx_load(image, size, path);

    int plen = 0;
    while (path[plen])
        plen++;
    int is_cue = plen > 4 && path[plen - 4] == '.' && (path[plen - 3] | 32) == 'c' &&
                 (path[plen - 2] | 32) == 'u' && (path[plen - 1] | 32) == 'e';

    if (is_cue) {
        char track_rel[128];
        track_rel[0] = 0;
        u32 hint_ssz = 0, base_lba = 0;
        int in_track1 = 0;
        for (u32 i = 0; i < size;) {
            while (i < size && (image[i] == ' ' || image[i] == '\t' || image[i] == '\r' || image[i] == '\n'))
                i++;
            u32 line_end = i;
            while (line_end < size && image[line_end] != '\r' && image[line_end] != '\n')
                line_end++;
            u32 rem = line_end - i;
            if (!track_rel[0] && psx_ci_word(image + i, rem, "FILE")) {
                u32 p = i + 4u;
                while (p < line_end && (image[p] == ' ' || image[p] == '\t'))
                    p++;
                int tlen = 0;
                if (p < line_end && image[p] == '"') {
                    p++;
                    while (p < line_end && image[p] != '"' && tlen < (int)sizeof(track_rel) - 1)
                        track_rel[tlen++] = image[p] == '\\' ? '/' : (char)image[p], p++;
                } else {
                    while (p < line_end && image[p] != ' ' && image[p] != '\t' && tlen < (int)sizeof(track_rel) - 1)
                        track_rel[tlen++] = image[p] == '\\' ? '/' : (char)image[p], p++;
                }
                track_rel[tlen] = 0;
            } else if (psx_ci_word(image + i, rem, "TRACK")) {
                u32 p = i + 5u;
                while (p < line_end && (image[p] == ' ' || image[p] == '\t'))
                    p++;
                int trk = 0;
                while (p < line_end && image[p] >= '0' && image[p] <= '9')
                    trk = trk * 10 + (image[p++] - '0');
                in_track1 = (trk == 1);
                for (u32 q = p; q + 4u <= line_end; q++) {
                    if (image[q] == '2' && image[q + 1] == '0' && image[q + 2] == '4' && image[q + 3] == '8')
                        hint_ssz = 2048u;
                    else if (image[q] == '2' && image[q + 1] == '3' && image[q + 2] == '5' && image[q + 3] == '2')
                        hint_ssz = 2352u;
                }
            } else if (in_track1 && psx_ci_word(image + i, rem, "INDEX")) {
                u32 p = i + 5u;
                while (p < line_end && (image[p] == ' ' || image[p] == '\t'))
                    p++;
                int idx = 0;
                while (p < line_end && image[p] >= '0' && image[p] <= '9')
                    idx = idx * 10 + (image[p++] - '0');
                while (p < line_end && (image[p] == ' ' || image[p] == '\t'))
                    p++;
                if (idx == 1 && p + 8u <= line_end && image[p + 2] == ':' && image[p + 5] == ':') {
                    u32 mm = (u32)(image[p] - '0') * 10u + (u32)(image[p + 1] - '0');
                    u32 ss = (u32)(image[p + 3] - '0') * 10u + (u32)(image[p + 4] - '0');
                    u32 ff = (u32)(image[p + 6] - '0') * 10u + (u32)(image[p + 7] - '0');
                    base_lba = (mm * 60u + ss) * 75u + ff;
                }
            }
            i = line_end + 1u;
        }
        if (!track_rel[0])
            return "no FILE entry in .cue sheet";
        int dir_len = 0;
        for (int i = 0; path[i]; i++)
            if (path[i] == '/' || path[i] == '\\' || path[i] == ':')
                dir_len = i + 1;
        char cand[200];
        zx_join(cand, sizeof(cand), path, dir_len, track_rel);
        if (!disk_exists(cand)) {
            const char *base = track_rel;
            for (const char *q = track_rel; *q; q++)
                if (*q == '/' || *q == ':')
                    base = q + 1;
            zx_join(cand, sizeof(cand), path, dir_len, base);
        }
        if (!disk_exists(cand))
            return "the track file named in the .cue was not found beside it";
        if (!psx_stream_disc(cand, hint_ssz, base_lba))
            return "the track file in the .cue is not a valid ISO9660 PlayStation CD-ROM";
        const char *why = psx_load(0, 0, path);
        psx_machine.frame_us = psx_pal() ? PSX_FRAME_US_PAL : PSX_FRAME_US;
        return why;
    }

    if (psx_open_fsize > MEDIA_MAX || size >= MEDIA_MAX ||
        (size >= 512u && image[0] == 'P' && image[1] == 'S' && image[2] == 'X' && image[3] == 'S')) {
        if (!psx_stream_disc(path, 0, 0))
            return "not a PlayStation 1 PS-X EXE or ISO9660 CD-ROM";
        const char *why = psx_load(0, 0, path);
        psx_machine.frame_us = psx_pal() ? PSX_FRAME_US_PAL : PSX_FRAME_US;
        return why;
    }

    const char *why = psx_load(image, size, path);
    psx_machine.frame_us = psx_pal() ? PSX_FRAME_US_PAL : PSX_FRAME_US;
    return why;
}

static void psx_one(u16 pad, void *pic_out)
{
    psx_frame(pad, (u16 *)pic_out);
    psx_machine.frame_us = psx_pal() ? PSX_FRAME_US_PAL : PSX_FRAME_US;
}

static void psx_size(int *w, int *h)
{
    *w = psx_width();
    *h = psx_height();
    psx_machine.xs = (*w <= 320) ? 3 : 2;
    psx_machine.ys = (*h <= 240) ? 3 : 1;
}

static struct machine psx_machine = {
    PSX_W_DEF, PSX_H_DEF, 3, 3, PSX_FRAME_US, psx_open, psx_info, psx_one, psx_save_ram, psx_save_changed,
    psx_jammed, 0, 0, "the R3000A", 0, 0,
    "arrows or W A S D, X = Circle, Z = Cross, C = Triangle, V = Square, Q = L1, E = R1, Enter = Start, Tab = Select; "
    "Ctrl-C or Esc ends",
    psx_size, psx_audio_rate, psx_audio
};

void psx_play_region(int region)
{
    psx_set_region(region);
}

int psx_play(const char *path, u32 frames, const char *script)
{
    int r = play(&psx_machine, path, frames, script);
    if (psx_stream_active) {
        disk_stream_close();
        psx_stream_active = 0;
    }
    psx_set_skip_render(0);
    psx_set_region(0);
    psx_set_disc(0, 0, 0);
    return r;
}

/* Capcom CPS-1 / CPS-1.5 / CPS-2 arcade (.cps, .cps1, .cps2, MAME .zip): 384 x 224 three times as large (1152 x 672)
   at 59.63 frames a second, with its 10/12/16 MHz 68000 + Z80, YM2151 FM + OKIM6295 ADPCM / 16-voice QSound DSP sound,
   and 128-byte 93C46 EEPROM (.sav) */
static const char *cps_open(u8 *image, u32 size, const char *path)
{
    cps_set_extra(0, 0);
    struct disk_entry e;
    if (size == MEDIA_MAX && disk_stat(path, &e) == 0 && e.kind == DISK_FILE && !e.size_hi &&
        e.size > MEDIA_MAX && e.size <= MEDIA_MAX + 0x0097FE00u) {
        u64 fsz = 0;
        if (disk_stream_open(path, &fsz) == 0) {
            u8 *extra = (u8 *)KSEG0(0x07580000u);
            u32 need = e.size - MEDIA_MAX, done = 0;
            if (disk_stream_seek(MEDIA_MAX) == MEDIA_MAX) {
                while (done < need) {
                    u32 ask = ((need - done) + 511u) & ~511u;
                    int r = disk_stream_read(extra + done, ask);
                    if (r <= 0)
                        break;
                    done += (u32)r;
                    (void)now_ms();
                }
            }
            disk_stream_close();
            if (done >= need)
                cps_set_extra(extra, need);
        }
    }
    return cps_load(image, size, path);
}

static void cps_one(u16 pad, void *pic_out)
{
    cps_frame(pad, (u16 *)pic_out);
}

static const struct machine cps_machine = {
    CPS_W, CPS_H, 3, 3, CPS_FRAME_US, cps_open, cps_info, cps_one, cps_save_ram, cps_save_changed,
    cps_jammed, 0, 0, "the 68000", 0, 0,
    "arrows or W A S D, X/Z/C = LP/MP/HP, V/Q/E = LK/MK/HK, Enter = Start, Tab = Coin; Ctrl-C or Esc ends",
    0, cps_audio_rate, cps_audio
};

int cps_play(const char *path, u32 frames, const char *script)
{
    int r = play(&cps_machine, path, frames, script);
    cps_set_extra(0, 0);
    return r;
}

/* Atari 520ST / 1040STFM (.st, .msa, .prg, .tos; "": boot TOS / EmuTOS desktop): 320 x 200 three times as large
   (960 x 600), 640 x 200 (1280 x 600) or 640 x 400 monochrome (1280 x 400), with 8 MHz 68000, Shifter + STE Blitter,
   MC68901 MFP, IKBD, WD1772 FDC, YM2149F 48 kHz sound, and optional tos.img / etos256uk.img / etos192uk.img in
   atarist/ (else built-in clean-room TOS) */
static struct machine st_machine;
static u8 st_hid[16];
static int st_hid_n;

static const char *st_open(u8 *image, u32 size, const char *path)
{
    u8 *tos = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    static const char *const names[] = {
        "tos.img", "etos256uk.img", "etos192uk.img", "emutos.img", "tos104.img", "tos206.img"
    };
    u32 got_t = 0;
    for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]) && !got_t; i++)
        got_t = rom_find(path, "atarist", names[i], tos, 0x30000u, 0x40000u);
    st_hid_n = 0;
    st_machine.xs = 3;
    st_machine.ys = 3;
    const char *why = st_load(got_t ? tos : 0, got_t, size ? image : 0, size, path);
    st_machine.frame_us = st_pal() ? ST_FRAME_US : ST_FRAME_US_NT;
    return why;
}

static void st_one(u16 pad, void *pic_out)
{
    for (int i = 0; i < st_hid_n; i++)
        if (st_hid[i] == 0xE4u)         /* right Ctrl = Joystick 1 fire (as on Amiga & C64) */
            pad |= ST_A;
    st_frame(pad, st_hid, st_hid_n, (u16 *)pic_out);
    st_machine.frame_us = st_pal() ? ST_FRAME_US : ST_FRAME_US_NT;
}

static void st_keyboard(const u8 *usages, int n)
{
    if (n > 16)
        n = 16;
    for (int i = 0; i < n; i++)
        st_hid[i] = usages[i];
    st_hid_n = n;
}

static void st_typed(char c)
{
    st_type(c);
}

static void st_size(int *w, int *h)
{
    *w = st_width();
    *h = st_height();
    st_machine.xs = (*w <= 320) ? 3 : 2;
    st_machine.ys = (*h <= 200) ? 3 : 1;
}

static struct machine st_machine = {
    ST_W_LOW, ST_H_LOW, 3, 3, ST_FRAME_US, st_open, st_info, st_one, st_save_ram, st_save_changed,
    st_jammed, 0, 0, "the 68000", st_keyboard, st_typed,
    "the USB keyboard is the Atari ST's, its arrows joystick 1 (fire: right Ctrl, the remote's OK; remote 0 = Space, "
    "MENU = Return); what is typed on this console is typed on it; Esc ends",
    st_size, st_audio_rate, st_audio
};

int st_play(const char *path, u32 frames, const char *script)
{
    return play(&st_machine, path, frames, script);
}

/* Sega System 16A / System 16B / OutRun-Road arcade (.s16, MAME .zip): 320 x 224 three times as large (960 x 672)
   at 60 frames a second, with 10/12.5 MHz 68000 + Z80, 315-5195 mapper, 315-5197 tilemaps + zoomed sprites + road
   generator, YM2151 FM + uPD7759 ADPCM + Sega 16-ch PCM 48 kHz sound, and 16 KB NVRAM (.sav) */
static const char *s16_open(u8 *image, u32 size, const char *path)
{
    return s16_load(image, size, path);
}

static void s16_one(u16 pad, void *pic_out)
{
    s16_frame(pad, (u16 *)pic_out);
}

static const struct machine s16_machine = {
    S16_W, S16_H, 3, 3, S16_FRAME_US, s16_open, s16_info, s16_one, s16_save_ram, s16_save_changed,
    s16_jammed, 0, 0, "the 68000", 0, 0,
    "arrows or W A S D, X = button 1, Z = button 2, C = button 3, Enter = Start, Tab = Coin; Ctrl-C or Esc ends",
    0, s16_audio_rate, s16_audio
};

int s16_play(const char *path, u32 frames, const char *script)
{
    return play(&s16_machine, path, frames, script);
}

/* Atari 800XL / 130XE (128 KB; .atr, .xex, .obx, .com, .car, .rom; "": boot 8K BASIC): 336 x 240 three times as large
   (1008 x 720), with SALLY 6502C, ANTIC Display List modes 2..F + DLI + WSYNC + fine scroll, GTIA Players/Missiles +
   modes 9/10/11, POKEY 4-channel 48 kHz sound + SIO (.sav disk writeback), 130XE PORTB banking, and built-in AltirraOS
   XL/XE + Altirra BASIC (or optional atarixl.rom / ataribas.rom in atari8/) */
static struct machine a8_machine;
static struct machine a52_machine;
static u8 a8_hid[16];
static int a8_hid_n;

static const char *a8_open(u8 *image, u32 size, const char *path)
{
    u8 *os_buf = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u8 *bas_buf = os_buf + 0x4000u;
    u32 got_os = rom_find(path, "atari8", "atarixl.rom", os_buf, 0x4000u, 0x4000u);
    u32 got_bas = rom_find(path, "atari8", "ataribas.rom", bas_buf, 0x2000u, 0x2000u);
    a8_hid_n = 0;
    const char *why = a8_load(got_os == 0x4000u ? os_buf : 0, got_bas == 0x2000u ? bas_buf : 0,
                              size ? image : 0, size, path);
    a8_machine.frame_us = a8_pal() ? A8_FRAME_US_PAL : A8_FRAME_US_NTSC;
    return why;
}

static void a8_one(u16 pad, void *pic_out)
{
    a8_frame(pad, a8_hid, a8_hid_n, (u16 *)pic_out);
    a8_machine.frame_us = a8_pal() ? A8_FRAME_US_PAL : A8_FRAME_US_NTSC;
}

static void a8_keyboard(const u8 *usages, int n)
{
    if (n > 16)
        n = 16;
    for (int i = 0; i < n; i++)
        a8_hid[i] = usages[i];
    a8_hid_n = n;
}

static void a8_typed(char c)
{
    a8_type(c);
}

static struct machine a8_machine = {
    A8_W, A8_H, 3, 3, A8_FRAME_US_PAL, a8_open, a8_info, a8_one, a8_save_ram, a8_save_changed,
    a8_jammed, 0, 0, "the 6502C", a8_keyboard, a8_typed,
    "the USB keyboard is the Atari 800XL/130XE's (F1/F2 = START, F3 = SELECT, F4 = OPTION, F5 = Reset, F6 = HELP), "
    "its arrows joystick 1 (fire: right Ctrl / Alt, remote OK; remote MENU = START, INFO = SELECT); Esc ends",
    0, a8_audio_rate, a8_audio
};

int a8_play(const char *path, u32 frames, const char *script)
{
    return play(&a8_machine, path, frames, script);
}

/* Atari 5200 SuperSystem (.a52, .car, .bin): 336 x 240 three times as large (1008 x 720) at 59.92 frames a second,
   with SALLY 6502C, ANTIC + GTIA, POKEY 48 kHz sound, analog joystick + 12-key pad, and built-in Altirra 5200 OS
   (or optional 5200.rom in a5200/) */
static const char *a52_open(u8 *image, u32 size, const char *path)
{
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 got = rom_find(path, "a5200", "5200.rom", bios, 0x800u, 0x800u);
    const char *why = a52_load(got == 0x800u ? bios : 0, image, size, path);
    a52_machine.frame_us = a8_pal() ? A8_FRAME_US_PAL : A8_FRAME_US_NTSC;
    return why;
}

static void a52_one(u16 pad, void *pic_out)
{
    u8 hid[16];
    int n = kbd_held_all(hid, 16);
    a8_frame(pad, hid, n, (u16 *)pic_out);
}

static struct machine a52_machine = {
    A8_W, A8_H, 3, 3, A8_FRAME_US_NTSC, a52_open, a8_info, a52_one, a8_save_ram, a8_save_changed,
    a8_jammed, 0, 0, "the 6502C", 0, 0,
    "arrows or W A S D (analog stick), X = Bottom Fire, Z = Top Fire, Enter = Start, C = Pause, Tab = Reset "
    "(0..9/- /= on USB keyboard = keypad); Ctrl-C or Esc ends",
    0, a8_audio_rate, a8_audio
};

int a52_play(const char *path, u32 frames, const char *script)
{
    return play(&a52_machine, path, frames, script);
}
