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
#include "sv.h"
#include "chip8.h"
#include "channelf.h"
#include "pokemini.h"
#include "cpc.h"
#include "vic20.h"
#include "apple2.h"
#include "coco.h"
#include "cvm5.h"
#include "z80con.h"
#include "arcadia.h"
#include "scv.h"
#include "vb.h"
#include "bbc.h"
#include "ti99.h"
#include "oric.h"
#include "ted81.h"
#include "jp8bit.h"
#include "s32x.h"
#include "cd32.h"
#include "arcade.h"
#include "x68k.h"
#include "threedo.h"
#include "pc98.h"
#include "konami.h"
#include "williams.h"
#include "irem.h"
#include "taito.h"
#include "pico8.h"
#include "jaguar.h"
#include "pcfx.h"
#include "n64.h"
#include "segacd.h"
#include "cdrom.h"
#include "snd.h"
#include "zip.h"
#include "image.h"

void prof_frame(u32 n);                         /* prof.c: `prof -f N` counts a game's samples from frame N on */

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
                                          gb_save_changed, gb_jammed, 0, 0, "the Game Boy's CPU", 0, 0, 0, 0,
                                          gb_audio_rate, gb_audio};

static const char *megaduck_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    return megaduck_load(image, size);
}

static const struct machine megaduck_machine = {GB_W, GB_H, 5, 5, 16743, megaduck_open, gb_info, gb_one, gb_save_ram,
                                                gb_save_changed, gb_jammed, 0, 0, "the Mega Duck's SM83", 0, 0, 0, 0,
                                                gb_audio_rate, gb_audio};

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

#define PICTURE_MAX (768 * 512)          /* up to 768 x 512 (Sharp X68000 / PS1 640x480), 1.5 MB in PICTURE_PHYS */
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
static struct machine snes_machine;         /* (play() asks whether it runs one of these two: they can skip a */
static const struct machine gba_machine;    /*  frame's picture) */
static const struct machine astro_machine;
static const struct machine arcadia_machine;
static const struct machine vc4000_machine;
static const struct machine studio2_machine;
static const struct machine scv_machine;
static const struct machine vb_machine;
static const struct machine pcecd_machine;
static struct machine segacd_machine;

/* words of one picture row into the frame buffer at byte offset `off`: through the cache, each whole 32-byte line
   allocated without being read from memory (pref 30, PrepareForStore) and written back at once (cache 0x15), the
   ends that are not whole lines uncached.  Uncached stores took ~10 cycles each here (a 1024 x 720 picture ~7 ms);
   the memory gets the same words either way (a core that ignored the hint would just fill the lines first) */
static void __attribute__((optimize("O3"))) fb_put_row(u32 off, const u32 *src, int words)
{
    u32 a = 0x80000000u | (FB_PHYS + off);
    volatile u32 *uc = (volatile u32 *)KSEG1(FB_PHYS + off);
    int i = 0;
    for (; i < words && ((a + (u32)i * 4u) & 31u); i++)
        uc[i] = src[i];
    u32 *line = 0;
    for (; i + 8 <= words; i += 8) {
        line = (u32 *)(a + (u32)i * 4u);
        __asm__ volatile("pref 30, 0(%0)" : : "r"(line) : "memory");
        line[0] = src[i];
        line[1] = src[i + 1];
        line[2] = src[i + 2];
        line[3] = src[i + 3];
        line[4] = src[i + 4];
        line[5] = src[i + 5];
        line[6] = src[i + 6];
        line[7] = src[i + 7];
        /* (the line before written back, as fb_put_row_x2 does: the first time, the line of the uncached head or
           one before -- written back only if it is in the cache: frame-buffer lines never stay there dirty) */
        __asm__ volatile("cache 0x15, -32(%0)" : : "r"(line) : "memory");
    }
    if (line)
        __asm__ volatile("cache 0x15, 0(%0)" : : "r"(line) : "memory");
    for (; i < words; i++)
        uc[i] = src[i];
}

/* two BGR555 pixels (a word of the PS1's VRAM) -> each of them twice in ARGB1555 (o0: the first, o1: the second):
   G stays, R and B change places, bit 15 (the PS1's mask bit) set -- 12 instructions (MIPS32r2 ins), where GCC's
   own code for the same took ~19 */
#define PSX_PAIR(c, o0, o1) \
    __asm__(".set push\n\t.set mips32r2\n\t" \
            "and  %[p], %[cc], %[mg]\n\t"       /* G of both */ \
            "sll  %[t], %[cc], 10\n\t" \
            "and  %[t], %[t], %[mr]\n\t"        /* R of both, where B was */ \
            "or   %[p], %[p], %[t]\n\t" \
            "srl  %[t], %[cc], 10\n\t" \
            "and  %[t], %[t], %[mb]\n\t"        /* B of both, where R was */ \
            "or   %[p], %[p], %[t]\n\t" \
            "or   %[p], %[p], %[ma]\n\t"        /* bit 15 of both */ \
            "sll  %[a], %[p], 16\n\t" \
            "ins  %[a], %[p], 0, 16\n\t"        /* the first pixel twice */ \
            "srl  %[b], %[p], 16\n\t" \
            "ins  %[b], %[b], 16, 16\n\t"       /* the second twice */ \
            ".set pop" \
            : [p] "=&r"(p_), [t] "=&r"(t_), [a] "=&r"(o0), [b] "=&r"(o1) \
            : [cc] "r"(c), [mg] "r"(0x03E003E0u), [mr] "r"(0x7C007C00u), [mb] "r"(0x001F001Fu), \
              [ma] "r"(0x80008000u))

/* one PS1 picture row (`wn` words of two BGR555 pixels, a multiple of 4) into `rows` frame-buffer rows from byte
   offset `off` (32-byte aligned), each pixel twice in ARGB1555: converted in registers and written as whole lines as
   fb_put_row does, without the row being stored and read back between; `keep`: the words copied there too.
   Timed on the box for a 512 x 240 picture (720 rows of 2 KB): 5.5 ms with the line written back at once and
   GCC's conversion; 3.3 ms with the source fetched ahead (pref 0), each line written back once the next one is
   written (cache 0x15 on the line before: the last ones after the loop) and the conversion above.  Writing 1.4 MB
   alone takes 1.7 ms */
static void __attribute__((optimize("O3"))) fb_put_row_x2(u32 off, const u32 *s32, int wn, int rows, u32 *keep)
{
    u32 *line = (u32 *)(0x80000000u | (FB_PHYS + off));
    for (int w = 0; w < wn; w += 4, line += 8) {
        __asm__ volatile("pref 0, 64(%0)" : : "r"(s32 + w));
        u32 c0 = s32[w], c1 = s32[w + 1], c2 = s32[w + 2], c3 = s32[w + 3];
        if (keep) {
            keep[w] = c0;
            keep[w + 1] = c1;
            keep[w + 2] = c2;
            keep[w + 3] = c3;
        }
        u32 o[8], p_, t_;
        PSX_PAIR(c0, o[0], o[1]);
        PSX_PAIR(c1, o[2], o[3]);
        PSX_PAIR(c2, o[4], o[5]);
        PSX_PAIR(c3, o[6], o[7]);
        u32 *l = line;
        for (int r = 0; r < rows; r++, l += SCREEN_W / 2) {
            __asm__ volatile("pref 30, 0(%0)" : : "r"(l) : "memory");
            l[0] = o[0];
            l[1] = o[1];
            l[2] = o[2];
            l[3] = o[3];
            l[4] = o[4];
            l[5] = o[5];
            l[6] = o[6];
            l[7] = o[7];
            /* (the line before written back: the first time a line just left of the picture, or before the frame
               buffer -- written back only if it is in the cache, nothing lost either way) */
            __asm__ volatile("cache 0x15, -32(%0)" : : "r"(l) : "memory");
        }
    }
    for (int r = 0; r < rows; r++, line += SCREEN_W / 2)
        __asm__ volatile("cache 0x15, -32(%0)" : : "r"(line) : "memory");
}

/* the same three times as wide (320- / 256-wide pictures: Gran Turismo, ...): a word of two pixels p, q -> (p, p),
   (p, q), (q, q) -- the middle one is PSX_PAIR's converted pair itself; 8 words (16 pixels) a turn = 3 whole lines.
   `wn` a multiple of 8, `off` 32-byte aligned.  Before: the row converted into a buffer by GCC's code and written
   `rows` times by fb_put_row (6.7% of Gran Turismo's time on the box) */
static void __attribute__((optimize("O3"))) fb_put_row_x3(u32 off, const u32 *s32, int wn, int rows, u32 *keep)
{
    u32 *line = (u32 *)(0x80000000u | (FB_PHYS + off));
    for (int w = 0; w < wn; w += 8, line += 24) {
        __asm__ volatile("pref 0, 64(%0)" : : "r"(s32 + w));
        u32 o[24], p_, t_;
        for (int k = 0; k < 8; k++) {
            u32 c = s32[w + k];
            if (keep)
                keep[w + k] = c;
            PSX_PAIR(c, o[3 * k], o[3 * k + 2]);
            o[3 * k + 1] = p_;
        }
        u32 *l = line;
        for (int r = 0; r < rows; r++, l += SCREEN_W / 2) {
            for (int q = 0; q < 3; q++) {
                u32 *ll = l + q * 8;
                __asm__ volatile("pref 30, 0(%0)" : : "r"(ll) : "memory");
                ll[0] = o[q * 8];
                ll[1] = o[q * 8 + 1];
                ll[2] = o[q * 8 + 2];
                ll[3] = o[q * 8 + 3];
                ll[4] = o[q * 8 + 4];
                ll[5] = o[q * 8 + 5];
                ll[6] = o[q * 8 + 6];
                ll[7] = o[q * 8 + 7];
                __asm__ volatile("cache 0x15, -32(%0)" : : "r"(ll) : "memory");
            }
        }
    }
    for (int r = 0; r < rows; r++, line += SCREEN_W / 2)
        __asm__ volatile("cache 0x15, -32(%0)" : : "r"(line) : "memory");
}

/* four times as wide (the Game Boy Advance's 240 pixels over 960): a word of two pixels p, q -> (p, p), (p, p),
   (q, q), (q, q); two words (4 pixels) a turn = one whole line.  `wn` a multiple of 2, `off` 32-byte aligned.
   Before: the row converted into a buffer and written `rows` times by fb_put_row */
static void __attribute__((optimize("O3"))) fb_put_row_x4(u32 off, const u32 *s32, int wn, int rows, u32 *keep)
{
    u32 *line = (u32 *)(0x80000000u | (FB_PHYS + off));
    for (int w = 0; w < wn; w += 2, line += 8) {
        __asm__ volatile("pref 0, 64(%0)" : : "r"(s32 + w));
        u32 c0 = s32[w], c1 = s32[w + 1];
        if (keep) {
            keep[w] = c0;
            keep[w + 1] = c1;
        }
        u32 o[4], p_, t_;
        PSX_PAIR(c0, o[0], o[1]);
        PSX_PAIR(c1, o[2], o[3]);
        u32 *l = line;
        for (int r = 0; r < rows; r++, l += SCREEN_W / 2) {
            __asm__ volatile("pref 30, 0(%0)" : : "r"(l) : "memory");
            l[0] = o[0];
            l[1] = o[0];
            l[2] = o[1];
            l[3] = o[1];
            l[4] = o[2];
            l[5] = o[2];
            l[6] = o[3];
            l[7] = o[3];
            __asm__ volatile("cache 0x15, -32(%0)" : : "r"(l) : "memory");
        }
    }
    for (int r = 0; r < rows; r++, line += SCREEN_W / 2)
        __asm__ volatile("cache 0x15, -32(%0)" : : "r"(line) : "memory");
}

/* a 24-bit PS1 picture (videos) straight from VRAM's bytes into the frame buffer: what psx_scanout + show() drew
   -- each channel's top 5 bits as ARGB1555, xs (2 or 3) times as wide, ys times as high -- without the 15-bit
   picture between, its byte-by-byte VRAM addressing and its line-by-line comparison (a video changes every line).
   Every line is drawn and `before` is not kept: returns 2.  0: a line not in one VRAM row, a width this does not
   cover (psx_scanout + show() then) */
static int __attribute__((optimize("O3"))) show_psx_vram24(void)
{
    static u32 pair_buf[SCREEN_W / 2];
    if (pw <= 0 || ph <= 0 || (pw & 1) || !psx_vram_line24(0))
        return 0;
    int xs = m->xs, ys = m->ys;
    while (xs > 1 && pw * xs > SCREEN_W) xs--;
    while (ys > 1 && ph * ys > SCREEN_H) ys--;
    if (xs != 2 && xs != 3)
        return 0;
    int out_w = (pw * xs) & ~1, out_x = ((SCREEN_W - out_w) / 2) & ~1, out_y = (SCREEN_H - ph * ys) / 2;
    if (out_y < 0)
        out_y = 0;
    for (int y = 0; y < ph && out_y + y * ys < SCREEN_H; y++) {
        const u8 *s = psx_vram_line24(y);
        u32 *o = pair_buf;
        for (int x = 0; x < pw; x += 2, s += 6) {
            u32 p = 0x8000u | ((u32)(s[0] >> 3) << 10) | ((u32)(s[1] >> 3) << 5) | (u32)(s[2] >> 3);
            u32 q = 0x8000u | ((u32)(s[3] >> 3) << 10) | ((u32)(s[4] >> 3) << 5) | (u32)(s[5] >> 3);
            if (xs == 3) {
                *o++ = p | (p << 16);
                *o++ = p | (q << 16);
                *o++ = q | (q << 16);
            } else {
                *o++ = p | (p << 16);
                *o++ = q | (q << 16);
            }
        }
        for (int r = 0; r < ys && out_y + y * ys + r < SCREEN_H; r++)
            fb_put_row(((u32)(out_y + y * ys + r) * SCREEN_W + (u32)out_x) * 2u, pair_buf, out_w / 2);
    }
    return 2;
}

/* Direct zero-copy PS1 VRAM -> FB_PHYS scanout blit with dirty-line & 480i even/odd row reuse (`all`: every line;
   `keep`: the lines drawn copied into `before` for the next one's diff -- not after a flip, every line changes) */
static int __attribute__((optimize("O3"))) show_psx_vram_direct(int all, int keep)
{
    int vstride = 0, is24 = 0;
    const u16 *vbase = psx_vram_frame(&vstride, &is24);
    if (is24)
        return show_psx_vram24();
    if (!vbase || ((unsigned long)vbase & 3u) || pw <= 0 || ph <= 0)
        return 0;
    static u32 pair_buf[SCREEN_W / 2];
    int xs = m->xs, ys = m->ys;
    while (xs > 1 && pw * xs > SCREEN_W) xs--;
    while (ys > 1 && ph * ys > SCREEN_H) ys--;
    int out_w = (pw * xs) & ~1, out_x = ((SCREEN_W - out_w) / 2) & ~1, out_y = (SCREEN_H - ph * ys) / 2;
    if (out_y < 0) out_y = 0;

    if (xs == 2 && !(pw & 1) && pw * 2 <= SCREEN_W) {
        int wn = pw >> 1;
        int fused = !((out_x * 2) & 31) && !(wn & 3);      /* (whole lines: fb_put_row_x2) */
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
                if (fused) {
                    fb_put_row_x2(((u32)(out_y + y) * SCREEN_W + (u32)out_x) * 2u, s32, wn,
                                  out_y + y + 1 < SCREEN_H ? 2 : 1, keep ? o32 : 0);
                    continue;
                }
                for (int w = 0; w < wn; w++) {
                    u32 c01 = s32[w];
                    if (keep)
                        o32[w] = c01;
                    u32 c0 = c01 & 0x7FFFu, c1 = (c01 >> 16) & 0x7FFFu;
                    u32 p0 = 0x8000u | ((c0 & 0x1Fu) << 10) | (c0 & 0x3E0u) | ((c0 >> 10) & 0x1Fu);
                    u32 p1 = 0x8000u | ((c1 & 0x1Fu) << 10) | (c1 & 0x3E0u) | ((c1 >> 10) & 0x1Fu);
                    pair_buf[w * 2]     = p0 | (p0 << 16);
                    pair_buf[w * 2 + 1] = p1 | (p1 << 16);
                }
                for (int r = 0; r < 2 && out_y + y + r < SCREEN_H; r++)
                    fb_put_row(((u32)(out_y + y + r) * SCREEN_W + (u32)out_x) * 2u, pair_buf, wn * 2);
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
            if (fused) {
                int rows = SCREEN_H - (out_y + y * ys);
                fb_put_row_x2(((u32)(out_y + y * ys) * SCREEN_W + (u32)out_x) * 2u, s32, wn, rows < ys ? rows : ys,
                              keep ? o32 : 0);
                continue;
            }
            for (int w = 0; w < wn; w++) {
                u32 c01 = s32[w];
                if (keep)
                    o32[w] = c01;
                u32 c0 = c01 & 0x7FFFu, c1 = (c01 >> 16) & 0x7FFFu;
                u32 p0 = 0x8000u | ((c0 & 0x1Fu) << 10) | (c0 & 0x3E0u) | ((c0 >> 10) & 0x1Fu);
                u32 p1 = 0x8000u | ((c1 & 0x1Fu) << 10) | (c1 & 0x3E0u) | ((c1 >> 10) & 0x1Fu);
                pair_buf[w * 2]     = p0 | (p0 << 16);
                pair_buf[w * 2 + 1] = p1 | (p1 << 16);
            }
            for (int r = 0; r < ys && out_y + y * ys + r < SCREEN_H; r++)
                fb_put_row(((u32)(out_y + y * ys + r) * SCREEN_W + (u32)out_x) * 2u, pair_buf, wn * 2);
        }
        return 1;
    }
    if (xs == 3 && !(pw & 1) && pw * 3 <= SCREEN_W) {
        int wn = pw >> 1;
        int fused = !((out_x * 2) & 31) && !(wn & 7);      /* (whole lines: fb_put_row_x3) */
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
            if (fused) {
                int rows = SCREEN_H - (out_y + y * ys);
                fb_put_row_x3(((u32)(out_y + y * ys) * SCREEN_W + (u32)out_x) * 2u, s32, wn, rows < ys ? rows : ys,
                              keep ? o32 : 0);
                continue;
            }
            for (int w = 0; w < wn; w++) {
                u32 c01 = s32[w];
                if (keep)
                    o32[w] = c01;
                u32 c0 = c01 & 0x7FFFu, c1 = (c01 >> 16) & 0x7FFFu;
                u32 p = 0x8000u | ((c0 & 0x1Fu) << 10) | (c0 & 0x3E0u) | ((c0 >> 10) & 0x1Fu);
                u32 q = 0x8000u | ((c1 & 0x1Fu) << 10) | (c1 & 0x3E0u) | ((c1 >> 10) & 0x1Fu);
                pair_buf[w * 3]     = p | (p << 16);
                pair_buf[w * 3 + 1] = p | (q << 16);
                pair_buf[w * 3 + 2] = q | (q << 16);
            }
            for (int r = 0; r < ys && out_y + y * ys + r < SCREEN_H; r++)
                fb_put_row(((u32)(out_y + y * ys + r) * SCREEN_W + (u32)out_x) * 2u, pair_buf, wn * 3);
        }
        return 1;
    }
    return 0;
}

/* the lines of the picture that changed, xs times as wide and ys times as high, into the middle of the test
   screen's picture (`all`: every line) */
static void __attribute__((optimize("O3"))) show(int all)
{
    /* (fb_put_row: plain cached writes with the lines written back were no faster than uncached ones -- the
       whole 800 x 720 took 9 to 10 ms either way -- the lines are now allocated without being read) */
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
            if (xs == 2 && !(pw & 7) && pw * 2 <= SCREEN_W && !((out_x * 2) & 31)) {
                /* twice as wide, whole cache lines (the PC-98's 640, the X68000's 512 ...): the PlayStation's writer */
                int rows = SCREEN_H - (out_y + y * ys);
                fb_put_row_x2(((u32)(out_y + y * ys) * SCREEN_W + (u32)out_x) * 2u, (const u32 *)line, pw >> 1,
                              rows < ys ? rows : ys, (u32 *)old);
                continue;
            }
            if (xs == 3 && !(pw & 15) && pw * 3 <= SCREEN_W && !((out_x * 2) & 31)) {
                /* three times as wide, whole cache lines (the Super Nintendo's 256, the Neo Geo's 320 ...): the
                   PlayStation's writer -- converted in registers and written straight to the rows, `before`
                   kept on the way; the same pixels as the general way below makes */
                int rows = SCREEN_H - (out_y + y * ys);
                fb_put_row_x3(((u32)(out_y + y * ys) * SCREEN_W + (u32)out_x) * 2u, (const u32 *)line, pw >> 1,
                              rows < ys ? rows : ys, (u32 *)old);
                continue;
            }
            if (xs == 4 && !(pw & 3) && pw * 4 <= SCREEN_W && !((out_x * 2) & 31)) {
                /* four times as wide, whole cache lines (the Game Boy Advance): the same way */
                int rows = SCREEN_H - (out_y + y * ys);
                fb_put_row_x4(((u32)(out_y + y * ys) * SCREEN_W + (u32)out_x) * 2u, (const u32 *)line, pw >> 1,
                              rows < ys ? rows : ys, (u32 *)old);
                continue;
            }
            if (xs == 2 && !(pw & 1) && pw * 2 <= SCREEN_W) {
                const u32 *l32 = (const u32 *)line;
                u32 *o32 = (u32 *)old;
                for (int k = 0, wn = pw >> 1, w = 0; k < wn; k++, w += 2) {
                    u32 c = o32[k] = l32[k], p_, t_;
                    PSX_PAIR(c, row.pair[w], row.pair[w + 1]);
                }
            } else if (xs == 2 && pw * 2 <= SCREEN_W) {
                for (int x = 0, w = 0; x < pw; x++) {
                    u32 c = old[x] = line[x];
                    u32 p = 0x8000u | (c & 0x1Fu) << 10 | (c & 0x3E0u) | ((c >> 10) & 0x1Fu);
                    row.pair[w++] = p | (p << 16);
                }
            } else if (xs == 3 && !(pw & 1) && pw * 3 <= SCREEN_W) {
                const u32 *l32 = (const u32 *)line;
                u32 *o32 = (u32 *)old;
                for (int k = 0, wn = pw >> 1, w = 0; k < wn; k++, w += 3) {
                    u32 c = o32[k] = l32[k], p_, t_;
                    PSX_PAIR(c, row.pair[w], row.pair[w + 2]);
                    row.pair[w + 1] = p_;
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
        for (int r = 0; r < ys && out_y + y * ys + r < SCREEN_H; r++)
            fb_put_row(((u32)(out_y + y * ys + r) * SCREEN_W + (u32)out_x) * 2u, row.pair, out_w / 2);
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
        case 'm':
            if (m == &vb_machine)
                vb_set_mode((vb_get_mode() + 1) & 3);
            break;
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            if (m == &astro_machine)
                z80con_typed((char)c);
            else if (m == &arcadia_machine || m == &vc4000_machine || m == &studio2_machine)
                arc_typed((char)c);
            else if (m == &scv_machine)
                scv_typed((char)c);
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
static const struct machine ti99_machine;
static const struct machine cd32_machine;
static const struct machine arcade_machine;
static const struct machine x68k_machine;
static const struct machine a1200_machine;
static const struct machine dos_machine;
static const struct machine threedo_machine;
static const struct machine neocd_machine;
static const struct machine pc98_machine;
static struct machine konami_machine;
static struct machine williams_machine;
static struct machine irem_machine;
static struct machine taito_machine;
static const struct machine pico8_machine;
static struct machine jaguar_machine;
static struct machine pcfx_machine;
static const struct machine n64_machine;

/* 'nes' / 'gb' [-f frames] [-k script] <file>: frames 0 = until the player ends it.  0, -1 it could not
   start */
static int play(const struct machine *machine, const char *path, u32 frames, const char *script)
{
    m = machine;
    u8 *image = (u8 *)KSEG0(MEDIA_PHYS);
    u32 size = 0;
    tv_opening(path, 0);                        /* (on the TV at once: reading a game takes a moment) */
    int is_cd_only = (m == &pcecd_machine || m == &segacd_machine || m == &cd32_machine ||
                      (m == &threedo_machine && *path != 0) ||
                      (m == &neocd_machine && *path != 0) ||
                      (m == &pcfx_machine && *path != 0));
    u32 head_lim = (m == &psx_machine) ? 4096u : (is_cd_only ? 16384u : MEDIA_MAX);
    int got = *path ? disk_read_head(path, image, head_lim, &size) : 0;      /* ("": no file -- BASIC) */
    if (m == &psx_machine) {
        psx_open_fsize = size;
        if (got > 0 && size > 4096u && size <= MEDIA_MAX &&
            !(got >= 512 && image[0] == 'P' && image[1] == 'S' && image[2] == 'X' && image[3] == 'S'))
            got = disk_read_head(path, image, MEDIA_MAX, &size);
    }
    const char *why = 0;
    if (got >= 0 && size > MEDIA_MAX && m != &psx_machine && !is_cd_only &&
        !(m == &cps_machine && size <= MEDIA_MAX + 0x0097FE00u)) {
        uprintf("%s: %u bytes -- more than a cartridge file can be here (%u MB)\n", path, size, MEDIA_MAX >> 20);
        got = -1;
    }
    char as[160];                               /* (a game in an archive: its own name, beside the archive) */
    if (got > 0 && size <= MEDIA_MAX && !(is_cd_only && size > 16384u) &&
        !((m == &cps_machine || m == &s16_machine || m == &arcade_machine || m == &ti99_machine ||
           m == &a1200_machine || m == &dos_machine || m == &pc98_machine || m == &konami_machine ||
           m == &williams_machine || m == &irem_machine || m == &taito_machine) &&
          zip_is(image, (u32)got)))
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
    u32 ram_size = 0;
    int battery = 0, have_sav = save_path(path, sav, sizeof(sav), 0), foreign = 0;
    u8 *ram = m->save_ram ? m->save_ram(&ram_size, &battery) : 0;
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
    u32 n = 0, late = 0, emu = 0, draw = 0, per = ticks_per_ms() / 1000u;   /* (emu, draw: microseconds) */
    u32 slowest = 0, slowest_at = 0, slowest_draw = 0, over = 0;     /* (the longest frame's run and draw
                                                                       together; frames longer than their time) */
    u16 pad = 0;
    int first = 1, by_script = *script != 0;    /* (a test's buttons: the script's alone) */
    /* The Super Nintendo's and the Game Boy Advance's frame() run without a picture (0) too, the machine going
       on the same: in live play a frame that starts more than a frame late is then not drawn (never two in a
       row) -- the game keeps its speed and its sound, the picture loses that frame */
    int can_skip = (m == &snes_machine || m == &gba_machine || m == &x68k_machine ||
                    m == &cd32_machine || m == &a1200_machine || m == &dos_machine ||
                    m == &threedo_machine || m == &neocd_machine || m == &pc98_machine ||
                    m == &konami_machine || m == &williams_machine || m == &irem_machine ||
                    m == &taito_machine || m == &pico8_machine || m == &jaguar_machine ||
                    m == &pcfx_machine || m == &n64_machine);
    int skipped = 0;                            /* (the frame before was not drawn: this one is) */
    u32 n_skipped = 0;
    int psx_live = (m == &psx_machine && !frames), psx_pending = 0, psx_flip = 0;
    int psx_before_ok = 0;                      /* (`before` holds what the TV shows: diffs work) */
    u32 psx_held = 0, psx_flips = 0;            /* (pictures shown: the game's frames that reached the TV; flips) */
    if (m == &psx_machine)
        psx_set_skip_render(psx_live ? 1 : 0);
    /* sound, played as it is made (a test's run of -f frames makes none); what does not fit in the sound's ring
       (a game ahead of it) is dropped */
    static s16 samples[4096];
    u32 dropped = 0, sound_us = 0;              /* (sound_us: the run's time in m->audio and snd_write) */
    int sound = !frames && m->audio && snd_init(0) == 0;
    if (sound)
        m->audio_rate(snd_rate());
    u64 next = now_ticks();
    u64 started_ms = now_ms();
    for (;; n++) {
        if (frames && n == frames)
            break;
        prof_frame(n);
        int held = buttons(n == 0);
        if (held < 0)
            break;
        pad = by_script ? scripted(&script, n, pad) : (u16)held;
        /* PlayStation, live: more than a frame behind -> psx.c skips drawing the next whole game frame (decided
           at the game's display flip; that frame is then never shown: the picture before it stays) */
        if (psx_live)
            psx_set_skip_render(n > 30 && !first && now_ticks() > next + frame_ticks ? 2 : 1);
        int skip = can_skip && !frames && !first && !skipped && now_ticks() > next + frame_ticks;
        skipped = skip;
        n_skipped += (u32)skip;
        u64 t0 = now_ticks();
        m->frame(pad, skip ? 0 : picture);
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
        if (psx_live) {
            /* shown when the game's picture changed (a flip, drawing into what is shown, a video's frame), at once
               -- never a skipped game frame (the picture before it stays) */
            psx_pending |= psx_display_changed();
            psx_flip |= psx_display_flipped();
            if (first || (psx_pending && !psx_display_stale())) {
                int whole = first || psx_flip || !psx_before_ok;
                int drawn = show_psx_vram_direct(whole, !psx_flip);
                if (drawn) {
                    psx_before_ok = drawn == 1 && !psx_flip;    /* (2: a 24-bit picture, `before` not kept) */
                } else {
                    psx_scanout(picture);
                    show(whole);
                    psx_before_ok = 1;
                }
                psx_held += !first;
                psx_flips += psx_flip && !first;
                psx_pending = 0;
                psx_flip = 0;
                first = 0;
            }
        } else if (!skip) {
            if (first || m != &dos_machine || dos_picture_changed())
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
    if (m == &psx_machine) {
        psx_print_stats();
        if (psx_live)
            uprintf("psx: %u pictures shown (%u at a flip); %u game frames not drawn (the run was late)\n",
                    psx_held, psx_flips, psx_frames_skipped());
    }
    if (n_skipped)
        uprintf("%u of the frames were not drawn (they started more than a frame late)\n", n_skipped);
    if (sound) {
        uprintf("sound: %u us a frame of the run handing it over\n", n ? sound_us / n : 0);
        m->audio_rate(0);
        snd_stop();
        if (dropped)
            uprintf("sound: %u samples did not fit in the sound's ring\n", dropped);
    }
    if (battery && have_sav && !foreign && m->save_changed && m->save_changed())
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

/* a 386 DOS PC (real mode + 386 32-bit protected mode / DOS/4GW, 8 MB XMS, VGA Mode 13h / Mode X,
   48 kHz AdLib YM3812 OPL2 + Sound Blaster 2.0 DMA + PC Speaker, single .exe/.com or multi-file .zip) */
static u8 dos_keys[32];

static const char dos_doom_default_cfg[] =
    "mouse_sensitivity\t\t5\r\n"
    "sfx_volume\t\t8\r\n"
    "music_volume\t\t8\r\n"
    "show_messages\t\t1\r\n"
    "key_right\t\t77\r\n"
    "key_left\t\t75\r\n"
    "key_up\t\t72\r\n"
    "key_down\t\t80\r\n"
    "key_strafeleft\t\t51\r\n"
    "key_straferight\t\t52\r\n"
    "key_fire\t\t29\r\n"
    "key_use\t\t57\r\n"
    "key_strafe\t\t56\r\n"
    "key_speed\t\t54\r\n"
    "use_mouse\t\t0\r\n"
    "use_joystick\t\t0\r\n"
    "screenblocks\t\t10\r\n"
    "detaillevel\t\t0\r\n"
    "snd_channels\t\t3\r\n"
    "snd_musicdevice\t\t3\r\n"
    "snd_sfxdevice\t\t3\r\n"
    "snd_sbport\t\t544\r\n"
    "snd_sbirq\t\t7\r\n"
    "snd_sbdma\t\t1\r\n"
    "usegamma\t\t0\r\n";

static int dos_str_eq_ci(const char *a, const char *b)
{
    int i = 0;
    while (a[i] && b[i]) {
        if ((a[i] | 32) != (b[i] | 32)) return 0;
        i++;
    }
    return a[i] == 0 && b[i] == 0;
}

static int dos_ends_ci(const char *s, const char *suf)
{
    int ls = 0, lf = 0;
    while (s[ls]) ls++;
    while (suf[lf]) lf++;
    if (ls < lf) return 0;
    for (int i = 0; i < lf; i++)
        if ((s[ls - lf + i] | 32) != (suf[i] | 32)) return 0;
    return 1;
}

static const char *dos_base_of(const char *p)
{
    const char *b = p;
    for (; *p; p++)
        if (*p == '/' || *p == '\\' || *p == ':')
            b = p + 1;
    return b;
}

static int dos_is_helper_exe(const char *bn)
{
    static const char *const helpers[] = {
        "setup.exe", "install.exe", "sersetup.exe", "ipxsetup.exe",
        "dm.exe", "dwango.exe", "deice.exe", "dos4gw.exe", "dos32a.exe",
        "cwsdpmi.exe", "readme.exe", "order.exe", "catalog.exe"
    };
    for (unsigned i = 0; i < sizeof(helpers) / sizeof(helpers[0]); i++)
        if (dos_str_eq_ci(bn, helpers[i])) return 1;
    return 0;
}

static const char *dos_open(u8 *image, u32 size, const char *path)
{
    for (int i = 0; i < 32; i++)
        dos_keys[i] = 0;
    dos_clear_files();
    dos_args("");

    if (size > 0 && zip_is(image, size)) {
        u8 *pool = (u8 *)KSEG0(IMAGE_WORK_PHYS);
        u32 pool_used = 0;
        u32 cnt = zip_count(image, size);
        struct {
            char name[16];
            u8 *ptr;
            u32 sz;
        } unpacked[96];
        u32 n_unp = 0;
        int best_idx = -1, best_score = -1;
        int has_wad = 0, has_cfg = 0;

        for (u32 i = 0; i < cnt && n_unp < 95u; i++) {
            char mname[96];
            u32 msz = 0;
            if (zip_unpack_at(image, size, i, 0, 0, &msz, mname, sizeof(mname)) != 0)
                continue;
            const char *bn = dos_base_of(mname);
            if (!*bn)
                continue;
            u32 aligned = (pool_used + 3u) & ~3u;
            if (aligned + msz > IMAGE_WORK_SIZE)
                return "unpacked DOS .zip exceeds 22 MB RAM work buffer";
            image_poll = unpack_poll;
            const char *zwhy = zip_unpack_at(image, size, i, pool + aligned, IMAGE_WORK_SIZE - aligned,
                                             &msz, mname, sizeof(mname));
            image_poll = 0;
            if (zwhy)
                return zwhy;
            bn = dos_base_of(mname);
            int k = 0;
            while (bn[k] && k < 15) { unpacked[n_unp].name[k] = bn[k]; k++; }
            unpacked[n_unp].name[k] = 0;
            unpacked[n_unp].ptr = pool + aligned;
            unpacked[n_unp].sz = msz;
            pool_used = aligned + msz;

            if (dos_ends_ci(bn, ".wad")) has_wad = 1;
            if (dos_str_eq_ci(bn, "default.cfg")) has_cfg = 1;

            int is_exe = dos_ends_ci(bn, ".exe");
            int is_com = dos_ends_ci(bn, ".com");
            if (is_exe || is_com) {
                int sc = is_exe ? 1000 : 500;
                if (dos_is_helper_exe(bn)) sc = 10;
                sc += (int)(msz >> 10);
                if (sc > best_score) {
                    best_score = sc;
                    best_idx = (int)n_unp;
                }
            }
            n_unp++;
        }
        if (best_idx < 0)
            return "no .exe or .com program found in DOS .zip";
        for (u32 i = 0; i < n_unp; i++) {
            if ((int)i == best_idx) continue;
            (void)dos_add_file(unpacked[i].name, unpacked[i].ptr, unpacked[i].sz);
        }
        if (has_wad && !has_cfg)
            (void)dos_add_file("DEFAULT.CFG", (const u8 *)dos_doom_default_cfg,
                               (u32)(sizeof(dos_doom_default_cfg) - 1u));
        return dos_load(unpacked[best_idx].ptr, unpacked[best_idx].sz, unpacked[best_idx].name);
    }

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
                                           dos_save_ram, dos_save_changed, dos_jammed, 0, 0, "the 386",
                                           dos_keyboard, dos_typed,
                                           "the USB keyboard is the PC's (but Esc, which ends); the remote: arrows, "
                                           "OK = Fire/Up, 0 = Space, MENU = Enter, INFO = Esc; what is typed on this "
                                           "console is typed on it", 0, dos_audio_rate, dos_audio};

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
    if (kbd_held(0x3F))                         /* F6 (or Q / Tab-Select when mapped) flips FDS disk side */
        pad |= FDS_PAD_FLIP;
    fds_frame(pad, (u8 *)pic_out);
}

static const struct machine fds_machine = {
    NES_W, NES_H, 3, 3, 16639, fds_open, nes_info, fds_one, nes_save_ram, nes_save_changed,
    nes_jammed, nes_rgb, 64, "the 6502", 0, 0,
    "arrows or W A S D, X = A, Z = B, Enter = Start, Tab = Select, Q / F6 = flip disk side; Ctrl-C or Esc ends",
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

static u32 psx_cue_total;

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
        if (byte_pos + psx_sec_size > psx_stream_fsize) {
            if (lba < psx_cue_total) {
                for (u32 i = 0; i < psx_sec_size; i++)
                    buf2352[i] = 0;
                return (int)psx_sec_size;
            }
            return -1;
        }
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
    psx_cue_total = 0;
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

static void cdrom_close_disc(void);
static int cd_cb_read_2352(u32 lba, u8 *dst2352);
static const struct cdrom_toc *cdrom_open_disc(const char *path, const u8 *head, u32 head_len, const char **err_out);
static int psx_cue_active;

static int psx_cue_sector(u32 lba, u8 *buf2352)
{
    return cd_cb_read_2352(lba, buf2352) == 0 ? 2352 : -1;
}

static const char *psx_open(u8 *image, u32 size, const char *path)
{
    if (psx_stream_active) {
        disk_stream_close();
        psx_stream_active = 0;
    }
    if (psx_cue_active) {
        cdrom_close_disc();
        psx_cue_active = 0;
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
        const char *cue_err = 0;
        const struct cdrom_toc *toc = cdrom_open_disc(path, image, size, &cue_err);
        if (!toc)
            return cue_err ? cue_err : "invalid .cue sheet";
        u8 probe[2352];
        if (cd_cb_read_2352(16u, probe) < 0) {
            cdrom_close_disc();
            return "the track file in the .cue is not a valid ISO9660 PlayStation CD-ROM";
        }
        u32 off = probe[15] == 1u ? 16u : 24u;
        if (probe[off + 1u] != 'C' || probe[off + 2u] != 'D' || probe[off + 3u] != '0') {
            cdrom_close_disc();
            return "the track file in the .cue is not a valid ISO9660 PlayStation CD-ROM";
        }
        psx_cue_active = 1;
        psx_set_disc(psx_cue_sector, toc->total_lba, 2352u);
        u32 tlba[101];
        u8  taud[101];
        for (int t = 0; t <= 100; t++) {
            tlba[t] = toc->tracks[t].lba;
            taud[t] = toc->tracks[t].is_audio;
        }
        psx_set_toc(toc->first_track, toc->last_track, tlba, taud);
        const char *why = psx_load(0, 0, path);
        if (why) {
            cdrom_close_disc();
            psx_cue_active = 0;
        }
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
    if (psx_cue_active) {
        cdrom_close_disc();
        psx_cue_active = 0;
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

int megaduck_play(const char *path, u32 frames, const char *script)
{
    return play(&megaduck_machine, path, frames, script);
}

/* Watara Supervision (.sv): 160 x 160 four times as large (640 x 640) at ~61 frames a second */
static const char *sv_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    return sv_load(image, size);
}

static void sv_one(u16 pad, void *pic_out)
{
    sv_frame(pad, (u16 *)pic_out);
}

static const struct machine sv_machine = {
    SV_W, SV_H, 4, 4, SV_FRAME_US, sv_open, sv_info, sv_one, sv_save_ram, sv_save_changed,
    sv_jammed, 0, 0, "the 65SC02", 0, 0, 0, 0, sv_audio_rate, sv_audio
};

int sv_play(const char *path, u32 frames, const char *script)
{
    return play(&sv_machine, path, frames, script);
}

/* CHIP-8 / SUPER-CHIP 1.1 / XO-CHIP (.ch8, .sc8, .xo8): 128 x 64 ten times as large (1280 x 640) at 60 Hz */
static const char *chip8_open(u8 *image, u32 size, const char *path)
{
    return chip8_load(image, size, path);
}

static void chip8_one(u16 pad, void *pic_out)
{
    u8 hid[16];
    int n = kbd_held_all(hid, 16);
    chip8_frame(pad, hid, n, (u16 *)pic_out);
}

static const struct machine chip8_machine = {
    CHIP8_W, CHIP8_H, 10, 10, CHIP8_FRAME_US, chip8_open, chip8_info, chip8_one, chip8_save_ram, chip8_save_changed,
    chip8_jammed, 0, 0, "the CHIP-8 VM", 0, 0,
    "arrows or W A S D (5/8/7/9), X/E/Space = 6 (action), Z/Q = 4, or full 1234/QWER/ASDF/ZXCV hex pad on USB keyboard; "
    "Ctrl-C or Esc ends",
    0, chip8_audio_rate, chip8_audio
};

int chip8_play(const char *path, u32 frames, const char *script)
{
    return play(&chip8_machine, path, frames, script);
}

/* Fairchild Channel F / VES (.chf, .bin, .rom): 102 x 58 ten times as large (1020 x 580) at 60 Hz */
static const char *channelf_open(u8 *image, u32 size, const char *path)
{
    u8 *psu1 = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u8 *psu2 = psu1 + 1024u;
    u32 g1 = rom_find(path, "channelf", "sl31253.bin", psu1, 1024u, 1024u);
    if (g1 != 1024u)
        g1 = rom_find(path, "channelf", "sl31253.rom", psu1, 1024u, 1024u);
    u32 g2 = rom_find(path, "channelf", "sl31254.bin", psu2, 1024u, 1024u);
    if (g2 != 1024u)
        g2 = rom_find(path, "channelf", "sl31254.rom", psu2, 1024u, 1024u);
    return channelf_load(g1 == 1024u ? psu1 : 0, g2 == 1024u ? psu2 : 0, image, size);
}

static void channelf_one(u16 pad, void *pic_out)
{
    u8 hid[16];
    int n = kbd_held_all(hid, 16);
    channelf_frame(pad, hid, n, (u16 *)pic_out);
}

static const struct machine channelf_machine = {
    CHF_W, CHF_H, 10, 10, CHF_FRAME_US, channelf_open, channelf_info, channelf_one, channelf_save_ram,
    channelf_save_changed, channelf_jammed, 0, 0, "the Fairchild F8", 0, 0,
    "arrows or W A S D, X/Space = Push (fire), Z/C = Pull, Q/E = Rotate CCW/CW, 1..4 or F1..F4 = TIME/MODE/HOLD/START "
    "(Enter = START, Tab = MODE, F5 = Reset); Ctrl-C or Esc ends",
    0, channelf_audio_rate, channelf_audio
};

int channelf_play(const char *path, u32 frames, const char *script)
{
    return play(&channelf_machine, path, frames, script);
}

/* Nintendo Pokemon Mini (.min): 96 x 64 ten times as large (960 x 640) at 72 Hz */
static const char *pokemini_open(u8 *image, u32 size, const char *path)
{
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 got = rom_find(path, "pokemini", "bios.min", bios, 4096u, 4096u);
    return pokemini_load(got == 4096u ? bios : 0, image, size);
}

static void pokemini_one(u16 pad, void *pic_out)
{
    u8 hid[16];
    int n = kbd_held_all(hid, 16);
    pokemini_frame(pad, hid, n, (u16 *)pic_out);
}

static const struct machine pokemini_machine = {
    PM_W, PM_H, 10, 10, PM_FRAME_US, pokemini_open, pokemini_info, pokemini_one, pokemini_save_ram,
    pokemini_save_changed, pokemini_jammed, 0, 0, "the Seiko S1C88", 0, 0,
    "arrows or W A S D, X = A, Z = B, Enter/C/E = C, Q/Space = Shake/Shock, Tab/P = Power; Ctrl-C or Esc ends",
    0, pokemini_audio_rate, pokemini_audio
};

int pokemini_play(const char *path, u32 frames, const char *script)
{
    return play(&pokemini_machine, path, frames, script);
}

/* Amstrad CPC 464 / 6128 + GX4000 (.sna, .dsk, .cpr, .bin; "": boot Locomotive BASIC 1.1): 384 x 240 three times as
   large (1152 x 720) in Mode 0/1, or 640 x 200 (1280 x 600) in Mode 2, at 50.08 frames a second */
static struct machine cpc_machine;

static const char *cpc_open(u8 *image, u32 size, const char *path)
{
    u8 *os_buf = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u8 *bas_buf = os_buf + 0x4000u;
    u8 *ams_buf = bas_buf + 0x4000u;
    u32 got_os  = rom_find(path, "cpc", "cpc6128.rom", os_buf,  0x4000u, 0x4000u);
    u32 got_bas = rom_find(path, "cpc", "basic.rom",   bas_buf, 0x4000u, 0x4000u);
    u32 got_ams = rom_find(path, "cpc", "amsdos.rom",  ams_buf, 0x4000u, 0x4000u);
    return cpc_load(got_os == 0x4000u ? os_buf : 0,
                    got_bas == 0x4000u ? bas_buf : 0,
                    got_ams == 0x4000u ? ams_buf : 0,
                    size ? image : 0, size, path);
}

static void cpc_one(u16 pad, void *pic_out)
{
    cpc_frame(pad, (u16 *)pic_out);
}

static void cpc_size(int *w, int *h)
{
    *w = cpc_width();
    *h = cpc_height();
    cpc_machine.xs = (*w <= 384) ? 3 : 2;
    cpc_machine.ys = 3;
}

static struct machine cpc_machine = {
    CPC_W_STD, CPC_H_STD, 3, 3, CPC_FRAME_US, cpc_open, cpc_info, cpc_one, cpc_save_ram, cpc_save_changed,
    cpc_jammed, 0, 0, "the Z80", cpc_keyboard, cpc_typed,
    "the USB keyboard is the Amstrad CPC's, its arrows also joystick 0 (fire 1/2: X/Z or remote OK/0; remote MENU = "
    "Return, INFO = Space); what is typed on this console is typed on it; Esc ends",
    cpc_size, cpc_audio_rate, cpc_audio
};

int cpc_play(const char *path, u32 frames, const char *script)
{
    return play(&cpc_machine, path, frames, script);
}

/* Commodore VIC-20 PAL (.prg, .crt, .a0, .20, .40, .60, .d64; "": boot +24K BASIC V2): 224 x 240 three times as large
   (672 x 720) at 50 frames a second, with MOS 6502, MOS 6561 VIC-I video + 4-channel 48 kHz sound, dual MOS 6522 VIAs,
   automatic unexpanded / +3K / +24K RAM expansion selection, and embedded KERNAL + BASIC + Character ROMs */
static const char *vic20_open(u8 *image, u32 size, const char *path)
{
    u8 *k_buf = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u8 *b_buf = k_buf + 0x2000u;
    u8 *c_buf = b_buf + 0x2000u;
    u32 gk = rom_find(path, "vic20", "kernal.rom",  k_buf, 0x2000u, 0x2000u);
    u32 gb = rom_find(path, "vic20", "basic.rom",   b_buf, 0x2000u, 0x2000u);
    u32 gc = rom_find(path, "vic20", "chargen.rom", c_buf, 0x1000u, 0x1000u);
    return vic20_load(gk == 0x2000u ? k_buf : 0,
                      gb == 0x2000u ? b_buf : 0,
                      gc == 0x1000u ? c_buf : 0,
                      size ? image : 0, size, path);
}

static void vic20_one(u16 pad, void *pic_out)
{
    vic20_frame(pad, (u16 *)pic_out);
}

static const struct machine vic20_machine = {
    VIC20_W, VIC20_H, 3, 3, VIC20_FRAME_US, vic20_open, vic20_info, vic20_one, vic20_save_ram, vic20_save_changed,
    vic20_jammed, 0, 0, "the 6502", vic20_keyboard, vic20_typed,
    "the USB keyboard is the VIC-20's (Tab = RUN/STOP, PageUp = RESTORE, Alt = C=, F1/F3/F5/F7), its arrows also the "
    "joystick (fire: right Ctrl or remote OK; remote 0 = Space, MENU = F1, INFO = F3); Esc ends",
    0, vic20_audio_rate, vic20_audio
};

int vic20_play(const char *path, u32 frames, const char *script)
{
    return play(&vic20_machine, path, frames, script);
}

/* Apple IIe Enhanced (128 KB; .dsk, .do, .po, .nib, .bin; "": boot Applesoft BASIC): 280 x 192 three times as large
   (840 x 576) or 560 x 192 twice as wide and three times as high (1120 x 576) in 80-col / Double Hi-Res, at 59.92 frames
   a second, with WDC 65C02, Disk II GCR 6-and-2 (.sav writeback), 48 kHz $C030 speaker + Mockingboard AY-3-8910, and
   embedded Apple IIe Enhanced + Video + Disk II ROMs */
static struct machine apple2_machine;

static const char *apple2_open(u8 *image, u32 size, const char *path)
{
    u8 *r_main = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u8 *r_char = r_main + 0x4000u;
    u8 *r_dsk  = r_char + 0x1000u;
    u32 gm = rom_find(path, "apple2", "apple2e.rom", r_main, 0x4000u, 0x4000u);
    u32 gc = rom_find(path, "apple2", "video.rom",   r_char, 0x1000u, 0x1000u);
    u32 gd = rom_find(path, "apple2", "disk2.rom",   r_dsk,  0x0100u, 0x0100u);
    apple2_machine.xs = 3;
    apple2_machine.ys = 3;
    return apple2_load(gm == 0x4000u ? r_main : 0,
                       gc == 0x1000u ? r_char : 0,
                       gd == 0x0100u ? r_dsk  : 0,
                       size ? image : 0, size, path);
}

static void apple2_one(u16 pad, void *pic_out)
{
    apple2_frame(pad, (u16 *)pic_out);
}

static void apple2_size(int *w, int *h)
{
    *w = apple2_width();
    *h = apple2_height();
    apple2_machine.xs = (*w <= 280) ? 3 : 2;
    apple2_machine.ys = 3;
}

static struct machine apple2_machine = {
    A2_W_STD, A2_H, 3, 3, A2_FRAME_US, apple2_open, apple2_info, apple2_one, apple2_save_ram, apple2_save_changed,
    apple2_jammed, 0, 0, "the 65C02", apple2_keyboard, apple2_typed,
    "the USB keyboard is the Apple IIe's (left/right Alt = Open/Closed Apple), its arrows also the analog joystick "
    "(button 0/1: remote OK/0; remote MENU = Return, INFO = Space); what is typed on this console is typed on it; Esc ends",
    apple2_size, apple2_audio_rate, apple2_audio
};

int apple2_play(const char *path, u32 frames, const char *script)
{
    return play(&apple2_machine, path, frames, script);
}

/* TRS-80 Color Computer 1/2 (NTSC 60 Hz) & Dragon 32/64 (PAL 50 Hz) (.ccc, .rom, .bin, .cas; "": boot Color BASIC):
   320 x 240 with border three times as large (960 x 720), with Motorola MC6809, SAM MC6883, dual MC6821 PIAs, MC6847
   VDG (all text/SG4/SG6/CG1..CG6/RG1..RG6 modes + CoCo NTSC RG6 artifact colours), and 48 kHz 6-bit DAC + 1-bit sound */
static const char *coco_open(u8 *image, u32 size, const char *path)
{
    u8 *bas = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u8 *ext = bas + 0x2000u;
    u32 gb = rom_find(path, "coco", "bas13.rom",    bas, 0x2000u, 0x2000u);
    u32 ge = rom_find(path, "coco", "extbas11.rom", ext, 0x2000u, 0x2000u);
    return coco_load(gb == 0x2000u ? bas : 0, ge == 0x2000u ? ext : 0,
                     size ? image : 0, size, path);
}

static const char *dragon_open(u8 *image, u32 size, const char *path)
{
    u8 *d32 = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 gd = rom_find(path, "dragon", "d32.rom", d32, 0x4000u, 0x4000u);
    return dragon_load(gd == 0x4000u ? d32 : 0, size ? image : 0, size, path);
}

static void coco_one(u16 pad, void *pic_out)
{
    coco_frame(pad, (u16 *)pic_out);
}

static const struct machine coco_machine = {
    COCO_W, COCO_H, 3, 3, COCO_FRAME_US, coco_open, coco_info, coco_one, 0, 0,
    coco_jammed, 0, 0, "the 6809", coco_keyboard, coco_typed,
    "the USB keyboard is the CoCo's, its arrows also the right joystick (fire: Space / remote OK, Shift / remote 0 = "
    "button 2, remote MENU = Enter); what is typed on this console is typed on it; Esc ends",
    0, coco_audio_rate, coco_audio
};

static const struct machine dragon_machine = {
    COCO_W, COCO_H, 3, 3, DRAGON_FRAME_US, dragon_open, coco_info, coco_one, 0, 0,
    coco_jammed, 0, 0, "the 6809", coco_keyboard, coco_typed,
    "the USB keyboard is the Dragon's, its arrows also the right joystick (fire: Space / remote OK, Shift / remote 0 = "
    "button 2, remote MENU = Enter); what is typed on this console is typed on it; Esc ends",
    0, coco_audio_rate, coco_audio
};

int coco_play(const char *path, u32 frames, const char *script)
{
    return play(&coco_machine, path, frames, script);
}

int dragon_play(const char *path, u32 frames, const char *script)
{
    return play(&dragon_machine, path, frames, script);
}

/* VTech CreatiVision / Dick Smith Wizzard (.cv, .rom, .bin) & Sord M5 (.m5, .rom, .bin):
   256 x 192 three times as large (768 x 576), with TMS9929A/TMS9918A VDP and TI SN76489A 48 kHz sound */
static const char *cv_open(u8 *image, u32 size, const char *path)
{
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 gb = rom_find(path, "cv", "bioscv.rom", bios, 0x0800u, 0x0800u);
    return cv_load(gb == 0x0800u ? bios : 0, image, size);
}

static const char *m5_open(u8 *image, u32 size, const char *path)
{
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 gb = rom_find(path, "m5", "m5.rom", bios, 0x2000u, 0x2000u);
    return m5_load(gb == 0x2000u ? bios : 0, image, size);
}

static void cvm5_one(u16 pad, void *pic_out)
{
    cvm5_frame(pad, (u16 *)pic_out);
}

static const struct machine cv_machine = {
    CVM5_W, CVM5_H, 3, 3, CV_FRAME_US, cv_open, cvm5_info, cvm5_one, 0, 0,
    cvm5_jammed, 0, 0, "the 6502", cvm5_keyboard, cvm5_typed,
    "arrows or USB keyboard = joystick, Space/Ctrl/remote OK = fire 1, Shift/remote 0 = fire 2, F2 = Reset/Select; "
    "Esc ends",
    0, cvm5_audio_rate, cvm5_audio
};

static const struct machine m5_machine = {
    CVM5_W, CVM5_H, 3, 3, M5_FRAME_US, m5_open, cvm5_info, cvm5_one, 0, 0,
    cvm5_jammed, 0, 0, "the Z80", cvm5_keyboard, cvm5_typed,
    "the USB keyboard is the Sord M5's, its arrows also joystick 1 (fire 1: Space/Ctrl/remote OK, fire 2: Shift/remote 0); "
    "Esc ends",
    0, cvm5_audio_rate, cvm5_audio
};

int cv_play(const char *path, u32 frames, const char *script)
{
    return play(&cv_machine, path, frames, script);
}

int m5_play(const char *path, u32 frames, const char *script)
{
    return play(&m5_machine, path, frames, script);
}

/* ============================================================================
 * Category 1 Famous Consoles & Multi-Track CD-ROM Add-Ons
 * ============================================================================ */

/* Casio PV-1000 (.pv, .bin, .rom): 256 x 192 three times as large (768 x 576) at 59.92 Hz,
   with 3.58 MHz Z80, NEC D65010G031 VDP and 3-channel square/XOR 48 kHz PSG */
static const char *pv1000_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    return pv1000_load(image, size);
}

static void pv1000_one(u16 pad, void *pic_out)
{
    z80con_frame(pad, (u16 *)pic_out);
}

static const struct machine pv1000_machine = {
    PV1000_W, PV1000_H, 3, 3, Z80CON_FRAME_US, pv1000_open, z80con_info, pv1000_one, 0, 0,
    z80con_jammed, 0, 0, "the Z80", 0, 0,
    "arrows or W A S D, X = button 1, Z = button 2, Enter = Start, Tab = Select; Ctrl-C or Esc ends",
    0, z80con_audio_rate, z80con_audio
};

int pv1000_play(const char *path, u32 frames, const char *script)
{
    return play(&pv1000_machine, path, frames, script);
}

/* Bally Astrocade (.ast, .bin, .rom; "": built-in Star Blaster): 320 x 204 three times as large
   (960 x 612) at 59.92 Hz, with 1.79 MHz Z80, Data Chip Magic-RAM blitter + split palette,
   3-voice + vibrato + LFSR noise 48 kHz synth, and built-in BIOS (or astro.bin in astro/) */
static const char *astro_open(u8 *image, u32 size, const char *path)
{
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 gb = rom_find(path, "astro", "astro.bin", bios, 0x2000u, 0x2000u);
    return astro_load(gb == 0x2000u ? bios : 0, gb, size ? image : 0, size);
}

static void astro_one(u16 pad, void *pic_out)
{
    u8 hid[16];
    int n = kbd_held_all(hid, 16);
    z80con_keyboard(hid, n);
    z80con_frame(pad, (u16 *)pic_out);
}

static const struct machine astro_machine = {
    ASTRO_W, ASTRO_H, 3, 3, Z80CON_FRAME_US, astro_open, z80con_info, astro_one, 0, 0,
    z80con_jammed, 0, 0, "the Z80", 0, 0,
    "arrows or W A S D, X = Trigger, Z/C = Knob CCW/CW, 0..9 and Enter on USB keyboard / UART = 24-key pad; "
    "Ctrl-C or Esc ends",
    0, z80con_audio_rate, z80con_audio
};

int astro_play(const char *path, u32 frames, const char *script)
{
    return play(&astro_machine, path, frames, script);
}

/* Emerson Arcadia 2001 (.a2k, .bin), Interton VC 4000 (.vc4, .bin) & RCA Studio II (.st2, .bin; "": built-in) */
static const char *arcadia_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    return arcadia_load(image, size);
}

static const char *vc4000_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    return vc4000_load(image, size);
}

static const char *studio2_open(u8 *image, u32 size, const char *path)
{
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 gb = rom_find(path, "studio2", "studio2.bin", bios, 0x0800u, 0x0800u);
    return studio2_load(gb == 0x0800u ? bios : 0, gb, size ? image : 0, size);
}

static void arc_one(u16 pad, void *pic_out)
{
    u8 hid[16];
    int n = kbd_held_all(hid, 16);
    arc_keyboard(hid, n);
    arc_frame(pad, (u16 *)pic_out);
}

static const struct machine arcadia_machine = {
    ARCADIA_W, ARCADIA_H, 4, 3, ARCADIA_FRAME_US, arcadia_open, arc_info, arc_one, 0, 0,
    arc_jammed, 0, 0, "the Signetics 2650", 0, 0,
    "arrows or W A S D, X/Z = fire, Enter = Start (A), Tab = Option (B), 0..9 on USB keyboard / UART = keypad; "
    "Ctrl-C or Esc ends",
    0, arc_audio_rate, arc_audio
};

static const struct machine vc4000_machine = {
    VC4000_W, VC4000_H, 4, 3, VC4000_FRAME_US, vc4000_open, arc_info, arc_one, 0, 0,
    arc_jammed, 0, 0, "the Signetics 2650", 0, 0,
    "arrows or W A S D, X/Z = fire, Enter = Start, Tab = Select, 0..9 on USB keyboard / UART = 12-key pad; "
    "Ctrl-C or Esc ends",
    0, arc_audio_rate, arc_audio
};

static const struct machine studio2_machine = {
    STUDIO2_W, STUDIO2_H, 4, 5, STUDIO2_FRAME_US, studio2_open, arc_info, arc_one, 0, 0,
    arc_jammed, 0, 0, "the COSMAC CDP1802", 0, 0,
    "arrows or W A S D (2/4/6/8), X/Z = 5 (fire), Enter = 0, 0..9 on USB keyboard / UART = 10-key pad; "
    "Ctrl-C or Esc ends",
    0, arc_audio_rate, arc_audio
};

int arcadia_play(const char *path, u32 frames, const char *script)
{
    return play(&arcadia_machine, path, frames, script);
}

int vc4000_play(const char *path, u32 frames, const char *script)
{
    return play(&vc4000_machine, path, frames, script);
}

int studio2_play(const char *path, u32 frames, const char *script)
{
    return play(&studio2_machine, path, frames, script);
}

/* Epoch Super Cassette Vision (.scv, .bin, .cart): 192 x 222 four times wide and three times high
   (768 x 666) at 59.92 Hz, with 4 MHz NEC uPD7801G, Epoch TV-1 VDP, uPD1771C 48 kHz sound, .sav SRAM,
   and built-in BIOS + font (or optional upd7801g.s01 in scv/) */
static const char *scv_open(u8 *image, u32 size, const char *path)
{
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 gb = rom_find(path, "scv", "upd7801g.s01", bios, 0x1000u, 0x1000u);
    if (!gb)
        gb = rom_find(path, "scv", "scv_bios.bin", bios, 0x1000u, 0x1000u);
    return scv_load(gb == 0x1000u ? bios : 0, gb, image, size);
}

static void scv_one(u16 pad, void *pic_out)
{
    u8 hid[16];
    int n = kbd_held_all(hid, 16);
    scv_keyboard(hid, n);
    scv_frame(pad, (u16 *)pic_out);
}

static const struct machine scv_machine = {
    SCV_W, SCV_H, 4, 3, SCV_FRAME_US, scv_open, scv_info, scv_one, scv_save_ram, scv_save_changed,
    scv_jammed, 0, 0, "the uPD7801G", 0, 0,
    "arrows or W A S D, X = trigger 1, Z = trigger 2, Enter = En, Tab = Cl, P = Pause, 0..9 on USB keyboard / UART; "
    "Ctrl-C or Esc ends",
    0, scv_audio_rate, scv_audio
};

int scv_play(const char *path, u32 frames, const char *script)
{
    return play(&scv_machine, path, frames, script);
}

/* Nintendo Virtual Boy (.vb, .vboy): 384 x 224 three times as large (1152 x 672) at 50.27 Hz,
   with 20 MHz NEC V810 RISC CPU, VIP dual-eye 3D Worlds/OBJ display (4 live modes: Red/Black,
   Red/Cyan 3D Anaglyph, White, Amber), 6-channel VSU 48 kHz sound, and 64 KB SRAM (.sav) */
static int vb_init_mode;

void vb_play_mode(int mode)
{
    vb_init_mode = mode & 3;
}

static const char *vb_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    const char *why = vb_load(image, size);
    if (!why)
        vb_set_mode(vb_init_mode);
    return why;
}

static void vb_one(u16 pad, void *pic_out)
{
    u8 hid[16];
    int n = kbd_held_all(hid, 16);
    vb_frame(pad, hid, n, (u16 *)pic_out);
}

static const struct machine vb_machine = {
    VB_W, VB_H, 3, 3, VB_FRAME_US, vb_open, vb_info, vb_one, vb_save_ram, vb_save_changed,
    vb_jammed, 0, 0, "the V810", 0, 0,
    "arrows or W A S D (left D-pad), I/J/K/L or T/F/G/H (right D-pad), X = A, Z = B, Q/C = L, E = R, "
    "Enter = Start, Tab = Select, V/F2/M = cycle Red / 3D Anaglyph / White / Amber; Ctrl-C or Esc ends",
    0, vb_audio_rate, vb_audio
};

int vb_play(const char *path, u32 frames, const char *script)
{
    return play(&vb_machine, path, frames, script);
}

/* NEC SuperGrafx (.sgx): Dual HuC6270 VDCs (128 KB VRAM) + HuC6202 VPC + 32 KB WRAM + 6-ch PSG */
static const char *sgx_open(u8 *image, u32 size, const char *path)
{
    (void)path;
    return sgx_load(image, size);
}

static const struct machine sgx_machine = {
    PCE_W_DEF, PCE_H_DEF, 3, 3, PCE_FRAME_US, sgx_open, pce_info, pce_one, pce_save_ram, pce_save_changed,
    pce_jammed, 0, 0, "the HuC6280", 0, 0,
    "arrows or W A S D, X = I, Z = II, Enter = Run, Tab = Select (C/V/Q/E = III..VI); Ctrl-C or Esc ends",
    pce_size, pce_audio_rate, pce_audio
};

int sgx_play(const char *path, u32 frames, const char *script)
{
    return play(&sgx_machine, path, frames, script);
}

/* Shared Multi-Track / Multi-File CD-ROM Streamer (.cue/.bin & .iso) for PCE-CD and Sega CD,
   using IMAGE_WORK_PHYS + 1 MB for 0 B static .bss metadata and MEDIA_PHYS's 8 MB 512-slot LRU cache */
#define CD_MAX_FILES 100
struct cd_file_info {
    char path[200];
    u64  fsize;
    u32  data_off;
};

struct cd_disc_ws {
    struct cd_file_info files[CD_MAX_FILES];
    u32 n_files;
    u8  trk_file[CDROM_MAX_TRACKS + 1];
    u64 trk_byte_off[CDROM_MAX_TRACKS + 1];
    struct cdrom_toc toc;
    int active_file;
    u32 stream_gen;
    int stream_open;
    u8  cue_copy[16384];
};

#define CD_WS ((struct cd_disc_ws *)KSEG0(IMAGE_WORK_PHYS + 0x00100000u))

static void cdrom_close_disc(void)
{
    if (CD_WS->stream_open) {
        disk_stream_close();
        CD_WS->stream_open = 0;
    }
    CD_WS->active_file = -1;
}

static int cd_ensure_file(u32 fidx)
{
    struct cd_disc_ws *ws = CD_WS;
    if (fidx >= ws->n_files)
        return -1;
    if (!ws->stream_open || ws->active_file != (int)fidx || disk_stream_opens() != ws->stream_gen) {
        if (ws->stream_open) {
            disk_stream_close();
            ws->stream_open = 0;
        }
        u64 sz = 0;
        if (disk_stream_open(ws->files[fidx].path, &sz) < 0)
            return -1;
        ws->files[fidx].fsize = sz;
        ws->active_file = (int)fidx;
        ws->stream_gen = disk_stream_opens();
        ws->stream_open = 1;
    }
    return 0;
}

static const u8 *cd_cache_get_chunk(u32 fidx, u32 chunk_id, u32 *avail_out)
{
    struct cd_disc_ws *ws = CD_WS;
    u8 *base = (u8 *)KSEG0(MEDIA_PHYS);
    u32 tag = (fidx << 20) | (chunk_id & 0xFFFFFu);
    u32 set_base = ((chunk_id ^ (fidx * 17u)) & (PSX_CACHE_SETS - 1u)) * PSX_CACHE_WAYS;
    for (u32 w = 0; w < PSX_CACHE_WAYS; w++) {
        u32 i = set_base + w;
        if (psx_cache_tag[i] == tag) {
            psx_cache_lru[i] = ++psx_cache_clock;
            *avail_out = psx_cache_len[i];
            return base + i * PSX_CACHE_BYTES;
        }
    }
    if (cd_ensure_file(fidx) < 0)
        return 0;
    u64 fsize = ws->files[fidx].fsize;
    u64 file_off = (u64)chunk_id << PSX_CACHE_SHIFT;
    if (file_off >= fsize)
        return 0;
    u64 rem64 = fsize - file_off;
    u32 want = (rem64 >= PSX_CACHE_BYTES) ? PSX_CACHE_BYTES : (u32)rem64;
    u32 ask_total = (want + 511u) & ~511u;

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
        if (step > 4096u)
            step = 4096u;
        int r = disk_stream_read(slot + got, step);
        if (r <= 0)
            break;
        got += (u32)r;
    }
    (void)now_ms();
    if (got < want)
        return 0;
    psx_cache_tag[victim] = tag;
    psx_cache_len[victim] = want;
    psx_cache_lru[victim] = ++psx_cache_clock;
    *avail_out = want;
    return slot;
}

static int cd_stream_read_cached(u32 fidx, u64 byte_pos, u8 *dst, u32 len)
{
    u32 done = 0u;
    while (done < len) {
        u64 cur = byte_pos + done;
        u32 chunk_id = (u32)(cur >> PSX_CACHE_SHIFT);
        u32 off = (u32)(cur & (PSX_CACHE_BYTES - 1u));
        u32 avail = 0u;
        const u8 *chunk = cd_cache_get_chunk(fidx, chunk_id, &avail);
        if (!chunk || off >= avail)
            return -1;
        u32 take = avail - off;
        if (take > len - done)
            take = len - done;
        for (u32 i = 0; i < take; i++)
            dst[done + i] = chunk[off + i];
        done += take;
    }
    return 0;
}

static int cd_find_track(const struct cd_disc_ws *ws, u32 lba)
{
    for (int t = ws->toc.first_track; t <= ws->toc.last_track; t++) {
        u32 tlba = ws->toc.tracks[t].lba;
        u32 tlen = ws->toc.tracks[t].length;
        if (lba >= tlba && lba - tlba < tlen)
            return t;
    }
    return -1;
}

static int cd_cb_read_2048(u32 lba, u8 *dst2048)
{
    struct cd_disc_ws *ws = CD_WS;
    if (lba >= ws->toc.total_lba)
        return -1;
    int t = cd_find_track(ws, lba);
    if (t < 0) {
        for (u32 i = 0; i < 2048u; i++)
            dst2048[i] = 0;
        return 0;
    }
    u32 ssz = ws->toc.tracks[t].sec_size;
    u64 pos = ws->trk_byte_off[t] + (u64)(lba - ws->toc.tracks[t].lba) * (u64)ssz;
    u32 fidx = ws->trk_file[t];
    if (ssz == 2048u)
        return cd_stream_read_cached(fidx, pos, dst2048, 2048u);
    u8 hdr[24];
    if (cd_stream_read_cached(fidx, pos, hdr, 24u) < 0)
        return -1;
    u32 pay_off = (hdr[0] == 0x00u && hdr[1] == 0xFFu && hdr[11] == 0x00u && hdr[15] == 2u) ? 24u : 16u;
    return cd_stream_read_cached(fidx, pos + pay_off, dst2048, 2048u);
}

static int cd_cb_read_2352(u32 lba, u8 *dst2352)
{
    struct cd_disc_ws *ws = CD_WS;
    if (lba >= ws->toc.total_lba)
        return -1;
    int t = cd_find_track(ws, lba);
    if (t < 0) {
        for (u32 i = 0; i < 2352u; i++)
            dst2352[i] = 0;
        return 0;
    }
    u32 ssz = ws->toc.tracks[t].sec_size;
    u64 pos = ws->trk_byte_off[t] + (u64)(lba - ws->toc.tracks[t].lba) * (u64)ssz;
    u32 fidx = ws->trk_file[t];
    if (ssz == 2352u)
        return cd_stream_read_cached(fidx, pos, dst2352, 2352u);
    for (u32 i = 0; i < 2352u; i++)
        dst2352[i] = 0;
    if (ws->toc.tracks[t].is_audio)
        return 0;
    for (int i = 1; i <= 10; i++)
        dst2352[i] = 0xFFu;
    u32 msf = lba + 150u;
    dst2352[12] = psx_bcd(msf / (60u * 75u));
    dst2352[13] = psx_bcd((msf / 75u) % 60u);
    dst2352[14] = psx_bcd(msf % 75u);
    dst2352[15] = 1u;
    return cd_stream_read_cached(fidx, pos, dst2352 + 16u, 2048u);
}

static int cd_ends_ci(const char *s, const char *ext)
{
    int sl = 0, el = 0;
    while (s[sl]) sl++;
    while (ext[el]) el++;
    if (sl < el)
        return 0;
    for (int i = 0; i < el; i++)
        if ((s[sl - el + i] | 32) != (ext[i] | 32))
            return 0;
    return 1;
}

static int cd_line_has_ci(const u8 *p, u32 len, const char *word)
{
    u32 wl = 0;
    while (word[wl]) wl++;
    for (u32 i = 0; i + wl <= len; i++) {
        u32 k = 0;
        while (k < wl && ((p[i + k] | 32) == (word[k] | 32)))
            k++;
        if (k == wl)
            return 1;
    }
    return 0;
}

static const struct cdrom_toc *cdrom_open_disc(const char *path, const u8 *head, u32 head_len, const char **err_out)
{
    struct cd_disc_ws *ws = CD_WS;
    cdrom_close_disc();
    for (u32 i = 0; i < sizeof(*ws) - sizeof(ws->cue_copy); i++)
        ((u8 *)ws)[i] = 0;
    ws->active_file = -1;
    psx_cache_reset();

    if (!path || !*path) {
        *err_out = "a .cue or .iso disc image is required";
        return 0;
    }

    if (cd_ends_ci(path, ".cue")) {
        if (head_len > sizeof(ws->cue_copy))
            head_len = sizeof(ws->cue_copy);
        for (u32 i = 0; i < head_len; i++)
            ws->cue_copy[i] = head[i];
        const u8 *cue = ws->cue_copy;

        int dir_len = 0;
        for (int i = 0; path[i]; i++)
            if (path[i] == '/' || path[i] == '\\' || path[i] == ':')
                dir_len = i + 1;

        int cur_file = -1, cur_trk = 0, prev_trk = 0, cur_file_tracks = 0;
        u32 file_base_lba = 0, pending_pregap = 0;

        for (u32 i = 0; i < head_len;) {
            while (i < head_len && (cue[i] == ' ' || cue[i] == '\t' || cue[i] == '\r' || cue[i] == '\n'))
                i++;
            u32 line_end = i;
            while (line_end < head_len && cue[line_end] != '\r' && cue[line_end] != '\n')
                line_end++;
            u32 rem = line_end - i;

            if (psx_ci_word(cue + i, rem, "FILE")) {
                if (cur_file >= 0 && prev_trk >= 1 && ws->toc.tracks[prev_trk].length == 0) {
                    u64 fsz = ws->files[cur_file].fsize;
                    u64 boff = ws->trk_byte_off[prev_trk];
                    u64 left = (fsz > boff) ? (fsz - boff) : 0;
                    u32 left32 = left > 0xFFFFFFFFULL ? 0xFFFFFFFFu : (u32)left;
                    u32 ssz = ws->toc.tracks[prev_trk].sec_size;
                    u32 secs = (ssz == 2048u) ? (left32 >> 11) : (left32 / 2352u);
                    ws->toc.tracks[prev_trk].length = secs;
                    file_base_lba = ws->toc.tracks[prev_trk].lba + secs;
                }
                char track_rel[160];
                u32 p = i + 4u;
                while (p < line_end && (cue[p] == ' ' || cue[p] == '\t'))
                    p++;
                int tlen = 0;
                if (p < line_end && cue[p] == '"') {
                    p++;
                    while (p < line_end && cue[p] != '"' && tlen < (int)sizeof(track_rel) - 1)
                        track_rel[tlen++] = cue[p] == '\\' ? '/' : (char)cue[p], p++;
                } else {
                    while (p < line_end && cue[p] != ' ' && cue[p] != '\t' && tlen < (int)sizeof(track_rel) - 1)
                        track_rel[tlen++] = cue[p] == '\\' ? '/' : (char)cue[p], p++;
                }
                track_rel[tlen] = 0;
                if (!tlen || ws->n_files >= CD_MAX_FILES) {
                    *err_out = "invalid FILE entry in .cue sheet";
                    return 0;
                }
                char cand[200];
                zx_join(cand, sizeof(cand), path, dir_len, track_rel);
                if (!disk_exists(cand)) {
                    const char *base = track_rel;
                    for (const char *q = track_rel; *q; q++)
                        if (*q == '/' || *q == ':')
                            base = q + 1;
                    zx_join(cand, sizeof(cand), path, dir_len, base);
                }
                struct disk_entry de;
                if (!disk_exists(cand) || disk_stat(cand, &de) < 0 || de.kind != DISK_FILE) {
                    *err_out = "a track file named in the .cue was not found beside it";
                    return 0;
                }
                cur_file = (int)ws->n_files++;
                int ck = 0;
                while (cand[ck] && ck < (int)sizeof(ws->files[cur_file].path) - 1) {
                    ws->files[cur_file].path[ck] = cand[ck];
                    ck++;
                }
                ws->files[cur_file].path[ck] = 0;
                ws->files[cur_file].fsize = ((u64)de.size_hi << 32) | (u64)de.size;
                ws->files[cur_file].data_off = cd_ends_ci(cand, ".wav") ? 44u : 0u;
                cur_file_tracks = 0;
                prev_trk = 0;
            } else if (psx_ci_word(cue + i, rem, "TRACK")) {
                u32 p = i + 5u;
                while (p < line_end && (cue[p] == ' ' || cue[p] == '\t'))
                    p++;
                int trk = 0;
                while (p < line_end && cue[p] >= '0' && cue[p] <= '9')
                    trk = trk * 10 + (cue[p++] - '0');
                if (trk >= 1 && trk <= 99 && cur_file >= 0) {
                    cur_trk = trk;
                    if (!ws->toc.first_track || trk < ws->toc.first_track)
                        ws->toc.first_track = (u8)trk;
                    if (trk > ws->toc.last_track)
                        ws->toc.last_track = (u8)trk;
                    int is_aud = cd_line_has_ci(cue + p, line_end - p, "AUDIO");
                    u16 ssz = 2352u;
                    if (!is_aud) {
                        if (cd_line_has_ci(cue + p, line_end - p, "2048"))
                            ssz = 2048u;
                        else if (!cd_line_has_ci(cue + p, line_end - p, "2352") &&
                                 cd_ends_ci(ws->files[cur_file].path, ".iso"))
                            ssz = 2048u;
                    }
                    ws->trk_file[cur_trk] = (u8)cur_file;
                    ws->toc.tracks[cur_trk].sec_size = ssz;
                    ws->toc.tracks[cur_trk].is_audio = (u8)is_aud;
                    ws->toc.tracks[cur_trk].control  = is_aud ? 0x00u : 0x04u;
                    pending_pregap = 0;
                }
            } else if (psx_ci_word(cue + i, rem, "PREGAP")) {
                u32 p = i + 6u;
                while (p < line_end && (cue[p] == ' ' || cue[p] == '\t'))
                    p++;
                if (p + 8u <= line_end && cue[p + 2] == ':' && cue[p + 5] == ':') {
                    u32 mm = (u32)(cue[p] - '0') * 10u + (u32)(cue[p + 1] - '0');
                    u32 ss = (u32)(cue[p + 3] - '0') * 10u + (u32)(cue[p + 4] - '0');
                    u32 ff = (u32)(cue[p + 6] - '0') * 10u + (u32)(cue[p + 7] - '0');
                    pending_pregap += (mm * 60u + ss) * 75u + ff;
                }
            } else if (psx_ci_word(cue + i, rem, "INDEX")) {
                u32 p = i + 5u;
                while (p < line_end && (cue[p] == ' ' || cue[p] == '\t'))
                    p++;
                int idx = 0;
                while (p < line_end && cue[p] >= '0' && cue[p] <= '9')
                    idx = idx * 10 + (cue[p++] - '0');
                while (p < line_end && (cue[p] == ' ' || cue[p] == '\t'))
                    p++;
                if (idx == 1 && cur_trk >= 1 && cur_file >= 0 &&
                    p + 8u <= line_end && cue[p + 2] == ':' && cue[p + 5] == ':') {
                    u32 mm = (u32)(cue[p] - '0') * 10u + (u32)(cue[p + 1] - '0');
                    u32 ss = (u32)(cue[p + 3] - '0') * 10u + (u32)(cue[p + 4] - '0');
                    u32 ff = (u32)(cue[p + 6] - '0') * 10u + (u32)(cue[p + 7] - '0');
                    u32 frames_in_file = (mm * 60u + ss) * 75u + ff;
                    u32 ssz = ws->toc.tracks[cur_trk].sec_size;
                    u64 boff = (u64)ws->files[cur_file].data_off + (u64)frames_in_file * (u64)ssz;
                    if (cur_file_tracks > 0 && prev_trk >= 1) {
                        u64 span = (boff > ws->trk_byte_off[prev_trk]) ? (boff - ws->trk_byte_off[prev_trk]) : 0;
                        u32 span32 = span > 0xFFFFFFFFULL ? 0xFFFFFFFFu : (u32)span;
                        u32 pssz = ws->toc.tracks[prev_trk].sec_size;
                        u32 psecs = (pssz == 2048u) ? (span32 >> 11) : (span32 / 2352u);
                        ws->toc.tracks[prev_trk].length = psecs;
                        ws->toc.tracks[cur_trk].lba = ws->toc.tracks[prev_trk].lba + psecs + pending_pregap;
                    } else {
                        ws->toc.tracks[cur_trk].lba = file_base_lba + pending_pregap + frames_in_file;
                    }
                    ws->trk_byte_off[cur_trk] = boff;
                    prev_trk = cur_trk;
                    cur_file_tracks++;
                    pending_pregap = 0;
                }
            }
            i = line_end + 1u;
        }

        if (cur_file >= 0 && prev_trk >= 1 && ws->toc.tracks[prev_trk].length == 0) {
            u64 fsz = ws->files[cur_file].fsize;
            u64 boff = ws->trk_byte_off[prev_trk];
            u64 left = (fsz > boff) ? (fsz - boff) : 0;
            u32 left32 = left > 0xFFFFFFFFULL ? 0xFFFFFFFFu : (u32)left;
            u32 ssz = ws->toc.tracks[prev_trk].sec_size;
            u32 secs = (ssz == 2048u) ? (left32 >> 11) : (left32 / 2352u);
            ws->toc.tracks[prev_trk].length = secs;
        }
        if (!ws->toc.last_track) {
            *err_out = "no valid TRACK entries in .cue sheet";
            return 0;
        }
        int lt = ws->toc.last_track;
        ws->toc.total_lba = ws->toc.tracks[lt].lba + ws->toc.tracks[lt].length;
        ws->toc.tracks[CDROM_MAX_TRACKS].lba = ws->toc.total_lba;
    } else {
        struct disk_entry de;
        if (!disk_exists(path) || disk_stat(path, &de) < 0 || de.kind != DISK_FILE) {
            *err_out = "disc image not found";
            return 0;
        }
        u64 fsz = ((u64)de.size_hi << 32) | (u64)de.size;
        if (fsz < 16u * 2048u) {
            *err_out = "disc image is too small";
            return 0;
        }
        int ck = 0;
        while (path[ck] && ck < (int)sizeof(ws->files[0].path) - 1) {
            ws->files[0].path[ck] = path[ck];
            ck++;
        }
        ws->files[0].path[ck] = 0;
        ws->files[0].fsize = fsz;
        ws->files[0].data_off = 0;
        ws->n_files = 1;

        u8 sync[16];
        u16 ssz = 2048u;
        if (cd_stream_read_cached(0, 0, sync, 16u) == 0 &&
            sync[0] == 0x00u && sync[1] == 0xFFu && sync[10] == 0xFFu && sync[11] == 0x00u &&
            (sync[15] == 1u || sync[15] == 2u))
            ssz = 2352u;
        u32 fsz32 = fsz > 0xFFFFFFFFULL ? 0xFFFFFFFFu : (u32)fsz;
        u32 secs = (ssz == 2048u) ? (u32)(fsz >> 11) : (fsz32 / 2352u);
        ws->toc.first_track = 1;
        ws->toc.last_track  = 1;
        ws->toc.total_lba   = secs;
        ws->trk_file[1]     = 0;
        ws->trk_byte_off[1] = 0;
        ws->toc.tracks[1].lba      = 0;
        ws->toc.tracks[1].length   = secs;
        ws->toc.tracks[1].sec_size = ssz;
        ws->toc.tracks[1].is_audio = 0;
        ws->toc.tracks[1].control  = 0x04u;
        ws->toc.tracks[CDROM_MAX_TRACKS].lba = secs;
    }

    ws->toc.read_2048 = cd_cb_read_2048;
    ws->toc.read_2352 = cd_cb_read_2352;
    *err_out = 0;
    return &ws->toc;
}

/* PC Engine CD-ROM2 / Super CD-ROM2 / Arcade Card (.cue, .iso): streamed CD-ROM, OKI MSM5205 ADPCM +
   Redbook CD-DA @ 48 kHz, 256 KB Super System Card 3.0 + 2 MB Arcade Card RAM, 2 KB BRAM (.sav),
   and built-in System Card 3.0 BIOS (or optional syscard3.pce in pcecd/ or pce/) */
static const char *pcecd_open(u8 *image, u32 size, const char *path)
{
    const char *cd_err = 0;
    const struct cdrom_toc *toc = cdrom_open_disc(path, image, size, &cd_err);
    if (!toc)
        return cd_err;
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 gb = rom_find(path, "pcecd", "syscard3.pce", bios, 0x40000u, 0x40200u);
    if (!gb)
        gb = rom_find(path, "pce", "syscard3.pce", bios, 0x40000u, 0x40200u);
    const char *why = pcecd_load(gb ? bios : 0, gb, toc);
    if (why)
        cdrom_close_disc();
    return why;
}

static const struct machine pcecd_machine = {
    PCE_W_DEF, PCE_H_DEF, 3, 3, PCE_FRAME_US, pcecd_open, pce_info, pce_one, pce_save_ram, pce_save_changed,
    pce_jammed, 0, 0, "the HuC6280", 0, 0,
    "arrows or W A S D, X = I, Z = II, Enter = Run, Tab = Select (C/V/Q/E = III..VI); Ctrl-C or Esc ends",
    pce_size, pce_audio_rate, pce_audio
};

int pcecd_play(const char *path, u32 frames, const char *script)
{
    int r = play(&pcecd_machine, path, frames, script);
    cdrom_close_disc();
    return r;
}

/* Sega CD / Mega-CD (.cue, .iso): 7.67 MHz Main-68000 + 12.5 MHz Sub-68000 + Z80, 512 KB PRG-RAM,
   256 KB Word-RAM (2M & 1M/1M), Word-RAM Stamp ASIC (scaling/rotation), LC89510 CDC + CDD,
   YM2612 + PSG + Ricoh RF5C164 8-ch PCM + Redbook CD-DA @ 48 kHz, 8 KB BRAM (.sav), and built-in
   Mega-CD BIOS (or optional bios_CD_{U,E,J}.bin in segacd/) */
static int segacd_region;

void segacd_play_region(int region)
{
    segacd_region = region;
}

static const char *segacd_open(u8 *image, u32 size, const char *path)
{
    const char *cd_err = 0;
    const struct cdrom_toc *toc = cdrom_open_disc(path, image, size, &cd_err);
    if (!toc)
        return cd_err;
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    static const char *const bnames[] = {
        "bios_CD_U.bin", "bios_CD_E.bin", "bios_CD_J.bin",
        "us_scd1_9210.bin", "eu_mcd1_9210.bin", "jp_mcd1_9112.bin"
    };
    u32 gb = 0;
    if (segacd_region == 'E')
        gb = rom_find(path, "segacd", "bios_CD_E.bin", bios, 0x20000u, 0x20000u);
    else if (segacd_region == 'J')
        gb = rom_find(path, "segacd", "bios_CD_J.bin", bios, 0x20000u, 0x20000u);
    for (unsigned i = 0; i < sizeof(bnames) / sizeof(bnames[0]) && !gb; i++)
        gb = rom_find(path, "segacd", bnames[i], bios, 0x20000u, 0x20000u);
    const char *why = segacd_load(gb == 0x20000u ? bios : 0, gb, toc, segacd_region);
    if (why) {
        cdrom_close_disc();
        return why;
    }
    segacd_machine.frame_us = md_pal() ? MD_FRAME_US_PAL : MD_FRAME_US;
    return 0;
}

static struct machine segacd_machine = {
    MD_W_MAX, 224, 3, 3, MD_FRAME_US, segacd_open, md_info, md_one, segacd_save_ram, segacd_save_changed,
    md_jammed, 0, 0, "the dual 68000s", 0, 0,
    "arrows or W A S D, Z = A, X = B, Tab / Space = C, Enter = Start; Ctrl-C or Esc ends",
    md_size, md_audio_rate, md_audio
};

int segacd_play(const char *path, u32 frames, const char *script)
{
    int r = play(&segacd_machine, path, frames, script);
    cdrom_close_disc();
    segacd_region = 0;
    return r;
}

/* ============================================================================
 * Classic Home Computers ('bbc', 'ti99', 'oric', 'plus4', 'zx81', 'pc88', 'mz700', 'x1'),
 * 32-Bit Heavyweights ('s32x', 'cd32'), and Arcade Boards ('cps2', 'arcade')
 * ============================================================================ */

/* 1. BBC Micro Model B & Acorn Electron (.ssd, .dsd, .uef; "": Mode 7 BASIC) */
static const char *bbc_open(u8 *image, u32 size, const char *path)
{
    u8 *os_rom  = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u8 *bas_rom = (u8 *)KSEG0(IMAGE_WORK_PHYS + 0x8000u);
    u32 os_sz  = rom_find(path, "bbc", "os12.rom",   os_rom,  0x4000u, 0x4000u);
    u32 bas_sz = rom_find(path, "bbc", "basic2.rom", bas_rom, 0x4000u, 0x4000u);
    return bbc_load(size ? image : 0, size, path,
                    os_sz == 0x4000u ? os_rom : 0, os_sz,
                    bas_sz == 0x4000u ? bas_rom : 0, bas_sz);
}

static void bbc_one(u16 pad, void *pic_out)
{
    bbc_frame(pad, (u16 *)pic_out);
}

static const struct machine bbc_machine = {
    BBC_W, BBC_H, 3, 2, BBC_FRAME_US, bbc_open, bbc_info, bbc_one, 0, 0,
    bbc_jammed, 0, 0, "the 2 MHz 6502", bbc_keyboard, bbc_typed,
    "the USB keyboard is the BBC Micro / Electron's, its arrows + Space/Return also mapped; "
    "what is typed on this console is typed on it; Esc ends",
    0, bbc_audio_rate, bbc_audio
};

int bbc_play(const char *path, u32 frames, const char *script)
{
    return play(&bbc_machine, path, frames, script);
}

/* 2. Texas Instruments TI-99/4A (.rpk, .bin, .zip; "": TI BASIC) */
static const char *ti99_open(u8 *image, u32 size, const char *path)
{
    return ti99_load(size ? image : 0, size, path);
}

static void ti99_one(u16 pad, void *pic_out)
{
    ti99_frame(pad, (u16 *)pic_out);
}

static const struct machine ti99_machine = {
    TI99_W, TI99_H, 3, 3, TI99_FRAME_US, ti99_open, ti99_info, ti99_one, 0, 0,
    ti99_jammed, 0, 0, "the 16-bit TMS9900", ti99_keyboard, ti99_typed,
    "the USB keyboard is the TI-99/4A's, its arrows + fire (Q/Tab/Space/remote OK) also Joystick 1; "
    "what is typed on this console is typed on it; Esc ends",
    0, ti99_audio_rate, ti99_audio
};

int ti99_play(const char *path, u32 frames, const char *script)
{
    return play(&ti99_machine, path, frames, script);
}

/* 3. Tangerine Oric-1 / Oric Atmos 48K (.tap, .dsk; "": Atmos BASIC) */
static const char *oric_open(u8 *image, u32 size, const char *path)
{
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 gb = rom_find(path, "oric", "basic11b.rom", bios, 0x4000u, 0x4000u);
    if (!gb)
        gb = rom_find(path, "oric", "oric.rom", bios, 0x4000u, 0x4000u);
    return oric_load(size ? image : 0, size, path, gb == 0x4000u ? bios : 0, gb);
}

static void oric_one(u16 pad, void *pic_out)
{
    oric_frame(pad, (u16 *)pic_out);
}

static const struct machine oric_machine = {
    ORIC_W, ORIC_H, 4, 3, ORIC_FRAME_US, oric_open, oric_info, oric_one, 0, 0,
    oric_jammed, 0, 0, "the 6502", oric_keyboard, oric_typed,
    "the USB keyboard is the Oric Atmos's, its arrows + Space/Return also mapped; "
    "what is typed on this console is typed on it; Esc ends",
    0, oric_audio_rate, oric_audio
};

int oric_play(const char *path, u32 frames, const char *script)
{
    return play(&oric_machine, path, frames, script);
}

/* 4a. Commodore Plus/4 & C16 (.prg, .tap, .t64; "": BASIC V3.5) */
static const char *plus4_open(u8 *image, u32 size, const char *path)
{
    return plus4_load(size ? image : 0, size, path);
}

static void ted81_one(u16 pad, void *pic_out)
{
    ted81_frame(pad, (u16 *)pic_out);
}

static const struct machine plus4_machine = {
    PLUS4_W, PLUS4_H, 3, 3, PLUS4_FRAME_US, plus4_open, ted81_info, ted81_one, 0, 0,
    ted81_jammed, 0, 0, "the MOS 7501/8501", ted81_keyboard, ted81_typed,
    "the USB keyboard is the Plus/4's, its arrows + fire also TED Joystick 1 & 2; "
    "what is typed on this console is typed on it; Esc ends",
    0, ted81_audio_rate, ted81_audio
};

int plus4_play(const char *path, u32 frames, const char *script)
{
    return play(&plus4_machine, path, frames, script);
}

/* 4b. Sinclair ZX81 16K (.p, .81; "": Sinclair 16K BASIC) */
static const char *zx81_open(u8 *image, u32 size, const char *path)
{
    return zx81_load(size ? image : 0, size, path);
}

static const struct machine zx81_machine = {
    ZX81_W, ZX81_H, 3, 3, ZX81_FRAME_US, zx81_open, ted81_info, ted81_one, 0, 0,
    ted81_jammed, 0, 0, "the Z80", ted81_keyboard, ted81_typed,
    "the USB keyboard is the ZX81's, its arrows + 0/Z/Space also Cursor Joystick; "
    "what is typed on this console is typed on it; Esc ends",
    0, ted81_audio_rate, ted81_audio
};

int zx81_play(const char *path, u32 frames, const char *script)
{
    return play(&zx81_machine, path, frames, script);
}

/* 5a. NEC PC-8801mkIISR (.d88, .n88; "": N88-BASIC) */
static const char *pc88_open(u8 *image, u32 size, const char *path)
{
    return pc88_load(size ? image : 0, size, path);
}

static void jp8bit_one(u16 pad, void *pic_out)
{
    jp8bit_frame(pad, (u16 *)pic_out);
}

static const struct machine pc88_machine = {
    PC88_W, PC88_H, 2, 3, PC88_FRAME_US, pc88_open, jp8bit_info, jp8bit_one, 0, 0,
    jp8bit_jammed, 0, 0, "the 4 MHz Z80", jp8bit_keyboard, jp8bit_typed,
    "the USB keyboard is the PC-8801's, its arrows + Z/X/Space also numpad & OPN Atari Joystick; "
    "what is typed on this console is typed on it; Esc ends",
    0, jp8bit_audio_rate, jp8bit_audio
};

int pc88_play(const char *path, u32 frames, const char *script)
{
    return play(&pc88_machine, path, frames, script);
}

/* 5b. Sharp MZ-700 (.mzt, .mzf; "": 1Z-009A Monitor) */
static const char *mz700_open(u8 *image, u32 size, const char *path)
{
    return mz700_load(size ? image : 0, size, path);
}

static const struct machine mz700_machine = {
    MZ700_W, MZ700_H, 3, 3, MZ700_FRAME_US, mz700_open, jp8bit_info, jp8bit_one, 0, 0,
    jp8bit_jammed, 0, 0, "the Z80", jp8bit_keyboard, jp8bit_typed,
    "the USB keyboard is the Sharp MZ-700's, its arrows + Space/CR also mapped; "
    "what is typed on this console is typed on it; Esc ends",
    0, jp8bit_audio_rate, jp8bit_audio
};

int mz700_play(const char *path, u32 frames, const char *script)
{
    return play(&mz700_machine, path, frames, script);
}

/* 5c. Sharp X1 (.d88, .2d, .tap; "": IPL/BASIC) */
static const char *x1_open(u8 *image, u32 size, const char *path)
{
    return x1_load(size ? image : 0, size, path);
}

static const struct machine x1_machine = {
    X1_W, X1_H, 3, 3, X1_FRAME_US, x1_open, jp8bit_info, jp8bit_one, 0, 0,
    jp8bit_jammed, 0, 0, "the 4 MHz Z80", jp8bit_keyboard, jp8bit_typed,
    "the USB keyboard is the Sharp X1's, its arrows + Z/X/Space also PSG Joystick & numpad; "
    "what is typed on this console is typed on it; Esc ends",
    0, jp8bit_audio_rate, jp8bit_audio
};

int x1_play(const char *path, u32 frames, const char *script)
{
    return play(&x1_machine, path, frames, script);
}

/* 7. Sega 32X (.32x, .bin): Dual 23 MHz Hitachi SH-2 RISC + SuperVDP + Stereo PWM */
static int s32x_region;
static struct machine s32x_machine;

void s32x_play_region(int region)
{
    s32x_region = region;
}

static const char *s32x_open(u8 *image, u32 size, const char *path)
{
    u8 *bg = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u8 *bm = (u8 *)KSEG0(IMAGE_WORK_PHYS + 0x4000u);
    u8 *bs = (u8 *)KSEG0(IMAGE_WORK_PHYS + 0x8000u);
    u32 g_sz = rom_find(path, "s32x", "32x_g_bios.bin", bg, 256u, 256u);
    u32 m_sz = rom_find(path, "s32x", "32x_m_bios.bin", bm, 2048u, 2048u);
    u32 s_sz = rom_find(path, "s32x", "32x_s_bios.bin", bs, 1024u, 1024u);
    const char *why = s32x_load(image, size,
                                g_sz == 256u  ? bg : 0, g_sz,
                                m_sz == 2048u ? bm : 0, m_sz,
                                s_sz == 1024u ? bs : 0, s_sz,
                                s32x_region);
    if (!why)
        s32x_machine.frame_us = md_pal() ? MD_FRAME_US_PAL : MD_FRAME_US;
    return why;
}

static struct machine s32x_machine = {
    MD_W_MAX, 224, 3, 3, MD_FRAME_US, s32x_open, md_info, md_one, md_save_ram, md_save_changed,
    md_jammed, 0, 0, "the 68000 + dual SH-2s", 0, 0,
    "arrows or W A S D, Z = A, X = B, Tab / Space = C, C/V/Q/E = X/Y/Z/Mode, Enter = Start; Ctrl-C or Esc ends",
    md_size, md_audio_rate, md_audio
};

int s32x_play(const char *path, u32 frames, const char *script)
{
    int r = play(&s32x_machine, path, frames, script);
    s32x_region = 0;
    return r;
}

/* 8. Commodore Amiga CD32 (.cue, .iso): 14.18 MHz 68EC020-compat + 2 MB AGA + Akiko C2P + Paula + CD-DA */
static const char *cd32_open(u8 *image, u32 size, const char *path)
{
    const char *cd_err = 0;
    const struct cdrom_toc *toc = cdrom_open_disc(path, image, size, &cd_err);
    if (!toc)
        return cd_err;
    u8 *kick = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u8 *ext  = (u8 *)KSEG0(IMAGE_WORK_PHYS + 0x80000u);
    u32 gk = rom_find(path, "cd32", "cd32_kick31.rom", kick, 0x80000u, 0x80000u);
    if (!gk)
        gk = rom_find(path, "cd32", "kick40060.cd32", kick, 0x80000u, 0x80000u);
    u32 ge = rom_find(path, "cd32", "cd32_ext.rom", ext, 0x80000u, 0x80000u);
    if (!ge)
        ge = rom_find(path, "cd32", "ext40060.cd32", ext, 0x80000u, 0x80000u);
    const char *why = cd32_load(gk == 0x80000u ? kick : 0, gk,
                                ge == 0x80000u ? ext  : 0, ge, toc);
    if (why)
        cdrom_close_disc();
    return why;
}

static void cd32_one(u16 pad, void *pic_out)
{
    cd32_frame(pad, (u16 *)pic_out);
}

static const struct machine cd32_machine = {
    CD32_W, CD32_H, 3, 2, CD32_FRAME_US, cd32_open, cd32_info, cd32_one, cd32_save_ram, cd32_save_changed,
    cd32_jammed, 0, 0, "the 14 MHz 68EC020 + AGA + Akiko", 0, 0,
    "arrows or W A S D, Z = Red, X = Blue, C = Yellow, Tab = Green, Q/E = Rev/Fwd, Enter = Play; Ctrl-C or Esc ends",
    0, cd32_audio_rate, cd32_audio
};

int cd32_play(const char *path, u32 frames, const char *script)
{
    int r = play(&cd32_machine, path, frames, script);
    cdrom_close_disc();
    return r;
}

/* 9. Capcom CPS-2 QSound Arcade ('cps2': .zip, .cps2) */
int cps2_play(const char *path, u32 frames, const char *script)
{
    return cps_play(path, frames, script);
}

/* 10. Golden-Age Z80 Classic Arcade Pack ('arcade': Pac-Man, Galaxian, Frogger, Donkey Kong .zip; "": built-in) */
static const char *arcade_open(u8 *image, u32 size, const char *path)
{
    return arcade_load(size ? image : 0, size, path);
}

static void arcade_one(u16 pad, void *pic_out)
{
    arcade_frame(pad, (u16 *)pic_out);
}

static void arcade_size(int *w, int *h)
{
    *w = arcade_width();
    *h = arcade_height();
}

static const struct machine arcade_machine = {
    ARCADE_W, ARCADE_H_MAX, 3, 2, ARCADE_FRAME_US, arcade_open, arcade_info, arcade_one, 0, 0,
    arcade_jammed, 0, 0, "the arcade Z80", 0, 0,
    "arrows or W A S D, X/Z = Jump/Fire, Tab/Space = Insert Coin, Enter = 1P Start; Ctrl-C or Esc ends",
    arcade_size, arcade_audio_rate, arcade_audio
};

int arcade_play(const char *path, u32 frames, const char *script)
{
    return play(&arcade_machine, path, frames, script);
}

/* 11. Sharp X68000 ('x68k': .dim, .xdf, .hdm, .2hd, .dup, .hdf, .x) */
static const char *x68k_open(u8 *image, u32 size, const char *path)
{
    u8 *ipl = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u8 *cg  = (u8 *)KSEG0(IMAGE_WORK_PHYS + 0x20000u);
    u32 gipl = rom_find(path, "x68k", "iplrom.dat", ipl, 0x20000u, 0x20000u);
    u32 gcg  = rom_find(path, "x68k", "cgrom.dat",  cg,  0x40000u, 0xC0000u);
    x68k_set_roms(gipl == 0x20000u ? ipl : 0, gipl, gcg >= 0x40000u ? cg : 0, gcg);
    return x68k_load(image, size, path);
}

static void x68k_one(u16 pad, void *pic_out)
{
    x68k_frame(pad, (u16 *)pic_out);
}

static void x68k_size(int *w, int *h)
{
    *w = x68k_width();
    *h = x68k_height();
}

static void x68k_typed(char c)
{
    char s[2] = {c, 0};
    x68k_type(s);
}

static const struct machine x68k_machine = {
    X68K_W_MAX, X68K_H_MAX, 3, 2, X68K_FRAME_US, x68k_open, x68k_info, x68k_one,
    x68k_save_ram, x68k_save_changed, x68k_jammed, 0, 0, "the 10 MHz 68000",
    x68k_keys_from_hid, x68k_typed,
    "arrows or W A S D, Z/Space = Button 1, X = Button 2, Enter = Return, Tab = XF1, USB keyboard + mouse; Esc ends",
    x68k_size, x68k_audio_rate, x68k_audio
};

int x68k_play(const char *path, u32 frames, const char *script)
{
    return play(&x68k_machine, path, frames, script);
}

/* 12. Commodore Amiga 1200 ('a1200': 14.18 MHz 68EC020 + 2 MB AGA + HAM8 + 4-ch Paula + DF0: .adf + keyboard/mouse) */
static int a1200_ends_ci(const char *s, const char *suf)
{
    int ls = 0, lf = 0;
    while (s[ls]) ls++;
    while (suf[lf]) lf++;
    if (ls < lf) return 0;
    for (int i = 0; i < lf; i++)
        if ((s[ls - lf + i] | 32) != (suf[i] | 32)) return 0;
    return 1;
}

static int a1200_has_ci(const char *s, const char *sub)
{
    for (int i = 0; s[i]; i++) {
        int k = 0;
        while (sub[k] && (s[i + k] | 32) == (sub[k] | 32)) k++;
        if (!sub[k]) return 1;
    }
    return 0;
}

static u32 a1200_extract_zip_rom(const u8 *z, u32 zsz, u8 *kick, u8 *u6a, u8 *u6b)
{
    u32 cnt = zip_count(z, zsz);
    char nm[96];
    u32 msz = 0;
    /* Pass 1: single 512 KB Kickstart .rom / .a1200 */
    for (u32 i = 0; i < cnt; i++) {
        if (zip_unpack_at(z, zsz, i, 0, 0, &msz, nm, sizeof(nm)) == 0 && msz == 0x80000u &&
            (a1200_ends_ci(nm, ".rom") || a1200_ends_ci(nm, ".a1200"))) {
            if (zip_unpack_at(z, zsz, i, kick, 0x80000u, &msz, nm, sizeof(nm)) == 0)
                return 0x80000u;
        }
    }
    /* Pass 2: split 256 KB .u6a + .u6b EPROM pairs (prefer KS 3.1 391773/391774, then KS 3.0 391523/391524, then any) */
    static const char *const prefs[3] = {"39177", "39152", ""};
    for (int p = 0; p < 3; p++) {
        int ia = -1, ib = -1;
        for (u32 i = 0; i < cnt; i++) {
            if (zip_unpack_at(z, zsz, i, 0, 0, &msz, nm, sizeof(nm)) == 0 && msz == 0x40000u) {
                if (prefs[p][0] && !a1200_has_ci(nm, prefs[p])) continue;
                if (ia < 0 && a1200_ends_ci(nm, ".u6a")) ia = (int)i;
                if (ib < 0 && a1200_ends_ci(nm, ".u6b")) ib = (int)i;
            }
        }
        if (ia >= 0 && ib >= 0 &&
            zip_unpack_at(z, zsz, (u32)ia, u6a, 0x40000u, &msz, nm, sizeof(nm)) == 0 &&
            zip_unpack_at(z, zsz, (u32)ib, u6b, 0x40000u, &msz, nm, sizeof(nm)) == 0) {
            a1200_interleave_roms(u6a, u6b, kick);
            return 0x80000u;
        }
    }
    return 0;
}

static const char *a1200_open(u8 *image, u32 size, const char *path)
{
    u8 *kick = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u8 *ext  = (u8 *)KSEG0(IMAGE_WORK_PHYS + 0x080000u);
    u8 *u6a  = (u8 *)KSEG0(IMAGE_WORK_PHYS + 0x100000u);
    u8 *u6b  = (u8 *)KSEG0(IMAGE_WORK_PHYS + 0x140000u);
    u8 *zbuf = (u8 *)KSEG0(IMAGE_WORK_PHYS + 0x180000u);
    u32 gk = 0, ge = 0;

    if (size > 0 && gz_is(image, size)) {
        char gname[96];
        u32 gsz = 0;
        image_poll = unpack_poll;
        const char *why = gz_unpack(image, size, zbuf, 0x200000u, &gsz, gname, sizeof(gname));
        image_poll = 0;
        if (why) return why;
        for (u32 i = 0; i < gsz; i++) image[i] = zbuf[i];
        size = gsz;
    } else if (size > 0 && zip_is(image, size)) {
        char zname[96];
        u32 asz = 0;
        image_poll = unpack_poll;
        const char *zwhy = zip_unpack(image, size, ".adf", zbuf, 0x200000u, &asz, zname, sizeof(zname));
        image_poll = 0;
        if (!zwhy && (asz == 901120u || asz == 1802240u)) {
            for (u32 i = 0; i < asz; i++) image[i] = zbuf[i];
            size = asz;
        } else {
            gk = a1200_extract_zip_rom(image, size, kick, u6a, u6b);
            if (!gk) return zwhy ? zwhy : "no .adf floppy or Amiga 1200 Kickstart ROM found in .zip";
            size = 0;
        }
    } else if (size == 0x80000u && (a1200_ends_ci(path, ".rom") || a1200_ends_ci(path, ".a1200"))) {
        for (u32 i = 0; i < 0x80000u; i++) kick[i] = image[i];
        gk = 0x80000u;
        size = 0;
    }

    if (!gk) gk = rom_find(path, "a1200", "a1200.rom", kick, 0x80000u, 0x80000u);
    if (!gk) gk = rom_find(path, "a1200", "kick40068.A1200", kick, 0x80000u, 0x80000u);
    if (!gk) gk = rom_find(path, "a1200", "kick.rom", kick, 0x40000u, 0x80000u);
    if (!gk) {
        u32 ga = rom_find(path, "a1200", "391773-01.u6a", u6a, 0x40000u, 0x40000u);
        u32 gb = ga ? rom_find(path, "a1200", "391774-01.u6b", u6b, 0x40000u, 0x40000u) : 0u;
        if (!ga || !gb) {
            ga = rom_find(path, "a1200", "391523-01.u6a", u6a, 0x40000u, 0x40000u);
            gb = ga ? rom_find(path, "a1200", "391524-01.u6b", u6b, 0x40000u, 0x40000u) : 0u;
        }
        if (ga == 0x40000u && gb == 0x40000u) {
            a1200_interleave_roms(u6a, u6b, kick);
            gk = 0x80000u;
        }
    }
    if (!gk) {
        u32 gz = rom_find(path, "a1200", "a1200.zip", zbuf, 256u, 0x300000u);
        if (!gz) gz = rom_find(path, "amiga", "a1200.zip", zbuf, 256u, 0x300000u);
        if (gz) gk = a1200_extract_zip_rom(zbuf, gz, kick, u6a, u6b);
    }
    if (!gk) {
        gk = rom_find(path, "a1200", "aros-rom.bin", kick, 0x80000u, 0x80000u);
        if (gk) ge = rom_find(path, "a1200", "aros-ext.bin", ext, 0x80000u, 0x80000u);
        if (!gk) {
            gk = rom_find(path, "amiga", "aros-rom.bin", kick, 0x80000u, 0x80000u);
            if (gk) ge = rom_find(path, "amiga", "aros-ext.bin", ext, 0x80000u, 0x80000u);
        }
    }
    if (!gk) gk = rom_find(path, "amiga", "kick.rom", kick, 0x40000u, 0x80000u);

    for (int i = 0; i < 16; i++)
        amiga_keys[i] = 0;
    return a1200_load(gk ? kick : 0, gk, ge == 0x80000u ? ext : 0, ge, size ? image : 0, size, path);
}

static void a1200_one(u16 pad, void *pic_out)
{
    a1200_frame(pad, amiga_keys, (u16 *)pic_out);
}

static void a1200_typed(char c)
{
    char s[2] = {c, 0};
    a1200_type(s);
}

static const struct machine a1200_machine = {
    CD32_W, CD32_H, 2, 2, CD32_FRAME_US, a1200_open, cd32_info, a1200_one, cd32_save_ram, cd32_save_changed,
    cd32_jammed, 0, 0, "the 14 MHz 68EC020 + AGA", amiga_keyboard, a1200_typed,
    "the USB keyboard is the Amiga's, arrows = joystick (fire: right Ctrl / remote OK), Page Up/Down or remote 0 = "
    "mouse button, MENU = Return, INFO = Space; Esc ends",
    0, cd32_audio_rate, cd32_audio
};

int a1200_play(const char *path, u32 frames, const char *script)
{
    return play(&a1200_machine, path, frames, script);
}

/* 13. 3DO Interactive Multiplayer ('3do': .iso, .cue; "": built-in 3D CEL showcase) */
static const char *threedo_open(u8 *image, u32 size, const char *path)
{
    if (!*path) {
        threedo_set_bios(0, 0);
        return threedo_load(0, "");
    }
    const char *cd_err = 0;
    const struct cdrom_toc *toc = cdrom_open_disc(path, image, size, &cd_err);
    if (!toc)
        return cd_err;
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 gb = rom_find(path, "3do", "panafz10.bin", bios, 0x80000u, 0x100000u);
    if (!gb) gb = rom_find(path, "3do", "panafz1.bin", bios, 0x80000u, 0x100000u);
    if (!gb) gb = rom_find(path, "3do", "goldstar.bin", bios, 0x80000u, 0x100000u);
    threedo_set_bios(gb ? bios : 0, gb);
    const char *why = threedo_load(toc, path);
    if (why)
        cdrom_close_disc();
    return why;
}

static void threedo_one(u16 pad, void *pic_out)
{
    threedo_frame(pad, (u16 *)pic_out);
}

static const struct machine threedo_machine = {
    THREEDO_W, THREEDO_H, 3, 3, THREEDO_FRAME_US, threedo_open, threedo_info, threedo_one,
    threedo_save_ram, threedo_save_changed, threedo_jammed, 0, 0, "the 12.5 MHz ARM60 + Madam CEL", 0, 0,
    "arrows or W A S D, X = A, Z = B, C = C, Q/E = L/R, Enter = P (Start), Tab = X (Stop); Ctrl-C or Esc ends",
    0, threedo_audio_rate, threedo_audio
};

int threedo_play(const char *path, u32 frames, const char *script)
{
    int r = play(&threedo_machine, path, frames, script);
    cdrom_close_disc();
    return r;
}

/* 14. SNK Neo Geo CD ('neocd': .cue, .iso; "": built-in Neo Geo CD showcase) */
static const char *neocd_open(u8 *image, u32 size, const char *path)
{
    if (!*path) {
        neocd_set_bios(0, 0);
        return neocd_load(0, "");
    }
    const char *cd_err = 0;
    const struct cdrom_toc *toc = cdrom_open_disc(path, image, size, &cd_err);
    if (!toc)
        return cd_err;
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 gb = rom_find(path, "neocd", "neocd.bin", bios, 0x40000u, 0x80000u);
    if (!gb) gb = rom_find(path, "neocd", "top-sp1.bin", bios, 0x40000u, 0x80000u);
    if (!gb) gb = rom_find(path, "neocd", "front-sp1.bin", bios, 0x40000u, 0x80000u);
    if (!gb) gb = rom_find(path, "neocd", "uni-bioscd.rom", bios, 0x40000u, 0x80000u);
    if (!gb) gb = rom_find(path, "neogeo", "neocd.bin", bios, 0x40000u, 0x80000u);
    neocd_set_bios(gb ? bios : 0, gb);
    const char *why = neocd_load(toc, path);
    if (why)
        cdrom_close_disc();
    return why;
}

static const struct machine neocd_machine = {
    NEO_W, NEO_H, 3, 3, NEO_FRAME_US, neocd_open, neo_info, neo_one, neo_save_ram, neo_save_changed,
    neo_jammed, 0, 0, "the 12 MHz 68000 + Z80 (Neo Geo CD)", 0, 0,
    "arrows or W A S D, X = A, Z = B, C = C, V = D, Enter = Start, Tab = Select; Ctrl-C or Esc ends",
    0, neo_audio_rate, neo_audio
};

int neocd_play(const char *path, u32 frames, const char *script)
{
    int r = play(&neocd_machine, path, frames, script);
    cdrom_close_disc();
    return r;
}

/* 15. NEC PC-9801VM / VX ('pc98': .fdi, .hdi, .d88, .hdm, .xdf, .2hd, .zip; "": built-in showcase) */
#define PC98_FONT_AT (IMAGE_WORK_PHYS + IMAGE_WORK_SIZE - 0x00080000u)
#define PC98_POOL_LIM (IMAGE_WORK_SIZE - 0x00080000u)

static int pc98_is_disk_ext(const char *nm)
{
    return dos_ends_ci(nm, ".fdi") || dos_ends_ci(nm, ".hdi") || dos_ends_ci(nm, ".d88") ||
           dos_ends_ci(nm, ".d98") || dos_ends_ci(nm, ".hdm") || dos_ends_ci(nm, ".xdf") ||
           dos_ends_ci(nm, ".2hd") || dos_ends_ci(nm, ".dup") || dos_ends_ci(nm, ".img");
}

static const char *pc98_open(u8 *image, u32 size, const char *path)
{
    u8 *fbuf = (u8 *)KSEG0(PC98_FONT_AT);
    u32 gf = rom_find(path, "pc98", "font.rom", fbuf, 0x46800u, 0x80000u);
    pc98_set_font(gf >= 0x46800u ? fbuf : 0, gf);
    pc98_clear_files();

    if (size > 0 && zip_is(image, size)) {
        u32 cnt = zip_count(image, size);
        /* First check if the .zip wraps a floppy/HDD image (.fdi/.hdm/.d88/.hdi) */
        for (u32 i = 0; i < cnt; i++) {
            char mname[96];
            u32 msz = 0;
            if (zip_unpack_at(image, size, i, 0, 0, &msz, mname, sizeof(mname)) == 0 &&
                pc98_is_disk_ext(mname) && msz <= MEDIA_MAX - size) {
                u8 *top = image + MEDIA_MAX - size;
                for (u32 b = size; b-- > 0;)
                    top[b] = image[b];
                image_poll = unpack_poll;
                const char *zwhy = zip_unpack_at(top, size, i, image, MEDIA_MAX - size, &msz, mname, sizeof(mname));
                image_poll = 0;
                if (zwhy)
                    return zwhy;
                return pc98_load(image, msz, mname);
            }
        }
        /* Otherwise unpack multi-file PC-98 DOS game archive into IMAGE_WORK_PHYS */
        u8 *pool = (u8 *)KSEG0(IMAGE_WORK_PHYS);
        u32 pool_used = 0;
        for (u32 i = 0; i < cnt; i++) {
            char mname[96];
            u32 msz = 0;
            if (zip_unpack_at(image, size, i, 0, 0, &msz, mname, sizeof(mname)) != 0)
                continue;
            const char *bn = dos_base_of(mname);
            if (!*bn)
                continue;
            u32 aligned = (pool_used + 3u) & ~3u;
            if (aligned + msz > PC98_POOL_LIM)
                return "unpacked PC-98 .zip exceeds RAM work buffer";
            image_poll = unpack_poll;
            const char *zwhy = zip_unpack_at(image, size, i, pool + aligned, PC98_POOL_LIM - aligned,
                                             &msz, mname, sizeof(mname));
            image_poll = 0;
            if (zwhy)
                return zwhy;
            (void)pc98_add_file(dos_base_of(mname), pool + aligned, msz);
            pool_used = aligned + msz;
        }
        return pc98_load(0, 0, path);
    }

    return pc98_load(size ? image : 0, size, path);
}

static void pc98_one(u16 pad, void *pic_out)
{
    pc98_frame(pad, (u16 *)pic_out);
}

static void pc98_typed(char c)
{
    char s[2] = {c, 0};
    pc98_type(s);
}

static const struct machine pc98_machine = {
    PC98_W, PC98_H, 2, 2, PC98_FRAME_US, pc98_open, pc98_info, pc98_one,
    pc98_save_ram, pc98_save_changed, pc98_jammed, 0, 0, "the 10 MHz V30/286 + uPD7220 GDC",
    pc98_keys_from_hid, pc98_typed,
    "arrows/tenkey = move, Z/Space = Trig 1, X = Trig 2, Enter = Return, USB keyboard; Esc ends",
    0, pc98_audio_rate, pc98_audio
};

int pc98_play(const char *path, u32 frames, const char *script)
{
    return play(&pc98_machine, path, frames, script);
}

/* 16. Konami Classic Arcade ('konami': .zip; "": built-in Viper Strike GX) */
static const char *konami_open(u8 *image, u32 size, const char *path)
{
    const char *why = konami_load(size ? image : 0, size, path);
    if (!why) {
        int w = konami_width(), h = konami_height();
        int xs = 1280 / (w > 0 ? w : 304);
        int ys = 720 / (h > 0 ? h : 224);
        int s = xs < ys ? xs : ys;
        if (s < 1) s = 1;
        konami_machine.w = w;
        konami_machine.h = h;
        konami_machine.xs = s;
        konami_machine.ys = s;
    }
    return why;
}

static void konami_one(u16 pad, void *pic_out)
{
    konami_frame(pad, (u16 *)pic_out);
}

static void konami_size(int *w, int *h)
{
    *w = konami_width();
    *h = konami_height();
}

static struct machine konami_machine = {
    304, 224, 3, 3, KONAMI_FRAME_US, konami_open, konami_info, konami_one,
    konami_save_ram, konami_save_changed, konami_jammed, 0, 0,
    "the Konami 68000/6809 + Z80", 0, 0,
    "arrows or W A S D, X = Shot/Attack, Z = Jump/Power, C = Button 3, Tab/Space = Coin, Enter = Start; Ctrl-C or Esc ends",
    konami_size, konami_audio_rate, konami_audio
};

int konami_play(const char *path, u32 frames, const char *script)
{
    return play(&konami_machine, path, frames, script);
}

/* 17. Williams & Midway Classic Arcade ('williams': .zip; "": built-in Cybertron: 2084) */
static const char *williams_open(u8 *image, u32 size, const char *path)
{
    const char *why = williams_load(size ? image : 0, size, path);
    if (!why) {
        int w = williams_width(), h = williams_height();
        int xs = 1280 / (w > 0 ? w : 304);
        int ys = 720 / (h > 0 ? h : 240);
        int s = xs < ys ? xs : ys;
        if (s < 1) s = 1;
        williams_machine.w = w;
        williams_machine.h = h;
        williams_machine.xs = s;
        williams_machine.ys = s;
    }
    return why;
}

static void williams_one(u16 pad, void *pic_out)
{
    williams_frame(pad, (u16 *)pic_out);
}

static void williams_size(int *w, int *h)
{
    *w = williams_width();
    *h = williams_height();
}

static struct machine williams_machine = {
    304, 240, 3, 3, WILLIAMS_FRAME_US, williams_open, williams_info, williams_one,
    williams_save_ram, williams_save_changed, williams_jammed, 0, 0,
    "the Williams Dual-6809 / Midway TMS34010", 0, 0,
    "arrows or W A S D, X = Fire/Flap, Z = Bomb/Action, C = Hyper, V = Fire Up, Tab/Space = Coin, Enter = Start; Ctrl-C or Esc ends",
    williams_size, williams_audio_rate, williams_audio
};

int williams_play(const char *path, u32 frames, const char *script)
{
    return play(&williams_machine, path, frames, script);
}

/* 18. Irem M72 & M92 Classic Arcade ('irem': .zip; "": built-in R-Force: Bydo Assault) */
static const char *irem_open(u8 *image, u32 size, const char *path)
{
    const char *why = irem_load(size ? image : 0, size, path);
    if (!why) {
        int w = irem_width(), h = irem_height();
        int xs = 1280 / (w > 0 ? w : 384);
        int ys = 720 / (h > 0 ? h : 240);
        int s = xs < ys ? xs : ys;
        if (s < 1) s = 1;
        irem_machine.w = w;
        irem_machine.h = h;
        irem_machine.xs = s;
        irem_machine.ys = s;
    }
    return why;
}

static void irem_one(u16 pad, void *pic_out)
{
    irem_frame(pad, (u16 *)pic_out);
}

static void irem_size(int *w, int *h)
{
    *w = irem_width();
    *h = irem_height();
}

static struct machine irem_machine = {
    384, 240, 3, 3, IREM_FRAME_US, irem_open, irem_info, irem_one,
    irem_save_ram, irem_save_changed, irem_jammed, 0, 0,
    "the Irem NEC V30/V33 + Z80", 0, 0,
    "arrows or W A S D, X = Fire/Beam, Z = Force/Jump, Tab/Space = Coin, Enter = Start; Ctrl-C or Esc ends",
    irem_size, irem_audio_rate, irem_audio
};

int irem_play(const char *path, u32 frames, const char *script)
{
    return play(&irem_machine, path, frames, script);
}

/* 19. Taito Classic & F2 / B-System Arcade ('taito': .zip; "": built-in Bubble Dragons F2) */
static const char *taito_open(u8 *image, u32 size, const char *path)
{
    const char *why = taito_load(size ? image : 0, size, path);
    if (!why) {
        int w = taito_width(), h = taito_height();
        int xs = 1280 / (w > 0 ? w : 320);
        int ys = 720 / (h > 0 ? h : 224);
        int s = xs < ys ? xs : ys;
        if (s < 1) s = 1;
        taito_machine.w = w;
        taito_machine.h = h;
        taito_machine.xs = s;
        taito_machine.ys = s;
    }
    return why;
}

static void taito_one(u16 pad, void *pic_out)
{
    taito_frame(pad, (u16 *)pic_out);
}

static void taito_size(int *w, int *h)
{
    *w = taito_width();
    *h = taito_height();
}

static struct machine taito_machine = {
    320, 224, 3, 3, TAITO_FRAME_US, taito_open, taito_info, taito_one,
    taito_save_ram, taito_save_changed, taito_jammed, 0, 0,
    "the Taito 68000 / Z80", 0, 0,
    "arrows or W A S D, X = Bubble/Fire, Z = Jump, Tab/Space = Coin, Enter = Start; Ctrl-C or Esc ends",
    taito_size, taito_audio_rate, taito_audio
};

int taito_play(const char *path, u32 frames, const char *script)
{
    return play(&taito_machine, path, frames, script);
}

/* 20. PICO-8 128x128 Fantasy Console ('pico8': .p8, .p8.png; "": built-in CelestePeak-8) */
static const char *pico8_open(u8 *image, u32 size, const char *path)
{
    return pico8_load(size ? image : 0, size, path);
}

static void pico8_one(u16 pad, void *pic_out)
{
    pico8_frame(pad, (u16 *)pic_out);
}

static const struct machine pico8_machine = {
    PICO8_W, PICO8_H, 5, 5, PICO8_FRAME_US, pico8_open, pico8_info, pico8_one,
    pico8_save_ram, pico8_save_changed, pico8_jammed, 0, 0,
    "the PICO-8 Lua VM", 0, 0,
    "arrows or W A S D, Z = O (Jump/Action 1), X = X (Dash/Action 2); Ctrl-C or Esc ends",
    0, pico8_audio_rate, pico8_audio
};

int pico8_play(const char *path, u32 frames, const char *script)
{
    return play(&pico8_machine, path, frames, script);
}

/* 21. Atari Jaguar 64-Bit Console ('jaguar': .j64, .jag, .rom; "": built-in Tempest Jaguar 64) */
static struct machine jaguar_machine;
static const char *jaguar_open(u8 *image, u32 size, const char *path)
{
    const char *why = jaguar_load(size ? image : 0, size, path);
    if (!why) {
        int w = jaguar_width(), h = jaguar_height();
        int xs = 1280 / (w > 0 ? w : 320);
        int ys = 720 / (h > 0 ? h : 224);
        int s = xs < ys ? xs : ys;
        if (s < 1) s = 1;
        jaguar_machine.w = w;
        jaguar_machine.h = h;
        jaguar_machine.xs = s;
        jaguar_machine.ys = s;
    }
    return why;
}

static void jaguar_one(u16 pad, void *pic_out)
{
    jaguar_frame(pad, (u16 *)pic_out);
}

static void jaguar_size(int *w, int *h)
{
    *w = jaguar_width();
    *h = jaguar_height();
}

static struct machine jaguar_machine = {
    320, 224, 3, 3, JAGUAR_FRAME_US, jaguar_open, jaguar_info, jaguar_one,
    jaguar_save_ram, jaguar_save_changed, jaguar_jammed, 0, 0,
    "the Jaguar 68000 + Tom GPU + Jerry DSP", 0, 0,
    "arrows or W A S D, X = Button A, Z = Button B, C = Button C, Enter = Pause; Ctrl-C or Esc ends",
    jaguar_size, jaguar_audio_rate, jaguar_audio
};

int jaguar_play(const char *path, u32 frames, const char *script)
{
    return play(&jaguar_machine, path, frames, script);
}

/* 22. NEC PC-FX 32-Bit CD-ROM Console ('pcfx': .cue, .iso; "": built-in Star Soldier FX-32) */
static struct machine pcfx_machine;
static const char *pcfx_open(u8 *image, u32 size, const char *path)
{
    if (!*path) {
        pcfx_set_bios(0, 0);
        const char *why = pcfx_load(0, "");
        pcfx_machine.w = pcfx_width();
        pcfx_machine.h = pcfx_height();
        pcfx_machine.xs = 3;
        pcfx_machine.ys = 3;
        return why;
    }
    const char *cd_err = 0;
    const struct cdrom_toc *toc = cdrom_open_disc(path, image, size, &cd_err);
    if (!toc)
        return cd_err;
    u8 *bios = (u8 *)KSEG0(IMAGE_WORK_PHYS);
    u32 gb = rom_find(path, "pcfx", "pcfx.rom", bios, 0x80000u, 0x100000u);
    if (!gb) gb = rom_find(path, "pcfx", "pcfxbios.bin", bios, 0x80000u, 0x100000u);
    if (!gb) gb = rom_find(path, "pcfx", "fx-scsi.rom", bios, 0x80000u, 0x100000u);
    pcfx_set_bios(gb ? bios : 0, gb);
    const char *why = pcfx_load(toc, path);
    if (why) {
        cdrom_close_disc();
        return why;
    }
    int w = pcfx_width(), h = pcfx_height();
    pcfx_machine.w = w;
    pcfx_machine.h = h;
    pcfx_machine.xs = (w <= 256) ? 3 : 3;
    pcfx_machine.ys = 3;
    return 0;
}

static void pcfx_one(u16 pad, void *pic_out)
{
    pcfx_frame(pad, (u16 *)pic_out);
}

static void pcfx_size(int *w, int *h)
{
    *w = pcfx_width();
    *h = pcfx_height();
}

static struct machine pcfx_machine = {
    PCFX_W, PCFX_H, 3, 3, PCFX_FRAME_US, pcfx_open, pcfx_info, pcfx_one,
    pcfx_save_ram, pcfx_save_changed, pcfx_jammed, 0, 0,
    "the 21.5 MHz NEC V810 + HuC6272 KING", 0, 0,
    "arrows or W A S D, X = I, Z = II, C = III, V = IV, Q/E = V/VI, Enter = Run, Tab = Select; Ctrl-C or Esc ends",
    pcfx_size, pcfx_audio_rate, pcfx_audio
};

int pcfx_play(const char *path, u32 frames, const char *script)
{
    int r = play(&pcfx_machine, path, frames, script);
    cdrom_close_disc();
    return r;
}

/* 23. Nintendo 64 ('n64': .z64, .n64, .v64; "": built-in Star Wing 64 3D) */
static const char *n64_open(u8 *image, u32 size, const char *path)
{
    return n64_load(size ? image : 0, size, path);
}

static void n64_one(u16 pad, void *pic_out)
{
    n64_frame(pad, (u16 *)pic_out);
}

static const struct machine n64_machine = {
    N64_W_MAX, N64_H_MAX, 3, 3, N64_FRAME_US, n64_open, n64_info, n64_one,
    n64_save_ram, n64_save_changed, n64_jammed, 0, 0,
    "the 93.75 MHz MIPS VR4300 + RCP/RDP", 0, 0,
    "arrows or W A S D = Stick / D-Pad, X = A, Z = B, C/Tab = Z-Trigger, Q/E = L/R, Enter = Start; Ctrl-C or Esc ends",
    0, n64_audio_rate, n64_audio
};

int n64_play(const char *path, u32 frames, const char *script)
{
    return play(&n64_machine, path, frames, script);
}
