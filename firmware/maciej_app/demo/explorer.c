/* A file explorer on the TV: 'explorer' shows the current directory of a USB
   disk ('cd', the prompt's) on the test screen's picture -- a title bar with
   the disk and its volume, a path bar with the current directory, the
   directory's entries (a ".." row first, the directories, then the files,
   each by name; their sizes and dates) and a status line.
   It is synced to the shell both ways: a 'cd' typed on the UART lists the
   new directory (so does anything that writes a disk, a disk plugged in or
   out: disk_changes); opening a directory here is a 'cd' (the prompt
   follows, main.c prints it again).  Without a current directory -- before
   any 'cd', or ".." at a volume's root -- it lists the disks' volumes to
   open one.
   While it is on the TV the USB keyboard is its own (main.c hands the
   characters over): Up / Down / PgUp / PgDn / Home / End select, Enter or
   Right opens (a file: its beginning in a preview on the TV -- never on the
   UART), Backspace or Left goes up, a letter jumps to the next name
   starting with it, '/' or Tab puts a caret into the path bar -- typing
   edits the path, Enter goes there as 'cd' would ("4:" a disk, ".." one up,
   a path without '/' from here), Esc cancels -- Ctrl-R lists again, and
   Esc (the keyboard's Escape arrives as Ctrl-C) brings the console back.
   The mouse (mouse.c hands its reports over and does not paint): a click
   selects, a double-click opens, a click on the path bar types a path, the
   wheel scrolls.  The disk calls' messages (a path not found, a sector that
   did not read) go to the status line, not to the UART: uart_capture keeps
   them (the explorer calls the disk only from the main loop, never inside
   a command whose output is going into a file). */
#include "hw.h"
#include "av.h"
#include "md.h"
#include "msx.h"
#include "intv.h"
#include "psx.h"
#include "cps.h"
#include "s16.h"
#include "a8.h"
#include "zip.h"

#define CELL        12                  /* the font's cells (gfx_cell): 12 x 16 */
#define TITLE_H     44
#define PATH_X      80
#define PATH_Y      54
#define PATH_W      (SCREEN_W - 16 - PATH_X)
#define PATH_H      32
#define PATH_TX     (PATH_X + 10)
#define PATH_TY     (PATH_Y + 8)
#define PATH_LEN    96                  /* a typed path (disk.c's paths are as long) */
#define HEAD_Y      94
#define HEAD_H      26
#define LIST_X      8
#define LIST_Y      124
#define ROW_H       22
#define ROWS        23                  /* rows on the TV */
#define LIST_H      (ROWS * ROW_H)
#define BAR_X       1258                /* the scroll bar */
#define BAR_W       10
#define ROW_W       (BAR_X - 4 - LIST_X)
#define ICON_X      16
#define NAME_X      40
#define NAME_CELLS  64
#define SIZE_END    1000                /* sizes end here */
#define DATE_X      1040
#define WIDE_CELLS  98                  /* a volume's line: across the size and date columns */
#define STATUS_Y    (LIST_Y + LIST_H + 8)
#define LINE_Y      (STATUS_Y + 10)     /* the status lines' first */
#define LINE_GAP    24
#define LINE_CELLS  104
#define MAX_ENTRIES 512
#define DOUBLE_MS   400                 /* two clicks on a row this close: a double-click */
#define HEAD_BYTES  2048                /* a file's beginning, for its preview */
#define PREVIEW_LINE 18

#define C_BACK      RGB(2, 4, 16)
#define C_BAR       RGB(24, 48, 128)
#define C_LINE      RGB(90, 140, 230)
#define C_TEXT      RGB(255, 255, 255)
#define C_LABEL     RGB(150, 190, 255)
#define C_VALUE     RGB(255, 230, 120)
#define C_DIRC      RGB(255, 210, 90)
#define C_DIM       RGB(120, 120, 140)
#define C_LIST      RGB(10, 16, 40)
#define C_ALT       RGB(14, 22, 52)
#define C_SEL       RGB(40, 90, 190)
#define C_HEAD      RGB(16, 32, 88)
#define C_FIELD     RGB(0, 0, 0)
#define C_FOCUS     RGB(255, 230, 120)
#define C_ERR       RGB(255, 120, 100)
#define C_TRACK     RGB(20, 30, 60)
#define C_THUMB     RGB(90, 140, 230)
#define C_PAGE      RGB(220, 220, 230)
#define C_PAGE_LINE RGB(130, 130, 150)
#define C_DRIVE     RGB(170, 170, 185)
#define C_LED       RGB(90, 230, 90)
#define C_PREVIEW   RGB(6, 10, 26)

/* keys after their escape sequences */
#define K_UP    0x100
#define K_DOWN  0x101
#define K_LEFT  0x102
#define K_RIGHT 0x103
#define K_HOME  0x104
#define K_END   0x105
#define K_PGUP  0x106
#define K_PGDN  0x107
#define K_DEL   0x108
#define K_INS   0x109
#define K_F2    0x112                   /* (kbd.c: F1..F12 as ESC [ 11 ~ .. ESC [ 24 ~) */
#define K_F5    0x115
#define K_F6    0x116
#define K_F7    0x117
#define K_F8    0x118
#define K_ESC   0x03                    /* (a USB keyboard's Escape is Ctrl-C: kbd.c) */

static int on;                          /* shown with 'explorer', until the console or a drawing */
static int loaded;                      /* the listing is the current directory's */
static struct disk_entry ents[MAX_ENTRIES];
static u16 order[MAX_ENTRIES];          /* ents by kind and name */
static int n_ents;
static u32 n_total;                     /* entries in the directory (more than MAX_ENTRIES: the first shown) */
static int volumes_view;                /* no current directory: the disks' volumes */
static int has_up;                      /* a ".." row first */
static int rows;                        /* has_up + n_ents */
static int sel, top;                    /* the selected row, the first on the TV */
static int dirs, files;
static u32 bytes, bytes_4g;             /* the files' bytes: bytes_4g * 4 GB + bytes */
static char cwd_shown[PATH_LEN + 16];   /* disk_cwd() as listed */
static char vol_text[96];               /* "disk 4: FAT32 'STICK', 39 MB" */
static u32 changes_seen;                /* disk_changes() as listed */
static char want_sel[DISK_ENTRY_NAME];  /* the next listing selects this name ("4:" a volume) */
static int prompt_stale;                /* the explorer changed the current directory */
static char status_msg[160];            /* what the disk said (an error), until the next key or click */

static int editing;                     /* the path bar has the caret */
static char edit[PATH_LEN + 8];         /* (as long as disk.c's current directory: "4.2:" and a 95-byte path) */
static int edit_len, caret;

/* writing (FAT, and NTFS when disk.c's gate lets it: else it refuses, and says so in the status line) */
static int input_kind;                  /* the path bar's text: 0 a path to go to, 1 a new name (F2), 2 a new
                                           directory's (F7) */
static char input_from[DISK_ENTRY_NAME];/* F2: the name being changed */
static int confirm;                     /* Delete / F8 asked: 'y' deletes the selected entry */
static char clip[PATH_LEN + 16 + DISK_ENTRY_NAME];      /* F5 / F6: a file's whole path ("" none) */
static int clip_move;                   /* F6: Insert moves it (else copies it) */
static int want_forced;                 /* the next listing selects want_sel, not the entry selected now */

static int esc;                         /* 1: after ESC, 2: in ESC [ */
static int esc_arg;

static u8 mouse_buttons;
static u64 last_click_ms;
static int last_click_row = -1;
static int pending_open = -1;           /* a double-clicked row: opened by explorer_poll */

static int preview;                     /* a file's beginning is on the TV */
static u8 head[HEAD_BYTES];

static char said[160];                  /* the disk calls' output, captured */

/* ---- small helpers ---- */
static int slen(const char *s)
{
    int n = 0;
    while (s[n])
        n++;
    return n;
}

static void scopy(char *to, const char *from, int size)
{
    int i = 0;
    for (; i < size - 1 && from[i]; i++)
        to[i] = from[i];
    to[i] = 0;
}

static int same(const char *a, const char *b)
{
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a == *b;
}

static char low(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c + 32) : c;
}

static int clampi(int v, int lo, int hi)
{
    return v < lo ? lo : v > hi ? hi : v;
}

/* what the disk calls print goes into `said`; its first line, when there is one, into the status line */
static void capture_begin(void)
{
    uart_capture((u8 *)said, sizeof(said) - 1);
}

static int capture_end(void)
{
    u32 over;
    u32 n = uart_capture_end(&over);
    said[n] = 0;
    int i = 0;
    while (said[i] && said[i] != '\n')
        i++;
    said[i] = 0;
    if (!said[0])
        return 0;
    scopy(status_msg, said, sizeof(status_msg));
    return 1;
}

/* row i's entry; 0 for the ".." row (and past the end) */
static const struct disk_entry *entry(int i)
{
    if (i < 0 || i >= rows || (has_up && i == 0))
        return 0;
    return &ents[order[i - has_up]];
}

/* at a volume's root ("4:/")? */
static int at_root(void)
{
    int i = 0;
    while (cwd_shown[i] && cwd_shown[i] != ':')
        i++;
    return cwd_shown[i] == ':' && cwd_shown[i + 1] == '/' && !cwd_shown[i + 2];
}

/* ---- drawing ---- */
/* text in the font's cells from x (even): `max` cells at most (a longer one ends in '~'); where it ends */
static int put(int x, int y, const char *s, int max, u16 fg, u16 bg)
{
    int n = slen(s);
    for (int i = 0; i < n && i < max; i++)
        gfx_cell(x + i * CELL, y, n > max && i == max - 1 ? '~' : s[i], fg, bg);
    return x + (n < max ? n : max) * CELL;
}

static void draw_title(void)
{
    char t[96];
    gfx_fill(0, 0, SCREEN_W, TITLE_H, C_BAR);
    gfx_fill(0, TITLE_H, SCREEN_W, 3, C_LINE);
    gfx_text(16, 11, "FILE EXPLORER", 3, C_TEXT);
    if (volumes_view) {
        int d = disk_count();
        usnprintf(t, sizeof(t), d ? "%d USB disk%s" : "no USB disk", d, d == 1 ? "" : "s");
    } else {
        scopy(t, vol_text, sizeof(t));
    }
    int n = clampi(slen(t), 0, 76);
    put(SCREEN_W - 16 - n * CELL, 14, t, n, C_LABEL, C_BAR);
}

static void draw_path(void)
{
    int max = (PATH_W - 20) / CELL;
    put(16, PATH_TY, editing && input_kind ? "Name" : "Path", 4, C_LABEL, C_BACK);
    gfx_frame(PATH_X, PATH_Y, PATH_W, PATH_H, 2, editing ? C_FOCUS : C_LINE);
    gfx_fill(PATH_X + 2, PATH_Y + 2, PATH_W - 4, PATH_H - 4, C_FIELD);
    if (editing) {                                      /* (a path longer than the field: it scrolls with the caret) */
        int first = caret > max - 2 ? caret - (max - 2) : 0;
        put(PATH_TX, PATH_TY, edit + first, max - 1, C_TEXT, C_FIELD);
        gfx_cell(PATH_TX + (caret - first) * CELL, PATH_TY, caret < edit_len ? edit[caret] : ' ', C_FIELD, C_FOCUS);
    } else if (volumes_view) {
        put(PATH_TX, PATH_TY, "(no current directory: open a disk below, or type a path: '/', Tab or a click here)",
            max, C_DIM, C_FIELD);
    } else {
        int len = slen(cwd_shown);                      /* (too long: its end) */
        put(PATH_TX, PATH_TY, cwd_shown + (len > max ? len - max : 0), max, C_TEXT, C_FIELD);
    }
}

static void draw_header(void)
{
    int y = HEAD_Y + 5;
    gfx_fill(LIST_X, HEAD_Y, SCREEN_W - 2 * LIST_X, HEAD_H, C_HEAD);
    if (volumes_view) {
        put(NAME_X, y, "Disk:  volume  -  device", 40, C_LABEL, C_HEAD);
        return;
    }
    put(NAME_X, y, "Name", 4, C_LABEL, C_HEAD);
    put(SIZE_END - 4 * CELL, y, "Size", 4, C_LABEL, C_HEAD);
    put(DATE_X, y, "Modified", 8, C_LABEL, C_HEAD);
}

static void icon(int kind, int y, int dim)
{
    if (kind == DISK_DIR) {                             /* a folder */
        u16 c = dim ? C_DIM : C_DIRC;
        gfx_fill(ICON_X, y + 5, 8, 3, c);
        gfx_fill(ICON_X, y + 7, 18, 11, c);
    } else if (kind == DISK_VOLUME) {                   /* a drive with its light */
        gfx_fill(ICON_X, y + 7, 18, 10, dim ? C_DIM : C_DRIVE);
        gfx_fill(ICON_X + 12, y + 13, 3, 2, dim ? C_PAGE_LINE : C_LED);
    } else {                                            /* a page */
        gfx_fill(ICON_X + 3, y + 3, 12, 16, dim ? C_DIM : C_PAGE);
        for (int k = 0; k < 3; k++)
            gfx_fill(ICON_X + 5, y + 8 + 3 * k, 8, 1, C_PAGE_LINE);
    }
}

/* a file's size: "123456" bytes; 4 GB or more (NTFS): "5120 MB" */
static void size_text(char *t, int size, const struct disk_entry *e, const char *unit)
{
    if (e->size_hi)
        usnprintf(t, size, "%u MB", e->size_hi << 12 | e->size >> 20);
    else
        usnprintf(t, size, "%u%s", e->size, unit);
}

static void date_text(char *t, int size, const struct disk_entry *e)
{
    usnprintf(t, size, "%04u-%02u-%02u %02u:%02u", 1980 + (e->date >> 9), (e->date >> 5) & 15, e->date & 31,
              e->time >> 11, (e->time >> 5) & 63);
}

/* the row `vis` rows from the top of the list */
static void draw_row(int vis)
{
    if (vis < 0 || vis >= ROWS)
        return;
    int i = top + vis, y = LIST_Y + vis * ROW_H, ty = y + 3;
    u16 bg = i == sel && i < rows ? C_SEL : (i & 1) ? C_ALT : C_LIST;
    gfx_fill(LIST_X, y, ROW_W, ROW_H, bg);
    if (i >= rows)
        return;
    const struct disk_entry *e = entry(i);
    if (!e) {                                           /* ".." */
        icon(DISK_DIR, y, 0);
        int x = put(NAME_X, ty, "..", 2, C_DIRC, bg);
        put(x + 2 * CELL, ty, at_root() ? "(the list of disks)" : "(one directory up)", 24, C_LABEL, bg);
        return;
    }
    int dim = (e->attr & 0x02) != 0;                    /* hidden; a volume whose files are not read */
    icon(e->kind, y, dim);
    if (e->kind == DISK_VOLUME) {
        put(NAME_X, ty, e->name, WIDE_CELLS, dim ? C_DIM : C_TEXT, bg);
        return;
    }
    put(NAME_X, ty, e->name, NAME_CELLS, dim ? C_DIM : e->kind == DISK_DIR ? C_DIRC : C_TEXT, bg);
    char t[24];
    if (e->kind == DISK_DIR)
        scopy(t, "<DIR>", sizeof(t));
    else
        size_text(t, sizeof(t), e, "");
    put(SIZE_END - slen(t) * CELL, ty, t, 12, e->kind == DISK_DIR ? C_LABEL : C_TEXT, bg);
    if (e->date) {
        date_text(t, sizeof(t), e);
        put(DATE_X, ty, t, 16, C_LABEL, bg);
    }
}

static void draw_bar(void)
{
    gfx_fill(BAR_X, LIST_Y, BAR_W, LIST_H, C_TRACK);
    if (rows <= ROWS)
        return;
    int h = clampi(LIST_H * ROWS / rows, 16, LIST_H);
    gfx_fill(BAR_X, LIST_Y + (LIST_H - h) * top / (rows - ROWS), BAR_W, h, C_THUMB);
}

static void draw_list(void)
{
    for (int v = 0; v < ROWS; v++)
        draw_row(v);
    draw_bar();
}

static void status_line(int n, const char *s, u16 fg)
{
    int y = LINE_Y + n * LINE_GAP;
    gfx_fill(0, y - 4, SCREEN_W, LINE_GAP, C_BAR);
    put(16, y, s, LINE_CELLS, fg, C_BAR);
}

/* the second status line: what the disk said, or what is selected */
static void draw_selection(void)
{
    char t[200];
    const struct disk_entry *e = entry(sel);
    if (status_msg[0]) {
        status_line(1, status_msg, C_ERR);
        return;
    }
    if (sel >= rows) {
        t[0] = 0;
    } else if (!e) {
        char up[PATH_LEN + 16];
        scopy(up, cwd_shown, sizeof(up));
        int i = slen(up);
        while (i > 0 && up[i - 1] != '/')
            i--;
        if (i > 1 && up[i - 2] != ':')
            i--;                                        /* (the root keeps its '/') */
        up[i] = 0;
        if (at_root())
            scopy(t, "..: the list of disks (no current directory)", sizeof(t));
        else
            usnprintf(t, sizeof(t), "..: one directory up, %s", up);
    } else if (e->kind == DISK_VOLUME) {
        int i = 0;
        char name[12];
        while (e->name[i] && e->name[i] != ':' && i < 9) {
            name[i] = e->name[i];
            i++;
        }
        name[i++] = ':';
        name[i] = 0;
        usnprintf(t, sizeof(t), (e->attr & 0x02) ? "%s  its files are not read" : "%s  Enter opens its root "
                  "(as 'cd %s')", name, name);
    } else {
        char d[24], z[24];
        date_text(d, sizeof(d), e);
        size_text(z, sizeof(z), e, " bytes");
        if (e->kind == DISK_DIR)
            usnprintf(t, sizeof(t), "%s: a directory, %s%s", e->name, d, (e->attr & 0x02) ? ", hidden" : "");
        else
            usnprintf(t, sizeof(t), "%s: %s, %s%s", e->name, z, d, (e->attr & 0x02) ? ", hidden" : "");
    }
    status_line(1, t, C_VALUE);
}

static void draw_status(void)
{
    char t[300];
    if (!loaded)
        scopy(t, "reading...", sizeof(t));
    else if (volumes_view)
        usnprintf(t, sizeof(t), n_ents ? "%d volume%s on %d USB disk%s: open one (Enter, or a double-click)"
                  : "no USB disk: plug a stick in (the list follows)", n_ents, n_ents == 1 ? "" : "s", disk_count(),
                  disk_count() == 1 ? "" : "s");
    else {
        char size[24];
        if (bytes_4g)
            usnprintf(size, sizeof(size), "%u MB", bytes_4g * 4096 + (bytes >> 20));
        else
            usnprintf(size, sizeof(size), "%u bytes", bytes);
        if (n_total > (u32)n_ents)
            usnprintf(t, sizeof(t), "%d directories, %d files, %s -- the first %d of %u entries shown", dirs, files,
                      size, n_ents, n_total);
        else
            usnprintf(t, sizeof(t), "%d director%s, %d file%s, %s", dirs, dirs == 1 ? "y" : "ies", files,
                      files == 1 ? "" : "s", size);
        if (clip[0]) {
            int n = slen(t);
            usnprintf(t + n, (int)sizeof(t) - n, "   |   to %s: %s (Ins)", clip_move ? "move" : "copy", clip);
        }
    }
    status_line(0, t, C_TEXT);
    draw_selection();
    status_line(2, preview ? "a key or a click closes the preview"
                : editing && input_kind == 1 ? "the new name: Enter renames it, Esc cancels, Ctrl-U clears"
                : editing && input_kind == 2 ? "the new directory's name: Enter makes it, Esc cancels"
                : editing ? "typing a path (as for cd: 4: a disk, .. up, / the root): Enter goes there, Esc cancels, "
                            "Ctrl-U clears"
                : "Enter open  Bksp up  / path  F2 rename  F5 copy  F6 move  Ins paste  F7 new dir  Del delete  "
                  "Esc back", C_LABEL);
}

/* everything but the background */
static void draw_parts(void)
{
    gfx_target(0);
    draw_title();
    draw_path();
    draw_header();
    draw_list();
    draw_status();
}

static void draw_all(void)
{
    gfx_target(0);
    gfx_fill(0, 0, SCREEN_W, SCREEN_H, C_BACK);
    gfx_fill(0, STATUS_Y, SCREEN_W, 3, C_LINE);
    gfx_fill(0, STATUS_Y + 3, SCREEN_W, SCREEN_H - STATUS_Y - 3, C_BAR);
    draw_parts();
}

/* ---- the listing ---- */
/* a sorts before b: directories first, then by name (case aside) */
static int before(const struct disk_entry *a, const struct disk_entry *b)
{
    if (a->kind != b->kind)
        return a->kind == DISK_DIR;
    for (int i = 0;; i++) {
        u8 x = (u8)low(a->name[i]), y = (u8)low(b->name[i]);
        if (x != y)
            return x < y;
        if (!x)
            return 0;
    }
}

/* the directory `now` from `old` below it ("4:/Docs/sub" from "4:/Docs", "4:" for none from "4:/..."): the
   name to select, the one come up from */
static void child_of(const char *old, const char *now)
{
    int n = slen(now), i = 0;
    if (!n) {
        while (old[i] && old[i] != ':' && i < 9)
            i++;
        if (old[i] == ':')
            scopy(want_sel, old, i + 2);                /* "4:" */
        return;
    }
    for (; i < n; i++)
        if (old[i] != now[i])
            return;
    if (now[n - 1] != '/') {
        if (old[n] != '/')
            return;
        n++;
    }
    for (i = 0; old[n + i] && old[n + i] != '/' && i < DISK_ENTRY_NAME - 1; i++)
        want_sel[i] = old[n + i];
    want_sel[i] = 0;
}

static int wanted(const struct disk_entry *e)
{
    if (e->kind == DISK_VOLUME) {                       /* "4:" -> "4:  FAT32 ..." */
        int n = slen(want_sel);
        for (int i = 0; i < n; i++)
            if (e->name[i] != want_sel[i])
                return 0;
        return e->name[n] == ' ' || !e->name[n];        /* (a listing read again keeps the whole line) */
    }
    return same(e->name, want_sel);
}

/* the current directory (or the volumes) read again; the selection kept on the same name when it is the
   same directory, on the one come up from when it is the one above */
static u64 loaded_at;

static void load(void)
{
    loaded_at = now_ms();
    confirm = 0;                        /* ("delete X?" was asked of the listing before this one) */
    const char *now = disk_cwd();
    int same_dir = loaded && same(now, cwd_shown), keep_top = top, want_up = 0;
    if (same_dir && sel < rows && !want_forced) {
        const struct disk_entry *e = entry(sel);
        if (e)
            scopy(want_sel, e->name, sizeof(want_sel));
        else
            want_up = 1;
    } else if (!want_sel[0] && loaded) {
        child_of(cwd_shown, now);
    }
    scopy(cwd_shown, now, sizeof(cwd_shown));
    changes_seen = disk_changes();
    volumes_view = !now[0];
    has_up = !volumes_view;
    pending_open = last_click_row = -1;                 /* (a double-click meant the listing before) */
    if (preview) {                                      /* (the frame around it too) */
        preview = 0;
        gfx_fill(LIST_X, HEAD_Y, SCREEN_W - 2 * LIST_X, LIST_Y + LIST_H - HEAD_Y, C_BACK);
    }
    vol_text[0] = 0;
    n_total = 0;
    capture_begin();
    if (volumes_view) {
        n_ents = disk_volumes(ents, MAX_ENTRIES);
        n_total = (u32)n_ents;
    } else {
        n_ents = disk_dir_read("", ents, MAX_ENTRIES, &n_total);
        if (n_ents < 0)
            n_ents = 0;
        disk_cwd_volume(vol_text, sizeof(vol_text));
    }
    capture_end();
    for (int i = 0; i < n_ents; i++)
        order[i] = (u16)i;
    for (int i = 1; i < n_ents && !volumes_view; i++) {     /* (insertion sort: a few hundred at most; the
                                                               volumes stay in disk order: "10:" after "4.2:") */
        u16 o = order[i];
        int j = i;
        while (j > 0 && before(&ents[o], &ents[order[j - 1]])) {
            order[j] = order[j - 1];
            j--;
        }
        order[j] = o;
    }
    rows = has_up + n_ents;
    dirs = files = 0;
    bytes = bytes_4g = 0;
    for (int i = 0; i < n_ents; i++) {
        if (ents[i].kind == DISK_DIR)
            dirs++;
        else if (ents[i].kind == DISK_FILE) {
            files++;
            u32 was = bytes;
            bytes += ents[i].size;
            bytes_4g += (bytes < was) + ents[i].size_hi;   /* (two 3 GB videos: over 32 bits; NTFS: a 5 GB one) */
        }
    }
    sel = 0;
    if (want_sel[0] && !want_up)
        for (int i = has_up; i < rows; i++)
            if (wanted(entry(i))) {
                sel = i;
                break;
            }
    want_sel[0] = 0;
    want_forced = 0;
    top = same_dir ? keep_top : 0;
    if (sel < top)
        top = sel;
    if (sel >= top + ROWS)
        top = sel - ROWS / 2;
    top = clampi(top, 0, rows > ROWS ? rows - ROWS : 0);
    loaded = 1;
}

/* 'cd path' as the shell's; what it said into the status line: 0, -1 */
static int go(const char *path)
{
    char was[PATH_LEN + 16];
    scopy(was, disk_cwd(), sizeof(was));
    capture_begin();
    disk_cd(path);
    if (capture_end()) {
        draw_selection();
        return -1;
    }
    if (!same(was, disk_cwd()))
        prompt_stale = 1;                               /* (main.c prints the prompt again) */
    load();
    draw_parts();
    return 0;
}

static void go_up(void)
{
    if (volumes_view)
        return;
    go(at_root() ? "" : "..");                          /* (at the root: no current directory, the volumes) */
}

/* ---- the preview: a file's beginning (text, or hex) over the list ---- */
static void draw_preview(const struct disk_entry *e, u32 size, int n)
{
    int x0 = LIST_X, y0 = HEAD_Y, w = SCREEN_W - 2 * LIST_X, h = LIST_Y + LIST_H - HEAD_Y;
    int cols = (w - 32) / CELL, lines = (h - 40) / PREVIEW_LINE, ty = y0 + 34, tx = x0 + 16;
    int odd = 0;
    char t[200];
    for (int i = 0; i < n; i++)
        if (head[i] < 32 && head[i] != '\n' && head[i] != '\r' && head[i] != '\t')
            odd++;
    int binary = odd * 10 > n;
    gfx_fill(x0, y0, w, h, C_PREVIEW);
    gfx_frame(x0, y0, w, h, 2, C_LINE);
    gfx_fill(x0 + 2, y0 + 2, w - 4, 26, C_HEAD);
    char z[24];
    if (e->size_hi)                                     /* (4 GB or more: read_head's 32 bits do not tell) */
        size_text(z, sizeof(z), e, "");
    else
        usnprintf(z, sizeof(z), "%u bytes", size);
    usnprintf(t, sizeof(t), "%s  -  %s%s", e->name, z, binary ? ", its first bytes in hex"
              : size > (u32)n ? ", its beginning" : "");
    put(tx, y0 + 7, t, cols, C_TEXT, C_HEAD);
    if (binary) {
        for (int l = 0; l < lines && l * 16 < n; l++) {
            char line[80];
            int k = usnprintf(line, sizeof(line), "%04x:", l * 16);
            for (int j = l * 16; j < l * 16 + 16; j++)
                k += j < n ? usnprintf(line + k, (int)sizeof(line) - k, " %02x", head[j])
                           : usnprintf(line + k, (int)sizeof(line) - k, "   ");
            line[k++] = ' ';
            line[k++] = ' ';
            for (int j = l * 16; j < l * 16 + 16 && j < n; j++)
                line[k++] = head[j] >= 32 && head[j] < 127 ? (char)head[j] : '.';
            line[k] = 0;
            uart_rx_poll();
            put(tx, ty + l * PREVIEW_LINE, line, cols, C_TEXT, C_PREVIEW);
        }
        return;
    }
    int row = 0, col = 0;
    for (int i = 0; i < n && row < lines; i++) {
        u8 c = head[i];
        if (c == '\r')
            continue;
        if (c == '\n' || col >= cols) {
            row++;
            col = 0;
            uart_rx_poll();
            if (c == '\n' || row >= lines)
                continue;
        }
        if (c == '\t') {
            col = (col + 4) & ~3;
            continue;
        }
        if (c != ' ')
            gfx_cell(tx + col * CELL, ty + row * PREVIEW_LINE, c >= 32 && c < 127 ? (char)c : '.', C_TEXT, C_PREVIEW);
        col++;
    }
}

static void open_preview(const struct disk_entry *e)
{
    u32 size;
    capture_begin();
    int n = disk_read_head(e->name, head, HEAD_BYTES, &size);
    if (capture_end() || n < 0) {
        draw_selection();
        return;
    }
    preview = 1;
    draw_preview(e, size, n);
    draw_status();
}

static void close_preview(void)
{
    preview = 0;
    gfx_fill(LIST_X, HEAD_Y, SCREEN_W - 2 * LIST_X, LIST_Y + LIST_H - HEAD_Y, C_BACK);
    draw_header();
    draw_list();
    draw_status();
}

static int ends_nes(const char *s)
{
    int n = 0;
    while (s[n])
        n++;
    return n > 4 && s[n - 4] == '.' && (s[n - 3] | 32) == 'n' && (s[n - 2] | 32) == 'e' && (s[n - 1] | 32) == 's';
}

static int ends_gb(const char *s)        /* .gb, and .gbc (the Game Boy Color's) */
{
    int n = 0;
    while (s[n])
        n++;
    if (n > 4 && s[n - 4] == '.' && (s[n - 3] | 32) == 'g' && (s[n - 2] | 32) == 'b' && (s[n - 1] | 32) == 'c')
        return 1;
    return n > 3 && s[n - 3] == '.' && (s[n - 2] | 32) == 'g' && (s[n - 1] | 32) == 'b';
}

typedef int (*player_fn)(const char *, u32, const char *);
static player_fn player_for(const char *s, int on_disk);

/* the name of the game in a .zip / .gz / .adz: a .gz's own (kept in its header), else its file's name without
   .gz (.adz: .adf); a .zip's first member when a player knows it, else the member the player would unpack (the
   whole archive read for that).  1, or 0: none */
static int archive_name(const char *s, char *inner, int max)
{
    u32 size = 0;
    int got = disk_read_head(s, head, HEAD_BYTES, &size);
    if (got <= 0)
        return 0;
    if (gz_is(head, (u32)got)) {
        if (gz_name(head, (u32)got, inner, max))
            return 1;
        int n = 0, dot = -1;
        for (; s[n] && n < max - 5; n++) {
            inner[n] = s[n];
            if (s[n] == '.')
                dot = n;
            else if (s[n] == '/' || s[n] == ':')
                dot = -1;
        }
        inner[n] = 0;
        if (dot > 0 && (inner[dot + 1] | 32) == 'a' && (inner[dot + 2] | 32) == 'd' && (inner[dot + 3] | 32) == 'z')
            inner[dot + 3] = 'f';
        else if (dot > 0)
            inner[dot] = 0;
        return 1;
    }
    if (!zip_is(head, (u32)got))
        return 0;
    if (!zip_first_name(head, (u32)got, inner, max) && player_for(inner, 0))
        return 1;
    if (size > MEDIA_MAX)
        return 0;
    u8 *all = (u8 *)KSEG0(MEDIA_PHYS);
    got = disk_read_head(s, all, MEDIA_MAX, &size);
    return got > 0 && !zip_pick_name(all, (u32)got, inner, max);
}

/* a game file (NES, Game Boy, Master System / Game Gear / SG-1000, Spectrum, Atari 2600, C64, Amiga, DOS, Mega
   Drive): which player (0: none).  A .bin is the Mega Drive's only when its beginning says it is one of its
   cartridges; a .zip / .gz / .adz goes to the player of the game in it.  on_disk 0: s is only a name (a game's
   in an archive): nothing read */
static player_fn player_for(const char *s, int on_disk)
{
    int n = 0, dot = -1;
    for (; s[n]; n++)
        if (s[n] == '.')
            dot = n;
    if (dot < 0)
        return 0;
    if (n - dot == 6 && (s[dot + 1] | 32) == 'p' && (s[dot + 2] | 32) == 's' && (s[dot + 3] | 32) == 'e' &&
        (s[dot + 4] | 32) == 'x' && (s[dot + 5] | 32) == 'e')
        return psx_play;
    if (n - dot == 7 && (s[dot + 1] | 32) == 'p' && (s[dot + 2] | 32) == 's' && s[dot + 3] == '-' &&
        (s[dot + 4] | 32) == 'e' && (s[dot + 5] | 32) == 'x' && (s[dot + 6] | 32) == 'e')
        return psx_play;
    if (n - dot == 5 && (s[dot + 1] | 32) == 'c' && (s[dot + 2] | 32) == 'p' && (s[dot + 3] | 32) == 's' &&
        (s[dot + 4] == '1' || s[dot + 4] == '2'))
        return cps_play;
    if (n - dot == 5 && (s[dot + 1] | 32) == 'd' && (s[dot + 2] | 32) == 'u' && (s[dot + 3] | 32) == 'c' &&
        (s[dot + 4] | 32) == 'k')
        return megaduck_play;
    if (n - dot > 4)
        return 0;
    char e[4] = {0, 0, 0, 0};
    for (int i = 0; dot + 1 + i < n; i++)
        e[i] = (char)(s[dot + 1 + i] | 32);
    if (ends_nes(s))
        return nes_play;
    if (ends_gb(s))
        return gb_play;
    int zip = e[0] == 'z' && e[1] == 'i' && e[2] == 'p' && !e[3];
    int adz = e[0] == 'a' && e[1] == 'd' && e[2] == 'z' && !e[3];
    int gz = e[0] == 'g' && e[1] == 'z' && !e[2];
    if (on_disk && (zip || adz || gz)) {
        char inner[96];
        player_fn pf = archive_name(s, inner, sizeof(inner)) ? player_for(inner, 0) : 0;
        if (pf)
            return pf;
        if (zip) {
            u32 size = 0;
            u8 *all = (u8 *)KSEG0(MEDIA_PHYS);
            int got = disk_read_head(s, all, MEDIA_MAX, &size);
            if (got > 0 && size <= MEDIA_MAX && cps_is_rom(all, (u32)got, s))
                return cps_play;
            if (got > 0 && size <= MEDIA_MAX && s16_is_zip(all, (u32)got))
                return s16_play;
        }
        return 0;
    }
    if (e[0] == 'c' && e[1] == 'p' && e[2] == 's' && !e[3])
        return cps_play;
    if (e[0] == 's' && e[1] == '1' && e[2] == '6' && !e[3])
        return s16_play;
    if (e[0] == 's' && e[1] == 'm' && e[2] == 's' && !e[3])
        return sms_play;
    if (e[0] == 'g' && e[1] == 'g' && !e[2])
        return gg_play;
    if (e[0] == 's' && (e[1] == 'g' || e[1] == 'c') && !e[2])
        return sg_play;
    if (e[0] == 'a' && e[1] == '2' && e[2] == '6' && !e[3])
        return a26_play;
    if ((e[0] == 's' && e[1] == 'n' && e[2] == 'a') || (e[0] == 'z' && e[1] == '8' && e[2] == '0') ||
        (e[0] == 't' && e[1] == 'a' && e[2] == 'p') || (e[0] == 't' && e[1] == 'z' && e[2] == 'x') ||
        (e[0] == 't' && e[1] == 'r' && e[2] == 'd') || (e[0] == 's' && e[1] == 'c' && e[2] == 'l'))
        return e[3] ? 0 : zx_play;
    if ((e[0] == 's' && e[1] == 't' && !e[2]) ||
        (((e[0] == 'm' && e[1] == 's' && e[2] == 'a') ||
          (e[0] == 's' && e[1] == 't' && e[2] == 'x') ||
          (e[0] == 't' && e[1] == 'o' && e[2] == 's')) && !e[3]))
        return st_play;
    if (e[0] == 'p' && e[1] == 'r' && e[2] == 'g' && !e[3]) {
        if (on_disk) {
            u32 size = 0;
            int got = disk_read_head(s, head, HEAD_BYTES, &size);
            if (got >= 2 && head[0] == 0x60 && head[1] == 0x1A)
                return st_play;
        }
        return c64_play;
    }
    if ((e[0] == 't' && e[1] == '6' && e[2] == '4') ||
        (e[0] == 'd' && e[1] == '6' && e[2] == '4') || (e[0] == 'p' && e[1] == '0' && e[2] == '0') ||
        (e[0] == 'c' && e[1] == 'r' && e[2] == 't'))
        return e[3] ? 0 : c64_play;
    if (e[0] == 'a' && e[1] == 'd' && e[2] == 'f' && !e[3])
        return amiga_play;
    if (e[0] == 'e' && e[1] == 'x' && e[2] == 'e' && !e[3]) {
        if (on_disk) {
            u32 size = 0;
            int got = disk_read_head(s, head, HEAD_BYTES, &size);
            if (got >= 8 && psx_is_exe(head, (u32)got))
                return psx_play;
            if (got >= 7 && a8_is_xex(head, (u32)got))
                return a8_play;
        }
        return dos_play;
    }
    if (e[0] == 'c' && e[1] == 'o' && e[2] == 'm' && !e[3]) {
        if (on_disk) {
            u32 size = 0;
            int got = disk_read_head(s, head, HEAD_BYTES, &size);
            if (got >= 7 && a8_is_xex(head, (u32)got))
                return a8_play;
        }
        return dos_play;
    }
    if (((e[0] == 'a' && e[1] == 't' && e[2] == 'r') ||
         (e[0] == 'x' && e[1] == 'e' && e[2] == 'x') ||
         (e[0] == 'o' && e[1] == 'b' && e[2] == 'x')) && !e[3])
        return a8_play;
    if (e[0] == 'a' && e[1] == '5' && e[2] == '2' && !e[3])
        return a52_play;
    if (e[0] == 'c' && e[1] == 'a' && e[2] == 'r' && !e[3]) {
        if (on_disk) {
            u32 size = 0;
            int got = disk_read_head(s, head, HEAD_BYTES, &size);
            int is_52 = 0;
            if (got >= 16 && a8_is_car(head, (u32)got, &is_52))
                return is_52 ? a52_play : a8_play;
        }
        return a8_play;
    }
    if (((e[0] == 'c' && e[1] == 'u' && e[2] == 'e') || (e[0] == 'i' && e[1] == 's' && e[2] == 'o') ||
         (e[0] == 'p' && e[1] == 's' && e[2] == 'x')) && !e[3])
        return psx_play;
    if (((e[0] == 'm' && e[1] == 'd' && !e[2]) || (e[0] == 'g' && e[1] == 'e' && e[2] == 'n') ||
         (e[0] == 's' && e[1] == 'm' && e[2] == 'd')) && !e[3])
        return md_play;
    if (e[0] == 'm' && e[1] == 'd' && (e[2] == '1' || e[2] == '2') && !e[3])
        return megaduck_play;
    if (e[0] == 's' && e[1] == 'v' && !e[2])
        return sv_play;
    if (((e[0] == 'c' && e[1] == 'h' && e[2] == '8') ||
         (e[0] == 's' && e[1] == 'c' && (e[2] == '8' || e[2] == 'h')) ||
         (e[0] == 'x' && e[1] == 'o' && e[2] == '8')) && !e[3])
        return chip8_play;
    if (e[0] == 'c' && e[1] == 'h' && e[2] == 'f' && !e[3])
        return channelf_play;
    if (e[0] == 'm' && e[1] == 'i' && e[2] == 'n' && !e[3]) {
        const char *bn = s;
        for (const char *q = s; *q; q++)
            if (*q == '/' || *q == '\\' || *q == ':')
                bn = q + 1;
        if ((bn[0] | 32) == 'b' && (bn[1] | 32) == 'i' && (bn[2] | 32) == 'o' && (bn[3] | 32) == 's' && bn[4] == '.')
            return 0;
        return pokemini_play;
    }
    if (e[0] == 'p' && e[1] == 'c' && e[2] == 'e' && !e[3])
        return pce_play;
    if (e[0] == 'c' && e[1] == 'o' && e[2] == 'l' && !e[3])
        return col_play;
    if (e[0] == 'm' && e[1] == 'x' && e[2] == '1' && !e[3])
        return msx_play;
    if (((e[0] == 'm' && e[1] == 'x' && e[2] == '2') || (e[0] == 'd' && e[1] == 's' && e[2] == 'k')) && !e[3])
        return msx2_play;
    if (e[0] == 'w' && e[1] == 's' && (!e[2] || (e[2] == 'c' && !e[3])))
        return ws_play;
    if (e[0] == 's' && (e[1] == 'f' || e[1] == 'm') && e[2] == 'c' && !e[3])
        return snes_play;
    if (e[0] == 'n' && e[1] == 'e' && e[2] == 'o' && !e[3])
        return neo_play;
    if (e[0] == 'g' && e[1] == 'b' && e[2] == 'a' && !e[3])
        return gba_play;
    if (e[0] == 'a' && e[1] == '7' && e[2] == '8' && !e[3])
        return a78_play;
    if (e[0] == 'l' && (e[1] == 'n' || e[1] == 'y') && e[2] == 'x' && !e[3])
        return lnx_play;
    if (e[0] == 'v' && e[1] == 'e' && e[2] == 'c' && !e[3])
        return vec_play;
    if (e[0] == 'f' && e[1] == 'd' && e[2] == 's' && !e[3])
        return fds_play;
    if (e[0] == 'n' && e[1] == 'g' && (e[2] == 'p' || e[2] == 'c') && !e[3])
        return ngp_play;
    if (e[0] == 'o' && e[1] == '2' && !e[2])
        return o2_play;
    if (e[0] == 'i' && e[1] == 'n' && e[2] == 't' && !e[3])
        return intv_play;
    if (on_disk && e[0] == 'r' && e[1] == 'o' && e[2] == 'm' && !e[3]) {
        u32 size = 0;
        int got = disk_read_head(s, head, HEAD_BYTES, &size);
        if (got >= 2 && ((head[0] == 0x55 && head[1] == 0xAA) || (head[0] == 0xAA && head[1] == 0x55)))
            return col_play;
        if (got > 0 && intv_is_rom(head, (u32)got, size))
            return intv_play;
        if (got > 0 && msx_is_cart(head, (u32)got, size)) {
            const char *cwd = disk_cwd();
            for (const char *q = cwd; *q; q++)
                if ((q[0] | 32) == 'm' && (q[1] | 32) == 's' && (q[2] | 32) == 'x' && q[3] == '2')
                    return msx2_play;
            for (const char *q = s; *q; q++)
                if ((q[0] | 32) == 'm' && (q[1] | 32) == 's' && (q[2] | 32) == 'x' && q[3] == '2')
                    return msx2_play;
            return msx_play;
        }
        /* Atari 800XL/130XE & 5200 raw .rom cartridges inside atari8/ or a5200/ (excluding system BIOS ROMs) */
        const char *bn = s;
        for (const char *q = s; *q; q++)
            if (*q == '/' || *q == '\\' || *q == ':')
                bn = q + 1;
        int is_sys = ((bn[0] | 32) == 'a' && (bn[1] | 32) == 't' && (bn[2] | 32) == 'a' && (bn[3] | 32) == 'r' &&
                      (bn[4] | 32) == 'i' && ((bn[5] | 32) == 'x' || (bn[5] | 32) == 'b')) ||
                     (bn[0] == '5' && bn[1] == '2' && bn[2] == '0' && bn[3] == '0' && bn[4] == '.');
        if (!is_sys) {
            const char *cwd = disk_cwd();
            for (const char *q = cwd; *q; q++) {
                if ((q[0] | 32) == 'a' && q[1] == '5' && q[2] == '2' && q[3] == '0' && q[4] == '0')
                    return a52_play;
                if ((q[0] | 32) == 'a' && (q[1] | 32) == 't' && (q[2] | 32) == 'a' && (q[3] | 32) == 'r' &&
                    (q[4] | 32) == 'i' && q[5] == '8')
                    return a8_play;
            }
            for (const char *q = s; *q; q++) {
                if ((q[0] | 32) == 'a' && q[1] == '5' && q[2] == '2' && q[3] == '0' && q[4] == '0')
                    return a52_play;
                if ((q[0] | 32) == 'a' && (q[1] | 32) == 't' && (q[2] | 32) == 'a' && (q[3] | 32) == 'r' &&
                    (q[4] | 32) == 'i' && q[5] == '8')
                    return a8_play;
            }
        }
        return 0;
    }
    if (on_disk && e[0] == 'b' && e[1] == 'i' && e[2] == 'n' && !e[3]) {
        u32 size = 0;
        int got = disk_read_head(s, head, HEAD_BYTES, &size);
        if (got > 0 && md_cartridge(head, (u32)got, size))
            return md_play;
        if (got >= 16 && size >= 18u * 2352u && head[0] == 0x00 && head[1] == 0xFF && head[2] == 0xFF &&
            head[3] == 0xFF && head[10] == 0xFF && head[11] == 0x00 && (head[15] == 1 || head[15] == 2))
            return psx_play;
        const char *cwd = disk_cwd();
        for (const char *q = cwd; *q; q++)
            if ((q[0] | 32) == 'm' && (q[1] | 32) == 'e' && (q[2] | 32) == 'g' && (q[3] | 32) == 'a' &&
                (q[4] | 32) == 'd' && (q[5] | 32) == 'u')
                return megaduck_play;
        for (const char *q = s; *q; q++)
            if ((q[0] | 32) == 'm' && (q[1] | 32) == 'e' && (q[2] | 32) == 'g' && (q[3] | 32) == 'a' &&
                (q[4] | 32) == 'd' && (q[5] | 32) == 'u')
                return megaduck_play;
        return 0;
    }
    return 0;
}

static void open_row(int i)
{
    if (i < 0 || i >= rows)
        return;
    const struct disk_entry *e = entry(i);
    int video = 0;
    player_fn play = 0;
    if (!e) {
        go_up();
    } else if (e->kind == DISK_VOLUME) {
        char name[12];
        int k = 0;
        while (e->name[k] && e->name[k] != ':' && k < 9) {
            name[k] = e->name[k];
            k++;
        }
        name[k++] = ':';
        name[k] = 0;
        go(name);
    } else if (e->kind == DISK_DIR) {
        go(e->name);
    } else if (view_is_picture(e->name) || (video = av_is_video(e->name)) != 0 ||
               (play = player_for(e->name, 1)) != 0) {  /* (asked once: for a game in an archive player_for
                                                           reads the archive -- three askings were three reads,
                                                           and one that failed the third time called nothing) */
        char name[DISK_ENTRY_NAME];                     /* a picture, a game or a video: on the whole TV, then back */
        scopy(name, e->name, sizeof(name));
        on = 0;
        if (video) {
            static char word[] = "play";
            char *argv[2] = {word, name};
            (void)av_play(2, argv);
        } else if (play) {
            (void)play(name, 0, "");
        } else {
            view_file(name, 0);
            const char *last = view_last(), *b = last;          /* (the picture it ended on: selected) */
            for (const char *q = last; *q; q++)
                if (*q == '/' || *q == '\\' || *q == ':')
                    b = q + 1;
            if (*b)
                scopy(name, b, sizeof(name));
        }
        explorer_show();
        scopy(want_sel, name, sizeof(want_sel));
    } else {
        open_preview(e);
    }
}

/* ---- selection, scrolling ---- */
static void select_row(int i)
{
    if (!rows)
        return;
    i = clampi(i, 0, rows - 1);
    int old = sel, old_top = top;
    sel = i;
    if (sel < top)
        top = sel;
    else if (sel >= top + ROWS)
        top = sel - ROWS + 1;
    if (top != old_top) {
        draw_list();
    } else if (old != sel) {
        draw_row(old - top);
        draw_row(sel - top);
    }
    draw_selection();
}

static void scroll(int by)
{
    int t = clampi(top + by, 0, rows > ROWS ? rows - ROWS : 0);
    if (t != top) {
        top = t;
        draw_list();
    }
}

/* the next name after the selected one that starts with c */
static void jump_to(char c)
{
    c = low(c);
    for (int k = 1; k <= rows; k++) {
        int i = (sel + k) % rows;
        const struct disk_entry *e = entry(i);
        if (e && low(e->name[0]) == c) {
            select_row(i);
            return;
        }
    }
}

/* ---- writing: rename, a new directory, delete, copy / move and paste (disk.c's commands: FAT, and NTFS
   when its journal is clean -- else each says read-only and why, and that goes into the status line as any
   error) ---- */
static void say(const char *s)                  /* a line in the status line, in the error's place */
{
    scopy(status_msg, s, sizeof(status_msg));
    draw_selection();
}

/* the shown directory's entry `name` with its whole path: "4:/DIR/name" */
static void full_path(char *out, int size, const char *name)
{
    int n = slen(cwd_shown);
    usnprintf(out, size, "%s%s%s", cwd_shown, n && cwd_shown[n - 1] == '/' ? "" : "/", name);
}

/* after capture_begin and a disk.c command: what it printed (an error) into the status line: 0 none, -1 */
static int did(void)
{
    if (capture_end()) {
        draw_selection();
        return -1;
    }
    return 0;
}

static void reload_selecting(const char *name)
{
    scopy(want_sel, name, sizeof(want_sel));
    want_forced = 1;
    load();
    draw_parts();
}

static int plain_name(const char *s)            /* a name, not a path */
{
    if (!s[0]) {
        say("an empty name");
        return 0;
    }
    for (; *s; s++)
        if (*s == '/' || *s == '\\' || *s == ':') {
            say("a name has no '/', '\\' or ':' in it");
            return 0;
        }
    return 1;
}

/* the path bar takes a name: F2 the selected entry's new one (1), F7 a new directory's (2) */
static void start_input(int kind)
{
    const struct disk_entry *e = entry(sel);
    if (volumes_view) {
        say("open a volume first (Enter)");
        return;
    }
    if (kind == 1 && (!e || e->kind == DISK_VOLUME)) {
        say("F2 renames the selected file or directory");
        return;
    }
    scopy(input_from, kind == 1 ? e->name : "", sizeof(input_from));
    scopy(edit, input_from, sizeof(edit));
    input_kind = kind;
    editing = 1;
    edit_len = slen(edit);
    caret = edit_len;
    draw_path();
    draw_status();
}

static int rename_to(const char *name)
{
    if (!plain_name(name))
        return -1;
    if (same(name, input_from)) {
        draw_parts();
        return 0;
    }
    char from[sizeof(clip)], to[sizeof(clip)];
    full_path(from, sizeof(from), input_from);
    full_path(to, sizeof(to), name);
    status_line(1, "renaming...", C_VALUE);
    capture_begin();
    disk_mv(from, to);
    if (did() < 0)
        return -1;
    if (same(clip, from))
        scopy(clip, to, sizeof(clip));          /* (the clipboard follows it) */
    reload_selecting(name);
    return 0;
}

static int make_dir(const char *name)
{
    if (!plain_name(name))
        return -1;
    char p[sizeof(clip)];
    full_path(p, sizeof(p), name);
    capture_begin();
    disk_mkdir(p);
    if (did() < 0)
        return -1;
    reload_selecting(name);
    return 0;
}

static void ask_delete(void)
{
    const struct disk_entry *e = entry(sel);
    if (!e || e->kind == DISK_VOLUME) {
        say("Delete removes the selected file or (empty) directory");
        return;
    }
    char t[200];
    usnprintf(t, sizeof(t), "delete %s%s?   y: yes   another key: no", e->kind == DISK_DIR ? "the directory " : "",
              e->name);
    confirm = 1;
    status_line(1, t, C_FOCUS);
}

static void do_delete(void)
{
    const struct disk_entry *e = entry(sel), *next = entry(sel + 1 < rows ? sel + 1 : sel - 1);
    if (!e)
        return;
    char p[sizeof(clip)], keep[DISK_ENTRY_NAME];
    full_path(p, sizeof(p), e->name);
    scopy(keep, next ? next->name : "", sizeof(keep));      /* (the next entry selected after it) */
    status_line(1, "deleting...", C_VALUE);
    capture_begin();
    if (e->kind == DISK_DIR)
        disk_rmdir(p);
    else
        disk_rm(p);
    if (did() < 0)
        return;
    if (same(clip, p))
        clip[0] = 0;
    reload_selecting(keep);
}

static void to_clip(int move)
{
    const struct disk_entry *e = entry(sel);
    if (!e || e->kind != DISK_FILE) {
        say("F5 / F6 take the selected file (cp and mv move files)");
        return;
    }
    full_path(clip, sizeof(clip), e->name);
    clip_move = move;
    draw_status();
}

/* the clipboard's file into the shown directory: copied (onto any volume) or moved (on the same one) */
static void paste(void)
{
    if (!clip[0]) {
        say("nothing to paste: F5 marks a file to copy, F6 one to move");
        return;
    }
    if (volumes_view) {
        say("open a directory to paste into first");
        return;
    }
    const char *name = clip + slen(clip);
    while (name > clip && name[-1] != '/')
        name--;
    char keep[DISK_ENTRY_NAME];
    scopy(keep, name, sizeof(keep));
    status_line(1, clip_move ? "moving..." : "copying...", C_VALUE);
    capture_begin();
    if (clip_move)
        disk_mv(clip, cwd_shown);
    else
        disk_cp(clip, cwd_shown);
    if (did() < 0)
        return;
    if (clip_move)
        clip[0] = 0;
    reload_selecting(keep);
}

/* ---- the path bar ---- */
static void start_edit(int slash)
{
    input_kind = 0;
    editing = 1;
    scopy(edit, cwd_shown, sizeof(edit));
    edit_len = slen(edit);
    if (slash && edit_len < (int)sizeof(edit) - 1 && (!edit_len || edit[edit_len - 1] != '/')) {
        edit[edit_len++] = '/';
        edit[edit_len] = 0;
    }
    caret = edit_len;
    draw_path();
    draw_status();
}

static void stop_edit(void)
{
    editing = 0;
    draw_path();
    draw_status();
}

static void edit_key(int k)
{
    switch (k) {
    case '\r':
    case '\n': {
        char text[sizeof(edit)];
        scopy(text, edit, sizeof(text));
        int kind = input_kind;
        editing = 0;
        input_kind = 0;
        if ((kind == 1 ? rename_to(text) : kind == 2 ? make_dir(text) : go(text)) < 0) {
            editing = 1;                                /* (the text kept, to be put right) */
            input_kind = kind;
            draw_path();
            draw_status();
        }
        return;
    }
    case K_ESC:
        input_kind = 0;
        stop_edit();
        return;
    case 0x08:
    case 0x7f:
        if (caret > 0) {
            for (int i = caret - 1; i < edit_len; i++)
                edit[i] = edit[i + 1];
            edit_len--;
            caret--;
        }
        break;
    case K_DEL:
        if (caret < edit_len) {
            for (int i = caret; i < edit_len; i++)
                edit[i] = edit[i + 1];
            edit_len--;
        }
        break;
    case K_LEFT:
        caret = clampi(caret - 1, 0, edit_len);
        break;
    case K_RIGHT:
        caret = clampi(caret + 1, 0, edit_len);
        break;
    case K_HOME:
        caret = 0;
        break;
    case K_END:
        caret = edit_len;
        break;
    case 0x15:                                          /* Ctrl-U */
        edit_len = caret = 0;
        edit[0] = 0;
        break;
    default:
        if (k < 0x20 || k > 0x7e || edit_len >= (int)sizeof(edit) - 1)
            return;
        for (int i = edit_len; i >= caret; i--)
            edit[i + 1] = edit[i];
        edit[caret++] = (char)k;
        edit_len++;
    }
    draw_path();
}

/* ---- input ---- */
/* the listing no longer the shell's: a cd typed on the UART, a disk written, plugged in or out (in the main loop
   the keys come before explorer_poll and the hubs' poll: a key right after an unplug would act on the old rows,
   and cd into another disk's directory of the same name) */
static int stale(void)
{
    if (!loaded || !same(disk_cwd(), cwd_shown))
        return 1;
    /* (a disk written: listed again a second after the last time at the soonest -- an FTP upload writes a
       sector every few passes, and each listing read the directory and drew it all again) */
    return disk_changes() != changes_seen && now_ms() - loaded_at >= 1000;
}

static int ensure_loaded(void)          /* 1: listed again now (a key meant for the old listing is dropped) */
{
    if (!stale())
        return 0;
    load();
    draw_parts();
    return 1;
}

static void leave(void)
{
    on = editing = preview = 0;
    gfx_view(1);                                        /* (main.c's show_console) */
    console_redraw();
}

static void key(int k)
{
    if (ensure_loaded())
        return;
    if (preview) {                                      /* any key closes it */
        close_preview();
        return;
    }
    if (confirm) {                                      /* "delete X?": y deletes, any other key does not */
        confirm = 0;
        if (k == 'y' || k == 'Y')
            do_delete();
        else
            draw_selection();
        return;
    }
    if (status_msg[0]) {
        status_msg[0] = 0;
        draw_selection();
    }
    if (editing) {
        edit_key(k);
        return;
    }
    switch (k) {
    case K_F2: start_input(1); return;
    case K_F7: start_input(2); return;
    case K_F5: to_clip(0); return;
    case K_F6: to_clip(1); return;
    case K_F8:
    case K_DEL: ask_delete(); return;
    case K_INS:
    case 0x16: paste(); return;                         /* (Insert, or Ctrl-V) */
    case K_UP: select_row(sel - 1); return;
    case K_DOWN: select_row(sel + 1); return;
    case K_PGUP: select_row(sel - (ROWS - 1)); return;
    case K_PGDN: select_row(sel + (ROWS - 1)); return;
    case K_HOME: select_row(0); return;
    case K_END: select_row(rows - 1); return;
    case '\r':
    case '\n':
    case K_RIGHT: open_row(sel); return;
    case 0x08:
    case 0x7f:
    case K_LEFT: go_up(); return;
    case K_ESC: leave(); return;
    case '\t': start_edit(0); return;
    case '/': start_edit(1); return;
    case 0x12:                                          /* Ctrl-R: read again */
        load();
        draw_parts();
        return;
    }
    if (k > 0x20 && k <= 0x7e)
        jump_to((char)k);
}

void explorer_key(int c)
{
    if (esc == 1) {
        if (c == '[' || c == 'O') {
            esc = 2;
            esc_arg = 0;
            return;
        }
        esc = 0;
        key(K_ESC);                                     /* (a lone ESC: from a terminal, not a USB keyboard) */
    } else if (esc == 2) {
        if (c >= '0' && c <= '9') {
            esc_arg = esc_arg * 10 + (c - '0');
            if (esc_arg > 99)
                esc_arg = 99;
            return;
        }
        if (c == ';')
            return;
        esc = 0;
        switch (c) {
        case 'A': key(K_UP); return;
        case 'B': key(K_DOWN); return;
        case 'C': key(K_RIGHT); return;
        case 'D': key(K_LEFT); return;
        case 'H': key(K_HOME); return;
        case 'F': key(K_END); return;
        case '~':
            key(esc_arg == 1 || esc_arg == 7 ? K_HOME : esc_arg == 4 || esc_arg == 8 ? K_END : esc_arg == 5 ? K_PGUP
                : esc_arg == 6 ? K_PGDN : esc_arg == 3 ? K_DEL : esc_arg == 2 ? K_INS : esc_arg == 12 ? K_F2
                : esc_arg == 15 ? K_F5 : esc_arg == 17 ? K_F6 : esc_arg == 18 ? K_F7 : esc_arg == 19 ? K_F8 : 0);
            return;
        }
        return;
    }
    if (c == 0x1b) {
        esc = 1;
        return;
    }
    key(c);
}

void explorer_mouse(int x, int y, u8 buttons, int wheel)
{
    u8 down = (u8)(buttons & ~mouse_buttons);
    mouse_buttons = buttons;                            /* (followed while hidden too: a button held when it
                                                           closed would cost the first click after) */
    if (!on || gfx_view_console())
        return;
    ensure_loaded();
    if (confirm && (wheel || (down & 1))) {
        confirm = 0;                    /* ("delete X?" stayed armed while a click selected another entry: 'y'
                                           then deleted that one, never asked about) */
        draw_selection();
    }
    if (wheel && !preview)
        scroll(-3 * wheel);                             /* (away from you: up) */
    if (!(down & 1))
        return;
    if (preview) {
        close_preview();
        return;
    }
    if (status_msg[0]) {
        status_msg[0] = 0;
        draw_selection();
    }
    if (x >= PATH_X && x < PATH_X + PATH_W && y >= PATH_Y && y < PATH_Y + PATH_H) {
        if (!editing)
            start_edit(0);
        caret = clampi((x - PATH_TX + CELL / 2) / CELL, 0, edit_len);
        draw_path();
        return;
    }
    if (editing)
        stop_edit();
    if (y < LIST_Y || y >= LIST_Y + LIST_H)
        return;
    if (x >= BAR_X - 2) {                               /* the scroll bar: a page up or down */
        int h = rows > ROWS ? clampi(LIST_H * ROWS / rows, 16, LIST_H) : LIST_H;
        int thumb = rows > ROWS ? LIST_Y + (LIST_H - h) * top / (rows - ROWS) : LIST_Y;
        scroll(y < thumb ? -(ROWS - 1) : y >= thumb + h ? ROWS - 1 : 0);
        return;
    }
    int i = top + (y - LIST_Y) / ROW_H;
    if (i >= rows)
        return;
    u64 now = now_ms();
    if (i == last_click_row && now - last_click_ms <= DOUBLE_MS) {
        pending_open = i;                               /* (opened from the main loop, not inside a report) */
        last_click_row = -1;
    } else {
        last_click_row = i;
        last_click_ms = now;
    }
    select_row(i);
}

/* ---- from main.c ---- */
void explorer_show(void)
{
    on = 1;
    loaded = 0;
    editing = preview = 0;
    confirm = 0;
    esc = 0;
    pending_open = last_click_row = -1;
    status_msg[0] = 0;
    want_sel[0] = 0;
    rows = n_ents = 0;
    sel = top = 0;
    has_up = 0;
    scopy(cwd_shown, disk_cwd(), sizeof(cwd_shown));
    volumes_view = !cwd_shown[0];
    disk_cwd_volume(vol_text, sizeof(vol_text));
    draw_all();                                         /* the frame; the listing on the next poll */
    gfx_view(0);
}

void explorer_hide(void)
{
    on = editing = preview = 0;
}

int explorer_shown(void)
{
    return on && !gfx_view_console();
}

int explorer_poll(void)
{
    if (!on)
        return 0;
    if (gfx_view_console()) {                           /* ('console', a key on the test screen...) */
        on = editing = preview = 0;
    } else if (!ensure_loaded() && pending_open >= 0) {     /* (listed again: the double-click meant the old) */
        int i = pending_open;
        pending_open = -1;
        open_row(i);
    }
    int r = prompt_stale;
    prompt_stale = 0;
    return r;
}
