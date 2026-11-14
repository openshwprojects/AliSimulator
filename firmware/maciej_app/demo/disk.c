/* USB mass storage: the sectors of a stick, a card reader's card or a USB
   disk -- the bulk-only transport (a 31-byte command block wrapper out
   through the controller's endpoint A, the data and the 13-byte status
   wrapper in through endpoint B) with SCSI commands (INQUIRY, TEST UNIT
   READY, REQUEST SENSE, READ CAPACITY(10), READ(10), WRITE(10)) -- and the
   FAT file systems on them: FAT12, FAT16 and FAT32 with long file names,
   read and written.  Partitions come from an MBR (its four primary entries)
   or a GPT; NTFS and exFAT are recognised but not read.

   usb.c hands over every device with a bulk-only SCSI interface
   (disk_attach), and the commands use them: 'disks', 'ls', 'cd', 'cat',
   'sector', 'mkdir', 'rmdir', 'rm', 'touch', 'cp', 'mv', 'command > file'.
   A disk is named by its USB device address, as lsusb lists it: 'ls 4:/docs'
   (and '4.2:' for its second partition); without one the first FAT volume
   found is used.  Only the device's first logical unit is read. */
#include "hw.h"

#define DISKS      4
#define VOLUMES    4
#define SECTOR     512
#define NAME_MAX   128
#define PATH_MAX   96

#define FS_NONE    0
#define FS_FAT     1
#define FS_NTFS    2
#define FS_EXFAT   3
#define FS_OTHER   4

struct volume {
    u32 start, sectors;                 /* the partition's first sector and its length */
    u8 number;                          /* its number in the partition table (0: no table, the whole disk) */
    u8 fs;                              /* FS_* */
    u8 part_type;                       /* the MBR's type byte (0: GPT, or no table) */
    u8 fat;                             /* 12, 16 or 32 */
    u8 spc;                             /* sectors per cluster */
    u32 fat_start;                      /* the first FAT's first sector */
    u32 root_start, root_sectors;       /* FAT12 / FAT16: the root directory's fixed place */
    u32 root_cluster;                   /* FAT32: the root directory's first cluster */
    u32 data_start;                     /* the first sector of cluster 2 */
    u32 clusters;                       /* the data clusters: 2 .. clusters + 1 */
    u8 fats;                            /* the copies of the FAT (all of them written) */
    u32 fat_size;                       /* sectors each */
    u32 fsinfo;                         /* FAT32: the FSInfo sector (0: none) */
    u32 alloc_hint;                     /* where the search for a free cluster starts */
    u8 written;                         /* (written since it was mounted: the FSInfo counts made unknown) */
    char label[12];
};

struct disk {
    u8 used, device, iface, in_ep, out_ep;
    u16 maxp;
    u8 ready;                           /* its medium answered READ CAPACITY */
    u8 volumes;
    u32 tag;
    u32 blocks, block_size;
    u32 lost;                           /* commands it did not answer in time, sent again */
    u8 wp;                              /* MODE SENSE's word: 0 not asked, 1 writable, 2 write-protected */
    char name[32];                      /* INQUIRY's vendor, product, revision */
    const char *problem;                /* why it is not ready */
    struct volume vol[VOLUMES];
};

/* GCC calls these for structure copies; there is no C library */
void *memcpy(void *to, const void *from, unsigned n) __attribute__((optimize("no-tree-loop-distribute-patterns")));
void *memcpy(void *to, const void *from, unsigned n)
{
    u8 *d = to;
    const u8 *s = from;
    while (n--)
        *d++ = *s++;
    return to;
}

void *memset(void *to, int c, unsigned n) __attribute__((optimize("no-tree-loop-distribute-patterns")));
void *memset(void *to, int c, unsigned n)
{
    u8 *d = to;
    while (n--)
        *d++ = (u8)c;
    return to;
}

static struct disk disks[DISKS];

/* the current directory ('cd') */
static struct {
    struct disk *k;                     /* 0: none chosen */
    struct volume *v;
    u32 cluster;                        /* the directory (0: the root) */
    char path[PATH_MAX];                /* "/Docs/sub" ("/" the root) */
} cwd;
static char cwd_text[PATH_MAX + 8];     /* "3:/Docs/sub" ("3.2:/..." on a disk's second FAT volume) */

static u8 sector[SECTOR];               /* the sector being looked at */
static u8 fat_cache[SECTOR];            /* one sector of a FAT */
static const struct disk *fat_cache_disk;
static u32 fat_cache_lba;
static char text[200];

static u16 le16(const u8 *p)
{
    return (u16)(p[0] | p[1] << 8);
}

static u32 le32(const u8 *p)
{
    return (u32)p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24;
}

static u32 be32(const u8 *p)
{
    return (u32)p[0] << 24 | (u32)p[1] << 16 | (u32)p[2] << 8 | (u32)p[3];
}

static void put32(u8 *p, u32 v)
{
    p[0] = (u8)v;
    p[1] = (u8)(v >> 8);
    p[2] = (u8)(v >> 16);
    p[3] = (u8)(v >> 24);
}

static int same(const u8 *p, const char *s, int n)
{
    for (int i = 0; i < n; i++)
        if (p[i] != (u8)s[i])
            return 0;
    return 1;
}

static char lower(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c + 32) : c;
}

static int path_len(const char *s)
{
    int n = 0;
    while (s[n])
        n++;
    return n;
}

static u32 mb(u32 sectors)              /* sectors of 512 bytes in MB */
{
    return sectors >> 11;
}

int disk_count(void)
{
    int n = 0;
    for (int i = 0; i < DISKS; i++)
        n += disks[i].used;
    return n;
}

/* ---- the bulk-only transport ---- */
/* reset recovery: the class's Bulk-Only Mass Storage Reset, then both bulk
   endpoints' halt cleared (a real stick took a while after it) */
static void reset_recovery(struct disk *k)
{
    usb_request(k->device, 0x21, 0xFF, 0, k->iface, 0, 0, 1000);
    usb_clear_halt(k->device, (u8)(0x80 | k->in_ep));
    usb_clear_halt(k->device, k->out_ep);
    delay_ms(100);
}

/* one try of a command (see transfer), waiting up to `wait_ms` for its data
   and for its status: -3 its command block was not taken (the device is
   still in a command of before), -4 no answer to it in time, or one that
   makes no sense (the reset recovery done) */
static int command_once(struct disk *k, const u8 *cb, u8 cb_len, u8 *data, u32 len, int out, u32 wait_ms)
{
    u8 cbw[31], csw[13];
    if (usb_bulk_sync(k->device, k->out_ep, k->in_ep) < 0)
        return -1;
    for (int i = 0; i < 31; i++)
        cbw[i] = 0;
    cbw[0] = 'U';
    cbw[1] = 'S';
    cbw[2] = 'B';
    cbw[3] = 'C';
    put32(cbw + 4, ++k->tag);
    put32(cbw + 8, len);
    cbw[12] = len && !out ? 0x80 : 0x00;    /* the data comes in (or goes out) */
    cbw[14] = cb_len;
    for (int i = 0; i < cb_len; i++)
        cbw[15 + i] = cb[i];
    if (usb_bulk_out(k->device, k->out_ep, k->maxp, cbw, 31, 2000) < 0) {
        u8 e = usb_last_error();
        return (e & 0x20) ? -1 : -3;    /* no answer: gone; a stall or no end: stuck */
    }
    int got = 0;
    if (len && out) {                   /* the data out through endpoint A, as the command block */
        if (usb_bulk_out(k->device, k->out_ep, k->maxp, data, len, wait_ms) < 0) {
            u8 e = usb_last_error();
            if (e & 0x20)
                return -1;
            if (!(e & 0x80)) {
                reset_recovery(k);
                return -4;
            }
            usb_clear_halt(k->device, k->out_ep);   /* the data stalled: the status follows */
        }
    } else if (len) {
        got = usb_bulk_in(k->device, k->in_ep, k->maxp, data, len, wait_ms);
        if (got < 0) {
            u8 e = usb_last_error();
            if (e & 0x20)
                return -1;              /* no answer: gone */
            if (!(e & 0x80)) {
                reset_recovery(k);      /* no data at all */
                return -4;
            }
            usb_clear_halt(k->device, (u8)(0x80 | k->in_ep));   /* the data stalled: the status follows */
            got = 0;
        }
    }
    int n = usb_bulk_in(k->device, k->in_ep, k->maxp, csw, 13, wait_ms);
    if (n < 0 && (usb_last_error() & 0x80)) {
        usb_clear_halt(k->device, (u8)(0x80 | k->in_ep));
        n = usb_bulk_in(k->device, k->in_ep, k->maxp, csw, 13, wait_ms);
    }
    if (n != 13 || le32(csw) != 0x53425355u || le32(csw + 4) != k->tag || csw[12] > 1) {
        if (n < 0 && (usb_last_error() & 0x20))
            return -1;                  /* no answer: gone */
        reset_recovery(k);              /* a status that makes no sense, a phase error, none at all */
        return -4;
    }
    if (out)
        got = (int)(len - le32(csw + 8));   /* (what it took: the length less its residue) */
    return csw[12] ? -2 : got;
}

/* how long a command's data and status are waited for: the first try
   briefly -- on the box a 64 GB stick (090c:2000) idle for a minute or more
   answered the first command after it with nothing at all (5 times in 5)
   and the next one at once -- the second try as long as a slow device may
   need */
#define FIRST_WAIT_MS 2000
#define WAIT_MS 10000

/* one SCSI command, its data in (`len` bytes at most) or, with `out`, out:
   the bytes received (sent); -1 the transport failed (usb_error_text), -2
   the command failed (REQUEST SENSE tells why).  A device that does not take
   the command block is still in some command of before: a reset recovery,
   and the command once more; one that does not answer a command in time (or
   answers nonsense) gets it once more after the reset recovery, too */
static int transfer(struct disk *k, const u8 *cb, u8 cb_len, u8 *data, u32 len, int out)
{
    int r = command_once(k, cb, cb_len, data, len, out, FIRST_WAIT_MS);
    if (r == -3) {
        reset_recovery(k);
        r = command_once(k, cb, cb_len, data, len, out, WAIT_MS);
    } else if (r == -4) {
        k->lost++;
        r = command_once(k, cb, cb_len, data, len, out, WAIT_MS);
    }
    return r == -3 || r == -4 ? -1 : r;
}

static int command(struct disk *k, const u8 *cb, u8 cb_len, u8 *data, u32 len)
{
    return transfer(k, cb, cb_len, data, len, 0);
}

/* REQUEST SENSE: the sense key and the additional sense code; -1 */
static int sense(struct disk *k, u8 *key, u8 *asc)
{
    static const u8 cb[6] = {0x03, 0, 0, 0, 18, 0};
    u8 b[18];
    if (command(k, cb, 6, b, 18) < 14)
        return -1;
    *key = b[2] & 0x0F;
    *asc = b[12];
    return 0;
}

/* READ(10): `count` sectors (8 at most) from `lba` into buf; 0, -1 */
static int read_sectors(struct disk *k, u32 lba, u32 count, u8 *buf)
{
    u8 cb[10];
    cb[0] = 0x28;
    cb[1] = 0;
    cb[2] = (u8)(lba >> 24);
    cb[3] = (u8)(lba >> 16);
    cb[4] = (u8)(lba >> 8);
    cb[5] = (u8)lba;
    cb[6] = 0;
    cb[7] = (u8)(count >> 8);
    cb[8] = (u8)count;
    cb[9] = 0;
    for (int attempt = 0; attempt < 2; attempt++) {
        int n = command(k, cb, 10, buf, count * SECTOR);
        if (n == (int)(count * SECTOR))
            return 0;
        if (n == -1)
            return -1;
        u8 key, asc;
        if (sense(k, &key, &asc) < 0 || key != 6)
            return -1;                  /* (a unit attention: once more) */
    }
    return -1;
}

static int read_sector(struct disk *k, u32 lba)
{
    if (lba >= k->blocks)
        return -1;
    return read_sectors(k, lba, 1, sector);
}

/* ---- partitions and file systems ---- */
static int fat_boot_sector(const u8 *b)
{
    u8 spc = b[13];
    return (b[0] == 0xEB || b[0] == 0xE9) && le16(b + 11) == SECTOR && spc && !(spc & (spc - 1))
           && le16(b + 14) && b[16] >= 1 && b[16] <= 2 && (le16(b + 22) || le32(b + 36))
           && (le16(b + 19) || le32(b + 32));
}

static void copy_label(char *to, const u8 *from)
{
    int n = 11;
    while (n > 0 && from[n - 1] == ' ')
        n--;
    for (int i = 0; i < n; i++)
        to[i] = from[i] >= 32 && from[i] < 127 ? (char)from[i] : '?';
    to[n] = 0;
}

static u32 cluster_sector(const struct volume *v, u32 cluster)
{
    return v->data_start + (cluster - 2) * v->spc;
}

/* the file system in the volume's first sector (in `sector`) */
static void mount(struct disk *k, struct volume *v)
{
    const u8 *b = sector;
    if (same(b + 3, "NTFS    ", 8)) {
        v->fs = FS_NTFS;
        return;
    }
    if (same(b + 3, "EXFAT   ", 8)) {
        v->fs = FS_EXFAT;
        return;
    }
    if (!fat_boot_sector(b)) {
        v->fs = FS_OTHER;
        return;
    }
    u32 reserved = le16(b + 14), fats = b[16], root_entries = le16(b + 17);
    u32 total = le16(b + 19) ? le16(b + 19) : le32(b + 32);
    u32 fat_size = le16(b + 22) ? le16(b + 22) : le32(b + 36);
    v->spc = b[13];
    v->root_sectors = (root_entries * 32 + SECTOR - 1) / SECTOR;
    v->fat_start = v->start + reserved;
    v->root_start = v->fat_start + fats * fat_size;
    v->data_start = v->root_start + v->root_sectors;
    u32 meta = reserved + fats * fat_size + v->root_sectors;
    if (total <= meta) {
        v->fs = FS_OTHER;
        return;
    }
    v->clusters = (total - meta) / v->spc;
    v->fat = v->clusters < 4085 ? 12 : v->clusters < 65525 ? 16 : 32;
    v->root_cluster = v->fat == 32 ? le32(b + 44) : 0;
    v->fats = (u8)fats;
    v->fat_size = fat_size;
    v->fsinfo = v->fat == 32 && le16(b + 48) && le16(b + 48) < reserved ? v->start + le16(b + 48) : 0;
    v->alloc_hint = 2;
    v->written = 0;
    v->fs = FS_FAT;
    u32 at = v->fat == 32 ? 66 : 38;    /* the extended boot signature, then the serial and the label */
    v->label[0] = 0;
    if (b[at] == 0x29)
        copy_label(v->label, b + at + 5);
    /* the label in the root directory's first sector wins (what Windows shows) */
    if (read_sector(k, v->fat == 32 ? cluster_sector(v, v->root_cluster) : v->root_start) < 0)
        return;
    for (int i = 0; i < SECTOR && sector[i]; i += 32)
        if (sector[i] != 0xE5 && (sector[i + 11] & 0x3F) == 0x08) {
            copy_label(v->label, sector + i);
            break;
        }
}

static void add_volume(struct disk *k, u8 number, u8 type, u32 start, u32 count)
{
    if (k->volumes >= VOLUMES || !count || start >= k->blocks)
        return;
    struct volume *v = &k->vol[k->volumes++];
    for (unsigned i = 0; i < sizeof(*v); i++)
        ((u8 *)v)[i] = 0;
    v->number = number;
    v->part_type = type;
    v->start = start;
    v->sectors = count;
}

/* GPT: its first partition entries (a sector's four) */
static void read_gpt(struct disk *k)
{
    if (read_sector(k, 1) < 0 || !same(sector, "EFI PART", 8))
        return;
    u32 entries = le32(sector + 72), count = le32(sector + 80), size = le32(sector + 84);
    if (size != 128)
        return;
    for (u32 s = 0; s < 8 && s * 4 < count && k->volumes < VOLUMES; s++) {
        if (read_sector(k, entries + s) < 0)
            return;
        for (int i = 0; i < 4 && k->volumes < VOLUMES; i++) {
            const u8 *e = sector + i * 128;
            u32 type = le32(e) | le32(e + 4) | le32(e + 8) | le32(e + 12);
            u32 first = le32(e + 32), last = le32(e + 40);
            if (type && !le32(e + 36) && last >= first)     /* (the first 2 TB) */
                add_volume(k, (u8)(s * 4 + i + 1), 0, first, last - first + 1);
        }
    }
}

/* the partitions and what is on each */
static void find_volumes(struct disk *k)
{
    k->volumes = 0;
    if (read_sector(k, 0) < 0) {
        k->problem = "its first sector does not read";
        return;
    }
    if (sector[510] != 0x55 || sector[511] != 0xAA) {
        k->problem = "no partition table";
        return;
    }
    if (fat_boot_sector(sector) || same(sector + 3, "NTFS    ", 8) || same(sector + 3, "EXFAT   ", 8)) {
        add_volume(k, 0, 0, 0, k->blocks);  /* a file system without a partition table */
    } else {
        u8 types[4];
        u32 starts[4], counts[4];
        for (int i = 0; i < 4; i++) {
            const u8 *e = sector + 446 + 16 * i;
            types[i] = e[4];
            starts[i] = le32(e + 8);
            counts[i] = le32(e + 12);
        }
        for (int i = 0; i < 4; i++) {
            if (types[i] == 0xEE) {         /* a protective MBR: the GPT says */
                read_gpt(k);
                break;
            }
            if (types[i] && types[i] != 0x05 && types[i] != 0x0F && types[i] != 0x85)    /* (not extended) */
                add_volume(k, (u8)(i + 1), types[i], starts[i], counts[i]);
        }
    }
    for (int i = 0; i < k->volumes; i++) {
        struct volume *v = &k->vol[i];
        if (read_sector(k, v->start) < 0)
            v->fs = FS_NONE;
        else
            mount(k, v);
    }
}

/* INQUIRY: the vendor, product and revision as its name (their spaces
   folded); 0, -1 no answer (usb_error_text), -2 the command failed
   (k->problem says which) */
static int identify(struct disk *k)
{
    static const u8 inquiry[6] = {0x12, 0, 0, 0, 36, 0};
    u8 b[36];
    int n = command(k, inquiry, 6, b, 36);
    if (n < 36) {
        k->problem = n == -1 ? "INQUIRY got no answer" : "INQUIRY failed";
        return n == -1 ? -1 : -2;
    }
    int at = 0;
    for (int i = 8; i < 36; i++) {
        char c = b[i] >= 32 && b[i] < 127 ? (char)b[i] : ' ';
        if ((i == 16 || i == 32) && at && k->name[at - 1] != ' ')
            k->name[at++] = ' ';
        if (c != ' ' || (at && k->name[at - 1] != ' '))
            k->name[at++] = c;
    }
    while (at && k->name[at - 1] == ' ')
        at--;
    k->name[at] = 0;
    if (!at)
        usnprintf(k->name, sizeof(k->name), "(no name)");
    return 0;
}

/* the medium: TEST UNIT READY until it is (a unit attention first is the
   rule), READ CAPACITY, the partitions; 0 ready.  A disk whose INQUIRY
   failed when it was plugged in is asked again first. */
static int probe(struct disk *k)
{
    static const u8 tur[6] = {0x00, 0, 0, 0, 0, 0};
    static const u8 capacity[10] = {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    u8 b[8], key = 0, asc = 0;
    k->ready = 0;
    k->volumes = 0;
    if (!k->name[0] && identify(k) < 0)
        return -1;
    k->problem = "it does not answer";
    for (int i = 0; i < 12; i++) {
        int r = command(k, tur, 6, 0, 0);
        if (r == 0)
            break;
        if (r == -1)
            return -1;
        if (sense(k, &key, &asc) == 0 && key == 2 && asc == 0x3A) {
            k->problem = "no medium";
            return -1;
        }
        delay_ms(i < 3 ? 20 : 200);
    }
    if (command(k, capacity, 10, b, 8) != 8) {
        k->problem = "READ CAPACITY failed";
        return -1;
    }
    k->blocks = be32(b) + 1;
    k->block_size = be32(b + 4);
    if (k->block_size != SECTOR) {
        k->problem = "its sectors are not 512 bytes";
        return -1;
    }
    k->ready = 1;
    k->problem = 0;
    find_volumes(k);
    return 0;
}

static const char *fs_name(const struct volume *v)
{
    switch (v->fs) {
    case FS_FAT: return v->fat == 12 ? "FAT12" : v->fat == 16 ? "FAT16" : "FAT32";
    case FS_NTFS: return "NTFS";
    case FS_EXFAT: return "exFAT";
    case FS_NONE: return "unreadable";
    }
    return "unknown";
}

/* "FAT32 'LABEL', 961 MB" into text at `at` */
static int volume_text(int at, const struct volume *v)
{
    at += usnprintf(text + at, (int)sizeof(text) - at, "%s", fs_name(v));
    if (v->fs == FS_FAT && v->label[0])
        at += usnprintf(text + at, (int)sizeof(text) - at, " '%s'", v->label);
    if (v->fs == FS_OTHER && v->part_type)
        at += usnprintf(text + at, (int)sizeof(text) - at, " (type %02x)", v->part_type);
    at += usnprintf(text + at, (int)sizeof(text) - at, ", %u MB", mb(v->sectors));
    return at;
}

/* a device with a bulk-only SCSI interface: GET MAX LUN, INQUIRY, the
   medium; a line about it */
const char *disk_attach(u8 device, u8 iface, u8 in_ep, u8 out_ep, u16 maxp)
{
    struct disk *k = 0;
    for (int i = 0; i < DISKS && !k; i++)
        if (!disks[i].used || disks[i].device == device)
            k = &disks[i];
    if (!k)
        return "a disk, but the demo keeps 4 at most";
    for (unsigned i = 0; i < sizeof(*k); i++)
        ((u8 *)k)[i] = 0;
    k->used = 1;
    k->device = device;
    k->iface = iface;
    k->in_ep = in_ep;
    k->out_ep = out_ep;
    k->maxp = maxp;
    k->tag = 0x4D300000u;
    u8 lun = 0;
    usb_request(device, 0xA1, 0xFE, 0, iface, &lun, 1, 500);     /* GET MAX LUN (a stall: one unit) */
    /* a stick just plugged in may not take its first command yet (one on the
       box did not, and answered when asked again later): three tries */
    int r = identify(k);
    for (int i = 0; i < 2 && r < 0; i++) {
        delay_ms(300);
        r = identify(k);
    }
    if (r < 0) {
        int at = usnprintf(text, sizeof(text), "disk %u: %s", device, k->problem);
        if (r == -1)                    /* (no answer: why) */
            at += usnprintf(text + at, (int)sizeof(text) - at, " (%s)", usb_error_text());
        usnprintf(text + at, (int)sizeof(text) - at, "; 'disks' asks it again");
        return text;
    }
    probe(k);
    int at = usnprintf(text, sizeof(text), "disk %u: %s", device, k->name);
    if (!k->ready) {
        usnprintf(text + at, (int)sizeof(text) - at, ": %s", k->problem);
        return text;
    }
    at += usnprintf(text + at, (int)sizeof(text) - at, ", %u MB", mb(k->blocks));
    if (lun)
        at += usnprintf(text + at, (int)sizeof(text) - at, " (%u more units, not read)", lun);
    if (k->volumes) {
        if (k->vol[0].number)
            at += usnprintf(text + at, (int)sizeof(text) - at, "; partition %u: ", k->vol[0].number);
        else
            at += usnprintf(text + at, (int)sizeof(text) - at, "; no partition table: ");
        at = volume_text(at, &k->vol[0]);
        if (k->volumes > 1)
            usnprintf(text + at, (int)sizeof(text) - at, " (+%u)", k->volumes - 1);
    } else if (k->problem) {
        usnprintf(text + at, (int)sizeof(text) - at, "; %s", k->problem);
    }
    return text;
}

void disk_detach(u8 device)
{
    for (int i = 0; i < DISKS; i++)
        if (disks[i].used && disks[i].device == device) {
            disks[i].used = 0;
            if (fat_cache_disk == &disks[i])
                fat_cache_disk = 0;
            if (cwd.k == &disks[i])
                cwd.k = 0;              /* (the prompt says so: no directory any more) */
        }
}

/* 'disks': every disk, its partitions */
void disk_list(void)
{
    int any = 0;
    for (int i = 0; i < DISKS; i++) {
        struct disk *k = &disks[i];
        if (!k->used)
            continue;
        any = 1;
        if (!k->ready)
            probe(k);                   /* (a card put in since) */
        uprintf("device %u: %s", k->device, k->name[0] ? k->name : "(INQUIRY not answered)");
        if (!k->ready) {
            uprintf(": %s\n", k->problem);
            continue;
        }
        uprintf(", %u sectors of 512 bytes (%u MB)\n", k->blocks, mb(k->blocks));
        if (!k->volumes && k->problem)
            uprintf("  %s\n", k->problem);
        for (int j = 0; j < k->volumes; j++) {
            const struct volume *v = &k->vol[j];
            volume_text(0, v);
            if (v->number)
                uprintf("  partition %u: %s, from sector %u%s\n", v->number, text, v->start,
                        v->fs == FS_NTFS || v->fs == FS_EXFAT ? " (its files are not read)" : "");
            else
                uprintf("  no partition table: %s%s\n", text,
                        v->fs == FS_NTFS || v->fs == FS_EXFAT ? " (its files are not read)" : "");
        }
        if (k->lost)
            uprintf("  %u command%s not answered in time, sent again\n", k->lost, k->lost == 1 ? "" : "s");
    }
    if (!any)
        uprintf("no USB disk (plug a stick in; 'lsusb' lists the devices)\n");
}

/* ---- FAT ---- */
static int fat_sector(struct disk *k, u32 lba)
{
    if (fat_cache_disk == k && fat_cache_lba == lba)
        return 0;
    fat_cache_disk = 0;
    if (lba >= k->blocks || read_sectors(k, lba, 1, fat_cache) < 0)
        return -1;
    fat_cache_disk = k;
    fat_cache_lba = lba;
    return 0;
}

/* cluster c's entry in the (first) FAT as it is: 0 free, the next cluster,
   or an end mark; -1 a sector did not read */
static int fat_get(struct disk *k, const struct volume *v, u32 c, u32 *value)
{
    if (v->fat == 32) {
        if (fat_sector(k, v->fat_start + c * 4 / SECTOR))
            return -1;
        *value = le32(fat_cache + c * 4 % SECTOR) & 0x0FFFFFFFu;
    } else if (v->fat == 16) {
        if (fat_sector(k, v->fat_start + c * 2 / SECTOR))
            return -1;
        *value = le16(fat_cache + c * 2 % SECTOR);
    } else {
        u32 off = c + c / 2;            /* 12 bits each: two entries in three bytes */
        if (fat_sector(k, v->fat_start + off / SECTOR))
            return -1;
        u32 n = fat_cache[off % SECTOR];
        if (fat_sector(k, v->fat_start + (off + 1) / SECTOR))
            return -1;
        n |= (u32)fat_cache[(off + 1) % SECTOR] << 8;
        *value = (c & 1) ? n >> 4 : n & 0xFFF;
    }
    return 0;
}

/* the cluster after `c` in its chain; 0 at its end (or on an error) */
static u32 next_cluster(struct disk *k, const struct volume *v, u32 c)
{
    u32 n;
    if (c < 2 || c >= v->clusters + 2 || fat_get(k, v, c, &n) < 0)
        return 0;
    return n >= 2 && n < v->clusters + 2 ? n : 0;
}

#define SLOTS_MAX  21                   /* an entry's 32-byte slots: 20 long-name parts, the 8.3 one */

struct entry {
    char name[NAME_MAX];                /* the long name, else the 8.3 one */
    char short_name[13];
    u8 attr;
    u32 cluster, size;
    u16 date, time;
    u8 slots;                           /* where its slots are (its long name's parts, then the 8.3 one) */
    u32 slot_lba[SLOTS_MAX];
    u16 slot_off[SLOTS_MAX];
};

typedef int (*entry_fn)(const struct entry *e, void *ctx);      /* not 0: enough */

static u8 lfn_checksum(const u8 *d)
{
    u8 s = 0;
    for (int i = 0; i < 11; i++)
        s = (u8)(((s & 1) << 7) + (s >> 1) + d[i]);
    return s;
}

/* every entry of a directory (its first cluster; 0: the FAT12 / FAT16 root)
   to `fn`, with its long name when it has one; 1 when fn stopped, 0 at the
   end, -1 a sector did not read.  `fn` may not read sectors itself */
static const u8 lfn_at[13] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};   /* a long-name part's 13 characters */

static int dir_walk(struct disk *k, const struct volume *v, u32 cluster, entry_fn fn, void *ctx)
{
    static struct entry e;
    const u8 *parts = lfn_at;
    u8 sum = 0, next = 0, long_ok = 0;
    u32 index = 0, steps = 0;
    if (!cluster && v->fat == 32)
        cluster = v->root_cluster;
    for (;;) {
        u32 lba;
        if (!cluster) {
            if (index >= v->root_sectors)
                return 0;
            lba = v->root_start + index;
        } else {
            if (index && !(index % v->spc)) {
                cluster = next_cluster(k, v, cluster);
                if (!cluster || ++steps > v->clusters)
                    return 0;
            }
            lba = cluster_sector(v, cluster) + index % v->spc;
        }
        index++;
        if (read_sector(k, lba) < 0)
            return -1;
        for (int i = 0; i < SECTOR; i += 32) {
            const u8 *d = sector + i;
            if (!d[0])
                return 0;               /* the directory ends */
            if (d[0] == 0xE5) {         /* deleted */
                long_ok = 0;
                continue;
            }
            if ((d[11] & 0x3F) == 0x0F) {   /* a part of a long name (they come last part first) */
                u8 seq = d[0] & 0x1F;
                if (d[0] & 0x40) {
                    long_ok = seq >= 1;
                    sum = d[13];
                    for (int c = 0; c < NAME_MAX; c++)
                        e.name[c] = 0;
                    e.slots = 0;
                } else if (!long_ok || seq != next || d[13] != sum) {
                    long_ok = 0;
                    continue;
                }
                if (e.slots < SLOTS_MAX - 1) {
                    e.slot_lba[e.slots] = lba;
                    e.slot_off[e.slots] = (u16)i;
                    e.slots++;
                } else {
                    long_ok = 0;            /* (longer than any name: not taken as one) */
                }
                next = (u8)(seq - 1);
                for (int c = 0; c < 13; c++) {
                    u16 ch = le16(d + parts[c]);
                    int at = (seq - 1) * 13 + c;
                    if (!ch || ch == 0xFFFF || at >= NAME_MAX - 1)
                        break;
                    e.name[at] = ch >= 32 && ch < 127 ? (char)ch : '?';
                }
                continue;
            }
            /* an 8.3 entry */
            int n = 0;
            for (int c = 0; c < 8 && d[c] != ' '; c++)
                e.short_name[n++] = (c == 0 && d[0] == 0x05) ? (char)0xE5 : (char)d[c];
            if (d[8] != ' ') {
                e.short_name[n++] = '.';
                for (int c = 8; c < 11 && d[c] != ' '; c++)
                    e.short_name[n++] = (char)d[c];
            }
            e.short_name[n] = 0;
            if (!(long_ok && next == 0 && lfn_checksum(d) == sum)) {
                int dot = 0;            /* the short name, with Windows' lower-case flags (base 0x08, extension 0x10) */
                for (int c = 0; c <= n; c++) {
                    char ch = e.short_name[c];
                    if (ch == '.')
                        dot = 1;
                    else if (d[12] & (dot ? 0x10 : 0x08))
                        ch = lower(ch);
                    e.name[c] = ch;
                }
                e.slots = 0;            /* (no long name of its own) */
            }
            e.slot_lba[e.slots] = lba;
            e.slot_off[e.slots] = (u16)i;
            e.slots++;
            long_ok = 0;
            e.attr = d[11];
            e.cluster = le16(d + 26) | (v->fat == 32 ? (u32)le16(d + 20) << 16 : 0);
            e.size = le32(d + 28);
            e.time = le16(d + 22);
            e.date = le16(d + 24);
            if (fn(&e, ctx))
                return 1;
        }
    }
}

static int name_is(const char *name, const char *want, int len)
{
    int i = 0;
    for (; i < len; i++)
        if (!name[i] || lower(name[i]) != lower(want[i]))
            return 0;
    return !name[i];
}

struct find {
    const char *want;
    int len;
    struct entry found;
    int hit;
};

static int find_fn(const struct entry *e, void *ctx)
{
    struct find *f = ctx;
    if ((e->attr & 0x08) || !(name_is(e->name, f->want, f->len) || name_is(e->short_name, f->want, f->len)))
        return 0;
    f->found = *e;
    f->hit = 1;
    return 1;
}

/* the entry named `want` (`len` characters) in directory `dir`: 1 found
   (into f->found), 0 not there, -1 a sector did not read */
static int find_in(struct disk *k, const struct volume *v, u32 dir, const char *want, int len, struct find *f)
{
    f->want = want;
    f->len = len;
    f->hit = 0;
    if (dir_walk(k, v, dir, find_fn, f) < 0)
        return -1;
    return f->hit;
}

/* the entry at `path` from directory `dir`, whose own path is `from` ("/"
   for the root): components split at '/' (or '\'), '.' this one, '..' the
   one above (the root's is the root); its path, with the names as the disk
   spells them, into out_path (PATH_MAX; when not 0).  -1 when it is not
   there (said why) */
static int quiet;                       /* walk_path says nothing (a path only tried) */

static int walk_path(struct disk *k, const struct volume *v, u32 dir, const char *from, const char *path,
                     struct entry *out, char *out_path)
{
    static struct find f;
    char p[PATH_MAX];
    int plen = 0;
    for (; from[plen] && plen < PATH_MAX - 1; plen++)
        p[plen] = from[plen];
    p[plen] = 0;
    if (!plen) {
        p[plen++] = '/';
        p[plen] = 0;
    }
    for (int i = 0; i < NAME_MAX; i++)
        out->name[i] = 0;
    out->name[0] = '/';
    out->short_name[0] = 0;
    out->attr = 0x10;
    out->cluster = dir;
    out->size = 0;
    out->slots = 0;
    while (*path) {
        while (*path == '/' || *path == '\\')
            path++;
        if (!*path)
            break;
        int len = 0;
        while (path[len] && path[len] != '/' && path[len] != '\\')
            len++;
        if (!(out->attr & 0x10)) {
            if (!quiet)
                uprintf("not a directory: %s\n", out->name);
            return -1;
        }
        if (len == 1 && path[0] == '.') {
            path += len;
            continue;
        }
        int up = len == 2 && path[0] == '.' && path[1] == '.';
        if (up && plen == 1) {          /* the root's '..': the root */
            path += len;
            continue;
        }
        int r = find_in(k, v, out->cluster, path, len, &f);
        if (r < 0) {
            uprintf("a sector did not read: %s\n", usb_error_text());
            return -1;
        }
        if (!r) {
            if (!quiet) {
                uprintf("not found: ");
                for (int i = 0; i < len; i++)
                    uprintf("%c", path[i]);
                uprintf("\n");
            }
            return -1;
        }
        *out = f.found;
        if (up) {                       /* the path one shorter */
            while (plen > 1 && p[plen - 1] != '/')
                plen--;
            if (plen > 1)
                plen--;
            p[plen] = 0;
        } else {
            if (plen > 1 && plen < PATH_MAX - 1)
                p[plen++] = '/';
            for (const char *s = out->name; *s && plen < PATH_MAX - 1; s++)
                p[plen++] = *s;
            p[plen] = 0;
        }
        path += len;
    }
    if (out_path) {
        for (int i = 0; i <= plen; i++)
            out_path[i] = p[i];
    }
    return 0;
}

/* "[device[.partition]:][path]": the disk and volume (the first FAT volume
   when none is named), the path; 0 when there is none (said why) */
static const char *where(const char *arg, struct disk **pk, struct volume **pv)
{
    u32 device = 0, part = 0;
    const char *p = arg;
    while (*p >= '0' && *p <= '9')
        device = device * 10 + (u32)(*p++ - '0');
    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9')
            part = part * 10 + (u32)(*p++ - '0');
    }
    if (*p == ':' && p != arg)
        arg = p + 1;
    else
        device = part = 0;
    for (int i = 0; i < DISKS; i++) {
        struct disk *k = &disks[i];
        if (!k->used || (device && k->device != device))
            continue;
        if (!k->ready)
            probe(k);
        for (int j = 0; j < k->volumes; j++) {
            struct volume *v = &k->vol[j];
            if (part ? v->number == part : v->fs == FS_FAT) {
                if (v->fs != FS_FAT) {
                    uprintf("device %u partition %u is %s: its files are not read\n", k->device, v->number, fs_name(v));
                    return 0;
                }
                *pk = k;
                *pv = v;
                return arg;
            }
        }
        if (device) {
            uprintf("device %u: %s\n", device, !k->ready ? k->problem : "no FAT volume there ('disks' lists it)");
            return 0;
        }
    }
    uprintf(device ? "device %u is not a USB disk ('disks' lists them)\n" : "no FAT volume on a USB disk ('disks')\n",
            device);
    return 0;
}

/* ---- the current directory ('cd') ---- */
static void cwd_text_set(void);

const char *disk_cwd(void)
{
    return cwd.k ? cwd_text : "";
}

/* is the path named with a disk ("3:", "3.2:")? */
static int named_disk(const char *arg)
{
    const char *p = arg;
    while (*p >= '0' && *p <= '9')
        p++;
    if (*p == '.' && p != arg) {
        p++;
        while (*p >= '0' && *p <= '9')
            p++;
    }
    return *p == ':' && p != arg;
}

/* where a path starts: "n[.p]:path" at that volume's root; without it in the
   current directory -- at its volume's root when it begins with '/' -- or,
   before any 'cd', at the first FAT volume's root.  The volume, the
   directory and its path; what follows.  0 when there is no such volume
   (said why) */
static const char *locate(const char *arg, struct disk **pk, struct volume **pv, u32 *dir, const char **from)
{
    if (!named_disk(arg) && cwd.k && cwd.k->used) {
        *pk = cwd.k;
        *pv = cwd.v;
        if (arg[0] == '/' || arg[0] == '\\') {
            *dir = 0;
            *from = "/";
        } else {
            *dir = cwd.cluster;
            *from = cwd.path;
        }
        return arg;
    }
    const char *rest = where(arg, pk, pv);
    *dir = 0;
    *from = "/";
    return rest;
}

/* 'cd [n:][path]' (alone: no current directory any more) */
void disk_cd(const char *arg)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    static char path[PATH_MAX];
    u32 dir;
    const char *from;
    if (!arg[0]) {
        cwd.k = 0;
        return;
    }
    const char *rest = locate(arg, &k, &v, &dir, &from);
    if (!rest || walk_path(k, v, dir, from, rest, &e, path) < 0)
        return;
    if (!(e.attr & 0x10)) {
        uprintf("not a directory: %s\n", e.name);
        return;
    }
    cwd.k = k;
    cwd.v = v;
    cwd.cluster = e.cluster;
    for (int i = 0; i < PATH_MAX; i++)
        cwd.path[i] = path[i];
    cwd_text_set();
}

void disk_pwd(void)
{
    if (cwd.k)
        uprintf("%s\n", cwd_text);
    else
        uprintf("no current directory ('cd 3:' chooses disk 3's root; 'disks' lists them)\n");
}

struct listing {
    u32 files, dirs, bytes;
};

static int ls_fn(const struct entry *e, void *ctx)
{
    struct listing *l = ctx;
    if ((e->attr & 0x08) || (e->name[0] == '.' && (!e->name[1] || (e->name[1] == '.' && !e->name[2]))))
        return 0;                       /* the volume label, '.', '..' */
    u32 year = 1980 + (e->date >> 9), month = (e->date >> 5) & 15, day = e->date & 31;
    uprintf("%04u-%02u-%02u %02u:%02u ", year, month, day, e->time >> 11, (e->time >> 5) & 63);
    if (e->attr & 0x10) {
        uprintf("     <DIR>  ");
        l->dirs++;
    } else {
        uprintf("%10u  ", e->size);
        l->files++;
        l->bytes += e->size;
    }
    uprintf("%s%s\n", e->name, (e->attr & 0x02) ? "  (hidden)" : "");
    (void)now_ms();                     /* (the watchdog: a long listing) */
    return 0;
}

/* 'ls [n:][path]' */
void disk_ls(const char *arg)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    u32 dir;
    const char *from;
    const char *path = locate(arg, &k, &v, &dir, &from);
    if (!path || walk_path(k, v, dir, from, path, &e, 0) < 0)
        return;
    if (!(e.attr & 0x10)) {
        struct listing one = {0, 0, 0};
        ls_fn(&e, &one);
        return;
    }
    volume_text(0, v);
    if (v->number)
        uprintf("device %u partition %u: %s\n", k->device, v->number, text);
    else
        uprintf("device %u: %s\n", k->device, text);
    struct listing l = {0, 0, 0};
    if (dir_walk(k, v, e.cluster, ls_fn, &l) < 0)
        uprintf("a sector did not read: %s\n", usb_error_text());
    uprintf("%u file%s, %u director%s, %u bytes\n", l.files, l.files == 1 ? "" : "s", l.dirs,
            l.dirs == 1 ? "y" : "ies", l.bytes);
}

/* 'cat [n:]/path': a text file as it is (a binary one: its first 256 bytes
   as hex); Ctrl-C on the UART stops it */
void disk_cat(const char *arg)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    u32 dir;
    const char *from;
    const char *path = locate(arg, &k, &v, &dir, &from);
    if (!path || walk_path(k, v, dir, from, path, &e, 0) < 0)
        return;
    if (e.attr & 0x10) {
        uprintf("a directory: 'ls' lists it\n");
        return;
    }
    u32 left = e.size, cluster = e.cluster, in = 0, steps = 0, binary = 0, column = 0;
    if (!left)
        return;
    while (left) {
        if (cluster < 2 || cluster >= v->clusters + 2 || read_sector(k, cluster_sector(v, cluster) + in) < 0) {
            uprintf("\na sector did not read (cluster %u): %s\n", cluster, usb_error_text());
            return;
        }
        u32 n = left < SECTOR ? left : SECTOR;
        if (left == e.size) {           /* the first sector: text? */
            for (u32 i = 0; i < n; i++)
                if (sector[i] < 32 && sector[i] != '\n' && sector[i] != '\r' && sector[i] != '\t')
                    binary++;
            if (binary * 10 > n) {
                uprintf("a binary file, %u bytes; its first %u:\n", e.size, n < 256 ? n : 256);
                for (u32 i = 0; i < n && i < 256; i += 16) {
                    uprintf("%04x:", i);
                    for (u32 j = i; j < i + 16 && j < n; j++)
                        uprintf(" %02x", sector[j]);
                    uprintf("\n");
                }
                return;
            }
        }
        for (u32 i = 0; i < n; i++) {
            u8 c = sector[i];
            if (c == '\n') {
                uprintf("\n");
                column = 0;
            } else if (c != '\r') {
                uprintf("%c", c == '\t' ? ' ' : c >= 32 && c < 127 ? c : '.');
                column++;
            }
        }
        left -= n;
        if (++in == v->spc) {
            in = 0;
            cluster = next_cluster(k, v, cluster);
            if (left && (!cluster || ++steps > v->clusters)) {
                uprintf("\nthe file's cluster chain ends early (%u bytes left)\n", left);
                return;
            }
        }
        if (uart_getc() == 3) {
            uprintf("^C\n");
            return;
        }
    }
    if (column)
        uprintf("\n");
}

/* 'sector [n:]<lba>': one sector of a disk in hex */
void disk_sector(const char *arg)
{
    u32 device = 0, lba = 0;
    const char *p = arg;
    struct disk *k = 0;
    while (*p >= '0' && *p <= '9')
        device = device * 10 + (u32)(*p++ - '0');
    if (*p == ':')
        p++;
    else {
        p = arg;
        device = 0;
    }
    int digits = 0;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        for (p += 2; (*p >= '0' && *p <= '9') || (lower(*p) >= 'a' && lower(*p) <= 'f'); p++, digits++)
            lba = lba * 16 + (u32)(*p <= '9' ? *p - '0' : lower(*p) - 'a' + 10);
    } else {
        for (; *p >= '0' && *p <= '9'; p++, digits++)
            lba = lba * 10 + (u32)(*p - '0');
    }
    if (!digits || *p) {
        uprintf("usage: sector [device:]<sector number>\n");
        return;
    }
    for (int i = 0; i < DISKS && !k; i++)
        if (disks[i].used && (!device || disks[i].device == device))
            k = &disks[i];
    if (!k) {
        uprintf("no such USB disk ('disks' lists them)\n");
        return;
    }
    if (!k->ready && probe(k) < 0) {
        uprintf("device %u: %s\n", k->device, k->problem);
        return;
    }
    if (read_sector(k, lba) < 0) {
        uprintf("device %u: sector %u does not read (%u sectors; %s)\n", k->device, lba, k->blocks, usb_error_text());
        return;
    }
    uprintf("device %u, sector %u:\n", k->device, lba);
    for (int i = 0; i < SECTOR; i += 16) {
        uprintf("%03x:", i);
        for (int j = i; j < i + 16; j++)
            uprintf(" %02x", sector[j]);
        uprintf("  ");
        for (int j = i; j < i + 16; j++)
            uprintf("%c", sector[j] >= 32 && sector[j] < 127 ? sector[j] : '.');
        uprintf("\n");
    }
}

/* ---- writing: mkdir, rmdir, rm, touch ---- */
/* SCSI WRITE(10) through the bulk-only transport's data-out stage; every
   copy of the FAT is written; a new directory's cluster is zeroed and gets
   its '.' and '..' before its entry links it in, and an entry is deleted
   before its clusters are freed (cut off half way, a volume keeps at most a
   lost cluster); a FAT32 volume's FSInfo counts are made unknown at its
   first change (the next system to mount it counts again).  The box has no
   clock: what is made is dated FAT_DATE / FAT_TIME. */
#define FAT_DATE ((u16)(((2026 - 1980) << 9) | (11 << 5) | 13))   /* 2026-11-13 */
#define FAT_TIME ((u16)(12 << 11))                                 /* 12:00 */

static u8 wbuf[SECTOR], wbuf2[SECTOR];  /* sectors being changed */
static u8 zeros[8 * SECTOR];

static void put16(u8 *p, u16 v)
{
    p[0] = (u8)v;
    p[1] = (u8)(v >> 8);
}

static int write_sectors(struct disk *k, u32 lba, u32 count, const u8 *buf)
{
    u8 cb[10] = {0x2A, 0, (u8)(lba >> 24), (u8)(lba >> 16), (u8)(lba >> 8), (u8)lba, 0, (u8)(count >> 8),
                 (u8)count, 0};
    if (!count || count > 8 || lba + count > k->blocks)
        return -1;
    for (int attempt = 0; attempt < 2; attempt++) {
        int n = transfer(k, cb, 10, (u8 *)buf, count * SECTOR, 1);
        if (n == (int)(count * SECTOR))
            return 0;
        if (n == -1)
            return -1;
        u8 key = 0, asc = 0;
        if (sense(k, &key, &asc) < 0 || key != 6) {
            if (key == 7)
                k->wp = 2;              /* data protect: write-protected after all */
            return -1;
        }
    }
    return -1;
}

/* may the disk be written?  MODE SENSE(6)'s write-protect bit (a device that
   does not answer it is tried; WRITE then says); said when not */
static int writable(struct disk *k)
{
    if (!k->wp) {
        static const u8 cb[6] = {0x1A, 0, 0x3F, 0, 4, 0};
        u8 b[4], key, asc;
        int n = command(k, cb, 6, b, 4);
        if (n == -2)
            (void)sense(k, &key, &asc);
        k->wp = n >= 3 && (b[2] & 0x80) ? 2 : 1;
    }
    if (k->wp == 2)
        uprintf("device %u is write-protected\n", k->device);
    return k->wp == 1;
}

/* SYNCHRONIZE CACHE(10): what the device holds written to its medium */
static void sync_disk(struct disk *k)
{
    static const u8 cb[10] = {0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    u8 key, asc;
    if (command(k, cb, 10, 0, 0) == -2)
        (void)sense(k, &key, &asc);     /* (a device without it) */
}

static u32 fat_end(const struct volume *v)
{
    return v->fat == 32 ? 0x0FFFFFFFu : v->fat == 16 ? 0xFFFFu : 0xFFFu;
}

/* cluster c's entry set to `value` in every copy of the FAT */
static int fat_set(struct disk *k, const struct volume *v, u32 c, u32 value)
{
    fat_cache_disk = 0;                 /* (the cached FAT sector may change) */
    for (u32 copy = 0; copy < v->fats; copy++) {
        u32 off = v->fat == 32 ? c * 4 : v->fat == 16 ? c * 2 : c + c / 2;
        u32 lba = v->fat_start + copy * v->fat_size + off / SECTOR, at = off % SECTOR;
        if (read_sectors(k, lba, 1, wbuf) < 0)
            return -1;
        if (v->fat == 32) {
            put32(wbuf + at, (le32(wbuf + at) & 0xF0000000u) | (value & 0x0FFFFFFFu));
        } else if (v->fat == 16) {
            put16(wbuf + at, (u16)value);
        } else {                        /* 12 bits, perhaps across two sectors */
            u8 *hi = wbuf + at + 1;
            if (at + 1 == SECTOR) {
                if (read_sectors(k, lba + 1, 1, wbuf2) < 0)
                    return -1;
                hi = wbuf2;
            }
            u32 word = wbuf[at] | (u32)*hi << 8;
            word = (c & 1) ? (word & 0x000Fu) | ((value & 0xFFFu) << 4) : (word & 0xF000u) | (value & 0xFFFu);
            wbuf[at] = (u8)word;
            *hi = (u8)(word >> 8);
            if (hi == wbuf2 && write_sectors(k, lba + 1, 1, wbuf2) < 0)
                return -1;
        }
        if (write_sectors(k, lba, 1, wbuf) < 0)
            return -1;
    }
    return 0;
}

/* before the first change of a volume: FAT32's FSInfo free count and next
   free cluster made unknown (its hint taken first) */
static int fsinfo_unknown(struct disk *k, struct volume *v)
{
    if (v->written)
        return 0;
    if (v->fsinfo) {
        if (read_sectors(k, v->fsinfo, 1, wbuf) < 0)
            return -1;
        if (le32(wbuf) == 0x41615252u && le32(wbuf + 484) == 0x61417272u) {
            u32 hint = le32(wbuf + 492);
            if (hint >= 2 && hint < v->clusters + 2)
                v->alloc_hint = hint;
            put32(wbuf + 488, 0xFFFFFFFFu);
            put32(wbuf + 492, 0xFFFFFFFFu);
            if (write_sectors(k, v->fsinfo, 1, wbuf) < 0)
                return -1;
        }
    }
    v->written = 1;
    return 0;
}

/* a free cluster, marked as a chain's end: its number, 0 none (said why) */
static u32 fat_alloc(struct disk *k, struct volume *v)
{
    u32 c = v->alloc_hint >= 2 && v->alloc_hint < v->clusters + 2 ? v->alloc_hint : 2;
    for (u32 i = 0; i < v->clusters; i++) {
        u32 value;
        if (fat_get(k, v, c, &value) < 0) {
            uprintf("a FAT sector did not read: %s\n", usb_error_text());
            return 0;
        }
        if (!value) {
            if (fat_set(k, v, c, fat_end(v)) < 0) {
                uprintf("the FAT was not written: %s\n", usb_error_text());
                return 0;
            }
            v->alloc_hint = c + 1;
            return c;
        }
        c = c + 1 < v->clusters + 2 ? c + 1 : 2;
        if (!(i & 0xFF))
            (void)now_ms();             /* (the watchdog: a long search) */
    }
    uprintf("the volume is full\n");
    return 0;
}

/* a chain of clusters made free */
static int free_chain(struct disk *k, const struct volume *v, u32 c)
{
    for (u32 steps = 0; c >= 2 && c < v->clusters + 2 && steps <= v->clusters; steps++) {
        u32 next;
        if (fat_get(k, v, c, &next) < 0 || fat_set(k, v, c, 0) < 0)
            return -1;
        c = next;
        if (!(steps & 0x3F))
            (void)now_ms();
    }
    return 0;
}

static int zero_cluster(struct disk *k, const struct volume *v, u32 c)
{
    u32 lba = cluster_sector(v, c);
    for (u32 i = 0; i < v->spc; i += 8)
        if (write_sectors(k, lba + i, v->spc - i < 8 ? v->spc - i : 8, zeros) < 0)
            return -1;
    return 0;
}

/* a directory's sectors one after the other: 1 the next one's LBA, 0 its end,
   -1 a FAT sector did not read; `last`: its last cluster (to grow it) */
struct dir_iter {
    u32 cluster, index, steps, last;
};

static void dir_iter_start(const struct volume *v, u32 dir, struct dir_iter *it)
{
    it->cluster = dir ? dir : v->fat == 32 ? v->root_cluster : 0;
    it->index = 0;
    it->steps = 0;
    it->last = it->cluster;
}

static int dir_iter_next(struct disk *k, const struct volume *v, struct dir_iter *it, u32 *lba)
{
    if (!it->cluster) {                 /* the FAT12 / FAT16 root's fixed place */
        if (it->index >= v->root_sectors)
            return 0;
        *lba = v->root_start + it->index++;
        return 1;
    }
    if (it->index && !(it->index % v->spc)) {
        u32 n;
        if (fat_get(k, v, it->cluster, &n) < 0)
            return -1;
        if (n < 2 || n >= v->clusters + 2 || ++it->steps > v->clusters)
            return 0;
        it->cluster = n;
    }
    it->last = it->cluster;
    *lba = cluster_sector(v, it->cluster) + it->index % v->spc;
    it->index++;
    return 1;
}

/* `n` new 32-byte entries (a long name's parts, then the 8.3 one) into
   directory `dir` (0: the root), in the first run of n free slots -- a
   deleted entry's, or after the directory's end mark -- a cluster added to
   the directory when it has no such run (the FAT12 / FAT16 root cannot grow).
   Where the 8.3 entry went into *at_lba / *at_off (when not 0) */
static int dir_put(struct disk *k, struct volume *v, u32 dir, u8 (*ents)[32], int n, u32 *at_lba, u16 *at_off)
{
    struct dir_iter it;
    u32 lba_of[SLOTS_MAX];
    u16 off_of[SLOTS_MAX];
    int run = 0, ended = 0, r = 0;
    u32 lba;
    dir_iter_start(v, dir, &it);
    while (run < n && (r = dir_iter_next(k, v, &it, &lba)) > 0) {
        if (read_sectors(k, lba, 1, sector) < 0)
            return -1;
        for (int i = 0; i < SECTOR && run < n; i += 32) {
            if (ended || sector[i] == 0x00 || sector[i] == 0xE5) {
                if (sector[i] == 0x00)
                    ended = 1;
                lba_of[run] = lba;
                off_of[run] = (u16)i;
                run++;
            } else {
                run = 0;
            }
        }
    }
    if (r < 0)
        return -1;
    while (run < n) {                   /* full: one more cluster */
        if (!it.cluster) {
            uprintf("the root directory is full\n");
            return -1;
        }
        u32 c = fat_alloc(k, v);
        if (!c)
            return -1;
        if (zero_cluster(k, v, c) < 0 || fat_set(k, v, it.last, c) < 0) {
            (void)fat_set(k, v, c, 0);
            return -1;
        }
        it.last = c;
        for (u32 s = 0; s < v->spc && run < n; s++)
            for (int i = 0; i < SECTOR && run < n; i += 32) {
                lba_of[run] = cluster_sector(v, c) + s;
                off_of[run] = (u16)i;
                run++;
            }
    }
    for (int i = 0; i < n;) {           /* each sector read, changed, written */
        u32 l = lba_of[i];
        if (read_sectors(k, l, 1, wbuf) < 0)
            return -1;
        for (; i < n && lba_of[i] == l; i++)
            for (int b = 0; b < 32; b++)
                wbuf[off_of[i] + b] = ents[i][b];
        if (write_sectors(k, l, 1, wbuf) < 0)
            return -1;
    }
    if (at_lba) {
        *at_lba = lba_of[n - 1];
        *at_off = off_of[n - 1];
    }
    return 0;
}

/* an entry's slots marked deleted (0xE5), its long name's parts too */
static int delete_slots(struct disk *k, const struct entry *e)
{
    for (int i = 0; i < e->slots;) {
        u32 l = e->slot_lba[i];
        if (read_sectors(k, l, 1, wbuf) < 0)
            return -1;
        for (; i < e->slots && e->slot_lba[i] == l; i++)
            wbuf[e->slot_off[i]] = 0xE5;
        if (write_sectors(k, l, 1, wbuf) < 0)
            return -1;
    }
    return 0;
}

static char upper(char c)
{
    return c >= 'a' && c <= 'z' ? (char)(c - 32) : c;
}

/* a character an 8.3 name may have (upper case) */
static int sfn_char(char c)
{
    if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
        return 1;
    for (const char *s = "!#$%&'()-@^_`{}~"; *s; s++)
        if (c == *s)
            return 1;
    return 0;
}

/* the 8.3 name (11 bytes) for `name`: 1 when the name is one -- in upper
   case, or each part all in one case (*nt: Windows' lower-case flags, 0x08
   the base, 0x10 the extension) -- 0 when it needs a long name: then `sfn`
   is its basis (upper case, what is not allowed as '_'; ~n added later) */
static int short_form(const char *name, u8 *sfn, u8 *nt)
{
    int len = 0, dot = -1, dots = 0;
    for (; name[len]; len++)
        if (name[len] == '.') {
            dot = len;
            dots++;
        }
    for (int i = 0; i < 11; i++)
        sfn[i] = ' ';
    *nt = 0;
    int base_len = dot < 0 ? len : dot, ext_len = dot < 0 ? 0 : len - dot - 1;
    int ok = dots <= 1 && base_len >= 1 && base_len <= 8 && ext_len <= 3 && !(dot >= 0 && !ext_len);
    int lower_b = 0, upper_b = 0, lower_e = 0, upper_e = 0;
    for (int i = 0; i < len; i++) {
        char c = name[i];
        int ext = dot >= 0 && i > dot;
        if (i == dot)
            continue;
        if (c >= 'a' && c <= 'z')
            *(ext ? &lower_e : &lower_b) += 1;
        else if (c >= 'A' && c <= 'Z')
            *(ext ? &upper_e : &upper_b) += 1;
        else if (!sfn_char(c))
            ok = 0;
    }
    if ((lower_b && upper_b) || (lower_e && upper_e))
        ok = 0;
    int b = 0, e = 0;
    for (int i = 0; i < (dot < 0 ? len : dot) && b < 8; i++)
        if (name[i] != ' ' && name[i] != '.')
            sfn[b++] = (u8)(sfn_char(upper(name[i])) ? upper(name[i]) : '_');
    for (int i = dot + 1; dot >= 0 && i < len && e < 3; i++)
        if (name[i] != ' ')
            sfn[8 + e++] = (u8)(sfn_char(upper(name[i])) ? upper(name[i]) : '_');
    if (!b) {                           /* (".profile": the extension's letters as the base) */
        for (int i = 0; i < 3; i++) {
            sfn[i] = sfn[8 + i];
            sfn[8 + i] = ' ';
        }
        b = e;
    }
    if (!b)
        sfn[0] = '_';
    if (ok) {
        if (lower_b)
            *nt |= 0x08;
        if (lower_e)
            *nt |= 0x10;
    }
    return ok;
}

/* "BASE.EXT" of an 8.3 name */
static void sfn_text(const u8 *sfn, char *out)
{
    int n = 0;
    for (int i = 0; i < 8 && sfn[i] != ' '; i++)
        out[n++] = (char)sfn[i];
    if (sfn[8] != ' ') {
        out[n++] = '.';
        for (int i = 8; i < 11 && sfn[i] != ' '; i++)
            out[n++] = (char)sfn[i];
    }
    out[n] = 0;
}

/* the slots of a new entry `name` (attribute, first cluster, size) for
   directory `dir`: its long name's parts when it needs them (the last
   first), then the 8.3 entry -- "BASIS~n" with an n no entry there has.
   Their number; -1 (said why) */
static int make_entry(struct disk *k, const struct volume *v, u32 dir, const char *name, u8 attr, u32 cluster,
                      u32 size, u8 (*ents)[32])
{
    static struct find f;
    u8 sfn[11], nt;
    int n = 0, len = path_len(name);
    int fits = short_form(name, sfn, &nt);
    if (!fits) {
        int base = 0, found = 0;
        while (base < 8 && sfn[base] != ' ')
            base++;
        for (int t = 1; t < 100 && !found; t++) {
            u8 try[11];
            char tail[4], cand[13];
            int tl = usnprintf(tail, sizeof(tail), "~%d", t), keep = 8 - tl < base ? 8 - tl : base;
            for (int i = 0; i < 11; i++)
                try[i] = sfn[i];
            for (int i = 0; i < tl; i++)
                try[keep + i] = (u8)tail[i];
            for (int i = keep + tl; i < 8; i++)
                try[i] = ' ';
            sfn_text(try, cand);
            int r = find_in(k, v, dir, cand, path_len(cand), &f);
            if (r < 0) {
                uprintf("a sector did not read: %s\n", usb_error_text());
                return -1;
            }
            if (!r) {
                for (int i = 0; i < 11; i++)
                    sfn[i] = try[i];
                found = 1;
            }
        }
        if (!found) {
            uprintf("no 8.3 name left for '%s'\n", name);
            return -1;
        }
        int parts = (len + 12) / 13;
        u8 sum = lfn_checksum(sfn);
        for (int p = parts; p >= 1; p--) {
            u8 *d = ents[n++];
            for (int i = 0; i < 32; i++)
                d[i] = 0;
            d[0] = (u8)(p | (p == parts ? 0x40 : 0));
            d[11] = 0x0F;
            d[13] = sum;
            for (int c = 0; c < 13; c++) {
                int at = (p - 1) * 13 + c;
                put16(d + lfn_at[c], (u16)(at < len ? (u8)name[at] : at == len ? 0x0000 : 0xFFFF));
            }
        }
    }
    u8 *d = ents[n++];
    for (int i = 0; i < 32; i++)
        d[i] = 0;
    for (int i = 0; i < 11; i++)
        d[i] = sfn[i];
    d[11] = attr;
    d[12] = fits ? nt : 0;
    put16(d + 14, FAT_TIME);            /* created */
    put16(d + 16, FAT_DATE);
    put16(d + 18, FAT_DATE);            /* accessed */
    put16(d + 20, (u16)(v->fat == 32 ? cluster >> 16 : 0));
    put16(d + 22, FAT_TIME);            /* written */
    put16(d + 24, FAT_DATE);
    put16(d + 26, (u16)cluster);
    put32(d + 28, size);
    return n;
}

/* a character a long FAT name may have (of ASCII) */
static int name_char(char c)
{
    if ((u8)c < 32 || (u8)c > 126)
        return 0;
    for (const char *s = "\\/:*?\"<>|"; *s; s++)
        if (c == *s)
            return 0;
    return 1;
}

/* "a/b/name": "a/b" into parent, "name" into name (trailing '/', spaces and
   dots dropped, as Windows does); 0 when there is no name or it has a
   character a FAT name may not have */
static int split_path(const char *path, char *parent, char *name)
{
    int len = path_len(path), cut;
    while (len > 0 && (path[len - 1] == '/' || path[len - 1] == '\\'))
        len--;
    for (cut = len; cut > 0 && path[cut - 1] != '/' && path[cut - 1] != '\\'; cut--)
        ;
    int pl = cut < PATH_MAX - 1 ? cut : PATH_MAX - 1;
    for (int i = 0; i < pl; i++)
        parent[i] = path[i];
    parent[pl] = 0;
    int nl = 0;
    for (int i = cut; i < len && nl < NAME_MAX - 1; i++)
        name[nl++] = path[i];
    while (nl > 0 && (name[nl - 1] == ' ' || name[nl - 1] == '.'))
        nl--;
    name[nl] = 0;
    for (int i = 0; i < nl; i++)
        if (!name_char(name[i]))
            return 0;
    return nl > 0;
}

/* what mkdir, touch, '>' and mv start from: the directory to put `name` in
   (said why when there is none) and its path into place_path; 1 when the
   name is there already (that entry into *found, when not 0), 0 not */
static char place_path[PATH_MAX];

static int new_place(const char *arg, const char *verb, struct disk **pk, struct volume **pv, struct entry *parent,
                     char *name, struct entry *found)
{
    static char pdir[PATH_MAX];
    static struct find f;
    u32 dir;
    const char *from;
    const char *path = locate(arg, pk, pv, &dir, &from);
    if (!path)
        return -1;
    if (!split_path(path, pdir, name)) {
        uprintf("%s: not a name for a FAT volume: '%s'\n", verb, arg);
        return -1;
    }
    if (walk_path(*pk, *pv, dir, from, pdir, parent, place_path) < 0)
        return -1;
    if (!(parent->attr & 0x10)) {
        uprintf("not a directory: %s\n", parent->name);
        return -1;
    }
    int r = find_in(*pk, *pv, parent->cluster, name, path_len(name), &f);
    if (r < 0) {
        uprintf("a sector did not read: %s\n", usb_error_text());
        return -1;
    }
    if (r && found)
        *found = f.found;
    return r;                           /* (1: it is there already) */
}

void disk_mkdir(const char *arg)
{
    struct disk *k;
    struct volume *v;
    static struct entry parent;
    static char name[NAME_MAX];
    static u8 ents[SLOTS_MAX][32];
    int there = new_place(arg, "mkdir", &k, &v, &parent, name, 0);
    if (there) {
        if (there > 0)
            uprintf("mkdir: '%s' exists\n", name);
        return;
    }
    if (!writable(k) || fsinfo_unknown(k, v) < 0)
        return;
    u32 c = fat_alloc(k, v);
    if (!c)
        return;
    for (int i = 0; i < SECTOR; i++)    /* its first sector: '.' and '..' */
        wbuf2[i] = 0;
    for (int dots = 1; dots <= 2; dots++) {
        u8 *d = wbuf2 + (dots - 1) * 32;
        for (int i = 0; i < 11; i++)
            d[i] = i < dots ? '.' : ' ';
        u32 to = dots == 1 ? c : parent.cluster;    /* ('..' of a directory in the root: 0) */
        d[11] = 0x10;
        put16(d + 14, FAT_TIME);
        put16(d + 16, FAT_DATE);
        put16(d + 18, FAT_DATE);
        put16(d + 20, (u16)(v->fat == 32 ? to >> 16 : 0));
        put16(d + 22, FAT_TIME);
        put16(d + 24, FAT_DATE);
        put16(d + 26, (u16)to);
    }
    int n;
    if (zero_cluster(k, v, c) < 0 || write_sectors(k, cluster_sector(v, c), 1, wbuf2) < 0
        || (n = make_entry(k, v, parent.cluster, name, 0x10, c, 0, ents)) < 0
        || dir_put(k, v, parent.cluster, ents, n, 0, 0) < 0) {
        uprintf("mkdir: not made (%s)\n", usb_error_text());
        (void)fat_set(k, v, c, 0);
        return;
    }
    sync_disk(k);
}

void disk_touch(const char *arg)
{
    struct disk *k;
    struct volume *v;
    static struct entry parent;
    static char name[NAME_MAX];
    static u8 ents[SLOTS_MAX][32];
    if (new_place(arg, "touch", &k, &v, &parent, name, 0))
        return;                         /* (there already: left as it is -- there is no clock to set) */
    if (!writable(k) || fsinfo_unknown(k, v) < 0)
        return;
    int n = make_entry(k, v, parent.cluster, name, 0x20, 0, 0, ents);
    if (n < 0 || dir_put(k, v, parent.cluster, ents, n, 0, 0) < 0) {
        uprintf("touch: not made (%s)\n", usb_error_text());
        return;
    }
    sync_disk(k);
}

struct count {
    u32 n;
};

static int count_fn(const struct entry *e, void *ctx)
{
    struct count *c = ctx;
    if ((e->attr & 0x08) || (e->name[0] == '.' && (!e->name[1] || (e->name[1] == '.' && !e->name[2]))))
        return 0;
    c->n++;
    return 1;
}

/* rm and rmdir: the entry at the path (not the root, '.' or '..') */
static int old_entry(const char *arg, struct disk **pk, struct volume **pv, struct entry *e)
{
    u32 dir;
    const char *from;
    const char *path = locate(arg, pk, pv, &dir, &from);
    if (!path || walk_path(*pk, *pv, dir, from, path, e, 0) < 0)
        return -1;
    if (!e->slots || (e->name[0] == '.' && (!e->name[1] || (e->name[1] == '.' && !e->name[2])))) {
        uprintf("not that one: '%s'\n", arg);
        return -1;
    }
    return 0;
}

void disk_rmdir(const char *arg)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    struct count c = {0};
    if (old_entry(arg, &k, &v, &e) < 0)
        return;
    if (!(e.attr & 0x10) || !e.cluster) {
        uprintf("rmdir: not a directory: %s\n", e.name);
        return;
    }
    if (cwd.k == k && cwd.v == v && cwd.cluster == e.cluster) {
        uprintf("rmdir: the current directory ('cd ..' first)\n");
        return;
    }
    if (dir_walk(k, v, e.cluster, count_fn, &c) < 0) {
        uprintf("a sector did not read: %s\n", usb_error_text());
        return;
    }
    if (c.n) {
        uprintf("rmdir: not empty: %s\n", e.name);
        return;
    }
    if (!writable(k) || fsinfo_unknown(k, v) < 0)
        return;
    if (delete_slots(k, &e) < 0 || free_chain(k, v, e.cluster) < 0) {
        uprintf("rmdir: %s\n", usb_error_text());
        return;
    }
    sync_disk(k);
}

void disk_rm(const char *arg)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    if (old_entry(arg, &k, &v, &e) < 0)
        return;
    if (e.attr & 0x10) {
        uprintf("rm: a directory ('rmdir' removes an empty one): %s\n", e.name);
        return;
    }
    if (e.attr & 0x01) {
        uprintf("rm: read-only: %s\n", e.name);
        return;
    }
    if (!writable(k) || fsinfo_unknown(k, v) < 0)
        return;
    if (delete_slots(k, &e) < 0 || (e.cluster && free_chain(k, v, e.cluster) < 0)) {
        uprintf("rm: %s\n", usb_error_text());
        return;
    }
    sync_disk(k);
}

/* ---- a file's data: 'command > path' / '>>', cp, mv ---- */

/* a file being written: its clusters and size, where its 8.3 entry is; the
   sector being filled, and up to 8 full ones that follow each other on the
   disk, waiting to be written in one go */
struct wfile {
    struct disk *k;
    struct volume *v;
    u32 first, last, count;             /* its first and last cluster, how many (0: none yet) */
    u32 old_last;                       /* (adding to it: its last cluster before) */
    u32 size;                           /* its bytes so far */
    u32 ent_lba;                        /* its 8.3 entry: that sector, the place in it */
    u16 ent_off;
    u32 cur_lba;                        /* the sector byte `size` goes into, in cur when cur_ready */
    int cur_ready;
    u32 q_lba, q_n;                     /* q_n sectors in q, from q_lba on */
    u8 cur[SECTOR];
    u8 q[8 * SECTOR];
};

static struct wfile wf;                 /* (one file written at a time) */

/* an 8.3 entry given its first cluster and size, the time written (the box's
   fixed one) and the archive bit */
static int entry_set(struct disk *k, const struct volume *v, u32 lba, u16 off, u32 cluster, u32 size)
{
    if (read_sectors(k, lba, 1, wbuf) < 0)
        return -1;
    u8 *d = wbuf + off;
    d[11] |= 0x20;
    put16(d + 18, FAT_DATE);
    put16(d + 20, (u16)(v->fat == 32 ? cluster >> 16 : 0));
    put16(d + 22, FAT_TIME);
    put16(d + 24, FAT_DATE);
    put16(d + 26, (u16)cluster);
    put32(d + 28, size);
    return write_sectors(k, lba, 1, wbuf);
}

static int wf_flush(struct wfile *f)
{
    if (f->q_n && write_sectors(f->k, f->q_lba, f->q_n, f->q) < 0)
        return -1;
    f->q_n = 0;
    return 0;
}

/* the sector being filled, into the queue (written when the next one is not
   right after it on the disk, or 8 wait) */
static int wf_queue(struct wfile *f)
{
    if (f->q_n && (f->q_n == 8 || f->cur_lba != f->q_lba + f->q_n) && wf_flush(f) < 0)
        return -1;
    if (!f->q_n)
        f->q_lba = f->cur_lba;
    for (int i = 0; i < SECTOR; i++)
        f->q[f->q_n * SECTOR + i] = f->cur[i];
    f->q_n++;
    f->cur_ready = 0;
    return 0;
}

/* the sector byte `size` goes into: a cluster added to the chain when it
   begins one; when it begins in the middle of a sector (adding to a file),
   the bytes before it read */
static int wf_sector(struct wfile *f)
{
    struct volume *v = f->v;
    u32 csize = (u32)v->spc * SECTOR, in = f->size % csize;
    if (!in && f->size / csize >= f->count) {
        u32 c = fat_alloc(f->k, v);
        if (!c)
            return -1;
        if (f->last && fat_set(f->k, v, f->last, c) < 0) {
            (void)fat_set(f->k, v, c, 0);
            return -1;
        }
        if (!f->first)
            f->first = c;
        f->last = c;
        f->count++;
    }
    f->cur_lba = cluster_sector(v, f->last) + in / SECTOR;
    if (f->size % SECTOR) {
        if (read_sectors(f->k, f->cur_lba, 1, f->cur) < 0)
            return -1;
    } else {
        for (int i = 0; i < SECTOR; i++)
            f->cur[i] = 0;
    }
    f->cur_ready = 1;
    return 0;
}

static int wf_put(struct wfile *f, const u8 *data, u32 n)
{
    for (u32 i = 0; i < n; i++) {
        if (!f->cur_ready && wf_sector(f) < 0)
            return -1;
        f->cur[f->size % SECTOR] = data[i];
        f->size++;
        if (!(f->size % SECTOR) && wf_queue(f) < 0)
            return -1;
    }
    return 0;
}

/* the rest written, then the entry: its first cluster and size */
static int wf_close(struct wfile *f)
{
    if (f->cur_ready && wf_queue(f) < 0)
        return -1;
    if (wf_flush(f) < 0 || entry_set(f->k, f->v, f->ent_lba, f->ent_off, f->first, f->size) < 0)
        return -1;
    sync_disk(f->k);
    return 0;
}

/* a write that failed: the clusters it added freed again (as far as the disk
   still answers) */
static void wf_abort(struct wfile *f)
{
    if (f->old_last) {
        u32 added = next_cluster(f->k, f->v, f->old_last);
        if (added && fat_set(f->k, f->v, f->old_last, fat_end(f->v)) == 0)
            (void)free_chain(f->k, f->v, added);
    } else if (f->first) {
        (void)free_chain(f->k, f->v, f->first);
    }
}

/* `arg` opened for writing: made when it is not there, emptied (`append` 0)
   or to be added to (1) when it is a file; 0, or -1 (said why) */
static int wf_open(struct wfile *f, const char *arg, int append, const char *verb)
{
    static struct entry parent, e;
    static char name[NAME_MAX];
    static u8 ents[SLOTS_MAX][32];
    f->first = f->last = f->count = f->old_last = f->size = f->q_n = 0;
    f->cur_ready = 0;
    int there = new_place(arg, verb, &f->k, &f->v, &parent, name, &e);
    if (there < 0)
        return -1;
    struct disk *k = f->k;
    struct volume *v = f->v;
    if (there && (e.attr & 0x10)) {
        uprintf("%s: a directory: %s\n", verb, e.name);
        return -1;
    }
    if (there && (e.attr & 0x01)) {
        uprintf("%s: read-only: %s\n", verb, e.name);
        return -1;
    }
    if (!writable(k) || fsinfo_unknown(k, v) < 0)
        return -1;
    if (!there) {
        int n = make_entry(k, v, parent.cluster, name, 0x20, 0, 0, ents);
        if (n < 0 || dir_put(k, v, parent.cluster, ents, n, &f->ent_lba, &f->ent_off) < 0) {
            uprintf("%s: not made (%s)\n", verb, usb_error_text());
            return -1;
        }
        return 0;
    }
    f->ent_lba = e.slot_lba[e.slots - 1];
    f->ent_off = e.slot_off[e.slots - 1];
    if (append && e.size) {             /* its last cluster (one after it, if any, freed) */
        u32 csize = (u32)v->spc * SECTOR, need = (e.size + csize - 1) / csize, c = e.cluster;
        for (u32 i = 1; i < need && c; i++)
            c = next_cluster(k, v, c);
        if (c < 2) {
            uprintf("%s: %s's cluster chain is shorter than its size\n", verb, e.name);
            return -1;
        }
        u32 tail = next_cluster(k, v, c);
        if (tail && (fat_set(k, v, c, fat_end(v)) < 0 || free_chain(k, v, tail) < 0))
            goto failed;
        f->first = e.cluster;
        f->last = f->old_last = c;
        f->count = need;
        f->size = e.size;
        return 0;
    }
    if (e.cluster && (entry_set(k, v, f->ent_lba, f->ent_off, 0, 0) < 0 || free_chain(k, v, e.cluster) < 0))
        goto failed;                    /* (emptied: the entry first, then its clusters freed) */
    return 0;
failed:
    uprintf("%s: %s\n", verb, usb_error_text());
    return -1;
}

/* 'command > path' (and '>>'): what the command printed into the file */
void disk_write_file(const char *path, const u8 *data, u32 len, int append)
{
    const char *verb = append ? ">>" : ">";
    if (wf_open(&wf, path, append, verb) < 0)
        return;
    if (wf_put(&wf, data, len) < 0 || wf_close(&wf) < 0) {
        uprintf("%s: %s\n", verb, usb_error_text());
        wf_abort(&wf);
    }
}

static int is_dots(const char *n)
{
    return n[0] == '.' && (!n[1] || (n[1] == '.' && !n[2]));
}

/* the path `to` names, a directory there: with "/name" added (into it) */
static const char *target_of(const char *to, const char *name)
{
    static char t[PATH_MAX + NAME_MAX + 2];
    static struct entry d;
    struct disk *k;
    struct volume *v;
    u32 dir;
    const char *from;
    int n = 0;
    for (; to[n] && n < PATH_MAX; n++)
        t[n] = to[n];
    t[n] = 0;
    const char *path = locate(to, &k, &v, &dir, &from);
    if (!path)
        return 0;
    quiet = 1;
    int is_dir = walk_path(k, v, dir, from, path, &d, 0) == 0 && (d.attr & 0x10);
    quiet = 0;
    if (is_dir) {
        if (n && t[n - 1] != '/' && t[n - 1] != ':')
            t[n++] = '/';
        for (const char *s = name; *s && n < PATH_MAX + NAME_MAX; s++)
            t[n++] = *s;
        t[n] = 0;
    }
    return t;
}

/* the same entry (its 8.3 slot) on the same volume? */
static int same_entry(const struct entry *a, const struct entry *b)
{
    return a->slots && b->slots && a->slot_lba[a->slots - 1] == b->slot_lba[b->slots - 1]
           && a->slot_off[a->slots - 1] == b->slot_off[b->slots - 1];
}

/* 'cp <from> <to>': a file copied -- <to> a directory: into it by the same
   name -- from any FAT volume to any, another disk's too; a file there is
   written over */
void disk_cp(const char *src, const char *dst)
{
    struct disk *sk, *tk;
    struct volume *sv, *tv;
    static struct entry se, te;
    static u8 cbuf[8 * SECTOR];
    u32 dir;
    const char *from;
    if (old_entry(src, &sk, &sv, &se) < 0)
        return;
    if (se.attr & 0x10) {
        uprintf("cp: a directory (cp copies files): %s\n", se.name);
        return;
    }
    const char *target = target_of(dst, se.name);
    if (!target)
        return;
    const char *tpath = locate(target, &tk, &tv, &dir, &from);
    quiet = 1;
    int there = tpath && walk_path(tk, tv, dir, from, tpath, &te, 0) == 0;
    quiet = 0;
    if (there && tk == sk && tv == sv && same_entry(&te, &se)) {
        uprintf("cp: the same file: %s\n", se.name);
        return;
    }
    if (wf_open(&wf, target, 0, "cp") < 0)
        return;
    u32 left = se.size, c = se.cluster, in = 0, steps = 0;
    while (left) {
        if (c < 2 || c >= sv->clusters + 2 || steps > sv->clusters) {
            uprintf("cp: %s's cluster chain ends early\n", se.name);
            wf_abort(&wf);
            return;
        }
        u32 n = sv->spc - in < 8 ? sv->spc - in : 8, bytes = n * SECTOR;
        if (bytes > left) {
            bytes = left;
            n = (bytes + SECTOR - 1) / SECTOR;
        }
        if (read_sectors(sk, cluster_sector(sv, c) + in, n, cbuf) < 0 || wf_put(&wf, cbuf, bytes) < 0)
            goto failed;
        left -= bytes;
        in += n;
        if (in == sv->spc) {
            in = 0;
            steps++;
            if (left)
                c = next_cluster(sk, sv, c);
        }
        if (uart_getc() == 3) {         /* Ctrl-C: what was copied stays, a shorter file */
            uprintf("^C (%u of %u bytes copied)\n", se.size - left, se.size);
            break;
        }
    }
    if (wf_close(&wf) == 0)
        return;
failed:
    uprintf("cp: %s\n", usb_error_text());
    wf_abort(&wf);
}

/* the directory above directory `c` (its '..'; 0: the root) into *up */
static int parent_of(struct disk *k, const struct volume *v, u32 c, u32 *up)
{
    if (read_sectors(k, cluster_sector(v, c), 1, wbuf2) < 0)
        return -1;
    const u8 *d = wbuf2 + 32;
    *up = d[0] == '.' && d[1] == '.' ? le16(d + 26) | (v->fat == 32 ? (u32)le16(d + 20) << 16 : 0) : 0;
    if (v->fat == 32 && *up == v->root_cluster)
        *up = 0;
    return 0;
}

static void cwd_text_set(void)
{
    struct disk *k = cwd.k;
    int first = 1;                      /* the disk's first FAT volume: "n:", another "n.p:" */
    for (int i = 0; i < k->volumes; i++)
        if (k->vol[i].fs == FS_FAT) {
            first = &k->vol[i] == cwd.v;
            break;
        }
    if (first)
        usnprintf(cwd_text, sizeof(cwd_text), "%u:%s", k->device, cwd.path);
    else
        usnprintf(cwd_text, sizeof(cwd_text), "%u.%u:%s", k->device, cwd.v->number, cwd.path);
}

/* 'mv <from> <to>': a file or directory renamed, or moved into another
   directory of the same volume (<to> a directory: into it); its dates kept,
   a directory's '..' pointed at its new place */
void disk_mv(const char *src, const char *dst)
{
    struct disk *k, *tk;
    struct volume *v, *tv;
    static struct entry se, te, parent;
    static char name[NAME_MAX], old_path[PATH_MAX], new_path[PATH_MAX];
    static u8 ents[SLOTS_MAX][32];
    u32 dir;
    const char *from;
    const char *spath = locate(src, &k, &v, &dir, &from);
    if (!spath || walk_path(k, v, dir, from, spath, &se, old_path) < 0)
        return;
    if (!se.slots || is_dots(se.name)) {
        uprintf("not that one: '%s'\n", src);
        return;
    }
    const char *target = target_of(dst, se.name);
    if (!target)
        return;
    int there = new_place(target, "mv", &tk, &tv, &parent, name, &te);
    if (there < 0)
        return;
    if (tk != k || tv != v) {
        uprintf("mv: to another volume ('cp', then 'rm')\n");
        return;
    }
    if (there && !same_entry(&te, &se)) {
        uprintf("mv: '%s' exists\n", te.name);
        return;
    }
    if (there && name_is(se.name, name, path_len(name)) && path_len(name) == path_len(se.name)) {
        int i = 0;
        while (name[i] && name[i] == se.name[i])
            i++;
        if (!name[i] && !se.name[i])
            return;                     /* (the same name: nothing to do) */
    }
    if (se.attr & 0x10) {               /* not into itself, nor below it */
        u32 c = parent.cluster;
        for (int steps = 0; c && steps < 256; steps++) {
            if (c == se.cluster) {
                uprintf("mv: a directory into itself: %s\n", se.name);
                return;
            }
            if (parent_of(k, v, c, &c) < 0)
                goto failed;
        }
    }
    if (!writable(k) || fsinfo_unknown(k, v) < 0)
        return;
    int n = make_entry(k, v, parent.cluster, name, se.attr, se.cluster, se.size, ents);
    if (n < 0)
        return;
    if (read_sectors(k, se.slot_lba[se.slots - 1], 1, wbuf) < 0)
        goto failed;
    const u8 *old = wbuf + se.slot_off[se.slots - 1];
    for (int i = 13; i < 20; i++)       /* its times and dates as they were */
        ents[n - 1][i] = old[i];
    for (int i = 22; i < 26; i++)
        ents[n - 1][i] = old[i];
    if (dir_put(k, v, parent.cluster, ents, n, 0, 0) < 0)
        goto failed;
    if ((se.attr & 0x10) && se.cluster) {   /* a directory: its '..' */
        u32 lba = cluster_sector(v, se.cluster);
        if (read_sectors(k, lba, 1, wbuf) < 0)
            goto failed;
        u8 *d = wbuf + 32;
        u32 up = v->fat == 32 && parent.cluster == v->root_cluster ? 0 : parent.cluster;   /* (the root: 0) */
        if (d[0] == '.' && d[1] == '.') {
            put16(d + 26, (u16)up);
            put16(d + 20, (u16)(v->fat == 32 ? up >> 16 : 0));
            if (write_sectors(k, lba, 1, wbuf) < 0)
                goto failed;
        }
    }
    if (delete_slots(k, &se) < 0)
        goto failed;
    sync_disk(k);
    if ((se.attr & 0x10) && cwd.k == k && cwd.v == v) {     /* the current directory's path, if it moved */
        int ol = path_len(old_path), pl = path_len(place_path), m = 0;
        int under = 1;
        for (int i = 0; i < ol; i++)
            if (cwd.path[i] != old_path[i])
                under = 0;
        if (under && (cwd.path[ol] == 0 || cwd.path[ol] == '/')) {
            for (int i = 0; i < pl && m < PATH_MAX - 1; i++)
                new_path[m++] = place_path[i];
            if (m > 1 && m < PATH_MAX - 1)
                new_path[m++] = '/';
            for (const char *s = name; *s && m < PATH_MAX - 1; s++)
                new_path[m++] = *s;
            for (const char *s = cwd.path + ol; *s && m < PATH_MAX - 1; s++)
                new_path[m++] = *s;
            new_path[m] = 0;
            for (int i = 0; i <= m; i++)
                cwd.path[i] = new_path[i];
            cwd_text_set();
        }
    }
    return;
failed:
    uprintf("mv: %s\n", usb_error_text());
}
