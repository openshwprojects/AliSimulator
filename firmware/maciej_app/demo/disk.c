/* USB mass storage: the sectors of a stick, a card reader's card or a USB
   disk -- the bulk-only transport (a 31-byte command block wrapper out
   through the controller's endpoint A, the data and the 13-byte status
   wrapper in through endpoint B) with SCSI commands (INQUIRY, TEST UNIT
   READY, REQUEST SENSE, READ CAPACITY(10), READ(10)) -- and the FAT file
   systems on them: FAT12, FAT16 and FAT32 with long file names, read only.
   Partitions come from an MBR (its four primary entries) or a GPT; NTFS and
   exFAT are recognised but not read.

   usb.c hands over every device with a bulk-only SCSI interface
   (disk_attach), and the commands use them: 'disks', 'ls', 'cat', 'sector'.
   A disk is named by its USB device address, as lsusb lists it: 'ls 4:/docs'
   (and '4.2:' for its second partition); without one the first FAT volume
   found is used.  Only the device's first logical unit is read. */
#include "hw.h"

#define DISKS      4
#define VOLUMES    4
#define SECTOR     512
#define NAME_MAX   128

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

/* one try of a command (see command), waiting up to `wait_ms` for its data
   and for its status: -3 its command block was not taken (the device is
   still in a command of before), -4 no answer to it in time, or one that
   makes no sense (the reset recovery done) */
static int command_once(struct disk *k, const u8 *cb, u8 cb_len, u8 *data, u32 len, u32 wait_ms)
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
    cbw[12] = len ? 0x80 : 0x00;        /* the data comes in */
    cbw[14] = cb_len;
    for (int i = 0; i < cb_len; i++)
        cbw[15 + i] = cb[i];
    if (usb_bulk_out(k->device, k->out_ep, k->maxp, cbw, 31, 2000) < 0) {
        u8 e = usb_last_error();
        return (e & 0x20) ? -1 : -3;    /* no answer: gone; a stall or no end: stuck */
    }
    int got = 0;
    if (len) {
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
    return csw[12] ? -2 : got;
}

/* how long a command's data and status are waited for: the first try
   briefly -- on the box a 64 GB stick (090c:2000) idle for a minute or more
   answered the first command after it with nothing at all (5 times in 5)
   and the next one at once -- the second try as long as a slow device may
   need */
#define FIRST_WAIT_MS 2000
#define WAIT_MS 10000

/* one SCSI command, its data in (`len` bytes at most): the bytes received;
   -1 the transport failed (usb_error_text), -2 the command failed (REQUEST
   SENSE tells why).  A device that does not take the command block is still
   in some command of before: a reset recovery, and the command once more;
   one that does not answer a command in time (or answers nonsense) gets it
   once more after the reset recovery, too */
static int command(struct disk *k, const u8 *cb, u8 cb_len, u8 *data, u32 len)
{
    int r = command_once(k, cb, cb_len, data, len, FIRST_WAIT_MS);
    if (r == -3) {
        reset_recovery(k);
        r = command_once(k, cb, cb_len, data, len, WAIT_MS);
    } else if (r == -4) {
        k->lost++;
        r = command_once(k, cb, cb_len, data, len, WAIT_MS);
    }
    return r == -3 || r == -4 ? -1 : r;
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

/* the cluster after `c` in its chain; 0 at its end (or on an error) */
static u32 next_cluster(struct disk *k, const struct volume *v, u32 c)
{
    u32 n;
    if (c < 2 || c >= v->clusters + 2)
        return 0;
    if (v->fat == 32) {
        if (fat_sector(k, v->fat_start + c * 4 / SECTOR))
            return 0;
        n = le32(fat_cache + c * 4 % SECTOR) & 0x0FFFFFFFu;
    } else if (v->fat == 16) {
        if (fat_sector(k, v->fat_start + c * 2 / SECTOR))
            return 0;
        n = le16(fat_cache + c * 2 % SECTOR);
    } else {
        u32 off = c + c / 2;            /* 12 bits each: two entries in three bytes */
        if (fat_sector(k, v->fat_start + off / SECTOR))
            return 0;
        n = fat_cache[off % SECTOR];
        if (fat_sector(k, v->fat_start + (off + 1) / SECTOR))
            return 0;
        n |= (u32)fat_cache[(off + 1) % SECTOR] << 8;
        n = (c & 1) ? n >> 4 : n & 0xFFF;
    }
    return n >= 2 && n < v->clusters + 2 ? n : 0;
}

struct entry {
    char name[NAME_MAX];                /* the long name, else the 8.3 one */
    char short_name[13];
    u8 attr;
    u32 cluster, size;
    u16 date, time;
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
static int dir_walk(struct disk *k, const struct volume *v, u32 cluster, entry_fn fn, void *ctx)
{
    static struct entry e;
    static const u8 parts[13] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
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
                } else if (!long_ok || seq != next || d[13] != sum) {
                    long_ok = 0;
                    continue;
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
            }
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

/* the entry at `path` ("/a/b"; '/' or "": the root) */
static int lookup(struct disk *k, const struct volume *v, const char *path, struct entry *out)
{
    static struct find f;
    for (int i = 0; i < NAME_MAX; i++)
        out->name[i] = 0;
    out->name[0] = '/';
    out->short_name[0] = 0;
    out->attr = 0x10;
    out->cluster = 0;                   /* the root */
    out->size = 0;
    while (*path) {
        while (*path == '/' || *path == '\\')
            path++;
        if (!*path)
            break;
        int len = 0;
        while (path[len] && path[len] != '/' && path[len] != '\\')
            len++;
        if (!(out->attr & 0x10)) {
            uprintf("not a directory: %s\n", out->name);
            return -1;
        }
        f.want = path;
        f.len = len;
        f.hit = 0;
        if (dir_walk(k, v, out->cluster, find_fn, &f) < 0) {
            uprintf("a sector did not read: %s\n", usb_error_text());
            return -1;
        }
        if (!f.hit) {
            uprintf("not found: ");
            for (int i = 0; i < len; i++)
                uprintf("%c", path[i]);
            uprintf("\n");
            return -1;
        }
        *out = f.found;
        if ((out->attr & 0x10) && !out->cluster)
            out->cluster = 0;           /* ('..' to the root) */
        path += len;
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

/* 'ls [n:][/path]' */
void disk_ls(const char *arg)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    const char *path = where(arg, &k, &v);
    if (!path || lookup(k, v, path, &e) < 0)
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
    const char *path = where(arg, &k, &v);
    if (!path || lookup(k, v, path, &e) < 0)
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
