/* USB mass storage: the sectors of a stick, a card reader's card or a USB
   disk -- the bulk-only transport (a 31-byte command block wrapper out
   through the controller's endpoint A, the data and the 13-byte status
   wrapper in through endpoint B) with SCSI commands (INQUIRY, TEST UNIT
   READY, REQUEST SENSE, READ CAPACITY(10), READ(10), WRITE(10)) -- and the
   FAT file systems on them: FAT12, FAT16 and FAT32 with long file names,
   read and written; NTFS read, and written when its journal is empty or
   clean (the section "NTFS, written"; 'ntfs' tells).  Partitions come from
   an MBR (its four primary entries) or a GPT; exFAT is recognised but not
   read.

   usb.c hands over every device with a bulk-only SCSI interface
   (disk_attach), and the commands use them: 'disks', 'ls', 'cd', 'cat',
   'sum', 'sector', 'mkdir', 'rmdir', 'rm', 'touch', 'cp', 'mv', 'command >
   file'.  A disk is named by its USB device address, as lsusb lists it:
   'ls 4:/docs' (its first FAT volume, else its first NTFS one; '4.2:' its
   second partition); without one the first FAT volume found is used (none:
   the first NTFS one).  Only the device's first logical unit is read. */
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

/* NTFS: a run of an attribute's clusters, `len` of them from virtual cluster `vcn` on at logical cluster
   `lcn` (NO_LCN: a sparse run, read as zeros).  The disk has fewer than 2^32 sectors (READ(10)): clusters
   fit 32 bits */
struct nrun {
    u32 vcn, lcn, len;
};
#define NO_LCN     0xFFFFFFFFu
#define NW_UNKNOWN 0                    /* an NTFS volume's write gate: not looked at yet */
#define NW_OK      1                    /*   passed: the demo writes the volume */
#define NW_REFUSED 2                    /*   not passed: read only */

struct runs {
    struct nrun *r;
    u32 n, max;
};
#define MFT_RUNS   128                  /* $MFT's own pieces at most */

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
    u8 free_known;                      /* free_clusters counted (disk_space), then kept as clusters come and go */
    u32 free_clusters, free_gen, free_changes;  /* (its disk's medium, and NTFS: the changes count, it holds for) */
    char label[34];                     /* FAT: 11 characters, NTFS: 32 */
    /* NTFS */
    const char *problem;                /* why its files are not read (0: they are) */
    u8 nw_state;                        /* is it written?  NW_UNKNOWN until the first write is asked for */
    u8 nw_small;                        /* its free space is in small pieces: the first free one is taken */
    const char *nw_why;                 /* NW_REFUSED: why not */
    u8 csh;                             /* a cluster's sectors as a shift: 512 << csh bytes */
    u8 vcn_shift;                       /* an index block's VCN counts 1 << vcn_shift bytes */
    u32 ntfs_clusters;                  /* the volume's clusters */
    u32 rec_size, idx_size;             /* an MFT record's bytes, an index (INDX) block's */
    struct runs mft;                    /* $MFT's $DATA: where every record is (in mft_run) */
    struct nrun mft_run[MFT_RUNS];
};

struct disk {
    u8 used, device, iface, in_ep, out_ep;
    u16 maxp;
    u8 ready;                           /* its medium answered READ CAPACITY */
    u8 volumes;
    u32 tag;
    u32 blocks, block_size;
    u32 lost;                           /* commands it did not answer in time, sent again */
    u32 lost_reads;                     /* of them READs and the like (data in): QUICK_AFTER of them -> short waits */
    u8 wp;                              /* MODE SENSE's word: 0 not asked, 1 writable, 2 write-protected */
    u8 wrote;                           /* its last command was a WRITE: the next one waits as long as a write
                                           (the device may still be busy with its flash) */
    u8 resent;                          /* a command was sent again since the medium was last looked at: the
                                           next WRITE first compares its first sectors (medium_same) */
    u32 gen;                            /* its generation: new when it is plugged in, taken out, or its medium
                                           changes (FTP's reader and writer stop on their own disk's change) */
    u32 sig, sig_lba;                   /* what probe read: a hash of sector 0 and of sector sig_lba (its first
                                           volume's boot sector; 0 none) */
    char name[32];                      /* INQUIRY's vendor, product, revision */
    const char *problem;                /* why it is not ready */
    struct volume vol[VOLUMES];
};

/* GCC calls these for structure copies and for loops that clear or copy (a player's 2 MB table cleared,
   sound buffers, ...); there is no C library.  Words at a time when both places share their alignment (four
   bytes a store: a 2 MB clear took ~13 ms byte by byte), bytes for the rest */
void *memcpy(void *to, const void *from, unsigned n) __attribute__((optimize("no-tree-loop-distribute-patterns")));
void *memcpy(void *to, const void *from, unsigned n)
{
    u8 *d = to;
    const u8 *s = from;
    if (n >= 8 && !(((u32)d ^ (u32)s) & 3u)) {
        while ((u32)d & 3u) {
            *d++ = *s++;
            n--;
        }
        u32 *dw = (u32 *)d;
        const u32 *sw = (const u32 *)s;
        for (; n >= 16; n -= 16, dw += 4, sw += 4) {
            u32 a = sw[0], b = sw[1], c = sw[2], e = sw[3];
            dw[0] = a;
            dw[1] = b;
            dw[2] = c;
            dw[3] = e;
        }
        for (; n >= 4; n -= 4)
            *dw++ = *sw++;
        d = (u8 *)dw;
        s = (const u8 *)sw;
    }
    while (n--)
        *d++ = *s++;
    return to;
}

void *memset(void *to, int c, unsigned n) __attribute__((optimize("no-tree-loop-distribute-patterns")));
void *memset(void *to, int c, unsigned n)
{
    u8 *d = to;
    if (n >= 8) {
        while ((u32)d & 3u) {
            *d++ = (u8)c;
            n--;
        }
        u32 v = (u8)c;
        v |= v << 8;
        v |= v << 16;
        u32 *dw = (u32 *)d;
        for (; n >= 16; n -= 16, dw += 4) {
            dw[0] = v;
            dw[1] = v;
            dw[2] = v;
            dw[3] = v;
        }
        for (; n >= 4; n -= 4)
            *dw++ = v;
        d = (u8 *)dw;
    }
    while (n--)
        *d++ = (u8)c;
    return to;
}

/* (bytes moved within a buffer: the places may overlap) */
void *memmove(void *to, const void *from, unsigned n) __attribute__((optimize("no-tree-loop-distribute-patterns")));
void *memmove(void *to, const void *from, unsigned n)
{
    u8 *d = to;
    const u8 *s = from;
    if (d < s || d >= s + n)            /* (forward is safe: it never reads what it wrote) */
        return memcpy(to, from, n);
    if (d > s) {
        if (n >= 8 && !(((u32)d ^ (u32)s) & 3u)) {     /* backward, words where aligned */
            while ((u32)(d + n) & 3u) {
                n--;
                d[n] = s[n];
            }
            for (; n >= 4; n -= 4)
                *(u32 *)(d + n - 4) = *(const u32 *)(s + n - 4);
        }
        while (n--)
            d[n] = s[n];
    }
    return to;
}

/* and these (libgcc's) for a 64-bit shift by a count not known when compiling (NTFS's sizes and offsets);
   a constant count is done in line */
u64 __ashldi3(u64 a, int b);
u64 __ashldi3(u64 a, int b)
{
    u32 lo = (u32)a, hi = (u32)(a >> 32);
    if (b >= 32) {
        hi = lo << (b - 32);
        lo = 0;
    } else if (b > 0) {
        hi = hi << b | lo >> (32 - b);
        lo <<= b;
    }
    return (u64)hi << 32 | lo;
}

u64 __lshrdi3(u64 a, int b);
u64 __lshrdi3(u64 a, int b)
{
    u32 lo = (u32)a, hi = (u32)(a >> 32);
    if (b >= 32) {
        lo = hi >> (b - 32);
        hi = 0;
    } else if (b > 0) {
        lo = lo >> b | hi << (32 - b);
        hi >>= b;
    }
    return (u64)hi << 32 | lo;
}

static struct disk disks[DISKS];
static u32 changes;                     /* disks come and go, sectors written: the explorer looks again */
static u32 gens;                        /* the last disk generation given out (struct disk's gen) */

/* the current directory ('cd') */
static struct {
    struct disk *k;                     /* 0: none chosen */
    struct volume *v;
    u32 cluster;                        /* the directory (0: the root) */
    char path[PATH_MAX];                /* "/Docs/sub" ("/" the root) */
} cwd;
static char cwd_text[PATH_MAX + 8];     /* "3:/Docs/sub" ("3.2:/..." on a disk's other volume) */

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

static u64 le64(const u8 *p)
{
    return (u64)le32(p) | (u64)le32(p + 4) << 32;
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
    if (usb_bulk_sync(k->device, k->out_ep, k->in_ep, len && !out) < 0)
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
    if (usb_bulk_out(k->device, k->out_ep, k->maxp, cbw, 31, wait_ms > 2000 ? wait_ms : 2000) < 0) {
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
#define FIRST_READ_WAIT_MS 100          /* a command with data in, on a disk that lost QUICK_AFTER commands: the
                                           same stick lost the first command after a pause most times (6 of 8
                                           small files' `sum`, Ethernet polled or not), and about one READ of 1
                                           sector in 6 back to back -- neither data nor status -- and answered
                                           each at once after a reset recovery; its reads take 2 ms at most, so a
                                           lost one costs about 0.25 s instead of 2.1 s, and one lost twice is
                                           tried a third time.  NOT for every disk: the 05e3:0751 card reader,
                                           busy after FTP's writes, took longer than 100 ms over a READ, and the
                                           reset recovery then wedged it (every command timed out until the bus
                                           was set up again) */
#define QUICK_AFTER 3
#define WAIT_MS 10000

/* why the last disk command failed when that was not the USB transport's doing (usb_error_text) but the
   disk's own answer -- a SCSI error, another medium: its text; 0 the transport (every command starts so) */
static const char *io_said;
static char io_text[48];

static const char *io_error(void)
{
    return io_said ? io_said : usb_error_text();
}

static void io_sense(u8 key, u8 asc)
{
    usnprintf(io_text, sizeof(io_text), "the disk answered an error (sense %x/%02x)", key, asc);
    io_said = io_text;
}

/* one SCSI command, its data in (`len` bytes at most) or, with `out`, out:
   the bytes received (sent); -1 the transport failed (usb_error_text), -2
   the command failed (REQUEST SENSE tells why).  A device that does not take
   the command block is still in some command of before: a reset recovery,
   and the command once more; one that does not answer a command in time (or
   answers nonsense) gets it once more after the reset recovery, too.  A
   command with data out (a WRITE) is sent up to three times, whichever way
   the tries before went: the same sectors with the same bytes, so one the
   device did carry out before its answer was lost is only written again --
   and a write that fails for good is costly (an NTFS volume is read-only from
   then on, until 'ntfs' looked at it again) on a stick that loses a command
   in ten.  Before a command is sent again the device is asked why the try
   before went unanswered (REQUEST SENSE): a card reader whose card was
   changed answers the next command CHECK CONDITION, 6/28 -- when that answer
   is the one lost, sending the command again would run it on the new card
   with what was known of the old one */
static int lost_answer_sense(struct disk *k);

static int transfer(struct disk *k, const u8 *cb, u8 cb_len, u8 *data, u32 len, int out)
{
    io_said = 0;
    int quick = len && !out && k->lost_reads >= QUICK_AFTER;   /* (a disk known to lose reads: short waits --
                                                                   lost writes, a card busy, do not count) */
    int sends = (len && out) || quick ? 3 : 2;
    /* (a write's first try waits as long as a slow device may need: a stick busy writing its flash is not to
       be reset after 2 s -- on the box a 64 GB stick stopped answering for good, until unplugged, when a write
       that had not answered in 2 s was followed by the reset recovery) */
    /* (and so does what follows a write -- SYNCHRONIZE CACHE, the next command whatever it is: the device
       may be busy with that write still, and a command block not taken in 2 s was followed by the reset too) */
    int slow = (len && out) || cb[0] == 0x35 || k->wrote;
    k->wrote = len && out;
    int r = command_once(k, cb, cb_len, data, len, out,
                         slow ? WAIT_MS : quick ? FIRST_READ_WAIT_MS : FIRST_WAIT_MS);
    for (int n = 1; (r == -3 || r == -4) && n < sends; n++) {
        u32 wait = WAIT_MS;
        if (r == -3) {
            reset_recovery(k);          /* (still in a command of before) */
        } else {
            k->lost++;
            k->lost_reads += len && !out;
            if (quick && n == 1)
                wait = FIRST_READ_WAIT_MS;      /* (a second short try first) */
        }
        k->resent = 1;
        if (lost_answer_sense(k))
            return -1;                  /* (the answer lost was "another medium") */
        r = command_once(k, cb, cb_len, data, len, out, wait);
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

static void nw_forget(const struct disk *k);

/* the sense after a command that failed: is the medium another one now (6/28 "the medium may have changed":
   a card reader stays on the bus when its card is changed, nothing attaches it again) or gone (2/3A)?  Then
   everything the demo knew of it is forgotten -- its size, its volumes, what was cached of them, the current
   directory on it, an NTFS volume's write gate and layout -- and nothing more is read or written until the
   next command looks at the disk again (where -> probe).  Said, once: 1.  Any other sense: 0 */
static void medium_forget(struct disk *k, const char *why)
{
    k->ready = 0;
    k->volumes = 0;
    k->wp = 0;
    k->resent = 0;
    k->problem = "its medium was changed";
    k->gen = ++gens;                    /* (FTP's reader and writer of it stop) */
    changes++;                          /* (the explorer lists again) */
    if (fat_cache_disk == k)
        fat_cache_disk = 0;
    if (cwd.k == k)
        cwd.k = 0;
    nw_forget(k);
    uprintf("device %u: %s\n", k->device, why);
    io_said = "its medium was changed";
}

static int medium_changed(struct disk *k, u8 key, u8 asc)
{
    if (!((key == 6 && asc == 0x28) || (key == 2 && asc == 0x3A)))
        return 0;
    medium_forget(k, "the medium was changed (or taken out)");
    return 1;
}

/* a command whose try went unanswered is about to be sent again: why did the device not answer -- was it
   "another medium" (6/28, the answer that was lost)?  Then that: 1.  0 send it again (REQUEST SENSE itself
   is not asked about) */
static int lost_answer_sense(struct disk *k)
{
    static int asking;
    u8 key, asc;
    if (asking || !k->ready)
        return 0;
    asking = 1;
    int r = sense(k, &key, &asc) == 0 && medium_changed(k, key, asc);
    asking = 0;
    return r;
}

/* a READ or WRITE answered CHECK CONDITION: its sense into key, asc -- 0; -1 the medium is taken as another
   one: it is ("medium changed") or why the command failed was lost (REQUEST SENSE not answered, or answered
   "nothing": the reader's 6/28 may have been the answer lost) -- said, the disk looked at again by the next
   command */
static int check_condition(struct disk *k, u8 *key, u8 *asc)
{
    *key = *asc = 0;
    if (sense(k, key, asc) < 0 || (!*key && !*asc)) {
        medium_forget(k, "a command failed and its reason was lost -- the disk is looked at again (its medium may "
                         "have been changed)");
        return -1;
    }
    return medium_changed(k, *key, *asc) ? -1 : 0;
}

/* a hash of the medium's sector 0 and of sector sig_lba (its first volume's boot sector): what tells one card
   from another of the same size (a disk signature, a volume serial number).  0, -1 not read */
static u8 sig_buf[SECTOR];

static int read_sectors(struct disk *k, u32 lba, u32 count, u8 *buf);

static int medium_sig(struct disk *k, u32 *h)
{
    u32 x = 2166136261u;
    for (int i = 0; i < 2; i++) {
        if (i && !k->sig_lba)
            break;
        if (read_sectors(k, i ? k->sig_lba : 0, 1, sig_buf) < 0)
            return -1;
        for (u32 j = 0; j < SECTOR; j++)
            x = (x ^ sig_buf[j]) * 16777619u;
    }
    *h = x;
    return 0;
}

/* before a WRITE, when a command was sent again since the medium was last looked at (its answer lost: it may
   have been the reader's "another medium" -- and a reader may forget that once its reset recovery is done):
   is it the medium probe read?  0; -1 not (said: looked at again), or it does not read */
static int medium_same(struct disk *k)
{
    u32 h;
    k->resent = 0;
    if (medium_sig(k, &h) < 0)
        return -1;
    k->resent = 0;
    if (h != k->sig) {
        medium_forget(k, "its first sectors are not what they were: another medium -- the disk is looked at again");
        return -1;
    }
    return 0;
}

/* READ(10): `count` sectors (8 at most) from `lba` into buf; 0, -1 */
static int read_sectors(struct disk *k, u32 lba, u32 count, u8 *buf)
{
    u8 cb[10];
    if (!k->ready) {
        io_said = "its medium was changed";
        return -1;                      /* (its medium went: the next command looks at the disk again) */
    }
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
        if (check_condition(k, &key, &asc) < 0)
            return -1;
        io_sense(key, asc);
        k->resent = 1;
        if (key != 6)
            return -1;                  /* (a unit attention that is not a new medium -- a reset: once more) */
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

static void ntfs_mount(struct disk *k, struct volume *v);

/* the file system in the volume's first sector (in `sector`) */
static void mount(struct disk *k, struct volume *v)
{
    const u8 *b = sector;
    if (same(b + 3, "NTFS    ", 8)) {
        ntfs_mount(k, v);
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
    /* (FAT32 as it is laid out -- its FAT's size in the 32-bit field, no fixed root -- whatever its cluster
       count: mkfs.fat -F 32 makes volumes under 65525 clusters, which Windows and Linux read as FAT32; by the
       count alone they were FAT16 with an empty root) */
    v->fat = (!le16(b + 22) && !root_entries) ? 32 : v->clusters < 4085 ? 12 : v->clusters < 65525 ? 16 : 32;
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
    if (count > k->blocks - start)
        count = k->blocks - start;      /* (a partition said to end past the disk: as far as the disk goes) */
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
    k->sig_lba = k->volumes ? k->vol[0].start : 0;
    if (medium_sig(k, &k->sig) < 0)
        k->resent = 1;                  /* (not read now: compared before the first WRITE) */
    else
        k->resent = 0;
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

/* are its files read?  FAT, and NTFS that mounted */
static int readable(const struct volume *v)
{
    return v->fs == FS_FAT || (v->fs == FS_NTFS && !v->problem);
}

/* the volume "n:" names: the disk's first FAT volume, else its first NTFS one read (0: none) */
static struct volume *first_volume(struct disk *k)
{
    for (int pass = 0; pass < 2; pass++)
        for (int j = 0; j < k->volumes; j++)
            if (pass ? readable(&k->vol[j]) : k->vol[j].fs == FS_FAT)
                return &k->vol[j];
    return 0;
}

/* "FAT32 'LABEL', 961 MB" ("NTFS 'LABEL', 59379 MB, read-only" once a write was asked for and refused: 'ntfs'
   tells why) into text at `at` */
static int volume_text(int at, const struct volume *v)
{
    at += usnprintf(text + at, (int)sizeof(text) - at, "%s", fs_name(v));
    if ((v->fs == FS_FAT || v->fs == FS_NTFS) && v->label[0])
        at += usnprintf(text + at, (int)sizeof(text) - at, " '%s'", v->label);
    if (v->fs == FS_OTHER && v->part_type)
        at += usnprintf(text + at, (int)sizeof(text) - at, " (type %02x)", v->part_type);
    at += usnprintf(text + at, (int)sizeof(text) - at, ", %u MB", mb(v->sectors));
    if (v->fs == FS_NTFS && readable(v) && v->nw_state == NW_REFUSED)
        at += usnprintf(text + at, (int)sizeof(text) - at, ", read-only");
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
    changes++;
    for (unsigned i = 0; i < sizeof(*k); i++)
        ((u8 *)k)[i] = 0;
    k->used = 1;
    k->gen = ++gens;
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
            disks[i].gen = ++gens;
            changes++;
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
            int at = volume_text(0, v);
            if (v->number)
                at += usnprintf(text + at, (int)sizeof(text) - at, ", from sector %u", v->start);
            if ((v->fs == FS_NTFS || v->fs == FS_EXFAT) && !readable(v))
                usnprintf(text + at, (int)sizeof(text) - at, " (its files are not read%s%s)",
                          v->problem ? ": " : "", v->problem ? v->problem : "");
            if (v->number)
                uprintf("  partition %u: %s\n", v->number, text);
            else
                uprintf("  no partition table: %s\n", text);
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
    u8 attr;                            /* FAT's (0x10 a directory, 0x02 hidden); NTFS: its attributes' low bits */
    u32 cluster, size;                  /* NTFS: cluster is the MFT record */
    u32 size_hi;                        /* NTFS: the size's bits 32..63 */
    u16 date, time;
    u8 slots;                           /* where its slots are (its long name's parts, then the 8.3 one) */
    u32 slot_lba[SLOTS_MAX];            /* (NTFS: one, its record) */
    u16 slot_off[SLOTS_MAX];            /* (NTFS: the record's sequence number as the entry names it) */
    u32 dir;                            /* NTFS: the directory's record the entry was found in */
};

typedef int (*entry_fn)(const struct entry *e, void *ctx);      /* not 0: enough */

/* NTFS: the sequence number an entry read from a directory names its record with -- whoever follows the
   entry to the record compares it: a record let go and taken again has another one (the entry is stale: a
   move or a removal cut off half way, a damaged directory) and is somebody else's file now.  NO_SEQ: not an
   entry from a directory (the root, the current directory, '..') -- nothing to compare */
#define NO_SEQ 0x10000u

static u32 seq_of(const struct entry *e)
{
    return e->slots ? e->slot_off[0] : NO_SEQ;
}

static const char ntfs_stale[] = "NTFS: a stale directory entry (the record it names is another file's now): run "
                                 "chkdsk /f in Windows";

static u8 lfn_checksum(const u8 *d)
{
    u8 s = 0;
    for (int i = 0; i < 11; i++)
        s = (u8)(((s & 1) << 7) + (s >> 1) + d[i]);
    return s;
}

/* why a read failed: 0 a sector did not read (usb_error_text), else what was wrong */
static const char *fail_why;

static int fail(const char *why)
{
    fail_why = why;
    return -1;
}

static void nw_found_sick(const struct volume *v);

/* an entry that names another file's record was followed: said (-1), and the volume is not written any more
   until 'ntfs' looked at it again -- it wants chkdsk */
static int stale(const struct volume *v)
{
    nw_found_sick(v);
    return fail(ntfs_stale);
}

static void say_why(const char *verb)
{
    if (verb)
        uprintf("%s: ", verb);
    if (fail_why)
        uprintf("%s\n", fail_why);
    else
        uprintf("a sector did not read: %s\n", io_error());
}

/* a directory did not read (dir_walk, find_in: -1): a sector -- or, NTFS, what is wrong with it */
static void dir_failed(void)
{
    say_why(0);
}

/* n / d (no libgcc: 64-bit division is not there), the remainder into *rem */
static u64 div64(u64 n, u32 d, u32 *rem)
{
    u64 q = 0, r = 0;
    for (int i = 63; i >= 0; i--) {
        r = r << 1 | ((n >> i) & 1);
        if (r >= d) {
            r -= d;
            q |= (u64)1 << i;
        }
    }
    if (rem)
        *rem = (u32)r;
    return q;
}

/* a 64-bit number in decimal into t (21 bytes at least) */
static const char *dec64(char *t, u64 n)
{
    if (!(n >> 32)) {
        usnprintf(t, 21, "%u", (u32)n);
    } else {
        u32 low;
        char high[21];
        dec64(high, div64(n, 1000000000u, &low));
        usnprintf(t, 21, "%s%09u", high, low);
    }
    return t;
}

/* ---- NTFS, read ----
   An NTFS volume is read through its master file table (MFT): records of 1 KB as a rule, each with a
   file's attributes -- its names ($FILE_NAME), its bytes ($DATA: in the record when they are few, else
   runs of clusters), a directory's index ($INDEX_ROOT and, when that is full, $INDEX_ALLOCATION's INDX
   blocks: a B-tree of $FILE_NAME keys, alphabetical) -- and, for a file whose attributes do not fit one
   record, an $ATTRIBUTE_LIST naming the records the rest is in.  Record 0 ($MFT) says in its own $DATA's
   runs where every record is.  Records and INDX blocks keep each 512-byte stride's last two bytes in their
   header and an update sequence number there instead (the fixups, undone after reading).  A directory is
   named by its record number as a FAT one is by its first cluster (0: the root, record 5); names are
   matched case aside (ASCII), as on FAT; '..' is the parent its $FILE_NAME names.  Compressed and
   encrypted files are refused, sparse ones read (their holes as zeros, as the bytes past the initialized
   size).  Writing is further down ("NTFS, written"): nothing here writes, and write_sectors refuses an NTFS
   volume's sectors to everything but that section's nw_write. */
typedef signed long long s64;

#define REC_MAX    4096                 /* MFT records of 4 KB at most, INDX blocks too */
#define IDX_MAX    4096
#define DEPTH_MAX  6                    /* a directory's B-tree levels below its root */
#define LIST_MAX   (16 * 1024)          /* an attribute list's bytes */
#define DIR_RUNS   1024                 /* a directory's index in this many pieces at most */
#define FILE_RUNS  (NTFS_RUNS_SIZE / sizeof(struct nrun))   /* a file's (at NTFS_RUNS_PHYS: 87381) */
#define MFT_ROOT   5                    /* the root directory's record */

struct nattr {
    u8 resident;                        /* its value in the record (copied out: len bytes) */
    u16 flags;                          /* 0x00FF compressed, 0x4000 encrypted, 0x8000 sparse */
    u64 size, init;                     /* its bytes; how many of them were written (the rest: zeros) */
    u32 len;
};

static u8 nrec[REC_MAX];                /* a file's (base) record */
static u8 nxrec[REC_MAX];               /* another record of it (its attribute list names it) */
static u8 nval[REC_MAX];                /* a resident value: a directory's $INDEX_ROOT, a $FILE_NAME */
static u8 nlist[LIST_MAX];              /* an $ATTRIBUTE_LIST */
static u8 nidx[DEPTH_MAX][IDX_MAX];     /* the INDX blocks on the way down a directory's B-tree */
static u8 file_res[REC_MAX];            /* a small file's bytes (resident) */
static struct nrun dir_run[DIR_RUNS], list_run[64];
static struct runs dir_runs = {dir_run, 0, DIR_RUNS};
static struct runs file_runs = {(struct nrun *)KSEG0(NTFS_RUNS_PHYS), 0, FILE_RUNS};

/* a record's or an INDX block's fixups undone: 0, -1 (damaged, or a write cut off half way) */
static int fixup(u8 *b, u32 size)
{
    u32 off = le16(b + 4), count = le16(b + 6);
    if (count != size / SECTOR + 1 || (off & 1) || off + 2 * count > size)
        return -1;
    for (u32 i = 1; i < count; i++) {
        u8 *end = b + i * SECTOR - 2;
        if (end[0] != b[off] || end[1] != b[off + 1])
            return -1;
        end[0] = b[off + 2 * i];
        end[1] = b[off + 2 * i + 1];
    }
    return 0;
}

/* the run with virtual cluster `vcn` in it (0: none) */
static const struct nrun *run_at(const struct nrun *r, u32 n, u32 vcn)
{
    u32 lo = 0, hi = n;
    while (lo < hi) {
        u32 mid = (lo + hi) / 2;
        if (vcn < r[mid].vcn)
            hi = mid;
        else if (vcn - r[mid].vcn >= r[mid].len)
            lo = mid + 1;
        else
            return &r[mid];
    }
    return 0;
}

/* the sectors one READ takes of the `n` wanted: 8 at most; from a high-speed disk an odd number -- its data
   and its status are then an even number of 512-byte packets, the IN's toggle stays DATA0 (a 090c:2000
   stick lost commands that began at DATA1: usb_bulk_sync) */
static u32 read_count(const struct disk *k, u32 n)
{
    if (n > 8)
        n = 8;
    if (k->maxp == SECTOR && n > 1 && !(n & 1))
        n--;
    return n;
}

/* `count` sectors of an attribute from its byte `off` (a multiple of 512) on, through its runs, into buf
   (sparse runs as zeros): 0, -1 */
static int runs_read(struct disk *k, const struct volume *v, const struct nrun *r, u32 n, u64 off, u32 count,
                     u8 *buf)
{
    u32 csh = v->csh, mask = (1u << csh) - 1;
    while (count) {
        u64 vcn64 = off >> (9 + csh);
        const struct nrun *p = vcn64 >> 32 ? 0 : run_at(r, n, (u32)vcn64);
        if (!p)
            return fail("NTFS: past the end of an attribute's runs");
        u32 vcn = (u32)vcn64, in = (u32)(off >> 9) & mask, now = count < 8 ? count : 8;
        u64 room = ((u64)(p->len - (vcn - p->vcn)) << csh) - in;
        if (room < now)
            now = (u32)room;
        now = read_count(k, now);
        if (p->lcn == NO_LCN) {
            for (u32 i = 0; i < now * SECTOR; i++)
                buf[i] = 0;
        } else if (read_sectors(k, v->start + ((p->lcn + (vcn - p->vcn)) << csh) + in, now, buf) < 0) {
            fail_why = 0;
            return -1;
        }
        buf += now * SECTOR;
        off += now * SECTOR;
        count -= now;
    }
    return 0;
}

/* MFT record `rec` into buf, its fixups undone: 0, -1 */
static int mft_read(struct disk *k, const struct volume *v, u32 rec, u8 *buf)
{
    if (runs_read(k, v, v->mft.r, v->mft.n, (u64)rec * v->rec_size, v->rec_size / SECTOR, buf) < 0)
        return -1;
    if (!same(buf, "FILE", 4) || fixup(buf, v->rec_size) < 0 || (le16(buf + 4) >= 0x30 && le32(buf + 0x2C) != rec))
        return fail("NTFS: a damaged MFT record");
    if (!(le16(buf + 0x16) & 1))
        return fail("NTFS: an MFT record not in use (a file deleted?)");
    return 0;
}

/* the attribute after the one at `at` (0: the first) in a record: its offset, 0 after the last */
static u32 attr_next(const struct volume *v, const u8 *rec, u32 at)
{
    u32 used = le32(rec + 0x18) < v->rec_size ? le32(rec + 0x18) : v->rec_size;
    at = at ? at + le32(rec + at + 4) : le16(rec + 0x14);
    if (at < 0x18 || at + 8 > used || le32(rec + at) == 0xFFFFFFFFu)
        return 0;
    u32 len = le32(rec + at + 4);
    if (len < 0x18 || (len & 7) || len > used - at)
        return 0;
    return at;
}

/* is the UTF-16 name of `n` characters at base + off (room bytes there) `name`? */
static int named(const u8 *base, u32 n, u32 off, u32 room, const char *name)
{
    if (off + 2 * n > room)
        return 0;
    for (u32 i = 0; i < n; i++)
        if (!name[i] || le16(base + off + 2 * i) != (u8)name[i])
            return 0;
    return !name[n];
}

/* a non-resident attribute piece's runs (its header at h) added to *runs (they go on from where the runs
   before end): 0, -1 */
static int runs_add(const struct volume *v, const u8 *h, struct runs *runs)
{
    u32 hlen = le32(h + 4), at = le16(h + 0x20);
    u64 vcn = le64(h + 0x10), last = le64(h + 0x18);
    struct nrun *prev = runs->n ? &runs->r[runs->n - 1] : 0;
    s64 lcn = 0;
    if (vcn != (prev ? (u64)prev->vcn + prev->len : 0))
        return fail("NTFS: an attribute's pieces do not follow each other");
    while (at < hlen && h[at]) {
        u32 ls = h[at] & 15, os = h[at] >> 4;
        if (!ls || ls > 8 || os > 8 || at + 1 + ls + os > hlen)
            return fail("NTFS: damaged runs");
        u64 len = 0, delta = 0;
        for (u32 i = 0; i < ls; i++)
            len |= (u64)h[at + 1 + i] << (8 * i);
        for (u32 i = 0; i < os; i++)
            delta |= (u64)h[at + 1 + ls + i] << (8 * i);
        if (os && os < 8 && (h[at + ls + os] & 0x80))
            delta |= ~(u64)0 << (8 * os);   /* (a negative offset) */
        at += 1 + ls + os;
        if (!len || vcn + len > 0xFFFFFFFFull)
            return fail("NTFS: an attribute too big for the demo");
        u32 lcn32 = NO_LCN;
        if (os) {                       /* (none: a sparse run) */
            lcn += (s64)delta;
            if (lcn < 0 || (u64)lcn + len > v->ntfs_clusters)
                return fail("NTFS: a run outside the volume");
            lcn32 = (u32)lcn;
        }
        if (prev && (prev->lcn == NO_LCN ? lcn32 == NO_LCN : lcn32 == prev->lcn + prev->len)) {
            prev->len += (u32)len;      /* (on from the run before: one run) */
        } else {
            if (runs->n >= runs->max)
                return fail("NTFS: a file in too many pieces for the demo");
            prev = &runs->r[runs->n++];
            prev->vcn = (u32)vcn;
            prev->lcn = lcn32;
            prev->len = (u32)len;
        }
        vcn += len;
    }
    if (vcn != last + 1)
        return fail("NTFS: an attribute's runs do not match its size");
    return 0;
}

/* an attribute's piece (its header at h) taken: the first one's sizes and flags into *a (resident: its
   value into val, cap bytes at most), the runs of each added to *runs (0: not wanted): 1, -1 */
static int attr_take(const u8 *h, int first, struct nattr *a, u8 *val, u32 cap, const struct volume *v,
                     struct runs *runs)
{
    if (first) {
        a->resident = !h[8];
        a->flags = le16(h + 0x0C);
        if (a->resident) {
            u32 len = le32(h + 0x10), off = le16(h + 0x14);
            if (off + len > le32(h + 4) || (val && len > cap))
                return fail("NTFS: a damaged attribute");
            for (u32 i = 0; val && i < len; i++)
                val[i] = h[off + i];
            a->len = len;
            a->size = a->init = len;
            return 1;
        }
        if (le32(h + 4) < 0x40)
            return fail("NTFS: a damaged attribute");
        a->len = 0;
        a->size = le64(h + 0x30);
        a->init = le64(h + 0x38);
    } else if (!h[8] || a->resident || le32(h + 4) < 0x40) {
        return fail("NTFS: a damaged attribute list");
    }
    return runs && runs_add(v, h, runs) < 0 ? -1 : 1;
}

/* an $ATTRIBUTE_LIST's value (its header at h) into nlist: its bytes, -1 */
static int list_read(struct disk *k, const struct volume *v, const u8 *h)
{
    static struct runs lr = {list_run, 0, 64};
    if (!h[8]) {
        u32 len = le32(h + 0x10), off = le16(h + 0x14);
        if (len > LIST_MAX || off + len > le32(h + 4))
            return fail("NTFS: a damaged attribute list");
        for (u32 i = 0; i < len; i++)
            nlist[i] = h[off + i];
        return (int)len;
    }
    u64 size = le64(h + 0x30);
    if (size > LIST_MAX)
        return fail("NTFS: an attribute list too long for the demo");
    lr.n = 0;
    if (runs_add(v, h, &lr) < 0 || runs_read(k, v, lr.r, lr.n, 0, ((u32)size + SECTOR - 1) / SECTOR, nlist) < 0)
        return -1;
    return (int)size;
}

/* attribute `type` named `name` ("" unnamed) of the file whose base record (number rec) is in `base`:
   1 there -- its sizes and flags into *a; resident: its value into val (cap bytes at most); non-resident:
   its runs into *runs (when not 0), every piece of it, through the attribute list when the file has one --
   0 not there, -1 not read (fail_why).  It may read records into nxrec */
static int ntfs_attr(struct disk *k, const struct volume *v, const u8 *base, u32 rec, u32 type, const char *name,
                     struct nattr *a, u8 *val, u32 cap, struct runs *runs)
{
    u32 at, list = 0;
    for (at = 0; !list && (at = attr_next(v, base, at));)
        if (le32(base + at) == 0x20)
            list = at;
    if (runs)
        runs->n = 0;
    if (!list) {
        for (at = 0; (at = attr_next(v, base, at));)
            if (le32(base + at) == type && named(base + at, base[at + 9], le16(base + at + 10), le32(base + at + 4), name))
                return attr_take(base + at, 1, a, val, cap, v, runs);
        return 0;
    }
    int len = list_read(k, v, base + list), found = 0;
    if (len < 0)
        return -1;
    for (u32 p = 0; p + 0x1A <= (u32)len;) {    /* (the list is in the order of type, name, first VCN) */
        const u8 *e = nlist + p;
        u32 elen = le16(e + 4);
        if (elen < 0x1A || p + elen > (u32)len)
            return fail("NTFS: a damaged attribute list");
        p += elen;
        if (le32(e) != type || !named(e, e[6], e[7], elen, name))
            continue;
        u32 seg = le32(e + 0x10);
        const u8 *r = base, *h = 0;
        if (seg != rec) {
            if (le16(e + 0x14))
                return fail("NTFS: a damaged attribute list");
            if (mft_read(k, v, seg, nxrec) < 0)
                return -1;
            if (le32(nxrec + 0x20) != rec)
                return fail("NTFS: a record its attribute list names is not its own");
            r = nxrec;
        }
        for (u32 x = 0; !h && (x = attr_next(v, r, x));)
            if (le32(r + x) == type && le16(r + x + 0x0E) == le16(e + 0x18))
                h = r + x;
        if (!h)
            return fail("NTFS: an attribute its attribute list names is not there");
        if (attr_take(h, !found, a, val, cap, v, runs) < 0)
            return -1;
        found = 1;
        if (a->resident)
            return 1;
    }
    return found;
}

/* a UTF-16 name as the demo's ASCII: what is not printable ASCII as '?' (as FAT's long names) */
static void name_text(char *to, int room, const u8 *from, u32 n)
{
    u32 i = 0;
    for (; i < n && (int)i < room - 1; i++) {
        u16 c = le16(from + 2 * i);
        to[i] = c >= 32 && c < 127 ? (char)c : '?';
    }
    to[i] = 0;
}

/* the volume's first sector (in `sector`) is NTFS's: its geometry, $MFT's runs, its label; v->problem says
   why its files are not read when they are not */
static void ntfs_mount(struct disk *k, struct volume *v)
{
    const u8 *b = sector;
    u32 spc = b[13], csh = 0;
    u64 total = le64(b + 0x28), mft = le64(b + 0x30);
    s32 per_rec = (signed char)b[0x40], per_idx = (signed char)b[0x44];
    struct nattr a;
    v->fs = FS_NTFS;
    v->label[0] = 0;
    v->mft.r = v->mft_run;
    v->mft.n = 0;
    v->mft.max = MFT_RUNS;
    v->problem = "its boot sector is not one the demo reads";
    if (le16(b + 11) != SECTOR) {
        v->problem = "its sectors are not 512 bytes";
        return;
    }
    if (spc > 0x80 && 256 - spc >= 9 && 256 - spc <= 21) {
        csh = 256 - spc - 9;            /* (clusters over 64 KB: 2^(256 - n) bytes) */
    } else if (spc && spc <= 0x80 && !(spc & (spc - 1))) {
        while ((1u << csh) < spc)
            csh++;
    } else {
        return;
    }
    u32 cshift = 9 + csh;               /* a cluster's bytes as a shift */
    u32 rec = per_rec > 0 ? (per_rec <= 8 ? (u32)per_rec << cshift : 0) : per_rec <= -9 && per_rec >= -12 ? 1u << -per_rec : 0;
    u32 idx = per_idx > 0 ? (per_idx <= 8 ? (u32)per_idx << cshift : 0) : per_idx <= -9 && per_idx >= -12 ? 1u << -per_idx : 0;
    if (!rec || rec > REC_MAX || (rec & (rec - 1)) || !idx || idx > IDX_MAX || (idx & (idx - 1))) {
        v->problem = "its MFT or index records are over 4 KB";
        return;
    }
    if (total > v->sectors || mft >= (total >> csh))
        return;
    v->csh = (u8)csh;
    v->ntfs_clusters = (u32)(total >> csh);
    v->rec_size = rec;
    v->idx_size = idx;
    v->vcn_shift = (u8)(idx >= (1u << cshift) ? cshift : 9);
    /* record 0 where the boot sector says the MFT starts; its $DATA says where every record is */
    v->mft_run[0].vcn = 0;
    v->mft_run[0].lcn = (u32)mft;
    v->mft_run[0].len = (16 * rec) >> cshift ? (16 * rec) >> cshift : 1;
    v->mft.n = 1;
    if (mft_read(k, v, 0, nrec) < 0 || ntfs_attr(k, v, nrec, 0, 0x80, "", &a, 0, 0, &v->mft) != 1 || a.resident) {
        v->mft.n = 0;
        v->problem = "its MFT does not read";
        return;
    }
    v->problem = 0;
    /* the label: record 3, $Volume, its $VOLUME_NAME */
    if (mft_read(k, v, 3, nrec) == 0 && ntfs_attr(k, v, nrec, 3, 0x60, "", &a, nval, REC_MAX, 0) == 1 && a.resident)
        name_text(v->label, sizeof(v->label), nval, a.len / 2);
}

/* ---- the calendar (as net.c's: proleptic Gregorian from 1970, H. Hinnant's days <-> civil date) ---- */
static void civil(u32 days, u32 *y, u32 *m, u32 *d)
{
    u32 z = days + 719468, era = z / 146097, doe = z - era * 146097;
    u32 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    u32 doy = doe - (365 * yoe + yoe / 4 - yoe / 100), mp = (5 * doy + 2) / 153;
    *d = doy - (153 * mp + 2) / 5 + 1;
    *m = mp < 10 ? mp + 3 : mp - 9;
    *y = yoe + era * 400 + (*m <= 2);
}

static u32 days_of(u32 y, u32 m, u32 d)
{
    y -= m <= 2;
    u32 era = y / 400, yoe = y - era * 400;
    u32 doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    return era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
}

/* Europe/Warsaw (as 'date'): CEST from the last Sunday of March 01:00 UTC to the last Sunday of October */
static int summer_time(u32 t)
{
    u32 y, m, d;
    civil(t / 86400, &y, &m, &d);
    u32 march = days_of(y, 3, 31), october = days_of(y, 10, 31);
    march -= (march + 4) % 7;
    october -= (october + 4) % 7;
    return t >= march * 86400 + 3600 && t < october * 86400 + 3600;
}

/* an NTFS time (100 ns since 1601, UTC) as FAT's date and time in Polish time (Windows shows its local
   time); before 1980 (FAT's first year): 1980-01-01 00:00 */
static void ntfs_time(u64 ft, u16 *date, u16 *time)
{
    u64 s = div64(ft, 10000000u, 0);
    *date = (1 << 5) | 1;
    *time = 0;
    if (s < 11644473600ull + 315532800u)            /* (1601 to 1970, 1970 to 1980) */
        return;
    s -= 11644473600ull;
    u32 t = s > 0xFFFFFFFFu - 7200 ? 0xFFFFFFFFu - 7200 : (u32)s, y, m, d;
    t += summer_time(t) ? 7200 : 3600;
    civil(t / 86400, &y, &m, &d);
    u32 sec = t % 86400;
    *date = (u16)((y - 1980) << 9 | m << 5 | d);
    *time = (u16)((sec / 3600) << 11 | (sec / 60 % 60) << 5 | (sec % 60) / 2);
}

/* a directory being walked: its index blocks' runs in dir_runs */
struct nwalk {
    struct disk *k;
    const struct volume *v;
    entry_fn fn;
    void *ctx;
    u32 dir;                            /* the directory's record */
    u64 alloc;                          /* $INDEX_ALLOCATION's bytes (0: the root holds every entry) */
    u32 visits, max_visits;             /* INDX blocks read; at most each once (a damaged index whose blocks
                                           point back at each other would be walked for ever, the watchdog fed) */
};

/* an index entry's file to fn (not its DOS name -- the long one has an entry of its own --, not the
   metafiles nor the root's own entry: records below 16): fn's answer */
static int ntfs_entry(struct nwalk *w, const u8 *p)
{
    static struct entry e;
    const u8 *f = p + 0x10;             /* the key: a $FILE_NAME */
    u32 rec = le32(p), n = f[0x40], klen = le16(p + 10);
    if (klen < 0x42 || 0x42 + 2 * n > klen || f[0x41] == 2 || le16(p + 4) || rec < 16)
        return 0;
    name_text(e.name, NAME_MAX, f + 0x42, n);
    e.short_name[0] = 0;
    u32 flags = le32(f + 0x38);         /* (FILE_ATTRIBUTE_*; 0x10000000: a directory's index) */
    e.attr = (u8)((flags & 0x27) | (flags & 0x10000000u ? 0x10 : 0));
    e.cluster = rec;
    e.size = e.attr & 0x10 ? 0 : le32(f + 0x30);
    e.size_hi = e.attr & 0x10 ? 0 : le32(f + 0x34);
    ntfs_time(le64(f + 0x10), &e.date, &e.time);
    e.slots = 1;
    e.slot_lba[0] = rec;
    e.slot_off[0] = le16(p + 6);        /* (the file reference's sequence number: a writer checks the record
                                           still is that file's) */
    e.dir = w->dir;
    return w->fn(&e, w->ctx);
}

static int ntfs_node(struct nwalk *w, const u8 *p, const u8 *end, int depth);

/* the INDX block at `vcn` and the blocks below it, in order: 0, 1 fn stopped, -1 */
static int ntfs_block(struct nwalk *w, u64 vcn, int depth)
{
    const struct volume *v = w->v;
    if (depth > DEPTH_MAX)
        return fail("NTFS: a directory's index too deep for the demo");
    if (++w->visits > w->max_visits)
        return fail("NTFS: a damaged directory index (a block named twice)");
    u8 *b = nidx[depth - 1];
    u64 off = vcn << v->vcn_shift;
    if (off + v->idx_size > w->alloc)
        return fail("NTFS: a damaged directory index");
    if (runs_read(w->k, v, dir_runs.r, dir_runs.n, off, v->idx_size / SECTOR, b) < 0)
        return -1;
    if (!same(b, "INDX", 4) || fixup(b, v->idx_size) < 0 || le64(b + 0x10) != vcn)
        return fail("NTFS: a damaged index block");
    const u8 *h = b + 0x18;             /* its node header: where its entries start, where they end */
    u32 first = le32(h), used = le32(h + 4);
    if (first >= used || 0x18 + used > v->idx_size)
        return fail("NTFS: a damaged index block");
    (void)now_ms();                     /* (the watchdog: a big directory) */
    return ntfs_node(w, h + first, h + used, depth);
}

/* the entries of a B-tree node (from p to end), each after the node below it (in-order: alphabetical) */
static int ntfs_node(struct nwalk *w, const u8 *p, const u8 *end, int depth)
{
    while (p + 0x10 <= end) {
        u32 len = le16(p + 8), flags = le16(p + 12);
        if (len < 0x10 || (len & 7) || len > (u32)(end - p) || le16(p + 10) > len - 0x10)
            return fail("NTFS: a damaged index entry");
        if (flags & 1) {                /* a node below it: its VCN in the entry's last 8 bytes */
            if (len < 0x18 || !w->alloc)
                return fail("NTFS: a damaged index entry");
            int r = ntfs_block(w, le64(p + len - 8), depth + 1);
            if (r)
                return r;
        }
        if (flags & 2)                  /* the node's last entry: no file */
            return 0;
        int r = ntfs_entry(w, p);
        if (r)
            return r;
        p += len;
    }
    return 0;
}

/* every file and directory in directory `dir` (its record; 0 the root) to fn: 1 when fn stopped, 0 at
   the end, -1 not read (fail_why).  fn may not read sectors itself */
static int ntfs_dir_walk(struct disk *k, const struct volume *v, u32 dir, u32 seq, entry_fn fn, void *ctx)
{
    static struct nwalk w;
    struct nattr a;
    if (!dir)
        dir = MFT_ROOT;
    if (mft_read(k, v, dir, nrec) < 0)
        return -1;
    if (seq != NO_SEQ && le16(nrec + 0x10) != seq)
        return stale(v);                /* (the entry that led here names another file) */
    if (!(le16(nrec + 0x16) & 2))
        return fail("NTFS: not a directory");
    int r = ntfs_attr(k, v, nrec, dir, 0x90, "$I30", &a, nval, REC_MAX, 0);
    if (r <= 0 || !a.resident || a.len < 0x20 || le32(nval) != 0x30)
        return r < 0 ? -1 : fail("NTFS: a directory without its index");
    u32 first = le32(nval + 0x10), used = le32(nval + 0x14);  /* the node header at 0x10 */
    if (first >= used || 0x10 + used > a.len)
        return fail("NTFS: a damaged directory index");
    w.k = k;
    w.v = v;
    w.dir = dir;
    w.fn = fn;
    w.ctx = ctx;
    w.alloc = 0;
    w.visits = w.max_visits = 0;
    if (nval[0x1C] & 1) {               /* more than its root holds: INDX blocks */
        r = ntfs_attr(k, v, nrec, dir, 0xA0, "$I30", &a, 0, 0, &dir_runs);
        if (r <= 0 || a.resident)
            return r < 0 ? -1 : fail("NTFS: a directory without its index blocks");
        w.alloc = a.size;
        u32 shift = 0;
        while ((1u << shift) < v->idx_size)
            shift++;
        u64 blocks = a.size >> shift;   /* (idx_size: a power of two, 4 KB at most) */
        w.max_visits = blocks > 0xFFFFFFu ? 0xFFFFFFu : (u32)blocks;
    }
    return ntfs_node(&w, nval + 0x10 + first, nval + 0x10 + used, 0);
}

/* the directory above directory `dir` (its record; 0 the root) from its $FILE_NAME: into *up (0 the root) */
static int ntfs_parent(struct disk *k, const struct volume *v, u32 dir, u32 *up)
{
    struct nattr a;
    *up = 0;
    if (!dir || dir == MFT_ROOT)
        return 0;
    if (mft_read(k, v, dir, nrec) < 0)
        return -1;
    int r = ntfs_attr(k, v, nrec, dir, 0x30, "", &a, nval, REC_MAX, 0);
    if (r <= 0 || !a.resident || a.len < 0x42)
        return r < 0 ? -1 : fail("NTFS: a directory without its name");
    *up = le32(nval) == MFT_ROOT ? 0 : le32(nval);
    return 0;
}

/* every entry of a directory (its first cluster; 0: the FAT12 / FAT16 root)
   to `fn`, with its long name when it has one; 1 when fn stopped, 0 at the
   end, -1 a sector did not read.  `fn` may not read sectors itself.  `seq`:
   seq_of the entry the directory was found through (NTFS compares it) */
static const u8 lfn_at[13] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};   /* a long-name part's 13 characters */

static int dir_walk(struct disk *k, const struct volume *v, u32 cluster, u32 dir_seq, entry_fn fn, void *ctx)
{
    static struct entry e;
    const u8 *parts = lfn_at;
    u8 sum = 0, next = 0, long_ok = 0;
    u32 index = 0, steps = 0;
    fail_why = 0;
    if (v->fs == FS_NTFS)
        return ntfs_dir_walk(k, v, cluster, dir_seq, fn, ctx);
    e.size_hi = 0;
    if (!cluster && v->fat == 32)
        cluster = v->root_cluster;
    if (cluster && (cluster < 2 || cluster >= v->clusters + 2)) {
        fail_why = "a directory's first cluster is outside the volume (a damaged entry)";
        return -1;
    }
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
                if (!seq) {                 /* (no part has number 0: its 13 characters would go in front of
                                               the name's buffer) */
                    long_ok = 0;
                    continue;
                }
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
    int more;                           /* NTFS: names that differ in case only may both be there (they are
                                           next to each other in the index): the one spelled as asked wins */
};

static int name_exact(const char *name, const char *want, int len)
{
    int i = 0;
    for (; i < len; i++)
        if (name[i] != want[i])
            return 0;
    return !name[i];
}

static int find_fn(const struct entry *e, void *ctx)
{
    struct find *f = ctx;
    if ((e->attr & 0x08) || !(name_is(e->name, f->want, f->len) || name_is(e->short_name, f->want, f->len)))
        return f->hit;                  /* (after a match: no more of them) */
    int exact = !f->more || name_exact(e->name, f->want, f->len);
    if (f->hit && !exact)
        return 0;
    f->found = *e;
    f->hit = 1;
    return exact;
}

/* the entry named `want` (`len` characters) in directory `dir` (`seq`: as
   dir_walk's): 1 found (into f->found), 0 not there, -1 a sector did not read */
static int find_in(struct disk *k, const struct volume *v, u32 dir, u32 seq, const char *want, int len,
                   struct find *f)
{
    /* NTFS: the name a directory was last found not to have -- cp and mv ask for a new name two or three
       times before they make it, and each asking reads the directory's whole index.  Good until a sector
       is written or a disk comes or goes (`changes` counts both) */
    static struct {
        const struct disk *k;
        const struct volume *v;
        u32 dir, seq, changes;          /* (seq: as the directory was reached -- a stale entry to the same
                                           record is not answered from here) */
        int len;
        char name[NAME_MAX];
    } absent;
    f->want = want;
    f->len = len;
    f->hit = 0;
    f->more = v->fs == FS_NTFS;
    if (f->more && absent.k == k && absent.v == v && absent.dir == dir && absent.seq == seq
        && absent.changes == changes && absent.len == len && name_exact(absent.name, want, len))
        return 0;
    if (dir_walk(k, v, dir, seq, find_fn, f) < 0)
        return -1;
    if (f->more && !f->hit && len < NAME_MAX) {
        absent.k = k;
        absent.v = v;
        absent.dir = dir;
        absent.seq = seq;
        absent.changes = changes;
        absent.len = len;
        for (int i = 0; i < len; i++)
            absent.name[i] = want[i];
        absent.name[len] = 0;
    }
    return f->hit;
}

/* the entry at `path` from directory `dir`, whose own path is `from` ("/"
   for the root): components split at '/' (or '\'), '.' this one, '..' the
   one above (the root's is the root); its path, with the names as the disk
   spells them, into out_path (PATH_MAX; when not 0).  -1 when it is not
   there (said why) */
static int quiet;                       /* walk_path says nothing (a path only tried) */

/* entry_ok without a word: 0, -1 (fail_why) */
static int entry_check(struct disk *k, const struct volume *v, const struct entry *e)
{
    if (v->fs != FS_NTFS || seq_of(e) == NO_SEQ)
        return 0;
    fail_why = 0;
    if (mft_read(k, v, e->cluster, nrec) < 0 || (le16(nrec + 0x10) != seq_of(e) && stale(v)))
        return -1;
    return 0;
}

static int walk_path(struct disk *k, const struct volume *v, u32 dir, const char *from, const char *path,
                     struct entry *out, char *out_path)
{
    static struct find f;
    char p[PATH_MAX];
    int plen = 0, over = 0;             /* (over: the path's text is longer than p[] holds) */
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
    out->size = out->size_hi = 0;
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
        int r;
        if (up && v->fs == FS_NTFS) {   /* (NTFS has no '..' entries: the parent its $FILE_NAME names) */
            u32 parent = 0;             /* (the parent its record names: that record the entry's first) */
            r = entry_check(k, v, out) < 0 || ntfs_parent(k, v, out->cluster, &parent) < 0 ? -1 : 1;
            f.found = *out;
            f.found.name[0] = f.found.name[1] = '.';
            f.found.name[2] = 0;
            f.found.cluster = parent;
            f.found.slots = 0;
        } else {
            r = find_in(k, v, out->cluster, seq_of(out), path, len, &f);
        }
        if (r < 0) {
            say_why(0);
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
        } else if (plen + (plen > 1) + path_len(out->name) > PATH_MAX - 1) {
            over = 1;
        } else {
            if (plen > 1)
                p[plen++] = '/';
            for (const char *s = out->name; *s; s++)
                p[plen++] = *s;
            p[plen] = 0;
        }
        path += len;
    }
    if (out_path) {
        /* (cut to fit, the text named a directory above the one reached: 'cd' showed -- and the explorer
           deleted in -- the wrong one, a new file went into it) */
        if (over) {
            if (!quiet)
                uprintf("the path is too long: %u characters at most after the volume\n", PATH_MAX - 1);
            return -1;
        }
        for (int i = 0; i <= plen; i++)
            out_path[i] = p[i];
    }
    return 0;
}

/* "[device[.partition]:][path]": the disk and volume -- "n:" the disk's first
   FAT volume, else its first NTFS one; none named: the first FAT volume of
   any disk, else the first NTFS one --, the path; 0 when there is none (said
   why) */
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
    for (int pass = 0; pass < 2; pass++)            /* (none named: FAT first, then NTFS) */
        for (int i = 0; i < DISKS; i++) {
            struct disk *k = &disks[i];
            if (!k->used || (device && k->device != device))
                continue;
            if (!k->ready && !pass)
                probe(k);
            struct volume *v = 0;
            for (int j = 0; j < k->volumes && !v; j++)
                if (part ? k->vol[j].number == part : device ? &k->vol[j] == first_volume(k)
                                                        : pass ? readable(&k->vol[j]) : k->vol[j].fs == FS_FAT)
                    v = &k->vol[j];
            if (v && !readable(v)) {
                uprintf("device %u partition %u is %s: its files are not read%s%s\n", k->device, v->number,
                        fs_name(v), v->problem ? ": " : "", v->problem ? v->problem : "");
                return 0;
            }
            if (v) {
                *pk = k;
                *pv = v;
                return arg;
            }
            if (device) {
                uprintf("device %u: %s\n", device,
                        !k->ready ? k->problem : "no FAT or NTFS volume there ('disks' lists it)");
                return 0;
            }
        }
    uprintf(device ? "device %u is not a USB disk ('disks' lists them)\n"
                   : "no FAT or NTFS volume on a USB disk ('disks')\n", device);
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
   before any 'cd', at the first FAT (else NTFS) volume's root.  The volume, the
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

/* NTFS: the record entry e names is still that file's or directory's (its sequence number is the entry's)?
   Asked where a command is about to go by the record alone -- the current directory, '..' --, or to make
   something before it reads through the entry (cp -r): 0, -1 (said why, after `verb`) */
static int entry_ok(struct disk *k, const struct volume *v, const struct entry *e, const char *verb)
{
    if (entry_check(k, v, e) < 0) {
        say_why(verb);
        return -1;
    }
    return 0;
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
    if (entry_ok(k, v, &e, "cd") < 0)   /* (kept by its record alone from here on) */
        return;
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
    u32 files, dirs;
    u64 bytes;
};

static u64 size_of(const struct entry *e)
{
    return (u64)e->size_hi << 32 | e->size;
}

static int ls_fn(const struct entry *e, void *ctx)
{
    struct listing *l = ctx;
    char t[24];
    if ((e->attr & 0x08) || (e->name[0] == '.' && (!e->name[1] || (e->name[1] == '.' && !e->name[2]))))
        return 0;                       /* the volume label, '.', '..' */
    u32 year = 1980 + (e->date >> 9), month = (e->date >> 5) & 15, day = e->date & 31;
    uprintf("%04u-%02u-%02u %02u:%02u ", year, month, day, e->time >> 11, (e->time >> 5) & 63);
    if (e->attr & 0x10) {
        uprintf("     <DIR>  ");
        l->dirs++;
    } else {
        uprintf("%10s  ", dec64(t, size_of(e)));
        l->files++;
        l->bytes += size_of(e);
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
    char t[24];
    if (dir_walk(k, v, e.cluster, seq_of(&e), ls_fn, &l) < 0)
        say_why(0);
    uprintf("%u file%s, %u director%s, %s bytes\n", l.files, l.files == 1 ? "" : "s", l.dirs,
            l.dirs == 1 ? "y" : "ies", dec64(t, l.bytes));
}

/* ---- a file's bytes, in order: FAT (its cluster chain) or NTFS (its $DATA) ---- */
struct reader {
    struct disk *k;
    const struct volume *v;
    u64 size, pos;                      /* its bytes, how many were read */
    u64 init;                           /* NTFS: its bytes from here on read as zeros (never written) */
    u8 resident;                        /* NTFS: its bytes in its record (copied into file_res) */
    u32 run;                            /* NTFS: the run (file_runs) being read */
    u32 cluster, in, steps;             /* FAT: the cluster being read, its sector, the chain's steps */
    u32 first;                          /* FAT: the file's first cluster (a seek back walks the chain again) */
    struct runs *runs;                  /* NTFS: its runs and a small file's bytes (0: file_runs, file_res --
                                           ftp.c's reader has its own: it lasts across main loop passes) */
    u8 *res;
};

static u8 file_buf[8 * SECTOR];         /* (what cat, cp, sum, the explorer's preview read) */

/* the file of entry e (on volume v) to read from its start: 0, -1 (said why, after `verb`) */
static int file_open(struct reader *r, struct disk *k, const struct volume *v, const struct entry *e,
                     const char *verb)
{
    struct nattr a;
    r->k = k;
    r->v = v;
    r->pos = 0;
    r->run = 0;
    r->resident = 0;
    if (!r->runs) {
        r->runs = &file_runs;
        r->res = file_res;
    }
    if (v->fs == FS_FAT) {
        r->size = r->init = e->size;
        r->cluster = r->first = e->cluster;
        r->in = r->steps = 0;
        return 0;
    }
    fail_why = 0;
    int x = mft_read(k, v, e->cluster, nrec);
    if (x == 0 && seq_of(e) != NO_SEQ && le16(nrec + 0x10) != seq_of(e))
        x = stale(v);                   /* (never another file's bytes under this one's name) */
    if (x == 0)
        x = ntfs_attr(k, v, nrec, e->cluster, 0x80, "", &a, r->res, REC_MAX, r->runs);
    if (x < 0) {
        say_why(verb);
        return -1;
    }
    if (!x) {                           /* (no unnamed $DATA: no bytes) */
        r->size = r->init = 0;
        return 0;
    }
    if (a.flags & 0x00FF) {
        uprintf("%s: %s is compressed (NTFS compression is not read)\n", verb, e->name);
        return -1;
    }
    if (a.flags & 0x4000) {
        uprintf("%s: %s is encrypted (EFS: not read)\n", verb, e->name);
        return -1;
    }
    r->resident = a.resident;
    r->size = a.size;
    r->init = a.init < a.size ? a.init : a.size;
    if (!a.resident && a.size
        && (!r->runs->n || ((u64)r->runs->r[r->runs->n - 1].vcn + r->runs->r[r->runs->n - 1].len)
                                     << (9 + v->csh) < a.size)) {
        uprintf("%s: %s: its runs end before its size\n", verb, e->name);
        return -1;
    }
    return 0;
}

/* its next bytes into buf (`max` of them at most: a multiple of 512, 4096 at most -- one SCSI READ): how
   many, 0 at its end, -1 not read (fail_why) */
static int file_read(struct reader *r, u8 *buf, u32 max)
{
    const struct volume *v = r->v;
    if (r->pos >= r->size)
        return 0;
    u32 want = r->size - r->pos < max ? (u32)(r->size - r->pos) : max, n = (want + SECTOR - 1) / SECTOR;
    if (v->fs == FS_FAT) {              /* within a cluster, as many sectors as it has left */
        if (r->cluster < 2 || r->cluster >= v->clusters + 2 || r->steps > v->clusters)
            return fail("the file's cluster chain ends early");
        if (n > v->spc - r->in)
            n = v->spc - r->in;
        if (read_sectors(r->k, cluster_sector(v, r->cluster) + r->in, n, buf) < 0)
            return fail(0);
        r->in += n;
        if (r->in == v->spc) {
            r->in = 0;
            r->steps++;
            if (r->size - r->pos > n * SECTOR)
                r->cluster = next_cluster(r->k, v, r->cluster);
        }
    } else if (r->resident) {
        for (u32 i = 0; i < want; i++)
            buf[i] = r->res[r->pos + i];
    } else {                            /* within a run, as many sectors as it has left */
        u32 csh = v->csh, vcn = (u32)(r->pos >> (9 + csh)), in = (u32)(r->pos >> 9) & ((1u << csh) - 1);
        const struct nrun *p = r->runs->r;
        while (r->run < r->runs->n && vcn - p[r->run].vcn >= p[r->run].len)
            r->run++;
        if (r->run >= r->runs->n || vcn < p[r->run].vcn)
            return fail("NTFS: the file's runs end early");
        p += r->run;
        u64 room = ((u64)(p->len - (vcn - p->vcn)) << csh) - in;
        if (room < n)
            n = (u32)room;
        n = read_count(r->k, n);
        if (p->lcn == NO_LCN || r->pos >= r->init) {
            for (u32 i = 0; i < n * SECTOR; i++)
                buf[i] = 0;
        } else if (read_sectors(r->k, v->start + ((p->lcn + (vcn - p->vcn)) << csh) + in, n, buf) < 0) {
            return fail(0);
        } else if (r->init - r->pos < n * SECTOR) {
            for (u32 i = (u32)(r->init - r->pos); i < n * SECTOR; i++)
                buf[i] = 0;             /* (past what was written: zeros) */
        }
    }
    if (want > n * SECTOR)
        want = n * SECTOR;
    r->pos += want;
    return (int)want;
}

/* 'cat [n:]/path': a text file as it is (a binary one: its first 256 bytes
   as hex); Ctrl-C on the UART stops it */
void disk_cat(const char *arg)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    static struct reader r;
    u32 dir;
    char t[24];
    const char *from;
    const char *path = locate(arg, &k, &v, &dir, &from);
    if (!path || walk_path(k, v, dir, from, path, &e, 0) < 0)
        return;
    if (e.attr & 0x10) {
        uprintf("a directory: 'ls' lists it\n");
        return;
    }
    if (file_open(&r, k, v, &e, "cat") < 0)
        return;
    u32 binary = 0, column = 0;
    int n;
    while ((n = file_read(&r, file_buf, SECTOR)) > 0) {
        if (r.pos == (u32)n) {          /* the first sector: text? */
            for (int i = 0; i < n; i++)
                if (file_buf[i] < 32 && file_buf[i] != '\n' && file_buf[i] != '\r' && file_buf[i] != '\t')
                    binary++;
            if (binary * 10 > (u32)n) {
                uprintf("a binary file, %s bytes; its first %u:\n", dec64(t, r.size), n < 256 ? n : 256);
                for (int i = 0; i < n && i < 256; i += 16) {
                    uprintf("%04x:", i);
                    for (int j = i; j < i + 16 && j < n; j++)
                        uprintf(" %02x", file_buf[j]);
                    uprintf("\n");
                }
                return;
            }
        }
        for (int i = 0; i < n; i++) {
            u8 c = file_buf[i];
            if (c == '\n') {
                uprintf("\n");
                column = 0;
            } else if (c != '\r') {
                uprintf("%c", c == '\t' ? ' ' : c >= 32 && c < 127 ? c : '.');
                column++;
            }
        }
        if (uart_getc() == 3) {
            uprintf("^C\n");
            return;
        }
    }
    if (n < 0) {
        uprintf("\n");
        say_why(0);
        return;
    }
    if (column)
        uprintf("\n");
}

/* CRC-32 (zlib's, 7-Zip's) of n more bytes */
static u32 crc32(u32 crc, const u8 *p, u32 n)
{
    static u32 table[256];
    if (!table[1])
        for (u32 i = 0; i < 256; i++) {
            u32 c = i;
            for (int j = 0; j < 8; j++)
                c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
    while (n--)
        crc = table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    return crc;
}

/* 'sum [n:]path': a file read to its end -- its size, its CRC-32, its first bytes, how fast (Ctrl-C stops) */
void disk_sum(const char *arg)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    static struct reader r;
    static u8 head[16];
    u32 dir, crc = 0xFFFFFFFFu, heads = 0;
    char t[24], h[52];
    const char *from;
    const char *path = locate(arg, &k, &v, &dir, &from);
    if (!path || walk_path(k, v, dir, from, path, &e, 0) < 0)
        return;
    if (e.attr & 0x10) {
        uprintf("a directory: 'ls' lists it\n");
        return;
    }
    if (file_open(&r, k, v, &e, "sum") < 0)
        return;
    u64 t0 = now_ms();
    int n;
    while ((n = file_read(&r, file_buf, sizeof(file_buf))) > 0) {
        for (int i = 0; i < n && heads < 16; i++)
            head[heads++] = file_buf[i];
        crc = crc32(crc, file_buf, (u32)n);
        if (uart_getc() == 3) {
            uprintf("^C (%s of ", dec64(t, r.pos));
            uprintf("%s bytes read)\n", dec64(t, r.size));
            return;
        }
    }
    u32 ms = (u32)(now_ms() - t0);
    if (n < 0) {
        uprintf("sum: at byte %s: ", dec64(t, r.pos));
        say_why(0);
        return;
    }
    int at = 0;
    for (u32 i = 0; i < heads; i++)
        at += usnprintf(h + at, (int)sizeof(h) - at, " %02x", head[i]);
    h[at] = 0;
    uprintf("%s: %s bytes, CRC-32 %08x; read in %u.%u s (%u KB/s); its first bytes:%s\n", e.name, dec64(t, r.size),
            ~crc, ms / 1000, ms % 1000 / 100, ms ? (u32)div64((r.size >> 10) * 1000, ms, 0) : 0, h);
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
        uprintf("device %u: sector %u does not read (%u sectors; %s)\n", k->device, lba, k->blocks, io_error());
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
   first change (the next system to mount it counts again).  What is made
   is dated by the clock once NTP set it (net.c), in Polish time as FAT
   keeps local time; until then FAT_DATE / FAT_TIME. */
#define FAT_DATE ((u16)(((2026 - 1980) << 9) | (11 << 5) | 13))   /* 2026-11-13 */
#define FAT_TIME ((u16)(12 << 11))                                 /* 12:00 */

static void fat_stamp(u16 *date, u16 *time)
{
    u32 t = net_clock_utc(), y, m, d;
    *date = FAT_DATE;
    *time = FAT_TIME;
    if (!t)
        return;
    t += summer_time(t) ? 7200 : 3600;
    civil(t / 86400, &y, &m, &d);
    if (y < 1980 || y > 2107)
        return;
    u32 s = t % 86400;
    *date = (u16)((y - 1980) << 9 | m << 5 | d);
    *time = (u16)((s / 3600) << 11 | (s / 60 % 60) << 5 | (s % 60) / 2);
}

static u8 wbuf[SECTOR], wbuf2[SECTOR];  /* sectors being changed */
static u8 zeros[8 * SECTOR];
static const struct volume *nw_unlocked;        /* the NTFS volume whose sectors write_sectors lets through just
                                                   now: set by nw_write alone, for one call (0: none) */

static void put16(u8 *p, u16 v)
{
    p[0] = (u8)v;
    p[1] = (u8)(v >> 8);
}

static int write_sectors(struct disk *k, u32 lba, u32 count, const u8 *buf)
{
    u8 cb[10] = {0x2A, 0, (u8)(lba >> 24), (u8)(lba >> 16), (u8)(lba >> 8), (u8)lba, 0, (u8)(count >> 8),
                 (u8)count, 0};
    if (!k->ready || !count || count > 8 || lba >= k->blocks || count > k->blocks - lba) {
        io_said = k->ready ? "a sector beyond the disk's end" : "its medium was changed";
        return -1;                      /* (not ready: its medium went, the next command looks at the disk again) */
    }
    for (int i = 0; i < k->volumes; i++)    /* (FAT is written; a sector of an NTFS volume through nw_write alone,
                                               one of an exFAT or unknown volume never) */
        if (k->vol[i].fs != FS_FAT && &k->vol[i] != nw_unlocked && lba < k->vol[i].start + k->vol[i].sectors
            && lba + count > k->vol[i].start) {
            uprintf("not written: sector %u is in device %u's %s volume (read-only)\n", lba, k->device,
                    fs_name(&k->vol[i]));
            return -1;
        }
    if (k->resent && medium_same(k) < 0)
        return -1;                      /* (a command's answer was lost since: the medium compared first) */
    changes++;
    for (int attempt = 0; attempt < 2; attempt++) {
        int n = transfer(k, cb, 10, (u8 *)buf, count * SECTOR, 1);
        if (n == (int)(count * SECTOR))
            return 0;
        if (n == -1)
            return -1;
        u8 key = 0, asc = 0;
        if (check_condition(k, &key, &asc) < 0)
            return -1;                  /* (a new medium is never written with what was known of the old one) */
        io_sense(key, asc);
        k->resent = 1;
        if (key != 6) {
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
    if (!k->ready)
        return 0;                       /* (its medium went: said then) */
    if (!k->wp) {
        static const u8 cb[6] = {0x1A, 0, 0x3F, 0, 4, 0};
        u8 b[4], key, asc;
        int n = command(k, cb, 6, b, 4);
        if (n == -2 && sense(k, &key, &asc) == 0 && medium_changed(k, key, asc))
            return 0;                   /* (the card was changed: nothing of it is written with the old one's state) */
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
    if (k->ready && command(k, cb, 10, 0, 0) == -2 && sense(k, &key, &asc) == 0)
        (void)medium_changed(k, key, asc);      /* (a device without it; a medium changed just now) */
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
            uprintf("a FAT sector did not read: %s\n", io_error());
            return 0;
        }
        if (!value) {
            if (fat_set(k, v, c, fat_end(v)) < 0) {
                uprintf("the FAT was not written: %s\n", io_error());
                return 0;
            }
            v->alloc_hint = c + 1;
            if (v->free_known && v->free_clusters)
                v->free_clusters--;
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
    struct volume *w = (struct volume *)v;      /* (its free count kept) */
    for (u32 steps = 0; c >= 2 && c < v->clusters + 2 && steps <= v->clusters; steps++) {
        u32 next;
        if (fat_get(k, v, c, &next) < 0 || fat_set(k, v, c, 0) < 0)
            return -1;
        if (w->free_known)
            w->free_clusters++;
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
    if (it->cluster < 2 || it->cluster >= v->clusters + 2)
        return -1;                      /* (a damaged entry's first cluster: its "sectors" are the FAT's own or
                                           another volume's -- nothing is written through it) */
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

/* the "~n" tails a directory's 8.3 names have that begin as `sfn` does and end in its extension: the
   highest n.  ("IMG_2026" gives IMG_20~1 .. IMG_20~9, IMG_2~10 .. IMG_2~99, IMG_~100 ...: the part before
   the tail is as much of the base as the tail leaves of its eight characters) */
struct tails {
    const u8 *sfn;                      /* the name wanted: 11 characters, no tail */
    int base;                           /* its base's length */
    u32 highest;
};

static int tail_fn(const struct entry *e, void *ctx)
{
    struct tails *t = ctx;
    const char *s = e->short_name;
    int n = 0, tilde = -1;
    for (; s[n] && s[n] != '.'; n++)
        if (s[n] == '~')
            tilde = n;
    if (tilde < 1 || tilde == n - 1)
        return 0;
    u32 v = 0;
    for (int i = tilde + 1; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return 0;
        v = v * 10 + (u32)(s[i] - '0');
    }
    int keep = 7 - (n - tilde - 1) < t->base ? 7 - (n - tilde - 1) : t->base;
    if (tilde != keep)
        return 0;
    for (int i = 0; i < keep; i++)
        if ((u8)s[i] != t->sfn[i])
            return 0;
    const char *x = s[n] == '.' ? s + n + 1 : "";
    for (int i = 0; i < 3; i++)
        if ((u8)(*x ? *x++ : ' ') != t->sfn[8 + i])
            return 0;
    if (!*x && v > t->highest)
        t->highest = v;
    return 0;
}

/* the slots of a new entry `name` (attribute, first cluster, size) for
   directory `dir`: its long name's parts when it needs them (the last
   first), then the 8.3 entry -- "BASIS~n", n one more than the highest
   such name there has.  Their number; -1 (said why) */
static int make_entry(struct disk *k, const struct volume *v, u32 dir, const char *name, u8 attr, u32 cluster,
                      u32 size, u8 (*ents)[32])
{
    u8 sfn[11], nt;
    int n = 0, len = path_len(name);
    int fits = short_form(name, sfn, &nt);
    if (!fits) {
        /* (one walk for the highest tail there is.  It was a walk for each of ~1 .. ~99 until one was free:
           the hundredth photo of a camera's folder -- IMG_2026... -- was refused, the 99th cost 99 walks) */
        int base = 0;
        while (base < 8 && sfn[base] != ' ')
            base++;
        struct tails tails = {sfn, base, 0};
        if (dir_walk(k, v, dir, NO_SEQ, tail_fn, &tails) < 0) {
            uprintf("a sector did not read: %s\n", io_error());
            return -1;
        }
        if (tails.highest >= 999999) {
            uprintf("no 8.3 name left for '%s'\n", name);
            return -1;
        }
        char tail[8];
        int tl = usnprintf(tail, sizeof(tail), "~%u", tails.highest + 1), keep = 8 - tl < base ? 8 - tl : base;
        for (int i = 0; i < tl; i++)
            sfn[keep + i] = (u8)tail[i];
        for (int i = keep + tl; i < 8; i++)
            sfn[i] = ' ';
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
    u16 date, time;
    fat_stamp(&date, &time);
    put16(d + 14, time);                /* created */
    put16(d + 16, date);
    put16(d + 18, date);                /* accessed */
    put16(d + 20, (u16)(v->fat == 32 ? cluster >> 16 : 0));
    put16(d + 22, time);                /* written */
    put16(d + 24, date);
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
   dots dropped, as Windows does); 1, 0 when there is no name or it has a
   character a FAT name may not have, -1 the directory part is longer than
   parent holds, -2 the name is longer than name does.  (Too long was cut:
   a file then got a shorter name, or -- the cut at a '/' -- went into a
   directory above the one named, over a file of its name there) */
static int split_path(const char *path, char *parent, char *name)
{
    int len = path_len(path), cut;
    while (len > 0 && (path[len - 1] == '/' || path[len - 1] == '\\'))
        len--;
    for (cut = len; cut > 0 && path[cut - 1] != '/' && path[cut - 1] != '\\'; cut--)
        ;
    if (cut > PATH_MAX - 1)
        return -1;
    if (len - cut > NAME_MAX - 1)
        return -2;
    int pl = cut;
    for (int i = 0; i < pl; i++)
        parent[i] = path[i];
    parent[pl] = 0;
    int nl = 0;
    for (int i = cut; i < len; i++)
        name[nl++] = path[i];
    while (nl > 0 && (name[nl - 1] == ' ' || name[nl - 1] == '.'))
        nl--;
    name[nl] = 0;
    for (int i = 0; i < nl; i++)
        if (!name_char(name[i]))
            return 0;
    return nl > 0;
}

/* ---- NTFS, written ----
   What the writing commands do on an NTFS volume, as ntfs-3g does it and as little as will do:

   The gate (nw_gate_read; once per volume, when the first write is asked for; 'ntfs' shows it).  A volume is
   written only when it is NTFS 3.x with 512-byte sectors, records of 4 KB at most and index blocks of 4 KB,
   its volume flags have none of the bits ntfs-3g mounts read-only for (0xC027: dirty, the log to be
   resized, an upgrade on mount, object IDs to repair, chkdsk under way or just done), its journal
   ($LogFile) is EMPTY (0xFF: as mkntfs and ntfs-3g leave it) or CLEAN as ntfs-3g's ntfs_is_logfile_clean
   decides it (both restart pages valid RSTR pages; in the newer one no client in use, or
   RESTART_VOLUME_IS_CLEAN set) and not of version 2.0 (Windows left the volume mounted: fast start-up,
   hibernation), $MFTMirr matches $MFT, and Windows is not hibernated on it.  A clean journal is left as it
   is: Windows does not replay it.  One that is not clean would be replayed over what the demo wrote, so
   the volume stays read-only; 'ntfs n: reset-journal' fills it with 0xFF as ntfs-3g does, when asked for
   by name and never by itself.  Every sector goes through nw_write, the one place that opens
   write_sectors for an NTFS volume.

   The order of every change is such that one cut off half way can only leak -- clusters marked in use that
   no file has, a file record in use that no directory names; chkdsk takes those back -- and never gives two
   files the same cluster: clusters and records are taken in the bitmaps first, then the data is written,
   then the file's record, then its directory's entry; a file is removed the other way round.  Three
   changes cannot be made in one write and have a state in between that is not a leak, and not a
   cross-link either: a new name or directory for a file (a file moved is taken OUT of its old directory
   first, put INTO the new one second, and its record -- the name, the directory it says it is in -- is
   written last: between the first two it is in no directory, a record in use that no directory names,
   which is a leak chkdsk puts back; between the last two its entry and its record's name do not agree
   yet; it is never in two directories.  One renamed where it is: the entry first, the record second), a
   file written over or added to (its record has the new size, its directory's entry the old one), and
   the records $MFTMirr holds a copy of (0..3; with mkntfs's 64 KB clusters 0..63, the root's among them):
   the copy is written right after the record.  Where two directories' indexes or an index and a record
   have to change together, the index that comes later is PREPARED first (nw_index with NW_PREPARE: laid
   out, its blocks written beside the old ones, only its record's write kept back), so that what can fail
   for want of room fails before anything is changed, and after the first change only single record
   writes are left.

   A write that fails makes the volume read-only on the spot (nw_write): "failed" is not "not written",
   so nothing is undone on the strength of it -- the change is left as a power cut would leave it.  The
   same when something on the volume is found not to be as it should be (an entry that names another
   file's record -- every reader and writer that follows an entry compares the record's sequence number
   --, an index whose bitmap does not match it) or when what a change let go cannot be given back: said,
   and read-only until 'ntfs' looked at the volume again.

   A directory's index ($I30) is not changed entry by entry: every change REBUILDS it.  Its entries are read
   in order (each one's key kept byte for byte), the change is made in that list (NTFS's file name
   collation: the volume's $UpCase table first, the characters themselves when two names differ in case
   only), and the list is laid out again: in the record's $INDEX_ROOT when it fits there, else as a balanced
   B-tree of INDX blocks -- written into blocks the old tree does not use, so the old tree is whole until
   the record (the root, the blocks' bitmap) is written and the new one whole after it.

   Not taken on (each refused with its reason, nothing changed): files and directories with an
   $ATTRIBUTE_LIST, compressed, encrypted and sparse ones, reparse points, files with several hard links
   (a long name with its 8.3 name beside it is one file with two $FILE_NAMEs and link count 2: taken --
   both entries go, both get new sizes, a rename leaves the one new name), a new name that differs from
   one in the directory in its characters' case only (the same name to Windows: $UpCase), the volume's own
   files (records below 24, '$' names in the root), a file with an object ID when it is to
   be removed ($ObjId's index would have to lose its entry), directories of more than NW_DIR_MAX entries
   or whose index bitmap is not in their record, a file in more pieces than fit its record (no attribute
   lists are made).  New names are in the POSIX namespace, as ntfs-3g's; a file's security is its
   directory's (its security_id copied: an entry $Secure has already), or, where the directory has none
   (mkntfs's root, ntfs-3g's directories), ntfs-3g's descriptor for everyone in the record.  $UsnJrnl and
   $Quota are not kept up (ntfs-3g does not either); the times are FAT_DATE / FAT_TIME: the box's fixed
   ones.

   On a slow disk what counts is the commands: a directory's index is read whole for a change (and once
   more by the look-up before it), its new blocks are written whole; bitmaps are read from a hint on, a
   few sectors at a time, and written a sector at a time. */
#define NW_FIRST_REC 64                 /* a new file's record: from here on, as ntfs-3g (the ones before are
                                           left to the volume's own files) */
#define NW_META      24                 /* the records below are the volume's own files */
#define NW_DIR_MAX   4096               /* a directory's entries, at most, for the demo to change it */
#define NW_BLOCKS    1024               /* its new index's INDX blocks */
#define NW_TBLOCKS   4096               /* the blocks its $INDEX_ALLOCATION holds */
#define NW_BMP_RUNS  64                 /* $Bitmap's pieces */
#define NW_MBM_RUNS  32                 /* the pieces of $MFT's bitmap */
#define NW_BLOCK     4096               /* an INDX block (the only size Windows and mkntfs make) */
#define NW_WINDOW    7                  /* the sectors of a bitmap (or of $UpCase) read at a time: an odd number
                                           is one READ on a high-speed disk, 8 would be two (read_count) --
                                           and a big volume's $Bitmap is thousands of them */
#define NO_BLOCK     0xFFFFFFFFu
#define UPCASE_CHARS 65536

#define J_UNREAD     0                  /* the journal: not read */
#define J_EMPTY      1                  /*   both restart pages 0xFF */
#define J_CLEAN      2                  /*   shut down cleanly */
#define J_UNCLEAN    3                  /*   in use: Windows would replay it */
#define J_LFS2       4                  /*   version 2.0: Windows left the volume mounted */
#define J_BAD        5                  /*   its restart pages are not valid */
#define J_PARTLY     6                  /*   emptied at its start only (a reset cut short) */

struct iitem {                          /* an entry in a node above the leaves: which entry, the block below it */
    u32 ent, child;
};

struct iblock {                         /* an INDX block of the index being laid out */
    u32 first, n;                       /* its entries: items first .. first + n - 1 of its level */
    u32 end_child;                      /* the block below its end entry (NO_BLOCK: a leaf) */
    u32 level;                          /* 0: a leaf */
};

struct iplan {                          /* the root of the index being laid out */
    u32 level;                          /* 0: every entry is in it (no blocks) */
    u32 first, n;                       /* its items */
    u32 end_child;
};

struct idx_op {                         /* a change to a directory's index */
    u32 remove;                         /* every entry of this record out (0: none) */
    const u8 *add;                      /* an entry to put in (0: none) */
    u32 patch;                          /* this record's entries: new times and sizes (0: none) */
    const u8 *dup;                      /*   $FILE_NAME's bytes 0x08 .. 0x3B */
};

struct nw_page {                        /* a restart page of the journal, as 'ntfs' shows it */
    u8 kind;                            /* 0: all 0xFF, 1: a valid RSTR page, 2: something else */
    const char *bad;                    /* kind 2: what */
    char magic[5];
    u16 major, minor;                   /* the journal's version (LFS 1.1, 2.0) */
    u32 sys_page, log_page;
    u64 lsn;
    u16 clients, free_list, in_use, flags;
};

struct nw_info {                        /* what the gate read */
    u8 version_read, major, minor;
    u16 vflags;
    u32 log_kb;
    struct nw_page page[2];
    u8 journal;                         /* J_* */
    u8 newer;                           /* the restart page that decides (0, 1) */
    u8 loaded;                          /* $Bitmap, $MFT's bitmap, $MFTMirr and $UpCase were read */
    const char *why;                    /* why the demo does not write the volume (0: it does) */
};

static u8 nw_rec[REC_MAX];              /* the record being made or changed */
static u8 nw_dir[REC_MAX];              /* its directory's */
static u8 nw_m0[REC_MAX];               /* $MFT's own (record 0), when it grows */
static u8 nw_tmp[REC_MAX];              /* a record in passing: one formatted, one read to look at */
static u8 nw_blk[NW_BLOCK];             /* an INDX block being made; a restart page */
static u8 nw_bm[8 * SECTOR];            /* a piece of a bitmap */
static u8 nw_key[0x42 + 2 * 255 + 6];   /* a $FILE_NAME value being made */
static u8 nw_ent[0x10 + sizeof(nw_key) + 8];    /* the index entry with it */
static struct find nw_find;

#define nw_up    ((u16 *)KSEG0(NTFS_UPCASE_PHYS))                   /* $UpCase: a character's upper case */
#define nw_off   ((u32 *)KSEG0(NTFS_WORK_PHYS))                     /* where each entry is in the blob */
#define nw_item  ((struct iitem *)KSEG0(NTFS_WORK_PHYS + 0x8000))   /* the levels above the leaves */
#define nw_plan  ((struct iblock *)KSEG0(NTFS_WORK_PHYS + 0xC000))  /* the new index's blocks */
#define nw_no    ((u32 *)KSEG0(NTFS_WORK_PHYS + 0x14000))           /* which block of the allocation each is */
#define nw_old   ((u8 *)KSEG0(NTFS_WORK_PHYS + 0x18000))            /* the blocks the old index uses */
#define nw_blob  ((u8 *)KSEG0(NTFS_INDEX_PHYS))                     /* the directory's entries */

/* the volume being written: where its bitmaps are, its $MFTMirr, how many records $MFT has ($UpCase is at
   nw_up).  One volume at a time: nw_use loads another's */
static struct {
    struct disk *k;                     /* (0: none) */
    struct volume *v;
    struct runs bmp, mbm, mir;          /* $Bitmap's $DATA, $MFT's $BITMAP, $MFTMirr's $DATA */
    struct nrun bmp_run[NW_BMP_RUNS], mbm_run[NW_MBM_RUNS], mir_run[8];
    u32 mbm_bytes;                      /* $MFT's bitmap: its bytes */
    u32 mft_records;                    /* the records $MFT holds (formatted ones) */
    u32 mirror_count;                   /* the records $MFTMirr holds a copy of */
    u32 zone_start, zone_end;           /* the MFT zone: clusters kept for $MFT to grow into */
    u32 rec_hint;                       /* where the search for a free record starts */
    u32 blob_used;                      /* the bytes of nw_blob in use */
} nw;

/* (medium_changed: the disk's medium is another one now) */
static void nw_forget(const struct disk *k)
{
    if (nw.k == k)
        nw.k = 0;
}

static const struct volume *nw_resetting;       /* 'ntfs n: reset-journal': the volume whose journal is filled */
static const char *nw_verb = "ntfs";            /* the command, for what it says */
static const char *nw_why;              /* why an NTFS write failed (0: a sector did not read or was not written) */
static int nw_said;                     /* it said so itself: the caller's own line is left out */

static int nw_err(const char *why)
{
    nw_why = why;
    return -1;
}

/* why it failed, after the command's name: -1 */
static int nw_fail(void)
{
    if (nw_why)
        uprintf("%s: %s\n", nw_verb, nw_why);
    else
        uprintf("%s: a sector of the NTFS volume did not read or was not written: %s\n", nw_verb, io_error());
    nw_said = 1;
    return -1;
}

static void put64(u8 *p, u64 v)
{
    put32(p, (u32)v);
    put32(p + 4, (u32)(v >> 32));
}

static void wipe(u8 *p, u32 n)
{
    while (n--)
        *p++ = 0;
}

static void copy(u8 *to, const u8 *from, u32 n)
{
    while (n--)
        *to++ = *from++;
}

/* a 64-bit number times a 32-bit one (no libgcc: two widening multiplications) */
static u64 mul64(u64 a, u32 b)
{
    return (u64)(u32)a * b + (((u64)(u32)(a >> 32) * b) << 32);
}

/* the time new files get, as NTFS counts it (100 ns since 1601, UTC): the clock's once NTP set it, else
   FAT's fixed date and time (Polish time) */
static u64 nw_now(void)
{
    u32 utc = net_clock_utc();
    if (!utc) {
        u32 local = days_of(1980 + (FAT_DATE >> 9), (FAT_DATE >> 5) & 15, FAT_DATE & 31) * 86400u
                    + (FAT_TIME >> 11) * 3600u + ((FAT_TIME >> 5) & 63) * 60u;
        utc = local - (summer_time(local - 7200) ? 7200 : 3600);
    }
    return mul64((u64)utc + 11644473600ull, 10000000u);
}

/* -- sectors -- */

static const char nw_failed[] = "a write to it failed -- what was being changed may be half done: 'ntfs' looks at "
                               "the volume again (chkdsk in Windows to be sure)";

/* sectors of an NTFS volume written: the one way there is.  The volume passed the gate (or its journal is
   being reset, asked for by name), and the sectors are its own.  A write that fails for good makes the
   volume read-only at once (NW_REFUSED, until 'ntfs' has looked at it again): "failed" is not "not written"
   -- the disk may have carried it out and its answer was lost -- so nothing may be undone on the strength
   of it: every write after it is refused, the undo's too, and the change is left as a power cut would
   leave it (leaks at worst) */
static int nw_write(struct disk *k, struct volume *v, u32 lba, u32 count, const u8 *buf)
{
    u32 size = v->ntfs_clusters << v->csh;
    if (v->fs == FS_NTFS && v->nw_state == NW_REFUSED && v->nw_why == nw_failed)
        return nw_err("a write to the volume failed before: nothing more is written to it ('ntfs' looks at it "
                      "again)");
    if (v->fs != FS_NTFS || (v->nw_state != NW_OK && nw_resetting != v) || lba < v->start || lba - v->start >= size
        || count > size - (lba - v->start))
        return nw_err("NTFS: a write that is not the demo's to make (refused)");
    nw_unlocked = v;
    int r = write_sectors(k, lba, count, buf);
    nw_unlocked = 0;
    if (r < 0) {
        v->nw_state = NW_REFUSED;
        v->nw_why = nw_failed;
        return nw_err("a write failed: the volume is read-only from now on, what was being changed may be half "
                      "done ('ntfs' looks at it again; chkdsk in Windows to be sure)");
    }
    return 0;
}

/* something on the volume was found not to be as it should be -- an entry that names another file's record,
   an index whose bitmap does not match it, a bitmap that says free what is in use; or what a change let go
   could not be given back --: `why` is the command's answer, and the volume is not written any more (it
   says: run chkdsk) until 'ntfs' has looked at it again */
static const char nw_sick[] = "something on it was found not to be as it should be (said then): run chkdsk /f in "
                              "Windows; 'ntfs' looks at the volume again";

static int nw_chk(struct volume *v, const char *why)
{
    if (v->nw_state == NW_OK) {
        v->nw_state = NW_REFUSED;
        v->nw_why = nw_sick;
    }
    return nw_err(why);
}

/* (a reader found it: the readers take the volume as const -- its write gate is the one thing changed here) */
static void nw_found_sick(const struct volume *v)
{
    struct volume *w = (struct volume *)v;
    if (w->fs == FS_NTFS && w->nw_state != NW_REFUSED) {
        w->nw_state = NW_REFUSED;
        w->nw_why = nw_sick;
    }
}

/* the change is made, but what it let go -- clusters, a record -- could not be given back in the bitmaps
   (r < 0): they stay marked in use (a leak).  Said, and the volume is read-only from here on */
static void nw_leaked(struct volume *v, int r)
{
    if (r >= 0)
        return;
    uprintf("%s: done -- but what it let go is still marked in use on the volume (%s): chkdsk /f in Windows gives "
            "it back\n", nw_verb, nw_why ? nw_why : io_error());
    (void)nw_chk(v, nw_why);
}

/* an undo's give-back (r: how it went) after a change that failed: when it failed too -- and not because
   the volume is read-only after a failed write (that was said) -- what the change had taken stays marked
   in use: said, and the volume is read-only from here on */
static void nw_back(struct volume *v, int r)
{
    if (r >= 0 || (v->nw_state == NW_REFUSED && v->nw_why == nw_failed))
        return;
    const char *why = nw_why;
    uprintf("%s: what the change had taken on the volume could not be given back (it stays marked in use: chkdsk "
            "/f in Windows frees it)\n", nw_verb);
    (void)nw_chk(v, why);
}

/* `count` sectors of an attribute from its byte `off` (a multiple of 512) on, through its runs, from buf */
static int runs_write(struct disk *k, struct volume *v, const struct nrun *r, u32 n, u64 off, u32 count,
                      const u8 *buf)
{
    u32 csh = v->csh, mask = (1u << csh) - 1;
    while (count) {
        u64 vcn64 = off >> (9 + csh);
        const struct nrun *p = vcn64 >> 32 ? 0 : run_at(r, n, (u32)vcn64);
        if (!p || p->lcn == NO_LCN)
            return nw_err("NTFS: a write past an attribute's clusters (refused)");
        u32 vcn = (u32)vcn64, in = (u32)(off >> 9) & mask, now = count < 8 ? count : 8;
        u64 room = ((u64)(p->len - (vcn - p->vcn)) << csh) - in;
        if (room < now)
            now = (u32)room;
        if (nw_write(k, v, v->start + ((p->lcn + (vcn - p->vcn)) << csh) + in, now, buf) < 0)
            return -1;
        buf += now * SECTOR;
        off += now * SECTOR;
        count -= now;
    }
    return 0;
}

static int nw_read(struct disk *k, const struct volume *v, const struct runs *r, u64 off, u32 count, u8 *buf)
{
    fail_why = 0;
    if (runs_read(k, v, r->r, r->n, off, count, buf) < 0)
        return nw_err(fail_why);
    return 0;
}

/* a record's or an INDX block's fixups put in for the disk: its update sequence number one up, each
   sector's last two bytes kept in the array and that number in their place (fixup undoes it) */
static void fixup_put(u8 *b, u32 size)
{
    u32 off = le16(b + 4), count = size / SECTOR + 1;
    u16 usn = (u16)(le16(b + off) + 1);
    if (!usn)
        usn = 1;
    put16(b + off, usn);
    for (u32 i = 1; i < count; i++) {
        u8 *end = b + i * SECTOR - 2;
        b[off + 2 * i] = end[0];
        b[off + 2 * i + 1] = end[1];
        put16(end, usn);
    }
}

/* -- a record's attributes -- */

/* a record is sound: its attributes in the order of their types, each inside the bytes in use, the end mark
   where those end.  0, -1 */
static int rec_check(const struct volume *v, const u8 *rec)
{
    u32 used = le32(rec + 0x18), at = le16(rec + 0x14), last = 0;
    if (used > v->rec_size || (used & 7) || (at & 7) || at < 0x38 || le32(rec + 0x1C) != v->rec_size)
        return -1;
    for (;;) {
        if (at + 8 > used)
            return -1;
        u32 type = le32(rec + at), len = le32(rec + at + 4);
        if (type == 0xFFFFFFFFu)
            return at + 8 == used ? 0 : -1;
        if (type < last || len < 0x18 || (len & 7) || len > used - at - 8 || rec[at + 8] > 1)
            return -1;
        if (rec[at + 9] && le16(rec + at + 10) + 2u * rec[at + 9] > len)
            return -1;
        if (!rec[at + 8]) {
            if (le16(rec + at + 0x14) < 0x18 || le16(rec + at + 0x14) > len
                || le32(rec + at + 0x10) > len - le16(rec + at + 0x14))
                return -1;
        } else if (len < 0x40 || le16(rec + at + 0x20) < 0x40 || le16(rec + at + 0x20) >= len) {
            return -1;
        }
        last = type;
        at += len;
    }
}

/* attribute `type` named `name` ("": without a name) in a record: where, 0 not there */
static u32 rec_find(const struct volume *v, const u8 *rec, u32 type, const char *name)
{
    for (u32 at = 0; (at = attr_next(v, rec, at));)
        if (le32(rec + at) == type
            && named(rec + at, rec[at + 9], le16(rec + at + 10), le32(rec + at + 4), name))
            return at;
    return 0;
}

/* the attribute at `at` made `len` bytes long (a multiple of 8), what follows it moved: 0, -1 no room */
static int rec_resize(const struct volume *v, u8 *rec, u32 at, u32 len)
{
    u32 used = le32(rec + 0x18), old = le32(rec + at + 4);
    if (len > old && used + (len - old) > v->rec_size)
        return -1;
    memmove(rec + at + len, rec + at + old, used - at - old);
    if (len > old)
        wipe(rec + at + old, len - old);
    else
        wipe(rec + used - (old - len), old - len);
    put32(rec + at + 4, len);
    put32(rec + 0x18, used + len - old);
    return 0;
}

/* a number for a new attribute (a record's attributes are numbered as they come; near the end of the 16
   bits they are numbered again from 0 -- nothing names them by number in a record without an attribute
   list) */
static u16 rec_new_id(u8 *rec)
{
    u16 id = le16(rec + 0x28);
    if (id >= 0xFFF0) {
        id = 0;
        for (u32 at = le16(rec + 0x14); le32(rec + at) != 0xFFFFFFFFu; at += le32(rec + at + 4))
            put16(rec + at + 0x0E, id++);
    }
    put16(rec + 0x28, (u16)(id + 1));
    return id;
}

/* room for an attribute of `len` bytes where its type belongs (after the ones of its type and lower): where
   -- type, length and number set (`id`; 0xFFFF: a new one), the rest zero --, 0 no room */
static u32 rec_insert(const struct volume *v, u8 *rec, u32 type, u32 len, u16 id)
{
    u32 used = le32(rec + 0x18), at = le16(rec + 0x14);
    if (used + len > v->rec_size)
        return 0;
    if (id == 0xFFFF)
        id = rec_new_id(rec);
    while (le32(rec + at) != 0xFFFFFFFFu && le32(rec + at) <= type)
        at += le32(rec + at + 4);
    memmove(rec + at + len, rec + at, used - at);
    wipe(rec + at, len);
    put32(rec + at, type);
    put32(rec + at + 4, len);
    put16(rec + at + 0x0E, id);
    put32(rec + 0x18, used + len);
    return at;
}

static void rec_remove(u8 *rec, u32 at)
{
    u32 used = le32(rec + 0x18), len = le32(rec + at + 4);
    memmove(rec + at, rec + at + len, used - at - len);
    wipe(rec + used - len, len);
    put32(rec + 0x18, used - len);
}

/* the place for an attribute of `len` bytes: the one at `at` made that long and emptied (its number kept),
   or (at 0) a new one */
static u32 rec_place(const struct volume *v, u8 *rec, u32 at, u32 type, u32 len, u16 id)
{
    if (!at)
        return rec_insert(v, rec, type, len, id);
    if (rec_resize(v, rec, at, len) < 0)
        return 0;
    wipe(rec + at + 8, 6);
    wipe(rec + at + 0x10, len - 0x10);
    return at;
}

/* a resident attribute put in -- in place of the one at `at`, or (at 0) a new one numbered `id` (0xFFFF: the
   next number) --: its header, name and value.  Where it is, 0 no room in the record */
static u32 rec_put_resident(const struct volume *v, u8 *rec, u32 at, u32 type, const char *name, const u8 *val,
                            u32 vlen, u8 indexed, u16 id)
{
    u32 nlen = (u32)path_len(name), voff = (0x18 + 2 * nlen + 7) & ~7u, len = (voff + vlen + 7) & ~7u;
    at = rec_place(v, rec, at, type, len, id);
    if (!at)
        return 0;
    rec[at + 9] = (u8)nlen;
    put16(rec + at + 10, 0x18);
    put32(rec + at + 0x10, vlen);
    put16(rec + at + 0x14, (u16)voff);
    rec[at + 0x16] = indexed;
    for (u32 i = 0; i < nlen; i++)
        put16(rec + at + 0x18 + 2 * i, (u8)name[i]);
    copy(rec + at + voff, val, vlen);
    return at;
}

/* the bytes a number takes in a mapping pair (signed: its top bit is its sign) */
static u32 mp_bytes(s64 n)
{
    u32 bytes = 1;
    while (n < -128 || n > 127) {
        n >>= 8;
        bytes++;
    }
    return bytes;
}

/* runs as an attribute's mapping pairs into out (room bytes; 0: only counted): their bytes with the 0 that
   ends them, 0 when they do not fit */
static u32 mp_encode(const struct nrun *r, u32 n, u8 *out, u32 room)
{
    u32 at = 0;
    s64 prev = 0;
    for (u32 i = 0; i < n; i++) {
        s64 len = r[i].len, delta = (s64)r[i].lcn - prev;
        u32 lb = mp_bytes(len), ob = mp_bytes(delta);
        if (out) {
            if (at + 1 + lb + ob + 1 > room)
                return 0;
            out[at] = (u8)(ob << 4 | lb);
            for (u32 j = 0; j < lb; j++, len >>= 8)
                out[at + 1 + j] = (u8)len;
            for (u32 j = 0; j < ob; j++, delta >>= 8)
                out[at + 1 + lb + j] = (u8)delta;
        }
        at += 1 + lb + ob;
        prev = r[i].lcn;
    }
    if (out)
        out[at] = 0;
    return at + 1;
}

/* a non-resident attribute put in (as rec_put_resident): its runs, `size` bytes of them in use (all of them
   written).  Where it is, 0 no room in the record */
static u32 rec_put_runs(const struct volume *v, u8 *rec, u32 at, u32 type, const char *name, const struct nrun *r,
                        u32 n, u64 size, u16 id)
{
    u32 nlen = (u32)path_len(name), moff = (0x40 + 2 * nlen + 7) & ~7u;
    u32 len = (moff + mp_encode(r, n, 0, 0) + 7) & ~7u, clusters = n ? r[n - 1].vcn + r[n - 1].len : 0;
    at = rec_place(v, rec, at, type, len, id);
    if (!at)
        return 0;
    rec[at + 8] = 1;
    rec[at + 9] = (u8)nlen;
    put16(rec + at + 10, 0x40);
    put64(rec + at + 0x18, (u64)clusters - 1);          /* (the last cluster's number; none: -1) */
    put16(rec + at + 0x20, (u16)moff);
    put64(rec + at + 0x28, (u64)clusters << (9 + v->csh));
    put64(rec + at + 0x30, size);
    put64(rec + at + 0x38, size);
    for (u32 i = 0; i < nlen; i++)
        put16(rec + at + 0x40 + 2 * i, (u8)name[i]);
    (void)mp_encode(r, n, rec + at + moff, len - moff);
    return at;
}

/* the runs of the non-resident attribute at `at` of a record into *runs: 0, -1 (resident, compressed,
   sparse, in several records, damaged, too many pieces) */
static int nw_attr_runs(const struct volume *v, const u8 *rec, u32 at, struct runs *runs)
{
    if (!at || !rec[at + 8] || (le16(rec + at + 0x0C) & 0xC0FF) || le64(rec + at + 0x10))
        return nw_err("NTFS: an attribute of a kind the demo does not write (in the record, compressed or sparse)");
    runs->n = 0;
    fail_why = 0;
    if (runs_add(v, rec + at, runs) < 0)
        return nw_err(fail_why);
    for (u32 i = 0; i < runs->n; i++)
        if (runs->r[i].lcn == NO_LCN)
            return nw_err("NTFS: a sparse attribute");
    return 0;
}

/* -- MFT records -- */

/* MFT record `rec` as it is on the disk into buf (REC_MAX bytes): 0 a FILE record (its fixups undone), 1 not
   one, -1 not read.  A record of two sectors is read with the sector after it where $MFT has one there: a
   high-speed disk is read an odd number of sectors at a time (read_count), so two sectors would be two
   READs -- and the box's slow stick loses about one command in ten */
static int nw_mft_raw(struct disk *k, const struct volume *v, u32 rec, u8 *buf)
{
    u64 off = (u64)rec * v->rec_size;
    u32 n = v->rec_size / SECTOR, csh = v->csh;
    const struct nrun *p = off >> (9 + csh + 32) ? 0 : run_at(v->mft.r, v->mft.n, (u32)(off >> (9 + csh)));
    if (n == 2 && p && (off >> 9) + 2 < ((u64)(p->vcn + p->len) << csh))
        n = 3;                          /* (the third sector is in the same run: one READ) */
    if (nw_read(k, v, &v->mft, off, n, buf) < 0)
        return -1;
    return same(buf, "FILE", 4) && fixup(buf, v->rec_size) == 0 ? 0 : 1;
}

/* record `rec` -- in use, sound -- into buf: 0, -1 */
static int nw_mft_get(struct disk *k, const struct volume *v, u32 rec, u8 *buf)
{
    int r = nw_mft_raw(k, v, rec, buf);
    if (r < 0)
        return -1;
    if (r || le16(buf + 4) != 0x30 || le32(buf + 0x2C) != rec || rec_check(v, buf) < 0)
        return nw_err("NTFS: a file record the demo does not take (damaged, or of an old kind)");
    if (!(le16(buf + 0x16) & 1))
        return nw_err("NTFS: a file record that is not in use");
    return 0;
}

/* the record in buf written: its update sequence number one up, the fixups in for the disk and out again;
   $MFTMirr gets its copy of the records it holds */
static int nw_mft_put(struct disk *k, struct volume *v, u32 rec, u8 *buf)
{
    fixup_put(buf, v->rec_size);
    int r = runs_write(k, v, v->mft.r, v->mft.n, (u64)rec * v->rec_size, v->rec_size / SECTOR, buf);
    if (r == 0 && rec < nw.mirror_count)
        r = runs_write(k, v, nw.mir.r, nw.mir.n, (u64)rec * v->rec_size, v->rec_size / SECTOR, buf);
    (void)fixup(buf, v->rec_size);
    return r;
}

/* -- bitmaps: $Bitmap (a bit a cluster), $MFT's $BITMAP (a bit a record) -- */

/* in a bitmap (an attribute's runs) the first run of clear bits from bit `from` on and below `to` that is
   `want` long -- when there is none that long, the longest (with `first`: the first one, however short):
   where (*at), how long (*len; 0: no clear bit).  0, -1 not read */
static int bm_find(struct disk *k, const struct volume *v, const struct runs *bm, u32 from, u32 to, u32 want,
                   int first, u32 *at, u32 *len)
{
    u32 run = 0, run_at = 0, best = 0, best_at = 0, bit = from;
    *len = 0;
    while (bit < to) {
        u32 sec = bit >> 12, last = (to - 1) >> 12;     /* (4096 bits a sector) */
        u32 n = last - sec + 1 < NW_WINDOW ? last - sec + 1 : NW_WINDOW;
        if (nw_read(k, v, bm, (u64)sec << 9, n, nw_bm) < 0)
            return -1;
        u32 base = sec << 12, end = last - sec < NW_WINDOW ? to : base + n * 4096;
        while (bit < end) {
            u32 byte = nw_bm[(bit - base) >> 3];
            if (!(bit & 7) && end - bit >= 8 && (byte == 0xFF || !byte)) {      /* a whole byte at once */
                if (byte) {
                    if (run && first)
                        break;
                    if (run > best) {
                        best = run;
                        best_at = run_at;
                    }
                    run = 0;
                } else {
                    if (!run)
                        run_at = bit;
                    run += 8;
                }
                bit += 8;
            } else {
                if (byte & (1u << (bit & 7))) {
                    if (run && first)
                        break;
                    if (run > best) {
                        best = run;
                        best_at = run_at;
                    }
                    run = 0;
                } else {
                    if (!run)
                        run_at = bit;
                    run++;
                }
                bit++;
            }
            if (run >= want) {
                *at = run_at;
                *len = want;
                return 0;
            }
        }
        if (bit < end)
            break;                      /* (the first run ended) */
        (void)now_ms();                 /* (the watchdog: a big bitmap) */
    }
    if (run > best) {
        best = run;
        best_at = run_at;
    }
    *at = best_at;
    *len = best;
    return 0;
}

/* bits first .. first + count - 1 of a bitmap set or cleared: 0, -1.  One to be set that is set already is
   refused: somebody has that cluster or record */
static int bm_set(struct disk *k, struct volume *v, const struct runs *bm, u32 first, u32 count, int set)
{
    while (count) {
        u32 sec = first >> 12, in = first & 4095, n = 4096 - in < count ? 4096 - in : count;
        if (nw_read(k, v, bm, (u64)sec << 9, 1, nw_bm) < 0)
            return -1;
        for (u32 i = in; i < in + n; i++) {
            u8 m = (u8)(1u << (i & 7));
            if (!set)
                nw_bm[i >> 3] &= (u8)~m;
            else if (nw_bm[i >> 3] & m)
                return nw_err("NTFS: a bitmap says in use what was free a moment ago (nothing more written)");
            else
                nw_bm[i >> 3] |= m;
        }
        if (runs_write(k, v, bm->r, bm->n, (u64)sec << 9, 1, nw_bm) < 0)
            return -1;
        first += n;
        count -= n;
    }
    return 0;
}

/* the clear bits among a bitmap's first `bits`: 0, -1 not read, -2 Ctrl-C */
static int bm_count(struct disk *k, const struct volume *v, const struct runs *bm, u32 bits, u32 *clear)
{
    *clear = 0;
    for (u32 bit = 0; bit < bits;) {
        u32 sec = bit >> 12, last = (bits - 1) >> 12, n = last - sec + 1 < NW_WINDOW ? last - sec + 1 : NW_WINDOW;
        if (nw_read(k, v, bm, (u64)sec << 9, n, nw_bm) < 0)
            return -1;
        for (u32 i = 0; i < n * SECTOR && bit < bits; i++)
            for (u32 j = 0; j < 8 && bit < bits; j++, bit++)
                *clear += !(nw_bm[i] & (1u << j));
        if (uart_getc() == 3)
            return -2;
    }
    return 0;
}

/* do clusters lcn .. lcn + len - 1 touch a run of *r? */
static int nw_overlap(const struct runs *r, u32 lcn, u32 len)
{
    for (u32 i = 0; i < r->n; i++)
        if (r->r[i].lcn != NO_LCN && lcn < r->r[i].lcn + r->r[i].len && lcn + len > r->r[i].lcn)
            return 1;
    return 0;
}

/* clusters made free in $Bitmap -- never the boot sector's, $MFT's, $MFTMirr's or the bitmaps' own (a file
   whose runs name those is damaged) */
static int nw_free_ok(const struct volume *v, u32 lcn, u32 len)
{
    if (!lcn || lcn >= v->ntfs_clusters || len > v->ntfs_clusters - lcn || nw_overlap(&v->mft, lcn, len)
        || nw_overlap(&nw.mir, lcn, len) || nw_overlap(&nw.bmp, lcn, len) || nw_overlap(&nw.mbm, lcn, len))
        return nw_err("NTFS: clusters that are the volume's own in a file's runs (a damaged file): not freed, "
                      "the file not changed");
    return 0;
}

static int nw_free(struct disk *k, struct volume *v, u32 lcn, u32 len)
{
    if (!len)
        return 0;
    if (nw_free_ok(v, lcn, len) < 0)
        return -1;
    v->nw_small = 0;                    /* (there may be a long piece again) */
    return bm_set(k, v, &nw.bmp, lcn, len, 0);
}

static const char nw_full[] = "the NTFS volume is full";

/* `want` clusters taken in $Bitmap: at `near` when that one is free (a file that grows: on from its last
   cluster), else the first free piece that long -- outside the MFT zone while there is room (`mft`: inside it
   first) --, else the longest piece there is.  Where (*lcn) and how many (*got: `want` at most): 0, -1.
   The search starts where the last one ended (v->alloc_hint) and reads the bitmap from there on, 4 KB at
   a time, only as far as it has to: on a big volume $Bitmap is megabytes (a 64 GB stick's: 1.86 MB, 17 s
   to read on the box) -- so once a search has found no piece of `want` outside the MFT zone (it read the
   bitmap through), the volume is known to be in small pieces (v->nw_small) and from then on the first
   free piece after the hint is taken, however short, until clusters are freed again */
static int nw_alloc(struct disk *k, struct volume *v, u32 want, u32 near, int mft, u32 *lcn, u32 *got)
{
    u32 total = v->ntfs_clusters, zs = nw.zone_start, ze = nw.zone_end, at = 0, len = 0, best_at = 0, best = 0;
    u32 hint = v->alloc_hint >= ze && v->alloc_hint < total ? v->alloc_hint : ze;
    u32 from[4] = {hint, ze, 1, zs}, to[4] = {total, hint, zs, ze};     /* (cluster 0: the boot sector's) */
    if (!zs)
        from[3] = 1;
    if (near && near < total) {
        if (bm_find(k, v, &nw.bmp, near, near + want > total || near + want < near ? total : near + want, want, 1,
                    &at, &len) < 0)
            return -1;
        if (len && at != near)
            len = 0;
    }
    for (int i = 0; i < 4 && !len; i++) {
        int z = mft ? (i + 3) & 3 : i;                  /* ($MFT: its zone first) */
        if (from[z] >= to[z])
            continue;
        if (!mft && z == 3 && best)
            break;                                      /* (a piece outside the zone, though a short one) */
        if (bm_find(k, v, &nw.bmp, from[z], to[z], want, !mft && v->nw_small, &at, &len) < 0)
            return -1;
        if (len && !mft && v->nw_small)
            break;                                      /* (the first free piece) */
        if (len < want) {
            if (len > best) {
                best = len;
                best_at = at;
            }
            len = 0;
        }
    }
    if (!len && best) {
        len = best;
        at = best_at;
        if (!mft)
            v->nw_small = 1;
    }
    if (!len)
        return nw_err(nw_full);
    if (bm_set(k, v, &nw.bmp, at, len, 1) < 0)
        return -1;
    if (!mft)
        v->alloc_hint = at + len;
    *lcn = at;
    *got = len;
    return 0;
}

/* a run of clusters added to *runs (on from its last run when they follow it): 0, -1 too many pieces */
static int runs_append(struct runs *runs, u32 lcn, u32 len)
{
    struct nrun *last = runs->n ? &runs->r[runs->n - 1] : 0;
    if (last && last->lcn + last->len == lcn) {
        last->len += len;
        return 0;
    }
    if (runs->n >= runs->max)
        return -1;
    runs->r[runs->n].vcn = last ? last->vcn + last->len : 0;
    runs->r[runs->n].lcn = lcn;
    runs->r[runs->n].len = len;
    runs->n++;
    return 0;
}

/* *runs cut back to its first `keep` clusters, the others made free again: 0, -1 */
static int runs_trim(struct disk *k, struct volume *v, struct runs *runs, u32 keep)
{
    while (runs->n) {
        struct nrun *r = &runs->r[runs->n - 1];
        if (r->vcn + r->len <= keep)
            break;
        u32 cut = r->vcn >= keep ? r->len : r->vcn + r->len - keep;
        if (nw_free(k, v, r->lcn + r->len - cut, cut) < 0)
            return -1;
        r->len -= cut;
        if (!r->len)
            runs->n--;
    }
    return 0;
}

static u32 runs_clusters(const struct runs *runs)
{
    return runs->n ? runs->r[runs->n - 1].vcn + runs->r[runs->n - 1].len : 0;
}

/* an attribute's clusters (its header at h): are its runs sound, and clusters that may be freed (asked
   before anything is changed) -- and, with `free_them`, each made free.  0, -1 */
static int nw_attr_free(struct disk *k, struct volume *v, const u8 *h, int free_them)
{
    u32 hlen = le32(h + 4), p = le16(h + 0x20);
    s64 lcn = 0;
    if (!h[8])
        return 0;
    if (hlen < 0x40 || p < 0x40 || p > hlen)
        return nw_err("NTFS: a damaged attribute");
    while (p < hlen && h[p]) {
        u32 ls = h[p] & 15, os = h[p] >> 4, len = 0;
        u64 delta = 0;
        if (!ls || ls > 4 || !os || os > 8 || p + 1 + ls + os > hlen)
            return nw_err("NTFS: damaged runs (or sparse ones)");
        for (u32 i = 0; i < ls; i++)
            len |= (u32)h[p + 1 + i] << (8 * i);
        for (u32 i = 0; i < os; i++)
            delta |= (u64)h[p + 1 + ls + i] << (8 * i);
        if (os < 8 && (h[p + ls + os] & 0x80))
            delta |= ~(u64)0 << (8 * os);
        p += 1 + ls + os;
        lcn += (s64)delta;
        if (!len || lcn <= 0 || (u64)lcn + len > v->ntfs_clusters)
            return nw_err("NTFS: a run outside the volume");
        if ((free_them ? nw_free(k, v, (u32)lcn, len) : nw_free_ok(v, (u32)lcn, len)) < 0)
            return -1;
    }
    return 0;
}

/* every cluster a record's attributes have: sound?  With `free_them`: made free */
static int nw_rec_free_runs(struct disk *k, struct volume *v, const u8 *rec, int free_them)
{
    for (u32 at = 0; (at = attr_next(v, rec, at));)
        if (nw_attr_free(k, v, rec + at, free_them) < 0)
            return -1;
    return 0;
}

/* -- the volume: what is read once (nw_load), the gate -- */

static u32 shift_of(u32 n)              /* a power of two as a shift */
{
    u32 s = 0;
    while ((1u << s) < n)
        s++;
    return s;
}

/* where the volume's bitmaps and $MFTMirr are, how many records $MFT has, its $UpCase table: 0, -1 (why) */
static int nw_load(struct disk *k, struct volume *v)
{
    static struct nrun up_run[32];
    struct runs up = {up_run, 0, 32};
    u8 *r = nw_tmp;
    u32 at, cshift = 9 + v->csh, rsh = shift_of(v->rec_size);
    nw.k = 0;
    nw.bmp.r = nw.bmp_run;
    nw.bmp.max = NW_BMP_RUNS;
    nw.mbm.r = nw.mbm_run;
    nw.mbm.max = NW_MBM_RUNS;
    nw.mir.r = nw.mir_run;
    nw.mir.max = 8;
    if (v->ntfs_clusters > 0xFFF00000u || v->ntfs_clusters < 64)
        return nw_err("NTFS: a volume of a size the demo does not write");
    /* $Bitmap: a bit for each cluster */
    if (nw_mft_get(k, v, 6, r) < 0 || nw_attr_runs(v, r, at = rec_find(v, r, 0x80, ""), &nw.bmp) < 0)
        return -1;
    if (le64(r + at + 0x30) < (v->ntfs_clusters + 7) / 8 || le64(r + at + 0x38) < (v->ntfs_clusters + 7) / 8)
        return nw_err("NTFS: $Bitmap is shorter than the volume");
    /* $MFT: its records, its own bitmap */
    if (nw_mft_get(k, v, 0, r) < 0)
        return -1;
    at = rec_find(v, r, 0x80, "");
    if (!at || !r[at + 8] || le64(r + at + 0x38) >> (rsh + 31)
        || le64(r + at + 0x38) > (u64)runs_clusters(&v->mft) << cshift)
        return nw_err("NTFS: $MFT's own record is not one the demo takes");
    nw.mft_records = (u32)(le64(r + at + 0x38) >> rsh);
    if (nw_attr_runs(v, r, at = rec_find(v, r, 0xB0, ""), &nw.mbm) < 0)
        return -1;
    if (le64(r + at + 0x30) != le64(r + at + 0x38) || le64(r + at + 0x30) > 0x10000000u
        || le64(r + at + 0x30) > (u64)runs_clusters(&nw.mbm) << cshift)
        return nw_err("NTFS: $MFT's bitmap is not one the demo takes");
    nw.mbm_bytes = (u32)le64(r + at + 0x30);
    if (nw.mft_records < NW_META || nw.mft_records > nw.mbm_bytes * 8)
        return nw_err("NTFS: $MFT's bitmap is shorter than $MFT");
    /* $MFTMirr: a copy of $MFT's first four records (ntfs-3g: of a cluster's worth, when that is more) */
    if (nw_mft_get(k, v, 1, r) < 0 || nw_attr_runs(v, r, at = rec_find(v, r, 0x80, ""), &nw.mir) < 0)
        return -1;
    u32 most = (1u << cshift) > 4 * v->rec_size ? (1u << cshift) >> rsh : 4;
    u64 held = le64(r + at + 0x30) >> rsh;
    nw.mirror_count = held < most ? (u32)held : most;
    if (nw.mirror_count < 4 || ((u64)nw.mirror_count << rsh) > (u64)runs_clusters(&nw.mir) << cshift)
        return nw_err("NTFS: $MFTMirr is shorter than four records");
    /* $UpCase: every character's upper case (file names are compared through it) */
    if (nw_mft_get(k, v, 10, r) < 0 || nw_attr_runs(v, r, at = rec_find(v, r, 0x80, ""), &up) < 0)
        return -1;
    if (le64(r + at + 0x30) != 2 * UPCASE_CHARS || le64(r + at + 0x38) != 2 * UPCASE_CHARS)
        return nw_err("NTFS: $UpCase is not 128 KB");
    for (u32 s = 0, n; s < 2 * UPCASE_CHARS / SECTOR; s += n) {
        n = 2 * UPCASE_CHARS / SECTOR - s < NW_WINDOW ? 2 * UPCASE_CHARS / SECTOR - s : NW_WINDOW;
        if (nw_read(k, v, &up, (u64)s * SECTOR, n, (u8 *)nw_up + s * SECTOR) < 0)
            return -1;
        (void)now_ms();
    }
    if (nw_up['a'] != 'A' || nw_up['z'] != 'Z' || nw_up['A'] != 'A' || nw_up['0'] != '0' || nw_up['$'] != '$')
        return nw_err("NTFS: $UpCase is not the table the demo expects");
    nw.zone_start = v->mft_run[0].lcn;
    nw.zone_end = nw.zone_start + v->ntfs_clusters / 8;
    if (nw.zone_end > v->ntfs_clusters || nw.zone_end < nw.zone_start)
        nw.zone_end = v->ntfs_clusters;
    nw.rec_hint = NW_FIRST_REC;
    nw.k = k;
    nw.v = v;
    return 0;
}

/* a restart page of the journal (4096 bytes at p: its fixups are undone in place) looked at, as ntfs-3g's
   ntfs_check_restart_page_header and ntfs_check_restart_area do */
static void nw_restart_page(u8 *p, struct nw_page *g)
{
    int blank = 1;
    for (u32 i = 0; i < NW_BLOCK; i++)
        if (p[i] != 0xFF)
            blank = 0;
    for (int i = 0; i < 4; i++)
        g->magic[i] = p[i] >= 32 && p[i] < 127 ? (char)p[i] : '.';
    g->magic[4] = 0;
    g->bad = 0;
    g->kind = blank ? 0 : 2;
    if (blank)
        return;
    if (same(p, "CHKD", 4)) {
        g->bad = "chkdsk's mark";
        return;
    }
    if (!same(p, "RSTR", 4)) {
        g->bad = "not a restart page";
        return;
    }
    u32 usa = le16(p + 4), count = le16(p + 6), ra = le16(p + 0x18);
    g->sys_page = le32(p + 0x10);
    g->log_page = le32(p + 0x14);
    g->minor = le16(p + 0x1A);
    g->major = le16(p + 0x1C);
    if (g->sys_page != NW_BLOCK || g->log_page != NW_BLOCK)
        g->bad = "pages that are not 4096 bytes";
    else if (!((g->major == 1 && g->minor == 1) || (g->major == 2 && g->minor == 0)))
        g->bad = "a version the demo does not know";
    else if (count != NW_BLOCK / SECTOR + 1 || usa < 30 || usa + 2 * count > SECTOR - 2)
        g->bad = "a damaged header (its update sequence array)";
    else if ((ra & 7) || ra < usa + 2 * count || ra + 0x30 > SECTOR - 2)
        g->bad = "a damaged header (its restart area's place)";
    else if (le64(p + 8))
        g->bad = "chkdsk's mark (its LSN)";
    else if (fixup(p, NW_BLOCK) < 0)
        g->bad = "a write cut off half way (its sectors' check words differ)";
    if (g->bad)
        return;
    const u8 *a = p + ra;
    u32 ca = le16(a + 0x16), len = le16(a + 0x14), bits = 0;
    g->lsn = le64(a);
    g->clients = le16(a + 8);
    g->free_list = le16(a + 0x0A);
    g->in_use = le16(a + 0x0C);
    g->flags = le16(a + 0x0E);
    for (u64 size = le64(a + 0x18); size; size >>= 1)
        bits++;
    if ((ca & 7) || ra + ca > SECTOR - 2 || ra + ca + 160u * g->clients > NW_BLOCK || ra + len > NW_BLOCK
        || ca + 160u * g->clients > len)
        g->bad = "a damaged restart area (its client array)";
    else if ((g->free_list != 0xFFFF && g->free_list >= g->clients)
             || (g->in_use != 0xFFFF && g->in_use >= g->clients))
        g->bad = "a damaged restart area (its client lists)";
    else if (le32(a + 0x10) != 67 - bits || (le16(a + 0x24) & 7) || (le16(a + 0x26) & 7))
        g->bad = "a damaged restart area (its sizes)";
    else
        g->kind = 1;
}

/* the journal: $LogFile's (record 2) first two pages -- its two restart pages -- read and judged: into
   g->page, g->journal, g->newer; its runs into *log (when not 0) */
static void nw_journal_read(struct disk *k, struct volume *v, struct nw_info *g, struct runs *log, u64 *size)
{
    static struct nrun log_run[64];
    struct runs runs = {log_run, 0, 64};
    u8 *r = nw_tmp;
    u32 at;
    g->journal = J_UNREAD;
    if (nw_mft_get(k, v, 2, r) < 0 || nw_attr_runs(v, r, at = rec_find(v, r, 0x80, ""), &runs) < 0)
        return;
    u64 bytes = le64(r + at + 0x30);
    if (bytes < 2 * NW_BLOCK || bytes > (u64)runs_clusters(&runs) << (9 + v->csh) || le64(r + at + 0x38) < bytes)
        return;
    g->log_kb = (u32)(bytes >> 10);
    if (log) {
        *log = runs;
        *size = bytes;
    }
    for (u32 i = 0; i < 2; i++) {
        if (nw_read(k, v, &runs, (u64)i * NW_BLOCK, NW_BLOCK / SECTOR, nw_blk) < 0)
            return;
        nw_restart_page(nw_blk, &g->page[i]);
    }
    const struct nw_page *a = &g->page[0], *b = &g->page[1];
    if (!a->kind && !b->kind) {
        /* no restart pages: empty -- when the rest is 0xFF too.  Not all of it is read (64 MB on the box's
           stick): a sector where ntfs-3g's ntfs_check_logfile looks (at every power of two from here to the
           end), and the last block.  'reset-journal' fills from the start, so one cut short shows at the
           first of these it did not reach -- one cut short between the last two of them (in the journal's
           second half) reads as empty here, as it does to ntfs-3g; there is no restart page then either way,
           nothing that could be replayed */
        g->journal = J_EMPTY;
        for (u64 off = 2 * NW_BLOCK; bytes >= 3 * NW_BLOCK && g->journal == J_EMPTY;
             off = off << 1 < bytes ? off << 1 : bytes - NW_BLOCK) {
            if (nw_read(k, v, &runs, off & ~(u64)(SECTOR - 1), 1, nw_blk) < 0) {
                g->journal = J_UNREAD;
                return;
            }
            for (u32 i = 0; i < SECTOR; i++)
                if (nw_blk[i] != 0xFF)
                    g->journal = J_PARTLY;
            if (off >= bytes - NW_BLOCK)
                break;
        }
    } else if (a->kind != 1 || b->kind != 1) {
        g->journal = J_BAD;
    } else {
        g->newer = (s64)b->lsn > (s64)a->lsn;   /* (the page written last tells; LSNs are signed, as ntfs-3g
                                                   compares them) */
        const struct nw_page *p = &g->page[g->newer];
        g->journal = p->major == 2 ? J_LFS2 : p->in_use == 0xFFFF || (p->flags & 2) ? J_CLEAN : J_UNCLEAN;
    }
}

/* /hiberfil.sys with a hibernated Windows in it (as ntfs-3g's ntfs_volume_check_hiberfile): 1, 0 none, -1 it
   does not read */
static int nw_hibernated(struct disk *k, struct volume *v)
{
    static struct nrun hib_run[16];
    static struct runs hib = {hib_run, 0, 16};
    static struct reader r;
    int found = find_in(k, v, 0, NO_SEQ, "hiberfil.sys", 12, &nw_find);
    if (found <= 0 || (nw_find.found.attr & 0x10))
        return found < 0 ? -1 : 0;
    r.runs = &hib;
    r.res = nw_rec;
    if (file_open(&r, k, v, &nw_find.found, "hiberfil.sys") < 0)
        return -1;
    if (r.size < NW_BLOCK)
        return 1;                       /* (ntfs-3g: "hibernated non-system partition") */
    u32 got = 0, zero = 1;
    while (got < NW_BLOCK) {
        int n = file_read(&r, nw_blk + got, NW_BLOCK - got);
        if (n <= 0)
            return -1;
        got += (u32)n;
    }
    for (u32 i = 0; i < NW_BLOCK; i++)
        zero &= !nw_blk[i];
    return zero || same(nw_blk, "hibr", 4) || same(nw_blk, "HIBR", 4);
}

/* everything the gate looks at, read: into *g; g->why says why the demo does not write the volume (the first
   reason found; 0: it does) */
static void nw_gate_read(struct disk *k, struct volume *v, struct nw_info *g)
{
    u8 *r = nw_tmp;
    u32 at;
    struct nattr a;
    wipe((u8 *)g, sizeof(*g));
    /* everything kept of the volume is read again from the disk: $MFT's own runs first (ntfs_mount read
       them; a change that failed half way -- $MFT made longer -- may have left them ahead of record 0), the
       search hints; nw_load below reads the rest */
    static struct nrun was[MFT_RUNS];   /* (the runs as they were: kept, for reading, when record 0 does not
                                           read now -- the volume is not written then) */
    u32 was_n = v->mft.n;
    for (u32 i = 0; i < was_n; i++)
        was[i] = v->mft_run[i];
    nw_forget(k);
    v->alloc_hint = 0;
    v->nw_small = 0;
    v->mft_run[0].vcn = 0;
    v->mft_run[0].len = (16 * v->rec_size) >> (9 + v->csh) ? (16 * v->rec_size) >> (9 + v->csh) : 1;
    v->mft.n = 1;
    if (mft_read(k, v, 0, nrec) < 0 || ntfs_attr(k, v, nrec, 0, 0x80, "", &a, 0, 0, &v->mft) != 1 || a.resident) {
        for (u32 i = 0; i < was_n; i++)
            v->mft_run[i] = was[i];
        v->mft.n = was_n;
        g->why = "its $MFT's own record does not read";
        return;
    }
    /* $Volume (record 3): the version, the flags */
    if (nw_mft_get(k, v, 3, r) < 0 || !(at = rec_find(v, r, 0x70, "")) || r[at + 8] || le32(r + at + 0x10) < 12) {
        g->why = "its $Volume record does not read";
    } else {
        const u8 *val = r + at + le16(r + at + 0x14);
        g->version_read = 1;
        g->major = val[8];
        g->minor = val[9];
        g->vflags = le16(val + 10);
        if (g->major != 3)
            g->why = "it is not NTFS 3.x";
        else if (g->vflags & 0x0001)
            g->why = "it is marked dirty (not removed safely, or chkdsk is due): run chkdsk /f in Windows";
        else if (g->vflags & 0xC026)    /* (with the dirty bit: the flags ntfs-3g mounts read-only for, 0xC027
                                           -- the log to be resized, an upgrade on mount, object IDs to be
                                           repaired, chkdsk under way or just done; other bits do not matter) */
            g->why = "Windows has work pending on it (its volume flags): mount it in Windows once, then 'Safely "
                     "remove' it";
    }
    if (!g->why && v->idx_size != NW_BLOCK)
        g->why = "its index blocks are not 4096 bytes";
    if (!g->why && v->rec_size < 1024)
        g->why = "its file records are smaller than 1 KB";
    /* the journal */
    nw_journal_read(k, v, g, 0, 0);
    if (!g->why && g->journal != J_EMPTY && g->journal != J_CLEAN)
        g->why = g->journal == J_UNREAD ? "its journal ($LogFile) does not read"
                 : g->journal == J_UNCLEAN ? "it was not removed safely (Windows would replay its journal over what "
                                             "is written here): 'Safely remove' it in Windows first"
                 : g->journal == J_LFS2 ? "Windows left it mounted (fast start-up or hibernation: its journal is "
                                          "version 2.0): shut Windows down fully, or 'Safely remove' it there"
                 : g->journal == J_PARTLY ? "its journal was emptied only in part (a 'reset-journal' cut short): "
                                            "run it again, to its end"
                 : "its journal's restart pages are not valid";
    /* the bitmaps, $MFTMirr, $UpCase */
    if (nw_load(k, v) < 0) {
        if (!g->why)
            g->why = nw_why ? nw_why : "a sector of it did not read";
        return;
    }
    g->loaded = 1;
    for (u32 i = 0; i < 4 && !g->why; i++) {            /* $MFTMirr: the copy as the original */
        u32 n = v->rec_size / SECTOR;
        if (nw_read(k, v, &v->mft, (u64)i * v->rec_size, n, nw_tmp) < 0
            || nw_read(k, v, &nw.mir, (u64)i * v->rec_size, n, nw_m0) < 0) {
            g->why = "a sector of it did not read";
            break;
        }
        u32 used = le32(nw_tmp + 0x18) < v->rec_size ? le32(nw_tmp + 0x18) : v->rec_size;
        for (u32 j = 0; j < used; j++)
            if (nw_tmp[j] != nw_m0[j]) {
                g->why = "$MFTMirr is not a copy of $MFT's first records: run chkdsk /f in Windows";
                break;
            }
    }
    if (!g->why) {
        int h = nw_hibernated(k, v);
        if (h)
            g->why = h < 0 ? "its hiberfil.sys does not read" : "Windows is hibernated on it (hiberfil.sys)";
    }
}

/* the volume about to be written: through the gate (looked at once), its bitmaps and $UpCase at hand.
   0, -1 (nw_why) */
static int nw_use(struct disk *k, struct volume *v)
{
    if (v->nw_state == NW_UNKNOWN) {
        static struct nw_info g;
        nw_gate_read(k, v, &g);
        v->nw_state = g.why ? NW_REFUSED : NW_OK;
        v->nw_why = g.why;
    }
    if (v->nw_state != NW_OK)
        return nw_err(v->nw_why);
    if (nw.k != k || nw.v != v)         /* (the same volume as before: its bitmaps' places and $UpCase are at
                                           hand -- a disk plugged in again starts at the gate, above) */
        return nw_load(k, v);
    return 0;
}

/* -- $MFT: a record for a new file -- */

/* $MFT made longer: the room its clusters still have formatted as unused records, else 64 records' worth of
   new clusters (after its last one when they are free) -- taken in $Bitmap, formatted, $MFT's bitmap grown to
   cover them, then record 0 (and its copy in $MFTMirr) with the new runs and sizes.  0, -1 */
static int nw_mft_grow(struct disk *k, struct volume *v)
{
    u8 *m = nw_m0, *t = nw_tmp;
    u32 cshift = 9 + v->csh, rsh = shift_of(v->rec_size), da, ba;
    u32 per = v->rec_size >> cshift ? v->rec_size >> cshift : 1;       /* (a record's clusters, when it has several) */
    u32 have = runs_clusters(&v->mft), bm_have = runs_clusters(&nw.mbm);
    u32 mft_n = v->mft.n, mft_len = v->mft.r[mft_n - 1].len, mft_lcn = 0, mft_got = 0;     /* (for the undo) */
    u32 bm_n = nw.mbm.n, bm_len = nw.mbm.r[bm_n - 1].len, bm_lcn = 0, bm_got = 0;
    if (nw_mft_get(k, v, 0, m) < 0)
        return -1;
    da = rec_find(v, m, 0x80, "");
    ba = rec_find(v, m, 0xB0, "");
    if (rec_find(v, m, 0x20, "") || !da || !ba || !m[da + 8] || !m[ba + 8] || (le16(m + da + 0x0C) & 0xC0FF)
        || le64(m + da + 0x28) != (u64)have << cshift || (u32)(le64(m + da + 0x38) >> rsh) != nw.mft_records)
        return nw_err("no free file record, and $MFT is not one the demo makes longer (it has an attribute list)");
    if ((u64)(nw.mft_records + 1) << rsh > (u64)have << cshift) {       /* no room left in its clusters: more */
        u32 want = (64 * v->rec_size) >> cshift, lcn, got;
        struct nrun *last = &v->mft.r[v->mft.n - 1];
        if (want < per)
            want = per;
        if (nw_alloc(k, v, want, last->lcn + last->len, 1, &lcn, &got) < 0)
            return -1;
        if (got % per) {                                /* (whole records only) */
            nw_back(v, nw_free(k, v, lcn + got - got % per, got % per));
            got -= got % per;
        }
        if (!got || runs_append(&v->mft, lcn, got) < 0) {
            nw_back(v, nw_free(k, v, lcn, got));
            return nw_err("no free file record, and no room to make $MFT longer");
        }
        mft_lcn = lcn;
        mft_got = got;
        have += got;
    }
    u32 records = (u32)(((u64)have << cshift) >> rsh), count = v->rec_size / SECTOR + 1;
    u32 first = (0x30 + 2 * count + 7) & ~7u, need = ((records + 63) >> 6) << 3;
    for (u32 i = nw.mft_records; i < records; i++) {    /* the new records: FILE records not in use */
        wipe(t, v->rec_size);
        copy(t, (const u8 *)"FILE", 4);
        put16(t + 4, 0x30);
        put16(t + 6, (u16)count);
        put16(t + 0x10, 1);
        put16(t + 0x14, (u16)first);
        put32(t + 0x18, first + 8);
        put32(t + 0x1C, v->rec_size);
        put32(t + 0x2C, i);
        put32(t + first, 0xFFFFFFFFu);
        fixup_put(t, v->rec_size);
        if (runs_write(k, v, v->mft.r, v->mft.n, (u64)i * v->rec_size, v->rec_size / SECTOR, t) < 0)
            goto undo;
        (void)now_ms();
    }
    if (need > nw.mbm_bytes) {                          /* $MFT's bitmap: 8 more bytes at a time, zero */
        if (need > (u64)bm_have << cshift) {
            u32 lcn, got;
            struct nrun *last = &nw.mbm.r[nw.mbm.n - 1];
            if (nw_alloc(k, v, 1, last->lcn + last->len, 0, &lcn, &got) < 0)
                goto undo;
            if (runs_append(&nw.mbm, lcn, got) < 0) {
                nw_back(v, nw_free(k, v, lcn, got));
                nw_err("$MFT's bitmap is in too many pieces for the demo to make it longer");
                goto undo;
            }
            bm_lcn = lcn;
            bm_got = got;
        }
        for (u32 at = nw.mbm_bytes; at < need;) {
            u32 sec = at / SECTOR, in = at % SECTOR, n = need - at < SECTOR - in ? need - at : SECTOR - in;
            if (in && nw_read(k, v, &nw.mbm, (u64)sec * SECTOR, 1, nw_bm) < 0)
                goto undo;
            wipe(nw_bm + in, SECTOR - in);
            if (runs_write(k, v, nw.mbm.r, nw.mbm.n, (u64)sec * SECTOR, 1, nw_bm) < 0)
                goto undo;
            at += n;
        }
    } else {
        need = nw.mbm_bytes;
    }
    /* record 0: $DATA's and $BITMAP's runs and sizes */
    if (!rec_put_runs(v, m, da, 0x80, "", v->mft.r, v->mft.n, (u64)records << rsh, 0)
        || !(ba = rec_find(v, m, 0xB0, "")) || !rec_put_runs(v, m, ba, 0xB0, "", nw.mbm.r, nw.mbm.n, need, 0)) {
        nw_err("no room in $MFT's own record for another piece of it");
        goto undo;
    }
    if (nw_mft_put(k, v, 0, m) < 0)
        goto undo;
    nw.mft_records = records;
    nw.mbm_bytes = need;
    return 0;
undo:                                   /* record 0 is as it was (or the volume is read-only now: a write
                                           failed).  What is kept of $MFT's and its bitmap's runs is cut back
                                           to what record 0 says first -- nw_free does not free what is
                                           $MFT's own --, then the clusters taken are given back */
    {
        const char *why = nw_why;
        v->mft.n = mft_n;
        v->mft.r[mft_n - 1].len = mft_len;
        nw.mbm.n = bm_n;
        nw.mbm.r[bm_n - 1].len = bm_len;
        nw_back(v, nw_free(k, v, bm_lcn, bm_got));
        nw_back(v, nw_free(k, v, mft_lcn, mft_got));
        nw_why = why;
    }
    return -1;
}

/* a record for a new file: a free one from NW_FIRST_REC on ($MFT made longer when it has none), taken in
   $MFT's bitmap.  Its number, the sequence number it gets (one up from the file it was before) and its update
   sequence number so far: 0, -1 */
static int nw_rec_alloc(struct disk *k, struct volume *v, u32 *rec, u16 *seq, u16 *usn)
{
    u32 at = 0, len = 0;
    for (int tries = 0; tries < 4 && !len; tries++) {
        u32 from = nw.rec_hint >= NW_FIRST_REC && nw.rec_hint < nw.mft_records ? nw.rec_hint : NW_FIRST_REC;
        if (nw.mft_records > NW_FIRST_REC) {
            if (bm_find(k, v, &nw.mbm, from, nw.mft_records, 1, 0, &at, &len) < 0)
                return -1;
            if (!len && from > NW_FIRST_REC && bm_find(k, v, &nw.mbm, NW_FIRST_REC, from, 1, 0, &at, &len) < 0)
                return -1;
        }
        if (!len && nw_mft_grow(k, v) < 0)
            return -1;
    }
    if (!len)
        return nw_err("no free file record in $MFT");
    int r = nw_mft_raw(k, v, at, nw_tmp);
    if (r < 0)
        return -1;
    if (!r && (le16(nw_tmp + 0x16) & 1))
        return nw_chk(v, "a file record is in use that $MFT's bitmap calls free: run chkdsk /f in Windows");
    *seq = r ? 1 : (u16)(le16(nw_tmp + 0x10) + 1);
    if (!*seq)
        *seq = 1;
    *usn = r || le16(nw_tmp + 4) != 0x30 ? 0 : le16(nw_tmp + 0x30);
    if (bm_set(k, v, &nw.mbm, at, 1, 1) < 0)
        return -1;
    nw.rec_hint = at + 1;
    *rec = at;
    return 0;
}

/* -- names, and the order of a directory's entries -- */

/* two $FILE_NAME keys as NTFS orders them in a directory: by their characters' upper case ($UpCase), a
   shorter name before a longer one that starts with it; two that differ in case only by the characters
   themselves.  < 0, 0 the same name, > 0 */
static int nw_collate(const u8 *a, const u8 *b)
{
    u32 na = a[0x40], nb = b[0x40], n = na < nb ? na : nb;
    for (u32 i = 0; i < n; i++) {
        u16 x = nw_up[le16(a + 0x42 + 2 * i)], y = nw_up[le16(b + 0x42 + 2 * i)];
        if (x != y)
            return x < y ? -1 : 1;
    }
    if (na != nb)
        return na < nb ? -1 : 1;
    for (u32 i = 0; i < n; i++) {
        u16 x = le16(a + 0x42 + 2 * i), y = le16(b + 0x42 + 2 * i);
        if (x != y)
            return x < y ? -1 : 1;
    }
    return 0;
}

/* two $FILE_NAME keys' names are the same but for their characters' case ($UpCase): Windows takes them for
   one name */
static int nw_same_name(const u8 *a, const u8 *b)
{
    u32 n = a[0x40];
    if (n != b[0x40])
        return 0;
    for (u32 i = 0; i < n; i++)
        if (nw_up[le16(a + 0x42 + 2 * i)] != nw_up[le16(b + 0x42 + 2 * i)])
            return 0;
    return 1;
}

/* a $FILE_NAME value into key: the directory it is in (its record and that record's sequence number), the
   times, sizes and flags (dup: 0x38 bytes), the name (ASCII), in the POSIX namespace.  Its bytes */
static u32 nw_name_value(u8 *key, u32 dir, u16 dir_seq, const u8 *dup, const char *name)
{
    u32 n = (u32)path_len(name);
    put32(key, dir);
    put16(key + 4, 0);
    put16(key + 6, dir_seq);
    copy(key + 8, dup, 0x38);
    key[0x40] = (u8)n;
    key[0x41] = 0;
    for (u32 i = 0; i < n; i++)
        put16(key + 0x42 + 2 * i, (u8)name[i]);
    return 0x42 + 2 * n;
}

/* the index entry of a file (its record and sequence number) with that key into e */
static void nw_entry_make(u8 *e, u32 rec, u16 seq, const u8 *key, u32 klen)
{
    u32 len = (0x10 + klen + 7) & ~7u;
    wipe(e, len);
    put32(e, rec);
    put16(e + 6, seq);
    put16(e + 8, (u16)len);
    put16(e + 10, (u16)klen);
    copy(e + 0x10, key, klen);
}

/* the times, sizes and flags a file's names carry (its directory's entry shows them), from its record: its
   $STANDARD_INFORMATION's times and flags, its $DATA's sizes (a directory: none) */
static void nw_dup(const struct volume *v, const u8 *rec, u8 *dup)
{
    u32 si = rec_find(v, rec, 0x10, ""), da = rec_find(v, rec, 0x80, ""), fn = rec_find(v, rec, 0x30, "");
    const u8 *s = rec + si + le16(rec + si + 0x14);
    int dir = le16(rec + 0x16) & 2;
    u64 alloc = 0, size = 0;
    copy(dup, s, 0x20);
    if (da && !dir) {
        if (rec[da + 8]) {
            alloc = le64(rec + da + 0x28);
            size = le64(rec + da + 0x30);
        } else {
            size = le32(rec + da + 0x10);
            alloc = (size + 7) & ~7ull;
        }
    }
    put64(dup + 0x20, alloc);
    put64(dup + 0x28, size);
    put32(dup + 0x30, le32(s + 0x20) | (dir ? 0x10000000u : 0));
    put32(dup + 0x34, fn ? le32(rec + fn + le16(rec + fn + 0x14) + 0x3C) : 0);
}

/* the record (in rec) of a file or directory to be written over, renamed or (`removing`) removed: one the
   demo changes?  0 (the directory it is in into *parent), -1.  A file with a DOS name beside its long one
   has two $FILE_NAMEs and two entries in that directory: both are removed (nw_index's `remove` takes
   every entry of the record), both get the new sizes (`patch`), and a rename leaves it the one new name */
static int nw_file_ok(const struct volume *v, const u8 *rec, u32 number, int removing, u32 *parent)
{
    u32 names = 0, spaces = 0, up = 0, si = 0;
    if (number < NW_META)
        return nw_err("one of the volume's own files: not changed");
    if ((le16(rec + 0x16) & ~3u) || le64(rec + 0x20))
        return nw_err("not a plain file's or directory's record: not changed");
    for (u32 at = 0; (at = attr_next(v, rec, at));) {
        u32 type = le32(rec + at);
        const u8 *val = rec + at + le16(rec + at + 0x14);
        if (type == 0x20)
            return nw_err("its record has an attribute list (many pieces or names): the demo reads it, and does "
                          "not change it");
        if (le16(rec + at + 0x0C) & 0xC0FF)
            return nw_err("compressed, encrypted or sparse: the demo reads it, and does not change it");
        if (type == 0xC0)
            return nw_err("a reparse point (a link, a junction): not changed");
        if (type == 0x40 && removing)
            return nw_err("it has an object ID (Windows tracks it for a shortcut): the demo does not remove it");
        if (type == 0x10) {
            if (rec[at + 8] || le32(rec + at + 0x10) < 0x30)
                return nw_err("NTFS: a damaged file record");
            if (le32(val + 0x20) & 0x4E00u)
                return nw_err("compressed, encrypted, sparse or a reparse point: not changed");
            si = at;
        }
        if (type == 0x30) {
            if (rec[at + 8] || le32(rec + at + 0x10) < 0x44 || le16(val + 4)
                || le32(rec + at + 0x10) != 0x42 + 2u * val[0x40])
                return nw_err("NTFS: a damaged file record");
            if (names && le32(val) != up)
                return nw_err("it has names in several directories (hard links): not changed");
            up = le32(val);
            names++;
            spaces |= 1u << (val[0x41] & 3);
            if (up == MFT_ROOT && le16(val + 0x42) == '$')
                return nw_err("one of the volume's own files (a '$' name in the root): not changed");
        }
    }
    if (!si || !names)
        return nw_err("NTFS: a damaged file record");
    /* one name, or a long one with its 8.3 name beside it (Windows with short names on): the link count
       counts every $FILE_NAME, the DOS one too.  Anything else is a hard link */
    if (names > 2 || (names == 2 && spaces != 0x06) || le16(rec + 0x12) != names)
        return nw_err("it has several names (hard links): the demo does not change it");
    *parent = up;
    return 0;
}

/* the record (in d) of a directory whose index is to be changed: one the demo changes?  0, -1 */
static int nw_dir_ok(const struct volume *v, const u8 *d, u32 dir)
{
    u32 ir = 0, ia = 0, bm = 0;
    if (dir != MFT_ROOT && dir < NW_META)
        return nw_err("one of the volume's own directories: not changed");
    if ((le16(d + 0x16) & ~1u) != 2 || le64(d + 0x20))
        return nw_err("NTFS: not a directory's record");
    for (u32 at = 0; (at = attr_next(v, d, at));) {
        u32 type = le32(d + at);
        int i30 = named(d + at, d[at + 9], le16(d + at + 10), le32(d + at + 4), "$I30");
        if (type == 0x20)
            return nw_err("the directory's record has an attribute list (a very big directory): the demo reads "
                          "it, and does not change it");
        if (type == 0xC0)
            return nw_err("the directory is a reparse point (a junction): not changed");
        if (type == 0x10 && (d[at + 8] || le32(d + at + 0x10) < 0x30
                             || (le32(d + at + le16(d + at + 0x14) + 0x20) & 0x4E00u)))
            return nw_err("the directory is compressed, encrypted or a reparse point: not changed");
        if (type == 0x90 && i30)
            ir = at;
        if (type == 0xA0 && i30)
            ia = at;
        if (type == 0xB0 && i30)
            bm = at;
    }
    if (!rec_find(v, d, 0x10, "") || !ir || d[ir + 8] || le32(d + ir + 0x10) < 0x30)
        return nw_err("NTFS: a directory without its index");
    const u8 *r = d + ir + le16(d + ir + 0x14);
    if (le32(r) != 0x30 || le32(r + 4) != 1 || le32(r + 8) != v->idx_size)
        return nw_err("NTFS: a directory index of a kind the demo does not know");
    if (!ia != !bm || (ia && (!d[ia + 8] || (le16(d + ia + 0x0C) & 0xC0FF))))
        return nw_err("NTFS: a damaged directory index");
    if (bm && d[bm + 8])
        return nw_err("the directory's index bitmap is not in its record (a very big directory): not changed");
    return 0;
}

/* -- a directory's index: read whole, changed, laid out again -- */

struct ncollect {
    struct disk *k;
    struct volume *v;
    u64 alloc;                          /* $INDEX_ALLOCATION's bytes */
    u32 n;                              /* entries so far */
};

static int nw_collect_node(struct ncollect *c, const u8 *p, const u8 *end, int depth, int inner);

/* the INDX block at `vcn` and the ones below it: their entries, in order */
static int nw_collect_block(struct ncollect *c, u64 vcn, int depth)
{
    struct volume *v = c->v;
    u64 off = vcn << v->vcn_shift;
    if (depth > DEPTH_MAX)
        return nw_err("the directory's index is too deep for the demo");
    u8 *b = nidx[depth - 1];
    if ((off & (NW_BLOCK - 1)) || off + NW_BLOCK > c->alloc || nw_old[off >> 12])
        return nw_err("NTFS: a damaged directory index (a block named twice, or one it does not have)");
    nw_old[off >> 12] = 1;
    if (nw_read(c->k, v, &dir_runs, off, NW_BLOCK / SECTOR, b) < 0)
        return -1;
    const u8 *h = b + 0x18;
    if (!same(b, "INDX", 4) || fixup(b, NW_BLOCK) < 0 || le64(b + 0x10) != vcn || le32(h) < 0x10 || (le32(h) & 7)
        || le32(h) >= le32(h + 4) || 0x18 + le32(h + 4) > NW_BLOCK)
        return nw_err("NTFS: a damaged index block");
    (void)now_ms();                     /* (the watchdog: a big directory) */
    return nw_collect_node(c, h + le32(h), h + le32(h + 4), depth, h[12] & 1);
}

/* a node's entries (from p to end; `inner`: each has a node below it), each after the node below it: into
   the blob, without that node's number */
static int nw_collect_node(struct ncollect *c, const u8 *p, const u8 *end, int depth, int inner)
{
    for (;;) {
        if (p + 0x10 > end)
            return nw_err("NTFS: a damaged directory index (a node without its end)");
        u32 len = le16(p + 8), klen = le16(p + 10), flags = le16(p + 12);
        if (len < 0x10 || (len & 7) || len > (u32)(end - p) || !(flags & 1) != !inner || (inner && len < 0x18))
            return nw_err("NTFS: a damaged index entry");
        if (inner && nw_collect_block(c, le64(p + len - 8), depth + 1) < 0)
            return -1;
        if (flags & 2)
            return 0;
        if (klen < 0x44 || 0x10 + klen > len - (inner ? 8 : 0) || klen != 0x42 + 2u * p[0x10 + 0x40])
            return nw_err("an index entry of a kind the demo does not know: the directory is not changed");
        u32 size = (0x10 + klen + 7) & ~7u;
        if (c->n >= NW_DIR_MAX || nw.blob_used + size > NTFS_INDEX_SIZE)
            return nw_err("the directory has more entries than the demo changes (4096)");
        u8 *e = nw_blob + nw.blob_used;
        wipe(e, size);
        copy(e, p, 0x10 + klen);
        put16(e + 8, (u16)size);
        put16(e + 12, 0);
        nw_off[c->n++] = nw.blob_used;
        nw.blob_used += size;
        p += len;
    }
}

/* the index of the directory whose record is in nw_dir (checked: nw_dir_ok), read: its entries, in order,
   into the blob (nw_off: where each is), its blocks' runs into dir_runs, the blocks it uses marked in nw_old
   -- and looked over: the blocks' bitmap says the same, the entries are in the order the demo would put them
   in.  How many entries (*n) and blocks its allocation holds (*total): 0, -1 */
static int nw_collect(struct disk *k, struct volume *v, u32 *n, u32 *total)
{
    const u8 *d = nw_dir;
    u32 ir = rec_find(v, d, 0x90, "$I30"), ia = rec_find(v, d, 0xA0, "$I30"), bm = rec_find(v, d, 0xB0, "$I30");
    const u8 *r = d + ir + le16(d + ir + 0x14);
    u32 vlen = le32(d + ir + 0x10), first = le32(r + 0x10), used = le32(r + 0x14);
    static struct ncollect c;
    c.k = k;
    c.v = v;
    c.alloc = 0;
    c.n = 0;
    nw.blob_used = 0;
    dir_runs.n = 0;
    *total = 0;
    if (ia) {
        if (nw_attr_runs(v, d, ia, &dir_runs) < 0)
            return -1;
        c.alloc = le64(d + ia + 0x30);
        if ((c.alloc & (NW_BLOCK - 1)) || c.alloc > (u64)NW_TBLOCKS * NW_BLOCK || le64(d + ia + 0x38) != c.alloc
            || c.alloc > (u64)runs_clusters(&dir_runs) << (9 + v->csh))
            return nw_err("the directory's index is bigger than the demo changes (or its sizes are odd)");
        *total = (u32)(c.alloc >> 12);
    }
    wipe(nw_old, NW_TBLOCKS);
    if (first < 0x10 || (first & 7) || first >= used || 0x10 + used > vlen || ((r[0x1C] & 1) && !ia))
        return nw_err("NTFS: a damaged directory index");
    if (nw_collect_node(&c, r + 0x10 + first, r + 0x10 + used, 0, r[0x1C] & 1) < 0)
        return -1;
    if (bm) {                           /* the blocks in use: the bitmap's word against the tree's */
        const u8 *bits = d + bm + le16(d + bm + 0x14);
        u32 blen = le32(d + bm + 0x10);
        for (u32 b = 0; b < blen * 8 || b < *total; b++) {
            int set = b < blen * 8 && (bits[b >> 3] & (1u << (b & 7)));
            if (set != (b < *total && nw_old[b]))
                return nw_chk(v, "the directory's index bitmap does not match its blocks: run chkdsk /f in "
                                 "Windows");
        }
    }
    for (u32 i = 1; i < c.n; i++)
        if (nw_collate(nw_blob + nw_off[i - 1] + 0x10, nw_blob + nw_off[i] + 0x10) >= 0)
            return nw_err("the directory's entries are not in the order the demo knows: it is not changed");
    *n = c.n;
    return 0;
}

static u32 nw_item_size(u32 level, u32 i)
{
    return level ? le16(nw_blob + nw_off[nw_item[i].ent] + 8) + 8u : le16(nw_blob + nw_off[i] + 8);
}

/* the bytes an INDX block has for its entries */
static u32 nw_block_room(void)
{
    return NW_BLOCK - ((0x28 + 2 * (NW_BLOCK / SECTOR + 1) + 7) & ~7u);
}

/* the n entries laid out as a B-tree whose root has `root_room` bytes for entries: the leaves filled one
   after the other, the entry between two of them going up to their parent (with the left one's number), and
   so on level by level until what is left fits the root -- every block with an entry at least, all leaves
   at one depth.  The blocks into nw_plan, the root into *p: how many blocks, -1 */
static int nw_plan_index(u32 n, u32 root_room, struct iplan *p)
{
    u32 nb = 0, items = 0, first = 0, count = n, end_child = NO_BLOCK, level = 0;
    for (;;) {
        u32 sum = level ? 0x18 : 0x10;
        for (u32 i = 0; i < count && sum <= root_room; i++)
            sum += nw_item_size(level, first + i);
        if (sum <= root_room) {
            p->level = level;
            p->first = first;
            p->n = count;
            p->end_child = end_child;
            return (int)nb;
        }
        if (level >= DEPTH_MAX)
            return nw_err("the directory's index would be too deep for the demo");
        u32 cap = nw_block_room() - (level ? 0x18 : 0x10), from = 0, bytes = 0, next_first = items, next_n = 0;
        for (u32 i = 0; i < count;) {
            u32 size = nw_item_size(level, first + i);
            if (bytes + size <= cap) {
                bytes += size;
                i++;
                continue;
            }
            if (i == count - 1)
                i--;                    /* (the last one starts the last block: the one before it goes up) */
            if (i <= from || nb >= NW_BLOCKS - 1 || items >= NW_BLOCKS)
                return nw_err("the directory's index would be bigger than the demo writes");
            nw_plan[nb].first = first + from;
            nw_plan[nb].n = i - from;
            nw_plan[nb].end_child = level ? nw_item[first + i].child : NO_BLOCK;
            nw_plan[nb].level = level;
            nw_item[items].ent = level ? nw_item[first + i].ent : first + i;
            nw_item[items].child = nb++;
            items++;
            next_n++;
            from = ++i;
            bytes = 0;
        }
        if (nb >= NW_BLOCKS)
            return nw_err("the directory's index would be bigger than the demo writes");
        nw_plan[nb].first = first + from;
        nw_plan[nb].n = count - from;
        nw_plan[nb].end_child = end_child;
        nw_plan[nb].level = level;
        end_child = nb++;
        first = next_first;
        count = next_n;
        level++;
    }
}

/* a block's number as index entries name it (a VCN) */
static u64 nw_vcn(const struct volume *v, u32 block)
{
    return ((u64)block << 12) >> v->vcn_shift;
}

/* a node's entries -- items first .. first + n - 1 of a level, then its end entry -- at o + at, in a buffer
   of `limit` bytes: where they end; 0 when they do not fit (the layout and this disagree: nothing is put
   past the buffer, the caller writes nothing) */
static u32 nw_node_put(const struct volume *v, u8 *o, u32 at, u32 limit, u32 level, u32 first, u32 n,
                       u32 end_child)
{
    u32 end = level ? 0x18 : 0x10;      /* (the end entry: with the node below it above the leaves, without in a
                                           leaf -- and a leaf may be full to its block's last byte) */
    for (u32 i = 0; i < n; i++) {
        const u8 *e = nw_blob + nw_off[level ? nw_item[first + i].ent : first + i];
        u32 len = le16(e + 8);
        if (at + len + (level ? 8 : 0) + end > limit)
            return 0;
        copy(o + at, e, len);
        if (level) {
            put16(o + at + 8, (u16)(len + 8));
            put16(o + at + 12, 1);
            put64(o + at + len, nw_vcn(v, nw_no[nw_item[first + i].child]));
            len += 8;
        }
        at += len;
    }
    if (at + end > limit)
        return 0;
    wipe(o + at, end);
    put16(o + at + 8, (u16)end);
    put16(o + at + 12, level ? 3 : 2);
    if (level)
        put64(o + at + 0x10, nw_vcn(v, nw_no[end_child]));
    return at + end;
}

#define NW_DO      0                    /* nw_index: the change made */
#define NW_DRY     1                    /*   only tried -- may it be made? --, nothing written */
#define NW_PREPARE 2                    /*   all but the last write: the new index is laid out and its blocks
                                             written beside the old ones, the directory's record -- the one
                                             write that puts it in the old one's place -- is kept for
                                             nw_index_commit (or let go: nw_index_drop) */

/* the clusters a directory's index let go (it fits its record again), freed only when the whole change is
   written -- the file's record last: a give-back that fails (a write) in between would leave the change
   half made, and the volume read-only before its last write.  Two at most (a move: both directories) */
static struct nrun nw_later_run[2][DIR_RUNS];
static u32 nw_later_n[2], nw_later_count;

static void nw_later_add(struct disk *k, struct volume *v, const struct runs *r)
{
    if (nw_later_count >= 2) {          /* (not so: freed now) */
        struct runs now = {(struct nrun *)r->r, r->n, r->max};
        nw_leaked(v, runs_trim(k, v, &now, 0));
        return;
    }
    for (u32 i = 0; i < r->n; i++)
        nw_later_run[nw_later_count][i] = r->r[i];
    nw_later_n[nw_later_count++] = r->n;
}

/* the change is written: what its indexes let go, freed (a failure: said, a leak) */
static void nw_later_free(struct disk *k, struct volume *v)
{
    for (u32 i = 0; i < nw_later_count; i++) {
        struct runs r = {nw_later_run[i], nw_later_n[i], DIR_RUNS};
        nw_leaked(v, runs_trim(k, v, &r, 0));
    }
    nw_later_count = 0;
}

/* the change failed after an index was written: what that index let go stays marked in use (said) */
static void nw_later_drop(void)
{
    if (nw_later_count)
        uprintf("%s: the clusters a directory's old index had stay marked in use (chkdsk /f in Windows frees "
                "them)\n", nw_verb);
    nw_later_count = 0;
}

/* an index prepared (NW_PREPARE): the directory's record as it will be (nw_pdir), its blocks' runs.  Kept
   apart from every work buffer: the caller changes another directory, or writes a file's record, before
   it commits this one */
static struct {
    u32 dir;                            /* the directory's record (0: nothing is prepared) */
    u32 old_clusters;                   /* the clusters its blocks had before */
    u32 n;                              /* its blocks' runs now (nw_pend_run) */
    u8 shrunk;                          /* the new index is all in the record: the blocks' clusters go */
} nw_pend;
static struct nrun nw_pend_run[DIR_RUNS];
static u8 nw_pdir[REC_MAX];

/* a change to directory `dir`'s index (`mode`: NW_DO, NW_DRY, NW_PREPARE): 0, -1 -- nothing is changed then */
static int nw_index(struct disk *k, struct volume *v, u32 dir, const struct idx_op *op, int mode)
{
    u8 *d = nw_dir;
    u32 n, total, cshift = 9 + v->csh;
    struct iplan p;
    if (nw_mft_get(k, v, dir, d) < 0 || nw_dir_ok(v, d, dir) < 0 || nw_collect(k, v, &n, &total) < 0)
        return -1;
    /* the change, in the list */
    if (op->remove) {
        u32 j = 0;
        for (u32 i = 0; i < n; i++) {
            const u8 *e = nw_blob + nw_off[i];
            if (le32(e) != op->remove || le16(e + 4))
                nw_off[j++] = nw_off[i];
        }
        if (j == n)
            return nw_chk(v, "the directory has no entry for that file's record (a stale entry?): run chkdsk /f in "
                             "Windows");
        n = j;
    }
    if (op->patch)
        for (u32 i = 0; i < n; i++) {
            u8 *e = nw_blob + nw_off[i];
            if (le32(e) == op->patch && !le16(e + 4))
                copy(e + 0x10 + 8, op->dup, 0x34);
        }
    if (op->add) {
        u32 lo = 0, hi = n, size = le16(op->add + 8);
        while (lo < hi) {
            u32 mid = (lo + hi) / 2;
            int c = nw_collate(op->add + 0x10, nw_blob + nw_off[mid] + 0x10);
            if (!c)
                return nw_err("the name is taken in that directory (by a file's other, short name)");
            if (c < 0)
                hi = mid;
            else
                lo = mid + 1;
        }
        /* a name that differs from one there in its characters' case only is that name to Windows -- a
           file's DOS name among them, which the look-up before this does not show.  In the index's order
           such names are neighbours: the entry before the new one's place, the one after */
        if ((lo && nw_same_name(op->add + 0x10, nw_blob + nw_off[lo - 1] + 0x10))
            || (lo < n && nw_same_name(op->add + 0x10, nw_blob + nw_off[lo] + 0x10)))
            return nw_err("the name is taken in that directory (in another case: a file's other, short name, or "
                          "one made where case counts)");
        if (n >= NW_DIR_MAX || nw.blob_used + size > NTFS_INDEX_SIZE)
            return nw_err("the directory would have more entries than the demo writes (4096)");
        copy(nw_blob + nw.blob_used, op->add, size);
        for (u32 i = n; i > lo; i--)
            nw_off[i] = nw_off[i - 1];
        nw_off[lo] = nw.blob_used;
        nw.blob_used += size;
        n++;
    }
    if (mode == NW_DRY)
        return 0;
    /* the record without its index: what room is there for the new one? */
    u32 ir = rec_find(v, d, 0x90, "$I30"), ia, bm, had_ia = 0, old_clusters = runs_clusters(&dir_runs), nb = 0;
    u16 ir_id = le16(d + ir + 0x0E), ia_id = 0xFFFF, bm_id = 0xFFFF, usn = le16(d + 0x30);
    u8 head[16];
    copy(head, d + ir + le16(d + ir + 0x14), 16);
    rec_remove(d, ir);
    if ((ia = rec_find(v, d, 0xA0, "$I30"))) {
        ia_id = le16(d + ia + 0x0E);
        rec_remove(d, ia);
        had_ia = 1;
    }
    if ((bm = rec_find(v, d, 0xB0, "$I30"))) {
        bm_id = le16(d + bm + 0x0E);
        rec_remove(d, bm);
    }
    u32 room = v->rec_size - le32(d + 0x18), sum = 0x10, bm_bytes = 0;
    for (u32 i = 0; i < n; i++)
        sum += le16(nw_blob + nw_off[i] + 8);
    if (room >= 0x40 + sum) {           /* a small index: all of it in the record */
        p.level = 0;
        p.first = 0;
        p.n = n;
        p.end_child = NO_BLOCK;
    } else {                            /* a B-tree of INDX blocks, in blocks the old one does not use */
        u32 used_old = 0, most, want, b = 0;
        int r = nw_plan_index(n, 0x18, &p);     /* (with nothing but the end in the root: the most blocks) */
        if (r < 0)
            return -1;
        most = (u32)r;
        for (u32 i = 0; i < total; i++)
            used_old += nw_old[i];
        want = total - used_old >= most ? total : used_old + most;
        if (want > NW_TBLOCKS)
            return nw_err("the directory's index would be bigger than the demo writes");
        want = (u32)((((u64)want << 12) + (1u << cshift) - 1) >> cshift);       /* (as clusters) */
        while (runs_clusters(&dir_runs) < want) {
            u32 lcn, got, have = runs_clusters(&dir_runs);
            struct nrun *last = dir_runs.n ? &dir_runs.r[dir_runs.n - 1] : 0;
            if (nw_alloc(k, v, want - have, last ? last->lcn + last->len : 0, 0, &lcn, &got) < 0) {
                if (nw_why == nw_full)  /* (the new index is written beside the old one: that takes room,
                                           for an entry removed as for one added) */
                    nw_err("the NTFS volume is full: no room to rewrite the directory's index (every change of "
                           "a directory writes its index anew, beside the old one)");
                goto undo;
            }
            if (runs_append(&dir_runs, lcn, got) < 0) {
                nw_back(v, nw_free(k, v, lcn, got));
                nw_err("the directory's index is in too many pieces for the demo");
                goto undo;
            }
        }
        total = (u32)(((u64)runs_clusters(&dir_runs) << cshift) >> 12);
        if (total > NW_TBLOCKS)
            total = NW_TBLOCKS;
        bm_bytes = ((total + 63) >> 6) << 3;
        u32 ia_len = 0x48 + ((mp_encode(dir_runs.r, dir_runs.n, 0, 0) + 7) & ~7u), bm_len = 0x20 + bm_bytes;
        if (room < 0x40 + 0x18 + ia_len + bm_len) {
            nw_err("no room in the directory's record for a bigger index (the demo makes no attribute lists)");
            goto undo;
        }
        r = nw_plan_index(n, room - 0x40 - ia_len - bm_len, &p);
        if (r < 0)
            goto undo;
        nb = (u32)r;
        for (u32 i = 0; i < nb; i++) {  /* each new block: the next one free in the old index */
            while (b < total && nw_old[b])
                b++;
            if (b >= total) {
                nw_err("NTFS: the index's blocks do not add up (nothing written)");
                goto undo;
            }
            nw_no[i] = b++;
        }
        for (u32 i = 0; i < nb; i++) {  /* the blocks written: nothing names them yet */
            u8 *o = nw_blk;
            u32 count = NW_BLOCK / SECTOR + 1, eo = NW_BLOCK - nw_block_room() - 0x18;
            wipe(o, NW_BLOCK);
            copy(o, (const u8 *)"INDX", 4);
            put16(o + 4, 0x28);
            put16(o + 6, (u16)count);
            put64(o + 0x10, nw_vcn(v, nw_no[i]));
            put16(o + 0x28, usn);
            put32(o + 0x18, eo);
            u32 filled = nw_node_put(v, o, 0x18 + eo, NW_BLOCK, nw_plan[i].level, nw_plan[i].first, nw_plan[i].n,
                                     nw_plan[i].end_child);
            if (!filled) {
                nw_err("NTFS: the new index does not fit its blocks as laid out (nothing changed)");
                goto undo;
            }
            put32(o + 0x1C, filled - 0x18);
            put32(o + 0x20, NW_BLOCK - 0x18);
            o[0x24] = nw_plan[i].level ? 1 : 0;
            fixup_put(o, NW_BLOCK);
            if (runs_write(k, v, dir_runs.r, dir_runs.n, (u64)nw_no[i] << 12, NW_BLOCK / SECTOR, o) < 0)
                goto undo;
            (void)now_ms();
        }
    }
    /* the record: the root, and for a tree the blocks' runs and their bitmap -- with it the new index is
       there, whole */
    {
        u8 *o = nw_blk;
        u32 end;
        wipe(o, 0x20);
        copy(o, head, 16);
        end = nw_node_put(v, o, 0x20, NW_BLOCK, p.level, p.first, p.n, p.end_child);
        if (!end)
            goto no_room;
        put32(o + 0x10, 0x10);
        put32(o + 0x14, end - 0x10);
        put32(o + 0x18, end - 0x10);
        o[0x1C] = p.level ? 1 : 0;
        if (!rec_put_resident(v, d, 0, 0x90, "$I30", o, end, 0, ir_id))
            goto no_room;
        if (p.level) {
            if (!rec_put_runs(v, d, 0, 0xA0, "$I30", dir_runs.r, dir_runs.n, (u64)total << 12, ia_id))
                goto no_room;
            wipe(o, bm_bytes);
            for (u32 i = 0; i < nb; i++)
                o[nw_no[i] >> 3] |= (u8)(1u << (nw_no[i] & 7));
            if (!rec_put_resident(v, d, 0, 0xB0, "$I30", o, bm_bytes, 0, bm_id))
                goto no_room;
        }
    }
    if (mode == NW_PREPARE) {           /* the record is kept: the caller's other writes come first */
        nw_pend.dir = dir;
        nw_pend.old_clusters = old_clusters;
        nw_pend.shrunk = !p.level && had_ia;
        nw_pend.n = dir_runs.n;
        for (u32 i = 0; i < dir_runs.n; i++)
            nw_pend_run[i] = dir_runs.r[i];
        copy(nw_pdir, d, v->rec_size);
        return 0;
    }
    if (nw_mft_put(k, v, dir, d) < 0)
        goto undo;
    if (!p.level && had_ia)             /* a small index again: its blocks' clusters are free -- when the whole
                                           change is written (nw_later_free) */
        nw_later_add(k, v, &dir_runs);
    return 0;
no_room:
    nw_err("NTFS: the directory's new index does not fit its record after all (nothing changed)");
undo:                                   /* (the record is as it was: the clusters taken here given back) */
    {
        const char *why = nw_why;
        nw_back(v, runs_trim(k, v, &dir_runs, old_clusters));
        nw_why = why;
    }
    return -1;
}

/* the index prepared for directory nw_pend.dir put in the old one's place: its record written.  0; -1 a
   write failed (the volume is read-only from then on: what was taken for the new index stays taken) */
static int nw_index_commit(struct disk *k, struct volume *v)
{
    struct runs runs = {nw_pend_run, nw_pend.n, DIR_RUNS};
    u32 dir = nw_pend.dir;
    nw_pend.dir = 0;
    if (!dir)
        return nw_err("NTFS: no index was prepared (nothing written)");
    if (nw_mft_put(k, v, dir, nw_pdir) < 0)
        return -1;
    if (nw_pend.shrunk)
        nw_later_add(k, v, &runs);
    return 0;
}

/* the index prepared is not wanted after all (what came before its commit failed): the clusters taken
   for it given back, the directory is as it was */
static void nw_index_drop(struct disk *k, struct volume *v)
{
    struct runs runs = {nw_pend_run, nw_pend.n, DIR_RUNS};
    const char *why = nw_why;
    if (nw_pend.dir)
        nw_back(v, runs_trim(k, v, &runs, nw_pend.old_clusters));
    nw_pend.dir = 0;
    nw_why = why;
}

/* -- files and directories: made, removed, renamed -- */

/* ntfs-3g's security descriptor for a new file where its directory has no security_id to hand on
   (ntfs_sd_add_everyone: the Administrators own it, everyone has every right) */
static const u8 nw_everyone[80] = {
    0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x34, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00,
    0x20, 0x02, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00,
    0x20, 0x02, 0x00, 0x00, 0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x14, 0x00,
    0xff, 0x01, 0x1f, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};

/* the bytes of a new file's record before its $DATA (or a directory's $INDEX_ROOT): the header, its
   $STANDARD_INFORMATION, its $FILE_NAME of `namelen` characters, its security descriptor when it has no
   security_id (`sec` 0), and the end mark */
static u32 nw_fixed(const struct volume *v, u32 namelen, u32 sec)
{
    u32 first = (0x30 + 2 * (v->rec_size / SECTOR + 1) + 7) & ~7u;
    return first + (sec ? 0x60 : 0x48 + 0x68) + ((0x18 + 0x42 + 2 * namelen + 7) & ~7u) + 8;
}

/* the directory `dir` a new name goes into (its record into nw_dir): one the demo changes; its sequence
   number, and the security_id its files get (0: it has none).  0, -1 */
static int nw_parent(struct disk *k, struct volume *v, u32 dir, const char *name, u16 *seq, u32 *sec)
{
    const u8 *d = nw_dir;
    if (nw_mft_get(k, v, dir, nw_dir) < 0 || nw_dir_ok(v, d, dir) < 0)
        return -1;
    if (dir == MFT_ROOT && name[0] == '$')
        return nw_err("a name that starts with '$' in the root is the volume's own: not made");
    u32 si = rec_find(v, d, 0x10, "");
    *seq = le16(d + 0x10);
    *sec = le32(d + si + 0x10) >= 0x48 ? le32(d + si + le16(d + si + 0x14) + 0x34) : 0;
    return 0;
}

/* a new file -- its bytes in its record (data, len) or in clusters (runs: `size` bytes) -- or a new, empty
   directory named `name` in directory `dir`: a record taken, written, then its entry put into the
   directory's index -- when that fails (the name is another file's short name, the directory is not one
   the demo changes) the record is let go again.  0, -1 */
static int nw_new(struct disk *k, struct volume *v, u32 dir, const char *name, int is_dir, const u8 *data, u32 len,
                  const struct nrun *runs, u32 nruns, u64 size)
{
    u8 *r = nw_rec, dup[0x38], si[0x48];
    u32 rec, sec, klen, count = v->rec_size / SECTOR + 1, first = (0x30 + 2 * count + 7) & ~7u;
    u16 seq, usn, dir_seq;
    u64 now = nw_now(), alloc = runs ? (u64)(nruns ? runs[nruns - 1].vcn + runs[nruns - 1].len : 0) << (9 + v->csh)
                                     : (len + 7) & ~7u;
    struct idx_op op = {0, nw_ent, 0, 0};
    nw_later_count = 0;
    if (nw_parent(k, v, dir, name, &dir_seq, &sec) < 0)
        return -1;
    for (int i = 0; i < 4; i++)
        put64(dup + 8 * i, now);
    put64(dup + 0x20, is_dir ? 0 : alloc);
    put64(dup + 0x28, is_dir ? 0 : runs ? size : len);
    put32(dup + 0x30, is_dir ? 0x10000000u : 0x20);
    put32(dup + 0x34, 0);
    klen = nw_name_value(nw_key, dir, dir_seq, dup, name);
    if (nw_rec_alloc(k, v, &rec, &seq, &usn) < 0)
        return -1;
    /* its record */
    wipe(r, v->rec_size);
    copy(r, (const u8 *)"FILE", 4);
    put16(r + 4, 0x30);
    put16(r + 6, (u16)count);
    put16(r + 0x10, seq);
    put16(r + 0x12, 1);
    put16(r + 0x14, (u16)first);
    put16(r + 0x16, is_dir ? 3 : 1);
    put32(r + 0x18, first + 8);
    put32(r + 0x1C, v->rec_size);
    put32(r + 0x2C, rec);
    put16(r + 0x30, usn);
    put32(r + first, 0xFFFFFFFFu);
    wipe(si, sizeof(si));
    copy(si, dup, 0x20);
    put32(si + 0x20, is_dir ? 0 : 0x20);
    put32(si + 0x34, sec);
    int ok = rec_put_resident(v, r, 0, 0x10, "", si, sec ? 0x48 : 0x30, 0, 0xFFFF)
             && rec_put_resident(v, r, 0, 0x30, "", nw_key, klen, 1, 0xFFFF)
             && (sec || rec_put_resident(v, r, 0, 0x50, "", nw_everyone, sizeof(nw_everyone), 0, 0xFFFF));
    if (ok && is_dir) {
        u8 root[0x30];
        wipe(root, sizeof(root));
        put32(root, 0x30);                              /* an index of $FILE_NAMEs, */
        put32(root + 4, 1);                             /* in file name order, */
        put32(root + 8, v->idx_size);                   /* its blocks' size, as clusters (or sectors) */
        root[12] = (u8)(v->idx_size >> (v->idx_size >= (1u << (9 + v->csh)) ? 9 + v->csh : 9));
        put32(root + 0x10, 0x10);
        put32(root + 0x14, 0x20);
        put32(root + 0x18, 0x20);
        put16(root + 0x28, 0x10);                       /* (the end entry alone) */
        put16(root + 0x2C, 2);
        ok = rec_put_resident(v, r, 0, 0x90, "$I30", root, sizeof(root), 0, 0xFFFF) != 0;
    } else if (ok) {
        ok = runs ? rec_put_runs(v, r, 0, 0x80, "", runs, nruns, size, 0xFFFF) != 0
                  : rec_put_resident(v, r, 0, 0x80, "", data, len, 0, 0xFFFF) != 0;
    }
    if (!ok) {
        nw_back(v, bm_set(k, v, &nw.mbm, rec, 1, 0));
        return nw_err("the name and the file's pieces do not fit one file record (the demo makes no attribute "
                      "lists)");
    }
    if (nw_mft_put(k, v, rec, r) < 0) {
        const char *why = nw_why;
        nw_back(v, bm_set(k, v, &nw.mbm, rec, 1, 0));
        nw_why = why;
        return -1;
    }
    /* its name into the directory */
    nw_entry_make(nw_ent, rec, seq, nw_key, klen);
    if (nw_index(k, v, dir, &op, NW_DO) < 0) {
        const char *why = nw_why;
        put16(r + 0x16, (u16)(le16(r + 0x16) & ~1u));
        nw_back(v, nw_mft_put(k, v, rec, r) < 0 ? -1 : bm_set(k, v, &nw.mbm, rec, 1, 0));
        nw_why = why;
        return -1;
    }
    nw_later_free(k, v);
    return 0;
}

/* a file or (is_dir) an empty directory removed -- e: its entry as the directory showed it, checked against
   its record (the sequence number, the directory) --: its names out of its directory's index (with them
   it is gone), then its record marked not in use (its sequence number one up) and given back in $MFT's
   bitmap, then its clusters given back in $Bitmap.  0, -1 nothing changed */
static const char nw_stale[] = "the directory's entry is stale (its record is another file's now, or in another "
                              "directory): run chkdsk /f in Windows";

static int nw_remove(struct disk *k, struct volume *v, const struct entry *e, int is_dir)
{
    u8 *r = nw_rec;
    u32 rec = e->cluster, parent, n, total;
    struct idx_op op = {rec, 0, 0, 0};
    if (nw_mft_get(k, v, rec, r) < 0 || nw_file_ok(v, r, rec, 1, &parent) < 0)
        return -1;
    if (le16(r + 0x10) != e->slot_off[0] || parent != e->dir)
        return nw_chk(v, nw_stale);
    if (!(le16(r + 0x16) & 2) != !is_dir)
        return nw_err(is_dir ? "not a directory" : "a directory");
    if (nw_rec_free_runs(k, v, r, 0) < 0)               /* (its runs: sound, and its own to free?  Asked before
                                                           anything is changed) */
        return -1;
    if (is_dir) {                                       /* empty: not an entry of any kind in its index */
        copy(nw_dir, r, v->rec_size);
        if (nw_dir_ok(v, nw_dir, rec) < 0 || nw_collect(k, v, &n, &total) < 0)
            return -1;
        if (n)
            return nw_err("the directory is not empty (it has entries the demo does not list)");
    }
    nw_later_count = 0;
    if (nw_index(k, v, parent, &op, NW_DO) < 0)
        return -1;
    /* it is out of its directory: gone.  What follows gives back what it had; where that fails it stays
       marked in use (said) */
    put16(r + 0x16, (u16)(le16(r + 0x16) & ~1u));
    put16(r + 0x10, le16(r + 0x10) == 0xFFFF ? 1 : (u16)(le16(r + 0x10) + 1));
    int x = nw_mft_put(k, v, rec, r);
    if (x == 0)
        x = bm_set(k, v, &nw.mbm, rec, 1, 0);
    if (x == 0 && rec >= NW_FIRST_REC && rec < nw.rec_hint)
        nw.rec_hint = rec;
    if (x == 0)
        x = nw_rec_free_runs(k, v, r, 1);
    nw_leaked(v, x);
    if (x == 0)
        nw_later_free(k, v);
    else
        nw_later_drop();
    return 0;
}

/* a file or directory given the name `name` in directory `to` (0: the root), on the same volume: its
   record's $FILE_NAME (a DOS name it had beside it is dropped: the new name is its only one, its link count
   1) and the directories' entries.  From one directory to another: the new directory's index with the
   entry in it is prepared first -- laid out, its blocks written beside the old ones: whatever can fail for
   want of room fails here, with nothing changed --, then the entry is taken OUT of the old directory, then
   the new directory's record is written (the entry is IN), then the file's own record.  Cut off between
   the two, or a write failing there: the file is in no directory (its record is in use, with its bytes:
   chkdsk puts it back) -- never in two.  0, -1 */
static int nw_move(struct disk *k, struct volume *v, const struct entry *e, u32 to, const char *name)
{
    u8 *r = nw_rec, dup[0x38];
    u32 rec = e->cluster, from, sec, klen, fn, names = 0;
    u16 to_seq;
    if (!to)
        to = MFT_ROOT;
    if (nw_parent(k, v, to, name, &to_seq, &sec) < 0 || nw_mft_get(k, v, rec, r) < 0
        || nw_file_ok(v, r, rec, 0, &from) < 0)
        return -1;
    if (le16(r + 0x10) != e->slot_off[0] || from != e->dir)
        return nw_chk(v, nw_stale);
    nw_dup(v, r, dup);
    for (u32 at = 0; (at = attr_next(v, r, at));)
        names += le32(r + at) == 0x30;
    for (u32 at = 0; names == 2 && (at = attr_next(v, r, at));)     /* (two names: the DOS one goes) */
        if (le32(r + at) == 0x30 && r[at + le16(r + at + 0x14) + 0x41] == 2) {
            rec_remove(r, at);
            break;
        }
    put16(r + 0x12, 1);                                 /* (one name from here on: one link) */
    fn = rec_find(v, r, 0x30, "");
    klen = nw_name_value(nw_key, to, to_seq, dup, name);
    if (!fn || !rec_put_resident(v, r, fn, 0x30, "", nw_key, klen, 1, 0))
        return nw_err("no room in its record for the longer name (the demo makes no attribute lists)");
    nw_entry_make(nw_ent, rec, le16(r + 0x10), nw_key, klen);
    nw_later_count = 0;
    if (from == to) {                                   /* renamed where it is: one change of the index */
        struct idx_op op = {rec, nw_ent, 0, 0};
        if (nw_index(k, v, to, &op, NW_DO) < 0)
            return -1;
        if (nw_mft_put(k, v, rec, r) < 0) {
            nw_later_drop();
            return nw_err("a write failed: the file has its new name in the directory, but its record was not "
                          "told so -- chkdsk /f in Windows puts that right; the volume is read-only from now on");
        }
        nw_later_free(k, v);
        return 0;
    }
    struct idx_op in = {0, nw_ent, 0, 0}, out = {rec, 0, 0, 0};
    if (nw_index(k, v, to, &in, NW_PREPARE) < 0)
        return -1;
    if (nw_index(k, v, from, &out, NW_DO) < 0) {        /* (it stays where it is) */
        int cut = v->nw_state == NW_REFUSED && v->nw_why == nw_failed;
        nw_index_drop(k, v);
        if (cut)                        /* (the failed write may have been the old directory's record: done) */
            return nw_err("a write failed while the file was taken out of its directory: it is still there -- "
                          "or, when 'ls' shows it in neither directory, in none (its record and bytes are kept: "
                          "chkdsk /f in Windows puts it back, in found.000); the volume is read-only from now on");
        return -1;
    }
    if (nw_index_commit(k, v) < 0) {
        nw_later_drop();
        return nw_err("a write failed after the file had left its directory: it is in no directory now (or "
                      "already in the new one) -- its record and bytes are kept: chkdsk /f in Windows puts it "
                      "back, in found.000; the volume is read-only from now on");
    }
    if (nw_mft_put(k, v, rec, r) < 0) {
        nw_later_drop();
        return nw_err("a write failed: the file is in its new directory, but its record was not told so -- "
                      "chkdsk /f in Windows puts that right; the volume is read-only from now on");
    }
    nw_later_free(k, v);
    return 0;
}

/* -- 'ntfs' -- */

/* a writing command: refused (1, said why) on a volume an FTP upload is writing, and on an NTFS volume that
   does not pass the gate */
static int upload_on(const struct disk *k, const struct volume *v);

static int read_only(struct disk *k, struct volume *v, const char *verb)
{
    nw_said = 0;
    if (upload_on(k, v)) {              /* (FAT and NTFS alike: the upload's writer has the file's clusters, its
                                           directory -- nothing else may change them under it) */
        uprintf("%s: busy: an FTP upload is writing this volume\n", verb);
        nw_said = 1;
        return 1;
    }
    if (v->fs != FS_NTFS)
        return 0;
    nw_verb = verb;
    if (nw_use(k, v) == 0)
        return 0;
    if (v->nw_state != NW_REFUSED) {
        (void)nw_fail();
        return 1;
    }
    if (v->number)
        uprintf("%s: read-only: device %u partition %u is NTFS and %s ('ntfs' tells more)\n", verb, k->device,
                v->number, v->nw_why);
    else
        uprintf("%s: read-only: device %u is NTFS and %s ('ntfs' tells more)\n", verb, k->device, v->nw_why);
    nw_said = 1;
    return 1;
}

/* a write failed: the USB side's word for it -- unless the NTFS writer said why itself */
static void write_failed(const char *verb)
{
    if (!nw_said)
        uprintf("%s: %s\n", verb, io_error());
    nw_said = 0;
}

static void ntfs_page_say(int i, const struct nw_page *p)
{
    uprintf("    restart page %u: ", i + 1);
    if (!p->kind) {
        uprintf("empty (all 0xFF)\n");
        return;
    }
    if (p->kind == 2) {
        uprintf("'%s': %s\n", p->magic, p->bad);
        return;
    }
    uprintf("RSTR, LFS %u.%u, pages of %u bytes, LSN 0x%08x%08x, clients: %u, free list 0x%04x, in use 0x%04x, "
            "flags 0x%04x (%s)\n", p->major, p->minor, p->sys_page, (u32)(p->lsn >> 32), (u32)p->lsn, p->clients,
            p->free_list, p->in_use, p->flags,
            p->in_use == 0xFFFF ? "no client in use: closed" : p->flags & 2 ? "the clean flag is set"
                                                                               : "in use, the clean flag is not set");
}

/* 'ntfs': one volume's geometry, $MFT, free space, flags, journal -- and whether the demo writes it */
static void ntfs_info(struct disk *k, struct volume *v)
{
    static struct nw_info g;
    char t[24];
    u32 cshift = 9 + v->csh, clear;
    uprintf("device %u", k->device);
    if (v->number)
        uprintf(" partition %u", v->number);
    if (v->fs != FS_NTFS || v->problem) {
        uprintf(": %s%s%s\n", fs_name(v), v->problem ? ": " : " (not NTFS)", v->problem ? v->problem : "");
        return;
    }
    nw_gate_read(k, v, &g);
    v->nw_state = g.why ? NW_REFUSED : NW_OK;
    v->nw_why = g.why;
    uprintf(": NTFS");
    if (g.version_read)
        uprintf(" %u.%u", g.major, g.minor);
    uprintf(" '%s', %u MB\n", v->label, mb(v->sectors));
    uprintf("  clusters: %u of %u bytes; MFT records of %u bytes, index blocks of %u\n", v->ntfs_clusters,
            1u << cshift, v->rec_size, v->idx_size);
    uprintf("  $MFT: at cluster %u, %s bytes in %u piece%s", v->mft_run[0].lcn,
            dec64(t, (u64)runs_clusters(&v->mft) << cshift), v->mft.n, v->mft.n == 1 ? "" : "s");
    if (g.loaded)
        uprintf(", %u records; $MFTMirr at cluster %u (%u records)", nw.mft_records, nw.mir.r[0].lcn,
                nw.mirror_count);
    uprintf("\n");
    if (g.version_read)
        uprintf("  volume flags: 0x%04x (%s)\n", g.vflags, g.vflags & 1 ? "DIRTY" : "not dirty");
    if (g.journal == J_UNREAD) {
        uprintf("  journal ($LogFile): not read\n");
    } else {
        uprintf("  journal ($LogFile, %u KB):\n", g.log_kb);
        ntfs_page_say(0, &g.page[0]);
        ntfs_page_say(1, &g.page[1]);
        uprintf("    -> %s\n",
                g.journal == J_EMPTY ? "empty (both restart pages 0xFF, and a sector at every power of two up to "
                                       "its end): as mkntfs, ntfs-3g and 'reset-journal' leave it"
                : g.journal == J_CLEAN ? (g.newer ? "clean (page 2 is the newer one)" : "clean (page 1 is the newer "
                                                                                        "one)")
                : g.journal == J_UNCLEAN ? "NOT clean: Windows did not close it (the disk was pulled out, or the "
                                           "volume is in use)"
                : g.journal == J_LFS2 ? "version 2.0: Windows left the volume mounted (fast start-up, hibernation)"
                : g.journal == J_PARTLY ? "emptied at its start only: a 'reset-journal' that was cut short"
                                        : "not valid restart pages");
    }
    if (!g.why)
        uprintf("  the demo writes this volume\n");
    else
        uprintf("  the demo does NOT write this volume: %s\n", g.why);
    if (g.journal == J_LFS2)            /* (that Windows still holds the volume's state: no reset-journal here) */
        uprintf("  what to do: shut that Windows down fully (not fast start-up, not hibernation: 'Restart', or "
                "shutdown /s /t 0), then 'Safely remove' the disk there\n");
    else if (g.journal == J_UNCLEAN || g.journal == J_BAD)
        uprintf("  what to do: in Windows, 'Safely remove' the disk (or run chkdsk /f on it);\n  without Windows: "
                "'ntfs %u%s%s: reset-journal' empties the journal as ntfs-3g does -- what Windows had not finished "
                "writing is lost\n", k->device, v->number ? "." : "", v->number ? dec64(t, v->number) : "");
    if (g.loaded) {                     /* the bitmaps counted, last: a big volume's take a while */
        if ((v->ntfs_clusters >> 3) > 256 * 1024)
            uprintf("  (counting its free space: %u KB of $Bitmap to read; Ctrl-C leaves it)\n",
                    v->ntfs_clusters >> 13);
        int r = bm_count(k, v, &nw.mbm, nw.mft_records, &clear);
        if (r == 0)
            uprintf("  file records: %u in use, %u free\n", nw.mft_records - clear, clear);
        if (r == 0)
            r = bm_count(k, v, &nw.bmp, v->ntfs_clusters, &clear);
        if (r == 0)
            uprintf("  free: %u clusters (%u MB)\n", clear, (u32)(((u64)clear << cshift) >> 20));
        else
            uprintf("  free space: %s\n", r == -2 ? "^C (not counted)" : "a bitmap did not read");
    }
}

/* 'ntfs n: reset-journal': $LogFile filled with 0xFF, as ntfs-3g's ntfs_logfile_reset does (asked for by
   name: never by itself) -- from its start, 4 KB a write (the most one SCSI WRITE of the demo takes): the
   two restart pages go first, so that from the first two writes on there is nothing Windows could replay.
   One cut short (Ctrl-C, a write that fails, the disk pulled) leaves the start empty and old log records
   further on: the gate calls that "emptied only in part" where it looks (nw_journal_read) and the volume
   stays read-only until the reset ran to its end.  Not for a journal of version 2.0: the Windows that left
   the volume mounted (fast start-up, hibernation) still holds its state and would write it back */
static void ntfs_reset_journal(struct disk *k, struct volume *v)
{
    static struct nw_info g;
    static struct nrun mir_run[8];
    struct runs log = {0, 0, 0}, mir = {mir_run, 0, 8};
    u64 size = 0, done = 0, t0 = now_ms();
    u32 said_at = 0;
    char which[40];                     /* "device 4 partition 2": a disk may have several NTFS volumes */
    int at = usnprintf(which, sizeof(which), "device %u", k->device);
    if (v->number)
        usnprintf(which + at, (int)sizeof(which) - at, " partition %u", v->number);
    if (v->fs != FS_NTFS || v->problem) {
        uprintf("reset-journal: %s is not an NTFS volume the demo reads\n", which);
        return;
    }
    if (upload_on(k, v)) {
        uprintf("reset-journal: busy: an FTP upload is writing %s\n", which);
        return;
    }
    nw_journal_read(k, v, &g, &log, &size);
    if (!size) {
        uprintf("reset-journal: %s: the journal ($LogFile) does not read\n", which);
        return;
    }
    if (g.journal == J_EMPTY) {
        uprintf("reset-journal: %s: the journal is empty already\n", which);
        return;
    }
    if (g.journal == J_LFS2) {
        uprintf("reset-journal: %s: not done -- its journal is version 2.0: a Windows left the volume mounted "
                "(fast start-up, hibernation) and still holds its state; shut that Windows down fully, then "
                "'Safely remove' the disk there\n", which);
        return;
    }
    /* the journal's clusters are its own: not the boot sector's, $MFT's or $MFTMirr's (a damaged volume) */
    if (nw_mft_get(k, v, 1, nw_tmp) < 0 || nw_attr_runs(v, nw_tmp, rec_find(v, nw_tmp, 0x80, ""), &mir) < 0) {
        uprintf("reset-journal: %s: $MFTMirr does not read: nothing written\n", which);
        return;
    }
    for (u32 i = 0; i < log.n; i++)
        if (!log.r[i].lcn || nw_overlap(&v->mft, log.r[i].lcn, log.r[i].len)
            || nw_overlap(&mir, log.r[i].lcn, log.r[i].len)) {
            uprintf("reset-journal: %s: its $LogFile names clusters that are $MFT's, $MFTMirr's or the boot "
                    "sector's (a damaged volume): nothing written\n", which);
            return;
        }
    if (!writable(k))
        return;
    uprintf("%s: its journal ($LogFile, %u KB) is filled with 0xFF (Ctrl-C stops)%s\n", which, (u32)(size >> 10),
            g.journal == J_CLEAN ? "; it was clean" : ": what Windows had not finished writing is lost -- run "
                                                      "chkdsk when you can");
    for (u32 i = 0; i < NW_BLOCK; i++)
        nw_blk[i] = 0xFF;
    v->nw_state = NW_UNKNOWN;           /* (whatever the gate said of the volume: it looks again after this) */
    nw_resetting = v;
    while (done < size) {
        u32 n = size - done < NW_BLOCK ? (u32)((size - done + SECTOR - 1) / SECTOR) : NW_BLOCK / SECTOR;
        if (runs_write(k, v, log.r, log.n, done, n, nw_blk) < 0) {
            nw_resetting = 0;
            uprintf("reset-journal: %s: stopped after %u of %u KB: %s\n", which, (u32)(done >> 10),
                    (u32)(size >> 10), nw_why ? nw_why : "a write failed");
            return;
        }
        done += n * SECTOR;
        if (done < size && (u32)(done >> 10) - said_at >= (size >> 10 > 16384 ? 1024u : (u32)(size >> 10) / 10)) {
            u32 s = (u32)(now_ms() - t0) / 1000, kb = (u32)(done >> 10);    /* (a line a megabyte: 64 MB take long) */
            said_at = kb;
            uprintf("  %u of %u KB (%u%%), %u s", kb, (u32)(size >> 10), kb * 100 / (u32)(size >> 10), s);
            if (s)
                uprintf(", %u KB/s", kb / s);
            uprintf("\n");
        }
        if (uart_getc() == 3) {
            uprintf("^C (%u of %u KB emptied: the volume stays read-only until 'reset-journal' ran to its end)\n",
                    (u32)(done >> 10), (u32)(size >> 10));
            break;
        }
    }
    nw_resetting = 0;
    sync_disk(k);
    if (done >= size)
        uprintf("%s: the journal is empty; 'ntfs' shows the volume's state\n", which);
}

/* 'ntfs [n:]' (every NTFS volume, or disk n's; "n.p:" its partition p), 'ntfs n: reset-journal' */
void disk_ntfs(const char *arg, const char *what)
{
    u32 device = 0, part = 0, any = 0;
    const char *p = arg;
    while (*p >= '0' && *p <= '9')
        device = device * 10 + (u32)(*p++ - '0');
    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9')
            part = part * 10 + (u32)(*p++ - '0');
    }
    if (*p == ':')
        p++;
    int reset = same((const u8 *)what, "reset-journal", 14);
    if (*p || (arg[0] && !device) || (what[0] && !reset) || (reset && !device)) {
        uprintf("usage: ntfs [n:]            an NTFS volume's state, and whether the demo writes it\n"
                "       ntfs n: reset-journal   empty its journal ($LogFile), as ntfs-3g does\n");
        return;
    }
    nw_verb = "ntfs";
    for (int i = 0; i < DISKS; i++) {
        struct disk *k = &disks[i];
        if (!k->used || (device && k->device != device))
            continue;
        if (!k->ready)
            probe(k);
        for (int j = 0; k->ready && j < k->volumes; j++) {
            struct volume *v = &k->vol[j];
            if (part ? v->number != part : v->fs != FS_NTFS)
                continue;
            any = 1;
            if (reset) {
                ntfs_reset_journal(k, v);
                return;
            }
            ntfs_info(k, v);
        }
    }
    if (!any)
        uprintf(device ? "device %u: no NTFS volume there ('disks' lists them)\n"
                       : "no NTFS volume on a USB disk ('disks' lists them)\n", device);
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
    if (!path || read_only(*pk, *pv, verb))
        return -1;
    int split = split_path(path, pdir, name);
    if (split < 0) {
        uprintf(split == -1 ? "%s: the path is too long (%u characters at most before the name)\n"
                            : "%s: the name is too long (%u characters at most)\n", verb,
                split == -1 ? PATH_MAX - 1 : NAME_MAX - 1);
        return -1;
    }
    if (!split) {
        uprintf((*pv)->fs == FS_NTFS ? "%s: not a name Windows takes (no \\ / : * ? \" < > |): '%s'\n"
                                     : "%s: not a name for a FAT volume: '%s'\n", verb, arg);
        return -1;
    }
    if (walk_path(*pk, *pv, dir, from, pdir, parent, place_path) < 0)
        return -1;
    if (!(parent->attr & 0x10)) {
        uprintf("not a directory: %s\n", parent->name);
        return -1;
    }
    int r = find_in(*pk, *pv, parent->cluster, seq_of(parent), name, path_len(name), &f);
    if (r < 0) {
        dir_failed();
        return -1;
    }
    if (r && found)
        *found = f.found;
    return r;                           /* (1: it is there already) */
}

/* mkdir's work: 0 made, -1 not (said why) */
static int make_dir_at(const char *arg)
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
        return -1;
    }
    if (!writable(k))
        return -1;
    if (v->fs == FS_NTFS) {
        if (nw_new(k, v, parent.cluster ? parent.cluster : MFT_ROOT, name, 1, 0, 0, 0, 0, 0) < 0)
            return nw_fail();
        sync_disk(k);
        return 0;
    }
    if (fsinfo_unknown(k, v) < 0)
        return -1;
    u32 c = fat_alloc(k, v);
    if (!c)
        return -1;
    for (int i = 0; i < SECTOR; i++)    /* its first sector: '.' and '..' */
        wbuf2[i] = 0;
    for (int dots = 1; dots <= 2; dots++) {
        u8 *d = wbuf2 + (dots - 1) * 32;
        for (int i = 0; i < 11; i++)
            d[i] = i < dots ? '.' : ' ';
        u32 to = dots == 1 ? c : parent.cluster;    /* ('..' of a directory in the root: 0) */
        d[11] = 0x10;
        u16 date, time;
        fat_stamp(&date, &time);
        put16(d + 14, time);
        put16(d + 16, date);
        put16(d + 18, date);
        put16(d + 20, (u16)(v->fat == 32 ? to >> 16 : 0));
        put16(d + 22, time);
        put16(d + 24, date);
        put16(d + 26, (u16)to);
    }
    int n;
    if (zero_cluster(k, v, c) < 0 || write_sectors(k, cluster_sector(v, c), 1, wbuf2) < 0
        || (n = make_entry(k, v, parent.cluster, name, 0x10, c, 0, ents)) < 0
        || dir_put(k, v, parent.cluster, ents, n, 0, 0) < 0) {
        uprintf("mkdir: not made (%s)\n", io_error());
        (void)fat_set(k, v, c, 0);
        return -1;
    }
    sync_disk(k);
    return 0;
}

void disk_mkdir(const char *arg)
{
    (void)make_dir_at(arg);
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
    if (!writable(k))
        return;
    if (v->fs == FS_NTFS) {
        if (nw_new(k, v, parent.cluster ? parent.cluster : MFT_ROOT, name, 0, 0, 0, 0, 0, 0) < 0)
            (void)nw_fail();
        else
            sync_disk(k);
        return;
    }
    if (fsinfo_unknown(k, v) < 0)
        return;
    int n = make_entry(k, v, parent.cluster, name, 0x20, 0, 0, ents);
    if (n < 0 || dir_put(k, v, parent.cluster, ents, n, 0, 0) < 0) {
        uprintf("touch: not made (%s)\n", io_error());
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

/* rm and rmdir (`verb`: an NTFS volume refused), cp's source (0): the entry at the path (not the root, '.'
   or '..') */
static int old_entry(const char *arg, const char *verb, struct disk **pk, struct volume **pv, struct entry *e)
{
    u32 dir;
    const char *from;
    const char *path = locate(arg, pk, pv, &dir, &from);
    if (!path || (verb && read_only(*pk, *pv, verb)) || walk_path(*pk, *pv, dir, from, path, e, 0) < 0)
        return -1;
    if (!e->slots || (e->name[0] == '.' && (!e->name[1] || (e->name[1] == '.' && !e->name[2])))) {
        uprintf("not that one: '%s'\n", arg);
        return -1;
    }
    return 0;
}

/* rmdir's work once its entry is found: 0 removed, -1 not (said why) */
static int remove_dir(struct disk *k, struct volume *v, struct entry *e)
{
    struct count c = {0};
    if (!(e->attr & 0x10) || !e->cluster) {
        uprintf("rmdir: not a directory: %s\n", e->name);
        return -1;
    }
    if (cwd.k == k && cwd.v == v && cwd.cluster == e->cluster) {
        uprintf("rmdir: the current directory ('cd ..' first)\n");
        return -1;
    }
    if (dir_walk(k, v, e->cluster, seq_of(e), count_fn, &c) < 0) {
        dir_failed();
        return -1;
    }
    if (c.n) {
        uprintf("rmdir: not empty: %s\n", e->name);
        return -1;
    }
    if (!writable(k))
        return -1;
    if (v->fs == FS_NTFS) {
        nw_verb = "rmdir";
        if (nw_use(k, v) < 0 || nw_remove(k, v, e, 1) < 0)
            return nw_fail();
        sync_disk(k);
        return 0;
    }
    if (fsinfo_unknown(k, v) < 0)
        return -1;
    if (delete_slots(k, e) < 0 || free_chain(k, v, e->cluster) < 0) {
        uprintf("rmdir: %s\n", io_error());
        return -1;
    }
    sync_disk(k);
    return 0;
}

void disk_rmdir(const char *arg)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    if (old_entry(arg, "rmdir", &k, &v, &e) == 0)
        (void)remove_dir(k, v, &e);
}

/* rm's work once its entry is found: 0 removed, -1 not (said why) */
static int remove_file(struct disk *k, struct volume *v, struct entry *e)
{
    if (e->attr & 0x10) {
        uprintf("rm: a directory ('rmdir' removes an empty one, 'rm -r' one and all in it): %s\n", e->name);
        return -1;
    }
    if (e->attr & 0x01) {
        uprintf("rm: read-only: %s\n", e->name);
        return -1;
    }
    if (!writable(k))
        return -1;
    if (v->fs == FS_NTFS) {
        nw_verb = "rm";
        if (nw_use(k, v) < 0 || nw_remove(k, v, e, 0) < 0)
            return nw_fail();
        sync_disk(k);
        return 0;
    }
    if (fsinfo_unknown(k, v) < 0)
        return -1;
    if (delete_slots(k, e) < 0 || (e->cluster && free_chain(k, v, e->cluster) < 0)) {
        uprintf("rm: %s\n", io_error());
        return -1;
    }
    sync_disk(k);
    return 0;
}

void disk_rm(const char *arg)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    if (old_entry(arg, "rm", &k, &v, &e) == 0)
        (void)remove_file(k, v, &e);
}

/* ---- a file's data: 'command > path' / '>>', cp, mv ---- */

/* a file being written: its clusters and size, where its 8.3 entry is; the
   sector being filled, and up to 8 full ones that follow each other on the
   disk, waiting to be written in one go */
#define WF_RUNS    256                  /* NTFS: the pieces a file being written may be in */
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
    /* a file on NTFS (nt not 0: see "a file's data on NTFS"): nothing of it is on the volume's books until
       it is closed */
    u8 nt;                              /* 1: its bytes are in q so far (they fit its record), 2: in clusters */
    u8 nt_tried;                        /* a new file: its name was tried against its directory's index */
    const char *nverb;                  /* the command writing it, for what it says */
    u32 nt_dir;                         /* its directory's record */
    u32 nt_rec;                         /* its own, when it is there already (0: a new file) */
    u16 nt_seq;                         /*   that record's sequence number when the file was opened */
    u32 nt_room;                        /* the bytes its record has for its $DATA attribute */
    u64 nsize;                          /* its bytes so far */
    u32 nalloc, nkeep;                  /* its clusters; of them the ones it had before (a file added to) */
    u32 nruns, nri;                     /* its runs (nrun); the one being written */
    struct nrun nrun[WF_RUNS];
    char nname[NAME_MAX];
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
    u16 date, time;
    fat_stamp(&date, &time);
    put16(d + 18, date);
    put16(d + 20, (u16)(v->fat == 32 ? cluster >> 16 : 0));
    put16(d + 22, time);
    put16(d + 24, date);
    put16(d + 26, (u16)cluster);
    put32(d + 28, size);
    return write_sectors(k, lba, 1, wbuf);
}

static int wf_flush(struct wfile *f)
{
    if (f->q_n && (f->nt ? nw_write(f->k, f->v, f->q_lba, f->q_n, f->q)
                         : write_sectors(f->k, f->q_lba, f->q_n, f->q)) < 0)
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

/* ---- a file's data on NTFS: the writer's other half ----
   The file's size is not known when it is opened: its first bytes are kept in the writer (q) while they would
   fit its record as a resident $DATA; when they no longer do, clusters are taken -- 1 MB at a time, on from
   the file's last one while those are free -- and the bytes go there, the runs kept in the writer.  Nothing
   of the file is on the volume's books until it is closed: then its record is written (a new one, or the
   one it has, with the new $DATA in the old one's place) and then its directory's entry -- a file appears
   when it is complete, and one written over is whole (the old bytes) until then; the old clusters are freed
   last.  Adding to a file ('>>', APPE) goes on in its last cluster. */

/* more clusters for the file: 0, -1 (nw_why) */
static int nw_more(struct wfile *f)
{
    struct volume *v = f->v;
    struct runs runs = {f->nrun, f->nruns, WF_RUNS};
    u32 cshift = 9 + v->csh, want = cshift >= 20 ? 1 : 1u << (20 - cshift), lcn, got;
    struct nrun *last = f->nruns ? &f->nrun[f->nruns - 1] : 0;
    if (nw_alloc(f->k, v, want, last ? last->lcn + last->len : 0, 0, &lcn, &got) < 0)
        return -1;
    if (runs_append(&runs, lcn, got) < 0
        || 0x40 + ((mp_encode(runs.r, runs.n, 0, 0) + 7) & ~7u) > f->nt_room) {
        nw_back(v, nw_free(f->k, v, lcn, got));
        return nw_err("the volume's free space is in too many pieces for the file's record (the demo makes no "
                      "attribute lists)");
    }
    f->nruns = runs.n;
    f->nalloc += got;
    return 0;
}

/* n more bytes into the file's clusters */
static int nw_put_clusters(struct wfile *f, const u8 *data, u32 n)
{
    struct volume *v = f->v;
    u32 csh = v->csh;
    while (n) {
        u32 in = (u32)f->nsize & (SECTOR - 1), take = SECTOR - in < n ? SECTOR - in : n;
        if (!f->cur_ready) {            /* the sector byte nsize goes into */
            u32 s = (u32)(f->nsize >> 9), vcn = s >> csh;
            if (vcn >= f->nalloc && nw_more(f) < 0)
                return -1;
            while (f->nri < f->nruns && vcn - f->nrun[f->nri].vcn >= f->nrun[f->nri].len)
                f->nri++;
            if (f->nri >= f->nruns)
                return nw_err("NTFS: the file's runs end early");
            f->cur_lba = v->start + ((f->nrun[f->nri].lcn + (vcn - f->nrun[f->nri].vcn)) << csh)
                         + (s & ((1u << csh) - 1));
            if (!in)
                wipe(f->cur, SECTOR);
            else if (read_sectors(f->k, f->cur_lba, 1, f->cur) < 0)     /* (adding to a file: the bytes before) */
                return nw_err(0);
            f->cur_ready = 1;
        }
        copy(f->cur + in, data, take);
        f->nsize += take;
        data += take;
        n -= take;
        if (!(f->nsize & (SECTOR - 1)) && wf_queue(f) < 0)
            return -1;
    }
    return 0;
}

/* a new file's name tried against its directory's index (nothing written): may it go in?  0, -1 */
static int nw_try_name(struct wfile *f)
{
    u8 dup[0x38];
    u16 seq;
    u32 sec, klen;
    struct idx_op op = {0, nw_ent, 0, 0};
    if (nw_parent(f->k, f->v, f->nt_dir, f->nname, &seq, &sec) < 0)
        return -1;
    wipe(dup, sizeof(dup));
    klen = nw_name_value(nw_key, f->nt_dir, seq, dup, f->nname);
    nw_entry_make(nw_ent, 0, 0, nw_key, klen);
    return nw_index(f->k, f->v, f->nt_dir, &op, NW_DRY);
}

static int nw_put(struct wfile *f, const u8 *data, u32 n)
{
    nw_verb = f->nverb;
    if (nw_use(f->k, f->v) < 0)
        return nw_fail();
    if (f->nt == 1) {
        u32 room = f->nt_room >= 0x18 ? f->nt_room - 0x18 : 0;
        if (f->nsize + n <= room) {     /* still few enough for its record */
            copy(f->q + (u32)f->nsize, data, n);
            f->nsize += n;
            return 0;
        }
        /* clusters from here on.  A new file: may its name go into the directory at all?  Asked now,
           before a long copy is written for nothing (a file that stays in its record is not asked for:
           its record is let go again when the name does not go in) */
        if (!f->nt_rec && !f->nt_tried) {
            if (nw_try_name(f) < 0)
                return nw_fail();
            f->nt_tried = 1;
        }
        u8 head[REC_MAX];               /* what was kept goes into the clusters first */
        u32 kept = (u32)f->nsize;
        copy(head, f->q, kept);
        f->nt = 2;
        f->nsize = 0;
        f->q_n = 0;
        f->cur_ready = 0;
        if (nw_put_clusters(f, head, kept) < 0)
            return nw_fail();
    }
    return nw_put_clusters(f, data, n) < 0 ? nw_fail() : 0;
}

/* the file there already gets its new $DATA: in its record, in the old one's place; its times and its names'
   sizes.  Its directory's index with the new sizes is prepared first (laid out, written beside the old
   one: what can fail for want of room fails here, the file as it was), then the file's record is written --
   from here the new bytes are the file's --, then the directory's record, then the clusters it had before
   are freed.  0, -1 */
static u8 nw_had[REC_MAX];              /* the $DATA attribute it had: kept here, and nowhere a work buffer is,
                                           until its clusters are freed -- after the index was written */

static int nw_set_data(struct wfile *f)
{
    struct disk *k = f->k;
    struct volume *v = f->v;
    u8 *r = nw_rec, dup[0x38];
    u32 up, rec = f->nt_rec, da, si, had = 0;
    struct idx_op op = {0, 0, rec, dup};
    if (nw_mft_get(k, v, rec, r) < 0 || nw_file_ok(v, r, rec, 0, &up) < 0)
        return -1;
    if (le16(r + 0x10) != f->nt_seq || (le16(r + 0x16) & 2) || up != f->nt_dir)
        return nw_err("the file was changed while it was being written: not replaced");
    da = rec_find(v, r, 0x80, "");
    if (da && r[da + 8] && !f->nkeep) { /* the clusters it has now (not when it was added to: those stay its own) */
        copy(nw_had, r + da, le32(r + da + 4));
        if (nw_attr_free(k, v, nw_had, 0) < 0)          /* (sound, and its own to free: asked now) */
            return -1;
        had = 1;
    }
    if (!(f->nt == 2 ? rec_put_runs(v, r, da, 0x80, "", f->nrun, f->nruns, f->nsize, 0xFFFF)
                     : rec_put_resident(v, r, da, 0x80, "", f->q, (u32)f->nsize, 0, 0xFFFF)))
        return nw_err("no room in the file's record for its new bytes' place (the demo makes no attribute lists)");
    si = rec_find(v, r, 0x10, "");
    u8 *s = r + si + le16(r + si + 0x14);
    put64(s + 8, nw_now());             /* written, */
    put64(s + 0x10, nw_now());          /* its record changed */
    put32(s + 0x20, le32(s + 0x20) | 0x20);
    nw_dup(v, r, dup);
    for (u32 at = 0; (at = attr_next(v, r, at));)
        if (le32(r + at) == 0x30)
            copy(r + at + le16(r + at + 0x14) + 8, dup, 0x34);
    nw_later_count = 0;
    if (nw_index(k, v, f->nt_dir, &op, NW_PREPARE) < 0)
        return -1;
    if (nw_mft_put(k, v, rec, r) < 0) {
        nw_index_drop(k, v);
        return -1;
    }
    f->nkeep = f->nalloc;               /* (the record names the new clusters: they are the file's from here) */
    if (nw_index_commit(k, v) < 0) {
        nw_later_drop();
        return -1;                      /* (a write failed: the entry still shows the old size) */
    }
    if (had)
        nw_leaked(v, nw_attr_free(k, v, nw_had, 1));
    nw_later_free(k, v);
    return 0;
}

/* the file complete: what is left written, the clusters taken ahead given back, its record and its
   directory's entry.  0, -1 (said why) */
static int nw_close(struct wfile *f)
{
    struct disk *k = f->k;
    struct volume *v = f->v;
    nw_verb = f->nverb;
    if (nw_use(k, v) < 0)
        return nw_fail();
    if (f->nt == 2) {
        struct runs runs = {f->nrun, f->nruns, WF_RUNS};
        u32 cshift = 9 + v->csh, need = (u32)((f->nsize + ((1u << cshift) - 1)) >> cshift);
        if ((f->cur_ready && wf_queue(f) < 0) || wf_flush(f) < 0)
            return nw_fail();
        if (need < f->nkeep)
            need = f->nkeep;
        if (runs_trim(k, v, &runs, need) < 0)
            return nw_fail();
        f->nruns = runs.n;
        f->nalloc = runs_clusters(&runs);
        if (runs.n)
            v->alloc_hint = runs.r[runs.n - 1].lcn + runs.r[runs.n - 1].len;    /* (the next file: right after) */
    }
    int r = f->nt_rec ? nw_set_data(f)
                      : f->nt == 2 ? nw_new(k, v, f->nt_dir, f->nname, 0, 0, 0, f->nrun, f->nruns, f->nsize)
                                   : nw_new(k, v, f->nt_dir, f->nname, 0, f->q, (u32)f->nsize, 0, 0, 0);
    if (r < 0)
        return nw_fail();
    f->nt = 0;
    sync_disk(k);
    return 0;
}

/* a write that failed: the clusters it took given back (the file there before is as it was) */
static void nw_abort(struct wfile *f)
{
    struct runs runs = {f->nrun, f->nruns, WF_RUNS};
    u32 taken = runs_clusters(&runs);
    if (f->nt == 2 && taken > f->nkeep) {
        if (nw_use(f->k, f->v) == 0)
            nw_back(f->v, runs_trim(f->k, f->v, &runs, f->nkeep));
        else if (f->k->ready)           /* (read-only now -- something found wrong, a write that failed: what the
                                           write had taken cannot be given back) */
            uprintf("%s: the %u clusters it had taken stay marked in use (the volume is read-only now: chkdsk "
                    "/f in Windows frees them)\n", f->nverb, taken - f->nkeep);
    }
    f->nt = 0;
}

/* a file on an NTFS volume opened for writing: `name` in the directory of entry `parent`; `old`: the entry it
   has there already (0: a new file).  Nothing is written yet; what can be told now is told: is the
   directory one the demo changes (for a file there already: its whole index read and looked over), the
   file one it writes over?  0, -1 (said why) */
static int nw_open(struct wfile *f, const struct entry *parent, const char *name, const struct entry *old,
                   int append, const char *verb)
{
    struct disk *k = f->k;
    struct volume *v = f->v;
    u8 *r = nw_rec;
    u32 dir = parent->cluster ? parent->cluster : MFT_ROOT, cshift = 9 + v->csh;
    f->nt = 0;
    f->nsize = 0;
    f->nalloc = f->nkeep = f->nruns = f->nri = 0;
    f->nt_rec = 0;
    f->nt_dir = dir;
    f->nverb = nw_verb = verb;
    for (int i = 0; i < NAME_MAX; i++)
        f->nname[i] = i < NAME_MAX - 1 ? name[i] : 0;
    if (nw_use(k, v) < 0)
        return nw_fail();
    f->nt_tried = 0;
    if (!old) {                         /* a new file: is its directory one the demo changes? */
        u16 seq;
        u32 sec;
        if (nw_parent(k, v, dir, name, &seq, &sec) < 0)
            return nw_fail();
        if (nw_fixed(v, (u32)path_len(name), sec) + 0x18 > v->rec_size) {
            (void)nw_err("the name does not fit a file record of this volume");
            return nw_fail();
        }
        f->nt_room = v->rec_size - nw_fixed(v, (u32)path_len(name), sec);
        f->nt = 1;
        return 0;
    }
    u32 up, da;
    struct idx_op op = {0, 0, 0, 0};
    if (nw_mft_get(k, v, old->cluster, r) < 0 || nw_file_ok(v, r, old->cluster, 0, &up) < 0)
        return nw_fail();
    if (le16(r + 0x10) != old->slot_off[0] || up != dir) {
        (void)nw_chk(v, nw_stale);
        return nw_fail();
    }
    if (le16(r + 0x16) & 2) {
        (void)nw_err("not a plain file: not written over");
        return nw_fail();
    }
    da = rec_find(v, r, 0x80, "");
    f->nt_rec = old->cluster;
    f->nt_seq = le16(r + 0x10);
    f->nt_room = v->rec_size - le32(r + 0x18) + (da ? le32(r + da + 4) : 0);
    if (append && da && !r[da + 8]) {   /* added to: the bytes in its record first */
        f->nsize = le32(r + da + 0x10);
        copy(f->q, r + da + le16(r + da + 0x14), (u32)f->nsize);
    } else if (append && da) {          /* its runs: on from its last byte */
        struct runs runs = {f->nrun, 0, WF_RUNS};
        if (nw_attr_runs(v, r, da, &runs) < 0)
            return nw_fail();
        u64 size = le64(r + da + 0x30), have = (u64)runs_clusters(&runs) << cshift;
        if (le64(r + da + 0x38) != size || have < size || have != le64(r + da + 0x28)) {
            (void)nw_err("the file has bytes never written (its valid length is shorter than its size): the demo "
                         "does not add to it");
            return nw_fail();
        }
        f->nruns = runs.n;
        f->nalloc = f->nkeep = runs_clusters(&runs);
        if (f->nalloc) {
            f->nsize = size;
            f->q_n = 0;
            f->cur_ready = 0;
        }
    }
    if (nw_index(k, v, dir, &op, NW_DRY) < 0)   /* (its directory: one the demo changes?) */
        return nw_fail();
    f->nt = f->nalloc ? 2 : 1;
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
    if (f->nt)
        return nw_put(f, data, n);
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
    if (f->nt)
        return nw_close(f);
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
    if (f->nt) {
        nw_abort(f);
        return;
    }
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
    f->nt = 0;
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
    if (!writable(k))
        return -1;
    if (v->fs == FS_NTFS)
        return nw_open(f, &parent, name, there ? &e : 0, append, verb);
    if (fsinfo_unknown(k, v) < 0)
        return -1;
    if (!there) {
        int n = make_entry(k, v, parent.cluster, name, 0x20, 0, 0, ents);
        if (n < 0 || dir_put(k, v, parent.cluster, ents, n, &f->ent_lba, &f->ent_off) < 0) {
            uprintf("%s: not made (%s)\n", verb, io_error());
            return -1;
        }
        return 0;
    }
    f->ent_lba = e.slot_lba[e.slots - 1];
    f->ent_off = e.slot_off[e.slots - 1];
    if (append && e.size) {             /* its last cluster (one after it, if any, freed) */
        u32 csize = (u32)v->spc * SECTOR, need = e.size / csize + (e.size % csize != 0), c = e.cluster;
                                        /* (not (size + csize - 1) / csize: within a cluster of 4 GB that wraps
                                           to 0, and the file's chain was cut after its first cluster) */
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
    uprintf("%s: %s\n", verb, io_error());
    return -1;
}

/* 'command > path' (and '>>'): what the command printed into the file */
void disk_write_file(const char *path, const u8 *data, u32 len, int append)
{
    const char *verb = append ? ">>" : ">";
    if (wf_open(&wf, path, append, verb) < 0)
        return;
    if (wf_put(&wf, data, len) < 0 || wf_close(&wf) < 0) {
        write_failed(verb);
        wf_abort(&wf);
    }
}

static int is_dots(const char *n)
{
    return n[0] == '.' && (!n[1] || (n[1] == '.' && !n[2]));
}

/* the path `to` names, a directory there: with "/name" added (into it); 0 (said why).  self: the entry
   being renamed, when `to` may name it in another spelling ('mv Photos photos': the directory itself, not one
   to move it into) */
static int same_entry(const struct entry *a, const struct entry *b);

static const char *target_of(const char *to, const char *name, const struct entry *self)
{
    static char t[PATH_MAX + NAME_MAX + 2];
    static struct entry d;
    struct disk *k;
    struct volume *v;
    u32 dir;
    const char *from;
    int n = 0, max = (int)sizeof(t) - 1;
    for (; to[n] && n < max; n++)
        t[n] = to[n];
    t[n] = 0;
    if (to[n]) {                        /* (it was cut after 96 characters, whatever they were: the file went to
                                           a shorter name or into another directory.  What a path's directory
                                           part and its name may be is new_place's to say) */
        uprintf("the path is too long\n");
        return 0;
    }
    const char *path = locate(to, &k, &v, &dir, &from);
    if (!path)
        return 0;
    quiet = 1;
    int is_dir = walk_path(k, v, dir, from, path, &d, 0) == 0 && (d.attr & 0x10);
    quiet = 0;
    if (is_dir && self && same_entry(&d, self))
        is_dir = 0;
    if (is_dir) {
        if (n + 1 + path_len(name) > max) {
            uprintf("the path is too long\n");
            return 0;
        }
        if (n && t[n - 1] != '/' && t[n - 1] != ':')
            t[n++] = '/';
        for (const char *s = name; *s; s++)
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
   name -- from any FAT or NTFS volume to any other, another disk's too; a
   file there is written over */
/* cp's work: 0 copied (Ctrl-C: copy_stopped, a shorter file), -1 not (said why) */
static int copy_stopped;

static int copy_file(const char *src, const char *dst)
{
    struct disk *sk, *tk;
    struct volume *sv, *tv;
    static struct entry se, te;
    static struct reader r;
    u32 dir;
    const char *from;
    if (old_entry(src, 0, &sk, &sv, &se) < 0)
        return -1;
    if (se.attr & 0x10) {
        uprintf("cp: a directory (cp copies files): %s\n", se.name);
        return -1;
    }
    const char *target = target_of(dst, se.name, 0);
    if (!target)
        return -1;
    const char *tpath = locate(target, &tk, &tv, &dir, &from);
    if (!tpath || read_only(tk, tv, "cp"))
        return -1;
    quiet = 1;
    int there = walk_path(tk, tv, dir, from, tpath, &te, 0) == 0;
    quiet = 0;
    if (there && tk == sk && tv == sv && same_entry(&te, &se)) {
        uprintf("cp: the same file: %s\n", se.name);
        return -1;
    }
    if (file_open(&r, sk, sv, &se, "cp") < 0)  /* (after the target's directories were read: NTFS's buffers) */
        return -1;
    if (r.size > 0xFFFFFFFFu && tv->fs == FS_FAT) {
        uprintf("cp: %s is 4 GB or more: a FAT file cannot hold it\n", se.name);
        return -1;
    }
    if (wf_open(&wf, target, 0, "cp") < 0)
        return -1;
    int n;
    while ((n = file_read(&r, file_buf, sizeof(file_buf))) > 0) {
        if (wf_put(&wf, file_buf, (u32)n) < 0)
            goto failed;
        if (uart_getc() == 3) {         /* Ctrl-C: what was copied stays, a shorter file */
            uprintf("^C (%u of %u bytes copied)\n", (u32)r.pos, (u32)r.size);
            copy_stopped = 1;
            break;
        }
    }
    if (n < 0) {
        say_why("cp");
        wf_abort(&wf);
        return -1;
    }
    if (wf_close(&wf) == 0)
        return 0;
failed:
    write_failed("cp");
    wf_abort(&wf);
    return -1;
}

void disk_cp(const char *src, const char *dst)
{
    (void)copy_file(src, dst);
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
    if (first_volume(k) == cwd.v || !cwd.v->number)     /* the volume "n:" names; another "n.p:" */
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
    if (!spath || read_only(k, v, "mv") || walk_path(k, v, dir, from, spath, &se, old_path) < 0)
        return;
    if (!se.slots || is_dots(se.name)) {
        uprintf("not that one: '%s'\n", src);
        return;
    }
    const char *target = target_of(dst, se.name, &se);
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
            if ((v->fs == FS_NTFS ? ntfs_parent(k, v, c, &c) : parent_of(k, v, c, &c)) < 0)
                goto failed;
        }
    }
    if (!writable(k))
        return;
    if (v->fs == FS_NTFS) {
        nw_verb = "mv";
        if (nw_use(k, v) < 0 || nw_move(k, v, &se, parent.cluster, name) < 0) {
            (void)nw_fail();
            return;
        }
        sync_disk(k);
        goto moved;
    }
    if (fsinfo_unknown(k, v) < 0)
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
moved:
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
            const char *rest = cwd.path + ol;
            for (; *rest && m < PATH_MAX - 1; rest++)
                new_path[m++] = *rest;
            new_path[m] = 0;
            if (*rest || pl + (pl > 1) + path_len(name) + path_len(cwd.path + ol) > PATH_MAX - 1) {
                cwd.k = 0;              /* (its new path is longer than a path's text: none, rather than a
                                           text that names another directory) */
                uprintf("mv: the current directory's path is too long now: back to none ('cd' chooses one)\n");
                return;
            }
            for (int i = 0; i <= m; i++)
                cwd.path[i] = new_path[i];
            cwd_text_set();
        }
    }
    return;
failed:
    uprintf("mv: %s\n", io_error());
}

/* ---- what the explorer on the TV reads (explorer.c) ---- */
/* a number that changes when a disk comes or goes or a sector is written: the explorer lists again */
u32 disk_changes(void)
{
    return changes;
}

struct dir_read {
    struct disk_entry *out;
    int max, n;
    u32 total;
};

static int dir_read_fn(const struct entry *e, void *ctx)
{
    struct dir_read *d = ctx;
    if ((e->attr & 0x08) || is_dots(e->name))
        return 0;                       /* the volume label, '.', '..' (as ls) */
    d->total++;
    if (d->n < d->max) {
        struct disk_entry *o = &d->out[d->n++];
        int i = 0;
        for (; i < DISK_ENTRY_NAME - 1 && e->name[i]; i++)
            o->name[i] = e->name[i];
        o->name[i] = 0;
        o->size = e->size;
        o->size_hi = e->size_hi;
        o->date = e->date;
        o->time = e->time;
        o->kind = (e->attr & 0x10) ? DISK_DIR : DISK_FILE;
        o->attr = e->attr;
    }
    (void)now_ms();                     /* (the watchdog: a long directory) */
    return 0;
}

/* the entries of the directory at `arg` (as 'ls' takes it: "" the current directory) into out (max of
   them, in the directory's order; *total: all of them): how many, -1 when it cannot be read (said why) */
int disk_dir_read(const char *arg, struct disk_entry *out, int max, u32 *total)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    u32 dir;
    const char *from;
    *total = 0;
    const char *path = locate(arg, &k, &v, &dir, &from);
    if (!path || walk_path(k, v, dir, from, path, &e, 0) < 0)
        return -1;
    if (!(e.attr & 0x10)) {
        uprintf("not a directory: %s\n", e.name);
        return -1;
    }
    struct dir_read d = {out, max, 0, 0};
    if (dir_walk(k, v, e.cluster, seq_of(&e), dir_read_fn, &d) < 0) {
        say_why(0);
        return -1;
    }
    *total = d.total;
    return d.n;
}

/* every volume of every disk as an entry (DISK_VOLUME) whose name starts with what 'cd' takes for it --
   "4:" (a disk's first FAT volume, else its first NTFS one), "4.2:" (another partition) -- and says what it is;
   size: its MB; attr 0x02 for one whose files are not read (not FAT nor NTFS, no medium).  How many */
int disk_volumes(struct disk_entry *out, int max)
{
    int n = 0;
    for (int i = 0; i < DISKS && n < max; i++) {
        struct disk *k = &disks[i];
        if (!k->used)
            continue;
        if (!k->ready)
            probe(k);                   /* (a card put in since) */
        const char *name = k->name[0] ? k->name : "(INQUIRY not answered)";
        if (!k->ready || !k->volumes) {
            struct disk_entry *o = &out[n++];
            usnprintf(o->name, DISK_ENTRY_NAME, "%u:  %s: %s", k->device, name,
                      k->problem ? k->problem : "no volume");
            o->size = mb(k->blocks);
            o->size_hi = 0;
            o->date = o->time = 0;
            o->kind = DISK_VOLUME;
            o->attr = 0x02;
            continue;
        }
        for (int j = 0; j < k->volumes && n < max; j++) {
            struct volume *v = &k->vol[j];
            struct disk_entry *o = &out[n++];
            volume_text(0, v);
            if (v == first_volume(k) || !v->number)
                usnprintf(o->name, DISK_ENTRY_NAME, "%u:  %s  -  %s", k->device, text, name);
            else
                usnprintf(o->name, DISK_ENTRY_NAME, "%u.%u:  %s  -  %s", k->device, v->number, text, name);
            o->size = mb(v->sectors);
            o->size_hi = 0;
            o->date = o->time = 0;
            o->kind = DISK_VOLUME;
            o->attr = readable(v) ? 0 : 0x02;
        }
    }
    return n;
}

/* the current directory's volume: "disk 4: FAT32 'STICK32', 39 MB" ("" without one) */
void disk_cwd_volume(char *out, int size)
{
    if (!cwd.k || !cwd.k->used) {
        out[0] = 0;
        return;
    }
    volume_text(0, cwd.v);
    if (cwd.v->number)
        usnprintf(out, size, "disk %u partition %u: %s", cwd.k->device, cwd.v->number, text);
    else
        usnprintf(out, size, "disk %u: %s", cwd.k->device, text);
}

/* the first `max` bytes of the file at `arg` (as 'cat' takes it) into buf, its size into *size: the
   bytes read, -1 when it cannot be read (said why) */
int disk_read_head(const char *arg, u8 *buf, u32 max, u32 *size)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    u32 dir;
    const char *from;
    *size = 0;
    const char *path = locate(arg, &k, &v, &dir, &from);
    if (!path || walk_path(k, v, dir, from, path, &e, 0) < 0)
        return -1;
    if (e.attr & 0x10) {
        uprintf("a directory: %s\n", e.name);
        return -1;
    }
    static struct reader r;
    if (file_open(&r, k, v, &e, "preview") < 0)
        return -1;
    *size = r.size > 0xFFFFFFFFu ? 0xFFFFFFFFu : (u32)r.size;
    u32 got = 0;
    while (got < max) {
        int n = file_read(&r, file_buf, sizeof(file_buf));
        if (n < 0) {
            say_why(0);
            return -1;
        }
        if (!n)
            break;
        for (int i = 0; i < n && got < max; i++)
            buf[got++] = file_buf[i];
    }
    return (int)got;
}

/* ---- what the FTP server reads and writes (ftp.c): a reader and a writer of its own -- a transfer lasts
   across main loop passes, and cat, cp, sum, the explorer or '>' may read and write in between: the
   reader's NTFS runs and small file's bytes are its own (NTFS_RUNS2_PHYS), and both stop when a disk comes
   or goes (their disk and volume pointers would name another) ---- */
static struct runs stream_runs = {(struct nrun *)KSEG0(NTFS_RUNS2_PHYS), 0, FILE_RUNS};
static u8 stream_res[REC_MAX];
static struct reader stream;
static u32 stream_gen;
static struct wfile up;
static int up_open;
static u32 up_gen;

/* the disk is the one it was when generation `gen` was noted (plugged in, its medium the same)? */
static int disk_same(const struct disk *k, u32 gen)
{
    return k && k->used && k->gen == gen;
}

/* is an FTP upload under way on that volume?  (read_only: every other writer of it waits) */
static int upload_on(const struct disk *k, const struct volume *v)
{
    return up_open && disk_same(up.k, up_gen) && up.k == k && up.v == v;
}

/* is there a file at `arg`?  Nothing is said when there is none (a path only tried: a game's save file) */
int disk_exists(const char *arg)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    u32 dir;
    const char *from;
    quiet = 1;
    const char *path = locate(arg, &k, &v, &dir, &from);
    int found = path && walk_path(k, v, dir, from, path, &e, 0) == 0 && !(e.attr & 0x10);
    quiet = 0;
    return found;
}

/* the entry at `arg` (a file, a directory, a volume's root) into *o: 0, -1 (said why) */
int disk_stat(const char *arg, struct disk_entry *o)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    u32 dir;
    const char *from;
    const char *path = locate(arg, &k, &v, &dir, &from);
    if (!path || walk_path(k, v, dir, from, path, &e, 0) < 0)
        return -1;
    int i = 0;
    for (; i < DISK_ENTRY_NAME - 1 && e.name[i]; i++)
        o->name[i] = e.name[i];
    o->name[i] = 0;
    o->size = e.attr & 0x10 ? 0 : e.size;
    o->size_hi = e.attr & 0x10 ? 0 : e.size_hi;
    o->date = e.date;
    o->time = e.time;
    o->kind = (e.attr & 0x10) ? DISK_DIR : DISK_FILE;
    o->attr = e.attr;
    return 0;
}

static u32 stream_opens;                /* disk_stream_open's calls (smb.c: is the reader still its own?) */

u32 disk_stream_opens(void)
{
    return stream_opens;
}

/* the file at `arg` opened for disk_stream_read: 0 (its size into *size), -1 (said why) */
int disk_stream_open(const char *arg, u64 *size)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    u32 dir;
    const char *from;
    stream_opens++;
    stream.k = 0;
    const char *path = locate(arg, &k, &v, &dir, &from);
    if (!path || walk_path(k, v, dir, from, path, &e, 0) < 0)
        return -1;
    if (e.attr & 0x10) {
        uprintf("a directory: %s\n", e.name);
        return -1;
    }
    stream.runs = &stream_runs;
    stream.res = stream_res;
    if (file_open(&stream, k, v, &e, "RETR") < 0) {
        stream.k = 0;
        return -1;
    }
    stream_gen = k->gen;
    *size = stream.size;
    return 0;
}

static u64 reader_seek(struct reader *r, u64 pos);

/* the reader moved to the sector holding `pos` (forwards or back, any time after disk_stream_open): where it is
   now (the bytes from there to pos are the caller's to leave out) */
u64 disk_stream_seek(u64 pos)
{
    return stream.k ? reader_seek(&stream, pos) : 0;
}

/* its next bytes (max: a multiple of 512, 4096 at most): how many, 0 at its end, -1 (said why) */
int disk_stream_read(u8 *buf, u32 max)
{
    if (!stream.k)
        return 0;
    if (!disk_same(stream.k, stream_gen)) {
        stream.k = 0;
        uprintf("its disk went away\n");
        return -1;
    }
    fail_why = 0;
    int n = file_read(&stream, buf, max);
    if (n < 0) {
        stream.k = 0;
        say_why(0);
    }
    return n;
}

void disk_stream_close(void)
{
    stream.k = 0;
}

/* `arg` opened for writing (made, emptied, or added to with `append`): 0, -1 (said why) */
int disk_upload_open(const char *arg, int append)
{
    if (up_open && up.nt && disk_same(up.k, up_gen))
        wf_abort(&up);                  /* (an NTFS upload never closed: the clusters it took given back) */
    up_open = 0;
    if (wf_open(&up, arg, append, append ? "APPE" : "STOR") < 0)
        return -1;
    up_open = 1;
    up_gen = up.k->gen;
    return 0;
}

/* more of its bytes: 0, -1 (said why; the clusters it took are freed again) */
int disk_upload_put(const u8 *data, u32 n)
{
    if (!up_open)
        return -1;
    if (!disk_same(up.k, up_gen)) {    /* (its own disk went, or its medium: nothing of it is written) */
        up_open = 0;
        uprintf("its disk went away\n");
        return -1;
    }
    if (!up.nt && up.size + n < up.size) {
        uprintf("over 4 GB: FAT's limit\n");
        wf_abort(&up);
        up_open = 0;
        return -1;
    }
    nw_said = 0;
    if (wf_put(&up, data, n) < 0) {
        if (!nw_said)
            uprintf("%s\n", io_error());
        wf_abort(&up);
        up_open = 0;
        return -1;
    }
    return 0;
}

/* written to its end, its entry set: 0, -1 (said why) */
int disk_upload_close(void)
{
    if (!up_open)
        return -1;
    up_open = 0;
    if (!disk_same(up.k, up_gen)) {
        uprintf("its disk went away\n");
        return -1;
    }
    nw_said = 0;
    if (wf_close(&up) < 0) {
        if (!nw_said)
            uprintf("%s\n", io_error());
        wf_abort(&up);
        return -1;
    }
    return 0;
}

/* ---- rm -r, cp -r, df, head, tail ---- */
#define TREE_DEPTH 16                   /* directories below the one named, at most */
#define BATCH      32                   /* a directory's entries read at a time (rm -r, cp -r) */
#define TAIL_BYTES 16384                /* tail reads the file's last 16 KB (and back to its cluster's start) */

static struct entry batch_e[BATCH];

struct batch {
    u32 skip, n;
};

static int batch_fn(const struct entry *e, void *ctx)
{
    struct batch *b = ctx;
    if ((e->attr & 0x08) || is_dots(e->name))
        return 0;                       /* (the volume's label, '.', '..') */
    if (b->skip) {
        b->skip--;
        return 0;
    }
    batch_e[b->n++] = *e;
    (void)now_ms();                     /* (the watchdog: a long directory) */
    return b->n >= BATCH;
}

/* directory `cluster`'s entries after its first `skip` into batch_e (BATCH at most): how many, -1 not read
   (`seq`: as dir_walk's -- 'rm -r' through a stale entry would empty another directory) */
static int batch_read(struct disk *k, const struct volume *v, u32 cluster, u32 seq, u32 skip)
{
    struct batch b = {skip, 0};
    if (dir_walk(k, v, cluster, seq, batch_fn, &b) < 0) {
        dir_failed();
        return -1;
    }
    return (int)b.n;
}

static u32 tree_files, tree_dirs;
static u32 tree_path[TREE_DEPTH + 2];   /* rm -r: the clusters of the directories it is in */

/* a directory and everything in it, deepest first: 0, -1 (said why; what was removed stays removed).  A
   directory entry whose cluster is 0, the volume's root or one it is already in (a damaged disk) is not
   followed: its "contents" would be another directory's */
static int remove_tree(struct disk *k, struct volume *v, struct entry *dir, int depth)
{
    if (depth > TREE_DEPTH) {
        uprintf("rm -r: deeper than %u directories: stopped\n", TREE_DEPTH);
        return -1;
    }
    int bad = v->fs == FS_NTFS ? dir->cluster < NW_META
                               : !dir->cluster || (v->fat == 32 && dir->cluster == v->root_cluster);
    for (int i = 0; i < depth && !bad; i++)
        bad = tree_path[i] == dir->cluster;
    if (bad) {
        uprintf("rm -r: %s: a damaged directory entry (its cluster is another directory's): not followed\n",
                dir->name);
        return -1;
    }
    tree_path[depth] = dir->cluster;
    for (;;) {
        int n = batch_read(k, v, dir->cluster, seq_of(dir), 0);
        if (n < 0)
            return -1;
        if (!n)
            break;
        int sub = -1;
        for (int i = 0; i < n; i++) {
            if (batch_e[i].attr & 0x10) {
                if (sub < 0)
                    sub = i;
                continue;
            }
            if (remove_file(k, v, &batch_e[i]) < 0)
                return -1;
            tree_files++;
        }
        if (uart_getc() == 3) {
            uprintf("^C\n");
            return -1;
        }
        if (sub >= 0) {
            struct entry e = batch_e[sub];          /* (batch_e is read again in it) */
            if (remove_tree(k, v, &e, depth + 1) < 0)
                return -1;
        }
    }
    if (remove_dir(k, v, dir) < 0)
        return -1;
    tree_dirs++;
    return 0;
}

static void tree_said(const char *done, int r)
{
    uprintf("%s%u file%s and %u director%s %s\n", r < 0 ? "stopped: " : "", tree_files, tree_files == 1 ? "" : "s",
            tree_dirs, tree_dirs == 1 ? "y" : "ies", done);
}

/* 'rm -r <path>': a file, or a directory and everything in it (never the current directory's tree) */
void disk_rm_r(const char *arg)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    if (old_entry(arg, "rm", &k, &v, &e) < 0)
        return;
    if (!(e.attr & 0x10)) {
        (void)remove_file(k, v, &e);
        return;
    }
    if (cwd.k == k && cwd.v == v) {
        u32 c = cwd.cluster;
        for (int steps = 0; c && steps < 256; steps++) {
            if (c == e.cluster) {
                uprintf("rm -r: the current directory is in it ('cd' out of it first)\n");
                return;
            }
            if ((v->fs == FS_NTFS ? ntfs_parent(k, v, c, &c) : parent_of(k, v, c, &c)) < 0)
                break;
        }
    }
    tree_files = tree_dirs = 0;
    tree_said("removed", remove_tree(k, v, &e, 0));
}

/* a path that disk.c takes whole (its part after "n:" under PATH_MAX): 1; else said, 0 */
static int path_fits(const char *p)
{
    const char *q = p;
    while (*q && *q != ':')
        q++;
    q = *q ? q + 1 : p;
    int n = 0;
    while (q[n])
        n++;
    if (n < PATH_MAX)
        return 1;
    uprintf("cp -r: a path longer than %u characters: %s\n", PATH_MAX - 1, p);
    return 0;
}

static void path_join(char *out, int size, const char *dir, const char *name)
{
    int n = 0;
    while (dir[n])
        n++;
    usnprintf(out, size, "%s%s%s", dir, n && (dir[n - 1] == '/' || dir[n - 1] == ':') ? "" : "/", name);
}

static char tree_dirs_at[TREE_DEPTH + 1][BATCH][NAME_MAX];     /* cp -r: each level's directories, by name */
static struct disk *made_k;             /* the directory cp -r made first: never copied into itself */
static struct volume *made_v;
static u32 made_cluster;

/* directory `src` as the new directory `dst` (FAT or NTFS, each) with all in it: 0, -1 (said why) */
static int copy_tree(const char *src, const char *dst, int depth)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    static char s[PATH_MAX + 16 + NAME_MAX], d[PATH_MAX + 16 + NAME_MAX];
    u32 dir;
    const char *from;
    if (depth > TREE_DEPTH) {
        uprintf("cp -r: deeper than %u directories: stopped\n", TREE_DEPTH);
        return -1;
    }
    if (!path_fits(src) || !path_fits(dst) || make_dir_at(dst) < 0)
        return -1;
    tree_dirs++;
    if (!depth) {                       /* (the one made: its place, to leave it out below) */
        const char *path = locate(dst, &made_k, &made_v, &dir, &from);
        if (!path || walk_path(made_k, made_v, dir, from, path, &e, 0) < 0)
            return -1;
        made_cluster = e.cluster;
    }
    const char *path = locate(src, &k, &v, &dir, &from);
    if (!path || walk_path(k, v, dir, from, path, &e, 0) < 0)
        return -1;
    u32 cluster = e.cluster, seq = seq_of(&e);
    for (u32 start = 0;;) {
        int n = batch_read(k, v, cluster, seq, start);
        if (n < 0)
            return -1;
        if (!n)
            break;
        start += (u32)n;
        int nd = 0;
        for (int i = 0; i < n; i++) {
            const struct entry *c = &batch_e[i];
            if (c->attr & 0x10) {
                if (!(k == made_k && v == made_v && c->cluster == made_cluster)) {
                    int j = 0;
                    for (; j < NAME_MAX - 1 && c->name[j]; j++)
                        tree_dirs_at[depth][nd][j] = c->name[j];
                    tree_dirs_at[depth][nd++][j] = 0;
                }
                continue;
            }
            path_join(s, sizeof(s), src, c->name);  /* (copy_file reads no batch_e: the batch stays) */
            path_join(d, sizeof(d), dst, c->name);
            if (!path_fits(s) || !path_fits(d) || copy_file(s, d) < 0 || copy_stopped)
                return -1;
            tree_files++;
        }
        for (int j = 0; j < nd; j++) {
            static char s2[PATH_MAX + 16 + NAME_MAX], d2[PATH_MAX + 16 + NAME_MAX];
            path_join(s2, sizeof(s2), src, tree_dirs_at[depth][j]);
            path_join(d2, sizeof(d2), dst, tree_dirs_at[depth][j]);
            char sub_src[PATH_MAX + 16], sub_dst[PATH_MAX + 16];   /* (the statics are the next level's too) */
            if (!path_fits(s2) || !path_fits(d2))
                return -1;
            int a = 0;
            for (; s2[a] && a < (int)sizeof(sub_src) - 1; a++)
                sub_src[a] = s2[a];
            sub_src[a] = 0;
            for (a = 0; d2[a] && a < (int)sizeof(sub_dst) - 1; a++)
                sub_dst[a] = d2[a];
            sub_dst[a] = 0;
            if (copy_tree(sub_src, sub_dst, depth + 1) < 0)
                return -1;
        }
    }
    return 0;
}

/* 'cp -r <from> <to>': a file as cp; a directory with all in it -- into <to> when that is a directory, else
   as <to> */
void disk_cp_r(const char *src, const char *dst)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    static char to[PATH_MAX + 16 + NAME_MAX];
    if (old_entry(src, 0, &k, &v, &e) < 0)
        return;
    if (!(e.attr & 0x10)) {
        (void)copy_file(src, dst);
        return;
    }
    if (entry_ok(k, v, &e, "cp -r") < 0)        /* (before the copy's directory is made) */
        return;
    const char *target = target_of(dst, e.name, 0);
    if (!target)
        return;
    int i = 0;
    for (; target[i] && i < (int)sizeof(to) - 1; i++)
        to[i] = target[i];
    to[i] = 0;
    tree_files = tree_dirs = 0;
    copy_stopped = 0;
    made_k = 0;
    tree_said("copied", copy_tree(src, to, 0));
}

/* 'df [n:]': each volume's size, free and used space (FAT: its free clusters counted in the FAT; NTFS: in its
   $Bitmap, record 6) */
static void df_volume(struct disk *k, struct volume *v)
{
    static struct reader r;
    static struct entry e;
    u32 total_mb, free_mb;
    usnprintf(text, sizeof(text), "device %u", k->device);
    int at = 0;
    while (text[at])
        at++;
    if (v->number)
        at += usnprintf(text + at, (int)sizeof(text) - at, " partition %u", v->number);
    at += usnprintf(text + at, (int)sizeof(text) - at, ": ");
    volume_text(at, v);
    if (v->fs == FS_FAT) {
        u32 n_free = 0;
        for (u32 c = 2; c < v->clusters + 2; c++) {
            u32 value;
            if (fat_get(k, v, c, &value) < 0) {
                uprintf("%s: the FAT did not read (%s)\n", text, io_error());
                return;
            }
            n_free += !value;
            if (!(c & 0x3FFF) && uart_getc() == 3) {
                uprintf("^C\n");
                return;
            }
        }
        total_mb = (u32)(((u64)v->clusters * v->spc) >> 11);
        free_mb = (u32)(((u64)n_free * v->spc) >> 11);
    } else if (v->fs == FS_NTFS && readable(v)) {
        for (unsigned i = 0; i < sizeof(e); i++)
            ((u8 *)&e)[i] = 0;
        e.cluster = 6;                  /* ($Bitmap: a bit for each cluster, 1 in use) */
        if (file_open(&r, k, v, &e, "df") < 0)
            return;
        u32 bits = v->ntfs_clusters, seen = 0, n_free = 0;
        int n;
        while (seen < bits && (n = file_read(&r, file_buf, sizeof(file_buf))) > 0) {
            for (int i = 0; i < n && seen < bits; i++) {
                u8 b = file_buf[i];
                for (int j = 0; j < 8 && seen < bits; j++, seen++)
                    n_free += !(b & (1u << j));
            }
            if (uart_getc() == 3) {
                uprintf("^C\n");
                return;
            }
        }
        if (seen < bits) {
            uprintf("%s: its $Bitmap did not read\n", text);
            return;
        }
        total_mb = (u32)(((u64)bits << (9 + v->csh)) >> 20);
        free_mb = (u32)(((u64)n_free << (9 + v->csh)) >> 20);
    } else {
        uprintf("%s: its files are not read\n", text);
        return;
    }
    u32 pct = !total_mb ? 0 : free_mb <= 42949672u ? free_mb * 100 / total_mb : free_mb / (total_mb / 100);
                                        /* (32-bit: no 64-bit division in the demo) */
    uprintf("%s: %u MB free, %u MB used (%u%% free)\n", text, free_mb, total_mb - free_mb, pct > 100 ? 100 : pct);
}

/* the volume holding `arg`: its size and free space, file system and label (smb.c).  The free clusters are
   counted once (FAT: in the FAT, NTFS: in its $Bitmap) and then kept: FAT's as fat_alloc / free_chain take and
   give them, NTFS's counted again after a change -- the FSInfo count disk.c makes unknown at its first write,
   and a count at every look took seconds on a big card: 0, -1 (said why) */
int disk_space(const char *arg, struct disk_space *o)
{
    static struct reader r;
    static struct entry e;
    struct disk *k;
    struct volume *v;
    u32 dir;
    const char *from;
    if (!locate(arg, &k, &v, &dir, &from))
        return -1;
    u32 total, cbytes;
    if (v->fs == FS_FAT) {
        total = v->clusters;
        cbytes = (u32)v->spc * SECTOR;
    } else if (v->fs == FS_NTFS && readable(v)) {
        total = v->ntfs_clusters;
        cbytes = (u32)SECTOR << v->csh;
    } else {
        uprintf("its files are not read\n");
        return -1;
    }
    if (!v->free_known || v->free_gen != k->gen || (v->fs == FS_NTFS && v->free_changes != changes)) {
        u32 n_free = 0;
        if (v->fs == FS_FAT) {
            for (u32 c = 2; c < v->clusters + 2; c++) {
                u32 value;
                if (fat_get(k, v, c, &value) < 0) {
                    uprintf("the FAT did not read (%s)\n", io_error());
                    return -1;
                }
                n_free += !value;
                if (!(c & 0xFFF))
                    (void)now_ms();
            }
        } else {
            for (unsigned i = 0; i < sizeof(e); i++)
                ((u8 *)&e)[i] = 0;
            e.cluster = 6;              /* ($Bitmap) */
            if (file_open(&r, k, v, &e, "space") < 0)
                return -1;
            u32 seen = 0;
            int n;
            while (seen < total && (n = file_read(&r, file_buf, sizeof(file_buf))) > 0)
                for (int i = 0; i < n && seen < total; i++)
                    for (int j = 0; j < 8 && seen < total; j++, seen++)
                        n_free += !(file_buf[i] & (1u << j));
            if (seen < total) {
                uprintf("its $Bitmap did not read\n");
                return -1;
            }
        }
        v->free_clusters = n_free;
        v->free_known = 1;
        v->free_gen = k->gen;
        v->free_changes = changes;
    }
    o->total = (u64)total * cbytes;
    o->avail = (u64)(v->free_clusters < total ? v->free_clusters : total) * cbytes;
    o->cluster = cbytes;
    const char *fs = v->fs == FS_NTFS ? "NTFS" : v->fat == 32 ? "FAT32" : v->fat == 16 ? "FAT16" : "FAT12";
    int i = 0;
    for (; fs[i]; i++)
        o->fs[i] = fs[i];
    o->fs[i] = 0;
    for (i = 0; i < (int)sizeof(o->label) - 1 && v->label[i]; i++)
        o->label[i] = v->label[i];
    o->label[i] = 0;
    o->serial = v->start * 2654435761u ^ v->sectors;
    return 0;
}

void disk_df(const char *arg)
{
    int any = 0;
    if (arg[0]) {
        struct disk *k;
        struct volume *v;
        u32 dir;
        const char *from;
        if (locate(arg, &k, &v, &dir, &from))
            df_volume(k, v);
        return;
    }
    for (int i = 0; i < DISKS; i++) {
        struct disk *k = &disks[i];
        if (!k->used)
            continue;
        if (!k->ready)
            probe(k);
        for (int j = 0; k->ready && j < k->volumes; j++) {
            df_volume(k, &k->vol[j]);
            any = 1;
        }
        if (!k->ready || !k->volumes) {
            uprintf("device %u: %s\n", k->device, k->problem ? k->problem : "no volume");
            any = 1;
        }
    }
    if (!any)
        uprintf("no USB disk\n");
}

/* the reader moved to the sector holding `pos` (a resident NTFS file's: to pos), forwards or back -- FAT walks its
   cluster chain on from the cluster being read, or again from the file's first one: where it is now (the bytes
   from there to pos are the caller's to leave out; a chain that ends early leaves the reader where it was) */
static u64 reader_seek(struct reader *r, u64 pos)
{
    const struct volume *v = r->v;
    if (pos >= r->size) {
        r->pos = r->size;               /* (the end: file_read gives 0; a seek back from here starts the chain
                                           again) */
        return r->pos;
    }
    if (v->fs == FS_FAT) {
        u32 shift = 9;
        while ((1u << shift) < (u32)v->spc * SECTOR)
            shift++;
        u32 steps = (u32)(pos >> shift), from = r->steps, c = r->cluster;
        if (steps < from || r->pos >= r->size) {        /* (back, or from the end -- where the cluster read last
                                                           is not the next one's) */
            from = 0;
            c = r->first;
        }
        for (u32 i = from; i < steps && c; i++) {
            c = next_cluster(r->k, v, c);
            if (!((i - from) & 0xFFF))
                (void)now_ms();
        }
        if (!c)
            return r->pos;
        r->cluster = c;
        r->steps = steps;
        r->in = (u32)(pos >> 9) & (v->spc - 1u);        /* (a cluster's sectors: a power of two) */
        r->pos = pos & ~(u64)(SECTOR - 1);
    } else if (r->resident) {
        r->pos = pos;
    } else {
        r->pos = pos & ~(u64)(SECTOR - 1);
        r->run = 0;
    }
    return r->pos;
}

/* a file opened for head / tail (as cat opens it): its reader, 0 when not */
static struct reader *text_open(const char *arg, const char *verb)
{
    struct disk *k;
    struct volume *v;
    static struct entry e;
    static struct reader r;
    u32 dir;
    const char *from;
    const char *path = locate(arg, &k, &v, &dir, &from);
    if (!path || walk_path(k, v, dir, from, path, &e, 0) < 0)
        return 0;
    if (e.attr & 0x10) {
        uprintf("a directory: 'ls' lists it\n");
        return 0;
    }
    return file_open(&r, k, v, &e, verb) < 0 ? 0 : &r;
}

static void text_char(u8 c)
{
    if (c == '\n')
        uprintf("\n");
    else if (c != '\r')
        uprintf("%c", c == '\t' ? ' ' : c >= 32 && c < 127 ? c : '.');
}

/* 'head [-n N] path': its first N lines */
void disk_head(const char *arg, u32 lines)
{
    struct reader *r = text_open(arg, "head");
    if (!r)
        return;
    u32 seen = 0;
    u8 last = '\n';
    int n = 0;
    while (seen < lines && (n = file_read(r, file_buf, sizeof(file_buf))) > 0) {
        for (int i = 0; i < n && seen < lines; i++) {
            text_char(file_buf[i]);
            last = file_buf[i];
            seen += file_buf[i] == '\n';
        }
        if (uart_getc() == 3) {
            uprintf("^C\n");
            return;
        }
    }
    if (n < 0)
        say_why("head");
    else if (last != '\n')
        uprintf("\n");
}

/* 'tail [-n N] path': its last N lines (of its last 16 KB) */
void disk_tail(const char *arg, u32 lines)
{
    static u8 tail[TAIL_BYTES + 65536 + 4096];  /* (from a cluster's start: up to 64 KB more) */
    struct reader *r = text_open(arg, "tail");
    if (!r)
        return;
    reader_seek(r, r->size > TAIL_BYTES ? r->size - TAIL_BYTES : 0);
    u32 len = 0;
    int n;
    while ((n = file_read(r, file_buf, sizeof(file_buf))) > 0) {
        if (len + (u32)n > sizeof(tail)) {      /* (keep the last part) */
            u32 drop = len + (u32)n - sizeof(tail);
            for (u32 i = drop; i < len; i++)
                tail[i - drop] = tail[i];
            len -= drop;
        }
        for (int i = 0; i < n; i++)
            tail[len++] = file_buf[i];
        if (uart_getc() == 3) {
            uprintf("^C\n");
            return;
        }
    }
    if (n < 0) {
        say_why("tail");
        return;
    }
    u32 i = len, found = 0;
    if (i && tail[i - 1] == '\n')
        i--;
    while (i > 0) {
        if (tail[i - 1] == '\n' && ++found == lines)
            break;
        i--;
    }
    for (; i < len; i++)
        text_char(tail[i]);
    if (len && tail[len - 1] != '\n')
        uprintf("\n");
}
