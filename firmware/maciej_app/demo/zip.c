/* A game inside a .zip: see zip.h.

   The end of central directory record (searched for in the last 64 KB + 22
   bytes) gives the central directory; each of its entries gives a member's
   name, method, sizes, CRC-32 and where its local header is.  The local
   header's own name and extra field lengths say where the data starts (its
   sizes may be zero when a data descriptor follows: the central entry's are
   used).  Methods: 0 (stored) and 8 (deflate).  Not read: ZIP64, encrypted
   members, split archives. */
#include "zip.h"
#include "image.h"

static u32 le16(const u8 *p)
{
    return (u32)p[0] | (u32)p[1] << 8;
}

static u32 le32(const u8 *p)
{
    return le16(p) | le16(p + 2) << 16;
}

static char lower(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c + 32) : c;
}

/* the name's extension is `ext` (".nes"; any case) */
static int has_ext(const u8 *name, u32 len, const char *ext)
{
    u32 e = 0;
    while (ext[e])
        e++;
    if (len < e)
        return 0;
    for (u32 i = 0; i < e; i++)
        if (lower((char)name[len - e + i]) != lower(ext[i]))
            return 0;
    return 1;
}

static int skipped(const u8 *name, u32 len)
{
    static const char *const skip[] = {".txt", ".nfo", ".diz", ".doc", ".htm", ".html", ".pdf", ".jpg", ".jpeg",
                                       ".png", ".gif", ".bmp", ".url", ".sfv", ".xml", ".ini", ".cfg", ".dat", 0};
    if (!len || name[len - 1] == '/' || name[len - 1] == '\\')
        return 1;
    for (int i = 0; skip[i]; i++)
        if (has_ext(name, len, skip[i]))
            return 1;
    return 0;
}

static void copy_name(const u8 *src, u32 len, char *name, int max)
{
    if (max <= 0)
        return;
    /* (a name too long for the buffer: its end is kept -- the players tell a game's kind by its extension, and
       only the part after the last '/' is used) */
    u32 skip = len > (u32)(max - 1) ? len - (u32)(max - 1) : 0, i = 0;
    for (; skip + i < len; i++)
        name[i] = (char)src[skip + i];
    name[i] = 0;
}

int zip_is(const u8 *p, u32 n)
{
    return n >= 30 && p[0] == 'P' && p[1] == 'K' && p[2] == 3 && p[3] == 4;
}

/* the central directory: where, how many entries; 0, or why not */
static const char *central(const u8 *zip, u32 n, u32 *at, u32 *count)
{
    if (n < 22)
        return "not a zip archive";
    u32 lo = n > 0x10000 + 22 ? n - 0x10000 - 22 : 0;
    for (u32 i = n - 22 + 1; i-- > lo;) {
        const u8 *e = zip + i;
        if (e[0] == 'P' && e[1] == 'K' && e[2] == 5 && e[3] == 6) {
            *count = le16(e + 10);
            *at = le32(e + 16);
            if (le16(e + 4) || le16(e + 6))
                return "a zip archive split in parts";
            if (*at == 0xFFFFFFFFu || *count == 0xFFFFu)
                return "a ZIP64 archive (not read)";
            if (*at > i)
                return "a damaged zip archive";
            return 0;
        }
    }
    return "a zip archive without its directory (damaged or cut short)";
}

/* the member to unpack: its central entry (0: none fits) */
static const u8 *pick(const u8 *zip, u32 n, const char *ext, const char **why)
{
    u32 at, count;
    *why = central(zip, n, &at, &count);
    if (*why)
        return 0;
    const u8 *best = 0, *best_ext = 0;
    u32 best_size = 0, best_ext_size = 0;
    for (u32 k = 0; k < count; k++) {
        if (at + 46 > n || le32(zip + at) != 0x02014B50u) {
            *why = "a damaged zip directory";
            return 0;
        }
        const u8 *e = zip + at;
        u32 nlen = le16(e + 28), xlen = le16(e + 30), clen = le16(e + 32), size = le32(e + 24);
        if (at + 46 + nlen > n) {
            *why = "a damaged zip directory";
            return 0;
        }
        const u8 *name = e + 46;
        if (!skipped(name, nlen)) {
            if (ext && has_ext(name, nlen, ext) && (!best_ext || size > best_ext_size)) {
                best_ext = e;
                best_ext_size = size;
            }
            if (!best || size > best_size) {
                best = e;
                best_size = size;
            }
        }
        at += 46 + nlen + xlen + clen;
    }
    if (!best && !best_ext)
        *why = "no game file in the zip archive (only texts, pictures or folders)";
    return best_ext ? best_ext : best;
}

static u32 crc_table[256];

static u32 crc32(const u8 *p, u32 n)
{
    if (!crc_table[1])
        for (u32 i = 0; i < 256; i++) {
            u32 c = i;
            for (int k = 0; k < 8; k++)
                c = c & 1 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            crc_table[i] = c;
        }
    u32 c = 0xFFFFFFFFu;
    for (u32 i = 0; i < n; i++)
        c = crc_table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return ~c;
}

const char *zip_pick_name(const u8 *zip, u32 n, char *name, int max)
{
    const char *why;
    const u8 *e = pick(zip, n, 0, &why);
    if (!e)
        return why;
    copy_name(e + 46, le16(e + 28), name, max);
    return 0;
}

static const char *unpack_entry(const u8 *zip, u32 n, const u8 *e, u8 *dst, u32 cap, u32 *size, char *name, int max)
{
    const char *why;
    u32 flags = le16(e + 8), method = le16(e + 10), crc = le32(e + 16), clen = le32(e + 20), ulen = le32(e + 24);
    u32 local = le32(e + 42);
    copy_name(e + 46, le16(e + 28), name, max);
    if (!dst) {
        *size = ulen;
        return 0;
    }
    if (flags & 1)
        return "an encrypted zip member (not read)";
    if (ulen > cap)
        return "a zip member too big to unpack here";
    if (local + 30 > n || le32(zip + local) != 0x04034B50u)
        return "a damaged zip archive (a member's header)";
    u32 data = local + 30 + le16(zip + local + 26) + le16(zip + local + 28);
    if (data > n || clen > n - data)
        return "a zip archive cut short";
    u32 made = 0;
    if (method == 0) {
        if (clen != ulen)
            return "a damaged zip member";
        for (u32 i = 0; i < clen; i++)
            dst[i] = zip[data + i];
        made = clen;
    } else if (method == 8) {
        why = image_inflate(zip + data, clen, dst, cap, &made);
        if (why)
            return why;
    } else {
        return "a zip member packed by a method other than deflate (not read)";
    }
    if (made != ulen)
        return "a damaged zip member (its size)";
    if (crc32(dst, made) != crc)
        return "a damaged zip member (its CRC-32)";
    *size = made;
    return 0;
}

const char *zip_unpack(const u8 *zip, u32 n, const char *ext, u8 *dst, u32 cap, u32 *size, char *name, int max)
{
    const char *why;
    *size = 0;
    const u8 *e = pick(zip, n, ext, &why);
    if (!e)
        return why;
    return unpack_entry(zip, n, e, dst, cap, size, name, max);
}

u32 zip_count(const u8 *zip, u32 n)
{
    u32 at = 0, count = 0;
    return central(zip, n, &at, &count) ? 0 : count;
}

const char *zip_unpack_at(const u8 *zip, u32 n, u32 index, u8 *dst, u32 cap, u32 *size, char *name, int max)
{
    u32 at = 0, count = 0;
    *size = 0;
    if (max > 0)
        name[0] = 0;
    const char *why = central(zip, n, &at, &count);
    if (why)
        return why;
    if (index >= count)
        return "zip member index out of range";
    for (u32 k = 0; k < index; k++) {
        if (at + 46 > n || le32(zip + at) != 0x02014B50u)
            return "a damaged zip directory";
        const u8 *e = zip + at;
        at += 46 + le16(e + 28) + le16(e + 30) + le16(e + 32);
    }
    if (at + 46 > n || le32(zip + at) != 0x02014B50u)
        return "a damaged zip directory";
    const u8 *e = zip + at;
    if (at + 46 + le16(e + 28) > n)
        return "a damaged zip directory";
    return unpack_entry(zip, n, e, dst, cap, size, name, max);
}

int gz_is(const u8 *p, u32 n)
{
    return n >= 18 && p[0] == 0x1F && p[1] == 0x8B && p[2] == 8;
}

const char *gz_unpack(const u8 *gz, u32 n, u8 *dst, u32 cap, u32 *size, char *name, int max)
{
    *size = 0;
    if (max > 0)
        name[0] = 0;
    if (!gz_is(gz, n))
        return "not a gzip file";
    u32 flags = gz[3], at = 10;
    if (flags & 0xE0)
        return "a gzip header this does not know";
    if (flags & 4) {                    /* FEXTRA */
        if (at + 2 > n)
            return "a gzip file cut short";
        at += 2 + le16(gz + at);
    }
    if (flags & 8) {                    /* FNAME: zero-terminated */
        u32 s = at;
        while (at < n && gz[at])
            at++;
        copy_name(gz + s, at - s, name, max);
        at++;
    }
    if (flags & 16) {                   /* FCOMMENT */
        while (at < n && gz[at])
            at++;
        at++;
    }
    if (flags & 2)                      /* FHCRC */
        at += 2;
    if (at + 8 > n)
        return "a gzip file cut short";
    u32 crc = le32(gz + n - 8), want = le32(gz + n - 4), made = 0;
    if (want > cap)
        return "a gzip file too big to unpack here";
    const char *why = image_inflate(gz + at, n - 8 - at, dst, cap, &made);
    if (why)
        return why;
    if (made != want)
        return "a damaged gzip file (its size)";
    if (crc32(dst, made) != crc)
        return "a damaged gzip file (its CRC-32)";
    *size = made;
    return 0;
}

int gz_name(const u8 *head, u32 n, char *name, int max)
{
    if (max > 0)
        name[0] = 0;
    if (!gz_is(head, n) || !(head[3] & 8))
        return 0;
    u32 at = 10;
    if (head[3] & 4) {
        if (at + 2 > n)
            return 0;
        at += 2 + le16(head + at);
    }
    u32 s = at;
    while (at < n && head[at])
        at++;
    if (at >= n)                        /* (longer than was read) */
        return 0;
    copy_name(head + s, at - s, name, max);
    return name[0] != 0;
}

const char *zip_first_name(const u8 *head, u32 n, char *name, int max)
{
    if (!zip_is(head, n))
        return "not a zip archive";
    u32 nlen = le16(head + 26);
    if (30 + nlen > n)
        return "a zip member's name longer than read";
    copy_name(head + 30, nlen, name, max);
    return 0;
}
