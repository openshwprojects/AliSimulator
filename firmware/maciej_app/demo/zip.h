/* zip.c: a game inside a .zip -- the archive read whole into RAM, one
   member unpacked (stored or deflated, image.c's inflate) and its CRC-32
   checked.  Nothing in it knows the box (a PC harness runs it too). */
#ifndef DEMO_ZIP_H
#define DEMO_ZIP_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

int zip_is(const u8 *p, u32 n);         /* a zip's first local header ("PK\3\4") */
/* the member a player wants: the largest file that is not a text, a picture or a page (readme.txt, a cover
   .jpg, an .nfo); with `ext` (".nes", or 0) a member with that extension first.  Unpacked into dst (at most
   cap bytes; dst must not overlap the archive): 0, or why not; *size its bytes, name (max bytes) its name */
const char *zip_unpack(const u8 *zip, u32 n, const char *ext, u8 *dst, u32 cap, u32 *size, char *name, int max);
/* the first member's name from the archive's first bytes (its first local header: the explorer reads only
   those): 0, or why not */
const char *zip_first_name(const u8 *head, u32 n, char *name, int max);
/* the name of the member zip_unpack would pick, from the whole archive (0: none) */
const char *zip_pick_name(const u8 *zip, u32 n, char *name, int max);
/* multi-member archives (arcade ROM sets): member count (0: not a valid zip), and member `index` unpacked into
   dst (or, with dst == 0, only its *size and name inspected): 0, or why not */
u32 zip_count(const u8 *zip, u32 n);
const char *zip_unpack_at(const u8 *zip, u32 n, u32 index, u8 *dst, u32 cap, u32 *size, char *name, int max);

/* a gzip file (.gz; the Amiga's .adz is one): its header ("\x1F\x8B", deflate) */
int gz_is(const u8 *p, u32 n);
/* unpacked into dst (at most cap bytes, not overlapping it), its CRC-32 and size checked: 0, or why not; name:
   the name kept in its header ("" when it has none) */
const char *gz_unpack(const u8 *gz, u32 n, u8 *dst, u32 cap, u32 *size, char *name, int max);
/* the name kept in a gzip file's header, from its first bytes: 1, or 0 when it has none (name "") */
int gz_name(const u8 *head, u32 n, char *name, int max);

#endif
