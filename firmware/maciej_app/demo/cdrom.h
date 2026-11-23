/* cdrom.h: Shared multi-track CD-ROM TOC & sector callback interface for
   PC Engine CD-ROM2 ('pcecd') and Sega CD / Mega-CD ('segacd').
   Backed by play.c's 8 MB 4-way set-associative sector cache over .cue/.bin
   and .iso images on disk, or in-memory callbacks in host test harnesses. */
#ifndef DEMO_CDROM_H
#define DEMO_CDROM_H

#define CDROM_MAX_TRACKS 100

struct cdrom_track {
    unsigned int   lba;         /* Track INDEX 01 start LBA (0-based; MSF = LBA + 150) */
    unsigned int   length;      /* Sector count */
    unsigned short sec_size;    /* 2048 (cooked ISO) or 2352 (raw BIN / CD-DA) */
    unsigned char  is_audio;    /* 1 = Redbook CD-DA stereo 16-bit LE PCM, 0 = Data */
    unsigned char  control;     /* Subchannel Q control nibble: 0x04 = Data, 0x00 = Audio */
};

struct cdrom_toc {
    unsigned char first_track;  /* Usually 1 */
    unsigned char last_track;   /* 1..99 */
    unsigned int  total_lba;    /* Lead-out LBA (also stored at tracks[100].lba) */
    struct cdrom_track tracks[CDROM_MAX_TRACKS + 1];
    /* Read 2048-byte Mode 1 / Mode 2 Form 1 user data payload at disc LBA.
       Returns 0 on success, -1 on out-of-range or I/O error. */
    int (*read_2048)(unsigned int lba, unsigned char *dst2048);
    /* Read 2352-byte raw sector (16-bit LE stereo PCM for audio tracks, or raw
       Mode 1 sector for data tracks). Returns 0 on success, -1 on error. */
    int (*read_2352)(unsigned int lba, unsigned char *dst2352);
};

#endif
