/* threedo.c: 3DO Interactive Multiplayer ('3do': .iso, .cue; "": built-in 3D CEL showcase)
   Clean-room implementation of the 3DO Opera hardware & Portfolio 2.5 runtime:
   - CPU: 12.5 MHz 32-bit Big-Endian ARM60 (ARMv3, USR/FIQ/IRQ/SVC/ABT/UND register banks)
   - Memory: 2 MB DRAM (0x00000000) + 1 MB dual-bank VRAM (0x00200000) + 1 MB ROM (0x03000000)
     + 32 KB battery-backed NVRAM (0x03140000) stored in EMU_RAM_PHYS (zero static .bss)
   - Video: Madam (0x03300000) hardware CEL Quad Engine (1/2/4/6/8/16-bpp Unpacked & RLE Packed,
     PLUT, PIXC translucency/shading, perspective quad fill) + SPORT (0x03200000) + VDL CLUT
   - I/O & Sound: Clio (0x03400000) timers/IRQs, PBUS 11-button pad, XBUS CR-563 CD-ROM,
     DSPP / Portfolio Audio + 44.1 kHz Redbook CD-DA resampled to 48 kHz
   - Boot: Opera FS (\x01ZZZZZ\x01) + Portfolio OS 2.5 HLE (Kernel, Graphics, File, Audio,
     OperaMath, EventBroker, SPORT, Timer) or optional external panafz10.bin BIOS */

#pragma GCC optimize("O2")
#include "threedo.h"

#ifdef THREEDO_HOST
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
static u8 *host_ram_buf;
static void *threedo_ram_base(void)
{
    if (!host_ram_buf)
        host_ram_buf = (u8 *)calloc(1, 0x00980000u);
    return host_ram_buf;
}
#define THREEDO_RAM_MAX 0x00980000u
#else
#include "hw.h"
static inline void *threedo_ram_base(void) { return (void *)KSEG0(EMU_RAM_PHYS); }
#define THREEDO_RAM_MAX EMU_RAM_SIZE
#endif

typedef unsigned long long u64;
typedef signed long long s64;

#define DRAM_SIZE   (2u * 1024u * 1024u)
#define VRAM_SIZE   (1u * 1024u * 1024u)
#define ROM_SIZE    (1u * 1024u * 1024u)
#define NVRAM_SIZE  (32u * 1024u)

/* Fixed HLE system area at top of 2 MB DRAM: 0x001E0000..0x001FFFFF (128 KB) */
#define HLE_BASE        0x001E0000u
#define HLE_STUBS       0x001E0000u     /* Folio negative-vector ARM60 SWI trampolines */
#define HLE_KERNEL      0x001E2400u     /* KernelBase (+256B negative vectors at 0x1E2300) */
#define HLE_GRAF        0x001E2800u     /* GrafFolio  (+256B negative vectors at 0x1E2700) */
#define HLE_FILE        0x001E2C00u     /* FileFolio  (+256B negative vectors at 0x1E2B00) */
#define HLE_AUDIO       0x001E3000u     /* AudioFolio (+256B negative vectors at 0x1E2F00) */
#define HLE_MATH        0x001E3400u     /* MathFolio  (+256B negative vectors at 0x1E3300) */
#define HLE_TASK        0x001E3600u     /* CurrentTask struct */
#define HLE_MEMHDR_LIST 0x001E3800u     /* kb_MemHdrList */
#define HLE_MEMHDR_DRAM 0x001E3840u     /* DRAM MemHdr + free page bits */
#define HLE_MEMHDR_VRAM 0x001E38C0u     /* VRAM MemHdr + free page bits */
#define HLE_TASK_MLIST  0x001E3940u     /* t_FreeMemoryLists (empty list) */
#define HLE_DRAM_BITS   0x001E3A00u     /* 64 bytes (512 x 4KB pages) */
#define HLE_VRAM_BITS   0x001E3A80u     /* 64 bytes (512 x 2KB pages) */
#define HLE_DISPINFO    0x001E3B00u     /* DisplayInfo node + tags */
#define HLE_STRINGS     0x001E3C00u     /* Constant strings ("Graphics", etc.) */
#define HLE_EVBUF       0x001E3E00u     /* EventBroker outgoing message payload */
#define HLE_ITEM_ARENA  0x001E4000u     /* 0x1E4000..0x1F7FFF: ItemNode structs (80 KB) */
#define HLE_SUPER_SP    0x001FFFC0u
#define HLE_USER_SP     0x001DF000u     /* User stack grows down from 0x1DF000; heap below */

#define MAX_ITEMS       256
#define MAX_OPEN_FILES  32
#define MAX_VOICES      8
#define SND_RING_FRAMES 4096

/* ARM60 processor modes */
#define MODE_USR 0x10u
#define MODE_FIQ 0x11u
#define MODE_IRQ 0x12u
#define MODE_SVC 0x13u
#define MODE_ABT 0x17u
#define MODE_UND 0x1Bu

#define CPSR_N   0x80000000u
#define CPSR_Z   0x40000000u
#define CPSR_C   0x20000000u
#define CPSR_V   0x10000000u
#define CPSR_I   0x00000080u
#define CPSR_F   0x00000040u

/* Item kinds in our HLE table */
enum {
    IK_NONE = 0,
    IK_FOLIO,
    IK_TASK,
    IK_DEVICE,
    IK_IOREQ,
    IK_SCREENGROUP,
    IK_SCREEN,
    IK_BITMAP,
    IK_VDL,
    IK_MSGPORT,
    IK_MSG,
    IK_SEMAPHORE,
    IK_DISKFILE,
    IK_AUDIO_INS,
    IK_AUDIO_SMP,
    IK_AUDIO_ATT,
    IK_AUDIO_KNOB,
    IK_AUDIO_CUE
};

struct hle_item {
    u8  kind;
    u8  subsys;
    u8  ntype;
    u8  dev_type;       /* 1=SPORT, 2=timer, 3=cdrom, 4=mac, 5=diskfile */
    u32 node_addr;      /* Address of ItemNode in DRAM */
    u32 aux0;           /* Bitmap vram addr / File start LBA / Screen bitmap item / MsgPort signal */
    u32 aux1;           /* Bitmap width / File byte size / ReplyPort / Ins template */
    u32 aux2;           /* Bitmap height / File cur pos */
    char name[32];
};

struct dsp_voice {
    u8  active;
    u8  stereo;
    u8  loop;
    u8  is_16bit;
    u32 data_addr;
    u32 byte_len;
    u32 pos_fp;         /* 16.16 sample index */
    u32 step_fp;        /* 16.16 step @ host rate */
    s32 gain_l;         /* 0..32767 */
    s32 gain_r;
    u32 phase;          /* Built-in synth oscillator phase */
    u32 freq_inc;
};

struct threedo_mem {
    /* Host-endian u32 word arrays: word[a>>2] is the big-endian 32-bit ARM word at (a & ~3);
       ((u8 *)word)[a ^ 3] is the exact big-endian byte at address a! */
    u32 dram32[DRAM_SIZE / 4];
    u32 vram32[VRAM_SIZE / 4];
    u32 rom32[ROM_SIZE / 4];
    u8  nvram[NVRAM_SIZE];

    /* ARM60 CPU state */
    u32 r[16];
    u32 cpsr;
    u32 spsr[6];        /* 0=USR(unused), 1=FIQ, 2=IRQ, 3=SVC, 4=ABT, 5=UND */
    u32 r_usr[7];       /* R8..R14 user */
    u32 r_fiq[7];       /* R8..R14 FIQ */
    u32 r13_bank[6];
    u32 r14_bank[6];
    int halted;
    int vbl_yield;      /* >0: remaining VBL fields to wait */

    /* Madam & Clio hardware state */
    u32 madam[2048 / 4];
    u32 clio[2048 / 4];
    u16 plut[32];
    u32 ccb_regs[12];   /* Persistent XPos,YPos,HDX,HDY,VDX,VDY,HDDX,HDDY,PIXC,PRE0,PRE1 */
    u32 display_vram;   /* Currently displayed VRAM offset (0..VRAM_SIZE-1) */
    u32 draw_vram;      /* Default CEL write VRAM offset */
    u32 read_vram;      /* Default CEL read/CFBD VRAM offset */
    s32 clip_w, clip_h;
    u8  clut_r[32], clut_g[32], clut_b[32];
    u8  clut_identity;
    u32 bg_rgb;
    u32 lfsr;

    /* Disc / Opera FS state */
    const struct cdrom_toc *cd;
    int has_bios;
    int hle_mode;       /* 1 = Portfolio HLE, 2 = Built-in ARM60 3D CEL demo, 0 = Low-level BIOS */
    u32 fs_root_lba;
    u32 fs_blk_size;
    u32 cwd_lba;
    char cwd_path[96];
    u8  sec_buf[2048];
    u32 sec_cached_lba;

    /* XBUS CR-563 CD-ROM state */
    u8  xbus_cmd[16];
    u8  xbus_cmd_len;
    u8  xbus_stat[32];
    u32 xbus_stat_pos, xbus_stat_len;
    u8  xbus_data[2352];
    u32 xbus_data_pos, xbus_data_len;
    u8  xbus_poll;

    /* Portfolio HLE allocator & items */
    u32 dram_heap_lo;
    u32 dram_heap_hi;
    u32 vram_heap_lo;
    u32 item_arena_ptr;
    struct hle_item items[MAX_ITEMS];

    /* EventBroker state */
    u32 eb_port_item;
    u32 eb_listener_port;
    u32 eb_event_msg;
    u32 eb_msg_in_flight;
    u32 prev_pad_3do;
    u32 cur_pad_3do;

    /* Timing */
    u32 frame_count;
    u64 total_usec;
    s32 demo_ang_y, demo_ang_x;
    int nvram_dirty;

    /* Audio & CD-DA */
    u32 audio_hz;
    u32 sample_acc;
    struct dsp_voice voices[MAX_VOICES];
    int cdda_playing;
    u32 cdda_lba;
    u32 cdda_end_lba;
    u32 cdda_pos_fp;    /* 16.16 sample index within current 588-frame sector */
    u8  cdda_buf[2352];
    s16 snd_ring[SND_RING_FRAMES * 2];
    u32 snd_r, snd_w;

    char info_str[128];
};

static struct threedo_mem *S;
static const u8 *bios_ext_ptr;
static u32 bios_ext_sz;

void threedo_set_bios(const u8 *rom, u32 size)
{
    bios_ext_ptr = (rom && size >= 0x40000u && size <= ROM_SIZE) ? rom : 0;
    bios_ext_sz  = bios_ext_ptr ? size : 0;
}

/* 64-bit by 32-bit unsigned division without __udivdi3 for freestanding MIPS32 */
static u32 udiv64_32(u64 num, u32 den, u32 *rem_out)
{
    if (den == 0) {
        if (rem_out) *rem_out = 0xFFFFFFFFu;
        return 0xFFFFFFFFu;
    }
    u32 hi = (u32)(num >> 32);
    u32 lo = (u32)num;
    if (hi >= den) {
        /* Saturate to 32-bit max on overflow (matches OperaMath DivUF16 spec) */
        if (rem_out) *rem_out = 0xFFFFFFFFu;
        return 0xFFFFFFFFu;
    }
    u64 rem = hi;
    u32 q = 0;
    for (int i = 31; i >= 0; i--) {
        rem = (rem << 1) | ((lo >> i) & 1u);
        if (rem >= den) {
            rem -= den;
            q |= (1u << i);
        }
    }
    if (rem_out) *rem_out = (u32)rem;
    return q;
}

static s32 sdiv64_32(s64 num, s32 den)
{
    if (den == 0) return 0;
    int neg = (num < 0) ^ (den < 0);
    u64 un = (num < 0) ? (u64)(-num) : (u64)num;
    u32 ud = (den < 0) ? (u32)(-den) : (u32)den;
    u32 q = udiv64_32(un, ud, 0);
    return neg ? -(s32)q : (s32)q;
}

static u32 isqrt32(u32 x)
{
    u32 op = x, res = 0, one = 1u << 30;
    while (one > op) one >>= 2;
    while (one != 0) {
        if (op >= res + one) {
            op -= res + one;
            res = res + 2u * one;
        }
        res >>= 1;
        one >>= 2;
    }
    return res;
}

/* Quarter-wave 65-entry 16.16 sine table (64 steps per quadrant = 256 units/circle) */
static const s32 sin_q64[65] = {
        0,  1608,  3216,  4821,  6424,  8022,  9616, 11204,
    12785, 14359, 15924, 17479, 19024, 20557, 22078, 23586,
    25080, 26558, 28020, 29466, 30893, 32303, 33692, 35062,
    36410, 37736, 39040, 40320, 41576, 42806, 44011, 45190,
    46341, 47464, 48559, 49624, 50660, 51665, 52639, 53581,
    54491, 55368, 56212, 57022, 57798, 58538, 59244, 59914,
    60547, 61145, 61705, 62228, 62714, 63162, 63572, 63944,
    64277, 64571, 64827, 65043, 65220, 65358, 65457, 65516,
    65536
};

static s32 sin_f16(s32 angle_f16)
{
    /* 256.0 in 16.16 = 0x01000000 full circle */
    u32 u = (u32)angle_f16 & 0x00FFFFFFu;
    u32 idx = u >> 16;          /* 0..255 */
    u32 frac = (u >> 8) & 0xFFu;
    u32 q = idx >> 6;           /* 0..3 */
    u32 off = idx & 63u;
    s32 a, b;
    if (q == 0) {
        a = sin_q64[off]; b = sin_q64[off + 1];
    } else if (q == 1) {
        a = sin_q64[64 - off]; b = sin_q64[63 - off];
    } else if (q == 2) {
        a = -sin_q64[off]; b = -sin_q64[off + 1];
    } else {
        a = -sin_q64[64 - off]; b = -sin_q64[63 - off];
    }
    return a + (((b - a) * (s32)frac) >> 8);
}

/* --- Big-Endian Byte/Half/Word Accessors over word-native arrays --- */
static inline u8 dram_r8(u32 a)
{
    return ((const u8 *)S->dram32)[(a & (DRAM_SIZE - 1u)) ^ 3u];
}
static inline void dram_w8(u32 a, u8 v)
{
    ((u8 *)S->dram32)[(a & (DRAM_SIZE - 1u)) ^ 3u] = v;
}
static inline u16 dram_r16(u32 a)
{
    return ((const u16 *)S->dram32)[((a & (DRAM_SIZE - 1u)) >> 1) ^ 1u];
}
static inline void dram_w16(u32 a, u16 v)
{
    ((u16 *)S->dram32)[((a & (DRAM_SIZE - 1u)) >> 1) ^ 1u] = v;
}
static inline u32 dram_r32(u32 a)
{
    return S->dram32[(a & (DRAM_SIZE - 1u)) >> 2];
}
static inline void dram_w32(u32 a, u32 v)
{
    S->dram32[(a & (DRAM_SIZE - 1u)) >> 2] = v;
}

static inline u8 vram_r8(u32 a)
{
    return ((const u8 *)S->vram32)[(a & (VRAM_SIZE - 1u)) ^ 3u];
}
static inline void vram_w8(u32 a, u8 v)
{
    ((u8 *)S->vram32)[(a & (VRAM_SIZE - 1u)) ^ 3u] = v;
}
static inline u16 vram_r16(u32 a)
{
    return ((const u16 *)S->vram32)[((a & (VRAM_SIZE - 1u)) >> 1) ^ 1u];
}
static inline void vram_w16(u32 a, u16 v)
{
    ((u16 *)S->vram32)[((a & (VRAM_SIZE - 1u)) >> 1) ^ 1u] = v;
}
static inline u32 vram_r32(u32 a)
{
    return S->vram32[(a & (VRAM_SIZE - 1u)) >> 2];
}
static inline void vram_w32(u32 a, u32 v)
{
    S->vram32[(a & (VRAM_SIZE - 1u)) >> 2] = v;
}

static void mem_write_bytes(u32 dst, const u8 *src, u32 len)
{
    for (u32 i = 0; i < len; i++) {
        u32 a = dst + i;
        if (a < DRAM_SIZE)
            dram_w8(a, src[i]);
        else if (a >= 0x00200000u && a < 0x00300000u)
            vram_w8(a - 0x00200000u, src[i]);
    }
}

static void mem_read_str(u32 addr, char *out, int max)
{
    int i = 0;
    while (i < max - 1) {
        u8 c = 0;
        if (addr < DRAM_SIZE)
            c = dram_r8(addr);
        else if (addr >= 0x00200000u && addr < 0x00300000u)
            c = vram_r8(addr - 0x00200000u);
        else if (addr >= 0x03000000u && addr < 0x03100000u)
            c = ((const u8 *)S->rom32)[(addr - 0x03000000u) ^ 3u];
        if (!c) break;
        out[i++] = (char)c;
        addr++;
    }
    out[i] = 0;
}

static u32 mem_write_str(u32 addr, const char *s)
{
    u32 i = 0;
    do {
        dram_w8(addr + i, (u8)s[i]);
    } while (s[i++]);
    return (addr + i + 3u) & ~3u;
}

static inline u32 any_r32(u32 a)
{
    if (a < DRAM_SIZE)
        return S->dram32[a >> 2];
    if (a >= 0x00200000u && a < 0x00300000u)
        return S->vram32[(a - 0x00200000u) >> 2];
    if (a >= 0x03000000u && a < 0x03100000u)
        return S->rom32[(a - 0x03000000u) >> 2];
    return 0;
}

static inline u16 any_r16(u32 a)
{
    if (a < DRAM_SIZE)
        return dram_r16(a);
    if (a >= 0x00200000u && a < 0x00300000u)
        return vram_r16(a - 0x00200000u);
    if (a >= 0x03000000u && a < 0x03100000u)
        return ((const u16 *)S->rom32)[((a - 0x03000000u) >> 1) ^ 1u];
    return 0;
}

static inline u8 any_r8(u32 a)
{
    if (a < DRAM_SIZE)
        return dram_r8(a);
    if (a >= 0x00200000u && a < 0x00300000u)
        return vram_r8(a - 0x00200000u);
    if (a >= 0x03000000u && a < 0x03100000u)
        return ((const u8 *)S->rom32)[(a - 0x03000000u) ^ 3u];
    return 0;
}

/* --- VDL Parser & CLUT --- */
static void vdl_reset_default(void)
{
    for (int i = 0; i < 32; i++) {
        u8 v = (u8)((i << 3) | (i >> 2));
        S->clut_r[i] = v;
        S->clut_g[i] = v;
        S->clut_b[i] = v;
    }
    S->clut_identity = 1;
    S->bg_rgb = 0;
}

static void vdl_apply_entry(u32 w)
{
    if ((w & 0xE0000000u) == 0xE0000000u)
        return; /* VDL_NOP / background */
    if ((w & 0xC0000000u) == 0xC0000000u) {
        if (w & 0x20000000u)
            S->bg_rgb = w & 0x00FFFFFFu;
        return;
    }
    if (w & 0x80000000u) {
        u32 pen = (w >> 24) & 31u;
        u32 ctl = (w >> 29) & 3u;
        u8 r = (u8)(w >> 16), g = (u8)(w >> 8), b = (u8)w;
        if (ctl == 0) {
            S->clut_r[pen] = r; S->clut_g[pen] = g; S->clut_b[pen] = b;
        } else if (ctl == 3) {
            S->clut_r[pen] = r;
        } else if (ctl == 2) {
            S->clut_g[pen] = g;
        } else if (ctl == 1) {
            S->clut_b[pen] = b;
        }
        S->clut_identity = 0;
    }
}

static void vdl_parse_list(u32 addr, int max_words)
{
    if (!addr || addr >= DRAM_SIZE)
        return;
    for (int safety = 0; safety < 64 && addr >= 16u && addr + 16u <= DRAM_SIZE; safety++) {
        u32 dma = dram_r32(addr);
        u32 cur_bmp = dram_r32(addr + 4);
        u32 prv_bmp = dram_r32(addr + 8);
        u32 next_vdl = dram_r32(addr + 12);
        if ((dma & 0x00200000u) && cur_bmp >= 0x00200000u && cur_bmp < 0x00300000u)
            S->display_vram = cur_bmp - 0x00200000u;
        (void)prv_bmp;
        u32 len = (dma >> 9) & 0x3Fu;
        if ((int)len > max_words) len = (u32)max_words;
        for (u32 i = 0; i < len && addr + 16u + i * 4u < DRAM_SIZE; i++)
            vdl_apply_entry(dram_r32(addr + 16u + i * 4u));
        if (dma & 0x00040000u)
            next_vdl = addr + 16u + (s32)next_vdl;
        if (!next_vdl || next_vdl == addr || (dma & 0x1FFu) == 0)
            break;
        addr = next_vdl;
    }
}

/* --- Madam Hardware CEL Quad Projector --- */
static inline u16 vram_read_pix(u32 base_off, s32 w, s32 x, s32 y)
{
    u32 idx = ((base_off >> 2) + (u32)(y >> 1) * (u32)w + (u32)x) & ((VRAM_SIZE >> 2) - 1u);
    u32 word = S->vram32[idx];
    return (y & 1) ? (u16)word : (u16)(word >> 16);
}

static inline void vram_write_pix(u32 base_off, s32 w, s32 x, s32 y, u16 pix)
{
    u32 idx = ((base_off >> 2) + (u32)(y >> 1) * (u32)w + (u32)x) & ((VRAM_SIZE >> 2) - 1u);
    u32 word = S->vram32[idx];
    if (y & 1)
        S->vram32[idx] = (word & 0xFFFF0000u) | pix;
    else
        S->vram32[idx] = (word & 0x0000FFFFu) | ((u32)pix << 16);
}

static u16 cel_shade_pixc(u16 rgb15, u16 cfbd, u16 ppmp, u8 amv, u32 ccb_flags)
{
    /* Fast path 1: opaque 1.0x unshaded (PPMP_MODE_NORMAL = 0x1F00 or 0x1F40) */
    if (ppmp == 0x1F00u || ppmp == 0x1F40u) {
        u16 out = rgb15 & 0x7FFFu;
        if (!out && !(ccb_flags & 0x10u))
            out = 0x0400u;
        return out;
    }
    /* Fast path 2: 50/50 average blend (PPMP_MODE_AVERAGE = 0x1F81) */
    if (ppmp == 0x1F81u) {
        u16 out = (u16)((((rgb15 & 0x7BDEu) + (cfbd & 0x7BDEu)) >> 1) & 0x7FFFu);
        if (!out && !(ccb_flags & 0x10u))
            out = 0x0400u;
        return out;
    }

    u16 s1 = (ppmp & 0x8000u) ? cfbd : rgb15;
    s32 r1 = (s1 >> 10) & 31, g1 = (s1 >> 5) & 31, b1 = s1 & 31;

    u32 ms = (ppmp >> 13) & 3u;
    s32 mf_r, mf_g, mf_b;
    if (ms == 0) {
        mf_r = mf_g = mf_b = (s32)((ppmp >> 10) & 7u) + 1;
    } else if (ms == 2 || ms == 3) {
        mf_r = mf_g = mf_b = (s32)(amv & 7u) + 1;
    } else {
        mf_r = ((rgb15 >> 12) & 7) + 1;
        mf_g = ((rgb15 >> 7) & 7) + 1;
        mf_b = ((rgb15 >> 2) & 7) + 1;
    }

    static const u8 sf_shift[4] = { 4, 1, 2, 3 };
    u32 sf = (ms == 3) ? 3u : sf_shift[(ppmp >> 8) & 3u];
    r1 = (r1 * mf_r) >> sf;
    g1 = (g1 * mf_g) >> sf;
    b1 = (b1 * mf_b) >> sf;

    u32 s2_sel = (ppmp >> 6) & 3u;
    s32 r2 = 0, g2 = 0, b2 = 0;
    if (s2_sel == 1) {
        s32 av = (s32)((ppmp >> 1) & 31u);
        r2 = g2 = b2 = av;
    } else if (s2_sel == 2) {
        r2 = (cfbd >> 10) & 31; g2 = (cfbd >> 5) & 31; b2 = cfbd & 31;
    } else if (s2_sel == 3) {
        r2 = (rgb15 >> 10) & 31; g2 = (rgb15 >> 5) & 31; b2 = rgb15 & 31;
    }

    s32 r = r1 + r2, g = g1 + g2, b = b1 + b2;
    if (ppmp & 1u) {
        r >>= 1; g >>= 1; b >>= 1;
    }
    if (r > 31) r = 31; else if (r < 0) r = 0;
    if (g > 31) g = 31; else if (g < 0) g = 0;
    if (b > 31) b = 31; else if (b < 0) b = 0;

    u16 out = (u16)((r << 10) | (g << 5) | b);
    if (!out && !(ccb_flags & 0x10u))
        out = 0x0400u;
    return out;
}

static inline void cel_plot_texel(u32 dst_vram, u32 src_vram, s32 clip_w, s32 clip_h,
                                  s32 x0, s32 y0, s32 x1, s32 y1, s32 x2, s32 y2, s32 x3, s32 y3,
                                  u16 rgb15, u16 ppmp, u8 amv, u32 ccb_flags, int simple_1to1)
{
    int need_cfbd = (ppmp != 0x1F00u && ppmp != 0x1F40u &&
                     ((ppmp & 0x8000u) || (((ppmp >> 6) & 3u) == 2u)));

    if (simple_1to1) {
        s32 px = x0 >> 20, py = y0 >> 20;
        if ((u32)px < (u32)clip_w && (u32)py < (u32)clip_h) {
            u16 cfbd = need_cfbd ? vram_read_pix(src_vram, clip_w, px, py) : 0;
            u16 out = cel_shade_pixc(rgb15, cfbd, ppmp, amv, ccb_flags);
            vram_write_pix(dst_vram, clip_w, px, py, out);
        }
        return;
    }

    /* Bounding box of the 4 sub-quad corners in screen pixels (12.20 -> int) */
    s32 min_x = x0, max_x = x0;
    if (x1 < min_x) min_x = x1; else if (x1 > max_x) max_x = x1;
    if (x2 < min_x) min_x = x2; else if (x2 > max_x) max_x = x2;
    if (x3 < min_x) min_x = x3; else if (x3 > max_x) max_x = x3;

    s32 min_y = y0, max_y = y0;
    if (y1 < min_y) min_y = y1; else if (y1 > max_y) max_y = y1;
    if (y2 < min_y) min_y = y2; else if (y2 > max_y) max_y = y2;
    if (y3 < min_y) min_y = y3; else if (y3 > max_y) max_y = y3;

    s32 ix0 = min_x >> 20, ix1 = (max_x - 1) >> 20;
    s32 iy0 = min_y >> 20, iy1 = (max_y - 1) >> 20;
    if (ix1 < ix0) ix1 = ix0;
    if (iy1 < iy0) iy1 = iy0;
    if (ix1 < 0 || iy1 < 0 || ix0 >= clip_w || iy0 >= clip_h)
        return;

    /* Single-pixel footprint fast path */
    if (ix0 == ix1 && iy0 == iy1) {
        u16 cfbd = need_cfbd ? vram_read_pix(src_vram, clip_w, ix0, iy0) : 0;
        u16 out = cel_shade_pixc(rgb15, cfbd, ppmp, amv, ccb_flags);
        vram_write_pix(dst_vram, clip_w, ix0, iy0, out);
        return;
    }

    /* Axis-aligned scaled rectangle fast path */
    if (y0 == y1 && y2 == y3 && x0 == x3 && x1 == x2) {
        if (ix0 < 0) ix0 = 0;
        if (iy0 < 0) iy0 = 0;
        if (ix1 >= clip_w) ix1 = clip_w - 1;
        if (iy1 >= clip_h) iy1 = clip_h - 1;
        u16 pre_out = need_cfbd ? 0 : cel_shade_pixc(rgb15, 0, ppmp, amv, ccb_flags);
        for (s32 py = iy0; py <= iy1; py++) {
            for (s32 px = ix0; px <= ix1; px++) {
                u16 out = pre_out;
                if (need_cfbd)
                    out = cel_shade_pixc(rgb15, vram_read_pix(src_vram, clip_w, px, py), ppmp, amv, ccb_flags);
                vram_write_pix(dst_vram, clip_w, px, py, out);
            }
        }
        return;
    }

    /* Arbitrary rotated / perspective-projected convex quad scanline rasterizer */
    if (iy0 < 0) iy0 = 0;
    if (iy1 >= clip_h) iy1 = clip_h - 1;
    if (iy1 - iy0 > 240) iy1 = iy0 + 240;

    s32 vx[4] = { x0, x1, x2, x3 };
    s32 vy[4] = { y0, y1, y2, y3 };
    u16 pre_out = need_cfbd ? 0 : cel_shade_pixc(rgb15, 0, ppmp, amv, ccb_flags);

    for (s32 py = iy0; py <= iy1; py++) {
        s32 scan_y = (py << 20) + (1 << 19);
        s32 lx = 0x7FFFFFFF, rx = -0x7FFFFFFF;
        for (int e = 0; e < 4; e++) {
            s32 ey0 = vy[e], ey1 = vy[(e + 1) & 3];
            s32 ex0 = vx[e], ex1 = vx[(e + 1) & 3];
            if ((ey0 <= scan_y && ey1 > scan_y) || (ey1 <= scan_y && ey0 > scan_y)) {
                s32 dx = ex1 - ex0, edy = ey1 - ey0, et = scan_y - ey0;
                s32 step_x;
                if (dx > -(64 << 20) && dx < (64 << 20) && et > -(64 << 20) && et < (64 << 20) && (edy >> 11) != 0)
                    step_x = (((dx >> 11) * (et >> 11)) / (edy >> 11)) << 11;
                else
                    step_x = (edy >> 8) ? sdiv64_32((s64)dx * (et >> 8), edy >> 8) : 0;
                s32 ix = ex0 + step_x;
                if (ix < lx) lx = ix;
                if (ix > rx) rx = ix;
            }
        }
        if (lx <= rx) {
            s32 sx0 = lx >> 20, sx1 = rx >> 20;
            if (sx0 < 0) sx0 = 0;
            if (sx1 >= clip_w) sx1 = clip_w - 1;
            for (s32 px = sx0; px <= sx1; px++) {
                u16 out = pre_out;
                if (need_cfbd)
                    out = cel_shade_pixc(rgb15, vram_read_pix(src_vram, clip_w, px, py), ppmp, amv, ccb_flags);
                vram_write_pix(dst_vram, clip_w, px, py, out);
            }
        }
    }
}

static inline int cel_decode_pixel(u32 raw, int bpp, int linear, int rep8, u32 ccb_flags,
                                   u16 *rgb_out, u16 *ppmp_out, u8 *amv_out, u32 pixc)
{
    u16 rgb15 = 0;
    u32 pmode = 0;
    u8 amv = 7;

    if (linear) {
        if (bpp == 16) {
            pmode = (raw >> 15) & 1u;
            rgb15 = (u16)(raw & 0x7FFFu);
        } else if (bpp == 8) {
            u32 r3 = (raw >> 5) & 7u, g3 = (raw >> 2) & 7u, b2 = raw & 3u;
            if (rep8)
                rgb15 = (u16)(((r3 << 2 | r3 >> 1) << 10) | ((g3 << 2 | g3 >> 1) << 5) | (b2 << 3 | b2 << 1 | b2 >> 1));
            else
                rgb15 = (u16)((r3 << 12) | (g3 << 7) | (b2 << 3));
        } else if (bpp == 6) {
            pmode = (raw >> 5) & 1u;
            u32 r = ((raw >> 3) & 3u) * 10u, g = ((raw >> 1) & 3u) * 10u, b = (raw & 1u) * 31u;
            rgb15 = (u16)((r << 10) | (g << 5) | b);
        } else {
            u32 v = (raw & 15u) * 2u;
            rgb15 = (u16)((v << 10) | (v << 5) | v);
        }
    } else {
        u32 pluta = ccb_flags & 0x0Fu;
        u32 idx = 0;
        if (bpp == 1)      idx = ((pluta & 0x0Eu) << 1) | (raw & 1u);
        else if (bpp == 2) idx = ((pluta & 0x0Cu) << 1) | (raw & 3u);
        else if (bpp == 4) idx = ((pluta & 0x08u) << 1) | (raw & 15u);
        else if (bpp == 6) { idx = raw & 31u; pmode = (raw >> 5) & 1u; }
        else if (bpp == 8) { idx = raw & 31u; amv = (u8)((raw >> 5) & 7u); }
        else               { idx = raw & 31u; pmode = (raw >> 15) & 1u; }

        u16 pe = S->plut[idx & 31u];
        rgb15 = pe & 0x7FFFu;
        if (ccb_flags & 0x40u) /* CCB_PLUTPOS */
            pmode = (pe >> 15) & 1u;
    }

    /* Transparency check: 0x0000 is transparent when CCB_BGND (0x20) is clear */
    if (rgb15 == 0 && !(ccb_flags & 0x20u))
        return 0;

    u32 pover = (ccb_flags >> 7) & 3u;
    if (pover == 2u) pmode = 0;
    else if (pover == 3u) pmode = 1;

    *rgb_out = rgb15;
    *ppmp_out = pmode ? (u16)(pixc >> 16) : (u16)(pixc & 0xFFFFu);
    *amv_out = amv;
    return 1;
}

/* Bitstream reader for unpacked / packed CEL rows */
struct cel_bits {
    u32 byte_addr;
    u32 bit_pos;
};

static inline u32 cel_get_bits(struct cel_bits *bs, int nbits)
{
    if (nbits <= 0) return 0;
    u32 cur_word_addr = (bs->byte_addr + (bs->bit_pos >> 3)) & ~3u;
    u32 shift_in_word = (bs->byte_addr * 8u + bs->bit_pos) & 31u;
    bs->bit_pos += (u32)nbits;
    u64 hi = any_r32(cur_word_addr);
    u64 lo = any_r32(cur_word_addr + 4u);
    u64 pair = (hi << 32) | lo;
    return (u32)((pair >> (64u - shift_in_word - (u32)nbits)) & ((1ull << nbits) - 1ull));
}

static void madam_draw_ccb_chain(u32 ccb_addr, u32 dst_vram, u32 src_vram, s32 clip_w, s32 clip_h)
{
    static const u8 bpp_tab[8] = { 0, 1, 2, 4, 6, 8, 16, 0 };

    for (int chain_step = 0; chain_step < 8192 && ccb_addr && ccb_addr < 0x03100000u; chain_step++) {
        u32 flags    = any_r32(ccb_addr + 0x00u);
        u32 next_raw = any_r32(ccb_addr + 0x04u);
        u32 src_raw  = any_r32(ccb_addr + 0x08u);
        u32 plut_raw = any_r32(ccb_addr + 0x0Cu);

        u32 next_addr = (flags & 0x20000000u) ? next_raw : (next_raw ? (ccb_addr + 8u + (u32)(s32)next_raw) : 0u);
        u32 src_addr  = (flags & 0x10000000u) ? src_raw  : (ccb_addr + 12u + (u32)(s32)src_raw);
        u32 plut_addr = (flags & 0x08000000u) ? plut_raw : (ccb_addr + 16u + (u32)(s32)plut_raw);

        if (!(flags & 0x80000000u)) { /* !CCB_SKIP */
            u32 ptr = ccb_addr + 0x10u;
            if (flags & 0x00200000u) { /* CCB_YOXY */
                S->ccb_regs[0] = any_r32(ptr);
                S->ccb_regs[1] = any_r32(ptr + 4u);
                ptr += 8u;
            }
            if (flags & 0x04000000u) { /* CCB_LDSIZE */
                S->ccb_regs[2] = any_r32(ptr);
                S->ccb_regs[3] = any_r32(ptr + 4u);
                S->ccb_regs[4] = any_r32(ptr + 8u);
                S->ccb_regs[5] = any_r32(ptr + 12u);
                ptr += 16u;
            }
            if (flags & 0x02000000u) { /* CCB_LDPRS */
                S->ccb_regs[6] = any_r32(ptr);
                S->ccb_regs[7] = any_r32(ptr + 4u);
                ptr += 8u;
            }
            if (flags & 0x01000000u) { /* CCB_LDPPMP */
                S->ccb_regs[8] = any_r32(ptr);
                ptr += 4u;
            }

            int packed = (flags & 0x00000200u) != 0;
            u32 pre0, pre1 = 0;
            u32 data_addr = src_addr;
            if (flags & 0x00400000u) { /* CCB_CCBPRE */
                pre0 = any_r32(ptr);
                ptr += 4u;
                if (!packed)
                    pre1 = any_r32(ptr);
            } else {
                pre0 = any_r32(data_addr);
                data_addr += 4u;
                if (!packed) {
                    pre1 = any_r32(data_addr);
                    data_addr += 4u;
                }
            }

            if ((flags & 0x00800000u) && plut_addr) { /* CCB_LDPLUT */
                for (u32 i = 0; i < 32u; i++)
                    S->plut[i] = any_r16(plut_addr + i * 2u);
            }

            int bpp = bpp_tab[pre0 & 7u];
            u32 vcnt = ((pre0 >> 6) & 0x3FFu) + 1u;
            int linear = (pre0 & 0x80000010u) != 0;
            int rep8   = (pre0 & 0x00000008u) != 0;
            u32 skipx  = (pre0 >> 24) & 0x0Fu;

            s32 xpos = (s32)S->ccb_regs[0] << 4; /* 16.16 -> 12.20 */
            s32 ypos = (s32)S->ccb_regs[1] << 4;
            s32 hdx  = (s32)S->ccb_regs[2];      /* 12.20 */
            s32 hdy  = (s32)S->ccb_regs[3];      /* 12.20 */
            s32 vdx  = (s32)S->ccb_regs[4] << 4; /* 16.16 -> 12.20 */
            s32 vdy  = (s32)S->ccb_regs[5] << 4;
            s32 hddx = (s32)S->ccb_regs[6];      /* 12.20 */
            s32 hddy = (s32)S->ccb_regs[7];      /* 12.20 */
            u32 pixc = S->ccb_regs[8];

            /* Backface winding check (CCB_ACW 0x40000 / CCB_ACCW 0x20000) */
            int cull = 0;
            if ((flags & 0x00060000u) != 0x00060000u) {
                if ((flags & 0x00060000u) == 0) {
                    cull = 1;
                } else {
                    s64 cross = (s64)(hdx >> 6) * (s64)(vdy >> 6) - (s64)(hdy >> 6) * (s64)(vdx >> 6);
                    if (cross > 0 && !(flags & 0x00040000u)) cull = 1;
                    if (cross < 0 && !(flags & 0x00020000u)) cull = 1;
                }
            }

            if (bpp > 0 && !cull && vcnt <= 1024u) {
                int simple_1to1 = (hdy == 0 && vdx == 0 && hddx == 0 && hddy == 0 &&
                                   hdx > 0 && hdx <= (1 << 20) && vdy > 0 && vdy <= (1 << 20));

                if (!packed) {
                    u32 woffset = (bpp < 8) ? (((pre1 >> 24) & 0xFFu) + 2u) : (((pre1 >> 16) & 0x3FFu) + 2u);
                    u32 hpcnt = (pre1 & 0x7FFu) + 1u;
                    int lrform = (pre1 & 0x0800u) != 0 && bpp == 16;

                    if (lrform) {
                        /* VRAM frame-buffer interleaved source (2 rows per word strip) */
                        u32 pairs = (vcnt + 1u) >> 1;
                        u32 row_addr = data_addr;
                        for (u32 py_pair = 0; py_pair < pairs; py_pair++) {
                            for (u32 sub = 0; sub < 2u; sub++) {
                                u32 sy = py_pair * 2u + sub;
                                if (sy >= vcnt) break;
                                s32 rx0 = xpos + (s32)sy * vdx, ry0 = ypos + (s32)sy * vdy;
                                s32 rx1 = rx0 + vdx, ry1 = ry0 + vdy;
                                s32 chdx0 = hdx + (s32)sy * hddx, chdy0 = hdy + (s32)sy * hddy;
                                s32 chdx1 = chdx0 + hddx, chdy1 = chdy0 + hddy;
                                for (u32 sx = skipx; sx < hpcnt; sx++) {
                                    u32 w = any_r32(row_addr + sx * 4u);
                                    u32 raw = sub ? (w & 0xFFFFu) : (w >> 16);
                                    u16 rgb15, ppmp; u8 amv;
                                    if (cel_decode_pixel(raw, 16, linear, rep8, flags, &rgb15, &ppmp, &amv, pixc)) {
                                        s32 ux = (s32)(sx - skipx);
                                        s32 x0 = rx0 + ux * chdx0, y0 = ry0 + ux * chdy0;
                                        s32 x3 = rx1 + ux * chdx1, y3 = ry1 + ux * chdy1;
                                        cel_plot_texel(dst_vram, src_vram, clip_w, clip_h,
                                                       x0, y0, x0 + chdx0, y0 + chdy0,
                                                       x3 + chdx1, y3 + chdy1, x3, y3,
                                                       rgb15, ppmp, amv, flags, simple_1to1);
                                    }
                                }
                            }
                            row_addr += woffset * 4u;
                        }
                    } else {
                        u32 row_addr = data_addr;
                        for (u32 sy = 0; sy < vcnt; sy++) {
                            s32 rx0 = xpos + (s32)sy * vdx, ry0 = ypos + (s32)sy * vdy;
                            s32 rx1 = rx0 + vdx, ry1 = ry0 + vdy;
                            s32 chdx0 = hdx + (s32)sy * hddx, chdy0 = hdy + (s32)sy * hddy;
                            s32 chdx1 = chdx0 + hddx, chdy1 = chdy0 + hddy;
                            struct cel_bits bs;
                            bs.byte_addr = row_addr;
                            bs.bit_pos = skipx * (u32)bpp;
                            for (u32 sx = skipx; sx < hpcnt; sx++) {
                                u32 raw = cel_get_bits(&bs, bpp);
                                u16 rgb15, ppmp; u8 amv;
                                if (cel_decode_pixel(raw, bpp, linear, rep8, flags, &rgb15, &ppmp, &amv, pixc)) {
                                    s32 ux = (s32)(sx - skipx);
                                    s32 x0 = rx0 + ux * chdx0, y0 = ry0 + ux * chdy0;
                                    s32 x3 = rx1 + ux * chdx1, y3 = ry1 + ux * chdy1;
                                    cel_plot_texel(dst_vram, src_vram, clip_w, clip_h,
                                                   x0, y0, x0 + chdx0, y0 + chdy0,
                                                   x3 + chdx1, y3 + chdy1, x3, y3,
                                                   rgb15, ppmp, amv, flags, simple_1to1);
                                }
                            }
                            row_addr += woffset * 4u;
                        }
                    }
                } else {
                    /* RLE Packed CEL:
                       bpp < 8: 8-bit woffset in [31:24], packets start at bit 8
                       bpp >= 8: 6 pad bits + 10-bit woffset in [25:16], packets start at bit 16 */
                    u32 row_addr = data_addr;
                    for (u32 sy = 0; sy < vcnt; sy++) {
                        u32 hdr = any_r32(row_addr);
                        u32 woffset = (bpp < 8) ? (((hdr >> 24) & 0xFFu) + 2u) : (((hdr >> 16) & 0x3FFu) + 2u);
                        u32 max_bits = woffset * 32u;
                        struct cel_bits bs;
                        bs.byte_addr = row_addr;
                        bs.bit_pos = (bpp < 8) ? 8u : 16u;

                        s32 rx0 = xpos + (s32)sy * vdx, ry0 = ypos + (s32)sy * vdy;
                        s32 rx1 = rx0 + vdx, ry1 = ry0 + vdy;
                        s32 chdx0 = hdx + (s32)sy * hddx, chdy0 = hdy + (s32)sy * hddy;
                        s32 chdx1 = chdx0 + hddx, chdy1 = chdy0 + hddy;
                        s32 ux = 0;

                        while (bs.bit_pos + 2u <= max_bits && ux < 2048) {
                            u32 ptype = cel_get_bits(&bs, 2);
                            if (ptype == 0) /* PACK_EOL */
                                break;
                            if (bs.bit_pos + 6u > max_bits)
                                break;
                            u32 count = cel_get_bits(&bs, 6) + 1u;
                            if (ptype == 2u) { /* PACK_TRANSPARENT */
                                ux += (s32)count;
                            } else if (ptype == 1u) { /* PACK_LITERAL */
                                for (u32 k = 0; k < count && bs.bit_pos + (u32)bpp <= max_bits; k++, ux++) {
                                    u32 raw = cel_get_bits(&bs, bpp);
                                    u16 rgb15, ppmp; u8 amv;
                                    if (cel_decode_pixel(raw, bpp, linear, rep8, flags, &rgb15, &ppmp, &amv, pixc)) {
                                        s32 x0 = rx0 + ux * chdx0, y0 = ry0 + ux * chdy0;
                                        s32 x3 = rx1 + ux * chdx1, y3 = ry1 + ux * chdy1;
                                        cel_plot_texel(dst_vram, src_vram, clip_w, clip_h,
                                                       x0, y0, x0 + chdx0, y0 + chdy0,
                                                       x3 + chdx1, y3 + chdy1, x3, y3,
                                                       rgb15, ppmp, amv, flags, simple_1to1);
                                    }
                                }
                            } else { /* PACK_PACKED */
                                if (bs.bit_pos + (u32)bpp > max_bits)
                                    break;
                                u32 raw = cel_get_bits(&bs, bpp);
                                u16 rgb15, ppmp; u8 amv;
                                if (cel_decode_pixel(raw, bpp, linear, rep8, flags, &rgb15, &ppmp, &amv, pixc)) {
                                    for (u32 k = 0; k < count; k++, ux++) {
                                        s32 x0 = rx0 + ux * chdx0, y0 = ry0 + ux * chdy0;
                                        s32 x3 = rx1 + ux * chdx1, y3 = ry1 + ux * chdy1;
                                        cel_plot_texel(dst_vram, src_vram, clip_w, clip_h,
                                                       x0, y0, x0 + chdx0, y0 + chdy0,
                                                       x3 + chdx1, y3 + chdy1, x3, y3,
                                                       rgb15, ppmp, amv, flags, simple_1to1);
                                    }
                                } else {
                                    ux += (s32)count;
                                }
                            }
                        }
                        row_addr += woffset * 4u;
                    }
                }
            }
        }

        if ((flags & 0x40000000u) || !next_addr) /* CCB_LAST */
            break;
        ccb_addr = next_addr;
    }
}

/* --- Disc & Opera FS Reader --- */
static int disc_read_sector(u32 lba, u8 *dst2048)
{
    if (!S->cd || !S->cd->read_2048)
        return -1;
    if (S->sec_cached_lba == lba) {
        for (int i = 0; i < 2048; i++) dst2048[i] = S->sec_buf[i];
        return 0;
    }
    if (S->cd->read_2048(lba, S->sec_buf) < 0)
        return -1;
    S->sec_cached_lba = lba;
    for (int i = 0; i < 2048; i++) dst2048[i] = S->sec_buf[i];
    return 0;
}

static u32 be32_buf(const u8 *p)
{
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

static int str_eq_ci(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a++, cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb + 32);
        if (ca != cb) return 0;
    }
    return *a == 0 && *b == 0;
}

/* Look up a single path component in an Opera FS directory starting at dir_lba */
static int operafs_lookup_one(u32 dir_lba, const char *comp, u32 *out_lba, u32 *out_bytes, int *out_isdir)
{
    u8 blk[2048];
    for (u32 cur_rel = 0; cur_rel < 64u; ) {
        if (disc_read_sector(dir_lba + cur_rel, blk) < 0)
            return -1;
        s32 next_rel = (s32)be32_buf(blk + 0);
        u32 first_free = be32_buf(blk + 12);
        u32 off = be32_buf(blk + 16);
        if (first_free > 2048u) first_free = 2048u;
        while (off + 72u <= first_free) {
            u32 flags = be32_buf(blk + off);
            u32 byte_cnt = be32_buf(blk + off + 16);
            u32 last_copy = be32_buf(blk + off + 64);
            u32 lba0 = be32_buf(blk + off + 68);
            char ename[33];
            for (int i = 0; i < 32; i++) ename[i] = (char)blk[off + 32 + i];
            ename[32] = 0;
            if (str_eq_ci(ename, comp)) {
                *out_lba = lba0;
                *out_bytes = byte_cnt;
                *out_isdir = ((flags & 7u) == 7u) ? 1 : 0;
                return 0;
            }
            if (flags & 0xC0000000u)
                break;
            if (last_copy > 16u)
                break;
            off += 72u + 4u * last_copy;
        }
        if (next_rel <= 0)
            break;
        cur_rel = (u32)next_rel;
    }
    return -1;
}

static int operafs_resolve(u32 base_dir_lba, const char *path, u32 *out_lba, u32 *out_bytes, int *out_isdir)
{
    u32 cur_lba = base_dir_lba ? base_dir_lba : S->fs_root_lba;
    int is_dir = 1;
    u32 byte_sz = 2048u;

    const char *p = path;
    /* Strip leading '/', '$boot/', '/cd-rom/', '^/' */
    if (*p == '/' || *p == '\\') {
        cur_lba = S->fs_root_lba;
        p++;
    } else if (*p == '$' || *p == '^') {
        cur_lba = S->fs_root_lba;
        while (*p && *p != '/' && *p != '\\') p++;
        if (*p) p++;
    }

    while (*p) {
        while (*p == '/' || *p == '\\') p++;
        if (!*p) break;
        char comp[64];
        int n = 0;
        while (*p && *p != '/' && *p != '\\' && n < 63)
            comp[n++] = *p++;
        comp[n] = 0;
        if (comp[0] == '.' && comp[1] == 0)
            continue;
        if (str_eq_ci(comp, "cd-rom") && cur_lba == S->fs_root_lba)
            continue;
        if (operafs_lookup_one(cur_lba, comp, &cur_lba, &byte_sz, &is_dir) < 0)
            return -1;
    }
    *out_lba = cur_lba;
    *out_bytes = byte_sz;
    *out_isdir = is_dir;
    return 0;
}

static int operafs_read_to_dram(u32 start_lba, u32 file_offset, u32 dram_dst, u32 count)
{
    u8 blk[2048];
    u32 done = 0;
    while (done < count) {
        u32 sec = start_lba + ((file_offset + done) >> 11);
        u32 in_sec = (file_offset + done) & 2047u;
        u32 chunk = 2048u - in_sec;
        if (chunk > count - done)
            chunk = count - done;
        if (disc_read_sector(sec, blk) < 0)
            return done ? (int)done : -1;
        mem_write_bytes(dram_dst + done, blk + in_sec, chunk);
        done += chunk;
    }
    return (int)done;
}

/* --- Portfolio HLE Kernel / Memory / Item / Folio Manager --- */
static void hle_list_init(u32 list_addr)
{
    for (u32 i = 0; i < 32u; i += 4u) dram_w32(list_addr + i, 0);
    dram_w8(list_addr + 8u, 1); /* NST_KERNEL */
    dram_w8(list_addr + 9u, 2); /* LISTNODE */
    dram_w32(list_addr + 12u, 32u);
    dram_w32(list_addr + 0x14u, list_addr + 0x18u); /* head.flink = &head.blink */
    dram_w32(list_addr + 0x18u, 0u);
    dram_w32(list_addr + 0x1Cu, list_addr + 0x14u); /* tail.blink = &head.flink */
}

static void hle_list_add_tail(u32 list_addr, u32 node_addr)
{
    u32 prev = dram_r32(list_addr + 0x1Cu);
    dram_w32(node_addr + 0u, list_addr + 0x18u);
    dram_w32(node_addr + 4u, prev);
    dram_w32(prev + 0u, node_addr);
    dram_w32(list_addr + 0x1Cu, node_addr);
}

static u32 hle_list_rem_head(u32 list_addr)
{
    u32 first = dram_r32(list_addr + 0x14u);
    if (first == list_addr + 0x18u || !first)
        return 0;
    u32 next = dram_r32(first + 0u);
    dram_w32(list_addr + 0x14u, next);
    dram_w32(next + 4u, list_addr + 0x14u);
    return first;
}

static void hle_sync_mem_bitmaps(void)
{
    /* Update DRAM (512 x 4KB pages) & VRAM (512 x 2KB pages) free bitmaps for AvailMem() */
    u32 lo_page = (S->dram_heap_lo + 4095u) >> 12;
    u32 hi_page = S->dram_heap_hi >> 12;
    for (u32 w = 0; w < 16u; w++) {
        u32 mask = 0;
        for (u32 b = 0; b < 32u; b++) {
            u32 pg = w * 32u + b;
            if (pg >= lo_page && pg < hi_page)
                mask |= (1u << b);
        }
        dram_w32(HLE_DRAM_BITS + w * 4u, mask);
    }
    u32 vlo = (S->vram_heap_lo - 0x00200000u + 2047u) >> 11;
    for (u32 w = 0; w < 16u; w++) {
        u32 mask = 0;
        for (u32 b = 0; b < 32u; b++) {
            u32 pg = w * 32u + b;
            if (pg >= vlo && pg < 512u)
                mask |= (1u << b);
        }
        dram_w32(HLE_VRAM_BITS + w * 4u, mask);
    }
}

static u32 hle_alloc_mem(s32 size, u32 typebits)
{
    if (size <= 0) return 0;
    int track = (typebits & 0x00400000u) != 0; /* MEMTYPE_TRACKSIZE */
    u32 total = (u32)size + (track ? 4u : 0u);
    u32 addr = 0;

    if (typebits & 0x00010000u) { /* MEMTYPE_VRAM */
        u32 align = (typebits & 0x06000000u) ? 2048u : 16u;
        u32 base = (S->vram_heap_lo + (track ? 4u : 0u) + (align - 1u)) & ~(align - 1u);
        if (track) base -= 4u;
        if (base + total > 0x00300000u)
            return 0;
        addr = base;
        S->vram_heap_lo = (base + total + 15u) & ~15u;
        if (track) {
            vram_w32(addr - 0x00200000u, (u32)size);
            addr += 4u;
        }
        if (typebits & 0x00000100u) {
            u8 fill = (u8)(typebits & 0xFFu);
            for (s32 i = 0; i < size; i++)
                vram_w8((addr - 0x00200000u) + (u32)i, fill);
        }
    } else {
        u32 align = (typebits & 0x06000000u) ? 4096u : 16u;
        if (typebits & 0x00004000u) { /* MEMTYPE_FROMTOP */
            u32 top = (S->dram_heap_hi - (u32)size) & ~(align - 1u);
            u32 raw = track ? (top - 4u) : top;
            if (raw < S->dram_heap_lo)
                return 0;
            S->dram_heap_hi = raw & ~15u;
            addr = top;
            if (track) dram_w32(addr - 4u, (u32)size);
        } else {
            u32 base = (S->dram_heap_lo + (track ? 4u : 0u) + (align - 1u)) & ~(align - 1u);
            if (track) base -= 4u;
            if (base + total > S->dram_heap_hi)
                return 0;
            addr = base;
            S->dram_heap_lo = (base + total + 15u) & ~15u;
            if (track) {
                dram_w32(addr, (u32)size);
                addr += 4u;
            }
        }
        if (typebits & 0x00000100u) {
            u8 fill = (u8)(typebits & 0xFFu);
            for (s32 i = 0; i < size; i++)
                dram_w8(addr + (u32)i, fill);
        }
    }
    hle_sync_mem_bitmaps();
    return addr;
}

static u32 hle_alloc_item(u8 kind, u8 subsys, u8 ntype, u32 node_size, const char *name, u32 fixed_addr)
{
    int slot = -1;
    for (int i = 1; i < MAX_ITEMS; i++) {
        if (S->items[i].kind == IK_NONE) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return (u32)-1;

    u32 item_id = 0x00010000u | (u32)slot;
    if (node_size < 0x24u) node_size = 0x24u;
    node_size = (node_size + 15u) & ~15u;

    u32 addr = fixed_addr;
    if (!addr) {
        if (S->item_arena_ptr + node_size <= 0x001F8000u) {
            addr = S->item_arena_ptr;
            S->item_arena_ptr += node_size;
        } else {
            addr = hle_alloc_mem((s32)node_size, 0x100u);
        }
    }
    if (!addr) return (u32)-1;

    for (u32 i = 0; i < node_size; i += 4u)
        dram_w32(addr + i, 0);

    struct hle_item *it = &S->items[slot];
    it->kind = kind;
    it->subsys = subsys;
    it->ntype = ntype;
    it->dev_type = 0;
    it->node_addr = addr;
    it->aux0 = it->aux1 = it->aux2 = 0;

    int ni = 0;
    if (name) {
        for (; name[ni] && ni < 31; ni++) it->name[ni] = name[ni];
    }
    it->name[ni] = 0;

    /* Populate standard ItemNode header (0x24 bytes) */
    dram_w8(addr + 0x08u, subsys);
    dram_w8(addr + 0x09u, ntype);
    dram_w8(addr + 0x0Au, 100);
    dram_w8(addr + 0x0Bu, 0x90u); /* NODE_NAMEVALID | NODE_ITEMVALID */
    dram_w32(addr + 0x0Cu, node_size);
    if (name && *name) {
        u32 saddr = S->item_arena_ptr;
        if (saddr + 32u <= 0x001F8000u) {
            S->item_arena_ptr = mem_write_str(saddr, name);
            dram_w32(addr + 0x10u, saddr);
        }
    }
    dram_w8(addr + 0x14u, 2);
    dram_w8(addr + 0x15u, 5);
    dram_w32(addr + 0x18u, item_id);
    dram_w32(addr + 0x1Cu, 0x00010002u); /* owned by main task */
    return item_id;
}

static struct hle_item *hle_get_item(u32 item_id)
{
    u32 slot = item_id & 0xFFFu;
    if (slot == 0 || slot >= MAX_ITEMS) return 0;
    if (S->items[slot].kind == IK_NONE) return 0;
    return &S->items[slot];
}

static void hle_install_folio_vecs(u32 folio_base, u32 folio_id, u32 stub_area)
{
    /* Install 64 negative function pointers at folio_base[-1 .. -64]
       pointing to 2-instruction ARM60 stubs:
         SWI (0x0E0000 | (folio_id << 8) | vec_idx)
         MOV PC, LR */
    for (u32 idx = 1; idx <= 64u; idx++) {
        u32 stub = stub_area + (idx - 1u) * 8u;
        u32 swi_num = 0x0E0000u | (folio_id << 8) | idx;
        dram_w32(stub + 0u, 0xEF000000u | swi_num); /* SWI #swi_num */
        dram_w32(stub + 4u, 0xE1A0F00Eu);           /* MOV PC, LR */
        dram_w32(folio_base - idx * 4u, stub);
    }
}

static void hle_init_portfolio(u32 entry_pc, u32 image_base, u32 image_end)
{
    S->dram_heap_lo = (image_end + 4095u) & ~4095u;
    if (S->dram_heap_lo < 0x00040000u)
        S->dram_heap_lo = 0x00040000u;
    S->dram_heap_hi = 0x001D8000u; /* Leave 32 KB stack 0x1D8000..0x1E0000 */
    S->vram_heap_lo = 0x00200000u;
    S->item_arena_ptr = HLE_ITEM_ARENA;

    for (int i = 0; i < MAX_ITEMS; i++)
        S->items[i].kind = IK_NONE;

    /* Install Folio negative-vector ARM60 stubs */
    hle_install_folio_vecs(HLE_KERNEL, 1u, HLE_STUBS + 0x0000u);
    hle_install_folio_vecs(HLE_GRAF,   2u, HLE_STUBS + 0x0200u);
    hle_install_folio_vecs(HLE_FILE,   3u, HLE_STUBS + 0x0400u);
    hle_install_folio_vecs(HLE_AUDIO,  4u, HLE_STUBS + 0x0600u);
    hle_install_folio_vecs(HLE_MATH,   5u, HLE_STUBS + 0x0800u);

    /* Create Folios: slot 1=Kernel, 2=Task, 3=Graphics, 4=File, 5=Audio, 6=Operamath */
    u32 kb_item   = hle_alloc_item(IK_FOLIO, 1, 4, 0x100u, "Kernel", HLE_KERNEL);
    u32 task_item = hle_alloc_item(IK_TASK,  1, 5, 0x100u, "LaunchMe", HLE_TASK);
    u32 gf_item   = hle_alloc_item(IK_FOLIO, 1, 4, 0x140u, "Graphics", HLE_GRAF);
    u32 ff_item   = hle_alloc_item(IK_FOLIO, 1, 4, 0x100u, "File", HLE_FILE);
    u32 af_item   = hle_alloc_item(IK_FOLIO, 1, 4, 0x100u, "audio", HLE_AUDIO);
    u32 mf_item   = hle_alloc_item(IK_FOLIO, 1, 4, 0x100u, "Operamath", HLE_MATH);
    (void)kb_item; (void)gf_item; (void)ff_item; (void)af_item; (void)mf_item;

    /* Create built-in Devices: SPORT, timer, cdrom, mac */
    u32 sport_dev = hle_alloc_item(IK_DEVICE, 1, 15, 0x40u, "SPORT", 0);
    S->items[sport_dev & 0xFFFu].dev_type = 1;
    u32 timer_dev = hle_alloc_item(IK_DEVICE, 1, 15, 0x40u, "timer", 0);
    S->items[timer_dev & 0xFFFu].dev_type = 2;
    u32 cdrom_dev = hle_alloc_item(IK_DEVICE, 1, 15, 0x40u, "cd-rom", 0);
    S->items[cdrom_dev & 0xFFFu].dev_type = 3;
    u32 mac_dev   = hle_alloc_item(IK_DEVICE, 1, 15, 0x40u, "mac", 0);
    S->items[mac_dev & 0xFFFu].dev_type = 4;

    /* EventBroker named message port */
    S->eb_port_item = hle_alloc_item(IK_MSGPORT, 1, 10, 0x50u, "eventbroker", 0);
    hle_list_init(S->items[S->eb_port_item & 0xFFFu].node_addr + 0x28u);
    S->eb_listener_port = 0;
    S->eb_event_msg = hle_alloc_item(IK_MSG, 1, 9, 0x40u, "eb_ev", 0);
    S->eb_msg_in_flight = 0;

    /* Populate MemHdr list for AvailMem() */
    hle_list_init(HLE_MEMHDR_LIST);
    hle_list_init(HLE_TASK_MLIST);

    for (u32 i = 0; i < 0x80u; i += 4u) {
        dram_w32(HLE_MEMHDR_DRAM + i, 0);
        dram_w32(HLE_MEMHDR_VRAM + i, 0);
    }
    dram_w32(HLE_MEMHDR_DRAM + 0x14u, 0x000E0000u); /* MEMTYPE_DRAM | CEL | DMA | AUDIO */
    dram_w32(HLE_MEMHDR_DRAM + 0x18u, 4096u);
    dram_w32(HLE_MEMHDR_DRAM + 0x1Cu, 0xFFFFF000u);
    dram_w32(HLE_MEMHDR_DRAM + 0x20u, 2048u);
    dram_w32(HLE_MEMHDR_DRAM + 0x24u, 0xFFFFF800u);
    dram_w32(HLE_MEMHDR_DRAM + 0x28u, HLE_DRAM_BITS);
    dram_w32(HLE_MEMHDR_DRAM + 0x2Cu, 0x00000000u);
    dram_w32(HLE_MEMHDR_DRAM + 0x30u, DRAM_SIZE);
    dram_w8(HLE_MEMHDR_DRAM  + 0x34u, 16u);
    dram_w8(HLE_MEMHDR_DRAM  + 0x35u, 12u);
    dram_w8(HLE_MEMHDR_DRAM  + 0x36u, 11u);
    hle_list_add_tail(HLE_MEMHDR_LIST, HLE_MEMHDR_DRAM);

    dram_w32(HLE_MEMHDR_VRAM + 0x14u, 0x30070000u); /* MEMTYPE_VRAM | CEL | DMA | BANK1 | BANK2 */
    dram_w32(HLE_MEMHDR_VRAM + 0x18u, 2048u);
    dram_w32(HLE_MEMHDR_VRAM + 0x1Cu, 0xFFFFF800u);
    dram_w32(HLE_MEMHDR_VRAM + 0x20u, 2048u);
    dram_w32(HLE_MEMHDR_VRAM + 0x24u, 0xFFFFF800u);
    dram_w32(HLE_MEMHDR_VRAM + 0x28u, HLE_VRAM_BITS);
    dram_w32(HLE_MEMHDR_VRAM + 0x2Cu, 0x00200000u);
    dram_w32(HLE_MEMHDR_VRAM + 0x30u, 0x00300000u);
    dram_w8(HLE_MEMHDR_VRAM  + 0x34u, 16u);
    dram_w8(HLE_MEMHDR_VRAM  + 0x35u, 11u);
    dram_w8(HLE_MEMHDR_VRAM  + 0x36u, 11u);
    hle_list_add_tail(HLE_MEMHDR_LIST, HLE_MEMHDR_VRAM);
    hle_sync_mem_bitmaps();

    /* Populate KernelBase & CurrentTask fields */
    dram_w32(HLE_KERNEL + 0x78u, HLE_MEMHDR_LIST); /* kb_MemHdrList */
    dram_w32(HLE_KERNEL + 0x98u, HLE_TASK);        /* kb_CurrentTask */
    dram_w32(HLE_KERNEL + 0xACu, 0x00008000u);     /* kb_CPUFlags = KB_NODBGR */
    dram_w8(HLE_KERNEL  + 0xE8u, 2);               /* kb_MadamRev */
    dram_w8(HLE_KERNEL  + 0xE9u, 2);               /* kb_ClioRev */

    dram_w32(HLE_TASK + 0x18u, task_item);
    dram_w32(HLE_TASK + 0x38u, 0x000000FFu);       /* t_AllocatedSigs (user bits 8..30 free) */
    dram_w32(HLE_TASK + 0x3Cu, 0x001D8000u);       /* t_StackBase */
    dram_w32(HLE_TASK + 0x40u, 0x00007000u);       /* t_StackSize (28 KB) */
    dram_w32(HLE_TASK + 0xA8u, HLE_TASK_MLIST);    /* t_FreeMemoryLists */

    /* Populate GrafFolio & NTSC DisplayInfo */
    u32 zero_pg = hle_alloc_mem(2048, 0x02010100u); /* Zero VRAM page */
    dram_w32(HLE_GRAF + 0x74u, 0);                 /* gf_VBLNumber */
    dram_w32(HLE_GRAF + 0x78u, zero_pg);           /* gf_ZeroPage */
    dram_w32(HLE_GRAF + 0x7Cu, zero_pg);           /* gf_VIRSPage */
    dram_w32(HLE_GRAF + 0x80u, 2048u);             /* gf_VRAMPageSize */
    dram_w32(HLE_GRAF + 0x84u, 320u);              /* gf_DefaultDisplayWidth */
    dram_w32(HLE_GRAF + 0x88u, 240u);              /* gf_DefaultDisplayHeight */
    dram_w32(HLE_GRAF + 0xB4u, 16683u);            /* gf_VBLTime */
    dram_w32(HLE_GRAF + 0xB8u, 60u);               /* gf_VBLFreq */
    dram_w32(HLE_GRAF + 0x120u, 1u);               /* gf_DefaultDisplayType = DI_TYPE_NTSC */
    dram_w32(HLE_GRAF + 0x124u, 2u);               /* gf_DisplayTypeMask */

    hle_list_init(HLE_GRAF + 0x100u);              /* gf_DisplayInfoList */
    for (u32 i = 0; i < 0x80u; i += 4u) dram_w32(HLE_DISPINFO + i, 0);
    dram_w8(HLE_DISPINFO + 8u, 2);
    dram_w8(HLE_DISPINFO + 9u, 5);
    dram_w32(HLE_DISPINFO + 12u, 0x80u);
    u32 tp = HLE_DISPINFO + 0x14u;
    dram_w32(tp +  0u, 1u); dram_w32(tp +  4u, 1u);       /* DI_TYPE = DI_TYPE_NTSC */
    dram_w32(tp +  8u, 2u); dram_w32(tp + 12u, 320u);     /* DI_WIDTH = 320 */
    dram_w32(tp + 16u, 3u); dram_w32(tp + 20u, 240u);     /* DI_HEIGHT = 240 */
    dram_w32(tp + 24u, 4u); dram_w32(tp + 28u, 16683u);   /* DI_FIELDTIME */
    dram_w32(tp + 32u, 5u); dram_w32(tp + 36u, 60u);      /* DI_FIELDFREQ */
    dram_w32(tp + 40u, 6u); dram_w32(tp + 44u, 0x10000u); /* DI_ASPECT */
    dram_w32(tp + 48u, 7u); dram_w32(tp + 52u, 1u);       /* DI_ASPECTW */
    dram_w32(tp + 56u, 8u); dram_w32(tp + 60u, 1u);       /* DI_ASPECTH */
    dram_w32(tp + 64u, 0u); dram_w32(tp + 68u, 0u);       /* DI_END */
    hle_list_add_tail(HLE_GRAF + 0x100u, HLE_DISPINFO);

    /* Set up argv[0] = "LaunchMe" and initial ARM60 registers for AIF entry */
    u32 arg_str = mem_write_str(HLE_STRINGS, "LaunchMe");
    u32 argv_ptr = arg_str;
    dram_w32(argv_ptr + 0u, HLE_STRINGS);
    dram_w32(argv_ptr + 4u, 0u);

    for (int i = 0; i < 16; i++) S->r[i] = 0;
    S->r[0]  = 1u;              /* argc */
    S->r[1]  = argv_ptr;        /* argv */
    S->r[5]  = 1u;              /* AIF R5 = argc */
    S->r[6]  = argv_ptr;        /* AIF R6 = argv */
    S->r[7]  = HLE_KERNEL;      /* AIF R7 = KernelBase */
    S->r[9]  = image_base;      /* SB base */
    S->r[10] = 0x001D8100u;     /* SL stack limit (below SP = 0x1DF000!) */
    S->r[13] = HLE_USER_SP;
    S->r[14] = HLE_STUBS + 0x0F00u;
    dram_w32(S->r[14], 0xEF000011u); /* Exit SWI trampoline */
    S->r[15] = entry_pc;
    S->cpsr  = MODE_SVC;
    S->r13_bank[3] = HLE_USER_SP;
}

static void hle_deliver_pad_event(void)
{
    if (!S->eb_listener_port || S->eb_msg_in_flight)
        return;
    struct hle_item *mp = hle_get_item(S->eb_listener_port);
    struct hle_item *msg = hle_get_item(S->eb_event_msg);
    if (!mp || !msg)
        return;

    /* Build EB_EventRecord (flavor = 3) + ControlButtonUpdate EventFrame (number = 3, pod = 1) */
    u32 ev = HLE_EVBUF;
    dram_w32(ev + 0x00u, 3u);                   /* EB_EventRecord */
    dram_w32(ev + 0x04u, 0x20u);                /* ef_ByteCount = 32 bytes */
    dram_w32(ev + 0x08u, 0u);                   /* ef_SystemID */
    dram_w32(ev + 0x0Cu, S->frame_count);       /* ef_SystemTimeStamp */
    dram_w32(ev + 0x10u, 0u);                   /* ef_Submitter */
    dram_w8(ev  + 0x14u, 3u);                   /* ef_EventNumber = ControlButtonUpdate */
    dram_w8(ev  + 0x15u, 1u);                   /* ef_PodNumber = 1 */
    dram_w8(ev  + 0x16u, 1u);                   /* ef_PodPosition = 1 */
    dram_w8(ev  + 0x17u, 1u);                   /* ef_GenericPosition = 1 (padNumber 1!) */
    dram_w8(ev  + 0x18u, 1u);                   /* ef_Trigger */
    dram_w8(ev  + 0x19u, 0u);
    dram_w8(ev  + 0x1Au, 0u);
    dram_w8(ev  + 0x1Bu, 0u);
    dram_w32(ev + 0x1Cu, 0u);                   /* rfu2 */
    dram_w32(ev + 0x20u, S->cur_pad_3do);       /* cped_ButtonBits */
    dram_w32(ev + 0x24u, 0u);                   /* terminating ef_ByteCount = 0 */

    u32 mnode = msg->node_addr;
    dram_w32(mnode + 0x24u, S->eb_port_item);   /* msg_ReplyPort */
    dram_w32(mnode + 0x28u, 0u);                /* msg_Result >= 0 */
    dram_w32(mnode + 0x2Cu, ev);                /* msg_DataPtr */
    dram_w32(mnode + 0x30u, 0x28u);             /* msg_DataSize */
    dram_w32(mnode + 0x34u, S->eb_listener_port);

    hle_list_add_tail(mp->node_addr + 0x28u, mnode);
    u32 sig = dram_r32(mp->node_addr + 0x24u);
    dram_w32(HLE_TASK + 0x34u, dram_r32(HLE_TASK + 0x34u) | sig);
    S->eb_msg_in_flight = 1;
}

/* Execute Portfolio I/O request (SPORT, timer, cdrom, diskfile, mac) */
static s32 hle_exec_io(u32 ior_item, u32 ioi_addr)
{
    struct hle_item *ior = hle_get_item(ior_item);
    if (!ior || ior->kind != IK_IOREQ)
        return -1;

    u32 in_node = ior->node_addr;
    if (ioi_addr) {
        for (u32 i = 0; i < 32u; i += 4u)
            dram_w32(in_node + 0x34u + i, dram_r32(ioi_addr + i));
    }
    u32 info = in_node + 0x34u;
    u8  cmd  = dram_r8(info + 0u);
    u8  unit = dram_r8(info + 2u);
    u32 opts = dram_r32(info + 4u);
    s32 offs = (s32)dram_r32(info + 12u);
    u32 send_buf = dram_r32(info + 16u);
    s32 send_len = (s32)dram_r32(info + 20u);
    u32 recv_buf = dram_r32(info + 24u);
    s32 recv_len = (s32)dram_r32(info + 28u);
    (void)send_buf; (void)send_len;

    struct hle_item *dev = hle_get_item(ior->aux0);
    u8 dtype = dev ? dev->dev_type : ior->dev_type;
    s32 actual = 0, err = 0;

    if (dtype == 1) { /* SPORT */
        if (cmd == 4u) { /* SPORTCMD_CLONE (SetVRAMPages / CloneVRAMPages) */
            u32 mask = opts ? opts : 0xFFFFFFFFu;
            u32 val  = (u32)offs;
            int from_src_page = (send_buf >= 0x00200000u && send_buf < 0x00300000u && send_len >= 2048);
            if (recv_buf >= 0x00200000u && recv_buf < 0x00300000u && recv_len > 0) {
                u32 dst_off = recv_buf - 0x00200000u;
                u32 nwords = (u32)recv_len >> 2;
                if (from_src_page) {
                    u32 src_off = send_buf - 0x00200000u;
                    for (u32 i = 0; i < nwords && dst_off + i * 4u < VRAM_SIZE; i++) {
                        u32 sv = vram_r32(src_off + (i & 511u) * 4u);
                        u32 dv = vram_r32(dst_off + i * 4u);
                        vram_w32(dst_off + i * 4u, (dv & ~mask) | (sv & mask));
                    }
                } else if (mask == 0xFFFFFFFFu) {
                    u32 idx = dst_off >> 2;
                    u32 max_w = (VRAM_SIZE - dst_off) >> 2;
                    if (nwords > max_w) nwords = max_w;
                    for (u32 i = 0; i < nwords; i++)
                        S->vram32[idx + i] = val;
                } else {
                    for (u32 i = 0; i < nwords && dst_off + i * 4u < VRAM_SIZE; i++) {
                        u32 dv = vram_r32(dst_off + i * 4u);
                        vram_w32(dst_off + i * 4u, (dv & ~mask) | (val & mask));
                    }
                }
                actual = recv_len;
            }
        } else if (cmd == 5u) { /* SPORTCMD_COPY (CopyVRAMPages) */
            u32 mask = opts ? opts : 0xFFFFFFFFu;
            if (send_buf >= 0x00200000u && send_buf < 0x00300000u &&
                recv_buf >= 0x00200000u && recv_buf < 0x00300000u && recv_len > 0) {
                u32 src_off = send_buf - 0x00200000u;
                u32 dst_off = recv_buf - 0x00200000u;
                u32 nwords = (u32)recv_len >> 2;
                for (u32 i = 0; i < nwords && dst_off + i * 4u < VRAM_SIZE && src_off + i * 4u < VRAM_SIZE; i++) {
                    u32 sv = vram_r32(src_off + i * 4u);
                    u32 dv = vram_r32(dst_off + i * 4u);
                    vram_w32(dst_off + i * 4u, (dv & ~mask) | (sv & mask));
                }
                actual = recv_len;
            }
        }
    } else if (dtype == 2) { /* timer */
        if (cmd == 1u && recv_buf && recv_len >= 8) { /* CMD_READ */
            if (unit == 1u) { /* USEC */
                u32 sec  = udiv64_32(S->total_usec, 1000000u, 0);
                u32 usec = (u32)(S->total_usec - (u64)sec * 1000000ull);
                dram_w32(recv_buf + 0u, sec);
                dram_w32(recv_buf + 4u, usec);
            } else { /* VBLANK */
                dram_w32(recv_buf + 0u, 0u);
                dram_w32(recv_buf + 4u, S->frame_count);
            }
            actual = 8;
        } else if (cmd == 3u || cmd == 4u) { /* TIMERCMD_DELAY / DELAYUNTIL */
            if (unit == 0u) {
                s32 fields = (cmd == 4u) ? (offs - (s32)S->frame_count) : offs;
                if (fields < 1) fields = 1;
                if (fields > 8) fields = 8;
                S->vbl_yield = fields;
            } else {
                S->total_usec += (offs > 0) ? (u32)offs : 1000u;
            }
        }
    } else if (dtype == 5 || dtype == 3) { /* diskfile or cd-rom */
        u32 base_lba = (dtype == 5 && dev) ? dev->aux0 : 0u;
        u32 file_sz  = (dtype == 5 && dev) ? dev->aux1 : (S->cd ? S->cd->total_lba * 2048u : 0u);
        if (cmd == 1u && recv_buf && recv_len > 0) { /* CMD_READ */
            u32 byte_off = (u32)offs * 2048u;
            /* Note: Portfolio DiskFile CMD_READ passes block offset in ioi_Offset (2048-byte blocks)! */
            u32 got = (u32)recv_len;
            if (operafs_read_to_dram(base_lba, byte_off, recv_buf, got) < 0)
                err = -1;
            else
                actual = (s32)got;
        } else if (cmd == 2u && recv_buf) { /* CMD_STATUS -> FileStatus / DeviceStatus */
            for (s32 i = 0; i < recv_len; i += 4) dram_w32(recv_buf + (u32)i, 0);
            if (recv_len >= 0x38) {
                dram_w8(recv_buf + 0x00u, 1u);           /* ds_DriverIdentity */
                dram_w32(recv_buf + 0x10u, 2048u);       /* ds_DeviceBlockSize */
                dram_w32(recv_buf + 0x14u, (file_sz + 2047u) >> 11); /* ds_DeviceBlockCount */
                dram_w32(recv_buf + 0x20u, 0x00000001u); /* ds_DeviceUsageFlags */
                if (recv_len >= 0x40)
                    dram_w32(recv_buf + 0x3Cu, file_sz); /* fs_ByteCount! */
            }
            actual = recv_len;
        }
    } else if (dtype == 4) { /* mac host debug console */
        actual = send_len;
    }

    dram_w32(in_node + 0x54u, (u32)actual);
    dram_w32(in_node + 0x58u, 1u); /* IO_DONE */
    dram_w32(in_node + 0x5Cu, (u32)err);
    dram_w32(HLE_TASK + 0x34u, dram_r32(HLE_TASK + 0x34u) | 8u); /* SIGF_IODONE */
    return err;
}

static u32 hle_find_tag(u32 tag_list, u32 want_tag, u32 def_val, int *found)
{
    if (found) *found = 0;
    if (!tag_list || tag_list >= DRAM_SIZE) return def_val;
    for (int i = 0; i < 64 && tag_list + 8u <= DRAM_SIZE; i++) {
        u32 t = dram_r32(tag_list);
        u32 v = dram_r32(tag_list + 4u);
        if (t == 0u) break;      /* TAG_END */
        if (t == 254u) {         /* TAG_JUMP (0xFE) */
            tag_list = v;
            continue;
        }
        if (t == 255u) {         /* TAG_NOP (0xFF) */
            tag_list += 8u;
            continue;
        }
        if (t == want_tag) {
            if (found) *found = 1;
            return v;
        }
        tag_list += 8u;
    }
    return def_val;
}

/* Handle all Portfolio SWIs + negative-vector Folio traps */
static void hle_handle_swi(u32 swi)
{
    u32 r0 = S->r[0], r1 = S->r[1], r2 = S->r[2], r3 = S->r[3];

    /* ARM Angel / Demon semihosting (0x123456) */
    if (swi == 0x123456u) {
        if (r0 == 0x18u) /* SYS_EXIT */
            S->halted = 1;
        else
            S->r[0] = 0;
        return;
    }

    /* Negative Folio vector trampolines: 0x0E0000 | (folio_id << 8) | vec_idx */
    if ((swi & 0xFF0000u) == 0x0E0000u) {
        u32 fid = (swi >> 8) & 0xFFu;
        u32 vec = swi & 0xFFu;

        if (fid == 1u) { /* KernelBase negative vectors */
            switch (vec) {
            case 1: /* KBV_REMHEAD */
                S->r[0] = hle_list_rem_head(r0);
                return;
            case 2: /* KBV_ADDHEAD */
            case 4: /* KBV_ADDTAIL */
            case 5: /* KBV_INSERTTAIL */
            case 17: /* KBV_FINSERT */
            case 20: /* KBV_INSERTHEAD */
                hle_list_add_tail(r0, r1);
                return;
            case 7:  /* KBV_ALLOCMEM: AllocMemFromMemLists(l, size, typebits) */
            case 26: /* KBV_ALLOCMEMML */
                S->r[0] = hle_alloc_mem((s32)r1, r2);
                return;
            case 8:  /* KBV_FREEMEM */
            case 27: /* KBV_FREEMEMML */
                S->r[0] = 0;
                return;
            case 9:  /* KBV_INITLIST */
                hle_list_init(r0);
                S->r[0] = 0;
                return;
            case 10: { /* KBV_FINDNAMEDNODE(list, name) */
                char want[64];
                mem_read_str(r1, want, sizeof(want));
                u32 cur = dram_r32(r0 + 0x14u);
                u32 end = r0 + 0x18u;
                S->r[0] = 0;
                for (int k = 0; k < 64 && cur && cur != end && cur < DRAM_SIZE; k++) {
                    char nm[64];
                    u32 np = dram_r32(cur + 0x10u);
                    if (np) {
                        mem_read_str(np, nm, sizeof(nm));
                        if (str_eq_ci(nm, want)) { S->r[0] = cur; break; }
                    }
                    cur = dram_r32(cur);
                }
                return;
            }
            case 12: /* KBV_LOOKUPITEM */
            case 16: { /* KBV_CHECKITEM */
                struct hle_item *it = hle_get_item(r0);
                S->r[0] = it ? it->node_addr : 0u;
                return;
            }
            case 13: { /* KBV_MEMSET(p, val, len) */
                u8 c = (u8)r1;
                for (u32 i = 0; i < r2; i++) {
                    if (r0 + i < DRAM_SIZE) dram_w8(r0 + i, c);
                    else if (r0 + i >= 0x00200000u && r0 + i < 0x00300000u) vram_w8(r0 + i - 0x00200000u, c);
                }
                S->r[0] = r0;
                return;
            }
            case 14: { /* KBV_MEMCPY(dst, src, len) */
                for (u32 i = 0; i < r2; i++) {
                    u8 b = any_r8(r1 + i);
                    if (r0 + i < DRAM_SIZE) dram_w8(r0 + i, b);
                    else if (r0 + i >= 0x00200000u && r0 + i < 0x00300000u) vram_w8(r0 + i - 0x00200000u, b);
                }
                S->r[0] = r0;
                return;
            }
            case 15: /* KBV_GETPAGESIZE */
                S->r[0] = (r0 & 0x00010000u) ? 2048u : 4096u;
                return;
            case 18: /* KBV_USEC2TICKS */
                S->r[0] = r0 >> 10;
                return;
            case 21: /* KBV_VFPRINTF */
                S->r[0] = 0;
                return;
            case 22: /* KBV_GETSYSERR */
                if (r0 && r1 > 0) dram_w8(r0, 0);
                S->r[0] = 0;
                return;
            case 25: /* KBV_FINDMH */
                S->r[0] = (r0 >= 0x00200000u && r0 < 0x00300000u) ? HLE_MEMHDR_VRAM : HLE_MEMHDR_DRAM;
                return;
            case 30: /* Task C init hook */
                S->r[0] = 0;
                return;
            case 31: /* Stack overflow / extender */
                S->r[0] = 0;
                return;
            case 32: /* KBV_ITEMOPENED */
                S->r[0] = hle_get_item(r1) ? 0u : (u32)-1;
                return;
            case 37: /* Task exit() */
                S->halted = 1;
                return;
            case 39: /* KBV_GETMEMALLOCALIGNMENT */
                S->r[0] = 16u;
                return;
            case 40: /* KBV_GETMEMTRACKSIZE */
                S->r[0] = (r0 >= 4u && r0 < DRAM_SIZE) ? dram_r32(r0 - 4u) :
                          (r0 >= 0x00200004u && r0 < 0x00300000u) ? vram_r32(r0 - 0x00200004u) : 0u;
                return;
            case 41: { /* KBV_CHECKIO */
                struct hle_item *ior = hle_get_item(r0);
                S->r[0] = ior ? (dram_r32(ior->node_addr + 0x58u) & 1u) : 1u;
                return;
            }
            case 42: /* KBV_ISMEMREADABLE */
            case 43: /* KBV_ISMEMWRITABLE */
                S->r[0] = 1u;
                return;
            case 44: { /* KBV_FINDTAGARG(tagList, tag) */
                u32 tp = r0;
                S->r[0] = 0;
                for (int i = 0; i < 64 && tp && tp + 8u <= DRAM_SIZE; i++) {
                    u32 t = dram_r32(tp);
                    if (t == 0u) break;
                    if (t == 254u) { tp = dram_r32(tp + 4u); continue; }
                    if (t == 255u) { tp += 8u; continue; }
                    if (t == r1) { S->r[0] = tp; break; }
                    tp += 8u;
                }
                return;
            }
            case 45: { /* KBV_NEXTTAGARG(&tp) */
                u32 tp = r0 ? dram_r32(r0) : 0u;
                S->r[0] = 0;
                while (tp && tp + 8u <= DRAM_SIZE) {
                    u32 t = dram_r32(tp);
                    if (t == 0u) { dram_w32(r0, 0u); break; }
                    if (t == 254u) { tp = dram_r32(tp + 4u); continue; }
                    if (t == 255u) { tp += 8u; continue; }
                    dram_w32(r0, tp + 8u);
                    S->r[0] = tp;
                    break;
                }
                return;
            }
            default:
                S->r[0] = 0;
                return;
            }
        }

        if (fid == 2u) { /* GrafBase negative vectors (idx = -routine_number) */
            switch (vec) {
            case 1: { /* _MAPSPRITE_ / MapCel(CCB *ccb, Point *quad) */
                if (r0 && r1) {
                    s32 qx0 = (s32)dram_r32(r1 +  0u), qy0 = (s32)dram_r32(r1 +  4u);
                    s32 qx1 = (s32)dram_r32(r1 +  8u), qy1 = (s32)dram_r32(r1 + 12u);
                    s32 qx2 = (s32)dram_r32(r1 + 16u), qy2 = (s32)dram_r32(r1 + 20u);
                    s32 qx3 = (s32)dram_r32(r1 + 24u), qy3 = (s32)dram_r32(r1 + 28u);
                    s32 w = (s32)dram_r32(r0 + 0x3Cu), h = (s32)dram_r32(r0 + 0x40u);
                    if (w <= 0) w = 1;
                    if (h <= 0) h = 1;
                    dram_w32(r0 + 0x10u, (u32)(qx0 << 16));
                    dram_w32(r0 + 0x14u, (u32)(qy0 << 16));
                    s32 hdx0 = ((qx1 - qx0) << 20) / w, hdy0 = ((qy1 - qy0) << 20) / w;
                    s32 hdx1 = ((qx2 - qx3) << 20) / w, hdy1 = ((qy2 - qy3) << 20) / w;
                    dram_w32(r0 + 0x18u, (u32)hdx0);
                    dram_w32(r0 + 0x1Cu, (u32)hdy0);
                    dram_w32(r0 + 0x20u, (u32)(((qx3 - qx0) << 16) / h));
                    dram_w32(r0 + 0x24u, (u32)(((qy3 - qy0) << 16) / h));
                    dram_w32(r0 + 0x28u, (u32)((hdx1 - hdx0) / h));
                    dram_w32(r0 + 0x2Cu, (u32)((hdy1 - hdy0) / h));
                }
                return;
            }
            case 2: { /* _READPIXEL_(bitmapItem, gc, x, y) */
                struct hle_item *bm = hle_get_item(r0);
                if (bm && bm->kind == IK_BITMAP && (u32)r2 < bm->aux1 && (u32)r3 < bm->aux2)
                    S->r[0] = vram_read_pix(bm->aux0 - 0x00200000u, (s32)bm->aux1, (s32)r2, (s32)r3);
                else
                    S->r[0] = 0;
                return;
            }
            case 3: { /* _READVDLCOLOR_(index) */
                u32 idx = r0 & 31u;
                S->r[0] = ((u32)S->clut_r[idx] << 16) | ((u32)S->clut_g[idx] << 8) | S->clut_b[idx];
                return;
            }
            case 4: { /* _GETPIXELADDRESS_(screenOrBmItem, x, y) */
                struct hle_item *it = hle_get_item(r0);
                if (it && it->kind == IK_SCREEN) it = hle_get_item(it->aux0);
                if (it && it->kind == IK_BITMAP)
                    S->r[0] = it->aux0 + (((r2 >> 1) * it->aux1 + r1) * 4u) + ((r2 & 1u) * 2u);
                else
                    S->r[0] = 0;
                return;
            }
            case 5: { /* _WRITEPIXEL_(bitmapItem, gc, x, y) */
                struct hle_item *bm = hle_get_item(r0);
                if (bm && bm->kind == IK_BITMAP && r1 && (u32)r2 < bm->aux1 && (u32)r3 < bm->aux2) {
                    u16 col = (u16)dram_r32(r1 + 0x14u); /* gc_FGPen */
                    vram_write_pix(bm->aux0 - 0x00200000u, (s32)bm->aux1, (s32)r2, (s32)r3, col);
                }
                S->r[0] = 0;
                return;
            }
            case 12: { /* _CREATESCREENGROUP_(Item *screenItemArray, TagArg *targs) */
                u32 nscreens = hle_find_tag(r1, 2u, 2u, 0); /* CSG_TAG_SCREENCOUNT */
                u32 disp_h   = hle_find_tag(r1, 1u, 240u, 0);
                u32 scr_h    = hle_find_tag(r1, 3u, disp_h, 0);
                u32 buf_arr  = hle_find_tag(r1, 7u, 0u, 0); /* CSG_TAG_BITMAPBUF_ARRAY */
                u32 wid_arr  = hle_find_tag(r1, 5u, 0u, 0);
                if (nscreens < 1u) nscreens = 1u;
                if (nscreens > 6u) nscreens = 6u;

                u32 sg_item = hle_alloc_item(IK_SCREENGROUP, 2, 1, 0x60u, "sg", 0);
                struct hle_item *sgi = hle_get_item(sg_item);
                u32 sgn = sgi->node_addr;
                dram_w32(sgn + 0x28u, scr_h);
                dram_w32(sgn + 0x2Cu, disp_h);
                hle_list_init(sgn + 0x30u);
                hle_list_init(sgn + 0x48u);

                for (u32 s = 0; s < nscreens; s++) {
                    u32 bw = wid_arr ? dram_r32(wid_arr + s * 4u) : 320u;
                    u32 bh = scr_h ? scr_h : 240u;
                    u32 bbuf = buf_arr ? dram_r32(buf_arr + s * 4u) : 0u;
                    if (!bbuf) {
                        u32 bsz = ((bw * ((bh + 1u) >> 1) * 4u) + 2047u) & ~2047u;
                        bbuf = hle_alloc_mem((s32)bsz, 0x02010100u); /* VRAM page-aligned zeroed */
                    }

                    u32 bm_item = hle_alloc_item(IK_BITMAP, 2, 3, 0x80u, "bm", 0);
                    struct hle_item *bmi = hle_get_item(bm_item);
                    bmi->aux0 = bbuf;
                    bmi->aux1 = bw;
                    bmi->aux2 = bh;
                    u32 bmn = bmi->node_addr;
                    dram_w32(bmn + 0x24u, bbuf); /* bm_Buffer */
                    dram_w32(bmn + 0x28u, bw);   /* bm_Width */
                    dram_w32(bmn + 0x2Cu, bh);   /* bm_Height */
                    dram_w32(bmn + 0x38u, bw);   /* bm_ClipWidth */
                    dram_w32(bmn + 0x3Cu, bh);   /* bm_ClipHeight */
                    hle_list_init(bmn + 0x4Cu);
                    dram_w32(bmn + 0x64u, 0xE1500000u); /* CECONTROL_DEFAULT */

                    u32 sc_item = hle_alloc_item(IK_SCREEN, 2, 2, 0x70u, "scr", 0);
                    struct hle_item *sci = hle_get_item(sc_item);
                    sci->aux0 = bm_item;
                    sci->aux1 = bbuf;
                    u32 scn = sci->node_addr;
                    dram_w32(scn + 0x24u, sgn);
                    dram_w32(scn + 0x34u, 1u);   /* scr_BitmapCount */
                    hle_list_init(scn + 0x38u);  /* scr_BitmapList */
                    hle_list_add_tail(scn + 0x38u, bmn);
                    hle_list_init(scn + 0x50u);
                    dram_w32(scn + 0x68u, bmn);  /* scr_TempBitmap */
                    hle_list_add_tail(sgn + 0x48u, scn);

                    if (r0)
                        dram_w32(r0 + s * 4u, sc_item);
                    if (s == 0) {
                        S->display_vram = bbuf - 0x00200000u;
                        S->draw_vram    = bbuf - 0x00200000u;
                        S->read_vram    = bbuf - 0x00200000u;
                        S->clip_w = (s32)bw;
                        S->clip_h = (s32)bh;
                    }
                }
                S->r[0] = sg_item;
                return;
            }
            case 13: { /* _SETREADADDRESS_(bitmapItem, buffer, width) */
                if (r1 >= 0x00200000u && r1 < 0x00300000u)
                    S->read_vram = r1 - 0x00200000u;
                S->r[0] = 0;
                return;
            }
            case 14: { /* _RESETREADADDRESS_(bitmapItem) */
                struct hle_item *bm = hle_get_item(r0);
                if (bm && bm->kind == IK_BITMAP)
                    S->read_vram = bm->aux0 - 0x00200000u;
                S->r[0] = 0;
                return;
            }
            case 20: /* _SETSCREENCOLOR_(screenItem, colorEntry) */
                vdl_apply_entry(r1 | 0x80000000u);
                S->r[0] = 0;
                return;
            case 21: /* _RESETSCREENCOLORS_ */
                vdl_reset_default();
                S->r[0] = 0;
                return;
            case 22: { /* _SETSCREENCOLORS_(screenItem, entries, count) */
                for (u32 i = 0; i < r2 && r1 + i * 4u < DRAM_SIZE; i++)
                    vdl_apply_entry(dram_r32(r1 + i * 4u) | 0x80000000u);
                S->r[0] = 0;
                return;
            }
            case 24: /* _SETFGPEN_(gc, c) */
                if (r0) dram_w32(r0 + 0x14u, r1);
                return;
            case 25: /* _SETBGPEN_(gc, c) */
                if (r0) dram_w32(r0 + 0x18u, r1);
                return;
            case 26: /* _ADDSCREENGROUP_ */
            case 27: /* _REMOVESCREENGROUP_ */
            case 23: /* _DELETESCREENGROUP_ */
            case 16: /* _ENABLEVAVG_ */
            case 17: /* _DISABLEVAVG_ */
            case 18: /* _ENABLEHAVG_ */
            case 19: /* _DISABLEHAVG_ */
            case 38: /* _SETCECONTROL_ */
            case 45: /* _SETCEWATCHDOG_ */
                S->r[0] = 0;
                return;
            case 28: { /* _SETCLIPWIDTH_(bm, w) */
                struct hle_item *bm = hle_get_item(r0);
                if (bm && bm->kind == IK_BITMAP) dram_w32(bm->node_addr + 0x38u, r1);
                S->r[0] = 0;
                return;
            }
            case 29: { /* _SETCLIPHEIGHT_(bm, h) */
                struct hle_item *bm = hle_get_item(r0);
                if (bm && bm->kind == IK_BITMAP) dram_w32(bm->node_addr + 0x3Cu, r1);
                S->r[0] = 0;
                return;
            }
            case 30: /* _MOVETO_(gc, x, y) */
                if (r0) { dram_w32(r0 + 0x1Cu, r1); dram_w32(r0 + 0x20u, r2); }
                return;
            case 34: { /* _FILLRECT_(bitmapItem, gc, rect) */
                struct hle_item *bm = hle_get_item(r0);
                if (bm && bm->kind == IK_BITMAP && r1 && r2) {
                    u16 col = (u16)dram_r32(r1 + 0x14u);
                    s32 x0 = (s32)dram_r32(r2 +  0u), y0 = (s32)dram_r32(r2 +  4u);
                    s32 x1 = (s32)dram_r32(r2 +  8u), y1 = (s32)dram_r32(r2 + 12u);
                    if (x0 < 0) x0 = 0;
                    if (y0 < 0) y0 = 0;
                    if (x1 >= (s32)bm->aux1) x1 = (s32)bm->aux1 - 1;
                    if (y1 >= (s32)bm->aux2) y1 = (s32)bm->aux2 - 1;
                    u32 voff = bm->aux0 - 0x00200000u;
                    for (s32 py = y0; py <= y1; py++)
                        for (s32 px = x0; px <= x1; px++)
                            vram_write_pix(voff, (s32)bm->aux1, px, py, col);
                }
                S->r[0] = 0;
                return;
            }
            case 40: { /* _DISPLAYSCREEN_(screenItem0, screenItem1) */
                struct hle_item *sc = hle_get_item(r0);
                if (sc && sc->kind == IK_SCREEN)
                    S->display_vram = sc->aux1 - 0x00200000u;
                S->r[0] = 0;
                return;
            }
            case 41: /* _SETVDL_ */
            case 47: /* _MODIFYVDL_ */
                S->r[0] = 0;
                return;
            case 42: { /* _SUBMITVDL_(dataPtr, length, type) */
                u32 vi = hle_alloc_item(IK_VDL, 2, 4, 0x40u, "vdl", 0);
                vdl_parse_list(r0, (int)r1);
                S->r[0] = vi;
                return;
            }
            case 43:   /* _DRAWCELS_ */
            case 44: { /* _DRAWSCREENCELS_ */
                struct hle_item *it = hle_get_item(r0);
                if (it && it->kind == IK_SCREEN) it = hle_get_item(it->aux0);
                u32 dv = (it && it->kind == IK_BITMAP) ? (it->aux0 - 0x00200000u) : S->draw_vram;
                s32 cw = (it && it->kind == IK_BITMAP) ? (s32)dram_r32(it->node_addr + 0x38u) : S->clip_w;
                s32 ch = (it && it->kind == IK_BITMAP) ? (s32)dram_r32(it->node_addr + 0x3Cu) : S->clip_h;
                if (cw <= 0) cw = 320;
                if (ch <= 0) ch = 240;
                madam_draw_ccb_chain(r1, dv, dv, cw, ch);
                S->r[0] = 0;
                return;
            }
            case 46: /* _GETFIRSTDISPLAYINFO_ */
                S->r[0] = HLE_DISPINFO;
                return;
            case 48: { /* _QUERYGRAPHICS_(tag, ret) */
                if (r1) {
                    u32 val = (r0 == 1u) ? 60u : (r0 == 2u) ? 16683u :
                              (r0 == 3u) ? S->frame_count : (r0 == 4u) ? 320u :
                              (r0 == 5u) ? 240u : 1u;
                    dram_w32(r1, val);
                }
                S->r[0] = 0;
                return;
            }
            default:
                S->r[0] = 0;
                return;
            }
        }

        if (fid == 5u) { /* OperaMath negative vectors */
            switch (vec) {
            case 1: /* MulSF16 */
                S->r[0] = (u32)(((s64)(s32)r0 * (s64)(s32)r1) >> 16);
                return;
            case 2: /* MulUF16 */
                S->r[0] = (u32)(((u64)r0 * (u64)r1) >> 16);
                return;
            case 3: { /* DivUF16(d1, d2) -> (d1 << 16) / d2, rem in R1 */
                u32 rem = 0;
                S->r[0] = udiv64_32((u64)r0 << 16, r1, &rem);
                S->r[1] = rem;
                return;
            }
            case 4: { /* DivRemUF16(rem *, d1, d2) */
                u32 rem = 0;
                S->r[0] = udiv64_32((u64)r1 << 16, r2, &rem);
                if (r0) dram_w32(r0, rem);
                return;
            }
            case 5: { /* DivSF16(d1, d2) */
                int neg = ((s32)r0 < 0) ^ ((s32)r1 < 0);
                u32 a = ((s32)r0 < 0) ? (u32)-(s32)r0 : r0;
                u32 b = ((s32)r1 < 0) ? (u32)-(s32)r1 : r1;
                u32 rem = 0;
                u32 q = udiv64_32((u64)a << 16, b, &rem);
                if (q > 0x7FFFFFFFu) q = 0x7FFFFFFFu;
                S->r[0] = neg ? (u32)-(s32)q : q;
                S->r[1] = rem;
                return;
            }
            case 6: { /* DivRemSF16(rem *, d1, d2) */
                int neg = ((s32)r1 < 0) ^ ((s32)r2 < 0);
                u32 a = ((s32)r1 < 0) ? (u32)-(s32)r1 : r1;
                u32 b = ((s32)r2 < 0) ? (u32)-(s32)r2 : r2;
                u32 rem = 0;
                u32 q = udiv64_32((u64)a << 16, b, &rem);
                if (q > 0x7FFFFFFFu) q = 0x7FFFFFFFu;
                S->r[0] = neg ? (u32)-(s32)q : q;
                if (r0) dram_w32(r0, rem);
                return;
            }
            case 7: /* RecipUF16 */
                S->r[0] = udiv64_32(1ull << 32, r0, &S->r[1]);
                return;
            case 8: { /* RecipSF16 */
                int neg = (s32)r0 < 0;
                u32 a = neg ? (u32)-(s32)r0 : r0;
                u32 q = udiv64_32(1ull << 32, a, &S->r[1]);
                if (q > 0x7FFFFFFFu) q = 0x7FFFFFFFu;
                S->r[0] = neg ? (u32)-(s32)q : q;
                return;
            }
            case 9:  /* MulSF30 */
                S->r[0] = (u32)(((s64)(s32)r0 * (s64)(s32)r1) >> 30);
                return;
            case 10: /* SquareSF16 */
                S->r[0] = (u32)(((s64)(s32)r0 * (s64)(s32)r0) >> 16);
                return;
            case 11: /* SquareUF16 */
                S->r[0] = (u32)(((u64)r0 * (u64)r0) >> 16);
                return;
            case 12: /* SqrtF16 */
                S->r[0] = isqrt32(r0) << 8;
                return;
            case 13: /* Sqrt32 */
                S->r[0] = isqrt32(r0);
                return;
            case 14: /* SinF16 */
                S->r[0] = (u32)sin_f16((s32)r0);
                return;
            case 15: /* CosF16 */
                S->r[0] = (u32)sin_f16((s32)r0 + 0x00400000);
                return;
            default:
                S->r[0] = 0;
                return;
            }
        }

        S->r[0] = 0;
        return;
    }

    /* Standard Portfolio SWI (folio << 16) | op */
    u32 folio = swi >> 16;
    u32 op    = swi & 0xFFFFu;

    if (folio == 0u) {
        if (op == 0x10u) { /* OS_GetEnv (used by ARM AIF RelocCode) */
            S->r[0] = 0x00008000u; /* command string stub */
            S->r[1] = HLE_USER_SP; /* top of workspace */
        } else if (op == 0x11u) {  /* OS_Exit */
            S->halted = 1;
        }
        return;
    }

    if (folio == 1u) { /* KERNELSWI */
        switch (op) {
        case 0: { /* CreateSizedItem(ctype, TagArg *tp, size) */
            u8 subsys = (u8)((r0 >> 8) & 0xFFu);
            u8 ntype  = (u8)(r0 & 0xFFu);
            char nm[32]; nm[0] = 0;
            u32 np = hle_find_tag(r1, 1u, 0u, 0);
            if (np) mem_read_str(np, nm, sizeof(nm));

            if (subsys == 1 && ntype == 14) { /* IOREQNODE */
                u32 dev_i = hle_find_tag(r1, 11u, 0u, 0); /* CREATEIOREQ_TAG_DEVICE */
                u32 rp_i  = hle_find_tag(r1, 10u, 0u, 0); /* CREATEIOREQ_TAG_REPLYPORT */
                u32 id = hle_alloc_item(IK_IOREQ, 1, 14, 0x70u, nm, 0);
                struct hle_item *it = hle_get_item(id);
                struct hle_item *dv = hle_get_item(dev_i);
                it->aux0 = dev_i;
                it->aux1 = rp_i;
                it->dev_type = dv ? dv->dev_type : 0;
                dram_w32(it->node_addr + 0x2Cu, dv ? dv->node_addr : 0u);
                S->r[0] = id;
                return;
            }
            if (subsys == 1 && ntype == 10) { /* MSGPORTNODE */
                int has_sig = 0;
                u32 sig = hle_find_tag(r1, 10u, 0u, &has_sig);
                if (!has_sig || !sig) {
                    u32 allocd = dram_r32(HLE_TASK + 0x38u);
                    for (int b = 8; b < 31; b++) {
                        if (!(allocd & (1u << b))) {
                            sig = 1u << b;
                            dram_w32(HLE_TASK + 0x38u, allocd | sig);
                            break;
                        }
                    }
                }
                u32 id = hle_alloc_item(IK_MSGPORT, 1, 10, 0x50u, nm, 0);
                struct hle_item *it = hle_get_item(id);
                it->aux0 = sig;
                dram_w32(it->node_addr + 0x24u, sig);
                hle_list_init(it->node_addr + 0x28u);
                S->r[0] = id;
                return;
            }
            if (subsys == 1 && ntype == 9) { /* MESSAGENODE */
                u32 rp   = hle_find_tag(r1, 10u, 0u, 0);
                u32 dsz  = hle_find_tag(r1, 12u, 0u, 0);
                u32 id = hle_alloc_item(IK_MSG, 1, 9, 0x48u + dsz, nm, 0);
                struct hle_item *it = hle_get_item(id);
                it->aux1 = rp;
                dram_w32(it->node_addr + 0x24u, rp);
                if (dsz > 0) {
                    dram_w32(it->node_addr + 0x2Cu, it->node_addr + 0x48u);
                    dram_w32(it->node_addr + 0x38u, dsz);
                }
                S->r[0] = id;
                return;
            }
            if (subsys == 2 && ntype == 3) { /* BITMAPNODE */
                u32 bw = hle_find_tag(r1, 11u, 320u, 0);
                u32 bh = hle_find_tag(r1, 12u, 240u, 0);
                u32 bb = hle_find_tag(r1, 13u, 0u, 0);
                if (!bb) bb = hle_alloc_mem((s32)(((bw * ((bh + 1u) >> 1) * 4u) + 2047u) & ~2047u), 0x02010100u);
                u32 id = hle_alloc_item(IK_BITMAP, 2, 3, 0x80u, nm, 0);
                struct hle_item *it = hle_get_item(id);
                it->aux0 = bb; it->aux1 = bw; it->aux2 = bh;
                dram_w32(it->node_addr + 0x24u, bb);
                dram_w32(it->node_addr + 0x28u, bw);
                dram_w32(it->node_addr + 0x2Cu, bh);
                dram_w32(it->node_addr + 0x38u, bw);
                dram_w32(it->node_addr + 0x3Cu, bh);
                S->r[0] = id;
                return;
            }
            if (subsys == 4 && ntype == 5) { /* AUDIO CUE */
                u32 id = hle_alloc_item(IK_AUDIO_CUE, 4, 5, 0x40u, nm, 0);
                S->r[0] = id;
                return;
            }
            S->r[0] = hle_alloc_item(IK_SEMAPHORE, subsys, ntype, r2 ? r2 : 0x40u, nm, 0);
            return;
        }
        case 1: { /* WaitSignal(sigMask) */
            hle_deliver_pad_event();
            u32 sigs = dram_r32(HLE_TASK + 0x34u);
            u32 hit = sigs & r0;
            if (!hit) {
                /* Yield rest of frame waiting for VBL / pad update */
                S->vbl_yield = 1;
                hle_deliver_pad_event();
                sigs = dram_r32(HLE_TASK + 0x34u);
                hit = sigs & r0;
                if (!hit) hit = r0;
            }
            dram_w32(HLE_TASK + 0x34u, sigs & ~hit);
            S->r[0] = hit;
            return;
        }
        case 2: /* SendSignal */
            dram_w32(HLE_TASK + 0x34u, dram_r32(HLE_TASK + 0x34u) | r1);
            S->r[0] = 0;
            return;
        case 3: { /* DeleteItem */
            struct hle_item *it = hle_get_item(r0);
            if (it && r0 > 0x0001000Bu) it->kind = IK_NONE;
            S->r[0] = 0;
            return;
        }
        case 4:   /* FindItem(ctype, tp) */
        case 36: { /* FindAndOpenItem(ctype, tp) */
            u8 subsys = (u8)((r0 >> 8) & 0xFFu);
            u8 ntype  = (u8)(r0 & 0xFFu);
            u32 np = hle_find_tag(r1, 1u, 0u, 0);
            char want[48]; want[0] = 0;
            if (np) mem_read_str(np, want, sizeof(want));
            S->r[0] = (u32)-1;
            for (int i = 1; i < MAX_ITEMS; i++) {
                if (S->items[i].kind != IK_NONE && S->items[i].subsys == subsys && S->items[i].ntype == ntype) {
                    if (!want[0] || str_eq_ci(S->items[i].name, want)) {
                        S->r[0] = 0x00010000u | (u32)i;
                        return;
                    }
                }
            }
            return;
        }
        case 5: /* OpenItem(foundItem, args) */
            S->r[0] = hle_get_item(r0) ? r0 : (u32)-1;
            return;
        case 6: /* UnlockItem */
        case 7: /* LockItem */
        case 8: /* CloseItem */
        case 10: /* SetItemPri */
        case 28: /* SetItemOwner */
            S->r[0] = 0;
            return;
        case 9: /* Yield */
            S->vbl_yield = 1;
            return;
        case 13: /* AllocMemBlocks(size, typebits) */
            S->r[0] = hle_alloc_mem((s32)r0, r1);
            return;
        case 14: /* kprintf */
            S->r[0] = 0;
            return;
        case 16: { /* SendMsg(mp, msg, dataptr, datasize) */
            struct hle_item *mp = hle_get_item(r0);
            struct hle_item *ms = hle_get_item(r1);
            if (!mp || !ms) { S->r[0] = (u32)-1; return; }
            if (r0 == S->eb_port_item) {
                /* Message sent to EventBroker! */
                u32 flavor = r2 ? dram_r32(r2) : 0u;
                u32 reply_port = dram_r32(ms->node_addr + 0x24u);
                if (flavor == 1u) /* EB_Configure */
                    S->eb_listener_port = reply_port;
                /* Immediately reply on reply_port with msg_Result = 0 */
                struct hle_item *rp = hle_get_item(reply_port);
                dram_w32(ms->node_addr + 0x28u, 0u);
                dram_w32(ms->node_addr + 0x2Cu, 0u);
                dram_w32(ms->node_addr + 0x30u, 0u);
                if (rp) {
                    hle_list_add_tail(rp->node_addr + 0x28u, ms->node_addr);
                    u32 sig = dram_r32(rp->node_addr + 0x24u);
                    dram_w32(HLE_TASK + 0x34u, dram_r32(HLE_TASK + 0x34u) | sig);
                }
                hle_deliver_pad_event();
                S->r[0] = 0;
                return;
            }
            dram_w32(ms->node_addr + 0x2Cu, r2);
            dram_w32(ms->node_addr + 0x30u, r3);
            hle_list_add_tail(mp->node_addr + 0x28u, ms->node_addr);
            dram_w32(HLE_TASK + 0x34u, dram_r32(HLE_TASK + 0x34u) | dram_r32(mp->node_addr + 0x24u));
            S->r[0] = 0;
            return;
        }
        case 17: /* ReadHardwareRandomNumber */
            S->lfsr = S->lfsr * 1664525u + 1013904223u;
            S->r[0] = S->lfsr;
            return;
        case 18: { /* ReplyMsg(msg, result, dataptr, datasize) */
            if (r0 == S->eb_event_msg) {
                S->eb_msg_in_flight = 0;
                S->r[0] = 0;
                return;
            }
            struct hle_item *ms = hle_get_item(r0);
            if (ms) {
                dram_w32(ms->node_addr + 0x28u, r1);
                dram_w32(ms->node_addr + 0x2Cu, r2);
                dram_w32(ms->node_addr + 0x30u, r3);
                struct hle_item *rp = hle_get_item(dram_r32(ms->node_addr + 0x24u));
                if (rp) {
                    hle_list_add_tail(rp->node_addr + 0x28u, ms->node_addr);
                    dram_w32(HLE_TASK + 0x34u, dram_r32(HLE_TASK + 0x34u) | dram_r32(rp->node_addr + 0x24u));
                }
            }
            S->r[0] = 0;
            return;
        }
        case 19:   /* GetMsg(mp) */
        case 40: { /* WaitPort(mp, msg) */
            if (r0 == S->eb_listener_port)
                hle_deliver_pad_event();
            struct hle_item *mp = hle_get_item(r0);
            if (!mp) { S->r[0] = (u32)-1; return; }
            u32 mnode = hle_list_rem_head(mp->node_addr + 0x28u);
            S->r[0] = mnode ? dram_r32(mnode + 0x18u) : 0u;
            return;
        }
        case 20: /* ControlMem */
        case 22: /* FreeSignal */
        case 33: /* SystemScavengeMem */
        case 39: /* SetExitStatus */
            S->r[0] = 0;
            return;
        case 21: { /* AllocSignal(sigMask) */
            u32 allocd = dram_r32(HLE_TASK + 0x38u);
            if (r0) {
                if (allocd & r0) { S->r[0] = 0; return; }
                dram_w32(HLE_TASK + 0x38u, allocd | r0);
                S->r[0] = r0;
                return;
            }
            for (int b = 8; b < 31; b++) {
                if (!(allocd & (1u << b))) {
                    u32 s = 1u << b;
                    dram_w32(HLE_TASK + 0x38u, allocd | s);
                    S->r[0] = s;
                    return;
                }
            }
            S->r[0] = 0;
            return;
        }
        case 24: /* SendIO(ior, ioiP) */
        case 37: /* DoIO(ior, ioiP) */
            S->r[0] = (u32)hle_exec_io(r0, r1);
            return;
        case 25: /* AbortIO */
        case 41: /* WaitIO */
            S->r[0] = 0;
            return;
        default:
            S->r[0] = 0;
            return;
        }
    }

    if (folio == 2u) { /* GRAFSWI */
        if (op == 39u || op == 23u) { /* DrawCels / DrawScreenCels */
            struct hle_item *it = hle_get_item(r0);
            if (it && it->kind == IK_SCREEN) it = hle_get_item(it->aux0);
            u32 dv = (it && it->kind == IK_BITMAP) ? (it->aux0 - 0x00200000u) : S->draw_vram;
            s32 cw = (it && it->kind == IK_BITMAP) ? (s32)dram_r32(it->node_addr + 0x38u) : S->clip_w;
            s32 ch = (it && it->kind == IK_BITMAP) ? (s32)dram_r32(it->node_addr + 0x3Cu) : S->clip_h;
            if (cw <= 0) cw = 320;
            if (ch <= 0) ch = 240;
            madam_draw_ccb_chain(r1, dv, dv, cw, ch);
            S->r[0] = 0;
            return;
        }
        S->r[0] = 0;
        return;
    }

    if (folio == 3u) { /* FILEFOLIOSWI */
        switch (op) {
        case 0:   /* OpenDiskFile(path) */
        case 5: { /* OpenDiskFileInDir(dirItem, path) */
            u32 path_ptr = (op == 5u) ? r1 : r0;
            u32 base_lba = S->cwd_lba;
            if (op == 5u) {
                struct hle_item *di = hle_get_item(r0);
                if (di) base_lba = di->aux0;
            }
            char path[128];
            mem_read_str(path_ptr, path, sizeof(path));
            u32 lba = 0, bsz = 0;
            int isdir = 0;
            if (operafs_resolve(base_lba, path, &lba, &bsz, &isdir) < 0) {
                S->r[0] = (u32)-1;
                return;
            }
            u32 id = hle_alloc_item(IK_DISKFILE, 3, 1, 0x50u, path, 0);
            struct hle_item *fi = hle_get_item(id);
            fi->dev_type = 5;
            fi->aux0 = lba;
            fi->aux1 = bsz;
            fi->aux2 = 0;
            S->r[0] = id;
            return;
        }
        case 1: /* CloseDiskFile */
            S->r[0] = 0;
            return;
        case 7: { /* ChangeDirectory(path) */
            char path[128];
            mem_read_str(r0, path, sizeof(path));
            u32 lba = 0, bsz = 0;
            int isdir = 0;
            if (operafs_resolve(S->cwd_lba, path, &lba, &bsz, &isdir) < 0) {
                S->r[0] = (u32)-1;
                return;
            }
            S->cwd_lba = lba;
            S->r[0] = 0x00010004u;
            return;
        }
        case 8: { /* GetDirectory(buf, len) */
            if (r0 && r1 > 2u) mem_write_str(r0, "/");
            S->r[0] = 0x00010004u;
            return;
        }
        default:
            S->r[0] = 0;
            return;
        }
    }

    if (folio == 4u) { /* AUDIOSWI */
        if (op == 38u) S->r[0] = (u16)(S->frame_count * 735u); /* GetAudioFrameCount */
        else S->r[0] = 0;
        return;
    }

    if (folio == 5u) { /* MATHSWI matrix/vector ops */
        switch (op) {
        case 0: { /* MulVec3Mat33_F16(dest, vec, mat) */
            s32 vx = (s32)dram_r32(r1 + 0u), vy = (s32)dram_r32(r1 + 4u), vz = (s32)dram_r32(r1 + 8u);
            for (u32 c = 0; c < 3u; c++) {
                s64 acc = (s64)vx * (s32)dram_r32(r2 +  0u + c * 4u)
                        + (s64)vy * (s32)dram_r32(r2 + 12u + c * 4u)
                        + (s64)vz * (s32)dram_r32(r2 + 24u + c * 4u);
                dram_w32(r0 + c * 4u, (u32)(acc >> 16));
            }
            return;
        }
        case 1: { /* MulMat33Mat33_F16(dest, s1, s2) */
            s32 out[9];
            for (u32 i = 0; i < 3u; i++) {
                for (u32 j = 0; j < 3u; j++) {
                    s64 acc = (s64)(s32)dram_r32(r1 + i * 12u + 0u) * (s32)dram_r32(r2 +  0u + j * 4u)
                            + (s64)(s32)dram_r32(r1 + i * 12u + 4u) * (s32)dram_r32(r2 + 12u + j * 4u)
                            + (s64)(s32)dram_r32(r1 + i * 12u + 8u) * (s32)dram_r32(r2 + 24u + j * 4u);
                    out[i * 3u + j] = (s32)(acc >> 16);
                }
            }
            for (u32 k = 0; k < 9u; k++) dram_w32(r0 + k * 4u, (u32)out[k]);
            return;
        }
        case 2: { /* MulManyVec3Mat33_F16(dest, src, mat, count) */
            for (s32 n = 0; n < (s32)r3; n++) {
                u32 sp = r1 + (u32)n * 12u, dp = r0 + (u32)n * 12u;
                s32 vx = (s32)dram_r32(sp), vy = (s32)dram_r32(sp + 4u), vz = (s32)dram_r32(sp + 8u);
                for (u32 c = 0; c < 3u; c++) {
                    s64 acc = (s64)vx * (s32)dram_r32(r2 +  0u + c * 4u)
                            + (s64)vy * (s32)dram_r32(r2 + 12u + c * 4u)
                            + (s64)vz * (s32)dram_r32(r2 + 24u + c * 4u);
                    dram_w32(dp + c * 4u, (u32)(acc >> 16));
                }
            }
            return;
        }
        case 12: { /* Dot3_F16 */
            s64 acc = (s64)(s32)dram_r32(r0 + 0u) * (s32)dram_r32(r1 + 0u)
                    + (s64)(s32)dram_r32(r0 + 4u) * (s32)dram_r32(r1 + 4u)
                    + (s64)(s32)dram_r32(r0 + 8u) * (s32)dram_r32(r1 + 8u);
            S->r[0] = (u32)(acc >> 16);
            return;
        }
        case 14: { /* Cross3_F16(dest, v1, v2) */
            s32 ax = (s32)dram_r32(r1), ay = (s32)dram_r32(r1 + 4u), az = (s32)dram_r32(r1 + 8u);
            s32 bx = (s32)dram_r32(r2), by = (s32)dram_r32(r2 + 4u), bz = (s32)dram_r32(r2 + 8u);
            dram_w32(r0 + 0u, (u32)(((s64)ay * bz - (s64)az * by) >> 16));
            dram_w32(r0 + 4u, (u32)(((s64)az * bx - (s64)ax * bz) >> 16));
            dram_w32(r0 + 8u, (u32)(((s64)ax * by - (s64)ay * bx) >> 16));
            return;
        }
        default:
            S->r[0] = 0;
            return;
        }
    }

    S->r[0] = 0;
}

/* --- Hardware MMIO Bus (Madam / Clio / SPORT / NVRAM / XBUS / DSPP) --- */
static void xbus_issue_cmd(void)
{
    u8 cmd = S->xbus_cmd[0];
    S->xbus_stat_pos = 0;
    S->xbus_stat_len = 1;
    S->xbus_stat[0]  = 0x1Au; /* Spinup + Disc present + Ready */

    if (cmd == 0x83u) { /* Read ID */
        static const u8 id[11] = { 0x1Au, 0, 'M', 'E', 'I', ' ', 'C', 'D', '-', 'R', 'O' };
        for (int i = 0; i < 11; i++) S->xbus_stat[i] = id[i];
        S->xbus_stat_len = 11;
    } else if (cmd == 0x10u && S->xbus_cmd_len >= 7) { /* Read Data MSF */
        u32 m = S->xbus_cmd[1], s = S->xbus_cmd[2], f = S->xbus_cmd[3];
        u32 lba = (m * 60u + s) * 75u + f;
        if (lba >= 150u) lba -= 150u;
        if (disc_read_sector(lba, S->xbus_data) == 0) {
            S->xbus_data_pos = 0;
            S->xbus_data_len = 2048u;
            S->xbus_poll |= 0x04u; /* Data ready */
        }
    } else if (cmd == 0x8Bu) { /* Read TOC */
        S->xbus_stat[1] = 1;
        S->xbus_stat[2] = S->cd ? S->cd->last_track : 1;
        S->xbus_stat_len = 8;
    }
    S->xbus_poll |= 0x02u; /* Status ready */
    S->clio[0x40 / 4] |= (1u << 9);
    S->xbus_cmd_len = 0;
}

static u32 mmio_r32(u32 addr)
{
    if (addr >= 0x03140000u && addr < 0x03160000u)
        return S->nvram[(addr - 0x03140000u) >> 2];

    if (addr >= 0x03200000u && addr < 0x03300000u)
        return vram_r32(addr - 0x03200000u);

    if (addr >= 0x03300000u && addr < 0x03300800u) {
        u32 off = addr - 0x03300000u;
        if (off == 0x000u) return 0x01020000u; /* Madam rev */
        if (off == 0x004u) return 0x00000030u; /* 2MB DRAM + 1MB VRAM */
        if (off == 0x580u) return 0u;          /* CEL idle */
        return S->madam[off >> 2];
    }

    if (addr >= 0x03400000u && addr < 0x03408000u) {
        u32 off = addr - 0x03400000u;
        if (off == 0x000u) return 0x02020000u; /* Clio rev */
        if (off == 0x034u) return (S->frame_count & 1u) << 11 | ((S->clio[0x34 / 4]) & 0x3FFu);
        if (off == 0x080u) {
            S->lfsr = S->lfsr * 1664525u + 1013904223u;
            return S->lfsr;
        }
        if (off == 0x400u) return S->xbus_poll;
        if (off == 0x410u) {
            u8 v = (S->xbus_stat_pos < S->xbus_stat_len) ? S->xbus_stat[S->xbus_stat_pos++] : 0;
            if (S->xbus_stat_pos >= S->xbus_stat_len) S->xbus_poll &= ~0x02u;
            return v;
        }
        if (off == 0x414u) {
            u8 v = (S->xbus_data_pos < S->xbus_data_len) ? S->xbus_data[S->xbus_data_pos++] : 0;
            if (S->xbus_data_pos >= S->xbus_data_len) S->xbus_poll &= ~0x04u;
            return v;
        }
        if (off < 0x800u) return S->clio[off >> 2];
    }
    return 0;
}

static void mmio_w32(u32 addr, u32 val)
{
    if (addr >= 0x03140000u && addr < 0x03160000u) {
        u32 idx = (addr - 0x03140000u) >> 2;
        u8 b = (u8)val;
        if (S->nvram[idx] != b) {
            S->nvram[idx] = b;
            S->nvram_dirty = 1;
        }
        return;
    }

    if (addr >= 0x03200000u && addr < 0x03300000u) {
        /* SPORT hardware row flash-clear */
        u32 row_off = (addr - 0x03200000u) & (VRAM_SIZE - 1u);
        u32 base = (row_off & ~0x7FFu) >> 2;
        for (u32 i = 0; i < 512u && base + i < (VRAM_SIZE >> 2); i++)
            S->vram32[base + i] = val;
        return;
    }

    if (addr >= 0x03300000u && addr < 0x03300800u) {
        u32 off = addr - 0x03300000u;
        S->madam[off >> 2] = val;
        if (off == 0x020u) { /* VDL head pointer */
            vdl_parse_list(val, 64);
        } else if (off == 0x580u || off == 0x588u) { /* SPRSTRT / SPRCNTU */
            u32 ccb = S->madam[0x5A0 / 4];
            u32 reg0 = S->madam[0x5B0 / 4];
            u32 reg2 = S->madam[0x5B8 / 4];
            u32 reg3 = S->madam[0x5BC / 4];
            u32 r_vram = (reg2 >= 0x00200000u && reg2 < 0x00300000u) ? (reg2 - 0x00200000u) : S->read_vram;
            u32 w_vram = (reg3 >= 0x00200000u && reg3 < 0x00300000u) ? (reg3 - 0x00200000u) : S->draw_vram;
            s32 cw = (s32)((reg0 >> 16) & 0x3FFu);
            s32 ch = (s32)(reg0 & 0x3FFu);
            if (cw <= 0) cw = 320;
            if (ch <= 0) ch = 240;
            madam_draw_ccb_chain(ccb, w_vram, r_vram, cw, ch);
            S->clio[0x40 / 4] |= (1u << 2); /* SPREND IRQ */
        } else if (off == 0x5B8u && val >= 0x00200000u && val < 0x00300000u) {
            S->read_vram = val - 0x00200000u;
        } else if (off == 0x5BCu && val >= 0x00200000u && val < 0x00300000u) {
            S->draw_vram = val - 0x00200000u;
        } else if (off == 0x400u && S->hle_mode == 2) {
            /* Built-in demo helper port: set voice frequency & gain */
            u32 ch = (val >> 28) & 7u;
            S->voices[ch].active = (val & 0x0FFFFFFFu) != 0;
            S->voices[ch].freq_inc = (val & 0xFFFFFu) << 8;
            S->voices[ch].gain_l = (s32)(((val >> 20) & 0xFFu) * 64u);
            S->voices[ch].gain_r = S->voices[ch].gain_l;
        }
        return;
    }

    if (addr >= 0x03400000u && addr < 0x03408000u) {
        u32 off = addr - 0x03400000u;
        if (off == 0x040u) { S->clio[0x40 / 4] |= val; return; }
        if (off == 0x044u) { S->clio[0x40 / 4] &= ~val; return; }
        if (off == 0x048u) { S->clio[0x48 / 4] |= val; return; }
        if (off == 0x04Cu) { S->clio[0x48 / 4] &= ~val; return; }
        if (off == 0x060u) { S->clio[0x60 / 4] |= val; return; }
        if (off == 0x064u) { S->clio[0x60 / 4] &= ~val; return; }
        if (off == 0x068u) { S->clio[0x68 / 4] |= val; return; }
        if (off == 0x06Cu) { S->clio[0x68 / 4] &= ~val; return; }
        if (off == 0x200u) { S->clio[0x200 / 4] |= val; return; }
        if (off == 0x204u) { S->clio[0x200 / 4] &= ~val; return; }
        if (off == 0x400u) { S->xbus_poll = (u8)val; return; }
        if (off == 0x410u) {
            if (S->xbus_cmd_len < sizeof(S->xbus_cmd))
                S->xbus_cmd[S->xbus_cmd_len++] = (u8)val;
            if (S->xbus_cmd_len >= 7 || S->xbus_cmd[0] == 0x83u)
                xbus_issue_cmd();
            return;
        }
        if (off < 0x800u) S->clio[off >> 2] = val;
    }
}

/* --- ARM60 (ARMv3 Big-Endian) CPU Core --- */
static int mode_idx(u32 m)
{
    switch (m & 0x1Fu) {
    case MODE_FIQ: return 1;
    case MODE_IRQ: return 2;
    case MODE_SVC: return 3;
    case MODE_ABT: return 4;
    case MODE_UND: return 5;
    default:       return 0;
    }
}

static void arm_switch_mode(u32 new_cpsr)
{
    u32 old_m = S->cpsr & 0x1Fu;
    u32 new_m = new_cpsr & 0x1Fu;
    if (old_m != new_m) {
        int oi = mode_idx(old_m), ni = mode_idx(new_m);
        S->r13_bank[oi] = S->r[13];
        S->r14_bank[oi] = S->r[14];
        if (oi == 1) {
            for (int i = 0; i < 5; i++) S->r_fiq[i] = S->r[8 + i];
            for (int i = 0; i < 5; i++) S->r[8 + i] = S->r_usr[i];
        } else if (ni == 1) {
            for (int i = 0; i < 5; i++) S->r_usr[i] = S->r[8 + i];
            for (int i = 0; i < 5; i++) S->r[8 + i] = S->r_fiq[i];
        }
        S->r[13] = S->r13_bank[ni];
        S->r[14] = S->r14_bank[ni];
    }
    S->cpsr = new_cpsr;
}

static inline u32 bus_r32(u32 a)
{
    u32 aligned = a & ~3u;
    u32 v;
    if (aligned < DRAM_SIZE)
        v = S->dram32[aligned >> 2];
    else if (aligned >= 0x00200000u && aligned < 0x00300000u)
        v = S->vram32[(aligned - 0x00200000u) >> 2];
    else if (aligned >= 0x03000000u && aligned < 0x03100000u)
        v = S->rom32[(aligned - 0x03000000u) >> 2];
    else
        v = mmio_r32(aligned);

    /* Unaligned ARM big-endian LDR rotation */
    u32 rot = (a & 3u) << 3;
    if (rot)
        v = (v << rot) | (v >> (32u - rot));
    return v;
}

static inline void bus_w32(u32 a, u32 v)
{
    u32 aligned = a & ~3u;
    if (aligned < DRAM_SIZE)
        S->dram32[aligned >> 2] = v;
    else if (aligned >= 0x00200000u && aligned < 0x00300000u)
        S->vram32[(aligned - 0x00200000u) >> 2] = v;
    else if (aligned >= 0x03100000u)
        mmio_w32(aligned, v);
}

static inline u8 bus_r8(u32 a)
{
    if (a < DRAM_SIZE)
        return dram_r8(a);
    if (a >= 0x00200000u && a < 0x00300000u)
        return vram_r8(a - 0x00200000u);
    if (a >= 0x03000000u && a < 0x03100000u)
        return ((const u8 *)S->rom32)[(a - 0x03000000u) ^ 3u];
    return (u8)(mmio_r32(a & ~3u) >> ((3u - (a & 3u)) * 8u));
}

static inline void bus_w8(u32 a, u8 v)
{
    if (a < DRAM_SIZE)
        dram_w8(a, v);
    else if (a >= 0x00200000u && a < 0x00300000u)
        vram_w8(a - 0x00200000u, v);
    else if (a >= 0x03100000u)
        mmio_w32(a & ~3u, v);
}

static inline int cond_ok(u32 cond, u32 cpsr)
{
    switch (cond) {
    case 0x0: return (cpsr & CPSR_Z) != 0;
    case 0x1: return (cpsr & CPSR_Z) == 0;
    case 0x2: return (cpsr & CPSR_C) != 0;
    case 0x3: return (cpsr & CPSR_C) == 0;
    case 0x4: return (cpsr & CPSR_N) != 0;
    case 0x5: return (cpsr & CPSR_N) == 0;
    case 0x6: return (cpsr & CPSR_V) != 0;
    case 0x7: return (cpsr & CPSR_V) == 0;
    case 0x8: return (cpsr & (CPSR_C | CPSR_Z)) == CPSR_C;
    case 0x9: return (cpsr & (CPSR_C | CPSR_Z)) != CPSR_C;
    case 0xA: return ((cpsr >> 31) & 1u) == ((cpsr >> 28) & 1u);
    case 0xB: return ((cpsr >> 31) & 1u) != ((cpsr >> 28) & 1u);
    case 0xC: return !(cpsr & CPSR_Z) && (((cpsr >> 31) & 1u) == ((cpsr >> 28) & 1u));
    case 0xD: return (cpsr & CPSR_Z) || (((cpsr >> 31) & 1u) != ((cpsr >> 28) & 1u));
    case 0xE: return 1;
    default:  return 0;
    }
}

static void arm_step_slice(int max_cycles)
{
    for (int cyc = 0; cyc < max_cycles && !S->halted && !S->vbl_yield; cyc++) {
        /* Deliver Clio FIRQ / IRQ only when running real BIOS / low-level handlers */
        if (!S->hle_mode && !(S->cpsr & CPSR_F) && (S->clio[0x40 / 4] & S->clio[0x48 / 4])) {
            u32 old = S->cpsr;
            arm_switch_mode((old & ~0x1Fu) | MODE_FIQ | CPSR_F | CPSR_I);
            S->spsr[1] = old;
            S->r[14] = S->r[15] + 4u;
            S->r[15] = 0x0000001Cu;
        }

        u32 pc = S->r[15] & ~3u;
        u32 op = (pc < DRAM_SIZE) ? S->dram32[pc >> 2] :
                 (pc >= 0x03000000u && pc < 0x03100000u) ? S->rom32[(pc - 0x03000000u) >> 2] : 0u;
        S->r[15] = pc + 4u;

        u32 cond = op >> 28;
        if (cond != 0xEu && !cond_ok(cond, S->cpsr))
            continue;

        u32 top = (op >> 25) & 7u;

        /* Branch / Branch-and-Link: 101 L offset24 */
        if (top == 5u) {
            if (op & (1u << 24))
                S->r[14] = pc + 4u;
            s32 off = (s32)(op << 8) >> 6;
            S->r[15] = pc + 8u + (u32)off;
            continue;
        }

        /* Single Data Transfer: LDR / STR / LDRB / STRB (010 / 011) */
        if (top == 2u || top == 3u) {
            u32 rn = (op >> 16) & 15u;
            u32 rd = (op >> 12) & 15u;
            u32 base = (rn == 15u) ? (pc + 8u) : S->r[rn];
            u32 off;
            if (top == 2u) {
                off = op & 0xFFFu;
            } else {
                u32 rm = op & 15u;
                u32 mv = (rm == 15u) ? (pc + 8u) : S->r[rm];
                u32 sh = (op >> 7) & 31u;
                u32 st = (op >> 5) & 3u;
                if (st == 0u)      off = mv << sh;
                else if (st == 1u) off = sh ? (mv >> sh) : 0u;
                else if (st == 2u) off = sh ? (u32)((s32)mv >> sh) : (u32)((s32)mv >> 31);
                else               off = sh ? ((mv >> sh) | (mv << (32u - sh))) : (((S->cpsr & CPSR_C) ? 0x80000000u : 0u) | (mv >> 1));
            }
            u32 ea = (op & (1u << 23)) ? (base + off) : (base - off);
            u32 addr = (op & (1u << 24)) ? ea : base;

            if (op & (1u << 20)) { /* LDR */
                u32 val = (op & (1u << 22)) ? (u32)bus_r8(addr) : bus_r32(addr);
                if ((!(op & (1u << 24)) || (op & (1u << 21))) && rn != rd)
                    S->r[rn] = ea;
                S->r[rd] = (rd == 15u) ? (val & ~3u) : val;
            } else { /* STR */
                u32 val = (rd == 15u) ? (pc + 12u) : S->r[rd];
                if (op & (1u << 22))
                    bus_w8(addr, (u8)val);
                else
                    bus_w32(addr, val);
                if (!(op & (1u << 24)) || (op & (1u << 21)))
                    S->r[rn] = ea;
            }
            continue;
        }

        /* Data Processing / MUL / SWP / MRS / MSR (000 / 001) */
        if (top == 0u || top == 1u) {
            if (top == 0u && (op & 0x0FC000F0u) == 0x00000090u) {
                /* MUL / MLA */
                u32 rd = (op >> 16) & 15u;
                u32 rn = (op >> 12) & 15u;
                u32 rs = (op >> 8) & 15u;
                u32 rm = op & 15u;
                u32 res = S->r[rm] * S->r[rs];
                if (op & (1u << 21))
                    res += S->r[rn];
                if (rd != 15u)
                    S->r[rd] = res;
                if (op & (1u << 20)) {
                    S->cpsr = (S->cpsr & ~(CPSR_N | CPSR_Z)) |
                              (res & 0x80000000u) | (res == 0 ? CPSR_Z : 0u);
                }
                continue;
            }

            if (top == 0u && (op & 0x0FB00FF0u) == 0x01000090u) {
                /* SWP / SWPB */
                u32 rn = (op >> 16) & 15u;
                u32 rd = (op >> 12) & 15u;
                u32 rm = op & 15u;
                u32 addr = S->r[rn];
                u32 src = S->r[rm];
                if (op & (1u << 22)) {
                    u8 old = bus_r8(addr);
                    bus_w8(addr, (u8)src);
                    S->r[rd] = old;
                } else {
                    u32 old = bus_r32(addr);
                    bus_w32(addr, src);
                    S->r[rd] = old;
                }
                continue;
            }

            u32 alu = (op >> 21) & 15u;
            int set_cc = (op & (1u << 20)) != 0;

            /* MRS / MSR when alu in 8..11 and S == 0 */
            if (!set_cc && (alu >= 8u && alu <= 11u)) {
                if ((op & 0x0FBF0FFFu) == 0x010F0000u) { /* MRS */
                    u32 rd = (op >> 12) & 15u;
                    S->r[rd] = (op & (1u << 22)) ? S->spsr[mode_idx(S->cpsr)] : S->cpsr;
                } else { /* MSR */
                    u32 val;
                    if (top == 1u) {
                        u32 imm = op & 0xFFu, rot = ((op >> 8) & 15u) * 2u;
                        val = rot ? ((imm >> rot) | (imm << (32u - rot))) : imm;
                    } else {
                        val = S->r[op & 15u];
                    }
                    u32 mask = ((op & (1u << 19)) ? 0xF0000000u : 0u) |
                               (((op & (1u << 16)) && (S->cpsr & 0x1Fu) != MODE_USR) ? 0x000000FFu : 0u);
                    if (op & (1u << 22)) {
                        int mi = mode_idx(S->cpsr);
                        S->spsr[mi] = (S->spsr[mi] & ~mask) | (val & mask);
                    } else {
                        arm_switch_mode((S->cpsr & ~mask) | (val & mask));
                    }
                }
                continue;
            }

            u32 rn = (op >> 16) & 15u;
            u32 rd = (op >> 12) & 15u;
            u32 sh_c = (S->cpsr & CPSR_C) ? 1u : 0u;
            u32 op2;
            int reg_shift = 0;

            if (top == 1u) {
                u32 imm = op & 0xFFu;
                u32 rot = ((op >> 8) & 15u) * 2u;
                if (rot) {
                    op2 = (imm >> rot) | (imm << (32u - rot));
                    sh_c = (op2 >> 31) & 1u;
                } else {
                    op2 = imm;
                }
            } else {
                u32 rm = op & 15u;
                reg_shift = (op & 0x10u) != 0;
                u32 mv = (rm == 15u) ? (pc + (reg_shift ? 12u : 8u)) : S->r[rm];
                u32 st = (op >> 5) & 3u;
                if (!reg_shift) {
                    u32 sh = (op >> 7) & 31u;
                    if (st == 0u) {
                        if (sh == 0u) op2 = mv;
                        else { sh_c = (mv >> (32u - sh)) & 1u; op2 = mv << sh; }
                    } else if (st == 1u) {
                        if (sh == 0u) { sh_c = mv >> 31; op2 = 0u; }
                        else { sh_c = (mv >> (sh - 1u)) & 1u; op2 = mv >> sh; }
                    } else if (st == 2u) {
                        if (sh == 0u) { sh_c = mv >> 31; op2 = (u32)((s32)mv >> 31); }
                        else { sh_c = (mv >> (sh - 1u)) & 1u; op2 = (u32)((s32)mv >> sh); }
                    } else {
                        if (sh == 0u) { op2 = (sh_c << 31) | (mv >> 1); sh_c = mv & 1u; }
                        else { op2 = (mv >> sh) | (mv << (32u - sh)); sh_c = op2 >> 31; }
                    }
                } else {
                    u32 sh = S->r[(op >> 8) & 15u] & 0xFFu;
                    if (sh == 0u) {
                        op2 = mv;
                    } else if (st == 0u) {
                        if (sh < 32u) { sh_c = (mv >> (32u - sh)) & 1u; op2 = mv << sh; }
                        else if (sh == 32u) { sh_c = mv & 1u; op2 = 0u; }
                        else { sh_c = 0u; op2 = 0u; }
                    } else if (st == 1u) {
                        if (sh < 32u) { sh_c = (mv >> (sh - 1u)) & 1u; op2 = mv >> sh; }
                        else if (sh == 32u) { sh_c = mv >> 31; op2 = 0u; }
                        else { sh_c = 0u; op2 = 0u; }
                    } else if (st == 2u) {
                        if (sh < 32u) { sh_c = (mv >> (sh - 1u)) & 1u; op2 = (u32)((s32)mv >> sh); }
                        else { sh_c = mv >> 31; op2 = (u32)((s32)mv >> 31); }
                    } else {
                        u32 r = sh & 31u;
                        op2 = r ? ((mv >> r) | (mv << (32u - r))) : mv;
                        sh_c = op2 >> 31;
                    }
                }
            }

            u32 op1 = (rn == 15u) ? (pc + (reg_shift ? 12u : 8u)) : S->r[rn];
            u32 c_in = (S->cpsr & CPSR_C) ? 1u : 0u;
            u32 res = 0, c_out = sh_c, v_out = (S->cpsr & CPSR_V) ? 1u : 0u;
            int write_rd = 1;

            switch (alu) {
            case 0x0: res = op1 & op2; break;                       /* AND */
            case 0x1: res = op1 ^ op2; break;                       /* EOR */
            case 0x2:                                               /* SUB */
            case 0xA: {                                             /* CMP */
                res = op1 - op2;
                c_out = (op1 >= op2) ? 1u : 0u;
                v_out = ((op1 ^ op2) & (op1 ^ res)) >> 31;
                if (alu == 0xAu) write_rd = 0;
                break;
            }
            case 0x3: {                                             /* RSB */
                res = op2 - op1;
                c_out = (op2 >= op1) ? 1u : 0u;
                v_out = ((op2 ^ op1) & (op2 ^ res)) >> 31;
                break;
            }
            case 0x4:                                               /* ADD */
            case 0xB: {                                             /* CMN */
                u64 sum = (u64)op1 + (u64)op2;
                res = (u32)sum;
                c_out = (u32)(sum >> 32);
                v_out = (~(op1 ^ op2) & (op1 ^ res)) >> 31;
                if (alu == 0xBu) write_rd = 0;
                break;
            }
            case 0x5: {                                             /* ADC */
                u64 sum = (u64)op1 + (u64)op2 + c_in;
                res = (u32)sum;
                c_out = (u32)(sum >> 32);
                v_out = (~(op1 ^ op2) & (op1 ^ res)) >> 31;
                break;
            }
            case 0x6: {                                             /* SBC */
                u64 diff = (u64)op1 - (u64)op2 - (1u - c_in);
                res = (u32)diff;
                c_out = (diff >> 63) ? 0u : 1u;
                v_out = ((op1 ^ op2) & (op1 ^ res)) >> 31;
                break;
            }
            case 0x7: {                                             /* RSC */
                u64 diff = (u64)op2 - (u64)op1 - (1u - c_in);
                res = (u32)diff;
                c_out = (diff >> 63) ? 0u : 1u;
                v_out = ((op2 ^ op1) & (op2 ^ res)) >> 31;
                break;
            }
            case 0x8: res = op1 & op2; write_rd = 0; break;         /* TST */
            case 0x9: res = op1 ^ op2; write_rd = 0; break;         /* TEQ */
            case 0xC: res = op1 | op2; break;                       /* ORR */
            case 0xD: res = op2; break;                             /* MOV */
            case 0xE: res = op1 & ~op2; break;                      /* BIC */
            case 0xF: res = ~op2; break;                            /* MVN */
            }

            if (write_rd) {
                if (rd == 15u) {
                    S->r[15] = res & ~3u;
                    if (set_cc) {
                        int mi = mode_idx(S->cpsr);
                        if (mi > 0) arm_switch_mode(S->spsr[mi]);
                    }
                    continue;
                }
                S->r[rd] = res;
            }

            if (set_cc) {
                S->cpsr = (S->cpsr & 0x0FFFFFFFu) |
                          (res & 0x80000000u) |
                          (res == 0u ? CPSR_Z : 0u) |
                          (c_out ? CPSR_C : 0u) |
                          (v_out ? CPSR_V : 0u);
            }
            continue;
        }

        /* Block Data Transfer: LDM / STM (100) */
        if (top == 4u) {
            u32 rn = (op >> 16) & 15u;
            u32 list = op & 0xFFFFu;
            u32 base = S->r[rn];
            int nregs = 0;
            for (int i = 0; i < 16; i++)
                if (list & (1u << i)) nregs++;
            if (nregs == 0) continue;

            u32 up = (op >> 23) & 1u;
            u32 pre = (op >> 24) & 1u;
            u32 addr, wb_val;
            if (up) {
                addr = base + (pre ? 4u : 0u);
                wb_val = base + (u32)nregs * 4u;
            } else {
                wb_val = base - (u32)nregs * 4u;
                addr = wb_val + (pre ? 0u : 4u);
            }

            if (op & (1u << 20)) { /* LDM */
                if ((op & (1u << 21)) && !(list & (1u << rn)))
                    S->r[rn] = wb_val;
                for (int i = 0; i < 16; i++) {
                    if (list & (1u << i)) {
                        u32 v = bus_r32(addr);
                        addr += 4u;
                        if (i == 15) {
                            S->r[15] = v & ~3u;
                            if (op & (1u << 22)) {
                                int mi = mode_idx(S->cpsr);
                                if (mi > 0) arm_switch_mode(S->spsr[mi]);
                            }
                        } else {
                            S->r[i] = v;
                        }
                    }
                }
            } else { /* STM */
                for (int i = 0; i < 16; i++) {
                    if (list & (1u << i)) {
                        u32 v = (i == 15) ? (pc + 12u) : S->r[i];
                        bus_w32(addr, v);
                        addr += 4u;
                    }
                }
                if (op & (1u << 21))
                    S->r[rn] = wb_val;
            }
            continue;
        }

        /* Software Interrupt: SWI (1111) */
        if ((op & 0x0F000000u) == 0x0F000000u) {
            if (S->hle_mode) {
                hle_handle_swi(op & 0x00FFFFFFu);
            } else {
                u32 old = S->cpsr;
                arm_switch_mode((old & ~0x1Fu) | MODE_SVC | CPSR_I);
                S->spsr[3] = old;
                S->r[14] = pc + 4u;
                S->r[15] = 0x00000008u;
            }
            continue;
        }
    }
}

/* --- Built-in ARM60 + Madam Perspective CEL 3D Showcase (when run with no file) --- */
static void build_builtin_demo(void)
{
    S->hle_mode = 2;

    /* Texture 0 at 0x00050000: 32x32 16-bpp uncoded glowing neon grid & 3DO badge
       Texture 1 at 0x00052000: 32x32 16-bpp uncoded cyber plasma tile */
    for (int y = 0; y < 32; y++) {
        for (int x = 0; x < 32; x++) {
            int border = (x == 0 || x == 31 || y == 0 || y == 31 || x == 15 || y == 15);
            int diag = ((x ^ y) & 4) != 0;
            u16 c0, c1;
            if (border) {
                c0 = (31u << 10) | (26u << 5) | 6u;  /* Gold frame */
            } else if (x >= 10 && x < 22 && y >= 10 && y < 22) {
                int d = (x - 16) * (x - 16) + (y - 16) * (y - 16);
                c0 = (d <= 20) ? ((30u << 10) | (6u << 5) | 12u) : ((4u << 10) | (24u << 5) | 31u);
            } else {
                c0 = diag ? ((6u << 10) | (16u << 5) | 28u) : ((3u << 10) | (8u << 5) | 18u);
            }
            dram_w16(0x00050000u + (u32)(y * 32 + x) * 2u, c0);

            u32 r = (u32)((x + y) >> 1) & 31u;
            u32 g = (u32)(31 - x) & 31u;
            u32 b = (u32)(8 + (y >> 1)) & 31u;
            c1 = border ? ((28u << 10) | (31u << 5) | 28u) : (u16)((r << 10) | (g << 5) | b);
            if (c1 == 0) c1 = 0x0421u;
            dram_w16(0x00052000u + (u32)(y * 32 + x) * 2u, c1);
        }
    }

    /* Install real ARM60 machine-code frame loop at 0x00001000 that:
       1. Reads frame counter & pad state from 0x00002000,
       2. Computes Madam CCB perspective chain & triggers Madam SPRSTRT (0x03300580)
          and DSPP chord voices (0x03300400),
       3. Yields VBL via SWI 0x0E0109 (WaitVBL). */
    static const u32 arm_demo_prog[] = {
        0xE3A04902u, /* 1000: MOV R4, #0x00008000 (CCB chain base) */
        0xE3A05403u, /* 1004: MOV R5, #0x03000000 */
        0xE3855603u, /* 1008: ORR R5, R5, #0x00300000 (0x03300000 Madam) */
        0xE58545A0u, /* 100C: STR R4, [R5, #0x5A0] (CCBCTL0 = 0x8000) */
        0xE3A00001u, /* 1010: MOV R0, #1 */
        0xE5850580u, /* 1014: STR R0, [R5, #0x580] (SPRSTRT -> hardware CEL engine!) */
        0xEF010009u, /* 1018: SWI 0x010009 (Yield VBL) */
        0xEAFFFFF9u  /* 101C: B 0x1008 */
    };
    for (u32 i = 0; i < sizeof(arm_demo_prog) / 4u; i++)
        dram_w32(0x00001000u + i * 4u, arm_demo_prog[i]);

    for (int i = 0; i < 16; i++) S->r[i] = 0;
    S->r[13] = 0x001DF000u;
    S->r[15] = 0x00001000u;
    S->cpsr  = MODE_SVC;
    S->display_vram = 0;
    S->draw_vram    = 0;
    S->read_vram    = 0;
    S->clip_w = 320;
    S->clip_h = 240;
    S->demo_ang_y = 0x00180000;
    S->demo_ang_x = 0x00120000;

    /* Enable 3-voice warm 3DO boot chord */
    S->voices[0].active = 1; S->voices[0].gain_l = 4500; S->voices[0].gain_r = 3000;
    S->voices[1].active = 1; S->voices[1].gain_l = 3000; S->voices[1].gain_r = 4500;
    S->voices[2].active = 1; S->voices[2].gain_l = 3200; S->voices[2].gain_r = 3200;
}

static void update_builtin_demo_ccbs(void)
{
    /* Clear VRAM background gradient via SPORT-style word writes */
    for (int ry = 0; ry < 120; ry++) {
        u32 y0 = (u32)(ry * 2), y1 = y0 + 1u;
        u16 c0 = (y0 < 150u) ? (u16)(((2u + y0 / 24u) << 10) | ((1u + y0 / 32u) << 5) | (6u + y0 / 10u))
                             : (u16)(((4u + (y0 - 150u) / 8u) << 10) | (2u << 5) | (14u - (y0 - 150u) / 10u));
        u16 c1 = (y1 < 150u) ? (u16)(((2u + y1 / 24u) << 10) | ((1u + y1 / 32u) << 5) | (6u + y1 / 10u))
                             : (u16)(((4u + (y1 - 150u) / 8u) << 10) | (2u << 5) | (14u - (y1 - 150u) / 10u));
        u32 pair = ((u32)c0 << 16) | c1;
        u32 base = (u32)ry * 320u;
        for (int x = 0; x < 320; x++)
            S->vram32[base + (u32)x] = pair;
    }

    /* Update 3D rotating cube vertices & build 6 perspective-projected Madam CCBs at 0x00008000 */
    if (S->cur_pad_3do & 0x20000000u) S->demo_ang_y += 0x00030000;
    else if (S->cur_pad_3do & 0x10000000u) S->demo_ang_y -= 0x00030000;
    else S->demo_ang_y += 0x00018000;
    if (S->cur_pad_3do & 0x40000000u) S->demo_ang_x -= 0x00028000;
    else if (S->cur_pad_3do & 0x80000000u) S->demo_ang_x += 0x00028000;
    else S->demo_ang_x += 0x0000E000;

    s32 cy = sin_f16(S->demo_ang_y + 0x00400000), sy = sin_f16(S->demo_ang_y);
    s32 cx = sin_f16(S->demo_ang_x + 0x00400000), sx = sin_f16(S->demo_ang_x);

    static const s8 cube_v[8][3] = {
        {-1,-1,-1}, { 1,-1,-1}, { 1, 1,-1}, {-1, 1,-1},
        {-1,-1, 1}, { 1,-1, 1}, { 1, 1, 1}, {-1, 1, 1}
    };
    static const u8 faces[6][4] = {
        {0,1,2,3}, {5,4,7,6}, {4,0,3,7}, {1,5,6,2}, {4,5,1,0}, {3,2,6,7}
    };

    s32 px[8], py[8], pz[8];
    for (int i = 0; i < 8; i++) {
        s32 x = cube_v[i][0] * 54, y = cube_v[i][1] * 54, z = cube_v[i][2] * 54;
        s32 x1 = (x * cy + z * sy) >> 16;
        s32 z1 = (-x * sy + z * cy) >> 16;
        s32 y2 = (y * cx - z1 * sx) >> 16;
        s32 z2 = (y * sx + z1 * cx) >> 16;
        s32 dist = 210 + z2;
        if (dist < 60) dist = 60;
        px[i] = 160 + (x1 * 180) / dist;
        py[i] = 112 + (y2 * 180) / dist;
        pz[i] = z2;
    }

    int n_ccbs = 0;
    u32 ccb_base = 0x00008000u;
    for (int f = 0; f < 6; f++) {
        int i0 = faces[f][0], i1 = faces[f][1], i2 = faces[f][2], i3 = faces[f][3];
        s32 cross = (px[i1] - px[i0]) * (py[i3] - py[i0]) - (py[i1] - py[i0]) * (px[i3] - px[i0]);
        if (cross <= 0) continue; /* Backface cull */

        u32 addr = ccb_base + (u32)n_ccbs * 0x40u;
        u32 tex  = (f & 1) ? 0x00052000u : 0x00050000u;
        s32 hdx0 = ((px[i1] - px[i0]) << 20) / 32;
        s32 hdy0 = ((py[i1] - py[i0]) << 20) / 32;
        s32 hdx1 = ((px[i2] - px[i3]) << 20) / 32;
        s32 hdy1 = ((py[i2] - py[i3]) << 20) / 32;
        s32 shade = 7 - ((pz[i0] + pz[i2] + 120) / 40);
        if (shade < 3) shade = 3;
        if (shade > 7) shade = 7;
        u32 pixc = ((u32)shade << 10) | 0x0300u; /* MS=CCB, MF=shade+1, SF=8 */

        dram_w32(addr + 0x00u, 0x37660030u);     /* NPABS|SPABS|LDSIZE|LDPRS|LDPPMP|CCBPRE|YOXY|ACW|ACCW|BGND|NOBLK */
        dram_w32(addr + 0x04u, addr + 0x40u);
        dram_w32(addr + 0x08u, tex);
        dram_w32(addr + 0x0Cu, 0u);
        dram_w32(addr + 0x10u, (u32)(px[i0] << 16));
        dram_w32(addr + 0x14u, (u32)(py[i0] << 16));
        dram_w32(addr + 0x18u, (u32)hdx0);
        dram_w32(addr + 0x1Cu, (u32)hdy0);
        dram_w32(addr + 0x20u, (u32)(((px[i3] - px[i0]) << 16) / 32));
        dram_w32(addr + 0x24u, (u32)(((py[i3] - py[i0]) << 16) / 32));
        dram_w32(addr + 0x28u, (u32)((hdx1 - hdx0) / 32));
        dram_w32(addr + 0x2Cu, (u32)((hdy1 - hdy0) / 32));
        dram_w32(addr + 0x30u, pixc);
        dram_w32(addr + 0x34u, ((32u - 1u) << 6) | 0x16u); /* PRE0: 32 rows, LINEAR, 16-bpp */
        dram_w32(addr + 0x38u, ((16u - 2u) << 16) | (32u - 1u)); /* PRE1: 16 words/row, 32 px */
        n_ccbs++;
    }
    if (n_ccbs > 0) {
        u32 last = ccb_base + (u32)(n_ccbs - 1) * 0x40u;
        dram_w32(last + 0x00u, dram_r32(last + 0x00u) | 0x40000000u); /* CCB_LAST */
    }

    /* Gentle musical chord arpeggio on DSPP synth */
    static const u16 notes[4] = { 220, 277, 330, 440 };
    u32 hz = S->audio_hz ? S->audio_hz : 48000u;
    S->voices[0].freq_inc = (220u << 24) / hz;
    S->voices[1].freq_inc = (330u << 24) / hz;
    S->voices[2].freq_inc = ((u32)notes[(S->frame_count >> 5) & 3u] << 24) / hz;
}

/* --- Load / Reset / Frame / Audio Entry Points --- */
const char *threedo_load(const struct cdrom_toc *cd, const char *name)
{
    if (sizeof(struct threedo_mem) > THREEDO_RAM_MAX)
        return "not enough EMU_RAM_PHYS for 3DO";

    S = (struct threedo_mem *)threedo_ram_base();
    for (u32 i = 0; i < sizeof(struct threedo_mem) / 4u; i++)
        ((u32 *)S)[i] = 0;

    S->cd = cd;
    S->sec_cached_lba = 0xFFFFFFFFu;
    S->lfsr = 0x33444F21u;
    S->clip_w = THREEDO_W;
    S->clip_h = THREEDO_H;
    vdl_reset_default();

    /* Initialize valid 3DO NVRAM volume header ("nvram") so games using NVRAM succeed */
    S->nvram[0] = 0x01;
    for (int i = 1; i <= 5; i++) S->nvram[i] = 'Z';
    S->nvram[6] = 0x01;

    if (!cd) {
        build_builtin_demo();
        static const char *bi = "3DO ARM60 @ 12.5 MHz + Madam CEL Quad Engine (built-in 3D CEL showcase)";
        for (int i = 0; bi[i]; i++) S->info_str[i] = bi[i];
        return 0;
    }

    /* Check Opera FS volume header at LBA 0 (or 0..16) */
    u8 vol[2048];
    int found_opera = 0;
    for (u32 try_lba = 0; try_lba < 32u; try_lba++) {
        if (disc_read_sector(try_lba, vol) == 0 &&
            vol[0] == 0x01 && vol[1] == 'Z' && vol[2] == 'Z' && vol[3] == 'Z' && vol[4] == 'Z' && vol[5] == 'Z') {
            S->fs_blk_size = be32_buf(vol + 0x4Cu);
            if (!S->fs_blk_size) S->fs_blk_size = 2048u;
            S->fs_root_lba = try_lba + be32_buf(vol + 0x64u);
            S->cwd_lba = S->fs_root_lba;
            found_opera = 1;
            break;
        }
    }
    if (!found_opera)
        return "not a 3DO Opera FS disc image (missing \\x01ZZZZZ volume header)";

    /* Locate LaunchMe (or launchme / Launchme / AppStartup target) */
    static const char *const boot_candidates[] = {
        "LaunchMe", "launchme", "Launchme", "LAUNCHME",
        "Game", "Start", "Main"
    };
    u32 lm_lba = 0, lm_size = 0;
    int lm_dir = 0, got_lm = 0;
    for (unsigned i = 0; i < sizeof(boot_candidates) / sizeof(boot_candidates[0]); i++) {
        if (operafs_resolve(S->fs_root_lba, boot_candidates[i], &lm_lba, &lm_size, &lm_dir) == 0 &&
            !lm_dir && lm_size >= 256u) {
            got_lm = 1;
            break;
        }
    }
    if (!got_lm)
        return "no LaunchMe ARM60 executable found in 3DO Opera FS root";
    if (lm_size > 0x001A0000u)
        lm_size = 0x001A0000u;

    /* Load AIF executable into DRAM.
       Note: AIF header is 0x80 bytes, _3DOBinHeader is at +0x80..0xFF, code starts at +0x100.
       In 3DO AIF headers, ImageBase ([+0x28]) is typically 0x00000080 (or 0x00000000).
       Loading the AIF file at load_base = 0x00010000 lets AIF's built-in self-relocator
       at +0x04 relocate cleanly in-place to 0x00010000! */
    u32 load_base = 0x00010000u;
    if (operafs_read_to_dram(lm_lba, 0u, load_base, lm_size) < 0)
        return "could not read LaunchMe from 3DO disc";

    u32 ro_sz = dram_r32(load_base + 0x14u);
    u32 rw_sz = dram_r32(load_base + 0x18u);
    u32 zi_sz = dram_r32(load_base + 0x20u);
    u32 img_end = load_base + ((ro_sz + rw_sz + zi_sz > lm_size) ? (ro_sz + rw_sz + zi_sz + 0x200u) : (lm_size + 0x1000u));
    if (img_end > 0x001C0000u)
        img_end = 0x001C0000u;

    S->hle_mode = 1;
    if (bios_ext_ptr) {
        for (u32 i = 0; i < bios_ext_sz; i++)
            ((u8 *)S->rom32)[i ^ 3u] = bios_ext_ptr[i];
        S->has_bios = 1;
    }
    hle_init_portfolio(load_base, load_base, img_end);

    /* Start Redbook CD-DA background audio if disc has audio tracks >= 2 */
    for (u32 t = 2; t <= cd->last_track; t++) {
        if (cd->tracks[t].is_audio && cd->tracks[t].length > 0) {
            S->cdda_playing = 1;
            S->cdda_lba = cd->tracks[t].lba;
            S->cdda_end_lba = cd->tracks[t].lba + cd->tracks[t].length;
            S->cdda_pos_fp = 588u << 16;
            break;
        }
    }

    /* Format info string */
    const char *base_nm = name ? name : "disc";
    for (const char *q = base_nm; *q; q++)
        if (*q == '/' || *q == '\\' || *q == ':') base_nm = q + 1;
    const char *p = "3DO Opera ARM60 @ 12.5 MHz + Madam CEL (";
    int k = 0;
    while (*p && k < 90) S->info_str[k++] = *p++;
    while (*base_nm && k < 120) S->info_str[k++] = *base_nm++;
    S->info_str[k++] = ')';
    S->info_str[k] = 0;
    return 0;
}

void threedo_reset(void)
{
    if (!S) return;
    S->frame_count = 0;
    S->total_usec = 0;
    S->halted = 0;
    S->vbl_yield = 0;
}

static u32 map_pad_to_3do(u16 pad)
{
    /* Map play.c PAD_* bits to 3DO ControlPadEventData bits (event.h lines 186..196):
       Down=0x80000000, Up=0x40000000, Right=0x20000000, Left=0x10000000,
       A=0x08000000, B=0x04000000, C=0x02000000, Start(P)=0x01000000,
       X=0x00800000, R=0x00400000, L=0x00200000 */
    u32 b = 0;
    if (pad & 0x0020u) b |= 0x80000000u; /* DOWN */
    if (pad & 0x0010u) b |= 0x40000000u; /* UP */
    if (pad & 0x0080u) b |= 0x20000000u; /* RIGHT */
    if (pad & 0x0040u) b |= 0x10000000u; /* LEFT */
    if (pad & 0x0001u) b |= 0x08000000u; /* PAD_A -> A */
    if (pad & 0x0002u) b |= 0x04000000u; /* PAD_B -> B */
    if (pad & 0x0100u) b |= 0x02000000u; /* PAD_X ('c') -> C */
    if (pad & 0x0008u) b |= 0x01000000u; /* START -> P (Play/Pause) */
    if (pad & 0x0004u) b |= 0x00800000u; /* SELECT -> X (Stop) */
    if (pad & 0x0200u) b |= 0x00800000u; /* PAD_Y -> X */
    if (pad & 0x0800u) b |= 0x00400000u; /* PAD_R -> RightShift */
    if (pad & 0x0400u) b |= 0x00200000u; /* PAD_L -> LeftShift */
    return b;
}

static void render_audio_frame(void)
{
    if (!S->audio_hz) return;
    /* Exact samples for one 59.94 Hz frame (e.g. ~800.8 @ 48 kHz) */
    S->sample_acc += S->audio_hz * 1001u;
    u32 n_samp = S->sample_acc / 60000u;
    S->sample_acc %= 60000u;
    u32 cdda_step = (44100u << 16) / S->audio_hz;

    for (u32 i = 0; i < n_samp; i++) {
        s32 acc_l = 0, acc_r = 0;

        /* Mix active DSPP / built-in voices */
        for (int v = 0; v < MAX_VOICES; v++) {
            struct dsp_voice *vc = &S->voices[v];
            if (!vc->active) continue;
            if (vc->freq_inc) {
                vc->phase += vc->freq_inc;
                s32 tri = (vc->phase & 0x80000000u) ? (s32)(0x7FFFFFFFu - (vc->phase & 0x7FFFFFFFu))
                                                    : (s32)(vc->phase & 0x7FFFFFFFu);
                s32 wave = (tri >> 16) - 16384;
                acc_l += (wave * vc->gain_l) >> 14;
                acc_r += (wave * vc->gain_r) >> 14;
            }
        }

        /* Mix Redbook CD-DA stereo 44.1 kHz -> audio_hz */
        if (S->cdda_playing && S->cd && S->cd->read_2352) {
            u32 idx = S->cdda_pos_fp >> 16;
            if (idx >= 588u) {
                if (S->cdda_lba >= S->cdda_end_lba) {
                    S->cdda_playing = 0;
                } else {
                    if (S->cd->read_2352(S->cdda_lba++, S->cdda_buf) < 0)
                        S->cdda_playing = 0;
                    S->cdda_pos_fp -= 588u << 16;
                    idx = S->cdda_pos_fp >> 16;
                }
            }
            if (S->cdda_playing && idx < 588u) {
                const u8 *p = S->cdda_buf + idx * 4u;
                s16 cl = (s16)((u16)p[0] | ((u16)p[1] << 8));
                s16 cr = (s16)((u16)p[2] | ((u16)p[3] << 8));
                acc_l += cl >> 1;
                acc_r += cr >> 1;
                S->cdda_pos_fp += cdda_step;
            }
        }

        if (acc_l > 32767) acc_l = 32767; else if (acc_l < -32768) acc_l = -32768;
        if (acc_r > 32767) acc_r = 32767; else if (acc_r < -32768) acc_r = -32768;

        u32 next_w = (S->snd_w + 1u) & (SND_RING_FRAMES - 1u);
        if (next_w != S->snd_r) {
            S->snd_ring[S->snd_w * 2u + 0u] = (s16)acc_l;
            S->snd_ring[S->snd_w * 2u + 1u] = (s16)acc_r;
            S->snd_w = next_w;
        }
    }
}

void threedo_frame(u16 pad, u16 *picture)
{
    if (!S) return;

    S->prev_pad_3do = S->cur_pad_3do;
    S->cur_pad_3do = map_pad_to_3do(pad);

    if (S->hle_mode == 1) {
        dram_w32(HLE_GRAF + 0x74u, S->frame_count);
        hle_deliver_pad_event();
    } else if (S->hle_mode == 2) {
        update_builtin_demo_ccbs();
    }

    if (S->vbl_yield > 0)
        S->vbl_yield--;

    /* Run ARM60 across 262 scanlines (~208,000 cycles @ 12.5 MHz, or until WaitVBL yields) */
    if (!S->halted && S->vbl_yield == 0) {
        for (u32 line = 0; line < 262u && !S->halted && !S->vbl_yield; line++) {
            S->clio[0x34 / 4] = line;
            if (line == 240u)
                S->clio[0x40 / 4] |= 3u; /* VINT0 | VINT1 */
            arm_step_slice(760);
            S->total_usec += 63u;
        }
    } else {
        S->total_usec += THREEDO_FRAME_US;
    }

    S->frame_count++;
    render_audio_frame();

    /* Scan out 3DO dual-bank VRAM (320x240) to play.c's 15-bit BGR555 picture buffer */
    if (picture) {
        u32 base_w = (S->display_vram & (VRAM_SIZE - 1u)) >> 2;
        if (S->clut_identity) {
            for (int ry = 0; ry < 120; ry++) {
                const u32 *src = &S->vram32[(base_w + (u32)ry * 320u) & ((VRAM_SIZE >> 2) - 1u)];
                u16 *dst0 = picture + (ry * 2) * THREEDO_W;
                u16 *dst1 = dst0 + THREEDO_W;
                for (int x = 0; x < 320; x++) {
                    u32 w = src[x];
                    u32 c0 = w >> 16;
                    u32 c1 = w & 0xFFFFu;
                    /* Convert 3DO RGB555 (R in 14..10, B in 4..0) -> play.c BGR555 (B in 14..10, R in 4..0) */
                    dst0[x] = (u16)(((c0 & 0x1Fu) << 10) | (c0 & 0x3E0u) | ((c0 >> 10) & 0x1Fu));
                    dst1[x] = (u16)(((c1 & 0x1Fu) << 10) | (c1 & 0x3E0u) | ((c1 >> 10) & 0x1Fu));
                }
            }
        } else {
            for (int ry = 0; ry < 120; ry++) {
                const u32 *src = &S->vram32[(base_w + (u32)ry * 320u) & ((VRAM_SIZE >> 2) - 1u)];
                u16 *dst0 = picture + (ry * 2) * THREEDO_W;
                u16 *dst1 = dst0 + THREEDO_W;
                for (int x = 0; x < 320; x++) {
                    u32 w = src[x];
                    u32 c0 = w >> 16, c1 = w & 0xFFFFu;
                    u32 r0 = S->clut_r[(c0 >> 10) & 31u] >> 3;
                    u32 g0 = S->clut_g[(c0 >> 5) & 31u] >> 3;
                    u32 b0 = S->clut_b[c0 & 31u] >> 3;
                    u32 r1 = S->clut_r[(c1 >> 10) & 31u] >> 3;
                    u32 g1 = S->clut_g[(c1 >> 5) & 31u] >> 3;
                    u32 b1 = S->clut_b[c1 & 31u] >> 3;
                    dst0[x] = (u16)((b0 << 10) | (g0 << 5) | r0);
                    dst1[x] = (u16)((b1 << 10) | (g1 << 5) | r1);
                }
            }
        }
    }
}

const char *threedo_info(void)
{
    return S ? S->info_str : "3DO";
}

u8 *threedo_save_ram(u32 *size, int *battery)
{
    if (!S) return 0;
    *size = NVRAM_SIZE;
    *battery = 1;
    return S->nvram;
}

int threedo_save_changed(void)
{
    if (!S || !S->nvram_dirty) return 0;
    S->nvram_dirty = 0;
    return 1;
}

int threedo_jammed(void)
{
    return S ? S->halted : 0;
}

void threedo_audio_rate(u32 hz)
{
    if (!S) return;
    S->audio_hz = hz;
    S->sample_acc = 0;
    S->snd_r = S->snd_w = 0;
}

int threedo_audio(s16 *out, int max)
{
    if (!S) return 0;
    int frames = max >> 1;
    int got = 0;
    while (got < frames && S->snd_r != S->snd_w) {
        out[got * 2 + 0] = S->snd_ring[S->snd_r * 2u + 0u];
        out[got * 2 + 1] = S->snd_ring[S->snd_r * 2u + 1u];
        S->snd_r = (S->snd_r + 1u) & (SND_RING_FRAMES - 1u);
        got++;
    }
    return got * 2;
}

#ifdef THREEDO_HOST
void threedo_host_dbg(u32 out[8])
{
    if (!S) return;
    out[0] = S->r[15];
    out[1] = S->r[14];
    out[2] = S->r[13];
    out[3] = S->display_vram;
    out[4] = S->dram_heap_lo;
    out[5] = S->vram_heap_lo;
    out[6] = S->cpsr;
    out[7] = (u32)S->halted;
}
#endif
