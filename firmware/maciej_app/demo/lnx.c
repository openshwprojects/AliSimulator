/* An Atari Lynx (.lnx / .lyx / BLL .o): see lnx.h. */
#pragma GCC optimize("O2")
#include "lnx.h"

#ifdef LNX_HOST
typedef unsigned long long u64;
#else
#include "hw.h"
#endif

#define INLINE static inline __attribute__((always_inline))

/* Clock & frame timing:
   16 MHz crystal; 65SC02 runs at ~4 MHz average (~66,667 cycles / 60 Hz frame).
   Mikey base timer prescaler ticks every 1 us (1 MHz = 4 CPU cycles). */
#define LNX_CPU_HZ       4000000u
#define FRAME_CPU_CYC    66667
#define SLICES_PER_FRAME 264             /* ~252 CPU cyc (~63 us) per timer/audio slice */
#define SLICE_CPU_CYC    252
#define SLICE_US         63

/* 65SC02 flags */
#define FN 0x80u
#define FV 0x40u
#define FB 0x10u
#define FD 0x08u
#define FI 0x04u
#define FZ 0x02u
#define FC 0x01u

/* Rotation flags in .lnx header byte 58 */
#define ROT_NONE         0
#define ROT_LEFT         1
#define ROT_RIGHT        2

#define SND_RING         8192

struct lnx_timer {
    u8 backup, ctla, cnt, ctlb;
    u32 acc_us;
};

struct lnx_audio_ch {
    s8 vol;
    u8 feed, bkup, ctla, cnt, ctlb;
    s8 out;
    u16 shift;
    u32 acc_us;
};

/* Placed in EMU_RAM_PHYS after a78_mem or at base (only one machine runs at a time in play.c!) */
struct lnx_mem {
    u8 ram[0x10000];                     /* 64 KB Lynx unified system/video RAM */
    u8 bios[0x200];                      /* 512-byte boot ROM ($FE00..$FFFF) */
    u8 suzy[0x100];                      /* Suzy registers ($FC00..$FCFF) */
    u8 mikey[0x100];                     /* Mikey registers ($FD00..$FDFF) */
    u8 sram[0x2000];                     /* Optional EEPROM / cart save RAM */
    u16 rot_buf[LNX_H][LNX_W];           /* Scratch buffer for portrait-rotated games */
    s16 snd_ring[SND_RING];              /* 48 kHz mono output ring */
};

#ifdef LNX_HOST
static struct lnx_mem lnx_host_mem;
#define M (&lnx_host_mem)
#else
#define M ((struct lnx_mem *)KSEG0(EMU_RAM_PHYS))
#endif

static struct {
    const u8 *rom;                       /* Cartridge payload (past 64B .lnx header if present) */
    u32 rom_size;
    const u8 *bank0, *bank1;
    u32 bank0_size, bank1_size;
    u32 page_b0, page_b1;
    u8 audin_banked;
    u8 is_bll_o;                         /* 1 if raw BLL .o binary ($80 $08 header) */
    u16 bll_load_addr, bll_load_len;
    u8 rotation;

    const u8 *ext_bios;
    u32 ext_bios_size;
    int using_hle_bios;

    /* WDC 65SC02 CPU */
    u16 pc;
    u8 a, x, y, sp, p;
    s32 cyc;
    u8 mapctl;                           /* $FFF9 memory overlay register */
    u8 cpu_asleep;                       /* WAI or Mikey CPUSLEEP */
    u8 suzy_done_wakeup;                 /* Set when SPRGO finishes; cleared by SDONEACK/CPUSLEEP */
    u8 spr_pending;
    s8 spr_countdown;
    u8 jammed;

    /* Cartridge address shifter & ripple counter */
    u8 sysctl1, iodir, iodat;
    u8 cart_shifter;
    u32 cart_offset;

    /* Mikey timers, interrupts & audio */
    struct lnx_timer tmr[8];
    struct lnx_audio_ch aud[4];
    u8 irq_flags;                        /* Mikey pending timer IRQ mask */
    u8 atten[4], mpan, mstereo;
    u16 dispadr;
    u8 dispctl;
    u16 pal_bgr[16];                     /* Precomputed 15-bit BGR555 palette from GCOLMAP/RBCOLMAP */

    /* Suzy math unit */
    u8 sprsys_r;                         /* Read status: MATHWARNING, MATHCARRY, LEFTHANDED, etc. */
    u8 sprsys_w;                         /* Write flags: SIGNMATH, ACCUMULATE, NO_COLLIDE, VSTRETCH */
    u8 last_pen_map[16];                 /* Sticky SCB palette pen index table */

    u16 pad;

    /* Audio resampler */
    u32 snd_rate;
    u32 snd_phase;
    u32 snd_rd, snd_wr;

    int save_dirty;
    char title[40];
    char info[128];
} S;

static void mem_zero(void *dst, u32 n)
{
    u8 *p = (u8 *)dst;
    for (u32 i = 0; i < n; i++)
        p[i] = 0;
}

static void mem_copy(void *dst, const void *src, u32 n)
{
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    for (u32 i = 0; i < n; i++)
        d[i] = s[i];
}

/* ---- Clean-room 408-bit (51-byte) RSA Public-Key Cartridge Verification (m = c^3 mod N) ----
   Public modulus N (big-endian) from open-source BLL / cc65 Lynx documentation. */
static const u8 lynx_pub_mod_be[51] = {
    0x35, 0xB5, 0xA3, 0x94, 0x28, 0x06, 0xD8, 0xA2,
    0x26, 0x95, 0xD7, 0x71, 0xB2, 0x3C, 0xFD, 0x56,
    0x1C, 0x4A, 0x19, 0xB6, 0xA3, 0xB0, 0x26, 0x00,
    0x36, 0x5A, 0x30, 0x6E, 0x3C, 0x4D, 0x63, 0x38,
    0x1B, 0xD4, 0x1C, 0x13, 0x64, 0x89, 0x36, 0x4C,
    0xF2, 0xBA, 0x2A, 0x58, 0xF4, 0xFE, 0xE1, 0xFD,
    0xAC, 0x7E, 0x79
};

/* Compute out[0..50] = (a[0..50] * b[0..50]) mod n[0..50] in little-endian byte arrays */
static void bn51_mul_mod(u8 *out, const u8 *a, const u8 *b, const u8 *n)
{
    u8 prod[104];
    mem_zero(prod, sizeof(prod));

    for (int i = 0; i < 51; i++) {
        u32 carry = 0;
        u32 ai = a[i];
        for (int j = 0; j < 51; j++) {
            u32 t = prod[i + j] + ai * (u32)b[j] + carry;
            prod[i + j] = (u8)t;
            carry = t >> 8;
        }
        prod[i + 51] = (u8)(prod[i + 51] + carry);
    }

    /* Bit-by-bit shift-and-subtract remainder rem = prod mod n (MSB to LSB across 102 bytes) */
    u8 rem[52];
    mem_zero(rem, sizeof(rem));
    for (int bit = 102 * 8 - 1; bit >= 0; bit--) {
        u32 in_bit = (prod[bit >> 3] >> (bit & 7)) & 1u;
        for (int k = 51; k > 0; k--)
            rem[k] = (u8)((rem[k] << 1) | (rem[k - 1] >> 7));
        rem[0] = (u8)((rem[0] << 1) | in_bit);

        /* Compare rem[0..51] >= n[0..50] */
        int ge = (rem[51] > 0);
        if (!ge) {
            ge = 1;
            for (int k = 50; k >= 0; k--) {
                if (rem[k] != n[k]) {
                    ge = (rem[k] > n[k]);
                    break;
                }
            }
        }
        if (ge) {
            u32 borrow = 0;
            for (int k = 0; k < 51; k++) {
                s32 d = (s32)rem[k] - (s32)n[k] - (s32)borrow;
                rem[k] = (u8)d;
                borrow = (d < 0) ? 1u : 0u;
            }
            rem[51] = (u8)(rem[51] - borrow);
        }
    }
    mem_copy(out, rem, 51);
}

static u8 rcart0_read(void);

/* Decrypt one RSA frame from RCART0 into M->ram[dst_addr..]. Returns 1 on valid frame. */
static int decrypt_cart_frame(u16 dst_addr)
{
    u8 mod_le[51];
    for (int i = 0; i < 51; i++)
        mod_le[i] = lynx_pub_mod_be[50 - i];

    u8 cnt_byte = rcart0_read();
    int blocks = 256 - (int)cnt_byte;
    if (blocks < 1 || blocks > 5)
        return 0;

    u8 acc = 0;
    for (int b = 0; b < blocks; b++) {
        u8 enc[51], sq[51], res[51];
        for (int i = 0; i < 51; i++)
            enc[i] = rcart0_read();
        bn51_mul_mod(sq, enc, enc, mod_le);
        bn51_mul_mod(res, sq, enc, mod_le);
        /* res[0..49] are the 50 de-reversed delta bytes in ascending order! */
        for (int i = 0; i < 50; i++) {
            acc = (u8)(acc + res[i]);
            M->ram[(u16)(dst_addr + (u16)(b * 50 + i))] = acc;
        }
    }
    return 1;
}

/* ---- Cartridge Reading ---- */
static u8 rcart0_read(void)
{
    u8 val = 0xFFu;
    if (S.bank0 && S.bank0_size > 0 && S.page_b0 > 0) {
        u32 idx = (u32)S.cart_shifter * S.page_b0 + (S.cart_offset & (S.page_b0 - 1u));
        if (S.audin_banked && (S.iodat & 0x10u))
            idx += 256u * S.page_b0;
        if (idx < S.bank0_size)
            val = S.bank0[idx];
    }
    if (!(S.sysctl1 & 0x01u))
        S.cart_offset++;
    return val;
}

static u8 rcart1_read(void)
{
    u8 val = 0xFFu;
    if (S.bank1 && S.bank1_size > 0 && S.page_b1 > 0) {
        u32 idx = (u32)S.cart_shifter * S.page_b1 + (S.cart_offset & (S.page_b1 - 1u));
        if (idx < S.bank1_size)
            val = S.bank1[idx];
    }
    if (!(S.sysctl1 & 0x01u))
        S.cart_offset++;
    return val;
}

/* ---- Suzy Hardware Math Co-processor ---- */
INLINE u16 suzy16(u32 off)
{
    return (u16)(M->suzy[off] | ((u16)M->suzy[off + 1u] << 8));
}

INLINE void set_suzy16(u32 off, u16 v)
{
    M->suzy[off]      = (u8)v;
    M->suzy[off + 1u] = (u8)(v >> 8);
}

static void suzy_multiply(void)
{
    /* AB ($FC54=B low, $FC55=A high) * CD ($FC52=D low, $FC53=C high) -> EFGH ($FC60=H..$FC63=E) */
    S.sprsys_r &= (u8)~0x60u;
    u16 ab = suzy16(0x54);
    u16 cd = suzy16(0x52);
    u32 res;

    if (S.sprsys_w & 0x80u) {
        /* Signed multiply: Suzy converts magnitudes and tracks sign */
        s32 sab = (s16)ab;
        s32 scd = (s16)cd;
        s32 prod = sab * scd;
        res = (u32)prod;
    } else {
        res = (u32)ab * (u32)cd;
    }

    M->suzy[0x60] = (u8)res;
    M->suzy[0x61] = (u8)(res >> 8);
    M->suzy[0x62] = (u8)(res >> 16);
    M->suzy[0x63] = (u8)(res >> 24);

    if (S.sprsys_w & 0x40u) {
        /* Accumulate into JKLM ($FC6C=M low .. $FC6F=J high) */
        u32 jklm = (u32)M->suzy[0x6C] | ((u32)M->suzy[0x6D] << 8) |
                   ((u32)M->suzy[0x6E] << 16) | ((u32)M->suzy[0x6F] << 24);
        u64 sum = (u64)jklm + (u64)res;
        if (sum >> 32)
            S.sprsys_r |= 0x60u;         /* MATHWARNING + MATHCARRY */
        u32 r32 = (u32)sum;
        M->suzy[0x6C] = (u8)r32;
        M->suzy[0x6D] = (u8)(r32 >> 8);
        M->suzy[0x6E] = (u8)(r32 >> 16);
        M->suzy[0x6F] = (u8)(r32 >> 24);
    }
}

static void suzy_divide(void)
{
    /* Unsigned 32/16 divide: EFGH ($FC60..63) / NP ($FC56=P low, $FC57=N high)
       -> Quotient in ABCD ($FC52=D low .. $FC55=A high), Remainder in JKLM ($FC6C=M low .. $FC6F=J high) */
    S.sprsys_r &= (u8)~0x60u;
    u32 efgh = (u32)M->suzy[0x60] | ((u32)M->suzy[0x61] << 8) |
               ((u32)M->suzy[0x62] << 16) | ((u32)M->suzy[0x63] << 24);
    u16 np = suzy16(0x56);

    u32 q, rem;
    if (np == 0) {
        q = 0xFFFFFFFFu;
        rem = 0u;
        S.sprsys_r |= 0x60u;             /* Divide-by-zero warning + carry */
    } else {
        q = efgh / (u32)np;
        rem = efgh % (u32)np;
        if (rem == 0)
            S.sprsys_r |= 0x20u;
    }
    M->suzy[0x52] = (u8)q;
    M->suzy[0x53] = (u8)(q >> 8);
    M->suzy[0x54] = (u8)(q >> 16);
    M->suzy[0x55] = (u8)(q >> 24);

    M->suzy[0x6C] = (u8)rem;
    M->suzy[0x6D] = (u8)(rem >> 8);
    M->suzy[0x6E] = 0u;
    M->suzy[0x6F] = 0u;
}

static u32 suzy_run_sprites(void);

/* ---- Suzy & Mikey Register I/O ---- */
static u8 suzy_read(u8 off)
{
    switch (off) {
    case 0x88: return 0x01u;             /* SUZYHREV */
    case 0x92: return S.sprsys_r;        /* SPRSYS */
    case 0xB0: {                         /* JOYSTICK */
        u8 j = 0;
        int rot = S.rotation;
        u16 p = S.pad;
        int u = !!(p & LNX_PAD_UP), d = !!(p & LNX_PAD_DOWN);
        int l = !!(p & LNX_PAD_LEFT), r = !!(p & LNX_PAD_RIGHT);
        if (rot == ROT_LEFT) {
            /* Rotated 90 deg CCW: physical Up -> Right, Down -> Left, Left -> Up, Right -> Down */
            int nu = l, nd = r, nl = d, nr = u;
            u = nu; d = nd; l = nl; r = nr;
        } else if (rot == ROT_RIGHT) {
            int nu = r, nd = l, nl = u, nr = d;
            u = nu; d = nd; l = nl; r = nr;
        }
        if (S.sprsys_w & 0x08u) {        /* LEFTHAND flips directions */
            int t = u; u = d; d = t;
            t = l; l = r; r = t;
        }
        if (u) j |= 0x80u;
        if (d) j |= 0x40u;
        if (l) j |= 0x20u;
        if (r) j |= 0x10u;
        if (p & LNX_PAD_OPT1) j |= 0x08u;
        if (p & LNX_PAD_OPT2) j |= 0x04u;
        if (p & LNX_PAD_B)    j |= 0x02u;
        if (p & LNX_PAD_A)    j |= 0x01u;
        return j;
    }
    case 0xB1:                           /* SWITCHES */
        return (S.pad & LNX_PAD_PAUSE) ? 0x01u : 0x00u;
    case 0xB2:
        return rcart0_read();
    case 0xB3:
        return rcart1_read();
    default:
        return M->suzy[off];
    }
}

static void suzy_write(u8 off, u8 val)
{
    M->suzy[off] = val;
    switch (off) {
    /* Word-write low-byte clear rules on Suzy: writing certain low bytes clears high byte,
       and writing MATHA/MATHC/MATHM/MATHN triggers hardware math side effects! */
    case 0x52: /* MATHD */
        M->suzy[0x53] = 0u;              /* Writing MATHD clears MATHC to 0 on hardware! */
        break;
    case 0x54: /* MATHB */
        M->suzy[0x55] = 0u;              /* Writing MATHB clears MATHA to 0 on hardware! */
        break;
    case 0x56: /* MATHP */
        M->suzy[0x57] = 0u;              /* Writing MATHP clears MATHN to 0 on hardware! */
        break;
    case 0x60: /* MATHH */
        M->suzy[0x61] = 0u;
        break;
    case 0x62: /* MATHF */
        M->suzy[0x63] = 0u;
        break;
    case 0x6C: /* MATHM */
        M->suzy[0x6D] = 0u;
        S.sprsys_r &= (u8)~0x40u;
        break;
    case 0x6E: /* MATHK */
        M->suzy[0x6F] = 0u;
        break;
    case 0x55: /* MATHA -> triggers AB * CD! (WAIT: check order: games write D,C then B,A -> A triggers!) */
        suzy_multiply();
        break;
    case 0x57: /* MATHN -> triggers EFGH / NP! (Wait: games write H,G,F,E and P,N -> N or E triggers!) */
        /* Note: on real Suzy, writing MATHE ($FC63) triggers divide, while writing MATHA ($FC55) triggers multiply! */
        break;
    case 0x63: /* MATHE -> triggers EFGH / NP divide! */
        suzy_divide();
        break;
    case 0x91: /* SPRGO */
        if (val & 0x01u) {
            S.spr_pending   = 1u;
            S.spr_countdown = 12;
            S.sprsys_r     |= 0x01u;     /* SPRITEWORKING */
        }
        break;
    case 0xB2:
    case 0xB3:
        /* WCART0 / WCART1 strobes also clock the cartridge 74HC4040 ripple counter (used by 93C46 EEPROM!) */
        if (!(S.sysctl1 & 0x01u))
            S.cart_offset++;
        break;
    case 0x92: /* SPRSYS */
        S.sprsys_w = val;
        S.sprsys_r = (u8)((S.sprsys_r & ~0x18u) | (val & 0x18u));
        if (val & 0x04u)
            S.sprsys_r &= (u8)~0x04u;
        if (val & 0x02u)
            S.sprsys_r &= (u8)~0x03u;
        break;
    default:
        break;
    }
}

static void update_palette_entry(int idx)
{
    u8 g  = M->mikey[0xA0 + idx] & 0x0Fu;
    u8 br = M->mikey[0xB0 + idx];
    u8 r  = br & 0x0Fu;
    u8 b  = (br >> 4) & 0x0Fu;
    u32 r5 = (r * 31u + 7u) / 15u;
    u32 g5 = (g * 31u + 7u) / 15u;
    u32 b5 = (b * 31u + 7u) / 15u;
    S.pal_bgr[idx] = (u16)(r5 | (g5 << 5) | (b5 << 10));
}

static u8 mikey_read(u8 off)
{
    if (off < 0x20u) {
        int ch = off >> 2;
        switch (off & 3u) {
        case 0: return S.tmr[ch].backup;
        case 1: return S.tmr[ch].ctla;
        case 2: return S.tmr[ch].cnt;
        case 3: return S.tmr[ch].ctlb;
        }
    }
    if (off >= 0x20u && off < 0x40u) {
        int ch = (off - 0x20u) >> 3;
        switch (off & 7u) {
        case 0: return (u8)S.aud[ch].vol;
        case 1: return S.aud[ch].feed;
        case 2: return (u8)S.aud[ch].out;
        case 3: return (u8)(S.aud[ch].shift & 0xFFu);
        case 4: return S.aud[ch].bkup;
        case 5: return S.aud[ch].ctla;
        case 6: return S.aud[ch].cnt;
        case 7: return (u8)((S.aud[ch].ctlb & 0x0Fu) | ((S.aud[ch].shift >> 4) & 0xF0u));
        }
    }
    switch (off) {
    case 0x80: case 0x81:
        return S.irq_flags;
    case 0x84: case 0x85:
        return 0x00u;
    case 0x86:
        return (S.iodat & 0x10u) ? 0x01u : 0x00u;
    case 0x88:
        return 0x01u;                    /* MIKEYHREV */
    case 0x8A:
        return S.iodir;
    case 0x8B: {
        /* Bit 0 EXTERNAL_POWER = 1, Bit 2 NOEXP = 1; Bit 4 AUDIN = 1 when 93C46 CS (cart A7) is high */
        u8 in_pins = (u8)(0x05u | ((S.cart_offset & 0x80u) ? 0x10u : 0x00u));
        return (u8)((S.iodat & S.iodir) | (in_pins & ~S.iodir));
    }
    case 0x8C:
        return 0xA0u;                    /* SERCTL: TXRDY | TXEMPTY */
    case 0x94:
        return (u8)S.dispadr;
    case 0x95:
        return (u8)(S.dispadr >> 8);
    default:
        return M->mikey[off];
    }
}

static void mikey_write(u8 off, u8 val)
{
    M->mikey[off] = val;
    if (off < 0x20u) {
        int ch = off >> 2;
        switch (off & 3u) {
        case 0: S.tmr[ch].backup = val; break;
        case 1:
            S.tmr[ch].ctla = val;
            if (val & 0x40u)             /* RESET_DONE */
                S.tmr[ch].ctlb &= (u8)~0x08u;
            break;
        case 2: S.tmr[ch].cnt = val; break;
        case 3: S.tmr[ch].ctlb = val; break;
        }
        return;
    }
    if (off >= 0x20u && off < 0x40u) {
        int ch = (off - 0x20u) >> 3;
        switch (off & 7u) {
        case 0: S.aud[ch].vol  = (s8)val; break;
        case 1: S.aud[ch].feed = val; break;
        case 2: S.aud[ch].out  = (s8)val; break;
        case 3: S.aud[ch].shift = (u16)((S.aud[ch].shift & 0xFF00u) | val); break;
        case 4: S.aud[ch].bkup = val; break;
        case 5:
            S.aud[ch].ctla = val;
            if (val & 0x40u) S.aud[ch].ctlb &= (u8)~0x08u;
            break;
        case 6: S.aud[ch].cnt  = val; break;
        case 7:
            S.aud[ch].ctlb = (u8)(val & 0x0Fu);
            S.aud[ch].shift = (u16)((S.aud[ch].shift & 0x00FFu) | (((u16)(val & 0xF0u)) << 4));
            break;
        }
        return;
    }
    if (off >= 0xA0u && off < 0xC0u) {
        update_palette_entry(off & 0x0Fu);
        return;
    }
    switch (off) {
    case 0x40: case 0x41: case 0x42: case 0x43:
        S.atten[off - 0x40u] = val;
        break;
    case 0x44: S.mpan    = val; break;
    case 0x50: S.mstereo = val; break;
    case 0x80:                           /* INTRST: write 1 clears interrupt bits */
        S.irq_flags &= (u8)~val;
        break;
    case 0x81:                           /* INTSET: write 1 sets interrupt bits */
        S.irq_flags |= val;
        if (S.irq_flags) S.cpu_asleep = 0;
        break;
    case 0x87: {                         /* SYSCTL1 */
        u8 old = S.sysctl1;
        S.sysctl1 = val;
        if (!(old & 0x01u) && (val & 0x01u)) {
            /* Rising edge on CART_ADDR_STROBE shifts IODAT bit 1 into 74HC164 */
            S.cart_shifter = (u8)((S.cart_shifter << 1) | ((S.iodat >> 1) & 1u));
        }
        /* Active-high CART_ADDR_STROBE holds 74HC4040 ripple counter in reset */
        if (val & 0x01u)
            S.cart_offset = 0;
        break;
    }
    case 0x8A: S.iodir = val; break;
    case 0x8B:
        S.iodat = val;
        break;
    case 0x90:                           /* SDONEACK */
        S.suzy_done_wakeup = 0;
        break;
    case 0x91:                           /* CPUSLEEP */
        if (S.spr_pending) {
            u32 scyc = suzy_run_sprites();
            S.cyc -= (s32)scyc;
            S.spr_pending = 0;
            M->suzy[0x91] &= (u8)~0x01u;
            S.sprsys_r    &= (u8)~0x01u;
            S.suzy_done_wakeup = 0;
        } else if (S.suzy_done_wakeup) {
            S.suzy_done_wakeup = 0;
        } else if (!S.irq_flags) {
            S.cpu_asleep = 1;
        }
        break;
    case 0x92: S.dispctl = val; break;
    case 0x94: S.dispadr = (u16)((S.dispadr & 0xFF00u) | val); break;
    case 0x95: S.dispadr = (u16)((S.dispadr & 0x00FFu) | ((u16)val << 8)); break;
    default: break;
    }
}

/* ---- Mikey Timers & 4-Channel Audio ---- */
static void mikey_timer_fire(int i);

static void mikey_audio_fire(int ch)
{
    struct lnx_audio_ch *a = &S.aud[ch];
    a->ctlb |= 0x08u;
    if (a->ctla & 0x10u)
        a->cnt = a->bkup;

    /* 12-bit LFSR polynomial feedback:
       Feedback taps: bits 0..5 from AUDxFEED ($FD21), bit 7 from AUDxCTLA bit 7, bits 10..11 from AUDxFEED bits 6..7 */
    u16 mask = (u16)(a->feed & 0x3Fu) |
               ((a->ctla & 0x80u) ? 0x0080u : 0u) |
               ((u16)(a->feed & 0xC0u) << 4);
    u16 x = a->shift & mask;
    /* XNOR parity of masked bits */
    x ^= x >> 8;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    u16 inv_par = (~x) & 1u;
    a->shift = (u16)(((a->shift << 1) | inv_par) & 0x0FFFu);

    if (a->ctla & 0x20u) {
        /* Integrate mode */
        s32 next = (s32)a->out + ((a->shift & 1u) ? (s32)a->vol : -(s32)a->vol);
        if (next >  127) next =  127;
        if (next < -128) next = -128;
        a->out = (s8)next;
    } else {
        a->out = (a->shift & 1u) ? a->vol : (s8)(-a->vol);
    }

    /* Audio channel cascade */
    if (ch < 3 && (S.aud[ch + 1].ctla & 0x0Fu) == 0x0Fu &&
        ((S.aud[ch + 1].ctla & 0x10u) || !(S.aud[ch + 1].ctlb & 0x08u))) {
        if (S.aud[ch + 1].cnt == 0)
            mikey_audio_fire(ch + 1);
        else
            S.aud[ch + 1].cnt--;
    }
}

static void mikey_timer_fire(int i)
{
    struct lnx_timer *t = &S.tmr[i];
    t->ctlb |= 0x08u;                    /* TIMER_DONE always latches on borrow! */
    if (t->ctla & 0x10u)
        t->cnt = t->backup;

    if (t->ctla & 0x80u) {               /* ENABLE_INT */
        S.irq_flags |= (u8)(1u << i);
        S.cpu_asleep = 0;
    }

    /* Timer linking chain on Lynx: 0->2->4, 1->3->5->7->Aud0 */
    static const s8 link_next[8] = { 2, 3, 4, 5, -1, 7, -1, 8 };
    int nxt = link_next[i];
    if (nxt >= 0 && nxt < 8) {
        struct lnx_timer *nt = &S.tmr[nxt];
        if ((nt->ctla & 0x0Fu) == 0x0Fu && ((nt->ctla & 0x10u) || !(nt->ctlb & 0x08u))) {
            if (nt->cnt == 0)
                mikey_timer_fire(nxt);
            else
                nt->cnt--;
        }
    } else if (nxt == 8) {
        if ((S.aud[0].ctla & 0x0Fu) == 0x0Fu && ((S.aud[0].ctla & 0x10u) || !(S.aud[0].ctlb & 0x08u))) {
            if (S.aud[0].cnt == 0)
                mikey_audio_fire(0);
            else
                S.aud[0].cnt--;
        }
    }
}

static void mikey_step_slice(u32 us)
{
    for (int i = 0; i < 8; i++) {
        struct lnx_timer *t = &S.tmr[i];
        u8 ctla = t->ctla;
        if (!(ctla & 0x08u) || (ctla & 0x07u) == 0x07u)
            continue;
        if (!(ctla & 0x10u) && (t->ctlb & 0x08u))
            continue;
        u32 period_us = 1u << (ctla & 0x07u);
        t->acc_us += us;
        while (t->acc_us >= period_us) {
            t->acc_us -= period_us;
            if (t->cnt == 0) {
                mikey_timer_fire(i);
                if (!(t->ctla & 0x10u) && (t->ctlb & 0x08u))
                    break;
            } else {
                t->cnt--;
            }
        }
    }

    for (int c = 0; c < 4; c++) {
        struct lnx_audio_ch *a = &S.aud[c];
        u8 ctla = a->ctla;
        if (!(ctla & 0x08u) || (ctla & 0x07u) == 0x07u || a->bkup == 0)
            continue;
        if (!(ctla & 0x10u) && (a->ctlb & 0x08u))
            continue;
        u32 period_us = 1u << (ctla & 0x07u);
        a->acc_us += us;
        while (a->acc_us >= period_us) {
            a->acc_us -= period_us;
            if (a->cnt == 0) {
                mikey_audio_fire(c);
                if (!(a->ctla & 0x10u) && (a->ctlb & 0x08u))
                    break;
            } else {
                a->cnt--;
            }
        }
    }

    if (!S.snd_rate)
        return;

    S.snd_phase += S.snd_rate * us;
    if (S.snd_phase < 1000000u)
        return;

    s32 mix = 0;
    for (int c = 0; c < 4; c++) {
        /* MSTEREO bits disable L (b4..7) / R (b0..3) when 1 */
        int l_on = !(S.mstereo & (0x10u << c));
        int r_on = !(S.mstereo & (0x01u << c));
        if (l_on || r_on)
            mix += (s32)S.aud[c].out * ((l_on && r_on) ? 2 : 1);
    }
    mix *= 40;
    if (mix >  32767) mix =  32767;
    if (mix < -32768) mix = -32768;

    while (S.snd_phase >= 1000000u) {
        S.snd_phase -= 1000000u;
        if (S.snd_wr - S.snd_rd < SND_RING) {
            M->snd_ring[S.snd_wr & (SND_RING - 1u)] = (s16)mix;
            S.snd_wr++;
        }
    }
}

/* ---- Suzy Chained SCB Hardware Sprite Renderer ---- */
struct bit_reader {
    u16 ptr, end;
    u32 buf, bits;
};

INLINE u32 br_get(struct bit_reader *br, u32 n)
{
    while (br->bits < n) {
        u8 b = (br->ptr < br->end) ? M->ram[br->ptr++] : 0u;
        br->buf = (br->buf << 8) | b;
        br->bits += 8u;
    }
    br->bits -= n;
    return (br->buf >> br->bits) & ((1u << n) - 1u);
}

INLINE void plot_lynx_px(u16 vidbas, u16 collbas, int x, int y, u8 pen, u8 col,
                         u32 spr_type, int do_coll, u8 coll_id, int *max_hit)
{
    (void)pen;
    if ((unsigned)x >= LNX_W || (unsigned)y >= LNX_H)
        return;

    u32 byte_off = (u32)y * 80u + ((u32)x >> 1);
    u16 vaddr = (u16)(vidbas + byte_off);
    int hi_nib = !(x & 1);
    int opaque = 1;
    int collidable = 1;

    switch (spr_type) {
    case 0: /* BACKGROUND: all pens opaque, writes 0 to collision buffer */
        break;
    case 1: /* BACKNONCOLL: all pens opaque, no collision */
        collidable = 0;
        break;
    case 2: /* BSHADOW: col 0 transparent, col 0xE opaque non-colliding, others opaque colliding */
        if (col == 0u) return;
        if (col == 0xEu) collidable = 0;
        break;
    case 3: /* BOUNDARY: col 0 transparent, col 0xF transparent BUT colliding! */
        if (col == 0u) return;
        if (col == 0xFu) opaque = 0;
        break;
    case 4: /* NORMAL: col 0 transparent */
        if (col == 0u) return;
        break;
    case 5: /* NONCOLL: col 0 transparent, no collision */
        if (col == 0u) return;
        collidable = 0;
        break;
    case 6: /* XOR: col 0 transparent, XORs colour into framebuffer */
        if (col == 0u) return;
        if (hi_nib) M->ram[vaddr] ^= (u8)(col << 4);
        else        M->ram[vaddr] ^= (u8)(col & 0x0Fu);
        opaque = 0;
        break;
    case 7: /* SHADOW: col 0 transparent, col 0xE non-colliding */
        if (col == 0u) return;
        if (col == 0xEu) collidable = 0;
        break;
    }

    if (opaque) {
        if (hi_nib)
            M->ram[vaddr] = (u8)((M->ram[vaddr] & 0x0Fu) | (col << 4));
        else
            M->ram[vaddr] = (u8)((M->ram[vaddr] & 0xF0u) | (col & 0x0Fu));
    }

    if (do_coll) {
        u16 caddr = (u16)(collbas + byte_off);
        if (spr_type == 0u) {
            if (hi_nib) M->ram[caddr] &= 0x0Fu;
            else        M->ram[caddr] &= 0xF0u;
        } else if (collidable) {
            u8 prev = hi_nib ? (M->ram[caddr] >> 4) : (M->ram[caddr] & 0x0Fu);
            if ((int)prev > *max_hit)
                *max_hit = (int)prev;
            if (hi_nib)
                M->ram[caddr] = (u8)((M->ram[caddr] & 0x0Fu) | (coll_id << 4));
            else
                M->ram[caddr] = (u8)((M->ram[caddr] & 0xF0u) | (coll_id & 0x0Fu));
        }
    }
}

INLINE u16 ram16(u16 a)
{
    return (u16)M->ram[a] | ((u16)M->ram[(u16)(a + 1u)] << 8);
}

static u32 suzy_run_sprites(void)
{
    u16 vidbas  = suzy16(0x08);
    u16 collbas = suzy16(0x0A);
    s16 hoff    = (s16)suzy16(0x04);
    s16 voff    = (s16)suzy16(0x06);
    u16 coll_depo_off = suzy16(0x24);
    u16 hsiz_init = suzy16(0x28);
    u16 vsiz_init = suzy16(0x2A);
    if (hsiz_init == 0 && vsiz_init == 0) {
        hsiz_init = 0x007Fu;
        vsiz_init = 0x007Fu;
    }

    u16 scb = suzy16(0x10);
    u32 total_cyc = 16;
    int ever_on_en = (M->suzy[0x91] >> 2) & 1;

    for (int guard = 0; guard < 1024 && (scb & 0xFF00u) != 0u; guard++) {
        set_suzy16(0x2C, scb);
        u8 ctl0    = M->ram[scb];
        u8 ctl1    = M->ram[(u16)(scb + 1u)];
        u8 sprcoll = M->ram[(u16)(scb + 2u)];
        u16 next   = ram16((u16)(scb + 3u));
        set_suzy16(0x10, next);

        if (ctl1 & 0x04u) {              /* SKIP */
            scb = next;
            total_cyc += 5;
            continue;
        }

        u16 p = (u16)(scb + 5u);
        u16 sprdline = ram16(p); p = (u16)(p + 2u);
        s16 hposstrt = (s16)ram16(p); p = (u16)(p + 2u);
        s16 vposstrt = (s16)ram16(p); p = (u16)(p + 2u);

        u32 reload = (ctl1 >> 4) & 3u;
        if (reload >= 1u) {
            set_suzy16(0x18, ram16(p)); p = (u16)(p + 2u);
            set_suzy16(0x1A, ram16(p)); p = (u16)(p + 2u);
        }
        if (reload >= 2u) {
            set_suzy16(0x1C, ram16(p)); p = (u16)(p + 2u);
        }
        if (reload >= 3u) {
            set_suzy16(0x1E, ram16(p)); p = (u16)(p + 2u);
        }

        u32 bpp      = ((ctl0 >> 6) & 3u) + 1u;
        if (!(ctl1 & 0x08u)) {           /* Reload (1 << (bpp-1))-byte pen index table (hi=even, lo=odd) */
            int pbytes = 1 << (bpp - 1u);
            for (int i = 0; i < pbytes; i++) {
                u8 b = M->ram[(u16)(p + (u16)i)];
                S.last_pen_map[i * 2 + 0] = b >> 4;
                S.last_pen_map[i * 2 + 1] = b & 0x0Fu;
            }
        }

        int hflip    = (ctl0 >> 5) & 1;
        int vflip    = (ctl0 >> 4) & 1;
        u32 spr_type = ctl0 & 7u;
        int literal  = (ctl1 >> 7) & 1;
        int do_coll  = !(S.sprsys_w & 0x20u) && !(sprcoll & 0x20u);
        u8  coll_id  = sprcoll & 0x0Fu;
        int max_hit  = -1;
        int ever_on  = 0;

        u16 hsiz    = suzy16(0x18);
        u16 vsiz    = suzy16(0x1A);
        s16 stretch = (s16)suzy16(0x1C);
        s16 tilt    = (s16)suzy16(0x1E);
        s32 tilt_acc = (s16)suzy16(0x02);

        int orig_dx = ((ctl1 & 1u) ^ (u32)hflip) ? -1 : 1;
        int orig_dy = (((ctl1 >> 1) & 1u) ^ (u32)vflip) ? -1 : 1;
        int dx = orig_dx, dy = orig_dy;
        int cur_y = (int)vposstrt - (int)voff;
        int base_x = (int)hposstrt - (int)hoff;
        u32 vsiz_acc = vsiz_init;

        for (int q_step = 0, lines = 0; lines < 512; lines++) {
            u8 doff = M->ram[sprdline];
            if (doff == 0u)
                break;
            if (doff == 1u) {
                /* Quadrant change: Gray-code cycle flip V, flip H, flip V */
                q_step++;
                if (q_step > 3)
                    break;
                if (q_step & 1)
                    dy = -dy;
                else
                    dx = -dx;
                cur_y = (int)vposstrt - (int)voff + ((dy != orig_dy) ? dy : 0);
                base_x = (int)hposstrt - (int)hoff;
                vsiz_acc = vsiz_init;
                hsiz = suzy16(0x18);
                vsiz = suzy16(0x1A);
                tilt_acc = (s16)suzy16(0x02);
                sprdline++;
                continue;
            }

            u16 line_end = (u16)(sprdline + doff);
            vsiz_acc += vsiz;
            int v_rep = (int)(vsiz_acc >> 8);
            vsiz_acc &= 0xFFu;

            for (int vr = 0; vr < v_rep; vr++) {
                if ((unsigned)cur_y < LNX_H) {
                    int cur_x = base_x + ((dx != orig_dx) ? dx : 0);
                    u32 hsiz_acc = hsiz_init;
                    struct bit_reader br = { (u16)(sprdline + 1u), line_end, 0u, 0u };

                    if (literal) {
                        u32 total_bits = (u32)(doff - 1u) * 8u;
                        /* Suzy literal line ends with a trailing 0 stop bit (keep >= bpp + 1 or >= bpp) */
                        u32 n_px = (total_bits >= 1u) ? ((total_bits - 1u) / bpp) : 0u;
                        for (u32 k = 0; k < n_px; k++) {
                            u8 pen = (u8)br_get(&br, bpp);
                            u8 col = S.last_pen_map[pen];
                            hsiz_acc += hsiz;
                            int h_rep = (int)(hsiz_acc >> 8);
                            hsiz_acc &= 0xFFu;
                            for (int hr = 0; hr < h_rep; hr++) {
                                if ((unsigned)cur_x < LNX_W) ever_on = 1;
                                plot_lynx_px(vidbas, collbas, cur_x, cur_y, pen, col,
                                             spr_type, do_coll, coll_id, &max_hit);
                                cur_x += dx;
                            }
                        }
                    } else {
                        for (int seg = 0; seg < 256; seg++) {
                            if ((u32)(u16)(br.end - br.ptr) * 8u + br.bits < 5u)
                                break;
                            u32 hdr = br_get(&br, 5u);
                            if (hdr == 0u)
                                break;
                            u32 count = (hdr & 0x0Fu) + 1u;
                            if (hdr & 0x10u) {
                                /* Literal packet */
                                for (u32 k = 0; k < count; k++) {
                                    u8 pen = (u8)br_get(&br, bpp);
                                    u8 col = S.last_pen_map[pen];
                                    hsiz_acc += hsiz;
                                    int h_rep = (int)(hsiz_acc >> 8);
                                    hsiz_acc &= 0xFFu;
                                    for (int hr = 0; hr < h_rep; hr++) {
                                        if ((unsigned)cur_x < LNX_W) ever_on = 1;
                                        plot_lynx_px(vidbas, collbas, cur_x, cur_y, pen, col,
                                                     spr_type, do_coll, coll_id, &max_hit);
                                        cur_x += dx;
                                    }
                                }
                            } else {
                                /* Packed RLE packet */
                                u8 pen = (u8)br_get(&br, bpp);
                                u8 col = S.last_pen_map[pen];
                                for (u32 k = 0; k < count; k++) {
                                    hsiz_acc += hsiz;
                                    int h_rep = (int)(hsiz_acc >> 8);
                                    hsiz_acc &= 0xFFu;
                                    for (int hr = 0; hr < h_rep; hr++) {
                                        if ((unsigned)cur_x < LNX_W) ever_on = 1;
                                        plot_lynx_px(vidbas, collbas, cur_x, cur_y, pen, col,
                                                     spr_type, do_coll, coll_id, &max_hit);
                                        cur_x += dx;
                                    }
                                }
                            }
                        }
                    }
                    total_cyc += 12;
                }

                cur_y += dy;
                hsiz = (u16)(hsiz + stretch);
                if (S.sprsys_w & 0x10u)  /* VSTRETCH */
                    vsiz = (u16)(vsiz + stretch);
                tilt_acc += tilt;
                base_x += (tilt_acc >> 8);
                tilt_acc &= 0xFF;
            }
            sprdline = line_end;
        }

        if (do_coll || ever_on_en) {
            u8 depo = (max_hit >= 0) ? (u8)max_hit : 0u;
            if (ever_on_en && !ever_on)
                depo |= 0x80u;
            M->ram[(u16)(scb + coll_depo_off)] = depo;
        }

        scb = next;
        total_cyc += 10;
    }

    if (total_cyc > 16000u)
        total_cyc = 16000u;
    return total_cyc;
}

/* ---- 64 KB Bus with MAPCTL ($FFF9) ---- */
INLINE u8 bus_read(u16 addr)
{
    if (addr < 0xFC00u)
        return M->ram[addr];
    if (addr == 0xFFF9u)
        return S.mapctl;
    if (addr < 0xFD00u)
        return (S.mapctl & 0x01u) ? M->ram[addr] : suzy_read((u8)addr);
    if (addr < 0xFE00u)
        return (S.mapctl & 0x02u) ? M->ram[addr] : mikey_read((u8)addr);
    if (addr < 0xFFF8u)
        return (S.mapctl & 0x04u) ? M->ram[addr] : M->bios[addr - 0xFE00u];
    if (addr >= 0xFFFAu)
        return (S.mapctl & 0x08u) ? M->ram[addr] : M->bios[addr - 0xFE00u];
    return M->ram[addr];
}

INLINE void bus_write(u16 addr, u8 val)
{
    if (addr < 0xFC00u) {
        M->ram[addr] = val;
        return;
    }
    if (addr == 0xFFF9u) {
        S.mapctl = val;
        return;
    }
    if (addr < 0xFD00u) {
        if (S.mapctl & 0x01u) M->ram[addr] = val;
        else                  suzy_write((u8)addr, val);
        return;
    }
    if (addr < 0xFE00u) {
        if (S.mapctl & 0x02u) M->ram[addr] = val;
        else                  mikey_write((u8)addr, val);
        return;
    }
    /* Writes to $FE00..$FFFF (except $FFF9) ALWAYS write through to underlying RAM! */
    M->ram[addr] = val;
}

/* ---- WDC 65SC02 CPU ---- */
INLINE void set_nz(u8 v)
{
    S.p = (u8)((S.p & ~(FN | FZ)) | (v & FN) | (v == 0 ? FZ : 0u));
}

INLINE void push8(u8 v)
{
    M->ram[0x0100u | S.sp] = v;
    S.sp--;
}

INLINE u8 pull8(void)
{
    S.sp++;
    return M->ram[0x0100u | S.sp];
}

INLINE void push16(u16 v)
{
    push8((u8)(v >> 8));
    push8((u8)v);
}

INLINE u16 pull16(void)
{
    u16 lo = pull8();
    return (u16)(lo | ((u16)pull8() << 8));
}

INLINE u16 rd16_zp(u8 zp)
{
    return (u16)M->ram[zp] | ((u16)M->ram[(u8)(zp + 1u)] << 8);
}

INLINE u16 rd16_abs(u16 a)
{
    return (u16)bus_read(a) | ((u16)bus_read((u16)(a + 1u)) << 8);
}

static void adc65c02(u8 v)
{
    u32 c = S.p & FC;
    if (S.p & FD) {
        u32 lo = (S.a & 0x0Fu) + (v & 0x0Fu) + c;
        u32 hi = (S.a & 0xF0u) + (v & 0xF0u);
        if (lo > 0x09u) { lo += 0x06u; hi += 0x10u; }
        u8 ov = ((~(S.a ^ v) & (S.a ^ hi)) & 0x80u) ? FV : 0u;
        if (hi > 0x90u) hi += 0x60u;
        S.a = (u8)((hi & 0xF0u) | (lo & 0x0Fu));
        /* CMOS 65SC02 sets N and Z from the final BCD result (+1 cycle)! */
        S.p = (u8)((S.p & ~(FN | FV | FZ | FC)) | (S.a & FN) | (S.a == 0 ? FZ : 0u) | ov | (hi > 0xFFu ? FC : 0u));
        S.cyc--;
    } else {
        u32 sum = (u32)S.a + (u32)v + c;
        u8 ov = ((~(S.a ^ v) & (S.a ^ sum)) & 0x80u) ? FV : 0u;
        S.a = (u8)sum;
        S.p = (u8)((S.p & ~(FN | FV | FZ | FC)) | (S.a & FN) | (S.a == 0 ? FZ : 0u) | ov | (sum > 0xFFu ? FC : 0u));
    }
}

static void sbc65c02(u8 v)
{
    u32 c = S.p & FC;
    u32 diff = (u32)S.a - (u32)v - (1u - c);
    u8 ov = (((S.a ^ v) & (S.a ^ diff)) & 0x80u) ? FV : 0u;
    if (S.p & FD) {
        s32 lo = (s32)(S.a & 0x0Fu) - (s32)(v & 0x0Fu) - (s32)(1u - c);
        s32 bcd = (s32)diff;
        if (lo < 0)
            bcd -= 0x06;
        if (diff >= 0x100u)
            bcd -= 0x60;
        S.a = (u8)bcd;
        S.cyc--;
    } else {
        S.a = (u8)diff;
    }
    S.p = (u8)((S.p & ~(FN | FV | FZ | FC)) | (S.a & FN) | (S.a == 0 ? FZ : 0u) | ov | (diff < 0x100u ? FC : 0u));
}

INLINE void cmp65c02(u8 r, u8 v)
{
    u16 d = (u16)r - (u16)v;
    S.p = (u8)((S.p & ~(FN | FZ | FC)) | (d & FN) | ((d & 0xFFu) == 0 ? FZ : 0u) | (r >= v ? FC : 0u));
}

INLINE void branch65c02(int cond)
{
    s8 rel = (s8)bus_read(S.pc++);
    if (cond) {
        u16 old = S.pc;
        S.pc = (u16)(S.pc + rel);
        S.cyc -= ((old ^ S.pc) & 0xFF00u) ? 2 : 1;
    }
}

/* Built-in HLE Boot ROM handlers at $FE00, $FE19, $FE4A */
static int handle_hle_bootrom(void)
{
    if (S.pc == 0xFE00u) {
        /* $FE00: Select cartridge block in A */
        S.cart_shifter = S.a;
        S.cart_offset  = 0;
        S.iodat &= (u8)~0x02u;
        S.pc = (u16)(pull16() + 1u);
        S.cyc -= 12;
        return 1;
    }
    if (S.pc == 0xFE19u || S.pc == 0xFE4Au) {
        if (S.pc == 0xFE19u) {
            /* Power-on boot entry: clear palette, select block 0, target $0200 */
            for (int i = 0; i < 32; i++)
                M->mikey[0xA0 + i] = 0;
            for (int i = 0; i < 16; i++)
                S.pal_bgr[i] = 0;
            S.cart_shifter = 0;
            S.cart_offset  = 0;
            S.sysctl1 = 0x02u;           /* CART_POWER_ON */
            S.iodir   = 0x1Au;
            S.iodat   = 0x08u;
            M->ram[0x1A] = 0x08u;        /* Boot ROM IODAT shadow */
            M->ram[0x05] = 0x00u;
            M->ram[0x06] = 0x02u;
        }
        u16 dst = (u16)M->ram[0x05] | ((u16)M->ram[0x06] << 8);
        if (!decrypt_cart_frame(dst)) {
            /* Fallback for unencrypted raw Lynx directory at offset 0 (byte 3 == 0x88) */
            if (S.bank0 && S.bank0_size >= 8u && S.bank0[3] == 0x88u) {
                u8  blk  = S.bank0[0];
                u16 boff = (u16)(S.bank0[1] | ((u16)S.bank0[2] << 8));
                u16 dest = (u16)(S.bank0[4] | ((u16)S.bank0[5] << 8));
                u16 flen = (u16)(S.bank0[6] | ((u16)S.bank0[7] << 8));
                u32 src  = (u32)blk * S.page_b0 + boff;
                for (u32 i = 0; i < flen && src + i < S.bank0_size; i++)
                    M->ram[(u16)(dest + i)] = S.bank0[src + i];
                S.mapctl = 0x0Cu;        /* Unmap ROM & vectors */
                S.pc = dest;
                S.cyc -= 32;
                return 1;
            }
            S.jammed = 1;
            S.cyc = 0;
            return 1;
        }
        S.pc = 0x0200u;
        S.cyc -= 64;
        return 1;
    }
    return 0;
}

static void step_65sc02(void)
{
    if (S.spr_pending && --S.spr_countdown <= 0) {
        u32 scyc = suzy_run_sprites();
        S.cyc -= (s32)scyc;
        S.spr_pending = 0;
        M->suzy[0x91] &= (u8)~0x01u;
        S.sprsys_r    &= (u8)~0x01u;
        S.suzy_done_wakeup = 1u;
        S.cpu_asleep = 0;
    }

    if (S.irq_flags && !(S.p & FI)) {
        S.cpu_asleep = 0;
        push16(S.pc);
        push8((u8)((S.p & ~FB) | 0x20u));
        S.p = (u8)((S.p | FI) & ~FD);    /* CMOS 65SC02 clears D on interrupt! */
        S.pc = rd16_abs(0xFFFEu);
        S.cyc -= 7;
        return;
    }

    if (S.cpu_asleep) {
        S.cyc = 0;
        return;
    }

    if (S.using_hle_bios && !(S.mapctl & 0x04u) && S.pc >= 0xFE00u && S.pc < 0xFFF0u) {
        if (handle_hle_bootrom())
            return;
    }

    u8 op = bus_read(S.pc++);
    u16 addr;
    u8 v;

    /* Rockwell RMB / SMB / BBR / BBS (all low nibbles 0x7 and 0xF!) */
    if ((op & 0x0Fu) == 0x07u) {
        u8 zp = bus_read(S.pc++);
        u8 bit = (u8)(1u << ((op >> 4) & 7u));
        if (op & 0x80u) M->ram[zp] |= bit;  /* SMB0..7 */
        else            M->ram[zp] &= (u8)~bit; /* RMB0..7 */
        S.cyc -= 5;
        return;
    }
    if ((op & 0x0Fu) == 0x0Fu) {
        u8 zp = bus_read(S.pc++);
        u8 bit = (u8)(1u << ((op >> 4) & 7u));
        int set = (M->ram[zp] & bit) != 0;
        branch65c02((op & 0x80u) ? set : !set);
        S.cyc -= 5;
        return;
    }

    switch (op) {
    case 0x00: /* BRK */
        S.pc++;
        push16(S.pc);
        push8((u8)(S.p | FB | 0x20u));
        S.p = (u8)((S.p | FI) & ~FD);
        S.pc = rd16_abs(0xFFFEu);
        S.cyc -= 7;
        break;

    /* ORA */
    case 0x09: S.a |= bus_read(S.pc++); set_nz(S.a); S.cyc -= 2; break;
    case 0x05: S.a |= M->ram[bus_read(S.pc++)]; set_nz(S.a); S.cyc -= 3; break;
    case 0x15: S.a |= M->ram[(u8)(bus_read(S.pc++) + S.x)]; set_nz(S.a); S.cyc -= 4; break;
    case 0x12: S.a |= bus_read(rd16_zp(bus_read(S.pc++))); set_nz(S.a); S.cyc -= 5; break;
    case 0x0D: S.a |= bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x1D: S.a |= bus_read((u16)(rd16_abs(S.pc) + S.x)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x19: S.a |= bus_read((u16)(rd16_abs(S.pc) + S.y)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x01: S.a |= bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x))); set_nz(S.a); S.cyc -= 6; break;
    case 0x11: S.a |= bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y)); set_nz(S.a); S.cyc -= 5; break;

    /* AND */
    case 0x29: S.a &= bus_read(S.pc++); set_nz(S.a); S.cyc -= 2; break;
    case 0x25: S.a &= M->ram[bus_read(S.pc++)]; set_nz(S.a); S.cyc -= 3; break;
    case 0x35: S.a &= M->ram[(u8)(bus_read(S.pc++) + S.x)]; set_nz(S.a); S.cyc -= 4; break;
    case 0x32: S.a &= bus_read(rd16_zp(bus_read(S.pc++))); set_nz(S.a); S.cyc -= 5; break;
    case 0x2D: S.a &= bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x3D: S.a &= bus_read((u16)(rd16_abs(S.pc) + S.x)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x39: S.a &= bus_read((u16)(rd16_abs(S.pc) + S.y)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x21: S.a &= bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x))); set_nz(S.a); S.cyc -= 6; break;
    case 0x31: S.a &= bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y)); set_nz(S.a); S.cyc -= 5; break;

    /* EOR */
    case 0x49: S.a ^= bus_read(S.pc++); set_nz(S.a); S.cyc -= 2; break;
    case 0x45: S.a ^= M->ram[bus_read(S.pc++)]; set_nz(S.a); S.cyc -= 3; break;
    case 0x55: S.a ^= M->ram[(u8)(bus_read(S.pc++) + S.x)]; set_nz(S.a); S.cyc -= 4; break;
    case 0x52: S.a ^= bus_read(rd16_zp(bus_read(S.pc++))); set_nz(S.a); S.cyc -= 5; break;
    case 0x4D: S.a ^= bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x5D: S.a ^= bus_read((u16)(rd16_abs(S.pc) + S.x)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x59: S.a ^= bus_read((u16)(rd16_abs(S.pc) + S.y)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x41: S.a ^= bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x))); set_nz(S.a); S.cyc -= 6; break;
    case 0x51: S.a ^= bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y)); set_nz(S.a); S.cyc -= 5; break;

    /* ADC */
    case 0x69: adc65c02(bus_read(S.pc++)); S.cyc -= 2; break;
    case 0x65: adc65c02(M->ram[bus_read(S.pc++)]); S.cyc -= 3; break;
    case 0x75: adc65c02(M->ram[(u8)(bus_read(S.pc++) + S.x)]); S.cyc -= 4; break;
    case 0x72: adc65c02(bus_read(rd16_zp(bus_read(S.pc++)))); S.cyc -= 5; break;
    case 0x6D: adc65c02(bus_read(rd16_abs(S.pc))); S.pc += 2; S.cyc -= 4; break;
    case 0x7D: adc65c02(bus_read((u16)(rd16_abs(S.pc) + S.x))); S.pc += 2; S.cyc -= 4; break;
    case 0x79: adc65c02(bus_read((u16)(rd16_abs(S.pc) + S.y))); S.pc += 2; S.cyc -= 4; break;
    case 0x61: adc65c02(bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x)))); S.cyc -= 6; break;
    case 0x71: adc65c02(bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y))); S.cyc -= 5; break;

    /* SBC */
    case 0xE9: sbc65c02(bus_read(S.pc++)); S.cyc -= 2; break;
    case 0xE5: sbc65c02(M->ram[bus_read(S.pc++)]); S.cyc -= 3; break;
    case 0xF5: sbc65c02(M->ram[(u8)(bus_read(S.pc++) + S.x)]); S.cyc -= 4; break;
    case 0xF2: sbc65c02(bus_read(rd16_zp(bus_read(S.pc++)))); S.cyc -= 5; break;
    case 0xED: sbc65c02(bus_read(rd16_abs(S.pc))); S.pc += 2; S.cyc -= 4; break;
    case 0xFD: sbc65c02(bus_read((u16)(rd16_abs(S.pc) + S.x))); S.pc += 2; S.cyc -= 4; break;
    case 0xF9: sbc65c02(bus_read((u16)(rd16_abs(S.pc) + S.y))); S.pc += 2; S.cyc -= 4; break;
    case 0xE1: sbc65c02(bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x)))); S.cyc -= 6; break;
    case 0xF1: sbc65c02(bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y))); S.cyc -= 5; break;

    /* CMP / CPX / CPY */
    case 0xC9: cmp65c02(S.a, bus_read(S.pc++)); S.cyc -= 2; break;
    case 0xC5: cmp65c02(S.a, M->ram[bus_read(S.pc++)]); S.cyc -= 3; break;
    case 0xD5: cmp65c02(S.a, M->ram[(u8)(bus_read(S.pc++) + S.x)]); S.cyc -= 4; break;
    case 0xD2: cmp65c02(S.a, bus_read(rd16_zp(bus_read(S.pc++)))); S.cyc -= 5; break;
    case 0xCD: cmp65c02(S.a, bus_read(rd16_abs(S.pc))); S.pc += 2; S.cyc -= 4; break;
    case 0xDD: cmp65c02(S.a, bus_read((u16)(rd16_abs(S.pc) + S.x))); S.pc += 2; S.cyc -= 4; break;
    case 0xD9: cmp65c02(S.a, bus_read((u16)(rd16_abs(S.pc) + S.y))); S.pc += 2; S.cyc -= 4; break;
    case 0xC1: cmp65c02(S.a, bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x)))); S.cyc -= 6; break;
    case 0xD1: cmp65c02(S.a, bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y))); S.cyc -= 5; break;

    case 0xE0: cmp65c02(S.x, bus_read(S.pc++)); S.cyc -= 2; break;
    case 0xE4: cmp65c02(S.x, M->ram[bus_read(S.pc++)]); S.cyc -= 3; break;
    case 0xEC: cmp65c02(S.x, bus_read(rd16_abs(S.pc))); S.pc += 2; S.cyc -= 4; break;

    case 0xC0: cmp65c02(S.y, bus_read(S.pc++)); S.cyc -= 2; break;
    case 0xC4: cmp65c02(S.y, M->ram[bus_read(S.pc++)]); S.cyc -= 3; break;
    case 0xCC: cmp65c02(S.y, bus_read(rd16_abs(S.pc))); S.pc += 2; S.cyc -= 4; break;

    /* BIT / TSB / TRB */
    case 0x89: v = bus_read(S.pc++); S.p = (u8)((S.p & ~FZ) | ((S.a & v) == 0 ? FZ : 0u)); S.cyc -= 2; break;
    case 0x24: v = M->ram[bus_read(S.pc++)]; goto do_bit;
    case 0x34: v = M->ram[(u8)(bus_read(S.pc++) + S.x)]; S.cyc--; goto do_bit;
    case 0x2C: v = bus_read(rd16_abs(S.pc)); S.pc += 2; S.cyc--; goto do_bit;
    case 0x3C: v = bus_read((u16)(rd16_abs(S.pc) + S.x)); S.pc += 2; S.cyc--; do_bit:
        S.p = (u8)((S.p & ~(FN | FV | FZ)) | (v & (FN | FV)) | ((S.a & v) == 0 ? FZ : 0u)); S.cyc -= 3; break;

    case 0x04: addr = bus_read(S.pc++); goto do_tsb;
    case 0x0C: addr = rd16_abs(S.pc); S.pc += 2; S.cyc--; do_tsb:
        v = bus_read(addr); S.p = (u8)((S.p & ~FZ) | ((S.a & v) == 0 ? FZ : 0u)); bus_write(addr, (u8)(v | S.a)); S.cyc -= 5; break;

    case 0x14: addr = bus_read(S.pc++); goto do_trb;
    case 0x1C: addr = rd16_abs(S.pc); S.pc += 2; S.cyc--; do_trb:
        v = bus_read(addr); S.p = (u8)((S.p & ~FZ) | ((S.a & v) == 0 ? FZ : 0u)); bus_write(addr, (u8)(v & ~S.a)); S.cyc -= 5; break;

    /* LDA / LDX / LDY */
    case 0xA9: S.a = bus_read(S.pc++); set_nz(S.a); S.cyc -= 2; break;
    case 0xA5: S.a = M->ram[bus_read(S.pc++)]; set_nz(S.a); S.cyc -= 3; break;
    case 0xB5: S.a = M->ram[(u8)(bus_read(S.pc++) + S.x)]; set_nz(S.a); S.cyc -= 4; break;
    case 0xB2: S.a = bus_read(rd16_zp(bus_read(S.pc++))); set_nz(S.a); S.cyc -= 5; break;
    case 0xAD: S.a = bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0xBD: S.a = bus_read((u16)(rd16_abs(S.pc) + S.x)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0xB9: S.a = bus_read((u16)(rd16_abs(S.pc) + S.y)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0xA1: S.a = bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x))); set_nz(S.a); S.cyc -= 6; break;
    case 0xB1: S.a = bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y)); set_nz(S.a); S.cyc -= 5; break;

    case 0xA2: S.x = bus_read(S.pc++); set_nz(S.x); S.cyc -= 2; break;
    case 0xA6: S.x = M->ram[bus_read(S.pc++)]; set_nz(S.x); S.cyc -= 3; break;
    case 0xB6: S.x = M->ram[(u8)(bus_read(S.pc++) + S.y)]; set_nz(S.x); S.cyc -= 4; break;
    case 0xAE: S.x = bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.x); S.cyc -= 4; break;
    case 0xBE: S.x = bus_read((u16)(rd16_abs(S.pc) + S.y)); S.pc += 2; set_nz(S.x); S.cyc -= 4; break;

    case 0xA0: S.y = bus_read(S.pc++); set_nz(S.y); S.cyc -= 2; break;
    case 0xA4: S.y = M->ram[bus_read(S.pc++)]; set_nz(S.y); S.cyc -= 3; break;
    case 0xB4: S.y = M->ram[(u8)(bus_read(S.pc++) + S.x)]; set_nz(S.y); S.cyc -= 4; break;
    case 0xAC: S.y = bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.y); S.cyc -= 4; break;
    case 0xBC: S.y = bus_read((u16)(rd16_abs(S.pc) + S.x)); S.pc += 2; set_nz(S.y); S.cyc -= 4; break;

    /* STA / STX / STY / STZ */
    case 0x85: M->ram[bus_read(S.pc++)] = S.a; S.cyc -= 3; break;
    case 0x95: M->ram[(u8)(bus_read(S.pc++) + S.x)] = S.a; S.cyc -= 4; break;
    case 0x92: bus_write(rd16_zp(bus_read(S.pc++)), S.a); S.cyc -= 5; break;
    case 0x8D: bus_write(rd16_abs(S.pc), S.a); S.pc += 2; S.cyc -= 4; break;
    case 0x9D: bus_write((u16)(rd16_abs(S.pc) + S.x), S.a); S.pc += 2; S.cyc -= 5; break;
    case 0x99: bus_write((u16)(rd16_abs(S.pc) + S.y), S.a); S.pc += 2; S.cyc -= 5; break;
    case 0x81: bus_write(rd16_zp((u8)(bus_read(S.pc++) + S.x)), S.a); S.cyc -= 6; break;
    case 0x91: bus_write((u16)(rd16_zp(bus_read(S.pc++)) + S.y), S.a); S.cyc -= 6; break;

    case 0x86: M->ram[bus_read(S.pc++)] = S.x; S.cyc -= 3; break;
    case 0x96: M->ram[(u8)(bus_read(S.pc++) + S.y)] = S.x; S.cyc -= 4; break;
    case 0x8E: bus_write(rd16_abs(S.pc), S.x); S.pc += 2; S.cyc -= 4; break;

    case 0x84: M->ram[bus_read(S.pc++)] = S.y; S.cyc -= 3; break;
    case 0x94: M->ram[(u8)(bus_read(S.pc++) + S.x)] = S.y; S.cyc -= 4; break;
    case 0x8C: bus_write(rd16_abs(S.pc), S.y); S.pc += 2; S.cyc -= 4; break;

    case 0x64: M->ram[bus_read(S.pc++)] = 0u; S.cyc -= 3; break;
    case 0x74: M->ram[(u8)(bus_read(S.pc++) + S.x)] = 0u; S.cyc -= 4; break;
    case 0x9C: bus_write(rd16_abs(S.pc), 0u); S.pc += 2; S.cyc -= 4; break;
    case 0x9E: bus_write((u16)(rd16_abs(S.pc) + S.x), 0u); S.pc += 2; S.cyc -= 5; break;

    /* Shifts & Rotates */
    case 0x0A: S.p = (u8)((S.p & ~FC) | (S.a >> 7)); S.a <<= 1; set_nz(S.a); S.cyc -= 2; break;
    case 0x06: addr = bus_read(S.pc++); goto do_asl;
    case 0x16: addr = (u8)(bus_read(S.pc++) + S.x); goto do_asl;
    case 0x0E: addr = rd16_abs(S.pc); S.pc += 2; goto do_asl;
    case 0x1E: addr = (u16)(rd16_abs(S.pc) + S.x); S.pc += 2; do_asl:
        v = bus_read(addr); S.p = (u8)((S.p & ~FC) | (v >> 7)); v <<= 1; bus_write(addr, v); set_nz(v); S.cyc -= 6; break;

    case 0x4A: S.p = (u8)((S.p & ~FC) | (S.a & 1u)); S.a >>= 1; set_nz(S.a); S.cyc -= 2; break;
    case 0x46: addr = bus_read(S.pc++); goto do_lsr;
    case 0x56: addr = (u8)(bus_read(S.pc++) + S.x); goto do_lsr;
    case 0x4E: addr = rd16_abs(S.pc); S.pc += 2; goto do_lsr;
    case 0x5E: addr = (u16)(rd16_abs(S.pc) + S.x); S.pc += 2; do_lsr:
        v = bus_read(addr); S.p = (u8)((S.p & ~FC) | (v & 1u)); v >>= 1; bus_write(addr, v); set_nz(v); S.cyc -= 6; break;

    case 0x2A: { u8 c = S.p & FC; S.p = (u8)((S.p & ~FC) | (S.a >> 7)); S.a = (u8)((S.a << 1) | c); set_nz(S.a); S.cyc -= 2; break; }
    case 0x26: addr = bus_read(S.pc++); goto do_rol;
    case 0x36: addr = (u8)(bus_read(S.pc++) + S.x); goto do_rol;
    case 0x2E: addr = rd16_abs(S.pc); S.pc += 2; goto do_rol;
    case 0x3E: addr = (u16)(rd16_abs(S.pc) + S.x); S.pc += 2; do_rol:
        { u8 c = S.p & FC; v = bus_read(addr); S.p = (u8)((S.p & ~FC) | (v >> 7)); v = (u8)((v << 1) | c); bus_write(addr, v); set_nz(v); S.cyc -= 6; break; }

    case 0x6A: { u8 c = (u8)((S.p & FC) << 7); S.p = (u8)((S.p & ~FC) | (S.a & 1u)); S.a = (u8)((S.a >> 1) | c); set_nz(S.a); S.cyc -= 2; break; }
    case 0x66: addr = bus_read(S.pc++); goto do_ror;
    case 0x76: addr = (u8)(bus_read(S.pc++) + S.x); goto do_ror;
    case 0x6E: addr = rd16_abs(S.pc); S.pc += 2; goto do_ror;
    case 0x7E: addr = (u16)(rd16_abs(S.pc) + S.x); S.pc += 2; do_ror:
        { u8 c = (u8)((S.p & FC) << 7); v = bus_read(addr); S.p = (u8)((S.p & ~FC) | (v & 1u)); v = (u8)((v >> 1) | c); bus_write(addr, v); set_nz(v); S.cyc -= 6; break; }

    /* INC / DEC (including CMOS INC A $1A & DEC A $3A!) */
    case 0x1A: S.a++; set_nz(S.a); S.cyc -= 2; break;
    case 0x3A: S.a--; set_nz(S.a); S.cyc -= 2; break;
    case 0xE6: addr = bus_read(S.pc++); goto do_inc;
    case 0xF6: addr = (u8)(bus_read(S.pc++) + S.x); goto do_inc;
    case 0xEE: addr = rd16_abs(S.pc); S.pc += 2; goto do_inc;
    case 0xFE: addr = (u16)(rd16_abs(S.pc) + S.x); S.pc += 2; do_inc:
        v = (u8)(bus_read(addr) + 1u); bus_write(addr, v); set_nz(v); S.cyc -= 6; break;

    case 0xC6: addr = bus_read(S.pc++); goto do_dec;
    case 0xD6: addr = (u8)(bus_read(S.pc++) + S.x); goto do_dec;
    case 0xCE: addr = rd16_abs(S.pc); S.pc += 2; goto do_dec;
    case 0xDE: addr = (u16)(rd16_abs(S.pc) + S.x); S.pc += 2; do_dec:
        v = (u8)(bus_read(addr) - 1u); bus_write(addr, v); set_nz(v); S.cyc -= 6; break;

    case 0xE8: S.x++; set_nz(S.x); S.cyc -= 2; break;
    case 0xCA: S.x--; set_nz(S.x); S.cyc -= 2; break;
    case 0xC8: S.y++; set_nz(S.y); S.cyc -= 2; break;
    case 0x88: S.y--; set_nz(S.y); S.cyc -= 2; break;

    /* Transfers & Stack (including PHX/PLX/PHY/PLY!) */
    case 0xAA: S.x = S.a; set_nz(S.x); S.cyc -= 2; break;
    case 0x8A: S.a = S.x; set_nz(S.a); S.cyc -= 2; break;
    case 0xA8: S.y = S.a; set_nz(S.y); S.cyc -= 2; break;
    case 0x98: S.a = S.y; set_nz(S.a); S.cyc -= 2; break;
    case 0xBA: S.x = S.sp; set_nz(S.x); S.cyc -= 2; break;
    case 0x9A: S.sp = S.x; S.cyc -= 2; break;

    case 0x48: push8(S.a); S.cyc -= 3; break;
    case 0x68: S.a = pull8(); set_nz(S.a); S.cyc -= 4; break;
    case 0xDA: push8(S.x); S.cyc -= 3; break;
    case 0xFA: S.x = pull8(); set_nz(S.x); S.cyc -= 4; break;
    case 0x5A: push8(S.y); S.cyc -= 3; break;
    case 0x7A: S.y = pull8(); set_nz(S.y); S.cyc -= 4; break;
    case 0x08: push8((u8)(S.p | FB | 0x20u)); S.cyc -= 3; break;
    case 0x28: S.p = (u8)((pull8() & ~FB) | 0x20u); S.cyc -= 4; break;

    /* Branches (including BRA $80!) */
    case 0x80: branch65c02(1); S.cyc -= 2; break;
    case 0x10: branch65c02(!(S.p & FN)); S.cyc -= 2; break;
    case 0x30: branch65c02( (S.p & FN)); S.cyc -= 2; break;
    case 0x50: branch65c02(!(S.p & FV)); S.cyc -= 2; break;
    case 0x70: branch65c02( (S.p & FV)); S.cyc -= 2; break;
    case 0x90: branch65c02(!(S.p & FC)); S.cyc -= 2; break;
    case 0xB0: branch65c02( (S.p & FC)); S.cyc -= 2; break;
    case 0xD0: branch65c02(!(S.p & FZ)); S.cyc -= 2; break;
    case 0xF0: branch65c02( (S.p & FZ)); S.cyc -= 2; break;

    /* Jumps & Subroutines (CMOS 65SC02 fixes $6C page-wrap and adds $7C JMP (abs,X)!) */
    case 0x4C: S.pc = rd16_abs(S.pc); S.cyc -= 3; break;
    case 0x6C: S.pc = rd16_abs(rd16_abs(S.pc)); S.cyc -= 6; break;
    case 0x7C: S.pc = rd16_abs((u16)(rd16_abs(S.pc) + S.x)); S.cyc -= 6; break;
    case 0x20: {
        u16 dst = rd16_abs(S.pc);
        push16((u16)(S.pc + 1u));
        S.pc = dst;
        S.cyc -= 6;
        break;
    }
    case 0x60: S.pc = (u16)(pull16() + 1u); S.cyc -= 6; break;
    case 0x40: S.p = (u8)((pull8() & ~FB) | 0x20u); S.pc = pull16(); S.cyc -= 6; break;

    /* Flags & WAI / STP */
    case 0x18: S.p &= (u8)~FC; S.cyc -= 2; break;
    case 0x38: S.p |= FC;      S.cyc -= 2; break;
    case 0x58: S.p &= (u8)~FI; S.cyc -= 2; break;
    case 0x78: S.p |= FI;      S.cyc -= 2; break;
    case 0xB8: S.p &= (u8)~FV; S.cyc -= 2; break;
    case 0xD8: S.p &= (u8)~FD; S.cyc -= 2; break;
    case 0xF8: S.p |= FD;      S.cyc -= 2; break;

    case 0xCB: /* WAI */
        if (!S.irq_flags) S.cpu_asleep = 1;
        S.cyc -= 3;
        break;
    case 0xDB: /* STP */
        S.jammed = 1;
        S.pc--;
        S.cyc = 0;
        break;

    /* CMOS multi-byte NOPs */
    case 0x02: case 0x22: case 0x42: case 0x62: case 0x82: case 0xC2: case 0xE2:
    case 0x44: case 0x54: case 0xD4: case 0xF4:
        S.pc++; S.cyc -= 3; break;
    case 0x5C: case 0xDC: case 0xFC:
        S.pc += 2; S.cyc -= 4; break;

    default:
        S.cyc -= 2;
        break;
    }
}

/* ---- Built-in 512B Boot ROM Setup & Public Interface ---- */
static void build_builtin_bootrom(void)
{
    mem_fill: ;
    for (int i = 0; i < 0x200; i++)
        M->bios[i] = 0x60u;              /* RTS safe default */
    (void)&&mem_fill;
    /* Vectors at $FFFA..$FFFF */
    M->bios[0x1FA] = 0x00u; M->bios[0x1FB] = 0xFEu; /* NMI   -> $FE00 */
    M->bios[0x1FC] = 0x19u; M->bios[0x1FD] = 0xFEu; /* RESET -> $FE19 */
    M->bios[0x1FE] = 0x80u; M->bios[0x1FF] = 0xFEu; /* IRQ   -> $FE80 (RTI) */
    M->bios[0x080] = 0x40u;                         /* $FE80: RTI */
}

void lnx_set_bios(const u8 *rom, u32 size)
{
    S.ext_bios = (rom && size == 0x200u) ? rom : 0;
    S.ext_bios_size = S.ext_bios ? size : 0u;
}

static void fmt_lnx_info(void)
{
    char *d = S.info;
    const char *t = S.title[0] ? S.title : "Atari Lynx ROM";
    for (int i = 0; t[i] && d - S.info < 44; i++)
        *d++ = t[i];
    const char *s1 = " (";
    while (*s1) *d++ = *s1++;
    u32 kb = S.rom_size >> 10;
    if (!kb) kb = 1;
    char nb[16]; int ni = 0; u32 v = kb;
    while (v > 0) { nb[ni++] = (char)('0' + (v % 10u)); v /= 10u; }
    while (ni > 0) *d++ = nb[--ni];
    const char *s2 = S.is_bll_o ? " KB BLL" : " KB Lynx";
    while (*s2) *d++ = *s2++;
    if (S.rotation == ROT_LEFT)       { const char *r = ", rot-L"; while (*r) *d++ = *r++; }
    else if (S.rotation == ROT_RIGHT) { const char *r = ", rot-R"; while (*r) *d++ = *r++; }
    *d++ = ')';
    *d = 0;
}

const char *lnx_load(u8 *image, u32 size)
{
    if (!image || size < 64u)
        return "too small to be an Atari Lynx cartridge (under 64 bytes)";
    if (size > 0x100040u)
        return "larger than 1 MB Atari Lynx cartridge limit";

    const u8 *saved_bios = S.ext_bios;
    u32 saved_bios_sz = S.ext_bios_size;
    mem_zero(&S, sizeof(S));
    S.ext_bios = saved_bios;
    S.ext_bios_size = saved_bios_sz;

    /* Format 1: Standard 64-byte "LYNX" header (.lnx) */
    if (image[0] == 'L' && image[1] == 'Y' && image[2] == 'N' && image[3] == 'X' && size > 64u) {
        u16 p0 = (u16)(image[4] | ((u16)image[5] << 8));
        u16 p1 = (u16)(image[6] | ((u16)image[7] << 8));
        if (p0 == 0 || p0 > 4096u)
            return "invalid bank 0 page size in LYNX header";

        int ti = 0;
        for (int i = 0; i < 32; i++) {
            u8 c = image[10 + i];
            if (!c) break;
            if (c >= 0x20u && c < 0x7Fu)
                S.title[ti++] = (char)c;
        }
        while (ti > 0 && S.title[ti - 1] == ' ')
            ti--;
        S.title[ti] = 0;

        S.rotation  = (image[58] <= 2u) ? image[58] : 0u;
        S.rom       = image + 64u;
        S.rom_size  = size - 64u;
        S.page_b0   = p0;
        S.page_b1   = p1;
        S.bank0     = S.rom;
        u32 max_b0  = (u32)p0 * 256u;
        /* AUDIN banked 512 KB carts set bit 1 of header byte 59 or have rom_size == 2*max_b0 with p1==0 */
        if ((image[59] & 0x02u) || (p1 == 0 && S.rom_size > max_b0)) {
            S.audin_banked = 1;
            S.bank0_size   = S.rom_size;
        } else {
            S.bank0_size = (S.rom_size < max_b0) ? S.rom_size : max_b0;
            if (p1 > 0 && S.rom_size > max_b0) {
                S.bank1      = S.rom + max_b0;
                S.bank1_size = S.rom_size - max_b0;
            }
        }
    }
    /* Format 2: Homebrew BLL .o binary ($80 $08 + big-endian load_addr + big-endian len+10 + "BS93") */
    else if (image[0] == 0x80u && image[1] == 0x08u && size >= 16u &&
             image[6] == 'B' && image[7] == 'S' && image[8] == '9' && image[9] == '3') {
        u16 load_addr = (u16)(((u16)image[2] << 8) | image[3]);
        u16 raw_len   = (u16)(((u16)image[4] << 8) | image[5]);
        u16 pay_len   = (raw_len >= 10u) ? (u16)(raw_len - 10u) : raw_len;
        if (load_addr < 0x0100u || (u32)load_addr + pay_len > 0xFC00u || 10u + pay_len > size)
            return "invalid BLL header dimensions";
        S.is_bll_o      = 1;
        S.bll_load_addr = load_addr;
        S.bll_load_len  = pay_len;
        S.rom           = image + 10u;
        S.rom_size      = pay_len;
    }
    /* Format 3: Headerless .lyx raw cartridge dump (must start with valid RSA block count 0xFB..0xFF) */
    else if (image[0] >= 0xFBu &&
             (size == 0x10000u || size == 0x20000u || size == 0x40000u || size == 0x80000u)) {
        S.rom        = image;
        S.rom_size   = size;
        S.page_b0    = size / 256u;
        S.bank0      = image;
        S.bank0_size = size;
        if (S.page_b0 > 1024u) {
            S.page_b0 = 1024u;
            S.audin_banked = 1;
        }
    } else {
        return "not a valid Atari Lynx ROM (expected LYNX header, BLL BS93 header, or raw .lyx image)";
    }

    mem_zero(M->sram, sizeof(M->sram));
    S.save_dirty = 0;

    lnx_reset();
    fmt_lnx_info();
    return 0;
}

void lnx_reset(void)
{
    mem_zero(M->ram, sizeof(M->ram));
    mem_zero(M->suzy, sizeof(M->suzy));
    mem_zero(M->mikey, sizeof(M->mikey));

    if (S.ext_bios && S.ext_bios_size == 0x200u) {
        mem_copy(M->bios, S.ext_bios, 0x200u);
        S.using_hle_bios = 0;
    } else {
        build_builtin_bootrom();
        S.using_hle_bios = 1;
    }

    for (int i = 0; i < 16; i++) {
        S.pal_bgr[i] = 0;
        S.last_pen_map[i] = (u8)i;
    }
    mem_zero(S.tmr, sizeof(S.tmr));
    mem_zero(S.aud, sizeof(S.aud));
    S.irq_flags = 0;
    S.mstereo   = 0;
    S.dispadr   = 0xDF80u;
    S.dispctl   = 0xD0u;
    S.sprsys_r  = 0;
    S.sprsys_w  = 0;

    S.sysctl1 = 0;
    S.iodir   = 0;
    S.iodat   = 0;
    S.cart_shifter = 0;
    S.cart_offset  = 0;

    S.a = S.x = S.y = 0;
    S.sp = 0xFFu;
    S.p  = FI | 0x20u;
    S.cyc = 0;
    S.cpu_asleep = 0;
    S.suzy_done_wakeup = 0;
    S.spr_pending = 0;
    S.spr_countdown = 0;
    S.jammed = 0;

    if (S.is_bll_o) {
        mem_copy(M->ram + S.bll_load_addr, S.rom, S.bll_load_len);
        S.mapctl = 0x0Cu;                /* RAM at $FE00..$FFFF, Suzy & Mikey active */
        S.pc = S.bll_load_addr;
    } else {
        S.mapctl = 0x00u;                /* Boot ROM active -> starts at $FE19 */
        S.pc = rd16_abs(0xFFFCu);
    }
}

void lnx_frame(u16 pad, u16 *picture)
{
    S.pad = pad;

    for (int s = 0; s < SLICES_PER_FRAME; s++) {
        S.cyc += SLICE_CPU_CYC;
        while (S.cyc > 0 && !S.jammed)
            step_65sc02();
        if (S.cpu_asleep && S.cyc > 0)
            S.cyc = 0;
        mikey_step_slice(SLICE_US);
    }

    if (!picture)
        return;

    int flip = (S.dispctl >> 5) & 1;
    u16 base = S.dispadr;

    if (S.rotation == ROT_NONE) {
        for (int y = 0; y < LNX_H; y++) {
            int sy = flip ? (LNX_H - 1 - y) : y;
            u16 row_addr = (u16)(base + (u16)(sy * 80));
            u16 *out = picture + (u32)y * LNX_W;
            for (int bx = 0; bx < 80; bx++) {
                u8 b = M->ram[(u16)(row_addr + (u16)bx)];
                u16 c0 = S.pal_bgr[b >> 4];
                u16 c1 = S.pal_bgr[b & 0x0Fu];
                if (flip) {
                    out[LNX_W - 1 - bx * 2] = c0;
                    out[LNX_W - 2 - bx * 2] = c1;
                } else {
                    out[bx * 2 + 0] = c0;
                    out[bx * 2 + 1] = c1;
                }
            }
        }
    } else {
        /* Portrait rotated 102 x 160 output */
        for (int y = 0; y < LNX_H; y++) {
            int sy = flip ? (LNX_H - 1 - y) : y;
            u16 row_addr = (u16)(base + (u16)(sy * 80));
            for (int bx = 0; bx < 80; bx++) {
                u8 b = M->ram[(u16)(row_addr + (u16)bx)];
                if (flip) {
                    M->rot_buf[y][LNX_W - 1 - bx * 2] = S.pal_bgr[b >> 4];
                    M->rot_buf[y][LNX_W - 2 - bx * 2] = S.pal_bgr[b & 0x0Fu];
                } else {
                    M->rot_buf[y][bx * 2 + 0] = S.pal_bgr[b >> 4];
                    M->rot_buf[y][bx * 2 + 1] = S.pal_bgr[b & 0x0Fu];
                }
            }
        }
        for (int py = 0; py < LNX_W; py++) {
            u16 *out = picture + (u32)py * LNX_H;
            for (int px = 0; px < LNX_H; px++) {
                if (S.rotation == ROT_LEFT)
                    out[px] = M->rot_buf[px][LNX_W - 1 - py];
                else
                    out[px] = M->rot_buf[LNX_H - 1 - px][py];
            }
        }
    }
}

int lnx_width(void)
{
    return (S.rotation == ROT_NONE) ? LNX_W : LNX_H;
}

int lnx_height(void)
{
    return (S.rotation == ROT_NONE) ? LNX_H : LNX_W;
}

const char *lnx_info(void)
{
    return S.info;
}

u8 *lnx_save_ram(u32 *size, int *battery)
{
    *size = sizeof(M->sram);
    *battery = 0;
    return M->sram;
}

int lnx_save_changed(void)
{
    int c = S.save_dirty;
    S.save_dirty = 0;
    return c;
}

int lnx_jammed(void)
{
    return S.jammed;
}

void lnx_audio_rate(u32 hz)
{
    S.snd_rate = hz;
    S.snd_phase = 0;
    S.snd_rd = S.snd_wr = 0;
}

int lnx_audio(s16 *out, int max)
{
    int avail = (int)(S.snd_wr - S.snd_rd);
    if (avail > max)
        avail = max;
    for (int i = 0; i < avail; i++) {
        out[i] = M->snd_ring[S.snd_rd & (SND_RING - 1u)];
        S.snd_rd++;
    }
    return avail;
}
