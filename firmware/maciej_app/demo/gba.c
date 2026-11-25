/* A Nintendo Game Boy Advance (.gba): see gba.h. */
#pragma GCC optimize("O2")
#include "gba.h"

#ifdef GBA_HOST
typedef unsigned long long u64;
#else
#include "hw.h"
#endif
typedef signed long long s64;

#define INLINE static inline __attribute__((always_inline))

/* Clock & scanline geometry:
   Master clock = 16,777,216 Hz (2^24 Hz)
   Scanline     = 1,232 cycles (960 HDraw + 272 HBlank; HBlank flag set after 1,006 cycles)
   Frame        = 228 scanlines (160 VDraw + 68 VBlank) = 280,896 cycles (59.7275 Hz) */
#define GBA_CLOCK_HZ     16777216u
#define HDRAW_CYC        1006
#define HBLANK_CYC       226
#define LINE_CYC         1232
#define VDRAW_LINES      160
#define TOTAL_LINES      228

/* CPSR bits & processor modes */
#define FLAG_N           0x80000000u
#define FLAG_Z           0x40000000u
#define FLAG_C           0x20000000u
#define FLAG_V           0x10000000u
#define CPSR_I           0x00000080u
#define CPSR_F           0x00000040u
#define CPSR_T           0x00000020u
#define CPSR_MODE_MASK   0x0000001Fu

#define MODE_USR         0x10u
#define MODE_FIQ         0x11u
#define MODE_IRQ         0x12u
#define MODE_SVC         0x13u
#define MODE_ABT         0x17u
#define MODE_UND         0x1Bu
#define MODE_SYS         0x1Fu

/* Interrupt bit positions (IE / IF) */
#define IRQ_VBLANK       0x0001u
#define IRQ_HBLANK       0x0002u
#define IRQ_VCOUNT       0x0004u
#define IRQ_TIMER0       0x0008u
#define IRQ_TIMER1       0x0010u
#define IRQ_TIMER2       0x0020u
#define IRQ_TIMER3       0x0040u
#define IRQ_SERIAL       0x0080u
#define IRQ_DMA0         0x0100u
#define IRQ_DMA1         0x0200u
#define IRQ_DMA2         0x0400u
#define IRQ_DMA3         0x0800u
#define IRQ_KEYPAD       0x1000u
#define IRQ_GAMEPAK      0x2000u

/* Save types */
enum {
    SAVE_NONE = 0,
    SAVE_SRAM,
    SAVE_FLASH64,
    SAVE_FLASH128,
    SAVE_EEPROM
};

/* Flash state machine */
enum {
    FL_READY = 0,
    FL_CMD1,
    FL_CMD2,
    FL_ERASE_PREP,
    FL_WRITE_BYTE,
    FL_BANK_SEL
};

#define SND_RING         8192            /* stereo pairs (16,384 s16 samples) */

struct gba_dma {
    u32 sad, dad;
    u16 cnt_l, cnt_h;
    u32 int_sad, int_dad, int_cnt;
    u32 latch;
};

struct gba_timer {
    u16 counter, reload, cnt;
    u32 prescale_acc;
};

struct gba_fifo {
    s8 buf[32];
    u8 rd, wr, count;
    s8 sample;
};

struct gba_psg_sq {
    u16 nr0, nr1, nr2, nr3, nr4;
    u32 timer, phase;
    u8 duty, vol, env_period, env_dir, env_timer;
    u8 len_cnt, len_en, enabled;
    u16 sweep_freq, sweep_timer;
    u8 sweep_period, sweep_dir, sweep_shift, sweep_en;
};

struct gba_psg_wave {
    u16 nr0, nr1, nr2, nr3, nr4;
    u8 ram[32] __attribute__((aligned(4))); /* two 16-byte banks = 64 4-bit samples */
    u32 timer, pos;
    u16 len_cnt;
    u8 len_en, enabled;
};

struct gba_psg_noise {
    u16 nr1, nr2, nr3, nr4;
    u32 timer;
    u16 lfsr;
    u8 vol, env_period, env_dir, env_timer;
    u8 len_cnt, len_en, enabled;
};

/* Large backing RAM placed in EMU_RAM_PHYS on the S3811 (or BSS under GBA_HOST) */
struct gba_mem {
    u8 bios[0x4000]   __attribute__((aligned(4))); /* 16 KB system BIOS */
    u8 ewram[0x40000] __attribute__((aligned(4))); /* 256 KB external WRAM (0x02000000) */
    u8 iwram[0x8000]  __attribute__((aligned(4))); /* 32 KB internal fast WRAM (0x03000000) */
    u8 io[0x400]      __attribute__((aligned(4))); /* 1 KB MMIO registers (0x04000000) */
    u16 pal[0x200]    __attribute__((aligned(4))); /* 1 KB palette RAM in native BGR555 */
    u8 vram[0x18000]  __attribute__((aligned(4))); /* 96 KB VRAM (0x06000000) */
    u16 oam[0x200]    __attribute__((aligned(4))); /* 1 KB OAM (0x07000000) */
    u8 sram[0x20000]  __attribute__((aligned(4))); /* 128 KB save buffer (SRAM / Flash / EEPROM) */
    s16 sin_lut[256];                    /* 512 B 1.14 sine table for BIOS affine SWIs */
    u8 cond_lut[16][16];                 /* ARM condition evaluation table [cond][nzcv] */
    s16 snd_ring[SND_RING];              /* 48 kHz mono output ring (matching snd_write) */
};

#ifdef GBA_HOST
static struct gba_mem gba_host_mem;
#define M (&gba_host_mem)
#else
#define M ((struct gba_mem *)KSEG0(EMU_RAM_PHYS))
#endif

static struct {
    const u8 *rom;
    u32 rom_size;
    const u8 *ext_bios;
    u32 ext_bios_size;
    int using_hle_bios;

    /* ARM7TDMI state */
    u32 r[16];
    u32 cpsr;
    u32 spsr;
    /* Banked registers: 0=USR/SYS, 1=FIQ, 2=IRQ, 3=SVC, 4=ABT, 5=UND */
    u32 bank_r13[6];
    u32 bank_r14[6];
    u32 bank_spsr[6];
    u32 usr_r8_12[5];
    u32 fiq_r8_12[5];

    u32 bios_latch;
    u32 last_fetch;
    int halted;
    int jammed;
    int irq_line;

    /* Cycle counters */
    s32 cyc_left;
    u32 tmr_pend;
    s32 tmr_next_cyc;
    u8 ws_n16[16], ws_s16[16], ws_n32[16], ws_s32[16];
    u8 active_timers;                    /* bitmask of enabled non-cascade timers */

    /* PPU internal affine reference points (28.8 signed fixed point) */
    s32 bgx[2], bgy[2];
    u16 vcount;
    u16 keyinput;

    /* DMA & Timers */
    struct gba_dma dma[4];
    struct gba_timer tmr[4];

    /* Audio */
    struct gba_fifo fifo[2];
    struct gba_psg_sq psg1, psg2;
    struct gba_psg_wave psg3;
    struct gba_psg_noise psg4;
    u32 psg_frame_acc;
    u8 psg_frame_step;
    u32 snd_rate;
    u32 snd_phase;
    u32 snd_rd, snd_wr;

    /* Save media */
    int save_type;
    u32 save_size;
    int save_dirty;
    u8 flash_state;
    u8 flash_id_mode;
    u8 flash_bank;
    /* EEPROM serial state */
    u16 eep_buf[80];
    u8 eep_idx;
    u8 eep_addr_bits;                    /* 6 (512B) or 14 (8KB), 0 = auto */
    u16 eep_read_addr;
    u8 eep_read_bit;

    char title[16];
    char code[8];
    char info[128];
} S;

/* ---- Aligned little-endian memory helpers (1-cycle lw/sw/lhu/sh on MIPS32) ---- */
INLINE u16 rd16le(const u8 *p)
{
    return *(const u16 *)p;
}

INLINE u32 rd32le(const u8 *p)
{
    return *(const u32 *)p;
}

INLINE void wr16le(u8 *p, u16 v)
{
    *(u16 *)p = v;
}

INLINE void wr32le(u8 *p, u32 v)
{
    *(u32 *)p = v;
}

INLINE u16 io16(u32 off)
{
    return rd16le(M->io + off);
}

INLINE void set_io16(u32 off, u16 v)
{
    wr16le(M->io + off, v);
}

INLINE u32 ror32(u32 v, u32 sh)
{
    sh &= 31u;
    return sh ? ((v >> sh) | (v << (32u - sh))) : v;
}

INLINE u32 popcnt16(u32 x)
{
    x -= (x >> 1) & 0x5555u;
    x = (x & 0x3333u) + ((x >> 2) & 0x3333u);
    x = (x + (x >> 4)) & 0x0F0Fu;
    return (x + (x >> 8)) & 0x1Fu;
}

static void mem_zero(void *dst, u32 n)
{
    u8 *p = (u8 *)dst;
    for (u32 i = 0; i < n; i++)
        p[i] = 0;
}

static void mem_fill(void *dst, u8 val, u32 n)
{
    u8 *p = (u8 *)dst;
    for (u32 i = 0; i < n; i++)
        p[i] = val;
}

static void mem_copy(void *dst, const void *src, u32 n)
{
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    for (u32 i = 0; i < n; i++)
        d[i] = s[i];
}

/* ---- Lookup tables (ARM conditions, BIOS sine) ----
   Built at every load: they are in the players' shared memory (M), which the next machine played writes over.
   Built once (a flag here said so), a Game Boy Advance game started after a game of another machine ran with
   that machine's bytes for the ARM conditions -- Another World showed one still picture at half speed. */
static void init_luts(void)
{
    for (u32 f = 0; f < 16; f++) {
        int n = (f >> 3) & 1;
        int z = (f >> 2) & 1;
        int c = (f >> 1) & 1;
        int v = f & 1;
        M->cond_lut[0x0][f] = (u8)(z);
        M->cond_lut[0x1][f] = (u8)(!z);
        M->cond_lut[0x2][f] = (u8)(c);
        M->cond_lut[0x3][f] = (u8)(!c);
        M->cond_lut[0x4][f] = (u8)(n);
        M->cond_lut[0x5][f] = (u8)(!n);
        M->cond_lut[0x6][f] = (u8)(v);
        M->cond_lut[0x7][f] = (u8)(!v);
        M->cond_lut[0x8][f] = (u8)(c && !z);
        M->cond_lut[0x9][f] = (u8)(!c || z);
        M->cond_lut[0xA][f] = (u8)(n == v);
        M->cond_lut[0xB][f] = (u8)(n != v);
        M->cond_lut[0xC][f] = (u8)(!z && (n == v));
        M->cond_lut[0xD][f] = (u8)(z || (n != v));
        M->cond_lut[0xE][f] = 1;
        M->cond_lut[0xF][f] = 1;
    }
    /* High-accuracy 1.14 sine table for i = 0..255:
       Quadrant symmetry + 5th-order polynomial on [0, pi/2] */
    for (int i = 0; i <= 64; i++) {
        /* x = (i / 64) * (pi / 2) in Q16: pi/2 * 65536 = 102944 */
        s64 x = ((s64)i * 102944) >> 6;          /* Q16 in [0, 102944] */
        s64 x2 = (x * x) >> 16;                  /* Q16 */
        s64 x3 = (x2 * x) >> 16;                 /* Q16 */
        s64 x5 = (x3 * x2) >> 16;                /* Q16 */
        s64 x7 = (x5 * x2) >> 16;                /* Q16 */
        /* sin(x) = x - x^3/6 + x^5/120 - x^7/5040 */
        s64 s = x - ((x3 * 10923) >> 16) + ((x5 * 546) >> 16) - ((x7 * 13) >> 16);
        s32 v = (s32)((s + 2) >> 2);             /* Q14 */
        if (i == 0)  v = 0;
        if (i == 64) v = 16384;
        if (v > 16384) v = 16384;
        M->sin_lut[i] = (s16)v;
        if (i < 64)
            M->sin_lut[128 - i] = (s16)v;
    }
    M->sin_lut[128] = 0;
    for (int i = 1; i < 128; i++)
        M->sin_lut[128 + i] = (s16)(-M->sin_lut[i]);
}

/* ---- Waitstate table update (WAITCNT 0x04000204) ---- */
static void update_waitstates(u16 waitcnt)
{
    static const u8 n_tab[4] = { 4, 3, 2, 8 };
    static const u8 s0_tab[2] = { 2, 1 };
    static const u8 s1_tab[2] = { 4, 1 };
    static const u8 s2_tab[2] = { 8, 1 };

    for (int i = 0; i < 16; i++) {
        S.ws_n16[i] = 1;
        S.ws_s16[i] = 1;
        S.ws_n32[i] = 1;
        S.ws_s32[i] = 1;
    }
    /* EWRAM: 16-bit bus, 2 waitstates -> 3 cyc (16b), 6 cyc (32b) */
    S.ws_n16[2] = S.ws_s16[2] = 3;
    S.ws_n32[2] = S.ws_s32[2] = 6;
    /* Palette & VRAM: 16-bit bus, 0 waitstates -> 1 cyc (16b), 2 cyc (32b) */
    S.ws_n16[5] = S.ws_s16[5] = 1;
    S.ws_n32[5] = S.ws_s32[5] = 2;
    S.ws_n16[6] = S.ws_s16[6] = 1;
    S.ws_n32[6] = S.ws_s32[6] = 2;

    u8 sram_w = (u8)(1 + n_tab[waitcnt & 3]);
    u8 ws0_n  = (u8)(1 + n_tab[(waitcnt >> 2) & 3]);
    u8 ws0_s  = (u8)(1 + s0_tab[(waitcnt >> 4) & 1]);
    u8 ws1_n  = (u8)(1 + n_tab[(waitcnt >> 5) & 3]);
    u8 ws1_s  = (u8)(1 + s1_tab[(waitcnt >> 7) & 1]);
    u8 ws2_n  = (u8)(1 + n_tab[(waitcnt >> 8) & 3]);
    u8 ws2_s  = (u8)(1 + s2_tab[(waitcnt >> 10) & 1]);

    S.ws_n16[8] = S.ws_n16[9] = ws0_n;
    S.ws_s16[8] = S.ws_s16[9] = ws0_s;
    S.ws_n32[8] = S.ws_n32[9] = (u8)(ws0_n + ws0_s);
    S.ws_s32[8] = S.ws_s32[9] = (u8)(ws0_s + ws0_s);

    S.ws_n16[10] = S.ws_n16[11] = ws1_n;
    S.ws_s16[10] = S.ws_s16[11] = ws1_s;
    S.ws_n32[10] = S.ws_n32[11] = (u8)(ws1_n + ws1_s);
    S.ws_s32[10] = S.ws_s32[11] = (u8)(ws1_s + ws1_s);

    S.ws_n16[12] = S.ws_n16[13] = ws2_n;
    S.ws_s16[12] = S.ws_s16[13] = ws2_s;
    S.ws_n32[12] = S.ws_n32[13] = (u8)(ws2_n + ws2_s);
    S.ws_s32[12] = S.ws_s32[13] = (u8)(ws2_s + ws2_s);

    S.ws_n16[14] = S.ws_n16[15] = sram_w;
    S.ws_s16[14] = S.ws_s16[15] = sram_w;
    S.ws_n32[14] = S.ws_n32[15] = sram_w;
    S.ws_s32[14] = S.ws_s32[15] = sram_w;
}

/* ---- Built-in Clean-Room ARM7TDMI BIOS ----
   Matches exact GBA BIOS vector layout, IRQ trampoline addresses (0x128..0x144),
   SWI return instruction (0x188..0x190), and IntrWait/VBlankIntrWait loop so
   both hardware BIOS protection tests (jsmolka/bios) and commercial/homebrew SWIs
   work identically without an external gba_bios.bin. */
#define BIOS_SWI_TRAP_INSN 0xEFEE0000u   /* internal HLE SWI dispatch marker inside BIOS */

static void build_builtin_bios(void)
{
    mem_zero(M->bios, sizeof(M->bios));

    /* Exception vectors 0x00000000..0x0000001C */
    wr32le(M->bios + 0x00, 0xEA00001Eu); /* 0x00: B 0x00000080 (Reset) */
    wr32le(M->bios + 0x04, 0xEAFFFFFEu); /* 0x04: B . (Undefined) */
    wr32le(M->bios + 0x08, 0xEA00004Cu); /* 0x08: B 0x00000140 -> 0x160 SWI entry */
    wr32le(M->bios + 0x0C, 0xEAFFFFFEu); /* 0x0C: B . */
    wr32le(M->bios + 0x10, 0xEAFFFFFEu); /* 0x10: B . */
    wr32le(M->bios + 0x14, 0xEAFFFFFEu); /* 0x14: B . */
    wr32le(M->bios + 0x18, 0xEA000042u); /* 0x18: B 0x00000128 (IRQ) */
    wr32le(M->bios + 0x1C, 0xEAFFFFFEu); /* 0x1C: B . (FIQ) */

    /* Fix 0x08 vector -> 0x00000160: (0x160 - (0x08 + 8)) / 4 = 0x54 */
    wr32le(M->bios + 0x08, 0xEA000054u);

    /* Reset / SoftReset stub at 0x00000080..0x000000E4:
       0x0DC = BX R0 (jumps to 0x08000000), 0x0E4 = 0xE129F000 (MSR CPSR_fc, R0)
       so post-boot bios_latch is 0xE129F000 (jsmolka/bios t001)! */
    wr32le(M->bios + 0x080, 0xE3A00302u); /* MOV R0, #0x08000000 */
    wr32le(M->bios + 0x0DC, 0xE12FFF10u); /* BX  R0 */
    wr32le(M->bios + 0x0E4, 0xE129F000u); /* post-boot prefetch latch = 0xE129F000 */

    /* Hardware-exact 6-instruction IRQ trampoline at 0x00000128..0x00000144:
       During user handler (called by 0x134): prefetch at 0x13C = 0xE25EF004 (t003)
       After IRQ return (from 0x13C):         prefetch at 0x144 = 0xE55EC002 (t004) */
    wr32le(M->bios + 0x128, 0xE92D500Fu); /* STMFD SP!, {R0-R3, R12, LR} */
    wr32le(M->bios + 0x12C, 0xE3A00301u); /* MOV   R0, #0x04000000 */
    wr32le(M->bios + 0x130, 0xE28FE000u); /* ADD   LR, PC, #0  (LR = 0x138) */
    wr32le(M->bios + 0x134, 0xE510F004u); /* LDR   PC, [R0, #-4] ([0x03FFFFFC]) */
    wr32le(M->bios + 0x138, 0xE8BD500Fu); /* LDMFD SP!, {R0-R3, R12, LR} */
    wr32le(M->bios + 0x13C, 0xE25EF004u); /* SUBS  PC, LR, #4 */
    wr32le(M->bios + 0x140, 0xEAFFFFFEu);
    wr32le(M->bios + 0x144, 0xE55EC002u); /* post-IRQ prefetch latch = 0xE55EC002 */

    /* SWI entry at 0x00000160:
       Executes C HLE trap at 0x160; for SWI 0x04/0x05 (IntrWait / VBlankIntrWait)
       C handler jumps to 0x000001A0 (real ARM IntrWait loop); all other SWIs advance
       to 0x00000188 (MOVS PC, LR) whose prefetch at 0x190 is 0xE3A02004 (t002)! */
    wr32le(M->bios + 0x160, BIOS_SWI_TRAP_INSN);
    wr32le(M->bios + 0x164, 0xEA000007u); /* B 0x00000188 */
    wr32le(M->bios + 0x188, 0xE1B0F00Eu); /* MOVS PC, LR */
    wr32le(M->bios + 0x18C, 0xEAFFFFFEu);
    wr32le(M->bios + 0x190, 0xE3A02004u); /* post-SWI prefetch latch = 0xE3A02004 */

    /* Real ARM IntrWait loop at 0x000001A0 (entered in SVC mode with R0=clear, R1=flags):
       Uses [0x03FFFFF8] (= 0x03007FF8 INTR_WAIT_FLAGS), enables IME, switches to SYS mode
       with IRQs enabled during Halt so nested IRQs use SP_irq/SP_usr cleanly, then returns
       via 0x00000188 (MOVS PC, LR)! */
    u32 p = 0x1A0;
    wr32le(M->bios + p, 0xE92D400Cu); p += 4; /* 1A0: STMFD SP!, {R2, R3, LR} */
    wr32le(M->bios + p, 0xE3A02301u); p += 4; /* 1A4: MOV   R2, #0x04000000 */
    wr32le(M->bios + p, 0xE3A03000u); p += 4; /* 1A8: MOV   R3, #0 */
    wr32le(M->bios + p, 0xE5823208u); p += 4; /* 1AC: STR   R3, [R2, #0x208] (IME = 0) */
    wr32le(M->bios + p, 0xE3500000u); p += 4; /* 1B0: CMP   R0, #0 */
    wr32le(M->bios + p, 0x15123008u); p += 4; /* 1B4: LDRNE R3, [R2, #-8]    ([0x03007FF8]) */
    wr32le(M->bios + p, 0x11C33001u); p += 4; /* 1B8: BICNE R3, R3, R1 */
    wr32le(M->bios + p, 0x15023008u); p += 4; /* 1BC: STRNE R3, [R2, #-8] */
    wr32le(M->bios + p, 0xE3A03001u); p += 4; /* 1C0: MOV   R3, #1 */
    wr32le(M->bios + p, 0xE5823208u); p += 4; /* 1C4: STR   R3, [R2, #0x208] (IME = 1) */
    /* loop (0x1C8): */
    wr32le(M->bios + p, 0xE3A03000u); p += 4; /* 1C8: MOV   R3, #0 */
    wr32le(M->bios + p, 0xE5C23301u); p += 4; /* 1CC: STRB  R3, [R2, #0x301] (HALTCNT = Halt) */
    wr32le(M->bios + p, 0xE10F0000u); p += 4; /* 1D0: MRS   R0, CPSR */
    wr32le(M->bios + p, 0xE321F01Fu); p += 4; /* 1D4: MSR   CPSR_c, #0x1F (SYS mode, IRQ enabled!) */
    wr32le(M->bios + p, 0xE1A00000u); p += 4; /* 1D8: NOP   (IRQ fires here) */
    wr32le(M->bios + p, 0xE121F000u); p += 4; /* 1DC: MSR   CPSR_c, R0 (back to SVC, IRQ masked) */
    wr32le(M->bios + p, 0xE3A03000u); p += 4; /* 1E0: MOV   R3, #0 */
    wr32le(M->bios + p, 0xE5823208u); p += 4; /* 1E4: STR   R3, [R2, #0x208] (IME = 0) */
    wr32le(M->bios + p, 0xE5123008u); p += 4; /* 1E8: LDR   R3, [R2, #-8] */
    wr32le(M->bios + p, 0xE0130001u); p += 4; /* 1EC: ANDS  R0, R3, R1 */
    wr32le(M->bios + p, 0x1A000002u); p += 4; /* 1F0: BNE   done (0x200) */
    wr32le(M->bios + p, 0xE3A03001u); p += 4; /* 1F4: MOV   R3, #1 */
    wr32le(M->bios + p, 0xE5823208u); p += 4; /* 1F8: STR   R3, [R2, #0x208] (IME = 1) */
    wr32le(M->bios + p, 0xEAFFFFF1u); p += 4; /* 1FC: B     loop (0x1C8) */
    /* done (0x200): */
    wr32le(M->bios + p, 0xE1C33000u); p += 4; /* 200: BIC   R3, R3, R0 */
    wr32le(M->bios + p, 0xE5023008u); p += 4; /* 204: STR   R3, [R2, #-8] */
    wr32le(M->bios + p, 0xE3A03001u); p += 4; /* 208: MOV   R3, #1 */
    wr32le(M->bios + p, 0xE5823208u); p += 4; /* 20C: STR   R3, [R2, #0x208] (IME = 1) */
    wr32le(M->bios + p, 0xE8BD400Cu); p += 4; /* 210: LDMFD SP!, {R2, R3, LR} */
    wr32le(M->bios + p, 0xEAFFFFDBu);         /* 214: B     0x00000188 (MOVS PC, LR) */

    /* Stub function at 0x00000300 ("BX LR") for SoundGetJumpList table pointers */
    wr32le(M->bios + 0x300, 0xE12FFF1Eu);     /* BX LR */
}

/* ---- CPU mode & register banking ---- */
INLINE int mode_index(u32 mode)
{
    switch (mode & 0x1Fu) {
    case MODE_FIQ: return 1;
    case MODE_IRQ: return 2;
    case MODE_SVC: return 3;
    case MODE_ABT: return 4;
    case MODE_UND: return 5;
    default:       return 0; /* USR / SYS */
    }
}

static void cpu_switch_mode(u32 new_mode)
{
    u32 old_mode = S.cpsr & CPSR_MODE_MASK;
    new_mode &= CPSR_MODE_MASK;
    if (old_mode == new_mode)
        return;
    int oi = mode_index(old_mode);
    int ni = mode_index(new_mode);
    S.bank_r13[oi] = S.r[13];
    S.bank_r14[oi] = S.r[14];
    if (oi > 0)
        S.bank_spsr[oi] = S.spsr;

    if (oi == 1 && ni != 1) {
        for (int i = 0; i < 5; i++) {
            S.fiq_r8_12[i] = S.r[8 + i];
            S.r[8 + i] = S.usr_r8_12[i];
        }
    } else if (oi != 1 && ni == 1) {
        for (int i = 0; i < 5; i++) {
            S.usr_r8_12[i] = S.r[8 + i];
            S.r[8 + i] = S.fiq_r8_12[i];
        }
    }

    S.r[13] = S.bank_r13[ni];
    S.r[14] = S.bank_r14[ni];
    S.spsr  = (ni > 0) ? S.bank_spsr[ni] : S.cpsr;
    S.cpsr  = (S.cpsr & ~CPSR_MODE_MASK) | new_mode;
}

static void set_cpsr(u32 val)
{
    /* Force valid bit 4 in mode if privileged bits written */
    u32 new_mode = val & CPSR_MODE_MASK;
    cpu_switch_mode(new_mode);
    S.cpsr = (val & 0xF00000FFu) | new_mode;
}

INLINE void update_irq_line(void)
{
    u16 ie  = io16(0x200);
    u16 irf = io16(0x202);
    u16 ime = io16(0x208);
    if (ie & irf)
        S.halted = 0;
    S.irq_line = ((ime & 1u) && (ie & irf)) ? 1 : 0;
}

static void raise_irq(u16 mask)
{
    u16 irf = (u16)(io16(0x202) | mask);
    set_io16(0x202, irf);
    update_irq_line();
}

/* ---- Save memory (SRAM / Flash 64K / Flash 128K / EEPROM) ---- */
static u8 sram_read8(u32 addr)
{
    u32 off = addr & 0xFFFFu;
    if (S.save_type == SAVE_FLASH64 || S.save_type == SAVE_FLASH128) {
        if (S.flash_id_mode && off < 2u) {
            if (S.save_type == SAVE_FLASH128)
                return off == 0 ? 0x62u : 0x13u; /* Sanyo 128 KB */
            return off == 0 ? 0x32u : 0x1Bu;     /* Panasonic 64 KB */
        }
        u32 bank = (S.save_type == SAVE_FLASH128) ? ((u32)S.flash_bank << 16) : 0u;
        return M->sram[bank | off];
    }
    if (S.save_type == SAVE_SRAM)
        return M->sram[off];
    return 0xFFu;
}

static void sram_write8(u32 addr, u8 val)
{
    u32 off = addr & 0xFFFFu;

    /* Tagless homebrew promotion: if a ROM had no SDK tag string, detect Flash unlock
       or plain SRAM writes dynamically while keeping uninitialized reads at 0xFF. */
    if (S.save_type == SAVE_NONE) {
        if (off == 0x5555u && val == 0xAAu) {
            S.save_type = SAVE_FLASH64;
            S.save_size = 0x10000u;
        } else {
            S.save_type = SAVE_SRAM;
            S.save_size = 0x8000u;
        }
    }

    if (S.save_type == SAVE_SRAM) {
        if (M->sram[off] != val) {
            M->sram[off] = val;
            S.save_dirty = 1;
        }
        return;
    }

    if (S.save_type == SAVE_FLASH64 || S.save_type == SAVE_FLASH128) {
        u32 bank = (S.save_type == SAVE_FLASH128) ? ((u32)S.flash_bank << 16) : 0u;
        switch (S.flash_state) {
        case FL_READY:
            if (off == 0x5555u && val == 0xAAu)
                S.flash_state = FL_CMD1;
            else if (val == 0xF0u)
                S.flash_id_mode = 0;
            break;
        case FL_CMD1:
            if (off == 0x2AAAu && val == 0x55u)
                S.flash_state = FL_CMD2;
            else
                S.flash_state = FL_READY;
            break;
        case FL_CMD2:
            if (off == 0x5555u) {
                switch (val) {
                case 0x90u: S.flash_id_mode = 1; S.flash_state = FL_READY; break;
                case 0xF0u: S.flash_id_mode = 0; S.flash_state = FL_READY; break;
                case 0x80u: S.flash_state = FL_ERASE_PREP; break;
                case 0xA0u: S.flash_state = FL_WRITE_BYTE; break;
                case 0xB0u:
                    S.flash_state = (S.save_type == SAVE_FLASH128) ? FL_BANK_SEL : FL_READY;
                    break;
                case 0x10u:
                    /* Chip erase (after 0x80 -> AA -> 55 -> 10) */
                    mem_fill(M->sram, 0xFF, S.save_type == SAVE_FLASH128 ? 0x20000u : 0x10000u);
                    S.save_dirty = 1;
                    S.flash_state = FL_READY;
                    break;
                default:
                    S.flash_state = FL_READY;
                    break;
                }
            } else if (val == 0x30u) {
                /* 4 KB sector erase (after 0x80 -> AA -> 55 -> [sector] = 0x30) */
                mem_fill(M->sram + (bank | (off & 0xF000u)), 0xFF, 0x1000u);
                S.save_dirty = 1;
                S.flash_state = FL_READY;
            } else {
                S.flash_state = FL_READY;
            }
            break;
        case FL_ERASE_PREP:
            if (off == 0x5555u && val == 0xAAu)
                S.flash_state = FL_CMD1;
            else
                S.flash_state = FL_READY;
            break;
        case FL_WRITE_BYTE:
            M->sram[bank | off] &= val;
            S.save_dirty = 1;
            S.flash_state = FL_READY;
            break;
        case FL_BANK_SEL:
            if (off == 0x0000u)
                S.flash_bank = val & 1u;
            S.flash_state = FL_READY;
            break;
        }
    }
}

/* EEPROM serial bit interface (mapped in 0x0Dxxxxxx for DMA3) */
static u16 eeprom_read_bit(void)
{
    if (S.eep_read_bit < 4u) {
        S.eep_read_bit++;
        return 1u;
    }
    if (S.eep_read_bit < 68u) {
        u32 bit_pos = 67u - S.eep_read_bit;      /* MSB first across 64-bit block */
        S.eep_read_bit++;
        u32 byte_off = ((u32)S.eep_read_addr << 3) + (7u - (bit_pos >> 3));
        if (byte_off < 0x2000u)
            return (M->sram[byte_off] >> (bit_pos & 7u)) & 1u;
        return 1u;
    }
    return 1u;                                   /* Ready */
}

static void eeprom_write_bit(u16 val, u32 dma_total_len)
{
    if (S.eep_idx < 80u)
        S.eep_buf[S.eep_idx++] = val & 1u;

    if (S.eep_addr_bits == 0) {
        if (dma_total_len == 9u || dma_total_len == 73u) {
            S.eep_addr_bits = 6u;
            S.save_size = 0x200u;
        } else if (dma_total_len == 17u || dma_total_len == 81u) {
            S.eep_addr_bits = 14u;
            S.save_size = 0x2000u;
        }
    }
    u8 abits = S.eep_addr_bits ? S.eep_addr_bits : 6u;
    if (S.eep_idx < 2u)
        return;
    if (S.eep_buf[0] != 1u) {
        S.eep_idx = 0;
        return;
    }
    if (S.eep_buf[1] == 1u) {
        /* Read request: 1, 1, addr[abits], 0 */
        if (S.eep_idx >= (u8)(2u + abits + 1u)) {
            u16 addr = 0;
            for (u8 i = 0; i < abits; i++)
                addr = (u16)((addr << 1) | S.eep_buf[2u + i]);
            S.eep_read_addr = (abits == 6u) ? (addr & 0x3Fu) : (addr & 0x3FFFu);
            S.eep_read_bit = 0;
            S.eep_idx = 0;
        }
    } else {
        /* Write request: 1, 0, addr[abits], data[64], 0 */
        if (S.eep_idx >= (u8)(2u + abits + 64u + 1u)) {
            u16 addr = 0;
            for (u8 i = 0; i < abits; i++)
                addr = (u16)((addr << 1) | S.eep_buf[2u + i]);
            addr = (abits == 6u) ? (addr & 0x3Fu) : (addr & 0x3FFFu);
            u32 base = (u32)addr << 3;
            for (u32 b = 0; b < 8u; b++) {
                u8 byte = 0;
                for (u32 bit = 0; bit < 8u; bit++)
                    byte = (u8)((byte << 1) | S.eep_buf[2u + abits + b * 8u + bit]);
                if (base + b < 0x2000u)
                    M->sram[base + b] = byte;
            }
            S.save_dirty = 1;
            S.eep_idx = 0;
        }
    }
}

/* ---- Audio subsystem (DirectSound FIFO A/B + 4 PSG channels) ---- */
static const u8 psg_duty_tab[4] = { 0x01u, 0x03u, 0x0Fu, 0xFCu };

static void fifo_reset(int idx)
{
    S.fifo[idx].rd = 0;
    S.fifo[idx].wr = 0;
    S.fifo[idx].count = 0;
    S.fifo[idx].sample = 0;
}

static void fifo_push32(int idx, u32 word)
{
    struct gba_fifo *f = &S.fifo[idx];
    for (int i = 0; i < 4; i++) {
        if (f->count < 32u) {
            f->buf[f->wr] = (s8)(word & 0xFFu);
            f->wr = (u8)((f->wr + 1u) & 31u);
            f->count++;
        }
        word >>= 8;
    }
}

static void run_dma_fifo(int fifo_idx);

static void fifo_timer_overflow(int timer_idx)
{
    u16 sc_h = io16(0x082);
    for (int f = 0; f < 2; f++) {
        int sel = (sc_h >> (f ? 14 : 10)) & 1;
        if (sel != timer_idx)
            continue;
        struct gba_fifo *ff = &S.fifo[f];
        if (ff->count > 0) {
            ff->sample = ff->buf[ff->rd];
            ff->rd = (u8)((ff->rd + 1u) & 31u);
            ff->count--;
        }
        if (ff->count <= 16u)
            run_dma_fifo(f);
    }
}

static void psg_step_cycles(u32 cyc)
{
    if (!(io16(0x084) & 0x80u))
        return;

    /* 512 Hz frame sequencer (every 32,768 cycles at 16.777216 MHz) */
    S.psg_frame_acc += cyc;
    while (S.psg_frame_acc >= 32768u) {
        S.psg_frame_acc -= 32768u;
        u8 step = S.psg_frame_step;
        S.psg_frame_step = (u8)((step + 1u) & 7u);
        if ((step & 1u) == 0) {
            if (S.psg1.len_en && S.psg1.len_cnt > 0 && --S.psg1.len_cnt == 0) S.psg1.enabled = 0;
            if (S.psg2.len_en && S.psg2.len_cnt > 0 && --S.psg2.len_cnt == 0) S.psg2.enabled = 0;
            if (S.psg3.len_en && S.psg3.len_cnt > 0 && --S.psg3.len_cnt == 0) S.psg3.enabled = 0;
            if (S.psg4.len_en && S.psg4.len_cnt > 0 && --S.psg4.len_cnt == 0) S.psg4.enabled = 0;
        }
        if (step == 2u || step == 6u) {
            if (S.psg1.sweep_en && S.psg1.sweep_period > 0) {
                if (S.psg1.sweep_timer > 0 && --S.psg1.sweep_timer == 0) {
                    S.psg1.sweep_timer = S.psg1.sweep_period;
                    u16 df = (u16)(S.psg1.sweep_freq >> S.psg1.sweep_shift);
                    s32 nf = S.psg1.sweep_dir ? ((s32)S.psg1.sweep_freq - df) : ((s32)S.psg1.sweep_freq + df);
                    if (nf > 2047) {
                        S.psg1.enabled = 0;
                    } else if (S.psg1.sweep_shift > 0 && nf >= 0) {
                        S.psg1.sweep_freq = (u16)nf;
                        S.psg1.nr3 = (u16)((S.psg1.nr3 & ~0x7FFu) | (u16)nf);
                    }
                }
            }
        }
        if (step == 7u) {
            struct gba_psg_sq *sqs[2] = { &S.psg1, &S.psg2 };
            for (int i = 0; i < 2; i++) {
                struct gba_psg_sq *q = sqs[i];
                if (q->env_period > 0 && q->env_timer > 0 && --q->env_timer == 0) {
                    q->env_timer = q->env_period;
                    if (q->env_dir && q->vol < 15u) q->vol++;
                    else if (!q->env_dir && q->vol > 0u) q->vol--;
                }
            }
            if (S.psg4.env_period > 0 && S.psg4.env_timer > 0 && --S.psg4.env_timer == 0) {
                S.psg4.env_timer = S.psg4.env_period;
                if (S.psg4.env_dir && S.psg4.vol < 15u) S.psg4.vol++;
                else if (!S.psg4.env_dir && S.psg4.vol > 0u) S.psg4.vol--;
            }
        }
    }

    /* Tone & wave phase advance (GBA clock = 4 * GB 4.194304 MHz clock:
       Square period = (2048 - freq) * 16 GBA cycles per 1/8th wave step;
       Wave period   = (2048 - freq) * 8  GBA cycles per sample) */
    if (S.psg1.enabled) {
        u32 per = (2048u - (S.psg1.nr3 & 0x7FFu)) << 4;
        if (per < 16u) per = 16u;
        S.psg1.timer += cyc;
        while (S.psg1.timer >= per) {
            S.psg1.timer -= per;
            S.psg1.phase = (S.psg1.phase + 1u) & 7u;
        }
    }
    if (S.psg2.enabled) {
        u32 per = (2048u - (S.psg2.nr3 & 0x7FFu)) << 4;
        if (per < 16u) per = 16u;
        S.psg2.timer += cyc;
        while (S.psg2.timer >= per) {
            S.psg2.timer -= per;
            S.psg2.phase = (S.psg2.phase + 1u) & 7u;
        }
    }
    if (S.psg3.enabled && (S.psg3.nr0 & 0x80u)) {
        u32 per = (2048u - (S.psg3.nr3 & 0x7FFu)) << 3;
        if (per < 8u) per = 8u;
        S.psg3.timer += cyc;
        u32 mask = (S.psg3.nr0 & 0x20u) ? 63u : 31u;
        while (S.psg3.timer >= per) {
            S.psg3.timer -= per;
            S.psg3.pos = (S.psg3.pos + 1u) & mask;
        }
    }
    if (S.psg4.enabled) {
        static const u8 div_tab[8] = { 8, 16, 32, 48, 64, 80, 96, 112 };
        u32 sh = (S.psg4.nr3 >> 4) & 0xFu;
        u32 per = ((u32)div_tab[S.psg4.nr3 & 7u] << 2) << (sh > 13u ? 13u : sh);
        if (per < 32u) per = 32u;
        S.psg4.timer += cyc;
        while (S.psg4.timer >= per) {
            S.psg4.timer -= per;
            u16 xr = (u16)((S.psg4.lfsr ^ (S.psg4.lfsr >> 1)) & 1u);
            S.psg4.lfsr = (u16)((S.psg4.lfsr >> 1) | (xr << 14));
            if (S.psg4.nr3 & 8u)
                S.psg4.lfsr = (u16)((S.psg4.lfsr & ~0x40u) | (xr << 6));
        }
    }
}

static void audio_sample_line(void)
{
    psg_step_cycles(LINE_CYC);
    if (!S.snd_rate)
        return;

    S.snd_phase += S.snd_rate * LINE_CYC;
    if (S.snd_phase < GBA_CLOCK_HZ)
        return;

    /* Compute current stereo mix in [-32768, 32767] */
    s32 l = 0, r = 0;
    if (io16(0x084) & 0x80u) {
        u16 sc_l = io16(0x080);
        u16 sc_h = io16(0x082);

        /* DirectSound FIFO A & B (signed 8-bit -> 10-bit DAC) */
        s32 dsa = (s32)S.fifo[0].sample << ((sc_h & 0x0004u) ? 2 : 1);
        s32 dsb = (s32)S.fifo[1].sample << ((sc_h & 0x0008u) ? 2 : 1);
        if (sc_h & 0x0100u) r += dsa;
        if (sc_h & 0x0200u) l += dsa;
        if (sc_h & 0x1000u) r += dsb;
        if (sc_h & 0x2000u) l += dsb;

        /* 4 PSG channels */
        s32 c[4] = { 0, 0, 0, 0 };
        if (S.psg1.enabled && S.psg1.vol) {
            int hi = (psg_duty_tab[S.psg1.duty] >> S.psg1.phase) & 1;
            c[0] = hi ? (s32)S.psg1.vol : -(s32)S.psg1.vol;
        }
        if (S.psg2.enabled && S.psg2.vol) {
            int hi = (psg_duty_tab[S.psg2.duty] >> S.psg2.phase) & 1;
            c[1] = hi ? (s32)S.psg2.vol : -(s32)S.psg2.vol;
        }
        if (S.psg3.enabled && (S.psg3.nr0 & 0x80u)) {
            u32 bank = (S.psg3.nr0 & 0x20u) ? (S.psg3.pos >> 5) : ((S.psg3.nr0 >> 6) & 1u);
            u32 idx = (bank << 4) | ((S.psg3.pos & 31u) >> 1);
            u8 nib = (S.psg3.pos & 1u) ? (S.psg3.ram[idx] & 0xFu) : (S.psg3.ram[idx] >> 4);
            s32 w = (s32)nib - 8;
            u32 vcode = (S.psg3.nr2 >> 13) & 7u;
            if (S.psg3.nr2 & 0x8000u) w = (w * 3) >> 2; /* 75% mode */
            else if (vcode == 0)      w = 0;
            else if (vcode == 2)      w >>= 1;
            else if (vcode == 3)      w >>= 2;
            c[2] = w * 2;
        }
        if (S.psg4.enabled && S.psg4.vol)
            c[3] = (S.psg4.lfsr & 1u) ? -(s32)S.psg4.vol : (s32)S.psg4.vol;

        s32 pl = 0, pr = 0;
        for (int i = 0; i < 4; i++) {
            if (sc_l & (0x0100u << i)) pr += c[i];
            if (sc_l & (0x1000u << i)) pl += c[i];
        }
        pl *= (s32)((sc_l >> 4) & 7u) + 1;
        pr *= (s32)(sc_l & 7u) + 1;
        u32 ratio = sc_h & 3u;
        if (ratio == 0)      { pl >>= 2; pr >>= 2; }
        else if (ratio == 1) { pl >>= 1; pr >>= 1; }

        l += pl >> 1;
        r += pr >> 1;
    }

    /* Downmix L+R and scale 10-bit GBA DAC [-512, +511] to 48 kHz mono 16-bit PCM */
    s32 mono = ((l + r) * 24);
    if (mono >  32767) mono =  32767;
    if (mono < -32768) mono = -32768;

    while (S.snd_phase >= GBA_CLOCK_HZ) {
        S.snd_phase -= GBA_CLOCK_HZ;
        if (S.snd_wr - S.snd_rd < SND_RING) {
            M->snd_ring[S.snd_wr & (SND_RING - 1u)] = (s16)mono;
            S.snd_wr++;
        }
    }
}

/* ---- Timers 0..3 ---- */
static void timer_overflow(int i)
{
    struct gba_timer *t = &S.tmr[i];
    t->counter = t->reload;
    if (t->cnt & 0x0040u)
        raise_irq((u16)(IRQ_TIMER0 << i));
    if (i < 2)
        fifo_timer_overflow(i);
    if (i < 3 && (S.tmr[i + 1].cnt & 0x0084u) == 0x0084u) {
        if (++S.tmr[i + 1].counter == 0)
            timer_overflow(i + 1);
    }
}

static void timers_step(u32 cyc)
{
    static const u8 shifts[4] = { 0, 6, 8, 10 };
    u8 mask = S.active_timers;
    if (!mask)
        return;
    for (int i = 0; i < 4; i++) {
        if (!(mask & (1u << i)))
            continue;
        struct gba_timer *t = &S.tmr[i];
        u8 sh = shifts[t->cnt & 3u];
        t->prescale_acc += cyc;
        u32 ticks = t->prescale_acc >> sh;
        if (!ticks)
            continue;
        t->prescale_acc &= (1u << sh) - 1u;
        u32 rem = 0x10000u - (u32)t->counter;
        while (ticks >= rem) {
            ticks -= rem;
            timer_overflow(i);
            rem = 0x10000u - (u32)t->counter;
        }
        t->counter = (u16)(t->counter + ticks);
    }
}

/* Minimum cycles until the next active timer overflow (for accurate Halt fast-forward) */
static s32 timers_next_event(s32 max_cyc)
{
    static const u8 shifts[4] = { 0, 6, 8, 10 };
    u8 mask = S.active_timers;
    if (!mask)
        return max_cyc;
    s32 best = max_cyc;
    for (int i = 0; i < 4; i++) {
        if (!(mask & (1u << i)))
            continue;
        struct gba_timer *t = &S.tmr[i];
        u8 sh = shifts[t->cnt & 3u];
        u32 rem = 0x10000u - (u32)t->counter;
        u64 need = ((u64)rem << sh) - t->prescale_acc;
        if (need < 1u)
            need = 1u;
        if (need < (u64)best)
            best = (s32)need;
    }
    return best;
}

static void timers_flush(void)
{
    if (S.tmr_pend) {
        u32 p = S.tmr_pend;
        S.tmr_pend = 0;
        timers_step(p);
    }
    S.tmr_next_cyc = S.active_timers ? (S.cyc_left - timers_next_event(1000000)) : -1000000;
}

/* ---- MMIO reads & writes (0x04000000..0x040003FF) ---- */
static void run_dma_timing(int timing);

static u16 io_read16(u32 off)
{
    off &= 0x3FEu;
    switch (off) {
    case 0x004: { /* DISPSTAT */
        u16 st = (u16)(io16(0x004) & 0xFFF8u);
        if (S.vcount >= 160u && S.vcount < 227u)
            st |= 0x0001u;
        if (S.cyc_left <= HBLANK_CYC)
            st |= 0x0002u;
        if (S.vcount == ((st >> 8) & 0xFFu))
            st |= 0x0004u;
        return st;
    }
    case 0x006: /* VCOUNT */
        return S.vcount;
    case 0x010: case 0x012: case 0x014: case 0x016:
    case 0x018: case 0x01A: case 0x01C: case 0x01E:
    case 0x020: case 0x022: case 0x024: case 0x026:
    case 0x028: case 0x02A: case 0x02C: case 0x02E:
    case 0x030: case 0x032: case 0x034: case 0x036:
    case 0x038: case 0x03A: case 0x03C: case 0x03E:
    case 0x040: case 0x042: case 0x044: case 0x046:
    case 0x04C: case 0x054:
    case 0x0A0: case 0x0A2: case 0x0A4: case 0x0A6:
    case 0x0B0: case 0x0B2: case 0x0B4: case 0x0B6: case 0x0B8:
    case 0x0BC: case 0x0BE: case 0x0C0: case 0x0C2: case 0x0C4:
    case 0x0C8: case 0x0CA: case 0x0CC: case 0x0CE: case 0x0D0:
    case 0x0D4: case 0x0D6: case 0x0D8: case 0x0DA: case 0x0DC:
        /* Write-only PPU / FIFO / DMA registers return open-bus */
        return (u16)S.last_fetch;
    case 0x084: { /* SOUNDCNT_X */
        u16 v = (u16)(io16(0x084) & 0x0080u);
        if (v) {
            if (S.psg1.enabled) v |= 1u;
            if (S.psg2.enabled) v |= 2u;
            if (S.psg3.enabled && (S.psg3.nr0 & 0x80u)) v |= 4u;
            if (S.psg4.enabled) v |= 8u;
        }
        return v;
    }
    case 0x090: case 0x092: case 0x094: case 0x096:
    case 0x098: case 0x09A: case 0x09C: case 0x09E: {
        /* Wave RAM reads the bank NOT currently selected by SOUNDCNT_L bit 6 */
        u32 bank = (((S.psg3.nr0 >> 6) & 1u) ^ 1u) << 4;
        return rd16le(S.psg3.ram + bank + (off - 0x090u));
    }
    case 0x0BA: return (u16)(S.dma[0].cnt_h & 0xF7E0u);
    case 0x0C6: return (u16)(S.dma[1].cnt_h & 0xF7E0u);
    case 0x0D2: return (u16)(S.dma[2].cnt_h & 0xF7E0u);
    case 0x0DE: return (u16)(S.dma[3].cnt_h & 0xFFE0u);
    case 0x100: if (S.tmr_pend) timers_flush(); return S.tmr[0].counter;
    case 0x102: return S.tmr[0].cnt;
    case 0x104: if (S.tmr_pend) timers_flush(); return S.tmr[1].counter;
    case 0x106: return S.tmr[1].cnt;
    case 0x108: if (S.tmr_pend) timers_flush(); return S.tmr[2].counter;
    case 0x10A: return S.tmr[2].cnt;
    case 0x10C: if (S.tmr_pend) timers_flush(); return S.tmr[3].counter;
    case 0x10E: return S.tmr[3].cnt;
    case 0x130: return S.keyinput;
    default:
        if (off < 0x302u)
            return io16(off);
        return (u16)S.last_fetch;
    }
}

static void latch_bg_ref(int idx)
{
    u32 base = idx ? 0x038u : 0x028u;
    u32 rx = (u32)io16(base + 0) | ((u32)(io16(base + 2) & 0x0FFFu) << 16);
    u32 ry = (u32)io16(base + 4) | ((u32)(io16(base + 6) & 0x0FFFu) << 16);
    if (rx & 0x08000000u) rx |= 0xF0000000u;
    if (ry & 0x08000000u) ry |= 0xF0000000u;
    S.bgx[idx] = (s32)rx;
    S.bgy[idx] = (s32)ry;
}

static void io_write16(u32 off, u16 val, u16 byte_mask)
{
    off &= 0x3FEu;
    u16 cur = io16(off);
    u16 nv = (u16)((cur & ~byte_mask) | (val & byte_mask));

    switch (off) {
    case 0x004: /* DISPSTAT (bits 0..2 read-only) */
        set_io16(0x004, (u16)((cur & 0x0007u) | (nv & 0xFFF8u)));
        return;
    case 0x006: /* VCOUNT read-only */
        return;
    case 0x028: case 0x02A: case 0x02C: case 0x02E:
        set_io16(off, nv);
        latch_bg_ref(0);
        return;
    case 0x038: case 0x03A: case 0x03C: case 0x03E:
        set_io16(off, nv);
        latch_bg_ref(1);
        return;

    /* PSG Channel 1 */
    case 0x060:
        set_io16(off, nv);
        S.psg1.nr0 = nv;
        S.psg1.sweep_period = (u8)((nv >> 4) & 7u);
        S.psg1.sweep_dir    = (u8)((nv >> 3) & 1u);
        S.psg1.sweep_shift  = (u8)(nv & 7u);
        return;
    case 0x062:
        set_io16(off, nv);
        S.psg1.nr1 = (u16)(nv & 0xFFu);
        S.psg1.duty = (u8)((nv >> 6) & 3u);
        if (byte_mask & 0x00FFu)
            S.psg1.len_cnt = (u8)(64u - (nv & 63u));
        if (byte_mask & 0xFF00u) {
            S.psg1.nr2 = (u16)(nv >> 8);
            S.psg1.env_period = (u8)((nv >> 8) & 7u);
            S.psg1.env_dir    = (u8)((nv >> 11) & 1u);
            S.psg1.vol        = (u8)((nv >> 12) & 0xFu);
            if ((nv & 0xF800u) == 0)
                S.psg1.enabled = 0;
        }
        return;
    case 0x064:
        set_io16(off, nv);
        S.psg1.nr3 = nv;
        S.psg1.len_en = (u8)((nv >> 14) & 1u);
        if ((byte_mask & 0xFF00u) && (nv & 0x8000u)) {
            S.psg1.enabled = (S.psg1.nr2 & 0xF8u) ? 1 : 0;
            if (S.psg1.len_cnt == 0) S.psg1.len_cnt = 64u;
            S.psg1.vol = (u8)((S.psg1.nr2 >> 4) & 0xFu);
            S.psg1.env_timer = S.psg1.env_period;
            S.psg1.sweep_freq = nv & 0x7FFu;
            S.psg1.sweep_timer = S.psg1.sweep_period ? S.psg1.sweep_period : 8u;
            S.psg1.sweep_en = (S.psg1.sweep_period || S.psg1.sweep_shift) ? 1 : 0;
        }
        return;

    /* PSG Channel 2 */
    case 0x068:
        set_io16(off, nv);
        S.psg2.nr1 = (u16)(nv & 0xFFu);
        S.psg2.duty = (u8)((nv >> 6) & 3u);
        if (byte_mask & 0x00FFu)
            S.psg2.len_cnt = (u8)(64u - (nv & 63u));
        if (byte_mask & 0xFF00u) {
            S.psg2.nr2 = (u16)(nv >> 8);
            S.psg2.env_period = (u8)((nv >> 8) & 7u);
            S.psg2.env_dir    = (u8)((nv >> 11) & 1u);
            S.psg2.vol        = (u8)((nv >> 12) & 0xFu);
            if ((nv & 0xF800u) == 0)
                S.psg2.enabled = 0;
        }
        return;
    case 0x06C:
        set_io16(off, nv);
        S.psg2.nr3 = nv;
        S.psg2.len_en = (u8)((nv >> 14) & 1u);
        if ((byte_mask & 0xFF00u) && (nv & 0x8000u)) {
            S.psg2.enabled = (S.psg2.nr2 & 0xF8u) ? 1 : 0;
            if (S.psg2.len_cnt == 0) S.psg2.len_cnt = 64u;
            S.psg2.vol = (u8)((S.psg2.nr2 >> 4) & 0xFu);
            S.psg2.env_timer = S.psg2.env_period;
        }
        return;

    /* PSG Channel 3 (Wave) */
    case 0x070:
        set_io16(off, nv);
        S.psg3.nr0 = nv & 0xE0u;
        if (!(nv & 0x80u))
            S.psg3.enabled = 0;
        return;
    case 0x072:
        set_io16(off, nv);
        if (byte_mask & 0x00FFu)
            S.psg3.len_cnt = (u16)(256u - (nv & 0xFFu));
        S.psg3.nr2 = nv;
        return;
    case 0x074:
        set_io16(off, nv);
        S.psg3.nr3 = nv;
        S.psg3.len_en = (u8)((nv >> 14) & 1u);
        if ((byte_mask & 0xFF00u) && (nv & 0x8000u)) {
            S.psg3.enabled = (S.psg3.nr0 & 0x80u) ? 1 : 0;
            if (S.psg3.len_cnt == 0) S.psg3.len_cnt = 256u;
            S.psg3.pos = 0;
        }
        return;

    /* PSG Channel 4 (Noise) */
    case 0x078:
        set_io16(off, nv);
        if (byte_mask & 0x00FFu)
            S.psg4.len_cnt = (u8)(64u - (nv & 63u));
        if (byte_mask & 0xFF00u) {
            S.psg4.nr2 = (u16)(nv >> 8);
            S.psg4.env_period = (u8)((nv >> 8) & 7u);
            S.psg4.env_dir    = (u8)((nv >> 11) & 1u);
            S.psg4.vol        = (u8)((nv >> 12) & 0xFu);
            if ((nv & 0xF800u) == 0)
                S.psg4.enabled = 0;
        }
        return;
    case 0x07C:
        set_io16(off, nv);
        S.psg4.nr3 = nv;
        S.psg4.len_en = (u8)((nv >> 14) & 1u);
        if ((byte_mask & 0xFF00u) && (nv & 0x8000u)) {
            S.psg4.enabled = (S.psg4.nr2 & 0xF8u) ? 1 : 0;
            if (S.psg4.len_cnt == 0) S.psg4.len_cnt = 64u;
            S.psg4.vol = (u8)((S.psg4.nr2 >> 4) & 0xFu);
            S.psg4.env_timer = S.psg4.env_period;
            S.psg4.lfsr = 0x7FFFu;
        }
        return;

    case 0x082: /* SOUNDCNT_H */
        if ((byte_mask & 0xFF00u) && (val & 0x0800u))
            fifo_reset(0);
        if ((byte_mask & 0xFF00u) && (val & 0x8000u))
            fifo_reset(1);
        set_io16(0x082, (u16)(nv & 0x770Fu));
        return;
    case 0x084: /* SOUNDCNT_X */
        if (byte_mask & 0x00FFu) {
            set_io16(0x084, (u16)(val & 0x0080u));
            if (!(val & 0x0080u)) {
                S.psg1.enabled = S.psg2.enabled = S.psg3.enabled = S.psg4.enabled = 0;
            }
        }
        return;
    case 0x090: case 0x092: case 0x094: case 0x096:
    case 0x098: case 0x09A: case 0x09C: case 0x09E: {
        u32 bank = (((S.psg3.nr0 >> 6) & 1u) ^ 1u) << 4;
        u16 wcur = rd16le(S.psg3.ram + bank + (off - 0x090u));
        wr16le(S.psg3.ram + bank + (off - 0x090u), (u16)((wcur & ~byte_mask) | (val & byte_mask)));
        return;
    }

    /* DirectSound FIFO A & B (16-bit halfword writes also work; 32-bit writes use fast path) */
    case 0x0A0: case 0x0A2:
        set_io16(off, nv);
        if (off == 0x0A2u)
            fifo_push32(0, (u32)io16(0x0A0) | ((u32)nv << 16));
        return;
    case 0x0A4: case 0x0A6:
        set_io16(off, nv);
        if (off == 0x0A6u)
            fifo_push32(1, (u32)io16(0x0A4) | ((u32)nv << 16));
        return;

    /* DMA 0..3 */
    case 0x0B0: case 0x0B2: case 0x0B4: case 0x0B6: case 0x0B8:
    case 0x0BC: case 0x0BE: case 0x0C0: case 0x0C2: case 0x0C4:
    case 0x0C8: case 0x0CA: case 0x0CC: case 0x0CE: case 0x0D0:
    case 0x0D4: case 0x0D6: case 0x0D8: case 0x0DA: case 0x0DC: {
        set_io16(off, nv);
        int ch = (int)((off - 0x0B0u) / 12u);
        u32 b = 0x0B0u + (u32)ch * 12u;
        S.dma[ch].sad = ((u32)io16(b + 0) | ((u32)io16(b + 2) << 16)) & (ch == 0 ? 0x07FFFFFFu : 0x0FFFFFFFu);
        S.dma[ch].dad = ((u32)io16(b + 4) | ((u32)io16(b + 6) << 16)) & (ch < 3  ? 0x07FFFFFFu : 0x0FFFFFFFu);
        S.dma[ch].cnt_l = io16(b + 8);
        return;
    }
    case 0x0BA: case 0x0C6: case 0x0D2: case 0x0DE: {
        int ch = (int)((off - 0x0BAu) / 12u);
        u16 old_h = S.dma[ch].cnt_h;
        u16 new_h = (u16)((old_h & ~byte_mask) | (val & byte_mask));
        S.dma[ch].cnt_h = new_h;
        set_io16(off, new_h);
        if (!(old_h & 0x8000u) && (new_h & 0x8000u)) {
            S.dma[ch].int_sad = S.dma[ch].sad;
            S.dma[ch].int_dad = S.dma[ch].dad;
            u32 max_c = (ch == 3) ? 0x10000u : 0x4000u;
            u32 c = S.dma[ch].cnt_l & (max_c - 1u);
            S.dma[ch].int_cnt = c ? c : max_c;
            if (((new_h >> 12) & 3u) == 0u)
                run_dma_timing(0);
        }
        return;
    }

    /* Timers 0..3 */
    case 0x100: case 0x104: case 0x108: case 0x10C: {
        if (S.tmr_pend) timers_flush();
        int ch = (int)((off - 0x100u) >> 2);
        S.tmr[ch].reload = (u16)((S.tmr[ch].reload & ~byte_mask) | (val & byte_mask));
        return;
    }
    case 0x102: case 0x106: case 0x10A: case 0x10E: {
        if (S.tmr_pend) timers_flush();
        int ch = (int)((off - 0x102u) >> 2);
        u16 old_c = S.tmr[ch].cnt;
        u16 new_c = (u16)(((old_c & ~byte_mask) | (val & byte_mask)) & 0x00C7u);
        S.tmr[ch].cnt = new_c;
        set_io16(off, new_c);
        if (!(old_c & 0x0080u) && (new_c & 0x0080u)) {
            S.tmr[ch].counter = S.tmr[ch].reload;
            S.tmr[ch].prescale_acc = 0;
        }
        u8 m = 0;
        for (int i = 0; i < 4; i++) {
            if ((S.tmr[i].cnt & 0x0080u) && (i == 0 || !(S.tmr[i].cnt & 0x0004u)))
                m |= (u8)(1u << i);
        }
        S.active_timers = m;
        timers_flush();
        return;
    }

    case 0x130: /* KEYINPUT read-only */
        return;
    case 0x200: /* IE */
        set_io16(0x200, nv);
        update_irq_line();
        return;
    case 0x202: /* IF: write 1 to clear */
        set_io16(0x202, (u16)(cur & ~(val & byte_mask)));
        update_irq_line();
        return;
    case 0x204: /* WAITCNT */
        set_io16(0x204, nv);
        update_waitstates(nv);
        return;
    case 0x208: /* IME */
        set_io16(0x208, (u16)(nv & 1u));
        update_irq_line();
        return;
    case 0x300: /* POSTFLG (0x300) & HALTCNT (0x301) */
        if (byte_mask & 0x00FFu)
            M->io[0x300] = (u8)(val & 1u);
        if ((byte_mask & 0xFF00u) && !(io16(0x200) & io16(0x202)))
            S.halted = 1;
        return;
    default:
        set_io16(off, nv);
        return;
    }
}

/* ---- Bus reads & writes (8 / 16 / 32 bit) ---- */
static u32 open_bus_read(u32 addr)
{
    /* When PC is in BIOS (< 0x4000), last_fetch holds BIOS instruction; otherwise
       CPU prefetch from ROM/IWRAM/EWRAM is kept in S.last_fetch */
    (void)addr;
    return S.last_fetch;
}

static u32 bus_read32_slow(u32 addr)
{
    addr &= ~3u;
    switch (addr >> 24) {
    case 0x00:
        if (addr < 0x4000u) {
            if (S.r[15] < 0x4000u)
                return rd32le(M->bios + addr);
            return S.bios_latch;
        }
        return open_bus_read(addr);
    case 0x04:
        return (u32)io_read16(addr & 0x3FCu) | ((u32)io_read16((addr & 0x3FCu) + 2u) << 16);
    case 0x05: {
        u32 idx = (addr & 0x3FCu) >> 1;
        return (u32)M->pal[idx] | ((u32)M->pal[idx + 1u] << 16);
    }
    case 0x06: {
        u32 off = addr & 0x1FFFCu;
        if (off >= 0x18000u) off -= 0x8000u;
        return rd32le(M->vram + off);
    }
    case 0x07: {
        u32 idx = (addr & 0x3FCu) >> 1;
        return (u32)M->oam[idx] | ((u32)M->oam[idx + 1u] << 16);
    }
    case 0x08: case 0x09: case 0x0A: case 0x0B: case 0x0C: {
        u32 off = addr & 0x01FFFFFCu;
        if (off + 4u <= S.rom_size)
            return rd32le(S.rom + off);
        u16 lo = (off < S.rom_size) ? rd16le(S.rom + off) : (u16)(off >> 1);
        u16 hi = (off + 2u < S.rom_size) ? rd16le(S.rom + off + 2u) : (u16)((off + 2u) >> 1);
        return (u32)lo | ((u32)hi << 16);
    }
    case 0x0D: {
        if (S.save_type == SAVE_EEPROM && (S.rom_size <= 0x01000000u || addr >= 0x0DFFFF00u)) {
            u16 b = eeprom_read_bit();
            return (u32)b | ((u32)b << 16);
        }
        u32 off = addr & 0x01FFFFFCu;
        if (off + 4u <= S.rom_size)
            return rd32le(S.rom + off);
        return ((off >> 1) & 0xFFFFu) | ((((off + 2u) >> 1) & 0xFFFFu) << 16);
    }
    case 0x0E: case 0x0F:
        return (u32)sram_read8(addr) * 0x01010101u;
    default:
        return open_bus_read(addr);
    }
}

INLINE u32 bus_read32_aligned(u32 addr)
{
    u32 top = addr >> 24;
    if (top == 0x03u)
        return rd32le(M->iwram + (addr & 0x7FFCu));
    if (top == 0x02u)
        return rd32le(M->ewram + (addr & 0x3FFFCu));
    if (top == 0x08u) {
        u32 off = addr & 0x00FFFFFCu;
        if (off + 4u <= S.rom_size)
            return rd32le(S.rom + off);
    }
    return bus_read32_slow(addr);
}

static u16 bus_read16_slow(u32 addr)
{
    addr &= ~1u;
    switch (addr >> 24) {
    case 0x00:
        if (addr < 0x4000u) {
            u32 w = (S.r[15] < 0x4000u) ? rd32le(M->bios + (addr & ~3u)) : S.bios_latch;
            return (u16)(w >> ((addr & 2u) * 8u));
        }
        return (u16)(open_bus_read(addr) >> ((addr & 2u) * 8u));
    case 0x04:
        return io_read16(addr & 0x3FEu);
    case 0x05:
        return M->pal[(addr & 0x3FEu) >> 1];
    case 0x06: {
        u32 off = addr & 0x1FFFEu;
        if (off >= 0x18000u) off -= 0x8000u;
        return rd16le(M->vram + off);
    }
    case 0x07:
        return M->oam[(addr & 0x3FEu) >> 1];
    case 0x08: case 0x09: case 0x0A: case 0x0B: case 0x0C: {
        u32 off = addr & 0x01FFFFFEu;
        if (off + 2u <= S.rom_size)
            return rd16le(S.rom + off);
        return (u16)(off >> 1);
    }
    case 0x0D: {
        if (S.save_type == SAVE_EEPROM && (S.rom_size <= 0x01000000u || addr >= 0x0DFFFF00u))
            return eeprom_read_bit();
        u32 off = addr & 0x01FFFFFEu;
        if (off + 2u <= S.rom_size)
            return rd16le(S.rom + off);
        return (u16)(off >> 1);
    }
    case 0x0E: case 0x0F:
        return (u16)((u16)sram_read8(addr) * 0x0101u);
    default:
        return (u16)(open_bus_read(addr) >> ((addr & 2u) * 8u));
    }
}

INLINE u16 bus_read16_aligned(u32 addr)
{
    u32 top = addr >> 24;
    if (top == 0x03u)
        return rd16le(M->iwram + (addr & 0x7FFEu));
    if (top == 0x02u)
        return rd16le(M->ewram + (addr & 0x3FFFEu));
    if (top == 0x08u) {
        u32 off = addr & 0x00FFFFFEu;
        if (off + 2u <= S.rom_size)
            return rd16le(S.rom + off);
    }
    return bus_read16_slow(addr);
}

INLINE u8 bus_read8(u32 addr)
{
    u32 top = addr >> 24;
    if (top == 0x03u)
        return M->iwram[addr & 0x7FFFu];
    if (top == 0x02u)
        return M->ewram[addr & 0x3FFFFu];
    if (top == 0x08u) {
        u32 off = addr & 0x00FFFFFFu;
        if (off < S.rom_size)
            return S.rom[off];
    }
    if (top >= 0x0Eu && top <= 0x0Fu)
        return sram_read8(addr);
    u16 h = bus_read16_slow(addr & ~1u);
    return (u8)(h >> ((addr & 1u) * 8u));
}

static void bus_write32_slow(u32 addr, u32 val)
{
    u32 raw_addr = addr;
    addr &= ~3u;
    switch (addr >> 24) {
    case 0x04: {
        u32 off = addr & 0x3FCu;
        if (off == 0x0A0u) { fifo_push32(0, val); return; }
        if (off == 0x0A4u) { fifo_push32(1, val); return; }
        io_write16(off, (u16)val, 0xFFFFu);
        io_write16(off + 2u, (u16)(val >> 16), 0xFFFFu);
        return;
    }
    case 0x05: {
        u32 idx = (addr & 0x3FCu) >> 1;
        M->pal[idx]      = (u16)val;
        M->pal[idx + 1u] = (u16)(val >> 16);
        return;
    }
    case 0x06: {
        u32 off = addr & 0x1FFFCu;
        if (off >= 0x18000u) off -= 0x8000u;
        wr32le(M->vram + off, val);
        return;
    }
    case 0x07: {
        u32 idx = (addr & 0x3FCu) >> 1;
        M->oam[idx]      = (u16)val;
        M->oam[idx + 1u] = (u16)(val >> 16);
        return;
    }
    case 0x0E: case 0x0F:
        sram_write8(raw_addr, (u8)(val >> ((raw_addr & 3u) * 8u)));
        return;
    default:
        return;
    }
}

INLINE void bus_write32_aligned(u32 addr, u32 val)
{
    u32 top = addr >> 24;
    if (top == 0x03u) { wr32le(M->iwram + (addr & 0x7FFCu), val); return; }
    if (top == 0x02u) { wr32le(M->ewram + (addr & 0x3FFFCu), val); return; }
    bus_write32_slow(addr, val);
}

static void bus_write16_slow(u32 addr, u16 val)
{
    u32 raw_addr = addr;
    addr &= ~1u;
    switch (addr >> 24) {
    case 0x04:
        io_write16(addr & 0x3FEu, val, 0xFFFFu);
        return;
    case 0x05:
        M->pal[(addr & 0x3FEu) >> 1] = val;
        return;
    case 0x06: {
        u32 off = addr & 0x1FFFEu;
        if (off >= 0x18000u) off -= 0x8000u;
        wr16le(M->vram + off, val);
        return;
    }
    case 0x07:
        M->oam[(addr & 0x3FEu) >> 1] = val;
        return;
    case 0x0E: case 0x0F:
        sram_write8(raw_addr, (u8)(val >> ((raw_addr & 1u) * 8u)));
        return;
    default:
        return;
    }
}

INLINE void bus_write16_aligned(u32 addr, u16 val)
{
    u32 top = addr >> 24;
    if (top == 0x03u) { wr16le(M->iwram + (addr & 0x7FFEu), val); return; }
    if (top == 0x02u) { wr16le(M->ewram + (addr & 0x3FFFEu), val); return; }
    bus_write16_slow(addr, val);
}

static void bus_write8(u32 addr, u8 val)
{
    switch (addr >> 24) {
    case 0x02:
        M->ewram[addr & 0x3FFFFu] = val;
        return;
    case 0x03:
        M->iwram[addr & 0x7FFFu] = val;
        return;
    case 0x04: {
        u16 mask = (addr & 1u) ? 0xFF00u : 0x00FFu;
        io_write16(addr & 0x3FEu, (u16)((u16)val << ((addr & 1u) * 8u)), mask);
        return;
    }
    case 0x05:
        /* 8-bit STRB to Palette duplicates byte across the halfword */
        M->pal[(addr & 0x3FEu) >> 1] = (u16)((u16)val * 0x0101u);
        return;
    case 0x06: {
        /* 8-bit STRB to BG VRAM duplicates byte across the halfword; OBJ VRAM ignores STRB */
        u32 off = addr & 0x1FFFFu;
        u32 bg_end = ((io16(0x000) & 7u) >= 3u) ? 0x14000u : 0x10000u;
        if (off < bg_end)
            wr16le(M->vram + (off & ~1u), (u16)((u16)val * 0x0101u));
        return;
    }
    case 0x07:
        /* OAM ignores 8-bit STRB */
        return;
    case 0x0E: case 0x0F:
        sram_write8(addr, val);
        return;
    default:
        return;
    }
}

/* ---- DMA transfer engine ---- */
static void execute_dma(int ch, int is_fifo)
{
    struct gba_dma *d = &S.dma[ch];
    u16 h = d->cnt_h;
    int word32 = is_fifo ? 1 : ((h >> 10) & 1);
    u32 count  = is_fifo ? 4u : d->int_cnt;
    u32 step   = word32 ? 4u : 2u;

    static const s32 delta[4] = { 1, -1, 0, 1 };
    u32 dst_ctrl = (h >> 5) & 3u;
    u32 src_ctrl = (h >> 7) & 3u;
    s32 ds = is_fifo ? 0 : delta[dst_ctrl] * (s32)step;
    s32 ss = delta[src_ctrl] * (s32)step;

    u32 src = d->int_sad;
    u32 dst = d->int_dad;

    /* GamePak ROM (0x08..0x0D) always increments DMA source address on hardware */
    if ((src >> 24) >= 0x08u && (src >> 24) <= 0x0Du)
        ss = (s32)step;

    int eep_wr = (ch == 3 && !word32 && (dst >> 24) == 0x0Du &&
                  (S.rom_size <= 0x01000000u || dst >= 0x0DFFFF00u));
    if (eep_wr && S.save_type == SAVE_NONE) {
        S.save_type = SAVE_EEPROM;
        S.save_size = 0x200u;
    }

    if (word32) {
        for (u32 i = 0; i < count; i++) {
            if ((src >> 24) >= 0x02u)
                d->latch = bus_read32_aligned(src);
            bus_write32_aligned(dst, d->latch);
            src += (u32)ss;
            dst += (u32)ds;
        }
    } else {
        for (u32 i = 0; i < count; i++) {
            if ((src >> 24) >= 0x02u) {
                u16 v = bus_read16_aligned(src);
                d->latch = (u32)v * 0x00010001u;
            }
            u16 out = (u16)(d->latch >> ((dst & 2u) * 8u));
            if (eep_wr)
                eeprom_write_bit(out, count);
            else
                bus_write16_aligned(dst, out);
            src += (u32)ss;
            dst += (u32)ds;
        }
    }

    d->int_sad = src;
    d->int_dad = dst;
    S.last_fetch = d->latch;

    u32 cyc = count * (word32 ? 2u : 1u);
    S.cyc_left -= (s32)cyc;
    if (S.active_timers)
        S.tmr_pend += cyc;

    if (h & 0x4000u)
        raise_irq((u16)(IRQ_DMA0 << ch));

    int repeat = (h & 0x0200u) && (((h >> 12) & 3u) != 0u);
    if (repeat) {
        u32 max_c = (ch == 3) ? 0x10000u : 0x4000u;
        u32 c = d->cnt_l & (max_c - 1u);
        d->int_cnt = c ? c : max_c;
        if (!is_fifo && dst_ctrl == 3u)
            d->int_dad = d->dad;
    } else {
        d->cnt_h &= (u16)~0x8000u;
        set_io16(0x0BAu + (u32)ch * 12u, d->cnt_h);
    }
}

static void run_dma_timing(int timing)
{
    for (int ch = 0; ch < 4; ch++) {
        u16 h = S.dma[ch].cnt_h;
        if ((h & 0x8000u) && (int)((h >> 12) & 3u) == timing)
            execute_dma(ch, 0);
    }
}

static void run_dma_fifo(int fifo_idx)
{
    u32 want_dad = fifo_idx ? 0x040000A4u : 0x040000A0u;
    for (int ch = 1; ch <= 2; ch++) {
        u16 h = S.dma[ch].cnt_h;
        if ((h & 0x8200u) == 0x8200u && ((h >> 12) & 3u) == 3u && S.dma[ch].dad == want_dad)
            execute_dma(ch, 1);
    }
}

/* ---- Built-in BIOS HLE SWI Handlers (0x00..0x2A) ---- */
static u32 isqrt32(u32 n)
{
    u32 res = 0;
    u32 bit = 1u << 30;
    while (bit > n)
        bit >>= 2;
    while (bit != 0) {
        if (n >= res + bit) {
            n -= res + bit;
            res = (res >> 1) + bit;
        } else {
            res >>= 1;
        }
        bit >>= 2;
    }
    return res;
}

/* Exact GBA BIOS 1.14 fixed-point atan(t), returning s16 in [-0x2000, +0x2000] for |t| <= 1.0 (0x4000) */
static s16 bios_atan(s16 t)
{
    s32 a = -((t * t) >> 14);
    s32 r = ((0xA9 * a) >> 14) + 0x390;
    r = ((r * a) >> 14) + 0x91C;
    r = ((r * a) >> 14) + 0xFB6;
    r = ((r * a) >> 14) + 0x16AA;
    r = ((r * a) >> 14) + 0x2081;
    r = ((r * a) >> 14) + 0x3651;
    r = ((r * a) >> 14) + 0xA2F9;
    return (s16)((t * r) >> 16);
}

static u16 bios_atan2(s16 x, s16 y)
{
    if (y == 0)
        return (x >= 0) ? 0x0000u : 0x8000u;
    if (x == 0)
        return (y >= 0) ? 0x4000u : 0xC000u;
    if (y >= 0) {
        if (x >= 0) {
            if (x >= y)
                return (u16)bios_atan((s16)(((s32)y << 14) / x));
            return (u16)(0x4000 - bios_atan((s16)(((s32)x << 14) / y)));
        }
        if (-x >= y)
            return (u16)(0x8000 + bios_atan((s16)(((s32)y << 14) / x)));
        return (u16)(0x4000 - bios_atan((s16)(((s32)x << 14) / y)));
    }
    if (x < 0) {
        if (-x > -y)
            return (u16)(0x8000 + bios_atan((s16)(((s32)y << 14) / x)));
        return (u16)(0xC000 - bios_atan((s16)(((s32)x << 14) / y)));
    }
    if (x >= -y)
        return (u16)(0x10000 + bios_atan((s16)(((s32)y << 14) / x)));
    return (u16)(0xC000 - bios_atan((s16)(((s32)x << 14) / y)));
}

static void hle_register_ram_reset(u32 flags)
{
    if (flags & 0x01u) mem_zero(M->ewram, sizeof(M->ewram));
    if (flags & 0x02u) mem_zero(M->iwram, 0x7E00u);
    if (flags & 0x04u) mem_zero(M->pal, sizeof(M->pal));
    if (flags & 0x08u) mem_zero(M->vram, sizeof(M->vram));
    if (flags & 0x10u) mem_zero(M->oam, sizeof(M->oam));
    if (flags & 0x20u) mem_zero(M->io + 0x120, 0x10u);
    if (flags & 0x40u) {
        mem_zero(M->io + 0x060, 0x30u);
        set_io16(0x088, 0x0200u);
        fifo_reset(0);
        fifo_reset(1);
    }
    if (flags & 0x80u) {
        set_io16(0x000, 0x0080u);
        mem_zero(M->io + 0x008, 0x50u);
        set_io16(0x020, 0x0100u);
        set_io16(0x026, 0x0100u);
        set_io16(0x030, 0x0100u);
        set_io16(0x036, 0x0100u);
        S.bgx[0] = S.bgy[0] = S.bgx[1] = S.bgy[1] = 0;
    }
}

static void hle_lz77(u32 src, u32 dst, int vram16)
{
    if ((src >> 24) < 0x02u)
        return;
    u32 hdr = bus_read32_aligned(src);
    u32 rem = hdr >> 8;
    src += 4u;
    if (rem == 0 || rem > 0x80000u)
        return;

    /* Scratch ring of last 4 KB so VRAM reads never miss odd byte boundaries */
    static u8 win[4096];
    u32 wpos = 0;
    u16 half = 0;
    u32 out_pos = 0;

    while (rem > 0) {
        u8 flags = bus_read8(src++);
        for (int b = 7; b >= 0 && rem > 0; b--) {
            if (flags & (1u << b)) {
                u8 b0 = bus_read8(src++);
                u8 b1 = bus_read8(src++);
                u32 len = ((u32)(b0 >> 4) & 0xFu) + 3u;
                u32 disp = (((u32)(b0 & 0xFu) << 8) | b1) + 1u;
                for (u32 k = 0; k < len && rem > 0; k++) {
                    u8 v = win[(wpos - disp) & 0xFFFu];
                    win[wpos & 0xFFFu] = v;
                    wpos++;
                    if (vram16) {
                        if (out_pos & 1u)
                            bus_write16_aligned(dst + (out_pos & ~1u), (u16)(half | ((u16)v << 8)));
                        else
                            half = v;
                    } else {
                        bus_write8(dst + out_pos, v);
                    }
                    out_pos++;
                    rem--;
                }
            } else {
                u8 v = bus_read8(src++);
                win[wpos & 0xFFFu] = v;
                wpos++;
                if (vram16) {
                    if (out_pos & 1u)
                        bus_write16_aligned(dst + (out_pos & ~1u), (u16)(half | ((u16)v << 8)));
                    else
                        half = v;
                } else {
                    bus_write8(dst + out_pos, v);
                }
                out_pos++;
                rem--;
            }
        }
    }
}

static void hle_rl_uncomp(u32 src, u32 dst, int vram16)
{
    if ((src >> 24) < 0x02u)
        return;
    u32 rem = bus_read32_aligned(src) >> 8;
    src += 4u;
    if (rem == 0 || rem > 0x80000u)
        return;

    u16 half = 0;
    u32 out_pos = 0;
    while (rem > 0) {
        u8 hdr = bus_read8(src++);
        if (hdr & 0x80u) {
            u32 len = (hdr & 0x7Fu) + 3u;
            u8 v = bus_read8(src++);
            for (u32 k = 0; k < len && rem > 0; k++) {
                if (vram16) {
                    if (out_pos & 1u)
                        bus_write16_aligned(dst + (out_pos & ~1u), (u16)(half | ((u16)v << 8)));
                    else
                        half = v;
                } else {
                    bus_write8(dst + out_pos, v);
                }
                out_pos++;
                rem--;
            }
        } else {
            u32 len = (hdr & 0x7Fu) + 1u;
            for (u32 k = 0; k < len && rem > 0; k++) {
                u8 v = bus_read8(src++);
                if (vram16) {
                    if (out_pos & 1u)
                        bus_write16_aligned(dst + (out_pos & ~1u), (u16)(half | ((u16)v << 8)));
                    else
                        half = v;
                } else {
                    bus_write8(dst + out_pos, v);
                }
                out_pos++;
                rem--;
            }
        }
    }
}

static void hle_huff_uncomp(u32 src, u32 dst)
{
    if ((src >> 24) < 0x02u)
        return;
    u32 hdr = bus_read32_aligned(src);
    u32 bit_depth = hdr & 0xFu;
    u32 rem_bytes = hdr >> 8;
    if ((bit_depth != 4u && bit_depth != 8u) || rem_bytes == 0 || rem_bytes > 0x80000u)
        return;

    u32 tree_size = ((u32)bus_read8(src + 4u) + 1u) * 2u;
    u32 tree_root = src + 5u;
    u32 cur = src + 4u + tree_size;
    u32 node = tree_root;
    u32 out_word = 0, out_bits = 0;

    while (rem_bytes > 0) {
        u32 bits = bus_read32_aligned(cur);
        cur += 4u;
        for (int b = 31; b >= 0 && rem_bytes > 0; b--) {
            u32 bit = (bits >> b) & 1u;
            u8 nd = bus_read8(node);
            int leaf = (nd >> (7u - bit)) & 1;
            node = (node & ~1u) + (((u32)(nd & 0x3Fu) + 1u) << 1) + bit;
            if (leaf) {
                u32 sym = bus_read8(node);
                if (bit_depth == 4u) {
                    out_word |= (sym & 0xFu) << out_bits;
                    out_bits += 4u;
                } else {
                    out_word |= (sym & 0xFFu) << out_bits;
                    out_bits += 8u;
                }
                if (out_bits == 32u) {
                    bus_write32_aligned(dst, out_word);
                    dst += 4u;
                    out_word = 0;
                    out_bits = 0;
                    rem_bytes = (rem_bytes >= 4u) ? (rem_bytes - 4u) : 0u;
                }
                node = tree_root;
            }
        }
    }
}

static void hle_bit_unpack(u32 src, u32 dst, u32 info)
{
    if ((src >> 24) < 0x02u)
        return;
    u32 len = bus_read16_aligned(info);
    u32 sw  = bus_read8(info + 2u);
    u32 dw  = bus_read8(info + 3u);
    u32 ofs = bus_read32_aligned(info + 4u);
    int zero_add = (int)((ofs >> 31) & 1u);
    ofs &= 0x7FFFFFFFu;
    if (!sw || !dw || sw > 8u || dw > 32u)
        return;

    u32 mask = (1u << sw) - 1u;
    u32 out_word = 0, out_bits = 0;
    for (u32 i = 0; i < len; i++) {
        u8 b = bus_read8(src++);
        for (u32 sb = 0; sb < 8u; sb += sw) {
            u32 v = (b >> sb) & mask;
            if (v != 0 || zero_add)
                v += ofs;
            out_word |= v << out_bits;
            out_bits += dw;
            if (out_bits >= 32u) {
                bus_write32_aligned(dst, out_word);
                dst += 4u;
                out_word = 0;
                out_bits = 0;
            }
        }
    }
    if (out_bits > 0)
        bus_write32_aligned(dst, out_word);
}

static void hle_diff_unfilter(u32 src, u32 dst, int bits16, int vram16)
{
    if ((src >> 24) < 0x02u)
        return;
    u32 rem = bus_read32_aligned(src) >> 8;
    src += 4u;
    if (rem == 0 || rem > 0x80000u)
        return;

    if (bits16) {
        u16 acc = 0;
        while (rem >= 2u) {
            acc = (u16)(acc + bus_read16_aligned(src));
            bus_write16_aligned(dst, acc);
            src += 2u;
            dst += 2u;
            rem -= 2u;
        }
    } else {
        u8 acc = 0;
        u16 half = 0;
        u32 pos = 0;
        while (rem > 0) {
            acc = (u8)(acc + bus_read8(src++));
            if (vram16) {
                if (pos & 1u)
                    bus_write16_aligned(dst + (pos & ~1u), (u16)(half | ((u16)acc << 8)));
                else
                    half = acc;
            } else {
                bus_write8(dst + pos, acc);
            }
            pos++;
            rem--;
        }
    }
}

/* Returns 1 if PC was redirected (e.g. SoftReset / IntrWait), 0 for normal SWI return via 0x188 */
static int hle_swi_dispatch(void)
{
    u32 lr = S.r[14];
    u32 swi;
    if (S.spsr & CPSR_T)
        swi = bus_read16_aligned(lr - 2u) & 0xFFu;
    else
        swi = (bus_read32_aligned(lr - 4u) >> 16) & 0xFFu;

    switch (swi) {
    case 0x00: { /* SoftReset */
        u8 boot_ram = bus_read8(0x03007FFAu);
        mem_zero(M->iwram + 0x7E00u, 0x200u);
        S.cpsr = MODE_SYS;
        for (int i = 0; i < 15; i++) S.r[i] = 0;
        S.bank_r13[0] = S.r[13] = 0x03007F00u;
        S.bank_r13[2] = 0x03007FA0u;
        S.bank_r13[3] = 0x03007FE0u;
        S.bios_latch  = 0xE129F000u;
        S.r[15]       = boot_ram ? 0x02000000u : 0x08000000u;
        return 1;
    }
    case 0x01: /* RegisterRamReset */
        hle_register_ram_reset(S.r[0]);
        break;
    case 0x02: /* Halt */
    case 0x03: /* Stop */
        if (!(io16(0x200) & io16(0x202)))
            S.halted = 1;
        break;
    case 0x04: /* IntrWait(r0, r1) -> jump to real ARM loop at 0x000001A0 */
        S.r[15] = 0x000001A0u;
        return 1;
    case 0x05: /* VBlankIntrWait -> IntrWait(1, 1) */
        S.r[0] = 1u;
        S.r[1] = 1u;
        S.r[15] = 0x000001A0u;
        return 1;
    case 0x06:   /* Div(s32 num, s32 den) */
    case 0x07: { /* DivArm(s32 den, s32 num) */
        s32 num = (swi == 0x06u) ? (s32)S.r[0] : (s32)S.r[1];
        s32 den = (swi == 0x06u) ? (s32)S.r[1] : (s32)S.r[0];
        if (den == 0) {
            S.r[0] = (num < 0) ? (u32)-1 : 1u;
            S.r[1] = (u32)num;
            S.r[3] = 1u;
        } else if ((u32)num == 0x80000000u && den == -1) {
            S.r[0] = 0x80000000u;
            S.r[1] = 0u;
            S.r[3] = 0x80000000u;
        } else {
            s32 q = num / den;
            s32 r = num % den;
            S.r[0] = (u32)q;
            S.r[1] = (u32)r;
            S.r[3] = (q < 0) ? (u32)(-(s64)q) : (u32)q;
        }
        break;
    }
    case 0x08: /* Sqrt(u32 v) */
        S.r[0] = isqrt32(S.r[0]);
        break;
    case 0x09: /* ArcTan(s16 tan) */
        S.r[0] = (u32)(s32)bios_atan((s16)S.r[0]);
        break;
    case 0x0A: /* ArcTan2(s16 x, s16 y) */
        S.r[0] = bios_atan2((s16)S.r[0], (s16)S.r[1]);
        break;
    case 0x0B: { /* CpuSet(src, dst, cnt) */
        u32 src = S.r[0], dst = S.r[1], cnt = S.r[2];
        if ((src >> 24) < 0x02u)
            break;
        u32 n = cnt & 0x1FFFFFu;
        int fixed = (cnt >> 24) & 1;
        int w32   = (cnt >> 26) & 1;
        if (w32) {
            for (u32 i = 0; i < n; i++) {
                bus_write32_aligned(dst, bus_read32_aligned(src));
                if (!fixed) src += 4u;
                dst += 4u;
            }
        } else {
            for (u32 i = 0; i < n; i++) {
                bus_write16_aligned(dst, bus_read16_aligned(src));
                if (!fixed) src += 2u;
                dst += 2u;
            }
        }
        break;
    }
    case 0x0C: { /* CpuFastSet(src, dst, cnt) */
        u32 src = S.r[0] & ~3u, dst = S.r[1] & ~3u, cnt = S.r[2];
        if ((src >> 24) < 0x02u)
            break;
        u32 n = ((cnt & 0x1FFFFFu) + 7u) & ~7u;
        int fixed = (cnt >> 24) & 1;
        u32 fill = fixed ? bus_read32_aligned(src) : 0u;
        for (u32 i = 0; i < n; i++) {
            u32 v = fixed ? fill : bus_read32_aligned(src);
            bus_write32_aligned(dst, v);
            if (!fixed) src += 4u;
            dst += 4u;
        }
        break;
    }
    case 0x0D: /* GetBiosChecksum */
        S.r[0] = 0xBAAE187Fu;
        break;
    case 0x0E: { /* BgAffineSet(src, dst, count) */
        u32 src = S.r[0], dst = S.r[1], count = S.r[2];
        for (u32 i = 0; i < count; i++) {
            s32 ox = (s32)bus_read32_aligned(src + 0u);
            s32 oy = (s32)bus_read32_aligned(src + 4u);
            s16 cx = (s16)bus_read16_aligned(src + 8u);
            s16 cy = (s16)bus_read16_aligned(src + 10u);
            s16 sx = (s16)bus_read16_aligned(src + 12u);
            s16 sy = (s16)bus_read16_aligned(src + 14u);
            u8 ang = (u8)(bus_read16_aligned(src + 16u) >> 8);
            s32 sn = M->sin_lut[ang];
            s32 cs = M->sin_lut[(ang + 64u) & 255u];
            s16 pa = (s16)(((s32)sx * cs) >> 14);
            s16 pb = (s16)((-(s32)sx * sn) >> 14);
            s16 pc = (s16)(((s32)sy * sn) >> 14);
            s16 pd = (s16)(((s32)sy * cs) >> 14);
            s32 rx = ox - ((s32)pa * cx + (s32)pb * cy);
            s32 ry = oy - ((s32)pc * cx + (s32)pd * cy);
            bus_write16_aligned(dst + 0u,  (u16)pa);
            bus_write16_aligned(dst + 2u,  (u16)pb);
            bus_write16_aligned(dst + 4u,  (u16)pc);
            bus_write16_aligned(dst + 6u,  (u16)pd);
            bus_write32_aligned(dst + 8u,  (u32)rx);
            bus_write32_aligned(dst + 12u, (u32)ry);
            src += 20u;
            dst += 16u;
        }
        break;
    }
    case 0x0F: { /* ObjAffineSet(src, dst, count, offset) */
        u32 src = S.r[0], dst = S.r[1], count = S.r[2], stride = S.r[3];
        for (u32 i = 0; i < count; i++) {
            s16 sx = (s16)bus_read16_aligned(src + 0u);
            s16 sy = (s16)bus_read16_aligned(src + 2u);
            u8 ang = (u8)(bus_read16_aligned(src + 4u) >> 8);
            s32 sn = M->sin_lut[ang];
            s32 cs = M->sin_lut[(ang + 64u) & 255u];
            s16 pa = (s16)(((s32)sx * cs) >> 14);
            s16 pb = (s16)((-(s32)sx * sn) >> 14);
            s16 pc = (s16)(((s32)sy * sn) >> 14);
            s16 pd = (s16)(((s32)sy * cs) >> 14);
            bus_write16_aligned(dst + 0u * stride, (u16)pa);
            bus_write16_aligned(dst + 1u * stride, (u16)pb);
            bus_write16_aligned(dst + 2u * stride, (u16)pc);
            bus_write16_aligned(dst + 3u * stride, (u16)pd);
            src += 8u;
            dst += 4u * stride;
        }
        break;
    }
    case 0x10:
        hle_bit_unpack(S.r[0], S.r[1], S.r[2]);
        break;
    case 0x11:
        hle_lz77(S.r[0], S.r[1], 0);
        break;
    case 0x12:
        hle_lz77(S.r[0], S.r[1], 1);
        break;
    case 0x13:
        hle_huff_uncomp(S.r[0], S.r[1]);
        break;
    case 0x14:
        hle_rl_uncomp(S.r[0], S.r[1], 0);
        break;
    case 0x15:
        hle_rl_uncomp(S.r[0], S.r[1], 1);
        break;
    case 0x16:
        hle_diff_unfilter(S.r[0], S.r[1], 0, 0);
        break;
    case 0x17:
        hle_diff_unfilter(S.r[0], S.r[1], 0, 1);
        break;
    case 0x18:
        hle_diff_unfilter(S.r[0], S.r[1], 1, 1);
        break;
    case 0x19: /* SoundBias */
        set_io16(0x088, S.r[0] ? 0x0200u : 0x0000u);
        break;
    case 0x1A: /* SoundDriverInit */
        bus_write32_aligned(0x03007FF0u, S.r[0]);
        break;
    case 0x1B: /* SoundDriverMode */
    case 0x1C: /* SoundDriverMain */
    case 0x1D: /* SoundDriverVSync */
    case 0x28: /* SoundDriverVSyncOff */
    case 0x29: /* SoundDriverVSyncOn */
        break;
    case 0x1E: /* SoundChannelClear */
        fifo_reset(0);
        fifo_reset(1);
        S.psg1.enabled = S.psg2.enabled = S.psg3.enabled = S.psg4.enabled = 0;
        break;
    case 0x1F: { /* MidiKey2Freq(WaveData *wa, u8 mk, u8 fp) */
        static const u32 freq_tab[13] = {
            0x80000000u, 0x879C7C97u, 0x8FACD61Eu, 0x9837F052u,
            0xA14517CCu, 0xAADC0848u, 0xB504F334u, 0xBFC886BBu,
            0xCB2FF52Au, 0xD744FCCBu, 0xE411F03Au, 0xF1A1BF39u,
            0xFFFFFFFFu
        };
        u32 base_freq = bus_read32_aligned(S.r[0] + 4u);
        s32 mk = (s32)(S.r[1] & 0xFFu);
        u32 fp = S.r[2] & 0xFFu;
        s32 diff = 180 - mk;
        s32 oct = 0;
        while (diff > 0) { diff -= 12; oct++; }
        while (diff < -11) { diff += 12; oct--; }
        u32 semi = (u32)(-diff); /* 0..11 */
        u64 f0 = freq_tab[semi];
        u64 f1 = freq_tab[semi + 1u];
        u64 scale = f0 + (((f1 - f0) * fp) >> 8);
        u64 prod = ((u64)base_freq * scale) >> 31;
        if (oct > 0)
            prod >>= (oct > 31 ? 31 : oct);
        else if (oct < 0)
            prod <<= (-oct > 16 ? 16 : -oct);
        S.r[0] = (u32)prod;
        break;
    }
    case 0x2A: /* SoundGetJumpList */
        for (u32 i = 0; i < 36u; i++)
            bus_write32_aligned(S.r[0] + i * 4u, 0x00000300u);
        break;
    default:
        break;
    }
    return 0;
}

/* ---- ARM7TDMI CPU Execution ---- */
static void cpu_take_irq(void)
{
    u32 old_cpsr = S.cpsr;
    u32 ret_pc = (old_cpsr & CPSR_T) ? ((S.r[15] & ~1u) + 4u) : ((S.r[15] & ~3u) + 4u);
    cpu_switch_mode(MODE_IRQ);
    S.spsr  = old_cpsr;
    S.r[14] = ret_pc;
    S.cpsr  = (S.cpsr & ~CPSR_T) | CPSR_I;
    S.r[15] = 0x00000018u;
    S.halted = 0;
}

static void cpu_take_swi(u32 next_pc)
{
    u32 old_cpsr = S.cpsr;
    cpu_switch_mode(MODE_SVC);
    S.spsr  = old_cpsr;
    S.r[14] = next_pc;
    S.cpsr  = (S.cpsr & ~CPSR_T) | CPSR_I;
    S.r[15] = 0x00000008u;
}

static void cpu_take_undef(u32 next_pc)
{
    u32 old_cpsr = S.cpsr;
    cpu_switch_mode(MODE_UND);
    S.spsr  = old_cpsr;
    S.r[14] = next_pc;
    S.cpsr  = (S.cpsr & ~CPSR_T) | CPSR_I;
    S.r[15] = 0x00000004u;
}

INLINE u32 shift_imm(u32 val, u32 type, u32 amt, u32 *carry)
{
    switch (type & 3u) {
    case 0: /* LSL */
        if (amt == 0) return val;
        *carry = (val >> (32u - amt)) & 1u;
        return val << amt;
    case 1: /* LSR (#0 means #32) */
        if (amt == 0) { *carry = (val >> 31) & 1u; return 0u; }
        *carry = (val >> (amt - 1u)) & 1u;
        return val >> amt;
    case 2: /* ASR (#0 means #32) */
        if (amt == 0) {
            *carry = (val >> 31) & 1u;
            return (val & 0x80000000u) ? 0xFFFFFFFFu : 0u;
        }
        *carry = (val >> (amt - 1u)) & 1u;
        return (u32)((s32)val >> amt);
    default: /* ROR (#0 means RRX) */
        if (amt == 0) {
            u32 cin = *carry & 1u;
            *carry = val & 1u;
            return (cin << 31) | (val >> 1);
        }
        *carry = (val >> (amt - 1u)) & 1u;
        return ror32(val, amt);
    }
}

INLINE u32 shift_reg(u32 val, u32 type, u32 amt, u32 *carry)
{
    amt &= 0xFFu;
    if (amt == 0)
        return val;
    switch (type & 3u) {
    case 0: /* LSL */
        if (amt < 32u) { *carry = (val >> (32u - amt)) & 1u; return val << amt; }
        *carry = (amt == 32u) ? (val & 1u) : 0u;
        return 0u;
    case 1: /* LSR */
        if (amt < 32u) { *carry = (val >> (amt - 1u)) & 1u; return val >> amt; }
        *carry = (amt == 32u) ? ((val >> 31) & 1u) : 0u;
        return 0u;
    case 2: /* ASR */
        if (amt < 32u) { *carry = (val >> (amt - 1u)) & 1u; return (u32)((s32)val >> amt); }
        *carry = (val >> 31) & 1u;
        return (val & 0x80000000u) ? 0xFFFFFFFFu : 0u;
    default: { /* ROR */
        u32 s = amt & 31u;
        if (s == 0) { *carry = (val >> 31) & 1u; return val; }
        *carry = (val >> (s - 1u)) & 1u;
        return ror32(val, s);
    }
    }
}

INLINE void set_nz(u32 res)
{
    S.cpsr = (S.cpsr & ~(FLAG_N | FLAG_Z)) |
             (res & FLAG_N) |
             (res == 0 ? FLAG_Z : 0u);
}

INLINE void set_nzc(u32 res, u32 c)
{
    S.cpsr = (S.cpsr & ~(FLAG_N | FLAG_Z | FLAG_C)) |
             (res & FLAG_N) |
             (res == 0 ? FLAG_Z : 0u) |
             (c ? FLAG_C : 0u);
}

INLINE u32 alu_add(u32 a, u32 b, int set_flags)
{
    u32 res = a + b;
    if (set_flags) {
        u32 c = (res < a) ? FLAG_C : 0u;
        u32 v = ((~(a ^ b) & (a ^ res)) & 0x80000000u) ? FLAG_V : 0u;
        S.cpsr = (S.cpsr & 0x0FFFFFFFu) | (res & FLAG_N) | (res == 0 ? FLAG_Z : 0u) | c | v;
    }
    return res;
}

INLINE u32 alu_adc(u32 a, u32 b, u32 cin, int set_flags)
{
    u64 sum = (u64)a + (u64)b + (u64)cin;
    u32 res = (u32)sum;
    if (set_flags) {
        u32 c = (sum >> 32) ? FLAG_C : 0u;
        u32 v = ((~(a ^ b) & (a ^ res)) & 0x80000000u) ? FLAG_V : 0u;
        S.cpsr = (S.cpsr & 0x0FFFFFFFu) | (res & FLAG_N) | (res == 0 ? FLAG_Z : 0u) | c | v;
    }
    return res;
}

INLINE u32 alu_sub(u32 a, u32 b, int set_flags)
{
    u32 res = a - b;
    if (set_flags) {
        u32 c = (a >= b) ? FLAG_C : 0u;
        u32 v = (((a ^ b) & (a ^ res)) & 0x80000000u) ? FLAG_V : 0u;
        S.cpsr = (S.cpsr & 0x0FFFFFFFu) | (res & FLAG_N) | (res == 0 ? FLAG_Z : 0u) | c | v;
    }
    return res;
}

INLINE u32 alu_sbc(u32 a, u32 b, u32 cin, int set_flags)
{
    u64 diff = (u64)a - (u64)b - (u64)(1u - cin);
    u32 res = (u32)diff;
    if (set_flags) {
        u32 c = !(diff >> 63) ? FLAG_C : 0u;
        u32 v = (((a ^ b) & (a ^ res)) & 0x80000000u) ? FLAG_V : 0u;
        S.cpsr = (S.cpsr & 0x0FFFFFFFu) | (res & FLAG_N) | (res == 0 ? FLAG_Z : 0u) | c | v;
    }
    return res;
}

/* Read/write user-bank register for LDM/STM with S=1 (user bank transfer) */
static u32 read_usr_reg(int idx)
{
    u32 mode = S.cpsr & CPSR_MODE_MASK;
    if (idx < 8 || idx == 15)
        return S.r[idx];
    if (idx < 13)
        return (mode == MODE_FIQ) ? S.usr_r8_12[idx - 8] : S.r[idx];
    if (mode == MODE_USR || mode == MODE_SYS)
        return S.r[idx];
    return (idx == 13) ? S.bank_r13[0] : S.bank_r14[0];
}

static void write_usr_reg(int idx, u32 val)
{
    u32 mode = S.cpsr & CPSR_MODE_MASK;
    if (idx < 8) {
        S.r[idx] = val;
    } else if (idx < 13) {
        if (mode == MODE_FIQ) S.usr_r8_12[idx - 8] = val;
        else                  S.r[idx] = val;
    } else if (mode == MODE_USR || mode == MODE_SYS) {
        S.r[idx] = val;
    } else if (idx == 13) {
        S.bank_r13[0] = val;
    } else if (idx == 14) {
        S.bank_r14[0] = val;
    }
}

/* Fast ARM instruction fetch */
INLINE u32 fetch_arm(u32 pc)
{
    u32 reg = pc >> 24;
    u32 op;
    if (reg == 0x08u || reg == 0x09u || reg == 0x0Au || reg == 0x0Bu || reg == 0x0Cu) {
        u32 off = pc & 0x01FFFFFCu;
        op = (off + 4u <= S.rom_size) ? rd32le(S.rom + off) : bus_read32_aligned(pc);
    } else if (reg == 0x03u) {
        op = rd32le(M->iwram + (pc & 0x7FFCu));
    } else if (reg == 0x02u) {
        op = rd32le(M->ewram + (pc & 0x3FFFCu));
    } else if (pc < 0x4000u) {
        op = rd32le(M->bios + pc);
        S.bios_latch = rd32le(M->bios + ((pc + 8u) & 0x3FFCu));
    } else {
        op = bus_read32_aligned(pc);
    }
    S.last_fetch = op;
    return op;
}

/* Fast Thumb instruction fetch */
INLINE u16 fetch_thumb(u32 pc)
{
    u32 reg = pc >> 24;
    u16 op;
    if (reg == 0x08u || reg == 0x09u || reg == 0x0Au || reg == 0x0Bu || reg == 0x0Cu) {
        u32 off = pc & 0x01FFFFFEu;
        op = (off + 2u <= S.rom_size) ? rd16le(S.rom + off) : bus_read16_aligned(pc);
    } else if (reg == 0x03u) {
        op = rd16le(M->iwram + (pc & 0x7FFEu));
    } else if (reg == 0x02u) {
        op = rd16le(M->ewram + (pc & 0x3FFFEu));
    } else if (pc < 0x4000u) {
        op = rd16le(M->bios + pc);
        S.bios_latch = rd32le(M->bios + ((pc + 4u) & 0x3FFCu));
    } else {
        op = bus_read16_aligned(pc);
    }
    S.last_fetch = (u32)op * 0x00010001u;
    return op;
}

/* Returns >0 max cycle skip if `addr` is safe to fast-forward in a stateless poll loop, else 0 */
static s32 poll_skip_limit(u32 addr, s32 rem)
{
    u32 top = addr >> 24;
    if (top == 0x02u || top == 0x03u) {
        if (S.tmr_pend) timers_flush();
        return timers_next_event(rem);
    }
    if (top == 0x04u) {
        u32 io = addr & 0xFFFFFFu;
        if ((io >= 0x004u && io <= 0x007u) || (io >= 0x202u && io <= 0x203u)) {
            if (S.tmr_pend) timers_flush();
            return timers_next_event(rem);
        }
        if ((io == 0x100u || io == 0x104u || io == 0x108u || io == 0x10Cu)) {
            int ch = (int)((io - 0x100u) >> 2);
            u16 cnt = S.tmr[ch].cnt;
            /* Prescaled non-cascade timer: counter only changes every 64 / 256 / 1024 cycles! */
            if ((cnt & 0x0080u) && (ch == 0 || !(cnt & 0x0004u)) && (cnt & 3u) != 0u) {
                static const u8 sh_tab[4] = { 0, 6, 8, 10 };
                if (S.tmr_pend) timers_flush();
                s32 lim = timers_next_event(rem);
                s32 tick = (s32)((1u << sh_tab[cnt & 3u]) - S.tmr[ch].prescale_acc);
                if (tick < lim) lim = tick;
                return lim;
            }
        }
    }
    return 0;
}

static s32 arm_poll_skip(u32 target, u32 br_pc, s32 rem)
{
    if ((target >> 24) != (br_pc >> 24))
        return 0;
    /* a C compiler's form of the wait has the polled place's address loaded first, every pass:
       "ldr rX, [pc, #n]; ldrh rY, [rX]; cmp rZ, rY; b<cond> back" -- Another World's wait for a raster line
       (VCOUNT), a tenth of the instructions it ran */
    u32 lit_reg = 16u;
    if (br_pc - target == 12u) {
        u32 il = bus_read32_aligned(target);
        if ((il & 0xFF7F0000u) != 0xE51F0000u)
            return 0;
        lit_reg = (il >> 12) & 15u;
        target += 4u;
    } else if (br_pc - target != 8u) {
        return 0;
    }
    u32 i0 = bus_read32_aligned(target);
    u32 i1 = bus_read32_aligned(target + 4u);
    if ((i0 >> 28) != 0xEu || (i1 >> 28) != 0xEu)
        return 0;
    if (lit_reg != 16u && ((i0 >> 16) & 15u) != lit_reg)
        return 0;                               /* (the load must go through the literal's register) */
    u32 rn, rd, addr;
    if ((i0 & 0x0F300000u) == 0x05100000u) {
        rn = (i0 >> 16) & 15u;
        rd = (i0 >> 12) & 15u;
        u32 off = i0 & 0xFFFu;
        if (rn == rd || rn == 15u || rd == 15u) return 0;
        addr = (i0 & (1u << 23)) ? (S.r[rn] + off) : (S.r[rn] - off);
    } else if ((i0 & 0x0F700090u) == 0x01500090u && (i0 & 0x60u) != 0u) {
        rn = (i0 >> 16) & 15u;
        rd = (i0 >> 12) & 15u;
        u32 off = ((i0 >> 4) & 0xF0u) | (i0 & 0xFu);
        if (rn == rd || rn == 15u || rd == 15u) return 0;
        addr = (i0 & (1u << 23)) ? (S.r[rn] + off) : (S.r[rn] - off);
    } else {
        return 0;
    }
    if (((i1 >> 26) & 3u) != 0u)
        return 0;
    if (((i1 >> 25) & 1u) == 0u && (i1 & 0x90u) == 0x90u)
        return 0;
    if (((i1 >> 25) & 1u) == 0u && (i1 & 0x0FFFFFF0u) == 0x012FFF10u)
        return 0;
    u32 aop = (i1 >> 21) & 15u;
    u32 d1  = (i1 >> 12) & 15u;
    int ok = (aop >= 8u && aop <= 11u) ? ((i1 & (1u << 20)) && d1 != 15u) : (d1 == rd);
    return ok ? poll_skip_limit(addr, rem) : 0;
}

static s32 thumb_poll_skip(u32 target, u32 br_pc, s32 rem)
{
    if (br_pc - target != 6u || (target >> 24) != (br_pc >> 24))
        return 0;
    u16 t0 = bus_read16_aligned(target);
    u16 t1 = bus_read16_aligned(target + 2u);
    u32 rd = t0 & 7u;
    u32 rb = (t0 >> 3) & 7u;
    if (rd == rb)
        return 0;
    u32 imm = (t0 >> 6) & 31u;
    u32 addr;
    if ((t0 & 0xF800u) == 0x6800u)      addr = S.r[rb] + (imm << 2);
    else if ((t0 & 0xF800u) == 0x7800u) addr = S.r[rb] + imm;
    else if ((t0 & 0xF800u) == 0x8800u) addr = S.r[rb] + (imm << 1);
    else return 0;
    int ok = ((t1 & 0xF800u) == 0x2800u) ||
             ((t1 & 0xFFC0u) == 0x4200u) ||
             ((t1 & 0xFFC0u) == 0x4280u) ||
             ((t1 >> 13) == 0u && ((t1 >> 11) & 3u) != 3u && (t1 & 7u) == rd);
    return ok ? poll_skip_limit(addr, rem) : 0;
}

/* The loop a C compiler makes of "for (i ...) dst16[i] = src16[i]":
       add   rC, rC, #1
       ldrh  rT, [rS], #2
       cmp   rC, rN
       strh  rT, [rD], #2
       bcc   back
   Another World's GBA port copies its whole picture to the screen with it: three quarters of all the instructions
   it runs.  Here as many passes are run in one go as end before the slice's end and the timers' next event,
   with the interpreter's own bus functions and cycle counts, so nothing differs from the instructions run one
   by one (the pointers stay in memory without side effects, and out of the region the loop itself is in).  The
   last pass, whose branch falls through, and what does not fit go the usual way.
   Returns the cycles of the passes run; 0: none, the instruction at inst_pc is still to be run. */
static u32 __attribute__((noinline)) arm_copy16_loop(u32 inst_pc, u32 op, u32 base_cyc, s32 target_left)
{
    u32 i1 = fetch_arm(inst_pc + 4u), i2 = fetch_arm(inst_pc + 8u);
    u32 i3 = fetch_arm(inst_pc + 12u), i4 = fetch_arm(inst_pc + 16u);
    if ((i1 & 0xFFF00FFFu) != 0xE0D000B2u || (i2 & 0xFFF0FFF0u) != 0xE1500000u ||
        (i3 & 0xFFF00FFFu) != 0xE0C000B2u || i4 != 0x3AFFFFFAu)
        return 0;
    u32 rc = (op >> 12) & 15u, rs = (i1 >> 16) & 15u, rt = (i1 >> 12) & 15u, rn = i2 & 15u, rd = (i3 >> 16) & 15u;
    if (((i2 >> 16) & 15u) != rc || ((i3 >> 12) & 15u) != rt)
        return 0;
    u32 used = (1u << rc) | (1u << rs) | (1u << rt) | (1u << rn) | (1u << rd);
    if ((used & 0x8000u) || (used & (used - 1u)) == 0u)
        return 0;
    {                                           /* five different registers */
        u32 bits = 0;
        for (u32 m = used; m; m &= m - 1u)
            bits++;
        if (bits != 5u)
            return 0;
    }
    u32 cnt = S.r[rc], lim = S.r[rn], src = S.r[rs], dst = S.r[rd];
    if (cnt + 1u < cnt || cnt + 1u >= lim)
        return 0;                               /* (no pass whose branch is taken) */
    u32 n = lim - cnt - 1u;
    u32 sreg = src >> 24, dreg = dst >> 24;
    /* from RAM, palette, VRAM, OAM or the cartridge's ROM; to RAM, palette, VRAM or OAM */
    if (sreg > 12u || !((0x1FECu >> sreg) & 1u) || dreg > 7u || !((0x00ECu >> dreg) & 1u) ||
        dreg == (inst_pc >> 24))
        return 0;
    u32 room = (0x01000000u - (src & 0x00FFFFFFu) + 1u) >> 1;   /* passes with the pointer still in its region */
    if (n > room)
        n = room;
    room = (0x01000000u - (dst & 0x00FFFFFFu) + 1u) >> 1;
    if (n > room)
        n = room;
    u32 pass = 5u * base_cyc + 1u + S.ws_n16[sreg] + S.ws_n16[dreg] + 2u;
    s32 floor = target_left;
    if (S.active_timers && S.tmr_next_cyc > floor)
        floor = S.tmr_next_cyc;
    s32 fit = (S.cyc_left - floor - 1) / (s32)pass;     /* passes after which the slice still has cycles left */
    if (fit <= 0)
        return 0;
    if (n > (u32)fit)
        n = (u32)fit;
    u32 val = S.r[rt];
    for (u32 i = 0; i < n; i++) {
        u32 h = bus_read16_aligned(src);
        val = (src & 1u) ? ror32(h, 8u) : h;
        bus_write16_aligned(dst, (u16)val);
        src += 2u;
        dst += 2u;
    }
    S.r[rc] = cnt + n;
    S.r[rs] = src;
    S.r[rd] = dst;
    S.r[rt] = val;
    (void)alu_sub(cnt + n, lim, 1);             /* the flags of the last pass's cmp */
    S.r[15] = inst_pc;                          /* the next pass starts at the loop's head again */
    return n * pass;
}

static u32 step_arm(u32 inst_pc, s32 target_left)
{
    inst_pc &= ~3u;
    u32 op = fetch_arm(inst_pc);
    u32 cyc = S.ws_s32[(inst_pc >> 24) & 15u];

    if ((op & 0xFFF00FFFu) == 0xE2800001u && ((op >> 16) & 15u) == ((op >> 12) & 15u)) {
        u32 run = arm_copy16_loop(inst_pc, op, cyc, target_left);   /* add rC, rC, #1: a copy loop's head? */
        if (run)
            return run;
    }

    /* Unconditional idle branch `b .` (0xEAFFFFFE) fast-forward */
    if (op == 0xEAFFFFFEu) {
        if (S.tmr_pend) timers_flush();
        s32 rem = S.cyc_left - target_left;
        s32 skip = timers_next_event(rem);
        return (skip > (s32)cyc) ? (u32)skip : cyc;
    }

    u32 cond = op >> 28;
    if (cond != 0xEu && !M->cond_lut[cond][S.cpsr >> 28]) {
        S.r[15] = inst_pc + 4u;
        return cyc;
    }

    /* Expose PC + 8 during instruction execution */
    S.r[15] = inst_pc + 8u;
    int branched = 0;
    u32 top = (op >> 25) & 7u;

    switch (top) {
    case 0: /* BX, SWP, Multiply, Halfword/Signed Transfer, MRS/MSR, or Data Processing (reg) */
        if ((op & 0x0FFFFFF0u) == 0x012FFF10u) {
            /* BX Rn */
            u32 target = S.r[op & 15u];
            if (target & 1u) {
                S.cpsr |= CPSR_T;
                S.r[15] = target & ~1u;
            } else {
                S.cpsr &= ~CPSR_T;
                S.r[15] = target & ~3u;
            }
            branched = 1;
            cyc += 2u;
            break;
        }
        if ((op & 0x0FB00FF0u) == 0x01000090u) {
            /* SWP / SWPB */
            u32 rn = (op >> 16) & 15u;
            u32 rd = (op >> 12) & 15u;
            u32 rm = op & 15u;
            u32 addr = S.r[rn];
            u32 src_val = S.r[rm];
            if (op & (1u << 22)) {
                u32 old = bus_read8(addr);
                bus_write8(addr, (u8)src_val);
                S.r[rd] = old;
            } else {
                u32 old = ror32(bus_read32_aligned(addr), (addr & 3u) * 8u);
                bus_write32_aligned(addr, src_val);
                S.r[rd] = old;
            }
            if (rd == 15u) { S.r[15] &= ~3u; branched = 1; }
            cyc += 2u;
            break;
        }
        if ((op & 0x0FC000F0u) == 0x00000090u) {
            /* MUL / MLA */
            u32 rd = (op >> 16) & 15u;
            u32 rn = (op >> 12) & 15u;
            u32 rs = (op >> 8) & 15u;
            u32 rm = op & 15u;
            u32 res = S.r[rm] * S.r[rs];
            if (op & (1u << 21))
                res += S.r[rn];
            if (rd != 15u)
                S.r[rd] = res;
            if (op & (1u << 20))
                set_nz(res);
            cyc += 2u;
            break;
        }
        if ((op & 0x0F8000F0u) == 0x00800090u) {
            /* UMULL / UMLAL / SMULL / SMLAL */
            u32 rdhi = (op >> 16) & 15u;
            u32 rdlo = (op >> 12) & 15u;
            u32 rs   = (op >> 8) & 15u;
            u32 rm   = op & 15u;
            u64 res;
            if (op & (1u << 22)) {
                s64 prod = (s64)(s32)S.r[rm] * (s64)(s32)S.r[rs];
                if (op & (1u << 21))
                    prod += (s64)(((u64)S.r[rdhi] << 32) | S.r[rdlo]);
                res = (u64)prod;
            } else {
                res = (u64)S.r[rm] * (u64)S.r[rs];
                if (op & (1u << 21))
                    res += ((u64)S.r[rdhi] << 32) | S.r[rdlo];
            }
            if (rdlo != 15u) S.r[rdlo] = (u32)res;
            if (rdhi != 15u) S.r[rdhi] = (u32)(res >> 32);
            if (op & (1u << 20)) {
                S.cpsr = (S.cpsr & ~(FLAG_N | FLAG_Z)) |
                         ((u32)(res >> 32) & FLAG_N) |
                         (res == 0 ? FLAG_Z : 0u);
            }
            cyc += 3u;
            break;
        }
        if ((op & 0x0E000090u) == 0x00000090u) {
            /* Halfword & Signed Data Transfer: STRH, LDRH, LDRSB, LDRSH */
            int pre  = (op >> 24) & 1;
            int up   = (op >> 23) & 1;
            int imm  = (op >> 22) & 1;
            int wb   = (op >> 21) & 1;
            int load = (op >> 20) & 1;
            u32 rn   = (op >> 16) & 15u;
            u32 rd   = (op >> 12) & 15u;
            u32 shop = (op >> 5) & 3u;
            u32 off  = imm ? (((op >> 4) & 0xF0u) | (op & 0xFu)) : S.r[op & 15u];
            u32 base = S.r[rn];
            u32 mod  = up ? (base + off) : (base - off);
            u32 addr = pre ? mod : base;

            if (load) {
                u32 val;
                if (shop == 1u) {
                    /* LDRH: misaligned odd address rotates 16-bit halfword right by 8 in 32-bit! */
                    u32 h = bus_read16_aligned(addr);
                    val = (addr & 1u) ? ror32(h, 8u) : h;
                } else if (shop == 2u) {
                    /* LDRSB */
                    val = (u32)(s32)(s8)bus_read8(addr);
                } else {
                    /* LDRSH: misaligned odd address sign-extends the single byte! */
                    if (addr & 1u)
                        val = (u32)(s32)(s8)bus_read8(addr);
                    else
                        val = (u32)(s32)(s16)bus_read16_aligned(addr);
                }
                if ((!pre || wb) && rn != 15u)
                    S.r[rn] = mod;
                S.r[rd] = val;
                if (rd == 15u) { S.r[15] &= ~3u; branched = 1; }
                cyc += 1u + S.ws_n16[(addr >> 24) & 15u];
            } else {
                /* STRH (stores PC + 12 if Rd == 15) */
                u32 val = (rd == 15u) ? (inst_pc + 12u) : S.r[rd];
                bus_write16_aligned(addr, (u16)val);
                if ((!pre || wb) && rn != 15u)
                    S.r[rn] = mod;
                cyc += S.ws_n16[(addr >> 24) & 15u];
            }
            break;
        }
        if ((op & 0x0F900000u) == 0x01000000u) {
            /* MRS / MSR (register) */
            if (op & (1u << 21)) {
                /* MSR (register) */
                u32 val = S.r[op & 15u];
                u32 mask = 0;
                if (op & (1u << 19)) mask |= 0xFF000000u;
                if (op & (1u << 18)) mask |= 0x00FF0000u;
                if (op & (1u << 17)) mask |= 0x0000FF00u;
                if ((op & (1u << 16)) && (S.cpsr & CPSR_MODE_MASK) != MODE_USR)
                    mask |= 0x000000FFu;
                if (op & (1u << 22)) {
                    int mi = mode_index(S.cpsr);
                    if (mi > 0)
                        S.spsr = (S.spsr & ~mask) | (val & mask);
                } else {
                    set_cpsr((S.cpsr & ~mask) | (val & mask));
                    update_irq_line();
                }
            } else {
                /* MRS */
                u32 rd = (op >> 12) & 15u;
                if (rd != 15u)
                    S.r[rd] = (op & (1u << 22)) ? S.spsr : S.cpsr;
            }
            break;
        }
        /* Fall through to Data Processing (register / shifted register) */
        /* fallthrough */
    case 1: { /* Data Processing & MSR immediate */
        if (top == 1u && (op & 0x0F900000u) == 0x03000000u) {
            if (op & (1u << 21)) {
                /* MSR (immediate) */
                u32 val = ror32(op & 0xFFu, ((op >> 8) & 15u) * 2u);
                u32 mask = 0;
                if (op & (1u << 19)) mask |= 0xFF000000u;
                if ((op & (1u << 16)) && (S.cpsr & CPSR_MODE_MASK) != MODE_USR)
                    mask |= 0x000000FFu;
                if (op & (1u << 22)) {
                    int mi = mode_index(S.cpsr);
                    if (mi > 0)
                        S.spsr = (S.spsr & ~mask) | (val & mask);
                } else {
                    set_cpsr((S.cpsr & ~mask) | (val & mask));
                    update_irq_line();
                }
            }
            break;
        }

        u32 alu_op = (op >> 21) & 15u;
        int set_s  = (op >> 20) & 1;
        u32 rn     = (op >> 16) & 15u;
        u32 rd     = (op >> 12) & 15u;
        u32 sc     = (S.cpsr & FLAG_C) ? 1u : 0u;
        u32 op1, op2;

        if (top == 1u) {
            u32 imm = op & 0xFFu;
            u32 rot = ((op >> 8) & 15u) * 2u;
            op1 = S.r[rn];
            if (rot == 0) {
                op2 = imm;
            } else {
                op2 = ror32(imm, rot);
                sc  = (op2 >> 31) & 1u;
            }
        } else if (op & 0x10u) {
            /* Register-specified shift: +1I cycle, PC reads as inst_pc + 12! */
            u32 rs_val = S.r[(op >> 8) & 15u];
            S.r[15] = inst_pc + 12u;
            op1 = S.r[rn];
            op2 = shift_reg(S.r[op & 15u], (op >> 5) & 3u, rs_val, &sc);
            cyc += 1u;
        } else {
            op1 = S.r[rn];
            op2 = shift_imm(S.r[op & 15u], (op >> 5) & 3u, (op >> 7) & 31u, &sc);
        }

        /* When Rd == 15 and S == 1, CPSR is restored from SPSR instead of normal flag update */
        int flag_s = (set_s && rd != 15u);
        u32 res = 0;
        int write_rd = 1;

        switch (alu_op) {
        case 0x0: res = op1 & op2; if (flag_s) set_nzc(res, sc); break;
        case 0x1: res = op1 ^ op2; if (flag_s) set_nzc(res, sc); break;
        case 0x2: res = alu_sub(op1, op2, flag_s); break;
        case 0x3: res = alu_sub(op2, op1, flag_s); break;
        case 0x4: res = alu_add(op1, op2, flag_s); break;
        case 0x5: res = alu_adc(op1, op2, (S.cpsr & FLAG_C) ? 1u : 0u, flag_s); break;
        case 0x6: res = alu_sbc(op1, op2, (S.cpsr & FLAG_C) ? 1u : 0u, flag_s); break;
        case 0x7: res = alu_sbc(op2, op1, (S.cpsr & FLAG_C) ? 1u : 0u, flag_s); break;
        case 0x8: res = op1 & op2; if (flag_s) set_nzc(res, sc); write_rd = 0; break;
        case 0x9: res = op1 ^ op2; if (flag_s) set_nzc(res, sc); write_rd = 0; break;
        case 0xA: (void)alu_sub(op1, op2, flag_s); write_rd = 0; break;
        case 0xB: (void)alu_add(op1, op2, flag_s); write_rd = 0; break;
        case 0xC: res = op1 | op2; if (flag_s) set_nzc(res, sc); break;
        case 0xD: res = op2;       if (flag_s) set_nzc(res, sc); break;
        case 0xE: res = op1 & ~op2; if (flag_s) set_nzc(res, sc); break;
        case 0xF: res = ~op2;      if (flag_s) set_nzc(res, sc); break;
        }

        if (rd == 15u) {
            if (set_s) {
                int mi = mode_index(S.cpsr);
                if (mi > 0)
                    set_cpsr(S.spsr);
                update_irq_line();
            }
            if (write_rd) {
                S.r[15] = (S.cpsr & CPSR_T) ? (res & ~1u) : (res & ~3u);
                branched = 1;
                cyc += 2u;
            }
        } else if (write_rd) {
            S.r[rd] = res;
        }
        break;
    }

    case 2:
    case 3: { /* Single Data Transfer: LDR / STR / LDRB / STRB */
        if (top == 3u && (op & 0x10u)) {
            cpu_take_undef(inst_pc + 4u);
            branched = 1;
            break;
        }
        int pre  = (op >> 24) & 1;
        int up   = (op >> 23) & 1;
        int byte = (op >> 22) & 1;
        int wb   = (op >> 21) & 1;
        int load = (op >> 20) & 1;
        u32 rn   = (op >> 16) & 15u;
        u32 rd   = (op >> 12) & 15u;
        u32 sc   = (S.cpsr & FLAG_C) ? 1u : 0u;
        u32 off  = (top == 2u) ? (op & 0xFFFu)
                               : shift_imm(S.r[op & 15u], (op >> 5) & 3u, (op >> 7) & 31u, &sc);
        u32 base = S.r[rn];
        u32 mod  = up ? (base + off) : (base - off);
        u32 addr = pre ? mod : base;

        if (load) {
            u32 val = byte ? (u32)bus_read8(addr)
                           : ror32(bus_read32_aligned(addr), (addr & 3u) * 8u);
            if ((!pre || wb) && rn != 15u)
                S.r[rn] = mod;
            S.r[rd] = val;
            if (rd == 15u) { S.r[15] &= ~3u; branched = 1; cyc += 2u; }
            cyc += 1u + (byte ? S.ws_n16[(addr >> 24) & 15u] : S.ws_n32[(addr >> 24) & 15u]);
        } else {
            u32 val = (rd == 15u) ? (inst_pc + 12u) : S.r[rd];
            if (byte) bus_write8(addr, (u8)val);
            else      bus_write32_aligned(addr, val);
            if ((!pre || wb) && rn != 15u)
                S.r[rn] = mod;
            cyc += byte ? S.ws_n16[(addr >> 24) & 15u] : S.ws_n32[(addr >> 24) & 15u];
        }
        break;
    }

    case 4: { /* Block Data Transfer: LDM / STM */
        int pre   = (op >> 24) & 1;
        int up    = (op >> 23) & 1;
        int psr_u = (op >> 22) & 1;
        int wb    = (op >> 21) & 1;
        int load  = (op >> 20) & 1;
        u32 rn    = (op >> 16) & 15u;
        u32 rlist = op & 0xFFFFu;
        u32 base  = S.r[rn];

        if (rlist == 0) {
            /* Hardware ARM7TDMI empty-rlist quirk: transfers R15, +/- 0x40 offset */
            u32 new_base = up ? (base + 0x40u) : (base - 0x40u);
            u32 addr;
            if (up) addr = pre ? (base + 4u) : base;
            else    addr = pre ? (base - 0x40u) : (base - 0x3Cu);
            if (wb && rn != 15u)
                S.r[rn] = new_base;
            if (load) {
                S.r[15] = bus_read32_aligned(addr) & ~3u;
                branched = 1;
            } else {
                bus_write32_aligned(addr, inst_pc + 12u);
            }
            cyc += 4u;
            break;
        }

        u32 count = popcnt16(rlist);
        u32 new_base = up ? (base + count * 4u) : (base - count * 4u);
        u32 addr;
        if (up) addr = pre ? (base + 4u) : base;
        else    addr = pre ? new_base : (new_base + 4u);

        int usr_bank = psr_u && !(load && (rlist & 0x8000u));

        if (load) {
            if (wb && rn != 15u)
                S.r[rn] = new_base;
            for (u32 m = rlist; m; m &= m - 1u) {
                int i = __builtin_ctz(m);
                u32 v = bus_read32_aligned(addr);
                addr += 4u;
                if (i == 15) {
                    if (psr_u) {
                        int mi = mode_index(S.cpsr);
                        if (mi > 0)
                            set_cpsr(S.spsr);
                        update_irq_line();
                        S.r[15] = (S.cpsr & CPSR_T) ? (v & ~1u) : (v & ~3u);
                    } else {
                        S.r[15] = v & ~3u;
                    }
                    branched = 1;
                } else if (usr_bank) {
                    write_usr_reg(i, v);
                } else {
                    S.r[i] = v;
                }
            }
            cyc += 1u + count * S.ws_s32[(base >> 24) & 15u];
        } else {
            int rn_is_first = ((rlist & ((1u << rn) - 1u)) == 0);
            for (u32 m = rlist; m; m &= m - 1u) {
                int i = __builtin_ctz(m);
                u32 v;
                if (i == 15)
                    v = inst_pc + 12u;
                else if (usr_bank)
                    v = read_usr_reg(i);
                else if ((u32)i == rn && wb && !rn_is_first)
                    v = new_base;
                else
                    v = S.r[i];
                bus_write32_aligned(addr, v);
                addr += 4u;
            }
            if (wb && rn != 15u)
                S.r[rn] = new_base;
            cyc += count * S.ws_s32[(base >> 24) & 15u];
        }
        break;
    }

    case 5: { /* B / BL */
        s32 disp = ((s32)(op << 8)) >> 6;
        if (op & (1u << 24))
            S.r[14] = inst_pc + 4u;
        u32 dest = (inst_pc + 8u + (u32)disp) & ~3u;
        S.r[15] = dest;
        branched = 1;
        cyc += 2u;
        if (!(op & (1u << 24)) && cond != 0xEu && dest < inst_pc) {
            s32 skip = arm_poll_skip(dest, inst_pc, S.cyc_left - target_left);
            if (skip > (s32)cyc)
                cyc = (u32)skip;
        }
        break;
    }

    case 7: /* SWI & internal BIOS trap */
        if (op & (1u << 24)) {
            if (inst_pc == 0x00000160u && op == BIOS_SWI_TRAP_INSN && S.using_hle_bios) {
                if (hle_swi_dispatch())
                    branched = 1;
            } else {
                cpu_take_swi(inst_pc + 4u);
                branched = 1;
                cyc += 2u;
            }
        }
        break;

    default:
        break;
    }

    if (!branched)
        S.r[15] = inst_pc + 4u;
    return cyc;
}

static u32 __attribute__((noinline)) step_thumb(u32 inst_pc, s32 target_left);

static u32 step_thumb(u32 inst_pc, s32 target_left)
{
    inst_pc &= ~1u;
    u16 op = fetch_thumb(inst_pc);
    u32 cyc = S.ws_s16[(inst_pc >> 24) & 15u];

    /* Unconditional idle branch `b .` (0xE7FE) fast-forward */
    if (op == 0xE7FEu) {
        if (S.tmr_pend) timers_flush();
        s32 rem = S.cyc_left - target_left;
        s32 skip = timers_next_event(rem);
        return (skip > (s32)cyc) ? (u32)skip : cyc;
    }

    /* Expose PC + 4 during Thumb execution */
    S.r[15] = inst_pc + 4u;
    int branched = 0;

    switch (op >> 13) {
    case 0:
        if (((op >> 11) & 3u) == 3u) {
            /* Format 2: ADD / SUB Rd, Rs, Rn/#imm3 */
            u32 rd = op & 7u;
            u32 rs = (op >> 3) & 7u;
            u32 v2 = (op & 0x0400u) ? ((op >> 6) & 7u) : S.r[(op >> 6) & 7u];
            S.r[rd] = (op & 0x0200u) ? alu_sub(S.r[rs], v2, 1) : alu_add(S.r[rs], v2, 1);
        } else {
            /* Format 1: LSL / LSR / ASR Rd, Rs, #imm5 */
            u32 rd  = op & 7u;
            u32 rs  = (op >> 3) & 7u;
            u32 amt = (op >> 6) & 31u;
            u32 sc  = (S.cpsr & FLAG_C) ? 1u : 0u;
            u32 res = shift_imm(S.r[rs], (op >> 11) & 3u, amt, &sc);
            S.r[rd] = res;
            set_nzc(res, sc);
        }
        break;

    case 1: { /* Format 3: MOV / CMP / ADD / SUB Rd, #imm8 */
        u32 rd  = (op >> 8) & 7u;
        u32 imm = op & 0xFFu;
        switch ((op >> 11) & 3u) {
        case 0: S.r[rd] = imm; set_nz(imm); break;
        case 1: (void)alu_sub(S.r[rd], imm, 1); break;
        case 2: S.r[rd] = alu_add(S.r[rd], imm, 1); break;
        case 3: S.r[rd] = alu_sub(S.r[rd], imm, 1); break;
        }
        break;
    }

    case 2:
        if ((op >> 10) == 0x10u) {
            /* Format 4: ALU operations */
            u32 rd = op & 7u;
            u32 rs = (op >> 3) & 7u;
            u32 a = S.r[rd], b = S.r[rs], res;
            u32 sc = (S.cpsr & FLAG_C) ? 1u : 0u;
            switch ((op >> 6) & 15u) {
            case 0x0: res = a & b; S.r[rd] = res; set_nz(res); break;
            case 0x1: res = a ^ b; S.r[rd] = res; set_nz(res); break;
            case 0x2: res = shift_reg(a, 0u, b, &sc); S.r[rd] = res; set_nzc(res, sc); cyc++; break;
            case 0x3: res = shift_reg(a, 1u, b, &sc); S.r[rd] = res; set_nzc(res, sc); cyc++; break;
            case 0x4: res = shift_reg(a, 2u, b, &sc); S.r[rd] = res; set_nzc(res, sc); cyc++; break;
            case 0x5: S.r[rd] = alu_adc(a, b, sc, 1); break;
            case 0x6: S.r[rd] = alu_sbc(a, b, sc, 1); break;
            case 0x7: res = shift_reg(a, 3u, b, &sc); S.r[rd] = res; set_nzc(res, sc); cyc++; break;
            case 0x8: set_nz(a & b); break;
            case 0x9: S.r[rd] = alu_sub(0u, b, 1); break;
            case 0xA: (void)alu_sub(a, b, 1); break;
            case 0xB: (void)alu_add(a, b, 1); break;
            case 0xC: res = a | b; S.r[rd] = res; set_nz(res); break;
            case 0xD: res = a * b; S.r[rd] = res; set_nz(res); cyc += 2u; break;
            case 0xE: res = a & ~b; S.r[rd] = res; set_nz(res); break;
            case 0xF: res = ~b; S.r[rd] = res; set_nz(res); break;
            }
        } else if ((op >> 10) == 0x11u) {
            /* Format 5: Hi-register ADD / CMP / MOV / BX */
            u32 rd = (op & 7u) | ((op >> 4) & 8u);
            u32 rs = (op >> 3) & 15u;
            u32 vs = (rs == 15u) ? ((inst_pc + 4u) & ~1u) : S.r[rs];
            switch ((op >> 8) & 3u) {
            case 0:
                S.r[rd] += vs;
                if (rd == 15u) { S.r[15] &= ~1u; branched = 1; cyc += 2u; }
                break;
            case 1:
                (void)alu_sub(S.r[rd], vs, 1);
                break;
            case 2:
                S.r[rd] = vs;
                if (rd == 15u) { S.r[15] &= ~1u; branched = 1; cyc += 2u; }
                break;
            case 3:
                if (rs == 15u)
                    vs = (inst_pc + 4u) & ~3u;
                if (vs & 1u) {
                    S.cpsr |= CPSR_T;
                    S.r[15] = vs & ~1u;
                } else {
                    S.cpsr &= ~CPSR_T;
                    S.r[15] = vs & ~3u;
                }
                branched = 1;
                cyc += 2u;
                break;
            }
        } else if ((op >> 11) == 0x09u) {
            /* Format 6: LDR Rd, [PC, #imm8*4] */
            u32 rd = (op >> 8) & 7u;
            u32 addr = ((inst_pc + 4u) & ~2u) + ((u32)(op & 0xFFu) << 2);
            S.r[rd] = bus_read32_aligned(addr);
            cyc += 1u + S.ws_n32[(addr >> 24) & 15u];
        } else if (!(op & 0x0200u)) {
            /* Format 7: STR / STRB / LDR / LDRB [Rb, Ro] */
            u32 rd = op & 7u;
            u32 rb = (op >> 3) & 7u;
            u32 ro = (op >> 6) & 7u;
            u32 addr = S.r[rb] + S.r[ro];
            switch ((op >> 10) & 3u) {
            case 0: bus_write32_aligned(addr, S.r[rd]); cyc += S.ws_n32[(addr >> 24) & 15u]; break;
            case 1: bus_write8(addr, (u8)S.r[rd]);      cyc += S.ws_n16[(addr >> 24) & 15u]; break;
            case 2: S.r[rd] = ror32(bus_read32_aligned(addr), (addr & 3u) * 8u); cyc += 1u + S.ws_n32[(addr >> 24) & 15u]; break;
            case 3: S.r[rd] = bus_read8(addr);          cyc += 1u + S.ws_n16[(addr >> 24) & 15u]; break;
            }
        } else {
            /* Format 8: STRH / LDSB / LDRH / LDSH [Rb, Ro] */
            u32 rd = op & 7u;
            u32 rb = (op >> 3) & 7u;
            u32 ro = (op >> 6) & 7u;
            u32 addr = S.r[rb] + S.r[ro];
            switch ((op >> 10) & 3u) {
            case 0: bus_write16_aligned(addr, (u16)S.r[rd]); break;
            case 1: S.r[rd] = (u32)(s32)(s8)bus_read8(addr); break;
            case 2: {
                u32 h = bus_read16_aligned(addr);
                S.r[rd] = (addr & 1u) ? ror32(h, 8u) : h;
                break;
            }
            case 3:
                S.r[rd] = (addr & 1u) ? (u32)(s32)(s8)bus_read8(addr)
                                      : (u32)(s32)(s16)bus_read16_aligned(addr);
                break;
            }
            cyc += 1u + S.ws_n16[(addr >> 24) & 15u];
        }
        break;

    case 3: { /* Format 9: STR / LDR / STRB / LDRB [Rb, #imm5] */
        u32 rd  = op & 7u;
        u32 rb  = (op >> 3) & 7u;
        u32 imm = (op >> 6) & 31u;
        switch ((op >> 11) & 3u) {
        case 0: { u32 a = S.r[rb] + (imm << 2); bus_write32_aligned(a, S.r[rd]); cyc += S.ws_n32[(a >> 24) & 15u]; break; }
        case 1: { u32 a = S.r[rb] + (imm << 2); S.r[rd] = ror32(bus_read32_aligned(a), (a & 3u) * 8u); cyc += 1u + S.ws_n32[(a >> 24) & 15u]; break; }
        case 2: { u32 a = S.r[rb] + imm; bus_write8(a, (u8)S.r[rd]); cyc += S.ws_n16[(a >> 24) & 15u]; break; }
        case 3: { u32 a = S.r[rb] + imm; S.r[rd] = bus_read8(a); cyc += 1u + S.ws_n16[(a >> 24) & 15u]; break; }
        }
        break;
    }

    case 4:
        if (!(op & 0x1000u)) {
            /* Format 10: STRH / LDRH [Rb, #imm5*2] */
            u32 rd   = op & 7u;
            u32 rb   = (op >> 3) & 7u;
            u32 addr = S.r[rb] + (((op >> 6) & 31u) << 1);
            if (op & 0x0800u) {
                u32 h = bus_read16_aligned(addr);
                S.r[rd] = (addr & 1u) ? ror32(h, 8u) : h;
                cyc += 1u + S.ws_n16[(addr >> 24) & 15u];
            } else {
                bus_write16_aligned(addr, (u16)S.r[rd]);
                cyc += S.ws_n16[(addr >> 24) & 15u];
            }
        } else {
            /* Format 11: SP-relative STR / LDR */
            u32 rd   = (op >> 8) & 7u;
            u32 addr = S.r[13] + ((u32)(op & 0xFFu) << 2);
            if (op & 0x0800u) {
                S.r[rd] = ror32(bus_read32_aligned(addr), (addr & 3u) * 8u);
                cyc += 1u + S.ws_n32[(addr >> 24) & 15u];
            } else {
                bus_write32_aligned(addr, S.r[rd]);
                cyc += S.ws_n32[(addr >> 24) & 15u];
            }
        }
        break;

    case 5:
        if (!(op & 0x1000u)) {
            /* Format 12: ADD Rd, PC/SP, #imm8*4 */
            u32 rd = (op >> 8) & 7u;
            u32 base = (op & 0x0800u) ? S.r[13] : ((inst_pc + 4u) & ~2u);
            S.r[rd] = base + ((u32)(op & 0xFFu) << 2);
        } else if (!(op & 0x0400u)) {
            /* Format 13: ADD SP, #+-imm7*4 */
            u32 off = (u32)(op & 0x7Fu) << 2;
            S.r[13] = (op & 0x0080u) ? (S.r[13] - off) : (S.r[13] + off);
        } else {
            /* Format 14: PUSH / POP */
            u32 rlist = op & 0xFFu;
            int pbit  = (op >> 8) & 1;
            if (op & 0x0800u) {
                /* POP */
                if (!rlist && !pbit) {
                    S.r[15] = bus_read32_aligned(S.r[13]) & ~1u;
                    S.r[13] += 0x40u;
                    branched = 1;
                    break;
                }
                u32 addr = S.r[13];
                for (int i = 0; i < 8; i++) {
                    if (rlist & (1u << i)) {
                        S.r[i] = bus_read32_aligned(addr);
                        addr += 4u;
                        cyc++;
                    }
                }
                if (pbit) {
                    S.r[15] = bus_read32_aligned(addr) & ~1u;
                    addr += 4u;
                    branched = 1;
                    cyc += 2u;
                }
                S.r[13] = addr;
            } else {
                /* PUSH */
                if (!rlist && !pbit) {
                    S.r[13] -= 0x40u;
                    bus_write32_aligned(S.r[13], inst_pc + 6u);
                    break;
                }
                u32 cnt = (u32)pbit;
                for (u32 m = rlist; m; m &= m - 1u) cnt++;
                u32 addr = S.r[13] - cnt * 4u;
                S.r[13] = addr;
                for (int i = 0; i < 8; i++) {
                    if (rlist & (1u << i)) {
                        bus_write32_aligned(addr, S.r[i]);
                        addr += 4u;
                        cyc++;
                    }
                }
                if (pbit) {
                    bus_write32_aligned(addr, S.r[14]);
                    cyc++;
                }
            }
        }
        break;

    case 6:
        if (!(op & 0x1000u)) {
            /* Format 15: STMIA / LDMIA Rb!, {rlist} */
            u32 rb    = (op >> 8) & 7u;
            u32 rlist = op & 0xFFu;
            u32 base  = S.r[rb];
            if (rlist == 0) {
                S.r[rb] = base + 0x40u;
                if (op & 0x0800u) {
                    S.r[15] = bus_read32_aligned(base) & ~1u;
                    branched = 1;
                } else {
                    bus_write32_aligned(base, inst_pc + 6u);
                }
                cyc += 4u;
                break;
            }
            u32 cnt = 0;
            for (u32 m = rlist; m; m &= m - 1u) cnt++;
            u32 new_base = base + cnt * 4u;
            u32 addr = base;
            if (op & 0x0800u) {
                S.r[rb] = new_base;
                for (int i = 0; i < 8; i++) {
                    if (rlist & (1u << i)) {
                        S.r[i] = bus_read32_aligned(addr);
                        addr += 4u;
                        cyc++;
                    }
                }
            } else {
                int rb_first = ((rlist & ((1u << rb) - 1u)) == 0);
                for (int i = 0; i < 8; i++) {
                    if (rlist & (1u << i)) {
                        u32 v = ((u32)i == rb && !rb_first) ? new_base : S.r[i];
                        bus_write32_aligned(addr, v);
                        addr += 4u;
                        cyc++;
                    }
                }
                S.r[rb] = new_base;
            }
        } else {
            u32 cond = (op >> 8) & 15u;
            if (cond == 0xFu) {
                cpu_take_swi(inst_pc + 2u);
                branched = 1;
                cyc += 2u;
            } else if (cond == 0xEu) {
                cpu_take_undef(inst_pc + 2u);
                branched = 1;
            } else if (M->cond_lut[cond][S.cpsr >> 28]) {
                s32 disp = (s32)(s8)(op & 0xFFu) << 1;
                u32 dest = (inst_pc + 4u + (u32)disp) & ~1u;
                S.r[15] = dest;
                branched = 1;
                cyc += 2u;
                if (dest < inst_pc) {
                    s32 skip = thumb_poll_skip(dest, inst_pc, S.cyc_left - target_left);
                    if (skip > (s32)cyc)
                        cyc = (u32)skip;
                }
            }
        }
        break;

    case 7: {
        u32 sub = (op >> 11) & 3u;
        if (sub == 0u) {
            /* Format 18: Unconditional B offset11 */
            s32 disp = ((s32)((u32)op << 21)) >> 20;
            S.r[15] = (inst_pc + 4u + (u32)disp) & ~1u;
            branched = 1;
            cyc += 2u;
        } else if (sub == 2u) {
            /* Format 19: BL prefix */
            s32 hi = ((s32)((u32)op << 21)) >> 9;
            S.r[14] = (inst_pc + 4u) + (u32)hi;
        } else if (sub == 3u) {
            /* Format 19: BL suffix */
            u32 target = (S.r[14] + (((u32)op & 0x7FFu) << 1)) & ~1u;
            S.r[14] = (inst_pc + 2u) | 1u;
            S.r[15] = target;
            branched = 1;
            cyc += 2u;
        }
        break;
    }
    }

    if (!branched)
        S.r[15] = inst_pc + 2u;
    return cyc;
}

typedef u16 __attribute__((may_alias)) u16_alias;
typedef u32 __attribute__((may_alias)) u32_alias;

static const u16 thumb_cond_mask[16] = {
    0xF0F0u, 0x0F0Fu, 0xCCCCu, 0x3333u,
    0xFF00u, 0x00FFu, 0xAAAAu, 0x5555u,
    0x0C0Cu, 0xF3F3u, 0xAA55u, 0x55AAu,
    0x0A05u, 0xF5FAu, 0xFFFFu, 0xFFFFu
};

INLINE u32 cpsr_nz(u32 cpsr, u32 res)
{
    return (cpsr & ~(FLAG_N | FLAG_Z)) | (res & FLAG_N) | ((u32)(res == 0u) << 30);
}

INLINE u32 cpsr_nzc(u32 cpsr, u32 res, u32 c)
{
    return (cpsr & ~(FLAG_N | FLAG_Z | FLAG_C)) | (res & FLAG_N) |
           ((u32)(res == 0u) << 30) | ((c & 1u) << 29);
}

INLINE u32 cpsr_add(u32 cpsr, u32 a, u32 b, u32 *out)
{
    u32 res = a + b;
    *out = res;
    return (cpsr & 0x0FFFFFFFu) | (res & FLAG_N) | ((u32)(res == 0u) << 30) |
           ((u32)(res < a) << 29) | (((~(a ^ b) & (a ^ res)) >> 3) & FLAG_V);
}

INLINE u32 cpsr_sub(u32 cpsr, u32 a, u32 b, u32 *out)
{
    u32 res = a - b;
    *out = res;
    return (cpsr & 0x0FFFFFFFu) | (res & FLAG_N) | ((u32)(res == 0u) << 30) |
           ((u32)(a >= b) << 29) | ((((a ^ b) & (a ^ res)) >> 3) & FLAG_V);
}

INLINE u32 cpsr_adc(u32 cpsr, u32 a, u32 b, u32 cin, u32 *out)
{
    u32 res = a + b + cin;
    u32 c = cin ? (res <= a) : (res < a);
    *out = res;
    return (cpsr & 0x0FFFFFFFu) | (res & FLAG_N) | ((u32)(res == 0u) << 30) |
           (c << 29) | (((~(a ^ b) & (a ^ res)) >> 3) & FLAG_V);
}

INLINE u32 cpsr_sbc(u32 cpsr, u32 a, u32 b, u32 cin, u32 *out)
{
    u32 res = a - b - (1u - cin);
    u32 c = cin ? (a >= b) : (a > b);
    *out = res;
    return (cpsr & 0x0FFFFFFFu) | (res & FLAG_N) | ((u32)(res == 0u) << 30) |
           (c << 29) | ((((a ^ b) & (a ^ res)) >> 3) & FLAG_V);
}

#ifndef HOST_EXTRA
static u32 __attribute__((noinline)) shift_reg_noinline(u32 val, u32 type, u32 amt, u32 *carry)
{
    return shift_reg(val, type, amt, carry);
}

/* Fast Thumb slice: direct u16 instruction pointer, register-resident CPSR and cycle budget,
   64-way single-dispatch table, and inline IWRAM/EWRAM/ROM data accesses; cold/MMIO cases
   punt cleanly to step_thumb so the hot loop stays small inside the 16 KB I-cache. */
static int __attribute__((noinline)) run_thumb_slice(s32 target_left)
{
    u32 *const r = S.r;
    u8 *const iwram = M->iwram;
    u8 *const ewram = M->ewram;
    const u8 *const rom = S.rom;
    const u32 rom_size = S.rom_size;

    u32 cpsr = S.cpsr;
    s32 cyc_left = S.cyc_left;
    s32 start_cyc = cyc_left;
    s32 stop_left = target_left;
    if (S.active_timers && S.tmr_next_cyc > stop_left)
        stop_left = S.tmr_next_cyc;

    u32 pc = r[15] & ~1u;
    u32 last_op = 0, prev_op = 0;
    int ran = 0, had_prev = 0;

    const u16_alias *ip_base;
    const u16_alias *ip;
    const u16_alias *ip_end;
    u32 pc_base;
    u32 reg_bytes;
    u32 fetch_cyc;
    u32 ws_n32_pc;

rebase:
    {
        u32 reg = pc >> 24;
        if (reg >= 0x08u && reg <= 0x0Cu) {
            u32 off = pc & 0x01FFFFFEu;
            u32 lim = rom_size & ~1u;
            if (reg == 0x0Cu && lim > 0x01000000u)
                lim = 0x01000000u;
            if (off >= lim)
                goto unmapped;
            ip_base   = (const u16_alias *)rom;
            ip        = ip_base + (off >> 1);
            ip_end    = ip_base + (lim >> 1);
            pc_base   = pc & 0xFE000000u;
            reg_bytes = lim;
            fetch_cyc = S.ws_s16[reg];
            ws_n32_pc = S.ws_n32[reg];
        } else if (reg == 0x03u) {
            u32 off   = pc & 0x7FFEu;
            ip_base   = (const u16_alias *)iwram;
            ip        = ip_base + (off >> 1);
            ip_end    = ip_base + (0x8000u >> 1);
            pc_base   = pc & 0xFFFF8000u;
            reg_bytes = 0x8000u;
            fetch_cyc = S.ws_s16[3];
            ws_n32_pc = S.ws_n32[3];
        } else if (reg == 0x02u) {
            u32 off   = pc & 0x3FFFEu;
            ip_base   = (const u16_alias *)ewram;
            ip        = ip_base + (off >> 1);
            ip_end    = ip_base + (0x40000u >> 1);
            pc_base   = pc & 0xFFFC0000u;
            reg_bytes = 0x40000u;
            fetch_cyc = S.ws_s16[2];
            ws_n32_pc = S.ws_n32[2];
        } else {
        unmapped:
            if (!ran)
                return 0;
            goto exit_with_pc;
        }
    }

    while (cyc_left > stop_left) {
        if (__builtin_expect(ip >= ip_end, 0)) {
            pc = pc_base + (u32)((const u8 *)ip - (const u8 *)ip_base);
            goto rebase;
        }
        prev_op = last_op;
        had_prev = ran;
        u32 op = *ip++;
        last_op = op;
        ran = 1;
        u32 cyc = fetch_cyc;
        u32 addr, rd, val;

        switch (op >> 10) {
        case 0x00: case 0x01: { /* LSL Rd, Rs, #imm5 */
            u32 d = op & 7u, v = r[(op >> 3) & 7u], amt = (op >> 6) & 31u;
            if (amt == 0u) {
                r[d] = v;
                cpsr = cpsr_nz(cpsr, v);
            } else {
                u32 sc = (v >> (32u - amt)) & 1u;
                u32 res = v << amt;
                r[d] = res;
                cpsr = cpsr_nzc(cpsr, res, sc);
            }
            break;
        }
        case 0x02: case 0x03: { /* LSR Rd, Rs, #imm5 */
            u32 d = op & 7u, v = r[(op >> 3) & 7u], amt = (op >> 6) & 31u;
            u32 sc, res;
            if (amt == 0u) { sc = v >> 31; res = 0u; }
            else           { sc = (v >> (amt - 1u)) & 1u; res = v >> amt; }
            r[d] = res;
            cpsr = cpsr_nzc(cpsr, res, sc);
            break;
        }
        case 0x04: case 0x05: { /* ASR Rd, Rs, #imm5 */
            u32 d = op & 7u, v = r[(op >> 3) & 7u], amt = (op >> 6) & 31u;
            u32 sc, res;
            if (amt == 0u) { sc = v >> 31; res = (u32)((s32)v >> 31); }
            else           { sc = (v >> (amt - 1u)) & 1u; res = (u32)((s32)v >> amt); }
            r[d] = res;
            cpsr = cpsr_nzc(cpsr, res, sc);
            break;
        }
        case 0x06: { /* ADD / SUB Rd, Rs, Rn */
            u32 d = op & 7u, a = r[(op >> 3) & 7u], b = r[(op >> 6) & 7u];
            cpsr = (op & 0x0200u) ? cpsr_sub(cpsr, a, b, &r[d]) : cpsr_add(cpsr, a, b, &r[d]);
            break;
        }
        case 0x07: { /* ADD / SUB Rd, Rs, #imm3 */
            u32 d = op & 7u, a = r[(op >> 3) & 7u], b = (op >> 6) & 7u;
            cpsr = (op & 0x0200u) ? cpsr_sub(cpsr, a, b, &r[d]) : cpsr_add(cpsr, a, b, &r[d]);
            break;
        }
        case 0x08: case 0x09: { /* MOV Rd, #imm8 */
            u32 d = (op >> 8) & 7u, imm = op & 0xFFu;
            r[d] = imm;
            cpsr = (cpsr & ~(FLAG_N | FLAG_Z)) | ((u32)(imm == 0u) << 30);
            break;
        }
        case 0x0A: case 0x0B: { /* CMP Rd, #imm8 */
            u32 dummy;
            cpsr = cpsr_sub(cpsr, r[(op >> 8) & 7u], op & 0xFFu, &dummy);
            break;
        }
        case 0x0C: case 0x0D: { /* ADD Rd, #imm8 */
            u32 d = (op >> 8) & 7u;
            cpsr = cpsr_add(cpsr, r[d], op & 0xFFu, &r[d]);
            break;
        }
        case 0x0E: case 0x0F: { /* SUB Rd, #imm8 */
            u32 d = (op >> 8) & 7u;
            cpsr = cpsr_sub(cpsr, r[d], op & 0xFFu, &r[d]);
            break;
        }
        case 0x10: { /* Format 4: ALU */
            u32 d = op & 7u, a = r[d], b = r[(op >> 3) & 7u], res, dummy;
            u32 sc = (cpsr >> 29) & 1u;
            switch ((op >> 6) & 15u) {
            case 0x0: res = a & b; r[d] = res; cpsr = cpsr_nz(cpsr, res); break;
            case 0x1: res = a ^ b; r[d] = res; cpsr = cpsr_nz(cpsr, res); break;
            case 0x2: res = shift_reg_noinline(a, 0u, b, &sc); r[d] = res; cpsr = cpsr_nzc(cpsr, res, sc); cyc++; break;
            case 0x3: res = shift_reg_noinline(a, 1u, b, &sc); r[d] = res; cpsr = cpsr_nzc(cpsr, res, sc); cyc++; break;
            case 0x4: res = shift_reg_noinline(a, 2u, b, &sc); r[d] = res; cpsr = cpsr_nzc(cpsr, res, sc); cyc++; break;
            case 0x5: cpsr = cpsr_adc(cpsr, a, b, sc, &r[d]); break;
            case 0x6: cpsr = cpsr_sbc(cpsr, a, b, sc, &r[d]); break;
            case 0x7: res = shift_reg_noinline(a, 3u, b, &sc); r[d] = res; cpsr = cpsr_nzc(cpsr, res, sc); cyc++; break;
            case 0x8: cpsr = cpsr_nz(cpsr, a & b); break;
            case 0x9: cpsr = cpsr_sub(cpsr, 0u, b, &r[d]); break;
            case 0xA: cpsr = cpsr_sub(cpsr, a, b, &dummy); break;
            case 0xB: cpsr = cpsr_add(cpsr, a, b, &dummy); break;
            case 0xC: res = a | b; r[d] = res; cpsr = cpsr_nz(cpsr, res); break;
            case 0xD: res = a * b; r[d] = res; cpsr = cpsr_nz(cpsr, res); cyc += 2u; break;
            case 0xE: res = a & ~b; r[d] = res; cpsr = cpsr_nz(cpsr, res); break;
            case 0xF: res = ~b; r[d] = res; cpsr = cpsr_nz(cpsr, res); break;
            }
            break;
        }
        case 0x11: { /* Format 5: Hi-reg ADD / CMP / MOV / BX */
            u32 next_pc = pc_base + (u32)((const u8 *)ip - (const u8 *)ip_base);
            r[15] = next_pc + 2u;
            u32 d = (op & 7u) | ((op >> 4) & 8u);
            u32 s = (op >> 3) & 15u;
            u32 vs = r[s];
            switch ((op >> 8) & 3u) {
            case 0:
                r[d] += vs;
                if (d == 15u) {
                    cyc += 2u;
                    cyc_left -= (s32)cyc;
                    pc = r[15] & ~1u;
                    goto branch_pc;
                }
                break;
            case 1: {
                u32 dummy;
                cpsr = cpsr_sub(cpsr, r[d], vs, &dummy);
                break;
            }
            case 2:
                r[d] = vs;
                if (d == 15u) {
                    cyc += 2u;
                    cyc_left -= (s32)cyc;
                    pc = vs & ~1u;
                    goto branch_pc;
                }
                break;
            case 3:
                if (s == 15u)
                    vs &= ~3u;
                cyc += 2u;
                cyc_left -= (s32)cyc;
                if (vs & 1u) {
                    pc = vs & ~1u;
                    goto branch_pc;
                }
                cpsr &= ~CPSR_T;
                pc = vs & ~3u;
                goto exit_with_pc;
            }
            break;
        }
        case 0x12: case 0x13: { /* Format 6: LDR Rd, [PC, #imm8*4] */
            u32 next_pc = pc_base + (u32)((const u8 *)ip - (const u8 *)ip_base);
            addr = ((next_pc + 2u) & ~2u) + ((op & 0xFFu) << 2);
            u32 aoff = addr - pc_base;
            if (__builtin_expect(reg_bytes >= 4u && aoff <= reg_bytes - 4u, 1)) {
                r[(op >> 8) & 7u] = *(const u32_alias *)((const u8 *)ip_base + aoff);
                cyc += 1u + ws_n32_pc;
                break;
            }
            goto slow_step;
        }
        case 0x14: /* STR / STRH Rd, [Rb, Ro] */
            rd = op & 7u;
            addr = r[(op >> 3) & 7u] + r[(op >> 6) & 7u];
            val = r[rd];
            if (op & 0x0200u) { cyc++; goto do_strh; }
            goto do_str32;
        case 0x15: /* STRB / LDSB Rd, [Rb, Ro] */
            rd = op & 7u;
            addr = r[(op >> 3) & 7u] + r[(op >> 6) & 7u];
            if (!(op & 0x0200u)) { val = r[rd]; goto do_strb; }
            {
                u32 top = addr >> 24;
                if (top == 0x03u) { r[rd] = (u32)(s32)(s8)iwram[addr & 0x7FFFu]; cyc += 2u; break; }
                if (top == 0x02u) { r[rd] = (u32)(s32)(s8)ewram[addr & 0x3FFFFu]; cyc += 4u; break; }
                if (top - 0x08u <= 1u && (addr & 0x01FFFFFFu) < rom_size) {
                    r[rd] = (u32)(s32)(s8)rom[addr & 0x01FFFFFFu];
                    cyc += 1u + S.ws_n16[8];
                    break;
                }
                goto slow_step;
            }
        case 0x16: /* LDR / LDRH Rd, [Rb, Ro] */
            rd = op & 7u;
            addr = r[(op >> 3) & 7u] + r[(op >> 6) & 7u];
            if (op & 0x0200u) goto do_ldrh;
            goto do_ldr32;
        case 0x17: /* LDRB / LDSH Rd, [Rb, Ro] */
            rd = op & 7u;
            addr = r[(op >> 3) & 7u] + r[(op >> 6) & 7u];
            if (!(op & 0x0200u)) goto do_ldrb;
            if (!(addr & 1u)) {
                u32 top = addr >> 24;
                if (top == 0x03u) { r[rd] = (u32)(s32)(s16)*(const u16_alias *)(iwram + (addr & 0x7FFEu)); cyc += 2u; break; }
                if (top == 0x02u) { r[rd] = (u32)(s32)(s16)*(const u16_alias *)(ewram + (addr & 0x3FFFEu)); cyc += 4u; break; }
                if (top - 0x08u <= 1u && (addr & 0x01FFFFFEu) + 2u <= rom_size) {
                    r[rd] = (u32)(s32)(s16)*(const u16_alias *)(rom + (addr & 0x01FFFFFEu));
                    cyc += 1u + S.ws_n16[8];
                    break;
                }
            }
            goto slow_step;
        case 0x18: case 0x19: /* STR Rd, [Rb, #imm5*4] */
            rd = op & 7u;
            addr = r[(op >> 3) & 7u] + (((op >> 6) & 31u) << 2);
            val = r[rd];
            goto do_str32;
        case 0x1A: case 0x1B: /* LDR Rd, [Rb, #imm5*4] */
            rd = op & 7u;
            addr = r[(op >> 3) & 7u] + (((op >> 6) & 31u) << 2);
            goto do_ldr32;
        case 0x1C: case 0x1D: /* STRB Rd, [Rb, #imm5] */
            rd = op & 7u;
            addr = r[(op >> 3) & 7u] + ((op >> 6) & 31u);
            val = r[rd];
            goto do_strb;
        case 0x1E: case 0x1F: /* LDRB Rd, [Rb, #imm5] */
            rd = op & 7u;
            addr = r[(op >> 3) & 7u] + ((op >> 6) & 31u);
            goto do_ldrb;
        case 0x20: case 0x21: /* STRH Rd, [Rb, #imm5*2] */
            rd = op & 7u;
            addr = r[(op >> 3) & 7u] + (((op >> 6) & 31u) << 1);
            val = r[rd];
            goto do_strh;
        case 0x22: case 0x23: /* LDRH Rd, [Rb, #imm5*2] */
            rd = op & 7u;
            addr = r[(op >> 3) & 7u] + (((op >> 6) & 31u) << 1);
            goto do_ldrh;
        case 0x24: case 0x25: /* STR Rd, [SP, #imm8*4] */
            rd = (op >> 8) & 7u;
            addr = r[13] + ((op & 0xFFu) << 2);
            val = r[rd];
            goto do_str32;
        case 0x26: case 0x27: /* LDR Rd, [SP, #imm8*4] */
            rd = (op >> 8) & 7u;
            addr = r[13] + ((op & 0xFFu) << 2);
            goto do_ldr32;

        do_str32: {
            u32 top = addr >> 24;
            if (top == 0x03u) { *(u32_alias *)(iwram + (addr & 0x7FFCu)) = val; cyc += 1u; break; }
            if (top == 0x02u) { *(u32_alias *)(ewram + (addr & 0x3FFFCu)) = val; cyc += 6u; break; }
            if (top - 0x05u <= 2u) { bus_write32_slow(addr, val); cyc += S.ws_n32[top]; break; }
            goto slow_step;
        }
        do_ldr32: {
            u32 top = addr >> 24, v;
            if (top == 0x03u) {
                v = *(const u32_alias *)(iwram + (addr & 0x7FFCu));
                cyc += 2u;
            } else if (top == 0x02u) {
                v = *(const u32_alias *)(ewram + (addr & 0x3FFFCu));
                cyc += 7u;
            } else if (top - 0x08u <= 1u && (addr & 0x01FFFFFCu) + 4u <= rom_size) {
                v = *(const u32_alias *)(rom + (addr & 0x01FFFFFCu));
                cyc += 1u + S.ws_n32[8];
            } else if (top - 0x05u <= 2u) {
                v = bus_read32_slow(addr);
                cyc += 1u + S.ws_n32[top];
            } else {
                goto slow_step;
            }
            r[rd] = ror32(v, (addr & 3u) << 3);
            break;
        }
        do_strb: {
            u32 top = addr >> 24;
            if (top == 0x03u) { iwram[addr & 0x7FFFu] = (u8)val; cyc += 1u; break; }
            if (top == 0x02u) { ewram[addr & 0x3FFFFu] = (u8)val; cyc += 3u; break; }
            if (top - 0x05u <= 2u) { bus_write8(addr, (u8)val); cyc += 1u; break; }
            goto slow_step;
        }
        do_ldrb: {
            u32 top = addr >> 24;
            if (top == 0x03u) { r[rd] = iwram[addr & 0x7FFFu]; cyc += 2u; break; }
            if (top == 0x02u) { r[rd] = ewram[addr & 0x3FFFFu]; cyc += 4u; break; }
            if (top - 0x08u <= 1u && (addr & 0x01FFFFFFu) < rom_size) {
                r[rd] = rom[addr & 0x01FFFFFFu];
                cyc += 1u + S.ws_n16[8];
                break;
            }
            if (top - 0x05u <= 2u) {
                u16 h = bus_read16_slow(addr & ~1u);
                r[rd] = (h >> ((addr & 1u) << 3)) & 0xFFu;
                cyc += 2u;
                break;
            }
            goto slow_step;
        }
        do_strh: {
            u32 top = addr >> 24;
            if (top == 0x03u) { *(u16_alias *)(iwram + (addr & 0x7FFEu)) = (u16)val; cyc += 1u; break; }
            if (top == 0x02u) { *(u16_alias *)(ewram + (addr & 0x3FFFEu)) = (u16)val; cyc += 3u; break; }
            if (top - 0x05u <= 2u) { bus_write16_slow(addr, (u16)val); cyc += 1u; break; }
            goto slow_step;
        }
        do_ldrh: {
            u32 top = addr >> 24, h;
            if (top == 0x03u) {
                h = *(const u16_alias *)(iwram + (addr & 0x7FFEu));
                cyc += 2u;
            } else if (top == 0x02u) {
                h = *(const u16_alias *)(ewram + (addr & 0x3FFFEu));
                cyc += 4u;
            } else if (top - 0x08u <= 1u && (addr & 0x01FFFFFEu) + 2u <= rom_size) {
                h = *(const u16_alias *)(rom + (addr & 0x01FFFFFEu));
                cyc += 1u + S.ws_n16[8];
            } else if (top - 0x05u <= 2u) {
                h = bus_read16_slow(addr);
                cyc += 2u;
            } else {
                goto slow_step;
            }
            r[rd] = (addr & 1u) ? ror32(h, 8u) : h;
            break;
        }

        case 0x28: case 0x29: { /* ADD Rd, PC, #imm8*4 */
            u32 next_pc = pc_base + (u32)((const u8 *)ip - (const u8 *)ip_base);
            r[(op >> 8) & 7u] = ((next_pc + 2u) & ~2u) + ((op & 0xFFu) << 2);
            break;
        }
        case 0x2A: case 0x2B: /* ADD Rd, SP, #imm8*4 */
            r[(op >> 8) & 7u] = r[13] + ((op & 0xFFu) << 2);
            break;
        case 0x2C: case 0x2E: { /* ADD SP, #+-imm7*4 */
            u32 off = (op & 0x7Fu) << 2;
            r[13] = (op & 0x0080u) ? (r[13] - off) : (r[13] + off);
            break;
        }
        case 0x2D: { /* PUSH */
            u32 rlist = op & 0xFFu, pbit = (op >> 8) & 1u;
            u32 cnt = popcnt16(rlist) + pbit;
            if (__builtin_expect(!cnt, 0))
                goto slow_step;
            u32 a = r[13] - cnt * 4u;
            if (__builtin_expect(a - 0x03000000u >= 0x00FFFFDCu, 0))
                goto slow_step;
            r[13] = a;
            for (u32 m = rlist; m; m &= m - 1u) {
                *(u32_alias *)(iwram + (a & 0x7FFCu)) = r[__builtin_ctz(m)];
                a += 4u;
            }
            if (pbit)
                *(u32_alias *)(iwram + (a & 0x7FFCu)) = r[14];
            cyc += cnt;
            break;
        }
        case 0x2F: { /* POP */
            u32 rlist = op & 0xFFu, pbit = (op >> 8) & 1u;
            if (__builtin_expect(!rlist && !pbit, 0))
                goto slow_step;
            u32 a = r[13];
            if (__builtin_expect(a - 0x03000000u >= 0x00FFFFDCu, 0))
                goto slow_step;
            for (u32 m = rlist; m; m &= m - 1u) {
                r[__builtin_ctz(m)] = *(const u32_alias *)(iwram + (a & 0x7FFCu));
                a += 4u;
                cyc++;
            }
            if (pbit) {
                pc = *(const u32_alias *)(iwram + (a & 0x7FFCu)) & ~1u;
                r[13] = a + 4u;
                cyc += 2u;
                cyc_left -= (s32)cyc;
                goto branch_pc;
            }
            r[13] = a;
            break;
        }
        case 0x30: case 0x31: { /* STMIA Rb!, {rlist} */
            u32 rb = (op >> 8) & 7u, rlist = op & 0xFFu, base = r[rb];
            if (__builtin_expect(!rlist || base - 0x03000000u >= 0x00FFFFDCu, 0))
                goto slow_step;
            u32 cnt = popcnt16(rlist), new_base = base + cnt * 4u, a = base;
            int rb_first = ((rlist & ((1u << rb) - 1u)) == 0u);
            for (u32 m = rlist; m; m &= m - 1u) {
                int i = __builtin_ctz(m);
                *(u32_alias *)(iwram + (a & 0x7FFCu)) = ((u32)i == rb && !rb_first) ? new_base : r[i];
                a += 4u;
            }
            r[rb] = new_base;
            cyc += cnt;
            break;
        }
        case 0x32: case 0x33: { /* LDMIA Rb!, {rlist} */
            u32 rb = (op >> 8) & 7u, rlist = op & 0xFFu, base = r[rb];
            if (__builtin_expect(!rlist || base - 0x03000000u >= 0x00FFFFDCu, 0))
                goto slow_step;
            u32 cnt = popcnt16(rlist), a = base;
            r[rb] = base + cnt * 4u;
            for (u32 m = rlist; m; m &= m - 1u) {
                r[__builtin_ctz(m)] = *(const u32_alias *)(iwram + (a & 0x7FFCu));
                a += 4u;
            }
            cyc += cnt;
            break;
        }
        case 0x34: case 0x35: case 0x36: case 0x37: { /* B<cond> / UNDEF / SWI */
            u32 cond = (op >> 8) & 15u;
            if (__builtin_expect(cond >= 0xEu || (op & 0xFFu) == 0xFBu, 0))
                goto slow_step;
            if ((thumb_cond_mask[cond] >> (cpsr >> 28)) & 1u) {
                u32 next_pc = pc_base + (u32)((const u8 *)ip - (const u8 *)ip_base);
                pc = (next_pc + 2u + (u32)((s32)(s8)(op & 0xFFu) << 1)) & ~1u;
                cyc += 2u;
                cyc_left -= (s32)cyc;
                goto branch_pc;
            }
            break;
        }
        case 0x38: case 0x39: { /* Unconditional B offset11 */
            if (__builtin_expect(op == 0xE7FEu, 0))
                goto slow_step;
            u32 next_pc = pc_base + (u32)((const u8 *)ip - (const u8 *)ip_base);
            pc = (next_pc + 2u + (u32)(((s32)(op << 21)) >> 20)) & ~1u;
            cyc += 2u;
            cyc_left -= (s32)cyc;
            goto branch_pc;
        }
        case 0x3A: case 0x3B: /* Unused sub==1: falls through with fetch_cyc */
            break;
        case 0x3C: case 0x3D: { /* BL prefix */
            u32 next_pc = pc_base + (u32)((const u8 *)ip - (const u8 *)ip_base);
            r[14] = (next_pc + 2u) + (u32)(((s32)(op << 21)) >> 9);
            break;
        }
        case 0x3E: case 0x3F: { /* BL suffix */
            u32 next_pc = pc_base + (u32)((const u8 *)ip - (const u8 *)ip_base);
            pc = (r[14] + ((op & 0x7FFu) << 1)) & ~1u;
            r[14] = next_pc | 1u;
            cyc += 2u;
            cyc_left -= (s32)cyc;
            goto branch_pc;
        }
        }

        cyc_left -= (s32)cyc;
        continue;

    branch_pc:
        {
            u32 boff = pc - pc_base;
            if (__builtin_expect(boff < reg_bytes, 1)) {
                ip = (const u16_alias *)((const u8 *)ip_base + boff);
                continue;
            }
            goto rebase;
        }
    }

    pc = pc_base + (u32)((const u8 *)ip - (const u8 *)ip_base);

exit_with_pc:
    S.cpsr = cpsr;
    r[15] = pc;
    S.last_fetch = last_op * 0x00010001u;
    S.cyc_left = cyc_left;
    if (S.active_timers) {
        S.tmr_pend += (u32)(start_cyc - cyc_left);
        if (cyc_left <= S.tmr_next_cyc)
            timers_flush();
    }
    return 1;

slow_step:
    ip--;
    pc = pc_base + (u32)((const u8 *)ip - (const u8 *)ip_base);
    S.cpsr = cpsr;
    r[15] = pc;
    if (had_prev)
        S.last_fetch = prev_op * 0x00010001u;
    S.cyc_left = cyc_left;
    if (S.active_timers)
        S.tmr_pend += (u32)(start_cyc - cyc_left);
    {
        u32 c = step_thumb(pc, target_left);
        S.cyc_left -= (s32)c;
        if (S.active_timers) {
            S.tmr_pend += c;
            if (S.cyc_left <= S.tmr_next_cyc)
                timers_flush();
        }
    }
    return 1;
}
#endif

static void run_cpu_slice(s32 target_left)
{
    timers_flush();
    while (S.cyc_left > target_left) {
        if (S.irq_line && !(S.cpsr & CPSR_I))
            cpu_take_irq();

        if (S.halted) {
            if (S.tmr_pend)
                timers_flush();
            s32 rem = S.cyc_left - target_left;
            s32 step = timers_next_event(rem);
            if (step < 1) step = 1;
            if (step > rem) step = rem;
            S.cyc_left -= step;
            timers_step((u32)step);
            S.tmr_next_cyc = S.active_timers ? (S.cyc_left - timers_next_event(1000000)) : -1000000;
            if (S.halted && (!S.irq_line || (S.cpsr & CPSR_I)) && S.cyc_left <= target_left)
                break;
            continue;
        }

#ifndef HOST_EXTRA
        if ((S.cpsr & CPSR_T) && run_thumb_slice(target_left))
            continue;
#endif

        u32 cyc = (S.cpsr & CPSR_T) ? step_thumb(S.r[15], target_left)
                                    : step_arm(S.r[15], target_left);
        S.cyc_left -= (s32)cyc;
        if (S.active_timers) {
            S.tmr_pend += cyc;
            if (S.cyc_left <= S.tmr_next_cyc)
                timers_flush();
        }
    }
    if (S.tmr_pend)
        timers_flush();
}

/* ---- GBA PPU Scanline Renderer (240 x 160, Modes 0..5, OBJs, Windows, Blend) ---- */
enum {
    LYR_BG0 = 0,
    LYR_BG1 = 1,
    LYR_BG2 = 2,
    LYR_BG3 = 3,
    LYR_OBJ = 4,
    LYR_BD  = 5
};

static const u8 obj_w_tab[4][4] = {
    {  8, 16, 32, 64 }, /* Square */
    { 16, 32, 32, 64 }, /* Horizontal */
    {  8,  8, 16, 32 }, /* Vertical */
    {  8,  8,  8,  8 }
};

static const u8 obj_h_tab[4][4] = {
    {  8, 16, 32, 64 }, /* Square */
    {  8,  8, 16, 32 }, /* Horizontal */
    { 16, 32, 32, 64 }, /* Vertical */
    {  8,  8,  8,  8 }
};

static void render_text_bg(int bg, int y, u16 *line_col, u8 *line_hit)
{
    u16 cnt = io16(0x008u + (u32)bg * 2u);
    u32 char_base = ((cnt >> 2) & 3u) * 0x4000u;
    u32 scr_base  = ((cnt >> 8) & 31u) * 0x800u;
    int col256    = (cnt >> 7) & 1;
    u32 sz        = (cnt >> 14) & 3u;
    int mosaic    = (cnt >> 6) & 1;

    if (mosaic) {
        u32 m_v = ((io16(0x04Cu) >> 4) & 15u) + 1u;
        y -= y % (int)m_v;
    }

    u32 hofs = io16(0x010u + (u32)bg * 4u) & 0x1FFu;
    u32 vofs = io16(0x012u + (u32)bg * 4u) & 0x1FFu;
    u32 sy   = (u32)y + vofs;
    u32 ty   = (sy >> 3) & 31u;
    u32 py   = sy & 7u;
    u32 map_y_blk = ((sz & 2u) && (sy & 256u)) ? ((sz == 3u) ? 0x1000u : 0x800u) : 0u;

    /* Fast tile-at-a-time path for standard non-mosaic 4bpp Text BGs */
    if (!mosaic && !col256) {
        u32 *hit32 = (u32 *)line_hit;
        for (int w = 0; w < GBA_W / 4; w++)
            hit32[w] = 0u;

        int x = 0;
        u32 sx = hofs;
        while (x < GBA_W) {
            u32 tx = (sx >> 3) & 31u;
            u32 map_x_blk = ((sz & 1u) && (sx & 256u)) ? 0x800u : 0u;
            u32 map_off = (scr_base + map_y_blk + map_x_blk + ((ty * 32u + tx) << 1)) & 0xFFFFu;
            u16 entry = rd16le(M->vram + map_off);
            u32 tid = entry & 0x3FFu;
            u32 fy  = (entry & 0x0800u) ? (7u - py) : py;
            u32 toff = char_base + tid * 32u + fy * 4u;
            u32 row32 = (toff < 0x10000u) ? rd32le(M->vram + toff) : 0u;

            u32 start_k = sx & 7u;
            u32 span = 8u - start_k;
            if (x + (int)span > GBA_W)
                span = (u32)(GBA_W - x);

            if (row32 != 0u) {
                const u16 *pal = M->pal + ((entry >> 12) << 4);
                if (!(entry & 0x0400u)) {
                    u32 w = row32 >> (start_k * 4u);
                    for (u32 i = 0; i < span; i++, w >>= 4) {
                        u32 px = w & 15u;
                        if (px) { line_hit[x + (int)i] = 1u; line_col[x + (int)i] = pal[px]; }
                    }
                } else {
                    for (u32 i = 0; i < span; i++) {
                        u32 px = (row32 >> ((7u - (start_k + i)) * 4u)) & 15u;
                        if (px) { line_hit[x + (int)i] = 1u; line_col[x + (int)i] = pal[px]; }
                    }
                }
            }
            x += (int)span;
            sx += span;
        }
        return;
    }

    u32 m_h = mosaic ? ((io16(0x04Cu) & 15u) + 1u) : 1u;

    for (int x = 0; x < GBA_W; x++) {
        if (mosaic && ((u32)x % m_h) != 0) {
            line_hit[x] = line_hit[x - 1];
            line_col[x] = line_col[x - 1];
            continue;
        }
        u32 sx = (u32)x + hofs;
        u32 tx = (sx >> 3) & 31u;
        u32 map_x_blk = ((sz & 1u) && (sx & 256u)) ? 0x800u : 0u;
        u32 map_off = (scr_base + map_y_blk + map_x_blk + ((ty * 32u + tx) << 1)) & 0xFFFFu;
        u16 entry = rd16le(M->vram + map_off);
        u32 tid = entry & 0x3FFu;
        u32 fx  = (entry & 0x0400u) ? (7u - (sx & 7u)) : (sx & 7u);
        u32 fy  = (entry & 0x0800u) ? (7u - py) : py;

        if (col256) {
            u32 toff = char_base + tid * 64u + fy * 8u + fx;
            u8 px = (toff < 0x10000u) ? M->vram[toff] : 0u;
            if (px) {
                line_hit[x] = 1;
                line_col[x] = M->pal[px];
            } else {
                line_hit[x] = 0;
            }
        } else {
            u32 toff = char_base + tid * 32u + fy * 4u + (fx >> 1);
            u8 b = (toff < 0x10000u) ? M->vram[toff] : 0u;
            u8 px = (fx & 1u) ? (b >> 4) : (b & 15u);
            if (px) {
                line_hit[x] = 1;
                line_col[x] = M->pal[((entry >> 12) << 4) | px];
            } else {
                line_hit[x] = 0;
            }
        }
    }
}

static void render_affine_bg(int bg, u16 *line_col, u8 *line_hit)
{
    int idx = bg - 2;
    u16 cnt = io16(0x008u + (u32)bg * 2u);
    u32 char_base = ((cnt >> 2) & 3u) * 0x4000u;
    u32 scr_base  = ((cnt >> 8) & 31u) * 0x800u;
    int wrap      = (cnt >> 13) & 1;
    u32 sz_px     = 128u << ((cnt >> 14) & 3u);
    u32 tiles_w   = sz_px >> 3;
    u32 px_mask   = sz_px - 1u;

    u32 abase = idx ? 0x030u : 0x020u;
    s32 pa = (s16)io16(abase + 0u);
    s32 pc = (s16)io16(abase + 4u);
    s32 cx = S.bgx[idx];
    s32 cy = S.bgy[idx];

    for (int x = 0; x < GBA_W; x++, cx += pa, cy += pc) {
        s32 ix = cx >> 8;
        s32 iy = cy >> 8;
        if (wrap) {
            ix &= (s32)px_mask;
            iy &= (s32)px_mask;
        } else if ((u32)ix >= sz_px || (u32)iy >= sz_px) {
            line_hit[x] = 0;
            continue;
        }
        u32 map_off = scr_base + ((u32)iy >> 3) * tiles_w + ((u32)ix >> 3);
        u8 tid = (map_off < 0x10000u) ? M->vram[map_off] : 0u;
        u32 toff = char_base + (u32)tid * 64u + ((u32)iy & 7u) * 8u + ((u32)ix & 7u);
        u8 px = (toff < 0x10000u) ? M->vram[toff] : 0u;
        if (px) {
            line_hit[x] = 1;
            line_col[x] = M->pal[px];
        } else {
            line_hit[x] = 0;
        }
    }
}

static void render_bitmap_bg2(u32 mode, u16 dispcnt, u16 *line_col, u8 *line_hit)
{
    s32 pa = (s16)io16(0x020u);
    s32 pc = (s16)io16(0x024u);
    s32 cx = S.bgx[0];
    s32 cy = S.bgy[0];
    u32 frame_base = ((dispcnt & 0x0010u) && mode >= 4u) ? 0xA000u : 0u;
    u32 bw = (mode == 5u) ? 160u : 240u;
    u32 bh = (mode == 5u) ? 128u : 160u;

    for (int x = 0; x < GBA_W; x++, cx += pa, cy += pc) {
        s32 ix = cx >> 8;
        s32 iy = cy >> 8;
        if ((u32)ix >= bw || (u32)iy >= bh) {
            line_hit[x] = 0;
            continue;
        }
        if (mode == 4u) {
            u8 px = M->vram[frame_base + (u32)iy * 240u + (u32)ix];
            if (px) {
                line_hit[x] = 1;
                line_col[x] = M->pal[px];
            } else {
                line_hit[x] = 0;
            }
        } else {
            u32 off = frame_base + ((u32)iy * bw + (u32)ix) * 2u;
            line_hit[x] = 1;
            line_col[x] = rd16le(M->vram + off) & 0x7FFFu;
        }
    }
}

/* (returns what the line's sprite pixels are: bit p set -- one of priority p; bit 4 -- a semi-transparent one) */
static u32 render_objs(int y, u16 dispcnt, u16 *obj_col, u8 *obj_prio, u8 *obj_semi, u8 *obj_win)
{
    u32 flags = 0;
    u32 mode = dispcnt & 7u;
    u32 min_tile = (mode >= 3u) ? 512u : 0u;
    int map_1d   = (dispcnt >> 6) & 1;

    /* Evaluate OAM 0..127: lower OAM index has higher sprite-to-sprite priority! */
    for (int i = 0; i < 128; i++) {
        u16 a0 = M->oam[i * 4 + 0];
        u32 omode = (a0 >> 8) & 3u;
        if (omode == 2u) /* Disabled normal sprite */
            continue;
        int oy = a0 & 0xFFu;
        if (oy >= 160) oy -= 256;
        int ly = (y - oy) & 0xFF;
        if (ly >= 128 && !(a0 & 0x1000u))
            continue;
        u16 a1 = M->oam[i * 4 + 1];
        u16 a2 = M->oam[i * 4 + 2];

        int affine = a0 & 0x0100u;
        int dbl    = affine && (a0 & 0x0200u);
        u32 shape  = (a0 >> 14) & 3u;
        u32 sz     = (a1 >> 14) & 3u;
        if (shape == 3u)
            continue;

        int sw = obj_w_tab[shape][sz];
        int sh = obj_h_tab[shape][sz];
        int rw = dbl ? (sw * 2) : sw;
        int rh = dbl ? (sh * 2) : sh;
        if (ly >= rh && !(a0 & 0x1000u))
            continue;

        int ox = a1 & 0x1FFu;
        if (ox >= 240) ox -= 512;
        if (ox + rw <= 0 || ox >= GBA_W)
            continue;

        int mosaic = (a0 >> 12) & 1;
        if (mosaic) {
            u32 mv = ((io16(0x04Cu) >> 12) & 15u) + 1u;
            int my = y - (y % (int)mv);
            ly = (my - oy) & 0xFF;
            if (ly >= rh)
                continue;
        }

        int col256   = (a0 >> 13) & 1;
        u32 gfx_mode = (a0 >> 10) & 3u;  /* 0=normal, 1=semi-trans, 2=obj-win */
        u8 prio      = (u8)((a2 >> 10) & 3u);
        u32 base_tid = a2 & 0x3FFu;
        if (!map_1d && col256)
            base_tid &= ~1u;             /* Hardware quirk: 2D 8bpp ignores bit 0 of tile ID */
        u32 pal_base = 0x100u + (((a2 >> 12) & 15u) << 4);
        u32 row_stride = map_1d ? ((u32)(sw >> 3) << col256) : 32u;

        s32 pa = 0x100, pb = 0, pc = 0, pd = 0x100;
        s32 ref_x = 0, ref_y = 0;
        if (affine) {
            u32 grp = (a1 >> 9) & 31u;
            pa = (s16)M->oam[grp * 16u + 3u];
            pb = (s16)M->oam[grp * 16u + 7u];
            pc = (s16)M->oam[grp * 16u + 11u];
            pd = (s16)M->oam[grp * 16u + 15u];
            s32 dy = ly - (rh >> 1);
            s32 dx = -(rw >> 1);
            ref_x = ((sw << 7) + dx * pa + dy * pb);
            ref_y = ((sh << 7) + dx * pc + dy * pd);
        }

        int x0 = (ox < 0) ? -ox : 0;
        int x1 = (ox + rw > GBA_W) ? (GBA_W - ox) : rw;
        if (affine && x0 > 0) {
            ref_x += x0 * pa;
            ref_y += x0 * pc;
        }

        for (int lx = x0; lx < x1; lx++) {
            int sx = ox + lx;
            int tx, ty;
            if (affine) {
                tx = ref_x >> 8;
                ty = ref_y >> 8;
                ref_x += pa;
                ref_y += pc;
                if ((u32)tx >= (u32)sw || (u32)ty >= (u32)sh)
                    continue;
            } else {
                tx = (a1 & 0x1000u) ? (sw - 1 - lx) : lx;
                ty = (a1 & 0x2000u) ? (sh - 1 - ly) : ly;
            }

            /* Even if pixel is transparent or behind higher-index OAM, lower-OAM priority bug
               only updates visible pixel if obj_prio[sx] == 4 (no opaque OBJ yet) */
            if (gfx_mode != 2u && obj_prio[sx] != 4u) {
                /* Wait: on GBA hardware, if an earlier OAM had a LOWER priority number? No, OAM#0
                   ALWAYS beats OAM#1..127 once OAM#0 draws an opaque pixel! So checking obj_prio[sx]!=4
                   for normal/semi-trans sprites is 100% exact! */
                continue;
            }

            u32 tid = base_tid + (u32)(ty >> 3) * row_stride + ((u32)(tx >> 3) << col256);
            tid &= 0x3FFu;
            if (tid < min_tile)
                continue;

            u8 px;
            if (col256) {
                u32 off = 0x10000u + tid * 32u + (u32)(ty & 7) * 8u + (u32)(tx & 7);
                px = (off < 0x18000u) ? M->vram[off] : 0u;
            } else {
                u32 off = 0x10000u + tid * 32u + (u32)(ty & 7) * 4u + ((u32)(tx & 7) >> 1);
                u8 b = (off < 0x18000u) ? M->vram[off] : 0u;
                px = (tx & 1) ? (b >> 4) : (b & 15u);
            }
            if (!px)
                continue;

            if (gfx_mode == 2u) {
                obj_win[sx] = 1;
            } else {
                obj_prio[sx] = prio;
                obj_semi[sx] = (gfx_mode == 1u) ? 1 : 0;
                obj_col[sx]  = M->pal[col256 ? (0x100u + px) : (pal_base + px)];
                flags |= (1u << prio) | ((gfx_mode == 1u) ? 0x10u : 0u);
            }
        }
    }
    return flags;
}

static int in_win_v(int y, u16 wv)
{
    int y1 = (wv >> 8) & 0xFF;
    int y2 = wv & 0xFF;
    if (y1 <= y2)
        return y >= y1 && y < y2;
    return y >= y1 || y < y2;
}

typedef u32 __attribute__((may_alias)) u32_words;      /* (a line's u8 / u16 arrays a 32-bit word at a time) */

/* A 4-bit text BG's line (no mosaic) painted over `out`: render_text_bg's tiles, the opaque pixels alone written
   -- for a line whose pixels are each their top layer's colour, painted from the back */
static void paint_text_bg4(int bg, int y, u16 *out)
{
    u16 cnt = io16(0x008u + (u32)bg * 2u);
    u32 char_base = ((cnt >> 2) & 3u) * 0x4000u;
    u32 scr_base  = ((cnt >> 8) & 31u) * 0x800u;
    u32 sz        = (cnt >> 14) & 3u;
    u32 hofs = io16(0x010u + (u32)bg * 4u) & 0x1FFu;
    u32 vofs = io16(0x012u + (u32)bg * 4u) & 0x1FFu;
    u32 sy   = (u32)y + vofs;
    u32 ty   = (sy >> 3) & 31u;
    u32 py   = sy & 7u;
    u32 map_y_blk = ((sz & 2u) && (sy & 256u)) ? ((sz == 3u) ? 0x1000u : 0x800u) : 0u;
    int x = 0;
    u32 sx = hofs;
    while (x < GBA_W) {
        u32 tx = (sx >> 3) & 31u;
        u32 map_x_blk = ((sz & 1u) && (sx & 256u)) ? 0x800u : 0u;
        u32 map_off = (scr_base + map_y_blk + map_x_blk + ((ty * 32u + tx) << 1)) & 0xFFFFu;
        u16 entry = rd16le(M->vram + map_off);
        u32 tid = entry & 0x3FFu;
        u32 fy  = (entry & 0x0800u) ? (7u - py) : py;
        u32 toff = char_base + tid * 32u + fy * 4u;
        u32 row32 = (toff < 0x10000u) ? rd32le(M->vram + toff) : 0u;
        u32 start_k = sx & 7u;
        u32 span = 8u - start_k;
        if (x + (int)span > GBA_W)
            span = (u32)(GBA_W - x);
        if (row32 != 0u) {
            const u16 *pal = M->pal + ((entry >> 12) << 4);
            u16 *o = out + x;
            if (!(entry & 0x0400u)) {
                u32 w = row32 >> (start_k * 4u);
                for (u32 i = 0; w && i < span; i++, w >>= 4) {
                    u32 px = w & 15u;
                    if (px)
                        o[i] = pal[px];
                }
            } else {
                for (u32 i = 0; i < span; i++) {
                    u32 px = (row32 >> ((7u - (start_k + i)) * 4u)) & 15u;
                    if (px)
                        o[i] = pal[px];
                }
            }
        }
        x += (int)span;
        sx += span;
    }
}

/* A layer's pixels laid on the line's two top layers -- top[x], bot[x]: a colour with its layer's number << 16
   -- where sel[x] == want (a BG's hit flags: 1; the sprites' priorities: the one being laid) and, with windows,
   where win[x] has the layer's bit: what was on top goes below (BOT: only kept when the line's effects look at
   it) */
static inline __attribute__((always_inline)) void lay_line(u32 *top, u32 *bot, const u16 *col, const u8 *sel,
                                                           u32 want, const u8 *win, u32 bit, u32 tag, int BOT,
                                                           int WIN)
{
    for (int x = 0; x < GBA_W; x++) {
        if (sel[x] == want && (!WIN || (win[x] & bit))) {
            if (BOT)
                bot[x] = top[x];
            top[x] = (u32)col[x] | tag;
        }
    }
}

static void __attribute__((noinline)) lay_any(u32 *top, u32 *bot, const u16 *col, const u8 *sel, u32 want,
                                              const u8 *win, u32 bit, u32 tag)
{
    if (!win) {
        if (!bot)
            lay_line(top, bot, col, sel, want, win, bit, tag, 0, 0);
        else
            lay_line(top, bot, col, sel, want, win, bit, tag, 1, 0);
    } else {
        if (!bot)
            lay_line(top, bot, col, sel, want, win, bit, tag, 0, 1);
        else
            lay_line(top, bot, col, sel, want, win, bit, tag, 1, 1);
    }
}

static void render_scanline(int y, u16 *out)
{
    u16 dispcnt = io16(0x000);
    if (dispcnt & 0x0080u) {
        /* Forced blank outputs white (0x7FFF in GBA BGR555) */
        for (int x = 0; x < GBA_W; x++)
            out[x] = 0x7FFFu;
        return;
    }

    u32 mode = dispcnt & 7u;

    /* A bitmap picture alone -- modes 3 to 5 with BG2 unscaled, no sprites, windows or colour effects: every pixel
       is one look-up, no layers to sort or mix (the pictures a program draws itself: Another World's port, all of
       it).  The same pixels as the general way below gives. */
    if (mode >= 3u && mode <= 5u && (dispcnt & 0xF400u) == 0x0400u && ((io16(0x050) >> 6) & 3u) == 0u &&
        io16(0x020u) == 0x0100u && io16(0x024u) == 0u) {
        u32 frame_base = ((dispcnt & 0x0010u) && mode >= 4u) ? 0xA000u : 0u;
        s32 bw = (mode == 5u) ? 160 : 240;
        u32 bh = (mode == 5u) ? 128u : 160u;
        u16 bd = M->pal[0] & 0x7FFFu;
        s32 ix = S.bgx[0] >> 8, iy = S.bgy[0] >> 8;     /* (a step of 100h: the next column each pixel) */
        int x = 0, x0 = GBA_W, x1 = GBA_W;              /* the picture's columns: x0 .. x1 - 1 */
        if ((u32)iy < bh) {
            x0 = ix < 0 ? -ix : 0;
            if (x0 > GBA_W)
                x0 = GBA_W;
            x1 = bw - ix;
            if (x1 > GBA_W)
                x1 = GBA_W;
            if (x1 < x0)
                x1 = x0;
        }
        for (; x < x0; x++)
            out[x] = bd;
        if (mode == 4u) {
            const u8 *row = M->vram + frame_base + (u32)iy * 240u + ix;
            const u16 *pal = M->pal;
            for (; x < x1; x++) {
                u32 px = row[x];
                out[x] = px ? (u16)(pal[px] & 0x7FFFu) : bd;
            }
        } else {
            const u8 *row = M->vram + frame_base + ((u32)iy * (u32)bw + ix) * 2u;
            for (; x < x1; x++)
                out[x] = rd16le(row + x * 2) & 0x7FFFu;
        }
        for (; x < GBA_W; x++)
            out[x] = bd;
        S.bgx[0] += (s16)io16(0x022u);
        S.bgy[0] += (s16)io16(0x026u);
        S.bgx[1] += (s16)io16(0x032u);
        S.bgy[1] += (s16)io16(0x036u);
        return;
    }

    /* Evaluate OBJs first (needed for OBJWIN too) */
    u16 obj_col[GBA_W] __attribute__((aligned(4)));
    u8  obj_prio[GBA_W] __attribute__((aligned(4))), obj_semi[GBA_W] __attribute__((aligned(4)));
    u8  obj_win[GBA_W] __attribute__((aligned(4)));
    for (int w = 0; w < GBA_W / 4; w++) {
        ((u32_words *)obj_prio)[w] = 0x04040404u;
        ((u32_words *)obj_semi)[w] = 0u;
        ((u32_words *)obj_win)[w]  = 0u;
    }
    u32 obj_flags = 0;
    if (dispcnt & 0x1000u)
        obj_flags = render_objs(y, dispcnt, obj_col, obj_prio, obj_semi, obj_win);

    /* Per-pixel window enable mask (bits 0..3=BG0..3, bit 4=OBJ, bit 5=SFX): made when a window is on */
    u8 win_en[GBA_W];
    int any_win = (dispcnt & 0xE000u) != 0;
    if (any_win) {
        u16 winin  = io16(0x048);
        u16 winout = io16(0x04A);
        u8 out_m   = (u8)(winout & 0x3Fu);
        u8 obj_m   = (u8)((winout >> 8) & 0x3Fu);
        u8 w0_m    = (u8)(winin & 0x3Fu);
        u8 w1_m    = (u8)((winin >> 8) & 0x3Fu);

        for (int x = 0; x < GBA_W; x++)
            win_en[x] = ((dispcnt & 0x8000u) && obj_win[x]) ? obj_m : out_m;

        if ((dispcnt & 0x4000u) && in_win_v(y, io16(0x046))) {
            u16 wh = io16(0x042);
            int x1 = (wh >> 8) & 0xFF, x2 = wh & 0xFF;
            for (int x = 0; x < GBA_W; x++) {
                if ((x1 <= x2) ? (x >= x1 && x < x2) : (x >= x1 || x < x2))
                    win_en[x] = w1_m;
            }
        }
        if ((dispcnt & 0x2000u) && in_win_v(y, io16(0x044))) {
            u16 wh = io16(0x040);
            int x1 = (wh >> 8) & 0xFF, x2 = wh & 0xFF;
            for (int x = 0; x < GBA_W; x++) {
                if ((x1 <= x2) ? (x >= x1 && x < x2) : (x >= x1 || x < x2))
                    win_en[x] = w0_m;
            }
        }
    }

    /* The BGs the mode has and that are switched on: 1 a text BG, 2 an affine one, 3 the bitmap */
    u8 bg_kind[4] = { 0, 0, 0, 0 }, bg_prio[4];
    for (int b = 0; b < 4; b++)
        bg_prio[b] = (u8)(io16(0x008u + (u32)b * 2u) & 3u);
    if (mode == 0u) {
        for (int b = 0; b < 4; b++)
            if (dispcnt & (0x0100u << b))
                bg_kind[b] = 1;
    } else if (mode == 1u) {
        for (int b = 0; b < 2; b++)
            if (dispcnt & (0x0100u << b))
                bg_kind[b] = 1;
        if (dispcnt & 0x0400u)
            bg_kind[2] = 2;
    } else if (mode == 2u) {
        for (int b = 2; b < 4; b++)
            if (dispcnt & (0x0100u << b))
                bg_kind[b] = 2;
    } else if (mode <= 5u) {
        if (dispcnt & 0x0400u)
            bg_kind[2] = 3;
    }

    u16 bd_col   = M->pal[0] & 0x7FFFu;
    u16 bldcnt   = io16(0x050);
    u32 sfx_mode = (bldcnt >> 6) & 3u;
    /* The layers are painted from the back: the backdrop, then by priority 3 to 0 the BGs of that priority from
       BG3 to BG0 and the sprite pixels of that priority over them -- each pixel ends with its top layer, as
       sorting the layers at every pixel gave it (what that took: ~200 cycles a pixel on a line with a colour
       effect).  A line needs the layer below as well for alpha blending and under a semi-transparent sprite. */
    int need_bot = sfx_mode == 1u || (obj_flags & 0x10u) != 0u;

    if (sfx_mode == 0u && !need_bot && !any_win) {
        /* A line of top layers alone, no effect and no window: the colours straight into the picture's line --
           a 4-bit text BG's tiles painted over it as they are read (most BGs of most games), the other kinds
           from a line of their own */
        u16 tmp_col[GBA_W] __attribute__((aligned(4)));
        u8  tmp_hit[GBA_W] __attribute__((aligned(4)));
        for (int x = 0; x < GBA_W; x++)
            out[x] = bd_col;
        for (int pr = 3; pr >= 0; pr--) {
            for (int b = 3; b >= 0; b--) {
                if (!bg_kind[b] || bg_prio[b] != (u32)pr)
                    continue;
                if (bg_kind[b] == 1 && !(io16(0x008u + (u32)b * 2u) & 0x00C0u)) {
                    paint_text_bg4(b, y, out);
                    continue;
                }
                if (bg_kind[b] == 1)
                    render_text_bg(b, y, tmp_col, tmp_hit);
                else if (bg_kind[b] == 2)
                    render_affine_bg(b, tmp_col, tmp_hit);
                else
                    render_bitmap_bg2(mode, dispcnt, tmp_col, tmp_hit);
                for (int x = 0; x < GBA_W; x++)
                    if (tmp_hit[x])
                        out[x] = tmp_col[x];
            }
            if (obj_flags & (1u << pr))
                for (int x = 0; x < GBA_W; x++)
                    if (obj_prio[x] == (u32)pr)
                        out[x] = obj_col[x];
        }
        for (int x = 0; x < GBA_W; x++)
            out[x] &= 0x7FFFu;
        S.bgx[0] += (s16)io16(0x022u);
        S.bgy[0] += (s16)io16(0x026u);
        S.bgx[1] += (s16)io16(0x032u);
        S.bgy[1] += (s16)io16(0x036u);
        return;
    }

    /* The other lines: each BG into a line of its own, then laid on the two top layers */
    u16 bg_col[4][GBA_W] __attribute__((aligned(4)));
    u8  bg_hit[4][GBA_W] __attribute__((aligned(4)));
    for (int b = 0; b < 4; b++) {
        if (bg_kind[b] == 1)
            render_text_bg(b, y, bg_col[b], bg_hit[b]);
        else if (bg_kind[b] == 2)
            render_affine_bg(b, bg_col[b], bg_hit[b]);
        else if (bg_kind[b] == 3)
            render_bitmap_bg2(mode, dispcnt, bg_col[b], bg_hit[b]);
    }
    u32 top[GBA_W], bot[GBA_W];
    {
        u32 bd = (u32)bd_col | ((u32)LYR_BD << 16);
        for (int x = 0; x < GBA_W; x++)
            top[x] = bd;
        if (need_bot)
            for (int x = 0; x < GBA_W; x++)
                bot[x] = bd;
    }
    for (int pr = 3; pr >= 0; pr--) {
        for (int b = 3; b >= 0; b--)
            if (bg_kind[b] && bg_prio[b] == (u32)pr)
                lay_any(top, need_bot ? bot : 0, bg_col[b], bg_hit[b], 1u, any_win ? win_en : 0, 1u << b,
                        (u32)b << 16);
        if (obj_flags & (1u << pr))
            lay_any(top, need_bot ? bot : 0, obj_col, obj_prio, (u32)pr, any_win ? win_en : 0, 0x10u,
                    (u32)LYR_OBJ << 16);
    }

    /* the colour effects on what is on top (BLDCNT's first targets) and below (its second ones) */
    u32 eva = io16(0x052) & 0x1Fu;
    u32 evb = (io16(0x052) >> 8) & 0x1Fu;
    u32 evy = io16(0x054) & 0x1Fu;
    if (eva > 16u) eva = 16u;
    if (evb > 16u) evb = 16u;
    if (evy > 16u) evy = 16u;
    u8 fade[32];                        /* a channel made brighter / darker by BLDY */
    if (sfx_mode == 2u) {
        for (u32 c = 0; c < 32u; c++)
            fade[c] = (u8)(c + (((31u - c) * evy) >> 4));
    } else if (sfx_mode == 3u) {
        for (u32 c = 0; c < 32u; c++)
            fade[c] = (u8)(c - ((c * evy) >> 4));
    }
    for (int x = 0; x < GBA_W; x++) {
        u32 t = top[x], top_c = t & 0xFFFFu, top_l = t >> 16;
        u32 wm = any_win ? win_en[x] : 0x3Fu;
        int semi_hit = top_l == LYR_OBJ && obj_semi[x];
        int first = (wm & 0x20u) && sfx_mode != 0u && ((bldcnt >> top_l) & 1u);
        if (semi_hit || first) {
            u32 bot_c = bd_col, bot_l = LYR_BD;
            if (need_bot) {
                bot_c = bot[x] & 0xFFFFu;
                bot_l = bot[x] >> 16;
            }
            int t2_ok = (bldcnt >> (8u + bot_l)) & 1;
            if ((semi_hit && t2_ok) || (!(semi_hit && t2_ok) && first && sfx_mode == 1u && t2_ok)) {
                u32 r = (((top_c & 31u) * eva) + ((bot_c & 31u) * evb)) >> 4;
                u32 g = ((((top_c >> 5) & 31u) * eva) + (((bot_c >> 5) & 31u) * evb)) >> 4;
                u32 b = ((((top_c >> 10) & 31u) * eva) + (((bot_c >> 10) & 31u) * evb)) >> 4;
                if (r > 31u) r = 31u;
                if (g > 31u) g = 31u;
                if (b > 31u) b = 31u;
                top_c = r | (g << 5) | (b << 10);
            } else if (first && sfx_mode >= 2u && !semi_hit) {
                top_c = (u32)fade[top_c & 31u] | ((u32)fade[(top_c >> 5) & 31u] << 5) |
                        ((u32)fade[(top_c >> 10) & 31u] << 10);
            }
        }
        out[x] = (u16)(top_c & 0x7FFFu);
    }

    /* Advance internal affine reference registers by dmx (PB) and dmy (PD) */
    S.bgx[0] += (s16)io16(0x022u);
    S.bgy[0] += (s16)io16(0x026u);
    S.bgx[1] += (s16)io16(0x032u);
    S.bgy[1] += (s16)io16(0x036u);
}

/* ---- Public Interface ---- */
void gba_set_bios(const u8 *rom, u32 size)
{
    S.ext_bios = (rom && size == 0x4000u) ? rom : 0;
    S.ext_bios_size = S.ext_bios ? size : 0u;
}

static int match_tag(const u8 *p, const char *tag)
{
    for (int i = 0; tag[i]; i++) {
        if (p[i] != (u8)tag[i])
            return 0;
    }
    return 1;
}

static void detect_save_type(const u8 *rom, u32 size)
{
    S.save_type = SAVE_NONE;
    S.save_size = 0;
    if (size < 16u)
        return;
    for (u32 i = 0; i + 12u <= size; i += 4u) {
        u8 c = rom[i];
        if (c != 'E' && c != 'S' && c != 'F')
            continue;
        if (match_tag(rom + i, "EEPROM_V")) {
            S.save_type = SAVE_EEPROM;
            S.save_size = 0x2000u;           /* 8 KB buffer covers both 512B & 8KB EEPROM */
            return;
        }
        if (match_tag(rom + i, "SRAM_V") || match_tag(rom + i, "SRAM_F_V")) {
            S.save_type = SAVE_SRAM;
            S.save_size = 0x8000u;           /* 32 KB SRAM */
            return;
        }
        if (match_tag(rom + i, "FLASH1M_V")) {
            S.save_type = SAVE_FLASH128;
            S.save_size = 0x20000u;          /* 128 KB Flash */
            return;
        }
        if (match_tag(rom + i, "FLASH_V") || match_tag(rom + i, "FLASH512_V")) {
            S.save_type = SAVE_FLASH64;
            S.save_size = 0x10000u;          /* 64 KB Flash */
            return;
        }
    }
}

static void fmt_info(void)
{
    static const char * const save_names[] = { "no save", "SRAM 32KB", "Flash 64KB", "Flash 128KB", "EEPROM" };
    char *d = S.info;
    const char *t = S.title[0] ? S.title : "GBA ROM";
    for (int i = 0; t[i] && d - S.info < 40; i++)
        *d++ = t[i];
    if (S.code[0]) {
        *d++ = ' '; *d++ = '(';
        for (int i = 0; S.code[i]; i++) *d++ = S.code[i];
        *d++ = ')';
    }
    const char *sep = ", ";
    while (*sep) *d++ = *sep++;
    u32 kb = S.rom_size >> 10;
    if (kb == 0) kb = 1;
    char nb[16];
    int ni = 0;
    u32 v = kb;
    while (v > 0) { nb[ni++] = (char)('0' + (v % 10u)); v /= 10u; }
    while (ni > 0) *d++ = nb[--ni];
    const char *kbs = " KB, ";
    while (*kbs) *d++ = *kbs++;
    const char *sn = save_names[S.save_type];
    while (*sn) *d++ = *sn++;
    *d = 0;
}

const char *gba_load(u8 *image, u32 size)
{
    if (!image || size < 0xC0u)
        return "too small to be a GBA cartridge (under 192 bytes)";
    if (size > 0x02000000u)
        return "larger than the 32 MB GBA GamePak space";

    /* Validate entry instruction at 0x00 (must be an ARM branch / instruction, not all 00/FF garbage):
       Standard GBA carts have 0xEAxxxxxx (B ...) at 0x00 and 0x96 fixed byte at 0xB2, or valid Nintendo
       logo bytes at 0x04..0x9F; tiny test/multiboot ROMs at least start with valid ARM opcode at 0x00! */
    u32 entry = (u32)image[0] | ((u32)image[1] << 8) | ((u32)image[2] << 16) | ((u32)image[3] << 24);
    int logo_ok = (image[0x04] == 0x24u && image[0x05] == 0xFFu && image[0x06] == 0xAEu && image[0x07] == 0x51u);
    int branch_ok = ((entry >> 24) == 0xEAu || (entry >> 24) == 0xE5u || (entry >> 24) == 0xE3u);
    if (!logo_ok && !branch_ok)
        return "not a GBA cartridge (neither a Nintendo logo nor an ARM entry branch)";

    init_luts();
    S.rom = image;
    S.rom_size = size;

    /* Extract ASCII title (0xA0..0xAB) and game code (0xAC..0xAF) */
    int ti = 0;
    for (int i = 0; i < 12; i++) {
        u8 c = image[0xA0 + i];
        if (c >= 0x20u && c < 0x7Fu)
            S.title[ti++] = (char)c;
    }
    while (ti > 0 && S.title[ti - 1] == ' ')
        ti--;
    S.title[ti] = 0;

    int ci = 0;
    for (int i = 0; i < 4; i++) {
        u8 c = image[0xAC + i];
        if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
            S.code[ci++] = (char)c;
    }
    S.code[ci] = 0;

    detect_save_type(image, size);
    mem_fill(M->sram, 0xFF, sizeof(M->sram));
    S.save_dirty = 0;

    gba_reset();
    fmt_info();
    return 0;
}

void gba_reset(void)
{
    mem_zero(M->ewram, sizeof(M->ewram));
    mem_zero(M->iwram, sizeof(M->iwram));
    mem_zero(M->io, sizeof(M->io));
    mem_zero(M->pal, sizeof(M->pal));
    mem_zero(M->vram, sizeof(M->vram));
    mem_zero(M->oam, sizeof(M->oam));

    if (S.ext_bios && S.ext_bios_size == 0x4000u) {
        mem_copy(M->bios, S.ext_bios, 0x4000u);
        S.using_hle_bios = 0;
    } else {
        build_builtin_bios();
        S.using_hle_bios = 1;
    }

    for (int i = 0; i < 16; i++) S.r[i] = 0;
    for (int i = 0; i < 6; i++) {
        S.bank_r13[i] = 0;
        S.bank_r14[i] = 0;
        S.bank_spsr[i] = MODE_SYS;
    }
    for (int i = 0; i < 5; i++) {
        S.usr_r8_12[i] = 0;
        S.fiq_r8_12[i] = 0;
    }

    /* Post-BIOS direct-to-cartridge state (matches official GBA BIOS boot handoff) */
    S.cpsr         = MODE_SYS;
    S.spsr         = MODE_SYS;
    S.r[0]         = 0x08000000u;
    S.r[1]         = 0x000000EAu;
    S.r[13]        = 0x03007F00u;
    S.bank_r13[0]  = 0x03007F00u;            /* SP_usr / SP_sys */
    S.bank_r13[2]  = 0x03007FA0u;            /* SP_irq */
    S.bank_r13[3]  = 0x03007FE0u;            /* SP_svc */
    S.r[15]        = 0x08000000u;
    S.bios_latch   = 0xE129F000u;            /* Exact post-boot BIOS read latch */
    S.last_fetch   = 0xEA000000u;

    S.halted = 0;
    S.jammed = 0;
    S.irq_line = 0;
    S.cyc_left = 0;
    S.tmr_pend = 0;
    S.tmr_next_cyc = -1000000;
    S.vcount = 0;
    S.keyinput = 0x03FFu;

    mem_zero(S.dma, sizeof(S.dma));
    mem_zero(S.tmr, sizeof(S.tmr));
    S.active_timers = 0;
    fifo_reset(0);
    fifo_reset(1);
    mem_zero(&S.psg1, sizeof(S.psg1));
    mem_zero(&S.psg2, sizeof(S.psg2));
    mem_zero(&S.psg3, sizeof(S.psg3));
    mem_zero(&S.psg4, sizeof(S.psg4));
    S.psg4.lfsr = 0x7FFFu;
    S.psg_frame_acc = 0;
    S.psg_frame_step = 0;

    S.flash_state = FL_READY;
    S.flash_id_mode = 0;
    S.flash_bank = 0;
    S.eep_idx = 0;
    S.eep_addr_bits = 0;
    S.eep_read_addr = 0;
    S.eep_read_bit = 68u;

    /* Post-BIOS I/O register defaults */
    set_io16(0x000, 0x0080u);
    set_io16(0x020, 0x0100u);
    set_io16(0x026, 0x0100u);
    set_io16(0x030, 0x0100u);
    set_io16(0x036, 0x0100u);
    set_io16(0x088, 0x0200u);                /* SOUNDBIAS */
    M->io[0x300] = 1u;                       /* POSTFLG */
    S.bgx[0] = S.bgy[0] = S.bgx[1] = S.bgy[1] = 0;
    update_waitstates(0);
}

static void update_keypad(u16 pad)
{
    u16 pressed = 0;
    if (pad & GBA_PAD_A)      pressed |= 0x0001u;
    if (pad & GBA_PAD_B)      pressed |= 0x0002u;
    if (pad & GBA_PAD_SELECT) pressed |= 0x0004u;
    if (pad & GBA_PAD_START)  pressed |= 0x0008u;
    if (pad & GBA_PAD_RIGHT)  pressed |= 0x0010u;
    if (pad & GBA_PAD_LEFT)   pressed |= 0x0020u;
    if (pad & GBA_PAD_UP)     pressed |= 0x0040u;
    if (pad & GBA_PAD_DOWN)   pressed |= 0x0080u;
    if (pad & GBA_PAD_R)      pressed |= 0x0100u;
    if (pad & GBA_PAD_L)      pressed |= 0x0200u;

    S.keyinput = (u16)(0x03FFu & ~pressed);

    u16 keycnt = io16(0x132);
    if (keycnt & 0x4000u) {
        u16 want = keycnt & 0x03FFu;
        int fire = (keycnt & 0x8000u) ? ((pressed & want) == want && want != 0)
                                      : ((pressed & want) != 0);
        if (fire)
            raise_irq(IRQ_KEYPAD);
    }
}

void gba_frame(u16 pad, u16 *picture)
{
    update_keypad(pad);

    for (u16 line = 0; line < TOTAL_LINES; line++) {
        S.vcount = line;
        S.cyc_left += LINE_CYC;

        /* V-Counter match check at scanline start */
        u16 dispstat = io16(0x004);
        if (line == ((dispstat >> 8) & 0xFFu) && (dispstat & 0x0020u))
            raise_irq(IRQ_VCOUNT);

        if (line == VDRAW_LINES) {
            /* VBlank start (line 160): latch affine references, fire VBlank IRQ & VBlank DMA */
            latch_bg_ref(0);
            latch_bg_ref(1);
            if (dispstat & 0x0008u)
                raise_irq(IRQ_VBLANK);
            run_dma_timing(1);
        }

        /* Run HDraw (1,006 cycles -> cyc_left == 226) */
        run_cpu_slice(HBLANK_CYC);

        /* Render visible scanline & trigger HBlank DMA at start of HBlank */
        if (line < VDRAW_LINES) {
            if (picture)
                render_scanline((int)line, picture + (u32)line * GBA_W);
            run_dma_timing(2);
        }

        /* Fire HBlank IRQ if enabled */
        dispstat = io16(0x004);
        if (dispstat & 0x0010u)
            raise_irq(IRQ_HBLANK);

        /* Run HBlank (remaining 226 cycles -> cyc_left <= 0) */
        run_cpu_slice(0);

        /* Advance PSG & push 48 kHz stereo audio samples for this scanline */
        audio_sample_line();
    }
}

const char *gba_info(void)
{
    return S.info;
}

u8 *gba_save_ram(u32 *size, int *battery)
{
    if (S.save_type == SAVE_NONE) {
        /* Expose a 64 KB buffer without battery=1 until tagless cart writes, or if an existing .sav is loaded */
        *size = 0x10000u;
        *battery = 0;
        return M->sram;
    }
    *size = S.save_size;
    *battery = 1;
    return M->sram;
}

int gba_save_changed(void)
{
    int ch = S.save_dirty;
    S.save_dirty = 0;
    return ch;
}

int gba_jammed(void)
{
    return S.jammed;
}

void gba_audio_rate(u32 hz)
{
    S.snd_rate = hz;
    S.snd_phase = 0;
    S.snd_rd = S.snd_wr = 0;
}

int gba_audio(s16 *out, int max)
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
