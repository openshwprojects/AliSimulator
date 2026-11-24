/* Sony PlayStation 1 (.exe / .cue / .iso) emulator:
   - MIPS R3000A CPU (33.8688 MHz, 1-slot branch & load delays, LWL/LWR/SWL/SWR, COP0 exceptions & IsC cache isolate)
   - Full GTE (COP2) 3D geometry & lighting engine (RTPS/RTPT, NCLIP, AVSZ3/4, MVMVA, OP, SQR, NCDS/NCDT/NCCS/NCCT, DPCS/INTPL/GPF/GPL)
   - PS1 GPU (GP0/GP1, 1024 x 512 BGR555 VRAM, flat/Gouraud/textured 4bpp/8bpp/15bpp triangles, quads, lines & sprites, semi-transparency, dithering, mask bit, texture window, 15bpp & 24bpp display modes)
   - DMA0..6 (MDECin, MDECout, GPU VRAM & linked-list OT, CD-ROM, SPU, OTC) + 3 Root Counters
   - MDEC macroblock RLE + IDCT decoder (4bpp, 8bpp, 15bpp, 24bpp)
   - SPU 24-voice XA-ADPCM synthesizer + ADSR mixed to 48 kHz mono
   - Digital Joypad + 128 KB Memory Card (.sav) + CD-ROM XA/ISO9660 controller (.cue/.bin/.iso streaming + PS-X EXE)
   - Clean-room built-in HLE BIOS (A0/B0/C0 kernel, events, pad polling, ISO9660 SYSTEM.CNF boot) + optional scph1001.bin */
#pragma GCC optimize("O3")

#ifdef __mips__
#include "hw.h"
#endif
#include "psx.h"

typedef signed char s8;
typedef signed int s32;
typedef long long s64;
typedef unsigned long long u64;

#define PAD_A      0x0001u
#define PAD_B      0x0002u
#define PAD_SELECT 0x0004u
#define PAD_START  0x0008u
#define PAD_UP     0x0010u
#define PAD_DOWN   0x0020u
#define PAD_LEFT   0x0040u
#define PAD_RIGHT  0x0080u
#define PAD_X      0x0100u
#define PAD_Y      0x0200u
#define PAD_L      0x0400u
#define PAD_R      0x0800u

#define PSX_RAM_SIZE   0x200000u   /* 2 MB main RAM */
#define PSX_BIOS_SIZE  0x080000u   /* 512 KB BIOS */
#define PSX_SPU_SIZE   0x080000u   /* 512 KB SPU RAM */
#define PSX_MCD_SIZE   0x020000u   /* 128 KB Memory Card (.sav) */
#define PSX_AUD_MAX    2048
#define PSX_LINES_NTSC 263
#define PSX_VBL_LINE   240
#define PSX_CYC_LINE   2144        /* 33.8688 MHz / (59.94 * 263) ~= 2148 cycles/scanline */

/* VRAM rows lie VRAM_STRIDE pixels apart in memory, not 1024: the S3811's D-cache is 8 KB of four 2 KB ways, so
   2048-byte rows put a texture's texels of one column all into one cache set (four rows cached at most: a
   texture drawn at an angle missed on almost every texel); 2080-byte rows spread 64 rows over all 64 sets */
#define VRAM_STRIDE 1040u

struct psx_work {
    /* Hot small arrays placed in first 32 KB for 1-insn MIPS32 offset addressing */
    u8 scratch[0x400];             /* $1F800000..$1F8003FF (1 KB D-cache scratchpad) */
    u8 io[0x1000];                 /* $1F801000..$1F801FFF (4 KB MMIO backing) */
    s16 aud_buf[PSX_AUD_MAX];      /* 4 KB 48 kHz mono output */
    u8 cd_buf[2352];               /* Current CD sector raw buffer */
    u8 cd_fifo[2352];              /* Active CD data FIFO */
    u32 mdec_in[16384];            /* MDEC input buffer (up to 64 KB frame VLC output) */
    u8 mdec_out[24576];            /* MDEC decoded macroblock output FIFO */

    /* Main memories in EMU_RAM_PHYS (total ~4.69 MB + 4.00 MB MIPS32 JIT = ~8.73 MB of 9.50 MB available) */
    u8 ram[PSX_RAM_SIZE];
    u16 vram[VRAM_STRIDE * 512];
    u8 spu_ram[PSX_SPU_SIZE];
    u8 bios[PSX_BIOS_SIZE];
    u8 ext_bios[PSX_BIOS_SIZE];
    u8 mcd[PSX_MCD_SIZE];
    u8 exec_top_stack[4096];
    u8 exec_low_tables[1024];
#ifdef __mips__
#define JIT_RAM_WORDS 524288u
#define JIT_BUF_WORDS 524288u
#define JIT_CHUNKS    32768u /* 64-byte cache-line granularity across 2 MB PS1 RAM */
#define JIT_MAX_INSNS 44u    /* R3000 instructions in a block */
#define JIT_BLOCK_MAX 1024u  /* words a block may need at most */
    u32 jit_entry[JIT_RAM_WORDS];
    u32 jit_buf[JIT_BUF_WORDS];
    u8  jit_has_code[JIT_CHUNKS];
    u32 jit_code_bits[JIT_RAM_WORDS / 32u];     /* the RAM words recompiled code came from, one bit each: a write
                                                   into a chunk with code changes code only on one of these (Tony
                                                   Hawk's keeps a variable just after a function's last instructions,
                                                   written every other frame: ~90 whole resets a run without this) */
#endif
};

#ifdef __mips__
typedef char psx_work_fits[(sizeof(struct psx_work) <= EMU_RAM_SIZE) ? 1 : -1];   /* (up to PICTURE_PHYS) */
/* (VRAM's rows begin on 32-byte cache lines: the quick fill's pref 30 needs whole lines) */
typedef char psx_vram_lines[((__builtin_offsetof(struct psx_work, vram) | (VRAM_STRIDE * 2u) | EMU_RAM_PHYS) & 31u)
                            ? -1 : 1];
#define W (*((struct psx_work *)KSEG0(EMU_RAM_PHYS)))
#else
static struct psx_work psx_host_work;
#define W psx_host_work
#endif

struct spu_voice {
    u16 vol_l, vol_r;
    u16 pitch;
    u16 start_addr;
    u16 adsr_lo, adsr_hi;
    u16 repeat_addr;
    s16 vol_mono;
    u16 step;
    int cur_addr;          /* byte offset in spu_ram */
    u32 phase;             /* 12-bit fractional sample index (0..28*4096) */
    s32 env;               /* 0..0x7FFF */
    u8 state;              /* 0=off, 1=attack, 2=decay, 3=sustain, 4=release */
    u8 has_manual_repeat;
    s32 prev1, prev2;
    s16 samples[28];
    u8 loop_flags;
};

struct psx_event {
    u8 used, enabled, status;  /* status: 0=unused, 1=wait, 2=ready/delivered */
    u32 cls, spec, mode, cb;
};

static struct psx_state_s {
    /* Fixed-offset CPU/GTE state at +0x000..0x217 for 1-insn MIPS32 JIT addressing via $s0 */
    u32 r[32];             /* +0x000..0x07C */
    u32 pc;                /* +0x080 */
    u32 next_pc;           /* +0x084 */
    u32 hi;                /* +0x088 */
    u32 lo;                /* +0x08C */
    u32 gte_d[32];         /* +0x090..0x10C */
    u32 gte_c[32];         /* +0x110..0x18C */
    u32 cop0[32];          /* +0x190..0x20C */
    u32 jit_stop;          /* +0x210: non-zero when (IRQ pending || IsC cache isolate) */
    u8 *jit_hc_ptr;        /* +0x214: W.jit_has_code pointer */
    u32 jit_used;          /* +0x218: words used in W.jit_buf */
    s32 jit_bias;          /* +0x21C: budget parked when jit_stop came up in a helper ($s4 zeroed: the block's
                              exit leaves; psx_jit_exit adds it back, so the instruction count stays exact) */
    u8  scratch[0x400];    /* +0x220..0x61F: 1 KB D-cache scratchpad ($1F800000..$1F8003FF) */
    u32 jit_linked;        /* non-zero when direct native jumps link blocks */

    u32 cur_pc;
    u8 in_delay, next_delay;
    u8 ld_reg, pend_reg;
    u32 ld_val, pend_val;
    s16 gte_mat[4][3][3];

    /* Disc / Media source */
    const u8 *mem_disc;
    u32 mem_disc_size;
    psx_sector_fn sec_fn;
    u32 disc_sectors;
    u32 disc_sec_size;
    u8 has_disc;
    u8 has_ext_bios;
    u8 is_pal;
    u8 region_override;
    u8 skip_render;
    u8 sav_dirty;
    u8 jammed;

    /* Interrupts & DMA */
    u16 i_stat, i_mask;
    u32 dma_madr[7], dma_bcr[7], dma_chcr[7];
    u32 dpcr, dicr;

    /* Root Counters 0..2 */
    u32 rcnt_val[3];
    u16 rcnt_mode[3];
    u16 rcnt_targ[3];

    /* GPU state */
    u32 gpustat;
    u32 gpuread;
    u32 gp0_buf[16];
    u8 gp0_len, gp0_need, gp0_mode; /* mode: 0=cmd, 1=vram_write, 2=polyline */
    u8 gp0_poly_gouraud, gp0_poly_semi;
    u32 gp0_poly_prev_xy, gp0_poly_prev_col;
    u16 vram_tx, vram_ty, vram_tw, vram_th, vram_cx, vram_cy;
    u16 vram_rx, vram_ry, vram_rw, vram_rh, vram_rcx, vram_rcy;
    int clip_x1, clip_y1, clip_x2, clip_y2;
    int off_x, off_y;
    u8 tw_mx, tw_my, tw_ox, tw_oy;
    u8 set_mask, check_mask, dither, tex_disable;
    u16 disp_x, disp_y;
    int disp_w, disp_h;
    u8 disp_24bpp, disp_disabled, vram_full_clear;
    /* frame skipping in live play (skip_render 2 = the player is late): decided at a display flip, a whole game
       frame's drawing into a buffer not shown is dropped (fs_active); when that buffer is shown next it is
       "stale" and the player keeps the picture before it -- never an old frame in its place: drawing into a stale
       buffer does not make it new (only the next flip, or fs_age: a game that stopped flipping) */
    u8 fs_active, fs_dropped, disp_stale, disp_dirty, disp_flipped, fs_age;
    u32 fs_skipped;
    u32 vram_gen;
    u32 clut4_gen[4], clut4_klo[4], clut4_khi[4];
    s32 clut4_cache[4][16];
    u8  clut4_slot;

    /* MDEC state */
    u32 mdec_cmd, mdec_stat;
    u32 mdec_words_rem, mdec_in_cnt, mdec_in_pos;
    u32 mdec_out_pos, mdec_out_len;
    u8 mdec_iq_y[64], mdec_iq_uv[64];
    s16 mdec_scale[64];

    /* CD-ROM controller */
    u8 cd_index;
    u8 cd_param[16], cd_param_n;
    u8 cd_req_param[16], cd_req_param_n, cd_req_valid, cd_req_cmd;
    u8 cd_resp[16], cd_resp_n, cd_resp_p;
    u8 cd_irq_flag, cd_irq_en;
    u8 cd_stat;            /* bit1=motor, bit5=reading */
    u8 cd_mode;            /* bit7=2x, bit5=2340B */
    u8 cd_pend_cmd;
    u8 cd_xa_streak, cd_xa_file, cd_xa_ch, cd_xa_sub, cd_xa_cod, cd_flt_file, cd_flt_ch;
    int cd_req_delay;
    int cd_cmd_delay;
    int cd_read_delay;
    u32 cd_set_lba, cd_cur_lba;
    u32 cd_fifo_pos, cd_fifo_len;

    /* SIO0 Joypad & Memory Card */
    u16 sio_ctrl, sio_mode, sio_baud;
    u8 sio_fifo[256];
    u8 sio_len, sio_pos, sio_dev; /* 0=idle, 1=pad, 2=mcd, 0xFF=ignore */
    u8 sio_step;
    u8 mcd_cmd, mcd_flag, mcd_xor;
    u16 mcd_sec;
    int sio_irq_delay;

    /* SPU 24-voice audio */
    struct spu_voice spu_v[24];
    u16 spu_ctrl, spu_stat, spu_mvol_l, spu_mvol_r;
    u32 spu_xfer_addr;
    u32 spu_endx;
    u32 spu_active_mask;
    u32 sample_rate;
    u32 aud_count;
    u32 aud_frac;

    /* Clean-room HLE BIOS state */
    u32 exc_r[32], exc_epc, exc_hi, exc_lo;
    struct psx_event events[32];
    u32 pad_buf1, pad_buf2, pad_init_ptr;
    u8 pad_auto;
    u8 auto_clear_rcnt[4];
    u32 sys_int_rp[8];     /* SysEnqIntRP priority queues */
    u32 hook_entry_int;    /* HookEntryInt jumpbuf */
    u32 heap_base, heap_size, heap_cur;
    u32 vblank_count;
    struct {
        u32 sp, fp, gp, ra, s[8];
        u32 hook_entry_int, pad_init_ptr, pad_buf1, pad_buf2;
        u32 heap_base, heap_size, heap_cur;
        u32 sys_int_rp[8];
        struct psx_event events[32];
        u16 i_mask;
        u8 pad_auto;
        u8 auto_clear_rcnt[4];
    } exec_saved;

    u16 pad;
    int scan_y;
    char info_str[96];
} S;

/* ---- Interrupt & MIPS32 JIT Invalidation Helpers ---- */
static inline void sync_jit_stop(void)
{
    S.jit_stop = (((S.cop0[12] & 1u) && (S.cop0[12] & S.cop0[13] & 0xFF00u)) ? 1u : 0u)
               | (S.cop0[12] & 0x10000u);
}

/* counters for `psx` runs (printed by psx_print_stats after a game) */
static u32 st_reset_flush, st_reset_inval, st_reset_full, st_reset_other, st_compiles, st_inval, st_beside;
static u32 st_jit_enters, st_jit_insns, st_interp_runs, st_interp_insns;

#ifdef __mips__
static void jit_flush_all_icache(void)
{
    __asm__ volatile(
        ".set push\n\t"
        ".set noreorder\n\t"
        "lui   $t1, 0x8000\n\t"
        "lui   $t2, 0x8001\n\t"
        "1:\n\t"
        "cache 0x01, 0($t1)\n\t"
        "cache 0x00, 0($t1)\n\t"
        "addiu $t1, $t1, 16\n\t"
        "sltu  $t0, $t1, $t2\n\t"
        "bnez  $t0, 1b\n\t"
        "nop\n\t"
        "sync\n\t"
        ".word 0x000000c0\n\t"
        ".set pop"
        : : : "$t0", "$t1", "$t2", "memory"
    );
}

static void jit_reset_all(void)
{
    for (u32 i = 0; i < JIT_RAM_WORDS; i++)
        W.jit_entry[i] = 0u;
    for (u32 i = 0; i < JIT_CHUNKS; i++)
        W.jit_has_code[i] = 0u;
    for (u32 i = 0; i < JIT_RAM_WORDS / 32u; i++)
        W.jit_code_bits[i] = 0u;
    S.jit_used = 0u;
    S.jit_linked = 0u;
    S.jit_stop |= 2u;
    S.jit_hc_ptr = W.jit_has_code;
    jit_flush_all_icache();
}

static void jit_invalidate_chunk(u32 chunk, u32 off21)
{
    chunk &= (JIT_CHUNKS - 1u);
    if (!W.jit_has_code[chunk])
        return;
    if (!(W.jit_code_bits[(off21 >> 7) & (JIT_RAM_WORDS / 32u - 1u)] & (1u << ((off21 >> 2) & 31u)))) {
        st_beside++;                    /* a word beside code in the chunk: no code changed */
        return;
    }
    st_inval++;
    if (S.jit_linked) {
        st_reset_inval++;
        jit_reset_all();
        return;
    }
    W.jit_has_code[chunk] = 0u;
    u32 cw = chunk << 4; /* 16 words per 64-byte chunk; blocks are <= JIT_MAX_INSNS + 1 words */
    u32 start_w = (cw > JIT_MAX_INSNS + 4u) ? (cw - JIT_MAX_INSNS - 4u) : 0u;
    u32 end_w   = cw + 16u;
    for (u32 w = start_w; w < end_w; w++)
        W.jit_entry[w] = 0u;
}

static inline void jit_touch_ram(u32 off21)
{
    u32 ch = off21 >> 6;
    if (__builtin_expect(W.jit_has_code[ch], 0))
        jit_invalidate_chunk(ch, off21);
}
#else
static inline void jit_reset_all(void) {}
static inline void jit_touch_ram(u32 off21) { (void)off21; }
#endif

static inline void update_cop0_irq(void)
{
    if (S.i_stat & S.i_mask)
        S.cop0[13] |= 0x0400u;
    else
        S.cop0[13] &= ~0x0400u;
    sync_jit_stop();
}

static inline void raise_irq(u16 bit)
{
    S.i_stat |= bit;
    update_cop0_irq();
}

/* ---- Disc Sector Reader ---- */
static u8 from_bcd(u8 b) { return (u8)(((b >> 4) * 10u) + (b & 0x0Fu)); }
static u8 to_bcd(u32 v)  { return (u8)(((v / 10u) << 4) | (v % 10u)); }

static int read_disc_sector2048(u32 lba, u8 *out2048, u8 *raw2352_opt)
{
    if (!S.has_disc)
        return -1;
    if (S.sec_fn) {
        int got = S.sec_fn(lba, W.cd_buf);
        if (got <= 0)
            return -1;
        if (raw2352_opt && raw2352_opt != W.cd_buf && got == 2352)
            for (int i = 0; i < 2352; i++) raw2352_opt[i] = W.cd_buf[i];
        const u8 *src = (got == 2352) ? (W.cd_buf + (W.cd_buf[15] == 1u ? 16 : 24)) : W.cd_buf;
        for (int i = 0; i < 2048; i++)
            out2048[i] = src[i];
        return 0;
    }
    if (S.mem_disc) {
        u32 ssz = S.disc_sec_size ? S.disc_sec_size : 2352u;
        u32 off = lba * ssz;
        if (off + 2048u > S.mem_disc_size)
            return -1;
        if (raw2352_opt && ssz == 2352u && off + 2352u <= S.mem_disc_size)
            for (int i = 0; i < 2352; i++) raw2352_opt[i] = S.mem_disc[off + i];
        u32 hdr_skip = (ssz == 2352u) ? (S.mem_disc[off + 15u] == 1u ? 16u : 24u) : 0u;
        const u8 *src = S.mem_disc + off + hdr_skip;
        for (int i = 0; i < 2048; i++)
            out2048[i] = src[i];
        return 0;
    }
    return -1;
}

/* ---- Digital Joypad & 128 KB Memory Card (SIO0) ---- */
static u16 build_pad_buttons(void)
{
    /* Active-low PS1 standard digital pad bits:
       bit0=Select, bit3=Start, bit4=Up, bit5=Right, bit6=Down, bit7=Left,
       bit10=L1, bit11=R1, bit12=Triangle, bit13=Circle, bit14=Cross, bit15=Square */
    u16 b = 0xFFFFu;
    if (S.pad & PAD_SELECT) b &= (u16)~(1u << 0);
    if (S.pad & PAD_START)  b &= (u16)~(1u << 3);
    if (S.pad & PAD_UP)     b &= (u16)~(1u << 4);
    if (S.pad & PAD_RIGHT)  b &= (u16)~(1u << 5);
    if (S.pad & PAD_DOWN)   b &= (u16)~(1u << 6);
    if (S.pad & PAD_LEFT)   b &= (u16)~(1u << 7);
    if (S.pad & PAD_L)      b &= (u16)~(1u << 10);
    if (S.pad & PAD_R)      b &= (u16)~(1u << 11);
    if (S.pad & PAD_X)      b &= (u16)~(1u << 12); /* Triangle */
    if (S.pad & PAD_A)      b &= (u16)~(1u << 13); /* Circle   */
    if (S.pad & PAD_B)      b &= (u16)~(1u << 14); /* Cross    */
    if (S.pad & PAD_Y)      b &= (u16)~(1u << 15); /* Square   */
    return b;
}

static u8 sio0_txrx(u8 tx)
{
    int port = (S.sio_ctrl >> 13) & 1; /* 0 = Slot 1, 1 = Slot 2 */
    if (!(S.sio_ctrl & 0x0002u) || port != 0) {
        return 0xFFu; /* DTR not asserted or Slot 2 unconnected */
    }

    if (S.sio_step == 0) {
        if (tx == 0x01u) {
            S.sio_dev = 1u;
            S.sio_step = 1u;
            S.sio_irq_delay = 512;
            return 0xFFu;
        }
        if (tx == 0x81u) {
            S.sio_dev = 2u;
            S.sio_step = 1u;
            S.sio_irq_delay = 512;
            return 0xFFu;
        }
        S.sio_dev = 0xFFu;
        return 0xFFu;
    }

    if (S.sio_dev == 1u) { /* Digital Pad */
        u16 btns = build_pad_buttons();
        u8 step = S.sio_step++;
        if (step == 1u) {
            if (tx != 0x42u) { S.sio_dev = 0xFFu; return 0xFFu; }
            S.sio_irq_delay = 512;
            return 0x41u; /* Digital Pad ID low */
        }
        if (step == 2u) { S.sio_irq_delay = 512; return 0x5Au; }
        if (step == 3u) { S.sio_irq_delay = 512; return (u8)(btns & 0xFFu); }
        if (step == 4u) { S.sio_dev = 0xFFu; return (u8)(btns >> 8); }
        return 0xFFu;
    }

    if (S.sio_dev == 2u) { /* Memory Card 128 KB (1024 frames x 128 B) */
        u8 step = S.sio_step++;
        S.sio_irq_delay = 512;
        if (step == 1u) {
            S.mcd_cmd = tx;
            u8 fl = S.mcd_flag;
            if (tx == 'R' || tx == 'W' || tx == 'S')
                return fl;
            S.sio_dev = 0xFFu;
            return 0xFFu;
        }
        if (step == 2u) return 0x5Au;
        if (step == 3u) return 0x5Du;
        if (S.mcd_cmd == 'R') {
            if (step == 4u) { S.mcd_sec = (u16)tx << 8; S.mcd_xor = tx; return 0x00u; }
            if (step == 5u) { S.mcd_sec |= tx; S.mcd_xor ^= tx; return (u8)(S.mcd_sec >> 8); }
            if (step == 6u) return 0x5Cu;
            if (step == 7u) return 0x5Du;
            if (step == 8u) return (u8)(S.mcd_sec >> 8);
            if (step == 9u) return (u8)(S.mcd_sec & 0xFFu);
            if (step >= 10u && step < 138u) {
                u8 b = (S.mcd_sec < 1024u) ? W.mcd[(u32)S.mcd_sec * 128u + (step - 10u)] : 0xFFu;
                S.mcd_xor ^= b;
                return b;
            }
            if (step == 138u) return S.mcd_xor;
            if (step == 139u) { S.sio_dev = 0xFFu; S.sio_irq_delay = 0; return 0x47u; } /* 'G' good */
        } else if (S.mcd_cmd == 'W') {
            if (step == 4u) { S.mcd_sec = (u16)tx << 8; S.mcd_xor = tx; return 0x00u; }
            if (step == 5u) { S.mcd_sec |= tx; S.mcd_xor ^= tx; return (u8)(S.mcd_sec >> 8); }
            if (step >= 6u && step < 134u) {
                u8 prev = (step == 6u) ? (u8)(S.mcd_sec & 0xFFu) : S.sio_fifo[step - 7u];
                S.sio_fifo[step - 6u] = tx;
                S.mcd_xor ^= tx;
                return prev;
            }
            if (step == 134u) {
                u8 prev = S.sio_fifo[127];
                if (tx == S.mcd_xor && S.mcd_sec < 1024u) {
                    for (int i = 0; i < 128; i++)
                        W.mcd[(u32)S.mcd_sec * 128u + (u32)i] = S.sio_fifo[i];
                    S.mcd_flag &= (u8)~0x08u;
                    S.sav_dirty = 1;
                }
                return prev;
            }
            if (step == 135u) return 0x5Cu;
            if (step == 136u) return 0x5Du;
            if (step == 137u) { S.sio_dev = 0xFFu; S.sio_irq_delay = 0; return 0x47u; }
        } else if (S.mcd_cmd == 'S') {
            if (step == 4u) return 0x5Cu;
            if (step == 5u) return 0x5Du;
            if (step == 6u) return 0x04u;
            if (step == 7u) return 0x00u;
            if (step == 8u) return 0x00u;
            if (step == 9u) { S.sio_dev = 0xFFu; S.sio_irq_delay = 0; return 0x80u; }
        }
    }
    return 0xFFu;
}

/* ---- CD-ROM Controller ($1F801800..$1F801803) ---- */
static void cd_push_resp(u8 v)
{
    if (S.cd_resp_n < 16u)
        S.cd_resp[S.cd_resp_n++] = v;
}

static void cd_fire_irq(u8 irq_num)
{
    S.cd_irq_flag = (u8)((S.cd_irq_flag & ~0x07u) | (irq_num & 0x07u));
    if (S.cd_irq_en & irq_num)
        raise_irq(1u << 2); /* IRQ2 CDROM */
}

static void cd_exec_cmd(u8 cmd)
{
    S.cd_resp_n = 0;
    S.cd_resp_p = 0;
    u8 stat = (u8)(0x02u | (S.cd_stat & 0x20u)); /* motor on + optional reading */
    if (cmd != 0x01u && cmd != 0x10u && cmd != 0x11u)
        S.cd_pend_cmd = 0u;

    switch (cmd) {
    case 0x01u: /* CdlNop */
        cd_push_resp(stat);
        cd_fire_irq(3u);
        break;
    case 0x02u: /* CdlSetloc (MM, SS, FF in BCD) */
        S.cd_xa_streak = 0u;
        if (S.cd_req_param_n >= 3u) {
            u32 mm = from_bcd(S.cd_req_param[0]);
            u32 ss = from_bcd(S.cd_req_param[1]);
            u32 ff = from_bcd(S.cd_req_param[2]);
            u32 abs_f = (mm * 60u + ss) * 75u + ff;
            S.cd_set_lba = (abs_f >= 150u) ? (abs_f - 150u) : 0u;
        }
        cd_push_resp(stat);
        cd_fire_irq(3u);
        break;
    case 0x03u: /* CdlPlay */
        S.cd_xa_streak = 0u;
        S.cd_cur_lba = S.cd_set_lba;
        S.cd_stat = 0x82u;
        cd_push_resp(S.cd_stat);
        cd_fire_irq(3u);
        break;
    case 0x06u: /* CdlReadN */
    case 0x1Bu: /* CdlReadS */
        S.cd_xa_streak = 0u;
        S.cd_xa_sub = 0u;
        S.cd_fifo_pos = 0u;
        S.cd_cur_lba = S.cd_set_lba;
        S.cd_stat = 0x22u;
        S.cd_read_delay = (S.cd_mode & 0x80u) ? 225000 : 450000;
        cd_push_resp(S.cd_stat);
        cd_fire_irq(3u);
        break;
    case 0x07u: /* CdlStandby */
    case 0x08u: /* CdlStop */
    case 0x09u: /* CdlPause */
    case 0x0Au: /* CdlInit */
        S.cd_xa_streak = 0u;
        S.cd_stat = (cmd == 0x08u) ? 0x00u : 0x02u;
        S.cd_read_delay = 0;
        cd_push_resp(stat);
        cd_fire_irq(3u);
        /* 2nd completion response delivered right after 1st is acknowledged */
        S.cd_pend_cmd = 0xF0u | (cmd == 0x08u ? 0u : 2u);
        S.cd_cmd_delay = 4096;
        break;
    case 0x0Bu: /* CdlMute */
    case 0x0Cu: /* CdlDemute */
        cd_push_resp(stat);
        cd_fire_irq(3u);
        break;
    case 0x0Du: /* CdlSetfilter */
        if (S.cd_req_param_n >= 2u) {
            S.cd_flt_file = S.cd_req_param[0];
            S.cd_flt_ch   = S.cd_req_param[1];
        }
        cd_push_resp(stat);
        cd_fire_irq(3u);
        break;
    case 0x0Eu: /* CdlSetmode */
        S.cd_xa_streak = 0u;
        if (S.cd_req_param_n >= 1u)
            S.cd_mode = S.cd_req_param[0];
        cd_push_resp(stat);
        cd_fire_irq(3u);
        break;
    case 0x0Fu: /* CdlGetparam */
        cd_push_resp(stat);
        cd_push_resp(S.cd_mode);
        cd_push_resp(0u);
        cd_push_resp(0u);
        cd_push_resp(0u);
        cd_fire_irq(3u);
        break;
    case 0x10u: { /* CdlGetlocL */
        for (int i = 0; i < 8; i++)
            cd_push_resp(W.cd_buf[12 + i]);
        cd_fire_irq(3u);
        break;
    }
    case 0x11u: { /* CdlGetlocP */
        u32 rel = S.cd_cur_lba;
        u32 absf = rel + 150u;
        cd_push_resp(0x01u);
        cd_push_resp(0x01u);
        cd_push_resp(to_bcd(rel / (60u * 75u)));
        cd_push_resp(to_bcd((rel / 75u) % 60u));
        cd_push_resp(to_bcd(rel % 75u));
        cd_push_resp(to_bcd(absf / (60u * 75u)));
        cd_push_resp(to_bcd((absf / 75u) % 60u));
        cd_push_resp(to_bcd(absf % 75u));
        cd_fire_irq(3u);
        break;
    }
    case 0x13u: /* CdlGetTN */
        cd_push_resp(stat);
        cd_push_resp(0x01u);
        cd_push_resp(0x01u);
        cd_fire_irq(3u);
        break;
    case 0x14u: { /* CdlGetTD */
        u8 trk = S.cd_req_param_n ? from_bcd(S.cd_req_param[0]) : 0u;
        u32 frames = (trk == 0u) ? (S.disc_sectors + 150u) : 150u;
        cd_push_resp(stat);
        cd_push_resp(to_bcd(frames / (60u * 75u)));
        cd_push_resp(to_bcd((frames / 75u) % 60u));
        cd_fire_irq(3u);
        break;
    }
    case 0x15u: /* CdlSeekL */
    case 0x16u: /* CdlSeekP */
        S.cd_xa_streak = 0u;
        S.cd_cur_lba = S.cd_set_lba;
        S.cd_stat = 0x02u;
        S.cd_read_delay = 0;
        cd_push_resp(0x42u);
        cd_fire_irq(3u);
        S.cd_pend_cmd = 0xF2u;
        S.cd_cmd_delay = 4096;
        break;
    case 0x19u: /* CdlTest */
        if (S.cd_req_param_n >= 1u && S.cd_req_param[0] == 0x20u) {
            cd_push_resp(0x98u);
            cd_push_resp(0x06u);
            cd_push_resp(0x10u);
            cd_push_resp(0xC3u);
        } else {
            cd_push_resp(stat);
        }
        cd_fire_irq(3u);
        break;
    case 0x1Au: /* CdlGetID */
        cd_push_resp(stat);
        cd_fire_irq(3u);
        S.cd_pend_cmd = 0xFAu;
        S.cd_cmd_delay = 4096;
        break;
    case 0x1Eu: /* CdlReadTOC */
        S.cd_stat = 0x02u;
        cd_push_resp(stat);
        cd_fire_irq(3u);
        S.cd_pend_cmd = 0xF2u;
        S.cd_cmd_delay = 4096;
        break;
    default:
        cd_push_resp(stat);
        cd_fire_irq(3u);
        break;
    }
}

static void cd_step(int cycles)
{
    if (S.cd_req_valid) {
        S.cd_req_delay -= cycles;
        if ((S.cd_req_delay <= 0 && !(S.cd_irq_flag & 0x07u)) || S.cd_req_delay <= -2048) {
            u8 cmd = S.cd_req_cmd;
            S.cd_req_valid = 0u;
            S.cd_irq_flag = 0u;
            cd_exec_cmd(cmd);
        }
        return;
    }

    if (S.cd_pend_cmd && !(S.cd_irq_flag & 0x07u)) {
        S.cd_cmd_delay -= cycles;
        if (S.cd_cmd_delay <= 0) {
            u8 pc = S.cd_pend_cmd;
            S.cd_pend_cmd = 0;
            S.cd_resp_n = 0;
            S.cd_resp_p = 0;
            if (pc == 0xFAu) { /* GetID 2nd response */
                if (S.has_disc) {
                    cd_push_resp(0x02u); cd_push_resp(0x00u); cd_push_resp(0x20u); cd_push_resp(0x00u);
                    cd_push_resp('S');   cd_push_resp('C');   cd_push_resp('E');   cd_push_resp('A');
                    cd_fire_irq(2u);
                } else {
                    cd_push_resp(0x08u); cd_push_resp(0x40u); cd_push_resp(0x00u); cd_push_resp(0x00u);
                    cd_push_resp(0x00u); cd_push_resp(0x00u); cd_push_resp(0x00u); cd_push_resp(0x00u);
                    cd_fire_irq(5u);
                }
            } else {
                cd_push_resp((u8)(pc & 0x0Fu));
                cd_fire_irq(2u);
            }
        }
    }

    if ((S.cd_stat & 0x20u) && S.cd_read_delay > 0 && !(S.cd_irq_flag & 0x07u)) {
        S.cd_read_delay -= cycles;
        if (S.cd_read_delay <= 0) {
            S.cd_read_delay = (S.cd_mode & 0x80u) ? 225000 : 450000;
            if ((S.cd_mode & 0x42u) == 0x40u && S.cd_xa_streak >= 16u && S.cd_xa_sub &&
                S.has_disc && S.cd_cur_lba < S.disc_sectors) {
                /* Real PS1 CD-XA hardware behavior: when Setmode.6 (0x40) routes Real-Time XA-ADPCM sectors
                   to SPU (and AutoPause 0x02 is off), non-Data XA sectors do NOT enter Data FIFO or fire INT1.
                   After 16 consecutive non-Data XA sectors, advance LBA & subheader without unused USB reads. */
                u32 tot = S.cd_cur_lba + 150u;
                u8 ch = (u8)((S.cd_cur_lba + S.cd_xa_ch) & 7u);
                W.cd_buf[12] = to_bcd(tot / (60u * 75u));
                W.cd_buf[13] = to_bcd((tot / 75u) % 60u);
                W.cd_buf[14] = to_bcd(tot % 75u);
                W.cd_buf[15] = 2u;
                W.cd_buf[16] = S.cd_xa_file; W.cd_buf[17] = ch; W.cd_buf[18] = S.cd_xa_sub; W.cd_buf[19] = S.cd_xa_cod;
                W.cd_buf[20] = S.cd_xa_file; W.cd_buf[21] = ch; W.cd_buf[22] = S.cd_xa_sub; W.cd_buf[23] = S.cd_xa_cod;
                S.cd_cur_lba++;
                return;
            }
            u32 u2048_w[512];
            u8 *u2048 = (u8 *)u2048_w;
            if (read_disc_sector2048(S.cd_cur_lba, u2048, W.cd_buf) == 0) {
                u8 sm = W.cd_buf[18];
                if ((S.cd_mode & 0x40u) && S.disc_sec_size == 2352u && W.cd_buf[15] == 2u && !(sm & 0x08u) &&
                    (((sm & 0x44u) == 0x44u) || ((S.cd_mode & 0x08u) && (sm & 0x0Eu) == 0u))) {
                    if ((sm & 0x44u) == 0x44u) {
                        S.cd_xa_file = W.cd_buf[16];
                        S.cd_xa_ch   = (u8)(W.cd_buf[17] - (u8)(S.cd_cur_lba & 7u));
                        S.cd_xa_sub  = (u8)(sm & 0x7Fu);
                        S.cd_xa_cod  = W.cd_buf[19];
                    }
                    if (S.cd_xa_sub && S.cd_xa_streak < 32u)
                        S.cd_xa_streak++;
                    S.cd_cur_lba++;
                    if ((S.cd_mode & 0x02u) && (sm & 0x80u) &&
                        (!(S.cd_mode & 0x08u) || (W.cd_buf[16] == S.cd_flt_file && W.cd_buf[17] == S.cd_flt_ch))) {
                        S.cd_stat &= (u8)~0x20u;
                        S.cd_read_delay = 0;
                        S.cd_resp_n = 0;
                        S.cd_resp_p = 0;
                        cd_push_resp(S.cd_stat);
                        cd_fire_irq(4u); /* INT4 DataEnd on AutoPause */
                    }
                    return;
                }
                S.cd_xa_streak = 0u;
                u32 * fd32 = (u32 *)W.cd_fifo;
                if (S.cd_mode & 0x20u) {
                    const u32 *bs32 = (const u32 *)(W.cd_buf + 12);
                    for (int i = 0; i < 585; i++) fd32[i] = bs32[i];
                    S.cd_fifo_len = 2340u;
                } else {
                    for (int i = 0; i < 512; i++) fd32[i] = u2048_w[i];
                    S.cd_fifo_len = 2048u;
                }
                S.cd_fifo_pos = 0;
                S.cd_cur_lba++;
                S.cd_resp_n = 0;
                S.cd_resp_p = 0;
                cd_push_resp(S.cd_stat);
                cd_fire_irq(1u); /* INT1 DataReady */
            }
        }
    }
}

/* ---- MDEC Macroblock RLE + IDCT Decoder ($1F801820..$1F801824) ---- */
static const u8 mdec_zagzig[64] = {
     0,  1,  8, 16,  9,  2,  3, 10,
    17, 24, 32, 25, 18, 11,  4,  5,
    12, 19, 26, 33, 40, 48, 41, 34,
    27, 20, 13,  6,  7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36,
    29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46,
    53, 60, 61, 54, 47, 55, 62, 63
};

static inline s32 clamp_s8(s32 v) { return v < -128 ? -128 : (v > 127 ? 127 : v); }

static int mdec_rl_decode_block(s16 *blk, const u16 **src, const u16 *end, const u8 *iq)
{
    for (int i = 0; i < 64; i++) blk[i] = 0;
    const u16 *p = *src;
    while (p < end && *p == 0xFE00u) p++;
    if (p >= end) { *src = p; return 0; }

    u16 cur = *p++;
    u32 q_scale = (cur >> 10) & 0x3Fu;
    s32 dc = (cur & 0x0200u) ? (s32)(cur | ~0x03FFu) : (s32)(cur & 0x03FFu);
    if (q_scale == 0u) {
        s32 val = dc * 2;
        if (val < -0x400) val = -0x400;
        if (val >  0x3FF) val =  0x3FF;
        blk[0] = (s16)val;
        int has_ac = 0;
        for (int k = 1; k < 64 && p < end; k++) {
            cur = *p++;
            s32 ac = (cur & 0x0200u) ? (s32)(cur | ~0x03FFu) : (s32)(cur & 0x03FFu);
            val = ac * 2;
            if (val < -0x400) val = -0x400;
            if (val >  0x3FF) val =  0x3FF;
            if (val) has_ac = 1;
            blk[k] = (s16)val;
        }
        *src = p;
        return has_ac ? 2 : 1;
    }

    s32 val = dc * (s32)iq[0];
    if (val < -0x400) val = -0x400;
    if (val >  0x3FF) val =  0x3FF;
    blk[0] = (s16)val;

    int k = 0, has_ac = 0;
    while (p < end) {
        cur = *p++;
        if (cur == 0xFE00u) break;
        k += ((cur >> 10) & 0x3Fu) + 1;
        if (k >= 64) {
            while (p < end && *p++ != 0xFE00u) {}
            break;
        }
        s32 ac = (cur & 0x0200u) ? (s32)(cur | ~0x03FFu) : (s32)(cur & 0x03FFu);
        val = (ac * (s32)iq[k] * (s32)q_scale + 4) >> 3;
        if (val < -0x400) val = -0x400;
        if (val >  0x3FF) val =  0x3FF;
        if (val) {
            blk[mdec_zagzig[k]] = (s16)val;
            has_ac = 1;
        }
    }
    *src = p;
    return has_ac ? 2 : 1;
}

static void mdec_idct(s16 *blk, int mode)
{
    if (mode == 1) { /* DC-only fast path */
        s32 b0 = blk[0];
        if (b0 == 0)
            return;
        for (int y = 0; y < 8; y++) {
            s32 ty = (b0 * (s32)S.mdec_scale[y] + 0x8000) >> 16;
            for (int x = 0; x < 8; x++)
                blk[y * 8 + x] = (s16)clamp_s8((ty * (s32)S.mdec_scale[x] + 0x8000) >> 16);
        }
        return;
    }

    s32 tmp[64];
    const s16 *sc = S.mdec_scale;
    for (int x = 0; x < 8; x++) {
        s32 c0 = blk[x], c1 = blk[8 + x], c2 = blk[16 + x], c3 = blk[24 + x];
        s32 c4 = blk[32 + x], c5 = blk[40 + x], c6 = blk[48 + x], c7 = blk[56 + x];
        if ((c1 | c2 | c3 | c4 | c5 | c6 | c7) == 0) {
            if (c0 == 0) {
                for (int y = 0; y < 8; y++) tmp[y * 8 + x] = 0;
            } else {
                for (int y = 0; y < 8; y++) tmp[y * 8 + x] = (c0 * (s32)sc[y] + 0x8000) >> 16;
            }
            continue;
        }
        for (int y = 0; y < 8; y++) {
            s32 sum = c0 * sc[y] + c1 * sc[8 + y] + c2 * sc[16 + y] + c3 * sc[24 + y]
                    + c4 * sc[32 + y] + c5 * sc[40 + y] + c6 * sc[48 + y] + c7 * sc[56 + y];
            tmp[y * 8 + x] = (sum + 0x8000) >> 16;
        }
    }
    for (int y = 0; y < 8; y++) {
        const s32 *tr = &tmp[y * 8];
        s32 t0 = tr[0], t1 = tr[1], t2 = tr[2], t3 = tr[3];
        s32 t4 = tr[4], t5 = tr[5], t6 = tr[6], t7 = tr[7];
        if ((t1 | t2 | t3 | t4 | t5 | t6 | t7) == 0) {
            if (t0 == 0) {
                for (int x = 0; x < 8; x++) blk[y * 8 + x] = 0;
            } else {
                for (int x = 0; x < 8; x++) blk[y * 8 + x] = (s16)clamp_s8((t0 * (s32)sc[x] + 0x8000) >> 16);
            }
            continue;
        }
        for (int x = 0; x < 8; x++) {
            s32 sum = t0 * sc[x] + t1 * sc[8 + x] + t2 * sc[16 + x] + t3 * sc[24 + x]
                    + t4 * sc[32 + x] + t5 * sc[40 + x] + t6 * sc[48 + x] + t7 * sc[56 + x];
            blk[y * 8 + x] = (s16)clamp_s8((sum + 0x8000) >> 16);
        }
    }
}

static void mdec_decode_chunk(void)
{
    u32 depth = (S.mdec_cmd >> 27) & 3u; /* 0=4bpp, 1=8bpp, 2=24bpp, 3=15bpp */
    int is_signed = (S.mdec_cmd >> 26) & 1;
    u16 stp = (S.mdec_cmd & (1u << 25)) ? 0x8000u : 0u;
    const u16 *base = (const u16 *)W.mdec_in;
    const u16 *p = base + S.mdec_in_pos;
    const u16 *end = base + S.mdec_in_cnt * 2u;
    u32 out_p = 0;

    while (p < end && out_p + 768u <= sizeof(W.mdec_out)) {
        s16 b_cr[64], b_cb[64], b_y[4][64];
        if (depth <= 1u) { /* Monochrome 8x8 */
            int m0 = mdec_rl_decode_block(b_y[0], &p, end, S.mdec_iq_y);
            if (!m0) break;
            mdec_idct(b_y[0], m0);
            for (int i = 0; i < 64; i++) {
                s32 yv = clamp_s8(b_y[0][i]);
                u8 b8 = (u8)(yv + (is_signed ? 0 : 128));
                if (depth == 1u) {
                    W.mdec_out[out_p++] = b8;
                } else {
                    u8 n4 = (u8)(b8 >> 4);
                    if ((i & 1) == 0) W.mdec_out[out_p] = n4;
                    else              W.mdec_out[out_p++] |= (u8)(n4 << 4);
                }
            }
        } else { /* Color 16x16: Cr, Cb, Y0, Y1, Y2, Y3 */
            int mcr = mdec_rl_decode_block(b_cr, &p, end, S.mdec_iq_uv);
            if (!mcr) break;
            int mcb = mdec_rl_decode_block(b_cb, &p, end, S.mdec_iq_uv);
            if (!mcb) break;
            int ok_y = 1;
            for (int q = 0; q < 4; q++) {
                int my = mdec_rl_decode_block(b_y[q], &p, end, S.mdec_iq_y);
                if (!my) { ok_y = 0; break; }
                mdec_idct(b_y[q], my);
            }
            if (!ok_y) break;
            mdec_idct(b_cr, mcr);
            mdec_idct(b_cb, mcb);
            /* each Cr / Cb sample's terms once for its 2 x 2 pixels (they were worked out for every pixel); the
               pixels where they always went: row py, column px of the 16 x 16 */
            u32 bpp = (depth == 2u) ? 3u : 2u;
            for (int cy = 0; cy < 8; cy++) {
                for (int cx = 0; cx < 8; cx++) {
                    int cr = b_cr[cy * 8 + cx];
                    int cb = b_cb[cy * 8 + cx];
                    int dr = (359 * cr + 128) >> 8;
                    int dg = (88 * cb + 183 * cr + 128) >> 8;
                    int db = (454 * cb + 128) >> 8;
                    for (int sy = 0; sy < 2; sy++) {
                        int py = cy * 2 + sy;
                        for (int sx = 0; sx < 2; sx++) {
                            int px = cx * 2 + sx;
                            int q = ((py >> 3) << 1) | (px >> 3);
                            int yv = b_y[q][(py & 7) * 8 + (px & 7)];
                            s32 r = clamp_s8(yv + dr);
                            s32 g = clamp_s8(yv - dg);
                            s32 b = clamp_s8(yv + db);
                            u8 r8 = (u8)(r + (is_signed ? 0 : 128));
                            u8 g8 = (u8)(g + (is_signed ? 0 : 128));
                            u8 b8 = (u8)(b + (is_signed ? 0 : 128));
                            u32 o = out_p + (u32)(py * 16 + px) * bpp;
                            if (depth == 2u) {
                                W.mdec_out[o] = r8;
                                W.mdec_out[o + 1u] = g8;
                                W.mdec_out[o + 2u] = b8;
                            } else {
                                u16 c15 = (u16)(stp | ((u16)(b8 >> 3) << 10) | ((u16)(g8 >> 3) << 5) | (r8 >> 3));
                                W.mdec_out[o] = (u8)c15;
                                W.mdec_out[o + 1u] = (u8)(c15 >> 8);
                            }
                        }
                    }
                }
            }
            out_p += 256u * bpp;
        }
    }
    S.mdec_in_pos = (u32)(p - base);
    S.mdec_out_pos = 0;
    S.mdec_out_len = out_p;
    S.mdec_stat = (S.mdec_stat & ~(0x1FFu << 23)) | ((depth & 3u) << 25)
                | (out_p ? (1u << 29) : ((1u << 31) & ~(1u << 29)));
    if (!out_p)
        S.mdec_stat &= ~(1u << 29);
}

static void mdec_execute(void)
{
    u32 op = S.mdec_cmd >> 29;
    if (op == 2u) { /* Set Quant Table */
        const u8 *src = (const u8 *)W.mdec_in;
        for (int i = 0; i < 64; i++) S.mdec_iq_y[i] = src[i];
        if (S.mdec_cmd & 1u)
            for (int i = 0; i < 64; i++) S.mdec_iq_uv[i] = src[64 + i];
        S.mdec_stat &= ~(1u << 29);
        return;
    }
    if (op == 3u) { /* Set Scale Table */
        const s16 *src = (const s16 *)W.mdec_in;
        for (int i = 0; i < 64; i++) S.mdec_scale[i] = src[i];
        S.mdec_stat &= ~(1u << 29);
        return;
    }
    if (op == 1u) { /* Decode Macroblock(s) */
        S.mdec_in_pos = 0;
        mdec_decode_chunk();
    }
}

/* ---- SPU 24-Voice XA-ADPCM Synthesizer (48 kHz mono) ---- */
static const s32 adpcm_f0[5] = { 0,  60, 115,  98, 122 };
static const s32 adpcm_f1[5] = { 0,   0, -52, -55, -60 };

static void spu_decode_block(struct spu_voice *v)
{
    u32 a = (u32)v->cur_addr & 0x7FFF0u;
    u8 hdr = W.spu_ram[a];
    u8 shift = hdr & 0x0Fu;
    if (shift > 12u) shift = 9u;
    u8 filt = (hdr >> 4) & 0x07u;
    if (filt > 4u) filt = 0u;
    v->loop_flags = W.spu_ram[a + 1u];
    if ((v->loop_flags & 0x04u) && !v->has_manual_repeat)
        v->repeat_addr = (u16)(a >> 3);

    s32 p1 = v->prev1, p2 = v->prev2;
    s32 f0 = adpcm_f0[filt], f1 = adpcm_f1[filt];
    for (int i = 0; i < 28; i++) {
        u8 byte = W.spu_ram[a + 2u + (u32)(i >> 1)];
        int nib = (i & 1) ? (byte >> 4) : (byte & 0x0Fu);
        s32 s = (s32)(s16)((u16)nib << 12) >> shift;
        s += (p1 * f0 + p2 * f1 + 32) >> 6;
        if (s < -32768) s = -32768;
        if (s >  32767) s =  32767;
        v->samples[i] = (s16)s;
        p2 = p1;
        p1 = s;
    }
    v->prev1 = p1;
    v->prev2 = p2;
}

static inline void spu_update_voice_params(struct spu_voice *v)
{
    s16 vl = (v->vol_l & 0x8000u) ? 0x3FFF : (s16)(v->vol_l << 1);
    s16 vr = (v->vol_r & 0x8000u) ? 0x3FFF : (s16)(v->vol_r << 1);
    v->vol_mono = (s16)(((s32)vl + (s32)vr) >> 1);
    u32 st = ((u32)v->pitch * 147u) / 160u;
    v->step = (u16)(st > 0x3FFFu ? 0x3FFFu : st);
}

static void spu_key_on(u32 mask)
{
    for (int ch = 0; ch < 24; ch++) {
        if (!(mask & (1u << ch)))
            continue;
        struct spu_voice *v = &S.spu_v[ch];
        spu_update_voice_params(v);
        v->cur_addr = (int)((u32)v->start_addr << 3);
        v->phase = 0;
        v->prev1 = v->prev2 = 0;
        v->env = 0x7FFF;
        v->state = 1;
        v->has_manual_repeat = 0;
        S.spu_endx &= ~(1u << ch);
        S.spu_active_mask |= (1u << ch);
        spu_decode_block(v);
    }
}

static void spu_key_off(u32 mask)
{
    for (int ch = 0; ch < 24; ch++)
        if ((mask & (1u << ch)) && S.spu_v[ch].state)
            S.spu_v[ch].state = 4; /* release */
}

static void spu_step_lines(u32 n_lines)
{
    if (!S.sample_rate)
        return;
    /* Generate ~801 samples/frame @ 59.94 Hz NTSC or 960 samples/frame @ 50 Hz PAL */
    int eff_pal = (S.region_override == 'E') ? 1 : (S.region_override ? 0 : (int)S.is_pal);
    u32 target_per_frame = eff_pal ? (S.sample_rate / 50u) : ((S.sample_rate * 1001u) / 60000u);
    u32 total = S.aud_frac + target_per_frame * n_lines;
    u32 rem = total / PSX_LINES_NTSC;
    S.aud_frac = total % PSX_LINES_NTSC;
    if (S.aud_count + rem > PSX_AUD_MAX)
        rem = (S.aud_count < PSX_AUD_MAX) ? (PSX_AUD_MAX - S.aud_count) : 0u;
    if (!rem)
        return;
    if (!(S.spu_ctrl & 0x8000u) || !S.spu_active_mask) {
        for (u32 i = 0; i < rem; i++)
            W.aud_buf[S.aud_count++] = 0;
        return;
    }

    s32 mix_buf[64];
    while (rem > 0u) {
        u32 ns = rem > 64u ? 64u : rem;
        rem -= ns;
        for (u32 i = 0; i < ns; i++)
            mix_buf[i] = 0;

        u32 am = S.spu_active_mask;
        while (am) {
            u32 lsb = am & (0u - am);
            int ch = 31 - __builtin_clz(lsb);
            am ^= lsb;
            struct spu_voice *v = &S.spu_v[ch];
            if (!v->state) {
                S.spu_active_mask &= ~(1u << ch);
                continue;
            }
            u32 phase  = v->phase;
            u32 step   = v->step;
            s32 env    = v->env;
            s32 v_mono = v->vol_mono;
            u8  state  = v->state;
            for (u32 i = 0; i < ns; i++) {
                u32 idx = phase >> 12;
                s32 samp = v->samples[idx < 28u ? idx : 27u];
                samp = (samp * env) >> 15;
                mix_buf[i] += (samp * v_mono) >> 14;

                phase += step;
                while (phase >= (28u << 12)) {
                    phase -= (28u << 12);
                    if (v->loop_flags & 0x01u) { /* Loop end */
                        S.spu_endx |= (1u << ch);
                        if (v->loop_flags & 0x02u) { /* Loop repeat */
                            v->cur_addr = (int)((u32)v->repeat_addr << 3);
                            spu_decode_block(v);
                        } else {
                            state = 0;
                            env = 0;
                            S.spu_active_mask &= ~(1u << ch);
                            goto voice_done;
                        }
                    } else {
                        v->cur_addr = (v->cur_addr + 16) & 0x7FFF0;
                        spu_decode_block(v);
                    }
                }
                if (state == 4) { /* Release decay */
                    env -= 128;
                    if (env <= 0) {
                        env = 0;
                        state = 0;
                        S.spu_active_mask &= ~(1u << ch);
                        goto voice_done;
                    }
                }
            }
        voice_done:
            v->phase = phase;
            v->env   = env;
            v->state = state;
        }

        s16 *out = &W.aud_buf[S.aud_count];
        for (u32 i = 0; i < ns; i++) {
            s32 mix = mix_buf[i];
            if (mix > 32767) mix = 32767;
            else if (mix < -32768) mix = -32768;
            out[i] = (s16)mix;
        }
        S.aud_count += ns;
    }
}

/* ---- PlayStation 1 GPU (GP0 / GP1, 1024 x 512 BGR555 VRAM) ---- */
static const s8 gpu_dither[4][4] = {
    {-4,  0, -3,  1},
    { 2, -2,  3, -1},
    {-3,  1, -4,  0},
    { 3, -1,  2, -2}
};

static inline int sign_ext11(u32 v)
{
    v &= 0x7FFu;
    return (v & 0x400u) ? (int)(v | ~0x7FFu) : (int)v;
}

static const u8 clamp5_tab[96] = {
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
    16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
    31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,
    31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,
    31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31
};

static inline __attribute__((always_inline)) u8 clamp5(int v)
{
    if ((unsigned)(v + 16) < 96u)
        return clamp5_tab[v + 16];
    return v < 0 ? 0u : 31u;
}

static inline __attribute__((always_inline)) u16 gpu_blend(u16 bg, u16 fg, u32 abr)
{
    int br = bg & 31, bgc = (bg >> 5) & 31, bb = (bg >> 10) & 31;
    int fr = fg & 31, fgc = (fg >> 5) & 31, fb = (fg >> 10) & 31;
    int r, g, b;
    switch (abr & 3u) {
    case 0u: r = (br + fr) >> 1; g = (bgc + fgc) >> 1; b = (bb + fb) >> 1; break;
    case 1u: r = br + fr;        g = bgc + fgc;        b = bb + fb;        break;
    case 2u: r = br - fr;        g = bgc - fgc;        b = bb - fb;        break;
    default: r = br + (fr >> 2); g = bgc + (fgc >> 2); b = bb + (fb >> 2); break;
    }
    return (u16)(((u16)clamp5(b) << 10) | ((u16)clamp5(g) << 5) | clamp5(r));
}

static inline u16 gpu_fetch_texel(u32 u, u32 v, u32 tpage, u32 clut_word)
{
    /* Apply GP0(E2) Texture Window mask/offset */
    u = (u & ~((u32)S.tw_mx << 3)) | (((u32)S.tw_ox & S.tw_mx) << 3);
    v = (v & ~((u32)S.tw_my << 3)) | (((u32)S.tw_oy & S.tw_my) << 3);
    u &= 0xFFu;
    v &= 0xFFu;

    u32 tx_base = (tpage & 0x0Fu) * 64u;
    u32 ty_base = ((tpage >> 4) & 1u) * 256u;
    u32 depth = (tpage >> 7) & 3u;
    u32 cy = ((clut_word >> 6) & 0x1FFu);
    u32 cx = (clut_word & 0x3Fu) * 16u;

    if (depth == 0u) { /* 4bpp CLUT */
        u16 w16 = W.vram[((ty_base + v) & 511u) * VRAM_STRIDE + ((tx_base + (u >> 2)) & 1023u)];
        u32 idx = (w16 >> ((u & 3u) * 4u)) & 0x0Fu;
        return W.vram[cy * VRAM_STRIDE + ((cx + idx) & 1023u)];
    }
    if (depth == 1u) { /* 8bpp CLUT */
        u16 w16 = W.vram[((ty_base + v) & 511u) * VRAM_STRIDE + ((tx_base + (u >> 1)) & 1023u)];
        u32 idx = (w16 >> ((u & 1u) * 8u)) & 0xFFu;
        return W.vram[cy * VRAM_STRIDE + ((cx + idx) & 1023u)];
    }
    /* 15bpp direct */
    return W.vram[((ty_base + v) & 511u) * VRAM_STRIDE + ((tx_base + u) & 1023u)];
}

static inline __attribute__((always_inline)) void gpu_plot_pixel(int x, int y, int r8, int g8, int b8,
                                                                 int do_dither, int is_semi, u32 abr, u16 extra_mask)
{
    u16 *dst = &W.vram[y * VRAM_STRIDE + x];
    if (S.check_mask && (*dst & 0x8000u))
        return;
    if (do_dither && S.dither) {
        int d = gpu_dither[y & 3][x & 3];
        r8 += d; g8 += d; b8 += d;
    }
    u8 r5 = clamp5(r8 >> 3), g5 = clamp5(g8 >> 3), b5 = clamp5(b8 >> 3);
    u16 fg = (u16)(((u16)b5 << 10) | ((u16)g5 << 5) | r5);
    if (is_semi)
        fg = gpu_blend(*dst, fg, abr);
    *dst = (u16)(fg | extra_mask | (S.set_mask ? 0x8000u : 0u));
}

struct gpu_vtx {
    int x, y;
    int r, g, b;
    int u, v;
};

static u32 gpu_recip_dy[512];
static u32 gpu_inv_area[1024];
static u16 clamp5_g[96];
static u16 clamp5_b[96];

/* ---- textured spans: opaque, no mask test, no interlace copy (gpu_draw_tri_slow's common cases) ----
   One loop per texture depth and raw / modulated, everything in registers (the general loop kept ~16 values
   on the stack).  The pixels are the general loop's: texel = the texture window's (u, v); 0 = transparent;
   raw: texel | mask; modulated: each 5-bit channel t times the colour c (8.12 fixed point, flat = steps 0)
   plus the dither d, clamp(((t * c >> 4) + d) >> 3) = clamp((t * c + 16 d) >> 7). */
#define SPAN_CL_OFS 64                  /* the clamp table takes (x >> 7) from -64 to 447 */
static u16 span_cl[2][3 * 512];         /* clamp(i - 64, 0, 31): red as it is, green << 5 (+512), blue << 10 (+1024);
                                           [1]: the same with red | 0x8000 (the mask bit set: span_mod_body) */

struct gpu_span {
    const u8 *tex8;                     /* T 0 / 1 / 3: the texture page as bytes (2 * VRAM_STRIDE a row), from the
                                           texture window's offsets: row ov, byte ou (T 0: ou / 2) */
    const u16 *tex16;                   /* T 2: the texture page's pixels (VRAM_STRIDE a row), from row ov, x ou */
    const u16 *clut;                    /* T 0: 16 colours; T 1: the CLUT (its x added); T 3: its VRAM row */
    u32 cx;                             /* T 3 (8-bit with a CLUT that wraps at x 1024): the CLUT's x */
    u32 au12, av12;                     /* texture window: u = ((u_c & au12) >> 12) | ou, v the same (ou, ov: in
                                           tex8 / tex16) */
    u32 mask_or;
    s32 d16[4];                         /* the dither row times 16, by x & 3 (zeros: none) */
    u32 dw;                             /* the same as bytes d16 + 128, the first pixel's in the low byte (rotated
                                           right 8 a pixel): (t * c + d16 + 128) >> 7 is one more than the
                                           value wanted, so the clamp table is read one entry lower */
    const u8 *clb;                      /* span_mod_body's tables as bytes: span_cl[mask_or != 0] + SPAN_CL_OFS - 1
                                           (a pointer read from here, not a constant: one base register for the
                                           three tables, the mask bit in the red one -- the loop's values fit in
                                           registers, none read from the stack a pixel) */
};

/* dither words for span_mod_body: [y & 3] = bytes d16 + 128 for x & 3 = 0..3; [4]: no dither */
static u32 span_dw[5];

static inline __attribute__((always_inline)) u32 span_texel(const struct gpu_span *sp, int T, u32 u_c, u32 v_c)
{
    /* (the window's ou / ov are in tex8 / tex16 already: bits the masks clear, so | is +; ou even, as T 0 needs) */
    u32 uu = (u_c & sp->au12) >> 12;
    u32 vv = (v_c & sp->av12) >> 12;
    if (T == 0) {
        u32 b = sp->tex8[vv * (2u * VRAM_STRIDE) + (uu >> 1)];
        return sp->clut[(b >> ((uu & 1u) << 2)) & 15u];
    }
    if (T == 1)
        return sp->clut[sp->tex8[vv * (2u * VRAM_STRIDE) + uu]];
    if (T == 3)
        return sp->clut[(sp->cx + sp->tex8[vv * (2u * VRAM_STRIDE) + uu]) & 1023u];
    return sp->tex16[vv * VRAM_STRIDE + uu];
}

static inline __attribute__((always_inline)) u32 span_mod(u32 t, s32 r_c, s32 g_c, s32 b_c, s32 d16, u32 mask_or)
{
    s32 r = (s32)((t & 31u) * (u32)(r_c >> 12));
    s32 g = (s32)(((t >> 5) & 31u) * (u32)(g_c >> 12));
    s32 b = (s32)(((t >> 10) & 31u) * (u32)(b_c >> 12));
    const u16 *cl = span_cl[0] + SPAN_CL_OFS;
    return (u32)cl[(r + d16) >> 7] | cl[512 + ((g + d16) >> 7)] | cl[1024 + ((b + d16) >> 7)] |
           (t & 0x8000u) | mask_or;
}

/* n pixels from dst, raw: texel | mask */
static inline __attribute__((always_inline)) void span_raw_body(const struct gpu_span *sp, int T, u16 *dst, int n,
                                                                  u32 u_c, u32 v_c, s32 du, s32 dv)
{
    u32 mask_or = sp->mask_or;
    for (u16 *end = dst + n; dst < end; dst++, u_c += (u32)du, v_c += (u32)dv) {
        u32 t = span_texel(sp, T, u_c, v_c);
        if (t)
            *dst = (u16)(t | mask_or);
    }
}

/* modulated (sp->dw: the dither word for the first pixel) */
static inline __attribute__((always_inline)) void span_mod_body(const struct gpu_span *sp, int T, u16 *dst, int x0,
                                                                  int n, u32 u_c, u32 v_c, s32 du, s32 dv,
                                                                  s32 r_c, s32 g_c, s32 b_c, s32 dr, s32 dg, s32 db)
{
    (void)x0;
    u32 dw = sp->dw;
    const u8 *cl = sp->clb;                             /* (bytes: the tables' offsets fold) */
    for (u16 *end = dst + n; dst < end; dst++) {
        u32 t = span_texel(sp, T, u_c, v_c);
        if (t) {
            s32 d = (s32)(dw & 0xFFu);                     /* d16 + 128 */
            s32 r = (s32)((t & 31u) * (u32)(r_c >> 12)) + d;
            s32 g = (s32)(((t >> 5) & 31u) * (u32)(g_c >> 12)) + d;
            s32 b = (s32)(((t >> 10) & 31u) * (u32)(b_c >> 12)) + d;
            *dst = (u16)(*(const u16 *)(cl + ((r >> 7) << 1)) | *(const u16 *)(cl + 1024 + ((g >> 7) << 1)) |
                         *(const u16 *)(cl + 2048 + ((b >> 7) << 1)) | (t & 0x8000u));
        }
        dw = (dw >> 8) | (dw << 24);
        u_c += (u32)du; v_c += (u32)dv; r_c += dr; g_c += dg; b_c += db;
    }
}

/* semi-transparent (no mask test, no interlace copy): a texel with bit 15 set is blended with what is there
   (gpu_blend, mode abr), the others are drawn as opaque; raw or modulated as above */
static inline __attribute__((always_inline)) void span_semi_body(const struct gpu_span *sp, int T, int MOD, u16 *dst,
                                                                   int x0, int n, u32 u_c, u32 v_c, s32 du, s32 dv,
                                                                   s32 r_c, s32 g_c, s32 b_c, s32 dr, s32 dg, s32 db,
                                                                   u32 abr)
{
    u32 mask_or = sp->mask_or;
    const s32 *d16 = sp->d16;
    u32 x = (u32)x0;
    for (u16 *end = dst + n; dst < end; dst++, x++) {
        u32 t = span_texel(sp, T, u_c, v_c);
        if (t) {
            u32 fg = MOD ? (span_mod(t, r_c, g_c, b_c, d16[x & 3u], 0u) & 0x7FFFu) : (t & 0x7FFFu);
            if (t & 0x8000u)
                fg = gpu_blend(*dst, (u16)fg, abr);
            *dst = (u16)(fg | (t & 0x8000u) | mask_or);
        }
        u_c += (u32)du; v_c += (u32)dv;
        if (MOD) { r_c += dr; g_c += dg; b_c += db; }
    }
}

#define SPAN_SEMI(name, T, MOD)                                                                                     \
static void __attribute__((noinline)) name(const struct gpu_span *sp, u16 *dst, int x0, int n, u32 u, u32 v,     \
                                           s32 du, s32 dv, s32 r, s32 g, s32 b, s32 dr, s32 dg, s32 db, u32 abr)  \
{ span_semi_body(sp, T, MOD, dst, x0, n, u, v, du, dv, r, g, b, dr, dg, db, abr); }
SPAN_SEMI(span_semi_raw4, 0, 0)
SPAN_SEMI(span_semi_raw8, 1, 0)
SPAN_SEMI(span_semi_raw8w, 3, 0)
SPAN_SEMI(span_semi_raw15, 2, 0)
SPAN_SEMI(span_semi_mod4, 0, 1)
SPAN_SEMI(span_semi_mod8, 1, 1)
SPAN_SEMI(span_semi_mod8w, 3, 1)
SPAN_SEMI(span_semi_mod15, 2, 1)

/* untextured, semi-transparent: the colour (8.12, flat = steps 0) plus the dither d (d4: by x & 3, zeros: none),
   clamp((c + d) >> 3), blended */
static void __attribute__((noinline)) span_semi_notex(u16 *dst, int x0, int n, s32 r_c, s32 g_c, s32 b_c, s32 dr,
                                                      s32 dg, s32 db, const s32 *d4, u32 abr, u32 mask_or)
{
    const u16 *cl = span_cl[0] + SPAN_CL_OFS;
    u32 x = (u32)x0;
    for (u16 *end = dst + n; dst < end; dst++, x++, r_c += dr, g_c += dg, b_c += db) {
        s32 d = d4[x & 3u];
        u32 fg = (u32)cl[((r_c >> 12) + d) >> 3] | cl[512 + (((g_c >> 12) + d) >> 3)] |
                 cl[1024 + (((b_c >> 12) + d) >> 3)];
        *dst = (u16)(gpu_blend(*dst, (u16)fg, abr) | mask_or);
    }
}

static void __attribute__((noinline)) span_raw4(const struct gpu_span *sp, u16 *dst, int n, u32 u, u32 v, s32 du, s32 dv)
{ span_raw_body(sp, 0, dst, n, u, v, du, dv); }
static void __attribute__((noinline)) span_raw8(const struct gpu_span *sp, u16 *dst, int n, u32 u, u32 v, s32 du, s32 dv)
{ span_raw_body(sp, 1, dst, n, u, v, du, dv); }
static void __attribute__((noinline)) span_raw8w(const struct gpu_span *sp, u16 *dst, int n, u32 u, u32 v, s32 du, s32 dv)
{ span_raw_body(sp, 3, dst, n, u, v, du, dv); }
static void __attribute__((noinline)) span_raw15(const struct gpu_span *sp, u16 *dst, int n, u32 u, u32 v, s32 du, s32 dv)
{ span_raw_body(sp, 2, dst, n, u, v, du, dv); }
static void __attribute__((noinline)) span_mod4(const struct gpu_span *sp, u16 *dst, int x0, int n, u32 u, u32 v,
                                               s32 du, s32 dv, s32 r, s32 g, s32 b, s32 dr, s32 dg, s32 db)
{ span_mod_body(sp, 0, dst, x0, n, u, v, du, dv, r, g, b, dr, dg, db); }
static void __attribute__((noinline)) span_mod8(const struct gpu_span *sp, u16 *dst, int x0, int n, u32 u, u32 v,
                                               s32 du, s32 dv, s32 r, s32 g, s32 b, s32 dr, s32 dg, s32 db)
{ span_mod_body(sp, 1, dst, x0, n, u, v, du, dv, r, g, b, dr, dg, db); }
static void __attribute__((noinline)) span_mod8w(const struct gpu_span *sp, u16 *dst, int x0, int n, u32 u, u32 v,
                                                s32 du, s32 dv, s32 r, s32 g, s32 b, s32 dr, s32 dg, s32 db)
{ span_mod_body(sp, 3, dst, x0, n, u, v, du, dv, r, g, b, dr, dg, db); }
static void __attribute__((noinline)) span_mod15(const struct gpu_span *sp, u16 *dst, int x0, int n, u32 u, u32 v,
                                                s32 du, s32 dv, s32 r, s32 g, s32 b, s32 dr, s32 dg, s32 db)
{ span_mod_body(sp, 2, dst, x0, n, u, v, du, dv, r, g, b, dr, dg, db); }

static void __attribute__((noinline)) gpu_span_tex4_flat_notw(u16 *dst, int count, int lace2,
                                                              const u8 *tpage_u8, const s32 *clut_baked,
                                                              u32 u24, u32 v24, u32 du24, u32 dv24)
{
    if (lace2) {
        for (int i = 0; i < count; i++, dst++, u24 += du24, v24 += dv24) {
            u8 b8 = tpage_u8[(v24 >> 24) * (2u * VRAM_STRIDE) + (u24 >> 25)];
            s32 px = clut_baked[(b8 >> ((u24 >> 22) & 4u)) & 0x0Fu];
            if (px >= 0) {
                dst[0] = (u16)px;
                dst[VRAM_STRIDE] = (u16)px;
            }
        }
    } else {
        int i = 0;
        for (; i + 1 < count; i += 2, dst += 2) {
            u32 u0 = u24, v0 = v24;
            u32 u1 = u0 + du24, v1 = v0 + dv24;
            u24 = u1 + du24; v24 = v1 + dv24;
            u8 b0 = tpage_u8[(v0 >> 24) * (2u * VRAM_STRIDE) + (u0 >> 25)];
            u8 b1 = tpage_u8[(v1 >> 24) * (2u * VRAM_STRIDE) + (u1 >> 25)];
            s32 p0 = clut_baked[(b0 >> ((u0 >> 22) & 4u)) & 0x0Fu];
            s32 p1 = clut_baked[(b1 >> ((u1 >> 22) & 4u)) & 0x0Fu];
            if (p0 >= 0) dst[0] = (u16)p0;
            if (p1 >= 0) dst[1] = (u16)p1;
        }
        if (i < count) {
            u8 b8 = tpage_u8[(v24 >> 24) * (2u * VRAM_STRIDE) + (u24 >> 25)];
            s32 px = clut_baked[(b8 >> ((u24 >> 22) & 4u)) & 0x0Fu];
            if (px >= 0)
                dst[0] = (u16)px;
        }
    }
}

static void __attribute__((noinline)) gpu_span_tex4_gour_notw(u16 *dst, int xl, int xr, int lace2,
                                                              int use_dither, const u8 *tpage_u8,
                                                              const s32 *clut_rm, const s8 *drow,
                                                              u32 u24, u32 v24, u32 du24, u32 dv24,
                                                              s32 r_c, s32 g_c, s32 b_c,
                                                              s32 dr_dx, s32 dg_dx, s32 db_dx)
{
    if (!use_dither && !lace2) {
        int count = xr - xl + 1;
        int i = 0;
        s32 dr2 = dr_dx * 2, dg2 = dg_dx * 2, db2 = db_dx * 2;
        for (; i + 1 < count; i += 2, dst += 2) {
            u32 u0 = u24, v0 = v24;
            u32 u1 = u0 + du24, v1 = v0 + dv24;
            u24 = u1 + du24; v24 = v1 + dv24;
            u8 b0 = tpage_u8[(v0 >> 24) * (2u * VRAM_STRIDE) + (u0 >> 25)];
            u8 b1 = tpage_u8[(v1 >> 24) * (2u * VRAM_STRIDE) + (u1 >> 25)];
            s32 cg0 = clut_rm[(b0 >> ((u0 >> 22) & 4u)) & 0x0Fu];
            s32 cg1 = clut_rm[(b1 >> ((u1 >> 22) & 4u)) & 0x0Fu];
            s32 r0 = r_c >> 12, g0 = g_c >> 12, bl0 = b_c >> 12;
            s32 r1 = (r_c + dr_dx) >> 12, g1 = (g_c + dg_dx) >> 12, bl1 = (b_c + db_dx) >> 12;
            r_c += dr2; g_c += dg2; b_c += db2;
            if (cg0 >= 0) {
                int tr = ((cg0 & 31) * r0) >> 7;
                int tg = (((cg0 >> 5) & 31) * g0) >> 7;
                int tb = (((cg0 >> 10) & 31) * bl0) >> 7;
                dst[0] = (u16)(clamp5_b[tb + 16] | clamp5_g[tg + 16] | clamp5_tab[tr + 16] | (cg0 & 0x8000));
            }
            if (cg1 >= 0) {
                int tr = ((cg1 & 31) * r1) >> 7;
                int tg = (((cg1 >> 5) & 31) * g1) >> 7;
                int tb = (((cg1 >> 10) & 31) * bl1) >> 7;
                dst[1] = (u16)(clamp5_b[tb + 16] | clamp5_g[tg + 16] | clamp5_tab[tr + 16] | (cg1 & 0x8000));
            }
        }
        if (i < count) {
            u8 b8 = tpage_u8[(v24 >> 24) * (2u * VRAM_STRIDE) + (u24 >> 25)];
            s32 cg = clut_rm[(b8 >> ((u24 >> 22) & 4u)) & 0x0Fu];
            if (cg >= 0) {
                int tr = ((cg & 31) * (r_c >> 12)) >> 7;
                int tg = (((cg >> 5) & 31) * (g_c >> 12)) >> 7;
                int tb = (((cg >> 10) & 31) * (b_c >> 12)) >> 7;
                dst[0] = (u16)(clamp5_b[tb + 16] | clamp5_g[tg + 16] | clamp5_tab[tr + 16] | (cg & 0x8000));
            }
        }
        return;
    }

    if (use_dither) {
        if (lace2) {
            for (int x = xl; x <= xr; x++, dst++, u24 += du24, v24 += dv24, r_c += dr_dx, g_c += dg_dx, b_c += db_dx) {
                u8 b8 = tpage_u8[(v24 >> 24) * (2u * VRAM_STRIDE) + (u24 >> 25)];
                s32 cg = clut_rm[(b8 >> ((u24 >> 22) & 4u)) & 0x0Fu];
                if (cg >= 0) {
                    int d = drow[x & 3];
                    int tr = ((cg & 31) * (r_c >> 12)) >> 4;
                    int tg = (((cg >> 5) & 31) * (g_c >> 12)) >> 4;
                    int tb = (((cg >> 10) & 31) * (b_c >> 12)) >> 4;
                    u16 px = (u16)(clamp5_b[((tb + d) >> 3) + 16] |
                                   clamp5_g[((tg + d) >> 3) + 16] |
                                   clamp5_tab[((tr + d) >> 3) + 16] | (cg & 0x8000));
                    dst[0] = px;
                    dst[VRAM_STRIDE] = px;
                }
            }
        } else {
            for (int x = xl; x <= xr; x++, dst++, u24 += du24, v24 += dv24, r_c += dr_dx, g_c += dg_dx, b_c += db_dx) {
                u8 b8 = tpage_u8[(v24 >> 24) * (2u * VRAM_STRIDE) + (u24 >> 25)];
                s32 cg = clut_rm[(b8 >> ((u24 >> 22) & 4u)) & 0x0Fu];
                if (cg >= 0) {
                    int d = drow[x & 3];
                    int tr = ((cg & 31) * (r_c >> 12)) >> 4;
                    int tg = (((cg >> 5) & 31) * (g_c >> 12)) >> 4;
                    int tb = (((cg >> 10) & 31) * (b_c >> 12)) >> 4;
                    dst[0] = (u16)(clamp5_b[((tb + d) >> 3) + 16] |
                                   clamp5_g[((tg + d) >> 3) + 16] |
                                   clamp5_tab[((tr + d) >> 3) + 16] | (cg & 0x8000));
                }
            }
        }
    } else {
        for (int x = xl; x <= xr; x++, dst++, u24 += du24, v24 += dv24, r_c += dr_dx, g_c += dg_dx, b_c += db_dx) {
            u8 b8 = tpage_u8[(v24 >> 24) * (2u * VRAM_STRIDE) + (u24 >> 25)];
            s32 cg = clut_rm[(b8 >> ((u24 >> 22) & 4u)) & 0x0Fu];
            if (cg >= 0) {
                int tr = ((cg & 31) * (r_c >> 12)) >> 7;
                int tg = (((cg >> 5) & 31) * (g_c >> 12)) >> 7;
                int tb = (((cg >> 10) & 31) * (b_c >> 12)) >> 7;
                u16 px = (u16)(clamp5_b[tb + 16] | clamp5_g[tg + 16] | clamp5_tab[tr + 16] | (cg & 0x8000));
                dst[0] = px;
                dst[VRAM_STRIDE] = px;
            }
        }
    }
}

/* the rows of a triangle drawn by the span loops (gpu_draw_tri_slow's set-up, no interlace copy): the same
   edges and refinement, its products stepped from row to row instead of multiplied out (the same values, mod
   2^32), in a small function whose values stay in registers */
struct tri_rows {
    int x0, y0, x1, y1, x2, y2;         /* sorted by y */
    s32 s01, s02, s12;
    int minx, maxx, miny, maxy, y_step;
    s32 e0_row, e1_row, e2_row, a12, a20, a01, step_e0, step_e1, step_e2;
    u32 u_row, v_row, r_row, g_row, b_row;
    s32 du_dx, dv_dx, du_dy, dv_dy, dr_dx, dg_dx, db_dx, dr_dy, dg_dy, db_dy;
    s32 fr, fg, fb;                     /* flat: the colour << 12 */
    int gouraud, kind, t, dither;
    u32 abr, mask_or;
};

static void __attribute__((noinline)) gpu_tri_span_rows(const struct tri_rows *tr, struct gpu_span *sp)
{
    int y = tr->miny, y_step = tr->y_step, x0 = tr->x0, y0 = tr->y0, x1 = tr->x1, y1 = tr->y1;
    int minx = tr->minx, maxx = tr->maxx, kind = tr->kind, gouraud = tr->gouraud;
    u32 xa = (u32)(x0 << 16) + (u32)tr->s02 * (u32)(y - y0), step_xa = (u32)tr->s02 * (u32)y_step;
    int in_bot = (y >= y1);
    u32 xb, step_xb;
    if (!in_bot) {
        xb = (u32)(x0 << 16) + (u32)tr->s01 * (u32)(y - y0);
        step_xb = (u32)tr->s01 * (u32)y_step;
    } else {
        xb = (tr->y2 > y1) ? (u32)(x1 << 16) + (u32)tr->s12 * (u32)(y - y1) : (u32)(x1 << 16);
        step_xb = (u32)tr->s12 * (u32)y_step;
    }
    s32 e0 = tr->e0_row, e1 = tr->e1_row, e2 = tr->e2_row, a12 = tr->a12, a20 = tr->a20, a01 = tr->a01;
    u32 u_row = tr->u_row, v_row = tr->v_row, r_row = tr->r_row, g_row = tr->g_row, b_row = tr->b_row;
    for (; y <= tr->maxy; y += y_step) {
        if (!in_bot && y >= y1) {
            in_bot = 1;
            xb = (tr->y2 > y1) ? (u32)(x1 << 16) + (u32)tr->s12 * (u32)(y - y1) : (u32)(x1 << 16);
            step_xb = (u32)tr->s12 * (u32)y_step;
        }
        s32 lo = (s32)xa < (s32)xb ? (s32)xa : (s32)xb, hi = (s32)xa > (s32)xb ? (s32)xa : (s32)xb;
        int xl = (lo >> 16) - 1, xr = (hi >> 16) + 2;
        if (xl < minx) xl = minx;
        if (xr > maxx) xr = maxx;
        s32 dx0 = xl - minx;
        s32 w0 = e0 + a12 * dx0, w1 = e1 + a20 * dx0, w2 = e2 + a01 * dx0;
        while (xl <= xr && (w0 | w1 | w2) < 0) { xl++; w0 += a12; w1 += a20; w2 += a01; }
        if (xl <= xr) {
            s32 dx1 = xr - minx;
            s32 r0 = e0 + a12 * dx1, r1 = e1 + a20 * dx1, r2 = e2 + a01 * dx1;
            while (xr >= xl && (r0 | r1 | r2) < 0) { xr--; r0 -= a12; r1 -= a20; r2 -= a01; }
        }
        if (xl <= xr) {
            u32 dx = (u32)(xl - minx);
            int n = xr - xl + 1;
            u16 *d = W.vram + y * VRAM_STRIDE + xl;
            u32 uc = u_row + (u32)tr->du_dx * dx, vc = v_row + (u32)tr->dv_dx * dx;
            s32 du = tr->du_dx, dv = tr->dv_dx;
            if (kind == 1 || kind == 3) {
                switch ((kind == 3 ? 4 : 0) + tr->t) {
                case 0: span_raw4(sp, d, n, uc, vc, du, dv); break;
                case 1: span_raw8(sp, d, n, uc, vc, du, dv); break;
                case 2: span_raw15(sp, d, n, uc, vc, du, dv); break;
                case 3: span_raw8w(sp, d, n, uc, vc, du, dv); break;
                case 4: span_semi_raw4(sp, d, xl, n, uc, vc, du, dv, 0, 0, 0, 0, 0, 0, tr->abr); break;
                case 5: span_semi_raw8(sp, d, xl, n, uc, vc, du, dv, 0, 0, 0, 0, 0, 0, tr->abr); break;
                case 6: span_semi_raw15(sp, d, xl, n, uc, vc, du, dv, 0, 0, 0, 0, 0, 0, tr->abr); break;
                default: span_semi_raw8w(sp, d, xl, n, uc, vc, du, dv, 0, 0, 0, 0, 0, 0, tr->abr); break;
                }
            } else {
                s32 r_c, g_c, b_c, sdr = 0, sdg = 0, sdb = 0;
                if (gouraud) {
                    r_c = (s32)(r_row + (u32)tr->dr_dx * dx);
                    g_c = (s32)(g_row + (u32)tr->dg_dx * dx);
                    b_c = (s32)(b_row + (u32)tr->db_dx * dx);
                    sdr = tr->dr_dx;
                    sdg = tr->dg_dx;
                    sdb = tr->db_dx;
                } else {
                    r_c = tr->fr;
                    g_c = tr->fg;
                    b_c = tr->fb;
                }
                if (kind == 2) {
                    u32 w = span_dw[tr->dither ? (y & 3) : 4], s = ((u32)xl & 3u) * 8u;
                    sp->dw = s ? (w >> s) | (w << (32u - s)) : w;
                    switch (tr->t) {
                    case 0: span_mod4(sp, d, xl, n, uc, vc, du, dv, r_c, g_c, b_c, sdr, sdg, sdb); break;
                    case 1: span_mod8(sp, d, xl, n, uc, vc, du, dv, r_c, g_c, b_c, sdr, sdg, sdb); break;
                    case 2: span_mod15(sp, d, xl, n, uc, vc, du, dv, r_c, g_c, b_c, sdr, sdg, sdb); break;
                    default: span_mod8w(sp, d, xl, n, uc, vc, du, dv, r_c, g_c, b_c, sdr, sdg, sdb); break;
                    }
                } else {                        /* 4: semi-transparent modulated */
                    const s8 *drow = gpu_dither[y & 3];
                    for (int k = 0; k < 4; k++)
                        sp->d16[k] = tr->dither ? (s32)drow[k] * 16 : 0;
                    switch (tr->t) {
                    case 0: span_semi_mod4(sp, d, xl, n, uc, vc, du, dv, r_c, g_c, b_c, sdr, sdg, sdb, tr->abr); break;
                    case 1: span_semi_mod8(sp, d, xl, n, uc, vc, du, dv, r_c, g_c, b_c, sdr, sdg, sdb, tr->abr); break;
                    case 2: span_semi_mod15(sp, d, xl, n, uc, vc, du, dv, r_c, g_c, b_c, sdr, sdg, sdb, tr->abr); break;
                    default: span_semi_mod8w(sp, d, xl, n, uc, vc, du, dv, r_c, g_c, b_c, sdr, sdg, sdb, tr->abr); break;
                    }
                }
            }
        }
        xa += step_xa;
        xb += step_xb;
        e0 += tr->step_e0;
        e1 += tr->step_e1;
        e2 += tr->step_e2;
        u_row += (u32)tr->du_dy;
        v_row += (u32)tr->dv_dy;
        if (gouraud) {
            r_row += (u32)tr->dr_dy;
            g_row += (u32)tr->dg_dy;
            b_row += (u32)tr->db_dy;
        }
    }
}

static void __attribute__((noinline)) gpu_draw_tri_slow(struct gpu_vtx v0, struct gpu_vtx v1, struct gpu_vtx v2,
                                                        int minx, int maxx, int miny, int maxy, s32 area,
                                                        u8 op, u32 tpage, u32 clut)
{
    int lace = (S.disp_h > 240 && S.clip_y2 >= 240);
    int y_step = lace ? 2 : 1;
    int is_gouraud = (op & 0x10u) != 0u;
    int is_tex     = (op & 0x04u) != 0u && !(S.tex_disable && (tpage & 0x800u));
    int is_semi    = (op & 0x02u) != 0u;
    int is_raw     = (op & 0x01u) != 0u;
    int use_dither = (is_gouraud || (is_tex && !is_raw)) && S.dither && (S.skip_render == 0u);
    u32 abr        = is_tex ? ((tpage >> 5) & 3u) : ((S.gpustat >> 5) & 3u);
    u16 mask_or    = S.set_mask ? 0x8000u : 0u;

    int x0 = v0.x, y0 = v0.y, x1 = v1.x, y1 = v1.y, x2 = v2.x, y2 = v2.y;
    if (y0 > y1) { int t = x0; x0 = x1; x1 = t; t = y0; y0 = y1; y1 = t; }
    if (y1 > y2) { int t = x1; x1 = x2; x2 = t; t = y1; y1 = y2; y2 = t; }
    if (y0 > y1) { int t = x0; x0 = x1; x1 = t; t = y0; y0 = y1; y1 = t; }

    s32 s02 = (y2 > y0) ? ((x2 - x0) * (s32)gpu_recip_dy[y2 - y0]) : 0;
    s32 s01 = (y1 > y0) ? ((x1 - x0) * (s32)gpu_recip_dy[y1 - y0]) : 0;
    s32 s12 = (y2 > y1) ? ((x2 - x1) * (s32)gpu_recip_dy[y2 - y1]) : 0;

    int a01 = v0.y - v1.y, b01 = v1.x - v0.x;
    int a12 = v1.y - v2.y, b12 = v2.x - v1.x;
    int a20 = v2.y - v0.y, b20 = v0.x - v2.x;
    int bias0 = (a12 < 0 || (a12 == 0 && b12 < 0)) ? 0 : -1;
    int bias1 = (a20 < 0 || (a20 == 0 && b20 < 0)) ? 0 : -1;
    int bias2 = (a01 < 0 || (a01 == 0 && b01 < 0)) ? 0 : -1;

    s32 e0_row = (v2.x - v1.x) * (miny - v1.y) - (v2.y - v1.y) * (minx - v1.x) + bias0;
    s32 e1_row = (v0.x - v2.x) * (miny - v2.y) - (v0.y - v2.y) * (minx - v2.x) + bias1;
    s32 e2_row = (v1.x - v0.x) * (miny - v0.y) - (v1.y - v0.y) * (minx - v0.x) + bias2;
    s32 step_e0 = b12 * y_step, step_e1 = b20 * y_step, step_e2 = b01 * y_step;

    s32 inv_area = (area <= 1) ? (1 << 30) : (s32)((area < 1024) ? gpu_inv_area[area] : ((1u << 30) / (u32)area));
    s32 w0_base = e0_row - bias0, w1_base = e1_row - bias1, w2_base = e2_row - bias2;

    u32 r_row = 0, g_row = 0, b_row = 0;
    s32 dr_dx = 0, dg_dx = 0, db_dx = 0, dr_dy = 0, dg_dy = 0, db_dy = 0;
    if (is_gouraud) {
        r_row = (u32)(((s64)(w0_base * v0.r + w1_base * v1.r + w2_base * v2.r) * (s64)inv_area + (1LL << 29)) >> 18);
        g_row = (u32)(((s64)(w0_base * v0.g + w1_base * v1.g + w2_base * v2.g) * (s64)inv_area + (1LL << 29)) >> 18);
        b_row = (u32)(((s64)(w0_base * v0.b + w1_base * v1.b + w2_base * v2.b) * (s64)inv_area + (1LL << 29)) >> 18);
        dr_dx = (s32)(((s64)(a12 * v0.r + a20 * v1.r + a01 * v2.r) * (s64)inv_area) >> 18);
        dg_dx = (s32)(((s64)(a12 * v0.g + a20 * v1.g + a01 * v2.g) * (s64)inv_area) >> 18);
        db_dx = (s32)(((s64)(a12 * v0.b + a20 * v1.b + a01 * v2.b) * (s64)inv_area) >> 18);
        dr_dy = (s32)(((s64)(b12 * v0.r + b20 * v1.r + b01 * v2.r) * (s64)inv_area) >> 18) * y_step;
        dg_dy = (s32)(((s64)(b12 * v0.g + b20 * v1.g + b01 * v2.g) * (s64)inv_area) >> 18) * y_step;
        db_dy = (s32)(((s64)(b12 * v0.b + b20 * v1.b + b01 * v2.b) * (s64)inv_area) >> 18) * y_step;
    }

    u32 u_row = 0, v_row = 0;
    s32 du_dx = 0, dv_dx = 0, du_dy = 0, dv_dy = 0;
    u32 tx_base = 0, ty_base = 0, depth = 0, cy = 0, cx = 0;
    u32 tw_and_u = 0xFFu, tw_or_u = 0u, tw_and_v = 0xFFu, tw_or_v = 0u;
    u16 clut4_raw[16];

    if (is_tex) {
        u_row = (u32)(((s64)(w0_base * v0.u + w1_base * v1.u + w2_base * v2.u) * (s64)inv_area + (1LL << 29)) >> 18);
        v_row = (u32)(((s64)(w0_base * v0.v + w1_base * v1.v + w2_base * v2.v) * (s64)inv_area + (1LL << 29)) >> 18);
        du_dx = (s32)(((s64)(a12 * v0.u + a20 * v1.u + a01 * v2.u) * (s64)inv_area) >> 18);
        dv_dx = (s32)(((s64)(a12 * v0.v + a20 * v1.v + a01 * v2.v) * (s64)inv_area) >> 18);
        du_dy = (s32)(((s64)(b12 * v0.u + b20 * v1.u + b01 * v2.u) * (s64)inv_area) >> 18) * y_step;
        dv_dy = (s32)(((s64)(b12 * v0.v + b20 * v1.v + b01 * v2.v) * (s64)inv_area) >> 18) * y_step;
        tx_base  = (tpage & 0x0Fu) * 64u;
        ty_base  = ((tpage >> 4) & 1u) * 256u;
        depth    = (tpage >> 7) & 3u;
        cy       = (clut >> 6) & 0x1FFu;
        cx       = (clut & 0x3Fu) * 16u;
        tw_and_u = 0xFFu & ~((u32)S.tw_mx << 3);
        tw_or_u  = ((u32)(S.tw_ox & S.tw_mx) << 3);
        tw_and_v = 0xFFu & ~((u32)S.tw_my << 3);
        tw_or_v  = ((u32)(S.tw_oy & S.tw_my) << 3);
        if (depth == 0u) {
            const u16 *crow = W.vram + cy * VRAM_STRIDE;
            for (u32 i = 0; i < 16u; i++)
                clut4_raw[i] = crow[(cx + i) & 1023u];
        }
    }

    int opaque_nomask = (!is_semi && !S.check_mask);
    int tex8_ok = (is_tex && depth == 1u && opaque_nomask && tx_base + 128u <= 1024u && ty_base + 256u <= 512u);
    const u8  *tpage_u8  = (const u8 *)(W.vram + ty_base * VRAM_STRIDE + tx_base);
    const u16 *clut8_row = W.vram + cy * VRAM_STRIDE;

    /* the span loops above (each case with the dither of the loop it replaces): textures, opaque or
       semi-transparent, and semi-transparent colours; no mask test */
    struct gpu_span sp;
    int span_kind = 0, span_dither = 0;         /* 0: the loops below; 1 raw; 2 modulated; 3 / 4 the same
                                                   semi-transparent; 5 semi-transparent colour */
    u32 span_t = depth == 3u ? 2u : depth;
    if (!is_tex && is_semi && !S.check_mask) {
        span_kind = 5;
        span_dither = is_gouraud && S.dither;
    } else if (is_tex && !S.check_mask &&
        (span_t == 0u || (span_t == 1u && tx_base + 128u <= 1024u) || (span_t == 2u && tx_base + 256u <= 1024u))) {
        sp.tex8 = tpage_u8 + tw_or_v * (2u * VRAM_STRIDE) + (span_t == 0u ? tw_or_u >> 1 : tw_or_u);
        sp.tex16 = W.vram + (ty_base + tw_or_v) * VRAM_STRIDE + tx_base + tw_or_u;
        sp.clut = span_t == 0u ? clut4_raw : clut8_row;
        sp.cx = cx;
        if (span_t == 1u && cx + 255u <= 1023u)
            sp.clut = clut8_row + cx;           /* (the CLUT does not wrap: its x added once) */
        else if (span_t == 1u)
            span_t = 3u;
        sp.au12 = tw_and_u << 12;
        sp.av12 = tw_and_v << 12;
        sp.mask_or = mask_or;
        sp.clb = (const u8 *)(span_cl[mask_or ? 1 : 0] + (SPAN_CL_OFS - 1));
        if (is_raw) {
            span_kind = is_semi ? 3 : 1;
        } else {
            span_kind = is_semi ? 4 : 2;
            span_dither = !is_semi && (span_t == 1u || span_t == 3u) ? (is_gouraud ? use_dither : 0)
                                                                     : (S.dither != 0u);
        }
    }

    /* textured spans and no interlace copy on any row: the rows in gpu_tri_span_rows */
    if (span_kind >= 1 && span_kind <= 4 &&
        !(lace && (S.skip_render == 0u || maxx >= S.disp_w || maxy >= S.disp_h))) {
        struct tri_rows tr;
        tr.x0 = x0; tr.y0 = y0; tr.x1 = x1; tr.y1 = y1; tr.x2 = x2; tr.y2 = y2;
        tr.s01 = s01; tr.s02 = s02; tr.s12 = s12;
        tr.minx = minx; tr.maxx = maxx; tr.miny = miny; tr.maxy = maxy; tr.y_step = y_step;
        tr.e0_row = e0_row; tr.e1_row = e1_row; tr.e2_row = e2_row;
        tr.a12 = a12; tr.a20 = a20; tr.a01 = a01;
        tr.step_e0 = step_e0; tr.step_e1 = step_e1; tr.step_e2 = step_e2;
        tr.u_row = u_row; tr.v_row = v_row; tr.r_row = r_row; tr.g_row = g_row; tr.b_row = b_row;
        tr.du_dx = du_dx; tr.dv_dx = dv_dx; tr.du_dy = du_dy; tr.dv_dy = dv_dy;
        tr.dr_dx = dr_dx; tr.dg_dx = dg_dx; tr.db_dx = db_dx; tr.dr_dy = dr_dy; tr.dg_dy = dg_dy; tr.db_dy = db_dy;
        tr.fr = v0.r << 12; tr.fg = v0.g << 12; tr.fb = v0.b << 12;
        tr.gouraud = is_gouraud;
        tr.kind = span_kind;
        tr.t = (int)span_t;
        tr.dither = span_dither;
        tr.abr = abr;
        tr.mask_or = mask_or;
        gpu_tri_span_rows(&tr, &sp);
        return;
    }

    for (int y = miny; y <= maxy; y += y_step) {
        s32 xa = (x0 << 16) + s02 * (y - y0);
        s32 xb = (y < y1) ? ((x0 << 16) + s01 * (y - y0))
               : (y2 > y1) ? ((x1 << 16) + s12 * (y - y1)) : (x1 << 16);
        s32 lo = xa < xb ? xa : xb, hi = xa > xb ? xa : xb;
        int xl = (lo >> 16) - 1, xr = (hi >> 16) + 2;
        if (xl < minx) xl = minx;
        if (xr > maxx) xr = maxx;

        s32 dx0 = xl - minx;
        s32 w0 = e0_row + a12 * dx0, w1 = e1_row + a20 * dx0, w2 = e2_row + a01 * dx0;
        while (xl <= xr && (w0 | w1 | w2) < 0) { xl++; w0 += a12; w1 += a20; w2 += a01; }
        if (xl <= xr) {
            s32 dx1 = xr - minx;
            s32 r0 = e0_row + a12 * dx1, r1 = e1_row + a20 * dx1, r2 = e2_row + a01 * dx1;
            while (xr >= xl && (r0 | r1 | r2) < 0) { xr--; r0 -= a12; r1 -= a20; r2 -= a01; }
        }

        if (xl <= xr) {
            u32 dx = (u32)(xl - minx);
            s32 u_c = (s32)(u_row + (u32)du_dx * dx);
            s32 v_c = (s32)(v_row + (u32)dv_dx * dx);
            u16 *row = W.vram + y * VRAM_STRIDE;
            int dup_odd = lace && (S.skip_render == 0u || maxx >= S.disp_w || maxy >= S.disp_h);
            u16 *row2 = (dup_odd && y + 1 <= S.clip_y2) ? (row + VRAM_STRIDE) : 0;

            if (span_kind && !row2) {
                int n = xr - xl + 1;
                u16 *d = row + xl;
                u32 uc = (u32)u_c, vc = (u32)v_c;
                s32 r_c = 0, g_c = 0, b_c = 0, sdr = 0, sdg = 0, sdb = 0;
                if (span_kind != 1 && span_kind != 3) {
                    if (is_gouraud) {
                        r_c = (s32)(r_row + (u32)dr_dx * dx);
                        g_c = (s32)(g_row + (u32)dg_dx * dx);
                        b_c = (s32)(b_row + (u32)db_dx * dx);
                        sdr = dr_dx;
                        sdg = dg_dx;
                        sdb = db_dx;
                    } else {
                        r_c = v0.r << 12;
                        g_c = v0.g << 12;
                        b_c = v0.b << 12;
                    }
                    if (span_kind == 2) {               /* (the dither word, turned to x's phase) */
                        u32 w = span_dw[span_dither ? (y & 3) : 4], s = ((u32)xl & 3u) * 8u;
                        sp.dw = s ? (w >> s) | (w << (32u - s)) : w;
                    } else {
                        const s8 *drow = gpu_dither[y & 3];
                        for (int k = 0; k < 4; k++)
                            sp.d16[k] = span_dither ? (s32)drow[k] * (span_kind == 5 ? 1 : 16) : 0;
                    }
                }
                switch (span_kind * 4 + (int)span_t) {
                case 1 * 4 + 0: span_raw4(&sp, d, n, uc, vc, du_dx, dv_dx); break;
                case 1 * 4 + 1: span_raw8(&sp, d, n, uc, vc, du_dx, dv_dx); break;
                case 1 * 4 + 2: span_raw15(&sp, d, n, uc, vc, du_dx, dv_dx); break;
                case 1 * 4 + 3: span_raw8w(&sp, d, n, uc, vc, du_dx, dv_dx); break;
                case 2 * 4 + 0: span_mod4(&sp, d, xl, n, uc, vc, du_dx, dv_dx, r_c, g_c, b_c, sdr, sdg, sdb); break;
                case 2 * 4 + 1: span_mod8(&sp, d, xl, n, uc, vc, du_dx, dv_dx, r_c, g_c, b_c, sdr, sdg, sdb); break;
                case 2 * 4 + 2: span_mod15(&sp, d, xl, n, uc, vc, du_dx, dv_dx, r_c, g_c, b_c, sdr, sdg, sdb); break;
                case 2 * 4 + 3: span_mod8w(&sp, d, xl, n, uc, vc, du_dx, dv_dx, r_c, g_c, b_c, sdr, sdg, sdb); break;
                case 3 * 4 + 0: span_semi_raw4(&sp, d, xl, n, uc, vc, du_dx, dv_dx, 0, 0, 0, 0, 0, 0, abr); break;
                case 3 * 4 + 1: span_semi_raw8(&sp, d, xl, n, uc, vc, du_dx, dv_dx, 0, 0, 0, 0, 0, 0, abr); break;
                case 3 * 4 + 2: span_semi_raw15(&sp, d, xl, n, uc, vc, du_dx, dv_dx, 0, 0, 0, 0, 0, 0, abr); break;
                case 3 * 4 + 3: span_semi_raw8w(&sp, d, xl, n, uc, vc, du_dx, dv_dx, 0, 0, 0, 0, 0, 0, abr); break;
                case 4 * 4 + 0: span_semi_mod4(&sp, d, xl, n, uc, vc, du_dx, dv_dx, r_c, g_c, b_c, sdr, sdg, sdb, abr); break;
                case 4 * 4 + 1: span_semi_mod8(&sp, d, xl, n, uc, vc, du_dx, dv_dx, r_c, g_c, b_c, sdr, sdg, sdb, abr); break;
                case 4 * 4 + 2: span_semi_mod15(&sp, d, xl, n, uc, vc, du_dx, dv_dx, r_c, g_c, b_c, sdr, sdg, sdb, abr); break;
                case 4 * 4 + 3: span_semi_mod8w(&sp, d, xl, n, uc, vc, du_dx, dv_dx, r_c, g_c, b_c, sdr, sdg, sdb, abr); break;
                default: span_semi_notex(d, xl, n, r_c, g_c, b_c, sdr, sdg, sdb, sp.d16, abr, mask_or); break;
                }
            } else if (tex8_ok && !is_gouraud) {
                int raw_or_neutral = is_raw || (v0.r == 128 && v0.g == 128 && v0.b == 128);
                for (int x = xl; x <= xr; x++, u_c += du_dx, v_c += dv_dx) {
                    u32 uu = ((u32)(u_c >> 12) & tw_and_u) | tw_or_u;
                    u32 vv = ((u32)(v_c >> 12) & tw_and_v) | tw_or_v;
                    u8 idx = tpage_u8[vv * (2u * VRAM_STRIDE) + uu];
                    u16 tex = clut8_row[(cx + idx) & 1023u];
                    if (tex != 0u) {
                        u16 px;
                        if (raw_or_neutral) {
                            px = tex | mask_or;
                        } else {
                            int tr = ((int)(tex & 31u) * v0.r) >> 7;
                            int tg = ((int)((tex >> 5) & 31u) * v0.g) >> 7;
                            int tb = ((int)((tex >> 10) & 31u) * v0.b) >> 7;
                            px = (u16)(clamp5_b[tb + 16] | clamp5_g[tg + 16] |
                                       clamp5_tab[tr + 16] | (tex & 0x8000u) | mask_or);
                        }
                        row[x] = px;
                        if (row2) row2[x] = px;
                    }
                }
            } else if (tex8_ok && is_gouraud && !is_raw) {
                s32 r_c = (s32)(r_row + (u32)dr_dx * dx);
                s32 g_c = (s32)(g_row + (u32)dg_dx * dx);
                s32 b_c = (s32)(b_row + (u32)db_dx * dx);
                const s8 *drow = gpu_dither[y & 3];
                for (int x = xl; x <= xr; x++, u_c += du_dx, v_c += dv_dx, r_c += dr_dx, g_c += dg_dx, b_c += db_dx) {
                    u32 uu = ((u32)(u_c >> 12) & tw_and_u) | tw_or_u;
                    u32 vv = ((u32)(v_c >> 12) & tw_and_v) | tw_or_v;
                    u8 idx = tpage_u8[vv * (2u * VRAM_STRIDE) + uu];
                    u16 tex = clut8_row[(cx + idx) & 1023u];
                    if (tex != 0u) {
                        int d = use_dither ? drow[x & 3] : 0;
                        int tr = ((int)(tex & 31u) * (r_c >> 12)) >> 4;
                        int tg = ((int)((tex >> 5) & 31u) * (g_c >> 12)) >> 4;
                        int tb = ((int)((tex >> 10) & 31u) * (b_c >> 12)) >> 4;
                        u16 px = (u16)(clamp5_b[((tb + d) >> 3) + 16] |
                                       clamp5_g[((tg + d) >> 3) + 16] |
                                       clamp5_tab[((tr + d) >> 3) + 16] | (tex & 0x8000u) | mask_or);
                        row[x] = px;
                        if (row2) row2[x] = px;
                    }
                }
            } else if (!is_tex && is_gouraud && opaque_nomask) {
                s32 r_c = (s32)(r_row + (u32)dr_dx * dx);
                s32 g_c = (s32)(g_row + (u32)dg_dx * dx);
                s32 b_c = (s32)(b_row + (u32)db_dx * dx);
                const s8 *drow = gpu_dither[y & 3];
                for (int x = xl; x <= xr; x++, r_c += dr_dx, g_c += dg_dx, b_c += db_dx) {
                    int d = use_dither ? drow[x & 3] : 0;
                    u16 px = (u16)(((u16)clamp5_tab[(((b_c >> 12) + d) >> 3) + 16] << 10) |
                                   ((u16)clamp5_tab[(((g_c >> 12) + d) >> 3) + 16] << 5) |
                                   clamp5_tab[(((r_c >> 12) + d) >> 3) + 16] | mask_or);
                    row[x] = px;
                    if (row2) row2[x] = px;
                }
            } else {
                s32 r_c = (s32)(r_row + (u32)dr_dx * dx);
                s32 g_c = (s32)(g_row + (u32)dg_dx * dx);
                s32 b_c = (s32)(b_row + (u32)db_dx * dx);
                int do_dith = is_gouraud || (is_tex && !is_raw);
                for (int x = xl; x <= xr; x++, u_c += du_dx, v_c += dv_dx, r_c += dr_dx, g_c += dg_dx, b_c += db_dx) {
                    int r = is_gouraud ? (r_c >> 12) : v0.r;
                    int g = is_gouraud ? (g_c >> 12) : v0.g;
                    int b = is_gouraud ? (b_c >> 12) : v0.b;
                    if (is_tex) {
                        u32 uu = ((u32)(u_c >> 12) & tw_and_u) | tw_or_u;
                        u32 vv = ((u32)(v_c >> 12) & tw_and_v) | tw_or_v;
                        u16 tex = (depth == 0u)
                            ? clut4_raw[(W.vram[((ty_base + vv) & 511u) * VRAM_STRIDE + ((tx_base + (uu >> 2)) & 1023u)] >> ((uu & 3u) << 2)) & 0x0Fu]
                            : (depth == 1u)
                                ? W.vram[cy * VRAM_STRIDE + ((cx + ((W.vram[((ty_base + vv) & 511u) * VRAM_STRIDE + ((tx_base + (uu >> 1)) & 1023u)] >> ((uu & 1u) << 3)) & 0xFFu)) & 1023u)]
                                : W.vram[((ty_base + vv) & 511u) * VRAM_STRIDE + ((tx_base + uu) & 1023u)];
                        if (tex != 0u) {
                            if (is_raw) {
                                u16 *dst = &row[x];
                                if (!(S.check_mask && (*dst & 0x8000u))) {
                                    u16 fg = tex & 0x7FFFu;
                                    if (is_semi && (tex & 0x8000u))
                                        fg = gpu_blend(*dst, fg, abr);
                                    *dst = (u16)(fg | (tex & 0x8000u) | mask_or);
                                    if (row2 && !(S.check_mask && (row2[x] & 0x8000u))) {
                                        u16 fg2 = (is_semi && (tex & 0x8000u)) ? gpu_blend(row2[x], tex & 0x7FFFu, abr) : (tex & 0x7FFFu);
                                        row2[x] = (u16)(fg2 | (tex & 0x8000u) | mask_or);
                                    }
                                }
                            } else {
                                int tr = (((int)(tex & 31u) << 3) * r) >> 7;
                                int tg = (((int)((tex >> 5) & 31u) << 3) * g) >> 7;
                                int tb = (((int)((tex >> 10) & 31u) << 3) * b) >> 7;
                                gpu_plot_pixel(x, y, tr, tg, tb, do_dith, is_semi && (tex & 0x8000u), abr, tex & 0x8000u);
                                if (row2)
                                    gpu_plot_pixel(x, y + 1, tr, tg, tb, do_dith, is_semi && (tex & 0x8000u), abr, tex & 0x8000u);
                            }
                        }
                    } else {
                        gpu_plot_pixel(x, y, r, g, b, do_dith, is_semi, abr, 0u);
                        if (row2)
                            gpu_plot_pixel(x, y + 1, r, g, b, do_dith, is_semi, abr, 0u);
                    }
                }
            }
        }
        e0_row += step_e0; e1_row += step_e1; e2_row += step_e2;
        if (is_gouraud) { r_row += (u32)dr_dy; g_row += (u32)dg_dy; b_row += (u32)db_dy; }
        if (is_tex)     { u_row += (u32)du_dy; v_row += (u32)dv_dy; }
    }
}

static void __attribute__((noinline)) gpu_tri_tex4_flat(struct gpu_vtx v0, struct gpu_vtx v1, struct gpu_vtx v2,
                                                        int minx, int maxx, int miny, int maxy, s32 area,
                                                        int lace, int is_raw, u32 tpage, u32 clut)
{
    int y_step = lace ? 2 : 1;
    int dup_odd = lace && (S.skip_render == 0u || maxx >= S.disp_w || maxy >= S.disp_h);
    u16 mask_or = S.set_mask ? 0x8000u : 0u;
    int x0 = v0.x, y0 = v0.y, x1 = v1.x, y1 = v1.y, x2 = v2.x, y2 = v2.y;
    if (y0 > y1) { int t = x0; x0 = x1; x1 = t; t = y0; y0 = y1; y1 = t; }
    if (y1 > y2) { int t = x1; x1 = x2; x2 = t; t = y1; y1 = y2; y2 = t; }
    if (y0 > y1) { int t = x0; x0 = x1; x1 = t; t = y0; y0 = y1; y1 = t; }

    s32 s02 = (y2 > y0) ? ((x2 - x0) * (s32)gpu_recip_dy[y2 - y0]) : 0;
    s32 s01 = (y1 > y0) ? ((x1 - x0) * (s32)gpu_recip_dy[y1 - y0]) : 0;
    s32 s12 = (y2 > y1) ? ((x2 - x1) * (s32)gpu_recip_dy[y2 - y1]) : 0;

    int a01 = v0.y - v1.y, b01 = v1.x - v0.x;
    int a12 = v1.y - v2.y, b12 = v2.x - v1.x;
    int a20 = v2.y - v0.y, b20 = v0.x - v2.x;
    int bias0 = (a12 < 0 || (a12 == 0 && b12 < 0)) ? 0 : -1;
    int bias1 = (a20 < 0 || (a20 == 0 && b20 < 0)) ? 0 : -1;
    int bias2 = (a01 < 0 || (a01 == 0 && b01 < 0)) ? 0 : -1;

    s32 e0_row = (v2.x - v1.x) * (miny - v1.y) - (v2.y - v1.y) * (minx - v1.x) + bias0;
    s32 e1_row = (v0.x - v2.x) * (miny - v2.y) - (v0.y - v2.y) * (minx - v2.x) + bias1;
    s32 e2_row = (v1.x - v0.x) * (miny - v0.y) - (v1.y - v0.y) * (minx - v0.x) + bias2;
    s32 step_e0 = b12 * y_step, step_e1 = b20 * y_step, step_e2 = b01 * y_step;

    s32 inv_area = (area <= 1) ? (1 << 30) : (s32)((area < 1024) ? gpu_inv_area[area] : ((1u << 30) / (u32)area));
    s32 w0_base = e0_row - bias0, w1_base = e1_row - bias1, w2_base = e2_row - bias2;
    u32 u_row = (u32)(((s64)(w0_base * v0.u + w1_base * v1.u + w2_base * v2.u) * (s64)inv_area + (1LL << 29)) >> 18);
    u32 v_row = (u32)(((s64)(w0_base * v0.v + w1_base * v1.v + w2_base * v2.v) * (s64)inv_area + (1LL << 29)) >> 18);
    s32 du_dx = (s32)(((s64)(a12 * v0.u + a20 * v1.u + a01 * v2.u) * (s64)inv_area) >> 18);
    s32 dv_dx = (s32)(((s64)(a12 * v0.v + a20 * v1.v + a01 * v2.v) * (s64)inv_area) >> 18);
    s32 du_dy = (s32)(((s64)(b12 * v0.u + b20 * v1.u + b01 * v2.u) * (s64)inv_area) >> 18) * y_step;
    s32 dv_dy = (s32)(((s64)(b12 * v0.v + b20 * v1.v + b01 * v2.v) * (s64)inv_area) >> 18) * y_step;
    u32 du24 = (u32)du_dx << 12, dv24 = (u32)dv_dx << 12;

    u32 tx_base = (tpage & 0x0Fu) * 64u, ty_base = ((tpage >> 4) & 1u) * 256u;
    const u8 *tpage_u8 = (const u8 *)(W.vram + ty_base * VRAM_STRIDE + tx_base);
    u32 cy = (clut >> 6) & 0x1FFu, cx = (clut & 0x3Fu) * 16u;

    int raw_or_neutral = is_raw || (v0.r == 128 && v0.g == 128 && v0.b == 128);
    u32 klo = (clut & 0x7FFFu) | (mask_or ? 0x8000u : 0u) | (raw_or_neutral ? 0x10000u : 0u);
    u32 khi = raw_or_neutral ? 0u : ((u32)v0.r | ((u32)v0.g << 8) | ((u32)v0.b << 16));
    const s32 *baked = 0;
    for (int s = 0; s < 4; s++) {
        if (S.clut4_gen[s] == S.vram_gen && S.clut4_klo[s] == klo && S.clut4_khi[s] == khi) {
            baked = S.clut4_cache[s];
            break;
        }
    }
    if (!baked) {
        u32 slot = (S.clut4_slot++) & 3u;
        s32 *dst_c = S.clut4_cache[slot];
        const u16 *crow = W.vram + cy * VRAM_STRIDE;
        if (raw_or_neutral) {
            for (u32 i = 0; i < 16u; i++) {
                u16 t = crow[(cx + i) & 1023u];
                dst_c[i] = (t == 0u) ? -1 : (s32)(u32)(t | mask_or);
            }
        } else {
            for (u32 i = 0; i < 16u; i++) {
                u16 t = crow[(cx + i) & 1023u];
                if (t == 0u) {
                    dst_c[i] = -1;
                } else {
                    int mr = ((int)(t & 31u) * v0.r) >> 4;
                    int mg = ((int)((t >> 5) & 31u) * v0.g) >> 4;
                    int mb = ((int)((t >> 10) & 31u) * v0.b) >> 4;
                    dst_c[i] = (s32)(u32)(clamp5_b[(mb >> 3) + 16] |
                                          clamp5_g[(mg >> 3) + 16] |
                                          clamp5_tab[(mr >> 3) + 16] | (t & 0x8000u) | mask_or);
                }
            }
        }
        S.clut4_gen[slot] = S.vram_gen;
        S.clut4_klo[slot] = klo;
        S.clut4_khi[slot] = khi;
        baked = dst_c;
    }

    int clip_y2 = S.clip_y2;
    s32 xa = (x0 << 16) + s02 * (miny - y0), step_xa = s02 * y_step;
    int in_bot = (miny >= y1);
    s32 xb = in_bot ? ((x1 << 16) + s12 * (miny - y1)) : ((x0 << 16) + s01 * (miny - y0));
    s32 step_xb = (in_bot ? s12 : s01) * y_step;

    for (int y = miny; y <= maxy; y += y_step) {
        if (!in_bot && y >= y1) {
            in_bot = 1;
            xb = (x1 << 16) + s12 * (y - y1);
            step_xb = s12 * y_step;
        }
        s32 lo = xa < xb ? xa : xb, hi = xa > xb ? xa : xb;
        int xl = (lo >> 16) - 1, xr = (hi >> 16) + 2;
        if (xl < minx) xl = minx;
        if (xr > maxx) xr = maxx;
        s32 dx0 = xl - minx;
        s32 w0 = e0_row + a12 * dx0, w1 = e1_row + a20 * dx0, w2 = e2_row + a01 * dx0;
        while (xl <= xr && (w0 | w1 | w2) < 0) { xl++; w0 += a12; w1 += a20; w2 += a01; }
        if (xl <= xr) {
            s32 dx1 = xr - minx;
            s32 r0 = e0_row + a12 * dx1, r1 = e1_row + a20 * dx1, r2 = e2_row + a01 * dx1;
            while (xr >= xl && (r0 | r1 | r2) < 0) { xr--; r0 -= a12; r1 -= a20; r2 -= a01; }
        }
        if (xl <= xr) {
            u32 dx = (u32)(xl - minx);
            gpu_span_tex4_flat_notw(W.vram + y * VRAM_STRIDE + xl, xr - xl + 1, dup_odd && (y + 1 <= clip_y2),
                                    tpage_u8, baked, (u_row + (u32)du_dx * dx) << 12,
                                    (v_row + (u32)dv_dx * dx) << 12, du24, dv24);
        }
        xa += step_xa; xb += step_xb;
        e0_row += step_e0; e1_row += step_e1; e2_row += step_e2;
        u_row += (u32)du_dy; v_row += (u32)dv_dy;
    }
}

static void __attribute__((noinline)) gpu_tri_tex4_gour(struct gpu_vtx v0, struct gpu_vtx v1, struct gpu_vtx v2,
                                                        int minx, int maxx, int miny, int maxy, s32 area,
                                                        int lace, u32 tpage, u32 clut)
{
    int y_step = lace ? 2 : 1;
    int dup_odd = lace && (S.skip_render == 0u || maxx >= S.disp_w || maxy >= S.disp_h);
    int use_dither = S.dither && (S.skip_render == 0u);
    u16 mask_or = S.set_mask ? 0x8000u : 0u;
    int x0 = v0.x, y0 = v0.y, x1 = v1.x, y1 = v1.y, x2 = v2.x, y2 = v2.y;
    if (y0 > y1) { int t = x0; x0 = x1; x1 = t; t = y0; y0 = y1; y1 = t; }
    if (y1 > y2) { int t = x1; x1 = x2; x2 = t; t = y1; y1 = y2; y2 = t; }
    if (y0 > y1) { int t = x0; x0 = x1; x1 = t; t = y0; y0 = y1; y1 = t; }

    s32 s02 = (y2 > y0) ? ((x2 - x0) * (s32)gpu_recip_dy[y2 - y0]) : 0;
    s32 s01 = (y1 > y0) ? ((x1 - x0) * (s32)gpu_recip_dy[y1 - y0]) : 0;
    s32 s12 = (y2 > y1) ? ((x2 - x1) * (s32)gpu_recip_dy[y2 - y1]) : 0;

    int a01 = v0.y - v1.y, b01 = v1.x - v0.x;
    int a12 = v1.y - v2.y, b12 = v2.x - v1.x;
    int a20 = v2.y - v0.y, b20 = v0.x - v2.x;
    int bias0 = (a12 < 0 || (a12 == 0 && b12 < 0)) ? 0 : -1;
    int bias1 = (a20 < 0 || (a20 == 0 && b20 < 0)) ? 0 : -1;
    int bias2 = (a01 < 0 || (a01 == 0 && b01 < 0)) ? 0 : -1;

    s32 e0_row = (v2.x - v1.x) * (miny - v1.y) - (v2.y - v1.y) * (minx - v1.x) + bias0;
    s32 e1_row = (v0.x - v2.x) * (miny - v2.y) - (v0.y - v2.y) * (minx - v2.x) + bias1;
    s32 e2_row = (v1.x - v0.x) * (miny - v0.y) - (v1.y - v0.y) * (minx - v0.x) + bias2;
    s32 step_e0 = b12 * y_step, step_e1 = b20 * y_step, step_e2 = b01 * y_step;

    s32 inv_area = (area <= 1) ? (1 << 30) : (s32)((area < 1024) ? gpu_inv_area[area] : ((1u << 30) / (u32)area));
    s32 w0_base = e0_row - bias0, w1_base = e1_row - bias1, w2_base = e2_row - bias2;
    u32 u_row = (u32)(((s64)(w0_base * v0.u + w1_base * v1.u + w2_base * v2.u) * (s64)inv_area + (1LL << 29)) >> 18);
    u32 v_row = (u32)(((s64)(w0_base * v0.v + w1_base * v1.v + w2_base * v2.v) * (s64)inv_area + (1LL << 29)) >> 18);
    s32 du_dx = (s32)(((s64)(a12 * v0.u + a20 * v1.u + a01 * v2.u) * (s64)inv_area) >> 18);
    s32 dv_dx = (s32)(((s64)(a12 * v0.v + a20 * v1.v + a01 * v2.v) * (s64)inv_area) >> 18);
    s32 du_dy = (s32)(((s64)(b12 * v0.u + b20 * v1.u + b01 * v2.u) * (s64)inv_area) >> 18) * y_step;
    s32 dv_dy = (s32)(((s64)(b12 * v0.v + b20 * v1.v + b01 * v2.v) * (s64)inv_area) >> 18) * y_step;
    u32 du24 = (u32)du_dx << 12, dv24 = (u32)dv_dx << 12;

    u32 r_row = (u32)(((s64)(w0_base * v0.r + w1_base * v1.r + w2_base * v2.r) * (s64)inv_area + (1LL << 29)) >> 18);
    u32 g_row = (u32)(((s64)(w0_base * v0.g + w1_base * v1.g + w2_base * v2.g) * (s64)inv_area + (1LL << 29)) >> 18);
    u32 b_row = (u32)(((s64)(w0_base * v0.b + w1_base * v1.b + w2_base * v2.b) * (s64)inv_area + (1LL << 29)) >> 18);
    s32 dr_dx = (s32)(((s64)(a12 * v0.r + a20 * v1.r + a01 * v2.r) * (s64)inv_area) >> 18);
    s32 dg_dx = (s32)(((s64)(a12 * v0.g + a20 * v1.g + a01 * v2.g) * (s64)inv_area) >> 18);
    s32 db_dx = (s32)(((s64)(a12 * v0.b + a20 * v1.b + a01 * v2.b) * (s64)inv_area) >> 18);
    s32 dr_dy = (s32)(((s64)(b12 * v0.r + b20 * v1.r + b01 * v2.r) * (s64)inv_area) >> 18) * y_step;
    s32 dg_dy = (s32)(((s64)(b12 * v0.g + b20 * v1.g + b01 * v2.g) * (s64)inv_area) >> 18) * y_step;
    s32 db_dy = (s32)(((s64)(b12 * v0.b + b20 * v1.b + b01 * v2.b) * (s64)inv_area) >> 18) * y_step;

    u32 tx_base = (tpage & 0x0Fu) * 64u, ty_base = ((tpage >> 4) & 1u) * 256u;
    const u8 *tpage_u8 = (const u8 *)(W.vram + ty_base * VRAM_STRIDE + tx_base);
    u32 cy = (clut >> 6) & 0x1FFu, cx = (clut & 0x3Fu) * 16u;
    s32 clut_rm[16];
    const u16 *crow = W.vram + cy * VRAM_STRIDE;
    for (u32 i = 0; i < 16u; i++) {
        u16 t = crow[(cx + i) & 1023u];
        clut_rm[i] = (t == 0u) ? -1 : (s32)(u32)(t | mask_or);
    }

    int clip_y2 = S.clip_y2;
    s32 xa = (x0 << 16) + s02 * (miny - y0), step_xa = s02 * y_step;
    int in_bot = (miny >= y1);
    s32 xb = in_bot ? ((x1 << 16) + s12 * (miny - y1)) : ((x0 << 16) + s01 * (miny - y0));
    s32 step_xb = (in_bot ? s12 : s01) * y_step;

    for (int y = miny; y <= maxy; y += y_step) {
        if (!in_bot && y >= y1) {
            in_bot = 1;
            xb = (x1 << 16) + s12 * (y - y1);
            step_xb = s12 * y_step;
        }
        s32 lo = xa < xb ? xa : xb, hi = xa > xb ? xa : xb;
        int xl = (lo >> 16) - 1, xr = (hi >> 16) + 2;
        if (xl < minx) xl = minx;
        if (xr > maxx) xr = maxx;
        s32 dx0 = xl - minx;
        s32 w0 = e0_row + a12 * dx0, w1 = e1_row + a20 * dx0, w2 = e2_row + a01 * dx0;
        while (xl <= xr && (w0 | w1 | w2) < 0) { xl++; w0 += a12; w1 += a20; w2 += a01; }
        if (xl <= xr) {
            s32 dx1 = xr - minx;
            s32 r0 = e0_row + a12 * dx1, r1 = e1_row + a20 * dx1, r2 = e2_row + a01 * dx1;
            while (xr >= xl && (r0 | r1 | r2) < 0) { xr--; r0 -= a12; r1 -= a20; r2 -= a01; }
        }
        if (xl <= xr) {
            u32 dx = (u32)(xl - minx);
            gpu_span_tex4_gour_notw(W.vram + y * VRAM_STRIDE + xl, xl, xr, dup_odd && (y + 1 <= clip_y2),
                                    use_dither, tpage_u8, clut_rm, gpu_dither[y & 3],
                                    (u_row + (u32)du_dx * dx) << 12, (v_row + (u32)dv_dx * dx) << 12, du24, dv24,
                                    (s32)(r_row + (u32)dr_dx * dx), (s32)(g_row + (u32)dg_dx * dx),
                                    (s32)(b_row + (u32)db_dx * dx), dr_dx, dg_dx, db_dx);
        }
        xa += step_xa; xb += step_xb;
        e0_row += step_e0; e1_row += step_e1; e2_row += step_e2;
        u_row += (u32)du_dy; v_row += (u32)dv_dy;
        r_row += (u32)dr_dy; g_row += (u32)dg_dy; b_row += (u32)db_dy;
    }
}

static void __attribute__((noinline)) gpu_draw_tri(const struct gpu_vtx *pv0, const struct gpu_vtx *pv1, const struct gpu_vtx *pv2,
                                                   u8 op, u32 tpage, u32 clut)
{
    int minx = pv0->x < pv1->x ? pv0->x : pv1->x; if (pv2->x < minx) minx = pv2->x;
    int maxx = pv0->x > pv1->x ? pv0->x : pv1->x; if (pv2->x > maxx) maxx = pv2->x;
    int miny = pv0->y < pv1->y ? pv0->y : pv1->y; if (pv2->y < miny) miny = pv2->y;
    int maxy = pv0->y > pv1->y ? pv0->y : pv1->y; if (pv2->y > maxy) maxy = pv2->y;
    if (maxx - minx >= 1024 || maxy - miny >= 512)
        return;

    if (minx < S.clip_x1) minx = S.clip_x1;
    if (miny < S.clip_y1) miny = S.clip_y1;
    if (maxx > S.clip_x2) maxx = S.clip_x2;
    if (maxy > S.clip_y2) maxy = S.clip_y2;
    int lace = (S.disp_h > 240 && S.clip_y2 >= 240);
    if (lace && (miny & 1))
        miny++;
    if (minx > maxx || miny > maxy)
        return;
    if (maxx >= S.disp_w || maxy >= S.disp_h)
        S.vram_gen++;

    s32 area = (pv1->x - pv0->x) * (pv2->y - pv0->y) - (pv1->y - pv0->y) * (pv2->x - pv0->x);
    if (area == 0)
        return;
    if (area < 0) {
        const struct gpu_vtx *tmp = pv1; pv1 = pv2; pv2 = tmp;
        area = -area;
    }
    struct gpu_vtx v0 = *pv0, v1 = *pv1, v2 = *pv2;

    int is_gouraud = (op & 0x10u) != 0u;
    int is_tex     = (op & 0x04u) != 0u && !(S.tex_disable && (tpage & 0x800u));
    int is_semi    = (op & 0x02u) != 0u;
    int is_raw     = (op & 0x01u) != 0u;
    u32 depth      = (tpage >> 7) & 3u;
    u32 tx_base    = (tpage & 0x0Fu) * 64u;
    u32 ty_base    = ((tpage >> 4) & 1u) * 256u;

    if (is_tex && depth == 0u && !is_semi && !S.check_mask &&
        ((S.tw_mx | S.tw_my) == 0u) && !(is_gouraud && is_raw) &&
        tx_base + 64u <= 1024u && ty_base + 256u <= 512u) {
        if (!is_gouraud)
            gpu_tri_tex4_flat(v0, v1, v2, minx, maxx, miny, maxy, area, lace, is_raw, tpage, clut);
        else
            gpu_tri_tex4_gour(v0, v1, v2, minx, maxx, miny, maxy, area, lace, tpage, clut);
        return;
    }

    if (!is_gouraud && !is_tex && !is_semi && !S.check_mask) {
        int y_step = lace ? 2 : 1;
        int dup_odd = lace && (S.skip_render == 0u || maxx >= S.disp_w || maxy >= S.disp_h);
        u16 mask_or = S.set_mask ? 0x8000u : 0u;
        int x0 = v0.x, y0 = v0.y, x1 = v1.x, y1 = v1.y, x2 = v2.x, y2 = v2.y;
        if (y0 > y1) { int t = x0; x0 = x1; x1 = t; t = y0; y0 = y1; y1 = t; }
        if (y1 > y2) { int t = x1; x1 = x2; x2 = t; t = y1; y1 = y2; y2 = t; }
        if (y0 > y1) { int t = x0; x0 = x1; x1 = t; t = y0; y0 = y1; y1 = t; }
        s32 s02 = (y2 > y0) ? ((x2 - x0) * (s32)gpu_recip_dy[y2 - y0]) : 0;
        s32 s01 = (y1 > y0) ? ((x1 - x0) * (s32)gpu_recip_dy[y1 - y0]) : 0;
        s32 s12 = (y2 > y1) ? ((x2 - x1) * (s32)gpu_recip_dy[y2 - y1]) : 0;
        int a01 = v0.y - v1.y, b01 = v1.x - v0.x;
        int a12 = v1.y - v2.y, b12 = v2.x - v1.x;
        int a20 = v2.y - v0.y, b20 = v0.x - v2.x;
        int bias0 = (a12 < 0 || (a12 == 0 && b12 < 0)) ? 0 : -1;
        int bias1 = (a20 < 0 || (a20 == 0 && b20 < 0)) ? 0 : -1;
        int bias2 = (a01 < 0 || (a01 == 0 && b01 < 0)) ? 0 : -1;
        s32 e0_row = (v2.x - v1.x) * (miny - v1.y) - (v2.y - v1.y) * (minx - v1.x) + bias0;
        s32 e1_row = (v0.x - v2.x) * (miny - v2.y) - (v0.y - v2.y) * (minx - v2.x) + bias1;
        s32 e2_row = (v1.x - v0.x) * (miny - v0.y) - (v1.y - v0.y) * (minx - v0.x) + bias2;
        s32 step_e0 = b12 * y_step, step_e1 = b20 * y_step, step_e2 = b01 * y_step;
        u16 flat_col = (u16)(clamp5(v0.r >> 3) | clamp5_g[(v0.g >> 3) + 16] |
                             clamp5_b[(v0.b >> 3) + 16] | mask_or);
        u32 flat32 = (u32)flat_col | ((u32)flat_col << 16);
        for (int y = miny; y <= maxy; y += y_step) {
            s32 xa = (x0 << 16) + s02 * (y - y0);
            s32 xb = (y < y1) ? ((x0 << 16) + s01 * (y - y0))
                   : (y2 > y1) ? ((x1 << 16) + s12 * (y - y1)) : (x1 << 16);
            s32 lo = xa < xb ? xa : xb, hi = xa > xb ? xa : xb;
            int xl = (lo >> 16) - 1, xr = (hi >> 16) + 2;
            if (xl < minx) xl = minx;
            if (xr > maxx) xr = maxx;
            s32 dx0 = xl - minx;
            s32 w0 = e0_row + a12 * dx0, w1 = e1_row + a20 * dx0, w2 = e2_row + a01 * dx0;
            while (xl <= xr && (w0 | w1 | w2) < 0) { xl++; w0 += a12; w1 += a20; w2 += a01; }
            if (xl <= xr) {
                s32 dx1 = xr - minx;
                s32 r0 = e0_row + a12 * dx1, r1 = e1_row + a20 * dx1, r2 = e2_row + a01 * dx1;
                while (xr >= xl && (r0 | r1 | r2) < 0) { xr--; r0 -= a12; r1 -= a20; r2 -= a01; }
            }
            if (xl <= xr) {
                u16 *row = W.vram + y * VRAM_STRIDE;
                int x = xl;
                if (x & 1) row[x++] = flat_col;
                for (; x + 1 <= xr; x += 2)
                    *(u32 *)(row + x) = flat32;
                if (x <= xr) row[x] = flat_col;
                if (dup_odd && y + 1 <= S.clip_y2) {
                    u16 *row2 = row + VRAM_STRIDE;
                    int x2 = xl;
                    if (x2 & 1) row2[x2++] = flat_col;
                    for (; x2 + 1 <= xr; x2 += 2)
                        *(u32 *)(row2 + x2) = flat32;
                    if (x2 <= xr) row2[x2] = flat_col;
                }
            }
            e0_row += step_e0; e1_row += step_e1; e2_row += step_e2;
        }
        return;
    }

    gpu_draw_tri_slow(v0, v1, v2, minx, maxx, miny, maxy, area, op, tpage, clut);
}

static void gpu_draw_line(int x0, int y0, u32 c0, int x1, int y1, u32 c1, int is_gouraud, int is_semi)
{
    int dx = (x1 > x0) ? (x1 - x0) : (x0 - x1);
    int dy = (y1 > y0) ? (y1 - y0) : (y0 - y1);
    if (dx >= 1024 || dy >= 512)
        return;
    int steps = dx > dy ? dx : dy;
    u32 abr = (S.gpustat >> 5) & 3u;
    if (steps == 0) {
        if (x0 >= S.clip_x1 && x0 <= S.clip_x2 && y0 >= S.clip_y1 && y0 <= S.clip_y2)
            gpu_plot_pixel(x0, y0, (int)(c0 & 0xFFu), (int)((c0 >> 8) & 0xFFu), (int)((c0 >> 16) & 0xFFu),
                           S.dither, is_semi, abr, 0u);
        return;
    }
    int r0 = (int)(c0 & 0xFFu), g0 = (int)((c0 >> 8) & 0xFFu), b0 = (int)((c0 >> 16) & 0xFFu);
    int r1 = (int)(c1 & 0xFFu), g1 = (int)((c1 >> 8) & 0xFFu), b1 = (int)((c1 >> 16) & 0xFFu);
    for (int i = 0; i <= steps; i++) {
        int x = x0 + ((x1 - x0) * i) / steps;
        int y = y0 + ((y1 - y0) * i) / steps;
        if (x >= S.clip_x1 && x <= S.clip_x2 && y >= S.clip_y1 && y <= S.clip_y2) {
            int r = is_gouraud ? (r0 + ((r1 - r0) * i) / steps) : r0;
            int g = is_gouraud ? (g0 + ((g1 - g0) * i) / steps) : g0;
            int b = is_gouraud ? (b0 + ((b1 - b0) * i) / steps) : b0;
            gpu_plot_pixel(x, y, r, g, b, S.dither, is_semi, abr, 0u);
        }
    }
}

static void gpu_draw_rect(u8 op)
{
    u32 c0 = S.gp0_buf[0];
    int is_tex  = (op & 0x04u) != 0u;
    int is_semi = (op & 0x02u) != 0u;
    int is_raw  = (op & 0x01u) != 0u;
    u32 sz_mode = (op >> 3) & 3u;
    int idx = 1;
    u32 xy = S.gp0_buf[idx++];
    int x0 = sign_ext11(xy) + S.off_x;
    int y0 = sign_ext11(xy >> 16) + S.off_y;
    u32 uv_clut = is_tex ? S.gp0_buf[idx++] : 0u;
    int w = 1, h = 1;
    if (sz_mode == 0u) {
        u32 wh = S.gp0_buf[idx++];
        w = (int)(wh & 0x3FFu);
        h = (int)((wh >> 16) & 0x1FFu);
    } else if (sz_mode == 2u) { w = h = 8; }
    else if (sz_mode == 3u)   { w = h = 16; }

    int r = (int)(c0 & 0xFFu), g = (int)((c0 >> 8) & 0xFFu), b = (int)((c0 >> 16) & 0xFFu);
    u32 u0 = uv_clut & 0xFFu, v0 = (uv_clut >> 8) & 0xFFu, clut = uv_clut >> 16;
    u32 tpage = S.gpustat & 0x9FFu;
    u32 abr = (S.gpustat >> 5) & 3u;
    int xflip = (S.gpustat >> 12) & 1;
    int yflip = (S.gpustat >> 13) & 1;

    int lace_even = (S.skip_render != 0u && S.disp_h > 240 && S.clip_y2 >= 240 && x0 + w <= S.disp_w);
    if (x0 + w > S.disp_w || y0 + h > S.disp_h)
        S.vram_gen++;
    for (int dy = 0; dy < h; dy++) {
        int y = y0 + dy;
        if (y < S.clip_y1 || y > S.clip_y2) continue;
        if (lace_even) {
            if (h > 1 && (y & 1)) continue;
            y &= ~1;
        }
        u32 tv = yflip ? ((v0 - (u32)dy) & 0xFFu) : ((v0 + (u32)dy) & 0xFFu);
        for (int dx = 0; dx < w; dx++) {
            int x = x0 + dx;
            if (x < S.clip_x1 || x > S.clip_x2) continue;
            if (is_tex) {
                u32 tu = xflip ? ((u0 - (u32)dx) & 0xFFu) : ((u0 + (u32)dx) & 0xFFu);
                u16 tex = gpu_fetch_texel(tu, tv, tpage, clut);
                if (tex == 0u) continue;
                if (is_raw) {
                    u16 *dst = &W.vram[y * VRAM_STRIDE + x];
                    if (S.check_mask && (*dst & 0x8000u)) continue;
                    u16 fg = tex & 0x7FFFu;
                    if (is_semi && (tex & 0x8000u))
                        fg = gpu_blend(*dst, fg, abr);
                    *dst = (u16)(fg | (tex & 0x8000u) | (S.set_mask ? 0x8000u : 0u));
                } else {
                    int tr = (((int)(tex & 31u) << 3) * r) >> 7;
                    int tg = (((int)((tex >> 5) & 31u) << 3) * g) >> 7;
                    int tb = (((int)((tex >> 10) & 31u) << 3) * b) >> 7;
                    gpu_plot_pixel(x, y, tr, tg, tb, 0, is_semi && (tex & 0x8000u), abr, tex & 0x8000u);
                }
            } else {
                gpu_plot_pixel(x, y, r, g, b, 0, is_semi, abr, 0u);
            }
        }
    }
}

static const u8 gp0_poly_words[32] = {
    /* 0x20..0x27 (flat tri):  4,4,4,4, 7,7,7,7 */
    4, 4, 4, 4, 7, 7, 7, 7,
    /* 0x28..0x2F (flat quad): 5,5,5,5, 9,9,9,9 */
    5, 5, 5, 5, 9, 9, 9, 9,
    /* 0x30..0x37 (gour tri):  6,6,6,6, 9,9,9,9 */
    6, 6, 6, 6, 9, 9, 9, 9,
    /* 0x38..0x3F (gour quad): 8,8,8,8, 12,12,12,12 */
    8, 8, 8, 8, 12, 12, 12, 12
};

/* does VRAM rectangle x1..x2, y1..y2 (inclusive) meet the part shown? (a shown part that wraps: always yes) */
static inline int gpu_rect_shown(int x1, int y1, int x2, int y2)
{
    int dx = S.disp_x, dy = S.disp_y, dw = S.disp_w, dh = S.disp_h;
    if (dx + dw > 1024 || dy + dh > 512)
        return 1;
    return x1 < dx + dw && x2 >= dx && y1 < dy + dh && y2 >= dy;
}

/* a primitive about to be drawn: dropped while a game frame is skipped (it goes to a buffer not shown);
   else it marks the picture changed when the drawing area meets what is shown */
static inline int gpu_can_skip_draw(void)
{
    int shown = gpu_rect_shown(S.clip_x1, S.clip_y1, S.clip_x2, S.clip_y2);
    if (S.fs_active && !shown) {
        S.fs_dropped = 1u;
        return 1;
    }
    if (shown)
        S.disp_dirty = 1u;
    return 0;
}

static inline void gpu_exec_poly_words(const u32 *buf, u8 op)
{
    int tex  = (op >> 2) & 1;
    int gour = (op >> 4) & 1;
    if (gpu_can_skip_draw()) {
        if (tex) {
            u32 tpage = (buf[gour ? 5 : 4] >> 16) & 0x9FFu;
            S.gpustat = (S.gpustat & ~0x9FFu) | tpage;
        }
        return;
    }
    int quad = (op >> 3) & 1;
    int nv = quad ? 4 : 3;
    struct gpu_vtx v[4];
    int p = 0;
    u32 w0 = buf[0], clut = 0, tpage = S.gpustat & 0x9FFu;
    for (int i = 0; i < nv; i++) {
        u32 col = (i == 0 || gour) ? buf[p++] : w0;
        u32 xy  = buf[p++];
        u32 uv  = tex ? buf[p++] : 0u;
        v[i].r = (int)(col & 0xFFu);
        v[i].g = (int)((col >> 8) & 0xFFu);
        v[i].b = (int)((col >> 16) & 0xFFu);
        v[i].x = sign_ext11(xy) + S.off_x;
        v[i].y = sign_ext11(xy >> 16) + S.off_y;
        v[i].u = (int)(uv & 0xFFu);
        v[i].v = (int)((uv >> 8) & 0xFFu);
        if (tex && i == 0) clut = uv >> 16;
        if (tex && i == 1) {
            tpage = (uv >> 16) & 0x9FFu;
            S.gpustat = (S.gpustat & ~0x9FFu) | (tpage & 0x9FFu);
        }
    }
    gpu_draw_tri(&v[0], &v[1], &v[2], op, tpage, clut);
    if (quad)
        gpu_draw_tri(&v[1], &v[3], &v[2], op, tpage, clut);
}

static u8 gp0_cmd_words(u8 op)
{
    u8 top = op >> 5;
    if (top == 0u) return (op == 0x02u) ? 3u : 1u;
    if (top == 1u) { /* Polygons 0x20..0x3F */
        int quad = (op >> 3) & 1;
        int gour = (op >> 4) & 1;
        int tex  = (op >> 2) & 1;
        int nv = quad ? 4 : 3;
        return (u8)(1 + nv * (1 + gour + tex) - gour);
    }
    if (top == 2u) { /* Lines 0x40..0x5F */
        int gour = (op >> 4) & 1;
        return (u8)(gour ? 4 : 3);
    }
    if (top == 3u) { /* Rectangles 0x60..0x7F */
        int tex = (op >> 2) & 1;
        int var = ((op >> 3) & 3) == 0;
        return (u8)(2 + tex + var);
    }
    if (top == 4u) return 4u; /* VRAM->VRAM copy */
    if (top == 5u) return 3u; /* CPU->VRAM */
    if (top == 6u) return 3u; /* VRAM->CPU */
    return 1u;                /* 0xE0..0xFF env */
}

static void gp0_exec_packet(void)
{
    u32 w0 = S.gp0_buf[0];
    u8 op = (u8)(w0 >> 24);
    u8 top = op >> 5;

    if (top == 0u) {
        if (op == 0x02u) { /* Quick VRAM Fill (16-pixel X aligned) */
            u32 x0 = S.gp0_buf[1] & 0x3F0u;
            u32 y0 = (S.gp0_buf[1] >> 16) & 0x1FFu;
            u32 fw = ((S.gp0_buf[2] & 0x3FFu) + 0x0Fu) & ~0x0Fu;
            u32 fh = (S.gp0_buf[2] >> 16) & 0x1FFu;
            if (x0 == 0u && fw >= (u32)S.disp_w && fh >= (u32)(S.disp_h > 240 ? 240 : S.disp_h))
                S.vram_full_clear = 1u;
            if (fw && fh) {
                int shown = gpu_rect_shown((int)x0, (int)y0, (int)(x0 + fw - 1u), (int)(y0 + fh - 1u));
                if (S.fs_active && !shown && (int)x0 >= S.clip_x1 && (int)(x0 + fw - 1u) <= S.clip_x2 &&
                    (int)y0 >= S.clip_y1 && (int)(y0 + fh - 1u) <= S.clip_y2) {
                    S.fs_dropped = 1u;                  /* (clearing the skipped frame's own buffer) */
                    return;
                }
                if (shown)
                    S.disp_dirty = 1u;
            }
            S.vram_gen++;
            u16 r5 = (u16)((w0 >> 3) & 31u);
            u16 g5 = (u16)(((w0 >> 11) & 31u) << 5);
            u16 b5 = (u16)(((w0 >> 19) & 31u) << 10);
            u16 col = r5 | g5 | b5;
            u32 col32 = (u32)col | ((u32)col << 16);
            u32 dy_step = (S.skip_render != 0u && S.disp_h > 240 && x0 + fw <= (u32)S.disp_w && fh > 240u) ? 2u : 1u;
            u32 dy_init = (dy_step == 2u && (y0 & 1u)) ? 1u : 0u;
            for (u32 dy = dy_init; dy < fh; dy += dy_step) {
                u16 *row = W.vram + ((y0 + dy) & 511u) * VRAM_STRIDE;
                if (x0 + fw <= 1024u) {
                    u32 *r32 = (u32 *)(row + x0);
#ifdef __mips__
                    /* whole 32-byte lines (rows 2080 bytes apart, x0 and fw in 16 pixels): each one allocated
                       without being read from memory first (pref 30, PrepareForStore), then all of it written */
                    for (u32 *e = r32 + (fw >> 1); r32 < e; r32 += 8) {
                        __asm__ volatile("pref 30, 0(%0)" : : "r"(r32) : "memory");
                        r32[0] = col32;
                        r32[1] = col32;
                        r32[2] = col32;
                        r32[3] = col32;
                        r32[4] = col32;
                        r32[5] = col32;
                        r32[6] = col32;
                        r32[7] = col32;
                    }
#else
                    for (u32 w = 0, wn = fw >> 1; w < wn; w++)
                        r32[w] = col32;
#endif
                } else {
                    for (u32 dx = 0; dx < fw; dx++)
                        row[(x0 + dx) & 1023u] = col;
                }
            }
        } else if (op == 0x1Fu) { /* IRQ1 */
            S.gpustat |= (1u << 24);
            raise_irq(1u << 1);
        }
        return;
    }

    if (top == 1u) { /* Polygon */
        gpu_exec_poly_words(S.gp0_buf, op);
        return;
    }

    if (top == 2u) { /* Line / Polyline */
        int gour = (op >> 4) & 1;
        int poly = (op >> 3) & 1;
        int semi = (op >> 1) & 1;
        u32 c0 = S.gp0_buf[0], xy0 = S.gp0_buf[1];
        u32 c1 = gour ? S.gp0_buf[2] : c0;
        u32 xy1 = S.gp0_buf[gour ? 3 : 2];
        if (!gpu_can_skip_draw())
            gpu_draw_line(sign_ext11(xy0) + S.off_x, sign_ext11(xy0 >> 16) + S.off_y, c0,
                          sign_ext11(xy1) + S.off_x, sign_ext11(xy1 >> 16) + S.off_y, c1, gour, semi);
        if (poly) {
            S.gp0_mode = 2u;
            S.gp0_poly_gouraud = (u8)gour;
            S.gp0_poly_semi = (u8)semi;
            S.gp0_poly_prev_xy = xy1;
            S.gp0_poly_prev_col = c1;
            S.gp0_len = 0;
        }
        return;
    }

    if (top == 3u) { /* Rectangle */
        if (!gpu_can_skip_draw())
            gpu_draw_rect(op);
        return;
    }

    if (top == 4u) { /* VRAM -> VRAM copy */
        S.vram_gen++;
        u32 sx = S.gp0_buf[1] & 0x3FFu, sy = (S.gp0_buf[1] >> 16) & 0x1FFu;
        u32 dx = S.gp0_buf[2] & 0x3FFu, dy = (S.gp0_buf[2] >> 16) & 0x1FFu;
        u32 cw = ((S.gp0_buf[3] - 1u) & 0x3FFu) + 1u;
        u32 ch = (((S.gp0_buf[3] >> 16) - 1u) & 0x1FFu) + 1u;
        u16 mask_or = S.set_mask ? 0x8000u : 0u;
        if (sx == dx && sy == dy && !mask_or)
            return;                     /* (onto itself: nothing changes -- Tony Hawk's 2 x 1 at 0,0 most frames) */
        if (dx + cw > 1024u || dy + ch > 512u || gpu_rect_shown((int)dx, (int)dy, (int)(dx + cw - 1u), (int)(dy + ch - 1u)))
            S.disp_dirty = 1u;
        for (u32 y = 0; y < ch; y++) {
            for (u32 x = 0; x < cw; x++) {
                u16 sv = W.vram[((sy + y) & 511u) * VRAM_STRIDE + ((sx + x) & 1023u)];
                u16 *dp = &W.vram[((dy + y) & 511u) * VRAM_STRIDE + ((dx + x) & 1023u)];
                if (!(S.check_mask && (*dp & 0x8000u)))
                    *dp = sv | mask_or;
            }
        }
        return;
    }

    if (top == 5u) { /* CPU -> VRAM */
        S.vram_gen++;
        S.vram_tx = (u16)(S.gp0_buf[1] & 0x3FFu);
        S.vram_ty = (u16)((S.gp0_buf[1] >> 16) & 0x1FFu);
        S.vram_tw = (u16)(((S.gp0_buf[2] - 1u) & 0x3FFu) + 1u);
        S.vram_th = (u16)((((S.gp0_buf[2] >> 16) - 1u) & 0x1FFu) + 1u);
        S.vram_cx = S.vram_cy = 0;
        S.gp0_mode = 1u;
        if (S.vram_tx + S.vram_tw > 1024 || S.vram_ty + S.vram_th > 512 ||
            gpu_rect_shown(S.vram_tx, S.vram_ty, S.vram_tx + S.vram_tw - 1, S.vram_ty + S.vram_th - 1))
            S.disp_dirty = 1u;
        return;
    }

    if (top == 6u) { /* VRAM -> CPU */
        S.vram_rx = (u16)(S.gp0_buf[1] & 0x3FFu);
        S.vram_ry = (u16)((S.gp0_buf[1] >> 16) & 0x1FFu);
        S.vram_rw = (u16)(((S.gp0_buf[2] - 1u) & 0x3FFu) + 1u);
        S.vram_rh = (u16)((((S.gp0_buf[2] >> 16) - 1u) & 0x1FFu) + 1u);
        S.vram_rcx = S.vram_rcy = 0;
        S.gpustat |= (1u << 27);
        return;
    }

    /* 0xE1..0xE6 Environment */
    switch (op) {
    case 0xE1u:
        S.gpustat = (S.gpustat & ~0x7FFu) | (w0 & 0x7FFu);
        S.dither = (u8)((w0 >> 9) & 1u);
        if (w0 & (1u << 11)) S.gpustat |= (1u << 15);
        else                 S.gpustat &= ~(1u << 15);
        S.gpustat = (S.gpustat & ~(3u << 12)) | ((w0 & (3u << 12)));
        break;
    case 0xE2u:
        S.tw_mx = (u8)(w0 & 0x1Fu);
        S.tw_my = (u8)((w0 >> 5) & 0x1Fu);
        S.tw_ox = (u8)((w0 >> 10) & 0x1Fu);
        S.tw_oy = (u8)((w0 >> 15) & 0x1Fu);
        break;
    case 0xE3u:
        S.clip_x1 = (int)(w0 & 0x3FFu);
        S.clip_y1 = (int)((w0 >> 10) & 0x1FFu);
        break;
    case 0xE4u:
        S.clip_x2 = (int)(w0 & 0x3FFu);
        S.clip_y2 = (int)((w0 >> 10) & 0x1FFu);
        break;
    case 0xE5u:
        S.off_x = sign_ext11(w0);
        S.off_y = sign_ext11(w0 >> 11);
        break;
    case 0xE6u:
        S.set_mask   = (u8)(w0 & 1u);
        S.check_mask = (u8)((w0 >> 1) & 1u);
        S.gpustat = (S.gpustat & ~(3u << 11)) | ((w0 & 3u) << 11);
        break;
    default:
        break;
    }
}

static inline void vram_put_half(u16 val)
{
    u16 *dst = &W.vram[((S.vram_ty + S.vram_cy) & 511u) * VRAM_STRIDE + ((S.vram_tx + S.vram_cx) & 1023u)];
    if (!(S.check_mask && (*dst & 0x8000u)))
        *dst = val | (S.set_mask ? 0x8000u : 0u);
    if (++S.vram_cx >= S.vram_tw) {
        S.vram_cx = 0;
        if (++S.vram_cy >= S.vram_th)
            S.gp0_mode = 0u;
    }
}

/* words from RAM (2 MB offset `addr`, ascending) into the CPU -> VRAM transfer in progress (gp0_mode 1): what as
   many gpu_gp0() calls do -- two vram_put_half() a word, a word's upper half dropped when the transfer ends after
   its lower one -- with the position in registers and the row's address once a row.  Videos (MDEC) and textures
   arrive this way by DMA: Tony Hawk's intro spent ~19% of its time in a call a word.  Returns the words used */
static u32 gpu_vram_write_block(u32 addr, u32 n)
{
    u32 tx = S.vram_tx, ty = S.vram_ty, tw = S.vram_tw, th = S.vram_th, cx = S.vram_cx, cy = S.vram_cy;
    u16 mask_or = S.set_mask ? 0x8000u : 0u;
    int check = S.check_mask;
    if (!check && !((tx | tw | cx) & 1u) && tx + tw <= 1024u) {
        /* even x and width, no mask test, no wrap at x 1024: each word is two pixels side by side in one row --
           one 32-bit store a word (rows 2080 bytes apart, x even: aligned) */
        u32 mask32 = mask_or ? 0x80008000u : 0u, i = 0;
        while (i < n) {
            u32 *d = (u32 *)&W.vram[((ty + cy) & 511u) * VRAM_STRIDE + tx + cx];
            u32 k, run = (tw - cx) >> 1;
            if (run > n - i)
                run = n - i;
            for (k = 0; k < run; k++, addr = (addr + 4u) & 0x1FFFFCu)
                d[k] = *(const u32 *)(W.ram + addr) | mask32;
            i += run;
            cx += run * 2u;
            if (cx >= tw) {
                cx = 0;
                if (++cy >= th) {
                    S.vram_cx = (u16)cx;
                    S.vram_cy = (u16)cy;
                    S.gp0_mode = 0u;
                    return i;
                }
            }
        }
        S.vram_cx = (u16)cx;
        S.vram_cy = (u16)cy;
        return n;
    }
    u16 *row = &W.vram[((ty + cy) & 511u) * VRAM_STRIDE];
    for (u32 i = 0; i < n; i++, addr = (addr + 4u) & 0x1FFFFCu) {
        u32 w = *(const u32 *)(W.ram + addr);
        for (int h = 0; h < 2; h++, w >>= 16) {
            u16 *dst = &row[(tx + cx) & 1023u];
            if (!(check && (*dst & 0x8000u)))
                *dst = (u16)((u16)w | mask_or);
            if (++cx >= tw) {
                cx = 0;
                if (++cy >= th) {
                    S.vram_cx = (u16)cx;
                    S.vram_cy = (u16)cy;
                    S.gp0_mode = 0u;
                    return i + 1u;
                }
                row = &W.vram[((ty + cy) & 511u) * VRAM_STRIDE];
            }
        }
    }
    S.vram_cx = (u16)cx;
    S.vram_cy = (u16)cy;
    return n;
}

static void gpu_gp0(u32 word)
{
    if (S.gp0_mode == 1u) { /* CPU -> VRAM pixel stream */
        vram_put_half((u16)word);
        if (S.gp0_mode == 1u)
            vram_put_half((u16)(word >> 16));
        return;
    }
    if (S.gp0_mode == 2u) { /* Polyline continuation */
        if ((word & 0xF000F000u) == 0x50005000u) {
            S.gp0_mode = 0u;
            S.gp0_len = 0;
            return;
        }
        S.gp0_buf[S.gp0_len++] = word;
        u8 need = S.gp0_poly_gouraud ? 2u : 1u;
        if (S.gp0_len >= need) {
            u32 nc = S.gp0_poly_gouraud ? S.gp0_buf[0] : S.gp0_poly_prev_col;
            u32 nxy = S.gp0_buf[S.gp0_poly_gouraud ? 1 : 0];
            if (!gpu_can_skip_draw())
                gpu_draw_line(sign_ext11(S.gp0_poly_prev_xy) + S.off_x, sign_ext11(S.gp0_poly_prev_xy >> 16) + S.off_y, S.gp0_poly_prev_col,
                              sign_ext11(nxy) + S.off_x, sign_ext11(nxy >> 16) + S.off_y, nc,
                              S.gp0_poly_gouraud, S.gp0_poly_semi);
            S.gp0_poly_prev_xy = nxy;
            S.gp0_poly_prev_col = nc;
            S.gp0_len = 0;
        }
        return;
    }

    if (S.gp0_len == 0u) {
        u8 op = (u8)(word >> 24);
        if (op == 0x00u || op == 0x01u)
            return;
        S.gp0_need = gp0_cmd_words(op);
    }
    S.gp0_buf[S.gp0_len++] = word;
    if (S.gp0_len >= S.gp0_need) {
        S.gp0_len = 0;
        gp0_exec_packet();
    }
}

static u32 gpu_read_data(void)
{
    if (S.gpustat & (1u << 27)) {
        u16 lo = W.vram[((S.vram_ry + S.vram_rcy) & 511u) * VRAM_STRIDE + ((S.vram_rx + S.vram_rcx) & 1023u)];
        if (++S.vram_rcx >= S.vram_rw) {
            S.vram_rcx = 0;
            if (++S.vram_rcy >= S.vram_rh)
                S.gpustat &= ~(1u << 27);
        }
        u16 hi = 0;
        if (S.gpustat & (1u << 27)) {
            hi = W.vram[((S.vram_ry + S.vram_rcy) & 511u) * VRAM_STRIDE + ((S.vram_rx + S.vram_rcx) & 1023u)];
            if (++S.vram_rcx >= S.vram_rw) {
                S.vram_rcx = 0;
                if (++S.vram_rcy >= S.vram_rh)
                    S.gpustat &= ~(1u << 27);
            }
        }
        S.gpuread = (u32)lo | ((u32)hi << 16);
    }
    return S.gpuread;
}

static void gpu_gp1(u32 word)
{
    u8 op = (u8)((word >> 24) & 0x3Fu);
    u32 arg = word & 0xFFFFFFu;
    switch (op) {
    case 0x00u: /* Reset GPU */
        S.gpustat = 0x14802000u;
        S.gp0_len = S.gp0_mode = 0;
        S.clip_x1 = S.clip_y1 = 0;
        S.clip_x2 = 1023;
        S.clip_y2 = 511;
        S.off_x = S.off_y = 0;
        S.tw_mx = S.tw_my = S.tw_ox = S.tw_oy = 0;
        S.set_mask = S.check_mask = S.dither = S.disp_24bpp = 0;
        S.disp_x = S.disp_y = 0;
        S.disp_w = PSX_W_DEF;
        S.disp_h = PSX_H_DEF;
        S.disp_disabled = S.vram_full_clear = 0;
        S.fs_active = S.fs_dropped = S.disp_stale = 0;
        S.disp_dirty = 1u;
        break;
    case 0x01u: /* Reset Command Buffer */
        S.gp0_len = S.gp0_mode = 0;
        break;
    case 0x02u: /* Ack GPU IRQ */
        S.gpustat &= ~(1u << 24);
        break;
    case 0x03u: /* Display Enable (0=on, 1=off) */
        if (S.disp_disabled != (u8)(arg & 1u))
            S.disp_dirty = 1u;
        S.disp_disabled = (u8)(arg & 1u);
        if (S.disp_disabled) S.gpustat |= (1u << 23);
        else                 S.gpustat &= ~(1u << 23);
        break;
    case 0x04u: /* DMA Direction */
        S.gpustat = (S.gpustat & ~(3u << 29)) | ((arg & 3u) << 29);
        break;
    case 0x05u: { /* Start of Display Area in VRAM */
        u16 nx = (u16)(arg & 0x3FEu), ny = (u16)((arg >> 10) & 0x1FFu);
        if (nx != S.disp_x || ny != S.disp_y) {         /* a flip: the next game frame begins */
            S.disp_stale = (u8)(S.fs_active && S.fs_dropped);   /* the buffer shown now was not drawn */
            /* the player is late: skip drawing the coming game frame -- never two in a row */
            S.fs_active = (u8)(S.skip_render >= 2u && !S.disp_stale);
            S.fs_dropped = 0u;
            S.fs_age = 0u;
            S.fs_skipped += S.fs_active;
            S.disp_dirty = 1u;
            S.disp_flipped = 1u;
        }
        S.disp_x = nx;
        S.disp_y = ny;
        break;
    }
    case 0x06u: /* Horizontal Display Range */
        break;
    case 0x07u: /* Vertical Display Range */
        break;
    case 0x08u: { /* Display Mode */
        static const int wtab[4] = {256, 320, 512, 640};
        S.disp_w = (arg & 0x40u) ? 368 : wtab[arg & 3u];
        S.disp_h = ((arg & 0x04u) && (arg & 0x20u)) ? 480 : 240;
        S.disp_24bpp = (u8)((arg >> 4) & 1u);
        S.disp_dirty = 1u;
        if (arg & 0x08u)
            S.is_pal = 1u;
        S.gpustat = (S.gpustat & ~0x7F4000u)
                  | ((arg & 0x3Fu) << 17)
                  | ((arg & 0x40u) << 10)
                  | ((arg & 0x80u) << 7);
        break;
    }
    case 0x09u:
        S.tex_disable = (u8)(arg & 1u);
        break;
    default:
        if ((op & 0xF0u) == 0x10u) {
            switch (arg & 7u) {
            case 2u: S.gpuread = S.tw_mx | ((u32)S.tw_my << 5) | ((u32)S.tw_ox << 10) | ((u32)S.tw_oy << 15); break;
            case 3u: S.gpuread = (u32)S.clip_x1 | ((u32)S.clip_y1 << 10); break;
            case 4u: S.gpuread = (u32)S.clip_x2 | ((u32)S.clip_y2 << 10); break;
            case 5u: S.gpuread = ((u32)S.off_x & 0x7FFu) | (((u32)S.off_y & 0x7FFu) << 11); break;
            case 7u: S.gpuread = 2u; break;
            default: S.gpuread = 0u; break;
            }
        }
        break;
    }
}

static void gpu_scanout(u16 *picture)
{
    int w = S.disp_w, h = S.disp_h;
    if (S.disp_disabled) {
        for (int i = 0; i < w * h; i++)
            picture[i] = 0u;
        return;
    }
    if (S.disp_24bpp) {
        const u8 *vbytes = (const u8 *)W.vram;
        for (int y = 0; y < h; y++) {
            u32 row_byte_base = ((u32)(S.disp_y + y) & 511u) * 2048u + (u32)S.disp_x * 2u;
            u16 *dst = picture + y * w;
            for (int x = 0; x < w; x++) {
                u32 bo = (row_byte_base + (u32)x * 3u) & 0xFFFFFu;
                u32 b1 = (bo + 1u) & 0xFFFFFu, b2 = (bo + 2u) & 0xFFFFFu;
                u8 r = vbytes[(bo >> 11) * (2u * VRAM_STRIDE) + (bo & 2047u)];
                u8 g = vbytes[(b1 >> 11) * (2u * VRAM_STRIDE) + (b1 & 2047u)];
                u8 b = vbytes[(b2 >> 11) * (2u * VRAM_STRIDE) + (b2 & 2047u)];
                dst[x] = (u16)(((u16)(b >> 3) << 10) | ((u16)(g >> 3) << 5) | (r >> 3));
            }
        }
    } else if (((S.disp_x | (u16)w | ((u32)(__UINTPTR_TYPE__)picture >> 1)) & 1u) == 0u && S.disp_x + w <= 1024) {
        int wn = w >> 1;
        for (int y = 0; y < h; y++) {
            const u32 *s32 = (const u32 *)(W.vram + ((S.disp_y + y) & 511) * VRAM_STRIDE + S.disp_x);
            u32 *d32 = (u32 *)(picture + y * w);
            for (int i = 0; i < wn; i++)
                d32[i] = s32[i] & 0x7FFF7FFFu;
        }
    } else {
        for (int y = 0; y < h; y++) {
            const u16 *src = W.vram + ((S.disp_y + y) & 511) * VRAM_STRIDE;
            u16 *dst = picture + y * w;
            for (int x = 0; x < w; x++)
                dst[x] = src[(S.disp_x + x) & 1023] & 0x7FFFu;
        }
    }
}

/* ---- DMA Controller (DMA0..6 + DICR) ---- */
static void dicr_update_irq(void)
{
    int force = (S.dicr >> 15) & 1;
    int master_en = (S.dicr >> 23) & 1;
    u32 en = (S.dicr >> 16) & 0x7Fu;
    u32 fl = (S.dicr >> 24) & 0x7Fu;
    int active = force || (master_en && (en & fl) != 0u);
    if (active) {
        if (!(S.dicr & 0x80000000u)) {
            S.dicr |= 0x80000000u;
            raise_irq(1u << 3); /* IRQ3 DMA */
        }
    } else {
        S.dicr &= ~0x80000000u;
    }
}

static inline u32 ram_rd32(u32 phys)
{
    u32 off = phys & 0x1FFFFCu;
    return *(const u32 *)(W.ram + off);
}

static inline void ram_wr32(u32 phys, u32 val)
{
    u32 off = phys & 0x1FFFFCu;
    u32 *p32 = (u32 *)(W.ram + off);
    if (*p32 != val) {
        *p32 = val;
        jit_touch_ram(off);
    }
}

static void dma_run(int ch)
{
    u32 chcr = S.dma_chcr[ch];
    if (!(chcr & (1u << 24)))
        return;

    u32 addr = S.dma_madr[ch] & 0x1FFFFCu;
    u32 sync = (chcr >> 9) & 3u;
    int dir_from_ram = chcr & 1u;
    int step = (chcr & 2u) ? -4 : 4;

    u32 words = 0;
    if (sync == 0u) {
        words = S.dma_bcr[ch] & 0xFFFFu;
        if (words == 0u) words = 0x10000u;
    } else if (sync == 1u) {
        u32 bs = S.dma_bcr[ch] & 0xFFFFu;
        u32 ba = (S.dma_bcr[ch] >> 16) & 0xFFFFu;
        if (bs == 0u) bs = 0x10000u;
        words = bs * ba;
    }

    if (ch == 6) { /* OTC: reverse clear Ordering Table in RAM */
        u32 cnt = S.dma_bcr[6] & 0xFFFFu;
        if (cnt == 0u) cnt = 0x10000u;
        while (cnt > 1u) {
            u32 prev = (addr - 4u) & 0x1FFFFCu;
            ram_wr32(addr, prev);
            addr = prev;
            cnt--;
        }
        ram_wr32(addr, 0x00FFFFFFu);
    } else if (ch == 2) { /* GPU */
        if (sync == 2u) { /* Linked-list Ordering Table */
            u32 guard = 0;
            const u8 *ram_base = W.ram;
            while ((addr & 0x800000u) == 0u && addr != 0xFFFFFFu && guard++ < 0x40000u) {
                const u32 *node = (const u32 *)(ram_base + (addr & 0x1FFFFCu));
                u32 hdr = node[0];
                u32 cnt = hdr >> 24;
                if (cnt) {
                    if ((addr & 0x1FFFFCu) + cnt * 4u < PSX_RAM_SIZE && S.gp0_mode == 0u && S.gp0_len == 0u) {
                        u32 i = 1u;
                        while (i <= cnt) {
                            u32 w0 = node[i];
                            u8 op = (u8)(w0 >> 24);
                            if (op == 0x00u || op == 0x01u) {
                                i++;
                                continue;
                            }
                            if ((op >> 5) == 1u) {
                                u32 nw = gp0_poly_words[op & 0x1Fu];
                                if (i + nw - 1u <= cnt) {
                                    gpu_exec_poly_words(&node[i], op);
                                    i += nw;
                                    continue;
                                }
                            }
                            gpu_gp0(w0);
                            i++;
                            if (S.gp0_mode != 0u || S.gp0_len != 0u) {
                                for (; i <= cnt; i++)
                                    gpu_gp0(node[i]);
                                break;
                            }
                        }
                    } else if ((addr & 0x1FFFFCu) + cnt * 4u < PSX_RAM_SIZE) {
                        for (u32 i = 1; i <= cnt; i++)
                            gpu_gp0(node[i]);
                    } else {
                        for (u32 i = 1; i <= cnt; i++)
                            gpu_gp0(ram_rd32(addr + i * 4u));
                    }
                }
                u32 next = hdr & 0xFFFFFFu;
                if (next == 0xFFFFFFu || (next & 0x800000u))
                    break;
                addr = next & 0x1FFFFCu;
            }
            S.dma_madr[2] = 0xFFFFFFu;
        } else if (dir_from_ram) {
            for (u32 i = 0; i < words; ) {
                if (S.gp0_mode == 1u && step > 0) {             /* pixels of a CPU -> VRAM transfer: a block */
                    u32 used = gpu_vram_write_block(addr, words - i);
                    i += used;
                    addr = (addr + used * 4u) & 0x1FFFFCu;
                    continue;
                }
                gpu_gp0(ram_rd32(addr));
                i++;
                addr = (u32)((int)addr + step) & 0x1FFFFCu;
            }
            S.dma_madr[2] = addr;
        } else {
            for (u32 i = 0; i < words; i++, addr = (u32)((int)addr + step) & 0x1FFFFCu)
                ram_wr32(addr, gpu_read_data());
            S.dma_madr[2] = addr;
        }
    } else if (ch == 3) { /* CD-ROM -> RAM */
        S.cd_xa_streak = 0u;
        /* (the FIFO's place in a register, 4 bytes a word while 4 are left: it was kept in S a byte -- a video's
           sectors came through here at ~10% of the time; past the end the last byte again, as before) */
        u32 pos = S.cd_fifo_pos, len = S.cd_fifo_len;
        const u8 *f = W.cd_fifo;
        for (u32 i = 0; i < words; i++, addr = (u32)((int)addr + step) & 0x1FFFFCu) {
            u32 w;
            if (pos + 4u <= len) {
                w = (u32)f[pos] | ((u32)f[pos + 1u] << 8) | ((u32)f[pos + 2u] << 16) | ((u32)f[pos + 3u] << 24);
                pos += 4u;
            } else {
                w = 0;
                for (int b = 0; b < 4; b++) {
                    u8 v = (pos < len) ? f[pos++] : (len ? f[len - 1u] : 0u);
                    w |= (u32)v << (b * 8);
                }
            }
            ram_wr32(addr, w);
        }
        S.cd_fifo_pos = pos;
        S.dma_madr[3] = addr;
    } else if (ch == 4) { /* SPU <-> RAM */
        for (u32 i = 0; i < words; i++, addr = (u32)((int)addr + step) & 0x1FFFFCu) {
            if (dir_from_ram) {
                u32 w = ram_rd32(addr);
                for (int b = 0; b < 4; b++)
                    W.spu_ram[(S.spu_xfer_addr++) & 0x7FFFFu] = (u8)(w >> (b * 8));
            } else {
                u32 w = 0;
                for (int b = 0; b < 4; b++)
                    w |= (u32)W.spu_ram[(S.spu_xfer_addr++) & 0x7FFFFu] << (b * 8);
                ram_wr32(addr, w);
            }
        }
        S.dma_madr[4] = addr;
    } else if (ch == 0) { /* MDECin (RAM -> MDEC) */
        for (u32 i = 0; i < words; i++, addr = (u32)((int)addr + step) & 0x1FFFFCu) {
            u32 w = ram_rd32(addr);
            if (S.mdec_words_rem == 0u) {
                S.mdec_cmd = w;
                u32 op = w >> 29;
                if (op == 1u) S.mdec_words_rem = (w & 0xFFFFu) ? (w & 0xFFFFu) : 1u;
                else if (op == 2u) S.mdec_words_rem = (w & 1u) ? 32u : 16u;
                else if (op == 3u) S.mdec_words_rem = 32u;
                S.mdec_in_cnt = 0;
                S.mdec_stat |= (1u << 29);
            } else {
                if (S.mdec_in_cnt < 16384u)
                    W.mdec_in[S.mdec_in_cnt++] = w;
                if (--S.mdec_words_rem == 0u)
                    mdec_execute();
            }
        }
        S.dma_madr[0] = addr;
    } else if (ch == 1) { /* MDECout (MDEC -> RAM) */
        if (S.mdec_out_pos >= S.mdec_out_len && S.mdec_in_pos < S.mdec_in_cnt * 2u)
            mdec_decode_chunk();
        if (S.mdec_out_pos >= S.mdec_out_len && S.mdec_words_rem > 0u)
            return; /* Defer DMA1 until DMA0 finishes feeding MDEC */
        for (u32 i = 0; i < words; i++, addr = (u32)((int)addr + step) & 0x1FFFFCu) {
            u32 w = 0;
            for (int b = 0; b < 4; b++) {
                if (S.mdec_out_pos >= S.mdec_out_len && S.mdec_in_pos < S.mdec_in_cnt * 2u)
                    mdec_decode_chunk();
                u8 v = (S.mdec_out_pos < S.mdec_out_len) ? W.mdec_out[S.mdec_out_pos++] : 0u;
                w |= (u32)v << (b * 8);
            }
            ram_wr32(addr, w);
        }
        if (S.mdec_out_pos >= S.mdec_out_len && S.mdec_in_pos < S.mdec_in_cnt * 2u)
            mdec_decode_chunk();
        if (S.mdec_out_pos >= S.mdec_out_len) {
            S.mdec_stat |= (1u << 31);
            S.mdec_stat &= ~(1u << 29);
        }
        S.dma_madr[1] = addr;
    }

    S.dma_chcr[ch] &= ~((1u << 24) | (1u << 28));
    if (S.dicr & (1u << (16 + ch)))
        S.dicr |= (1u << (24 + ch));
    dicr_update_irq();
    if (ch == 0 && (S.dma_chcr[1] & (1u << 24)))
        dma_run(1);
}

/* ---- Root Counters 0..2 ($1F801100..$1F80112F) ---- */
static void rcnt_step(int sys_cycles, int hblank_edge, int in_vblank)
{
    for (int t = 0; t < 3; t++) {
        u16 mode = S.rcnt_mode[t];
        if (mode & 1u) { /* Sync enable */
            u32 sm = (mode >> 1) & 3u;
            if (t == 1 && (sm == 0u || sm == 3u) && in_vblank) continue;
            if (t == 2 && (sm == 0u || sm == 3u)) continue;
        }
        u32 inc = 0;
        u32 clk = (mode >> 8) & 3u;
        if (t == 0) {
            inc = (u32)sys_cycles / 5u;
            if (inc == 0u && sys_cycles > 0) inc = 1u;
        } else if (t == 1) {
            inc = (clk & 1u) ? (u32)hblank_edge : (u32)sys_cycles;
        } else {
            inc = (clk >= 2u) ? ((u32)sys_cycles >> 3) : (u32)sys_cycles;
            if (inc == 0u && sys_cycles >= 8) inc = 1u;
        }
        if (!inc) continue;

        u32 old_v = S.rcnt_val[t];
        u32 new_v = old_v + inc;
        u32 targ = S.rcnt_targ[t] ? (u32)S.rcnt_targ[t] : 0x10000u;

        if (old_v < targ && new_v >= targ) {
            S.rcnt_mode[t] |= (1u << 11);
            if (mode & (1u << 3))
                new_v %= targ;
            if (mode & (1u << 4))
                raise_irq((u16)(1u << (4 + t)));
        }
        if (new_v >= 0xFFFFu) {
            S.rcnt_mode[t] |= (1u << 12);
            new_v &= 0xFFFFu;
            if (mode & (1u << 5))
                raise_irq((u16)(1u << (4 + t)));
        }
        S.rcnt_val[t] = new_v;
    }
}

/* ---- MMIO Bus ($1F801000..$1F801FFF) ---- */
static u8 hle_ev_cb_cursor;
static u32 io_read32(u32 off);
static void io_write32(u32 off, u32 val);

static u8 io_read8(u32 off)
{
    if (off == 0x040u) {
        int had = (S.sio_pos < S.sio_len);
        u8 v = had ? S.sio_fifo[S.sio_pos++] : 0xFFu;
        if (had && S.sio_irq_delay > 32)
            S.sio_irq_delay = 32; /* /ACK pulse begins right after 8-bit RX byte is read */
        return v;
    }
    if (off == 0x044u) {
        u8 st = 0x05u; /* TX ready 1 & 2 */
        if (S.sio_pos < S.sio_len) st |= 0x02u; /* RX FIFO not empty */
        if (S.sio_irq_delay > 0 && S.sio_irq_delay <= 48) st |= 0x80u; /* /ACK (DSR) pulse */
        return st;
    }
    if (off == 0x045u)
        return (S.sio_irq_delay < 0) ? 0x02u : 0x00u;
    if (off == 0x800u) {
        u8 st = (u8)(S.cd_index & 3u);
        if (S.cd_param_n == 0u) st |= 0x08u; /* PRMEMPT */
        if (S.cd_param_n < 16u) st |= 0x10u; /* PRMWRDY */
        if (S.cd_resp_p < S.cd_resp_n) st |= 0x20u; /* RSLRRDY */
        if (S.cd_fifo_pos < S.cd_fifo_len) st |= 0x40u; /* DRQSTS */
        if (S.cd_req_valid && S.cd_req_delay > 0) st |= 0x80u; /* BUSYSTS */
        return st;
    }
    if (off == 0x801u) {
        return (S.cd_resp_p < S.cd_resp_n) ? S.cd_resp[S.cd_resp_p++] : 0u;
    }
    if (off == 0x802u) {
        S.cd_xa_streak = 0u;
        return (S.cd_fifo_pos < S.cd_fifo_len) ? W.cd_fifo[S.cd_fifo_pos++] : 0u;
    }
    if (off == 0x803u) {
        return (S.cd_index & 1u) ? (u8)(0xE0u | S.cd_irq_flag) : (u8)(0xE0u | S.cd_irq_en);
    }
    if ((off >= 0x070u && off < 0x078u) || (off >= 0x080u && off < 0x0F8u)) {
        u32 v32 = io_read32(off & ~3u);
        return (u8)(v32 >> ((off & 3u) * 8u));
    }
    return W.io[off & 0xFFFu];
}

static u16 io_read16(u32 off)
{
    if (off == 0x044u) {
        u16 st = 0x0005u;
        if (S.sio_pos < S.sio_len) st |= 0x0002u;
        if (S.sio_irq_delay > 0 && S.sio_irq_delay <= 48) st |= 0x0080u;
        if (S.sio_irq_delay < 0)   st |= 0x0200u;
        return st;
    }
    if (off == 0x04Au) return S.sio_ctrl;
    if (off == 0x04Eu) return S.sio_baud;
    if (off == 0x070u) return S.i_stat;
    if (off == 0x074u) return S.i_mask;
    if (off >= 0x100u && off < 0x130u) {
        u32 t = (off - 0x100u) >> 4, r = off & 0x0Fu;
        if (r == 0u) return (u16)S.rcnt_val[t];
        if (r == 4u) { u16 m = S.rcnt_mode[t]; S.rcnt_mode[t] &= ~0x1800u; return m; }
        if (r == 8u) return S.rcnt_targ[t];
        return 0u;
    }
    if (off >= 0xC00u && off < 0xD80u) {
        u32 ch = (off - 0xC00u) >> 4, r = off & 0x0Eu;
        const struct spu_voice *v = &S.spu_v[ch];
        switch (r) {
        case 0x0u: return v->vol_l;
        case 0x2u: return v->vol_r;
        case 0x4u: return v->pitch;
        case 0x6u: return v->start_addr;
        case 0x8u: return v->adsr_lo;
        case 0xAu: return v->adsr_hi;
        case 0xCu: return (u16)v->env;
        case 0xEu: return v->repeat_addr;
        }
    }
    if (off == 0xDAAu) return S.spu_ctrl;
    if (off == 0xDAEu) return (u16)(S.spu_ctrl & 0x3Fu);
    if (off == 0xD9Cu) return (u16)S.spu_endx;
    if (off == 0xD9Eu) return (u16)(S.spu_endx >> 16);
    if (off == 0xDA6u) return (u16)(S.spu_xfer_addr >> 3);
    if (off >= 0x080u && off < 0x0F0u) {
        u32 v32 = io_read32(off & ~3u);
        return (u16)((off & 2u) ? (v32 >> 16) : v32);
    }
    if (off == 0x0F0u || off == 0x0F2u)
        return (u16)((off & 2u) ? (S.dpcr >> 16) : S.dpcr);
    if (off == 0x0F4u || off == 0x0F6u)
        return (u16)((off & 2u) ? (S.dicr >> 16) : S.dicr);
    return (u16)io_read8(off) | ((u16)io_read8(off + 1u) << 8);
}

static u32 io_read32(u32 off)
{
    if (off == 0x070u) return S.i_stat;
    if (off == 0x074u) return S.i_mask;
    if (off >= 0x080u && off < 0x0F0u) {
        u32 ch = (off - 0x080u) >> 4, r = off & 0x0Cu;
        if (r == 0u) return S.dma_madr[ch];
        if (r == 4u) return S.dma_bcr[ch];
        if (r == 8u) return S.dma_chcr[ch];
        return 0u;
    }
    if (off == 0x0F0u) return S.dpcr;
    if (off == 0x0F4u) return S.dicr;
    if (off == 0x810u) return gpu_read_data();
    if (off == 0x814u) {
        /* 480i interlace: bit 31 tracks odd/even field (flips at VBlank); 240p: alternates per active line */
        u32 lcf = ((S.gpustat & ((1u << 22) | (1u << 19))) == ((1u << 22) | (1u << 19)))
                ? ((S.vblank_count & 1u) << 31)
                : (((S.scan_y & 1) && S.scan_y < PSX_VBL_LINE) ? 0x80000000u : 0u);
        u32 fld = (S.gpustat & (1u << 22)) ? ((S.vblank_count & 1u) << 13) : (1u << 13);
        return (S.gpustat & ~0x80002000u) | 0x1C000000u | fld | lcf;
    }
    if (off == 0x820u) {
        u32 w = 0;
        for (int b = 0; b < 4; b++) {
            if (S.mdec_out_pos >= S.mdec_out_len && S.mdec_in_pos < S.mdec_in_cnt * 2u)
                mdec_decode_chunk();
            u8 v = (S.mdec_out_pos < S.mdec_out_len) ? W.mdec_out[S.mdec_out_pos++] : 0u;
            w |= (u32)v << (b * 8);
        }
        if (S.mdec_out_pos >= S.mdec_out_len && S.mdec_in_pos < S.mdec_in_cnt * 2u)
            mdec_decode_chunk();
        if (S.mdec_out_pos >= S.mdec_out_len) {
            S.mdec_stat |= (1u << 31);
            S.mdec_stat &= ~(1u << 29);
        }
        return w;
    }
    if (off == 0x824u) return S.mdec_stat;
    return (u32)io_read16(off) | ((u32)io_read16(off + 2u) << 16);
}

static void io_write8(u32 off, u8 val)
{
    if (off == 0x040u) {
        S.sio_fifo[0] = sio0_txrx(val);
        S.sio_pos = 0;
        S.sio_len = 1;
        return;
    }
    if (off == 0x800u) { S.cd_index = val & 3u; return; }
    if (off == 0x801u) {
        if (S.cd_index == 0u) {
            if (S.cd_req_valid) {
                u8 prev_cmd = S.cd_req_cmd;
                S.cd_req_valid = 0u;
                cd_exec_cmd(prev_cmd);
            }
            for (u32 i = 0; i < S.cd_param_n && i < 16u; i++)
                S.cd_req_param[i] = S.cd_param[i];
            S.cd_req_param_n = S.cd_param_n;
            S.cd_param_n = 0u;
            if ((S.cd_irq_flag & 0x07u) && (hle_ev_cb_cursor != 0u || (S.i_stat & 4u))) {
                /* Defer INT3 until active guest ISR acknowledges current CD IRQ at $1F801803 (Sony libds DmCdIntr) */
                S.cd_req_cmd = val;
                S.cd_req_valid = 1u;
                S.cd_req_delay = 256;
            } else {
                S.cd_irq_flag = 0u;
                cd_exec_cmd(val);
            }
        }
        return;
    }
    if (off == 0x802u) {
        if (S.cd_index == 0u && S.cd_param_n < 16u) S.cd_param[S.cd_param_n++] = val;
        else if (S.cd_index == 1u) {
            S.cd_irq_en = val & 0x1Fu;
            if (S.cd_irq_flag & S.cd_irq_en)
                raise_irq(1u << 2);
        }
        return;
    }
    if (off == 0x803u) {
        if (S.cd_index == 1u) {
            S.cd_irq_flag &= (u8)~(val & 0x1Fu);
            if (val & 0x40u) S.cd_param_n = 0;
            if (S.cd_req_valid && !(S.cd_irq_flag & 0x07u)) {
                S.cd_req_delay = 0;
                S.jit_stop |= 2u;
            }
        }
        return;
    }
    if (off == 0x070u || off == 0x071u) {
        u16 m = (off & 1u) ? (u16)(0x00FFu | ((u16)val << 8)) : (u16)(0xFF00u | val);
        S.i_stat &= m;
        update_cop0_irq();
        return;
    }
    if (off == 0x074u) { S.i_mask = (S.i_mask & 0x0700u) | val; update_cop0_irq(); return; }
    if (off == 0x075u) { S.i_mask = (S.i_mask & 0x00FFu) | (((u16)val & 0x07u) << 8); update_cop0_irq(); return; }
    if (off >= 0x080u && off < 0x0F0u) {
        u32 sh = (off & 3u) * 8u;
        u32 cur = io_read32(off & ~3u);
        if ((off & 0x0Cu) == 8u && (off & 3u) != 3u) cur &= ~(1u << 24);
        io_write32(off & ~3u, (cur & ~(0xFFu << sh)) | ((u32)val << sh));
        return;
    }
    if (off >= 0x0F0u && off < 0x0F4u) {
        u32 sh = (off & 3u) * 8u;
        S.dpcr = (S.dpcr & ~(0xFFu << sh)) | ((u32)val << sh);
        return;
    }
    if (off == 0x0F4u) { S.dicr = (S.dicr & ~0x0000003Fu) | (val & 0x3Fu); dicr_update_irq(); return; }
    if (off == 0x0F5u) { S.dicr = (S.dicr & ~0x00008000u) | (((u32)val & 0x80u) << 8); dicr_update_irq(); return; }
    if (off == 0x0F6u) { S.dicr = (S.dicr & ~0x00FF0000u) | ((u32)val << 16); dicr_update_irq(); return; }
    if (off == 0x0F7u) { S.dicr &= ~(((u32)val & 0x7Fu) << 24); dicr_update_irq(); return; }
    if (off == 0x1041u) return; /* POST */
    W.io[off & 0xFFFu] = val;
}

static void io_write16(u32 off, u16 val)
{
    if (off == 0x040u) { io_write8(0x040u, (u8)val); return; }
    if (off == 0x048u) { S.sio_mode = val; return; }
    if (off == 0x04Au) {
        if (val & 0x0040u) { /* Reset */
            S.sio_ctrl = 0; S.sio_step = 0; S.sio_dev = 0; S.sio_len = S.sio_pos = 0; S.sio_irq_delay = 0;
            return;
        }
        if (val & 0x0010u) { /* Ack IRQ */
            if (S.sio_irq_delay < 0) S.sio_irq_delay = 0;
        }
        if (!(val & 0x0002u)) { /* DTR dropped -> end packet */
            S.sio_step = 0;
            S.sio_dev = 0;
            S.sio_irq_delay = 0;
        }
        S.sio_ctrl = (u16)(val & ~0x0050u);
        return;
    }
    if (off == 0x04Eu) { S.sio_baud = val; return; }
    if (off == 0x070u) { S.i_stat &= val; update_cop0_irq(); return; }
    if (off == 0x074u) { S.i_mask = val & 0x7FFu; update_cop0_irq(); return; }
    if (off >= 0x080u && off < 0x0F8u) {
        io_write8(off, (u8)val);
        io_write8(off + 1u, (u8)(val >> 8));
        return;
    }
    if (off >= 0x100u && off < 0x130u) {
        u32 t = (off - 0x100u) >> 4, r = off & 0x0Fu;
        if (r == 0u) S.rcnt_val[t] = val;
        else if (r == 4u) { S.rcnt_mode[t] = (u16)((val & 0x03FFu) | (1u << 10)); S.rcnt_val[t] = 0; }
        else if (r == 8u) S.rcnt_targ[t] = val;
        return;
    }
    if (off >= 0xC00u && off < 0xD80u) {
        u32 ch = (off - 0xC00u) >> 4, r = off & 0x0Eu;
        struct spu_voice *v = &S.spu_v[ch];
        switch (r) {
        case 0x0u: v->vol_l = val; spu_update_voice_params(v); break;
        case 0x2u: v->vol_r = val; spu_update_voice_params(v); break;
        case 0x4u: v->pitch = val; spu_update_voice_params(v); break;
        case 0x6u: v->start_addr = val; break;
        case 0x8u: v->adsr_lo = val; break;
        case 0xAu: v->adsr_hi = val; break;
        case 0xCu: v->env = val & 0x7FFFu; break;
        case 0xEu: v->repeat_addr = val; v->has_manual_repeat = 1; break;
        }
        return;
    }
    if (off == 0xD80u) { S.spu_mvol_l = val; return; }
    if (off == 0xD82u) { S.spu_mvol_r = val; return; }
    if (off == 0xD88u) { W.io[0xD88] = (u8)val; W.io[0xD89] = (u8)(val >> 8); spu_key_on(val); return; }
    if (off == 0xD8Au) { spu_key_on(((u32)(val & 0xFFu)) << 16); return; }
    if (off == 0xD8Cu) { spu_key_off(val); return; }
    if (off == 0xD8Eu) { spu_key_off(((u32)(val & 0xFFu)) << 16); return; }
    if (off == 0xDA6u) { S.spu_xfer_addr = ((u32)val) << 3; return; }
    if (off == 0xDA8u) {
        W.spu_ram[(S.spu_xfer_addr++) & 0x7FFFFu] = (u8)val;
        W.spu_ram[(S.spu_xfer_addr++) & 0x7FFFFu] = (u8)(val >> 8);
        return;
    }
    if (off == 0xDAAu) { S.spu_ctrl = val; return; }
    W.io[off & 0xFFFu] = (u8)val;
    W.io[(off + 1u) & 0xFFFu] = (u8)(val >> 8);
}

static void io_write32(u32 off, u32 val)
{
    if (off == 0x070u) { S.i_stat &= (u16)val; update_cop0_irq(); return; }
    if (off == 0x074u) { S.i_mask = (u16)(val & 0x7FFu); update_cop0_irq(); return; }
    if (off >= 0x080u && off < 0x0F0u) {
        u32 ch = (off - 0x080u) >> 4, r = off & 0x0Cu;
        if (r == 0u) S.dma_madr[ch] = val & 0xFFFFFFu;
        else if (r == 4u) S.dma_bcr[ch] = val;
        else if (r == 8u) {
            S.dma_chcr[ch] = val;
            if (val & (1u << 24))
                dma_run((int)ch);
        }
        return;
    }
    if (off == 0x0F0u) { S.dpcr = val; return; }
    if (off == 0x0F4u) {
        u32 ack = val & 0x7F000000u;
        S.dicr = (val & 0x00FF803Fu) | ((S.dicr & 0x7F000000u) & ~ack);
        dicr_update_irq();
        return;
    }
    if (off == 0x810u) { gpu_gp0(val); return; }
    if (off == 0x814u) { gpu_gp1(val); return; }
    if (off == 0x820u) {
        if (S.mdec_words_rem == 0u) {
            S.mdec_cmd = val;
            u32 op = val >> 29;
            if (op == 1u) S.mdec_words_rem = (val & 0xFFFFu) ? (val & 0xFFFFu) : 1u;
            else if (op == 2u) S.mdec_words_rem = (val & 1u) ? 32u : 16u;
            else if (op == 3u) S.mdec_words_rem = 32u;
            S.mdec_in_cnt = 0;
            S.mdec_stat |= (1u << 29);
        } else {
            if (S.mdec_in_cnt < 16384u)
                W.mdec_in[S.mdec_in_cnt++] = val;
            if (--S.mdec_words_rem == 0u)
                mdec_execute();
        }
        return;
    }
    if (off == 0x824u) {
        if (val & 0x80000000u) {
            S.mdec_stat = 0x80040000u;
            S.mdec_words_rem = S.mdec_in_cnt = S.mdec_in_pos = S.mdec_out_pos = S.mdec_out_len = 0;
        }
        return;
    }
    if (off == 0xD88u) { spu_key_on(val & 0xFFFFFFu); return; }
    if (off == 0xD8Cu) { spu_key_off(val & 0xFFFFFFu); return; }
    io_write16(off, (u16)val);
    io_write16(off + 2u, (u16)(val >> 16));
}

/* ---- GTE (COP2) 3D Geometry & Lighting Engine ---- */
static const u8 unr_table[257] = {
    0xFF,0xFD,0xFB,0xF9,0xF7,0xF5,0xF3,0xF1,0xEF,0xEE,0xEC,0xEA,0xE8,0xE6,0xE4,0xE3,
    0xE1,0xDF,0xDD,0xDC,0xDA,0xD8,0xD6,0xD5,0xD3,0xD1,0xD0,0xCE,0xCD,0xCB,0xC9,0xC8,
    0xC6,0xC5,0xC3,0xC1,0xC0,0xBE,0xBD,0xBB,0xBA,0xB8,0xB7,0xB5,0xB4,0xB2,0xB1,0xB0,
    0xAE,0xAD,0xAB,0xAA,0xA9,0xA7,0xA6,0xA4,0xA3,0xA2,0xA0,0x9F,0x9E,0x9C,0x9B,0x9A,
    0x99,0x97,0x96,0x95,0x94,0x92,0x91,0x90,0x8F,0x8D,0x8C,0x8B,0x8A,0x89,0x87,0x86,
    0x85,0x84,0x83,0x82,0x81,0x7F,0x7E,0x7D,0x7C,0x7B,0x7A,0x79,0x78,0x77,0x75,0x74,
    0x73,0x72,0x71,0x70,0x6F,0x6E,0x6D,0x6C,0x6B,0x6A,0x69,0x68,0x67,0x66,0x65,0x64,
    0x63,0x62,0x61,0x60,0x5F,0x5E,0x5D,0x5D,0x5C,0x5B,0x5A,0x59,0x58,0x57,0x56,0x55,
    0x54,0x53,0x53,0x52,0x51,0x50,0x4F,0x4E,0x4D,0x4D,0x4C,0x4B,0x4A,0x49,0x48,0x48,
    0x47,0x46,0x45,0x44,0x43,0x43,0x42,0x41,0x40,0x3F,0x3F,0x3E,0x3D,0x3C,0x3C,0x3B,
    0x3A,0x39,0x39,0x38,0x37,0x36,0x36,0x35,0x34,0x33,0x33,0x32,0x31,0x31,0x30,0x2F,
    0x2E,0x2E,0x2D,0x2C,0x2C,0x2B,0x2A,0x2A,0x29,0x28,0x28,0x27,0x26,0x26,0x25,0x24,
    0x24,0x23,0x22,0x22,0x21,0x20,0x20,0x1F,0x1E,0x1E,0x1D,0x1D,0x1C,0x1B,0x1B,0x1A,
    0x19,0x19,0x18,0x18,0x17,0x16,0x16,0x15,0x15,0x14,0x14,0x13,0x12,0x12,0x11,0x11,
    0x10,0x0F,0x0F,0x0E,0x0E,0x0D,0x0D,0x0C,0x0C,0x0B,0x0A,0x0A,0x09,0x09,0x08,0x08,
    0x07,0x07,0x06,0x06,0x05,0x05,0x04,0x04,0x03,0x03,0x02,0x02,0x01,0x01,0x00,0x00,
    0x00
};

static inline __attribute__((always_inline)) u32 count_lz16(u16 v)
{
    return v ? (u32)(__builtin_clz((u32)v) - 16) : 16u;
}

static inline __attribute__((always_inline)) u32 gte_divide(u16 h, u16 sz3)
{
    if ((u32)h >= (u32)sz3 * 2u) {
        S.gte_c[31] |= (1u << 17);
        return 0x1FFFFu;
    }
    u32 z = count_lz16(sz3);
    u32 n = (u32)h << z;
    u32 d = (u32)sz3 << z;
    u32 u = (u32)unr_table[((d & 0x7FFFu) + 0x40u) >> 7] + 0x101u;
    u32 d2 = (0x2000080u - d * u) >> 8;
    u32 d3 = (0x0000080u + d2 * u) >> 8;
    u32 res = (u32)(((u64)n * (u64)d3 + 0x8000u) >> 16);
    if (res > 0x1FFFFu) {
        S.gte_c[31] |= (1u << 17);
        res = 0x1FFFFu;
    }
    return res;
}

static inline __attribute__((always_inline)) s64 gte_mac_row(s32 tx, s32 m0, s32 m1, s32 m2, s32 vx, s32 vy, s32 vz)
{
#ifdef __mips__
    u32 hi = (u32)(tx >> 20);
    u32 lo = (u32)tx << 12;
    __asm__(
        ".set push\n\t.set mips32r2\n\t"
        "mthi %0\n\t"
        "mtlo %1\n\t"
        "madd %2, %5\n\t"
        "madd %3, %6\n\t"
        "madd %4, %7\n\t"
        "mfhi %0\n\t"
        "mflo %1\n\t"
        ".set pop"
        : "+r"(hi), "+r"(lo)
        : "r"(m0), "r"(m1), "r"(m2), "r"(vx), "r"(vy), "r"(vz)
        : "hi", "lo"
    );
    return ((s64)(s32)hi << 32) | (u64)lo;
#else
    return ((s64)tx << 12) + (s64)(m0 * vx) + (s64)(m1 * vy) + (s64)(m2 * vz);
#endif
}

static inline __attribute__((always_inline)) s32 gte_mac_set(int idx, s64 val, int sf)
{
    s32 hi = (s32)((u64)val >> 32);
    if (__builtin_expect((u32)(hi + 0x800) >= 0x1000u, 0)) {
        if (hi >= 0x800) S.gte_c[31] |= (1u << (31 - idx));
        else             S.gte_c[31] |= (1u << (28 - idx));
    }
    u32 lo = (u32)val;
    s32 res = sf ? (s32)(((u32)hi << 20) | (lo >> 12)) : (s32)lo;
    S.gte_d[24 + idx] = (u32)res;
    return res;
}

static inline __attribute__((always_inline)) void gte_mac0_set(s64 val)
{
    s32 hi = (s32)((u64)val >> 32);
    u32 lo = (u32)val;
    if (__builtin_expect(hi != ((s32)lo >> 31), 0)) {
        if (val >  0x7FFFFFFFLL) S.gte_c[31] |= (1u << 16);
        if (val < -0x80000000LL) S.gte_c[31] |= (1u << 15);
    }
    S.gte_d[24] = lo;
}

static inline __attribute__((always_inline)) s32 gte_ir_set(int idx, s32 val, int lm)
{
    s32 lo = lm ? 0 : -0x8000;
    if (val < lo) { S.gte_c[31] |= (1u << (25 - idx)); val = lo; }
    else if (val > 0x7FFF) { S.gte_c[31] |= (1u << (25 - idx)); val = 0x7FFF; }
    S.gte_d[8 + idx] = (u32)val;
    return val;
}

static inline __attribute__((always_inline)) void gte_ir0_set(s32 val)
{
    if (val < 0)      { S.gte_c[31] |= (1u << 12); val = 0; }
    if (val > 0x1000) { S.gte_c[31] |= (1u << 12); val = 0x1000; }
    S.gte_d[8] = (u32)val;
}

static inline __attribute__((always_inline)) u8 gte_col_clamp(int idx, s32 v)
{
    if (v < 0)    { S.gte_c[31] |= (1u << (22 - idx)); return 0u; }
    if (v > 0xFF) { S.gte_c[31] |= (1u << (22 - idx)); return 0xFFu; }
    return (u8)v;
}

static void gte_push_rgb_from_mac(void)
{
    u8 r = gte_col_clamp(1, (s32)S.gte_d[25] >> 4);
    u8 g = gte_col_clamp(2, (s32)S.gte_d[26] >> 4);
    u8 b = gte_col_clamp(3, (s32)S.gte_d[27] >> 4);
    u8 c = (u8)(S.gte_d[6] >> 24);
    S.gte_d[20] = S.gte_d[21];
    S.gte_d[21] = S.gte_d[22];
    S.gte_d[22] = (u32)r | ((u32)g << 8) | ((u32)b << 16) | ((u32)c << 24);
}

static void gte_push_sz(s32 z)
{
    if (z < 0)      { S.gte_c[31] |= (1u << 18); z = 0; }
    if (z > 0xFFFF) { S.gte_c[31] |= (1u << 18); z = 0xFFFF; }
    S.gte_d[16] = S.gte_d[17];
    S.gte_d[17] = S.gte_d[18];
    S.gte_d[18] = S.gte_d[19];
    S.gte_d[19] = (u32)(u16)z;
}

static void gte_push_sxy(s32 sx, s32 sy)
{
    if (sx < -1024) { S.gte_c[31] |= (1u << 14); sx = -1024; }
    if (sx >  1023) { S.gte_c[31] |= (1u << 14); sx =  1023; }
    if (sy < -1024) { S.gte_c[31] |= (1u << 13); sy = -1024; }
    if (sy >  1023) { S.gte_c[31] |= (1u << 13); sy =  1023; }
    S.gte_d[12] = S.gte_d[13];
    S.gte_d[13] = S.gte_d[14];
    S.gte_d[14] = ((u32)(u16)(s16)sx) | (((u32)(u16)(s16)sy) << 16);
    S.gte_d[15] = S.gte_d[14];
}

static void gte_finalize_flag(void)
{
    S.gte_c[31] &= 0x7FFFF000u;
    if (S.gte_c[31] & 0x7F87E000u)
        S.gte_c[31] |= 0x80000000u;
}

static u32 gte_read_data(u32 reg)
{
    reg &= 31u;
    switch (reg) {
    case 1u: case 3u: case 5u:
    case 8u: case 9u: case 10u: case 11u:
        return (u32)(s32)(s16)S.gte_d[reg];
    case 7u: case 16u: case 17u: case 18u: case 19u:
        return S.gte_d[reg] & 0xFFFFu;
    case 15u:
        return S.gte_d[14];
    case 28u:
    case 29u: {
        s32 r = (s32)(s16)S.gte_d[9] >> 7;  if (r < 0) r = 0; if (r > 31) r = 31;
        s32 g = (s32)(s16)S.gte_d[10] >> 7; if (g < 0) g = 0; if (g > 31) g = 31;
        s32 b = (s32)(s16)S.gte_d[11] >> 7; if (b < 0) b = 0; if (b > 31) b = 31;
        return (u32)r | ((u32)g << 5) | ((u32)b << 10);
    }
    default:
        return S.gte_d[reg];
    }
}

static void gte_write_data(u32 reg, u32 val)
{
    reg &= 31u;
    if (reg == 15u) {
        S.gte_d[12] = S.gte_d[13];
        S.gte_d[13] = S.gte_d[14];
        S.gte_d[14] = val;
        S.gte_d[15] = val;
        return;
    }
    if (reg == 28u) {
        S.gte_d[28] = val & 0x7FFFu;
        S.gte_d[9]  = (val & 31u) << 7;
        S.gte_d[10] = ((val >> 5) & 31u) << 7;
        S.gte_d[11] = ((val >> 10) & 31u) << 7;
        return;
    }
    if (reg == 29u || reg == 31u)
        return;
    if (reg == 30u) {
        S.gte_d[30] = val;
        u32 v = (val & 0x80000000u) ? ~val : val;
        S.gte_d[31] = v ? (u32)__builtin_clz(v) : 32u;
        return;
    }
    S.gte_d[reg] = val;
}

static u32 gte_read_ctrl(u32 reg)
{
    reg &= 31u;
    if (reg == 4u || reg == 12u || reg == 20u || reg == 26u || reg == 27u || reg == 29u || reg == 30u)
        return (u32)(s32)(s16)S.gte_c[reg];
    return S.gte_c[reg];
}

static void gte_write_ctrl(u32 reg, u32 val)
{
    reg &= 31u;
    if (reg == 31u) {
        val &= 0x7FFFF000u;
        if (val & 0x7F87E000u) val |= 0x80000000u;
    }
    S.gte_c[reg] = val;
    if (reg < 21u) {
        u32 mx = reg >> 3, sub = reg & 7u;
        if (sub <= 4u) {
            s16 (*m)[3] = S.gte_mat[mx];
            switch (sub) {
            case 0u: m[0][0] = (s16)val; m[0][1] = (s16)(val >> 16); break;
            case 1u: m[0][2] = (s16)val; m[1][0] = (s16)(val >> 16); break;
            case 2u: m[1][1] = (s16)val; m[1][2] = (s16)(val >> 16); break;
            case 3u: m[2][0] = (s16)val; m[2][1] = (s16)(val >> 16); break;
            case 4u: m[2][2] = (s16)val; break;
            }
        }
    }
}

static inline __attribute__((always_inline)) void gte_mul_mat_vec(int mx, s16 vx, s16 vy, s16 vz,
                                                                  s32 tx, s32 ty, s32 tz, int sf, int lm)
{
    const s16 (*m)[3] = S.gte_mat[mx & 3];
    s32 ivx = vx, ivy = vy, ivz = vz;
    s64 x = gte_mac_row(tx, m[0][0], m[0][1], m[0][2], ivx, ivy, ivz);
    s64 y = gte_mac_row(ty, m[1][0], m[1][1], m[1][2], ivx, ivy, ivz);
    s64 z = gte_mac_row(tz, m[2][0], m[2][1], m[2][2], ivx, ivy, ivz);
    gte_ir_set(1, gte_mac_set(1, x, sf), lm);
    gte_ir_set(2, gte_mac_set(2, y, sf), lm);
    gte_ir_set(3, gte_mac_set(3, z, sf), lm);
}

static inline __attribute__((always_inline)) void gte_rtps_one(int v_idx, int sf, int lm, int last)
{
    s32 vx = (s16)S.gte_d[v_idx * 2];
    s32 vy = (s16)(S.gte_d[v_idx * 2] >> 16);
    s32 vz = (s16)S.gte_d[v_idx * 2 + 1];
    const s16 (*m)[3] = S.gte_mat[0];

    s64 mx = gte_mac_row((s32)S.gte_c[5], m[0][0], m[0][1], m[0][2], vx, vy, vz);
    s64 my = gte_mac_row((s32)S.gte_c[6], m[1][0], m[1][1], m[1][2], vx, vy, vz);
    s64 mz = gte_mac_row((s32)S.gte_c[7], m[2][0], m[2][1], m[2][2], vx, vy, vz);

    s32 ir1 = gte_ir_set(1, gte_mac_set(1, mx, sf), lm);
    s32 ir2 = gte_ir_set(2, gte_mac_set(2, my, sf), lm);
    (void)gte_mac_set(3, mz, sf);

    s32 z_chk = (s32)((((u32)((u64)mz >> 32)) << 20) | ((u32)mz >> 12));
    if ((u32)(z_chk + 0x8000) > 0xFFFFu)
        S.gte_c[31] |= (1u << 22);
    s32 ir3 = (s32)S.gte_d[27];
    s32 lo = lm ? 0 : -0x8000;
    if (ir3 < lo) ir3 = lo;
    if (ir3 > 0x7FFF) ir3 = 0x7FFF;
    S.gte_d[11] = (u32)ir3;

    gte_push_sz(z_chk);
    u32 q = gte_divide((u16)S.gte_c[26], (u16)S.gte_d[19]);

    s64 sx_fp = (s64)(s32)S.gte_c[24] + (s64)ir1 * (s64)q;
    s64 sy_fp = (s64)(s32)S.gte_c[25] + (s64)ir2 * (s64)q;
    gte_mac0_set(sx_fp);
    gte_mac0_set(sy_fp);
    gte_push_sxy((s32)(sx_fp >> 16), (s32)(sy_fp >> 16));

    if (last) {
        s64 dq = (s64)(s32)S.gte_c[28] + (s64)(s16)S.gte_c[27] * (s64)q;
        gte_mac0_set(dq);
        gte_ir0_set((s32)(dq >> 12));
    }
}

static void gte_ncd_one(int v_idx, int sf, int lm, int with_col, int with_dp)
{
    s16 vx = (s16)S.gte_d[v_idx * 2];
    s16 vy = (s16)(S.gte_d[v_idx * 2] >> 16);
    s16 vz = (s16)S.gte_d[v_idx * 2 + 1];
    /* 1. LLM * V */
    gte_mul_mat_vec(1, vx, vy, vz, 0, 0, 0, sf, lm);
    /* 2. BK + LCM * IR */
    gte_mul_mat_vec(2, (s16)S.gte_d[9], (s16)S.gte_d[10], (s16)S.gte_d[11],
                    (s32)S.gte_c[13], (s32)S.gte_c[14], (s32)S.gte_c[15], sf, lm);
    if (with_col) {
        s32 r = (s32)(S.gte_d[6] & 0xFFu) << 4;
        s32 g = (s32)((S.gte_d[6] >> 8) & 0xFFu) << 4;
        s32 b = (s32)((S.gte_d[6] >> 16) & 0xFFu) << 4;
        if (!with_dp) {
            /* r,g,b in [0..4080], IR1..3 in [-32768..32767] -> product in [-1.34e8..1.34e8], fits in s32 without 44-bit overflow */
            s32 mr32 = r * (s16)S.gte_d[9];
            s32 mg32 = g * (s16)S.gte_d[10];
            s32 mb32 = b * (s16)S.gte_d[11];
            S.gte_d[25] = (u32)(sf ? (mr32 >> 12) : mr32);
            S.gte_d[26] = (u32)(sf ? (mg32 >> 12) : mg32);
            S.gte_d[27] = (u32)(sf ? (mb32 >> 12) : mb32);
            gte_ir_set(1, (s32)S.gte_d[25], lm);
            gte_ir_set(2, (s32)S.gte_d[26], lm);
            gte_ir_set(3, (s32)S.gte_d[27], lm);
        } else {
            s64 mr = (s64)r * (s16)S.gte_d[9];
            s64 mg = (s64)g * (s16)S.gte_d[10];
            s64 mb = (s64)b * (s16)S.gte_d[11];
            s16 ir0 = (s16)S.gte_d[8];
            s32 dr = gte_ir_set(1, (s32)((((s64)(s32)S.gte_c[21] << 12) - mr) >> (sf ? 12 : 0)), 0);
            s32 dg = gte_ir_set(2, (s32)((((s64)(s32)S.gte_c[22] << 12) - mg) >> (sf ? 12 : 0)), 0);
            s32 db = gte_ir_set(3, (s32)((((s64)(s32)S.gte_c[23] << 12) - mb) >> (sf ? 12 : 0)), 0);
            mr += (s64)dr * ir0;
            mg += (s64)dg * ir0;
            mb += (s64)db * ir0;
            gte_ir_set(1, gte_mac_set(1, mr, sf), lm);
            gte_ir_set(2, gte_mac_set(2, mg, sf), lm);
            gte_ir_set(3, gte_mac_set(3, mb, sf), lm);
        }
    }
    gte_push_rgb_from_mac();
}

#ifdef __mips__
static void gte_op_rtps(u32 cmd)
{
    S.gte_c[31] = 0;
    gte_rtps_one(0, (cmd >> 19) & 1, (cmd >> 10) & 1, 1);
    gte_finalize_flag();
}

static void gte_op_rtpt(u32 cmd)
{
    int sf = (cmd >> 19) & 1, lm = (cmd >> 10) & 1;
    S.gte_c[31] = 0;
    gte_rtps_one(0, sf, lm, 0);
    gte_rtps_one(1, sf, lm, 0);
    gte_rtps_one(2, sf, lm, 1);
    gte_finalize_flag();
}

static void gte_op_avsz3(void)
{
    S.gte_c[31] = 0;
    s64 sum = (s64)(s16)S.gte_c[29] * (s32)((u16)S.gte_d[17] + (u16)S.gte_d[18] + (u16)S.gte_d[19]);
    gte_mac0_set(sum);
    s32 otz = (s32)(sum >> 12);
    if ((u32)otz > 0xFFFFu) { S.gte_c[31] |= (1u << 18); otz = (otz < 0) ? 0 : 0xFFFF; }
    S.gte_d[7] = (u32)(u16)otz;
    gte_finalize_flag();
}

static void gte_op_avsz4(void)
{
    S.gte_c[31] = 0;
    s64 sum = (s64)(s16)S.gte_c[30] * (s32)((u16)S.gte_d[16] + (u16)S.gte_d[17] + (u16)S.gte_d[18] + (u16)S.gte_d[19]);
    gte_mac0_set(sum);
    s32 otz = (s32)(sum >> 12);
    if ((u32)otz > 0xFFFFu) { S.gte_c[31] |= (1u << 18); otz = (otz < 0) ? 0 : 0xFFFF; }
    S.gte_d[7] = (u32)(u16)otz;
    gte_finalize_flag();
}

static void gte_op_gpf(u32 cmd)
{
    int sf = (cmd >> 19) & 1, lm = (cmd >> 10) & 1;
    S.gte_c[31] = 0;
    s32 ir0 = (s16)S.gte_d[8];
    s32 m1 = (s32)(s16)S.gte_d[9]  * ir0;
    s32 m2 = (s32)(s16)S.gte_d[10] * ir0;
    s32 m3 = (s32)(s16)S.gte_d[11] * ir0;
    S.gte_d[25] = (u32)(sf ? (m1 >> 12) : m1);
    S.gte_d[26] = (u32)(sf ? (m2 >> 12) : m2);
    S.gte_d[27] = (u32)(sf ? (m3 >> 12) : m3);
    gte_ir_set(1, (s32)S.gte_d[25], lm);
    gte_ir_set(2, (s32)S.gte_d[26], lm);
    gte_ir_set(3, (s32)S.gte_d[27], lm);
    gte_push_rgb_from_mac();
    gte_finalize_flag();
}

static void gte_op_mvmva(u32 cmd)
{
    int sf = (cmd >> 19) & 1, lm = (cmd >> 10) & 1;
    int mx = (cmd >> 17) & 3, vx_sel = (cmd >> 15) & 3, cv = (cmd >> 13) & 3;
    S.gte_c[31] = 0;
    s16 vx, vy, vz;
    if (vx_sel < 3) {
        vx = (s16)S.gte_d[vx_sel * 2];
        vy = (s16)(S.gte_d[vx_sel * 2] >> 16);
        vz = (s16)S.gte_d[vx_sel * 2 + 1];
    } else {
        vx = (s16)S.gte_d[9]; vy = (s16)S.gte_d[10]; vz = (s16)S.gte_d[11];
    }
    s32 tx = 0, ty = 0, tz = 0;
    if (cv == 0)      { tx = (s32)S.gte_c[5];  ty = (s32)S.gte_c[6];  tz = (s32)S.gte_c[7]; }
    else if (cv == 1) { tx = (s32)S.gte_c[13]; ty = (s32)S.gte_c[14]; tz = (s32)S.gte_c[15]; }
    else if (cv == 2) { tx = (s32)S.gte_c[21]; ty = (s32)S.gte_c[22]; tz = (s32)S.gte_c[23]; }
    gte_mul_mat_vec(mx, vx, vy, vz, tx, ty, tz, sf, lm);
    gte_finalize_flag();
}
#endif

static void gte_exec(u32 cmd)
{
    int sf = (cmd >> 19) & 1;
    int lm = (cmd >> 10) & 1;
    S.gte_c[31] = 0;

    switch (cmd & 0x3Fu) {
    case 0x01u: /* RTPS */
        gte_rtps_one(0, sf, lm, 1);
        break;
    case 0x30u: /* RTPT */
        gte_rtps_one(0, sf, lm, 0);
        gte_rtps_one(1, sf, lm, 0);
        gte_rtps_one(2, sf, lm, 1);
        break;
    case 0x06u: { /* NCLIP */
        s32 x0 = (s16)S.gte_d[12], y0 = (s16)(S.gte_d[12] >> 16);
        s32 x1 = (s16)S.gte_d[13], y1 = (s16)(S.gte_d[13] >> 16);
        s32 x2 = (s16)S.gte_d[14], y2 = (s16)(S.gte_d[14] >> 16);
        gte_mac0_set((s64)(x1 - x0) * (s64)(y2 - y0) - (s64)(x2 - x0) * (s64)(y1 - y0));
        break;
    }
    case 0x0Cu: { /* OP */
        s16 d1 = (s16)S.gte_c[0], d2 = (s16)S.gte_c[2], d3 = (s16)S.gte_c[4];
        s16 ir1 = (s16)S.gte_d[9], ir2 = (s16)S.gte_d[10], ir3 = (s16)S.gte_d[11];
        gte_ir_set(1, gte_mac_set(1, (s64)ir3 * d2 - (s64)ir2 * d3, sf), lm);
        gte_ir_set(2, gte_mac_set(2, (s64)ir1 * d3 - (s64)ir3 * d1, sf), lm);
        gte_ir_set(3, gte_mac_set(3, (s64)ir2 * d1 - (s64)ir1 * d2, sf), lm);
        break;
    }
    case 0x10u: /* DPCS */
    case 0x2Au: { /* DPCT */
        int reps = ((cmd & 0x3Fu) == 0x2Au) ? 3 : 1;
        for (int i = 0; i < reps; i++) {
            u32 rgb = ((cmd & 0x3Fu) == 0x2Au) ? S.gte_d[20] : S.gte_d[6];
            s64 r = (s64)(rgb & 0xFFu) << 16;
            s64 g = (s64)((rgb >> 8) & 0xFFu) << 16;
            s64 b = (s64)((rgb >> 16) & 0xFFu) << 16;
            s16 ir0 = (s16)S.gte_d[8];
            s32 dr = gte_ir_set(1, gte_mac_set(1, ((s64)(s32)S.gte_c[21] << 12) - r, sf), 0);
            s32 dg = gte_ir_set(2, gte_mac_set(2, ((s64)(s32)S.gte_c[22] << 12) - g, sf), 0);
            s32 db = gte_ir_set(3, gte_mac_set(3, ((s64)(s32)S.gte_c[23] << 12) - b, sf), 0);
            gte_ir_set(1, gte_mac_set(1, r + (s64)dr * ir0, sf), lm);
            gte_ir_set(2, gte_mac_set(2, g + (s64)dg * ir0, sf), lm);
            gte_ir_set(3, gte_mac_set(3, b + (s64)db * ir0, sf), lm);
            gte_push_rgb_from_mac();
        }
        break;
    }
    case 0x11u: { /* INTPL */
        s64 r = (s64)(s16)S.gte_d[9] << 12;
        s64 g = (s64)(s16)S.gte_d[10] << 12;
        s64 b = (s64)(s16)S.gte_d[11] << 12;
        s16 ir0 = (s16)S.gte_d[8];
        s32 dr = gte_ir_set(1, gte_mac_set(1, ((s64)(s32)S.gte_c[21] << 12) - r, sf), 0);
        s32 dg = gte_ir_set(2, gte_mac_set(2, ((s64)(s32)S.gte_c[22] << 12) - g, sf), 0);
        s32 db = gte_ir_set(3, gte_mac_set(3, ((s64)(s32)S.gte_c[23] << 12) - b, sf), 0);
        gte_ir_set(1, gte_mac_set(1, r + (s64)dr * ir0, sf), lm);
        gte_ir_set(2, gte_mac_set(2, g + (s64)dg * ir0, sf), lm);
        gte_ir_set(3, gte_mac_set(3, b + (s64)db * ir0, sf), lm);
        gte_push_rgb_from_mac();
        break;
    }
    case 0x12u: { /* MVMVA */
        int mx = (cmd >> 17) & 3;
        int vx_sel = (cmd >> 15) & 3;
        int cv = (cmd >> 13) & 3;
        s16 vx, vy, vz;
        if (vx_sel < 3) {
            vx = (s16)S.gte_d[vx_sel * 2];
            vy = (s16)(S.gte_d[vx_sel * 2] >> 16);
            vz = (s16)S.gte_d[vx_sel * 2 + 1];
        } else {
            vx = (s16)S.gte_d[9]; vy = (s16)S.gte_d[10]; vz = (s16)S.gte_d[11];
        }
        s64 tx = 0, ty = 0, tz = 0;
        if (cv == 0)      { tx = (s32)S.gte_c[5];  ty = (s32)S.gte_c[6];  tz = (s32)S.gte_c[7]; }
        else if (cv == 1) { tx = (s32)S.gte_c[13]; ty = (s32)S.gte_c[14]; tz = (s32)S.gte_c[15]; }
        else if (cv == 2) { tx = (s32)S.gte_c[21]; ty = (s32)S.gte_c[22]; tz = (s32)S.gte_c[23]; }
        gte_mul_mat_vec(mx, vx, vy, vz, tx, ty, tz, sf, lm);
        break;
    }
    case 0x13u: gte_ncd_one(0, sf, lm, 1, 1); break; /* NCDS */
    case 0x16u: gte_ncd_one(0, sf, lm, 1, 1); gte_ncd_one(1, sf, lm, 1, 1); gte_ncd_one(2, sf, lm, 1, 1); break; /* NCDT */
    case 0x1Bu: gte_ncd_one(0, sf, lm, 1, 0); break; /* NCCS */
    case 0x3Fu: gte_ncd_one(0, sf, lm, 1, 0); gte_ncd_one(1, sf, lm, 1, 0); gte_ncd_one(2, sf, lm, 1, 0); break; /* NCCT */
    case 0x1Eu: gte_ncd_one(0, sf, lm, 0, 0); break; /* NCS */
    case 0x20u: gte_ncd_one(0, sf, lm, 0, 0); gte_ncd_one(1, sf, lm, 0, 0); gte_ncd_one(2, sf, lm, 0, 0); break; /* NCT */
    case 0x14u: /* CDP */
    case 0x1Cu: { /* CC */
        gte_mul_mat_vec(2, (s16)S.gte_d[9], (s16)S.gte_d[10], (s16)S.gte_d[11],
                        (s32)S.gte_c[13], (s32)S.gte_c[14], (s32)S.gte_c[15], sf, lm);
        s64 mr = (s64)((S.gte_d[6] & 0xFFu) << 4) * (s16)S.gte_d[9];
        s64 mg = (s64)(((S.gte_d[6] >> 8) & 0xFFu) << 4) * (s16)S.gte_d[10];
        s64 mb = (s64)(((S.gte_d[6] >> 16) & 0xFFu) << 4) * (s16)S.gte_d[11];
        if ((cmd & 0x3Fu) == 0x14u) {
            s16 ir0 = (s16)S.gte_d[8];
            s32 dr = gte_ir_set(1, (s32)((((s64)(s32)S.gte_c[21] << 12) - mr) >> (sf ? 12 : 0)), 0);
            s32 dg = gte_ir_set(2, (s32)((((s64)(s32)S.gte_c[22] << 12) - mg) >> (sf ? 12 : 0)), 0);
            s32 db = gte_ir_set(3, (s32)((((s64)(s32)S.gte_c[23] << 12) - mb) >> (sf ? 12 : 0)), 0);
            mr += (s64)dr * ir0; mg += (s64)dg * ir0; mb += (s64)db * ir0;
        }
        gte_ir_set(1, gte_mac_set(1, mr, sf), lm);
        gte_ir_set(2, gte_mac_set(2, mg, sf), lm);
        gte_ir_set(3, gte_mac_set(3, mb, sf), lm);
        gte_push_rgb_from_mac();
        break;
    }
    case 0x28u: { /* SQR */
        s32 x = (s16)S.gte_d[9], y = (s16)S.gte_d[10], z = (s16)S.gte_d[11];
        S.gte_d[25] = (u32)((x * x) >> (sf ? 12 : 0));
        S.gte_d[26] = (u32)((y * y) >> (sf ? 12 : 0));
        S.gte_d[27] = (u32)((z * z) >> (sf ? 12 : 0));
        gte_ir_set(1, (s32)S.gte_d[25], lm);
        gte_ir_set(2, (s32)S.gte_d[26], lm);
        gte_ir_set(3, (s32)S.gte_d[27], lm);
        break;
    }
    case 0x29u: { /* DCPL */
        s64 mr = (s64)((S.gte_d[6] & 0xFFu) << 4) * (s16)S.gte_d[9];
        s64 mg = (s64)(((S.gte_d[6] >> 8) & 0xFFu) << 4) * (s16)S.gte_d[10];
        s64 mb = (s64)(((S.gte_d[6] >> 16) & 0xFFu) << 4) * (s16)S.gte_d[11];
        s16 ir0 = (s16)S.gte_d[8];
        s32 dr = gte_ir_set(1, (s32)((((s64)(s32)S.gte_c[21] << 12) - mr) >> (sf ? 12 : 0)), 0);
        s32 dg = gte_ir_set(2, (s32)((((s64)(s32)S.gte_c[22] << 12) - mg) >> (sf ? 12 : 0)), 0);
        s32 db = gte_ir_set(3, (s32)((((s64)(s32)S.gte_c[23] << 12) - mb) >> (sf ? 12 : 0)), 0);
        gte_ir_set(1, gte_mac_set(1, mr + (s64)dr * ir0, sf), lm);
        gte_ir_set(2, gte_mac_set(2, mg + (s64)dg * ir0, sf), lm);
        gte_ir_set(3, gte_mac_set(3, mb + (s64)db * ir0, sf), lm);
        gte_push_rgb_from_mac();
        break;
    }
    case 0x2Du: { /* AVSZ3 */
        s64 sum = (s64)(s16)S.gte_c[29] * ((s64)(u16)S.gte_d[17] + (u16)S.gte_d[18] + (u16)S.gte_d[19]);
        gte_mac0_set(sum);
        s32 otz = (s32)(sum >> 12);
        if (otz < 0)      { S.gte_c[31] |= (1u << 18); otz = 0; }
        if (otz > 0xFFFF) { S.gte_c[31] |= (1u << 18); otz = 0xFFFF; }
        S.gte_d[7] = (u32)(u16)otz;
        break;
    }
    case 0x2Eu: { /* AVSZ4 */
        s64 sum = (s64)(s16)S.gte_c[30] * ((s64)(u16)S.gte_d[16] + (u16)S.gte_d[17] + (u16)S.gte_d[18] + (u16)S.gte_d[19]);
        gte_mac0_set(sum);
        s32 otz = (s32)(sum >> 12);
        if (otz < 0)      { S.gte_c[31] |= (1u << 18); otz = 0; }
        if (otz > 0xFFFF) { S.gte_c[31] |= (1u << 18); otz = 0xFFFF; }
        S.gte_d[7] = (u32)(u16)otz;
        break;
    }
    case 0x3Du: /* GPF */
    case 0x3Eu: { /* GPL */
        int add = ((cmd & 0x3Fu) == 0x3Eu);
        s16 ir0 = (s16)S.gte_d[8];
        s64 b1 = add ? ((s64)(s32)S.gte_d[25] << (sf ? 12 : 0)) : 0;
        s64 b2 = add ? ((s64)(s32)S.gte_d[26] << (sf ? 12 : 0)) : 0;
        s64 b3 = add ? ((s64)(s32)S.gte_d[27] << (sf ? 12 : 0)) : 0;
        gte_ir_set(1, gte_mac_set(1, b1 + (s64)(s16)S.gte_d[9]  * ir0, sf), lm);
        gte_ir_set(2, gte_mac_set(2, b2 + (s64)(s16)S.gte_d[10] * ir0, sf), lm);
        gte_ir_set(3, gte_mac_set(3, b3 + (s64)(s16)S.gte_d[11] * ir0, sf), lm);
        gte_push_rgb_from_mac();
        break;
    }
    default:
        break;
    }
    gte_finalize_flag();
}

/* ---- R3000A Memory Bus ---- */
static inline __attribute__((always_inline)) u32 mask_phys(u32 addr)
{
    /* Map KUSEG low 512M (s=0), KSEG0 (s=4), KSEG1 (s=5) -> 29-bit physical; all others -> 0xFFFFFFFF */
    return ((0x31u >> (addr >> 29)) & 1u) ? (addr & 0x1FFFFFFFu) : 0xFFFFFFFFu;
}

static inline __attribute__((always_inline)) u8 bus_read8(u32 vaddr)
{
    u32 p = mask_phys(vaddr);
    if (__builtin_expect(p < 0x800000u, 1))
        return W.ram[p & 0x1FFFFFu];
    if (p >= 0x1F800000u && p < 0x1F800400u)
        return S.scratch[p & 0x3FFu];
    if (p >= 0x1F801000u && p < 0x1F802000u)
        return io_read8(p & 0xFFFu);
    if (p >= 0x1FC00000u && p < 0x1FC80000u)
        return (S.has_ext_bios ? W.ext_bios : W.bios)[p & 0x7FFFFu];
    return 0xFFu;
}

static inline __attribute__((always_inline)) u16 bus_read16(u32 vaddr)
{
    u32 p = mask_phys(vaddr);
    if (__builtin_expect(p < 0x800000u, 1))
        return *(const u16 *)(W.ram + (p & 0x1FFFFEu));
    if (p >= 0x1F800000u && p < 0x1F800400u)
        return *(const u16 *)(S.scratch + (p & 0x3FEu));
    if (p >= 0x1F801000u && p < 0x1F802000u)
        return io_read16(p & 0xFFFu);
    if (p >= 0x1FC00000u && p < 0x1FC80000u)
        return *(const u16 *)((S.has_ext_bios ? W.ext_bios : W.bios) + (p & 0x7FFFEu));
    return 0xFFFFu;
}

static inline __attribute__((always_inline)) u32 bus_read32(u32 vaddr)
{
    if (__builtin_expect(vaddr == 0xFFFE0130u, 0))
        return W.io[0xFE0];
    u32 p = mask_phys(vaddr);
    if (__builtin_expect(p < 0x800000u, 1))
        return *(const u32 *)(W.ram + (p & 0x1FFFFCu));
    if (p >= 0x1F800000u && p < 0x1F800400u)
        return *(const u32 *)(S.scratch + (p & 0x3FCu));
    if (p >= 0x1F801000u && p < 0x1F802000u)
        return io_read32(p & 0xFFFu);
    if (p >= 0x1FC00000u && p < 0x1FC80000u)
        return *(const u32 *)((S.has_ext_bios ? W.ext_bios : W.bios) + (p & 0x7FFFCu));
    return 0xFFFFFFFFu;
}

static inline __attribute__((always_inline)) void bus_write8(u32 vaddr, u8 val)
{
    if (__builtin_expect((S.cop0[12] & 0x10000u) != 0u && vaddr < 0xA0000000u, 0))
        return; /* IsC: Isolate Cache */
    u32 p = mask_phys(vaddr);
    if (__builtin_expect(p < 0x800000u, 1)) {
        u32 off = p & 0x1FFFFFu;
        if (W.ram[off] != val) {
            W.ram[off] = val;
            jit_touch_ram(off);
        }
        return;
    }
    if (p >= 0x1F800000u && p < 0x1F800400u) {
        S.scratch[p & 0x3FFu] = val;
        return;
    }
    if (p >= 0x1F801000u && p < 0x1F803000u)
        io_write8(p - 0x1F801000u, val);
}

static inline __attribute__((always_inline)) void bus_write16(u32 vaddr, u16 val)
{
    if (__builtin_expect((S.cop0[12] & 0x10000u) != 0u && vaddr < 0xA0000000u, 0))
        return;
    u32 p = mask_phys(vaddr);
    if (__builtin_expect(p < 0x800000u, 1)) {
        u32 off = p & 0x1FFFFEu;
        u16 *p16 = (u16 *)(W.ram + off);
        if (*p16 != val) {
            *p16 = val;
            jit_touch_ram(off);
        }
        return;
    }
    if (p >= 0x1F800000u && p < 0x1F800400u) {
        *(u16 *)(S.scratch + (p & 0x3FEu)) = val;
        return;
    }
    if (p >= 0x1F801000u && p < 0x1F802000u)
        io_write16(p & 0xFFFu, val);
}

static inline __attribute__((always_inline)) void bus_write32(u32 vaddr, u32 val)
{
    if (__builtin_expect(vaddr == 0xFFFE0130u, 0)) { W.io[0xFE0] = (u8)val; return; }
    if (__builtin_expect((S.cop0[12] & 0x10000u) != 0u && vaddr < 0xA0000000u, 0))
        return;
    u32 p = mask_phys(vaddr);
    if (__builtin_expect(p < 0x800000u, 1)) {
        u32 off = p & 0x1FFFFCu;
        u32 *p32 = (u32 *)(W.ram + off);
        if (*p32 != val) {
            *p32 = val;
            jit_touch_ram(off);
        }
        return;
    }
    if (p >= 0x1F800000u && p < 0x1F800400u) {
        *(u32 *)(S.scratch + (p & 0x3FCu)) = val;
        return;
    }
    if (p >= 0x1F801000u && p < 0x1F802000u)
        io_write32(p & 0xFFFu, val);
}

/* ---- Clean-Room Built-In MIPS BIOS & HLE Kernel (A0 / B0 / C0) ---- */
static inline void put_insn(u8 *dst, u32 off, u32 insn)
{
    dst[off + 0] = (u8)(insn);
    dst[off + 1] = (u8)(insn >> 8);
    dst[off + 2] = (u8)(insn >> 16);
    dst[off + 3] = (u8)(insn >> 24);
}

static void install_ram_vectors(void)
{
    /* $00000080: LUI $k0, 0xBFC0; ORI $k0, $k0, 0x0180; JR $k0; NOP */
    put_insn(W.ram, 0x0080u, 0x3C1ABFC0u);
    put_insn(W.ram, 0x0084u, 0x375A0180u);
    put_insn(W.ram, 0x0088u, 0x03400008u);
    put_insn(W.ram, 0x008Cu, 0x00000000u);
    /* $000000A0, $000000B0, $000000C0 -> JR $ra; NOP fallback */
    put_insn(W.ram, 0x00A0u, 0x03E00008u); put_insn(W.ram, 0x00A4u, 0x00000000u);
    put_insn(W.ram, 0x00B0u, 0x03E00008u); put_insn(W.ram, 0x00B4u, 0x00000000u);
    put_insn(W.ram, 0x00C0u, 0x03E00008u); put_insn(W.ram, 0x00C4u, 0x00000000u);
    /* Safe kernel scratch stub at $80000400 for PsyQ libmcrd InitCARD2 C0[6] patching */
    for (u32 off = 0x0400u; off < 0x0480u; off += 8u) {
        put_insn(W.ram, off + 0u, 0x03E00008u);
        put_insn(W.ram, off + 4u, 0x00000000u);
    }
    /* Populate GetC0Table ($80000500) & GetB0Table ($80000600) function pointer tables */
    for (u32 i = 0; i < 128u; i++) {
        put_insn(W.ram, 0x0500u + i * 4u, 0xBFC01000u + i * 16u);
        put_insn(W.ram, 0x0600u + i * 4u, 0xBFC01800u + i * 16u);
    }
    put_insn(W.ram, 0x0500u + 6u * 4u, 0xBFC00400u);
}

static void build_clean_bios(void)
{
    /* Fill unmapped BIOS ROM words with `jr $ra ; nop` so direct B0/C0 table-offset jumps return cleanly */
    for (u32 i = 0; i < PSX_BIOS_SIZE; i += 8u) {
        put_insn(W.bios, i + 0u, 0x03E00008u);
        put_insn(W.bios, i + 4u, 0x00000000u);
    }

    /* $BFC00000: J $BFC00100; NOP */
    put_insn(W.bios, 0x0000u, 0x0BF00040u);
    put_insn(W.bios, 0x0004u, 0x00000000u);
    /* $BFC00100: Idle loop if booted with no executable */
    put_insn(W.bios, 0x0100u, 0x1000FFFFu);
    put_insn(W.bios, 0x0104u, 0x00000000u);

    /* $BFC00180: Reentrant HLE exception / SYSCALL / IRQ entry trap */
    put_insn(W.bios, 0x0180u, 0x00000000u);
    put_insn(W.bios, 0x0184u, 0x00000000u);

    /* $BFC00200: HLE IRQ callback dispatch loop ($v0 = next callback or 0) */
    put_insn(W.bios, 0x0200u, 0x00000000u);
    u32 p = 0x0204u;
    put_insn(W.bios, p, 0x10400007u); p += 4;       /* 0x0204: beqz $v0, 0xBFC00224 (+7 from 0x0208) */
    put_insn(W.bios, p, 0x00000000u); p += 4;       /* 0x0208: nop */
    put_insn(W.bios, p, 0x3C1D8000u); p += 4;       /* 0x020C: lui $sp, 0x8000 */
    put_insn(W.bios, p, 0x37BD0FE0u); p += 4;       /* 0x0210: ori $sp, $sp, 0x0FE0 (IRQ stack, >2 KB clear below) */
    put_insn(W.bios, p, 0x0040F809u); p += 4;       /* 0x0214: jalr $v0 */
    put_insn(W.bios, p, 0x00000000u); p += 4;       /* 0x0218: nop */
    put_insn(W.bios, p, 0x0BF00080u); p += 4;       /* 0x021C: j 0xBFC00200 */
    put_insn(W.bios, p, 0x00000000u); p += 4;       /* 0x0220: nop */
    put_insn(W.bios, 0x0224u, 0x00000000u);         /* 0x0224: HLE ReturnFromException trap */

    /* 0xBFC00300: HLE A0(43h) Exec child-return trap */
    put_insn(W.bios, 0x0300u, 0x00000000u);

    /* 0xBFC00400: C0(06h) ExceptionHandler stub with `lui/addiu $k0, 0x80000400` at +0x70/+0x74 for InitCARD2 */
    put_insn(W.bios, 0x0400u, 0x240A00C0u);
    put_insn(W.bios, 0x0404u, 0x01400008u);
    put_insn(W.bios, 0x0408u, 0x24090006u);
    put_insn(W.bios, 0x040Cu, 0x00000000u);
    put_insn(W.bios, 0x0470u, 0x3C1A8000u);
    put_insn(W.bios, 0x0474u, 0x275A0400u);

    /* 0xBFC01000..0xBFC017FF: Callable C0(00h..7Fh) ROM stubs; 0xBFC01800..0xBFC01FFF: B0(00h..7Fh) */
    for (u32 i = 0; i < 128u; i++) {
        u32 c0 = 0x1000u + i * 16u;
        put_insn(W.bios, c0 + 0u,  0x240A00C0u);        /* addiu $t2, $0, 0x00C0 */
        put_insn(W.bios, c0 + 4u,  0x01400008u);        /* jr    $t2 */
        put_insn(W.bios, c0 + 8u,  0x24090000u | i);    /* addiu $t1, $0, i */
        put_insn(W.bios, c0 + 12u, 0x00000000u);
        u32 b0 = 0x1800u + i * 16u;
        put_insn(W.bios, b0 + 0u,  0x240A00B0u);        /* addiu $t2, $0, 0x00B0 */
        put_insn(W.bios, b0 + 4u,  0x01400008u);        /* jr    $t2 */
        put_insn(W.bios, b0 + 8u,  0x24090000u | i);    /* addiu $t1, $0, i */
        put_insn(W.bios, b0 + 12u, 0x00000000u);
    }
}

static u32 event_class_for_irq(int bit)
{
    switch (bit) {
    case 0: return 0xF0000001u; /* VBlank */
    case 1: return 0xF0000002u; /* GPU */
    case 2: return 0xF0000003u; /* CDROM */
    case 3: return 0xF0000004u; /* DMA */
    case 4: return 0xF2000000u; /* RCnt0 */
    case 5: return 0xF2000001u; /* RCnt1 */
    case 6: return 0xF2000002u; /* RCnt2 */
    case 7: return 0xF0000008u; /* Controller */
    case 9: return 0xF0000009u; /* SPU */
    default: return 0u;
    }
}

static void hle_update_pad_buffers(void)
{
    u16 btns = build_pad_buttons();
    if (S.pad_init_ptr)
        bus_write32(S.pad_init_ptr, (u32)(u16)(~btns));
    if (!S.pad_auto)
        return;
    if (S.pad_buf1) {
        bus_write8(S.pad_buf1 + 0u, 0x00u); /* status OK */
        bus_write8(S.pad_buf1 + 1u, 0x41u); /* digital pad */
        bus_write8(S.pad_buf1 + 2u, (u8)(btns & 0xFFu));
        bus_write8(S.pad_buf1 + 3u, (u8)(btns >> 8));
    }
    if (S.pad_buf2) {
        bus_write8(S.pad_buf2 + 0u, 0xFFu); /* disconnected */
        bus_write8(S.pad_buf2 + 1u, 0xFFu);
    }
}

static u16 hle_exc_active;
static u32 hle_rp_fn1[16], hle_rp_fn2[16];
static u8 hle_rp_n, hle_rp_idx, hle_rp_stage;

static void hle_return_from_exception(void)
{
    for (u32 r = 1; r <= 31; r++) {
        if (r == 26) continue;
        S.r[r] = S.exc_r[r];
    }
    S.hi = S.exc_hi;
    S.lo = S.exc_lo;
    u32 epc = S.exc_epc;
    S.cop0[12] = (S.cop0[12] & ~0x0Fu) | ((S.cop0[12] >> 2) & 0x0Fu);
    if (S.hook_entry_int != 0u && S.auto_clear_rcnt[3] && (hle_exc_active & 1u))
        S.i_stat &= ~1u;
    update_cop0_irq();
    hle_ev_cb_cursor = 0u;
    S.pc = epc;
    S.next_pc = epc + 4u;
}

static void hle_bios_exception_step(void)
{
    /* Phase 1 (cursor == 100): walk SysEnqIntRP chain; if fn1() returns $v0 != 0, invoke fn2()! */
    if (hle_ev_cb_cursor == 100u) {
        if (hle_rp_stage == 1u) {
            hle_rp_stage = 0u;
            u32 fn2 = hle_rp_fn2[hle_rp_idx++];
            if (S.r[2] != 0u && fn2 != 0u) {
                S.r[28] = S.exc_r[28];
                S.r[2] = fn2;
                S.pc = 0xBFC00204u;
                S.next_pc = 0xBFC00208u;
                return;
            }
        }
        while (hle_rp_idx < hle_rp_n) {
            u32 fn1 = hle_rp_fn1[hle_rp_idx];
            if (fn1 != 0u) {
                hle_rp_stage = 1u;
                S.r[28] = S.exc_r[28];
                S.r[2] = fn1;
                S.pc = 0xBFC00204u;
                S.next_pc = 0xBFC00208u;
                return;
            }
            u32 fn2 = hle_rp_fn2[hle_rp_idx++];
            if (fn2 != 0u) {
                S.r[28] = S.exc_r[28];
                S.r[2] = fn2;
                S.pc = 0xBFC00204u;
                S.next_pc = 0xBFC00208u;
                return;
            }
        }

        /* Deliver kernel events for remaining active IRQ bits & apply kernel auto-acknowledge */
        u16 active = (S.i_stat & S.i_mask) | hle_exc_active;
        for (int b = 0; b < 11; b++) {
            if (!(active & (1u << b)))
                continue;
            u32 ecls = event_class_for_irq(b);
            for (int i = 0; i < 32; i++) {
                if (!S.events[i].used || !S.events[i].enabled)
                    continue;
                int match = (S.events[i].cls == ecls) ||
                            (b == 0 && S.events[i].cls == 0xF2000003u) ||
                            (b == 7 && S.events[i].cls == 0xF0000011u && S.events[i].spec == 0x0004u);
                if (match)
                    S.events[i].status = 2u;
            }
        }
        if (S.hook_entry_int == 0u) {
            S.i_stat &= (u16)~(S.i_stat & S.i_mask);
        } else {
            u16 clr = 0u;
            if (S.auto_clear_rcnt[3]) clr |= (1u << 0);
            if (S.auto_clear_rcnt[0]) clr |= (1u << 4);
            if (S.auto_clear_rcnt[1]) clr |= (1u << 5);
            if (S.auto_clear_rcnt[2]) clr |= (1u << 6);
            S.i_stat &= (u16)~clr;
        }
        update_cop0_irq();
        hle_ev_cb_cursor = 1u; /* Phase 2: EvMdINTR callbacks */
    }

    /* Phase 2: Step through enabled EvMdINTR (mode == 0x1000) callbacks */
    while (hle_ev_cb_cursor >= 1u && hle_ev_cb_cursor <= 32u) {
        int idx = (int)hle_ev_cb_cursor - 1;
        hle_ev_cb_cursor++;
        if (S.events[idx].used && S.events[idx].enabled && S.events[idx].status == 2u &&
            S.events[idx].mode == 0x1000u && S.events[idx].cb != 0u) {
            S.events[idx].status = 1u;
            S.r[28] = S.exc_r[28];
            S.r[2] = S.events[idx].cb;
            S.pc = 0xBFC00204u;
            S.next_pc = 0xBFC00208u;
            return;
        }
    }

    /* Phase 3: Check HookEntryInt jump_buf if installed by PsyQ ResetGraph/InterruptCallback AND unacknowledged IRQs remain */
    if (hle_ev_cb_cursor == 33u && S.hook_entry_int != 0u) {
        hle_ev_cb_cursor = 34u;
        if ((S.i_stat & S.i_mask) != 0u || (hle_exc_active & 1u)) {
            if (hle_exc_active & 1u)
                S.i_stat |= 1u;
            u32 jb = S.hook_entry_int;
            u32 hook_ra = bus_read32(jb + 0u);
            if (hook_ra) {
                S.r[29] = bus_read32(jb + 4u);
                S.r[30] = bus_read32(jb + 8u);
                for (int k = 0; k < 8; k++)
                    S.r[16 + k] = bus_read32(jb + 12u + (u32)k * 4u);
                S.r[28] = bus_read32(jb + 44u);
                S.r[2] = 1u;
                S.pc = hook_ra;
                S.next_pc = hook_ra + 4u;
                hle_ev_cb_cursor = 0u;
                return;
            }
        }
    }

    hle_return_from_exception();
}

static void hle_bios_exception_entry(void)
{
    u32 cause = S.cop0[13];
    u32 exc = (cause >> 2) & 0x1Fu;

    /* Reentrant SYSCALL handler: safe both in main thread and inside SysEnqIntRP/EvMdINTR IRQ callbacks! */
    if (exc == 8u) {
        u32 a0 = S.r[4];
        if (a0 == 1u) { /* EnterCriticalSection */
            u32 prev = ((S.cop0[12] & 0x0404u) == 0x0404u) ? 1u : 0u;
            S.cop0[12] &= ~0x0404u;
            S.r[2] = prev;
        } else if (a0 == 2u) { /* ExitCriticalSection */
            S.cop0[12] |= 0x0404u;
        } else if (a0 >= 4u) { /* DeliverEvent */
            u32 ev_cls = S.r[5], ev_spec = S.r[6];
            for (int i = 0; i < 32; i++)
                if (S.events[i].used && S.events[i].enabled && S.events[i].cls == ev_cls && S.events[i].spec == ev_spec)
                    S.events[i].status = 2u;
        }
        S.cop0[12] = (S.cop0[12] & ~0x0Fu) | ((S.cop0[12] >> 2) & 0x0Fu);
        update_cop0_irq();
        S.pc = (cause & 0x80000000u) ? (S.cop0[14] + 8u) : (S.cop0[14] + 4u);
        S.next_pc = S.pc + 4u;
        return;
    }

    if (exc != 0u) {
        S.cop0[12] = (S.cop0[12] & ~0x0Fu) | ((S.cop0[12] >> 2) & 0x0Fu);
        update_cop0_irq();
        S.pc = (cause & 0x80000000u) ? (S.cop0[14] + 8u) : (S.cop0[14] + 4u);
        S.next_pc = S.pc + 4u;
        return;
    }

    /* Hardware Interrupt (exc == 0): stash interrupted thread registers in S (never clobbers guest RAM!) */
    for (u32 r = 1; r <= 31; r++)
        S.exc_r[r] = S.r[r];
    S.exc_hi = S.hi;
    S.exc_lo = S.lo;
    S.exc_epc = S.cop0[14];

    hle_exc_active = S.i_stat & S.i_mask;
    if (hle_exc_active & 1u)
        hle_update_pad_buffers();

    hle_rp_n = 0u;
    hle_rp_idx = 0u;
    hle_rp_stage = 0u;
    for (int pr = 0; pr < 8; pr++) {
        u32 node = S.sys_int_rp[pr];
        int guard = 0;
        while (node && (node & 0x1FFFFFFFu) < PSX_RAM_SIZE && guard++ < 16 && hle_rp_n < 16u) {
            u32 fn2 = bus_read32(node + 4u);
            u32 fn1 = bus_read32(node + 8u);
            if (fn1 || fn2) {
                hle_rp_fn1[hle_rp_n] = fn1;
                hle_rp_fn2[hle_rp_n] = fn2;
                hle_rp_n++;
            }
            node = bus_read32(node);
        }
    }
    hle_ev_cb_cursor = 100u;
    hle_bios_exception_step();
}

static u32 hle_rand_seed = 1u;

static int hle_bios_call(u32 table, u32 fn)
{
    u32 a0 = S.r[4], a1 = S.r[5], a2 = S.r[6], a3 = S.r[7];
    fn &= 0xFFu;

    if (table == 0xA0u) {
        switch (fn) {
        case 0x13u: { /* setjmp */
            bus_write32(a0 + 0u, S.r[31]);
            bus_write32(a0 + 4u, S.r[29]);
            bus_write32(a0 + 8u, S.r[30]);
            for (int i = 0; i < 8; i++) bus_write32(a0 + 12u + (u32)i * 4u, S.r[16 + i]);
            bus_write32(a0 + 44u, S.r[28]);
            S.r[2] = 0u;
            break;
        }
        case 0x14u: { /* longjmp */
            S.r[31] = bus_read32(a0 + 0u);
            S.r[29] = bus_read32(a0 + 4u);
            S.r[30] = bus_read32(a0 + 8u);
            for (int i = 0; i < 8; i++) S.r[16 + i] = bus_read32(a0 + 12u + (u32)i * 4u);
            S.r[28] = bus_read32(a0 + 44u);
            S.r[2] = a1 ? a1 : 1u;
            break;
        }
        case 0x15u: /* strcat */
            if (a0 && a1) {
                u32 d = a0; while (bus_read8(d)) d++;
                u32 s = a1; for (;;) { u8 c = bus_read8(s++); bus_write8(d++, c); if (!c) break; }
            }
            S.r[2] = a0; break;
        case 0x16u: /* strncat */
            if (a0 && a1) {
                u32 d = a0; while (bus_read8(d)) d++;
                for (u32 i = 0; i < a2; i++) { u8 c = bus_read8(a1 + i); if (!c) break; bus_write8(d++, c); }
                bus_write8(d, 0u);
            }
            S.r[2] = a0; break;
        case 0x17u: { /* strcmp */
            for (u32 i = 0;; i++) {
                u8 c1 = bus_read8(a0 + i), c2 = bus_read8(a1 + i);
                if (c1 != c2 || !c1) { S.r[2] = (u32)((int)c1 - (int)c2); break; }
            }
            break;
        }
        case 0x18u: { /* strncmp */
            int res = 0;
            for (u32 i = 0; i < a2; i++) {
                u8 c1 = bus_read8(a0 + i), c2 = bus_read8(a1 + i);
                if (c1 != c2 || !c1) { res = (int)c1 - (int)c2; break; }
            }
            S.r[2] = (u32)res; break;
        }
        case 0x19u: /* strcpy */
            if (a0 && a1) {
                for (u32 i = 0;; i++) { u8 c = bus_read8(a1 + i); bus_write8(a0 + i, c); if (!c) break; }
            }
            S.r[2] = a0; break;
        case 0x1Au: { /* strncpy */
            u32 i = 0;
            for (; i < a2; i++) { u8 c = bus_read8(a1 + i); bus_write8(a0 + i, c); if (!c) { i++; break; } }
            for (; i < a2; i++) bus_write8(a0 + i, 0u);
            S.r[2] = a0; break;
        }
        case 0x1Bu: { /* strlen */
            u32 n = 0; if (a0) while (bus_read8(a0 + n)) n++;
            S.r[2] = n; break;
        }
        case 0x2Au: /* memcpy */
            for (u32 i = 0; i < a2; i++) bus_write8(a0 + i, bus_read8(a1 + i));
            S.r[2] = a0; break;
        case 0x2Bu: /* memset */
            for (u32 i = 0; i < a2; i++) bus_write8(a0 + i, (u8)a1);
            S.r[2] = a0; break;
        case 0x2Cu: /* bcopy */
            if (a1 < a0) { for (u32 i = a2; i-- > 0;) bus_write8(a1 + i, bus_read8(a0 + i)); }
            else         { for (u32 i = 0; i < a2; i++) bus_write8(a1 + i, bus_read8(a0 + i)); }
            S.r[2] = a1; break;
        case 0x28u: /* bzero */
        case 0x2Du:
            for (u32 i = 0; i < a1; i++) bus_write8(a0 + i, 0u);
            break;
        case 0x2Eu: { /* memcmp */
            int res = 0;
            for (u32 i = 0; i < a2; i++) {
                u8 c1 = bus_read8(a0 + i), c2 = bus_read8(a1 + i);
                if (c1 != c2) { res = (int)c1 - (int)c2; break; }
            }
            S.r[2] = (u32)res; break;
        }
        case 0x2Fu: /* rand */
            hle_rand_seed = hle_rand_seed * 1103515245u + 12345u;
            S.r[2] = (hle_rand_seed >> 16) & 0x7FFFu;
            break;
        case 0x30u: /* srand */
            hle_rand_seed = a0;
            break;
        case 0x33u: { /* malloc */
            u32 sz = (a0 + 7u) & ~7u;
            if (!S.heap_cur) { S.heap_base = S.heap_cur = 0x80180000u; S.heap_size = 0x60000u; }
            S.r[2] = S.heap_cur;
            S.heap_cur += sz;
            break;
        }
        case 0x34u: /* free */
            break;
        case 0x37u: { /* calloc */
            u32 tot = (a0 * a1 + 7u) & ~7u;
            if (!S.heap_cur) { S.heap_base = S.heap_cur = 0x80180000u; S.heap_size = 0x60000u; }
            u32 ptr = S.heap_cur;
            S.heap_cur += tot;
            for (u32 i = 0; i < tot; i++) bus_write8(ptr + i, 0u);
            S.r[2] = ptr;
            break;
        }
        case 0x39u: /* InitHeap */
            S.heap_base = S.heap_cur = a0;
            S.heap_size = a1;
            break;
        case 0x3Fu: /* printf */
            S.r[2] = 0u;
            break;
        case 0x43u: { /* Exec(struct EXEC *hdr, int argc, char **argv) */
            u32 pc0    = bus_read32(a0 + 0x00u);
            u32 gp0    = bus_read32(a0 + 0x04u);
            u32 b_addr = bus_read32(a0 + 0x10u);
            u32 b_size = bus_read32(a0 + 0x14u);
            u32 s_addr = bus_read32(a0 + 0x18u);
            u32 s_size = bus_read32(a0 + 0x1Cu);
            if (b_addr && b_size && b_size < PSX_RAM_SIZE) {
                for (u32 i = 0; i < b_size; i++)
                    bus_write8(b_addr + i, 0u);
            }
            S.exec_saved.sp = S.r[29];
            S.exec_saved.fp = S.r[30];
            S.exec_saved.gp = S.r[28];
            S.exec_saved.ra = S.r[31];
            for (int i = 0; i < 8; i++) S.exec_saved.s[i] = S.r[16 + i];
            S.exec_saved.hook_entry_int = S.hook_entry_int;
            S.exec_saved.pad_init_ptr = S.pad_init_ptr;
            S.exec_saved.pad_buf1 = S.pad_buf1;
            S.exec_saved.pad_buf2 = S.pad_buf2;
            S.exec_saved.pad_auto = S.pad_auto;
            for (int i = 0; i < 4; i++) S.exec_saved.auto_clear_rcnt[i] = S.auto_clear_rcnt[i];
            S.exec_saved.i_mask = S.i_mask;
            for (int i = 0; i < 8; i++) S.exec_saved.sys_int_rp[i] = S.sys_int_rp[i];
            for (int i = 0; i < 32; i++) S.exec_saved.events[i] = S.events[i];
            S.exec_saved.heap_base = S.heap_base;
            S.exec_saved.heap_size = S.heap_size;
            S.exec_saved.heap_cur  = S.heap_cur;
            for (u32 i = 0; i < 4096u; i++) W.exec_top_stack[i] = W.ram[0x1FF000u + i];
            for (u32 i = 0; i < 1024u; i++) W.exec_low_tables[i] = W.ram[0x0500u + i];

            S.hook_entry_int = 0u;
            S.pad_auto = 0u;
            S.pad_init_ptr = 0u;
            S.pad_buf1 = S.pad_buf2 = 0u;
            for (int i = 0; i < 4; i++) S.auto_clear_rcnt[i] = 1u;
            for (int i = 0; i < 8; i++) S.sys_int_rp[i] = 0u;
            for (int i = 0; i < 32; i++) S.events[i].used = S.events[i].enabled = S.events[i].status = 0u;
            install_ram_vectors();
            if (s_addr) {
                S.r[29] = s_addr + s_size;
                S.r[30] = S.r[29];
            }
            S.r[28] = gp0;
            S.r[4]  = a1;
            S.r[5]  = a2;
            S.r[31] = 0xBFC00300u;
            st_reset_other++;
            jit_reset_all();
            S.pc = pc0;
            S.next_pc = pc0 + 4u;
            return 1;
        }
        case 0x44u: /* FlushCache */
            st_reset_flush++;
            jit_reset_all();
            break;
        case 0x49u: /* GPU_cw */
            gpu_gp0(a0);
            break;
        case 0x4Au: /* GPU_cwp */
            for (u32 i = 0; i < a1; i++) gpu_gp0(bus_read32(a0 + i * 4u));
            break;
        case 0x4Bu: /* send_gpu_linked_list */
            S.dma_madr[2] = a0 & 0xFFFFFFu;
            S.dma_chcr[2] = 0x01000401u;
            dma_run(2);
            break;
        case 0x4Cu: /* gpu_abort_dma */
            gpu_gp1(0x04000000u);
            S.r[2] = 0u;
            break;
        case 0x4Eu: /* gpu_sync */
            S.r[2] = 0u;
            break;
        case 0x70u: /* _bu_init */
        case 0x71u: /* _96_init */
        case 0x72u: /* _96_remove */
        case 0x96u: /* AddCDROMDevice */
        case 0x97u: /* AddMemCardDevice */
        case 0x99u: /* AddDummyTtyDevice */
            S.r[2] = 1u;
            break;
        case 0x9Fu: /* SetMem */
            S.r[2] = a0;
            break;
        default:
            S.r[2] = 0u;
            break;
        }
        S.pc = S.r[31];
        S.next_pc = S.pc + 4u;
        return 1;
    }

    if (table == 0xB0u) {
        switch (fn) {
        case 0x00u: /* SysMalloc */
            if (!S.heap_cur) { S.heap_base = S.heap_cur = 0x80180000u; S.heap_size = 0x60000u; }
            S.r[2] = S.heap_cur;
            S.heap_cur += (a0 + 7u) & ~7u;
            break;
        case 0x02u: { /* SetRCnt */
            u32 spec = a0 & 3u;
            if (spec < 3u) {
                S.rcnt_targ[spec] = (u16)a1;
                u16 m = 0x0008u; /* reset on target */
                if (a2 & 0x1000u) m |= 0x0010u; /* IRQ on target */
                if (a2 & 0x0100u) m |= 0x0100u; /* pixel/hblank/div8 */
                if (spec == 2u && (a2 & 0x0001u)) m |= 0x0200u;
                S.rcnt_mode[spec] = m;
                S.rcnt_val[spec] = 0u;
            }
            S.r[2] = 1u;
            break;
        }
        case 0x03u: { /* GetRCnt */
            u32 spec = a0 & 3u;
            S.r[2] = (spec < 3u) ? (S.rcnt_val[spec] & 0xFFFFu) : (S.vblank_count & 0xFFFFu);
            break;
        }
        case 0x04u: { /* StartRCnt */
            u32 spec = a0 & 3u;
            if (spec < 3u) S.i_mask |= (u16)(1u << (4u + spec));
            else           S.i_mask |= 1u;
            update_cop0_irq();
            S.r[2] = 1u;
            break;
        }
        case 0x05u: { /* StopRCnt */
            u32 spec = a0 & 3u;
            if (spec < 3u) S.i_mask &= (u16)~(1u << (4u + spec));
            update_cop0_irq();
            S.r[2] = 1u;
            break;
        }
        case 0x06u: { /* ResetRCnt */
            u32 spec = a0 & 3u;
            if (spec < 3u) S.rcnt_val[spec] = 0u;
            S.r[2] = 1u;
            break;
        }
        case 0x07u: { /* DeliverEvent */
            for (int i = 0; i < 32; i++) {
                if (S.events[i].used && S.events[i].enabled &&
                    S.events[i].cls == a0 && S.events[i].spec == a1) {
                    S.events[i].status = 2u;
                }
            }
            break;
        }
        case 0x08u: { /* OpenEvent */
            u32 desc = 0xFFFFFFFFu;
            for (int i = 0; i < 32; i++) {
                if (!S.events[i].used) {
                    S.events[i].used = 1u;
                    S.events[i].enabled = 0u;
                    S.events[i].status = 0u;
                    S.events[i].cls = a0;
                    S.events[i].spec = a1;
                    S.events[i].mode = a2;
                    S.events[i].cb = a3;
                    desc = 0xF1000000u | (u32)i;
                    break;
                }
            }
            S.r[2] = desc;
            break;
        }
        case 0x09u: { /* CloseEvent */
            u32 idx = a0 & 31u;
            S.events[idx].used = S.events[idx].enabled = S.events[idx].status = 0u;
            S.r[2] = 1u;
            break;
        }
        case 0x0Au: { /* WaitEvent */
            u32 idx = a0 & 31u;
            if (!S.events[idx].used || !S.events[idx].enabled) {
                S.r[2] = 0u;
                break;
            }
            if (S.events[idx].status == 2u) {
                S.events[idx].status = 1u;
                S.r[2] = 1u;
                break;
            }
            /* Re-execute B0(0A) call until interrupt delivers the event */
            S.cop0[12] |= 0x0401u;
            sync_jit_stop();
            return 0; /* stay/yield */
        }
        case 0x0Bu: { /* TestEvent */
            u32 idx = a0 & 31u;
            if (S.events[idx].used && S.events[idx].status == 2u) {
                S.events[idx].status = 1u;
                S.r[2] = 1u;
            } else {
                S.r[2] = 0u;
            }
            break;
        }
        case 0x0Cu: { /* EnableEvent */
            u32 idx = a0 & 31u;
            if (S.events[idx].used) {
                S.events[idx].enabled = 1u;
                S.events[idx].status = 1u;
                /* Ensure hardware IRQ mask bit for this event class is unmasked */
                u32 cls = S.events[idx].cls;
                if (cls == 0xF0000001u || cls == 0xF2000003u) S.i_mask |= 1u;
                else if (cls == 0xF0000003u) S.i_mask |= (1u << 2);
                else if (cls == 0xF0000004u) S.i_mask |= (1u << 3);
                else if (cls == 0xF2000000u) S.i_mask |= (1u << 4);
                else if (cls == 0xF2000001u) S.i_mask |= (1u << 5);
                else if (cls == 0xF2000002u) S.i_mask |= (1u << 6);
                else if (cls == 0xF0000008u || cls == 0xF0000011u) S.i_mask |= (1u << 7);
                else if (cls == 0xF0000009u) S.i_mask |= (1u << 9);
                update_cop0_irq();
            }
            S.r[2] = 1u;
            break;
        }
        case 0x0Du: { /* DisableEvent */
            u32 idx = a0 & 31u;
            S.events[idx].enabled = 0u;
            S.r[2] = 1u;
            break;
        }
        case 0x12u: /* InitPAD */
            S.pad_buf1 = a0;
            S.pad_buf2 = a2;
            S.r[2] = 1u;
            break;
        case 0x13u: /* StartPAD */
            S.pad_auto = 1u;
            S.i_mask |= 1u;
            update_cop0_irq();
            hle_update_pad_buffers();
            S.r[2] = 1u;
            break;
        case 0x14u: /* StopPAD */
            S.pad_auto = 0u;
            break;
        case 0x15u: /* PAD_init(type, &pad_buf) */
            S.pad_init_ptr = a1;
            S.i_mask |= 1u;
            update_cop0_irq();
            if (a1)
                bus_write32(a1, (u32)(u16)(~build_pad_buttons()));
            S.r[2] = 2u;
            break;
        case 0x16u: { /* PAD_dr() */
            u32 v = (u32)(u16)(~build_pad_buttons());
            if (S.pad_init_ptr)
                bus_write32(S.pad_init_ptr, v);
            S.r[2] = v;
            break;
        }
        case 0x17u: /* ReturnFromException */
            hle_return_from_exception();
            return 1;
        case 0x18u: /* ResetEntryInt */
            S.hook_entry_int = 0u;
            break;
        case 0x19u: /* HookEntryInt */
            S.hook_entry_int = a0;
            break;
        case 0x20u: { /* UnDeliverEvent */
            for (int i = 0; i < 32; i++)
                if (S.events[i].used && S.events[i].cls == a0 && S.events[i].spec == a1)
                    S.events[i].status = 1u;
            break;
        }
        case 0x3Du: /* std_out_putchar */
        case 0x3Fu: /* puts */
            break;
        case 0x4Au: /* InitCARD */
        case 0x4Bu: /* StartCARD */
        case 0x4Cu: /* StopCARD */
        case 0x56u: /* GetC0Table */
        case 0x57u: /* GetB0Table */
            if (fn == 0x56u) S.r[2] = 0x80000500u;
            else if (fn == 0x57u) S.r[2] = 0x80000600u;
            else S.r[2] = 1u;
            break;
        case 0x5Bu: /* ChangeClearPAD */
            S.auto_clear_rcnt[3] = (u8)(a0 & 1u);
            S.r[2] = 1u;
            break;
        default:
            S.r[2] = 1u;
            break;
        }
        S.pc = S.r[31];
        S.next_pc = S.pc + 4u;
        return 1;
    }

    if (table == 0xC0u) {
        switch (fn) {
        case 0x00u: /* EnqueueTimerAndVblankIrqs */
        case 0x01u: /* EnqueueSyscallHandler */
        case 0x07u: /* InstallExceptionHandlers */
        case 0x08u: /* SysInitMemory */
        case 0x0Cu: /* InitDefInt */
        case 0x12u: /* InstallDevices */
            if (fn == 0x08u) { S.heap_base = S.heap_cur = a0; S.heap_size = a1; }
            S.r[2] = 1u;
            break;
        case 0x02u: { /* SysEnqIntRP */
            u32 pr = a0 & 7u;
            bus_write32(a1 + 0u, S.sys_int_rp[pr]);
            S.sys_int_rp[pr] = a1;
            S.r[2] = 1u;
            break;
        }
        case 0x03u: { /* SysDeqIntRP */
            u32 pr = a0 & 7u;
            u32 cur = S.sys_int_rp[pr], prev = 0u;
            while (cur && cur != a1) { prev = cur; cur = bus_read32(cur); }
            if (cur == a1) {
                u32 nxt = bus_read32(cur);
                if (prev) bus_write32(prev, nxt);
                else      S.sys_int_rp[pr] = nxt;
            }
            S.r[2] = 1u;
            break;
        }
        case 0x0Au: { /* ChangeClearRCnt(t, flag) */
            u32 sp = a0 & 3u;
            u32 old = S.auto_clear_rcnt[sp];
            S.auto_clear_rcnt[sp] = (u8)(a1 & 1u);
            S.r[2] = old;
            break;
        }
        case 0x1Cu: /* AdjustA0Table */
            break;
        default:
            S.r[2] = 0u;
            break;
        }
        S.pc = S.r[31];
        S.next_pc = S.pc + 4u;
        return 1;
    }
    return 0;
}

/* ---- R3000A Exception & Single-Instruction Execution ---- */
static void cpu_exception(u32 code)
{
    u32 sr = S.cop0[12];
    S.cop0[12] = (sr & ~0x3Fu) | ((sr & 0x0Fu) << 2);
    S.cop0[13] = (S.cop0[13] & ~0x8000007Cu) | ((code & 0x1Fu) << 2) | (S.in_delay ? 0x80000000u : 0u);
    S.cop0[14] = S.in_delay ? (S.cur_pc - 4u) : S.cur_pc;
    u32 vec = (sr & (1u << 22)) ? 0xBFC00180u : 0x80000080u;
    S.pc = vec;
    S.next_pc = vec + 4u;
    S.in_delay = S.next_delay = 0;
    sync_jit_stop();
}

static int r3000_run_batch(int count)
{
    u8 *const ram = W.ram;
    u32 pc = S.pc;
    u32 next_pc = S.next_pc;
    u32 ld_reg = S.ld_reg;
    u32 ld_val = S.ld_val;
    u8 next_delay = S.next_delay;
    u32 isc = S.cop0[12] & 0x10000u;
    int irq_pend = (S.cop0[12] & 1u) && (S.cop0[12] & S.cop0[13] & 0xFF00u);
    int cost = 0;
    u32 exc_code = 0u;

    while (cost < count) {
        if (__builtin_expect(irq_pend && !next_delay, 0)) {
            S.pc = pc; S.next_pc = next_pc; S.cur_pc = pc; S.in_delay = 0;
            S.ld_reg = (u8)ld_reg; S.ld_val = ld_val; S.next_delay = 0;
            cpu_exception(0u);
            pc = S.pc; next_pc = S.next_pc;
            isc = S.cop0[12] & 0x10000u;
            irq_pend = 0;
        }

        u32 op;
        /* Fast fetch: aligned KSEG0 game RAM 0x80001000..0x801FFFFC (~99.99% of PS1 instructions) */
        if (__builtin_expect((pc - 0x80001000u) < 0x001FF000u && (pc & 3u) == 0u, 1)) {
            op = *(const u32 *)(ram + (pc & 0x1FFFFCu));
        } else {
            if (!S.has_ext_bios) {
                u32 low29 = pc & 0x1FFFFFFFu;
                if (__builtin_expect(low29 == 0xA0u || low29 == 0xB0u || low29 == 0xC0u, 0)) {
                    if (ld_reg) { S.r[ld_reg] = ld_val; ld_reg = 0u; }
                    S.pc = pc; S.next_pc = next_pc; S.ld_reg = 0; S.pend_reg = 0; S.next_delay = next_delay;
                    if (!hle_bios_call(low29, S.r[9]))
                        return count;
                    pc = S.pc; next_pc = S.next_pc; next_delay = S.next_delay;
                    isc = S.cop0[12] & 0x10000u;
                    irq_pend = (S.cop0[12] & 1u) && (S.cop0[12] & S.cop0[13] & 0xFF00u);
                    cost++;
                    continue;
                }
                if (__builtin_expect(low29 == 0x1FC00300u, 0)) {
                    if (ld_reg) { S.r[ld_reg] = ld_val; ld_reg = 0u; }
                    S.r[29] = S.exec_saved.sp;
                    S.r[30] = S.exec_saved.fp;
                    S.r[28] = S.exec_saved.gp;
                    S.r[31] = S.exec_saved.ra;
                    for (int i = 0; i < 8; i++) S.r[16 + i] = S.exec_saved.s[i];
                    S.hook_entry_int = S.exec_saved.hook_entry_int;
                    S.pad_init_ptr = S.exec_saved.pad_init_ptr;
                    S.pad_buf1 = S.exec_saved.pad_buf1;
                    S.pad_buf2 = S.exec_saved.pad_buf2;
                    S.pad_auto = S.exec_saved.pad_auto;
                    for (int i = 0; i < 4; i++) S.auto_clear_rcnt[i] = S.exec_saved.auto_clear_rcnt[i];
                    S.i_mask = S.exec_saved.i_mask;
                    for (int i = 0; i < 8; i++) S.sys_int_rp[i] = S.exec_saved.sys_int_rp[i];
                    for (int i = 0; i < 32; i++) S.events[i] = S.exec_saved.events[i];
                    S.heap_base = S.exec_saved.heap_base;
                    S.heap_size = S.exec_saved.heap_size;
                    S.heap_cur  = S.exec_saved.heap_cur;
                    for (u32 i = 0; i < 4096u; i++) W.ram[0x1FF000u + i] = W.exec_top_stack[i];
                    for (u32 i = 0; i < 1024u; i++) W.ram[0x0500u + i] = W.exec_low_tables[i];
                    hle_ev_cb_cursor = 0u;
                    update_cop0_irq();
                    st_reset_other++;
                    jit_reset_all();
                    pc = S.pc = S.exec_saved.ra;
                    next_pc = S.next_pc = pc + 4u;
                    next_delay = S.next_delay = 0;
                    isc = S.cop0[12] & 0x10000u;
                    irq_pend = (S.cop0[12] & 1u) && (S.cop0[12] & S.cop0[13] & 0xFF00u);
                    cost++;
                    continue;
                }
                if (__builtin_expect(low29 == 0x1FC00180u || low29 == 0x1FC00200u || low29 == 0x1FC00224u, 0)) {
                    if (ld_reg) { S.r[ld_reg] = ld_val; ld_reg = 0u; }
                    S.pc = pc; S.next_pc = next_pc; S.cur_pc = pc; S.ld_reg = 0; S.pend_reg = 0; S.next_delay = next_delay;
                    if (low29 == 0x1FC00180u)      hle_bios_exception_entry();
                    else if (low29 == 0x1FC00200u) hle_bios_exception_step();
                    else                           hle_return_from_exception();
                    pc = S.pc; next_pc = S.next_pc; next_delay = S.next_delay;
                    isc = S.cop0[12] & 0x10000u;
                    irq_pend = (S.cop0[12] & 1u) && (S.cop0[12] & S.cop0[13] & 0xFF00u);
                    cost++;
                    continue;
                }
            }
            if (__builtin_expect((pc & 3u) != 0u, 0)) {
                if (ld_reg) { S.r[ld_reg] = ld_val; ld_reg = 0u; }
                S.cur_pc = pc; S.cop0[8] = pc; S.in_delay = next_delay; S.ld_reg = 0; S.pend_reg = 0;
                cpu_exception(4u);
                pc = S.pc; next_pc = S.next_pc; next_delay = 0;
                isc = S.cop0[12] & 0x10000u;
                irq_pend = (S.cop0[12] & 1u) && (S.cop0[12] & S.cop0[13] & 0xFF00u);
                cost++;
                continue;
            }
            u32 p = mask_phys(pc);
            op = (__builtin_expect(p < 0x800000u, 1))
                ? *(const u32 *)(ram + (p & 0x1FFFFCu))
                : bus_read32(pc);
        }

        u32 cur_pc = pc;
        u8 in_delay = next_delay;
        pc = next_pc;
        next_pc = pc + 4u;
        next_delay = 0;
        cost++;

        u32 opc = op >> 26;
        u32 rs = (op >> 21) & 31u;
        u32 rt = (op >> 16) & 31u;
        u32 rsv = S.r[rs];
        u32 rtv = S.r[rt];

        /* 1-stage post-operand-read R3000A load-delay commit (zero work on ~80% of instructions) */
        if (__builtin_expect(ld_reg != 0u, 0)) {
            S.r[ld_reg] = ld_val;
            ld_reg = 0u;
        }

        switch (opc) {
        case 0x00u: { /* SPECIAL */
            u32 rd = (op >> 11) & 31u;
            switch (op & 0x3Fu) {
            case 0x00u: if (rd) S.r[rd] = rtv << ((op >> 6) & 31u); break; /* SLL */
            case 0x02u: if (rd) S.r[rd] = rtv >> ((op >> 6) & 31u); break; /* SRL */
            case 0x03u: if (rd) S.r[rd] = (u32)((s32)rtv >> ((op >> 6) & 31u)); break; /* SRA */
            case 0x04u: if (rd) S.r[rd] = rtv << (rsv & 31u); break; /* SLLV */
            case 0x06u: if (rd) S.r[rd] = rtv >> (rsv & 31u); break; /* SRLV */
            case 0x07u: if (rd) S.r[rd] = (u32)((s32)rtv >> (rsv & 31u)); break; /* SRAV */
            case 0x08u: next_pc = rsv; next_delay = 1; break; /* JR */
            case 0x09u: if (rd) S.r[rd] = cur_pc + 8u; next_pc = rsv; next_delay = 1; break; /* JALR */
            case 0x0Cu: exc_code = 8u; goto do_exc; /* SYSCALL */
            case 0x0Du: exc_code = 9u; goto do_exc; /* BREAK */
            case 0x10u: if (rd) S.r[rd] = S.hi; break; /* MFHI */
            case 0x11u: S.hi = rsv; break; /* MTHI */
            case 0x12u: if (rd) S.r[rd] = S.lo; break; /* MFLO */
            case 0x13u: S.lo = rsv; break; /* MTLO */
            case 0x18u: { /* MULT */
                s64 prod = (s64)(s32)rsv * (s64)(s32)rtv;
                S.lo = (u32)prod; S.hi = (u32)((u64)prod >> 32);
                break;
            }
            case 0x19u: { /* MULTU */
                u64 prod = (u64)rsv * (u64)rtv;
                S.lo = (u32)prod; S.hi = (u32)(prod >> 32);
                break;
            }
            case 0x1Au: { /* DIV */
                s32 a = (s32)rsv, b = (s32)rtv;
                if (b == 0) {
                    S.lo = (a >= 0) ? 0xFFFFFFFFu : 1u;
                    S.hi = (u32)a;
                } else if ((u32)a == 0x80000000u && b == -1) {
                    S.lo = 0x80000000u;
                    S.hi = 0u;
                } else {
                    S.lo = (u32)(a / b);
                    S.hi = (u32)(a % b);
                }
                break;
            }
            case 0x1Bu: { /* DIVU */
                if (rtv == 0u) {
                    S.lo = 0xFFFFFFFFu;
                    S.hi = rsv;
                } else {
                    S.lo = rsv / rtv;
                    S.hi = rsv % rtv;
                }
                break;
            }
            case 0x20u: { /* ADD */
                u32 res = rsv + rtv;
                if (((~(rsv ^ rtv) & (rsv ^ res)) & 0x80000000u) != 0u) { exc_code = 12u; goto do_exc; }
                if (rd) S.r[rd] = res;
                break;
            }
            case 0x21u: if (rd) S.r[rd] = rsv + rtv; break; /* ADDU */
            case 0x22u: { /* SUB */
                u32 res = rsv - rtv;
                if ((((rsv ^ rtv) & (rsv ^ res)) & 0x80000000u) != 0u) { exc_code = 12u; goto do_exc; }
                if (rd) S.r[rd] = res;
                break;
            }
            case 0x23u: if (rd) S.r[rd] = rsv - rtv; break; /* SUBU */
            case 0x24u: if (rd) S.r[rd] = rsv & rtv; break; /* AND */
            case 0x25u: if (rd) S.r[rd] = rsv | rtv; break; /* OR */
            case 0x26u: if (rd) S.r[rd] = rsv ^ rtv; break; /* XOR */
            case 0x27u: if (rd) S.r[rd] = ~(rsv | rtv); break; /* NOR */
            case 0x2Au: if (rd) S.r[rd] = ((s32)rsv < (s32)rtv) ? 1u : 0u; break; /* SLT */
            case 0x2Bu: if (rd) S.r[rd] = (rsv < rtv) ? 1u : 0u; break; /* SLTU */
            default: exc_code = 10u; goto do_exc;
            }
            break;
        }
        case 0x01u: { /* REGIMM: BLTZ / BGEZ / BLTZAL / BGEZAL */
            int cond = (rt & 1u) ? ((s32)rsv >= 0) : ((s32)rsv < 0);
            if ((rt & 0x1Eu) == 0x10u) S.r[31] = cur_pc + 8u;
            next_delay = 1;
            if (cond) next_pc = pc + ((u32)(s32)(s16)op << 2);
            break;
        }
        case 0x02u: next_pc = (pc & 0xF0000000u) | ((op & 0x03FFFFFFu) << 2); next_delay = 1; break; /* J */
        case 0x03u: S.r[31] = cur_pc + 8u; next_pc = (pc & 0xF0000000u) | ((op & 0x03FFFFFFu) << 2); next_delay = 1; break; /* JAL */
        case 0x04u: next_delay = 1; if (rsv == rtv) next_pc = pc + ((u32)(s32)(s16)op << 2); break; /* BEQ */
        case 0x05u: next_delay = 1; if (rsv != rtv) next_pc = pc + ((u32)(s32)(s16)op << 2); break; /* BNE */
        case 0x06u: next_delay = 1; if ((s32)rsv <= 0) next_pc = pc + ((u32)(s32)(s16)op << 2); break; /* BLEZ */
        case 0x07u: next_delay = 1; if ((s32)rsv >  0) next_pc = pc + ((u32)(s32)(s16)op << 2); break; /* BGTZ */
        case 0x08u: { /* ADDI */
            u32 simm = (u32)(s32)(s16)op, res = rsv + simm;
            if (((~(rsv ^ simm) & (rsv ^ res)) & 0x80000000u) != 0u) { exc_code = 12u; goto do_exc; }
            if (rt) S.r[rt] = res;
            break;
        }
        case 0x09u: if (rt) S.r[rt] = rsv + (u32)(s32)(s16)op; break; /* ADDIU */
        case 0x0Au: if (rt) S.r[rt] = ((s32)rsv < (s32)(s16)op) ? 1u : 0u; break; /* SLTI */
        case 0x0Bu: if (rt) S.r[rt] = (rsv < (u32)(s32)(s16)op) ? 1u : 0u; break; /* SLTIU */
        case 0x0Cu: if (rt) S.r[rt] = rsv & (op & 0xFFFFu); break; /* ANDI */
        case 0x0Du: if (rt) S.r[rt] = rsv | (op & 0xFFFFu); break; /* ORI */
        case 0x0Eu: if (rt) S.r[rt] = rsv ^ (op & 0xFFFFu); break; /* XORI */
        case 0x0Fu: if (rt) S.r[rt] = (op & 0xFFFFu) << 16; break; /* LUI */

        case 0x10u: { /* COP0 */
            u32 rd = (op >> 11) & 31u;
            if (rs == 0x00u) { /* MFC0 */
                if (rt) { ld_reg = rt; ld_val = (rd == 15u) ? 0x00000002u : S.cop0[rd]; }
            } else if (rs == 0x04u) { /* MTC0 */
                if (rd == 13u) S.cop0[13] = (S.cop0[13] & ~0x0300u) | (rtv & 0x0300u);
                else if (rd == 12u) S.cop0[12] = rtv;
                else if (rd != 14u && rd != 15u) S.cop0[rd] = rtv;
                update_cop0_irq();
                isc = S.cop0[12] & 0x10000u;
                irq_pend = (S.cop0[12] & 1u) && (S.cop0[12] & S.cop0[13] & 0xFF00u);
            } else if ((rs & 0x10u) && (op & 0x3Fu) == 0x10u) { /* RFE */
                S.cop0[12] = (S.cop0[12] & ~0x0Fu) | ((S.cop0[12] >> 2) & 0x0Fu);
                update_cop0_irq();
                isc = S.cop0[12] & 0x10000u;
                irq_pend = (S.cop0[12] & 1u) && (S.cop0[12] & S.cop0[13] & 0xFF00u);
            }
            break;
        }

        case 0x12u: { /* COP2: GTE */
            if (op & (1u << 25)) {
                u32 gop = op & 0x3Fu;
                gte_exec(op);
                cost += (gop == 0x30u) ? 6 : (gop == 0x16u || gop == 0x3Fu || gop == 0x20u) ? 10 : 2;
            } else {
                u32 rd = (op >> 11) & 31u;
                switch (rs) {
                case 0x00u: if (rt) { ld_reg = rt; ld_val = gte_read_data(rd); } break; /* MFC2 */
                case 0x02u: if (rt) { ld_reg = rt; ld_val = gte_read_ctrl(rd); } break; /* CFC2 */
                case 0x04u: gte_write_data(rd, rtv); break;                             /* MTC2 */
                case 0x06u: gte_write_ctrl(rd, rtv); break;                             /* CTC2 */
                }
            }
            break;
        }

        case 0x20u: { /* LB */
            u32 ea = rsv + (u32)(s32)(s16)op;
            u32 v = (__builtin_expect((ea & 0x7FFFFFFFu) < 0x200000u, 1))
                ? (u32)(s32)(s8)ram[ea & 0x1FFFFFu]
                : (u32)(s32)(s8)bus_read8(ea);
            if (rt) { ld_reg = rt; ld_val = v; }
            break;
        }
        case 0x21u: { /* LH */
            u32 ea = rsv + (u32)(s32)(s16)op;
            if (__builtin_expect(((ea & 0x7FFFFFFFu) < 0x200000u) && !(ea & 1u), 1)) {
                u32 v = (u32)(s32)*(const s16 *)(ram + (ea & 0x1FFFFEu));
                if (rt) { ld_reg = rt; ld_val = v; }
            } else {
                if (ea & 1u) { S.cop0[8] = ea; exc_code = 4u; goto do_exc; }
                u32 v = (u32)(s32)(s16)bus_read16(ea);
                if (rt) { ld_reg = rt; ld_val = v; }
            }
            break;
        }
        case 0x22u: { /* LWL */
            u32 ea = rsv + (u32)(s32)(s16)op;
            u32 cur = S.r[rt];
            u32 aligned = bus_read32(ea & ~3u);
            u32 res;
            switch (ea & 3u) {
            case 0u: res = (cur & 0x00FFFFFFu) | (aligned << 24); break;
            case 1u: res = (cur & 0x0000FFFFu) | (aligned << 16); break;
            case 2u: res = (cur & 0x000000FFu) | (aligned <<  8); break;
            default: res = aligned; break;
            }
            if (rt) { ld_reg = rt; ld_val = res; }
            break;
        }
        case 0x23u: { /* LW */
            u32 ea = rsv + (u32)(s32)(s16)op;
            if (__builtin_expect(((ea & 0x7FFFFFFFu) < 0x200000u) && !(ea & 3u), 1)) {
                u32 v = *(const u32 *)(ram + (ea & 0x1FFFFCu));
                if (rt) { ld_reg = rt; ld_val = v; }
            } else {
                if (ea & 3u) { S.cop0[8] = ea; exc_code = 4u; goto do_exc; }
                u32 v = bus_read32(ea);
                if (rt) { ld_reg = rt; ld_val = v; }
            }
            break;
        }
        case 0x24u: { /* LBU */
            u32 ea = rsv + (u32)(s32)(s16)op;
            u32 v = (__builtin_expect((ea & 0x7FFFFFFFu) < 0x200000u, 1))
                ? (u32)ram[ea & 0x1FFFFFu]
                : (u32)bus_read8(ea);
            if (rt) { ld_reg = rt; ld_val = v; }
            break;
        }
        case 0x25u: { /* LHU */
            u32 ea = rsv + (u32)(s32)(s16)op;
            if (__builtin_expect(((ea & 0x7FFFFFFFu) < 0x200000u) && !(ea & 1u), 1)) {
                u32 v = (u32)*(const u16 *)(ram + (ea & 0x1FFFFEu));
                if (rt) { ld_reg = rt; ld_val = v; }
            } else {
                if (ea & 1u) { S.cop0[8] = ea; exc_code = 4u; goto do_exc; }
                u32 v = (u32)bus_read16(ea);
                if (rt) { ld_reg = rt; ld_val = v; }
            }
            break;
        }
        case 0x26u: { /* LWR */
            u32 ea = rsv + (u32)(s32)(s16)op;
            u32 cur = S.r[rt];
            u32 aligned = bus_read32(ea & ~3u);
            u32 res;
            switch (ea & 3u) {
            case 0u: res = aligned; break;
            case 1u: res = (cur & 0xFF000000u) | (aligned >>  8); break;
            case 2u: res = (cur & 0xFFFF0000u) | (aligned >> 16); break;
            default: res = (cur & 0xFFFFFF00u) | (aligned >> 24); break;
            }
            if (rt) { ld_reg = rt; ld_val = res; }
            break;
        }
        case 0x28u: { /* SB */
            u32 ea = rsv + (u32)(s32)(s16)op;
            if (__builtin_expect(((ea & 0x7FFFFFFFu) < 0x200000u) && !isc, 1)) {
                u32 off = ea & 0x1FFFFFu;
                ram[off] = (u8)rtv;
                jit_touch_ram(off);
            } else {
                bus_write8(ea, (u8)rtv);
                irq_pend = (S.cop0[12] & 1u) && (S.cop0[12] & S.cop0[13] & 0xFF00u);
            }
            break;
        }
        case 0x29u: { /* SH */
            u32 ea = rsv + (u32)(s32)(s16)op;
            if (__builtin_expect(((ea & 0x7FFFFFFFu) < 0x200000u) && !((ea & 1u) | isc), 1)) {
                u32 off = ea & 0x1FFFFEu;
                *(u16 *)(ram + off) = (u16)rtv;
                jit_touch_ram(off);
            } else {
                if (ea & 1u) { S.cop0[8] = ea; exc_code = 5u; goto do_exc; }
                bus_write16(ea, (u16)rtv);
                irq_pend = (S.cop0[12] & 1u) && (S.cop0[12] & S.cop0[13] & 0xFF00u);
            }
            break;
        }
        case 0x2Au: { /* SWL */
            u32 ea = rsv + (u32)(s32)(s16)op;
            u32 cur = bus_read32(ea & ~3u), res;
            switch (ea & 3u) {
            case 0u: res = (cur & 0xFFFFFF00u) | (rtv >> 24); break;
            case 1u: res = (cur & 0xFFFF0000u) | (rtv >> 16); break;
            case 2u: res = (cur & 0xFF000000u) | (rtv >>  8); break;
            default: res = rtv; break;
            }
            bus_write32(ea & ~3u, res);
            irq_pend = (S.cop0[12] & 1u) && (S.cop0[12] & S.cop0[13] & 0xFF00u);
            break;
        }
        case 0x2Bu: { /* SW */
            u32 ea = rsv + (u32)(s32)(s16)op;
            if (__builtin_expect(((ea & 0x7FFFFFFFu) < 0x200000u) && !((ea & 3u) | isc), 1)) {
                u32 off = ea & 0x1FFFFCu;
                *(u32 *)(ram + off) = rtv;
                jit_touch_ram(off);
            } else {
                if (ea & 3u) { S.cop0[8] = ea; exc_code = 5u; goto do_exc; }
                bus_write32(ea, rtv);
                irq_pend = (S.cop0[12] & 1u) && (S.cop0[12] & S.cop0[13] & 0xFF00u);
            }
            break;
        }
        case 0x2Eu: { /* SWR */
            u32 ea = rsv + (u32)(s32)(s16)op;
            u32 cur = bus_read32(ea & ~3u), res;
            switch (ea & 3u) {
            case 0u: res = rtv; break;
            case 1u: res = (cur & 0x000000FFu) | (rtv <<  8); break;
            case 2u: res = (cur & 0x0000FFFFu) | (rtv << 16); break;
            default: res = (cur & 0x00FFFFFFu) | (rtv << 24); break;
            }
            bus_write32(ea & ~3u, res);
            irq_pend = (S.cop0[12] & 1u) && (S.cop0[12] & S.cop0[13] & 0xFF00u);
            break;
        }
        case 0x32u: { /* LWC2 */
            u32 ea = rsv + (u32)(s32)(s16)op;
            if (__builtin_expect(((ea & 0x7FFFFFFFu) < 0x200000u) && !(ea & 3u), 1)) {
                gte_write_data(rt, *(const u32 *)(ram + (ea & 0x1FFFFCu)));
            } else {
                if (ea & 3u) { S.cop0[8] = ea; exc_code = 4u; goto do_exc; }
                gte_write_data(rt, bus_read32(ea));
            }
            break;
        }
        case 0x3Au: { /* SWC2 */
            u32 ea = rsv + (u32)(s32)(s16)op;
            if (__builtin_expect(((ea & 0x7FFFFFFFu) < 0x200000u) && !((ea & 3u) | isc), 1)) {
                u32 off = ea & 0x1FFFFCu;
                *(u32 *)(ram + off) = gte_read_data(rt);
                jit_touch_ram(off);
            } else {
                if (ea & 3u) { S.cop0[8] = ea; exc_code = 5u; goto do_exc; }
                bus_write32(ea, gte_read_data(rt));
                irq_pend = (S.cop0[12] & 1u) && (S.cop0[12] & S.cop0[13] & 0xFF00u);
            }
            break;
        }
        default:
            exc_code = 10u;
            goto do_exc;
        }
        continue;

    do_exc:
        S.cur_pc = cur_pc;
        S.in_delay = in_delay;
        S.ld_reg = 0;
        S.pend_reg = 0;
        cpu_exception(exc_code);
        pc = S.pc;
        next_pc = S.next_pc;
        next_delay = 0;
        isc = S.cop0[12] & 0x10000u;
        irq_pend = (S.cop0[12] & 1u) && (S.cop0[12] & S.cop0[13] & 0xFF00u);
    }

    S.pc = pc;
    S.next_pc = next_pc;
    S.ld_reg = (u8)ld_reg;
    S.ld_val = ld_val;
    S.pend_reg = 0;
    S.next_delay = next_delay;
    return cost;
}

static inline void r3000_step(void)
{
    (void)r3000_run_batch(1);
}

#ifdef __mips__
/* ---- Native R3000A -> MIPS32 Stage-4 Basic-Block Dynarec (ALi S3811 24KEc) ---- */
typedef char jit_chk_pc  [(__builtin_offsetof(struct psx_state_s, pc)         == 0x080) ? 1 : -1];
typedef char jit_chk_npc [(__builtin_offsetof(struct psx_state_s, next_pc)    == 0x084) ? 1 : -1];
typedef char jit_chk_hi  [(__builtin_offsetof(struct psx_state_s, hi)         == 0x088) ? 1 : -1];
typedef char jit_chk_lo  [(__builtin_offsetof(struct psx_state_s, lo)         == 0x08C) ? 1 : -1];
typedef char jit_chk_gted[(__builtin_offsetof(struct psx_state_s, gte_d)      == 0x090) ? 1 : -1];
typedef char jit_chk_gtec[(__builtin_offsetof(struct psx_state_s, gte_c)      == 0x110) ? 1 : -1];
typedef char jit_chk_stop[(__builtin_offsetof(struct psx_state_s, jit_stop)   == 0x210) ? 1 : -1];
typedef char jit_chk_hc  [(__builtin_offsetof(struct psx_state_s, jit_hc_ptr) == 0x214) ? 1 : -1];
typedef char jit_chk_bias[(__builtin_offsetof(struct psx_state_s, jit_bias)   == 0x21C) ? 1 : -1];
typedef char jit_chk_spad[(__builtin_offsetof(struct psx_state_s, scratch)    == 0x220) ? 1 : -1];

extern int  psx_jit_enter(int budget, void *s_ptr, void *ram_ptr, void *entry_ptr);
extern void psx_jit_exit(void);
extern void psx_jit_link_ram(void);
extern void psx_jit_link_ram2(void);
extern void psx_jit_nclip(void);
extern void psx_jit_call_hlp(void);
extern void psx_jit_lb(void);
extern void psx_jit_lbu(void);
extern void psx_jit_lh(void);
extern void psx_jit_lhu(void);
extern void psx_jit_lw(void);
extern void psx_jit_lwl(void);
extern void psx_jit_lwr(void);
extern void psx_jit_sb(void);
extern void psx_jit_sh(void);
extern void psx_jit_sw(void);
extern void psx_jit_swl(void);
extern void psx_jit_swr(void);

u32  __attribute__((noinline, used)) psx_hlp_rd8s (u32 ea) { return (u32)(s32)(s8)bus_read8(ea); }
u32  __attribute__((noinline, used)) psx_hlp_rd8u (u32 ea) { return (u32)bus_read8(ea); }
u32  __attribute__((noinline, used)) psx_hlp_rd16s(u32 ea) { return (u32)(s32)(s16)bus_read16(ea); }
u32  __attribute__((noinline, used)) psx_hlp_rd16u(u32 ea) { return (u32)bus_read16(ea); }
u32  __attribute__((noinline, used)) psx_hlp_rd32 (u32 ea) { return bus_read32(ea); }
void __attribute__((noinline, used)) psx_hlp_wr8  (u32 ea, u32 v) { bus_write8(ea, (u8)v); }
void __attribute__((noinline, used)) psx_hlp_wr16 (u32 ea, u32 v) { bus_write16(ea, (u16)v); }
void __attribute__((noinline, used)) psx_hlp_wr32 (u32 ea, u32 v) { bus_write32(ea, v); }

u32 __attribute__((noinline, used)) psx_hlp_lwl(u32 ea, u32 cur)
{
    u32 aligned = bus_read32(ea & ~3u);
    switch (ea & 3u) {
    case 0u: return (cur & 0x00FFFFFFu) | (aligned << 24);
    case 1u: return (cur & 0x0000FFFFu) | (aligned << 16);
    case 2u: return (cur & 0x000000FFu) | (aligned <<  8);
    default: return aligned;
    }
}

u32 __attribute__((noinline, used)) psx_hlp_lwr(u32 ea, u32 cur)
{
    u32 aligned = bus_read32(ea & ~3u);
    switch (ea & 3u) {
    case 0u: return aligned;
    case 1u: return (cur & 0xFF000000u) | (aligned >>  8);
    case 2u: return (cur & 0xFFFF0000u) | (aligned >> 16);
    default: return (cur & 0xFFFFFF00u) | (aligned >> 24);
    }
}

void __attribute__((noinline, used)) psx_hlp_swl(u32 ea, u32 rtv)
{
    u32 a = ea & ~3u, cur = bus_read32(a), res;
    switch (ea & 3u) {
    case 0u: res = (cur & 0xFFFFFF00u) | (rtv >> 24); break;
    case 1u: res = (cur & 0xFFFF0000u) | (rtv >> 16); break;
    case 2u: res = (cur & 0xFF000000u) | (rtv >>  8); break;
    default: res = rtv; break;
    }
    bus_write32(a, res);
}

void __attribute__((noinline, used)) psx_hlp_swr(u32 ea, u32 rtv)
{
    u32 a = ea & ~3u, cur = bus_read32(a), res;
    switch (ea & 3u) {
    case 0u: res = rtv; break;
    case 1u: res = (cur & 0x000000FFu) | (rtv <<  8); break;
    case 2u: res = (cur & 0x0000FFFFu) | (rtv << 16); break;
    default: res = (cur & 0x00FFFFFFu) | (rtv << 24); break;
    }
    bus_write32(a, res);
}

__asm__(
    ".section .text\n"
    ".align 2\n"
    ".set push\n"
    ".set mips32r2\n"
    ".set noreorder\n"
    ".set noat\n"
    ".globl psx_jit_enter\n"
    ".globl psx_jit_exit\n"
    ".globl psx_jit_link_ram\n"
    ".globl psx_jit_link_ram2\n"
    ".globl psx_jit_nclip\n"
    ".globl psx_jit_call_hlp\n"
    ".globl psx_jit_lb\n"
    ".globl psx_jit_lbu\n"
    ".globl psx_jit_lh\n"
    ".globl psx_jit_lhu\n"
    ".globl psx_jit_lw\n"
    ".globl psx_jit_lwl\n"
    ".globl psx_jit_lwr\n"
    ".globl psx_jit_sb\n"
    ".globl psx_jit_sh\n"
    ".globl psx_jit_sw\n"
    ".globl psx_jit_swl\n"
    ".globl psx_jit_swr\n"
    "psx_jit_enter:\n"
    "    addiu $sp, $sp, -72\n"
    "    sw    $a0, 24($sp)\n"
    "    sw    $s0, 28($sp)\n"
    "    sw    $s1, 32($sp)\n"
    "    sw    $s2, 36($sp)\n"
    "    sw    $s3, 40($sp)\n"
    "    sw    $s4, 44($sp)\n"
    "    sw    $s5, 48($sp)\n"
    "    sw    $s6, 52($sp)\n"
    "    sw    $s7, 56($sp)\n"
    "    sw    $fp, 60($sp)\n"
    "    sw    $ra, 64($sp)\n"
    "    addu  $s4, $a0, $0\n"
    "    addu  $s0, $a1, $0\n"
    "    addu  $s1, $a2, $0\n"
    "    addu  $s2, $a3, $0\n"
    "    lw    $s3, 0x214($s0)\n"
    "    lui   $s5, 0x7f80\n"
    "    lui   $s7, %hi(psx_jit_dispatch_ram)\n"
    "    addiu $s7, $s7, %lo(psx_jit_dispatch_ram)\n"
    "    lui   $fp, %hi(psx_jit_dispatch)\n"
    "    addiu $fp, $fp, %lo(psx_jit_dispatch)\n"
    "    lw    $a0, 0x080($s0)\n"
    "psx_jit_dispatch:\n"
    "    blez  $s4, psx_jit_exit\n"
    "    lw    $t0, 0x210($s0)\n"
    "    lui   $t3, 0x8000\n"
    "    bne   $t0, $0, psx_jit_exit\n"
    "    subu  $t1, $a0, $t3\n"
    "    lui   $t2, 0xffe0\n"
    "    ori   $t2, $t2, 3\n"
    "    and   $t2, $t1, $t2\n"
    "    bne   $t2, $0, psx_jit_exit\n"
    "    addu  $t1, $s2, $t1\n"
    "    lw    $t2, 0($t1)\n"
    "    sltiu $t0, $t2, 2\n"
    "    bne   $t0, $0, psx_jit_exit\n"
    "    nop\n"
    "    jr    $t2\n"
    "    nop\n"
    "psx_jit_dispatch_ram:\n"
    "    blez  $s4, psx_jit_exit\n"
    "    lw    $t0, 0x210($s0)\n"
    "    nop\n"
    "    bne   $t0, $0, psx_jit_exit\n"
    "    ext   $t1, $a0, 0, 21\n"
    "    addu  $t1, $s2, $t1\n"
    "    lw    $t2, 0($t1)\n"
    "    sltiu $t0, $t2, 2\n"
    "    bne   $t0, $0, psx_jit_exit\n"
    "    nop\n"
    "    jr    $t2\n"
    "    nop\n"
    /* a block's exit not linked yet: "jal psx_jit_link_ram2; addiu $s4, $s4, -cost; .word target_pc" -- the
       target compiled: the jal becomes "j target" (the addiu stays its delay slot) and it goes there (the
       target's prologue tests the budget); not compiled: leaves with $a0 = target_pc */
    "psx_jit_link_ram2:\n"
    "    lw    $a0, 0($ra)\n"
    "    ext   $t1, $a0, 0, 21\n"
    "    addu  $t1, $s2, $t1\n"
    "    lw    $t2, 0($t1)\n"
    "    sltiu $t0, $t2, 2\n"
    "    bne   $t0, $0, psx_jit_exit\n"
    "    ext   $t3, $t2, 2, 26\n"
    "    lui   $t0, 0x0800\n"
    "    or    $t3, $t3, $t0\n"
    "    addiu $t1, $ra, -8\n"
    "    sw    $t3, 0($t1)\n"
    "    cache 0x15, 0($t1)\n"
    "    cache 0x10, 0($t1)\n"
    "    sync\n"
    "    .word 0x000000c0\n"
    "    jr    $t2\n"
    "    nop\n"
    "psx_jit_link_ram:\n"
    "    ext   $t1, $a0, 0, 21\n"
    "    addu  $t1, $s2, $t1\n"
    "    lw    $t2, 0($t1)\n"
    "    sltiu $t0, $t2, 2\n"
    "    bne   $t0, $0, psx_jit_exit\n"
    "    ext   $t3, $t2, 2, 26\n"
    "    lui   $t0, 0x0800\n"
    "    or    $t3, $t3, $t0\n"
    "    addiu $t1, $ra, -8\n"
    "    sw    $t3, 0($t1)\n"
    "    cache 0x15, 0($t1)\n"
    "    cache 0x10, 0($t1)\n"
    "    sync\n"
    "    .word 0x000000c0\n"
    "    jr    $t2\n"
    "    nop\n"
    "psx_jit_exit:\n"
    "    lw    $t1, 0x21C($s0)\n"        /* the budget a helper parked (jit_stop came up) */
    "    sw    $a0, 0x080($s0)\n"
    "    addiu $t0, $a0, 4\n"
    "    sw    $t0, 0x084($s0)\n"
    "    sw    $0,  0x000($s0)\n"
    "    sw    $0,  0x21C($s0)\n"
    "    addu  $s4, $s4, $t1\n"
    "    lw    $v0, 24($sp)\n"
    "    subu  $v0, $v0, $s4\n"
    "    lw    $s0, 28($sp)\n"
    "    lw    $s1, 32($sp)\n"
    "    lw    $s2, 36($sp)\n"
    "    lw    $s3, 40($sp)\n"
    "    lw    $s4, 44($sp)\n"
    "    lw    $s5, 48($sp)\n"
    "    lw    $s6, 52($sp)\n"
    "    lw    $s7, 56($sp)\n"
    "    lw    $fp, 60($sp)\n"
    "    lw    $ra, 64($sp)\n"
    "    jr    $ra\n"
    "    addiu $sp, $sp, 72\n"

    /* Register-cache-preserving GTE NCLIP thunk (preserves $a2,$a3,$t4..$t9 without rc_flush_all!) */
    "psx_jit_nclip:\n"
    "    lh    $t0, 0x0c0($s0)\n"
    "    lh    $t1, 0x0c2($s0)\n"
    "    lh    $t2, 0x0c4($s0)\n"
    "    lh    $t3, 0x0c6($s0)\n"
    "    lh    $a0, 0x0c8($s0)\n"
    "    lh    $a1, 0x0ca($s0)\n"
    "    subu  $t2, $t2, $t0\n"
    "    subu  $a1, $a1, $t1\n"
    "    mult  $t2, $a1\n"
    "    subu  $a0, $t0, $a0\n"
    "    subu  $t3, $t3, $t1\n"
    "    madd  $a0, $t3\n"
    "    mflo  $v0\n"
    "    mfhi  $v1\n"
    "    sra   $t0, $v0, 31\n"
    "    sw    $v0, 0x0f0($s0)\n"
    "    bne   $v1, $t0, 1f\n"
    "    sw    $0,  0x18c($s0)\n"
    "    jr    $ra\n"
    "    nop\n"
    "1:  slt   $t1, $v1, $0\n"
    "    beq   $t1, $0, 2f\n"
    "    lui   $t2, 0x8001\n"
    "    lui   $t2, 0x8000\n"
    "    ori   $t2, $t2, 0x8000\n"
    "2:  jr    $ra\n"
    "    sw    $t2, 0x18c($s0)\n"

    /* Shared L1-resident RAM + Scratchpad ($1F800000..$1F8003FF) memory thunks
       (preserves $a2,$a3,$t4..$t9 across all 98% RAM/SPAD hits AND via psx_jit_call_hlp on 2% MMIO!) */
    "psx_jit_call_hlp:\n"
    "    addiu $sp, $sp, -56\n"
    "    sw    $a2, 16($sp)\n"
    "    sw    $a3, 20($sp)\n"
    "    sw    $t4, 24($sp)\n"
    "    sw    $t5, 28($sp)\n"
    "    sw    $t6, 32($sp)\n"
    "    sw    $t7, 36($sp)\n"
    "    sw    $t8, 40($sp)\n"
    "    sw    $t9, 44($sp)\n"
    "    sw    $ra, 48($sp)\n"
    "    jalr  $t0\n"
    "    nop\n"
    /* the helper raised jit_stop (an IRQ, a write to code): the budget is parked and $s4 zeroed, so the
       block's own exit test leaves -- the blocks do not test jit_stop themselves */
    "    lw    $t0, 0x210($s0)\n"
    "    beq   $t0, $0, 3f\n"
    "    lw    $t1, 0x21C($s0)\n"
    "    addu  $t1, $t1, $s4\n"
    "    sw    $t1, 0x21C($s0)\n"
    "    addu  $s4, $0, $0\n"
    "3:  lw    $a2, 16($sp)\n"
    "    lw    $a3, 20($sp)\n"
    "    lw    $t4, 24($sp)\n"
    "    lw    $t5, 28($sp)\n"
    "    lw    $t6, 32($sp)\n"
    "    lw    $t7, 36($sp)\n"
    "    lw    $t8, 40($sp)\n"
    "    lw    $t9, 44($sp)\n"
    "    lw    $ra, 48($sp)\n"
    "    jr    $ra\n"
    "    addiu $sp, $sp, 56\n"

    "psx_jit_lw:\n"
    "    ori   $t2, $s5, 3\n"
    "    and   $t2, $a0, $t2\n"
    "    bne   $t2, $0, 1f\n"
    "    ext   $t1, $a0, 0, 21\n"
    "    addu  $t0, $s1, $t1\n"
    "    jr    $ra\n"
    "    lw    $v0, 0($t0)\n"
    "1:  ext   $t1, $a0, 0, 31\n"
    "    lui   $t2, 0x1f80\n"
    "    subu  $t2, $t1, $t2\n"
    "    sltiu $t0, $t2, 0x0400\n"
    "    beq   $t0, $0, 2f\n"
    "    andi  $t3, $a0, 3\n"
    "    bne   $t3, $0, 2f\n"
    "    addu  $t0, $s0, $t2\n"
    "    jr    $ra\n"
    "    lw    $v0, 0x220($t0)\n"
    "2:  lui   $t0, %hi(psx_hlp_rd32)\n"
    "    j     psx_jit_call_hlp\n"
    "    addiu $t0, $t0, %lo(psx_hlp_rd32)\n"

    "psx_jit_lh:\n"
    "    ori   $t2, $s5, 1\n"
    "    and   $t2, $a0, $t2\n"
    "    bne   $t2, $0, 1f\n"
    "    ext   $t1, $a0, 0, 21\n"
    "    addu  $t0, $s1, $t1\n"
    "    jr    $ra\n"
    "    lh    $v0, 0($t0)\n"
    "1:  ext   $t1, $a0, 0, 31\n"
    "    lui   $t2, 0x1f80\n"
    "    subu  $t2, $t1, $t2\n"
    "    sltiu $t0, $t2, 0x0400\n"
    "    beq   $t0, $0, 2f\n"
    "    andi  $t3, $a0, 1\n"
    "    bne   $t3, $0, 2f\n"
    "    addu  $t0, $s0, $t2\n"
    "    jr    $ra\n"
    "    lh    $v0, 0x220($t0)\n"
    "2:  lui   $t0, %hi(psx_hlp_rd16s)\n"
    "    j     psx_jit_call_hlp\n"
    "    addiu $t0, $t0, %lo(psx_hlp_rd16s)\n"

    "psx_jit_lhu:\n"
    "    ori   $t2, $s5, 1\n"
    "    and   $t2, $a0, $t2\n"
    "    bne   $t2, $0, 1f\n"
    "    ext   $t1, $a0, 0, 21\n"
    "    addu  $t0, $s1, $t1\n"
    "    jr    $ra\n"
    "    lhu   $v0, 0($t0)\n"
    "1:  ext   $t1, $a0, 0, 31\n"
    "    lui   $t2, 0x1f80\n"
    "    subu  $t2, $t1, $t2\n"
    "    sltiu $t0, $t2, 0x0400\n"
    "    beq   $t0, $0, 2f\n"
    "    andi  $t3, $a0, 1\n"
    "    bne   $t3, $0, 2f\n"
    "    addu  $t0, $s0, $t2\n"
    "    jr    $ra\n"
    "    lhu   $v0, 0x220($t0)\n"
    "2:  lui   $t0, %hi(psx_hlp_rd16u)\n"
    "    j     psx_jit_call_hlp\n"
    "    addiu $t0, $t0, %lo(psx_hlp_rd16u)\n"

    "psx_jit_lb:\n"
    "    and   $t2, $a0, $s5\n"
    "    bne   $t2, $0, 1f\n"
    "    ext   $t1, $a0, 0, 21\n"
    "    addu  $t0, $s1, $t1\n"
    "    jr    $ra\n"
    "    lb    $v0, 0($t0)\n"
    "1:  ext   $t1, $a0, 0, 31\n"
    "    lui   $t2, 0x1f80\n"
    "    subu  $t2, $t1, $t2\n"
    "    sltiu $t0, $t2, 0x0400\n"
    "    beq   $t0, $0, 2f\n"
    "    addu  $t0, $s0, $t2\n"
    "    jr    $ra\n"
    "    lb    $v0, 0x220($t0)\n"
    "2:  lui   $t0, %hi(psx_hlp_rd8s)\n"
    "    j     psx_jit_call_hlp\n"
    "    addiu $t0, $t0, %lo(psx_hlp_rd8s)\n"

    "psx_jit_lbu:\n"
    "    and   $t2, $a0, $s5\n"
    "    bne   $t2, $0, 1f\n"
    "    ext   $t1, $a0, 0, 21\n"
    "    addu  $t0, $s1, $t1\n"
    "    jr    $ra\n"
    "    lbu   $v0, 0($t0)\n"
    "1:  ext   $t1, $a0, 0, 31\n"
    "    lui   $t2, 0x1f80\n"
    "    subu  $t2, $t1, $t2\n"
    "    sltiu $t0, $t2, 0x0400\n"
    "    beq   $t0, $0, 2f\n"
    "    addu  $t0, $s0, $t2\n"
    "    jr    $ra\n"
    "    lbu   $v0, 0x220($t0)\n"
    "2:  lui   $t0, %hi(psx_hlp_rd8u)\n"
    "    j     psx_jit_call_hlp\n"
    "    addiu $t0, $t0, %lo(psx_hlp_rd8u)\n"

    "psx_jit_sw:\n"
    "    ori   $t2, $s5, 3\n"
    "    and   $t2, $a0, $t2\n"
    "    bne   $t2, $0, 1f\n"
    "    ext   $t1, $a0, 0, 21\n"
    "    srl   $t0, $t1, 6\n"
    "    addu  $t0, $s3, $t0\n"
    "    lbu   $t3, 0($t0)\n"
    "    addu  $t2, $s1, $t1\n"
    "    bne   $t3, $0, 2f\n"
    "    nop\n"
    "    jr    $ra\n"
    "    sw    $a1, 0($t2)\n"
    "1:  ext   $t1, $a0, 0, 31\n"
    "    lui   $t2, 0x1f80\n"
    "    subu  $t2, $t1, $t2\n"
    "    sltiu $t0, $t2, 0x0400\n"
    "    beq   $t0, $0, 2f\n"
    "    andi  $t3, $a0, 3\n"
    "    bne   $t3, $0, 2f\n"
    "    addu  $t0, $s0, $t2\n"
    "    jr    $ra\n"
    "    sw    $a1, 0x220($t0)\n"
    "2:  lui   $t0, %hi(psx_hlp_wr32)\n"
    "    j     psx_jit_call_hlp\n"
    "    addiu $t0, $t0, %lo(psx_hlp_wr32)\n"

    "psx_jit_sh:\n"
    "    ori   $t2, $s5, 1\n"
    "    and   $t2, $a0, $t2\n"
    "    bne   $t2, $0, 1f\n"
    "    ext   $t1, $a0, 0, 21\n"
    "    srl   $t0, $t1, 6\n"
    "    addu  $t0, $s3, $t0\n"
    "    lbu   $t3, 0($t0)\n"
    "    addu  $t2, $s1, $t1\n"
    "    bne   $t3, $0, 2f\n"
    "    nop\n"
    "    jr    $ra\n"
    "    sh    $a1, 0($t2)\n"
    "1:  ext   $t1, $a0, 0, 31\n"
    "    lui   $t2, 0x1f80\n"
    "    subu  $t2, $t1, $t2\n"
    "    sltiu $t0, $t2, 0x0400\n"
    "    beq   $t0, $0, 2f\n"
    "    andi  $t3, $a0, 1\n"
    "    bne   $t3, $0, 2f\n"
    "    addu  $t0, $s0, $t2\n"
    "    jr    $ra\n"
    "    sh    $a1, 0x220($t0)\n"
    "2:  lui   $t0, %hi(psx_hlp_wr16)\n"
    "    j     psx_jit_call_hlp\n"
    "    addiu $t0, $t0, %lo(psx_hlp_wr16)\n"

    "psx_jit_sb:\n"
    "    and   $t2, $a0, $s5\n"
    "    bne   $t2, $0, 1f\n"
    "    ext   $t1, $a0, 0, 21\n"
    "    srl   $t0, $t1, 6\n"
    "    addu  $t0, $s3, $t0\n"
    "    lbu   $t3, 0($t0)\n"
    "    addu  $t2, $s1, $t1\n"
    "    bne   $t3, $0, 2f\n"
    "    nop\n"
    "    jr    $ra\n"
    "    sb    $a1, 0($t2)\n"
    "1:  ext   $t1, $a0, 0, 31\n"
    "    lui   $t2, 0x1f80\n"
    "    subu  $t2, $t1, $t2\n"
    "    sltiu $t0, $t2, 0x0400\n"
    "    beq   $t0, $0, 2f\n"
    "    addu  $t0, $s0, $t2\n"
    "    jr    $ra\n"
    "    sb    $a1, 0x220($t0)\n"
    "2:  lui   $t0, %hi(psx_hlp_wr8)\n"
    "    j     psx_jit_call_hlp\n"
    "    addiu $t0, $t0, %lo(psx_hlp_wr8)\n"

    "psx_jit_lwl:\n"
    "    and   $t2, $a0, $s5\n"
    "    bne   $t2, $0, 2f\n"
    "    ext   $t1, $a0, 0, 21\n"
    "    addiu $t3, $t1, 4\n"
    "    srl   $t3, $t3, 21\n"
    "    bne   $t3, $0, 2f\n"
    "    addu  $t0, $s1, $t1\n"
    "    addu  $v0, $a1, $0\n"
    "    jr    $ra\n"
    "    lwl   $v0, 0($t0)\n"
    "2:  lui   $t0, %hi(psx_hlp_lwl)\n"
    "    j     psx_jit_call_hlp\n"
    "    addiu $t0, $t0, %lo(psx_hlp_lwl)\n"

    "psx_jit_lwr:\n"
    "    and   $t2, $a0, $s5\n"
    "    bne   $t2, $0, 2f\n"
    "    ext   $t1, $a0, 0, 21\n"
    "    addiu $t3, $t1, 4\n"
    "    srl   $t3, $t3, 21\n"
    "    bne   $t3, $0, 2f\n"
    "    addu  $t0, $s1, $t1\n"
    "    addu  $v0, $a1, $0\n"
    "    jr    $ra\n"
    "    lwr   $v0, 0($t0)\n"
    "2:  lui   $t0, %hi(psx_hlp_lwr)\n"
    "    j     psx_jit_call_hlp\n"
    "    addiu $t0, $t0, %lo(psx_hlp_lwr)\n"

    "psx_jit_swl:\n"
    "    and   $t2, $a0, $s5\n"
    "    bne   $t2, $0, 2f\n"
    "    ext   $t1, $a0, 0, 21\n"
    "    addiu $t3, $t1, 4\n"
    "    srl   $t3, $t3, 21\n"
    "    bne   $t3, $0, 2f\n"
    "    srl   $t0, $t1, 6\n"
    "    addu  $t0, $s3, $t0\n"
    "    lbu   $t3, 0($t0)\n"
    "    addu  $t2, $s1, $t1\n"
    "    bne   $t3, $0, 2f\n"
    "    nop\n"
    "    jr    $ra\n"
    "    swl   $a1, 0($t2)\n"
    "2:  lui   $t0, %hi(psx_hlp_swl)\n"
    "    j     psx_jit_call_hlp\n"
    "    addiu $t0, $t0, %lo(psx_hlp_swl)\n"

    "psx_jit_swr:\n"
    "    and   $t2, $a0, $s5\n"
    "    bne   $t2, $0, 2f\n"
    "    ext   $t1, $a0, 0, 21\n"
    "    addiu $t3, $t1, 4\n"
    "    srl   $t3, $t3, 21\n"
    "    bne   $t3, $0, 2f\n"
    "    srl   $t0, $t1, 6\n"
    "    addu  $t0, $s3, $t0\n"
    "    lbu   $t3, 0($t0)\n"
    "    addu  $t2, $s1, $t1\n"
    "    bne   $t3, $0, 2f\n"
    "    nop\n"
    "    jr    $ra\n"
    "    swr   $a1, 0($t2)\n"
    "2:  lui   $t0, %hi(psx_hlp_swr)\n"
    "    j     psx_jit_call_hlp\n"
    "    addiu $t0, $t0, %lo(psx_hlp_swr)\n"
    ".set pop\n"
);

static void jit_hlp_div(s32 a, s32 b)
{
    if (b == 0) {
        S.lo = (a >= 0) ? 0xFFFFFFFFu : 1u;
        S.hi = (u32)a;
    } else if ((u32)a == 0x80000000u && b == -1) {
        S.lo = 0x80000000u;
        S.hi = 0u;
    } else {
        S.lo = (u32)(a / b);
        S.hi = (u32)(a % b);
    }
}

static void jit_hlp_divu(u32 a, u32 b)
{
    if (b == 0u) {
        S.lo = 0xFFFFFFFFu;
        S.hi = a;
    } else {
        S.lo = a / b;
        S.hi = a % b;
    }
}

static void jit_hlp_lwc2(u32 ea, u32 rt)
{
    gte_write_data(rt, bus_read32(ea));
}

static void jit_hlp_swc2(u32 ea, u32 rt)
{
    bus_write32(ea, gte_read_data(rt));
}

#define J_R(op, rs, rt, rd, sh, fn) (((u32)(op) << 26) | ((u32)(rs) << 21) | ((u32)(rt) << 16) | ((u32)(rd) << 11) | ((u32)(sh) << 6) | (u32)(fn))
#define J_I(op, rs, rt, imm)        (((u32)(op) << 26) | ((u32)(rs) << 21) | ((u32)(rt) << 16) | ((u32)(imm) & 0xFFFFu))
#define J_J(op, fn_addr)            (((u32)(op) << 26) | (((u32)(__UINTPTR_TYPE__)(fn_addr) >> 2) & 0x03FFFFFFu))

/* 8-slot persistent intra-block register cache in host $a2,$a3,$t4..$t7,$t8,$t9 (preserved across all RAM/SPAD/MMIO thunks!) */
static const u8 rc_hreg[8] = { 6u, 7u, 12u, 13u, 14u, 15u, 24u, 25u };

struct jit_rc {
    u8 greg[8];
    u8 dirty[8];
    u8 clock;
};

static inline void rc_init(struct jit_rc *rc)
{
    for (int i = 0; i < 8; i++) { rc->greg[i] = 0u; rc->dirty[i] = 0u; }
    rc->clock = 0u;
}

static inline void rc_flush_all(u32 **pp, struct jit_rc *rc)
{
    for (int i = 0; i < 8; i++) {
        if (rc->greg[i] && rc->dirty[i])
            *(*pp)++ = J_I(0x2Bu, 16u, rc_hreg[i], (u32)rc->greg[i] * 4u);
        rc->greg[i] = 0u;
        rc->dirty[i] = 0u;
    }
}

static u32 __attribute__((noinline, optimize("Os"))) rc_pick_slot(u32 **pp, struct jit_rc *rc, u32 forbid1, u32 forbid2)
{
    for (int i = 0; i < 8; i++)
        if (rc->greg[i] == 0u && rc_hreg[i] != forbid1 && rc_hreg[i] != forbid2)
            return (u32)i;
    for (int tries = 0; tries < 16; tries++) {
        u32 s = rc->clock;
        rc->clock = (u8)((s + 1u == 8u) ? 0u : (s + 1u));
        u32 hr = rc_hreg[s];
        if (hr != forbid1 && hr != forbid2) {
            if (rc->greg[s] && rc->dirty[s])
                *(*pp)++ = J_I(0x2Bu, 16u, hr, (u32)rc->greg[s] * 4u);
            rc->greg[s] = 0u;
            rc->dirty[s] = 0u;
            return s;
        }
    }
    return 0u;
}

static u32 rc_read(u32 **pp, struct jit_rc *rc, u32 greg, u32 forbid1)
{
    if (greg == 0u)
        return 0u;
    for (int i = 0; i < 8; i++)
        if (rc->greg[i] == greg)
            return rc_hreg[i];
    u32 s = rc_pick_slot(pp, rc, forbid1, 0xFFu);
    u32 hr = rc_hreg[s];
    *(*pp)++ = J_I(0x23u, 16u, hr, greg * 4u);
    rc->greg[s] = (u8)greg;
    rc->dirty[s] = 0u;
    return hr;
}

static u32 rc_write(u32 **pp, struct jit_rc *rc, u32 greg, u32 forbid1, u32 forbid2)
{
    for (int i = 0; i < 8; i++) {
        if (rc->greg[i] == greg) {
            rc->dirty[i] = 1u;
            return rc_hreg[i];
        }
    }
    u32 s = rc_pick_slot(pp, rc, forbid1, forbid2);
    rc->greg[s] = (u8)greg;
    rc->dirty[s] = 1u;
    return rc_hreg[s];
}

static inline void rc_load_into_hreg(u32 **pp, struct jit_rc *rc, u32 hreg, u32 greg)
{
    if (greg == 0u) {
        *(*pp)++ = J_R(0, 0u, 0u, hreg, 0u, 0x21u);
        return;
    }
    for (int i = 0; i < 8; i++) {
        if (rc->greg[i] == greg) {
            *(*pp)++ = J_R(0, rc_hreg[i], 0u, hreg, 0u, 0x21u);
            return;
        }
    }
    *(*pp)++ = J_I(0x23u, 16u, hreg, greg * 4u);
}

static inline void j_emit_store_gpr(u32 **pp, u32 hreg, u32 greg)
{
    if (greg != 0u)
        *(*pp)++ = J_I(0x2Bu, 16u, hreg, greg * 4u);
}

static inline void j_emit_li32(u32 **pp, u32 hreg, u32 val)
{
    if ((val & 0xFFFF0000u) == 0u) {
        *(*pp)++ = J_I(0x0Du, 0u, hreg, val);
    } else if ((val & 0xFFFF8000u) == 0xFFFF8000u) {
        *(*pp)++ = J_I(0x09u, 0u, hreg, val);
    } else {
        *(*pp)++ = J_I(0x0Fu, 0u, hreg, val >> 16);
        if (val & 0xFFFFu)
            *(*pp)++ = J_I(0x0Du, hreg, hreg, val);
    }
}

static int jit_insn_reads_gpr(u32 op, u32 reg)
{
    if (reg == 0u) return 0;
    u32 opc = op >> 26, rs = (op >> 21) & 31u, rt = (op >> 16) & 31u;
    switch (opc) {
    case 0x00u: {
        u32 fn = op & 0x3Fu;
        if (fn == 0x00u || fn == 0x02u || fn == 0x03u) return rt == reg;
        if (fn == 0x10u || fn == 0x12u) return 0;
        if (fn == 0x08u || fn == 0x09u || fn == 0x11u || fn == 0x13u) return rs == reg;
        return rs == reg || rt == reg;
    }
    case 0x02u: case 0x03u: case 0x0Fu:
        return 0;
    case 0x01u: case 0x06u: case 0x07u:
    case 0x08u: case 0x09u: case 0x0Au: case 0x0Bu: case 0x0Cu: case 0x0Du: case 0x0Eu:
    case 0x20u: case 0x21u: case 0x23u: case 0x24u: case 0x25u: case 0x32u:
        return rs == reg;
    case 0x10u: case 0x12u:
        if (op & (1u << 25)) return 0;
        return (rs == 0x04u || rs == 0x06u) ? (rt == reg) : 0;
    default:
        return rs == reg || rt == reg;
    }
}

static int jit_insn_writes_gpr(u32 op, u32 reg)
{
    if (reg == 0u) return 0;
    u32 opc = op >> 26, rs = (op >> 21) & 31u, rt = (op >> 16) & 31u, rd = (op >> 11) & 31u;
    switch (opc) {
    case 0x00u: {
        u32 fn = op & 0x3Fu;
        if (fn == 0x08u || fn == 0x0Cu || fn == 0x0Du || (fn >= 0x11u && fn <= 0x1Bu && fn != 0x12u))
            return 0;
        return rd == reg;
    }
    case 0x01u:
        return ((rt & 0x1Eu) == 0x10u) && (reg == 31u);
    case 0x03u:
        return reg == 31u;
    case 0x08u: case 0x09u: case 0x0Au: case 0x0Bu: case 0x0Cu: case 0x0Du: case 0x0Eu: case 0x0Fu:
    case 0x20u: case 0x21u: case 0x22u: case 0x23u: case 0x24u: case 0x25u: case 0x26u:
        return rt == reg;
    case 0x10u: case 0x12u:
        if (op & (1u << 25)) return 0;
        return (rs == 0x00u || rs == 0x02u) && (rt == reg);
    default:
        return 0;
    }
}

/* Classify non-branch instructions: 0=unsupported, 1=plain inline, 2=load with 1-insn delay on `rt` */
static int jit_classify_nonbranch(u32 op, u32 *load_rt_out)
{
    u32 opc = op >> 26, rs = (op >> 21) & 31u, rt = (op >> 16) & 31u;
    *load_rt_out = 0u;
    switch (opc) {
    case 0x00u: {
        u32 fn = op & 0x3Fu;
        switch (fn) {
        case 0x00u: case 0x02u: case 0x03u:
        case 0x04u: case 0x06u: case 0x07u:
        case 0x10u: case 0x11u: case 0x12u: case 0x13u:
        case 0x18u: case 0x19u: case 0x1Au: case 0x1Bu:
        case 0x20u: case 0x21u: case 0x22u: case 0x23u:
        case 0x24u: case 0x25u: case 0x26u: case 0x27u:
        case 0x2Au: case 0x2Bu:
            return 1;
        default:
            return 0;
        }
    }
    case 0x08u: case 0x09u: case 0x0Au: case 0x0Bu: case 0x0Cu: case 0x0Du: case 0x0Eu: case 0x0Fu:
    case 0x28u: case 0x29u: case 0x2Au: case 0x2Bu: case 0x2Eu:
    case 0x32u: case 0x3Au:
        return 1;
    case 0x20u: case 0x21u: case 0x22u: case 0x23u: case 0x24u: case 0x25u: case 0x26u:
        *load_rt_out = rt;
        return rt ? 2 : 1;
    case 0x12u:
        if (op & (1u << 25)) return 1;
        if (rs == 0x04u || rs == 0x06u) return 1;
        if (rs == 0x00u || rs == 0x02u) { *load_rt_out = rt; return rt ? 2 : 1; }
        return 0;
    default:
        return 0;
    }
}

static int jit_is_branch(u32 op)
{
    u32 opc = op >> 26;
    if (opc >= 0x01u && opc <= 0x07u) return 1;
    if (opc == 0x00u) {
        u32 fn = op & 0x3Fu;
        if (fn == 0x08u || fn == 0x09u) return 1;
    }
    return 0;
}

static inline void j_emit_call_hlp(u32 **pp, void *fn)
{
    u32 addr = (u32)(__UINTPTR_TYPE__)fn;
    *(*pp)++ = J_I(0x0Fu, 0u, 8u, addr >> 16);
    *(*pp)++ = J_J(0x03u, (void *)psx_jit_call_hlp);
    *(*pp)++ = J_I(0x0Du, 8u, 8u, addr);
}

static void jit_emit_gte_read_to_hreg(u32 **pp, struct jit_rc *rc, u32 hreg, int is_ctrl, u32 rd)
{
    (void)rc;
    rd &= 31u;
    if (is_ctrl) {
        u32 l_op = (rd == 4u || rd == 12u || rd == 20u || rd == 26u || rd == 27u || rd == 29u || rd == 30u) ? 0x21u : 0x23u;
        *(*pp)++ = J_I(l_op, 16u, hreg, 0x110u + rd * 4u);
        return;
    }
    if (rd == 28u || rd == 29u) {
        j_emit_li32(pp, 4u, rd);
        j_emit_call_hlp(pp, (void *)gte_read_data);
        if (hreg != 2u)
            *(*pp)++ = J_R(0, 2u, 0u, hreg, 0u, 0x21u);
        return;
    }
    u32 eff_rd = (rd == 15u) ? 14u : rd;
    u32 l_op = (rd == 1u || rd == 3u || rd == 5u || (rd >= 8u && rd <= 11u)) ? 0x21u /* lh */
             : (rd == 7u || (rd >= 16u && rd <= 19u)) ? 0x25u                        /* lhu */
             : 0x23u;                                                                /* lw */
    *(*pp)++ = J_I(l_op, 16u, hreg, 0x090u + eff_rd * 4u);
}

static void __attribute__((noinline, optimize("Os"))) jit_emit_load_into_v0(u32 **pp, struct jit_rc *rc, u32 op)
{
    u32 opc = op >> 26, rs = (op >> 21) & 31u, rt = (op >> 16) & 31u, rd = (op >> 11) & 31u, imm = op & 0xFFFFu;
    if (opc == 0x12u) {
        jit_emit_gte_read_to_hreg(pp, rc, 2u, rs == 0x02u, rd);
        return;
    }
    if (opc == 0x22u || opc == 0x26u) {
        u32 rsh = rc_read(pp, rc, rs, 0xFFu);
        rc_load_into_hreg(pp, rc, 5u, rt);
        *(*pp)++ = J_J(0x03u, (opc == 0x22u) ? (void *)psx_jit_lwl : (void *)psx_jit_lwr);
        *(*pp)++ = J_I(0x09u, rsh, 4u, imm);
        return;
    }
    void *thunk = (opc == 0x23u) ? (void *)psx_jit_lw
                : (opc == 0x25u) ? (void *)psx_jit_lhu
                : (opc == 0x21u) ? (void *)psx_jit_lh
                : (opc == 0x24u) ? (void *)psx_jit_lbu : (void *)psx_jit_lb;
    u32 rsh = rc_read(pp, rc, rs, 0xFFu);
    *(*pp)++ = J_J(0x03u, thunk);
    *(*pp)++ = J_I(0x09u, rsh, 4u, imm);
}

static void __attribute__((noinline, optimize("Os"))) jit_emit_nonbranch(u32 **pp, struct jit_rc *rc, u32 op, int *extra_cost)
{
    if (op == 0u) return;
    u32 opc = op >> 26, rs = (op >> 21) & 31u, rt = (op >> 16) & 31u;
    u32 rd = (op >> 11) & 31u, sh = (op >> 6) & 31u, fn = op & 0x3Fu, imm = op & 0xFFFFu;

    if (opc == 0x00u) {
        switch (fn) {
        case 0x00u: case 0x02u: case 0x03u:
            if (rd) {
                u32 rth = rc_read(pp, rc, rt, 0xFFu);
                u32 rdh = rc_write(pp, rc, rd, rth, 0xFFu);
                *(*pp)++ = J_R(0, 0u, rth, rdh, sh, fn);
            }
            return;
        case 0x04u: case 0x06u: case 0x07u:
            if (rd) {
                u32 rsh = rc_read(pp, rc, rs, 0xFFu);
                u32 rth = rc_read(pp, rc, rt, rsh);
                u32 rdh = rc_write(pp, rc, rd, rsh, rth);
                *(*pp)++ = J_R(0, rsh, rth, rdh, 0u, fn);
            }
            return;
        case 0x10u: case 0x12u:
            if (rd) {
                u32 rdh = rc_write(pp, rc, rd, 0xFFu, 0xFFu);
                *(*pp)++ = J_I(0x23u, 16u, rdh, (fn == 0x10u) ? 0x088u : 0x08Cu);
            }
            return;
        case 0x11u: case 0x13u: {
            u32 rsh = rc_read(pp, rc, rs, 0xFFu);
            *(*pp)++ = J_I(0x2Bu, 16u, rsh, (fn == 0x11u) ? 0x088u : 0x08Cu);
            return;
        }
        case 0x18u: case 0x19u: {
            u32 rsh = rc_read(pp, rc, rs, 0xFFu);
            u32 rth = rc_read(pp, rc, rt, rsh);
            *(*pp)++ = J_R(0, rsh, rth, 0u, 0u, fn);
            *(*pp)++ = J_R(0, 0u, 0u, 10u, 0u, 0x12u);
            *(*pp)++ = J_R(0, 0u, 0u, 11u, 0u, 0x10u);
            *(*pp)++ = J_I(0x2Bu, 16u, 10u, 0x08Cu);
            *(*pp)++ = J_I(0x2Bu, 16u, 11u, 0x088u);
            return;
        }
        case 0x1Au: case 0x1Bu:
            rc_load_into_hreg(pp, rc, 4u, rs);
            rc_load_into_hreg(pp, rc, 5u, rt);
            j_emit_call_hlp(pp, (fn == 0x1Au) ? (void *)jit_hlp_div : (void *)jit_hlp_divu);
            return;
        default: { /* ADD/ADDU, SUB/SUBU, AND, OR, XOR, NOR, SLT, SLTU */
            if (!rd) return;
            u32 hfn = (fn == 0x20u) ? 0x21u : (fn == 0x22u) ? 0x23u : fn;
            u32 rsh = rc_read(pp, rc, rs, 0xFFu);
            u32 rth = rc_read(pp, rc, rt, rsh);
            u32 rdh = rc_write(pp, rc, rd, rsh, rth);
            *(*pp)++ = J_R(0, rsh, rth, rdh, 0u, hfn);
            return;
        }
        }
    }

    if (opc >= 0x08u && opc <= 0x0Fu) {
        if (!rt) return;
        u32 hopc = (opc == 0x08u) ? 0x09u : opc;
        if (hopc == 0x0Fu) {
            u32 rth = rc_write(pp, rc, rt, 0xFFu, 0xFFu);
            *(*pp)++ = J_I(0x0Fu, 0u, rth, imm);
        } else {
            u32 rsh = rc_read(pp, rc, rs, 0xFFu);
            u32 rth = rc_write(pp, rc, rt, rsh, 0xFFu);
            *(*pp)++ = J_I(hopc, rsh, rth, imm);
        }
        return;
    }

    if (opc == 0x12u) { /* COP2: GTE */
        if (op & (1u << 25)) {
            u32 gop = op & 0x3Fu;
            if (gop == 0x06u) {
                /* psx_jit_nclip preserves all 8 register-cache slots ($a2,$a3,$t4..$t9)! */
                *(*pp)++ = J_J(0x03u, (void *)psx_jit_nclip);
                *(*pp)++ = 0u;
                *extra_cost += 2;
                return;
            }
            if (gop == 0x2Du) {
                j_emit_call_hlp(pp, (void *)gte_op_avsz3);
            } else if (gop == 0x2Eu) {
                j_emit_call_hlp(pp, (void *)gte_op_avsz4);
            } else {
                void *gfn = (gop == 0x01u) ? (void *)gte_op_rtps
                          : (gop == 0x30u) ? (void *)gte_op_rtpt
                          : (gop == 0x12u) ? (void *)gte_op_mvmva
                          : (gop == 0x3Du) ? (void *)gte_op_gpf
                          : (void *)gte_exec;
                j_emit_li32(pp, 4u, op);
                j_emit_call_hlp(pp, gfn);
            }
            *extra_cost += (gop == 0x30u) ? 6 : (gop == 0x16u || gop == 0x3Fu || gop == 0x20u) ? 10 : 2;
        } else if (rs == 0x00u || rs == 0x02u) { /* MFC2 / CFC2 */
            if (rt) {
                u32 rth = rc_write(pp, rc, rt, 0xFFu, 0xFFu);
                jit_emit_gte_read_to_hreg(pp, rc, rth, rs == 0x02u, rd);
            }
        } else if (rs == 0x04u) { /* MTC2 */
            if (rd == 29u || rd == 31u) return;
            if (rd != 15u && rd != 28u && rd != 30u) {
                u32 rth = rc_read(pp, rc, rt, 0xFFu);
                *(*pp)++ = J_I(0x2Bu, 16u, rth, 0x090u + rd * 4u);
            } else {
                rc_load_into_hreg(pp, rc, 5u, rt);
                j_emit_li32(pp, 4u, rd);
                j_emit_call_hlp(pp, (void *)gte_write_data);
            }
        } else if (rs == 0x06u) { /* CTC2 */
            if (!(rd < 21u && (rd & 7u) <= 4u) && rd != 31u) {
                u32 rth = rc_read(pp, rc, rt, 0xFFu);
                *(*pp)++ = J_I(0x2Bu, 16u, rth, 0x110u + rd * 4u);
            } else {
                rc_load_into_hreg(pp, rc, 5u, rt);
                j_emit_li32(pp, 4u, rd);
                j_emit_call_hlp(pp, (void *)gte_write_ctrl);
            }
        }
        return;
    }

    if (opc == 0x32u) { /* LWC2 */
        if (rt != 15u && rt != 28u && rt != 29u && rt != 30u && rt != 31u) {
            u32 rsh = rc_read(pp, rc, rs, 0xFFu);
            *(*pp)++ = J_J(0x03u, (void *)psx_jit_lw);
            *(*pp)++ = J_I(0x09u, rsh, 4u, imm);
            *(*pp)++ = J_I(0x2Bu, 16u, 2u, 0x090u + rt * 4u);
        } else {
            rc_load_into_hreg(pp, rc, 4u, rs);
            if (imm) *(*pp)++ = J_I(0x09u, 4u, 4u, imm);
            j_emit_li32(pp, 5u, rt);
            j_emit_call_hlp(pp, (void *)jit_hlp_lwc2);
        }
        return;
    }

    if (opc == 0x3Au) { /* SWC2 */
        if (rt != 28u && rt != 29u) {
            u32 rsh = rc_read(pp, rc, rs, 0xFFu);
            jit_emit_gte_read_to_hreg(pp, rc, 5u, 0, rt);
            *(*pp)++ = J_J(0x03u, (void *)psx_jit_sw);
            *(*pp)++ = J_I(0x09u, rsh, 4u, imm);
        } else {
            rc_load_into_hreg(pp, rc, 4u, rs);
            if (imm) *(*pp)++ = J_I(0x09u, 4u, 4u, imm);
            j_emit_li32(pp, 5u, rt);
            j_emit_call_hlp(pp, (void *)jit_hlp_swc2);
        }
        return;
    }

    /* Loads: LB(0x20), LH(0x21), LWL(0x22), LW(0x23), LBU(0x24), LHU(0x25), LWR(0x26) */
    if (opc == 0x20u || opc == 0x21u || opc == 0x23u || opc == 0x24u || opc == 0x25u) {
        void *thunk = (opc == 0x23u) ? (void *)psx_jit_lw
                    : (opc == 0x25u) ? (void *)psx_jit_lhu
                    : (opc == 0x21u) ? (void *)psx_jit_lh
                    : (opc == 0x24u) ? (void *)psx_jit_lbu : (void *)psx_jit_lb;
        /* (a call of the shared thunk, 3 words: in line it was 11 and the 16 KB I-cache made that slower) */
        u32 rsh = rc_read(pp, rc, rs, 0xFFu);
        *(*pp)++ = J_J(0x03u, thunk);
        *(*pp)++ = J_I(0x09u, rsh, 4u, imm);
        if (rt) {
            u32 rth = rc_write(pp, rc, rt, 0xFFu, 0xFFu);
            *(*pp)++ = J_R(0, 2u, 0u, rth, 0u, 0x21u);
        }
        return;
    }
    if (opc >= 0x20u && opc <= 0x26u) {                 /* LWL / LWR */
        jit_emit_load_into_v0(pp, rc, op);
        if (rt) {
            u32 rth = rc_write(pp, rc, rt, 0xFFu, 0xFFu);
            *(*pp)++ = J_R(0, 2u, 0u, rth, 0u, 0x21u);
        }
        return;
    }

    /* Stores: SB(0x28), SH(0x29), SWL(0x2A), SW(0x2B), SWR(0x2E) */
    if (opc == 0x28u || opc == 0x29u || opc == 0x2Au || opc == 0x2Bu || opc == 0x2Eu) {
        void *thunk = (opc == 0x2Bu) ? (void *)psx_jit_sw
                    : (opc == 0x29u) ? (void *)psx_jit_sh
                    : (opc == 0x28u) ? (void *)psx_jit_sb
                    : (opc == 0x2Au) ? (void *)psx_jit_swl : (void *)psx_jit_swr;
        u32 rsh = rc_read(pp, rc, rs, 0xFFu);
        rc_load_into_hreg(pp, rc, 5u, rt);
        *(*pp)++ = J_J(0x03u, thunk);
        *(*pp)++ = J_I(0x09u, rsh, 4u, imm);
        return;
    }
}

static int jit_target_safe_after_load(u32 target_pc, u32 load_rt)
{
    if ((target_pc - 0x80001000u) >= 0x001FF000u || (target_pc & 3u))
        return 0;
    u32 op0 = *(const u32 *)(W.ram + (target_pc & 0x1FFFFCu));
    if (jit_insn_reads_gpr(op0, load_rt))
        return 0;
    if (!jit_insn_writes_gpr(op0, load_rt))
        return 1;
    u32 dm = 0u;
    return jit_classify_nonbranch(op0, &dm) == 1;
}

/* a jump to another block (in RAM), its delay slot `delay` (0: nop): compiled already -> "j code" (2 words),
   else "jal psx_jit_link_ram2; delay; .word target_pc" (3 words; the jal becomes a j once the target is compiled) */
static void jit_emit_exit_to(u32 **pp, u32 target_pc, u32 known_code, int cost_delta)
{
    u32 *p = *pp;
    u32 delay = cost_delta ? J_I(0x09u, 20u, 20u, cost_delta) : 0u;   /* addiu $s4, $s4, cost_delta */
    if (known_code >= 2u) {
        *p++ = J_J(0x02u, known_code);
        *p++ = delay;
    } else {
        *p++ = J_J(0x03u, (void *)psx_jit_link_ram2);
        *p++ = delay;
        *p++ = target_pc;
    }
    *pp = p;
}

static void __attribute__((noinline, optimize("Os"))) jit_emit_direct_jump_ram(u32 **pp, u32 target_pc, u32 known_code, int cost)
{
    u32 *p = *pp;
    S.jit_linked = 1u;
    /* the target's prologue tests the budget (and $s4 zeroed by a helper that raised jit_stop) */
    jit_emit_exit_to(&p, target_pc, known_code, -cost);
    *pp = p;
}

/* psx_frame's Pattern 7 / Pattern 8 VBlank waits: left to the interpreter, which fast-forwards them (never
   recompiled) */
static int jit_wait_loop_at(u32 off)
{
    if (off + 68u > PSX_RAM_SIZE)
        return 0;
    const u32 *rp0 = (const u32 *)(W.ram + off);
    if ((rp0[0] >> 26) == 0x03u && rp0[1] == 0u && (rp0[15] & 0xFC1FFFFFu) == 0x1000FFF0u)
        return 1;
    return off + 96u <= PSX_RAM_SIZE &&
           rp0[0] == 0x8FA20010u && rp0[2] == 0x2442FFFFu && rp0[3] == 0xAFA20010u &&
           rp0[6] == 0x1443000Bu && rp0[22] == 0x1440FFE9u;
}

static u32 __attribute__((noinline, optimize("Os"))) jit_compile_block(u32 start_pc)
{
    if (S.jit_used + JIT_BLOCK_MAX > JIT_BUF_WORDS) {
        st_reset_full++;
        jit_reset_all();
    }
    st_compiles++;

    u32 start_off = start_pc & 0x1FFFFCu;
    /* Leave Namco/PsyQ VBlank wait loops uncompiled so Pattern 7 / Pattern 8 fast-forwards immediately */
    if (jit_wait_loop_at(start_off)) {
        W.jit_entry[start_off >> 2] = 1u;
        return 1u;
    }

    u32 *block_start = &W.jit_buf[S.jit_used];
    u32 *p = block_start;
    /* the prologue: the budget (blocks run on while $s4 > 0; a helper that raised jit_stop zeroed it) */
    *p++ = J_I(0x07u, 20u, 0u, 3);                      /* bgtz  $s4, body */
    *p++ = J_I(0x0Fu, 0u, 4u, start_pc >> 16);          /* [delay] lui $a0, hi(start_pc) */
    *p++ = J_J(0x02u, (void *)psx_jit_exit);            /* j     psx_jit_exit */
    *p++ = J_I(0x0Du, 4u, 4u, start_pc);                /* [delay] ori $a0, $a0, lo(start_pc) */
    struct jit_rc rc;
    rc_init(&rc);
    int cost = 0;
    u32 k = 0;
    u32 last_off = start_off;
    int ended_by_branch = 0;

    while (k < JIT_MAX_INSNS) {
        u32 cur_pc  = start_pc + k * 4u;
        u32 cur_off = cur_pc & 0x1FFFFCu;
        if (cur_off < 0x1000u || cur_off > 0x1FFFF4u)
            break;
        u32 op = *(const u32 *)(W.ram + cur_off);

        if (jit_is_branch(op)) {
            u32 delay_op = *(const u32 *)(W.ram + cur_off + 4u);
            u32 delay_rt = 0u;
            int dcls = jit_classify_nonbranch(delay_op, &delay_rt);
            if (dcls == 0)
                break;

            u32 opc = op >> 26, rs = (op >> 21) & 31u, rt = (op >> 16) & 31u, rd = (op >> 11) & 31u;
            u32 fall_pc = cur_pc + 8u;
            u32 rel_pc  = (cur_pc + 4u) + ((u32)(s32)(s16)op << 2);
            u32 jmp_pc  = ((cur_pc + 4u) & 0xF0000000u) | ((op & 0x03FFFFFFu) << 2);

            int overlap_cond_br = 0;
            u32 fop_ov = 0u, rop_ov = 0u;
            if (dcls == 2) {
                int ok = 0;
                if (opc == 0x02u || opc == 0x03u)
                    ok = jit_target_safe_after_load(jmp_pc, delay_rt);
                else if (opc != 0x00u)
                    ok = jit_target_safe_after_load(fall_pc, delay_rt) && jit_target_safe_after_load(rel_pc, delay_rt);
                if (!ok && opc != 0x00u && opc != 0x02u && opc != 0x03u &&
                    (fall_pc - 0x80001000u) < 0x001FEFFCu && !(fall_pc & 3u) &&
                    (rel_pc  - 0x80001000u) < 0x001FEFFCu && !(rel_pc  & 3u)) {
                    fop_ov = *(const u32 *)(W.ram + (fall_pc & 0x1FFFFCu));
                    rop_ov = *(const u32 *)(W.ram + (rel_pc  & 0x1FFFFCu));
                    u32 dm1 = 0u, dm2 = 0u;
                    if (jit_classify_nonbranch(fop_ov, &dm1) == 1 && jit_classify_nonbranch(rop_ov, &dm2) == 1) {
                        ok = 1;
                        overlap_cond_br = 1;
                    }
                }
                if (!ok)
                    break;
            }

            if (opc == 0x02u || opc == 0x03u) { /* J / JAL */
                /* the link through the register cache (no flush before the delay slot: it reloaded them) */
                if (opc == 0x03u) { u32 rah = rc_write(&p, &rc, 31u, 0xFFu, 0xFFu); j_emit_li32(&p, rah, fall_pc); }
                int extra = 0;
                jit_emit_nonbranch(&p, &rc, delay_op, &extra);
                rc_flush_all(&p, &rc);
                cost += 2 + extra;
                last_off = cur_off + 4u;
                k += 2u;

                int jmp_ram = ((jmp_pc - 0x80001000u) < 0x001FF000u && !(jmp_pc & 3u));
                u32 jmp_code = jmp_ram
                    ? ((jmp_pc == start_pc) ? (u32)(__UINTPTR_TYPE__)block_start : W.jit_entry[(jmp_pc & 0x1FFFFCu) >> 2])
                    : 0u;
                if (jmp_ram) {
                    jit_emit_direct_jump_ram(&p, jmp_pc, jmp_code, cost);
                } else {
                    j_emit_li32(&p, 4u, jmp_pc);
                    *p++ = J_R(0, 30u, 0u, 0u, 0u, 0x08u);
                    *p++ = J_I(0x09u, 20u, 20u, -cost);
                }
            } else if (opc == 0x00u) { /* JR / JALR */
                rc_load_into_hreg(&p, &rc, 22u, rs); /* $s6 = target (before the link: JALR rd = rs) */
                if ((op & 0x3Fu) == 0x09u && rd) {
                    u32 rdh = rc_write(&p, &rc, rd, 0xFFu, 0xFFu);
                    j_emit_li32(&p, rdh, fall_pc);
                }
                int extra = 0;
                jit_emit_nonbranch(&p, &rc, delay_op, &extra);
                rc_flush_all(&p, &rc);
                cost += 2 + extra;
                last_off = cur_off + 4u;
                k += 2u;

                *p++ = J_I(0x09u, 20u, 20u, -cost);
                *p++ = J_R(0, 30u, 0u, 0u, 0u, 0x08u);       /* jr $fp (psx_jit_dispatch) */
                *p++ = J_R(0, 22u, 0u, 4u, 0u, 0x21u);       /* [delay] move $a0, $s6 */
            } else if (overlap_cond_br) { /* Conditional branch with delay-slot load overlapping target's 1st insn */
                rc_load_into_hreg(&p, &rc, 8u, rs);
                if (opc == 0x04u || opc == 0x05u)
                    rc_load_into_hreg(&p, &rc, 9u, rt);
                rc_flush_all(&p, &rc);
                if (opc == 0x01u && (rt & 0x1Eu) == 0x10u) {
                    j_emit_li32(&p, 10u, fall_pc);
                    j_emit_store_gpr(&p, 10u, 31u);
                }
                if (opc == 0x04u || opc == 0x05u) *p++ = J_I(opc, 8u, 9u, 2);
                else if (opc == 0x01u)            *p++ = J_I(0x01u, 8u, rt & 1u, 2);
                else                              *p++ = J_I(opc, 8u, 0u, 2);
                *p++ = J_I(0x0Du, 0u, 22u, 1u);                /* [delay] $s6 = 1 (taken) */
                *p++ = J_R(0, 0u, 0u, 22u, 0u, 0x21u);         /* not taken: $s6 = 0 */

                jit_emit_load_into_v0(&p, &rc, delay_op);
                *p++ = J_I(0x2Bu, 29u, 2u, 20);                /* sw $v0, 20($sp) */
                rc_flush_all(&p, &rc);

                u32 *br_taken = p;
                *p++ = J_I(0x05u, 22u, 0u, 0);                 /* bne $s6, $0, taken_arm */
                *p++ = 0u;

                int exf = 0;
                jit_emit_nonbranch(&p, &rc, fop_ov, &exf);
                rc_flush_all(&p, &rc);
                if (!jit_insn_writes_gpr(fop_ov, delay_rt)) {
                    *p++ = J_I(0x23u, 29u, 8u, 20);
                    j_emit_store_gpr(&p, 8u, delay_rt);
                }
                j_emit_li32(&p, 4u, fall_pc + 4u);
                *p++ = J_R(0, 23u, 0u, 0u, 0u, 0x08u);
                *p++ = J_I(0x09u, 20u, 20u, -(cost + 3 + exf));

                *br_taken = J_I(0x05u, 22u, 0u, (u32)(p - (br_taken + 1)));
                int exr = 0;
                jit_emit_nonbranch(&p, &rc, rop_ov, &exr);
                rc_flush_all(&p, &rc);
                if (!jit_insn_writes_gpr(rop_ov, delay_rt)) {
                    *p++ = J_I(0x23u, 29u, 8u, 20);
                    j_emit_store_gpr(&p, 8u, delay_rt);
                }
                j_emit_li32(&p, 4u, rel_pc + 4u);
                *p++ = J_R(0, 23u, 0u, 0u, 0u, 0x08u);
                *p++ = J_I(0x09u, 20u, 20u, -(cost + 3 + exr));

                W.jit_has_code[(fall_pc & 0x1FFFFCu) >> 6] = 1u;
                W.jit_has_code[(rel_pc  & 0x1FFFFCu) >> 6] = 1u;
                S.jit_linked = 1u;
                last_off = cur_off + 4u;
                k += 2u;
            } else { /* BEQ, BNE, BLEZ, BGTZ, REGIMM */
                int both_ram = ((fall_pc - 0x80001000u) < 0x001FF000u && !(fall_pc & 3u) &&
                                (rel_pc  - 0x80001000u) < 0x001FF000u && !(rel_pc  & 3u));
                if (!both_ram) {
                    rc_load_into_hreg(&p, &rc, 8u, rs);
                    if (opc == 0x04u || opc == 0x05u)
                        rc_load_into_hreg(&p, &rc, 9u, rt);
                    rc_flush_all(&p, &rc);
                    if (opc == 0x01u && (rt & 0x1Eu) == 0x10u) {
                        j_emit_li32(&p, 10u, fall_pc);
                        j_emit_store_gpr(&p, 10u, 31u);
                    }
                }

                if (both_ram) {
                    S.jit_linked = 1u;
                    u32 fall_code = (fall_pc == start_pc) ? (u32)(__UINTPTR_TYPE__)block_start : W.jit_entry[(fall_pc & 0x1FFFFCu) >> 2];
                    u32 rel_code  = (rel_pc  == start_pc) ? (u32)(__UINTPTR_TYPE__)block_start : W.jit_entry[(rel_pc  & 0x1FFFFCu) >> 2];

                    /* the condition into $s6 from the cached registers, before the delay slot's instruction runs
                       (and before a link): taken when it is non-zero (taken_if_set) or zero */
                    u32 rsh = rc_read(&p, &rc, rs, 0xFFu);
                    int taken_if_set;
                    if (opc == 0x04u || opc == 0x05u) {         /* BEQ / BNE: xor $s6, rs, rt */
                        u32 rth = rc_read(&p, &rc, rt, rsh);
                        *p++ = J_R(0, rsh, rth, 22u, 0u, 0x26u);
                        taken_if_set = (opc == 0x05u);
                    } else if (opc == 0x06u || opc == 0x07u) {  /* BLEZ / BGTZ: slti $s6, rs, 1 */
                        *p++ = J_I(0x0Au, rsh, 22u, 1u);
                        taken_if_set = (opc == 0x06u);
                    } else {                                    /* BLTZ(AL) / BGEZ(AL): srl $s6, rs, 31 */
                        *p++ = J_R(0, 0u, rsh, 22u, 31u, 0x02u);
                        taken_if_set = !(rt & 1u);
                    }
                    if (opc == 0x01u && (rt & 0x1Eu) == 0x10u) {     /* BLTZAL / BGEZAL: the link, taken or not */
                        u32 rah = rc_write(&p, &rc, 31u, 0xFFu, 0xFFu);
                        j_emit_li32(&p, rah, fall_pc);
                    }

                    int extra = 0;
                    jit_emit_nonbranch(&p, &rc, delay_op, &extra);
                    cost += 2 + extra;
                    last_off = cur_off + 4u;
                    k += 2u;
                    rc_flush_all(&p, &rc);

                    /* bne/beq $s6, $0, taken; [delay] addiu $s4, -cost; the fall-through's exit; taken: the
                       branch target's exit (each 2 words, 3 while not linked; the targets' prologues test the
                       budget) */
                    u32 fall_words = (fall_code >= 2u) ? 2u : 3u;
                    *p++ = J_I(taken_if_set ? 0x05u : 0x04u, 22u, 0u, 1u + fall_words);
                    *p++ = J_I(0x09u, 20u, 20u, -cost);
                    jit_emit_exit_to(&p, fall_pc, fall_code, 0);
                    jit_emit_exit_to(&p, rel_pc, rel_code, 0);
                } else {
                    j_emit_li32(&p, 10u, fall_pc);
                    j_emit_li32(&p, 11u, rel_pc);
                    if (opc == 0x04u || opc == 0x05u) *p++ = J_I(opc, 8u, 9u, 2);
                    else if (opc == 0x01u)            *p++ = J_I(0x01u, 8u, rt & 1u, 2);
                    else                              *p++ = J_I(opc, 8u, 0u, 2);
                    *p++ = J_R(0, 11u, 0u, 22u, 0u, 0x21u);       /* [delay] move $s6, $t3 (taken) */
                    *p++ = J_R(0, 10u, 0u, 22u, 0u, 0x21u);       /* move $s6, $t2 (not taken) */

                    int extra = 0;
                    jit_emit_nonbranch(&p, &rc, delay_op, &extra);
                    rc_flush_all(&p, &rc);
                    cost += 2 + extra;
                    last_off = cur_off + 4u;
                    k += 2u;

                    *p++ = J_I(0x09u, 20u, 20u, -cost);
                    *p++ = J_R(0, both_ram ? 23u : 30u, 0u, 0u, 0u, 0x08u);
                    *p++ = J_R(0, 22u, 0u, 4u, 0u, 0x21u);
                }
            }
            ended_by_branch = 1;
            break;
        }

        u32 load_rt = 0u;
        int cls = jit_classify_nonbranch(op, &load_rt);
        if (cls == 0)
            break;
        if (cls == 2) {
            if (cur_off + 8u > 0x200000u)
                break;
            u32 next_op = *(const u32 *)(W.ram + cur_off + 4u);
            u32 next_rt = 0u;
            int ncls = jit_classify_nonbranch(next_op, &next_rt);
            int nbr  = jit_is_branch(next_op);
            int is_lwl_pair = (((op >> 26) == 0x22u || (op >> 26) == 0x26u) &&
                               ((next_op >> 26) == 0x22u || (next_op >> 26) == 0x26u) &&
                               next_rt == load_rt && ((next_op >> 21) & 31u) != load_rt);
            if (is_lwl_pair ||
                ((ncls != 0 || nbr) &&
                 !jit_insn_reads_gpr(next_op, load_rt) && !jit_insn_writes_gpr(next_op, load_rt))) {
                /* Fast path: next instruction does not touch load_rt (or LWL+LWR merge pair) */
            } else if (ncls == 1 && k + 1u < JIT_MAX_INSNS) {
                /* True R3000A load-delay overlap: evaluate load into 20($sp), run next_op on old GPR, then commit */
                jit_emit_load_into_v0(&p, &rc, op);
                *p++ = J_I(0x2Bu, 29u, 2u, 20);
                int extra2 = 0;
                jit_emit_nonbranch(&p, &rc, next_op, &extra2);
                if (!jit_insn_writes_gpr(next_op, load_rt)) {
                    u32 rth = rc_write(&p, &rc, load_rt, 0xFFu, 0xFFu);
                    *p++ = J_I(0x23u, 29u, rth, 20);
                }
                cost += 2 + extra2;
                last_off = cur_off + 4u;
                k += 2u;
                continue;
            } else {
                break;
            }
        }

        int extra = 0;
        jit_emit_nonbranch(&p, &rc, op, &extra);
        cost += 1 + extra;
        last_off = cur_off;
        k++;
    }

    if (k == 0u) {
        W.jit_entry[start_off >> 2] = 1u; /* Fallback to interpreter at this PC */
        return 1u;
    }

    if (!ended_by_branch) {
        rc_flush_all(&p, &rc);
        u32 next_guest_pc = start_pc + k * 4u;
        int next_ram = ((next_guest_pc - 0x80001000u) < 0x001FF000u && !(next_guest_pc & 3u));
        if (next_ram) {
            u32 next_code = W.jit_entry[(next_guest_pc & 0x1FFFFCu) >> 2];
            jit_emit_direct_jump_ram(&p, next_guest_pc, next_code, cost);
        } else {
            j_emit_li32(&p, 4u, next_guest_pc);
            *p++ = J_R(0, 30u, 0u, 0u, 0u, 0x08u);
            *p++ = J_I(0x09u, 20u, 20u, -cost);
        }
    }

    S.jit_used = (u32)(p - W.jit_buf);
    for (u32 c = (start_off >> 6); c <= (last_off >> 6); c++)
        W.jit_has_code[c] = 1u;
    for (u32 w = (start_off >> 2); w <= (last_off >> 2); w++)
        W.jit_code_bits[(w >> 5) & (JIT_RAM_WORDS / 32u - 1u)] |= 1u << (w & 31u);

    /* Write back D-cache & invalidate I-cache over the newly emitted block */
    u32 ca = (u32)(__UINTPTR_TYPE__)block_start & ~15u;
    u32 cb = ((u32)(__UINTPTR_TYPE__)p + 15u) & ~15u;
    for (; ca < cb; ca += 16u) {
        __asm__ volatile(
            ".set push\n\t.set noreorder\n\t"
            "cache 0x15, 0(%0)\n\t"
            "cache 0x10, 0(%0)\n\t"
            ".set pop"
            : : "r"(ca) : "memory"
        );
    }
    __asm__ volatile(".set push\n\t.set noreorder\n\tsync\n\t.word 0x000000c0\n\t.set pop" : : : "memory");

    u32 code_addr = (u32)(__UINTPTR_TYPE__)block_start;
    W.jit_entry[start_off >> 2] = code_addr;
    return code_addr;
}
#endif

/* ---- Loaders: PS-X EXE & ISO9660 SYSTEM.CNF CD-ROM Boot ---- */
int psx_is_exe(const u8 *head, u32 got)
{
    if (!head || got < 0x40u)
        return 0;
    const char *m = "PS-X EXE";
    for (int i = 0; i < 8; i++)
        if (head[i] != (u8)m[i]) return 0;
    return 1;
}

static u32 rd32_le(const u8 *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static const char *apply_psx_exe_header(const u8 *hdr, const u8 *body, u32 body_avail)
{
    u32 pc0    = rd32_le(hdr + 0x10);
    u32 gp0    = rd32_le(hdr + 0x14);
    u32 t_addr = rd32_le(hdr + 0x18) & 0x1FFFFFu;
    u32 t_size = rd32_le(hdr + 0x1C);
    u32 sp_b   = rd32_le(hdr + 0x30);
    u32 sp_o   = rd32_le(hdr + 0x34);

    if (pc0 < 0x80000000u && pc0 >= PSX_RAM_SIZE)
        return "invalid PS-X EXE entry point";
    u32 copy_n = t_size < body_avail ? t_size : body_avail;
    if (t_addr + copy_n > PSX_RAM_SIZE)
        copy_n = (t_addr < PSX_RAM_SIZE) ? (PSX_RAM_SIZE - t_addr) : 0u;
    for (u32 i = 0; i < copy_n; i++)
        W.ram[t_addr + i] = body[i];

    S.pc = pc0;
    S.next_pc = pc0 + 4u;
    S.r[28] = gp0;
    S.r[29] = sp_b ? (sp_b + sp_o) : 0x801FFF00u;
    S.r[30] = S.r[29];
    S.cop0[12] = 0x00000401u; /* IEc + IM2 enabled so IRQ-driven EXEs run out of the box */
    sync_jit_stop();
    jit_reset_all();
    return 0;
}

static int ci_eq_iso_name(const u8 *rec_id, int id_len, const char *want)
{
    int i = 0;
    while (want[i] && i < id_len) {
        char a = (char)rec_id[i], b = want[i];
        if (a >= 'a' && a <= 'z') a = (char)(a - 32);
        if (b >= 'a' && b <= 'z') b = (char)(b - 32);
        if (a != b) return 0;
        i++;
    }
    if (want[i] != 0)
        return 0;
    return (i == id_len) || (rec_id[i] == ';');
}

static int iso_find_in_dir(u32 dir_lba, u32 dir_size, const char *name, u32 *out_lba, u32 *out_size)
{
    u8 sec[2048];
    u32 n_sec = (dir_size + 2047u) >> 11;
    if (n_sec == 0u) n_sec = 1u;
    if (n_sec > 32u) n_sec = 32u;
    for (u32 s = 0; s < n_sec; s++) {
        if (read_disc_sector2048(dir_lba + s, sec, 0) < 0)
            return 0;
        u32 p = 0;
        while (p + 34u <= 2048u) {
            u8 rlen = sec[p];
            if (rlen == 0u) break;
            u8 nlen = sec[p + 32u];
            if (p + rlen <= 2048u && ci_eq_iso_name(sec + p + 33u, nlen, name)) {
                *out_lba  = rd32_le(sec + p + 2u);
                *out_size = rd32_le(sec + p + 10u);
                return 1;
            }
            p += rlen;
        }
    }
    return 0;
}

static const char *boot_iso9660_disc(char *out_exe_name, int max_name)
{
    u8 pvd[2048];
    if (read_disc_sector2048(16u, pvd, 0) < 0)
        return "cannot read CD-ROM sector 16 (PVD)";
    if (pvd[0] != 1u || pvd[1] != 'C' || pvd[2] != 'D' || pvd[3] != '0' || pvd[4] != '0' || pvd[5] != '1')
        return "not an ISO9660 PlayStation CD-ROM";

    u32 root_lba  = rd32_le(pvd + 156u + 2u);
    u32 root_size = rd32_le(pvd + 156u + 10u);

    char boot_path[64];
    int bp_len = 0;
    u32 cnf_lba = 0, cnf_size = 0;
    if (iso_find_in_dir(root_lba, root_size, "SYSTEM.CNF", &cnf_lba, &cnf_size)) {
        u8 cnf[2048];
        for (int i = 0; i < 2048; i++) cnf[i] = 0;
        if (read_disc_sector2048(cnf_lba, cnf, 0) == 0) {
            u32 len = cnf_size < 2047u ? cnf_size : 2047u;
            for (u32 i = 0; i + 4u < len; i++) {
                if ((cnf[i] | 32) == 'b' && (cnf[i+1] | 32) == 'o' &&
                    (cnf[i+2] | 32) == 'o' && (cnf[i+3] | 32) == 't') {
                    u32 k = i + 4u;
                    while (k < len && (cnf[k] == ' ' || cnf[k] == '\t' || cnf[k] == '=')) k++;
                    /* Skip "cdrom:" and leading '\' or '/' */
                    if (k + 6u <= len && (cnf[k] | 32) == 'c' && (cnf[k+5]) == ':') k += 6u;
                    while (k < len && (cnf[k] == '\\' || cnf[k] == '/')) k++;
                    while (k < len && cnf[k] > 0x20u && cnf[k] != ';' && bp_len < 62)
                        boot_path[bp_len++] = (char)cnf[k++];
                    break;
                }
            }
        }
    }
    boot_path[bp_len] = 0;
    if (!bp_len) {
        const char *def = "PSX.EXE";
        while (def[bp_len]) { boot_path[bp_len] = def[bp_len]; bp_len++; }
        boot_path[bp_len] = 0;
    }

    /* Traverse optional subdirectories in boot_path */
    u32 cur_lba = root_lba, cur_size = root_size;
    const char *seg = boot_path;
    u32 exe_lba = 0, exe_size = 0;
    for (;;) {
        char part[32];
        int pl = 0;
        while (*seg && *seg != '\\' && *seg != '/' && pl < 31)
            part[pl++] = *seg++;
        part[pl] = 0;
        if (!iso_find_in_dir(cur_lba, cur_size, part, &exe_lba, &exe_size))
            return "boot executable from SYSTEM.CNF not found on CD-ROM";
        if (!*seg) {
            int k = 0;
            while (part[k] && k < max_name - 1) { out_exe_name[k] = part[k]; k++; }
            out_exe_name[k] = 0;
            if (k >= 4 && (part[0] | 32) == 's' && ((part[1] | 32) == 'c' || (part[1] | 32) == 'l') &&
                (part[2] | 32) == 'e' && ((part[3] | 32) == 's' || (part[3] | 32) == 'd'))
                S.is_pal = 1u;
            break;
        }
        seg++;
        cur_lba = exe_lba;
        cur_size = exe_size;
    }

    u8 hdr[2048];
    if (exe_size < 0x800u || read_disc_sector2048(exe_lba, hdr, 0) < 0 || !psx_is_exe(hdr, 2048u))
        return "boot file on CD-ROM is not a valid PS-X EXE";

    u32 pc0    = rd32_le(hdr + 0x10);
    u32 gp0    = rd32_le(hdr + 0x14);
    u32 t_addr = rd32_le(hdr + 0x18) & 0x1FFFFFu;
    u32 t_size = rd32_le(hdr + 0x1C);
    u32 sp_b   = rd32_le(hdr + 0x30);
    u32 sp_o   = rd32_le(hdr + 0x34);

    u32 rem = (t_size < exe_size - 0x800u) ? t_size : (exe_size - 0x800u);
    if (t_addr + rem > PSX_RAM_SIZE)
        rem = (t_addr < PSX_RAM_SIZE) ? (PSX_RAM_SIZE - t_addr) : 0u;
    u32 sec_idx = 1u, dst = t_addr;
    while (rem > 0u) {
        u8 sbuf[2048];
        if (read_disc_sector2048(exe_lba + sec_idx++, sbuf, 0) < 0)
            break;
        u32 chunk = rem < 2048u ? rem : 2048u;
        for (u32 i = 0; i < chunk; i++)
            W.ram[dst++] = sbuf[i];
        rem -= chunk;
    }

    S.pc = pc0;
    S.next_pc = pc0 + 4u;
    S.r[28] = gp0;
    S.r[29] = sp_b ? (sp_b + sp_o) : 0x801FFF00u;
    S.r[30] = S.r[29];
    S.cop0[12] = 0x00000401u;
    sync_jit_stop();
    jit_reset_all();
    return 0;
}

static void init_blank_memcard(void)
{
    for (u32 i = 0; i < PSX_MCD_SIZE; i++)
        W.mcd[i] = 0u;
    W.mcd[0] = 'M'; W.mcd[1] = 'C'; W.mcd[127] = 0x0Eu;
    for (u32 f = 1u; f <= 15u; f++) {
        u8 *blk = W.mcd + f * 128u;
        blk[0] = 0xA0u; /* Free block */
        blk[8] = 0xFFu; blk[9] = 0xFFu;
        u8 x = 0;
        for (int i = 0; i < 127; i++) x ^= blk[i];
        blk[127] = x;
    }
    for (u32 f = 16u; f < 36u; f++) {
        u8 *blk = W.mcd + f * 128u;
        for (int i = 0; i < 128; i++) blk[i] = 0xFFu;
        blk[0] = blk[1] = blk[2] = blk[3] = 0xFFu;
        blk[8] = blk[9] = 0xFFu;
    }
    W.mcd[63 * 128 + 0] = 'M'; W.mcd[63 * 128 + 1] = 'C'; W.mcd[63 * 128 + 127] = 0x0Eu;
}

/* ---- Public API ---- */
void psx_set_bios(const u8 *data, u32 size)
{
    if (data && size == PSX_BIOS_SIZE) {
        for (u32 i = 0; i < PSX_BIOS_SIZE; i++)
            W.ext_bios[i] = data[i];
        S.has_ext_bios = 1;
    } else {
        S.has_ext_bios = 0;
    }
}

void psx_set_disc(psx_sector_fn fn, u32 total_sectors, u32 sector_size)
{
    S.sec_fn = fn;
    S.disc_sectors = total_sectors;
    S.disc_sec_size = sector_size;
    S.has_disc = (fn != 0 && total_sectors > 0u) ? 1u : 0u;
}

const char *psx_load(const u8 *data, u32 size, const char *path)
{
    (void)path;
    u8 keep_ext = S.has_ext_bios;
    u8 keep_reg = S.region_override;
    u32 keep_rate = S.sample_rate;
    psx_sector_fn keep_fn = S.sec_fn;
    u32 keep_secs = S.disc_sectors;
    u32 keep_ssz  = S.disc_sec_size;
    u8  keep_disc = S.has_disc;

    for (u32 i = 0; i < sizeof(S); i++)
        ((u8 *)&S)[i] = 0;
    S.has_ext_bios    = keep_ext;
    S.region_override = keep_reg;
    S.sample_rate     = keep_rate;
    S.sec_fn          = keep_fn;
    S.disc_sectors    = keep_secs;
    S.disc_sec_size   = keep_ssz;
    S.has_disc        = keep_disc;
    hle_ev_cb_cursor = 0u;

    for (u32 i = 0; i < PSX_RAM_SIZE; i++) W.ram[i] = 0u;
    for (u32 i = 0; i < VRAM_STRIDE * 512u; i++) W.vram[i] = 0u;
    for (u32 i = 0; i < PSX_SPU_SIZE; i++) W.spu_ram[i] = 0u;
    for (u32 i = 0; i < 0x1000u; i++)      W.io[i] = 0u;
    gpu_recip_dy[0] = 0u;
    for (u32 i = 1; i < 512u; i++)
        gpu_recip_dy[i] = (1u << 16) / i;
    gpu_inv_area[0] = gpu_inv_area[1] = (1u << 30);
    for (u32 i = 2; i < 1024u; i++)
        gpu_inv_area[i] = (1u << 30) / i;
    for (u32 i = 0; i < 96u; i++) {
        clamp5_g[i] = (u16)clamp5_tab[i] << 5;
        clamp5_b[i] = (u16)clamp5_tab[i] << 10;
    }
    for (int y = 0; y < 4; y++) {
        span_dw[y] = 0u;
        for (int k = 0; k < 4; k++)
            span_dw[y] |= (u32)(gpu_dither[y][k] * 16 + 128) << (8 * k);
    }
    span_dw[4] = 0x80808080u;
    for (int i = 0; i < 512; i++) {
        int v = i - SPAN_CL_OFS;
        u16 c = (u16)(v < 0 ? 0 : v > 31 ? 31 : v);
        for (int k = 0; k < 2; k++) {
            span_cl[k][i] = (u16)(c | (k ? 0x8000u : 0u));
            span_cl[k][512 + i] = (u16)(c << 5);
            span_cl[k][1024 + i] = (u16)(c << 10);
        }
    }
    S.vram_gen = 1u;
    jit_reset_all();

    build_clean_bios();
    install_ram_vectors();
    init_blank_memcard();
    S.mcd_flag = 0x08u;
    for (int i = 0; i < 4; i++) S.auto_clear_rcnt[i] = 1u;
    S.i_mask = 0x0001u; /* VBlank IRQ enabled as left by BIOS kernel init */

    gpu_gp1(0x00000000u); /* Reset GPU -> 320 x 240 */
    S.dpcr = 0x07654321u;
    S.mdec_stat = 0x80040000u;
    S.spu_ctrl = 0x8000u;
    S.cd_stat = 0x02u;
    S.cd_irq_en = 0x1Fu; /* BIOS leaves CD-ROM INT_ENABLE unmasked after disc boot */

    /* 1. Direct PS-X EXE binary */
    if (data && size >= 0x800u && psx_is_exe(data, size)) {
        const char *err = apply_psx_exe_header(data, data + 0x800u, size - 0x800u);
        if (err) return err;
        u32 kb = (size + 1023u) >> 10;
        char *p = S.info_str;
        const char *pre = "PlayStation 1 PS-X EXE (PC 0x";
        while (*pre) *p++ = *pre++;
        for (int s = 28; s >= 0; s -= 4) {
            u32 n = (S.pc >> s) & 15u;
            *p++ = (char)(n < 10u ? ('0' + n) : ('A' + n - 10u));
        }
        *p++ = ')'; *p++ = ','; *p++ = ' ';
        if (kb >= 1000u) *p++ = (char)('0' + (kb / 1000u) % 10u);
        if (kb >= 100u)  *p++ = (char)('0' + (kb / 100u) % 10u);
        if (kb >= 10u)   *p++ = (char)('0' + (kb / 10u) % 10u);
        *p++ = (char)('0' + kb % 10u);
        const char *suf = " KB";
        while (*suf) *p++ = *suf++;
        *p = 0;
        return 0;
    }

    /* 2. In-memory .bin / .iso image if no external sector callback was set */
    if (!S.has_disc && data && size >= 2048u * 18u) {
        u32 ssz = 0u;
        if (size >= 16u * 2352u + 32u &&
            ((data[16u * 2352u + 25u] == 'C' && data[16u * 2352u + 26u] == 'D') ||
             (data[16u * 2352u + 17u] == 'C' && data[16u * 2352u + 18u] == 'D')))
            ssz = 2352u;
        else if (size >= 16u * 2048u + 8u && data[16u * 2048u + 1u] == 'C' && data[16u * 2048u + 2u] == 'D')
            ssz = 2048u;
        if (ssz) {
            S.mem_disc = data;
            S.mem_disc_size = size;
            S.disc_sec_size = ssz;
            S.disc_sectors = size / ssz;
            S.has_disc = 1u;
        }
    }

    /* 3. CD-ROM disc boot (streaming via S.sec_fn or in-memory S.mem_disc) */
    if (S.has_disc) {
        if (S.has_ext_bios) {
            S.pc = 0xBFC00000u;
            S.next_pc = 0xBFC00004u;
            S.cop0[12] = 0x00400000u; /* BEV = 1 */
            char *p = S.info_str;
            const char *s = "PlayStation 1 CD-ROM (external BIOS)";
            while (*s) *p++ = *s++;
            *p = 0;
            return 0;
        }
        char exe_name[32];
        exe_name[0] = 0;
        const char *err = boot_iso9660_disc(exe_name, sizeof(exe_name));
        if (err) return err;
        char *p = S.info_str;
        const char *pre = "PlayStation 1 CD-ROM (";
        while (*pre) *p++ = *pre++;
        for (int i = 0; exe_name[i]; i++) *p++ = exe_name[i];
        const char *suf = ", built-in BIOS)";
        while (*suf) *p++ = *suf++;
        *p = 0;
        return 0;
    }

    return "not a PlayStation 1 PS-X EXE or ISO9660 CD-ROM";
}

const char *psx_info(void) { return S.info_str; }
int psx_width(void)  { return S.disp_w > 0 ? S.disp_w : PSX_W_DEF; }
int psx_height(void) { return S.disp_h > 0 ? S.disp_h : PSX_H_DEF; }
int psx_pal(void)    { return (S.region_override == 'E') ? 1 : (S.region_override ? 0 : S.is_pal); }
void psx_set_region(int region) { S.region_override = (u8)region; }
void psx_set_skip_render(int skip) { S.skip_render = (u8)skip; }
int psx_jammed(void) { return S.jammed; }

#ifdef __mips__
/* prof.c's hook: the samples in the recompiled code, by the R3000 block each 64-byte piece belongs to (the
   block starting in it or before it, as the code is laid down now), the 40 hottest: "G guest-address samples" */
void prof_report_more(const volatile u32 *h, u32 pieces, u32 shift)
{
    u32 base = (u32)(__UINTPTR_TYPE__)W.jit_buf, used = S.jit_used * 4u;
    if (!used)
        return;
    u32 first = (base - 0x80000000u) >> shift, last = (base + used - 1u - 0x80000000u) >> shift;
    if (last >= pieces)
        return;
    u32 n = last - first + 1u;
    u32 *map = (u32 *)KSEG0(0x05400000u);               /* (scratch: WGET_PHYS beside prof.c's histogram) */
    u32 *key = map + n, *cnt = key + 4096;
    for (u32 k = 0; k < n; k++)
        map[k] = 0u;
    for (u32 i = 0; i < JIT_RAM_WORDS; i++) {
        u32 e = W.jit_entry[i];
        if (e >= base && e < base + used)
            map[((e - 0x80000000u) >> shift) - first] = 0x80000000u | (i << 2);
    }
    for (u32 k = 0, cur = 0; k < n; k++) {
        if (map[k])
            cur = map[k];
        else
            map[k] = cur;
    }
    for (u32 j = 0; j < 4096u; j++)
        key[j] = cnt[j] = 0u;
    u32 total = 0;
    for (u32 k = 0; k < n; k++) {
        u32 c = h[first + k], pc = map[k];
        if (!c || !pc)
            continue;
        total += c;
        for (u32 j = (pc >> 2) & 4095u, tries = 0; tries < 4096u; j = (j + 1u) & 4095u, tries++) {
            if (key[j] == pc || !key[j]) {
                key[j] = pc;
                cnt[j] += c;
                break;
            }
        }
    }
    uprintf("prof: %u samples in the recompiled code (%u resets since it was laid down)\n", total,
            st_reset_flush + st_reset_inval + st_reset_full + st_reset_other);
    for (int t = 0; t < 40; t++) {
        u32 best = 0;
        for (u32 j = 1; j < 4096u; j++)
            if (cnt[j] > cnt[best])
                best = j;
        if (!cnt[best])
            break;
        uprintf("G %08x %u\n", key[best], cnt[best]);
        cnt[best] = 0u;
    }
}

void psx_print_stats(void)
{
    uprintf("psx: recompiler: %u blocks compiled; resets: %u by FlushCache, %u by a write to code, %u full, "
            "%u other; %u code pieces written, %u writes beside code\n", st_compiles, st_reset_flush,
            st_reset_inval, st_reset_full, st_reset_other, st_inval, st_beside);
    uprintf("psx: %u entries into recompiled code ran %u instructions; %u interpreter runs %u\n", st_jit_enters,
            st_jit_insns, st_interp_runs, st_interp_insns);
    st_compiles = st_reset_flush = st_reset_inval = st_reset_full = st_reset_other = st_inval = st_beside = 0;
    st_jit_enters = st_jit_insns = st_interp_runs = st_interp_insns = 0;
}
#endif

const u16 *psx_vram_frame(int *stride, int *is_24bpp)
{
    if (stride) *stride = (int)VRAM_STRIDE;
    if (is_24bpp) *is_24bpp = S.disp_24bpp;
    if (S.disp_disabled || S.disp_24bpp || (S.disp_x & 1u) || (S.disp_w & 1u) ||
        S.disp_x + S.disp_w > 1024 || S.disp_y + S.disp_h > 512)
        return 0;
    return W.vram + (u32)S.disp_y * VRAM_STRIDE + S.disp_x;
}

/* live play, a 24-bit picture (videos): line y's bytes (R, G, B a pixel), the same gpu_scanout reads, when the
   line lies in one VRAM row (x and 3 bytes a pixel within its 2048 bytes: a video at x 0 always does); else 0 */
const u8 *psx_vram_line24(int y)
{
    if (S.disp_disabled || !S.disp_24bpp || (u32)S.disp_x * 2u + (u32)S.disp_w * 3u > 2048u)
        return 0;
    return (const u8 *)(W.vram + (((u32)S.disp_y + (u32)y) & 511u) * VRAM_STRIDE + S.disp_x);
}

u8 *psx_save_ram(u32 *size, int *battery)
{
    *size = PSX_MCD_SIZE;
    *battery = 1;
    return W.mcd;
}

int psx_save_changed(void)
{
    int d = S.sav_dirty;
    S.sav_dirty = 0;
    return d;
}

void psx_audio_rate(u32 hz) { S.sample_rate = hz; S.aud_frac = 0; }

int psx_audio(s16 *out, int max)
{
    int n = (int)S.aud_count < max ? (int)S.aud_count : max;
    for (int i = 0; i < n; i++)
        out[i] = W.aud_buf[i];
    S.aud_count = 0;
    return n;
}

static inline void psx_advance_periph(int units, int in_vbl)
{
    if (units <= 0)
        return;
    if (S.sio_irq_delay > 0) {
        S.sio_irq_delay -= units * 4;
        if (S.sio_irq_delay <= 0) {
            S.sio_irq_delay = -1;
            if (S.sio_ctrl & 0x1D00u)
                raise_irq(1u << 7); /* IRQ7 SIO0 (/ACK DSR, RX, or TX IRQ) */
        }
    }
    if (S.cd_req_valid || S.cd_pend_cmd || (S.cd_stat & 0x20u))
        cd_step(units * 4);
    rcnt_step(units * 2, 0, in_vbl);
}

void psx_frame(u16 pad, u16 *picture)
{
    S.pad = pad;
    S.aud_count = 0;

    /* Run up to 1024 R3000A instructions per scanline (~269K insns/frame, with idle VSync-spin fast-forward) */
    const int insn_per_line = 1024;

    for (int y = 0; y < PSX_LINES_NTSC; y++) {
        int in_vbl = (y >= PSX_VBL_LINE);
        S.scan_y = y;
        if (y == PSX_VBL_LINE) {
            S.vblank_count++;
            if (!S.has_ext_bios)
                hle_update_pad_buffers();
            raise_irq(1u << 0); /* IRQ0 VBlank */
        }

        int ran = 0;
        while (ran < insn_per_line) {
            /* Fast-forward if stalled inside B0(0A) WaitEvent with no pending IRQ */
            if (!S.has_ext_bios && (S.pc & 0x1FFFFFFFu) == 0xB0u && S.r[9] == 0x0Au &&
                !(S.cop0[12] & S.cop0[13] & 0xFF00u)) {
                psx_advance_periph(insn_per_line - ran, in_vbl);
                ran = insn_per_line;
                break;
            }
            /* Fast-forward tight RAM spin & counted delay loops */
            u32 p = mask_phys(S.pc);
            if (__builtin_expect(p < 0x800000u, 1) && !S.next_delay && !S.ld_reg && !S.pend_reg &&
                !(S.cop0[12] & S.cop0[13] & 0xFF00u)) {
                const u32 *rp = (const u32 *)(W.ram + (p & 0x1FFFFCu));
                u32 op0 = rp[0];
                /* 1. Unconditional self-branch (`b . ; nop` or `j . ; nop`) */
                if ((op0 == 0x1000FFFFu ||
                     ((op0 >> 26) == 0x02u && ((S.pc & 0xF0000000u) | ((op0 & 0x03FFFFFFu) << 2)) == S.pc)) &&
                    rp[1] == 0x00000000u) {
                    psx_advance_periph(insn_per_line - ran, in_vbl);
                    ran = insn_per_line;
                    break;
                }
                /* 2. 4-insn RAM poll (`lw/lh/lhu/lb/lbu rx, off(rb) ; nop ; beq/bne rx, ry, -3 ; <alu/nop>`) */
                u32 opc0 = op0 >> 26;
                if ((opc0 == 0x20u || opc0 == 0x21u || opc0 == 0x23u || opc0 == 0x24u || opc0 == 0x25u) &&
                    rp[1] == 0x00000000u &&
                    (((rp[2] >> 26) == 0x04u || (rp[2] >> 26) == 0x05u) && (rp[2] & 0xFFFFu) == 0xFFFDu) &&
                    (rp[3] >> 26) == 0x00u && (rp[3] & 0x3Fu) != 0x08u && (rp[3] & 0x3Fu) != 0x09u) {
                    u32 base_r = (op0 >> 21) & 31u;
                    u32 poll_p = mask_phys(S.r[base_r] + (u32)(s32)(s16)op0);
                    if (poll_p < 0x800000u) {
                        u32 before_pc = S.pc;
                        (void)r3000_run_batch(4);
                        psx_advance_periph(4, in_vbl);
                        ran += 4;
                        if (S.pc == before_pc) {
                            psx_advance_periph(insn_per_line - ran, in_vbl);
                            ran = insn_per_line;
                            break;
                        }
                        continue;
                    }
                }
                /* 3. 5-insn lui + RAM poll (`lui rat, hi ; lw/lh/lb rx, lo(rat) ; nop ; beq/bne rx, ry, -4 ; <alu/nop>`) */
                if (opc0 == 0x0Fu && rp[2] == 0x00000000u &&
                    (((rp[3] >> 26) == 0x04u || (rp[3] >> 26) == 0x05u) && (rp[3] & 0xFFFFu) == 0xFFFCu)) {
                    u32 opc1 = rp[1] >> 26;
                    if (opc1 == 0x20u || opc1 == 0x21u || opc1 == 0x23u || opc1 == 0x24u || opc1 == 0x25u) {
                        u32 hi_p = mask_phys((op0 & 0xFFFFu) << 16);
                        if (hi_p < 0x800000u) {
                            u32 before_pc = S.pc;
                            (void)r3000_run_batch(5);
                            psx_advance_periph(5, in_vbl);
                            ran += 5;
                            if (S.pc == before_pc) {
                                psx_advance_periph(insn_per_line - ran, in_vbl);
                                ran = insn_per_line;
                                break;
                            }
                            continue;
                        }
                    }
                }
                /* 4. 2-insn delay-slot countdown (`bnez rx, -1 ; addiu rx, rx, -1`, e.g. PeterLemon PlaySong) */
                if ((op0 & 0xFC1FFFFFu) == 0x1400FFFFu) {
                    u32 rx = (op0 >> 21) & 31u;
                    if (rx && rp[1] == (0x2400FFFFu | (rx << 21) | (rx << 16)) && S.r[rx] > 2u) {
                        u32 max_it = (u32)((insn_per_line - ran) >> 1);
                        if (max_it >= 1u) {
                            u32 rem_it = S.r[rx] - 1u;
                            u32 do_it = (rem_it < max_it) ? rem_it : max_it;
                            S.r[rx] -= do_it;
                            psx_advance_periph((int)(do_it * 2u), in_vbl);
                            ran += (int)(do_it * 2u);
                            continue;
                        }
                    }
                }
                /* 5. PsyQ 9-insn v_wait (`beqz rtmo,+N; nop; lw rcur,off(rb); nop; bne rold,rcur,+M; nop; addiu rtmo,-1; b -8; nop`) */
                if ((op0 >> 26) == 0x04u && ((op0 >> 16) & 31u) == 0u &&
                    rp[1] == 0x00000000u && (rp[2] >> 26) == 0x23u && rp[3] == 0x00000000u &&
                    (rp[4] >> 26) == 0x05u && rp[5] == 0x00000000u &&
                    rp[7] == 0x1000FFF8u && rp[8] == 0x00000000u) {
                    u32 rtmo = (op0 >> 21) & 31u;
                    u32 rb   = (rp[2] >> 21) & 31u;
                    u32 rcur = (rp[2] >> 16) & 31u;
                    if (rtmo && rcur && rtmo != rcur && rtmo != rb &&
                        rp[6] == (0x2400FFFFu | (rtmo << 21) | (rtmo << 16))) {
                        u32 poll_p = mask_phys(S.r[rb] + (u32)(s32)(s16)rp[2]);
                        if (poll_p < 0x800000u && S.r[rtmo] > 256u) {
                            u32 before_pc = S.pc;
                            (void)r3000_run_batch(9);
                            psx_advance_periph(9, in_vbl);
                            ran += 9;
                            if (S.pc == before_pc) {
                                int rem = insn_per_line - ran;
                                int rem_it = rem / 9;
                                if (rem_it > 0 && S.r[rtmo] > (u32)(rem_it + 16))
                                    S.r[rtmo] -= (u32)rem_it;
                                psx_advance_periph(rem, in_vbl);
                                ran = insn_per_line;
                                break;
                            }
                            continue;
                        }
                    }
                }
                /* 6. Counted busy-wait (`addiu rx, rx, 1 ; slti ry, rx, imm ; bne ry, $0, -3 ; nop`) */
                if ((op0 & 0xFC00FFFFu) == 0x24000001u && ((op0 >> 21) & 31u) == ((op0 >> 16) & 31u) &&
                    (rp[1] >> 26) == 0x0Au && rp[3] == 0x00000000u) {
                    u32 rx = (op0 >> 16) & 31u;
                    u32 ry = (rp[1] >> 16) & 31u;
                    if (rx && ry && rx != ry && ((rp[1] >> 21) & 31u) == rx &&
                        rp[2] == (0x1400FFFDu | (ry << 21))) {
                        s32 cur = (s32)S.r[rx];
                        s32 lim = (s32)(s16)rp[1];
                        if (cur < lim) {
                            int max_it = (insn_per_line - ran) >> 2;
                            s32 rem_it = lim - cur;
                            if (max_it >= 1) {
                                int do_it = (rem_it < max_it) ? (int)rem_it : max_it;
                                S.r[rx] = (u32)(cur + do_it);
                                psx_advance_periph(do_it * 4, in_vbl);
                                ran += do_it * 4;
                                if ((s32)S.r[rx] >= lim) {
                                    S.r[ry] = 0u;
                                    S.pc += 16u;
                                    S.next_pc = S.pc + 4u;
                                } else {
                                    S.r[ry] = 1u;
                                }
                                continue;
                            }
                        }
                    }
                }
                /* 7. Namco / PsyQ VBlank PRNG-churn wait (`jal leaf_prng; nop; lw; lw rflag,...; ...; beqz rflag, -16; sw`) */
                if (!in_vbl && (p & 0x1FFFFCu) + 68u <= PSX_RAM_SIZE &&
                    (op0 >> 26) == 0x03u && rp[1] == 0x00000000u && (rp[15] & 0xFC1FFFFFu) == 0x1000FFF0u &&
                    insn_per_line - ran >= 25) {
                    u32 before_pc = S.pc;
                    int d25 = r3000_run_batch(25);
                    psx_advance_periph(d25, in_vbl);
                    ran += d25;
                    if (S.pc == before_pc && ran < insn_per_line) {
                        psx_advance_periph(insn_per_line - ran, in_vbl);
                        ran = insn_per_line;
                        break;
                    }
                    continue;
                }
                /* 8. PsyQ 4.6 14-insn stack-timeout v_wait (`lw v0,16(sp); nop; addiu v0,-1; sw v0,16(sp); ...; bnez v0,-23; nop`) */
                if ((p & 0x1FFFFCu) + 96u <= PSX_RAM_SIZE &&
                    op0 == 0x8FA20010u && rp[2] == 0x2442FFFFu && rp[3] == 0xAFA20010u &&
                    rp[6] == 0x1443000Bu && rp[22] == 0x1440FFE9u && insn_per_line - ran >= 16) {
                    u32 tmo = bus_read32(S.r[29] + 16u);
                    if (tmo > 256u && S.r[3] == 0xFFFFFFFFu) {
                        u32 before_pc = S.pc;
                        int d14 = r3000_run_batch(14);
                        psx_advance_periph(d14, in_vbl);
                        ran += d14;
                        if (S.pc == before_pc && ran < insn_per_line) {
                            int rem = insn_per_line - ran;
                            u32 rem_it = (u32)(rem / 14);
                            tmo = bus_read32(S.r[29] + 16u);
                            if (rem_it > 0u && tmo > rem_it + 16u)
                                bus_write32(S.r[29] + 16u, tmo - rem_it);
                            psx_advance_periph(rem, in_vbl);
                            ran = insn_per_line;
                            break;
                        }
                        continue;
                    }
                }
            }

#ifdef __mips__
            S.jit_stop &= ~2u;
            if (!S.next_delay && !S.ld_reg && !S.pend_reg && !S.jit_stop &&
                (S.pc - 0x80001000u) < 0x001FF000u && !(S.pc & 3u)) {
                u32 jent = W.jit_entry[(S.pc & 0x1FFFFCu) >> 2];
                if (jent == 0u)
                    jent = jit_compile_block(S.pc);
                if (jent >= 2u) {
                    int jbudget = insn_per_line - ran;
                    int jdone = psx_jit_enter(jbudget, &S, W.ram, W.jit_entry);
                    st_jit_enters++;
                    st_jit_insns += (u32)jdone;
                    if (jdone > 0) {
                        ran += jdone;
                        psx_advance_periph(jdone, in_vbl);
                        continue;
                    }
                }
            }
            {
                int batch = insn_per_line - ran;
                if (batch > 4) batch = 4;
                int done = r3000_run_batch(batch);
                st_interp_runs++;
                st_interp_insns += (u32)done;
                ran += done;
                psx_advance_periph(done, in_vbl);
            }
#else
            /* Prime batch size (37) keeps gcd(37, L) == 1 for loop detection while halving batch dispatch overhead */
            int batch = insn_per_line - ran;
            if (batch > 37) batch = 37;
            int done = r3000_run_batch(batch);
            ran += done;
            psx_advance_periph(done, in_vbl);
#endif
        }

        rcnt_step(1, 1, in_vbl);
        if ((y & 15) == 15)
            spu_step_lines(16u);
        else if (y == PSX_LINES_NTSC - 1)
            spu_step_lines((u32)(PSX_LINES_NTSC & 15));
    }

    if (picture && S.skip_render == 0u)                 /* (live play: the player asks, psx_scanout) */
        gpu_scanout(picture);
    /* a game frame being skipped, or a stale buffer shown, ends at the next flip; a game that stops flipping (it
       draws straight into what is shown from then on) gets its drawing, and its picture shown, back after 8 frames
       (a game frame of 8 vblanks: 7.5 a second) -- what it draws then is shown, an old buffer alone is not */
    if ((S.fs_active | S.disp_stale) && ++S.fs_age > 8u)
        S.fs_active = S.disp_stale = 0u;
}

void psx_scanout(u16 *picture)
{
    gpu_scanout(picture);
}

/* live play: has what is shown changed since the last call (a flip, drawing or a transfer into it, the
   display's mode)?  And is it a frame whose drawing was skipped (keep the picture before it)? */
int psx_display_changed(void)
{
    int d = S.disp_dirty;
    S.disp_dirty = 0u;
    return d;
}

int psx_display_stale(void)
{
    return S.disp_stale;
}

/* has the shown part moved (a flip: every line changes) since the last call? */
int psx_display_flipped(void)
{
    int f = S.disp_flipped;
    S.disp_flipped = 0u;
    return f;
}

u32 psx_frames_skipped(void)
{
    return S.fs_skipped;
}
