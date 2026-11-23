/* Nintendo Virtual Boy (1995): see vb.h.
 *
 * Clean C implementation derived from NEC V810 / Virtual Boy hardware
 * documentation, Mednafen VB (David Tucker / Mednafen team, GPLv2), and
 * John R. Hauser's SoftFloat Release 2b (pure 32-bit integer IEEE-754
 * single-precision FPU with NEC V810 exponent-wrap semantics).
 * All state resides in EMU_RAM_PHYS so static .bss is 0 bytes.
 */
#pragma GCC optimize("O2")
#include "vb.h"
#ifndef VB_HOST
#include "hw.h"
#endif

typedef unsigned long long u64;
typedef signed long long   s64;

/* play.c pad bits */
#define PAD_A      0x01u
#define PAD_B      0x02u
#define PAD_SELECT 0x04u
#define PAD_START  0x08u
#define PAD_UP     0x10u
#define PAD_DOWN   0x20u
#define PAD_LEFT   0x40u
#define PAD_RIGHT  0x80u

/* Virtual Boy 16-bit serial controller bits (SDLR / SDHR) */
#define VBPAD_SIG     0x0002u
#define VBPAD_A       0x0004u
#define VBPAD_B       0x0008u
#define VBPAD_R       0x0010u
#define VBPAD_L       0x0020u
#define VBPAD_R_UP    0x0040u
#define VBPAD_R_RIGHT 0x0080u
#define VBPAD_L_RIGHT 0x0100u
#define VBPAD_L_LEFT  0x0200u
#define VBPAD_L_DOWN  0x0400u
#define VBPAD_L_UP    0x0800u
#define VBPAD_START   0x1000u
#define VBPAD_SELECT  0x2000u
#define VBPAD_R_LEFT  0x4000u
#define VBPAD_R_DOWN  0x8000u

/* V810 System Registers */
#define SR_EIPC   0
#define SR_EIPSW  1
#define SR_FEPC   2
#define SR_FEPSW  3
#define SR_ECR    4
#define SR_PSW    5
#define SR_PIR    6
#define SR_TKCW   7
#define SR_CHCW   24
#define SR_ADDTRE 25

/* V810 PSW bits */
#define PSW_IA  0xF0000u
#define PSW_NP  0x08000u
#define PSW_EP  0x04000u
#define PSW_AE  0x02000u
#define PSW_ID  0x01000u
#define PSW_FRO 0x00200u
#define PSW_FIV 0x00100u
#define PSW_FZD 0x00080u
#define PSW_FOV 0x00040u
#define PSW_FUD 0x00020u
#define PSW_FPR 0x00010u
#define PSW_CY  0x00008u
#define PSW_OV  0x00004u
#define PSW_S   0x00002u
#define PSW_Z   0x00001u

/* V810 exception vectors & cause codes */
#define EXC_INVALID_OP_ADDR 0xFFFFFF90u
#define EXC_ZERO_DIV_ADDR   0xFFFFFF80u
#define EXC_FPU_ADDR        0xFFFFFF60u
#define EXC_TRAP_BASE       0xFFFFFFA0u

#define ECODE_TRAP_BASE  0xFFA0u
#define ECODE_INVALID_OP 0xFF90u
#define ECODE_ZERO_DIV   0xFF80u
#define ECODE_FIV        0xFF70u
#define ECODE_FZD        0xFF68u
#define ECODE_FOV        0xFF64u
#define ECODE_FRO        0xFF60u

/* IRQ sources (priority 4 highest .. 0 lowest) */
#define VBIRQ_INPUT     0
#define VBIRQ_TIMER     1
#define VBIRQ_EXPANSION 2
#define VBIRQ_COMM      3
#define VBIRQ_VIP       4

#define VB_EVENT_NEVER  0x7FFFFFFF

/* VIP interrupt flags */
#define VIP_INT_SCAN_ERR    0x0001u
#define VIP_INT_LFB_END     0x0002u
#define VIP_INT_RFB_END     0x0004u
#define VIP_INT_GAME_START  0x0008u
#define VIP_INT_FRAME_START 0x0010u
#define VIP_INT_SB_HIT      0x2000u
#define VIP_INT_XP_END      0x4000u
#define VIP_INT_TIME_ERR    0x8000u

/* Timer control bits */
#define TC_TENABLE  0x01u
#define TC_ZSTAT    0x02u
#define TC_ZSTATCLR 0x04u
#define TC_TIMZINT  0x08u
#define TC_TCLKSEL  0x10u

/* Serial input control bits */
#define SCR_S_ABT_DIS 0x01u
#define SCR_SI_STAT   0x02u
#define SCR_HW_SI     0x04u
#define SCR_SOFT_CLK  0x10u
#define SCR_PARA_SI   0x20u
#define SCR_K_INT_INH 0x80u

/* V810 lastop pipeline tags */
#define LASTOP_LD  0x100
#define LASTOP_ST  0x200
#define LASTOP_IN  0x400
#define LASTOP_OUT 0x800

/* HALT states */
#define HALT_NONE  0
#define HALT_HALT  1
#define HALT_FATAL 2

#define VB_AUDIO_RING 4096

struct v810_cache_entry {
    u32 tag;
    u32 data[2];
    u8  valid[2];
    u16 pad;
};

struct vb_ws {
    /* V810 CPU state */
    u32 p_reg[32];
    u32 s_reg[32];
    u32 pc;
    s32 timestamp;
    s32 next_event_ts;
    s32 lastop;
    s32 ilevel;
    u32 ipending_cache;
    u8  halted;
    u8  running;
    u8  in_bstr;
    u8  have_src_cache;
    u8  have_dst_cache;
    u16 in_bstr_to;
    u32 src_cache;
    u32 dst_cache;
    u8  fp_flags;
    struct v810_cache_entry icache[128];

    /* Event scheduler & IRQ latch */
    s32 next_vip_ts;
    s32 next_timer_ts;
    s32 next_input_ts;
    u32 irq_asserted;
    u32 vip_poll_pc;
    s32 idle_skip_to;
    u8  vip_poll_cnt;
    u8  wcr;
    u8  disp_mode;
    u8  mode_key_prev;
    u8  sram_dirty;

    /* VIP state */
    u8  fb[2][2][0x6004];
    u16 chr_ram[0x8000 / 2];
    u16 dram[0x20000 / 2];
    u8  draw_buf[2][512 * 8 + 16];
    u16 vip_ipending;
    u16 vip_ienable;
    u8  brta, brtb, brtc, rest;
    u8  repeat;
    u16 frmcyc;
    u16 dpctrl;
    u8  disp_active;
    u8  disp_fb;
    u16 xpctrl;
    u16 sbcmp;
    u16 spt[4];
    u16 gplt[4];
    u8  gplt_cache[4][4];
    u16 jplt[4];
    u8  jplt_cache[4][4];
    u16 bkcol;
    s32 vip_last_ts;
    s32 column;
    s32 column_counter;
    s32 disp_region;
    s32 game_frame_counter;
    s32 drawing_counter;
    u8  drawing_active;
    u8  drawing_fb;
    u32 drawing_block;
    s32 sb_latch;
    s32 sbout_inactive_ts;
    s32 bright_cache[4];
    u16 bright_clut[2][4];
    u16 *cur_pic;

    /* Hardware Timer */
    u8  timer_ctrl;
    u16 timer_reload;
    u16 timer_counter;
    s32 timer_divider;
    s32 timer_last_ts;
    u8  timer_status;
    u8  timer_status_shadow;
    u8  timer_reload_pending;

    /* Controller Input */
    u16 pad_data;
    u16 pad_latched;
    u8  scr;
    u16 sdr;
    u32 read_bit_pos;
    s32 read_counter;
    s32 input_last_ts;
    u8  input_int_pending;

    /* VSU 6-channel Wavetable + Noise Synthesizer */
    u8  vsu_intl[6];
    u8  vsu_left[6];
    u8  vsu_right[6];
    u16 vsu_freq[6];
    u16 vsu_env_ctrl[6];
    u8  vsu_ram_addr[6];
    u8  vsu_sweep;
    u8  vsu_wave[5][0x20];
    u8  vsu_mod[0x20];
    s32 vsu_eff_freq[6];
    s32 vsu_env[6];
    s32 vsu_wave_pos[6];
    s32 vsu_mod_pos;
    s32 vsu_latcher_div[6];
    s32 vsu_freq_cnt[6];
    s32 vsu_intl_cnt[6];
    s32 vsu_env_cnt[6];
    s32 vsu_sweep_cnt;
    s32 vsu_fx_div[6];
    s32 vsu_intl_div[6];
    s32 vsu_env_div[6];
    s32 vsu_sweep_div;
    s32 vsu_noise_div;
    u32 vsu_noise_latch;
    u32 vsu_lfsr;
    s32 vsu_last_ts;
    u32 vsu_cycle_fix;
    u32 audio_hz;
    u32 audio_phase;
    s32 audio_dc;
    s16 audio_ring[VB_AUDIO_RING];
    u32 audio_r;
    u32 audio_w;

    /* Memory & Cartridge */
    u8  wram[0x10000];
    u8  sram[0x10000];
    const u8 *rom_ptr;
    u32 rom_mask;
    u32 rom_orig_size;
    char title[24];
    char info_str[96];
    u8  rom_buf[0x400000];      /* 4 MB power-of-2 mirrored ROM storage */
};

#ifdef VB_HOST
static struct vb_ws host_vb_ws;
#define VB_WS (&host_vb_ws)
#else
#define KSEG0_VB(p) ((void *)(0x80000000u | (u32)(p)))
#define VB_WS ((struct vb_ws *)KSEG0_VB(EMU_RAM_PHYS))
_Static_assert(sizeof(struct vb_ws) <= EMU_RAM_SIZE, "vb_ws exceeds EMU_RAM_SIZE");
#endif

static void *vb_memset(void *dst, int val, u32 n)
{
    u8 *p = (u8 *)dst;
    for (u32 i = 0; i < n; i++)
        p[i] = (u8)val;
    return dst;
}

static void *vb_memcpy(void *dst, const void *src, u32 n)
{
    u8 *d = (u8 *)dst;
    const u8 *s = (const u8 *)src;
    for (u32 i = 0; i < n; i++)
        d[i] = s[i];
    return dst;
}

static inline u16 rd16_le(const u8 *p)
{
    return (u16)((u16)p[0] | ((u16)p[1] << 8));
}

static inline void wr16_le(u8 *p, u16 v)
{
    p[0] = (u8)v;
    p[1] = (u8)(v >> 8);
}

static inline s32 sign_x_s32(int bits, u32 v)
{
    int sh = 32 - bits;
    return ((s32)(v << sh)) >> sh;
}

static inline s16 sign_9_s16(u32 v)  { return (s16)sign_x_s32(9, v);  }
static inline s16 sign_10_s16(u32 v) { return (s16)sign_x_s32(10, v); }
static inline s16 sign_11_s16(u32 v) { return (s16)sign_x_s32(11, v); }

/* Precomputed pow(i / 255.0, 1.0 / 2.2) * 255 gamma table (zero floats!) */
static const u8 vb_gamma_lut[256] = {
      0,  21,  28,  34,  39,  43,  46,  50,  53,  56,  59,  61,  64,  66,  68,  70,
     72,  74,  76,  78,  80,  82,  84,  85,  87,  89,  90,  92,  93,  95,  96,  98,
     99, 101, 102, 103, 105, 106, 107, 109, 110, 111, 112, 114, 115, 116, 117, 118,
    119, 120, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135,
    136, 137, 138, 139, 140, 141, 142, 143, 144, 144, 145, 146, 147, 148, 149, 150,
    151, 151, 152, 153, 154, 155, 156, 156, 157, 158, 159, 160, 160, 161, 162, 163,
    164, 164, 165, 166, 167, 167, 168, 169, 170, 170, 171, 172, 173, 173, 174, 175,
    175, 176, 177, 178, 178, 179, 180, 180, 181, 182, 182, 183, 184, 184, 185, 186,
    186, 187, 188, 188, 189, 190, 190, 191, 192, 192, 193, 194, 194, 195, 195, 196,
    197, 197, 198, 199, 199, 200, 200, 201, 202, 202, 203, 203, 204, 205, 205, 206,
    206, 207, 208, 208, 209, 209, 210, 210, 211, 212, 212, 213, 213, 214, 214, 215,
    216, 216, 217, 217, 218, 218, 219, 219, 220, 221, 221, 222, 222, 223, 223, 224,
    224, 225, 225, 226, 227, 227, 228, 228, 229, 229, 230, 230, 231, 231, 232, 232,
    233, 233, 234, 234, 235, 235, 236, 236, 237, 237, 238, 238, 239, 239, 240, 240,
    241, 241, 242, 242, 243, 243, 244, 244, 245, 245, 246, 246, 247, 247, 248, 248,
    249, 249, 250, 250, 251, 251, 251, 252, 252, 253, 253, 254, 254, 255, 255, 255
};

static inline u16 vb_bgr555(u32 r, u32 g, u32 b)
{
    return (u16)(((b >> 3) << 10) | ((g >> 3) << 5) | (r >> 3));
}

/* ========================================================================
 * Pure-Integer IEEE-754 Single-Precision SoftFloat (NEC V810 semantics)
 * ======================================================================== */

#define FP_FLAG_INEXACT   0x01u
#define FP_FLAG_DIVBYZERO 0x02u
#define FP_FLAG_UNDERFLOW 0x04u
#define FP_FLAG_OVERFLOW  0x08u
#define FP_FLAG_INVALID   0x10u
#define FP_DEFAULT_NAN    0xFFFFFFFFu

static inline u32 fp_frac(u32 a) { return a & 0x007FFFFFu; }
static inline s16 fp_exp(u32 a)  { return (s16)((a >> 23) & 0xFFu); }
static inline u8  fp_sign(u32 a) { return (u8)(a >> 31); }

static inline u32 fp_pack(u8 sign, s16 exp, u32 sig)
{
    return ((u32)sign << 31) + ((u32)(u16)exp << 23) + sig;
}

static inline u32 fp_shift32_jam(u32 a, s16 count)
{
    if (count == 0)
        return a;
    if (count < 32)
        return (a >> count) | ((a << ((-count) & 31)) != 0);
    return (a != 0);
}

static inline void fp_add64(u32 a0, u32 a1, u32 b0, u32 b1, u32 *z0, u32 *z1)
{
    u32 r1 = a1 + b1;
    *z1 = r1;
    *z0 = a0 + b0 + (r1 < a1);
}

static inline void fp_sub64(u32 a0, u32 a1, u32 b0, u32 b1, u32 *z0, u32 *z1)
{
    *z1 = a1 - b1;
    *z0 = a0 - b0 - (a1 < b1);
}

static inline void fp_mul32to64(u32 a, u32 b, u32 *z0, u32 *z1)
{
    u32 aL = a & 0xFFFFu, aH = a >> 16;
    u32 bL = b & 0xFFFFu, bH = b >> 16;
    u32 r1 = aL * bL;
    u32 mA = aL * bH;
    u32 mB = aH * bL;
    u32 r0 = aH * bH;
    mA += mB;
    r0 += (((u32)(mA < mB)) << 16) + (mA >> 16);
    mA <<= 16;
    r1 += mA;
    r0 += (r1 < mA);
    *z1 = r1;
    *z0 = r0;
}

static u32 fp_est_div64to32(u32 a0, u32 a1, u32 b)
{
    u32 b0, b1, rem0, rem1, term0, term1, z;
    if (b <= a0)
        return 0xFFFFFFFFu;
    b0 = b >> 16;
    z = ((b0 << 16) <= a0) ? 0xFFFF0000u : ((a0 / b0) << 16);
    fp_mul32to64(b, z, &term0, &term1);
    fp_sub64(a0, a1, term0, term1, &rem0, &rem1);
    while ((s32)rem0 < 0) {
        z -= 0x10000u;
        b1 = b << 16;
        fp_add64(rem0, rem1, b0, b1, &rem0, &rem1);
    }
    rem0 = (rem0 << 16) | (rem1 >> 16);
    z |= ((b0 << 16) <= rem0) ? 0xFFFFu : (rem0 / b0);
    return z;
}

static s8 fp_clz32(u32 a)
{
    static const s8 clz_hi[16] = { 4, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0 };
    s8 n = 0;
    if (a == 0)
        return 32;
    if (a < 0x10000u) { n += 16; a <<= 16; }
    if (a < 0x1000000u) { n += 8; a <<= 8; }
    if (a < 0x10000000u) { n += 4; a <<= 4; }
    return (s8)(n + clz_hi[a >> 28]);
}

static void fp_norm_subnormal(u32 aSig, s16 *zExp, u32 *zSig)
{
    s8 sh = (s8)(fp_clz32(aSig) - 8);
    *zSig = aSig << sh;
    *zExp = (s16)(1 - sh);
}

static inline int fp_is_nan(u32 a)
{
    return 0xFF000000u < (u32)(a << 1);
}

static inline int fp_is_snan(u32 a)
{
    return (((a >> 22) & 0x1FFu) == 0x1FEu) && (a & 0x003FFFFFu);
}

static u32 fp_prop_nan(struct vb_ws *ws, u32 a, u32 b)
{
    int aNaN = fp_is_nan(a), aSNaN = fp_is_snan(a);
    int bNaN = fp_is_nan(b), bSNaN = fp_is_snan(b);
    a |= 0x00400000u;
    b |= 0x00400000u;
    if (aSNaN | bSNaN)
        ws->fp_flags |= FP_FLAG_INVALID;
    if (aNaN)
        return (aSNaN & bNaN) ? b : a;
    return b;
}

static u32 fp_round_pack(struct vb_ws *ws, u8 zSign, s16 zExp, u32 zSig)
{
    u32 roundInc = 0x40u;
    u32 roundBits = zSig & 0x7Fu;
    if (0xFDu <= (u16)zExp) {
        if (zExp > 0xFD || (zExp == 0xFD && (s32)(zSig + roundInc) < 0)) {
            ws->fp_flags |= FP_FLAG_OVERFLOW;
            zExp = (s16)(zExp - 192);   /* V810 hardware exponent wrap */
        }
        if (zExp < 0) {
            int tiny = (zExp < -1) || (zSig + roundInc < 0x80000000u);
            zSig = fp_shift32_jam(zSig, (s16)(-zExp));
            zExp = 0;
            roundBits = zSig & 0x7Fu;
            if (tiny && roundBits)
                ws->fp_flags |= FP_FLAG_UNDERFLOW;
        }
    }
    if (roundBits)
        ws->fp_flags |= FP_FLAG_INEXACT;
    zSig = (zSig + roundInc) >> 7;
    if ((roundBits ^ 0x40u) == 0)
        zSig &= ~1u;
    if (zSig == 0)
        zExp = 0;
    return fp_pack(zSign, zExp, zSig);
}

static u32 fp_norm_round_pack(struct vb_ws *ws, u8 zSign, s16 zExp, u32 zSig)
{
    s8 sh = (s8)(fp_clz32(zSig) - 1);
    return fp_round_pack(ws, zSign, (s16)(zExp - sh), zSig << sh);
}

static u32 fp_i32_to_f32(struct vb_ws *ws, s32 a)
{
    if (a == 0)
        return 0;
    if ((u32)a == 0x80000000u)
        return fp_pack(1, 0x9E, 0);
    u8 zSign = (a < 0);
    u32 absA = zSign ? (0u - (u32)a) : (u32)a;
    return fp_norm_round_pack(ws, zSign, 0x9C, absA);
}

static s32 fp_f32_to_i32(struct vb_ws *ws, u32 a)
{
    u32 aSig = fp_frac(a), aSigExtra;
    s16 aExp = fp_exp(a);
    u8  aSign = fp_sign(a);
    s16 sh = (s16)(aExp - 0x96);
    s32 z;
    if (sh >= 0) {
        if (aExp >= 0x9E) {
            if (a != 0xCF000000u) {
                ws->fp_flags |= FP_FLAG_INVALID;
                if (!aSign || (aExp == 0xFF && aSig))
                    return 0x7FFFFFFF;
            }
            return (s32)0x80000000u;
        }
        z = (s32)((aSig | 0x00800000u) << sh);
        if (aSign)
            z = -z;
    } else {
        if (aExp < 0x7E) {
            aSigExtra = (u32)aExp | aSig;
            z = 0;
        } else {
            aSig |= 0x00800000u;
            aSigExtra = aSig << (sh & 31);
            z = (s32)(aSig >> (-sh));
        }
        if (aSigExtra)
            ws->fp_flags |= FP_FLAG_INEXACT;
        if ((s32)aSigExtra < 0) {
            ++z;
            if ((u32)(aSigExtra << 1) == 0)
                z &= ~1;
        }
        if (aSign)
            z = -z;
    }
    return z;
}

static s32 fp_f32_to_i32_trunc(struct vb_ws *ws, u32 a)
{
    u32 aSig = fp_frac(a);
    s16 aExp = fp_exp(a);
    u8  aSign = fp_sign(a);
    s16 sh = (s16)(aExp - 0x9E);
    if (sh >= 0) {
        if (a != 0xCF000000u) {
            ws->fp_flags |= FP_FLAG_INVALID;
            if (!aSign || (aExp == 0xFF && aSig))
                return 0x7FFFFFFF;
        }
        return (s32)0x80000000u;
    }
    if (aExp <= 0x7E) {
        if ((u32)aExp | aSig)
            ws->fp_flags |= FP_FLAG_INEXACT;
        return 0;
    }
    aSig = (aSig | 0x00800000u) << 8;
    s32 z = (s32)(aSig >> (-sh));
    if ((u32)(aSig << (sh & 31)))
        ws->fp_flags |= FP_FLAG_INEXACT;
    if (aSign)
        z = -z;
    return z;
}

static u32 fp_add_sigs(struct vb_ws *ws, u32 a, u32 b, u8 zSign)
{
    u32 aSig = fp_frac(a) << 6, bSig = fp_frac(b) << 6, zSig;
    s16 aExp = fp_exp(a), bExp = fp_exp(b), zExp;
    s16 expDiff = (s16)(aExp - bExp);
    if (expDiff > 0) {
        if (aExp == 0xFF)
            return aSig ? fp_prop_nan(ws, a, b) : a;
        if (bExp == 0)
            --expDiff;
        else
            bSig |= 0x20000000u;
        bSig = fp_shift32_jam(bSig, expDiff);
        zExp = aExp;
    } else if (expDiff < 0) {
        if (bExp == 0xFF)
            return bSig ? fp_prop_nan(ws, a, b) : fp_pack(zSign, 0xFF, 0);
        if (aExp == 0)
            ++expDiff;
        else
            aSig |= 0x20000000u;
        aSig = fp_shift32_jam(aSig, (s16)(-expDiff));
        zExp = bExp;
    } else {
        if (aExp == 0xFF)
            return (aSig | bSig) ? fp_prop_nan(ws, a, b) : a;
        if (aExp == 0)
            return fp_pack(zSign, 0, (aSig + bSig) >> 6);
        zSig = 0x40000000u + aSig + bSig;
        zExp = aExp;
        return fp_round_pack(ws, zSign, zExp, zSig);
    }
    aSig |= 0x20000000u;
    zSig = (aSig + bSig) << 1;
    --zExp;
    if ((s32)zSig < 0) {
        zSig = aSig + bSig;
        ++zExp;
    }
    return fp_round_pack(ws, zSign, zExp, zSig);
}

static u32 fp_sub_sigs(struct vb_ws *ws, u32 a, u32 b, u8 zSign)
{
    u32 aSig = fp_frac(a) << 7, bSig = fp_frac(b) << 7, zSig;
    s16 aExp = fp_exp(a), bExp = fp_exp(b), zExp;
    s16 expDiff = (s16)(aExp - bExp);
    if (expDiff > 0) {
        if (aExp == 0xFF)
            return aSig ? fp_prop_nan(ws, a, b) : a;
        if (bExp == 0)
            --expDiff;
        else
            bSig |= 0x40000000u;
        bSig = fp_shift32_jam(bSig, expDiff);
        aSig |= 0x40000000u;
        zSig = aSig - bSig;
        zExp = aExp;
    } else if (expDiff < 0) {
        if (bExp == 0xFF)
            return bSig ? fp_prop_nan(ws, a, b) : fp_pack(zSign ^ 1u, 0xFF, 0);
        if (aExp == 0)
            ++expDiff;
        else
            aSig |= 0x40000000u;
        aSig = fp_shift32_jam(aSig, (s16)(-expDiff));
        bSig |= 0x40000000u;
        zSig = bSig - aSig;
        zExp = bExp;
        zSign ^= 1u;
    } else {
        if (aExp == 0xFF) {
            if (aSig | bSig)
                return fp_prop_nan(ws, a, b);
            ws->fp_flags |= FP_FLAG_INVALID;
            return FP_DEFAULT_NAN;
        }
        if (aExp == 0)
            aExp = bExp = 1;
        if (bSig < aSig) {
            zSig = aSig - bSig;
            zExp = aExp;
        } else if (aSig < bSig) {
            zSig = bSig - aSig;
            zExp = bExp;
            zSign ^= 1u;
        } else {
            return fp_pack(0, 0, 0);
        }
    }
    --zExp;
    return fp_norm_round_pack(ws, zSign, zExp, zSig);
}

static u32 fp_add(struct vb_ws *ws, u32 a, u32 b)
{
    u8 aS = fp_sign(a), bS = fp_sign(b);
    return (aS == bS) ? fp_add_sigs(ws, a, b, aS) : fp_sub_sigs(ws, a, b, aS);
}

static u32 fp_sub(struct vb_ws *ws, u32 a, u32 b)
{
    u8 aS = fp_sign(a), bS = fp_sign(b);
    return (aS == bS) ? fp_sub_sigs(ws, a, b, aS) : fp_add_sigs(ws, a, b, aS);
}

static u32 fp_mul(struct vb_ws *ws, u32 a, u32 b)
{
    u32 aSig = fp_frac(a), bSig = fp_frac(b), zSig0, zSig1;
    s16 aExp = fp_exp(a), bExp = fp_exp(b), zExp;
    u8  zSign = fp_sign(a) ^ fp_sign(b);
    if (aExp == 0xFF) {
        if (aSig || (bExp == 0xFF && bSig))
            return fp_prop_nan(ws, a, b);
        if (((u32)bExp | bSig) == 0) {
            ws->fp_flags |= FP_FLAG_INVALID;
            return FP_DEFAULT_NAN;
        }
        return fp_pack(zSign, 0xFF, 0);
    }
    if (bExp == 0xFF) {
        if (bSig)
            return fp_prop_nan(ws, a, b);
        if (((u32)aExp | aSig) == 0) {
            ws->fp_flags |= FP_FLAG_INVALID;
            return FP_DEFAULT_NAN;
        }
        return fp_pack(zSign, 0xFF, 0);
    }
    if (aExp == 0) {
        if (aSig == 0)
            return fp_pack(zSign, 0, 0);
        fp_norm_subnormal(aSig, &aExp, &aSig);
    }
    if (bExp == 0) {
        if (bSig == 0)
            return fp_pack(zSign, 0, 0);
        fp_norm_subnormal(bSig, &bExp, &bSig);
    }
    zExp = (s16)(aExp + bExp - 0x7F);
    aSig = (aSig | 0x00800000u) << 7;
    bSig = (bSig | 0x00800000u) << 8;
    fp_mul32to64(aSig, bSig, &zSig0, &zSig1);
    zSig0 |= (zSig1 != 0);
    if ((s32)(zSig0 << 1) >= 0) {
        zSig0 <<= 1;
        --zExp;
    }
    return fp_round_pack(ws, zSign, zExp, zSig0);
}

static u32 fp_div(struct vb_ws *ws, u32 a, u32 b)
{
    u32 aSig = fp_frac(a), bSig = fp_frac(b), zSig, rem0, rem1, term0, term1;
    s16 aExp = fp_exp(a), bExp = fp_exp(b), zExp;
    u8  zSign = fp_sign(a) ^ fp_sign(b);
    if (aExp == 0xFF) {
        if (aSig)
            return fp_prop_nan(ws, a, b);
        if (bExp == 0xFF) {
            if (bSig)
                return fp_prop_nan(ws, a, b);
            ws->fp_flags |= FP_FLAG_INVALID;
            return FP_DEFAULT_NAN;
        }
        return fp_pack(zSign, 0xFF, 0);
    }
    if (bExp == 0xFF)
        return bSig ? fp_prop_nan(ws, a, b) : fp_pack(zSign, 0, 0);
    if (bExp == 0) {
        if (bSig == 0) {
            if (((u32)aExp | aSig) == 0) {
                ws->fp_flags |= FP_FLAG_INVALID;
                return FP_DEFAULT_NAN;
            }
            ws->fp_flags |= FP_FLAG_DIVBYZERO;
            return fp_pack(zSign, 0xFF, 0);
        }
        fp_norm_subnormal(bSig, &bExp, &bSig);
    }
    if (aExp == 0) {
        if (aSig == 0)
            return fp_pack(zSign, 0, 0);
        fp_norm_subnormal(aSig, &aExp, &aSig);
    }
    zExp = (s16)(aExp - bExp + 0x7D);
    aSig = (aSig | 0x00800000u) << 7;
    bSig = (bSig | 0x00800000u) << 8;
    if (bSig <= (aSig + aSig)) {
        aSig >>= 1;
        ++zExp;
    }
    zSig = fp_est_div64to32(aSig, 0, bSig);
    if ((zSig & 0x3Fu) <= 2) {
        fp_mul32to64(bSig, zSig, &term0, &term1);
        fp_sub64(aSig, 0, term0, term1, &rem0, &rem1);
        while ((s32)rem0 < 0) {
            --zSig;
            fp_add64(rem0, rem1, 0, bSig, &rem0, &rem1);
        }
        zSig |= (rem1 != 0);
    }
    return fp_round_pack(ws, zSign, zExp, zSig);
}

static int fp_eq(struct vb_ws *ws, u32 a, u32 b)
{
    if ((fp_exp(a) == 0xFF && fp_frac(a)) || (fp_exp(b) == 0xFF && fp_frac(b))) {
        if (fp_is_snan(a) || fp_is_snan(b))
            ws->fp_flags |= FP_FLAG_INVALID;
        return 0;
    }
    return (a == b) || ((u32)((a | b) << 1) == 0);
}

static int fp_lt(struct vb_ws *ws, u32 a, u32 b)
{
    if ((fp_exp(a) == 0xFF && fp_frac(a)) || (fp_exp(b) == 0xFF && fp_frac(b))) {
        ws->fp_flags |= FP_FLAG_INVALID;
        return 0;
    }
    u8 aS = fp_sign(a), bS = fp_sign(b);
    if (aS != bS)
        return aS && ((u32)((a | b) << 1) != 0);
    return (a != b) && (aS ^ (a < b));
}

/* ========================================================================
 * Interrupt & Event Scheduler
 * ======================================================================== */

static inline void v810_recalc_ipending(struct vb_ws *ws)
{
    ws->ipending_cache = 0;
    if (ws->ilevel < 0)
        return;
    if (ws->halted == HALT_FATAL)
        return;
    if (ws->s_reg[SR_PSW] & (PSW_NP | PSW_EP | PSW_ID))
        return;
    if (ws->ilevel < (s32)((ws->s_reg[SR_PSW] & PSW_IA) >> 16))
        return;
    ws->ipending_cache = 0xFFu;
}

static void vbirq_assert(struct vb_ws *ws, int source, int assert_line)
{
    if (assert_line)
        ws->irq_asserted |= (1u << source);
    else
        ws->irq_asserted &= ~(1u << source);

    int lvl = -1;
    for (int i = 4; i >= 0; i--) {
        if (ws->irq_asserted & (1u << i)) {
            lvl = i;
            break;
        }
    }
    ws->ilevel = lvl;
    v810_recalc_ipending(ws);
}

static inline s32 vb_calc_next_ts(const struct vb_ws *ws)
{
    s32 nt = ws->next_vip_ts;
    if (nt > ws->next_timer_ts)
        nt = ws->next_timer_ts;
    if (nt > ws->next_input_ts)
        nt = ws->next_input_ts;
    return nt;
}

static inline void vb_set_event(struct vb_ws *ws, int type, s32 next_ts)
{
    if (type == 0)
        ws->next_vip_ts = next_ts;
    else if (type == 1)
        ws->next_timer_ts = next_ts;
    else
        ws->next_input_ts = next_ts;
    if (next_ts < ws->next_event_ts)
        ws->next_event_ts = next_ts;
}

/* ========================================================================
 * VSU 6-Channel Wavetable + Sweep/Mod + Noise Audio @ 48 kHz
 * ======================================================================== */

static const u8 vsu_tap_lut[8] = { 14, 10, 13, 4, 8, 6, 9, 11 };

static inline s32 vsu_calc_mono(const struct vb_ws *ws)
{
    s32 total = 0;
    for (int ch = 0; ch < 6; ch++) {
        if (!(ws->vsu_intl[ch] & 0x80u))
            continue;
        s32 wd;
        if (ch == 5) {
            wd = (s32)ws->vsu_noise_latch;
        } else {
            if (ws->vsu_ram_addr[ch] > 4)
                wd = 0;
            else
                wd = ws->vsu_wave[ws->vsu_ram_addr[ch]][ws->vsu_wave_pos[ch] & 0x1F];
        }
        s32 l_ol = ws->vsu_env[ch] * ws->vsu_left[ch];
        if (l_ol)
            l_ol = (l_ol >> 3) + 1;
        s32 r_ol = ws->vsu_env[ch] * ws->vsu_right[ch];
        if (r_ol)
            r_ol = (r_ol >> 3) + 1;
        total += wd * (l_ol + r_ol);
    }
    return total >> 1;
}

static void vsu_step_clocks(struct vb_ws *ws, s32 clocks)
{
    if (clocks <= 0)
        return;
    for (int ch = 0; ch < 6; ch++) {
        if (!(ws->vsu_intl[ch] & 0x80u))
            continue;
        s32 rem = clocks;
        while (rem > 0) {
            s32 chunk = rem;
            if (chunk > ws->vsu_fx_div[ch])
                chunk = ws->vsu_fx_div[ch];
            if (ch == 5) {
                if (chunk > ws->vsu_noise_div)
                    chunk = ws->vsu_noise_div;
            } else {
                if (ws->vsu_eff_freq[ch] >= 2040) {
                    if (chunk > ws->vsu_latcher_div[ch])
                        chunk = ws->vsu_latcher_div[ch];
                } else {
                    if (chunk > ws->vsu_freq_cnt[ch])
                        chunk = ws->vsu_freq_cnt[ch];
                }
            }
            if (chunk < 1)
                chunk = 1;

            ws->vsu_freq_cnt[ch] -= chunk;
            while (ws->vsu_freq_cnt[ch] <= 0) {
                if (ch == 5) {
                    u32 tap = vsu_tap_lut[(ws->vsu_env_ctrl[5] >> 12) & 7u];
                    u32 fb = ((ws->vsu_lfsr >> 7) & 1u) ^ ((ws->vsu_lfsr >> tap) & 1u) ^ 1u;
                    ws->vsu_lfsr = ((ws->vsu_lfsr << 1) & 0x7FFFu) | fb;
                    s32 step = 10 * (2048 - ws->vsu_eff_freq[5]);
                    ws->vsu_freq_cnt[5] += (step > 0) ? step : 10;
                } else {
                    s32 step = 2048 - ws->vsu_eff_freq[ch];
                    ws->vsu_freq_cnt[ch] += (step > 0) ? step : 1;
                    ws->vsu_wave_pos[ch] = (ws->vsu_wave_pos[ch] + 1) & 0x1F;
                }
            }

            ws->vsu_latcher_div[ch] -= chunk;
            while (ws->vsu_latcher_div[ch] <= 0)
                ws->vsu_latcher_div[ch] += 120;

            if (ch == 5) {
                ws->vsu_noise_div -= chunk;
                while (ws->vsu_noise_div <= 0) {
                    ws->vsu_noise_div += 120;
                    ws->vsu_noise_latch = (ws->vsu_lfsr & 1u) ? 63u : 0u;
                }
            }

            ws->vsu_fx_div[ch] -= chunk;
            while (ws->vsu_fx_div[ch] <= 0) {
                ws->vsu_fx_div[ch] += 4800;
                ws->vsu_intl_div[ch]--;
                while (ws->vsu_intl_div[ch] <= 0) {
                    ws->vsu_intl_div[ch] += 4;
                    if (ws->vsu_intl[ch] & 0x20u) {
                        ws->vsu_intl_cnt[ch]--;
                        if (ws->vsu_intl_cnt[ch] <= 0)
                            ws->vsu_intl[ch] &= ~0x80u;
                    }
                    ws->vsu_env_div[ch]--;
                    while (ws->vsu_env_div[ch] <= 0) {
                        ws->vsu_env_div[ch] += 4;
                        if (ws->vsu_env_ctrl[ch] & 0x0100u) {
                            ws->vsu_env_cnt[ch]--;
                            if (ws->vsu_env_cnt[ch] <= 0) {
                                ws->vsu_env_cnt[ch] = (ws->vsu_env_ctrl[ch] & 7u) + 1;
                                if (ws->vsu_env_ctrl[ch] & 0x0008u) {
                                    if (ws->vsu_env[ch] < 0xF || (ws->vsu_env_ctrl[ch] & 0x0200u))
                                        ws->vsu_env[ch] = (ws->vsu_env[ch] + 1) & 0xF;
                                } else {
                                    if (ws->vsu_env[ch] > 0 || (ws->vsu_env_ctrl[ch] & 0x0200u))
                                        ws->vsu_env[ch] = (ws->vsu_env[ch] - 1) & 0xF;
                                }
                            }
                        }
                    }
                }
                if (ch == 4) {
                    ws->vsu_sweep_div--;
                    while (ws->vsu_sweep_div <= 0) {
                        ws->vsu_sweep_div += (ws->vsu_sweep & 0x80u) ? 8 : 1;
                        if (((ws->vsu_sweep >> 4) & 7u) && (ws->vsu_env_ctrl[4] & 0x4000u)) {
                            if (ws->vsu_sweep_cnt > 0)
                                ws->vsu_sweep_cnt--;
                            if (ws->vsu_sweep_cnt <= 0) {
                                ws->vsu_sweep_cnt = (ws->vsu_sweep >> 4) & 7u;
                                if (ws->vsu_env_ctrl[4] & 0x1000u) {
                                    if (ws->vsu_mod_pos < 32 || (ws->vsu_env_ctrl[4] & 0x2000u)) {
                                        ws->vsu_mod_pos &= 0x1F;
                                        ws->vsu_eff_freq[4] = (ws->vsu_freq[4] + (s8)ws->vsu_mod[ws->vsu_mod_pos]) & 0x7FF;
                                        ws->vsu_mod_pos++;
                                    }
                                } else {
                                    s32 delta = ws->vsu_eff_freq[4] >> (ws->vsu_sweep & 7u);
                                    s32 nf = ws->vsu_eff_freq[4] + ((ws->vsu_sweep & 8u) ? delta : -delta);
                                    if (nf < 0)
                                        ws->vsu_eff_freq[4] = 0;
                                    else if (nf > 0x7FF)
                                        ws->vsu_intl[4] &= ~0x80u;
                                    else
                                        ws->vsu_eff_freq[4] = nf;
                                }
                            }
                        }
                    }
                }
            }
            rem -= chunk;
            if (!(ws->vsu_intl[ch] & 0x80u))
                break;
        }
    }
}

/* VSU runs at 5,000,000 Hz (VB_MASTER_CLOCK / 4). Emit 48 kHz mono samples. */
static void vsu_update(struct vb_ws *ws, s32 vsu_ts)
{
    s32 clocks = vsu_ts - ws->vsu_last_ts;
    if (clocks <= 0)
        return;
    ws->vsu_last_ts = vsu_ts;

    if (!ws->audio_hz) {
        vsu_step_clocks(ws, clocks);
        return;
    }

    while (clocks > 0) {
        /* Clocks until next audio sample: ceil((5000000 - phase) / hz) */
        u32 rem_phase = 5000000u - ws->audio_phase;
        s32 step = (s32)((rem_phase + ws->audio_hz - 1u) / ws->audio_hz);
        if (step < 1)
            step = 1;
        if (step > clocks)
            step = clocks;

        vsu_step_clocks(ws, step);
        clocks -= step;
        ws->audio_phase += (u32)step * ws->audio_hz;

        while (ws->audio_phase >= 5000000u) {
            ws->audio_phase -= 5000000u;
            s32 raw = vsu_calc_mono(ws) << 4;
            ws->audio_dc += (raw - ws->audio_dc) >> 8;
            s32 pcm = (raw - ws->audio_dc) * 3 >> 3;
            if (pcm > 32767) pcm = 32767;
            if (pcm < -32768) pcm = -32768;
            if (ws->audio_w - ws->audio_r < VB_AUDIO_RING)
                ws->audio_ring[ws->audio_w++ & (VB_AUDIO_RING - 1)] = (s16)pcm;
        }
    }
}

static void vsu_write(struct vb_ws *ws, s32 vsu_ts, u32 A, u8 V)
{
    if (A & 3u)
        return;
    A &= 0x7FFu;
    vsu_update(ws, vsu_ts);

    if (A < 0x280u) {
        ws->vsu_wave[A >> 7][(A >> 2) & 0x1Fu] = V & 0x3Fu;
    } else if (A < 0x400u) {
        ws->vsu_mod[(A >> 2) & 0x1Fu] = V;
    } else if (A < 0x600u) {
        int ch = (int)((A >> 6) & 0xFu);
        if (ch > 5) {
            if (A == 0x580u && (V & 1u)) {
                for (int i = 0; i < 6; i++)
                    ws->vsu_intl[i] &= ~0x80u;
            }
            return;
        }
        switch ((A >> 2) & 0xFu) {
        case 0x0:
            ws->vsu_intl[ch] = V & ~0x40u;
            if (V & 0x80u) {
                ws->vsu_eff_freq[ch] = ws->vsu_freq[ch];
                ws->vsu_freq_cnt[ch] = (ch == 5) ? (10 * (2048 - ws->vsu_eff_freq[5]))
                                                 : (2048 - ws->vsu_eff_freq[ch]);
                ws->vsu_intl_cnt[ch] = (V & 0x1Fu) + 1;
                ws->vsu_env_cnt[ch]  = (ws->vsu_env_ctrl[ch] & 7u) + 1;
                if (ch == 4) {
                    ws->vsu_sweep_cnt = (ws->vsu_sweep >> 4) & 7u;
                    ws->vsu_sweep_div = (ws->vsu_sweep & 0x80u) ? 8 : 1;
                    ws->vsu_mod_pos = 0;
                }
                ws->vsu_wave_pos[ch] = 0;
                if (ch == 5)
                    ws->vsu_lfsr = 1;
                ws->vsu_fx_div[ch]   = 4800;
                ws->vsu_intl_div[ch] = 4;
                ws->vsu_env_div[ch]  = 4;
            }
            break;
        case 0x1:
            ws->vsu_left[ch]  = (V >> 4) & 0xFu;
            ws->vsu_right[ch] = V & 0xFu;
            break;
        case 0x2:
            ws->vsu_freq[ch]     = (u16)((ws->vsu_freq[ch] & 0xFF00u) | V);
            ws->vsu_eff_freq[ch] = (ws->vsu_eff_freq[ch] & 0xFF00) | V;
            break;
        case 0x3:
            ws->vsu_freq[ch]     = (u16)((ws->vsu_freq[ch] & 0x00FFu) | ((u16)(V & 7u) << 8));
            ws->vsu_eff_freq[ch] = (ws->vsu_eff_freq[ch] & 0x00FF) | ((s32)(V & 7u) << 8);
            break;
        case 0x4:
            ws->vsu_env_ctrl[ch] = (u16)((ws->vsu_env_ctrl[ch] & 0xFF00u) | V);
            ws->vsu_env[ch]      = (V >> 4) & 0xFu;
            break;
        case 0x5:
            ws->vsu_env_ctrl[ch] &= 0x00FFu;
            if (ch == 4) {
                ws->vsu_env_ctrl[4] |= (u16)(V & 0x73u) << 8;
            } else if (ch == 5) {
                ws->vsu_env_ctrl[5] |= (u16)(V & 0x73u) << 8;
                ws->vsu_lfsr = 1;
            } else {
                ws->vsu_env_ctrl[ch] |= (u16)(V & 0x03u) << 8;
            }
            break;
        case 0x6:
            ws->vsu_ram_addr[ch] = V & 0xFu;
            break;
        case 0x7:
            if (ch == 4)
                ws->vsu_sweep = V;
            break;
        }
    }
}

/* ========================================================================
 * Hardware Timer & Serial Gamepad I/O ($02000000..$0200002F)
 * ======================================================================== */

static s32 vb_timer_update(struct vb_ws *ws, s32 ts)
{
    s32 run = ts - ws->timer_last_ts;
    if (ws->timer_ctrl & TC_TENABLE) {
        ws->timer_divider -= run;
        while (ws->timer_divider <= 0) {
            if (!ws->timer_counter || ws->timer_reload_pending) {
                ws->timer_counter = ws->timer_reload;
                ws->timer_reload_pending = 0;
            }
            if (ws->timer_counter)
                ws->timer_counter--;
            if (!ws->timer_counter || ws->timer_status)
                ws->timer_status_shadow = ws->timer_status = 1;
            vbirq_assert(ws, VBIRQ_TIMER,
                         ws->timer_status_shadow && (ws->timer_ctrl & TC_TIMZINT));
            ws->timer_divider += (ws->timer_ctrl & TC_TCLKSEL) ? 400 : 2000;
        }
    }
    ws->timer_last_ts = ts;
    return (ws->timer_ctrl & TC_TENABLE) ? (ts + ws->timer_divider) : VB_EVENT_NEVER;
}

static u8 vb_timer_read(struct vb_ws *ws, s32 ts, u32 A)
{
    vb_timer_update(ws, ts);
    switch (A & 0xFFu) {
    case 0x18: return (u8)ws->timer_counter;
    case 0x1C: return (u8)(ws->timer_counter >> 8);
    case 0x20: return (u8)(ws->timer_ctrl | 0xE0u | TC_ZSTATCLR | (ws->timer_status ? TC_ZSTAT : 0));
    }
    return 0;
}

static void vb_timer_write(struct vb_ws *ws, s32 ts, u32 A, u8 V)
{
    if (A & 3u)
        return;
    vb_timer_update(ws, ts);
    switch (A & 0xFFu) {
    case 0x18:
        ws->timer_reload = (u16)((ws->timer_reload & 0xFF00u) | V);
        ws->timer_reload_pending = 1;
        break;
    case 0x1C:
        ws->timer_reload = (u16)((ws->timer_reload & 0x00FFu) | ((u16)V << 8));
        ws->timer_reload_pending = 1;
        break;
    case 0x20:
        if (V & TC_ZSTATCLR) {
            if (!((ws->timer_ctrl & TC_TENABLE) && ws->timer_counter == 0))
                ws->timer_status = 0;
            ws->timer_status_shadow = 0;
        }
        if ((V & TC_TENABLE) && !(ws->timer_ctrl & TC_TENABLE))
            ws->timer_divider = (V & TC_TCLKSEL) ? 400 : 2000;
        ws->timer_ctrl = V & (TC_TCLKSEL | TC_TIMZINT | TC_TENABLE);
        if (!(ws->timer_ctrl & TC_TIMZINT))
            ws->timer_status = ws->timer_status_shadow = 0;
        vbirq_assert(ws, VBIRQ_TIMER,
                     ws->timer_status_shadow && (ws->timer_ctrl & TC_TIMZINT));
        if (ws->timer_ctrl & TC_TENABLE)
            vb_set_event(ws, 1, ts + ws->timer_divider);
        break;
    }
}

static s32 vb_input_update(struct vb_ws *ws, s32 ts)
{
    s32 clocks = ts - ws->input_last_ts;
    if (ws->read_counter > 0) {
        ws->read_counter -= clocks;
        while (ws->read_counter <= 0) {
            if (ws->read_bit_pos < 16) {
                ws->sdr &= (u16)~(1u << ws->read_bit_pos);
                ws->sdr |= (u16)(ws->pad_latched & (1u << ws->read_bit_pos));
                ws->read_bit_pos++;
            }
            if (ws->read_bit_pos < 16) {
                ws->read_counter += 640;
            } else {
                if (!(ws->scr & SCR_K_INT_INH)) {
                    ws->input_int_pending = 1;
                    vbirq_assert(ws, VBIRQ_INPUT, 1);
                }
                break;
            }
        }
    }
    ws->input_last_ts = ts;
    return (ws->read_counter > 0) ? (ts + ws->read_counter) : VB_EVENT_NEVER;
}

static u8 vb_input_read(struct vb_ws *ws, s32 ts, u32 A)
{
    u8 ret = 0;
    vb_input_update(ws, ts);
    switch (A & 0xFFu) {
    case 0x10: ret = (u8)(ws->pad_data & 0xFFu); break;
    case 0x14: ret = (u8)(ws->pad_data >> 8); break;
    case 0x28:
        ret = (u8)(ws->scr | 0x48u | SCR_HW_SI | ((ws->read_counter > 0) ? SCR_SI_STAT : 0));
        break;
    }
    vb_set_event(ws, 2, (ws->read_counter > 0) ? (ts + ws->read_counter) : VB_EVENT_NEVER);
    return ret;
}

static void vb_input_write(struct vb_ws *ws, s32 ts, u32 A, u8 V)
{
    vb_input_update(ws, ts);
    if ((A & 0xFFu) == 0x28u) {
        if ((V & SCR_HW_SI) && !(ws->scr & SCR_S_ABT_DIS) && ws->read_counter <= 0) {
            ws->pad_latched = ws->pad_data;
            ws->read_bit_pos = 0;
            ws->read_counter = 640;
        }
        if (V & SCR_S_ABT_DIS) {
            ws->read_counter = 0;
            ws->read_bit_pos = 0;
        }
        if (V & SCR_K_INT_INH) {
            ws->input_int_pending = 0;
            vbirq_assert(ws, VBIRQ_INPUT, 0);
        }
        ws->scr = V & (0x80u | 0x20u | 0x10u | 0x01u);
    }
    vb_set_event(ws, 2, (ws->read_counter > 0) ? (ts + ws->read_counter) : VB_EVENT_NEVER);
}

/* ========================================================================
 * Virtual Image Processor (VIP): 384x224 Worlds, Affine, HBias, OBJs
 * ======================================================================== */

static inline void vip_check_irq(struct vb_ws *ws)
{
    vbirq_assert(ws, VBIRQ_VIP, (ws->vip_ienable & ws->vip_ipending) != 0);
}

static void vip_recalc_brightness(struct vb_ws *ws)
{
    s32 cum = ((s32)ws->brta + 1 + (s32)ws->brtb + 1 + (s32)ws->brtc + 1 + (s32)ws->rest + 1) + 1;
    s32 max_t = 128;
    ws->bright_cache[0] = 0;
    ws->bright_cache[1] = 0;
    ws->bright_cache[2] = 0;
    ws->bright_cache[3] = 0;

    for (u32 i = 0; i < (u32)ws->repeat + 1u; i++) {
        s32 base = (s32)i * cum;
        if (base >= max_t)
            break;
        s32 b1 = base + ws->brta;
        if (b1 > max_t) b1 = max_t;
        b1 -= base;
        if (b1 < 0) b1 = 0;

        s32 b2 = base + ws->brta + 1 + ws->brtb;
        if (b2 > max_t) b2 = max_t;
        b2 -= base + ws->brta + 1;
        if (b2 < 0) b2 = 0;

        s32 b3 = base + ws->brta + ws->brtb + ws->brtc + 1;
        if (b3 > max_t) b3 = max_t;
        b3 -= base + 1;
        if (b3 < 0) b3 = 0;

        ws->bright_cache[1] += b1;
        ws->bright_cache[2] += b2;
        ws->bright_cache[3] += b3;
    }

    for (int i = 0; i < 4; i++) {
        s32 v = (255 * ws->bright_cache[i]) / max_t;
        if (v < 0) v = 0;
        if (v > 255) v = 255;
        ws->bright_cache[i] = v;
        u32 g = vb_gamma_lut[v];
        switch (ws->disp_mode) {
        default:
        case VB_MODE_RED:
            ws->bright_clut[0][i] = vb_bgr555(g, 0, 0);
            ws->bright_clut[1][i] = 0;
            break;
        case VB_MODE_ANAGLYPH:
            /* Left eye = Red (R), Right eye = Electric Cyan (G, B) */
            ws->bright_clut[0][i] = vb_bgr555(g, 0, 0);
            ws->bright_clut[1][i] = vb_bgr555(0, (g * 224u) >> 8, g);
            break;
        case VB_MODE_WHITE:
            ws->bright_clut[0][i] = vb_bgr555(g, g, g);
            ws->bright_clut[1][i] = 0;
            break;
        case VB_MODE_AMBER:
            ws->bright_clut[0][i] = vb_bgr555(g, (g * 176u) >> 8, (g * 32u) >> 8);
            ws->bright_clut[1][i] = 0;
            break;
        }
    }
}

static inline void vip_recalc_gplt(struct vb_ws *ws, int w)
{
    for (int i = 0; i < 4; i++)
        ws->gplt_cache[w][i] = (u8)((ws->gplt[w] >> (i * 2)) & 3u);
}

static inline void vip_recalc_jplt(struct vb_ws *ws, int w)
{
    for (int i = 0; i < 4; i++)
        ws->jplt_cache[w][i] = (u8)((ws->jplt[w] >> (i * 2)) & 3u);
}

static inline void vb_note_status_poll(struct vb_ws *ws, s32 ts)
{
    if (ws->vip_poll_pc == ws->pc) {
        if (++ws->vip_poll_cnt >= 3 && ws->next_event_ts - ts > 16)
            ws->idle_skip_to = ws->next_event_ts - 8;
    } else {
        ws->vip_poll_pc = ws->pc;
        ws->vip_poll_cnt = 1;
    }
}

static u16 vip_read_reg(struct vb_ws *ws, s32 ts, u32 A)
{
    u16 ret = 0;
    switch (A & 0xFEu) {
    case 0x00:
        vb_note_status_poll(ws, ts);
        ret = ws->vip_ipending;
        break;
    case 0x02: ret = ws->vip_ienable; break;
    case 0x20:
        vb_note_status_poll(ws, ts);
        ret = (u16)((ws->dpctrl & 0x0702u) | 0x0040u);
        if ((ws->disp_region & 1) && ws->disp_active) {
            u32 dpbsy = 1u << ((ws->disp_region >> 1) & 1);
            if (ws->disp_fb)
                dpbsy <<= 2;
            ret |= (u16)(dpbsy << 2);
        }
        break;
    case 0x24: ret = ws->brta; break;
    case 0x26: ret = ws->brtb; break;
    case 0x28: ret = ws->brtc; break;
    case 0x2A: ret = ws->rest; break;
    case 0x30: ret = 0xFFFFu; break;
    case 0x40:
        if (ts >= ws->sbout_inactive_ts)
            vb_note_status_poll(ws, ts);
        ret = (u16)(ws->xpctrl & 2u);
        if (ws->drawing_active)
            ret |= (u16)((1u + ws->drawing_fb) << 2);
        if (ts < ws->sbout_inactive_ts)
            ret |= (u16)(0x8000u | ((ws->sb_latch & 0x1F) << 8));
        break;
    case 0x44: ret = 2; break;
    case 0x48: case 0x4A: case 0x4C: case 0x4E:
        ret = ws->spt[(A >> 1) & 3u];
        break;
    case 0x60: case 0x62: case 0x64: case 0x66:
        ret = ws->gplt[(A >> 1) & 3u];
        break;
    case 0x68: case 0x6A: case 0x6C: case 0x6E:
        ret = ws->jplt[(A >> 1) & 3u];
        break;
    case 0x70: ret = ws->bkcol; break;
    }
    return ret;
}

static void vip_write_reg(struct vb_ws *ws, u32 A, u16 V)
{
    switch (A & 0xFEu) {
    case 0x02:
        ws->vip_ienable = V & 0xE01Fu;
        vip_check_irq(ws);
        break;
    case 0x04:
        ws->vip_ipending &= (u16)~V;
        vip_check_irq(ws);
        break;
    case 0x22:
        ws->dpctrl = V & 0x0703u;
        if (V & 1u) {
            ws->disp_active = 0;
            ws->vip_ipending &= (u16)~(VIP_INT_TIME_ERR | VIP_INT_FRAME_START |
                                       VIP_INT_GAME_START | VIP_INT_RFB_END |
                                       VIP_INT_LFB_END | VIP_INT_SCAN_ERR);
            vip_check_irq(ws);
        }
        break;
    case 0x24: ws->brta = (u8)V; vip_recalc_brightness(ws); break;
    case 0x26: ws->brtb = (u8)V; vip_recalc_brightness(ws); break;
    case 0x28: ws->brtc = (u8)V; vip_recalc_brightness(ws); break;
    case 0x2A: ws->rest = (u8)V; vip_recalc_brightness(ws); break;
    case 0x2E: ws->frmcyc = V & 0xFu; break;
    case 0x42:
        ws->xpctrl = V & 0x0002u;
        ws->sbcmp = (V >> 8) & 0x1Fu;
        if (V & 1u) {
            ws->drawing_fb = ws->disp_fb;
            ws->disp_fb ^= 1u;
            ws->drawing_active = 0;
            ws->drawing_counter = 0;
            ws->vip_ipending &= (u16)~(VIP_INT_SB_HIT | VIP_INT_XP_END | VIP_INT_TIME_ERR);
            vip_check_irq(ws);
        }
        break;
    case 0x48: case 0x4A: case 0x4C: case 0x4E:
        ws->spt[(A >> 1) & 3u] = V & 0x3FFu;
        break;
    case 0x60: case 0x62: case 0x64: case 0x66:
        ws->gplt[(A >> 1) & 3u] = V & 0xFCu;
        vip_recalc_gplt(ws, (int)((A >> 1) & 3u));
        break;
    case 0x68: case 0x6A: case 0x6C: case 0x6E:
        ws->jplt[(A >> 1) & 3u] = V & 0xFCu;
        vip_recalc_jplt(ws, (int)((A >> 1) & 3u));
        break;
    case 0x70:
        ws->bkcol = V & 3u;
        break;
    }
}

static u8 vip_read8(struct vb_ws *ws, s32 ts, u32 A)
{
    A &= 0x7FFFFu;
    switch (A >> 16) {
    case 0x0:
    case 0x1:
        if ((A & 0x7FFFu) >= 0x6000u)
            return ((const u8 *)ws->chr_ram)[(A & 0x1FFFu) | ((A >> 2) & 0x6000u)];
        return ws->fb[(A >> 15) & 1u][(A >> 16) & 1u][A & 0x7FFFu];
    case 0x2:
    case 0x3:
        return ((const u8 *)ws->dram)[A & 0x1FFFFu];
    case 0x4:
    case 0x5:
        if (A >= 0x5E000u)
            return (u8)(vip_read_reg(ws, ts, A) >> ((A & 1u) * 8u));
        break;
    case 0x7:
        if (A >= 0x78000u)
            return ((const u8 *)ws->chr_ram)[A & 0x7FFFu];
        break;
    }
    return 0;
}

static u16 vip_read16(struct vb_ws *ws, s32 ts, u32 A)
{
    A &= 0x7FFFEu;
    switch (A >> 16) {
    case 0x0:
    case 0x1:
        if ((A & 0x7FFFu) >= 0x6000u)
            return ws->chr_ram[((A & 0x1FFFu) | ((A >> 2) & 0x6000u)) >> 1];
        return rd16_le(&ws->fb[(A >> 15) & 1u][(A >> 16) & 1u][A & 0x7FFFu]);
    case 0x2:
    case 0x3:
        return ws->dram[(A & 0x1FFFFu) >> 1];
    case 0x4:
    case 0x5:
        if (A >= 0x5E000u)
            return vip_read_reg(ws, ts, A);
        break;
    case 0x7:
        if (A >= 0x78000u)
            return ws->chr_ram[(A & 0x7FFFu) >> 1];
        break;
    }
    return 0;
}

static void vip_write8(struct vb_ws *ws, u32 A, u8 V)
{
    A &= 0x7FFFFu;
    switch (A >> 16) {
    case 0x0:
    case 0x1:
        if ((A & 0x7FFFu) >= 0x6000u)
            ((u8 *)ws->chr_ram)[(A & 0x1FFFu) | ((A >> 2) & 0x6000u)] = V;
        else
            ws->fb[(A >> 15) & 1u][(A >> 16) & 1u][A & 0x7FFFu] = V;
        break;
    case 0x2:
    case 0x3:
        ((u8 *)ws->dram)[A & 0x1FFFFu] = V;
        break;
    case 0x4:
    case 0x5:
        if (A >= 0x5E000u)
            vip_write_reg(ws, A, V);
        break;
    case 0x7:
        if (A >= 0x78000u)
            ((u8 *)ws->chr_ram)[A & 0x7FFFu] = V;
        break;
    }
}

static void vip_write16(struct vb_ws *ws, u32 A, u16 V)
{
    A &= 0x7FFFEu;
    switch (A >> 16) {
    case 0x0:
    case 0x1:
        if ((A & 0x7FFFu) >= 0x6000u)
            ws->chr_ram[((A & 0x1FFFu) | ((A >> 2) & 0x6000u)) >> 1] = V;
        else
            wr16_le(&ws->fb[(A >> 15) & 1u][(A >> 16) & 1u][A & 0x7FFFu], V);
        break;
    case 0x2:
    case 0x3:
        ws->dram[(A & 0x1FFFFu) >> 1] = V;
        break;
    case 0x4:
    case 0x5:
        if (A >= 0x5E000u)
            vip_write_reg(ws, A, V);
        break;
    case 0x7:
        if (A >= 0x78000u)
            ws->chr_ram[(A & 0x7FFFu) >> 1] = V;
        break;
    }
}

static void vip_draw_bg(struct vb_ws *ws, u8 *target, u16 RealY, u8 bgmap_base_raw,
                        int overplane, u16 overplane_char, u32 SourceX, u32 SourceY,
                        u32 scx, u32 scy, u16 DestX, u16 DestY, u16 DestWidth, u16 DestHeight)
{
    const u16 *CHR16 = ws->chr_ram;
    const u16 *BGMap = ws->dram;
    u32 BGMap_Base = (u32)bgmap_base_raw << 12;
    const u32 bgsc_overplane = BGMap[overplane_char];
    const u32 BGMap_XCount = 1u << scx;
    const u32 BGMap_YCount = 1u << scy;
    const u32 SourceX_Size = 512u * BGMap_XCount;
    const u32 SourceY_Size = 512u * BGMap_YCount;
    const u32 SourceX_Mask = overplane ? 0x1FFFu : (SourceX_Size - 1u);
    const u32 SourceY_Mask = overplane ? 0x1FFFu : (SourceY_Size - 1u);

    if ((u16)(RealY - DestY) > DestHeight)
        return;

    DestX = (u16)sign_10_s16(DestX);
    if (DestX & 0x8000u)
        SourceX -= DestX;

    s32 start_x = (s16)DestX;
    s32 final_x = (s16)DestX + DestWidth;
    if (start_x < 0)
        start_x = 0;
    if (final_x > 383)
        final_x = 383;
    if (start_x > final_x)
        return;

    SourceY &= SourceY_Mask;
    BGMap_Base |= (((SourceY >> 3) & 0x3Fu) * 0x40u) | (((SourceY << 3) & ~0xFFFu) << scx);

    for (s32 x = start_x; x <= final_x; x++) {
        SourceX &= SourceX_Mask;
        u32 bgsc = bgsc_overplane;
        if (SourceX < SourceX_Size && SourceY < SourceY_Size)
            bgsc = BGMap[(BGMap_Base | ((SourceX << 3) & ~0xFFFu) | ((SourceX >> 3) & 0x3Fu)) & 0xFFFFu];

        u32 char_no = bgsc & 0x7FFu;
        u32 pal_sel = bgsc >> 14;
        u32 hflip_xor = (bgsc & 0x2000u) ? 7u : 0u;
        u32 vflip_xor = (bgsc & 0x1000u) ? 7u : 0u;
        u32 char_sub_y = vflip_xor ^ (SourceY & 7u);
        const u8 *plt = ws->gplt_cache[pal_sel];

        if (!(SourceX & 7u) && (x + 7) <= final_x) {
            u32 pixels = CHR16[char_no * 8u + char_sub_y];
            if (bgsc & 0x2000u) {
                if ((pixels >> 14) & 3u) target[x + 0] = plt[(pixels >> 14) & 3u];
                if ((pixels >> 12) & 3u) target[x + 1] = plt[(pixels >> 12) & 3u];
                if ((pixels >> 10) & 3u) target[x + 2] = plt[(pixels >> 10) & 3u];
                if ((pixels >>  8) & 3u) target[x + 3] = plt[(pixels >>  8) & 3u];
                if ((pixels >>  6) & 3u) target[x + 4] = plt[(pixels >>  6) & 3u];
                if ((pixels >>  4) & 3u) target[x + 5] = plt[(pixels >>  4) & 3u];
                if ((pixels >>  2) & 3u) target[x + 6] = plt[(pixels >>  2) & 3u];
                if ((pixels >>  0) & 3u) target[x + 7] = plt[(pixels >>  0) & 3u];
            } else {
                if ((pixels >>  0) & 3u) target[x + 0] = plt[(pixels >>  0) & 3u];
                if ((pixels >>  2) & 3u) target[x + 1] = plt[(pixels >>  2) & 3u];
                if ((pixels >>  4) & 3u) target[x + 2] = plt[(pixels >>  4) & 3u];
                if ((pixels >>  6) & 3u) target[x + 3] = plt[(pixels >>  6) & 3u];
                if ((pixels >>  8) & 3u) target[x + 4] = plt[(pixels >>  8) & 3u];
                if ((pixels >> 10) & 3u) target[x + 5] = plt[(pixels >> 10) & 3u];
                if ((pixels >> 12) & 3u) target[x + 6] = plt[(pixels >> 12) & 3u];
                if ((pixels >> 14) & 3u) target[x + 7] = plt[(pixels >> 14) & 3u];
            }
            x += 7;
            SourceX += 8u;
        } else {
            u32 char_sub_x = hflip_xor ^ (SourceX & 7u);
            u32 pixel = (CHR16[char_no * 8u + char_sub_y] >> (char_sub_x * 2u)) & 3u;
            if (pixel)
                target[x] = plt[pixel];
            SourceX++;
        }
    }
}

static void vip_draw_affine(struct vb_ws *ws, u8 *target, u16 RealY, int lr,
                            u32 ParamBase, u32 BGMap_Base, int OverplaneMode,
                            u16 OverplaneChar, u32 scx, u32 scy,
                            u16 DestX, u16 DestY, u16 DestWidth, u16 DestHeight)
{
    const u16 *CHR16 = ws->chr_ram;
    const u16 *BGMap = ws->dram;
    const u32 BGMap_XCount = 1u << scx;
    const u32 BGMap_YCount = 1u << scy;
    const u32 SourceX_Size = 512u * BGMap_XCount;
    const u32 SourceY_Size = 512u * BGMap_YCount;

    if ((u16)(RealY - DestY) > DestHeight)
        return;

    const u16 *param_ptr = &BGMap[(ParamBase + 8u * (u16)(RealY - DestY)) & 0xFFFFu];
    s16 mx = (s16)param_ptr[0];
    s16 mp = (s16)param_ptr[1];
    s16 my = (s16)param_ptr[2];
    s16 dx = (s16)param_ptr[3];
    s16 dy = (s16)param_ptr[4];

    DestX = (u16)sign_10_s16(DestX);
    u32 SourceX = (u32)((s32)mx << 6);
    u32 SourceY = (u32)((s32)my << 6);

    if (DestX & 0x8000u) {
        SourceX += (u32)((s32)dx * (65536 - (s32)DestX));
        SourceY += (u32)((s32)dy * (65536 - (s32)DestX));
    }
    if (mp >= 0 && lr) {
        SourceX += (u32)((s32)dx * mp);
        SourceY += (u32)((s32)dy * mp);
    } else if (mp < 0 && !lr) {
        SourceX += (u32)((s32)dx * (-mp));
        SourceY += (u32)((s32)dy * (-mp));
    }

    u32 SourceX_Mask = OverplaneMode ? 0x3FFFFFFu : ((SourceX_Size << 9) - 1u);
    u32 SourceY_Mask = OverplaneMode ? 0x3FFFFFFu : ((SourceY_Size << 9) - 1u);
    const u32 bgsc_overplane = BGMap[OverplaneChar];

    s32 start_x = (s16)DestX;
    s32 final_x = (s16)DestX + DestWidth;
    if (start_x < 0)
        start_x = 0;
    if (final_x > 383)
        final_x = 383;

    if (dy == 0) {
        SourceY &= SourceY_Mask;
        if (SourceY >= (SourceY_Size << 9))
            return;
        BGMap_Base |= (((SourceY >> 6) & ~0xFFFu) << scx) | (((SourceY >> 12) & 0x3Fu) * 0x40u);
        for (s32 x = start_x; x <= final_x; x++) {
            SourceX &= SourceX_Mask;
            u32 bgsc = bgsc_overplane;
            if (SourceX < (SourceX_Size << 9))
                bgsc = BGMap[(BGMap_Base | ((SourceX >> 6) & ~0xFFFu) | ((SourceX >> 12) & 0x3Fu)) & 0xFFFFu];
            u32 hflip_xor = (bgsc & 0x2000u) ? 0xEu : 0u;
            u32 vflip_xor = (bgsc & 0x1000u) ? 0x7u : 0u;
            u32 char_sub_y = vflip_xor ^ ((SourceY >> 9) & 7u);
            u32 char_sub_x = hflip_xor ^ ((SourceX >> 8) & 0xEu);
            u32 pixel = (CHR16[((bgsc & 0x7FFu) * 8u) | char_sub_y] >> char_sub_x) & 3u;
            if (pixel)
                target[x] = ws->gplt_cache[bgsc >> 14][pixel];
            SourceX += (u32)(s32)dx;
        }
    } else {
        for (s32 x = start_x; x <= final_x; x++) {
            SourceX &= SourceX_Mask;
            SourceY &= SourceY_Mask;
            u32 bgsc = bgsc_overplane;
            if (SourceX < (SourceX_Size << 9) && SourceY < (SourceY_Size << 9)) {
                u32 m_idx = ((SourceX >> 6) & ~0xFFFu) + (((SourceY >> 6) & ~0xFFFu) << scx);
                u32 s_idx = ((SourceX >> 12) & 0x3Fu) + (((SourceY >> 12) & 0x3Fu) * 0x40u);
                bgsc = BGMap[(BGMap_Base | m_idx | s_idx) & 0xFFFFu];
            }
            u32 char_no = bgsc & 0x7FFu;
            u32 pal_sel = bgsc >> 14;
            u32 hflip_xor = (bgsc & 0x2000u) ? 7u : 0u;
            u32 vflip_xor = (bgsc & 0x1000u) ? 7u : 0u;
            u32 char_sub_y = vflip_xor ^ ((SourceY >> 9) & 7u);
            u32 char_sub_x = hflip_xor ^ ((SourceX >> 9) & 7u);
            u32 pixel = (CHR16[char_no * 8u + char_sub_y] >> (char_sub_x * 2u)) & 3u;
            if (pixel)
                target[x] = ws->gplt_cache[pal_sel][pixel];
            SourceX += (u32)(s32)dx;
            SourceY += (u32)(s32)dy;
        }
    }
}

static void vip_draw_obj(struct vb_ws *ws, u8 *fb[2], u16 Y, const int lron[2], int obj_group)
{
    const u16 *CHR16 = ws->chr_ram;
    s32 start_oam = ws->spt[obj_group];
    s32 end_oam = obj_group ? ws->spt[obj_group - 1] : 1023;
    s32 oam = start_oam;
    do {
        const u16 *oam_ptr = &ws->dram[(0x1E000u + (u32)oam * 8u) >> 1];
        u32 jy = oam_ptr[2];
        u32 tile_y = (Y - jy) & 0xFFu;
        if (tile_y < 8u) {
            u32 jx = oam_ptr[0];
            u32 jp = oam_ptr[1] & 0x3FFFu;
            u32 pal_sel = oam_ptr[3] >> 14;
            u32 vflip_xor = (oam_ptr[3] & 0x1000u) ? 7u : 0u;
            u32 char_sub_y = vflip_xor ^ tile_y;
            int jlron[2] = { (oam_ptr[1] & 0x8000u) != 0, (oam_ptr[1] & 0x4000u) != 0 };
            u32 char_no = oam_ptr[3] & 0x7FFu;
            u32 pixels_save = CHR16[char_no * 8u + char_sub_y];
            const u8 *plt = ws->jplt_cache[pal_sel];

            for (int lr = 0; lr < 2; lr++) {
                if (!(jlron[lr] && lron[lr]))
                    continue;
                u32 pixels = pixels_save;
                s32 x = sign_x_s32(10, jx + (lr ? jp : (0u - jp)));
                if (x >= -7 && x < 384) {
                    u8 *target = &fb[lr][x];
                    if (oam_ptr[3] & 0x2000u) {
                        target += 7;
                        for (int k = 8; k; k--) {
                            if (pixels & 3u)
                                *target = plt[pixels & 3u];
                            target--;
                            pixels >>= 2;
                        }
                    } else {
                        for (int k = 8; k; k--) {
                            if (pixels & 3u)
                                *target = plt[pixels & 3u];
                            target++;
                            pixels >>= 2;
                        }
                    }
                }
            }
        }
    } while ((oam = (oam - 1) & 1023) != end_oam);
}

static void vip_draw_block(struct vb_ws *ws, u32 block_no, u8 *fb_l, u8 *fb_r)
{
    for (int y = 0; y < 8; y++) {
        vb_memset(fb_l + y * 512, ws->bkcol, 384);
        vb_memset(fb_r + y * 512, ws->bkcol, 384);
    }

    int obj_group = 3;
    for (int world = 31; world >= 0; world--) {
        const u16 *wp = &ws->dram[(0x1D800u + (u32)world * 0x20u) >> 1];
        u32 bgmap_base = wp[0] & 0xFu;
        int end  = (wp[0] & 0x0040u) != 0;
        int over = (wp[0] & 0x0080u) != 0;
        u32 scy  = (wp[0] >> 8) & 3u;
        u32 scx  = (wp[0] >> 10) & 3u;
        u32 bgm  = (wp[0] >> 12) & 3u;
        int lron[2] = { (wp[0] & 0x8000u) != 0, (wp[0] & 0x4000u) != 0 };

        if (end)
            break;

        u16 gx = (u16)sign_11_s16(wp[1]);
        u16 gp = (u16)sign_9_s16(wp[2]);
        u16 gy = (u16)sign_11_s16(wp[3]);
        u16 mx = wp[4];
        u16 mp = (u16)sign_9_s16(wp[5]);
        u16 my = wp[6];
        u16 win_w = (u16)sign_11_s16(wp[7]);
        u16 win_h = wp[8] & 0x3FFu;
        u32 param_base = wp[9];
        u16 over_char  = wp[10];

        for (int y = 0; y < 8; y++) {
            u8 *fb[2] = { &fb_l[y * 512], &fb_r[y * 512] };
            u16 real_y = (u16)(block_no * 8u + (u32)y);

            if (bgm == 3u) {
                vip_draw_obj(ws, fb, real_y, lron, obj_group);
            } else if (bgm == 2u) {
                for (int lr = 0; lr < 2; lr++) {
                    if (lron[lr]) {
                        vip_draw_affine(ws, fb[lr], real_y, lr, param_base,
                                        bgmap_base * 4096u, over, over_char, scx, scy,
                                        (u16)(gx + (lr ? gp : (u16)(0u - gp))), gy, win_w, win_h);
                    }
                }
            } else {
                for (int lr = 0; lr < 2; lr++) {
                    if (!lron[lr])
                        continue;
                    u16 srcX = (u16)(mx + (lr ? mp : (u16)(0u - mp)));
                    u16 srcY = (u16)(my + (real_y - gy));
                    u16 dstX = (u16)(gx + (lr ? gp : (u16)(0u - gp)));
                    if (bgm == 1u)
                        srcX = (u16)(srcX + ws->dram[((param_base + (u32)(u16)(real_y - gy) * 2u) | (u32)lr) & 0xFFFFu]);
                    vip_draw_bg(ws, fb[lr], real_y, (u8)bgmap_base, over, over_char,
                                (u32)(s32)(s16)srcX, (u32)(s32)(s16)srcY,
                                scx, scy, dstX, gy, win_w, win_h);
                }
            }
        }
        if (bgm == 3u && obj_group > 0)
            obj_group--;
    }
}

static void vip_blit_eye(struct vb_ws *ws, int lr)
{
    if (!ws->cur_pic)
        return;
    if (lr && ws->disp_mode != VB_MODE_ANAGLYPH)
        return;

    if (!ws->disp_active) {
        if (!lr)
            vb_memset(ws->cur_pic, 0, VB_W * VB_H * 2u);
        return;
    }

    const u8 *fb_base = ws->fb[ws->disp_fb][lr];
    /* Process in 16-column strips (16 u16s = 32 bytes = 1 exact MIPS L1 D-cache line per row!) */
    for (int c0 = 0; c0 < 384; c0 += 16) {
        u16 lclut[4][4];
        for (int g = 0; g < 4; g++) {
            int col = c0 + g * 4;
            u16 ctdata = ws->dram[(0x1DFFEu - (u32)((col >> 2) * 2) - (lr ? 0u : 0x200u)) >> 1];
            if ((ctdata >> 8) != ws->repeat) {
                ws->repeat = (u8)(ctdata >> 8);
                vip_recalc_brightness(ws);
            }
            for (int k = 0; k < 4; k++)
                lclut[g][k] = ws->bright_clut[lr][k];
        }

        const u8 *s0 = fb_base + c0 * 64;
        u16 *row = ws->cur_pic + c0;
        if (lr) {
            for (int by = 0; by < 56; by++) {
                u16 *r0 = row, *r1 = row + VB_W, *r2 = row + 2 * VB_W, *r3 = row + 3 * VB_W;
                for (int c = 0; c < 16; c++) {
                    const u16 *cl = lclut[c >> 2];
                    u32 bits = s0[c * 64];
                    r0[c] |= cl[bits & 3u];
                    r1[c] |= cl[(bits >> 2) & 3u];
                    r2[c] |= cl[(bits >> 4) & 3u];
                    r3[c] |= cl[(bits >> 6) & 3u];
                }
                s0++;
                row += 4 * VB_W;
            }
        } else {
            for (int by = 0; by < 56; by++) {
                u16 *r0 = row, *r1 = row + VB_W, *r2 = row + 2 * VB_W, *r3 = row + 3 * VB_W;
                for (int c = 0; c < 16; c++) {
                    const u16 *cl = lclut[c >> 2];
                    u32 bits = s0[c * 64];
                    r0[c] = cl[bits & 3u];
                    r1[c] = cl[(bits >> 2) & 3u];
                    r2[c] = cl[(bits >> 4) & 3u];
                    r3[c] = cl[(bits >> 6) & 3u];
                }
                s0++;
                row += 4 * VB_W;
            }
        }
    }
}

static s32 vip_update(struct vb_ws *ws, s32 ts)
{
    s32 clocks = ts - ws->vip_last_ts;
    s32 run_ts = ws->vip_last_ts;

    while (clocks > 0) {
        s32 chunk = clocks;
        if (ws->drawing_counter > 0 && chunk > ws->drawing_counter)
            chunk = ws->drawing_counter;
        if (chunk > ws->column_counter)
            chunk = ws->column_counter;

        run_ts += chunk;

        if (ws->drawing_counter > 0) {
            ws->drawing_counter -= chunk;
            if (ws->drawing_counter <= 0) {
                u8 *buf_l = ws->draw_buf[0] + 8;
                u8 *buf_r = ws->draw_buf[1] + 8;
                vip_draw_block(ws, ws->drawing_block, buf_l, buf_r);

                for (int lr = 0; lr < 2; lr++) {
                    const u8 *db = ws->draw_buf[lr] + 8;
                    u8 *fbt = ws->fb[ws->drawing_fb][lr] + ws->drawing_block * 2u;
                    for (int x = 0; x < 384; x++) {
                        fbt[64 * x + 0] = (u8)((db[x + 512 * 0] << 0) |
                                               (db[x + 512 * 1] << 2) |
                                               (db[x + 512 * 2] << 4) |
                                               (db[x + 512 * 3] << 6));
                        fbt[64 * x + 1] = (u8)((db[x + 512 * 4] << 0) |
                                               (db[x + 512 * 5] << 2) |
                                               (db[x + 512 * 6] << 4) |
                                               (db[x + 512 * 7] << 6));
                    }
                }

                ws->sbout_inactive_ts = run_ts + 1120;
                ws->sb_latch = (s32)ws->drawing_block;
                if (ws->drawing_block == ws->sbcmp) {
                    ws->vip_ipending |= VIP_INT_SB_HIT;
                    vip_check_irq(ws);
                }

                ws->drawing_block++;
                if (ws->drawing_block == 28u) {
                    ws->drawing_active = 0;
                    ws->vip_ipending |= VIP_INT_XP_END;
                    vip_check_irq(ws);
                } else {
                    ws->drawing_counter += 1120 * 4;
                }
            }
        }

        ws->column_counter -= chunk;
        if (ws->column_counter == 0) {
            ws->column_counter = 259 * 384;
            ws->column = 0;
            if (ws->disp_region & 1) {
                vip_blit_eye(ws, (ws->disp_region & 2) >> 1);
                if (ws->disp_active) {
                    ws->vip_ipending |= (ws->disp_region & 2) ? VIP_INT_RFB_END : VIP_INT_LFB_END;
                    vip_check_irq(ws);
                }
            }
            ws->disp_region = (ws->disp_region + 1) & 3;
            if (ws->disp_region == 0) {
                    ws->disp_active = (ws->dpctrl & 2u) != 0;
                    if (ws->disp_active) {
                        ws->vip_ipending |= VIP_INT_FRAME_START;
                        vip_check_irq(ws);
                    }
                ws->game_frame_counter++;
                if (ws->game_frame_counter > (s32)ws->frmcyc) {
                    ws->vip_ipending |= VIP_INT_GAME_START;
                    vip_check_irq(ws);
                    if (ws->xpctrl & 2u) {
                        ws->disp_fb = ws->drawing_fb;
                        ws->drawing_fb ^= 1u;
                        ws->drawing_block = 0;
                        ws->drawing_active = 1;
                        ws->drawing_counter = 1120 * 4;
                    }
                    ws->game_frame_counter = 0;
                }
                ws->running = 0;
            }
        }
        clocks -= chunk;
    }

    ws->vip_last_ts = ts;
    s32 next_ev = ws->column_counter;
    if (ws->drawing_counter > 0 && ws->drawing_counter < next_ev)
        next_ev = ws->drawing_counter;
    return ts + next_ev;
}

/* ========================================================================
 * Physical Bus Read / Write (27-bit Virtual Boy address space)
 * ======================================================================== */

static u8 vb_hwctrl_read(struct vb_ws *ws, s32 ts, u32 A)
{
    if (A & 3u)
        return 0;
    switch (A & 0xFFu) {
    case 0x18: case 0x1C: case 0x20:
        return vb_timer_read(ws, ts, A);
    case 0x24:
        return (u8)(ws->wcr | 0xFCu);
    case 0x10: case 0x14: case 0x28:
        return vb_input_read(ws, ts, A);
    }
    return 0;
}

static void vb_hwctrl_write(struct vb_ws *ws, s32 ts, u32 A, u8 V)
{
    if (A & 3u)
        return;
    switch (A & 0xFFu) {
    case 0x18: case 0x1C: case 0x20:
        vb_timer_write(ws, ts, A, V);
        break;
    case 0x24:
        ws->wcr = V & 3u;
        break;
    case 0x10: case 0x14: case 0x28:
        vb_input_write(ws, ts, A, V);
        break;
    }
}

static u8 vb_mem_read8(struct vb_ws *ws, s32 ts, u32 A)
{
    A &= 0x07FFFFFFu;
    switch (A >> 24) {
    case 0: return vip_read8(ws, ts, A);
    case 2: return vb_hwctrl_read(ws, ts, A);
    case 5: return ws->wram[A & 0xFFFFu];
    case 6: return ws->sram[A & 0xFFFFu];
    case 7: return ws->rom_ptr[A & ws->rom_mask];
    }
    return 0;
}

static u16 vb_mem_read16(struct vb_ws *ws, s32 ts, u32 A)
{
    A &= 0x07FFFFFEu;
    switch (A >> 24) {
    case 0: return vip_read16(ws, ts, A);
    case 2: return vb_hwctrl_read(ws, ts, A);
    case 5: return rd16_le(&ws->wram[A & 0xFFFFu]);
    case 6: return rd16_le(&ws->sram[A & 0xFFFFu]);
    case 7: return rd16_le(&ws->rom_ptr[A & ws->rom_mask]);
    }
    return 0;
}

static void vb_mem_write8(struct vb_ws *ws, s32 ts, u32 A, u8 V)
{
    ws->vip_poll_cnt = 0;
    A &= 0x07FFFFFFu;
    switch (A >> 24) {
    case 0: vip_write8(ws, A, V); break;
    case 1: vsu_write(ws, (ts + (s32)ws->vsu_cycle_fix) >> 2, A, V); break;
    case 2: vb_hwctrl_write(ws, ts, A, V); break;
    case 5: ws->wram[A & 0xFFFFu] = V; break;
    case 6:
        if (ws->sram[A & 0xFFFFu] != V) {
            ws->sram[A & 0xFFFFu] = V;
            ws->sram_dirty = 1;
        }
        break;
    }
}

static void vb_mem_write16(struct vb_ws *ws, s32 ts, u32 A, u16 V)
{
    ws->vip_poll_cnt = 0;
    A &= 0x07FFFFFEu;
    switch (A >> 24) {
    case 0: vip_write16(ws, A, V); break;
    case 1: vsu_write(ws, (ts + (s32)ws->vsu_cycle_fix) >> 2, A, (u8)V); break;
    case 2: vb_hwctrl_write(ws, ts, A, (u8)V); break;
    case 5: wr16_le(&ws->wram[A & 0xFFFFu], V); break;
    case 6:
        if (rd16_le(&ws->sram[A & 0xFFFFu]) != V) {
            wr16_le(&ws->sram[A & 0xFFFFu], V);
            ws->sram_dirty = 1;
        }
        break;
    }
}

/* ========================================================================
 * NEC V810 Core Execution (I-Cache, BSTR, Custom VB Ops, SoftFloat)
 * ======================================================================== */

static inline void v810_set_flag(struct vb_ws *ws, u32 mask, int cond)
{
    if (cond)
        ws->s_reg[SR_PSW] |= mask;
    else
        ws->s_reg[SR_PSW] &= ~mask;
}

static inline void v810_set_sz(struct vb_ws *ws, u32 val)
{
    v810_set_flag(ws, PSW_Z, val == 0);
    v810_set_flag(ws, PSW_S, (val & 0x80000000u) != 0);
}

static void v810_exception(struct vb_ws *ws, u32 handler, u16 ecode)
{
    ws->in_bstr = 0;
    ws->have_src_cache = 0;
    ws->have_dst_cache = 0;

    if (ws->s_reg[SR_PSW] & PSW_NP) {
        ws->halted = HALT_FATAL;
        ws->ipending_cache = 0;
    } else if (ws->s_reg[SR_PSW] & PSW_EP) {
        ws->s_reg[SR_FEPC]  = ws->pc;
        ws->s_reg[SR_FEPSW] = ws->s_reg[SR_PSW];
        ws->s_reg[SR_ECR]   = (ws->s_reg[SR_ECR] & 0xFFFFu) | ((u32)ecode << 16);
        ws->s_reg[SR_PSW]  |= PSW_NP | PSW_ID;
        ws->s_reg[SR_PSW]  &= ~PSW_AE;
        ws->pc = 0xFFFFFFD0u;
        ws->ipending_cache = 0;
    } else {
        ws->s_reg[SR_EIPC]  = ws->pc;
        ws->s_reg[SR_EIPSW] = ws->s_reg[SR_PSW];
        ws->s_reg[SR_ECR]   = (ws->s_reg[SR_ECR] & 0xFFFF0000u) | ecode;
        ws->s_reg[SR_PSW]  |= PSW_EP | PSW_ID;
        ws->s_reg[SR_PSW]  &= ~PSW_AE;
        ws->pc = handler;
        ws->ipending_cache = 0;
    }
}

static void v810_cache_clear(struct vb_ws *ws, u32 start, u32 count)
{
    for (u32 i = 0; i < count && (i + start) < 128u; i++)
        vb_memset(&ws->icache[i + start], 0, sizeof(ws->icache[0]));
}

static void v810_cache_dump(struct vb_ws *ws, s32 *ts, u32 sa)
{
    for (u32 i = 0; i < 128u; i++) {
        u32 a0 = sa + i * 8u;
        *ts += 4;
        vb_mem_write16(ws, *ts, a0, (u16)ws->icache[i].data[0]);
        vb_mem_write16(ws, *ts, a0 | 2u, (u16)(ws->icache[i].data[0] >> 16));
        *ts += 4;
        vb_mem_write16(ws, *ts, a0 + 4u, (u16)ws->icache[i].data[1]);
        vb_mem_write16(ws, *ts, a0 + 6u, (u16)(ws->icache[i].data[1] >> 16));
    }
    for (u32 i = 0; i < 128u; i++) {
        u32 icht = ws->icache[i].tag |
                   ((u32)ws->icache[i].valid[0] << 22) |
                   ((u32)ws->icache[i].valid[1] << 23);
        u32 a = sa + 1024u + i * 4u;
        *ts += 4;
        vb_mem_write16(ws, *ts, a, (u16)icht);
        vb_mem_write16(ws, *ts, a | 2u, (u16)(icht >> 16));
    }
}

static void v810_cache_restore(struct vb_ws *ws, s32 *ts, u32 sa)
{
    for (u32 i = 0; i < 128u; i++) {
        u32 a0 = sa + i * 8u;
        *ts += 4;
        ws->icache[i].data[0] = vb_mem_read16(ws, *ts, a0) |
                                ((u32)vb_mem_read16(ws, *ts, a0 | 2u) << 16);
        *ts += 4;
        ws->icache[i].data[1] = vb_mem_read16(ws, *ts, a0 + 4u) |
                                ((u32)vb_mem_read16(ws, *ts, a0 + 6u) << 16);
    }
    for (u32 i = 0; i < 128u; i++) {
        u32 a = sa + 1024u + i * 4u;
        *ts += 4;
        u32 icht = vb_mem_read16(ws, *ts, a) | ((u32)vb_mem_read16(ws, *ts, a | 2u) << 16);
        ws->icache[i].tag = icht & 0x3FFFFFu;
        ws->icache[i].valid[0] = (u8)((icht >> 22) & 1u);
        ws->icache[i].valid[1] = (u8)((icht >> 23) & 1u);
    }
}

static void v810_set_sreg(struct vb_ws *ws, s32 *ts, u32 which, u32 val)
{
    switch (which) {
    case SR_EIPSW:
    case SR_FEPSW:
        ws->s_reg[which] = val & 0xFF3FFu;
        break;
    case SR_PSW:
        ws->s_reg[SR_PSW] = val & 0xFF3FFu;
        v810_recalc_ipending(ws);
        break;
    case SR_EIPC:
    case SR_FEPC:
    case SR_ADDTRE:
        ws->s_reg[which] = val & 0xFFFFFFFEu;
        break;
    case SR_CHCW:
        ws->s_reg[SR_CHCW] = val & 2u;
        switch (val & 0x31u) {
        case 0x01: v810_cache_clear(ws, (val >> 20) & 0xFFFu, (val >> 8) & 0xFFFu); break;
        case 0x10: v810_cache_dump(ws, ts, val & ~0xFFu); break;
        case 0x20: v810_cache_restore(ws, ts, val & ~0xFFu); break;
        }
        break;
    }
}

static inline u16 v810_rdop(struct vb_ws *ws, s32 *ts, u32 addr, s32 uncached_cost)
{
    addr &= ~1u;
    if (ws->s_reg[SR_CHCW] & 2u) {
        u32 ci  = (addr >> 3) & 0x7Fu;
        u32 sbi = (addr >> 2) & 1u;
        u32 tag = addr >> 10;
        struct v810_cache_entry *ce = &ws->icache[ci];
        if (ce->tag != tag) {
            ce->tag = tag;
            ce->valid[sbi ^ 1u] = 0;
            ce->valid[sbi] = 0;
        }
        if (!ce->valid[sbi]) {
            *ts += 3;
            u32 base = addr & ~3u;
            u32 reg = (base >> 24) & 7u;
            if (reg == 7u) {
                const u8 *p = &ws->rom_ptr[base & ws->rom_mask];
                ce->data[sbi] = rd16_le(p) | ((u32)rd16_le(p + 2) << 16);
            } else if (reg == 5u) {
                const u8 *p = &ws->wram[base & 0xFFFCu];
                ce->data[sbi] = rd16_le(p) | ((u32)rd16_le(p + 2) << 16);
            } else {
                ce->data[sbi] = vb_mem_read16(ws, *ts, base) |
                                ((u32)vb_mem_read16(ws, *ts, base | 2u) << 16);
            }
            ce->valid[sbi] = 1;
        }
        return (u16)(ce->data[sbi] >> ((addr & 2u) * 8u));
    }

    *ts += uncached_cost;
    u32 reg = (addr >> 24) & 7u;
    if (reg == 7u)
        return rd16_le(&ws->rom_ptr[addr & ws->rom_mask]);
    if (reg == 5u)
        return rd16_le(&ws->wram[addr & 0xFFFEu]);
    return vb_mem_read16(ws, *ts, addr);
}

static inline u32 bstr_rword(struct vb_ws *ws, s32 *ts, u32 a)
{
    *ts += 4;
    return vb_mem_read16(ws, *ts, a) | ((u32)vb_mem_read16(ws, *ts, a | 2u) << 16);
}

static inline void bstr_wword(struct vb_ws *ws, s32 *ts, u32 a, u32 v)
{
    *ts += 4;
    vb_mem_write16(ws, *ts, a, (u16)v);
    vb_mem_write16(ws, *ts, a | 2u, (u16)(v >> 16));
}

static int v810_bstr_subop(struct vb_ws *ws, s32 *ts, u32 sub_op)
{
    if (sub_op >= 0x10u || (!(sub_op & 8u) && sub_op >= 4u)) {
        ws->pc -= 2u;
        v810_exception(ws, EXC_INVALID_OP_ADDR, ECODE_INVALID_OP);
        return 0;
    }

    if (sub_op & 8u) {
        u32 dstoff = ws->p_reg[26] & 0x1Fu;
        u32 srcoff = ws->p_reg[27] & 0x1Fu;
        u32 len    = ws->p_reg[28];
        u32 dst    = ws->p_reg[29] & 0xFFFFFFFCu;
        u32 src    = ws->p_reg[30] & 0xFFFFFFFCu;

        while (len) {
            if (!ws->have_src_cache) {
                ws->have_src_cache = 1;
                ws->src_cache = bstr_rword(ws, ts, src);
            }
            if (!ws->have_dst_cache) {
                ws->have_dst_cache = 1;
                ws->dst_cache = bstr_rword(ws, ts, dst);
            }
            u32 sb = (ws->src_cache >> srcoff) & 1u;
            switch (sub_op) {
            case 0x08: ws->dst_cache |= sb << dstoff; break;                                   /* ORBSU */
            case 0x09: ws->dst_cache &= ~((sb ^ 1u) << dstoff); break;                         /* ANDBSU */
            case 0x0A: ws->dst_cache ^= sb << dstoff; break;                                   /* XORBSU */
            case 0x0B: ws->dst_cache = (ws->dst_cache & ~(1u << dstoff)) | (sb << dstoff); break; /* MOVBSU */
            case 0x0C: ws->dst_cache |= (sb ^ 1u) << dstoff; break;                            /* ORNBSU */
            case 0x0D: ws->dst_cache &= ~(sb << dstoff); break;                                /* ANDNBSU */
            case 0x0E: ws->dst_cache ^= (sb ^ 1u) << dstoff; break;                            /* XORNBSU */
            case 0x0F: ws->dst_cache = (ws->dst_cache & ~(1u << dstoff)) | ((sb ^ 1u) << dstoff); break; /* NOTBSU */
            }
            srcoff = (srcoff + 1u) & 0x1Fu;
            dstoff = (dstoff + 1u) & 0x1Fu;
            len--;
            if (!srcoff) {
                src += 4u;
                ws->have_src_cache = 0;
            }
            if (!dstoff) {
                bstr_wword(ws, ts, dst, ws->dst_cache);
                dst += 4u;
                ws->have_dst_cache = 0;
                if (*ts >= ws->next_event_ts)
                    break;
            }
        }
        if (ws->have_dst_cache)
            bstr_wword(ws, ts, dst, ws->dst_cache);

        ws->p_reg[26] = dstoff;
        ws->p_reg[27] = srcoff;
        ws->p_reg[28] = len;
        ws->p_reg[29] = dst;
        ws->p_reg[30] = src;
        return len != 0;
    }

    /* Bitstring search: SCH0BSU (0), SCH0BSD (1), SCH1BSU (2), SCH1BSD (3) */
    s32 inc_mul = (sub_op & 1u) ? -1 : 1;
    u32 bit_test = (sub_op >> 1) & 1u;
    u32 srcoff = ws->p_reg[27] & 0x1Fu;
    u32 len    = ws->p_reg[28];
    u32 skipped = ws->p_reg[29];
    u32 src    = ws->p_reg[30] & 0xFFFFFFFCu;
    int found  = 0;

    while (len) {
        if (!ws->have_src_cache) {
            ws->have_src_cache = 1;
            (*ts)++;
            ws->src_cache = bstr_rword(ws, ts, src);
        }
        if (((ws->src_cache >> srcoff) & 1u) == bit_test) {
            found = 1;
            srcoff -= (u32)inc_mul;
            if (srcoff & 0x20u) {
                src -= (u32)(inc_mul * 4);
                srcoff &= 0x1Fu;
            }
            break;
        }
        srcoff = (srcoff + (u32)inc_mul) & 0x1Fu;
        skipped++;
        len--;
        if (!srcoff) {
            ws->have_src_cache = 0;
            src += (u32)(inc_mul * 4);
            if (*ts >= ws->next_event_ts)
                break;
        }
    }

    ws->p_reg[27] = srcoff;
    ws->p_reg[28] = len;
    ws->p_reg[29] = skipped;
    ws->p_reg[30] = src;
    if (found) {
        v810_set_flag(ws, PSW_Z, 0);
        return 0;
    }
    if (!len)
        v810_set_flag(ws, PSW_Z, 1);
    return len != 0;
}

static int v810_fp_check_in(struct vb_ws *ws, u32 fpval)
{
    if (fpval & 0x7FFFFFFFu) {
        u32 exp = (fpval >> 23) & 0xFFu;
        if (exp == 0x00u || exp == 0xFFu) {
            ws->s_reg[SR_PSW] |= PSW_FRO;
            ws->pc -= 4u;
            v810_exception(ws, EXC_FPU_ADDR, ECODE_FRO);
            return 1;
        }
    }
    return 0;
}

static inline void v810_fp_set_flags(struct vb_ws *ws, u32 res)
{
    v810_set_flag(ws, PSW_OV, 0);
    if (!(res & 0x7FFFFFFFu)) {
        v810_set_flag(ws, PSW_Z, 1);
        v810_set_flag(ws, PSW_S, 0);
        v810_set_flag(ws, PSW_CY, 0);
    } else {
        v810_set_flag(ws, PSW_Z, 0);
        v810_set_flag(ws, PSW_S, (res & 0x80000000u) != 0);
        v810_set_flag(ws, PSW_CY, (res & 0x80000000u) != 0);
    }
}

static void v810_fp_do_exc(struct vb_ws *ws)
{
    if (ws->fp_flags & FP_FLAG_INVALID) {
        ws->s_reg[SR_PSW] |= PSW_FIV;
        ws->pc -= 4u;
        v810_exception(ws, EXC_FPU_ADDR, ECODE_FIV);
        return;
    }
    if (ws->fp_flags & FP_FLAG_DIVBYZERO) {
        ws->s_reg[SR_PSW] |= PSW_FZD;
        ws->pc -= 4u;
        v810_exception(ws, EXC_FPU_ADDR, ECODE_FZD);
        return;
    }
    if (ws->fp_flags & FP_FLAG_UNDERFLOW)
        ws->s_reg[SR_PSW] |= PSW_FUD;
    if (ws->fp_flags & FP_FLAG_INEXACT)
        ws->s_reg[SR_PSW] |= PSW_FPR;
    if (ws->fp_flags & FP_FLAG_OVERFLOW) {
        ws->s_reg[SR_PSW] |= PSW_FOV;
        ws->pc -= 4u;
        v810_exception(ws, EXC_FPU_ADDR, ECODE_FOV);
    }
}

static void v810_fpu_subop(struct vb_ws *ws, s32 *ts, u32 sub_op, u32 arg1, u32 arg2)
{
    /* Virtual Boy custom integer extensions */
    switch (sub_op) {
    case 0x08: /* XB */
        (*ts)++;
        if (arg1)
            ws->p_reg[arg1] = (ws->p_reg[arg1] & 0xFFFF0000u) |
                              ((ws->p_reg[arg1] & 0x00FFu) << 8) |
                              ((ws->p_reg[arg1] & 0xFF00u) >> 8);
        return;
    case 0x09: /* XH */
        (*ts)++;
        if (arg1)
            ws->p_reg[arg1] = (ws->p_reg[arg1] << 16) | (ws->p_reg[arg1] >> 16);
        return;
    case 0x0A: /* REV */
        (*ts)++;
        if (arg1) {
            u32 v = ws->p_reg[arg2];
            v = ((v >> 1) & 0x55555555u) | ((v & 0x55555555u) << 1);
            v = ((v >> 2) & 0x33333333u) | ((v & 0x33333333u) << 2);
            v = ((v >> 4) & 0x0F0F0F0Fu) | ((v & 0x0F0F0F0Fu) << 4);
            v = ((v >> 8) & 0x00FF00FFu) | ((v & 0x00FF00FFu) << 8);
            v = (v >> 16) | (v << 16);
            ws->p_reg[arg1] = v;
        }
        return;
    case 0x0C: /* MPYHW */
        *ts += 8;
        if (arg1) {
            u32 v = ws->p_reg[arg2] & 0x1FFFFu;
            v -= (v & 0x10000u) << 1;
            ws->p_reg[arg1] *= v;
        }
        return;
    }

    switch (sub_op) {
    case 0x00: /* CMPF.S */
        *ts += 6;
        if (!v810_fp_check_in(ws, ws->p_reg[arg1]) && !v810_fp_check_in(ws, ws->p_reg[arg2])) {
            ws->fp_flags = 0;
            v810_set_flag(ws, PSW_OV, 0);
            if (fp_eq(ws, ws->p_reg[arg1], ws->p_reg[arg2])) {
                v810_set_flag(ws, PSW_Z, 1);
                v810_set_flag(ws, PSW_S, 0);
                v810_set_flag(ws, PSW_CY, 0);
            } else {
                v810_set_flag(ws, PSW_Z, 0);
                int lt = fp_lt(ws, ws->p_reg[arg1], ws->p_reg[arg2]);
                v810_set_flag(ws, PSW_S, lt);
                v810_set_flag(ws, PSW_CY, lt);
            }
        }
        break;
    case 0x02: /* CVT.WS */
        *ts += 5;
        ws->fp_flags = 0;
        {
            u32 res = fp_i32_to_f32(ws, (s32)ws->p_reg[arg2]);
            if (!(ws->fp_flags & (FP_FLAG_INVALID | FP_FLAG_DIVBYZERO))) {
                if (arg1) ws->p_reg[arg1] = res;
                v810_fp_set_flags(ws, res);
            }
            v810_fp_do_exc(ws);
        }
        break;
    case 0x03: /* CVT.SW */
        *ts += 8;
        if (!v810_fp_check_in(ws, ws->p_reg[arg2])) {
            ws->fp_flags = 0;
            u32 res = (u32)fp_f32_to_i32(ws, ws->p_reg[arg2]);
            if (!(ws->fp_flags & (FP_FLAG_INVALID | FP_FLAG_DIVBYZERO))) {
                if (arg1) ws->p_reg[arg1] = res;
                v810_set_flag(ws, PSW_OV, 0);
                v810_set_sz(ws, res);
            }
            v810_fp_do_exc(ws);
        }
        break;
    case 0x04: /* ADDF.S */
    case 0x05: /* SUBF.S */
    case 0x06: /* MULF.S */
    case 0x07: /* DIVF.S */
        *ts += (sub_op == 0x04) ? 8 : (sub_op == 0x05) ? 11 : (sub_op == 0x06) ? 7 : 43;
        if (!v810_fp_check_in(ws, ws->p_reg[arg1]) && !v810_fp_check_in(ws, ws->p_reg[arg2])) {
            ws->fp_flags = 0;
            u32 a = ws->p_reg[arg1], b = ws->p_reg[arg2], res;
            if (sub_op == 0x04)      res = fp_add(ws, a, b);
            else if (sub_op == 0x05) res = fp_sub(ws, a, b);
            else if (sub_op == 0x06) res = fp_mul(ws, a, b);
            else                     res = fp_div(ws, a, b);
            if (((res >> 23) & 0xFFu) == 0 && (res & 0x7FFFFFu))
                ws->fp_flags |= FP_FLAG_UNDERFLOW | FP_FLAG_INEXACT;
            if (!(ws->fp_flags & (FP_FLAG_INVALID | FP_FLAG_DIVBYZERO))) {
                if (ws->fp_flags & FP_FLAG_UNDERFLOW)
                    res &= 0x80000000u;
                v810_fp_set_flags(ws, res);
                if (arg1) ws->p_reg[arg1] = res;
            }
            v810_fp_do_exc(ws);
        }
        break;
    case 0x0B: /* TRNC.SW */
        *ts += 7;
        if (!v810_fp_check_in(ws, ws->p_reg[arg2])) {
            ws->fp_flags = 0;
            u32 res = (u32)fp_f32_to_i32_trunc(ws, ws->p_reg[arg2]);
            if (!(ws->fp_flags & (FP_FLAG_INVALID | FP_FLAG_DIVBYZERO))) {
                if (arg1) ws->p_reg[arg1] = res;
                v810_set_flag(ws, PSW_OV, 0);
                v810_set_sz(ws, res);
            }
            v810_fp_do_exc(ws);
        }
        break;
    default:
        ws->pc -= 4u;
        v810_exception(ws, EXC_INVALID_OP_ADDR, ECODE_INVALID_OP);
        break;
    }
}

static inline int v810_cond_true(u32 psw, u32 cond)
{
    int z  = (psw & PSW_Z) != 0;
    int s  = (psw & PSW_S) != 0;
    int ov = (psw & PSW_OV) != 0;
    int cy = (psw & PSW_CY) != 0;
    switch (cond & 0xFu) {
    case 0x0: return ov;                    /* V */
    case 0x1: return cy;                    /* C / L */
    case 0x2: return z;                     /* Z / E */
    case 0x3: return z || cy;               /* NH */
    case 0x4: return s;                     /* S / N */
    case 0x5: return 1;                     /* T / BR */
    case 0x6: return s ^ ov;                /* LT */
    case 0x7: return (s ^ ov) || z;         /* LE */
    case 0x8: return !ov;                   /* NV */
    case 0x9: return !cy;                   /* NC / NL */
    case 0xA: return !z;                    /* NZ / NE */
    case 0xB: return !(z || cy);            /* H */
    case 0xC: return !s;                    /* NS / P */
    case 0xD: return 0;                     /* F / NOP */
    case 0xE: return !(s ^ ov);             /* GE */
    default:  return !((s ^ ov) || z);      /* GT */
    }
}

static s32 vb_event_handler(struct vb_ws *ws, s32 ts)
{
    if (ts >= ws->next_vip_ts)
        ws->next_vip_ts = vip_update(ws, ts);
    if (ts >= ws->next_timer_ts)
        ws->next_timer_ts = vb_timer_update(ws, ts);
    if (ts >= ws->next_input_ts)
        ws->next_input_ts = vb_input_update(ws, ts);
    return vb_calc_next_ts(ws);
}

#define SET_PREG(r, v) do { u32 _r = (r), _v = (v); if (_r) ws->p_reg[_r] = _v; } while (0)
#define BRANCH_ALIGN(p) do { if ((ws->s_reg[SR_CHCW] & 2u) && ((p) & 2u)) ts += 1; } while (0)
#define CHECK_HALT() do { if (ws->halted && ts < ws->next_event_ts) ts = ws->next_event_ts; } while (0)

static s32 v810_run_frame(struct vb_ws *ws)
{
    s32 ts = ws->timestamp;
    ws->running = 1;

    while (ws->running) {
        if (!ws->ipending_cache) {
            if (ws->halted) {
                ts = ws->next_event_ts;
            } else if (ws->in_bstr) {
                u32 tmpop = ws->in_bstr_to;
                ws->pc += 2u;
                if (v810_bstr_subop(ws, &ts, tmpop & 0x1Fu)) {
                    ws->pc -= 2u;
                    ws->in_bstr = 1;
                    ws->in_bstr_to = (u16)tmpop;
                } else {
                    ws->in_bstr = 0;
                    ws->have_src_cache = ws->have_dst_cache = 0;
                }
                ws->lastop = (s32)(tmpop >> 9);
            }
        }

        while (ts < ws->next_event_ts) {
            if (ws->idle_skip_to > ts) {
                ts = ws->idle_skip_to;
                ws->idle_skip_to = 0;
                if (ts >= ws->next_event_ts)
                    break;
            }
            ws->p_reg[0] = 0;

            if (ws->ipending_cache) {
                int inum = ws->ilevel;
                ws->s_reg[SR_EIPC]  = ws->pc;
                ws->s_reg[SR_EIPSW] = ws->s_reg[SR_PSW];
                ws->pc = 0xFFFFFE00u | ((u32)inum << 4);
                ws->s_reg[SR_ECR] = 0xFE00u | ((u32)inum << 4);
                ws->s_reg[SR_PSW] |= PSW_EP | PSW_ID;
                ws->s_reg[SR_PSW] &= ~PSW_AE;
                inum++;
                if (inum > 0x0F)
                    inum = 0x0F;
                ws->s_reg[SR_PSW] = (ws->s_reg[SR_PSW] & ~PSW_IA) | ((u32)inum << 16);
                ws->halted = HALT_NONE;
                ws->in_bstr = 0;
                ws->have_src_cache = ws->have_dst_cache = 0;
                ws->ipending_cache = 0;
                ws->lastop = 0xFF;
                continue;
            }

            u32 tmpop = v810_rdop(ws, &ts, ws->pc, 1);
            u32 op6 = tmpop >> 10;

            if ((op6 & 0x38u) == 0x20u) {
                /* Conditional branches Bcond / BR / NOP (op6 = 0x20..0x27) */
                u32 cond = (tmpop >> 9) & 0xFu;
                if (cond == 0xDu) {
                    /* NOP */
                    ts += 1;
                    ws->pc += 2u;
                } else if (v810_cond_true(ws->s_reg[SR_PSW], cond)) {
                    ts += 3;
                    u32 disp = (u32)sign_x_s32(9, tmpop & 0x1FEu) & 0xFFFFFFFEu;
                    ws->pc += disp;
                    BRANCH_ALIGN(ws->pc);
                } else {
                    ts += 1;
                    ws->pc += 2u;
                }
                ws->lastop = (s32)(tmpop >> 9);
                continue;
            }

            u32 r1 = tmpop & 0x1Fu;
            u32 r2 = (tmpop >> 5) & 0x1Fu;

            switch (op6) {
            case 0x00: /* MOV */
                ws->pc += 2u;
                ts += 1;
                SET_PREG(r2, ws->p_reg[r1]);
                break;

            case 0x01: /* ADD */ {
                ws->pc += 2u;
                ts += 1;
                u32 a = ws->p_reg[r2], b = ws->p_reg[r1], res = a + b;
                v810_set_flag(ws, PSW_OV, (((a ^ ~b) & (a ^ res)) & 0x80000000u) != 0);
                v810_set_flag(ws, PSW_CY, res < a);
                SET_PREG(r2, res);
                v810_set_sz(ws, res);
                break;
            }

            case 0x02: /* SUB */ {
                ws->pc += 2u;
                ts += 1;
                u32 a = ws->p_reg[r2], b = ws->p_reg[r1], res = a - b;
                v810_set_flag(ws, PSW_OV, (((a ^ b) & (a ^ res)) & 0x80000000u) != 0);
                v810_set_flag(ws, PSW_CY, res > a);
                SET_PREG(r2, res);
                v810_set_sz(ws, res);
                break;
            }

            case 0x03: /* CMP */ {
                ws->pc += 2u;
                ts += 1;
                u32 a = ws->p_reg[r2], b = ws->p_reg[r1], res = a - b;
                v810_set_sz(ws, res);
                v810_set_flag(ws, PSW_OV, (((a ^ b) & (a ^ res)) & 0x80000000u) != 0);
                v810_set_flag(ws, PSW_CY, res > a);
                break;
            }

            case 0x04: /* SHL */ {
                ws->pc += 2u;
                ts += 1;
                u32 sh = ws->p_reg[r1] & 0x1Fu;
                u32 v = ws->p_reg[r2];
                v810_set_flag(ws, PSW_CY, sh && ((v >> (32u - sh)) & 1u));
                v810_set_flag(ws, PSW_OV, 0);
                u32 res = v << sh;
                SET_PREG(r2, res);
                v810_set_sz(ws, res);
                break;
            }

            case 0x05: /* SHR */ {
                ws->pc += 2u;
                ts += 1;
                u32 sh = ws->p_reg[r1] & 0x1Fu;
                u32 v = ws->p_reg[r2];
                v810_set_flag(ws, PSW_CY, sh && ((v >> (sh - 1u)) & 1u));
                v810_set_flag(ws, PSW_OV, 0);
                u32 res = v >> sh;
                SET_PREG(r2, res);
                v810_set_sz(ws, res);
                break;
            }

            case 0x06: /* JMP */
                ts += 3;
                ws->pc = ws->p_reg[r1] & 0xFFFFFFFEu;
                BRANCH_ALIGN(ws->pc);
                break;

            case 0x07: /* SAR */ {
                ws->pc += 2u;
                ts += 1;
                u32 sh = ws->p_reg[r1] & 0x1Fu;
                u32 v = ws->p_reg[r2];
                v810_set_flag(ws, PSW_CY, sh && ((v >> (sh - 1u)) & 1u));
                v810_set_flag(ws, PSW_OV, 0);
                u32 res = (u32)((s32)v >> sh);
                SET_PREG(r2, res);
                v810_set_sz(ws, res);
                break;
            }

            case 0x08: /* MUL */ {
                ws->pc += 2u;
                ts += 13;
                s64 prod = (s64)(s32)ws->p_reg[r1] * (s64)(s32)ws->p_reg[r2];
                u32 lo = (u32)prod;
                ws->p_reg[30] = (u32)((u64)prod >> 32);
                SET_PREG(r2, lo);
                v810_set_sz(ws, r2 ? lo : 0u);
                v810_set_flag(ws, PSW_OV, prod != (s64)(s32)lo);
                ws->lastop = -1;
                continue;
            }

            case 0x09: /* DIV */ {
                ws->pc += 2u;
                ts += 38;
                u32 denom = ws->p_reg[r1];
                if (denom == 0) {
                    ws->pc -= 2u;
                    v810_exception(ws, EXC_ZERO_DIV_ADDR, ECODE_ZERO_DIV);
                    CHECK_HALT();
                } else if (ws->p_reg[r2] == 0x80000000u && denom == 0xFFFFFFFFu) {
                    v810_set_flag(ws, PSW_OV, 1);
                    ws->p_reg[30] = 0;
                    SET_PREG(r2, 0x80000000u);
                    v810_set_sz(ws, r2 ? 0x80000000u : 0u);
                } else {
                    u32 q = (u32)((s32)ws->p_reg[r2] / (s32)denom);
                    u32 rem = (u32)((s32)ws->p_reg[r2] % (s32)denom);
                    ws->p_reg[30] = rem;
                    SET_PREG(r2, q);
                    v810_set_flag(ws, PSW_OV, 0);
                    v810_set_sz(ws, q);
                }
                ws->lastop = -1;
                continue;
            }

            case 0x0A: /* MULU */ {
                ws->pc += 2u;
                ts += 13;
                u64 prod = (u64)ws->p_reg[r1] * (u64)ws->p_reg[r2];
                u32 lo = (u32)prod;
                ws->p_reg[30] = (u32)(prod >> 32);
                SET_PREG(r2, lo);
                v810_set_sz(ws, r2 ? lo : 0u);
                v810_set_flag(ws, PSW_OV, (prod >> 32) != 0);
                ws->lastop = -1;
                continue;
            }

            case 0x0B: /* DIVU */ {
                ws->pc += 2u;
                ts += 36;
                u32 denom = ws->p_reg[r1];
                if (denom == 0) {
                    ws->pc -= 2u;
                    v810_exception(ws, EXC_ZERO_DIV_ADDR, ECODE_ZERO_DIV);
                    CHECK_HALT();
                } else {
                    u32 q = ws->p_reg[r2] / denom;
                    u32 rem = ws->p_reg[r2] % denom;
                    ws->p_reg[30] = rem;
                    SET_PREG(r2, q);
                    v810_set_flag(ws, PSW_OV, 0);
                    v810_set_sz(ws, q);
                }
                ws->lastop = -1;
                continue;
            }

            case 0x0C: /* OR */ {
                ws->pc += 2u;
                ts += 1;
                u32 res = ws->p_reg[r1] | ws->p_reg[r2];
                SET_PREG(r2, res);
                v810_set_flag(ws, PSW_OV, 0);
                v810_set_sz(ws, r2 ? res : 0u);
                break;
            }

            case 0x0D: /* AND */ {
                ws->pc += 2u;
                ts += 1;
                u32 res = ws->p_reg[r1] & ws->p_reg[r2];
                SET_PREG(r2, res);
                v810_set_flag(ws, PSW_OV, 0);
                v810_set_sz(ws, r2 ? res : 0u);
                break;
            }

            case 0x0E: /* XOR */ {
                ws->pc += 2u;
                ts += 1;
                u32 res = ws->p_reg[r1] ^ ws->p_reg[r2];
                SET_PREG(r2, res);
                v810_set_flag(ws, PSW_OV, 0);
                v810_set_sz(ws, r2 ? res : 0u);
                break;
            }

            case 0x0F: /* NOT */ {
                ws->pc += 2u;
                ts += 1;
                u32 res = ~ws->p_reg[r1];
                SET_PREG(r2, res);
                v810_set_flag(ws, PSW_OV, 0);
                v810_set_sz(ws, r2 ? res : 0u);
                break;
            }

            case 0x10: /* MOV imm5 */
                ws->pc += 2u;
                ts += 1;
                SET_PREG(r2, (u32)sign_x_s32(5, r1));
                break;

            case 0x11: /* ADD imm5 */ {
                ws->pc += 2u;
                ts += 1;
                u32 a = ws->p_reg[r2], b = (u32)sign_x_s32(5, r1), res = a + b;
                v810_set_flag(ws, PSW_OV, (((a ^ ~b) & (a ^ res)) & 0x80000000u) != 0);
                v810_set_flag(ws, PSW_CY, res < a);
                SET_PREG(r2, res);
                v810_set_sz(ws, r2 ? res : 0u);
                break;
            }

            case 0x12: /* SETF */
                ws->pc += 2u;
                ts += 1;
                SET_PREG(r2, (u32)v810_cond_true(ws->s_reg[SR_PSW], r1));
                break;

            case 0x13: /* CMP imm5 */ {
                ws->pc += 2u;
                ts += 1;
                u32 a = ws->p_reg[r2], b = (u32)sign_x_s32(5, r1), res = a - b;
                v810_set_sz(ws, res);
                v810_set_flag(ws, PSW_OV, (((a ^ b) & (a ^ res)) & 0x80000000u) != 0);
                v810_set_flag(ws, PSW_CY, res > a);
                break;
            }

            case 0x14: /* SHL imm5 */ {
                ws->pc += 2u;
                ts += 1;
                u32 v = ws->p_reg[r2];
                v810_set_flag(ws, PSW_CY, r1 && ((v >> (32u - r1)) & 1u));
                v810_set_flag(ws, PSW_OV, 0);
                u32 res = v << r1;
                SET_PREG(r2, res);
                v810_set_sz(ws, r2 ? res : 0u);
                break;
            }

            case 0x15: /* SHR imm5 */ {
                ws->pc += 2u;
                ts += 1;
                u32 v = ws->p_reg[r2];
                v810_set_flag(ws, PSW_CY, r1 && ((v >> (r1 - 1u)) & 1u));
                v810_set_flag(ws, PSW_OV, 0);
                u32 res = v >> r1;
                SET_PREG(r2, res);
                v810_set_sz(ws, r2 ? res : 0u);
                break;
            }

            case 0x16: /* EI */
                ws->pc += 2u;
                ts += 1;
                ws->s_reg[SR_PSW] &= ~PSW_ID;
                v810_recalc_ipending(ws);
                break;

            case 0x17: /* SAR imm5 */ {
                ws->pc += 2u;
                ts += 1;
                u32 v = ws->p_reg[r2];
                v810_set_flag(ws, PSW_CY, r1 && ((v >> (r1 - 1u)) & 1u));
                v810_set_flag(ws, PSW_OV, 0);
                u32 res = (u32)((s32)v >> r1);
                SET_PREG(r2, res);
                v810_set_sz(ws, r2 ? res : 0u);
                break;
            }

            case 0x18: /* TRAP */
                ws->pc += 2u;
                ts += 15;
                v810_exception(ws, EXC_TRAP_BASE + (r1 & 0x10u), (u16)(ECODE_TRAP_BASE + r1));
                CHECK_HALT();
                break;

            case 0x19: /* RETI */
                ts += 10;
                if (ws->s_reg[SR_PSW] & PSW_NP) {
                    ws->pc = ws->s_reg[SR_FEPC] & 0xFFFFFFFEu;
                    ws->s_reg[SR_PSW] = ws->s_reg[SR_FEPSW];
                } else {
                    ws->pc = ws->s_reg[SR_EIPC] & 0xFFFFFFFEu;
                    ws->s_reg[SR_PSW] = ws->s_reg[SR_EIPSW];
                }
                v810_recalc_ipending(ws);
                break;

            case 0x1A: /* HALT */
                ws->pc += 2u;
                ts += 1;
                ws->halted = HALT_HALT;
                CHECK_HALT();
                break;

            case 0x1C: /* LDSR */
                ws->pc += 2u;
                ts += 1;
                v810_set_sreg(ws, &ts, r1, ws->p_reg[r2]);
                break;

            case 0x1D: /* STSR */
                ws->pc += 2u;
                ts += 1;
                SET_PREG(r2, ws->s_reg[r1]);
                break;

            case 0x1E: /* DI */
                ws->pc += 2u;
                ts += 1;
                ws->s_reg[SR_PSW] |= PSW_ID;
                ws->ipending_cache = 0;
                break;

            case 0x1F: /* BSTR */
                ws->pc += 2u;
                ts += 1;
                if (v810_bstr_subop(ws, &ts, r1)) {
                    ws->pc -= 2u;
                    ws->in_bstr = 1;
                    ws->in_bstr_to = (u16)tmpop;
                } else {
                    ws->in_bstr = 0;
                    ws->have_src_cache = ws->have_dst_cache = 0;
                }
                break;

            case 0x28: /* MOVEA */ {
                u16 imm = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                SET_PREG(r2, ws->p_reg[r1] + (u32)(s32)(s16)imm);
                break;
            }

            case 0x29: /* ADDI */ {
                u16 imm = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                u32 a = ws->p_reg[r1], b = (u32)(s32)(s16)imm, res = a + b;
                v810_set_flag(ws, PSW_OV, (((a ^ ~b) & (a ^ res)) & 0x80000000u) != 0);
                v810_set_flag(ws, PSW_CY, res < a);
                SET_PREG(r2, res);
                v810_set_sz(ws, r2 ? res : 0u);
                break;
            }

            case 0x2A: /* JR */ {
                u32 lo16 = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                u32 disp = ((tmpop & 0x3FFu) << 16) | lo16;
                ts += 3;
                ws->pc += (u32)sign_x_s32(26, disp) & 0xFFFFFFFEu;
                BRANCH_ALIGN(ws->pc);
                break;
            }

            case 0x2B: /* JAL */ {
                u32 lo16 = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                u32 disp = ((tmpop & 0x3FFu) << 16) | lo16;
                ts += 3;
                ws->p_reg[31] = ws->pc + 4u;
                ws->pc += (u32)sign_x_s32(26, disp) & 0xFFFFFFFEu;
                BRANCH_ALIGN(ws->pc);
                break;
            }

            case 0x2C: /* ORI */ {
                u32 imm = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                u32 res = ws->p_reg[r1] | imm;
                SET_PREG(r2, res);
                v810_set_flag(ws, PSW_OV, 0);
                v810_set_sz(ws, r2 ? res : 0u);
                break;
            }

            case 0x2D: /* ANDI */ {
                u32 imm = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                u32 res = ws->p_reg[r1] & imm;
                SET_PREG(r2, res);
                v810_set_flag(ws, PSW_OV, 0);
                v810_set_sz(ws, r2 ? res : 0u);
                break;
            }

            case 0x2E: /* XORI */ {
                u32 imm = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                u32 res = ws->p_reg[r1] ^ imm;
                SET_PREG(r2, res);
                v810_set_flag(ws, PSW_OV, 0);
                v810_set_sz(ws, r2 ? res : 0u);
                break;
            }

            case 0x2F: /* MOVHI */ {
                u32 imm = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                SET_PREG(r2, ws->p_reg[r1] + (imm << 16));
                break;
            }

            case 0x30: /* LD.B */ {
                u16 disp = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                u32 addr = ws->p_reg[r1] + (u32)(s32)(s16)disp;
                SET_PREG(r2, (u32)(s32)(s8)vb_mem_read8(ws, ts, addr));
                if (ws->lastop >= 0)
                    ts += (ws->lastop == LASTOP_LD) ? 1 : 2;
                ws->lastop = LASTOP_LD;
                continue;
            }

            case 0x31: /* LD.H */ {
                u16 disp = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                u32 addr = (ws->p_reg[r1] + (u32)(s32)(s16)disp) & 0xFFFFFFFEu;
                SET_PREG(r2, (u32)(s32)(s16)vb_mem_read16(ws, ts, addr));
                if (ws->lastop >= 0)
                    ts += (ws->lastop == LASTOP_LD) ? 1 : 2;
                ws->lastop = LASTOP_LD;
                continue;
            }

            case 0x33: /* LD.W */ {
                u16 disp = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                u32 addr = (ws->p_reg[r1] + (u32)(s32)(s16)disp) & 0xFFFFFFFCu;
                u32 v = vb_mem_read16(ws, ts, addr) | ((u32)vb_mem_read16(ws, ts, addr | 2u) << 16);
                SET_PREG(r2, v);
                if (ws->lastop >= 0)
                    ts += (ws->lastop == LASTOP_LD) ? 3 : 4;
                ws->lastop = LASTOP_LD;
                continue;
            }

            case 0x34: /* ST.B */ {
                u16 disp = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                vb_mem_write8(ws, ts, ws->p_reg[r1] + (u32)(s32)(s16)disp, (u8)ws->p_reg[r2]);
                if (ws->lastop == LASTOP_ST)
                    ts += 1;
                ws->lastop = LASTOP_ST;
                continue;
            }

            case 0x35: /* ST.H */ {
                u16 disp = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                vb_mem_write16(ws, ts, (ws->p_reg[r1] + (u32)(s32)(s16)disp) & 0xFFFFFFFEu, (u16)ws->p_reg[r2]);
                if (ws->lastop == LASTOP_ST)
                    ts += 1;
                ws->lastop = LASTOP_ST;
                continue;
            }

            case 0x37: /* ST.W */ {
                u16 disp = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                u32 addr = (ws->p_reg[r1] + (u32)(s32)(s16)disp) & 0xFFFFFFFCu;
                u32 v = ws->p_reg[r2];
                vb_mem_write16(ws, ts, addr, (u16)v);
                vb_mem_write16(ws, ts, addr | 2u, (u16)(v >> 16));
                if (ws->lastop == LASTOP_ST)
                    ts += 3;
                ws->lastop = LASTOP_ST;
                continue;
            }

            case 0x38: /* IN.B (zero-extended byte load on Virtual Boy) */ {
                u16 disp = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 3;
                SET_PREG(r2, (u32)vb_mem_read8(ws, ts, ws->p_reg[r1] + (u32)(s32)(s16)disp));
                ws->lastop = LASTOP_IN;
                continue;
            }

            case 0x39: /* IN.H (zero-extended halfword load on Virtual Boy) */ {
                u16 disp = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 3;
                SET_PREG(r2, (u32)vb_mem_read16(ws, ts, (ws->p_reg[r1] + (u32)(s32)(s16)disp) & 0xFFFFFFFEu));
                ws->lastop = LASTOP_IN;
                continue;
            }

            case 0x3A: /* CAXI */ {
                u16 disp = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 26;
                u32 addr = (ws->p_reg[r1] + (u32)(s32)(s16)disp) & 0xFFFFFFFCu;
                u32 memv = vb_mem_read16(ws, ts, addr) | ((u32)vb_mem_read16(ws, ts, addr | 2u) << 16);
                u32 cmp = ws->p_reg[r2] - memv;
                v810_set_sz(ws, cmp);
                v810_set_flag(ws, PSW_OV, (((ws->p_reg[r2] ^ memv) & (ws->p_reg[r2] ^ cmp)) & 0x80000000u) != 0);
                v810_set_flag(ws, PSW_CY, cmp > ws->p_reg[r2]);
                u32 wr = (cmp == 0) ? ws->p_reg[30] : memv;
                vb_mem_write16(ws, ts, addr, (u16)wr);
                vb_mem_write16(ws, ts, addr | 2u, (u16)(wr >> 16));
                SET_PREG(r2, memv);
                break;
            }

            case 0x3B: /* IN.W */ {
                u16 disp = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 5;
                u32 addr = (ws->p_reg[r1] + (u32)(s32)(s16)disp) & 0xFFFFFFFCu;
                u32 v = vb_mem_read16(ws, ts, addr) | ((u32)vb_mem_read16(ws, ts, addr | 2u) << 16);
                SET_PREG(r2, v);
                ws->lastop = LASTOP_IN;
                continue;
            }

            case 0x3C: /* OUT.B */ {
                u16 disp = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                vb_mem_write8(ws, ts, ws->p_reg[r1] + (u32)(s32)(s16)disp, (u8)ws->p_reg[r2]);
                if (ws->lastop == LASTOP_OUT)
                    ts += 1;
                ws->lastop = LASTOP_OUT;
                continue;
            }

            case 0x3D: /* OUT.H */ {
                u16 disp = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                vb_mem_write16(ws, ts, (ws->p_reg[r1] + (u32)(s32)(s16)disp) & 0xFFFFFFFEu, (u16)ws->p_reg[r2]);
                if (ws->lastop == LASTOP_OUT)
                    ts += 1;
                ws->lastop = LASTOP_OUT;
                continue;
            }

            case 0x3E: /* FPP (FPU + Virtual Boy custom ops) */ {
                u16 ext = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                v810_fpu_subop(ws, &ts, (ext >> 10) & 0x3Fu, r2, r1);
                ws->lastop = -1;
                CHECK_HALT();
                continue;
            }

            case 0x3F: /* OUT.W */ {
                u16 disp = v810_rdop(ws, &ts, ws->pc + 2u, 2);
                ws->pc += 4u;
                ts += 1;
                u32 addr = (ws->p_reg[r1] + (u32)(s32)(s16)disp) & 0xFFFFFFFCu;
                u32 v = ws->p_reg[r2];
                vb_mem_write16(ws, ts, addr, (u16)v);
                vb_mem_write16(ws, ts, addr | 2u, (u16)(v >> 16));
                if (ws->lastop == LASTOP_OUT)
                    ts += 3;
                ws->lastop = LASTOP_OUT;
                continue;
            }

            default: /* INVALID */
                ts += 1;
                v810_exception(ws, EXC_INVALID_OP_ADDR, ECODE_INVALID_OP);
                CHECK_HALT();
                break;
            }

            ws->lastop = (s32)(tmpop >> 9);
        }

        ws->next_event_ts = vb_event_handler(ws, ts);
    }

    ws->timestamp = ts;
    return ts;
}

/* ========================================================================
 * Public Lifecycle, Controls, Audio & Info API
 * ======================================================================== */

static u32 round_up_pow2(u32 v)
{
    if (v == 0)
        return 1;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return v + 1u;
}

static void vb_rebuild_info(struct vb_ws *ws)
{
    static const char *const mode_names[4] = {
        "Red/Black", "Red/Cyan 3D", "White", "Amber"
    };
    const char *mname = mode_names[ws->disp_mode & 3u];
    u32 kb = ws->rom_orig_size >> 10;
    if (!kb) kb = 1;

    char *p = ws->info_str;
    const char *pre = "Nintendo Virtual Boy (";
    while (*pre) *p++ = *pre++;

    /* KB decimal */
    char num[16];
    int n = 0;
    u32 tmp = kb;
    do { num[n++] = (char)('0' + (tmp % 10u)); tmp /= 10u; } while (tmp);
    while (n > 0) *p++ = num[--n];
    const char *kbs = " KB";
    while (*kbs) *p++ = *kbs++;

    if (ws->title[0]) {
        *p++ = ','; *p++ = ' '; *p++ = '"';
        for (int i = 0; ws->title[i] && i < 20; i++)
            *p++ = ws->title[i];
        *p++ = '"';
    }
    *p++ = ','; *p++ = ' ';
    while (*mname) *p++ = *mname++;
    *p++ = ')';
    *p = 0;
}

void vb_reset(void)
{
    struct vb_ws *ws = VB_WS;

    vb_memset(ws->wram, 0, sizeof(ws->wram));
    vb_memset(ws->fb, 0, sizeof(ws->fb));
    vb_memset(ws->chr_ram, 0, sizeof(ws->chr_ram));
    vb_memset(ws->dram, 0, sizeof(ws->dram));
    vb_memset(ws->icache, 0, sizeof(ws->icache));
    vb_memset(ws->p_reg, 0, sizeof(ws->p_reg));
    vb_memset(ws->s_reg, 0, sizeof(ws->s_reg));

    /* VIP power-on state */
    ws->vip_ipending = 0;
    ws->vip_ienable  = 0;
    ws->brta = ws->brtb = ws->brtc = ws->rest = 0;
    ws->repeat = 0;
    ws->frmcyc = 0;
    ws->dpctrl = 2;
    ws->disp_active = 0;
    ws->disp_fb = 0;
    ws->xpctrl = 0;
    ws->sbcmp = 0;
    for (int i = 0; i < 4; i++) {
        ws->spt[i] = 0;
        ws->gplt[i] = 0;
        ws->jplt[i] = 0;
        vip_recalc_gplt(ws, i);
        vip_recalc_jplt(ws, i);
    }
    ws->bkcol = 0;
    ws->vip_last_ts = 0;
    ws->column = 0;
    ws->column_counter = 259 * 384;
    ws->disp_region = 0;
    ws->game_frame_counter = 0;
    ws->drawing_counter = 0;
    ws->drawing_active = 0;
    ws->drawing_fb = 0;
    ws->drawing_block = 0;
    ws->sb_latch = 0;
    ws->sbout_inactive_ts = -1;
    vip_recalc_brightness(ws);

    /* VSU power-on state */
    ws->vsu_sweep = 0;
    ws->vsu_sweep_cnt = 0;
    ws->vsu_sweep_div = 1;
    for (int ch = 0; ch < 6; ch++) {
        ws->vsu_intl[ch] = 0;
        ws->vsu_left[ch] = 0;
        ws->vsu_right[ch] = 0;
        ws->vsu_freq[ch] = 0;
        ws->vsu_env_ctrl[ch] = 0;
        ws->vsu_ram_addr[ch] = 0;
        ws->vsu_eff_freq[ch] = 0;
        ws->vsu_env[ch] = 0;
        ws->vsu_wave_pos[ch] = 0;
        ws->vsu_freq_cnt[ch] = 1;
        ws->vsu_intl_cnt[ch] = 0;
        ws->vsu_env_cnt[ch] = 1;
        ws->vsu_fx_div[ch] = 4800;
        ws->vsu_intl_div[ch] = 4;
        ws->vsu_env_div[ch] = 4;
        ws->vsu_latcher_div[ch] = 120;
    }
    ws->vsu_mod_pos = 0;
    ws->vsu_noise_div = 120;
    ws->vsu_noise_latch = 0;
    ws->vsu_lfsr = 0;
    vb_memset(ws->vsu_wave, 0, sizeof(ws->vsu_wave));
    vb_memset(ws->vsu_mod, 0, sizeof(ws->vsu_mod));
    ws->vsu_last_ts = 0;
    ws->vsu_cycle_fix = 0;
    ws->audio_phase = 0;
    ws->audio_dc = 0;
    ws->audio_r = ws->audio_w = 0;

    /* Timer & Input power-on state */
    ws->timer_last_ts = 0;
    ws->timer_counter = 0xFFFFu;
    ws->timer_reload  = 0xFFFFu;
    ws->timer_divider = 2000;
    ws->timer_status = 0;
    ws->timer_status_shadow = 0;
    ws->timer_ctrl = 0;
    ws->timer_reload_pending = 0;

    ws->input_last_ts = 0;
    ws->pad_data = VBPAD_SIG;
    ws->pad_latched = VBPAD_SIG;
    ws->sdr = 0;
    ws->scr = 0;
    ws->read_bit_pos = 0;
    ws->read_counter = 0;
    ws->input_int_pending = 0;

    /* V810 reset state */
    ws->pc = 0xFFFFFFF0u;
    ws->s_reg[SR_ECR]  = 0x0000FFF0u;
    ws->s_reg[SR_PSW]  = 0x00008000u;
    ws->s_reg[SR_PIR]  = 0x00005346u;
    ws->s_reg[SR_TKCW] = 0x000000E0u;
    ws->halted = HALT_NONE;
    ws->ilevel = -1;
    ws->irq_asserted = 0;
    ws->lastop = 0;
    ws->in_bstr = 0;
    ws->have_src_cache = 0;
    ws->have_dst_cache = 0;
    ws->wcr = 0;
    ws->timestamp = 0;
    v810_recalc_ipending(ws);

    ws->next_vip_ts   = vip_update(ws, 0);
    ws->next_timer_ts = vb_timer_update(ws, 0);
    ws->next_input_ts = vb_input_update(ws, 0);
    ws->next_event_ts = vb_calc_next_ts(ws);
}

const char *vb_load(const u8 *rom, u32 rom_size)
{
    if (!rom || rom_size < 256u)
        return "too small for a Virtual Boy cartridge";
    if (rom_size > 0x01000000u)
        return "too large for a Virtual Boy cartridge";

    struct vb_ws *ws = VB_WS;
    u8 keep_mode = ws->disp_mode;
    u32 keep_hz  = ws->audio_hz;
    vb_memset(ws, 0, sizeof(*ws) - sizeof(ws->rom_buf));
    ws->disp_mode = (keep_mode <= VB_MODE_AMBER) ? keep_mode : VB_MODE_RED;
    ws->audio_hz  = keep_hz ? keep_hz : 48000u;

    ws->rom_orig_size = rom_size;
    u32 pow2 = round_up_pow2(rom_size);
    if (pow2 < 0x10000u)
        pow2 = 0x10000u;

    if (pow2 <= sizeof(ws->rom_buf)) {
        /* Copy and mirror ROM to fill power-of-2 window (>= 64 KB) so
           0xFFFFFFF0 maps cleanly to the top 16 bytes of the ROM image. */
        if (rom_size == round_up_pow2(rom_size)) {
            for (u32 off = 0; off < pow2; off += rom_size)
                vb_memcpy(ws->rom_buf + off, rom, rom_size);
        } else {
            /* Non-power-of-2 homebrew: place at top of pow2 window so reset vector aligns */
            vb_memset(ws->rom_buf, 0xFF, pow2 - rom_size);
            vb_memcpy(ws->rom_buf + (pow2 - rom_size), rom, rom_size);
        }
        ws->rom_ptr  = ws->rom_buf;
        ws->rom_mask = pow2 - 1u;
    } else {
        /* 8 MB / 16 MB ROMs live directly in MEDIA_PHYS */
        ws->rom_ptr  = rom;
        ws->rom_mask = pow2 - 1u;
    }

    /* Extract ASCII header title from 0xFFFFFDE0 (top - 0x220) if printable */
    ws->title[0] = 0;
    if (pow2 >= 0x400u) {
        const u8 *hdr = &ws->rom_ptr[(ws->rom_mask + 1u) - 0x220u];
        int ok = 1, last_nonspace = -1;
        for (int i = 0; i < 20; i++) {
            u8 c = hdr[i];
            if (c == 0)
                break;
            if (c < 0x20u || c > 0x7Eu) {
                ok = 0;
                break;
            }
            ws->title[i] = (char)c;
            if (c != ' ')
                last_nonspace = i;
        }
        if (!ok || last_nonspace < 0)
            ws->title[0] = 0;
        else
            ws->title[last_nonspace + 1] = 0;
    }

    vb_memset(ws->sram, 0, sizeof(ws->sram));
    ws->sram_dirty = 0;
    vb_reset();
    vb_rebuild_info(ws);
    return 0;
}

void vb_set_mode(int mode)
{
    struct vb_ws *ws = VB_WS;
    ws->disp_mode = (u8)(mode & 3);
    vip_recalc_brightness(ws);
    vb_rebuild_info(ws);
}

int vb_get_mode(void)
{
    return VB_WS->disp_mode;
}

void vb_frame(u16 pad, const u8 *hid, int hid_n, u16 *picture)
{
    struct vb_ws *ws = VB_WS;

    u16 vb_pad = VBPAD_SIG;
    if (pad & PAD_A)      vb_pad |= VBPAD_A;
    if (pad & PAD_B)      vb_pad |= VBPAD_B;
    if (pad & PAD_SELECT) vb_pad |= VBPAD_SELECT;
    if (pad & PAD_START)  vb_pad |= VBPAD_START;
    if (pad & PAD_UP)     vb_pad |= VBPAD_L_UP;
    if (pad & PAD_DOWN)   vb_pad |= VBPAD_L_DOWN;
    if (pad & PAD_LEFT)   vb_pad |= VBPAD_L_LEFT;
    if (pad & PAD_RIGHT)  vb_pad |= VBPAD_L_RIGHT;

    u8 mode_key = 0;
    if (hid && hid_n > 0) {
        for (int i = 0; i < hid_n; i++) {
            switch (hid[i]) {
            case 0x14: case 0x18: case 0x06: vb_pad |= VBPAD_L; break;       /* Q / U / C = L */
            case 0x08: case 0x12: case 0x05: vb_pad |= VBPAD_R; break;       /* E / O / B = R */
            case 0x0C: case 0x17: case 0x60: vb_pad |= VBPAD_R_UP; break;    /* I / T / KP8 = Right-Up */
            case 0x0A: case 0x5A:            vb_pad |= VBPAD_R_DOWN; break;  /* G / KP2 = Right-Down */
            case 0x09: case 0x5C:            vb_pad |= VBPAD_R_LEFT; break;  /* F / KP4 = Right-Left */
            case 0x0B: case 0x5E:            vb_pad |= VBPAD_R_RIGHT; break; /* H / KP6 = Right-Right */
            case 0x19: case 0x3B:            mode_key = 1; break;            /* V / F2 = Palette / 3D mode */
            }
        }
    }
    if (mode_key && !ws->mode_key_prev)
        vb_set_mode((ws->disp_mode + 1) & 3);
    ws->mode_key_prev = mode_key;

    /* Cancel simultaneous opposite D-pad presses */
    if ((vb_pad & (VBPAD_L_LEFT | VBPAD_L_RIGHT)) == (VBPAD_L_LEFT | VBPAD_L_RIGHT))
        vb_pad &= (u16)~(VBPAD_L_LEFT | VBPAD_L_RIGHT);
    if ((vb_pad & (VBPAD_L_UP | VBPAD_L_DOWN)) == (VBPAD_L_UP | VBPAD_L_DOWN))
        vb_pad &= (u16)~(VBPAD_L_UP | VBPAD_L_DOWN);
    if ((vb_pad & (VBPAD_R_LEFT | VBPAD_R_RIGHT)) == (VBPAD_R_LEFT | VBPAD_R_RIGHT))
        vb_pad &= (u16)~(VBPAD_R_LEFT | VBPAD_R_RIGHT);
    if ((vb_pad & (VBPAD_R_UP | VBPAD_R_DOWN)) == (VBPAD_R_UP | VBPAD_R_DOWN))
        vb_pad &= (u16)~(VBPAD_R_UP | VBPAD_R_DOWN);

    ws->pad_data = vb_pad;
    ws->cur_pic  = picture;

    s32 end_ts = v810_run_frame(ws);

    if (ws->next_vip_ts & 0x40000000)   ws->next_vip_ts   = VB_EVENT_NEVER;
    if (ws->next_timer_ts & 0x40000000) ws->next_timer_ts = VB_EVENT_NEVER;
    if (ws->next_input_ts & 0x40000000) ws->next_input_ts = VB_EVENT_NEVER;

    ws->next_vip_ts   = vip_update(ws, end_ts);
    ws->next_timer_ts = vb_timer_update(ws, end_ts);
    ws->next_input_ts = vb_input_update(ws, end_ts);

    vsu_update(ws, (end_ts + (s32)ws->vsu_cycle_fix) >> 2);
    ws->vsu_last_ts = 0;
    ws->vsu_cycle_fix = ((u32)end_ts + ws->vsu_cycle_fix) & 3u;

    /* Rebase timestamps to 0 for next frame */
    ws->timer_last_ts = 0;
    ws->input_last_ts = 0;
    if (ws->sbout_inactive_ts >= 0)
        ws->sbout_inactive_ts -= ws->vip_last_ts;
    ws->vip_last_ts = 0;

    if (ws->next_vip_ts != VB_EVENT_NEVER)   ws->next_vip_ts   -= end_ts;
    if (ws->next_timer_ts != VB_EVENT_NEVER) ws->next_timer_ts -= end_ts;
    if (ws->next_input_ts != VB_EVENT_NEVER) ws->next_input_ts -= end_ts;

    ws->next_event_ts = vb_calc_next_ts(ws);
    ws->timestamp = 0;
}

const char *vb_info(void)
{
    return VB_WS->info_str;
}

int vb_jammed(void)
{
    return VB_WS->halted == HALT_FATAL;
}

u8 *vb_save_ram(u32 *size, int *battery)
{
    *size = sizeof(VB_WS->sram);
    *battery = 1;
    return VB_WS->sram;
}

int vb_save_changed(void)
{
    return VB_WS->sram_dirty;
}

void vb_audio_rate(u32 hz)
{
    VB_WS->audio_hz = hz;
}

int vb_audio(s16 *out, int max)
{
    struct vb_ws *ws = VB_WS;
    int n = 0;
    while (n < max && ws->audio_r != ws->audio_w)
        out[n++] = ws->audio_ring[ws->audio_r++ & (VB_AUDIO_RING - 1)];
    return n;
}
