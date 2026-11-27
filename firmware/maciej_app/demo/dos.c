/* An IBM PC AT / 386DX with MS-DOS, XMS, VGA Mode X, AdLib OPL2 & Sound Blaster 2.0: see dos.h.
   - Real-mode 8086/286 cycle-compatible execution + full 80386 32-bit Protected Mode, GDT/IDT/LDT/TSS & 4 KB Paging
   - 8 MB RAM in EMU_RAM_PHYS (640 KB conventional + 7 MB Extended XMS 3.0 / INT 15h for DOS/4GW, DOOM, Wolf3D, etc.)
   - VGA text, CGA, EGA planar, Mode 13h chain-4 & Mode X unchained 256-colour page-flipped modes
   - 48 kHz Audio: Yamaha YM3812 (OPL2 / AdLib 0x388) + Sound Blaster 2.0 8-bit Auto-Init DMA PCM (0x220, IRQ 7, DMA 1) + PC Speaker
   - Multi-file virtual C:\ drive (up to 96 files + 64 KB writable RAM scratch files for .CFG / saves) */
#include "dos.h"
#include "font5x7.h"

typedef signed char s8;

#define INLINE static inline __attribute__((always_inline))

#pragma GCC push_options
#pragma GCC optimize("O2")
#include "opl2.inc"
#pragma GCC pop_options

/* ---- time ---- */
#ifndef PIT_CYCLES
#define PIT_CYCLES   12                 /* real-mode CPU cycles per 1.193182 MHz PIT tick (14.318 MHz 286 compat) */
#endif
#define FRAME_PIT    17024              /* timer ticks in a 70.09 Hz VGA frame (14268 us) */
#define FRAME_CYCLES (FRAME_PIT * PIT_CYCLES)
#define LINES        449
#define SHOWN        400
#define RETRACE_FROM 412
#define RETRACE_TO   432
#define DRAW_AT      (SHOWN * (FRAME_CYCLES / LINES))
#define SLICES       16
#define SND_RING     4096

#ifdef PM_EXACT_CPI3
#define PM_STEP_CYC       3
#define PM_CYC            3
#define PM_CYC66          6
#define PM_DIV_CYC        0
#define PM_JCC32_TAKEN    2
#define PM_FUSE_FMUL      3
#define PM_FUSE_VIS_HIT   6
#define PM_FUSE_PAT_END   12
#define PM_FUSE_VIS       18
#define PM_FUSE_MSP20     24
#define PM_FUSE_PAT       27
#define PM_FUSE_MIX       27
#define PM_FUSE_CLIP30    27
#define PM_FUSE_MSP28     30
#define PM_FUSE_DMX26     33
#define PM_FUSE_BLT27     36
#define PM_FUSE_FUZZ      42
#define PM_FUSE_FUZZ_WRAP 3
#define PM_FUSE_COL       45
#define PM_FUSE_SPN       51
#define PM_FUSE_DMX50     57
#else
#define PM_STEP_CYC       1
#ifndef PM_CYC
#define PM_CYC            5
#endif
#define PM_CYC66          (PM_CYC)
#define PM_DIV_CYC        (39 * PM_CYC)
#define PM_JCC32_TAKEN    0
#define PM_FUSE_FMUL      0
#define PM_FUSE_VIS_HIT   (PM_CYC)
#define PM_FUSE_PAT_END   (PM_CYC)
#define PM_FUSE_VIS       (2 * PM_CYC)
#define PM_FUSE_MSP20     (2 * PM_CYC)
#define PM_FUSE_PAT       (3 * PM_CYC)
#define PM_FUSE_MIX       (3 * PM_CYC)
#define PM_FUSE_CLIP30    (3 * PM_CYC)
#define PM_FUSE_MSP28     (3 * PM_CYC)
#define PM_FUSE_DMX26     (5 * PM_CYC)
#define PM_FUSE_BLT27     (4 * PM_CYC)
#define PM_FUSE_FUZZ      (5 * PM_CYC)
#define PM_FUSE_FUZZ_WRAP 0
#define PM_FUSE_COL       (5 * PM_CYC)
#define PM_FUSE_SPN       (6 * PM_CYC)
#define PM_FUSE_DMX50     (5 * PM_CYC)
#endif

/* ---- memory & zero-BSS layout in EMU_RAM_PHYS ---- */
#define RAM_BYTES    0x800000u          /* 8 MB total PC RAM (640 KB low + 7 MB XMS/386 extended) */
#define SCRATCH_CAP  0x10000u           /* 64 KB writable RAM pool for runtime created files (.CFG, saves) */

struct dos_mem {
    u8  mem[RAM_BYTES + 64] __attribute__((aligned(4)));
    u8  vram[4][65536 + 256] __attribute__((aligned(32)));
    u8  scratch[SCRATCH_CAP];
    u32 tlb_tag[1024];
    u32 tlb_phys[1024];
    u16 pel_ink[256];
    struct opl2_chip opl;
    s16 snd_ring[SND_RING];
};
static u32 tmap_col_eip = 0xFFFFFFFFu, tmap_spn_eip = 0xFFFFFFFFu;
#if !defined(PM_EXACT_CPI3) && !defined(NO_FUSE_PUSHAD)
static u32 tmap_col_lo, tmap_col_hi, tmap_col_wlo, tmap_col_whi;
static u32 tmap_spn_lo, tmap_spn_hi, tmap_spn_wlo, tmap_spn_whi;
#endif
static u32 msp_eip = 0xFFFFFFFFu, msp_span_a;

#ifdef __mips__
#include "hw.h"
#define M ((struct dos_mem *)KSEG0(EMU_RAM_PHYS))
_Static_assert(sizeof(struct dos_mem) <= EMU_RAM_SIZE, "dos_mem exceeds EMU_RAM_SIZE");
#else
static struct dos_mem dos_host_mem;
#define M (&dos_host_mem)
#endif

#define mem  (M->mem)
#define vram (M->vram)

struct dos_u16_ua { u16 v; } __attribute__((packed));
struct dos_u32_ua { u32 v; } __attribute__((packed));
INLINE u16 ua_r16(const u8 *p) { return ((const struct dos_u16_ua *)p)->v; }
INLINE u32 ua_r32(const u8 *p) { return ((const struct dos_u32_ua *)p)->v; }
INLINE void ua_w16(u8 *p, u16 v) { ((struct dos_u16_ua *)p)->v = v; }
INLINE void ua_w32(u8 *p, u32 v) { ((struct dos_u32_ua *)p)->v = v; }

static u32 a20_mask = 0xFFFFFu;         /* 0xFFFFF at reset (A20 off); 0x7FFFFF once A20 enabled */
static u32 vga_lo = 0xA0000, vga_n;
static u8 *vga_single_ptr;
static u8 *vga_fast_lut[16];
static u8 vdirty[0x10000 >> 8] __attribute__((aligned(4)));
static u8 vga_read(u32 a);
static void vga_write(u32 a, u8 v);
static void hi_write(u32 a, u32 v);

/* ---- CPU state (8086 / 80286 / 80386) ---- */
enum { ES, CS, SS, DS, FS, GS };
#define F_CF   0x00001u
#define F_PF   0x00004u
#define F_AF   0x00010u
#define F_ZF   0x00040u
#define F_SF   0x00080u
#define F_TF   0x00100u
#define F_IF   0x00200u
#define F_DF   0x00400u
#define F_OF   0x00800u
#define F_IOPL 0x03000u
#define F_NT   0x04000u
#define F_RF   0x10000u
#define F_VM   0x20000u
#define F_AC   0x40000u

static struct {
    union { u32 d; u16 w[2]; u8 b[4]; } reg[8]; /* EAX ECX EDX EBX ESP EBP ESI EDI */
    u16 sr[6];                          /* ES CS SS DS FS GS */
    u32 base[6];
    u32 limit[6];
    u8  d32[6];                         /* 1 = 32-bit default (D/B bit) */
    u8  acc[6];
    u32 eip, op_eip;
    u32 fl;                             /* CF, AF, OF */
    s32 zs;                             /* ZF: (u32)zs << 1 == 0; SF: zs < 0 */
    u32 pb;                             /* PF: parity[pb & 0xFF] */
    u32 sys;                            /* TF, IF, DF, IOPL, NT, RF, VM, AC */
    u32 cr0, cr2, cr3;
    u32 dr[8], tr_reg[8];
    u32 gdt_base, idt_base, ldt_base, tr_base;
    u16 gdt_limit, idt_limit, ldt_limit, tr_limit;
    u16 ldt_sel, tr_sel;
    u8  tr_acc;
    s32 cycles;
    int halted;
    int check;
    int faulted;
    u32 wr_total;
    s32 slice_end;
    u32 wr_guard_lo;
    u32 wr_fast_lo;
    u8  sub_cyc;
} c;
#define PM_CODE_GUARD_TOP 0x1A0000u
#define writes     (c.wr_total)
#define run_end    (c.slice_end)
#define pm_sub_cyc (c.sub_cyc)
static __attribute__((noinline)) void pm_inval_code_snaps(void);
INLINE void pm_check_code_write(u32 lin, u32 len) {
    if (__builtin_expect(lin < c.wr_fast_lo && lin + len > c.wr_guard_lo, 0))
        pm_inval_code_snaps();
}

/* Little-endian register accessors (both x86_64 host and mipsel S3811 are little-endian) */
#define rEAX c.reg[0].d
#define rECX c.reg[1].d
#define rEDX c.reg[2].d
#define rEBX c.reg[3].d
#define rESP c.reg[4].d
#define rEBP c.reg[5].d
#define rESI c.reg[6].d
#define rEDI c.reg[7].d

#define R32(n) (c.reg[(n) & 7].d)
#define R16(n) (c.reg[(n) & 7].w[0])
#define R8(n)  (c.reg[(n) & 3].b[((n) >> 2) & 1])

#define rAX  R16(0)
#define rCX  R16(1)
#define rDX  R16(2)
#define rBX  R16(3)
#define rSP  R16(4)
#define rBP  R16(5)
#define rSI  R16(6)
#define rDI  R16(7)
#define rAL  R8(0)
#define rCL  R8(1)
#define rDL  R8(2)
#define rBL  R8(3)
#define rAH  R8(4)
#define rCH  R8(5)
#define rDH  R8(6)
#define rBH  R8(7)

static u8 parity[256];
static u32 ea_base, ea_off32;
static int sego;
static int op32, ad32;
static u32 cycles_hi;
static u8 ended;

INLINE int pmode_on(void)
{
    return (c.cr0 & 1u) != 0 && !(c.sys & F_VM);
}

static void tlb_flush(void)
{
    for (int i = 0; i < 1024; i++)
        M->tlb_tag[i] = 0;
}

static __attribute__((noinline)) void interrupt_ex(u32 n, int is_int, int has_err, u32 err);

INLINE u32 phys_read32_raw(u32 p)
{
    p &= (RAM_BYTES - 1u);
    return (u32)mem[p] | ((u32)mem[p + 1] << 8) | ((u32)mem[p + 2] << 16) | ((u32)mem[p + 3] << 24);
}

INLINE void phys_write32_raw(u32 p, u32 v)
{
    p &= (RAM_BYTES - 1u);
    pm_check_code_write(p, 4u);
    mem[p] = (u8)v;
    mem[p + 1] = (u8)(v >> 8);
    mem[p + 2] = (u8)(v >> 16);
    mem[p + 3] = (u8)(v >> 24);
}

#pragma GCC push_options
#pragma GCC optimize("O2")

static u32 page_walk(u32 lin, int wr)
{
    u32 pde_a = (c.cr3 & 0xFFFFF000u) + ((lin >> 22) << 2);
    u32 pde = phys_read32_raw(pde_a);
    if (!(pde & 1u)) {
        c.cr2 = lin;
        c.eip = c.op_eip;
        c.faulted = 1;
        interrupt_ex(14, 0, 1, (wr ? 2u : 0u) | ((c.sr[CS] & 3u) == 3u ? 4u : 0u));
        return 0;
    }
    u32 pte_a = (pde & 0xFFFFF000u) + (((lin >> 12) & 0x3FFu) << 2);
    u32 pte = phys_read32_raw(pte_a);
    if (!(pte & 1u)) {
        c.cr2 = lin;
        c.eip = c.op_eip;
        c.faulted = 1;
        interrupt_ex(14, 0, 1, (wr ? 2u : 0u) | ((c.sr[CS] & 3u) == 3u ? 4u : 0u));
        return 0;
    }
    if (!(pde & 0x20u)) phys_write32_raw(pde_a, pde | 0x20u);
    u32 want = 0x20u | (wr ? 0x40u : 0u);
    if ((pte & want) != want) phys_write32_raw(pte_a, pte | want);
    u32 vp = lin >> 12, idx = vp & 1023u;
    M->tlb_tag[idx] = vp | 0x80000000u | (wr ? 0x40000000u : 0u);
    M->tlb_phys[idx] = pte & 0xFFFFF000u;
    return (pte & 0xFFFFF000u) | (lin & 0xFFFu);
}

static u32 lin_to_phys(u32 lin, int wr)
{
    if (!(c.cr0 & 0x80000000u))
        return lin & a20_mask;
    u32 vp = lin >> 12, idx = vp & 1023u;
    u32 tag = M->tlb_tag[idx];
    if ((tag & 0xBFFFFFFFu) == (vp | 0x80000000u) && (!wr || (tag & 0x40000000u)))
        return M->tlb_phys[idx] | (lin & 0xFFFu);
    return page_walk(lin, wr);
}

static u8 rd8_phys(u32 p)
{
    if (p - vga_lo < vga_n)
        return vga_read(p);
    if (p < RAM_BYTES)
        return mem[p];
    return 0xFF;
}

static void wr8_phys(u32 p, u32 v)
{
    writes++;
    if (p < 0xA0000u)
        mem[p] = (u8)v;
    else if (p < 0x100000u)
        hi_write(p, v);
    else if (p < RAM_BYTES) {
        pm_check_code_write(p, 1u);
        mem[p] = (u8)v;
    }
}

static __attribute__((noinline)) u8 rd8_slow(u32 lin)
{
    u32 p = lin_to_phys(lin, 0);
    return c.faulted ? 0 : rd8_phys(p);
}

static __attribute__((noinline)) void wr8_slow(u32 lin, u32 v)
{
    u32 p = lin_to_phys(lin, 1);
    if (!c.faulted)
        wr8_phys(p, v);
}

static inline u8 rd8(u32 lin)
{
    if (!(c.cr0 & 0x80000000u)) {
        u32 p = lin & a20_mask;
        if (p < 0xA0000u || (p >= 0x100000u && p < RAM_BYTES))
            return mem[p];
    }
    return rd8_slow(lin);
}

static inline void wr8(u32 lin, u32 v)
{
    if (!(c.cr0 & 0x80000000u)) {
        u32 p = lin & a20_mask;
        if (p < 0xA0000u || (p >= 0x100000u && p < RAM_BYTES)) {
            pm_check_code_write(p, 1u);
            writes++;
            mem[p] = (u8)v;
            return;
        }
        if ((p - 0xA0000u) < 0x10000u && vga_single_ptr) {
            u32 vo = p - 0xA0000u;
            writes++;
            vdirty[vo >> 8] = 1;
            vga_single_ptr[vo] = (u8)v;
            return;
        }
    }
    wr8_slow(lin, v);
}

static u16 rd16(u32 base, u32 off)
{
    u32 mOff = ad32 ? off : (off & 0xFFFFu);
    u32 lin = base + mOff;
    if (!(c.cr0 & 0x80000000u) && (ad32 || mOff < 0xFFFFu)) {
        u32 p = lin & a20_mask;
        if (p < 0x9FFFFu || (p >= 0x100000u && p < RAM_BYTES - 2u))
            return ua_r16(mem + p);
    }
    if (!ad32 && mOff == 0xFFFFu)
        return (u16)(rd8(base + 0xFFFFu) | ((u32)rd8(base) << 8));
    if ((lin & 0xFFFu) <= 0xFFEu) {
        u32 p = lin_to_phys(lin, 0);
        if (c.faulted) return 0;
        if (p < 0x9FFFFu || (p >= 0x100000u && p < RAM_BYTES - 2u))
            return ua_r16(mem + p);
    }
    u32 lo = rd8(lin);
    u32 hi = rd8(base + (ad32 ? (mOff + 1u) : ((mOff + 1u) & 0xFFFFu)));
    return (u16)(lo | (hi << 8));
}

static u32 rd32(u32 base, u32 off)
{
    u32 mOff = ad32 ? off : (off & 0xFFFFu);
    u32 lin = base + mOff;
    if (!(c.cr0 & 0x80000000u) && (ad32 || mOff <= 0xFFFCu)) {
        u32 p = lin & a20_mask;
        if (p < 0x9FFFCu || (p >= 0x100000u && p < RAM_BYTES - 4u))
            return ua_r32(mem + p);
    }
    if ((ad32 || mOff <= 0xFFFCu) && (lin & 0xFFFu) <= 0xFFCu) {
        u32 p = lin_to_phys(lin, 0);
        if (c.faulted) return 0;
        if (p < 0x9FFFCu || (p >= 0x100000u && p < RAM_BYTES - 4u))
            return ua_r32(mem + p);
    }
    u32 b0 = rd8(lin);
    u32 b1 = rd8(base + (ad32 ? mOff + 1u : ((mOff + 1u) & 0xFFFFu)));
    u32 b2 = rd8(base + (ad32 ? mOff + 2u : ((mOff + 2u) & 0xFFFFu)));
    u32 b3 = rd8(base + (ad32 ? mOff + 3u : ((mOff + 3u) & 0xFFFFu)));
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}

static void wr16(u32 base, u32 off, u32 v)
{
    u32 mOff = ad32 ? off : (off & 0xFFFFu);
    u32 lin = base + mOff;
    if (!(c.cr0 & 0x80000000u) && (ad32 || mOff < 0xFFFFu)) {
        u32 p = lin & a20_mask;
        if (p < 0x9FFFFu || (p >= 0x100000u && p < RAM_BYTES - 2u)) {
            pm_check_code_write(p, 2u);
            writes++;
            ua_w16(mem + p, (u16)v);
            return;
        }
    }
    if (!ad32 && mOff == 0xFFFFu) {
        wr8(base + 0xFFFFu, v);
        wr8(base, v >> 8);
        return;
    }
    if ((lin & 0xFFFu) <= 0xFFEu) {
        u32 p = lin_to_phys(lin, 1);
        if (c.faulted) return;
        if (p < 0x9FFFFu || (p >= 0x100000u && p < RAM_BYTES - 2u)) {
            pm_check_code_write(p, 2u);
            writes++;
            ua_w16(mem + p, (u16)v);
            return;
        }
    }
    wr8(lin, v);
    wr8(base + (ad32 ? (mOff + 1u) : ((mOff + 1u) & 0xFFFFu)), v >> 8);
}

static void wr32(u32 base, u32 off, u32 v)
{
    u32 mOff = ad32 ? off : (off & 0xFFFFu);
    u32 lin = base + mOff;
    if (!(c.cr0 & 0x80000000u) && (ad32 || mOff <= 0xFFFCu)) {
        u32 p = lin & a20_mask;
        if (p < 0x9FFFCu || (p >= 0x100000u && p < RAM_BYTES - 4u)) {
            pm_check_code_write(p, 4u);
            writes++;
            ua_w32(mem + p, v);
            return;
        }
    }
    if ((ad32 || mOff <= 0xFFFCu) && (lin & 0xFFFu) <= 0xFFCu) {
        u32 p = lin_to_phys(lin, 1);
        if (c.faulted) return;
        if (p < 0x9FFFCu || (p >= 0x100000u && p < RAM_BYTES - 4u)) {
            pm_check_code_write(p, 4u);
            writes++;
            ua_w32(mem + p, v);
            return;
        }
    }
    wr8(lin, v);
    wr8(base + (ad32 ? mOff + 1u : ((mOff + 1u) & 0xFFFFu)), v >> 8);
    wr8(base + (ad32 ? mOff + 2u : ((mOff + 2u) & 0xFFFFu)), v >> 16);
    wr8(base + (ad32 ? mOff + 3u : ((mOff + 3u) & 0xFFFFu)), v >> 24);
}

static inline u16 rd16_lin(u32 lin)
{
    if (!(c.cr0 & 0x80000000u)) {
        u32 p = lin & a20_mask;
        if (p < 0x9FFFFu || (p >= 0x100000u && p < RAM_BYTES - 2u))
            return ua_r16(mem + p);
    }
    u32 lo = rd8(lin), hi = rd8(lin + 1u);
    return (u16)(lo | (hi << 8));
}

static inline u32 rd32_lin(u32 lin)
{
    if (!(c.cr0 & 0x80000000u)) {
        u32 p = lin & a20_mask;
        if (p < 0x9FFFCu || (p >= 0x100000u && p < RAM_BYTES - 4u))
            return ua_r32(mem + p);
    }
    u32 lo = rd16_lin(lin), hi = rd16_lin(lin + 2u);
    return lo | (hi << 16);
}

static inline void wr16_lin(u32 lin, u32 v)
{
    if (!(c.cr0 & 0x80000000u)) {
        u32 p = lin & a20_mask;
        if (p < 0x9FFFFu || (p >= 0x100000u && p < RAM_BYTES - 2u)) {
            pm_check_code_write(p, 2u);
            writes++;
            ua_w16(mem + p, (u16)v);
            return;
        }
    }
    wr8(lin, v);
    wr8(lin + 1u, v >> 8);
}

static inline void wr32_lin(u32 lin, u32 v)
{
    if (!(c.cr0 & 0x80000000u)) {
        u32 p = lin & a20_mask;
        if (p < 0x9FFFCu || (p >= 0x100000u && p < RAM_BYTES - 4u)) {
            pm_check_code_write(p, 4u);
            writes++;
            ua_w32(mem + p, v);
            return;
        }
    }
    wr16_lin(lin, v);
    wr16_lin(lin + 2u, v >> 16);
}

static u16 get16(u32 a)                 /* plain conventional memory: BIOS / DOS */
{
    return (u16)(mem[a & 0xFFFFFu] | ((u32)mem[(a + 1u) & 0xFFFFFu] << 8));
}

static void put16(u32 a, u32 v)
{
    mem[a & 0xFFFFFu] = (u8)v;
    mem[(a + 1u) & 0xFFFFFu] = (u8)(v >> 8);
}

/* ---- Segment Descriptor Loading ---- */
static int desc_read(u16 sel, u32 *w0_out, u32 *w1_out, u32 *addr_out)
{
    u32 ti = sel & 4u;
    u32 idx = sel & 0xFFF8u;
    u32 base = ti ? c.ldt_base : c.gdt_base;
    u32 lim  = ti ? c.ldt_limit : c.gdt_limit;
    if (idx + 7u > lim)
        return 0;
    u32 a = base + idx;
    *w0_out = rd32_lin(a);
    *w1_out = rd32_lin(a + 4u);
    if (addr_out) *addr_out = a;
    return !c.faulted;
}

static void set_seg_real(int s, u32 v)
{
    c.sr[s] = (u16)v;
    c.base[s] = (v & 0xFFFFu) << 4;
    if (s == CS || s == SS || (c.sys & F_VM)) {
        c.d32[s] = 0;
        c.limit[s] = 0xFFFFu;
    }
}

static void set_seg(int s, u32 v)
{
    v &= 0xFFFFu;
    if (!pmode_on()) {
        set_seg_real(s, v);
        return;
    }
    if ((v & 0xFFFCu) == 0u) {
        if (s == CS || s == SS) {
            c.eip = c.op_eip;
            c.faulted = 1;
            interrupt_ex(13, 0, 1, 0);
            return;
        }
        c.sr[s] = (u16)v;
        c.base[s] = 0;
        c.limit[s] = 0;
        c.d32[s] = 0;
        c.acc[s] = 0;
        return;
    }
    u32 w0 = 0, w1 = 0, daddr = 0;
    if (!desc_read((u16)v, &w0, &w1, &daddr) || !(w1 & 0x8000u)) {
        c.eip = c.op_eip;
        c.faulted = 1;
        interrupt_ex(((w1 & 0x8000u) == 0 && daddr) ? (s == SS ? 12u : 11u) : 13u, 0, 1, v & 0xFFFCu);
        return;
    }
    u32 base = (w0 >> 16) | ((w1 & 0xFFu) << 16) | (w1 & 0xFF000000u);
    u32 lim  = (w0 & 0xFFFFu) | (w1 & 0x000F0000u);
    if (w1 & 0x00800000u)
        lim = (lim << 12) | 0xFFFu;
    c.sr[s] = (u16)v;
    c.base[s] = base;
    c.limit[s] = lim;
    c.d32[s] = (u8)((w1 >> 22) & 1u);
    c.acc[s] = (u8)((w1 >> 8) & 0xFFu);
    if ((w1 & 0x1100u) == 0x1000u)      /* mark segment Accessed */
        wr8(daddr + 5u, c.acc[s] | 1u);
}

static inline u32 fetch8(void)
{
    u32 ip;
    if (c.d32[CS]) {
        ip = c.eip++;
    } else {
        ip = (u16)c.eip;
        c.eip = (u16)(ip + 1u);
    }
    u32 lin = c.base[CS] + ip;
    if (!(c.cr0 & 0x80000000u)) {
        u32 p = lin & a20_mask;
        return p < RAM_BYTES ? mem[p] : 0xFFu;
    }
    return rd8_slow(lin);
}

static inline u32 fetch16(void)
{
    if (!(c.cr0 & 0x80000000u) && (c.d32[CS] || (u16)c.eip < 0xFFFFu)) {
        u32 p = (c.base[CS] + c.eip) & a20_mask;
        if (p < RAM_BYTES - 2u) {
            u16 w = ua_r16(mem + p);
            c.eip = c.d32[CS] ? (c.eip + 2u) : (u32)(u16)(c.eip + 2u);
            return w;
        }
    }
    u32 v = fetch8();
    return v | (fetch8() << 8);
}

static inline u32 fetch32(void)
{
    if (c.d32[CS] && !(c.cr0 & 0x80000000u)) {
        u32 p = (c.base[CS] + c.eip) & a20_mask;
        if (p < RAM_BYTES - 4u) {
            u32 d = ua_r32(mem + p);
            c.eip += 4u;
            return d;
        }
    }
    u32 lo = fetch16();
    return lo | (fetch16() << 16);
}

static void push16(u32 v)
{
    if (c.d32[SS]) {
        u32 nsp = rESP - 2u;
        wr16_lin(c.base[SS] + nsp, v);
        if (!c.faulted) rESP = nsp;
    } else {
        u16 nsp = (u16)(rSP - 2u);
        int sv_ad = ad32;
        ad32 = 0;
        wr16(c.base[SS], nsp, v);
        ad32 = sv_ad;
        if (!c.faulted) rSP = nsp;
    }
}

static void push32(u32 v)
{
    if (c.d32[SS]) {
        u32 nsp = rESP - 4u;
        wr32_lin(c.base[SS] + nsp, v);
        if (!c.faulted) rESP = nsp;
    } else {
        u16 nsp = (u16)(rSP - 4u);
        int sv_ad = ad32;
        ad32 = 0;
        wr32(c.base[SS], nsp, v);
        ad32 = sv_ad;
        if (!c.faulted) rSP = nsp;
    }
}

static u32 pop16(void)
{
    if (c.d32[SS]) {
        u32 v = rd16_lin(c.base[SS] + rESP);
        if (!c.faulted) rESP += 2u;
        return v;
    } else {
        int sv_ad = ad32;
        ad32 = 0;
        u32 v = rd16(c.base[SS], rSP);
        ad32 = sv_ad;
        if (!c.faulted) rSP = (u16)(rSP + 2u);
        return v;
    }
}

static u32 pop32(void)
{
    if (c.d32[SS]) {
        u32 v = rd32_lin(c.base[SS] + rESP);
        if (!c.faulted) rESP += 4u;
        return v;
    } else {
        int sv_ad = ad32;
        ad32 = 0;
        u32 v = rd32(c.base[SS], rSP);
        ad32 = sv_ad;
        if (!c.faulted) rSP = (u16)(rSP + 4u);
        return v;
    }
}

INLINE void pushv(u32 v) { if (op32) push32(v); else push16(v); }
INLINE u32  popv(void)   { return op32 ? pop32() : pop16(); }

static u32 get_eflags(void)
{
    return (c.fl & (F_CF | F_AF | F_OF)) | (parity[c.pb & 0xFFu] ? F_PF : 0u) |
           (((u32)c.zs << 1) ? 0u : F_ZF) | (c.zs < 0 ? F_SF : 0u) | c.sys | 0x0002u;
}

static void set_eflags(u32 f, int full32)
{
    c.fl = f & (F_CF | F_AF | F_OF);
    c.pb = (f & F_PF) ? 0u : 1u;
    c.zs = (f & F_ZF) ? ((f & F_SF) ? (s32)0x80000000u : 0) : ((f & F_SF) ? -1 : 1);
    u32 mask = F_TF | F_IF | F_DF | F_IOPL | F_NT;
    if (full32)
        mask |= F_RF | F_AC;
    c.sys = (c.sys & ~mask) | (f & mask);
}

static __attribute__((noinline)) void interrupt_ex(u32 n, int is_int, int has_err, u32 err)
{
    (void)is_int;
    if (!pmode_on()) {
        if (c.sys & F_VM) {
            /* V86 hardware or software interrupt -> reflect through PM IDT if IOPL==3 or hardware IRQ */
            if ((c.cr0 & 1u) && (!is_int || ((c.sys & F_IOPL) != F_IOPL))) {
                goto pm_dispatch;
            }
        }
        push16(get_eflags());
        c.sys &= ~(F_IF | F_TF);
        push16(c.sr[CS]);
        push16(c.eip);
        c.eip = get16(n * 4u);
        set_seg_real(CS, get16(n * 4u + 2u));
        c.cycles += 23;
        return;
    }

pm_dispatch:;
    u32 off_idx = n * 8u;
    if (off_idx + 7u > c.idt_limit) {
        ended = 1;
        c.halted = 1;
        return;
    }
    int prev_flt = c.faulted;
    c.faulted = 0;
    u32 w0 = rd32_lin(c.idt_base + off_idx);
    u32 w1 = rd32_lin(c.idt_base + off_idx + 4u);
    if (c.faulted) { c.faulted = prev_flt; return; }

    u32 gtype = (w1 >> 8) & 0x1Fu;
    u32 sel = w0 >> 16;
    u32 new_eip = (w0 & 0xFFFFu) | ((gtype >= 14u) ? (w1 & 0xFFFF0000u) : 0u);
    int g32 = (gtype >= 14u);

    u32 dw0 = 0, dw1 = 0;
    if (!desc_read((u16)sel, &dw0, &dw1, 0)) {
        c.faulted = prev_flt;
        return;
    }
    u32 target_dpl = (dw1 >> 13) & 3u;
    u32 old_efl = get_eflags();
    u32 old_cs = c.sr[CS], old_eip = c.eip;
    u32 old_ss = c.sr[SS], old_esp = c.d32[SS] ? rESP : rSP;
    u32 cur_cpl = (old_efl & F_VM) ? 3u : (old_cs & 3u);

    if (old_efl & F_VM) {
        u32 esp0 = rd32_lin(c.tr_base + 4u);
        u16 ss0  = rd16_lin(c.tr_base + 8u);
        c.sys &= ~(F_VM | F_TF | F_RF | F_NT);
        set_seg(SS, ss0);
        rESP = esp0;
        push32(c.sr[GS]); push32(c.sr[FS]); push32(c.sr[DS]); push32(c.sr[ES]);
        push32(old_ss);   push32(old_esp);
        set_seg(ES, 0); set_seg(DS, 0); set_seg(FS, 0); set_seg(GS, 0);
    } else if (target_dpl < cur_cpl) {
        u32 esp0 = (c.tr_acc & 8u) ? rd32_lin(c.tr_base + 4u) : rd16_lin(c.tr_base + 2u);
        u16 ss0  = (c.tr_acc & 8u) ? rd16_lin(c.tr_base + 8u) : rd16_lin(c.tr_base + 4u);
        set_seg(SS, ss0);
        if (c.d32[SS]) rESP = esp0; else rSP = (u16)esp0;
        if (g32) { push32(old_ss); push32(old_esp); }
        else     { push16(old_ss); push16(old_esp); }
    }

    if (g32) {
        push32(old_efl);
        push32(old_cs);
        push32(old_eip);
        if (has_err) push32(err);
    } else {
        push16(old_efl);
        push16(old_cs);
        push16(old_eip);
        if (has_err) push16(err);
    }

    if ((gtype & 1u) == 0u)             /* Interrupt gate (6 or 14) clears IF */
        c.sys &= ~F_IF;
    c.sys &= ~(F_TF | F_NT | F_RF);
    set_seg(CS, (sel & 0xFFFCu) | target_dpl);
    c.eip = new_eip;
    c.faulted = prev_flt;
    c.cycles += 12;
}

static void interrupt(u32 n)
{
    interrupt_ex(n, 0, 0, 0);
}

/* ---- 16-bit & 32-bit ModR/M + SIB Effective Address ---- */
static __attribute__((noinline)) void ea(u32 m)
{
    if (!ad32) {
        u32 off;
        int s = DS;
        switch (m & 7u) {
        case 0: off = (u32)rBX + rSI; break;
        case 1: off = (u32)rBX + rDI; break;
        case 2: off = (u32)rBP + rSI; s = SS; break;
        case 3: off = (u32)rBP + rDI; s = SS; break;
        case 4: off = rSI; break;
        case 5: off = rDI; break;
        case 6:
            if (!(m & 0xC0u)) { off = fetch16(); break; }
            off = rBP; s = SS; break;
        default: off = rBX; break;
        }
        if ((m & 0xC0u) == 0x40u)
            off += (u32)(s32)(s8)fetch8();
        else if ((m & 0xC0u) == 0x80u)
            off += fetch16();
        ea_base = c.base[sego >= 0 ? sego : s];
        ea_off32 = off & 0xFFFFu;
        if (!pmode_on())
            c.cycles += 3;
        return;
    }

    u32 mod = m >> 6, rm = m & 7u, off = 0;
    int s = DS;
    if (rm == 4u) {                     /* SIB byte */
        u32 sib = fetch8();
        u32 scale = sib >> 6, idx = (sib >> 3) & 7u, br = sib & 7u;
        u32 iv = (idx == 4u) ? 0u : (R32(idx) << scale);
        if (br == 5u && mod == 0u) {
            off = fetch32() + iv;
        } else {
            if (br == 4u || br == 5u) s = SS;
            off = R32(br) + iv;
        }
    } else if (rm == 5u && mod == 0u) {
        off = fetch32();
    } else {
        if (rm == 5u) s = SS;
        off = R32(rm);
    }
    if (mod == 1u)
        off += (u32)(s32)(s8)fetch8();
    else if (mod == 2u)
        off += fetch32();
    ea_base = c.base[sego >= 0 ? sego : s];
    ea_off32 = off;
}

INLINE u32 get8(u32 m)
{
    if (m >= 0xC0u) return R8(m);
    ea(m);
    return rd8(ea_base + ea_off32);
}

INLINE u32 getv(u32 m)
{
    if (m >= 0xC0u) return op32 ? R32(m) : R16(m);
    ea(m);
    return op32 ? rd32(ea_base, ea_off32) : rd16(ea_base, ea_off32);
}

INLINE void put8(u32 m, u32 v)
{
    if (c.faulted) return;
    if (m >= 0xC0u) R8(m) = (u8)v;
    else wr8(ea_base + ea_off32, v);
}

INLINE void putv(u32 m, u32 v)
{
    if (c.faulted) return;
    if (m >= 0xC0u) {
        if (op32) R32(m) = v;
        else      R16(m) = (u16)v;
    } else {
        if (op32) wr32(ea_base, ea_off32, v);
        else      wr16(ea_base, ea_off32, v);
    }
}

INLINE void ea_only(u32 m)
{
    if (m < 0xC0u)
        ea(m);
}

/* ---- 8 / 16 / 32-bit ALU ---- */
static u32 add8(u32 a, u32 b, u32 carry)
{
    a &= 0xFFu; b &= 0xFFu;
    u32 r = a + b + carry;
    c.fl = ((r >> 8) & 1u) | ((a ^ b ^ r) & F_AF) | (((a ^ r) & (b ^ r) & 0x80u) << 4);
    c.zs = (s8)r;
    c.pb = r;
    return r & 0xFFu;
}

static u32 add16(u32 a, u32 b, u32 carry)
{
    a &= 0xFFFFu; b &= 0xFFFFu;
    u32 r = a + b + carry;
    c.fl = ((r >> 16) & 1u) | ((a ^ b ^ r) & F_AF) | (((a ^ r) & (b ^ r) & 0x8000u) >> 4);
    c.zs = (s16)r;
    c.pb = r;
    return r & 0xFFFFu;
}

#define ZS32(r) (((s32)(u32)(r) >> 31) | (s32)((u32)(r) != 0u))

INLINE u32 add32(u32 a, u32 b, u32 carry)
{
    u32 r = a + b + carry;
    u32 cout = (a & b) | ((a | b) & ~r);
    c.fl = (cout >> 31) | ((a ^ b ^ r) & F_AF) | (((a ^ r) & (b ^ r) & 0x80000000u) >> 20);
    c.zs = ZS32(r);
    c.pb = r;
    return r;
}

static u32 sub8(u32 a, u32 b, u32 borrow)
{
    a &= 0xFFu; b &= 0xFFu;
    u32 r = a - b - borrow;
    c.fl = ((r >> 8) & 1u) | ((a ^ b ^ r) & F_AF) | (((a ^ b) & (a ^ r) & 0x80u) << 4);
    c.zs = (s8)r;
    c.pb = r;
    return r & 0xFFu;
}

static u32 sub16(u32 a, u32 b, u32 borrow)
{
    a &= 0xFFFFu; b &= 0xFFFFu;
    u32 r = a - b - borrow;
    c.fl = ((r >> 16) & 1u) | ((a ^ b ^ r) & F_AF) | (((a ^ b) & (a ^ r) & 0x8000u) >> 4);
    c.zs = (s16)r;
    c.pb = r;
    return r & 0xFFFFu;
}

INLINE u32 sub32(u32 a, u32 b, u32 borrow)
{
    u32 r = a - b - borrow;
    u32 bout = (~a & b) | ((~a | b) & r);
    c.fl = (bout >> 31) | ((a ^ b ^ r) & F_AF) | (((a ^ b) & (a ^ r) & 0x80000000u) >> 20);
    c.zs = ZS32(r);
    c.pb = r;
    return r;
}

INLINE u32 logic8(u32 r)  { c.fl = 0; c.zs = (s8)r;  c.pb = r; return r & 0xFFu; }
INLINE u32 logic16(u32 r) { c.fl = 0; c.zs = (s16)r; c.pb = r; return r & 0xFFFFu; }
INLINE u32 logic32(u32 r) { c.fl = 0; c.zs = ZS32(r); c.pb = r; return r; }
INLINE u32 logicv(u32 r)  { return op32 ? logic32(r) : logic16(r); }

static __attribute__((noinline)) u32 alu8(u32 k, u32 a, u32 b)
{
    switch (k & 7u) {
    case 0: return add8(a, b, 0);
    case 1: return logic8(a | b);
    case 2: return add8(a, b, c.fl & F_CF);
    case 3: return sub8(a, b, c.fl & F_CF);
    case 4: return logic8(a & b);
    case 6: return logic8(a ^ b);
    default: return sub8(a, b, 0);
    }
}

static __attribute__((noinline)) u32 aluv(u32 k, u32 a, u32 b)
{
    if (!op32) {
        switch (k & 7u) {
        case 0: return add16(a, b, 0);
        case 1: return logic16(a | b);
        case 2: return add16(a, b, c.fl & F_CF);
        case 3: return sub16(a, b, c.fl & F_CF);
        case 4: return logic16(a & b);
        case 6: return logic16(a ^ b);
        default: return sub16(a, b, 0);
        }
    }
    switch (k & 7u) {
    case 0: return add32(a, b, 0);
    case 1: return logic32(a | b);
    case 2: return add32(a, b, c.fl & F_CF);
    case 3: return sub32(a, b, c.fl & F_CF);
    case 4: return logic32(a & b);
    case 6: return logic32(a ^ b);
    default: return sub32(a, b, 0);
    }
}

static u32 inc8(u32 a)
{
    u32 r = (a + 1u) & 0xFFu;
    c.fl = (c.fl & F_CF) | ((a ^ r) & F_AF) | (r == 0x80u ? F_OF : 0u);
    c.zs = (s8)r; c.pb = r;
    return r;
}

static u32 dec8(u32 a)
{
    u32 r = (a - 1u) & 0xFFu;
    c.fl = (c.fl & F_CF) | ((a ^ r) & F_AF) | (a == 0x80u ? F_OF : 0u);
    c.zs = (s8)r; c.pb = r;
    return r;
}

static u32 incv(u32 a)
{
    if (!op32) {
        u32 r = (a + 1u) & 0xFFFFu;
        c.fl = (c.fl & F_CF) | ((a ^ r) & F_AF) | (r == 0x8000u ? F_OF : 0u);
        c.zs = (s16)r; c.pb = r;
        return r;
    }
    u32 r = a + 1u;
    c.fl = (c.fl & F_CF) | ((a ^ r) & F_AF) | (r == 0x80000000u ? F_OF : 0u);
    c.zs = (r == 0u) ? 0 : ((r & 0x80000000u) ? -1 : 1);
    c.pb = r;
    return r;
}

static u32 decv(u32 a)
{
    if (!op32) {
        u32 r = (a - 1u) & 0xFFFFu;
        c.fl = (c.fl & F_CF) | ((a ^ r) & F_AF) | (a == 0x8000u ? F_OF : 0u);
        c.zs = (s16)r; c.pb = r;
        return r;
    }
    u32 r = a - 1u;
    c.fl = (c.fl & F_CF) | ((a ^ r) & F_AF) | (a == 0x80000000u ? F_OF : 0u);
    c.zs = (r == 0u) ? 0 : ((r & 0x80000000u) ? -1 : 1);
    c.pb = r;
    return r;
}

/* ROL ROR RCL RCR SHL SHR SAL SAR on 8, 16, or 32 bits */
static __attribute__((noinline)) u32 shift(u32 k, u32 v, u32 n, u32 bits)
{
    u32 top = bits - 1u, mask = bits == 32u ? 0xFFFFFFFFu : ((1u << bits) - 1u);
    u32 cf = c.fl & F_CF, of = 0, r = v & mask;
    n &= 31u;
    if (!n)
        return r;
    if (!pmode_on())
        c.cycles += (s32)n;
    switch (k & 7u) {
    case 0:                             /* ROL */
        n &= top;
        if (n) r = ((r << n) | (r >> (bits - n))) & mask;
        cf = r & 1u;
        of = ((r >> top) ^ cf) & 1u;
        c.fl = (c.fl & F_AF) | cf | (of << 11);
        return r;
    case 1:                             /* ROR */
        n &= top;
        if (n) r = ((r >> n) | (r << (bits - n))) & mask;
        cf = (r >> top) & 1u;
        of = (cf ^ ((r >> (top - 1u)) & 1u)) & 1u;
        c.fl = (c.fl & F_AF) | cf | (of << 11);
        return r;
    case 2:                             /* RCL */
        n %= bits + 1u;
        if (!n) return r;
        for (u32 i = 0; i < n; i++) {
            u32 out = (r >> top) & 1u;
            r = ((r << 1) | cf) & mask;
            cf = out;
        }
        of = ((r >> top) ^ cf) & 1u;
        c.fl = (c.fl & F_AF) | cf | (of << 11);
        return r;
    case 3:                             /* RCR */
        n %= bits + 1u;
        if (!n) return r;
        of = ((r >> top) ^ cf) & 1u;
        for (u32 i = 0; i < n; i++) {
            u32 out = r & 1u;
            r = (r >> 1) | (cf << top);
            cf = out;
        }
        c.fl = (c.fl & F_AF) | cf | (of << 11);
        return r;
    case 5:                             /* SHR */
        cf = (r >> (n - 1u)) & 1u;
        of = (v >> top) & 1u;
        r = r >> n;
        c.fl = cf | (of << 11);
        break;
    case 7: {                           /* SAR */
        s32 sv = bits == 8u ? (s32)(s8)r : (bits == 16u ? (s32)(s16)r : (s32)r);
        cf = (u32)(sv >> (n - 1u)) & 1u;
        r = (u32)(sv >> n) & mask;
        c.fl = cf;
        break;
    }
    default:                            /* SHL / SAL */
        cf = (r >> (bits - n)) & 1u;
        r = (r << n) & mask;
        of = ((r >> top) ^ cf) & 1u;
        c.fl = cf | (of << 11);
        break;
    }
    if (bits == 8u)       c.zs = (s8)r;
    else if (bits == 16u) c.zs = (s16)r;
    else                  c.zs = (r == 0u) ? 0 : ((r & 0x80000000u) ? -1 : 1);
    c.pb = r;
    return r;
}

INLINE int cond(u32 k)
{
    int r;
    switch ((k >> 1) & 7u) {
    case 0: r = (c.fl & F_OF) != 0; break;
    case 1: r = (c.fl & F_CF) != 0; break;
    case 2: r = !((u32)c.zs << 1); break;
    case 3: r = (c.fl & F_CF) || !((u32)c.zs << 1); break;
    case 4: r = c.zs < 0; break;
    case 5: r = parity[c.pb & 0xFFu]; break;
    case 6: r = (c.zs < 0) != ((c.fl & F_OF) != 0); break;
    default: r = !((u32)c.zs << 1) || ((c.zs < 0) != ((c.fl & F_OF) != 0)); break;
    }
    return r ^ (int)(k & 1u);
}

static void divide_error(void)
{
    c.eip = c.op_eip;
    interrupt(0);
}

/* Pure 32-bit 64/32 unsigned division (zero __udivdi3 on freestanding MIPS) */
static __attribute__((noinline)) int dos_divu64_32(u32 hi, u32 lo, u32 d, u32 *qo, u32 *ro)
{
    if (!d || hi >= d)
        return -1;
    if (__builtin_expect(hi == 0u, 1)) {
        *qo = lo / d;
        *ro = lo % d;
        return 0;
    }
    u32 rem = hi, q = 0;
    int i = 31;
    u32 lz_diff = (u32)(__builtin_clz(hi) - __builtin_clz(d));
    if (lz_diff > 1u) {
        u32 sk = lz_diff - 1u;
        rem = (hi << sk) | (lo >> (32u - sk));
        i = 31 - (int)sk;
    }
    for (; i >= 0; i--) {
        u32 top = rem >> 31;
        rem = (rem << 1) | ((lo >> i) & 1u);
        if (top || rem >= d) {
            rem -= d;
            q |= 1u << i;
        }
    }
    *qo = q;
    *ro = rem;
    return 0;
}

static __attribute__((noinline)) void group3(u32 op)
{
    u32 m = fetch8(), k = (m >> 3) & 7u, v, r;
    if (op == 0xF6u) {
        v = get8(m);
        if (c.faulted) return;
        switch (k) {
        case 0: case 1: logic8(v & fetch8()); break;
        case 2: put8(m, ~v); break;
        case 3: put8(m, sub8(0, v, 0)); c.fl = (c.fl & ~F_CF) | (v != 0u); break;
        case 4:
            r = rAL * v;
            rAX = (u16)r;
            c.fl = (r >> 8) ? (F_CF | F_OF) : 0u;
            c.zs = (s8)r; c.pb = r;
            if (!pmode_on()) c.cycles += 11;
            break;
        case 5: {
            s32 p = (s8)rAL * (s8)v;
            rAX = (u16)p;
            c.fl = p != (s8)p ? (F_CF | F_OF) : 0u;
            c.zs = (s8)p; c.pb = (u32)p;
            if (!pmode_on()) c.cycles += 11;
            break;
        }
        case 6: {
            u32 n = rAX;
            if (!v || n / v > 0xFFu) { divide_error(); return; }
            rAL = (u8)(n / v);
            rAH = (u8)(n % v);
            if (!pmode_on()) c.cycles += 14;
            break;
        }
        default: {
            s32 n = (s16)rAX, d = (s8)v;
            if (!d || n / d > 127 || n / d < -128) { divide_error(); return; }
            rAL = (u8)(n / d);
            rAH = (u8)(n % d);
            if (!pmode_on()) c.cycles += 17;
            break;
        }
        }
        return;
    }

    v = getv(m);
    if (c.faulted) return;
    if (!op32) {
        switch (k) {
        case 0: case 1: logic16(v & fetch16()); break;
        case 2: putv(m, ~v); break;
        case 3: putv(m, sub16(0, v, 0)); c.fl = (c.fl & ~F_CF) | (v != 0u); break;
        case 4:
            r = (u32)rAX * v;
            rAX = (u16)r;
            rDX = (u16)(r >> 16);
            c.fl = (r >> 16) ? (F_CF | F_OF) : 0u;
            c.zs = (s16)r; c.pb = r;
            if (!pmode_on()) c.cycles += 19;
            break;
        case 5: {
            s32 p = (s16)rAX * (s16)v;
            rAX = (u16)p;
            rDX = (u16)((u32)p >> 16);
            c.fl = p != (s16)p ? (F_CF | F_OF) : 0u;
            c.zs = (s16)p; c.pb = (u32)p;
            if (!pmode_on()) c.cycles += 19;
            break;
        }
        case 6: {
            u32 n = ((u32)rDX << 16) | rAX;
            if (!v || n / v > 0xFFFFu) { divide_error(); return; }
            rAX = (u16)(n / v);
            rDX = (u16)(n % v);
            if (!pmode_on()) c.cycles += 20;
            break;
        }
        default: {
            s32 n = (s32)(((u32)rDX << 16) | rAX), d = (s16)v;
            if (!d || (d == -1 && n == (s32)0x80000000u) || n / d > 32767 || n / d < -32768) { divide_error(); return; }
            rAX = (u16)(n / d);
            rDX = (u16)(n % d);
            if (!pmode_on()) c.cycles += 23;
            break;
        }
        }
        return;
    }

    /* 32-bit F7 */
    switch (k) {
    case 0: case 1: logic32(v & fetch32()); break;
    case 2: putv(m, ~v); break;
    case 3: putv(m, sub32(0, v, 0)); c.fl = (c.fl & ~F_CF) | (v != 0u); break;
    case 4: {
        unsigned long long prod = (unsigned long long)rEAX * (unsigned long long)v;
        rEAX = (u32)prod;
        rEDX = (u32)(prod >> 32);
        c.fl = rEDX ? (F_CF | F_OF) : 0u;
        break;
    }
    case 5: {
        signed long long prod = (signed long long)(s32)rEAX * (signed long long)(s32)v;
        rEAX = (u32)prod;
        rEDX = (u32)((unsigned long long)prod >> 32);
        c.fl = (prod < -(signed long long)0x80000000LL || prod > (signed long long)0x7FFFFFFFLL) ? (F_CF | F_OF) : 0u;
        break;
    }
    case 6: {
        u32 q = 0, rem = 0;
        if (dos_divu64_32(rEDX, rEAX, v, &q, &rem) < 0) { divide_error(); return; }
        rEAX = q;
        rEDX = rem;
        break;
    }
    default: {
        u32 hi = rEDX, lo = rEAX;
        int neg_n = (hi & 0x80000000u) != 0, neg_d = (v & 0x80000000u) != 0;
        if (neg_n) {
            lo = ~lo + 1u;
            hi = ~hi + (lo == 0u ? 1u : 0u);
        }
        u32 ud = neg_d ? (~v + 1u) : v, q = 0, rem = 0;
        if (dos_divu64_32(hi, lo, ud, &q, &rem) < 0) { divide_error(); return; }
        int neg_q = neg_n ^ neg_d;
        if (q > (neg_q ? 0x80000000u : 0x7FFFFFFFu)) { divide_error(); return; }
        rEAX = neg_q ? (~q + 1u) : q;
        rEDX = neg_n ? (~rem + 1u) : rem;
        break;
    }
    }
}

static u32 imul_v(u32 a, u32 b)
{
    if (!op32) {
        s32 p = (s16)a * (s16)b;
        c.fl = p != (s16)p ? (F_CF | F_OF) : 0u;
        c.zs = (s16)p; c.pb = (u32)p;
        if (!pmode_on()) c.cycles += 18;
        return (u32)p & 0xFFFFu;
    }
    signed long long p = (signed long long)(s32)a * (signed long long)(s32)b;
    u32 lo = (u32)p;
    c.fl = (p < -(signed long long)0x80000000LL || p > (signed long long)0x7FFFFFFFLL) ? (F_CF | F_OF) : 0u;
    c.zs = (lo == 0u) ? 0 : ((lo & 0x80000000u) ? -1 : 1);
    c.pb = lo;
    return lo;
}

static u8 in8(u32 port);
static void out8(u32 port, u32 v);

static u32 in16(u32 port)
{
    u32 lo = in8(port);
    return lo | ((u32)in8(port + 1u) << 8);
}

static u32 in32(u32 port)
{
    u32 lo = in16(port);
    return lo | (in16(port + 2u) << 16);
}

static void out16(u32 port, u32 v)
{
    out8(port, v & 0xFFu);
    out8(port + 1u, (v >> 8) & 0xFFu);
}

static void out32(u32 port, u32 v)
{
    out16(port, v & 0xFFFFu);
    out16(port + 2u, v >> 16);
}

/* MOVS CMPS STOS LODS SCAS INS OUTS (8 / 16 / 32-bit, with 16 or 32-bit SI/DI/CX) */
static __attribute__((noinline)) void string(u32 op, u32 rep)
{
    u32 src = c.base[sego >= 0 ? sego : DS], dst = c.base[ES];
    u32 sz = (op & 1u) ? (op32 ? 4u : 2u) : 1u;
    s32 step = (c.sys & F_DF) ? -(s32)sz : (s32)sz;

    /* Fast path for forward 32-bit flat / real-mode REP MOVS / STOS into RAM or Mode X planes */
    if (rep && step > 0 && !(c.cr0 & 0x80000000u) && (op == 0xA4u || op == 0xA5u || op == 0xAAu || op == 0xABu)) {
        u32 cnt = ad32 ? rECX : rCX;
        if (cnt > 0u && cnt <= 0x100000u) {
            u32 si0 = ad32 ? rESI : rSI, di0 = ad32 ? rEDI : rDI;
            u32 nb = cnt * sz;
            u32 s_lin = (src + si0) & a20_mask, d_lin = (dst + di0) & a20_mask;
            int movs = op < 0xA8u;
            int wrap_ok = ad32 || (di0 + nb <= 0x10000u && (!movs || si0 + nb <= 0x10000u));
            int d_ram = (d_lin + nb <= 0xA0000u) || (d_lin >= 0x100000u && d_lin + nb <= RAM_BYTES);
            int d_vga = vga_n && d_lin >= vga_lo && d_lin + nb <= vga_lo + vga_n;
            int s_ram = !movs || ((s_lin + nb <= 0xA0000u || (s_lin >= 0x100000u && s_lin + nb <= RAM_BYTES)) &&
                                  !(d_lin > s_lin && d_lin < s_lin + sz));
            if (wrap_ok && s_ram && (d_ram || d_vga)) {
                if (d_ram) pm_check_code_write(d_lin, nb);
                u32 pat = rEAX;
                if (movs) {
                    if (d_ram) {
                        u32 i = 0;
                        if (d_lin <= s_lin || d_lin >= s_lin + nb) {
                            for (; i + 4u <= nb; i += 4u)
                                ua_w32(mem + d_lin + i, ua_r32(mem + s_lin + i));
                        }
                        for (; i < nb; i++)
                            mem[d_lin + i] = mem[s_lin + i];
                    } else {
                        for (u32 i = 0; i < nb; i++)
                            vga_write(d_lin + i, mem[s_lin + i]);
                    }
                    if (ad32) rESI = si0 + nb; else rSI = (u16)(si0 + nb);
                } else {
                    if (d_ram) {
                        if (sz == 1u) {
                            u8 b = (u8)pat;
                            u32 w4 = (u32)b | ((u32)b << 8) | ((u32)b << 16) | ((u32)b << 24), i = 0;
                            for (; i + 4u <= nb; i += 4u) ua_w32(mem + d_lin + i, w4);
                            for (; i < nb; i++) mem[d_lin + i] = b;
                        } else if (sz == 2u) {
                            u16 w2 = (u16)pat;
                            u32 w4 = (u32)w2 | ((u32)w2 << 16), i = 0;
                            for (; i + 4u <= nb; i += 4u) ua_w32(mem + d_lin + i, w4);
                            for (; i < nb; i += 2u) ua_w16(mem + d_lin + i, w2);
                        } else {
                            for (u32 i = 0; i < nb; i += 4u)
                                ua_w32(mem + d_lin + i, pat);
                        }
                    } else {
                        for (u32 i = 0; i < nb; i++)
                            vga_write(d_lin + i, (u8)(pat >> ((i & (sz - 1u)) * 8u)));
                    }
                }
                if (ad32) rEDI = di0 + nb; else rDI = (u16)(di0 + nb);
                c.cycles += (pmode_on() ? 1 : 4) * (s32)(cnt > 4096u ? 4096u : cnt);
                if (ad32) rECX = 0; else rCX = 0;
                writes++;
                return;
            }
        }
    }

    for (;;) {
        u32 cnt = ad32 ? rECX : rCX;
        if (rep && !cnt)
            break;
        u32 si = ad32 ? rESI : rSI, di = ad32 ? rEDI : rDI;
        switch (op) {
        case 0xA4: wr8(dst + di, rd8(src + si)); si += (u32)step; di += (u32)step; break;
        case 0xA5:
            if (op32) wr32(dst, di, rd32(src, si));
            else      wr16(dst, di, rd16(src, si));
            si += (u32)step; di += (u32)step;
            break;
        case 0xA6: sub8(rd8(src + si), rd8(dst + di), 0); si += (u32)step; di += (u32)step; break;
        case 0xA7:
            if (op32) sub32(rd32(src, si), rd32(dst, di), 0);
            else      sub16(rd16(src, si), rd16(dst, di), 0);
            si += (u32)step; di += (u32)step;
            break;
        case 0xAA: wr8(dst + di, rAL); di += (u32)step; break;
        case 0xAB:
            if (op32) wr32(dst, di, rEAX);
            else      wr16(dst, di, rAX);
            di += (u32)step;
            break;
        case 0xAC: rAL = rd8(src + si); si += (u32)step; break;
        case 0xAD:
            if (op32) rEAX = rd32(src, si);
            else      rAX  = rd16(src, si);
            si += (u32)step;
            break;
        case 0xAE: sub8(rAL, rd8(dst + di), 0); di += (u32)step; break;
        case 0xAF:
            if (op32) sub32(rEAX, rd32(dst, di), 0);
            else      sub16(rAX,  rd16(dst, di), 0);
            di += (u32)step;
            break;
        case 0x6C: wr8(dst + di, in8(rDX)); di += (u32)step; break;
        case 0x6D:
            if (op32) wr32(dst, di, in32(rDX));
            else      wr16(dst, di, in16(rDX));
            di += (u32)step;
            break;
        case 0x6E: out8(rDX, rd8(src + si)); si += (u32)step; break;
        default:
            if (op32) out32(rDX, rd32(src, si));
            else      out16(rDX, rd16(src, si));
            si += (u32)step;
            break;
        }
        if (c.faulted)
            return;
        if (ad32) { rESI = si; rEDI = di; }
        else      { rSI = (u16)si; rDI = (u16)di; }
        if (!rep)
            break;
        c.cycles += pmode_on() ? 1 : 4;
        if (ad32) rECX--; else rCX--;
        if ((op & 0xF6u) == 0xA6u && (rep == 0xF3u ? ((u32)c.zs << 1) != 0u : ((u32)c.zs << 1) == 0u))
            break;
        if (c.cycles >= run_end && (c.sys & F_IF)) {
            /* Yield long interruptible REP so timer/SB DMA IRQs stay cycle-accurate! */
            c.eip = c.op_eip;
            break;
        }
    }
}

static __attribute__((noinline)) void hle(u32 n);
static void note(const char *what, u32 a, u32 b);

static void invalid(void)
{
    note("invalid opcode at", ((u32)c.sr[CS] << 16) ^ c.op_eip, rd8(c.base[CS] + c.op_eip));
    c.eip = c.op_eip;
    interrupt(6);
}

/* ---- 80386 0F xx Two-Byte Instructions ---- */
static __attribute__((noinline)) u32 shld_v(u32 dst, u32 src, u32 cnt, u32 bits)
{
    cnt &= 31u;
    if (!cnt) return dst;
    u32 mask = bits == 32u ? 0xFFFFFFFFu : 0xFFFFu;
    dst &= mask; src &= mask;
    u32 cf, r;
    if (cnt <= bits) {
        cf = (dst >> (bits - cnt)) & 1u;
        r = ((dst << cnt) | (src >> (bits - cnt))) & mask;
    } else {
        cf = (src >> (2u * bits - cnt)) & 1u;
        r = (src << (cnt - bits)) & mask;
    }
    u32 of = ((r ^ dst) >> (bits - 1u)) & 1u;
    c.fl = cf | (of << 11);
    c.zs = (bits == 16u) ? (s16)r : (r == 0u ? 0 : ((r & 0x80000000u) ? -1 : 1));
    c.pb = r;
    return r;
}

static __attribute__((noinline)) u32 shrd_v(u32 dst, u32 src, u32 cnt, u32 bits)
{
    cnt &= 31u;
    if (!cnt) return dst;
    u32 mask = bits == 32u ? 0xFFFFFFFFu : 0xFFFFu;
    dst &= mask; src &= mask;
    u32 cf, r;
    if (cnt <= bits) {
        cf = (dst >> (cnt - 1u)) & 1u;
        r = ((dst >> cnt) | (src << (bits - cnt))) & mask;
    } else {
        cf = (src >> (cnt - bits - 1u)) & 1u;
        r = (src >> (cnt - bits)) & mask;
    }
    u32 of = ((r ^ dst) >> (bits - 1u)) & 1u;
    c.fl = cf | (of << 11);
    c.zs = (bits == 16u) ? (s16)r : (r == 0u ? 0 : ((r & 0x80000000u) ? -1 : 1));
    c.pb = r;
    return r;
}

static __attribute__((noinline)) u32 alu16(u32 k, u32 a, u32 b)
{
    switch (k & 7u) {
    case 0: return add16(a, b, 0);
    case 1: return logic16(a | b);
    case 2: return add16(a, b, c.fl & F_CF);
    case 3: return sub16(a, b, c.fl & F_CF);
    case 4: return logic16(a & b);
    case 6: return logic16(a ^ b);
    default: return sub16(a, b, 0);
    }
}

INLINE u32 alu32(u32 k, u32 a, u32 b)
{
    k &= 7u;
    if (k == 0u) return add32(a, b, 0u);
    if (k == 5u || k == 7u) return sub32(a, b, 0u);
    if (k == 4u) return logic32(a & b);
    if (k == 1u) return logic32(a | b);
    if (k == 6u) return logic32(a ^ b);
    if (k == 2u) return add32(a, b, c.fl & F_CF);
    return sub32(a, b, c.fl & F_CF);
}

INLINE u32 shld32_fast(u32 dst, u32 src, u32 cnt)
{
    cnt &= 31u;
    if (!cnt) return dst;
    u32 cf = (dst >> (32u - cnt)) & 1u;
    u32 r = (dst << cnt) | (src >> (32u - cnt));
    u32 of = ((r ^ dst) >> 31) & 1u;
    c.fl = cf | (of << 11);
    c.zs = ZS32(r);
    c.pb = r;
    return r;
}

INLINE u32 shrd32_fast(u32 dst, u32 src, u32 cnt)
{
    cnt &= 31u;
    if (!cnt) return dst;
    u32 cf = (dst >> (cnt - 1u)) & 1u;
    u32 r = (dst >> cnt) | (src << (32u - cnt));
    u32 of = ((r ^ dst) >> 31) & 1u;
    c.fl = cf | (of << 11);
    c.zs = ZS32(r);
    c.pb = r;
    return r;
}

INLINE u32 shift32_fast(u32 k, u32 v, u32 n)
{
    n &= 31u;
    if (!n) return v;
    k &= 7u;
    if (k == 4u || k == 6u) {
        u32 cf = (v >> (32u - n)) & 1u;
        u32 r = v << n;
        c.fl = cf | ((((r >> 31) ^ cf) & 1u) << 11);
        c.zs = ZS32(r);
        c.pb = r;
        return r;
    }
    if (k == 5u) {
        u32 cf = (v >> (n - 1u)) & 1u;
        u32 r = v >> n;
        c.fl = cf | (((v >> 31) & 1u) << 11);
        c.zs = ZS32(r);
        c.pb = r;
        return r;
    }
    if (k == 7u) {
        s32 sv = (s32)v;
        u32 cf = (u32)(sv >> (n - 1u)) & 1u;
        u32 r = (u32)(sv >> n);
        c.fl = cf;
        c.zs = ZS32(r);
        c.pb = r;
        return r;
    }
    return shift(k, v, n, 32u);
}

INLINE u32 inc32(u32 a)
{
    u32 r = a + 1u;
    c.fl = (c.fl & F_CF) | ((a ^ r) & F_AF) | (r == 0x80000000u ? F_OF : 0u);
    c.zs = ZS32(r);
    c.pb = r;
    return r;
}

INLINE u32 dec32(u32 a)
{
    u32 r = a - 1u;
    c.fl = (c.fl & F_CF) | ((a ^ r) & F_AF) | (a == 0x80000000u ? F_OF : 0u);
    c.zs = ZS32(r);
    c.pb = r;
    return r;
}

INLINE u32 imul32_fast(u32 a, u32 b)
{
    signed long long p = (signed long long)(s32)a * (signed long long)(s32)b;
    u32 lo = (u32)p, hi = (u32)((unsigned long long)p >> 32);
    c.fl = (hi != (u32)((s32)lo >> 31)) ? (F_CF | F_OF) : 0u;
    c.zs = ZS32(lo);
    c.pb = lo;
    return lo;
}

static __attribute__((noinline)) u32 imul32(u32 a, u32 b)
{
    return imul32_fast(a, b);
}

static void idle(void);
static __attribute__((noinline)) void op_0f(void)
{
    u32 op = fetch8(), m, v, r;
    switch (op) {
    case 0x00: {                        /* SLDT STR LLDT LTR VERR VERW */
        m = fetch8();
        u32 sub = (m >> 3) & 7u;
        if (sub == 0u) {                /* SLDT */
            ea_only(m);
            if (m >= 0xC0u) { if (op32) R32(m) = c.ldt_sel; else R16(m) = c.ldt_sel; }
            else wr16(ea_base, ea_off32, c.ldt_sel);
            return;
        }
        if (sub == 1u) {                /* STR */
            ea_only(m);
            if (m >= 0xC0u) { if (op32) R32(m) = c.tr_sel; else R16(m) = c.tr_sel; }
            else wr16(ea_base, ea_off32, c.tr_sel);
            return;
        }
        int sv_op = op32; op32 = 0;
        u16 sel = (u16)getv(m);
        op32 = sv_op;
        if (c.faulted) return;
        if (sub == 2u) {                /* LLDT */
            c.ldt_sel = sel;
            if ((sel & 0xFFFCu) == 0u) {
                c.ldt_base = 0; c.ldt_limit = 0;
            } else {
                u32 w0 = 0, w1 = 0;
                if (desc_read(sel, &w0, &w1, 0)) {
                    c.ldt_base = (w0 >> 16) | ((w1 & 0xFFu) << 16) | (w1 & 0xFF000000u);
                    c.ldt_limit = (u16)(w0 & 0xFFFFu);
                }
            }
            return;
        }
        if (sub == 3u) {                /* LTR */
            c.tr_sel = sel;
            u32 w0 = 0, w1 = 0, da = 0;
            if ((sel & 0xFFFCu) && desc_read(sel, &w0, &w1, &da)) {
                c.tr_base = (w0 >> 16) | ((w1 & 0xFFu) << 16) | (w1 & 0xFF000000u);
                c.tr_limit = (u16)(w0 & 0xFFFFu);
                c.tr_acc = (u8)((w1 >> 8) & 0xFFu);
                wr8(da + 5u, c.tr_acc | 2u);    /* mark TSS busy */
            }
            return;
        }
        if (sub == 4u || sub == 5u) {   /* VERR / VERW */
            int ok = 0;
            u32 w0 = 0, w1 = 0;
            if ((sel & 0xFFFCu) && desc_read(sel, &w0, &w1, 0) && (w1 & 0x1000u)) {
                u32 tp = (w1 >> 8) & 15u;
                if (sub == 4u) ok = !(tp & 8u) || (tp & 2u);
                else           ok = !(tp & 8u) && (tp & 2u);
            }
            c.zs = ok ? 0 : 1;
            return;
        }
        invalid();
        return;
    }
    case 0x01: {                        /* SGDT SIDT LGDT LIDT SMSW LMSW */
        m = fetch8();
        u32 sub = (m >> 3) & 7u;
        if (sub == 4u) {                /* SMSW */
            ea_only(m);
            if (m >= 0xC0u) { if (op32) R32(m) = c.cr0; else R16(m) = (u16)c.cr0; }
            else wr16(ea_base, ea_off32, (u16)c.cr0);
            return;
        }
        if (sub == 6u) {                /* LMSW */
            int sv_op = op32; op32 = 0;
            v = getv(m);
            op32 = sv_op;
            if (c.faulted) return;
            c.cr0 = (c.cr0 & 0xFFFFFFF0u) | (v & 0x0Fu) | (c.cr0 & 1u);
            if (c.cr0 & 1u) a20_mask = RAM_BYTES - 1u;
            return;
        }
        if (m >= 0xC0u) { invalid(); return; }
        ea(m);
        u32 lin = ea_base + ea_off32;
        if (sub == 0u) {                /* SGDT */
            wr16_lin(lin, c.gdt_limit);
            wr32_lin(lin + 2u, op32 ? c.gdt_base : (c.gdt_base & 0x00FFFFFFu));
            return;
        }
        if (sub == 1u) {                /* SIDT */
            wr16_lin(lin, c.idt_limit);
            wr32_lin(lin + 2u, op32 ? c.idt_base : (c.idt_base & 0x00FFFFFFu));
            return;
        }
        if (sub == 2u) {                /* LGDT */
            c.gdt_limit = rd16_lin(lin);
            c.gdt_base  = rd32_lin(lin + 2u) & (op32 ? 0xFFFFFFFFu : 0x00FFFFFFu);
            return;
        }
        if (sub == 3u) {                /* LIDT */
            c.idt_limit = rd16_lin(lin);
            c.idt_base  = rd32_lin(lin + 2u) & (op32 ? 0xFFFFFFFFu : 0x00FFFFFFu);
            return;
        }
        return;
    }
    case 0x02: {                        /* LAR */
        m = fetch8();
        int sv_op = op32; op32 = 0;
        u16 sel = (u16)getv(m);
        op32 = sv_op;
        if (c.faulted) return;
        u32 w0 = 0, w1 = 0;
        if ((sel & 0xFFFCu) && desc_read(sel, &w0, &w1, 0)) {
            if (op32) R32(m >> 3) = w1 & 0x00FFFF00u;
            else      R16(m >> 3) = (u16)(w1 & 0xFF00u);
            c.zs = 0;                   /* ZF = 1 */
        } else {
            c.zs = 1;                   /* ZF = 0 */
        }
        return;
    }
    case 0x03: {                        /* LSL */
        m = fetch8();
        int sv_op = op32; op32 = 0;
        u16 sel = (u16)getv(m);
        op32 = sv_op;
        if (c.faulted) return;
        u32 w0 = 0, w1 = 0;
        if ((sel & 0xFFFCu) && desc_read(sel, &w0, &w1, 0)) {
            u32 lim = (w0 & 0xFFFFu) | (w1 & 0x000F0000u);
            if (w1 & 0x00800000u) lim = (lim << 12) | 0xFFFu;
            if (op32) R32(m >> 3) = lim;
            else      R16(m >> 3) = (u16)lim;
            c.zs = 0;                   /* ZF = 1 */
        } else {
            c.zs = 1;                   /* ZF = 0 */
        }
        return;
    }
    case 0x06:                          /* CLTS */
        c.cr0 &= ~8u;
        return;
    case 0x08: case 0x09:               /* INVD / WBINVD */
        tlb_flush();
        return;
    case 0x20:                          /* MOV r32, CRn */
        m = fetch8();
        switch ((m >> 3) & 7u) {
        case 0: R32(m) = c.cr0; break;
        case 2: R32(m) = c.cr2; break;
        case 3: R32(m) = c.cr3; break;
        default: R32(m) = 0; break;
        }
        return;
    case 0x21:                          /* MOV r32, DRn */
        m = fetch8();
        R32(m) = c.dr[(m >> 3) & 7u];
        return;
    case 0x22: {                        /* MOV CRn, r32 */
        m = fetch8();
        v = R32(m);
        u32 crn = (m >> 3) & 7u;
        if (crn == 0u) {
            u32 old = c.cr0;
            c.cr0 = (v & 0x8000001Fu) | 0x00000010u;
            if (c.cr0 & 1u) a20_mask = RAM_BYTES - 1u;
            if ((old ^ c.cr0) & 0x80000001u) tlb_flush();
        } else if (crn == 2u) {
            c.cr2 = v;
        } else if (crn == 3u) {
            c.cr3 = v;
            tlb_flush();
        }
        return;
    }
    case 0x23:                          /* MOV DRn, r32 */
        m = fetch8();
        c.dr[(m >> 3) & 7u] = R32(m);
        return;
    case 0x24:                          /* MOV r32, TRn */
        m = fetch8();
        R32(m) = c.tr_reg[(m >> 3) & 7u];
        return;
    case 0x26:                          /* MOV TRn, r32 */
        m = fetch8();
        c.tr_reg[(m >> 3) & 7u] = R32(m);
        return;
    case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E: case 0x8F:
        v = op32 ? fetch32() : (u32)(s32)(s16)fetch16();
        if (cond(op)) {
            c.eip = op32 ? (c.eip + v) : (u32)(u16)(c.eip + v);
            c.cycles += pmode_on() ? PM_JCC32_TAKEN : 2;
            if (v & 0x80000000u)
                idle();
        }
        return;
    case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
    case 0x98: case 0x99: case 0x9A: case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F:
        m = fetch8();
        ea_only(m);
        put8(m, cond(op) ? 1u : 0u);
        return;
    case 0xA0: pushv(c.sr[FS]); return;
    case 0xA1: v = popv(); if (!c.faulted) set_seg(FS, v); return;
    case 0xA8: pushv(c.sr[GS]); return;
    case 0xA9: v = popv(); if (!c.faulted) set_seg(GS, v); return;
    case 0xA3: case 0xAB: case 0xB3: case 0xBB: case 0xBA: {
        /* BT (0), BTS (1), BTR (2), BTC (3) */
        m = fetch8();
        u32 kind = (op == 0xBAu) ? (((m >> 3) & 7u) - 4u) : ((op >> 3) & 3u);
        if (op == 0xBAu && ((m >> 3) & 7u) < 4u) { invalid(); return; }
        u32 bits = op32 ? 32u : 16u;
        if (m >= 0xC0u) {
            u32 bi = (op == 0xBAu ? fetch8() : (op32 ? R32(m >> 3) : R16(m >> 3))) & (bits - 1u);
            u32 rv = op32 ? R32(m) : R16(m);
            c.fl = (c.fl & ~F_CF) | ((rv >> bi) & 1u);
            if (kind == 1u) rv |= (1u << bi);
            else if (kind == 2u) rv &= ~(1u << bi);
            else if (kind == 3u) rv ^= (1u << bi);
            if (kind) { if (op32) R32(m) = rv; else R16(m) = (u16)rv; }
            return;
        }
        ea(m);
        s32 boff = (op == 0xBAu) ? (s32)(fetch8() & (bits - 1u)) : (op32 ? (s32)R32(m >> 3) : (s32)(s16)R16(m >> 3));
        u32 addr_delta = (op == 0xBAu) ? 0u : (u32)((boff >> (op32 ? 5 : 4)) * (op32 ? 4 : 2));
        u32 bi = (u32)boff & (bits - 1u);
        u32 off = ea_off32 + addr_delta;
        u32 mv = op32 ? rd32(ea_base, off) : rd16(ea_base, off);
        if (c.faulted) return;
        c.fl = (c.fl & ~F_CF) | ((mv >> bi) & 1u);
        if (kind == 1u) mv |= (1u << bi);
        else if (kind == 2u) mv &= ~(1u << bi);
        else if (kind == 3u) mv ^= (1u << bi);
        if (kind) {
            if (op32) wr32(ea_base, off, mv);
            else      wr16(ea_base, off, mv);
        }
        return;
    }
    case 0xA4: case 0xA5: {             /* SHLD */
        m = fetch8();
        v = getv(m);
        u32 src_r = op32 ? R32(m >> 3) : R16(m >> 3);
        u32 cnt = (op == 0xA4u) ? fetch8() : rCL;
        if (!c.faulted) putv(m, shld_v(v, src_r, cnt, op32 ? 32u : 16u));
        return;
    }
    case 0xAC: case 0xAD: {             /* SHRD */
        m = fetch8();
        v = getv(m);
        u32 src_r = op32 ? R32(m >> 3) : R16(m >> 3);
        u32 cnt = (op == 0xACu) ? fetch8() : rCL;
        if (!c.faulted) putv(m, shrd_v(v, src_r, cnt, op32 ? 32u : 16u));
        return;
    }
    case 0xAF:                          /* IMUL r, r/m */
        m = fetch8();
        v = getv(m);
        if (c.faulted) return;
        r = imul_v(op32 ? R32(m >> 3) : R16(m >> 3), v);
        if (op32) R32(m >> 3) = r;
        else      R16(m >> 3) = (u16)r;
        return;
    case 0xB0: {                        /* CMPXCHG r/m8, r8 */
        m = fetch8();
        v = get8(m);
        if (c.faulted) return;
        sub8(rAL, v, 0);
        if (rAL == (u8)v) put8(m, R8(m >> 3));
        else              rAL = (u8)v;
        return;
    }
    case 0xB1: {                        /* CMPXCHG r/m16/32, r16/32 */
        m = fetch8();
        v = getv(m);
        if (c.faulted) return;
        u32 acc = op32 ? rEAX : rAX;
        aluv(7, acc, v);
        if (acc == v) putv(m, op32 ? R32(m >> 3) : R16(m >> 3));
        else          { if (op32) rEAX = v; else rAX = (u16)v; }
        return;
    }
    case 0xB2: case 0xB4: case 0xB5: {  /* LSS, LFS, LGS */
        m = fetch8();
        if (m >= 0xC0u) { invalid(); return; }
        ea(m);
        int seg_i = (op == 0xB2u) ? SS : (op == 0xB4u ? FS : GS);
        u32 off_v = op32 ? rd32(ea_base, ea_off32) : rd16(ea_base, ea_off32);
        u32 sel_v = rd16(ea_base, ea_off32 + (op32 ? 4u : 2u));
        if (c.faulted) return;
        set_seg(seg_i, sel_v);
        if (!c.faulted) {
            if (op32) R32(m >> 3) = off_v;
            else      R16(m >> 3) = (u16)off_v;
        }
        return;
    }
    case 0xB6:                          /* MOVZX r16/32, r/m8 */
        m = fetch8();
        v = get8(m);
        if (c.faulted) return;
        if (op32) R32(m >> 3) = v;
        else      R16(m >> 3) = (u16)v;
        return;
    case 0xB7: {                        /* MOVZX r32, r/m16 */
        m = fetch8();
        int sv = op32; op32 = 0;
        v = getv(m);
        op32 = sv;
        if (c.faulted) return;
        if (op32) R32(m >> 3) = v;
        else      R16(m >> 3) = (u16)v;
        return;
    }
    case 0xBE:                          /* MOVSX r16/32, r/m8 */
        m = fetch8();
        v = (u32)(s32)(s8)get8(m);
        if (c.faulted) return;
        if (op32) R32(m >> 3) = v;
        else      R16(m >> 3) = (u16)v;
        return;
    case 0xBF: {                        /* MOVSX r32, r/m16 */
        m = fetch8();
        int sv = op32; op32 = 0;
        v = (u32)(s32)(s16)getv(m);
        op32 = sv;
        if (c.faulted) return;
        if (op32) R32(m >> 3) = v;
        else      R16(m >> 3) = (u16)v;
        return;
    }
    case 0xBC: case 0xBD: {             /* BSF / BSR */
        m = fetch8();
        v = getv(m);
        if (c.faulted) return;
        if (!v) {
            c.zs = 0;                   /* ZF = 1 */
        } else {
            c.zs = 1;                   /* ZF = 0 */
            u32 idx = 0;
            if (op == 0xBCu) {
                while (!(v & (1u << idx))) idx++;
            } else {
                idx = op32 ? 31u : 15u;
                while (!(v & (1u << idx))) idx--;
            }
            if (op32) R32(m >> 3) = idx;
            else      R16(m >> 3) = (u16)idx;
        }
        return;
    }
    case 0xC0: {                        /* XADD r/m8, r8 */
        m = fetch8();
        v = get8(m);
        if (c.faulted) return;
        u32 rv = R8(m >> 3);
        put8(m, add8(v, rv, 0));
        if (!c.faulted) R8(m >> 3) = (u8)v;
        return;
    }
    case 0xC1: {                        /* XADD r/m16/32, r16/32 */
        m = fetch8();
        v = getv(m);
        if (c.faulted) return;
        u32 rv = op32 ? R32(m >> 3) : R16(m >> 3);
        putv(m, aluv(0, v, rv));
        if (!c.faulted) { if (op32) R32(m >> 3) = v; else R16(m >> 3) = (u16)v; }
        return;
    }
    case 0xC8: case 0xC9: case 0xCA: case 0xCB: case 0xCC: case 0xCD: case 0xCE: case 0xCF: {
        u32 x = R32(op);
        R32(op) = (x >> 24) | ((x >> 8) & 0xFF00u) | ((x & 0xFF00u) << 8) | (x << 24);
        return;
    }
    default:
        invalid();
        return;
    }
}

static const u8 cyc[256] = {
    2, 2, 2, 2, 3, 3, 3, 5, 2, 2, 2, 2, 3, 3, 3, 0,
    2, 2, 2, 2, 3, 3, 3, 5, 2, 2, 2, 2, 3, 3, 3, 5,
    2, 2, 2, 2, 3, 3, 0, 3, 2, 2, 2, 2, 3, 3, 0, 3,
    2, 2, 2, 2, 3, 3, 0, 3, 2, 2, 2, 2, 3, 3, 0, 3,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 5, 5, 5, 5, 5, 5, 5, 5,
    17, 19, 13, 2, 0, 0, 0, 0, 3, 21, 3, 21, 5, 5, 5, 5,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 2, 2, 3, 3, 2, 2, 2, 2, 2, 3, 2, 5,
    3, 3, 3, 3, 3, 3, 3, 3, 2, 2, 13, 3, 3, 5, 2, 2,
    5, 5, 3, 3, 5, 5, 8, 8, 3, 3, 3, 3, 5, 5, 7, 7,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    5, 5, 11, 11, 7, 7, 3, 3, 11, 5, 15, 15, 23, 23, 3, 17,
    2, 2, 5, 5, 16, 14, 2, 5, 2, 2, 2, 2, 2, 2, 2, 2,
    8, 8, 8, 8, 5, 5, 3, 3, 7, 7, 11, 7, 5, 5, 3, 3,
    0, 0, 0, 0, 2, 2, 3, 3, 2, 2, 2, 2, 2, 2, 3, 3,
};

static struct {
    u32 wr_snap, cs_eip, fl, pb, sys;
    s32 zs;
    u32 reg[8];
    u16 sr[6];
    u8  armed;
} was, was0f;
static u32 idle_cycles;

static void idle(void)
{
    if (!(c.sys & F_IF)) {
        was.sys = c.sys;
        was.armed = 0;
        return;
    }
    const u32 *cs_sr32 = (const u32 *)(const void *)c.sr;
    u32 *was_sr32 = (u32 *)(void *)was.sr;
    u32 cs_eip = ((u32)c.sr[CS] << 16) ^ c.eip;
    if (was.armed && cs_eip == was.cs_eip && writes == was.wr_snap && c.fl == was.fl && c.zs == was.zs &&
        c.pb == was.pb && c.sys == was.sys &&
        cs_sr32[0] == was_sr32[0] && cs_sr32[1] == was_sr32[1] && cs_sr32[2] == was_sr32[2] &&
        c.reg[0].d == was.reg[0] && c.reg[1].d == was.reg[1] &&
        c.reg[2].d == was.reg[2] && c.reg[3].d == was.reg[3] &&
        c.reg[4].d == was.reg[4] && c.reg[5].d == was.reg[5] &&
        c.reg[6].d == was.reg[6] && c.reg[7].d == was.reg[7]) {
        if (c.cycles < run_end) {
            idle_cycles += (u32)(run_end - c.cycles);
            c.cycles = run_end;
            return;
        }
    }
    was.cs_eip = cs_eip; was.wr_snap = writes; was.fl = c.fl;
    was.zs = c.zs; was.pb = c.pb; was.sys = c.sys;
    was.reg[0] = c.reg[0].d; was.reg[1] = c.reg[1].d;
    was.reg[2] = c.reg[2].d; was.reg[3] = c.reg[3].d;
    was.reg[4] = c.reg[4].d; was.reg[5] = c.reg[5].d;
    was.reg[6] = c.reg[6].d; was.reg[7] = c.reg[7].d;
    was_sr32[0] = cs_sr32[0];
    was_sr32[1] = cs_sr32[1];
    was_sr32[2] = cs_sr32[2];
    was.armed = 1;
}

static __attribute__((noinline, optimize("O2,no-align-jumps,no-align-loops,no-align-labels"))) void step(void)
{
    u32 op, m, v, r, rep = 0;
    sego = -1;
    op32 = c.d32[CS];
    ad32 = c.d32[CS];
    c.op_eip = c.eip;
    c.faulted = 0;
#ifdef DOS_PROFILE
    DOS_PROFILE(c.sr[CS], (u16)c.eip);
#endif
next:
    if (__builtin_expect(!(c.cr0 & 0x80000000u), 1)) {
        u32 ip_ = c.d32[CS] ? c.eip++ : (u32)(u16)c.eip;
        if (!c.d32[CS]) c.eip = (u16)(ip_ + 1u);
        u32 p_ = (c.base[CS] + ip_) & a20_mask;
        op = __builtin_expect(p_ < RAM_BYTES, 1) ? mem[p_] : 0xFFu;
    } else {
        op = fetch8();
        if (c.faulted) return;
    }
    c.cycles += pmode_on() ? PM_STEP_CYC : cyc[op];
    switch (op) {
    case 0x00: case 0x08: case 0x10: case 0x18: case 0x20: case 0x28: case 0x30: case 0x38:
        m = fetch8();
        r = alu8(op >> 3, get8(m), R8(m >> 3));
        if (op != 0x38u) put8(m, r);
        break;
    case 0x01: case 0x09: case 0x11: case 0x19: case 0x21: case 0x29: case 0x31: case 0x39:
        m = fetch8();
        r = aluv(op >> 3, getv(m), op32 ? R32(m >> 3) : R16(m >> 3));
        if (op != 0x39u) putv(m, r);
        break;
    case 0x02: case 0x0A: case 0x12: case 0x1A: case 0x22: case 0x2A: case 0x32: case 0x3A:
        m = fetch8();
        r = alu8(op >> 3, R8(m >> 3), get8(m));
        if (!c.faulted && op != 0x3Au) R8(m >> 3) = (u8)r;
        break;
    case 0x03: case 0x0B: case 0x13: case 0x1B: case 0x23: case 0x2B: case 0x33: case 0x3B:
        m = fetch8();
        r = aluv(op >> 3, op32 ? R32(m >> 3) : R16(m >> 3), getv(m));
        if (!c.faulted && op != 0x3Bu) {
            if (op32) R32(m >> 3) = r;
            else      R16(m >> 3) = (u16)r;
        }
        break;
    case 0x04: case 0x0C: case 0x14: case 0x1C: case 0x24: case 0x2C: case 0x34: case 0x3C:
        r = alu8(op >> 3, rAL, fetch8());
        if (op != 0x3Cu) rAL = (u8)r;
        break;
    case 0x05: case 0x0D: case 0x15: case 0x1D: case 0x25: case 0x2D: case 0x35: case 0x3D:
        if (op32) {
            r = aluv(op >> 3, rEAX, fetch32());
            if (op != 0x3Du) rEAX = r;
        } else {
            r = aluv(op >> 3, rAX, fetch16());
            if (op != 0x3Du) rAX = (u16)r;
        }
        break;
    case 0x06: case 0x0E: case 0x16: case 0x1E:
        pushv(c.sr[(op >> 3) & 3u]);
        break;
    case 0x07: case 0x17: case 0x1F:
        v = popv();
        if (!c.faulted) set_seg((int)((op >> 3) & 3u), v);
        break;
    case 0x0F:
        op_0f();
        break;
    case 0x26: case 0x2E: case 0x36: case 0x3E:
        sego = (int)((op >> 3) & 3u);
        goto next;
    case 0x64: sego = FS; goto next;
    case 0x65: sego = GS; goto next;
    case 0x66: op32 = !op32; goto next;
    case 0x67: ad32 = !ad32; goto next;
    case 0x27: {                        /* DAA */
        u32 a = rAL, cf = c.fl & F_CF, af = 0;
        if ((a & 0xFu) > 9u || (c.fl & F_AF)) { rAL = (u8)(a + 6u); af = F_AF; }
        if (a > 0x99u || cf) { rAL += 0x60u; cf = 1u; }
        c.fl = cf | af; c.zs = (s8)rAL; c.pb = rAL;
        break;
    }
    case 0x2F: {                        /* DAS */
        u32 a = rAL, cf = c.fl & F_CF, af = 0;
        if ((a & 0xFu) > 9u || (c.fl & F_AF)) { rAL = (u8)(a - 6u); af = F_AF; }
        if (a > 0x99u || cf) { rAL -= 0x60u; cf = 1u; }
        c.fl = cf | af; c.zs = (s8)rAL; c.pb = rAL;
        break;
    }
    case 0x37: case 0x3F:               /* AAA, AAS */
        if ((rAL & 0xFu) > 9u || (c.fl & F_AF)) {
            rAX = (u16)(op == 0x37u ? rAX + 0x106u : rAX - 0x106u);
            c.fl = F_AF | F_CF;
        } else {
            c.fl = 0;
        }
        rAL &= 0xFu; c.zs = (s8)rAL; c.pb = rAL;
        break;
    case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47:
        if (op32) R32(op) = incv(R32(op));
        else      R16(op) = (u16)incv(R16(op));
        break;
    case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F:
        if (op32) R32(op) = decv(R32(op));
        else      R16(op) = (u16)decv(R16(op));
        break;
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57:
        pushv(op32 ? R32(op) : R16(op));
        break;
    case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F:
        v = popv();
        if (!c.faulted) {
            if (op32) R32(op) = v;
            else      R16(op) = (u16)v;
        }
        break;
    case 0x60: {                        /* PUSHA / PUSHAD */
        if (op32) {
            u32 esp = rESP;
            for (int i = 0; i < 8; i++) push32(i == 4 ? esp : c.reg[i].d);
        } else {
            u32 sp = rSP;
            for (int i = 0; i < 8; i++) push16(i == 4 ? sp : R16(i));
        }
        break;
    }
    case 0x61:                          /* POPA / POPAD */
        if (op32) {
            for (int i = 7; i >= 0; i--) { v = pop32(); if (!c.faulted && i != 4) c.reg[i].d = v; }
        } else {
            for (int i = 7; i >= 0; i--) { v = pop16(); if (!c.faulted && i != 4) R16(i) = (u16)v; }
        }
        break;
    case 0x62: {                        /* BOUND */
        m = fetch8();
        ea_only(m);
        if (op32) {
            s32 i = (s32)R32(m >> 3), lo = (s32)rd32(ea_base, ea_off32), hi = (s32)rd32(ea_base, ea_off32 + 4u);
            if (!c.faulted && (i < lo || i > hi)) { c.eip = c.op_eip; interrupt(5); }
        } else {
            s32 i = (s16)R16(m >> 3), lo = (s16)rd16(ea_base, ea_off32), hi = (s16)rd16(ea_base, ea_off32 + 2u);
            if (!c.faulted && (i < lo || i > hi)) { c.eip = c.op_eip; interrupt(5); }
        }
        break;
    }
    case 0x63: {                        /* ARPL r/m16, r16 */
        if (!pmode_on()) { invalid(); break; }
        m = fetch8();
        int sv = op32; op32 = 0;
        u32 dst = getv(m), src = R16(m >> 3);
        if (!c.faulted) {
            if ((dst & 3u) < (src & 3u)) {
                dst = (dst & 0xFFFCu) | (src & 3u);
                putv(m, dst);
                c.zs = 0;               /* ZF = 1 */
            } else {
                c.zs = 1;               /* ZF = 0 */
            }
        }
        op32 = sv;
        break;
    }
    case 0x68:
        pushv(op32 ? fetch32() : fetch16());
        break;
    case 0x6A:
        pushv((u32)(s32)(s8)fetch8());
        break;
    case 0x69:
        m = fetch8();
        v = getv(m);
        r = imul_v(v, op32 ? fetch32() : fetch16());
        if (!c.faulted) { if (op32) R32(m >> 3) = r; else R16(m >> 3) = (u16)r; }
        break;
    case 0x6B:
        m = fetch8();
        v = getv(m);
        r = imul_v(v, (u32)(s32)(s8)fetch8());
        if (!c.faulted) { if (op32) R32(m >> 3) = r; else R16(m >> 3) = (u16)r; }
        break;
    case 0x6C: case 0x6D: case 0x6E: case 0x6F:
    case 0xA4: case 0xA5: case 0xA6: case 0xA7: case 0xAA: case 0xAB: case 0xAC: case 0xAD: case 0xAE: case 0xAF:
        string(op, rep);
        break;
    case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B: case 0x7C: case 0x7D: case 0x7E: case 0x7F:
        v = (u32)(s32)(s8)fetch8();
        if (cond(op)) {
            c.eip = op32 ? (c.eip + v) : (u32)(u16)(c.eip + v);
            if (!pmode_on()) c.cycles += 4;
            if (v & 0x80000000u)
                idle();
        }
        break;
    case 0x80: case 0x82:
        m = fetch8();
        v = get8(m);
        r = alu8(m >> 3, v, fetch8());
        if (((m >> 3) & 7u) != 7u) put8(m, r);
        break;
    case 0x81:
        m = fetch8();
        v = getv(m);
        r = aluv(m >> 3, v, op32 ? fetch32() : fetch16());
        if (((m >> 3) & 7u) != 7u) putv(m, r);
        break;
    case 0x83:
        m = fetch8();
        v = getv(m);
        r = aluv(m >> 3, v, (u32)(s32)(s8)fetch8());
        if (((m >> 3) & 7u) != 7u) putv(m, r);
        break;
    case 0x84:
        m = fetch8();
        logic8(get8(m) & R8(m >> 3));
        break;
    case 0x85:
        m = fetch8();
        logicv(getv(m) & (op32 ? R32(m >> 3) : R16(m >> 3)));
        break;
    case 0x86:
        m = fetch8();
        v = get8(m);
        put8(m, R8(m >> 3));
        if (!c.faulted) R8(m >> 3) = (u8)v;
        break;
    case 0x87:
        m = fetch8();
        v = getv(m);
        putv(m, op32 ? R32(m >> 3) : R16(m >> 3));
        if (!c.faulted) { if (op32) R32(m >> 3) = v; else R16(m >> 3) = (u16)v; }
        break;
    case 0x88:
        m = fetch8();
        ea_only(m);
        put8(m, R8(m >> 3));
        break;
    case 0x89:
        m = fetch8();
        ea_only(m);
        putv(m, op32 ? R32(m >> 3) : R16(m >> 3));
        break;
    case 0x8A:
        m = fetch8();
        v = get8(m);
        if (!c.faulted) R8(m >> 3) = (u8)v;
        break;
    case 0x8B:
        m = fetch8();
        v = getv(m);
        if (!c.faulted) { if (op32) R32(m >> 3) = v; else R16(m >> 3) = (u16)v; }
        break;
    case 0x8C: {                        /* MOV r/m16, Sreg */
        m = fetch8();
        u32 sidx = (m >> 3) & 7u;
        if (sidx >= 6u) { invalid(); break; }
        if (m >= 0xC0u) {
            if (op32) R32(m) = c.sr[sidx];
            else      R16(m) = c.sr[sidx];
        } else {
            ea(m);
            wr16(ea_base, ea_off32, c.sr[sidx]);
        }
        break;
    }
    case 0x8D:
        m = fetch8();
        ea_only(m);
        if (op32) R32(m >> 3) = ea_off32;
        else      R16(m >> 3) = (u16)ea_off32;
        break;
    case 0x8E: {                        /* MOV Sreg, r/m16 */
        m = fetch8();
        u32 sidx = (m >> 3) & 7u;
        if (sidx >= 6u || sidx == CS) { invalid(); break; }
        int sv = op32; op32 = 0;
        v = getv(m);
        op32 = sv;
        if (!c.faulted) {
            set_seg((int)sidx, v);
            if (sidx == SS) c.check = 2;
        }
        break;
    }
    case 0x8F:                          /* POP r/m (pop BEFORE evaluating [ESP + disp]!) */
        m = fetch8();
        v = popv();
        if (!c.faulted) {
            ea_only(m);
            putv(m, v);
        }
        break;
    case 0x90:
        break;
    case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
        if (op32) { v = rEAX; rEAX = R32(op); R32(op) = v; }
        else      { v = rAX;  rAX  = R16(op); R16(op) = (u16)v; }
        break;
    case 0x98:                          /* CBW / CWDE */
        if (op32) rEAX = (u32)(s32)(s16)rAX;
        else      rAH  = (rAL & 0x80u) ? 0xFFu : 0u;
        break;
    case 0x99:                          /* CWD / CDQ */
        if (op32) rEDX = (rEAX & 0x80000000u) ? 0xFFFFFFFFu : 0u;
        else      rDX  = (rAX & 0x8000u) ? 0xFFFFu : 0u;
        break;
    case 0x9A: {                        /* CALL ptr16:16/32 */
        u32 off = op32 ? fetch32() : fetch16(), seg = fetch16();
        pushv(c.sr[CS]);
        pushv(c.eip);
        if (!c.faulted) {
            set_seg(CS, seg);
            if (!c.faulted) c.eip = off;
        }
        break;
    }
    case 0x9B:
        break;
    case 0x9C:
        pushv(get_eflags() & (op32 ? 0x00FCFFFFu : 0xFFFFu));
        break;
    case 0x9D:
        v = popv();
        if (!c.faulted) {
            set_eflags(v, op32);
            c.check = 1;
        }
        break;
    case 0x9E:
        set_eflags((get_eflags() & ~0xFFu) | rAH, 0);
        break;
    case 0x9F:
        rAH = (u8)get_eflags();
        break;
    case 0xA0: {
        u32 mo = ad32 ? fetch32() : fetch16();
        rAL = rd8(c.base[sego >= 0 ? sego : DS] + mo);
        break;
    }
    case 0xA1: {
        u32 mo = ad32 ? fetch32() : fetch16();
        if (op32) rEAX = rd32(c.base[sego >= 0 ? sego : DS], mo);
        else      rAX  = rd16(c.base[sego >= 0 ? sego : DS], mo);
        break;
    }
    case 0xA2: {
        u32 mo = ad32 ? fetch32() : fetch16();
        wr8(c.base[sego >= 0 ? sego : DS] + mo, rAL);
        break;
    }
    case 0xA3: {
        u32 mo = ad32 ? fetch32() : fetch16();
        if (op32) wr32(c.base[sego >= 0 ? sego : DS], mo, rEAX);
        else      wr16(c.base[sego >= 0 ? sego : DS], mo, rAX);
        break;
    }
    case 0xA8:
        logic8(rAL & fetch8());
        break;
    case 0xA9:
        if (op32) logic32(rEAX & fetch32());
        else      logic16(rAX  & fetch16());
        break;
    case 0xB0: case 0xB1: case 0xB2: case 0xB3: case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        R8(op) = (u8)fetch8();
        break;
    case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        if (op32) R32(op) = fetch32();
        else      R16(op) = (u16)fetch16();
        break;
    case 0xC0: case 0xD0: case 0xD2:
        m = fetch8();
        v = get8(m);
        if (!c.faulted) put8(m, shift(m >> 3, v, op == 0xC0u ? fetch8() : op == 0xD0u ? 1u : rCL, 8u));
        break;
    case 0xC1: case 0xD1: case 0xD3:
        m = fetch8();
        v = getv(m);
        if (!c.faulted) putv(m, shift(m >> 3, v, op == 0xC1u ? fetch8() : op == 0xD1u ? 1u : rCL, op32 ? 32u : 16u));
        break;
    case 0xC2:
        v = fetch16();
        r = popv();
        if (!c.faulted) {
            c.eip = r;
            if (c.d32[SS]) rESP += v; else rSP = (u16)(rSP + v);
        }
        break;
    case 0xC3:
        r = popv();
        if (!c.faulted) c.eip = r;
        break;
    case 0xC4: case 0xC5:               /* LES / LDS */
        m = fetch8();
        ea_only(m);
        v = op32 ? rd32(ea_base, ea_off32) : rd16(ea_base, ea_off32);
        r = rd16(ea_base, ea_off32 + (op32 ? 4u : 2u));
        if (!c.faulted) {
            set_seg(op == 0xC4u ? ES : DS, r);
            if (!c.faulted) { if (op32) R32(m >> 3) = v; else R16(m >> 3) = (u16)v; }
        }
        break;
    case 0xC6:
        m = fetch8();
        ea_only(m);
        put8(m, fetch8());
        break;
    case 0xC7:
        m = fetch8();
        ea_only(m);
        putv(m, op32 ? fetch32() : fetch16());
        break;
    case 0xC8: {                        /* ENTER */
        u32 size = fetch16(), level = fetch8() & 31u;
        if (op32) {
            push32(rEBP);
            u32 frame = rESP;
            if (level) {
                for (u32 i = 1; i < level; i++) {
                    rEBP -= 4u;
                    push32(rd32_lin(c.base[SS] + rEBP));
                }
                push32(frame);
            }
            rEBP = frame;
            if (c.d32[SS]) rESP -= size; else rSP = (u16)(rSP - size);
        } else {
            push16(rBP);
            u32 frame = rSP;
            if (level) {
                for (u32 i = 1; i < level; i++) {
                    rBP -= 2u;
                    push16(rd16(c.base[SS], rBP));
                }
                push16(frame);
            }
            rBP = (u16)frame;
            if (c.d32[SS]) rESP -= size; else rSP = (u16)(rSP - size);
        }
        break;
    }
    case 0xC9:                          /* LEAVE */
        if (c.d32[SS]) rESP = rEBP; else rSP = rBP;
        v = popv();
        if (!c.faulted) { if (op32) rEBP = v; else rBP = (u16)v; }
        break;
    case 0xCA: case 0xCB: {             /* RETF */
        u32 add_sp = op == 0xCAu ? fetch16() : 0u;
        u32 new_eip = popv();
        u32 new_cs  = popv() & 0xFFFFu;
        if (c.faulted) break;
        u32 cur_cpl = pmode_on() ? (c.sr[CS] & 3u) : 0u;
        if (c.d32[SS]) rESP += add_sp; else rSP = (u16)(rSP + add_sp);
        if (pmode_on() && (new_cs & 3u) > cur_cpl) {
            u32 new_esp = popv();
            u32 new_ss  = popv() & 0xFFFFu;
            set_seg(CS, new_cs);
            set_seg(SS, new_ss);
            if (c.d32[SS]) rESP = new_esp + add_sp; else rSP = (u16)(new_esp + add_sp);
        } else {
            set_seg(CS, new_cs);
        }
        c.eip = new_eip;
        break;
    }
    case 0xCC:
        interrupt_ex(3, 1, 0, 0);
        break;
    case 0xCD:
        v = fetch8();
        interrupt_ex(v, 1, 0, 0);
        break;
    case 0xCE:
        if (c.fl & F_OF) interrupt_ex(4, 1, 0, 0);
        break;
    case 0xCF: {                        /* IRET / IRETD */
        u32 cur_cpl = pmode_on() ? (c.sr[CS] & 3u) : 0u;
        u32 new_eip = popv();
        u32 new_cs  = popv() & 0xFFFFu;
        u32 new_fl  = popv();
        if (c.faulted) break;
        if (pmode_on() && op32 && (new_fl & F_VM) && cur_cpl == 0u) {
            u32 new_esp = pop32(), new_ss = pop32();
            u32 new_es = pop32(), new_ds = pop32(), new_fs = pop32(), new_gs = pop32();
            c.sys |= F_VM;
            set_eflags(new_fl, 1);
            set_seg_real(CS, new_cs); c.eip = new_eip & 0xFFFFu;
            set_seg_real(SS, new_ss); rESP = new_esp;
            set_seg_real(ES, new_es); set_seg_real(DS, new_ds);
            set_seg_real(FS, new_fs); set_seg_real(GS, new_gs);
            c.check = 1;
            break;
        }
        if (pmode_on() && (new_cs & 3u) > cur_cpl) {
            u32 new_esp = popv();
            u32 new_ss  = popv() & 0xFFFFu;
            set_seg(CS, new_cs);
            set_seg(SS, new_ss);
            if (c.d32[SS]) rESP = new_esp; else rSP = (u16)new_esp;
        } else {
            set_seg(CS, new_cs);
        }
        c.eip = op32 ? new_eip : (new_eip & 0xFFFFu);
        set_eflags(new_fl, op32);
        c.check = 1;
        break;
    }
    case 0xD4:
        v = fetch8();
        if (!v) { divide_error(); break; }
        rAH = (u8)(rAL / v);
        rAL = (u8)(rAL % v);
        logic8(rAL);
        break;
    case 0xD5:
        v = fetch8();
        rAX = (u16)logic8(rAL + rAH * v);
        break;
    case 0xD6:
        rAL = (c.fl & F_CF) ? 0xFFu : 0u;
        break;
    case 0xD7: {
        u32 off = ad32 ? (rEBX + rAL) : (u16)(rBX + rAL);
        rAL = rd8(c.base[sego >= 0 ? sego : DS] + off);
        break;
    }
    case 0xD8: case 0xD9: case 0xDA: case 0xDB: case 0xDC: case 0xDD: case 0xDE: case 0xDF: {
        /* Minimal FPU stub: FNSTSW AX / FNSTSW m16 / FNSTCW m16 write valid idle words so FPU probes never hang! */
        m = fetch8();
        if (op == 0xDFu && m == 0xE0u) { rAX = 0xFFFFu; break; } /* FNSTSW AX -> no FPU present (0xFF) */
        if (m < 0xC0u) {
            ea(m);
            if (op == 0xD9u && ((m >> 3) & 7u) == 7u) wr16(ea_base, ea_off32, 0x037Fu); /* FNSTCW */
            if (op == 0xDDu && ((m >> 3) & 7u) == 7u) wr16(ea_base, ea_off32, 0xFFFFu); /* FNSTSW */
        }
        break;
    }
    case 0xE0: case 0xE1: case 0xE2: {
        v = (u32)(s32)(s8)fetch8();
        u32 cnt = ad32 ? --rECX : (u32)--rCX;
        if (cnt && (op == 0xE2u || (op == 0xE1u) == !((u32)c.zs << 1)))
            c.eip = op32 ? (c.eip + v) : (u32)(u16)(c.eip + v);
        break;
    }
    case 0xE3: {
        v = (u32)(s32)(s8)fetch8();
        u32 cnt = ad32 ? rECX : rCX;
        if (!cnt)
            c.eip = op32 ? (c.eip + v) : (u32)(u16)(c.eip + v);
        break;
    }
    case 0xE4: rAL = in8(fetch8()); break;
    case 0xE5: if (op32) rEAX = in32(fetch8()); else rAX = (u16)in16(fetch8()); break;
    case 0xE6: out8(fetch8(), rAL); break;
    case 0xE7: if (op32) out32(fetch8(), rEAX); else out16(fetch8(), rAX); break;
    case 0xEC: rAL = in8(rDX); break;
    case 0xED: if (op32) rEAX = in32(rDX); else rAX = (u16)in16(rDX); break;
    case 0xEE: out8(rDX, rAL); break;
    case 0xEF: if (op32) out32(rDX, rEAX); else out16(rDX, rAX); break;
    case 0xE8:
        v = op32 ? fetch32() : fetch16();
        pushv(c.eip);
        if (!c.faulted) c.eip = op32 ? (c.eip + v) : (u32)(u16)(c.eip + v);
        break;
    case 0xE9:
        v = op32 ? fetch32() : (u32)(s32)(s16)fetch16();
        c.eip = op32 ? (c.eip + v) : (u32)(u16)(c.eip + v);
        if (v & 0x80000000u) idle();
        break;
    case 0xEA: {
        u32 off = op32 ? fetch32() : fetch16(), seg = fetch16();
        set_seg(CS, seg);
        if (!c.faulted) c.eip = off;
        break;
    }
    case 0xEB:
        v = (u32)(s32)(s8)fetch8();
        c.eip = op32 ? (c.eip + v) : (u32)(u16)(c.eip + v);
        if (v & 0x80000000u) idle();
        break;
    case 0xF0:
        goto next;
    case 0xF1:
        if (!pmode_on() && c.sr[CS] == 0xF000u) {
            hle(fetch8());
            break;
        }
        goto next;
    case 0xF2: case 0xF3:
        rep = op;
        goto next;
    case 0xF4:
        c.halted = 1;
        break;
    case 0xF5:
        c.fl ^= F_CF;
        break;
    case 0xF6: case 0xF7:
        group3(op);
        break;
    case 0xF8: c.fl &= ~F_CF; break;
    case 0xF9: c.fl |=  F_CF; break;
    case 0xFA: c.sys &= ~F_IF; break;
    case 0xFB: c.sys |= F_IF; c.check = 2; break;
    case 0xFC: c.sys &= ~F_DF; break;
    case 0xFD: c.sys |=  F_DF; break;
    case 0xFE:
        m = fetch8();
        v = get8(m);
        if (!c.faulted) {
            if (((m >> 3) & 7u) == 0u)      put8(m, inc8(v));
            else if (((m >> 3) & 7u) == 1u) put8(m, dec8(v));
            else                            invalid();
        }
        break;
    case 0xFF:
        m = fetch8();
        switch ((m >> 3) & 7u) {
        case 0: v = getv(m); if (!c.faulted) putv(m, incv(v)); break;
        case 1: v = getv(m); if (!c.faulted) putv(m, decv(v)); break;
        case 2:
            v = getv(m);
            if (!c.faulted) { pushv(c.eip); if (!c.faulted) c.eip = v; if (!pmode_on()) c.cycles += 5; }
            break;
        case 3: case 5:
            if (m >= 0xC0u) { invalid(); break; }
            ea(m);
            v = op32 ? rd32(ea_base, ea_off32) : rd16(ea_base, ea_off32);
            r = rd16(ea_base, ea_off32 + (op32 ? 4u : 2u));
            if (c.faulted) break;
            if (((m >> 3) & 7u) == 3u) {
                pushv(c.sr[CS]);
                pushv(c.eip);
                if (!pmode_on()) c.cycles += 10;
            }
            if (!c.faulted) {
                set_seg(CS, r);
                if (!c.faulted) c.eip = v;
            }
            break;
        case 4:
            v = getv(m);
            if (!c.faulted) { c.eip = v; if (!pmode_on()) c.cycles += 4; }
            break;
        case 6:
            v = getv(m);
            if (!c.faulted) pushv(v);
            break;
        default:
            invalid();
            break;
        }
        break;
    default:
        invalid();
        break;
    }
}

#pragma GCC pop_options

/* ---- Dual 8259A PIC (Master 0x20/0x21 + Slave 0xA0/0xA1) ---- */
static struct {
    u8 irr, imr, isr, base, init, need4, read_isr;
} pic[2];

static void pic_raise(int irq)
{
    int idx = irq >> 3, bit = irq & 7;
    pic[idx].irr |= (u8)(1u << bit);
    if (idx == 1 && !(pic[1].imr & (1u << bit)))
        pic[0].irr |= 0x04u;            /* cascade on master IRQ 2 */
    if (!c.check)
        c.check = 1;
}

static void irq_check(void)
{
    c.check = 0;
    if (!(c.sys & F_IF))
        return;
    u8 pending = pic[0].irr & ~pic[0].imr;
    for (int n = 0; n < 8 && pending; n++) {
        if (pic[0].isr & (1u << n))
            return;
        if (pending & (1u << n)) {
            if (n == 2) {
                u8 sp = pic[1].irr & ~pic[1].imr;
                for (int s = 0; s < 8; s++) {
                    if (pic[1].isr & (1u << s)) return;
                    if (sp & (1u << s)) {
                        pic[1].irr &= (u8)~(1u << s);
                        pic[1].isr |= (u8)(1u << s);
                        if (!(pic[1].irr & ~pic[1].imr))
                            pic[0].irr &= (u8)~0x04u;
                        pic[0].isr |= 0x04u;
                        c.halted = 0;
                        interrupt(pic[1].base + (u32)s);
                        return;
                    }
                }
                pic[0].irr &= (u8)~0x04u;
                continue;
            }
            pic[0].irr &= (u8)~(1u << n);
            pic[0].isr |= (u8)(1u << n);
            c.halted = 0;
            interrupt(pic[0].base + (u32)n);
            return;
        }
    }
}

static void pic_out(int idx, u32 port, u32 v)
{
    if (!(port & 1u)) {
        if (v & 0x10u) {
            pic[idx].init = 1;
            pic[idx].need4 = v & 1u;
            pic[idx].imr = 0;
            pic[idx].isr = 0;
            pic[idx].irr = 0;
        } else if (v & 0x08u) {
            if (v & 2u) pic[idx].read_isr = v & 1u;
        } else if ((v & 0xE0u) == 0x20u) {
            for (int n = 0; n < 8; n++)
                if (pic[idx].isr & (1u << n)) {
                    pic[idx].isr &= (u8)~(1u << n);
                    break;
                }
        } else if ((v & 0xE0u) == 0x60u) {
            pic[idx].isr &= (u8)~(1u << (v & 7u));
        }
    } else if (pic[idx].init == 1) {
        pic[idx].base = (u8)(v & 0xF8u);
        pic[idx].init = 2;
    } else if (pic[idx].init == 2) {
        pic[idx].init = pic[idx].need4 ? 3 : 0;
    } else if (pic[idx].init == 3) {
        pic[idx].init = 0;
    } else {
        pic[idx].imr = (u8)v;
    }
    if (!c.check)
        c.check = 1;
}

/* ---- 8237A ISA DMA Controller (Ch 0..3, Sound Blaster uses Ch 1) ---- */
static struct {
    u16 addr[4], base_addr[4];
    u16 cnt[4],  base_cnt[4];
    u8  page[4], mode[4];
    u8  mask, ff;
} dma;

static void dma_out(u32 port, u32 v)
{
    if (port < 8u) {
        u32 ch = port >> 1;
        if (port & 1u) {
            if (!dma.ff) dma.base_cnt[ch] = dma.cnt[ch] = (u16)((dma.base_cnt[ch] & 0xFF00u) | v);
            else         dma.base_cnt[ch] = dma.cnt[ch] = (u16)((dma.base_cnt[ch] & 0x00FFu) | (v << 8));
        } else {
            if (!dma.ff) dma.base_addr[ch] = dma.addr[ch] = (u16)((dma.base_addr[ch] & 0xFF00u) | v);
            else         dma.base_addr[ch] = dma.addr[ch] = (u16)((dma.base_addr[ch] & 0x00FFu) | (v << 8));
        }
        dma.ff ^= 1u;
        return;
    }
    switch (port) {
    case 0x0A:
        if (v & 4u) dma.mask |= (u8)(1u << (v & 3u));
        else        dma.mask &= (u8)~(1u << (v & 3u));
        break;
    case 0x0B: dma.mode[v & 3u] = (u8)v; break;
    case 0x0C: dma.ff = 0; break;
    case 0x0D: dma.ff = 0; dma.mask = 0x0Fu; break;
    case 0x0E: dma.mask = 0; break;
    case 0x0F: dma.mask = (u8)(v & 15u); break;
    case 0x87: dma.page[0] = (u8)v; break;
    case 0x83: dma.page[1] = (u8)v; break;
    case 0x81: dma.page[2] = (u8)v; break;
    case 0x82: dma.page[3] = (u8)v; break;
    }
}

static u8 dma_in(u32 port)
{
    if (port < 8u) {
        u32 ch = port >> 1;
        u16 val = (port & 1u) ? dma.cnt[ch] : dma.addr[ch];
        u8 res = dma.ff ? (u8)(val >> 8) : (u8)val;
        dma.ff ^= 1u;
        return res;
    }
    if (port == 0x08u) return 0x0Fu;
    if (port == 0x83u) return dma.page[1];
    return 0xFFu;
}

static u8 dma_read_byte(int ch)
{
    if (dma.mask & (1u << ch))
        return 0x80u;
    u32 phys = (((u32)dma.page[ch] << 16) | dma.addr[ch]) & (RAM_BYTES - 1u);
    u8 val = mem[phys];
    dma.addr[ch] = (u16)(dma.addr[ch] + ((dma.mode[ch] & 0x20u) ? -1 : 1));
    if (dma.cnt[ch] == 0u) {
        if (dma.mode[ch] & 0x10u) {     /* Auto-init reload */
            dma.addr[ch] = dma.base_addr[ch];
            dma.cnt[ch]  = dma.base_cnt[ch];
        } else {
            dma.mask |= (u8)(1u << ch);
        }
    } else {
        dma.cnt[ch]--;
    }
    return val;
}

/* ---- Sound Blaster 2.0 DSP (0x220..0x22F, IRQ 7, DMA 1) ---- */
static struct {
    u8  fifo[16];
    u8  r_head, r_tail, last_read;
    u8  cmd, cmd_args[4], arg_cnt, arg_need;
    u8  reset_state, speaker_on, test_reg;
    u8  dma_active, dma_auto, dma_paused, silence_active;
    u8  cur_sample;
    u8  mixer_idx, mixer[256];
    u32 rate_hz;
    u32 blk_size, blk_rem;
    u32 phase_acc;                      /* 16.16 fixed-point accumulator for DMA rate */
} sb;

static void sb_push(u8 b)
{
    u8 next = (sb.r_tail + 1u) & 15u;
    if (next != sb.r_head) {
        sb.fifo[sb.r_tail] = b;
        sb.r_tail = next;
    }
}

static u32 sample_rate, opl_fp8_cached, opl_fp8_half, sb_inc_cached, snd_frac, snd_head, snd_tail;
static s32 opl_prev_fm;
static u8  opl_half_phase, aud_slice_pend;

static void sb_sync_rate(void)
{
    sb_inc_cached = sample_rate ? ((sb.rate_hz << 12) / sample_rate) : 0u;
}

static void sb_reset(void)
{
    u32 saved_rate = sb.rate_hz ? sb.rate_hz : 11025u;
    u8 *p = (u8 *)&sb;
    for (u32 i = 0; i < sizeof(sb); i++) p[i] = 0;
    sb.cur_sample = 0x80u;
    sb.last_read = 0xAAu;
    sb.rate_hz = saved_rate;
    sb_sync_rate();
    sb.blk_size = 256u;
    sb.mixer[0x04] = 0xEEu;
    sb.mixer[0x22] = 0xEEu;
    sb.mixer[0x26] = 0xEEu;
    sb.mixer[0x80] = 0x08u;             /* IRQ 7 */
    sb.mixer[0x81] = 0x02u;             /* DMA 1 */
}

static void sb_write_dsp(u8 v)
{
    if (sb.arg_need) {
        sb.cmd_args[sb.arg_cnt++] = v;
        if (sb.arg_cnt < sb.arg_need)
            return;
        sb.arg_need = 0;
        switch (sb.cmd) {
        case 0x10:                      /* Direct 8-bit DAC */
            sb.cur_sample = sb.cmd_args[0];
            break;
        case 0x14: case 0x16: case 0x17: case 0x91: /* Single-cycle 8-bit DMA */
            sb.blk_rem = ((u32)sb.cmd_args[0] | ((u32)sb.cmd_args[1] << 8)) + 1u;
            sb.dma_active = 1;
            sb.dma_auto = 0;
            sb.dma_paused = 0;
            sb.silence_active = 0;
            break;
        case 0x40: {                    /* Set Time Constant */
            u32 d = 256u - sb.cmd_args[0];
            sb.rate_hz = 1000000u / (d ? d : 1u);
            if (sb.rate_hz < 4000u) sb.rate_hz = 4000u;
            if (sb.rate_hz > 48000u) sb.rate_hz = 48000u;
            sb_sync_rate();
            break;
        }
        case 0x41: case 0x42:           /* Set Sample Rate (hi, lo) */
            sb.rate_hz = ((u32)sb.cmd_args[0] << 8) | sb.cmd_args[1];
            if (sb.rate_hz < 4000u) sb.rate_hz = 4000u;
            if (sb.rate_hz > 48000u) sb.rate_hz = 48000u;
            sb_sync_rate();
            break;
        case 0x48:                      /* Set DMA Block Size */
            sb.blk_size = ((u32)sb.cmd_args[0] | ((u32)sb.cmd_args[1] << 8)) + 1u;
            break;
        case 0x80:                      /* Silence DAC + IRQ after N+1 samples */
            sb.blk_rem = ((u32)sb.cmd_args[0] | ((u32)sb.cmd_args[1] << 8)) + 1u;
            sb.silence_active = 1;
            sb.dma_active = 0;
            sb.dma_paused = 0;
            break;
        case 0xE0:                      /* DSP Identification (~val) */
            sb_push((u8)~sb.cmd_args[0]);
            break;
        case 0xE2:
            dma.addr[1]++;
            break;
        case 0xE4:
            sb.test_reg = sb.cmd_args[0];
            break;
        }
        return;
    }

    sb.cmd = v;
    sb.arg_cnt = 0;
    switch (v) {
    case 0x10: case 0x40: case 0xE0: case 0xE2: case 0xE4:
        sb.arg_need = 1; break;
    case 0x14: case 0x16: case 0x17: case 0x41: case 0x42: case 0x48: case 0x80: case 0x91:
        sb.arg_need = 2; break;
    case 0x1C: case 0x90:               /* Auto-Init 8-bit DMA (DOOM / Wolf3D!) */
        sb.blk_rem = sb.blk_size ? sb.blk_size : 256u;
        sb.dma_active = 1;
        sb.dma_auto = 1;
        sb.dma_paused = 0;
        sb.silence_active = 0;
        break;
    case 0xD0: sb.dma_paused = 1; break;
    case 0xD1: sb.speaker_on = 1; break;
    case 0xD3: sb.speaker_on = 0; break;
    case 0xD4: sb.dma_paused = 0; break;
    case 0xD8: sb_push(sb.speaker_on ? 0xFFu : 0x00u); break;
    case 0xDA: sb.dma_auto = 0; break;  /* Exit Auto-Init at end of current block */
    case 0xE1: sb_push(0x02u); sb_push(0x01u); break; /* DSP v2.01 */
    case 0xE8: sb_push(sb.test_reg); break;
    case 0xF0: case 0xF2: pic_raise(7); break;        /* Trigger IRQ 7 immediately */
    }
}

static s32 opl_last_cyc;

static void opl_sync(void)
{
    s32 diff = c.cycles - opl_last_cyc;
    if (diff >= 14) {
        u32 us = (u32)diff / 14u;
        opl_last_cyc += (s32)(us * 14u);
        opl2_advance_timers(&M->opl, us);
    }
}

static u8 sb_in(u32 port)
{
    if (pmode_on()) c.cycles += 21;
    switch (port & 0x0Fu) {
    case 0x00: case 0x02: case 0x08:
        opl_sync();
        return opl2_read_status(&M->opl);
    case 0x05:
        return sb.mixer[sb.mixer_idx];
    case 0x0A:
        if (sb.r_head != sb.r_tail) {
            sb.last_read = sb.fifo[sb.r_head];
            sb.r_head = (sb.r_head + 1u) & 15u;
        }
        return sb.last_read;
    case 0x0C:
        return 0x00u;                   /* Write buffer ready (bit 7 = 0) */
    case 0x0E:
        return (sb.r_head != sb.r_tail) ? 0x80u : 0x00u;
    default:
        return 0xFFu;
    }
}

static void sb_out(u32 port, u8 v)
{
    if (pmode_on()) c.cycles += 21;
    switch (port & 0x0Fu) {
    case 0x00: case 0x01: case 0x02: case 0x03: case 0x08: case 0x09:
        opl_sync();
        opl2_write(&M->opl, port & 1u, v);
        break;
    case 0x04:
        sb.mixer_idx = v;
        break;
    case 0x05:
        if (sb.mixer_idx == 0x00u) {
            sb.mixer[0x04] = sb.mixer[0x22] = sb.mixer[0x26] = 0xEEu;
        } else {
            sb.mixer[sb.mixer_idx] = v;
        }
        break;
    case 0x06:
        if ((v & 1u) && !sb.reset_state) {
            sb.reset_state = 1;
            sb.dma_active = sb.dma_auto = sb.silence_active = 0;
            sb.arg_need = sb.arg_cnt = 0;
        } else if (!(v & 1u) && sb.reset_state) {
            sb.reset_state = 0;
            sb.r_head = sb.r_tail = 0;
            sb_push(0xAAu);
        }
        break;
    case 0x0C:
        sb_write_dsp(v);
        break;
    }
}

/* ---- 8253 PIT ---- */
static u32 pit_n[3], pit_new[3];
static u32 pit_mode[3], pit_access[3], pit_low[3], pit_latch[3];
static u8 pit_half[3], pit_latched[3], pit_read_hi[3], pit_running[3], pit_gate2;
static s32 pit_start[3];
static s32 pit0_next;
static int pit0_on;

static int periodic(int ch) { return pit_mode[ch] == 2 || pit_mode[ch] == 3; }

static void pit_catch_up(int ch)
{
    if (!periodic(ch) || !pit_running[ch])
        return;
    s32 span = (s32)(pit_n[ch] * PIT_CYCLES);
    if (c.cycles - pit_start[ch] < span)
        return;
    pit_start[ch] += span;
    if (pit_new[ch]) {
        pit_n[ch] = pit_new[ch];
        pit_new[ch] = 0;
        span = (s32)(pit_n[ch] * PIT_CYCLES);
    }
    if (c.cycles - pit_start[ch] >= span)
        pit_start[ch] += (c.cycles - pit_start[ch]) / span * span;
}

static u32 pit_ticks(int ch)
{
    s32 t = c.cycles - pit_start[ch];
    return t < 0 ? 0 : (u32)t / PIT_CYCLES;
}

static u32 pit_count(int ch)
{
    u32 n = pit_n[ch];
    if (!pit_running[ch] || (ch == 2 && !pit_gate2))
        return n & 0xFFFFu;
    pit_catch_up(ch);
    n = pit_n[ch];
    u32 t = pit_ticks(ch);
    switch (pit_mode[ch]) {
    case 2: return (n - t % n) & 0xFFFFu;
    case 3: return (n - (t * 2u) % n) & 0xFFFEu;
    default: return (n - t) & 0xFFFFu;
    }
}

static int pit_out2(void)
{
    if (!pit_gate2 || !pit_running[2])
        return 1;
    pit_catch_up(2);
    u32 n = pit_n[2], t = pit_ticks(2);
    if (pit_mode[2] == 3) return t % n < n / 2u;
    if (pit_mode[2] == 2) return t % n != n - 1u;
    return t >= n;
}

static void pit_start_now(int ch)
{
    pit_start[ch] = c.cycles;
    pit_running[ch] = 1;
    if (ch == 0) {
        pit0_next = c.cycles + (s32)(pit_n[0] * PIT_CYCLES);
        pit0_on = 1;
        run_end = c.cycles;
    }
}

static void pit_count_written(int ch, u32 v)
{
    u32 n = v ? v : 0x10000u;
    if (periodic(ch) && pit_running[ch]) {
        pit_catch_up(ch);
        pit_new[ch] = n;
        return;
    }
    pit_n[ch] = n;
    pit_new[ch] = 0;
    pit_start_now(ch);
}

static void pit_out(u32 port, u32 v)
{
    if (port == 0x43u) {
        int ch = (int)(v >> 6);
        if (ch == 3) return;
        if (!(v & 0x30u)) {
            pit_latch[ch] = pit_count(ch);
            pit_latched[ch] = 2;
            return;
        }
        u32 mode = (v >> 1) & 7u;
        if (mode > 5u) mode -= 4u;
        if (!(periodic(ch) && (mode == 2u || mode == 3u))) {
            pit_running[ch] = 0;
            if (ch == 0) pit0_on = 0;
        }
        pit_access[ch] = (v >> 4) & 3u;
        pit_mode[ch] = mode;
        pit_half[ch] = 0;
        pit_read_hi[ch] = 0;
        return;
    }
    int ch = (int)(port & 3u);
    switch (pit_access[ch]) {
    case 1: pit_count_written(ch, v); break;
    case 2: pit_count_written(ch, v << 8); break;
    default:
        if (!pit_half[ch]) { pit_low[ch] = v; pit_half[ch] = 1; }
        else { pit_half[ch] = 0; pit_count_written(ch, pit_low[ch] | (v << 8)); }
        break;
    }
}

static u8 pit_in(u32 port)
{
    int ch = (int)(port & 3u);
    u32 v;
    if (ch == 3) return 0xFFu;
    if (pit_latched[ch]) {
        v = pit_latch[ch];
        if (pit_access[ch] == 3u) {
            pit_latched[ch]--;
            return (u8)(pit_latched[ch] ? v : v >> 8);
        }
        pit_latched[ch] = 0;
    } else {
        v = pit_count(ch);
        if (pit_access[ch] == 3u) {
            pit_read_hi[ch] ^= 1u;
            return (u8)(pit_read_hi[ch] ? v : v >> 8);
        }
    }
    return (u8)(pit_access[ch] == 2u ? v >> 8 : v);
}

/* ---- 8042 Keyboard Controller + CMOS + A20 ---- */
static u8 kbd_queue[64];
static int kq_head, kq_tail;
static u8 kbc_data, kbc_full, kbc_command, kbd_command, port61, port92;
static u8 cmos_index, cmos_ram[128];

static void kbd_put(u32 b)
{
    int next = (kq_tail + 1) & 63;
    if (next != kq_head) {
        kbd_queue[kq_tail] = (u8)b;
        kq_tail = next;
    }
}

static void kbd_deliver(void)
{
    if (kbc_full || kq_head == kq_tail)
        return;
    kbc_data = kbd_queue[kq_head];
    kq_head = (kq_head + 1) & 63;
    kbc_full = 1;
    pic_raise(1);
}

static void kbc_out(u32 port, u32 v)
{
    if (port == 0x64u) {
        kbc_command = (u8)v;
        if (v == 0x20u) {
            kbc_data = 0x45u;
            kbc_full = 1;
        } else if (v == 0xAAu) {
            kbc_data = 0x55u;
            kbc_full = 1;
        } else if (v == 0xD0u) {
            kbc_data = (a20_mask != 0xFFFFFu) ? 0xDFu : 0xDDu;
            kbc_full = 1;
        } else if ((v & 0xF0u) == 0xF0u && !(v & 1u)) {
            /* 286/386 CPU reset pulse via 8042 (CMOS 0x0F == 0x05 or 0x0A -> warm jump to [0040:0067]!) */
            u8 shut = cmos_ram[0x0F];
            if (shut == 0x05u || shut == 0x0Au) {
                c.cr0 &= ~0x80000001u;
                c.sys &= ~F_VM;
                tlb_flush();
                c.idt_base = 0;
                c.idt_limit = 0x3FFu;
                for (int s = 0; s < 6; s++) { c.d32[s] = 0; c.limit[s] = 0xFFFFu; }
                c.eip = get16(0x467u);
                set_seg_real(CS, get16(0x469u));
                if (shut == 0x05u) {
                    pic[0].irr = pic[0].isr = 0;
                    pic[1].irr = pic[1].isr = 0;
                }
            }
            kbc_command = 0;
            return;
        }
        if (v != 0x60u && v != 0xD1u)
            kbc_command = 0;
        return;
    }
    if (kbc_command == 0xD1u) {
        a20_mask = (v & 2u) ? (RAM_BYTES - 1u) : 0xFFFFFu;
        kbc_command = 0;
        return;
    }
    if (kbc_command) {
        kbc_command = 0;
        return;
    }
    if (kbd_command) {
        kbd_command = 0;
        kbd_put(0xFAu);
        return;
    }
    kbd_put(0xFAu);
    if (v == 0xEDu || v == 0xF3u)
        kbd_command = (u8)v;
    else if (v == 0xFFu)
        kbd_put(0xAAu);
    else if (v == 0xF2u)
        kbd_put(0xABu), kbd_put(0x41u);
}

static u32 bios_ticks(void);

static u8 bcd(u32 v) { return (u8)(((v / 10u) << 4) | (v % 10u)); }

static u8 cmos_in(void)
{
    u32 s = (u32)((bios_ticks() * 10u) / 182u);
    u32 idx = cmos_index & 0x7Fu;
    switch (idx) {
    case 0x00: return bcd(s % 60u);
    case 0x02: return bcd((s / 60u) % 60u);
    case 0x04: return bcd((s / 3600u) % 24u);
    case 0x06: return 3;
    case 0x07: return 0x01;
    case 0x08: return 0x06;
    case 0x09: return 0x93;
    case 0x0A: return 0x26;
    case 0x0B: return 0x02;
    case 0x0D: return 0x80;
    case 0x0F: return cmos_ram[0x0F];
    case 0x10: return 0x40;
    case 0x14: return 0x41;
    case 0x15: return 0x80;             /* 640 KB base */
    case 0x16: return 0x02;
    case 0x17: case 0x30: return 0x00;  /* 7168 KB (0x1C00) extended memory */
    case 0x18: case 0x31: return 0x1C;
    case 0x32: return 0x19;
    default: return cmos_ram[idx];
    }
}

/* ---- VGA ---- */
enum { T_TEXT, T_CGA4, T_CGA2, T_PLANAR, T_VGA256 };
static u8 latch[4];
static u8 seq[8], gc[16], crtc[32], attr[32], seq_i, gc_i, crtc_i, attr_i, attr_flip, misc_out;
static u8 dac[256][3], dac_w, dac_r, dac_c, dac_rc, pel_mask = 0xFF, cga_mode, cga_colour;
static u8 video_mode = 3, kind;
static u16 pal15[256];
static int dirty = 1, pal_dirty = 1;

static void planar_on(void);

#pragma GCC push_options
#pragma GCC optimize("O2")

static void vga_sync_fast(void)
{
    int ok = (vga_n == 0x10000u && (gc[5] & 3u) == 0u && !gc[1] && !gc[3] && gc[8] == 0xFFu);
    vga_fast_lut[1] = ok ? vram[0] : 0;
    vga_fast_lut[2] = ok ? vram[1] : 0;
    vga_fast_lut[4] = ok ? vram[2] : 0;
    vga_fast_lut[8] = ok ? vram[3] : 0;
    vga_single_ptr = vga_fast_lut[seq[2] & 15u];
}

static void vga_write(u32 a, u8 v)
{
    u32 o = (a - 0xA0000u) & 0xFFFFu, mode = gc[5] & 3u, mask = seq[2] & 15u, bits = gc[8];
    u32 rot = gc[3] & 7u, fn = (gc[3] >> 3) & 3u;
    vdirty[o >> 8] = 1;
    if (mode == 0u && !gc[1] && !gc[3] && bits == 0xFFu) {
        if (mask & 1u) vram[0][o] = v;
        if (mask & 2u) vram[1][o] = v;
        if (mask & 4u) vram[2][o] = v;
        if (mask & 8u) vram[3][o] = v;
        return;
    }
    if (mode == 1u) {
        for (int p = 0; p < 4; p++)
            if (mask & (1u << p)) vram[p][o] = latch[p];
        return;
    }
    if (rot && mode != 2u)
        v = (u8)((v >> rot) | (v << (8u - rot)));
    if (mode == 3u) {
        bits &= v;
        for (int p = 0; p < 4; p++)
            if (mask & (1u << p)) {
                u32 s = ((gc[0] >> p) & 1u) ? 0xFFu : 0u;
                vram[p][o] = (u8)((s & bits) | (latch[p] & ~bits));
            }
        return;
    }
    for (int p = 0; p < 4; p++) {
        if (!(mask & (1u << p))) continue;
        u32 d;
        if (mode == 2u)                d = ((v >> p) & 1u) ? 0xFFu : 0u;
        else if (gc[1] & (1u << p))    d = ((gc[0] >> p) & 1u) ? 0xFFu : 0u;
        else                           d = v;
        switch (fn) {
        case 1: d &= latch[p]; break;
        case 2: d |= latch[p]; break;
        case 3: d ^= latch[p]; break;
        }
        vram[p][o] = (u8)((d & bits) | (latch[p] & ~bits));
    }
}

static u8 vga_read(u32 a)
{
    u32 o = (a - 0xA0000u) & 0xFFFFu;
    for (int p = 0; p < 4; p++)
        latch[p] = vram[p][o];
    if (gc[5] & 8u) {
        u32 r = 0xFFu;
        for (int p = 0; p < 4; p++)
            if (gc[7] & (1u << p))
                r &= ~(latch[p] ^ (((gc[2] >> p) & 1u) ? 0xFFu : 0u));
        return (u8)r;
    }
    return latch[gc[4] & 3u];
}

static void hi_write(u32 a, u32 v)
{
    if (a - vga_lo < vga_n) {
        vga_write(a, (u8)v);
        return;
    }
    if (a < 0xC0000u) {
        mem[a] = (u8)v;
        dirty = 1;
    }
}

static void chain4(int on)
{
    if (kind != T_VGA256)
        return;
    if (!on && !vga_n) {
        for (u32 i = 0; i < 0x10000u; i++)
            vram[i & 3u][i >> 2] = mem[0xA0000u + i];
        planar_on();
    } else if (on && vga_n) {
        for (u32 i = 0; i < 0x10000u; i++)
            mem[0xA0000u + i] = vram[i & 3u][i >> 2];
        vga_n = 0;
        vga_sync_fast();
    }
    dirty = 1;
}

static void planar_on(void)
{
    vga_lo = 0xA0000u;
    vga_n = 0x10000u;
    vga_sync_fast();
}

static u8 status1(void)
{
    s32 t = c.cycles;
    if (t < 0) t = 0;
    t %= FRAME_CYCLES;
    u32 x = (u32)t * LINES, line = x / FRAME_CYCLES, in = x % FRAME_CYCLES;
    u8 v = 0;
    if (line >= SHOWN || in >= FRAME_CYCLES * 4 / 5)
        v |= 1;
    if (line >= RETRACE_FROM && line < RETRACE_TO)
        v |= 8;
    attr_flip = 0;
    static u32 last_at, last_writes;
    static u8 last_v;
    u32 at = ((u32)c.sr[CS] << 16) ^ c.op_eip;
    if (at == last_at && v == last_v && writes == last_writes + 1u) {
        u32 next;
        if (line < SHOWN)
            next = in < FRAME_CYCLES * 4 / 5 ? line * FRAME_CYCLES + FRAME_CYCLES * 4 / 5 : (line + 1u) * FRAME_CYCLES;
        else
            next = (line < RETRACE_FROM ? RETRACE_FROM : line < RETRACE_TO ? RETRACE_TO : LINES) * FRAME_CYCLES;
        s32 skip = (s32)((next + LINES - 1u) / LINES) - t;
        if (skip > run_end - c.cycles)
            skip = run_end - c.cycles;
        if (skip > 0) {
            c.cycles += skip;
            idle_cycles += (u32)skip;
        }
    }
    last_at = at; last_v = v; last_writes = writes;
    return v;
}

static void vga_out(u32 port, u32 v)
{
    switch (port) {
    case 0x3C0:
        if (!attr_flip) {
            attr_i = (u8)v;
        } else if ((attr_i & 0x1Fu) < 0x15u) {
            attr[attr_i & 0x1Fu] = (u8)v;
            pal_dirty = 1;
        }
        attr_flip ^= 1u;
        dirty = 1;
        break;
    case 0x3C2: misc_out = (u8)v; break;
    case 0x3C4: seq_i = (u8)(v & 7u); break;
    case 0x3C5: {
        u8 prev = seq[seq_i];
        if (seq_i == 4u && ((prev ^ v) & 8u))
            chain4((v & 8u) != 0);
        seq[seq_i] = (u8)v;
        if (seq_i == 2u)
            vga_sync_fast();
        else if (prev != (u8)v)
            dirty = 1;
        break;
    }
    case 0x3C6:
        if (pel_mask != (u8)v) { pel_mask = (u8)v; dirty = 1; }
        break;
    case 0x3C7: dac_r = (u8)v; dac_rc = 0; break;
    case 0x3C8: dac_w = (u8)v; dac_c = 0; break;
    case 0x3C9:
        dac[dac_w][dac_c] = (u8)(v & 0x3Fu);
        if (++dac_c == 3u) { dac_c = 0; dac_w++; }
        pal_dirty = 1;
        dirty = 1;
        break;
    case 0x3CE: gc_i = (u8)(v & 15u); break;
    case 0x3CF: gc[gc_i] = (u8)v; vga_sync_fast(); break;
    case 0x3B4: case 0x3D4: crtc_i = (u8)(v & 31u); break;
    case 0x3B5: case 0x3D5:
        if (crtc[crtc_i] != (u8)v) { crtc[crtc_i] = (u8)v; dirty = 1; }
        break;
    case 0x3D8: cga_mode = (u8)v; dirty = 1; break;
    case 0x3D9:
        cga_colour = (u8)v;
        if (kind == T_CGA4) {
            u32 bright = (v & 0x10u) ? 0x10u : 0u, base = (v & 0x20u) ? 3u : 2u;
            attr[0] = (u8)((v & 7u) | ((v & 8u) ? 0x10u : 0u));
            for (u32 i = 1; i < 4; i++)
                attr[i] = (u8)((base + 2u * (i - 1u)) | bright);
            pal_dirty = 1;
        }
        dirty = 1;
        break;
    }
}

static u8 vga_in(u32 port)
{
    switch (port) {
    case 0x3C0: return attr_i;
    case 0x3C1: return attr[attr_i & 0x1Fu];
    case 0x3C2: return 0x10;
    case 0x3C4: return seq_i;
    case 0x3C5: return seq[seq_i];
    case 0x3C6: return pel_mask;
    case 0x3C7: return 0;
    case 0x3C8: return dac_w;
    case 0x3C9: {
        u8 v = dac[dac_r][dac_rc];
        if (++dac_rc == 3u) { dac_rc = 0; dac_r++; }
        return v;
    }
    case 0x3CC: return misc_out;
    case 0x3CE: return gc_i;
    case 0x3CF: return gc[gc_i];
    case 0x3B4: case 0x3D4: return crtc_i;
    case 0x3B5: case 0x3D5: return crtc[crtc_i];
    case 0x3BA: case 0x3DA: return status1();
    default: return 0xFF;
    }
}

/* ---- Ports ---- */
static u8 in8(u32 port)
{
    port &= 0xFFFFu;
    if (!pmode_on()) c.cycles += 2;
    writes++;
    if (port < 0x10u || (port >= 0x80u && port <= 0x8Fu))
        return dma_in(port);
    if ((port & 0xFFF0u) == 0x220u)
        return sb_in(port);
    if ((port & 0xFFFEu) == 0x388u) {
        if (pmode_on()) c.cycles += 21;
        opl_sync();
        return (port & 1u) ? 0xFFu : opl2_read_status(&M->opl);
    }
    switch (port) {
    case 0x20: return pic[0].read_isr ? pic[0].isr : pic[0].irr;
    case 0x21: return pic[0].imr;
    case 0xA0: return pic[1].read_isr ? pic[1].isr : pic[1].irr;
    case 0xA1: return pic[1].imr;
    case 0x40: case 0x41: case 0x42: case 0x43: return pit_in(port);
    case 0x60: kbc_full = 0; return kbc_data;
    case 0x61: return (u8)((port61 & 0x0Fu) | (((pit_ticks(0) / 18u) & 1u) ? 0x10u : 0u) | (pit_out2() ? 0x20u : 0u));
    case 0x64: return (u8)(0x14u | kbc_full);
    case 0x71: return cmos_in();
    case 0x92: return (u8)((port92 & ~2u) | ((a20_mask != 0xFFFFFu) ? 2u : 0u));
    case 0x201: return 0xFFu;
    }
    if (port >= 0x3B0u && port < 0x3E0u)
        return vga_in(port);
    return 0xFFu;
}

static void out8(u32 port, u32 v)
{
    port &= 0xFFFFu;
    v &= 0xFFu;
    if (!pmode_on()) c.cycles += 2;
    writes++;
    if (port < 0x10u || (port >= 0x81u && port <= 0x8Fu)) {
        dma_out(port, v);
        return;
    }
    if ((port & 0xFFF0u) == 0x220u) {
        sb_out(port, (u8)v);
        return;
    }
    if ((port & 0xFFFEu) == 0x388u) {
        if (pmode_on()) c.cycles += 21;
        opl_sync();
        opl2_write(&M->opl, port & 1u, (u8)v);
        return;
    }
    switch (port) {
    case 0x20: case 0x21: pic_out(0, port, v); return;
    case 0xA0: case 0xA1: pic_out(1, port, v); return;
    case 0x40: case 0x41: case 0x42: case 0x43: pit_out(port, v); return;
    case 0x60: case 0x64: kbc_out(port, v); return;
    case 0x61:
        if ((v & 1u) && !(port61 & 1u) && pit_running[2]) {
            pit_start[2] = c.cycles;
            if (pit_new[2]) { pit_n[2] = pit_new[2]; pit_new[2] = 0; }
        }
        pit_gate2 = v & 1u;
        port61 = (u8)v;
        return;
    case 0x70: cmos_index = (u8)v; return;
    case 0x71: cmos_ram[cmos_index & 0x7Fu] = (u8)v; return;
    case 0x92:
        port92 = (u8)v;
        a20_mask = (v & 2u) ? (RAM_BYTES - 1u) : 0xFFFFFu;
        return;
    case 0x80: case 0x201: case 0x3F2: return;
    }
    if (port >= 0x3B0u && port < 0x3E0u) {
        vga_out(port, v);
        return;
    }
}

/* ---- 48 kHz Audio Mixer (OPL2 + Sound Blaster 8-bit DMA + PC Speaker) ---- */
static u32 spk_phase;

static void step_sb_dma_slice(u32 slice_us)
{
    opl_sync();

    if (sb.dma_paused || (!sb.dma_active && !sb.silence_active))
        return;

    /* Advance SB DMA / Silence counter over `slice_us` microseconds so IRQ 7 fires right on time! */
    u32 add = (sb.rate_hz * slice_us * 65536u) / 1000000u; /* slice_us ~ 892, rate_hz <= 48000 => fits u32? Wait! */
    /* Avoid 32-bit overflow: 48000 * 892 = 42,816,000; * 65536 overflows u32!
       Compute cleanly in 32-bit: ((rate_hz * slice_us) / 125) * 8 -> exact in 16.6 fixed-point! */
    (void)add;
    u32 fp12 = ((sb.rate_hz * slice_us) << 4) / 3906u;     /* * 4096 / 1000000 = * 16 / 3906.25 */
    sb.phase_acc += fp12;
    u32 n_bytes = sb.phase_acc >> 12;
    sb.phase_acc &= 0xFFFu;

    while (n_bytes > 0u) {
        if (sb.silence_active) {
            u32 step = n_bytes < sb.blk_rem ? n_bytes : sb.blk_rem;
            sb.blk_rem -= step;
            n_bytes -= step;
            if (sb.blk_rem == 0u) {
                sb.silence_active = 0;
                pic_raise(7);
                break;
            }
        } else if (sb.dma_active) {
            sb.cur_sample = dma_read_byte(1);
            n_bytes--;
            if (--sb.blk_rem == 0u) {
                pic_raise(7);
                if (sb.dma_auto) {
                    sb.blk_rem = sb.blk_size ? sb.blk_size : 256u;
                } else {
                    sb.dma_active = 0;
                    break;
                }
            }
        } else {
            break;
        }
    }
}

/* Sample SB DMA seamlessly at output rate when audio output is active */
static __attribute__((noinline)) void sb_step_dma_slow(void)
{
    do {
        sb.phase_acc -= 0x1000u;
        sb.cur_sample = dma_read_byte(1);
        if (--sb.blk_rem == 0u) {
            pic_raise(7);
            if (sb.dma_auto) {
                sb.blk_rem = sb.blk_size ? sb.blk_size : 256u;
            } else {
                sb.dma_active = 0;
                break;
            }
        }
    } while (sb.phase_acc >= 0x1000u);
}

INLINE u8 sb_next_audio_byte(u32 sb_inc)
{
    if (!sb.dma_active || sb.dma_paused)
        return sb.cur_sample;
    sb.phase_acc += sb_inc;
    if (__builtin_expect(sb.phase_acc >= 0x1000u, 0))
        sb_step_dma_slow();
    return sb.cur_sample;
}

static void render_audio_slice(u32 n_slices)
{
    if (!sample_rate) {
        opl2_advance_timers(&M->opl, DOS_FRAME_US / SLICES);
        step_sb_dma_slice(DOS_FRAME_US / SLICES);
        return;
    }
    /* DOS_FRAME_US = 14268 us across 16 slices -> sample_rate * 14268 * n_slices / 16000000 */
    u32 num = sample_rate * (14268u * n_slices) + snd_frac;
    u32 n_samp = num / 16000000u;
    snd_frac = num % 16000000u;

    u32 sb_inc = (sb.dma_active && !sb.dma_paused) ? sb_inc_cached : 0u;
    int spk_on = ((port61 & 3u) == 3u) && pit_running[2] && pit_n[2] >= 24u;
    s16 *ring = M->snd_ring;
    u32 head = snd_head;

#ifndef PM_EXACT_CPI3
    if (__builtin_expect((c.cr0 & 1u) != 0u && sample_rate >= 32000u && !spk_on, 1)) {
        u32 fp8_h = opl_fp8_half;
        s32 prev_fm = opl_prev_fm;
        u8  ph = opl_half_phase;
        int fm_on = (M->opl.active_mask != 0u);
        if (!fm_on) {
            M->opl.lfo_cnt += opl_fp8_cached * n_samp;
            prev_fm = 0;
            for (u32 i = 0; i < n_samp; i++) {
                u8  pcm8 = sb_next_audio_byte(sb_inc);
                s32 mix = sb.speaker_on ? (((s32)pcm8 - 128) * 140) : 0;
                if (mix > 32767) mix = 32767;
                else if (mix < -32768) mix = -32768;
                ring[head & (SND_RING - 1u)] = (s16)mix;
                head++;
            }
        } else {
            for (u32 i = 0; i < n_samp; i++) {
                s32 fm;
                if (!ph) {
                    s32 cur_fm = opl2_sample(&M->opl, fp8_h);
                    fm = (prev_fm + cur_fm) >> 1;
                    prev_fm = cur_fm;
                    ph = 1u;
                } else {
                    fm = prev_fm;
                    ph = 0u;
                }
                u8  pcm8 = sb_next_audio_byte(sb_inc);
                s32 pcm = sb.speaker_on ? (((s32)pcm8 - 128) * 140) : 0;
                s32 mix = fm + pcm;
                if (mix > 32767) mix = 32767;
                else if (mix < -32768) mix = -32768;
                ring[head & (SND_RING - 1u)] = (s16)mix;
                head++;
            }
        }
        opl_prev_fm = prev_fm;
        opl_half_phase = ph;
        snd_head = head;
        if (head - snd_tail > SND_RING)
            snd_tail = head - SND_RING;
        return;
    }
#endif

    u32 opl_fp8 = opl_fp8_cached;
    if (__builtin_expect(!spk_on, 1)) {
        for (u32 i = 0; i < n_samp; i++) {
            s32 fm = opl2_sample(&M->opl, opl_fp8);
            u8  pcm8 = sb_next_audio_byte(sb_inc);
            s32 pcm = sb.speaker_on ? (((s32)pcm8 - 128) * 140) : 0;
            s32 mix = fm + pcm;
            if (mix > 32767) mix = 32767;
            else if (mix < -32768) mix = -32768;
            ring[head & (SND_RING - 1u)] = (s16)mix;
            head++;
        }
    } else {
        u32 spk_inc = ((1193182u / pit_n[2]) << 16) / sample_rate;
        for (u32 i = 0; i < n_samp; i++) {
            s32 fm = opl2_sample(&M->opl, opl_fp8);
            u8  pcm8 = sb_next_audio_byte(sb_inc);
            s32 pcm = sb.speaker_on ? (((s32)pcm8 - 128) * 140) : 0;
            spk_phase += spk_inc;
            s32 spk = (spk_phase & 0x8000u) ? 2200 : -2200;
            s32 mix = fm + pcm + spk;
            if (mix > 32767) mix = 32767;
            else if (mix < -32768) mix = -32768;
            ring[head & (SND_RING - 1u)] = (s16)mix;
            head++;
        }
    }
    snd_head = head;
    if (head - snd_tail > SND_RING)
        snd_tail = head - SND_RING;
}

void dos_audio_rate(u32 hz)
{
    sample_rate = hz;
    opl_fp8_cached = hz ? ((49716u << 8) / hz) : 0u;
    opl_fp8_half   = hz ? ((49716u << 9) / hz) : 0u;
    opl_prev_fm = 0;
    opl_half_phase = 0;
    aud_slice_pend = 0;
    sb_sync_rate();
    snd_frac = 0;
    snd_head = snd_tail = 0;
}

int dos_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && snd_tail != snd_head) {
        out[n++] = M->snd_ring[snd_tail & (SND_RING - 1u)];
        snd_tail++;
    }
    return n;
}

/* ---- Picture Rendering ---- */
static u16 *pic_buf;
static int pic_changed;
static u32 frames;
static u8 squeeze[256];
static u32 spread[256];
static u8 font[256][8];

static u16 colour15(const u8 *rgb)
{
    return (u16)((rgb[0] >> 1) | ((rgb[1] >> 1) << 5) | ((rgb[2] >> 1) << 10));
}

static void palette(void)
{
    for (int i = 0; i < 256; i++)
        pal15[i] = colour15(dac[i]);
    pal_dirty = 0;
}

static u8 attr_dac(u32 i)
{
    u32 a = attr[i & 15u], cs = attr[0x14];
    if (attr[0x10] & 0x80u)
        return (u8)(((a & 0x0Fu) | ((cs & 3u) << 4) | ((cs & 0x0Cu) << 4)) & pel_mask);
    return (u8)(((a & 0x3Fu) | ((cs & 0x0Cu) << 4)) & pel_mask);
}

static void draw_text(void)
{
    u32 cols = mem[0x44A] ? mem[0x44A] : 80u, start = (((u32)crtc[0x0C] << 8) | crtc[0x0D]) * 2u;
    u16 ink[16];
    for (u32 i = 0; i < 16; i++)
        ink[i] = pal15[attr_dac(i)];
    int blink = (attr[0x10] & 8u) != 0, cursor_on = (frames & 16u) != 0 && !(crtc[0x0A] & 0x20u);
    u32 cursor = (((u32)crtc[0x0E] << 8) | crtc[0x0F]) * 2u;
    for (u32 row = 0; row < 25; row++)
        for (u32 col = 0; col < cols && col < 80u; col++) {
            u32 at = (start + (row * cols + col) * 2u) & 0x7FFFu;
            u8 ch = mem[0xB8000u + at], a = mem[0xB8001u + at];
            u32 fg = a & 15u, bg = a >> 4;
            if (blink) {
                bg &= 7u;
                if ((a & 0x80u) && (frames & 32u)) fg = bg;
            }
            for (u32 y = 0; y < 8; y++) {
                u32 bits = font[ch][y];
                if (cursor_on && at == cursor && y >= 6u) bits = 0xFFu;
                if (cols <= 40u) {
                    u16 *o = pic_buf + (row * 8u + y) * DOS_W + col * 8u;
                    for (int x = 0; x < 8; x++)
                        o[x] = ink[((bits << x) & 0x80u) ? fg : bg];
                } else {
                    u16 *o = pic_buf + (row * 8u + y) * DOS_W + col * 4u;
                    bits = squeeze[bits];
                    for (int x = 0; x < 4; x++)
                        o[x] = ink[((bits << x) & 8u) ? fg : bg];
                }
            }
        }
}

static void draw_cga(void)
{
    u16 ink[4];
    for (u32 i = 0; i < 4; i++) ink[i] = pal15[attr_dac(i)];
    for (u32 y = 0; y < DOS_H; y++) {
        const u8 *line = mem + 0xB8000u + (y & 1u) * 0x2000u + (y >> 1) * 80u;
        u16 *o = pic_buf + y * DOS_W;
        for (u32 x = 0; x < 80; x++, o += 4) {
            u32 b = line[x];
            if (kind == T_CGA2) {
                b = (b | (b << 1)) & 0xAAu;
                o[0] = ink[(b >> 7) & 1u]; o[1] = ink[(b >> 5) & 1u];
                o[2] = ink[(b >> 3) & 1u]; o[3] = ink[(b >> 1) & 1u];
                continue;
            }
            o[0] = ink[b >> 6]; o[1] = ink[(b >> 4) & 3u];
            o[2] = ink[(b >> 2) & 3u]; o[3] = ink[b & 3u];
        }
    }
}

static int line_changed(u32 at, u32 bytes, int all)
{
    if (all) return 1;
    for (u32 b = at >> 8; b <= (at + bytes - 1u) >> 8; b++)
        if (vdirty[b & 0xFFu]) return 1;
    return 0;
}

static void draw_planar(int all)
{
    u16 ink[16];
    for (u32 i = 0; i < 16; i++)
        ink[i] = pal15[attr_dac(i & attr[0x12])];
    u32 start = ((u32)crtc[0x0C] << 8) | crtc[0x0D], width = crtc[0x13] * 2u, pan = attr[0x13] & 7u;
    u32 wide = video_mode == 0x0E || video_mode == 0x10 || video_mode == 0x12;
    if (!width) width = 40u;
    for (u32 y = 0; y < DOS_H; y++) {
        u32 at = start + y * width, x = 0;
        u16 *o = pic_buf + y * DOS_W;
        u32 skip = pan;
        if (!line_changed(at & 0xFFFFu, wide ? 81u : 41u, all))
            continue;
        pic_changed = 1;
        if (!pan && !wide && (at & 0xFFFFu) + 40u <= 0x10000u) {
            const u8 *p0 = vram[0] + (at & 0xFFFFu), *p1 = vram[1] + (at & 0xFFFFu);
            const u8 *p2 = vram[2] + (at & 0xFFFFu), *p3 = vram[3] + (at & 0xFFFFu);
            for (u32 b = 0; b < 40u; b++, o += 8) {
                u32 n = spread[p0[b]] | (spread[p1[b]] << 1) | (spread[p2[b]] << 2) | (spread[p3[b]] << 3);
                o[0] = ink[n >> 28]; o[1] = ink[(n >> 24) & 15u]; o[2] = ink[(n >> 20) & 15u]; o[3] = ink[(n >> 16) & 15u];
                o[4] = ink[(n >> 12) & 15u]; o[5] = ink[(n >> 8) & 15u]; o[6] = ink[(n >> 4) & 15u]; o[7] = ink[n & 15u];
            }
            continue;
        }
        for (u32 b = 0; x < DOS_W; b++) {
            u32 a = (at + b) & 0xFFFFu;
            u32 n = spread[vram[0][a]] | (spread[vram[1][a]] << 1) | (spread[vram[2][a]] << 2) | (spread[vram[3][a]] << 3);
            for (int i = 0; i < 8 && x < DOS_W; i += 1 + (int)wide) {
                if (skip) { skip--; continue; }
                o[x++] = ink[(n >> (28 - 4 * i)) & 15u];
            }
        }
    }
}

static __attribute__((noinline)) const u16 *build_pel_ink(void)
{
    for (u32 i = 0; i < 256; i++)
        M->pel_ink[i] = pal15[i & pel_mask];
    return M->pel_ink;
}

static void draw_256(int all)
{
    const u16 *ink = __builtin_expect(pel_mask == 0xFFu, 1) ? pal15 : build_pel_ink();
    u32 start = ((u32)crtc[0x0C] << 8) | crtc[0x0D], width = crtc[0x13] * 8u;
    if (!width) width = 320u;
    if (!vga_n) {
        if (!all) return;
        pic_changed = 1;
        start *= 4u;
        for (u32 y = 0; y < DOS_H; y++) {
            const u8 *line = mem + 0xA0000u;
            u32 at = start + y * width;
            u16 *o = pic_buf + y * DOS_W;
            for (u32 x = 0; x < DOS_W; x++)
                o[x] = ink[line[(at + x) & 0xFFFFu]];
        }
        return;
    }
    width /= 4u;
    for (u32 y = 0; y < DOS_H; y++) {
        u32 at = start + y * width, o0 = at & 0xFFFFu;
        u16 *o = pic_buf + y * DOS_W;
        if (!line_changed(o0, 80u, all))
            continue;
        pic_changed = 1;
        if (o0 <= 0x10000u - 80u && (((__UINTPTR_TYPE__)o & 3u) == 0u)) {
            const u8 *p0 = vram[0] + o0, *p1 = vram[1] + o0;
            const u8 *p2 = vram[2] + o0, *p3 = vram[3] + o0;
            u32 *d32 = (u32 *)(void *)o;
            if ((o0 & 3u) == 0u) {
                const u32 *w0 = (const u32 *)(const void *)p0, *w1 = (const u32 *)(const void *)p1;
                const u32 *w2 = (const u32 *)(const void *)p2, *w3 = (const u32 *)(const void *)p3;
#ifdef __mips__
                int d32_cl_ok = (((__UINTPTR_TYPE__)d32 & 31u) == 0u);
#endif
                for (u32 b = 0; b < 20u; b++, d32 += 8) {
#ifdef __mips__
                    if ((b & 7u) == 0u) {
                        __builtin_prefetch(w0 + b + 8, 0, 0);
                        __builtin_prefetch(w1 + b + 8, 0, 0);
                        __builtin_prefetch(w2 + b + 8, 0, 0);
                        __builtin_prefetch(w3 + b + 8, 0, 0);
                    }
                    if (__builtin_expect(d32_cl_ok, 1))
                        __asm__ volatile("pref 30, 0(%0)" : : "r"(d32) : "memory");
#endif
                    u32 x0 = w0[b], x1 = w1[b], x2 = w2[b], x3 = w3[b];
                    d32[0] = (u32)ink[x0 & 0xFFu]         | ((u32)ink[x1 & 0xFFu] << 16);
                    d32[1] = (u32)ink[x2 & 0xFFu]         | ((u32)ink[x3 & 0xFFu] << 16);
                    d32[2] = (u32)ink[(x0 >> 8) & 0xFFu]  | ((u32)ink[(x1 >> 8) & 0xFFu] << 16);
                    d32[3] = (u32)ink[(x2 >> 8) & 0xFFu]  | ((u32)ink[(x3 >> 8) & 0xFFu] << 16);
                    d32[4] = (u32)ink[(x0 >> 16) & 0xFFu] | ((u32)ink[(x1 >> 16) & 0xFFu] << 16);
                    d32[5] = (u32)ink[(x2 >> 16) & 0xFFu] | ((u32)ink[(x3 >> 16) & 0xFFu] << 16);
                    d32[6] = (u32)ink[x0 >> 24]           | ((u32)ink[x1 >> 24] << 16);
                    d32[7] = (u32)ink[x2 >> 24]           | ((u32)ink[x3 >> 24] << 16);
                }
                continue;
            }
            for (u32 b = 0; b < 80u; b++) {
                d32[b * 2u]      = (u32)ink[p0[b]] | ((u32)ink[p1[b]] << 16);
                d32[b * 2u + 1u] = (u32)ink[p2[b]] | ((u32)ink[p3[b]] << 16);
            }
            continue;
        }
        for (u32 x = 0; x < DOS_W; x++)
            o[x] = ink[vram[x & 3u][(at + (x >> 2)) & 0xFFFFu]];
    }
}

static void draw(void)
{
    static u16 *last;
    static int black;
    int all = dirty || pal_dirty || pic_buf != last || black;
    last = pic_buf;
    if (pal_dirty) palette();
    dirty = 0;
    black = !(attr_i & 0x20u) || (seq[1] & 0x20u);
    if (black) {
        pic_changed = 1;
        for (u32 i = 0; i < DOS_W * DOS_H; i++)
            pic_buf[i] = 0;
    } else {
        switch (kind) {
        case T_TEXT: pic_changed = 1; draw_text(); break;
        case T_CGA4: case T_CGA2: if (all) { pic_changed = 1; draw_cga(); } break;
        case T_PLANAR: draw_planar(all); break;
        default: draw_256(all); break;
        }
    }
    u32 *vd32 = (u32 *)(void *)vdirty;
    for (u32 i = 0; i < sizeof(vdirty) / 4u; i++)
        vd32[i] = 0;
}

#pragma GCC pop_options

/* ---- XMS 3.0 Extended Memory Manager (HIMEM.SYS HLE, 7 MB @ 0x100000..0x7FFFFF) ---- */
#define XMS_BASE   0x110000u
#define XMS_END    0x800000u            /* 7104 KB usable EMB pool (+ 64 KB HMA at 0x100000) */
#define XMS_MAX_H  32

static struct {
    u32 base, size_kb;
    u8  used, locks;
} xms_blk[XMS_MAX_H];
static u8 xms_hma_used;

static u32 xms_free_kb(u32 *largest_out)
{
    /* Walk free gaps in [XMS_BASE, XMS_END) */
    u32 cur = XMS_BASE, total = 0, best = 0;
    for (;;) {
        u32 next_b = XMS_END, next_end = XMS_END;
        for (int i = 0; i < XMS_MAX_H; i++) {
            if (xms_blk[i].used && xms_blk[i].base >= cur && xms_blk[i].base < next_b) {
                next_b = xms_blk[i].base;
                next_end = xms_blk[i].base + (xms_blk[i].size_kb << 10);
            }
        }
        u32 gap = (next_b - cur) >> 10;
        total += gap;
        if (gap > best) best = gap;
        if (next_b >= XMS_END) break;
        cur = next_end;
    }
    if (largest_out) *largest_out = best;
    return total;
}

static u32 xms_alloc_at(u32 want_kb)
{
    u32 cur = XMS_BASE, want_b = want_kb << 10;
    for (;;) {
        u32 next_b = XMS_END, next_end = XMS_END;
        for (int i = 0; i < XMS_MAX_H; i++) {
            if (xms_blk[i].used && xms_blk[i].base >= cur && xms_blk[i].base < next_b) {
                next_b = xms_blk[i].base;
                next_end = xms_blk[i].base + (xms_blk[i].size_kb << 10);
            }
        }
        if (next_b - cur >= want_b)
            return cur;
        if (next_b >= XMS_END)
            return 0;
        cur = next_end;
    }
}

static void xms_dispatch(void)
{
    u32 fn = rAH;
    switch (fn) {
    case 0x00:                          /* Get XMS Version */
        rAX = 0x0300;
        rBX = 0x0301;
        rDX = 0x0001;
        break;
    case 0x01:                          /* Request HMA */
        if (xms_hma_used) { rAX = 0; rBL = 0x91; }
        else { xms_hma_used = 1; rAX = 1; rBL = 0; }
        break;
    case 0x02:
        xms_hma_used = 0; rAX = 1; rBL = 0;
        break;
    case 0x03: case 0x05:               /* Global / Local Enable A20 */
        a20_mask = RAM_BYTES - 1u;
        rAX = 1; rBL = 0;
        break;
    case 0x04: case 0x06:               /* Global / Local Disable A20 */
        a20_mask = 0xFFFFFu;
        rAX = 1; rBL = 0;
        break;
    case 0x07:                          /* Query A20 */
        rAX = (a20_mask != 0xFFFFFu) ? 1 : 0;
        rBL = 0;
        break;
    case 0x08: {                        /* Query Free Extended Memory (16-bit) */
        u32 best = 0, tot = xms_free_kb(&best);
        rAX = (u16)(best > 65535u ? 65535u : best);
        rDX = (u16)(tot  > 65535u ? 65535u : tot);
        rBL = best ? 0 : 0xA0u;
        break;
    }
    case 0x88: {                        /* Query Free Extended Memory (XMS 3.0 32-bit) */
        u32 best = 0, tot = xms_free_kb(&best);
        rEAX = best;
        rEDX = tot;
        rECX = RAM_BYTES - 1u;
        rBL  = best ? 0 : 0xA0u;
        break;
    }
    case 0x09: case 0x89: {             /* Allocate EMB */
        u32 want_kb = (fn == 0x89u) ? rEDX : rDX;
        int h = -1;
        for (int i = 1; i < XMS_MAX_H; i++)
            if (!xms_blk[i].used) { h = i; break; }
        if (h < 0) { rAX = 0; rBL = 0xA1u; break; }
        u32 base = want_kb ? xms_alloc_at(want_kb) : XMS_BASE;
        if (want_kb && !base) { rAX = 0; rBL = 0xA0u; break; }
        xms_blk[h].used = 1;
        xms_blk[h].locks = 0;
        xms_blk[h].base = base;
        xms_blk[h].size_kb = want_kb;
        rAX = 1; rDX = (u16)h; rBL = 0;
        break;
    }
    case 0x0A:                          /* Free EMB */
        if (rDX < XMS_MAX_H && xms_blk[rDX].used) {
            xms_blk[rDX].used = 0;
            rAX = 1; rBL = 0;
        } else {
            rAX = 0; rBL = 0xA2u;
        }
        break;
    case 0x0B: {                        /* Move Extended Memory Block (DS:SI) */
        u32 p = (c.base[DS] + rSI) & 0xFFFFFu;
        u32 len = get16(p) | ((u32)get16(p + 2u) << 16);
        u16 sh  = get16(p + 4u);
        u32 so  = get16(p + 6u) | ((u32)get16(p + 8u) << 16);
        u16 dh  = get16(p + 10u);
        u32 d_o = get16(p + 12u) | ((u32)get16(p + 14u) << 16);
        u32 sa = sh ? ((sh < XMS_MAX_H && xms_blk[sh].used) ? xms_blk[sh].base + so : RAM_BYTES)
                    : (((so >> 16) << 4) + (so & 0xFFFFu));
        u32 da = dh ? ((dh < XMS_MAX_H && xms_blk[dh].used) ? xms_blk[dh].base + d_o : RAM_BYTES)
                    : (((d_o >> 16) << 4) + (d_o & 0xFFFFu));
        if (sa + len <= RAM_BYTES && da + len <= RAM_BYTES) {
            pm_check_code_write(da, len);
            if (da >= sa + len || sa >= da + len) {
                u32 i = 0;
                for (; i + 4u <= len; i += 4u)
                    ua_w32(mem + da + i, ua_r32(mem + sa + i));
                for (; i < len; i++)
                    mem[da + i] = mem[sa + i];
            } else if (da < sa) {
                for (u32 i = 0; i < len; i++) mem[da + i] = mem[sa + i];
            } else if (da > sa) {
                for (u32 i = len; i-- > 0u;) mem[da + i] = mem[sa + i];
            }
            rAX = 1; rBL = 0;
        } else {
            rAX = 0; rBL = 0xA7u;
        }
        break;
    }
    case 0x0C:                          /* Lock EMB -> DX:BX = 32-bit linear address */
        if (rDX < XMS_MAX_H && xms_blk[rDX].used) {
            xms_blk[rDX].locks++;
            rDX = (u16)(xms_blk[rDX].base >> 16);
            rBX = (u16)xms_blk[rDX].base;
            rAX = 1; rBL = 0;
        } else {
            rAX = 0; rBL = 0xA2u;
        }
        break;
    case 0x0D:                          /* Unlock EMB */
        if (rDX < XMS_MAX_H && xms_blk[rDX].used) {
            if (xms_blk[rDX].locks) xms_blk[rDX].locks--;
            rAX = 1; rBL = 0;
        } else {
            rAX = 0; rBL = 0xA2u;
        }
        break;
    case 0x0E: case 0x8E:               /* Get EMB Handle Info */
        if (rDX < XMS_MAX_H && xms_blk[rDX].used) {
            u8 free_h = 0;
            for (int i = 1; i < XMS_MAX_H; i++) if (!xms_blk[i].used) free_h++;
            rBH = xms_blk[rDX].locks;
            if (fn == 0x8Eu) { rBL = 0; rECX = free_h; rEDX = xms_blk[rDX].size_kb; }
            else             { rBL = free_h; rDX = (u16)xms_blk[rDX].size_kb; }
            rAX = 1;
        } else {
            rAX = 0; rBL = 0xA2u;
        }
        break;
    case 0x0F: case 0x8F: {             /* Reallocate EMB */
        u32 nkb = (fn == 0x8Fu) ? rEBX : rBX;
        if (rDX < XMS_MAX_H && xms_blk[rDX].used) {
            if (nkb <= xms_blk[rDX].size_kb) {
                xms_blk[rDX].size_kb = nkb;
                rAX = 1; rBL = 0;
            } else {
                xms_blk[rDX].used = 0;
                u32 nb = xms_alloc_at(nkb);
                xms_blk[rDX].used = 1;
                if (nb) {
                    u32 old_b = xms_blk[rDX].base, old_len = xms_blk[rDX].size_kb << 10;
                    if (nb != old_b) {
                        pm_check_code_write(nb, old_len);
                        for (u32 i = 0; i < old_len; i++) mem[nb + i] = mem[old_b + i];
                    }
                    xms_blk[rDX].base = nb;
                    xms_blk[rDX].size_kb = nkb;
                    rAX = 1; rBL = 0;
                } else {
                    rAX = 0; rBL = 0xA0u;
                }
            }
        } else {
            rAX = 0; rBL = 0xA2u;
        }
        break;
    }
    default:
        rAX = 0; rBL = 0x80u;
        break;
    }
}

/* ---- BIOS & DOS HLE ---- */
#define BDA 0x400

static void put_str(char *p, int *n, int size, const char *s)
{
    while (*s && *n < size - 1) p[(*n)++] = *s++;
}

static void put_hex(char *p, int *n, int size, u32 v)
{
    int digits = v > 0xFFFFu ? 8 : v > 0xFFu ? 4 : 2;
    for (int i = digits - 1; i >= 0 && *n < size - 1; i--)
        p[(*n)++] = "0123456789ABCDEF"[(v >> (4 * i)) & 15u];
}

void (*dos_log)(const char *line);

static void note(const char *what, u32 a, u32 b)
{
    if (!dos_log) return;
    char line[96];
    int n = 0;
    put_str(line, &n, sizeof(line), what);
    put_str(line, &n, sizeof(line), " ");
    put_hex(line, &n, sizeof(line), a);
    put_str(line, &n, sizeof(line), " ");
    put_hex(line, &n, sizeof(line), b);
    line[n] = 0;
    dos_log(line);
}

static void ret_flag(u32 bit, int on)
{
    u32 a = c.base[SS] + (u16)(rSP + 4u);
    u32 f = get16(a);
    put16(a, on ? (f | bit) : (f & ~bit));
    if (bit == F_CF)
        c.fl = on ? (c.fl | F_CF) : (c.fl & ~F_CF);
}

static u32 bios_ticks(void)
{
    return get16(BDA + 0x6C) | ((u32)get16(BDA + 0x6E) << 16);
}

static void wait_here(void)
{
    c.eip = (u16)(c.eip - 2u);
    c.sys |= F_IF;
    c.halted = 1;
    c.check = 1;
}

static void bios_key(void)
{
    static const char plain[] = "\0\0331234567890-=\b\tqwertyuiop[]\r\0asdfghjkl;'`\0\\zxcvbnm,./\0*\0 ";
    static const char shifted[] = "\0\033!@#$%^&*()_+\b\tQWERTYUIOP{}\r\0ASDFGHJKL:\"~\0|ZXCVBNM<>?\0*\0 ";
    static const char pad[] = "789-456+1230.";
    u32 code = in8(0x60), sc = code & 0x7Fu, up = code & 0x80u, e0 = mem[BDA + 0x96] & 2u;
    u8 *fl = mem + BDA + 0x17;
    if (code == 0xE0u || code == 0xE1u) { mem[BDA + 0x96] |= 2u; return; }
    mem[BDA + 0x96] &= (u8)~2u;
    if (e0 && (sc == 0x2Au || sc == 0x36u)) return;
    u32 bit = sc == 0x36u ? 1u : sc == 0x2Au ? 2u : sc == 0x1Du ? 4u : sc == 0x38u ? 8u : 0u;
    if (bit) { *fl = (u8)(up ? (*fl & ~bit) : (*fl | bit)); return; }
    if (up) return;
    if (sc == 0x3Au || sc == 0x45u || sc == 0x46u) {
        *fl ^= sc == 0x3Au ? 0x40u : sc == 0x45u ? 0x20u : 0x10u;
        return;
    }
    u32 ascii = 0, shift = (*fl & 3u) != 0;
    if (e0) {
        ascii = sc == 0x1Cu ? 13u : sc == 0x35u ? '/' : 0u;
    } else if (sc < sizeof(plain) - 1u) {
        ascii = (u8)(shift ? shifted : plain)[sc];
        if ((*fl & 0x40u) && ((ascii | 0x20u) >= 'a' && (ascii | 0x20u) <= 'z')) ascii ^= 0x20u;
        if (*fl & 4u) ascii = ((ascii | 0x20u) >= 'a' && (ascii | 0x20u) <= 'z') ? (ascii & 31u) : 0u;
        if (*fl & 8u) ascii = 0;
    } else if (sc >= 0x47u && sc <= 0x53u) {
        u32 num = (*fl & 0x20u) != 0;
        if (num != shift || sc == 0x4Au || sc == 0x4Eu) ascii = (u8)pad[sc - 0x47u];
    }
    u32 head = get16(BDA + 0x1A), tail = get16(BDA + 0x1C), next = tail + 2u;
    if (next >= get16(BDA + 0x82)) next = get16(BDA + 0x80);
    if (next == head) return;
    put16(BDA + tail, (sc << 8) | ascii);
    put16(BDA + 0x1C, next);
}

static int key_waiting(void) { return get16(BDA + 0x1A) != get16(BDA + 0x1C); }

static u32 key_take(void)
{
    u32 head = get16(BDA + 0x1A), k = get16(BDA + head);
    head += 2u;
    if (head >= get16(BDA + 0x82)) head = get16(BDA + 0x80);
    put16(BDA + 0x1A, head);
    return k;
}

static const u8 ega_attr[16] = {0, 1, 2, 3, 4, 5, 0x14, 7, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F};

static void dac_ega(int cga)
{
    for (u32 i = 0; i < 64; i++) {
        u32 r, g, b;
        if (cga) {
            u32 in = ((i >> 4) & 1u) * 21u;
            r = ((i & 4u) ? 42u : 0u) + in; g = ((i & 2u) ? 42u : 0u) + in; b = ((i & 1u) ? 42u : 0u) + in;
            if ((i & 0x17u) == 6u) g = 21u;
        } else {
            r = ((i >> 2) & 1u) * 42u + ((i >> 5) & 1u) * 21u;
            g = ((i >> 1) & 1u) * 42u + ((i >> 4) & 1u) * 21u;
            b = (i & 1u) * 42u + ((i >> 3) & 1u) * 21u;
        }
        dac[i][0] = (u8)r; dac[i][1] = (u8)g; dac[i][2] = (u8)b;
    }
}

static void dac_256(void)
{
    dac_ega(1);
    for (u32 i = 0; i < 16; i++) {
        u32 in = ((i >> 3) & 1u) * 21u;
        dac[i][0] = (u8)(((i & 4u) ? 42u : 0u) + in);
        dac[i][1] = (u8)(((i & 2u) ? 42u : 0u) + in);
        dac[i][2] = (u8)(((i & 1u) ? 42u : 0u) + in);
        if (i == 6u) dac[i][1] = 21u;
    }
    for (u32 i = 0; i < 16; i++)
        dac[16 + i][0] = dac[16 + i][1] = dac[16 + i][2] = (u8)(i * 63u / 15u);
    for (u32 i = 32; i < 256; i++) {
        u32 h = (i - 32u) % 24u, level = (i - 32u) / 24u, top = 63u - level * 7u, low = level * 3u;
        u32 up = low + (top - low) * (h % 4u) / 4u, down = top - (top - low) * (h % 4u) / 4u, rgb[3];
        switch (h / 4u) {
        case 0: rgb[0] = top; rgb[1] = up; rgb[2] = low; break;
        case 1: rgb[0] = down; rgb[1] = top; rgb[2] = low; break;
        case 2: rgb[0] = low; rgb[1] = top; rgb[2] = up; break;
        case 3: rgb[0] = low; rgb[1] = down; rgb[2] = top; break;
        case 4: rgb[0] = up; rgb[1] = low; rgb[2] = top; break;
        default: rgb[0] = top; rgb[1] = low; rgb[2] = down; break;
        }
        dac[i][0] = (u8)rgb[0]; dac[i][1] = (u8)rgb[1]; dac[i][2] = (u8)rgb[2];
    }
}

static u32 text_cols(void) { return mem[BDA + 0x4A] ? mem[BDA + 0x4A] : 80u; }

static void set_mode(u32 mode, int clear)
{
    u32 cols = 80;
    video_mode = (u8)mode;
    vga_n = 0;
    for (int i = 0; i < 8; i++) seq[i] = 0;
    for (int i = 0; i < 16; i++) gc[i] = 0;
    for (int i = 0; i < 32; i++) crtc[i] = 0;
    seq[2] = 15; seq[4] = 6; gc[8] = 0xFF; gc[7] = 15; gc[6] = 5;
    attr[0x10] = 0x01; attr[0x11] = 0; attr[0x12] = 15; attr[0x13] = 0; attr[0x14] = 0;
    attr_i = 0x20; attr_flip = 0; pel_mask = 0xFF;
    crtc[0x0A] = 6; crtc[0x0B] = 7;
    for (int i = 0; i < 16; i++) attr[i] = ega_attr[i];
    dac_ega(0);
    switch (mode) {
    case 0: case 1: cols = 40; kind = T_TEXT; crtc[0x13] = 20; attr[0x10] = 0x08; break;
    case 4: case 5: case 6:
        kind = mode == 6 ? T_CGA2 : T_CGA4;
        cols = mode == 6 ? 80 : 40;
        dac_ega(1);
        if (mode == 6) { attr[0] = 0; attr[1] = 0x17; }
        else           { attr[0] = 0; attr[1] = 0x13; attr[2] = 0x15; attr[3] = 0x17; }
        crtc[0x13] = 40; cga_colour = 0x30;
        break;
    case 0x0D: case 0x0E: case 0x10: case 0x12:
        kind = T_PLANAR;
        cols = mode == 0x0D ? 40 : 80;
        crtc[0x13] = mode == 0x0D ? 20 : 40;
        seq[4] = 6; gc[5] = 0;
        if (mode == 0x0D || mode == 0x0E) {
            dac_ega(1);
            for (int i = 0; i < 16; i++) attr[i] = (u8)((i & 7) | ((i & 8) ? 0x10 : 0));
        }
        planar_on();
        break;
    case 0x13:
        kind = T_VGA256; cols = 40; crtc[0x13] = 40; seq[4] = 0x0E; gc[5] = 0x40; attr[0x10] = 0x41;
        for (int i = 0; i < 16; i++) attr[i] = (u8)i;
        dac_256();
        break;
    default:
        video_mode = 3; kind = T_TEXT; crtc[0x13] = 40; attr[0x10] = 0x08;
        break;
    }
    mem[BDA + 0x49] = video_mode;
    put16(BDA + 0x4A, cols);
    put16(BDA + 0x4C, kind == T_TEXT ? (cols == 40 ? 0x800u : 0x1000u) : kind == T_VGA256 ? 0xFA00u :
                      mode == 0x0D ? 0x2000u : mode == 0x0E ? 0x4000u : mode == 0x10 ? 0x8000u :
                      mode == 0x12 ? 0xA000u : 0x4000u);
    put16(BDA + 0x4E, 0);
    for (int i = 0; i < 16; i++) mem[BDA + 0x50 + i] = 0;
    mem[BDA + 0x62] = 0; mem[BDA + 0x84] = 24; mem[BDA + 0x85] = 8;
    if (clear) {
        if (kind == T_TEXT) {
            u32 *tp = (u32 *)(mem + 0xB8000u);
            for (u32 i = 0; i < 0x8000u / 4u; i++) tp[i] = 0x07200720u;
        } else if (kind == T_CGA4 || kind == T_CGA2) {
            u32 *cp2 = (u32 *)(mem + 0xB8000u);
            for (u32 i = 0; i < 0x8000u / 4u; i++) cp2[i] = 0;
        } else {
            u32 *ap = (u32 *)(mem + 0xA0000u), *vp = (u32 *)&vram[0][0];
            for (u32 i = 0; i < 0x10000u / 4u; i++) ap[i] = 0;
            for (u32 i = 0; i < (4u * 0x10000u) / 4u; i++) vp[i] = 0;
        }
    }
    pal_dirty = 1;
    dirty = 1;
    vga_sync_fast();
}

static void put_pixel(u32 x, u32 y, u32 colour)
{
    switch (kind) {
    case T_VGA256:
        if (x < 320u && y < 200u) {
            u32 a = y * 320u + x;
            if (vga_n) vram[a & 3u][a >> 2] = (u8)((colour & 0x80u) ? (vram[a & 3u][a >> 2] ^ colour) : colour);
            else       mem[0xA0000u + a] = (u8)((colour & 0x80u) ? (mem[0xA0000u + a] ^ (colour & 0x7Fu)) : colour);
        }
        break;
    case T_PLANAR: {
        u32 w = crtc[0x13] * 2u, a = (y * w + (x >> 3)) & 0xFFFFu, bit = 0x80u >> (x & 7u);
        for (int p = 0; p < 4; p++) {
            u32 on = (colour >> p) & 1u;
            if (colour & 0x80u) vram[p][a] ^= (u8)(on ? bit : 0u);
            else                vram[p][a] = (u8)(on ? (vram[p][a] | bit) : (vram[p][a] & ~bit));
        }
        break;
    }
    case T_CGA4: case T_CGA2: {
        u32 a = 0xB8000u + (y & 1u) * 0x2000u + (y >> 1) * 80u, bits = kind == T_CGA2 ? 1u : 2u;
        if (y >= 200u || x >= (kind == T_CGA2 ? 640u : 320u)) break;
        a += x * bits / 8u;
        u32 sh = 8u - bits - (x * bits) % 8u, mask = (bits == 1u ? 1u : 3u) << sh, v = (colour << sh) & mask;
        mem[a] = (u8)((colour & 0x80u) ? (mem[a] ^ v) : ((mem[a] & ~mask) | v));
        break;
    }
    }
    dirty = 1;
}

static u32 get_pixel(u32 x, u32 y)
{
    switch (kind) {
    case T_VGA256: { u32 a = y * 320u + x; return vga_n ? vram[a & 3u][(a >> 2) & 0xFFFFu] : mem[0xA0000u + (a & 0xFFFFu)]; }
    case T_PLANAR: {
        u32 w = crtc[0x13] * 2u, a = (y * w + (x >> 3)) & 0xFFFFu, v = 0;
        for (int p = 0; p < 4; p++) v |= (u32)((vram[p][a] >> (7u - (x & 7u))) & 1u) << p;
        return v;
    }
    case T_CGA4: case T_CGA2: {
        u32 bits = kind == T_CGA2 ? 1u : 2u, a = 0xB8000u + (y & 1u) * 0x2000u + (y >> 1) * 80u + x * bits / 8u;
        return (mem[a & 0xFFFFFu] >> (8u - bits - (x * bits) % 8u)) & (bits == 1u ? 1u : 3u);
    }
    }
    return 0;
}

static void put_char(u32 ch, u32 attrib, u32 page, u32 count, int with_attr)
{
    u32 pos = get16(BDA + 0x50 + (page & 7u) * 2u), col = pos & 0xFFu, row = pos >> 8, cols = text_cols();
    for (u32 k = 0; k < count && col < cols; k++, col++) {
        if (kind == T_TEXT) {
            u32 a = 0xB8000u + (page & 7u) * get16(BDA + 0x4C) + (row * cols + col) * 2u;
            mem[a & 0xFFFFFu] = (u8)ch;
            if (with_attr) mem[(a + 1u) & 0xFFFFFu] = (u8)attrib;
            continue;
        }
        for (u32 y = 0; y < 8; y++)
            for (u32 x = 0; x < 8; x++) {
                u32 on = (font[ch & 255u][y] << x) & 0x80u;
                if (on || !(attrib & 0x80u))
                    put_pixel(col * 8u + x, row * 8u + y, on ? attrib : 0u);
            }
    }
    dirty = 1;
}

static void scroll(u32 lines, u32 fill, u32 top, u32 left, u32 bottom, u32 right, int down)
{
    u32 cols = text_cols();
    if (right >= cols) right = cols - 1u;
    if (bottom > 24u) bottom = 24u;
    if (top > bottom || left > right) return;
    if (kind != T_TEXT) {
        for (u32 y = top * 8u; y < (bottom + 1u) * 8u; y++)
            for (u32 x = left * 8u; x < (right + 1u) * 8u; x++)
                put_pixel(x, y, kind == T_VGA256 ? (fill & 0xFFu) : 0u);
        c.cycles += (s32)((bottom + 1u - top) * (right + 1u - left) * 64u * 4u);
        return;
    }
    u32 base = 0xB8000u + mem[BDA + 0x62] * (u32)get16(BDA + 0x4C), h = bottom - top + 1u;
    if (!lines || lines > h) lines = h;
    for (u32 i = 0; i < h; i++) {
        u32 y = down ? (bottom - i) : (top + i), from = down ? (y - lines) : (y + lines);
        int blank = down ? (y < top + lines) : (y + lines > bottom);
        for (u32 x = left; x <= right; x++) {
            u32 a = (base + (y * cols + x) * 2u) & 0xFFFFFu;
            if (blank) {
                mem[a] = ' '; mem[a + 1u] = (u8)fill;
            } else {
                u32 b = (base + (from * cols + x) * 2u) & 0xFFFFFu;
                mem[a] = mem[b]; mem[a + 1u] = mem[b + 1u];
            }
        }
    }
    dirty = 1;
}

static void teletype(u32 ch, u32 colour)
{
    u32 page = mem[BDA + 0x62], pos = get16(BDA + 0x50 + page * 2u), col = pos & 0xFFu, row = pos >> 8;
    u32 cols = text_cols();
    switch (ch) {
    case 7: return;
    case 8: if (col) col--; break;
    case 10: row++; break;
    case 13: col = 0; break;
    default:
        put_char(ch, colour, page, 1, kind != T_TEXT);
        if (++col >= cols) { col = 0; row++; }
    }
    if (row > 24u) { scroll(1, kind == T_TEXT ? 7u : 0u, 0, 0, 24, cols - 1u, 0); row = 24u; }
    put16(BDA + 0x50 + page * 2u, (row << 8) | col);
    if (kind == T_TEXT) {
        u32 at = page * get16(BDA + 0x4C) / 2u + row * cols + col;
        crtc[0x0E] = (u8)(at >> 8); crtc[0x0F] = (u8)at;
    }
}

static void bios_video(void)
{
    u32 es = c.base[ES];
    switch (rAH) {
    case 0x00: set_mode(rAL & 0x7Fu, !(rAL & 0x80u)); break;
    case 0x01: mem[BDA + 0x60] = rCL; mem[BDA + 0x61] = rCH; crtc[0x0A] = rCH; crtc[0x0B] = rCL; break;
    case 0x02:
        put16(BDA + 0x50 + (rBH & 7u) * 2u, rDX);
        if (kind == T_TEXT && rBH == mem[BDA + 0x62]) {
            u32 at = rBH * get16(BDA + 0x4C) / 2u + rDH * text_cols() + rDL;
            crtc[0x0E] = (u8)(at >> 8); crtc[0x0F] = (u8)at;
        }
        break;
    case 0x03: rDX = get16(BDA + 0x50 + (rBH & 7u) * 2u); rCX = get16(BDA + 0x60); break;
    case 0x05:
        mem[BDA + 0x62] = rAL & 7u;
        if (kind == T_TEXT || kind == T_PLANAR) {
            u32 at = (rAL & 7u) * get16(BDA + 0x4C) / (kind == T_TEXT ? 2u : 1u);
            put16(BDA + 0x4E, (rAL & 7u) * get16(BDA + 0x4C));
            crtc[0x0C] = (u8)(at >> 8); crtc[0x0D] = (u8)at;
        }
        dirty = 1;
        break;
    case 0x06: case 0x07: scroll(rAL, rBH, rCH, rCL, rDH, rDL, rAH == 7); break;
    case 0x08: {
        u32 pos = get16(BDA + 0x50 + (rBH & 7u) * 2u);
        u32 a = 0xB8000u + (rBH & 7u) * get16(BDA + 0x4C) + ((pos >> 8) * text_cols() + (pos & 0xFFu)) * 2u;
        rAX = kind == T_TEXT ? get16(a) : 0;
        break;
    }
    case 0x09: case 0x0A: put_char(rAL, rBL, rBH, rCX, rAH == 9 || kind != T_TEXT); break;
    case 0x0B:
        if (kind == T_CGA4) {
            u32 v = cga_colour;
            v = rBH ? ((v & ~0x20u) | ((rBL & 1u) ? 0x20u : 0u)) : ((v & 0x20u) | (rBL & 0x1Fu));
            vga_out(0x3D9, v);
        }
        break;
    case 0x0C: put_pixel(rCX, rDX, rAL); break;
    case 0x0D: rAL = (u8)get_pixel(rCX, rDX); break;
    case 0x0E: teletype(rAL, rBL); break;
    case 0x0F: rAL = video_mode; rAH = (u8)text_cols(); rBH = mem[BDA + 0x62]; break;
    case 0x10:
        switch (rAL) {
        case 0x00: if (rBL < 16u) attr[rBL] = rBH; break;
        case 0x01: attr[0x11] = rBH; break;
        case 0x02:
            for (u32 i = 0; i < 16; i++) attr[i] = rd8(es + (u16)(rDX + i));
            attr[0x11] = rd8(es + (u16)(rDX + 16));
            break;
        case 0x03: attr[0x10] = (u8)((attr[0x10] & ~8u) | ((rBL & 1u) ? 8u : 0u)); break;
        case 0x07: rBH = attr[rBL & 0x1Fu]; break;
        case 0x08: rBH = attr[0x11]; break;
        case 0x09:
            for (u32 i = 0; i < 16; i++) wr8(es + (u16)(rDX + i), attr[i]);
            wr8(es + (u16)(rDX + 16), attr[0x11]);
            break;
        case 0x10: dac[rBX & 255u][0] = rDH & 63u; dac[rBX & 255u][1] = rCH & 63u; dac[rBX & 255u][2] = rCL & 63u; break;
        case 0x12:
            for (u32 i = 0; i < rCX; i++)
                for (u32 k = 0; k < 3; k++)
                    dac[(rBX + i) & 255u][k] = rd8(es + (u16)(rDX + i * 3u + k)) & 63u;
            break;
        case 0x13:
            if (rBL == 0) attr[0x10] = (u8)((attr[0x10] & 0x7Fu) | ((rBH & 1u) << 7));
            else          attr[0x14] = rBH;
            break;
        case 0x15: rDH = dac[rBX & 255u][0]; rCH = dac[rBX & 255u][1]; rCL = dac[rBX & 255u][2]; break;
        case 0x17:
            for (u32 i = 0; i < rCX; i++)
                for (u32 k = 0; k < 3; k++)
                    wr8(es + (u16)(rDX + i * 3u + k), dac[(rBX + i) & 255u][k]);
            break;
        case 0x18: pel_mask = rBL; break;
        case 0x19: rBL = pel_mask; break;
        case 0x1A: rBL = attr[0x10] >> 7; rBH = attr[0x14]; break;
        case 0x1B:
            for (u32 i = 0; i < rCX; i++) {
                u8 *d = dac[(rBX + i) & 255u];
                u32 g = (30u * d[0] + 59u * d[1] + 11u * d[2] + 50u) / 100u;
                d[0] = d[1] = d[2] = (u8)g;
            }
            break;
        }
        attr_i |= 0x20u; pal_dirty = 1; dirty = 1;
        break;
    case 0x11:
        if (rAL == 0x30u) {
            set_seg_real(ES, 0xF000);
            rBP = rBH == 4u ? 0xA400u : rBH == 0u ? get16(0x1F * 4) : 0xA000u;
            if (rBH == 1u) { set_seg_real(ES, get16(0x43 * 4 + 2)); rBP = get16(0x43 * 4); }
            rCX = 8; rDL = 24;
        }
        break;
    case 0x12:
        if (rBL == 0x10u) { rBX = 0x0003; rCX = 0x0009; }
        else if (rBL >= 0x30u && rBL <= 0x36u) rAL = 0x12;
        break;
    case 0x13: {
        u32 page = rBH, n = rCX > 4000u ? 4000u : rCX, at = rBP, attrib = rBL;
        put16(BDA + 0x50 + (page & 7u) * 2u, rDX);
        u32 saved = mem[BDA + 0x62];
        mem[BDA + 0x62] = (u8)(page & 7u);
        for (u32 i = 0; i < n; i++) {
            u32 ch = rd8(es + (u16)at++);
            if (rAL & 2u) attrib = rd8(es + (u16)at++);
            teletype(ch, attrib);
        }
        mem[BDA + 0x62] = (u8)saved;
        if (!(rAL & 1u)) put16(BDA + 0x50 + (page & 7u) * 2u, rDX);
        break;
    }
    case 0x1A:
        if (rAL == 0) { rAL = 0x1A; rBX = 0x0008; }
        break;
    }
}

/* ---- DOS File System & Memory ---- */
#define FILES      96
#define HANDLES    40
#define ENV_SEG    0x0101
#define PSP_SEG    0x0112
#define MCB_FIRST  0x0100
#define MEM_TOP    0xA000

static struct {
    char name[13];
    const u8 *data;
    u8 *wr_data;
    u32 size, cap;
} files[FILES];
static int nfiles;
static u32 scratch_used;

static struct {
    int file;
    u32 pos;
} handle[HANDLES];
static u32 psp = PSP_SEG, dta, last_error, pending_ascii;
static char args[128], info[96];
static u8 *program;
static u32 program_size;
static int line_active;

static char upper(char ch) { return (ch >= 'a' && ch <= 'z') ? (char)(ch - 32) : ch; }

static void dos_name(const char *path, char *out)
{
    const char *base = path;
    for (const char *p = path; *p; p++)
        if (*p == '/' || *p == '\\' || *p == ':')
            base = p + 1;
    int n = 0;
    while (base[n] && n < 12) {
        out[n] = upper(base[n]);
        n++;
    }
    out[n] = 0;
}

static void read_name(u32 a, char *out, int size)
{
    int n = 0;
    for (; n < size - 1; n++) {
        char ch = (char)rd8(a + (u32)n);
        if (!ch) break;
        out[n] = ch;
    }
    out[n] = 0;
}

static int find_file(u32 a)
{
    char path[80], name[13];
    read_name(a, path, sizeof(path));
    dos_name(path, name);
    for (int i = 0; i < nfiles; i++) {
        int k = 0;
        while (name[k] && name[k] == files[i].name[k]) k++;
        if (!name[k] && !files[i].name[k]) return i;
    }
    return -1;
}

static void fcb_form(const char *name, char out[11])
{
    int i = 0, k = 0;
    for (; i < 11; i++) out[i] = ' ';
    for (i = 0; name[k] && name[k] != '.' && i < 8; k++)
        if (name[k] == '*') { while (i < 8) out[i++] = '?'; }
        else out[i++] = upper(name[k]);
    while (name[k] && name[k] != '.') k++;
    if (name[k] == '.') k++;
    for (i = 8; name[k] && i < 11; k++)
        if (name[k] == '*') { while (i < 11) out[i++] = '?'; }
        else out[i++] = upper(name[k]);
}

static void dos_ok(void) { ret_flag(F_CF, 0); }
static void dos_fail(u32 code) { last_error = code; rAX = (u16)code; ret_flag(F_CF, 1); }

static u32 mcb_size(u32 s)  { return get16((s << 4) + 3u); }
static u32 mcb_owner(u32 s) { return get16((s << 4) + 1u); }

static void mcb_set(u32 s, u32 type, u32 owner, u32 size)
{
    mem[s << 4] = (u8)type;
    put16((s << 4) + 1u, owner);
    put16((s << 4) + 3u, size);
}

static int mcb_valid(u32 s) { return s < MEM_TOP && (mem[s << 4] == 'M' || mem[s << 4] == 'Z'); }

static void mcb_absorb(u32 s)
{
    while (mem[s << 4] == 'M') {
        u32 n = s + 1u + mcb_size(s);
        if (!mcb_valid(n) || mcb_owner(n)) break;
        mcb_set(s, mem[n << 4], mcb_owner(s), mcb_size(s) + 1u + mcb_size(n));
    }
}

static void mcb_split(u32 s, u32 want)
{
    u32 size = mcb_size(s);
    if (size > want) {
        mcb_set(s + 1u + want, mem[s << 4], 0, size - want - 1u);
        mcb_set(s, 'M', mcb_owner(s), want);
    }
}

static void dos_alloc(void)
{
    u32 want = rBX, best = 0;
    for (u32 s = MCB_FIRST; mcb_valid(s); s += 1u + mcb_size(s)) {
        if (!mcb_owner(s)) {
            mcb_absorb(s);
            if (mcb_size(s) >= want) {
                mcb_split(s, want);
                put16((s << 4) + 1u, psp);
                rAX = (u16)(s + 1u);
                dos_ok();
                return;
            }
            if (mcb_size(s) > best) best = mcb_size(s);
        }
        if (mem[s << 4] == 'Z') break;
    }
    rBX = (u16)best;
    dos_fail(8);
}

static void dos_resize(void)
{
    u32 s = c.sr[ES] - 1u, want = rBX;
    if (!mcb_valid(s)) { dos_fail(9); return; }
    u32 had = mcb_size(s);
    mcb_absorb(s);
    if (mcb_size(s) >= want) {
        mcb_split(s, want);
        dos_ok();
        return;
    }
    rBX = (u16)mcb_size(s);
    mcb_split(s, had);
    dos_fail(8);
}

static void dos_end(u32 code)
{
    note("the program ended, its code", code, 0);
    ended = 1;
    c.halted = 1;
    c.sys &= ~F_IF;
}

static void dos_out(u32 ch)
{
    teletype(ch, 7);
    if (dos_log) {
        static char line[100];
        static int n;
        if (ch == 10 || ch == 13 || n == 98) {
            if (n) { line[n] = 0; dos_log(line); }
            n = 0;
        } else if (ch >= 32) {
            line[n++] = (char)ch;
        }
    }
}

static int dos_key(u32 *ch)
{
    if (pending_ascii) {
        *ch = pending_ascii & 0xFFu;
        pending_ascii = 0;
        return 1;
    }
    if (!key_waiting()) return 0;
    u32 k = key_take();
    *ch = k & 0xFFu;
    if (!*ch) pending_ascii = 0x100u | (k >> 8);
    return 1;
}

static void find_next(u32 d)
{
    char pattern[11], name[11];
    for (int i = 0; i < 11; i++)
        pattern[i] = (char)mem[(d + 1u + (u32)i) & 0xFFFFFu];
    for (u32 i = mem[(d + 13u) & 0xFFFFFu]; i < (u32)nfiles; i++) {
        fcb_form(files[i].name, name);
        int k = 0;
        while (k < 11 && (pattern[k] == '?' || pattern[k] == name[k])) k++;
        if (k < 11) continue;
        mem[(d + 13u) & 0xFFFFFu] = (u8)(i + 1u);
        wr8(d + 0x15u, 0x20);
        put16(d + 0x16u, 0x6000);
        put16(d + 0x18u, (13u << 9) | (6u << 5) | 1u);
        put16(d + 0x1Au, files[i].size);
        put16(d + 0x1Cu, files[i].size >> 16);
        int n = 0;
        for (; files[i].name[n]; n++)
            wr8(d + 0x1Eu + (u32)n, (u8)files[i].name[n]);
        wr8(d + 0x1Eu + (u32)n, 0);
        rAX = 0;
        dos_ok();
        return;
    }
    dos_fail(18);
}

static void dos(void)
{
    u32 ds = c.base[DS];
    u32 ch;
    switch (rAH) {
    case 0x00: dos_end(0); break;
    case 0x01: case 0x07: case 0x08:
        if (!dos_key(&ch)) { wait_here(); return; }
        rAL = (u8)ch;
        if (rAH == 1) dos_out(ch);
        break;
    case 0x02: dos_out(rDL); break;
    case 0x06:
        if (rDL != 0xFFu) { dos_out(rDL); break; }
        if (dos_key(&ch)) { rAL = (u8)ch; ret_flag(F_ZF, 0); }
        else              { rAL = 0;      ret_flag(F_ZF, 1); }
        break;
    case 0x09:
        for (u32 i = 0; i < 4096; i++) {
            u32 b = rd8(ds + (u16)(rDX + i));
            if (b == '$') break;
            dos_out(b);
        }
        break;
    case 0x0A: {
        u32 room = rd8(ds + rDX), n;
        if (!line_active) { line_active = 1; wr8(ds + (u16)(rDX + 1u), 0); }
        n = rd8(ds + (u16)(rDX + 1u));
        while (dos_key(&ch)) {
            if (ch == 13u) {
                wr8(ds + (u16)(rDX + 2u + n), 13);
                dos_out(13); dos_out(10);
                line_active = 0;
                return;
            }
            if (ch == 8u && n) {
                n--; dos_out(8); dos_out(' '); dos_out(8);
            } else if (ch >= 32u && n + 1u < room) {
                wr8(ds + (u16)(rDX + 2u + n), ch);
                n++; dos_out(ch);
            }
            wr8(ds + (u16)(rDX + 1u), n);
        }
        wait_here();
        return;
    }
    case 0x0B: rAL = (pending_ascii || key_waiting()) ? 0xFFu : 0u; break;
    case 0x0C:
        while (key_waiting()) key_take();
        pending_ascii = 0;
        if (rAL == 1 || rAL == 6 || rAL == 7 || rAL == 8 || rAL == 0x0A) { rAH = rAL; dos(); }
        break;
    case 0x0D: break;
    case 0x0E: rAL = 26; break;
    case 0x19: rAL = 2; break;
    case 0x1A: dta = ds + rDX; break;
    case 0x25: put16(rAL * 4u, rDX); put16(rAL * 4u + 2u, c.sr[DS]); break;
    case 0x29: {
        u32 si = rSI, fcb = c.base[ES] + rDI;
        char name[14], form[11];
        int n = 0;
        while (rd8(ds + (u16)si) == ' ' || rd8(ds + (u16)si) == '\t') si++;
        while (n < 13) {
            char k = (char)rd8(ds + (u16)si);
            if (k <= ' ' || k == '/' || k == ',' || k == ';' || k == '=' || k == '+') break;
            name[n++] = k; si++;
        }
        name[n] = 0;
        fcb_form(name, form);
        wr8(fcb, 0);
        for (int i = 0; i < 11; i++) wr8(fcb + 1u + (u32)i, (u8)form[i]);
        rSI = (u16)si; rAL = 0;
        break;
    }
    case 0x2A: rCX = 1993; rDH = 6; rDL = 1; rAL = 2; break;
    case 0x2B: case 0x2D: rAL = 0; break;
    case 0x2C: {
        u32 cs_t = bios_ticks() * 1000u / 182u, s = cs_t / 100u;
        rCH = (u8)((s / 3600u) % 24u); rCL = (u8)((s / 60u) % 60u);
        rDH = (u8)(s % 60u); rDL = (u8)(cs_t % 100u);
        break;
    }
    case 0x2F: set_seg_real(ES, dta >> 4); rBX = (u16)(dta & 15u); break;
    case 0x30: rAX = 0x0005; rBX = 0xFF00; rCX = 0; break;
    case 0x33:
        if (rAL == 6) { rBX = 0x0005; rDX = 0; }
        else if (rAL == 0) rDL = 0;
        break;
    case 0x34: set_seg_real(ES, 0x60); rBX = 0x10; break;
    case 0x35: rBX = get16(rAL * 4u); set_seg_real(ES, get16(rAL * 4u + 2u)); break;
    case 0x36: rAX = 4; rBX = 8000; rCX = 512; rDX = 16000; break;
    case 0x37: rAL = 0; rDL = '/'; break;
    case 0x38:
        for (u32 i = 0; i < 34; i++) wr8(ds + (u16)(rDX + i), 0);
        wr8(ds + (u16)(rDX + 2), '$'); wr8(ds + (u16)(rDX + 7), ',');
        wr8(ds + (u16)(rDX + 9), '.'); wr8(ds + (u16)(rDX + 11), '-'); wr8(ds + (u16)(rDX + 13), ':');
        rBX = 1; dos_ok();
        break;
    case 0x39: case 0x3A: case 0x3B: case 0x41: case 0x56:
        dos_ok();
        break;
    case 0x3C: case 0x5A: case 0x5B: {  /* Create File in RAM scratch pool */
        char path[80], nm[13];
        read_name(ds + rDX, path, sizeof(path));
        dos_name(path, nm);
        int f = find_file(ds + rDX);
        if (f < 0) {
            if (nfiles >= FILES || scratch_used + 4096u > SCRATCH_CAP) { dos_fail(4); break; }
            f = nfiles++;
            for (int i = 0; i < 13; i++) files[f].name[i] = nm[i];
            files[f].wr_data = M->scratch + scratch_used;
            files[f].data = files[f].wr_data;
            files[f].size = 0;
            files[f].cap = 4096u;
            scratch_used += 4096u;
        } else if (files[f].wr_data) {
            files[f].size = 0;
        }
        int h = 5;
        while (h < HANDLES && handle[h].file != -1) h++;
        if (h == HANDLES) { dos_fail(4); break; }
        handle[h].file = f;
        handle[h].pos = 0;
        rAX = (u16)h;
        dos_ok();
        break;
    }
    case 0x3D: case 0x6C: {
        u32 name_ptr = ds + (rAH == 0x6Cu ? rSI : rDX);
        int f = find_file(name_ptr);
        if (f < 0 && rAH == 0x6Cu && (rDX & 0x10u)) {
            /* Extended Open with Create flag */
            char path[80], nm[13];
            read_name(name_ptr, path, sizeof(path));
            dos_name(path, nm);
            if (nfiles < FILES && scratch_used + 4096u <= SCRATCH_CAP) {
                f = nfiles++;
                for (int i = 0; i < 13; i++) files[f].name[i] = nm[i];
                files[f].wr_data = M->scratch + scratch_used;
                files[f].data = files[f].wr_data;
                files[f].size = 0;
                files[f].cap = 4096u;
                scratch_used += 4096u;
            }
        }
        if (f < 0) {
            dos_fail(2);
            break;
        }
        int h = 5;
        while (h < HANDLES && handle[h].file != -1) h++;
        if (h == HANDLES) { dos_fail(4); break; }
        handle[h].file = f;
        handle[h].pos = 0;
        rAX = (u16)h;
        if (rAH == 0x6Cu) rCX = 1;
        dos_ok();
        break;
    }
    case 0x3E:
        if (rBX < HANDLES && handle[rBX].file >= 0) { handle[rBX].file = -1; dos_ok(); }
        else if (rBX < 5u) dos_ok();
        else dos_fail(6);
        break;
    case 0x3F: {
        if (rBX >= HANDLES || handle[rBX].file == -1) { dos_fail(6); break; }
        if (handle[rBX].file == -2) {
            u32 n = 0;
            while (n < rCX && dos_key(&ch)) { wr8(ds + (u16)(rDX + n), ch); n++; }
            rAX = (u16)n;
            dos_ok();
            break;
        }
        u32 f = (u32)handle[rBX].file, pos = handle[rBX].pos, n = rCX;
        if (pos >= files[f].size) n = 0;
        else if (n > files[f].size - pos) n = files[f].size - pos;
        u32 dst = ds + rDX;
        if ((dst & a20_mask) + n <= 0xA0000u && !(c.cr0 & 0x80000000u)) {
            u32 p = dst & a20_mask;
            const u8 *src = files[f].data + pos;
            u32 i = 0;
            for (; i + 4u <= n; i += 4u)
                ua_w32(mem + p + i, ua_r32(src + i));
            for (; i < n; i++)
                mem[p + i] = src[i];
            writes++;
        } else {
            for (u32 i = 0; i < n; i++) wr8(ds + (u16)(rDX + i), files[f].data[pos + i]);
        }
        handle[rBX].pos = pos + n;
        rAX = (u16)n;
        c.cycles += (s32)(n / 4u);
        dos_ok();
        break;
    }
    case 0x40:
        if (rBX >= HANDLES || handle[rBX].file == -1) { dos_fail(6); break; }
        if (handle[rBX].file == -2) {
            for (u32 i = 0; i < rCX; i++) dos_out(rd8(ds + (u16)(rDX + i)));
        } else {
            int f = handle[rBX].file;
            if (files[f].wr_data) {
                for (u32 i = 0; i < rCX && handle[rBX].pos < files[f].cap; i++) {
                    files[f].wr_data[handle[rBX].pos++] = rd8(ds + (u16)(rDX + i));
                    if (handle[rBX].pos > files[f].size) files[f].size = handle[rBX].pos;
                }
            } else {
                handle[rBX].pos += rCX;
            }
        }
        rAX = rCX;
        dos_ok();
        break;
    case 0x42: {
        if (rBX >= HANDLES || handle[rBX].file < 0) { dos_fail(6); break; }
        s32 off = (s32)(((u32)rCX << 16) | rDX), base = 0;
        if (rAL == 1)      base = (s32)handle[rBX].pos;
        else if (rAL == 2) base = (s32)files[handle[rBX].file].size;
        s32 to = base + off;
        if (to < 0) { dos_fail(0x19); break; }
        handle[rBX].pos = (u32)to;
        rAX = (u16)to;
        rDX = (u16)((u32)to >> 16);
        dos_ok();
        break;
    }
    case 0x43:
        if (find_file(ds + rDX) < 0) { dos_fail(2); break; }
        rCX = 0x20;
        dos_ok();
        break;
    case 0x44:
        if (rAL == 0 || rAL == 1) {
            if (rBX >= HANDLES || handle[rBX].file == -1) { dos_fail(6); break; }
            if (rAL == 0) rDX = handle[rBX].file == -2 ? 0x80D3u : 0x0002u;
            dos_ok();
        } else if (rAL == 6 || rAL == 7) {
            rAL = 0xFF; dos_ok();
        } else if (rAL == 8) {
            rAX = 1; dos_ok();
        } else if (rAL == 9) {
            rDX = 0; dos_ok();
        } else {
            dos_fail(1);
        }
        break;
    case 0x45: case 0x46: {
        int h = rAH == 0x46 ? rCX : 0;
        if (rBX >= HANDLES || handle[rBX].file == -1 || (rAH == 0x46 && rCX >= HANDLES)) { dos_fail(6); break; }
        if (rAH == 0x45) {
            h = 0;
            while (h < HANDLES && handle[h].file != -1) h++;
            if (h == HANDLES) { dos_fail(4); break; }
            rAX = (u16)h;
        }
        handle[h] = handle[rBX];
        dos_ok();
        break;
    }
    case 0x47: wr8(ds + rSI, 0); dos_ok(); break;
    case 0x48: dos_alloc(); break;
    case 0x49:
        if (!mcb_valid(c.sr[ES] - 1u)) { dos_fail(9); break; }
        put16(((c.sr[ES] - 1u) << 4) + 1u, 0);
        dos_ok();
        break;
    case 0x4A: dos_resize(); break;
    case 0x4B: dos_fail(2); break;
    case 0x4C: dos_end(rAL); break;
    case 0x4D: rAX = 0; break;
    case 0x4E: {
        char path[80], name[13], form[11];
        read_name(ds + rDX, path, sizeof(path));
        dos_name(path, name);
        fcb_form(name, form);
        if ((rCX & 0x08u) && !(rCX & 0x10u)) { dos_fail(18); break; }
        for (int i = 0; i < 11; i++) wr8(dta + 1u + (u32)i, (u8)form[i]);
        wr8(dta + 13u, 0);
        find_next(dta);
        break;
    }
    case 0x4F: find_next(dta); break;
    case 0x50: psp = rBX; break;
    case 0x51: case 0x62: rBX = (u16)psp; break;
    case 0x52: set_seg_real(ES, 0x60); rBX = 0x26; break;
    case 0x54: rAL = 0; break;
    case 0x57:
        if (rAL == 0) { rCX = 0x6000; rDX = (13u << 9) | (6u << 5) | 1u; }
        dos_ok();
        break;
    case 0x58: if (rAL == 0) rAX = 0; dos_ok(); break;
    case 0x59: rAX = (u16)last_error; rBX = 0x0104; rCH = 1; break;
    case 0x63: dos_fail(1); break;
    case 0x66: rBX = 437; rDX = 437; dos_ok(); break;
    case 0x67: case 0x68: dos_ok(); break;
    case 0x31: dos_end(rAL); break;
    default:
        dos_fail(1);
        break;
    }
}

static __attribute__((noinline)) void hle(u32 n)
{
    switch (n) {
    case 0x00:
        note("divide error at", ((u32)get16(c.base[SS] + (u16)(rSP + 2u)) << 16) | get16(c.base[SS] + rSP), 0);
        dos_end(0xFF);
        break;
    case 0x06: dos_end(0xFF); break;
    case 0x08: {
        u32 t = bios_ticks() + 1u;
        if (t >= 0x1800B0u) { t = 0; mem[BDA + 0x70] = 1; }
        put16(BDA + 0x6C, t);
        put16(BDA + 0x6E, t >> 16);
        break;
    }
    case 0x09: bios_key(); break;
    case 0x10: bios_video(); break;
    case 0x11: rAX = get16(BDA + 0x10); break;
    case 0x12: rAX = 640; break;
    case 0x13:
        if (rAH) { rAH = 1; ret_flag(F_CF, 1); }
        else ret_flag(F_CF, 0);
        break;
    case 0x14: rAH = 0x80; break;
    case 0x15:
        if (rAH == 0x88u) {
            /* Report 0 KB to INT 15h once XMS is used (standard HIMEM.SYS behavior), or 0 so extenders use XMS cleanly! */
            int any_xms = 0;
            for (int i = 1; i < XMS_MAX_H; i++) any_xms |= xms_blk[i].used;
            rAX = any_xms ? 0 : 0;      /* Always 0 so DOS/4GW uses our XMS 3.0 manager without overlap! */
            ret_flag(F_CF, 0);
        } else if (rAH == 0x87u) {      /* Move Extended Memory Block via GDT at ES:SI */
            u32 g = (c.base[ES] + rSI) & 0xFFFFFu;
            u32 sa = get16(g + 0x12u) | ((u32)mem[g + 0x14u] << 16) | ((u32)mem[g + 0x17u] << 24);
            u32 da = get16(g + 0x1Au) | ((u32)mem[g + 0x1Cu] << 16) | ((u32)mem[g + 0x1Fu] << 24);
            u32 nb = (u32)rCX * 2u;
            if (sa + nb <= RAM_BYTES && da + nb <= RAM_BYTES) {
                pm_check_code_write(da, nb);
                if (da >= sa + nb || sa >= da + nb) {
                    u32 i = 0;
                    for (; i + 4u <= nb; i += 4u)
                        ua_w32(mem + da + i, ua_r32(mem + sa + i));
                    for (; i < nb; i++)
                        mem[da + i] = mem[sa + i];
                } else {
                    for (u32 i = 0; i < nb; i++) mem[da + i] = mem[sa + i];
                }
                rAH = 0; ret_flag(F_CF, 0);
            } else {
                rAH = 2; ret_flag(F_CF, 1);
            }
        } else if (rAH == 0x86u) {
            u32 us = ((u32)rCX << 16) | rDX;
            if (us > 1000000u) us = 1000000u;
            c.cycles += (s32)(us * 1193u / 1000u * PIT_CYCLES);
            ret_flag(F_CF, 0);
        } else if (rAH == 0xC0u) {      /* Return System Configuration Parameters (F000:E6F5) */
            set_seg_real(ES, 0xF000);
            rBX = 0xE6F5;
            rAH = 0;
            ret_flag(F_CF, 0);
        } else if (rAH == 0x90u || rAH == 0x91u) {
            rAH = 0;
        } else {
            if (rAH != 0x4Fu) rAH = 0x86;
            ret_flag(F_CF, 1);
        }
        break;
    case 0x16:
        switch (rAH) {
        case 0x00: case 0x10:
            if (!key_waiting()) { wait_here(); return; }
            rAX = (u16)key_take();
            break;
        case 0x01: case 0x11:
            if (key_waiting()) { rAX = get16(BDA + get16(BDA + 0x1A)); ret_flag(F_ZF, 0); }
            else ret_flag(F_ZF, 1);
            break;
        case 0x02: case 0x12: rAL = mem[BDA + 0x17]; rAH = 0; break;
        case 0x05: {
            u32 head = get16(BDA + 0x1A), tail = get16(BDA + 0x1C), next = tail + 2u;
            if (next >= get16(BDA + 0x82)) next = get16(BDA + 0x80);
            if (next == head) { rAL = 1; break; }
            put16(BDA + tail, rCX); put16(BDA + 0x1C, next); rAL = 0;
            break;
        }
        }
        break;
    case 0x17: rAH = 0x90; break;
    case 0x1A:
        switch (rAH) {
        case 0x00:
            rCX = get16(BDA + 0x6E); rDX = get16(BDA + 0x6C);
            rAL = mem[BDA + 0x70]; mem[BDA + 0x70] = 0;
            break;
        case 0x01: put16(BDA + 0x6E, rCX); put16(BDA + 0x6C, rDX); break;
        case 0x02: {
            u32 s = (u32)((bios_ticks() * 10u) / 182u);
            rCH = bcd((s / 3600u) % 24u); rCL = bcd((s / 60u) % 60u); rDH = bcd(s % 60u); rDL = 0;
            ret_flag(F_CF, 0);
            break;
        }
        case 0x04: rCX = 0x1993; rDX = 0x0601; ret_flag(F_CF, 0); break;
        default: ret_flag(F_CF, 1); break;
        }
        break;
    case 0x20: dos_end(0); break;
    case 0x21: dos(); break;
    case 0x24: rAL = 3; break;
    case 0x29: teletype(rAL, 7); break;
    case 0x2F:
        if (rAX == 0x4300u) {
            rAL = 0x80u;                /* XMS driver installed! */
        } else if (rAX == 0x4310u) {
            set_seg_real(ES, 0xF000);   /* XMS far entry stub at F000:0500 */
            rBX = 0x0500u;
        } else if (rAX == 0x1600u) {
            rAL = 0;
        }
        break;
    case 0x33:
        if (rAX == 0) rBX = 0;
        break;
    case 0x67:                          /* No EMS / VCPI */
        rAH = 0x84u;
        break;
    case 0x80:                          /* XMS far-call entry (F1 80 CB at F000:0505) */
        xms_dispatch();
        break;
    }
}

static void rom_build(void)
{
    static const u8 timer[]     = {0xF1, 0x08, 0xCD, 0x1C, 0x50, 0xB0, 0x20, 0xE6, 0x20, 0x58, 0xCF};
    static const u8 keyboard[]  = {0xF1, 0x09, 0x50, 0xB0, 0x20, 0xE6, 0x20, 0x58, 0xCF};
    static const u8 irq[]       = {0x50, 0xB0, 0x20, 0xE6, 0x20, 0x58, 0xCF};
    static const u8 irq_slave[] = {0x50, 0xB0, 0x20, 0xE6, 0xA0, 0xE6, 0x20, 0x58, 0xCF};
    /* XMS standard 5-byte header (JMP SHORT +3; NOP; NOP; NOP) followed by F1 80; RETF */
    static const u8 xms_stub[]  = {0xEB, 0x03, 0x90, 0x90, 0x90, 0xF1, 0x80, 0xCB};
    /* AT 386 System Configuration Table at F000:E6F5 */
    static const u8 sys_cfg[]   = {0x08, 0x00, 0xFC, 0x01, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00};

    u8 *rom = mem + 0xF0000u;
    for (u32 i = 0; i < 0x10000u; i++) rom[i] = 0;
    for (u32 n = 0; n < 256; n++) {
        rom[n * 4u] = 0xF1;
        rom[n * 4u + 1u] = (u8)n;
        rom[n * 4u + 2u] = 0xCF;
    }
    for (u32 i = 0; i < sizeof(timer); i++)     rom[0x400 + i] = timer[i];
    for (u32 i = 0; i < sizeof(keyboard); i++)  rom[0x410 + i] = keyboard[i];
    for (u32 i = 0; i < sizeof(irq); i++)       rom[0x420 + i] = irq[i];
    for (u32 i = 0; i < sizeof(irq_slave); i++) rom[0x430 + i] = irq_slave[i];
    for (u32 i = 0; i < sizeof(xms_stub); i++)  rom[0x500 + i] = xms_stub[i];
    for (u32 i = 0; i < sizeof(sys_cfg); i++)   rom[0xE6F5 + i] = sys_cfg[i];

    for (u32 ch = 0; ch < 256; ch++)
        for (u32 y = 0; y < 8; y++) {
            rom[0xA000u + ch * 8u + y] = font[ch][y];
            if (ch < 128u) rom[0xFA6Eu + ch * 8u + y] = font[ch][y];
        }
    static const char date[] = "06/01/93";
    for (u32 i = 0; i < 8; i++) rom[0xFFF5u + i] = (u8)date[i];
    rom[0xFFFE] = 0xFC;
}

static void font_build(void)
{
    for (u32 ch = 0; ch < 256; ch++)
        for (u32 y = 0; y < 8; y++) {
            u32 b = 0;
            if (ch >= FONT_FIRST && ch <= FONT_LAST && y < FONT_H)
                b = (u32)font5x7[ch - FONT_FIRST][y] << 2;
            else if (ch == 0xDBu) b = 0xFFu;
            else if (ch == 0xDCu) b = y >= 4u ? 0xFFu : 0u;
            else if (ch == 0xDFu) b = y < 4u ? 0xFFu : 0u;
            else if (ch == 0xB0u || ch == 0xB1u || ch == 0xB2u)
                b = (y & 1u) ? (ch == 0xB2u ? 0xFFu : 0x55u) : (ch == 0xB0u ? 0u : 0xAAu);
            else if (ch == 0xC4u || ch == 0xCDu)
                b = (y == 3u || (ch == 0xCDu && y == 5u)) ? 0xFFu : 0u;
            else if (ch == 0xB3u || ch == 0xBAu)
                b = ch == 0xB3u ? 0x10u : 0x28u;
            font[ch][y] = (u8)b;
        }
    for (u32 b = 0; b < 256; b++) {
        squeeze[b] = (u8)(((b & 0xC0u) ? 8 : 0) | ((b & 0x20u) ? 4 : 0) | ((b & 0x18u) ? 2 : 0) | ((b & 0x06u) ? 1 : 0));
        u32 s = 0;
        for (u32 i = 0; i < 8; i++)
            if (b & (0x80u >> i)) s |= 1u << (28 - 4 * i);
        spread[b] = s;
    }
}

static u32 w16(const u8 *p) { return (u32)(p[0] | ((u32)p[1] << 8)); }

static const char *start_program(void)
{
    const u8 *f = program;
    u32 size = program_size, load = psp + 0x10u, block, cs, ip, ss, sp;
    static const char env[] = "COMSPEC=C:\\COMMAND.COM\0PATH=C:\\\0PROMPT=$P$G\0BLASTER=A220 I7 D1 T3\0";
    u32 e = ENV_SEG << 4, k = 0;
    for (; k < sizeof(env) - 1u; k++) mem[e + k] = (u8)env[k];
    mem[e + k++] = 0;
    put16(e + k, 1); k += 2u;
    const char *path = "C:\\";
    while (*path) mem[e + k++] = (u8)*path++;
    for (int i = 0; files[0].name[i]; i++) mem[e + k++] = (u8)files[0].name[i];
    mem[e + k] = 0;
    mcb_set(MCB_FIRST, 'M', psp, 0x10);
    for (int i = 0; i < 8; i++) mem[(MCB_FIRST << 4) + 8u + (u32)i] = 0;

    u32 avail = MEM_TOP - psp;
    if (size >= 0x1Cu && f[0] == 'M' && f[1] == 'Z') {
        u32 header = w16(f + 8) * 16u, pages = w16(f + 4), last = w16(f + 2), image;
        image = pages * 512u - (last ? (512u - last) : 0u);
        if (image > size) image = size;
        if (image < header) return "a broken .exe header";
        image -= header;
        u32 need = 0x10u + (image + 15u) / 16u + w16(f + 0x0A);
        u32 most = 0x10u + (image + 15u) / 16u + w16(f + 0x0C);
        if (need > avail) return "an .exe stub that needs more than 640 KB low RAM";
        block = (most > avail || most < need) ? avail : most;
        for (u32 i = 0; i < image; i++)
            mem[(load << 4) + i] = f[header + i];
        u32 n = w16(f + 6), at = w16(f + 0x18);
        for (u32 i = 0; i < n && at + 4u * i + 4u <= size; i++) {
            u32 a = ((w16(f + at + 4u * i + 2u) + load) << 4) + w16(f + at + 4u * i);
            put16(a, get16(a) + load);
        }
        ss = w16(f + 0x0E) + load; sp = w16(f + 0x10);
        cs = w16(f + 0x16) + load; ip = w16(f + 0x14);
    } else {
        if (size > 0xFF00u) return "a .com file larger than 64 KB";
        block = avail;
        for (u32 i = 0; i < size; i++) mem[(psp << 4) + 0x100u + i] = f[i];
        ss = cs = psp; ip = 0x100; sp = 0xFFFE;
        put16((psp << 4) + 0xFFFEu, 0);
    }
    mcb_set(psp - 1u, block == avail ? 'Z' : 'M', psp, block);
    if (block < avail) mcb_set(psp + block, 'Z', 0, avail - block - 1u);

    u32 p = psp << 4;
    for (u32 i = 0; i < 256; i++) mem[p + i] = 0;
    mem[p] = 0xCD; mem[p + 1] = 0x20;
    put16(p + 2, psp + block);
    mem[p + 5] = 0x9A; put16(p + 6, 0xFEF0); put16(p + 8, 0xF01D);
    put16(p + 0x0A, get16(0x22 * 4)); put16(p + 0x0C, get16(0x22 * 4 + 2));
    put16(p + 0x0E, get16(0x23 * 4)); put16(p + 0x10, get16(0x23 * 4 + 2));
    put16(p + 0x12, get16(0x24 * 4)); put16(p + 0x14, get16(0x24 * 4 + 2));
    put16(p + 0x16, psp);
    for (u32 i = 0; i < 20; i++)
        mem[p + 0x18 + i] = (u8)(i < 5 ? (i == 3 ? 0 : i == 4 ? 2 : 1) : 0xFF);
    put16(p + 0x2C, ENV_SEG);
    put16(p + 0x32, 20); put16(p + 0x34, 0x18); put16(p + 0x36, psp);
    mem[p + 0x50] = 0xCD; mem[p + 0x51] = 0x21; mem[p + 0x52] = 0xCB;
    for (u32 i = 0; i < 11; i++) mem[p + 0x5D + i] = mem[p + 0x6D + i] = ' ';
    u32 n = 0;
    while (args[n] && n < 126u) n++;
    mem[p + 0x80] = (u8)n;
    for (u32 i = 0; i < n; i++) mem[p + 0x81 + i] = (u8)args[i];
    mem[p + 0x81 + n] = 13;
    dta = p + 0x80u;

    for (int i = 0; i < 8; i++) c.reg[i].d = 0;
    for (int i = 0; i < 6; i++) { set_seg_real(i, psp); c.limit[i] = 0xFFFFu; c.d32[i] = 0; }
    set_seg_real(SS, ss);
    set_seg_real(CS, cs);
    rSP = (u16)sp;
    c.eip = ip & 0xFFFFu;
    rCX = 0x00FF;
    rDX = (u16)psp;
    rSI = (u16)ip;
    rDI = (u16)sp;
    rBP = 0x091C;
    set_eflags(F_IF, 1);
    return 0;
}

static void bios_data(void)
{
    for (u32 i = 0; i < 0x500; i++) mem[i] = 0;
    for (u32 n = 0; n < 256; n++) {
        put16(n * 4u, n * 4u);
        put16(n * 4u + 2u, 0xF000);
    }
    put16(8 * 4, 0x400);
    put16(9 * 4, 0x410);
    for (u32 n = 0x0A; n < 0x10; n++) put16(n * 4u, 0x420);
    for (u32 n = 0x70; n < 0x78; n++) put16(n * 4u, 0x430);
    put16(0x1F * 4, 0xA400);
    put16(0x43 * 4, 0xA000);
    put16(0x1D * 4, 0xB000);
    put16(0x1E * 4, 0xB000);
    for (u32 n = 0x60; n < 0x67; n++) { put16(n * 4u, 0); put16(n * 4u + 2u, 0); }
    put16(BDA + 0x10, 0x0021);
    put16(BDA + 0x13, 640);
    put16(BDA + 0x1A, 0x1E); put16(BDA + 0x1C, 0x1E); put16(BDA + 0x80, 0x1E); put16(BDA + 0x82, 0x3E);
    put16(BDA + 0x63, 0x3D4);
    mem[BDA + 0x87] = 0x60; mem[BDA + 0x88] = 0x09; mem[BDA + 0x89] = 0x11;
    mem[BDA + 0x96] = 0x10;
    u32 t = 12u * 65543u;
    put16(BDA + 0x6C, t); put16(BDA + 0x6E, t >> 16);
    put16(0x600 + 0x24, MCB_FIRST);
}

static u8 held_was[32];
static char queue[256];
static int q_head, q_tail, q_frame;

static void machine_reset(void)
{
    for (int i = 0; i < 256; i++) {
        u32 b = (u32)i, n = 0;
        while (b) { n += b & 1u; b >>= 1; }
        parity[i] = (u8)!(n & 1u);
    }
    /* Clear conventional + first 256 KB + XMS tables (leave upper 7 MB lazy-cleared or zeroed cleanly) */
    u32 *mp = (u32 *)mem;
    for (u32 i = 0; i < (RAM_BYTES + 64u) / 4u; i++)
        mp[i] = 0;
    tlb_flush();
    opl2_init(&M->opl);
    opl_last_cyc = 0;
    sb_reset();
    u8 *dp = (u8 *)&dma;
    for (u32 i = 0; i < sizeof(dma); i++) dp[i] = 0;
    dma.mask = 0x0Fu;
    for (int i = 0; i < XMS_MAX_H; i++) xms_blk[i].used = 0;
    xms_hma_used = 0;
    a20_mask = 0xFFFFFu;
    port92 = 0;
    for (int i = 0; i < 128; i++) cmos_ram[i] = 0;

    font_build();
    rom_build();
    bios_data();
    u32 *vp = (u32 *)&vram[0][0];
    for (u32 i = 0; i < sizeof(vram) / 4u; i++)
        vp[i] = 0;

    u8 *cp = (u8 *)&c;
    for (u32 i = 0; i < sizeof(c); i++) cp[i] = 0;
    was.cs_eip = 0; was.sys = 0; was.armed = 0;
    was0f.cs_eip = 0; was0f.sys = 0; was0f.armed = 0;
    pm_inval_code_snaps();
    idle_cycles = 0;
    writes = 0;
    c.cr0 = 0x00000010u;
    c.idt_limit = 0x3FFu;
    c.gdt_limit = 0xFFFFu;
    cycles_hi = 0;
    ended = 0;

    for (int i = 0; i < 2; i++) {
        pic[i].irr = pic[i].isr = pic[i].init = pic[i].need4 = pic[i].read_isr = 0;
    }
    pic[0].imr = 0x38u;                 /* Enable Timer (0), KBD (1), Slave (2), Floppy (6), Sound Blaster (7)! */
    pic[0].base = 0x08u;
    pic[1].imr = 0xFFu;
    pic[1].base = 0x70u;

    for (int i = 0; i < 3; i++) {
        pit_n[i] = i == 1 ? 18u : 0x10000u;
        pit_new[i] = 0;
        pit_mode[i] = i == 1 ? 2u : 3u;
        pit_access[i] = 3;
        pit_half[i] = pit_latched[i] = pit_read_hi[i] = 0;
        pit_running[i] = i != 2;
        pit_start[i] = 0;
    }
    pit0_next = 0x10000 * PIT_CYCLES;
    pit0_on = 1;
    pit_gate2 = 0;
    port61 = 0;
    kq_head = kq_tail = 0;
    kbc_full = kbc_command = kbd_command = 0;
    kbc_data = 0;
    for (int i = 0; i < 32; i++) held_was[i] = 0;
    q_head = q_tail = q_frame = 0;
    for (int i = 0; i < HANDLES; i++)
        handle[i].file = i < 5 ? -2 : -1;
    psp = PSP_SEG;
    last_error = 0;
    pending_ascii = 0;
    line_active = 0;
    frames = 0;
    pm_sub_cyc = 0;
    snd_frac = snd_head = snd_tail = 0;
    opl_prev_fm = 0; opl_half_phase = 0; aud_slice_pend = 0;
    set_mode(3, 1);
}

void dos_reset(void)
{
    machine_reset();
    if (program)
        (void)start_program();
}

#pragma GCC push_options
#pragma GCC optimize("O2,no-align-jumps,no-align-loops,no-align-labels")

#define PM32_FAST_OK() \
    ((c.cr0 & 0x80000001u) == 1u && !(c.sys & F_VM) && c.d32[CS] && c.d32[SS] && \
     a20_mask == (RAM_BYTES - 1u) && !(c.base[CS] | c.base[DS] | c.base[SS] | c.base[ES]))

typedef unsigned long long pm_ea_t;

static __attribute__((noinline)) pm_ea_t pm_ea_sib(u32 m, const u8 *p)
{
    u32 mod = m >> 6, sib = p[0];
    u32 idx = (sib >> 3) & 7u, br = sib & 7u;
    u32 iv = __builtin_expect(idx != 4u, 1) ? (R32(idx) << (sib >> 6)) : 0u;
    if (mod == 0u) {
        if (br == 5u) return ((pm_ea_t)5u << 32) | (ua_r32(p + 1) + iv);
        return ((pm_ea_t)1u << 32) | (R32(br) + iv);
    }
    if (mod == 1u)
        return ((pm_ea_t)2u << 32) | (R32(br) + iv + (u32)(s32)(s8)p[1]);
    return ((pm_ea_t)5u << 32) | (R32(br) + iv + ua_r32(p + 1));
}

typedef __UINTPTR_TYPE__ pm_uptr_t;
typedef __INTPTR_TYPE__  pm_sptr_t;

INLINE pm_ea_t pm_ea_off_esp(u32 m, const u8 *p)
{
    u32 rm = m & 7u, mod = m >> 6;
    if (__builtin_expect(rm == 4u, 0)) {
        u32 sib = p[0];
        if (sib == 0x24u) {
            if (mod == 1u) return ((pm_ea_t)2u << 32) | (rESP + (u32)(s32)(s8)p[1]);
            if (mod == 0u) return ((pm_ea_t)1u << 32) | rESP;
            return ((pm_ea_t)5u << 32) | (rESP + ua_r32(p + 1));
        }
        if (mod == 0u && (sib & 7u) != 5u && (sib & 0x38u) != 0x20u)
            return ((pm_ea_t)1u << 32) | (R32(sib & 7u) + (R32((sib >> 3) & 7u) << (sib >> 6)));
        return pm_ea_sib(m, p);
    }
    if (mod == 1u)
        return ((pm_ea_t)1u << 32) | (R32(rm) + (u32)(s32)(s8)*p);
    if (mod == 0u) {
        if (rm == 5u) return ((pm_ea_t)4u << 32) | ua_r32(p);
        return (pm_ea_t)R32(rm);
    }
    return ((pm_ea_t)4u << 32) | (R32(rm) + ua_r32(p));
}

INLINE pm_ea_t pm_ea_off(u32 m, const u8 *p)
{
    return pm_ea_off_esp(m, p);
}

static __attribute__((noinline)) pm_ea_t pm_ea_off_fn(u32 m, const u8 *p)
{
    return pm_ea_off(m, p);
}

#define PM_EA(m_, p_, off_) do { \
    pm_ea_t ea_ = pm_ea_off((m_), (p_)); \
    (off_) = (u32)ea_; \
    (p_) += (u32)(ea_ >> 32); \
} while (0)

#define PM_EA_ESP(m_, p_, off_) do { \
    pm_ea_t ea_ = pm_ea_off_esp((m_), (p_)); \
    (off_) = (u32)ea_; \
    (p_) += (u32)(ea_ >> 32); \
} while (0)

#define PM_EA_SIB PM_EA

#define PM_EA_FN(m_, p_, off_) do { \
    pm_ea_t ea_ = pm_ea_off_fn((m_), (p_)); \
    (off_) = (u32)ea_; \
    (p_) += (u32)(ea_ >> 32); \
} while (0)

static __attribute__((noinline)) int pm_div32(u32 subk, u32 v)
{
    if (subk == 6u) {
        if (rEDX == 0u && v != 0u) {
            u32 a = rEAX;
            rEAX = a / v;
            rEDX = a % v;
            return 0;
        }
        u32 q = 0, rem = 0;
        if (dos_divu64_32(rEDX, rEAX, v, &q, &rem) < 0) return -1;
        rEAX = q;
        rEDX = rem;
        return 0;
    }
    u32 hi = rEDX, lo = rEAX;
    int neg_n = (hi & 0x80000000u) != 0, neg_d = (v & 0x80000000u) != 0;
    if (neg_n) {
        lo = ~lo + 1u;
        hi = ~hi + (lo == 0u ? 1u : 0u);
    }
    u32 ud = neg_d ? (~v + 1u) : v, q = 0, rem = 0;
    if (dos_divu64_32(hi, lo, ud, &q, &rem) < 0) return -1;
    int neg_q = neg_n ^ neg_d;
    if (q > (neg_q ? 0x80000000u : 0x7FFFFFFFu)) return -1;
    rEAX = neg_q ? (~q + 1u) : q;
    rEDX = neg_n ? (~rem + 1u) : rem;
    return 0;
}

static __attribute__((noinline)) u8 pm_rd8_slow(u32 lin)
{
    return rd8_phys(lin & (RAM_BYTES - 1u));
}

static __attribute__((noinline)) u32 pm_wr8_slow(u32 lin, u32 v, u32 wr_cnt)
{
    writes = wr_cnt;
    wr8_phys(lin & (RAM_BYTES - 1u), v);
    return writes;
}

static __attribute__((noinline)) u16 pm_rd16_slow(u32 lin)
{
    return rd16_lin(lin);
}

static __attribute__((noinline)) u32 pm_wr16_slow(u32 lin, u32 v, u32 wr_cnt)
{
    writes = wr_cnt;
    wr16_lin(lin, v);
    return writes;
}

static __attribute__((noinline)) u32 pm_rd32_slow(u32 lin)
{
    return rd32_lin(lin);
}

#define PM_WR8_RAM(p_, v_)  do { wr_cnt++; (p_) = (u8)(v_); } while (0)
#define PM_WR16_RAM(p_, v_) do { wr_cnt++; ua_w16((p_), (u16)(v_)); } while (0)
#define PM_WR32_RAM(p_, v_) do { wr_cnt++; ua_w32((p_), (v_)); } while (0)

static __attribute__((noinline)) u32 pm_wr32_slow(u32 lin, u32 v, u32 wr_cnt)
{
    if (lin < 0x9FFFCu) {
        PM_WR32_RAM(mem + lin, v);
        return wr_cnt;
    }
    if (lin >= 0x100000u && lin < RAM_BYTES - 4u) {
        if (lin < c.wr_fast_lo && lin + 4u > c.wr_guard_lo &&
            lin != tmap_col_eip + 0x0D4u && lin != tmap_col_eip + 0x0E1u &&
            lin != tmap_spn_eip + 0x1DCu && lin != tmap_spn_eip + 0x1F6u)
            pm_inval_code_snaps();
        PM_WR32_RAM(mem + lin, v);
        return wr_cnt;
    }
    writes = wr_cnt;
    wr32_lin(lin, v);
    return writes;
}

#define PM_IS_RAM2(a_)  ((u32)(a_) < (RAM_BYTES - 2u) && (u32)((u32)(a_) - 0x9FFFFu) >= 0x60001u)
#define PM_IS_RAM4(a_)  ((u32)(a_) < (RAM_BYTES - 4u) && (u32)((u32)(a_) - 0x9FFFCu) >= 0x60004u)
#define PM_IS_XRAM4(a_) ((u32)((u32)(a_) - 0x100000u) < (RAM_BYTES - 0x100004u))

#define PM_RD8(addr, res) do { \
    u32 pa_ = (addr) & (RAM_BYTES - 1u); \
    if (__builtin_expect((u32)(pa_ - 0xA0000u) >= 0x60000u, 1)) (res) = ram[pa_]; \
    else (res) = pm_rd8_slow(pa_); \
} while (0)

#define PM_IS_WFAST4(a_) ((u32)((u32)(a_) - PM_CODE_GUARD_TOP) < (RAM_BYTES - PM_CODE_GUARD_TOP - 4u))

#define PM_WR8(addr, val) do { \
    u32 pa_ = (addr) & (RAM_BYTES - 1u), vv_ = (val); \
    if (__builtin_expect(PM_IS_WFAST4(pa_), 1)) { \
        PM_WR8_RAM(ram[pa_], vv_); \
    } else { \
        wr_cnt = pm_wr8_slow(pa_, vv_, wr_cnt); \
    } \
} while (0)

#define PM_WR8_VGA(addr, val) do { \
    u32 pa_ = (addr) & (RAM_BYTES - 1u), vo_ = pa_ - 0xA0000u, vv_ = (val); \
    if (__builtin_expect(PM_IS_WFAST4(pa_), 1)) { \
        PM_WR8_RAM(ram[pa_], vv_); \
    } else if (vo_ < 0x10000u && vga_single_ptr) { \
        wr_cnt++; \
        vdirty[vo_ >> 8] = 1; \
        vga_single_ptr[vo_] = (u8)vv_; \
    } else { \
        wr_cnt = pm_wr8_slow(pa_, vv_, wr_cnt); \
    } \
} while (0)

#define PM_RD16(addr, res) do { \
    u32 a_ = (addr); \
    if (__builtin_expect(PM_IS_RAM2(a_), 1)) \
        (res) = ua_r16(ram + a_); \
    else \
        (res) = pm_rd16_slow(a_); \
} while (0)

#define PM_WR16(addr, val) do { \
    u32 a_ = (addr), vv_ = (val); \
    if (__builtin_expect(PM_IS_WFAST4(a_), 1)) { \
        PM_WR16_RAM(ram + a_, vv_); \
    } else { \
        wr_cnt = pm_wr16_slow(a_, vv_, wr_cnt); \
    } \
} while (0)

#define PM_WR16_VGA(addr, val) do { \
    u32 a_ = (addr), vv_ = (val); \
    if (__builtin_expect(PM_IS_WFAST4(a_), 1)) { \
        PM_WR16_RAM(ram + a_, vv_); \
    } else { \
        u32 vo_ = (a_ & (RAM_BYTES - 1u)) - 0xA0000u; \
        if (__builtin_expect(vo_ < 0xFFFFu && vga_single_ptr != 0, 1)) { \
            wr_cnt += 2u; \
            vdirty[vo_ >> 8] = 1; \
            vdirty[(vo_ + 1u) >> 8] = 1; \
            ua_w16(vga_single_ptr + vo_, (u16)vv_); \
        } else { \
            wr_cnt = pm_wr16_slow(a_, vv_, wr_cnt); \
        } \
    } \
} while (0)

#define PM_RD32(addr, res) do { \
    u32 a_ = (addr); \
    if (__builtin_expect(PM_IS_XRAM4(a_), 1)) \
        (res) = ua_r32(ram + a_); \
    else \
        (res) = pm_rd32_slow(a_); \
} while (0)

#define PM_WR32(addr, val) do { \
    u32 a_ = (addr), vv_ = (val); \
    if (__builtin_expect(PM_IS_WFAST4(a_), 1)) { \
        PM_WR32_RAM(ram + a_, vv_); \
    } else { \
        wr_cnt = pm_wr32_slow(a_, vv_, wr_cnt); \
    } \
} while (0)

#ifdef PM_EXACT_CPI3
#define PM_PUSH32(addr, val) PM_WR32(addr, val)
#else
static __attribute__((noinline)) u32 pm_push32_slow(u32 lin, u32 v, u32 wr_cnt)
{
    if (lin < 0x9FFFCu || (lin >= 0x100000u && lin < RAM_BYTES - 4u)) {
        pm_check_code_write(lin, 4u);
        ua_w32(mem + lin, v);
        return wr_cnt;
    }
    writes = wr_cnt;
    wr32_lin(lin, v);
    return writes;
}
#define PM_PUSH32(addr, val) do { \
    u32 a_ = (addr), vv_ = (val); \
    if (__builtin_expect(PM_IS_WFAST4(a_), 1)) { \
        ua_w32(ram + a_, vv_); \
    } else { \
        wr_cnt = pm_push32_slow(a_, vv_, wr_cnt); \
    } \
} while (0)
#endif

static __attribute__((noinline)) int pm_pushad(u32 ds_base)
{
    u32 esp = rESP, top = ds_base + esp - 32u;
    if (__builtin_expect((u32)(top - 0x100000u) < (RAM_BYTES - 0x100020u) || top < 0x9FFE0u, 1)) {
        pm_check_code_write(top, 32u);
        u8 *sp = mem + top;
        ua_w32(sp + 28u, c.reg[0].d);
        ua_w32(sp + 24u, c.reg[1].d);
        ua_w32(sp + 20u, c.reg[2].d);
        ua_w32(sp + 16u, c.reg[3].d);
        ua_w32(sp + 12u, esp);
        ua_w32(sp +  8u, c.reg[5].d);
        ua_w32(sp +  4u, c.reg[6].d);
        ua_w32(sp +  0u, c.reg[7].d);
        rESP = esp - 32u;
#ifdef PM_EXACT_CPI3
        writes += 8u;
#endif
        return 1;
    }
    return 0;
}

static __attribute__((noinline)) int pm_popad(u32 ds_base)
{
    u32 esp = rESP, base = ds_base + esp;
    if (__builtin_expect((u32)(base - 0x100000u) < (RAM_BYTES - 0x100020u) || base < 0x9FFE0u, 1)) {
        const u8 *sp = mem + base;
        c.reg[7].d = ua_r32(sp +  0u);
        c.reg[6].d = ua_r32(sp +  4u);
        c.reg[5].d = ua_r32(sp +  8u);
        c.reg[3].d = ua_r32(sp + 16u);
        c.reg[2].d = ua_r32(sp + 20u);
        c.reg[1].d = ua_r32(sp + 24u);
        c.reg[0].d = ua_r32(sp + 28u);
        rESP = esp + 32u;
        return 1;
    }
    return 0;
}

#ifdef PM_EXACT_CPI3
#define PM_CLK_SH       0
#define PM_CYC_IN()     (c.cycles)
#define PM_CYC_OUT(cc_) (c.cycles = (cc_))
#else
#ifndef PM_CLK_SH
#define PM_CLK_SH       3
#endif
#if PM_CLK_SH == 0
#define PM_CYC_IN()     (c.cycles)
#define PM_CYC_OUT(cc_) (c.cycles = (cc_))
#else
#define PM_CYC_IN()     ((s32)((u32)c.cycles << PM_CLK_SH) | (s32)pm_sub_cyc)
#define PM_CYC_OUT(cc_) do { \
    s32 cc_v_ = (cc_); \
    c.cycles = cc_v_ >> PM_CLK_SH; \
    pm_sub_cyc = (u8)((u32)cc_v_ & ((1u << PM_CLK_SH) - 1u)); \
} while (0)
#endif
#endif

static __attribute__((noinline)) s32 idle_match_slow(u32 eip, s32 cyc_cnt, u32 wr_cnt)
{
    c.eip = eip;
    PM_CYC_OUT(cyc_cnt);
    s32 prev = c.cycles;
    writes = wr_cnt;
    idle();
    if (c.cycles != prev)
        pm_sub_cyc = 0;
    return PM_CYC_IN();
}

static __attribute__((noinline)) s32 idle_pm32(u32 eip, s32 cyc_cnt, u32 wr_cnt)
{
    u32 sys = c.sys;
    if (!(sys & F_IF)) {
        was.sys = sys;
        was.armed = 0;
        return cyc_cnt;
    }
    u32 cs_eip = ((u32)c.sr[CS] << 16) ^ eip;
    if (__builtin_expect(cs_eip == was.cs_eip && wr_cnt == was.wr_snap, 0))
        return idle_match_slow(eip, cyc_cnt, wr_cnt);
    was.cs_eip = cs_eip;
    was.wr_snap = wr_cnt;
#ifdef PM_EXACT_CPI3
    was.fl = c.fl;
    was.zs = c.zs;
    was.pb = c.pb;
    was.sys = sys;
    was.reg[0] = c.reg[0].d; was.reg[1] = c.reg[1].d;
    was.reg[2] = c.reg[2].d; was.reg[3] = c.reg[3].d;
    was.reg[4] = c.reg[4].d; was.reg[5] = c.reg[5].d;
    was.reg[6] = c.reg[6].d; was.reg[7] = c.reg[7].d;
    const u32 *sr = (const u32 *)(const void *)c.sr;
    u32 *wsr = (u32 *)(void *)was.sr;
    wsr[0] = sr[0]; wsr[1] = sr[1]; wsr[2] = sr[2];
    was.armed = 1;
#else
    was.armed = 0;
#endif
    return cyc_cnt;
}

#ifndef PM_EXACT_CPI3
static __attribute__((noinline)) s32 idle_match_0f_slow(s32 cyc_cnt)
{
    const u32 *sr = (const u32 *)(const void *)c.sr;
    const u32 *wsr = (const u32 *)(const void *)was0f.sr;
    if (was0f.armed && c.fl == was0f.fl && c.zs == was0f.zs && c.pb == was0f.pb && c.sys == was0f.sys &&
        sr[0] == wsr[0] && sr[1] == wsr[1] && sr[2] == wsr[2] &&
        c.reg[0].d == was0f.reg[0] && c.reg[1].d == was0f.reg[1] &&
        c.reg[2].d == was0f.reg[2] && c.reg[3].d == was0f.reg[3] &&
        c.reg[4].d == was0f.reg[4] && c.reg[5].d == was0f.reg[5] &&
        c.reg[6].d == was0f.reg[6] && c.reg[7].d == was0f.reg[7]) {
        s32 end_sc = (s32)((u32)run_end << PM_CLK_SH);
        if (cyc_cnt < end_sc) {
            idle_cycles += (u32)((end_sc - cyc_cnt) >> PM_CLK_SH);
            return end_sc;
        }
    }
    was0f.fl = c.fl; was0f.zs = c.zs; was0f.pb = c.pb; was0f.sys = c.sys;
    was0f.reg[0] = c.reg[0].d; was0f.reg[1] = c.reg[1].d;
    was0f.reg[2] = c.reg[2].d; was0f.reg[3] = c.reg[3].d;
    was0f.reg[4] = c.reg[4].d; was0f.reg[5] = c.reg[5].d;
    was0f.reg[6] = c.reg[6].d; was0f.reg[7] = c.reg[7].d;
    u32 *wsr_mut = (u32 *)(void *)was0f.sr;
    wsr_mut[0] = sr[0]; wsr_mut[1] = sr[1]; wsr_mut[2] = sr[2];
    was0f.armed = 1;
    return cyc_cnt;
}

static __attribute__((noinline)) s32 idle_pm32_0f(u32 eip, s32 cyc_cnt, u32 wr_cnt)
{
    u32 sys = c.sys;
    if (!(sys & F_IF)) {
        was0f.sys = sys;
        was0f.armed = 0;
        return cyc_cnt;
    }
    u32 cs_eip = ((u32)c.sr[CS] << 16) ^ eip;
    if (__builtin_expect(cs_eip == was0f.cs_eip && wr_cnt == was0f.wr_snap, 0))
        return idle_match_0f_slow(cyc_cnt);
    was0f.cs_eip = cs_eip;
    was0f.wr_snap = wr_cnt;
    was0f.armed = 0;
    return cyc_cnt;
}
#define IDLE_PM32_0F idle_pm32_0f
#else
#define IDLE_PM32_0F idle_pm32
#endif

/* Returns: 1 = handled, 2 = handled I/O (recheck state), 0 = fallback to slow_step */
static __attribute__((noinline)) int pm_exec_66(u32 op_eip, const u8 *ip, u32 ds_base)
{
    u8 * const ram = mem;
    const u8 *p = ip + 2;
    u32 op2 = ip[1], m, v, r, off, addr = 0;
    u32 wr_cnt = writes;
    switch (op2) {
    case 0x01: case 0x09: case 0x11: case 0x19: case 0x21: case 0x29: case 0x31: case 0x39:
        m = *p++;
        if (m >= 0xC0u) { v = R16(m); c.eip = op_eip + 3u; }
        else { PM_EA_FN(m, p, off); addr = ds_base + off; c.eip = op_eip + (u32)(p - ip); PM_RD16(addr, v); }
        r = alu16(op2 >> 3, v, R16(m >> 3));
        if (op2 != 0x39u) { if (m >= 0xC0u) R16(m) = (u16)r; else PM_WR16(addr, r); }
        c.cycles += PM_CYC66; writes = wr_cnt;
        return 1;
    case 0x03: case 0x0B: case 0x13: case 0x1B: case 0x23: case 0x2B: case 0x33: case 0x3B:
        m = *p++;
        if (m >= 0xC0u) { v = R16(m); c.eip = op_eip + 3u; }
        else { PM_EA_FN(m, p, off); addr = ds_base + off; c.eip = op_eip + (u32)(p - ip); PM_RD16(addr, v); }
        r = alu16(op2 >> 3, R16(m >> 3), v);
        if (op2 != 0x3Bu) R16(m >> 3) = (u16)r;
        c.cycles += PM_CYC66; writes = wr_cnt;
        return 1;
    case 0x05: case 0x0D: case 0x15: case 0x1D: case 0x25: case 0x2D: case 0x35: case 0x3D:
        r = alu16(op2 >> 3, rAX, ua_r16(p));
        if (op2 != 0x3Du) rAX = (u16)r;
        c.eip = op_eip + 4u; c.cycles += PM_CYC66;
        return 1;
    case 0x0F: {
        u32 op3 = *p++;
        switch (op3) {
        case 0xA4: case 0xA5: case 0xAC: case 0xAD: {
            m = *p++;
            u32 src_r = R16(m >> 3), cnt;
            if (m >= 0xC0u) {
                v = R16(m);
                cnt = (op3 & 1u) ? rCL : *p++;
                c.eip = op_eip + (u32)(p - ip);
            } else {
                PM_EA_FN(m, p, off);
                addr = ds_base + off;
                cnt = (op3 & 1u) ? rCL : *p++;
                c.eip = op_eip + (u32)(p - ip);
                PM_RD16(addr, v);
            }
            r = (op3 < 0xA8u) ? shld_v(v, src_r, cnt, 16u) : shrd_v(v, src_r, cnt, 16u);
            if (m >= 0xC0u) R16(m) = (u16)r; else PM_WR16(addr, r);
            c.cycles += PM_CYC66; writes = wr_cnt;
            return 1;
        }
        case 0xAF: {
            m = *p++;
            if (m >= 0xC0u) { v = R16(m); c.eip = op_eip + 4u; }
            else { PM_EA_FN(m, p, off); addr = ds_base + off; c.eip = op_eip + (u32)(p - ip); PM_RD16(addr, v); }
            s32 pr = (s16)R16(m >> 3) * (s16)v;
            c.fl = pr != (s16)pr ? (F_CF | F_OF) : 0u;
            c.zs = (s16)pr;
            c.pb = (u32)pr;
            R16(m >> 3) = (u16)pr;
            c.cycles += PM_CYC66; writes = wr_cnt;
            return 1;
        }
        case 0xB6: case 0xBE:
            m = *p++;
            if (m >= 0xC0u) { v = R8(m); c.eip = op_eip + 4u; }
            else { PM_EA_FN(m, p, off); addr = ds_base + off; c.eip = op_eip + (u32)(p - ip); PM_RD8(addr, v); }
            R16(m >> 3) = (op3 == 0xBEu) ? (u16)(s16)(s8)v : (u16)v;
            c.cycles += PM_CYC66; writes = wr_cnt;
            return 1;
        case 0xB7: case 0xBF:
            m = *p++;
            if (m >= 0xC0u) { v = R16(m); c.eip = op_eip + 4u; }
            else { PM_EA_FN(m, p, off); addr = ds_base + off; c.eip = op_eip + (u32)(p - ip); PM_RD16(addr, v); }
            R16(m >> 3) = (u16)v;
            c.cycles += PM_CYC66; writes = wr_cnt;
            return 1;
        default:
            return 0;
        }
    }
    case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: case 0x46: case 0x47: {
        u32 a = R16(op2), res = (a + 1u) & 0xFFFFu;
        c.fl = (c.fl & F_CF) | ((a ^ res) & F_AF) | (res == 0x8000u ? F_OF : 0u);
        c.zs = (s16)res; c.pb = res;
        R16(op2) = (u16)res;
        c.eip = op_eip + 2u; c.cycles += PM_CYC66;
        return 1;
    }
    case 0x48: case 0x49: case 0x4A: case 0x4B: case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
        u32 a = R16(op2), res = (a - 1u) & 0xFFFFu;
        c.fl = (c.fl & F_CF) | ((a ^ res) & F_AF) | (a == 0x8000u ? F_OF : 0u);
        c.zs = (s16)res; c.pb = res;
        R16(op2) = (u16)res;
        c.eip = op_eip + 2u; c.cycles += PM_CYC66;
        return 1;
    }
    case 0x81: case 0x83: {
        m = *p++;
        if (m >= 0xC0u) v = R16(m);
        else { PM_EA_FN(m, p, off); addr = ds_base + off; PM_RD16(addr, v); }
        u32 imm = (op2 == 0x81u) ? ua_r16(p) : (u32)(u16)(s16)(s8)*p;
        p += (op2 == 0x81u) ? 2 : 1;
        c.eip = op_eip + (u32)(p - ip);
        r = alu16(m >> 3, v, imm);
        if (((m >> 3) & 7u) != 7u) { if (m >= 0xC0u) R16(m) = (u16)r; else PM_WR16(addr, r); }
        c.cycles += PM_CYC66; writes = wr_cnt;
        return 1;
    }
    case 0x85:
        m = *p++;
        if (m >= 0xC0u) { v = R16(m); c.eip = op_eip + 3u; }
        else { PM_EA_FN(m, p, off); addr = ds_base + off; c.eip = op_eip + (u32)(p - ip); PM_RD16(addr, v); }
        logic16(v & R16(m >> 3));
        c.cycles += PM_CYC66; writes = wr_cnt;
        return 1;
    case 0x89:
        m = *p++;
        v = R16(m >> 3);
        if (m >= 0xC0u) { c.eip = op_eip + 3u; R16(m) = (u16)v; }
        else { PM_EA_FN(m, p, off); addr = ds_base + off; c.eip = op_eip + (u32)(p - ip); PM_WR16_VGA(addr, v); }
        c.cycles += PM_CYC66; writes = wr_cnt;
        return 1;
    case 0x8B:
        m = *p++;
        if (m >= 0xC0u) { v = R16(m); c.eip = op_eip + 3u; }
        else { PM_EA_FN(m, p, off); addr = ds_base + off; c.eip = op_eip + (u32)(p - ip); PM_RD16(addr, v); }
        R16(m >> 3) = (u16)v;
        c.cycles += PM_CYC66; writes = wr_cnt;
        return 1;
    case 0xA9:
        logic16(rAX & ua_r16(p));
        c.eip = op_eip + 4u; c.cycles += PM_CYC66;
        return 1;
    case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        R16(op2) = ua_r16(p);
        c.eip = op_eip + 4u; c.cycles += PM_CYC66;
        return 1;
    case 0xC1: case 0xD1: case 0xD3: {
        m = *p++;
        u32 cnt;
        if (m >= 0xC0u) {
            v = R16(m);
            cnt = (op2 == 0xC1u) ? *p++ : (op2 == 0xD1u ? 1u : rCL);
            c.eip = op_eip + (u32)(p - ip);
        } else {
            PM_EA_FN(m, p, off); addr = ds_base + off;
            cnt = (op2 == 0xC1u) ? *p++ : (op2 == 0xD1u ? 1u : rCL);
            c.eip = op_eip + (u32)(p - ip);
            PM_RD16(addr, v);
        }
        r = shift(m >> 3, v, cnt, 16u);
        if (m >= 0xC0u) R16(m) = (u16)r; else PM_WR16(addr, r);
        c.cycles += PM_CYC66; writes = wr_cnt;
        return 1;
    }
    case 0xC7:
        m = *p++;
        if (m >= 0xC0u) { R16(m) = ua_r16(p); c.eip = op_eip + 5u; }
        else { PM_EA_FN(m, p, off); addr = ds_base + off; v = ua_r16(p); p += 2; c.eip = op_eip + (u32)(p - ip); PM_WR16(addr, v); }
        c.cycles += PM_CYC66; writes = wr_cnt;
        return 1;
    case 0xEF:
        if (rDX == 0x3C4u && rAL == 2u) {
            u8 ah = rAH;
            seq_i = 2u;
            seq[2] = ah;
            vga_single_ptr = vga_fast_lut[ah & 15u];
            c.eip = op_eip + 2u; c.cycles += PM_CYC66; writes = wr_cnt + 2u;
            return 1;
        }
        c.eip = op_eip + 2u; c.op_eip = op_eip;
        PM_CYC_OUT(c.cycles + PM_CYC66); writes = wr_cnt;
        out16(rDX, rAX);
        return 2;
    default:
        return 0;
    }
}

static __attribute__((noinline)) int pm_exec_f7(u32 op_eip, const u8 *ip, u32 ds_base)
{
    u8 * const ram = mem;
    const u8 *p = ip + 1;
    u32 m = *p++, subk = (m >> 3) & 7u, v, r, off, addr = 0;
    u32 wr_cnt = writes;
    if (m >= 0xC0u) v = R32(m);
    else { PM_EA_FN(m, p, off); addr = ds_base + off; PM_RD32(addr, v); }
    if (subk <= 1u) {
        u32 imm = ua_r32(p); p += 4;
        c.eip = op_eip + (u32)(p - ip);
        logic32(v & imm);
    } else if (subk == 2u) {
        c.eip = op_eip + (u32)(p - ip);
        if (m >= 0xC0u) R32(m) = ~v; else PM_WR32(addr, ~v);
    } else if (subk == 3u) {
        c.eip = op_eip + (u32)(p - ip);
        r = sub32(0, v, 0);
        c.fl = (c.fl & ~F_CF) | (v != 0u);
        if (m >= 0xC0u) R32(m) = r; else PM_WR32(addr, r);
    } else if (subk == 4u) {
        c.eip = op_eip + (u32)(p - ip);
        unsigned long long prod = (unsigned long long)rEAX * (unsigned long long)v;
        rEAX = (u32)prod;
        rEDX = (u32)(prod >> 32);
        c.fl = rEDX ? (F_CF | F_OF) : 0u;
    } else if (subk == 5u) {
        c.eip = op_eip + (u32)(p - ip);
        signed long long prod = (signed long long)(s32)rEAX * (signed long long)(s32)v;
        rEAX = (u32)prod;
        rEDX = (u32)((unsigned long long)prod >> 32);
        if (c.cycles + PM_CYC < (s32)((u32)run_end << PM_CLK_SH) && ua_r32(p) == 0x10D0AC0Fu) {
            rEAX = shrd32_fast(rEAX, rEDX, 16u);
            c.eip += 4u;
            c.cycles += PM_FUSE_FMUL;
        } else {
            c.fl = (prod < -(signed long long)0x80000000LL || prod > (signed long long)0x7FFFFFFFLL) ? (F_CF | F_OF) : 0u;
        }
    } else {
        if (pm_div32(subk, v) < 0) return 0;
        c.eip = op_eip + (u32)(p - ip);
        c.cycles += PM_DIV_CYC;
    }
    c.cycles += PM_CYC;
    writes = wr_cnt;
    return 1;
}

#if !defined(PM_EXACT_CPI3) && !defined(NO_FUSE_PUSHAD)
static __attribute__((noinline)) void pm_mark_vdirty_span(u32 b0, u32 b1)
{
    b0 &= 0xFFu;
    b1 &= 0xFFu;
    if (b1 < b0) b1 = 0xFFu;
    volatile u8 *vd = vdirty;
    u32 b = b0;
    for (; b <= b1 && (b & 3u); b++)
        vd[b] = 1;
    volatile u32 *vd32 = (volatile u32 *)(volatile void *)vdirty;
    for (; b + 3u <= b1; b += 4u)
        vd32[b >> 2] = 0x01010101u;
    for (; b <= b1; b++)
        vd[b] = 1;
}

static __attribute__((noinline)) int pm_try_fuse_pushad(u32 op_eip, const u8 *ip);
#endif

/* Returns: 1 = handled, 2 = handled I/O (recheck state), 0 = fallback to slow_step */
static __attribute__((noinline)) int pm_exec_cold(u32 op_eip, const u8 *ip, u32 ds_base)
{
    u8 * const ram = mem;
    const u8 *p = ip + 1;
    u32 op = ip[0], m, v, r, off, addr = 0;
    u32 wr_cnt = writes;
    switch (op) {
    case 0x00: case 0x08: case 0x10: case 0x18: case 0x20: case 0x28: case 0x30:
        m = *p++;
        if (m >= 0xC0u) { v = R8(m); c.eip = op_eip + 2u; }
        else { PM_EA_FN(m, p, off); addr = ds_base + off; c.eip = op_eip + (u32)(p - ip); PM_RD8(addr, v); }
        r = alu8(op >> 3, v, R8(m >> 3));
        if (m >= 0xC0u) R8(m) = (u8)r; else PM_WR8(addr, r);
        c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    case 0x02: case 0x0A: case 0x12: case 0x1A: case 0x22: case 0x2A: case 0x32:
        m = *p++;
        if (m >= 0xC0u) { v = R8(m); c.eip = op_eip + 2u; }
        else { PM_EA_FN(m, p, off); addr = ds_base + off; c.eip = op_eip + (u32)(p - ip); PM_RD8(addr, v); }
        R8(m >> 3) = (u8)alu8(op >> 3, R8(m >> 3), v);
        c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    case 0x0F: {
        u32 op2 = *p++;
        if (op2 < 0x90u || op2 > 0x9Fu) return 0;
        m = *p++;
        r = cond(op2) ? 1u : 0u;
        if (m >= 0xC0u) { c.eip = op_eip + 3u; R8(m) = (u8)r; }
        else { PM_EA_FN(m, p, off); addr = ds_base + off; c.eip = op_eip + (u32)(p - ip); PM_WR8(addr, r); }
        c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    }
    case 0x60:
#if !defined(PM_EXACT_CPI3) && !defined(NO_FUSE_PUSHAD)
        if (ds_base == 0u && (ip[1] == 0x8Bu || ip[1] == 0xA1u) && pm_try_fuse_pushad(op_eip, ip))
            return 1;
#endif
        if (!pm_pushad(ds_base)) return 0;
        c.eip = op_eip + 1u; c.cycles += PM_CYC;
        return 1;
    case 0x61:
        if (!pm_popad(ds_base)) return 0;
        c.eip = op_eip + 1u; c.cycles += PM_CYC;
        return 1;
    case 0x68:
        v = ua_r32(p);
        r = rESP - 4u;
        PM_PUSH32(ds_base + r, v);
        rESP = r;
        c.eip = op_eip + 5u; c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    case 0x6A:
        v = (u32)(s32)(s8)*p;
        r = rESP - 4u;
        PM_PUSH32(ds_base + r, v);
        rESP = r;
        c.eip = op_eip + 2u; c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    case 0x69: case 0x6B: {
        m = *p++;
        if (m >= 0xC0u) v = R32(m);
        else { PM_EA_FN(m, p, off); addr = ds_base + off; PM_RD32(addr, v); }
        u32 imm = (op == 0x69u) ? ua_r32(p) : (u32)(s32)(s8)*p;
        p += (op == 0x69u) ? 4 : 1;
        c.eip = op_eip + (u32)(p - ip);
        R32(m >> 3) = imul32(v, imm);
        c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    }
    case 0x84:
        m = *p++;
        if (m >= 0xC0u) { v = R8(m); c.eip = op_eip + 2u; }
        else { PM_EA_FN(m, p, off); addr = ds_base + off; c.eip = op_eip + (u32)(p - ip); PM_RD8(addr, v); }
        logic8(v & R8(m >> 3));
        c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    case 0x86: {
        m = *p++;
        u32 rv = R8(m >> 3);
        if (m >= 0xC0u) { v = R8(m); R8(m) = (u8)rv; c.eip = op_eip + 2u; }
        else { PM_EA_FN(m, p, off); addr = ds_base + off; c.eip = op_eip + (u32)(p - ip); PM_RD8(addr, v); PM_WR8(addr, rv); }
        R8(m >> 3) = (u8)v;
        c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    }
    case 0x87: {
        m = *p++;
        u32 rv = R32(m >> 3);
        if (m >= 0xC0u) { v = R32(m); R32(m) = rv; c.eip = op_eip + 2u; }
        else { PM_EA_FN(m, p, off); addr = ds_base + off; c.eip = op_eip + (u32)(p - ip); PM_RD32(addr, v); PM_WR32(addr, rv); }
        R32(m >> 3) = v;
        c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    }
    case 0x8F:
        m = *p++;
        if (((m >> 3) & 7u) != 0u) return 0;
        PM_RD32(ds_base + rESP, v);
        rESP += 4u;
        if (m >= 0xC0u) { c.eip = op_eip + 2u; R32(m) = v; }
        else { PM_EA_FN(m, p, off); addr = ds_base + off; c.eip = op_eip + (u32)(p - ip); PM_WR32(addr, v); }
        c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
        v = rEAX; rEAX = R32(op); R32(op) = v;
        c.eip = op_eip + 1u; c.cycles += PM_CYC;
        return 1;
    case 0x98:
        rEAX = (u32)(s32)(s16)rAX;
        c.eip = op_eip + 1u; c.cycles += PM_CYC;
        return 1;
    case 0xA0:
        addr = ds_base + ua_r32(p);
        PM_RD8(addr, v);
        rAL = (u8)v;
        c.eip = op_eip + 5u; c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    case 0xA2:
        addr = ds_base + ua_r32(p);
        PM_WR8_VGA(addr, rAL);
        c.eip = op_eip + 5u; c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    case 0xA4: case 0xA5: case 0xA6: case 0xA7:
    case 0xAA: case 0xAB: case 0xAC: case 0xAD: case 0xAE: case 0xAF:
        sego = -1; op32 = 1; ad32 = 1;
        c.op_eip = op_eip; c.eip = op_eip + 1u; c.faulted = 0;
        PM_CYC_OUT(c.cycles + PM_CYC);
        string(op, 0u);
        if (c.faulted) return 2;
        c.cycles = PM_CYC_IN();
        return 1;
    case 0xC0: case 0xD0: case 0xD2: {
        m = *p++;
        u32 cnt;
        if (m >= 0xC0u) {
            v = R8(m);
            cnt = (op == 0xC0u) ? *p++ : (op == 0xD0u ? 1u : rCL);
            c.eip = op_eip + (u32)(p - ip);
        } else {
            PM_EA_FN(m, p, off); addr = ds_base + off;
            cnt = (op == 0xC0u) ? *p++ : (op == 0xD0u ? 1u : rCL);
            c.eip = op_eip + (u32)(p - ip);
            PM_RD8(addr, v);
        }
        r = shift(m >> 3, v, cnt, 8u);
        if (m >= 0xC0u) R8(m) = (u8)r; else PM_WR8(addr, r);
        c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    }
    case 0xC1: case 0xD1: case 0xD3: {
        m = *p++;
        u32 cnt;
        if (m >= 0xC0u) {
            v = R32(m);
            cnt = (op == 0xC1u) ? *p++ : (op == 0xD1u ? 1u : rCL);
            c.eip = op_eip + (u32)(p - ip);
        } else {
            PM_EA_FN(m, p, off); addr = ds_base + off;
            cnt = (op == 0xC1u) ? *p++ : (op == 0xD1u ? 1u : rCL);
            c.eip = op_eip + (u32)(p - ip);
            PM_RD32(addr, v);
        }
        r = shift32_fast(m >> 3, v, cnt);
        if (m >= 0xC0u) R32(m) = r; else PM_WR32(addr, r);
        c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    }
    case 0xC6:
        m = *p++;
        if (m >= 0xC0u) { R8(m) = *p++; c.eip = op_eip + 3u; }
        else { PM_EA_FN(m, p, off); addr = ds_base + off; v = *p++; c.eip = op_eip + (u32)(p - ip); PM_WR8_VGA(addr, v); }
        c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    case 0xC9:
        rESP = rEBP;
        PM_RD32(ds_base + rESP, rEBP);
        rESP += 4u;
        c.eip = op_eip + 1u; c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    case 0xE4: case 0xEC:
        v = (op == 0xE4u) ? *p : rDX;
        c.eip = op_eip + (op == 0xE4u ? 2u : 1u);
        c.op_eip = op_eip; PM_CYC_OUT(c.cycles + PM_CYC); writes = wr_cnt;
        rAL = in8(v);
        return 2;
    case 0xE6: case 0xEE:
        v = (op == 0xE6u) ? *p : rDX;
        c.eip = op_eip + (op == 0xE6u ? 2u : 1u);
        c.op_eip = op_eip; PM_CYC_OUT(c.cycles + PM_CYC); writes = wr_cnt;
        out8(v, rAL);
        return 2;
    case 0xF2: case 0xF3: {
        u32 op2 = *p++;
        if (op2 >= 0xA4u && op2 <= 0xAFu && op2 != 0xA8u && op2 != 0xA9u) {
            sego = -1; op32 = 1; ad32 = 1;
            c.op_eip = op_eip; c.eip = op_eip + 2u; c.faulted = 0;
            PM_CYC_OUT(c.cycles + PM_CYC * 2);
            string(op2, op);
            if (c.faulted) return 2;
            c.cycles = PM_CYC_IN();
            return 1;
        }
        if (op2 == 0x66u) {
            u32 op3 = *p++;
            if (op3 >= 0xA4u && op3 <= 0xAFu && op3 != 0xA8u && op3 != 0xA9u) {
                sego = -1; op32 = 0; ad32 = 1;
                c.op_eip = op_eip; c.eip = op_eip + 3u; c.faulted = 0;
                PM_CYC_OUT(c.cycles + PM_CYC + PM_CYC66);
                string(op3, op);
                if (c.faulted) return 2;
                c.cycles = PM_CYC_IN();
                return 1;
            }
        }
        return 0;
    }
    case 0xF6: {
        m = *p++;
        u32 subk = (m >> 3) & 7u;
        if (subk >= 4u) return 0;
        if (m >= 0xC0u) v = R8(m);
        else { PM_EA_FN(m, p, off); addr = ds_base + off; PM_RD8(addr, v); }
        if (subk <= 1u) {
            u32 imm = *p++;
            c.eip = op_eip + (u32)(p - ip);
            logic8(v & imm);
        } else if (subk == 2u) {
            c.eip = op_eip + (u32)(p - ip);
            if (m >= 0xC0u) R8(m) = (u8)~v; else PM_WR8(addr, ~v);
        } else {
            c.eip = op_eip + (u32)(p - ip);
            r = sub8(0, v, 0);
            c.fl = (c.fl & ~F_CF) | (v != 0u);
            if (m >= 0xC0u) R8(m) = (u8)r; else PM_WR8(addr, r);
        }
        c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    }
    case 0xF8: c.eip = op_eip + 1u; c.cycles += PM_CYC; c.fl &= ~F_CF; return 1;
    case 0xF9: c.eip = op_eip + 1u; c.cycles += PM_CYC; c.fl |=  F_CF; return 1;
    case 0xFA: c.eip = op_eip + 1u; c.cycles += PM_CYC; c.sys &= ~F_IF; return 1;
    case 0xFC: c.eip = op_eip + 1u; c.cycles += PM_CYC; c.sys &= ~F_DF; return 1;
    case 0xFD: c.eip = op_eip + 1u; c.cycles += PM_CYC; c.sys |=  F_DF; return 1;
    case 0xFE: {
        m = *p++;
        u32 subk = (m >> 3) & 7u;
        if (subk > 1u) return 0;
        if (m >= 0xC0u) {
            c.eip = op_eip + 2u;
            R8(m) = (u8)(subk == 0u ? inc8(R8(m)) : dec8(R8(m)));
        } else {
            PM_EA_FN(m, p, off); addr = ds_base + off;
            c.eip = op_eip + (u32)(p - ip);
            PM_RD8(addr, v);
            r = subk == 0u ? inc8(v) : dec8(v);
            PM_WR8(addr, r);
        }
        c.cycles += PM_CYC; writes = wr_cnt;
        return 1;
    }
    default:
        return 0;
    }
}

INLINE int pm_span_ok(u32 base, u32 len)
{
    return (base <= 0x9FFFCu && len <= 0xA0000u - base) ||
           (base >= 0x100000u && base <= RAM_BYTES && len <= RAM_BYTES - base);
}

static inline int pm_mem_eq(const u8 *a, const u8 *b, u32 n)
{
    u32 i = 0;
    for (; i + 4u <= n; i += 4u)
        if (ua_r32(a + i) != ua_r32(b + i)) return 0;
    for (; i < n; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

static int pm_match_masked(const u8 *ip, const u8 *tmpl, const u8 *mask, u32 n)
{
    for (u32 i = 0; i < n; i++)
        if ((mask[i >> 3] & (1u << (i & 7u))) && ip[i] != tmpl[i])
            return 0;
    return 1;
}



static const u8 msp_tmpl[221] = {
    0x56,0x57,0x55,0x83,0xEC,0x0C,0x89,0x44,0x24,0x08,0x89,0xD6,0x89,0xDF,0x39,0xCA,
    0x7D,0x27,0x48,0x8D,0x2C,0x95,0x00,0x00,0x00,0x00,0x89,0x04,0x24,0x39,0xFE,0x7F,
    0x18,0x8B,0x1C,0x24,0x89,0xF0,0x8B,0x95,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,0x00,
    0x00,0x46,0x83,0xC5,0x04,0x39,0xCE,0x7C,0xE4,0x8B,0x44,0x24,0x08,0x48,0x8D,0x2C,
    0xBD,0x00,0x00,0x00,0x00,0x89,0x44,0x24,0x04,0x3B,0x7C,0x24,0x1C,0x7E,0x1B,0x39,
    0xF7,0x7C,0x17,0x8B,0x5C,0x24,0x04,0x89,0xF8,0x8B,0x95,0x00,0x00,0x00,0x00,0xE8,
    0x00,0x00,0x00,0x00,0x83,0xED,0x04,0x4F,0xEB,0xDF,0x8B,0x54,0x24,0x1C,0x8B,0x6C,
    0x24,0x08,0x8D,0x04,0x8D,0x00,0x00,0x00,0x00,0x8D,0x34,0xB5,0x00,0x00,0x00,0x00,
    0x8D,0x14,0x95,0x00,0x00,0x00,0x00,0x39,0xF0,0x7D,0x10,0x39,0xD0,0x7F,0x0C,0x83,
    0xC0,0x04,0x41,0x89,0xA8,0x00,0x00,0x00,0x00,0xEB,0xEC,0x8B,0x74,0x24,0x1C,0x8B,
    0x44,0x24,0x08,0x8D,0x0C,0x8D,0x00,0x00,0x00,0x00,0x8D,0x3C,0xBD,0x00,0x00,0x00,
    0x00,0x8D,0x34,0xB5,0x00,0x00,0x00,0x00,0x39,0xFE,0x7E,0x18,0x39,0xCE,0x7C,0x14,
    0x8B,0x5C,0x24,0x1C,0x83,0xEE,0x04,0x4B,0x89,0x86,0x00,0x00,0x00,0x00,0x89,0x5C,
    0x24,0x1C,0xEB,0xE4,0x83,0xC4,0x0C,0x5D,0x5F,0x5E,0xC2,0x04,0x00,
};
static const u8 msp_mask[28] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0x10,0xFE,0xFF,0xFF,0xFF,0xFF,0x87,0xF0,0xFF,0xFF,0xFF,
    0xFF,0xFF,0x1F,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xC3,0xFF,0x1F,
};

static __attribute__((noinline)) int pm_init_msp_snap(u32 fn_eip, const u8 *fp)
{
    if (!pm_match_masked(fp, msp_tmpl, msp_mask, 221u))
        return 0;
    u32 sp0 = ua_r32(fp + 0x28);
    if (ua_r32(fp + 0x5B) != sp0 || ua_r32(fp + 0x95) != sp0 - 4u || ua_r32(fp + 0xCA) != sp0 + 4u)
        return 0;
    if ((sp0 & 3u) != 0u || sp0 < 0x100000u || sp0 + 800u > RAM_BYTES - 16u)
        return 0;
    if (!(sp0 + 800u <= fn_eip || fn_eip + 221u <= sp0))
        return 0;
    if (fn_eip + 225u > PM_CODE_GUARD_TOP) return 0;
    msp_span_a = sp0;
    msp_eip = fn_eip;
    if (fn_eip < c.wr_guard_lo) c.wr_guard_lo = fn_eip;
    if (fn_eip + 225u > c.wr_fast_lo) c.wr_fast_lo = fn_eip + 225u;
    return 1;
}

#if !defined(PM_EXACT_CPI3) && !defined(NO_FUSE_PUSHAD)
static const u8 tmap_col_tmpl[279] = {
    0x60,0x8B,0x2D,0x00,0x00,0x00,0x00,0x3B,0x2D,0x00,0x00,0x00,0x00,0x0F,0x8F,0x02,
    0x01,0x00,0x00,0x8D,0x7C,0xED,0x00,0x03,0xFD,0xC1,0xE7,0x03,0x8B,0x1D,0x00,0x00,
    0x00,0x00,0x8B,0xCB,0xC1,0xEB,0x02,0x03,0xFB,0x03,0x3D,0x00,0x00,0x00,0x00,0x83,
    0xE1,0x03,0xB8,0x01,0x00,0x00,0x00,0xD3,0xE0,0xBA,0xC5,0x03,0x00,0x00,0xEE,0xA1,
    0x00,0x00,0x00,0x00,0x40,0x2B,0xC5,0xA3,0x00,0x00,0x00,0x00,0x0F,0x88,0xC3,0x00,
    0x00,0x00,0xD1,0xE8,0xA3,0x00,0x00,0x00,0x00,0x8B,0x0D,0x00,0x00,0x00,0x00,0xA1,
    0x00,0x00,0x00,0x00,0x2B,0xC5,0xF7,0xE9,0x8B,0x2D,0x00,0x00,0x00,0x00,0x2B,0xE8,
    0xC1,0xE5,0x09,0x8B,0x35,0x00,0x00,0x00,0x00,0x8B,0x1D,0x00,0x00,0x00,0x00,0xC1,
    0xE3,0x09,0xB8,0x00,0x00,0x00,0x00,0x89,0x18,0xB8,0x00,0x00,0x00,0x00,0x89,0x18,
    0x8B,0xCD,0x03,0xEB,0xC1,0xE9,0x19,0x8B,0xD5,0x03,0xEB,0xC1,0xEA,0x19,0xA1,0x00,
    0x00,0x00,0x00,0x8B,0xD8,0x8A,0x04,0x0E,0x8A,0x1C,0x16,0x8A,0x00,0x8A,0x1B,0xF7,
    0x05,0x00,0x00,0x00,0x00,0xFE,0xFF,0xFF,0xFF,0x75,0x15,0x90,0x90,0x90,0x90,0xEB,
    0x42,0x90,0x90,0x90,0x87,0xDB,0x87,0xDB,0x87,0xDB,0x87,0xDB,0x87,0xDB,0x87,0xDB,
    0x8B,0xCD,0x81,0xC5,0x00,0x00,0x00,0x00,0x88,0x07,0xC1,0xE9,0x19,0x8B,0xD5,0x81,
    0xC5,0x00,0x00,0x00,0x00,0x88,0x5F,0x50,0xC1,0xEA,0x19,0x8A,0x04,0x0E,0x81,0xC7,
    0xA0,0x00,0x00,0x00,0x8A,0x1C,0x16,0xFF,0x0D,0x00,0x00,0x00,0x00,0x8A,0x00,0x8A,
    0x1B,0x75,0xCD,0xF7,0x05,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x74,0x06,0x90,
    0x90,0x90,0x90,0x88,0x07,0x61,0xC3,
};
static const u8 tmap_col_mask[35] = {
    0x87,0xE1,0xFF,0x3F,0xFC,0x87,0xFF,0xFF,0xF0,0xF0,0x1F,0x86,0xF0,0xC3,0x1F,0x86,
    0x87,0xC3,0xFF,0x7F,0xF8,0xFF,0xE1,0xFF,0xFF,0xFF,0x0F,0xFF,0xE1,0xFF,0xFF,0xE1,
    0x1F,0xFE,0x7F,
};
static const u8 tmap_spn_tmpl[617] = {
    0x60,0xA1,0x00,0x00,0x00,0x00,0xA3,0x00,0x00,0x00,0x00,0x8B,0xD8,0x83,0xE3,0x03,
    0x89,0x1D,0x00,0x00,0x00,0x00,0x89,0x1D,0x00,0x00,0x00,0x00,0xC1,0xE8,0x02,0x8B,
    0x2D,0x00,0x00,0x00,0x00,0x8D,0x7C,0xED,0x00,0x03,0xFD,0xC1,0xE7,0x03,0x03,0xF8,
    0x03,0x3D,0x00,0x00,0x00,0x00,0x89,0x3D,0x00,0x00,0x00,0x00,0x8B,0x1D,0x00,0x00,
    0x00,0x00,0xC1,0xE3,0x0A,0x81,0xE3,0x00,0x00,0xFF,0xFF,0xA1,0x00,0x00,0x00,0x00,
    0xC1,0xE8,0x06,0x25,0xFF,0xFF,0x00,0x00,0x0B,0xD8,0x89,0x1D,0x00,0x00,0x00,0x00,
    0x8B,0x1D,0x00,0x00,0x00,0x00,0xC1,0xE3,0x0A,0x81,0xE3,0x00,0x00,0xFF,0xFF,0xA1,
    0x00,0x00,0x00,0x00,0xC1,0xE8,0x06,0x25,0xFF,0xFF,0x00,0x00,0x0B,0xD8,0x89,0x1D,
    0x00,0x00,0x00,0x00,0xC1,0xE3,0x02,0x89,0x1D,0x00,0x00,0x00,0x00,0xB8,0x00,0x00,
    0x00,0x00,0x89,0x18,0xB8,0x00,0x00,0x00,0x00,0x89,0x18,0x8B,0x0D,0x00,0x00,0x00,
    0x00,0xB8,0x01,0x00,0x00,0x00,0xD3,0xE0,0xBA,0xC5,0x03,0x00,0x00,0xEE,0xA1,0x00,
    0x00,0x00,0x00,0x3B,0x05,0x00,0x00,0x00,0x00,0x0F,0x82,0xA8,0x01,0x00,0x00,0x2B,
    0x05,0x00,0x00,0x00,0x00,0x0F,0x88,0x57,0x01,0x00,0x00,0xC1,0xE8,0x02,0xA3,0x00,
    0x00,0x00,0x00,0x48,0x0F,0x88,0xBE,0x00,0x00,0x00,0xD1,0xE8,0x8B,0x1D,0x00,0x00,
    0x00,0x00,0xC1,0xEB,0x02,0x3B,0x1D,0x00,0x00,0x00,0x00,0x0F,0x84,0xA7,0x00,0x00,
    0x00,0x89,0x1D,0x00,0x00,0x00,0x00,0x43,0xD1,0xEB,0x40,0x2B,0xC3,0x0F,0x88,0x1F,
    0x01,0x00,0x00,0xA3,0x00,0x00,0x00,0x00,0xA1,0x00,0x00,0x00,0x00,0x8B,0xD8,0x8B,
    0x35,0x00,0x00,0x00,0x00,0x8B,0x3D,0x00,0x00,0x00,0x00,0x8B,0x2D,0x00,0x00,0x00,
    0x00,0xF7,0x05,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x74,0x26,0x90,0x90,0x90,
    0x90,0x0F,0xA4,0xE9,0x16,0x0F,0xA4,0xE9,0x06,0x03,0x2D,0x00,0x00,0x00,0x00,0x81,
    0xE1,0xFF,0x0F,0x00,0x00,0x8A,0x04,0x0E,0x8A,0x10,0x88,0x17,0x47,0x0F,0x84,0xCF,
    0x00,0x00,0x00,0x0F,0xA4,0xE9,0x16,0x0F,0xA4,0xE9,0x06,0x03,0x2D,0x00,0x00,0x00,
    0x00,0x81,0xE1,0xFF,0x0F,0x00,0x00,0x0F,0xA4,0xEA,0x16,0x0F,0xA4,0xEA,0x06,0x03,
    0x2D,0x00,0x00,0x00,0x00,0x81,0xE2,0xFF,0x0F,0x00,0x00,0x8A,0x04,0x0E,0x8A,0x1C,
    0x16,0x8A,0x10,0xF7,0x05,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0x75,0x41,0x90,
    0x90,0x90,0x90,0xEB,0x7B,0x90,0x90,0x90,0xA1,0x00,0x00,0x00,0x00,0x8B,0x35,0x00,
    0x00,0x00,0x00,0x8B,0x3D,0x00,0x00,0x00,0x00,0x8B,0x2D,0x00,0x00,0x00,0x00,0x0F,
    0xA4,0xE9,0x16,0x0F,0xA4,0xE9,0x06,0x81,0xE1,0xFF,0x0F,0x00,0x00,0x8A,0x04,0x0E,
    0x8A,0x10,0x88,0x17,0xEB,0x5C,0x90,0x90,0x90,0x87,0xDB,0x87,0xDB,0x87,0xDB,0x90,
    0x0F,0xA4,0xE9,0x16,0x8A,0x33,0x0F,0xA4,0xE9,0x06,0x81,0xC5,0x00,0x00,0x00,0x00,
    0x81,0xE1,0xFF,0x0F,0x00,0x00,0x66,0x89,0x17,0x0F,0xA4,0xEA,0x16,0x83,0xC7,0x02,
    0x0F,0xA4,0xEA,0x06,0x81,0xC5,0x00,0x00,0x00,0x00,0x81,0xE2,0xFF,0x0F,0x00,0x00,
    0x8A,0x04,0x0E,0x8A,0x1C,0x16,0xFF,0x0D,0x00,0x00,0x00,0x00,0x8A,0x10,0x75,0xC0,
    0xF7,0x05,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x75,0x06,0x90,0x90,0x90,0x90,
    0x88,0x17,0x8B,0x0D,0x00,0x00,0x00,0x00,0x41,0x83,0xE1,0x03,0x75,0x0A,0x90,0x90,
    0x90,0x90,0xFF,0x05,0x00,0x00,0x00,0x00,0x3B,0x0D,0x00,0x00,0x00,0x00,0x74,0x27,
    0x90,0x90,0x90,0x90,0x89,0x0D,0x00,0x00,0x00,0x00,0x8B,0x1D,0x00,0x00,0x00,0x00,
    0x03,0x1D,0x00,0x00,0x00,0x00,0x89,0x1D,0x00,0x00,0x00,0x00,0xFF,0x05,0x00,0x00,
    0x00,0x00,0xE9,0x3A,0xFE,0xFF,0xFF,0x61,0xC3,
};
static const u8 tmap_spn_mask[78] = {
    0x43,0xF8,0xC3,0xF0,0xE1,0xFF,0xC3,0x30,0xFC,0x0F,0xFF,0x0F,0xC3,0xFF,0xF0,0xFF,
    0xF0,0x21,0x1C,0x1E,0xFE,0x7F,0x18,0xFE,0xE1,0x7F,0xF8,0x3F,0x7C,0xF8,0x87,0xFF,
    0x0F,0xE1,0x61,0x18,0x86,0xFF,0xFF,0x87,0xFF,0xFF,0xFF,0x1F,0xFE,0xFF,0xE1,0xFF,
    0x1F,0xFE,0xFF,0x61,0x18,0x86,0xFF,0xFF,0xFF,0xFF,0xFF,0x0F,0xFF,0xFF,0x3F,0xFC,
    0xFF,0xF0,0xC3,0xFF,0x0F,0xFF,0x0F,0xC3,0x3F,0x0C,0xC3,0x30,0xFC,0x01,
};

INLINE void pm_write_pushad_raw(u8 *sp, u32 esp)
{
    if (__builtin_expect(((pm_uptr_t)sp & 3u) == 0u, 1)) {
        u32 *d = (u32 *)(void *)sp;
        d[7] = c.reg[0].d; d[6] = c.reg[1].d;
        d[5] = c.reg[2].d; d[4] = c.reg[3].d;
        d[3] = esp;        d[2] = c.reg[5].d;
        d[1] = c.reg[6].d; d[0] = c.reg[7].d;
    } else {
        ua_w32(sp + 28u, c.reg[0].d); ua_w32(sp + 24u, c.reg[1].d);
        ua_w32(sp + 20u, c.reg[2].d); ua_w32(sp + 16u, c.reg[3].d);
        ua_w32(sp + 12u, esp);        ua_w32(sp +  8u, c.reg[5].d);
        ua_w32(sp +  4u, c.reg[6].d); ua_w32(sp +  0u, c.reg[7].d);
    }
}

static inline int pm_disjoint4(u32 a, u32 b)
{
    return a + 4u <= b || b + 4u <= a;
}

static struct {
    u32 *yl, *yh, *x, *dv, *lc, *pc, *isc, *cy, *tm, *src, *cm;
    int aligned_var;
} tmap_col_p;

static struct {
    u32 *s_58, *s_60, *s_64, *s_68, *s_6c, *s_70, *s_74, *s_78, *s_7c, *s_80;
    u32 *x1, *x2, *y, *dv, *yfrac, *xfrac, *ystep, *xstep, *cm, *src;
    int aligned_var;
} tmap_spn_p;

static __attribute__((noinline)) int pm_init_col_snap(u32 op_eip, const u8 *ip)
{
    if (!pm_match_masked(ip, tmap_col_tmpl, tmap_col_mask, 279u))
        return 0;
    u32 ad[11] = {
        ua_r32(ip + 0x003), ua_r32(ip + 0x009), ua_r32(ip + 0x01E),
        ua_r32(ip + 0x02B), ua_r32(ip + 0x048), ua_r32(ip + 0x055),
        ua_r32(ip + 0x05B), ua_r32(ip + 0x060), ua_r32(ip + 0x06A),
        ua_r32(ip + 0x075), ua_r32(ip + 0x09F)
    };
    if (ua_r32(ip + 0x040) != ad[1] || ua_r32(ip + 0x07B) != ad[6] ||
        ua_r32(ip + 0x083) != op_eip + 0x0D4u || ua_r32(ip + 0x08A) != op_eip + 0x0E1u ||
        ua_r32(ip + 0x0B1) != ad[4] || ua_r32(ip + 0x0F9) != ad[5] ||
        ua_r32(ip + 0x105) != ad[4] || !pm_disjoint4(ad[4], ad[5]))
        return 0;
    u32 lo = op_eip, hi = op_eip + 279u, or_align = 0;
    for (int k = 0; k < 11; k++) {
        if (!PM_IS_XRAM4(ad[k])) return 0;
        if (ad[k] + 4u > op_eip && ad[k] < op_eip + 279u) return 0;
        if (k != 4 && k != 5 && (!pm_disjoint4(ad[k], ad[4]) || !pm_disjoint4(ad[k], ad[5])))
            return 0;
        if (ad[k] < lo) lo = ad[k];
        if (ad[k] + 4u > hi) hi = ad[k] + 4u;
        or_align |= ad[k];
    }
    if ((or_align & 3u) != 0u)
        return 0;
    u32 wlo = op_eip + 0x0D4u, whi = op_eip + 0x0E5u;
    if (ad[4] < wlo) wlo = ad[4];
    if (ad[4] + 4u > whi) whi = ad[4] + 4u;
    if (ad[5] < wlo) wlo = ad[5];
    if (ad[5] + 4u > whi) whi = ad[5] + 4u;
    if (op_eip + 283u > PM_CODE_GUARD_TOP) return 0;
    u8 *ram = mem;
    tmap_col_p.yl  = (u32 *)(void *)(ram + ad[0]);
    tmap_col_p.yh  = (u32 *)(void *)(ram + ad[1]);
    tmap_col_p.x   = (u32 *)(void *)(ram + ad[2]);
    tmap_col_p.dv  = (u32 *)(void *)(ram + ad[3]);
    tmap_col_p.lc  = (u32 *)(void *)(ram + ad[4]);
    tmap_col_p.pc  = (u32 *)(void *)(ram + ad[5]);
    tmap_col_p.isc = (u32 *)(void *)(ram + ad[6]);
    tmap_col_p.cy  = (u32 *)(void *)(ram + ad[7]);
    tmap_col_p.tm  = (u32 *)(void *)(ram + ad[8]);
    tmap_col_p.src = (u32 *)(void *)(ram + ad[9]);
    tmap_col_p.cm  = (u32 *)(void *)(ram + ad[10]);
    tmap_col_lo = lo; tmap_col_hi = hi;
    tmap_col_wlo = wlo; tmap_col_whi = whi;
    tmap_col_eip = op_eip;
    if (op_eip < c.wr_guard_lo) c.wr_guard_lo = op_eip;
    if (op_eip + 283u > c.wr_fast_lo) c.wr_fast_lo = op_eip + 283u;
    return 1;
}

static __attribute__((noinline)) int pm_init_spn_snap(u32 op_eip, const u8 *ip)
{
    if (!pm_match_masked(ip, tmap_spn_tmpl, tmap_spn_mask, 617u))
        return 0;
    u32 sc_a[10] = {
        ua_r32(ip + 0x104), ua_r32(ip + 0x038), ua_r32(ip + 0x012),
        ua_r32(ip + 0x018), ua_r32(ip + 0x05C), ua_r32(ip + 0x080),
        ua_r32(ip + 0x089), ua_r32(ip + 0x007), ua_r32(ip + 0x0F3),
        ua_r32(ip + 0x0CF)
    };
    u32 in_a[10] = {
        ua_r32(ip + 0x002), ua_r32(ip + 0x0AF), ua_r32(ip + 0x021),
        ua_r32(ip + 0x032), ua_r32(ip + 0x03E), ua_r32(ip + 0x04C),
        ua_r32(ip + 0x062), ua_r32(ip + 0x070), ua_r32(ip + 0x109),
        ua_r32(ip + 0x111)
    };
    if (ua_r32(ip + 0x08E) != op_eip + 0x1DCu || ua_r32(ip + 0x095) != op_eip + 0x1F6u ||
        ua_r32(ip + 0x09D) != sc_a[3] || ua_r32(ip + 0x0B5) != sc_a[7] ||
        ua_r32(ip + 0x0C1) != sc_a[3] || ua_r32(ip + 0x0DE) != sc_a[7] ||
        ua_r32(ip + 0x0E7) != sc_a[9] || ua_r32(ip + 0x117) != sc_a[1] ||
        ua_r32(ip + 0x11D) != sc_a[4] || ua_r32(ip + 0x123) != sc_a[8] ||
        ua_r32(ip + 0x13B) != sc_a[6] || ua_r32(ip + 0x15D) != sc_a[6] ||
        ua_r32(ip + 0x171) != sc_a[6] || ua_r32(ip + 0x185) != sc_a[0] ||
        ua_r32(ip + 0x199) != in_a[8] || ua_r32(ip + 0x19F) != in_a[9] ||
        ua_r32(ip + 0x1A5) != sc_a[1] || ua_r32(ip + 0x1AB) != sc_a[4] ||
        ua_r32(ip + 0x208) != sc_a[0] || ua_r32(ip + 0x212) != sc_a[9] ||
        ua_r32(ip + 0x224) != sc_a[3] || ua_r32(ip + 0x234) != sc_a[1] ||
        ua_r32(ip + 0x23A) != sc_a[2] || ua_r32(ip + 0x246) != sc_a[3] ||
        ua_r32(ip + 0x24C) != sc_a[4] || ua_r32(ip + 0x252) != sc_a[5] ||
        ua_r32(ip + 0x258) != sc_a[4] || ua_r32(ip + 0x25E) != sc_a[7])
        return 0;
    u32 lo = op_eip, hi = op_eip + 617u, or_align = 0;
    u32 wlo = op_eip + 0x1DCu, whi = op_eip + 0x1FAu;
    for (int k = 0; k < 10; k++) {
        if (!PM_IS_XRAM4(sc_a[k]) || !PM_IS_XRAM4(in_a[k])) return 0;
        if (sc_a[k] + 4u > op_eip && sc_a[k] < op_eip + 617u) return 0;
        for (int j = k + 1; j < 10; j++)
            if (!pm_disjoint4(sc_a[k], sc_a[j])) return 0;
        for (int j = 0; j < 10; j++)
            if (!pm_disjoint4(sc_a[k], in_a[j])) return 0;
        if (sc_a[k] < lo) lo = sc_a[k];
        if (sc_a[k] + 4u > hi) hi = sc_a[k] + 4u;
        if (in_a[k] < lo) lo = in_a[k];
        if (in_a[k] + 4u > hi) hi = in_a[k] + 4u;
        if (sc_a[k] < wlo) wlo = sc_a[k];
        if (sc_a[k] + 4u > whi) whi = sc_a[k] + 4u;
        or_align |= sc_a[k] | in_a[k];
    }
    if ((or_align & 3u) != 0u)
        return 0;
    if (op_eip + 621u > PM_CODE_GUARD_TOP) return 0;
    u8 *ram = mem;
    tmap_spn_p.s_58 = (u32 *)(void *)(ram + sc_a[0]);
    tmap_spn_p.s_60 = (u32 *)(void *)(ram + sc_a[1]);
    tmap_spn_p.s_64 = (u32 *)(void *)(ram + sc_a[2]);
    tmap_spn_p.s_68 = (u32 *)(void *)(ram + sc_a[3]);
    tmap_spn_p.s_6c = (u32 *)(void *)(ram + sc_a[4]);
    tmap_spn_p.s_70 = (u32 *)(void *)(ram + sc_a[5]);
    tmap_spn_p.s_74 = (u32 *)(void *)(ram + sc_a[6]);
    tmap_spn_p.s_78 = (u32 *)(void *)(ram + sc_a[7]);
    tmap_spn_p.s_7c = (u32 *)(void *)(ram + sc_a[8]);
    tmap_spn_p.s_80 = (u32 *)(void *)(ram + sc_a[9]);
    tmap_spn_p.x1    = (u32 *)(void *)(ram + in_a[0]);
    tmap_spn_p.x2    = (u32 *)(void *)(ram + in_a[1]);
    tmap_spn_p.y     = (u32 *)(void *)(ram + in_a[2]);
    tmap_spn_p.dv    = (u32 *)(void *)(ram + in_a[3]);
    tmap_spn_p.yfrac = (u32 *)(void *)(ram + in_a[4]);
    tmap_spn_p.xfrac = (u32 *)(void *)(ram + in_a[5]);
    tmap_spn_p.ystep = (u32 *)(void *)(ram + in_a[6]);
    tmap_spn_p.xstep = (u32 *)(void *)(ram + in_a[7]);
    tmap_spn_p.cm    = (u32 *)(void *)(ram + in_a[8]);
    tmap_spn_p.src   = (u32 *)(void *)(ram + in_a[9]);
    tmap_spn_lo = lo; tmap_spn_hi = hi;
    tmap_spn_wlo = wlo; tmap_spn_whi = whi;
    tmap_spn_eip = op_eip;
    if (op_eip < c.wr_guard_lo) c.wr_guard_lo = op_eip;
    if (op_eip + 621u > c.wr_fast_lo) c.wr_fast_lo = op_eip + 621u;
    return 1;
}

static __attribute__((noinline)) int pm_try_fuse_pushad(u32 op_eip, const u8 *ip)
{
    if (seq_i != 2u || vga_fast_lut[1] == 0)
        return 0;
    u32 esp = rESP;
    if ((u32)(esp - 0x100020u) >= (RAM_BYTES - 0x100024u))
        return 0;
    u8 * const ram = mem;
    s32 end_cyc = (s32)((u32)run_end << PM_CLK_SH);

    /* ---- Full Mode X R_DrawColumn (279 B: PUSHAD .. POPAD; RET) ---- */
    if (ip[1] == 0x8Bu && ip[2] == 0x2Du) {
        if ((u32)(op_eip - 0x100000u) >= (RAM_BYTES - 0x100120u))
            return 0;
        if (__builtin_expect(op_eip != tmap_col_eip, 0)) {
            if (!pm_init_col_snap(op_eip, ip))
                return 0;
        }
        if (!(esp - 32u >= tmap_col_hi || esp + 4u <= tmap_col_lo))
            return 0;
        u32 yl = *tmap_col_p.yl, yh = *tmap_col_p.yh;
        if ((s32)yl > (s32)yh) {
            if (c.cycles + 6 * PM_CYC > end_cyc) return 0;
            pm_write_pushad_raw(ram + esp - 32u, esp);
            (void)sub32(yl, yh, 0u);
            c.eip = ((esp & 3u) == 0u) ? *(const u32 *)(const void *)(ram + esp) : ua_r32(ram + esp);
            rESP = esp + 4u;
            c.cycles += 6 * PM_CYC;
            return 1;
        }
        if (yl >= 200u || yh >= 200u)
            return 0;
        u32 count = yh - yl + 1u, half = count >> 1;
        s32 est_cyc = (half == 0u)
            ? (66 * PM_CYC)
            : (s32)((56u + 5u * (count & 1u)) * (u32)PM_CYC + half * (u32)PM_FUSE_COL);
        if (c.cycles + est_cyc > end_cyc)
            return 0;
        u32 x = *tmap_col_p.x, dv = *tmap_col_p.dv;
        u32 edi0 = yl * 80u + (x >> 2) + dv;
        if (edi0 < 0xA0000u || edi0 + (count - 1u) * 80u >= 0xB0000u)
            return 0;
        u32 esi = *tmap_col_p.src, ea_hi = *tmap_col_p.cm & 0xFFFFFF00u;
        if (!pm_span_ok(esi, 128u) || !pm_span_ok(ea_hi, 256u) ||
            !(esi >= tmap_col_whi || esi + 128u <= tmap_col_wlo) ||
            !(ea_hi >= tmap_col_whi || ea_hi + 256u <= tmap_col_wlo) ||
            !(esp - 32u >= esi + 128u || esp <= esi) ||
            !(esp - 32u >= ea_hi + 256u || esp <= ea_hi))
            return 0;

        u32 wr_cnt = writes;
        pm_write_pushad_raw(ram + esp - 32u, esp);
        u8 *vp = vram[x & 3u];
        seq[2] = (u8)(1u << (x & 3u));
        vga_single_ptr = vp;
        wr_cnt++;

        u32 *p_lc = tmap_col_p.lc, *p_pc = tmap_col_p.pc;
        wr_cnt += (*p_lc != count) + (*p_pc != half);
        *p_lc = count;
        *p_pc = 0u;

        u32 iscale = *tmap_col_p.isc, step = iscale << 9;
        PM_WR32_RAM(ram + op_eip + 0x0D4u, step);
        PM_WR32_RAM(ram + op_eip + 0x0E1u, step);

        u32 ebp = (*tmap_col_p.tm - (*tmap_col_p.cy - yl) * iscale) << 9;
        u32 vo = edi0 - 0xA0000u;
        pm_mark_vdirty_span(vo >> 8, (vo + (count - 1u) * 80u) >> 8);
        u8 *vpx = vp + vo;
        const u8 *tex = ram + esi, *cma = ram + ea_hi;
        u32 i = 0;
        for (; i + 4u <= count; i += 4u, vpx += 320) {
            __builtin_prefetch(vpx + 320, 1, 0);
            u8 p0 = cma[tex[ebp >> 25]]; ebp += step;
            u8 p1 = cma[tex[ebp >> 25]]; ebp += step;
            u8 p2 = cma[tex[ebp >> 25]]; ebp += step;
            u8 p3 = cma[tex[ebp >> 25]]; ebp += step;
            vpx[0]   = p0;
            vpx[80]  = p1;
            vpx[160] = p2;
            vpx[240] = p3;
        }
        for (; i < count; i++, vpx += 80) {
            vpx[0] = cma[tex[ebp >> 25]];
            ebp += step;
        }
        wr_cnt += 3u * half + (count & 1u);
        (void)logic32(count & 1u);
        c.eip = ((esp & 3u) == 0u) ? *(const u32 *)(const void *)(ram + esp) : ua_r32(ram + esp);
        rESP = esp + 4u;
        c.cycles += est_cyc;
        writes = wr_cnt;
        return 1;
    }

    /* ---- Full Mode X R_DrawSpan (617 B: PUSHAD .. POPAD; RET) ---- */
    if (ip[1] == 0xA1u && ip[6] == 0xA3u) {
        if ((u32)(op_eip - 0x100000u) >= (RAM_BYTES - 0x100270u))
            return 0;
        if (__builtin_expect(op_eip != tmap_spn_eip, 0)) {
            if (!pm_init_spn_snap(op_eip, ip))
                return 0;
        }
        if (!(esp - 32u >= tmap_spn_hi || esp + 4u <= tmap_spn_lo))
            return 0;
        u32 x1 = *tmap_spn_p.x1, x2 = *tmap_spn_p.x2;
        u32 y  = *tmap_spn_p.y,  dv = *tmap_spn_p.dv;
        if (x1 > x2 || x2 >= 320u || y >= 200u)
            return 0;
        u32 edi0 = y * 80u + (x1 >> 2) + dv;
        u32 edi_max = y * 80u + (x2 >> 2) + dv;
        if (edi0 < 0xA0000u || edi_max >= 0xB0000u)
            return 0;
        u32 esi = *tmap_spn_p.src, ea_hi = *tmap_spn_p.cm & 0xFFFFFF00u;
        if (!pm_span_ok(esi, 4096u) || !pm_span_ok(ea_hi, 256u) ||
            !(esi >= tmap_spn_whi || esi + 4096u <= tmap_spn_wlo) ||
            !(ea_hi >= tmap_spn_whi || ea_hi + 256u <= tmap_spn_wlo) ||
            !(esp - 32u >= esi + 4096u || esp <= esi) ||
            !(esp - 32u >= ea_hi + 256u || esp <= ea_hi))
            return 0;

        u32 pfrac  = ((*tmap_spn_p.yfrac << 10) & 0xFFFF0000u) | ((*tmap_spn_p.xfrac >> 6) & 0xFFFFu);
        u32 pstep  = ((*tmap_spn_p.ystep << 10) & 0xFFFF0000u) | ((*tmap_spn_p.xstep >> 6) & 0xFFFFu);
        u32 pstep4 = pstep << 2;

        u32 m_58 = *tmap_spn_p.s_58, m_7c = *tmap_spn_p.s_7c, m_80 = *tmap_spn_p.s_80;
        u32 m_78 = x1, m_64 = x1 & 3u, m_68 = m_64, m_60 = edi0, m_6c = pfrac;
        u32 last_seq2 = 0, cmp_a = 0, cmp_b = 0;
        s32 est_cyc = 38 * PM_CYC;
        for (;;) {
            last_seq2 = 1u << m_68;
            cmp_a = x2; cmp_b = m_78;
            if (x2 < m_78) {
                est_cyc += 9 * PM_CYC;
                break;
            }
            est_cyc += 9 * PM_CYC;
            u32 eax_s = x2 - m_68;
            if ((s32)eax_s >= 0) {
                u32 ep = eax_s >> 2;
                m_80 = ep;
                est_cyc += 4 * PM_CYC;
                if (ep == 0u) {
                    est_cyc += 11 * PM_CYC;
                } else {
                    u32 spx = m_78 >> 2;
                    est_cyc += 5 * PM_CYC;
                    if (spx == ep) {
                        est_cyc += 11 * PM_CYC;
                    } else {
                        m_7c = spx;
                        u32 sc = (((ep - 1u) >> 1) + 1u) - ((spx + 1u) >> 1);
                        m_58 = 0u;
                        est_cyc += (29 + ((spx & 1u) ? 13 : 0) + ((ep & 1u) == 0u ? 5 : 0)) * PM_CYC;
                        if (sc == 0u) est_cyc += 5 * PM_CYC;
                        else          est_cyc += (s32)(sc * (u32)PM_FUSE_SPN);
                    }
                }
            }
            u32 nxt = (m_68 + 1u) & 3u;
            est_cyc += (6 + (nxt == 0u ? 5 : 0)) * PM_CYC;
            if (nxt == 0u) m_60++;
            cmp_a = nxt; cmp_b = m_64;
            if (nxt == m_64) {
                est_cyc += 2 * PM_CYC;
                break;
            }
            est_cyc += 10 * PM_CYC;
            m_68 = nxt;
            m_6c += pstep;
            m_78++;
        }
        if (c.cycles + est_cyc > end_cyc)
            return 0;

        pm_write_pushad_raw(ram + esp - 32u, esp);
        ua_w32(ram + op_eip + 0x1DCu, pstep4);
        ua_w32(ram + op_eip + 0x1F6u, pstep4);

        *tmap_spn_p.s_58 = m_58; *tmap_spn_p.s_60 = m_60;
        *tmap_spn_p.s_64 = m_64; *tmap_spn_p.s_68 = m_68;
        *tmap_spn_p.s_6c = m_6c; *tmap_spn_p.s_70 = pstep;
        *tmap_spn_p.s_74 = pstep4; *tmap_spn_p.s_78 = m_78;
        *tmap_spn_p.s_7c = m_7c; *tmap_spn_p.s_80 = m_80;

        const u8 *tex = ram + esi, *cma = ram + ea_hi;
        u32 n_planes = (x2 - x1 < 3u) ? (x2 - x1 + 1u) : 4u;
        for (u32 k = 0; k < n_planes; k++) {
            u32 cx = x1 + k;
            u32 n_px = ((x2 - cx) >> 2) + 1u;
            u32 vo = (y * 80u + (cx >> 2) + dv) - 0xA0000u;
            u8 *vp = vram[cx & 3u] + vo;
            vdirty[vo >> 8] = 1;
            vdirty[(vo + n_px - 1u) >> 8] = 1;
            u32 ebp = pfrac + k * pstep;
            u32 i = 0;
            for (; i + 4u <= n_px; i += 4u) {
                u32 i0 = ((ebp >> 4) & 0xFC0u) | (ebp >> 26); ebp += pstep4;
                u32 i1 = ((ebp >> 4) & 0xFC0u) | (ebp >> 26); ebp += pstep4;
                u32 i2 = ((ebp >> 4) & 0xFC0u) | (ebp >> 26); ebp += pstep4;
                u32 i3 = ((ebp >> 4) & 0xFC0u) | (ebp >> 26); ebp += pstep4;
                vp[i]      = cma[tex[i0]];
                vp[i + 1u] = cma[tex[i1]];
                vp[i + 2u] = cma[tex[i2]];
                vp[i + 3u] = cma[tex[i3]];
            }
            for (; i < n_px; i++) {
                u32 i0 = ((ebp >> 4) & 0xFC0u) | (ebp >> 26); ebp += pstep4;
                vp[i] = cma[tex[i0]];
            }
        }
        seq[2] = (u8)last_seq2;
        vga_single_ptr = vga_fast_lut[last_seq2 & 15u];
        (void)sub32(cmp_a, cmp_b, 0u);
        c.eip = ((esp & 3u) == 0u) ? *(const u32 *)(const void *)(ram + esp) : ua_r32(ram + esp);
        rESP = esp + 4u;
        c.cycles += est_cyc;
        writes += (x2 - x1 + 1u) + n_planes;
        return 1;
    }
    return 0;
}
#endif

/* ---- Watcom 386 Call-Target, R_RenderSegLoop, R_MapPlane & R_DrawVisSprite Fusion ---- */
#if !defined(PM_EXACT_CPI3) && !defined(NO_CALL_FUSE)
static u32 pos_eip = 0xFFFFFFFFu, fdiv_eip = 0xFFFFFFFFu;
static u32 wcl_eip = 0xFFFFFFFFu, getcol_eip = 0xFFFFFFFFu;
static u32 mcol_eip = 0xFFFFFFFFu, segfn_eip = 0xFFFFFFFFu;
static u32 mapplane_eip = 0xFFFFFFFFu, visspr63_eip = 0xFFFFFFFFu;
static u32 rpos1_eip = 0xFFFFFFFFu, rnode_eip = 0xFFFFFFFFu;
static u32 pta_eip = 0xFFFFFFFFu, outp_eip = 0xFFFFFFFFu;
#ifndef NO_TRT_IDLE
static u32 trt_eip = 0xFFFFFFFFu, trt_tic_a, trt_gtic_a, trt_last_tic, trt_last_gtic, trt_spin_cnt;
static s32 trt_last_end;
#endif
#endif

static __attribute__((noinline)) void pm_inval_code_snaps(void)
{
    tmap_col_eip = 0xFFFFFFFFu;
    tmap_spn_eip = 0xFFFFFFFFu;
    msp_eip      = 0xFFFFFFFFu;
#if !defined(PM_EXACT_CPI3) && !defined(NO_CALL_FUSE)
    pos_eip      = 0xFFFFFFFFu;
    fdiv_eip     = 0xFFFFFFFFu;
    wcl_eip      = 0xFFFFFFFFu;
    getcol_eip   = 0xFFFFFFFFu;
    mcol_eip     = 0xFFFFFFFFu;
    segfn_eip    = 0xFFFFFFFFu;
    mapplane_eip = 0xFFFFFFFFu;
    visspr63_eip = 0xFFFFFFFFu;
    rpos1_eip    = 0xFFFFFFFFu;
    rnode_eip    = 0xFFFFFFFFu;
    pta_eip      = 0xFFFFFFFFu;
    outp_eip     = 0xFFFFFFFFu;
#ifndef NO_TRT_IDLE
    trt_eip      = 0xFFFFFFFFu;
    trt_spin_cnt = 0u;
#endif
#endif
    c.wr_guard_lo  = 0xFFFFFFFFu;
    c.wr_fast_lo   = 0x100000u;
}

#if !defined(PM_EXACT_CPI3) && !defined(NO_CALL_FUSE)

static void pm_guard_code(u32 lo, u32 hi)
{
    if (lo < c.wr_guard_lo) c.wr_guard_lo = lo;
    if (hi > c.wr_fast_lo)  c.wr_fast_lo  = hi;
}

static struct {
    u32 *numlumps, *lumpcache;
    u32 zct_ret;
} wcl_p;

static struct {
    u32 *wmask, *clump, *cofs, *comp;
    u32 wcl_target;
} getcol_p;

static struct {
    u32 *dc_yl, *dc_yh, *dc_texmid, *dc_x, *dc_src, *colfunc;
    u32 *spryscale, *sprtopscreen, *mfloorclip, *mceilingclip;
} mcol_p;

static struct {
    u32 *rw_x, *rw_stopx, *topfrac, *topstep, *bottomfrac, *bottomstep;
    u32 *rw_scale, *rw_scalestep, *markceiling, *markfloor, *segtextured;
    u32 *ceilingplane, *floorplane, *rw_centerangle, *rw_distance, *rw_offset;
    u32 *walllights, *midtexture, *rw_midtexmid, *toptexture, *pixhigh, *pixhighstep, *rw_toptexmid;
    u32 *bottomtexture, *pixlow, *pixlowstep, *rw_bottexmid, *maskedtexture, *maskedtexcol;
    u32 *dc_colormap, *dc_x, *dc_iscale, *dc_yl, *dc_yh, *dc_texmid, *dc_src, *colfunc, *viewheight;
    u32 cc_a, fc_a, x2v_a, ft_a;
    u32 getcol_target;
} seg_p;

static struct {
    u32 *viewwidth, *viewheight, *planeheight, *basexscale, *baseyscale;
    u32 *ds_xstep, *ds_ystep, *viewangle, *finecosine_p, *viewx, *ds_xfrac;
    u32 *viewy, *fixedcolormap, *ds_yfrac, *ds_colormap, *planezlight;
    u32 *ds_y, *ds_x1, *ds_x2, *spanfunc;
    u32 ch_a, ysl_a, cdist_a, cxstep_a, cystep_a, dscale_a, x2v_a, fsin_a;
} mp_p;

static const u8 mapplane_tmpl[385] = {
    0x51,0x56,0x57,0x55,0x83,0xEC,0x0C,0x89,0xC7,0x89,0xD6,0x89,0x5C,0x24,0x08,0x39,
    0xDA,0x7F,0x16,0x85,0xD2,0x7C,0x12,0x89,0xD8,0x3B,0x05,0x00,0x00,0x00,0x00,0x7D,
    0x08,0x3B,0x3D,0x00,0x00,0x00,0x00,0x76,0x14,0x57,0x8B,0x6C,0x24,0x0C,0x55,0x56,
    0x68,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,0x00,0x00,0x83,0xC4,0x10,0x8D,0x0C,0xBD,
    0x00,0x00,0x00,0x00,0xA1,0x00,0x00,0x00,0x00,0x3B,0x81,0x00,0x00,0x00,0x00,0x74,
    0x50,0x8B,0x99,0x00,0x00,0x00,0x00,0x89,0x81,0x00,0x00,0x00,0x00,0xF7,0xEB,0x0F,
    0xAC,0xD0,0x10,0x8B,0x1D,0x00,0x00,0x00,0x00,0x89,0xC5,0x89,0x44,0x24,0x04,0x89,
    0x81,0x00,0x00,0x00,0x00,0xF7,0xEB,0x0F,0xAC,0xD0,0x10,0x8B,0x1D,0x00,0x00,0x00,
    0x00,0xA3,0x00,0x00,0x00,0x00,0x89,0x81,0x00,0x00,0x00,0x00,0x89,0xE8,0xF7,0xEB,
    0x0F,0xAC,0xD0,0x10,0xA3,0x00,0x00,0x00,0x00,0x89,0x81,0x00,0x00,0x00,0x00,0xEB,
    0x20,0x8B,0x81,0x00,0x00,0x00,0x00,0x89,0x44,0x24,0x04,0x8B,0x81,0x00,0x00,0x00,
    0x00,0xA3,0x00,0x00,0x00,0x00,0x8B,0x81,0x00,0x00,0x00,0x00,0xA3,0x00,0x00,0x00,
    0x00,0x8D,0x04,0xB5,0x00,0x00,0x00,0x00,0x89,0x04,0x24,0x8B,0x98,0x00,0x00,0x00,
    0x00,0x8B,0x44,0x24,0x04,0xF7,0xEB,0x0F,0xAC,0xD0,0x10,0x89,0xC1,0x8B,0x04,0x24,
    0x8B,0x2D,0x00,0x00,0x00,0x00,0x03,0xA8,0x00,0x00,0x00,0x00,0xA1,0x00,0x00,0x00,
    0x00,0xC1,0xED,0x13,0x89,0xCB,0x8B,0x04,0xA8,0xF7,0xEB,0x0F,0xAC,0xD0,0x10,0x8B,
    0x1D,0x00,0x00,0x00,0x00,0x01,0xD8,0xA3,0x00,0x00,0x00,0x00,0x89,0xCB,0x8B,0x04,
    0xAD,0x00,0x00,0x00,0x00,0xF7,0xEB,0x0F,0xAC,0xD0,0x10,0x8B,0x1D,0x00,0x00,0x00,
    0x00,0xF7,0xDB,0x29,0xC3,0x8B,0x0D,0x00,0x00,0x00,0x00,0x89,0x1D,0x00,0x00,0x00,
    0x00,0x85,0xC9,0x74,0x08,0x89,0x0D,0x00,0x00,0x00,0x00,0xEB,0x21,0x8B,0x4C,0x24,
    0x04,0xC1,0xF9,0x14,0x81,0xF9,0x80,0x00,0x00,0x00,0x72,0x05,0xB9,0x7F,0x00,0x00,
    0x00,0xA1,0x00,0x00,0x00,0x00,0x8B,0x04,0x88,0xA3,0x00,0x00,0x00,0x00,0x8B,0x44,
    0x24,0x08,0x89,0x3D,0x00,0x00,0x00,0x00,0x89,0x35,0x00,0x00,0x00,0x00,0xA3,0x00,
    0x00,0x00,0x00,0xFF,0x15,0x00,0x00,0x00,0x00,0x83,0xC4,0x0C,0x5D,0x5F,0x5E,0x59,
    0xC3,
};
static const u8 mapplane_mask[49] = {
    0xFF,0xFF,0xFF,0x87,0x87,0xFF,0x21,0xFC,0x1F,0x86,0x87,0xE1,0x1F,0xFE,0xE1,0x1F,
    0xC2,0xF0,0x1F,0x86,0x87,0x1F,0xC2,0x10,0xFE,0x1F,0xFE,0xFF,0xC3,0x10,0xFE,0xFF,
    0xE1,0xF0,0xE1,0x1F,0x7E,0x18,0x7E,0xF8,0xFF,0xFF,0xC3,0xC3,0x0F,0x43,0x18,0xFE,
    0x01,
};

static const u8 visspr63_tmpl[63] = {
    0x89,0xCA,0xC1,0xFA,0x10,0x85,0xD2,0x7C,0x07,0x0F,0xBF,0x06,0x39,0xC2,0x7C,0x0D,
    0x68,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,0x00,0x00,0x83,0xC4,0x04,0x8B,0x44,0x96,
    0x08,0x01,0xF0,0xE8,0x00,0x00,0x00,0x00,0xA1,0x00,0x00,0x00,0x00,0x8B,0x57,0x28,
    0x8B,0x5F,0x0C,0x40,0x01,0xD1,0xA3,0x00,0x00,0x00,0x00,0x39,0xD8,0x7E,0xC1,
};
static const u8 visspr63_mask[8] = {
    0xFF,0xFF,0x21,0xFC,0x0F,0xE1,0x7F,0x78,
};

static const u8 rpos_tmpl[163] = {
    0x51,0x56,0x57,0x55,0x89,0xD9,0x83,0x7B,0x08,0x00,0x75,0x28,0x8B,0x11,0x3B,0x02,
    0x7F,0x11,0x83,0x79,0x0C,0x00,0x0F,0x9F,0xC0,0x25,0xFF,0x00,0x00,0x00,0x5D,0x5F,
    0x5E,0x59,0xC3,0x83,0x79,0x0C,0x00,0x0F,0x9C,0xC0,0x25,0xFF,0x00,0x00,0x00,0x5D,
    0x5F,0x5E,0x59,0xC3,0x83,0x79,0x0C,0x00,0x75,0x29,0x8B,0x01,0x3B,0x50,0x04,0x7F,
    0x11,0x83,0x79,0x08,0x00,0x0F,0x9C,0xC0,0x25,0xFF,0x00,0x00,0x00,0x5D,0x5F,0x5E,
    0x59,0xC3,0x83,0x79,0x08,0x00,0x0F,0x9F,0xC0,0x25,0xFF,0x00,0x00,0x00,0x5D,0x5F,
    0x5E,0x59,0xC3,0x8B,0x31,0x89,0xC3,0x8B,0x3E,0x8B,0x41,0x0C,0x8B,0x6E,0x04,0xC1,
    0xF8,0x10,0x29,0xFB,0x89,0xD6,0xF7,0xEB,0x0F,0xAC,0xD0,0x10,0x89,0xC7,0x8B,0x59,
    0x08,0x29,0xEE,0xC1,0xFB,0x10,0x89,0xF0,0xF7,0xEB,0x0F,0xAC,0xD0,0x10,0x39,0xF8,
    0x7D,0x07,0x31,0xC0,0x5D,0x5F,0x5E,0x59,0xC3,0xB8,0x01,0x00,0x00,0x00,0x5D,0x5F,
    0x5E,0x59,0xC3,
};
static const u8 rnode_tmpl[189] = {
    0x51,0x56,0x57,0x55,0x89,0xD9,0x83,0x7B,0x08,0x00,0x75,0x26,0x3B,0x01,0x7F,0x11,
    0x83,0x79,0x0C,0x00,0x0F,0x9F,0xC0,0x25,0xFF,0x00,0x00,0x00,0x5D,0x5F,0x5E,0x59,
    0xC3,0x83,0x79,0x0C,0x00,0x0F,0x9C,0xC0,0x25,0xFF,0x00,0x00,0x00,0x5D,0x5F,0x5E,
    0x59,0xC3,0x83,0x79,0x0C,0x00,0x75,0x27,0x3B,0x51,0x04,0x7F,0x11,0x83,0x79,0x08,
    0x00,0x0F,0x9C,0xC0,0x25,0xFF,0x00,0x00,0x00,0x5D,0x5F,0x5E,0x59,0xC3,0x83,0x79,
    0x08,0x00,0x0F,0x9F,0xC0,0x25,0xFF,0x00,0x00,0x00,0x5D,0x5F,0x5E,0x59,0xC3,0x89,
    0xC3,0x89,0xD6,0x8B,0x39,0x8B,0x69,0x04,0x8B,0x41,0x0C,0x8B,0x51,0x08,0x29,0xFB,
    0x31,0xD0,0x29,0xEE,0x31,0xD8,0x31,0xF0,0xA9,0x00,0x00,0x00,0x80,0x74,0x0D,0x33,
    0x59,0x0C,0xF7,0xC3,0x00,0x00,0x00,0x80,0x74,0x22,0xEB,0x27,0x8B,0x41,0x0C,0xC1,
    0xF8,0x10,0xF7,0xEB,0x0F,0xAC,0xD0,0x10,0x8B,0x59,0x08,0x89,0xC7,0xC1,0xFB,0x10,
    0x89,0xF0,0xF7,0xEB,0x0F,0xAC,0xD0,0x10,0x39,0xF8,0x7D,0x07,0x31,0xC0,0x5D,0x5F,
    0x5E,0x59,0xC3,0xB8,0x01,0x00,0x00,0x00,0x5D,0x5F,0x5E,0x59,0xC3,
};

static struct {
    u32 *viewx, *viewy;
    u32 vx_a, vy_a, tanto_a;
} pta_p;

static const u8 pta_tmpl[547] = {
    0x53,0x51,0x56,0x57,0x55,0x89,0xC3,0x89,0xD0,0x8B,0x15,0x00,0x00,0x00,0x00,0x8B,
    0x0D,0x00,0x00,0x00,0x00,0x29,0xD3,0x29,0xC8,0x85,0xDB,0x75,0x08,0x85,0xC0,0x0F,
    0x84,0xF8,0x01,0x00,0x00,0x89,0xC5,0x8D,0x34,0xC5,0x00,0x00,0x00,0x00,0xC1,0xED,
    0x08,0x85,0xDB,0x0F,0x8C,0xE4,0x00,0x00,0x00,0x89,0xDF,0x8D,0x0C,0xDD,0x00,0x00,
    0x00,0x00,0xC1,0xEF,0x08,0x85,0xC0,0x7C,0x5D,0x39,0xC3,0x7E,0x2E,0x81,0xFB,0x00,
    0x02,0x00,0x00,0x73,0x07,0xB8,0x00,0x08,0x00,0x00,0xEB,0x13,0x89,0xF0,0x31,0xD2,
    0xF7,0xF7,0xBA,0x00,0x08,0x00,0x00,0x29,0xD0,0x19,0xC9,0x21,0xC8,0x01,0xD0,0x8B,
    0x04,0x85,0x00,0x00,0x00,0x00,0xE9,0xA2,0x01,0x00,0x00,0x3D,0x00,0x02,0x00,0x00,
    0x73,0x07,0xB8,0x00,0x08,0x00,0x00,0xEB,0x13,0x89,0xC8,0x31,0xD2,0xF7,0xF5,0xBA,
    0x00,0x08,0x00,0x00,0x29,0xD0,0x19,0xC9,0x21,0xC8,0x01,0xD0,0xBB,0xFF,0xFF,0xFF,
    0x3F,0xE9,0x6C,0x01,0x00,0x00,0xF7,0xD8,0x39,0xC3,0x7E,0x36,0x81,0xFB,0x00,0x02,
    0x00,0x00,0x73,0x07,0xB8,0x00,0x08,0x00,0x00,0xEB,0x18,0x8D,0x04,0xC5,0x00,0x00,
    0x00,0x00,0x31,0xD2,0xF7,0xF7,0xBA,0x00,0x08,0x00,0x00,0x29,0xD0,0x19,0xC9,0x21,
    0xC8,0x01,0xD0,0x8B,0x04,0x85,0x00,0x00,0x00,0x00,0xF7,0xD8,0x5D,0x5F,0x5E,0x59,
    0x5B,0xC3,0x3D,0x00,0x02,0x00,0x00,0x73,0x07,0xB8,0x00,0x08,0x00,0x00,0xEB,0x18,
    0x89,0xC3,0x31,0xD2,0xC1,0xEB,0x08,0x89,0xC8,0xF7,0xF3,0xBA,0x00,0x08,0x00,0x00,
    0x29,0xD0,0x19,0xC9,0x21,0xC8,0x01,0xD0,0xBB,0x00,0x00,0x00,0xC0,0x8B,0x0C,0x85,
    0x00,0x00,0x00,0x00,0x8D,0x04,0x0B,0x5D,0x5F,0x5E,0x59,0x5B,0xC3,0xF7,0xDB,0x89,
    0xDF,0x8D,0x0C,0xDD,0x00,0x00,0x00,0x00,0xC1,0xEF,0x08,0x85,0xC0,0x0F,0x8C,0x72,
    0x00,0x00,0x00,0x39,0xC3,0x7E,0x38,0x81,0xFB,0x00,0x02,0x00,0x00,0x73,0x07,0xB8,
    0x00,0x08,0x00,0x00,0xEB,0x13,0x89,0xF0,0x31,0xD2,0xF7,0xF7,0xBA,0x00,0x08,0x00,
    0x00,0x29,0xD0,0x19,0xC9,0x21,0xC8,0x01,0xD0,0xBB,0xFF,0xFF,0xFF,0x7F,0x8B,0x14,
    0x85,0x00,0x00,0x00,0x00,0x89,0xD8,0x29,0xD0,0x5D,0x5F,0x5E,0x59,0x5B,0xC3,0x3D,
    0x00,0x02,0x00,0x00,0x73,0x07,0xB8,0x00,0x08,0x00,0x00,0xEB,0x13,0x89,0xC8,0x31,
    0xD2,0xF7,0xF5,0xBA,0x00,0x08,0x00,0x00,0x29,0xD0,0x19,0xC9,0x21,0xC8,0x01,0xD0,
    0xBB,0x00,0x00,0x00,0x40,0x8B,0x2C,0x85,0x00,0x00,0x00,0x00,0x8D,0x04,0x2B,0x5D,
    0x5F,0x5E,0x59,0x5B,0xC3,0xF7,0xD8,0x39,0xC3,0x7E,0x3C,0x81,0xFB,0x00,0x02,0x00,
    0x00,0x73,0x07,0xB8,0x00,0x08,0x00,0x00,0xEB,0x18,0x8D,0x04,0xC5,0x00,0x00,0x00,
    0x00,0x31,0xD2,0xF7,0xF7,0xBA,0x00,0x08,0x00,0x00,0x29,0xD0,0x19,0xC9,0x21,0xC8,
    0x01,0xD0,0xBB,0x00,0x00,0x00,0x80,0x8B,0x3C,0x85,0x00,0x00,0x00,0x00,0x8D,0x04,
    0x3B,0x5D,0x5F,0x5E,0x59,0x5B,0xC3,0x3D,0x00,0x02,0x00,0x00,0x73,0x07,0xB8,0x00,
    0x08,0x00,0x00,0xEB,0x18,0x89,0xC3,0x31,0xD2,0xC1,0xEB,0x08,0x89,0xC8,0xF7,0xF3,
    0xBA,0x00,0x08,0x00,0x00,0x29,0xD0,0x19,0xC9,0x21,0xC8,0x01,0xD0,0xBB,0xFF,0xFF,
    0xFF,0xBF,0x8B,0x34,0x85,0x00,0x00,0x00,0x00,0x89,0xD8,0x29,0xF0,0x5D,0x5F,0x5E,
    0x59,0x5B,0xC3,
};
static const u8 pta_mask[69] = {
    0xFF,0x87,0xE1,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC3,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x3F,0xFC,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xF0,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xE1,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xF0,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC3,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0x1F,0xFE,0x07,
};
static const u8 outp_tmpl[14] = {
    0x53,0x51,0x89,0xC3,0x89,0xD1,0x89,0xC2,0x88,0xC8,0xEE,0x59,0x5B,0xC3,
};

static __attribute__((noinline)) int pm_init_pta_snap(u32 fn_eip, const u8 *fp)
{
    if (fn_eip + 547u > PM_CODE_GUARD_TOP || !pm_match_masked(fp, pta_tmpl, pta_mask, 547u))
        return 0;
    u32 vx_a = ua_r32(fp + 0x0B), vy_a = ua_r32(fp + 0x11), tt_a = ua_r32(fp + 0x72);
    if (ua_r32(fp + 0xD6)  != tt_a || ua_r32(fp + 0x110) != tt_a || ua_r32(fp + 0x161) != tt_a ||
        ua_r32(fp + 0x198) != tt_a || ua_r32(fp + 0x1DA) != tt_a || ua_r32(fp + 0x215) != tt_a)
        return 0;
    if (((vx_a | vy_a | tt_a) & 3u) != 0u || !PM_IS_XRAM4(vx_a) || !PM_IS_XRAM4(vy_a) ||
        tt_a < 0x100000u || tt_a + 2049u * 4u > RAM_BYTES)
        return 0;
    pta_p.viewx   = (u32 *)(void *)(mem + vx_a);
    pta_p.viewy   = (u32 *)(void *)(mem + vy_a);
    pta_p.vx_a    = vx_a;
    pta_p.vy_a    = vy_a;
    pta_p.tanto_a = tt_a;
    pta_eip = fn_eip;
    pm_guard_code(fn_eip, fn_eip + 547u);
    return 1;
}

#ifndef NO_TRT_IDLE
static const u8 trt_tmpl[148] = {
    0x8B,0x15,0x00,0x00,0x00,0x00,0x8B,0x1D,0x00,0x00,0x00,0x00,0x89,0xD0,0xC1,0xFA,
    0x1F,0xF7,0xFB,0x01,0xF8,0x39,0xC6,0x0F,0x8D,0x83,0x00,0x00,0x00,0xE8,0x00,0x00,
    0x00,0x00,0xBE,0xFF,0xFF,0xFF,0x7F,0x89,0xEA,0x89,0xE8,0xEB,0x18,0x3B,0xA8,0x00,
    0x00,0x00,0x00,0x74,0x0C,0x8B,0x98,0x00,0x00,0x00,0x00,0x39,0xDE,0x7E,0x02,0x89,
    0xDE,0x83,0xC0,0x04,0x42,0x8B,0x1D,0x00,0x00,0x00,0x00,0x0F,0xBF,0x5B,0x0C,0x39,
    0xDA,0x7C,0xDA,0x8B,0x15,0x00,0x00,0x00,0x00,0x8B,0x1D,0x00,0x00,0x00,0x00,0x89,
    0xD0,0xC1,0xFA,0x1F,0xF7,0xFB,0x39,0xC6,0x7D,0x0D,0x68,0x00,0x00,0x00,0x00,0xE8,
    0x00,0x00,0x00,0x00,0x83,0xC4,0x04,0xE8,0x00,0x00,0x00,0x00,0x89,0xC2,0x8B,0x1D,
    0x00,0x00,0x00,0x00,0xC1,0xFA,0x1F,0xF7,0xFB,0x29,0xC8,0x83,0xF8,0x14,0x0F,0x8C,
    0x6C,0xFF,0xFF,0xFF,
};
static const u8 trt_mask[19] = {
    0xC3,0xF0,0xFF,0x3F,0xFC,0x7F,0x78,0xF8,0x7F,0xF8,0x1F,0x86,0xFF,0x87,0xF0,0xF0,
    0xF0,0xFF,0x0F,
};

static __attribute__((noinline)) s32 pm_try_trt_idle(const u8 *ip, s32 cyc_cnt, s32 end_cyc)
{
    u8 * const ram = mem;
    u32 fn_eip = (u32)(ip - ram);
    if (__builtin_expect(fn_eip != trt_eip, 0)) {
        if (trt_eip != 0xFFFFFFFFu || fn_eip < 0x100000u || fn_eip + 148u > PM_CODE_GUARD_TOP)
            return cyc_cnt;
        if (!pm_match_masked(ip, trt_tmpl, trt_mask, 148u))
            return cyc_cnt;
        u32 gtic_a = ua_r32(ip + 0x02), tdup_a = ua_r32(ip + 0x08);
        if (ua_r32(ip + 0x55) != gtic_a || ua_r32(ip + 0x5B) != tdup_a || ua_r32(ip + 0x80) != tdup_a)
            return cyc_cnt;
        u32 igt_eip = (fn_eip + 0x7Cu) + ua_r32(ip + 0x78);
        if (igt_eip < 0x100000u || igt_eip + 6u > PM_CODE_GUARD_TOP)
            return cyc_cnt;
        if (ram[igt_eip] != 0xA1u || ram[igt_eip + 5u] != 0xC3u)
            return cyc_cnt;
        u32 tic_a = ua_r32(ram + igt_eip + 1u);
        if (((gtic_a | tdup_a | tic_a) & 3u) != 0u || !PM_IS_XRAM4(gtic_a) || !PM_IS_XRAM4(tic_a))
            return cyc_cnt;
        trt_gtic_a = gtic_a;
        trt_tic_a  = tic_a;
        trt_eip    = fn_eip;
        trt_spin_cnt = 0u;
        pm_guard_code(fn_eip, fn_eip + 148u);
        pm_guard_code(igt_eip, igt_eip + 6u);
    }
    if (!(c.sys & F_IF) || cyc_cnt >= end_cyc)
        return cyc_cnt;
    u32 cur_tic  = ua_r32(ram + trt_tic_a);
    u32 cur_gtic = ua_r32(ram + trt_gtic_a);
    if (cur_tic == trt_last_tic && cur_gtic == trt_last_gtic && end_cyc == trt_last_end) {
        if (++trt_spin_cnt >= 2u) {
            idle_cycles += (u32)((end_cyc - cyc_cnt) >> PM_CLK_SH);
            return end_cyc;
        }
        return cyc_cnt;
    }
    trt_last_tic  = cur_tic;
    trt_last_gtic = cur_gtic;
    trt_last_end  = end_cyc;
    trt_spin_cnt  = 1u;
    return cyc_cnt;
}
#endif

static const u8 pos_tmpl[171] = {
    0x51,0x56,0x83,0x7B,0x08,0x00,0x75,0x2E,0x8B,0x13,0x39,0xD0,0x75,0x08,0xB8,0x02,
    0x00,0x00,0x00,0x5E,0x59,0xC3,0x7F,0x0F,0x83,0x7B,0x0C,0x00,0x0F,0x9F,0xC0,0x25,
    0xFF,0x00,0x00,0x00,0x5E,0x59,0xC3,0x83,0x7B,0x0C,0x00,0x0F,0x9C,0xC0,0x25,0xFF,
    0x00,0x00,0x00,0x5E,0x59,0xC3,0x8B,0x73,0x0C,0x85,0xF6,0x75,0x31,0x8B,0x4B,0x04,
    0x39,0xC8,0x75,0x08,0xB8,0x02,0x00,0x00,0x00,0x5E,0x59,0xC3,0x39,0xCA,0x7F,0x0F,
    0x83,0x7B,0x08,0x00,0x0F,0x9C,0xC0,0x25,0xFF,0x00,0x00,0x00,0x5E,0x59,0xC3,0x83,
    0x7B,0x08,0x00,0x0F,0x9F,0xC0,0x25,0xFF,0x00,0x00,0x00,0x5E,0x59,0xC3,0x2B,0x03,
    0x89,0xD1,0x89,0xC2,0xC1,0xFE,0x10,0xC1,0xFA,0x10,0x0F,0xAF,0xD6,0x2B,0x4B,0x04,
    0x8B,0x43,0x08,0x89,0xCB,0xC1,0xF8,0x10,0xC1,0xFB,0x10,0x0F,0xAF,0xC3,0x39,0xD0,
    0x7D,0x05,0x31,0xC0,0x5E,0x59,0xC3,0x39,0xC2,0x75,0x08,0xB8,0x02,0x00,0x00,0x00,
    0x5E,0x59,0xC3,0xB8,0x01,0x00,0x00,0x00,0x5E,0x59,0xC3,
};

static const u8 fdiv_tmpl[65] = {
    0x53,0x51,0x56,0x89,0xC1,0x89,0xD3,0x99,0x31,0xD0,0x29,0xD0,0x89,0xC6,0x89,0xD8,
    0xC1,0xFE,0x0E,0x99,0x31,0xD0,0x29,0xD0,0x39,0xC6,0x7C,0x15,0x31,0xCB,0x85,0xDB,
    0x0F,0x9C,0xC0,0x25,0xFF,0x00,0x00,0x00,0x05,0xFF,0xFF,0xFF,0x7F,0x5E,0x59,0x5B,
    0xC3,0x89,0xC8,0x99,0x0F,0xA4,0xC2,0x10,0xC1,0xE0,0x10,0xF7,0xFB,0x5E,0x59,0x5B,
    0xC3,
};

static const u8 wcl_hit_tmpl[54] = {
    0x81,0x7F,0xF4,0x11,0x4A,0x1D,0x00,0x74,0x12,0x68,0xFE,0x01,0x00,0x00,0x68,0x00,
    0x00,0x00,0x00,0xE8,0x00,0x00,0x00,0x00,0x83,0xC4,0x08,0xA1,0x00,0x00,0x00,0x00,
    0x8B,0x04,0x88,0xE8,0x00,0x00,0x00,0x00,0x8B,0x15,0x00,0x00,0x00,0x00,0x8B,0x04,
    0x8A,0x5F,0x5E,0x59,0x5B,0xC3,
};
static const u8 wcl_hit_mask[7] = {
    0xFF,0x7F,0x08,0x0F,0x0F,0xC3,0x3F,
};

static const u8 wcl_ent_tmpl[53] = {
    0x53,0x51,0x56,0x57,0x89,0xC1,0x3B,0x05,0x00,0x00,0x00,0x00,0x72,0x0E,0x50,0x68,
    0x00,0x00,0x00,0x00,0xE8,0x00,0x00,0x00,0x00,0x83,0xC4,0x08,0x8B,0x1D,0x00,0x00,
    0x00,0x00,0x8D,0x34,0x8D,0x00,0x00,0x00,0x00,0x01,0xF3,0x8B,0x3B,0x85,0xFF,0x0F,
    0x85,0x76,0xFF,0xFF,0xFF,
};
static const u8 wcl_ent_mask[7] = {
    0xFF,0xF0,0x10,0x3E,0xFC,0xFF,0x1F,
};

static const u8 zct_tmpl[58] = {
    0x53,0x8D,0x58,0xE8,0x81,0x7B,0x0C,0x11,0x4A,0x1D,0x00,0x74,0x0D,0x68,0x00,0x00,
    0x00,0x00,0xE8,0x00,0x00,0x00,0x00,0x83,0xC4,0x04,0x83,0xFA,0x64,0x7C,0x16,0x81,
    0x7B,0x04,0x00,0x01,0x00,0x00,0x73,0x0D,0x68,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,
    0x00,0x00,0x83,0xC4,0x04,0x89,0x53,0x08,0x5B,0xC3,
};
static const u8 zct_mask[8] = {
    0xFF,0x3F,0x84,0xFF,0xFF,0x21,0xFC,0x03,
};

static const u8 getcol_tmpl[111] = {
    0x53,0x51,0x56,0x89,0xC3,0x8B,0x0D,0x00,0x00,0x00,0x00,0x8D,0x04,0x85,0x00,0x00,
    0x00,0x00,0x23,0x14,0x01,0x8B,0x35,0x00,0x00,0x00,0x00,0x8D,0x0C,0x55,0x00,0x00,
    0x00,0x00,0x8B,0x14,0x06,0x8B,0x35,0x00,0x00,0x00,0x00,0x8B,0x34,0x06,0x0F,0xBF,
    0x14,0x11,0x66,0x8B,0x0C,0x31,0x81,0xE1,0xFF,0xFF,0x00,0x00,0x85,0xD2,0x7E,0x0E,
    0x89,0xD0,0xBA,0x65,0x00,0x00,0x00,0xE8,0x00,0x00,0x00,0x00,0xEB,0x1B,0x8B,0x15,
    0x00,0x00,0x00,0x00,0x83,0x3C,0x02,0x00,0x75,0x07,0x89,0xD8,0xE8,0x00,0x00,0x00,
    0x00,0xA1,0x00,0x00,0x00,0x00,0x8B,0x04,0x98,0x01,0xC8,0x5E,0x59,0x5B,0xC3,
};
static const u8 getcol_mask[14] = {
    0x7F,0xF8,0x7F,0xF8,0x7F,0xF8,0xFF,0xFF,0xFF,0xF0,0xF0,0x1F,0xC2,0x7F,
};

static const u8 mcol_tmpl[233] = {
    0x53,0x51,0x52,0x56,0x57,0x8B,0x0D,0x00,0x00,0x00,0x00,0x8B,0x35,0x00,0x00,0x00,
    0x00,0x89,0xC2,0x8A,0x20,0x8B,0x3D,0x00,0x00,0x00,0x00,0x80,0xFC,0xFF,0x0F,0x84,
    0xAD,0x00,0x00,0x00,0x31,0xC0,0x8B,0x1D,0x00,0x00,0x00,0x00,0x8A,0x02,0x0F,0xAF,
    0xC3,0x31,0xDB,0x8B,0x35,0x00,0x00,0x00,0x00,0x8A,0x5A,0x01,0x0F,0xAF,0xF3,0x03,
    0x05,0x00,0x00,0x00,0x00,0x8D,0x88,0xFF,0xFF,0x00,0x00,0x01,0xC6,0x8B,0x1D,0x00,
    0x00,0x00,0x00,0x4E,0xA1,0x00,0x00,0x00,0x00,0xC1,0xFE,0x10,0x0F,0xBF,0x04,0x43,
    0xC1,0xF9,0x10,0x39,0xC6,0x7C,0x03,0x8D,0x70,0xFF,0x8B,0x1D,0x00,0x00,0x00,0x00,
    0xA1,0x00,0x00,0x00,0x00,0x0F,0xBF,0x04,0x58,0x39,0xC1,0x7F,0x03,0x8D,0x48,0x01,
    0x89,0x0D,0x00,0x00,0x00,0x00,0x89,0x35,0x00,0x00,0x00,0x00,0x39,0xF1,0x7F,0x1F,
    0x8D,0x42,0x03,0xA3,0x00,0x00,0x00,0x00,0x31,0xC0,0x8A,0x02,0x89,0xFB,0xC1,0xE0,
    0x10,0x29,0xC3,0x89,0x1D,0x00,0x00,0x00,0x00,0xFF,0x15,0x00,0x00,0x00,0x00,0x8B,
    0x35,0x00,0x00,0x00,0x00,0x8B,0x0D,0x00,0x00,0x00,0x00,0x31,0xC0,0x8A,0x42,0x01,
    0x01,0xC2,0x8A,0x5A,0x04,0x83,0xC2,0x04,0x80,0xFB,0xFF,0x0F,0x85,0x53,0xFF,0xFF,
    0xFF,0x89,0x3D,0x00,0x00,0x00,0x00,0x89,0x35,0x00,0x00,0x00,0x00,0x89,0x0D,0x00,
    0x00,0x00,0x00,0x5F,0x5E,0x5A,0x59,0x5B,0xC3,
};
static const u8 mcol_mask[30] = {
    0x7F,0x18,0x7E,0xF8,0xFF,0xF0,0x1F,0xFE,0xE1,0x7F,0x18,0xFE,0xFF,0x0F,0xE1,0xFF,
    0xC3,0xF0,0x0F,0xFF,0x1F,0x86,0x61,0xF8,0xFF,0xFF,0x87,0x61,0xF8,0x01,
};

static const u8 segfn_tmpl[883] = {
    0x53,0x51,0x52,0x56,0x57,0x55,0xA1,0x00,0x00,0x00,0x00,0x8B,0x15,0x00,0x00,0x00,
    0x00,0x31,0xC9,0x39,0xD0,0x0F,0x8D,0x51,0x03,0x00,0x00,0x8B,0x3D,0x00,0x00,0x00,
    0x00,0xA1,0x00,0x00,0x00,0x00,0x81,0xC7,0xFF,0x0F,0x00,0x00,0x0F,0xBF,0x04,0x45,
    0x00,0x00,0x00,0x00,0xC1,0xFF,0x0C,0x40,0x39,0xC7,0x7D,0x02,0x89,0xC7,0x83,0x3D,
    0x00,0x00,0x00,0x00,0x00,0x74,0x3A,0x8B,0x15,0x00,0x00,0x00,0x00,0x8D,0x47,0xFF,
    0x0F,0xBF,0x1C,0x55,0x00,0x00,0x00,0x00,0x0F,0xBF,0x14,0x55,0x00,0x00,0x00,0x00,
    0x43,0x39,0xD0,0x7C,0x03,0x8D,0x42,0xFF,0x39,0xC3,0x7F,0x15,0x8B,0x35,0x00,0x00,
    0x00,0x00,0x03,0x35,0x00,0x00,0x00,0x00,0x88,0x5E,0x15,0x88,0x86,0x57,0x01,0x00,
    0x00,0x8B,0x35,0x00,0x00,0x00,0x00,0xA1,0x00,0x00,0x00,0x00,0xC1,0xFE,0x0C,0x0F,
    0xBF,0x04,0x45,0x00,0x00,0x00,0x00,0x39,0xC6,0x7C,0x03,0x8D,0x70,0xFF,0x83,0x3D,
    0x00,0x00,0x00,0x00,0x00,0x74,0x3A,0x8B,0x15,0x00,0x00,0x00,0x00,0x8D,0x5E,0x01,
    0x0F,0xBF,0x04,0x55,0x00,0x00,0x00,0x00,0x0F,0xBF,0x14,0x55,0x00,0x00,0x00,0x00,
    0x48,0x39,0xD3,0x7F,0x03,0x8D,0x5A,0x01,0x39,0xC3,0x7F,0x15,0x8B,0x15,0x00,0x00,
    0x00,0x00,0x03,0x15,0x00,0x00,0x00,0x00,0x88,0x5A,0x15,0x88,0x82,0x57,0x01,0x00,
    0x00,0x83,0x3D,0x00,0x00,0x00,0x00,0x00,0x74,0x77,0x8B,0x15,0x00,0x00,0x00,0x00,
    0xA1,0x00,0x00,0x00,0x00,0x03,0x04,0x95,0x00,0x00,0x00,0x00,0xC1,0xE8,0x13,0x8B,
    0x1D,0x00,0x00,0x00,0x00,0x8B,0x04,0x85,0x00,0x00,0x00,0x00,0xF7,0xEB,0x0F,0xAC,
    0xD0,0x10,0x8B,0x0D,0x00,0x00,0x00,0x00,0x29,0xC1,0xA1,0x00,0x00,0x00,0x00,0xC1,
    0xF8,0x0C,0xC1,0xF9,0x10,0x83,0xF8,0x30,0x72,0x05,0xB8,0x2F,0x00,0x00,0x00,0x8D,
    0x14,0x85,0x00,0x00,0x00,0x00,0xA1,0x00,0x00,0x00,0x00,0x8B,0x04,0x02,0x8B,0x1D,
    0x00,0x00,0x00,0x00,0xA3,0x00,0x00,0x00,0x00,0xA1,0x00,0x00,0x00,0x00,0x31,0xD2,
    0xA3,0x00,0x00,0x00,0x00,0xB8,0xFF,0xFF,0xFF,0xFF,0xF7,0xF3,0xA3,0x00,0x00,0x00,
    0x00,0x8B,0x2D,0x00,0x00,0x00,0x00,0x85,0xED,0x74,0x4D,0xA1,0x00,0x00,0x00,0x00,
    0x89,0x3D,0x00,0x00,0x00,0x00,0x89,0xCA,0xA3,0x00,0x00,0x00,0x00,0x89,0xE8,0x89,
    0x35,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,0x00,0x00,0xA3,0x00,0x00,0x00,0x00,0xFF,
    0x15,0x00,0x00,0x00,0x00,0xA1,0x00,0x00,0x00,0x00,0x66,0x8B,0x15,0x00,0x00,0x00,
    0x00,0x66,0x89,0x14,0x45,0x00,0x00,0x00,0x00,0x66,0xC7,0x04,0x45,0x00,0x00,0x00,
    0x00,0xFF,0xFF,0xE9,0x60,0x01,0x00,0x00,0xA1,0x00,0x00,0x00,0x00,0x8B,0x15,0x00,
    0x00,0x00,0x00,0x01,0xC0,0x85,0xD2,0x0F,0x84,0x7B,0x00,0x00,0x00,0x8B,0x1D,0x00,
    0x00,0x00,0x00,0x8B,0x15,0x00,0x00,0x00,0x00,0x8B,0x2D,0x00,0x00,0x00,0x00,0x0F,
    0xBF,0x80,0x00,0x00,0x00,0x00,0x01,0xD5,0xC1,0xFB,0x0C,0x89,0x2D,0x00,0x00,0x00,
    0x00,0x39,0xC3,0x7C,0x03,0x8D,0x58,0xFF,0x39,0xFB,0x7C,0x3C,0xA1,0x00,0x00,0x00,
    0x00,0x89,0x3D,0x00,0x00,0x00,0x00,0x89,0xCA,0xA3,0x00,0x00,0x00,0x00,0xA1,0x00,
    0x00,0x00,0x00,0x89,0x1D,0x00,0x00,0x00,0x00,0xE8,0x00,0x00,0x00,0x00,0xA3,0x00,
    0x00,0x00,0x00,0xFF,0x15,0x00,0x00,0x00,0x00,0xA1,0x00,0x00,0x00,0x00,0x66,0x89,
    0x1C,0x45,0x00,0x00,0x00,0x00,0xEB,0x21,0xA1,0x00,0x00,0x00,0x00,0x4F,0x66,0x89,
    0x3C,0x45,0x00,0x00,0x00,0x00,0xEB,0x11,0x83,0x3D,0x00,0x00,0x00,0x00,0x00,0x74,
    0x08,0x4F,0x66,0x89,0xB8,0x00,0x00,0x00,0x00,0xA1,0x00,0x00,0x00,0x00,0x8B,0x15,
    0x00,0x00,0x00,0x00,0x01,0xC0,0x85,0xD2,0x0F,0x84,0x81,0x00,0x00,0x00,0x8B,0x1D,
    0x00,0x00,0x00,0x00,0x8B,0x15,0x00,0x00,0x00,0x00,0x8B,0x3D,0x00,0x00,0x00,0x00,
    0x0F,0xBF,0x80,0x00,0x00,0x00,0x00,0x81,0xC3,0xFF,0x0F,0x00,0x00,0x01,0xD7,0xC1,
    0xFB,0x0C,0x89,0x3D,0x00,0x00,0x00,0x00,0x39,0xC3,0x7F,0x03,0x8D,0x58,0x01,0x39,
    0xF3,0x7F,0x3C,0xA1,0x00,0x00,0x00,0x00,0x89,0x1D,0x00,0x00,0x00,0x00,0x89,0xCA,
    0xA3,0x00,0x00,0x00,0x00,0xA1,0x00,0x00,0x00,0x00,0x89,0x35,0x00,0x00,0x00,0x00,
    0xE8,0x00,0x00,0x00,0x00,0xA3,0x00,0x00,0x00,0x00,0xFF,0x15,0x00,0x00,0x00,0x00,
    0xA1,0x00,0x00,0x00,0x00,0x66,0x89,0x1C,0x45,0x00,0x00,0x00,0x00,0xEB,0x21,0xA1,
    0x00,0x00,0x00,0x00,0x46,0x66,0x89,0x34,0x45,0x00,0x00,0x00,0x00,0xEB,0x11,0x83,
    0x3D,0x00,0x00,0x00,0x00,0x00,0x74,0x08,0x46,0x66,0x89,0xB0,0x00,0x00,0x00,0x00,
    0x83,0x3D,0x00,0x00,0x00,0x00,0x00,0x74,0x0F,0x8B,0x15,0x00,0x00,0x00,0x00,0xA1,
    0x00,0x00,0x00,0x00,0x66,0x89,0x0C,0x50,0xA1,0x00,0x00,0x00,0x00,0x8B,0x1D,0x00,
    0x00,0x00,0x00,0x8B,0x35,0x00,0x00,0x00,0x00,0x8B,0x3D,0x00,0x00,0x00,0x00,0x8B,
    0x2D,0x00,0x00,0x00,0x00,0x8B,0x15,0x00,0x00,0x00,0x00,0x45,0x01,0xC3,0xA1,0x00,
    0x00,0x00,0x00,0x89,0x1D,0x00,0x00,0x00,0x00,0x01,0xC6,0xA1,0x00,0x00,0x00,0x00,
    0x89,0x2D,0x00,0x00,0x00,0x00,0x01,0xC7,0x89,0x35,0x00,0x00,0x00,0x00,0x89,0x3D,
    0x00,0x00,0x00,0x00,0x39,0xD5,0x0F,0x8C,0xAF,0xFC,0xFF,0xFF,0x5D,0x5F,0x5E,0x5A,
    0x59,0x5B,0xC3,
};
static const u8 segfn_mask[111] = {
    0x7F,0x18,0xFE,0x1F,0xC2,0xFF,0xF0,0xFF,0xF0,0xE1,0x0F,0x0F,0xFF,0x3F,0x0C,0xFF,
    0x87,0xF0,0x87,0xFF,0xF0,0xE1,0x0F,0x0F,0xFF,0x3F,0x0C,0xFF,0x87,0x0F,0xE1,0xF0,
    0xE1,0xF0,0x0F,0x87,0xFF,0xFF,0x7F,0xF8,0x10,0xC2,0xE1,0x1F,0x86,0x0F,0xC3,0xE1,
    0x21,0x84,0x21,0x1C,0x1E,0x1E,0xFE,0x61,0xF8,0x7F,0x18,0x86,0xC3,0x1F,0xFE,0x1F,
    0x86,0x43,0x18,0x42,0x18,0xC2,0xC3,0xE1,0xC3,0xC3,0x1F,0xC2,0xF0,0xFF,0x30,0x0C,
    0x87,0xFF,0x0F,0xFF,0x0F,0xC3,0x21,0x0C,0x21,0x0C,0xE1,0xE1,0xF0,0xE1,0xE1,0x0F,
    0xC3,0x87,0xF0,0x61,0x18,0x86,0x61,0x78,0x18,0x0E,0xC3,0xC3,0xF0,0xFF,0x07,
};

static __attribute__((noinline)) int pm_init_wcl_snap(u32 fn_eip, const u8 *fp)
{
    if (fn_eip < 0x100060u || fn_eip + 96u > PM_CODE_GUARD_TOP)
        return 0;
    const u8 *hp = fp - 0x55;
    if (!pm_match_masked(fp, wcl_ent_tmpl, wcl_ent_mask, 53u) ||
        !pm_match_masked(hp, wcl_hit_tmpl, wcl_hit_mask, 54u))
        return 0;
    u32 nl_a = ua_r32(fp + 0x08), lc_a = ua_r32(fp + 0x1E);
    if (ua_r32(hp + 0x1C) != lc_a || ua_r32(hp + 0x2A) != lc_a)
        return 0;
    if (((nl_a | lc_a) & 3u) != 0u || !PM_IS_XRAM4(nl_a) || !PM_IS_XRAM4(lc_a))
        return 0;
    u32 zct_ret = (fn_eip - 0x55u) + 0x28u;
    u32 zct_eip = zct_ret + ua_r32(hp + 0x24);
    if (zct_eip < 0x100000u || zct_eip + 58u > PM_CODE_GUARD_TOP)
        return 0;
    if (!pm_match_masked(mem + zct_eip, zct_tmpl, zct_mask, 58u))
        return 0;
    wcl_p.numlumps  = (u32 *)(void *)(mem + nl_a);
    wcl_p.lumpcache = (u32 *)(void *)(mem + lc_a);
    wcl_p.zct_ret   = zct_ret;
    wcl_eip = fn_eip;
    pm_guard_code(fn_eip - 0x55u, fn_eip + 94u);
    pm_guard_code(zct_eip, zct_eip + 58u);
    return 1;
}

static __attribute__((noinline)) int pm_init_getcol_snap(u32 fn_eip, const u8 *fp)
{
    if (fn_eip < 0x100000u || fn_eip + 111u > PM_CODE_GUARD_TOP)
        return 0;
    if (!pm_match_masked(fp, getcol_tmpl, getcol_mask, 111u))
        return 0;
    u32 wm_a = ua_r32(fp + 0x07), cl_a = ua_r32(fp + 0x17);
    u32 co_a = ua_r32(fp + 0x27), cp_a = ua_r32(fp + 0x50);
    if (ua_r32(fp + 0x62) != cp_a)
        return 0;
    if (((wm_a | cl_a | co_a | cp_a) & 3u) != 0u ||
        !PM_IS_XRAM4(wm_a) || !PM_IS_XRAM4(cl_a) || !PM_IS_XRAM4(co_a) || !PM_IS_XRAM4(cp_a))
        return 0;
    u32 wcl_tgt = (fn_eip + 0x4Cu) + ua_r32(fp + 0x48);
    if (wcl_eip != wcl_tgt && !pm_init_wcl_snap(wcl_tgt, mem + wcl_tgt))
        return 0;
    getcol_p.wmask = (u32 *)(void *)(mem + wm_a);
    getcol_p.clump = (u32 *)(void *)(mem + cl_a);
    getcol_p.cofs  = (u32 *)(void *)(mem + co_a);
    getcol_p.comp  = (u32 *)(void *)(mem + cp_a);
    getcol_p.wcl_target = wcl_tgt;
    getcol_eip = fn_eip;
    pm_guard_code(fn_eip, fn_eip + 111u);
    return 1;
}

static __attribute__((noinline)) int pm_init_mcol_snap(u32 fn_eip, const u8 *fp)
{
    if (fn_eip < 0x100000u || fn_eip + 233u > PM_CODE_GUARD_TOP)
        return 0;
    if (!pm_match_masked(fp, mcol_tmpl, mcol_mask, 233u))
        return 0;
    u32 a_yl  = ua_r32(fp + 0x07), a_yh  = ua_r32(fp + 0x0D), a_tm = ua_r32(fp + 0x17);
    u32 a_sy  = ua_r32(fp + 0x28), a_st  = ua_r32(fp + 0x41), a_mfc = ua_r32(fp + 0x4F);
    u32 a_x   = ua_r32(fp + 0x55), a_mcc = ua_r32(fp + 0x71), a_src = ua_r32(fp + 0x94);
    u32 a_cf  = ua_r32(fp + 0xAB);
    if (ua_r32(fp + 0x35) != a_sy || ua_r32(fp + 0x6C) != a_x ||
        ua_r32(fp + 0x82) != a_yl || ua_r32(fp + 0x88) != a_yh ||
        ua_r32(fp + 0xA5) != a_tm || ua_r32(fp + 0xB1) != a_yh ||
        ua_r32(fp + 0xB7) != a_yl || ua_r32(fp + 0xD3) != a_tm ||
        ua_r32(fp + 0xD9) != a_yh || ua_r32(fp + 0xDF) != a_yl)
        return 0;
    u32 ad[10] = { a_yl, a_yh, a_tm, a_sy, a_st, a_mfc, a_x, a_mcc, a_src, a_cf };
    u32 or_al = 0;
    for (int i = 0; i < 10; i++) {
        if (!PM_IS_XRAM4(ad[i])) return 0;
        or_al |= ad[i];
    }
    if ((or_al & 3u) != 0u) return 0;
    mcol_p.dc_yl        = (u32 *)(void *)(mem + a_yl);
    mcol_p.dc_yh        = (u32 *)(void *)(mem + a_yh);
    mcol_p.dc_texmid    = (u32 *)(void *)(mem + a_tm);
    mcol_p.spryscale    = (u32 *)(void *)(mem + a_sy);
    mcol_p.sprtopscreen = (u32 *)(void *)(mem + a_st);
    mcol_p.mfloorclip   = (u32 *)(void *)(mem + a_mfc);
    mcol_p.dc_x         = (u32 *)(void *)(mem + a_x);
    mcol_p.mceilingclip = (u32 *)(void *)(mem + a_mcc);
    mcol_p.dc_src       = (u32 *)(void *)(mem + a_src);
    mcol_p.colfunc      = (u32 *)(void *)(mem + a_cf);
    mcol_eip = fn_eip;
    pm_guard_code(fn_eip, fn_eip + 233u);
    return 1;
}

static __attribute__((noinline)) int pm_init_segfn_snap(u32 fn_eip, const u8 *fp)
{
    if (fn_eip < 0x100000u || fn_eip + 883u > PM_CODE_GUARD_TOP)
        return 0;
    if (!pm_match_masked(fp, segfn_tmpl, segfn_mask, 883u))
        return 0;
    u32 a_rwx   = ua_r32(fp + 0x007), a_stopx = ua_r32(fp + 0x00D);
    u32 a_tfrac = ua_r32(fp + 0x01D), a_cc    = ua_r32(fp + 0x030);
    u32 a_mceil = ua_r32(fp + 0x040), a_fc    = ua_r32(fp + 0x05C);
    u32 a_cpln  = ua_r32(fp + 0x06E), a_bfrac = ua_r32(fp + 0x083);
    u32 a_mflr  = ua_r32(fp + 0x0A0), a_fpln  = ua_r32(fp + 0x0CE);
    u32 a_segtx = ua_r32(fp + 0x0E3), a_cang  = ua_r32(fp + 0x0F1);
    u32 a_x2v   = ua_r32(fp + 0x0F8), a_dist  = ua_r32(fp + 0x101);
    u32 a_ft    = ua_r32(fp + 0x108), a_offs  = ua_r32(fp + 0x114);
    u32 a_scale = ua_r32(fp + 0x11B), a_wlit  = ua_r32(fp + 0x137);
    u32 a_dccm  = ua_r32(fp + 0x145), a_dcx   = ua_r32(fp + 0x151);
    u32 a_dcisc = ua_r32(fp + 0x15D), a_midtx = ua_r32(fp + 0x163);
    u32 a_midtm = ua_r32(fp + 0x16C), a_dcyl  = ua_r32(fp + 0x172);
    u32 a_dctm  = ua_r32(fp + 0x179), a_dcyh  = ua_r32(fp + 0x181);
    u32 a_dcsrc = ua_r32(fp + 0x18B), a_colfn = ua_r32(fp + 0x191);
    u32 a_vh    = ua_r32(fp + 0x19D), a_toptx = ua_r32(fp + 0x1BF);
    u32 a_pixhi = ua_r32(fp + 0x1CF), a_phstp = ua_r32(fp + 0x1D5);
    u32 a_toptm = ua_r32(fp + 0x1FD), a_bottx = ua_r32(fp + 0x260);
    u32 a_pixlo = ua_r32(fp + 0x270), a_plstp = ua_r32(fp + 0x276);
    u32 a_bottm = ua_r32(fp + 0x2A4), a_msktx = ua_r32(fp + 0x302);
    u32 a_msktc = ua_r32(fp + 0x310), a_scstp = ua_r32(fp + 0x319);
    u32 a_tstp  = ua_r32(fp + 0x33F), a_bstp  = ua_r32(fp + 0x34C);

    u32 gc1 = (fn_eip + 0x18Au) + ua_r32(fp + 0x186);
    u32 gc2 = (fn_eip + 0x21Eu) + ua_r32(fp + 0x21A);
    u32 gc3 = (fn_eip + 0x2C5u) + ua_r32(fp + 0x2C1);
    if (gc1 != gc2 || gc1 != gc3)
        return 0;
    if (getcol_eip != gc1 && !pm_init_getcol_snap(gc1, mem + gc1))
        return 0;

    u32 vars[38] = {
        a_rwx, a_stopx, a_tfrac, a_tstp, a_bfrac, a_bstp, a_scale, a_scstp,
        a_mceil, a_mflr, a_segtx, a_cpln, a_fpln, a_cang, a_dist, a_offs,
        a_wlit, a_midtx, a_midtm, a_toptx, a_pixhi, a_phstp, a_toptm,
        a_bottx, a_pixlo, a_plstp, a_bottm, a_msktx, a_msktc,
        a_dccm, a_dcx, a_dcisc, a_dcyl, a_dcyh, a_dctm, a_dcsrc, a_colfn, a_vh
    };
    u32 or_al = 0;
    for (int i = 0; i < 38; i++) {
        if (!PM_IS_XRAM4(vars[i])) return 0;
        if (i != 37) or_al |= vars[i];
    }
    if ((or_al & 3u) != 0u || (a_vh & 1u) != 0u)
        return 0;
    if (!pm_span_ok(a_cc, 644u) || !pm_span_ok(a_fc, 644u) ||
        !pm_span_ok(a_x2v, 322u * 4u) || !pm_span_ok(a_ft, 4096u * 4u))
        return 0;

    seg_p.rw_x          = (u32 *)(void *)(mem + a_rwx);
    seg_p.rw_stopx      = (u32 *)(void *)(mem + a_stopx);
    seg_p.topfrac       = (u32 *)(void *)(mem + a_tfrac);
    seg_p.topstep       = (u32 *)(void *)(mem + a_tstp);
    seg_p.bottomfrac    = (u32 *)(void *)(mem + a_bfrac);
    seg_p.bottomstep    = (u32 *)(void *)(mem + a_bstp);
    seg_p.rw_scale      = (u32 *)(void *)(mem + a_scale);
    seg_p.rw_scalestep  = (u32 *)(void *)(mem + a_scstp);
    seg_p.markceiling   = (u32 *)(void *)(mem + a_mceil);
    seg_p.markfloor     = (u32 *)(void *)(mem + a_mflr);
    seg_p.segtextured   = (u32 *)(void *)(mem + a_segtx);
    seg_p.ceilingplane  = (u32 *)(void *)(mem + a_cpln);
    seg_p.floorplane    = (u32 *)(void *)(mem + a_fpln);
    seg_p.rw_centerangle= (u32 *)(void *)(mem + a_cang);
    seg_p.rw_distance   = (u32 *)(void *)(mem + a_dist);
    seg_p.rw_offset     = (u32 *)(void *)(mem + a_offs);
    seg_p.walllights    = (u32 *)(void *)(mem + a_wlit);
    seg_p.midtexture    = (u32 *)(void *)(mem + a_midtx);
    seg_p.rw_midtexmid  = (u32 *)(void *)(mem + a_midtm);
    seg_p.toptexture    = (u32 *)(void *)(mem + a_toptx);
    seg_p.pixhigh       = (u32 *)(void *)(mem + a_pixhi);
    seg_p.pixhighstep   = (u32 *)(void *)(mem + a_phstp);
    seg_p.rw_toptexmid  = (u32 *)(void *)(mem + a_toptm);
    seg_p.bottomtexture = (u32 *)(void *)(mem + a_bottx);
    seg_p.pixlow        = (u32 *)(void *)(mem + a_pixlo);
    seg_p.pixlowstep    = (u32 *)(void *)(mem + a_plstp);
    seg_p.rw_bottexmid  = (u32 *)(void *)(mem + a_bottm);
    seg_p.maskedtexture = (u32 *)(void *)(mem + a_msktx);
    seg_p.maskedtexcol  = (u32 *)(void *)(mem + a_msktc);
    seg_p.dc_colormap   = (u32 *)(void *)(mem + a_dccm);
    seg_p.dc_x          = (u32 *)(void *)(mem + a_dcx);
    seg_p.dc_iscale     = (u32 *)(void *)(mem + a_dcisc);
    seg_p.dc_yl         = (u32 *)(void *)(mem + a_dcyl);
    seg_p.dc_yh         = (u32 *)(void *)(mem + a_dcyh);
    seg_p.dc_texmid     = (u32 *)(void *)(mem + a_dctm);
    seg_p.dc_src        = (u32 *)(void *)(mem + a_dcsrc);
    seg_p.colfunc       = (u32 *)(void *)(mem + a_colfn);
    seg_p.viewheight    = (u32 *)(void *)(mem + a_vh);
    seg_p.cc_a = a_cc; seg_p.fc_a = a_fc;
    seg_p.x2v_a = a_x2v; seg_p.ft_a = a_ft;
    seg_p.getcol_target = gc1;
    segfn_eip = fn_eip;
    pm_guard_code(fn_eip, fn_eip + 883u);
    return 1;
}

static __attribute__((noinline)) int pm_init_mapplane_snap(u32 fn_eip, const u8 *fp)
{
    if (fn_eip + 385u > PM_CODE_GUARD_TOP || !pm_match_masked(fp, mapplane_tmpl, mapplane_mask, 385u))
        return 0;
    u32 a_vw     = ua_r32(fp + 0x01B), a_vh     = ua_r32(fp + 0x023);
    u32 a_ph     = ua_r32(fp + 0x045), a_ch     = ua_r32(fp + 0x04B);
    u32 a_ysl    = ua_r32(fp + 0x053), a_bxs    = ua_r32(fp + 0x065);
    u32 a_cdist  = ua_r32(fp + 0x071), a_bys    = ua_r32(fp + 0x07D);
    u32 a_xstep  = ua_r32(fp + 0x082), a_cxstep = ua_r32(fp + 0x088);
    u32 a_ystep  = ua_r32(fp + 0x095), a_cystep = ua_r32(fp + 0x09B);
    u32 a_dscale = ua_r32(fp + 0x0CD), a_vang   = ua_r32(fp + 0x0E2);
    u32 a_x2v    = ua_r32(fp + 0x0E8), a_fcos_p = ua_r32(fp + 0x0ED);
    u32 a_vx     = ua_r32(fp + 0x101), a_xfrac  = ua_r32(fp + 0x108);
    u32 a_fsin   = ua_r32(fp + 0x111), a_vy     = ua_r32(fp + 0x11D);
    u32 a_fcm    = ua_r32(fp + 0x127), a_yfrac  = ua_r32(fp + 0x12D);
    u32 a_dscm   = ua_r32(fp + 0x137), a_pzl    = ua_r32(fp + 0x152);
    u32 a_dsy    = ua_r32(fp + 0x164), a_dsx1   = ua_r32(fp + 0x16A);
    u32 a_dsx2   = ua_r32(fp + 0x16F), a_spnfn  = ua_r32(fp + 0x175);

    if (ua_r32(fp + 0x059) != a_ch    || ua_r32(fp + 0x0A3) != a_cdist  ||
        ua_r32(fp + 0x0AD) != a_cxstep|| ua_r32(fp + 0x0B2) != a_xstep  ||
        ua_r32(fp + 0x0B8) != a_cystep|| ua_r32(fp + 0x0BD) != a_ystep  ||
        ua_r32(fp + 0x15A) != a_dscm)
        return 0;

    u32 scs[20] = {
        a_vw, a_vh, a_ph, a_bxs, a_bys, a_xstep, a_ystep, a_vang, a_fcos_p, a_vx,
        a_xfrac, a_vy, a_fcm, a_yfrac, a_dscm, a_pzl, a_dsy, a_dsx1, a_dsx2, a_spnfn
    };
    u32 or_al = 0;
    for (int i = 0; i < 20; i++) {
        if (!PM_IS_XRAM4(scs[i])) return 0;
        or_al |= scs[i];
    }
    if ((or_al & 3u) != 0u) return 0;
    if (!pm_span_ok(a_ch, 200u * 4u)     || !pm_span_ok(a_ysl, 200u * 4u) ||
        !pm_span_ok(a_cdist, 200u * 4u)  || !pm_span_ok(a_cxstep, 200u * 4u) ||
        !pm_span_ok(a_cystep, 200u * 4u) || !pm_span_ok(a_dscale, 320u * 4u) ||
        !pm_span_ok(a_x2v, 320u * 4u)    || !pm_span_ok(a_fsin, 8192u * 4u) ||
        a_ch < PM_CODE_GUARD_TOP || a_cdist < PM_CODE_GUARD_TOP ||
        a_cxstep < PM_CODE_GUARD_TOP || a_cystep < PM_CODE_GUARD_TOP)
        return 0;

    mp_p.viewwidth     = (u32 *)(void *)(mem + a_vw);
    mp_p.viewheight    = (u32 *)(void *)(mem + a_vh);
    mp_p.planeheight   = (u32 *)(void *)(mem + a_ph);
    mp_p.basexscale    = (u32 *)(void *)(mem + a_bxs);
    mp_p.baseyscale    = (u32 *)(void *)(mem + a_bys);
    mp_p.ds_xstep      = (u32 *)(void *)(mem + a_xstep);
    mp_p.ds_ystep      = (u32 *)(void *)(mem + a_ystep);
    mp_p.viewangle     = (u32 *)(void *)(mem + a_vang);
    mp_p.finecosine_p  = (u32 *)(void *)(mem + a_fcos_p);
    mp_p.viewx         = (u32 *)(void *)(mem + a_vx);
    mp_p.ds_xfrac      = (u32 *)(void *)(mem + a_xfrac);
    mp_p.viewy         = (u32 *)(void *)(mem + a_vy);
    mp_p.fixedcolormap = (u32 *)(void *)(mem + a_fcm);
    mp_p.ds_yfrac      = (u32 *)(void *)(mem + a_yfrac);
    mp_p.ds_colormap   = (u32 *)(void *)(mem + a_dscm);
    mp_p.planezlight   = (u32 *)(void *)(mem + a_pzl);
    mp_p.ds_y          = (u32 *)(void *)(mem + a_dsy);
    mp_p.ds_x1         = (u32 *)(void *)(mem + a_dsx1);
    mp_p.ds_x2         = (u32 *)(void *)(mem + a_dsx2);
    mp_p.spanfunc      = (u32 *)(void *)(mem + a_spnfn);
    mp_p.ch_a = a_ch; mp_p.ysl_a = a_ysl; mp_p.cdist_a = a_cdist;
    mp_p.cxstep_a = a_cxstep; mp_p.cystep_a = a_cystep;
    mp_p.dscale_a = a_dscale; mp_p.x2v_a = a_x2v; mp_p.fsin_a = a_fsin;
    mapplane_eip = fn_eip;
    pm_guard_code(fn_eip, fn_eip + 385u);
    return 1;
}

INLINE u32 pm_fmul(s32 a, s32 b, u32 *out_hi)
{
    signed long long prod = (signed long long)a * (signed long long)b;
    if (out_hi) *out_hi = (u32)((unsigned long long)prod >> 32);
    return (u32)((unsigned long long)prod >> 16);
}

INLINE u32 pm_fast_wcl_lookup(u32 lump, u32 tag, u32 *out_lc_base)
{
    if (lump >= *wcl_p.numlumps || lump >= 0x40000u)
        return 0u;
    u32 lc_base = *wcl_p.lumpcache;
    if (!PM_IS_XRAM4(lc_base + lump * 4u))
        return 0u;
    u32 ptr = ua_r32(mem + lc_base + lump * 4u);
    if (ptr < 0x100020u || ptr >= RAM_BYTES - 4u)
        return 0u;
    if (ua_r32(mem + ptr - 12u) != 0x001D4A11u)
        return 0u;
    if ((s32)tag >= 100 && ua_r32(mem + ptr - 20u) < 0x100u)
        return 0u;
    *out_lc_base = lc_base;
    return ptr;
}

INLINE int pm_fast_getcol_lookup(u32 tex, u32 col, u32 *out_base, u32 *out_ofs, u32 *out_tag_addr, u32 *out_edx, s32 *out_cyc)
{
    if (tex >= 0x10000u) return 0;
    u32 wm_b = *getcol_p.wmask, cl_b = *getcol_p.clump, co_b = *getcol_p.cofs;
    if (!PM_IS_XRAM4(wm_b + tex * 4u) || !PM_IS_XRAM4(cl_b + tex * 4u) || !PM_IS_XRAM4(co_b + tex * 4u))
        return 0;
    u32 mc = col & ua_r32(mem + wm_b + tex * 4u);
    if (mc >= 0x10000u) return 0;
    u32 lp_a = ua_r32(mem + cl_b + tex * 4u) + mc * 2u;
    u32 of_a = ua_r32(mem + co_b + tex * 4u) + mc * 2u;
    if (!PM_IS_RAM2(lp_a) || !PM_IS_RAM2(of_a))
        return 0;
    s32 lump = (s16)ua_r16(mem + lp_a);
    u32 ofs  = (u16)ua_r16(mem + of_a);
    if (lump > 0) {
        u32 lc_b = 0, ptr = pm_fast_wcl_lookup((u32)lump, 101u, &lc_b);
        if (!ptr) return 0;
        *out_base = ptr;
        *out_ofs  = ofs;
        *out_tag_addr = ptr - 16u;
        *out_edx = lc_b;
        *out_cyc = 62 * PM_CYC;
        return 1;
    }
    u32 cp_b = *getcol_p.comp;
    if (!PM_IS_XRAM4(cp_b + tex * 4u)) return 0;
    u32 comp = ua_r32(mem + cp_b + tex * 4u);
    if (!comp) return 0;
    *out_base = comp;
    *out_ofs  = ofs;
    *out_tag_addr = 0u;
    *out_edx = cp_b;
    *out_cyc = 27 * PM_CYC;
    return 1;
}

INLINE int pm_modex_col_can_draw(s32 yl, s32 yh, u32 x, u32 dv, u32 esi, u32 cm, s32 *out_cyc)
{
    if (yl > yh) {
        *out_cyc = 6 * PM_CYC;
        return 1;
    }
    if ((u32)yl >= 200u || (u32)yh >= 200u)
        return 0;
    u32 count = (u32)(yh - yl) + 1u, half = count >> 1;
    u32 edi0 = (u32)yl * 80u + (x >> 2) + dv;
    if (edi0 < 0xA0000u || edi0 + (count - 1u) * 80u >= 0xB0000u)
        return 0;
    u32 ea_hi = cm & 0xFFFFFF00u;
    if (!pm_span_ok(esi, 128u) || !pm_span_ok(ea_hi, 256u) ||
        !(esi >= tmap_col_whi || esi + 128u <= tmap_col_wlo) ||
        !(ea_hi >= tmap_col_whi || ea_hi + 256u <= tmap_col_wlo))
        return 0;
    *out_cyc = (half == 0u)
        ? (66 * PM_CYC)
        : (s32)((56u + 5u * (count & 1u)) * (u32)PM_CYC + half * (u32)PM_FUSE_COL);
    return 1;
}

INLINE void pm_modex_col_exec(s32 yl, s32 yh, u32 x, u32 dv, u32 iscale, u32 cy, u32 tm, u32 esi, u32 cm, u32 *wr_io)
{
    if (yl > yh) {
        (void)sub32((u32)yl, (u32)yh, 0u);
        return;
    }
    u8 * const ram = mem;
    u32 count = (u32)(yh - yl) + 1u, half = count >> 1;
    u32 edi0 = (u32)yl * 80u + (x >> 2) + dv;
    u32 vo = edi0 - 0xA0000u;
    u8 *vp_plane = vram[x & 3u];
    seq[2] = (u8)(1u << (x & 3u));
    vga_single_ptr = vp_plane;

    *tmap_col_p.lc = count;
    *tmap_col_p.pc = 0u;
    u32 step = iscale << 9;
    ua_w32(ram + tmap_col_eip + 0x0D4u, step);
    ua_w32(ram + tmap_col_eip + 0x0E1u, step);

    pm_mark_vdirty_span(vo >> 8, (vo + (count - 1u) * 80u) >> 8);

    u8 *vp = vp_plane + vo;
    const u8 *tex = ram + esi, *cma = ram + (cm & 0xFFFFFF00u);
    u32 ebp = (tm - (cy - (u32)yl) * iscale) << 9;
    u32 i = 0;
    for (; i + 4u <= count; i += 4u, vp += 320) {
        __builtin_prefetch(vp + 320, 1, 0);
        u8 p0 = cma[tex[ebp >> 25]]; ebp += step;
        u8 p1 = cma[tex[ebp >> 25]]; ebp += step;
        u8 p2 = cma[tex[ebp >> 25]]; ebp += step;
        u8 p3 = cma[tex[ebp >> 25]]; ebp += step;
        vp[0]   = p0;
        vp[80]  = p1;
        vp[160] = p2;
        vp[240] = p3;
    }
    for (; i < count; i++, vp += 80) {
        vp[0] = cma[tex[ebp >> 25]];
        ebp += step;
    }
    (void)logic32(count & 1u);
    *wr_io += 3u + 3u * half + (count & 1u);
}

/* Shared core for R_RenderSegLoop (is_call=1 from L_call at +0x00, is_call=0 from JL -849 at +0x1B) */
static __attribute__((noinline)) const u8 *pm_run_segloop(int is_call, u32 ret_eip, s32 end_cyc)
{
#ifndef NO_FUSE_PUSHAD
    if (__builtin_expect(tmap_col_eip == 0xFFFFFFFFu && PM_IS_XRAM4(*seg_p.colfunc), 0))
        (void)pm_init_col_snap(*seg_p.colfunc, mem + *seg_p.colfunc);
#endif
    if (tmap_col_eip == 0xFFFFFFFFu || getcol_eip != seg_p.getcol_target || wcl_eip != getcol_p.wcl_target ||
        *seg_p.colfunc != tmap_col_eip || seq_i != 2u || vga_fast_lut[1] == 0)
        return 0;
    u8 * const ram = mem;
    u32 esp_base = is_call ? (rESP - 28u) : rESP;
    if (esp_base < 0x100060u || esp_base >= RAM_BYTES - 32u)
        return 0;
    if (!(esp_base - 40u >= tmap_col_hi || esp_base + 28u <= tmap_col_lo))
        return 0;

    s32 cyc_cnt = c.cycles;
    u32 wr_cnt  = c.wr_total;
    s32 rw_x    = (s32)*seg_p.rw_x;
    s32 stopx   = (s32)*seg_p.rw_stopx;
    u32 texcol  = is_call ? 0u : rECX;

    if (is_call) {
        if (cyc_cnt + 18 * PM_CYC > end_cyc)
            return 0;
        if (rw_x >= stopx) {
            ua_w32(ram + esp_base + 24u, ret_eip);
            ua_w32(ram + esp_base + 20u, rEBX);
            ua_w32(ram + esp_base + 16u, rECX);
            ua_w32(ram + esp_base + 12u, rEDX);
            ua_w32(ram + esp_base +  8u, rESI);
            ua_w32(ram + esp_base +  4u, rEDI);
            ua_w32(ram + esp_base +  0u, rEBP);
            rEAX = (u32)rw_x;
            (void)sub32((u32)rw_x, (u32)stopx, 0u);
            c.cycles = cyc_cnt + 18 * PM_CYC;
            c.wr_total = wr_cnt + 7u;
            return ram + ret_eip;
        }
        cyc_cnt += 11 * PM_CYC;
    }

    if (rw_x < 0 || stopx > 320 || rw_x >= stopx)
        return 0;

    s32 topfrac    = (s32)*seg_p.topfrac,    topstep    = (s32)*seg_p.topstep;
    s32 bottomfrac = (s32)*seg_p.bottomfrac, bottomstep = (s32)*seg_p.bottomstep;
    s32 rw_scale   = (s32)*seg_p.rw_scale,   scalestep  = (s32)*seg_p.rw_scalestep;
    u32 mceil  = *seg_p.markceiling, mflr  = *seg_p.markfloor, segtx = *seg_p.segtextured;
    u32 midtx  = *seg_p.midtexture,  toptx = *seg_p.toptexture, bottx = *seg_p.bottomtexture;
    u32 msktx  = *seg_p.maskedtexture;
    u32 cpln   = *seg_p.ceilingplane, fpln = *seg_p.floorplane;
    u32 wlit   = *seg_p.walllights,  msktc = *seg_p.maskedtexcol;
    s32 pixhi  = (s32)*seg_p.pixhigh, phstp = (s32)*seg_p.pixhighstep;
    s32 pixlo  = (s32)*seg_p.pixlow,  plstp = (s32)*seg_p.pixlowstep;
    u32 dv     = *tmap_col_p.dv, cy = *tmap_col_p.cy;
    s16 vh_s16 = (s16)ua_r16(ram + ((u32)((const u8 *)seg_p.viewheight - ram)));

    if (mceil && (cpln < 0x100000u || cpln + 0x158u + (u32)stopx > RAM_BYTES)) return 0;
    if (mflr  && (fpln < 0x100000u || fpln + 0x158u + (u32)stopx > RAM_BYTES)) return 0;
    if (msktx && !midtx && !pm_span_ok(msktc, (u32)stopx * 2u)) return 0;

    u32 cols_done = 0u;
    while (rw_x < stopx) {
        s16 cc_cur = (s16)ua_r16(ram + seg_p.cc_a + (u32)rw_x * 2u);
        s16 fc_cur = (s16)ua_r16(ram + seg_p.fc_a + (u32)rw_x * 2u);
        s32 raw_yl = (topfrac + 0xFFF) >> 12;
        s32 ccp1   = (s32)cc_cur + 1;
        s32 yl     = (raw_yl < ccp1) ? ccp1 : raw_yl;
        s32 step_c = (10 + (raw_yl < ccp1 ? 1 : 0)) * PM_CYC;
        if (mceil) {
            s32 bot_c = yl - 1;
            step_c += (9 + (bot_c >= (s32)fc_cur ? 1 : 0)) * PM_CYC;
            if (bot_c >= (s32)fc_cur) bot_c = (s32)fc_cur - 1;
            if (ccp1 <= bot_c) step_c += 4 * PM_CYC;
        }

        s32 raw_yh = bottomfrac >> 12;
        s32 yh     = (raw_yh >= (s32)fc_cur) ? ((s32)fc_cur - 1) : raw_yh;
        step_c += (8 + (raw_yh >= (s32)fc_cur ? 1 : 0)) * PM_CYC;
        if (mflr) {
            s32 top_f = yh + 1;
            step_c += (9 + (top_f <= (s32)cc_cur ? 1 : 0)) * PM_CYC;
            if (top_f <= (s32)cc_cur) top_f = (s32)cc_cur + 1;
            if (top_f <= (s32)fc_cur - 1) step_c += 4 * PM_CYC;
        }

        u32 next_texcol = texcol;
        u32 next_cm = *seg_p.dc_colormap, next_isc = *seg_p.dc_iscale;
        if (!segtx) {
            step_c += 2 * PM_CYC;
        } else {
            u32 ang = (*seg_p.rw_centerangle + ua_r32(ram + seg_p.x2v_a + (u32)rw_x * 4u)) >> 19;
            if (ang >= 4096u || (u32)rw_scale == 0u) break;
            s32 ft = (s32)ua_r32(ram + seg_p.ft_a + ang * 4u);
            s32 dist = (s32)*seg_p.rw_distance;
            u32 prod = (u32)(((signed long long)ft * (signed long long)dist) >> 16);
            next_texcol = (u32)(((s32)(*seg_p.rw_offset - prod)) >> 16);
            s32 lidx = rw_scale >> 12;
            int clamped = ((u32)lidx >= 48u);
            if (clamped) lidx = 47;
            if (!PM_IS_XRAM4(wlit + (u32)lidx * 4u)) break;
            next_cm  = ua_r32(ram + wlit + (u32)lidx * 4u);
            next_isc = 0xFFFFFFFFu / (u32)rw_scale;
            step_c += (27 + clamped) * PM_CYC + PM_FUSE_FMUL + PM_DIV_CYC;
        }

        /* Pre-validate texture column & Mode X draw bounds before mutating column state! */
        u32 mid_b = 0, mid_o = 0, mid_src = 0, mid_tag = 0;
        u32 top_b = 0, top_o = 0, top_src = 0, top_tag = 0;
        u32 bot_b = 0, bot_o = 0, bot_src = 0, bot_tag = 0, dummy_edx = 0;
        s32 gc_c = 0, col_c = 0;
        s32 mid_top = 0, mid_bot = 0;
        s16 new_cc = cc_cur;

        if (midtx) {
            if (!pm_fast_getcol_lookup(midtx, next_texcol, &mid_b, &mid_o, &mid_tag, &dummy_edx, &gc_c))
                break;
            mid_src = mid_b + mid_o;
            if (!pm_modex_col_can_draw(yl, yh, (u32)rw_x, dv, mid_src, next_cm, &col_c))
                break;
            step_c += 17 * PM_CYC + gc_c + col_c;
        } else {
            step_c += 3 * PM_CYC;
            if (!toptx) {
                step_c += (5 + (mceil ? 4 : 2)) * PM_CYC;
                if (mceil) new_cc = (s16)(yl - 1);
            } else {
                s32 raw_m = pixhi >> 12;
                mid_top = (raw_m >= (s32)fc_cur) ? ((s32)fc_cur - 1) : raw_m;
                step_c += (16 + (raw_m >= (s32)fc_cur ? 1 : 0)) * PM_CYC;
                if (mid_top >= yl) {
                    if (!pm_fast_getcol_lookup(toptx, next_texcol, &top_b, &top_o, &top_tag, &dummy_edx, &gc_c))
                        break;
                    top_src = top_b + top_o;
                    if (!pm_modex_col_can_draw(yl, mid_top, (u32)rw_x, dv, top_src, next_cm, &col_c))
                        break;
                    step_c += 12 * PM_CYC + gc_c + col_c;
                    new_cc = (s16)mid_top;
                } else {
                    step_c += 4 * PM_CYC;
                    new_cc = (s16)(yl - 1);
                }
            }
            if (!bottx) {
                step_c += (5 + (mflr ? 4 : 2)) * PM_CYC;
            } else {
                s32 raw_m = (pixlo + 0xFFF) >> 12;
                mid_bot = (raw_m <= (s32)new_cc) ? ((s32)new_cc + 1) : raw_m;
                step_c += (17 + (raw_m <= (s32)new_cc ? 1 : 0)) * PM_CYC;
                if (mid_bot <= yh) {
                    if (!pm_fast_getcol_lookup(bottx, next_texcol, &bot_b, &bot_o, &bot_tag, &dummy_edx, &gc_c))
                        break;
                    bot_src = bot_b + bot_o;
                    if (!pm_modex_col_can_draw(mid_bot, yh, (u32)rw_x, dv, bot_src, next_cm, &col_c))
                        break;
                    step_c += 12 * PM_CYC + gc_c + col_c;
                } else {
                    step_c += 4 * PM_CYC;
                }
            }
            step_c += (msktx ? 5 : 2) * PM_CYC;
        }
        step_c += 18 * PM_CYC;

        s32 tail_need = (rw_x + 1 == stopx) ? (7 * PM_CYC) : 0;
        if (cyc_cnt + step_c + tail_need > end_cyc)
            break;

        /* Commit column! */
        if (mceil) {
            s32 bot_c = (yl - 1 >= (s32)fc_cur) ? ((s32)fc_cur - 1) : (yl - 1);
            if (ccp1 <= bot_c) {
                ram[cpln + (u32)rw_x + 0x15u]  = (u8)ccp1;
                ram[cpln + (u32)rw_x + 0x157u] = (u8)bot_c;
                wr_cnt += 2u;
            }
        }
        if (mflr) {
            s32 top_f = (yh + 1 <= (s32)cc_cur) ? ((s32)cc_cur + 1) : (yh + 1);
            if (top_f <= (s32)fc_cur - 1) {
                ram[fpln + (u32)rw_x + 0x15u]  = (u8)top_f;
                ram[fpln + (u32)rw_x + 0x157u] = (u8)(fc_cur - 1);
                wr_cnt += 2u;
            }
        }
        if (segtx) {
            texcol = next_texcol;
            *seg_p.dc_colormap = next_cm;
            *seg_p.dc_x        = (u32)rw_x;
            *seg_p.dc_iscale   = next_isc;
            wr_cnt += 3u;
        }
        if (midtx) {
            if (mid_tag) { ua_w32(ram + mid_tag, 101u); wr_cnt++; }
            *seg_p.dc_yl     = (u32)yl;
            *seg_p.dc_yh     = (u32)yh;
            *seg_p.dc_texmid = *seg_p.rw_midtexmid;
            *seg_p.dc_src    = mid_src;
            wr_cnt += 4u;
            pm_modex_col_exec(yl, yh, (u32)rw_x, dv, next_isc, cy, *seg_p.rw_midtexmid, mid_src, next_cm, &wr_cnt);
            ua_w16(ram + seg_p.cc_a + (u32)rw_x * 2u, (u16)vh_s16);
            ua_w16(ram + seg_p.fc_a + (u32)rw_x * 2u, 0xFFFFu);
            wr_cnt += 2u;
        } else {
            if (toptx) {
                pixhi += phstp;
                *seg_p.pixhigh = (u32)pixhi;
                wr_cnt++;
                if (mid_top >= yl) {
                    if (top_tag) { ua_w32(ram + top_tag, 101u); wr_cnt++; }
                    *seg_p.dc_yl     = (u32)yl;
                    *seg_p.dc_yh     = (u32)mid_top;
                    *seg_p.dc_texmid = *seg_p.rw_toptexmid;
                    *seg_p.dc_src    = top_src;
                    wr_cnt += 4u;
                    pm_modex_col_exec(yl, mid_top, (u32)rw_x, dv, next_isc, cy, *seg_p.rw_toptexmid, top_src, next_cm, &wr_cnt);
                }
                ua_w16(ram + seg_p.cc_a + (u32)rw_x * 2u, (u16)new_cc);
                wr_cnt++;
            } else if (mceil) {
                ua_w16(ram + seg_p.cc_a + (u32)rw_x * 2u, (u16)new_cc);
                wr_cnt++;
            }
            if (bottx) {
                pixlo += plstp;
                *seg_p.pixlow = (u32)pixlo;
                wr_cnt++;
                if (mid_bot <= yh) {
                    if (bot_tag) { ua_w32(ram + bot_tag, 101u); wr_cnt++; }
                    *seg_p.dc_yl     = (u32)mid_bot;
                    *seg_p.dc_yh     = (u32)yh;
                    *seg_p.dc_texmid = *seg_p.rw_bottexmid;
                    *seg_p.dc_src    = bot_src;
                    wr_cnt += 4u;
                    pm_modex_col_exec(mid_bot, yh, (u32)rw_x, dv, next_isc, cy, *seg_p.rw_bottexmid, bot_src, next_cm, &wr_cnt);
                    ua_w16(ram + seg_p.fc_a + (u32)rw_x * 2u, (u16)mid_bot);
                } else {
                    ua_w16(ram + seg_p.fc_a + (u32)rw_x * 2u, (u16)(yh + 1));
                }
                wr_cnt++;
            } else if (mflr) {
                ua_w16(ram + seg_p.fc_a + (u32)rw_x * 2u, (u16)(yh + 1));
                wr_cnt++;
            }
            if (msktx) {
                ua_w16(ram + msktc + (u32)rw_x * 2u, (u16)texcol);
                wr_cnt++;
            }
        }

        rw_x++;
        rw_scale   += scalestep;
        topfrac    += topstep;
        bottomfrac += bottomstep;
        *seg_p.rw_scale   = (u32)rw_scale;
        *seg_p.rw_x       = (u32)rw_x;
        *seg_p.topfrac    = (u32)topfrac;
        *seg_p.bottomfrac = (u32)bottomfrac;
        wr_cnt += 4u;
        cyc_cnt += step_c;
        cols_done++;
    }

    if (cols_done == 0u)
        return 0;

    if (is_call) {
        ua_w32(ram + esp_base + 24u, ret_eip);
        ua_w32(ram + esp_base + 20u, rEBX);
        ua_w32(ram + esp_base + 16u, rECX);
        ua_w32(ram + esp_base + 12u, rEDX);
        ua_w32(ram + esp_base +  8u, rESI);
        ua_w32(ram + esp_base +  4u, rEDI);
        ua_w32(ram + esp_base +  0u, rEBP);
        wr_cnt += 7u;
    }

    (void)sub32((u32)rw_x, (u32)stopx, 0u);
    if (rw_x >= stopx) {
        if (!is_call) {
            rEBP = ua_r32(ram + esp_base +  0u);
            rEDI = ua_r32(ram + esp_base +  4u);
            rESI = ua_r32(ram + esp_base +  8u);
            rEDX = ua_r32(ram + esp_base + 12u);
            rECX = ua_r32(ram + esp_base + 16u);
            rEBX = ua_r32(ram + esp_base + 20u);
            u32 r_eip = ua_r32(ram + esp_base + 24u);
            if ((u32)(r_eip - 0x100000u) >= (RAM_BYTES - 0x100010u))
                return 0;
            rESP = esp_base + 28u;
            ret_eip = r_eip;
        }
        rEAX = (u32)bottomstep;
        c.cycles = cyc_cnt + 7 * PM_CYC;
        c.wr_total = wr_cnt;
        return ram + ret_eip;
    }

    /* Paused mid-seg (slice boundary or uncached column): resume cleanly at 0x18e99b (+0x1B)! */
    if (is_call)
        rESP = esp_base;
    rEAX = (u32)bottomstep;
    rEBX = (u32)rw_scale;
    rECX = texcol;
    rEDX = (u32)stopx;
    rESI = (u32)topfrac;
    rEDI = (u32)bottomfrac;
    rEBP = (u32)rw_x;
    c.cycles = idle_pm32(segfn_eip + 0x1Bu, cyc_cnt, wr_cnt);
    c.wr_total = wr_cnt;
    return ram + segfn_eip + 0x1Bu;
}

static __attribute__((noinline)) const u8 *pm_try_fuse_call(const u8 *cand, u32 ret_eip, s32 end_cyc)
{
    u8 * const ram = mem;
    u32 fn_eip = (u32)(cand - ram);
    u32 esp0 = rESP;
    if (esp0 < 0x100060u || esp0 >= RAM_BYTES - 4u)
        return 0;

    /* 1. R_PointOnSide (171 B, zero relocations) */
    if (fn_eip == pos_eip || (__builtin_expect(pos_eip == 0xFFFFFFFFu && ua_r32(cand) == 0x7B835651u, 0) &&
        fn_eip + 171u <= PM_CODE_GUARD_TOP && pm_mem_eq(cand, pos_tmpl, 171u) &&
        (pos_eip = fn_eip, pm_guard_code(fn_eip, fn_eip + 171u), 1))) {
        u32 ebx = rEBX;
        if (!PM_IS_XRAM4(ebx) || !PM_IS_XRAM4(ebx + 12u) || !(esp0 - 12u >= ebx + 16u || esp0 <= ebx))
            return 0;
        s32 x = (s32)rEAX, y = (s32)rEDX;
        s32 nx  = (s32)ua_r32(ram + ebx);
        s32 ny  = (s32)ua_r32(ram + ebx + 4u);
        s32 ndx = (s32)ua_r32(ram + ebx + 8u);
        s32 ndy = (s32)ua_r32(ram + ebx + 12u);
        s32 cyc = 0;
        if (ndx == 0) {
            cyc = ((x == nx) ? 11 : 14) * PM_CYC;
            if (c.cycles + cyc > end_cyc) return 0;
            rEDX = (u32)nx;
            if (x == nx) { (void)sub32((u32)x, (u32)nx, 0u); rEAX = 2u; }
            else if (x <= nx) rEAX = logic32(ndy > 0 ? 1u : 0u);
            else              rEAX = logic32(ndy < 0 ? 1u : 0u);
        } else if (ndy == 0) {
            cyc = ((x == ny) ? 14 : 18) * PM_CYC;
            if (c.cycles + cyc > end_cyc) return 0;
            if (x == ny) { (void)sub32((u32)x, (u32)ny, 0u); rEAX = 2u; }
            else if (y <= ny) rEAX = logic32(ndx < 0 ? 1u : 0u);
            else              rEAX = logic32(ndx > 0 ? 1u : 0u);
        } else {
            s32 dx = (s32)((u32)x - (u32)nx), dy = (s32)((u32)y - (u32)ny);
            s32 left  = (s32)((u32)(ndy >> 16) * (u32)(dx >> 16));
            s32 right = (s32)((u32)(dy >> 16)  * (u32)(ndx >> 16));
            cyc = ((right < left) ? 25 : 27) * PM_CYC;
            if (c.cycles + cyc > end_cyc) return 0;
            rEDX = (u32)left;
            rEBX = (u32)(dy >> 16);
            if (right < left) {
                rEAX = logic32(0u);
            } else {
                (void)sub32((u32)left, (u32)right, 0u);
                rEAX = (left == right) ? 2u : 1u;
            }
        }
        ua_w32(ram + esp0 - 4u, ret_eip);
        ua_w32(ram + esp0 - 8u, rECX);
        ua_w32(ram + esp0 - 12u, rESI);
        c.cycles += cyc;
        c.wr_total += 3u;
        return ram + ret_eip;
    }

    /* 2. R_GetColumn (111 B) */
    if (fn_eip == getcol_eip || (__builtin_expect(getcol_eip == 0xFFFFFFFFu &&
        ua_r32(cand) == 0x89565153u && cand[4] == 0xC3u, 0) && pm_init_getcol_snap(fn_eip, cand))) {
        if (wcl_eip != getcol_p.wcl_target)
            return 0;
        u32 base_p = 0, ofs = 0, tag_a = 0, out_edx = 0;
        s32 cyc = 0;
        if (!pm_fast_getcol_lookup(rEAX, rEDX, &base_p, &ofs, &tag_a, &out_edx, &cyc))
            return 0;
        if (c.cycles + cyc > end_cyc)
            return 0;
        if (tag_a) {
            if (!(esp0 - 40u >= tag_a + 4u || esp0 <= tag_a))
                return 0;
            ua_w32(ram + tag_a, 101u);
            c.wr_total++;
        }
        ua_w32(ram + esp0 - 4u, ret_eip);
        ua_w32(ram + esp0 - 8u, rEBX);
        ua_w32(ram + esp0 - 12u, rECX);
        ua_w32(ram + esp0 - 16u, rESI);
        rEDX = out_edx;
        rEAX = add32(base_p, ofs, 0u);
        c.cycles += cyc;
        c.wr_total += 4u;
        return ram + ret_eip;
    }

    /* 3. W_CacheLumpNum (cache hit) */
    if (fn_eip == wcl_eip || (__builtin_expect(wcl_eip == 0xFFFFFFFFu && ua_r32(cand) == 0x57565153u, 0) &&
        pm_init_wcl_snap(fn_eip, cand))) {
        u32 lump = rEAX, tag = rEDX, lc_b = 0;
        u32 ptr = pm_fast_wcl_lookup(lump, tag, &lc_b);
        if (!ptr) return 0;
        s32 cyc = (((s32)tag < 100) ? 34 : 36) * PM_CYC;
        if (c.cycles + cyc > end_cyc) return 0;
        u32 tag_a = ptr - 16u;
        if (!(esp0 - 28u >= tag_a + 4u || esp0 <= tag_a))
            return 0;
        ua_w32(ram + tag_a, tag);
        ua_w32(ram + esp0 - 4u, ret_eip);
        ua_w32(ram + esp0 - 8u, rEBX);
        ua_w32(ram + esp0 - 12u, rECX);
        ua_w32(ram + esp0 - 16u, rESI);
        ua_w32(ram + esp0 - 20u, rEDI);
        if ((s32)tag < 100) (void)sub32(tag, 0x64u, 0u);
        else                (void)sub32(ua_r32(ram + ptr - 20u), 0x100u, 0u);
        rEDX = lc_b;
        rEAX = ptr;
        c.cycles += cyc;
        c.wr_total += 6u;
        return ram + ret_eip;
    }

    /* 4. FixedDiv (65 B, zero relocations) */
    if (fn_eip == fdiv_eip || (__builtin_expect(fdiv_eip == 0xFFFFFFFFu &&
        ua_r32(cand) == 0x89565153u && cand[4] == 0xC1u, 0) &&
        fn_eip + 65u <= PM_CODE_GUARD_TOP && pm_mem_eq(cand, fdiv_tmpl, 65u) &&
        (fdiv_eip = fn_eip, pm_guard_code(fn_eip, fn_eip + 65u), 1))) {
        s32 a = (s32)rEAX, b = (s32)rEDX;
        u32 d1 = (u32)(a >> 31), ua = ((u32)a ^ d1) - d1;
        u32 esi_v = (u32)((s32)ua >> 14);
        u32 d2 = (u32)(b >> 31), ub = ((u32)b ^ d2) - d2;
        if ((s32)esi_v >= (s32)ub) {
            if (c.cycles + 25 * PM_CYC > end_cyc) return 0;
            u32 neg = (((u32)a ^ (u32)b) >> 31) & 1u;
            rEDX = d2;
            rEAX = add32(neg, 0x7FFFFFFFu, 0u);
            c.cycles += 25 * PM_CYC;
        } else {
            if (b == 0 || c.cycles + 25 * PM_CYC + PM_DIV_CYC > end_cyc) return 0;
            u32 uq = 0, urem = 0;
            if (dos_divu64_32(ua >> 16, ua << 16, ub, &uq, &urem) < 0) return 0;
            int neg_n = (d1 != 0u), neg_q = neg_n ^ (d2 != 0u);
            if (uq > (neg_q ? 0x80000000u : 0x7FFFFFFFu)) return 0;
            (void)shift32_fast(4u, (u32)a, 16u);
            rEAX = neg_q ? (0u - uq) : uq;
            rEDX = neg_n ? (0u - urem) : urem;
            c.cycles += 25 * PM_CYC + PM_DIV_CYC;
        }
        ua_w32(ram + esp0 - 4u, ret_eip);
        ua_w32(ram + esp0 - 8u, rEBX);
        ua_w32(ram + esp0 - 12u, rECX);
        ua_w32(ram + esp0 - 16u, rESI);
        c.wr_total += 4u;
        return ram + ret_eip;
    }

    /* 5. R_RenderSegLoop (883 B) */
    if (fn_eip == segfn_eip || (__builtin_expect(segfn_eip == 0xFFFFFFFFu &&
        ua_r32(cand) == 0x56525153u && cand[5] == 0x55u, 0) && pm_init_segfn_snap(fn_eip, cand))) {
        return pm_run_segloop(1, ret_eip, end_cyc);
    }

    /* 6. R_DrawMaskedColumn (233 B) */
    if (fn_eip == mcol_eip || (__builtin_expect(mcol_eip == 0xFFFFFFFFu &&
        ua_r32(cand) == 0x56525153u && cand[5] == 0x8Bu, 0) && pm_init_mcol_snap(fn_eip, cand))) {
#ifndef NO_FUSE_PUSHAD
        if (__builtin_expect(tmap_col_eip == 0xFFFFFFFFu && PM_IS_XRAM4(*mcol_p.colfunc), 0))
            (void)pm_init_col_snap(*mcol_p.colfunc, ram + *mcol_p.colfunc);
#endif
        if (tmap_col_eip == 0xFFFFFFFFu || *mcol_p.colfunc != tmap_col_eip ||
            seq_i != 2u || vga_fast_lut[1] == 0)
            return 0;
        u32 col_ptr = rEAX;
        if (!PM_IS_XRAM4(col_ptr) || !(esp0 - 60u >= tmap_col_hi || esp0 <= tmap_col_lo))
            return 0;
        u8 top0 = ram[col_ptr];
        if (top0 == 0xFFu) {
            if (c.cycles + 21 * PM_CYC > end_cyc) return 0;
            ua_w32(ram + esp0 - 4u, ret_eip);
            ua_w32(ram + esp0 - 8u, rEBX);
            ua_w32(ram + esp0 - 12u, rECX);
            ua_w32(ram + esp0 - 16u, rEDX);
            ua_w32(ram + esp0 - 20u, rESI);
            ua_w32(ram + esp0 - 24u, rEDI);
            (void)sub8(0xFFu, 0xFFu, 0u);
            rEAX = (col_ptr & 0xFFFF00FFu) | 0xFF00u;
            c.cycles += 21 * PM_CYC;
            c.wr_total += 9u;
            return ram + ret_eip;
        }
        u32 dc_x = *mcol_p.dc_x, mfc_b = *mcol_p.mfloorclip, mcc_b = *mcol_p.mceilingclip;
        if (dc_x >= 320u || !PM_IS_RAM2(mfc_b + dc_x * 2u) || !PM_IS_RAM2(mcc_b + dc_x * 2u))
            return 0;
        s32 mfc = (s16)ua_r16(ram + mfc_b + dc_x * 2u);
        s32 mcc = (s16)ua_r16(ram + mcc_b + dc_x * 2u);
        s32 spry = (s32)*mcol_p.spryscale, sprtop = (s32)*mcol_p.sprtopscreen;
        u32 orig_tm = *mcol_p.dc_texmid, dv = *tmap_col_p.dv, cy = *tmap_col_p.cy;
        u32 isc = *tmap_col_p.isc, cm = *tmap_col_p.cm;
        s32 tot_cyc = 21 * PM_CYC;
        u32 p_cur = col_ptr, posts = 0;
        while (posts < 64u) {
            if (p_cur < 0x100000u || p_cur + 6u > RAM_BYTES) return 0;
            u8 td = ram[p_cur], len = ram[p_cur + 1u];
            if (p_cur + (u32)len + 5u > RAM_BYTES) return 0;
            s32 ts = sprtop + spry * (s32)td;
            s32 bs = ts + spry * (s32)len;
            s32 raw_yh = (bs - 1) >> 16, raw_yl = (ts + 0xFFFF) >> 16;
            s32 yh = (raw_yh >= mfc) ? (mfc - 1) : raw_yh;
            s32 yl = (raw_yl <= mcc) ? (mcc + 1) : raw_yl;
            tot_cyc += (28 + (raw_yh >= mfc ? 1 : 0) + (raw_yl <= mcc ? 1 : 0)) * PM_CYC;
            if (yl <= yh) {
                s32 cc = 0;
                if (!pm_modex_col_can_draw(yl, yh, dc_x, dv, p_cur + 3u, cm, &cc))
                    return 0;
                tot_cyc += 18 * PM_CYC + cc;
            } else {
                tot_cyc += 9 * PM_CYC;
            }
            p_cur += (u32)len + 4u;
            posts++;
            if (ram[p_cur] == 0xFFu) break;
        }
        if (ram[p_cur] != 0xFFu || c.cycles + tot_cyc > end_cyc)
            return 0;

        u32 wr_cnt = c.wr_total + 9u;
        p_cur = col_ptr;
        u32 last_len = 0;
        s32 last_yl = (s32)*mcol_p.dc_yl, last_yh = (s32)*mcol_p.dc_yh;
        for (;;) {
            u8 td = ram[p_cur], len = ram[p_cur + 1u];
            last_len = len;
            s32 ts = sprtop + spry * (s32)td;
            s32 bs = ts + spry * (s32)len;
            s32 yh = ((bs - 1) >> 16 >= mfc) ? (mfc - 1) : ((bs - 1) >> 16);
            s32 yl = ((ts + 0xFFFF) >> 16 <= mcc) ? (mcc + 1) : ((ts + 0xFFFF) >> 16);
            last_yl = yl; last_yh = yh;
            if (yl <= yh) {
                u32 p_tm = orig_tm - ((u32)td << 16);
                *mcol_p.dc_src = p_cur + 3u;
                pm_modex_col_exec(yl, yh, dc_x, dv, isc, cy, p_tm, p_cur + 3u, cm, &wr_cnt);
                wr_cnt += 4u;
            } else {
                wr_cnt += 2u;
            }
            p_cur += (u32)len + 4u;
            if (ram[p_cur] == 0xFFu) break;
        }
        *mcol_p.dc_texmid = orig_tm;
        *mcol_p.dc_yh     = (u32)last_yh;
        *mcol_p.dc_yl     = (u32)last_yl;
        ua_w32(ram + esp0 - 4u, ret_eip);
        ua_w32(ram + esp0 - 8u, rEBX);
        ua_w32(ram + esp0 - 12u, rECX);
        ua_w32(ram + esp0 - 16u, rEDX);
        ua_w32(ram + esp0 - 20u, rESI);
        ua_w32(ram + esp0 - 24u, rEDI);
        (void)sub8(0xFFu, 0xFFu, 0u);
        rEAX = last_len;
        c.cycles += tot_cyc;
        c.wr_total = wr_cnt;
        return ram + ret_eip;
    }

    /* 7. R_MapPlane (385 B) + inline *spanfunc (R_DrawSpan) */
    if (fn_eip == mapplane_eip || (__builtin_expect(mapplane_eip == 0xFFFFFFFFu &&
        ua_r32(cand) == 0x55575651u, 0) && pm_init_mapplane_snap(fn_eip, cand))) {
        u32 sf = *mp_p.spanfunc;
#ifndef NO_FUSE_PUSHAD
        if (__builtin_expect(tmap_spn_eip == 0xFFFFFFFFu && PM_IS_XRAM4(sf), 0))
            (void)pm_init_spn_snap(sf, ram + sf);
#endif
        if (tmap_spn_eip != sf || seq_i != 2u || vga_fast_lut[1] == 0 || esp0 < 0x100080u)
            return 0;
        u32 y = rEAX, x1 = rEDX, x2 = rEBX;
        if ((s32)x1 > (s32)x2 || (s32)x1 < 0 || (s32)x2 >= (s32)*mp_p.viewwidth ||
            y > *mp_p.viewheight || y >= 200u || x2 >= 320u)
            return 0;
        u32 ang = (*mp_p.viewangle + ua_r32(ram + mp_p.x2v_a + x1 * 4u)) >> 19;
        u32 fcos_b = *mp_p.finecosine_p, pzl_b = *mp_p.planezlight;
        if (ang >= 8192u || !PM_IS_XRAM4(fcos_b + ang * 4u))
            return 0;
        u32 ph = *mp_p.planeheight, ch = ua_r32(ram + mp_p.ch_a + y * 4u);
        int hit = (ph == ch);
        u32 dist = hit ? ua_r32(ram + mp_p.cdist_a + y * 4u)
                       : pm_fmul((s32)ph, (s32)ua_r32(ram + mp_p.ysl_a + y * 4u), 0);
        u32 fcm = *mp_p.fixedcolormap;
        s32 lidx = (s32)dist >> 20;
        int clamped = ((u32)lidx >= 128u);
        s32 cl_idx = clamped ? 127 : lidx;
        if (fcm == 0u && !PM_IS_XRAM4(pzl_b + (u32)cl_idx * 4u))
            return 0;

        s32 pre_cyc = (hit ? (59 * PM_CYC + 3 * PM_FUSE_FMUL) : (69 * PM_CYC + 6 * PM_FUSE_FMUL))
                    + ((fcm != 0u) ? (2 * PM_CYC) : ((7 + clamped) * PM_CYC));
        if (c.cycles + pre_cyc > end_cyc)
            return 0;

        u32 sv_ecx = rECX, sv_esi = rESI, sv_edi = rEDI, sv_ebp = rEBP;
        u32 xstep, ystep, wr_pre;
        if (hit) {
            xstep = ua_r32(ram + mp_p.cxstep_a + y * 4u);
            ystep = ua_r32(ram + mp_p.cystep_a + y * 4u);
            wr_pre = 11u;
        } else {
            ua_w32(ram + mp_p.ch_a + y * 4u, ph);
            ua_w32(ram + mp_p.cdist_a + y * 4u, dist);
            xstep = pm_fmul((s32)dist, (s32)*mp_p.basexscale, 0);
            ystep = pm_fmul((s32)dist, (s32)*mp_p.baseyscale, 0);
            ua_w32(ram + mp_p.cxstep_a + y * 4u, xstep);
            ua_w32(ram + mp_p.cystep_a + y * 4u, ystep);
            wr_pre = 15u;
        }
        *mp_p.ds_xstep = xstep;
        *mp_p.ds_ystep = ystep;

        u32 length = pm_fmul((s32)dist, (s32)ua_r32(ram + mp_p.dscale_a + x1 * 4u), 0);
        u32 xfrac  = pm_fmul((s32)ua_r32(ram + fcos_b + ang * 4u), (s32)length, 0) + *mp_p.viewx;
        u32 sin_hi = 0;
        u32 sin_m  = pm_fmul((s32)ua_r32(ram + mp_p.fsin_a + ang * 4u), (s32)length, &sin_hi);
        u32 yfrac  = (0u - *mp_p.viewy) - sin_m;
        *mp_p.ds_xfrac = xfrac;
        *mp_p.ds_yfrac = yfrac;

        u32 spn_ecx, cm;
        if (fcm != 0u) {
            (void)logic32(fcm);
            spn_ecx = fcm;
            cm = fcm;
        } else {
            (void)sub32((u32)lidx, 0x80u, 0u);
            spn_ecx = (u32)cl_idx;
            cm = ua_r32(ram + pzl_b + (u32)cl_idx * 4u);
        }
        *mp_p.ds_colormap = cm;
        *mp_p.ds_y  = y;
        *mp_p.ds_x1 = x1;
        *mp_p.ds_x2 = x2;

        ua_w32(ram + esp0 -  4u, ret_eip);
        ua_w32(ram + esp0 -  8u, sv_ecx);
        ua_w32(ram + esp0 - 12u, sv_esi);
        ua_w32(ram + esp0 - 16u, sv_edi);
        ua_w32(ram + esp0 - 20u, sv_ebp);
        ua_w32(ram + esp0 - 24u, x2);
        ua_w32(ram + esp0 - 28u, dist);
        ua_w32(ram + esp0 - 32u, x1 * 4u);
        ua_w32(ram + esp0 - 36u, fn_eip + 0x179u);

        rEAX = x2; rECX = spn_ecx; rEDX = sin_hi; rEBX = yfrac;
        rESP = esp0 - 36u; rEBP = ang; rESI = x1; rEDI = y;
        c.cycles += pre_cyc;
        c.wr_total += wr_pre;

#ifndef NO_FUSE_PUSHAD
        if (pm_try_fuse_pushad(sf, ram + sf)) {
            if (c.cycles + 6 * PM_CYC <= end_cyc) {
                rESP = esp0;
                (void)add32(esp0 - 32u, 12u, 0u);
                rEBP = sv_ebp; rEDI = sv_edi; rESI = sv_esi; rECX = sv_ecx;
                c.cycles += 6 * PM_CYC;
                return ram + ret_eip;
            }
            return ram + fn_eip + 0x179u;
        }
#endif
        return ram + sf;
    }

    /* 8. R_PointOnSide (189 B, zero relocations, ~85 calls/VGAf in BSP traversal) */
    if (fn_eip == rnode_eip ||
        (__builtin_expect(rnode_eip == 0xFFFFFFFFu && ua_r32(cand) == 0x55575651u &&
         cand[4] == 0x89u && cand[0x0B] == 0x26u, 0) &&
         fn_eip + 189u <= PM_CODE_GUARD_TOP && pm_mem_eq(cand, rnode_tmpl, 189u) &&
         (rnode_eip = fn_eip, pm_guard_code(fn_eip, fn_eip + 189u), 1))) {
        u32 node_p = rEBX;
        if (!PM_IS_XRAM4(node_p) || !PM_IS_XRAM4(node_p + 12u) ||
            !(esp0 - 20u >= node_p + 16u || esp0 <= node_p))
            return 0;
        s32 x = (s32)rEAX, y = (s32)rEDX;
        s32 nx  = (s32)ua_r32(ram + node_p);
        s32 ny  = (s32)ua_r32(ram + node_p + 4u);
        s32 ndx = (s32)ua_r32(ram + node_p + 8u);
        s32 ndy = (s32)ua_r32(ram + node_p + 12u);
        s32 cyc = 0;
        if (ndx == 0) {
            cyc = 17 * PM_CYC;
            if (c.cycles + cyc > end_cyc) return 0;
            if (x <= nx) rEAX = logic32(ndy > 0 ? 1u : 0u);
            else         rEAX = logic32(ndy < 0 ? 1u : 0u);
        } else if (ndy == 0) {
            cyc = 19 * PM_CYC;
            if (c.cycles + cyc > end_cyc) return 0;
            if (y <= ny) rEAX = logic32(ndx < 0 ? 1u : 0u);
            else         rEAX = logic32(ndx > 0 ? 1u : 0u);
        } else {
            u32 dx = (u32)x - (u32)nx, dy = (u32)y - (u32)ny;
            if ((((u32)ndy ^ (u32)ndx ^ dx ^ dy) & 0x80000000u) != 0u) {
                u32 xb = dx ^ (u32)ndy;
                cyc = ((xb & 0x80000000u) ? 32 : 31) * PM_CYC;
                if (c.cycles + cyc > end_cyc) return 0;
                rEDX = (u32)ndx;
                rEBX = xb;
                if ((xb & 0x80000000u) == 0u) {
                    rEAX = logic32(0u);
                } else {
                    (void)logic32(xb & 0x80000000u);
                    rEAX = 1u;
                }
            } else {
                u32 hi2 = 0;
                s32 left  = (s32)pm_fmul(ndy >> 16, (s32)dx, 0);
                s32 right = (s32)pm_fmul((s32)dy, ndx >> 16, &hi2);
                cyc = 38 * PM_CYC + 2 * PM_FUSE_FMUL;
                if (c.cycles + cyc > end_cyc) return 0;
                rEBX = (u32)(ndx >> 16);
                rEDX = hi2;
                if (right < left) {
                    rEAX = logic32(0u);
                } else {
                    (void)sub32((u32)right, (u32)left, 0u);
                    rEAX = 1u;
                }
            }
        }
        ua_w32(ram + esp0 -  4u, ret_eip);
        ua_w32(ram + esp0 -  8u, rECX);
        ua_w32(ram + esp0 - 12u, rESI);
        ua_w32(ram + esp0 - 16u, rEDI);
        ua_w32(ram + esp0 - 20u, rEBP);
        c.cycles += cyc;
        return ram + ret_eip;
    }

    /* 9. P_PointOnLineSide (163 B, zero relocations) */
    if (fn_eip == rpos1_eip ||
        (__builtin_expect(rpos1_eip == 0xFFFFFFFFu && ua_r32(cand) == 0x55575651u &&
         cand[4] == 0x89u && cand[0x0B] == 0x28u, 0) &&
         fn_eip + 163u <= PM_CODE_GUARD_TOP && pm_mem_eq(cand, rpos_tmpl, 163u) &&
         (rpos1_eip = fn_eip, pm_guard_code(fn_eip, fn_eip + 163u), 1))) {
        u32 line_p = rEBX;
        if (!PM_IS_XRAM4(line_p) || !PM_IS_XRAM4(line_p + 12u) ||
            !(esp0 - 20u >= line_p + 16u || esp0 <= line_p))
            return 0;
        u32 v1_p = ua_r32(ram + line_p);
        if (!PM_IS_XRAM4(v1_p) || !PM_IS_XRAM4(v1_p + 4u) ||
            !(esp0 - 20u >= v1_p + 8u || esp0 <= v1_p))
            return 0;
        s32 x = (s32)rEAX, y = (s32)rEDX;
        s32 vx  = (s32)ua_r32(ram + v1_p);
        s32 vy  = (s32)ua_r32(ram + v1_p + 4u);
        s32 ndx = (s32)ua_r32(ram + line_p + 8u);
        s32 ndy = (s32)ua_r32(ram + line_p + 12u);
        s32 cyc = 0;
        if (ndx == 0) {
            cyc = 18 * PM_CYC;
            if (c.cycles + cyc > end_cyc) return 0;
            rEDX = v1_p;
            if (x <= vx) rEAX = logic32(ndy > 0 ? 1u : 0u);
            else         rEAX = logic32(ndy < 0 ? 1u : 0u);
        } else if (ndy == 0) {
            cyc = 20 * PM_CYC;
            if (c.cycles + cyc > end_cyc) return 0;
            if (y <= vy) rEAX = logic32(ndx < 0 ? 1u : 0u);
            else         rEAX = logic32(ndx > 0 ? 1u : 0u);
        } else {
            u32 hi2 = 0;
            s32 left  = (s32)pm_fmul(ndy >> 16, (s32)((u32)x - (u32)vx), 0);
            s32 right = (s32)pm_fmul((s32)((u32)y - (u32)vy), ndx >> 16, &hi2);
            cyc = 32 * PM_CYC + 2 * PM_FUSE_FMUL;
            if (c.cycles + cyc > end_cyc) return 0;
            rEBX = (u32)(ndx >> 16);
            rEDX = hi2;
            if (right < left) {
                rEAX = logic32(0u);
            } else {
                (void)sub32((u32)right, (u32)left, 0u);
                rEAX = 1u;
            }
        }
        ua_w32(ram + esp0 -  4u, ret_eip);
        ua_w32(ram + esp0 -  8u, rECX);
        ua_w32(ram + esp0 - 12u, rESI);
        ua_w32(ram + esp0 - 16u, rEDI);
        ua_w32(ram + esp0 - 20u, rEBP);
        c.cycles += cyc;
        return ram + ret_eip;
    }

    /* 10. R_PointToAngle (547 B, ~85 calls/VGAf in DEMO1 & DEMO2) */
    if (fn_eip == pta_eip ||
        (__builtin_expect(pta_eip == 0xFFFFFFFFu && ua_r32(cand) == 0x57565153u &&
         cand[4] == 0x55u && cand[5] == 0x89u, 0) && pm_init_pta_snap(fn_eip, cand))) {
        u32 tt_a = pta_p.tanto_a;
        if (!(esp0 - 24u >= tt_a + 2049u * 4u || esp0 <= tt_a) ||
            !(esp0 - 24u >= pta_p.vx_a + 4u || esp0 <= pta_p.vx_a) ||
            !(esp0 - 24u >= pta_p.vy_a + 4u || esp0 <= pta_p.vy_a))
            return 0;
        u32 vx = *pta_p.viewx, vy = *pta_p.viewy;
        u32 dx = rEAX - vx, dy = rEDX - vy;
        const u32 *tt = (const u32 *)(const void *)(ram + tt_a);
        s32 cyc = 0;
        u32 out_eax = 0, out_edx = vx;
        if ((dx | dy) == 0u) {
            cyc = 21 * PM_CYC;
            if (c.cycles + cyc > end_cyc) return 0;
            out_eax = logic32(0u);
        } else {
            if (dx == 0x80000000u || dy == 0x80000000u) return 0;
            int dx_z2 = (dx == 0u) ? 2 : 0;
            if ((s32)dx >= 0) {
                if ((s32)dy >= 0) {
                    if (dx > dy) {
                        if (dx < 0x200u) {
                            cyc = 37 * PM_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            (void)sub32(dx, 0x200u, 0u);
                            out_eax = tt[0x800];
                        } else {
                            cyc = 43 * PM_CYC + PM_DIV_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            u32 q = (dy << 3) / (dx >> 8);
                            u32 idx = add32((q - 0x800u) & (q < 0x800u ? ~0u : 0u), 0x800u, 0u);
                            out_edx = 0x800u;
                            out_eax = tt[idx];
                        }
                    } else {
                        u32 idx;
                        if (dy < 0x200u) {
                            cyc = (40 + dx_z2) * PM_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            idx = 0x800u;
                        } else {
                            cyc = (46 + dx_z2) * PM_CYC + PM_DIV_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            u32 q = (dx << 3) / (dy >> 8);
                            idx = (q < 0x800u) ? q : 0x800u;
                            out_edx = 0x800u;
                        }
                        out_eax = sub32(0x3FFFFFFFu, tt[idx], 0u);
                    }
                } else {
                    u32 udy = 0u - dy;
                    if (dx > udy) {
                        u32 idx;
                        if (dx < 0x200u) {
                            cyc = 38 * PM_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            idx = 0x800u;
                        } else {
                            cyc = 44 * PM_CYC + PM_DIV_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            u32 q = (udy << 3) / (dx >> 8);
                            idx = (q < 0x800u) ? q : 0x800u;
                            out_edx = 0x800u;
                        }
                        u32 tv = tt[idx];
                        out_eax = sub32(0u, tv, 0u);
                        c.fl = (c.fl & ~F_CF) | (tv != 0u);
                    } else {
                        if (udy < 0x200u) {
                            cyc = (39 + dx_z2) * PM_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            (void)sub32(udy, 0x200u, 0u);
                            out_eax = 0xC0000000u + tt[0x800];
                        } else {
                            cyc = (47 + dx_z2) * PM_CYC + PM_DIV_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            u32 q = (dx << 3) / (udy >> 8);
                            u32 idx = add32((q - 0x800u) & (q < 0x800u ? ~0u : 0u), 0x800u, 0u);
                            out_edx = 0x800u;
                            out_eax = 0xC0000000u + tt[idx];
                        }
                    }
                }
            } else {
                u32 udx = 0u - dx;
                if ((s32)dy >= 0) {
                    if (udx > dy) {
                        u32 idx;
                        if (udx < 0x200u) {
                            cyc = 40 * PM_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            idx = 0x800u;
                        } else {
                            cyc = 46 * PM_CYC + PM_DIV_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            u32 q = (dy << 3) / (udx >> 8);
                            idx = (q < 0x800u) ? q : 0x800u;
                        }
                        u32 tv = tt[idx];
                        out_edx = tv;
                        out_eax = sub32(0x7FFFFFFFu, tv, 0u);
                    } else {
                        if (dy < 0x200u) {
                            cyc = 39 * PM_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            (void)sub32(dy, 0x200u, 0u);
                            out_eax = 0x40000000u + tt[0x800];
                        } else {
                            cyc = 45 * PM_CYC + PM_DIV_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            u32 q = (udx << 3) / (dy >> 8);
                            u32 idx = add32((q - 0x800u) & (q < 0x800u ? ~0u : 0u), 0x800u, 0u);
                            out_edx = 0x800u;
                            out_eax = 0x40000000u + tt[idx];
                        }
                    }
                } else {
                    u32 udy = 0u - dy;
                    if (udx > udy) {
                        if (udx < 0x200u) {
                            cyc = 40 * PM_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            (void)sub32(udx, 0x200u, 0u);
                            out_eax = 0x80000000u + tt[0x800];
                        } else {
                            cyc = 46 * PM_CYC + PM_DIV_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            u32 q = (udy << 3) / (udx >> 8);
                            u32 idx = add32((q - 0x800u) & (q < 0x800u ? ~0u : 0u), 0x800u, 0u);
                            out_edx = 0x800u;
                            out_eax = 0x80000000u + tt[idx];
                        }
                    } else {
                        u32 idx;
                        if (udy < 0x200u) {
                            cyc = 41 * PM_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            idx = 0x800u;
                        } else {
                            cyc = 49 * PM_CYC + PM_DIV_CYC;
                            if (c.cycles + cyc > end_cyc) return 0;
                            u32 q = (udx << 3) / (udy >> 8);
                            idx = (q < 0x800u) ? q : 0x800u;
                            out_edx = 0x800u;
                        }
                        out_eax = sub32(0xBFFFFFFFu, tt[idx], 0u);
                    }
                }
            }
        }
        rEAX = out_eax;
        rEDX = out_edx;
        ua_w32(ram + esp0 -  4u, ret_eip);
        ua_w32(ram + esp0 -  8u, rEBX);
        ua_w32(ram + esp0 - 12u, rECX);
        ua_w32(ram + esp0 - 16u, rESI);
        ua_w32(ram + esp0 - 20u, rEDI);
        ua_w32(ram + esp0 - 24u, rEBP);
        c.cycles += cyc;
        return ram + ret_eip;
    }

    /* 11. Watcom outp(port, val) (14 B, ~62 calls/VGAf on Mode X 0x3C5 plane select) */
    if (fn_eip == outp_eip ||
        (__builtin_expect(outp_eip == 0xFFFFFFFFu && ua_r32(cand) == 0xC3895153u, 0) &&
         fn_eip + 14u <= PM_CODE_GUARD_TOP && pm_mem_eq(cand, outp_tmpl, 14u) &&
         (outp_eip = fn_eip, pm_guard_code(fn_eip, fn_eip + 14u), 1))) {
        if (rEAX == 0x3C5u && seq_i == 2u) {
            if (c.cycles + 10 * PM_CYC > end_cyc) return 0;
            u8 val = (u8)rEDX;
            seq[2] = val;
            vga_single_ptr = vga_fast_lut[val & 15u];
            ua_w32(ram + esp0 -  4u, ret_eip);
            ua_w32(ram + esp0 -  8u, rEBX);
            ua_w32(ram + esp0 - 12u, rECX);
            rEDX = 0x3C5u;
            rEAX = 0x300u | val;
            c.cycles += 10 * PM_CYC;
            c.wr_total += 1u;
            return ram + ret_eip;
        }
        return 0;
    }

    return 0;
}

/* Fuses R_DrawVisSprite sprite column loop (0x18fc47..0x18fc85, disp == -63) */
static __attribute__((noinline)) const u8 *pm_fuse_visspr63(const u8 *ip, s32 end_cyc)
{
    u8 * const ram = mem;
    u32 op_eip = (u32)(ip - ram);
    if (op_eip != visspr63_eip) {
        if (op_eip + 63u > PM_CODE_GUARD_TOP || !pm_match_masked(ip, visspr63_tmpl, visspr63_mask, 63u))
            return ip;
        u32 mc_tgt = (op_eip + 0x28u) + ua_r32(ip + 0x24);
        if (mcol_eip != mc_tgt && (mcol_eip != 0xFFFFFFFFu || !PM_IS_XRAM4(mc_tgt) || !pm_init_mcol_snap(mc_tgt, ram + mc_tgt)))
            return ip;
        u32 a_dcx1 = ua_r32(ip + 0x29), a_dcx2 = ua_r32(ip + 0x37);
        if (a_dcx1 != a_dcx2 || ram + a_dcx1 != (u8 *)mcol_p.dc_x)
            return ip;
        visspr63_eip = op_eip;
        pm_guard_code(op_eip, op_eip + 63u);
    }
#ifndef NO_FUSE_PUSHAD
    if (__builtin_expect(tmap_col_eip == 0xFFFFFFFFu && PM_IS_XRAM4(*mcol_p.colfunc), 0))
        (void)pm_init_col_snap(*mcol_p.colfunc, ram + *mcol_p.colfunc);
#endif
    if (mcol_eip == 0xFFFFFFFFu || tmap_col_eip == 0xFFFFFFFFu || *mcol_p.colfunc != tmap_col_eip ||
        seq_i != 2u || vga_fast_lut[1] == 0)
        return ip;

    u32 esp0 = rESP, esi = rESI, edi = rEDI;
    if (esp0 < 0x100080u || esp0 >= RAM_BYTES - 4u ||
        !(esp0 - 64u >= tmap_col_hi || esp0 <= tmap_col_lo) ||
        !pm_span_ok(esi, 8u) || !pm_span_ok(edi, 0x2Cu) ||
        !(esp0 - 64u >= edi + 0x2Cu || esp0 <= edi))
        return ip;

    s32 patch_w = (s16)ua_r16(ram + esi);
    if (patch_w <= 0 || patch_w > 1024 || !pm_span_ok(esi, 8u + (u32)patch_w * 4u) ||
        !(esp0 - 64u >= esi + 8u + (u32)patch_w * 4u || esp0 <= esi))
        return ip;

    u32 xiscale = ua_r32(ram + edi + 0x28u);
    s32 x2      = (s32)ua_r32(ram + edi + 0x0Cu);
    s32 dc_x    = (s32)*mcol_p.dc_x;
    if (dc_x < 0 || x2 >= 320 || dc_x > x2)
        return ip;
    u32 mfc_b = *mcol_p.mfloorclip, mcc_b = *mcol_p.mceilingclip;
    if (!pm_span_ok(mfc_b, (u32)(x2 + 1) * 2u) || !pm_span_ok(mcc_b, (u32)(x2 + 1) * 2u))
        return ip;

    s32 spry = (s32)*mcol_p.spryscale, sprtop = (s32)*mcol_p.sprtopscreen;
    u32 orig_tm = *mcol_p.dc_texmid, dv = *tmap_col_p.dv, cy = *tmap_col_p.cy;
    u32 isc = *tmap_col_p.isc, cm = *tmap_col_p.cm;
    u32 frac = rECX, cur_ebx = rEBX;
    s32 cyc_cnt = c.cycles;
    u32 wr_cnt  = c.wr_total;
    u32 cols_done = 0u;

    while (dc_x <= x2) {
        s32 texcol = (s32)frac >> 16;
        if (texcol < 0 || texcol >= patch_w)
            break;
        u32 col_ptr = esi + ua_r32(ram + esi + 8u + (u32)texcol * 4u);
        if (!PM_IS_XRAM4(col_ptr))
            break;

        s32 mcol_cyc = 21 * PM_CYC;
        u8 top0 = ram[col_ptr];
        if (top0 != 0xFFu) {
            s32 mfc = (s16)ua_r16(ram + mfc_b + (u32)dc_x * 2u);
            s32 mcc = (s16)ua_r16(ram + mcc_b + (u32)dc_x * 2u);
            u32 p_cur = col_ptr, posts = 0;
            int ok = 1;
            while (posts < 64u) {
                if (p_cur < 0x100000u || p_cur + 6u > RAM_BYTES) { ok = 0; break; }
                u8 td = ram[p_cur], len = ram[p_cur + 1u];
                if (p_cur + (u32)len + 5u > RAM_BYTES) { ok = 0; break; }
                s32 ts = sprtop + spry * (s32)td;
                s32 bs = ts + spry * (s32)len;
                s32 raw_yh = (bs - 1) >> 16, raw_yl = (ts + 0xFFFF) >> 16;
                s32 yh = (raw_yh >= mfc) ? (mfc - 1) : raw_yh;
                s32 yl = (raw_yl <= mcc) ? (mcc + 1) : raw_yl;
                mcol_cyc += (28 + (raw_yh >= mfc ? 1 : 0) + (raw_yl <= mcc ? 1 : 0)) * PM_CYC;
                if (yl <= yh) {
                    s32 cc = 0;
                    if (!pm_modex_col_can_draw(yl, yh, (u32)dc_x, dv, p_cur + 3u, cm, &cc)) { ok = 0; break; }
                    mcol_cyc += 18 * PM_CYC + cc;
                } else {
                    mcol_cyc += 9 * PM_CYC;
                }
                p_cur += (u32)len + 4u;
                posts++;
                if (ram[p_cur] == 0xFFu) break;
            }
            if (!ok || ram[p_cur] != 0xFFu)
                break;
        }

        if (cyc_cnt + 18 * PM_CYC + mcol_cyc > end_cyc)
            break;

        if (top0 != 0xFFu) {
            s32 mfc = (s16)ua_r16(ram + mfc_b + (u32)dc_x * 2u);
            s32 mcc = (s16)ua_r16(ram + mcc_b + (u32)dc_x * 2u);
            u32 p_cur = col_ptr;
            s32 last_yl = (s32)*mcol_p.dc_yl, last_yh = (s32)*mcol_p.dc_yh;
            for (;;) {
                u8 td = ram[p_cur], len = ram[p_cur + 1u];
                s32 ts = sprtop + spry * (s32)td;
                s32 bs = ts + spry * (s32)len;
                s32 yh = ((bs - 1) >> 16 >= mfc) ? (mfc - 1) : ((bs - 1) >> 16);
                s32 yl = ((ts + 0xFFFF) >> 16 <= mcc) ? (mcc + 1) : ((ts + 0xFFFF) >> 16);
                last_yl = yl; last_yh = yh;
                if (yl <= yh) {
                    u32 p_tm = orig_tm - ((u32)td << 16);
                    *mcol_p.dc_src = p_cur + 3u;
                    pm_modex_col_exec(yl, yh, (u32)dc_x, dv, isc, cy, p_tm, p_cur + 3u, cm, &wr_cnt);
                    wr_cnt += 4u;
                } else {
                    wr_cnt += 2u;
                }
                p_cur += (u32)len + 4u;
                if (ram[p_cur] == 0xFFu) break;
            }
            *mcol_p.dc_texmid = orig_tm;
            *mcol_p.dc_yh     = (u32)last_yh;
            *mcol_p.dc_yl     = (u32)last_yl;
        }
        ua_w32(ram + esp0 -  4u, op_eip + 0x28u);
        ua_w32(ram + esp0 -  8u, cur_ebx);
        ua_w32(ram + esp0 - 12u, frac);
        ua_w32(ram + esp0 - 16u, (u32)texcol);
        ua_w32(ram + esp0 - 20u, esi);
        ua_w32(ram + esp0 - 24u, edi);
        wr_cnt += 9u;

        dc_x++;
        frac += xiscale;
        *mcol_p.dc_x = (u32)dc_x;
        wr_cnt++;
        cur_ebx = (u32)x2;
        cyc_cnt += 18 * PM_CYC + mcol_cyc;
        cols_done++;
    }

    if (cols_done == 0u)
        return ip;

    rEAX = (u32)dc_x;
    rECX = frac;
    rEDX = xiscale;
    rEBX = (u32)x2;
    (void)sub32((u32)dc_x, (u32)x2, 0u);
    if (dc_x > x2) {
        c.cycles = cyc_cnt;
        c.wr_total = wr_cnt;
        return ip + 63;
    }
    c.cycles = idle_pm32(op_eip, cyc_cnt, wr_cnt);
    c.wr_total = wr_cnt;
    return ip;
}
#endif


/* Exact x86 basic-block loop fusion for hot 32-bit TASM/Watcom inner loops
   (DMX 16-bit audio resampler & pack, Mode X R_DrawColumn, and 64x64 flat R_DrawSpan).
   Matches the exact guest machine-code byte sequence at `ip` so it works at any
   linear address and preserves 100% bit-exact register, flag, and write state. */
static __attribute__((noinline)) const u8 *pm_try_fuse_jnz(
    const u8 *ip, const u8 *ip_lim, s32 disp, s32 end_cyc)
{
    if (ip + (u32)(-disp) > ip_lim)
        return ip;
    u8 * const ram = mem;
    s32 cyc_cnt = c.cycles;
    u32 wr_cnt = writes;

    if (disp == -12) {
        static const u8 sig12[12] = {
            0x80,0x7A,0x15,0xFF, 0x75,0x06, 0x40, 0x42, 0x39,0xD8, 0x7E,0xF4
        };
        s32 sa = (s32)rEAX, sb_v = (s32)rEBX;
        if (sa > sb_v || (u32)(sb_v - sa) > 1024u || !pm_mem_eq(ip, sig12, 12u))
            return ip;
        u32 eax = rEAX, edx = rEDX, rem_max = (u32)(sb_v - sa) + 1u;
        if (!pm_span_ok(edx + 0x15u, rem_max))
            return ip;
        u32 ran = 0, hit = 0, done_scan = 0;
        for (;;) {
            u8 b = ram[edx + 0x15u];
            if (b != 0xFFu) {
                if (cyc_cnt + PM_FUSE_VIS_HIT > end_cyc) break;
                (void)sub8(b, 0xFFu, 0u);
                cyc_cnt += PM_FUSE_VIS_HIT;
                hit = 1u;
                break;
            }
            if (cyc_cnt + PM_FUSE_VIS > end_cyc) break;
            eax++;
            edx++;
            ran = 1u;
            cyc_cnt += PM_FUSE_VIS;
            if ((s32)eax > sb_v) {
                done_scan = 1u;
                break;
            }
        }
        if (!ran && !hit) return ip;
        rEAX = eax; rEDX = edx;
        if (hit) {
            c.cycles = cyc_cnt;
            return ip + 12;
        }
        (void)sub32(eax, rEBX, 0u);
        if (!done_scan) cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
        c.cycles = cyc_cnt;
        return done_scan ? (ip + 12) : ip;
    }

    if (disp == -18) {
        if (ip[16] == 0xEBu) {
            static const u8 sig18_pat[18] = {
                0x89,0xD1, 0x4A, 0x85,0xC9, 0x74,0x0B, 0x83,0xC0,0x50,
                0x8A,0x0B, 0x43, 0x88,0x48,0xB0, 0xEB,0xEE
            };
            if (!pm_mem_eq(ip, sig18_pat, 18u)) return ip;
            u32 edx = rEDX;
            if (edx == 0u) {
                if (cyc_cnt + PM_FUSE_PAT_END > end_cyc) return ip;
                rECX = 0u; rEDX = 0xFFFFFFFFu;
                c.fl = 0u; c.zs = 0; c.pb = 0u;
                c.cycles = cyc_cnt + PM_FUSE_PAT_END;
                return ip + 18;
            }
            if (cyc_cnt + PM_FUSE_PAT > end_cyc || edx > 200u || vga_single_ptr == 0)
                return ip;
            u32 eax = rEAX, ebx = rEBX;
            if (eax >= 0xA0000u && eax + (edx - 1u) * 80u < 0xB0000u && pm_span_ok(ebx, edx)) {
                u8 *vp = vga_single_ptr;
                u32 ecx = 0, cf_add = 0, af_of_inc = 0;
                do {
                    u32 cur_cnt = edx--;
                    u32 wo = eax - 0xA0000u;
                    u32 na = eax + 80u;
                    cf_add = (na < eax) ? F_CF : 0u;
                    eax = na;
                    u8 cl = ram[ebx];
                    u32 nb = ebx + 1u;
                    af_of_inc = ((ebx ^ nb) & F_AF) | (nb == 0x80000000u ? F_OF : 0u);
                    ebx = nb;
                    vdirty[wo >> 8] = 1;
                    vp[wo] = cl;
                    wr_cnt++;
                    ecx = (cur_cnt & 0xFFFFFF00u) | cl;
                    cyc_cnt += PM_FUSE_PAT;
                } while (edx != 0u && cyc_cnt + PM_FUSE_PAT <= end_cyc);
                rEAX = eax; rEBX = ebx;
                writes = wr_cnt;
                if (edx == 0u && cyc_cnt + PM_FUSE_PAT_END <= end_cyc) {
                    rECX = 0u; rEDX = 0xFFFFFFFFu;
                    c.fl = 0u; c.zs = 0; c.pb = 0u;
                    c.cycles = cyc_cnt + PM_FUSE_PAT_END;
                    return ip + 18;
                }
                rECX = ecx; rEDX = edx;
                c.fl = cf_add | af_of_inc;
                c.zs = ZS32(ebx); c.pb = ebx;
                cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
                c.cycles = cyc_cnt;
                return ip;
            }
            return ip;
        }
        static const u8 sig18[18] = {
            0x8A,0x06, 0x02,0xF2, 0x13,0xF5, 0x0F,0xBE,0x18,
            0x66,0x01,0x1F, 0x83,0xC7,0x02, 0x49, 0x75,0xEE
        };
        if (cyc_cnt + PM_FUSE_MIX > end_cyc) return ip;
        u32 esi = rESI, edi = rEDI, ecx = rECX, ebp = rEBP, ea_hi = rEAX & 0xFFFFFF00u;
        if (ecx > 0u && ecx <= 0x10000u && ebp <= 16u && pm_mem_eq(ip, sig18, 18u) &&
            pm_span_ok(esi, ecx * (ebp + 1u)) && pm_span_ok(ea_hi, 256u) &&
            pm_span_ok(edi, ecx * 2u) && (edi >= 0x100000u || edi + ecx * 2u <= 0x9FFFFu) &&
            (edi + ecx * 2u <= esi   || esi + ecx * (ebp + 1u) <= edi) &&
            (edi + ecx * 2u <= ea_hi || ea_hi + 256u <= edi)) {
            u32 dl = rDL, dh = rDH, al = 0, ebx = 0, cf_add = 0, old_ecx;
            do {
                al = ram[esi];
                u32 s8sum = dh + dl;
                dh = s8sum & 0xFFu;
                esi += ebp + (s8sum >> 8);
                ebx = (u32)(s32)(s8)ram[ea_hi | al];
                ua_w16(ram + edi, (u16)(ua_r16(ram + edi) + ebx));
                wr_cnt++;
                u32 nedi = edi + 2u;
                cf_add = (nedi < edi) ? F_CF : 0u;
                edi = nedi;
                old_ecx = ecx;
                ecx = old_ecx - 1u;
                cyc_cnt += PM_FUSE_MIX;
            } while (ecx != 0u && cyc_cnt + PM_FUSE_MIX <= end_cyc);
            rEAX = ea_hi | al; rEBX = ebx; rECX = ecx; rDH = (u8)dh;
            rESI = esi; rEDI = edi;
            c.fl = cf_add | ((old_ecx ^ ecx) & F_AF) | (old_ecx == 0x80000000u ? F_OF : 0u);
            c.zs = ZS32(ecx); c.pb = ecx;
            writes = wr_cnt;
            if (ecx != 0u) cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
            c.cycles = cyc_cnt;
            return (ecx == 0u) ? (ip + 18) : ip;
        }
        return ip;
    }

    if (disp == -20) {
        static const u8 m20_0[14] = {
            0x39,0xF0, 0x7D,0x10, 0x39,0xD0, 0x7F,0x0C, 0x83,0xC0,0x04, 0x41, 0x89,0xA8
        };
        if (ip[18] == 0xEBu && ip[19] == 0xECu && pm_mem_eq(ip, m20_0, 14u)) {
            u32 eax = rEAX, esi = rESI, edx = rEDX;
            if ((s32)eax >= (s32)esi) {
                if (cyc_cnt + PM_FUSE_VIS_HIT > end_cyc) return ip;
                (void)sub32(eax, esi, 0u);
                c.cycles = cyc_cnt + PM_FUSE_VIS_HIT;
                return ip + 20;
            }
            if ((s32)eax > (s32)edx) {
                if (cyc_cnt + PM_FUSE_PAT_END > end_cyc) return ip;
                (void)sub32(eax, edx, 0u);
                c.cycles = cyc_cnt + PM_FUSE_PAT_END;
                return ip + 20;
            }
            if (cyc_cnt + PM_FUSE_MSP20 > end_cyc || (s32)eax < 0)
                return ip;
            s32 s_lim = ((s32)esi - 1 < (s32)edx) ? ((s32)esi - 1) : (s32)edx;
            u32 n_max = ((u32)(s_lim - (s32)eax) >> 2) + 1u;
            u32 span_off = ua_r32(ip + 14), wr_lo = span_off + eax + 4u;
            if (n_max <= 1024u && pm_span_ok(wr_lo, n_max * 4u) &&
                (wr_lo >= 0x100000u || wr_lo + n_max * 4u <= 0x9FFFFu)) {
                u32 ecx = rECX, ebp = rEBP, old_ecx = ecx, cf_add = 0;
                do {
                    u32 na = eax + 4u;
                    cf_add = (na < eax) ? F_CF : 0u;
                    eax = na;
                    old_ecx = ecx;
                    ecx = old_ecx + 1u;
                    PM_WR32_RAM(ram + span_off + eax, ebp);
                    cyc_cnt += PM_FUSE_MSP20;
                } while ((s32)eax <= s_lim && cyc_cnt + PM_FUSE_MSP20 <= end_cyc);
                rEAX = eax; rECX = ecx;
                writes = wr_cnt;
                if ((s32)eax >= (s32)esi && cyc_cnt + PM_FUSE_VIS_HIT <= end_cyc) {
                    (void)sub32(eax, esi, 0u);
                    c.cycles = cyc_cnt + PM_FUSE_VIS_HIT;
                    return ip + 20;
                }
                if ((s32)eax > (s32)edx && cyc_cnt + PM_FUSE_PAT_END <= end_cyc) {
                    (void)sub32(eax, edx, 0u);
                    c.cycles = cyc_cnt + PM_FUSE_PAT_END;
                    return ip + 20;
                }
                c.fl = cf_add | ((old_ecx ^ ecx) & F_AF) | (ecx == 0x80000000u ? F_OF : 0u);
                c.zs = ZS32(ecx); c.pb = ecx;
                cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
                c.cycles = cyc_cnt;
                return ip;
            }
        }
        return ip;
    }

    if (disp == -24) {
        static const u8 sig24[24] = {
            0x89,0xD1, 0x4A, 0x85,0xC9, 0x74,0x11, 0x81,0xC3,0x40,0x01,0x00,0x00,
            0x8A,0x08, 0x40, 0x88,0x8B,0xC0,0xFE,0xFF,0xFF, 0xEB,0xE8
        };
        if (!pm_mem_eq(ip, sig24, 24u)) return ip;
        u32 edx = rEDX;
        if (edx == 0u) {
            if (cyc_cnt + PM_FUSE_PAT_END > end_cyc) return ip;
            rECX = 0u; rEDX = 0xFFFFFFFFu;
            c.fl = 0u; c.zs = 0; c.pb = 0u;
            c.cycles = cyc_cnt + PM_FUSE_PAT_END;
            return ip + 24;
        }
        if (cyc_cnt + PM_FUSE_PAT > end_cyc || edx > 200u) return ip;
        u32 eax = rEAX, ebx = rEBX, span_b = (edx - 1u) * 320u + 1u;
        if (pm_span_ok(eax, edx) && pm_span_ok(ebx, span_b) &&
            (ebx + span_b <= eax || eax + edx <= ebx)) {
            u32 ecx = 0, cf_add = 0, af_of_inc = 0;
            do {
                u32 cur_cnt = edx--;
                u8 cl = ram[eax];
                u32 na = eax + 1u;
                af_of_inc = ((eax ^ na) & F_AF) | (na == 0x80000000u ? F_OF : 0u);
                eax = na;
                ram[ebx] = cl;
                wr_cnt++;
                u32 nb = ebx + 320u;
                cf_add = (nb < ebx) ? F_CF : 0u;
                ebx = nb;
                ecx = (cur_cnt & 0xFFFFFF00u) | cl;
                cyc_cnt += PM_FUSE_PAT;
            } while (edx != 0u && cyc_cnt + PM_FUSE_PAT <= end_cyc);
            rEAX = eax; rEBX = ebx;
            writes = wr_cnt;
            if (edx == 0u && cyc_cnt + PM_FUSE_PAT_END <= end_cyc) {
                rECX = 0u; rEDX = 0xFFFFFFFFu;
                c.fl = 0u; c.zs = 0; c.pb = 0u;
                c.cycles = cyc_cnt + PM_FUSE_PAT_END;
                return ip + 24;
            }
            rECX = ecx; rEDX = edx;
            c.fl = cf_add | af_of_inc;
            c.zs = ZS32(eax); c.pb = eax;
            cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
            c.cycles = cyc_cnt;
            return ip;
        }
        return ip;
    }

    if (disp == -26) {
        static const u8 sig26[26] = {
            0x89,0xDE, 0x8D,0x2C,0x55,0x00,0x00,0x00,0x00, 0x83,0xC3,0x02,
            0x01,0xFD, 0x66,0x8B,0x36, 0x01,0xCA, 0x66,0x89,0x75,0x00, 0x48, 0x75,0xE6
        };
        if (cyc_cnt + PM_FUSE_DMX26 > end_cyc) return ip;
        u32 eax = rEAX, ebx = rEBX, ecx = rECX, edx = rEDX, edi = rEDI;
        if (eax == 0u || eax > 4096u || ecx > 1024u || edx > 0x10000u || !pm_mem_eq(ip, sig26, 26u))
            return ip;
        u32 src_len = eax * 2u, dst_lo = edi + edx * 2u, dst_len = (eax - 1u) * ecx * 2u + 2u;
        if (!pm_span_ok(ebx, src_len) || !(ebx >= 0x100000u || ebx + src_len <= 0x9FFFFu))
            return ip;
        int to_vga = (vga_single_ptr != 0 && dst_lo >= 0xA0000u && dst_lo + dst_len <= 0xB0000u);
        int to_ram = (!to_vga && pm_span_ok(dst_lo, dst_len) &&
                      (dst_lo >= 0x100000u || dst_lo + dst_len <= 0x9FFFFu) &&
                      (ebx + src_len <= dst_lo || dst_lo + dst_len <= ebx));
        if (to_vga || to_ram) {
            u32 esi = rESI, ebp = rEBP, cf_add = 0, old_eax;
            u8 *vp = vga_single_ptr;
            do {
                esi = ebx;
                ebp = edi + (edx << 1);
                ebx += 2u;
                u16 si = ua_r16(ram + esi);
                esi = (esi & 0xFFFF0000u) | si;
                u32 ndx = edx + ecx;
                cf_add = (ndx < edx) ? F_CF : 0u;
                edx = ndx;
                if (to_vga) {
                    u32 vo = ebp - 0xA0000u;
                    vdirty[vo >> 8] = 1;
                    vdirty[(vo + 1u) >> 8] = 1;
                    ua_w16(vp + vo, si);
                    wr_cnt += 2u;
                } else {
                    PM_WR16_RAM(ram + ebp, si);
                }
                old_eax = eax;
                eax = old_eax - 1u;
                cyc_cnt += PM_FUSE_DMX26;
            } while (eax != 0u && cyc_cnt + PM_FUSE_DMX26 <= end_cyc);
            rEAX = eax; rEBX = ebx; rEDX = edx; rESI = esi; rEBP = ebp;
            c.fl = cf_add | ((old_eax ^ eax) & F_AF) | (old_eax == 0x80000000u ? F_OF : 0u);
            c.zs = ZS32(eax); c.pb = eax;
            writes = wr_cnt;
            if (eax != 0u) cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
            c.cycles = cyc_cnt;
            return (eax == 0u) ? (ip + 26) : ip;
        }
        return ip;
    }

    if (disp == -27) {
        static const u8 sig27[27] = {
            0x31,0xC9, 0x8A,0x48,0x04, 0x66,0x0F,0xB6,0x30, 0xC1,0xE1,0x08,
            0x83,0xC2,0x02, 0x01,0xF1, 0x83,0xC0,0x08, 0x66,0x89,0x4A,0xFE, 0x4B, 0x75,0xE5
        };
        if (cyc_cnt + PM_FUSE_BLT27 > end_cyc) return ip;
        u32 eax = rEAX, edx = rEDX, ebx = rEBX;
        if (ebx == 0u || ebx > 0x10000u || !pm_span_ok(eax, ebx * 8u) || !pm_mem_eq(ip, sig27, 27u))
            return ip;
        int to_vga = (vga_single_ptr != 0 && edx >= 0xA0000u && edx + ebx * 2u <= 0xAFFFEu);
        int to_ram = (!to_vga && pm_span_ok(edx, ebx * 2u) &&
                      (edx >= 0x100000u || edx + ebx * 2u <= 0x9FFFFu) &&
                      (edx + ebx * 2u <= eax || eax + ebx * 8u <= edx));
        if (to_vga || to_ram) {
            u32 esi_hi = rESI & 0xFFFF0000u, b0 = 0, ecx = 0, cf_add = 0, old_ebx;
            u8 *vp = vga_single_ptr;
            do {
                u32 b4 = ram[eax + 4u];
                b0 = ram[eax];
                edx += 2u;
                ecx = (b4 << 8) + (esi_hi | b0);
                u32 na = eax + 8u;
                cf_add = (na < eax) ? F_CF : 0u;
                eax = na;
                if (to_vga) {
                    u32 vo = edx - 2u - 0xA0000u;
                    vdirty[vo >> 8] = 1;
                    vdirty[(vo + 1u) >> 8] = 1;
                    ua_w16(vp + vo, (u16)ecx);
                    wr_cnt += 2u;
                } else {
                    ua_w16(ram + edx - 2u, (u16)ecx);
                    wr_cnt++;
                }
                old_ebx = ebx;
                ebx = old_ebx - 1u;
                cyc_cnt += PM_FUSE_BLT27;
            } while (ebx != 0u && cyc_cnt + PM_FUSE_BLT27 <= end_cyc);
            rEAX = eax; rEDX = edx; rEBX = ebx; rECX = ecx; rSI = (u16)b0;
            c.fl = cf_add | ((old_ebx ^ ebx) & F_AF) | (old_ebx == 0x80000000u ? F_OF : 0u);
            c.zs = ZS32(ebx); c.pb = ebx;
            writes = wr_cnt;
            if (ebx != 0u) cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
            c.cycles = cyc_cnt;
            return (ebx == 0u) ? (ip + 27) : ip;
        }
        return ip;
    }

    if (disp == -28) {
        static const u8 m28_0[18] = {
            0x39,0xFE, 0x7E,0x18, 0x39,0xCE, 0x7C,0x14, 0x8B,0x5C,0x24,0x1C,
            0x83,0xEE,0x04, 0x4B, 0x89,0x86
        };
        static const u8 m28_22[6] = {0x89,0x5C,0x24,0x1C, 0xEB,0xE4};
        if (pm_mem_eq(ip, m28_0, 18u) && pm_mem_eq(ip + 22, m28_22, 6u)) {
            u32 esi = rESI, edi = rEDI, ecx = rECX;
            if ((s32)esi <= (s32)edi) {
                if (cyc_cnt + PM_FUSE_VIS_HIT > end_cyc) return ip;
                (void)sub32(esi, edi, 0u);
                c.cycles = cyc_cnt + PM_FUSE_VIS_HIT;
                return ip + 28;
            }
            if ((s32)esi < (s32)ecx) {
                if (cyc_cnt + PM_FUSE_PAT_END > end_cyc) return ip;
                (void)sub32(esi, ecx, 0u);
                c.cycles = cyc_cnt + PM_FUSE_PAT_END;
                return ip + 28;
            }
            s32 s_lo = ((s32)edi < 0x7FFFFFFF && (s32)edi + 1 > (s32)ecx) ? ((s32)edi + 1) : (s32)ecx;
            if (cyc_cnt + PM_FUSE_MSP28 > end_cyc || s_lo < 4 || (s32)esi > 4096)
                return ip;
            u32 n_max = ((u32)((s32)esi - s_lo) >> 2) + 1u;
            u32 span_off = ua_r32(ip + 18), wr_lo = span_off + esi - n_max * 4u;
            u32 sp_a = rESP + 0x1Cu;
            if (PM_IS_RAM4(sp_a) && pm_span_ok(wr_lo, n_max * 4u) &&
                (wr_lo >= 0x100000u || wr_lo + n_max * 4u <= 0x9FFFFu) &&
                (sp_a + 4u <= wr_lo || sp_a >= wr_lo + n_max * 4u)) {
                u32 ebx = ua_r32(ram + sp_a), eax = rEAX, old_ebx = ebx, cf_sub = 0;
                do {
                    cf_sub = (esi < 4u) ? F_CF : 0u;
                    esi -= 4u;
                    old_ebx = ebx;
                    ebx = old_ebx - 1u;
                    PM_WR32_RAM(ram + span_off + esi, eax);
                    PM_WR32_RAM(ram + sp_a, ebx);
                    cyc_cnt += PM_FUSE_MSP28;
                } while ((s32)esi >= s_lo && cyc_cnt + PM_FUSE_MSP28 <= end_cyc);
                rESI = esi; rEBX = ebx;
                writes = wr_cnt;
                if ((s32)esi <= (s32)edi && cyc_cnt + PM_FUSE_VIS_HIT <= end_cyc) {
                    (void)sub32(esi, edi, 0u);
                    c.cycles = cyc_cnt + PM_FUSE_VIS_HIT;
                    return ip + 28;
                }
                if ((s32)esi < (s32)ecx && cyc_cnt + PM_FUSE_PAT_END <= end_cyc) {
                    (void)sub32(esi, ecx, 0u);
                    c.cycles = cyc_cnt + PM_FUSE_PAT_END;
                    return ip + 28;
                }
                c.fl = cf_sub | ((old_ebx ^ ebx) & F_AF) | (old_ebx == 0x80000000u ? F_OF : 0u);
                c.zs = ZS32(ebx); c.pb = ebx;
                cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
                c.cycles = cyc_cnt;
                return ip;
            }
        }
        return ip;
    }

    if (disp == -30) {
        static const u8 c0[6]  = {0x83,0xC0,0x02, 0x66,0x8B,0x1D};
        static const u8 c10[3] = {0x66,0x89,0x98};
        static const u8 c17[3] = {0x66,0xC7,0x80};
        static const u8 c24[6] = {0xFF,0xFF, 0x39,0xD0, 0x7C,0xE2};
        if (cyc_cnt + PM_FUSE_CLIP30 > end_cyc) return ip;
        u32 eax = rEAX, edx = rEDX;
        s32 sa = (s32)eax, sd = (s32)edx;
        if (sa < 0 || sd <= sa || sd > 4096) return ip;
        if (pm_mem_eq(ip, c0, 6u) && pm_mem_eq(ip + 10, c10, 3u) &&
            pm_mem_eq(ip + 17, c17, 3u) && pm_mem_eq(ip + 24, c24, 6u)) {
            u32 rem_iters = ((u32)(sd - sa) + 1u) >> 1, span_w = rem_iters * 2u;
            u32 vh_a = ua_r32(ip + 6), fc_off = ua_r32(ip + 13), cc_off = ua_r32(ip + 20);
            u32 fc_b = fc_off + (u32)sa + 2u, cc_b = cc_off + (u32)sa + 2u;
            if (PM_IS_RAM2(vh_a) &&
                pm_span_ok(fc_b, span_w) && (fc_b >= 0x100000u || fc_b + span_w <= 0x9FFFFu) &&
                pm_span_ok(cc_b, span_w) && (cc_b >= 0x100000u || cc_b + span_w <= 0x9FFFFu) &&
                (vh_a + 2u <= fc_b || vh_a >= fc_b + span_w) &&
                (vh_a + 2u <= cc_b || vh_a >= cc_b + span_w)) {
                u16 bx = ua_r16(ram + vh_a);
                do {
                    eax += 2u;
                    PM_WR16_RAM(ram + fc_off + eax, bx);
                    PM_WR16_RAM(ram + cc_off + eax, 0xFFFFu);
                    cyc_cnt += PM_FUSE_CLIP30;
                } while ((s32)eax < sd && cyc_cnt + PM_FUSE_CLIP30 <= end_cyc);
                rEAX = eax; rBX = bx;
                (void)sub32(eax, edx, 0u);
                writes = wr_cnt;
                if ((s32)eax < sd) cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
                c.cycles = cyc_cnt;
                return ((s32)eax < sd) ? ip : (ip + 30);
            }
        }
        return ip;
    }

    if (disp == -43) {
        static const u8 dp43_0[30] = {
            0x31,0xC0,0x31,0xC9,0x31,0xDB,0x31,0xD2,0x8A,0x86,0x57,0x01,0x00,0x00,0x8A,0x4E,
            0x15,0x8A,0x9E,0x56,0x01,0x00,0x00,0x50,0x8A,0x56,0x14,0x89,0xF8,0xE8
        };
        static const u8 dp43_34[9] = {0x8B,0x04,0x24,0x47,0x46,0x39,0xC7,0x7E,0xD5};
        if (!pm_mem_eq(ip, dp43_0, 30u) || !pm_mem_eq(ip + 34, dp43_34, 9u))
            return ip;
        u32 op_eip = (u32)(ip - ram), ret_eip = op_eip + 34u;
        u32 fn_eip = ret_eip + ua_r32(ip + 30);
        if ((u32)(fn_eip - 0x100000u) >= (RAM_BYTES - 0x1000E0u))
            return ip;
        if (__builtin_expect(fn_eip != msp_eip, 0)) {
            if (!pm_init_msp_snap(fn_eip, ram + fn_eip))
                return ip;
        }
        u32 esp0 = rESP, edi = rEDI, esi = rESI, ebp = rEBP;
        if (esp0 < 0x100020u || esp0 >= RAM_BYTES - 8u)
            return ip;
        u32 stop = ua_r32(ram + esp0);
        if ((s32)edi < 0 || (s32)edi > (s32)stop || (u32)((s32)stop - (s32)edi) > 322u)
            return ip;
        u32 max_cols = (u32)((s32)stop - (s32)edi) + 1u;
        u32 vp_lo = esi + 0x14u, vp_hi = esi + 0x158u + max_cols;
        u32 sp_lo = esp0 - 32u, sp_hi = esp0 + 4u;
        u32 ss_lo = msp_span_a, ss_hi = ss_lo + 800u;
        if (esi < 0x100000u || vp_hi > RAM_BYTES ||
            !(sp_hi <= vp_lo || vp_hi <= sp_lo) ||
            !(sp_hi <= ss_lo || ss_hi <= sp_lo) ||
            !(ss_hi <= vp_lo || vp_hi <= ss_lo) ||
            !(sp_hi <= op_eip || op_eip + 43u <= sp_lo) ||
            !(sp_hi <= fn_eip || fn_eip + 221u <= sp_lo) ||
            !(ss_hi <= op_eip || op_eip + 43u <= ss_lo))
            return ip;

        u32 *spanstart = (u32 *)(void *)(ram + ss_lo);
        u8  *sp_frame  = ram + sp_lo;
        u32 ran = 0, last_ecx = 0, last_edx = 0, last_ebx = 0, last_b2_rem = 0, last_x = 0, last_ptr = 0;
        for (;;) {
            u32 b2 = ram[esi + 0x157u], t2 = ram[esi + 0x15u];
            u32 b1 = ram[esi + 0x156u], t1 = ram[esi + 0x14u];
            if ((t1 < t2 && t1 <= b1) || (b1 > b2 && b1 >= t1))
                break;
            if (t2 <= b2 && b2 >= 200u)
                break;
            u32 n_top = 0u;
            if (t2 < t1 && t2 <= b2) {
                u32 y_hi = (t1 - 1u < b2) ? (t1 - 1u) : b2;
                n_top = y_hi - t2 + 1u;
            }
            u32 ecx_mid = t2 + n_top;
            u32 y_lo_bot = (b1 + 1u > ecx_mid) ? (b1 + 1u) : ecx_mid;
            u32 n_bot = (b2 >= y_lo_bot) ? (b2 - y_lo_bot + 1u) : 0u;
            if (n_bot > 0u && b2 >= 200u)
                break;

            u32 extra_ops = (t1 < t2 ? 5u : 0u) + (b1 > b2 ? 2u : 0u) +
                            (ecx_mid >= t1 ? 2u : 4u) +
                            ((s32)(b2 - n_bot) <= (s32)b1 ? 2u : 4u);
            s32 step_cyc = (s32)((46u + extra_ops) * (u32)PM_CYC +
                           (n_top ? (8u * (u32)PM_CYC + (n_top - 1u) * (u32)PM_FUSE_MSP20) : 0u) +
                           (n_bot ? (10u * (u32)PM_CYC + (n_bot - 1u) * (u32)PM_FUSE_MSP28) : 0u));
            if (cyc_cnt + step_cyc > end_cyc)
                break;

            if (t1 < t2)
                ua_w32(sp_frame, edi - 1u);
            for (u32 y = t2, y_end = t2 + n_top; y < y_end; y++)
                spanstart[y] = edi;
            for (u32 k = 0; k < n_bot; k++)
                spanstart[b2 - k] = edi;

        #ifdef PM_EXACT_CPI3
            wr_cnt += 7u + (t1 < t2 ? 1u : 0u) + n_top + 2u * n_bot;
        #else
            wr_cnt += 2u + (t1 < t2 ? 1u : 0u) + n_top + 2u * n_bot;
        #endif
            last_ecx    = ecx_mid << 2;
            last_edx    = b2 << 2;
            last_b2_rem = b2 - n_bot;
            last_ebx    = n_bot ? last_b2_rem : b1;
            last_x      = edi;
            last_ptr    = esi;
            edi++;
            esi++;
            cyc_cnt += step_cyc;
            ran = 1u;
            if ((s32)edi > (s32)stop)
                break;
        }
        if (!ran) return ip;
        ua_w32(sp_frame +  4u, last_x - 1u);
        ua_w32(sp_frame +  8u, last_x);
        ua_w32(sp_frame + 12u, ebp);
        ua_w32(sp_frame + 16u, last_x);
        ua_w32(sp_frame + 20u, last_ptr);
        ua_w32(sp_frame + 24u, ret_eip);
        ua_w32(sp_frame + 28u, last_b2_rem);
        rEAX = stop; rECX = last_ecx; rEDX = last_edx; rEBX = last_ebx;
        rESI = esi;  rEDI = edi;
        (void)sub32(edi, stop, 0u);
        writes = wr_cnt;
        if ((s32)edi <= (s32)stop)
            cyc_cnt = idle_pm32(op_eip, cyc_cnt, wr_cnt);
        c.cycles = cyc_cnt;
        return ((s32)edi <= (s32)stop) ? ip : (ip + 43);
    }

    if (disp == -45) {
        static const u8 f0[3]   = {0x8B,0x14,0x9D};
        static const u8 f7[14]  = {0x8A,0x14,0x02, 0x81,0xE2,0xFF,0x00,0x00,0x00, 0x89,0xF9, 0x8A,0x94,0x11};
        static const u8 f25[20] = {
            0x43, 0x88,0x10, 0x83,0xFB,0x32, 0x75,0x02, 0x31,0xDB,
            0x89,0xF2, 0x83,0xC0,0x50, 0x4E, 0x85,0xD2, 0x75,0xD3
        };
        if (vga_single_ptr != 0 && (gc[5] & 8u) == 0u &&
            pm_mem_eq(ip, f0, 3u) && pm_mem_eq(ip + 7, f7, 14u) && pm_mem_eq(ip + 25, f25, 20u)) {
            u32 eax = rEAX, ebx = rEBX, esi = rESI, edi = rEDI;
            u32 fuzz_tbl = ua_r32(ip + 3), cmap_base = edi + ua_r32(ip + 21);
            if (ebx < 50u && esi < 200u &&
                eax >= 0xA0000u && eax + esi * 80u < 0xB0000u &&
                pm_span_ok(fuzz_tbl, 200u) && pm_span_ok(cmap_base, 256u)) {
                u8 * const vp = vga_single_ptr;
                u8 * const rp = vram[gc[4] & 3u];
                const u8 * const cmap = ram + cmap_base;
                u32 edx = 0, last_ro = 0, ran = 0;
                do {
                    s32 step_cyc = PM_FUSE_FUZZ + (ebx == 49u ? PM_FUSE_FUZZ_WRAP : 0);
                    if (cyc_cnt + step_cyc > end_cyc) break;
                    u32 foff = ua_r32(ram + fuzz_tbl + ebx * 4u);
                    u32 ro = (eax + foff) - 0xA0000u;
                    if (__builtin_expect(ro >= 0x10000u, 0)) break;
                    last_ro = ro;
                    u8 out_px = cmap[rp[ro]];
                    ebx++;
                    u32 wo = eax - 0xA0000u;
                    vdirty[wo >> 8] = 1;
                    vp[wo] = out_px;
                    wr_cnt++;
                    if (ebx == 50u) ebx = 0u;
                    edx = esi;
                    eax += 80u;
                    esi = edx - 1u;
                    cyc_cnt += step_cyc;
                    ran = 1u;
                } while (edx != 0u);
                if (!ran) return ip;
                latch[0] = vram[0][last_ro]; latch[1] = vram[1][last_ro];
                latch[2] = vram[2][last_ro]; latch[3] = vram[3][last_ro];
                rEAX = eax; rEBX = ebx; rECX = edi; rEDX = edx; rESI = esi;
                (void)logic32(edx);
                writes = wr_cnt;
                if (edx != 0u) cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
                c.cycles = cyc_cnt;
                return (edx == 0u) ? (ip + 45) : ip;
            }
        }
        return ip;
    }

    if (disp == -50) {
        static const u8 sig50[50] = {
            0x01,0xF8, 0x88,0x13, 0x43, 0x89,0xC1, 0x83,0xC6,0x02, 0xC1,0xF9,0x08,
            0x25,0xFF,0x00,0x00,0x00, 0x01,0xE9, 0x01,0xF8, 0x01,0xCA, 0x89,0xC1,
            0x43, 0xC1,0xF9,0x08, 0x88,0x53,0xFF, 0x01,0xE9, 0x25,0xFF,0x00,0x00,0x00,
            0x01,0xCA, 0x81,0xFE,0x00,0x01,0x00,0x00, 0x7C,0xCE
        };
        if (cyc_cnt + PM_FUSE_DMX50 > end_cyc) return ip;
        s32 s_esi = (s32)rESI;
        if (s_esi < 0 || s_esi >= 256 || !pm_mem_eq(ip, sig50, 50u)) return ip;
        u32 rem_iters = ((u32)(256 - s_esi) + 1u) >> 1, ebx = rEBX;
        if (pm_span_ok(ebx, rem_iters * 2u)) {
            u32 eax = rEAX, ecx = 0, edx = rEDX, esi = rESI, edi = rEDI, ebp = rEBP;
            do {
                eax += edi;
                PM_WR8_RAM(ram[ebx], edx);
                ebx++;
                ecx = (u32)((s32)eax >> 8) + ebp;
                esi += 2u;
                eax = (eax & 0xFFu) + edi;
                edx += ecx;
                ebx++;
                ecx = (u32)((s32)eax >> 8) + ebp;
                PM_WR8_RAM(ram[ebx - 1u], edx);
                eax &= 0xFFu;
                edx += ecx;
                cyc_cnt += PM_FUSE_DMX50;
            } while ((s32)esi < 256 && cyc_cnt + PM_FUSE_DMX50 <= end_cyc);
            rEAX = eax; rEBX = ebx; rECX = ecx; rEDX = edx; rESI = esi;
            (void)sub32(esi, 256u, 0u);
            writes = wr_cnt;
            if ((s32)esi < 256) cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
            c.cycles = cyc_cnt;
            return ((s32)esi < 256) ? ip : (ip + 50);
        }
        return ip;
    }

    if (disp == -51) {
        static const u8 s0[4]  = {0x8B,0xCD,0x81,0xC5};
        static const u8 s8[9]  = {0x88,0x07,0xC1,0xE9,0x19,0x8B,0xD5,0x81,0xC5};
        static const u8 s21[20]= {0x88,0x5F,0x50,0xC1,0xEA,0x19,0x8A,0x04,0x0E,0x81,0xC7,0xA0,0x00,0x00,0x00,0x8A,0x1C,0x16,0xFF,0x0D};
        static const u8 s45[6] = {0x8A,0x00,0x8A,0x1B,0x75,0xCD};
        if (cyc_cnt + PM_FUSE_COL > end_cyc) return ip;
        if (vga_single_ptr != 0 && pm_mem_eq(ip, s0, 4u) && pm_mem_eq(ip + 8, s8, 9u) &&
            pm_mem_eq(ip + 21, s21, 20u) && pm_mem_eq(ip + 45, s45, 6u)) {
            u32 cnt_addr = ua_r32(ip + 41);
            if (!PM_IS_RAM4(cnt_addr)) return ip;
            u32 cnt = ua_r32(ram + cnt_addr);
            u32 edi = rEDI, esi = rESI, ea_hi = rEAX & 0xFFFFFF00u, eb_hi = rEBX & 0xFFFFFF00u;
            if (cnt > 0u && cnt <= 200u &&
                edi >= 0xA0000u && edi + (cnt - 1u) * 160u + 80u < 0xB0000u &&
                pm_span_ok(esi, 128u) && pm_span_ok(ea_hi, 256u) && pm_span_ok(eb_hi, 256u) &&
                (cnt_addr + 4u <= esi   || cnt_addr >= esi + 128u) &&
                (cnt_addr + 4u <= ea_hi || cnt_addr >= ea_hi + 256u) &&
                (cnt_addr + 4u <= eb_hi || cnt_addr >= eb_hi + 256u)) {
                u32 step1 = ua_r32(ip + 4), step2 = ua_r32(ip + 17);
                u32 ebp = rEBP, ecx = 0, edx = 0, old_cnt;
                u8 al = rAL, bl = rBL;
                const u8 *tex = ram + esi, *cma = ram + ea_hi, *cmb = ram + eb_hi;
                u8 *vp = vga_single_ptr;
                do {
                    ecx = ebp >> 25;
                    ebp += step1;
                    u32 vo = edi - 0xA0000u;
                    vdirty[vo >> 8] = 1;
                    vp[vo] = al;
                    edx = ebp >> 25;
                    ebp += step2;
                    vdirty[(vo + 80u) >> 8] = 1;
                    vp[vo + 80u] = bl;
                    edi += 160u;
                    al = cma[tex[ecx]];
                    bl = cmb[tex[edx]];
                    old_cnt = cnt;
                    cnt = old_cnt - 1u;
                    wr_cnt += 3u;
                    cyc_cnt += PM_FUSE_COL;
                } while (cnt != 0u && cyc_cnt + PM_FUSE_COL <= end_cyc);
                ua_w32(ram + cnt_addr, cnt);
                rECX = ecx; rEDX = edx; rEBP = ebp; rEDI = edi;
                rEAX = ea_hi | al; rEBX = eb_hi | bl;
                c.fl = ((old_cnt ^ cnt) & F_AF) | (old_cnt == 0x80000000u ? F_OF : 0u);
                c.zs = ZS32(cnt); c.pb = cnt;
                writes = wr_cnt;
                if (cnt != 0u) cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
                c.cycles = cyc_cnt;
                return (cnt == 0u) ? (ip + 51) : ip;
            }
        }
        return ip;
    }

    if (disp == -64) {
        static const u8 p0[12]  = {0x0F,0xA4,0xE9,0x16, 0x8A,0x33, 0x0F,0xA4,0xE9,0x06, 0x81,0xC5};
        static const u8 p16[22] = {0x81,0xE1,0xFF,0x0F,0x00,0x00, 0x66,0x89,0x17, 0x0F,0xA4,0xEA,0x16, 0x83,0xC7,0x02, 0x0F,0xA4,0xEA,0x06, 0x81,0xC5};
        static const u8 p42[14] = {0x81,0xE2,0xFF,0x0F,0x00,0x00, 0x8A,0x04,0x0E, 0x8A,0x1C,0x16, 0xFF,0x0D};
        static const u8 p60[4]  = {0x8A,0x10, 0x75,0xC0};
        if (cyc_cnt + PM_FUSE_SPN > end_cyc) return ip;
        if (pm_mem_eq(ip, p0, 12u) && pm_mem_eq(ip + 16, p16, 22u) &&
            pm_mem_eq(ip + 42, p42, 14u) && pm_mem_eq(ip + 60, p60, 4u)) {
            u32 cnt_addr = ua_r32(ip + 56);
            if (!PM_IS_RAM4(cnt_addr)) return ip;
            u32 cnt = ua_r32(ram + cnt_addr);
            u32 edi = rEDI, esi = rESI, ea_hi = rEAX & 0xFFFFFF00u, eb_hi = rEBX & 0xFFFFFF00u;
            if (cnt == 0u || cnt > 320u) return ip;
            int to_vga = (vga_single_ptr != 0 && edi >= 0xA0000u && edi + cnt * 2u <= 0xAFFFEu);
            int to_ram = (!to_vga && pm_span_ok(edi, cnt * 2u) && (edi >= 0x100000u || edi + cnt * 2u <= 0x9FFFFu) &&
                          (edi + cnt * 2u <= cnt_addr || edi >= cnt_addr + 4u) &&
                          (edi + cnt * 2u <= esi   || edi >= esi + 4096u) &&
                          (edi + cnt * 2u <= ea_hi || edi >= ea_hi + 256u) &&
                          (edi + cnt * 2u <= eb_hi || edi >= eb_hi + 256u));
            if ((to_vga || to_ram) &&
                pm_span_ok(esi, 4096u) && pm_span_ok(ea_hi, 256u) && pm_span_ok(eb_hi, 256u) &&
                (cnt_addr + 4u <= esi   || cnt_addr >= esi + 4096u) &&
                (cnt_addr + 4u <= ea_hi || cnt_addr >= ea_hi + 256u) &&
                (cnt_addr + 4u <= eb_hi || cnt_addr >= eb_hi + 256u)) {
                u32 step1 = ua_r32(ip + 12), step2 = ua_r32(ip + 38);
                u32 ebp = rEBP, ecx = 0, edx_idx = 0, old_cnt;
                u8 al = rAL, bl = rBL, dl = rDL;
                const u8 *tex = ram + esi, *cma = ram + ea_hi, *cmb = ram + eb_hi;
                do {
                    u8 dh = cmb[bl];
                    ecx = ((ebp >> 4) & 0xFC0u) | (ebp >> 26);
                    ebp += step1;
                    u16 dx = (u16)dl | ((u16)dh << 8);
                    if (to_vga) {
                        u32 vo = edi - 0xA0000u;
                        vdirty[vo >> 8] = 1;
                        vdirty[(vo + 1u) >> 8] = 1;
                        ua_w16(vga_single_ptr + vo, dx);
                        wr_cnt += 3u;
                    } else {
                        ua_w16(ram + edi, dx);
                        wr_cnt += 2u;
                    }
                    edi += 2u;
                    edx_idx = ((ebp >> 4) & 0xFC0u) | (ebp >> 26);
                    ebp += step2;
                    al = tex[ecx];
                    bl = tex[edx_idx];
                    old_cnt = cnt;
                    cnt = old_cnt - 1u;
                    dl = cma[al];
                    cyc_cnt += PM_FUSE_SPN;
                } while (cnt != 0u && cyc_cnt + PM_FUSE_SPN <= end_cyc);
                ua_w32(ram + cnt_addr, cnt);
                rECX = ecx; rEBP = ebp; rEDI = edi;
                rEAX = ea_hi | al; rEBX = eb_hi | bl;
                rEDX = (edx_idx & 0x0F00u) | dl;
                c.fl = ((old_cnt ^ cnt) & F_AF) | (old_cnt == 0x80000000u ? F_OF : 0u);
                c.zs = ZS32(cnt); c.pb = cnt;
                writes = wr_cnt;
                if (cnt != 0u) cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
                c.cycles = cyc_cnt;
                return (cnt == 0u) ? (ip + 64) : ip;
            }
        }
    }
#if !defined(PM_EXACT_CPI3) && !defined(NO_CALL_FUSE)
    if (disp == -63)
        return pm_fuse_visspr63(ip, end_cyc);
#endif

    if (disp == -23) {
        static const u8 sig23[23] = {
            0x66,0x89,0x94,0x0C,0x80,0x02,0x00,0x00, 0x66,0x89,0x14,0x0C,
            0x40, 0x8B,0x5E,0x0C, 0x83,0xC1,0x02, 0x39,0xD8, 0x7E,0xE9
        };
        s32 step_cyc = 2 * PM_CYC66 + 5 * PM_CYC;
        if (cyc_cnt + step_cyc > end_cyc || !PM_IS_XRAM4(rESI + 0x0Cu))
            return ip;
        s32 sa = (s32)rEAX, sb_v = (s32)ua_r32(ram + rESI + 0x0Cu);
        if (sa < 0 || sb_v < sa || sb_v >= 320 || !pm_mem_eq(ip, sig23, 23u))
            return ip;
        u32 ecx = rECX, esp0 = rESP, n_iters = (u32)(sb_v - sa) + 1u;
        if (ecx >= 0x1000u)
            return ip;
        u32 wr_lo = esp0 + ecx, wr_len = (n_iters - 1u) * 2u + 0x282u;
        if (wr_lo >= PM_CODE_GUARD_TOP && wr_lo <= RAM_BYTES && wr_len <= RAM_BYTES - wr_lo &&
            (wr_lo + wr_len <= rESI + 0x0Cu || rESI + 0x10u <= wr_lo)) {
            u16 dx = rDX;
            u32 eax = (u32)sa;
            do {
                ua_w16(ram + esp0 + ecx + 0x280u, dx);
                ua_w16(ram + esp0 + ecx, dx);
                wr_cnt += 2u;
                eax++;
                ecx += 2u;
                cyc_cnt += step_cyc;
            } while ((s32)eax <= sb_v && cyc_cnt + step_cyc <= end_cyc);
            rEAX = eax; rEBX = (u32)sb_v; rECX = ecx;
            (void)sub32(eax, (u32)sb_v, 0u);
            writes = wr_cnt;
            if ((s32)eax <= sb_v) cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
            c.cycles = cyc_cnt;
            return ((s32)eax <= sb_v) ? ip : (ip + 23);
        }
        return ip;
    }

    if (disp == -52) {
        static const u8 s52_0[12] = {
            0x0F,0xBF,0x14,0x04,0x83,0xFA,0xFE,0x75,0x0B,0x66,0x8B,0x15
        };
        static const u8 s52_16[36] = {
            0x66,0x89,0x14,0x04,0x0F,0xBF,0x94,0x04,0x80,0x02,0x00,0x00,
            0x83,0xFA,0xFE,0x75,0x08,0x66,0x89,0x9C,0x04,0x80,0x02,0x00,
            0x00,0x45,0x8B,0x56,0x0C,0x83,0xC0,0x02,0x39,0xD5,0x7E,0xCC
        };
        if (!PM_IS_XRAM4(rESI + 0x0Cu))
            return ip;
        s32 sebp = (s32)rEBP, sedx = (s32)ua_r32(ram + rESI + 0x0Cu);
        if (sebp < 0 || sedx < sebp || sedx >= 320 ||
            !pm_mem_eq(ip, s52_0, 12u) || !pm_mem_eq(ip + 16, s52_16, 36u))
            return ip;
        u32 vh_a = ua_r32(ip + 12), eax = rEAX, esp0 = rESP, n_iters = (u32)(sedx - sebp) + 1u;
        if (!PM_IS_XRAM4(vh_a) || eax >= 0x1000u)
            return ip;
        u32 wr_lo = esp0 + eax, wr_len = (n_iters - 1u) * 2u + 0x282u;
        if (wr_lo >= PM_CODE_GUARD_TOP && wr_lo <= RAM_BYTES && wr_len <= RAM_BYTES - wr_lo &&
            (wr_lo + wr_len <= rESI + 0x0Cu || rESI + 0x10u <= wr_lo) &&
            (wr_lo + wr_len <= vh_a || vh_a + 2u <= wr_lo)) {
            u16 vh_w = ua_r16(ram + vh_a), bx_w = rBX;
            u32 ebp = (u32)sebp, ran = 0;
            do {
                s16 d0 = (s16)ua_r16(ram + esp0 + eax);
                s16 d1 = (s16)ua_r16(ram + esp0 + eax + 0x280u);
                s32 step_cyc = 11 * PM_CYC + (d0 == -2 ? 2 * PM_CYC66 : 0) + (d1 == -2 ? PM_CYC66 : 0);
                if (cyc_cnt + step_cyc > end_cyc) break;
                if (d0 == -2) { ua_w16(ram + esp0 + eax, vh_w); wr_cnt++; }
                if (d1 == -2) { ua_w16(ram + esp0 + eax + 0x280u, bx_w); wr_cnt++; }
                ebp++;
                eax += 2u;
                cyc_cnt += step_cyc;
                ran = 1u;
            } while ((s32)ebp <= sedx);
            if (!ran) return ip;
            rEBP = ebp; rEDX = (u32)sedx; rEAX = eax;
            (void)sub32(ebp, (u32)sedx, 0u);
            writes = wr_cnt;
            if ((s32)ebp <= sedx) cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
            c.cycles = cyc_cnt;
            return ((s32)ebp <= sedx) ? ip : (ip + 52);
        }
        return ip;
    }

    if (disp == -56) {
        static const u8 sig56_ifu[56] = {
            0x8B,0x5C,0x24,0x18,0x39,0xDF,0x74,0x1B,0x31,0xC9,0x8A,0x48,0x04,0x66,0x0F,0xB6,
            0x30,0xC1,0xE1,0x08,0x83,0xC2,0x02,0x01,0xF1,0x83,0xC0,0x08,0x66,0x89,0x4A,0xFE,
            0x4B,0x75,0xE5,0x8B,0x5C,0x24,0x0C,0x8B,0x4C,0x24,0x10,0x8B,0x74,0x24,0x14,0x45,
            0x01,0xD8,0x01,0xCA,0x39,0xF5,0x7C,0xC8
        };
        u32 esp0 = rESP;
        if (vga_single_ptr == 0 || rEDI != 0u || !pm_span_ok(esp0, 0x1Cu) ||
            !pm_mem_eq(ip, sig56_ifu, 56u))
            return ip;
        u32 w_cnt  = ua_r32(ram + esp0 + 0x18u);
        u32 s_step = ua_r32(ram + esp0 + 0x0Cu);
        u32 d_step = ua_r32(ram + esp0 + 0x10u);
        u32 h_lim  = ua_r32(ram + esp0 + 0x14u);
        s32 sebp = (s32)rEBP, sh = (s32)h_lim;
        if (w_cnt == 0u || w_cnt > 42u || sebp < 0 || sh <= sebp || sh > 200)
            return ip;
        s32 row_s_stride = (s32)(w_cnt * 8u) + (s32)s_step;
        s32 row_d_stride = (s32)(w_cnt * 2u) + (s32)d_step;
        if (row_s_stride < 0 || row_s_stride > 640 || row_d_stride < 0 || row_d_stride > 160)
            return ip;
        s32 row_cyc = 19 * PM_CYC + 2 * PM_CYC66 + (s32)((w_cnt - 1u) * (u32)PM_FUSE_BLT27);
        if (cyc_cnt + row_cyc > end_cyc)
            return ip;
        u32 rows_rem = (u32)(sh - sebp);
        u32 eax = rEAX, edx = rEDX;
        u32 src_end = (rows_rem - 1u) * (u32)row_s_stride + w_cnt * 8u;
        u32 dst_end = (rows_rem - 1u) * (u32)row_d_stride + w_cnt * 2u;
        if (pm_span_ok(eax, src_end) &&
            (esp0 + 0x1Cu <= eax || eax + src_end <= esp0) &&
            edx >= 0xA0000u && edx + dst_end <= 0xAFFFEu) {
            u8 *vp_base = vga_single_ptr;
            u32 ebp = (u32)sebp;
            do {
                u32 vo = edx - 0xA0000u;
                vdirty[vo >> 8] = 1;
                vdirty[(vo + w_cnt * 2u - 1u) >> 8] = 1;
                u8 *vp = vp_base + vo;
                const u8 *sp = ram + eax;
                for (u32 k = 0; k < w_cnt; k++, sp += 8, vp += 2) {
                    vp[0] = sp[0];
                    vp[1] = sp[4];
                }
                wr_cnt += w_cnt * 2u;
                ebp++;
                eax += (u32)row_s_stride;
                edx += (u32)row_d_stride;
                cyc_cnt += row_cyc;
            } while ((s32)ebp < sh && cyc_cnt + row_cyc <= end_cyc);
            rEAX = eax; rEDX = edx; rEBX = s_step; rECX = d_step; rESI = h_lim; rEBP = ebp;
            (void)sub32(ebp, h_lim, 0u);
            writes = wr_cnt;
            if ((s32)ebp < sh) cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
            c.cycles = cyc_cnt;
            return ((s32)ebp < sh) ? ip : (ip + 56);
        }
        return ip;
    }

    if (disp == -104) {
        static const u8 sig104_vdp[104] = {
            0x8B,0x74,0x24,0x04,0x03,0x75,0x08,0x80,0x3E,0xFF,0x74,0x3F,0x31,0xD2,0x8A,0x16,
            0x69,0xD2,0x40,0x01,0x00,0x00,0x8D,0x1C,0x17,0x31,0xD2,0x8D,0x46,0x03,0x8A,0x56,
            0x01,0x89,0xD1,0x4A,0x85,0xC9,0x74,0x11,0x81,0xC3,0x40,0x01,0x00,0x00,0x8A,0x08,
            0x40,0x88,0x8B,0xC0,0xFE,0xFF,0xFF,0xEB,0xE8,0x31,0xC0,0x8A,0x46,0x01,0x01,0xC6,
            0x8A,0x56,0x04,0x83,0xC6,0x04,0x80,0xFA,0xFF,0x75,0xC1,0x8B,0x5C,0x24,0x08,0x8B,
            0x4C,0x24,0x0C,0x8B,0x34,0x24,0x83,0xC5,0x04,0x47,0x43,0x41,0x89,0x5C,0x24,0x08,
            0x89,0x4C,0x24,0x0C,0x39,0xF1,0x7C,0x98
        };
        u32 esp0 = rESP;
        if (esp0 < PM_CODE_GUARD_TOP || esp0 + 16u > RAM_BYTES || !pm_mem_eq(ip, sig104_vdp, 104u))
            return ip;
        u32 width = ua_r32(ram + esp0), patch = ua_r32(ram + esp0 + 4u);
        u32 ebx = ua_r32(ram + esp0 + 8u), ecx = ua_r32(ram + esp0 + 12u);
        if (patch < 0x100000u || patch >= RAM_BYTES || (s32)ecx < 0 || (s32)width <= (s32)ecx || width > 320u)
            return ip;
        u32 ebp = rEBP, edi = rEDI, cur_eax = rEAX, cur_edx = rEDX, ran = 0;
        while ((s32)ecx < (s32)width) {
            if (!PM_IS_XRAM4(ebp + 8u) || !(esp0 + 16u <= ebp + 8u || ebp + 12u <= esp0))
                break;
            u32 col_p = patch + ua_r32(ram + ebp + 8u);
            if (col_p < 0x100000u || col_p >= RAM_BYTES || !(esp0 + 16u <= col_p || col_p + 1u <= esp0))
                break;
            s32 col_cyc = 15 * PM_CYC;
            u32 p_cur = col_p, posts = 0, col_wr = 2u;
            int ok = 1;
            if (ram[p_cur] != 0xFFu) {
                while (posts < 64u) {
                    if (p_cur < 0x100000u || p_cur + 5u > RAM_BYTES) { ok = 0; break; }
                    u8 td = ram[p_cur], len = ram[p_cur + 1u];
                    if (p_cur + (u32)len + 5u > RAM_BYTES ||
                        !(esp0 + 16u <= p_cur || p_cur + (u32)len + 5u <= esp0)) { ok = 0; break; }
                    if (len == 0u) {
                        col_cyc += 18 * PM_CYC;
                    } else {
                        u32 dst0 = edi + (u32)td * 320u, dst_span = ((u32)len - 1u) * 320u + 1u;
                        if (!(dst0 + dst_span <= 0x9FFFFu ||
                              (dst0 >= PM_CODE_GUARD_TOP && dst0 <= RAM_BYTES && dst_span <= RAM_BYTES - dst0)) ||
                            !(dst0 + dst_span <= c.wr_guard_lo || dst0 >= c.wr_fast_lo) ||
                            !(dst0 + dst_span <= p_cur || p_cur + (u32)len + 5u <= dst0) ||
                            !(dst0 + dst_span <= esp0 || esp0 + 16u <= dst0) ||
                            !(dst0 + dst_span <= ebp + 8u || ebp + 12u <= dst0) ||
                            !(dst0 + dst_span <= (u32)(ip - ram) || (u32)(ip - ram) + 104u <= dst0)) { ok = 0; break; }
                        col_cyc += 23 * PM_CYC + (s32)(((u32)len - 1u) * (u32)PM_FUSE_PAT) + PM_FUSE_PAT_END;
                        col_wr += len;
                    }
                    p_cur += (u32)len + 4u;
                    posts++;
                    if (ram[p_cur] == 0xFFu) break;
                }
                if (!ok || ram[p_cur] != 0xFFu) break;
            }
            if (cyc_cnt + col_cyc > end_cyc)
                break;
            if (ram[col_p] != 0xFFu) {
                p_cur = col_p;
                for (;;) {
                    u8 td = ram[p_cur], len = ram[p_cur + 1u];
                    u8 *dp = ram + edi + (u32)td * 320u;
                    const u8 *sp = ram + p_cur + 3u;
                    for (u32 k = 0; k < len; k++, dp += 320)
                        *dp = sp[k];
                    cur_eax = len;
                    p_cur += (u32)len + 4u;
                    if (ram[p_cur] == 0xFFu) break;
                }
                cur_edx = 0xFFFFFFFFu;
            }
            ebp += 4u;
            edi++;
            ebx++;
            ecx++;
            ua_w32(ram + esp0 + 8u, ebx);
            ua_w32(ram + esp0 + 12u, ecx);
            wr_cnt += col_wr;
            cyc_cnt += col_cyc;
            ran = 1u;
        }
        if (!ran) return ip;
        rEAX = cur_eax; rEDX = cur_edx; rEBX = ebx; rECX = ecx;
        rESI = width; rEDI = edi; rEBP = ebp;
        (void)sub32(ecx, width, 0u);
        writes = wr_cnt;
        if ((s32)ecx < (s32)width) cyc_cnt = idle_pm32((u32)(ip - ram), cyc_cnt, wr_cnt);
        c.cycles = cyc_cnt;
        return ((s32)ecx < (s32)width) ? ip : (ip + 104);
    }

    return ip;
}

#define OP_EIP ((u32)(ip - ram))
#define PM_IN_SPAN(p_) ((p_) >= ip_lo && (p_) < ip_lim)

static __attribute__((noinline)) void run_pm32(void)
{
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Woverride-init"
    static const void * const disp_tab[256] = {
        [0x00 ... 0xFF] = &&L_slow,
        [0x00] = &&L_cold, [0x08] = &&L_cold, [0x10] = &&L_cold, [0x18] = &&L_cold,
        [0x20] = &&L_cold, [0x28] = &&L_cold, [0x30] = &&L_cold, [0x38] = &&L_cmp38,
        [0x01] = &&L_alu_rm32, [0x09] = &&L_alu_rm32, [0x11] = &&L_alu_rm32, [0x19] = &&L_alu_rm32,
        [0x21] = &&L_alu_rm32, [0x29] = &&L_alu_rm32, [0x31] = &&L_alu_rm32, [0x39] = &&L_alu_rm32,
        [0x02] = &&L_cold, [0x0A] = &&L_cold, [0x12] = &&L_cold, [0x1A] = &&L_cold,
        [0x22] = &&L_cold, [0x2A] = &&L_cold, [0x32] = &&L_cold, [0x3A] = &&L_cmp3a,
        [0x03] = &&L_alu_r32, [0x0B] = &&L_alu_r32, [0x13] = &&L_alu_r32, [0x1B] = &&L_alu_r32,
        [0x23] = &&L_alu_r32, [0x2B] = &&L_alu_r32, [0x33] = &&L_alu_r32, [0x3B] = &&L_alu_r32,
        [0x04] = &&L_alu_al,  [0x0C] = &&L_alu_al,  [0x14] = &&L_alu_al,  [0x1C] = &&L_alu_al,
        [0x24] = &&L_alu_al,  [0x2C] = &&L_alu_al,  [0x34] = &&L_alu_al,  [0x3C] = &&L_alu_al,
        [0x05] = &&L_alu_eax, [0x0D] = &&L_alu_eax, [0x15] = &&L_alu_eax, [0x1D] = &&L_alu_eax,
        [0x25] = &&L_alu_eax, [0x2D] = &&L_alu_eax, [0x35] = &&L_alu_eax, [0x3D] = &&L_alu_eax,
        [0x0F] = &&L_0f,
        [0x26] = &&L_seg_flat, [0x2E] = &&L_seg_flat, [0x36] = &&L_seg_flat, [0x3E] = &&L_seg_flat,
        [0x40 ... 0x47] = &&L_inc_r32,
        [0x48 ... 0x4F] = &&L_dec_r32,
        [0x50 ... 0x57] = &&L_push_r32,
        [0x58 ... 0x5F] = &&L_pop_r32,
        [0x60 ... 0x61] = &&L_cold,
        [0x66] = &&L_66,
        [0x68] = &&L_push_i32,
        [0x69] = &&L_imul_imm,
        [0x6A] = &&L_push_i8,
        [0x6B] = &&L_imul_imm,
        [0x70 ... 0x7F] = &&L_jcc8,
        [0x80] = &&L_grp1_8,  [0x82] = &&L_grp1_8,
        [0x81] = &&L_grp1_32, [0x83] = &&L_grp1_32,
        [0x84] = &&L_test8,
        [0x85] = &&L_test32,
        [0x86] = &&L_cold, [0x87] = &&L_cold,
        [0x88] = &&L_mov_mr8,
        [0x89] = &&L_mov_mr32,
        [0x8A] = &&L_mov_rm8,
        [0x8B] = &&L_mov_rm32,
        [0x8D] = &&L_lea,
        [0x8F] = &&L_cold,
        [0x90] = &&L_nop,
        [0x91 ... 0x98] = &&L_cold,
        [0x99] = &&L_cdq,
        [0xA0] = &&L_cold,
        [0xA1] = &&L_mov_eax_moffs,
        [0xA2] = &&L_cold,
        [0xA3] = &&L_mov_moffs_eax,
        [0xA4 ... 0xA7] = &&L_cold,
        [0xA8] = &&L_test_al,
        [0xA9] = &&L_test_eax,
        [0xAA ... 0xAF] = &&L_cold,
        [0xB0 ... 0xB7] = &&L_mov_r8_i,
        [0xB8 ... 0xBF] = &&L_mov_r32_i,
        [0xC0] = &&L_cold,
        [0xC1] = &&L_shift32,
        [0xC2] = &&L_ret_i16,
        [0xC3] = &&L_ret,
        [0xC6] = &&L_mov_m8_i,
        [0xC7] = &&L_mov_m32_i,
        [0xC9] = &&L_leave,
        [0xD0] = &&L_cold, [0xD2] = &&L_cold,
        [0xD1] = &&L_shift32, [0xD3] = &&L_shift32,
        [0xE4] = &&L_cold, [0xE6] = &&L_cold, [0xEC] = &&L_cold,
        [0xEE] = &&L_out_dx_al,
        [0xE8] = &&L_call,
        [0xE9] = &&L_jmp32,
        [0xEB] = &&L_jmp8,
        [0xF2 ... 0xF3] = &&L_cold,
        [0xF6] = &&L_f6,
        [0xF7] = &&L_f7,
        [0xF8 ... 0xFA] = &&L_cold,
        [0xFB] = &&L_sti,
        [0xFC ... 0xFE] = &&L_cold,
        [0xFF] = &&L_ff,
    };
    static const u8 jcc_b0[64] = {
        [0 ... 63] = 0xF4,
        [11] = 0x80, [17] = 0x8A, [22] = 0x66, [25] = 0x89, [26] = 0x31, [29] = 0x83,
        [42] = 0x31, [44] = 0x8B, [49] = 0x01, [50] = 0x8B, [51] = 0x0F, [55] = 0x8B,
        [62] = 0x89, [63] = 0x0F
    };
    static const u8 jmp_b0[12] = {
        [0 ... 11] = 0xF4,
        [0] = 0x89, [2] = 0x39, [6] = 0x89, [10] = 0x39
    };
    #pragma GCC diagnostic pop

    __typeof__(c) * const cp = &c;
    __asm__ volatile("" : : "r"(cp));
    #undef rEAX
    #undef rECX
    #undef rEDX
    #undef rEBX
    #undef rESP
    #undef rEBP
    #undef rESI
    #undef rEDI
    #undef R32
    #undef R16
    #undef R8
    #define rEAX (cp->reg[0].d)
    #define rECX (cp->reg[1].d)
    #define rEDX (cp->reg[2].d)
    #define rEBX (cp->reg[3].d)
    #define rESP (cp->reg[4].d)
    #define rEBP (cp->reg[5].d)
    #define rESI (cp->reg[6].d)
    #define rEDI (cp->reg[7].d)
    #define R32(n) (cp->reg[(n) & 7].d)
    #define R16(n) (cp->reg[(n) & 7].w[0])
    #define R8(n)  (cp->reg[(n) & 3].b[((n) >> 2) & 1])

    #undef writes
    #undef run_end
    #undef pm_sub_cyc
    #define writes     (cp->wr_total)
    #define run_end    (cp->slice_end)
    #define pm_sub_cyc (cp->sub_cyc)
    u8 * const ram = mem;
    s32 end_cyc = (s32)((u32)run_end << PM_CLK_SH);
    u32 eip = cp->eip, wr_cnt = writes;
    s32 cyc_cnt = PM_CYC_IN();
    const u8 *ip, *ip_lo, *ip_lim, *p;
    u32 op, m, v, r, off, addr = 0;
    cp->faulted = 0;

sync_eip:
    if (__builtin_expect((u32)(eip - 0x100000u) < (RAM_BYTES - 0x100010u), 1)) {
        ip     = ram + eip;
        ip_lo  = ram + 0x100000u;
        ip_lim = ram + (RAM_BYTES - 16u);
    } else if (eip < 0x9FFF0u) {
        ip     = ram + eip;
        ip_lo  = ram;
        ip_lim = ram + 0x9FFF0u;
    } else {
        goto L_slow_eip;
    }

next_op:
    if (__builtin_expect(cyc_cnt >= end_cyc, 0)) goto L_done_ip;
    if (__builtin_expect(ip >= ip_lim, 0)) goto L_slow;
    p = ip + 1;
    op = ip[0];
    goto *disp_tab[op];

L_seg_flat:
    op = *p;
    if (__builtin_expect(ip + 2 < ip_lim &&
        ((op < 0x3Cu && (op & 6u) != 6u) || (op >= 0x80u && op <= 0x8Bu) ||
         (op >= 0xA0u && op <= 0xA3u) || op == 0xC6u || op == 0xC7u), 1)) {
        cyc_cnt += PM_CYC;
        ip = p;
        p = ip + 1;
        goto *disp_tab[op];
    }
    goto L_slow;

L_cmp38:
    cyc_cnt += PM_CYC;
    m = *p++;
    if (m >= 0xC0u) { v = R8(m); ip = p; }
    else { PM_EA_FN(m, p, addr); ip = p; PM_RD8(addr, v); }
    (void)sub8(v, R8(m >> 3), 0);
    goto next_op;

L_alu_rm32:
    cyc_cnt += PM_CYC;
    m = *p++;
    if (m >= 0xC0u) { v = R32(m); ip = p; }
    else { PM_EA(m, p, addr); ip = p; PM_RD32(addr, v); }
    r = alu32(op >> 3, v, R32(m >> 3));
    if (op != 0x39u) { if (m >= 0xC0u) R32(m) = r; else PM_WR32(addr, r); }
    goto next_op;

L_cmp3a:
    cyc_cnt += PM_CYC;
    m = *p++;
    if (m >= 0xC0u) { v = R8(m); ip = p; }
    else { PM_EA_FN(m, p, addr); ip = p; PM_RD8(addr, v); }
    (void)sub8(R8(m >> 3), v, 0);
    goto next_op;

L_alu_r32:
    cyc_cnt += PM_CYC;
    m = *p++;
    if (m >= 0xC0u) { v = R32(m); ip = p; }
    else { PM_EA(m, p, addr); ip = p; PM_RD32(addr, v); }
    r = alu32(op >> 3, R32(m >> 3), v);
    if (op != 0x3Bu) R32(m >> 3) = r;
    goto next_op;

L_alu_al:
    cyc_cnt += PM_CYC;
    r = alu8(op >> 3, rAL, *p);
    ip += 2;
    if (op != 0x3Cu) rAL = (u8)r;
    goto next_op;

L_alu_eax:
    cyc_cnt += PM_CYC;
    r = alu32(op >> 3, rEAX, ua_r32(p));
    ip += 5;
    if (op != 0x3Du) rEAX = r;
    goto next_op;

L_0f: {
    u32 op2 = *p++;
    switch (op2) {
    case 0x80: case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8C: case 0x8D: case 0x8E: case 0x8F:
        cyc_cnt += PM_CYC;
        if (cond(op2)) {
            s32 disp = (s32)ua_r32(p);
            cyc_cnt += PM_JCC32_TAKEN;
            const u8 *cand = ip + 6 + (pm_sptr_t)disp;
            if (__builtin_expect(PM_IN_SPAN(cand), 1)) {
                ip = cand;
                if (disp < 0) {
                    cyc_cnt = IDLE_PM32_0F(OP_EIP, cyc_cnt, wr_cnt);
#if !defined(PM_EXACT_CPI3) && !defined(NO_CALL_FUSE) && !defined(NO_TRT_IDLE)
                    if (__builtin_expect(disp == -148 && op2 == 0x8Cu && ip[0] == 0x8Bu && ip[1] == 0x15u, 0))
                        cyc_cnt = pm_try_trt_idle(ip, cyc_cnt, end_cyc);
#endif
#if !defined(PM_EXACT_CPI3) && !defined(NO_CALL_FUSE)
                    if (__builtin_expect(disp == -849 && op2 == 0x8Cu &&
                        (u32)(ip - ram) == segfn_eip + 0x1Bu && cyc_cnt < end_cyc, 0)) {
                        cp->cycles = cyc_cnt; writes = wr_cnt;
                        const u8 *nip = pm_run_segloop(0, 0u, end_cyc);
                        if (nip) {
                            cyc_cnt = cp->cycles; wr_cnt = writes;
                            if (__builtin_expect(PM_IN_SPAN(nip), 1)) { ip = nip; goto next_op; }
                            eip = (u32)(nip - ram); goto sync_eip;
                        }
                    }
#endif
                }
                goto next_op;
            }
            eip = OP_EIP + 6u + (u32)disp;
            if (disp < 0) cyc_cnt = IDLE_PM32_0F(eip, cyc_cnt, wr_cnt);
            goto sync_eip;
        }
        ip += 6;
        goto next_op;
    case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
    case 0x98: case 0x99: case 0x9A: case 0x9B: case 0x9C: case 0x9D: case 0x9E: case 0x9F:
        cyc_cnt += PM_CYC;
        m = *p++;
        r = cond(op2) ? 1u : 0u;
        if (m >= 0xC0u) { ip = p; R8(m) = (u8)r; }
        else { PM_EA_FN(m, p, addr); ip = p; PM_WR8(addr, r); }
        goto next_op;
    case 0xA4: case 0xA5: case 0xAC: case 0xAD:
        m = *p++;
        if (__builtin_expect(m >= 0xC0u, 1)) {
            cyc_cnt += PM_CYC;
            u32 cnt = (op2 & 1u) ? rCL : *p++;
            ip = p;
            R32(m) = (op2 < 0xA8u) ? shld32_fast(R32(m), R32(m >> 3), cnt) : shrd32_fast(R32(m), R32(m >> 3), cnt);
            goto next_op;
        }
        goto L_slow;
    case 0xAF:
        cyc_cnt += PM_CYC;
        m = *p++;
        if (m >= 0xC0u) { v = R32(m); ip = p; }
        else { PM_EA_FN(m, p, addr); ip = p; PM_RD32(addr, v); }
        R32(m >> 3) = imul32_fast(R32(m >> 3), v);
        goto next_op;
    case 0xB6: case 0xBE:
        cyc_cnt += PM_CYC;
        m = *p++;
        if (m >= 0xC0u) { v = R8(m); ip = p; }
        else { PM_EA(m, p, addr); ip = p; PM_RD8(addr, v); }
        R32(m >> 3) = (op2 == 0xBEu) ? (u32)(s32)(s8)v : v;
        goto next_op;
    case 0xB7: case 0xBF:
        cyc_cnt += PM_CYC;
        m = *p++;
        if (m >= 0xC0u) { v = R16(m); ip = p; }
        else { PM_EA_FN(m, p, addr); ip = p; PM_RD16(addr, v); }
        R32(m >> 3) = (op2 == 0xBFu) ? (u32)(s32)(s16)v : v;
        goto next_op;
    default:
        goto L_slow;
    }
}

L_inc_r32:
    cyc_cnt += PM_CYC;
    ip += 1;
    R32(op) = inc32(R32(op));
    goto next_op;

L_dec_r32:
    cyc_cnt += PM_CYC;
    ip += 1;
    R32(op) = dec32(R32(op));
    goto next_op;

L_push_r32:
    cyc_cnt += PM_CYC;
    ip += 1;
    v = R32(op);
L_do_push32:
    r = rESP - 4u;
    PM_PUSH32(r, v);
    rESP = r;
    goto next_op;

L_pop_r32:
    cyc_cnt += PM_CYC;
    ip += 1;
    PM_RD32(rESP, v);
    rESP += 4u;
    R32(op) = v;
    goto next_op;

L_66: {
    u32 op2 = *p++;
    if (op2 == 0x89u) {
        cyc_cnt += PM_CYC66;
        m = *p++;
        v = R16(m >> 3);
        if (m >= 0xC0u) { ip = p; R16(m) = (u16)v; }
        else { PM_EA_FN(m, p, addr); ip = p; PM_WR16_VGA(addr, v); }
        goto next_op;
    }
    if (op2 == 0x8Bu) {
        cyc_cnt += PM_CYC66;
        m = *p++;
        if (m >= 0xC0u) { ip = p; v = R16(m); }
        else { PM_EA_FN(m, p, addr); ip = p; PM_RD16(addr, v); }
        R16(m >> 3) = (u16)v;
        goto next_op;
    }
    if (op2 == 0xEFu && __builtin_expect(rDX == 0x3C4u && rAL == 2u, 1)) {
        u8 ah = rAH;
        seq_i = 2u;
        seq[2] = ah;
        vga_single_ptr = vga_fast_lut[ah & 15u];
        wr_cnt += 2u;
        cyc_cnt += PM_CYC66;
        ip += 2;
        goto next_op;
    }
    cp->cycles = cyc_cnt; writes = wr_cnt;
    int rc = pm_exec_66(OP_EIP, ip, 0u);
    if (!rc) goto L_slow;
    eip = cp->eip; wr_cnt = writes;
    if (__builtin_expect(rc == 2, 0)) {
        if (cp->check || cp->halted || !PM32_FAST_OK())
            return;
        cyc_cnt = PM_CYC_IN();
        end_cyc = (s32)((u32)run_end << PM_CLK_SH);
    } else {
        cyc_cnt = cp->cycles;
    }
    if (__builtin_expect(PM_IN_SPAN(ram + eip), 1)) {
        ip = ram + eip;
        goto next_op;
    }
    goto sync_eip;
}

L_push_i32:
    cyc_cnt += PM_CYC;
    v = ua_r32(p);
    ip += 5;
    goto L_do_push32;

L_push_i8:
    cyc_cnt += PM_CYC;
    v = (u32)(s32)(s8)*p;
    ip += 2;
    goto L_do_push32;

L_imul_imm: {
    cyc_cnt += PM_CYC;
    m = *p++;
    if (m >= 0xC0u) v = R32(m);
    else { PM_EA_FN(m, p, addr); PM_RD32(addr, v); }
    u32 imm = (op == 0x69u) ? ua_r32(p) : (u32)(s32)(s8)*p;
    ip = p + ((op == 0x69u) ? 4 : 1);
    R32(m >> 3) = imul32_fast(v, imm);
    goto next_op;
}

L_cold: {
    cp->cycles = cyc_cnt; writes = wr_cnt;
    int rc = pm_exec_cold(OP_EIP, ip, 0u);
    if (!rc) goto L_slow;
    eip = cp->eip; wr_cnt = writes;
    if (__builtin_expect(rc == 2, 0)) {
        if (cp->check || cp->halted || !PM32_FAST_OK())
            return;
        cyc_cnt = PM_CYC_IN();
        end_cyc = (s32)((u32)run_end << PM_CLK_SH);
    } else {
        cyc_cnt = cp->cycles;
    }
    if (__builtin_expect(PM_IN_SPAN(ram + eip), 1)) {
        ip = ram + eip;
        goto next_op;
    }
    goto sync_eip;
}

L_jcc8:
    cyc_cnt += PM_CYC;
    if (cond(op)) {
        s32 disp = (s8)*p;
        const u8 *cand = ip + 2 + (pm_sptr_t)disp;
        if (__builtin_expect(PM_IN_SPAN(cand), 1)) {
            ip = cand;
            if (disp < 0) {
                cyc_cnt = idle_pm32(OP_EIP, cyc_cnt, wr_cnt);
                u32 u = (u32)(-1 - disp);
                if ((u < 64u ? (ip[0] == jcc_b0[u]) : (disp == -104 && ip[0] == 0x8Bu)) && cyc_cnt < end_cyc) {
                    cp->cycles = cyc_cnt; writes = wr_cnt;
                    ip = pm_try_fuse_jnz(ip, ip_lim, disp, end_cyc);
                    cyc_cnt = cp->cycles; wr_cnt = writes;
                }
            } else if (__builtin_expect(op == 0x75u && (disp == 0x15 || disp == 0x41) && cyc_cnt < end_cyc, 0)) {
                cp->cycles = cyc_cnt; writes = wr_cnt;
                ip = pm_try_fuse_jnz(ip, ip_lim, disp == 0x15 ? -51 : -64, end_cyc);
                cyc_cnt = cp->cycles; wr_cnt = writes;
            }
            goto next_op;
        }
        eip = OP_EIP + 2u + (u32)disp;
        if (disp < 0) cyc_cnt = idle_pm32(eip, cyc_cnt, wr_cnt);
        goto sync_eip;
    }
    ip += 2;
    goto next_op;

L_grp1_8: {
    cyc_cnt += PM_CYC;
    m = *p++;
    if (m >= 0xC0u) v = R8(m);
    else { PM_EA_FN(m, p, addr); PM_RD8(addr, v); }
    u32 imm = *p++;
    ip = p;
    r = alu8(m >> 3, v, imm);
    if (((m >> 3) & 7u) != 7u) { if (m >= 0xC0u) R8(m) = (u8)r; else PM_WR8(addr, r); }
    goto next_op;
}

L_grp1_32: {
    cyc_cnt += PM_CYC;
    m = *p++;
    if (m >= 0xC0u) v = R32(m);
    else { PM_EA(m, p, addr); PM_RD32(addr, v); }
    u32 imm = (op == 0x81u) ? ua_r32(p) : (u32)(s32)(s8)*p;
    p += (op == 0x81u) ? 4 : 1;
    ip = p;
    r = alu32(m >> 3, v, imm);
    if (((m >> 3) & 7u) != 7u) { if (m >= 0xC0u) R32(m) = r; else PM_WR32(addr, r); }
    goto next_op;
}

L_test8:
    cyc_cnt += PM_CYC;
    m = *p++;
    if (m >= 0xC0u) { v = R8(m); ip = p; }
    else { PM_EA_FN(m, p, addr); ip = p; PM_RD8(addr, v); }
    logic8(v & R8(m >> 3));
    goto next_op;

L_test32:
    cyc_cnt += PM_CYC;
    m = *p++;
    if (m >= 0xC0u) { v = R32(m); ip = p; }
    else { PM_EA(m, p, addr); ip = p; PM_RD32(addr, v); }
    logic32(v & R32(m >> 3));
    goto next_op;

L_mov_mr8:
    cyc_cnt += PM_CYC;
    m = *p++;
    v = R8(m >> 3);
    if (m >= 0xC0u) { ip = p; R8(m) = (u8)v; }
    else { PM_EA(m, p, addr); ip = p; PM_WR8_VGA(addr, v); }
    goto next_op;

L_mov_mr32:
    cyc_cnt += PM_CYC;
    m = *p++;
    v = R32(m >> 3);
    if (m >= 0xC0u) { ip = p; R32(m) = v; }
    else { PM_EA(m, p, addr); ip = p; PM_WR32(addr, v); }
    goto next_op;

L_mov_rm8:
    cyc_cnt += PM_CYC;
    m = *p++;
    if (m >= 0xC0u) { v = R8(m); ip = p; }
    else { PM_EA(m, p, addr); ip = p; PM_RD8(addr, v); }
    R8(m >> 3) = (u8)v;
    goto next_op;

L_mov_rm32:
    cyc_cnt += PM_CYC;
    m = *p++;
    if (m >= 0xC0u) { v = R32(m); ip = p; }
    else { PM_EA(m, p, addr); ip = p; PM_RD32(addr, v); }
    R32(m >> 3) = v;
    goto next_op;

L_lea:
    m = *p++;
    if (m >= 0xC0u) goto L_slow;
    cyc_cnt += PM_CYC;
    if ((m & 0xC7u) == 4u && (p[0] & 0x07u) == 5u && (p[0] & 0x38u) != 0x20u) {
        u32 sib = p[0];
        R32(m >> 3) = ua_r32(p + 1) + (R32((sib >> 3) & 7u) << (sib >> 6));
        ip = p + 5;
        goto next_op;
    }
    PM_EA(m, p, v);
    ip = p;
    R32(m >> 3) = v;
    goto next_op;

L_nop:
    if (ua_r32(ip) == 0x90909090u && cyc_cnt + PM_CYC * 3 < end_cyc) {
        cyc_cnt += PM_CYC * 4;
        ip += 4;
        goto next_op;
    }
    cyc_cnt += PM_CYC;
    ip += 1;
    goto next_op;

L_cdq:
    cyc_cnt += PM_CYC;
    ip += 1;
    rEDX = (u32)((s32)rEAX >> 31);
    goto next_op;

L_mov_eax_moffs:
    cyc_cnt += PM_CYC;
    addr = ua_r32(p);
    ip += 5;
    PM_RD32(addr, rEAX);
    goto next_op;

L_mov_moffs_eax:
    cyc_cnt += PM_CYC;
    addr = ua_r32(p);
    ip += 5;
    PM_WR32(addr, rEAX);
    goto next_op;

L_test_al:
    cyc_cnt += PM_CYC;
    logic8(rAL & *p);
    ip += 2;
    goto next_op;

L_test_eax:
    cyc_cnt += PM_CYC;
    logic32(rEAX & ua_r32(p));
    ip += 5;
    goto next_op;

L_mov_r8_i:
    cyc_cnt += PM_CYC;
    R8(op) = *p;
    ip += 2;
    goto next_op;

L_mov_r32_i:
    cyc_cnt += PM_CYC;
    R32(op) = ua_r32(p);
    ip += 5;
    goto next_op;

L_shift32:
    m = *p++;
    if (__builtin_expect(m >= 0xC0u, 1)) {
        cyc_cnt += PM_CYC;
        u32 cnt = (op == 0xC1u) ? *p++ : (op == 0xD1u ? 1u : rCL);
        ip = p;
        R32(m) = shift32_fast(m >> 3, R32(m), cnt);
        goto next_op;
    }
    goto L_cold;

L_ret_i16:
    cyc_cnt += PM_CYC;
    v = ua_r16(p);
    PM_RD32(rESP, eip);
    rESP += 4u + v;
    if (__builtin_expect(PM_IN_SPAN(ram + eip), 1)) {
        ip = ram + eip;
        goto next_op;
    }
    goto sync_eip;

L_ret:
    cyc_cnt += PM_CYC;
    PM_RD32(rESP, eip);
    rESP += 4u;
    if (__builtin_expect(PM_IN_SPAN(ram + eip), 1)) {
        ip = ram + eip;
        goto next_op;
    }
    goto sync_eip;

L_mov_m8_i:
    cyc_cnt += PM_CYC;
    m = *p++;
    if (m >= 0xC0u) { R8(m) = *p++; ip = p; }
    else { PM_EA_FN(m, p, addr); v = *p++; ip = p; PM_WR8_VGA(addr, v); }
    goto next_op;

L_mov_m32_i:
    cyc_cnt += PM_CYC;
    m = *p++;
    if (m >= 0xC0u) { R32(m) = ua_r32(p); ip += 6; }
    else { PM_EA_FN(m, p, addr); v = ua_r32(p); p += 4; ip = p; PM_WR32(addr, v); }
    goto next_op;

L_leave:
    cyc_cnt += PM_CYC;
    ip += 1;
    rESP = rEBP;
    PM_RD32(rESP, rEBP);
    rESP += 4u;
    goto next_op;

L_out_dx_al:
    if (rDX == 0x3C5u && seq_i == 2u) {
        u8 al = rAL;
        seq[2] = al;
        vga_single_ptr = vga_fast_lut[al & 15u];
        wr_cnt++;
        cyc_cnt += PM_CYC;
        ip += 1;
        goto next_op;
    }
    goto L_cold;

L_call: {
    cyc_cnt += PM_CYC;
    s32 disp = (s32)ua_r32(p);
    off = OP_EIP + 5u;
    const u8 *cand = ip + 5 + (pm_sptr_t)disp;
    if (__builtin_expect(PM_IN_SPAN(cand), 1)) {
#if !defined(PM_EXACT_CPI3) && !defined(NO_CALL_FUSE)
        u32 cw0_ = ua_r16(cand);
        if ((cw0_ == 0x5651u ||
             (cw0_ == 0x5153u && (cand[2] == 0x56u || cand[2] == 0x89u || cand[5] == 0x8Bu || cand[6] == 0xA1u))) &&
            cyc_cnt < end_cyc) {
            cp->cycles = cyc_cnt; writes = wr_cnt;
            const u8 *nip = pm_try_fuse_call(cand, off, end_cyc);
            if (nip) {
                cyc_cnt = cp->cycles; wr_cnt = writes;
                ip = nip;
                goto next_op;
            }
        }
#endif
        r = rESP - 4u;
        PM_PUSH32(r, off);
        rESP = r;
        ip = cand;
        goto next_op;
    }
    r = rESP - 4u;
    PM_PUSH32(r, off);
    rESP = r;
    eip = off + (u32)disp;
    goto sync_eip;
}

L_jmp32: {
    cyc_cnt += PM_CYC;
    s32 disp = (s32)ua_r32(p);
    const u8 *cand = ip + 5 + (pm_sptr_t)disp;
    if (__builtin_expect(PM_IN_SPAN(cand), 1)) {
        ip = cand;
        if (disp < 0) cyc_cnt = idle_pm32(OP_EIP, cyc_cnt, wr_cnt);
        goto next_op;
    }
    eip = OP_EIP + 5u + (u32)disp;
    if (disp < 0) cyc_cnt = idle_pm32(eip, cyc_cnt, wr_cnt);
    goto sync_eip;
}

L_jmp8: {
    cyc_cnt += PM_CYC;
    s32 disp = (s8)*p;
    const u8 *cand = ip + 2 + (pm_sptr_t)disp;
    if (__builtin_expect(PM_IN_SPAN(cand), 1)) {
        ip = cand;
        if (disp < 0) {
            cyc_cnt = idle_pm32(OP_EIP, cyc_cnt, wr_cnt);
            u32 u = (u32)(-18 - disp);
            if (u <= 10u && ip[0] == jmp_b0[u] && cyc_cnt < end_cyc) {
                cp->cycles = cyc_cnt; writes = wr_cnt;
                ip = pm_try_fuse_jnz(ip, ip_lim, disp, end_cyc);
                cyc_cnt = cp->cycles; wr_cnt = writes;
            }
        }
        goto next_op;
    }
    eip = OP_EIP + 2u + (u32)disp;
    if (disp < 0) cyc_cnt = idle_pm32(eip, cyc_cnt, wr_cnt);
    goto sync_eip;
}

L_f6: {
    m = *p++;
    if (__builtin_expect(((m >> 3) & 7u) <= 1u, 1)) {
        cyc_cnt += PM_CYC;
        if (m >= 0xC0u) v = R8(m);
        else { PM_EA_FN(m, p, addr); PM_RD8(addr, v); }
        u32 imm = *p++;
        ip = p;
        logic8(v & imm);
        goto next_op;
    }
    goto L_cold;
}

L_f7: {
    u32 m7 = *p, subk = (m7 >> 3) & 7u;
    if (__builtin_expect(subk <= 1u || subk == 3u || subk == 5u, 1)) {
        p++;
        cyc_cnt += PM_CYC;
        if (m7 >= 0xC0u) v = R32(m7);
        else { PM_EA(m7, p, addr); PM_RD32(addr, v); }
        if (subk <= 1u) {
            u32 imm = ua_r32(p);
            ip = p + 4;
            logic32(v & imm);
            goto next_op;
        }
        if (subk == 3u) {
            ip = p;
            r = sub32(0u, v, 0u);
            cp->fl = (cp->fl & ~F_CF) | (v != 0u);
            if (m7 >= 0xC0u) R32(m7) = r; else PM_WR32(addr, r);
            goto next_op;
        }
        signed long long prod = (signed long long)(s32)rEAX * (signed long long)(s32)v;
        u32 lo = (u32)prod, hi = (u32)((unsigned long long)prod >> 32);
        rEAX = lo;
        rEDX = hi;
        if (cyc_cnt < end_cyc && p < ip_lim && ua_r32(p) == 0x10D0AC0Fu) {
            rEAX = shrd32_fast(lo, hi, 16u);
            cyc_cnt += PM_FUSE_FMUL;
            ip = p + 4;
            goto next_op;
        }
        cp->fl = (hi != (u32)((s32)lo >> 31)) ? (F_CF | F_OF) : 0u;
        ip = p;
        goto next_op;
    }
    cp->cycles = cyc_cnt; writes = wr_cnt;
    if (!pm_exec_f7(OP_EIP, ip, 0u)) goto L_slow;
    eip = cp->eip; cyc_cnt = cp->cycles; wr_cnt = writes;
    if (__builtin_expect(PM_IN_SPAN(ram + eip), 1)) {
        ip = ram + eip;
        goto next_op;
    }
    goto sync_eip;
}

L_sti:
    cyc_cnt += PM_CYC;
    cp->sys |= F_IF; cp->check = 2;
    cp->eip = OP_EIP + 1u; PM_CYC_OUT(cyc_cnt); writes = wr_cnt;
    return;

L_ff: {
    m = *p++;
    u32 subk = (m >> 3) & 7u;
    if (subk == 3u || subk == 5u || subk == 7u) goto L_slow;
    cyc_cnt += PM_CYC;
    if (m >= 0xC0u) {
        v = R32(m);
        if (subk == 0u) { R32(m) = inc32(v); ip = p; goto next_op; }
        if (subk == 1u) { R32(m) = dec32(v); ip = p; goto next_op; }
    } else {
        PM_EA_FN(m, p, addr);
        PM_RD32(addr, v);
        if (subk == 0u) { PM_WR32(addr, inc32(v)); ip = p; goto next_op; }
        if (subk == 1u) { PM_WR32(addr, dec32(v)); ip = p; goto next_op; }
    }
    if (subk == 6u) { ip = p; goto L_do_push32; }
    if (subk == 2u) {
        u32 ret_eip = OP_EIP + (u32)(p - ip);
        r = rESP - 4u;
        PM_PUSH32(r, ret_eip);
        rESP = r;
    }
    eip = v;
    if (__builtin_expect(PM_IN_SPAN(ram + eip), 1)) {
        ip = ram + eip;
        goto next_op;
    }
    goto sync_eip;
}

L_slow:
    eip = OP_EIP;
L_slow_eip:
    cp->eip = eip;
    PM_CYC_OUT(cyc_cnt);
    writes = wr_cnt;
    step();
    if (cp->check || cp->halted || !PM32_FAST_OK())
        return;
    eip = cp->eip;
    cyc_cnt = PM_CYC_IN();
    wr_cnt = writes;
    end_cyc = (s32)((u32)run_end << PM_CLK_SH);
    goto sync_eip;

L_done_ip:
    cp->eip = OP_EIP;
    PM_CYC_OUT(cyc_cnt);
    writes = wr_cnt;

    #undef rEAX
    #undef rECX
    #undef rEDX
    #undef rEBX
    #undef rESP
    #undef rEBP
    #undef rESI
    #undef rEDI
    #undef R32
    #undef R16
    #undef R8
    #define rEAX c.reg[0].d
    #define rECX c.reg[1].d
    #define rEDX c.reg[2].d
    #define rEBX c.reg[3].d
    #define rESP c.reg[4].d
    #define rEBP c.reg[5].d
    #define rESI c.reg[6].d
    #define rEDI c.reg[7].d
    #define R32(n) (c.reg[(n) & 7].d)
    #define R16(n) (c.reg[(n) & 7].w[0])
    #define R8(n)  (c.reg[(n) & 3].b[((n) >> 2) & 1])
    #undef writes
    #undef run_end
    #undef pm_sub_cyc
    #define writes     (c.wr_total)
    #define run_end    (c.slice_end)
    #define pm_sub_cyc (c.sub_cyc)
}

#undef PM_IN_SPAN
#undef PM_CLK_SH
#undef PM_CYC_IN
#undef PM_CYC_OUT
#undef OP_EIP
#undef PM_EA
#undef PM_EA_ESP
#undef PM_EA_SIB
#undef PM_EA_FN
#undef PM_IS_RAM2
#undef PM_IS_RAM4
#undef PM_IS_XRAM4
#undef PM_RD8
#undef PM_WR8
#undef PM_WR8_VGA
#undef PM_RD16
#undef PM_WR16
#undef PM_WR16_VGA
#undef PM_RD32
#undef PM_WR32
#undef PM_PUSH32

static void run(s32 t)
{
    run_end = t;
    while (c.cycles < run_end) {
        if (c.check) {
            if (c.check > 1) c.check--;
            else             irq_check();
        }
        if (c.halted) {
            if (c.cycles < run_end) c.cycles = run_end;
            break;
        }
        if (PM32_FAST_OK() && !c.check) {
            run_pm32();
            continue;
        }
        step();
    }
}

static void advance(s32 t)
{
    while (c.cycles < t) {
        s32 next = t;
        if (pit0_on && pit0_next < next)
            next = pit0_next;
        run(next);
        while (pit0_on && c.cycles >= pit0_next) {
            pic_raise(0);
            if (periodic(0)) {
                pit_start[0] = pit0_next;
                if (pit_new[0]) { pit_n[0] = pit_new[0]; pit_new[0] = 0; }
                pit0_next += (s32)(pit_n[0] * PIT_CYCLES);
            } else {
                pit0_on = 0;
            }
        }
    }
}

#pragma GCC pop_options

/* ---- Keyboard ---- */
static const u8 hid_scan[0x64] = {
    0x1E, 0x30, 0x2E, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19,
    0x10, 0x13, 0x1F, 0x14, 0x16, 0x2F, 0x11, 0x2D, 0x15, 0x2C,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    0x1C, 0x01, 0x0E, 0x0F, 0x39, 0x0C, 0x0D, 0x1A, 0x1B, 0x2B, 0x2B, 0x27, 0x28, 0x29, 0x33, 0x34,
    0x35, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x57, 0x58, 0x00, 0x46,
    0x00, 0xD2, 0xC7, 0xC9, 0xD3, 0xCF, 0xD1, 0xCD, 0xCB, 0xD0, 0xC8, 0x45, 0xB5, 0x37, 0x4A, 0x4E,
    0x9C, 0x4F, 0x50, 0x51, 0x4B, 0x4C, 0x4D, 0x47, 0x48, 0x49, 0x52, 0x53, 0x56, 0xDD, 0x00, 0x00,
};
static const u8 hid_mods[8] = {0x1D, 0x2A, 0x38, 0xDB, 0x9D, 0x36, 0xB8, 0xDC};

void dos_keys_from_hid(const u8 *usages, int n, u8 keys[32])
{
    for (int i = 0; i < 32; i++) keys[i] = 0;
    for (int i = 0; i < n; i++) {
        u32 u = usages[i], k = 0;
        if (u >= 0x04u && u < 0x04u + sizeof(hid_scan)) k = hid_scan[u - 0x04u];
        else if (u >= 0xE0u && u <= 0xE7u)              k = hid_mods[u - 0xE0u];
        if (k) keys[k >> 3] |= (u8)(1u << (k & 7u));
    }
}

static u32 char_scan(u32 ch)
{
    static const char plain[]   = "\0\0331234567890-=\b\tqwertyuiop[]\r\0asdfghjkl;'`\0\\zxcvbnm,./";
    static const char shifted[] = "\0\033!@#$%^&*()_+\b\tQWERTYUIOP{}\r\0ASDFGHJKL:\"~\0|ZXCVBNM<>?";
    if (ch == ' ')  return 0x39;
    if (ch == '\n') return 0x1C;
    if (ch == 127)  return 0x0E;
    for (u32 i = 1; i < sizeof(plain) - 1u; i++) {
        if ((u8)plain[i] == ch && ch)   return i;
        if ((u8)shifted[i] == ch && ch) return 0x100u | i;
    }
    return 0;
}

void dos_type(const char *text)
{
    while (*text) {
        int next = (q_tail + 1) & 255;
        if (next == q_head) break;
        queue[q_tail] = *text++;
        q_tail = next;
    }
}

int dos_typing(void) { return (q_tail - q_head) & 255; }

static void typed(u8 keys[32])
{
    if (q_head == q_tail) return;
    u32 k = char_scan((u8)queue[q_head]);
    if (q_frame < 3 && k) {
        keys[(k & 0xFFu) >> 3] |= (u8)(1u << (k & 7u));
        if (k & 0x100u) keys[0x2A >> 3] |= 1u << (0x2A & 7);
    }
    if (++q_frame == 6) {
        q_frame = 0;
        q_head = (q_head + 1) & 255;
    }
}

static void press(u8 keys[32], u32 k) { keys[k >> 3] |= (u8)(1u << (k & 7u)); }

void dos_frame(u8 pad, const u8 keys[32], u16 *picture)
{
    u8 now[32];
    for (int i = 0; i < 32; i++) now[i] = keys ? keys[i] : 0;
    typed(now);
    if (pad & DOS_UP)     press(now, 0xC8);
    if (pad & DOS_DOWN)   press(now, 0xD0);
    if (pad & DOS_LEFT)   press(now, 0xCB);
    if (pad & DOS_RIGHT)  press(now, 0xCD);
    if (pad & DOS_A)      press(now, (c.cr0 & 1u) ? 0x1Du : 0xC8u); /* 386 pmode: Ctrl (Fire); real-mode: Up (Dizzy jump) */
    if (pad & DOS_B)      press(now, 0x39);                         /* Space (Open / Use) */
    if (pad & DOS_START)  press(now, 0x1C);                         /* Enter */
    if (pad & DOS_SELECT) press(now, 0x01);                         /* Esc */

    for (u32 k = 1; k < 256; k++) {
        u32 bit = 1u << (k & 7u), down = now[k >> 3] & bit;
        if (down == (held_was[k >> 3] & bit)) continue;
        if (k & 0x80u) kbd_put(0xE0);
        kbd_put((k & 0x7Fu) | (down ? 0u : 0x80u));
    }
    for (int i = 0; i < 32; i++) held_was[i] = now[i];

    pic_buf = picture;
    pic_changed = 0;
    int drawn = 0;
    for (int s = 0; s < SLICES; s++) {
        s32 end = (s + 1) * (FRAME_CYCLES / SLICES);
        if (!drawn && end > DRAW_AT) {
            advance(DRAW_AT);
            if (pic_buf) draw();
            else dirty = 1;
            drawn = 1;
        }
        advance(end);
        kbd_deliver();
#ifdef PM_EXACT_CPI3
        opl2_advance_timers(&M->opl, DOS_FRAME_US / SLICES);
        render_audio_slice(1u);
#else
        if (!sample_rate) {
            render_audio_slice(1u);
        } else {
            opl2_advance_timers(&M->opl, DOS_FRAME_US / SLICES);
            aud_slice_pend++;
            if (s == SLICES - 1 || (s & 3) == 3 || !(c.cr0 & 1u) || sample_rate < 32000u ||
                (sb.dma_active && !sb.dma_paused && sb.blk_rem <= 128u)) {
                render_audio_slice(aud_slice_pend);
                aud_slice_pend = 0;
            }
        }
#endif
    }
    for (int i = 1; i < 3; i++) pit_catch_up(i);
    c.cycles -= FRAME_CYCLES;
    opl_last_cyc -= FRAME_CYCLES;
    if (opl_last_cyc < -0x40000000) opl_last_cyc = -0x40000000;
    pit0_next -= FRAME_CYCLES;
    for (int i = 0; i < 3; i++) {
        pit_start[i] -= FRAME_CYCLES;
        if (pit_start[i] < -0x40000000) pit_start[i] = -0x40000000;
    }
    cycles_hi += FRAME_CYCLES;
    frames++;
}

static char *put(char *p, const char *s)
{
    while (*s && p < info + sizeof(info) - 1) *p++ = *s++;
    *p = 0;
    return p;
}

static char *put_number(char *p, u32 v)
{
    char d[12];
    int n = 0;
    do d[n++] = (char)('0' + v % 10u); while (v /= 10u);
    while (n && p < info + sizeof(info) - 1) *p++ = d[--n];
    *p = 0;
    return p;
}

void dos_clear_files(void)
{
    nfiles = 1;
    scratch_used = 0;
    for (int i = 0; i < FILES; i++) {
        files[i].wr_data = 0;
        files[i].cap = 0;
    }
}

const char *dos_add_file(const char *name, const u8 *data, u32 size)
{
    if (nfiles < 1) nfiles = 1;
    if (nfiles >= FILES) return "too many files";
    dos_name(name, files[nfiles].name);
    files[nfiles].data = data;
    files[nfiles].wr_data = 0;
    files[nfiles].size = size;
    files[nfiles].cap = 0;
    nfiles++;
    return 0;
}

void dos_args(const char *text)
{
    int n = 0;
    if (text && *text && *text != ' ') args[n++] = ' ';
    while (text && *text && n < (int)sizeof(args) - 1) args[n++] = *text++;
    args[n] = 0;
}

const char *dos_load(u8 *file, u32 size, const char *name)
{
    if (!file || size < 2u) return "no program";
    int exe = file[0] == 'M' && file[1] == 'Z';
    char base[13];
    dos_name(name ? name : "PROGRAM.EXE", base);
    int n = 0, dot = 0;
    while (base[n]) if (base[n++] == '.') dot = 1;
    if (!exe) {
        if (size > 0xFF00u) return "not a DOS program (an .exe starts with MZ; a .com file is 64 KB at most)";
        if (!dot && n < 9) { base[n++] = '.'; base[n++] = 'C'; base[n++] = 'O'; base[n++] = 'M'; base[n] = 0; }
    }
    if (nfiles < 1) nfiles = 1;
    for (int i = 0; i < 13; i++) files[0].name[i] = base[i];
    files[0].data = file;
    files[0].wr_data = 0;
    files[0].size = size;
    files[0].cap = 0;
    program = file;
    program_size = size;
    machine_reset();
    const char *why = start_program();
    if (why) {
        program = 0;
        return why;
    }
    char *p = put(info, files[0].name);
    p = put(p, exe ? ": 386 DOS .exe of " : ": DOS .com of ");
    p = put_number(p, (size + 1023u) >> 10);
    p = put(p, " KB (8 MB XMS + SB/OPL2");
    if (nfiles > 1) {
        p = put(p, ", +");
        p = put_number(p, (u32)nfiles - 1u);
        p = put(p, nfiles == 2 ? " file" : " files");
    }
    p = put(p, ")");
    if (args[0]) {
        p = put(p, ", args:");
        put(p, args);
    }
    return 0;
}

const char *dos_info(void) { return info; }

u8 *dos_save_ram(u32 *size, int *battery)
{
    *size = 0;
    *battery = 0;
    return mem;
}

int dos_save_changed(void) { return 0; }
u32 dos_cpu_cycles(void)   { return cycles_hi + (u32)c.cycles; }
int dos_jammed(void)       { return ended || (c.halted && !(c.sys & F_IF)); }
u32 dos_idle_cycles(void)  { return idle_cycles; }
int dos_mode(void)            { return video_mode; }
int dos_pmode(void)           { return (c.cr0 & 1u) != 0; }
int dos_picture_changed(void) { return pic_changed; }

u8 dos_peek(u32 a)
{
    a &= (RAM_BYTES - 1u);
    if (a - vga_lo < vga_n)
        return vram[gc[4] & 3u][a - vga_lo];
    return mem[a];
}

void dos_registers(u16 r[14])
{
    for (int i = 0; i < 8; i++) r[i] = R16(i);
    for (int i = 0; i < 4; i++) r[8 + i] = c.sr[i];
    r[12] = (u16)c.eip;
    r[13] = (u16)get_eflags();
}
