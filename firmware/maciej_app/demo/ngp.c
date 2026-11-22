/* SNK Neo Geo Pocket & Neo Geo Pocket Color (.ngp / .ngc) emulator:
   - Toshiba TLCS-900/H 32-bit CPU (6.144 MHz, 4 register banks, MicroDMA 0..3, 8-bit Timers 0..3, interrupt controller)
   - Zilog Z80 sound coprocessor (3.072 MHz, shared 4 KB RAM $7000..$7FFF, via z80.c)
   - K1GE (monochrome) & K2GE (color) 2D scanline engine (160 x 152 BGR555, Scroll 1 & 2, 64 chained sprites, window)
   - T6W28 dual-PSG + dual 8-bit DAC ($A0..$A3) synthesized at 48 kHz mono
   - Cartridge Flash save (both BIOS VECT_FLASHWRITE/ERS & direct $5555/$2AAA Flash commands, 64 KB .sav)
   - Clean-room built-in 64 KB BIOS ($FF0000..$FFFFFF, $FFFE00 vector table + SWI 1) + optional ngp_bios.rom */
#pragma GCC optimize("O2")

#ifdef __mips__
#include "hw.h"
#endif
#include "z80.h"
#include "ngp.h"

#define PAD_A      0x0001u
#define PAD_B      0x0002u
#define PAD_SELECT 0x0004u
#define PAD_START  0x0008u
#define PAD_UP     0x0010u
#define PAD_DOWN   0x0020u
#define PAD_LEFT   0x0040u
#define PAD_RIGHT  0x0080u

#define NGP_MAX_ROM   0x400000u   /* up to 4 MB (2x 2 MB Flash chips) */
#define NGP_SAV_SIZE  0x10000u    /* top 64 KB Flash save area for .sav */
#define NGP_AUD_MAX   2048
#define NGP_LINES     199         /* 0..151 active, 152..198 VBlank */
#define NGP_CYC_LINE  515         /* 6.144 MHz / (199 * 59.73) = ~515 cycles/line */

/* Flag bits in low byte F of SR */
#define FL_C  0x01u
#define FL_N  0x02u
#define FL_V  0x04u
#define FL_H  0x10u
#define FL_Z  0x40u
#define FL_S  0x80u

struct ngp_work {
    u32 sfr_align;
    u8 sfr[0x100];         /* $0000..$00FF internal SFRs (32-bit aligned, offset < 32 KB for 1-insn MIPS loads) */
    u8 wram[0x3000];       /* $4000..$6FFF (12 KB) */
    u8 zram[0x1000];       /* $7000..$7FFF (4 KB shared with Z80) */
    u8 vram[0x4000];       /* $8000..$BFFF (16 KB K1GE/K2GE regs, OAM, palettes, tilemaps, tiles) */
    s16 aud_buf[NGP_AUD_MAX];
    u8 bios[0x10000];
    u8 ext_bios[0x10000];
    u8 sav_buf[NGP_SAV_SIZE];
    u8 rom[NGP_MAX_ROM];
};

#ifdef __mips__
#define W (*((struct ngp_work *)KSEG0(EMU_RAM_PHYS)))
#else
static struct ngp_work ngp_host_work;
#define W ngp_host_work
#endif

struct t6w_side {
    u16 period[3];
    u8 attn[4];
    u8 noise_ctrl;
    u8 latch_ch;
    u8 latch_attn;
    int cnt[4];
    u8 out[4];
    u16 lfsr;
};

static struct {
    u32 rom_size;
    u32 sav_offset;        /* offset inside W.rom persisted to .sav */
    u8 has_ext_bios;
    u8 is_color_rom;
    u8 sav_dirty;
    u8 jammed;

    /* TLCS-900/H CPU state */
    u32 bank[4][4];        /* 4 banks x (XWA, XBC, XDE, XHL) */
    u32 ix[4];             /* XIX, XIY, XIZ, XSP */
    u32 pc;
    u16 sr;                /* bits 15=SYSM, 14..12=IFF, 10..8=RFP, 7..0=F */
    u8 f_dash;
    u8 halted;
    u16 intnest;
    u8 clk_gear;           /* 0..4 divider shift */

    /* MicroDMA channels 0..3 */
    u32 dmas[4];
    u32 dmad[4];
    u16 dmac[4];
    u8 dmam[4];

    /* 8-bit Timers 0..3 */
    u8 t_cnt[4];
    u32 t_presc;
    u8 t_out[2];           /* TO1 / TO3 flip-flops */

    /* Cartridge Flash state machine */
    u8 flash_step;
    u8 flash_cmd;

    /* Scanline state */
    int scan_y;
    int line_cyc;

    /* Z80 & T6W28 Audio */
    struct z80 zcpu;
    u8 z80_active;
    struct t6w_side psg_l, psg_r;
    u8 dac_l, dac_r;
    int psg_rem;
    u32 sample_rate;
    u32 aud_count;
    u32 aud_frac;
    int dc_acc;

    u16 pad;
    char info_str[96];
} S;

/* Clean-room 96-glyph 8x8 ASCII font (0x20..0x7F) for VECT_SYSFONTSET */
static const u8 sys_font96[96][8] = {
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, {0x18,0x18,0x18,0x18,0x18,0x00,0x18,0x00},
    {0x6C,0x6C,0x24,0x00,0x00,0x00,0x00,0x00}, {0x6C,0xFE,0x6C,0x6C,0xFE,0x6C,0x00,0x00},
    {0x18,0x7E,0xD8,0x7C,0x1B,0x7E,0x18,0x00}, {0xC6,0xCC,0x18,0x30,0x66,0xC6,0x00,0x00},
    {0x38,0x6C,0x38,0x76,0xDC,0xCC,0x76,0x00}, {0x18,0x18,0x30,0x00,0x00,0x00,0x00,0x00},
    {0x0C,0x18,0x30,0x30,0x30,0x18,0x0C,0x00}, {0x30,0x18,0x0C,0x0C,0x0C,0x18,0x30,0x00},
    {0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00}, {0x00,0x18,0x18,0x7E,0x18,0x18,0x00,0x00},
    {0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x30}, {0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0x00},
    {0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00}, {0x06,0x0C,0x18,0x30,0x60,0xC0,0x00,0x00},
    {0x7C,0xC6,0xCE,0xD6,0xE6,0xC6,0x7C,0x00}, {0x18,0x38,0x18,0x18,0x18,0x18,0x7E,0x00},
    {0x7C,0xC6,0x06,0x3C,0x60,0xC0,0xFE,0x00}, {0x7C,0xC6,0x06,0x3C,0x06,0xC6,0x7C,0x00},
    {0x1C,0x3C,0x6C,0xCC,0xFE,0x0C,0x0C,0x00}, {0xFE,0xC0,0xFC,0x06,0x06,0xC6,0x7C,0x00},
    {0x7C,0xC0,0xFC,0xC6,0xC6,0xC6,0x7C,0x00}, {0xFE,0x06,0x0C,0x18,0x30,0x30,0x30,0x00},
    {0x7C,0xC6,0xC6,0x7C,0xC6,0xC6,0x7C,0x00}, {0x7C,0xC6,0xC6,0x7E,0x06,0xC6,0x7C,0x00},
    {0x00,0x18,0x18,0x00,0x18,0x18,0x00,0x00}, {0x00,0x18,0x18,0x00,0x18,0x18,0x30,0x00},
    {0x0C,0x18,0x30,0x60,0x30,0x18,0x0C,0x00}, {0x00,0x00,0x7E,0x00,0x7E,0x00,0x00,0x00},
    {0x30,0x18,0x0C,0x06,0x0C,0x18,0x30,0x00}, {0x7C,0xC6,0x0C,0x18,0x18,0x00,0x18,0x00},
    {0x7C,0xC6,0xDE,0xDE,0xDC,0xC0,0x7C,0x00}, {0x38,0x6C,0xC6,0xC6,0xFE,0xC6,0xC6,0x00},
    {0xFC,0xC6,0xC6,0xFC,0xC6,0xC6,0xFC,0x00}, {0x7C,0xC6,0xC0,0xC0,0xC0,0xC6,0x7C,0x00},
    {0xF8,0xCC,0xC6,0xC6,0xC6,0xCC,0xF8,0x00}, {0xFE,0xC0,0xC0,0xFC,0xC0,0xC0,0xFE,0x00},
    {0xFE,0xC0,0xC0,0xFC,0xC0,0xC0,0xC0,0x00}, {0x7C,0xC6,0xC0,0xCE,0xC6,0xC6,0x7E,0x00},
    {0xC6,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0x00}, {0x7E,0x18,0x18,0x18,0x18,0x18,0x7E,0x00},
    {0x1E,0x06,0x06,0x06,0xC6,0xC6,0x7C,0x00}, {0xC6,0xCC,0xD8,0xF0,0xD8,0xCC,0xC6,0x00},
    {0xC0,0xC0,0xC0,0xC0,0xC0,0xC0,0xFE,0x00}, {0xC6,0xEE,0xFE,0xD6,0xC6,0xC6,0xC6,0x00},
    {0xC6,0xE6,0xF6,0xDE,0xCE,0xC6,0xC6,0x00}, {0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00},
    {0xFC,0xC6,0xC6,0xFC,0xC0,0xC0,0xC0,0x00}, {0x7C,0xC6,0xC6,0xC6,0xD6,0xDE,0x7C,0x06},
    {0xFC,0xC6,0xC6,0xFC,0xD8,0xCC,0xC6,0x00}, {0x7C,0xC6,0xC0,0x7C,0x06,0xC6,0x7C,0x00},
    {0xFE,0x18,0x18,0x18,0x18,0x18,0x18,0x00}, {0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00},
    {0xC6,0xC6,0xC6,0xC6,0x6C,0x38,0x10,0x00}, {0xC6,0xC6,0xC6,0xD6,0xFE,0xEE,0xC6,0x00},
    {0xC6,0xC6,0x6C,0x38,0x6C,0xC6,0xC6,0x00}, {0xC6,0xC6,0x6C,0x38,0x18,0x18,0x18,0x00},
    {0xFE,0x06,0x0C,0x18,0x30,0x60,0xFE,0x00}, {0x3C,0x30,0x30,0x30,0x30,0x30,0x3C,0x00},
    {0xC0,0x60,0x30,0x18,0x0C,0x06,0x00,0x00}, {0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0x00},
    {0x10,0x38,0x6C,0xC6,0x00,0x00,0x00,0x00}, {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF},
    {0x30,0x18,0x0C,0x00,0x00,0x00,0x00,0x00}, {0x00,0x00,0x78,0x0C,0x7C,0xCC,0x76,0x00},
    {0xC0,0xC0,0xDC,0xE6,0xC6,0xC6,0xDC,0x00}, {0x00,0x00,0x7C,0xC6,0xC0,0xC6,0x7C,0x00},
    {0x06,0x06,0x76,0xCE,0xC6,0xC6,0x76,0x00}, {0x00,0x00,0x7C,0xC6,0xFE,0xC0,0x7C,0x00},
    {0x1C,0x36,0x30,0x78,0x30,0x30,0x30,0x00}, {0x00,0x00,0x76,0xC6,0xC6,0x7E,0x06,0x7C},
    {0xC0,0xC0,0xDC,0xE6,0xC6,0xC6,0xC6,0x00}, {0x18,0x00,0x38,0x18,0x18,0x18,0x3C,0x00},
    {0x06,0x00,0x06,0x06,0x06,0x06,0xC6,0x7C}, {0xC0,0xC0,0xCC,0xD8,0xF0,0xD8,0xCC,0x00},
    {0x38,0x18,0x18,0x18,0x18,0x18,0x3C,0x00}, {0x00,0x00,0xEC,0xFE,0xD6,0xC6,0xC6,0x00},
    {0x00,0x00,0xDC,0xE6,0xC6,0xC6,0xC6,0x00}, {0x00,0x00,0x7C,0xC6,0xC6,0xC6,0x7C,0x00},
    {0x00,0x00,0xDC,0xC6,0xC6,0xDC,0xC0,0xC0}, {0x00,0x00,0x76,0xC6,0xC6,0x76,0x06,0x06},
    {0x00,0x00,0xDC,0xE6,0xC0,0xC0,0xC0,0x00}, {0x00,0x00,0x7C,0xC0,0x7C,0x06,0xFC,0x00},
    {0x30,0x30,0x7C,0x30,0x30,0x36,0x1C,0x00}, {0x00,0x00,0xC6,0xC6,0xC6,0xCE,0x76,0x00},
    {0x00,0x00,0xC6,0xC6,0xC6,0x6C,0x38,0x00}, {0x00,0x00,0xC6,0xC6,0xD6,0xFE,0x6C,0x00},
    {0x00,0x00,0xC6,0x6C,0x38,0x6C,0xC6,0x00}, {0x00,0x00,0xC6,0xC6,0xC6,0x7E,0x06,0x7C},
    {0x00,0x00,0xFE,0x0C,0x38,0x60,0xFE,0x00}, {0x0E,0x18,0x18,0x70,0x18,0x18,0x0E,0x00},
    {0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x00}, {0x70,0x18,0x18,0x0E,0x18,0x18,0x70,0x00},
    {0x76,0xDC,0x00,0x00,0x00,0x00,0x00,0x00}, {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}
};

static const s16 sn_vol[16] = {
    5120, 4067, 3231, 2566, 2038, 1619, 1286, 1021, 811, 644, 512, 406, 323, 256, 204, 0
};

/* ---- T6W28 Dual PSG + Z80 Sound Bus ---- */
static void t6w_reset_side(struct t6w_side *p)
{
    for (int i = 0; i < 3; i++) p->period[i] = 1u;
    for (int i = 0; i < 4; i++) { p->attn[i] = 0x0Fu; p->cnt[i] = 1; p->out[i] = 1; }
    p->noise_ctrl = 0;
    p->latch_ch = 0;
    p->latch_attn = 0;
    p->lfsr = 0x4000u;
}

static void t6w_write_side(struct t6w_side *p, u8 v)
{
    if (v & 0x80u) {
        u8 ch = (v >> 5) & 3u;
        p->latch_ch = ch;
        p->latch_attn = (v >> 4) & 1u;
        if (p->latch_attn) {
            p->attn[ch] = v & 0x0Fu;
        } else if (ch < 3u) {
            p->period[ch] = (u16)((p->period[ch] & 0x3F0u) | (v & 0x0Fu));
        } else {
            p->noise_ctrl = v & 0x07u;
            p->lfsr = 0x4000u;
        }
    } else {
        u8 ch = p->latch_ch;
        if (p->latch_attn)
            p->attn[ch] = v & 0x0Fu;
        else if (ch < 3u)
            p->period[ch] = (u16)(((u16)(v & 0x3Fu) << 4) | (p->period[ch] & 0x0Fu));
        else {
            p->noise_ctrl = v & 0x07u;
            p->lfsr = 0x4000u;
        }
    }
}

static void irq_set_pending(u8 sfr_addr, int hi_nibble);

static u8 z80_mem_rd(struct z80 *z, u16 addr)
{
    (void)z;
    if (addr < 0x4000u) return W.zram[addr & 0xFFFu];
    if (addr == 0x8000u) return W.sfr[0xBC];
    return 0xFFu;
}

static void z80_mem_wr(struct z80 *z, u16 addr, u8 val)
{
    (void)z;
    if (addr < 0x4000u) { W.zram[addr & 0xFFFu] = val; return; }
    if (addr == 0x4000u) { t6w_write_side(&S.psg_r, val); return; }
    if (addr == 0x4001u) { t6w_write_side(&S.psg_l, val); return; }
    if (addr == 0x8000u) { W.sfr[0xBC] = val; return; }
    if (addr == 0xC000u) { irq_set_pending(0x71u, 1); return; } /* INT5 from Z80 */
}

static u8 z80_io_in(struct z80 *z, u16 port) { (void)z; (void)port; return 0xFFu; }
static void z80_io_out(struct z80 *z, u16 port, u8 val) { (void)z; (void)port; (void)val; }

static void z80_setup_bus(void)
{
    z80_init(&S.zcpu);
    S.zcpu.read = z80_mem_rd;
    S.zcpu.write = z80_mem_wr;
    S.zcpu.in = z80_io_in;
    S.zcpu.out = z80_io_out;
    S.zcpu.trap = -1;
    for (int i = 0; i < 64; i++) {
        S.zcpu.rd[i] = (i < 4) ? (W.zram + i * 1024) : 0;
        S.zcpu.wr[i] = (i < 4) ? (W.zram + i * 1024) : 0;
    }
}

/* ---- Joypad Helper ($00B0 & $6F82) ---- */
static u8 current_joypad(void)
{
    u8 v = 0;
    if (S.pad & PAD_UP)                  v |= 0x01u;
    if (S.pad & PAD_DOWN)                v |= 0x02u;
    if (S.pad & PAD_LEFT)                v |= 0x04u;
    if (S.pad & PAD_RIGHT)               v |= 0x08u;
    if (S.pad & PAD_A)                   v |= 0x10u;
    if (S.pad & PAD_B)                   v |= 0x20u;
    if (S.pad & (PAD_START | PAD_SELECT)) v |= 0x40u; /* Option */
    return v;
}

/* ---- 24-bit Memory Bus ---- */
static u8 mem_read8(u32 addr)
{
    addr &= 0xFFFFFFu;
    if (addr >= 0x4000u && addr < 0x7000u)
        return W.wram[addr - 0x4000u];
    if (addr >= 0x200000u && addr < 0x400000u) {
        u32 off = addr - 0x200000u;
        if (__builtin_expect(S.flash_cmd == 0x90u, 0)) {
            u32 r = off & 3u;
            if (r == 0u) return 0x98u; /* Toshiba Flash manufacturer ID */
            if (r == 1u) return (S.rom_size >= 0x200000u) ? 0x2Fu : (S.rom_size >= 0x100000u ? 0xABu : 0x2Cu);
            return 0x00u;
        }
        return (off < S.rom_size) ? W.rom[off] : 0xFFu;
    }
    if (addr >= 0x8000u && addr < 0xC000u) {
        if (addr >= 0x8020u)
            return W.vram[addr - 0x8000u];
        if (addr == 0x8008u) {
            u32 rh = ((u32)S.line_cyc * 256u) / NGP_CYC_LINE;
            return (u8)(rh > 255u ? 255u : rh);
        }
        if (addr == 0x8009u)
            return (u8)S.scan_y;
        if (addr == 0x8010u)
            return (S.scan_y >= NGP_H) ? 0x40u : 0x00u;
        return W.vram[addr - 0x8000u];
    }
    if (addr < 0x0100u) {
        if (addr == 0xB0u) return current_joypad();
        return W.sfr[addr];
    }
    if (addr >= 0x7000u && addr < 0x8000u)
        return W.zram[addr - 0x7000u];
    if (addr >= 0x800000u && addr < 0xA00000u) {
        u32 off = 0x200000u + (addr - 0x800000u);
        return (off < S.rom_size) ? W.rom[off] : 0xFFu;
    }
    if (addr >= 0xFF0000u)
        return S.has_ext_bios ? W.ext_bios[addr & 0xFFFFu] : W.bios[addr & 0xFFFFu];
    return 0x00u;
}

static void flash_bus_write(u32 chip_base, u32 addr, u8 val)
{
    u32 sub = addr & 0x1FFFFFu;
    if (val == 0xF0u) {
        S.flash_step = 0;
        S.flash_cmd = 0;
        return;
    }
    if (S.flash_step == 0 && (sub & 0x7FFFu) == 0x5555u && val == 0xAAu) {
        S.flash_step = 1;
        return;
    }
    if (S.flash_step == 1 && (sub & 0x7FFFu) == 0x2AAAu && val == 0x55u) {
        S.flash_step = 2;
        return;
    }
    if (S.flash_step == 2 && (sub & 0x7FFFu) == 0x5555u) {
        if (val == 0xA0u || val == 0x80u || val == 0x90u) {
            S.flash_cmd = val;
            S.flash_step = (val == 0x80u) ? 3u : 0u;
        } else {
            S.flash_step = 0;
        }
        return;
    }
    if (S.flash_cmd == 0xA0u) {
        u32 off = chip_base + sub;
        if (off < NGP_MAX_ROM) {
            W.rom[off] &= val;
            S.sav_dirty = 1;
        }
        S.flash_cmd = 0;
        S.flash_step = 0;
        return;
    }
    if (S.flash_step == 3 && (sub & 0x7FFFu) == 0x5555u && val == 0xAAu) { S.flash_step = 4; return; }
    if (S.flash_step == 4 && (sub & 0x7FFFu) == 0x2AAAu && val == 0x55u) { S.flash_step = 5; return; }
    if (S.flash_step == 5) {
        if (val == 0x30u) {
            /* Erase 8 KB / 64 KB block */
            u32 blk = (chip_base + sub) & ~0x3FFFu;
            for (u32 i = 0; i < 0x4000u && blk + i < NGP_MAX_ROM; i++)
                W.rom[blk + i] = 0xFFu;
            S.sav_dirty = 1;
        } else if (val == 0x10u && (sub & 0x7FFFu) == 0x5555u) {
            for (u32 i = 0x40u; i < 0x200000u && chip_base + i < NGP_MAX_ROM; i++)
                W.rom[chip_base + i] = 0xFFu;
            S.sav_dirty = 1;
        }
        S.flash_step = 0;
        S.flash_cmd = 0;
    }
}

static void sfr_write8(u8 reg, u8 val)
{
    switch (reg) {
    case 0x20u: /* TRUN */
        for (int i = 0; i < 4; i++)
            if (!(W.sfr[0x20] & (1u << i)) && (val & (1u << i)))
                S.t_cnt[i] = 0;
        W.sfr[0x20] = val;
        return;
    case 0xA0u: t6w_write_side(&S.psg_r, val); W.sfr[reg] = val; return;
    case 0xA1u: t6w_write_side(&S.psg_l, val); W.sfr[reg] = val; return;
    case 0xA2u: S.dac_l = val; W.sfr[reg] = val; return;
    case 0xA3u: S.dac_r = val; W.sfr[reg] = val; return;
    case 0xB9u:
        if (val == 0x55u && !S.z80_active) {
            z80_reset(&S.zcpu);
            S.zcpu.cycles = 0;
            S.z80_active = 1;
        } else if (val == 0xAAu) {
            S.z80_active = 0;
        }
        W.sfr[reg] = val;
        return;
    case 0xBAu:
        if (S.z80_active)
            S.zcpu.nmi = 1;
        W.sfr[reg] = val;
        return;
    default:
        if (reg >= 0x70u && reg <= 0x7Bu) {
            /* Writing 0 to bit 3 or bit 7 clears the interrupt pending latch; writing 1 does NOT set it */
            u8 old_pend = W.sfr[reg] & 0x88u;
            u8 clr_mask = (u8)((val & 0x88u) | ~0x88u);
            W.sfr[reg] = (u8)((val & 0x77u) | (old_pend & clr_mask));
            return;
        }
        W.sfr[reg] = val;
        return;
    }
}

static void mem_write8(u32 addr, u8 val)
{
    addr &= 0xFFFFFFu;
    if (addr >= 0x4000u && addr < 0x7000u) {
        W.wram[addr - 0x4000u] = val;
        return;
    }
    if (addr >= 0x8000u && addr < 0xC000u) {
        if (__builtin_expect(addr == 0x87E2u, 0) && W.vram[0x07F0] != 0xAAu)
            return; /* K2GE mode register write-protected unless $87F0 == $AA */
        W.vram[addr - 0x8000u] = val;
        return;
    }
    if (addr < 0x0100u) {
        sfr_write8((u8)addr, val);
        return;
    }
    if (addr >= 0x7000u && addr < 0x8000u) {
        W.zram[addr - 0x7000u] = val;
        return;
    }
    if (addr >= 0x200000u && addr < 0x400000u) {
        flash_bus_write(0u, addr, val);
        return;
    }
    if (addr >= 0x800000u && addr < 0xA00000u) {
        flash_bus_write(0x200000u, addr, val);
        return;
    }
}

static inline u16 mem_read16(u32 addr)
{
    return (u16)mem_read8(addr) | ((u16)mem_read8(addr + 1u) << 8);
}

static inline u32 mem_read32(u32 addr)
{
    return (u32)mem_read16(addr) | ((u32)mem_read16(addr + 2u) << 16);
}

static inline void mem_write16(u32 addr, u16 v)
{
    mem_write8(addr, (u8)v);
    mem_write8(addr + 1u, (u8)(v >> 8));
}

static inline void mem_write32(u32 addr, u32 v)
{
    mem_write16(addr, (u16)v);
    mem_write16(addr + 2u, (u16)(v >> 16));
}

static u32 mem_read_sz(u32 addr, int sz)
{
    return (sz == 0) ? mem_read8(addr) : (sz == 1) ? mem_read16(addr) : mem_read32(addr);
}

static void mem_write_sz(u32 addr, int sz, u32 val)
{
    if (sz == 0) mem_write8(addr, (u8)val);
    else if (sz == 1) mem_write16(addr, (u16)val);
    else mem_write32(addr, val);
}

/* ---- TLCS-900/H Register Access Helpers ---- */
static inline u32 *ptr_r32_short(u32 idx)
{
    u32 rfp = (S.sr >> 8) & 3u;
    return (idx < 4u) ? &S.bank[rfp][idx] : &S.ix[idx - 4u];
}

static inline u32 *ptr_r32_code(u8 rc)
{
    if (rc < 0x40u)
        return &S.bank[(rc >> 4) & 3u][(rc >> 2) & 3u];
    if (rc >= 0xF0u)
        return &S.ix[(rc >> 2) & 3u];
    return &S.bank[(S.sr >> 8) & 3u][(rc >> 2) & 3u];
}

/* Short 3-bit reg index (0..7):
   - sz==0: 0=W(b1), 1=A(b0), 2=B(b1), 3=C(b0), 4=D(b1), 5=E(b0), 6=H(b1), 7=L(b0)
   - sz==1: 0=WA, 1=BC, 2=DE, 3=HL, 4=IX, 5=IY, 6=IZ, 7=SP (low 16 bits)
   - sz==2: 0=XWA, 1=XBC, 2=XDE, 3=XHL, 4=XIX, 5=XIY, 6=XIZ, 7=XSP */
static u32 reg_short_get(int sz, u32 r)
{
    if (sz == 0) {
        u32 v = S.bank[(S.sr >> 8) & 3u][(r >> 1) & 3u];
        return (r & 1u) ? (v & 0xFFu) : ((v >> 8) & 0xFFu);
    }
    u32 v = *ptr_r32_short(r & 7u);
    return (sz == 1) ? (v & 0xFFFFu) : v;
}

static void reg_short_set(int sz, u32 r, u32 val)
{
    if (sz == 0) {
        u32 *p = &S.bank[(S.sr >> 8) & 3u][(r >> 1) & 3u];
        if (r & 1u) *p = (*p & 0xFFFFFF00u) | (val & 0xFFu);
        else        *p = (*p & 0xFFFF00FFu) | ((val & 0xFFu) << 8);
        return;
    }
    u32 *p = ptr_r32_short(r & 7u);
    if (sz == 1) *p = (*p & 0xFFFF0000u) | (val & 0xFFFFu);
    else         *p = val;
}

/* Full 8-bit register code rc (0x00..0xFF): pure little-endian sub-offset! */
static u32 reg_code_get(int sz, u8 rc)
{
    u32 v = *ptr_r32_code(rc);
    if (sz == 0) return (v >> ((rc & 3u) * 8u)) & 0xFFu;
    if (sz == 1) return (v >> (((rc >> 1) & 1u) * 16u)) & 0xFFFFu;
    return v;
}

static void reg_code_set(int sz, u8 rc, u32 val)
{
    u32 *p = ptr_r32_code(rc);
    if (sz == 0) {
        u32 sh = (rc & 3u) * 8u;
        *p = (*p & ~(0xFFu << sh)) | ((val & 0xFFu) << sh);
    } else if (sz == 1) {
        u32 sh = ((rc >> 1) & 1u) * 16u;
        *p = (*p & ~(0xFFFFu << sh)) | ((val & 0xFFFFu) << sh);
    } else {
        *p = val;
    }
}

/* ---- Flags & ALU ---- */
static const u8 parity_tab[256] = {
    4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4, 0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0,
    0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0, 4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4,
    0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0, 4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4,
    4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4, 0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0,
    0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0, 4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4,
    4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4, 0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0,
    4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4, 0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0,
    0,4,4,0,4,0,0,4,4,0,0,4,0,4,4,0, 4,0,0,4,0,4,4,0,0,4,4,0,4,0,0,4
};

static inline void set_flags(u8 f)
{
    S.sr = (u16)((S.sr & 0xFF00u) | (f & 0xD7u));
}

static inline u8 get_flags(void) { return (u8)(S.sr & 0xFFu); }

static int eval_cc(u32 cc)
{
    u8 f = get_flags();
    int s = (f & FL_S) != 0, z = (f & FL_Z) != 0, v = (f & FL_V) != 0, c = (f & FL_C) != 0;
    int r = 0;
    switch (cc & 7u) {
    case 0u: r = 0; break;
    case 1u: r = (s != v); break;
    case 2u: r = (z || (s != v)); break;
    case 3u: r = (c || z); break;
    case 4u: r = v; break;
    case 5u: r = s; break;
    case 6u: r = z; break;
    case 7u: r = c; break;
    }
    return (cc & 8u) ? !r : r;
}

static u32 sz_mask(int sz) { return (sz == 0) ? 0xFFu : (sz == 1) ? 0xFFFFu : 0xFFFFFFFFu; }
static u32 sz_msb(int sz)  { return (sz == 0) ? 0x80u : (sz == 1) ? 0x8000u : 0x80000000u; }

static u32 alu_op(int kind, int sz, u32 dst, u32 src)
{
    u32 mask = sz_mask(sz), msb = sz_msb(sz);
    dst &= mask;
    src &= mask;
    u8 f = get_flags();
    u32 res = dst;

    switch (kind & 7) {
    case 0: /* ADD */
    case 1: { /* ADC */
        u32 cin = ((kind & 7) == 1 && (f & FL_C)) ? 1u : 0u;
        res = (dst + src + cin) & mask;
        int cout = (sz == 2) ? ((res < dst) || (cin && res == dst)) : ((dst + src + cin) > mask);
        u32 hmask = (sz == 0) ? 0x0Fu : (sz == 1) ? 0x0FFFu : 0x0FFFFFFFu;
        int hout = ((dst & hmask) + (src & hmask) + cin) > hmask;
        int vout = ((~(dst ^ src) & (dst ^ res)) & msb) != 0;
        u8 nf = (u8)((res & msb ? FL_S : 0u) | (res == 0u ? FL_Z : 0u) |
                     (hout ? FL_H : 0u) | (vout ? FL_V : 0u) | (cout ? FL_C : 0u));
        set_flags(nf);
        return res;
    }
    case 2: /* SUB */
    case 3: /* SBC */
    case 7: { /* CP */
        u32 cin = ((kind & 7) == 3 && (f & FL_C)) ? 1u : 0u;
        res = (dst - src - cin) & mask;
        int bout = (dst < src) || (cin && dst == src);
        u32 hmask = (sz == 0) ? 0x0Fu : (sz == 1) ? 0x0FFFu : 0x0FFFFFFFu;
        int hbout = (dst & hmask) < ((src & hmask) + cin);
        int vout = (((dst ^ src) & (dst ^ res)) & msb) != 0;
        u8 nf = (u8)(FL_N | (res & msb ? FL_S : 0u) | (res == 0u ? FL_Z : 0u) |
                     (hbout ? FL_H : 0u) | (vout ? FL_V : 0u) | (bout ? FL_C : 0u));
        set_flags(nf);
        return ((kind & 7) == 7) ? dst : res;
    }
    case 4: /* AND */
        res = dst & src;
        set_flags((u8)(FL_H | (res & msb ? FL_S : 0u) | (res == 0u ? FL_Z : 0u) |
                       (sz == 0 ? parity_tab[res] : (sz == 1 ? (parity_tab[res & 0xFFu] ^ parity_tab[res >> 8] ^ FL_V) : 0u))));
        return res;
    case 5: /* XOR */
        res = dst ^ src;
        set_flags((u8)((res & msb ? FL_S : 0u) | (res == 0u ? FL_Z : 0u) |
                       (sz == 0 ? parity_tab[res] : (sz == 1 ? (parity_tab[res & 0xFFu] ^ parity_tab[res >> 8] ^ FL_V) : 0u))));
        return res;
    default: /* OR */
        res = dst | src;
        set_flags((u8)((res & msb ? FL_S : 0u) | (res == 0u ? FL_Z : 0u) |
                       (sz == 0 ? parity_tab[res] : (sz == 1 ? (parity_tab[res & 0xFFu] ^ parity_tab[res >> 8] ^ FL_V) : 0u))));
        return res;
    }
}

static u32 inc_dec_val(int sz, u32 val, u32 amt, int is_dec)
{
    /* INC/DEC on TLCS-900/H: in 8-bit & 16-bit modes updates S, Z, H, V, N (preserves C!);
       in 32-bit mode (address pointer increment/decrement!) updates NO flags at all! */
    u32 mask = sz_mask(sz);
    u32 res = (is_dec ? (val - amt) : (val + amt)) & mask;
    if (sz < 2) {
        u8 c_keep = get_flags() & FL_C;
        (void)alu_op(is_dec ? 2 : 0, sz, val, amt);
        set_flags((u8)((get_flags() & ~FL_C) | c_keep));
    }
    return res;
}

static u32 shift_op(u32 kind, int sz, u32 val, u32 cnt)
{
    if (cnt == 0u)
        return val & sz_mask(sz);
    u32 mask = sz_mask(sz), msb = sz_msb(sz);
    val &= mask;
    u8 c = (get_flags() & FL_C) ? 1u : 0u;
    for (u32 i = 0; i < cnt; i++) {
        switch (kind & 7u) {
        case 0u: /* RLC */ c = (val & msb) ? 1u : 0u; val = ((val << 1) | c) & mask; break;
        case 1u: /* RRC */ c = (u8)(val & 1u); val = (val >> 1) | (c ? msb : 0u); break;
        case 2u: /* RL  */ { u8 nc = (val & msb) ? 1u : 0u; val = ((val << 1) | c) & mask; c = nc; break; }
        case 3u: /* RR  */ { u8 nc = (u8)(val & 1u); val = (val >> 1) | (c ? msb : 0u); c = nc; break; }
        case 4u: /* SLA */
        case 6u: /* SLL */ c = (val & msb) ? 1u : 0u; val = (val << 1) & mask; break;
        case 5u: /* SRA */ c = (u8)(val & 1u); val = (val >> 1) | (val & msb); break;
        default: /* SRL */ c = (u8)(val & 1u); val >>= 1; break;
        }
    }
    u8 p = (sz == 0) ? parity_tab[val] : (sz == 1 ? (u8)(parity_tab[val & 0xFFu] ^ parity_tab[val >> 8] ^ FL_V) : 0u);
    set_flags((u8)((val & msb ? FL_S : 0u) | (val == 0u ? FL_Z : 0u) | p | (c ? FL_C : 0u)));
    return val;
}

/* ---- Control Registers (LDC: MicroDMA & INTNEST) ---- */
static void cr_write(u8 cr, int sz, u32 val)
{
    (void)sz;
    if (cr < 0x10u && (cr & 3u) == 0u) { S.dmas[cr >> 2] = val & 0xFFFFFFu; return; }
    if (cr >= 0x10u && cr < 0x20u && (cr & 3u) == 0u) { S.dmad[(cr - 0x10u) >> 2] = val & 0xFFFFFFu; return; }
    if (cr >= 0x20u && cr < 0x30u) {
        u32 ch = (cr - 0x20u) >> 2;
        if ((cr & 3u) == 0u) S.dmac[ch] = (u16)val;
        else if ((cr & 3u) == 2u) S.dmam[ch] = (u8)(val & 0x1Fu);
        return;
    }
    if (cr == 0x3Cu) S.intnest = (u16)val;
}

static u32 cr_read(u8 cr, int sz)
{
    (void)sz;
    if (cr < 0x10u && (cr & 3u) == 0u) return S.dmas[cr >> 2];
    if (cr >= 0x10u && cr < 0x20u && (cr & 3u) == 0u) return S.dmad[(cr - 0x10u) >> 2];
    if (cr >= 0x20u && cr < 0x30u) {
        u32 ch = (cr - 0x20u) >> 2;
        if ((cr & 3u) == 0u) return S.dmac[ch];
        if ((cr & 3u) == 2u) return S.dmam[ch];
    }
    if (cr == 0x3Cu) return S.intnest;
    return 0u;
}

/* ---- Interrupts & MicroDMA ---- */
struct irq_src_def {
    u8 sfr;
    u8 hi;
    u8 udma_vec;
    u16 ram_vec;   /* $6FB8..$6FFC */
};

static const struct irq_src_def irq_table[] = {
    {0x70u, 0u, 0x0Au, 0x6FC8u}, /* RTC Alarm */
    {0x71u, 0u, 0x0Bu, 0x6FCCu}, /* INT4: VBlank */
    {0x71u, 1u, 0x0Cu, 0x6FD0u}, /* INT5: Z80 */
    {0x73u, 0u, 0x10u, 0x6FD4u}, /* INTT0: Timer 0 */
    {0x73u, 1u, 0x11u, 0x6FD8u}, /* INTT1: Timer 1 */
    {0x74u, 0u, 0x12u, 0x6FDCu}, /* INTT2: Timer 2 */
    {0x74u, 1u, 0x13u, 0x6FE0u}, /* INTT3: Timer 3 */
    {0x77u, 0u, 0x18u, 0x6FE4u}, /* Serial TX */
    {0x77u, 1u, 0x19u, 0x6FE8u}, /* Serial RX */
    {0x79u, 0u, 0xFFu, 0x6FF0u}, /* INTDMA0 */
    {0x79u, 1u, 0xFFu, 0x6FF4u}, /* INTDMA1 */
    {0x7Au, 0u, 0xFFu, 0x6FF8u}, /* INTDMA2 */
    {0x7Au, 1u, 0xFFu, 0x6FFCu}  /* INTDMA3 */
};

static int run_microdma(int ch)
{
    u8 mode = S.dmam[ch] & 0x1Fu;
    int sz = (int)(mode & 3u);
    if (sz > 2) sz = 0;
    int step = 1 << sz;

    switch (mode >> 2) {
    case 0: /* (DMAD+) <- (DMAS) */
        mem_write_sz(S.dmad[ch], sz, mem_read_sz(S.dmas[ch], sz));
        S.dmad[ch] = (S.dmad[ch] + (u32)step) & 0xFFFFFFu;
        break;
    case 1: /* (DMAD-) <- (DMAS) */
        mem_write_sz(S.dmad[ch], sz, mem_read_sz(S.dmas[ch], sz));
        S.dmad[ch] = (S.dmad[ch] - (u32)step) & 0xFFFFFFu;
        break;
    case 2: /* (DMAD) <- (DMAS+) */
        mem_write_sz(S.dmad[ch], sz, mem_read_sz(S.dmas[ch], sz));
        S.dmas[ch] = (S.dmas[ch] + (u32)step) & 0xFFFFFFu;
        break;
    case 3: /* (DMAD) <- (DMAS-) */
        mem_write_sz(S.dmad[ch], sz, mem_read_sz(S.dmas[ch], sz));
        S.dmas[ch] = (S.dmas[ch] - (u32)step) & 0xFFFFFFu;
        break;
    case 4: /* (DMAD) <- (DMAS), fixed */
        mem_write_sz(S.dmad[ch], sz, mem_read_sz(S.dmas[ch], sz));
        break;
    case 5: /* Counter mode: DMAS++ */
        S.dmas[ch] = (S.dmas[ch] + 1u) & 0xFFFFFFu;
        break;
    default:
        break;
    }

    S.dmac[ch]--;
    if (S.dmac[ch] == 0u) {
        W.sfr[0x7Cu + ch] = 0u; /* disable DMA start vector */
        irq_set_pending((ch < 2) ? 0x79u : 0x7Au, ch & 1);
    }
    return 8;
}

static void irq_set_pending(u8 sfr_addr, int hi_nibble)
{
    /* First check if a MicroDMA channel is armed for this vector! */
    u8 vec = 0xFFu;
    for (unsigned i = 0; i < sizeof(irq_table) / sizeof(irq_table[0]); i++) {
        if (irq_table[i].sfr == sfr_addr && irq_table[i].hi == (u8)hi_nibble) {
            vec = irq_table[i].udma_vec;
            break;
        }
    }
    if (vec != 0xFFu) {
        for (int ch = 0; ch < 4; ch++) {
            if (W.sfr[0x7Cu + ch] == vec) {
                (void)run_microdma(ch);
                return; /* MicroDMA consumes the trigger without latching CPU IRQ! */
            }
        }
    }
    W.sfr[sfr_addr] |= hi_nibble ? 0x80u : 0x08u;
}

static void push16(u16 v) { S.ix[3] = (S.ix[3] - 2u) & 0xFFFFFFu; mem_write16(S.ix[3], v); }
static void push32(u32 v) { S.ix[3] = (S.ix[3] - 4u) & 0xFFFFFFu; mem_write32(S.ix[3], v); }
static u16 pop16(void)    { u16 v = mem_read16(S.ix[3]); S.ix[3] = (S.ix[3] + 2u) & 0xFFFFFFu; return v; }
static u32 pop32(void)    { u32 v = mem_read32(S.ix[3]); S.ix[3] = (S.ix[3] + 4u) & 0xFFFFFFu; return v; }

static inline int any_irq_latched(void)
{
    const u32 *p70 = (const u32 *)(W.sfr + 0x70);
    return ((p70[0] | p70[1] | p70[2]) & 0x88888888u) != 0u;
}

static int check_interrupts(void)
{
    u32 iff = (S.sr >> 12) & 7u;
    if (iff == 7u || !any_irq_latched())
        return 0;

    int best_idx = -1;
    u32 best_lvl = 0;
    for (unsigned i = 0; i < sizeof(irq_table) / sizeof(irq_table[0]); i++) {
        u8 reg = W.sfr[irq_table[i].sfr];
        u8 nib = irq_table[i].hi ? (reg >> 4) : (reg & 0x0Fu);
        if (!(nib & 0x08u))
            continue;
        u32 lvl = nib & 0x07u;
        if (lvl == 0u || lvl == 7u || lvl < iff)
            continue;
        if (lvl > best_lvl) {
            best_lvl = lvl;
            best_idx = (int)i;
        }
    }
    if (best_idx < 0)
        return 0;

    /* Acknowledge pending latch */
    const struct irq_src_def *src = &irq_table[best_idx];
    W.sfr[src->sfr] &= src->hi ? (u8)~0x80u : (u8)~0x08u;

    /* On VBlank (INT4), real NGPC BIOS updates $6F82 joypad mirror before jumping to ($6FCC)! */
    if (src->ram_vec == 0x6FCCu && !S.has_ext_bios)
        W.wram[0x6F82u - 0x4000u] = current_joypad();

    u32 target = S.has_ext_bios
        ? mem_read32(0xFFFF00u + (u32)src->udma_vec * 4u)
        : mem_read32(src->ram_vec);

    S.halted = 0;
    push32(S.pc);
    push16(S.sr);
    u32 next_iff = (best_lvl < 7u) ? (best_lvl + 1u) : 7u;
    S.sr = (u16)(0x8000u | (next_iff << 12) | (S.sr & 0x0FFFu));
    S.intnest++;
    S.pc = target & 0xFFFFFFu;
    return 18;
}

/* ---- Clean-room Built-in BIOS ($FF0000..$FFFFFF) ---- */
static void build_clean_bios(void)
{
    for (u32 i = 0; i < 0x10000u; i++)
        W.bios[i] = 0x0Eu; /* RET fallback */

    /* $FF0100: SWI 1 dispatcher -> HLE hooked, ends with RETI (0x07) */
    W.bios[0x0100] = 0x07u;
    /* $FF0200: Default dummy ISR -> RETI (0x07) */
    W.bios[0x0200] = 0x07u;

    /* $FF1000 + i*16 (i = 0..31): Direct-call BIOS vectors pointed to by $FFFE00 + i*4 -> end with RET (0x0E) */
    for (u32 i = 0; i < 32u; i++) {
        u32 fn_addr = 0x00FF1000u + i * 16u;
        W.bios[0x1000u + i * 16u] = 0x0Eu;
        u32 tab = 0xFE00u + i * 4u;
        W.bios[tab + 0] = (u8)(fn_addr);
        W.bios[tab + 1] = (u8)(fn_addr >> 8);
        W.bios[tab + 2] = (u8)(fn_addr >> 16);
        W.bios[tab + 3] = 0u;
    }

    /* Hardware exception vectors $FFFF00..$FFFF7F */
    for (u32 i = 0; i < 32u; i++) {
        u32 v = (i == 1u) ? 0x00FF0100u : 0x00FF0200u;
        u32 tab = 0xFF00u + i * 4u;
        W.bios[tab + 0] = (u8)(v);
        W.bios[tab + 1] = (u8)(v >> 8);
        W.bios[tab + 2] = (u8)(v >> 16);
        W.bios[tab + 3] = 0u;
    }
}

static void hle_bios_vector(u32 vec)
{
    u8 ra3 = (u8)(S.bank[3][0] & 0xFFu);
    u8 rc3 = (u8)(S.bank[3][1] & 0xFFu);
    u8 rb3 = (u8)((S.bank[3][1] >> 8) & 0xFFu);
    u16 bc3 = (u16)(S.bank[3][1] & 0xFFFFu);
    u32 xde3 = S.bank[3][2] & 0xFFFFFFu;
    u32 xhl3 = S.bank[3][3] & 0xFFFFFFu;

    switch (vec) {
    case 0u: /* VECT_SHUTDOWN */
        break;
    case 1u: /* VECT_CLOCKGEARSET */
        S.clk_gear = (rb3 <= 4u) ? rb3 : 0u;
        break;
    case 2u: /* VECT_RTCGET: write 7-byte BCD date/time to (XHL3) */
        mem_write8(xhl3 + 0u, 0x26u); /* 2026 */
        mem_write8(xhl3 + 1u, 0x11u); /* Nov */
        mem_write8(xhl3 + 2u, 0x19u); /* 19 */
        mem_write8(xhl3 + 3u, 0x12u); /* 12:00:00 */
        mem_write8(xhl3 + 4u, 0x00u);
        mem_write8(xhl3 + 5u, 0x00u);
        mem_write8(xhl3 + 6u, 0x04u);
        break;
    case 4u: { /* VECT_INTLVSET: RB3 = level (bits 2..0), RC3 = interrupt source */
        u8 lvl = rb3 & 0x07u;
        static const struct { u8 sfr; u8 hi; } lv_map[11] = {
            {0x70u, 0u}, /* 0: RTC / INT0 */
            {0x71u, 0u}, /* 1: VBlank (INT4) */
            {0x71u, 1u}, /* 2: Z80 (INT5) */
            {0x73u, 0u}, /* 3: Timer 0 */
            {0x73u, 1u}, /* 4: Timer 1 */
            {0x74u, 0u}, /* 5: Timer 2 */
            {0x74u, 1u}, /* 6: Timer 3 */
            {0x77u, 0u}, /* 7: Serial TX */
            {0x77u, 1u}, /* 8: Serial RX */
            {0x79u, 0u}, /* 9: MicroDMA 0 */
            {0x79u, 1u}  /* 10: MicroDMA 1 */
        };
        if (rc3 < 11u) {
            u8 s = lv_map[rc3].sfr;
            if (lv_map[rc3].hi)
                W.sfr[s] = (u8)((W.sfr[s] & 0x8Fu) | (lvl << 4));
            else
                W.sfr[s] = (u8)((W.sfr[s] & 0xF8u) | lvl);
        }
        break;
    }
    case 5u: { /* VECT_SYSFONTSET: unpack 256 8x8 glyphs into 2bpp VRAM $A000..$AFFF */
        u32 fg = ra3 & 3u;
        u32 bg = (ra3 >> 4) & 3u;
        for (u32 c = 0; c < 256u; c++) {
            const u8 *g = (c >= 0x20u && c < 0x80u) ? sys_font96[c - 0x20u] : sys_font96[0];
            for (u32 r = 0; r < 8u; r++) {
                u8 bits = (c < 0x20u) ? 0u : (c >= 0x80u ? (u8)((c * 17u + r * 31u) & 0x7Eu) : g[r]);
                u16 row16 = 0;
                for (u32 x = 0; x < 8u; x++) {
                    u32 px = ((bits >> (7u - x)) & 1u) ? fg : bg;
                    row16 |= (u16)(px << ((7u - x) * 2u));
                }
                u32 dst = 0x2000u + c * 16u + r * 2u; /* $A000 - $8000 = 0x2000 */
                W.vram[dst] = (u8)row16;
                W.vram[dst + 1u] = (u8)(row16 >> 8);
            }
        }
        break;
    }
    case 6u: { /* VECT_FLASHWRITE: RA3=chip, BC3=blocks of 256B, XHL3=src RAM, XDE3=flash offset */
        u32 base = (ra3 == 1u) ? 0x200000u : 0u;
        u32 dst = base + (xde3 & 0x1FFFFFu);
        u32 n_bytes = (u32)(bc3 ? bc3 : 1u) * 256u;
        for (u32 i = 0; i < n_bytes && dst + i < NGP_MAX_ROM; i++)
            W.rom[dst + i] = mem_read8(xhl3 + i);
        S.sav_dirty = 1;
        S.bank[3][0] = (S.bank[3][0] & 0xFFFFFF00u); /* RA3 = 0 (OK) */
        break;
    }
    case 7u:   /* VECT_FLASHALLERS */
    case 8u: { /* VECT_FLASHERS: RA3=chip, RB3=block */
        u32 base = (ra3 == 1u) ? 0x200000u : 0u;
        u32 off = base + (u32)rb3 * 0x10000u;
        if (rb3 >= 31u && S.rom_size <= 0x200000u)
            off = (S.rom_size >= 0x10000u) ? (S.rom_size - 0x10000u) : 0u;
        for (u32 i = 0; i < 0x10000u && off + i < NGP_MAX_ROM; i++)
            W.rom[off + i] = 0xFFu;
        S.sav_dirty = 1;
        S.bank[3][0] = (S.bank[3][0] & 0xFFFFFF00u); /* RA3 = 0 (OK) */
        break;
    }
    case 13u: { /* VECT_GEMODESET: initialize K1GE compatibility palettes on K2GE */
        static const u16 mono_shades[8] = {
            0x0FFFu, 0x0DDDu, 0x0BBBu, 0x0999u, 0x0777u, 0x0555u, 0x0333u, 0x0000u
        };
        for (int s = 0; s < 8; s++) {
            u16 c = mono_shades[s];
            for (int p = 0; p < 0x180; p += 2) {
                W.vram[0x0200 + p] = (u8)c;
                W.vram[0x0200 + p + 1] = (u8)(c >> 8);
            }
        }
        break;
    }
    default:
        /* Link-cable / alarm stubs: return RA3 = 0 (no error / idle) */
        S.bank[3][0] = (S.bank[3][0] & 0xFFFFFF00u);
        break;
    }
}

/* ---- TLCS-900/H Instruction Decoder ---- */
static inline u8 fetch8(void)
{
    u32 pc = S.pc;
    S.pc = (pc + 1u) & 0xFFFFFFu;
    u32 roff = pc - 0x200000u;
    if (__builtin_expect(roff < S.rom_size && !S.flash_cmd, 1))
        return W.rom[roff];
    return mem_read8(pc);
}

static inline u16 fetch16(void)
{
    u16 lo = fetch8();
    return lo | ((u16)fetch8() << 8);
}

static inline u32 fetch24(void)
{
    u32 b0 = fetch8(), b1 = fetch8(), b2 = fetch8();
    return b0 | (b1 << 8) | (b2 << 16);
}

static inline u32 fetch32(void)
{
    u32 lo = fetch16();
    return lo | ((u32)fetch16() << 16);
}

static u32 fetch_imm_sz(int sz)
{
    return (sz == 0) ? fetch8() : (sz == 1) ? fetch16() : fetch32();
}

static u32 decode_ea_ext(u32 kind)
{
    /* kind: 0=(abs8), 1=(abs16), 2=(abs24), 3=indexed, 4=(-r32), 5=(r32+) */
    switch (kind) {
    case 0u: return fetch8();
    case 1u: return fetch16();
    case 2u: return fetch24();
    case 3u: {
        u8 m = fetch8();
        if (m == 0x03u) {
            u8 rb = fetch8(), ri = fetch8();
            return (reg_code_get(2, rb) + (u32)(int)(signed char)reg_code_get(0, ri)) & 0xFFFFFFu;
        }
        if (m == 0x07u) {
            u8 rb = fetch8(), ri = fetch8();
            return (reg_code_get(2, rb) + (u32)(int)(s16)reg_code_get(1, ri)) & 0xFFFFFFu;
        }
        if ((m & 3u) == 1u) {
            s16 d16 = (s16)fetch16();
            return (reg_code_get(2, (u8)(m & 0xFCu)) + (u32)(int)d16) & 0xFFFFFFu;
        }
        return reg_code_get(2, (u8)(m & 0xFCu)) & 0xFFFFFFu;
    }
    case 4u: { /* (-r32) */
        u8 arg = fetch8();
        u32 step = 1u << (arg & 3u);
        u32 *p = ptr_r32_code((u8)(arg & 0xFCu));
        *p = (*p - step) & 0xFFFFFFu;
        return *p;
    }
    default: { /* (r32+) */
        u8 arg = fetch8();
        u32 step = 1u << (arg & 3u);
        u32 *p = ptr_r32_code((u8)(arg & 0xFCu));
        u32 ea = *p & 0xFFFFFFu;
        *p = (*p + step) & 0xFFFFFFu;
        return ea;
    }
    }
}

/* Execute 2nd byte of REG prefix (PREG: is_short ? reg_short(sz, r_idx) : reg_code(sz, rc)) */
static int exec_reg_prefix(int sz, int is_short, u32 r_id)
{
    u8 op = fetch8();
    u32 pv = is_short ? reg_short_get(sz, r_id) : reg_code_get(sz, (u8)r_id);
    #define SET_PREG(val) do { if (is_short) reg_short_set(sz, r_id, (val)); else reg_code_set(sz, (u8)r_id, (val)); } while (0)

    if (op >= 0x80u && op < 0xF8u && (op & 8u) == 0u) {
        u32 r = op & 7u;
        u32 res = alu_op((op >> 4) & 7u, sz, reg_short_get(sz, r), pv);
        if (((op >> 4) & 7u) != 7u)
            reg_short_set(sz, r, res);
        return 4;
    }
    if ((op & 0xF8u) == 0x88u) { reg_short_set(sz, op & 7u, pv); return 4; }
    if ((op & 0xF8u) == 0x98u) { SET_PREG(reg_short_get(sz, op & 7u)); return 4; }
    if ((op & 0xF8u) == 0xA8u) { SET_PREG(op & 7u); return 4; }
    if ((op & 0xF8u) == 0xB8u) {
        u32 r = op & 7u, other = reg_short_get(sz, r);
        reg_short_set(sz, r, pv);
        SET_PREG(other);
        return 6;
    }
    if ((op & 0xF8u) == 0xC8u) {
        u32 imm = fetch_imm_sz(sz);
        u32 res = alu_op(op & 7u, sz, pv, imm);
        if ((op & 7u) != 7u) SET_PREG(res);
        return 6;
    }
    if ((op & 0xF8u) == 0xD8u) {
        (void)alu_op(7, sz, pv, op & 7u);
        return 4;
    }
    if ((op & 0xF8u) == 0xE8u) {
        u32 cnt = fetch8() & 0x0Fu;
        if (cnt == 0u) cnt = 16u;
        SET_PREG(shift_op(op & 7u, sz, pv, cnt));
        return 6 + (int)cnt * 2;
    }
    if (op >= 0xF8u) {
        u32 cnt = reg_short_get(0, 1u) & 0x0Fu; /* A & 15 */
        if (cnt) SET_PREG(shift_op(op & 7u, sz, pv, cnt));
        return 6 + (int)cnt * 2;
    }
    if ((op & 0xF0u) == 0x70u) { /* SCC cc, r */
        SET_PREG(eval_cc(op & 15u) ? 1u : 0u);
        return 6;
    }
    if ((op & 0xF0u) == 0x60u) { /* INC / DEC #3, r */
        u32 amt = op & 7u;
        if (amt == 0u) amt = 8u;
        SET_PREG(inc_dec_val(sz, pv, amt, (op & 8u) != 0u));
        return 4;
    }
    if ((op & 0xF0u) == 0x40u) { /* MUL / MULS RR[r], PREG */
        u32 r = op & 7u;
        int dsz = (sz == 0) ? 1 : 2;
        u32 a = reg_short_get(sz, (sz == 0) ? (r * 2u + 1u) : r);
        u32 prod = (op & 8u)
            ? (u32)((sz == 0) ? ((int)(signed char)a * (int)(signed char)pv) : ((int)(s16)a * (int)(s16)pv))
            : (a * pv);
        reg_short_set(dsz, r, prod);
        return 18;
    }
    if ((op & 0xF0u) == 0x50u) { /* DIV / DIVS RR[r], PREG */
        u32 r = op & 7u;
        int dsz = (sz == 0) ? 1 : 2;
        u32 num = reg_short_get(dsz, r);
        u8 f = (u8)(get_flags() & ~FL_V);
        if (pv == 0u) {
            set_flags((u8)(f | FL_V));
            return 22;
        }
        if (op & 8u) {
            if (sz == 0) {
                int q = (int)(s16)num / (int)(signed char)pv;
                int rem = (int)(s16)num % (int)(signed char)pv;
                if (q < -128 || q > 127) set_flags((u8)(f | FL_V));
                else { set_flags(f); reg_short_set(1, r, ((u32)(rem & 0xFF) << 8) | (u32)(q & 0xFF)); }
            } else {
                s32 snum = (s32)num, sden = (s32)(s16)pv;
                if (snum == (s32)0x80000000u && sden == -1) {
                    set_flags((u8)(f | FL_V));
                } else {
                    s32 q = snum / sden, rem = snum % sden;
                    if (q < -32768 || q > 32767) set_flags((u8)(f | FL_V));
                    else { set_flags(f); reg_short_set(2, r, ((u32)(u16)rem << 16) | (u16)q); }
                }
            }
        } else {
            u32 q = num / pv, rem = num % pv;
            u32 maxq = (sz == 0) ? 0xFFu : 0xFFFFu;
            if (q > maxq) set_flags((u8)(f | FL_V));
            else { set_flags(f); reg_short_set(dsz, r, (rem << (sz == 0 ? 8 : 16)) | q); }
        }
        return 22;
    }

    switch (op) {
    case 0x03u: SET_PREG(fetch_imm_sz(sz)); return 4;
    case 0x04u: if (sz == 0) push16((u16)pv); else if (sz == 1) push16((u16)pv); else push32(pv); return 6;
    case 0x05u: SET_PREG((sz == 2) ? pop32() : pop16()); return 6;
    case 0x06u: { u32 r = (~pv) & sz_mask(sz); SET_PREG(r); set_flags((u8)(get_flags() | FL_H | FL_N)); return 4; }
    case 0x07u: SET_PREG(alu_op(2, sz, 0u, pv)); return 4;
    case 0x08u: case 0x09u: { /* MUL / MULS PREG, #imm */
        u32 imm = fetch_imm_sz(sz);
        int dsz = (sz == 0) ? 1 : 2;
        u32 prod = (op == 0x09u)
            ? (u32)((sz == 0) ? ((int)(signed char)pv * (int)(signed char)imm) : ((int)(s16)pv * (int)(s16)imm))
            : (pv * imm);
        if (is_short) reg_short_set(dsz, (sz == 0) ? (r_id >> 1) : r_id, prod);
        else          reg_code_set(dsz, (u8)(r_id & (sz == 0 ? 0xFEu : 0xFCu)), prod);
        return 18;
    }
    case 0x0Au: case 0x0Bu: { /* DIV / DIVS PREG, #imm */
        u32 imm = fetch_imm_sz(sz);
        int dsz = (sz == 0) ? 1 : 2;
        u32 num = is_short ? reg_short_get(dsz, (sz == 0) ? (r_id >> 1) : r_id)
                           : reg_code_get(dsz, (u8)(r_id & (sz == 0 ? 0xFEu : 0xFCu)));
        u8 f = (u8)(get_flags() & ~FL_V);
        if (imm == 0u) { set_flags((u8)(f | FL_V)); return 22; }
        u32 packed = num;
        if (op == 0x0Bu) {
            s32 snum = (sz == 0) ? (s32)(s16)num : (s32)num;
            s32 sden = (sz == 0) ? (s32)(signed char)imm : (s32)(s16)imm;
            s32 q = snum / sden, rem = snum % sden;
            s32 lim = (sz == 0) ? 127 : 32767;
            if (q < -lim - 1 || q > lim) { set_flags((u8)(f | FL_V)); return 22; }
            packed = (sz == 0) ? (((u32)(rem & 0xFF) << 8) | (u32)(q & 0xFF)) : (((u32)(u16)rem << 16) | (u16)q);
        } else {
            u32 q = num / imm, rem = num % imm;
            if (q > (sz == 0 ? 0xFFu : 0xFFFFu)) { set_flags((u8)(f | FL_V)); return 22; }
            packed = (rem << (sz == 0 ? 8 : 16)) | q;
        }
        set_flags(f);
        if (is_short) reg_short_set(dsz, (sz == 0) ? (r_id >> 1) : r_id, packed);
        else          reg_code_set(dsz, (u8)(r_id & (sz == 0 ? 0xFEu : 0xFCu)), packed);
        return 22;
    }
    case 0x0Cu: { /* LINK r32, d16 */
        s16 d16 = (s16)fetch16();
        push32(pv);
        SET_PREG(S.ix[3]);
        S.ix[3] = (S.ix[3] + (u32)(int)d16) & 0xFFFFFFu;
        return 10;
    }
    case 0x0Du: /* UNLK r32 */
        S.ix[3] = pv & 0xFFFFFFu;
        SET_PREG(pop32());
        return 8;
    case 0x0Eu: /* BS1F A, r16 */
    case 0x0Fu: { /* BS1B A, r16 */
        u16 w = (u16)pv;
        if (!w) {
            set_flags((u8)((get_flags() & ~FL_V) | FL_V));
        } else {
            int pos = 0;
            if (op == 0x0Eu) { while (!(w & (1u << pos))) pos++; }
            else             { pos = 15; while (!(w & (1u << pos))) pos--; }
            reg_short_set(0, 1u, (u32)pos);
            set_flags((u8)(get_flags() & ~FL_V));
        }
        return 8;
    }
    case 0x10u: { /* DAA r8 */
        u8 f = get_flags();
        int a = (int)(pv & 0xFFu), cy = (f & FL_C) != 0;
        if (f & FL_N) {
            if ((f & FL_H) || (a & 0x0F) > 9) a -= 6;
            if (cy || (pv & 0xFFu) > 0x99u) { a -= 0x60; cy = 1; }
        } else {
            if ((f & FL_H) || (a & 0x0F) > 9) a += 6;
            if (cy || a > 0x9F) { a += 0x60; cy = 1; }
        }
        u8 res = (u8)a;
        SET_PREG(res);
        set_flags((u8)((f & FL_N) | (res & 0x80u ? FL_S : 0u) | (res == 0u ? FL_Z : 0u) | parity_tab[res] | (cy ? FL_C : 0u)));
        return 6;
    }
    case 0x12u: /* EXTZ */
        SET_PREG((sz == 1) ? (pv & 0xFFu) : (pv & 0xFFFFu));
        return 4;
    case 0x13u: /* EXTS */
        SET_PREG((sz == 1) ? (u16)(s16)(signed char)pv : (u32)(s32)(s16)pv);
        return 4;
    case 0x14u: /* PAA */
        if (pv & 1u) SET_PREG((pv + 1u) & sz_mask(sz));
        return 4;
    case 0x16u: { /* MIRR r16 */
        u16 v = (u16)pv, out = 0;
        for (int i = 0; i < 16; i++)
            if (v & (1u << i)) out |= (u16)(0x8000u >> i);
        SET_PREG(out);
        return 6;
    }
    case 0x1Cu: { /* DJNZ r, d8 */
        s16 d8 = (signed char)fetch8();
        u32 nv = (pv - 1u) & sz_mask(sz);
        SET_PREG(nv);
        if (nv != 0u)
            S.pc = (S.pc + (u32)(int)d8) & 0xFFFFFFu;
        return 8;
    }
    case 0x20u: case 0x21u: case 0x22u: case 0x23u: case 0x24u: { /* ANDCF/ORCF/XORCF/LDCF/STCF #b, r */
        u32 b = fetch8() & (sz == 0 ? 7u : 15u);
        u32 bit = (pv >> b) & 1u;
        u8 f = get_flags(), c = f & 1u;
        if (op == 0x20u) c &= (u8)bit;
        else if (op == 0x21u) c |= (u8)bit;
        else if (op == 0x22u) c ^= (u8)bit;
        else if (op == 0x23u) c = (u8)bit;
        else { SET_PREG((pv & ~(1u << b)) | ((u32)c << b)); return 4; }
        set_flags((u8)((f & ~FL_C) | c));
        return 4;
    }
    case 0x28u: case 0x29u: case 0x2Au: case 0x2Bu: case 0x2Cu: { /* ANDCF..STCF A, r */
        u32 b = reg_short_get(0, 1u) & (sz == 0 ? 7u : 15u);
        u32 bit = (pv >> b) & 1u;
        u8 f = get_flags(), c = f & 1u;
        if (op == 0x28u) c &= (u8)bit;
        else if (op == 0x29u) c |= (u8)bit;
        else if (op == 0x2Au) c ^= (u8)bit;
        else if (op == 0x2Bu) c = (u8)bit;
        else { SET_PREG((pv & ~(1u << b)) | ((u32)c << b)); return 4; }
        set_flags((u8)((f & ~FL_C) | c));
        return 4;
    }
    case 0x2Eu: cr_write(fetch8(), sz, pv); return 6;
    case 0x2Fu: SET_PREG(cr_read(fetch8(), sz)); return 6;
    case 0x30u: case 0x31u: case 0x32u: case 0x33u: case 0x34u: { /* RES/SET/CHG/BIT/TSET #b, r */
        u32 b = fetch8() & (sz == 0 ? 7u : 15u);
        u32 m = 1u << b;
        if (op == 0x30u) SET_PREG(pv & ~m);
        else if (op == 0x31u) SET_PREG(pv | m);
        else if (op == 0x32u) SET_PREG(pv ^ m);
        else {
            u8 f = (u8)((get_flags() & FL_C) | FL_H | ((pv & m) ? 0u : FL_Z));
            set_flags(f);
            if (op == 0x34u) SET_PREG(pv | m);
        }
        return 4;
    }
    case 0x38u: case 0x39u: case 0x3Au: { /* MINC1/2/4 */
        u16 m = fetch16();
        u32 step = 1u << (op - 0x38u);
        SET_PREG(((pv & ~m) | ((pv + step) & m)) & 0xFFFFu);
        return 8;
    }
    case 0x3Cu: case 0x3Du: case 0x3Eu: { /* MDEC1/2/4 */
        u16 m = fetch16();
        u32 step = 1u << (op - 0x3Cu);
        SET_PREG(((pv & ~m) | ((pv - step) & m)) & 0xFFFFu);
        return 8;
    }
    default:
        return 4;
    }
    #undef SET_PREG
}

/* Execute 2nd byte of SRC MEM prefix (size sz = 0/1/2, effective address ea) */
static int exec_src_mem(int sz, u32 ea, u32 ptr_reg_idx)
{
    u8 op = fetch8();
    if (op >= 0x80u) {
        u32 r = op & 7u;
        u32 mv = mem_read_sz(ea, sz);
        u32 rv = reg_short_get(sz, r);
        if ((op & 8u) == 0u) {
            u32 res = alu_op((op >> 4) & 7u, sz, rv, mv);
            if (((op >> 4) & 7u) != 7u) reg_short_set(sz, r, res);
        } else {
            u32 res = alu_op((op >> 4) & 7u, sz, mv, rv);
            if (((op >> 4) & 7u) != 7u) mem_write_sz(ea, sz, res);
        }
        return 8;
    }
    if ((op & 0xF8u) == 0x20u) { reg_short_set(sz, op & 7u, mem_read_sz(ea, sz)); return 6; }
    if ((op & 0xF8u) == 0x30u) {
        u32 mv = mem_read_sz(ea, sz), rv = reg_short_get(sz, op & 7u);
        mem_write_sz(ea, sz, rv);
        reg_short_set(sz, op & 7u, mv);
        return 8;
    }
    if ((op & 0xF8u) == 0x38u) {
        u32 mv = mem_read_sz(ea, sz), imm = fetch_imm_sz(sz);
        u32 res = alu_op(op & 7u, sz, mv, imm);
        if ((op & 7u) != 7u) mem_write_sz(ea, sz, res);
        return 8;
    }
    if ((op & 0xF0u) == 0x40u) { /* MUL / MULS RR[r], (mem) */
        u32 r = op & 7u, mv = mem_read_sz(ea, sz);
        int dsz = (sz == 0) ? 1 : 2;
        u32 a = reg_short_get(sz, (sz == 0) ? (r * 2u + 1u) : r);
        u32 prod = (op & 8u)
            ? (u32)((sz == 0) ? ((int)(signed char)a * (int)(signed char)mv) : ((int)(s16)a * (int)(s16)mv))
            : (a * mv);
        reg_short_set(dsz, r, prod);
        return 20;
    }
    if ((op & 0xF0u) == 0x50u) { /* DIV / DIVS RR[r], (mem) */
        u32 r = op & 7u, mv = mem_read_sz(ea, sz);
        int dsz = (sz == 0) ? 1 : 2;
        u32 num = reg_short_get(dsz, r);
        u8 f = (u8)(get_flags() & ~FL_V);
        if (mv == 0u) { set_flags((u8)(f | FL_V)); return 24; }
        if (op & 8u) {
            s32 snum = (sz == 0) ? (s32)(s16)num : (s32)num;
            s32 sden = (sz == 0) ? (s32)(signed char)mv : (s32)(s16)mv;
            s32 q = snum / sden, rem = snum % sden;
            s32 lim = (sz == 0) ? 127 : 32767;
            if (q < -lim - 1 || q > lim) set_flags((u8)(f | FL_V));
            else { set_flags(f); reg_short_set(dsz, r, (sz == 0) ? (((u32)(rem & 0xFF) << 8) | (u32)(q & 0xFF)) : (((u32)(u16)rem << 16) | (u16)q)); }
        } else {
            u32 q = num / mv, rem = num % mv;
            if (q > (sz == 0 ? 0xFFu : 0xFFFFu)) set_flags((u8)(f | FL_V));
            else { set_flags(f); reg_short_set(dsz, r, (rem << (sz == 0 ? 8 : 16)) | q); }
        }
        return 24;
    }
    if ((op & 0xF0u) == 0x60u) { /* INC / DEC #3, (mem) */
        u32 amt = op & 7u;
        if (amt == 0u) amt = 8u;
        mem_write_sz(ea, sz, inc_dec_val(sz, mem_read_sz(ea, sz), amt, (op & 8u) != 0u));
        return 8;
    }
    if ((op & 0xF8u) == 0x78u) {
        mem_write_sz(ea, sz, shift_op(op & 7u, sz, mem_read_sz(ea, sz), 1u));
        return 8;
    }

    switch (op) {
    case 0x00u: mem_write_sz(ea, sz, fetch_imm_sz(sz)); return 8;
    case 0x04u: { u32 v = mem_read_sz(ea, sz); if (sz == 2) push32(v); else push16((u16)v); return 8; }
    case 0x06u: { /* RLD A, (mem) */
        u8 a = (u8)reg_short_get(0, 1u), m = mem_read8(ea);
        mem_write8(ea, (u8)((m << 4) | (a & 0x0Fu)));
        a = (u8)((a & 0xF0u) | (m >> 4));
        reg_short_set(0, 1u, a);
        set_flags((u8)((get_flags() & FL_C) | (a & 0x80u ? FL_S : 0u) | (a == 0u ? FL_Z : 0u) | parity_tab[a]));
        return 12;
    }
    case 0x07u: { /* RRD A, (mem) */
        u8 a = (u8)reg_short_get(0, 1u), m = mem_read8(ea);
        mem_write8(ea, (u8)((m >> 4) | ((a & 0x0Fu) << 4)));
        a = (u8)((a & 0xF0u) | (m & 0x0Fu));
        reg_short_set(0, 1u, a);
        set_flags((u8)((get_flags() & FL_C) | (a & 0x80u ? FL_S : 0u) | (a == 0u ? FL_Z : 0u) | parity_tab[a]));
        return 12;
    }
    case 0x10u: case 0x11u: case 0x12u: case 0x13u: { /* LDI / LDIR / LDD / LDDR */
        int step = ((op & 2u) ? -1 : 1) * (1 << sz);
        u32 *src_p = (ptr_reg_idx == 5u) ? &S.ix[0] : &S.bank[(S.sr >> 8) & 3u][3]; /* XIX or XHL */
        u32 *dst_p = (ptr_reg_idx == 5u) ? &S.ix[1] : &S.bank[(S.sr >> 8) & 3u][2]; /* XIY or XDE */
        u32 *bc_p  = &S.bank[(S.sr >> 8) & 3u][1];
        mem_write_sz(*dst_p, sz, mem_read_sz(*src_p, sz));
        *src_p = (u32)((int)*src_p + step) & 0xFFFFFFu;
        *dst_p = (u32)((int)*dst_p + step) & 0xFFFFFFu;
        u16 bc = (u16)((*bc_p & 0xFFFFu) - 1u);
        *bc_p = (*bc_p & 0xFFFF0000u) | bc;
        set_flags((u8)((get_flags() & (FL_S | FL_Z | FL_C)) | (bc ? FL_V : 0u)));
        if ((op & 1u) && bc != 0u)
            S.pc = (S.pc - 2u) & 0xFFFFFFu;
        return 10;
    }
    case 0x14u: case 0x15u: case 0x16u: case 0x17u: { /* CPI / CPIR / CPD / CPDR */
        int step = ((op & 2u) ? -1 : 1) * (1 << sz);
        u32 *ptr = ptr_r32_short(ptr_reg_idx & 7u);
        u32 *bc_p = &S.bank[(S.sr >> 8) & 3u][1];
        u32 av = (sz == 0) ? reg_short_get(0, 1u) : reg_short_get(1, 0u);
        u32 mv = mem_read_sz(*ptr, sz);
        u8 c_keep = get_flags() & FL_C;
        (void)alu_op(7, sz, av, mv);
        *ptr = (u32)((int)*ptr + step) & 0xFFFFFFu;
        u16 bc = (u16)((*bc_p & 0xFFFFu) - 1u);
        *bc_p = (*bc_p & 0xFFFF0000u) | bc;
        u8 nf = (u8)((get_flags() & ~(FL_V | FL_C)) | (bc ? FL_V : 0u) | c_keep);
        set_flags(nf);
        if ((op & 1u) && bc != 0u && !(nf & FL_Z))
            S.pc = (S.pc - 2u) & 0xFFFFFFu;
        return 10;
    }
    case 0x19u: { /* LD (abs16), (mem) */
        u16 dst = fetch16();
        mem_write_sz(dst, sz, mem_read_sz(ea, sz));
        return 8;
    }
    default:
        return 6;
    }
}

/* Execute 2nd byte of DST MEM prefix (effective address ea, from_b0 = op1 == 0xB0) */
static int exec_dst_mem(u32 ea, int from_b0)
{
    u8 op = fetch8();
    if (from_b0 && op >= 0xF0u) { /* RET cc (encoded as B0 F0..FF!) */
        if (eval_cc(op & 15u)) {
            S.pc = pop32() & 0xFFFFFFu;
            return 12;
        }
        return 6;
    }
    if ((op & 0xF8u) == 0x20u) { reg_short_set(1, op & 7u, ea & 0xFFFFu); return 4; }
    if ((op & 0xF8u) == 0x30u) { reg_short_set(2, op & 7u, ea & 0xFFFFFFu); return 4; }
    if ((op & 0xF8u) == 0x40u) { mem_write8(ea, (u8)reg_short_get(0, op & 7u)); return 6; }
    if ((op & 0xF8u) == 0x50u) { mem_write16(ea, (u16)reg_short_get(1, op & 7u)); return 6; }
    if ((op & 0xF8u) == 0x60u) { mem_write32(ea, reg_short_get(2, op & 7u)); return 8; }
    if (op >= 0x80u && op < 0xA8u) { /* ANDCF/ORCF/XORCF/LDCF/STCF #b, (mem) */
        u32 b = op & 7u;
        u8 mv = mem_read8(ea), bit = (mv >> b) & 1u;
        u8 f = get_flags(), c = f & 1u;
        u32 grp = (op - 0x80u) >> 3;
        if (grp == 0u) c &= bit;
        else if (grp == 1u) c |= bit;
        else if (grp == 2u) c ^= bit;
        else if (grp == 3u) c = bit;
        else { mem_write8(ea, (u8)((mv & ~(1u << b)) | (c << b))); return 8; }
        set_flags((u8)((f & ~FL_C) | c));
        return 6;
    }
    if (op >= 0x28u && op <= 0x2Cu) { /* ANDCF..STCF A, (mem) */
        u32 b = reg_short_get(0, 1u) & 7u;
        u8 mv = mem_read8(ea), bit = (mv >> b) & 1u;
        u8 f = get_flags(), c = f & 1u;
        if (op == 0x28u) c &= bit;
        else if (op == 0x29u) c |= bit;
        else if (op == 0x2Au) c ^= bit;
        else if (op == 0x2Bu) c = bit;
        else { mem_write8(ea, (u8)((mv & ~(1u << b)) | (c << b))); return 8; }
        set_flags((u8)((f & ~FL_C) | c));
        return 6;
    }
    if ((op & 0xF8u) == 0xA8u) { /* TSET #b, (mem) */
        u8 m = (u8)(1u << (op & 7u)), mv = mem_read8(ea);
        set_flags((u8)((get_flags() & FL_C) | FL_H | ((mv & m) ? 0u : FL_Z)));
        mem_write8(ea, mv | m);
        return 8;
    }
    if ((op & 0xF8u) == 0xB0u) { mem_write8(ea, (u8)(mem_read8(ea) & ~(1u << (op & 7u)))); return 8; }
    if ((op & 0xF8u) == 0xB8u) { mem_write8(ea, (u8)(mem_read8(ea) | (1u << (op & 7u)))); return 8; }
    if ((op & 0xF8u) == 0xC0u) { mem_write8(ea, (u8)(mem_read8(ea) ^ (1u << (op & 7u)))); return 8; }
    if ((op & 0xF8u) == 0xC8u) {
        u8 mv = mem_read8(ea);
        set_flags((u8)((get_flags() & FL_C) | FL_H | ((mv & (1u << (op & 7u))) ? 0u : FL_Z)));
        return 6;
    }
    if ((op & 0xF0u) == 0xD0u) { /* JP cc, mem */
        if (eval_cc(op & 15u)) { S.pc = ea & 0xFFFFFFu; return 8; }
        return 4;
    }
    if ((op & 0xF0u) == 0xE0u) { /* CALL cc, mem */
        if (eval_cc(op & 15u)) { push32(S.pc); S.pc = ea & 0xFFFFFFu; return 12; }
        return 6;
    }

    switch (op) {
    case 0x00u: mem_write8(ea, fetch8()); return 6;
    case 0x02u: mem_write16(ea, fetch16()); return 8;
    case 0x04u: mem_write8(ea, (u8)pop16()); return 8;
    case 0x06u: mem_write16(ea, pop16()); return 8;
    case 0x14u: mem_write8(ea, mem_read8(fetch16())); return 8;
    case 0x16u: mem_write16(ea, mem_read16(fetch16())); return 8;
    default: return 6;
    }
}

static int tlcs900_step(void)
{
    int i_cyc = check_interrupts();
    if (i_cyc)
        return i_cyc;
    if (S.halted)
        return 4;

    /* Clean-room BIOS HLE hooks ($FF0100 = SWI 1, $FF1000..$FF11FF = $FFFE00 vector table) */
    if (!S.has_ext_bios && S.pc >= 0xFF0000u) {
        if (S.pc == 0xFF0100u) {
            u8 rw3 = (u8)((S.bank[3][0] >> 8) & 0x1Fu);
            hle_bios_vector(rw3);
        } else if (S.pc >= 0xFF1000u && S.pc < 0xFF1200u && ((S.pc & 0x0Fu) == 0u)) {
            u32 vec = (S.pc - 0xFF1000u) >> 4;
            hle_bios_vector(vec);
        }
    }

    u8 op = fetch8();

    /* Prefix ranges 0x80..0xF5 */
    if (op >= 0x80u && op < 0xB0u) {
        int sz = (op - 0x80u) >> 4; /* 0=byte, 1=word, 2=long */
        u32 r = op & 7u;
        u32 ea = *ptr_r32_short(r);
        if (op & 8u) ea += (u32)(int)(signed char)fetch8();
        return exec_src_mem(sz, ea & 0xFFFFFFu, r);
    }
    if (op >= 0xB0u && op < 0xC0u) {
        u32 ea = *ptr_r32_short(op & 7u);
        if (op & 8u) ea += (u32)(int)(signed char)fetch8();
        return exec_dst_mem(ea & 0xFFFFFFu, op == 0xB0u);
    }
    if (op >= 0xC0u && op <= 0xEFu) {
        u32 lo = op & 0x0Fu;
        int sz = (op - 0xC0u) >> 4;
        if (lo <= 5u)
            return exec_src_mem(sz, decode_ea_ext(lo), 3u);
        if (lo == 7u)
            return exec_reg_prefix(sz, 0, fetch8());
        if (lo >= 8u)
            return exec_reg_prefix(sz, 1, lo - 8u);
        return 4;
    }
    if (op >= 0xF0u && op <= 0xF5u)
        return exec_dst_mem(decode_ea_ext(op - 0xF0u), 0);

    /* Standalone 1st-byte opcodes */
    if ((op & 0xF8u) == 0x20u) { reg_short_set(0, op & 7u, fetch8()); return 4; }
    if ((op & 0xF8u) == 0x28u) { push16((u16)reg_short_get(1, op & 7u)); return 6; }
    if ((op & 0xF8u) == 0x30u) { reg_short_set(1, op & 7u, fetch16()); return 4; }
    if ((op & 0xF8u) == 0x38u) { push32(reg_short_get(2, op & 7u)); return 8; }
    if ((op & 0xF8u) == 0x40u) { reg_short_set(2, op & 7u, fetch32()); return 6; }
    if ((op & 0xF8u) == 0x48u) { reg_short_set(1, op & 7u, pop16()); return 6; }
    if ((op & 0xF8u) == 0x58u) { reg_short_set(2, op & 7u, pop32()); return 8; }
    if ((op & 0xF0u) == 0x60u) {
        s16 d8 = (signed char)fetch8();
        if (eval_cc(op & 15u)) { S.pc = (S.pc + (u32)(int)d8) & 0xFFFFFFu; return 8; }
        return 4;
    }
    if ((op & 0xF0u) == 0x70u) {
        s16 d16 = (s16)fetch16();
        if (eval_cc(op & 15u)) { S.pc = (S.pc + (u32)(int)d16) & 0xFFFFFFu; return 8; }
        return 4;
    }
    if (op >= 0xF8u) { /* SWI 0..7 */
        u32 n = op & 7u;
        u32 target = (n >= 3u && n <= 6u && !S.has_ext_bios)
            ? mem_read32(0x6FB8u + (n - 3u) * 4u)
            : mem_read32(0xFFFF00u + n * 4u);
        push32(S.pc);
        push16(S.sr);
        S.sr |= 0x8000u;
        S.intnest++;
        S.pc = target & 0xFFFFFFu;
        return 16;
    }

    switch (op) {
    case 0x00u: case 0x01u: case 0x04u: return 4;
    case 0x02u: push16(S.sr); return 6;
    case 0x03u: S.sr = (u16)((pop16() & 0xF7D7u) | 0x8000u); return 6;
    case 0x05u: S.halted = 1; return 6;
    case 0x06u: { u8 lv = fetch8() & 7u; S.sr = (u16)((S.sr & 0x8FFFu) | ((u16)lv << 12)); return 4; }
    case 0x07u: { /* RETI */
        S.sr = (u16)((pop16() & 0xF7D7u) | 0x8000u);
        S.pc = pop32() & 0xFFFFFFu;
        if (S.intnest > 0u) S.intnest--;
        return 12;
    }
    case 0x08u: { u8 a = fetch8(), v = fetch8(); mem_write8(a, v); return 6; }
    case 0x09u: push16(fetch8()); return 6;
    case 0x0Au: { u8 a = fetch8(); u16 v = fetch16(); mem_write16(a, v); return 8; }
    case 0x0Bu: push16(fetch16()); return 6;
    case 0x0Cu: S.sr = (u16)((S.sr & 0xF8FFu) | ((((S.sr >> 8) + 1u) & 3u) << 8)); return 4;
    case 0x0Du: S.sr = (u16)((S.sr & 0xF8FFu) | ((((S.sr >> 8) - 1u) & 3u) << 8)); return 4;
    case 0x0Eu: S.pc = pop32() & 0xFFFFFFu; return 10;
    case 0x0Fu: { s16 d = (s16)fetch16(); S.pc = pop32() & 0xFFFFFFu; S.ix[3] = (S.ix[3] + (u32)(int)d) & 0xFFFFFFu; return 12; }
    case 0x10u: set_flags((u8)(get_flags() & ~(FL_C | FL_N | FL_H))); return 4;
    case 0x11u: set_flags((u8)((get_flags() & ~(FL_N | FL_H)) | FL_C)); return 4;
    case 0x12u: { u8 f = get_flags(); set_flags((u8)((f & ~(FL_N | FL_H | FL_C)) | ((f & FL_C) ? FL_H : FL_C))); return 4; }
    case 0x13u: { u8 f = get_flags(); set_flags((u8)((f & ~(FL_N | FL_C)) | ((f & FL_Z) ? 0u : FL_C))); return 4; }
    case 0x14u: push16((u16)reg_short_get(0, 1u)); return 6;
    case 0x15u: reg_short_set(0, 1u, pop16() & 0xFFu); return 6;
    case 0x16u: { u8 t = get_flags(); set_flags(S.f_dash); S.f_dash = t; return 4; }
    case 0x17u: { u8 b = fetch8() & 3u; S.sr = (u16)((S.sr & 0xF8FFu) | ((u16)b << 8)); return 4; }
    case 0x18u: push16(get_flags()); return 6;
    case 0x19u: set_flags((u8)pop16()); return 6;
    case 0x1Au: S.pc = fetch16(); return 8;
    case 0x1Bu: S.pc = fetch24(); return 8;
    case 0x1Cu: { u16 t = fetch16(); push32(S.pc); S.pc = t; return 12; }
    case 0x1Du: { u32 t = fetch24(); push32(S.pc); S.pc = t; return 12; }
    case 0x1Eu: { s16 d = (s16)fetch16(); push32(S.pc); S.pc = (S.pc + (u32)(int)d) & 0xFFFFFFu; return 12; }
    case 0xF7u: { /* LDX (#d8), #imm8: F7 00 d8 00 imm 00 */
        (void)fetch8();
        u8 a = fetch8();
        (void)fetch8();
        u8 v = fetch8();
        (void)fetch8();
        mem_write8(a, v);
        return 8;
    }
    default:
        return 4;
    }
}

/* ---- 8-bit Timers 0..3 ---- */
static void timers_step(u32 cpu_cycles, int hblank_pulse)
{
    u8 trun = W.sfr[0x20];
    if (!(trun & 0x8Fu))
        return;

    u32 prev = S.t_presc;
    S.t_presc += cpu_cycles;
    u32 edges = prev ^ S.t_presc;

    /* Prescaler taps (@ 6.144 MHz -> phiT1=/8 (bit 2), phiT4=/32 (bit 4), phiT16=/128 (bit 6), phiT256=/2048 (bit 10)) */
    static const u8 shift_tab[4] = {3u, 5u, 7u, 11u};

    /* Timer 0 */
    if (trun & 0x01u) {
        u8 src = W.sfr[0x24] & 3u;
        int tick = (src == 0u) ? hblank_pulse : (int)((edges >> shift_tab[src]) & (S.t_presc >> shift_tab[src]) & 1u);
        if (tick) {
            S.t_cnt[0]++;
            u8 reg0 = W.sfr[0x22] ? W.sfr[0x22] : 0u;
            if (S.t_cnt[0] == reg0) {
                S.t_cnt[0] = 0;
                irq_set_pending(0x73u, 0);
                /* Cascade to Timer 1 in 16-bit /PPG mode or when T1 clock == TO0 */
                if ((trun & 0x02u) && (((W.sfr[0x24] >> 2) & 3u) == 0u || ((W.sfr[0x24] >> 6) & 3u) == 1u)) {
                    if (++S.t_cnt[1] == W.sfr[0x23]) {
                        S.t_cnt[1] = 0;
                        irq_set_pending(0x73u, 1);
                    }
                }
            }
        }
    }

    /* Timer 1 (independent 8-bit mode) */
    if ((trun & 0x02u) && ((W.sfr[0x24] >> 6) & 3u) == 0u) {
        u8 src = (W.sfr[0x24] >> 2) & 3u;
        if (src > 0u) {
            u8 sh = (src == 1u) ? 3u : (src == 2u) ? 7u : 11u;
            if ((edges >> sh) & (S.t_presc >> sh) & 1u) {
                if (++S.t_cnt[1] == W.sfr[0x23]) {
                    S.t_cnt[1] = 0;
                    irq_set_pending(0x73u, 1);
                }
            }
        }
    }

    /* Timer 2 */
    if (trun & 0x04u) {
        u8 src = W.sfr[0x28] & 3u;
        if (src > 0u) {
            u8 sh = shift_tab[src];
            if ((edges >> sh) & (S.t_presc >> sh) & 1u) {
                if (++S.t_cnt[2] == W.sfr[0x26]) {
                    S.t_cnt[2] = 0;
                    irq_set_pending(0x74u, 0);
                    if ((trun & 0x08u) && (((W.sfr[0x28] >> 2) & 3u) == 0u)) {
                        if (++S.t_cnt[3] == W.sfr[0x27]) {
                            S.t_cnt[3] = 0;
                            irq_set_pending(0x74u, 1);
                            if (S.z80_active) S.zcpu.irq = 1;
                        }
                    }
                }
            }
        }
    }

    /* Timer 3 (independent 8-bit mode -- also drives Z80 IRQ!) */
    if ((trun & 0x08u) && ((W.sfr[0x28] >> 6) & 3u) == 0u) {
        u8 src = (W.sfr[0x28] >> 2) & 3u;
        if (src > 0u) {
            u8 sh = (src == 1u) ? 3u : (src == 2u) ? 7u : 11u;
            if ((edges >> sh) & (S.t_presc >> sh) & 1u) {
                if (++S.t_cnt[3] == W.sfr[0x27]) {
                    S.t_cnt[3] = 0;
                    irq_set_pending(0x74u, 1);
                    if (S.z80_active) S.zcpu.irq = 1;
                }
            }
        }
    }
}

/* ---- K1GE / K2GE Scanline Renderer (160 x 152 BGR555) ---- */
static inline u16 k2ge_rgb444_to_bgr555(u16 c12)
{
    /* K2GE 12-bit color: bits 3..0 = R, 7..4 = G, 11..8 = B -> 15-bit BGR555 */
    u32 r4 = c12 & 0x0Fu, g4 = (c12 >> 4) & 0x0Fu, b4 = (c12 >> 8) & 0x0Fu;
    u32 r5 = (r4 << 1) | (r4 >> 3);
    u32 g5 = (g4 << 1) | (g4 >> 3);
    u32 b5 = (b4 << 1) | (b4 >> 3);
    return (u16)((b5 << 10) | (g5 << 5) | r5);
}

static inline u16 mono_shade_bgr555(u8 shade)
{
    /* K1GE 3-bit shade: 0 = crisp LCD white, 7 = black */
    u32 lv = (7u - (shade & 7u)) * 31u / 7u;
    return (u16)((lv << 10) | (lv << 5) | lv);
}

static void draw_scroll_plane(u16 *line, int y, int which, int k1ge_mode)
{
    u32 map_base = which ? 0x1800u : 0x1000u; /* $9800 or $9000 */
    u32 pal_base = which ? 0x0300u : 0x0280u; /* $8300 or $8280 */
    u32 mono_base = which ? 0x0110u : 0x0108u; /* $8110 or $8108 */
    u8 sx = W.vram[which ? 0x0034u : 0x0032u];
    u8 sy = W.vram[which ? 0x0035u : 0x0033u];

    u32 py = ((u32)y + sy) & 0xFFu;
    u32 ty_row = (py >> 3) * 32u, fy = py & 7u;

    int x = 0;
    while (x < NGP_W) {
        u32 px = ((u32)x + sx) & 0xFFu;
        u32 tx = px >> 3, fx = px & 7u;
        int span = (int)(8u - fx);
        if (x + span > NGP_W)
            span = NGP_W - x;

        u32 m_off = map_base + (ty_row + tx) * 2u;
        u16 entry = (u16)W.vram[m_off] | ((u16)W.vram[m_off + 1u] << 8);
        u32 tile = entry & 0x1FFu;
        u32 ry = (entry & 0x4000u) ? (7u - fy) : fy;
        u32 t_off = 0x2000u + tile * 16u + ry * 2u;
        u16 row = (u16)W.vram[t_off] | ((u16)W.vram[t_off + 1u] << 8);
        if (!row) {
            x += span;
            continue;
        }
        int hflip = (entry & 0x8000u) != 0u;
        if (k1ge_mode) {
            u32 mp = mono_base + ((entry >> 13) & 1u) * 4u;
            for (int i = 0; i < span; i++, fx++) {
                u32 rx = hflip ? fx : (7u - fx);
                u32 pix = (row >> (rx * 2u)) & 3u;
                if (pix)
                    line[x + i] = mono_shade_bgr555(W.vram[mp + pix] & 7u);
            }
        } else {
            u32 p_base = pal_base + ((entry >> 9) & 0x0Fu) * 8u;
            for (int i = 0; i < span; i++, fx++) {
                u32 rx = hflip ? fx : (7u - fx);
                u32 pix = (row >> (rx * 2u)) & 3u;
                if (pix) {
                    u32 p_off = p_base + pix * 2u;
                    u16 c12 = (u16)W.vram[p_off] | ((u16)W.vram[p_off + 1u] << 8);
                    line[x + i] = k2ge_rgb444_to_bgr555(c12);
                }
            }
        }
        x += span;
    }
}

static void draw_sprites_prio(u16 *line, int y, u32 want_prio, int k1ge_mode,
                              const u8 *sp_x, const u8 *sp_y, const u8 *vis, int n_vis)
{
    u8 pox = W.vram[0x0020], poy = W.vram[0x0021];
    /* Sprite 0 has highest priority -> iterate visible list from back (highest index) to front (0) */
    for (int vi = n_vis - 1; vi >= 0; vi--) {
        int s = vis[vi];
        const u8 *oam = W.vram + 0x0800 + s * 4;
        u8 attr = oam[1];
        if (((attr >> 3) & 3u) != want_prio)
            continue;
        u8 dy = (u8)((u8)y - (u8)(sp_y[s] + poy));
        u8 sx = (u8)(sp_x[s] + pox);
        u32 tile = (u32)oam[0] | (((u32)attr & 1u) << 8);
        u32 ry = (attr & 0x40u) ? (7u - dy) : dy;
        u32 t_off = 0x2000u + tile * 16u + ry * 2u;
        u16 row = (u16)W.vram[t_off] | ((u16)W.vram[t_off + 1u] << 8);
        if (!row)
            continue;
        u32 pal = W.vram[0x0C00 + s] & 0x0Fu;
        u32 mpal = (attr >> 5) & 1u;
        for (u32 fx = 0; fx < 8u; fx++) {
            u8 px = (u8)(sx + fx);
            if (px >= NGP_W)
                continue;
            u32 rx = (attr & 0x80u) ? fx : (7u - fx);
            u32 pix = (row >> (rx * 2u)) & 3u;
            if (!pix)
                continue;
            if (k1ge_mode) {
                u8 shade = W.vram[0x0100u + mpal * 4u + pix] & 7u;
                line[px] = mono_shade_bgr555(shade);
            } else {
                u32 p_off = 0x0200u + (pal * 4u + pix) * 2u;
                u16 c12 = (u16)W.vram[p_off] | ((u16)W.vram[p_off + 1u] << 8);
                line[px] = k2ge_rgb444_to_bgr555(c12);
            }
        }
    }
}

static void render_scanline(int y, u16 *picture)
{
    u16 *line = picture + y * NGP_W;
    int k1ge_mode = (W.vram[0x07E2] & 0x80u) != 0u;

    /* Background color */
    u16 bg_col;
    if (k1ge_mode) {
        u8 bg_ctl = W.vram[0x0118];
        bg_col = ((bg_ctl & 0xC0u) == 0x80u) ? mono_shade_bgr555(bg_ctl & 7u) : mono_shade_bgr555(0u);
    } else {
        u8 bg_ctl = W.vram[0x0118];
        u32 idx = ((bg_ctl & 0xC0u) == 0x80u) ? (bg_ctl & 7u) : 0u;
        u16 c12 = (u16)W.vram[0x03E0u + idx * 2u] | ((u16)W.vram[0x03E0u + idx * 2u + 1u] << 8);
        bg_col = k2ge_rgb444_to_bgr555(c12);
    }
    for (int x = 0; x < NGP_W; x++)
        line[x] = bg_col;

    /* Precompute chained sprite positions (0..63) & filter active sprites overlapping scanline y */
    u8 sp_x[64], sp_y[64], vis[64];
    int n_vis = 0;
    u8 cx = 0, cy = 0, poy = W.vram[0x0021];
    for (int s = 0; s < 64; s++) {
        const u8 *oam = W.vram + 0x0800 + s * 4;
        u8 attr = oam[1];
        cx = (attr & 0x04u) ? (u8)(cx + oam[2]) : oam[2];
        cy = (attr & 0x02u) ? (u8)(cy + oam[3]) : oam[3];
        sp_x[s] = cx;
        sp_y[s] = cy;
        if ((attr & 0x18u) && (u8)((u8)y - (u8)(cy + poy)) < 8u)
            vis[n_vis++] = (u8)s;
    }

    int p2_front = (W.vram[0x0030] & 0x80u) != 0u;
    int back_plane = p2_front ? 0 : 1;
    int front_plane = p2_front ? 1 : 0;

    if (n_vis) draw_sprites_prio(line, y, 1u, k1ge_mode, sp_x, sp_y, vis, n_vis);
    draw_scroll_plane(line, y, back_plane, k1ge_mode);
    if (n_vis) draw_sprites_prio(line, y, 2u, k1ge_mode, sp_x, sp_y, vis, n_vis);
    draw_scroll_plane(line, y, front_plane, k1ge_mode);
    if (n_vis) draw_sprites_prio(line, y, 3u, k1ge_mode, sp_x, sp_y, vis, n_vis);

    /* Window clipping ($8002..$8005) & negative invert ($8012) */
    u8 wx = W.vram[0x0002], wy = W.vram[0x0003];
    u8 ww = W.vram[0x0004], wh = W.vram[0x0005];
    if (ww < NGP_W || wh < NGP_H || wx > 0u || wy > 0u) {
        u32 oidx = W.vram[0x0012] & 7u;
        u16 ocol = k1ge_mode
            ? mono_shade_bgr555((u8)oidx)
            : k2ge_rgb444_to_bgr555((u16)W.vram[0x03F0u + oidx * 2u] | ((u16)W.vram[0x03F0u + oidx * 2u + 1u] << 8));
        if (y < (int)wy || y >= (int)wy + (int)wh) {
            for (int x = 0; x < NGP_W; x++) line[x] = ocol;
        } else {
            for (int x = 0; x < NGP_W; x++)
                if (x < (int)wx || x >= (int)wx + (int)ww)
                    line[x] = ocol;
        }
    }
    if (W.vram[0x0012] & 0x80u) {
        for (int x = 0; x < NGP_W; x++)
            line[x] ^= 0x7FFFu;
    }
}

/* ---- T6W28 + DAC Audio Synthesis (48 kHz mono) ---- */
static void psg_tick_one(void)
{
    for (int ch = 0; ch < 3; ch++) {
        if (--S.psg_l.cnt[ch] <= 0) {
            u16 p = (S.psg_l.period[ch] != 1u || S.psg_r.period[ch] == 1u)
                ? S.psg_l.period[ch] : S.psg_r.period[ch];
            S.psg_l.cnt[ch] = p ? (int)p : 1;
            S.psg_l.out[ch] ^= 1u;
        }
    }
    if (--S.psg_r.cnt[3] <= 0) {
        u8 nctrl = S.psg_r.noise_ctrl ? S.psg_r.noise_ctrl : S.psg_l.noise_ctrl;
        u8 nc = nctrl & 3u;
        u16 t2 = (S.psg_l.period[2] != 1u || S.psg_r.period[2] == 1u)
            ? S.psg_l.period[2] : S.psg_r.period[2];
        int per = (nc == 0u) ? 0x10 : (nc == 1u) ? 0x20 : (nc == 2u) ? 0x40 : (t2 ? (int)t2 * 2 : 0x10);
        S.psg_r.cnt[3] = per;
        S.psg_r.out[3] ^= 1u;
        if (S.psg_r.out[3]) {
            u16 s = S.psg_r.lfsr;
            u16 fb = (nctrl & 4u) ? (u16)(((s >> 0) ^ (s >> 1)) & 1u) : (u16)(s & 1u);
            S.psg_r.lfsr = (u16)((s >> 1) | (fb << 14));
        }
    }
}

static void audio_step_line(u32 cyc)
{
    if (!S.sample_rate)
        return;
    /* T6W28 clock is 3.072 MHz / 16 = 192 kHz = 6.144 MHz / 32 */
    S.psg_rem += (int)cyc;
    while (S.psg_rem >= 32) {
        S.psg_rem -= 32;
        psg_tick_one();
        S.aud_frac += S.sample_rate;
        if (S.aud_frac >= 191940u) { /* 515 * 199 * 59.73 / 32 = ~191,940 Hz */
            S.aud_frac -= 191940u;
            int mix = 0;
            for (int ch = 0; ch < 3; ch++) {
                int amp = (sn_vol[S.psg_l.attn[ch] & 15u] + sn_vol[S.psg_r.attn[ch] & 15u]) >> 1;
                mix += S.psg_l.out[ch] ? amp : -amp;
            }
            int namp = (sn_vol[S.psg_l.attn[3] & 15u] + sn_vol[S.psg_r.attn[3] & 15u]) >> 1;
            mix += (S.psg_r.lfsr & 1u) ? namp : -namp;
            mix += (((int)S.dac_l - 128) + ((int)S.dac_r - 128)) * 32;

            S.dc_acc += (mix * 128 - S.dc_acc) >> 9;
            int centered = mix - (S.dc_acc >> 7);
            if (centered > 32767) centered = 32767;
            if (centered < -32768) centered = -32768;
            if (S.aud_count < NGP_AUD_MAX)
                W.aud_buf[S.aud_count++] = (s16)centered;
        }
    }
}

/* ---- Public API ---- */
void ngp_set_bios(const u8 *data, u32 size)
{
    if (data && size == 0x10000u) {
        for (u32 i = 0; i < 0x10000u; i++)
            W.ext_bios[i] = data[i];
        S.has_ext_bios = 1;
    } else {
        S.has_ext_bios = 0;
    }
}

const char *ngp_load(const u8 *data, u32 size)
{
    if (!data || size < 0x40u || size > NGP_MAX_ROM)
        return "not a Neo Geo Pocket cartridge (invalid size)";

    /* Verify SNK license string ("COPYRIGHT BY SNK" or " LICENSED BY SNK") or valid $200000..$3FFFFF entry */
    int snk = 0;
    const char *m1 = "COPYRIGHT BY SNK", *m2 = " LICENSED BY SNK";
    int ok1 = 1, ok2 = 1;
    for (int i = 0; i < 16; i++) {
        if (data[i] != (u8)m1[i]) ok1 = 0;
        if (data[i] != (u8)m2[i]) ok2 = 0;
    }
    snk = ok1 || ok2;
    u32 ep = (u32)data[0x1C] | ((u32)data[0x1D] << 8) | ((u32)data[0x1E] << 16) | ((u32)data[0x1F] << 24);
    if (!snk && (ep < 0x200000u || ep >= 0x400000u))
        return "invalid Neo Geo Pocket cartridge header";
    if (ep < 0x200000u || ep >= 0xFF0000u)
        return "invalid Neo Geo Pocket entry point";

    u8 keep_ext = S.has_ext_bios;
    u32 keep_rate = S.sample_rate;
    for (u32 i = 0; i < sizeof(S); i++)
        ((u8 *)&S)[i] = 0;
    S.has_ext_bios = keep_ext;
    S.sample_rate = keep_rate;
    S.rom_size = size;
    S.is_color_rom = (data[0x23] != 0u) ? 1u : 0u;

    for (u32 i = 0; i < size; i++)
        W.rom[i] = data[i];
    for (u32 i = size; i < (size <= 0x200000u ? 0x200000u : NGP_MAX_ROM); i++)
        W.rom[i] = 0xFFu;

    /* Persist top 64 KB of first 2 MB Flash chip (where homebrew & SNK games store Flash saves, e.g. $1F0000..$1FFFFF) */
    S.sav_offset = (size <= 0x200000u) ? (0x200000u - NGP_SAV_SIZE) : (size - NGP_SAV_SIZE);
    for (u32 i = 0; i < NGP_SAV_SIZE; i++)
        W.sav_buf[i] = W.rom[S.sav_offset + i];

    for (u32 i = 0; i < 0x3000u; i++) W.wram[i] = 0u;
    for (u32 i = 0; i < 0x1000u; i++) W.zram[i] = 0u;
    for (u32 i = 0; i < 0x4000u; i++) W.vram[i] = 0u;
    for (u32 i = 0; i < 0x100u; i++)  W.sfr[i] = 0u;

    build_clean_bios();
    z80_setup_bus();
    t6w_reset_side(&S.psg_l);
    t6w_reset_side(&S.psg_r);
    S.dac_l = S.dac_r = 0x80u;

    /* Default K2GE / BIOS boot state */
    W.vram[0x0004] = NGP_W;      /* WSI.H = 160 */
    W.vram[0x0005] = NGP_H;      /* WSI.V = 152 */
    W.vram[0x0006] = 0xC6u;
    W.vram[0x0000] = 0x80u;      /* VBlank IRQ enabled */
    W.vram[0x07F0] = 0x55u;
    W.vram[0x07E2] = S.is_color_rom ? 0x00u : 0x80u;
    /* Default K1GE shades so monochrome games have proper contrast out of the box */
    for (int i = 0; i < 3; i++) {
        W.vram[0x0100 + i * 8 + 1] = 2u;
        W.vram[0x0100 + i * 8 + 2] = 5u;
        W.vram[0x0100 + i * 8 + 3] = 7u;
        W.vram[0x0100 + i * 8 + 5] = 2u;
        W.vram[0x0100 + i * 8 + 6] = 5u;
        W.vram[0x0100 + i * 8 + 7] = 7u;
    }

    /* BIOS system RAM ($6F80..$6FFF) */
    W.wram[0x6F80u - 0x4000u] = 0xFFu; /* Battery OK */
    W.wram[0x6F81u - 0x4000u] = 0xFFu;
    W.wram[0x6F87u - 0x4000u] = 0x01u; /* Language: English */
    W.wram[0x6F91u - 0x4000u] = 0x10u; /* OS Version: Neo Geo Pocket Color */
    W.wram[0x6F95u - 0x4000u] = S.is_color_rom ? 0x10u : 0x00u;
    for (u32 v = 0x6FB8u; v < 0x7000u; v += 4u) {
        W.wram[v - 0x4000u + 0] = 0x00u;
        W.wram[v - 0x4000u + 1] = 0x02u;
        W.wram[v - 0x4000u + 2] = 0xFFu;
        W.wram[v - 0x4000u + 3] = 0x00u;
    }

    /* Default VBlank interrupt priority level 4 in INTE45 ($71) */
    W.sfr[0x71] = 0x04u;

    /* Preload system font into VRAM so carts skipping VECT_SYSFONTSET still have BIOS ASCII */
    S.bank[3][0] = 0x03u;
    hle_bios_vector(5u);
    S.bank[3][0] = 0u;

    S.ix[3] = 0x00006C00u; /* Initial XSP */
    S.sr = 0xF800u;        /* System mode, IFF=7 (game's EI 0 enables interrupts) */
    S.pc = S.has_ext_bios ? (mem_read32(0xFF0000u) & 0xFFFFFFu) : (ep & 0xFFFFFFu);

    /* Format info string */
    char title[13];
    for (int i = 0; i < 12; i++) {
        u8 ch = data[0x24 + i];
        title[i] = (ch >= 0x20u && ch < 0x7Fu) ? (char)ch : ' ';
    }
    int tlen = 12;
    while (tlen > 0 && title[tlen - 1] == ' ') tlen--;
    title[tlen] = 0;

    char *p = S.info_str;
    const char *pre = S.is_color_rom ? "Neo Geo Pocket Color" : "Neo Geo Pocket";
    while (*pre) *p++ = *pre++;
    if (tlen > 0) {
        *p++ = ' '; *p++ = '"';
        for (int i = 0; i < tlen; i++) *p++ = title[i];
        *p++ = '"';
    }
    *p++ = ','; *p++ = ' ';
    u32 kb = (size + 1023u) >> 10;
    if (kb >= 1000u) *p++ = (char)('0' + (kb / 1000u) % 10u);
    if (kb >= 100u)  *p++ = (char)('0' + (kb / 100u) % 10u);
    if (kb >= 10u)   *p++ = (char)('0' + (kb / 10u) % 10u);
    *p++ = (char)('0' + kb % 10u);
    const char *suf = " KB";
    while (*suf) *p++ = *suf++;
    *p = 0;
    return 0;
}

const char *ngp_info(void) { return S.info_str; }
int ngp_jammed(void) { return S.jammed; }

u8 *ngp_save_ram(u32 *size, int *battery)
{
    for (u32 i = 0; i < NGP_SAV_SIZE; i++)
        W.sav_buf[i] = W.rom[S.sav_offset + i];
    *size = NGP_SAV_SIZE;
    *battery = 1;
    return W.sav_buf;
}

int ngp_save_changed(void)
{
    if (!S.sav_dirty) {
        /* If play.c just loaded .sav into W.sav_buf at boot, copy non-0xFF save bytes back into W.rom! */
        for (u32 i = 0; i < NGP_SAV_SIZE; i++) {
            if (W.sav_buf[i] != W.rom[S.sav_offset + i])
                W.rom[S.sav_offset + i] = W.sav_buf[i];
        }
        return 0;
    }
    for (u32 i = 0; i < NGP_SAV_SIZE; i++)
        W.sav_buf[i] = W.rom[S.sav_offset + i];
    S.sav_dirty = 0;
    return 1;
}

void ngp_audio_rate(u32 hz) { S.sample_rate = hz; S.aud_frac = 0; S.psg_rem = 0; S.dc_acc = 0; }

int ngp_audio(s16 *out, int max)
{
    int n = (int)S.aud_count < max ? (int)S.aud_count : max;
    for (int i = 0; i < n; i++)
        out[i] = W.aud_buf[i];
    S.aud_count = 0;
    return n;
}

void ngp_frame(u16 pad, u16 *picture)
{
    S.pad = pad;
    S.aud_count = 0;

    for (int y = 0; y < NGP_LINES; y++) {
        S.scan_y = y;
        if (y == NGP_H) {
            /* Start of VBlank (scanline 152): assert INT4 if $8000 bit 7 enabled */
            W.wram[0x6F82u - 0x4000u] = current_joypad();
            if (W.vram[0x0000] & 0x80u)
                irq_set_pending(0x71u, 0);
        }

        int line_budget = NGP_CYC_LINE >> S.clk_gear;
        if (line_budget < 32) line_budget = 32;
        int cyc = 0;
        while (cyc < line_budget) {
            if (S.halted && !any_irq_latched()) {
                u8 trun = W.sfr[0x20] & 0x0Fu;
                if (trun == 0u || (trun == 0x01u && (W.sfr[0x24] & 3u) == 0u)) {
                    int rem = ((line_budget - cyc + 3) & ~3);
                    if (trun)
                        S.t_presc += (u32)(rem << S.clk_gear);
                    cyc += rem;
                    break;
                }
            }
            S.line_cyc = cyc << S.clk_gear;
            int step = tlcs900_step();
            cyc += step;
            if (W.sfr[0x20] & 0x8Fu)
                timers_step((u32)(step << S.clk_gear), 0);
        }
        S.line_cyc = NGP_CYC_LINE - 1;

        if (y < NGP_H)
            render_scanline(y, picture);

        /* HBlank pulse for Timer 0 HBlank clock mode (on lines 0..151 when $8000 bit 6 enabled, or all active lines) */
        if (y < NGP_H && (W.vram[0x0000] & 0x40u))
            timers_step(0u, 1);
        else if (y < NGP_H && (W.sfr[0x24] & 3u) == 0u)
            timers_step(0u, 1);

        if (S.z80_active) {
            S.zcpu.cycles = 0;
            (void)z80_run(&S.zcpu, NGP_CYC_LINE / 2);
            S.zcpu.irq = 0;
        }

        audio_step_line(NGP_CYC_LINE);
    }
}
