/* A Bandai WonderSwan and WonderSwan Color (SPHINX SoC + NEC V30MZ): see ws.h. */
#include "ws.h"
#ifndef WS_HOST
#include "hw.h"
#endif

#define LINE_CYC   256
#define LINES_ACT  144
#define LINES_TOT  159
#define FRAME_CYC  (LINE_CYC * LINES_TOT)       /* 40704 cycles @ 3.072 MHz = 75.4717 Hz */

/* V30MZ FLAGS bits (bits 15..12 fixed 1, bit 1 fixed 1, bits 3 & 5 fixed 0) */
#define FC 0x0001u
#define FP 0x0004u
#define FA 0x0010u
#define FZ 0x0040u
#define FS 0x0080u
#define FT 0x0100u
#define FI 0x0200u
#define FD 0x0400u
#define FO 0x0800u
#define F_FIXED_SET 0xF002u
#define F_MASK      0x0FD5u

enum { R_AX = 0, R_CX, R_DX, R_BX, R_SP, R_BP, R_SI, R_DI };
enum { S_ES = 0, S_CS, S_SS, S_DS };

struct ws_mem {
    u8 ram[0x10000];                    /* 64 KB internal RAM (WSC palettes at $FE00..$FFFF) */
    u8 sram[0x10000];                   /* up to 64 KB cartridge SRAM / EEPROM backing (.sav) */
    u8 ieeprom[0x800];                  /* 2 KB internal WSC EEPROM */
    u8 oam[512];                        /* 128 sprites x 4 bytes latched at VBlank */
    u8 parity[256];                     /* FP (0x04) parity lookup */
    u32 bp_lut[256];                    /* bit (7-k) -> nibble k (for 2bpp / 4bpp planar unpack) */
    u32 bp_lut_flip[256];               /* bit k -> nibble k (horizontally flipped planar unpack) */
    u16 wsc_pal15[256];                 /* cached 15-bit WSC palettes ($FE00..$FFFF) */
    u16 mono_pool15[8];                 /* cached 15-bit mono shade pool (IO $1C..$1F) */
    u16 mono_pal15[64];                 /* cached 15-bit mono 16x4 palettes (IO $20..$3F) */
    u16 rot_buf[WS_W * WS_H];           /* scratch buffer for vertical 144x224 rotation */
    s16 audio_ring[4096];
};

#ifdef WS_HOST
static struct ws_mem ws_mem_buf;
#define M (&ws_mem_buf)
#else
#define M ((struct ws_mem *)KSEG0(EMU_RAM_PHYS))
#endif

static struct {
    /* NEC V30MZ registers */
    u16 reg[8];
    u16 sreg[4];
    u16 ip, flags;
    u16 last_mul_co;                    /* CF|OF from most recent MUL/IMUL (used by V30MZ DIV/IDIV/AAM) */
    u8 halted, tf_delay, irq_inhibit;
    s32 cycles, line_end;

    /* Cartridge & cached 64 KB segment read pointers */
    u8 *rom;
    const u8 *seg_r[16];
    u32 rom_size, rom_banks64k;
    u32 save_size;
    u8 is_wsc_cart, is_vertical, has_ceeprom, sram_dirty;
    u8 wsc_pal_dirty, mono_pal_dirty;

    /* SoC I/O registers ($00..$FF) */
    u8 io[256];
    u16 hblank_cnt, vblank_cnt;
    u16 pad_state;
    int out_w, out_h;

    /* Sound DMA shadow & state */
    u32 sdma_src_reload, sdma_len_reload;
    u32 sdma_phase;

    /* 4-channel audio */
    u32 ch_phase[4];
    u8 ch_pos[4];
    u16 noise_lfsr;
    u32 sweep_cnt;
    u32 sample_rate, audio_cyc_acc;
    s32 audio_last_cyc;
    int audio_count;
} S;

static char info_buf[96];

/* ---- Memory & I/O helpers ---- */
static inline const u8 *rom_seg_ptr(u8 bank64k)
{
    if (!S.rom || !S.rom_banks64k)
        return 0;
    /* WonderSwan ROMs align their top bank to 0xFF: mask by power-of-two bank count */
    u32 idx = bank64k & (S.rom_banks64k - 1u);
    u32 off = idx << 16;
    if (off >= S.rom_size)
        off %= S.rom_size;
    return S.rom + off;
}

static void update_seg_ptrs(void)
{
    S.seg_r[0] = ((S.io[0x60] & 0x80u) || (S.io[0xA0] & 0x02u)) ? M->ram : 0;
    S.seg_r[1] = 0;
    S.seg_r[2] = rom_seg_ptr(S.io[0xC2]);
    S.seg_r[3] = rom_seg_ptr(S.io[0xC3]);
    u8 hi = (u8)((S.io[0xC0] & 0x0Fu) << 4);
    for (u32 seg = 4; seg < 16; seg++)
        S.seg_r[seg] = rom_seg_ptr((u8)(hi | seg));
}

static inline u8 mem_rd8(u32 phys)
{
    phys &= 0xFFFFFu;
    u32 seg = phys >> 16;
    const u8 *p = S.seg_r[seg];
    if (p)
        return p[phys & 0xFFFFu];
    u32 off = phys & 0xFFFFu;
    if (seg == 0)
        return off >= 0x4000u ? 0x90u : M->ram[off];
    if (seg == 1) {
        if (!S.save_size || S.has_ceeprom)
            return 0xFFu;
        u32 sa = (((u32)S.io[0xC1] << 16) | off) & (S.save_size - 1u);
        return sa < sizeof(M->sram) ? M->sram[sa] : 0xFFu;
    }
    return 0xFFu;
}

static void mem_wr8(u32 phys, u8 v)
{
    phys &= 0xFFFFFu;
    u32 seg = phys >> 16;
    u32 off = phys & 0xFFFFu;
    if (seg == 0) {
        M->ram[off] = v;
        if (off >= 0xFE00u)
            S.wsc_pal_dirty = 1;
        return;
    }
    if (seg == 1 && S.save_size && !S.has_ceeprom) {
        u32 sa = (((u32)S.io[0xC1] << 16) | off) & (S.save_size - 1u);
        if (sa < sizeof(M->sram) && M->sram[sa] != v) {
            M->sram[sa] = v;
            S.sram_dirty = 1;
        }
    }
}

static inline u16 seg_rd16(u16 seg, u16 off)
{
    u32 lo_a = (((u32)seg << 4) + off) & 0xFFFFFu;
    if ((lo_a & 0xFFFFu) != 0xFFFFu) {
        const u8 *p = (lo_a >> 16) == 0 ? M->ram : S.seg_r[lo_a >> 16];
        if (p) {
            u32 o = lo_a & 0xFFFFu;
            return (u16)(p[o] | ((u16)p[o + 1u] << 8));
        }
    }
    u8 lo = mem_rd8(lo_a);
    u8 hi = mem_rd8((((u32)seg << 4) + (u16)(off + 1u)) & 0xFFFFFu);
    return (u16)(lo | ((u16)hi << 8));
}

static inline void seg_wr16(u16 seg, u16 off, u16 v)
{
    u32 lo_a = (((u32)seg << 4) + off) & 0xFFFFFu;
    if (off != 0xFFFFu && (lo_a >> 16) == 0) {
        M->ram[lo_a] = (u8)v;
        M->ram[lo_a + 1u] = (u8)(v >> 8);
        if (lo_a >= 0xFDFFu)
            S.wsc_pal_dirty = 1;
        return;
    }
    mem_wr8(lo_a, (u8)v);
    mem_wr8((((u32)seg << 4) + (u16)(off + 1u)) & 0xFFFFFu, (u8)(v >> 8));
}

static inline u8 seg_rd8(u16 seg, u16 off)
{
    u32 a = (((u32)seg << 4) + off) & 0xFFFFFu;
    const u8 *p = (a >> 16) == 0 ? M->ram : S.seg_r[a >> 16];
    return p ? p[a & 0xFFFFu] : mem_rd8(a);
}

static inline void seg_wr8(u16 seg, u16 off, u8 v)
{
    u32 a = (((u32)seg << 4) + off) & 0xFFFFFu;
    if ((a >> 16) == 0) {
        M->ram[a] = v;
        if (a >= 0xFE00u)
            S.wsc_pal_dirty = 1;
    } else {
        mem_wr8(a, v);
    }
}

/* ---- 4-Channel WonderSwan Audio + Sound DMA ---- */
static void sdma_tick_one(void)
{
    if (!(S.io[0x52] & 0x80u))
        return;
    u32 src = ((u32)(S.io[0x4C] & 0x0Fu) << 16) | S.io[0x4A] | ((u32)S.io[0x4B] << 8);
    u32 len = ((u32)(S.io[0x50] & 0x0Fu) << 16) | S.io[0x4E] | ((u32)S.io[0x4F] << 8);
    if (!len) {
        S.io[0x52] &= (u8)~0x80u;
        return;
    }
    u8 val = (S.io[0x52] & 0x04u) ? 0 : mem_rd8(src);
    if (!(S.io[0x52] & 0x10u))
        S.io[0x89] = val;               /* Ch2 PCM voice */
    if (S.io[0x52] & 0x40u) src = (src - 1u) & 0xFFFFFu;
    else                    src = (src + 1u) & 0xFFFFFu;
    len--;
    if (len == 0) {
        if (S.io[0x52] & 0x08u) {       /* Repeat */
            src = S.sdma_src_reload;
            len = S.sdma_len_reload;
        } else {
            S.io[0x52] &= (u8)~0x80u;
        }
    }
    S.io[0x4A] = (u8)src;
    S.io[0x4B] = (u8)(src >> 8);
    S.io[0x4C] = (u8)((src >> 16) & 0x0Fu);
    S.io[0x4E] = (u8)len;
    S.io[0x4F] = (u8)(len >> 8);
    S.io[0x50] = (u8)((len >> 16) & 0x0Fu);
}

static void audio_step_cycles(u32 cyc)
{
    if (!cyc)
        return;
    /* Exact 64 clocks per 48 kHz sample (3,072,000 / 48,000 == 64) */
    u32 per_sample = S.sample_rate ? (3072000u / S.sample_rate) : 64u;
    if (!per_sample) per_sample = 64u;
    S.audio_cyc_acc += cyc;

    while (S.audio_cyc_acc >= per_sample) {
        S.audio_cyc_acc -= per_sample;

        /* Sound DMA clock: 4000, 6000, 12000, or 24000 Hz */
        if (S.io[0x52] & 0x80u) {
            static const u32 sdma_div[4] = {768u, 512u, 256u, 128u};
            u32 d = sdma_div[S.io[0x52] & 3u];
            S.sdma_phase += per_sample;
            while (S.sdma_phase >= d) {
                S.sdma_phase -= d;
                sdma_tick_one();
            }
        }

        /* Ch3 hardware frequency sweep (every 8192 * ((IO[0x8D]&0x1F)+1) clocks) */
        if ((S.io[0x90] & 0x44u) == 0x44u && S.io[0x8C]) {
            u32 sw_per = ((u32)(S.io[0x8D] & 0x1Fu) + 1u) * 8192u;
            S.sweep_cnt += per_sample;
            while (S.sweep_cnt >= sw_per) {
                S.sweep_cnt -= sw_per;
                u16 f = (u16)((S.io[0x84] | ((u16)S.io[0x85] << 8)) & 0x7FFu);
                f = (u16)((f + (s8)S.io[0x8C]) & 0x7FFu);
                S.io[0x84] = (u8)f;
                S.io[0x85] = (u8)(f >> 8);
            }
        }

        u16 wave_base = (u16)((u16)S.io[0x8F] << 6);
        u8 ch_en = S.io[0x90];
        s32 mix_l = 0, mix_r = 0;

        for (int ch = 0; ch < 4; ch++) {
            if (!(ch_en & (1u << ch)))
                continue;
            if (ch == 1 && (ch_en & 0x20u)) {
                /* 8-bit unsigned PCM voice in IO[0x89], volume bits in IO[0x94] */
                s32 pcm = (s32)S.io[0x89] - 128;
                u8 vc = S.io[0x94];
                s32 l = (vc & 0x08u) ? (pcm << 4) : (vc & 0x04u) ? (pcm << 3) : 0;
                s32 r = (vc & 0x02u) ? (pcm << 4) : (vc & 0x01u) ? (pcm << 3) : 0;
                mix_l += l;
                mix_r += r;
                continue;
            }
            u16 raw_f = (u16)((S.io[0x80 + ch * 2] | ((u16)S.io[0x81 + ch * 2] << 8)) & 0x7FFu);
            u32 period = 2048u - raw_f;
            S.ch_phase[ch] += per_sample;
            while (S.ch_phase[ch] >= period) {
                S.ch_phase[ch] -= period;
                S.ch_pos[ch] = (S.ch_pos[ch] + 1u) & 31u;
                if (ch == 3 && (S.io[0x8E] & 0x10u)) {
                    static const u8 taps[8] = {14, 10, 13, 4, 8, 6, 9, 11};
                    u8 tap = taps[S.io[0x8E] & 7u];
                    u16 bit = (u16)((1u ^ (S.noise_lfsr >> 7) ^ (S.noise_lfsr >> tap)) & 1u);
                    S.noise_lfsr = (u16)(((S.noise_lfsr << 1) | bit) & 0x7FFFu);
                    S.io[0x92] = (u8)S.noise_lfsr;
                    S.io[0x93] = (u8)(S.noise_lfsr >> 8);
                }
            }
            if (!S.sample_rate)
                continue;
            int samp4;
            if (ch == 3 && (ch_en & 0x80u)) {
                samp4 = (S.noise_lfsr & 1u) ? 15 : 0;
            } else {
                u8 wb = M->ram[(wave_base + (u16)ch * 16u + (S.ch_pos[ch] >> 1)) & 0xFFFFu];
                samp4 = (S.ch_pos[ch] & 1u) ? (wb >> 4) : (wb & 0x0Fu);
            }
            s32 centered = samp4 - 8;
            s32 lv = (S.io[0x88 + ch] >> 4) & 0x0Fu;
            s32 rv = S.io[0x88 + ch] & 0x0Fu;
            mix_l += centered * lv * 16;
            mix_r += centered * rv * 16;
        }

        if (S.sample_rate) {
            s32 mono = (mix_l + mix_r) >> 1;
            if (mono > 32767) mono = 32767;
            if (mono < -32768) mono = -32768;
            if (S.audio_count < 4096)
                M->audio_ring[S.audio_count++] = (s16)mono;
        }
    }
}

static void audio_catch_up(void)
{
    s32 now = S.cycles;
    if (now > S.audio_last_cyc) {
        audio_step_cycles((u32)(now - S.audio_last_cyc));
        S.audio_last_cyc = now;
    }
}

/* ---- SoC I/O Ports ($00..$FF) ---- */
static void run_gdma(void)
{
    u32 src = (((u32)(S.io[0x42] & 0x0Fu) << 16) | S.io[0x40] | ((u32)S.io[0x41] << 8)) & 0xFFFFEu;
    u16 dst = (u16)((S.io[0x44] | ((u16)S.io[0x45] << 8)) & 0xFFFEu);
    u16 len = (u16)((S.io[0x46] | ((u16)S.io[0x47] << 8)) & 0xFFFEu);
    int dec = (S.io[0x48] & 0x40u) != 0;
    while (len >= 2) {
        u8 b0 = mem_rd8(src);
        u8 b1 = mem_rd8((src + 1u) & 0xFFFFFu);
        M->ram[dst] = b0;
        M->ram[(u16)(dst + 1u)] = b1;
        if (dst >= 0xFDFFu)
            S.wsc_pal_dirty = 1;
        if (dec) { src = (src - 2u) & 0xFFFFEu; dst = (u16)(dst - 2u); }
        else     { src = (src + 2u) & 0xFFFFEu; dst = (u16)(dst + 2u); }
        len = (u16)(len - 2u);
        S.cycles += 2;
    }
    S.io[0x40] = (u8)src;
    S.io[0x41] = (u8)(src >> 8);
    S.io[0x42] = (u8)((src >> 16) & 0x0Fu);
    S.io[0x44] = (u8)dst;
    S.io[0x45] = (u8)(dst >> 8);
    S.io[0x46] = 0;
    S.io[0x47] = 0;
    S.io[0x48] &= (u8)~0x80u;
}

static void eeprom_exec(u8 *buf, u32 mask_words, u8 data_port, u8 addr_port, u8 ctrl, int mark_dirty)
{
    u16 cmd = (u16)(S.io[addr_port] | ((u16)S.io[addr_port + 1] << 8));
    /* NM93C46/93C66/93C86 serial command word: start bit followed by 2-bit op (10=READ, 01=WRITE) and word addr */
    u32 waddr = cmd & mask_words;
    if (ctrl & 0x10u) {                 /* READ */
        S.io[data_port] = buf[waddr * 2u];
        S.io[data_port + 1] = buf[waddr * 2u + 1u];
    } else if (ctrl & 0x20u) {          /* WRITE */
        buf[waddr * 2u] = S.io[data_port];
        buf[waddr * 2u + 1u] = S.io[data_port + 1];
        if (mark_dirty)
            S.sram_dirty = 1;
    }
}

static u8 read_keypad(void)
{
    u8 sel = S.io[0xB5] & 0x70u;
    u8 lo = 0;
    u16 p = S.pad_state;
    if (sel & 0x40u) {                  /* Buttons: Start(bit1), A(bit2), B(bit3) */
        if (p & (WS_START | WS_SELECT)) lo |= 0x02u;
        if (p & WS_A)                   lo |= 0x04u;
        if (p & WS_B)                   lo |= 0x08u;
    }
    if (sel & 0x20u) {                  /* X1..X4 (horizontal primary D-pad) */
        if (!S.is_vertical) {
            if (p & WS_UP)    lo |= 0x01u;
            if (p & WS_RIGHT) lo |= 0x02u;
            if (p & WS_DOWN)  lo |= 0x04u;
            if (p & WS_LEFT)  lo |= 0x08u;
        } else {
            if (p & WS_Y1) lo |= 0x01u;
            if (p & WS_Y2) lo |= 0x02u;
            if (p & WS_Y3) lo |= 0x04u;
            if (p & WS_Y4) lo |= 0x08u;
        }
    }
    if (sel & 0x10u) {                  /* Y1..Y4 (vertical D-pad / extra keys) */
        if (S.is_vertical) {
            /* Rotated 90 deg CCW: Y2=Up, Y3=Right, Y4=Down, Y1=Left */
            if (p & WS_LEFT)  lo |= 0x01u;
            if (p & WS_UP)    lo |= 0x02u;
            if (p & WS_RIGHT) lo |= 0x04u;
            if (p & WS_DOWN)  lo |= 0x08u;
        } else {
            if (p & WS_Y1) lo |= 0x01u;
            if (p & WS_Y2) lo |= 0x02u;
            if (p & WS_Y3) lo |= 0x04u;
            if (p & WS_Y4) lo |= 0x08u;
        }
    }
    return (u8)(sel | lo);
}

static u8 port_rd8(u8 p)
{
    if ((p >= 0x4Au && p <= 0x52u) || (p >= 0x80u && p <= 0x94u))
        audio_catch_up();
    switch (p) {
    case 0xA0: return S.io[0xA0];
    case 0xA8: return (u8)S.hblank_cnt;
    case 0xA9: return (u8)(S.hblank_cnt >> 8);
    case 0xAA: return (u8)S.vblank_cnt;
    case 0xAB: return (u8)(S.vblank_cnt >> 8);
    case 0xB3: return (u8)((S.io[0xB3] & 0xE0u) | 0x04u);   /* TX ready */
    case 0xB5: return read_keypad();
    case 0xBE: return 0x83u;                        /* Internal EEPROM ready */
    case 0xC8: return 0x83u;                        /* Cart EEPROM ready */
    case 0xCA: return (u8)(S.io[0xCA] | 0x80u);     /* RTC ready */
    case 0xCB: return 0x00u;
    }
    return S.io[p];
}

static void port_wr8(u8 p, u8 v)
{
    if (p >= 0x80u && p <= 0x94u)
        audio_catch_up();
    if (p >= 0x1Cu && p <= 0x3Fu)
        S.mono_pal_dirty = 1;

    switch (p) {
    case 0x02:                          /* IO_LCD_LINE is read-only */
        return;
    case 0x48:
        S.io[0x48] = v;
        if (v & 0x80u)
            run_gdma();
        return;
    case 0x4A: case 0x4B: case 0x4C:
        S.io[p] = v;
        S.sdma_src_reload = ((u32)(S.io[0x4C] & 0x0Fu) << 16) | S.io[0x4A] | ((u32)S.io[0x4B] << 8);
        return;
    case 0x4E: case 0x4F: case 0x50:
        S.io[p] = v;
        S.sdma_len_reload = ((u32)(S.io[0x50] & 0x0Fu) << 16) | S.io[0x4E] | ((u32)S.io[0x4F] << 8);
        return;
    case 0x52:
        audio_catch_up();
        S.io[0x52] = v;
        S.sdma_phase = 0;
        return;
    case 0x60:
        S.io[0x60] = v;
        update_seg_ptrs();
        return;
    case 0x8E:
        if (v & 0x08u) {
            S.noise_lfsr = 0;
            S.io[0x92] = S.io[0x93] = 0;
        }
        S.io[0x8E] = (u8)(v & ~0x08u);
        return;
    case 0xA0:
        S.io[0xA0] = (u8)((v & ~0x03u) | (S.is_wsc_cart ? 0x03u : 0x01u));
        update_seg_ptrs();
        return;
    case 0xA2:
        S.io[0xA2] = v;
        if (v & 0x01u)
            S.hblank_cnt = (u16)(S.io[0xA4] | ((u16)S.io[0xA5] << 8));
        if (v & 0x04u)
            S.vblank_cnt = (u16)(S.io[0xA6] | ((u16)S.io[0xA7] << 8));
        return;
    case 0xA4:
        S.io[0xA4] = v;
        S.hblank_cnt = (u16)((S.hblank_cnt & 0xFF00u) | v);
        return;
    case 0xA5:
        S.io[0xA5] = v;
        S.hblank_cnt = (u16)((S.hblank_cnt & 0x00FFu) | ((u16)v << 8));
        return;
    case 0xA6:
        S.io[0xA6] = v;
        S.vblank_cnt = (u16)((S.vblank_cnt & 0xFF00u) | v);
        return;
    case 0xA7:
        S.io[0xA7] = v;
        S.vblank_cnt = (u16)((S.vblank_cnt & 0x00FFu) | ((u16)v << 8));
        return;
    case 0xB3:
        S.io[0xB3] = v;
        if (v & 0x20u)
            S.io[0xB4] |= 0x01u;        /* Serial TX empty IRQ */
        else
            S.io[0xB4] &= (u8)~0x01u;
        return;
    case 0xB4:                          /* Read-only IRQ status */
        return;
    case 0xB6:                          /* IRQ acknowledge: clear 1 bits */
        S.io[0xB4] &= (u8)~v;
        return;
    case 0xBE:
        S.io[0xBE] = v;
        eeprom_exec(M->ieeprom, 0x3FFu, 0xBA, 0xBC, v, 0);
        return;
    case 0xC0: case 0xC2: case 0xC3:
        S.io[p] = v;
        update_seg_ptrs();
        return;
    case 0xC8:
        S.io[0xC8] = v;
        if (S.has_ceeprom && S.save_size >= 2)
            eeprom_exec(M->sram, (S.save_size >> 1) - 1u, 0xC4, 0xC6, v, 1);
        return;
    }
    S.io[p] = v;
}

static inline u16 port_rd16(u16 p)
{
    u8 lo = port_rd8((u8)p);
    u8 hi = port_rd8((u8)(p + 1u));
    return (u16)(lo | ((u16)hi << 8));
}

static inline void port_wr16(u16 p, u16 v)
{
    port_wr8((u8)p, (u8)v);
    port_wr8((u8)(p + 1u), (u8)(v >> 8));
}

/* ---- NEC V30MZ CPU helpers ---- */
static inline u8 *reg8_ptr(int r)
{
    /* AL, CL, DL, BL, AH, CH, DH, BH (little-endian host & MIPS32) */
    u8 *base = (u8 *)&S.reg[r & 3];
    return (r & 4) ? (base + 1) : base;
}

static inline u8 fetch8(void)
{
    u8 v = seg_rd8(S.sreg[S_CS], S.ip);
    S.ip++;
    return v;
}

static inline u16 fetch16(void)
{
    u16 v = seg_rd16(S.sreg[S_CS], S.ip);
    S.ip = (u16)(S.ip + 2u);
    return v;
}

static inline void push16(u16 v)
{
    S.reg[R_SP] = (u16)(S.reg[R_SP] - 2u);
    seg_wr16(S.sreg[S_SS], S.reg[R_SP], v);
}

static inline u16 pop16(void)
{
    u16 v = seg_rd16(S.sreg[S_SS], S.reg[R_SP]);
    S.reg[R_SP] = (u16)(S.reg[R_SP] + 2u);
    return v;
}

static inline void set_flags(u16 f)
{
    S.flags = (u16)((f & F_MASK) | F_FIXED_SET);
}

static inline void set_szp8(u8 r)
{
    S.flags = (u16)((S.flags & ~(FZ | FS | FP)) | (r == 0 ? FZ : 0) | (r & FS) | M->parity[r]);
}

static inline void set_szp16(u16 r)
{
    S.flags = (u16)((S.flags & ~(FZ | FS | FP)) | (r == 0 ? FZ : 0) | ((r >> 8) & FS) | M->parity[r & 0xFFu]);
}

static void cpu_int(u8 vec)
{
    S.halted = 0;
    push16((u16)((S.flags & F_MASK) | F_FIXED_SET));
    S.flags &= (u16)~(FI | FT);
    push16(S.sreg[S_CS]);
    push16(S.ip);
    S.ip = seg_rd16(0, (u16)((u16)vec * 4u));
    S.sreg[S_CS] = seg_rd16(0, (u16)((u16)vec * 4u + 2u));
    S.cycles += 32;
}

static u8 alu8(int op, u8 a, u8 b)
{
    u32 res;
    u32 cf = S.flags & FC;
    switch (op) {
    case 0: /* ADD */
        res = (u32)a + b;
        S.flags = (u16)((S.flags & ~(FC | FA | FO | FZ | FS | FP)) |
                        (res > 0xFFu ? FC : 0) |
                        (((a ^ b ^ res) & 0x10u) ? FA : 0) |
                        (((~(a ^ b) & (a ^ res)) & 0x80u) ? FO : 0));
        set_szp8((u8)res);
        return (u8)res;
    case 1: /* OR */
        res = a | b;
        S.flags &= (u16)~(FC | FA | FO);
        set_szp8((u8)res);
        return (u8)res;
    case 2: /* ADC */
        res = (u32)a + b + cf;
        S.flags = (u16)((S.flags & ~(FC | FA | FO | FZ | FS | FP)) |
                        (res > 0xFFu ? FC : 0) |
                        (((a ^ b ^ res) & 0x10u) ? FA : 0) |
                        (((~(a ^ b) & (a ^ res)) & 0x80u) ? FO : 0));
        set_szp8((u8)res);
        return (u8)res;
    case 3: /* SBB */
        res = (u32)a - b - cf;
        S.flags = (u16)((S.flags & ~(FC | FA | FO | FZ | FS | FP)) |
                        (res > 0xFFu ? FC : 0) |
                        (((a ^ b ^ res) & 0x10u) ? FA : 0) |
                        ((((a ^ b) & (a ^ res)) & 0x80u) ? FO : 0));
        set_szp8((u8)res);
        return (u8)res;
    case 4: /* AND */
        res = a & b;
        S.flags &= (u16)~(FC | FA | FO);
        set_szp8((u8)res);
        return (u8)res;
    case 5: /* SUB */
    case 7: /* CMP */
        res = (u32)a - b;
        S.flags = (u16)((S.flags & ~(FC | FA | FO | FZ | FS | FP)) |
                        (res > 0xFFu ? FC : 0) |
                        (((a ^ b ^ res) & 0x10u) ? FA : 0) |
                        ((((a ^ b) & (a ^ res)) & 0x80u) ? FO : 0));
        set_szp8((u8)res);
        return op == 7 ? a : (u8)res;
    default: /* XOR */
        res = a ^ b;
        S.flags &= (u16)~(FC | FA | FO);
        set_szp8((u8)res);
        return (u8)res;
    }
}

static u16 alu16(int op, u16 a, u16 b)
{
    u32 res;
    u32 cf = S.flags & FC;
    switch (op) {
    case 0:
        res = (u32)a + b;
        S.flags = (u16)((S.flags & ~(FC | FA | FO | FZ | FS | FP)) |
                        (res > 0xFFFFu ? FC : 0) |
                        (((a ^ b ^ res) & 0x10u) ? FA : 0) |
                        (((~(a ^ b) & (a ^ res)) & 0x8000u) ? FO : 0));
        set_szp16((u16)res);
        return (u16)res;
    case 1:
        res = a | b;
        S.flags &= (u16)~(FC | FA | FO);
        set_szp16((u16)res);
        return (u16)res;
    case 2:
        res = (u32)a + b + cf;
        S.flags = (u16)((S.flags & ~(FC | FA | FO | FZ | FS | FP)) |
                        (res > 0xFFFFu ? FC : 0) |
                        (((a ^ b ^ res) & 0x10u) ? FA : 0) |
                        (((~(a ^ b) & (a ^ res)) & 0x8000u) ? FO : 0));
        set_szp16((u16)res);
        return (u16)res;
    case 3:
        res = (u32)a - b - cf;
        S.flags = (u16)((S.flags & ~(FC | FA | FO | FZ | FS | FP)) |
                        (res > 0xFFFFu ? FC : 0) |
                        (((a ^ b ^ res) & 0x10u) ? FA : 0) |
                        ((((a ^ b) & (a ^ res)) & 0x8000u) ? FO : 0));
        set_szp16((u16)res);
        return (u16)res;
    case 4:
        res = a & b;
        S.flags &= (u16)~(FC | FA | FO);
        set_szp16((u16)res);
        return (u16)res;
    case 5:
    case 7:
        res = (u32)a - b;
        S.flags = (u16)((S.flags & ~(FC | FA | FO | FZ | FS | FP)) |
                        (res > 0xFFFFu ? FC : 0) |
                        (((a ^ b ^ res) & 0x10u) ? FA : 0) |
                        ((((a ^ b) & (a ^ res)) & 0x8000u) ? FO : 0));
        set_szp16((u16)res);
        return op == 7 ? a : (u16)res;
    default:
        res = a ^ b;
        S.flags &= (u16)~(FC | FA | FO);
        set_szp16((u16)res);
        return (u16)res;
    }
}

static u8 grp2_8(int op, u8 v, u8 cnt)
{
    cnt &= 0x1Fu;
    if (op == 6)                        /* V30MZ /6: clears operand, flags untouched */
        return 0;
    u32 cf = S.flags & FC;
    switch (op) {
    case 0: /* ROL */
        for (u8 i = 0; i < cnt; i++) { cf = (v >> 7) & 1u; v = (u8)((v << 1) | cf); }
        S.flags = (u16)((S.flags & ~(FC | FO)) | cf | ((((v >> 7) ^ cf) & 1u) ? FO : 0));
        return v;
    case 1: /* ROR */
        for (u8 i = 0; i < cnt; i++) { cf = v & 1u; v = (u8)((v >> 1) | (cf << 7)); }
        S.flags = (u16)((S.flags & ~(FC | FO)) | cf | ((((v >> 7) ^ (v >> 6)) & 1u) ? FO : 0));
        return v;
    case 2: /* RCL */
        for (u8 i = 0; i < cnt; i++) { u32 nc = (v >> 7) & 1u; v = (u8)((v << 1) | cf); cf = nc; }
        S.flags = (u16)((S.flags & ~(FC | FO)) | cf | ((((v >> 7) ^ cf) & 1u) ? FO : 0));
        return v;
    case 3: /* RCR */
        for (u8 i = 0; i < cnt; i++) { u32 nc = v & 1u; v = (u8)((v >> 1) | (cf << 7)); cf = nc; }
        S.flags = (u16)((S.flags & ~(FC | FO)) | cf | ((((v >> 7) ^ (v >> 6)) & 1u) ? FO : 0));
        return v;
    case 4: /* SHL */
        for (u8 i = 0; i < cnt; i++) { cf = (v >> 7) & 1u; v <<= 1; }
        S.flags = (u16)((S.flags & ~(FC | FA | FO)) | cf | ((((v >> 7) ^ cf) & 1u) ? FO : 0));
        set_szp8(v);
        return v;
    case 5: /* SHR */
        for (u8 i = 0; i < cnt; i++) { cf = v & 1u; v >>= 1; }
        S.flags = (u16)((S.flags & ~(FC | FA | FO)) | cf | ((((v >> 7) ^ (v >> 6)) & 1u) ? FO : 0));
        set_szp8(v);
        return v;
    default: /* SAR */
        for (u8 i = 0; i < cnt; i++) { cf = v & 1u; v = (u8)(((s8)v) >> 1); }
        S.flags = (u16)((S.flags & ~(FC | FA | FO)) | cf | ((((v >> 7) ^ (v >> 6)) & 1u) ? FO : 0));
        set_szp8(v);
        return v;
    }
}

static u16 grp2_16(int op, u16 v, u8 cnt)
{
    cnt &= 0x1Fu;
    if (op == 6)
        return 0;
    u32 cf = S.flags & FC;
    switch (op) {
    case 0:
        for (u8 i = 0; i < cnt; i++) { cf = (v >> 15) & 1u; v = (u16)((v << 1) | cf); }
        S.flags = (u16)((S.flags & ~(FC | FO)) | cf | ((((v >> 15) ^ cf) & 1u) ? FO : 0));
        return v;
    case 1:
        for (u8 i = 0; i < cnt; i++) { cf = v & 1u; v = (u16)((v >> 1) | (cf << 15)); }
        S.flags = (u16)((S.flags & ~(FC | FO)) | cf | ((((v >> 15) ^ (v >> 14)) & 1u) ? FO : 0));
        return v;
    case 2:
        for (u8 i = 0; i < cnt; i++) { u32 nc = (v >> 15) & 1u; v = (u16)((v << 1) | cf); cf = nc; }
        S.flags = (u16)((S.flags & ~(FC | FO)) | cf | ((((v >> 15) ^ cf) & 1u) ? FO : 0));
        return v;
    case 3:
        for (u8 i = 0; i < cnt; i++) { u32 nc = v & 1u; v = (u16)((v >> 1) | (cf << 15)); cf = nc; }
        S.flags = (u16)((S.flags & ~(FC | FO)) | cf | ((((v >> 15) ^ (v >> 14)) & 1u) ? FO : 0));
        return v;
    case 4:
        for (u8 i = 0; i < cnt; i++) { cf = (v >> 15) & 1u; v <<= 1; }
        S.flags = (u16)((S.flags & ~(FC | FA | FO)) | cf | ((((v >> 15) ^ cf) & 1u) ? FO : 0));
        set_szp16(v);
        return v;
    case 5:
        for (u8 i = 0; i < cnt; i++) { cf = v & 1u; v >>= 1; }
        S.flags = (u16)((S.flags & ~(FC | FA | FO)) | cf | ((((v >> 15) ^ (v >> 14)) & 1u) ? FO : 0));
        set_szp16(v);
        return v;
    default:
        for (u8 i = 0; i < cnt; i++) { cf = v & 1u; v = (u16)(((s16)v) >> 1); }
        S.flags = (u16)((S.flags & ~(FC | FA | FO)) | cf | ((((v >> 15) ^ (v >> 14)) & 1u) ? FO : 0));
        set_szp16(v);
        return v;
    }
}

/* ModR/M decoder (including V30MZ's undocumented mod==3 addressing modes for LEA/LES/LDS/CALL far/JMP far!) */
struct ea_info {
    u8 mod, reg, rm;
    u16 seg, off;
};

static struct ea_info decode_modrm(int seg_ovr, int force_mem_mod3)
{
    struct ea_info e;
    u8 m = fetch8();
    e.mod = (m >> 6) & 3u;
    e.reg = (m >> 3) & 7u;
    e.rm = m & 7u;
    e.seg = 0;
    e.off = 0;

    if (e.mod == 3 && !force_mem_mod3)
        return e;

    int def_seg = S_DS;
    if (e.mod == 3) {                   /* V30MZ undocumented mod==3 memory EA! */
        switch (e.rm) {
        case 0: e.off = (u16)(S.reg[R_BX] + S.reg[R_AX]); break;
        case 1: e.off = (u16)(S.reg[R_BX] + S.reg[R_CX]); break;
        case 2: e.off = (u16)(S.reg[R_BP] + S.reg[R_DX]); def_seg = S_SS; break;
        case 3: e.off = (u16)(S.reg[R_BP] + S.reg[R_BX]); def_seg = S_SS; break;
        case 4: e.off = (u16)(S.reg[R_SI] + S.reg[R_SP]); break;
        case 5: e.off = (u16)(S.reg[R_DI] + S.reg[R_BP]); break;
        case 6: e.off = (u16)(S.reg[R_BP] + S.reg[R_SI]); def_seg = S_SS; break;
        default:e.off = (u16)(S.reg[R_BX] + S.reg[R_DI]); break;
        }
        e.seg = S.sreg[seg_ovr >= 0 ? seg_ovr : def_seg];
        e.mod = 0;                      /* treat as memory */
        return e;
    }

    if (e.mod == 0 && e.rm == 6) {
        e.off = fetch16();
    } else {
        switch (e.rm) {
        case 0: e.off = (u16)(S.reg[R_BX] + S.reg[R_SI]); break;
        case 1: e.off = (u16)(S.reg[R_BX] + S.reg[R_DI]); break;
        case 2: e.off = (u16)(S.reg[R_BP] + S.reg[R_SI]); def_seg = S_SS; break;
        case 3: e.off = (u16)(S.reg[R_BP] + S.reg[R_DI]); def_seg = S_SS; break;
        case 4: e.off = S.reg[R_SI]; break;
        case 5: e.off = S.reg[R_DI]; break;
        case 6: e.off = S.reg[R_BP]; def_seg = S_SS; break;
        default:e.off = S.reg[R_BX]; break;
        }
        if (e.mod == 1)
            e.off = (u16)(e.off + (s16)(s8)fetch8());
        else if (e.mod == 2)
            e.off = (u16)(e.off + fetch16());
    }
    e.seg = S.sreg[seg_ovr >= 0 ? seg_ovr : def_seg];
    return e;
}

static inline u8 ea_rd8(const struct ea_info *e)
{
    return e->mod == 3 ? *reg8_ptr(e->rm) : seg_rd8(e->seg, e->off);
}

static inline void ea_wr8(const struct ea_info *e, u8 v)
{
    if (e->mod == 3) *reg8_ptr(e->rm) = v;
    else             seg_wr8(e->seg, e->off, v);
}

static inline u16 ea_rd16(const struct ea_info *e)
{
    return e->mod == 3 ? S.reg[e->rm] : seg_rd16(e->seg, e->off);
}

static inline void ea_wr16(const struct ea_info *e, u16 v)
{
    if (e->mod == 3) S.reg[e->rm] = v;
    else             seg_wr16(e->seg, e->off, v);
}

static void do_daa(void)
{
    u8 al = *reg8_ptr(0);
    u8 old_al = al;
    u16 cf = S.flags & FC;
    u16 af = S.flags & FA;
    u8 add_val = 0;
    if ((al & 0x0Fu) > 9u || af) {
        add_val += 0x06u;
        af = FA;
    }
    if (old_al > 0x99u || cf) {
        add_val += 0x60u;
        cf = FC;
    }
    /* V30MZ DAA: all flags as normal ADD(old_al, add_val) except AF and CF are never cleared */
    u8 res = alu8(0, old_al, add_val);
    *reg8_ptr(0) = res;
    S.flags |= (u16)(cf | af);
}

static void do_das(void)
{
    u8 old_al = *reg8_ptr(0);
    u16 cf = S.flags & FC;
    u16 af = S.flags & FA;
    u8 sub_val = 0;
    if (old_al > 0x99u || cf) {
        sub_val += 0x60u;
        cf = FC;
    }
    if ((old_al & 0x0Fu) > 9u || af) {
        sub_val += 0x06u;
        af = FA;
    }
    /* V30MZ DAS: S, Z, P, V from subtraction old_al - sub_val; AF & CF only from comparison */
    u8 res = alu8(5, old_al, sub_val);
    *reg8_ptr(0) = res;
    S.flags = (u16)((S.flags & ~(FC | FA)) | cf | af);
}

static void do_aaa_aas(int is_sub)
{
    u8 *al = reg8_ptr(0), *ah = reg8_ptr(4);
    int adj = ((S.flags & FA) != 0) || ((*al & 0x0Fu) > 9u);
    if (adj) {
        if (is_sub) { *al = (u8)(*al - 6u); (*ah)--; }
        else        { *al = (u8)(*al + 6u); (*ah)++; }
        S.flags = (u16)((S.flags & ~(FO | FS)) | FA | FC | FZ | FP);
    } else {
        S.flags = (u16)((S.flags & ~(FO | FA | FC | FZ)) | FS | FP);
    }
    *al &= 0x0Fu;
}

static void do_mul8(u8 rhs, int is_signed)
{
    u8 lhs = *reg8_ptr(0);
    u16 co;
    if (is_signed) {
        s16 prod = (s16)(s8)lhs * (s16)(s8)rhs;
        S.reg[R_AX] = (u16)prod;
        co = (prod < -128 || prod > 127) ? (FC | FO) : 0;
    } else {
        u16 prod = (u16)lhs * (u16)rhs;
        S.reg[R_AX] = prod;
        co = (prod > 0xFFu) ? (FC | FO) : 0;
    }
    S.last_mul_co = co;
    /* SPHINX (WSC): ZF always set (signed & unsigned); ASWAN (Mono): ZF set on signed, cleared on unsigned */
    u16 zf = (is_signed || S.is_wsc_cart) ? FZ : 0;
    S.flags = (u16)((S.flags & ~(FA | FP | FS | FZ | FC | FO)) | zf | co);
}

static u16 do_mul16_core(u16 lhs, u16 rhs, int is_signed, int write_dx_ax)
{
    u16 co;
    u32 uprod;
    if (is_signed) {
        s32 sprod = (s32)(s16)lhs * (s32)(s16)rhs;
        uprod = (u32)sprod;
        co = (sprod < -32768 || sprod > 32767) ? (FC | FO) : 0;
    } else {
        uprod = (u32)lhs * (u32)rhs;
        co = (uprod > 0xFFFFu) ? (FC | FO) : 0;
    }
    if (write_dx_ax) {
        S.reg[R_AX] = (u16)uprod;
        S.reg[R_DX] = (u16)(uprod >> 16);
    }
    S.last_mul_co = co;
    u16 zf = (is_signed || S.is_wsc_cart) ? FZ : 0;
    S.flags = (u16)((S.flags & ~(FA | FP | FS | FZ | FC | FO)) | zf | co);
    return (u16)uprod;
}

static void do_div8(u8 d)
{
    u16 num = S.reg[R_AX];
    if (d == 0 || (num >> 8) >= d) {
        u16 zf;
        if (d == 0) {
            zf = (num & 0x3FC0u) == 0 ? FZ : 0;
        } else {
            u32 t1 = ((u32)num + ((0x100u - d) << 6)) & 0xFFC0u;
            u32 t2 = ((u32)num + (((0x100u - d) * 3u) << 6)) & 0xFFC0u;
            zf = (t1 == 0 || t2 == 0) ? FZ : 0;
        }
        S.flags = (u16)((S.flags & ~(FA | FP | FS | FZ | FC | FO)) | S.last_mul_co | zf);
        cpu_int(0);
        return;
    }
    u8 q = (u8)(num / d);
    u8 r = (u8)(num % d);
    S.reg[R_AX] = (u16)(((u16)r << 8) | q);
    u16 zf = (r == 0 && (q & 1u)) ? FZ : 0;
    S.flags = (u16)((S.flags & ~(FA | FP | FS | FZ | FC | FO)) | S.last_mul_co | zf);
}

static void do_div16(u16 d)
{
    u32 num = ((u32)S.reg[R_DX] << 16) | S.reg[R_AX];
    if (d == 0 || S.reg[R_DX] >= d) {
        u16 zf;
        if (d == 0) {
            zf = (num & 0x3FFFC000u) == 0 ? FZ : 0;
        } else {
            u32 t1 = (num + ((0x10000u - d) << 14)) & 0xFFFFC000u;
            u32 t2 = (num + (((0x10000u - d) * 3u) << 14)) & 0xFFFFC000u;
            zf = (t1 == 0 || t2 == 0) ? FZ : 0;
        }
        S.flags = (u16)((S.flags & ~(FA | FP | FS | FZ | FC | FO)) | zf);
        cpu_int(0);
        return;
    }
    u16 q = (u16)(num / d);
    u16 r = (u16)(num % d);
    S.reg[R_AX] = q;
    S.reg[R_DX] = r;
    u16 zf = (r == 0 && (q & 1u)) ? FZ : 0;
    S.flags = (u16)((S.flags & ~(FA | FP | FS | FZ | FC | FO)) | zf);
}

static void do_idiv8(u8 d_raw)
{
    u16 num_u = S.reg[R_AX];
    if (num_u == 0x8000u && d_raw == 0) {
        S.reg[R_AX] = 0x0081u;
        S.flags &= (u16)~(FA | FC | FO);
        set_szp8(0x81u);
        return;
    }
    if (d_raw == 0) {
        S.flags = (u16)((S.flags & ~(FA | FP | FS | FZ | FC | FO)) | S.last_mul_co);
        cpu_int(0);
        return;
    }
    u32 abs_n = (num_u & 0x8000u) ? (0x10000u - num_u) : num_u;
    u32 abs_d = (d_raw & 0x80u) ? (0x100u - d_raw) : d_raw;
    if (abs_n >= (abs_d << 7)) {
        S.flags = (u16)((S.flags & ~(FA | FP | FS | FZ | FC | FO)) | S.last_mul_co);
        cpu_int(0);
        return;
    }
    u32 uq = abs_n / abs_d;
    u32 ur = abs_n % abs_d;
    s8 q = ((num_u >> 8) ^ d_raw) & 0x80u ? (s8)-(s32)uq : (s8)uq;
    s8 r = (num_u & 0x8000u) ? (s8)-(s32)ur : (s8)ur;
    S.reg[R_AX] = (u16)(((u16)(u8)r << 8) | (u8)q);
    S.flags &= (u16)~(FA | FC | FO);
    set_szp8((u8)q);
}

static void do_idiv16(u16 d_raw)
{
    u32 num_u = ((u32)S.reg[R_DX] << 16) | S.reg[R_AX];
    if (num_u == 0x80000000u && d_raw == 0) {
        S.reg[R_AX] = 0x8001u;
        S.reg[R_DX] = 0x0000u;
        S.flags = (u16)((S.flags & ~(FA | FP | FS | FC | FO)) | FZ);
        return;
    }
    if (d_raw == 0) {
        S.flags &= (u16)~(FA | FP | FS | FZ | FC | FO);
        cpu_int(0);
        return;
    }
    u32 abs_n = (num_u & 0x80000000u) ? (0u - num_u) : num_u;
    u32 abs_d = (d_raw & 0x8000u) ? (0x10000u - d_raw) : d_raw;
    if (abs_n >= (abs_d << 15)) {
        S.flags &= (u16)~(FA | FP | FS | FZ | FC | FO);
        cpu_int(0);
        return;
    }
    u32 uq = abs_n / abs_d;
    u32 ur = abs_n % abs_d;
    u16 q = (((num_u >> 16) ^ d_raw) & 0x8000u) ? (u16)(0u - uq) : (u16)uq;
    u16 r = (num_u & 0x80000000u) ? (u16)(0u - ur) : (u16)ur;
    S.reg[R_AX] = q;
    S.reg[R_DX] = r;
    u16 zf = (r == 0 && (q & 1u)) ? FZ : 0;
    S.flags = (u16)((S.flags & ~(FA | FP | FS | FZ | FC | FO)) | zf);
}

static int cond_true(u8 cc)
{
    u16 f = S.flags;
    switch (cc & 0x0Fu) {
    case 0x0: return (f & FO) != 0;
    case 0x1: return (f & FO) == 0;
    case 0x2: return (f & FC) != 0;
    case 0x3: return (f & FC) == 0;
    case 0x4: return (f & FZ) != 0;
    case 0x5: return (f & FZ) == 0;
    case 0x6: return (f & (FC | FZ)) != 0;
    case 0x7: return (f & (FC | FZ)) == 0;
    case 0x8: return (f & FS) != 0;
    case 0x9: return (f & FS) == 0;
    case 0xA: return (f & FP) != 0;
    case 0xB: return (f & FP) == 0;
    case 0xC: return (((f & FS) != 0) != ((f & FO) != 0));
    case 0xD: return (((f & FS) != 0) == ((f & FO) != 0));
    case 0xE: return ((f & FZ) != 0) || (((f & FS) != 0) != ((f & FO) != 0));
    default:  return ((f & FZ) == 0) && (((f & FS) != 0) == ((f & FO) != 0));
    }
}

/* Execute one V30MZ instruction (accumulating cycles into S.cycles) */
static void cpu_step(void)
{
    if (S.halted) {
        S.cycles += 4;
        return;
    }

    int trap_before = (S.flags & FT) != 0;
    int inhibit_ss = 0;
    int seg_ovr = -1;
    int rep = 0;                        /* 0 = none, 1 = REPNZ (F2), 2 = REP/REPZ (F3) */
    u16 start_ip = S.ip;

    u8 op;
    for (;;) {
        op = fetch8();
        if (op == 0x26)      { seg_ovr = S_ES; S.cycles += 1; }
        else if (op == 0x2E) { seg_ovr = S_CS; S.cycles += 1; }
        else if (op == 0x36) { seg_ovr = S_SS; S.cycles += 1; }
        else if (op == 0x3E) { seg_ovr = S_DS; S.cycles += 1; }
        else if (op == 0xF0) { S.cycles += 1; }                 /* LOCK */
        else if (op == 0xF2) { rep = 1; S.cycles += 1; }        /* REPNZ */
        else if (op == 0xF3) { rep = 2; S.cycles += 1; }        /* REP/REPZ */
        else break;
    }

    /* String instructions (6C..6F, A4..A7, AA..AF) */
    if ((op >= 0x6Cu && op <= 0x6Fu) || (op >= 0xA4u && op <= 0xA7u) || (op >= 0xAAu && op <= 0xAFu)) {
        int step = (op & 1u) ? ((S.flags & FD) ? -2 : 2) : ((S.flags & FD) ? -1 : 1);
        u16 src_seg = S.sreg[seg_ovr >= 0 ? seg_ovr : S_DS];
        u16 es = S.sreg[S_ES];
        if (rep && S.reg[R_CX] == 0) {
            S.cycles += 4;
            goto after_step;
        }
        /* Perform one element (if REP continues and an IRQ is pending/budget reached, rewind IP to start_ip!) */
        for (;;) {
            switch (op) {
            case 0x6C: /* INSB */
                seg_wr8(es, S.reg[R_DI], port_rd8((u8)S.reg[R_DX]));
                S.reg[R_DI] = (u16)(S.reg[R_DI] + step);
                S.cycles += 6;
                break;
            case 0x6D: /* INSW */
                seg_wr16(es, S.reg[R_DI], port_rd16(S.reg[R_DX]));
                S.reg[R_DI] = (u16)(S.reg[R_DI] + step);
                S.cycles += 6;
                break;
            case 0x6E: /* OUTSB */
                port_wr8((u8)S.reg[R_DX], seg_rd8(src_seg, S.reg[R_SI]));
                S.reg[R_SI] = (u16)(S.reg[R_SI] + step);
                S.cycles += 6;
                break;
            case 0x6F: /* OUTSW */
                port_wr16(S.reg[R_DX], seg_rd16(src_seg, S.reg[R_SI]));
                S.reg[R_SI] = (u16)(S.reg[R_SI] + step);
                S.cycles += 6;
                break;
            case 0xA4: /* MOVSB */
                seg_wr8(es, S.reg[R_DI], seg_rd8(src_seg, S.reg[R_SI]));
                S.reg[R_SI] = (u16)(S.reg[R_SI] + step);
                S.reg[R_DI] = (u16)(S.reg[R_DI] + step);
                S.cycles += 5;
                break;
            case 0xA5: /* MOVSW */
                seg_wr16(es, S.reg[R_DI], seg_rd16(src_seg, S.reg[R_SI]));
                S.reg[R_SI] = (u16)(S.reg[R_SI] + step);
                S.reg[R_DI] = (u16)(S.reg[R_DI] + step);
                S.cycles += 5;
                break;
            case 0xA6: /* CMPSB */
                (void)alu8(7, seg_rd8(src_seg, S.reg[R_SI]), seg_rd8(es, S.reg[R_DI]));
                S.reg[R_SI] = (u16)(S.reg[R_SI] + step);
                S.reg[R_DI] = (u16)(S.reg[R_DI] + step);
                S.cycles += 6;
                break;
            case 0xA7: /* CMPSW */
                (void)alu16(7, seg_rd16(src_seg, S.reg[R_SI]), seg_rd16(es, S.reg[R_DI]));
                S.reg[R_SI] = (u16)(S.reg[R_SI] + step);
                S.reg[R_DI] = (u16)(S.reg[R_DI] + step);
                S.cycles += 6;
                break;
            case 0xAA: /* STOSB */
                seg_wr8(es, S.reg[R_DI], *reg8_ptr(0));
                S.reg[R_DI] = (u16)(S.reg[R_DI] + step);
                S.cycles += 3;
                break;
            case 0xAB: /* STOSW */
                seg_wr16(es, S.reg[R_DI], S.reg[R_AX]);
                S.reg[R_DI] = (u16)(S.reg[R_DI] + step);
                S.cycles += 3;
                break;
            case 0xAC: /* LODSB */
                *reg8_ptr(0) = seg_rd8(src_seg, S.reg[R_SI]);
                S.reg[R_SI] = (u16)(S.reg[R_SI] + step);
                S.cycles += 3;
                break;
            case 0xAD: /* LODSW */
                S.reg[R_AX] = seg_rd16(src_seg, S.reg[R_SI]);
                S.reg[R_SI] = (u16)(S.reg[R_SI] + step);
                S.cycles += 3;
                break;
            case 0xAE: /* SCASB */
                (void)alu8(7, *reg8_ptr(0), seg_rd8(es, S.reg[R_DI]));
                S.reg[R_DI] = (u16)(S.reg[R_DI] + step);
                S.cycles += 4;
                break;
            default:   /* SCASW */
                (void)alu16(7, S.reg[R_AX], seg_rd16(es, S.reg[R_DI]));
                S.reg[R_DI] = (u16)(S.reg[R_DI] + step);
                S.cycles += 4;
                break;
            }
            if (!rep)
                break;
            S.reg[R_CX]--;
            if (S.reg[R_CX] == 0)
                break;
            if (op == 0xA6 || op == 0xA7 || op == 0xAE || op == 0xAF) {
                int z = (S.flags & FZ) != 0;
                if ((rep == 2 && !z) || (rep == 1 && z))
                    break;
            }
            if (trap_before || ((S.flags & FI) && (S.io[0xB4] & S.io[0xB2]))) {
                S.ip = start_ip;        /* V30MZ resumes full prefix sequence after IRQ/TF */
                break;
            }
        }
        goto after_step;
    }

    /* Standard ALU group 0x00..0x3F (except segment prefixes & PUSH/POP/DAA/DAS/AAA/AAS) */
    if ((op & 0xC4u) == 0x00u) {
        int aop = (op >> 3) & 7;
        struct ea_info e = decode_modrm(seg_ovr, 0);
        S.cycles += (e.mod == 3) ? 1 : 3;
        switch (op & 3u) {
        case 0: { u8 r = alu8(aop, ea_rd8(&e), *reg8_ptr(e.reg)); if (aop != 7) ea_wr8(&e, r); break; }
        case 1: { u16 r = alu16(aop, ea_rd16(&e), S.reg[e.reg]);  if (aop != 7) ea_wr16(&e, r); break; }
        case 2: { u8 r = alu8(aop, *reg8_ptr(e.reg), ea_rd8(&e)); if (aop != 7) *reg8_ptr(e.reg) = r; break; }
        case 3: { u16 r = alu16(aop, S.reg[e.reg], ea_rd16(&e));  if (aop != 7) S.reg[e.reg] = r; break; }
        }
        goto after_step;
    }
    if ((op & 0xC6u) == 0x04u) {
        int aop = (op >> 3) & 7;
        S.cycles += 1;
        if (op & 1u) {
            u16 r = alu16(aop, S.reg[R_AX], fetch16());
            if (aop != 7) S.reg[R_AX] = r;
        } else {
            u8 r = alu8(aop, *reg8_ptr(0), fetch8());
            if (aop != 7) *reg8_ptr(0) = r;
        }
        goto after_step;
    }

    /* Jcc short 0x70..0x7F */
    if ((op & 0xF0u) == 0x70u) {
        s8 disp = (s8)fetch8();
        if (cond_true(op & 0x0Fu)) {
            S.ip = (u16)(S.ip + disp);
            S.cycles += 4;
        } else {
            S.cycles += 1;
        }
        goto after_step;
    }

    /* INC/DEC reg16 (0x40..0x4F), PUSH/POP reg16 (0x50..0x5F), XCHG AX,reg16 (0x90..0x97), MOV reg,imm (0xB0..0xBF) */
    if ((op & 0xF8u) == 0x40u) {
        u16 cf = S.flags & FC;
        S.reg[op & 7u] = alu16(0, S.reg[op & 7u], 1);
        S.flags = (u16)((S.flags & ~FC) | cf);
        S.cycles += 1;
        goto after_step;
    }
    if ((op & 0xF8u) == 0x48u) {
        u16 cf = S.flags & FC;
        S.reg[op & 7u] = alu16(5, S.reg[op & 7u], 1);
        S.flags = (u16)((S.flags & ~FC) | cf);
        S.cycles += 1;
        goto after_step;
    }
    if ((op & 0xF8u) == 0x50u) {
        int r = op & 7;
        if (r == R_SP) {                /* V30MZ PUSH SP: SP -= 2; [SS:SP] = new SP */
            S.reg[R_SP] = (u16)(S.reg[R_SP] - 2u);
            seg_wr16(S.sreg[S_SS], S.reg[R_SP], S.reg[R_SP]);
        } else {
            push16(S.reg[r]);
        }
        S.cycles += 1;
        goto after_step;
    }
    if ((op & 0xF8u) == 0x58u) {
        S.reg[op & 7u] = pop16();
        S.cycles += 1;
        goto after_step;
    }
    if ((op & 0xF8u) == 0x90u) {
        int r = op & 7;
        u16 t = S.reg[R_AX];
        S.reg[R_AX] = S.reg[r];
        S.reg[r] = t;
        S.cycles += (r == 0) ? 1 : 3;
        goto after_step;
    }
    if ((op & 0xF8u) == 0xB0u) {
        *reg8_ptr(op & 7) = fetch8();
        S.cycles += 1;
        goto after_step;
    }
    if ((op & 0xF8u) == 0xB8u) {
        S.reg[op & 7u] = fetch16();
        S.cycles += 1;
        goto after_step;
    }

    switch (op) {
    case 0x06: push16(S.sreg[S_ES]); S.cycles += 2; break;
    case 0x07: S.sreg[S_ES] = pop16(); S.cycles += 2; break;
    case 0x0E: push16(S.sreg[S_CS]); S.cycles += 2; break;
    case 0x0F: S.cycles += 1; break;    /* V30MZ: 0x0F is a 1-byte NOP! */
    case 0x16: push16(S.sreg[S_SS]); S.cycles += 2; break;
    case 0x17: S.sreg[S_SS] = pop16(); inhibit_ss = 1; S.cycles += 2; break;
    case 0x1E: push16(S.sreg[S_DS]); S.cycles += 2; break;
    case 0x1F: S.sreg[S_DS] = pop16(); S.cycles += 2; break;

    case 0x27: do_daa(); S.cycles += 10; break;
    case 0x2F: do_das(); S.cycles += 10; break;
    case 0x37: do_aaa_aas(0); S.cycles += 9; break;
    case 0x3F: do_aaa_aas(1); S.cycles += 9; break;

    case 0x60: {                        /* PUSHA */
        u16 old_sp = S.reg[R_SP];
        push16(S.reg[R_AX]); push16(S.reg[R_CX]); push16(S.reg[R_DX]); push16(S.reg[R_BX]);
        push16(old_sp);      push16(S.reg[R_BP]); push16(S.reg[R_SI]); push16(S.reg[R_DI]);
        S.cycles += 9;
        break;
    }
    case 0x61:                          /* POPA */
        S.reg[R_DI] = pop16(); S.reg[R_SI] = pop16(); S.reg[R_BP] = pop16();
        (void)pop16();                  /* skip SP */
        S.reg[R_BX] = pop16(); S.reg[R_DX] = pop16(); S.reg[R_CX] = pop16(); S.reg[R_AX] = pop16();
        S.cycles += 8;
        break;
    case 0x62: {                        /* BOUND reg16, mem32 */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        S.cycles += 13;
        if (e.mod != 3) {
            s16 val = (s16)S.reg[e.reg];
            s16 lo = (s16)seg_rd16(e.seg, e.off);
            s16 hi = (s16)seg_rd16(e.seg, (u16)(e.off + 2u));
            if (val < lo || val > hi)
                cpu_int(5);
        }
        break;
    }
    case 0x63: case 0x64: case 0x65: case 0x66: case 0x67:
        S.cycles += 1;                  /* V30MZ: 1-byte NOPs */
        break;
    case 0x68: push16(fetch16()); S.cycles += 1; break;
    case 0x6A: push16((u16)(s16)(s8)fetch8()); S.cycles += 1; break;
    case 0x69: {                        /* IMUL r16, rm16, imm16 */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        u16 v = ea_rd16(&e);
        u16 imm = fetch16();
        S.reg[e.reg] = do_mul16_core(v, imm, 1, 0);
        S.cycles += 4;
        break;
    }
    case 0x6B: {                        /* IMUL r16, rm16, imm8 */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        u16 v = ea_rd16(&e);
        u16 imm = (u16)(s16)(s8)fetch8();
        S.reg[e.reg] = do_mul16_core(v, imm, 1, 0);
        S.cycles += 4;
        break;
    }

    case 0x80: case 0x82: {             /* GRP1 rm8, imm8 */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        u8 v = ea_rd8(&e), imm = fetch8();
        u8 r = alu8(e.reg, v, imm);
        if (e.reg != 7) ea_wr8(&e, r);
        S.cycles += (e.mod == 3) ? 1 : 3;
        break;
    }
    case 0x81: {                        /* GRP1 rm16, imm16 */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        u16 v = ea_rd16(&e), imm = fetch16();
        u16 r = alu16(e.reg, v, imm);
        if (e.reg != 7) ea_wr16(&e, r);
        S.cycles += (e.mod == 3) ? 1 : 3;
        break;
    }
    case 0x83: {                        /* GRP1 rm16, sign_ext(imm8) */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        u16 v = ea_rd16(&e), imm = (u16)(s16)(s8)fetch8();
        u16 r = alu16(e.reg, v, imm);
        if (e.reg != 7) ea_wr16(&e, r);
        S.cycles += (e.mod == 3) ? 1 : 3;
        break;
    }
    case 0x84: {                        /* TEST rm8, r8 */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        (void)alu8(4, ea_rd8(&e), *reg8_ptr(e.reg));
        S.cycles += (e.mod == 3) ? 1 : 2;
        break;
    }
    case 0x85: {                        /* TEST rm16, r16 */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        (void)alu16(4, ea_rd16(&e), S.reg[e.reg]);
        S.cycles += (e.mod == 3) ? 1 : 2;
        break;
    }
    case 0x86: {                        /* XCHG rm8, r8 */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        u8 *rp = reg8_ptr(e.reg);
        u8 t = ea_rd8(&e);
        ea_wr8(&e, *rp);
        *rp = t;
        S.cycles += (e.mod == 3) ? 3 : 5;
        break;
    }
    case 0x87: {                        /* XCHG rm16, r16 */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        u16 t = ea_rd16(&e);
        ea_wr16(&e, S.reg[e.reg]);
        S.reg[e.reg] = t;
        S.cycles += (e.mod == 3) ? 3 : 5;
        break;
    }
    case 0x88: { struct ea_info e = decode_modrm(seg_ovr, 0); ea_wr8(&e, *reg8_ptr(e.reg)); S.cycles += 1; break; }
    case 0x89: { struct ea_info e = decode_modrm(seg_ovr, 0); ea_wr16(&e, S.reg[e.reg]); S.cycles += 1; break; }
    case 0x8A: { struct ea_info e = decode_modrm(seg_ovr, 0); *reg8_ptr(e.reg) = ea_rd8(&e); S.cycles += 1; break; }
    case 0x8B: { struct ea_info e = decode_modrm(seg_ovr, 0); S.reg[e.reg] = ea_rd16(&e); S.cycles += 1; break; }
    case 0x8C: {                        /* MOV rm16, sreg (bit 5 of modrm ignored on V30MZ: e.reg & 3) */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        ea_wr16(&e, S.sreg[e.reg & 3u]);
        S.cycles += 2;
        break;
    }
    case 0x8D: {                        /* LEA r16, mem (supports V30MZ mod==3 custom EA!) */
        struct ea_info e = decode_modrm(seg_ovr, 1);
        S.reg[e.reg] = e.off;
        S.cycles += 1;
        break;
    }
    case 0x8E: {                        /* MOV sreg, rm16 */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        int sr = e.reg & 3;
        u16 v = ea_rd16(&e);
        S.sreg[sr] = v;
        if (sr == S_SS)
            inhibit_ss = 1;
        S.cycles += 2;
        break;
    }
    case 0x8F: {                        /* POP rm16 */
        u16 v = pop16();
        struct ea_info e = decode_modrm(seg_ovr, 0);
        ea_wr16(&e, v);
        S.cycles += 2;
        break;
    }

    case 0x98:                          /* CBW */
        S.reg[R_AX] = (u16)(s16)(s8)*reg8_ptr(0);
        S.cycles += 1;
        break;
    case 0x99:                          /* CWD */
        S.reg[R_DX] = (S.reg[R_AX] & 0x8000u) ? 0xFFFFu : 0x0000u;
        S.cycles += 1;
        break;
    case 0x9A: {                        /* CALL far ptr16:16 */
        u16 new_ip = fetch16();
        u16 new_cs = fetch16();
        push16(S.sreg[S_CS]);
        push16(S.ip);
        S.ip = new_ip;
        S.sreg[S_CS] = new_cs;
        S.cycles += 10;
        break;
    }
    case 0x9B: S.cycles += 9; break;    /* WAIT/POLL: 1-byte NOP on WonderSwan */
    case 0x9C: push16((u16)((S.flags & F_MASK) | F_FIXED_SET)); S.cycles += 2; break;
    case 0x9D: set_flags(pop16()); S.cycles += 3; break;
    case 0x9E:                          /* SAHF */
        set_flags((u16)((S.flags & 0xFF00u) | *reg8_ptr(4)));
        S.cycles += 2;
        break;
    case 0x9F:                          /* LAHF */
        *reg8_ptr(4) = (u8)((S.flags & 0xD5u) | 0x02u);
        S.cycles += 2;
        break;

    case 0xA0: { u16 s = S.sreg[seg_ovr >= 0 ? seg_ovr : S_DS]; *reg8_ptr(0) = seg_rd8(s, fetch16()); S.cycles += 1; break; }
    case 0xA1: { u16 s = S.sreg[seg_ovr >= 0 ? seg_ovr : S_DS]; S.reg[R_AX] = seg_rd16(s, fetch16()); S.cycles += 1; break; }
    case 0xA2: { u16 s = S.sreg[seg_ovr >= 0 ? seg_ovr : S_DS]; seg_wr8(s, fetch16(), *reg8_ptr(0)); S.cycles += 1; break; }
    case 0xA3: { u16 s = S.sreg[seg_ovr >= 0 ? seg_ovr : S_DS]; seg_wr16(s, fetch16(), S.reg[R_AX]); S.cycles += 1; break; }
    case 0xA8: (void)alu8(4, *reg8_ptr(0), fetch8()); S.cycles += 1; break;
    case 0xA9: (void)alu16(4, S.reg[R_AX], fetch16()); S.cycles += 1; break;

    case 0xC0: {                        /* GRP2 rm8, imm8 */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        u8 cnt = fetch8();
        ea_wr8(&e, grp2_8(e.reg, ea_rd8(&e), cnt));
        S.cycles += 3;
        break;
    }
    case 0xC1: {                        /* GRP2 rm16, imm8 */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        u8 cnt = fetch8();
        ea_wr16(&e, grp2_16(e.reg, ea_rd16(&e), cnt));
        S.cycles += 3;
        break;
    }
    case 0xC2: { u16 n = fetch16(); S.ip = pop16(); S.reg[R_SP] = (u16)(S.reg[R_SP] + n); S.cycles += 6; break; }
    case 0xC3: S.ip = pop16(); S.cycles += 6; break;
    case 0xC4:                          /* LES r16, m16:16 (supports V30MZ mod==3 EA!) */
    case 0xC5: {                        /* LDS r16, m16:16 */
        struct ea_info e = decode_modrm(seg_ovr, 1);
        u16 off = seg_rd16(e.seg, e.off);
        u16 seg = seg_rd16(e.seg, (u16)(e.off + 2u));
        S.reg[e.reg] = off;
        S.sreg[op == 0xC4 ? S_ES : S_DS] = seg;
        S.cycles += 6;
        break;
    }
    case 0xC6: { struct ea_info e = decode_modrm(seg_ovr, 0); ea_wr8(&e, fetch8()); S.cycles += 2; break; }
    case 0xC7: { struct ea_info e = decode_modrm(seg_ovr, 0); ea_wr16(&e, fetch16()); S.cycles += 2; break; }
    case 0xC8: {                        /* ENTER imm16, imm8 */
        u16 alloc = fetch16();
        u8 lvl = fetch8() & 31u;
        push16(S.reg[R_BP]);
        u16 frame = S.reg[R_SP];
        if (lvl > 0) {
            for (u8 i = 1; i < lvl; i++) {
                S.reg[R_BP] = (u16)(S.reg[R_BP] - 2u);
                push16(seg_rd16(S.sreg[S_SS], S.reg[R_BP]));
            }
            push16(frame);
        }
        S.reg[R_BP] = frame;
        S.reg[R_SP] = (u16)(S.reg[R_SP] - alloc);
        S.cycles += 8 + lvl * 4;
        break;
    }
    case 0xC9:                          /* LEAVE */
        S.reg[R_SP] = S.reg[R_BP];
        S.reg[R_BP] = pop16();
        S.cycles += 2;
        break;
    case 0xCA: { u16 n = fetch16(); S.ip = pop16(); S.sreg[S_CS] = pop16(); S.reg[R_SP] = (u16)(S.reg[R_SP] + n); S.cycles += 9; break; }
    case 0xCB: S.ip = pop16(); S.sreg[S_CS] = pop16(); S.cycles += 8; break;
    case 0xCC: cpu_int(3); break;
    case 0xCD: cpu_int(fetch8()); break;
    case 0xCE: if (S.flags & FO) cpu_int(4); else S.cycles += 3; break;
    case 0xCF:                          /* IRET */
        S.ip = pop16();
        S.sreg[S_CS] = pop16();
        set_flags(pop16());
        S.cycles += 10;
        break;

    case 0xD0: { struct ea_info e = decode_modrm(seg_ovr, 0); ea_wr8(&e, grp2_8(e.reg, ea_rd8(&e), 1)); S.cycles += 1; break; }
    case 0xD1: { struct ea_info e = decode_modrm(seg_ovr, 0); ea_wr16(&e, grp2_16(e.reg, ea_rd16(&e), 1)); S.cycles += 1; break; }
    case 0xD2: { struct ea_info e = decode_modrm(seg_ovr, 0); ea_wr8(&e, grp2_8(e.reg, ea_rd8(&e), *reg8_ptr(1))); S.cycles += 3; break; }
    case 0xD3: { struct ea_info e = decode_modrm(seg_ovr, 0); ea_wr16(&e, grp2_16(e.reg, ea_rd16(&e), *reg8_ptr(1))); S.cycles += 3; break; }
    case 0xD4: {                        /* AAM ib */
        u8 ib = fetch8();
        u8 al = *reg8_ptr(0);
        if (ib == 0) {
            u16 zf = (al & 0xC0u) == 0 ? FZ : 0;
            S.flags = (u16)((S.flags & ~(FA | FP | FS | FZ | FC | FO)) | S.last_mul_co | zf);
            cpu_int(0);
        } else {
            *reg8_ptr(4) = (u8)(al / ib);
            *reg8_ptr(0) = (u8)(al % ib);
            S.flags &= (u16)~(FA | FC | FO);
            set_szp8(*reg8_ptr(0));
            S.cycles += 16;
        }
        break;
    }
    case 0xD5: {                        /* AAD ib: AL = add8(AL, AH * ib), AH = 0 */
        u8 ib = fetch8();
        u8 prod = (u8)(*reg8_ptr(4) * ib);
        *reg8_ptr(0) = alu8(0, *reg8_ptr(0), prod);
        *reg8_ptr(4) = 0;
        S.cycles += 6;
        break;
    }
    case 0xD6:                          /* SALC */
        *reg8_ptr(0) = (S.flags & FC) ? 0xFFu : 0x00u;
        S.cycles += 8;
        break;
    case 0xD7: {                        /* XLAT */
        u16 s = S.sreg[seg_ovr >= 0 ? seg_ovr : S_DS];
        *reg8_ptr(0) = seg_rd8(s, (u16)(S.reg[R_BX] + *reg8_ptr(0)));
        S.cycles += 5;
        break;
    }
    case 0xD8: case 0xD9: case 0xDA: case 0xDB:
    case 0xDC: case 0xDD: case 0xDE: case 0xDF:
        /* V30MZ FPO1: 2-byte NOP (consumes ModR/M + any displacement!) */
        (void)decode_modrm(seg_ovr, 0);
        S.cycles += 1;
        break;

    case 0xE0: {                        /* LOOPNZ */
        s8 d = (s8)fetch8();
        S.reg[R_CX]--;
        if (S.reg[R_CX] != 0 && !(S.flags & FZ)) { S.ip = (u16)(S.ip + d); S.cycles += 5; }
        else S.cycles += 2;
        break;
    }
    case 0xE1: {                        /* LOOPZ */
        s8 d = (s8)fetch8();
        S.reg[R_CX]--;
        if (S.reg[R_CX] != 0 && (S.flags & FZ)) { S.ip = (u16)(S.ip + d); S.cycles += 5; }
        else S.cycles += 2;
        break;
    }
    case 0xE2: {                        /* LOOP */
        s8 d = (s8)fetch8();
        S.reg[R_CX]--;
        if (S.reg[R_CX] != 0) { S.ip = (u16)(S.ip + d); S.cycles += 5; }
        else S.cycles += 2;
        break;
    }
    case 0xE3: {                        /* JCXZ */
        s8 d = (s8)fetch8();
        if (S.reg[R_CX] == 0) { S.ip = (u16)(S.ip + d); S.cycles += 5; }
        else S.cycles += 1;
        break;
    }
    case 0xE4: *reg8_ptr(0) = port_rd8(fetch8()); S.cycles += 5; break;
    case 0xE5: S.reg[R_AX] = port_rd16(fetch8()); S.cycles += 5; break;
    case 0xE6: { u8 p = fetch8(); port_wr8(p, *reg8_ptr(0)); S.cycles += 4; break; }
    case 0xE7: { u8 p = fetch8(); port_wr16(p, S.reg[R_AX]); S.cycles += 4; break; }
    case 0xE8: { s16 d = (s16)fetch16(); push16(S.ip); S.ip = (u16)(S.ip + d); S.cycles += 5; break; }
    case 0xE9: { s16 d = (s16)fetch16(); S.ip = (u16)(S.ip + d); S.cycles += 4; break; }
    case 0xEA: { u16 nip = fetch16(), ncs = fetch16(); S.ip = nip; S.sreg[S_CS] = ncs; S.cycles += 7; break; }
    case 0xEB: {
        s8 d = (s8)fetch8();
        S.ip = (u16)(S.ip + d);
        S.cycles += 4;
        if (d == -2 && seg_ovr < 0 && !rep && !trap_before && !(S.flags & FT) && !S.irq_inhibit &&
            !((S.flags & FI) && (S.io[0xB2] & S.io[0xB4])) && S.cycles < S.line_end) {
            s32 rem = S.line_end - S.cycles;
            S.cycles += ((rem + 3) >> 2) << 2;
        }
        break;
    }
    case 0xEC: *reg8_ptr(0) = port_rd8((u8)S.reg[R_DX]); S.cycles += 5; break;
    case 0xED: S.reg[R_AX] = port_rd16(S.reg[R_DX]); S.cycles += 5; break;
    case 0xEE: port_wr8((u8)S.reg[R_DX], *reg8_ptr(0)); S.cycles += 4; break;
    case 0xEF: port_wr16(S.reg[R_DX], S.reg[R_AX]); S.cycles += 4; break;

    case 0xF4: S.halted = 1; S.cycles += 4; break;
    case 0xF5: S.flags ^= FC; S.cycles += 4; break;
    case 0xF6: {                        /* GRP3 rm8 */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        switch (e.reg) {
        case 0: (void)alu8(4, ea_rd8(&e), fetch8()); S.cycles += 2; break;
        case 1: S.cycles += 1; break;   /* V30MZ F6 /1: 1-cycle NOP */
        case 2: ea_wr8(&e, (u8)~ea_rd8(&e)); S.cycles += 2; break;
        case 3: ea_wr8(&e, alu8(5, 0, ea_rd8(&e))); S.cycles += 2; break;
        case 4: do_mul8(ea_rd8(&e), 0); S.cycles += 3; break;
        case 5: do_mul8(ea_rd8(&e), 1); S.cycles += 3; break;
        case 6: do_div8(ea_rd8(&e)); S.cycles += 15; break;
        case 7: do_idiv8(ea_rd8(&e)); S.cycles += 17; break;
        }
        break;
    }
    case 0xF7: {                        /* GRP3 rm16 */
        struct ea_info e = decode_modrm(seg_ovr, 0);
        switch (e.reg) {
        case 0: (void)alu16(4, ea_rd16(&e), fetch16()); S.cycles += 2; break;
        case 1: S.cycles += 1; break;   /* V30MZ F7 /1: 1-cycle NOP */
        case 2: ea_wr16(&e, (u16)~ea_rd16(&e)); S.cycles += 2; break;
        case 3: ea_wr16(&e, alu16(5, 0, ea_rd16(&e))); S.cycles += 2; break;
        case 4: (void)do_mul16_core(S.reg[R_AX], ea_rd16(&e), 0, 1); S.cycles += 3; break;
        case 5: (void)do_mul16_core(S.reg[R_AX], ea_rd16(&e), 1, 1); S.cycles += 3; break;
        case 6: do_div16(ea_rd16(&e)); S.cycles += 23; break;
        case 7: do_idiv16(ea_rd16(&e)); S.cycles += 24; break;
        }
        break;
    }
    case 0xF8: S.flags &= (u16)~FC; S.cycles += 4; break;
    case 0xF9: S.flags |= FC;       S.cycles += 4; break;
    case 0xFA: S.flags &= (u16)~FI; S.cycles += 4; break;
    case 0xFB: S.flags |= FI;       S.cycles += 4; break;
    case 0xFC: S.flags &= (u16)~FD; S.cycles += 4; break;
    case 0xFD: S.flags |= FD;       S.cycles += 4; break;
    case 0xFE:
    case 0xFF: {                        /* GRP4 / GRP5 (note V30MZ 0xFE /2..6 behaves like 0xFF!) */
        u8 peek = seg_rd8(S.sreg[S_CS], S.ip);
        u8 sub = (peek >> 3) & 7u;
        if (op == 0xFE && sub < 2) {
            struct ea_info e = decode_modrm(seg_ovr, 0);
            u16 cf = S.flags & FC;
            u8 r = alu8(sub == 0 ? 0 : 5, ea_rd8(&e), 1);
            S.flags = (u16)((S.flags & ~FC) | cf);
            ea_wr8(&e, r);
            S.cycles += 2;
            break;
        }
        int force_mem = (sub == 3 || sub == 5);     /* CALL far / JMP far use V30MZ mod==3 custom EA! */
        struct ea_info e = decode_modrm(seg_ovr, force_mem);
        switch (sub) {
        case 0: {
            u16 cf = S.flags & FC;
            u16 r = alu16(0, ea_rd16(&e), 1);
            S.flags = (u16)((S.flags & ~FC) | cf);
            ea_wr16(&e, r);
            S.cycles += 2;
            break;
        }
        case 1: {
            u16 cf = S.flags & FC;
            u16 r = alu16(5, ea_rd16(&e), 1);
            S.flags = (u16)((S.flags & ~FC) | cf);
            ea_wr16(&e, r);
            S.cycles += 2;
            break;
        }
        case 2: {                       /* CALL near rm16 */
            u16 dst = ea_rd16(&e);
            push16(S.ip);
            S.ip = dst;
            S.cycles += 6;
            break;
        }
        case 3: {                       /* CALL far m16:16 (push return BEFORE reading target!) */
            push16(S.sreg[S_CS]);
            push16(S.ip);
            u16 nip = seg_rd16(e.seg, e.off);
            u16 ncs = seg_rd16(e.seg, (u16)(e.off + 2u));
            S.ip = nip;
            S.sreg[S_CS] = ncs;
            S.cycles += 12;
            break;
        }
        case 4: S.ip = ea_rd16(&e); S.cycles += 5; break;
        case 5: {
            u16 nip = seg_rd16(e.seg, e.off);
            u16 ncs = seg_rd16(e.seg, (u16)(e.off + 2u));
            S.ip = nip;
            S.sreg[S_CS] = ncs;
            S.cycles += 8;
            break;
        }
        case 6:
            if (e.mod == 3 && e.rm == R_SP) {
                S.reg[R_SP] = (u16)(S.reg[R_SP] - 2u);
                seg_wr16(S.sreg[S_SS], S.reg[R_SP], S.reg[R_SP]);
            } else {
                push16(ea_rd16(&e));
            }
            S.cycles += 2;
            break;
        default:                        /* /7: NOP on V30MZ */
            S.cycles += 1;
            break;
        }
        break;
    }
    default:
        S.cycles += 1;
        break;
    }

after_step:
    S.irq_inhibit = (u8)inhibit_ss;
    if (trap_before && (S.flags & FT) && !inhibit_ss)
        cpu_int(1);
}

static void check_hw_irq(void)
{
    if (S.irq_inhibit)
        return;
    u8 pending = S.io[0xB4] & S.io[0xB2];
    if (!pending)
        return;
    S.halted = 0;                       /* Any enabled pending SoC interrupt wakes V30MZ from HLT */
    if (!(S.flags & FI))
        return;
    int top = 7;
    while (top > 0 && !(pending & (1u << top)))
        top--;
    cpu_int((u8)((S.io[0xB0] & 0xF8u) | top));
}

/* ---- WonderSwan & WonderSwan Color Scanline PPU ---- */
static u16 wsc_rgb12_to_15(u16 c)
{
    u32 b = c & 0x0Fu, g = (c >> 4) & 0x0Fu, r = (c >> 8) & 0x0Fu;
    u32 r5 = (r << 1) | (r >> 3);
    u32 g5 = (g << 1) | (g >> 3);
    u32 b5 = (b << 1) | (b >> 3);
    return (u16)((b5 << 10) | (g5 << 5) | r5);
}

static u16 mono_shade_to_15(u8 pool_idx)
{
    u8 p = S.io[0x1C + ((pool_idx & 7u) >> 1)];
    u8 dark = (pool_idx & 1u) ? (p >> 4) : (p & 0x0Fu);
    u32 v = 15u - dark;                 /* 0 = lightest white, 15 = darkest black */
    u32 v5 = (v << 1) | (v >> 3);
    return (u16)((v5 << 10) | (v5 << 5) | v5);
}

static void refresh_mono_pals(void)
{
    for (int i = 0; i < 8; i++)
        M->mono_pool15[i] = mono_shade_to_15((u8)i);
    for (int p = 0; p < 16; p++) {
        u16 lut = (u16)(S.io[0x20 + p * 2] | ((u16)S.io[0x21 + p * 2] << 8));
        M->mono_pal15[p * 4 + 0] = M->mono_pool15[lut & 7u];
        M->mono_pal15[p * 4 + 1] = M->mono_pool15[(lut >> 4) & 7u];
        M->mono_pal15[p * 4 + 2] = M->mono_pool15[(lut >> 8) & 7u];
        M->mono_pal15[p * 4 + 3] = M->mono_pool15[(lut >> 12) & 7u];
    }
    S.mono_pal_dirty = 0;
}

static void refresh_wsc_pals(void)
{
    const u8 *pr = M->ram + 0xFE00u;
    for (int i = 0; i < 256; i++)
        M->wsc_pal15[i] = wsc_rgb12_to_15((u16)(pr[i * 2] | ((u16)pr[i * 2 + 1] << 8)));
    S.wsc_pal_dirty = 0;
}

/* Unpack all 8 pixels of a tile row into 8 nibbles (nibble k = pixel k from left, after hflip!) */
static inline u32 unpack_tile_row(u8 vmode, u16 tile, u8 bank, int ty, int hflip)
{
    if (!(vmode & 0x80u)) {             /* Mono 2bpp planar (16B/tile at $2000) */
        const u8 *p = M->ram + 0x2000u + ((u32)tile << 4) + ((u32)ty << 1);
        const u32 *lut = hflip ? M->bp_lut_flip : M->bp_lut;
        return lut[p[0]] | (lut[p[1]] << 1);
    }
    if (!(vmode & 0x40u)) {             /* WSC 2bpp planar (16B/tile at $2000 / $4000) */
        const u8 *p = M->ram + (bank ? 0x4000u : 0x2000u) + ((u32)tile << 4) + ((u32)ty << 1);
        const u32 *lut = hflip ? M->bp_lut_flip : M->bp_lut;
        return lut[p[0]] | (lut[p[1]] << 1);
    }
    const u8 *p = M->ram + (bank ? 0x8000u : 0x4000u) + ((u32)tile << 5) + ((u32)ty << 2);
    if (!(vmode & 0x20u)) {             /* WSC 4bpp planar */
        const u32 *lut = hflip ? M->bp_lut_flip : M->bp_lut;
        return lut[p[0]] | (lut[p[1]] << 1) | (lut[p[2]] << 2) | (lut[p[3]] << 3);
    }
    /* WSC 4bpp chunky / packed: high nibble = even x, low nibble = odd x */
    if (!hflip) {
        return (u32)(p[0] >> 4) | ((u32)(p[0] & 0x0Fu) << 4) |
               ((u32)(p[1] >> 4) << 8) | ((u32)(p[1] & 0x0Fu) << 12) |
               ((u32)(p[2] >> 4) << 16) | ((u32)(p[2] & 0x0Fu) << 20) |
               ((u32)(p[3] >> 4) << 24) | ((u32)(p[3] & 0x0Fu) << 28);
    }
    return (u32)(p[3] & 0x0Fu) | ((u32)(p[3] >> 4) << 4) |
           ((u32)(p[2] & 0x0Fu) << 8) | ((u32)(p[2] >> 4) << 12) |
           ((u32)(p[1] & 0x0Fu) << 16) | ((u32)(p[1] >> 4) << 20) |
           ((u32)(p[0] & 0x0Fu) << 24) | ((u32)(p[0] >> 4) << 28);
}

static inline int in_rect(int x, int y, u8 x1, u8 y1, u8 x2, u8 y2)
{
    return x >= x1 && x <= x2 && y >= y1 && y <= y2;
}

static void render_ws_line(int y, u16 *dst)
{
    u8 dctrl = S.io[0x00];
    u8 vmode = S.io[0x60];
    int color_mode = (vmode & 0x80u) != 0;
    int is_4bpp = (vmode & 0xC0u) == 0xC0u;

    if (!(S.io[0x14] & 0x01u)) {        /* LCD off */
        u16 blank = color_mode ? 0 : 0x7FFFu;
        for (int x = 0; x < WS_W; x++)
            dst[x] = blank;
        return;
    }

    if (color_mode) {
        if (S.wsc_pal_dirty)
            refresh_wsc_pals();
    } else {
        if (S.mono_pal_dirty)
            refresh_mono_pals();
    }

    u16 backdrop = color_mode ? M->wsc_pal15[S.io[0x01]] : M->mono_pool15[S.io[0x01] & 7u];
    for (int x = 0; x < WS_W; x++)
        dst[x] = backdrop;

    /* 1. Screen 1 (BG) — tile-by-tile 8-pixel sliver loop */
    if (dctrl & 0x01u) {
        const u8 *map_row = M->ram + ((u32)(S.io[0x07] & (color_mode ? 0x0Fu : 0x07u)) << 11) +
                            (u32)(((y + S.io[0x11]) & 0xF8) << 3);
        int fy = (y + S.io[0x11]) & 7;
        int sx = S.io[0x10];
        int x = 0;
        while (x < WS_W) {
            int tx0 = sx & 7;
            int n = 8 - tx0;
            if (x + n > WS_W)
                n = WS_W - x;
            u32 ma = (u32)(((sx >> 3) & 31) << 1);
            u16 ent = (u16)(map_row[ma] | ((u16)map_row[ma + 1u] << 8));
            u8 pal = (u8)((ent >> 9) & 15u);
            u32 row32 = unpack_tile_row(vmode, ent & 0x1FFu, (u8)((ent >> 13) & 1u),
                                        (ent & 0x8000u) ? (7 - fy) : fy, (ent & 0x4000u) != 0);
            row32 >>= (tx0 << 2);
            const u16 *p15 = color_mode ? &M->wsc_pal15[(u32)pal << 4] : &M->mono_pal15[(u32)pal << 2];
            int opaque0 = !is_4bpp && !(pal & 4u);
            if (opaque0) {
                for (int i = 0; i < n; i++, row32 >>= 4)
                    dst[x + i] = p15[row32 & 0x0Fu];
            } else if (row32) {
                for (int i = 0; i < n; i++, row32 >>= 4) {
                    u8 px = (u8)(row32 & 0x0Fu);
                    if (px)
                        dst[x + i] = p15[px];
                }
            }
            x += n;
            sx += n;
        }
    }

    /* Evaluate up to 32 sprites on line y into per-pixel sprite buffer */
    u16 spr_col[WS_W];
    u8 spr_pri[WS_W];                   /* 0 = none, 1 = behind FG, 2 = in front of FG */
    int any_spr = 0;

    if (dctrl & 0x04u) {
        int cnt = S.io[0x06];
        if (cnt > 128) cnt = 128;
        int start = S.io[0x05] & 0x7Fu;
        int spr_win_en = (dctrl & 0x08u) != 0;
        u8 wx1 = S.io[0x0C], wy1 = S.io[0x0D], wx2 = S.io[0x0E], wy2 = S.io[0x0F];

        u8 sel_idx[32];
        int n_sel = 0;
        for (int i = 0; i < cnt && n_sel < 32; i++) {
            int idx = (start + i) & 0x7F;
            u8 sy = M->oam[idx * 4 + 2];
            int dy = (y - sy) & 0xFF;
            if (dy < 8)
                sel_idx[n_sel++] = (u8)idx;
        }
        if (n_sel > 0) {
            any_spr = 1;
            for (int x = 0; x < WS_W; x++)
                spr_pri[x] = 0;
            for (int s = n_sel - 1; s >= 0; s--) {
                const u8 *sp = &M->oam[sel_idx[s] * 4];
                u16 attr = (u16)(sp[0] | ((u16)sp[1] << 8));
                u8 sy = sp[2], sx = sp[3];
                int dy = (y - sy) & 0xFF;
                u8 pal = (u8)(8u + ((attr >> 9) & 7u));
                u32 row32 = unpack_tile_row(vmode, attr & 0x1FFu, 0,
                                            (attr & 0x8000u) ? (7 - dy) : dy, (attr & 0x4000u) != 0);
                int opaque0 = !is_4bpp && !(pal & 4u);
                if (!row32 && !opaque0)
                    continue;
                const u16 *p15 = color_mode ? &M->wsc_pal15[(u32)pal << 4] : &M->mono_pal15[(u32)pal << 2];
                int clip_outside = (attr & 0x1000u) != 0;
                u8 pri = (attr & 0x2000u) ? 2 : 1;
                for (int k = 0; k < 8; k++, row32 >>= 4) {
                    u8 px = (u8)(row32 & 0x0Fu);
                    if (!px && !opaque0)
                        continue;
                    int dx = (sx + k) & 0xFF;
                    if (dx >= WS_W)
                        continue;
                    if (spr_win_en) {
                        int inside = in_rect(dx, y, wx1, wy1, wx2, wy2);
                        if (clip_outside ? inside : !inside)
                            continue;
                    }
                    spr_col[dx] = p15[px];
                    spr_pri[dx] = pri;
                }
            }
        }
    }

    /* Draw behind-FG sprites */
    if (any_spr) {
        for (int x = 0; x < WS_W; x++)
            if (spr_pri[x] == 1)
                dst[x] = spr_col[x];
    }

    /* 2. Screen 2 (FG) with optional window */
    if (dctrl & 0x02u) {
        const u8 *map_row = M->ram + ((u32)((S.io[0x07] >> 4) & (color_mode ? 0x0Fu : 0x07u)) << 11) +
                            (u32)(((y + S.io[0x13]) & 0xF8) << 3);
        int win_en = (dctrl & 0x20u) != 0;
        int win_out = (dctrl & 0x10u) != 0;
        u8 wx1 = S.io[0x08], wy1 = S.io[0x09], wx2 = S.io[0x0A], wy2 = S.io[0x0B];
        int fy = (y + S.io[0x13]) & 7;
        int sx = S.io[0x12];
        int x = 0;
        while (x < WS_W) {
            int tx0 = sx & 7;
            int n = 8 - tx0;
            if (x + n > WS_W)
                n = WS_W - x;
            u32 ma = (u32)(((sx >> 3) & 31) << 1);
            u16 ent = (u16)(map_row[ma] | ((u16)map_row[ma + 1u] << 8));
            u8 pal = (u8)((ent >> 9) & 15u);
            u32 row32 = unpack_tile_row(vmode, ent & 0x1FFu, (u8)((ent >> 13) & 1u),
                                        (ent & 0x8000u) ? (7 - fy) : fy, (ent & 0x4000u) != 0);
            row32 >>= (tx0 << 2);
            const u16 *p15 = color_mode ? &M->wsc_pal15[(u32)pal << 4] : &M->mono_pal15[(u32)pal << 2];
            int opaque0 = !is_4bpp && !(pal & 4u);
            if (opaque0 || row32) {
                for (int i = 0; i < n; i++, row32 >>= 4) {
                    if (win_en) {
                        int inside = in_rect(x + i, y, wx1, wy1, wx2, wy2);
                        if (win_out ? inside : !inside)
                            continue;
                    }
                    u8 px = (u8)(row32 & 0x0Fu);
                    if (px || opaque0)
                        dst[x + i] = p15[px];
                }
            }
            x += n;
            sx += n;
        }
    }

    /* Draw front-of-FG sprites */
    if (any_spr) {
        for (int x = 0; x < WS_W; x++)
            if (spr_pri[x] == 2)
                dst[x] = spr_col[x];
    }
}

/* ---- Public API ---- */
static void fmt_info(void)
{
    char *p = info_buf;
    const char *tag = S.is_wsc_cart ? "WonderSwan Color" : "WonderSwan";
    while (*tag) *p++ = *tag++;
    if (S.is_vertical) {
        const char *vt = " (vertical)";
        while (*vt) *p++ = *vt++;
    }
    const char *sep = ", ROM ";
    while (*sep) *p++ = *sep++;
    u32 kb = (S.rom_size + 1023u) >> 10;
    char tmp[16];
    int n = 0;
    do { tmp[n++] = (char)('0' + kb % 10); kb /= 10; } while (kb);
    while (n--) *p++ = tmp[n];
    const char *suf = " KB";
    while (*suf) *p++ = *suf++;
    *p = 0;
}

const char *ws_load(u8 *image, u32 size, int prefer_color)
{
    if (!image || size < 0x10000u)
        return "too small for a WonderSwan cartridge (at least 64 KB)";
    if (size > 0x1000000u)
        return "too large for a WonderSwan cartridge (over 16 MB)";
    /* Footer at image[size - 16]: byte 0 must be far JMP (0xEA) */
    const u8 *hdr = image + size - 16u;
    if (hdr[0] != 0xEAu)
        return "not a WonderSwan cartridge (missing far JMP in footer)";

    for (u32 i = 0; i < sizeof(*M); i++)
        ((u8 *)M)[i] = 0;
    for (u32 v = 0; v < 256; v++) {
        u32 p = v ^ (v >> 4);
        p ^= p >> 2;
        p ^= p >> 1;
        M->parity[v] = (p & 1u) ? 0 : FP;
        u32 fw = 0, rv = 0;
        for (int k = 0; k < 8; k++) {
            if (v & (1u << (7 - k))) fw |= (1u << (k * 4));
            if (v & (1u << k))       rv |= (1u << (k * 4));
        }
        M->bp_lut[v] = fw;
        M->bp_lut_flip[v] = rv;
    }
    for (u32 i = 0; i < sizeof(S); i++)
        ((u8 *)&S)[i] = 0;

    S.rom = image;
    S.rom_size = size;
    u32 b64 = (size + 0xFFFFu) >> 16;
    S.rom_banks64k = 1;
    while (S.rom_banks64k < b64)
        S.rom_banks64k <<= 1;

    S.is_wsc_cart = (u8)((hdr[7] != 0 || prefer_color) ? 1 : 0);
    S.is_vertical = (hdr[12] & 1u) != 0;

    switch (hdr[11]) {
    case 0x01: S.save_size = 8192; break;
    case 0x02: S.save_size = 32768; break;
    case 0x03: case 0x04: case 0x05: S.save_size = 65536; break;
    case 0x10: S.save_size = 128;  S.has_ceeprom = 1; break;
    case 0x20: S.save_size = 2048; S.has_ceeprom = 1; break;
    case 0x50: S.save_size = 1024; S.has_ceeprom = 1; break;
    default:   S.save_size = 0; break;
    }
    if (S.has_ceeprom) {
        for (u32 i = 0; i < S.save_size; i++)
            M->sram[i] = 0xFFu;
    }

    ws_reset();
    fmt_info();
    return 0;
}

void ws_reset(void)
{
    for (int i = 0; i < 8; i++) S.reg[i] = 0;
    for (int i = 0; i < 4; i++) S.sreg[i] = 0;
    S.reg[R_SP] = 0x2000u;
    S.sreg[S_CS] = 0xFFFFu;
    S.ip = 0x0000u;
    S.flags = F_FIXED_SET;
    S.last_mul_co = 0;
    S.halted = 0;
    S.irq_inhibit = 0;
    S.cycles = 0;

    for (u32 i = 0; i < sizeof(M->ram); i++) M->ram[i] = 0;
    for (u32 i = 0; i < sizeof(M->oam); i++) M->oam[i] = 0;
    for (int i = 0; i < 256; i++) S.io[i] = 0;

    /* Post-IPL WonderSwan Color hardware state */
    S.io[0x14] = 0x01u;                 /* LCD enabled */
    S.io[0x1C] = 0x20u;                 /* Default 8-shade mono pool (0,2,4,6,8,10,12,15) */
    S.io[0x1D] = 0x64u;
    S.io[0x1E] = 0xA8u;
    S.io[0x1F] = 0xFCu;
    S.io[0x91] = 0x89u;                 /* Speaker + headphone enabled */
    S.io[0xA0] = S.is_wsc_cart ? 0x87u : 0x01u; /* SPHINX (WSC) vs ASWAN (Mono WS) */
    S.io[0xC0] = 0xFFu;
    S.io[0xC1] = 0xFFu;
    S.io[0xC2] = 0xFFu;
    S.io[0xC3] = 0xFFu;
    S.wsc_pal_dirty = 1;
    S.mono_pal_dirty = 1;
    update_seg_ptrs();

    S.out_w = S.is_vertical ? WS_H : WS_W;
    S.out_h = S.is_vertical ? WS_W : WS_H;
}

void ws_frame(u16 pad, u16 *picture)
{
    S.pad_state = pad;
    S.audio_count = 0;
    S.audio_last_cyc = S.cycles;

    /* Check if LCD orientation icon changed dynamically (IO[0x15] bit 1 = vertical, bit 2 = horizontal) */
    if (S.io[0x15] & 0x02u) S.is_vertical = 1;
    else if (S.io[0x15] & 0x04u) S.is_vertical = 0;
    S.out_w = S.is_vertical ? WS_H : WS_W;
    S.out_h = S.is_vertical ? WS_W : WS_H;

    u16 *render_buf = (picture && !S.is_vertical) ? picture : M->rot_buf;

    for (int line = 0; line < LINES_TOT; line++) {
        S.io[0x02] = (u8)line;

        /* Line compare interrupt (INT 4: bit 4) */
        if (line == S.io[0x03])
            S.io[0xB4] |= 0x10u;

        /* VBlank start at line 144: latch OAM, fire VBlank IRQ (bit 6) & VBlank timer (bit 5) */
        if (line == LINES_ACT) {
            int color_mode = (S.io[0x60] & 0x80u) != 0;
            u32 oam_base = (u32)(S.io[0x04] & (color_mode ? 0x7Fu : 0x1Fu)) << 9;
            for (u32 i = 0; i < 512u; i++)
                M->oam[i] = M->ram[(oam_base + i) & 0xFFFFu];
            S.io[0xB4] |= 0x40u;
            if ((S.io[0xA2] & 0x04u) && S.vblank_cnt > 0) {
                S.vblank_cnt--;
                if (S.vblank_cnt == 0) {
                    S.io[0xB4] |= 0x20u;
                    if (S.io[0xA2] & 0x08u)
                        S.vblank_cnt = (u16)(S.io[0xA6] | ((u16)S.io[0xA7] << 8));
                    else
                        S.io[0xA2] &= (u8)~0x04u;
                }
            }
        }

        s32 line_end = (line + 1) * LINE_CYC;
        S.line_end = line_end;
        while (S.cycles < line_end) {
            check_hw_irq();
            if (S.halted) {
                S.cycles = line_end;
                break;
            }
            cpu_step();
        }

        if (line < LINES_ACT && picture)
            render_ws_line(line, render_buf + line * WS_W);

        /* HBlank timer at end of each line (12 kHz) */
        if ((S.io[0xA2] & 0x01u) && S.hblank_cnt > 0) {
            S.hblank_cnt--;
            if (S.hblank_cnt == 0) {
                S.io[0xB4] |= 0x80u;
                if (S.io[0xA2] & 0x02u)
                    S.hblank_cnt = (u16)(S.io[0xA4] | ((u16)S.io[0xA5] << 8));
                else
                    S.io[0xA2] &= (u8)~0x01u;
            }
        }
    }

    /* If game is vertical (144x224), rotate 224x144 90 degrees CCW so it stands upright on the TV! */
    if (picture && S.is_vertical) {
        for (int y = 0; y < WS_H; y++)
            for (int x = 0; x < WS_W; x++)
                picture[(WS_W - 1 - x) * WS_H + y] = M->rot_buf[y * WS_W + x];
    }

    audio_catch_up();
    S.cycles -= FRAME_CYC;
    S.audio_last_cyc = S.cycles;
}

int ws_width(void)   { return S.out_w; }
int ws_height(void)  { return S.out_h; }
const char *ws_info(void) { return info_buf; }

u8 *ws_save_ram(u32 *size, int *battery)
{
    *size = S.save_size ? S.save_size : 256u;
    *battery = S.save_size != 0;
    return M->sram;
}

int ws_save_changed(void)
{
    int d = S.sram_dirty;
    S.sram_dirty = 0;
    return d;
}

int ws_jammed(void)
{
    return S.halted && !(S.flags & FI) && !S.io[0xB2];
}

void ws_audio_rate(u32 hz)
{
    S.sample_rate = hz;
    S.audio_cyc_acc = 0;
    S.audio_count = 0;
    S.audio_last_cyc = S.cycles;
}

int ws_audio(s16 *out, int max)
{
    int n = S.audio_count < max ? S.audio_count : max;
    for (int i = 0; i < n; i++)
        out[i] = M->audio_ring[i];
    S.audio_count = 0;
    return n;
}
