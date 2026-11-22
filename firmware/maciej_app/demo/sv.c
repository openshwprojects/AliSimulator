/* A Watara Supervision (.sv): see sv.h. */
#pragma GCC optimize("O2")
#include "sv.h"

#ifndef SV_HOST
#include "hw.h"
#endif

typedef signed char s8;

#define INLINE static inline __attribute__((always_inline))

#define SV_CLOCK     4000000u
#define SLICES       256
#define SLICE_CYC    256                /* 256 * 256 = 65536 cycles / frame */
#define SND_RING     4096

/* 65SC02 status flags */
#define FN 0x80u
#define FV 0x40u
#define FB 0x10u
#define FD 0x08u
#define FI 0x04u
#define FZ 0x02u
#define FC 0x01u

struct sv_mem {
    u8 ram[0x2000];                     /* $0000..$1FFF: 8 KB system RAM */
    u8 vram[0x2000];                    /* $4000..$5FFF: 8 KB 2bpp LCD VRAM */
    u8 regs[0x2000];                    /* $2000..$3FFF: ASIC registers */
    u8 small_rom[0x4000];               /* Padded 16 KB buffer when cartridge < 16 KB */
    u8 sav_dummy[16];
    s16 snd_ring[SND_RING];
};

#ifdef SV_HOST
static struct sv_mem sv_host_mem;
#define M (&sv_host_mem)
#else
#define M ((struct sv_mem *)KSEG0(EMU_RAM_PHYS))
#endif

struct sv_tone {
    u8 reg[4];
    u8 on, duty, vol;
    u16 count;                          /* frame length counter (decremented at 61 Hz) */
    u32 period;                         /* CPU cycles per full wave ((freq + 1) << 5) */
    u32 phase;
};

struct sv_noise {
    u8 reg[3];
    u8 on, play, left, right, tap, vol, val;
    u16 state, count;
    u32 period, phase;
};

struct sv_adma {
    u8 reg[5];
    u8 on, left, right;
    u16 start, size, pos;               /* size & pos in 4-bit nybbles */
    u32 ca14to16;
    u32 period, phase;
};

static struct {
    const u8 *rom;
    u32 rom_size;
    const u8 *lo_bank;
    const u8 *hi_bank;
    u8 magnum;

    /* WDC 65SC02 */
    u16 pc;
    u8 a, x, y, sp, p;
    s32 cyc;
    u8 irq_line, cpu_asleep, jammed;

    /* Timer & DMA */
    s32 timer_cyc;
    u8 timer_active, timer_shot, dma_done;
    u16 gdma_caddr, gdma_vaddr, gdma_len;
    u8 gdma_cpu2vram;

    /* Controls (active-high bits before inversion at $2020) */
    u8 ctl;

    /* Audio */
    struct sv_tone ch[2];
    struct sv_noise noise;
    struct sv_adma adma;
    u32 snd_hz, snd_acc;
    u32 snd_head, snd_count;

    u16 pal[4];
    char info[96];
} S;

/* Authentic Watara Supervision LCD 4-shade green-teal palette (0bbbbbgggggrrrrr) */
static const u8 sv_lcd_rgb[4][3] = {
    {0x9C, 0xCA, 0x84},                 /* 0: sunlit LCD background */
    {0x62, 0x9E, 0x7A},                 /* 1: light pixel */
    {0x32, 0x62, 0x56},                 /* 2: dark pixel */
    {0x0C, 0x2C, 0x28},                 /* 3: full ink */
};

static u8 bus_read(u16 a);
static void bus_write(u16 a, u8 v);

static void check_irq(void)
{
    u8 bank = M->regs[0x26];
    S.irq_line = (u8)(((S.timer_shot && (bank & 0x02u)) || (S.dma_done && (bank & 0x04u))) ? 1 : 0);
    if (S.irq_line)
        S.cpu_asleep = 0;
}

static void update_banks(void)
{
    u32 off = S.magnum
        ? (((u32)(M->regs[0x26] & 0x20u) << 9) | ((u32)(M->regs[0x21] & 0x0Fu) << 15))
        : ((u32)(M->regs[0x26] & 0xE0u) << 9);
    S.lo_bank = S.rom + (off % S.rom_size);
}

static void sound_wave_write(int idx, int off, u8 v)
{
    struct sv_tone *t = &S.ch[idx];
    t->reg[off] = v;
    switch (off) {
    case 0:
    case 1: {
        u32 f = (u32)t->reg[0] | ((u32)(t->reg[1] & 7u) << 8);
        t->period = (f + 1u) << 5;
        if (t->count == 0)
            t->phase = 0;
        break;
    }
    case 2:
        t->on   = (v & 0x40u) != 0;
        t->duty = (v >> 4) & 3u;
        t->vol  = v & 0x0Fu;
        break;
    case 3:
        t->count = (u16)v + 1u;
        break;
    }
}

static void sound_dma_write(int off, u8 v)
{
    S.adma.reg[off] = v;
    switch (off) {
    case 0:
    case 1:
        S.adma.start = (u16)S.adma.reg[0] | ((u16)S.adma.reg[1] << 8);
        break;
    case 2:
        S.adma.size = (u16)((v ? (u32)v : 0x100u) * 32u);
        break;
    case 3:
        S.adma.period   = 256u << (v & 3u);
        S.adma.right    = (v & 0x04u) != 0;
        S.adma.left     = (v & 0x08u) != 0;
        S.adma.ca14to16 = ((u32)(v & 0x70u) >> 4) << 14;
        break;
    case 4:
        S.adma.on = (v & 0x80u) != 0;
        if (S.adma.on) {
            S.adma.pos = 0;
            S.adma.phase = 0;
            if (!S.adma.period)
                S.adma.period = 256u;
        }
        break;
    }
}

static void sound_noise_write(int off, u8 v)
{
    S.noise.reg[off] = v;
    switch (off) {
    case 0:
        S.noise.period = 8u << (v >> 4);
        S.noise.vol    = v & 0x0Fu;
        break;
    case 1:
        S.noise.count = (u16)v + 1u;
        break;
    case 2:
        S.noise.tap   = (v & 0x01u) ? 14u : 6u;
        S.noise.play  = (v & 0x02u) != 0;
        S.noise.right = (v & 0x04u) != 0;
        S.noise.left  = (v & 0x08u) != 0;
        S.noise.on    = (v & 0x10u) != 0;
        if (S.noise.state == 0)
            S.noise.state = 1u;
        S.noise.phase = 0;
        break;
    }
}

/* Step Audio DMA in real time even when snd_hz == 0 so ADMA completion IRQs always fire! */
static void step_adma_silent(u32 cyc)
{
    if (!S.adma.on || !S.adma.period)
        return;
    S.adma.phase += cyc;
    while (S.adma.phase >= S.adma.period) {
        S.adma.phase -= S.adma.period;
        if (++S.adma.pos >= S.adma.size) {
            S.adma.on = 0;
            S.dma_done = 1;
            check_irq();
            break;
        }
    }
}

static void sound_sample(u32 dt_cyc)
{
    s32 left = 0, right = 0;

    for (int j = 0; j < 2; j++) {
        struct sv_tone *t = &S.ch[j];
        if (!t->period)
            continue;
        if (t->on || t->count) {
            u32 th = 0;
            switch (t->duty) {
            case 0: th = (t->period * 7u) >> 3; break;
            case 1: th = (t->period * 3u) >> 2; break;
            case 2: th = t->period >> 1; break;
            default: th = t->period >> 2; break;
            }
            s32 s = (t->phase < th) ? (s32)t->vol : -(s32)t->vol;
            if (j == 0) right += s;
            else        left  += s;
        }
        t->phase = (t->phase + dt_cyc) % t->period;
    }

    if (S.noise.on && (S.noise.play || S.noise.count) && S.noise.period) {
        S.noise.phase += dt_cyc;
        while (S.noise.phase >= S.noise.period) {
            S.noise.phase -= S.noise.period;
            S.noise.val = (u8)(S.noise.state & 1u);
            u16 fb = (u16)(((S.noise.state >> 1) ^ S.noise.state) & 1u);
            S.noise.state = (u16)((S.noise.state >> 1) | (fb << S.noise.tap));
        }
        s32 s = S.noise.val ? (s32)S.noise.vol : -(s32)S.noise.vol;
        if (S.noise.left)  left  += s;
        if (S.noise.right) right += s;
    }

    if (S.adma.on && S.adma.period) {
        u16 addr = (u16)(S.adma.start + (S.adma.pos >> 1));
        u8 byte = (addr >= 0x8000u && addr < 0xC000u)
            ? S.rom[((addr & 0x3FFFu) | S.adma.ca14to16) % S.rom_size]
            : bus_read(addr);
        u8 nib = (S.adma.pos & 1u) ? (byte & 0x0Fu) : (byte >> 4);
        s32 s = (s32)nib - 8;
        if (S.adma.left)  left  += s;
        if (S.adma.right) right += s;
        S.adma.phase += dt_cyc;
        while (S.adma.phase >= S.adma.period) {
            S.adma.phase -= S.adma.period;
            if (++S.adma.pos >= S.adma.size) {
                S.adma.on = 0;
                S.dma_done = 1;
                check_irq();
                break;
            }
        }
    }

    s32 mono = (left + right) * 320;
    if (mono > 32767)  mono = 32767;
    if (mono < -32768) mono = -32768;

    if (S.snd_count < SND_RING) {
        M->snd_ring[(S.snd_head + S.snd_count) % SND_RING] = (s16)mono;
        S.snd_count++;
    } else {
        M->snd_ring[S.snd_head] = (s16)mono;
        S.snd_head = (S.snd_head + 1u) % SND_RING;
    }
}

static u8 reg_read(u16 a)
{
    u16 r = a & 0x1FFFu;
    u8 v = M->regs[r];
    switch (r) {
    case 0x20:
        return (u8)(S.ctl ^ 0xFFu);
    case 0x21:
        return (u8)(v | (M->regs[0x22] & 0x0Fu));
    case 0x24:
        S.timer_shot = 0;
        check_irq();
        return v;
    case 0x25:
        S.dma_done = 0;
        check_irq();
        return v;
    case 0x27:
        return (u8)((v & ~3u) | (S.timer_shot ? 1u : 0u) | (S.dma_done ? 2u : 0u));
    }
    return v;
}

static void reg_write(u16 a, u8 v)
{
    u16 r = a & 0x1FFFu;
    M->regs[r] = v;
    switch (r) {
    case 0x08: S.gdma_caddr = (u16)((S.gdma_caddr & 0xFF00u) | v); break;
    case 0x09: S.gdma_caddr = (u16)((S.gdma_caddr & 0x00FFu) | ((u16)v << 8)); break;
    case 0x0A: S.gdma_vaddr = (u16)((S.gdma_vaddr & 0x1F00u) | v); break;
    case 0x0B:
        S.gdma_vaddr = (u16)(((S.gdma_vaddr & 0x00FFu) | ((u16)v << 8)) & 0x1FFFu);
        S.gdma_cpu2vram = (u8)((v >> 6) & 1u);
        break;
    case 0x0C:
        S.gdma_len = v ? (u16)((u16)v * 16u) : 4096u;
        break;
    case 0x0D:
        if (v & 0x80u) {
            for (u16 i = 0; i < S.gdma_len; i++) {
                u16 va = (u16)((S.gdma_vaddr + i) & 0x1FFFu);
                u16 ca = (u16)(S.gdma_caddr + i);
                if (S.gdma_cpu2vram)
                    M->vram[va] = bus_read(ca);
                else
                    bus_write(ca, M->vram[va]);
            }
            S.gdma_caddr = 0;
            S.gdma_vaddr = 0;
        }
        break;
    case 0x10: case 0x11: case 0x12: case 0x13:
    case 0x14: case 0x15: case 0x16: case 0x17:
        sound_wave_write((r >> 2) & 1, r & 3, v);
        break;
    case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x1C:
        sound_dma_write(r & 7, v);
        break;
    case 0x21:
        if (S.magnum && M->regs[0x22] == 0) {
            update_banks();
            check_irq();
        }
        break;
    case 0x23: {
        u32 d = v ? (u32)v : 0x100u;
        S.timer_cyc = (s32)((M->regs[0x26] & 0x10u) ? (d * 0x4000u) : (d * 0x100u));
        S.timer_active = 1;
        break;
    }
    case 0x26:
        update_banks();
        check_irq();
        break;
    case 0x28: case 0x29: case 0x2A:
        sound_noise_write(r & 7, v);
        break;
    }
}

INLINE u8 bus_read(u16 a)
{
    switch (a >> 13) {
    case 0: return M->ram[a];
    case 1: return reg_read(a);
    case 2: return M->vram[a & 0x1FFFu];
    case 3: return (u8)(a >> 8);
    case 4:
    case 5: return S.lo_bank[a & 0x3FFFu];
    default: return S.hi_bank[a & 0x3FFFu];
    }
}

INLINE void bus_write(u16 a, u8 v)
{
    switch (a >> 13) {
    case 0: M->ram[a] = v; break;
    case 1: reg_write(a, v); break;
    case 2: M->vram[a & 0x1FFFu] = v; break;
    default: break;
    }
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
        if (lo < 0) bcd -= 0x06;
        if (diff >= 0x100u) bcd -= 0x60;
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

static void trigger_nmi(void)
{
    S.cpu_asleep = 0;
    push16(S.pc);
    push8((u8)((S.p & ~FB) | 0x20u));
    S.p = (u8)((S.p | FI) & ~FD);
    S.pc = rd16_abs(0xFFFAu);
    S.cyc -= 7;
}

static void step_cpu(void)
{
    if (S.irq_line && !(S.p & FI)) {
        S.cpu_asleep = 0;
        push16(S.pc);
        push8((u8)((S.p & ~FB) | 0x20u));
        S.p = (u8)((S.p | FI) & ~FD);
        S.pc = rd16_abs(0xFFFEu);
        S.cyc -= 7;
        return;
    }
    if (S.cpu_asleep) {
        S.cyc = 0;
        return;
    }

    u8 op = bus_read(S.pc++);
    u16 addr;
    u8 v;

    if ((op & 0x0Fu) == 0x07u) {
        u8 zp = bus_read(S.pc++);
        u8 bit = (u8)(1u << ((op >> 4) & 7u));
        if (op & 0x80u) M->ram[zp] |= bit;
        else            M->ram[zp] &= (u8)~bit;
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
    case 0x00:
        S.pc++;
        push16(S.pc);
        push8((u8)(S.p | FB | 0x20u));
        S.p = (u8)((S.p | FI) & ~FD);
        S.pc = rd16_abs(0xFFFEu);
        S.cyc -= 7;
        break;

    case 0x09: S.a |= bus_read(S.pc++); set_nz(S.a); S.cyc -= 2; break;
    case 0x05: S.a |= M->ram[bus_read(S.pc++)]; set_nz(S.a); S.cyc -= 3; break;
    case 0x15: S.a |= M->ram[(u8)(bus_read(S.pc++) + S.x)]; set_nz(S.a); S.cyc -= 4; break;
    case 0x12: S.a |= bus_read(rd16_zp(bus_read(S.pc++))); set_nz(S.a); S.cyc -= 5; break;
    case 0x0D: S.a |= bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x1D: S.a |= bus_read((u16)(rd16_abs(S.pc) + S.x)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x19: S.a |= bus_read((u16)(rd16_abs(S.pc) + S.y)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x01: S.a |= bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x))); set_nz(S.a); S.cyc -= 6; break;
    case 0x11: S.a |= bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y)); set_nz(S.a); S.cyc -= 5; break;

    case 0x29: S.a &= bus_read(S.pc++); set_nz(S.a); S.cyc -= 2; break;
    case 0x25: S.a &= M->ram[bus_read(S.pc++)]; set_nz(S.a); S.cyc -= 3; break;
    case 0x35: S.a &= M->ram[(u8)(bus_read(S.pc++) + S.x)]; set_nz(S.a); S.cyc -= 4; break;
    case 0x32: S.a &= bus_read(rd16_zp(bus_read(S.pc++))); set_nz(S.a); S.cyc -= 5; break;
    case 0x2D: S.a &= bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x3D: S.a &= bus_read((u16)(rd16_abs(S.pc) + S.x)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x39: S.a &= bus_read((u16)(rd16_abs(S.pc) + S.y)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x21: S.a &= bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x))); set_nz(S.a); S.cyc -= 6; break;
    case 0x31: S.a &= bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y)); set_nz(S.a); S.cyc -= 5; break;

    case 0x49: S.a ^= bus_read(S.pc++); set_nz(S.a); S.cyc -= 2; break;
    case 0x45: S.a ^= M->ram[bus_read(S.pc++)]; set_nz(S.a); S.cyc -= 3; break;
    case 0x55: S.a ^= M->ram[(u8)(bus_read(S.pc++) + S.x)]; set_nz(S.a); S.cyc -= 4; break;
    case 0x52: S.a ^= bus_read(rd16_zp(bus_read(S.pc++))); set_nz(S.a); S.cyc -= 5; break;
    case 0x4D: S.a ^= bus_read(rd16_abs(S.pc)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x5D: S.a ^= bus_read((u16)(rd16_abs(S.pc) + S.x)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x59: S.a ^= bus_read((u16)(rd16_abs(S.pc) + S.y)); S.pc += 2; set_nz(S.a); S.cyc -= 4; break;
    case 0x41: S.a ^= bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x))); set_nz(S.a); S.cyc -= 6; break;
    case 0x51: S.a ^= bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y)); set_nz(S.a); S.cyc -= 5; break;

    case 0x69: adc65c02(bus_read(S.pc++)); S.cyc -= 2; break;
    case 0x65: adc65c02(M->ram[bus_read(S.pc++)]); S.cyc -= 3; break;
    case 0x75: adc65c02(M->ram[(u8)(bus_read(S.pc++) + S.x)]); S.cyc -= 4; break;
    case 0x72: adc65c02(bus_read(rd16_zp(bus_read(S.pc++)))); S.cyc -= 5; break;
    case 0x6D: adc65c02(bus_read(rd16_abs(S.pc))); S.pc += 2; S.cyc -= 4; break;
    case 0x7D: adc65c02(bus_read((u16)(rd16_abs(S.pc) + S.x))); S.pc += 2; S.cyc -= 4; break;
    case 0x79: adc65c02(bus_read((u16)(rd16_abs(S.pc) + S.y))); S.pc += 2; S.cyc -= 4; break;
    case 0x61: adc65c02(bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x)))); S.cyc -= 6; break;
    case 0x71: adc65c02(bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y))); S.cyc -= 5; break;

    case 0xE9: sbc65c02(bus_read(S.pc++)); S.cyc -= 2; break;
    case 0xE5: sbc65c02(M->ram[bus_read(S.pc++)]); S.cyc -= 3; break;
    case 0xF5: sbc65c02(M->ram[(u8)(bus_read(S.pc++) + S.x)]); S.cyc -= 4; break;
    case 0xF2: sbc65c02(bus_read(rd16_zp(bus_read(S.pc++)))); S.cyc -= 5; break;
    case 0xED: sbc65c02(bus_read(rd16_abs(S.pc))); S.pc += 2; S.cyc -= 4; break;
    case 0xFD: sbc65c02(bus_read((u16)(rd16_abs(S.pc) + S.x))); S.pc += 2; S.cyc -= 4; break;
    case 0xF9: sbc65c02(bus_read((u16)(rd16_abs(S.pc) + S.y))); S.pc += 2; S.cyc -= 4; break;
    case 0xE1: sbc65c02(bus_read(rd16_zp((u8)(bus_read(S.pc++) + S.x)))); S.cyc -= 6; break;
    case 0xF1: sbc65c02(bus_read((u16)(rd16_zp(bus_read(S.pc++)) + S.y))); S.cyc -= 5; break;

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

    case 0x80: branch65c02(1); S.cyc -= 2; break;
    case 0x10: branch65c02(!(S.p & FN)); S.cyc -= 2; break;
    case 0x30: branch65c02( (S.p & FN)); S.cyc -= 2; break;
    case 0x50: branch65c02(!(S.p & FV)); S.cyc -= 2; break;
    case 0x70: branch65c02( (S.p & FV)); S.cyc -= 2; break;
    case 0x90: branch65c02(!(S.p & FC)); S.cyc -= 2; break;
    case 0xB0: branch65c02( (S.p & FC)); S.cyc -= 2; break;
    case 0xD0: branch65c02(!(S.p & FZ)); S.cyc -= 2; break;
    case 0xF0: branch65c02( (S.p & FZ)); S.cyc -= 2; break;

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
    case 0x40: S.p = (u8)((pull8() & ~FB) | 0x20u); S.pc = pull16(); S.cyc -= 6; check_irq(); break;

    case 0x18: S.p &= (u8)~FC; S.cyc -= 2; break;
    case 0x38: S.p |= FC;      S.cyc -= 2; break;
    case 0x58: S.p &= (u8)~FI; S.cyc -= 2; check_irq(); break;
    case 0x78: S.p |= FI;      S.cyc -= 2; break;
    case 0xB8: S.p &= (u8)~FV; S.cyc -= 2; break;
    case 0xD8: S.p &= (u8)~FD; S.cyc -= 2; break;
    case 0xF8: S.p |= FD;      S.cyc -= 2; break;

    case 0xCB:
        if (!S.irq_line) S.cpu_asleep = 1;
        S.cyc -= 3;
        break;
    case 0xDB:
        S.jammed = 1;
        S.pc--;
        S.cyc = 0;
        break;

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

static void put_str(char **p, const char *s)
{
    while (*s && *p < S.info + sizeof(S.info) - 1)
        *(*p)++ = *s++;
    **p = 0;
}

static void put_u32(char **p, u32 v)
{
    char d[12];
    int n = 0;
    do d[n++] = (char)('0' + (v % 10u)); while (v /= 10u);
    while (n && *p < S.info + sizeof(S.info) - 1)
        *(*p)++ = d[--n];
    **p = 0;
}

const char *sv_load(u8 *image, u32 size)
{
    if (!image || size < 0x100u || size > 0x100000u)
        return "not a Watara Supervision cartridge (expected 256 B .. 1 MB)";
    for (int i = 0; i < 4; i++)
        S.pal[i] = (u16)((sv_lcd_rgb[i][0] >> 3) | ((sv_lcd_rgb[i][1] >> 3) << 5) | ((sv_lcd_rgb[i][2] >> 3) << 10));

    if (size < 0x4000u) {
        for (u32 i = 0; i < 0x4000u; i++)
            M->small_rom[i] = i < size ? image[i] : 0xFFu;
        S.rom = M->small_rom;
        S.rom_size = 0x4000u;
    } else {
        S.rom = image;
        S.rom_size = size & ~0x3FFFu;
        if (!S.rom_size)
            S.rom_size = 0x4000u;
    }
    S.magnum = S.rom_size > 0x20000u;

    char *p = S.info;
    put_str(&p, "Watara Supervision, ");
    if (S.magnum)
        put_str(&p, "Magnum banked, ROM ");
    else if (S.rom_size > 0x8000u)
        put_str(&p, "banked ($2026), ROM ");
    else
        put_str(&p, "flat ROM, ");
    put_u32(&p, size >> 10 ? size >> 10 : 1u);
    put_str(&p, " KB");

    sv_reset();
    return 0;
}

void sv_reset(void)
{
    for (u32 i = 0; i < sizeof(M->ram); i++)  M->ram[i] = 0;
    for (u32 i = 0; i < sizeof(M->vram); i++) M->vram[i] = 0;
    for (u32 i = 0; i < sizeof(M->regs); i++) M->regs[i] = 0;

    S.lo_bank = S.rom;
    S.hi_bank = S.rom + (S.rom_size - 0x4000u);

    S.a = S.x = S.y = 0;
    S.sp = 0xFDu;
    S.p = 0x24u;
    S.pc = rd16_abs(0xFFFCu);
    S.cyc = 0;
    S.irq_line = S.cpu_asleep = S.jammed = 0;

    S.timer_cyc = 0;
    S.timer_active = S.timer_shot = S.dma_done = 0;
    S.gdma_caddr = S.gdma_vaddr = S.gdma_len = 0;
    S.gdma_cpu2vram = 0;
    S.ctl = 0;

    for (int i = 0; i < 2; i++) {
        for (int r = 0; r < 4; r++) S.ch[i].reg[r] = 0;
        S.ch[i].on = S.ch[i].duty = S.ch[i].vol = 0;
        S.ch[i].count = 0;
        S.ch[i].period = S.ch[i].phase = 0;
    }
    for (int r = 0; r < 3; r++) S.noise.reg[r] = 0;
    S.noise.on = S.noise.play = S.noise.left = S.noise.right = S.noise.tap = S.noise.vol = S.noise.val = 0;
    S.noise.state = 1u;
    S.noise.count = 0;
    S.noise.period = S.noise.phase = 0;

    for (int r = 0; r < 5; r++) S.adma.reg[r] = 0;
    S.adma.on = S.adma.left = S.adma.right = 0;
    S.adma.start = S.adma.size = S.adma.pos = 0;
    S.adma.ca14to16 = S.adma.period = S.adma.phase = 0;
}

void sv_frame(u16 pad, u16 *picture)
{
    /* play.c PAD bits -> Supervision $2020 bits (0:Right,1:Left,2:Down,3:Up,4:B,5:A,6:Select,7:Start) */
    S.ctl = (u8)(((pad & 0x80u) ? 0x01u : 0u) |
                 ((pad & 0x40u) ? 0x02u : 0u) |
                 ((pad & 0x20u) ? 0x04u : 0u) |
                 ((pad & 0x10u) ? 0x08u : 0u) |
                 ((pad & 0x02u) ? 0x10u : 0u) |
                 ((pad & 0x01u) ? 0x20u : 0u) |
                 ((pad & 0x04u) ? 0x40u : 0u) |
                 ((pad & 0x08u) ? 0x80u : 0u));

    u32 dt_sample = S.snd_hz ? (SV_CLOCK / S.snd_hz) : 0;

    for (int s = 0; s < SLICES && !S.jammed; s++) {
        S.cyc += SLICE_CYC;
        while (S.cyc > 0 && !S.jammed)
            step_cpu();
        u32 ran = (u32)(SLICE_CYC - S.cyc);
        if (S.timer_active) {
            S.timer_cyc -= (s32)ran;
            if (S.timer_cyc <= 0) {
                S.timer_active = 0;
                S.timer_shot = 1;
                check_irq();
            }
        }
        if (S.snd_hz) {
            S.snd_acc += ran * S.snd_hz;
            while (S.snd_acc >= SV_CLOCK) {
                S.snd_acc -= SV_CLOCK;
                sound_sample(dt_sample);
            }
        } else {
            step_adma_silent(ran);
        }

        if (picture && s < SV_H) {
            u8 xsize = M->regs[0x00];
            int w = (xsize == 0 || xsize > SV_W) ? SV_W : (int)xsize;
            u32 y_sc = (u32)M->regs[0x03] + (u32)s;
            u32 scan = ((u32)M->regs[0x02] >> 2) + y_sc * 0x30u;
            while (scan >= 0x1FE0u)
                scan -= 0x1FE0u;
            u8 inner = M->regs[0x02] & 3u;
            const u8 *vp = M->vram + scan;
            u16 *out = picture + s * SV_W;
            u8 j = inner, b = 0;
            if (j & 3u)
                b = (u8)((*vp++) >> ((j & 3u) * 2u));
            for (int x = 0; x < w; x++, j++) {
                if (!(j & 3u))
                    b = *vp++;
                out[x] = S.pal[b & 3u];
                b >>= 2;
            }
            for (int x = w; x < SV_W; x++)
                out[x] = S.pal[0];
        }

        if (s == SV_H && (M->regs[0x26] & 0x01u) && !S.jammed)
            trigger_nmi();
    }

    if (S.ch[0].count) S.ch[0].count--;
    if (S.ch[1].count) S.ch[1].count--;
    if (S.noise.count) S.noise.count--;
}

const char *sv_info(void)
{
    return S.info;
}

u8 *sv_save_ram(u32 *size, int *battery)
{
    *size = 0;
    *battery = 0;
    return M->sav_dummy;
}

int sv_save_changed(void)
{
    return 0;
}

int sv_jammed(void)
{
    return S.jammed;
}

void sv_audio_rate(u32 hz)
{
    S.snd_hz = (hz >= 8000u && hz <= 192000u) ? hz : 0;
    S.snd_acc = 0;
    S.snd_head = S.snd_count = 0;
}

int sv_audio(s16 *out, int max)
{
    int n = 0;
    while (n < max && S.snd_count) {
        out[n++] = M->snd_ring[S.snd_head];
        S.snd_head = (S.snd_head + 1u) % SND_RING;
        S.snd_count--;
    }
    return n;
}
