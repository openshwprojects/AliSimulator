/* opl2.inc: Yamaha YM3812 (OPL2 / AdLib / Sound Blaster FM) Synthesizer
   - 9 2-operator FM channels + 5 rhythm instruments, all 4 OPL2 waveforms
   - Hardware-accurate Timer 1 (80 us) & Timer 2 (320 us) status flags for AdLib detection
   - Pure 32-bit fixed-point arithmetic (zero 64-bit division, zero static .bss) */
#ifndef DEMO_OPL2_INC
#define DEMO_OPL2_INC

struct opl2_op {
    u32 phase;          /* 10.16 phase accumulator */
    s32 env;            /* 0 = max volume, 0x1FF00 = silent (9.8 fixed-point attenuation) */
    u32 inc;            /* precomputed base phase increment for current fnum/blk/mult/rate */
    s32 sl_target;      /* precomputed sustain level target */
    s32 ar_step;        /* precomputed attack step */
    s32 dr_step;        /* precomputed decay step */
    s32 rr_step;        /* precomputed release step */
    u16 tl_base;        /* (r40 & 0x3Fu) << 9 */
    u8  state;          /* 0=off, 1=attack, 2=decay, 3=sustain, 4=release */
    u8  flags;          /* bits 0..1 = ws, bit 5 = EGT, bit 6 = VIB, bit 7 = AM */
};
_Static_assert(sizeof(struct opl2_op) == 32, "opl2_op must be 32 bytes for shift indexing");

struct opl2_chip {
    u8  reg[256];
    u8  addr;
    u8  status;         /* bit 7: IRQ, bit 6: T1 (80 us), bit 5: T2 (320 us) */
    u8  t1_val, t2_val;
    u8  t_ctrl;
    u8  kon_was[9];
    u32 t1_us_rem, t2_us_rem;
    u32 lfo_cnt;
    u32 noise_rng;
    u32 active_mask;
    u32 ch_active;
    u32 lfo_mask;
    u32 cached_rate_fp8;
    u8  ch_fb_sh[9];
    u8  ch_con[9];
    u8  ch_pad[2];
    s32 fb_hist[9][2];
    struct opl2_op op[18];
    s16 sin_lut[1024];  /* quarter-period log/linear sine table [-4095 .. +4095] */
    u16 exp_lut[256];
};

static const u8 opl2_ch_mod[9] = {0, 1, 2, 6, 7, 8, 12, 13, 14};
static const u8 opl2_slot_ch[18] = {0, 1, 2, 0, 1, 2, 3, 4, 5, 3, 4, 5, 6, 7, 8, 6, 7, 8};
static const u8 opl2_slot_reg[18] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15
};
static const signed char opl2_off_to_slot[32] = {
     0,  1,  2,  3,  4,  5, -1, -1,
     6,  7,  8,  9, 10, 11, -1, -1,
    12, 13, 14, 15, 16, 17, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1
};
static const u8 opl2_mult_x2[16] = {1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 20, 24, 24, 30, 30};

static void opl2_recalc_slot(struct opl2_chip *o, int slot)
{
    struct opl2_op *op = &o->op[slot];
    int ch = opl2_slot_ch[slot];
    u8 rr_base = opl2_slot_reg[slot];
    u8 r20 = o->reg[0x20 + rr_base];
    u8 r40 = o->reg[0x40 + rr_base];
    u8 r60 = o->reg[0x60 + rr_base];
    u8 r80 = o->reg[0x80 + rr_base];
    u8 ws  = (o->reg[0x01] & 0x20u) ? (o->reg[0xE0 + rr_base] & 3u) : 0u;

    u32 fnum = o->reg[0xA0 + ch] | (((u32)(o->reg[0xB0 + ch] & 3u)) << 8);
    u32 blk  = (o->reg[0xB0 + ch] >> 2) & 7u;
    u32 kcode = (blk << 1) | ((fnum >> 9) & 1u);
    u32 ksr = (r20 & 0x10u) ? kcode : (kcode >> 2);
    u32 rate_scale = o->cached_rate_fp8;

    u32 base_inc = (((fnum << blk) >> 1) * rate_scale) >> 2;
    op->inc = (base_inc * opl2_mult_x2[r20 & 15u]) >> 1;
    op->tl_base = (u16)((u32)(r40 & 0x3Fu) << 9);
    op->flags = (u8)((r20 & 0xE0u) | ws);
    if (r20 & 0xC0u) o->lfo_mask |= (1u << slot);
    else             o->lfo_mask &= ~(1u << slot);

    u32 sl = r80 >> 4;
    op->sl_target = (sl == 15u) ? 0x1FF00 : (s32)(sl << 12);

    u32 ar = r60 >> 4;
    if (!ar) {
        op->ar_step = 0;
    } else {
        u32 eff = ar * 4u + ksr;
        if (eff > 63u) eff = 63u;
        s32 step = (s32)(((4u + (eff & 3u)) << (eff >> 2)) * rate_scale) >> 9;
        op->ar_step = (step < 8) ? 8 : step;
    }

    u32 dr = r60 & 15u;
    if (!dr) {
        op->dr_step = 0;
    } else {
        u32 eff = dr * 4u + ksr;
        if (eff > 63u) eff = 63u;
        s32 step = (s32)(((4u + (eff & 3u)) << (eff >> 2)) * rate_scale) >> 12;
        op->dr_step = (step < 1) ? 1 : step;
    }

    u32 rr = r80 & 15u;
    if (!rr) {
        op->rr_step = 0;
    } else {
        u32 eff = rr * 4u + ksr;
        if (eff > 63u) eff = 63u;
        s32 step = (s32)(((4u + (eff & 3u)) << (eff >> 2)) * rate_scale) >> 12;
        op->rr_step = (step < 1) ? 1 : step;
    }
}

static void opl2_recalc_all(struct opl2_chip *o, u32 rate_fp8)
{
    o->cached_rate_fp8 = rate_fp8;
    for (int s = 0; s < 18; s++)
        opl2_recalc_slot(o, s);
}

static void opl2_init(struct opl2_chip *o)
{
    u32 *p32 = (u32 *)(void *)o;
    for (u32 i = 0; i < sizeof(*o) / 4u; i++)
        p32[i] = 0;
    o->noise_rng = 0x1FFFFu;
    for (int i = 0; i < 18; i++) {
        o->op[i].env = 0x1FF00;
        o->op[i].sl_target = 0;
    }

    /* Accurate 1024-entry sine table using Bhaskara-refined minimax polynomial (0 libc) */
    for (int i = 0; i < 256; i++) {
        u32 x = (u32)(2 * i + 1);               /* 1..511 out of 512 */
        u32 u = x * (1024u - x);                /* t*(2-t) scaled by 512^2 = 262144 */
        u32 num = (u >> 4) * 4095u;             /* 16*u/256 * 4095 */
        u32 den = (5u << 18) - u;               /* (5 - t*(2-t)) * 262144; at t=0: 5, at t=1: 4 */
        s16 s = (s16)((num + (den >> 3)) / (den >> 2));
        if (s > 4095) s = 4095;
        o->sin_lut[i]         = s;
        o->sin_lut[511 - i]   = s;
        o->sin_lut[512 + i]   = (s16)-s;
        o->sin_lut[1023 - i]  = (s16)-s;
    }
    /* 2^(-x/256) * 4096 table for fast envelope attenuation scaling */
    for (int i = 0; i < 256; i++) {
        u32 t = (u32)i;
        u32 t2 = (t * t) >> 8;
        u32 t3 = (t2 * t) >> 8;
        s32 v = 4096 - (((s32)t * 2839) >> 8) + (((s32)t2 * 984) >> 8) - (((s32)t3 * 213) >> 8);
        if (v < 2048) v = 2048;
        if (v > 4096) v = 4096;
        o->exp_lut[i] = (u16)v;
    }
}

static void opl2_advance_timers(struct opl2_chip *o, u32 elapsed_us)
{
    if (o->t_ctrl & 0x01u) {                    /* Timer 1: 80 us per tick */
        u32 tot = o->t1_us_rem + elapsed_us;
        u32 ticks = tot / 80u;
        o->t1_us_rem = tot % 80u;
        u32 period = 256u - o->t1_val;
        if (ticks >= period) {
            if (!(o->t_ctrl & 0x40u))
                o->status |= 0xC0u;
        }
    }
    if (o->t_ctrl & 0x02u) {                    /* Timer 2: 320 us per tick */
        u32 tot = o->t2_us_rem + elapsed_us;
        u32 ticks = tot / 320u;
        o->t2_us_rem = tot % 320u;
        u32 period = 256u - o->t2_val;
        if (ticks >= period) {
            if (!(o->t_ctrl & 0x20u))
                o->status |= 0xA0u;
        }
    }
}

static u8 opl2_read_status(struct opl2_chip *o)
{
    return (u8)(o->status & 0xE0u);
}

static void opl2_key_on(struct opl2_chip *o, int slot)
{
    if (o->op[slot].state == 0 || o->op[slot].state == 4) {
        o->op[slot].phase = 0;
        o->op[slot].state = 1;
        o->active_mask |= (1u << slot);
        o->ch_active |= (1u << opl2_slot_ch[slot]);
    }
}

static void opl2_key_off(struct opl2_chip *o, int slot)
{
    if (o->op[slot].state != 0 && o->op[slot].state != 4)
        o->op[slot].state = 4;
}

static void opl2_write(struct opl2_chip *o, u32 port_lsb, u8 val)
{
    if (!(port_lsb & 1u)) {
        o->addr = val;
        return;
    }
    u8 r = o->addr;
    o->reg[r] = val;

    if (r == 0x01) {
        for (int s = 0; s < 18; s++)
            opl2_recalc_slot(o, s);
    } else if (r == 0x02) {
        o->t1_val = val;
    } else if (r == 0x03) {
        o->t2_val = val;
    } else if (r == 0x04) {
        if (val & 0x80u) {
            o->status &= (u8)~0xE0u;
        } else {
            u8 prev = o->t_ctrl;
            o->t_ctrl = val;
            if ((val & 1u) && !(prev & 1u)) o->t1_us_rem = 0;
            if ((val & 2u) && !(prev & 2u)) o->t2_us_rem = 0;
            if (val & 0x40u) o->status &= (u8)~0x40u;
            if (val & 0x20u) o->status &= (u8)~0x20u;
            if (!(o->status & 0x60u)) o->status &= (u8)~0x80u;
        }
    } else if ((r >= 0x20 && r <= 0x95) || r >= 0xE0) {
        int slot = opl2_off_to_slot[r & 0x1Fu];
        if (slot >= 0)
            opl2_recalc_slot(o, slot);
    } else if (r >= 0xA0 && r <= 0xA8) {
        int ms = opl2_ch_mod[r - 0xA0];
        opl2_recalc_slot(o, ms);
        opl2_recalc_slot(o, ms + 3);
    } else if (r >= 0xB0 && r <= 0xB8) {
        int ch = r - 0xB0;
        int ms = opl2_ch_mod[ch];
        u8 kon = (val >> 5) & 1u;
        if (kon != o->kon_was[ch]) {
            if (kon) { opl2_key_on(o, ms); opl2_key_on(o, ms + 3); }
            else     { opl2_key_off(o, ms); opl2_key_off(o, ms + 3); }
            o->kon_was[ch] = kon;
        }
        opl2_recalc_slot(o, ms);
        opl2_recalc_slot(o, ms + 3);
    } else if (r >= 0xC0 && r <= 0xC8) {
        int ch = r - 0xC0;
        u32 fb = (val >> 1) & 7u;
        o->ch_fb_sh[ch] = fb ? (u8)(9u - fb) : 0u;
        o->ch_con[ch] = val & 1u;
    } else if (r == 0xBD) {
        if (val & 0x20u) {                      /* Rhythm instruments on channels 6, 7, 8 */
            if (val & 0x10u) { opl2_key_on(o, 12); opl2_key_on(o, 15); } else { opl2_key_off(o, 12); opl2_key_off(o, 15); }
            if (val & 0x08u) opl2_key_on(o, 16); else opl2_key_off(o, 16);
            if (val & 0x04u) opl2_key_on(o, 14); else opl2_key_off(o, 14);
            if (val & 0x02u) opl2_key_on(o, 17); else opl2_key_off(o, 17);
            if (val & 0x01u) opl2_key_on(o, 13); else opl2_key_off(o, 13);
        }
    }
}

static inline __attribute__((always_inline)) s32 opl2_wave(const struct opl2_chip *o, u32 idx10, u8 ws, s32 atten9_8)
{
    if (atten9_8 >= 0xD000) return 0;
    idx10 &= 1023u;
    s32 s;
    if (__builtin_expect(ws == 0u, 1)) {
        s = o->sin_lut[idx10];
    } else if (ws == 1u) {
        if (idx10 >= 512u) return 0;
        s = o->sin_lut[idx10];
    } else if (ws == 2u) {
        s = o->sin_lut[idx10 & 511u];
    } else {
        if (idx10 & 256u) return 0;
        s = o->sin_lut[idx10 & 255u];
    }
    if (__builtin_expect(!s, 0)) return 0;
    u32 oct = (u32)atten9_8 >> 12;
    u32 frac = ((u32)atten9_8 >> 4) & 255u;
    s32 scaled = (s * (s32)o->exp_lut[frac]) >> 12;
    return scaled >> oct;
}

static inline __attribute__((always_inline)) void opl2_step_op_fast(struct opl2_chip *o, struct opl2_op *op, int slot)
{
    u8 st = op->state;
    if (st >= 3u) {
        if (st == 3u) {
            if (!(op->flags & 0x20u))
                op->state = 4;
        } else {
            s32 step = op->rr_step;
            if (!step) return;
            op->env += step;
            if (op->env >= 0x1FF00) {
                op->env = 0x1FF00;
                op->state = 0;
                o->active_mask &= ~(1u << slot);
            }
        }
    } else if (st == 2u) {
        s32 target = op->sl_target;
        if (op->env >= target) {
            op->env = target;
            op->state = (op->flags & 0x20u) ? 3 : 4;
            return;
        }
        s32 step = op->dr_step;
        if (!step) return;
        op->env += step;
        if (op->env >= target) {
            op->env = target;
            op->state = (op->flags & 0x20u) ? 3 : 4;
        }
    } else if (st == 1u) {
        s32 step = op->ar_step;
        if (!step) return;
        op->env -= ((op->env >> 3) + 32) * step >> 6;
        if (op->env <= 0) {
            op->env = 0;
            op->state = 2;
        }
    }
}

static __attribute__((noinline)) s32 opl2_sample_active(struct opl2_chip *o, u32 rate_fp8)
{
    if (__builtin_expect(o->cached_rate_fp8 != rate_fp8, 0))
        opl2_recalc_all(o, rate_fp8);

    s32 am_add = 0;
    u32 vib_neg = 0;
    if (o->lfo_mask & o->active_mask) {
        u32 am_lfo = ((o->lfo_cnt >> 15) & 63u);
        if (am_lfo >= 32u) am_lfo = 63u - am_lfo;
        if (!(o->reg[0xBD] & 0x80u)) am_lfo >>= 2;
        am_add = (s32)(am_lfo << 7);
        vib_neg = (o->lfo_cnt >> 18) & 1u;
    }
    u8 rhy = (o->reg[0xBD] & 0x20u) != 0;
    s32 total = 0;

    u32 cm = o->ch_active;
    while (cm) {
        int ch = __builtin_ctz(cm);
        cm &= cm - 1u;
        int ms = opl2_ch_mod[ch];
        struct opl2_op *mop = &o->op[ms];
        struct opl2_op *cop = mop + 3;
        if (__builtin_expect((mop->state | cop->state) == 0u, 0)) {
            o->ch_active &= ~(1u << ch);
            continue;
        }

        opl2_step_op_fast(o, mop, ms);
        opl2_step_op_fast(o, cop, ms + 3);
        if ((mop->state | cop->state) == 0u)
            o->ch_active &= ~(1u << ch);

        u8 m_fl = mop->flags, c_fl = cop->flags;
        u32 m_inc = mop->inc, c_inc = cop->inc;
        s32 m_tl = (s32)mop->tl_base + mop->env;
        s32 c_tl = (s32)cop->tl_base + cop->env;
        if (__builtin_expect(((m_fl | c_fl) & 0xC0u) != 0u, 0)) {
            if (m_fl & 0x40u) { u32 dv = m_inc >> 10; m_inc = vib_neg ? (m_inc - dv) : (m_inc + dv); }
            if (c_fl & 0x40u) { u32 dv = c_inc >> 10; c_inc = vib_neg ? (c_inc - dv) : (c_inc + dv); }
            if (m_fl & 0x80u) m_tl += am_add;
            if (c_fl & 0x80u) c_tl += am_add;
        }

        mop->phase += m_inc;
        cop->phase += c_inc;

        u8 m_ws = m_fl & 3u, c_ws = c_fl & 3u;
        u8 con = o->ch_con[ch];

        s32 mod_out = 0;
        if (m_tl < 0xD000) {
            u8 fb_sh = o->ch_fb_sh[ch];
            s32 fb_mod = fb_sh ? ((o->fb_hist[ch][0] + o->fb_hist[ch][1]) >> fb_sh) : 0;
            mod_out = opl2_wave(o, (mop->phase >> 16) + (u32)fb_mod, m_ws, m_tl);
        }
        o->fb_hist[ch][1] = o->fb_hist[ch][0];
        o->fb_hist[ch][0] = mod_out;

        if (__builtin_expect(!rhy || ch < 6, 1)) {
            if (!con)
                total += opl2_wave(o, (cop->phase >> 16) + (u32)(mod_out >> 1), c_ws, c_tl);
            else
                total += mod_out + opl2_wave(o, cop->phase >> 16, c_ws, c_tl);
        } else if (ch == 6) {
            s32 bd = opl2_wave(o, (cop->phase >> 16) + (con ? 0u : (u32)(mod_out >> 1)), c_ws, c_tl);
            total += bd * 2;
        } else {
            u32 nz = (o->noise_rng & 1u) ? 0x200u : 0u;
            total += opl2_wave(o, (mop->phase >> 16) ^ nz, m_ws, m_tl);
            total += opl2_wave(o, (cop->phase >> 16) ^ nz, c_ws, c_tl);
        }
    }
    return total;
}

/* Render one OPL2 sample at `out_hz` (e.g. 48000 Hz; native OPL2 = 49716 Hz -> rate_scale = (49716<<8)/out_hz) */
static inline __attribute__((always_inline)) s32 opl2_sample(struct opl2_chip *o, u32 rate_fp8)
{
    o->lfo_cnt += rate_fp8;
    o->noise_rng = (o->noise_rng >> 1) ^ ((o->noise_rng & 1u) ? 0x400181u : 0u);
    if (!o->active_mask)
        return 0;
    return opl2_sample_active(o, rate_fp8);
}

#endif
