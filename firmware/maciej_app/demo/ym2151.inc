/* Shared Yamaha YM2151 (OPM) 8-channel 4-operator FM synthesizer.
   Used by x68k.c, konami.c, irem.c, taito.c (configurable master clock 3.579545 / 4.000000 MHz). */
#ifndef DEMO_YM2151_INC
#define DEMO_YM2151_INC

enum { YM_EG_ATT = 0, YM_EG_DEC = 1, YM_EG_SUS = 2, YM_EG_REL = 3 };

struct ym2151_op {
    u32 phase, inc;
    s32 att;
    u32 env;
    s32 out, out1;
    u8 dt1, dt2, mul, tl, ks, ar, am, d1r, d2r, d1l, rr;
    u8 state;
    u8 rate[4];
};

struct ym2151_ch {
    struct ym2151_op op[4];             /* 0:M1, 1:C1, 2:M2, 3:C2 */
    u8 kc, kf, alg, fb, rl, pms, ams, quiet;
};

struct ym2151 {
    struct ym2151_ch ch[8];
    u8 regs[256];
    u8 addr_latch;
    u16 ta_load;
    u8 tb_load, timer_ctrl, status, ct; /* ct: bit 0 = CT1, bit 1 = CT2 (reg $1B bits 6..7) */
    s32 ta_cnt, tb_cnt;
    u32 clock_hz, sample_rate;
    u8 noise_en, noise_freq;
    u32 lfsr, noise_cnt, eg_cnt;
    u8 eg_div;
    s32 cached_l, cached_r;
    u8 sample_toggle;
};

static const u16 ym_logsin[256] = {
    2137,1731,1543,1419,1326,1252,1190,1137,1091,1050,1013,979,949,920,894,869,
    846,825,804,785,767,749,732,717,701,687,672,659,646,633,621,609,
    598,587,576,566,556,546,536,527,518,509,500,492,484,476,468,460,
    453,445,438,431,424,417,410,404,397,391,385,379,373,367,361,356,
    350,345,339,334,329,324,319,314,309,304,299,295,290,286,281,277,
    273,268,264,260,256,252,248,244,240,237,233,229,226,222,219,215,
    212,209,205,202,199,196,193,190,187,184,181,178,175,172,169,167,
    164,161,159,156,153,151,148,146,143,141,139,136,134,132,129,127,
    125,123,121,119,117,115,113,111,109,107,105,103,101,99,97,96,
    94,92,90,89,87,85,84,82,81,79,78,76,75,73,72,70,
    69,68,66,65,64,62,61,60,59,57,56,55,54,53,52,50,
    49,48,47,46,45,44,43,42,41,40,39,38,37,36,36,35,
    34,33,32,31,31,30,29,28,27,27,26,25,25,24,23,23,
    22,21,21,20,19,19,18,18,17,17,16,16,15,15,14,14,
    13,13,12,12,11,11,11,10,10,9,9,9,8,8,8,7,
    7,7,6,6,6,5,5,5,5,4,4,4,4,4,3,3
};

static const u16 ym_exp2[256] = {
    1018,1013,1007,1002,996,991,986,980,975,970,965,959,954,949,944,939,
    934,929,924,919,914,909,904,899,895,890,885,880,876,871,866,862,
    857,852,848,843,839,834,830,826,821,817,812,808,804,800,795,791,
    787,783,779,774,770,766,762,758,754,750,746,742,738,734,730,726,
    723,719,715,711,707,704,700,696,693,689,685,682,678,675,671,667,
    664,660,657,653,650,647,643,640,636,633,630,626,623,620,617,613,
    610,607,604,601,597,594,591,588,585,582,579,576,573,570,567,564,
    561,558,555,552,549,547,544,541,538,535,532,530,527,524,521,519,
    516,513,511,508,505,503,500,498,495,492,490,487,485,482,480,477,
    475,472,470,467,465,463,460,458,455,453,451,448,446,444,441,439,
    437,435,432,430,428,426,423,421,419,417,415,413,410,408,406,404,
    402,400,398,396,394,392,390,388,386,384,382,380,378,376,374,372,
    370,368,366,365,363,361,359,357,355,353,352,350,348,346,344,343,
    341,339,337,336,334,332,331,329,327,325,324,322,320,319,317,316,
    314,312,311,309,308,306,304,303,301,300,298,297,295,294,292,291,
    289,288,286,285,283,282,280,279,278,276,275,273,272,270,269,268
};

static const u8 ym_dt1_tab[4][32] = {
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0,0,0,0,1,1,1,1,1,1,1,1,2,2,2,2,2,3,3,3,4,4,4,5,5,6,6,7,8,8,8,8},
    {1,1,1,1,2,2,2,2,2,3,3,3,4,4,4,5,5,6,6,7,8,8,9,10,11,12,13,14,16,16,16,16},
    {2,2,2,2,2,3,3,3,4,4,4,5,5,6,6,7,8,8,9,10,11,12,13,14,16,17,19,20,22,22,22,22}
};

static const u8 ym_eg_steps[20][8] = {
    {0,1,0,1,0,1,0,1}, {0,1,0,1,1,1,0,1}, {0,1,1,1,0,1,1,1}, {0,1,1,1,1,1,1,1},
    {1,1,1,1,1,1,1,1}, {1,1,1,2,1,1,1,2}, {1,2,1,2,1,2,1,2}, {1,2,2,2,1,2,2,2},
    {2,2,2,2,2,2,2,2}, {2,2,2,4,2,2,2,4}, {2,4,2,4,2,4,2,4}, {2,4,4,4,2,4,4,4},
    {4,4,4,4,4,4,4,4}, {4,4,4,8,4,4,4,8}, {4,8,4,8,4,8,4,8}, {4,8,8,8,4,8,8,8},
    {8,8,8,8,8,8,8,8}, {8,8,8,8,8,8,8,8}, {8,8,8,8,8,8,8,8}, {8,8,8,8,8,8,8,8}
};

/* Concert-pitch phase increments at 24 kHz (20-bit phase) for 3.579545 MHz Octave 7 C#7..C#8 */
static const u32 ym_inc7_358[13] = {
    96887, 102648, 108751, 115217, 122068, 129327,
    137017, 145164, 153796, 162941, 172630, 182895, 193774
};
static const u8 ym_kc_to_semi[16] = {0, 1, 2, 2, 3, 4, 5, 5, 6, 7, 8, 8, 9, 10, 11, 11};
static const u16 ym_dt2_kf[4] = {0, 384, 500, 608};

static inline void ym2151_op_env(struct ym2151_op *o)
{
    u32 e = (u32)o->att + ((u32)o->tl << 3);
    o->env = e > 0x3FFu ? 0x3FFu : e;
}

static inline u8 ym2151_eff_rate(u8 r, u8 kcode, u8 ks)
{
    if (!r)
        return 0;
    u32 v = (u32)r * 2u + (kcode >> (3u - (ks & 3u)));
    return (u8)(v > 63u ? 63u : v);
}

static void ym2151_op_update(struct ym2151 *ym, struct ym2151_ch *c, int n)
{
    struct ym2151_op *o = &c->op[n];
    u32 oct = (c->kc >> 4) & 7u;
    u32 semi = ym_kc_to_semi[c->kc & 15u];
    u32 kcode = (oct << 2) | (semi >> 2);
    u32 total_kf = oct * 768u + semi * 64u + (c->kf & 63u) + ym_dt2_kf[o->dt2 & 3u];
    u32 eo = total_kf / 768u;
    u32 rem = total_kf - eo * 768u;
    u32 es = rem >> 6;
    u32 ef = rem & 63u;
    u32 base = ym_inc7_358[es] + (((ym_inc7_358[es + 1u] - ym_inc7_358[es]) * ef) >> 6);
    if (ym->clock_hz >= 3900000u)       /* 4.000 MHz OPM (X68000): scale by 4.0 / 3.579545 ~= 286 / 256 */
        base = (base * 286u) >> 8;
    u32 inc = (eo <= 7u) ? (base >> (7u - eo)) : (base << (eo - 7u));
    if (ym->sample_rate && ym->sample_rate != 48000u)
        inc = (inc * 48000u) / ym->sample_rate;
    u32 dt = ym_dt1_tab[o->dt1 & 3u][kcode & 31u] * 2u;
    inc = (o->dt1 & 4u) ? (inc > dt ? inc - dt : 0u) : (inc + dt);
    o->inc = (o->mul ? inc * o->mul : (inc >> 1)) & 0xFFFFFu;
    o->rate[YM_EG_ATT] = ym2151_eff_rate(o->ar, (u8)kcode, o->ks);
    o->rate[YM_EG_DEC] = ym2151_eff_rate(o->d1r, (u8)kcode, o->ks);
    o->rate[YM_EG_SUS] = ym2151_eff_rate(o->d2r, (u8)kcode, o->ks);
    o->rate[YM_EG_REL] = ym2151_eff_rate((u8)(o->rr * 2u + 1u), (u8)kcode, o->ks);
}

static void ym2151_init(struct ym2151 *ym, u32 clock_hz, u32 sample_rate)
{
    for (u32 i = 0; i < sizeof(*ym); i++)
        ((u8 *)ym)[i] = 0;
    ym->clock_hz = clock_hz ? clock_hz : 4000000u;
    ym->sample_rate = sample_rate ? sample_rate : 48000u;
    ym->lfsr = 1u;
    for (int ch = 0; ch < 8; ch++) {
        ym->ch[ch].rl = 3u;
        ym->ch[ch].quiet = 1u;
        for (int op = 0; op < 4; op++) {
            ym->ch[ch].op[op].att = 0x3FF;
            ym->ch[ch].op[op].env = 0x3FFu;
            ym->ch[ch].op[op].state = YM_EG_REL;
        }
    }
}

static inline s32 ym2151_ta_ticks(const struct ym2151 *ym, u32 host_hz)
{
    /* 1 OPM Timer A tick = 64 OPM clocks (pure 32-bit arithmetic for freestanding MIPS32) */
    u32 denom = (ym->clock_hz ? ym->clock_hz : 4000000u) >> 4;
    u32 host_per_64 = ((host_hz >> 4) * 64u) / (denom ? denom : 1u);
    s32 t = (s32)((1024u - (ym->ta_load & 0x3FFu)) * host_per_64);
    return t > 0 ? t : 64;
}

static inline s32 ym2151_tb_ticks(const struct ym2151 *ym, u32 host_hz)
{
    /* 1 OPM Timer B tick = 1024 OPM clocks */
    u32 denom = (ym->clock_hz ? ym->clock_hz : 4000000u) >> 4;
    u32 host_per_64 = ((host_hz >> 4) * 64u) / (denom ? denom : 1u);
    s32 t = (s32)((256u - ym->tb_load) * 16u * host_per_64);
    return t > 0 ? t : 1024;
}

static inline int ym2151_irq_active(const struct ym2151 *ym)
{
    u8 msk = (u8)((ym->timer_ctrl >> 2) & 3u);
    return (ym->status & msk) != 0;
}

static void ym2151_key(struct ym2151_ch *c, int n, int on)
{
    struct ym2151_op *o = &c->op[n];
    if (on) {
        if (o->state == YM_EG_REL) {
            o->phase = 0;
            o->state = YM_EG_ATT;
            if (o->rate[YM_EG_ATT] >= 62u) {
                o->att = 0;
                o->state = o->d1l ? YM_EG_DEC : YM_EG_SUS;
            }
            ym2151_op_env(o);
            c->quiet = 0;
        }
    } else if (o->state != YM_EG_REL) {
        o->state = YM_EG_REL;
    }
}

static void ym2151_write_reg(struct ym2151 *ym, u8 r, u8 v, u32 host_hz)
{
    static const u8 slot_map[4] = {0, 2, 1, 3};
    ym->regs[r] = v;
    if (r == 0x08u) {
        struct ym2151_ch *c = &ym->ch[v & 7u];
        ym2151_key(c, 0, (v >> 3) & 1);
        ym2151_key(c, 1, (v >> 4) & 1);
        ym2151_key(c, 2, (v >> 5) & 1);
        ym2151_key(c, 3, (v >> 6) & 1);
        return;
    }
    if (r == 0x0Fu) {
        ym->noise_en = (v >> 7) & 1u;
        ym->noise_freq = v & 0x1Fu;
        return;
    }
    if (r == 0x10u) { ym->ta_load = (u16)((ym->ta_load & 3u) | ((u16)v << 2)); return; }
    if (r == 0x11u) { ym->ta_load = (u16)((ym->ta_load & ~3u) | (v & 3u)); return; }
    if (r == 0x12u) { ym->tb_load = v; return; }
    if (r == 0x14u) {
        u8 prev = ym->timer_ctrl;
        ym->timer_ctrl = v;
        if (!(prev & 1u) && (v & 1u)) ym->ta_cnt = ym2151_ta_ticks(ym, host_hz);
        if (!(prev & 2u) && (v & 2u)) ym->tb_cnt = ym2151_tb_ticks(ym, host_hz);
        if (v & 0x10u) ym->status &= ~1u;
        if (v & 0x20u) ym->status &= ~2u;
        return;
    }
    if (r == 0x1Bu) {
        ym->ct = (v >> 6) & 3u;
        return;
    }
    if (r >= 0x20u && r < 0x28u) {
        struct ym2151_ch *c = &ym->ch[r & 7u];
        c->rl = (v >> 6) & 3u;
        c->fb = (v >> 3) & 7u;
        c->alg = v & 7u;
        return;
    }
    if (r >= 0x28u && r < 0x30u) {
        struct ym2151_ch *c = &ym->ch[r & 7u];
        c->kc = v & 0x7Fu;
        for (int i = 0; i < 4; i++) ym2151_op_update(ym, c, i);
        return;
    }
    if (r >= 0x30u && r < 0x38u) {
        struct ym2151_ch *c = &ym->ch[r & 7u];
        c->kf = (v >> 2) & 0x3Fu;
        for (int i = 0; i < 4; i++) ym2151_op_update(ym, c, i);
        return;
    }
    if (r >= 0x40u) {
        struct ym2151_ch *c = &ym->ch[r & 7u];
        int op_idx = slot_map[(r >> 3) & 3u];
        struct ym2151_op *o = &c->op[op_idx];
        switch (r & 0xE0u) {
        case 0x40u: o->dt1 = (v >> 4) & 7u; o->mul = v & 0x0Fu; ym2151_op_update(ym, c, op_idx); break;
        case 0x60u: o->tl = v & 0x7Fu; ym2151_op_env(o); break;
        case 0x80u: o->ks = (v >> 6) & 3u; o->ar = v & 0x1Fu; ym2151_op_update(ym, c, op_idx); break;
        case 0xA0u: o->am = (v >> 7) & 1u; o->d1r = v & 0x1Fu; ym2151_op_update(ym, c, op_idx); break;
        case 0xC0u: o->dt2 = (v >> 6) & 3u; o->d2r = v & 0x1Fu; ym2151_op_update(ym, c, op_idx); break;
        case 0xE0u:
            o->d1l = (v >> 4) & 0x0Fu;
            if (o->d1l == 15u) o->d1l = 31u;
            o->rr = v & 0x0Fu;
            ym2151_op_update(ym, c, op_idx);
            break;
        }
    }
}

static inline int ym2151_tick_timers(struct ym2151 *ym, s32 ticks, u32 host_hz)
{
    int changed = 0;
    if (ym->timer_ctrl & 1u) {
        ym->ta_cnt -= ticks;
        if (ym->ta_cnt <= 0) {
            s32 p = ym2151_ta_ticks(ym, host_hz);
            while (ym->ta_cnt <= 0) ym->ta_cnt += p;
            if ((ym->timer_ctrl & 4u) && !(ym->status & 1u)) {
                ym->status |= 1u;
                changed = 1;
            }
        }
    }
    if (ym->timer_ctrl & 2u) {
        ym->tb_cnt -= ticks;
        if (ym->tb_cnt <= 0) {
            s32 p = ym2151_tb_ticks(ym, host_hz);
            while (ym->tb_cnt <= 0) ym->tb_cnt += p;
            if ((ym->timer_ctrl & 8u) && !(ym->status & 2u)) {
                ym->status |= 2u;
                changed = 1;
            }
        }
    }
    return changed;
}

static inline s32 ym2151_calc_op(struct ym2151_op *o, s32 mod)
{
    u32 p = ((o->phase >> 10) + (u32)mod) & 0x3FFu;
    o->phase = (o->phase + o->inc) & 0xFFFFFu;
    if (o->env >= 0x340u)
        return 0;
    u32 idx = (p & 0x100u) ? (~p & 0xFFu) : (p & 0xFFu);
    u32 lv = (u32)ym_logsin[idx] + (o->env << 2);
    if (lv >= 0x1A00u)
        return 0;
    s32 mag = ((s32)ym_exp2[~lv & 0xFFu] << 2) >> (lv >> 8);
    return (p & 0x200u) ? -mag : mag;
}

static void ym2151_step_24khz(struct ym2151 *ym, s32 *out_l, s32 *out_r)
{
    ym->eg_div ^= 1u;
    if (!ym->eg_div)
        ym->eg_cnt++;
    int do_eg = !ym->eg_div;
    u32 egc = ym->eg_cnt;

    s32 sum_l = 0, sum_r = 0;
    for (int ch = 0; ch < 8; ch++) {
        struct ym2151_ch *c = &ym->ch[ch];
        if (c->quiet)
            continue;
        if (do_eg) {
            int all_rel = 1;
            for (int n = 0; n < 4; n++) {
                struct ym2151_op *o = &c->op[n];
                if (o->state != YM_EG_REL || o->att < 0x3FF)
                    all_rel = 0;
                u8 r = o->rate[o->state];
                if (!r)
                    continue;
                u32 sh = (r < 48u) ? (11u - (r >> 2)) : 0u;
                if ((egc & ((1u << sh) - 1u)) != 0)
                    continue;
                u32 st_row = (r < 48u) ? (r & 3u) : ((r - 44u) < 20u ? (r - 44u) : 19u);
                u8 inc = ym_eg_steps[st_row][(egc >> sh) & 7u];
                if (o->state == YM_EG_ATT) {
                    o->att += (~o->att * (s32)inc) >> 4;
                    if (o->att <= 0) {
                        o->att = 0;
                        o->state = o->d1l ? YM_EG_DEC : YM_EG_SUS;
                    }
                } else {
                    o->att += (s32)inc;
                    if (o->state == YM_EG_DEC && o->att >= ((s32)o->d1l << 5)) {
                        o->att = (s32)o->d1l << 5;
                        o->state = YM_EG_SUS;
                    }
                    if (o->att >= 0x3FF)
                        o->att = 0x3FF;
                }
                ym2151_op_env(o);
            }
            if (all_rel) {
                c->quiet = 1;
                continue;
            }
        }
        struct ym2151_op *o0 = &c->op[0], *o1 = &c->op[1], *o2 = &c->op[2], *o3 = &c->op[3];
        s32 fb = c->fb ? ((o0->out + o0->out1) >> (9 - c->fb)) : 0;
        o0->out1 = o0->out;
        o0->out = ym2151_calc_op(o0, fb);
        s32 v0 = o0->out, out = 0;
        switch (c->alg) {
        case 0: o1->out = ym2151_calc_op(o1, v0 >> 1); o2->out = ym2151_calc_op(o2, o1->out >> 1); out = ym2151_calc_op(o3, o2->out >> 1); break;
        case 1: o1->out = ym2151_calc_op(o1, 0); o2->out = ym2151_calc_op(o2, (v0 + o1->out) >> 1); out = ym2151_calc_op(o3, o2->out >> 1); break;
        case 2: o1->out = ym2151_calc_op(o1, 0); o2->out = ym2151_calc_op(o2, o1->out >> 1); out = ym2151_calc_op(o3, (v0 + o2->out) >> 1); break;
        case 3: o1->out = ym2151_calc_op(o1, v0 >> 1); o2->out = ym2151_calc_op(o2, 0); out = ym2151_calc_op(o3, (o1->out + o2->out) >> 1); break;
        case 4: o1->out = ym2151_calc_op(o1, v0 >> 1); o2->out = ym2151_calc_op(o2, 0); out = o1->out + ym2151_calc_op(o3, o2->out >> 1); break;
        case 5: out = ym2151_calc_op(o1, v0 >> 1) + ym2151_calc_op(o2, v0 >> 1) + ym2151_calc_op(o3, v0 >> 1); break;
        case 6: o1->out = ym2151_calc_op(o1, v0 >> 1); out = o1->out + ym2151_calc_op(o2, 0) + ym2151_calc_op(o3, 0); break;
        default: out = v0 + ym2151_calc_op(o1, 0) + ym2151_calc_op(o2, 0) + ym2151_calc_op(o3, 0); break;
        }
        if (ch == 7 && ym->noise_en && o3->env < 0x340u) {
            u32 period = 32u - ym->noise_freq;
            if (!period) period = 1u;
            if (++ym->noise_cnt >= period) {
                ym->noise_cnt = 0;
                ym->lfsr = (ym->lfsr >> 1) ^ ((ym->lfsr & 1u) ? 0x10008u : 0u);
            }
            s32 nmag = (s32)(0x800u >> (o3->env >> 6));
            out += (ym->lfsr & 1u) ? nmag : -nmag;
        }
        if (c->rl & 1u) sum_l += out;
        if (c->rl & 2u) sum_r += out;
    }
    *out_l = sum_l;
    *out_r = sum_r;
}

static inline void ym2151_sample_48khz(struct ym2151 *ym, s32 *out_l, s32 *out_r)
{
    if (!ym->sample_toggle)
        ym2151_step_24khz(ym, &ym->cached_l, &ym->cached_r);
    ym->sample_toggle ^= 1u;
    *out_l = ym->cached_l;
    *out_r = ym->cached_r;
}

#endif
